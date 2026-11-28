// SPDX-License-Identifier: Apache-2.0

//! The `encrypted` protection class in the driver: key slots, the receive
//! order and the usage accounting of `quantstratum-docs:
//! karyos/adr/0114-encrypted-protection-profile-v1.md` (sections 4 to 9;
//! quantstratum/karyos#650 and #651).
//!
//! [`karyos_protocol::protection::aes_gcm_siv`] is one derived key; this
//! module holds the keys a party needs and runs every check the ADR puts
//! around them:
//!
//! - [`ChannelKeys`] and [`PairwiseFiles`]: the `profile_id=16` key files
//!   a channel's configuration names, one class per file (section 4a);
//! - [`EncSealer`]: one encrypting party in one domain, which rolls to the
//!   next `party_epoch` before any budget of section 6 is reached (data
//!   keys) or caps its seal rate (bootstrap keys);
//! - [`EncOpener`]: a bound party's committed keys in domain 1 or 4, its
//!   next epoch tried in a scratch slot and committed only after the
//!   datagram is fully accepted, and the previous epoch kept for the 10 s
//!   overlap (sections 6 and 8);
//! - [`open_bootstrap`]: a domain 5 or 6 datagram, opened under a scratch
//!   derivation from its header (section 4, the bootstrap rule);
//! - [`OpenRate`] and [`EncRejections`]: the fixed per channel accounting
//!   of section 6 and the counter of every rejection reason (sections 8
//!   and 9);
//! - [`vm_generation`]: the VM generation change of section 10, after
//!   which no key is derived, no datagram sealed and none opened.
//!
//! The receive order is section 8's: fixed fields, epochs, sequence cap
//! and open rate, key age, key selection, replay precheck, open and
//! pairwise trailer, inner validation ([`EncOpener::verify`]); then the
//! caller's handler decides, and only a datagram it accepted is marked and
//! its epoch promoted ([`EncOpener::commit`]). A datagram refused anywhere
//! before the commit, its handler included, marks no sequence, commits no
//! key and promotes no epoch, by construction. Nothing here allocates
//! after construction: every slot is inline and every key is derived into
//! one.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use karyos_protocol::frame::FrameType;
use karyos_protocol::protection::aes_gcm_siv::{
    AesGcmSiv, BOOTSTRAP_SEQ_CAP, ContextError, DATA_BYTE_BUDGET, DATA_SEQ_CAP, Domain,
    ENVELOPE_LEN, EncRejection, EncSealError, FRAME_TYPE, HEADER_LEN, KeyContext, MAX_DATAGRAM,
    MAX_PLAINTEXT, PROFILE_ID, PairwiseKey, PublicationIdentity, ReceiverIdentity, Salt,
    check_inner_classes, classify_outer,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::wire_keys::{Class, KEY_LEN, KeyFile, Material, Purpose, Scope};

pub mod shards;
pub mod verify_pool;
pub mod vm_generation;

pub use shards::{
    DEFAULT_ENC_SHARD_RING, ENC_SHARD_IN_FLIGHT, EncShardConfig, MAX_ENC_SHARD_RING, MAX_ENC_SHARDS,
};

pub use verify_pool::{
    DEFAULT_ENC_VERIFY_SLOTS, EncVerifyConfig, MAX_ENC_VERIFIERS, MAX_ENC_VERIFY_SLOTS,
    enc_verify_inline_fallbacks,
};
pub use vm_generation::{VmGenerationWatch, quiesced};

/// Nanoseconds in a second: the open rate interval.
pub(crate) const SECOND_NS: u64 = 1_000_000_000;
/// Opens per second and channel under committed keys (section 6).
pub(crate) const COMMITTED_OPENS_PER_S: u32 = 1 << 24;
/// Opens per second and channel under scratch and bootstrap keys
/// (section 6).
pub(crate) const SCRATCH_OPENS_PER_S: u32 = 1 << 14;
/// The receiver's key age: 3660 s from a key's commit, the sender's
/// 1-hour budget plus 60 s of clock-rate margin (section 6).
pub(crate) const KEY_AGE_NS: u64 = 3_660 * SECOND_NS;
/// The sender's age budget of a data key: 1 hour (section 6).
pub(crate) const SEND_AGE_NS: u64 = 3_600 * SECOND_NS;
/// How long the previous `party_epoch` stays accepted after the first
/// datagram fully accepted under the next (section 6).
pub(crate) const EPOCH_OVERLAP_NS: u64 = 10 * SECOND_NS;
/// The sender's datagram budget of a data key: 2^32 seals, then the next
/// `party_epoch` (section 6, term 1 for data keys).
pub(crate) const SEND_ROLL_DATAGRAMS: u64 = DATA_SEQ_CAP;
/// The sender's byte budget of a data key: 2^42 protected bytes, then the
/// next `party_epoch` (section 6, the lower power of two below 2^42.4).
pub(crate) const SEND_ROLL_BYTES: u64 = DATA_BYTE_BUDGET;
/// Seals per second of one bootstrap key (section 6).
pub(crate) const BOOTSTRAP_SEALS_PER_S: u32 = 100;
/// Channel key files held at once: the current file epoch and the one
/// before it, for the 24-hour overlap (wire-key-files.md 2.3).
pub const CHANNEL_FILES: usize = 2;
/// Pairwise files held at once: two epochs for each of two receivers.
pub const PAIRWISE_FILES: usize = 4;
/// Retired boot ids a publication keeps per receiver id under the current
/// file epoch (section 7). The ADR fixes no size; when it is full a new
/// boot id is refused (fail closed).
pub(crate) const RETIRED_BOOTS: usize = 8;

/// The reasons [`EncRejections`] counts, one per [`EncRejection`].
pub const ENC_REASONS: usize = 33;

/// The counter index of `reason`. Exhaustive: a new reason does not
/// compile until it has its own counter.
#[must_use]
pub const fn reason_index(reason: EncRejection) -> usize {
    match reason {
        EncRejection::Short => 0,
        EncRejection::Length => 1,
        EncRejection::TooLong => 2,
        EncRejection::Version => 3,
        EncRejection::Flags => 4,
        EncRejection::Reserved => 5,
        EncRejection::FrameType => 6,
        EncRejection::BareFrame => 7,
        EncRejection::WrongClass => 8,
        EncRejection::MixedClass => 9,
        EncRejection::PlaintextSetup => 10,
        EncRejection::Profile => 11,
        EncRejection::TagLength => 12,
        EncRejection::Domain => 13,
        EncRejection::Epoch => 14,
        EncRejection::Binding => 15,
        EncRejection::Party => 16,
        EncRejection::SequenceCap => 17,
        EncRejection::Duplicate => 18,
        EncRejection::TooOld => 19,
        EncRejection::Tag => 20,
        EncRejection::Pairwise => 21,
        EncRejection::Unexpected => 22,
        EncRejection::InnerRejected => 23,
        EncRejection::OpenRate => 24,
        EncRejection::KeyAge => 25,
        EncRejection::RetiredBoot => 26,
        EncRejection::RetiredParty => 27,
        EncRejection::ResyncRefused => 28,
        EncRejection::BeforeJoin => 29,
        EncRejection::VmGeneration => 30,
        EncRejection::Withdrawn => 31,
        EncRejection::VerifyBusy => 32,
    }
}

/// Rejections by reason: one fixed saturating counter each, allocation
/// free (sections 8 and 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncRejections {
    counts: [u64; ENC_REASONS],
}

impl Default for EncRejections {
    fn default() -> Self {
        Self {
            counts: [0; ENC_REASONS],
        }
    }
}

impl EncRejections {
    /// Counts one rejection for `reason`.
    pub fn bump(&mut self, reason: EncRejection) {
        if let Some(count) = self.counts.get_mut(reason_index(reason)) {
            *count = count.saturating_add(1);
        }
    }

    /// The rejections counted for `reason`.
    #[must_use]
    pub fn get(&self, reason: EncRejection) -> u64 {
        self.counts.get(reason_index(reason)).copied().unwrap_or(0)
    }

    /// The sum of every reason.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts
            .iter()
            .fold(0_u64, |sum, count| sum.saturating_add(*count))
    }
}

/// Which rate counter an open is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// A committed key slot of a bound party.
    Committed,
    /// A scratch derivation: the next epoch of a bound party, or a
    /// bootstrap key of domain 5 or 6.
    Scratch,
}

/// The two fixed open rate counters of one channel (section 6): committed
/// keys at most `COMMITTED_OPENS_PER_S` and scratch or bootstrap keys at
/// most `SCRATCH_OPENS_PER_S` per one-second interval. A charge over the
/// limit is refused until the next interval, when the counter restarts
/// from 0. The intervals are the whole seconds of the clock it is charged
/// with.
///
/// Each counter is one atomic word, the interval number in its high half
/// and the count in its low half, shared by every clone: the receive
/// shards and the role of one channel charge the same two aggregate
/// counts (`quantstratum-docs:
/// karyos/adr/0127-encrypted-sharded-receive-per-endpoint.md` decision 3).
/// A charge is one compare-and-swap: it starts a new interval when the
/// clock has moved past the stored one, and otherwise adds one while the
/// count is below the budget. The two budgets stay separate.
#[derive(Debug, Clone, Default)]
pub struct OpenRate {
    words: Arc<RateWords>,
}

/// The two words of an [`OpenRate`], each on cache lines of its own.
#[derive(Debug, Default)]
struct RateWords {
    committed: RateWord,
    scratch: RateWord,
}

/// One rate word: `interval << 32 | count`.
#[derive(Debug, Default)]
#[repr(align(128))]
struct RateWord(AtomicU64);

/// The low half of a rate word: the count.
const RATE_COUNT: u64 = 0xFFFF_FFFF;

impl OpenRate {
    fn word(&self, kind: KeyKind) -> (&AtomicU64, u32) {
        match kind {
            KeyKind::Committed => (&self.words.committed.0, COMMITTED_OPENS_PER_S),
            KeyKind::Scratch => (&self.words.scratch.0, SCRATCH_OPENS_PER_S),
        }
    }

    /// Charges one open of `kind` at `now_ns`. Lock free; allocates
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`EncRejection::OpenRate`] over the limit; nothing is charged.
    pub fn charge(&self, kind: KeyKind, now_ns: u64) -> Result<(), EncRejection> {
        let (word, limit) = self.word(kind);
        let interval = (now_ns / SECOND_NS) & RATE_COUNT;
        let mut seen = word.load(Ordering::Acquire);
        loop {
            let (held, count) = (seen >> 32, seen & RATE_COUNT);
            let next = if interval > held {
                (interval << 32) | 1
            } else if count < u64::from(limit) {
                seen.saturating_add(1)
            } else {
                return Err(EncRejection::OpenRate);
            };
            match word.compare_exchange_weak(seen, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(()),
                Err(now) => seen = now,
            }
        }
    }

    /// Opens charged to `kind` in the newest interval either counter has
    /// seen: 0 for a counter still in an older one.
    #[must_use]
    pub fn charged(&self, kind: KeyKind) -> u32 {
        let (word, _) = self.word(kind);
        let other = match kind {
            KeyKind::Committed => &self.words.scratch.0,
            KeyKind::Scratch => &self.words.committed.0,
        };
        let (seen, newest) = (word.load(Ordering::Acquire), other.load(Ordering::Acquire));
        if seen >> 32 < newest >> 32 {
            return 0;
        }
        u32::try_from(seen & RATE_COUNT).unwrap_or(u32::MAX)
    }

    /// A counter of `kind` already charged `count` times in the interval
    /// of `now_ns` (tests).
    #[cfg(test)]
    pub(crate) fn preset(kind: KeyKind, now_ns: u64, count: u32) -> Self {
        let rate = Self::default();
        let (word, _) = rate.word(kind);
        word.store(
            (((now_ns / SECOND_NS) & RATE_COUNT) << 32) | u64::from(count),
            Ordering::Release,
        );
        rate
    }
}

/// The per channel accounting of one receiving party: the rate counters
/// and the rejection counters. Fixed size, allocation free.
#[derive(Debug, Clone, Default)]
pub struct EncChannel {
    /// The open rate counters.
    pub rate: OpenRate,
    /// Rejections by reason.
    pub rejections: EncRejections,
}

/// Why encrypted keys cannot be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EncKeyError {
    /// A file of the other class, of another purpose or without a secret:
    /// one class per file (section 4a).
    #[error("the key file does not serve an encrypted channel")]
    Class,
    /// No file, or more than the slots hold, or two of one epoch.
    #[error("bad set of encrypted key files")]
    Files,
    /// A pairwise file of another receiver than the party's.
    #[error("the pairwise file names another receiver")]
    Receiver,
    /// No key file of the requested epoch.
    #[error("no key of that epoch")]
    NoKey,
    /// The derivation context is refused.
    #[error(transparent)]
    Context(#[from] ContextError),
    /// A VM generation change was seen: no key is derived again in this
    /// process (section 10).
    #[error("no key is derived after a VM generation change")]
    VmGeneration,
}

/// One secret of a `profile_id=16` file and its file epoch.
struct Secret {
    /// The `key_id` of its file, to follow the key store (H8 finding 4).
    key_id: u32,
    epoch: u32,
    /// The scope its file names (wire-key-files.md 2.2): a successor of
    /// another scope is never admitted in its place (H8-03).
    scope: Scope,
    secret: Zeroizing<[u8; KEY_LEN]>,
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secret")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id,
            epoch: self.epoch,
            scope: self.scope.clone(),
            secret: Zeroizing::new(*self.secret),
        }
    }
}

fn secret_of(file: &KeyFile, purpose: Purpose) -> Result<Secret, EncKeyError> {
    file.serves(Class::Encrypted, purpose)
        .map_err(|_| EncKeyError::Class)?;
    match &file.material {
        Material::Secret(secret) => Ok(Secret {
            key_id: file.key_id,
            epoch: file.file_epoch,
            scope: file.scope.clone(),
            secret: Zeroizing::new(**secret),
        }),
        Material::Public(_) => Err(EncKeyError::Class),
    }
}

/// Whether the key set still names `secret`'s file among those that
/// verify its `key_id` (H8 finding 4).
fn still_verifies(secret: &Secret, keys: &dyn crate::wire_auth::KeySet) -> bool {
    keys.verifying(secret.key_id)
        .iter()
        .flatten()
        .any(|file| file.file_epoch == secret.epoch)
}

/// The context a withdrawn sealer or opener erases its keys under (H8
/// finding 4): a bootstrap context of the same key epoch and publication,
/// with no receiver, salt or pairwise key. It is checked when the sealer
/// or opener is made, so the erasing re-key cannot be refused: the old key
/// is overwritten in place, whatever domain was current (a bootstrap or
/// domain 6 one included), and never survives a withdrawal. The erased key
/// is never used: a withdrawn sealer or opener refuses before any key is
/// read.
fn erase_context(context: &KeyContext) -> Result<KeyContext, ContextError> {
    let erase = KeyContext {
        domain: Domain::Setup,
        party_epoch: 0,
        receiver: None,
        salt: Salt::Empty,
        ..*context
    };
    erase.validate()?;
    Ok(erase)
}

/// Overwrites `key` in place with the all-zero key under `erase`, a
/// context [`erase_context`] checked: the re-key's every condition then
/// holds (a non-empty key, a valid bootstrap context, no pairwise key for
/// a non-receiver domain), so it always takes effect.
fn erase(key: &mut AesGcmSiv, erase: KeyContext) {
    let erased = key.rekey(&[0; KEY_LEN], erase, &[]);
    debug_assert!(erased.is_ok(), "the erase context was checked");
}

/// Erases a cached scratch or bootstrap key in place (H8-05): the slot
/// stays, so the data path still constructs no key, but no derived key
/// or pairwise HMAC state of a rotated or retired file survives in it.
/// Every use of such a slot re-keys it first. A slot whose context
/// cannot give an erase context is dropped, which erases it too.
pub(crate) fn erase_slot(slot: &mut Option<AesGcmSiv>) {
    let Some(key) = slot.as_mut() else {
        return;
    };
    match erase_context(key.context()) {
        Ok(context) => erase(key, context),
        Err(_) => *slot = None,
    }
}

/// The channel key ids a role keeps an activation floor for.
pub(crate) const ACTIVATION_FLOORS: usize = 64;

/// Per channel `key_id`, the highest file epoch a role has seen sign for
/// the boot (H8-17): kept by the role, not by a subscription or
/// publication, so one made again under a wall clock stepped back across
/// a successor's activation starts at that floor, never at 0. Fixed,
/// made with the role; it only rises. A key id it has no room for keeps
/// nothing binding (fail closed).
#[derive(Debug, Clone)]
pub(crate) struct ActivationFloors {
    floors: [(u32, u32); ACTIVATION_FLOORS],
    len: usize,
}

impl Default for ActivationFloors {
    fn default() -> Self {
        Self {
            floors: [(0, 0); ACTIVATION_FLOORS],
            len: 0,
        }
    }
}

impl ActivationFloors {
    /// Raises the floor of `keys`' key id to its activation and `keys` to
    /// the floor: both end at the higher. A key set of a key id the table
    /// has no room for binds nothing.
    pub(crate) fn hold(&mut self, keys: &mut ChannelKeys) {
        let Some(key_id) = keys.key_id() else {
            return;
        };
        let held = self.floors.get(..self.len).unwrap_or_default();
        let at = held.iter().position(|(id, _)| *id == key_id);
        let at = match at {
            Some(at) => at,
            None if self.len < ACTIVATION_FLOORS => {
                let at = self.len;
                if let Some(slot) = self.floors.get_mut(at) {
                    *slot = (key_id, 0);
                }
                self.len = at.saturating_add(1);
                at
            }
            None => {
                // Blocked, not an epoch: `u32::MAX` is a valid file epoch
                // (H8-22).
                keys.blocked = true;
                return;
            }
        };
        if let Some((_, floor)) = self.floors.get_mut(at) {
            *floor = (*floor).max(keys.activated);
            keys.activated = *floor;
        }
    }

    /// The floor of `key_id` (tests).
    #[cfg(test)]
    pub(crate) fn floor(&self, key_id: u32) -> Option<u32> {
        self.floors
            .get(..self.len)
            .and_then(|held| held.iter().find(|(id, _)| *id == key_id))
            .map(|(_, floor)| *floor)
    }
}

/// The channel key files of an `encrypted` channel: the `IKM` of every
/// section 4 derivation, selected by `key_epoch` (its file epoch).
#[derive(Debug, Clone)]
pub struct ChannelKeys {
    files: [Option<Secret>; CHANNEL_FILES],
    /// The held epoch the key set signs and sends with (wire-key-files.md
    /// 2.3, H8-06): every new sealer takes it, never the highest epoch that
    /// only verifies early. `None` once no held file signs: nothing new is
    /// sealed.
    signing: Option<u32>,
    /// The highest epoch it has seen sign (H8-17): the activation floor of
    /// [`Self::binds`]. It only rises, so a wall clock stepped back across
    /// a successor's activation, which selects the predecessor to sign
    /// again, never lets the predecessor bind again.
    activated: u32,
    /// The role's activation table had no room for its key id: it binds
    /// nothing, at any epoch (H8-22).
    blocked: bool,
}

impl ChannelKeys {
    /// The keys of `files`: one or two `profile_id=16` channel files of
    /// distinct epochs.
    ///
    /// # Errors
    ///
    /// [`EncKeyError::Class`] for a file of the other class or purpose
    /// (a wrong-class configuration is refused), [`EncKeyError::Files`]
    /// for no file, too many, or two of one epoch.
    pub fn new(files: &[&KeyFile]) -> Result<Self, EncKeyError> {
        if files.is_empty() || files.len() > CHANNEL_FILES {
            return Err(EncKeyError::Files);
        }
        let mut slots: [Option<Secret>; CHANNEL_FILES] = [None, None];
        for (slot, file) in slots.iter_mut().zip(files) {
            *slot = Some(secret_of(file, Purpose::Channel)?);
        }
        if let [Some(a), Some(b)] = &slots
            && a.epoch == b.epoch
        {
            return Err(EncKeyError::Files);
        }
        let mut keys = Self {
            files: slots,
            signing: None,
            activated: 0,
            blocked: false,
        };
        // Until a key set names its signing file, the highest held signs:
        // admission sets the one the view signs with
        // ([`ChannelKeys::set_signing`]), and every key set applied
        // follows it ([`ChannelKeys::follow_signing`]). The activation
        // floor starts at the first selection the view makes.
        keys.signing = Some(keys.current_epoch());
        Ok(keys)
    }

    /// The epoch every new sealer takes (H8-06); `None` once no held file
    /// signs.
    #[must_use]
    pub fn signing_epoch(&self) -> Option<u32> {
        self.signing
    }

    /// Makes `epoch` the signing epoch; `false`, with nothing changed,
    /// when it is not held.
    pub fn set_signing(&mut self, epoch: u32) -> bool {
        if self.ikm(epoch).is_none() {
            return false;
        }
        self.signing = Some(epoch);
        self.activated = self.activated.max(epoch);
        true
    }

    /// Takes the signing epoch from `keys`, the file it signs with for this
    /// `key_id` (its signing window, not its verify window; H8-06), or
    /// none when that file is not held or no file signs.
    pub fn follow_signing(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        self.signing = self
            .key_id()
            .and_then(|key_id| keys.signing(key_id))
            .map(|file| file.file_epoch)
            .filter(|epoch| self.ikm(*epoch).is_some());
        if let Some(epoch) = self.signing {
            self.activated = self.activated.max(epoch);
        }
    }

    /// The lowest held epoch: every file epoch below it no longer verifies
    /// (H8-07).
    #[must_use]
    pub fn oldest_epoch(&self) -> Option<u32> {
        self.files.iter().flatten().map(|file| file.epoch).min()
    }

    /// Drops every file and the signing epoch (a withdrawal).
    fn clear(&mut self) {
        self.files = [None, None];
        self.signing = None;
    }

    /// Whether a bootstrap datagram verified under `key_epoch` may create
    /// or change a binding (section 7, H8-12): the active binding epoch is
    /// the signing one, so during a successor's early verify allowance its
    /// predecessor, which every party still sends under, binds, and so
    /// does the successor already; once the successor signs, the retired
    /// predecessor binds nothing, even when a backward wall-clock step
    /// selects it to sign again: nothing below the highest epoch seen to
    /// sign binds (H8-17). With no file signing nothing binds (fail
    /// closed).
    #[must_use]
    pub fn binds(&self, key_epoch: u32) -> bool {
        self.binding_epoch()
            .is_some_and(|binding| key_epoch >= binding && self.ikm(key_epoch).is_some())
    }

    /// The active binding epoch (H8-12, H8-17): the signing epoch, never
    /// below the highest epoch seen to sign; `None` with no file signing,
    /// or for a key id the role's activation table has no room for.
    #[must_use]
    pub fn binding_epoch(&self) -> Option<u32> {
        if self.blocked {
            return None;
        }
        self.signing.map(|signing| signing.max(self.activated))
    }

    /// The highest file epoch held, which may only verify yet (a
    /// successor in its early verify allowance): never the binding
    /// epoch, which is [`Self::binds`]'s (H8-12).
    #[must_use]
    pub fn current_epoch(&self) -> u32 {
        self.files
            .iter()
            .flatten()
            .map(|file| file.epoch)
            .max()
            .unwrap_or(0)
    }

    /// Drops, and so erases, every file the key set no longer names to
    /// verify (revoked, expired, or the store disabled; H8 finding 4).
    /// Returns whether one was dropped.
    pub fn retain(&mut self, keys: &dyn crate::wire_auth::KeySet) -> bool {
        let mut dropped = false;
        for slot in &mut self.files {
            if slot
                .take_if(|secret| !still_verifies(secret, keys))
                .is_some()
            {
                dropped = true;
            }
        }
        if self.signing.is_some_and(|epoch| self.ikm(epoch).is_none()) {
            self.signing = None;
        }
        dropped
    }

    /// The `IKM` of `key_epoch`, if held.
    fn ikm(&self, key_epoch: u32) -> Option<&[u8; KEY_LEN]> {
        self.files
            .iter()
            .flatten()
            .find(|file| file.epoch == key_epoch)
            .map(|file| &*file.secret)
    }

    /// The `key_id` of its files; `None` once every file is gone.
    pub(crate) fn key_id(&self) -> Option<u32> {
        self.files.iter().flatten().map(|file| file.key_id).next()
    }

    /// Admits every file of its `key_id` the key set names to verify and
    /// it does not hold yet (rotation, ADR-0114 section 6 and ADR-0086
    /// section 7): into a free slot, or in place of a lower epoch. A file
    /// of the other class, purpose or profile, or of another scope than
    /// the held files' (`channel_id` and `stream_id`, H8-03), is not
    /// admitted. Returns whether one was.
    pub fn admit(&mut self, keys: &dyn crate::wire_auth::KeySet) -> bool {
        let Some(key_id) = self.key_id() else {
            return false;
        };
        let Some(scope) = self
            .files
            .iter()
            .flatten()
            .map(|file| file.scope.clone())
            .next()
        else {
            return false;
        };
        let mut admitted = false;
        for file in keys.verifying(key_id).into_iter().flatten() {
            if self.ikm(file.file_epoch).is_some() || file.scope != scope {
                continue;
            }
            let Ok(secret) = secret_of(file, Purpose::Channel) else {
                continue;
            };
            let lowest = self
                .files
                .iter()
                .flatten()
                .map(|held| held.epoch)
                .min()
                .unwrap_or(0);
            let at = self.files.iter().position(Option::is_none).or_else(|| {
                self.files.iter().position(|slot| {
                    slot.as_ref()
                        .is_some_and(|held| held.epoch == lowest && lowest < secret.epoch)
                })
            });
            if let Some(slot) = at.and_then(|at| self.files.get_mut(at)) {
                *slot = Some(secret);
                admitted = true;
            }
        }
        admitted
    }

    /// The lowest held epoch above `key_epoch`.
    fn next_epoch(&self, key_epoch: u32) -> Option<u32> {
        self.files
            .iter()
            .flatten()
            .map(|file| file.epoch)
            .filter(|epoch| *epoch > key_epoch)
            .min()
    }

    /// Each held file epoch and its IKM, the inputs of a receive shard's
    /// domain 5 scratch derivations (ADR-0127 decision 2, step 4): the
    /// epochs a SETUP is accepted under, as in [`open_bootstrap`]. Each
    /// copy is erased on drop.
    pub(crate) fn shard_setup(&self) -> [Option<shards::SetupView>; CHANNEL_FILES] {
        self.files.each_ref().map(|file| {
            file.as_ref().map(|file| shards::SetupView {
                epoch: file.epoch,
                ikm: Zeroizing::new(*file.secret),
            })
        })
    }
}

/// One pairwise file: its receiver and epoch, and whether it is the one
/// its receiver's trailers are sealed with (its signing window, H8-06).
#[derive(Debug, Clone)]
struct PairwiseFile {
    receiver_id: u64,
    secret: Secret,
    signs: bool,
}

/// The pairwise key files of an `encrypted` channel's configuration
/// (section 4): on a receiver its own, on a publisher one or two epochs
/// for each receiver it serves.
#[derive(Debug, Clone)]
pub struct PairwiseFiles {
    files: [Option<PairwiseFile>; PAIRWISE_FILES],
}

impl PairwiseFiles {
    /// The files of `files`, each a `profile_id=16` pairwise file.
    ///
    /// # Errors
    ///
    /// [`EncKeyError::Class`] for a file of the other class or purpose;
    /// [`EncKeyError::Files`] for none or too many, or two with one
    /// receiver and epoch. A receiver whose configuration names no
    /// pairwise key cannot join an `encrypted` channel (section 4).
    pub fn new(files: &[&KeyFile]) -> Result<Self, EncKeyError> {
        if files.is_empty() || files.len() > PAIRWISE_FILES {
            return Err(EncKeyError::Files);
        }
        let mut slots: [Option<PairwiseFile>; PAIRWISE_FILES] = [None, None, None, None];
        for (index, file) in files.iter().enumerate() {
            let Scope::Pairwise { receiver_id, .. } = file.scope else {
                return Err(EncKeyError::Class);
            };
            let secret = secret_of(file, Purpose::Pairwise)?;
            let duplicate = slots
                .iter()
                .flatten()
                .any(|held| held.receiver_id == receiver_id && held.secret.epoch == secret.epoch);
            if duplicate {
                return Err(EncKeyError::Files);
            }
            if let Some(slot) = slots.get_mut(index) {
                *slot = Some(PairwiseFile {
                    receiver_id,
                    secret,
                    signs: false,
                });
            }
        }
        let mut files = Self { files: slots };
        // Until a key set names the signing files, each receiver's highest
        // epoch signs: every key set applied, the admission view first,
        // sets the one it signs with ([`Self::follow_signing`]).
        for at in 0..PAIRWISE_FILES {
            let Some((receiver_id, epoch)) = files
                .files
                .get(at)
                .and_then(Option::as_ref)
                .map(|file| (file.receiver_id, file.secret.epoch))
            else {
                continue;
            };
            let highest = files.epochs_of(receiver_id)[0] == Some(epoch);
            if let Some(Some(file)) = files.files.get_mut(at) {
                file.signs = highest;
            }
        }
        Ok(files)
    }

    /// Takes the signing file of each held pairwise `key_id` from `keys`
    /// (its signing window, not its verify window; H8-06): a held file
    /// signs exactly when the key set signs with it, so a successor in its
    /// early verify allowance and a predecessor past its signing expiry
    /// only verify.
    pub fn follow_signing(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        for file in self.files.iter_mut().flatten() {
            file.signs = keys.signing(file.secret.key_id).is_some_and(|signing| {
                signing.file_epoch == file.secret.epoch && signing.scope == file.secret.scope
            });
        }
    }

    /// Drops, and so erases, every file the key set no longer names to
    /// verify (H8 finding 4). Returns whether one was dropped.
    pub fn retain(&mut self, keys: &dyn crate::wire_auth::KeySet) -> bool {
        let mut dropped = false;
        for slot in &mut self.files {
            if slot
                .take_if(|file| !still_verifies(&file.secret, keys))
                .is_some()
            {
                dropped = true;
            }
        }
        dropped
    }

    /// Admits every pairwise file of a receiver it already serves that the
    /// key set names to verify and it does not hold yet (rotation): into a
    /// free slot, or in place of that receiver's lower epoch. Returns
    /// whether one was.
    pub fn admit(&mut self, keys: &dyn crate::wire_auth::KeySet) -> bool {
        let mut key_ids: [Option<u32>; PAIRWISE_FILES] = [None; PAIRWISE_FILES];
        for (slot, file) in key_ids.iter_mut().zip(self.files.iter().flatten()) {
            *slot = Some(file.secret.key_id);
        }
        let mut admitted = false;
        for key_id in key_ids.into_iter().flatten() {
            for file in keys.verifying(key_id).into_iter().flatten() {
                let Scope::Pairwise { receiver_id, .. } = file.scope else {
                    continue;
                };
                // The successor must name the held file's whole scope:
                // `receiver_id` and `publisher_id` (H8-03).
                let served = self.files.iter().flatten().any(|held| {
                    held.receiver_id == receiver_id
                        && held.secret.key_id == key_id
                        && held.secret.scope == file.scope
                });
                let [highest, lowest] = self.epochs_of(receiver_id);
                if !served || [highest, lowest].contains(&Some(file.file_epoch)) {
                    continue;
                }
                let Ok(secret) = secret_of(file, Purpose::Pairwise) else {
                    continue;
                };
                let lower = lowest.or(highest).filter(|epoch| *epoch < secret.epoch);
                let at = self.files.iter().position(Option::is_none).or_else(|| {
                    self.files.iter().position(|slot| {
                        slot.as_ref().is_some_and(|held| {
                            held.receiver_id == receiver_id && Some(held.secret.epoch) == lower
                        })
                    })
                });
                if let Some(slot) = at.and_then(|at| self.files.get_mut(at)) {
                    *slot = Some(PairwiseFile {
                        receiver_id,
                        secret,
                        signs: false,
                    });
                    admitted = true;
                }
            }
        }
        admitted
    }

    /// The epochs held for `receiver_id`, highest first.
    fn epochs_of(&self, receiver_id: u64) -> [Option<u32>; 2] {
        let mut out: [Option<u32>; 2] = [None, None];
        for file in self
            .files
            .iter()
            .flatten()
            .filter(|file| file.receiver_id == receiver_id)
        {
            let epoch = Some(file.secret.epoch);
            out = match out {
                [None, _] => [epoch, None],
                [Some(first), _] if file.secret.epoch > first => [epoch, Some(first)],
                [first, _] => [first, epoch],
            };
        }
        out
    }

    /// Whether a file names `receiver_id`.
    #[must_use]
    pub fn names(&self, receiver_id: u64) -> bool {
        self.files
            .iter()
            .flatten()
            .any(|file| file.receiver_id == receiver_id)
    }

    /// The pairwise keys of `receiver` for the target `publication`, the
    /// first the one that seals, every one verifying. For a sealer
    /// (`seal`) the first is the receiver's signing file (H8-06); for an
    /// opener the highest epoch comes first. Allocates nothing.
    ///
    /// # Errors
    ///
    /// [`EncKeyError::Receiver`] when no file names the receiver, or, for
    /// a sealer, none of its files signs.
    pub fn keys(
        &self,
        receiver: &ReceiverIdentity,
        publication: &PublicationIdentity,
        seal: bool,
    ) -> Result<([Option<PairwiseKey>; 2], usize), EncKeyError> {
        let mut out: [Option<PairwiseKey>; 2] = [None, None];
        let mut count = 0_usize;
        let mut epochs: [Option<u32>; 2] = [None, None];
        for file in self
            .files
            .iter()
            .flatten()
            .filter(|file| file.receiver_id == receiver.receiver_id)
        {
            if let Some(slot) = epochs.get_mut(count) {
                *slot = Some(file.secret.epoch);
                count = count.saturating_add(1);
            }
        }
        if count == 0 {
            return Err(EncKeyError::Receiver);
        }
        if let [Some(a), Some(b)] = epochs
            && b > a
        {
            epochs = [Some(b), Some(a)];
        }
        if seal {
            let signing = self
                .files
                .iter()
                .flatten()
                .find(|file| file.receiver_id == receiver.receiver_id && file.signs)
                .map(|file| file.secret.epoch)
                .ok_or(EncKeyError::Receiver)?;
            if epochs[0] != Some(signing) {
                epochs = [Some(signing), epochs[0]];
            }
        }
        for (slot, epoch) in out.iter_mut().zip(epochs) {
            let Some(epoch) = epoch else { continue };
            let file = self.files.iter().flatten().find(|file| {
                file.receiver_id == receiver.receiver_id && file.secret.epoch == epoch
            });
            if let Some(file) = file {
                *slot = Some(PairwiseKey::derive(
                    &*file.secret.secret,
                    epoch,
                    receiver,
                    publication,
                )?);
            }
        }
        Ok((out, count))
    }
}

/// The key of `context`, with the pairwise keys of its receiver domain:
/// for a sealer (`seal`) the signing one first (H8-06).
fn derive(
    keys: &ChannelKeys,
    pairwise: Option<&PairwiseFiles>,
    context: KeyContext,
    seal: bool,
) -> Result<AesGcmSiv, EncKeyError> {
    if quiesced() {
        return Err(EncKeyError::VmGeneration);
    }
    let ikm = keys.ikm(context.key_epoch).ok_or(EncKeyError::NoKey)?;
    match (context.domain.is_receiver(), context.receiver, pairwise) {
        (true, Some(receiver), Some(files)) => {
            let ([first, second], _) = files.keys(&receiver, &context.publication, seal)?;
            match (first, second) {
                (Some(a), Some(b)) => Ok(AesGcmSiv::new(ikm, context, &[a, b])?),
                (Some(a), None) => Ok(AesGcmSiv::new(ikm, context, &[a])?),
                _ => Err(EncKeyError::Receiver),
            }
        }
        (true, _, _) => Err(EncKeyError::Receiver),
        (false, _, _) => Ok(AesGcmSiv::new(ikm, context, &[])?),
    }
}

/// Re-keys `slot` in place for `context` (see [`AesGcmSiv::rekey`]):
/// the data path never constructs a key, so it never sets up a mutex.
/// For a sealer (`seal`) the signing pairwise key seals (H8-06).
fn derive_into(
    keys: &ChannelKeys,
    pairwise: Option<&PairwiseFiles>,
    context: KeyContext,
    slot: &mut AesGcmSiv,
    seal: bool,
) -> Result<(), EncKeyError> {
    if quiesced() {
        return Err(EncKeyError::VmGeneration);
    }
    let ikm = keys.ikm(context.key_epoch).ok_or(EncKeyError::NoKey)?;
    match (context.domain.is_receiver(), context.receiver, pairwise) {
        (true, Some(receiver), Some(files)) => {
            let ([first, second], _) = files.keys(&receiver, &context.publication, seal)?;
            match (first, second) {
                (Some(a), Some(b)) => Ok(slot.rekey(ikm, context, &[a, b])?),
                (Some(a), None) => Ok(slot.rekey(ikm, context, &[a])?),
                _ => Err(EncKeyError::Receiver),
            }
        }
        (true, _, _) => Err(EncKeyError::Receiver),
        (false, _, _) => Ok(slot.rekey(ikm, context, &[])?),
    }
}

/// Replaces the pairwise keys of a receiver domain `key` with those
/// `files` now hold for its receiver and publication, for a sealer
/// (`seal`) the signing one sealing (H8-05, H8-06): a pairwise-only
/// rotation, or the removal of a retired pairwise file, reaches the key
/// without touching its AEAD key, sequence or replay window. A key of
/// domain 1 or 5 is left as it is.
///
/// # Errors
///
/// [`EncKeyError::Receiver`] when no file names its receiver any more, or,
/// for a sealer, none of them signs.
fn refresh_pairwise(
    key: &mut AesGcmSiv,
    files: Option<&PairwiseFiles>,
    seal: bool,
) -> Result<(), EncKeyError> {
    let context = *key.context();
    let Some(receiver) = context.receiver.filter(|_| context.domain.is_receiver()) else {
        return Ok(());
    };
    let files = files.ok_or(EncKeyError::Receiver)?;
    let ([first, second], _) = files.keys(&receiver, &context.publication, seal)?;
    match (first, second) {
        (Some(a), Some(b)) => Ok(key.set_pairwise(&[a, b])?),
        (Some(a), None) => Ok(key.set_pairwise(&[a])?),
        _ => Err(EncKeyError::Receiver),
    }
}

/// The selector fields of an envelope header: untrusted until its tag
/// verifies (section 2). They select a key to try and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// `domain`.
    pub domain: Domain,
    /// `key_epoch`.
    pub key_epoch: u32,
    /// `party_epoch`.
    pub party_epoch: u16,
    /// `session_id`.
    pub session_id: i32,
    /// `stream_id`.
    pub stream_id: i32,
    /// `envelope_seq`.
    pub seq: u64,
    /// The encrypting publication in domains 1 and 5.
    pub publication: Option<PublicationIdentity>,
    /// The encrypting receiver in domains 4 and 6.
    pub receiver: Option<ReceiverIdentity>,
}

fn le<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], EncRejection> {
    bytes
        .get(at..at.saturating_add(N))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(EncRejection::Short)
}

/// Step 1 of section 8 for any datagram on an `encrypted` channel: the
/// outer class (section 9), the length (at most [`MAX_DATAGRAM`]), the
/// fixed fields, `profile_id` and `domain`; then the selectors. Changes
/// nothing.
///
/// # Errors
///
/// The first [`EncRejection`] that applies; a bare frame, an
/// authenticated envelope and a plaintext SETUP are each told apart.
pub fn header(datagram: &[u8]) -> Result<Header, EncRejection> {
    let frame_type = u16::from_le_bytes(le::<2>(datagram, 6)?);
    classify_outer(frame_type)?;
    if datagram.len() < ENVELOPE_LEN {
        return Err(EncRejection::Short);
    }
    if datagram.len() > MAX_DATAGRAM {
        return Err(EncRejection::TooLong);
    }
    let declared = i32::from_le_bytes(le::<4>(datagram, 0)?);
    match usize::try_from(declared) {
        Ok(declared) if declared == datagram.len() => {}
        Ok(declared) if declared >= ENVELOPE_LEN && declared < datagram.len() => {
            return Err(EncRejection::MixedClass);
        }
        _ => return Err(EncRejection::Length),
    }
    let byte = |at: usize| datagram.get(at).copied().unwrap_or_default();
    if byte(4) != karyos_protocol::protection::aes_gcm_siv::VERSION {
        return Err(EncRejection::Version);
    }
    if byte(5) != 0 {
        return Err(EncRejection::Flags);
    }
    if byte(8) != PROFILE_ID {
        return Err(EncRejection::Profile);
    }
    if usize::from(byte(9)) != karyos_protocol::protection::aes_gcm_siv::TAG_LEN {
        return Err(EncRejection::TagLength);
    }
    let domain = Domain::from_byte(byte(10)).ok_or(EncRejection::Domain)?;
    if byte(11) != 0 || le::<2>(datagram, 18)? != [0, 0] {
        return Err(EncRejection::Reserved);
    }
    let party: [u8; 32] = le(datagram, 36)?;
    let (publication, receiver) = if domain.is_receiver() {
        if party.get(24..) != Some(&[0_u8; 8][..]) {
            return Err(EncRejection::Reserved);
        }
        let receiver = ReceiverIdentity {
            receiver_boot_id: le(&party, 0)?,
            receiver_id: u64::from_le_bytes(le(&party, 16)?),
        };
        (None, Some(receiver))
    } else {
        let publication = PublicationIdentity {
            driver_id: le(&party, 0)?,
            registration_id: u64::from_le_bytes(le(&party, 16)?),
            incarnation: u64::from_le_bytes(le(&party, 24)?),
        };
        (Some(publication), None)
    };
    Ok(Header {
        domain,
        key_epoch: u32::from_le_bytes(le(datagram, 12)?),
        party_epoch: u16::from_le_bytes(le(datagram, 16)?),
        session_id: i32::from_le_bytes(le(datagram, 20)?),
        stream_id: i32::from_le_bytes(le(datagram, 24)?),
        seq: u64::from_le_bytes(le(datagram, 28)?),
        publication,
        receiver,
    })
}

/// Whether `bytes` is an encrypted envelope by its outer frame type.
#[must_use]
pub fn is_envelope(bytes: &[u8]) -> bool {
    bytes
        .get(6..8)
        .is_some_and(|field| field == FRAME_TYPE.to_le_bytes())
}

/// The frame and domain matrix of section 9, on the opened inner frames
/// before any takes effect: every frame's type must be allowed in
/// `domain`, domains 5 and 6 carry exactly one frame, and the class part
/// ([`check_inner_classes`]) refuses an inner envelope. GUARD,
/// SESSION_ABORT and SESSION_ABORT_ACK stay refused until ADR-0086 open
/// point 5 fixes their bodies ("Assigned to the implementation", item 2).
///
/// # Errors
///
/// [`EncRejection::MixedClass`] for an inner envelope and
/// [`EncRejection::InnerRejected`] for any other forbidden or malformed
/// frame: the whole datagram is refused.
pub fn check_matrix(domain: Domain, frames: &[u8]) -> Result<(), EncRejection> {
    check_inner_classes(frames)?;
    let alignment = usize::try_from(karyos_protocol::frame::FRAME_ALIGNMENT).unwrap_or(32);
    let mut at = 0_usize;
    let mut count = 0_usize;
    while let Some(rest) = frames.get(at..).filter(|rest| !rest.is_empty()) {
        let code = u16::from_le_bytes(le::<2>(rest, 6).map_err(|_| EncRejection::InnerRejected)?);
        let frame_type = FrameType::try_from_code(code).map_err(|_| EncRejection::InnerRejected)?;
        let allowed = match domain {
            Domain::Sender => matches!(
                frame_type,
                FrameType::Data
                    | FrameType::Pad
                    | FrameType::Aborted
                    | FrameType::PathHb
                    | FrameType::Setup
                    | FrameType::Err
                    | FrameType::Rttm
            ),
            Domain::Receiver => matches!(
                frame_type,
                FrameType::Sm | FrameType::Nak | FrameType::Err | FrameType::Rttm
            ),
            Domain::Setup => frame_type == FrameType::Setup,
            Domain::RspSetup => frame_type == FrameType::RspSetup,
        };
        if !allowed {
            return Err(EncRejection::InnerRejected);
        }
        let length = usize::try_from(i32::from_le_bytes(
            le::<4>(rest, 0).map_err(|_| EncRejection::InnerRejected)?,
        ))
        .map_err(|_| EncRejection::InnerRejected)?;
        let stride = length
            .div_ceil(alignment)
            .saturating_mul(alignment)
            .clamp(alignment, rest.len().max(1));
        at = at.saturating_add(stride);
        count = count.saturating_add(1);
    }
    if count == 0 || (domain.is_bootstrap() && count != 1) {
        return Err(EncRejection::InnerRejected);
    }
    Ok(())
}

/// The process monotonic clock in nanoseconds, for a sealer that seals a
/// control without a caller's reading.
#[must_use]
pub fn monotonic_ns() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Why a seal is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EncSendError {
    /// The profile refused the seal.
    #[error(transparent)]
    Seal(#[from] EncSealError),
    /// Every `party_epoch` is used: the party stops sending in this domain
    /// and the incarnation closes (section 6, "Epoch capacity").
    #[error("the party epochs of this key epoch are exhausted")]
    EpochsExhausted,
    /// Over `BOOTSTRAP_SEALS_PER_S` seals of a bootstrap key this second.
    #[error("the bootstrap seal rate is exceeded")]
    Rate,
    /// The next epoch could not be derived.
    #[error(transparent)]
    Key(#[from] EncKeyError),
    /// The key was withdrawn by a key reload (H8 finding 4).
    #[error("the key was withdrawn")]
    Withdrawn,
    /// A VM generation change was seen: nothing is sealed again in this
    /// process (section 10).
    #[error("nothing is sealed after a VM generation change")]
    VmGeneration,
}

/// One encrypting party in one domain (section 5): its key, rolled to the
/// next `party_epoch` before any data key budget is reached (2^32
/// datagrams, 2^42 bytes, 1 hour), or rate capped for a bootstrap key.
/// The key files it derives from are held so that a roll allocates
/// nothing.
pub struct EncSealer {
    keys: ChannelKeys,
    pairwise: Option<PairwiseFiles>,
    key: AesGcmSiv,
    derived_ns: u64,
    rate_interval: AtomicU64,
    clock: fn() -> u64,
    /// The checked context its key is erased under on withdrawal.
    erase: KeyContext,
    /// Withdrawn by a key reload (H8 finding 4): checked first by every
    /// seal, roll and re-key, so it never seals again.
    withdrawn: bool,
    /// The VM generation it was made in: it seals nothing in a later one
    /// (section 10).
    generation: u64,
}

impl core::fmt::Debug for EncSealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncSealer")
            .field("context", self.key.context())
            .finish_non_exhaustive()
    }
}

impl EncSealer {
    /// The sealer of `context` from the channel `keys` (and, in domains 4
    /// and 6, the receiver's `pairwise` files), its key derived at `now_ns`
    /// of `clock`.
    ///
    /// # Errors
    ///
    /// [`EncKeyError`] when the context or the files do not fit.
    pub fn new(
        keys: &ChannelKeys,
        pairwise: Option<&PairwiseFiles>,
        context: KeyContext,
        clock: fn() -> u64,
    ) -> Result<Self, EncKeyError> {
        let key = derive(keys, pairwise, context, true)?;
        Ok(Self {
            keys: keys.clone(),
            pairwise: pairwise.cloned(),
            key,
            derived_ns: clock(),
            rate_interval: AtomicU64::new(0),
            clock,
            erase: erase_context(&context)?,
            withdrawn: false,
            generation: vm_generation::generation(),
        })
    }

    /// Withdraws it (H8 finding 4): its key files are dropped and its key
    /// is replaced in place, both erased on drop, and every later seal,
    /// roll or re-key is refused with [`EncSendError::Withdrawn`].
    pub fn withdraw(&mut self) {
        self.withdrawn = true;
        self.keys.clear();
        self.pairwise = None;
        erase(&mut self.key, self.erase);
    }

    /// Whether it was withdrawn.
    #[must_use]
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn
    }

    /// Applies the key store's current key set (H8 finding 4): files no
    /// longer named are erased; once its own key epoch is revoked or
    /// expired, or no held file signs any more (signing expiry, H8-06), or
    /// no pairwise file of its receiver is left, it is withdrawn (fail
    /// closed). Its pairwise keys follow the files held, so a pairwise-only
    /// rotation reaches it with its sequence kept (H8-05).
    pub fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        if self.withdrawn {
            return;
        }
        // Only its own key matters: the channel file of its key epoch and,
        // in a receiver domain, the pairwise files of its receiver. An
        // unrelated file dropped leaves it, and its sequence, as it is: a
        // rebuilt sealer would reuse nonces. A successor is admitted before
        // its predecessor goes, so one key set that does both keeps the
        // pairwise side served (H8-05).
        let epoch = self.key.context().key_epoch;
        self.keys.admit(keys);
        if let Some(pairwise) = self.pairwise.as_mut() {
            pairwise.admit(keys);
        }
        self.keys.retain(keys);
        if let Some(pairwise) = self.pairwise.as_mut() {
            pairwise.retain(keys);
            pairwise.follow_signing(keys);
        }
        self.keys.follow_signing(keys);
        // Sending is the signing window's only (H8-06): no file signing, or
        // a signing epoch below its own, and it seals nothing again.
        let Some(signing) = self
            .keys
            .signing_epoch()
            .filter(|signing| *signing >= epoch && self.keys.ikm(epoch).is_some())
        else {
            self.withdraw();
            return;
        };
        if refresh_pairwise(&mut self.key, self.pairwise.as_ref(), true).is_err() {
            self.withdraw();
            return;
        }
        // Rotation (section 6): a newly admitted file epoch that the key
        // set signs with becomes the sealer's key epoch at the next
        // datagram, `party_epoch` 0, under a key whose context names the
        // new epoch, so its sequence restarting at 0 reuses no nonce.
        if signing > epoch {
            let mut next = *self.key.context();
            next.key_epoch = signing;
            next.party_epoch = 0;
            if derive_into(
                &self.keys,
                self.pairwise.as_ref(),
                next,
                &mut self.key,
                true,
            )
            .is_ok()
            {
                self.derived_ns = (self.clock)();
            } else {
                // The key may be half re-keyed: never seal under it.
                self.withdraw();
            }
        }
    }

    /// The current key's context.
    #[must_use]
    pub fn context(&self) -> &KeyContext {
        self.key.context()
    }

    /// The sealer's key, as a slot to re-key: a scratch slot made ahead of
    /// the data path.
    #[must_use]
    pub fn into_key(self) -> AesGcmSiv {
        self.key
    }

    /// The domain it seals in.
    #[must_use]
    pub fn domain(&self) -> Domain {
        self.key.context().domain
    }

    /// Bytes each datagram grows by: envelope and, in domains 4 and 6, the
    /// pairwise trailer.
    #[must_use]
    pub fn overhead(&self) -> usize {
        self.key.overhead()
    }

    /// Whether a data key must move to the next epoch before sealing
    /// `protected` more bytes at `now_ns` (section 6 budgets).
    fn must_roll(&self, protected: u64, now_ns: u64) -> bool {
        !self.domain().is_bootstrap()
            && (self.key.next_seq() >= SEND_ROLL_DATAGRAMS
                || self.key.sealed_bytes().saturating_add(protected) > SEND_ROLL_BYTES
                || now_ns.saturating_sub(self.derived_ns) >= SEND_AGE_NS)
    }

    /// Moves to the next `party_epoch` under the same `key_epoch`.
    fn roll(&mut self, now_ns: u64) -> Result<(), EncSendError> {
        if self.withdrawn {
            return Err(EncSendError::Withdrawn);
        }
        let mut next = *self.key.context();
        next.party_epoch = next
            .party_epoch
            .checked_add(1)
            .ok_or(EncSendError::EpochsExhausted)?;
        derive_into(
            &self.keys,
            self.pairwise.as_ref(),
            next,
            &mut self.key,
            true,
        )?;
        self.derived_ns = now_ns;
        Ok(())
    }

    /// Counts one bootstrap seal at `now_ns`, at most
    /// `BOOTSTRAP_SEALS_PER_S` per second. The interval and its count
    /// share one word: the second in the high 40 bits, the count below.
    fn charge_bootstrap(&self, now_ns: u64) -> Result<(), EncSendError> {
        let second = now_ns / SECOND_NS;
        self.rate_interval
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |word| {
                let (at, count) = (word >> 24, word & 0x00FF_FFFF);
                if at != second {
                    Some((second << 24) | 1)
                } else if count < u64::from(BOOTSTRAP_SEALS_PER_S) {
                    Some(word.saturating_add(1))
                } else {
                    None
                }
            })
            .map(|_| ())
            .map_err(|_| EncSendError::Rate)
    }

    /// Seals the `frames` bytes at the start of `datagram`, rolling first
    /// when a budget would be passed. Allocates nothing.
    ///
    /// # Errors
    ///
    /// [`EncSendError`]; nothing is written.
    pub fn seal(&mut self, datagram: &mut [u8], frames: usize) -> Result<usize, EncSendError> {
        self.seal_as(datagram, frames, None)
    }

    /// Seals as [`Self::seal`], the header naming `alias` (`session_id`,
    /// `stream_id`) instead of its context's when given: the selectors
    /// are no HKDF input, so the key and its one sequence are the same on
    /// every alias (H8-14). Allocates nothing.
    ///
    /// # Errors
    ///
    /// [`EncSendError`]; nothing is written.
    pub fn seal_as(
        &mut self,
        datagram: &mut [u8],
        frames: usize,
        alias: Option<(i32, i32)>,
    ) -> Result<usize, EncSendError> {
        if self.generation != vm_generation::generation() {
            return Err(EncSendError::VmGeneration);
        }
        if self.withdrawn {
            return Err(EncSendError::Withdrawn);
        }
        let now_ns = (self.clock)();
        if self.domain().is_bootstrap() {
            self.charge_bootstrap(now_ns)?;
        }
        // The protected bytes as the seal charges them: the header, the
        // frames and, in domains 4 and 6, the pairwise trailer.
        let trailer = self.key.overhead().saturating_sub(ENVELOPE_LEN);
        let protected = u64::try_from(HEADER_LEN.saturating_add(frames).saturating_add(trailer))
            .unwrap_or(u64::MAX);
        if self.must_roll(protected, now_ns) {
            self.roll(now_ns)?;
        }
        #[cfg(test)]
        let plaintext = recording().then(|| datagram.get(..frames).map(<[u8]>::to_vec));
        let context = *self.key.context();
        let alias = alias.unwrap_or((context.session_id, context.stream_id));
        let sealed = self.key.seal_next_as(datagram, frames, alias)?;
        #[cfg(test)]
        if let Some(Some(frames)) = plaintext {
            record(SealedRecord {
                context: KeyContext {
                    session_id: alias.0,
                    stream_id: alias.1,
                    ..context
                },
                seq: self.key.next_seq().saturating_sub(1),
                frames,
            });
        }
        Ok(sealed)
    }

    /// Moves to the next `party_epoch` now, as a budget would (tests).
    #[cfg(test)]
    pub(crate) fn roll_now(&mut self) {
        let now = (self.clock)();
        let _ = self.roll(now);
    }

    /// The current key (tests).
    #[cfg(test)]
    pub(crate) fn key(&self) -> &AesGcmSiv {
        &self.key
    }
}

/// One datagram a sealer sealed: its key's context, its envelope
/// sequence and its plaintext frames (tests).
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct SealedRecord {
    pub(crate) context: KeyContext,
    pub(crate) seq: u64,
    pub(crate) frames: Vec<u8>,
}

#[cfg(test)]
thread_local! {
    static SEALED: core::cell::RefCell<Option<Vec<SealedRecord>>> =
        const { core::cell::RefCell::new(None) };
}

#[cfg(test)]
fn recording() -> bool {
    SEALED.with(|sealed| sealed.borrow().is_some())
}

#[cfg(test)]
fn record(record: SealedRecord) {
    SEALED.with(|sealed| {
        if let Some(sealed) = sealed.borrow_mut().as_mut() {
            sealed.push(record);
        }
    });
}

/// Starts recording every seal on this thread (tests).
#[cfg(test)]
pub(crate) fn record_seals() {
    SEALED.with(|sealed| *sealed.borrow_mut() = Some(Vec::new()));
}

/// Stops recording and returns what was sealed since [`record_seals`]
/// (tests).
#[cfg(test)]
pub(crate) fn take_seals() -> Vec<SealedRecord> {
    SEALED.with(|sealed| sealed.borrow_mut().take().unwrap_or_default())
}

/// A sender datagram sealer of either class, as the repair path uses it.
pub trait DatagramSeal {
    /// Whether one more datagram can be sealed.
    fn can_seal(&self) -> bool;
    /// Bytes each sealed datagram grows by.
    fn envelope(&self) -> usize;
    /// Seals the first `frames` bytes of `datagram`; `None` when it cannot
    /// be sealed, and nothing may then be sent.
    fn seal_datagram(&mut self, datagram: &mut [u8], frames: usize) -> Option<usize>;
}

impl DatagramSeal for crate::wire_auth::Sealer {
    fn can_seal(&self) -> bool {
        crate::wire_auth::Sealer::can_seal(self)
    }

    fn envelope(&self) -> usize {
        crate::wire_auth::ENVELOPE_LEN
    }

    fn seal_datagram(&mut self, datagram: &mut [u8], frames: usize) -> Option<usize> {
        self.seal(datagram, frames).ok()
    }
}

impl DatagramSeal for EncSealer {
    /// It rolls its epoch itself; a seal it refuses sends nothing. A
    /// withdrawn one never seals.
    fn can_seal(&self) -> bool {
        !self.withdrawn
    }

    fn envelope(&self) -> usize {
        ENVELOPE_LEN
    }

    fn seal_datagram(&mut self, datagram: &mut [u8], frames: usize) -> Option<usize> {
        self.seal(datagram, frames).ok()
    }
}

/// A committed key slot and when it was committed. The key is shared:
/// a verifier's job holds it under a [`Lease`] while it opens (ADR-0126
/// decision 5), and nothing re-keys or erases it in place while a lease
/// holds it.
struct Slot {
    key: Arc<KeyCell>,
    committed_ns: u64,
}

/// A shared key on cache lines of its own: the reference counts its
/// [`Arc`] keeps in front of it, which the role thread changes at every
/// dispatch and consumption, are not on the lines a verifier reads the
/// key schedule from (ADR-0126).
#[repr(align(128))]
pub(crate) struct KeyCell(AesGcmSiv);

impl core::ops::Deref for KeyCell {
    type Target = AesGcmSiv;

    fn deref(&self) -> &AesGcmSiv {
        &self.0
    }
}

impl core::ops::DerefMut for KeyCell {
    fn deref_mut(&mut self) -> &mut AesGcmSiv {
        &mut self.0
    }
}

/// Erases the key `slot` holds in place when nothing else holds it, and
/// returns whether it did. A key a [`Lease`] still holds is left to its
/// leases: it is erased when the last one returns, on drop (ADR-0126
/// decision 5, erasure only at zero).
fn erase_shared(slot: &mut Arc<KeyCell>, context: KeyContext) -> bool {
    match Arc::get_mut(slot) {
        Some(key) => {
            erase(key, context);
            true
        }
        None => false,
    }
}

/// What one opener instance shares with the verifier threads of its jobs
/// (ADR-0126 decision 5): the withdrawn mark a verifier reads before it
/// opens, and the count of leases out.
#[derive(Debug, Default)]
pub(crate) struct OpenerShare {
    withdrawn: AtomicBool,
    /// On a cache line of its own: the role changes it, a verifier reads
    /// only the mark.
    leases: LeaseCount,
}

impl OpenerShare {
    /// Marks it withdrawn: a verifier cancels every job leased under it
    /// instead of opening it.
    pub(crate) fn withdraw(&self) {
        self.withdrawn.store(true, Ordering::Release);
    }

    /// The leases out (tests).
    #[cfg(test)]
    pub(crate) fn leases(&self) -> u32 {
        self.leases.0.load(Ordering::Acquire)
    }
}

/// The lease count of an [`OpenerShare`], away from its withdrawn mark.
#[derive(Debug, Default)]
#[repr(align(128))]
struct LeaseCount(AtomicU32);

/// One job's hold on the immutable key material of one committed slot
/// (ADR-0126 decision 5): taken at dispatch, before the job is queued,
/// and returned exactly once, when it is dropped, whatever the job's
/// outcome. While it is out the key is neither re-keyed nor erased; once
/// the last one of a dropped key returns, the key is erased on drop.
pub(crate) struct Lease {
    share: Arc<OpenerShare>,
    /// The committed key it holds; `None` for a receive shard's scratch
    /// derivation, whose key lives in its lane slot and is erased there
    /// after the open (ADR-0127 decision 2, step 4).
    key: Option<Arc<KeyCell>>,
}

impl Lease {
    /// A lease on `share` holding `key`, counted now: taken before its
    /// job is queued.
    pub(crate) fn take(share: &Arc<OpenerShare>, key: Option<Arc<KeyCell>>) -> Self {
        share.leases.0.fetch_add(1, Ordering::AcqRel);
        Self {
            share: Arc::clone(share),
            key,
        }
    }

    /// Whether its opener instance was withdrawn: a verifier that reads it
    /// before an open cancels instead.
    pub(crate) fn is_withdrawn(&self) -> bool {
        self.share.withdrawn.load(Ordering::Acquire)
    }

    /// The committed key it holds, if any.
    pub(crate) fn key(&self) -> Option<&AesGcmSiv> {
        self.key.as_deref().map(|cell| &**cell)
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let returned = self.share.leases.0.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(returned > 0, "a lease returns exactly once");
    }
}

impl core::fmt::Debug for Lease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Lease")
            .field("context", &self.key.as_ref().map(|key| *key.context()))
            .finish_non_exhaustive()
    }
}

/// The context a job is bound to at dispatch (ADR-0126 decision 2): the
/// opener instance, the epoch pair of the key slot it selected, the
/// sequence, the VM generation, and the authenticated header and length
/// of the datagram. Its result is checked against it again before any
/// handler runs ([`EncOpener::complete`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ticket {
    opener: u64,
    epochs: (u32, u16),
    seq: u64,
    generation: u64,
    len: usize,
    header: [u8; HEADER_LEN],
}

impl Ticket {
    /// The epoch pair of the key slot its job selected.
    pub(crate) fn epochs(&self) -> (u32, u16) {
        self.epochs
    }
}

/// What [`EncOpener::prepare`] decided for a datagram.
#[derive(Debug)]
pub(crate) enum Prepared {
    /// Under the next epoch, a scratch derivation: opened on the role
    /// thread, as without verifiers.
    Inline,
    /// Every check before the open passed and the open rate is charged:
    /// the job's context and its lease, for a verifier.
    Dispatch(Ticket, Lease),
}

/// Which key a datagram selects (section 8 steps 2 and 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selected {
    Current,
    Previous,
    Next,
}

/// A datagram [`EncOpener::verify`] verified and nothing yet committed
/// (section 8 steps 1 to 7): its inner frames are plaintext at the start
/// of the output buffer, its sequence is not marked and its epoch not
/// promoted. Its handler decides; only then [`EncOpener::commit`] marks
/// and promotes, and only for an accepted datagram. It names the opener
/// instance that verified it: no other opener commits it, and the mark is
/// the window's atomic check and mark, so a token committed twice, or two
/// tokens of one sequence, mark it once. It carries the one clock reading
/// and the VM generation it was verified at, which its commit uses: a
/// datagram verified and accepted commits however long its handler took
/// (H8-39).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    /// Length of the inner frames in the output buffer.
    pub frames: usize,
    /// The epoch pair it verified under.
    pub epochs: (u32, u16),
    seq: u64,
    opener: u64,
    /// The clock reading it was verified at.
    at: u64,
    /// The VM generation it was verified in, the opener's.
    generation: u64,
}

/// Opener instances, so a [`Pending`] commits only in the opener that
/// verified it: a binding made again has a new one.
static OPENERS: AtomicU64 = AtomicU64::new(1);

/// A datagram the opener fully accepted: its inner frames are plaintext
/// at the start of the output buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    /// Length of the inner frames in the output buffer.
    pub frames: usize,
    /// The epoch pair it was accepted under.
    pub epochs: (u32, u16),
    /// Whether it promoted the next epoch to current.
    pub promoted: bool,
}

/// A bound party's receive keys in domain 1 (a receiver's image) or 4 (a
/// publication's bound receiver), section 8: the committed current epoch,
/// the previous one kept for the 10 s overlap after a promotion, and one
/// scratch slot where the next epoch is tried and from which it is
/// committed only after the datagram is fully accepted.
pub struct EncOpener {
    keys: ChannelKeys,
    pairwise: Option<PairwiseFiles>,
    current: Slot,
    previous: Option<(Slot, u64)>,
    /// The scratch slot: made at construction and re-keyed in place for
    /// each next-epoch attempt, so the data path constructs no key. Never
    /// leased: a next-epoch open runs on the role thread.
    scratch: Arc<KeyCell>,
    /// A second key made at construction: the first promotion's recycled
    /// slot, before any previous epoch exists to recycle. Never leased.
    spare: Option<Arc<KeyCell>>,
    /// The withdrawn mark and lease count its verifiers' jobs share
    /// (ADR-0126 decision 5).
    share: Arc<OpenerShare>,
    /// The checked context its keys are erased under on withdrawal.
    erase: KeyContext,
    /// Withdrawn by a key reload (H8 finding 4): checked first by every
    /// open, resynchronisation and re-key, so it never opens again.
    withdrawn: bool,
    /// The VM generation it was made in: it opens nothing in a later one
    /// (section 10).
    generation: u64,
    /// This opener's instance, named by each [`Pending`] it verifies.
    instance: u64,
    /// Whether the receive shards' snapshot holds a reference to its
    /// previous key (ADR-0127): one more holder than its leases, which
    /// [`Self::can_promote`] allows for. Its role takes the snapshot back
    /// before anything changes a key in place.
    published_previous: bool,
}

impl Drop for EncOpener {
    /// A dropped opener (its binding removed, its role stopped) is
    /// withdrawn for its verifiers: a job still queued is cancelled
    /// instead of opened, and every key a lease holds is erased once the
    /// last returns (ADR-0126 decision 5).
    fn drop(&mut self) {
        self.share.withdrawn.store(true, Ordering::Release);
    }
}

impl core::fmt::Debug for EncOpener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncOpener")
            .field("current", self.current.key.context())
            .finish_non_exhaustive()
    }
}

impl EncOpener {
    /// The opener of a binding whose first context is `context` (domain 1
    /// or 4), committed at `now_ns`: on a receiver the epoch pair stated in
    /// the ENC ANSWER (section 6a), on a publication the pair of its bound
    /// receiver.
    ///
    /// # Errors
    ///
    /// [`EncKeyError`] when the context or files do not fit, or for a
    /// bootstrap domain.
    pub fn new(
        keys: &ChannelKeys,
        pairwise: Option<&PairwiseFiles>,
        context: KeyContext,
        now_ns: u64,
    ) -> Result<Self, EncKeyError> {
        if context.domain.is_bootstrap() {
            return Err(EncKeyError::Context(ContextError::Salt));
        }
        let key = derive(keys, pairwise, context, false)?;
        // Every key this opener will hold is made now, its mutex locked
        // once by the constructor: promotions and scratch derivations only
        // re-key and move them. Neither is in use yet, so neither keeps a
        // copy of the current key's schedule: both are erased in place now
        // (H8-16), and every use re-keys the scratch slot first.
        let erase_with = erase_context(&context)?;
        let mut scratch = derive(keys, pairwise, context, false)?;
        erase(&mut scratch, erase_with);
        let mut spare = derive(keys, pairwise, context, false)?;
        erase(&mut spare, erase_with);
        Ok(Self {
            keys: keys.clone(),
            pairwise: pairwise.cloned(),
            current: Slot {
                key: Arc::new(KeyCell(key)),
                committed_ns: now_ns,
            },
            previous: None,
            scratch: Arc::new(KeyCell(scratch)),
            spare: Some(Arc::new(KeyCell(spare))),
            share: Arc::new(OpenerShare::default()),
            erase: erase_with,
            withdrawn: false,
            generation: vm_generation::generation(),
            instance: OPENERS.fetch_add(1, Ordering::Relaxed),
            published_previous: false,
        })
    }

    /// What a receive shard reads of this opener at `now_ns` (ADR-0127
    /// decision 2): its instance, VM generation and withdrawal share, and
    /// its committed keys with their epoch pairs and original age
    /// deadlines (decision 4: from the commit, never restarted by a
    /// republication), the previous one only inside its overlap. `None`
    /// once withdrawn or of an earlier VM generation. Built on the control
    /// path; the snapshot then holds a reference to each key, which its
    /// role takes back before any key changes in place.
    pub(crate) fn shard_view(&mut self, now_ns: u64) -> Option<shards::OpenerView> {
        if self.withdrawn || self.generation != vm_generation::generation() {
            self.published_previous = false;
            return None;
        }
        let view = |slot: &Slot| shards::KeyView {
            epochs: (slot.key.context().key_epoch, slot.key.context().party_epoch),
            key: Arc::clone(&slot.key),
            deadline: slot.committed_ns.saturating_add(KEY_AGE_NS),
            until: u64::MAX,
        };
        let previous = self
            .previous
            .as_ref()
            .filter(|(_, until)| now_ns < *until)
            .map(|(slot, until)| shards::KeyView {
                until: *until,
                ..view(slot)
            });
        self.published_previous = previous.is_some();
        // The next epochs [`Self::is_next`] accepts, each with the inputs
        // of its scratch derivation (decision 2, step 4): the current
        // context at that pair, and its file epoch's IKM.
        let base = *self.current.key.context();
        let (key_epoch, party_epoch) = self.epochs();
        let next = [
            party_epoch.checked_add(1).map(|party| (key_epoch, party)),
            self.keys.next_epoch(key_epoch).map(|epoch| (epoch, 0)),
        ]
        .map(|pair| {
            let (key_epoch, party_epoch) = pair?;
            let ikm = self.keys.ikm(key_epoch)?;
            Some(shards::ScratchView {
                context: KeyContext {
                    key_epoch,
                    party_epoch,
                    ..base
                },
                ikm: Zeroizing::new(*ikm),
            })
        });
        Some(shards::OpenerView {
            instance: self.instance,
            generation: self.generation,
            share: Arc::clone(&self.share),
            current: view(&self.current),
            previous,
            next,
        })
    }

    /// The receive shards' snapshot no longer holds its keys (ADR-0127).
    pub(crate) fn shard_unpublished(&mut self) {
        self.published_previous = false;
    }

    /// Whether committing `pending` promotes its epoch: the role takes its
    /// shards' snapshot back first, so the promotion changes keys no
    /// snapshot holds (ADR-0127 decision 7).
    pub(crate) fn commit_promotes(&self, pending: &Pending) -> bool {
        pending.opener == self.instance && self.committed_slot(pending.epochs, pending.at).is_none()
    }

    /// Whether a datagram under `epochs` would promote them at `now_ns`:
    /// no committed key holds that pair (ADR-0127: the role takes its
    /// shards' snapshot back before such a datagram's last check).
    pub(crate) fn promotes(&self, epochs: (u32, u16), now_ns: u64) -> bool {
        self.committed_slot(epochs, now_ns).is_none()
    }

    /// Withdraws it (H8 finding 4): its key files, previous and spare keys
    /// are dropped and its current and scratch keys replaced in place, all
    /// erased on drop; every later open is refused with
    /// [`EncRejection::Withdrawn`] and every resynchronisation with
    /// [`EncRejection::ResyncRefused`].
    ///
    /// A key a verifier's job still holds under a lease is left to it
    /// (ADR-0126 decision 5): the verifier reads the withdrawn mark before
    /// it opens, and the key is erased once its last lease returns.
    pub fn withdraw(&mut self) {
        self.withdrawn = true;
        self.share.withdrawn.store(true, Ordering::Release);
        self.keys.clear();
        self.pairwise = None;
        self.previous = None;
        self.spare = None;
        let _ = erase_shared(&mut self.scratch, self.erase);
        if !erase_shared(&mut self.current.key, self.erase) {
            self.current.key = Arc::clone(&self.scratch);
        }
    }

    /// The leases its verifiers' jobs hold (ADR-0126 decision 5; tests).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn leases(&self) -> u32 {
        self.share.leases.0.load(Ordering::Acquire)
    }

    /// The current key, weakly (tests: whether it is still held).
    #[cfg(test)]
    pub(crate) fn current_key(&self) -> std::sync::Weak<KeyCell> {
        Arc::downgrade(&self.current.key)
    }

    /// Whether it was withdrawn.
    #[must_use]
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn
    }

    /// Applies the key store's current key set (H8 finding 4): files no
    /// longer named are erased; a previous epoch whose file is gone is
    /// dropped; once its current key epoch is revoked or expired, or no
    /// pairwise file of its receiver is left, it is withdrawn (fail
    /// closed). Its committed keys verify the pairwise trailers of exactly
    /// the files held: a pairwise-only rotation is admitted and a removed
    /// pairwise file stops verifying, with every AEAD key, sequence and
    /// replay window kept (H8-05).
    pub fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        if self.withdrawn {
            return;
        }
        // Successors first, so one key set that admits a successor and
        // drops its predecessor keeps the receiver served.
        self.keys.admit(keys);
        if let Some(pairwise) = self.pairwise.as_mut() {
            pairwise.admit(keys);
        }
        self.keys.retain(keys);
        if let Some(pairwise) = self.pairwise.as_mut() {
            pairwise.retain(keys);
        }
        // A key a lease holds is never changed in place: its role takes
        // every lease back before it applies a key set (ADR-0126 decision
        // 5), so one still out fails closed.
        if self.keys.ikm(self.epochs().0).is_none()
            || Arc::get_mut(&mut self.current.key)
                .is_none_or(|key| refresh_pairwise(key, self.pairwise.as_ref(), false).is_err())
        {
            self.withdraw();
            return;
        }
        if let Some((slot, _)) = self.previous.as_mut()
            && Arc::get_mut(&mut slot.key)
                .is_none_or(|key| refresh_pairwise(key, self.pairwise.as_ref(), false).is_err())
        {
            self.withdraw();
            return;
        }
        // A revoked previous epoch goes, its slot erased in place and kept
        // as the spare, so the next promotion still finds a slot and the
        // data path constructs no key.
        let keys_held = &self.keys;
        if let Some((mut slot, _)) = self
            .previous
            .take_if(|(slot, _)| keys_held.ikm(slot.key.context().key_epoch).is_none())
            && erase_shared(&mut slot.key, self.erase)
            && self.spare.is_none()
        {
            self.spare = Some(slot.key);
        }
        // The cached copies (H8-05): the scratch slot and the spare hold
        // keys derived from earlier files, their pairwise HMAC states
        // included. Both are re-keyed before any use, so each is erased in
        // place now and no rotated or retired file's schedule survives.
        let _ = erase_shared(&mut self.scratch, self.erase);
        if let Some(spare) = self.spare.as_mut() {
            let _ = erase_shared(spare, self.erase);
        }
        // Rotation (section 6): a newly admitted file epoch is the next
        // epoch at `party_epoch` 0; the first datagram fully accepted under
        // it promotes, and the current one stays for the 10 s overlap.
    }

    /// The pairwise epochs of the scratch slot and the spare (tests).
    #[cfg(test)]
    pub(crate) fn cached_pairwise(&self) -> [[Option<u32>; 2]; 2] {
        [
            self.scratch.pairwise_epochs(),
            self.spare
                .as_ref()
                .map_or([None, None], |spare| spare.pairwise_epochs()),
        ]
    }

    /// The current epoch pair.
    #[must_use]
    pub fn epochs(&self) -> (u32, u16) {
        let context = self.current.key.context();
        (context.key_epoch, context.party_epoch)
    }

    /// The current key's context.
    #[must_use]
    pub fn context(&self) -> &KeyContext {
        self.current.key.context()
    }

    /// Whether `(key_epoch, party_epoch)` is the next epoch of the current
    /// one: the next `party_epoch`, or `party_epoch` 0 of the next held
    /// file epoch.
    fn is_next(&self, key_epoch: u32, party_epoch: u16) -> bool {
        let (current_key, current_party) = self.epochs();
        (key_epoch == current_key && Some(party_epoch) == current_party.checked_add(1))
            || (party_epoch == 0 && self.keys.next_epoch(current_key) == Some(key_epoch))
    }

    /// Steps 2 to 4: the epoch pair against the accepted set, the sequence
    /// cap, the open rate and the key age. Changes only the rate counter.
    fn select(
        &mut self,
        header: &Header,
        rate: &mut OpenRate,
        now_ns: u64,
    ) -> Result<Selected, EncRejection> {
        let selected = self.selection(header, now_ns)?;
        if header.seq >= header.domain.seq_cap() {
            return Err(EncRejection::SequenceCap);
        }
        let kind = match selected {
            Selected::Current | Selected::Previous => KeyKind::Committed,
            Selected::Next => KeyKind::Scratch,
        };
        rate.charge(kind, now_ns)?;
        let committed_ns = match selected {
            Selected::Current | Selected::Next => self.current.committed_ns,
            Selected::Previous => self
                .previous
                .as_ref()
                .map_or(0, |(slot, _)| slot.committed_ns),
        };
        if now_ns.saturating_sub(committed_ns) > KEY_AGE_NS {
            return Err(EncRejection::KeyAge);
        }
        Ok(selected)
    }

    /// Step 2 alone: which key the epoch pair selects. Changes nothing.
    fn selection(&self, header: &Header, now_ns: u64) -> Result<Selected, EncRejection> {
        if header.domain != self.current.key.context().domain {
            return Err(EncRejection::Domain);
        }
        let pair = (header.key_epoch, header.party_epoch);
        let selected = if pair == self.epochs() {
            Selected::Current
        } else if let Some((previous, until)) = &self.previous
            && pair
                == (
                    previous.key.context().key_epoch,
                    previous.key.context().party_epoch,
                )
            && now_ns < *until
        {
            Selected::Previous
        } else if self.is_next(header.key_epoch, header.party_epoch) {
            Selected::Next
        } else {
            return Err(EncRejection::Epoch);
        };
        Ok(selected)
    }

    /// ADR-0126 decision 2, on the role thread: every check of section 8
    /// that comes before the open, the open rate charged here so the
    /// channel keeps one aggregate count, the replay precheck included;
    /// then the job's context is recorded and a lease taken on the
    /// selected committed key, before the job is queued. A datagram of the
    /// next epoch needs a scratch derivation and is opened inline
    /// ([`Prepared::Inline`]), with nothing charged yet. Changes only the
    /// rate counter and the lease count. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The first [`EncRejection`] that applies, as [`Self::verify`].
    pub(crate) fn prepare(
        &mut self,
        datagram: &[u8],
        rate: &mut OpenRate,
        now_ns: u64,
    ) -> Result<Prepared, EncRejection> {
        if self.generation != vm_generation::generation() {
            return Err(EncRejection::VmGeneration);
        }
        if self.withdrawn {
            return Err(EncRejection::Withdrawn);
        }
        let header = header(datagram)?;
        if self.selection(&header, now_ns)? == Selected::Next {
            return Ok(Prepared::Inline);
        }
        let key = match self.select(&header, rate, now_ns)? {
            Selected::Current => &self.current.key,
            Selected::Previous => self
                .previous
                .as_ref()
                .map(|(slot, _)| &slot.key)
                .ok_or(EncRejection::Epoch)?,
            Selected::Next => return Ok(Prepared::Inline),
        };
        let seq = key.check_before_open(datagram)?;
        let mut head = [0_u8; HEADER_LEN];
        head.copy_from_slice(datagram.get(..HEADER_LEN).ok_or(EncRejection::Short)?);
        let lease = Lease::take(&self.share, Some(Arc::clone(key)));
        Ok(Prepared::Dispatch(
            Ticket {
                opener: self.instance,
                epochs: (header.key_epoch, header.party_epoch),
                seq,
                generation: self.generation,
                len: datagram.len(),
                header: head,
            },
            lease,
        ))
    }

    /// ADR-0126 decision 3, on the role thread, when a verifier's result
    /// comes back: every predicate [`Self::prepare`] checked is evaluated
    /// again against the current state, changing nothing. The opener is
    /// still the job's instance, not withdrawn and of the job's VM
    /// generation; the verified header, length and sequence are the
    /// job's; the epoch pair still selects a committed key at `now_ns`,
    /// the very key the job's lease holds; that key is within its age; and
    /// the sequence is still outside the window. Then the result is a
    /// [`Pending`] verified at `now_ns`, which its handler decides and
    /// [`Self::commit`] marks, as in ADR-0124: no second open is needed.
    /// Allocates nothing.
    ///
    /// # Errors
    ///
    /// The [`EncRejection`] of the first predicate that changed; nothing
    /// changes.
    pub(crate) fn complete(
        &self,
        ticket: &Ticket,
        lease: &Lease,
        opened: &karyos_protocol::protection::aes_gcm_siv::Opened,
        (header, len): (&[u8; HEADER_LEN], usize),
        now_ns: u64,
    ) -> Result<Pending, EncRejection> {
        if self.generation != vm_generation::generation() || ticket.generation != self.generation {
            return Err(EncRejection::VmGeneration);
        }
        if self.withdrawn || lease.is_withdrawn() {
            return Err(EncRejection::Withdrawn);
        }
        if ticket.opener != self.instance {
            return Err(EncRejection::Epoch);
        }
        if *header != ticket.header || len != ticket.len || opened.seq != ticket.seq {
            return Err(EncRejection::Binding);
        }
        let committed = self.committed_entry(ticket.epochs, now_ns);
        let slot = match lease.key.as_ref() {
            Some(key) => committed
                .filter(|slot| Arc::ptr_eq(&slot.key, key))
                .ok_or(EncRejection::Epoch)?,
            // ADR-0127 decision 2, step 4: a receive shard's scratch
            // derivation of the next epoch, from the inputs this opener
            // derives that pair from. Once another datagram promoted the
            // pair, its committed slot decides; until then the pair must
            // still be the next one and promotable, within its
            // predecessor's age (decision 4). The open rate was charged on
            // the shard, never here; the commit derives and promotes.
            None => match committed {
                Some(slot) => slot,
                None if self.is_next(ticket.epochs.0, ticket.epochs.1) && self.can_promote() => {
                    if now_ns.saturating_sub(self.current.committed_ns) > KEY_AGE_NS {
                        return Err(EncRejection::KeyAge);
                    }
                    return Ok(Pending {
                        frames: opened.frames,
                        epochs: ticket.epochs,
                        seq: ticket.seq,
                        opener: self.instance,
                        at: now_ns,
                        generation: self.generation,
                    });
                }
                None => return Err(EncRejection::Epoch),
            },
        };
        if now_ns.saturating_sub(slot.committed_ns) > KEY_AGE_NS {
            return Err(EncRejection::KeyAge);
        }
        slot.key
            .window()
            .check(ticket.seq)
            .map_err(EncRejection::from)?;
        Ok(Pending {
            frames: opened.frames,
            epochs: ticket.epochs,
            seq: ticket.seq,
            opener: self.instance,
            at: now_ns,
            generation: self.generation,
        })
    }

    /// Opens `datagram` and commits it at once, as an accepting handler
    /// would (tests).
    ///
    /// # Errors
    ///
    /// As [`Self::verify`] and [`Self::commit`].
    #[cfg(test)]
    pub fn open(
        &mut self,
        datagram: &[u8],
        out: &mut [u8],
        rate: &mut OpenRate,
        now_ns: u64,
        inner: impl FnOnce(&[u8]) -> Result<(), EncRejection>,
    ) -> Result<Accepted, EncRejection> {
        let pending = self.verify(datagram, out, rate, now_ns, inner)?;
        self.commit(pending)
    }

    /// Verifies `datagram` into `out` in the receive order of section 8,
    /// steps 1 to 7: fixed fields, epochs, sequence cap, open rate, key
    /// age, key selection (the next epoch derived into the scratch slot),
    /// the replay precheck, the tag and pairwise trailer, the matrix of
    /// section 9 and `inner`, the caller's structural per-frame check
    /// (binding, alias). On success the inner frames are `out[..frames]`
    /// and nothing is marked or promoted: the caller hands them to their
    /// handler and commits the [`Pending`] only if it accepted them. On any
    /// refusal `out` is erased. Changes only the rate counter and the
    /// scratch slot. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The first [`EncRejection`] that applies.
    pub fn verify(
        &mut self,
        datagram: &[u8],
        out: &mut [u8],
        rate: &mut OpenRate,
        now_ns: u64,
        inner: impl FnOnce(&[u8]) -> Result<(), EncRejection>,
    ) -> Result<Pending, EncRejection> {
        if self.generation != vm_generation::generation() {
            return Err(EncRejection::VmGeneration);
        }
        if self.withdrawn {
            zeroize::Zeroize::zeroize(out);
            return Err(EncRejection::Withdrawn);
        }
        let header = header(datagram)?;
        let selected = self.select(&header, rate, now_ns)?;
        if selected == Selected::Next {
            // One that could not be promoted is refused before its handler
            // runs: a commit never reports a promotion it did not make.
            if !self.can_promote() {
                return Err(EncRejection::Epoch);
            }
            let mut next = *self.current.key.context();
            next.key_epoch = header.key_epoch;
            next.party_epoch = header.party_epoch;
            derive_into(
                &self.keys,
                self.pairwise.as_ref(),
                next,
                Arc::get_mut(&mut self.scratch).ok_or(EncRejection::Epoch)?,
                false,
            )
            .map_err(|_| EncRejection::Epoch)?;
        }
        let key = match selected {
            Selected::Current => Some(&*self.current.key),
            Selected::Previous => self.previous.as_ref().map(|(slot, _)| &*slot.key),
            Selected::Next => Some(&*self.scratch),
        }
        .ok_or(EncRejection::Epoch)?;
        let opened = key.open_into(datagram, out)?;
        let checked = out
            .get(..opened.frames)
            .ok_or(EncRejection::Short)
            .and_then(|frames| {
                check_matrix(header.domain, frames)?;
                inner(frames)
            });
        if let Err(reason) = checked {
            zeroize::Zeroize::zeroize(out);
            return Err(reason);
        }
        Ok(Pending {
            frames: opened.frames,
            epochs: (header.key_epoch, header.party_epoch),
            seq: opened.seq,
            opener: self.instance,
            at: now_ns,
            generation: self.generation,
        })
    }

    /// Whether `pending` would still commit at `now_ns`, changing nothing:
    /// it is this opener's, which is neither withdrawn nor of an earlier VM
    /// generation, its epoch pair is still the current one, the previous
    /// one inside its overlap, or the next one, and its sequence is not
    /// marked. A datagram whose handler runs later than its verification
    /// (a path queue's) is checked again here immediately before it, so
    /// the check, the handler and the commit run as one step.
    ///
    /// # Errors
    ///
    /// The [`EncRejection`] the commit would give.
    pub fn check(&self, pending: &Pending, now_ns: u64) -> Result<(), EncRejection> {
        self.owns(pending)?;
        match self.committed_slot(pending.epochs, now_ns) {
            Some(key) => key.window().check(pending.seq).map_err(EncRejection::from),
            None if self.is_next(pending.epochs.0, pending.epochs.1) && self.can_promote() => {
                Ok(())
            }
            None => Err(EncRejection::Epoch),
        }
    }

    /// Section 8 steps 8 and 9 for a datagram its handler accepted: marks
    /// `pending`'s sequence in the window of the key it verified under, the
    /// atomic check and mark, and, for the next epoch, commits it as
    /// current, keeping the old current for the overlap. A refused
    /// datagram is never committed, so it marks and promotes nothing.
    /// Allocates nothing.
    ///
    /// It decides at the token's own clock reading and VM generation, its
    /// verification's (H8-39): the previous epoch's overlap ending, or the
    /// process generation moving, while the handler ran refuses nothing,
    /// since the handler's effects are already applied. The token is the
    /// generation's: a later generation verifies nothing new.
    ///
    /// # Errors
    ///
    /// [`EncRejection::VmGeneration`] for a token of another generation,
    /// [`EncRejection::Withdrawn`], [`EncRejection::Epoch`] for another
    /// opener's token or an epoch no longer selected, or the replay refusal
    /// of a sequence already marked; nothing changes. None is reachable for
    /// a token verified and handled in one step.
    pub fn commit(&mut self, pending: Pending) -> Result<Accepted, EncRejection> {
        if pending.generation != self.generation {
            return Err(EncRejection::VmGeneration);
        }
        if self.withdrawn {
            return Err(EncRejection::Withdrawn);
        }
        if pending.opener != self.instance {
            return Err(EncRejection::Epoch);
        }
        let now_ns = pending.at;
        let accepted = |promoted| Accepted {
            frames: pending.frames,
            epochs: pending.epochs,
            promoted,
        };
        if let Some(key) = self.committed_slot(pending.epochs, now_ns) {
            key.mark(pending.seq)?;
            return Ok(accepted(false));
        }
        if !self.is_next(pending.epochs.0, pending.epochs.1) || !self.can_promote() {
            return Err(EncRejection::Epoch);
        }
        let mut next = *self.current.key.context();
        next.key_epoch = pending.epochs.0;
        next.party_epoch = pending.epochs.1;
        // The scratch slot holds the verifying key unless another
        // datagram's verification re-keyed it since: then it is derived
        // again, under the same inputs, with an empty window.
        if *self.scratch.context() != next {
            derive_into(
                &self.keys,
                self.pairwise.as_ref(),
                next,
                Arc::get_mut(&mut self.scratch).ok_or(EncRejection::Epoch)?,
                false,
            )
            .map_err(|_| EncRejection::Epoch)?;
        }
        self.scratch.mark(pending.seq)?;
        if !self.promote(now_ns) {
            return Err(EncRejection::Epoch);
        }
        Ok(accepted(true))
    }

    /// Whether `pending` is this opener's and it may still commit.
    fn owns(&self, pending: &Pending) -> Result<(), EncRejection> {
        if self.generation != vm_generation::generation() {
            return Err(EncRejection::VmGeneration);
        }
        if self.withdrawn {
            return Err(EncRejection::Withdrawn);
        }
        if pending.opener != self.instance {
            return Err(EncRejection::Epoch);
        }
        Ok(())
    }

    /// The committed key of `epochs` at `now_ns`: the current one, or the
    /// previous one inside its overlap.
    fn committed_slot(&self, epochs: (u32, u16), now_ns: u64) -> Option<&AesGcmSiv> {
        self.committed_entry(epochs, now_ns).map(|slot| &**slot.key)
    }

    /// The committed slot of `epochs` at `now_ns`, as
    /// [`Self::committed_slot`].
    fn committed_entry(&self, epochs: (u32, u16), now_ns: u64) -> Option<&Slot> {
        if epochs == self.epochs() {
            return Some(&self.current);
        }
        self.previous
            .as_ref()
            .filter(|(previous, until)| {
                epochs
                    == (
                        previous.key.context().key_epoch,
                        previous.key.context().party_epoch,
                    )
                    && now_ns < *until
            })
            .map(|(slot, _)| slot)
    }

    /// Moves the binding to the epoch pair of an accepted
    /// resynchronisation (section 6b step 4): a new context with an empty
    /// window, the previous kept for the 10 s overlap. The salt and every
    /// other derivation input stay.
    ///
    /// # Errors
    ///
    /// [`EncRejection::ResyncRefused`] for a pair lower than the bound one
    /// or one whose key cannot be derived; nothing changes.
    pub fn resync(
        &mut self,
        key_epoch: u32,
        party_epoch: u16,
        now_ns: u64,
    ) -> Result<(), EncRejection> {
        if self.generation != vm_generation::generation() {
            return Err(EncRejection::VmGeneration);
        }
        if self.withdrawn {
            return Err(EncRejection::ResyncRefused);
        }
        if (key_epoch, party_epoch) < self.epochs() {
            return Err(EncRejection::ResyncRefused);
        }
        if (key_epoch, party_epoch) == self.epochs() {
            return Ok(());
        }
        if !self.can_promote() {
            return Err(EncRejection::ResyncRefused);
        }
        let mut next = *self.current.key.context();
        next.key_epoch = key_epoch;
        next.party_epoch = party_epoch;
        derive_into(
            &self.keys,
            self.pairwise.as_ref(),
            next,
            Arc::get_mut(&mut self.scratch).ok_or(EncRejection::ResyncRefused)?,
            false,
        )
        .map_err(|_| EncRejection::ResyncRefused)?;
        if !self.promote(now_ns) {
            return Err(EncRejection::ResyncRefused);
        }
        Ok(())
    }

    /// Commits the scratch key as current at `now_ns`, keeping the old
    /// current for the overlap. The slot that becomes the next scratch is
    /// the dropped previous epoch's, or the spare: keys only move. The
    /// recycled slot is erased in place first, so the dropped epoch's
    /// schedule survives nowhere (H8-16).
    ///
    /// A previous key a verifier's lease still holds is never recycled or
    /// given up: the promotion waits for its last lease to return
    /// (ADR-0126 decision 5). Returns whether it promoted: never false
    /// after [`Self::can_promote`] held, since only the role thread takes
    /// leases and a lease only ever returns.
    fn promote(&mut self, now_ns: u64) -> bool {
        // A previous key the shards' snapshot still holds is never
        // recycled: its role takes the snapshot back first (ADR-0127).
        if !self.can_promote() || (self.published_previous && self.previous.is_some()) {
            return false;
        }
        let recycled = match self.previous.take() {
            Some((slot, _)) => Some(slot.key),
            None => self.spare.take(),
        };
        let Some(mut recycled) = recycled else {
            return false;
        };
        if !erase_shared(&mut recycled, self.erase) {
            return false;
        }
        let key = core::mem::replace(&mut self.scratch, recycled);
        let old = core::mem::replace(
            &mut self.current,
            Slot {
                key,
                committed_ns: now_ns,
            },
        );
        self.previous = Some((old, now_ns.saturating_add(EPOCH_OVERLAP_NS)));
        true
    }

    /// Whether a promotion now finds a slot to recycle, changing nothing:
    /// the previous key once no lease holds it, or the spare when there is
    /// no previous key. Checked before any next-epoch handler runs, so a
    /// datagram that could not promote is refused without effects.
    fn can_promote(&self) -> bool {
        match &self.previous {
            Some((slot, _)) => {
                Arc::strong_count(&slot.key)
                    == 1_usize.saturating_add(usize::from(self.published_previous))
            }
            None => self.spare.is_some(),
        }
    }

    /// Erases the previous epoch's key once its overlap has passed at
    /// `now_ns` (section 6b, H8-16): selection already refuses it from its
    /// deadline on, and from then nothing keeps its schedule. Its slot is
    /// erased in place and kept as the spare, so the next promotion still
    /// constructs no key. Role maintenance calls it every duty. Allocates
    /// nothing.
    ///
    /// One a verifier's lease still holds stays in place, selectable by
    /// nothing, until a duty after its last lease returns (ADR-0126
    /// decision 5): its storage is never given up, so a later promotion
    /// still finds a slot.
    pub fn expire_previous(&mut self, now_ns: u64) {
        let Some((mut slot, _)) = self
            .previous
            .take_if(|(slot, until)| now_ns >= *until && Arc::strong_count(&slot.key) == 1)
        else {
            return;
        };
        if erase_shared(&mut slot.key, self.erase) && self.spare.is_none() {
            self.spare = Some(slot.key);
        }
    }

    /// Whether every slot not in use, the scratch slot and the spare, is
    /// erased (tests, H8-16).
    #[cfg(test)]
    pub(crate) fn unused_erased(&self) -> bool {
        *self.scratch.context() == self.erase
            && self
                .spare
                .as_ref()
                .is_none_or(|spare| *spare.context() == self.erase)
    }

    /// Whether it holds a previous epoch's key (tests).
    #[cfg(test)]
    pub(crate) fn has_previous(&self) -> bool {
        self.previous.is_some()
    }

    /// A copy of the current key's replay window (tests).
    #[cfg(test)]
    pub(crate) fn current_window(&self) -> karyos_protocol::protection::replay::ReplayWindow {
        self.current.key.window()
    }
}

/// A domain 5 or 6 datagram opened under a scratch derivation (section 4,
/// the bootstrap rule): the key comes from the header's party and the
/// local identity, never from a value only this datagram makes trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bootstrap {
    /// The verified header.
    pub header: Header,
    /// Length of the one inner frame in the output buffer.
    pub frames: usize,
    /// Whether it verified under an epoch that binds
    /// ([`ChannelKeys::binds`]): only such a datagram may create or change
    /// a binding (section 7, H8-12).
    pub current_epoch: bool,
}

/// Opens a bootstrap datagram into `out`. `target` is the publication of a
/// domain 6 key (the local publication on a publisher); domain 5 takes the
/// header's. `pairwise` holds the receiver files a domain 6 key needs.
/// `inner` checks the one frame before the effect. A bootstrap key is a
/// scratch key: it is charged to the scratch rate and committed nowhere.
///
/// # Errors
///
/// The first [`EncRejection`] that applies.
#[expect(
    clippy::too_many_arguments,
    reason = "the inputs of one section 8 pass"
)]
pub fn open_bootstrap(
    keys: &ChannelKeys,
    pairwise: Option<&PairwiseFiles>,
    target: Option<PublicationIdentity>,
    datagram: &[u8],
    out: &mut [u8],
    rate: &mut OpenRate,
    now_ns: u64,
    inner: impl FnOnce(&Header, &[u8]) -> Result<(), EncRejection>,
) -> Result<Bootstrap, EncRejection> {
    open_bootstrap_in(
        &mut None, keys, pairwise, target, datagram, out, rate, now_ns, inner,
    )
}

/// [`open_bootstrap`] into the caller's scratch `slot`: re-keyed in place
/// when it holds a key made ahead of the data path, so that the open
/// constructs no key (and sets up no mutex); made here only when empty.
///
/// # Errors
///
/// As [`open_bootstrap`].
#[expect(
    clippy::too_many_arguments,
    reason = "the inputs of one section 8 pass"
)]
pub fn open_bootstrap_in(
    slot: &mut Option<AesGcmSiv>,
    keys: &ChannelKeys,
    pairwise: Option<&PairwiseFiles>,
    target: Option<PublicationIdentity>,
    datagram: &[u8],
    out: &mut [u8],
    rate: &mut OpenRate,
    now_ns: u64,
    inner: impl FnOnce(&Header, &[u8]) -> Result<(), EncRejection>,
) -> Result<Bootstrap, EncRejection> {
    if quiesced() {
        return Err(EncRejection::VmGeneration);
    }
    let header = header(datagram)?;
    if !header.domain.is_bootstrap() {
        return Err(EncRejection::Domain);
    }
    if header.party_epoch != 0 || keys.ikm(header.key_epoch).is_none() {
        return Err(EncRejection::Epoch);
    }
    if header.seq >= BOOTSTRAP_SEQ_CAP {
        return Err(EncRejection::SequenceCap);
    }
    rate.charge(KeyKind::Scratch, now_ns)?;
    let publication = match header.domain {
        Domain::Setup => header.publication,
        _ => target,
    }
    .ok_or(EncRejection::Party)?;
    if header.domain == Domain::RspSetup
        && let (Some(files), Some(receiver)) = (pairwise, header.receiver)
        && !files.names(receiver.receiver_id)
    {
        return Err(EncRejection::Pairwise);
    }
    let context = KeyContext {
        domain: header.domain,
        key_epoch: header.key_epoch,
        party_epoch: 0,
        session_id: header.session_id,
        stream_id: header.stream_id,
        publication,
        receiver: header.receiver,
        salt: Salt::Empty,
    };
    let refusal = |error| match error {
        EncKeyError::Receiver => EncRejection::Pairwise,
        _ => EncRejection::Party,
    };
    match slot {
        Some(held) => derive_into(keys, pairwise, context, held, false).map_err(refusal)?,
        None => *slot = Some(derive(keys, pairwise, context, false).map_err(refusal)?),
    }
    let key = slot.as_ref().ok_or(EncRejection::Party)?;
    let opened = key.open_into(datagram, out)?;
    let checked = out
        .get(..opened.frames)
        .ok_or(EncRejection::Short)
        .and_then(|frames| {
            check_matrix(header.domain, frames)?;
            inner(&header, frames)
        });
    if let Err(reason) = checked {
        zeroize::Zeroize::zeroize(out);
        return Err(reason);
    }
    Ok(Bootstrap {
        header,
        frames: opened.frames,
        current_epoch: keys.binds(header.key_epoch),
    })
}

/// ADR-0127 decision 2, on the role thread: a domain 5 SETUP whose scratch
/// key a receive shard derived and a verifier opened into `frames`. The
/// checks of [`open_bootstrap_in`] before the open are evaluated again
/// against `keys`, changing nothing and charging nothing (the shard
/// charged the scratch rate once, decision 3): the VM generation, the
/// job's authenticated header, length and sequence, the domain, the epoch
/// pair (a held file epoch, `party_epoch` 0), the sequence cap and the
/// publication. Then the frame is checked as there, `inner` included.
/// Allocates nothing.
///
/// # Errors
///
/// The first [`EncRejection`] that applies.
pub(crate) fn bootstrap_complete(
    keys: &ChannelKeys,
    (ticket, head): (&Ticket, &Header),
    opened: &karyos_protocol::protection::aes_gcm_siv::Opened,
    (header, len): (&[u8; HEADER_LEN], usize),
    frames: &[u8],
    inner: impl FnOnce(&Header, &[u8]) -> Result<(), EncRejection>,
) -> Result<Bootstrap, EncRejection> {
    if quiesced() || ticket.generation != vm_generation::generation() {
        return Err(EncRejection::VmGeneration);
    }
    if *header != ticket.header
        || len != ticket.len
        || opened.seq != ticket.seq
        || head.seq != ticket.seq
        || (head.key_epoch, head.party_epoch) != ticket.epochs
    {
        return Err(EncRejection::Binding);
    }
    if head.domain != Domain::Setup {
        return Err(EncRejection::Domain);
    }
    if head.party_epoch != 0 || keys.ikm(head.key_epoch).is_none() {
        return Err(EncRejection::Epoch);
    }
    if head.seq >= BOOTSTRAP_SEQ_CAP {
        return Err(EncRejection::SequenceCap);
    }
    if head.publication.is_none() {
        return Err(EncRejection::Party);
    }
    let frames = frames.get(..opened.frames).ok_or(EncRejection::Short)?;
    check_matrix(head.domain, frames)?;
    inner(head, frames)?;
    Ok(Bootstrap {
        header: *head,
        frames: opened.frames,
        current_epoch: keys.binds(head.key_epoch),
    })
}

/// The context a receive shard's lane slot rests in between scratch
/// derivations (ADR-0127): a valid bootstrap context under the all-zero
/// key, which is what [`erase`] writes.
fn scratch_rest() -> KeyContext {
    KeyContext {
        domain: Domain::Setup,
        key_epoch: 1,
        party_epoch: 0,
        session_id: 0,
        stream_id: 0,
        publication: PublicationIdentity {
            driver_id: [1; 16],
            registration_id: 1,
            incarnation: 1,
        },
        receiver: None,
        salt: Salt::Empty,
    }
}

/// A receive shard's lane slot for scratch derivations, made on the
/// control path at rest (erased): every derivation re-keys it in place,
/// so the data path constructs no key. `None` if it cannot be made.
pub(crate) fn scratch_slot() -> Option<AesGcmSiv> {
    AesGcmSiv::new(&[0; KEY_LEN], scratch_rest(), &[]).ok()
}

/// Erases a lane slot's scratch key in place after its use (H8-16, as the
/// role's scratch slot): no derived key survives its job.
pub(crate) fn erase_scratch(key: &mut AesGcmSiv) {
    erase(key, scratch_rest());
}

/// Whether a lane slot's scratch key is at rest, erased (tests).
#[cfg(test)]
pub(crate) fn scratch_erased(key: &AesGcmSiv) -> bool {
    *key.context() == scratch_rest()
}

/// The retired `receiver_boot_id` values of one publication incarnation
/// (section 7), preallocated. Kept until the file epoch they were retired
/// under stops verifying; full, it refuses further new boot ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetiredBoots {
    entries: [Option<(u32, u64, [u8; 16])>; RETIRED_BOOTS],
}

impl RetiredBoots {
    /// Whether `receiver` names a retired boot id.
    #[must_use]
    pub fn contains(&self, receiver: &ReceiverIdentity) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|(_, id, boot)| *id == receiver.receiver_id && *boot == receiver.receiver_boot_id)
    }

    /// Retires `receiver`'s boot id under file epoch `key_epoch`.
    ///
    /// # Errors
    ///
    /// [`EncRejection::RetiredBoot`] when the table is full: the new boot
    /// id is refused until the next file epoch (fail closed).
    pub fn retire(
        &mut self,
        receiver: &ReceiverIdentity,
        key_epoch: u32,
    ) -> Result<(), EncRejection> {
        if self.contains(receiver) {
            return Ok(());
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(EncRejection::RetiredBoot)?;
        *slot = Some((key_epoch, receiver.receiver_id, receiver.receiver_boot_id));
        Ok(())
    }

    /// Whether a new boot id could be retired.
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.entries.iter().any(Option::is_none)
    }

    /// Drops the entries of file epochs below `oldest`, whose keys no
    /// longer verify.
    pub fn expire(&mut self, oldest: u32) {
        for entry in &mut self.entries {
            if entry.is_some_and(|(epoch, _, _)| epoch < oldest) {
                *entry = None;
            }
        }
    }
}

/// The checks of an ENC ANSWER applied as a resynchronisation of a bound
/// receiver (section 6b step 3), except the challenge echo and its
/// consumption, which the challenge owner does.
///
/// # Errors
///
/// [`EncRejection::ResyncRefused`] when the identity or the term
/// parameters differ from the bound ones, the answer verified under an
/// epoch below the active binding (signing) epoch `binding_key_epoch` (a
/// retired predecessor, H8-12), or its epoch pair is lower than the bound
/// one.
pub fn check_resync(
    bound: (
        &karyos_protocol::network::Identity,
        &karyos_protocol::network::TermParams,
    ),
    bound_epochs: (u32, u16),
    binding_key_epoch: u32,
    answer: &karyos_protocol::network::encrypted::EncAnswer,
    envelope_key_epoch: u32,
) -> Result<(), EncRejection> {
    let (identity, term) = bound;
    if answer.answer.identity != *identity
        || answer.answer.term != *term
        || envelope_key_epoch < binding_key_epoch
        || answer.key_epoch != envelope_key_epoch
        || (answer.key_epoch, answer.party_epoch) < bound_epochs
    {
        return Err(EncRejection::ResyncRefused);
    }
    Ok(())
}

/// The 16 wire bytes of a 128-bit value of the control schemas: two
/// little-endian u64 words, `w0` first (section 2).
#[must_use]
pub fn id128([w0, w1]: [u64; 2]) -> [u8; 16] {
    let mut out = [0_u8; 16];
    let (low, high) = out.split_at_mut(8);
    low.copy_from_slice(&w0.to_le_bytes());
    high.copy_from_slice(&w1.to_le_bytes());
    out
}

/// The publication identity of a control schema identity block.
#[must_use]
pub fn publication_of(identity: &karyos_protocol::network::Identity) -> PublicationIdentity {
    PublicationIdentity {
        driver_id: id128(identity.driver_id),
        registration_id: identity.registration_id,
        incarnation: identity.incarnation,
    }
}

/// The control schema identity block of a publication identity: the
/// inverse of [`publication_of`].
#[must_use]
pub fn identity_of(publication: &PublicationIdentity) -> karyos_protocol::network::Identity {
    let (low, high) = publication.driver_id.split_at(8);
    let word = |bytes: &[u8]| {
        let mut out = [0_u8; 8];
        out.copy_from_slice(bytes);
        u64::from_le_bytes(out)
    };
    karyos_protocol::network::Identity {
        driver_id: [word(low), word(high)],
        registration_id: publication.registration_id,
        incarnation: publication.incarnation,
    }
}

/// The largest envelope a sealed control carries: the encrypted header
/// and tag with the pairwise trailer (104 bytes), above the authenticated
/// envelope (48 bytes). The control path's fixed buffers add it to the
/// largest control.
pub const MAX_CONTROL_ENVELOPE: usize = {
    let encrypted = ENVELOPE_LEN + karyos_protocol::protection::aes_gcm_siv::TRAILER_LEN;
    let authenticated = crate::wire_auth::ENVELOPE_LEN;
    if encrypted > authenticated {
        encrypted
    } else {
        authenticated
    }
};

/// The largest datagram the sealers write: [`MAX_PLAINTEXT`] plus the
/// envelope.
pub const MAX_SEALED: usize = MAX_PLAINTEXT + ENVELOPE_LEN;

#[cfg(test)]
mod tests;
