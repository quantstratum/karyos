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
//! The receive order is section 8's exactly: fixed fields, epochs,
//! sequence cap and open rate, key age, key selection, replay precheck,
//! open and pairwise trailer, inner validation, the atomic check and mark,
//! and only then the commit. A failure before the mark marks no sequence,
//! commits no key and promotes no epoch. Nothing here allocates after
//! construction: every slot is inline and every key is derived into one.

use core::sync::atomic::{AtomicU64, Ordering};

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

pub mod vm_generation;

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
pub const ENC_REASONS: usize = 32;

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
/// limit is refused until the next interval, when both counters restart
/// from 0. The intervals are the whole seconds of the monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenRate {
    interval: u64,
    committed: u32,
    scratch: u32,
}

impl OpenRate {
    /// Charges one open of `kind` at `now_ns`.
    ///
    /// # Errors
    ///
    /// [`EncRejection::OpenRate`] over the limit; nothing is charged.
    pub fn charge(&mut self, kind: KeyKind, now_ns: u64) -> Result<(), EncRejection> {
        let interval = now_ns / SECOND_NS;
        if interval > self.interval {
            *self = Self {
                interval,
                committed: 0,
                scratch: 0,
            };
        }
        let (count, limit) = match kind {
            KeyKind::Committed => (&mut self.committed, COMMITTED_OPENS_PER_S),
            KeyKind::Scratch => (&mut self.scratch, SCRATCH_OPENS_PER_S),
        };
        if *count >= limit {
            return Err(EncRejection::OpenRate);
        }
        *count = count.saturating_add(1);
        Ok(())
    }

    /// Opens charged to `kind` in the current interval.
    #[must_use]
    pub fn charged(&self, kind: KeyKind) -> u32 {
        match kind {
            KeyKind::Committed => self.committed,
            KeyKind::Scratch => self.scratch,
        }
    }
}

/// The per channel accounting of one receiving party: the rate counters
/// and the rejection counters. Fixed size, allocation free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

/// The channel key files of an `encrypted` channel: the `IKM` of every
/// section 4 derivation, selected by `key_epoch` (its file epoch).
#[derive(Debug, Clone)]
pub struct ChannelKeys {
    files: [Option<Secret>; CHANNEL_FILES],
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
        Ok(Self { files: slots })
    }

    /// The current `key_epoch`: the highest file epoch held. Only it
    /// creates or changes a binding (section 7).
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
    fn key_id(&self) -> Option<u32> {
        self.files.iter().flatten().map(|file| file.key_id).next()
    }

    /// Admits every file of its `key_id` the key set names to verify and
    /// it does not hold yet (rotation, ADR-0114 section 6 and ADR-0086
    /// section 7): into a free slot, or in place of a lower epoch. A file
    /// of the other class, purpose or profile is not admitted. Returns
    /// whether one was.
    pub fn admit(&mut self, keys: &dyn crate::wire_auth::KeySet) -> bool {
        let Some(key_id) = self.key_id() else {
            return false;
        };
        let mut admitted = false;
        for file in keys.verifying(key_id).into_iter().flatten() {
            if self.ikm(file.file_epoch).is_some() {
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
}

/// One pairwise file: its receiver and epoch.
#[derive(Debug, Clone)]
struct PairwiseFile {
    receiver_id: u64,
    secret: Secret,
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
                });
            }
        }
        Ok(Self { files: slots })
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
                let served =
                    self.files.iter().flatten().any(|held| {
                        held.receiver_id == receiver_id && held.secret.key_id == key_id
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
    /// highest epoch first (it seals; every one verifies). Allocates
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`EncKeyError::Receiver`] when no file names the receiver.
    pub fn keys(
        &self,
        receiver: &ReceiverIdentity,
        publication: &PublicationIdentity,
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

/// The key of `context`, with the pairwise keys of its receiver domain.
fn derive(
    keys: &ChannelKeys,
    pairwise: Option<&PairwiseFiles>,
    context: KeyContext,
) -> Result<AesGcmSiv, EncKeyError> {
    if quiesced() {
        return Err(EncKeyError::VmGeneration);
    }
    let ikm = keys.ikm(context.key_epoch).ok_or(EncKeyError::NoKey)?;
    match (context.domain.is_receiver(), context.receiver, pairwise) {
        (true, Some(receiver), Some(files)) => {
            let ([first, second], _) = files.keys(&receiver, &context.publication)?;
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
fn derive_into(
    keys: &ChannelKeys,
    pairwise: Option<&PairwiseFiles>,
    context: KeyContext,
    slot: &mut AesGcmSiv,
) -> Result<(), EncKeyError> {
    if quiesced() {
        return Err(EncKeyError::VmGeneration);
    }
    let ikm = keys.ikm(context.key_epoch).ok_or(EncKeyError::NoKey)?;
    match (context.domain.is_receiver(), context.receiver, pairwise) {
        (true, Some(receiver), Some(files)) => {
            let ([first, second], _) = files.keys(&receiver, &context.publication)?;
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
        let key = derive(keys, pairwise, context)?;
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
        self.keys.files = [None, None];
        self.pairwise = None;
        erase(&mut self.key, self.erase);
    }

    /// Whether it was withdrawn.
    #[must_use]
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn
    }

    /// Applies the key store's current key set (H8 finding 4): files no
    /// longer named are erased, and once its own key epoch, or any of its
    /// pairwise files, is revoked or expired it is withdrawn (fail
    /// closed).
    pub fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        if self.withdrawn {
            return;
        }
        // Only its own key matters: the channel file of its key epoch and,
        // in a receiver domain, the pairwise file that seals (the highest
        // epoch of its receiver). An unrelated file dropped leaves it, and
        // its sequence, as it is: a rebuilt sealer would reuse nonces.
        let epoch = self.key.context().key_epoch;
        let sealing = self.key.context().receiver.and_then(|receiver| {
            let [highest, _] = self.pairwise.as_ref()?.epochs_of(receiver.receiver_id);
            highest.map(|epoch| (receiver.receiver_id, epoch))
        });
        self.keys.retain(keys);
        if let Some(pairwise) = self.pairwise.as_mut() {
            pairwise.retain(keys);
        }
        let pairwise_lost = sealing.is_some_and(|(receiver_id, epoch)| {
            !self
                .pairwise
                .as_ref()
                .is_some_and(|pairwise| pairwise.epochs_of(receiver_id).contains(&Some(epoch)))
        });
        if pairwise_lost || self.keys.ikm(epoch).is_none() {
            self.withdraw();
            return;
        }
        // Rotation (section 6): a newly admitted file epoch that the key
        // set signs with becomes the sealer's key epoch at the next
        // datagram, `party_epoch` 0, under a key whose context names the
        // new epoch, so its sequence restarting at 0 reuses no nonce.
        self.keys.admit(keys);
        if let Some(pairwise) = self.pairwise.as_mut() {
            pairwise.admit(keys);
        }
        let signing = self
            .keys
            .key_id()
            .and_then(|key_id| keys.current_epoch(key_id))
            .filter(|signing| *signing > epoch && self.keys.ikm(*signing).is_some());
        if let Some(signing) = signing {
            let mut next = *self.key.context();
            next.key_epoch = signing;
            next.party_epoch = 0;
            if derive_into(&self.keys, self.pairwise.as_ref(), next, &mut self.key).is_ok() {
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
        derive_into(&self.keys, self.pairwise.as_ref(), next, &mut self.key)?;
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
        let protected = u64::try_from(HEADER_LEN.saturating_add(frames)).unwrap_or(u64::MAX);
        if self.must_roll(protected, now_ns) {
            self.roll(now_ns)?;
        }
        #[cfg(test)]
        let plaintext = recording().then(|| datagram.get(..frames).map(<[u8]>::to_vec));
        let sealed = self.key.seal_next(datagram, frames)?;
        #[cfg(test)]
        if let Some(Some(frames)) = plaintext {
            record(SealedRecord {
                context: *self.key.context(),
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

/// A committed key slot and when it was committed.
struct Slot {
    key: AesGcmSiv,
    committed_ns: u64,
}

/// Which key a datagram selects (section 8 steps 2 and 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selected {
    Current,
    Previous,
    Next,
}

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
    /// each next-epoch attempt, so the data path constructs no key.
    scratch: AesGcmSiv,
    /// A second key made at construction: the first promotion's recycled
    /// slot, before any previous epoch exists to recycle.
    spare: Option<AesGcmSiv>,
    /// The checked context its keys are erased under on withdrawal.
    erase: KeyContext,
    /// Withdrawn by a key reload (H8 finding 4): checked first by every
    /// open, resynchronisation and re-key, so it never opens again.
    withdrawn: bool,
    /// The VM generation it was made in: it opens nothing in a later one
    /// (section 10).
    generation: u64,
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
        let key = derive(keys, pairwise, context)?;
        // Every key this opener will hold is made now, its mutex locked
        // once by the constructor: promotions and scratch derivations only
        // re-key and move them.
        let scratch = derive(keys, pairwise, context)?;
        let spare = derive(keys, pairwise, context)?;
        Ok(Self {
            keys: keys.clone(),
            pairwise: pairwise.cloned(),
            current: Slot {
                key,
                committed_ns: now_ns,
            },
            previous: None,
            scratch,
            spare: Some(spare),
            erase: erase_context(&context)?,
            withdrawn: false,
            generation: vm_generation::generation(),
        })
    }

    /// Withdraws it (H8 finding 4): its key files, previous and spare keys
    /// are dropped and its current and scratch keys replaced in place, all
    /// erased on drop; every later open is refused with
    /// [`EncRejection::Withdrawn`] and every resynchronisation with
    /// [`EncRejection::ResyncRefused`].
    pub fn withdraw(&mut self) {
        self.withdrawn = true;
        self.keys.files = [None, None];
        self.pairwise = None;
        self.previous = None;
        self.spare = None;
        erase(&mut self.current.key, self.erase);
        erase(&mut self.scratch, self.erase);
    }

    /// Whether it was withdrawn.
    #[must_use]
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn
    }

    /// Applies the key store's current key set (H8 finding 4): files no
    /// longer named are erased; a previous epoch whose file is gone is
    /// dropped; once its current key epoch, or any of its pairwise files,
    /// is revoked or expired it is withdrawn (fail closed).
    pub fn apply_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        if self.withdrawn {
            return;
        }
        // Every pairwise file of its receiver verifies a trailer, so losing
        // any of them withdraws it; another receiver's file does not.
        let receiver = self.current.key.context().receiver;
        let held = receiver.and_then(|receiver| {
            Some((
                receiver.receiver_id,
                self.pairwise.as_ref()?.epochs_of(receiver.receiver_id),
            ))
        });
        self.keys.retain(keys);
        if let Some(pairwise) = self.pairwise.as_mut() {
            pairwise.retain(keys);
        }
        let pairwise_lost = held.is_some_and(|(receiver_id, held)| {
            let now = self
                .pairwise
                .as_ref()
                .map_or([None, None], |pairwise| pairwise.epochs_of(receiver_id));
            held.iter()
                .flatten()
                .any(|epoch| !now.contains(&Some(*epoch)))
        });
        if pairwise_lost || self.keys.ikm(self.epochs().0).is_none() {
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
        {
            erase(&mut slot.key, self.erase);
            if self.spare.is_none() {
                self.spare = Some(slot.key);
            }
        }
        // Rotation (section 6): a newly admitted file epoch is the next
        // epoch at `party_epoch` 0; the first datagram fully accepted under
        // it promotes, and the current one stays for the 10 s overlap.
        self.keys.admit(keys);
        if let Some(pairwise) = self.pairwise.as_mut() {
            pairwise.admit(keys);
        }
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

    /// Opens `datagram` into `out` in the receive order of section 8.
    /// `inner` is the caller's per-frame check of step 7 (binding, alias,
    /// authority); it runs after the matrix of section 9 and before the
    /// mark. On success the inner frames are `out[..frames]` and only then
    /// may they take effect; on any refusal `out` is erased, no sequence is
    /// marked, no key is committed and no epoch moves. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The first [`EncRejection`] that applies.
    pub fn open(
        &mut self,
        datagram: &[u8],
        out: &mut [u8],
        rate: &mut OpenRate,
        now_ns: u64,
        inner: impl FnOnce(&[u8]) -> Result<(), EncRejection>,
    ) -> Result<Accepted, EncRejection> {
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
            let mut next = *self.current.key.context();
            next.key_epoch = header.key_epoch;
            next.party_epoch = header.party_epoch;
            derive_into(&self.keys, self.pairwise.as_ref(), next, &mut self.scratch)
                .map_err(|_| EncRejection::Epoch)?;
        }
        let key = match selected {
            Selected::Current => Some(&self.current.key),
            Selected::Previous => self.previous.as_ref().map(|(slot, _)| &slot.key),
            Selected::Next => Some(&self.scratch),
        }
        .ok_or(EncRejection::Epoch)?;
        let opened = key.open_into(datagram, out)?;
        let checked = out
            .get(..opened.frames)
            .ok_or(EncRejection::Short)
            .and_then(|frames| {
                check_matrix(header.domain, frames)?;
                inner(frames)
            })
            .and_then(|()| key.mark(opened.seq));
        if let Err(reason) = checked {
            zeroize::Zeroize::zeroize(out);
            return Err(reason);
        }
        let promoted = selected == Selected::Next;
        if promoted {
            self.promote(now_ns);
        }
        Ok(Accepted {
            frames: opened.frames,
            epochs: (header.key_epoch, header.party_epoch),
            promoted,
        })
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
        let mut next = *self.current.key.context();
        next.key_epoch = key_epoch;
        next.party_epoch = party_epoch;
        derive_into(&self.keys, self.pairwise.as_ref(), next, &mut self.scratch)
            .map_err(|_| EncRejection::ResyncRefused)?;
        self.promote(now_ns);
        Ok(())
    }

    /// Commits the scratch key as current at `now_ns`, keeping the old
    /// current for the overlap. The slot that becomes the next scratch is
    /// the dropped previous epoch's, or the spare: keys only move.
    fn promote(&mut self, now_ns: u64) {
        let recycled = self
            .previous
            .take()
            .map(|(slot, _)| slot.key)
            .or_else(|| self.spare.take());
        let Some(recycled) = recycled else {
            return;
        };
        let key = core::mem::replace(&mut self.scratch, recycled);
        let old = core::mem::replace(
            &mut self.current,
            Slot {
                key,
                committed_ns: now_ns,
            },
        );
        self.previous = Some((old, now_ns.saturating_add(EPOCH_OVERLAP_NS)));
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
    /// Whether it verified under the current file epoch: only such a
    /// datagram may create or change a binding (section 7).
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
        Some(held) => derive_into(keys, pairwise, context, held).map_err(refusal)?,
        None => *slot = Some(derive(keys, pairwise, context).map_err(refusal)?),
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
        current_epoch: header.key_epoch == keys.current_epoch(),
    })
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
/// parameters differ from the bound ones, the answer verified only under
/// an earlier file epoch than the current one, or its epoch pair is lower
/// than the bound one.
pub fn check_resync(
    bound: (
        &karyos_protocol::network::Identity,
        &karyos_protocol::network::TermParams,
    ),
    bound_epochs: (u32, u16),
    current_key_epoch: u32,
    answer: &karyos_protocol::network::encrypted::EncAnswer,
    envelope_key_epoch: u32,
) -> Result<(), EncRejection> {
    let (identity, term) = bound;
    if answer.answer.identity != *identity
        || answer.answer.term != *term
        || envelope_key_epoch != current_key_epoch
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
