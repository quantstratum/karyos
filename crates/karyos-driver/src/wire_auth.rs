// SPDX-License-Identifier: Apache-2.0

//! The per-session keys of the wire authentication profile, unicast
//! (`quantstratum-docs: karyos/adr/0086-wire-authentication-profile-v1.md`
//! sections 4, 6, 7 and 7a; part of quantstratum/karyos#648).
//!
//! A [`Sealer`] tags one party's datagrams in a MAC domain (1, DATA and
//! the other sender frames; 4, receiver to publisher) under a key derived
//! for that party, purpose, direction, file epoch and in-band key epoch; it
//! moves to the next in-band epoch at 75% of the HMAC usage limit and
//! refuses to send at 100% (manifest 4.3). A [`Verifier`] checks them:
//! the fixed fields and the tag, and only then the replay window of that
//! key, so a forged datagram never moves a window. It accepts the current
//! and the previous in-band epoch, and the keys of at most two file epochs
//! (the 24-hour overlap); a reload keeps the window of every key that still
//! verifies (section 7). A [`Proof`] tags and checks the SETUP proof
//! (domain 5) and RSP_SETUP (domain 6), which keep no window. A
//! [`BootTable`] applies the publisher rule for a new `receiver_boot_id`
//! (section 7). Every structure is sized when it is made; sealing and
//! opening allocate nothing. Derived keys are erased on drop.
//!
//! Nothing here is wired into the data path yet, and no channel can be
//! `authenticated`: `karyos_protocol::channel` still refuses the class.
//! Multicast with several authorised senders is out (ADR-0086 open point
//! 6), so [`Party::Sender`] always salts with the unicast establishment.

use karyos_protocol::network::{Alias, Identity};
use karyos_protocol::protection::hmac_sha256::{
    Binding, Domain, HEADER_LEN, HmacSha256, Opened, PROFILE_ID,
};
use karyos_protocol::protection::replay::{Replay, ReplayWindow};
use karyos_protocol::protection::{Protection, Rejection, SealError};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::wire_keys::{Context, KEY_LEN, KeyFile, Material, Purpose, Scope};

/// Bytes the envelope adds to a datagram: the 32-byte header and the
/// 16-byte tag (ADR-0086 section 5, `E`).
pub const ENVELOPE_LEN: usize = HEADER_LEN + karyos_protocol::protection::hmac_sha256::TAG_LEN;
/// The HMAC-SHA-256 usage limit: tags per key (manifest 4.3).
pub const TAG_CAP: u64 = 1 << 48;
/// Where a sender moves to the next in-band key epoch: 75% of
/// [`TAG_CAP`] (manifest 4.3, usage limit action).
pub const ROTATE_AT: u64 = TAG_CAP / 4 * 3;
/// File epochs that verify at once: the current one and, for the overlap,
/// its predecessor (manifest 4.4).
pub const MAX_FILE_EPOCHS: usize = 2;
/// How long the previous in-band key epoch keeps verifying after a sender
/// moves to the next one, in monotonic nanoseconds: the 24-hour bound on
/// two accepted key epochs (manifest 4.4). It is measured on the monotonic
/// clock, so a wall clock correction can never reopen it (H8 finding 7);
/// file validity and durable retirement keep their wall clock rules.
pub const IN_BAND_OVERLAP_NS: u64 =
    crate::wire_keys::store::OVERLAP_S.unsigned_abs() * 1_000_000_000;
/// Boot ids a publisher retires per receiver and file epoch before it
/// refuses another new one (ADR-0086 section 7, publisher rule).
pub const MAX_RETIRED_BOOTS: usize = 8;

/// Why a key cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeyError {
    /// No key file, or more than [`MAX_FILE_EPOCHS`] of them.
    #[error("no usable key")]
    NoKey,
    /// The key file's purpose is not the one this domain needs.
    #[error("the key file's purpose does not fit this domain")]
    Purpose,
    /// The key file names other peers than this party.
    #[error("the key file does not name this party")]
    Scope,
    /// Key files of different `key_id`s, or two of one file epoch.
    #[error("the key files are not epochs of one key")]
    Mixed,
}

/// Why a seal fails. The sender sends nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SealFailure {
    /// The usage limit is reached and no further in-band epoch exists:
    /// the incarnation must close.
    #[error("the key's usage limit is reached")]
    Exhausted,
    /// The key was withdrawn by a key reload (expired, revoked, replaced
    /// or the store disabled): nothing is sent until the session is
    /// keyed again.
    #[error("the key was withdrawn")]
    Withdrawn,
    /// The buffer cannot hold the frames and the envelope.
    #[error(transparent)]
    Buffer(#[from] SealError),
}

/// Why a received datagram is refused. Nothing it carries is used and no
/// window moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The envelope's fields or tag (ADR-0086 section 2).
    Envelope(Rejection),
    /// The replay window of the key that verified it (section 6).
    Replay(Replay),
}

/// A datagram [`Verifier::check`] passed and nothing has yet recorded:
/// [`Verifier::commit`] records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Checked {
    opened: Opened,
    index: usize,
    file_epoch: u32,
    party_epoch: u8,
    advance: bool,
}

impl Checked {
    /// What the envelope opened to.
    pub fn opened(&self) -> Opened {
        self.opened
    }
}

/// The party a domain 1 or 4 key is derived for (ADR-0086 section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    /// The sender of a unicast publication, domain 1: salted with the
    /// receiver's boot id and the challenge nonce of the completed
    /// establishment.
    Sender {
        /// The full publication identity.
        identity: Identity,
        /// Lanes 0 to `lane_count - 1`.
        lane_count: u8,
        /// The receiver's boot id.
        receiver_boot_id: [u64; 2],
        /// The establishment's challenge nonce.
        nonce: [u64; 2],
    },
    /// A receiver of a publication, domain 4.
    Receiver {
        /// The full publication identity.
        identity: Identity,
        /// The receiver's boot id.
        receiver_boot_id: [u64; 2],
        /// The receiver.
        receiver_id: u64,
    },
}

impl Party {
    /// Whether `other` is a party of the same key scope: both senders, or
    /// receivers of the same receiver id. Only such a party may take over
    /// a key already checked against its file.
    fn same_scope(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Sender { .. }, Self::Sender { .. }) => true,
            (
                Self::Receiver {
                    receiver_id: mine, ..
                },
                Self::Receiver {
                    receiver_id: theirs,
                    ..
                },
            ) => mine == theirs,
            _ => false,
        }
    }

    fn domain(&self) -> Domain {
        match self {
            Self::Sender { .. } => Domain::Data,
            Self::Receiver { .. } => Domain::ReceiverToPublisher,
        }
    }

    fn context(&self, file_epoch: u32, party_epoch: u8, key_id: u32) -> Context {
        match *self {
            Self::Sender {
                identity,
                lane_count,
                receiver_boot_id,
                nonce,
            } => Context::Data {
                file_epoch,
                party_epoch,
                identity,
                lane_count,
                key_id,
                profile_id: PROFILE_ID,
                unicast: Some((receiver_boot_id, nonce)),
            },
            Self::Receiver {
                identity,
                receiver_boot_id,
                receiver_id,
            } => Context::Receiver {
                file_epoch,
                party_epoch,
                receiver_boot_id,
                receiver_id,
                identity,
                key_id,
                profile_id: PROFILE_ID,
            },
        }
    }

    /// The purpose and scope a key file must have for this party. The
    /// channel's scope is the operator's channel id, checked by the
    /// caller that maps channels to key ids; the pairwise scope must name
    /// this receiver.
    fn check(&self, file: &KeyFile) -> Result<(), KeyError> {
        match (self, &file.scope) {
            (Self::Sender { .. }, Scope::Channel { .. }) if file.purpose == Purpose::Channel => {
                Ok(())
            }
            (
                Self::Receiver { receiver_id, .. },
                Scope::Pairwise {
                    receiver_id: named, ..
                },
            ) if file.purpose == Purpose::Pairwise => {
                if named == receiver_id {
                    Ok(())
                } else {
                    Err(KeyError::Scope)
                }
            }
            _ => Err(KeyError::Purpose),
        }
    }
}

/// The symmetric secret of a key file, or why it has none.
fn secret(file: &KeyFile) -> Result<&[u8; KEY_LEN], KeyError> {
    match &file.material {
        Material::Secret(secret) if file.profile_id == PROFILE_ID => Ok(secret),
        _ => Err(KeyError::Purpose),
    }
}

/// An HMAC profile for one derived key.
fn keyed(key: &[u8; KEY_LEN], binding: Binding, first_seq: u64) -> HmacSha256 {
    // A derived key is 32 bytes, never empty.
    HmacSha256::new(key.as_slice(), binding, first_seq).unwrap_or_else(|_| unreachable!())
}

fn binding(domain: Domain, party_epoch: u8, alias: Alias, key_id: u32) -> Binding {
    Binding {
        domain,
        party_epoch,
        session_id: alias.session_id,
        stream_id: alias.stream_id,
        key_id,
    }
}

/// The `party_epoch` and `key_id` of a datagram, read before its tag only
/// to pick the key that checks it.
fn header_selectors(datagram: &[u8]) -> Option<(u8, u32)> {
    let header = datagram.get(..HEADER_LEN)?;
    let party_epoch = *header.get(11)?;
    let key_id = u32::from_le_bytes(header.get(20..24)?.try_into().ok()?);
    Some((party_epoch, key_id))
}

/// Tags one party's datagrams in domain 1 or 4.
pub struct Sealer {
    secret: Zeroizing<[u8; KEY_LEN]>,
    party: Party,
    alias: Alias,
    key_id: u32,
    file_epoch: u32,
    party_epoch: u8,
    profile: HmacSha256,
    /// Withdrawn by a key reload: it seals nothing again.
    withdrawn: bool,
}

impl core::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealer")
            .field("key_id", &self.key_id)
            .field("file_epoch", &self.file_epoch)
            .field("party_epoch", &self.party_epoch)
            .field("next_seq", &self.profile.next_seq())
            .finish_non_exhaustive()
    }
}

impl Sealer {
    /// A sealer for `party` on `alias` under the signing key `file` (the
    /// one `KeyStore::signing_key` names), from in-band epoch 0.
    ///
    /// # Errors
    ///
    /// [`KeyError`] when the file does not fit the party.
    pub fn new(file: &KeyFile, party: Party, alias: Alias) -> Result<Self, KeyError> {
        Self::starting(file, party, alias, 0, 0)
    }

    /// A sealer for `party` on `alias` under this sealer's key file, from
    /// in-band epoch 0: a new establishment of the same publication or receiver
    /// (a new boot id or nonce) without reading the key file again.
    ///
    /// # Errors
    ///
    /// [`KeyError::Scope`] for a party of another kind or receiver.
    pub fn with_party(&self, party: Party, alias: Alias) -> Result<Self, KeyError> {
        if !party.same_scope(&self.party) {
            return Err(KeyError::Scope);
        }
        let key = party
            .context(self.file_epoch, 0, self.key_id)
            .derive(&self.secret);
        Ok(Self {
            secret: Zeroizing::new(*self.secret),
            party,
            alias,
            key_id: self.key_id,
            file_epoch: self.file_epoch,
            party_epoch: 0,
            profile: keyed(&key, binding(party.domain(), 0, alias, self.key_id), 0),
            withdrawn: self.withdrawn,
        })
    }

    fn starting(
        file: &KeyFile,
        party: Party,
        alias: Alias,
        party_epoch: u8,
        first_seq: u64,
    ) -> Result<Self, KeyError> {
        party.check(file)?;
        let secret = Zeroizing::new(*secret(file)?);
        let key = party
            .context(file.file_epoch, party_epoch, file.key_id)
            .derive(&secret);
        let profile = keyed(
            &key,
            binding(party.domain(), party_epoch, alias, file.key_id),
            first_seq,
        );
        Ok(Self {
            secret,
            party,
            alias,
            key_id: file.key_id,
            file_epoch: file.file_epoch,
            party_epoch,
            profile,
            withdrawn: false,
        })
    }

    /// The `key_id` and file epoch of the key file it was made from.
    #[must_use]
    pub fn key_ref(&self) -> (u32, u32) {
        (self.key_id, self.file_epoch)
    }

    /// Whether it still seals under `signing`, the key file the store now
    /// names to sign for its `key_id`: the same file epoch, not withdrawn.
    #[must_use]
    pub fn signs_under(&self, signing: Option<&KeyFile>) -> bool {
        !self.withdrawn
            && signing.is_some_and(|file| (file.key_id, file.file_epoch) == self.key_ref())
    }

    /// A sealer of the same party and alias under `file`, from in-band
    /// epoch 0: the prototype re-keyed after a reload.
    ///
    /// # Errors
    ///
    /// [`KeyError`] when the file does not fit the party.
    pub fn rekeyed(&self, file: &KeyFile) -> Result<Self, KeyError> {
        Self::new(file, self.party, self.alias)
    }

    /// Withdraws the key (H8 finding 4): the secret and the session
    /// profile are erased and it never seals again, so its publication or
    /// image stops sending (fail closed) until a new sealer is made.
    pub fn withdraw(&mut self) {
        self.withdrawn = true;
        self.secret.fill(0);
        self.profile = keyed(
            &[0; KEY_LEN],
            binding(self.party.domain(), 0, self.alias, self.key_id),
            TAG_CAP,
        );
    }

    /// The domain this sealer tags in: 1 for a sender, 4 for a receiver.
    #[must_use]
    pub fn domain(&self) -> Domain {
        self.party.domain()
    }

    /// The party, and so the establishment, its key was derived for.
    #[must_use]
    pub fn party(&self) -> Party {
        self.party
    }

    /// The in-band key epoch the next datagram carries.
    #[must_use]
    pub fn party_epoch(&self) -> u8 {
        self.party_epoch
    }

    /// Whether [`Sealer::seal`] can seal one more datagram: false once the
    /// usage limit is reached with no in-band epoch left. A sender asks
    /// before it reads anything it would then have to drop.
    #[must_use]
    pub fn can_seal(&self) -> bool {
        if self.withdrawn {
            return false;
        }
        let seq = self.profile.next_seq();
        if seq >= ROTATE_AT {
            self.party_epoch < u8::MAX
        } else {
            seq < TAG_CAP
        }
    }

    /// Seals the first `frames` bytes of `datagram` with a fresh envelope
    /// sequence and returns the length to send. At [`ROTATE_AT`] tags it
    /// first moves to the next in-band epoch, under a new key and from
    /// sequence 0. Allocates nothing.
    ///
    /// # Errors
    ///
    /// [`SealFailure::Exhausted`] at [`TAG_CAP`] with no epoch left,
    /// [`SealFailure::Withdrawn`] once withdrawn, and
    /// [`SealFailure::Buffer`] when `datagram` is too small; nothing is
    /// sealed and no sequence is used.
    pub fn seal(&mut self, datagram: &mut [u8], frames: usize) -> Result<usize, SealFailure> {
        if self.withdrawn {
            return Err(SealFailure::Withdrawn);
        }
        if self.profile.next_seq() >= ROTATE_AT {
            self.rotate()?;
        }
        let seq = self.profile.next_seq();
        if seq >= TAG_CAP {
            return Err(SealFailure::Exhausted);
        }
        Ok(Protection::seal(&self.profile, datagram, frames)?)
    }

    fn with_seq(&self, party_epoch: u8, seq: u64) -> HmacSha256 {
        let key = self
            .party
            .context(self.file_epoch, party_epoch, self.key_id)
            .derive(&self.secret);
        keyed(
            &key,
            binding(self.party.domain(), party_epoch, self.alias, self.key_id),
            seq,
        )
    }

    fn rotate(&mut self) -> Result<(), SealFailure> {
        let next = self
            .party_epoch
            .checked_add(1)
            .ok_or(SealFailure::Exhausted)?;
        self.profile = self.with_seq(next, 0);
        self.party_epoch = next;
        Ok(())
    }

    #[cfg(test)]
    fn at_seq(file: &KeyFile, party: Party, alias: Alias, party_epoch: u8, seq: u64) -> Self {
        Self::starting(file, party, alias, party_epoch, seq).unwrap()
    }
}

/// One key that verifies and its replay window.
struct Slot {
    party_epoch: u8,
    profile: HmacSha256,
    window: ReplayWindow,
}

/// The keys of one file epoch: the current in-band epoch, the previous one
/// during its overlap, and the next one, derived ahead so that a sender's
/// move is recognised without deriving anything for an unverified
/// datagram.
struct EpochKeys {
    file_epoch: u32,
    secret: Zeroizing<[u8; KEY_LEN]>,
    previous: Option<Slot>,
    /// The previous in-band epoch verifies while the monotonic `now` is
    /// below this, at most [`IN_BAND_OVERLAP_NS`] after the move (manifest
    /// 4.4); once reached the slot is dropped for good.
    previous_until: u64,
    current: Slot,
    next: Option<Slot>,
}

/// Checks one party's datagrams in domain 1 or 4.
pub struct Verifier {
    party: Party,
    alias: Alias,
    key_id: u32,
    epochs: [Option<EpochKeys>; MAX_FILE_EPOCHS],
}

impl core::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let epochs: Vec<(u32, u8)> = self
            .epochs
            .iter()
            .flatten()
            .map(|keys| (keys.file_epoch, keys.current.party_epoch))
            .collect();
        f.debug_struct("Verifier")
            .field("key_id", &self.key_id)
            .field("epochs", &epochs)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// A verifier for `party` on `alias` under the key files `files`, the
    /// ones `KeyStore::verify_keys` returns: one or two file epochs of one
    /// `key_id`.
    ///
    /// # Errors
    ///
    /// [`KeyError`] when there is no file, more than two, or one does not
    /// fit the party.
    pub fn new<'a>(
        files: impl IntoIterator<Item = &'a KeyFile>,
        party: Party,
        alias: Alias,
    ) -> Result<Self, KeyError> {
        let mut verifier = Self {
            party,
            alias,
            key_id: 0,
            epochs: [None, None],
        };
        verifier.refresh(files)?;
        if verifier.epochs.iter().flatten().next().is_none() {
            return Err(KeyError::NoKey);
        }
        Ok(verifier)
    }

    /// Replaces the key files after a reload. A file epoch still present
    /// keeps its keys and windows, so replay state is never reset for a
    /// key that still verifies; a file epoch no longer present drops its
    /// keys at once (ADR-0086 section 7). No file at all clears every key,
    /// so nothing verifies. On an error nothing changes.
    ///
    /// # Errors
    ///
    /// As [`Verifier::new`].
    pub fn refresh<'a>(
        &mut self,
        files: impl IntoIterator<Item = &'a KeyFile>,
    ) -> Result<(), KeyError> {
        let mut chosen: [Option<&KeyFile>; MAX_FILE_EPOCHS] = [None, None];
        for (count, file) in files.into_iter().enumerate() {
            self.party.check(file)?;
            secret(file)?;
            let slot = chosen.get_mut(count).ok_or(KeyError::NoKey)?;
            *slot = Some(file);
        }
        let [Some(first), second] = chosen else {
            self.epochs = [None, None];
            return Ok(());
        };
        if let Some(second) = second
            && (second.key_id != first.key_id || second.file_epoch == first.file_epoch)
        {
            return Err(KeyError::Mixed);
        }
        if self.epochs.iter().flatten().next().is_some() && first.key_id != self.key_id {
            return Err(KeyError::Mixed);
        }
        // Every file was checked above, so building the keys cannot fail
        // and the old keys are only taken once the new set is complete.
        let mut next: [Option<EpochKeys>; MAX_FILE_EPOCHS] = [None, None];
        for (slot, file) in next.iter_mut().zip(chosen) {
            let Some(file) = file else { continue };
            let kept = self
                .epochs
                .iter_mut()
                .find(|keys| {
                    keys.as_ref()
                        .is_some_and(|k| k.file_epoch == file.file_epoch)
                })
                .and_then(Option::take);
            *slot = Some(match kept {
                Some(keys) => keys,
                None => self.fresh(file)?,
            });
        }
        self.epochs = next;
        self.key_id = first.key_id;
        Ok(())
    }

    /// A verifier for `party` on `alias` under this verifier's key files,
    /// with empty windows: the binding of a new boot id (ADR-0086 section 7, publisher
    /// rule) without reading the key files again.
    ///
    /// # Errors
    ///
    /// [`KeyError::Scope`] for a party of another kind or receiver.
    pub fn with_party(&self, party: Party, alias: Alias) -> Result<Self, KeyError> {
        if !party.same_scope(&self.party) {
            return Err(KeyError::Scope);
        }
        let mut verifier = Self {
            party,
            alias,
            key_id: self.key_id,
            epochs: [None, None],
        };
        let mut epochs: [Option<EpochKeys>; MAX_FILE_EPOCHS] = [None, None];
        for (slot, keys) in epochs.iter_mut().zip(&self.epochs) {
            let Some(keys) = keys else { continue };
            let secret = Zeroizing::new(*keys.secret);
            let current = verifier.slot_for(&secret, self.key_id, keys.file_epoch, 0);
            let next = Some(verifier.slot_for(&secret, self.key_id, keys.file_epoch, 1));
            *slot = Some(EpochKeys {
                file_epoch: keys.file_epoch,
                secret,
                previous: None,
                previous_until: 0,
                current,
                next,
            });
        }
        verifier.epochs = epochs;
        Ok(verifier)
    }

    /// The `key_id` this verifier checks.
    #[must_use]
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// Applies the store's current key set (H8 finding 4): the files that
    /// now verify its `key_id` replace its keys as [`Verifier::refresh`]
    /// does, so a retained file epoch keeps its window and a dropped one
    /// (expired, revoked, or the store disabled) is erased at once. A set
    /// that does not fit clears every key: nothing verifies (fail closed).
    pub fn apply(&mut self, keys: &dyn KeySet) {
        let files = keys.verifying(self.key_id);
        if self.refresh(files.iter().flatten().copied()).is_err() {
            self.epochs = [None, None];
        }
    }

    /// Drops, and so erases, every previous in-band epoch whose overlap
    /// ended at the monotonic `now` (H8 finding 7): it never verifies
    /// again, whatever any clock later reads.
    pub fn tick(&mut self, now: u64) {
        for keys in self.epochs.iter_mut().flatten() {
            keys.expire(now);
        }
    }

    /// Whether any key verifies (tests).
    #[cfg(test)]
    #[must_use]
    pub fn has_keys(&self) -> bool {
        self.epochs.iter().flatten().next().is_some()
    }

    fn slot_for(
        &self,
        secret: &[u8; KEY_LEN],
        key_id: u32,
        file_epoch: u32,
        party_epoch: u8,
    ) -> Slot {
        let key = self
            .party
            .context(file_epoch, party_epoch, key_id)
            .derive(secret);
        Slot {
            party_epoch,
            profile: keyed(
                &key,
                binding(self.party.domain(), party_epoch, self.alias, key_id),
                0,
            ),
            window: ReplayWindow::new(),
        }
    }

    fn fresh(&self, file: &KeyFile) -> Result<EpochKeys, KeyError> {
        let secret = Zeroizing::new(*secret(file)?);
        let current = self.slot_for(&secret, file.key_id, file.file_epoch, 0);
        let next = Some(self.slot_for(&secret, file.key_id, file.file_epoch, 1));
        Ok(EpochKeys {
            file_epoch: file.file_epoch,
            secret,
            previous: None,
            previous_until: 0,
            current,
            next,
        })
    }

    /// Opens a received datagram: the key is picked by the envelope's
    /// `key_id` and `party_epoch`, then the fields and the tag are
    /// checked, and only then the replay window of the key that verified
    /// it moves. A datagram under the next in-band epoch that verifies
    /// makes it current: the old current becomes the previous one, which
    /// verifies for [`IN_BAND_OVERLAP_NS`] from `now`, and the one before is
    /// dropped. `now` is the monotonic clock in nanoseconds, never the wall
    /// clock. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The [`Refusal`]; nothing changes.
    pub fn open(&mut self, datagram: &[u8], now: u64) -> Result<Opened, Refusal> {
        let checked = self.check(datagram, now)?;
        self.commit(checked, now)
    }

    /// The first half of [`Verifier::open`]: the fields, the tag and the
    /// replay window are checked, and nothing changes, so a caller can
    /// still refuse the datagram for its inner frames without consuming
    /// its sequence or moving its epoch. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The [`Refusal`]; nothing changes.
    pub fn check(&self, datagram: &[u8], now: u64) -> Result<Checked, Refusal> {
        let (party_epoch, key_id) =
            header_selectors(datagram).ok_or(Refusal::Envelope(Rejection::Short))?;
        if key_id != self.key_id {
            return Err(Refusal::Envelope(Rejection::Key));
        }
        let mut first = Refusal::Envelope(Rejection::Epoch);
        for (index, keys) in self.epochs.iter().enumerate() {
            let Some(keys) = keys else {
                continue;
            };
            match keys.find(party_epoch, datagram, now) {
                Some(Ok((opened, advance))) => {
                    return Ok(Checked {
                        opened,
                        index,
                        file_epoch: keys.file_epoch,
                        party_epoch,
                        advance,
                    });
                }
                Some(Err(refusal)) if first == Refusal::Envelope(Rejection::Epoch) => {
                    first = refusal;
                }
                Some(Err(_)) | None => {}
            }
        }
        Err(first)
    }

    /// The second half of [`Verifier::open`], for a datagram
    /// [`Verifier::check`] passed and the caller accepts: its sequence is
    /// recorded in the window of the key that verified it, and a datagram
    /// under the next in-band epoch makes that epoch current.
    ///
    /// # Errors
    ///
    /// The [`Refusal`] when the keys changed since the check (a refresh, or
    /// the same sequence committed meanwhile); nothing changes.
    pub fn commit(&mut self, checked: Checked, now: u64) -> Result<Opened, Refusal> {
        // An expired previous epoch is erased first, whatever this commit
        // does: it changes nothing a check at `now` would accept.
        self.tick(now);
        let key_id = self.key_id;
        let keys = self
            .epochs
            .get_mut(checked.index)
            .and_then(Option::as_mut)
            .filter(|keys| keys.file_epoch == checked.file_epoch)
            .ok_or(Refusal::Envelope(Rejection::Epoch))?;
        let slot = keys
            .slot_mut(checked.party_epoch, now)
            .ok_or(Refusal::Envelope(Rejection::Epoch))?;
        slot.window
            .accept(checked.opened.seq)
            .map_err(Refusal::Replay)?;
        if checked.advance {
            let next_epoch = checked.party_epoch.checked_add(1);
            let secret = Zeroizing::new(*keys.secret);
            let file_epoch = keys.file_epoch;
            let upcoming =
                next_epoch.map(|epoch| self.slot_for(&secret, key_id, file_epoch, epoch));
            if let Some(keys) = self.epochs.get_mut(checked.index).and_then(Option::as_mut) {
                keys.advance(upcoming, now);
            }
        }
        Ok(checked.opened)
    }
}

impl EpochKeys {
    /// Checks `datagram` against the slot of `party_epoch`, if this file
    /// epoch has one: the tag, then the window. Returns whether it was the
    /// next epoch, which the caller then makes current.
    fn find(
        &self,
        party_epoch: u8,
        datagram: &[u8],
        now: u64,
    ) -> Option<Result<(Opened, bool), Refusal>> {
        let previous_open = now < self.previous_until;
        let is_next = self
            .next
            .as_ref()
            .is_some_and(|slot| slot.party_epoch == party_epoch);
        let slot = if self.current.party_epoch == party_epoch {
            &self.current
        } else if is_next {
            self.next.as_ref()?
        } else {
            self.previous
                .as_ref()
                .filter(|slot| previous_open && slot.party_epoch == party_epoch)?
        };
        Some(slot.check(datagram).map(|opened| (opened, is_next)))
    }

    /// The slot of `party_epoch` that [`EpochKeys::find`] would pick at
    /// `now`, to commit to.
    fn slot_mut(&mut self, party_epoch: u8, now: u64) -> Option<&mut Slot> {
        let previous_open = now < self.previous_until;
        if self.current.party_epoch == party_epoch {
            Some(&mut self.current)
        } else if self
            .next
            .as_ref()
            .is_some_and(|slot| slot.party_epoch == party_epoch)
        {
            self.next.as_mut()
        } else {
            self.previous
                .as_mut()
                .filter(|slot| previous_open && slot.party_epoch == party_epoch)
        }
    }

    /// Drops the previous epoch for good once its overlap ended at `now`.
    fn expire(&mut self, now: u64) {
        if self.previous.is_some() && now >= self.previous_until {
            self.previous = None;
        }
    }

    fn advance(&mut self, upcoming: Option<Slot>, now: u64) {
        if let Some(next) = self.next.take() {
            let current = core::mem::replace(&mut self.current, next);
            self.previous = Some(current);
            self.previous_until = now.saturating_add(IN_BAND_OVERLAP_NS);
            self.next = upcoming;
        }
    }
}

impl Slot {
    fn check(&self, datagram: &[u8]) -> Result<Opened, Refusal> {
        let opened = self
            .profile
            .open_envelope(datagram)
            .map_err(Refusal::Envelope)?;
        self.window.check(opened.seq).map_err(Refusal::Replay)?;
        Ok(opened)
    }
}

/// The key set a key store names at one moment, which the live roles
/// apply to every derived key after each reload and on each clock tick
/// (H8 finding 4; design wire-key-files section 2.3). A disabled store
/// names nothing, so every path that depends on it stops.
pub trait KeySet {
    /// The file that signs and sends for `key_id`, if any.
    fn signing(&self, key_id: u32) -> Option<&KeyFile>;
    /// The files that verify for `key_id`, at most two, lowest epoch first.
    fn verifying(&self, key_id: u32) -> [Option<&KeyFile>; MAX_FILE_EPOCHS];
    /// The current file epoch of `key_id` from the durable lineage.
    fn current_epoch(&self, key_id: u32) -> Option<u32>;
}

/// A [`crate::wire_keys::store::KeyStore`]'s key set at the wall clock
/// `now` (seconds): file validity and retirement keep their wall clock
/// rules.
pub struct StoreKeys<'a, K: crate::wire_keys::store::Files, S: crate::wire_keys::store::Files> {
    /// The store.
    pub store: &'a crate::wire_keys::store::KeyStore<K, S>,
    /// The wall clock in seconds.
    pub now: i64,
}

impl<K: crate::wire_keys::store::Files, S: crate::wire_keys::store::Files> KeySet
    for StoreKeys<'_, K, S>
{
    fn signing(&self, key_id: u32) -> Option<&KeyFile> {
        self.store.signing_key(key_id, self.now)
    }

    fn verifying(&self, key_id: u32) -> [Option<&KeyFile>; MAX_FILE_EPOCHS] {
        let mut files = [None, None];
        let mut found = self.store.verify_keys(key_id, self.now);
        for slot in &mut files {
            *slot = found.next();
        }
        // More than two verifying files does not fit: none verifies.
        if found.next().is_some() {
            return [None, None];
        }
        files
    }

    fn current_epoch(&self, key_id: u32) -> Option<u32> {
        if self.store.is_disabled() {
            return None;
        }
        self.store
            .state()
            .lineages
            .get(&key_id)
            .map(|lineage| lineage.highest)
    }
}

/// A fixed key set (tests): `files` as loaded, the highest epoch of a
/// `key_id` signs and is current, the two highest verify.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct FixedKeys {
    pub(crate) files: Vec<KeyFile>,
}

#[cfg(test)]
impl KeySet for FixedKeys {
    fn signing(&self, key_id: u32) -> Option<&KeyFile> {
        self.files
            .iter()
            .filter(|file| file.key_id == key_id)
            .max_by_key(|file| file.file_epoch)
    }

    fn verifying(&self, key_id: u32) -> [Option<&KeyFile>; MAX_FILE_EPOCHS] {
        let mut of: Vec<&KeyFile> = self.files.iter().filter(|f| f.key_id == key_id).collect();
        of.sort_by_key(|file| file.file_epoch);
        let skip = of.len().saturating_sub(MAX_FILE_EPOCHS);
        let mut files = [None, None];
        for (slot, file) in files.iter_mut().zip(of.into_iter().skip(skip)) {
            *slot = Some(file);
        }
        files
    }

    fn current_epoch(&self, key_id: u32) -> Option<u32> {
        self.signing(key_id).map(|file| file.file_epoch)
    }
}

/// Tags and checks the SETUP proof (domain 5) or RSP_SETUP (domain 6) of
/// one channel or pair. These domains keep no window: freshness is the
/// challenge transcript (ADR-0086 sections 6 and 7), and `envelope_seq` is
/// a per-start counter.
pub struct Proof {
    kind: ProofKind,
    alias: Alias,
    /// Whether it was made to seal: a key reload re-keys only a signing
    /// proof's signing key.
    signs: bool,
    key_id: u32,
    /// The current file epoch of the key, from the durable lineage: only a
    /// proof under it may bind.
    current: u32,
    /// The signing file epoch's profile, which seals.
    signing: Option<(u32, HmacSha256)>,
    /// One profile per verifying file epoch.
    verifying: [Option<(u32, HmacSha256)>; MAX_FILE_EPOCHS],
    /// The derived keys of `signing` and `verifying`, for the same proof
    /// on another alias ([`Proof::for_alias`]).
    signing_key: Option<Zeroizing<[u8; KEY_LEN]>>,
    verifying_keys: [Option<Zeroizing<[u8; KEY_LEN]>>; MAX_FILE_EPOCHS],
}

impl core::fmt::Debug for Proof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Proof")
            .field("key_id", &self.key_id)
            .field("signing", &self.signing.as_ref().map(|(epoch, _)| *epoch))
            .finish_non_exhaustive()
    }
}

/// What a [`Proof`] is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// The SETUP proof under a channel key, domain 5.
    Setup,
    /// RSP_SETUP under the pairwise key of `receiver_id`, domain 6.
    RspSetup {
        /// The receiver of the pair.
        receiver_id: u64,
    },
}

/// A proof that verified, and under which file epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proved {
    /// The inner frames.
    pub opened: Opened,
    /// The file epoch whose key verified it.
    pub file_epoch: u32,
    /// Whether that is the current (signing) file epoch; an RSP_SETUP that
    /// verifies only under the previous one creates no binding
    /// (ADR-0086 section 7).
    pub current: bool,
}

impl ProofKind {
    fn check(self, file: &KeyFile) -> Result<(), KeyError> {
        match (self, &file.scope, file.purpose) {
            (Self::Setup, Scope::Channel { .. }, Purpose::Channel) => Ok(()),
            (
                Self::RspSetup { receiver_id },
                Scope::Pairwise {
                    receiver_id: named, ..
                },
                Purpose::Pairwise,
            ) => {
                if receiver_id == *named {
                    Ok(())
                } else {
                    Err(KeyError::Scope)
                }
            }
            _ => Err(KeyError::Purpose),
        }
    }

    fn domain(self) -> Domain {
        match self {
            Self::Setup => Domain::SetupProof,
            Self::RspSetup { .. } => Domain::RspSetup,
        }
    }

    fn profile(
        self,
        file: &KeyFile,
        alias: Alias,
    ) -> Result<(Zeroizing<[u8; KEY_LEN]>, HmacSha256), KeyError> {
        self.check(file)?;
        let context = match self {
            Self::Setup => Context::Setup {
                file_epoch: file.file_epoch,
                key_id: file.key_id,
                profile_id: PROFILE_ID,
            },
            Self::RspSetup { receiver_id } => Context::RspSetup {
                file_epoch: file.file_epoch,
                receiver_id,
                key_id: file.key_id,
                profile_id: PROFILE_ID,
            },
        };
        let key = context.derive(secret(file)?);
        let profile = keyed(&key, binding(self.domain(), 0, alias, file.key_id), 0);
        Ok((key, profile))
    }
}

impl Proof {
    /// A proof of `kind` on `alias`: `signing` is the file `signing_key`
    /// names, or `None` on a side that only verifies, `verifying` the files
    /// `verify_keys` returns, and `current` the key's current file epoch,
    /// the highest the durable lineage has admitted. Only a proof under
    /// `current` reports [`Proved::current`], whatever keys are loaded.
    ///
    /// # Errors
    ///
    /// [`KeyError`] as for [`Verifier::new`].
    pub fn new<'a>(
        kind: ProofKind,
        alias: Alias,
        signing: Option<&KeyFile>,
        verifying: impl IntoIterator<Item = &'a KeyFile>,
        current: u32,
    ) -> Result<Self, KeyError> {
        let mut proof = Self {
            kind,
            alias,
            signs: signing.is_some(),
            key_id: 0,
            current,
            signing: None,
            verifying: [None, None],
            signing_key: None,
            verifying_keys: [None, None],
        };
        let mut count = 0_usize;
        for file in verifying {
            let slot = proof.verifying.get_mut(count).ok_or(KeyError::NoKey)?;
            let (key, profile) = kind.profile(file, alias)?;
            *slot = Some((file.file_epoch, profile));
            if let Some(held) = proof.verifying_keys.get_mut(count) {
                *held = Some(key);
            }
            if count == 0 {
                proof.key_id = file.key_id;
            } else if file.key_id != proof.key_id {
                return Err(KeyError::Mixed);
            }
            count += 1;
        }
        if let Some(file) = signing {
            if count > 0 && file.key_id != proof.key_id {
                return Err(KeyError::Mixed);
            }
            proof.key_id = file.key_id;
            let (key, profile) = kind.profile(file, alias)?;
            proof.signing = Some((file.file_epoch, profile));
            proof.signing_key = Some(key);
        }
        if count == 0 && proof.signing.is_none() {
            return Err(KeyError::NoKey);
        }
        Ok(proof)
    }

    /// The same proof on `alias`: a subscription's SETUP proof checks, and
    /// its RSP_SETUP proof seals, for each session of its stream, whose
    /// alias it learns only from the datagram. Its sequence starts at 0:
    /// these domains keep no window (ADR-0086 section 7).
    #[must_use]
    pub fn for_alias(&self, alias: Alias) -> Self {
        let domain = self.kind.domain();
        let rebound =
            |key: &Zeroizing<[u8; KEY_LEN]>| keyed(key, binding(domain, 0, alias, self.key_id), 0);
        let mut verifying: [Option<(u32, HmacSha256)>; MAX_FILE_EPOCHS] = [None, None];
        let mut verifying_keys: [Option<Zeroizing<[u8; KEY_LEN]>>; MAX_FILE_EPOCHS] = [None, None];
        for ((slot, held), (old, key)) in verifying
            .iter_mut()
            .zip(verifying_keys.iter_mut())
            .zip(self.verifying.iter().zip(self.verifying_keys.iter()))
        {
            if let (Some((epoch, _)), Some(key)) = (old, key) {
                *slot = Some((*epoch, rebound(key)));
                *held = Some(Zeroizing::new(**key));
            }
        }
        let signing = self
            .signing
            .as_ref()
            .zip(self.signing_key.as_ref())
            .map(|((epoch, _), key)| (*epoch, rebound(key)));
        Self {
            kind: self.kind,
            alias,
            signs: self.signs,
            key_id: self.key_id,
            current: self.current,
            signing,
            verifying,
            signing_key: self.signing_key.as_ref().map(|key| Zeroizing::new(**key)),
            verifying_keys,
        }
    }

    /// The `key_id` this proof checks.
    #[must_use]
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// Applies the store's current key set (H8 finding 4): its keys become
    /// the files that now sign and verify its `key_id`, and its current
    /// epoch the lineage's. Unchanged keys keep their profiles; a key no
    /// longer in the set is erased. A set that leaves nothing, or does not
    /// fit, clears every key: it neither seals nor verifies (fail closed).
    pub fn apply(&mut self, keys: &dyn KeySet) {
        let signing = if self.signs {
            keys.signing(self.key_id)
        } else {
            None
        };
        let verifying = keys.verifying(self.key_id);
        let current = keys.current_epoch(self.key_id).unwrap_or(0);
        let held = |slot: &Option<(u32, HmacSha256)>| slot.as_ref().map(|(epoch, _)| *epoch);
        let wanted = verifying.map(|file| file.map(|file| file.file_epoch));
        if held(&self.signing) == signing.map(|file| file.file_epoch)
            && self.verifying.each_ref().map(held) == wanted
            && self.current == current
        {
            return;
        }
        let rebuilt = Self::new(
            self.kind,
            self.alias,
            signing,
            verifying.iter().flatten().copied(),
            current,
        );
        match rebuilt {
            Ok(proof) if proof.key_id == self.key_id => {
                *self = Self {
                    signs: self.signs,
                    ..proof
                };
            }
            _ => {
                self.signing = None;
                self.signing_key = None;
                self.verifying = [None, None];
                self.verifying_keys = [None, None];
            }
        }
    }

    /// Withdraws every key: it neither seals nor verifies again.
    pub fn withdraw(&mut self) {
        self.signing = None;
        self.signing_key = None;
        self.verifying = [None, None];
        self.verifying_keys = [None, None];
    }

    /// The domain this proof tags in: 5 for SETUP, 6 for RSP_SETUP.
    #[must_use]
    pub fn domain(&self) -> Domain {
        self.kind.domain()
    }

    /// Seals the first `frames` bytes of `datagram` under the signing key.
    ///
    /// # Errors
    ///
    /// [`SealFailure::Exhausted`] without a signing key or at the end of
    /// the sequence space, and [`SealFailure::Buffer`] when too small.
    pub fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealFailure> {
        let (_, profile) = self.signing.as_ref().ok_or(SealFailure::Exhausted)?;
        if profile.next_seq() >= TAG_CAP {
            return Err(SealFailure::Exhausted);
        }
        Ok(Protection::seal(profile, datagram, frames)?)
    }

    /// Checks a received proof under each verifying file epoch.
    ///
    /// # Errors
    ///
    /// The [`Rejection`] of the first key that applies; nothing changes.
    pub fn verify(&self, datagram: &[u8]) -> Result<Proved, Rejection> {
        let (_, key_id) = header_selectors(datagram).ok_or(Rejection::Short)?;
        if key_id != self.key_id {
            return Err(Rejection::Key);
        }
        let mut first = Rejection::Key;
        for (file_epoch, profile) in self.verifying.iter().flatten() {
            match profile.open_envelope(datagram) {
                Ok(opened) => {
                    return Ok(Proved {
                        opened,
                        file_epoch: *file_epoch,
                        current: *file_epoch == self.current,
                    });
                }
                Err(rejection) => {
                    if first == Rejection::Key {
                        first = rejection;
                    }
                }
            }
        }
        Err(first)
    }
}

/// What the publisher does with an RSP_SETUP that verified (ADR-0086
/// section 7, publisher rule for a new `receiver_boot_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootDecision {
    /// A new binding: derive the domain 4 key for this boot id with an
    /// empty window. Any earlier boot id of the receiver is now retired.
    Bind,
    /// The boot id already bound: nothing is re-derived and no window
    /// resets; the SETUP ANSWER may only be resent within its rates.
    Bound,
    /// A retired boot id: dropped and counted, no binding changes.
    Retired,
    /// Verified only under the previous file epoch's key: creates and
    /// changes no binding.
    PreviousEpoch,
    /// The receiver's retired boot ids, or the table of receivers, are
    /// full: refused and counted until the next file epoch or publication
    /// incarnation (fail closed).
    Full,
}

/// One receiver's boot ids under one file epoch of its pairwise key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Boots {
    file_epoch: u32,
    bound: Option<[u64; 2]>,
    retired: [[u64; 2]; MAX_RETIRED_BOOTS],
    retired_len: usize,
}

impl Boots {
    fn new(file_epoch: u32) -> Self {
        Self {
            file_epoch,
            bound: None,
            retired: [[0; 2]; MAX_RETIRED_BOOTS],
            retired_len: 0,
        }
    }

    fn is_retired(&self, boot: [u64; 2]) -> bool {
        self.retired
            .get(..self.retired_len)
            .is_some_and(|retired| retired.contains(&boot))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BootEntry {
    receiver_id: u64,
    current: Boots,
    /// The previous file epoch's boot ids, kept until its key stops
    /// verifying.
    previous: Option<Boots>,
}

/// The publisher's boot ids per receiver, for one publication
/// incarnation, sized at admission.
#[derive(Debug)]
pub struct BootTable {
    entries: Vec<BootEntry>,
    capacity: usize,
}

impl BootTable {
    /// A table for at most `receivers` receivers, allocated now.
    #[must_use]
    pub fn new(receivers: usize) -> Self {
        Self {
            entries: Vec::with_capacity(receivers),
            capacity: receivers,
        }
    }

    /// Decides on a verified RSP_SETUP of `receiver_id` naming `boot`,
    /// under `proved`. Allocates nothing.
    pub fn decide(&mut self, receiver_id: u64, boot: [u64; 2], proved: &Proved) -> BootDecision {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.receiver_id == receiver_id);
        let Some(index) = index else {
            if !proved.current {
                return BootDecision::PreviousEpoch;
            }
            if self.entries.len() >= self.capacity {
                return BootDecision::Full;
            }
            let mut boots = Boots::new(proved.file_epoch);
            boots.bound = Some(boot);
            self.entries.push(BootEntry {
                receiver_id,
                current: boots,
                previous: None,
            });
            return BootDecision::Bind;
        };
        let Some(entry) = self.entries.get_mut(index) else {
            return BootDecision::Full;
        };
        let retired_anywhere = entry.current.is_retired(boot)
            || entry
                .previous
                .is_some_and(|previous| previous.is_retired(boot));
        if retired_anywhere {
            return BootDecision::Retired;
        }
        if entry.current.bound == Some(boot) {
            return BootDecision::Bound;
        }
        if !proved.current {
            return BootDecision::PreviousEpoch;
        }
        if proved.file_epoch != entry.current.file_epoch {
            // A new current file epoch: the old one's boot ids stay until
            // its key stops verifying, and the new epoch starts empty but
            // for the boot id bound now.
            let mut fresh = Boots::new(proved.file_epoch);
            if let Some(bound) = entry.current.bound
                && let Some(slot) = fresh.retired.first_mut()
            {
                *slot = bound;
                fresh.retired_len = 1;
            }
            entry.previous = Some(entry.current);
            entry.current = fresh;
        } else if let Some(bound) = entry.current.bound {
            let Some(slot) = entry.current.retired.get_mut(entry.current.retired_len) else {
                return BootDecision::Full;
            };
            *slot = bound;
            entry.current.retired_len += 1;
        }
        entry.current.bound = Some(boot);
        BootDecision::Bind
    }

    /// Drops `receiver_id`'s boot ids of file epochs below `file_epoch`
    /// once its pairwise key's earlier epoch stops verifying. Each
    /// receiver's key rotates on its own, so no other receiver is touched.
    pub fn forget_before(&mut self, receiver_id: u64, file_epoch: u32) {
        for entry in &mut self.entries {
            if entry.receiver_id == receiver_id
                && entry
                    .previous
                    .is_some_and(|previous| previous.file_epoch < file_epoch)
            {
                entry.previous = None;
            }
        }
    }
}

#[cfg(test)]
mod tests;
