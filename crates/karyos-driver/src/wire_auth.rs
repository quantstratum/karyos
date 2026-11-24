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

/// The HMAC-SHA-256 usage limit: tags per key (manifest 4.3).
pub const TAG_CAP: u64 = 1 << 48;
/// Where a sender moves to the next in-band key epoch: 75% of
/// [`TAG_CAP`] (manifest 4.3, usage limit action).
pub const ROTATE_AT: u64 = TAG_CAP / 4 * 3;
/// File epochs that verify at once: the current one and, for the overlap,
/// its predecessor (manifest 4.4).
pub const MAX_FILE_EPOCHS: usize = 2;
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
        })
    }

    /// The in-band key epoch the next datagram carries.
    #[must_use]
    pub fn party_epoch(&self) -> u8 {
        self.party_epoch
    }

    /// Seals the first `frames` bytes of `datagram` with a fresh envelope
    /// sequence and returns the length to send. At [`ROTATE_AT`] tags it
    /// first moves to the next in-band epoch, under a new key and from
    /// sequence 0. Allocates nothing.
    ///
    /// # Errors
    ///
    /// [`SealFailure::Exhausted`] at [`TAG_CAP`] with no epoch left, and
    /// [`SealFailure::Buffer`] when `datagram` is too small; nothing is
    /// sealed and no sequence is used.
    pub fn seal(&mut self, datagram: &mut [u8], frames: usize) -> Result<usize, SealFailure> {
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
        Ok(verifier)
    }

    /// Replaces the key files after a reload. A file epoch still present
    /// keeps its keys and windows, so replay state is never reset for a
    /// key that still verifies; a file epoch no longer present drops its
    /// keys at once (ADR-0086 section 7). On an error nothing changes.
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
            return Err(KeyError::NoKey);
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
            current,
            next,
        })
    }

    /// Opens a received datagram: the key is picked by the envelope's
    /// `key_id` and `party_epoch`, then the fields and the tag are
    /// checked, and only then the replay window of the key that verified
    /// it moves. A datagram under the next in-band epoch that verifies
    /// makes it current: the old current becomes the previous one, and the
    /// one before is dropped. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The [`Refusal`]; nothing changes.
    pub fn open(&mut self, datagram: &[u8]) -> Result<Opened, Refusal> {
        let (party_epoch, key_id) =
            header_selectors(datagram).ok_or(Refusal::Envelope(Rejection::Short))?;
        if key_id != self.key_id {
            return Err(Refusal::Envelope(Rejection::Key));
        }
        let mut first = Refusal::Envelope(Rejection::Epoch);
        for index in 0..MAX_FILE_EPOCHS {
            let Some(keys) = self.epochs.get_mut(index).and_then(Option::as_mut) else {
                continue;
            };
            let (opened, advanced) = match keys.find(party_epoch, datagram) {
                Some(Ok(found)) => found,
                Some(Err(refusal)) => {
                    if first == Refusal::Envelope(Rejection::Epoch) {
                        first = refusal;
                    }
                    continue;
                }
                None => continue,
            };
            if advanced {
                let next_epoch = party_epoch.checked_add(1);
                let secret = Zeroizing::new(*keys.secret);
                let file_epoch = keys.file_epoch;
                let upcoming =
                    next_epoch.map(|epoch| self.slot_for(&secret, key_id, file_epoch, epoch));
                if let Some(keys) = self.epochs.get_mut(index).and_then(Option::as_mut) {
                    keys.advance(upcoming);
                }
            }
            return Ok(opened);
        }
        Err(first)
    }
}

impl EpochKeys {
    /// Checks `datagram` against the slot of `party_epoch`, if this file
    /// epoch has one: the tag, then the window. Returns whether it was the
    /// next epoch, which the caller then makes current.
    fn find(
        &mut self,
        party_epoch: u8,
        datagram: &[u8],
    ) -> Option<Result<(Opened, bool), Refusal>> {
        let is_next = self
            .next
            .as_ref()
            .is_some_and(|slot| slot.party_epoch == party_epoch);
        let slot = if self.current.party_epoch == party_epoch {
            &mut self.current
        } else if is_next {
            self.next.as_mut()?
        } else {
            self.previous
                .as_mut()
                .filter(|slot| slot.party_epoch == party_epoch)?
        };
        Some(slot.check(datagram).map(|opened| (opened, is_next)))
    }

    fn advance(&mut self, upcoming: Option<Slot>) {
        if let Some(next) = self.next.take() {
            let current = core::mem::replace(&mut self.current, next);
            self.previous = Some(current);
            self.next = upcoming;
        }
    }
}

impl Slot {
    fn check(&mut self, datagram: &[u8]) -> Result<Opened, Refusal> {
        let opened = self
            .profile
            .open_envelope(datagram)
            .map_err(Refusal::Envelope)?;
        self.window.accept(opened.seq).map_err(Refusal::Replay)?;
        Ok(opened)
    }
}

/// Tags and checks the SETUP proof (domain 5) or RSP_SETUP (domain 6) of
/// one channel or pair. These domains keep no window: freshness is the
/// challenge transcript (ADR-0086 sections 6 and 7), and `envelope_seq` is
/// a per-start counter.
pub struct Proof {
    key_id: u32,
    /// The signing file epoch's profile, which seals.
    signing: Option<(u32, HmacSha256)>,
    /// One profile per verifying file epoch.
    verifying: [Option<(u32, HmacSha256)>; MAX_FILE_EPOCHS],
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

    fn profile(self, file: &KeyFile, alias: Alias) -> Result<HmacSha256, KeyError> {
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
        Ok(keyed(
            &key,
            binding(self.domain(), 0, alias, file.key_id),
            0,
        ))
    }
}

impl Proof {
    /// A proof of `kind` on `alias`: `signing` is the file `signing_key`
    /// names, or `None` on a side that only verifies, and `verifying` the
    /// files `verify_keys` returns.
    ///
    /// # Errors
    ///
    /// [`KeyError`] as for [`Verifier::new`].
    pub fn new<'a>(
        kind: ProofKind,
        alias: Alias,
        signing: Option<&KeyFile>,
        verifying: impl IntoIterator<Item = &'a KeyFile>,
    ) -> Result<Self, KeyError> {
        let mut proof = Self {
            key_id: 0,
            signing: None,
            verifying: [None, None],
        };
        let mut count = 0_usize;
        for file in verifying {
            let slot = proof.verifying.get_mut(count).ok_or(KeyError::NoKey)?;
            *slot = Some((file.file_epoch, kind.profile(file, alias)?));
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
            proof.signing = Some((file.file_epoch, kind.profile(file, alias)?));
        }
        if count == 0 && proof.signing.is_none() {
            return Err(KeyError::NoKey);
        }
        Ok(proof)
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
        let signing_epoch = self.signing.as_ref().map(|(epoch, _)| *epoch);
        let newest = self
            .verifying
            .iter()
            .flatten()
            .map(|(epoch, _)| *epoch)
            .max();
        let current_epoch = signing_epoch.or(newest);
        let mut first = Rejection::Key;
        for (file_epoch, profile) in self.verifying.iter().flatten() {
            match profile.open_envelope(datagram) {
                Ok(opened) => {
                    return Ok(Proved {
                        opened,
                        file_epoch: *file_epoch,
                        current: Some(*file_epoch) == current_epoch,
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

    /// Drops the previous file epoch's boot ids once its key stops
    /// verifying.
    pub fn forget_before(&mut self, file_epoch: u32) {
        for entry in &mut self.entries {
            if entry
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
