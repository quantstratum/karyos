// SPDX-License-Identifier: Apache-2.0

//! The wire authentication of a publication's sender frames: domain 1 of
//! the profile (`quantstratum-docs:
//! karyos/adr/0086-wire-authentication-profile-v1.md` sections 2, 5 and 6;
//! part of quantstratum/karyos#648).
//!
//! An authenticated publication seals every datagram its sender path
//! writes (DATA batches, PAD and ABORTED records, heartbeats, EOS and
//! repairs) with one [`Sealer`], so every transmission, a retransmission
//! included, takes a fresh envelope sequence of one key. Until the
//! establishment installs the session's sealer it sends nothing, and a
//! sealer that can seal no more stops it: fail closed. The log's frames
//! keep the inner budget; the datagram adds [`ENVELOPE_LEN`] bytes, which
//! the channel's MTU accounts for when the log is sized (section 5).
//!
//! Unicast single-path only: a multi-destination or routed publication
//! refuses authentication (ADR-0086 open point 6; ADR-0076 clause 4 is
//! karyos#649). Nothing enables an authenticated channel yet.
//!
//! The `encrypted` class (ADR-0114, karyos#650) rides the same slot: an
//! encrypted publication waits in [`SenderAuth::EncPending`] until its
//! establishment installs the session's [`EncSealer`] (domain 1), which
//! rolls its `party_epoch` before any budget of the profile is reached;
//! every datagram grows by the encrypted envelope, 84 bytes. It never
//! falls back to bare or authenticated datagrams.

use thiserror::Error;

use super::Outbound;
use crate::embedded::StreamTerms;
use crate::wire_auth::{ENVELOPE_LEN, Sealer};
use crate::wire_enc::{DatagramSeal, EncSealer};
use karyos_protocol::protection::aes_gcm_siv::{
    Domain as EncDomain, ENVELOPE_LEN as ENC_ENVELOPE_LEN,
};

/// How a publication's sender frames are authenticated.
#[derive(Debug, Default)]
pub(crate) enum SenderAuth {
    /// A trusted channel: datagrams leave bare.
    #[default]
    Off,
    /// Authenticated, waiting for its session key: nothing leaves.
    Pending,
    /// Authenticated under the session's sealer.
    Sealing(Box<Sealer>),
    /// Encrypted, waiting for its session key: nothing leaves.
    EncPending,
    /// Encrypted under the session's domain 1 sealer.
    Encrypting(Box<EncSealer>),
}

/// Why a publication cannot be authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthUnsupported {
    /// It has several destinations or paths (ADR-0086 open point 6;
    /// karyos#649).
    #[error("only a unicast single-path publication can be authenticated")]
    NotUnicast,
    /// A sealer for a publication that was never made authenticated.
    #[error("the publication is not authenticated")]
    NotAuthenticated,
    /// The publication has already staged or sent bare datagrams: it
    /// must be authenticated from its creation, before any traffic.
    #[error("the publication already sent bare datagrams")]
    Started,
    /// A second sealer for the establishment already keyed: it would
    /// restart the envelope sequence under the same key.
    #[error("the establishment is already keyed")]
    SameEstablishment,
}

impl SenderAuth {
    /// Bytes each datagram grows by.
    pub(crate) fn envelope(&self) -> usize {
        match self {
            Self::Off => 0,
            Self::Pending | Self::Sealing(_) => ENVELOPE_LEN,
            Self::EncPending | Self::Encrypting(_) => ENC_ENVELOPE_LEN,
        }
    }

    /// Whether one more datagram can leave: always on a trusted channel,
    /// only with a sealer that can still seal on an authenticated one.
    pub(crate) fn ready(&self) -> bool {
        match self {
            Self::Off => true,
            Self::Pending | Self::EncPending => false,
            Self::Sealing(sealer) => sealer.can_seal(),
            // It rolls its epoch itself; a seal it refuses sends nothing.
            // A withdrawn sealer (H8 finding 4) seals nothing.
            Self::Encrypting(sealer) => !sealer.is_withdrawn(),
        }
    }

    /// Seals the first `frames` bytes of `datagram`, which has room for
    /// the envelope, and returns the length to send: `frames` itself on a
    /// trusted channel. `None` when it cannot be sealed; nothing may then
    /// be sent.
    pub(crate) fn seal(&mut self, datagram: &mut [u8], frames: usize) -> Option<usize> {
        match self {
            Self::Off => Some(frames),
            Self::Pending | Self::EncPending => None,
            Self::Sealing(sealer) => sealer.seal(datagram, frames).ok(),
            Self::Encrypting(sealer) => sealer.seal(datagram, frames).ok(),
        }
    }

    /// The sealer of either class, if one is installed: repairs are sealed
    /// under it like every other datagram.
    pub(crate) fn sealer(&mut self) -> Option<&mut (dyn DatagramSeal + 'static)> {
        match self {
            Self::Sealing(sealer) => Some(&mut **sealer),
            Self::Encrypting(sealer) => Some(&mut **sealer),
            Self::Off | Self::Pending | Self::EncPending => None,
        }
    }
}

impl<T: StreamTerms> Outbound<T> {
    /// Makes the publication authenticated: from now on it sends nothing
    /// until [`Outbound::install_sealer`] gives it the session's key. Its
    /// log must be sized for the inner budget, the channel MTU less
    /// [`ENVELOPE_LEN`]: a frame larger than that is a read error, never
    /// a datagram over the MTU.
    ///
    /// # Errors
    ///
    /// [`AuthUnsupported::NotUnicast`] for a multi-destination, dynamic or
    /// routed publication; nothing changes.
    pub fn require_auth(&mut self) -> Result<(), AuthUnsupported> {
        if self.routed.is_some() || self.fanout.is_some() || self.registration.is_some() {
            return Err(AuthUnsupported::NotUnicast);
        }
        match self.auth {
            SenderAuth::Off => {}
            SenderAuth::Pending | SenderAuth::Sealing(_) => return Ok(()),
            // An encrypted publication never changes class.
            SenderAuth::EncPending | SenderAuth::Encrypting(_) => {
                return Err(AuthUnsupported::Started);
            }
        }
        // Nothing bare may be queued or sent before: a staged datagram
        // would still leave unsealed (ADR-0086 section 2).
        let staged = self.tracks.iter().any(|track| !track.staged.is_empty())
            || (0..self.readers.len()).any(|lane| self.sender.pending(lane).unwrap_or(0) > 0);
        if self.counters.staged > 0 || staged {
            return Err(AuthUnsupported::Started);
        }
        if let Some(repair) = self.repair.as_deref_mut() {
            repair.reserve_envelope(ENVELOPE_LEN);
        }
        self.auth = SenderAuth::Pending;
        Ok(())
    }

    /// Installs the session's sealer, made at establishment. A
    /// re-establishment (a new receiver boot id or nonce) derives a new
    /// key and replaces it; the same establishment keeps the installed one
    /// and its envelope sequence.
    ///
    /// # Errors
    ///
    /// [`AuthUnsupported::NotAuthenticated`] unless
    /// [`Outbound::require_auth`] was called first, and
    /// [`AuthUnsupported::SameEstablishment`] for a sealer of the
    /// establishment already installed, or of another domain.
    pub fn install_sealer(&mut self, sealer: Sealer) -> Result<(), AuthUnsupported> {
        match &self.auth {
            SenderAuth::Off => return Err(AuthUnsupported::NotAuthenticated),
            SenderAuth::Sealing(current) if current.party() == sealer.party() => {
                return Err(AuthUnsupported::SameEstablishment);
            }
            SenderAuth::Pending | SenderAuth::Sealing(_) => {}
            SenderAuth::EncPending | SenderAuth::Encrypting(_) => {
                return Err(AuthUnsupported::NotAuthenticated);
            }
        }
        if sealer.domain() != karyos_protocol::protection::hmac_sha256::Domain::Data {
            return Err(AuthUnsupported::SameEstablishment);
        }
        self.auth = SenderAuth::Sealing(Box::new(sealer));
        Ok(())
    }

    /// Binds the publication to its role's key `fence` (H8 R3-1).
    pub(crate) fn set_key_fence(&mut self, fence: std::sync::Arc<crate::wire_auth::KeyGeneration>) {
        self.key_fence = Some(fence);
    }

    /// Whether its role's key fence admits the sender now; always without
    /// one.
    pub(crate) fn fence_admits(&self) -> bool {
        self.key_fence
            .as_ref()
            .is_none_or(|fence| fence.admits_now(crate::wire_auth::Side::Sender))
    }

    /// Whether one more datagram can leave: a trusted one always, an
    /// authenticated or encrypted one with a sealer that can seal and
    /// while the key fence admits it (H8 R3-1: a stale or unapplied key
    /// view stops it at the point of use).
    pub(crate) fn auth_ready(&self) -> bool {
        self.auth.ready() && (matches!(self.auth, SenderAuth::Off) || self.fence_admits())
    }

    /// Lends the installed sealer, to seal one of the publication's
    /// sender controls (PATH_HB, ERR, RTTM REPLY) in domain 1 under the
    /// same envelope sequence as its DATA; [`Outbound::return_sealer`]
    /// gives it back. `None` while no sealer is installed. Moves a box:
    /// allocates nothing.
    pub(crate) fn lend_sealer(&mut self) -> Option<Box<Sealer>> {
        if !self.fence_admits() {
            return None;
        }
        match core::mem::replace(&mut self.auth, SenderAuth::Pending) {
            SenderAuth::Sealing(sealer) => Some(sealer),
            other => {
                self.auth = other;
                None
            }
        }
    }

    /// Gives back the sealer [`Outbound::lend_sealer`] lent.
    pub(crate) fn return_sealer(&mut self, sealer: Box<Sealer>) {
        if matches!(self.auth, SenderAuth::Pending) {
            self.auth = SenderAuth::Sealing(sealer);
        }
    }

    /// Applies the key store's current key set to the installed session
    /// sealer of either class (H8 finding 4, ADR-0086 section 7). An
    /// authenticated one is kept while its channel
    /// file signs; on a routine file epoch rotation, while its own file
    /// still verifies through the overlap, re-keyed to the new signing
    /// file under the same establishment (no re-establishment; the new key
    /// starts its own sequence); otherwise (revoked, expired, no longer
    /// verifying, or the store disabled) withdrawn, its key erased in
    /// place. A withdrawn one stays installed as a tombstone (H8 N1): it
    /// seals nothing, does not come back if its file does, and a sealer of
    /// the same establishment (party) is refused, so no sequence restarts
    /// under its key; only a new establishment, with new key derivation
    /// inputs, replaces it.
    pub(crate) fn follow_keys(&mut self, keys: &dyn crate::wire_auth::KeySet) {
        match &mut self.auth {
            SenderAuth::Sealing(sealer) => sealer.follow(keys),
            // An encrypted publication's domain 1 sealer: withdrawn, its
            // key erased in place, once its key epoch is revoked or
            // expired. It stays installed as a tombstone: it seals nothing,
            // and a sealer of the same establishment (salt) is refused, so
            // no sequence ever restarts under its key; only a new
            // establishment replaces it.
            SenderAuth::Encrypting(sealer) => sealer.apply_keys(keys),
            SenderAuth::Off | SenderAuth::Pending | SenderAuth::EncPending => {}
        }
    }

    /// Whether an installed authenticated sealer still seals (tests): a
    /// withdrawn one stays installed as a tombstone.
    #[cfg(test)]
    pub(crate) fn sealer_live(&self) -> bool {
        matches!(&self.auth, SenderAuth::Sealing(sealer) if sealer.can_seal())
    }

    /// The installed sealer's party (tests).
    #[cfg(test)]
    pub(crate) fn sealer_party(&self) -> Option<crate::wire_auth::Party> {
        match &self.auth {
            SenderAuth::Sealing(sealer) => Some(sealer.party()),
            SenderAuth::Off
            | SenderAuth::Pending
            | SenderAuth::EncPending
            | SenderAuth::Encrypting(_) => None,
        }
    }

    /// Makes the publication encrypted (ADR-0114): from now on it sends
    /// nothing until `Outbound::install_enc_sealer` gives it the
    /// session's domain 1 key. Its log must be sized for the encrypted
    /// inner budget, the channel MTU (at most 1408) less the 84-byte
    /// envelope.
    ///
    /// # Errors
    ///
    /// [`AuthUnsupported::NotUnicast`] for a multi-destination, dynamic or
    /// routed publication, and [`AuthUnsupported::Started`] once anything
    /// was staged or sent bare, or the publication is already of another
    /// class; nothing changes.
    pub fn require_enc(&mut self) -> Result<(), AuthUnsupported> {
        if self.routed.is_some() || self.fanout.is_some() || self.registration.is_some() {
            return Err(AuthUnsupported::NotUnicast);
        }
        match self.auth {
            SenderAuth::EncPending | SenderAuth::Encrypting(_) => return Ok(()),
            SenderAuth::Pending | SenderAuth::Sealing(_) => return Err(AuthUnsupported::Started),
            SenderAuth::Off => {}
        }
        let staged = self.tracks.iter().any(|track| !track.staged.is_empty())
            || (0..self.readers.len()).any(|lane| self.sender.pending(lane).unwrap_or(0) > 0);
        if self.counters.staged > 0 || staged {
            return Err(AuthUnsupported::Started);
        }
        if let Some(repair) = self.repair.as_deref_mut() {
            repair.reserve_envelope(ENC_ENVELOPE_LEN);
        }
        self.auth = SenderAuth::EncPending;
        Ok(())
    }

    /// The current `party_epoch` of the session's encrypted sealer, which
    /// its ENC ANSWER states.
    pub(crate) fn enc_party_epoch(&self) -> Option<u16> {
        match &self.auth {
            SenderAuth::Encrypting(sealer) => Some(sealer.context().party_epoch),
            _ => None,
        }
    }

    /// Lends the installed encrypted sealer, to seal one of the
    /// publication's sender controls in domain 1 under the same envelope
    /// sequence as its DATA; [`Outbound::return_enc_sealer`] gives it back.
    /// Moves a box: allocates nothing.
    pub(crate) fn lend_enc_sealer(&mut self) -> Option<Box<EncSealer>> {
        if !self.fence_admits() {
            return None;
        }
        match core::mem::replace(&mut self.auth, SenderAuth::EncPending) {
            SenderAuth::Encrypting(sealer) => Some(sealer),
            other => {
                self.auth = other;
                None
            }
        }
    }

    /// Gives back the sealer [`Outbound::lend_enc_sealer`] lent.
    pub(crate) fn return_enc_sealer(&mut self, sealer: Box<EncSealer>) {
        if matches!(self.auth, SenderAuth::EncPending) {
            self.auth = SenderAuth::Encrypting(sealer);
        }
    }

    /// Moves the session's encrypted sealer `count` epochs on, as its
    /// budgets would (tests).
    #[cfg(test)]
    pub(crate) fn roll_enc_epochs(&mut self, count: u16) {
        if let SenderAuth::Encrypting(sealer) = &mut self.auth {
            for _ in 0..count {
                sealer.roll_now();
            }
        }
    }

    /// Installs the session's domain 1 sealer of an encrypted publication,
    /// made at establishment. A new binding replaces it; its own sealer
    /// is never installed twice, so no envelope sequence restarts under
    /// one key.
    ///
    /// # Errors
    ///
    /// [`AuthUnsupported::NotAuthenticated`] unless
    /// [`Outbound::require_enc`] was called first, and
    /// [`AuthUnsupported::SameEstablishment`] for a sealer of the
    /// establishment already installed, or of another domain.
    pub(crate) fn install_enc_sealer(&mut self, sealer: EncSealer) -> Result<(), AuthUnsupported> {
        match &self.auth {
            SenderAuth::EncPending => {}
            SenderAuth::Encrypting(current) if current.context().salt != sealer.context().salt => {}
            SenderAuth::Encrypting(_) => return Err(AuthUnsupported::SameEstablishment),
            SenderAuth::Off | SenderAuth::Pending | SenderAuth::Sealing(_) => {
                return Err(AuthUnsupported::NotAuthenticated);
            }
        }
        if sealer.domain() != EncDomain::Sender {
            return Err(AuthUnsupported::SameEstablishment);
        }
        self.auth = SenderAuth::Encrypting(Box::new(sealer));
        Ok(())
    }

    /// Drops the session's encrypted sealer, which erases its key and
    /// sequence (ADR-0114 section 10 step 2): the publication stays
    /// encrypted and sends nothing until another is installed. Nothing
    /// changes for a publication of another class.
    pub(crate) fn retire_enc_sealer(&mut self) {
        if matches!(self.auth, SenderAuth::Encrypting(_)) {
            self.auth = SenderAuth::EncPending;
        }
    }

    /// Takes out and erases the authenticated session sealer (a VM
    /// generation change; karyos#648): the publication sends nothing until
    /// a fresh establishment installs another. Nothing changes for a
    /// publication of another class.
    pub(crate) fn retire_auth_sealer(&mut self) {
        if matches!(self.auth, SenderAuth::Sealing(_)) {
            self.auth = SenderAuth::Pending;
        }
    }

    /// Whether it is of the authenticated class (not the encrypted one):
    /// it seals under a publication binding, or waits for one.
    pub(crate) fn needs_auth_binding(&self) -> bool {
        matches!(self.auth, SenderAuth::Sealing(_) | SenderAuth::Pending)
    }

    /// Whether the publication is authenticated.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        !matches!(self.auth, SenderAuth::Off)
    }
}
