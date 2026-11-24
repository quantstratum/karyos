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

use thiserror::Error;

use super::Outbound;
use crate::embedded::StreamTerms;
use crate::wire_auth::{ENVELOPE_LEN, Sealer};

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
}

impl SenderAuth {
    /// Bytes each datagram grows by.
    pub(crate) fn envelope(&self) -> usize {
        match self {
            Self::Off => 0,
            Self::Pending | Self::Sealing(_) => ENVELOPE_LEN,
        }
    }

    /// Whether one more datagram can leave: always on a trusted channel,
    /// only with a sealer that can still seal on an authenticated one.
    pub(crate) fn ready(&self) -> bool {
        match self {
            Self::Off => true,
            Self::Pending => false,
            Self::Sealing(sealer) => sealer.can_seal(),
        }
    }

    /// Seals the first `frames` bytes of `datagram`, which has room for
    /// the envelope, and returns the length to send: `frames` itself on a
    /// trusted channel. `None` when it cannot be sealed; nothing may then
    /// be sent.
    pub(crate) fn seal(&mut self, datagram: &mut [u8], frames: usize) -> Option<usize> {
        match self {
            Self::Off => Some(frames),
            Self::Pending => None,
            Self::Sealing(sealer) => sealer.seal(datagram, frames).ok(),
        }
    }

    /// The sealer, if one is installed.
    pub(crate) fn sealer(&mut self) -> Option<&mut Sealer> {
        match self {
            Self::Sealing(sealer) => Some(sealer),
            Self::Off | Self::Pending => None,
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
        if matches!(self.auth, SenderAuth::Off) {
            self.auth = SenderAuth::Pending;
        }
        Ok(())
    }

    /// Installs the session's sealer, made at establishment, replacing any
    /// earlier one (a re-establishment derives a new key).
    ///
    /// # Errors
    ///
    /// [`AuthUnsupported::NotAuthenticated`] unless
    /// [`Outbound::require_auth`] was called first.
    pub fn install_sealer(&mut self, sealer: Sealer) -> Result<(), AuthUnsupported> {
        if matches!(self.auth, SenderAuth::Off) {
            return Err(AuthUnsupported::NotAuthenticated);
        }
        self.auth = SenderAuth::Sealing(Box::new(sealer));
        Ok(())
    }

    /// Whether the publication is authenticated.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        !matches!(self.auth, SenderAuth::Off)
    }
}
