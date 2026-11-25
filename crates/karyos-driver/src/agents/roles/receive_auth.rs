// SPDX-License-Identifier: Apache-2.0

//! The wire authentication of an image's receive side, unicast
//! (`quantstratum-docs:
//! karyos/adr/0086-wire-authentication-profile-v1.md` sections 2, 4, 6
//! and 7a; part of quantstratum/karyos#648).
//!
//! An authenticated image opens every datagram of its binding with its
//! domain 1 [`Verifier`] before any inner frame is read, and seals every
//! control it sends (SM, NAK, RTTM REQUEST) with its domain 4 [`Sealer`].
//! A refused datagram changes nothing but a counter; a bare frame for an
//! authenticated binding is refused, and an envelope for no authenticated
//! binding is refused. Nothing makes an image authenticated yet: whether a
//! channel is authenticated comes from its configuration bound at
//! establishment, and `authenticated` channels are still refused.

use karyos_protocol::network::Alias;
use karyos_protocol::protection::hmac_sha256::{Domain, FRAME_TYPE};

use super::super::control::SharedSealer;
use crate::wire_auth::{KeyError, Party, Refusal, Sealer, Verifier};
use crate::wire_keys::KeyFile;

/// An authenticated image's keys: the sender's datagrams are opened in
/// domain 1, its own controls sealed in domain 4.
#[derive(Debug)]
pub(crate) struct ImageAuth {
    verifier: Verifier,
    sealer: SharedSealer,
    /// The wall clock in seconds, for the in-band epoch overlap.
    wall: fn() -> i64,
}

/// What the envelope of a datagram opened to: its inner frames' range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Inner {
    pub(crate) start: usize,
    pub(crate) len: usize,
}

impl ImageAuth {
    /// The keys of an image whose publication is `sender` (a
    /// [`Party::Sender`]) and whose receiver is `receiver` (a
    /// [`Party::Receiver`]) on `alias`: the channel key files `channel`
    /// verify the sender's datagrams, the pairwise signing key `pairwise`
    /// seals the receiver's controls.
    ///
    /// # Errors
    ///
    /// [`KeyError`] when a party is of the wrong kind or a file does not
    /// fit its party.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no authenticated channel opens yet")
    )]
    pub(crate) fn new<'a>(
        channel: impl IntoIterator<Item = &'a KeyFile>,
        pairwise: &KeyFile,
        sender: Party,
        receiver: Party,
        alias: Alias,
    ) -> Result<Self, KeyError> {
        if !matches!(sender, Party::Sender { .. }) || !matches!(receiver, Party::Receiver { .. }) {
            return Err(KeyError::Purpose);
        }
        let verifier = Verifier::new(channel, sender, alias)?;
        let sealer = Sealer::new(pairwise, receiver, alias)?;
        if sealer.domain() != Domain::ReceiverToPublisher {
            return Err(KeyError::Purpose);
        }
        Ok(Self {
            verifier,
            sealer: SharedSealer::new(sealer),
            wall: wall_seconds,
        })
    }

    /// Uses `wall` as the wall clock in seconds (tests).
    #[cfg(test)]
    pub(crate) fn set_wall(&mut self, wall: fn() -> i64) {
        self.wall = wall;
    }

    /// Opens `datagram`: its fields, its tag, then its replay window, and
    /// only then the inner frames' range. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The [`Refusal`]; nothing changes.
    pub(crate) fn open(&mut self, datagram: &[u8]) -> Result<Inner, Refusal> {
        let opened = self.verifier.open(datagram, (self.wall)())?;
        Ok(Inner {
            start: opened.start,
            len: opened.frames,
        })
    }

    /// The sealer of the image's controls: shared, allocation free.
    pub(crate) fn sealer(&self) -> SharedSealer {
        self.sealer.clone()
    }
}

/// Whether `bytes` starts like a wire authentication envelope: its frame
/// type field (bytes 6 to 8, little-endian) names the envelope.
pub(crate) fn is_envelope(bytes: &[u8]) -> bool {
    bytes
        .get(6..8)
        .is_some_and(|field| field == FRAME_TYPE.to_le_bytes())
}

/// The binding alias an envelope names (its `session_id` and `stream_id`
/// at offsets 12 and 16), read only to find the binding whose key opens
/// it; `None` for a datagram too short to hold them.
pub(crate) fn envelope_alias(bytes: &[u8]) -> Option<Alias> {
    let session_id = i32::from_le_bytes(bytes.get(12..16)?.try_into().ok()?);
    let stream_id = i32::from_le_bytes(bytes.get(16..20)?.try_into().ok()?);
    Some(Alias {
        session_id,
        stream_id,
    })
}

/// The wall clock in whole seconds since the Unix epoch. A clock before
/// the epoch reads as the far future, which ends every in-band overlap
/// early (fail closed) and never extends one.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "no authenticated channel opens yet")
)]
pub(crate) fn wall_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(i64::MAX, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}
