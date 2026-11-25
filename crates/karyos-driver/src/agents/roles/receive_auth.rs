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

use karyos_protocol::protection::Rejection;
use karyos_protocol::protection::hmac_sha256::Opened;
use karyos_protocol::protection::replay::Replay;

use super::super::control::SharedSealer;
use crate::wire_auth::{Checked, KeyError, Party, Refusal, Sealer, Verifier};
use crate::wire_keys::KeyFile;

/// Why a received datagram was refused, one counter each (ADR-0086
/// section 2: per key and source, by reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum AuthReason {
    /// Shorter than the envelope.
    Short = 0,
    /// `datagram_length` is not the datagram's length.
    Length,
    /// Another envelope version.
    Version,
    /// Nonzero flags.
    Flags,
    /// Another frame type.
    FrameType,
    /// Another profile.
    Profile,
    /// Another tag length.
    TagLength,
    /// Another domain.
    Domain,
    /// No key of its party epoch.
    Epoch,
    /// Another session or stream.
    Binding,
    /// An unknown `key_id`.
    Key,
    /// A tag that does not verify.
    Tag,
    /// A sequence already accepted.
    Duplicate,
    /// A sequence older than the window.
    TooOld,
    /// It opened, but its inner frames are not a domain 1 datagram of its
    /// own binding: its sequence is not consumed.
    Inner,
    /// An envelope for no authenticated binding.
    Unbound,
}

/// Reasons a datagram is refused for.
pub const AUTH_REASONS: usize = AuthReason::Unbound as usize + 1;

impl AuthReason {
    /// The reason of `refusal`.
    #[must_use]
    pub fn of(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Envelope(rejection) => match rejection {
                Rejection::Short => Self::Short,
                Rejection::Length => Self::Length,
                Rejection::Version => Self::Version,
                Rejection::Flags => Self::Flags,
                Rejection::FrameType => Self::FrameType,
                Rejection::Profile => Self::Profile,
                Rejection::TagLength => Self::TagLength,
                Rejection::Domain => Self::Domain,
                Rejection::Epoch => Self::Epoch,
                Rejection::Binding => Self::Binding,
                Rejection::Key => Self::Key,
                Rejection::Tag => Self::Tag,
            },
            Refusal::Replay(Replay::Duplicate) => Self::Duplicate,
            Refusal::Replay(Replay::TooOld) => Self::TooOld,
        }
    }
}

/// Refusals by reason: fixed, saturating, allocation free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthRejections {
    counts: [u64; AUTH_REASONS],
}

impl AuthRejections {
    /// Counts one refusal for `reason`.
    pub fn bump(&mut self, reason: AuthReason) {
        if let Some(count) = self.counts.get_mut(reason as usize) {
            *count = count.saturating_add(1);
        }
    }

    /// The refusals for `reason`.
    #[cfg(test)]
    #[must_use]
    pub fn get(&self, reason: AuthReason) -> u64 {
        self.counts.get(reason as usize).copied().unwrap_or(0)
    }

    /// Every reason's count, by [`AuthReason`] value.
    #[cfg(test)]
    #[must_use]
    pub fn counts(&self) -> [u64; AUTH_REASONS] {
        self.counts
    }
}

/// An authenticated image's keys: the sender's datagrams are opened in
/// domain 1, its own controls sealed in domain 4.
#[derive(Debug)]
pub(crate) struct ImageAuth {
    verifier: Verifier,
    sealer: SharedSealer,
    /// Its binding's refusals: one key and one source, by reason.
    pub(crate) rejections: AuthRejections,
    /// The wall clock in seconds, for the in-band epoch overlap.
    wall: fn() -> i64,
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
            rejections: AuthRejections::default(),
            wall: wall_seconds,
        })
    }

    /// Uses `wall` as the wall clock in seconds (tests).
    #[cfg(test)]
    pub(crate) fn set_wall(&mut self, wall: fn() -> i64) {
        self.wall = wall;
    }

    /// The wall clock reading one datagram is checked and committed at.
    pub(crate) fn now(&self) -> i64 {
        (self.wall)()
    }

    /// Checks `datagram`'s fields, tag and replay window at `now`; changes
    /// nothing. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The [`Refusal`].
    pub(crate) fn check(&self, datagram: &[u8], now: i64) -> Result<Checked, Refusal> {
        self.verifier.check(datagram, now)
    }

    /// Records a checked datagram its caller accepts: its sequence, and any
    /// in-band epoch move.
    ///
    /// # Errors
    ///
    /// The [`Refusal`]; nothing changes.
    pub(crate) fn commit(&mut self, checked: Checked, now: i64) -> Result<Opened, Refusal> {
        self.verifier.commit(checked, now)
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
