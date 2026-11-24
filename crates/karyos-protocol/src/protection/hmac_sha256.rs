// SPDX-License-Identifier: Apache-2.0

//! The selected wire authentication profile: HMAC-SHA-256 with a 16-byte
//! tag, `profile_id` 1 of the wire authentication profile v1
//! (`quantstratum-docs: karyos/adr/0086-wire-authentication-profile-v1.md`,
//! sections 1 to 3 and 6; owner decision D51).
//!
//! A datagram is `header || inner frames || tag`:
//!
//! | Offset | Width | Field |
//! | --- | --- | --- |
//! | 0 | 4 | `datagram_length`, i32, tag included |
//! | 4 | 1 | `version`, 1 |
//! | 5 | 1 | `flags`, 0 |
//! | 6 | 2 | `frame_type`, `0x20` |
//! | 8 | 1 | `profile_id`, 1 |
//! | 9 | 1 | `tag_len`, 16 |
//! | 10 | 1 | `domain` |
//! | 11 | 1 | `party_epoch` |
//! | 12 | 4 | `session_id` |
//! | 16 | 4 | `stream_id` |
//! | 20 | 4 | `key_id` |
//! | 24 | 8 | `envelope_seq`, u64, never wraps |
//!
//! All fields are little-endian. The tag is the leftmost 16 bytes of
//! HMAC-SHA-256 over `label || header || inner frames`, where the label is
//! the 20 bytes `karyos-wire-auth-v1\0`, never transmitted. Every field is
//! checked against the channel's [`Binding`] before the tag, and the tag
//! is compared in constant time by [`HmacState::verify_truncated_left`].
//! The key is held as an [`HmacKey`], whose padded copies are erased.
//!
//! This module implements the MAC domains only (DATA, receiver to
//! publisher, SETUP proof and RSP_SETUP). The signed authority domains, key
//! files, derivation and the channel gate are separate parts of
//! quantstratum/karyos#648. Nothing here enables an authenticated channel.

use core::cell::Cell;

use super::hmac_key::{HmacKey, HmacState};
use super::{Protection, Rejection, SealError, Verdict};

/// The label every MAC input starts with (ADR-0086 section 1).
pub const LABEL: &[u8; 20] = b"karyos-wire-auth-v1\0";
/// Bytes of the envelope header.
pub const HEADER_LEN: usize = 32;
/// Bytes of the tag.
pub const TAG_LEN: usize = 16;
/// The envelope's frame type (ADR-0086 open point 4).
pub const FRAME_TYPE: u16 = 0x20;
/// The envelope version.
pub const VERSION: u8 = 1;
/// The `profile_id` of HMAC-SHA-256 with a 16-byte tag.
pub const PROFILE_ID: u8 = 1;

/// The MAC key purposes of ADR-0086 section 2 (`domain`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Domain {
    /// DATA.
    Data = 1,
    /// Receiver to publisher: SM, NAK and SESSION_ABORT_ACK.
    ReceiverToPublisher = 4,
    /// SETUP proof.
    SetupProof = 5,
    /// RSP_SETUP.
    RspSetup = 6,
}

/// The fields a channel binds at establishment, which every datagram must
/// carry unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// Key purpose.
    pub domain: Domain,
    /// The sender's in-band key epoch.
    pub party_epoch: u8,
    /// The session id of the DATA header.
    pub session_id: i32,
    /// The stream id of the DATA header.
    pub stream_id: i32,
    /// The key file this key comes from.
    pub key_id: u32,
}

/// A datagram that passed every field check and its tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    /// Offset of the inner frames.
    pub start: usize,
    /// Length of the inner frames.
    pub frames: usize,
    /// The envelope sequence, for the replay window.
    pub seq: u64,
}

/// One HMAC-SHA-256/16 key bound to one channel and domain.
///
/// A value seals with consecutive envelope sequences from `first_seq`; it
/// is meant for one sender thread and is not `Sync`. The keyed MAC state is
/// erased on drop (`sha2` feature `zeroize`).
pub struct HmacSha256 {
    mac: HmacKey,
    binding: Binding,
    next_seq: Cell<u64>,
}

impl core::fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HmacSha256")
            .field("binding", &self.binding)
            .field("next_seq", &self.next_seq.get())
            .finish_non_exhaustive()
    }
}

/// The key is empty, which HMAC allows but the profile does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("an HMAC-SHA-256 profile key must not be empty")]
pub struct EmptyKey;

impl HmacSha256 {
    /// A profile for `binding`, keyed with `key`, sealing from `first_seq`.
    ///
    /// # Errors
    ///
    /// [`EmptyKey`] when `key` is empty.
    pub fn new(key: &[u8], binding: Binding, first_seq: u64) -> Result<Self, EmptyKey> {
        if key.is_empty() {
            return Err(EmptyKey);
        }
        let mac = HmacKey::new(key);
        Ok(Self {
            mac,
            binding,
            next_seq: Cell::new(first_seq),
        })
    }

    /// The binding this profile checks.
    #[must_use]
    pub fn binding(&self) -> Binding {
        self.binding
    }

    /// The sequence the next [`Protection::seal`] uses.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq.get()
    }

    /// The keyed MAC over `label || authed`.
    fn mac_over(&self, authed: &[u8]) -> HmacState {
        let mut mac = self.mac.mac();
        mac.update(LABEL);
        mac.update(authed);
        mac
    }

    /// Seals the `frames` bytes at the start of `datagram` with envelope
    /// sequence `seq`: moves them behind the header, writes the header and
    /// the tag, and returns the datagram length. Allocates nothing.
    ///
    /// # Errors
    ///
    /// [`SealError`] when `datagram` cannot hold the envelope, or when the
    /// length does not fit the i32 `datagram_length`.
    pub fn seal_with(
        &self,
        datagram: &mut [u8],
        frames: usize,
        seq: u64,
    ) -> Result<usize, SealError> {
        let envelope = HEADER_LEN.checked_add(TAG_LEN).ok_or(SealError {
            needed: usize::MAX,
            available: datagram.len(),
        })?;
        let total = super::sealed_len(datagram, frames, envelope)?;
        let length = i32::try_from(total).map_err(|_| SealError {
            needed: total,
            available: usize::try_from(i32::MAX).unwrap_or(usize::MAX),
        })?;
        let authed_len = HEADER_LEN.checked_add(frames).ok_or(SealError {
            needed: usize::MAX,
            available: datagram.len(),
        })?;
        let sealed = datagram.get_mut(..total).ok_or(SealError {
            needed: total,
            available: 0,
        })?;
        sealed.copy_within(..frames, HEADER_LEN);
        let header = encode_header(length, &self.binding, seq);
        if let Some(slot) = sealed.get_mut(..HEADER_LEN) {
            slot.copy_from_slice(&header);
        }
        let (authed, tag) = sealed.split_at_mut_checked(authed_len).ok_or(SealError {
            needed: authed_len,
            available: total,
        })?;
        let full = self.mac_over(authed).finalize();
        if let (Some(slot), Some(value)) = (tag.get_mut(..TAG_LEN), full.get(..TAG_LEN)) {
            slot.copy_from_slice(value);
        }
        Ok(total)
    }

    /// Opens a received datagram: the fixed fields, then the binding, then
    /// the tag. Nothing about the datagram is trusted before the tag
    /// verifies, and a rejection changes no state. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The first [`Rejection`] that applies.
    pub fn open_envelope(&self, datagram: &[u8]) -> Result<Opened, Rejection> {
        let min = HEADER_LEN.checked_add(TAG_LEN).ok_or(Rejection::Short)?;
        if datagram.len() < min {
            return Err(Rejection::Short);
        }
        let header = datagram.get(..HEADER_LEN).ok_or(Rejection::Short)?;
        let field =
            |at: usize, width: usize| header.get(at..at.saturating_add(width)).unwrap_or_default();
        let byte = |at: usize| header.get(at).copied().unwrap_or_default();
        let declared = i32::from_le_bytes(field(0, 4).try_into().map_err(|_| Rejection::Short)?);
        if usize::try_from(declared).ok() != Some(datagram.len()) {
            return Err(Rejection::Length);
        }
        if byte(4) != VERSION {
            return Err(Rejection::Version);
        }
        if byte(5) != 0 {
            return Err(Rejection::Flags);
        }
        if u16::from_le_bytes(field(6, 2).try_into().map_err(|_| Rejection::Short)?) != FRAME_TYPE {
            return Err(Rejection::FrameType);
        }
        if byte(8) != PROFILE_ID {
            return Err(Rejection::Profile);
        }
        if usize::from(byte(9)) != TAG_LEN {
            return Err(Rejection::TagLength);
        }
        if byte(10) != self.binding.domain as u8 {
            return Err(Rejection::Domain);
        }
        if byte(11) != self.binding.party_epoch {
            return Err(Rejection::Epoch);
        }
        let int = |at: usize| {
            field(at, 4)
                .try_into()
                .map(i32::from_le_bytes)
                .map_err(|_| Rejection::Short)
        };
        if int(12)? != self.binding.session_id || int(16)? != self.binding.stream_id {
            return Err(Rejection::Binding);
        }
        let key_id = field(20, 4)
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| Rejection::Short)?;
        if key_id != self.binding.key_id {
            return Err(Rejection::Key);
        }
        let seq = field(24, 8)
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| Rejection::Short)?;
        let authed_len = datagram
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Rejection::Short)?;
        let (authed, tag) = datagram
            .split_at_checked(authed_len)
            .ok_or(Rejection::Short)?;
        if !self.mac_over(authed).verify_truncated_left(tag) {
            return Err(Rejection::Tag);
        }
        let frames = authed_len.checked_sub(HEADER_LEN).ok_or(Rejection::Short)?;
        Ok(Opened {
            start: HEADER_LEN,
            frames,
            seq,
        })
    }
}

/// The 32 header bytes for a datagram of `length` bytes.
fn encode_header(length: i32, binding: &Binding, seq: u64) -> [u8; HEADER_LEN] {
    let mut header = [0_u8; HEADER_LEN];
    let mut put = |at: usize, bytes: &[u8]| {
        if let Some(slot) = header.get_mut(at..at.saturating_add(bytes.len())) {
            slot.copy_from_slice(bytes);
        }
    };
    put(0, &length.to_le_bytes());
    put(4, &[VERSION, 0]);
    put(6, &FRAME_TYPE.to_le_bytes());
    put(
        8,
        &[PROFILE_ID, 16, binding.domain as u8, binding.party_epoch],
    );
    put(12, &binding.session_id.to_le_bytes());
    put(16, &binding.stream_id.to_le_bytes());
    put(20, &binding.key_id.to_le_bytes());
    put(24, &seq.to_le_bytes());
    header
}

impl Protection for HmacSha256 {
    fn envelope_len(&self) -> usize {
        HEADER_LEN.saturating_add(TAG_LEN)
    }

    /// Seals with the next envelope sequence. When the sequence space is
    /// exhausted the seal fails with `needed == usize::MAX`, and the
    /// incarnation must close (manifest 4.3: the sequence never wraps).
    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError> {
        let seq = self.next_seq.get();
        let next = seq.checked_add(1).ok_or(SealError {
            needed: usize::MAX,
            available: datagram.len(),
        })?;
        let total = self.seal_with(datagram, frames, seq)?;
        self.next_seq.set(next);
        Ok(total)
    }

    fn open(&self, datagram: &[u8]) -> Verdict {
        match self.open_envelope(datagram) {
            Ok(opened) => Verdict::Accept {
                start: opened.start,
                frames: opened.frames,
            },
            Err(rejection) => Verdict::Reject(rejection),
        }
    }
}

#[cfg(test)]
mod tests;
