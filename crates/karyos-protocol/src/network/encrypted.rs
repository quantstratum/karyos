// SPDX-License-Identifier: Apache-2.0

//! SETUP variant 3, ENC ANSWER, of the `encrypted` class
//! (`quantstratum-docs: karyos/design/network-control-schemas.md` 4.1;
//! ADR-0114 section 6a; part of quantstratum/karyos#650).
//!
//! ENC ANSWER is the variant 2 ANSWER with an 8-byte epoch block inserted
//! after the challenge block:
//!
//! | Offset | Width | Field |
//! | --- | --- | --- |
//! | 0 | 24 | common header, `frame_type = 5`, `variant = 3`, `count` the lane count |
//! | 24 | 32 | identity block |
//! | 56 | 16 | term parameters |
//! | 72 | 32 | challenge block |
//! | 104 | 4 | `key_epoch` u32, at least 1 |
//! | 108 | 2 | `party_epoch` u16, any value |
//! | 110 | 2 | reserved, 0 |
//! | 112 | `8n` | `join_position[n]` |
//!
//! It is used only on `encrypted` channels, as the inner frame of a domain
//! 5 datagram. The trusted decoder, [`super::Control::decode`], keeps
//! refusing variant 3 with [`ControlError::InvalidVariant`], which is the
//! refusal on every other channel; on an `encrypted` channel
//! [`decode_setup`] refuses variant 2 the same way. Decoding allocates
//! nothing, reads no clock and changes no state.

use super::{ControlError, MAX_LANES, SetupAnnounce, SetupAnswer};
use crate::frame::FrameType;

/// The variant byte of ENC ANSWER.
pub const ENC_ANSWER_VARIANT: u8 = 3;
/// Bytes of the epoch block.
pub const EPOCH_BLOCK_LENGTH: usize = 8;
/// Offset of the epoch block.
pub const EPOCH_BLOCK_OFFSET: usize = 104;
/// Length of the largest ENC ANSWER: four lanes.
pub const MAX_ENC_ANSWER_LENGTH: usize = 112 + 8 * MAX_LANES;

/// SETUP ENC ANSWER: a variant 2 answer and the sender's current epochs
/// for this publication and binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EncAnswer {
    /// The answer: alias, identity, term parameters, echoed challenge and
    /// join points.
    pub answer: SetupAnswer,
    /// The sender's current `key_epoch`; at least 1, and equal to the
    /// envelope's (checked by the receiver).
    pub key_epoch: u32,
    /// The sender's current domain 1 `party_epoch` for this binding.
    pub party_epoch: u16,
}

/// A SETUP on an `encrypted` channel: ANNOUNCE or ENC ANSWER.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncSetup {
    /// Variant 1.
    Announce(SetupAnnounce),
    /// Variant 3.
    Answer(EncAnswer),
}

impl EncAnswer {
    /// The encoded length: `112 + 8n`.
    #[must_use]
    pub fn encoded_length(&self) -> usize {
        112 + 8 * usize::from(self.answer.joins.count())
    }

    /// Encodes into the start of `out`; returns the length. Every field is
    /// validated before anything is written.
    ///
    /// # Errors
    ///
    /// [`ControlError::InvalidValue`] for `key_epoch` 0, the answer's own
    /// encode errors, and [`ControlError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ControlError> {
        if self.key_epoch == 0 {
            return Err(ControlError::InvalidValue);
        }
        let mut inner = [0u8; MAX_ENC_ANSWER_LENGTH];
        let inner_length = self.answer.encode(&mut inner)?;
        let length = inner_length.saturating_add(EPOCH_BLOCK_LENGTH);
        let frame_length = i32::try_from(length).map_err(|_| ControlError::InvalidLength)?;
        let available = out.len();
        let target = out.get_mut(..length).ok_or(ControlError::BufferTooShort {
            required: length,
            available,
        })?;
        let (head, rest) = target
            .split_at_mut_checked(EPOCH_BLOCK_OFFSET)
            .ok_or(ControlError::InvalidLength)?;
        head.copy_from_slice(inner.get(..EPOCH_BLOCK_OFFSET).unwrap_or_default());
        if let Some(slot) = head.get_mut(..4) {
            slot.copy_from_slice(&frame_length.to_le_bytes());
        }
        if let Some(slot) = head.get_mut(8) {
            *slot = ENC_ANSWER_VARIANT;
        }
        let (block, joins) = rest
            .split_at_mut_checked(EPOCH_BLOCK_LENGTH)
            .ok_or(ControlError::InvalidLength)?;
        block.copy_from_slice(&epoch_block(self.key_epoch, self.party_epoch));
        joins.copy_from_slice(
            inner
                .get(EPOCH_BLOCK_OFFSET..inner_length)
                .unwrap_or_default(),
        );
        Ok(length)
    }

    /// Decodes one datagram holding exactly an ENC ANSWER.
    ///
    /// The common word and variant come first, then the length and count,
    /// then the epoch block (reserved bytes, then `key_epoch`), then every
    /// check of the variant 2 body in its own order.
    ///
    /// # Errors
    ///
    /// [`ControlError::WrongKind`] for another frame type;
    /// [`ControlError::InvalidVariant`] for any other variant, a variant 2
    /// ANSWER included; [`ControlError::Truncated`],
    /// [`ControlError::InvalidGrouping`], [`ControlError::InvalidLength`]
    /// or [`ControlError::InvalidCount`] for a length that is not
    /// `112 + 8n`; [`ControlError::ReservedBits`] for a nonzero reserved
    /// epoch field; [`ControlError::InvalidValue`] for `key_epoch` 0; then
    /// every error of the variant 2 body.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        let code = u16::from_le_bytes([byte(bytes, 6)?, byte(bytes, 7)?]);
        if code != FrameType::Setup.code() {
            return Err(ControlError::WrongKind { code });
        }
        if bytes.len() < super::CONTROL_HEADER_LENGTH {
            return Err(ControlError::Truncated);
        }
        if byte(bytes, 8)? != ENC_ANSWER_VARIANT {
            return Err(ControlError::InvalidVariant);
        }
        let count = byte(bytes, 9)?;
        if count == 0 || usize::from(count) > MAX_LANES {
            return Err(ControlError::InvalidCount);
        }
        let length = 112 + 8 * usize::from(count);
        let frame_length = usize::try_from(i32::from_le_bytes(word(bytes, 0)?))
            .map_err(|_| ControlError::InvalidLength)?;
        match frame_length.cmp(&bytes.len()) {
            core::cmp::Ordering::Greater => return Err(ControlError::Truncated),
            core::cmp::Ordering::Less => return Err(ControlError::InvalidGrouping),
            core::cmp::Ordering::Equal => {}
        }
        if frame_length != length {
            return Err(ControlError::InvalidLength);
        }
        if bytes.get(110..112) != Some(&[0, 0][..]) {
            return Err(ControlError::ReservedBits);
        }
        let key_epoch = u32::from_le_bytes(word(bytes, EPOCH_BLOCK_OFFSET)?);
        if key_epoch == 0 {
            return Err(ControlError::InvalidValue);
        }
        let party_epoch = u16::from_le_bytes([byte(bytes, 108)?, byte(bytes, 109)?]);
        // The variant 2 image: the same bytes without the epoch block.
        let inner_length = length - EPOCH_BLOCK_LENGTH;
        let mut inner = [0u8; MAX_ENC_ANSWER_LENGTH];
        let (head, joins) = inner
            .split_at_mut_checked(EPOCH_BLOCK_OFFSET)
            .ok_or(ControlError::InvalidLength)?;
        head.copy_from_slice(bytes.get(..EPOCH_BLOCK_OFFSET).unwrap_or_default());
        let tail = bytes.get(112..).unwrap_or_default();
        joins
            .get_mut(..tail.len())
            .ok_or(ControlError::Truncated)?
            .copy_from_slice(tail);
        let inner_frame = i32::try_from(inner_length).map_err(|_| ControlError::InvalidLength)?;
        if let Some(slot) = inner.get_mut(..4) {
            slot.copy_from_slice(&inner_frame.to_le_bytes());
        }
        if let Some(slot) = inner.get_mut(8) {
            *slot = 2;
        }
        let answer = SetupAnswer::decode(inner.get(..inner_length).unwrap_or_default())?;
        Ok(Self {
            answer,
            key_epoch,
            party_epoch,
        })
    }
}

/// Decodes the one SETUP an `encrypted` domain 5 datagram may carry:
/// ANNOUNCE (variant 1) or ENC ANSWER (variant 3).
///
/// # Errors
///
/// [`ControlError::InvalidVariant`] for a variant 2 ANSWER or any other
/// variant: an `encrypted` channel never takes a variant 2 answer, and the
/// receiver never retries with one; [`ControlError::WrongKind`] for
/// another frame type; otherwise the variant's own errors.
pub fn decode_setup(bytes: &[u8]) -> Result<EncSetup, ControlError> {
    let code = u16::from_le_bytes([byte(bytes, 6)?, byte(bytes, 7)?]);
    if code != FrameType::Setup.code() {
        return Err(ControlError::WrongKind { code });
    }
    match byte(bytes, 8)? {
        1 => SetupAnnounce::decode(bytes).map(EncSetup::Announce),
        ENC_ANSWER_VARIANT => EncAnswer::decode(bytes).map(EncSetup::Answer),
        _ => Err(ControlError::InvalidVariant),
    }
}

/// The 8 bytes of the epoch block.
fn epoch_block(key_epoch: u32, party_epoch: u16) -> [u8; EPOCH_BLOCK_LENGTH] {
    let mut out = [0u8; EPOCH_BLOCK_LENGTH];
    let (key, rest) = out.split_at_mut(4);
    key.copy_from_slice(&key_epoch.to_le_bytes());
    if let Some(slot) = rest.get_mut(..2) {
        slot.copy_from_slice(&party_epoch.to_le_bytes());
    }
    out
}

fn byte(bytes: &[u8], at: usize) -> Result<u8, ControlError> {
    bytes.get(at).copied().ok_or(ControlError::Truncated)
}

fn word(bytes: &[u8], at: usize) -> Result<[u8; 4], ControlError> {
    bytes
        .get(at..at.saturating_add(4))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ControlError::Truncated)
}

#[cfg(test)]
mod tests;
