// SPDX-License-Identifier: Apache-2.0

//! Bodies of the authenticated controls GUARD, SESSION_ABORT and
//! SESSION_ABORT_ACK (`quantstratum-docs:
//! karyos/design/authenticated-control-schemas.md`, ADR-0086 open point 5,
//! ADR-0107).
//!
//! These bodies are inner frames of an ADR-0086 envelope. They are decoded
//! only by [`AuthControl::decode`], which a caller reaches after the
//! envelope verified, and by [`decode_bare_status_challenge`] at a guard
//! authority's control endpoint. The trusted decoder,
//! [`super::Control::decode`] and [`super::classify`], still returns
//! [`ControlError::GatedType`] for every one of them. Decoding allocates
//! nothing, reads no clock and changes no state.

use super::{
    CONTROL_HEADER_LENGTH, ControlError, Identity, Lanes, MAX_CONTROL_LENGTH, Reader, Receiver,
    Writer, check_version,
};
use crate::frame::{FrameType, PROTOCOL_VERSION};

/// The `AbortReason` of a guard close (guards-and-abort.md G4).
pub const GUARD_CLOSED: u16 = 1;

/// The largest `lifetime_ms` a GUARD STATE may carry: one hour.
pub const MAX_LIFETIME_MS: u32 = 3_600_000;

/// A guard word (guards-and-abort.md G2): `(epoch << 1) | open`, with the
/// epoch at least 1 and an even epoch open, an odd one closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardWord(u64);

impl GuardWord {
    /// The word for `epoch`, whose parity decides open or closed.
    ///
    /// # Errors
    ///
    /// [`ControlError::InvalidValue`] for epoch 0 or an epoch above
    /// `2^63 - 1`.
    pub fn from_epoch(epoch: u64) -> Result<Self, ControlError> {
        let shifted = epoch
            .checked_shl(1)
            .filter(|_| epoch >> 63 == 0)
            .ok_or(ControlError::InvalidValue)?;
        Self::from_raw(shifted | (1 - (epoch & 1)))
    }

    /// Checks a raw word.
    ///
    /// # Errors
    ///
    /// [`ControlError::InvalidValue`] for epoch 0 or an open bit that does
    /// not match the epoch's parity.
    pub fn from_raw(word: u64) -> Result<Self, ControlError> {
        let epoch = word >> 1;
        if epoch == 0 || word & 1 != 1 - (epoch & 1) {
            return Err(ControlError::InvalidValue);
        }
        Ok(Self(word))
    }

    /// The raw word.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// The epoch, at least 1.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.0 >> 1
    }

    /// Whether the guard is open.
    #[must_use]
    pub const fn is_open(self) -> bool {
        self.0 & 1 == 1
    }
}

/// GUARD STATE: a transition pushed by the authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardState {
    /// The signing authority, at least 1.
    pub authority_id: u64,
    /// The guard, at least 1.
    pub guard_id: u64,
    /// The guard word.
    pub word: GuardWord,
    /// The lifetime of an `Open`, 1 to [`MAX_LIFETIME_MS`].
    pub lifetime_ms: u32,
}

/// GUARD STATUS_CHALLENGE: a receiver's request for the current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusChallenge {
    /// The authority asked, at least 1.
    pub authority_id: u64,
    /// The guard, at least 1.
    pub guard_id: u64,
    /// The challenging receiver.
    pub receiver: Receiver,
    /// Fresh 128-bit nonce; not all zero.
    pub nonce: [u64; 2],
}

/// GUARD STATUS: the authority's answer to one challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardStatus {
    /// The signing authority, at least 1.
    pub authority_id: u64,
    /// The guard, at least 1.
    pub guard_id: u64,
    /// Echo of the challenger.
    pub receiver: Receiver,
    /// Echo of the challenge nonce; not all zero.
    pub nonce: [u64; 2],
    /// The authority's current guard word.
    pub word: GuardWord,
}

/// SESSION_ABORT ABORT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionAbort {
    /// `session_id` and `stream_id` of the aborted session.
    pub alias: super::Alias,
    /// The aborted publication incarnation.
    pub identity: Identity,
    /// The signing authority, at least 1.
    pub authority_id: u64,
    /// The guard whose close caused the abort; 0 only when `reason` is not
    /// [`GUARD_CLOSED`].
    pub guard_id: u64,
    /// The sender's applied guard epoch, at least 1.
    pub guard_epoch: u64,
    /// The `AbortReason`, not 0; an unknown code decodes.
    pub reason: u16,
}

/// One lane of a SESSION_ABORT_ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AckLane {
    /// The contiguous delivered prefix.
    pub delivered: u64,
    /// The end of the unresolved range `[delivered, unresolved_end)`; equal
    /// to `delivered` when nothing is unresolved.
    pub unresolved_end: u64,
}

/// SESSION_ABORT_ACK ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AbortAck {
    /// `session_id` and `stream_id` of the aborted session.
    pub alias: super::Alias,
    /// The acknowledged incarnation.
    pub identity: Identity,
    /// The acknowledging receiver.
    pub receiver: Receiver,
    /// The `guard_epoch` of the acknowledged abort, at least 1.
    pub guard_epoch: u64,
    /// One entry per lane.
    pub lanes: Lanes<AckLane>,
}

/// One decoded authenticated control body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthControl {
    /// GUARD STATE.
    State(GuardState),
    /// GUARD STATUS_CHALLENGE.
    Challenge(StatusChallenge),
    /// GUARD STATUS.
    Status(GuardStatus),
    /// SESSION_ABORT ABORT.
    Abort(SessionAbort),
    /// SESSION_ABORT_ACK ACK.
    Ack(AbortAck),
}

const STATE_LENGTH: usize = 56;
const CHALLENGE_LENGTH: usize = 88;
const STATUS_LENGTH: usize = 88;
const ABORT_LENGTH: usize = 88;
const ACK_BASE: usize = 88;
const ACK_LANE: usize = 16;

/// `(frame_type, variant)` of a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    State,
    Challenge,
    Status,
    Abort,
    Ack,
}

impl Kind {
    fn from_parts(frame_type: FrameType, variant: u8) -> Option<Self> {
        match (frame_type, variant) {
            (FrameType::Guard, 1) => Some(Self::State),
            (FrameType::Guard, 2) => Some(Self::Challenge),
            (FrameType::Guard, 3) => Some(Self::Status),
            (FrameType::SessionAbort, 1) => Some(Self::Abort),
            (FrameType::SessionAbortAck, 1) => Some(Self::Ack),
            _ => None,
        }
    }

    const fn frame_type(self) -> FrameType {
        match self {
            Self::State | Self::Challenge | Self::Status => FrameType::Guard,
            Self::Abort => FrameType::SessionAbort,
            Self::Ack => FrameType::SessionAbortAck,
        }
    }

    const fn variant(self) -> u8 {
        match self {
            Self::State | Self::Abort | Self::Ack => 1,
            Self::Challenge => 2,
            Self::Status => 3,
        }
    }

    /// The schema size for `count`, if `count` is valid.
    fn length(self, count: u8) -> Option<usize> {
        match self {
            Self::State if count == 0 => Some(STATE_LENGTH),
            Self::Challenge if count == 0 => Some(CHALLENGE_LENGTH),
            Self::Status if count == 0 => Some(STATUS_LENGTH),
            Self::Abort if count == 0 => Some(ABORT_LENGTH),
            Self::Ack if (1..=4).contains(&count) => {
                ACK_BASE.checked_add(ACK_LANE.checked_mul(usize::from(count))?)
            }
            _ => None,
        }
    }

    /// Reserved byte ranges in offset order, `session_id` and `stream_id`
    /// included for GUARD.
    const fn reserved(self) -> &'static [(usize, usize)] {
        match self {
            Self::State => &[(10, 24), (52, 56)],
            Self::Challenge => &[(10, 24), (80, 88)],
            Self::Status => &[(10, 24)],
            Self::Abort => &[(10, 12), (20, 24), (82, 88)],
            Self::Ack => &[(10, 12), (20, 24)],
        }
    }
}

impl AuthControl {
    /// Decodes the inner frame of a verified envelope (design section 2;
    /// network-control-schemas.md 3.5 order).
    ///
    /// # Errors
    ///
    /// The first [`ControlError`] of the decode order; `WrongKind` for a
    /// type other than GUARD, SESSION_ABORT or SESSION_ABORT_ACK.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        let r = Reader(bytes);
        let frame_length = r.i32(0)?;
        let code = r.u16(6)?;
        check_version(r.u8(4)?, code, frame_length)?;
        let frame_type = match FrameType::try_from_code(code) {
            Err(_) => return Err(ControlError::UnknownType { code }),
            Ok(t @ (FrameType::Guard | FrameType::SessionAbort | FrameType::SessionAbortAck)) => t,
            Ok(_) => return Err(ControlError::WrongKind { code }),
        };
        let frame_length = usize::try_from(frame_length)
            .ok()
            .filter(|length| *length > 0)
            .ok_or(ControlError::InvalidLength)?;
        match frame_length.cmp(&bytes.len()) {
            core::cmp::Ordering::Greater => return Err(ControlError::Truncated),
            core::cmp::Ordering::Less => return Err(ControlError::InvalidGrouping),
            core::cmp::Ordering::Equal => {}
        }
        if r.u8(5)? != 0 {
            return Err(ControlError::ReservedBits);
        }
        if frame_length < CONTROL_HEADER_LENGTH {
            return Err(ControlError::InvalidLength);
        }
        let kind = Kind::from_parts(frame_type, r.u8(8)?).ok_or(ControlError::InvalidVariant)?;
        let count = r.u8(9)?;
        if kind.length(count).ok_or(ControlError::InvalidCount)? != frame_length {
            return Err(ControlError::InvalidLength);
        }
        for (start, end) in kind.reserved() {
            if bytes
                .get(*start..*end)
                .ok_or(ControlError::Truncated)?
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(ControlError::ReservedBits);
            }
        }
        let alias = super::Alias {
            session_id: r.i32(12)?,
            stream_id: r.i32(16)?,
        };
        Ok(match kind {
            Kind::State => {
                let authority_id = id(&r, 24)?;
                let guard_id = id(&r, 32)?;
                let word = GuardWord::from_raw(r.u64(40)?)?;
                let lifetime_ms = r.u32(48)?;
                check_lifetime(lifetime_ms)?;
                Self::State(GuardState {
                    authority_id,
                    guard_id,
                    word,
                    lifetime_ms,
                })
            }
            Kind::Challenge => Self::Challenge(StatusChallenge {
                authority_id: id(&r, 24)?,
                guard_id: id(&r, 32)?,
                receiver: r.receiver(40)?,
                nonce: nonce(&r, 64)?,
            }),
            Kind::Status => Self::Status(GuardStatus {
                authority_id: id(&r, 24)?,
                guard_id: id(&r, 32)?,
                receiver: r.receiver(40)?,
                nonce: nonce(&r, 64)?,
                word: GuardWord::from_raw(r.u64(80)?)?,
            }),
            Kind::Abort => {
                let identity = r.identity(24)?;
                let authority_id = id(&r, 56)?;
                // `guard_id` accepts 0 here; the cross-field check follows
                // the field checks (design section 5).
                let guard_id = r.u64(64)?;
                let guard_epoch = epoch(&r, 72)?;
                let reason = r.u16(80)?;
                if reason == 0 {
                    return Err(ControlError::InvalidValue);
                }
                if guard_id == 0 && reason == GUARD_CLOSED {
                    return Err(ControlError::InvalidIdentity);
                }
                Self::Abort(SessionAbort {
                    alias,
                    identity,
                    authority_id,
                    guard_id,
                    guard_epoch,
                    reason,
                })
            }
            Kind::Ack => {
                let identity = r.identity(24)?;
                let receiver = r.receiver(56)?;
                let guard_epoch = epoch(&r, 80)?;
                let mut lanes = [AckLane::default(); super::MAX_LANES];
                for (lane, entry) in lanes.iter_mut().take(usize::from(count)).enumerate() {
                    let at = ACK_BASE + ACK_LANE * lane;
                    entry.delivered = r.position(at)?;
                    entry.unresolved_end = r.position(at + 8)?;
                    if entry.unresolved_end < entry.delivered {
                        return Err(ControlError::InvalidPosition);
                    }
                }
                Self::Ack(AbortAck {
                    alias,
                    identity,
                    receiver,
                    guard_epoch,
                    lanes: Lanes::new(lanes.get(..usize::from(count)).unwrap_or(&[]))?,
                })
            }
        })
    }

    fn kind(&self) -> Kind {
        match self {
            Self::State(_) => Kind::State,
            Self::Challenge(_) => Kind::Challenge,
            Self::Status(_) => Kind::Status,
            Self::Abort(_) => Kind::Abort,
            Self::Ack(_) => Kind::Ack,
        }
    }

    /// Encodes the body into `out` and returns its length. The result
    /// decodes back to `self`; an invalid field is refused before anything
    /// is written.
    ///
    /// # Errors
    ///
    /// The error decoding would report for an invalid field, or
    /// [`ControlError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ControlError> {
        let kind = self.kind();
        let count = match self {
            Self::Ack(ack) => ack.lanes.count(),
            _ => 0,
        };
        let length = kind.length(count).ok_or(ControlError::InvalidCount)?;
        let available = out.len();
        let target = out.get_mut(..length).ok_or(ControlError::BufferTooShort {
            required: length,
            available,
        })?;
        let mut w = Writer::new(length.min(MAX_CONTROL_LENGTH))?;
        w.put(
            0,
            &i32::try_from(length)
                .map_err(|_| ControlError::InvalidLength)?
                .to_le_bytes(),
        )?;
        w.put(4, &[PROTOCOL_VERSION, 0])?;
        w.put(6, &kind.frame_type().code().to_le_bytes())?;
        w.put(8, &[kind.variant(), count])?;
        match self {
            Self::State(m) => {
                w.put(24, &m.authority_id.to_le_bytes())?;
                w.put(32, &m.guard_id.to_le_bytes())?;
                w.put(40, &m.word.raw().to_le_bytes())?;
                w.put(48, &m.lifetime_ms.to_le_bytes())?;
            }
            Self::Challenge(m) => {
                w.put(24, &m.authority_id.to_le_bytes())?;
                w.put(32, &m.guard_id.to_le_bytes())?;
                w.receiver(40, &m.receiver)?;
                w.id128(64, m.nonce)?;
            }
            Self::Status(m) => {
                w.put(24, &m.authority_id.to_le_bytes())?;
                w.put(32, &m.guard_id.to_le_bytes())?;
                w.receiver(40, &m.receiver)?;
                w.id128(64, m.nonce)?;
                w.put(80, &m.word.raw().to_le_bytes())?;
            }
            Self::Abort(m) => {
                w.put(12, &m.alias.session_id.to_le_bytes())?;
                w.put(16, &m.alias.stream_id.to_le_bytes())?;
                w.identity(24, &m.identity)?;
                w.put(56, &m.authority_id.to_le_bytes())?;
                w.put(64, &m.guard_id.to_le_bytes())?;
                w.put(72, &m.guard_epoch.to_le_bytes())?;
                w.put(80, &m.reason.to_le_bytes())?;
            }
            Self::Ack(m) => {
                w.put(12, &m.alias.session_id.to_le_bytes())?;
                w.put(16, &m.alias.stream_id.to_le_bytes())?;
                w.identity(24, &m.identity)?;
                w.receiver(56, &m.receiver)?;
                w.put(80, &m.guard_epoch.to_le_bytes())?;
                for (lane, entry) in m.lanes.as_slice().iter().enumerate() {
                    let at = ACK_BASE + ACK_LANE * lane;
                    w.put(at, &entry.delivered.to_le_bytes())?;
                    w.put(at + 8, &entry.unresolved_end.to_le_bytes())?;
                }
            }
        }
        let bytes = w.bytes()?;
        // Every field check is the decoder's: encode only what decodes.
        if Self::decode(bytes)? != *self {
            return Err(ControlError::InvalidValue);
        }
        target.copy_from_slice(bytes);
        Ok(length)
    }
}

/// Decodes a bare datagram at a guard authority's control endpoint
/// (design section 4.2, ADR-0107). Only GUARD STATUS_CHALLENGE is valid
/// bare; every other GUARD body, and every other gated type, returns
/// [`ControlError::GatedType`] without its body being read.
///
/// # Errors
///
/// `GatedType` for anything but a STATUS_CHALLENGE, or the first decode
/// error of the challenge.
pub fn decode_bare_status_challenge(bytes: &[u8]) -> Result<StatusChallenge, ControlError> {
    let r = Reader(bytes);
    let frame_length = r.i32(0)?;
    let code = r.u16(6)?;
    check_version(r.u8(4)?, code, frame_length)?;
    match FrameType::try_from_code(code) {
        Ok(FrameType::Guard) if r.u8(8)? == Kind::Challenge.variant() => {}
        Ok(
            frame_type @ (FrameType::Guard | FrameType::SessionAbort | FrameType::SessionAbortAck),
        ) => {
            return Err(ControlError::GatedType { frame_type });
        }
        Ok(_) => return Err(ControlError::WrongKind { code }),
        Err(_) => return Err(ControlError::UnknownType { code }),
    }
    match AuthControl::decode(bytes)? {
        AuthControl::Challenge(challenge) => Ok(challenge),
        _ => Err(ControlError::GatedType {
            frame_type: FrameType::Guard,
        }),
    }
}

/// An `authority_id` or `guard_id`: at least 1.
fn id(r: &Reader<'_>, at: usize) -> Result<u64, ControlError> {
    let value = r.u64(at)?;
    if value == 0 {
        return Err(ControlError::InvalidIdentity);
    }
    Ok(value)
}

/// A guard epoch: at least 1.
fn epoch(r: &Reader<'_>, at: usize) -> Result<u64, ControlError> {
    let value = r.u64(at)?;
    if value == 0 {
        return Err(ControlError::InvalidValue);
    }
    Ok(value)
}

/// A 128-bit nonce: not all zero.
fn nonce(r: &Reader<'_>, at: usize) -> Result<[u64; 2], ControlError> {
    let value = r.id128(at)?;
    if value == [0, 0] {
        return Err(ControlError::InvalidValue);
    }
    Ok(value)
}

fn check_lifetime(lifetime_ms: u32) -> Result<(), ControlError> {
    if lifetime_ms == 0 || lifetime_ms > MAX_LIFETIME_MS {
        return Err(ControlError::InvalidValue);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
