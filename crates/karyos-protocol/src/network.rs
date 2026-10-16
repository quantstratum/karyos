// SPDX-License-Identifier: Apache-2.0

//! Network control codecs for trusted traffic (`quantstratum-docs:
//! karyos/design/network-control-schemas.md`, Phase 2 batch P2.2) and the
//! datagram dispatcher that classifies a received UDP payload into one of
//! the three datagram groups of that design (section 2).
//!
//! **Groups.** A datagram is a data batch (one or more DATA, PAD or ABORTED
//! records of one publication and one lane), a heartbeat (exactly one
//! header-only DATA record) or a control (exactly one control record whose
//! `frame_length` equals the datagram length). [`classify`] reads the first
//! record's common word, selects the group and validates it as a whole: a
//! valid prefix never hides a trailing record or byte. The data groups are
//! only grouped here; their records are validated against the image by
//! `karyos_sys::receive::ValidatedDatagram::parse`, which needs the bound
//! image parameters.
//!
//! **Controls.** Every version 1 control starts with a 24-byte common header
//! (`frame_length` i32, `version` u8, `flags` u8 = 0, `frame_type` u16,
//! `variant` u8, `count` u8, reserved u16, `session_id` i32, `stream_id`
//! i32, reserved u32) followed by a body fixed by `(frame_type, variant,
//! count)`. All multibyte fields are little endian; 128-bit values are two
//! little-endian u64 words, `w0` first, compared as opaque values.
//!
//! | Type | Variant | Body after the common header | Bytes |
//! | --- | --- | --- | --- |
//! | SETUP `0x05` | 1 ANNOUNCE, `count` lanes 1 to 4 | identity; term parameters | 72 |
//! | SETUP `0x05` | 2 ANSWER, `count` lanes 1 to 4 | identity; term parameters; challenge; `count` join positions | `104 + 8n` |
//! | RSP_SETUP `0x07` | 1 CHALLENGE | identity; challenge | 88 |
//! | RSP_SETUP `0x07` | 2 SOLICIT | challenge | 56 |
//! | SM `0x03` | 1 STATUS, `count` lanes 1 to 4 | identity; receiver; `group_tag` u64; per lane consumption u64, window u32, reserved u32 | `88 + 16n` |
//! | NAK `0x02` | 1 RANGE | identity; receiver; lane u8, reserved 3, length u32, start u64 | 96 |
//! | ERR `0x04` | 1 NAK_REPLY | identity; the NAK's bytes 56 to 95; reason u16, reserved 6, detail u64 | 112 |
//! | ERR `0x04` | 2 UNBOUND | reason u16, rejected type u16, rejected version u8, min and max supported u8, reserved u8, rejected length i32, reserved u32 | 40 |
//! | RTTM `0x06` | 1 REQUEST, 2 REPLY | identity; receiver; `probe_id` u64; `service_delay_ns` u64 | 96 |
//! | PATH_HB `0x10` | 1 PATH | identity | 56 |
//!
//! The identity block is `driver_id` (128 bits, nonzero), `registration_id`
//! and `incarnation` (u64, at least 1); the receiver block is
//! `receiver_boot_id` (128 bits, nonzero) and `receiver_id` (u64, at least
//! 1); the challenge block is `receiver_boot_id` and `nonce` (both 128
//! bits, nonzero); term parameters are `term_length` (u32, a power of two
//! from 64 KiB to 1 GiB), `initial_term_id` (i32) and `mtu` (u32, 256 to
//! 8192) and a reserved u32. Positions are u64 lane positions, multiples of
//! 32 and at most 2^61; windows are u32 multiples of 32, at most 2^29; a NAK
//! length is a multiple of 32 from 32 to 2^30.
//!
//! GUARD, SESSION_ABORT and SESSION_ABORT_ACK have no trusted body: every
//! decoder returns [`ControlError::GatedType`] after their common word.
//!
//! **Decode order.** The decoder reports the first failure of the design's
//! section 3.5, in this order: a datagram shorter than 8 bytes
//! ([`ControlError::Truncated`]); `version` 0 or other than 1; the type
//! classification; `frame_length` against the datagram; `flags`;
//! `frame_length` below 24; `variant`; `count`; the schema size; reserved
//! bytes in offset order; then field checks in offset order. A decoder
//! allocates nothing, reads no clock and changes no state.
//!
//! **Syntax only.** A decoded value proves only that its bytes are a valid
//! encoding. Every context check (current binding, challenge freshness,
//! bound lane count, term boundaries, the sent frontier, retention floors,
//! receiver authority) belongs to the session and reliability owners.
//!
//! **Encoding** validates every field with the decoder's checks, then the
//! output capacity, before writing anything: a failed encode leaves the
//! output untouched and never exposes a sendable prefix. Reserved bytes are
//! written as zero. Whatever encodes decodes to itself.

use thiserror::Error;

use crate::frame::{FRAME_ALIGNMENT, Flags, FrameType, HEADER_LENGTH, Lane, PROTOCOL_VERSION};

/// Length of the common control header.
pub const CONTROL_HEADER_LENGTH: usize = 24;
/// Length of the largest version 1 control: SM with four lanes.
pub const MAX_CONTROL_LENGTH: usize = 152;
/// Most lanes of a publication.
pub const MAX_LANES: usize = Lane::COUNT as usize;
/// Largest syntactically valid position: `2^31 × 2^30`.
pub const MAX_POSITION: u64 = 1 << 61;
/// Largest syntactically valid window: half of the largest term.
pub const MAX_WINDOW: u32 = 1 << 29;
/// Largest syntactically valid NAK length: the largest term.
pub const MAX_NAK_LENGTH: u32 = 1 << 30;
/// Smallest term length.
pub const MIN_TERM_LENGTH: u32 = 1 << 16;
/// Largest term length.
pub const MAX_TERM_LENGTH: u32 = 1 << 30;
/// Smallest `mtu` a SETUP may carry (a syntax floor).
pub const MIN_MTU: u32 = 256;
/// Largest `mtu` a SETUP may carry.
pub const MAX_MTU: u32 = 8192;

/// ERR reason codes. Every other code, 0 included, is rejected.
pub mod reason {
    /// ERR UNBOUND: the rejected frame carries a version the replier does
    /// not support.
    pub const UNSUPPORTED_VERSION: u16 = 1;
    /// ERR NAK_REPLY: part of the requested range is below the retention
    /// floor; `detail` is the lowest retained position of the lane.
    pub const RANGE_UNAVAILABLE: u16 = 2;
    /// ERR NAK_REPLY: the request is not term-bounded, not on complete
    /// original extents or beyond the sent frontier; `detail` is 0.
    pub const RANGE_INVALID: u16 = 3;
}

/// Errors decoding or encoding a network datagram. These are local
/// categories, not wire reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ControlError {
    /// Fewer bytes than the common word, a record header or `frame_length`
    /// requires.
    #[error("truncated datagram")]
    Truncated,
    /// `version` is 0. Never answered.
    #[error("version 0")]
    InvalidVersion,
    /// `version` is neither 0 nor 1. Only the first word was read; the
    /// fields are the rejected frame's, for an ERR UNBOUND reply.
    #[error("unsupported version {version} (type {frame_type:#06x}, length {frame_length})")]
    UnsupportedVersion {
        /// Byte 4 of the rejected frame.
        version: u8,
        /// Bytes 6 to 7 of the rejected frame.
        frame_type: u16,
        /// Bytes 0 to 3 of the rejected frame.
        frame_length: i32,
    },
    /// GUARD, SESSION_ABORT or SESSION_ABORT_ACK: gated until a reviewed
    /// security profile exists. The body was not read.
    #[error("gated frame type {frame_type:?}")]
    GatedType {
        /// The gated type.
        frame_type: FrameType,
    },
    /// An undefined frame type code.
    #[error("unknown frame type {code:#06x}")]
    UnknownType {
        /// The type code.
        code: u16,
    },
    /// A valid classification of another kind than the decoder decodes: a
    /// data group given to a control decoder, or another control given to
    /// a decoder of one control kind.
    #[error("frame type {code:#06x} is not the kind this decoder decodes")]
    WrongKind {
        /// The type code found.
        code: u16,
    },
    /// `frame_length` is not positive, below the header, or not the
    /// schema size.
    #[error("invalid frame length")]
    InvalidLength,
    /// The datagram mixes groups, holds more than one control or
    /// heartbeat, holds bytes after its record, or holds a later batch
    /// record whose version is not the datagram's.
    #[error("invalid datagram grouping")]
    InvalidGrouping,
    /// A nonzero reserved byte or flag bit.
    #[error("nonzero reserved bits")]
    ReservedBits,
    /// An unknown variant for the frame type.
    #[error("invalid variant")]
    InvalidVariant,
    /// `count` outside the range of its `(type, variant)`.
    #[error("invalid count")]
    InvalidCount,
    /// A zero `driver_id`, `registration_id`, `incarnation`,
    /// `receiver_boot_id` or `receiver_id`.
    #[error("invalid identity")]
    InvalidIdentity,
    /// A position, window or NAK length that breaks the syntax bounds.
    #[error("invalid position")]
    InvalidPosition,
    /// Any other invalid field: nonce, lane, term parameters, reason codes,
    /// probe fields and version ranges.
    #[error("invalid value")]
    InvalidValue,
    /// The output buffer is shorter than the encoded record.
    #[error("buffer of {available} bytes is shorter than the required {required}")]
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}

/// The kind of a version 1 control: its frame type and variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlKind {
    /// SETUP ANNOUNCE.
    SetupAnnounce,
    /// SETUP ANSWER.
    SetupAnswer,
    /// RSP_SETUP CHALLENGE.
    Challenge,
    /// RSP_SETUP SOLICIT.
    Solicit,
    /// SM STATUS.
    Status,
    /// NAK RANGE.
    Nak,
    /// ERR NAK_REPLY.
    NakReply,
    /// ERR UNBOUND.
    Unbound,
    /// RTTM REQUEST.
    RttmRequest,
    /// RTTM REPLY.
    RttmReply,
    /// PATH_HB PATH.
    PathHeartbeat,
}

impl ControlKind {
    /// Every kind.
    pub const ALL: [Self; 11] = [
        Self::SetupAnnounce,
        Self::SetupAnswer,
        Self::Challenge,
        Self::Solicit,
        Self::Status,
        Self::Nak,
        Self::NakReply,
        Self::Unbound,
        Self::RttmRequest,
        Self::RttmReply,
        Self::PathHeartbeat,
    ];

    /// The frame type.
    #[must_use]
    pub const fn frame_type(self) -> FrameType {
        match self {
            Self::SetupAnnounce | Self::SetupAnswer => FrameType::Setup,
            Self::Challenge | Self::Solicit => FrameType::RspSetup,
            Self::Status => FrameType::Sm,
            Self::Nak => FrameType::Nak,
            Self::NakReply | Self::Unbound => FrameType::Err,
            Self::RttmRequest | Self::RttmReply => FrameType::Rttm,
            Self::PathHeartbeat => FrameType::PathHb,
        }
    }

    /// The `variant` byte.
    #[must_use]
    pub const fn variant(self) -> u8 {
        match self {
            Self::SetupAnnounce
            | Self::Challenge
            | Self::Status
            | Self::Nak
            | Self::NakReply
            | Self::RttmRequest
            | Self::PathHeartbeat => 1,
            Self::SetupAnswer | Self::Solicit | Self::Unbound | Self::RttmReply => 2,
        }
    }

    /// The kind of `(frame_type, variant)`; `None` for an unknown variant or
    /// a type without a trusted control body.
    #[must_use]
    pub const fn from_parts(frame_type: FrameType, variant: u8) -> Option<Self> {
        Some(match (frame_type, variant) {
            (FrameType::Setup, 1) => Self::SetupAnnounce,
            (FrameType::Setup, 2) => Self::SetupAnswer,
            (FrameType::RspSetup, 1) => Self::Challenge,
            (FrameType::RspSetup, 2) => Self::Solicit,
            (FrameType::Sm, 1) => Self::Status,
            (FrameType::Nak, 1) => Self::Nak,
            (FrameType::Err, 1) => Self::NakReply,
            (FrameType::Err, 2) => Self::Unbound,
            (FrameType::Rttm, 1) => Self::RttmRequest,
            (FrameType::Rttm, 2) => Self::RttmReply,
            (FrameType::PathHb, 1) => Self::PathHeartbeat,
            _ => return None,
        })
    }

    /// Whether `count` is valid: a lane count of 1 to 4 for SETUP and SM,
    /// 0 otherwise.
    #[must_use]
    pub const fn accepts_count(self, count: u8) -> bool {
        match self {
            Self::SetupAnnounce | Self::SetupAnswer | Self::Status => {
                count >= 1 && count <= Lane::COUNT
            }
            _ => count == 0,
        }
    }

    /// The exact record length for `count`; `None` when `count` is not
    /// valid for the kind.
    #[must_use]
    pub const fn length(self, count: u8) -> Option<usize> {
        if !self.accepts_count(count) {
            return None;
        }
        let n = count as usize;
        Some(match self {
            Self::SetupAnnounce => 72,
            Self::SetupAnswer => 104 + 8 * n,
            Self::Challenge => 88,
            Self::Solicit | Self::PathHeartbeat => 56,
            Self::Status => 88 + 16 * n,
            Self::Nak | Self::RttmRequest | Self::RttmReply => 96,
            Self::NakReply => 112,
            Self::Unbound => 40,
        })
    }

    /// The reserved byte ranges of the record, in offset order, as
    /// `(start, end)` pairs; unused slots are empty `(0, 0)` ranges. The
    /// common header contributes bytes 10 to 11 and 20 to 23 (and 12 to 19
    /// in UNBOUND, where `session_id` and `stream_id` are reserved).
    #[must_use]
    pub fn reserved(self, count: u8) -> [(usize, usize); 6] {
        const EMPTY: (usize, usize) = (0, 0);
        const HEADER: (usize, usize) = (10, 12);
        const TAIL: (usize, usize) = (20, 24);
        match self {
            Self::Unbound => [HEADER, (12, 24), (31, 32), (36, 40), EMPTY, EMPTY],
            Self::SetupAnnounce | Self::SetupAnswer => {
                [HEADER, TAIL, (68, 72), EMPTY, EMPTY, EMPTY]
            }
            Self::Status => {
                let mut out = [HEADER, TAIL, (100, 104), (116, 120), (132, 136), (148, 152)];
                for (lane, slot) in out.iter_mut().skip(2).enumerate() {
                    if lane >= usize::from(count) {
                        *slot = EMPTY;
                    }
                }
                out
            }
            Self::Nak => [HEADER, TAIL, (81, 84), EMPTY, EMPTY, EMPTY],
            Self::NakReply => [HEADER, TAIL, (81, 84), (98, 104), EMPTY, EMPTY],
            Self::Challenge
            | Self::Solicit
            | Self::RttmRequest
            | Self::RttmReply
            | Self::PathHeartbeat => [HEADER, TAIL, EMPTY, EMPTY, EMPTY, EMPTY],
        }
    }
}

/// `session_id` and `stream_id` of a control: compared for equality only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Alias {
    /// Session alias of the publication incarnation.
    pub session_id: i32,
    /// Stream.
    pub stream_id: i32,
}

/// The identity block: the full publication incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Identity {
    /// Random 128-bit driver id, `w0` then `w1`; not all zero.
    pub driver_id: [u64; 2],
    /// Registration, at least 1.
    pub registration_id: u64,
    /// Incarnation, at least 1.
    pub incarnation: u64,
}

/// The receiver block: the receiving agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Receiver {
    /// 128-bit id of the receiving driver's start; not all zero.
    pub receiver_boot_id: [u64; 2],
    /// Configured receiver id, at least 1.
    pub receiver_id: u64,
}

/// The challenge block: a receiver start and a nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ChallengeBlock {
    /// 128-bit id of the receiving driver's start; not all zero.
    pub receiver_boot_id: [u64; 2],
    /// 128-bit nonce; not all zero.
    pub nonce: [u64; 2],
}

/// The term parameters of a SETUP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TermParams {
    /// A power of two from [`MIN_TERM_LENGTH`] to [`MAX_TERM_LENGTH`].
    pub term_length: u32,
    /// Any bit pattern.
    pub initial_term_id: i32,
    /// [`MIN_MTU`] to [`MAX_MTU`].
    pub mtu: u32,
}

/// One lane's status in an SM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LaneStatus {
    /// Consumption position.
    pub consumption: u64,
    /// Receiver window; 0 grants no credit.
    pub window: u32,
}

/// The requested range of a NAK: `[start, start + length)` of one lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NakRange {
    /// The lane.
    pub lane: Lane,
    /// Range length in bytes.
    pub length: u32,
    /// First requested position.
    pub start: u64,
}

/// One to four per-lane entries; entry `i` is lane `i`, so duplicate,
/// missing and out-of-range lanes cannot be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Lanes<T> {
    count: u8,
    entries: [T; MAX_LANES],
}

impl<T: Copy + Default> Lanes<T> {
    /// Entries for lanes 0 to `entries.len() - 1`.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::InvalidCount`] for no entry or more than
    /// four.
    pub fn new(entries: &[T]) -> Result<Self, ControlError> {
        let count = u8::try_from(entries.len())
            .ok()
            .filter(|count| (1..=Lane::COUNT).contains(count))
            .ok_or(ControlError::InvalidCount)?;
        let mut all = [T::default(); MAX_LANES];
        for (slot, entry) in all.iter_mut().zip(entries) {
            *slot = *entry;
        }
        Ok(Self {
            count,
            entries: all,
        })
    }

    /// The lane count, 1 to 4.
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.count
    }

    /// The entries, lane 0 first.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.entries.get(..usize::from(self.count)).unwrap_or(&[])
    }

    /// The entry of `lane`, if the lane is present.
    #[must_use]
    pub fn get(&self, lane: Lane) -> Option<T> {
        self.as_slice().get(usize::from(lane.get())).copied()
    }
}

/// SETUP ANNOUNCE: a periodic announcement before establishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetupAnnounce {
    /// Alias and stream.
    pub alias: Alias,
    /// The announced publication incarnation.
    pub identity: Identity,
    /// Term parameters.
    pub term: TermParams,
    /// Lane count, 1 to 4.
    pub lane_count: u8,
}

/// SETUP ANSWER: the answer to a current challenge, with join points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetupAnswer {
    /// Alias and stream.
    pub alias: Alias,
    /// The answering publication incarnation.
    pub identity: Identity,
    /// Term parameters.
    pub term: TermParams,
    /// The echoed challenge.
    pub challenge: ChallengeBlock,
    /// Each lane's join position; the count is the lane count.
    pub joins: Lanes<u64>,
}

/// RSP_SETUP CHALLENGE: answers an announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RspChallenge {
    /// Alias and stream of the announcement.
    pub alias: Alias,
    /// Identity copied from the announcement.
    pub identity: Identity,
    /// A fresh challenge.
    pub challenge: ChallengeBlock,
}

/// RSP_SETUP SOLICIT: asks for SETUP after DATA for an unknown alias. It
/// has no identity field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RspSolicit {
    /// Alias and stream copied from the unbound DATA header.
    pub alias: Alias,
    /// A fresh challenge.
    pub challenge: ChallengeBlock,
}

/// SM STATUS: every configured lane's consumption and window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusMessage {
    /// Alias and stream.
    pub alias: Alias,
    /// The publication incarnation.
    pub identity: Identity,
    /// The reporting receiver.
    pub receiver: Receiver,
    /// Declared flow-control tag; 0 declares none.
    pub group_tag: u64,
    /// Per-lane status.
    pub lanes: Lanes<LaneStatus>,
}

/// NAK RANGE: requests one range of one lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nak {
    /// Alias and stream.
    pub alias: Alias,
    /// The publication incarnation.
    pub identity: Identity,
    /// The requesting receiver.
    pub receiver: Receiver,
    /// The requested range.
    pub range: NakRange,
}

/// The reason of an ERR NAK_REPLY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NakReplyReason {
    /// [`reason::RANGE_UNAVAILABLE`].
    RangeUnavailable {
        /// Lowest retained position of the lane.
        lowest_retained: u64,
    },
    /// [`reason::RANGE_INVALID`].
    RangeInvalid,
}

/// ERR NAK_REPLY: the correlated answer to a NAK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NakReply {
    /// Alias and stream of the NAK.
    pub alias: Alias,
    /// Publication of the NAK.
    pub identity: Identity,
    /// The NAK's receiver, echoed.
    pub receiver: Receiver,
    /// The NAK's range, echoed.
    pub range: NakRange,
    /// Why the range is refused.
    pub reason: NakReplyReason,
}

impl NakReply {
    /// The reply to `nak`, echoing its alias, identity and request.
    #[must_use]
    pub const fn answering(nak: &Nak, reason: NakReplyReason) -> Self {
        Self {
            alias: nak.alias,
            identity: nak.identity,
            receiver: nak.receiver,
            range: nak.range,
            reason,
        }
    }
}

/// ERR UNBOUND `UNSUPPORTED_VERSION`: the rejected frame's first word and
/// the replier's supported range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Unbound {
    /// Bytes 6 to 7 of the rejected frame.
    pub rejected_type: u16,
    /// Byte 4 of the rejected frame; outside the supported range, not 0.
    pub rejected_version: u8,
    /// Lowest supported version, at least 1.
    pub min_supported: u8,
    /// Highest supported version; the range contains 1.
    pub max_supported: u8,
    /// Bytes 0 to 3 of the rejected frame.
    pub rejected_length: i32,
}

/// Whether an RTTM is a request or a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RttmKind {
    /// A request; `service_delay_ns` is 0 on the wire.
    Request,
    /// A reply.
    Reply {
        /// Nanoseconds on the replier's monotonic clock from request receipt
        /// to reply submission; untrusted.
        service_delay_ns: u64,
    },
}

/// RTTM REQUEST or REPLY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rttm {
    /// Alias and stream.
    pub alias: Alias,
    /// The publication whose path is measured.
    pub identity: Identity,
    /// The receiver side of the measured pair.
    pub receiver: Receiver,
    /// Chosen by the requester, at least 1; echoed in the reply.
    pub probe_id: u64,
    /// Request or reply.
    pub kind: RttmKind,
}

/// PATH_HB PATH: refreshes the liveness of an established path binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathHeartbeat {
    /// Alias and stream.
    pub alias: Alias,
    /// The publication incarnation.
    pub identity: Identity,
}

/// One decoded version 1 control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Control {
    /// SETUP ANNOUNCE.
    SetupAnnounce(SetupAnnounce),
    /// SETUP ANSWER.
    SetupAnswer(SetupAnswer),
    /// RSP_SETUP CHALLENGE.
    Challenge(RspChallenge),
    /// RSP_SETUP SOLICIT.
    Solicit(RspSolicit),
    /// SM STATUS.
    Status(StatusMessage),
    /// NAK RANGE.
    Nak(Nak),
    /// ERR NAK_REPLY.
    NakReply(NakReply),
    /// ERR UNBOUND.
    Unbound(Unbound),
    /// RTTM REQUEST or REPLY.
    Rttm(Rttm),
    /// PATH_HB PATH.
    PathHeartbeat(PathHeartbeat),
}

/// A data batch or heartbeat datagram, grouped but not yet validated
/// against an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDatagram<'a> {
    bytes: &'a [u8],
    alias: Alias,
    lane: Lane,
}

impl<'a> DataDatagram<'a> {
    /// The whole datagram, for `karyos_sys::receive::ValidatedDatagram::parse`.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// `session_id` and `stream_id` shared by every record.
    #[must_use]
    pub const fn alias(&self) -> Alias {
        self.alias
    }

    /// The lane shared by every record.
    #[must_use]
    pub const fn lane(&self) -> Lane {
        self.lane
    }
}

/// The group of a classified datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datagram<'a> {
    /// DATA with payload, PAD and ABORTED records of one publication and
    /// one lane.
    DataBatch(DataDatagram<'a>),
    /// Exactly one header-only DATA record.
    Heartbeat(DataDatagram<'a>),
    /// Exactly one control.
    Control(Control),
}

/// Classifies and validates a received datagram (section 2 of the design):
/// a data batch, a heartbeat or one control.
///
/// # Errors
///
/// Returns the first [`ControlError`] in the decode order of the module
/// documentation. [`ControlError::UnsupportedVersion`] carries the rejected
/// first word, which [`unbound_reply`] turns into an ERR UNBOUND when the
/// reply policy allows one.
pub fn classify(bytes: &[u8]) -> Result<Datagram<'_>, ControlError> {
    match first_word(bytes)? {
        Group::Data => scan_data(bytes),
        Group::Control(frame_type) => decode_control(bytes, frame_type, &[]).map(Datagram::Control),
    }
}

/// The ERR UNBOUND reply to `error`, if the reply rules allow one: the
/// error is [`ControlError::UnsupportedVersion`], the rejected frame is not
/// an ERR of any version, and the rejected datagram is at least as long as
/// the 40-byte reply, so the reply never amplifies its input. The supported
/// range is version 1 only.
///
/// This is only the content rule. The destination rule (unicast source
/// endpoint on the arrival channel) and the rate limits belong to the
/// driver.
#[must_use]
pub fn unbound_reply(error: &ControlError, datagram_length: usize) -> Option<Unbound> {
    match *error {
        ControlError::UnsupportedVersion {
            version,
            frame_type,
            frame_length,
        } if frame_type != FrameType::Err.code()
            && ControlKind::Unbound
                .length(0)
                .is_some_and(|reply| datagram_length >= reply) =>
        {
            Some(Unbound {
                rejected_type: frame_type,
                rejected_version: version,
                min_supported: PROTOCOL_VERSION,
                max_supported: PROTOCOL_VERSION,
                rejected_length: frame_length,
            })
        }
        _ => None,
    }
}

impl Control {
    /// The kind of the control.
    #[must_use]
    pub const fn kind(&self) -> ControlKind {
        match self {
            Self::SetupAnnounce(_) => ControlKind::SetupAnnounce,
            Self::SetupAnswer(_) => ControlKind::SetupAnswer,
            Self::Challenge(_) => ControlKind::Challenge,
            Self::Solicit(_) => ControlKind::Solicit,
            Self::Status(_) => ControlKind::Status,
            Self::Nak(_) => ControlKind::Nak,
            Self::NakReply(_) => ControlKind::NakReply,
            Self::Unbound(_) => ControlKind::Unbound,
            Self::Rttm(Rttm {
                kind: RttmKind::Request,
                ..
            }) => ControlKind::RttmRequest,
            Self::Rttm(_) => ControlKind::RttmReply,
            Self::PathHeartbeat(_) => ControlKind::PathHeartbeat,
        }
    }

    /// The `count` byte.
    #[must_use]
    pub const fn count(&self) -> u8 {
        match self {
            Self::SetupAnnounce(setup) => setup.lane_count,
            Self::SetupAnswer(setup) => setup.joins.count,
            Self::Status(status) => status.lanes.count,
            _ => 0,
        }
    }

    /// The alias and stream; zero for UNBOUND, which carries none.
    #[must_use]
    pub const fn alias(&self) -> Alias {
        match self {
            Self::SetupAnnounce(m) => m.alias,
            Self::SetupAnswer(m) => m.alias,
            Self::Challenge(m) => m.alias,
            Self::Solicit(m) => m.alias,
            Self::Status(m) => m.alias,
            Self::Nak(m) => m.alias,
            Self::NakReply(m) => m.alias,
            Self::Unbound(_) => Alias {
                session_id: 0,
                stream_id: 0,
            },
            Self::Rttm(m) => m.alias,
            Self::PathHeartbeat(m) => m.alias,
        }
    }

    /// The encoded length; `None` when the lane count is invalid.
    #[must_use]
    pub const fn encoded_length(&self) -> Option<usize> {
        self.kind().length(self.count())
    }

    /// Decodes one control datagram.
    ///
    /// # Errors
    ///
    /// Returns the first [`ControlError`] in the decode order;
    /// [`ControlError::WrongKind`] for a data batch or heartbeat.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        decode_as(bytes, &[])
    }

    /// Validates every field with the decoder's checks, in offset order.
    ///
    /// # Errors
    ///
    /// Returns the error the decoder would return for the encoded value.
    pub fn check(&self) -> Result<(), ControlError> {
        let count_ok = self.kind().accepts_count(self.count());
        if !count_ok {
            return Err(ControlError::InvalidCount);
        }
        match self {
            Self::SetupAnnounce(m) => {
                check_identity(&m.identity)?;
                check_term(&m.term)
            }
            Self::SetupAnswer(m) => {
                check_identity(&m.identity)?;
                check_term(&m.term)?;
                check_challenge(&m.challenge)?;
                m.joins
                    .as_slice()
                    .iter()
                    .try_for_each(|j| check_position(*j))
            }
            Self::Challenge(m) => {
                check_identity(&m.identity)?;
                check_challenge(&m.challenge)
            }
            Self::Solicit(m) => check_challenge(&m.challenge),
            Self::Status(m) => {
                check_identity(&m.identity)?;
                check_receiver(&m.receiver)?;
                m.lanes.as_slice().iter().try_for_each(|lane| {
                    check_position(lane.consumption)?;
                    check_window(lane.window)
                })
            }
            Self::Nak(m) => {
                check_identity(&m.identity)?;
                check_receiver(&m.receiver)?;
                check_range(&m.range)
            }
            Self::NakReply(m) => {
                check_identity(&m.identity)?;
                check_receiver(&m.receiver)?;
                check_range(&m.range)?;
                match m.reason {
                    NakReplyReason::RangeUnavailable { lowest_retained } => {
                        check_position(lowest_retained)
                    }
                    NakReplyReason::RangeInvalid => Ok(()),
                }
            }
            Self::Unbound(m) => {
                check_versions(m.rejected_version, m.min_supported, m.max_supported)
            }
            Self::Rttm(m) => {
                check_identity(&m.identity)?;
                check_receiver(&m.receiver)?;
                if m.probe_id == 0 {
                    return Err(ControlError::InvalidValue);
                }
                Ok(())
            }
            Self::PathHeartbeat(m) => check_identity(&m.identity),
        }
    }

    /// Encodes the control into the start of `out`; returns its length.
    /// Nothing is written on failure.
    ///
    /// # Errors
    ///
    /// Returns the [`Control::check`] error for a value the decoder would
    /// refuse, and [`ControlError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ControlError> {
        self.check()?;
        let kind = self.kind();
        let count = self.count();
        let length = kind.length(count).ok_or(ControlError::InvalidCount)?;
        let available = out.len();
        let target = out.get_mut(..length).ok_or(ControlError::BufferTooShort {
            required: length,
            available,
        })?;
        let mut w = Writer::new(length)?;
        w.put(
            0,
            &i32::try_from(length)
                .map_err(|_| ControlError::InvalidLength)?
                .to_le_bytes(),
        )?;
        w.put(4, &[PROTOCOL_VERSION, 0])?;
        w.put(6, &kind.frame_type().code().to_le_bytes())?;
        w.put(8, &[kind.variant(), count])?;
        let alias = self.alias();
        w.put(12, &alias.session_id.to_le_bytes())?;
        w.put(16, &alias.stream_id.to_le_bytes())?;
        match self {
            Self::SetupAnnounce(m) => {
                w.identity(24, &m.identity)?;
                w.term(56, &m.term)?;
            }
            Self::SetupAnswer(m) => {
                w.identity(24, &m.identity)?;
                w.term(56, &m.term)?;
                w.challenge(72, &m.challenge)?;
                for (lane, join) in m.joins.as_slice().iter().enumerate() {
                    w.put(104 + 8 * lane, &join.to_le_bytes())?;
                }
            }
            Self::Challenge(m) => {
                w.identity(24, &m.identity)?;
                w.challenge(56, &m.challenge)?;
            }
            Self::Solicit(m) => w.challenge(24, &m.challenge)?,
            Self::Status(m) => {
                w.identity(24, &m.identity)?;
                w.receiver(56, &m.receiver)?;
                w.put(80, &m.group_tag.to_le_bytes())?;
                for (lane, status) in m.lanes.as_slice().iter().enumerate() {
                    let at = 88 + 16 * lane;
                    w.put(at, &status.consumption.to_le_bytes())?;
                    w.put(at + 8, &status.window.to_le_bytes())?;
                }
            }
            Self::Nak(m) => {
                w.identity(24, &m.identity)?;
                w.receiver(56, &m.receiver)?;
                w.range(80, &m.range)?;
            }
            Self::NakReply(m) => {
                w.identity(24, &m.identity)?;
                w.receiver(56, &m.receiver)?;
                w.range(80, &m.range)?;
                let (code, detail) = match m.reason {
                    NakReplyReason::RangeUnavailable { lowest_retained } => {
                        (reason::RANGE_UNAVAILABLE, lowest_retained)
                    }
                    NakReplyReason::RangeInvalid => (reason::RANGE_INVALID, 0),
                };
                w.put(96, &code.to_le_bytes())?;
                w.put(104, &detail.to_le_bytes())?;
            }
            Self::Unbound(m) => {
                w.put(24, &reason::UNSUPPORTED_VERSION.to_le_bytes())?;
                w.put(26, &m.rejected_type.to_le_bytes())?;
                w.put(28, &[m.rejected_version, m.min_supported, m.max_supported])?;
                w.put(32, &m.rejected_length.to_le_bytes())?;
            }
            Self::Rttm(m) => {
                w.identity(24, &m.identity)?;
                w.receiver(56, &m.receiver)?;
                w.put(80, &m.probe_id.to_le_bytes())?;
                let delay = match m.kind {
                    RttmKind::Request => 0,
                    RttmKind::Reply { service_delay_ns } => service_delay_ns,
                };
                w.put(88, &delay.to_le_bytes())?;
            }
            Self::PathHeartbeat(m) => w.identity(24, &m.identity)?,
        }
        target.copy_from_slice(w.bytes()?);
        Ok(length)
    }
}

macro_rules! kind_codec {
    ($type:ident, $variant:ident, $($kind:ident),+) => {
        impl $type {
            /// Decodes one datagram holding exactly this kind of control.
            ///
            /// # Errors
            ///
            /// Returns the first [`ControlError`] in the decode order;
            /// [`ControlError::WrongKind`] for a valid classification of
            /// another kind.
            pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
                match decode_as(bytes, &[$(ControlKind::$kind),+])? {
                    Control::$variant(value) => Ok(value),
                    other => Err(ControlError::WrongKind {
                        code: other.kind().frame_type().code(),
                    }),
                }
            }

            /// Encodes into the start of `out`; returns the length.
            ///
            /// # Errors
            ///
            /// As [`Control::encode`].
            pub fn encode(&self, out: &mut [u8]) -> Result<usize, ControlError> {
                Control::$variant(*self).encode(out)
            }
        }
    };
}

kind_codec!(SetupAnnounce, SetupAnnounce, SetupAnnounce);
kind_codec!(SetupAnswer, SetupAnswer, SetupAnswer);
kind_codec!(RspChallenge, Challenge, Challenge);
kind_codec!(RspSolicit, Solicit, Solicit);
kind_codec!(StatusMessage, Status, Status);
kind_codec!(Nak, Nak, Nak);
kind_codec!(NakReply, NakReply, NakReply);
kind_codec!(Unbound, Unbound, Unbound);
kind_codec!(Rttm, Rttm, RttmRequest, RttmReply);
kind_codec!(PathHeartbeat, PathHeartbeat, PathHeartbeat);

/// The group a first word selects.
enum Group {
    Data,
    Control(FrameType),
}

/// Steps 1 to 3: length of the common word, version and type.
fn first_word(bytes: &[u8]) -> Result<Group, ControlError> {
    let word = Reader(bytes);
    let frame_length = word.i32(0)?;
    let version = word.u8(4)?;
    let code = word.u16(6)?;
    check_version(version, code, frame_length)?;
    match FrameType::try_from_code(code) {
        Err(_) => Err(ControlError::UnknownType { code }),
        Ok(
            frame_type @ (FrameType::Guard | FrameType::SessionAbort | FrameType::SessionAbortAck),
        ) => Err(ControlError::GatedType { frame_type }),
        Ok(FrameType::Data | FrameType::Pad | FrameType::Aborted) => Ok(Group::Data),
        Ok(frame_type) => Ok(Group::Control(frame_type)),
    }
}

fn check_version(version: u8, frame_type: u16, frame_length: i32) -> Result<(), ControlError> {
    match version {
        0 => Err(ControlError::InvalidVersion),
        PROTOCOL_VERSION => Ok(()),
        _ => Err(ControlError::UnsupportedVersion {
            version,
            frame_type,
            frame_length,
        }),
    }
}

fn decode_as(bytes: &[u8], want: &[ControlKind]) -> Result<Control, ControlError> {
    match first_word(bytes)? {
        Group::Data => Err(ControlError::WrongKind {
            code: Reader(bytes).u16(6)?,
        }),
        Group::Control(frame_type) => decode_control(bytes, frame_type, want),
    }
}

/// Steps 4 to 11 for a control type.
fn decode_control(
    bytes: &[u8],
    frame_type: FrameType,
    want: &[ControlKind],
) -> Result<Control, ControlError> {
    let r = Reader(bytes);
    // Step 4: frame_length against the datagram.
    let frame_length = usize::try_from(r.i32(0)?)
        .ok()
        .filter(|length| *length > 0)
        .ok_or(ControlError::InvalidLength)?;
    match frame_length.cmp(&bytes.len()) {
        core::cmp::Ordering::Greater => return Err(ControlError::Truncated),
        core::cmp::Ordering::Less => return Err(ControlError::InvalidGrouping),
        core::cmp::Ordering::Equal => {}
    }
    // Step 5: no control flags exist.
    if r.u8(5)? != 0 {
        return Err(ControlError::ReservedBits);
    }
    // Step 6: room for the common header.
    if frame_length < CONTROL_HEADER_LENGTH {
        return Err(ControlError::InvalidLength);
    }
    // Step 7: variant.
    let kind = ControlKind::from_parts(frame_type, r.u8(8)?).ok_or(ControlError::InvalidVariant)?;
    if !want.is_empty() && !want.contains(&kind) {
        return Err(ControlError::WrongKind {
            code: frame_type.code(),
        });
    }
    // Steps 8 and 9: count and schema size.
    let count = r.u8(9)?;
    let length = kind.length(count).ok_or(ControlError::InvalidCount)?;
    if length != frame_length {
        return Err(ControlError::InvalidLength);
    }
    // Step 10: reserved bytes in offset order.
    for (start, end) in kind.reserved(count) {
        if bytes
            .get(start..end)
            .ok_or(ControlError::Truncated)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ControlError::ReservedBits);
        }
    }
    // Step 11: fields in offset order.
    let alias = Alias {
        session_id: r.i32(12)?,
        stream_id: r.i32(16)?,
    };
    Ok(match kind {
        ControlKind::SetupAnnounce => Control::SetupAnnounce(SetupAnnounce {
            alias,
            identity: r.identity(24)?,
            term: r.term(56)?,
            lane_count: count,
        }),
        ControlKind::SetupAnswer => {
            let identity = r.identity(24)?;
            let term = r.term(56)?;
            let challenge = r.challenge(72)?;
            let mut joins = [0u64; MAX_LANES];
            for (lane, join) in joins.iter_mut().take(usize::from(count)).enumerate() {
                *join = r.position(104 + 8 * lane)?;
            }
            Control::SetupAnswer(SetupAnswer {
                alias,
                identity,
                term,
                challenge,
                joins: Lanes::new(joins.get(..usize::from(count)).unwrap_or(&[]))?,
            })
        }
        ControlKind::Challenge => Control::Challenge(RspChallenge {
            alias,
            identity: r.identity(24)?,
            challenge: r.challenge(56)?,
        }),
        ControlKind::Solicit => Control::Solicit(RspSolicit {
            alias,
            challenge: r.challenge(24)?,
        }),
        ControlKind::Status => {
            let identity = r.identity(24)?;
            let receiver = r.receiver(56)?;
            let group_tag = r.u64(80)?;
            let mut lanes = [LaneStatus::default(); MAX_LANES];
            for (lane, status) in lanes.iter_mut().take(usize::from(count)).enumerate() {
                let at = 88 + 16 * lane;
                status.consumption = r.position(at)?;
                status.window = r.u32(at + 8)?;
                check_window(status.window)?;
            }
            Control::Status(StatusMessage {
                alias,
                identity,
                receiver,
                group_tag,
                lanes: Lanes::new(lanes.get(..usize::from(count)).unwrap_or(&[]))?,
            })
        }
        ControlKind::Nak => Control::Nak(Nak {
            alias,
            identity: r.identity(24)?,
            receiver: r.receiver(56)?,
            range: r.range(80)?,
        }),
        ControlKind::NakReply => {
            let identity = r.identity(24)?;
            let receiver = r.receiver(56)?;
            let range = r.range(80)?;
            let detail = r.u64(104)?;
            let reason = match r.u16(96)? {
                reason::RANGE_UNAVAILABLE => {
                    check_position(detail)?;
                    NakReplyReason::RangeUnavailable {
                        lowest_retained: detail,
                    }
                }
                reason::RANGE_INVALID if detail == 0 => NakReplyReason::RangeInvalid,
                _ => return Err(ControlError::InvalidValue),
            };
            Control::NakReply(NakReply {
                alias,
                identity,
                receiver,
                range,
                reason,
            })
        }
        ControlKind::Unbound => {
            if r.u16(24)? != reason::UNSUPPORTED_VERSION {
                return Err(ControlError::InvalidValue);
            }
            let unbound = Unbound {
                rejected_type: r.u16(26)?,
                rejected_version: r.u8(28)?,
                min_supported: r.u8(29)?,
                max_supported: r.u8(30)?,
                rejected_length: r.i32(32)?,
            };
            check_versions(
                unbound.rejected_version,
                unbound.min_supported,
                unbound.max_supported,
            )?;
            Control::Unbound(unbound)
        }
        ControlKind::RttmRequest | ControlKind::RttmReply => {
            let identity = r.identity(24)?;
            let receiver = r.receiver(56)?;
            let probe_id = r.u64(80)?;
            if probe_id == 0 {
                return Err(ControlError::InvalidValue);
            }
            let delay = r.u64(88)?;
            let rttm_kind = if kind == ControlKind::RttmRequest {
                if delay != 0 {
                    return Err(ControlError::InvalidValue);
                }
                RttmKind::Request
            } else {
                RttmKind::Reply {
                    service_delay_ns: delay,
                }
            };
            Control::Rttm(Rttm {
                alias,
                identity,
                receiver,
                probe_id,
                kind: rttm_kind,
            })
        }
        ControlKind::PathHeartbeat => Control::PathHeartbeat(PathHeartbeat {
            alias,
            identity: r.identity(24)?,
        }),
    })
}

/// The data batch and heartbeat rules: every record is DATA with payload,
/// PAD or ABORTED of the first record's alias and lane, records follow the
/// 32-byte stride, and the cursor ends exactly at the datagram end (the
/// last record may omit its whole alignment padding). A header-only DATA
/// first record is a heartbeat and must be the whole datagram.
fn scan_data(bytes: &[u8]) -> Result<Datagram<'_>, ControlError> {
    let mut offset = 0usize;
    let mut group: Option<(Alias, Lane)> = None;
    loop {
        let record = bytes.get(offset..).ok_or(ControlError::Truncated)?;
        let r = Reader(record);
        let frame_length = r.i32(0)?;
        let code = r.u16(6)?;
        let version = r.u8(4)?;
        if offset == 0 {
            check_version(version, code, frame_length)?;
        } else if version != PROTOCOL_VERSION {
            // Section 7.5 classifies by the datagram's first word only. A
            // later record of another version is a version 1 grouping
            // violation (section 7.1: no reply), never an unsupported
            // version that could be answered with a nested record's word.
            return Err(ControlError::InvalidGrouping);
        }
        let frame_type = match FrameType::try_from_code(code) {
            Ok(t @ (FrameType::Data | FrameType::Pad | FrameType::Aborted)) => t,
            // Only a later record can get here: the first selected this scan.
            _ => return Err(ControlError::InvalidGrouping),
        };
        let length = u32::try_from(frame_length)
            .ok()
            .filter(|length| *length > 0)
            .ok_or(ControlError::InvalidLength)?;
        let flags = Flags::try_new(r.u8(5)?).map_err(|_| ControlError::ReservedBits)?;
        if record.len() < HEADER_LENGTH as usize {
            return Err(ControlError::Truncated);
        }
        let stride = match frame_type {
            FrameType::Data => {
                let header_length = flags.header_length();
                if length < header_length {
                    return Err(ControlError::InvalidLength);
                }
                if length == header_length {
                    if offset != 0 {
                        return Err(ControlError::InvalidGrouping);
                    }
                    return match (length as usize).cmp(&bytes.len()) {
                        core::cmp::Ordering::Greater => Err(ControlError::Truncated),
                        core::cmp::Ordering::Less => Err(ControlError::InvalidGrouping),
                        core::cmp::Ordering::Equal => Ok(Datagram::Heartbeat(DataDatagram {
                            bytes,
                            alias: Alias {
                                session_id: r.i32(12)?,
                                stream_id: r.i32(16)?,
                            },
                            lane: flags.lane(),
                        })),
                    };
                }
                if length as usize > record.len() {
                    return Err(ControlError::Truncated);
                }
                length
                    .checked_next_multiple_of(FRAME_ALIGNMENT)
                    .ok_or(ControlError::InvalidLength)?
            }
            _ => {
                if length != HEADER_LENGTH {
                    return Err(ControlError::InvalidLength);
                }
                HEADER_LENGTH
            }
        };
        let alias = Alias {
            session_id: r.i32(12)?,
            stream_id: r.i32(16)?,
        };
        let lane = flags.lane();
        let first = *group.get_or_insert((alias, lane));
        if first != (alias, lane) {
            return Err(ControlError::InvalidGrouping);
        }
        let remaining = record.len();
        let (stride, length) = (stride as usize, length as usize);
        if stride == remaining || length == remaining {
            return Ok(Datagram::DataBatch(DataDatagram {
                bytes,
                alias: first.0,
                lane: first.1,
            }));
        }
        if stride > remaining {
            // Part of the padding of the last record: a trailer.
            return Err(ControlError::InvalidGrouping);
        }
        offset = offset
            .checked_add(stride)
            .ok_or(ControlError::InvalidLength)?;
    }
}

fn check_identity(identity: &Identity) -> Result<(), ControlError> {
    if identity.driver_id == [0, 0] || identity.registration_id == 0 || identity.incarnation == 0 {
        return Err(ControlError::InvalidIdentity);
    }
    Ok(())
}

fn check_receiver(receiver: &Receiver) -> Result<(), ControlError> {
    if receiver.receiver_boot_id == [0, 0] || receiver.receiver_id == 0 {
        return Err(ControlError::InvalidIdentity);
    }
    Ok(())
}

fn check_challenge(challenge: &ChallengeBlock) -> Result<(), ControlError> {
    if challenge.receiver_boot_id == [0, 0] {
        return Err(ControlError::InvalidIdentity);
    }
    if challenge.nonce == [0, 0] {
        return Err(ControlError::InvalidValue);
    }
    Ok(())
}

fn check_term(term: &TermParams) -> Result<(), ControlError> {
    let length_ok = term.term_length.is_power_of_two()
        && (MIN_TERM_LENGTH..=MAX_TERM_LENGTH).contains(&term.term_length);
    if !length_ok || !(MIN_MTU..=MAX_MTU).contains(&term.mtu) {
        return Err(ControlError::InvalidValue);
    }
    Ok(())
}

fn check_position(position: u64) -> Result<(), ControlError> {
    if !position.is_multiple_of(u64::from(FRAME_ALIGNMENT)) || position > MAX_POSITION {
        return Err(ControlError::InvalidPosition);
    }
    Ok(())
}

fn check_window(window: u32) -> Result<(), ControlError> {
    if !window.is_multiple_of(FRAME_ALIGNMENT) || window > MAX_WINDOW {
        return Err(ControlError::InvalidPosition);
    }
    Ok(())
}

fn check_range(range: &NakRange) -> Result<(), ControlError> {
    let length_ok = range.length.is_multiple_of(FRAME_ALIGNMENT)
        && (FRAME_ALIGNMENT..=MAX_NAK_LENGTH).contains(&range.length);
    if !length_ok {
        return Err(ControlError::InvalidPosition);
    }
    check_position(range.start)?;
    match range.start.checked_add(u64::from(range.length)) {
        Some(end) if end <= MAX_POSITION => Ok(()),
        _ => Err(ControlError::InvalidPosition),
    }
}

/// The UNBOUND version fields: the rejected version is not 0 and lies
/// outside `[min, max]`; `1 <= min <= max` and the range contains 1.
fn check_versions(rejected: u8, min: u8, max: u8) -> Result<(), ControlError> {
    let range = min..=max;
    let valid = rejected != 0
        && min >= 1
        && max >= min
        && range.contains(&PROTOCOL_VERSION)
        && !range.contains(&rejected);
    if valid {
        Ok(())
    } else {
        Err(ControlError::InvalidValue)
    }
}

/// Explicit little-endian reads at fixed offsets. The record length is
/// validated before any body read, so [`ControlError::Truncated`] is the
/// only possible failure and only for a short slice.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn bytes<const N: usize>(&self, at: usize) -> Result<[u8; N], ControlError> {
        let end = at.checked_add(N).ok_or(ControlError::Truncated)?;
        self.0
            .get(at..end)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(ControlError::Truncated)
    }

    fn u8(&self, at: usize) -> Result<u8, ControlError> {
        let [byte] = self.bytes::<1>(at)?;
        Ok(byte)
    }

    fn u16(&self, at: usize) -> Result<u16, ControlError> {
        Ok(u16::from_le_bytes(self.bytes(at)?))
    }

    fn u32(&self, at: usize) -> Result<u32, ControlError> {
        Ok(u32::from_le_bytes(self.bytes(at)?))
    }

    fn i32(&self, at: usize) -> Result<i32, ControlError> {
        Ok(i32::from_le_bytes(self.bytes(at)?))
    }

    fn u64(&self, at: usize) -> Result<u64, ControlError> {
        Ok(u64::from_le_bytes(self.bytes(at)?))
    }

    fn id128(&self, at: usize) -> Result<[u64; 2], ControlError> {
        Ok([self.u64(at)?, self.u64(at + 8)?])
    }

    fn position(&self, at: usize) -> Result<u64, ControlError> {
        let position = self.u64(at)?;
        check_position(position)?;
        Ok(position)
    }

    fn identity(&self, at: usize) -> Result<Identity, ControlError> {
        let identity = Identity {
            driver_id: self.id128(at)?,
            registration_id: self.u64(at + 16)?,
            incarnation: self.u64(at + 24)?,
        };
        check_identity(&identity)?;
        Ok(identity)
    }

    fn receiver(&self, at: usize) -> Result<Receiver, ControlError> {
        let receiver = Receiver {
            receiver_boot_id: self.id128(at)?,
            receiver_id: self.u64(at + 16)?,
        };
        check_receiver(&receiver)?;
        Ok(receiver)
    }

    fn challenge(&self, at: usize) -> Result<ChallengeBlock, ControlError> {
        let challenge = ChallengeBlock {
            receiver_boot_id: self.id128(at)?,
            nonce: self.id128(at + 16)?,
        };
        check_challenge(&challenge)?;
        Ok(challenge)
    }

    fn term(&self, at: usize) -> Result<TermParams, ControlError> {
        let term = TermParams {
            term_length: self.u32(at)?,
            initial_term_id: self.i32(at + 4)?,
            mtu: self.u32(at + 8)?,
        };
        check_term(&term)?;
        Ok(term)
    }

    /// The lane (byte 0), length (4) and start (8) of a NAK range, checked
    /// in that order.
    fn range(&self, at: usize) -> Result<NakRange, ControlError> {
        let lane = Lane::try_new(self.u8(at)?).map_err(|_| ControlError::InvalidValue)?;
        let range = NakRange {
            lane,
            length: self.u32(at + 4)?,
            start: self.u64(at + 8)?,
        };
        check_range(&range)?;
        Ok(range)
    }
}

/// A zeroed record image that is copied to the output only when complete.
struct Writer {
    buf: [u8; MAX_CONTROL_LENGTH],
    length: usize,
}

impl Writer {
    fn new(length: usize) -> Result<Self, ControlError> {
        if length > MAX_CONTROL_LENGTH {
            return Err(ControlError::InvalidLength);
        }
        Ok(Self {
            buf: [0; MAX_CONTROL_LENGTH],
            length,
        })
    }

    fn put(&mut self, at: usize, value: &[u8]) -> Result<(), ControlError> {
        let end = at
            .checked_add(value.len())
            .filter(|end| *end <= self.length)
            .ok_or(ControlError::InvalidLength)?;
        self.buf
            .get_mut(at..end)
            .ok_or(ControlError::InvalidLength)?
            .copy_from_slice(value);
        Ok(())
    }

    fn id128(&mut self, at: usize, [w0, w1]: [u64; 2]) -> Result<(), ControlError> {
        self.put(at, &w0.to_le_bytes())?;
        self.put(at + 8, &w1.to_le_bytes())
    }

    fn identity(&mut self, at: usize, identity: &Identity) -> Result<(), ControlError> {
        self.id128(at, identity.driver_id)?;
        self.put(at + 16, &identity.registration_id.to_le_bytes())?;
        self.put(at + 24, &identity.incarnation.to_le_bytes())
    }

    fn receiver(&mut self, at: usize, receiver: &Receiver) -> Result<(), ControlError> {
        self.id128(at, receiver.receiver_boot_id)?;
        self.put(at + 16, &receiver.receiver_id.to_le_bytes())
    }

    fn challenge(&mut self, at: usize, challenge: &ChallengeBlock) -> Result<(), ControlError> {
        self.id128(at, challenge.receiver_boot_id)?;
        self.id128(at + 16, challenge.nonce)
    }

    fn term(&mut self, at: usize, term: &TermParams) -> Result<(), ControlError> {
        self.put(at, &term.term_length.to_le_bytes())?;
        self.put(at + 4, &term.initial_term_id.to_le_bytes())?;
        self.put(at + 8, &term.mtu.to_le_bytes())
    }

    fn range(&mut self, at: usize, range: &NakRange) -> Result<(), ControlError> {
        self.put(at, &[range.lane.get()])?;
        self.put(at + 4, &range.length.to_le_bytes())?;
        self.put(at + 8, &range.start.to_le_bytes())
    }

    fn bytes(&self) -> Result<&[u8], ControlError> {
        self.buf
            .get(..self.length)
            .ok_or(ControlError::InvalidLength)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod properties;
