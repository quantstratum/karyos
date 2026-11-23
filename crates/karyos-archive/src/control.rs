// SPDX-License-Identifier: Apache-2.0

//! The Archive's control messages, version 1, derived with
//! `karyos-codec-derive` on the `karyos-codec` runtime (`quantstratum-docs:
//! karyos/design/archive-control-codec.md`, phase 3 batch A1; ADR-0036).
//!
//! Schema 1 holds nine requests ([`StartRecording`], [`StopRecording`],
//! [`ListRecordings`], [`Replay`], [`StopReplay`], and the retention
//! requests [`HoldRecording`], [`ReleaseHold`], [`PurgeRecording`] and
//! [`VerifyRecording`]) and four responses ([`ControlResponse`],
//! [`RecordingDescriptor`], [`RecordingSignal`], [`RangeOutcome`]). The
//! retention templates follow ADR-0088 (quantstratum-docs, Proposed;
//! karyos#967).
//! Each message is a plain value whose text fields borrow the decoded
//! input; [`ControlMessage::decode`] validates a whole message before any
//! value exists, and `encode` writes into the caller's buffer. Nothing
//! allocates. Every message is derived (karyos#1029, karyos#1104);
//! [`ControlMessage`], the dispatcher over the templates, is not a message
//! and stays written by hand.
//!
//! The derive refuses, when the crate compiles, a field past its
//! template's block and two fields that overlap (karyos#1066). A message
//! within its block compiles:
//!
//! ```
//! use karyos_codec_derive::Message;
//! const T: karyos_codec::Template = karyos_codec::Template {
//!     schema_id: 9, template_id: 1, version: 1, block_length: 12, max_length: 24,
//! };
//! #[derive(Message)]
//! #[message(template = T)]
//! struct M {
//!     #[field(offset = 0)]
//!     a: u64,
//!     #[field(offset = 8)]
//!     b: u32,
//! }
//! # let _ = M { a: 0, b: 0 }.encode(&mut [0u8; 24]);
//! ```
//!
//! A field past the block does not:
//!
//! ```compile_fail
//! use karyos_codec_derive::Message;
//! const T: karyos_codec::Template = karyos_codec::Template {
//!     schema_id: 9, template_id: 1, version: 1, block_length: 12, max_length: 24,
//! };
//! #[derive(Message)]
//! #[message(template = T)]
//! struct M {
//!     #[field(offset = 0)]
//!     a: u64,
//!     #[field(offset = 8)]
//!     b: u64,
//! }
//! # let _ = M { a: 0, b: 0 }.encode(&mut [0u8; 24]);
//! ```
//!
//! Nor do two fields that overlap:
//!
//! ```compile_fail
//! use karyos_codec_derive::Message;
//! const T: karyos_codec::Template = karyos_codec::Template {
//!     schema_id: 9, template_id: 1, version: 1, block_length: 12, max_length: 24,
//! };
//! #[derive(Message)]
//! #[message(template = T)]
//! struct M {
//!     #[field(offset = 0)]
//!     a: u64,
//!     #[field(offset = 4)]
//!     b: u32,
//! }
//! # let _ = M { a: 0, b: 0 }.encode(&mut [0u8; 24]);
//! ```

use karyos_codec::{Block, CodecError, Decoder, Encoder, Envelope, Template};
use karyos_codec_derive::Message;

use crate::catalog::{SourceIncarnation, Stop, StopReason};
use crate::recorder::{Mode, OnLap};
use crate::segment::{Geometry, SyncPolicy};

#[cfg(test)]
mod tests;

/// The Archive's schema id.
pub const SCHEMA_ID: u16 = 1;
/// Schema 1's first version, frozen at the `v0.1.0-alpha.2` tag.
pub const VERSION: u16 = 1;
/// Schema 1's second version: only the retention state query (ADR-0101;
/// archive-control-codec.md section 11), decoded beside version 1.
pub const VERSION_2: u16 = 2;
/// The longest channel, in bytes.
pub const MAX_CHANNEL: usize = 1024;
/// The longest response message, in bytes.
pub const MAX_RESPONSE_MESSAGE: usize = 256;
/// The most recordings one list request asks for.
pub const MAX_LIST_COUNT: u32 = 1000;
/// The largest replay scale, in parts per million of the recorded rate.
pub const MAX_SCALE_PPM: u32 = 100_000_000;

const fn template(template_id: u16, block_length: u16, max_length: u32) -> Template {
    Template {
        schema_id: SCHEMA_ID,
        template_id,
        version: VERSION,
        block_length,
        max_length,
    }
}

// Maximum lengths: the 12-byte envelope, the block, and the variable
// field's 2-byte length prefix and largest value.
/// `StartRecording`, template 1.
pub const START_RECORDING: Template = template(1, 35, 12 + 35 + 2 + 1024);
/// `StopRecording`, template 2.
pub const STOP_RECORDING: Template = template(2, 16, 12 + 16);
/// `ListRecordings`, template 3.
pub const LIST_RECORDINGS: Template = template(3, 20, 12 + 20);
/// `Replay`, template 4.
pub const REPLAY: Template = template(4, 41, 12 + 41 + 2 + 1024);
/// `StopReplay`, template 5.
pub const STOP_REPLAY: Template = template(5, 16, 12 + 16);
/// `ControlResponse`, template 101.
pub const CONTROL_RESPONSE: Template = template(101, 17, 12 + 17 + 2 + 256);
/// `RecordingDescriptor`, template 102.
pub const RECORDING_DESCRIPTOR: Template = template(102, 110, 12 + 110 + 2 + 1024);
/// `RecordingSignal`, template 103.
pub const RECORDING_SIGNAL: Template = template(103, 27, 12 + 27);
/// `HoldRecording`, template 6 (ADR-0088).
pub const HOLD_RECORDING: Template = template(6, 16, 12 + 16);
/// `ReleaseHold`, template 7 (ADR-0088).
pub const RELEASE_HOLD: Template = template(7, 16, 12 + 16);
/// `PurgeRecording`, template 8 (ADR-0088).
pub const PURGE_RECORDING: Template = template(8, 40, 12 + 40);
/// `VerifyRecording`, template 9 (ADR-0088).
pub const VERIFY_RECORDING: Template = template(9, 16, 12 + 16);
/// `RangeOutcome`, template 104 (ADR-0088).
pub const RANGE_OUTCOME: Template = template(104, 45, 12 + 45);
/// The reason bits a [`RangeOutcome`] may set: bits 0 to 9.
pub const RANGE_REASONS: u32 = (1 << 10) - 1;
/// A [`RangeOutcome`]'s `first_inconsistent` when there is none.
pub const NO_INCONSISTENT: u64 = u64::MAX;

const fn template_v2(template_id: u16, block_length: u16, max_length: u32) -> Template {
    Template {
        schema_id: SCHEMA_ID,
        template_id,
        version: VERSION_2,
        block_length,
        max_length,
    }
}

/// `RetentionState`, template 10, version 2 (ADR-0101).
pub const RETENTION_STATE: Template = template_v2(10, 24, 12 + 24 + 2 + 1024);
/// `RetentionDescriptor`, template 105, version 2 (ADR-0101).
pub const RETENTION_DESCRIPTOR: Template = template_v2(105, 57, 12 + 57);
/// `RetentionSummary`, template 106, version 2 (ADR-0101).
pub const RETENTION_SUMMARY: Template = template_v2(106, 32, 12 + 32);
/// A [`RetentionDescriptor`]'s `earliest_expiry_ns` with none.
pub const NO_EXPIRY: u64 = u64::MAX;
/// A [`RetentionSummary`]'s `free_bytes` when not known.
pub const FREE_UNKNOWN: u64 = u64::MAX;

fn invalid_enum(field: &'static str, value: impl Into<u64>) -> CodecError {
    CodecError::InvalidEnum {
        field,
        value: value.into(),
    }
}

fn out_of_range(field: &'static str) -> CodecError {
    CodecError::ValueOutOfRange { field }
}

/// An identifier, never 0.
fn id(field: &'static str, value: u64) -> Result<u64, CodecError> {
    if value == 0 {
        Err(out_of_range(field))
    } else {
        Ok(value)
    }
}

/// Requests a recording of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = START_RECORDING)]
pub struct StartRecording<'a> {
    /// Echoed in the responses.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The recorded stream.
    #[field(offset = 24)]
    pub stream_id: i32,
    /// The recorded session.
    #[field(offset = 28)]
    pub session_id: i32,
    /// Required or async: the mode at 32 and its on-lap byte at 33.
    #[field(with = mode_on_lap, spans = [(32, 1), (33, 1)])]
    pub mode: Mode,
    /// The store's sync policy: the policy at 34 and its interval at 8.
    #[field(with = sync_policy, spans = [(8, 8), (34, 1)])]
    pub sync_policy: SyncPolicy,
    /// Segment length in bytes; 0 for the Archive's default.
    #[field(offset = 16)]
    pub segment_length: u64,
    /// The channel, 1 to [`MAX_CHANNEL`] bytes.
    #[field(var, min = 1, max = MAX_CHANNEL)]
    pub channel: &'a str,
}

/// [`Mode`] as a tied field of the derive: the mode at 32, the on-lap byte
/// at 33 (karyos#1104).
mod mode_on_lap {
    use super::{
        Block, CodecError, Encoder, Mode, OnLap, StartRecording, invalid_enum, out_of_range,
    };

    pub(super) fn read(block: &Block<'_>) -> Result<Mode, CodecError> {
        match (block.u8(32)?, block.u8(33)?) {
            (1, 0) => Ok(Mode::Required),
            (2, 1) => Ok(Mode::Async {
                on_lap: OnLap::Stop,
            }),
            (2, 2) => Ok(Mode::Async {
                on_lap: OnLap::Resume,
            }),
            (1 | 2, 0..=2) => Err(out_of_range("on_lap")),
            (1 | 2, value) => Err(invalid_enum("on_lap", value)),
            (value, _) => Err(invalid_enum("mode", value)),
        }
    }

    fn write_value(encoder: &mut Encoder<'_>, mode: &Mode) -> Result<(), CodecError> {
        let (mode, on_lap) = match mode {
            Mode::Required => (1, 0),
            Mode::Async {
                on_lap: OnLap::Stop,
            } => (2, 1),
            Mode::Async {
                on_lap: OnLap::Resume,
            } => (2, 2),
        };
        encoder.u8(32, mode)?;
        encoder.u8(33, on_lap)
    }

    /// The message's `mode`, as the derive writes a tied field.
    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &StartRecording<'_>,
    ) -> Result<(), CodecError> {
        write_value(encoder, &message.mode)
    }
}

/// [`SyncPolicy`] as a tied field of the derive: the policy at 34, its
/// interval at 8, nonzero exactly for `Every` (karyos#1104).
mod sync_policy {
    use super::{
        Block, CodecError, Encoder, StartRecording, SyncPolicy, invalid_enum, out_of_range,
    };

    pub(super) fn read(block: &Block<'_>) -> Result<SyncPolicy, CodecError> {
        let interval = block.u64(8)?;
        match block.u8(34)? {
            0 | 1 if interval != 0 => Err(out_of_range("sync_interval_ns")),
            0 => Ok(SyncPolicy::None),
            1 => Ok(SyncPolicy::PerSegment),
            2 if interval == 0 => Err(out_of_range("sync_interval_ns")),
            2 => Ok(SyncPolicy::Every {
                interval_ns: interval,
            }),
            value => Err(invalid_enum("sync_policy", value)),
        }
    }

    fn write_value(encoder: &mut Encoder<'_>, policy: &SyncPolicy) -> Result<(), CodecError> {
        let (policy, interval) = match *policy {
            SyncPolicy::None => (0, 0),
            SyncPolicy::PerSegment => (1, 0),
            SyncPolicy::Every { interval_ns: 0 } => return Err(out_of_range("sync_interval_ns")),
            SyncPolicy::Every { interval_ns } => (2, interval_ns),
        };
        encoder.u64(8, interval)?;
        encoder.u8(34, policy)
    }

    /// The message's `sync_policy`, as the derive writes a tied field.
    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &StartRecording<'_>,
    ) -> Result<(), CodecError> {
        write_value(encoder, &message.sync_policy)
    }
}

/// Requests a recording's stop where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = STOP_RECORDING)]
pub struct StopRecording {
    /// Echoed in the response.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The recording, never 0.
    #[field(offset = 8, check = id)]
    pub recording_id: u64,
}

/// Requests the catalog's recordings from an id on: one
/// [`RecordingDescriptor`] each, then a [`ControlResponse`] with the count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = LIST_RECORDINGS)]
pub struct ListRecordings {
    /// Echoed in the responses.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The first id listed: a cursor, so 0 lists from the first
    /// recording.
    #[field(offset = 8)]
    pub from_id: u64,
    /// At most this many, 1 to [`MAX_LIST_COUNT`].
    #[field(offset = 16, check = list_count)]
    pub max_count: u32,
}

fn list_count(field: &'static str, count: u32) -> Result<u32, CodecError> {
    if (1..=MAX_LIST_COUNT).contains(&count) {
        Ok(count)
    } else {
        Err(out_of_range(field))
    }
}

/// A request naming one recording: [`HoldRecording`], [`ReleaseHold`] and
/// [`VerifyRecording`] share this block (ADR-0088).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(templates = [HOLD_RECORDING, RELEASE_HOLD, VERIFY_RECORDING])]
pub struct RecordingRequest {
    /// Echoed in the response.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The recording, never 0.
    #[field(offset = 8, check = id)]
    pub recording_id: u64,
}

/// Requests a legal hold on a recording, template 6 (ADR-0088): answered
/// by a [`ControlResponse`] with code 0 (applied with evidence),
/// [`ResponseCode::HeldWithoutEvidence`],
/// [`ResponseCode::HeldInMemoryOnly`] or
/// [`ResponseCode::UnknownRecording`].
pub type HoldRecording = RecordingRequest;
/// Requests the release of a recording's legal hold, template 7: answered
/// with code 0 or [`ResponseCode::Refused`].
pub type ReleaseHold = RecordingRequest;
/// Requests a seal verification of a recording, template 9: one
/// [`RangeOutcome`] per range, then a [`ControlResponse`] whose `id` is
/// the count sent.
pub type VerifyRecording = RecordingRequest;

/// Requests a purge of a recording below a position, template 8
/// (ADR-0088): answered with code 0 or [`ResponseCode::Refused`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = PURGE_RECORDING)]
pub struct PurgeRecording {
    /// Echoed in the response.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The recording, never 0.
    #[field(offset = 8, check = id)]
    pub recording_id: u64,
    /// The first position kept.
    #[field(offset = 16)]
    pub before: u64,
    /// The purge's id, unique among the Archive's outstanding purges,
    /// never 0.
    #[field(offset = 24, check = id)]
    pub request_id: u64,
    /// The operator the requester authenticated, never 0.
    #[field(offset = 32, check = id)]
    pub operator: u64,
}

/// A range's integrity outcome, the verifier's verbatim (SPEC.md §8.4,
/// "Verification"; ADR-0088).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntegrityOutcome {
    /// 1.
    Verified,
    /// 2.
    BeyondAnchor,
    /// 3.
    Unsealed,
    /// 4.
    Purged,
    /// 5.
    Inconsistent,
}

impl IntegrityOutcome {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Verified => 1,
            Self::BeyondAnchor => 2,
            Self::Unsealed => 3,
            Self::Purged => 4,
            Self::Inconsistent => 5,
        }
    }

    /// The outcome of wire code `code`.
    #[must_use]
    pub const fn of(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Verified),
            2 => Some(Self::BeyondAnchor),
            3 => Some(Self::Unsealed),
            4 => Some(Self::Purged),
            5 => Some(Self::Inconsistent),
            _ => None,
        }
    }

    /// Its name, as the verifier and the agent write it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::BeyondAnchor => "beyond_anchor",
            Self::Unsealed => "unsealed",
            Self::Purged => "purged",
            Self::Inconsistent => "inconsistent",
        }
    }
}

/// The names of the reason bits of a [`RangeOutcome`], bit 0 first, in the
/// order of `integrity::verify::Reason` (ADR-0088).
pub const REASON_NAMES: [&str; 10] = [
    "untrusted_evidence",
    "unknown_key",
    "unknown_algorithm",
    "malformed_evidence",
    "missing_evidence",
    "conflicting_anchors",
    "corruption",
    "shortened_index",
    "unauthenticated_purge",
    "no_anchor",
];

/// One range's verification outcome, template 104 (ADR-0088).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = RANGE_OUTCOME, check = Self::check)]
pub struct RangeOutcome {
    /// The verify request's.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The recording, never 0.
    #[field(offset = 8)]
    pub recording_id: u64,
    /// The range's start.
    #[field(offset = 16)]
    pub start: u64,
    /// Its end, exclusive, at least `start`.
    #[field(offset = 24)]
    pub end: u64,
    /// The counter of the first inconsistent record, [`NO_INCONSISTENT`]
    /// for none; always none unless the outcome is inconsistent.
    #[field(offset = 32)]
    pub first_inconsistent: u64,
    /// The reasons, a bit set within [`RANGE_REASONS`].
    #[field(offset = 40)]
    pub reasons: u32,
    /// The outcome.
    #[field(with = integrity_outcome, offset = 44, width = 1)]
    pub outcome: IntegrityOutcome,
}

/// A range's [`IntegrityOutcome`], as a `with` field.
mod integrity_outcome {
    use super::{Block, CodecError, Encoder, IntegrityOutcome, invalid_enum};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<IntegrityOutcome, CodecError> {
        let raw = block.u8(at)?;
        IntegrityOutcome::of(raw).ok_or_else(|| invalid_enum("outcome", raw))
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        value: &IntegrityOutcome,
    ) -> Result<(), CodecError> {
        encoder.u8(at, value.code())
    }
}

impl RangeOutcome {
    fn check(&self) -> Result<(), CodecError> {
        if self.end < self.start {
            return Err(out_of_range("end"));
        }
        if self.reasons & !RANGE_REASONS != 0 {
            return Err(out_of_range("reasons"));
        }
        if self.outcome != IntegrityOutcome::Inconsistent
            && self.first_inconsistent != NO_INCONSISTENT
        {
            return Err(out_of_range("first_inconsistent"));
        }
        id("recording_id", self.recording_id).map(|_| ())
    }

    /// The names of its reasons, bit 0 first.
    pub fn reason_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        REASON_NAMES
            .iter()
            .enumerate()
            .filter(|&(bit, _)| self.reasons & (1 << bit) != 0)
            .map(|(_, name)| *name)
    }
}

/// The pace of a replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplayRate {
    /// As fast as the target stream takes it.
    Full,
    /// At the recorded pace.
    AsRecorded,
    /// The recorded pace scaled, in parts per million (1 to
    /// [`MAX_SCALE_PPM`]).
    Scaled {
        /// The scale.
        ppm: u32,
    },
}

/// Requests a replay of a recording's range onto a new stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = REPLAY)]
pub struct Replay<'a> {
    /// Echoed in the responses.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The recording, never 0.
    #[field(offset = 8, check = id)]
    pub recording_id: u64,
    /// The first position replayed.
    #[field(offset = 16)]
    pub position: u64,
    /// Bytes; `u64::MAX` to the recording's end.
    #[field(offset = 24)]
    pub length: u64,
    /// The pace: the rate at 40 and its scale at 32.
    #[field(with = replay_rate, spans = [(32, 4), (40, 1)])]
    pub rate: ReplayRate,
    /// The target stream.
    #[field(offset = 36)]
    pub target_stream_id: i32,
    /// The target channel, 1 to [`MAX_CHANNEL`] bytes.
    #[field(var, min = 1, max = MAX_CHANNEL)]
    pub target_channel: &'a str,
}

/// [`ReplayRate`] as a tied field of the derive: the rate at 40, its scale
/// at 32, nonzero exactly for `Scaled` (karyos#1104).
mod replay_rate {
    use super::{
        Block, CodecError, Encoder, MAX_SCALE_PPM, Replay, ReplayRate, invalid_enum, out_of_range,
    };

    pub(super) fn read(block: &Block<'_>) -> Result<ReplayRate, CodecError> {
        let scale = block.u32(32)?;
        match block.u8(40)? {
            1 | 2 if scale != 0 => Err(out_of_range("scale_ppm")),
            1 => Ok(ReplayRate::Full),
            2 => Ok(ReplayRate::AsRecorded),
            3 if (1..=MAX_SCALE_PPM).contains(&scale) => Ok(ReplayRate::Scaled { ppm: scale }),
            3 => Err(out_of_range("scale_ppm")),
            value => Err(invalid_enum("rate", value)),
        }
    }

    fn write_value(encoder: &mut Encoder<'_>, rate: &ReplayRate) -> Result<(), CodecError> {
        let (rate, scale) = match *rate {
            ReplayRate::Full => (1, 0),
            ReplayRate::AsRecorded => (2, 0),
            ReplayRate::Scaled { ppm } if (1..=MAX_SCALE_PPM).contains(&ppm) => (3, ppm),
            ReplayRate::Scaled { .. } => return Err(out_of_range("scale_ppm")),
        };
        encoder.u32(32, scale)?;
        encoder.u8(40, rate)
    }

    /// The message's `rate`, as the derive writes a tied field.
    pub(super) fn write(encoder: &mut Encoder<'_>, message: &Replay<'_>) -> Result<(), CodecError> {
        write_value(encoder, &message.rate)
    }
}

/// Requests a replay's stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = STOP_REPLAY)]
pub struct StopReplay {
    /// Echoed in the response.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The replay, never 0.
    #[field(offset = 8, check = id)]
    pub replay_id: u64,
}

/// The outcome of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseCode {
    /// Done.
    Ok,
    /// Failed for a reason the message names.
    Error,
    /// No such recording.
    UnknownRecording,
    /// No such replay.
    UnknownReplay,
    /// The request does not hold.
    InvalidRequest,
    /// The request's schema, template or version is not supported.
    UnsupportedSchema,
    /// A hold is in force and its pending marker durable; the operations
    /// journal did not record it (ADR-0088).
    HeldWithoutEvidence,
    /// A hold is in force in this process only (ADR-0088).
    HeldInMemoryOnly,
    /// The Archive refused a release or a purge; the message names the
    /// reason (ADR-0088).
    Refused,
}

impl ResponseCode {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Error => 1,
            Self::UnknownRecording => 2,
            Self::UnknownReplay => 3,
            Self::InvalidRequest => 4,
            Self::UnsupportedSchema => 5,
            Self::HeldWithoutEvidence => 6,
            Self::HeldInMemoryOnly => 7,
            Self::Refused => 8,
        }
    }

    const fn of(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Ok),
            1 => Some(Self::Error),
            2 => Some(Self::UnknownRecording),
            3 => Some(Self::UnknownReplay),
            4 => Some(Self::InvalidRequest),
            5 => Some(Self::UnsupportedSchema),
            6 => Some(Self::HeldWithoutEvidence),
            7 => Some(Self::HeldInMemoryOnly),
            8 => Some(Self::Refused),
            _ => None,
        }
    }
}

/// The answer to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = CONTROL_RESPONSE, check = Self::check)]
pub struct ControlResponse<'a> {
    /// The request's.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The recording or replay id, or a list's count; 0 on an error.
    #[field(offset = 8)]
    pub id: u64,
    /// The outcome.
    #[field(offset = 16, width = 1, with = response_code)]
    pub code: ResponseCode,
    /// Why, on an error: up to [`MAX_RESPONSE_MESSAGE`] bytes; empty when
    /// the code is [`ResponseCode::Ok`].
    #[field(var, min = 0, max = MAX_RESPONSE_MESSAGE)]
    pub message: &'a str,
}

/// [`ResponseCode`] as a block field of the derive (karyos#1029).
mod response_code {
    use super::{Block, CodecError, Encoder, ResponseCode, invalid_enum};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<ResponseCode, CodecError> {
        let raw = block.u8(at)?;
        ResponseCode::of(raw).ok_or_else(|| invalid_enum("code", raw))
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        code: &ResponseCode,
    ) -> Result<(), CodecError> {
        encoder.u8(at, code.code())
    }
}

impl ControlResponse<'_> {
    fn check(&self) -> Result<(), CodecError> {
        match self.code {
            ResponseCode::Ok if !self.message.is_empty() => Err(CodecError::LengthOutOfRange {
                field: "message",
                length: self.message.len(),
                min: 0,
                max: 0,
            }),
            ResponseCode::Ok => Ok(()),
            _ if self.id != 0 => Err(out_of_range("id")),
            _ => Ok(()),
        }
    }
}

/// Whether a listed recording still records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordingState {
    /// It still records.
    Recording {
        /// The position written so far.
        written: u64,
        /// It lost ranges so far (an async recording that lapped and
        /// resumed).
        incomplete: bool,
    },
    /// Where, when and why it stopped.
    Stopped(Stop),
}

/// One recording of a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = RECORDING_DESCRIPTOR, check = Self::check)]
pub struct RecordingDescriptor<'a> {
    /// The list request's.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The recording, never 0.
    #[field(offset = 8, check = id)]
    pub recording_id: u64,
    /// Its first position.
    #[field(offset = 16)]
    pub start: u64,
    /// When it started.
    #[field(offset = 40)]
    pub start_time_ns: u64,
    /// Whether it still records, or where it stopped: the stop position
    /// at 24, the written position at 32, the stop time at 48, the reason
    /// at 108 and the incomplete flag at 109.
    #[field(with = recording_state, spans = [(24, 8), (32, 8), (48, 8), (108, 1), (109, 1)])]
    pub state: RecordingState,
    /// Its segment geometry: the segment length at 56, the term length at
    /// 96.
    #[field(with = geometry, spans = [(56, 8), (96, 4)])]
    pub geometry: Geometry,
    /// The publication recorded, which a live merge matches.
    #[field(offset = 64, width = 32, with = source_incarnation)]
    pub source: SourceIncarnation,
    /// The recorded stream.
    #[field(offset = 100)]
    pub stream_id: i32,
    /// The recorded session.
    #[field(offset = 104)]
    pub session_id: i32,
    /// The channel, 1 to [`MAX_CHANNEL`] bytes.
    #[field(var, min = 1, max = MAX_CHANNEL)]
    pub channel: &'a str,
}

impl RecordingDescriptor<'_> {
    /// Written from the start on: refused on decode and on encode.
    fn check(&self) -> Result<(), CodecError> {
        let written = match self.state {
            RecordingState::Recording { written, .. } => written,
            RecordingState::Stopped(stop) => stop.position,
        };
        if written < self.start {
            return Err(out_of_range("written"));
        }
        Ok(())
    }
}

/// [`RecordingState`] as a tied field of the derive (karyos#1104).
mod recording_state {
    use super::{
        Block, CodecError, Encoder, RecordingDescriptor, RecordingState, Stop, StopReason,
        invalid_enum, out_of_range,
    };

    pub(super) fn read(block: &Block<'_>) -> Result<RecordingState, CodecError> {
        let stop_position = block.u64(24)?;
        let written = block.u64(32)?;
        let stop_time_ns = block.u64(48)?;
        let reason = block.u8(108)?;
        let incomplete = block.bool("incomplete", 109)?;
        let state = match reason {
            0 if stop_position != u64::MAX || stop_time_ns != 0 => {
                return Err(out_of_range("stop"));
            }
            0 => RecordingState::Recording {
                written,
                incomplete,
            },
            code => RecordingState::Stopped(Stop {
                position: stop_position,
                time_ns: stop_time_ns,
                reason: StopReason::of(code).ok_or_else(|| invalid_enum("stop_reason", code))?,
                incomplete,
                // Not on the wire.
                closed_utc_ns: None,
            }),
        };
        // Written up to the stop once stopped.
        if matches!(state, RecordingState::Stopped(stop) if stop.position != written) {
            return Err(out_of_range("written"));
        }
        Ok(state)
    }

    fn write_value(encoder: &mut Encoder<'_>, state: &RecordingState) -> Result<(), CodecError> {
        let (stop, written, time, reason, incomplete) = match *state {
            RecordingState::Recording {
                written,
                incomplete,
            } => (u64::MAX, written, 0, 0, incomplete),
            RecordingState::Stopped(stop) => (
                stop.position,
                stop.position,
                stop.time_ns,
                stop.reason.code(),
                stop.incomplete,
            ),
        };
        encoder.u64(24, stop)?;
        encoder.u64(32, written)?;
        encoder.u64(48, time)?;
        encoder.u8(108, reason)?;
        encoder.bool(109, incomplete)
    }

    /// The message's `state`, as the derive writes a tied field.
    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &RecordingDescriptor<'_>,
    ) -> Result<(), CodecError> {
        write_value(encoder, &message.state)
    }
}

/// [`Geometry`] as a tied field of the derive: the segment length at 56,
/// the term length at 96 (karyos#1104).
mod geometry {
    use super::{Block, CodecError, Encoder, Geometry, RecordingDescriptor, out_of_range};

    pub(super) fn read(block: &Block<'_>) -> Result<Geometry, CodecError> {
        let term_length = block.u32(96)?;
        Geometry::new(term_length, block.u64(56)?).map_err(|_| {
            out_of_range(if term_length == 0 {
                "term_length"
            } else {
                "segment_length"
            })
        })
    }

    fn write_value(encoder: &mut Encoder<'_>, geometry: &Geometry) -> Result<(), CodecError> {
        encoder.u64(56, geometry.segment_length())?;
        encoder.u32(96, geometry.term_length())
    }

    /// The message's `geometry`, as the derive writes a tied field.
    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &RecordingDescriptor<'_>,
    ) -> Result<(), CodecError> {
        write_value(encoder, &message.geometry)
    }
}

/// [`SourceIncarnation`] as a block field of the derive: the driver at
/// `at` and `at + 8`, the registration and the incarnation after it
/// (karyos#1104).
mod source_incarnation {
    use super::{Block, CodecError, Encoder, SourceIncarnation};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<SourceIncarnation, CodecError> {
        Ok(SourceIncarnation {
            driver: [block.u64(at)?, block.u64(at + 8)?],
            registration: block.u64(at + 16)?,
            incarnation: block.u64(at + 24)?,
        })
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        source: &SourceIncarnation,
    ) -> Result<(), CodecError> {
        let [first, second] = source.driver;
        encoder.u64(at, first)?;
        encoder.u64(at + 8, second)?;
        encoder.u64(at + 16, source.registration)?;
        encoder.u64(at + 24, source.incarnation)
    }
}

/// What happened to a recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signal {
    /// It started.
    Started,
    /// It stopped, why, and whether it lost ranges.
    Stopped {
        /// Why.
        reason: StopReason,
        /// It lost ranges.
        incomplete: bool,
    },
    /// Its store failed; it is left for the next start to settle.
    Failed,
}

/// An unsolicited event of a recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = RECORDING_SIGNAL, check = Self::check)]
pub struct RecordingSignal {
    /// The start request's for [`Signal::Started`], else 0.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The recording, never 0.
    #[field(offset = 8, check = id)]
    pub recording_id: u64,
    /// Its start, or where it stopped.
    #[field(offset = 16)]
    pub position: u64,
    /// What happened: the signal at 24, the stop reason at 25 and the
    /// incomplete flag at 26.
    #[field(with = signal, spans = [(24, 1), (25, 1), (26, 1)])]
    pub signal: Signal,
}

impl RecordingSignal {
    /// A correlation id on [`Signal::Started`] only.
    fn check(&self) -> Result<(), CodecError> {
        if self.signal != Signal::Started && self.correlation_id != 0 {
            return Err(out_of_range("correlation_id"));
        }
        Ok(())
    }
}

/// [`Signal`] as a tied field of the derive (karyos#1104).
mod signal {
    use super::{
        Block, CodecError, Encoder, RecordingSignal, Signal, StopReason, invalid_enum, out_of_range,
    };

    pub(super) fn read(block: &Block<'_>) -> Result<Signal, CodecError> {
        let reason = block.u8(25)?;
        let incomplete = block.bool("incomplete", 26)?;
        match block.u8(24)? {
            1 | 3 if reason != 0 => Err(out_of_range("stop_reason")),
            1 | 3 if incomplete => Err(out_of_range("incomplete")),
            1 => Ok(Signal::Started),
            3 => Ok(Signal::Failed),
            2 => Ok(Signal::Stopped {
                reason: StopReason::of(reason)
                    .ok_or_else(|| invalid_enum("stop_reason", reason))?,
                incomplete,
            }),
            value => Err(invalid_enum("signal", value)),
        }
    }

    fn write_value(encoder: &mut Encoder<'_>, signal: &Signal) -> Result<(), CodecError> {
        let (signal, reason, incomplete) = match *signal {
            Signal::Started => (1, 0, false),
            Signal::Stopped { reason, incomplete } => (2, reason.code(), incomplete),
            Signal::Failed => (3, 0, false),
        };
        encoder.u8(24, signal)?;
        encoder.u8(25, reason)?;
        encoder.bool(26, incomplete)
    }

    /// The message's `signal`, as the derive writes a tied field.
    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &RecordingSignal,
    ) -> Result<(), CodecError> {
        write_value(encoder, &message.signal)
    }
}

/// Asks for the retention state of up to `max_count` recordings from
/// `from_id`, template 10, version 2 (ADR-0101): answered on the stream
/// it names, by a [`RetentionDescriptor`] per recording, in increasing id
/// from `from_id` (inclusive), then one [`RetentionSummary`]. Read only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = RETENTION_STATE)]
pub struct RetentionState<'a> {
    /// Echoed in the answers.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The first recording id reported: a cursor, 0 from the first.
    #[field(offset = 8)]
    pub from_id: u64,
    /// At most this many descriptors, 1 to [`MAX_LIST_COUNT`].
    #[field(offset = 16, check = list_count)]
    pub max_count: u32,
    /// The stream the answer is published on.
    #[field(offset = 20)]
    pub response_stream_id: i32,
    /// Its channel, 1 to [`MAX_CHANNEL`] bytes.
    #[field(var, min = 1, max = MAX_CHANNEL)]
    pub response_channel: &'a str,
}

/// A recording's hold, as a [`RetentionDescriptor`] reports it (ADR-0101).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HoldState {
    /// No hold (wire 1).
    None,
    /// A hold applied with the operations journal's evidence (wire 2).
    Held,
    /// A hold that inhibits purge without being applied with evidence:
    /// requested and not yet evidenced, or an evidenced hold whose release
    /// the journal holds but whose resolving marker is not written yet
    /// (wire 3).
    Pending,
    /// The Archive's hold state could not be read since it started
    /// (wire 4).
    Unknown,
}

impl HoldState {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::None => 1,
            Self::Held => 2,
            Self::Pending => 3,
            Self::Unknown => 4,
        }
    }

    /// The state of wire code `code`.
    #[must_use]
    pub const fn of(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::None),
            2 => Some(Self::Held),
            3 => Some(Self::Pending),
            4 => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// [`HoldState`] as a field of the derive.
mod hold_state {
    use super::{Block, CodecError, Encoder, HoldState, invalid_enum};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<HoldState, CodecError> {
        let code = block.u8(at)?;
        HoldState::of(code).ok_or_else(|| invalid_enum("hold", code))
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        hold: &HoldState,
    ) -> Result<(), CodecError> {
        encoder.u8(at, hold.code())
    }
}

/// One recording's retention state, template 105, version 2 (ADR-0101).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = RETENTION_DESCRIPTOR, check = Self::check)]
pub struct RetentionDescriptor {
    /// The query's.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The recording, never 0.
    #[field(offset = 8, check = id)]
    pub recording_id: u64,
    /// When the hold was applied or received, UTC; 0 without a hold, for
    /// an unknown state and when not recorded.
    #[field(offset = 16)]
    pub hold_since_ns: u64,
    /// The recorded UTC close time; 0 while it records or without one.
    #[field(offset = 24)]
    pub close_time_ns: u64,
    /// The earliest policy expiry from the close time, a lower bound and
    /// never purge eligibility; [`NO_EXPIRY`] for none.
    #[field(offset = 32)]
    pub earliest_expiry_ns: u64,
    /// The configured policy's identity; 0 for none.
    #[field(offset = 40)]
    pub policy: u64,
    /// Its version; 0 for none.
    #[field(offset = 48)]
    pub policy_version: u64,
    /// Its hold.
    #[field(offset = 56, width = 1, with = hold_state)]
    pub hold: HoldState,
}

impl RetentionDescriptor {
    /// The cross-field rules of archive-control-codec.md section 11.
    fn check(&self) -> Result<(), CodecError> {
        if self.hold_since_ns != 0 && !matches!(self.hold, HoldState::Held | HoldState::Pending) {
            return Err(out_of_range("hold_since_ns"));
        }
        if (self.policy == 0) != (self.policy_version == 0) {
            return Err(out_of_range("policy_version"));
        }
        if self.earliest_expiry_ns != NO_EXPIRY && (self.policy == 0 || self.close_time_ns == 0) {
            return Err(out_of_range("earliest_expiry_ns"));
        }
        Ok(())
    }
}

/// The last answer to a [`RetentionState`], template 106, version 2
/// (ADR-0101).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = RETENTION_SUMMARY)]
pub struct RetentionSummary {
    /// The query's.
    #[field(offset = 0)]
    pub correlation_id: u64,
    /// The descriptors sent before it.
    #[field(offset = 8)]
    pub count: u64,
    /// The `--archive-min-free` floor; 0 for none.
    #[field(offset = 16)]
    pub min_free_bytes: u64,
    /// The archive file system's free bytes; [`FREE_UNKNOWN`] when not
    /// known.
    #[field(offset = 24)]
    pub free_bytes: u64,
}

/// Any message of schema 1, version 1 and version 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlMessage<'a> {
    /// Template 1.
    StartRecording(StartRecording<'a>),
    /// Template 2.
    StopRecording(StopRecording),
    /// Template 3.
    ListRecordings(ListRecordings),
    /// Template 4.
    Replay(Replay<'a>),
    /// Template 5.
    StopReplay(StopReplay),
    /// Template 6.
    HoldRecording(HoldRecording),
    /// Template 7.
    ReleaseHold(ReleaseHold),
    /// Template 8.
    PurgeRecording(PurgeRecording),
    /// Template 9.
    VerifyRecording(VerifyRecording),
    /// Template 101.
    ControlResponse(ControlResponse<'a>),
    /// Template 102.
    RecordingDescriptor(RecordingDescriptor<'a>),
    /// Template 103.
    RecordingSignal(RecordingSignal),
    /// Template 104.
    RangeOutcome(RangeOutcome),
    /// Template 10, version 2.
    RetentionState(RetentionState<'a>),
    /// Template 105, version 2.
    RetentionDescriptor(RetentionDescriptor),
    /// Template 106, version 2.
    RetentionSummary(RetentionSummary),
}

impl<'a> ControlMessage<'a> {
    /// Decodes exactly one message from `buf`, validated whole.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any tuple but schema 1 with a
    /// listed template of its version (version 2 has only templates 10,
    /// 105 and 106; ADR-0101), and every other [`CodecError`] the message's
    /// fields can raise.
    pub fn decode(buf: &'a [u8]) -> Result<Self, CodecError> {
        let envelope = Envelope::read(buf)?;
        let unsupported = CodecError::UnsupportedSchema {
            schema: envelope.schema_id,
            template: envelope.template_id,
            version: envelope.version,
        };
        if envelope.schema_id != SCHEMA_ID {
            return Err(unsupported);
        }
        // A decoder supports (schema, template, version) tuples, not a
        // version per schema (ADR-0101, decision 2).
        if envelope.version == VERSION_2 {
            return Ok(match envelope.template_id {
                10 => {
                    let (block, decoder) = Decoder::new(buf, &RETENTION_STATE)?;
                    Self::RetentionState(RetentionState::decode(block, decoder)?)
                }
                105 => {
                    let (block, decoder) = Decoder::new(buf, &RETENTION_DESCRIPTOR)?;
                    Self::RetentionDescriptor(RetentionDescriptor::decode(block, decoder)?)
                }
                106 => {
                    let (block, decoder) = Decoder::new(buf, &RETENTION_SUMMARY)?;
                    Self::RetentionSummary(RetentionSummary::decode(block, decoder)?)
                }
                _ => return Err(unsupported),
            });
        }
        if envelope.version != VERSION {
            return Err(unsupported);
        }
        Ok(match envelope.template_id {
            1 => {
                let (block, decoder) = Decoder::new(buf, &START_RECORDING)?;
                Self::StartRecording(StartRecording::decode(block, decoder)?)
            }
            2 => {
                let (block, decoder) = Decoder::new(buf, &STOP_RECORDING)?;
                Self::StopRecording(StopRecording::decode(block, decoder)?)
            }
            3 => {
                let (block, decoder) = Decoder::new(buf, &LIST_RECORDINGS)?;
                Self::ListRecordings(ListRecordings::decode(block, decoder)?)
            }
            4 => {
                let (block, decoder) = Decoder::new(buf, &REPLAY)?;
                Self::Replay(Replay::decode(block, decoder)?)
            }
            5 => {
                let (block, decoder) = Decoder::new(buf, &STOP_REPLAY)?;
                Self::StopReplay(StopReplay::decode(block, decoder)?)
            }
            6 => {
                let (block, decoder) = Decoder::new(buf, &HOLD_RECORDING)?;
                Self::HoldRecording(RecordingRequest::decode(block, decoder)?)
            }
            7 => {
                let (block, decoder) = Decoder::new(buf, &RELEASE_HOLD)?;
                Self::ReleaseHold(RecordingRequest::decode(block, decoder)?)
            }
            8 => {
                let (block, decoder) = Decoder::new(buf, &PURGE_RECORDING)?;
                Self::PurgeRecording(PurgeRecording::decode(block, decoder)?)
            }
            9 => {
                let (block, decoder) = Decoder::new(buf, &VERIFY_RECORDING)?;
                Self::VerifyRecording(RecordingRequest::decode(block, decoder)?)
            }
            104 => {
                let (block, decoder) = Decoder::new(buf, &RANGE_OUTCOME)?;
                Self::RangeOutcome(RangeOutcome::decode(block, decoder)?)
            }
            101 => {
                let (block, decoder) = Decoder::new(buf, &CONTROL_RESPONSE)?;
                Self::ControlResponse(ControlResponse::decode(block, decoder)?)
            }
            102 => {
                let (block, decoder) = Decoder::new(buf, &RECORDING_DESCRIPTOR)?;
                Self::RecordingDescriptor(RecordingDescriptor::decode(block, decoder)?)
            }
            103 => {
                let (block, decoder) = Decoder::new(buf, &RECORDING_SIGNAL)?;
                Self::RecordingSignal(RecordingSignal::decode(block, decoder)?)
            }
            _ => return Err(unsupported),
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// The message's own encoding errors.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        match self {
            Self::StartRecording(message) => message.encode(out),
            Self::StopRecording(message) => message.encode(out),
            Self::ListRecordings(message) => message.encode(out),
            Self::Replay(message) => message.encode(out),
            Self::StopReplay(message) => message.encode(out),
            Self::ControlResponse(message) => message.encode(out),
            Self::RecordingDescriptor(message) => message.encode(out),
            Self::RecordingSignal(message) => message.encode(out),
            Self::HoldRecording(message) => message.encode(out, &HOLD_RECORDING),
            Self::ReleaseHold(message) => message.encode(out, &RELEASE_HOLD),
            Self::PurgeRecording(message) => message.encode(out),
            Self::VerifyRecording(message) => message.encode(out, &VERIFY_RECORDING),
            Self::RangeOutcome(message) => message.encode(out),
            Self::RetentionState(message) => message.encode(out),
            Self::RetentionDescriptor(message) => message.encode(out),
            Self::RetentionSummary(message) => message.encode(out),
        }
    }
}
