// SPDX-License-Identifier: Apache-2.0

//! A recording group's journal records, schema 3 version 2, derived with
//! `karyos-codec-derive` on the `karyos-codec` runtime (karyos#1104) (`quantstratum-docs:
//! karyos/design/recording-group-records.md`, phase 3 batch A7a; SPEC
//! §8.3, ADR-0024).
//!
//! A journal opens with a [`JournalHeader`]. Each event is one event
//! record ([`MessageEvent`], [`ConflatedEvent`], [`TimerEvent`],
//! [`LifecycleEvent`], [`ExternalEvent`], [`LossEvent`]), then the
//! handler's observations in order ([`OutcomeObservation`],
//! [`TimerObservation`], [`ExternalObservation`]), then its [`EventEnd`].
//! A best-effort group marks the events it could not capture with a
//! [`GapMarker`], and a reference its recording will never cover with a
//! [`ReferenceUnavailable`] (A7d, `recording-group-gateway.md` section
//! 10). A [`CheckpointRecord`] names a snapshot of the application's state
//! in the group's checkpoint store (A9, `recording-group-checkpoints.md`
//! section 4). As in A1, each record is a plain value whose variable field
//! borrows the decoded input; [`GroupRecord::decode`] validates a whole
//! record before any value exists, and `encode` writes into the caller's
//! buffer. Nothing allocates.
//!
//! Version 2 (ADR-0089, karyos#672) adds `image`, the registration of the
//! network image a source's event came from (0 for none), at the end of the
//! message, lifecycle and loss events' blocks. Version 1 records are still
//! read, as `image` 0; every record is written at version 2.

use karyos_codec::{Block, CodecError, Decoder, Encoder, Envelope, Template};
use karyos_codec_derive::Message;
use karyos_sys::frame::{FRAME_ALIGNMENT, Lane};
use karyos_sys::local_gap::GapReason as LocalGapReason;
use karyos_sys::log_buffer::SkipReason;

#[cfg(test)]
mod tests;

/// The recording group schema's id: schema 1 is the Archive's control
/// schema, and 2 is reserved for Cluster.
pub const SCHEMA_ID: u16 = 3;
/// The version of schema 3 this build writes (ADR-0089).
pub const VERSION: u16 = 2;
/// The version before image identity, still read: its records decode with
/// `image` 0.
pub const VERSION_1: u16 = 1;
/// The only capture contract version.
pub const CONTRACT_VERSION: u16 = 1;
/// The largest inline value: the largest variable field.
pub const MAX_INLINE: usize = 65_535;
/// The longest manifest, in bytes.
pub const MAX_MANIFEST: usize = 4096;
/// The largest reopen hold a journal header records, in events (A9).
pub const MAX_REOPEN_HOLD: u32 = 1 << 16;
/// The default inline threshold, in bytes.
pub const DEFAULT_INLINE_THRESHOLD: u32 = 4096;

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
/// `JournalHeader`, template 1.
pub const JOURNAL_HEADER: Template = template(1, 32, 12 + 32 + 2 + 4096);
/// `MessageEvent`, template 2.
pub const MESSAGE_EVENT: Template = template(2, 75, 12 + 75 + 2 + 65_535 + 2 + 64);
/// `ConflatedEvent`, template 3.
pub const CONFLATED_EVENT: Template = template(3, 45, 12 + 45 + 2 + 65_535);
/// `TimerEvent`, template 4.
pub const TIMER_EVENT: Template = template(4, 24, 12 + 24);
/// `LifecycleEvent`, template 5.
pub const LIFECYCLE_EVENT: Template = template(5, 51, 12 + 51);
/// `ExternalEvent`, template 6.
pub const EXTERNAL_EVENT: Template = template(6, 20, 12 + 20 + 2 + 65_535);
/// `LossEvent`, template 7.
pub const LOSS_EVENT: Template = template(7, 68, 12 + 68);
/// `OutcomeObservation`, template 11.
pub const OUTCOME_OBSERVATION: Template = template(11, 59, 12 + 59);
/// `TimerObservation`, template 12.
pub const TIMER_OBSERVATION: Template = template(12, 29, 12 + 29);
/// `DeliveryPoll`, template 15.
pub const DELIVERY_POLL: Template = template(15, 28, 12 + 28);
/// `DeliveryObservation`, template 14.
pub const DELIVERY_OBSERVATION: Template = template(14, 72, 12 + 72);
/// `ExternalObservation`, template 13.
pub const EXTERNAL_OBSERVATION: Template = template(13, 16, 12 + 16 + 2 + 65_535);
/// `EventEnd`, template 20.
pub const EVENT_END: Template = template(20, 13, 12 + 13);
/// `GapMarker`, template 21.
pub const GAP_MARKER: Template = template(21, 17, 12 + 17);
/// `ReferenceUnavailable`, template 22.
pub const REFERENCE_UNAVAILABLE: Template = template(22, 16, 12 + 16);
/// `Checkpoint`, template 30.
pub const CHECKPOINT: Template = template(30, 40, 12 + 40);

/// `template` as version 1 wrote it: the same, but for the three event
/// blocks without `image` (8 bytes shorter) and the envelope's version.
const fn version_1(template: &Template) -> Template {
    let shorter = matches!(template.template_id, 2 | 5 | 7);
    let (block_length, max_length) = if shorter {
        (template.block_length - 8, template.max_length - 8)
    } else {
        (template.block_length, template.max_length)
    };
    Template {
        schema_id: SCHEMA_ID,
        template_id: template.template_id,
        version: VERSION_1,
        block_length,
        max_length,
    }
}
/// A checkpoint record's `position` in a replay's capture: the replay's
/// digest only, its bytes stored nowhere (A9-2).
pub const CAPTURE_POSITION: u64 = u64::MAX;

/// The longest record of any template.
pub const MAX_RECORD: usize = 12 + 75 + 2 + 65_535 + 2 + 64;

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

/// A lane byte, below [`Lane::COUNT`].
fn lane(value: u8) -> Result<Lane, CodecError> {
    Lane::try_new(value).map_err(|_| out_of_range("lane"))
}

/// The clock whose readings a journal's logical times are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Clock {
    /// The host's monotonic clock in nanoseconds, read once when an event
    /// is dispatched; a timer event's time is its deadline.
    HostMonotonic,
}

/// What a group does with an event it cannot capture whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Capture {
    /// Stop admitting events: the loop stops with an incomplete capture.
    Strict,
    /// Go on, marking the uncaptured events with a [`GapMarker`].
    BestEffort,
}

/// The first record of a journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = JOURNAL_HEADER, zero = [(28, 4)])]
pub struct JournalHeader<'a> {
    /// The group, never 0.
    #[field(offset = 0, check = id)]
    pub group_id: u64,
    /// The first event's `group_seq`, never 0.
    #[field(offset = 8, check = id)]
    pub first_group_seq: u64,
    /// The payload size above which a recorded source's payload is stored
    /// by reference: 1 to [`MAX_INLINE`].
    #[field(offset = 16, check = inline_threshold)]
    pub inline_threshold: u32,
    /// The capture contract: [`CONTRACT_VERSION`].
    #[field(offset = 20, check = contract_version)]
    pub contract_version: u16,
    /// The clock of the logical times.
    #[field(with = clock_byte, offset = 22, width = 1)]
    pub clock: Clock,
    /// Strict or best effort.
    #[field(with = capture_byte, offset = 23, width = 1)]
    pub capture: Capture,
    /// The events the reopening window holds (A9): fixed when the group
    /// is made, at most [`MAX_REOPEN_HOLD`]; 0 for a group without
    /// checkpoints. Recovery and the running tracker both take it.
    #[field(offset = 24, check = reopen_hold)]
    pub reopen_hold: u32,
    /// The caller's identity of what ran, opaque: 1 to [`MAX_MANIFEST`]
    /// bytes.
    #[field(var, min = 1, max = MAX_MANIFEST)]
    pub manifest: &'a [u8],
}

/// A journal header this build cannot take, as its bytes name it: not a
/// corrupt record, a journal of another contract or clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedHeader {
    /// Another capture contract.
    Contract {
        /// The header's.
        found: u16,
    },
    /// A clock this build does not know.
    Clock {
        /// The header's code.
        found: u8,
    },
}

/// What a journal header's bytes, `buf`, name that this build cannot take:
/// `None` for anything else, a valid header or a record that is not one.
#[must_use]
pub fn unsupported_header(buf: &[u8]) -> Option<UnsupportedHeader> {
    let envelope = Envelope::read(buf).ok()?;
    if envelope.schema_id != SCHEMA_ID
        || envelope.version != VERSION
        || envelope.template_id != JOURNAL_HEADER.template_id
    {
        return None;
    }
    let block = |at: usize| buf.get(at.checked_add(12)?).copied();
    let contract = u16::from_le_bytes([block(20)?, block(21)?]);
    if contract != CONTRACT_VERSION {
        return Some(UnsupportedHeader::Contract { found: contract });
    }
    match block(22)? {
        1 => None,
        found => Some(UnsupportedHeader::Clock { found }),
    }
}

/// Where a message's payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Payload<'a> {
    /// The payload itself, 0 to [`MAX_INLINE`] bytes.
    Inline(&'a [u8]),
    /// The frames of a recording this Archive keeps: those of
    /// `[position, position + extent)` in `recording_id`. Once the range
    /// holding them is sealed, their integrity rests on that seal
    /// ([`crate::integrity::verify_range`]); until then only on the
    /// segment entry's CRC-32C, which is corruption detection (karyos#662).
    Reference {
        /// The recording, never 0.
        recording_id: u64,
        /// The payload's length.
        length: u32,
    },
    /// Not captured: a payload above [`MAX_INLINE`] of a source this
    /// Archive does not record as `required`. Its length, with the event's
    /// position and extent, lets replay report it.
    Unavailable {
        /// The payload's length, above [`MAX_INLINE`].
        length: u32,
    },
}

/// An unavailable payload's length: above [`MAX_INLINE`].
fn unavailable(length: u32) -> Result<u32, CodecError> {
    if usize::try_from(length).is_ok_and(|length| length > MAX_INLINE) {
        Ok(length)
    } else {
        Err(out_of_range("length"))
    }
}

/// A message delivered from a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = MESSAGE_EVENT, versioned, check = Self::check)]
pub struct MessageEvent<'a> {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// When it was dispatched, on the journal's clock.
    #[field(offset = 8)]
    pub logical_time: u64,
    /// The publication incarnation.
    #[field(offset = 16)]
    pub incarnation: u64,
    /// The stream position of the message's first frame.
    #[field(offset = 24)]
    pub position: u64,
    /// The frames' extent from `position`: a multiple of 32 that covers
    /// the payload and at least one frame header.
    #[field(offset = 52)]
    pub extent: u32,
    /// The stream.
    #[field(offset = 56)]
    pub stream_id: i32,
    /// The session.
    #[field(offset = 60)]
    pub session_id: i32,
    /// The lane.
    #[field(with = lane_byte, offset = 64, width = 1)]
    pub lane: Lane,
    /// The reserved value of the message's first fragment, which the
    /// publisher set.
    #[field(with = signed, offset = 40, width = 8)]
    pub reserved_value: i64,
    /// The message ended its stream.
    #[field(with = message_flags, spans = [(66, 1)])]
    pub end_of_stream: bool,
    /// The payload.
    #[field(with = payload, spans = [(32, 8), (48, 4), (65, 1)], var)]
    pub payload: Payload<'a>,
    /// The opaque trace extension the message carried, if any: an input,
    /// which A8's comparison schema may name as excludable.
    #[field(with = extension, var)]
    pub extension: Option<&'a [u8; EXTENSION]>,
    /// The registration of the network image the message came from, 0 for
    /// none (ADR-0089).
    #[field(offset = 67, since = 2)]
    pub image: u64,
}

/// A trace extension's length: `karyos_sys::frame::EXTENSION_LENGTH`.
pub const EXTENSION: usize = 64;
const _: () = assert!(
    karyos_sys::frame::EXTENSION_LENGTH == 64,
    "EXTENSION is the frame's extension length"
);
/// The end-of-stream flag of a message event.
const FLAG_END_OF_STREAM: u8 = 1;
/// The trace-extension flag of a message event.
const FLAG_EXTENSION: u8 = 2;

/// The frames' extent: a multiple of the frame alignment that holds the
/// payload after one frame header, at least.
fn extent(extent: u32, length: u32) -> Result<u32, CodecError> {
    let least = length
        .checked_add(FRAME_ALIGNMENT)
        .and_then(|least| least.checked_next_multiple_of(FRAME_ALIGNMENT));
    if !extent.is_multiple_of(FRAME_ALIGNMENT) || least.is_none_or(|least| extent < least) {
        Err(out_of_range("extent"))
    } else {
        Ok(extent)
    }
}

/// Whether a conflated value was covered by a committed gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Freshness {
    /// No committed gap covered it.
    Fresh,
    /// A committed gap covered it, from `since`.
    Stale {
        /// The gap's start.
        since: u64,
    },
}

/// A conflated value as the handler saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = CONFLATED_EVENT)]
pub struct ConflatedEvent<'a> {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// When it was dispatched.
    #[field(offset = 8)]
    pub logical_time: u64,
    /// The value's version.
    #[field(offset = 16)]
    pub version: u64,
    /// The value's key.
    #[field(offset = 32)]
    pub key: u32,
    /// The stream.
    #[field(offset = 36)]
    pub stream_id: i32,
    /// The session.
    #[field(offset = 40)]
    pub session_id: i32,
    /// Fresh or stale.
    #[field(with = freshness, spans = [(24, 8), (44, 1)])]
    pub freshness: Freshness,
    /// The value, 0 to [`MAX_INLINE`] bytes.
    #[field(var, min = 0, max = MAX_INLINE)]
    pub value: &'a [u8],
}

/// A timer that fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = TIMER_EVENT)]
pub struct TimerEvent {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// The timer's deadline.
    #[field(offset = 8)]
    pub logical_time: u64,
    /// The timer, never 0.
    #[field(offset = 16, check = id)]
    pub timer_id: u64,
}

/// Why a subscription ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndReason {
    /// Its stream ended (end of stream).
    EndOfStream,
    /// It was closed because it was overrun.
    Overrun,
    /// It was revoked.
    Revoked,
    /// Any other close.
    Closed,
}

/// What a lifecycle event announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleKind {
    /// An image became available.
    ImageAvailable,
    /// An image went away.
    ImageUnavailable,
    /// A subscription ended.
    SubscriptionEnded(EndReason),
}

/// An image's availability or a subscription's end, delivered to the
/// handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = LIFECYCLE_EVENT, versioned)]
pub struct LifecycleEvent {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// When it was dispatched.
    #[field(offset = 8)]
    pub logical_time: u64,
    /// The publication incarnation.
    #[field(offset = 16)]
    pub incarnation: u64,
    /// The position on `lane` the event names (where the stream ended), or
    /// 0 when it names none: image events carry no position.
    #[field(offset = 24)]
    pub position: u64,
    /// The stream.
    #[field(offset = 32)]
    pub stream_id: i32,
    /// The session.
    #[field(offset = 36)]
    pub session_id: i32,
    /// The lane `position` is on.
    #[field(with = lane_byte, offset = 41, width = 1)]
    pub lane: Lane,
    /// What happened.
    #[field(with = lifecycle_kind, spans = [(40, 1), (42, 1)])]
    pub kind: LifecycleKind,
    /// The registration of the network image the event names, 0 for none
    /// (ADR-0089).
    #[field(offset = 43, since = 2)]
    pub image: u64,
}

/// How a rejoin policy resolved an overrun, as the handler was told: the
/// loss report's applied outcomes, and `replaying` for a
/// `ReplayRejoin` still recovering the gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OverrunOutcome {
    /// Delivery went on at `resume`.
    ResumedAtHead,
    /// A snapshot rebuilt the state up to `resume`.
    SnapshotRebuilt,
    /// The snapshot failed, and the subscription closed.
    SnapshotFailed,
    /// The subscription closed.
    Closed,
    /// The gap was replayed from a recording and merged at `resume`.
    Replayed,
    /// The gap is being recovered from a recording.
    Replaying,
}

/// Why `replay` fell back to its secondary policy: the loss report's
/// reason codes, 1 to 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FallbackReason {
    /// No Archive.
    NoArchive,
    /// No recording covers the gap.
    NoRecording,
    /// The recording's retention does not reach the gap.
    RetentionShort,
    /// The recording had not reached the gap's end in time.
    RecordingBehind,
    /// The Archive refused the replay.
    Refused,
    /// The replay and the live stream did not merge.
    MergeFailed,
    /// The gap was given up before it resolved.
    Withdrawn,
}

/// What a source reported instead of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Loss {
    /// The reader was overrun, and its rejoin policy did `outcome`; a
    /// `replay` that fell back names its reason.
    Overrun {
        /// What the policy did.
        outcome: OverrunOutcome,
        /// Why `replay` fell back, if it did: only with an outcome of the
        /// secondary policy (resumed, rebuilt, failed or closed).
        fallback: Option<FallbackReason>,
    },
    /// A range was skipped.
    Skipped(SkipReason),
    /// An aborted block.
    Aborted,
}

/// A loss on a message source, delivered to the handler as an event of
/// its own (`recording-group-gateway.md` sections 5 and 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = LOSS_EVENT, versioned, check = Self::positions)]
pub struct LossEvent {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// When it was dispatched.
    #[field(offset = 8)]
    pub logical_time: u64,
    /// The publication incarnation.
    #[field(offset = 16)]
    pub incarnation: u64,
    /// An overrun's first position not delivered; a skip's or an abort's
    /// position.
    #[field(offset = 24)]
    pub from: u64,
    /// An overrun's end known lost; a skip's or an abort's end.
    #[field(offset = 32)]
    pub lost_to: u64,
    /// Where delivery resumed; for a skip or an abort, its end. A replayed
    /// overrun's cutover.
    #[field(offset = 40)]
    pub resume: u64,
    /// The stream.
    #[field(offset = 48)]
    pub stream_id: i32,
    /// The session.
    #[field(offset = 52)]
    pub session_id: i32,
    /// The lane.
    #[field(with = lane_byte, offset = 56, width = 1)]
    pub lane: Lane,
    /// What was lost, and how it resolved.
    #[field(with = loss, spans = [(57, 1), (58, 1), (59, 1)])]
    pub loss: Loss,
    /// The registration of the network image the loss was on, 0 for none
    /// (ADR-0089).
    #[field(offset = 60, since = 2)]
    pub image: u64,
}

impl OverrunOutcome {
    const fn code(self) -> u8 {
        match self {
            Self::ResumedAtHead => 1,
            Self::SnapshotRebuilt => 2,
            Self::SnapshotFailed => 3,
            Self::Closed => 4,
            Self::Replayed => 5,
            Self::Replaying => 6,
        }
    }

    fn from_code(code: u8) -> Result<Self, CodecError> {
        Ok(match code {
            1 => Self::ResumedAtHead,
            2 => Self::SnapshotRebuilt,
            3 => Self::SnapshotFailed,
            4 => Self::Closed,
            5 => Self::Replayed,
            6 => Self::Replaying,
            value => return Err(invalid_enum("outcome", value)),
        })
    }

    /// Whether the secondary policy did it, so a fallback may name why.
    const fn is_secondary(self) -> bool {
        matches!(
            self,
            Self::ResumedAtHead | Self::SnapshotRebuilt | Self::SnapshotFailed | Self::Closed
        )
    }
}

impl FallbackReason {
    const fn code(self) -> u8 {
        match self {
            Self::NoArchive => 1,
            Self::NoRecording => 2,
            Self::RetentionShort => 3,
            Self::RecordingBehind => 4,
            Self::Refused => 5,
            Self::MergeFailed => 6,
            Self::Withdrawn => 7,
        }
    }

    fn from_code(code: u8) -> Result<Option<Self>, CodecError> {
        Ok(Some(match code {
            0 => return Ok(None),
            1 => Self::NoArchive,
            2 => Self::NoRecording,
            3 => Self::RetentionShort,
            4 => Self::RecordingBehind,
            5 => Self::Refused,
            6 => Self::MergeFailed,
            7 => Self::Withdrawn,
            value => return Err(invalid_enum("reason", value)),
        }))
    }
}

/// A skip's reason code: 1 to 6 for the reasons in their declaration
/// order, then 7 and 8 for a local gap whose reason is 1 or 2.
const fn skip_code(reason: SkipReason) -> u8 {
    match reason {
        SkipReason::MessageTooLarge => 1,
        SkipReason::MissingEnd => 2,
        SkipReason::Interrupted => 3,
        SkipReason::Orphan => 4,
        SkipReason::JoinedMidMessage => 5,
        SkipReason::AfterLoss => 6,
        SkipReason::LocalGap(LocalGapReason::ReorderExpired) => 7,
        SkipReason::LocalGap(LocalGapReason::RangeUnavailable) => 8,
    }
}

fn skip_reason(code: u8) -> Result<SkipReason, CodecError> {
    Ok(match code {
        1 => SkipReason::MessageTooLarge,
        2 => SkipReason::MissingEnd,
        3 => SkipReason::Interrupted,
        4 => SkipReason::Orphan,
        5 => SkipReason::JoinedMidMessage,
        6 => SkipReason::AfterLoss,
        7 => SkipReason::LocalGap(LocalGapReason::ReorderExpired),
        8 => SkipReason::LocalGap(LocalGapReason::RangeUnavailable),
        value => return Err(invalid_enum("reason", value)),
    })
}

impl LossEvent {
    /// The positions' rule: `from <= lost_to <= resume`, and a skip's or an
    /// abort's `lost_to` is its `resume`.
    fn positions(&self) -> Result<(), CodecError> {
        if self.from > self.lost_to {
            return Err(out_of_range("lost_to"));
        }
        let ranged = matches!(self.loss, Loss::Skipped(_) | Loss::Aborted);
        if self.lost_to > self.resume || (ranged && self.lost_to != self.resume) {
            return Err(out_of_range("resume"));
        }
        Ok(())
    }
}

/// An input from outside Karyos, delivered as an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = EXTERNAL_EVENT)]
pub struct ExternalEvent<'a> {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// When it was dispatched.
    #[field(offset = 8)]
    pub logical_time: u64,
    /// The application's own code.
    #[field(offset = 16)]
    pub kind: u32,
    /// The input, 0 to [`MAX_INLINE`] bytes.
    #[field(var, min = 0, max = MAX_INLINE)]
    pub value: &'a [u8],
}

/// The call whose outcome was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    /// An offer.
    Offer,
    /// A claim.
    Claim,
    /// A claim's commit: accepted, or lost to an abort.
    Commit,
}

/// The highest `ClientError` code (section 5.1 of the note): codes 1 to
/// it name the client's errors in a stable order.
pub const MAX_ERROR_CODE: u16 = 21;

/// Per `ClientError` code, the highest `sub` it takes: the count of its
/// inner error's variants (or of the driver's refusal codes), 0 for a
/// variant with no inner one (section 5.1 of the note).
const MAX_SUB: [u16; 22] = [
    0, 0, 0, 0, 0, 7, 0, 4, 0, 0, 0, 26, 0, 0, 6, 11, 0, 0, 16, 0, 6, 0,
];

/// Per `ClientError` code with no inner error, its numeric fields, and
/// per inner error, its variants' numeric fields from `sub` 1 (section 5.1
/// of the note); an `Option<u64>` counts as two (its value and its flag).
const FLAT_FIELDS: [u8; 22] = [
    0, 2, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0,
];
const CONFLATION_FIELDS: [u8; 7] = [0, 1, 2, 0, 0, 0, 2];
const OUTCOMES_FIELDS: [u8; 4] = [0, 1, 1, 0];
const SYS_FIELDS: [u8; 26] = [
    1, 1, 1, 1, 1, 1, 2, 1, 2, 2, 2, 2, 1, 0, 2, 0, 0, 0, 1, 0, 0, 1, 0, 2, 1, 2,
];
const ATTACH_FIELDS: [u8; 6] = [1, 2, 0, 0, 0, 0];
const CONDUCTOR_FIELDS: [u8; 11] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];
const VIEW_FIELDS: [u8; 6] = [1, 1, 1, 2, 1, 2];

/// The numeric fields a failure of `error` and `sub` (already checked)
/// carries, and whether the second is an `Option` flag.
fn fields_of(error: u16, sub: u16) -> (u8, bool) {
    let inner = |table: &[u8]| {
        usize::from(sub)
            .checked_sub(1)
            .and_then(|at| table.get(at).copied())
            .unwrap_or_default()
    };
    match error {
        5 => (inner(&CONFLATION_FIELDS), false),
        7 => (inner(&OUTCOMES_FIELDS), false),
        11 => (inner(&SYS_FIELDS), false),
        14 => (inner(&ATTACH_FIELDS), sub == 2),
        15 => (inner(&CONDUCTOR_FIELDS), false),
        20 => (inner(&VIEW_FIELDS), sub == 4),
        _ => (
            FLAT_FIELDS
                .get(usize::from(error))
                .copied()
                .unwrap_or_default(),
            false,
        ),
    }
}

/// Whether a failure's details fit its variant: a field it does not have
/// is 0, and an `Option`'s flag is 0 or 1, with its value 0 when absent.
fn details_fit(error: u16, sub: u16, detail: u64, detail2: u64) -> bool {
    match fields_of(error, sub) {
        (0, _) => detail == 0 && detail2 == 0,
        (1, _) => detail2 == 0,
        (_, true) => detail2 == 1 || (detail2 == 0 && detail == 0),
        _ => true,
    }
}

/// Whether `sub` names a variant of `error`'s inner error: 1 to its count
/// when it has one, else 0.
fn sub_of(error: u16, sub: u16) -> bool {
    MAX_SUB.get(usize::from(error)).is_some_and(|&max| {
        if max == 0 {
            sub == 0
        } else {
            (1..=max).contains(&sub)
        }
    })
}

/// An operation's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// An offer accepted, a claim reserved, or a commit accepted, at
    /// `position` in `lane`.
    Accepted {
        /// The lane.
        lane: Lane,
        /// The position.
        position: u64,
    },
    /// Flow control did not admit it.
    BackPressured,
    /// It only padded or rotated, or waits for the driver.
    AdminAction,
    /// No subscriber and unconnected offers not allowed.
    NotConnected,
    /// The stream is sealed.
    Closed,
    /// The guard closed or a deadline was missed.
    Gated,
    /// The rate limit held no token.
    RateLimited,
    /// A claim consumed and aborted, or a commit that lost to an abort, at
    /// `position` in `lane`.
    Aborted {
        /// The lane.
        lane: Lane,
        /// The position.
        position: u64,
    },
    /// The call returned an error, as section 5.1 of the note maps it: its
    /// `ClientError` code, 1 to [`MAX_ERROR_CODE`]; `sub`, its inner
    /// error's variant (or the driver's refusal code), else 0; and its
    /// first two numeric fields, else 0.
    Failed {
        /// The error's code.
        error: u16,
        /// Its inner variant.
        sub: u16,
        /// Its first numeric field.
        detail: u64,
        /// Its second numeric field.
        detail2: u64,
    },
}

/// An operation's outcome, as the handler observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = OUTCOME_OBSERVATION, check = Self::check)]
pub struct OutcomeObservation {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// The observation's index within the event, from 0.
    #[field(offset = 32)]
    pub index: u32,
    /// The stream.
    #[field(offset = 36)]
    pub stream_id: i32,
    /// The session.
    #[field(offset = 40)]
    pub session_id: i32,
    /// Offer, claim or commit.
    #[field(with = operation_byte, offset = 48, width = 1)]
    pub operation: Operation,
    /// What it returned.
    #[field(with = outcome, spans = [(8, 8), (16, 8), (24, 8), (44, 2), (46, 2), (49, 1), (50, 1)])]
    pub outcome: Outcome,
    /// An offer's payload length, or a commit's claimed bytes' length,
    /// whatever the outcome; 0 for a claim.
    #[field(offset = 51)]
    pub length: u32,
    /// The CRC-32C of those bytes; 0 for a claim.
    #[field(offset = 55)]
    pub crc32c: u32,
}

/// Whether `operation` can return `outcome`'s code.
const fn returns(operation: Operation, outcome: u8) -> bool {
    match operation {
        Operation::Offer => matches!(outcome, 1..=7 | 9),
        Operation::Claim => matches!(outcome, 1..=9),
        Operation::Commit => matches!(outcome, 1 | 8),
    }
}

/// A `poll_outcomes` call on a guarded publication: it precedes the
/// `count` delivery observations the call presented, so replay can tell
/// the calls apart, an empty one included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = DELIVERY_POLL, check = Self::check)]
pub struct DeliveryPoll {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// The observation's index within the event, from 0.
    #[field(offset = 8)]
    pub index: u32,
    /// The call's maximum.
    #[field(offset = 12)]
    pub max: u32,
    /// The records it presented, at most `max`.
    #[field(offset = 16)]
    pub count: u32,
    /// The stream.
    #[field(offset = 20)]
    pub stream_id: i32,
    /// The session.
    #[field(offset = 24)]
    pub session_id: i32,
}

/// A guarded publication's delivery outcome, as the outcome ring
/// presented it to the handler (SPEC §8.3, asynchronous delivery
/// outcomes): its kind is the ring's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = DELIVERY_OBSERVATION, check = Self::check)]
pub struct DeliveryObservation {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// The observation's index within the event, from 0.
    #[field(offset = 56)]
    pub index: u32,
    /// The stream.
    #[field(offset = 60)]
    pub stream_id: i32,
    /// The session.
    #[field(offset = 64)]
    pub session_id: i32,
    /// The ring's kind code: 1 submitted, 2 confirmed cancelled, 3
    /// unknown, 4 rejected, 5 aborted, 16 range, 17 interrupted, 18 ended,
    /// 19 outcomes lost.
    #[field(with = delivery_kind, offset = 70, width = 1)]
    pub kind: u8,
    /// The lane.
    #[field(with = lane_byte, offset = 71, width = 1)]
    pub lane: Lane,
    /// The receiver index, for range kinds; else 0.
    #[field(offset = 68)]
    pub receiver: u16,
    /// The incarnation.
    #[field(offset = 8)]
    pub incarnation: u64,
    /// The message's start, or a receiver's delivered prefix.
    #[field(offset = 16)]
    pub start: u64,
    /// The message's end, or the unresolved range's end.
    #[field(offset = 24)]
    pub end: u64,
    /// The guard epoch at the decision.
    #[field(offset = 32)]
    pub epoch: u64,
    /// The reason, for the kinds that carry one.
    #[field(offset = 40)]
    pub reason: u64,
    /// The lost count, for outcomes lost.
    #[field(offset = 48)]
    pub lost: u64,
}

/// The outcome ring's kind codes.
const DELIVERY_KINDS: [u8; 9] = [1, 2, 3, 4, 5, 16, 17, 18, 19];
/// The ring's outcomes-lost kind.
const OUTCOMES_LOST: u8 = 19;

/// The ring's range-side kinds (`Kind::is_range`): range, interrupted,
/// ended and outcomes lost.
const fn range_side(kind: u8) -> bool {
    matches!(kind, 16..=19)
}

/// A timer created or cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimerAction {
    /// Created.
    Create,
    /// Cancelled.
    Cancel,
}

/// A timer operation, as the handler made it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = TIMER_OBSERVATION)]
pub struct TimerObservation {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// The observation's index within the event, from 0.
    #[field(offset = 24)]
    pub index: u32,
    /// The timer, never 0.
    #[field(offset = 8, check = id)]
    pub timer_id: u64,
    /// Its deadline; a cancel repeats it.
    #[field(offset = 16)]
    pub deadline: u64,
    /// Create or cancel.
    #[field(with = timer_action, offset = 28, width = 1)]
    pub action: TimerAction,
}

/// A response from outside Karyos the handler read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = EXTERNAL_OBSERVATION)]
pub struct ExternalObservation<'a> {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// The observation's index within the event, from 0.
    #[field(offset = 8)]
    pub index: u32,
    /// The application's own code.
    #[field(offset = 12)]
    pub kind: u32,
    /// The response, 0 to [`MAX_INLINE`] bytes.
    #[field(var, min = 0, max = MAX_INLINE)]
    pub value: &'a [u8],
}

/// Whether an event's capture is whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndOutcome {
    /// Every observation is recorded.
    Complete,
    /// The event exceeded its capture budget.
    Incomplete,
}

/// The end of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = EVENT_END)]
pub struct EventEnd {
    /// The event's sequence in its group, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// How many observations the event has.
    #[field(offset = 8)]
    pub observations: u32,
    /// Complete or incomplete.
    #[field(with = end_outcome, offset = 12, width = 1)]
    pub outcome: EndOutcome,
}

/// Why a best-effort group did not capture events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GapReason {
    /// An event exceeded its capture budget.
    BudgetExceeded,
    /// The ring to the Archive was full.
    RingFull,
    /// A payload above [`MAX_INLINE`] of a source this Archive does not
    /// record.
    PayloadUnavailable,
}

/// Events delivered and not captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = GAP_MARKER, check = Self::check)]
pub struct GapMarker {
    /// The first event not captured, never 0.
    #[field(offset = 0, check = id)]
    pub from_seq: u64,
    /// The last, at least `from_seq`.
    #[field(offset = 8)]
    pub to_seq: u64,
    /// Why.
    #[field(with = gap_reason, offset = 16, width = 1)]
    pub reason: GapReason,
}

/// A best-effort group's mark of an event whose payload is by reference to
/// a recording that stopped or failed before it covered the frames: the
/// payload will never be there, so the event counts complete with its
/// payload unavailable (`recording-group-gateway.md` section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = REFERENCE_UNAVAILABLE)]
pub struct ReferenceUnavailable {
    /// The event, already ended, never 0.
    #[field(offset = 0, check = id)]
    pub group_seq: u64,
    /// The recording its payload names, never 0.
    #[field(offset = 8, check = id)]
    pub recording_id: u64,
}

/// A checkpoint of the application's state after event `group_seq`,
/// stored at `position` in the group's checkpoint store (A9). It sits
/// outside events, as a gap marker does, and is appended once its bytes
/// are written, so events after `group_seq` may come before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
#[message(template = CHECKPOINT, check = Self::check)]
pub struct CheckpointRecord {
    /// The last event the state includes, never 0.
    #[field(offset = 0)]
    pub group_seq: u64,
    /// Never 0, increasing within the group.
    #[field(offset = 8)]
    pub checkpoint_id: u64,
    /// Where its range starts in the checkpoint store;
    /// [`CAPTURE_POSITION`] in a replay's capture, which stores nothing.
    #[field(offset = 16)]
    pub position: u64,
    /// The snapshot's bytes, at least 1.
    #[field(offset = 24)]
    pub length: u64,
    /// The CRC-32C of the snapshot's bytes.
    #[field(offset = 32)]
    pub crc32c: u32,
    /// The application's own tag for its snapshot format.
    #[field(offset = 36)]
    pub format: u32,
}

impl CheckpointRecord {
    /// The end of its range in the checkpoint store; `None` in a replay's
    /// capture.
    #[must_use]
    pub const fn end(&self) -> Option<u64> {
        if self.position == CAPTURE_POSITION {
            None
        } else {
            self.position.checked_add(self.length)
        }
    }

    fn check(&self) -> Result<(), CodecError> {
        id("group_seq", self.group_seq)?;
        id("checkpoint_id", self.checkpoint_id)?;
        if self.length == 0 {
            return Err(out_of_range("length"));
        }
        if self.position != CAPTURE_POSITION && self.end().is_none() {
            return Err(out_of_range("position"));
        }
        Ok(())
    }
}

// The derive's field modules and checks (karyos#1104): each reads and
// writes one field, or the fields that share its bytes, as the records'
// hand-written codecs did.

/// A lane byte, as a `with` field.
mod lane_byte {
    use super::{Block, CodecError, Encoder, Lane, lane};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<Lane, CodecError> {
        lane(block.u8(at)?)
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        value: &Lane,
    ) -> Result<(), CodecError> {
        encoder.u8(at, value.get())
    }
}

/// An `i64` stored as its two's complement `u64`, as a `with` field.
mod signed {
    use super::{Block, CodecError, Encoder};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<i64, CodecError> {
        Ok(block.u64(at)?.cast_signed())
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        value: &i64,
    ) -> Result<(), CodecError> {
        encoder.u64(at, value.cast_unsigned())
    }
}

/// The header's inline threshold: 1 to [`MAX_INLINE`].
fn inline_threshold(field: &'static str, value: u32) -> Result<u32, CodecError> {
    if value == 0 || usize::try_from(value).map_or(true, |value| value > MAX_INLINE) {
        Err(out_of_range(field))
    } else {
        Ok(value)
    }
}

/// The header's capture contract: [`CONTRACT_VERSION`].
fn contract_version(field: &'static str, value: u16) -> Result<u16, CodecError> {
    if value == CONTRACT_VERSION {
        Ok(value)
    } else {
        Err(out_of_range(field))
    }
}

/// The header's reopen hold: at most [`MAX_REOPEN_HOLD`].
fn reopen_hold(field: &'static str, value: u32) -> Result<u32, CodecError> {
    if value > MAX_REOPEN_HOLD {
        Err(out_of_range(field))
    } else {
        Ok(value)
    }
}

/// The header's [`Clock`], as a `with` field.
mod clock_byte {
    use super::{Block, Clock, CodecError, Encoder, invalid_enum};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<Clock, CodecError> {
        match block.u8(at)? {
            1 => Ok(Clock::HostMonotonic),
            value => Err(invalid_enum("clock", value)),
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        value: &Clock,
    ) -> Result<(), CodecError> {
        encoder.u8(
            at,
            match value {
                Clock::HostMonotonic => 1,
            },
        )
    }
}

/// The header's [`Capture`], as a `with` field.
mod capture_byte {
    use super::{Block, Capture, CodecError, Encoder, invalid_enum};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<Capture, CodecError> {
        match block.u8(at)? {
            1 => Ok(Capture::Strict),
            2 => Ok(Capture::BestEffort),
            value => Err(invalid_enum("capture", value)),
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        value: &Capture,
    ) -> Result<(), CodecError> {
        encoder.u8(
            at,
            match value {
                Capture::Strict => 1,
                Capture::BestEffort => 2,
            },
        )
    }
}

/// A message event's flags byte at 66, read as its known bits only.
fn flags(block: &Block<'_>) -> Result<u8, CodecError> {
    let flags = block.u8(66)?;
    if flags & !(FLAG_END_OF_STREAM | FLAG_EXTENSION) != 0 {
        Err(out_of_range("flags"))
    } else {
        Ok(flags)
    }
}

/// A message event's end-of-stream flag; it writes the whole flags byte,
/// the extension's bit included, which the two fields share.
mod message_flags {
    use super::{
        Block, CodecError, Encoder, FLAG_END_OF_STREAM, FLAG_EXTENSION, MessageEvent, flags,
    };

    pub(super) fn read(block: &Block<'_>) -> Result<bool, CodecError> {
        Ok(flags(block)? & FLAG_END_OF_STREAM != 0)
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &MessageEvent<'_>,
    ) -> Result<(), CodecError> {
        let mut flags = 0;
        if message.end_of_stream {
            flags |= FLAG_END_OF_STREAM;
        }
        if message.extension.is_some() {
            flags |= FLAG_EXTENSION;
        }
        encoder.u8(66, flags)
    }
}

/// A message event's payload: the recording at 32, the length at 48, the
/// kind at 65 and the inline value, the first variable field.
mod payload {
    use super::{
        Block, CodecError, Decoder, Encoder, MAX_INLINE, MessageEvent, Payload, id, invalid_enum,
        out_of_range, unavailable,
    };

    /// No value where the payload is not inline.
    fn no_value(value: &[u8]) -> Result<(), CodecError> {
        if value.is_empty() {
            Ok(())
        } else {
            Err(CodecError::LengthOutOfRange {
                field: "value",
                length: value.len(),
                min: 0,
                max: 0,
            })
        }
    }

    pub(super) fn read<'a>(
        block: &Block<'a>,
        decoder: &mut Decoder<'a>,
    ) -> Result<Payload<'a>, CodecError> {
        let recording_id = block.u64(32)?;
        let length = block.u32(48)?;
        let value = decoder.bytes("value", 0, MAX_INLINE)?;
        match block.u8(65)? {
            1 if recording_id != 0 => Err(out_of_range("recording_id")),
            1 if usize::try_from(length).ok() != Some(value.len()) => Err(out_of_range("length")),
            1 => Ok(Payload::Inline(value)),
            2 => {
                no_value(value)?;
                Ok(Payload::Reference {
                    recording_id: id("recording_id", recording_id)?,
                    length,
                })
            }
            3 if recording_id != 0 => Err(out_of_range("recording_id")),
            3 => {
                no_value(value)?;
                Ok(Payload::Unavailable {
                    length: unavailable(length)?,
                })
            }
            value => Err(invalid_enum("payload", value)),
        }
    }

    /// The payload's length.
    pub(super) fn length(payload: &Payload<'_>) -> Result<u32, CodecError> {
        match *payload {
            Payload::Inline(value) => {
                u32::try_from(value.len()).map_err(|_| CodecError::LengthOutOfRange {
                    field: "value",
                    length: value.len(),
                    min: 0,
                    max: MAX_INLINE,
                })
            }
            Payload::Reference { length, .. } => Ok(length),
            Payload::Unavailable { length } => unavailable(length),
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &MessageEvent<'_>,
    ) -> Result<(), CodecError> {
        let length = length(&message.payload)?;
        let (recording_id, kind, value) = match message.payload {
            Payload::Inline(value) => (0, 1, value),
            Payload::Reference { recording_id, .. } => {
                (id("recording_id", recording_id)?, 2, &[][..])
            }
            Payload::Unavailable { .. } => (0, 3, &[][..]),
        };
        encoder.u64(32, recording_id)?;
        encoder.u32(48, length)?;
        encoder.u8(65, kind)?;
        encoder.bytes("value", 0, MAX_INLINE, value)
    }
}

/// A message event's trace extension: the second variable field, present
/// exactly when the flags byte's extension bit is set.
mod extension {
    use super::{
        Block, CodecError, Decoder, EXTENSION, Encoder, FLAG_EXTENSION, MessageEvent, flags,
        out_of_range,
    };

    pub(super) fn read<'a>(
        block: &Block<'a>,
        decoder: &mut Decoder<'a>,
    ) -> Result<Option<&'a [u8; EXTENSION]>, CodecError> {
        if flags(block)? & FLAG_EXTENSION == 0 {
            decoder.bytes("extension", 0, 0)?;
            Ok(None)
        } else {
            let bytes = decoder.bytes("extension", EXTENSION, EXTENSION)?;
            Ok(Some(
                bytes.try_into().map_err(|_| out_of_range("extension"))?,
            ))
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &MessageEvent<'_>,
    ) -> Result<(), CodecError> {
        let extension = message
            .extension
            .map_or(&[][..], |extension| &extension[..]);
        encoder.bytes("extension", 0, EXTENSION, extension)
    }
}

impl MessageEvent<'_> {
    /// The extent covers the payload after one frame header.
    fn check(&self) -> Result<(), CodecError> {
        extent(self.extent, payload::length(&self.payload)?).map(|_| ())
    }
}

/// A conflated value's [`Freshness`]: the code at 44, a stale value's gap
/// start at 24.
mod freshness {
    use super::{
        Block, CodecError, ConflatedEvent, Encoder, Freshness, invalid_enum, out_of_range,
    };

    pub(super) fn read(block: &Block<'_>) -> Result<Freshness, CodecError> {
        let since = block.u64(24)?;
        match block.u8(44)? {
            1 if since != 0 => Err(out_of_range("stale_since")),
            1 => Ok(Freshness::Fresh),
            2 => Ok(Freshness::Stale { since }),
            value => Err(invalid_enum("freshness", value)),
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &ConflatedEvent<'_>,
    ) -> Result<(), CodecError> {
        let (freshness, since) = match message.freshness {
            Freshness::Fresh => (1, 0),
            Freshness::Stale { since } => (2, since),
        };
        encoder.u64(24, since)?;
        encoder.u8(44, freshness)
    }
}

/// A lifecycle event's [`LifecycleKind`]: the kind at 40, an end's reason
/// at 42.
mod lifecycle_kind {
    use super::{
        Block, CodecError, Encoder, EndReason, LifecycleEvent, LifecycleKind, invalid_enum,
        out_of_range,
    };

    pub(super) fn read(block: &Block<'_>) -> Result<LifecycleKind, CodecError> {
        match (block.u8(40)?, block.u8(42)?) {
            (1, 0) => Ok(LifecycleKind::ImageAvailable),
            (2, 0) => Ok(LifecycleKind::ImageUnavailable),
            (1 | 2, _) => Err(out_of_range("reason")),
            (3, 1) => Ok(LifecycleKind::SubscriptionEnded(EndReason::EndOfStream)),
            (3, 2) => Ok(LifecycleKind::SubscriptionEnded(EndReason::Overrun)),
            (3, 3) => Ok(LifecycleKind::SubscriptionEnded(EndReason::Revoked)),
            (3, 4) => Ok(LifecycleKind::SubscriptionEnded(EndReason::Closed)),
            (3, value) => Err(invalid_enum("reason", value)),
            (value, _) => Err(invalid_enum("kind", value)),
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &LifecycleEvent,
    ) -> Result<(), CodecError> {
        let (kind, reason) = match message.kind {
            LifecycleKind::ImageAvailable => (1, 0),
            LifecycleKind::ImageUnavailable => (2, 0),
            LifecycleKind::SubscriptionEnded(EndReason::EndOfStream) => (3, 1),
            LifecycleKind::SubscriptionEnded(EndReason::Overrun) => (3, 2),
            LifecycleKind::SubscriptionEnded(EndReason::Revoked) => (3, 3),
            LifecycleKind::SubscriptionEnded(EndReason::Closed) => (3, 4),
        };
        encoder.u8(40, kind)?;
        encoder.u8(42, reason)
    }
}

/// A loss event's [`Loss`]: the kind at 57, an overrun's outcome at 58 and
/// the reason at 59.
mod loss {
    use super::{
        Block, CodecError, Encoder, FallbackReason, Loss, LossEvent, OverrunOutcome, invalid_enum,
        out_of_range, skip_code, skip_reason,
    };

    pub(super) fn read(block: &Block<'_>) -> Result<Loss, CodecError> {
        let (outcome, reason) = (block.u8(58)?, block.u8(59)?);
        match block.u8(57)? {
            1 => {
                let outcome = OverrunOutcome::from_code(outcome)?;
                let fallback = FallbackReason::from_code(reason)?;
                if fallback.is_some() && !outcome.is_secondary() {
                    return Err(out_of_range("reason"));
                }
                Ok(Loss::Overrun { outcome, fallback })
            }
            2 | 3 if outcome != 0 => Err(out_of_range("outcome")),
            2 => Ok(Loss::Skipped(skip_reason(reason)?)),
            3 if reason != 0 => Err(out_of_range("reason")),
            3 => Ok(Loss::Aborted),
            value => Err(invalid_enum("kind", value)),
        }
    }

    pub(super) fn write(encoder: &mut Encoder<'_>, message: &LossEvent) -> Result<(), CodecError> {
        let (kind, outcome, reason) = match message.loss {
            Loss::Overrun { outcome, fallback } => {
                if fallback.is_some() && !outcome.is_secondary() {
                    return Err(out_of_range("reason"));
                }
                (1, outcome.code(), fallback.map_or(0, FallbackReason::code))
            }
            Loss::Skipped(reason) => (2, 0, skip_code(reason)),
            Loss::Aborted => (3, 0, 0),
        };
        encoder.u8(57, kind)?;
        encoder.u8(58, outcome)?;
        encoder.u8(59, reason)
    }
}

/// An observation's [`Operation`], as a `with` field.
mod operation_byte {
    use super::{Block, CodecError, Encoder, Operation, invalid_enum};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<Operation, CodecError> {
        match block.u8(at)? {
            1 => Ok(Operation::Offer),
            2 => Ok(Operation::Claim),
            3 => Ok(Operation::Commit),
            value => Err(invalid_enum("operation", value)),
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        value: &Operation,
    ) -> Result<(), CodecError> {
        encoder.u8(
            at,
            match value {
                Operation::Offer => 1,
                Operation::Claim => 2,
                Operation::Commit => 3,
            },
        )
    }
}

/// An outcome's code.
const fn outcome_code(outcome: &Outcome) -> u8 {
    match outcome {
        Outcome::Accepted { .. } => 1,
        Outcome::BackPressured => 2,
        Outcome::AdminAction => 3,
        Outcome::NotConnected => 4,
        Outcome::Closed => 5,
        Outcome::Gated => 6,
        Outcome::RateLimited => 7,
        Outcome::Aborted { .. } => 8,
        Outcome::Failed { .. } => 9,
    }
}

/// An observation's [`Outcome`]: the code at 49, the lane at 50, the
/// position at 8, a failure's error at 44, sub at 46 and details at 16
/// and 24.
mod outcome {
    use super::{
        Block, CodecError, Encoder, MAX_ERROR_CODE, Outcome, OutcomeObservation, details_fit,
        invalid_enum, lane, out_of_range, sub_of,
    };

    pub(super) fn read(block: &Block<'_>) -> Result<Outcome, CodecError> {
        let (position, detail, detail2) = (block.u64(8)?, block.u64(16)?, block.u64(24)?);
        let (error, sub) = (block.u16(44)?, block.u16(46)?);
        let lane_byte = block.u8(50)?;
        let code = block.u8(49)?;
        if !(1..=9).contains(&code) {
            return Err(invalid_enum("outcome", code));
        }
        let positioned = matches!(code, 1 | 8);
        if !positioned && position != 0 {
            return Err(out_of_range("position"));
        }
        if !positioned && lane_byte != 0 {
            return Err(out_of_range("lane"));
        }
        if code != 9 && (error != 0 || sub != 0 || detail != 0 || detail2 != 0) {
            return Err(out_of_range("error"));
        }
        Ok(match code {
            1 => Outcome::Accepted {
                lane: lane(lane_byte)?,
                position,
            },
            8 => Outcome::Aborted {
                lane: lane(lane_byte)?,
                position,
            },
            2 => Outcome::BackPressured,
            3 => Outcome::AdminAction,
            4 => Outcome::NotConnected,
            5 => Outcome::Closed,
            6 => Outcome::Gated,
            7 => Outcome::RateLimited,
            _ if error == 0 || error > MAX_ERROR_CODE => return Err(out_of_range("error")),
            _ if !sub_of(error, sub) => return Err(out_of_range("sub")),
            _ if !details_fit(error, sub, detail, detail2) => return Err(out_of_range("detail")),
            _ => Outcome::Failed {
                error,
                sub,
                detail,
                detail2,
            },
        })
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        message: &OutcomeObservation,
    ) -> Result<(), CodecError> {
        let none = (0u16, 0u16, 0u64, 0u64);
        let (lane, position, (error, sub, detail, detail2)) = match message.outcome {
            Outcome::Accepted { lane, position } | Outcome::Aborted { lane, position } => {
                (lane.get(), position, none)
            }
            Outcome::Failed { error, .. } if error == 0 || error > MAX_ERROR_CODE => {
                return Err(out_of_range("error"));
            }
            Outcome::Failed { error, sub, .. } if !sub_of(error, sub) => {
                return Err(out_of_range("sub"));
            }
            Outcome::Failed {
                error,
                sub,
                detail,
                detail2,
            } if !details_fit(error, sub, detail, detail2) => {
                return Err(out_of_range("detail"));
            }
            Outcome::Failed {
                error,
                sub,
                detail,
                detail2,
            } => (0, 0, (error, sub, detail, detail2)),
            _ => (0, 0, none),
        };
        encoder.u64(8, position)?;
        encoder.u64(16, detail)?;
        encoder.u64(24, detail2)?;
        encoder.u16(44, error)?;
        encoder.u16(46, sub)?;
        encoder.u8(49, super::outcome_code(&message.outcome))?;
        encoder.u8(50, lane)
    }
}

impl OutcomeObservation {
    /// The operation can return the outcome, and a claim records no
    /// length or digest.
    fn check(&self) -> Result<(), CodecError> {
        if !returns(self.operation, outcome_code(&self.outcome)) {
            return Err(out_of_range("outcome"));
        }
        if self.operation == Operation::Claim && (self.length != 0 || self.crc32c != 0) {
            return Err(out_of_range("length"));
        }
        Ok(())
    }
}

impl DeliveryPoll {
    /// It presented at most its maximum.
    fn check(&self) -> Result<(), CodecError> {
        if self.count > self.max {
            Err(out_of_range("count"))
        } else {
            Ok(())
        }
    }
}

/// A delivery's ring kind code, as a `with` field: refused on decode as
/// an unknown code, on encode as out of range.
mod delivery_kind {
    use super::{Block, CodecError, DELIVERY_KINDS, Encoder, invalid_enum, out_of_range};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<u8, CodecError> {
        let kind = block.u8(at)?;
        if DELIVERY_KINDS.contains(&kind) {
            Ok(kind)
        } else {
            Err(invalid_enum("kind", kind))
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        value: &u8,
    ) -> Result<(), CodecError> {
        if !DELIVERY_KINDS.contains(value) {
            return Err(out_of_range("kind"));
        }
        encoder.u8(at, *value)
    }
}

impl DeliveryObservation {
    /// As the ring itself refuses (`outcome_ring::Record`): a receiver
    /// only on a range-side kind, a lost count only on outcomes lost.
    fn check(&self) -> Result<(), CodecError> {
        if !range_side(self.kind) && self.receiver != 0 {
            return Err(out_of_range("receiver"));
        }
        if self.kind != OUTCOMES_LOST && self.lost != 0 {
            return Err(out_of_range("lost"));
        }
        Ok(())
    }
}

/// A timer observation's [`TimerAction`], as a `with` field.
mod timer_action {
    use super::{Block, CodecError, Encoder, TimerAction, invalid_enum};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<TimerAction, CodecError> {
        match block.u8(at)? {
            1 => Ok(TimerAction::Create),
            2 => Ok(TimerAction::Cancel),
            value => Err(invalid_enum("action", value)),
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        value: &TimerAction,
    ) -> Result<(), CodecError> {
        encoder.u8(
            at,
            match value {
                TimerAction::Create => 1,
                TimerAction::Cancel => 2,
            },
        )
    }
}

/// An event end's [`EndOutcome`], as a `with` field.
mod end_outcome {
    use super::{Block, CodecError, Encoder, EndOutcome, invalid_enum};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<EndOutcome, CodecError> {
        match block.u8(at)? {
            1 => Ok(EndOutcome::Complete),
            2 => Ok(EndOutcome::Incomplete),
            value => Err(invalid_enum("outcome", value)),
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        value: &EndOutcome,
    ) -> Result<(), CodecError> {
        encoder.u8(
            at,
            match value {
                EndOutcome::Complete => 1,
                EndOutcome::Incomplete => 2,
            },
        )
    }
}

/// A gap marker's [`GapReason`], as a `with` field.
mod gap_reason {
    use super::{Block, CodecError, Encoder, GapReason, invalid_enum};

    pub(super) fn read(block: &Block<'_>, at: usize) -> Result<GapReason, CodecError> {
        match block.u8(at)? {
            1 => Ok(GapReason::BudgetExceeded),
            2 => Ok(GapReason::RingFull),
            3 => Ok(GapReason::PayloadUnavailable),
            value => Err(invalid_enum("reason", value)),
        }
    }

    pub(super) fn write(
        encoder: &mut Encoder<'_>,
        at: usize,
        value: &GapReason,
    ) -> Result<(), CodecError> {
        encoder.u8(
            at,
            match value {
                GapReason::BudgetExceeded => 1,
                GapReason::RingFull => 2,
                GapReason::PayloadUnavailable => 3,
            },
        )
    }
}

impl GapMarker {
    /// The last event is at least the first.
    fn check(&self) -> Result<(), CodecError> {
        if self.to_seq < self.from_seq {
            Err(out_of_range("to_seq"))
        } else {
            Ok(())
        }
    }
}

/// Any record of schema 3, version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GroupRecord<'a> {
    /// Template 1.
    Header(JournalHeader<'a>),
    /// Template 2.
    Message(MessageEvent<'a>),
    /// Template 3.
    Conflated(ConflatedEvent<'a>),
    /// Template 4.
    Timer(TimerEvent),
    /// Template 5.
    Lifecycle(LifecycleEvent),
    /// Template 6.
    External(ExternalEvent<'a>),
    /// Template 7.
    Loss(LossEvent),
    /// Template 11.
    Outcome(OutcomeObservation),
    /// Template 12.
    TimerOperation(TimerObservation),
    /// Template 13.
    ExternalObservation(ExternalObservation<'a>),
    /// Template 14.
    Delivery(DeliveryObservation),
    /// Template 15.
    Poll(DeliveryPoll),
    /// Template 20.
    End(EventEnd),
    /// Template 21.
    Gap(GapMarker),
    /// Template 22.
    Unavailable(ReferenceUnavailable),
    /// Template 30.
    Checkpoint(CheckpointRecord),
}

/// What a record is within its journal, for the order rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// The journal header: its capture mode and first `group_seq`.
    Header {
        /// Strict or best effort.
        capture: Capture,
        /// The first event's `group_seq`.
        first_group_seq: u64,
    },
    /// An event's first record, with its `group_seq`.
    Event(u64),
    /// A message event whose payload was not captured (payload 3), with
    /// its `group_seq`: an event, which only a best-effort journal holds.
    Uncaptured(u64),
    /// An observation, with its `group_seq` and index.
    Observation(u64, u32),
    /// A delivery poll: an observation that the next `count` records of
    /// its event are its delivery observations, on its publication.
    Poll {
        /// The event's `group_seq`.
        group_seq: u64,
        /// The observation's index.
        index: u32,
        /// The delivery observations that follow.
        count: u32,
        /// The publication's stream.
        stream_id: i32,
        /// Its session.
        session_id: i32,
    },
    /// A delivery observation, on its publication.
    Delivery {
        /// The event's `group_seq`.
        group_seq: u64,
        /// The observation's index.
        index: u32,
        /// The publication's stream.
        stream_id: i32,
        /// Its session.
        session_id: i32,
    },
    /// An event's end.
    End(EventEnd),
    /// A gap marker.
    Gap(GapMarker),
    /// A reference unavailable, naming its event's `group_seq`.
    Unavailable(u64),
    /// A recorded checkpoint: its `group_seq` and `checkpoint_id`.
    Checkpoint {
        /// The last event its state includes.
        group_seq: u64,
        /// Its id.
        checkpoint_id: u64,
    },
}

impl<'a> GroupRecord<'a> {
    /// Decodes exactly one record from `buf`, validated whole.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any tuple but schema 3,
    /// version 1 or 2 and a listed template, and every other [`CodecError`] the
    /// record's fields can raise.
    pub fn decode(buf: &'a [u8]) -> Result<Self, CodecError> {
        let envelope = Envelope::read(buf)?;
        let unsupported = CodecError::UnsupportedSchema {
            schema: envelope.schema_id,
            template: envelope.template_id,
            version: envelope.version,
        };
        let v2 = envelope.version == VERSION;
        if envelope.schema_id != SCHEMA_ID || !(v2 || envelope.version == VERSION_1) {
            return Err(unsupported);
        }
        let template = match envelope.template_id {
            1 => &JOURNAL_HEADER,
            2 => &MESSAGE_EVENT,
            3 => &CONFLATED_EVENT,
            4 => &TIMER_EVENT,
            5 => &LIFECYCLE_EVENT,
            6 => &EXTERNAL_EVENT,
            7 => &LOSS_EVENT,
            11 => &OUTCOME_OBSERVATION,
            12 => &TIMER_OBSERVATION,
            13 => &EXTERNAL_OBSERVATION,
            14 => &DELIVERY_OBSERVATION,
            15 => &DELIVERY_POLL,
            20 => &EVENT_END,
            21 => &GAP_MARKER,
            22 => &REFERENCE_UNAVAILABLE,
            30 => &CHECKPOINT,
            _ => return Err(unsupported),
        };
        let earlier = version_1(template);
        let template = if v2 { template } else { &earlier };
        let (block, decoder) = Decoder::new(buf, template)?;
        Ok(match envelope.template_id {
            1 => Self::Header(JournalHeader::decode(block, decoder)?),
            2 => Self::Message(MessageEvent::decode(block, decoder, v2)?),
            3 => Self::Conflated(ConflatedEvent::decode(block, decoder)?),
            4 => Self::Timer(TimerEvent::decode(block, decoder)?),
            5 => Self::Lifecycle(LifecycleEvent::decode(block, decoder, v2)?),
            6 => Self::External(ExternalEvent::decode(block, decoder)?),
            7 => Self::Loss(LossEvent::decode(block, decoder, v2)?),
            11 => Self::Outcome(OutcomeObservation::decode(block, decoder)?),
            12 => Self::TimerOperation(TimerObservation::decode(block, decoder)?),
            13 => Self::ExternalObservation(ExternalObservation::decode(block, decoder)?),
            14 => Self::Delivery(DeliveryObservation::decode(block, decoder)?),
            15 => Self::Poll(DeliveryPoll::decode(block, decoder)?),
            20 => Self::End(EventEnd::decode(block, decoder)?),
            21 => Self::Gap(GapMarker::decode(block, decoder)?),
            22 => Self::Unavailable(ReferenceUnavailable::decode(block, decoder)?),
            _ => Self::Checkpoint(CheckpointRecord::decode(block, decoder)?),
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// The record's own encoding errors.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        match self {
            Self::Header(record) => record.encode(out),
            Self::Message(record) => record.encode(out),
            Self::Conflated(record) => record.encode(out),
            Self::Timer(record) => record.encode(out),
            Self::Lifecycle(record) => record.encode(out),
            Self::External(record) => record.encode(out),
            Self::Loss(record) => record.encode(out),
            Self::Outcome(record) => record.encode(out),
            Self::TimerOperation(record) => record.encode(out),
            Self::ExternalObservation(record) => record.encode(out),
            Self::Delivery(record) => record.encode(out),
            Self::Poll(record) => record.encode(out),
            Self::End(record) => record.encode(out),
            Self::Gap(record) => record.encode(out),
            Self::Unavailable(record) => record.encode(out),
            Self::Checkpoint(record) => record.encode(out),
        }
    }

    /// The record's place in the order rules.
    #[must_use]
    pub const fn role(&self) -> Role {
        match self {
            Self::Header(header) => Role::Header {
                capture: header.capture,
                first_group_seq: header.first_group_seq,
            },
            Self::Message(MessageEvent {
                group_seq,
                payload: Payload::Unavailable { .. },
                ..
            }) => Role::Uncaptured(*group_seq),
            Self::Message(MessageEvent { group_seq, .. })
            | Self::Conflated(ConflatedEvent { group_seq, .. })
            | Self::Timer(TimerEvent { group_seq, .. })
            | Self::Lifecycle(LifecycleEvent { group_seq, .. })
            | Self::External(ExternalEvent { group_seq, .. })
            | Self::Loss(LossEvent { group_seq, .. }) => Role::Event(*group_seq),
            Self::Outcome(OutcomeObservation {
                group_seq, index, ..
            })
            | Self::TimerOperation(TimerObservation {
                group_seq, index, ..
            })
            | Self::ExternalObservation(ExternalObservation {
                group_seq, index, ..
            }) => Role::Observation(*group_seq, *index),
            Self::Delivery(DeliveryObservation {
                group_seq,
                index,
                stream_id,
                session_id,
                ..
            }) => Role::Delivery {
                group_seq: *group_seq,
                index: *index,
                stream_id: *stream_id,
                session_id: *session_id,
            },
            Self::Poll(poll) => Role::Poll {
                group_seq: poll.group_seq,
                index: poll.index,
                count: poll.count,
                stream_id: poll.stream_id,
                session_id: poll.session_id,
            },
            Self::End(end) => Role::End(*end),
            Self::Gap(gap) => Role::Gap(*gap),
            Self::Unavailable(unavailable) => Role::Unavailable(unavailable.group_seq),
            Self::Checkpoint(checkpoint) => Role::Checkpoint {
                group_seq: checkpoint.group_seq,
                checkpoint_id: checkpoint.checkpoint_id,
            },
        }
    }
}
