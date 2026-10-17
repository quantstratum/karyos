// SPDX-License-Identifier: Apache-2.0

//! A recording group's journal records, schema 3 version 1, written by hand
//! on the `karyos-codec` runtime (`quantstratum-docs:
//! karyos/design/recording-group-records.md`, phase 3 batch A7a; SPEC
//! §8.3, ADR-0024).
//!
//! A journal opens with a [`JournalHeader`]. Each event is one event
//! record ([`MessageEvent`], [`ConflatedEvent`], [`TimerEvent`],
//! [`LifecycleEvent`], [`ExternalEvent`]), then the handler's observations
//! in order ([`OutcomeObservation`], [`TimerObservation`],
//! [`ExternalObservation`]), then its [`EventEnd`]. A best-effort group
//! marks the events it could not capture with a [`GapMarker`]. As in A1,
//! each record is a plain value whose variable field borrows the decoded
//! input; [`GroupRecord::decode`] validates a whole record before any value
//! exists, and `encode` writes into the caller's buffer. Nothing allocates.

use karyos_codec::{Block, CodecError, Decoder, Encoder, Envelope, Template};
use karyos_sys::frame::{FRAME_ALIGNMENT, Lane};

#[cfg(test)]
mod tests;

/// The recording group schema's id: schema 1 is the Archive's control
/// schema, and 2 is reserved for Cluster.
pub const SCHEMA_ID: u16 = 3;
/// The only version of schema 3.
pub const VERSION: u16 = 1;
/// The only capture contract version.
pub const CONTRACT_VERSION: u16 = 1;
/// The largest inline value: the largest variable field.
pub const MAX_INLINE: usize = 65_535;
/// The longest manifest, in bytes.
pub const MAX_MANIFEST: usize = 4096;
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
pub const JOURNAL_HEADER: Template = template(1, 24, 12 + 24 + 2 + 4096);
/// `MessageEvent`, template 2.
pub const MESSAGE_EVENT: Template = template(2, 58, 12 + 58 + 2 + 65_535);
/// `ConflatedEvent`, template 3.
pub const CONFLATED_EVENT: Template = template(3, 45, 12 + 45 + 2 + 65_535);
/// `TimerEvent`, template 4.
pub const TIMER_EVENT: Template = template(4, 24, 12 + 24);
/// `LifecycleEvent`, template 5.
pub const LIFECYCLE_EVENT: Template = template(5, 41, 12 + 41);
/// `ExternalEvent`, template 6.
pub const EXTERNAL_EVENT: Template = template(6, 20, 12 + 20 + 2 + 65_535);
/// `OutcomeObservation`, template 11.
pub const OUTCOME_OBSERVATION: Template = template(11, 31, 12 + 31);
/// `TimerObservation`, template 12.
pub const TIMER_OBSERVATION: Template = template(12, 29, 12 + 29);
/// `ExternalObservation`, template 13.
pub const EXTERNAL_OBSERVATION: Template = template(13, 16, 12 + 16 + 2 + 65_535);
/// `EventEnd`, template 20.
pub const EVENT_END: Template = template(20, 13, 12 + 13);
/// `GapMarker`, template 21.
pub const GAP_MARKER: Template = template(21, 17, 12 + 17);

/// The longest record of any template.
pub const MAX_RECORD: usize = 12 + 58 + 2 + 65_535;

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
pub enum Clock {
    /// The host's monotonic clock in nanoseconds, read once when an event
    /// is dispatched; a timer event's time is its deadline.
    HostMonotonic,
}

/// What a group does with an event it cannot capture whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capture {
    /// Stop admitting events: the loop stops with an incomplete capture.
    Strict,
    /// Go on, marking the uncaptured events with a [`GapMarker`].
    BestEffort,
}

/// The first record of a journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalHeader<'a> {
    /// The group, never 0.
    pub group_id: u64,
    /// The first event's `group_seq`, never 0.
    pub first_group_seq: u64,
    /// The payload size above which a recorded source's payload is stored
    /// by reference: 1 to [`MAX_INLINE`].
    pub inline_threshold: u32,
    /// The capture contract: [`CONTRACT_VERSION`].
    pub contract_version: u16,
    /// The clock of the logical times.
    pub clock: Clock,
    /// Strict or best effort.
    pub capture: Capture,
    /// The caller's identity of what ran, opaque: 1 to [`MAX_MANIFEST`]
    /// bytes.
    pub manifest: &'a [u8],
}

impl<'a> JournalHeader<'a> {
    fn decode(block: Block<'a>, mut decoder: Decoder<'a>) -> Result<Self, CodecError> {
        let inline_threshold = block.u32(16)?;
        if inline_threshold == 0
            || usize::try_from(inline_threshold).map_or(true, |t| t > MAX_INLINE)
        {
            return Err(out_of_range("inline_threshold"));
        }
        let contract_version = block.u16(20)?;
        if contract_version != CONTRACT_VERSION {
            return Err(out_of_range("contract_version"));
        }
        let clock = match block.u8(22)? {
            1 => Clock::HostMonotonic,
            value => return Err(invalid_enum("clock", value)),
        };
        let capture = match block.u8(23)? {
            1 => Capture::Strict,
            2 => Capture::BestEffort,
            value => return Err(invalid_enum("capture", value)),
        };
        let manifest = decoder.bytes("manifest", 1, MAX_MANIFEST)?;
        decoder.finish()?;
        Ok(Self {
            group_id: id("group_id", block.u64(0)?)?,
            first_group_seq: id("first_group_seq", block.u64(8)?)?,
            inline_threshold,
            contract_version,
            clock,
            capture,
            manifest,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] when `out` is short,
    /// [`CodecError::ValueOutOfRange`] for a field outside its rule, and
    /// [`CodecError::LengthOutOfRange`] for the manifest.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &JOURNAL_HEADER)?;
        if self.inline_threshold == 0
            || usize::try_from(self.inline_threshold).map_or(true, |t| t > MAX_INLINE)
        {
            return Err(out_of_range("inline_threshold"));
        }
        if self.contract_version != CONTRACT_VERSION {
            return Err(out_of_range("contract_version"));
        }
        let clock = match self.clock {
            Clock::HostMonotonic => 1,
        };
        let capture = match self.capture {
            Capture::Strict => 1,
            Capture::BestEffort => 2,
        };
        encoder.u64(0, id("group_id", self.group_id)?)?;
        encoder.u64(8, id("first_group_seq", self.first_group_seq)?)?;
        encoder.u32(16, self.inline_threshold)?;
        encoder.u16(20, self.contract_version)?;
        encoder.u8(22, clock)?;
        encoder.u8(23, capture)?;
        encoder.bytes("manifest", 1, MAX_MANIFEST, self.manifest)?;
        encoder.finish()
    }
}

/// Where a message's payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload<'a> {
    /// The payload itself, 0 to [`MAX_INLINE`] bytes.
    Inline(&'a [u8]),
    /// The frames of a recording this Archive keeps: those of
    /// `[position, position + extent)` in `recording_id`.
    Reference {
        /// The recording, never 0.
        recording_id: u64,
        /// The payload's length.
        length: u32,
    },
}

/// A message delivered from a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageEvent<'a> {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// When it was dispatched, on the journal's clock.
    pub logical_time: u64,
    /// The publication incarnation.
    pub incarnation: u64,
    /// The stream position of the message's first frame.
    pub position: u64,
    /// The frames' extent from `position`: a nonzero multiple of 32, at
    /// least the payload's length.
    pub extent: u32,
    /// The stream.
    pub stream_id: i32,
    /// The session.
    pub session_id: i32,
    /// The lane.
    pub lane: Lane,
    /// The payload.
    pub payload: Payload<'a>,
}

/// The frames' extent: a nonzero multiple of the frame alignment, covering
/// at least the payload.
fn extent(extent: u32, length: u32) -> Result<u32, CodecError> {
    if extent == 0 || !extent.is_multiple_of(FRAME_ALIGNMENT) || extent < length {
        Err(out_of_range("extent"))
    } else {
        Ok(extent)
    }
}

impl<'a> MessageEvent<'a> {
    fn decode(block: Block<'a>, mut decoder: Decoder<'a>) -> Result<Self, CodecError> {
        let recording_id = block.u64(32)?;
        let length = block.u32(40)?;
        let value = decoder.bytes("value", 0, MAX_INLINE)?;
        decoder.finish()?;
        let payload = match block.u8(57)? {
            1 if recording_id != 0 => return Err(out_of_range("recording_id")),
            1 if usize::try_from(length).ok() != Some(value.len()) => {
                return Err(out_of_range("length"));
            }
            1 => Payload::Inline(value),
            2 if !value.is_empty() => {
                return Err(CodecError::LengthOutOfRange {
                    field: "value",
                    length: value.len(),
                    min: 0,
                    max: 0,
                });
            }
            2 => Payload::Reference {
                recording_id: id("recording_id", recording_id)?,
                length,
            },
            value => return Err(invalid_enum("payload", value)),
        };
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            logical_time: block.u64(8)?,
            incarnation: block.u64(16)?,
            position: block.u64(24)?,
            extent: extent(block.u32(44)?, length)?,
            stream_id: block.i32(48)?,
            session_id: block.i32(52)?,
            lane: lane(block.u8(56)?)?,
            payload,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] when `out` is short,
    /// [`CodecError::ValueOutOfRange`] for a field outside its rule, and
    /// [`CodecError::LengthOutOfRange`] for an inline payload above
    /// [`MAX_INLINE`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &MESSAGE_EVENT)?;
        let (recording_id, length, kind, value) = match self.payload {
            Payload::Inline(value) => {
                let length =
                    u32::try_from(value.len()).map_err(|_| CodecError::LengthOutOfRange {
                        field: "value",
                        length: value.len(),
                        min: 0,
                        max: MAX_INLINE,
                    })?;
                (0, length, 1, value)
            }
            Payload::Reference {
                recording_id,
                length,
            } => (id("recording_id", recording_id)?, length, 2, &[][..]),
        };
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, self.logical_time)?;
        encoder.u64(16, self.incarnation)?;
        encoder.u64(24, self.position)?;
        encoder.u64(32, recording_id)?;
        encoder.u32(40, length)?;
        encoder.u32(44, extent(self.extent, length)?)?;
        encoder.i32(48, self.stream_id)?;
        encoder.i32(52, self.session_id)?;
        encoder.u8(56, self.lane.get())?;
        encoder.u8(57, kind)?;
        encoder.bytes("value", 0, MAX_INLINE, value)?;
        encoder.finish()
    }
}

/// Whether a conflated value was covered by a committed gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConflatedEvent<'a> {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// When it was dispatched.
    pub logical_time: u64,
    /// The value's version.
    pub version: u64,
    /// The value's key.
    pub key: u32,
    /// The stream.
    pub stream_id: i32,
    /// The session.
    pub session_id: i32,
    /// Fresh or stale.
    pub freshness: Freshness,
    /// The value, 0 to [`MAX_INLINE`] bytes.
    pub value: &'a [u8],
}

impl<'a> ConflatedEvent<'a> {
    fn decode(block: Block<'a>, mut decoder: Decoder<'a>) -> Result<Self, CodecError> {
        let since = block.u64(24)?;
        let freshness = match block.u8(44)? {
            1 if since != 0 => return Err(out_of_range("stale_since")),
            1 => Freshness::Fresh,
            2 => Freshness::Stale { since },
            value => return Err(invalid_enum("freshness", value)),
        };
        let value = decoder.bytes("value", 0, MAX_INLINE)?;
        decoder.finish()?;
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            logical_time: block.u64(8)?,
            version: block.u64(16)?,
            key: block.u32(32)?,
            stream_id: block.i32(36)?,
            session_id: block.i32(40)?,
            freshness,
            value,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], [`CodecError::ValueOutOfRange`] and
    /// [`CodecError::LengthOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &CONFLATED_EVENT)?;
        let (freshness, since) = match self.freshness {
            Freshness::Fresh => (1, 0),
            Freshness::Stale { since } => (2, since),
        };
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, self.logical_time)?;
        encoder.u64(16, self.version)?;
        encoder.u64(24, since)?;
        encoder.u32(32, self.key)?;
        encoder.i32(36, self.stream_id)?;
        encoder.i32(40, self.session_id)?;
        encoder.u8(44, freshness)?;
        encoder.bytes("value", 0, MAX_INLINE, self.value)?;
        encoder.finish()
    }
}

/// A timer that fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerEvent {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// The timer's deadline.
    pub logical_time: u64,
    /// The timer, never 0.
    pub timer_id: u64,
}

impl TimerEvent {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            logical_time: block.u64(8)?,
            timer_id: id("timer_id", block.u64(16)?)?,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] and [`CodecError::ValueOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &TIMER_EVENT)?;
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, self.logical_time)?;
        encoder.u64(16, id("timer_id", self.timer_id)?)?;
        encoder.finish()
    }
}

/// What a lifecycle event announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    /// An image became available.
    ImageAvailable,
    /// An image went away.
    ImageUnavailable,
    /// A subscription ended.
    SubscriptionEnded,
}

/// An image's availability or a subscription's end, delivered to the
/// handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleEvent {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// When it was dispatched.
    pub logical_time: u64,
    /// The publication incarnation.
    pub incarnation: u64,
    /// Where the image joined or ended.
    pub position: u64,
    /// The stream.
    pub stream_id: i32,
    /// The session.
    pub session_id: i32,
    /// What happened.
    pub kind: LifecycleKind,
}

impl LifecycleEvent {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let kind = match block.u8(40)? {
            1 => LifecycleKind::ImageAvailable,
            2 => LifecycleKind::ImageUnavailable,
            3 => LifecycleKind::SubscriptionEnded,
            value => return Err(invalid_enum("kind", value)),
        };
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            logical_time: block.u64(8)?,
            incarnation: block.u64(16)?,
            position: block.u64(24)?,
            stream_id: block.i32(32)?,
            session_id: block.i32(36)?,
            kind,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] and [`CodecError::ValueOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &LIFECYCLE_EVENT)?;
        let kind = match self.kind {
            LifecycleKind::ImageAvailable => 1,
            LifecycleKind::ImageUnavailable => 2,
            LifecycleKind::SubscriptionEnded => 3,
        };
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, self.logical_time)?;
        encoder.u64(16, self.incarnation)?;
        encoder.u64(24, self.position)?;
        encoder.i32(32, self.stream_id)?;
        encoder.i32(36, self.session_id)?;
        encoder.u8(40, kind)?;
        encoder.finish()
    }
}

/// An input from outside Karyos, delivered as an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalEvent<'a> {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// When it was dispatched.
    pub logical_time: u64,
    /// The application's own code.
    pub kind: u32,
    /// The input, 0 to [`MAX_INLINE`] bytes.
    pub value: &'a [u8],
}

impl<'a> ExternalEvent<'a> {
    fn decode(block: Block<'a>, mut decoder: Decoder<'a>) -> Result<Self, CodecError> {
        let value = decoder.bytes("value", 0, MAX_INLINE)?;
        decoder.finish()?;
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            logical_time: block.u64(8)?,
            kind: block.u32(16)?,
            value,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], [`CodecError::ValueOutOfRange`] and
    /// [`CodecError::LengthOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &EXTERNAL_EVENT)?;
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, self.logical_time)?;
        encoder.u32(16, self.kind)?;
        encoder.bytes("value", 0, MAX_INLINE, self.value)?;
        encoder.finish()
    }
}

/// The call whose outcome was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// An offer.
    Offer,
    /// A claim.
    Claim,
}

/// An offer's or a claim's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// An offer accepted, or a claim reserved, at `position` in `lane`.
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
    /// A claim consumed and aborted at `position` in `lane`.
    Aborted {
        /// The lane.
        lane: Lane,
        /// The position.
        position: u64,
    },
    /// The call returned an error.
    Failed,
}

/// An operation's outcome, as the handler observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutcomeObservation {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// The observation's index within the event, from 0.
    pub index: u32,
    /// The stream.
    pub stream_id: i32,
    /// The session.
    pub session_id: i32,
    /// Offer or claim.
    pub operation: Operation,
    /// What it returned.
    pub outcome: Outcome,
}

impl OutcomeObservation {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let operation = match block.u8(28)? {
            1 => Operation::Offer,
            2 => Operation::Claim,
            value => return Err(invalid_enum("operation", value)),
        };
        let (position, lane_byte) = (block.u64(8)?, block.u8(30)?);
        let positioned = || -> Result<(Lane, u64), CodecError> { Ok((lane(lane_byte)?, position)) };
        let outcome = match block.u8(29)? {
            1 => {
                let (lane, position) = positioned()?;
                Outcome::Accepted { lane, position }
            }
            8 if operation == Operation::Offer => return Err(out_of_range("outcome")),
            8 => {
                let (lane, position) = positioned()?;
                Outcome::Aborted { lane, position }
            }
            2..=7 | 9 if position != 0 => return Err(out_of_range("position")),
            2..=7 | 9 if lane_byte != 0 => return Err(out_of_range("lane")),
            2 => Outcome::BackPressured,
            3 => Outcome::AdminAction,
            4 => Outcome::NotConnected,
            5 => Outcome::Closed,
            6 => Outcome::Gated,
            7 => Outcome::RateLimited,
            9 => Outcome::Failed,
            value => return Err(invalid_enum("outcome", value)),
        };
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            index: block.u32(16)?,
            stream_id: block.i32(20)?,
            session_id: block.i32(24)?,
            operation,
            outcome,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// an aborted offer.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &OUTCOME_OBSERVATION)?;
        let (outcome, lane, position) = match self.outcome {
            Outcome::Accepted { lane, position } => (1, lane.get(), position),
            Outcome::BackPressured => (2, 0, 0),
            Outcome::AdminAction => (3, 0, 0),
            Outcome::NotConnected => (4, 0, 0),
            Outcome::Closed => (5, 0, 0),
            Outcome::Gated => (6, 0, 0),
            Outcome::RateLimited => (7, 0, 0),
            Outcome::Aborted { .. } if self.operation == Operation::Offer => {
                return Err(out_of_range("outcome"));
            }
            Outcome::Aborted { lane, position } => (8, lane.get(), position),
            Outcome::Failed => (9, 0, 0),
        };
        let operation = match self.operation {
            Operation::Offer => 1,
            Operation::Claim => 2,
        };
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, position)?;
        encoder.u32(16, self.index)?;
        encoder.i32(20, self.stream_id)?;
        encoder.i32(24, self.session_id)?;
        encoder.u8(28, operation)?;
        encoder.u8(29, outcome)?;
        encoder.u8(30, lane)?;
        encoder.finish()
    }
}

/// A timer created or cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerAction {
    /// Created.
    Create,
    /// Cancelled.
    Cancel,
}

/// A timer operation, as the handler made it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerObservation {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// The observation's index within the event, from 0.
    pub index: u32,
    /// The timer, never 0.
    pub timer_id: u64,
    /// Its deadline; a cancel repeats it.
    pub deadline: u64,
    /// Create or cancel.
    pub action: TimerAction,
}

impl TimerObservation {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let action = match block.u8(28)? {
            1 => TimerAction::Create,
            2 => TimerAction::Cancel,
            value => return Err(invalid_enum("action", value)),
        };
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            index: block.u32(24)?,
            timer_id: id("timer_id", block.u64(8)?)?,
            deadline: block.u64(16)?,
            action,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] and [`CodecError::ValueOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &TIMER_OBSERVATION)?;
        let action = match self.action {
            TimerAction::Create => 1,
            TimerAction::Cancel => 2,
        };
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, id("timer_id", self.timer_id)?)?;
        encoder.u64(16, self.deadline)?;
        encoder.u32(24, self.index)?;
        encoder.u8(28, action)?;
        encoder.finish()
    }
}

/// A response from outside Karyos the handler read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalObservation<'a> {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// The observation's index within the event, from 0.
    pub index: u32,
    /// The application's own code.
    pub kind: u32,
    /// The response, 0 to [`MAX_INLINE`] bytes.
    pub value: &'a [u8],
}

impl<'a> ExternalObservation<'a> {
    fn decode(block: Block<'a>, mut decoder: Decoder<'a>) -> Result<Self, CodecError> {
        let value = decoder.bytes("value", 0, MAX_INLINE)?;
        decoder.finish()?;
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            index: block.u32(8)?,
            kind: block.u32(12)?,
            value,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], [`CodecError::ValueOutOfRange`] and
    /// [`CodecError::LengthOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &EXTERNAL_OBSERVATION)?;
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u32(8, self.index)?;
        encoder.u32(12, self.kind)?;
        encoder.bytes("value", 0, MAX_INLINE, self.value)?;
        encoder.finish()
    }
}

/// Whether an event's capture is whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOutcome {
    /// Every observation is recorded.
    Complete,
    /// The event exceeded its capture budget.
    Incomplete,
}

/// The end of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventEnd {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// How many observations the event has.
    pub observations: u32,
    /// Complete or incomplete.
    pub outcome: EndOutcome,
}

impl EventEnd {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let outcome = match block.u8(12)? {
            1 => EndOutcome::Complete,
            2 => EndOutcome::Incomplete,
            value => return Err(invalid_enum("outcome", value)),
        };
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            observations: block.u32(8)?,
            outcome,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] and [`CodecError::ValueOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &EVENT_END)?;
        let outcome = match self.outcome {
            EndOutcome::Complete => 1,
            EndOutcome::Incomplete => 2,
        };
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u32(8, self.observations)?;
        encoder.u8(12, outcome)?;
        encoder.finish()
    }
}

/// Why a best-effort group did not capture events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapMarker {
    /// The first event not captured, never 0.
    pub from_seq: u64,
    /// The last, at least `from_seq`.
    pub to_seq: u64,
    /// Why.
    pub reason: GapReason,
}

impl GapMarker {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let reason = match block.u8(16)? {
            1 => GapReason::BudgetExceeded,
            2 => GapReason::RingFull,
            3 => GapReason::PayloadUnavailable,
            value => return Err(invalid_enum("reason", value)),
        };
        let from_seq = id("from_seq", block.u64(0)?)?;
        let to_seq = block.u64(8)?;
        if to_seq < from_seq {
            return Err(out_of_range("to_seq"));
        }
        Ok(Self {
            from_seq,
            to_seq,
            reason,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] and [`CodecError::ValueOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &GAP_MARKER)?;
        if self.to_seq < self.from_seq {
            return Err(out_of_range("to_seq"));
        }
        let reason = match self.reason {
            GapReason::BudgetExceeded => 1,
            GapReason::RingFull => 2,
            GapReason::PayloadUnavailable => 3,
        };
        encoder.u64(0, id("from_seq", self.from_seq)?)?;
        encoder.u64(8, self.to_seq)?;
        encoder.u8(16, reason)?;
        encoder.finish()
    }
}

/// Any record of schema 3, version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Template 11.
    Outcome(OutcomeObservation),
    /// Template 12.
    TimerOperation(TimerObservation),
    /// Template 13.
    ExternalObservation(ExternalObservation<'a>),
    /// Template 20.
    End(EventEnd),
    /// Template 21.
    Gap(GapMarker),
}

/// What a record is within its journal, for the order rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// An observation, with its `group_seq` and index.
    Observation(u64, u32),
    /// An event's end.
    End(EventEnd),
    /// A gap marker.
    Gap(GapMarker),
}

impl<'a> GroupRecord<'a> {
    /// Decodes exactly one record from `buf`, validated whole.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any tuple but schema 3,
    /// version 1 and a listed template, and every other [`CodecError`] the
    /// record's fields can raise.
    pub fn decode(buf: &'a [u8]) -> Result<Self, CodecError> {
        let envelope = Envelope::read(buf)?;
        let unsupported = CodecError::UnsupportedSchema {
            schema: envelope.schema_id,
            template: envelope.template_id,
            version: envelope.version,
        };
        if envelope.schema_id != SCHEMA_ID || envelope.version != VERSION {
            return Err(unsupported);
        }
        let template = match envelope.template_id {
            1 => &JOURNAL_HEADER,
            2 => &MESSAGE_EVENT,
            3 => &CONFLATED_EVENT,
            4 => &TIMER_EVENT,
            5 => &LIFECYCLE_EVENT,
            6 => &EXTERNAL_EVENT,
            11 => &OUTCOME_OBSERVATION,
            12 => &TIMER_OBSERVATION,
            13 => &EXTERNAL_OBSERVATION,
            20 => &EVENT_END,
            21 => &GAP_MARKER,
            _ => return Err(unsupported),
        };
        let (block, decoder) = Decoder::new(buf, template)?;
        Ok(match envelope.template_id {
            1 => Self::Header(JournalHeader::decode(block, decoder)?),
            2 => Self::Message(MessageEvent::decode(block, decoder)?),
            3 => Self::Conflated(ConflatedEvent::decode(block, decoder)?),
            4 => Self::Timer(TimerEvent::decode(block, decoder)?),
            5 => Self::Lifecycle(LifecycleEvent::decode(block, decoder)?),
            6 => Self::External(ExternalEvent::decode(block, decoder)?),
            11 => Self::Outcome(OutcomeObservation::decode(block, decoder)?),
            12 => Self::TimerOperation(TimerObservation::decode(block, decoder)?),
            13 => Self::ExternalObservation(ExternalObservation::decode(block, decoder)?),
            20 => Self::End(EventEnd::decode(block, decoder)?),
            _ => Self::Gap(GapMarker::decode(block, decoder)?),
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
            Self::Outcome(record) => record.encode(out),
            Self::TimerOperation(record) => record.encode(out),
            Self::ExternalObservation(record) => record.encode(out),
            Self::End(record) => record.encode(out),
            Self::Gap(record) => record.encode(out),
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
            Self::Message(MessageEvent { group_seq, .. })
            | Self::Conflated(ConflatedEvent { group_seq, .. })
            | Self::Timer(TimerEvent { group_seq, .. })
            | Self::Lifecycle(LifecycleEvent { group_seq, .. })
            | Self::External(ExternalEvent { group_seq, .. }) => Role::Event(*group_seq),
            Self::Outcome(OutcomeObservation {
                group_seq, index, ..
            })
            | Self::TimerOperation(TimerObservation {
                group_seq, index, ..
            })
            | Self::ExternalObservation(ExternalObservation {
                group_seq, index, ..
            }) => Role::Observation(*group_seq, *index),
            Self::End(end) => Role::End(*end),
            Self::Gap(gap) => Role::Gap(*gap),
        }
    }
}
