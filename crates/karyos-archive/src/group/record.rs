// SPDX-License-Identifier: Apache-2.0

//! A recording group's journal records, schema 3 version 2, written by hand
//! on the `karyos-codec` runtime (`quantstratum-docs:
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
    /// The events the reopening window holds (A9): fixed when the group
    /// is made, at most [`MAX_REOPEN_HOLD`]; 0 for a group without
    /// checkpoints. Recovery and the running tracker both take it.
    pub reopen_hold: u32,
    /// The caller's identity of what ran, opaque: 1 to [`MAX_MANIFEST`]
    /// bytes.
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
        let reopen_hold = block.u32(24)?;
        if reopen_hold > MAX_REOPEN_HOLD {
            return Err(out_of_range("reopen_hold"));
        }
        if block.u32(28)? != 0 {
            return Err(out_of_range("reserved"));
        }
        let manifest = decoder.bytes("manifest", 1, MAX_MANIFEST)?;
        decoder.finish()?;
        Ok(Self {
            group_id: id("group_id", block.u64(0)?)?,
            first_group_seq: id("first_group_seq", block.u64(8)?)?,
            inline_threshold,
            contract_version,
            clock,
            capture,
            reopen_hold,
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
        if self.reopen_hold > MAX_REOPEN_HOLD {
            return Err(out_of_range("reopen_hold"));
        }
        encoder.u32(24, self.reopen_hold)?;
        encoder.u32(28, 0)?;
        encoder.bytes("manifest", 1, MAX_MANIFEST, self.manifest)?;
        encoder.finish()
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
    /// The frames' extent from `position`: a multiple of 32 that covers
    /// the payload and at least one frame header.
    pub extent: u32,
    /// The stream.
    pub stream_id: i32,
    /// The session.
    pub session_id: i32,
    /// The lane.
    pub lane: Lane,
    /// The reserved value of the message's first fragment, which the
    /// publisher set.
    pub reserved_value: i64,
    /// The message ended its stream.
    pub end_of_stream: bool,
    /// The opaque trace extension the message carried, if any: an input,
    /// which A8's comparison schema may name as excludable.
    pub extension: Option<&'a [u8; EXTENSION]>,
    /// The payload.
    pub payload: Payload<'a>,
    /// The registration of the network image the message came from, 0 for
    /// none (ADR-0089).
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

impl<'a> MessageEvent<'a> {
    fn decode(block: Block<'a>, mut decoder: Decoder<'a>, v2: bool) -> Result<Self, CodecError> {
        let recording_id = block.u64(32)?;
        let length = block.u32(48)?;
        let flags = block.u8(66)?;
        if flags & !(FLAG_END_OF_STREAM | FLAG_EXTENSION) != 0 {
            return Err(out_of_range("flags"));
        }
        let value = decoder.bytes("value", 0, MAX_INLINE)?;
        let extension = if flags & FLAG_EXTENSION == 0 {
            decoder.bytes("extension", 0, 0)?;
            None
        } else {
            let bytes = decoder.bytes("extension", EXTENSION, EXTENSION)?;
            Some(bytes.try_into().map_err(|_| out_of_range("extension"))?)
        };
        decoder.finish()?;
        let payload = match block.u8(65)? {
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
            3 if recording_id != 0 => return Err(out_of_range("recording_id")),
            3 if !value.is_empty() => {
                return Err(CodecError::LengthOutOfRange {
                    field: "value",
                    length: value.len(),
                    min: 0,
                    max: 0,
                });
            }
            3 => Payload::Unavailable {
                length: unavailable(length)?,
            },
            value => return Err(invalid_enum("payload", value)),
        };
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            logical_time: block.u64(8)?,
            incarnation: block.u64(16)?,
            position: block.u64(24)?,
            extent: extent(block.u32(52)?, length)?,
            stream_id: block.i32(56)?,
            session_id: block.i32(60)?,
            lane: lane(block.u8(64)?)?,
            reserved_value: block.u64(40)?.cast_signed(),
            end_of_stream: flags & FLAG_END_OF_STREAM != 0,
            extension,
            payload,
            image: if v2 { block.u64(67)? } else { 0 },
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
            Payload::Unavailable { length } => (0, unavailable(length)?, 3, &[][..]),
        };
        let mut flags = 0;
        if self.end_of_stream {
            flags |= FLAG_END_OF_STREAM;
        }
        if self.extension.is_some() {
            flags |= FLAG_EXTENSION;
        }
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, self.logical_time)?;
        encoder.u64(16, self.incarnation)?;
        encoder.u64(24, self.position)?;
        encoder.u64(32, recording_id)?;
        encoder.u64(40, self.reserved_value.cast_unsigned())?;
        encoder.u32(48, length)?;
        encoder.u32(52, extent(self.extent, length)?)?;
        encoder.i32(56, self.stream_id)?;
        encoder.i32(60, self.session_id)?;
        encoder.u8(64, self.lane.get())?;
        encoder.u8(65, kind)?;
        encoder.u8(66, flags)?;
        encoder.u64(67, self.image)?;
        encoder.bytes("value", 0, MAX_INLINE, value)?;
        let extension = self.extension.map_or(&[][..], |extension| &extension[..]);
        encoder.bytes("extension", 0, EXTENSION, extension)?;
        encoder.finish()
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleEvent {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// When it was dispatched.
    pub logical_time: u64,
    /// The publication incarnation.
    pub incarnation: u64,
    /// The position on `lane` the event names (where the stream ended), or
    /// 0 when it names none: image events carry no position.
    pub position: u64,
    /// The stream.
    pub stream_id: i32,
    /// The session.
    pub session_id: i32,
    /// The lane `position` is on.
    pub lane: Lane,
    /// What happened.
    pub kind: LifecycleKind,
    /// The registration of the network image the event names, 0 for none
    /// (ADR-0089).
    pub image: u64,
}

impl LifecycleEvent {
    fn decode(block: Block<'_>, decoder: Decoder<'_>, v2: bool) -> Result<Self, CodecError> {
        decoder.finish()?;
        let reason = block.u8(42)?;
        let kind = match (block.u8(40)?, reason) {
            (1, 0) => LifecycleKind::ImageAvailable,
            (2, 0) => LifecycleKind::ImageUnavailable,
            (1 | 2, _) => return Err(out_of_range("reason")),
            (3, 1) => LifecycleKind::SubscriptionEnded(EndReason::EndOfStream),
            (3, 2) => LifecycleKind::SubscriptionEnded(EndReason::Overrun),
            (3, 3) => LifecycleKind::SubscriptionEnded(EndReason::Revoked),
            (3, 4) => LifecycleKind::SubscriptionEnded(EndReason::Closed),
            (3, value) => return Err(invalid_enum("reason", value)),
            (value, _) => return Err(invalid_enum("kind", value)),
        };
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            logical_time: block.u64(8)?,
            incarnation: block.u64(16)?,
            position: block.u64(24)?,
            stream_id: block.i32(32)?,
            session_id: block.i32(36)?,
            lane: lane(block.u8(41)?)?,
            kind,
            image: if v2 { block.u64(43)? } else { 0 },
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] and [`CodecError::ValueOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &LIFECYCLE_EVENT)?;
        let (kind, reason) = match self.kind {
            LifecycleKind::ImageAvailable => (1, 0),
            LifecycleKind::ImageUnavailable => (2, 0),
            LifecycleKind::SubscriptionEnded(EndReason::EndOfStream) => (3, 1),
            LifecycleKind::SubscriptionEnded(EndReason::Overrun) => (3, 2),
            LifecycleKind::SubscriptionEnded(EndReason::Revoked) => (3, 3),
            LifecycleKind::SubscriptionEnded(EndReason::Closed) => (3, 4),
        };
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, self.logical_time)?;
        encoder.u64(16, self.incarnation)?;
        encoder.u64(24, self.position)?;
        encoder.i32(32, self.stream_id)?;
        encoder.i32(36, self.session_id)?;
        encoder.u8(40, kind)?;
        encoder.u8(41, self.lane.get())?;
        encoder.u8(42, reason)?;
        encoder.u64(43, self.image)?;
        encoder.finish()
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossEvent {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// When it was dispatched.
    pub logical_time: u64,
    /// The publication incarnation.
    pub incarnation: u64,
    /// An overrun's first position not delivered; a skip's or an abort's
    /// position.
    pub from: u64,
    /// An overrun's end known lost; a skip's or an abort's end.
    pub lost_to: u64,
    /// Where delivery resumed; for a skip or an abort, its end. A replayed
    /// overrun's cutover.
    pub resume: u64,
    /// The stream.
    pub stream_id: i32,
    /// The session.
    pub session_id: i32,
    /// The lane.
    pub lane: Lane,
    /// What was lost, and how it resolved.
    pub loss: Loss,
    /// The registration of the network image the loss was on, 0 for none
    /// (ADR-0089).
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

    fn decode(block: Block<'_>, decoder: Decoder<'_>, v2: bool) -> Result<Self, CodecError> {
        decoder.finish()?;
        let (outcome, reason) = (block.u8(58)?, block.u8(59)?);
        let loss = match block.u8(57)? {
            1 => {
                let outcome = OverrunOutcome::from_code(outcome)?;
                let fallback = FallbackReason::from_code(reason)?;
                if fallback.is_some() && !outcome.is_secondary() {
                    return Err(out_of_range("reason"));
                }
                Loss::Overrun { outcome, fallback }
            }
            2 | 3 if outcome != 0 => return Err(out_of_range("outcome")),
            2 => Loss::Skipped(skip_reason(reason)?),
            3 if reason != 0 => return Err(out_of_range("reason")),
            3 => Loss::Aborted,
            value => return Err(invalid_enum("kind", value)),
        };
        let event = Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            logical_time: block.u64(8)?,
            incarnation: block.u64(16)?,
            from: block.u64(24)?,
            lost_to: block.u64(32)?,
            resume: block.u64(40)?,
            stream_id: block.i32(48)?,
            session_id: block.i32(52)?,
            lane: lane(block.u8(56)?)?,
            loss,
            image: if v2 { block.u64(60)? } else { 0 },
        };
        event.positions()?;
        Ok(event)
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] and [`CodecError::ValueOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &LOSS_EVENT)?;
        self.positions()?;
        let (kind, outcome, reason) = match self.loss {
            Loss::Overrun { outcome, fallback } => {
                if fallback.is_some() && !outcome.is_secondary() {
                    return Err(out_of_range("reason"));
                }
                (1, outcome.code(), fallback.map_or(0, FallbackReason::code))
            }
            Loss::Skipped(reason) => (2, 0, skip_code(reason)),
            Loss::Aborted => (3, 0, 0),
        };
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, self.logical_time)?;
        encoder.u64(16, self.incarnation)?;
        encoder.u64(24, self.from)?;
        encoder.u64(32, self.lost_to)?;
        encoder.u64(40, self.resume)?;
        encoder.i32(48, self.stream_id)?;
        encoder.i32(52, self.session_id)?;
        encoder.u8(56, self.lane.get())?;
        encoder.u8(57, kind)?;
        encoder.u8(58, outcome)?;
        encoder.u8(59, reason)?;
        encoder.u64(60, self.image)?;
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
    /// Offer, claim or commit.
    pub operation: Operation,
    /// What it returned.
    pub outcome: Outcome,
    /// An offer's payload length, or a commit's claimed bytes' length,
    /// whatever the outcome; 0 for a claim.
    pub length: u32,
    /// The CRC-32C of those bytes; 0 for a claim.
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

impl OutcomeObservation {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let operation = match block.u8(48)? {
            1 => Operation::Offer,
            2 => Operation::Claim,
            3 => Operation::Commit,
            value => return Err(invalid_enum("operation", value)),
        };
        let (position, detail, detail2) = (block.u64(8)?, block.u64(16)?, block.u64(24)?);
        let (error, sub) = (block.u16(44)?, block.u16(46)?);
        let lane_byte = block.u8(50)?;
        let code = block.u8(49)?;
        if !(1..=9).contains(&code) {
            return Err(invalid_enum("outcome", code));
        }
        if !returns(operation, code) {
            return Err(out_of_range("outcome"));
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
        let outcome = match code {
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
            _ if !details_fit(error, sub, detail, detail2) => {
                return Err(out_of_range("detail"));
            }
            _ => Outcome::Failed {
                error,
                sub,
                detail,
                detail2,
            },
        };
        let (length, crc32c) = (block.u32(51)?, block.u32(55)?);
        if operation == Operation::Claim && (length != 0 || crc32c != 0) {
            return Err(out_of_range("length"));
        }
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            index: block.u32(32)?,
            stream_id: block.i32(36)?,
            session_id: block.i32(40)?,
            operation,
            outcome,
            length,
            crc32c,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// an outcome its operation cannot return or an error code outside 1
    /// to [`MAX_ERROR_CODE`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &OUTCOME_OBSERVATION)?;
        let none = (0u16, 0u16, 0u64, 0u64);
        let (outcome, lane, position, (error, sub, detail, detail2)) = match self.outcome {
            Outcome::Accepted { lane, position } => (1, lane.get(), position, none),
            Outcome::BackPressured => (2, 0, 0, none),
            Outcome::AdminAction => (3, 0, 0, none),
            Outcome::NotConnected => (4, 0, 0, none),
            Outcome::Closed => (5, 0, 0, none),
            Outcome::Gated => (6, 0, 0, none),
            Outcome::RateLimited => (7, 0, 0, none),
            Outcome::Aborted { lane, position } => (8, lane.get(), position, none),
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
            } => (9, 0, 0, (error, sub, detail, detail2)),
        };
        if !returns(self.operation, outcome) {
            return Err(out_of_range("outcome"));
        }
        if self.operation == Operation::Claim && (self.length != 0 || self.crc32c != 0) {
            return Err(out_of_range("length"));
        }
        let operation = match self.operation {
            Operation::Offer => 1,
            Operation::Claim => 2,
            Operation::Commit => 3,
        };
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, position)?;
        encoder.u64(16, detail)?;
        encoder.u64(24, detail2)?;
        encoder.u32(32, self.index)?;
        encoder.i32(36, self.stream_id)?;
        encoder.i32(40, self.session_id)?;
        encoder.u16(44, error)?;
        encoder.u16(46, sub)?;
        encoder.u8(48, operation)?;
        encoder.u8(49, outcome)?;
        encoder.u8(50, lane)?;
        encoder.u32(51, self.length)?;
        encoder.u32(55, self.crc32c)?;
        encoder.finish()
    }
}

/// A `poll_outcomes` call on a guarded publication: it precedes the
/// `count` delivery observations the call presented, so replay can tell
/// the calls apart, an empty one included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryPoll {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// The observation's index within the event, from 0.
    pub index: u32,
    /// The call's maximum.
    pub max: u32,
    /// The records it presented, at most `max`.
    pub count: u32,
    /// The stream.
    pub stream_id: i32,
    /// The session.
    pub session_id: i32,
}

impl DeliveryPoll {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let (max, count) = (block.u32(12)?, block.u32(16)?);
        if count > max {
            return Err(out_of_range("count"));
        }
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            index: block.u32(8)?,
            max,
            count,
            stream_id: block.i32(20)?,
            session_id: block.i32(24)?,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a `count` over `max`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &DELIVERY_POLL)?;
        if self.count > self.max {
            return Err(out_of_range("count"));
        }
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u32(8, self.index)?;
        encoder.u32(12, self.max)?;
        encoder.u32(16, self.count)?;
        encoder.i32(20, self.stream_id)?;
        encoder.i32(24, self.session_id)?;
        encoder.finish()
    }
}

/// A guarded publication's delivery outcome, as the outcome ring
/// presented it to the handler (SPEC §8.3, asynchronous delivery
/// outcomes): its kind is the ring's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryObservation {
    /// The event's sequence in its group, never 0.
    pub group_seq: u64,
    /// The observation's index within the event, from 0.
    pub index: u32,
    /// The stream.
    pub stream_id: i32,
    /// The session.
    pub session_id: i32,
    /// The ring's kind code: 1 submitted, 2 confirmed cancelled, 3
    /// unknown, 4 rejected, 5 aborted, 16 range, 17 interrupted, 18 ended,
    /// 19 outcomes lost.
    pub kind: u8,
    /// The lane.
    pub lane: Lane,
    /// The receiver index, for range kinds; else 0.
    pub receiver: u16,
    /// The incarnation.
    pub incarnation: u64,
    /// The message's start, or a receiver's delivered prefix.
    pub start: u64,
    /// The message's end, or the unresolved range's end.
    pub end: u64,
    /// The guard epoch at the decision.
    pub epoch: u64,
    /// The reason, for the kinds that carry one.
    pub reason: u64,
    /// The lost count, for outcomes lost.
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

impl DeliveryObservation {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let kind = block.u8(70)?;
        if !DELIVERY_KINDS.contains(&kind) {
            return Err(invalid_enum("kind", kind));
        }
        // As the ring itself refuses (`outcome_ring::Record`): a receiver
        // only on a range-side kind, a lost count only on outcomes lost.
        if !range_side(kind) && block.u16(68)? != 0 {
            return Err(out_of_range("receiver"));
        }
        if kind != OUTCOMES_LOST && block.u64(48)? != 0 {
            return Err(out_of_range("lost"));
        }
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            incarnation: block.u64(8)?,
            start: block.u64(16)?,
            end: block.u64(24)?,
            epoch: block.u64(32)?,
            reason: block.u64(40)?,
            lost: block.u64(48)?,
            index: block.u32(56)?,
            stream_id: block.i32(60)?,
            session_id: block.i32(64)?,
            receiver: block.u16(68)?,
            kind,
            lane: lane(block.u8(71)?)?,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a kind the ring does not have.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &DELIVERY_OBSERVATION)?;
        if !DELIVERY_KINDS.contains(&self.kind) {
            return Err(out_of_range("kind"));
        }
        if !range_side(self.kind) && self.receiver != 0 {
            return Err(out_of_range("receiver"));
        }
        if self.kind != OUTCOMES_LOST && self.lost != 0 {
            return Err(out_of_range("lost"));
        }
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, self.incarnation)?;
        encoder.u64(16, self.start)?;
        encoder.u64(24, self.end)?;
        encoder.u64(32, self.epoch)?;
        encoder.u64(40, self.reason)?;
        encoder.u64(48, self.lost)?;
        encoder.u32(56, self.index)?;
        encoder.i32(60, self.stream_id)?;
        encoder.i32(64, self.session_id)?;
        encoder.u16(68, self.receiver)?;
        encoder.u8(70, self.kind)?;
        encoder.u8(71, self.lane.get())?;
        encoder.finish()
    }
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
#[non_exhaustive]
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

/// A best-effort group's mark of an event whose payload is by reference to
/// a recording that stopped or failed before it covered the frames: the
/// payload will never be there, so the event counts complete with its
/// payload unavailable (`recording-group-gateway.md` section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceUnavailable {
    /// The event, already ended, never 0.
    pub group_seq: u64,
    /// The recording its payload names, never 0.
    pub recording_id: u64,
}

impl ReferenceUnavailable {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        Ok(Self {
            group_seq: id("group_seq", block.u64(0)?)?,
            recording_id: id("recording_id", block.u64(8)?)?,
        })
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] and [`CodecError::ValueOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &REFERENCE_UNAVAILABLE)?;
        encoder.u64(0, id("group_seq", self.group_seq)?)?;
        encoder.u64(8, id("recording_id", self.recording_id)?)?;
        encoder.finish()
    }
}

/// A checkpoint of the application's state after event `group_seq`,
/// stored at `position` in the group's checkpoint store (A9). It sits
/// outside events, as a gap marker does, and is appended once its bytes
/// are written, so events after `group_seq` may come before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointRecord {
    /// The last event the state includes, never 0.
    pub group_seq: u64,
    /// Never 0, increasing within the group.
    pub checkpoint_id: u64,
    /// Where its range starts in the checkpoint store;
    /// [`CAPTURE_POSITION`] in a replay's capture, which stores nothing.
    pub position: u64,
    /// The snapshot's bytes, at least 1.
    pub length: u64,
    /// The CRC-32C of the snapshot's bytes.
    pub crc32c: u32,
    /// The application's own tag for its snapshot format.
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

    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let record = Self {
            group_seq: block.u64(0)?,
            checkpoint_id: block.u64(8)?,
            position: block.u64(16)?,
            length: block.u64(24)?,
            crc32c: block.u32(32)?,
            format: block.u32(36)?,
        };
        record.check()?;
        Ok(record)
    }

    /// Encodes into `out`; returns the record's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] and [`CodecError::ValueOutOfRange`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &CHECKPOINT)?;
        self.check()?;
        encoder.u64(0, self.group_seq)?;
        encoder.u64(8, self.checkpoint_id)?;
        encoder.u64(16, self.position)?;
        encoder.u64(24, self.length)?;
        encoder.u32(32, self.crc32c)?;
        encoder.u32(36, self.format)?;
        encoder.finish()
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
