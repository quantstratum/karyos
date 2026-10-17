// SPDX-License-Identifier: Apache-2.0

//! The Archive's control messages, version 1, written by hand on the
//! `karyos-codec` runtime (`quantstratum-docs:
//! karyos/design/archive-control-codec.md`, phase 3 batch A1; ADR-0036).
//!
//! Schema 1 holds five requests ([`StartRecording`], [`StopRecording`],
//! [`ListRecordings`], [`Replay`], [`StopReplay`]) and three responses
//! ([`ControlResponse`], [`RecordingDescriptor`], [`RecordingSignal`]).
//! Each message is a plain value whose text fields borrow the decoded
//! input; [`ControlMessage::decode`] validates a whole message before any
//! value exists, and `encode` writes into the caller's buffer. Nothing
//! allocates. A derive macro is to generate these from schema definitions;
//! these hand-written ones become its vectors.

use karyos_codec::{Block, CodecError, Decoder, Encoder, Envelope, Template};

use crate::catalog::{Stop, StopReason};
use crate::recorder::{Mode, OnLap};
use crate::segment::{Geometry, SyncPolicy};

#[cfg(test)]
mod tests;

/// The Archive's schema id.
pub const SCHEMA_ID: u16 = 1;
/// The only version of schema 1.
pub const VERSION: u16 = 1;
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
pub const RECORDING_DESCRIPTOR: Template = template(102, 70, 12 + 70 + 2 + 1024);
/// `RecordingSignal`, template 103.
pub const RECORDING_SIGNAL: Template = template(103, 27, 12 + 27);

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartRecording<'a> {
    /// Echoed in the responses.
    pub correlation_id: u64,
    /// The recorded stream.
    pub stream_id: i32,
    /// The recorded session.
    pub session_id: i32,
    /// Required or async.
    pub mode: Mode,
    /// The store's sync policy.
    pub sync_policy: SyncPolicy,
    /// Segment length in bytes; 0 for the Archive's default.
    pub segment_length: u64,
    /// The channel, 1 to [`MAX_CHANNEL`] bytes.
    pub channel: &'a str,
}

impl<'a> StartRecording<'a> {
    fn decode(block: Block<'a>, mut decoder: Decoder<'a>) -> Result<Self, CodecError> {
        let interval = block.u64(8)?;
        let mode = match (block.u8(32)?, block.u8(33)?) {
            (1, 0) => Mode::Required,
            (2, 1) => Mode::Async {
                on_lap: OnLap::Stop,
            },
            (2, 2) => Mode::Async {
                on_lap: OnLap::Resume,
            },
            (1 | 2, _) => return Err(out_of_range("on_lap")),
            (value, _) => return Err(invalid_enum("mode", value)),
        };
        let sync_policy = match block.u8(34)? {
            0 | 1 if interval != 0 => return Err(out_of_range("sync_interval_ns")),
            0 => SyncPolicy::None,
            1 => SyncPolicy::PerSegment,
            2 if interval == 0 => return Err(out_of_range("sync_interval_ns")),
            2 => SyncPolicy::Every {
                interval_ns: interval,
            },
            value => return Err(invalid_enum("sync_policy", value)),
        };
        let channel = decoder.str("channel", 1, MAX_CHANNEL)?;
        decoder.finish()?;
        Ok(Self {
            correlation_id: block.u64(0)?,
            stream_id: block.i32(24)?,
            session_id: block.i32(28)?,
            mode,
            sync_policy,
            segment_length: block.u64(16)?,
            channel,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] when `out` is short, and
    /// [`CodecError::LengthOutOfRange`] for the channel.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &START_RECORDING)?;
        let (mode, on_lap) = match self.mode {
            Mode::Required => (1, 0),
            Mode::Async {
                on_lap: OnLap::Stop,
            } => (2, 1),
            Mode::Async {
                on_lap: OnLap::Resume,
            } => (2, 2),
        };
        let (policy, interval) = match self.sync_policy {
            SyncPolicy::None => (0, 0),
            SyncPolicy::PerSegment => (1, 0),
            SyncPolicy::Every { interval_ns: 0 } => return Err(out_of_range("sync_interval_ns")),
            SyncPolicy::Every { interval_ns } => (2, interval_ns),
        };
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, interval)?;
        encoder.u64(16, self.segment_length)?;
        encoder.i32(24, self.stream_id)?;
        encoder.i32(28, self.session_id)?;
        encoder.u8(32, mode)?;
        encoder.u8(33, on_lap)?;
        encoder.u8(34, policy)?;
        encoder.bytes("channel", 1, MAX_CHANNEL, self.channel.as_bytes())?;
        encoder.finish()
    }
}

/// Requests a recording's stop where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopRecording {
    /// Echoed in the response.
    pub correlation_id: u64,
    /// The recording, never 0.
    pub recording_id: u64,
}

impl StopRecording {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        Ok(Self {
            correlation_id: block.u64(0)?,
            recording_id: id("recording_id", block.u64(8)?)?,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a recording id of 0.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &STOP_RECORDING)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, id("recording_id", self.recording_id)?)?;
        encoder.finish()
    }
}

/// Requests the catalog's recordings from an id on: one
/// [`RecordingDescriptor`] each, then a [`ControlResponse`] with the count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListRecordings {
    /// Echoed in the responses.
    pub correlation_id: u64,
    /// The first id listed.
    pub from_id: u64,
    /// At most this many, 1 to [`MAX_LIST_COUNT`].
    pub max_count: u32,
}

fn list_count(count: u32) -> Result<u32, CodecError> {
    if (1..=MAX_LIST_COUNT).contains(&count) {
        Ok(count)
    } else {
        Err(out_of_range("max_count"))
    }
}

impl ListRecordings {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        Ok(Self {
            correlation_id: block.u64(0)?,
            from_id: block.u64(8)?,
            max_count: list_count(block.u32(16)?)?,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a count outside its bounds.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &LIST_RECORDINGS)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, self.from_id)?;
        encoder.u32(16, list_count(self.max_count)?)?;
        encoder.finish()
    }
}

/// The pace of a replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replay<'a> {
    /// Echoed in the responses.
    pub correlation_id: u64,
    /// The recording, never 0.
    pub recording_id: u64,
    /// The first position replayed.
    pub position: u64,
    /// Bytes; `u64::MAX` to the recording's end.
    pub length: u64,
    /// The pace.
    pub rate: ReplayRate,
    /// The target stream.
    pub target_stream_id: i32,
    /// The target channel, 1 to [`MAX_CHANNEL`] bytes.
    pub target_channel: &'a str,
}

impl<'a> Replay<'a> {
    fn decode(block: Block<'a>, mut decoder: Decoder<'a>) -> Result<Self, CodecError> {
        let scale = block.u32(32)?;
        let rate = match block.u8(40)? {
            1 | 2 if scale != 0 => return Err(out_of_range("scale_ppm")),
            1 => ReplayRate::Full,
            2 => ReplayRate::AsRecorded,
            3 if (1..=MAX_SCALE_PPM).contains(&scale) => ReplayRate::Scaled { ppm: scale },
            3 => return Err(out_of_range("scale_ppm")),
            value => return Err(invalid_enum("rate", value)),
        };
        let target_channel = decoder.str("target_channel", 1, MAX_CHANNEL)?;
        decoder.finish()?;
        Ok(Self {
            correlation_id: block.u64(0)?,
            recording_id: id("recording_id", block.u64(8)?)?,
            position: block.u64(16)?,
            length: block.u64(24)?,
            rate,
            target_stream_id: block.i32(36)?,
            target_channel,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], [`CodecError::ValueOutOfRange`] for a
    /// recording id of 0 or a scale outside its bounds, and
    /// [`CodecError::LengthOutOfRange`] for the channel.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let (rate, scale) = match self.rate {
            ReplayRate::Full => (1, 0),
            ReplayRate::AsRecorded => (2, 0),
            ReplayRate::Scaled { ppm } if (1..=MAX_SCALE_PPM).contains(&ppm) => (3, ppm),
            ReplayRate::Scaled { .. } => return Err(out_of_range("scale_ppm")),
        };
        let mut encoder = Encoder::new(out, &REPLAY)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, id("recording_id", self.recording_id)?)?;
        encoder.u64(16, self.position)?;
        encoder.u64(24, self.length)?;
        encoder.u32(32, scale)?;
        encoder.i32(36, self.target_stream_id)?;
        encoder.u8(40, rate)?;
        encoder.bytes(
            "target_channel",
            1,
            MAX_CHANNEL,
            self.target_channel.as_bytes(),
        )?;
        encoder.finish()
    }
}

/// Requests a replay's stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopReplay {
    /// Echoed in the response.
    pub correlation_id: u64,
    /// The replay, never 0.
    pub replay_id: u64,
}

impl StopReplay {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        Ok(Self {
            correlation_id: block.u64(0)?,
            replay_id: id("replay_id", block.u64(8)?)?,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a replay id of 0.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &STOP_REPLAY)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, id("replay_id", self.replay_id)?)?;
        encoder.finish()
    }
}

/// The outcome of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl ResponseCode {
    const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Error => 1,
            Self::UnknownRecording => 2,
            Self::UnknownReplay => 3,
            Self::InvalidRequest => 4,
            Self::UnsupportedSchema => 5,
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
            _ => None,
        }
    }
}

/// The answer to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlResponse<'a> {
    /// The request's.
    pub correlation_id: u64,
    /// The recording or replay id, or a list's count; 0 on an error.
    pub id: u64,
    /// The outcome.
    pub code: ResponseCode,
    /// Why, on an error: up to [`MAX_RESPONSE_MESSAGE`] bytes; empty when
    /// the code is [`ResponseCode::Ok`].
    pub message: &'a str,
}

impl<'a> ControlResponse<'a> {
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

    fn decode(block: Block<'a>, mut decoder: Decoder<'a>) -> Result<Self, CodecError> {
        let raw = block.u8(16)?;
        let code = ResponseCode::of(raw).ok_or_else(|| invalid_enum("code", raw))?;
        let message = decoder.str("message", 0, MAX_RESPONSE_MESSAGE)?;
        decoder.finish()?;
        let response = Self {
            correlation_id: block.u64(0)?,
            id: block.u64(8)?,
            code,
            message,
        };
        response.check()?;
        Ok(response)
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], [`CodecError::LengthOutOfRange`] for the
    /// message (it must be empty on success), and
    /// [`CodecError::ValueOutOfRange`] for an id on an error.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        self.check()?;
        let mut encoder = Encoder::new(out, &CONTROL_RESPONSE)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, self.id)?;
        encoder.u8(16, self.code.code())?;
        encoder.bytes("message", 0, MAX_RESPONSE_MESSAGE, self.message.as_bytes())?;
        encoder.finish()
    }
}

/// One recording of a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingDescriptor<'a> {
    /// The list request's.
    pub correlation_id: u64,
    /// The recording, never 0.
    pub recording_id: u64,
    /// Its first position.
    pub start: u64,
    /// When it started.
    pub start_time_ns: u64,
    /// Where, when and why it stopped; `None` while it records.
    pub stop: Option<Stop>,
    /// Its segment geometry.
    pub geometry: Geometry,
    /// The recorded stream.
    pub stream_id: i32,
    /// The recorded session.
    pub session_id: i32,
    /// The channel, 1 to [`MAX_CHANNEL`] bytes.
    pub channel: &'a str,
}

impl<'a> RecordingDescriptor<'a> {
    fn decode(block: Block<'a>, mut decoder: Decoder<'a>) -> Result<Self, CodecError> {
        let stop_position = block.u64(24)?;
        let stop_time_ns = block.u64(40)?;
        let reason = block.u8(68)?;
        let incomplete = block.bool("incomplete", 69)?;
        let stop = match reason {
            0 if stop_position != u64::MAX || stop_time_ns != 0 || incomplete => {
                return Err(out_of_range("stop"));
            }
            0 => None,
            code => Some(Stop {
                position: stop_position,
                time_ns: stop_time_ns,
                reason: StopReason::of(code).ok_or_else(|| invalid_enum("stop_reason", code))?,
                incomplete,
            }),
        };
        let geometry =
            Geometry::new(block.u32(56)?, block.u64(48)?).map_err(|_| out_of_range("geometry"))?;
        let channel = decoder.str("channel", 1, MAX_CHANNEL)?;
        decoder.finish()?;
        Ok(Self {
            correlation_id: block.u64(0)?,
            recording_id: id("recording_id", block.u64(8)?)?,
            start: block.u64(16)?,
            start_time_ns: block.u64(32)?,
            stop,
            geometry,
            stream_id: block.i32(60)?,
            session_id: block.i32(64)?,
            channel,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], [`CodecError::ValueOutOfRange`] for a
    /// recording id of 0, and [`CodecError::LengthOutOfRange`] for the
    /// channel.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &RECORDING_DESCRIPTOR)?;
        let (stop, time, reason, incomplete) = match self.stop {
            None => (u64::MAX, 0, 0, false),
            Some(stop) => (
                stop.position,
                stop.time_ns,
                stop.reason.code(),
                stop.incomplete,
            ),
        };
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, id("recording_id", self.recording_id)?)?;
        encoder.u64(16, self.start)?;
        encoder.u64(24, stop)?;
        encoder.u64(32, self.start_time_ns)?;
        encoder.u64(40, time)?;
        encoder.u64(48, self.geometry.segment_length())?;
        encoder.u32(56, self.geometry.term_length())?;
        encoder.i32(60, self.stream_id)?;
        encoder.i32(64, self.session_id)?;
        encoder.u8(68, reason)?;
        encoder.bool(69, incomplete)?;
        encoder.bytes("channel", 1, MAX_CHANNEL, self.channel.as_bytes())?;
        encoder.finish()
    }
}

/// What happened to a recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingSignal {
    /// The start request's for [`Signal::Started`], else 0.
    pub correlation_id: u64,
    /// The recording, never 0.
    pub recording_id: u64,
    /// Its start, or where it stopped.
    pub position: u64,
    /// What happened.
    pub signal: Signal,
}

impl RecordingSignal {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        let reason = block.u8(25)?;
        let incomplete = block.bool("incomplete", 26)?;
        let signal = match block.u8(24)? {
            1 | 3 if reason != 0 || incomplete => return Err(out_of_range("stop_reason")),
            1 => Signal::Started,
            3 => Signal::Failed,
            2 => Signal::Stopped {
                reason: StopReason::of(reason)
                    .ok_or_else(|| invalid_enum("stop_reason", reason))?,
                incomplete,
            },
            value => return Err(invalid_enum("signal", value)),
        };
        decoder.finish()?;
        Ok(Self {
            correlation_id: block.u64(0)?,
            recording_id: id("recording_id", block.u64(8)?)?,
            position: block.u64(16)?,
            signal,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a recording id of 0.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let (signal, reason, incomplete) = match self.signal {
            Signal::Started => (1, 0, false),
            Signal::Stopped { reason, incomplete } => (2, reason.code(), incomplete),
            Signal::Failed => (3, 0, false),
        };
        let mut encoder = Encoder::new(out, &RECORDING_SIGNAL)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, id("recording_id", self.recording_id)?)?;
        encoder.u64(16, self.position)?;
        encoder.u8(24, signal)?;
        encoder.u8(25, reason)?;
        encoder.bool(26, incomplete)?;
        encoder.finish()
    }
}

/// Any message of schema 1, version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Template 101.
    ControlResponse(ControlResponse<'a>),
    /// Template 102.
    RecordingDescriptor(RecordingDescriptor<'a>),
    /// Template 103.
    RecordingSignal(RecordingSignal),
}

impl<'a> ControlMessage<'a> {
    /// Decodes exactly one message from `buf`, validated whole.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any tuple but schema 1,
    /// version 1 and a listed template, and every other [`CodecError`] the
    /// message's fields can raise.
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
        }
    }
}
