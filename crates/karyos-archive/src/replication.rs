// SPDX-License-Identifier: Apache-2.0

//! Recording replication between Archives, schema 6 version 1
//! (quantstratum-docs: karyos/design/archive-replication.md; ADR-0091;
//! quantstratum/karyos#996): the messages, their rules, and the checks
//! each side makes before acting on them.
//!
//! The replica asks with [`ReplicateRecording`] and stops with
//! [`StopReplication`]; the source answers with [`RecordingBytes`] (stored
//! bytes at their positions), [`SourceSeal`] (a range's seal record,
//! verbatim) and [`ReplicationStatus`]. A refusal is schema 1's
//! [`crate::control::ControlResponse`]. [`check_request`] is the source's
//! check of a request against its seals, and [`check_seal`] the replica's
//! check of a seal before [`crate::integrity::replication::Replica::verify`]
//! counts it.
//!
//! A replication's ranges are sealed under its [`SealScope`]: the open and
//! closed segment seals of the recording (ADR-0091), or, for a Cluster
//! log replication, the log's `ClusterLog` seals of one seal epoch
//! (ADR-0120 decision 2). [`check_request_in`] and [`check_seal_in`] take
//! the scope; [`check_request`] and [`check_seal`] are ADR-0091's.

use karyos_codec::{Block, CodecError, Decoder, Encoder, Envelope, Template};

use crate::integrity::{SEAL_RECORD_LENGTH, SealKind, SealRecord};

pub mod transport;

#[cfg(test)]
mod tests;

/// The replication schema's id.
pub const SCHEMA_ID: u16 = 6;
/// The only version of schema 6.
pub const VERSION: u16 = 1;
/// The most bytes one [`RecordingBytes`] carries.
pub const MAX_CHUNK: usize = 16384;

const fn template(template_id: u16, block_length: u16, max_length: u32) -> Template {
    Template {
        schema_id: SCHEMA_ID,
        template_id,
        version: VERSION,
        block_length,
        max_length,
    }
}

/// `ReplicateRecording`, template 1.
pub const REPLICATE_RECORDING: Template = template(1, 33, 12 + 33);
/// `StopReplication`, template 2.
pub const STOP_REPLICATION: Template = template(2, 16, 12 + 16);
/// `RecordingBytes`, template 101.
pub const RECORDING_BYTES: Template = template(101, 24, 12 + 24 + 2 + 16384);
/// `SourceSeal`, template 102.
pub const SOURCE_SEAL: Template = template(102, 120, 12 + 120);
/// `ReplicationStatus`, template 103.
pub const REPLICATION_STATUS: Template = template(103, 41, 12 + 41);

fn out_of_range(field: &'static str) -> CodecError {
    CodecError::ValueOutOfRange { field }
}

fn invalid_enum(field: &'static str, value: u8) -> CodecError {
    CodecError::InvalidEnum {
        field,
        value: u64::from(value),
    }
}

fn recording(value: u64) -> Result<u64, CodecError> {
    if value == 0 {
        Err(out_of_range("recording_id"))
    } else {
        Ok(value)
    }
}

/// Which seals cover a replication's ranges (ADR-0120 decision 2).
///
/// The recording id is the one the request names and the replica's
/// copies are recorded under; it is apart from the seals' subject, which
/// for a Cluster log is the seal epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealScope {
    /// Open and closed segment seals whose subject is `recording_id`:
    /// every replication but the Cluster log's (ADR-0091).
    Segments {
        /// The recording, never 0.
        recording_id: u64,
    },
    /// `ClusterLog` seals whose subject is `epoch`, for the Cluster log
    /// recording `recording_id` (ADR-0120 decisions 2 and 4).
    ClusterLog {
        /// The Cluster log recording (karyos-cluster's `LOG_RECORDING`).
        recording_id: u64,
        /// The source log's seal epoch every seal of the request names.
        epoch: u64,
    },
}

impl SealScope {
    /// ADR-0091's scope for `recording_id`.
    #[must_use]
    #[inline]
    pub const fn segments(recording_id: u64) -> Self {
        Self::Segments { recording_id }
    }

    /// A Cluster log replication of `recording_id` under the seals of
    /// `epoch`.
    #[must_use]
    #[inline]
    pub const fn cluster_log(recording_id: u64, epoch: u64) -> Self {
        Self::ClusterLog {
            recording_id,
            epoch,
        }
    }

    /// The recording the request names and copies are recorded under.
    #[must_use]
    #[inline]
    pub const fn recording_id(self) -> u64 {
        match self {
            Self::Segments { recording_id } | Self::ClusterLog { recording_id, .. } => recording_id,
        }
    }

    /// Whether `seal` is one of this scope's range seals.
    #[must_use]
    #[inline]
    pub const fn admits(self, seal: &SealRecord) -> bool {
        match self {
            Self::Segments { recording_id } => {
                seal.subject == recording_id
                    && matches!(seal.kind, SealKind::OpenSegment | SealKind::ClosedSegment)
            }
            Self::ClusterLog { epoch, .. } => {
                seal.subject == epoch && matches!(seal.kind, SealKind::ClusterLog)
            }
        }
    }
}

/// The seal kinds a [`SourceSeal`] may carry: open and closed segment
/// (ADR-0091), and `ClusterLog` (ADR-0120 decision 2).
const fn carried(kind: SealKind) -> bool {
    matches!(
        kind,
        SealKind::OpenSegment | SealKind::ClosedSegment | SealKind::ClusterLog
    )
}

/// How long a replication runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mode {
    /// The source keeps sending as the recording is written and sealed.
    Continuous,
    /// The source sends what is sealed now, then [`State::CaughtUp`].
    OnDemand,
}

/// A replica's request for a recording from `from` to `until`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicateRecording {
    /// Echoed in every answer.
    pub correlation_id: u64,
    /// The recording, never 0.
    pub recording_id: u64,
    /// The first position: the recording's start or a seal boundary.
    pub from: u64,
    /// Where it stops: a seal boundary, or `u64::MAX` for none; at least
    /// `from`.
    pub until: u64,
    /// Continuous or on demand.
    pub mode: Mode,
}

/// A replica's stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopReplication {
    /// The request's.
    pub correlation_id: u64,
    /// The recording, never 0.
    pub recording_id: u64,
}

/// Stored bytes of the recording at `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingBytes<'a> {
    /// The request's.
    pub correlation_id: u64,
    /// The recording, never 0.
    pub recording_id: u64,
    /// The position of the first byte.
    pub start: u64,
    /// 1 to [`MAX_CHUNK`] bytes; `start` plus their length fits `u64`.
    pub bytes: &'a [u8],
}

/// A range's seal record, as the source's integrity journal stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSeal {
    /// The request's.
    pub correlation_id: u64,
    /// The seal, checked as the journal checks it.
    pub seal: SealRecord,
}

/// Where a replication is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum State {
    /// Sending.
    Streaming,
    /// An on-demand request is done.
    CaughtUp,
    /// The recording stopped and everything to its end was sent.
    Ended,
    /// After [`StopReplication`].
    Stopped,
    /// A gap or a purge ended the request (design section 4).
    Interrupted,
}

/// The source's view of the recording, for the replica's lag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicationStatus {
    /// The request's.
    pub correlation_id: u64,
    /// The recording, never 0.
    pub recording_id: u64,
    /// The recording's start in the source's store.
    pub source_start: u64,
    /// The end of its sealed ranges (for [`State::Interrupted`], of the
    /// last range sent whole).
    pub sealed_end: u64,
    /// Its written end.
    pub written: u64,
    /// The state.
    pub state: State,
}

/// A schema 6 message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplicationMessage<'a> {
    /// Template 1.
    ReplicateRecording(ReplicateRecording),
    /// Template 2.
    StopReplication(StopReplication),
    /// Template 101.
    RecordingBytes(RecordingBytes<'a>),
    /// Template 102.
    SourceSeal(SourceSeal),
    /// Template 103.
    ReplicationStatus(ReplicationStatus),
}

impl ReplicateRecording {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let mode = match block.u8(32)? {
            1 => Mode::Continuous,
            2 => Mode::OnDemand,
            value => return Err(invalid_enum("mode", value)),
        };
        let (from, until) = (block.u64(16)?, block.u64(24)?);
        if from > until {
            return Err(out_of_range("from"));
        }
        Ok(Self {
            correlation_id: block.u64(0)?,
            recording_id: recording(block.u64(8)?)?,
            from,
            until,
            mode,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a recording id of 0 or `from` above `until`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        if self.from > self.until {
            return Err(out_of_range("from"));
        }
        let mut encoder = Encoder::new(out, &REPLICATE_RECORDING)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, recording(self.recording_id)?)?;
        encoder.u64(16, self.from)?;
        encoder.u64(24, self.until)?;
        encoder.u8(
            32,
            match self.mode {
                Mode::Continuous => 1,
                Mode::OnDemand => 2,
            },
        )?;
        encoder.finish()
    }
}

impl StopReplication {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        Ok(Self {
            correlation_id: block.u64(0)?,
            recording_id: recording(block.u64(8)?)?,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a recording id of 0.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &STOP_REPLICATION)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, recording(self.recording_id)?)?;
        encoder.finish()
    }
}

/// `start` plus `length` fits `u64`.
fn fits(start: u64, length: usize) -> Result<(), CodecError> {
    u64::try_from(length)
        .ok()
        .and_then(|length| start.checked_add(length))
        .map(|_| ())
        .ok_or(out_of_range("start"))
}

impl<'a> RecordingBytes<'a> {
    fn decode(block: Block<'a>, mut decoder: Decoder<'a>) -> Result<Self, CodecError> {
        let bytes = decoder.bytes("bytes", 1, MAX_CHUNK)?;
        decoder.finish()?;
        let start = block.u64(16)?;
        fits(start, bytes.len())?;
        Ok(Self {
            correlation_id: block.u64(0)?,
            recording_id: recording(block.u64(8)?)?,
            start,
            bytes,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], [`CodecError::LengthOutOfRange`] for the
    /// bytes, and [`CodecError::ValueOutOfRange`] for a recording id of 0
    /// or an end past `u64::MAX`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        fits(self.start, self.bytes.len())?;
        let mut encoder = Encoder::new(out, &RECORDING_BYTES)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, recording(self.recording_id)?)?;
        encoder.u64(16, self.start)?;
        encoder.bytes("bytes", 1, MAX_CHUNK, self.bytes)?;
        encoder.finish()
    }

    /// The position after the last byte.
    #[must_use]
    pub fn end(&self) -> u64 {
        // Checked when built: `fits`.
        u64::try_from(self.bytes.len())
            .ok()
            .and_then(|length| self.start.checked_add(length))
            .unwrap_or(u64::MAX)
    }
}

impl SourceSeal {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let bytes = block
            .bytes()
            .get(8..8 + SEAL_RECORD_LENGTH)
            .ok_or(out_of_range("seal"))?;
        let seal = SealRecord::decode(bytes).map_err(|_| out_of_range("seal"))?;
        if !carried(seal.kind) {
            return Err(out_of_range("seal"));
        }
        Ok(Self {
            correlation_id: block.u64(0)?,
            seal,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a seal of a kind other than an open or closed segment or a Cluster
    /// log range.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        if !carried(self.seal.kind) {
            return Err(out_of_range("seal"));
        }
        let mut encoder = Encoder::new(out, &SOURCE_SEAL)?;
        encoder.u64(0, self.correlation_id)?;
        let record = self.seal.encode();
        for (index, word) in record.as_chunks::<8>().0.iter().enumerate() {
            encoder.u64(8 + index * 8, u64::from_le_bytes(*word))?;
        }
        encoder.finish()
    }
}

impl ReplicationStatus {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        decoder.finish()?;
        let state = match block.u8(40)? {
            1 => State::Streaming,
            2 => State::CaughtUp,
            3 => State::Ended,
            4 => State::Stopped,
            5 => State::Interrupted,
            value => return Err(invalid_enum("state", value)),
        };
        let status = Self {
            correlation_id: block.u64(0)?,
            recording_id: recording(block.u64(8)?)?,
            source_start: block.u64(16)?,
            sealed_end: block.u64(24)?,
            written: block.u64(32)?,
            state,
        };
        status.ordered()?;
        Ok(status)
    }

    /// `source_start <= sealed_end <= written`, except that an interrupted
    /// status may name a start above the last range sent, after a purge:
    /// there `source_start <= written` (ADR-0094).
    fn ordered(&self) -> Result<(), CodecError> {
        let start_ok = if self.state == State::Interrupted {
            self.source_start <= self.written
        } else {
            self.source_start <= self.sealed_end
        };
        if start_ok && self.sealed_end <= self.written {
            Ok(())
        } else {
            Err(out_of_range("sealed_end"))
        }
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a recording id of 0 or positions out of order.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        self.ordered()?;
        let mut encoder = Encoder::new(out, &REPLICATION_STATUS)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, recording(self.recording_id)?)?;
        encoder.u64(16, self.source_start)?;
        encoder.u64(24, self.sealed_end)?;
        encoder.u64(32, self.written)?;
        encoder.u8(
            40,
            match self.state {
                State::Streaming => 1,
                State::CaughtUp => 2,
                State::Ended => 3,
                State::Stopped => 4,
                State::Interrupted => 5,
            },
        )?;
        encoder.finish()
    }
}

impl<'a> ReplicationMessage<'a> {
    /// Decodes one schema 6 message, checked whole.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for another schema, version or
    /// template, and each message's own errors.
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
                let (block, decoder) = Decoder::new(buf, &REPLICATE_RECORDING)?;
                Self::ReplicateRecording(ReplicateRecording::decode(block, decoder)?)
            }
            2 => {
                let (block, decoder) = Decoder::new(buf, &STOP_REPLICATION)?;
                Self::StopReplication(StopReplication::decode(block, decoder)?)
            }
            101 => {
                let (block, decoder) = Decoder::new(buf, &RECORDING_BYTES)?;
                Self::RecordingBytes(RecordingBytes::decode(block, decoder)?)
            }
            102 => {
                let (block, decoder) = Decoder::new(buf, &SOURCE_SEAL)?;
                Self::SourceSeal(SourceSeal::decode(block, decoder)?)
            }
            103 => {
                let (block, decoder) = Decoder::new(buf, &REPLICATION_STATUS)?;
                Self::ReplicationStatus(ReplicationStatus::decode(block, decoder)?)
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
            Self::ReplicateRecording(message) => message.encode(out),
            Self::StopReplication(message) => message.encode(out),
            Self::RecordingBytes(message) => message.encode(out),
            Self::SourceSeal(message) => message.encode(out),
            Self::ReplicationStatus(message) => message.encode(out),
        }
    }
}

/// Why a source refuses a request it decoded: answered with schema 1's
/// `ControlResponse` code 4 (design section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestRefusal {
    /// `from` is below the recording's start in the store.
    BelowStart,
    /// `from` is neither the start nor a seal boundary.
    FromOffBoundary,
    /// `until` is neither `u64::MAX` nor a seal boundary.
    UntilOffBoundary,
    /// The request names another recording than the scope's.
    OutOfScope,
}

/// The source's check of `request` against the recording's start and its
/// range seals (`seals`, the source's integrity journal records): bytes it
/// sends must be covered by a whole seal that follows.
///
/// # Errors
///
/// The [`RequestRefusal`].
pub fn check_request(
    request: &ReplicateRecording,
    start: u64,
    seals: &[SealRecord],
) -> Result<(), RequestRefusal> {
    check_request_in(
        request,
        SealScope::segments(request.recording_id),
        start,
        seals,
    )
}

/// [`check_request`] under `scope`: the boundaries are those of the
/// scope's seals, and the request must name the scope's recording.
///
/// # Errors
///
/// The [`RequestRefusal`].
pub fn check_request_in(
    request: &ReplicateRecording,
    scope: SealScope,
    start: u64,
    seals: &[SealRecord],
) -> Result<(), RequestRefusal> {
    if request.recording_id != scope.recording_id() {
        return Err(RequestRefusal::OutOfScope);
    }
    let boundary = |position: u64| {
        seals
            .iter()
            .any(|seal| scope.admits(seal) && seal.end == position)
    };
    if request.from < start {
        return Err(RequestRefusal::BelowStart);
    }
    if request.from != start && !boundary(request.from) {
        return Err(RequestRefusal::FromOffBoundary);
    }
    if request.until != u64::MAX && !boundary(request.until) {
        return Err(RequestRefusal::UntilOffBoundary);
    }
    Ok(())
}

/// The replica's check of a seal for `recording_id`: only an open or
/// closed segment seal whose subject is the recording counts.
///
/// # Errors
///
/// [`CodecError::ValueOutOfRange`] for any other kind or subject.
pub fn check_seal(seal: &SealRecord, recording_id: u64) -> Result<(), CodecError> {
    check_seal_in(seal, SealScope::segments(recording_id))
}

/// The replica's check of a seal under `scope`: only the scope's seals
/// count (for a Cluster log, `ClusterLog` seals of the request's epoch).
///
/// # Errors
///
/// [`CodecError::ValueOutOfRange`] for any other kind or subject.
pub fn check_seal_in(seal: &SealRecord, scope: SealScope) -> Result<(), CodecError> {
    if scope.admits(seal) {
        Ok(())
    } else {
        Err(out_of_range("seal"))
    }
}
