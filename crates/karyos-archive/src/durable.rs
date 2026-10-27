// SPDX-License-Identifier: Apache-2.0

//! The Archive's durable-prefix acknowledgement, R-CORE-12
//! (quantstratum-docs: karyos/design/archive-durable-acknowledgement.md).
//!
//! Two answers, never mixed:
//! - a recording's [`DurablePosition`]: the stream position below which
//!   every recorded byte, with its index, is on storage under the
//!   recording's sync policy;
//! - a recording group's [`GroupDurable`]: its durable `group_seq`, a
//!   sequence number of the group, never compared with a position.
//!
//! An acknowledgement is never ahead of the Archive's last successful
//! sync, and after a crash and recovery the recovered value is never
//! behind one reported before it. It does not say the data is
//! replicated, processed, signed or anchored, and under
//! [`DurableSync::None`] the position moves only at an explicit sync or
//! at the close (the note's section 3).
//!
//! In process, [`crate::agent::ArchiveHandle::durable_position`] and
//! [`crate::group::capture::CaptureSender::group_durable`] and
//! [`crate::group::capture::CaptureSender::durability`] answer. Over the
//! Archive's control streams, [`DurableQuery`] asks with schema 4's
//! [`QueryDurable`] and reads its [`DurableAnswer`]; an Archive that does
//! not know schema 4 is reported as [`DurablePoll::Unsupported`], never as
//! a durable position.

use karyos_codec::{Block, CodecError, Decoder, Encoder, Envelope, Template};

use crate::agent::Described;
use crate::client::{ControlRequests, ControlResponses};
use crate::control::{ControlMessage, ResponseCode};
use crate::group::prefix::DurableFor;
use crate::segment::SyncPolicy;
use crate::server::MAX_ANSWER;

#[cfg(test)]
mod tests;

/// Schema 4, the durability query.
pub const SCHEMA_ID: u16 = 4;
/// The only version of schema 4.
pub const VERSION: u16 = 1;

const fn template(template_id: u16, block_length: u16, max_length: u32) -> Template {
    Template {
        schema_id: SCHEMA_ID,
        template_id,
        version: VERSION,
        block_length,
        max_length,
    }
}

/// `QueryDurable`, template 1.
pub const QUERY_DURABLE: Template = template(1, 16, 12 + 16);
/// `DurablePosition`, template 2.
pub const DURABLE_POSITION: Template = template(2, 42, 12 + 42);

/// The longest schema 4 message, in bytes.
pub const MAX_MESSAGE: usize = 12 + 42;

fn out_of_range(field: &'static str) -> CodecError {
    CodecError::ValueOutOfRange { field }
}

fn invalid_enum(field: &'static str, value: u8) -> CodecError {
    CodecError::InvalidEnum {
        field,
        value: value.into(),
    }
}

/// An identifier, never 0.
fn id(field: &'static str, value: u64) -> Result<u64, CodecError> {
    if value == 0 {
        Err(out_of_range(field))
    } else {
        Ok(value)
    }
}

/// Whether the recording still records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurableState {
    /// It still records: `durable` may still move.
    Recording,
    /// It stopped: `durable` equals `written`, since the close syncs
    /// first.
    Stopped,
}

/// The recording's sync policy, which says when `durable` moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurableSync {
    /// Only at an explicit sync or at the close: a consumer that needs
    /// durability does not rely on this one.
    None,
    /// When a segment is finished, and at the close.
    PerSegment,
    /// Every interval, and at the close.
    Every,
}

impl DurableSync {
    /// The policy's kind.
    #[must_use]
    pub const fn of(policy: SyncPolicy) -> Self {
        match policy {
            SyncPolicy::None => Self::None,
            SyncPolicy::PerSegment => Self::PerSegment,
            SyncPolicy::Every { .. } => Self::Every,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::PerSegment => 1,
            Self::Every => 2,
        }
    }

    fn decode(code: u8) -> Result<Self, CodecError> {
        match code {
            0 => Ok(Self::None),
            1 => Ok(Self::PerSegment),
            2 => Ok(Self::Every),
            value => Err(invalid_enum("sync_policy", value)),
        }
    }
}

/// A recording's durable position: every byte below `durable`, from
/// `start`, is on storage under its sync policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DurablePosition {
    /// The recording, never 0.
    pub recording_id: u64,
    /// Its first position.
    pub start: u64,
    /// The position written so far; the stop once stopped.
    pub written: u64,
    /// The durable position, `start` ≤ `durable` ≤ `written`.
    pub durable: u64,
    /// Whether it still records.
    pub state: DurableState,
    /// When `durable` moves.
    pub sync: DurableSync,
}

impl DurablePosition {
    /// A recording's position, as the agent describes it.
    #[must_use]
    pub fn of(described: &Described) -> Self {
        let recording = &described.recording;
        let state = if recording.stop.is_some() {
            DurableState::Stopped
        } else {
            DurableState::Recording
        };
        Self {
            recording_id: recording.id,
            start: recording.start,
            written: described.end,
            durable: described.durable,
            state,
            sync: DurableSync::of(recording.policy),
        }
    }

    /// Whether a message whose frames end at `end` (the position of the
    /// next message) is durable.
    #[must_use]
    pub const fn covers(&self, end: u64) -> bool {
        end <= self.durable
    }

    /// The cross-field rules of the note's section 5.
    fn check(&self) -> Result<(), CodecError> {
        id("recording_id", self.recording_id)?;
        if self.start > self.durable || self.durable > self.written {
            return Err(out_of_range("durable"));
        }
        if self.state == DurableState::Stopped && self.durable != self.written {
            return Err(out_of_range("durable"));
        }
        Ok(())
    }
}

/// Asks for a recording's durable position (template 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryDurable {
    /// Echoed in the answer.
    pub correlation_id: u64,
    /// The recording, never 0.
    pub recording_id: u64,
}

impl QueryDurable {
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
        let mut encoder = Encoder::new(out, &QUERY_DURABLE)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, id("recording_id", self.recording_id)?)?;
        encoder.finish()
    }
}

/// The answer to a [`QueryDurable`] of a known recording (template 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableAnswer {
    /// The query's.
    pub correlation_id: u64,
    /// The recording's durable position.
    pub position: DurablePosition,
}

impl DurableAnswer {
    fn decode(block: Block<'_>, decoder: Decoder<'_>) -> Result<Self, CodecError> {
        let state = match block.u8(40)? {
            1 => DurableState::Recording,
            2 => DurableState::Stopped,
            value => return Err(invalid_enum("state", value)),
        };
        let position = DurablePosition {
            recording_id: block.u64(8)?,
            start: block.u64(16)?,
            written: block.u64(24)?,
            durable: block.u64(32)?,
            state,
            sync: DurableSync::decode(block.u8(41)?)?,
        };
        position.check()?;
        decoder.finish()?;
        Ok(Self {
            correlation_id: block.u64(0)?,
            position,
        })
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], and [`CodecError::ValueOutOfRange`] for
    /// a recording id of 0 or a position that breaks the note's rules.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let position = &self.position;
        position.check()?;
        let mut encoder = Encoder::new(out, &DURABLE_POSITION)?;
        encoder.u64(0, self.correlation_id)?;
        encoder.u64(8, position.recording_id)?;
        encoder.u64(16, position.start)?;
        encoder.u64(24, position.written)?;
        encoder.u64(32, position.durable)?;
        encoder.u8(
            40,
            match position.state {
                DurableState::Recording => 1,
                DurableState::Stopped => 2,
            },
        )?;
        encoder.u8(41, position.sync.code())?;
        encoder.finish()
    }
}

/// Any message of schema 4, version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurabilityMessage {
    /// Template 1.
    QueryDurable(QueryDurable),
    /// Template 2.
    DurablePosition(DurableAnswer),
}

impl DurabilityMessage {
    /// Decodes exactly one message from `buf`, validated whole.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any tuple but schema 4,
    /// version 1 and a listed template, and every other [`CodecError`] the
    /// message's fields can raise.
    pub fn decode(buf: &[u8]) -> Result<Self, CodecError> {
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
                let (block, decoder) = Decoder::new(buf, &QUERY_DURABLE)?;
                Self::QueryDurable(QueryDurable::decode(block, decoder)?)
            }
            2 => {
                let (block, decoder) = Decoder::new(buf, &DURABLE_POSITION)?;
                Self::DurablePosition(DurableAnswer::decode(block, decoder)?)
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
            Self::QueryDurable(message) => message.encode(out),
            Self::DurablePosition(message) => message.encode(out),
        }
    }
}

/// Whether one event of a group is durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Durability {
    /// It is: the `durable_group_seq` that covers it.
    Reached(u64),
    /// It never will be: it is before the current range and the first
    /// range's final durable prefix does not cover it. The value is that
    /// prefix.
    Never(u64),
    /// Not yet: the `durable_group_seq` so far.
    Pending(u64),
}

impl From<DurableFor> for Durability {
    fn from(durable: DurableFor) -> Self {
        match durable {
            DurableFor::Reached(seq) => Self::Reached(seq),
            DurableFor::Never(seq) => Self::Never(seq),
            DurableFor::Pending(seq) => Self::Pending(seq),
        }
    }
}

/// A recording group's durable prefix, read once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GroupDurable {
    /// The current range's `durable_group_seq`: every event of the range
    /// up to it is durable. It says nothing of events before the range's
    /// checkpoint; [`crate::group::capture::CaptureSender::durability`]
    /// answers per event across ranges.
    pub durable_group_seq: u64,
}

/// What a [`DurableQuery`] poll found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurablePoll {
    /// No query was asked, or the last one was already answered.
    Idle,
    /// The query is under way.
    Pending,
    /// The recording's durable position.
    Done(DurablePosition),
    /// The Archive answered with an error: an unknown recording, or an
    /// invalid query.
    Refused {
        /// Its code.
        code: ResponseCode,
        /// Its message.
        message: String,
    },
    /// The Archive does not know schema 4: durable acknowledgement is
    /// unsupported by this Archive. Never a durable position of 0.
    Unsupported,
}

/// Answers read at most per poll.
const ANSWERS_PER_POLL: usize = 64;

/// Where a query stands.
#[derive(Debug, Clone, Copy)]
enum Step {
    Idle,
    Sending {
        correlation_id: u64,
        recording_id: u64,
    },
    Waiting {
        correlation_id: u64,
    },
}

/// Asks an Archive, over its control streams, for a recording's durable
/// position. [`DurableQuery::ask`] begins a query; each
/// [`DurableQuery::poll`] sends what it can and reads the answers there
/// are, never blocking. Correlation ids carry `client_id` in their high 32
/// bits, as the other requesters' do; other answers are skipped. A lost
/// answer leaves the query pending: its owner bounds the wait and asks
/// again.
#[derive(Debug)]
pub struct DurableQuery<Q, R> {
    client_id: u32,
    requests: Q,
    responses: R,
    next: u32,
    step: Step,
    request: [u8; MAX_MESSAGE],
    answer: Vec<u8>,
}

impl<Q: ControlRequests, R: ControlResponses> DurableQuery<Q, R> {
    /// A requester `client_id`, unique among the Archive's requesters,
    /// sending on `requests` and reading `responses`.
    #[must_use]
    pub fn new(client_id: u32, requests: Q, responses: R) -> Self {
        Self {
            client_id,
            requests,
            responses,
            next: 1,
            step: Step::Idle,
            request: [0; MAX_MESSAGE],
            answer: vec![0; MAX_ANSWER],
        }
    }

    /// The transports back, dropping a query under way.
    #[must_use]
    pub fn into_transports(self) -> (Q, R) {
        (self.requests, self.responses)
    }

    /// Begins a query of `recording_id`, dropping one under way.
    pub fn ask(&mut self, recording_id: u64) {
        let low = self.next;
        self.next = self.next.checked_add(1).unwrap_or(1);
        self.step = Step::Sending {
            correlation_id: (u64::from(self.client_id) << 32) | u64::from(low),
            recording_id,
        };
    }

    /// Sends the query of [`Step::Sending`], if any.
    fn send(&mut self) -> Option<DurablePoll> {
        let Step::Sending {
            correlation_id,
            recording_id,
        } = self.step
        else {
            return None;
        };
        let query = QueryDurable {
            correlation_id,
            recording_id,
        };
        let Ok(length) = query.encode(&mut self.request) else {
            self.step = Step::Idle;
            return Some(DurablePoll::Refused {
                code: ResponseCode::InvalidRequest,
                message: "the query does not encode".to_owned(),
            });
        };
        let Some(bytes) = self.request.get(..length) else {
            self.step = Step::Idle;
            return Some(DurablePoll::Idle);
        };
        if !self.requests.send(bytes) {
            return Some(DurablePoll::Pending);
        }
        self.step = Step::Waiting { correlation_id };
        None
    }

    /// Sends what it can and reads the answers there are.
    pub fn poll(&mut self) -> DurablePoll {
        if let Some(answer) = self.send() {
            return answer;
        }
        let Step::Waiting { correlation_id } = self.step else {
            return DurablePoll::Idle;
        };
        let mut answer = std::mem::take(&mut self.answer);
        let mut found = None;
        for _ in 0..ANSWERS_PER_POLL {
            let Some(length) = self.responses.next(&mut answer) else {
                break;
            };
            let Some(bytes) = answer.get(..length) else {
                continue;
            };
            if let Ok(DurabilityMessage::DurablePosition(durable)) =
                DurabilityMessage::decode(bytes)
            {
                if durable.correlation_id == correlation_id {
                    found = Some(DurablePoll::Done(durable.position));
                    break;
                }
                continue;
            }
            if let Ok(ControlMessage::ControlResponse(response)) = ControlMessage::decode(bytes)
                && response.correlation_id == correlation_id
            {
                found = Some(match response.code {
                    ResponseCode::UnsupportedSchema => DurablePoll::Unsupported,
                    code => DurablePoll::Refused {
                        code,
                        message: response.message.to_owned(),
                    },
                });
                break;
            }
            // Other requesters' answers, signals, and what does not decode
            // are skipped.
        }
        self.answer = answer;
        match found {
            Some(poll) => {
                self.step = Step::Idle;
                poll
            }
            None => DurablePoll::Pending,
        }
    }
}
