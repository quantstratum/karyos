// SPDX-License-Identifier: Apache-2.0

//! Time evidence of a trace recording (ADR-0117, points 2 and 5): the
//! recording of `karyosd`'s trace stream ([`karyos_trace::stream`]) read
//! back as the observations it holds.
//!
//! [`frames`] walks a sealed range's frames; [`TraceSession`] reads their
//! messages in order and decides, for each record, whether it is in
//! session for the recording's declared clock:
//!
//! - the stream's first message is the self message, and it declares that
//!   very clock;
//! - the facts message of the record's journal for the record's facts
//!   generation came before it in the recording;
//! - those facts say provenance `HostMonotonic`, and a time namespace word
//!   equal to the driver's own in the self message (`trace-tool.md` T2: a
//!   fact the driver declared, never inferred);
//! - the record decodes, and its own uncertainty is at most the declared
//!   granularity.
//!
//! Anything else is out of session, so `no_evidence`: a facts generation
//! whose message is missing never lets earlier facts stand for it.
//! [`fold`] turns a range into the producer's events, each record at its
//! frame's positions with its observation time, the messages between them
//! folded into the event before (or, at the start, the first), so the
//! events tile the range; and it collects the range's loss messages.

use std::collections::BTreeMap;

use karyos_sys::frame::{FRAME_ALIGNMENT, FrameType, Word0};
use karyos_trace::stream::{DriverSelf, JournalFacts, StreamLoss, StreamMessage, TimeRequirement};
use karyos_trace::{ClockProvenance, decode_record};

use super::time_producer::{Event, EventClock};

/// Walks the whole frames of `bytes`, whose first byte is at stream
/// position `base`: calls `each` with each frame's positions `[start,
/// end)` (its aligned length) and, for an unfragmented data frame with a
/// payload, that payload. Padding, a fragment, a heartbeat or a control
/// frame gives `None`. Stops at the first frame that is not whole in
/// `bytes` or whose header does not decode; returns the position after the
/// last whole frame.
pub fn frames(bytes: &[u8], base: u64, mut each: impl FnMut(u64, u64, Option<&[u8]>)) -> u64 {
    let alignment = FRAME_ALIGNMENT as usize;
    let mut offset = 0usize;
    while let Some(word) = offset
        .checked_add(8)
        .and_then(|end| bytes.get(offset..end))
        .and_then(|word| <[u8; 8]>::try_from(word).ok())
    {
        let Ok(word0) = Word0::unpack(u64::from_le_bytes(word)) else {
            break;
        };
        let Ok(length) = usize::try_from(word0.frame_length()) else {
            break;
        };
        let (Some(aligned), true) = (length.checked_next_multiple_of(alignment), length > 0) else {
            break;
        };
        let Some(end) = offset
            .checked_add(aligned)
            .filter(|end| *end <= bytes.len())
        else {
            break;
        };
        let flags = word0.flags();
        let header = flags.header_length() as usize;
        let data = matches!(
            FrameType::try_from_code(word0.frame_type_code()),
            Ok(FrameType::Data)
        );
        let payload = (data && flags.begin() && flags.end() && length > header)
            .then(|| {
                offset
                    .checked_add(header)
                    .zip(offset.checked_add(length))
                    .and_then(|(from, to)| bytes.get(from..to))
            })
            .flatten();
        let position = |at: usize| base.saturating_add(at as u64);
        each(position(offset), position(end), payload);
        offset = end;
    }
    base.saturating_add(offset as u64)
}

/// What one frame of a trace recording is to the producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// An observation record: its time, and whether it is in session.
    Timed {
        /// Its observation time, in ns of the host's `CLOCK_MONOTONIC`.
        time: u64,
        /// Whether its time is of the declared clock (the module's rules).
        in_session: bool,
    },
    /// A record whose time cannot be read: out of session, at no time.
    Unreadable,
    /// A loss message.
    Loss(StreamLoss),
    /// Anything else: the self message, facts, padding, a frame that is
    /// not a trace stream message.
    Untimed,
}

/// The state a trace recording's messages build, read from its start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceSession {
    /// The self message, when the stream's first message was one.
    own: Option<DriverSelf>,
    /// Whether a message was read: only the first may be the self
    /// message.
    started: bool,
    /// Each journal's facts, by journal and generation.
    facts: BTreeMap<(u64, u64), JournalFacts>,
    /// The time requirement the recording carries for each clock domain:
    /// the first of each domain.
    requirements: BTreeMap<u64, TimeRequirement>,
}

impl TraceSession {
    /// A session of a recording read from its start.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The self message, if the stream began with one.
    #[must_use]
    pub fn own(&self) -> Option<&DriverSelf> {
        self.own.as_ref()
    }

    /// The time requirements the recording carries, by clock domain.
    #[must_use]
    pub fn requirements(&self) -> &BTreeMap<u64, TimeRequirement> {
        &self.requirements
    }

    /// Reads one frame's payload (`None` for a frame that carries no whole
    /// message) against the declared `clock`.
    pub fn observe(&mut self, payload: Option<&[u8]>, clock: &EventClock) -> Observation {
        let Some(message) = payload.and_then(|bytes| StreamMessage::decode(bytes).ok()) else {
            return Observation::Untimed;
        };
        let first = !self.started;
        self.started = true;
        match message {
            StreamMessage::DriverSelf(own) => {
                if first {
                    self.own = Some(own);
                }
                Observation::Untimed
            }
            StreamMessage::Facts(facts) => {
                let _ = self.facts.insert((facts.journal, facts.generation), facts);
                Observation::Untimed
            }
            StreamMessage::Loss(loss) => Observation::Loss(loss),
            StreamMessage::Requirement(requirement) => {
                let _ = self
                    .requirements
                    .entry(requirement.domain)
                    .or_insert(requirement);
                Observation::Untimed
            }
            StreamMessage::Record(record) => {
                let Ok((observation, _)) = decode_record(&record.words) else {
                    return Observation::Unreadable;
                };
                let observed = observation.observed;
                let declared = self.own.is_some_and(|own| {
                    own.clock == clock.clock
                        && own.granularity == clock.granularity
                        && own.namespace != 0
                });
                let facts = self.facts.get(&(record.journal, record.generation));
                let in_session = declared
                    && clock.clock != [0; 5]
                    && facts.is_some_and(|facts| {
                        facts.provenance == ClockProvenance::HostMonotonic.word()
                            && self
                                .own
                                .is_some_and(|own| facts.time_namespace == own.namespace)
                    })
                    && observed.uncertainty <= clock.granularity;
                Observation::Timed {
                    time: observed.time,
                    in_session,
                }
            }
        }
    }
}

/// A range of a trace recording, folded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Folded {
    /// Its events, tiling `[base, end)` when there is any.
    pub events: Vec<Event>,
    /// The position after its last whole frame.
    pub end: u64,
    /// Its loss messages, each with its frame's position.
    pub losses: Vec<(u64, StreamLoss)>,
}

/// Folds `bytes`, the range from stream position `base`, through
/// `session` against `clock`: each record is an event at its frame's
/// positions, every other frame joins the event before it (or the first
/// one, at the range's start), so the events tile the range. An unreadable
/// record is an out-of-session event at time 0; the producer bounds
/// nothing of it.
pub fn fold(session: &mut TraceSession, clock: &EventClock, bytes: &[u8], base: u64) -> Folded {
    let mut folded = Folded::default();
    folded.end = frames(bytes, base, |start, end, payload| {
        let (time, in_session) = match session.observe(payload, clock) {
            Observation::Timed { time, in_session } => (time, in_session),
            Observation::Unreadable => (0, false),
            Observation::Loss(loss) => {
                folded.losses.push((start, loss));
                if let Some(last) = folded.events.last_mut() {
                    last.end = end;
                }
                return;
            }
            Observation::Untimed => {
                if let Some(last) = folded.events.last_mut() {
                    last.end = end;
                }
                return;
            }
        };
        folded.events.push(Event {
            start,
            end,
            time,
            in_session,
        });
    });
    if let Some(first) = folded.events.first_mut() {
        first.start = base;
    }
    folded
}

#[cfg(test)]
pub(crate) mod tests;
