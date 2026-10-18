// SPDX-License-Identifier: Apache-2.0

//! The live Gateway: capture (quantstratum-docs:
//! karyos/design/recording-group-gateway.md, sections 3, 6, 8 and 9).
//!
//! The Gateway runs on the event loop. For each event it reads the clock
//! once, assigns the next `group_seq`, delivers the event to the handler,
//! and records the event and every [`Effects`] call into an event buffer
//! sized at configuration; the buffer goes to the Archive's thread as one
//! ring message. The publications are reached through a [`Port`], so the
//! Gateway performs each call and records the outcome the client returned.
//!
//! - **Admission.** Before an event, the sender's `admit` checks the ring's
//!   room and the in-flight bound. Strict capture never delivers what it
//!   cannot record: the event is refused ([`GatewayError::Refused`]). Best
//!   effort delivers it unrecorded, and the events refused in a row are
//!   coalesced into one pending gap marker, written first once the ring has
//!   room for it. Its reason is the first refusal's: ring full for a full
//!   ring or a full tracker, payload unavailable for a value over
//!   `MAX_INLINE`. Each refusal is counted by its own reason.
//! - **The buffer.** An observation that does not fit ends the event
//!   incomplete; the call is still performed, unrecorded (the budgets per
//!   mode are A7d-2b's). A strict journal ends at an incomplete event.
//! - **Nothing is allocated per event.** The buffer and the external
//!   value's scratch are allocated at configuration.

use super::{
    ClaimCommit, DeliveryOutcome, Dispatched, Effects, Event, GatewayError, GroupGateway, Handler,
    PublicationId, TimerId,
};
use crate::crc32c::crc32c;
use crate::group::capture::{CaptureSender, GroupState, Refusal};
use crate::group::record::{
    Capture, DEFAULT_INLINE_THRESHOLD, DELIVERY_OBSERVATION, DELIVERY_POLL, DeliveryObservation,
    DeliveryPoll, EVENT_END, EXTERNAL_OBSERVATION, EndOutcome, EventEnd, ExternalEvent,
    ExternalObservation, GapMarker, GapReason, GroupRecord, MAX_INLINE, MESSAGE_EVENT,
    OUTCOME_OBSERVATION, Operation, Outcome, OutcomeObservation, TIMER_OBSERVATION, TimerAction,
    TimerObservation,
};

mod sources;

pub use sources::{ConflatedSource, MessageSource, RecordingWord, SourceIdentity};

#[cfg(test)]
mod tests;

/// The publications and timers a Gateway acts on, as the client offers
/// them. Each call is performed, and its outcome returned as the client
/// gave it.
pub trait Port {
    /// The publication's stream and session.
    fn publication(&self, publication: PublicationId) -> (i32, i32);

    /// Offers `payload`.
    fn offer(&mut self, publication: PublicationId, payload: &[u8]) -> Outcome;

    /// Claims `length` bytes; on a reservation runs `write` on them, then
    /// commits when it returns true and aborts when it returns false.
    fn claim(
        &mut self,
        publication: PublicationId,
        length: usize,
        write: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> ClaimCommit;

    /// Presents a guarded publication's next delivery outcomes, at most
    /// `max`, to `each`; returns how many.
    fn poll_outcomes(
        &mut self,
        publication: PublicationId,
        max: u32,
        each: &mut dyn FnMut(&DeliveryOutcome),
    ) -> u32;

    /// Schedules `timer` at `deadline`.
    fn schedule(&mut self, timer: TimerId, deadline: u64);

    /// Cancels `timer`.
    fn cancel(&mut self, timer: TimerId);
}

/// The Gateway's refusals and uncaptured events, each counted by its own
/// reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GatewayStats {
    /// Events refused because the ring was full.
    pub ring_full: u64,
    /// Events refused because the prefix tracker was full.
    pub in_flight: u64,
    /// Events refused because a value exceeded `MAX_INLINE`.
    pub payload_unavailable: u64,
    /// Events delivered and not recorded (best effort), gaps or not.
    pub uncaptured: u64,
    /// Events that ended incomplete.
    pub incomplete: u64,
    /// Events refused because an earlier gap marker was still waiting for
    /// room: the gap must precede the next recorded event.
    pub gap_pending: u64,
    /// Gap markers written.
    pub gaps: u64,
    /// A count reached `u64::MAX` and stopped there: the counts are then
    /// lower bounds.
    pub overflowed: bool,
}

impl GatewayStats {
    /// Adds one to `count(self)`, sticky at its maximum with the overflow
    /// flag set.
    fn bump(&mut self, count: fn(&mut Self) -> &mut u64) {
        let counter = count(self);
        match counter.checked_add(1) {
            Some(next) => *counter = next,
            None => self.overflowed = true,
        }
    }
}

/// Events refused in a row, waiting to be written as one gap marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pending {
    from: u64,
    to: u64,
    reason: GapReason,
}

/// The live Gateway over port `P`, reading the host's clock through `C`.
#[derive(Debug)]
pub struct Gateway<P: Port, C: FnMut() -> u64> {
    port: P,
    clock: C,
    sender: CaptureSender,
    capture: Capture,
    next_seq: u64,
    buffer: Vec<u8>,
    scratch: Vec<u8>,
    pending: Option<Pending>,
    stats: GatewayStats,
    /// Each timer's pending deadline, for a cancel to repeat it and for
    /// dispatch to fire it.
    deadlines: Vec<Option<u64>>,
    /// The message sources, then the conflated views, polled in turn from
    /// `turn`.
    sources: Vec<sources::Source>,
    views: Vec<sources::View>,
    turn: usize,
    /// Payloads above it are recorded by reference when they can be.
    inline_threshold: u32,
    /// Observations recorded per event at most.
    observation_budget: u32,
    /// Strict capture sent an incomplete end: the journal ends there, and
    /// every later dispatch is refused, before the job ends the group.
    ended: bool,
    /// The next event's effects start incomplete: an event delivered so
    /// that its record ends the strict journal, every call refused.
    incomplete_next: bool,
}

/// Why a Gateway could not be configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The event buffer cannot hold an event's first record and its end.
    #[error("an event buffer of {0} bytes is too small")]
    Buffer(usize),
    /// The first `group_seq` is 0.
    #[error("the first group_seq is 0")]
    FirstSeq,
}

/// Encodes an event's first record for its `group_seq` into the buffer,
/// returning its length, or refuses the event.
pub(crate) type FirstRecord<'a> = dyn Fn(u64, &mut [u8]) -> Result<usize, Refusal> + 'a;

/// The end record's length.
const END: usize = 12 + EVENT_END.block_length as usize;

impl<P: Port, C: FnMut() -> u64> Gateway<P, C> {
    /// A Gateway over `sender`, whose journal's mode is `capture` and
    /// whose next event is `next_seq`. Its event buffer is `max_event`
    /// bytes, the sender's own bound; its timer table holds `timers`
    /// timers, ids below it.
    ///
    /// A message whose record does not fit `max_event` cannot be recorded:
    /// strict capture ends the journal at it, and best effort delivers it
    /// in a gap (above `MAX_INLINE`, its payload recorded unavailable). To
    /// record every inline payload of a source with no recording to
    /// reference, `max_event` needs at least 147 + `MAX_INLINE` + the end
    /// record (12 + its block): a message head with a trace extension, the
    /// largest inline payload and its end.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for a buffer too small for an event, or a first
    /// `group_seq` of 0.
    pub fn new(
        port: P,
        clock: C,
        sender: CaptureSender,
        capture: Capture,
        next_seq: u64,
        max_event: usize,
        timers: u16,
    ) -> Result<Self, ConfigError> {
        if next_seq == 0 {
            return Err(ConfigError::FirstSeq);
        }
        // The largest event head with no payload, and its end: a message
        // with an empty payload and a trace extension (above a loss, a
        // lifecycle or an external head), so every source's report and the
        // strict end's loss fit.
        let least = 12 + MESSAGE_EVENT.block_length as usize + 2 + 2 + 64 + END;
        if max_event < least {
            return Err(ConfigError::Buffer(max_event));
        }
        Ok(Self {
            port,
            clock,
            sender,
            capture,
            next_seq,
            buffer: vec![0; max_event],
            scratch: vec![0; MAX_INLINE],
            pending: None,
            stats: GatewayStats::default(),
            deadlines: vec![None; usize::from(timers)],
            sources: Vec::new(),
            views: Vec::new(),
            turn: 0,
            inline_threshold: DEFAULT_INLINE_THRESHOLD,
            observation_budget: u32::MAX,
            ended: false,
            incomplete_next: false,
        })
    }

    /// Sets the inline threshold: the journal header's. Configuration only.
    pub fn set_inline_threshold(&mut self, threshold: u32) {
        self.inline_threshold = threshold;
    }

    /// Sets the observation budget per event. Strict refuses a call past
    /// it; best effort performs it and ends the event incomplete.
    /// Configuration only.
    pub fn set_observation_budget(&mut self, budget: u32) {
        self.observation_budget = budget;
    }

    /// The refusals and uncaptured events so far.
    #[must_use]
    pub const fn stats(&self) -> &GatewayStats {
        &self.stats
    }

    /// The sender, for its prefixes and a waiter.
    #[must_use]
    pub const fn sender(&self) -> &CaptureSender {
        &self.sender
    }

    /// The `group_seq` the next event takes.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The port.
    pub fn port(&mut self) -> &mut P {
        &mut self.port
    }

    /// Writes the pending gap marker if the ring has room; returns whether
    /// none is left pending.
    fn flush(&mut self) -> bool {
        let Some(pending) = self.pending else {
            return true;
        };
        if self.sender.room().is_err() {
            return false;
        }
        let marker = GroupRecord::Gap(GapMarker {
            from_seq: pending.from,
            to_seq: pending.to,
            reason: pending.reason,
        });
        let Ok(length) = marker.encode(&mut self.buffer) else {
            return false;
        };
        let Some(records) = self.buffer.get(..length) else {
            return false;
        };
        if self.sender.send(records, pending.to).is_err() {
            return false;
        }
        self.pending = None;
        self.stats.bump(|stats| &mut stats.gaps);
        true
    }

    /// Counts `refusal` by its reason; returns the gap reason it maps to.
    fn count(&mut self, refusal: Refusal) -> GapReason {
        self.stats.bump(match refusal {
            Refusal::InFlight => |stats| &mut stats.in_flight,
            Refusal::TooLarge => |stats| &mut stats.payload_unavailable,
            _ => |stats| &mut stats.ring_full,
        });
        match refusal {
            Refusal::TooLarge => GapReason::PayloadUnavailable,
            _ => GapReason::RingFull,
        }
    }

    /// Joins event `seq` to the pending gap, which keeps its first reason.
    fn join_gap(&mut self, seq: u64, reason: GapReason) {
        self.pending = Some(match self.pending {
            Some(pending) => Pending { to: seq, ..pending },
            None => Pending {
                from: seq,
                to: seq,
                reason,
            },
        });
    }

    /// Takes event `seq`'s number.
    fn advance(&mut self) -> Result<u64, GatewayError> {
        let seq = self.next_seq;
        self.next_seq = seq.checked_add(1).ok_or(GatewayError::Ended)?;
        Ok(seq)
    }

    /// Delivers `event`, read at `logical_time`, and records it as
    /// `first`'s record followed by its observations and its end. `first`
    /// encodes the event's record for its `group_seq`, or refuses it.
    pub(crate) fn dispatch_event(
        &mut self,
        event: &Event<'_>,
        logical_time: u64,
        first: &FirstRecord<'_>,
        handler: &mut dyn Handler,
    ) -> Result<Dispatched, GatewayError> {
        let forced = core::mem::take(&mut self.incomplete_next);
        let state = self.sender.state();
        if state != GroupState::Running {
            if self.capture == Capture::Strict {
                return Err(GatewayError::Ended);
            }
            // Best effort records nothing more, and counts what it
            // delivers.
            self.advance()?;
            self.deliver_unrecorded(event, logical_time, handler);
            return Ok(Dispatched::Uncaptured);
        }
        if !self.flush() {
            // A gap still pending must precede the next recorded event: the
            // event joins it, counted as such.
            self.stats.bump(|stats| &mut stats.gap_pending);
            return self.refuse(None, event, logical_time, handler);
        }
        if let Err(refusal) = self.sender.admit() {
            return self.refuse(Some(refusal), event, logical_time, handler);
        }
        let seq = self.next_seq;
        // `new` checked that the buffer holds an end.
        let limit = self
            .buffer
            .len()
            .checked_sub(END)
            .ok_or(GatewayError::Ended)?;
        let opened = self
            .buffer
            .get_mut(..limit)
            .ok_or(GatewayError::Ended)
            .and_then(|room| first(seq, room).map_err(GatewayError::Refused));
        let length = match opened {
            Ok(length) => length,
            Err(GatewayError::Refused(refusal)) => {
                return self.refuse(Some(refusal), event, logical_time, handler);
            }
            Err(error) => return Err(error),
        };
        self.advance()?;
        let mut effects = Recording {
            port: &mut self.port,
            buffer: &mut self.buffer,
            scratch: &mut self.scratch,
            length,
            limit,
            seq,
            index: 0,
            logical_time,
            incomplete: forced,
            recording: true,
            strict: self.capture == Capture::Strict,
            deadlines: &mut self.deadlines,
            budget: self.observation_budget,
        };
        handler.on_event(event, &mut effects);
        let (length, index, incomplete) = (effects.length, effects.index, effects.incomplete);
        let end = GroupRecord::End(EventEnd {
            group_seq: seq,
            observations: index,
            outcome: if incomplete {
                EndOutcome::Incomplete
            } else {
                EndOutcome::Complete
            },
        });
        let written = self
            .buffer
            .get_mut(length..)
            .and_then(|room| end.encode(room).ok())
            .and_then(|end| length.checked_add(end))
            .and_then(|total| self.buffer.get(..total))
            .ok_or(GatewayError::Ended)?;
        if incomplete {
            self.stats.bump(|stats| &mut stats.incomplete);
        }
        // Admitted, so the ring has room: a refusal here is a failed group.
        self.sender
            .send(written, seq)
            .map_err(|_| GatewayError::Ended)?;
        // A strict journal ends at an incomplete event: nothing follows it.
        self.ended |= incomplete && self.capture == Capture::Strict;
        Ok(Dispatched::Event { group_seq: seq })
    }

    /// An event that cannot be recorded: strict refuses it; best effort
    /// delivers it unrecorded and joins it to the pending gap.
    /// `None` is an event behind a pending gap, already counted; it joins
    /// the gap, whose reason it keeps.
    fn refuse(
        &mut self,
        refusal: Option<Refusal>,
        event: &Event<'_>,
        logical_time: u64,
        handler: &mut dyn Handler,
    ) -> Result<Dispatched, GatewayError> {
        let Some(refusal) = refusal else {
            if self.capture == Capture::Strict {
                return Err(GatewayError::Refused(Refusal::RingFull));
            }
            let seq = self.advance()?;
            self.join_gap(seq, GapReason::RingFull);
            self.deliver_unrecorded(event, logical_time, handler);
            return Ok(Dispatched::Uncaptured);
        };
        if matches!(refusal, Refusal::Ended | Refusal::Failed | Refusal::Closing) {
            if self.capture == Capture::Strict {
                return Err(GatewayError::Ended);
            }
            self.advance()?;
            self.deliver_unrecorded(event, logical_time, handler);
            return Ok(Dispatched::Uncaptured);
        }
        let reason = self.count(refusal);
        if self.capture == Capture::Strict {
            return Err(GatewayError::Refused(refusal));
        }
        let seq = self.advance()?;
        self.join_gap(seq, reason);
        self.deliver_unrecorded(event, logical_time, handler);
        // A marker that fits now goes first; the next event finds it
        // written.
        let _ = self.flush();
        Ok(Dispatched::Uncaptured)
    }

    fn deliver_unrecorded(
        &mut self,
        event: &Event<'_>,
        logical_time: u64,
        handler: &mut dyn Handler,
    ) {
        self.stats.bump(|stats| &mut stats.uncaptured);
        let mut effects = Recording {
            port: &mut self.port,
            buffer: &mut self.buffer,
            scratch: &mut self.scratch,
            length: 0,
            limit: 0,
            seq: 0,
            index: 0,
            logical_time,
            incomplete: false,
            recording: false,
            strict: self.capture == Capture::Strict,
            deadlines: &mut self.deadlines,
            budget: self.observation_budget,
        };
        handler.on_event(event, &mut effects);
    }
}

impl<P: Port, C: FnMut() -> u64> GroupGateway for Gateway<P, C> {
    /// Takes the next event, a timer due now or a source's, and delivers
    /// it.
    fn dispatch(&mut self, handler: &mut dyn Handler) -> Result<Dispatched, GatewayError> {
        if self.ended
            || (self.capture == Capture::Strict && self.sender.state() != GroupState::Running)
        {
            return Err(GatewayError::Ended);
        }
        self.dispatch_next(handler)
    }

    fn deliver_external(
        &mut self,
        kind: u32,
        value: &[u8],
        handler: &mut dyn Handler,
    ) -> Result<Dispatched, GatewayError> {
        if self.ended {
            return Err(GatewayError::Ended);
        }
        let logical_time = (self.clock)();
        let event = Event::External { kind, value };
        let first = |group_seq: u64, out: &mut [u8]| {
            if value.len() > MAX_INLINE {
                return Err(Refusal::TooLarge);
            }
            GroupRecord::External(ExternalEvent {
                group_seq,
                logical_time,
                kind,
                value,
            })
            .encode(out)
            .map_err(|_| Refusal::TooLarge)
        };
        match self.dispatch_event(&event, logical_time, &first, handler) {
            Err(GatewayError::Refused(Refusal::TooLarge)) => {
                Err(GatewayError::TooLarge(value.len()))
            }
            other => other,
        }
    }
}

/// Observation lengths, envelope included: template 11, 12, 15 and 14,
/// and template 13 before its value.
const OUTCOME: usize = 12 + OUTCOME_OBSERVATION.block_length as usize;
const TIMER: usize = 12 + TIMER_OBSERVATION.block_length as usize;
const POLL: usize = 12 + DELIVERY_POLL.block_length as usize;
const DELIVERY: usize = 12 + DELIVERY_OBSERVATION.block_length as usize;
const EXTERNAL: usize = 12 + EXTERNAL_OBSERVATION.block_length as usize + 2;

/// The handler's effects during one event: each call performed through
/// the port and, while `recording`, its observation appended to the
/// buffer.
///
/// Strict capture never performs a call it cannot record: one whose
/// observations would not fit is refused, not performed, and ends the
/// event incomplete; so is every later call. An offer or a claim refused
/// so returns [`Outcome::Gated`], a poll presents nothing, and a timer
/// operation does nothing. Best effort performs every call and records
/// what fits. An external value is read first in both modes, since the
/// read acts on nothing Karyos records; in strict capture one that does
/// not fit ends the event incomplete.
struct Recording<'a, P: Port> {
    port: &'a mut P,
    buffer: &'a mut [u8],
    scratch: &'a mut [u8],
    /// Bytes written so far.
    length: usize,
    /// Where observations must stop, leaving room for the end.
    limit: usize,
    seq: u64,
    /// The next observation's index.
    index: u32,
    logical_time: u64,
    /// An observation did not fit: no more are recorded.
    incomplete: bool,
    recording: bool,
    strict: bool,
    deadlines: &'a mut [Option<u64>],
    /// Observations recorded per event at most.
    budget: u32,
}

impl<P: Port> Recording<'_, P> {
    /// Whether a call whose observations take `bytes` (`None` past
    /// `usize`) may run. Strict refuses one that cannot be recorded and
    /// ends the event incomplete; best effort runs every call.
    fn admit(&mut self, bytes: Option<usize>) -> bool {
        if !self.recording || !self.strict {
            return true;
        }
        let fits = !self.incomplete
            && self.index < self.budget
            && bytes
                .and_then(|bytes| self.length.checked_add(bytes))
                .is_some_and(|end| end <= self.limit);
        if !fits {
            self.incomplete = true;
        }
        fits
    }

    /// The observation index the next record takes, or `None` when no
    /// more are recorded.
    fn next_index(&self) -> Option<u32> {
        (self.recording && !self.incomplete).then_some(self.index)
    }

    /// Appends `record` as the next observation; one that does not fit
    /// ends the event incomplete.
    fn push(&mut self, record: &GroupRecord<'_>) {
        if !self.recording || self.incomplete {
            return;
        }
        if self.index >= self.budget {
            self.incomplete = true;
            return;
        }
        let encoded = self
            .buffer
            .get_mut(self.length..self.limit)
            .and_then(|room| record.encode(room).ok());
        let total = encoded.and_then(|length| self.length.checked_add(length));
        match (total, self.index.checked_add(1)) {
            (Some(total), Some(next)) => {
                self.length = total;
                self.index = next;
            }
            _ => self.incomplete = true,
        }
    }

    /// Records an operation's outcome; a length past `u32` cannot be
    /// recorded, and ends the event incomplete.
    fn outcome(
        &mut self,
        (stream_id, session_id): (i32, i32),
        operation: Operation,
        outcome: Outcome,
        bytes: Option<(usize, u32)>,
    ) {
        let Some(index) = self.next_index() else {
            return;
        };
        let (length, crc32c) = match bytes {
            None => (0, 0),
            Some((length, digest)) => match u32::try_from(length) {
                Ok(length) => (length, digest),
                Err(_) => {
                    self.incomplete = true;
                    return;
                }
            },
        };
        self.push(&GroupRecord::Outcome(OutcomeObservation {
            group_seq: self.seq,
            index,
            stream_id,
            session_id,
            operation,
            outcome,
            length,
            crc32c,
        }));
    }

    fn timer(&mut self, timer: TimerId, deadline: u64, action: TimerAction) {
        if let Some(index) = self.next_index() {
            self.push(&GroupRecord::TimerOperation(TimerObservation {
                group_seq: self.seq,
                index,
                timer_id: u64::from(timer.0),
                deadline,
                action,
            }));
        }
    }
}

/// A timer operation's observation length; timer 0 cannot be recorded
/// (template 12's `timer_id` is never 0).
fn recordable_timer(timer: TimerId) -> Option<usize> {
    (timer.0 != 0).then_some(TIMER)
}

/// Whether `length` fits template 11's `length`.
fn recordable(length: usize) -> Option<usize> {
    u32::try_from(length).ok().map(|_| OUTCOME)
}

impl<P: Port> Effects for Recording<'_, P> {
    fn clock(&self) -> u64 {
        self.logical_time
    }

    fn offer(&mut self, publication: PublicationId, payload: &[u8]) -> Outcome {
        if !self.admit(recordable(payload.len())) {
            return Outcome::Gated;
        }
        let ids = self.port.publication(publication);
        let outcome = self.port.offer(publication, payload);
        self.outcome(
            ids,
            Operation::Offer,
            outcome,
            Some((payload.len(), crc32c(payload))),
        );
        outcome
    }

    fn claim(
        &mut self,
        publication: PublicationId,
        length: usize,
        write: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> ClaimCommit {
        let both = recordable(length).and_then(|one| one.checked_mul(2));
        if !self.admit(both) {
            return ClaimCommit {
                claim: Outcome::Gated,
                commit: None,
            };
        }
        let ids = self.port.publication(publication);
        let mut digest = 0;
        let result = self.port.claim(publication, length, &mut |bytes| {
            let commit = write(bytes);
            digest = crc32c(bytes);
            commit
        });
        self.outcome(ids, Operation::Claim, result.claim, None);
        if let Some(commit) = result.commit {
            self.outcome(ids, Operation::Commit, commit, Some((length, digest)));
        }
        result
    }

    fn poll_outcomes(
        &mut self,
        publication: PublicationId,
        max: u32,
        each: &mut dyn FnMut(&DeliveryOutcome),
    ) -> u32 {
        let most = usize::try_from(max)
            .ok()
            .and_then(|max| max.checked_mul(DELIVERY))
            .and_then(|deliveries| deliveries.checked_add(POLL));
        if !self.admit(most) {
            return 0;
        }
        let (stream_id, session_id) = self.port.publication(publication);
        let poll = |index: u32, count: u32, seq: u64| {
            GroupRecord::Poll(DeliveryPoll {
                group_seq: seq,
                index,
                max,
                count,
                stream_id,
                session_id,
            })
        };
        // The poll goes first with no deliveries, and is rewritten in place
        // with the count recorded: its length does not change.
        let at = self.length;
        let poll_index = self.next_index();
        if let Some(index) = poll_index {
            self.push(&poll(index, 0, self.seq));
        }
        let mut recorded = 0u32;
        let presented = {
            let this = &mut *self;
            let port = &mut *this.port;
            let mut deliveries = |outcome: &DeliveryOutcome| {
                each(outcome);
                let Some(index) = (this.recording && !this.incomplete).then_some(this.index) else {
                    return;
                };
                let record = GroupRecord::Delivery(DeliveryObservation {
                    group_seq: this.seq,
                    index,
                    stream_id,
                    session_id,
                    kind: outcome.kind,
                    lane: outcome.lane,
                    receiver: outcome.receiver,
                    incarnation: outcome.incarnation,
                    start: outcome.start,
                    end: outcome.end,
                    epoch: outcome.epoch,
                    reason: outcome.reason,
                    lost: outcome.lost,
                });
                let encoded = this
                    .buffer
                    .get_mut(this.length..this.limit)
                    .and_then(|room| record.encode(room).ok());
                let total = encoded.and_then(|length| this.length.checked_add(length));
                match (total, index.checked_add(1), recorded.checked_add(1)) {
                    (Some(total), Some(next), Some(count)) => {
                        this.length = total;
                        this.index = next;
                        recorded = count;
                    }
                    _ => this.incomplete = true,
                }
            };
            port.poll_outcomes(publication, max, &mut deliveries)
        };
        if let Some(index) = poll_index
            && let Some(room) = self.buffer.get_mut(at..)
        {
            // Same length as before, so it fits where it was.
            let _ = poll(index, recorded, self.seq).encode(room);
        }
        presented
    }

    fn schedule(&mut self, timer: TimerId, deadline: u64) {
        if !self.admit(recordable_timer(timer)) {
            return;
        }
        self.port.schedule(timer, deadline);
        if let Some(slot) = self.deadlines.get_mut(usize::from(timer.0)) {
            *slot = Some(deadline);
        }
        self.timer(timer, deadline, TimerAction::Create);
    }

    /// A cancel repeats the timer's pending deadline; one not pending
    /// records 0.
    fn cancel(&mut self, timer: TimerId) {
        if !self.admit(recordable_timer(timer)) {
            return;
        }
        self.port.cancel(timer);
        let deadline = self
            .deadlines
            .get_mut(usize::from(timer.0))
            .and_then(Option::take)
            .unwrap_or(0);
        self.timer(timer, deadline, TimerAction::Cancel);
    }

    fn external(&mut self, kind: u32, read: &mut dyn FnMut(&mut [u8]) -> usize) -> &[u8] {
        let length = read(self.scratch).min(self.scratch.len());
        if self.admit(EXTERNAL.checked_add(length))
            && let Some(index) = self.next_index()
        {
            let value = self.scratch.get(..length).unwrap_or_default();
            let record = GroupRecord::ExternalObservation(ExternalObservation {
                group_seq: self.seq,
                index,
                kind,
                value,
            });
            let encoded = self
                .buffer
                .get_mut(self.length..self.limit)
                .and_then(|room| record.encode(room).ok());
            let total = encoded.and_then(|written| self.length.checked_add(written));
            match (total, index.checked_add(1)) {
                (Some(total), Some(next)) => {
                    self.length = total;
                    self.index = next;
                }
                _ => self.incomplete = true,
            }
        }
        self.scratch.get(..length).unwrap_or_default()
    }
}
