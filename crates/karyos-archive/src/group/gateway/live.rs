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
    Capture, DeliveryObservation, DeliveryPoll, EVENT_END, EndOutcome, EventEnd, ExternalEvent,
    ExternalObservation, GapMarker, GapReason, GroupRecord, MAX_INLINE, Operation, Outcome,
    OutcomeObservation, TimerAction, TimerObservation,
};

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
    /// Gap markers written.
    pub gaps: u64,
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
    /// bytes, the sender's own bound.
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
    ) -> Result<Self, ConfigError> {
        if next_seq == 0 {
            return Err(ConfigError::FirstSeq);
        }
        // An external event with an empty value, and its end.
        let least = 12 + 20 + 2 + END;
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
        })
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
        self.stats.gaps = self.stats.gaps.checked_add(1).unwrap_or(self.stats.gaps);
        true
    }

    /// Counts `refusal` by its reason; returns the gap reason it maps to.
    fn count(&mut self, refusal: Refusal) -> GapReason {
        let counter = match refusal {
            Refusal::InFlight => &mut self.stats.in_flight,
            Refusal::TooLarge => &mut self.stats.payload_unavailable,
            _ => &mut self.stats.ring_full,
        };
        *counter = counter.checked_add(1).unwrap_or(*counter);
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
        let flushed = self.flush();
        let refused = if flushed {
            self.sender.admit().err()
        } else {
            // A gap still pending must precede the next recorded event.
            Some(Refusal::RingFull)
        };
        if let Some(refusal) = refused {
            return self.refuse(refusal, event, logical_time, handler);
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
                return self.refuse(refusal, event, logical_time, handler);
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
            incomplete: false,
            recording: true,
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
            self.stats.incomplete = self
                .stats
                .incomplete
                .checked_add(1)
                .unwrap_or(self.stats.incomplete);
        }
        // Admitted, so the ring has room: a refusal here is a failed group.
        self.sender
            .send(written, seq)
            .map_err(|_| GatewayError::Ended)?;
        Ok(Dispatched::Event { group_seq: seq })
    }

    /// An event that cannot be recorded: strict refuses it; best effort
    /// delivers it unrecorded and joins it to the pending gap.
    fn refuse(
        &mut self,
        refusal: Refusal,
        event: &Event<'_>,
        logical_time: u64,
        handler: &mut dyn Handler,
    ) -> Result<Dispatched, GatewayError> {
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
        self.stats.uncaptured = self
            .stats
            .uncaptured
            .checked_add(1)
            .unwrap_or(self.stats.uncaptured);
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
        };
        handler.on_event(event, &mut effects);
    }
}

impl<P: Port, C: FnMut() -> u64> GroupGateway for Gateway<P, C> {
    /// A2b's sources dispatch here; until then there is no event but an
    /// external one, so a dispatch only writes a pending gap.
    fn dispatch(&mut self, _handler: &mut dyn Handler) -> Result<Dispatched, GatewayError> {
        if self.capture == Capture::Strict && self.sender.state() != GroupState::Running {
            return Err(GatewayError::Ended);
        }
        let _ = self.flush();
        Ok(Dispatched::Idle)
    }

    fn deliver_external(
        &mut self,
        kind: u32,
        value: &[u8],
        handler: &mut dyn Handler,
    ) -> Result<Dispatched, GatewayError> {
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

/// The handler's effects during one event: each call performed through
/// the port and, while `recording`, its observation appended to the
/// buffer.
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
}

impl<P: Port> Recording<'_, P> {
    /// Appends `record` as the next observation; one that does not fit
    /// ends the event incomplete.
    fn push(&mut self, record: &GroupRecord<'_>) {
        if !self.recording || self.incomplete {
            return;
        }
        let encoded = self
            .buffer
            .get_mut(self.length..self.limit)
            .and_then(|room| record.encode(room).ok());
        let next = self.index.checked_add(1);
        let total = encoded.and_then(|length| self.length.checked_add(length));
        match (total, next) {
            (Some(total), Some(next)) => {
                self.length = total;
                self.index = next;
            }
            _ => self.incomplete = true,
        }
    }

    /// The observation `index` the next push takes, or `None` when no more
    /// are recorded.
    fn next_index(&self) -> Option<u32> {
        (self.recording && !self.incomplete).then_some(self.index)
    }
}

/// A length as template 11 records it: a payload is at most a frame's,
/// far below `u32`.
fn length_u32(length: usize) -> u32 {
    u32::try_from(length).unwrap_or(u32::MAX)
}

impl<P: Port> Effects for Recording<'_, P> {
    fn clock(&self) -> u64 {
        self.logical_time
    }

    fn offer(&mut self, publication: PublicationId, payload: &[u8]) -> Outcome {
        let (stream_id, session_id) = self.port.publication(publication);
        let outcome = self.port.offer(publication, payload);
        if let Some(index) = self.next_index() {
            self.push(&GroupRecord::Outcome(OutcomeObservation {
                group_seq: self.seq,
                index,
                stream_id,
                session_id,
                operation: Operation::Offer,
                outcome,
                length: length_u32(payload.len()),
                crc32c: crc32c(payload),
            }));
        }
        outcome
    }

    fn claim(
        &mut self,
        publication: PublicationId,
        length: usize,
        write: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> ClaimCommit {
        let (stream_id, session_id) = self.port.publication(publication);
        let mut digest = 0;
        let result = self.port.claim(publication, length, &mut |bytes| {
            let commit = write(bytes);
            digest = crc32c(bytes);
            commit
        });
        if let Some(index) = self.next_index() {
            self.push(&GroupRecord::Outcome(OutcomeObservation {
                group_seq: self.seq,
                index,
                stream_id,
                session_id,
                operation: Operation::Claim,
                outcome: result.claim,
                length: 0,
                crc32c: 0,
            }));
        }
        if let (Some(commit), Some(index)) = (result.commit, self.next_index()) {
            self.push(&GroupRecord::Outcome(OutcomeObservation {
                group_seq: self.seq,
                index,
                stream_id,
                session_id,
                operation: Operation::Commit,
                outcome: commit,
                length: length_u32(length),
                crc32c: digest,
            }));
        }
        result
    }

    fn poll_outcomes(
        &mut self,
        publication: PublicationId,
        max: u32,
        each: &mut dyn FnMut(&DeliveryOutcome),
    ) -> u32 {
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
                match (total, index.checked_add(1)) {
                    (Some(total), Some(next)) => {
                        this.length = total;
                        this.index = next;
                        recorded = recorded.checked_add(1).unwrap_or(recorded);
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
        self.port.schedule(timer, deadline);
        if let Some(index) = self.next_index() {
            self.push(&GroupRecord::TimerOperation(TimerObservation {
                group_seq: self.seq,
                index,
                timer_id: u64::from(timer.0),
                deadline,
                action: TimerAction::Create,
            }));
        }
    }

    fn cancel(&mut self, timer: TimerId) {
        self.port.cancel(timer);
        if let Some(index) = self.next_index() {
            self.push(&GroupRecord::TimerOperation(TimerObservation {
                group_seq: self.seq,
                index,
                timer_id: u64::from(timer.0),
                deadline: 0,
                action: TimerAction::Cancel,
            }));
        }
    }

    fn external(&mut self, kind: u32, read: &mut dyn FnMut(&mut [u8]) -> usize) -> &[u8] {
        let length = read(self.scratch).min(self.scratch.len());
        if let Some(index) = self.next_index() {
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
