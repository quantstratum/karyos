// SPDX-License-Identifier: Apache-2.0

//! The timed gate of a lane sender (`quantstratum-docs:
//! karyos/design/timed-tx.md`, section 2 step 4, sections 3 and 4; P2.11
//! T1, steps 4 and 5, ACS 15436 and 15455).
//!
//! A [`TimedGate`] wraps another [`LaneGate`] (the guard gate, or any gate
//! of the sender) and holds a timed lane's head until its requested time:
//!
//! - **Eligibility.** A lane is eligible when its head carries no time or
//!   a time at or before the gate's clock ([`TimedGate::set_now`]), and
//!   the inner gate admits it. The inner gate is always asked, so a guard
//!   that closed while a head waits for its time is seen at once.
//! - **Exposure.** Only the prefix of the candidates whose times are due
//!   reaches the inner gate, so it charges nothing for a datagram not yet
//!   due; the permit is the minimum of that prefix and the inner gate's
//!   count. A batch of times `[past, past, future]` permits 2, and the
//!   third goes when its time comes.
//! - **Faults.** An exposure that is not the lane's next heads, in order,
//!   is denied and counted; the inner gate decides what it means for the
//!   lane.
//! - **Lateness.** A timed head submitted more than its lane's tolerance
//!   after its time is a late send, counted. Under cancel-on-deadline
//!   (guards-and-abort.md, G7), a timed head not yet exposed whose time
//!   plus the tolerance has passed aborts the lane for good: it is denied
//!   from then on, counted once, and [`TimedGate::between_gates`] seals its
//!   buffer once with `SealReason::DeadlineMissed`
//!   ([`seal_deadline_missed`]), so every message behind gets the final
//!   record `Aborted` and every one submitted keeps `Submitted`. Nothing
//!   is skipped, and no `SESSION_ABORT` is sent on sockets (O-11, GC-6).
//!   The inner gate is not told (ACS 15455): the heads it holds behind the
//!   miss were never exposed, so never charged, and leave at teardown or a
//!   reopen; its work in flight, which the close acknowledgement reads, is
//!   unchanged. A lane the inner gate already aborts
//!   ([`LaneGate::aborting`], its guard closed) never misses: the loser of
//!   a close against a deadline changes nothing (G7).
//! - **Order between gates.** The driver runs the inner gate's step between
//!   gates (the guard gate's, which applies a close and publishes the
//!   applied epoch) before this gate's [`TimedGate::between_gates`], so a
//!   close observed in that step is the lane's end, and a buffer already
//!   sealed keeps its first reason ([`seal_deadline_missed`]).
//!
//! The gate records each datagram's token and time when it is staged
//! ([`TimedGate::stage`], which stages the inner gate and sender in the
//! same step), and moves on as the sender reports each head that left
//! ([`LaneGate::left`]). It allocates only in [`TimedGate::new`].

use std::collections::VecDeque;

use core::num::NonZeroU16;

use karyos_io::backend::{Exposure, GateDecision, SenderGate, SenderToken, TxTicket};
use karyos_io::lanes::{LaneGate, Left, Staged};
use karyos_sys::error::SysError;
use karyos_sys::log_buffer::{BufferOwner, Conductor, SealReason, SealState};

/// A staged datagram, as the timed gate holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Head {
    token: SenderToken,
    /// The ticket it was committed with, checked when it leaves.
    ticket: TxTicket,
    /// Its message's requested time; `None` for a datagram that waits for
    /// nothing (a lane that is not timed, or a control datagram).
    time: Option<u64>,
    /// Permitted at an exposure: from then on it may have been sent, so
    /// it never misses its deadline.
    exposed: bool,
}

/// A lane's late policy (timed-tx.md, TT-3, and G7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatePolicy {
    /// How far past its time a head may be submitted and not be late, in
    /// the clock's units.
    pub tolerance: u64,
    /// Abort the lane when a head misses its time plus the tolerance,
    /// instead of sending it late.
    pub cancel_on_deadline: bool,
}

impl Default for LatePolicy {
    /// The provisional defaults (TT-3): 1 ms of tolerance, sent late.
    fn default() -> Self {
        Self {
            tolerance: 1_000_000,
            cancel_on_deadline: false,
        }
    }
}

/// One lane of the gate.
#[derive(Debug)]
struct TimedLane {
    heads: VecDeque<Head>,
    policy: LatePolicy,
    /// A head missed its deadline under cancel-on-deadline: for good.
    missed: bool,
    /// The lane's buffer was sealed for the miss.
    sealed: bool,
}

/// Why [`TimedGate::stage`] refused a head; nothing is recorded on error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimedStageError<E> {
    /// No such lane.
    #[error("no timed lane {lane}")]
    UnknownLane {
        /// The lane named.
        lane: usize,
    },
    /// The lane already records its bound.
    #[error("timed lane {lane} is full")]
    Full {
        /// The lane named.
        lane: usize,
    },
    /// The inner gate or the sender refused it.
    #[error(transparent)]
    Inner(E),
}

/// What the timed gate counted, for the driver's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimedCounts {
    /// Probes and exposures that held a head for its time.
    pub held: u64,
    /// Exposures or reports that contradicted the gate's record.
    pub faults: u64,
    /// Timed heads submitted.
    pub sent: u64,
    /// Timed heads submitted beyond their lane's tolerance.
    pub late_sends: u64,
    /// Lanes aborted for a missed deadline, once each.
    pub deadline_aborts: u64,
    /// The largest lateness of a submitted timed head, in the clock's
    /// units: its submission time less its requested time (signed: a clock
    /// set back makes it negative). `None` before the first.
    pub max_lateness: Option<i64>,
    /// Counts that would have overflowed and kept their last value.
    pub overflows: u64,
}

/// Adds one to `count`; at its end it keeps its value and `overflows`
/// counts it, itself kept at its end (SPEC.md section 14: checked, never
/// wrapped).
fn bump(count: &mut u64, overflows: &mut u64) {
    match count.checked_add(1) {
        Some(next) => *count = next,
        None => {
            if let Some(next) = overflows.checked_add(1) {
                *overflows = next;
            }
        }
    }
}

/// `now - time`, signed; `None` when it does not fit an `i64`.
#[must_use]
pub fn lateness(now: u64, time: u64) -> Option<i64> {
    i64::try_from(i128::from(now).checked_sub(i128::from(time))?).ok()
}

/// A lane gate that holds timed heads until their time, over an inner
/// gate `G`.
#[derive(Debug)]
pub struct TimedGate<G> {
    inner: G,
    lanes: Vec<TimedLane>,
    bound: usize,
    now: u64,
    flushing: Option<usize>,
    counts: TimedCounts,
}

impl<G: LaneGate> TimedGate<G> {
    /// A gate of one lane per entry of `policies`, each recording up to
    /// `bound` heads (its queue's bound), over `inner`; the clock starts at
    /// `now`.
    #[must_use]
    pub fn new(inner: G, policies: &[LatePolicy], bound: usize, now: u64) -> Self {
        Self {
            inner,
            lanes: policies
                .iter()
                .map(|policy| TimedLane {
                    heads: VecDeque::with_capacity(bound),
                    policy: *policy,
                    missed: false,
                    sealed: false,
                })
                .collect(),
            bound,
            now,
            flushing: None,
            counts: TimedCounts::default(),
        }
    }

    /// The inner gate.
    #[must_use]
    pub fn inner(&self) -> &G {
        &self.inner
    }

    /// The inner gate, for its own calls (`set_now`, `between_gates`).
    pub fn inner_mut(&mut self) -> &mut G {
        &mut self.inner
    }

    /// What the gate counted.
    #[must_use]
    pub fn counts(&self) -> TimedCounts {
        self.counts
    }

    /// The gate's clock: a head whose time is at or before `now` is due.
    /// The caller sets the inner gate's own clock.
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    /// When the sender should next run, if a lane waits on the clock: the
    /// earliest head time not yet due and, under cancel-on-deadline, the
    /// earliest deadline (time plus tolerance) of a head not yet exposed,
    /// so the idle wait wakes for a miss as for a send. A deadline already
    /// passed means now; a lane the inner gate aborts waits on nothing.
    #[must_use]
    pub fn earliest(&self) -> Option<u64> {
        let now = self.now;
        let heads = self
            .lanes
            .iter()
            .filter(|lane| !lane.missed)
            .filter_map(|lane| lane.heads.front().and_then(|head| head.time))
            .filter(|time| *time > now);
        let deadlines = self
            .lanes
            .iter()
            .enumerate()
            .filter(|(index, lane)| {
                !lane.missed && lane.policy.cancel_on_deadline && !self.inner.aborting(*index)
            })
            .filter_map(|(_, lane)| {
                lane.heads
                    .iter()
                    .filter(|head| !head.exposed)
                    .find_map(|head| head.time)
                    .and_then(|time| time.checked_add(lane.policy.tolerance))
            });
        heads.chain(deadlines).min()
    }

    /// Records a datagram committed to `lane`'s queue with `token` and
    /// `ticket`, for a message requested at `time`, after `inner` stages it
    /// in the inner gate and the sender (`|gate| gate.stage(sender, ...)`,
    /// or the sender's own `staged` for a gate that keeps no record).
    ///
    /// # Errors
    ///
    /// See [`TimedStageError`]; nothing is recorded on error, and `inner`
    /// does not run when this gate refuses.
    pub fn stage<E>(
        &mut self,
        lane: usize,
        token: SenderToken,
        ticket: TxTicket,
        time: Option<u64>,
        inner: impl FnOnce(&mut G) -> Result<(), E>,
    ) -> Result<(), TimedStageError<E>> {
        let state = self
            .lanes
            .get(lane)
            .ok_or(TimedStageError::UnknownLane { lane })?;
        if state.heads.len() >= self.bound {
            return Err(TimedStageError::Full { lane });
        }
        inner(&mut self.inner).map_err(TimedStageError::Inner)?;
        if let Some(state) = self.lanes.get_mut(lane) {
            state.heads.push_back(Head {
                token,
                ticket,
                time,
                exposed: false,
            });
        }
        Ok(())
    }

    /// Forgets `lane`'s heads after `inner` reopens its queue (the inner
    /// gate's or the sender's `reopen`): the reset returned them unsent.
    /// The sender stages them again with their original times: their
    /// schedule entries stay in the ring until their messages leave
    /// (`crate::schedule::ScheduleConsumer`), so re-staging re-times
    /// nothing.
    pub fn reopen(&mut self, lane: usize, inner: impl FnOnce(&mut G)) {
        inner(&mut self.inner);
        if let Some(state) = self.lanes.get_mut(lane) {
            state.heads.clear();
        }
    }

    /// Whether `lane` aborted for a missed deadline.
    #[must_use]
    pub fn deadline_missed(&self, lane: usize) -> bool {
        self.lanes.get(lane).is_some_and(|state| state.missed)
    }

    /// The step between gates: seals, through `seal`, the buffer of every
    /// lane that missed a deadline and is not sealed yet
    /// ([`seal_deadline_missed`] on the lane's conductor). A lane is
    /// sealed once; a second call neither reseals nor recounts.
    ///
    /// # Errors
    ///
    /// The first error of `seal`; every lane is still tried, and a lane
    /// whose seal failed is tried again at the next call.
    pub fn between_gates<E>(
        &mut self,
        mut seal: impl FnMut(usize) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut first_error = None;
        for (index, state) in self.lanes.iter_mut().enumerate() {
            if !state.missed || state.sealed {
                continue;
            }
            match seal(index) {
                Ok(()) => state.sealed = true,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn due(&self, head: &Head) -> bool {
        head.time.is_none_or(|time| time <= self.now)
    }

    /// Whether `lane` may go on: under cancel-on-deadline, its first timed
    /// head not yet exposed must not be past its time plus the tolerance
    /// (`now > time + tolerance`; at the boundary it is not late). A miss
    /// aborts the lane for good, counted once. A deadline that overflows
    /// was refused at offer (`ScheduleOverflow`), so it never misses here.
    fn live(&mut self, lane: usize) -> bool {
        let now = self.now;
        let Some(state) = self.lanes.get_mut(lane) else {
            return false;
        };
        if state.missed {
            return false;
        }
        if !state.policy.cancel_on_deadline {
            return true;
        }
        // A lane the inner gate already aborts (its guard closed) ends
        // that way: a deadline that passes afterwards changes nothing.
        if self.inner.aborting(lane) {
            return true;
        }
        let tolerance = state.policy.tolerance;
        let missed = state
            .heads
            .iter()
            .filter(|head| !head.exposed)
            .find_map(|head| head.time)
            .and_then(|time| time.checked_add(tolerance))
            .is_some_and(|deadline| now > deadline);
        if missed {
            state.missed = true;
            bump(&mut self.counts.deadline_aborts, &mut self.counts.overflows);
        }
        !missed
    }
}

/// Seals a lane's buffer for a missed deadline (G7): `DeadlineMissed`,
/// unless it is already sealed, which keeps its first reason.
///
/// # Errors
///
/// As [`Conductor::seal_with_reason`]: a broken invariant.
pub fn seal_deadline_missed<O: BufferOwner>(conductor: &mut Conductor<O>) -> Result<(), SysError> {
    if conductor.seal_state() == SealState::Active {
        conductor.seal_with_reason(SealReason::DeadlineMissed)?;
    }
    Ok(())
}

impl<G: LaneGate> SenderGate for TimedGate<G> {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        let Some(lane) = self.flushing.take().filter(|lane| *lane < self.lanes.len()) else {
            bump(&mut self.counts.faults, &mut self.counts.overflows);
            return GateDecision::Deny;
        };
        if !self.live(lane) {
            return GateDecision::Deny;
        }
        let Some(heads) = self.lanes.get(lane).map(|state| &state.heads) else {
            return GateDecision::Deny;
        };
        // Each candidate must be the lane's next head, in order.
        let placed = candidate.tokens.len() <= heads.len()
            && heads
                .iter()
                .zip(candidate.tokens)
                .all(|(head, token)| head.token == *token);
        if !placed {
            bump(&mut self.counts.faults, &mut self.counts.overflows);
            return GateDecision::Deny;
        }
        let due = heads
            .iter()
            .take(candidate.tokens.len())
            .take_while(|head| self.due(head))
            .count();
        if due < candidate.tokens.len() {
            bump(&mut self.counts.held, &mut self.counts.overflows);
        }
        let (Some(tokens), Some(lengths)) =
            (candidate.tokens.get(..due), candidate.lengths.get(..due))
        else {
            bump(&mut self.counts.faults, &mut self.counts.overflows);
            return GateDecision::Deny;
        };
        if tokens.is_empty() {
            return GateDecision::Deny;
        }
        // Only the due prefix reaches the inner gate: it charges nothing
        // for a head that is not due.
        let inner = self.inner.check(&Exposure {
            tokens,
            lengths,
            ..*candidate
        });
        match inner {
            GateDecision::Permit { count } => {
                let permitted = usize::from(count.get()).min(due);
                if let Some(state) = self.lanes.get_mut(lane) {
                    for head in state.heads.iter_mut().take(permitted) {
                        head.exposed = true;
                    }
                }
                u16::try_from(permitted)
                    .ok()
                    .and_then(NonZeroU16::new)
                    .map_or(GateDecision::Deny, |count| GateDecision::Permit { count })
            }
            GateDecision::Deny => GateDecision::Deny,
        }
    }
}

impl<G: LaneGate> LaneGate for TimedGate<G> {
    fn admits(&mut self, lane: usize) -> bool {
        // The inner gate first: it observes its guard on every probe.
        let inner = self.inner.admits(lane);
        if !self.live(lane) {
            return false;
        }
        let due = self
            .lanes
            .get(lane)
            .is_some_and(|state| state.heads.front().is_none_or(|head| self.due(head)));
        if inner && !due {
            bump(&mut self.counts.held, &mut self.counts.overflows);
        }
        inner && due
    }

    fn aborting(&self, lane: usize) -> bool {
        self.deadline_missed(lane) || self.inner.aborting(lane)
    }

    fn flushing(&mut self, lane: usize) {
        self.flushing = Some(lane);
        self.inner.flushing(lane);
    }

    fn left(&mut self, lane: usize, staged: Staged, how: Left) {
        let Some(state) = self.lanes.get_mut(lane) else {
            bump(&mut self.counts.faults, &mut self.counts.overflows);
            self.inner.left(lane, staged, how);
            return;
        };
        let tolerance = state.policy.tolerance;
        match state.heads.pop_front() {
            None => bump(&mut self.counts.faults, &mut self.counts.overflows),
            // The records diverged: counted, and the inner gate decides.
            Some(head) if head.ticket != staged.ticket => {
                bump(&mut self.counts.faults, &mut self.counts.overflows);
            }
            Some(Head {
                time: Some(time), ..
            }) if how == Left::Submitted => {
                bump(&mut self.counts.sent, &mut self.counts.overflows);
                // Late beyond the tolerance: at the boundary it is not.
                if self
                    .now
                    .checked_sub(time)
                    .is_some_and(|late| late > tolerance)
                {
                    bump(&mut self.counts.late_sends, &mut self.counts.overflows);
                }
                if let Some(late) = lateness(self.now, time) {
                    self.counts.max_lateness =
                        Some(self.counts.max_lateness.map_or(late, |max| max.max(late)));
                }
            }
            Some(_) => {}
        }
        self.inner.left(lane, staged, how);
    }
}

#[cfg(test)]
mod tests;
