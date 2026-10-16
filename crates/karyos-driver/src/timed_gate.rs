// SPDX-License-Identifier: Apache-2.0

//! The timed gate of a lane sender (`quantstratum-docs:
//! karyos/design/timed-tx.md`, section 2 step 4 and section 4; P2.11 T1,
//! step 4, ACS 15436).
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
//!
//! The gate records each datagram's token and time when it is staged
//! ([`TimedGate::stage`], which stages the inner gate and sender in the
//! same step), and moves on as the sender reports each head that left
//! ([`LaneGate::left`]). It allocates only in [`TimedGate::new`].

use std::collections::VecDeque;

use core::num::NonZeroU16;

use karyos_io::backend::{Exposure, GateDecision, SenderGate, SenderToken};
use karyos_io::lanes::{LaneGate, Left, Staged};

/// A staged datagram, as the timed gate holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Head {
    token: SenderToken,
    /// Its message's requested time; `None` for a datagram that waits for
    /// nothing (a lane that is not timed, or a control datagram).
    time: Option<u64>,
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
    /// The largest lateness of a submitted timed head, in the clock's
    /// units: its submission time less its requested time (signed: a clock
    /// set back makes it negative). `None` before the first.
    pub max_lateness: Option<i64>,
    /// Counts that would have overflowed and kept their last value.
    pub overflows: u64,
}

/// Adds one to `count`; at its end it keeps its value and `overflows`
/// counts it (SPEC.md section 14: checked, never wrapped).
fn bump(count: &mut u64, overflows: &mut u64) {
    match count.checked_add(1) {
        Some(next) => *count = next,
        None => *overflows = overflows.saturating_add(1),
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
    lanes: Vec<VecDeque<Head>>,
    bound: usize,
    now: u64,
    flushing: Option<usize>,
    counts: TimedCounts,
}

impl<G: LaneGate> TimedGate<G> {
    /// A gate of `lanes` lanes, each recording up to `bound` heads (its
    /// queue's bound), over `inner`; the clock starts at `now`.
    #[must_use]
    pub fn new(inner: G, lanes: usize, bound: usize, now: u64) -> Self {
        Self {
            inner,
            lanes: (0..lanes).map(|_| VecDeque::with_capacity(bound)).collect(),
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

    /// The earliest time a lane's head waits for, if any head waits: when
    /// the sender should next run.
    #[must_use]
    pub fn earliest(&self) -> Option<u64> {
        self.lanes
            .iter()
            .filter_map(|heads| heads.front().and_then(|head| head.time))
            .filter(|time| *time > self.now)
            .min()
    }

    /// Records a datagram committed to `lane`'s queue with `token`, for a
    /// message requested at `time`, after `inner` stages it in the inner
    /// gate and the sender (`|gate| gate.stage(sender, ...)`, or the
    /// sender's own `staged` for a gate that keeps no record).
    ///
    /// # Errors
    ///
    /// See [`TimedStageError`]; nothing is recorded on error, and `inner`
    /// does not run when this gate refuses.
    pub fn stage<E>(
        &mut self,
        lane: usize,
        token: SenderToken,
        time: Option<u64>,
        inner: impl FnOnce(&mut G) -> Result<(), E>,
    ) -> Result<(), TimedStageError<E>> {
        let heads = self
            .lanes
            .get(lane)
            .ok_or(TimedStageError::UnknownLane { lane })?;
        if heads.len() >= self.bound {
            return Err(TimedStageError::Full { lane });
        }
        inner(&mut self.inner).map_err(TimedStageError::Inner)?;
        if let Some(heads) = self.lanes.get_mut(lane) {
            heads.push_back(Head { token, time });
        }
        Ok(())
    }

    /// Forgets `lane`'s heads after `inner` reopens its queue (the inner
    /// gate's or the sender's `reopen`): the reset returned them unsent.
    pub fn reopen(&mut self, lane: usize, inner: impl FnOnce(&mut G)) {
        inner(&mut self.inner);
        if let Some(heads) = self.lanes.get_mut(lane) {
            heads.clear();
        }
    }

    fn due(&self, head: &Head) -> bool {
        head.time.is_none_or(|time| time <= self.now)
    }
}

impl<G: LaneGate> SenderGate for TimedGate<G> {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        let Some(heads) = self.flushing.take().and_then(|lane| self.lanes.get(lane)) else {
            bump(&mut self.counts.faults, &mut self.counts.overflows);
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
        let due = self
            .lanes
            .get(lane)
            .is_some_and(|heads| heads.front().is_none_or(|head| self.due(head)));
        if inner && !due {
            bump(&mut self.counts.held, &mut self.counts.overflows);
        }
        inner && due
    }

    fn flushing(&mut self, lane: usize) {
        self.flushing = Some(lane);
        self.inner.flushing(lane);
    }

    fn left(&mut self, lane: usize, staged: Staged, how: Left) {
        let head = self.lanes.get_mut(lane).and_then(VecDeque::pop_front);
        match head {
            None => bump(&mut self.counts.faults, &mut self.counts.overflows),
            Some(Head {
                time: Some(time), ..
            }) if how == Left::Submitted => {
                bump(&mut self.counts.sent, &mut self.counts.overflows);
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
