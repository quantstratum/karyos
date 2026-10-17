// SPDX-License-Identifier: Apache-2.0

//! The guard gate of a lane sender (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, The sender gate and applied epoch,
//! and Rate limits; `driver-network-agents.md` 6.1; G-e2b).
//!
//! A [`GuardGate`] serves one guard for one [`LaneSender`]: the sender's
//! DRR lanes are one publication's lanes, each one guarded incarnation's
//! lane bound to the open epoch it was admitted under. The gate is both
//! the probe's predicate ([`LaneGate::admits`]) and the exposure-time check
//! ([`SenderGate::check`]):
//!
//! - **Guard.** One Acquire load of the guard word per call. A word other
//!   than exactly `(e, Open)` denies and puts the lane's incarnation in
//!   `Aborting` for good; a later reopen cannot resume it. If the observed
//!   epoch is above the applied epoch, the gate publishes it once, with the
//!   last positions submitted per lane and the work in flight, through its
//!   [`AppliedEpoch`] cell, which this gate alone writes; the between gates
//!   step publishes again as that work drains, for the effective-close
//!   acknowledgement (`crate::guard_ack`).
//! - **Rate.** The authoritative bucket of the publication, one per gate:
//!   a channel's lanes are one publication (GC-5, ACS 15344). A datagram
//!   costs one message token per message it starts and its length in byte
//!   tokens. A head the bucket cannot pay for is held in order, never
//!   skipped; its lane is ineligible, so it forfeits its DRR deficit as any
//!   lane its gate closed, and with the bucket empty every lane is held.
//!   Tokens are reserved when an exposure is permitted and kept once the
//!   head is reported submitted (or unknown, which may have left). A head
//!   exposed again while pending is not charged twice; a head that left
//!   without exposure, or that an abort or a reopen drops, gets its tokens
//!   back. Only first sends are charged.
//! - **Faults.** The sender says which lane it flushes
//!   ([`LaneGate::flushing`]); an exposure that is not that lane's next
//!   heads, in order, is a sender fault: denied, and the lane aborts for
//!   good with [`AbortCause::Fault`] for the control path to report.
//!
//! - **Routes.** A publication over redundant paths (redundant-paths.md
//!   RP-10; rp-w4b2a) has one gate over a [`RoutedLaneSender`]: each lane
//!   keeps one ring of heads per route, in that route's order, and an
//!   exposure is placed on the route whose next head carries its first
//!   token (tokens are unique across a publication's routes). Every
//!   exposure on every route loads the guard, so a close between two
//!   routes' exposures denies the later one. A position is charged once,
//!   at its first permitted copy, and its tokens come back only when no
//!   copy of it is left on any route and none was sent. The submitted
//!   positions are the highest position submitted on any route, and the
//!   work in flight counts every route's.
//!
//! The gate and its sender stay in step through [`GuardGate::stage`] and
//! [`GuardGate::reopen`] (or [`GuardGate::stage_copy`] and
//! [`GuardGate::reopen_route`] over routes), which act on both; the sender
//! reports each head that left its queue through [`LaneGate::left`]
//! ([`LaneSender::reopen`] alone does not, so a reopen goes through the
//! gate). The gate allocates only in [`GuardGate::new`].
//!
//! [`LaneSender`]: karyos_io::lanes::LaneSender
//! [`LaneSender::reopen`]: karyos_io::lanes::LaneSender::reopen
//! [`RoutedLaneSender`]: karyos_io::lanes::routes::RoutedLaneSender

use std::collections::VecDeque;
use std::sync::Arc;

use core::num::NonZeroU16;

use karyos_client::SharedWords;
use karyos_io::backend::{Exposure, GateDecision, SenderGate, SenderToken, TxQueueId, TxTicket};
use karyos_io::lanes::routes::{MAX_ROUTES, RoutedLaneSender, RoutedStaged};
use karyos_io::lanes::{LaneGate, LaneSender, Left, StageError, Staged};
use karyos_sys::applied_epoch::{Applied, AppliedEpoch};
use karyos_sys::frame::Lane;
use karyos_sys::guard::{self, GuardState};
use karyos_sys::rate_limit::{RateLimiter, RatePolicy, RatePolicyError};

/// One DRR lane of a gate: a guarded incarnation's publication lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateLane {
    /// The publication lane, which indexes the applied positions.
    pub lane: Lane,
    /// The open epoch the incarnation was admitted under.
    pub epoch: u64,
    /// Heads the lane may record: its queue's bound.
    pub bound: usize,
}

/// A datagram staged on a lane, as the gate charges it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateHead {
    /// The token the datagram was committed with.
    pub token: SenderToken,
    /// Its length in bytes: its byte charge.
    pub length: u64,
    /// The messages it starts (frames that begin a message): its message
    /// charge (`quantstratum-docs: karyos/design/aggregate-lanes.md`, a
    /// datagram may carry several frames).
    pub messages: u64,
    /// The stream position just past it.
    pub end: u64,
}

/// Why a gate could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    /// The policy cannot be enforced: a zero rate or burst, or a byte burst
    /// below the largest datagram the route builds, which would then wait
    /// for good.
    #[error(transparent)]
    InvalidRatePolicy(RatePolicyError),
    /// The gate's lanes are not the sender's lanes, one for one.
    #[error("the gate has {gate} lanes, not the sender's")]
    LaneCount {
        /// The gate's lane count.
        gate: usize,
    },
}

/// Why [`GuardGate::stage`] refused a head; nothing is recorded on error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GateStageError {
    /// No such lane.
    #[error("no gate lane {lane}")]
    UnknownLane {
        /// The lane named.
        lane: usize,
    },
    /// The lane already records its bound.
    #[error("gate lane {lane} is full")]
    Full {
        /// The lane named.
        lane: usize,
    },
    /// The gate's record of the lane and the sender's disagree.
    #[error("gate lane {lane} is out of step with its sender")]
    OutOfStep {
        /// The lane named.
        lane: usize,
    },
    /// The sender refused the record.
    #[error(transparent)]
    Sender(StageError),
}

/// Why a lane's incarnation is aborting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortCause {
    /// Its guard was no longer its open epoch.
    Guard,
    /// The sender's exposure or report contradicted the gate's record.
    Fault,
}

/// What a gate counted, for the driver's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GateCounts {
    /// Exposure checks run.
    pub checks: u64,
    /// Probes and checks that held a head for its rate: not faults.
    pub rate_held: u64,
    /// Denials because the guard was not the lane's open epoch, once per
    /// incarnation.
    pub guard_denied: u64,
    /// Incarnations that entered `Aborting`.
    pub aborted: u64,
    /// Applied epochs published.
    pub applied: u64,
    /// Exposures or reports that contradicted the gate's record: a sender
    /// fault.
    pub faults: u64,
    /// Guard words that broke the encoding, treated as closed.
    pub corrupt: u64,
    /// Counts that would have overflowed and kept their last value.
    pub overflows: u64,
}

/// Adds one to `count`; at its end it keeps its value and `overflows`
/// counts it (SPEC.md section 14: checked, never wrapped).
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

/// One copy of a datagram on one route.
#[derive(Debug, Clone, Copy)]
struct Head {
    head: GateHead,
    ticket: TxTicket,
    /// It was permitted: backend work in flight until it leaves.
    exposed: bool,
}

/// One position of a lane, as its copies on the routes hold it: charged
/// once, whichever copy is permitted first.
#[derive(Debug, Clone, Copy)]
struct Charge {
    /// The first copy's head: its length, messages and end are every
    /// copy's.
    head: GateHead,
    /// Copies staged and not yet left.
    holders: usize,
    /// Its tokens are reserved.
    charged: bool,
    /// A copy left submitted or unknown: the tokens stay.
    sent: bool,
}

#[derive(Debug)]
struct State {
    lane: Lane,
    epoch: u64,
    /// One ring per route, in that route's order.
    heads: Vec<VecDeque<Head>>,
    /// The positions the rings hold, in position order.
    charges: VecDeque<Charge>,
    bound: usize,
    aborting: Option<AbortCause>,
    /// Per route, heads that left with an unproven exposure (`Unknown`), in
    /// flight until the control path resolves them with a reopen.
    unknown: Vec<u64>,
}

fn refund(limiter: &mut Option<RateLimiter>, charge: &mut Charge) {
    if charge.charged
        && let Some(limiter) = limiter
    {
        limiter.refund_datagram(charge.head.length, charge.head.messages);
    }
    charge.charged = false;
}

/// A copy ending at `end` left its ring, `sent` or not: once no copy of
/// its position is left, the position goes, refunded unless one was sent.
fn settle(limiter: &mut Option<RateLimiter>, charges: &mut VecDeque<Charge>, end: u64, sent: bool) {
    let Some(index) = charges.iter().position(|charge| charge.head.end == end) else {
        return;
    };
    let Some(charge) = charges.get_mut(index) else {
        return;
    };
    charge.sent |= sent;
    // Each ring entry was counted as a holder when staged: never zero here.
    let Some(left) = charge.holders.checked_sub(1) else {
        return;
    };
    charge.holders = left;
    if left == 0 {
        if !charge.sent {
            refund(limiter, charge);
        }
        let _ = charges.remove(index);
    }
}

/// The gate of one guard over one lane sender's lanes.
#[derive(Debug)]
pub struct GuardGate {
    word: Arc<dyn SharedWords>,
    cell: Arc<AppliedEpoch>,
    lanes: Vec<State>,
    /// The publication's bucket, shared by its lanes.
    limiter: Option<RateLimiter>,
    /// The lane the sender is flushing, from [`LaneGate::flushing`].
    flushing: Option<usize>,
    /// The epoch last published to the cell.
    applied: u64,
    /// The in-flight count last published to the cell.
    published_in_flight: u64,
    /// The last position submitted per publication lane.
    submitted: [u64; Lane::COUNT as usize],
    counts: GateCounts,
}

impl GuardGate {
    /// A gate over guard word 0 of `word`, writing its applied epoch to
    /// `cell` (this gate's alone), for `lanes` in the DRR lane order of
    /// `sender`, with the publication's `rate` policy, validated against
    /// the largest datagram the route builds, `max_datagram` bytes: the
    /// smaller of the route's own bound and the stream's MTU, which no
    /// datagram exceeds (aggregate-lanes.md). It is never above the MTU
    /// `guard_stream` validated the policy against, so a policy accepted
    /// there is accepted here. Every buffer it will use is allocated here;
    /// the bucket starts full at clock time `now`.
    ///
    /// # Errors
    ///
    /// [`GateError::InvalidRatePolicy`] and [`GateError::LaneCount`].
    pub fn new(
        word: Arc<dyn SharedWords>,
        cell: Arc<AppliedEpoch>,
        lanes: &[GateLane],
        sender: &LaneSender,
        rate: Option<RatePolicy>,
        max_datagram: u64,
        now: u64,
    ) -> Result<Self, GateError> {
        let gate = lanes.len();
        let matches =
            (0..gate).all(|lane| sender.pending(lane).is_some()) && sender.pending(gate).is_none();
        if !matches {
            return Err(GateError::LaneCount { gate });
        }
        Self::build(word, cell, lanes, 1, rate, max_datagram, now)
    }

    /// [`GuardGate::new`] for a publication over redundant paths: the gate
    /// of `sender`'s lanes on each of its routes (module docs).
    ///
    /// # Errors
    ///
    /// [`GateError::InvalidRatePolicy`] and [`GateError::LaneCount`].
    pub fn new_routed(
        word: Arc<dyn SharedWords>,
        cell: Arc<AppliedEpoch>,
        lanes: &[GateLane],
        sender: &RoutedLaneSender,
        rate: Option<RatePolicy>,
        max_datagram: u64,
        now: u64,
    ) -> Result<Self, GateError> {
        let gate = lanes.len();
        let matches = (0..gate).all(|lane| sender.pending(lane, 0).is_some())
            && sender.pending(gate, 0).is_none();
        if !matches {
            return Err(GateError::LaneCount { gate });
        }
        let routes = (0..MAX_ROUTES)
            .filter(|route| sender.pending(0, *route).is_some())
            .count();
        Self::build(word, cell, lanes, routes, rate, max_datagram, now)
    }

    fn build(
        word: Arc<dyn SharedWords>,
        cell: Arc<AppliedEpoch>,
        lanes: &[GateLane],
        routes: usize,
        rate: Option<RatePolicy>,
        max_datagram: u64,
        now: u64,
    ) -> Result<Self, GateError> {
        if let Some(policy) = rate {
            policy
                .validate(max_datagram)
                .map_err(GateError::InvalidRatePolicy)?;
        }
        let gate = lanes.len();
        let lanes = lanes
            .iter()
            .map(|lane| {
                // Each route's ring holds at most a bound: the positions held
                // on all routes together, at most the bound times the routes.
                let held = lane
                    .bound
                    .checked_mul(routes)
                    .ok_or(GateError::LaneCount { gate })?;
                Ok(State {
                    lane: lane.lane,
                    epoch: lane.epoch,
                    heads: (0..routes)
                        .map(|_| VecDeque::with_capacity(lane.bound))
                        .collect(),
                    charges: VecDeque::with_capacity(held),
                    bound: lane.bound,
                    aborting: None,
                    unknown: vec![0; routes],
                })
            })
            .collect::<Result<Vec<_>, GateError>>()?;
        Ok(Self {
            word,
            cell,
            lanes,
            limiter: rate.map(|policy| RateLimiter::new(policy, now)),
            flushing: None,
            applied: 0,
            published_in_flight: 0,
            submitted: [0; Lane::COUNT as usize],
            counts: GateCounts::default(),
        })
    }

    /// What the gate counted.
    #[must_use]
    pub fn counts(&self) -> GateCounts {
        self.counts
    }

    /// Why `lane`'s incarnation is aborting; `None` while it is not (or for
    /// an unknown lane).
    #[must_use]
    pub fn abort_cause(&self, lane: usize) -> Option<AbortCause> {
        self.lanes.get(lane).and_then(|state| state.aborting)
    }

    /// The last position submitted on publication lane `lane`.
    #[must_use]
    pub fn last_submitted(&self, lane: Lane) -> u64 {
        self.submitted
            .get(usize::from(lane.get()))
            .copied()
            .unwrap_or(0)
    }

    /// Whole message tokens the bucket holds; `None` without a rate.
    #[must_use]
    pub fn message_tokens(&self) -> Option<u64> {
        self.limiter.as_ref().map(RateLimiter::message_tokens)
    }

    /// Whole byte tokens the bucket holds; `None` without a byte rate.
    #[must_use]
    pub fn byte_tokens(&self) -> Option<u64> {
        self.limiter.as_ref().and_then(RateLimiter::byte_tokens)
    }

    /// Refills the bucket from the clock time `now`, before a serve call.
    /// A backward step earns nothing.
    pub fn set_now(&mut self, now: u64) {
        if let Some(limiter) = &mut self.limiter {
            limiter.refill_at(now);
        }
    }

    /// Records a datagram committed to `lane`'s queue, at its tail, in both
    /// `sender` ([`LaneSender::staged`]) and the gate.
    ///
    /// # Errors
    ///
    /// See [`GateStageError`]; nothing is recorded on error.
    pub fn stage(
        &mut self,
        sender: &mut LaneSender,
        lane: usize,
        staged: Staged,
        head: GateHead,
    ) -> Result<(), GateStageError> {
        let state = self
            .lanes
            .get_mut(lane)
            .ok_or(GateStageError::UnknownLane { lane })?;
        let ring = state
            .heads
            .first()
            .ok_or(GateStageError::UnknownLane { lane })?;
        if ring.len() >= state.bound {
            return Err(GateStageError::Full { lane });
        }
        if sender.pending(lane) != Some(ring.len()) {
            return Err(GateStageError::OutOfStep { lane });
        }
        sender
            .staged(lane, staged)
            .map_err(GateStageError::Sender)?;
        state.record(0, staged.ticket, head);
        Ok(())
    }

    /// Records a copy committed to `lane`'s queue on `route`, at its tail,
    /// in both `sender` ([`RoutedLaneSender::staged`]) and the gate.
    ///
    /// # Errors
    ///
    /// See [`GateStageError`]; nothing is recorded on error.
    pub fn stage_copy(
        &mut self,
        sender: &mut RoutedLaneSender,
        lane: usize,
        route: usize,
        copy: RoutedStaged,
        head: GateHead,
    ) -> Result<(), GateStageError> {
        let state = self
            .lanes
            .get_mut(lane)
            .ok_or(GateStageError::UnknownLane { lane })?;
        let ring = state
            .heads
            .get(route)
            .ok_or(GateStageError::UnknownLane { lane })?;
        if ring.len() >= state.bound {
            return Err(GateStageError::Full { lane });
        }
        if sender.pending(lane, route) != Some(ring.len()) {
            return Err(GateStageError::OutOfStep { lane });
        }
        sender
            .staged(lane, route, copy)
            .map_err(GateStageError::Sender)?;
        state.record(route, copy.staged.ticket, head);
        Ok(())
    }

    /// Gives `lane` a new `queue` in `sender` ([`LaneSender::reopen`]),
    /// after an endpoint reset or a queue close: both records go, and the
    /// tokens reserved for them come back, since the reset returned them
    /// unsent.
    pub fn reopen(&mut self, sender: &mut LaneSender, lane: usize, queue: TxQueueId) {
        sender.reopen(lane, queue);
        self.drop_route(lane, 0);
    }

    /// [`GuardGate::reopen`] for `lane` on one `route` of `sender`
    /// ([`RoutedLaneSender::reopen`]): that route's records go; a position
    /// another route still holds keeps its charge.
    pub fn reopen_route(
        &mut self,
        sender: &mut RoutedLaneSender,
        lane: usize,
        route: usize,
        queue: TxQueueId,
    ) {
        sender.reopen(lane, route, queue);
        self.drop_route(lane, route);
    }

    fn drop_route(&mut self, lane: usize, route: usize) {
        let Some(state) = self.lanes.get_mut(lane) else {
            return;
        };
        let State {
            heads,
            charges,
            unknown,
            ..
        } = state;
        if let Some(ring) = heads.get_mut(route) {
            while let Some(entry) = ring.pop_front() {
                settle(&mut self.limiter, charges, entry.head.end, false);
            }
        }
        // The reset settled every item of the old queue.
        if let Some(unknown) = unknown.get_mut(route) {
            *unknown = 0;
        }
    }

    /// `index`'s incarnation aborts for good, once, with `cause`; the
    /// tokens of its heads, which will never be sent, come back.
    fn abort(&mut self, index: usize, cause: AbortCause) {
        if let Some(state) = self.lanes.get_mut(index)
            && state.aborting.is_none()
        {
            state.aborting = Some(cause);
            for charge in &mut state.charges {
                if !charge.sent {
                    refund(&mut self.limiter, charge);
                }
            }
            bump(&mut self.counts.aborted, &mut self.counts.overflows);
        }
    }

    /// The guard is no longer `index`'s open epoch: the incarnation aborts,
    /// and an observed epoch above the applied one is published once, with
    /// the last positions submitted per lane.
    fn apply_close(&mut self, index: usize, observed: Option<GuardState>) {
        self.abort(index, AbortCause::Guard);
        if let Some(observed) = observed
            && observed.epoch > self.applied
        {
            self.applied = observed.epoch;
            self.publish();
            bump(&mut self.counts.applied, &mut self.counts.overflows);
        }
    }

    /// Backend work in flight: heads exposed and not yet left, and heads
    /// that left unproven (or whose report contradicted the record) until a
    /// reopen resolves them (DN-7), on every route. `None` only past `u64`,
    /// which would take 2^64 unresolved reports.
    ///
    /// The count errs high, never low: the matching prefix of a
    /// contradicted exposure, a permitted head the backend keeps pending,
    /// and a head marked exposed in a batch cut short all count until they
    /// leave or a reopen settles them. After those, only a reopen makes a
    /// close effective.
    #[must_use]
    pub fn in_flight(&self) -> Option<u64> {
        self.lanes.iter().try_fold(0u64, |total, state| {
            state
                .heads
                .iter()
                .zip(&state.unknown)
                .try_fold(total, |total, (ring, unknown)| {
                    let exposed = ring.iter().filter(|entry| entry.exposed).count();
                    u64::try_from(exposed)
                        .ok()?
                        .checked_add(*unknown)?
                        .checked_add(total)
                })
        })
    }

    /// Publishes the applied epoch, the submitted positions and the work in
    /// flight, whole (the cell's sequence lock).
    fn publish(&mut self) {
        // An unreachable overflow reports the most work in flight, which
        // never reads as drained.
        let in_flight = self.in_flight().unwrap_or(u64::MAX);
        self.published_in_flight = in_flight;
        self.cell.publish(Applied {
            epoch: self.applied,
            positions: self.submitted,
            in_flight,
        });
    }

    /// A probe or check found the guard closed for a lane that was not
    /// aborting yet: one denial, then the close.
    fn deny_guard(&mut self, index: usize, observed: Option<GuardState>) {
        bump(&mut self.counts.guard_denied, &mut self.counts.overflows);
        self.apply_close(index, observed);
    }

    /// A sender fault on `index`: counted, and terminal for the lane.
    fn fault(&mut self, index: Option<usize>) -> GateDecision {
        bump(&mut self.counts.faults, &mut self.counts.overflows);
        if let Some(index) = index {
            self.abort(index, AbortCause::Fault);
        }
        GateDecision::Deny
    }

    /// The between gates step (`quantstratum-docs:
    /// karyos/design/driver-network-agents.md`, 3.1 step 10 and 6.1): once
    /// per sender cycle, even when nothing was flushed, so a close becomes
    /// effective with no pending traffic. A guard that is no longer a lane's
    /// open epoch aborts that incarnation and publishes the applied epoch,
    /// as a denied exposure does; nothing is exposed here.
    pub fn between_gates(&mut self) {
        let observed = self.load();
        for index in 0..self.lanes.len() {
            let Some(state) = self.lanes.get(index) else {
                continue;
            };
            let open = observed
                == Some(GuardState {
                    epoch: state.epoch,
                    open: true,
                });
            if !open {
                self.apply_close(index, observed);
            }
        }
        // Once a close is applied, the acknowledgement watches its work
        // drain: a changed in-flight count is published again.
        if self.applied > 0 && self.in_flight() != Some(self.published_in_flight) {
            self.publish();
        }
    }

    /// The guard's state from one Acquire load; a corrupt word reads as
    /// `None`, which no epoch admits.
    fn load(&mut self) -> Option<GuardState> {
        match guard::load_in(&*self.word, 0) {
            Ok(state) => Some(state),
            Err(_) => {
                bump(&mut self.counts.corrupt, &mut self.counts.overflows);
                None
            }
        }
    }
}

impl State {
    /// Records a staged copy on `route` and its position.
    fn record(&mut self, route: usize, ticket: TxTicket, head: GateHead) {
        if let Some(ring) = self.heads.get_mut(route) {
            ring.push_back(Head {
                head,
                ticket,
                exposed: false,
            });
        }
        // Copies of one position are staged together on every route, in
        // position order: a held position is at the back or not held.
        match self.charges.back_mut() {
            Some(charge) if charge.head.end == head.end => {
                if let Some(holders) = charge.holders.checked_add(1) {
                    charge.holders = holders;
                }
            }
            _ => self.charges.push_back(Charge {
                head,
                holders: 1,
                charged: false,
                sent: false,
            }),
        }
    }
}

impl SenderGate for GuardGate {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        bump(&mut self.counts.checks, &mut self.counts.overflows);
        // The lane the sender said it flushes; without one the exposure
        // cannot be placed.
        let Some(index) = self.flushing.take() else {
            return self.fault(None);
        };
        let observed = self.load();
        let Some(state) = self.lanes.get(index) else {
            return self.fault(None);
        };
        if state.aborting.is_some() {
            return GateDecision::Deny;
        }
        let open = observed
            == Some(GuardState {
                epoch: state.epoch,
                open: true,
            });
        if !open {
            self.deny_guard(index, observed);
            return GateDecision::Deny;
        }
        // Each candidate must be its route's next head, in order; the
        // prefix whose tokens are reserved is permitted.
        let limiter = &mut self.limiter;
        let Some(state) = self.lanes.get_mut(index) else {
            return self.fault(None);
        };
        let State { heads, charges, .. } = state;
        let ring = candidate.tokens.first().and_then(|first| {
            heads
                .iter_mut()
                .find(|ring| ring.front().is_some_and(|entry| entry.head.token == *first))
        });
        let Some(ring) = ring else {
            return self.fault(Some(index));
        };
        if candidate.tokens.len() > ring.len() {
            return self.fault(Some(index));
        }
        let mut permitted: u16 = 0;
        let mut mismatch = false;
        let mut held = false;
        for (entry, token) in ring.iter_mut().zip(candidate.tokens) {
            if entry.head.token != *token {
                mismatch = true;
                break;
            }
            let Some(charge) = charges
                .iter_mut()
                .find(|charge| charge.head.end == entry.head.end)
            else {
                mismatch = true;
                break;
            };
            if !charge.charged {
                let paid = limiter.as_mut().is_none_or(|limiter| {
                    limiter.try_admit_datagram(charge.head.length, charge.head.messages)
                });
                if !paid {
                    held = true;
                    break;
                }
                charge.charged = true;
            }
            entry.exposed = true;
            let Some(next) = permitted.checked_add(1) else {
                break;
            };
            permitted = next;
        }
        if mismatch {
            // Nothing of a contradicted exposure goes out.
            return self.fault(Some(index));
        }
        if held {
            bump(&mut self.counts.rate_held, &mut self.counts.overflows);
        }
        NonZeroU16::new(permitted)
            .map_or(GateDecision::Deny, |count| GateDecision::Permit { count })
    }
}

impl LaneGate for GuardGate {
    fn admits(&mut self, lane: usize) -> bool {
        let Some(state) = self.lanes.get(lane) else {
            return false;
        };
        // An aborting lane stays ineligible; its denial was counted once.
        if state.aborting.is_some() {
            return false;
        }
        let epoch = state.epoch;
        // The probe asks the gate's rule, so a lane closed by its guard
        // aborts and publishes here as at an exposure (one Acquire load).
        let observed = self.load();
        if observed != Some(GuardState { epoch, open: true }) {
            self.deny_guard(lane, observed);
            return false;
        }
        // The lowest position held: the lane's next head on some route.
        let Some(charge) = self.lanes.get(lane).and_then(|state| state.charges.front()) else {
            return true;
        };
        let affordable = charge.charged
            || self.limiter.as_ref().is_none_or(|limiter| {
                limiter.admits_datagram(charge.head.length, charge.head.messages)
            });
        if !affordable {
            bump(&mut self.counts.rate_held, &mut self.counts.overflows);
        }
        affordable
    }

    fn aborting(&self, lane: usize) -> bool {
        self.lanes
            .get(lane)
            .is_some_and(|state| state.aborting.is_some())
    }

    fn flushing(&mut self, lane: usize) {
        self.flushing = Some(lane);
    }

    fn left(&mut self, lane: usize, staged: Staged, how: Left) {
        let Some(state) = self.lanes.get_mut(lane) else {
            bump(&mut self.counts.faults, &mut self.counts.overflows);
            return;
        };
        let State {
            heads,
            charges,
            unknown,
            lane: publication_lane,
            ..
        } = state;
        // The route whose next head left; with one route, its ring.
        let route = heads
            .iter()
            .position(|ring| {
                ring.front()
                    .is_some_and(|entry| entry.ticket == staged.ticket)
            })
            .or_else(|| (heads.len() == 1).then_some(0));
        let Some((route, entry)) = route.and_then(|route| {
            heads
                .get_mut(route)
                .and_then(VecDeque::pop_front)
                .map(|entry| (route, entry))
        }) else {
            bump(&mut self.counts.faults, &mut self.counts.overflows);
            return;
        };
        if entry.ticket != staged.ticket {
            // The records diverged: the lane cannot be trusted any more, and
            // the item's fate is unknown, so it stays in flight until a
            // reopen, as an `Unknown` one does.
            settle(&mut self.limiter, charges, entry.head.end, false);
            if let Some(count) = unknown.get_mut(route) {
                bump(count, &mut self.counts.overflows);
            }
            self.fault(Some(lane));
            return;
        }
        match how {
            Left::Submitted => {
                if let Some(slot) = self.submitted.get_mut(usize::from(publication_lane.get())) {
                    *slot = (*slot).max(entry.head.end);
                }
                settle(&mut self.limiter, charges, entry.head.end, true);
            }
            // It may have been sent: its charge stays, its position is not
            // counted as submitted, and it stays in flight until a reopen.
            Left::Unknown => {
                if let Some(count) = unknown.get_mut(route) {
                    bump(count, &mut self.counts.overflows);
                }
                settle(&mut self.limiter, charges, entry.head.end, true);
            }
            // It left without exposure: not a send.
            Left::Returned => settle(&mut self.limiter, charges, entry.head.end, false),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod routed_tests;
