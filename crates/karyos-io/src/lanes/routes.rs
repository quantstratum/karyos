// SPDX-License-Identifier: Apache-2.0

//! Lane selection over redundant paths (`quantstratum-docs:
//! karyos/design/redundant-paths.md` section 7, RP-10; L7): one DRR over
//! the lanes, and one TX queue per lane on each route.
//!
//! The packetizer commits each datagram of a lane once per route, a copy
//! in that route's own frame pool, and records each copy with its stream
//! `position` ([`RoutedLaneSender::staged`]). A route that cannot take a
//! copy skips it ([`RoutedLaneSender::skipped`], counted per route): its
//! next copy is a later position. The DRR selects a lane once. Its head is
//! the lowest position staged on any route and not yet debited. Every route
//! whose queue holds that head flushes its copy, in route order, each
//! through the gate at its own exposure. The first route that reports it
//! `Submitted` debits the lane, once, by its charge; a copy submitted on a
//! later route, or later, debits nothing.
//!
//! - **No route submitted.** An `Unknown` copy suspends its route only,
//!   and the head is uncertain only when no route served it; a route
//!   without room makes the call stop as backpressure only when no route
//!   served it either. A copy the gate denies pauses its route for the
//!   call. So a lane stays eligible while one route can still send its
//!   head.
//! - **Catching up.** A route behind the debited position (its copy was
//!   kept pending while another route submitted) flushes its older copies
//!   in [`RoutedLaneSender::catch_up`], one per route and lane per call,
//!   which debits nothing.
//! - **One route.** With one route the sender takes the same DRR steps as
//!   [`super::LaneSender`]: the tests run both side by side.
//!
//! Every allocation happens in [`RoutedLaneSender::new`]; the data calls do
//! not allocate.

use std::collections::VecDeque;

use core::num::NonZeroU16;

use karyos_protocol::lanes::drr::{
    Budget, Drr, DrrConfig, DrrError, LaneSource, Probe, Report, Service, Stop,
};

use super::{LaneGate, Left, SenderFailure, SenderReport, StageError, Staged};
use crate::backend::{
    BackendFailure, FlushRequest, FlushStop, PendingCause, QueueError, TxBackend, TxItemOutcome,
    TxQueueId, TxReport,
};

/// The most routes of one sender: the channel URI allows four paths.
pub const MAX_ROUTES: usize = 4;

/// The TX halves of a routed sender's routes, lent one at a time.
pub trait Routes {
    /// The backend of each route.
    type Backend: TxBackend;

    /// Route `route`'s TX half, if it is attached.
    fn route(&mut self, route: usize) -> Option<&mut Self::Backend>;
}

/// One copy of a datagram, committed to one route's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedStaged {
    /// The copy: its ticket in the route's backend, its charge and length.
    pub staged: Staged,
    /// The datagram's stream position: the same on every route.
    pub position: u64,
}

/// Per route counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RouteCounters {
    /// Copies the packetizer could not stage on this route (no room): the
    /// route skipped those datagrams (RP-8 feeds on this).
    pub skipped: u64,
    /// Copies this route submitted after another had debited them.
    pub late: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

#[derive(Debug)]
struct RouteLane {
    queue: TxQueueId,
    staged: VecDeque<RoutedStaged>,
    /// An uncertain copy awaits the control path.
    suspended: bool,
    /// The queue is faulted, closed or without its route.
    control: bool,
    /// Ineligible for the rest of the current call.
    paused: bool,
}

#[derive(Debug)]
struct Lane {
    routes: Vec<RouteLane>,
    bound: usize,
    /// The highest position debited on this lane.
    debited: Option<u64>,
}

impl Lane {
    /// The lowest position not yet debited, among the routes that may send
    /// now, with its charge.
    fn head(&self) -> Option<(u64, u64)> {
        self.routes
            .iter()
            .filter(|route| !(route.suspended || route.control || route.paused))
            .filter_map(|route| {
                route
                    .staged
                    .iter()
                    .find(|copy| self.debited.is_none_or(|debited| copy.position > debited))
            })
            .map(|copy| (copy.position, copy.staged.charge))
            .min_by_key(|(position, _)| *position)
    }
}

/// A DRR sender over one TX queue per lane on each of its routes.
#[derive(Debug)]
pub struct RoutedLaneSender {
    drr: Drr,
    lanes: Vec<Lane>,
    max_charge: u64,
    report: TxReport,
    counters: [RouteCounters; MAX_ROUTES],
}

impl RoutedLaneSender {
    /// A sender of `config`'s lanes over `queues`: per route, one queue per
    /// lane in lane order, each recording at most `bound` copies.
    /// Allocates every buffer it will use.
    ///
    /// # Errors
    ///
    /// [`DrrError::InvalidConfig`] when there are no routes, more than
    /// [`MAX_ROUTES`], or a route that does not name one queue per lane.
    pub fn new(config: DrrConfig, queues: &[&[TxQueueId]], bound: usize) -> Result<Self, DrrError> {
        if queues.is_empty()
            || queues.len() > MAX_ROUTES
            || queues.iter().any(|route| route.len() != config.lanes())
        {
            return Err(DrrError::InvalidConfig);
        }
        let max_charge = config.max_charge();
        let lanes = (0..config.lanes())
            .map(|lane| Lane {
                routes: queues
                    .iter()
                    .filter_map(|route| route.get(lane))
                    .map(|&queue| RouteLane {
                        queue,
                        staged: VecDeque::with_capacity(bound),
                        suspended: false,
                        control: false,
                        paused: false,
                    })
                    .collect(),
                bound,
                debited: None,
            })
            .collect();
        Ok(Self {
            drr: Drr::new(config),
            lanes,
            max_charge,
            report: TxReport::new(),
            counters: [RouteCounters::default(); MAX_ROUTES],
        })
    }

    /// The DRR state, for diagnostics.
    #[must_use]
    pub fn drr(&self) -> &Drr {
        &self.drr
    }

    /// Route `route`'s counters.
    #[must_use]
    pub fn counters(&self, route: usize) -> Option<RouteCounters> {
        self.counters.get(route).copied()
    }

    /// Records a copy the packetizer committed to `lane`'s queue on
    /// `route`, at its tail.
    ///
    /// # Errors
    ///
    /// See [`StageError`]; nothing is recorded on error.
    pub fn staged(
        &mut self,
        lane: usize,
        route: usize,
        copy: RoutedStaged,
    ) -> Result<(), StageError> {
        let staged = copy.staged;
        if staged.charge == 0 || staged.charge > self.max_charge {
            return Err(StageError::InvalidCharge {
                charge: staged.charge,
                max: self.max_charge,
            });
        }
        if u64::from(staged.len) > staged.charge {
            return Err(StageError::LengthAboveCharge {
                len: staged.len,
                charge: staged.charge,
            });
        }
        let entry = self
            .lanes
            .get_mut(lane)
            .ok_or(StageError::UnknownLane { lane })?;
        let bound = entry.bound;
        let queue = entry
            .routes
            .get_mut(route)
            .ok_or(StageError::UnknownLane { lane })?;
        if queue.staged.len() >= bound {
            return Err(StageError::Full { lane });
        }
        queue.staged.push_back(copy);
        Ok(())
    }

    /// `route` could not take a copy of `lane`'s next datagram (no room):
    /// the route skips it, counted (RP-8).
    pub fn skipped(&mut self, route: usize) {
        if let Some(counters) = self.counters.get_mut(route) {
            match counters.skipped.checked_add(1) {
                Some(next) => counters.skipped = next,
                None => counters.overflowed = true,
            }
        }
    }

    /// Copies of `lane` on `route` not yet reported.
    #[must_use]
    pub fn pending(&self, lane: usize, route: usize) -> Option<usize> {
        self.lanes
            .get(lane)
            .and_then(|entry| entry.routes.get(route))
            .map(|queue| queue.staged.len())
    }

    /// Whether `lane` on `route` waits for the control path.
    #[must_use]
    pub fn needs_control(&self, lane: usize, route: usize) -> Option<bool> {
        self.lanes
            .get(lane)
            .and_then(|entry| entry.routes.get(route))
            .map(|queue| queue.suspended || queue.control)
    }

    /// The highest position debited on `lane`, if any.
    #[must_use]
    pub fn debited(&self, lane: usize) -> Option<u64> {
        self.lanes.get(lane).and_then(|entry| entry.debited)
    }

    /// The control path cleared `lane`'s send fault on `route` with
    /// `retry_queue`: the queue keeps its pending copies.
    pub fn retry(&mut self, lane: usize, route: usize) {
        if let Some(queue) = self
            .lanes
            .get_mut(lane)
            .and_then(|entry| entry.routes.get_mut(route))
        {
            queue.control = false;
        }
    }

    /// The control path gave `lane` a new `queue` on `route`, after that
    /// route's endpoint reset or `close_queue`: its copies are dropped.
    pub fn reopen(&mut self, lane: usize, route: usize, queue: TxQueueId) {
        if let Some(entry) = self
            .lanes
            .get_mut(lane)
            .and_then(|entry| entry.routes.get_mut(route))
        {
            entry.queue = queue;
            entry.staged.clear();
            entry.suspended = false;
            entry.control = false;
        }
    }

    /// Returns the pending copies of `lane` that were never exposed, on
    /// every route, for a lane its gate aborted (as
    /// [`super::LaneSender::cancel`] does for one route): each leaves
    /// through `gate` as [`Left::Returned`], in staging order.
    ///
    /// # Errors
    ///
    /// The first route's [`QueueError`] from
    /// [`TxBackend::cancel_pending`]; the routes after it are not cancelled.
    pub fn cancel<R: Routes, G: LaneGate>(
        &mut self,
        routes: &mut R,
        lane: usize,
        gate: &mut G,
    ) -> Result<(), QueueError> {
        let Self { lanes, report, .. } = self;
        let Some(entry) = lanes.get_mut(lane) else {
            return Ok(());
        };
        for (index, queue) in entry.routes.iter_mut().enumerate() {
            let Some(backend) = routes.route(index) else {
                continue;
            };
            'route: loop {
                let outcome = backend.cancel_pending(queue.queue, report)?;
                while let Some(item) = report.pop_front() {
                    match queue.staged.front().copied() {
                        Some(head) if head.staged.ticket == item.ticket => {
                            queue.staged.pop_front();
                            gate.left(lane, head.staged, Left::Returned);
                        }
                        _ => {
                            while report.pop_front().is_some() {}
                            break 'route;
                        }
                    }
                }
                if !outcome.more {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Flushes, on each route, at most one copy of each lane that another
    /// route already debited (a route that fell behind). It debits nothing
    /// and asks `gate` at each exposure. Returns the copies submitted.
    pub fn catch_up<R: Routes, G: LaneGate>(&mut self, routes: &mut R, gate: &mut G) -> u32 {
        let Self {
            lanes,
            report,
            counters,
            ..
        } = self;
        let mut submitted = 0u32;
        for (lane, entry) in lanes.iter_mut().enumerate() {
            let Some(debited) = entry.debited else {
                continue;
            };
            for (index, queue) in entry.routes.iter_mut().enumerate() {
                if queue.suspended || queue.control {
                    continue;
                }
                let Some(head) = queue.staged.front().copied() else {
                    continue;
                };
                if head.position > debited {
                    continue;
                }
                let Some(backend) = routes.route(index) else {
                    continue;
                };
                gate.flushing(lane);
                match flush_one(backend, gate, report, queue.queue, head) {
                    Flushed::Submitted => {
                        queue.staged.pop_front();
                        gate.left(lane, head.staged, Left::Submitted);
                        // At most one copy per route and lane: no overflow.
                        if let Some(next) = submitted.checked_add(1) {
                            submitted = next;
                        }
                        if let Some(counters) = counters.get_mut(index) {
                            match counters.late.checked_add(1) {
                                Some(next) => counters.late = next,
                                None => counters.overflowed = true,
                            }
                        }
                    }
                    Flushed::Returned => {
                        queue.staged.pop_front();
                        gate.left(lane, head.staged, Left::Returned);
                    }
                    Flushed::Unknown => {
                        queue.staged.pop_front();
                        queue.suspended = true;
                        gate.left(lane, head.staged, Left::Unknown);
                    }
                    // Tried again on the next call.
                    Flushed::Denied | Flushed::Blocked | Flushed::Again | Flushed::Inactive => {}
                    Flushed::Hold | Flushed::Fail(_) => queue.control = true,
                }
            }
        }
        submitted
    }

    /// Serves the lanes within `budget` over `routes`, asking `gate` at
    /// each probe and at each route's exposure.
    pub fn serve<R: Routes, G: LaneGate>(
        &mut self,
        routes: &mut R,
        gate: &mut G,
        budget: Budget,
    ) -> SenderReport {
        for lane in &mut self.lanes {
            for route in &mut lane.routes {
                route.paused = false;
            }
        }
        let mut source = Source {
            routes,
            gate,
            lanes: &mut self.lanes,
            report: &mut self.report,
            counters: &mut self.counters,
            failure: None,
            inactive: false,
        };
        let drr: Report = self.drr.run(budget, &mut source);
        let failure = source.failure.or(match drr.stop {
            Stop::Failed(error) => Some(SenderFailure::Drr(error)),
            _ => None,
        });
        SenderReport {
            drr,
            failure,
            inactive: source.inactive,
        }
    }
}

/// What one flush of one copy did.
enum Flushed {
    Submitted,
    Returned,
    Unknown,
    /// The gate denied it at exposure.
    Denied,
    /// The socket had no room.
    Blocked,
    /// Interrupted or a peer error: try again.
    Again,
    /// The queue is faulted, closed or unrouted.
    Hold,
    /// The endpoint is resetting or retired.
    Inactive,
    /// The sender or the backend broke.
    Fail(FlushStop),
}

/// Flushes `head`, the front copy of `queue`, through `backend`.
fn flush_one<B: TxBackend, G: LaneGate>(
    backend: &mut B,
    gate: &mut G,
    report: &mut TxReport,
    queue: TxQueueId,
    head: RoutedStaged,
) -> Flushed {
    let request = FlushRequest {
        queue,
        max_datagrams: NonZeroU16::MIN,
        max_bytes: u32::from(head.staged.len),
    };
    let outcome = backend.flush(request, gate, report);
    let reported = report.pop_front();
    let extra = report.pop_front().is_some();
    while report.pop_front().is_some() {}
    let stop = outcome.stop;
    let Some(item) = reported else {
        return match stop {
            FlushStop::Queue(QueueError::NotActive) => Flushed::Inactive,
            FlushStop::Queue(
                QueueError::UnknownQueue | QueueError::RouteUnknown | QueueError::NeedsReset,
            )
            | FlushStop::Faulted(_)
            | FlushStop::Failed(BackendFailure::Invariant { .. }) => Flushed::Hold,
            _ => Flushed::Fail(stop),
        };
    };
    if extra || item.ticket != head.staged.ticket {
        return Flushed::Fail(stop);
    }
    match item.outcome {
        TxItemOutcome::Submitted { .. } => Flushed::Submitted,
        TxItemOutcome::Returned { .. } => Flushed::Returned,
        TxItemOutcome::Unknown => Flushed::Unknown,
        TxItemOutcome::Pending { cause } => match cause {
            PendingCause::GateDenied => Flushed::Denied,
            PendingCause::Interrupted | PendingCause::PeerError => Flushed::Again,
            PendingCause::WouldBlock | PendingCause::NoBuffers => Flushed::Blocked,
            PendingCause::Faulted(_) | PendingCause::Failed(BackendFailure::Invariant { .. }) => {
                Flushed::Hold
            }
            PendingCause::ErrorLost | PendingCause::NotAttempted | PendingCause::Failed(_) => {
                Flushed::Fail(stop)
            }
        },
    }
}

/// The DRR's view of the lanes for one call.
struct Source<'a, R, G> {
    routes: &'a mut R,
    gate: &'a mut G,
    lanes: &'a mut [Lane],
    report: &'a mut TxReport,
    counters: &'a mut [RouteCounters; MAX_ROUTES],
    failure: Option<SenderFailure>,
    inactive: bool,
}

impl<R: Routes, G: LaneGate> LaneSource for Source<'_, R, G> {
    fn probe(&mut self, lane: usize) -> Probe {
        if self.failure.is_some() || self.inactive {
            return Probe::Ineligible;
        }
        let Some((_, charge)) = self.lanes.get(lane).and_then(Lane::head) else {
            return Probe::Ineligible;
        };
        if self.gate.admits(lane) {
            Probe::Eligible { charge }
        } else {
            Probe::Ineligible
        }
    }

    fn serve(&mut self, lane: usize) -> Service {
        let Some(entry) = self.lanes.get_mut(lane) else {
            return Service::NotServed;
        };
        let Some((position, _)) = entry.head() else {
            return Service::NotServed;
        };
        let (mut served, mut uncertain, mut blocked) = (false, false, false);
        for (index, queue) in entry.routes.iter_mut().enumerate() {
            if queue.suspended || queue.control || queue.paused {
                continue;
            }
            let Some(head) = queue.staged.front().copied() else {
                continue;
            };
            if head.position != position {
                continue;
            }
            let Some(backend) = self.routes.route(index) else {
                continue;
            };
            self.gate.flushing(lane);
            match flush_one(backend, self.gate, self.report, queue.queue, head) {
                Flushed::Submitted => {
                    queue.staged.pop_front();
                    self.gate.left(lane, head.staged, Left::Submitted);
                    if served && let Some(counters) = self.counters.get_mut(index) {
                        match counters.late.checked_add(1) {
                            Some(next) => counters.late = next,
                            None => counters.overflowed = true,
                        }
                    }
                    served = true;
                }
                Flushed::Returned => {
                    queue.staged.pop_front();
                    self.gate.left(lane, head.staged, Left::Returned);
                }
                Flushed::Unknown => {
                    queue.staged.pop_front();
                    queue.suspended = true;
                    self.gate.left(lane, head.staged, Left::Unknown);
                    uncertain = true;
                }
                Flushed::Denied => queue.paused = true,
                Flushed::Blocked => {
                    queue.paused = true;
                    blocked = true;
                }
                Flushed::Again => {}
                Flushed::Hold => queue.control = true,
                Flushed::Inactive => {
                    queue.paused = true;
                    blocked = true;
                }
                Flushed::Fail(stop) => {
                    self.failure = Some(SenderFailure::Invariant { lane, stop });
                    return Service::Halt;
                }
            }
        }
        if served {
            entry.debited = Some(position);
            return Service::Served;
        }
        if uncertain {
            return Service::Uncertain;
        }
        if blocked {
            return Service::Backpressure;
        }
        Service::NotServed
    }
}

#[cfg(test)]
mod tests;
