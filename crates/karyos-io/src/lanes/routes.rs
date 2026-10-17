// SPDX-License-Identifier: Apache-2.0

//! Lane selection over redundant paths (`quantstratum-docs:
//! karyos/design/redundant-paths.md` section 7, RP-10; L7): one DRR over
//! the lanes, and one TX queue per lane on each route.
//!
//! The packetizer commits each datagram of a lane once per route, a copy
//! in that route's own frame pool, and records each copy with its stream
//! `position` ([`RoutedLaneSender::staged`]), in increasing order per
//! route. A route that cannot take a copy skips it
//! ([`RoutedLaneSender::skipped`], counted per route): its next copy is a
//! later position.
//!
//! The DRR selects a lane once. Its head is the lowest position not yet
//! debited that any route still holds, and the lane is eligible only when
//! some route can send that head now: the copy is at the front of the
//! route's queue, and the route is not waiting for the control path,
//! paused, blocked or inactive for the call. Every such route flushes its
//! copy, in route order, each through the gate at its own exposure. The
//! first route that reports it `Submitted` debits the lane, once, by its
//! charge; a copy submitted on a later route, or later, debits nothing.
//! The head never moves past a position no route submitted: while the
//! only copies of the lowest position wait on their routes (denied, held
//! or suspended), the lane waits too, as one route's lane would.
//!
//! - **No route submitted.** An `Unknown` copy suspends its route only,
//!   and the head is uncertain only when no route served it; a route
//!   without room makes the call stop as backpressure only when no route
//!   served it either. A copy the gate denies pauses its route's queue for
//!   the call.
//! - **Per socket.** Each route is its own endpoint. A route that would
//!   block, or whose endpoint is resetting or retired, takes no more
//!   flushes in the call, on any lane; the call reports
//!   [`SenderReport::inactive`] once every route is inactive.
//! - **Detached.** A route whose TX half is not lent this call
//!   ([`Routes::route`] is `None`) is out for the call, as a blocked one.
//! - **Failures.** Mapped as [`super::LaneSender`] maps them
//!   ([`SenderFailure`]). With one route a failure stops the call, as
//!   [`super::LaneSender`]'s does, after debiting a head another route
//!   submitted. With several, a failure stops only its route (a failure
//!   stops only that half, sockets-backend.md 3.10): the route is out for
//!   the call, its failure is kept for the control path
//!   ([`RoutedLaneSender::take_failures`]), and the other routes go on.
//! - **Catching up.** A route behind the debited position (its copy was
//!   kept pending while another route submitted) flushes its older copies
//!   in [`RoutedLaneSender::catch_up`], one per route and lane per call,
//!   which debits nothing.
//! - **One route.** With one route the sender takes the same DRR steps as
//!   [`super::LaneSender`] and reports the same failures: the tests run
//!   both side by side.
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
    /// Cancels this route could not run, one per lane and call: its TX
    /// half was detached, so its copies stay recorded until
    /// [`RoutedLaneSender::reopen`] drops them, or
    /// [`RoutedLaneSender::forget`] returns them (`forgotten`). A count of
    /// attempts, not of copies.
    pub uncancelled: u64,
    /// Copies [`RoutedLaneSender::forget`] returned while the route was
    /// detached.
    pub forgotten: u64,
    /// Datagrams this route submitted, catch-up copies included: each path
    /// keeps its own count for capacity planning (RP-10).
    pub datagrams: u64,
    /// Bytes this route submitted, catch-up copies included (RP-10).
    pub bytes: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

/// Counts one datagram of `len` bytes that `counters`' route submitted.
fn count_submitted(counters: &mut RouteCounters, len: u16) {
    bump(&mut counters.datagrams, &mut counters.overflowed);
    match counters.bytes.checked_add(u64::from(len)) {
        Some(total) => counters.bytes = total,
        None => counters.overflowed = true,
    }
}

/// What one [`RoutedLaneSender::catch_up`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CatchUp {
    /// Copies submitted.
    pub submitted: u32,
    /// Set when the call stopped on a failure (one route only; with
    /// several, see [`RoutedLaneSender::take_failures`]).
    pub failure: Option<SenderFailure>,
}

/// Each route's failure kept for the control path, the first per route.
pub type RouteFailures = [Option<SenderFailure>; MAX_ROUTES];

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

impl RouteLane {
    /// Whether this queue may flush now, its route not blocked or inactive.
    fn sendable(&self) -> bool {
        !(self.suspended || self.control || self.paused)
    }

    /// Its lowest copy above `debited`. Positions increase along the queue.
    fn undebited(&self, debited: Option<u64>) -> Option<&RoutedStaged> {
        let first = self
            .staged
            .partition_point(|copy| debited.is_some_and(|debited| copy.position <= debited));
        self.staged.get(first)
    }
}

#[derive(Debug)]
struct Lane {
    routes: Vec<RouteLane>,
    bound: usize,
    /// The highest position debited on this lane.
    debited: Option<u64>,
}

impl Lane {
    /// The head (module docs): the lowest position not yet debited on any
    /// live route, with its charge, when a route not in `out` holds it at
    /// its front and may send it now. A route out of the live set holds no
    /// position back (RP-8).
    fn head(&self, out: &[bool; MAX_ROUTES], live: &[bool; MAX_ROUTES]) -> Option<(u64, u64)> {
        let lowest = self
            .routes
            .iter()
            .zip(live)
            .filter(|(_, live)| **live)
            .filter_map(|(route, _)| route.undebited(self.debited))
            .map(|copy| copy.position)
            .min()?;
        self.routes
            .iter()
            .zip(out)
            .filter(|(route, out)| route.sendable() && !**out)
            .filter_map(|(route, _)| route.staged.front())
            .find(|copy| copy.position == lowest)
            .map(|copy| (copy.position, copy.staged.charge))
    }
}

/// A DRR sender over one TX queue per lane on each of its routes.
#[derive(Debug)]
pub struct RoutedLaneSender {
    drr: Drr,
    lanes: Vec<Lane>,
    routes: usize,
    max_charge: u64,
    report: TxReport,
    counters: [RouteCounters; MAX_ROUTES],
    failures: RouteFailures,
    /// The routes in the live set (redundant-paths.md RP-8): a route out of
    /// it takes no flush and holds no head back.
    live: [bool; MAX_ROUTES],
    /// The routes whose last flush would block (no room) or found the
    /// endpoint inactive: not ready. The copy that blocked stays staged
    /// and is tried again on every call that reaches it, so the flag lasts
    /// only while the socket keeps blocking: any other answer (submitted,
    /// returned, unknown, interrupted) clears it, and so does a reopen,
    /// which drops that copy. A route that has not tried since counts as
    /// ready: nothing probes a socket without a copy to send.
    blocked: [bool; MAX_ROUTES],
}

/// The routes not lent this call: out from its start.
fn detached<R: Routes>(routes: &mut R, count: usize) -> [bool; MAX_ROUTES] {
    let mut out = [false; MAX_ROUTES];
    for (route, out) in out.iter_mut().enumerate().take(count) {
        *out = routes.route(route).is_none();
    }
    out
}

/// Returns `queue`'s pending copies that were never exposed, through
/// `gate` as [`Left::Returned`], in staging order.
fn cancel_queue<B: TxBackend, G: LaneGate>(
    backend: &mut B,
    queue: &mut RouteLane,
    lane: usize,
    report: &mut TxReport,
    gate: &mut G,
) -> Result<(), QueueError> {
    loop {
        let outcome = backend.cancel_pending(queue.queue, report)?;
        while let Some(item) = report.pop_front() {
            match queue.staged.front().copied() {
                Some(head) if head.staged.ticket == item.ticket => {
                    queue.staged.pop_front();
                    gate.left(lane, head.staged, Left::Returned);
                }
                _ => {
                    while report.pop_front().is_some() {}
                    return Ok(());
                }
            }
        }
        if !outcome.more {
            return Ok(());
        }
    }
}

/// Keeps `failure` for `route`, unless one is kept already.
fn keep(failures: &mut RouteFailures, route: usize, failure: SenderFailure) {
    if let Some(slot) = failures.get_mut(route) {
        *slot = slot.or(Some(failure));
    }
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
            routes: queues.len(),
            max_charge,
            report: TxReport::new(),
            counters: [RouteCounters::default(); MAX_ROUTES],
            failures: [None; MAX_ROUTES],
            live: std::array::from_fn(|route| route < queues.len()),
            blocked: [false; MAX_ROUTES],
        })
    }

    /// Puts `route` in the live set, or takes it out (RP-8, RP-9). Out of
    /// it, a route takes no flush and holds no head back; its copies stay
    /// recorded until [`RoutedLaneSender::cancel_route`] or a reopen.
    pub fn set_live(&mut self, route: usize, live: bool) {
        if route < self.routes
            && let Some(slot) = self.live.get_mut(route)
        {
            *slot = live;
        }
        // A route entering or leaving the set starts with no blocked flag:
        // the copy that blocked it was cancelled when it left (RP-8), so a
        // returning route counts as ready until it tries (RP-9).
        if let Some(blocked) = self.blocked.get_mut(route) {
            *blocked = false;
        }
    }

    /// Whether `route` is in the live set.
    #[must_use]
    #[inline]
    pub fn is_live(&self, route: usize) -> Option<bool> {
        (route < self.routes)
            .then(|| self.live.get(route).copied())
            .flatten()
    }

    /// The copies of `lane` that only `route` holds above the debited
    /// position, no live route holding their position: a leaving route's
    /// copies no path will send (RP-8; receivers get them by NAK or close
    /// the gap by their gap policy).
    #[must_use]
    pub fn exclusive(&self, lane: usize, route: usize) -> usize {
        let Some(entry) = self.lanes.get(lane) else {
            return 0;
        };
        let Some(queue) = entry.routes.get(route) else {
            return 0;
        };
        queue
            .staged
            .iter()
            .filter(|copy| entry.debited.is_none_or(|debited| copy.position > debited))
            .filter(|copy| {
                !entry
                    .routes
                    .iter()
                    .zip(&self.live)
                    .enumerate()
                    .any(|(index, (other, live))| {
                        index != route
                            && *live
                            && other
                                .staged
                                .iter()
                                .any(|held| held.position == copy.position)
                    })
            })
            .count()
    }

    /// The route that alone holds `lane`'s head while another live route,
    /// ready to submit (not blocked in the last call, not suspended or
    /// faulted), holds a later copy: the lane waits on that route
    /// (redundant-paths.md RP-8; ACS 16856). The head need not be at its
    /// front: a catch-up copy may precede it there. `None` when the head is
    /// shared or absent, or no ready route waits (a shared bottleneck).
    #[must_use]
    pub fn sole_holder(&self, lane: usize) -> Option<usize> {
        let entry = self.lanes.get(lane)?;
        let live = |index: &usize| self.live.get(*index).is_some_and(|live| *live);
        let lowest = entry
            .routes
            .iter()
            .enumerate()
            .filter(|(index, _)| live(index))
            .filter_map(|(_, route)| route.undebited(entry.debited))
            .map(|copy| copy.position)
            .min()?;
        let mut holders = entry
            .routes
            .iter()
            .enumerate()
            .filter(|(index, route)| {
                live(index) && route.staged.iter().any(|copy| copy.position == lowest)
            })
            .map(|(index, _)| index);
        let holder = holders.next()?;
        if holders.next().is_some() {
            return None;
        }
        let ready = |index: &usize| !self.blocked.get(*index).is_some_and(|blocked| *blocked);
        let others_wait = entry.routes.iter().enumerate().any(|(index, route)| {
            index != holder
                && live(&index)
                && ready(&index)
                && !route.suspended
                && !route.control
                && route.staged.iter().any(|copy| copy.position > lowest)
        });
        others_wait.then_some(holder)
    }

    /// The failures that stopped one route of several since the last call,
    /// the first per route: each route's half waits for its control path
    /// (retry or reset). Taking them clears them.
    ///
    /// With several routes they are the only report of a failure: a call in
    /// which every route fails reports [`SenderReport::failure`] `None` (the
    /// DRR stops idle, every route out), so the control path reads them
    /// after every [`RoutedLaneSender::serve`] and
    /// [`RoutedLaneSender::catch_up`].
    pub fn take_failures(&mut self) -> RouteFailures {
        std::mem::take(&mut self.failures)
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
    /// `route`, at its tail, above the route's last copy.
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
        if queue
            .staged
            .back()
            .is_some_and(|last| last.position >= copy.position)
        {
            return Err(StageError::OutOfOrder { lane });
        }
        queue.staged.push_back(copy);
        Ok(())
    }

    /// `route` could not take a copy of a lane's next datagram (no room):
    /// the route skips it, counted (RP-8).
    pub fn skipped(&mut self, route: usize) {
        if let Some(counters) = self.counters.get_mut(route) {
            bump(&mut counters.skipped, &mut counters.overflowed);
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
        // The copy that blocked went with the old queue: nothing would
        // retry it, so the route counts as ready again.
        if let Some(blocked) = self.blocked.get_mut(route) {
            *blocked = false;
        }
    }

    /// Returns the pending copies of `lane` that were never exposed, on
    /// every route, for a lane its gate aborted (as
    /// [`super::LaneSender::cancel`] does for one route): each leaves
    /// through `gate` as [`Left::Returned`], in staging order. A route whose
    /// TX half is detached keeps its copies, counted
    /// ([`RouteCounters::uncancelled`]).
    ///
    /// # Errors
    ///
    /// The first route's [`QueueError`] from
    /// [`TxBackend::cancel_pending`]; every other route is still cancelled.
    pub fn cancel<R: Routes, G: LaneGate>(
        &mut self,
        routes: &mut R,
        lane: usize,
        gate: &mut G,
    ) -> Result<(), QueueError> {
        let Self {
            lanes,
            report,
            counters,
            ..
        } = self;
        let Some(entry) = lanes.get_mut(lane) else {
            return Ok(());
        };
        let mut first = None;
        for (index, queue) in entry.routes.iter_mut().enumerate() {
            let Some(backend) = routes.route(index) else {
                if !queue.staged.is_empty()
                    && let Some(counters) = counters.get_mut(index)
                {
                    bump(&mut counters.uncancelled, &mut counters.overflowed);
                }
                continue;
            };
            if let Err(error) = cancel_queue(backend, queue, lane, report, gate) {
                first = first.or(Some(error));
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// Forgets `route`'s pending copies of `lane` while that route's TX
    /// half is detached, for a lane its gate aborted: each leaves through
    /// `gate` as [`Left::Returned`], in staging order, with no backend
    /// call. None was submitted (a submitted copy leaves the record), so
    /// none can reach the wire unless flushed, and a forgotten copy is
    /// never flushed: the detached queue keeps the items until the route's
    /// reopen replaces it. A close then does not wait on a route that may
    /// never come back (ACS 17049). Returns how many it forgot.
    #[must_use]
    pub fn forget<G: LaneGate>(&mut self, lane: usize, route: usize, gate: &mut G) -> usize {
        let Some(queue) = self
            .lanes
            .get_mut(lane)
            .and_then(|entry| entry.routes.get_mut(route))
        else {
            return 0;
        };
        // At most the queue's bound: `len` before the drain cannot overflow.
        let forgotten = queue.staged.len();
        while let Some(head) = queue.staged.pop_front() {
            gate.left(lane, head.staged, Left::Returned);
        }
        if let Some(counters) = self.counters.get_mut(route) {
            match u64::try_from(forgotten)
                .ok()
                .and_then(|forgotten| counters.forgotten.checked_add(forgotten))
            {
                Some(total) => counters.forgotten = total,
                None => counters.overflowed = true,
            }
        }
        forgotten
    }

    /// Returns `route`'s pending copies of every lane that were never
    /// exposed, for a route leaving the live set (RP-8): only that route's
    /// queues, as [`RoutedLaneSender::cancel`] does per lane; each leaves
    /// through `gate` as [`Left::Returned`]. A detached route keeps its
    /// copies, counted ([`RouteCounters::uncancelled`]).
    ///
    /// # Errors
    ///
    /// The first lane's [`QueueError`]; every other lane is still
    /// cancelled.
    pub fn cancel_route<R: Routes, G: LaneGate>(
        &mut self,
        routes: &mut R,
        route: usize,
        gate: &mut G,
    ) -> Result<(), QueueError> {
        let Self {
            lanes,
            report,
            counters,
            ..
        } = self;
        let mut first = None;
        for (lane, entry) in lanes.iter_mut().enumerate() {
            let Some(queue) = entry.routes.get_mut(route) else {
                continue;
            };
            let Some(backend) = routes.route(route) else {
                if !queue.staged.is_empty()
                    && let Some(counters) = counters.get_mut(route)
                {
                    bump(&mut counters.uncancelled, &mut counters.overflowed);
                }
                continue;
            };
            if let Err(error) = cancel_queue(backend, queue, lane, report, gate) {
                first = first.or(Some(error));
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// Flushes, on each route, at most one copy of each lane at or below
    /// the position another route already debited (a route that fell
    /// behind). It debits nothing and asks `gate` at each exposure. A route
    /// that would block or is inactive takes no more flushes in the call;
    /// a failure stops it.
    pub fn catch_up<R: Routes, G: LaneGate>(&mut self, routes: &mut R, gate: &mut G) -> CatchUp {
        let Self {
            lanes,
            report,
            counters,
            failures,
            routes: count,
            live,
            blocked,
            ..
        } = self;
        let several = *count > 1;
        let mut done = CatchUp::default();
        let mut out = detached(routes, *count);
        for (out, live) in out.iter_mut().zip(&*live) {
            *out |= !*live;
        }
        for (lane, entry) in lanes.iter_mut().enumerate() {
            let Some(debited) = entry.debited else {
                continue;
            };
            for ((index, queue), out) in entry.routes.iter_mut().enumerate().zip(&mut out) {
                if *out || queue.suspended || queue.control {
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
                        if let Some(route) = blocked.get_mut(index) {
                            *route = false;
                        }
                        // At most one copy per route and lane: no overflow.
                        if let Some(next) = done.submitted.checked_add(1) {
                            done.submitted = next;
                        }
                        if let Some(counters) = counters.get_mut(index) {
                            bump(&mut counters.late, &mut counters.overflowed);
                            count_submitted(counters, head.staged.len);
                        }
                    }
                    Flushed::Returned => {
                        queue.staged.pop_front();
                        gate.left(lane, head.staged, Left::Returned);
                        if let Some(route) = blocked.get_mut(index) {
                            *route = false;
                        }
                    }
                    Flushed::Unknown => {
                        queue.staged.pop_front();
                        queue.suspended = true;
                        gate.left(lane, head.staged, Left::Unknown);
                        if let Some(route) = blocked.get_mut(index) {
                            *route = false;
                        }
                    }
                    // Tried again on the next call.
                    Flushed::Denied => {}
                    // The socket answered without blocking.
                    Flushed::Again => {
                        if let Some(route) = blocked.get_mut(index) {
                            *route = false;
                        }
                    }
                    Flushed::Blocked | Flushed::Inactive => {
                        *out = true;
                        if let Some(route) = blocked.get_mut(index) {
                            *route = true;
                        }
                    }
                    Flushed::Hold => queue.control = true,
                    Flushed::Fail(failure) if several => {
                        keep(failures, index, failure.at(lane));
                        *out = true;
                    }
                    Flushed::Fail(failure) => {
                        done.failure = Some(failure.at(lane));
                        return done;
                    }
                }
            }
        }
        done
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
        let mut out = detached(routes, self.routes);
        for (out, live) in out.iter_mut().zip(&self.live) {
            *out |= !*live;
        }
        let mut source = Source {
            routes,
            gate,
            lanes: &mut self.lanes,
            report: &mut self.report,
            counters: &mut self.counters,
            failures: &mut self.failures,
            count: self.routes,
            out,
            live: self.live,
            blocked: &mut self.blocked,
            inactive: [false; MAX_ROUTES],
            failure: None,
        };
        let drr: Report = self.drr.run(budget, &mut source);
        let inactive = source.all_inactive();
        let failure = source.failure.or(match drr.stop {
            Stop::Failed(error) => Some(SenderFailure::Drr(error)),
            _ => None,
        });
        SenderReport {
            drr,
            failure,
            inactive,
        }
    }
}

/// Adds one to `counter`, or records the overflow.
fn bump(counter: &mut u64, overflowed: &mut bool) {
    match counter.checked_add(1) {
        Some(next) => *counter = next,
        None => *overflowed = true,
    }
}

/// The kind of a [`SenderFailure`], before its lane is known.
#[derive(Clone, Copy)]
enum Failure {
    Backend(FlushStop),
    Invariant(FlushStop),
    Sender(FlushStop),
}

impl Failure {
    fn at(self, lane: usize) -> SenderFailure {
        match self {
            Self::Backend(stop) => SenderFailure::Backend { lane, stop },
            Self::Invariant(stop) => SenderFailure::Invariant { lane, stop },
            Self::Sender(stop) => SenderFailure::Sender { lane, stop },
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
    Fail(Failure),
}

/// Flushes `head`, the front copy of `queue`, through `backend`. The
/// outcomes map as [`super::LaneSender`]'s (lane-sender.md, outcome table).
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
            FlushStop::ReportNotEmpty | FlushStop::GateError { .. } => {
                Flushed::Fail(Failure::Sender(stop))
            }
            FlushStop::Failed(_) => Flushed::Fail(Failure::Backend(stop)),
            _ => Flushed::Fail(Failure::Invariant(stop)),
        };
    };
    if extra || item.ticket != head.staged.ticket {
        return Flushed::Fail(Failure::Invariant(stop));
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
            PendingCause::ErrorLost | PendingCause::NotAttempted => {
                Flushed::Fail(Failure::Invariant(stop))
            }
            PendingCause::Failed(_) => Flushed::Fail(Failure::Backend(stop)),
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
    failures: &'a mut RouteFailures,
    /// The sender's routes.
    count: usize,
    /// Routes that take no more flushes in the call: blocked or inactive.
    out: [bool; MAX_ROUTES],
    /// The live set (RP-8).
    live: [bool; MAX_ROUTES],
    /// Routes whose last flush would block or found them inactive.
    blocked: &'a mut [bool; MAX_ROUTES],
    /// Routes whose endpoint was resetting or retired in the call.
    inactive: [bool; MAX_ROUTES],
    failure: Option<SenderFailure>,
}

impl<R, G> Source<'_, R, G> {
    /// Whether every route was inactive in the call.
    fn all_inactive(&self) -> bool {
        self.inactive
            .iter()
            .take(self.count)
            .all(|inactive| *inactive)
    }
}

impl<R: Routes, G: LaneGate> LaneSource for Source<'_, R, G> {
    fn probe(&mut self, lane: usize) -> Probe {
        if self.failure.is_some() || self.all_inactive() {
            return Probe::Ineligible;
        }
        let Some((_, charge)) = self
            .lanes
            .get(lane)
            .and_then(|entry| entry.head(&self.out, &self.live))
        else {
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
        let Some((position, _)) = entry.head(&self.out, &self.live) else {
            return Service::NotServed;
        };
        let (mut served, mut uncertain, mut blocked) = (false, false, false);
        for (index, queue) in entry.routes.iter_mut().enumerate() {
            let (Some(out), Some(inactive)) =
                (self.out.get_mut(index), self.inactive.get_mut(index))
            else {
                continue;
            };
            if *out || !queue.sendable() {
                continue;
            }
            let Some(head) = queue.staged.front().copied() else {
                continue;
            };
            if head.position != position {
                continue;
            }
            let Some(backend) = self.routes.route(index) else {
                *out = true;
                continue;
            };
            self.gate.flushing(lane);
            match flush_one(backend, self.gate, self.report, queue.queue, head) {
                Flushed::Submitted => {
                    queue.staged.pop_front();
                    self.gate.left(lane, head.staged, Left::Submitted);
                    if let Some(route) = self.blocked.get_mut(index) {
                        *route = false;
                    }
                    if let Some(counters) = self.counters.get_mut(index) {
                        if served {
                            bump(&mut counters.late, &mut counters.overflowed);
                        }
                        count_submitted(counters, head.staged.len);
                    }
                    served = true;
                }
                Flushed::Returned => {
                    queue.staged.pop_front();
                    self.gate.left(lane, head.staged, Left::Returned);
                    if let Some(route) = self.blocked.get_mut(index) {
                        *route = false;
                    }
                }
                Flushed::Unknown => {
                    queue.staged.pop_front();
                    queue.suspended = true;
                    self.gate.left(lane, head.staged, Left::Unknown);
                    uncertain = true;
                    if let Some(route) = self.blocked.get_mut(index) {
                        *route = false;
                    }
                }
                // The probe raced the exposure-time gate.
                Flushed::Denied => queue.paused = true,
                // The socket answered without blocking.
                Flushed::Again => {
                    if let Some(route) = self.blocked.get_mut(index) {
                        *route = false;
                    }
                }
                // Per socket (LS-4): this route takes no more in the call.
                Flushed::Blocked => {
                    *out = true;
                    blocked = true;
                    if let Some(route) = self.blocked.get_mut(index) {
                        *route = true;
                    }
                }
                Flushed::Inactive => {
                    *out = true;
                    *inactive = true;
                    blocked = true;
                    if let Some(route) = self.blocked.get_mut(index) {
                        *route = true;
                    }
                }
                Flushed::Hold => queue.control = true,
                // One route of several: only it stops (module docs).
                Flushed::Fail(failure) if self.count > 1 => {
                    keep(self.failures, index, failure.at(lane));
                    *out = true;
                }
                Flushed::Fail(failure) => {
                    self.failure = Some(failure.at(lane));
                    if served {
                        // Debited first: the next probe stops the call.
                        entry.debited = Some(position);
                        return Service::Served;
                    }
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
