// SPDX-License-Identifier: Apache-2.0

//! A publication's first sends over redundant paths (`quantstratum-docs:
//! karyos/design/redundant-paths.md` section 7, RP-10; rp-w4b1).
//!
//! A routed [`Outbound`] keeps one route per path: the path's endpoint and
//! its destination, with a TX queue per lane opened on that endpoint. Each
//! cycle each lane reads a committed frame once, into scratch storage
//! allocated with the publication, and copies it into a claimed frame of
//! each route that has room; a route without room skips the copy, counted
//! ([`RoutedLaneSender::skipped`]). The lanes are then served under one DRR
//! ([`RoutedLaneSender`]): a head selected once is submitted on every route
//! that holds it and debited once, at the first route that submits it.
//! Routes that fell behind catch up afterwards, debiting nothing.
//!
//! Per lane the highest position submitted on any route is its sent
//! frontier (`sent_high`, monotonic): it moves the reader's registered
//! position and the membership's sent bound exactly as on one path. Repair
//! stays on the founding route (RP-11 is rp-w6). A guarded publication's
//! gate passes every copy's exposure on every route ([`GuardGate`], module
//! docs: Routes), so no path can bypass a close; a close cancels the
//! aborted lanes' copies on every route.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32};

use karyos_io::backend::{
    Authority, BackendEpoch, Commit, Exposure, GateDecision, RouteId, SenderGate, SenderToken,
    TxBackend, TxFrame, TxOptions, TxQueueConfig, TxQueueId, TxTicket,
};
use karyos_io::lanes::routes::{MAX_ROUTES, RoutedLaneSender, RoutedStaged, Routes};
use karyos_io::lanes::{LaneGate, Left, Staged};
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::lanes::drr::{Budget, DrrConfig};
use karyos_sys::log_buffer::{ReadError, ReadOrigin, ReadOutcome};

use super::super::repair::RouteRepairCounts;
use super::super::{AgentError, AgentKind, EndpointId, Half};
use super::removal::{EosSent, RemovalStep};
use super::{Limit, Outbound, OutboundError, STAGED_PER_LANE, align_frame, messages_started};
use crate::guard_gate::{GateHead, GuardGate};
use crate::repair::scheduler::RepairBudget;

/// When a path leaves the live set (redundant-paths.md section 7, RP-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathPolicy {
    /// `path_lag_limit` in ns: the sliding window of selected and skipped
    /// bytes (default 100 ms, at least 2 ns).
    pub lag_limit: u64,
    /// `path_skip_ratio` in percent: a path whose skipped share of the
    /// window exceeds it leaves (default 50, 1 to 100).
    pub skip_percent: u8,
    /// `path_skip_min_bytes`: the bytes selected in the window before a
    /// path can leave (default 64 KiB, at least 1).
    pub skip_min_bytes: u64,
    /// `path_backoff_initial` in ns: a left path's first wait before it
    /// returns (RP-9; default 10 ms, at least 1).
    pub backoff_initial: u64,
    /// `path_backoff_max` in ns: the wait doubles up to it (default 1 s, at
    /// least `backoff_initial`, at most [`MAX_PATH_BACKOFF`], so a left
    /// path always comes back).
    pub backoff_max: u64,
    /// `path_backoff_reset` in ns: live this long, a path's wait starts
    /// over at `backoff_initial` (default 10 s, at least 1).
    pub backoff_reset: u64,
    /// `path_skew_window` in ns: a NAK copy on another path within it is
    /// absorbed (RP-11; default 1 ms, at most 1 s, the receivers' window).
    pub skew_window: u64,
    /// `path_copy_entries`: the absorption table's entries per publication
    /// (RP-11; default 256, 1 to [`MAX_PATH_COPY_ENTRIES`]).
    pub copy_entries: usize,
}

/// The longest `path_backoff_max`, in ns (60 s): past it a left path
/// could wait so long it never comes back.
pub const MAX_PATH_BACKOFF: u64 = 60_000_000_000;

/// The largest `path_copy_entries`.
pub const MAX_PATH_COPY_ENTRIES: usize = 4_096;

impl Default for PathPolicy {
    fn default() -> Self {
        Self {
            lag_limit: 100_000_000,
            skip_percent: 50,
            skip_min_bytes: 64 * 1024,
            backoff_initial: 10_000_000,
            backoff_max: 1_000_000_000,
            backoff_reset: 10_000_000_000,
            skew_window: crate::paths::PathConfig::default().path_skew_window,
            copy_entries: 256,
        }
    }
}

/// What a path did in and out of the live set (RP-8), and what it sent
/// (RP-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PathCounters {
    /// Times it left the live set.
    pub exits: u64,
    /// Times it returned to the live set (RP-9).
    pub entries: u64,
    /// Times it became `Degraded`: it skipped something in the window.
    pub degraded: u64,
    /// Copies it held alone when it left: no live path sends them, so the
    /// receivers get them by NAK (reliable) or close the gap by their gap
    /// policy (unreliable).
    pub copies_abandoned: u64,
    /// The first-send DATA copies it submitted, catch-up copies included:
    /// each path's own count, for capacity planning (RP-10). Its route's
    /// `RouteCounters::datagrams`; repairs are in
    /// [`Outbound::repair_route_counts`], and PATH_HB, other controls and
    /// `Flushed::Unknown` copies are not counted.
    pub datagrams: u64,
    /// The bytes of those copies (RP-10), with the same scope. Its route's
    /// `RouteCounters::bytes`.
    pub bytes: u64,
    /// An increment did not apply, here or in its route's counters.
    pub overflowed: bool,
}

/// A path's sliding window of selected and skipped bytes: two buckets of
/// half the window each, so its sums cover between half and one window.
#[derive(Debug, Clone, Copy, Default)]
struct PathWindow {
    /// Per bucket: its half-window index, selected bytes, skipped bytes.
    buckets: [(u64, u64, u64); 2],
}

impl PathWindow {
    /// The bucket of `now` for a window of `limit` ns, emptied when stale.
    fn bucket(&mut self, now: u64, limit: u64) -> Option<&mut (u64, u64, u64)> {
        let half = limit.checked_div(2).filter(|half| *half > 0)?;
        let index = now.checked_div(half)?;
        let slot = self.buckets.get_mut(usize::try_from(index % 2).ok()?)?;
        if slot.0 != index {
            *slot = (index, 0, 0);
        }
        Some(slot)
    }

    /// Records `selected` bytes at `now`, `skipped` of them skipped.
    /// Returns `false` when a sum would overflow: nothing is recorded.
    fn record(&mut self, now: u64, limit: u64, selected: u64, skipped: u64) -> bool {
        let Some(slot) = self.bucket(now, limit) else {
            return false;
        };
        let (Some(selected), Some(skipped)) =
            (slot.1.checked_add(selected), slot.2.checked_add(skipped))
        else {
            return false;
        };
        slot.1 = selected;
        slot.2 = skipped;
        true
    }

    /// The selected and skipped bytes of the window ending at `now`; `None`
    /// past `u64`, which decides nothing.
    fn sums(&mut self, now: u64, limit: u64) -> Option<(u64, u64)> {
        let current = self.bucket(now, limit).map(|slot| slot.0)?;
        self.buckets
            .iter()
            .filter(|(index, _, _)| current.checked_sub(*index).is_some_and(|age| age <= 1))
            .try_fold((0u64, 0u64), |(selected, skipped), (_, s, k)| {
                Some((selected.checked_add(*s)?, skipped.checked_add(*k)?))
            })
    }
}

/// Path `index` leaves the live set (RP-8): out of the sender's live set,
/// its never-exposed copies of `lanes` lanes back through `gate` (the guard's
/// ring settles), and those it held alone counted abandoned. Returns whether
/// the cancel failed.
#[allow(clippy::too_many_arguments, reason = "one step over the routed state")]
fn leave<R: Routes, G: LaneGate>(
    sender: &mut RoutedLaneSender,
    routes: &mut [RouteSlot],
    index: usize,
    lanes: usize,
    (policy, now): (PathPolicy, u64),
    lent: &mut R,
    gate: &mut G,
) -> bool {
    let Some(slot) = routes.get_mut(index) else {
        return false;
    };
    slot.left = true;
    slot.left_at = now;
    slot.returning = false;
    slot.live_since = None;
    // RP-9: the wait doubles at each exit, up to its maximum.
    slot.backoff = if slot.backoff == 0 {
        policy.backoff_initial
    } else {
        match slot.backoff.checked_mul(2) {
            Some(doubled) => doubled.min(policy.backoff_max),
            // Past u64: past the maximum too.
            None => policy.backoff_max,
        }
    };
    slot.stall_since = None;
    slot.degraded = false;
    slot.window = PathWindow::default();
    bump_path(&mut slot.counters.exits, &mut slot.counters.overflowed);
    sender.set_live(index, false);
    for lane in 0..lanes {
        let alone = u64::try_from(sender.exclusive(lane, index)).ok();
        match alone.and_then(|alone| slot.counters.copies_abandoned.checked_add(alone)) {
            Some(total) => slot.counters.copies_abandoned = total,
            None => slot.counters.overflowed = true,
        }
    }
    // A path whose TX half is not lent this cycle (its endpoint resetting)
    // cannot cancel: its copies stay recorded, counted `uncancelled`, until
    // its reopen drops them through the guard gate (`reopen_route`) and
    // settles the ring; a close acknowledgement waits for that reopen.
    sender.cancel_route(lent, index, gate).is_err()
}

/// Adds one to a path count, or records the overflow.
fn bump_path(count: &mut u64, overflowed: &mut bool) {
    match count.checked_add(1) {
        Some(next) => *count = next,
        None => *overflowed = true,
    }
}

/// One path of a routed publication.
#[derive(Debug)]
pub(super) struct RouteSlot {
    endpoint: EndpointId,
    destination: SocketAddr,
    /// One queue per lane on this route's endpoint.
    queues: Vec<TxQueueId>,
    /// The endpoint epoch its queues were opened in.
    opened: Option<BackendEpoch>,
    /// The route its queues were opened on, in that epoch.
    route: Option<RouteId>,
    /// This route's endpoint needs a reset before the route sends again: a
    /// failure of its half, an item of unknown exposure, or a fault its
    /// queue refused to retry. Its new epoch clears it.
    needs_reset: bool,
    /// The sender cycle of the last reset request posted for it.
    reset_requested: Option<u64>,
    /// When it last submitted DATA or a PATH_HB was posted on it.
    last_sent: Option<u64>,
    /// Its window of selected and skipped bytes (RP-8).
    window: PathWindow,
    /// It skipped something in the window: `Degraded`.
    degraded: bool,
    /// It left the live set for lagging; it stays out until it returns
    /// (RP-9, rp-w5b).
    left: bool,
    /// Since when a lane has waited on it alone: it holds the lane's head
    /// and has not sent it while another path holds later copies (ACS
    /// 16856). Any submit on it ends the stall.
    stall_since: Option<u64>,
    /// Its current backoff in ns: 0 before its first exit (RP-9).
    backoff: u64,
    /// When it left.
    left_at: u64,
    /// It returned and has submitted nothing yet: it does not bound
    /// `sent_low` until then (RP-9).
    returning: bool,
    /// Since when it is live again, from its first submit after a return.
    live_since: Option<u64>,
    counters: PathCounters,
}

/// One lane's staged copies per route, in order, and what left.
#[derive(Debug)]
pub(super) struct RoutedTrack {
    /// Per route: the ticket of each staged copy, its position and the
    /// position after it.
    staged: [VecDeque<(TxTicket, u64, u64)>; MAX_ROUTES],
    /// The highest position a submitted copy reached, this call.
    submitted: Option<u64>,
    /// A copy left out of staging order, this call.
    mismatched: bool,
    /// Per route: a copy left with an unproven exposure; only that route's
    /// endpoint reset resolves it.
    unknown: [bool; MAX_ROUTES],
    /// Per route: a copy was submitted this call.
    sent: [bool; MAX_ROUTES],
    /// Per route: its frontier `sent_p`, the position past the last frame
    /// it submitted or skipped (a skipped frame counts as passed, RP-8).
    sent_p: [u64; MAX_ROUTES],
    /// Per route: since when the lane sent nothing on it, neither DATA nor
    /// a heartbeat, and held nothing for it (SPEC §6; #842).
    idle_since: [Option<u64>; MAX_ROUTES],
}

/// The copies `route` holds for `lane`: staged and not submitted yet
/// (tests).
#[cfg(test)]
fn held(routed: &Routed, lane: usize, route: usize) -> usize {
    routed
        .tracks
        .get(lane)
        .and_then(|track| track.staged.get(route))
        .map_or(0, VecDeque::len)
}

/// The routes on which `lane` is due an idle heartbeat at `now` (SPEC §6;
/// #842), and the position none may announce past. A sending route is
/// idle when the lane sent it no DATA and no heartbeat for `interval` and
/// it holds no copy of the lane; its wait restarts while it is busy, and
/// a route that cannot send waits afresh once it can. Any route holding a
/// copy of the lane bounds every route's heartbeat at that copy's
/// position: sending or not, live, or returning (it stages before its
/// first submit, RP-9). A route that left with its half away does not:
/// its half comes back only in a new epoch, which drops the copies, or
/// never, and either way they are not sent. A heartbeat so never
/// announces a position a held copy would still bring, and still reveals
/// what lies below it. The bound reads each copy's own position, never a
/// route's frontier, so nothing stale reaches it. While a route holds a
/// copy for long (its socket full, its endpoint in a reset), a tail lost
/// above that copy is revealed only once the copy goes: the copy may
/// still fill it; a copy held by a socket that keeps refusing (EAGAIN)
/// has no time limit of its own, the route's path policy removes it
/// from the live set.
fn idle_routes(
    routed: &mut Routed,
    lane: usize,
    (sending, present): (&[bool; MAX_ROUTES], &[bool; MAX_ROUTES]),
    now: u64,
    interval: u64,
) -> ([bool; MAX_ROUTES], Option<u64>) {
    let mut due = [false; MAX_ROUTES];
    // A route that left with its half away bounds nothing: its reset
    // reopens in a new epoch, which drops its copies, and if the reset
    // fails it never sends them (QS-COORDINATOR on #842).
    let counts: [bool; MAX_ROUTES] = std::array::from_fn(|route| {
        routed
            .routes
            .get(route)
            .is_some_and(|slot| !slot.left || present.get(route) == Some(&true))
    });
    let Some(track) = routed.tracks.get_mut(lane) else {
        return (due, None);
    };
    let bound = track
        .staged
        .iter()
        .zip(&counts)
        .filter(|(_, counts)| **counts)
        .filter_map(|(copies, _)| copies.front().map(|(_, start, _)| *start))
        .min();
    for (route, (idle, slot)) in track.idle_since.iter_mut().zip(&mut due).enumerate() {
        if sending.get(route) != Some(&true) {
            *idle = None;
            continue;
        }
        if track
            .staged
            .get(route)
            .is_some_and(|copies| !copies.is_empty())
        {
            *idle = Some(now);
            continue;
        }
        let since = *idle.get_or_insert(now);
        *slot = now.checked_sub(since).is_some_and(|age| age >= interval);
    }
    (due, bound)
}

/// One to [`MAX_ROUTES`] routes, each on its own endpoint: each route's TX
/// half is found by its endpoint.
fn check_routes(routes: &[(EndpointId, SocketAddr)]) -> Result<(), OutboundError> {
    let shared = (0..routes.len()).any(|index| {
        let (seen, rest) = routes.split_at(index);
        rest.first()
            .is_some_and(|(endpoint, _)| seen.iter().any(|(other, _)| other == endpoint))
    });
    if routes.is_empty() || routes.len() > MAX_ROUTES || shared {
        return Err(OutboundError::Routes);
    }
    Ok(())
}

/// The routed part of an [`Outbound`].
#[derive(Debug)]
pub(super) struct Routed {
    sender: RoutedLaneSender,
    policy: PathPolicy,
    /// Per route, datagrams it takes no copy of (tests: a skip without a
    /// full socket).
    #[cfg(test)]
    withhold: [u32; MAX_ROUTES],
    /// A route that leaves before the next cycle's flush (tests: copies
    /// it alone holds, never sent).
    #[cfg(test)]
    leave_now: Option<usize>,
    routes: Vec<RouteSlot>,
    tracks: Vec<RoutedTrack>,
    /// The frame read once per datagram before its copies.
    scratch: Vec<u8>,
}

impl Routed {
    /// The routed part of a publication of `lanes` lanes over `routes`,
    /// served under `config`, reading datagrams of at most `mtu` bytes.
    pub(super) fn new(
        routes: &[(EndpointId, SocketAddr)],
        lanes: usize,
        config: DrrConfig,
        mtu: usize,
    ) -> Result<Self, OutboundError> {
        check_routes(routes)?;
        let placeholder = TxQueueId::new(BackendEpoch::FIRST, u16::MAX, NonZeroU32::MAX);
        let queues = vec![placeholder; lanes];
        let per_route: Vec<&[TxQueueId]> = routes.iter().map(|_| queues.as_slice()).collect();
        let bound = usize::from(STAGED_PER_LANE);
        let sender =
            RoutedLaneSender::new(config, &per_route, bound).map_err(|_| OutboundError::Lanes)?;
        Ok(Self {
            sender,
            policy: PathPolicy::default(),
            #[cfg(test)]
            withhold: [0; MAX_ROUTES],
            #[cfg(test)]
            leave_now: None,
            routes: routes
                .iter()
                .map(|&(endpoint, destination)| RouteSlot {
                    endpoint,
                    destination,
                    queues: queues.clone(),
                    opened: None,
                    route: None,
                    needs_reset: false,
                    reset_requested: None,
                    last_sent: None,
                    window: PathWindow::default(),
                    degraded: false,
                    left: false,
                    stall_since: None,
                    backoff: 0,
                    left_at: 0,
                    returning: false,
                    live_since: None,
                    counters: PathCounters::default(),
                })
                .collect(),
            tracks: (0..lanes)
                .map(|_| RoutedTrack {
                    staged: std::array::from_fn(|_| VecDeque::with_capacity(bound)),
                    submitted: None,
                    mismatched: false,
                    unknown: [false; MAX_ROUTES],
                    sent: [false; MAX_ROUTES],
                    sent_p: [0; MAX_ROUTES],
                    idle_since: [None; MAX_ROUTES],
                })
                .collect(),
            scratch: vec![0; mtu],
        })
    }

    /// The routes whose endpoint needs a reset.
    pub(super) fn routes_needing_reset(&self) -> impl Iterator<Item = EndpointId> + '_ {
        self.routes
            .iter()
            .filter(|route| route.needs_reset)
            .map(|route| route.endpoint)
    }

    /// The routes needing a reset whose request is due in `cycle`: each
    /// endpoint with the cycle of its last request, to record a new one.
    pub(super) fn reset_requests_due(
        &mut self,
        cycle: u64,
    ) -> impl Iterator<Item = (EndpointId, &mut Option<u64>)> + '_ {
        self.routes.iter_mut().filter_map(move |route| {
            let due = route.needs_reset
                && route.reset_requested.is_none_or(|at| {
                    cycle
                        .checked_sub(at)
                        .is_none_or(|age| age >= super::RESET_REQUEST_CYCLES)
                });
            due.then_some((route.endpoint, &mut route.reset_requested))
        })
    }

    /// Posts, through `post`, a PATH_HB toward each route's destination
    /// that is open and has submitted nothing for `interval` ns at `now`
    /// (RP-3); `post` says whether it was posted. Returns the count posted.
    pub(super) fn path_heartbeats(
        &mut self,
        now: u64,
        interval: u64,
        mut post: impl FnMut(EndpointId, SocketAddr) -> bool,
    ) -> u32 {
        let mut posted = 0u32;
        for route in &mut self.routes {
            let idle = route
                .last_sent
                .is_none_or(|at| now.checked_sub(at).is_some_and(|quiet| quiet >= interval));
            // A path out of the live set sends no PATH_HB: its receivers
            // see it go quiet, as they should (RP-5).
            if !idle || route.opened.is_none() || route.needs_reset || route.left {
                continue;
            }
            if post(route.endpoint, route.destination) {
                // At most four routes: no overflow.
                if let Some(next) = posted.checked_add(1) {
                    posted = next;
                }
            }
        }
        posted
    }

    /// Whether route `index`, at its endpoint's `epoch`, takes repairs: open
    /// at that epoch, not waiting for a reset, and in the live set (RP-11).
    pub(super) fn repair_live(&self, index: usize, epoch: BackendEpoch) -> bool {
        self.routes
            .get(index)
            .is_some_and(|route| route.opened == Some(epoch) && !route.needs_reset && !route.left)
    }

    /// [`Outbound::opened_resources`] for each route: its route and its
    /// lane queues on its endpoint, and its repair queue.
    pub(super) fn opened_resources(
        &self,
        repair: Option<&super::super::repair::RepairPath>,
        held: &mut impl FnMut(super::Opened),
    ) {
        for (index, slot) in self.routes.iter().enumerate() {
            let (Some(epoch), Some(route)) = (slot.opened, slot.route) else {
                continue;
            };
            let mut queues = [None; super::OPENED_QUEUES];
            for (held, queue) in queues.iter_mut().zip(&slot.queues) {
                *held = Some(*queue);
            }
            if let Some(last) = queues.last_mut() {
                *last = repair.and_then(|repair| repair.queue_on(index));
            }
            held(super::Opened {
                endpoint: slot.endpoint,
                epoch,
                route,
                queues,
            });
        }
    }

    /// The routes' endpoints, in route order.
    pub(super) fn endpoints(&self) -> impl Iterator<Item = EndpointId> + '_ {
        self.routes.iter().map(|route| route.endpoint)
    }

    /// The routed sender, for diagnostics and tests.
    pub(super) fn sender(&self) -> &RoutedLaneSender {
        &self.sender
    }
}

/// The agent's TX halves lent to the routed sender, one route at a time.
struct HalfRoutes<'a, O: SocketOps> {
    halves: &'a mut [(EndpointId, Half<O>)],
    endpoints: [Option<EndpointId>; MAX_ROUTES],
}

impl<O: SocketOps> Routes for HalfRoutes<'_, O> {
    type Backend = SocketsTx<O>;

    fn route(&mut self, route: usize) -> Option<&mut Self::Backend> {
        let endpoint = self.endpoints.get(route).copied().flatten()?;
        self.halves.iter_mut().find_map(|(held, half)| match half {
            Half::Tx(tx) if *held == endpoint => Some(&mut **tx),
            _ => None,
        })
    }
}

/// The routed data gate: a guarded publication's gate decides every
/// exposure on every route; an unguarded one permits every candidate. The
/// lanes are held while a required loss is unresolved. It records, per
/// lane, the highest position a submitted copy reached.
struct RoutedGate<'a> {
    tracks: &'a mut [RoutedTrack],
    held: bool,
    guard: Option<&'a mut GuardGate>,
}

impl SenderGate for RoutedGate<'_> {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        if let Some(guard) = self.guard.as_deref_mut() {
            return guard.check(candidate);
        }
        match u16::try_from(candidate.tokens.len())
            .ok()
            .and_then(NonZeroU16::new)
        {
            Some(count) => GateDecision::Permit { count },
            None => GateDecision::Deny,
        }
    }
}

impl LaneGate for RoutedGate<'_> {
    fn admits(&mut self, lane: usize) -> bool {
        // The guard is asked even while held, so a close is seen at once.
        let guarded = self
            .guard
            .as_deref_mut()
            .is_none_or(|guard| guard.admits(lane));
        guarded && !self.held
    }

    fn aborting(&self, lane: usize) -> bool {
        self.guard
            .as_deref()
            .is_some_and(|guard| guard.aborting(lane))
    }

    fn flushing(&mut self, lane: usize) {
        if let Some(guard) = self.guard.as_deref_mut() {
            guard.flushing(lane);
        }
    }

    fn left(&mut self, lane: usize, staged: Staged, how: Left) {
        if let Some(guard) = self.guard.as_deref_mut() {
            guard.left(lane, staged, how);
        }
        let Some(track) = self.tracks.get_mut(lane) else {
            return;
        };
        // Copies leave in staging order on their own route.
        let found = track
            .staged
            .iter_mut()
            .enumerate()
            .find_map(|(route, copies)| match copies.front().copied() {
                Some((ticket, _, next)) if ticket == staged.ticket => {
                    copies.pop_front();
                    Some((route, next))
                }
                _ => None,
            });
        match (found, how) {
            (Some((route, next)), Left::Submitted) => {
                track.submitted = Some(track.submitted.map_or(next, |high| high.max(next)));
                if let Some(sent) = track.sent.get_mut(route) {
                    *sent = true;
                }
                if let Some(frontier) = track.sent_p.get_mut(route) {
                    *frontier = (*frontier).max(next);
                }
            }
            (Some((route, _)), Left::Unknown) => {
                if let Some(unknown) = track.unknown.get_mut(route) {
                    *unknown = true;
                }
            }
            (Some(_), Left::Returned) => {}
            (None, _) => track.mismatched = true,
        }
    }
}

impl<T: crate::embedded::StreamTerms> Outbound<T> {
    /// The data path of the publication `alias` over redundant paths:
    /// `routes` names each path's endpoint and destination, the founding
    /// path first. Otherwise as [`Outbound::new`].
    ///
    /// # Errors
    ///
    /// [`OutboundError`].
    /// Driver-internal: `net/publish.rs` builds one for a channel with
    /// `paths`, behind `SocketOps::isolates_paths` (rp-w4b2c).
    pub(crate) fn new_routed(
        routes: &[(EndpointId, SocketAddr)],
        alias: karyos_protocol::network::Alias,
        readers: Vec<super::LaneReader<T>>,
        quanta: &karyos_protocol::network::Lanes<u64>,
        mtu: u32,
        reliable: bool,
    ) -> Result<Self, OutboundError> {
        let &(endpoint, destination) = routes.first().ok_or(OutboundError::Routes)?;
        let lanes = readers.len();
        let mut outbound = Self::new(endpoint, alias, destination, readers, quanta, mtu, reliable)?;
        let max_charge = align_frame(mtu).map_err(|_| OutboundError::Mtu)?;
        let config = DrrConfig::new(quanta.as_slice(), u64::from(max_charge))
            .map_err(|_| OutboundError::Quanta)?;
        outbound.routed = Some(Box::new(Routed::new(routes, lanes, config, outbound.mtu)?));
        Ok(outbound)
    }

    /// Whether it sends over redundant paths.
    #[must_use]
    pub fn is_routed(&self) -> bool {
        self.routed.is_some()
    }

    /// The endpoints of its paths, the founding one first; one for a
    /// publication on one path.
    pub fn route_endpoints(&self) -> impl Iterator<Item = EndpointId> + '_ {
        let routed = self.routed.as_deref();
        std::iter::once(self.endpoint)
            .filter(move |_| routed.is_none())
            .chain(routed.into_iter().flat_map(Routed::endpoints))
    }

    /// Whether one of its paths sends on `endpoint`: controls from a
    /// receiver on any path (SM, NAK, RTTM) name the publication there.
    #[must_use]
    pub fn serves(&self, endpoint: EndpointId) -> bool {
        self.route_endpoints().any(|held| held == endpoint)
    }

    /// The destination of its path on `endpoint`, where answers on that
    /// path go; `None` when no path sends there.
    #[must_use]
    pub fn destination_on(&self, endpoint: EndpointId) -> Option<SocketAddr> {
        match self.routed.as_deref() {
            Some(routed) => routed
                .routes
                .iter()
                .find(|route| route.endpoint == endpoint)
                .map(|route| route.destination),
            None => (self.endpoint == endpoint).then_some(self.destination),
        }
    }

    /// Over redundant paths, names through `post` each path due a PATH_HB:
    /// open, and submitted nothing for `interval` ns at `now`
    /// (redundant-paths.md RP-3), with its destination; `post` says whether
    /// it took it. The caller reports each one submitted
    /// ([`Outbound::path_heartbeat_sent`]). None on one path. Returns the
    /// count taken.
    pub fn path_heartbeats(
        &mut self,
        now: u64,
        interval: u64,
        post: impl FnMut(EndpointId, SocketAddr) -> bool,
    ) -> u32 {
        self.routed
            .as_deref_mut()
            .map_or(0, |routed| routed.path_heartbeats(now, interval, post))
    }

    /// Records a PATH_HB submitted on the path on `endpoint` at `now`: the
    /// path is not idle until `path_heartbeat_interval` later. Only a
    /// submitted one counts (#336 review), so a refused send is tried again
    /// next cycle.
    pub fn path_heartbeat_sent(&mut self, endpoint: EndpointId, now: u64) {
        if let Some(route) = self.routed.as_deref_mut().and_then(|routed| {
            routed
                .routes
                .iter_mut()
                .find(|route| route.endpoint == endpoint)
        }) {
            route.last_sent = Some(now);
        }
    }

    /// Sets when its paths leave the live set (RP-8); a single-path
    /// publication has none.
    pub(crate) fn set_path_policy(&mut self, policy: PathPolicy) {
        if let Some(routed) = self.routed.as_deref_mut() {
            routed.policy = policy;
            // Its NAK copies arrive on every path: sized here, when the
            // publication is added (RP-11).
            if let Some(repair) = self.repair.as_deref_mut() {
                repair.set_absorb(policy.copy_entries, policy.skew_window);
            }
        }
    }

    /// Path `route`'s live-set counters; `None` on one path or past its
    /// paths.
    #[must_use]
    #[inline]
    pub fn path_counters(&self, route: usize) -> Option<PathCounters> {
        let routed = self.routed.as_deref()?;
        let mut counters = routed.routes.get(route)?.counters;
        // The datagrams and bytes are the routed sender's, per route.
        if let Some(sent) = routed.sender.counters(route) {
            counters.datagrams = sent.datagrams;
            counters.bytes = sent.bytes;
            counters.overflowed |= sent.overflowed;
        }
        Some(counters)
    }

    /// Whether path `route` is in the live set and whether it is
    /// `Degraded`; `None` on one path or past its paths.
    #[must_use]
    #[inline]
    pub fn path_state(&self, route: usize) -> Option<(bool, bool)> {
        self.routed
            .as_deref()
            .and_then(|routed| routed.routes.get(route))
            .map(|route| (!route.left, route.degraded))
    }

    /// Lane `lane`'s `sent_low`: the least frontier over its live paths, a
    /// returning path not counted until it submits (RP-9). It can move
    /// backwards: a path counts again from its first submit after a
    /// return, at the selection point, which can be below the frontier of
    /// the paths that stayed. `None` for a publication that is not routed
    /// (it has one path and no `sent_low`), past its lanes, or with no
    /// live path.
    #[must_use]
    pub fn sent_low(&self, lane: usize) -> Option<u64> {
        let routed = self.routed.as_deref()?;
        let track = routed.tracks.get(lane)?;
        routed
            .routes
            .iter()
            .zip(&track.sent_p)
            .filter(|(route, _)| !route.left && !route.returning)
            .map(|(_, frontier)| *frontier)
            .min()
    }

    /// Path `route` takes no copy of the next `count` datagrams, as if its
    /// socket had no room (tests).
    #[cfg(test)]
    pub(crate) fn withhold_route(&mut self, route: usize, count: u32) {
        if let Some(left) = self
            .routed
            .as_deref_mut()
            .and_then(|routed| routed.withhold.get_mut(route))
        {
            *left = count;
        }
    }

    /// Path `route` leaves the live set before the next cycle's flush
    /// (tests).
    #[cfg(test)]
    pub(crate) fn leave_before_serve(&mut self, route: usize) {
        if let Some(routed) = self.routed.as_deref_mut() {
            routed.leave_now = Some(route);
        }
    }

    /// A left path waits `backoff` before it returns (tests).
    #[cfg(test)]
    pub(crate) fn set_path_backoff(&mut self, backoff: u64) {
        if let Some(routed) = self.routed.as_deref_mut() {
            routed.policy.backoff_initial = backoff;
            routed.policy.backoff_max = backoff;
        }
    }

    /// Whether `route` left, and whether it is returning (tests).
    #[cfg(test)]
    pub(crate) fn route_state(&self, route: usize) -> Option<(bool, bool)> {
        self.routed
            .as_deref()
            .and_then(|routed| routed.routes.get(route))
            .map(|slot| (slot.left, slot.returning))
    }

    /// The position of `route`'s first copy held for `lane`, staged and not
    /// submitted (tests).
    #[cfg(test)]
    pub(crate) fn first_held(&self, lane: usize, route: usize) -> Option<u64> {
        self.routed
            .as_deref()
            .and_then(|routed| routed.tracks.get(lane))
            .and_then(|track| track.staged.get(route))
            .and_then(|copies| copies.front().map(|(_, start, _)| *start))
    }

    /// `route`'s frontier on lane `lane`: past the last frame it submitted
    /// or skipped (tests).
    #[cfg(test)]
    pub(crate) fn route_frontier(&self, lane: usize, route: usize) -> Option<u64> {
        self.routed
            .as_deref()
            .and_then(|routed| routed.tracks.get(lane))
            .and_then(|track| track.sent_p.get(route).copied())
    }

    /// Lane `lane`'s sent frontier (tests).
    #[cfg(test)]
    pub(crate) fn sent_high(&self, lane: usize) -> Option<u64> {
        self.tracks.get(lane).map(|track| track.high)
    }

    /// Serves its repairs on every live route (RP-11): each route's TX
    /// half in `halves` that is open at its epoch, not resetting and in the
    /// live set, within `budget`, which it spends, at `now`. Returns the
    /// heads submitted; 0 on one path (see [`Outbound::serve_repair`]).
    pub fn serve_repair_routes<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        budget: &mut RepairBudget,
        now: u64,
    ) -> u32 {
        let Some(routed) = self.routed.as_deref() else {
            return 0;
        };
        let mut routes: [Option<&mut SocketsTx<O>>; MAX_ROUTES] = std::array::from_fn(|_| None);
        for (held, half) in halves.iter_mut() {
            let Half::Tx(tx) = half else {
                continue;
            };
            let Some(index) = routed
                .routes
                .iter()
                .position(|route| route.endpoint == *held)
            else {
                continue;
            };
            if routed.repair_live(index, tx.capabilities().epoch)
                && let Some(slot) = routes.get_mut(index)
            {
                *slot = Some(&mut **tx);
            }
        }
        // A route in the live set that cannot take repairs now (not open
        // at its epoch, resetting, or detached) skips them, counted.
        let mut passed = [false; MAX_ROUTES];
        for ((passed, route), lent) in passed.iter_mut().zip(&routed.routes).zip(&routes) {
            *passed = !route.left && lent.is_none();
        }
        if routes.iter().all(Option::is_none) {
            return 0;
        }
        let served = self.serve_repair_with(&mut routes, budget, now);
        if let Some(repair) = self.repair.as_deref_mut() {
            for (route, passed) in passed.iter().enumerate() {
                if *passed {
                    repair.count_skipped(route, served);
                }
            }
        }
        served
    }

    /// The removal step of a routed publication at `now` (its EOS on every
    /// path): as [`Outbound::serve_removal`], with a lane drained once its
    /// first sends reached its seal on every live path whose TX half is in
    /// `halves`, and its EOS sent on each of them. A route detached (no TX
    /// half), resetting or out of the live set neither holds the drain nor
    /// gets the EOS; one that comes back during the linger gets the repeats.
    /// The EOS counts as sent once one path submitted it.
    pub(crate) fn serve_removal_routes<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        now: u64,
    ) -> RemovalStep {
        if self.routed.is_none() {
            return RemovalStep::default();
        }
        let sending = self.sending_routes(halves);
        self.serve_removal_with(
            now,
            |outbound, lane| outbound.routed_drained_seal(lane, &sending),
            |outbound, lane, seal| outbound.send_eos_routes(halves, &sending, lane, seal),
        )
    }

    /// The seal of `lane` once its first sends reached it on the `sending`
    /// routes: the seal is positioned, every frame below it was submitted,
    /// and none of those routes holds a copy of the lane.
    fn routed_drained_seal(&self, lane: usize, sending: &[bool; MAX_ROUTES]) -> Option<u64> {
        let routed = self.routed.as_deref()?;
        let reader = self.readers.get(lane)?;
        let seal = reader.seal_position()?;
        let high = self.tracks.get(lane)?.high;
        let track = routed.tracks.get(lane)?;
        let idle = sending
            .iter()
            .enumerate()
            .filter(|(_, sending)| **sending)
            .all(|(route, _)| {
                routed.sender.pending(lane, route).unwrap_or(0) == 0
                    && track.staged.get(route).is_none_or(VecDeque::is_empty)
            });
        (idle && high >= seal && reader.position() >= seal).then_some(seal)
    }

    /// The routes that can send now, by route: those whose endpoint's TX
    /// half is held, live in its epoch.
    fn sending_routes<O: SocketOps>(&self, halves: &[(EndpointId, Half<O>)]) -> [bool; MAX_ROUTES] {
        let mut sending = [false; MAX_ROUTES];
        let Some(routed) = self.routed.as_deref() else {
            return sending;
        };
        for (held, half) in halves {
            let Half::Tx(tx) = half else {
                continue;
            };
            if let Some(index) = routed
                .routes
                .iter()
                .position(|route| route.endpoint == *held)
                && routed.repair_live(index, tx.capabilities().epoch)
                && let Some(slot) = sending.get_mut(index)
            {
                *slot = true;
            }
        }
        sending
    }

    /// The idle heartbeats of a routed publication due at `now` (SPEC §6,
    /// karyos#834): a lane sends a header-only DATA frame on each route
    /// that can send and was idle for `interval` ([`idle_routes`]), at its
    /// next position, or at the first copy of it any route still holds
    /// when that is lower, as a single-path lane does on its one. PATH_HB
    /// still keeps each path's binding live (RP-3); this frame is what tells an image where the lane stands, so
    /// a tail lost on every path shows. None while the publication is
    /// removed (its EOS replaces them). Returns the frames submitted.
    pub(crate) fn serve_routed_heartbeats<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        now: u64,
        interval: u64,
    ) -> Option<u32> {
        if self.removing() || self.routed.is_none() {
            return Some(0);
        }
        let sending = self.sending_routes(halves);
        // The routes whose TX half the agent holds now.
        let present: [bool; MAX_ROUTES] = std::array::from_fn(|index| {
            self.routed
                .as_deref()
                .and_then(|routed| routed.routes.get(index))
                .is_some_and(|route| {
                    halves
                        .iter()
                        .any(|(held, half)| *held == route.endpoint && matches!(half, Half::Tx(_)))
                })
        });
        let mut sent = 0u32;
        for lane in 0..self.readers.len() {
            let Some(position) = self.readers.get(lane).map(|reader| reader.position()) else {
                continue;
            };
            // The routes whose lane is idle long enough for a heartbeat,
            // and the position a held copy bounds them at.
            let Some((due, bound)) = self
                .routed
                .as_deref_mut()
                .map(|routed| idle_routes(routed, lane, (&sending, &present), now, interval))
            else {
                break;
            };
            let position = bound.map_or(position, |bound| position.min(bound));
            if !due.contains(&true)
                || self
                    .guard
                    .as_deref_mut()
                    .is_some_and(|guard| !LaneGate::admits(guard, lane))
            {
                continue;
            }
            let routed = self.routed.as_deref()?;
            let mut queues: [Option<(usize, EndpointId, TxQueueId)>; MAX_ROUTES] =
                [None; MAX_ROUTES];
            for (index, (slot, route)) in queues.iter_mut().zip(&routed.routes).enumerate() {
                if due.get(index) == Some(&true) {
                    *slot = route
                        .queues
                        .get(lane)
                        .map(|queue| (index, route.endpoint, *queue));
                }
            }
            for (index, endpoint, queue) in queues.into_iter().flatten() {
                let tx = halves.iter_mut().find_map(|(held, half)| match half {
                    Half::Tx(tx) if *held == endpoint => Some(&mut **tx),
                    _ => None,
                });
                if let Some(tx) = tx
                    && self.write_heartbeat_on(tx, queue, lane, position, false)
                {
                    sent = sent.checked_add(1)?;
                    if let Some(idle) = self
                        .routed
                        .as_deref_mut()
                        .and_then(|routed| routed.tracks.get_mut(lane))
                        .and_then(|track| track.idle_since.get_mut(index))
                    {
                        *idle = Some(now);
                    }
                }
            }
        }
        Some(sent)
    }

    /// The copies `route` holds for `lane`, pending or staged (tests).
    #[cfg(test)]
    pub(crate) fn routed_pending(&self, lane: usize, route: usize) -> usize {
        self.routed
            .as_deref()
            .map_or(0, |routed| held(routed, lane, route))
    }

    /// Sends `lane`'s EOS at `seal` on every `sending` route's lane queue.
    fn send_eos_routes<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        sending: &[bool; MAX_ROUTES],
        lane: usize,
        seal: u64,
    ) -> EosSent {
        if self.eos_closed(lane) {
            return EosSent::Closed;
        }
        let Some(routed) = self.routed.as_deref() else {
            return EosSent::NotSent;
        };
        let mut queues: [Option<(EndpointId, TxQueueId)>; MAX_ROUTES] = [None; MAX_ROUTES];
        for ((slot, route), sending) in queues.iter_mut().zip(&routed.routes).zip(sending) {
            if *sending {
                *slot = route.queues.get(lane).map(|queue| (route.endpoint, *queue));
            }
        }
        let mut submitted = false;
        for (endpoint, queue) in queues.into_iter().flatten() {
            let tx = halves.iter_mut().find_map(|(held, half)| match half {
                Half::Tx(tx) if *held == endpoint => Some(&mut **tx),
                _ => None,
            });
            if let Some(tx) = tx {
                submitted |= self.write_heartbeat_on(tx, queue, lane, seal, true);
            }
        }
        if submitted {
            EosSent::Submitted
        } else {
            EosSent::NotSent
        }
    }

    /// What its repair path counted on `route` (RP-11); `None` on one path,
    /// without repair, or past its routes.
    #[must_use]
    pub fn repair_route_counts(&self, route: usize) -> Option<RouteRepairCounts> {
        self.routed.as_deref()?;
        self.repair.as_deref()?.route_counts(route)
    }

    /// The routed sender (tests).
    #[cfg(test)]
    pub(crate) fn routed_sender(&self) -> Option<&RoutedLaneSender> {
        self.routed.as_deref().map(Routed::sender)
    }

    /// Opens each route's queues on its endpoint, when its epoch is new.
    /// Returns whether at least one route is open.
    fn open_routes<O: SocketOps>(&mut self, halves: &mut [(EndpointId, Half<O>)]) -> bool {
        let Some(routed) = self.routed.as_deref_mut() else {
            return false;
        };
        let mut open = false;
        // The routes that can send, as this pass starts: opened and not
        // waiting for a reset.
        let mut live = [false; MAX_ROUTES];
        for (live, route) in live.iter_mut().zip(&routed.routes) {
            *live = route.opened.is_some() && !route.needs_reset;
        }
        for (index, slot) in routed.routes.iter_mut().enumerate() {
            let Some(tx) = halves.iter_mut().find_map(|(held, half)| match half {
                Half::Tx(tx) if *held == slot.endpoint => Some(&mut **tx),
                _ => None,
            }) else {
                continue;
            };
            let epoch = tx.capabilities().epoch;
            if slot.opened == Some(epoch) {
                open = true;
                continue;
            }
            let Ok(route) = tx.add_route(slot.destination) else {
                self.counters.bump(|c| &mut c.route_failures, 1);
                continue;
            };
            let mut ok = true;
            for lane in 0..slot.queues.len() {
                match tx.open_queue(TxQueueConfig {
                    authority: Authority::FIRST,
                    route,
                    max_pending: NonZeroU16::new(STAGED_PER_LANE).unwrap_or(NonZeroU16::MIN),
                }) {
                    Ok(queue) => {
                        if let Some(held) = slot.queues.get_mut(lane) {
                            *held = queue;
                        }
                    }
                    Err(_) => {
                        self.counters.bump(|c| &mut c.queue_failures, 1);
                        for queue in slot.queues.iter().take(lane) {
                            let _ = tx.close_queue(*queue, &mut self.report);
                            while self.report.pop_front().is_some() {}
                        }
                        let _ = tx.remove_route(route);
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                continue;
            }
            // A reset returned what this route staged and did not submit.
            // While another route still holds a lane's copies, the receivers
            // get them there or by NAK (RP-9: a route rejoins at the current
            // selection point). With none left, a reliable lane reads again
            // from its registered position, as on one path; the copies at
            // or below its debited position go as catch-up, debiting nothing.
            let reopened = slot.opened.is_some();
            // Per lane, whether it reads again what the reset returned.
            let mut rewound = [false; karyos_sys::frame::Lane::COUNT as usize];
            for (lane, reader) in self.readers.iter_mut().enumerate() {
                // Only a route that can still send them holds copies: one
                // resetting or never opened will drop its own (#331 review).
                let others = (0..MAX_ROUTES)
                    .filter(|route| *route != index)
                    .filter(|route| live.get(*route).is_some_and(|live| *live))
                    .filter_map(|route| routed.sender.pending(lane, route))
                    .any(|held| held > 0);
                if reopened && self.reliable && !others {
                    // A faulted reader cannot rewind: its lane already ended.
                    let _ = reader.rewind();
                    if let Some(flag) = rewound.get_mut(lane) {
                        *flag = true;
                    }
                }
            }
            // The route's repair queue, outside the lane sender: every
            // route carries every repair (RP-11).
            if let Some(repair) = self.repair.as_deref_mut() {
                let queue = tx
                    .open_queue(TxQueueConfig {
                        authority: Authority::FIRST,
                        route,
                        max_pending: NonZeroU16::MIN,
                    })
                    .ok();
                if queue.is_none() {
                    self.counters.bump(|c| &mut c.queue_failures, 1);
                }
                repair.reopened_route(index, queue);
            }
            for (lane, queue) in slot.queues.iter().enumerate() {
                // A guarded lane reopens through its gate, which refunds what
                // only this route held.
                match self.guard.as_deref_mut() {
                    Some(guard) => guard.reopen_route(
                        &mut routed.sender,
                        lane,
                        index,
                        *queue,
                        rewound.get(lane).copied().unwrap_or(false),
                    ),
                    None => routed.sender.reopen(lane, index, *queue),
                }
                if let Some(track) = routed.tracks.get_mut(lane) {
                    if let Some(copies) = track.staged.get_mut(index) {
                        copies.clear();
                    }
                    if let Some(unknown) = track.unknown.get_mut(index) {
                        *unknown = false;
                    }
                }
            }
            slot.opened = Some(epoch);
            slot.route = Some(route);
            slot.needs_reset = false;
            slot.reset_requested = None;
            open = true;
        }
        open
    }

    /// Stages `lane`'s committed frames on every route with room, each read
    /// once (module docs). Returns the datagrams read.
    fn stage_routes<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        lane: usize,
        limit: Limit,
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        let Self {
            routed: Some(routed),
            readers,
            tracks,
            counters,
            next_token,
            max_frame,
            mtu,
            guard,
            ..
        } = self
        else {
            return Ok(0);
        };
        let Some(reader) = readers.get_mut(lane) else {
            return Ok(0);
        };
        let bound = usize::from(STAGED_PER_LANE);
        let mut staged = 0u32;
        loop {
            let from = reader.position();
            let fits = match limit {
                Limit::Edge(edge) => from.checked_add(*max_frame).is_some_and(|end| end <= edge),
                Limit::NoReceiverWindow | Limit::Held => false,
            };
            if !fits {
                if let Some(track) = tracks.get_mut(lane)
                    && !std::mem::replace(&mut track.waiting, true)
                {
                    counters.bump(|c| &mut c.window_waits, 1);
                }
                break;
            }
            // Claim first, on every eligible route: opened, with its TX half
            // and room. A frame is read only once a route holds a claimed
            // frame for it, so with no route to take it, it waits, as on one
            // path; it is never read and lost (#321 review).
            let mut frames: [Option<<SocketsTx<O> as TxBackend>::Frame<'_>>; MAX_ROUTES] =
                std::array::from_fn(|_| None);
            for (held, half) in halves.iter_mut() {
                let Half::Tx(tx) = half else {
                    continue;
                };
                let Some(route) = routed.routes.iter().position(|slot| slot.endpoint == *held)
                else {
                    continue;
                };
                let (Some(slot), Some(frame)) = (routed.routes.get(route), frames.get_mut(route))
                else {
                    continue;
                };
                let room = routed
                    .sender
                    .pending(lane, route)
                    .is_some_and(|pending| pending < bound);
                #[cfg(test)]
                let room = room && routed.withhold.get(route).is_none_or(|left| *left == 0);
                // A path out of the live set takes no copy (RP-8).
                let (true, false, false, Some(_), Some(queue)) = (
                    room,
                    slot.needs_reset,
                    slot.left,
                    slot.opened,
                    slot.queues.get(lane),
                ) else {
                    continue;
                };
                *frame = tx.claim_tx(*queue, *mtu).ok();
            }
            if frames.iter().all(Option::is_none) {
                break;
            }
            let Some(scratch) = routed.scratch.get_mut(..*mtu) else {
                break;
            };
            // Unused frames are dropped, which frees their slots.
            let (len, next, record) = match reader.read_committed(from, ReadOrigin::Cursor, scratch)
            {
                Ok(ReadOutcome::Copied { len, next }) => (len, next, false),
                Ok(ReadOutcome::Canonical { next, .. }) => (32, next, true),
                Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => break,
                Err(_) => {
                    counters.bump(|c| &mut c.read_errors, 1);
                    break;
                }
            };
            let charge = u32::try_from(len)
                .ok()
                .and_then(|len| align_frame(len).ok())
                .map(u64::from);
            let (Some(charge), Ok(len16), Some(bytes)) =
                (charge, u16::try_from(len), routed.scratch.get(..len))
            else {
                break;
            };
            // The messages it starts: a guard's message charge.
            let messages = if record || guard.is_none() {
                0
            } else {
                messages_started(bytes)
            };
            let mut copies = 0u32;
            let mut took = [false; MAX_ROUTES];
            for (route, frame) in frames.iter_mut().enumerate().take(routed.routes.len()) {
                // A route without a claimed frame skips this datagram (RP-8);
                // one out of the live set takes none and skips nothing.
                let Some(mut frame) = frame.take() else {
                    if routed.routes.get(route).is_some_and(|slot| !slot.left) {
                        routed.sender.skipped(route);
                    }
                    continue;
                };
                let Some(target) = frame.bytes_mut().get_mut(..len) else {
                    routed.sender.skipped(route);
                    continue;
                };
                target.copy_from_slice(bytes);
                let token = SenderToken::new(*next_token);
                *next_token = next_token.checked_add(1).ok_or(overflow.clone())?;
                let Ok(ticket) = frame.commit(Commit {
                    len,
                    token,
                    options: TxOptions::none(),
                }) else {
                    routed.sender.skipped(route);
                    continue;
                };
                let copy = RoutedStaged {
                    staged: Staged {
                        ticket,
                        charge,
                        len: len16,
                    },
                    position: from,
                };
                // A guarded lane stages through its gate, which records the
                // copy in step with the sender.
                let refused = match guard.as_deref_mut() {
                    Some(guard) => guard
                        .stage_copy(
                            &mut routed.sender,
                            lane,
                            route,
                            copy,
                            GateHead {
                                token,
                                length: u64::from(len16),
                                messages,
                                start: from,
                                end: next,
                            },
                        )
                        .is_err(),
                    None => routed.sender.staged(lane, route, copy).is_err(),
                };
                if refused {
                    // Committed to the queue but not recorded: the route's
                    // records are out of step, and only its reset returns the
                    // item. It takes nothing more until then.
                    counters.bump(|c| &mut c.staged_refused, 1);
                    if let Some(slot) = routed.routes.get_mut(route) {
                        slot.needs_reset = true;
                    }
                    continue;
                }
                if let Some(track) = routed.tracks.get_mut(lane)
                    && let Some(held) = track.staged.get_mut(route)
                {
                    held.push_back((ticket, from, next));
                }
                copies = copies.checked_add(1).ok_or(overflow.clone())?;
                if let Some(took) = took.get_mut(route) {
                    *took = true;
                }
            }
            #[cfg(test)]
            if copies > 0 {
                for left in &mut routed.withhold {
                    if let Some(next) = left.checked_sub(1) {
                        *left = next;
                    }
                }
            }
            // RP-8: the datagram was selected for every live path; those
            // that took no copy skipped it. A datagram no path took waits
            // or is a gap, never one path's skip.
            if copies > 0 {
                for (route, slot) in routed.routes.iter_mut().enumerate() {
                    if slot.left {
                        continue;
                    }
                    let took_it = took.get(route).is_some_and(|took| *took);
                    // A skipped frame counts as passed for its frontier.
                    if !took_it
                        && let Some(frontier) = routed
                            .tracks
                            .get_mut(lane)
                            .and_then(|track| track.sent_p.get_mut(route))
                    {
                        *frontier = (*frontier).max(next);
                    }
                    let skipped = if took_it { 0 } else { charge };
                    if !slot
                        .window
                        .record(now, routed.policy.lag_limit, charge, skipped)
                    {
                        slot.counters.overflowed = true;
                    }
                }
            }
            if copies == 0 {
                // Claimed but committed on no route: a gap the receivers
                // close by repair or their gap policy, as a failed commit on
                // one path.
                counters.bump(|c| &mut c.queue_failures, 1);
                break;
            }
            if let Some(track) = tracks.get_mut(lane) {
                track.waiting = false;
            }
            counters.bump(
                if record {
                    |c| &mut c.records
                } else {
                    |c| &mut c.staged
                },
                1,
            );
            staged = staged.checked_add(1).ok_or(overflow.clone())?;
        }
        Ok(staged)
    }

    /// One cycle of a routed publication: as [`Outbound::serve`], over
    /// every path's TX half in `halves` (module docs).
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub fn serve_routes<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        budget: Budget,
        consumption: Option<&[u64]>,
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        if !self.open_routes(halves) {
            // No route this cycle, but a guard close still applies.
            self.guard_tick(now);
            return Ok(0);
        }
        let (limits, held) = self.limits(now);
        let mut work = 0u32;
        for lane in 0..self.readers.len() {
            let limit = limits.get(lane).copied().unwrap_or(Limit::Held);
            work = work
                .checked_add(self.stage_routes(halves, lane, limit, now)?)
                .ok_or(overflow.clone())?;
        }
        if let Some(guard) = self.guard.as_deref_mut() {
            guard.set_now(now);
        }
        let Some(routed) = self.routed.as_deref_mut() else {
            return Ok(work);
        };
        let mut endpoints = [None; MAX_ROUTES];
        for (slot, route) in endpoints.iter_mut().zip(&routed.routes) {
            *slot = Some(route.endpoint);
        }
        let mut lent = HalfRoutes { halves, endpoints };
        let mut gate = RoutedGate {
            tracks: &mut routed.tracks,
            held,
            guard: self.guard.as_deref_mut(),
        };
        #[cfg(test)]
        if let Some(index) = routed.leave_now.take() {
            let _ = leave(
                &mut routed.sender,
                &mut routed.routes,
                index,
                self.readers.len(),
                (routed.policy, now),
                &mut lent,
                &mut gate,
            );
        }
        let report = routed.sender.serve(&mut lent, &mut gate, budget);
        let caught = routed.sender.catch_up(&mut lent, &mut gate);
        // RP-8, after this cycle's flushes: a lagging path leaves the live
        // set, while another live path remains; its never-exposed copies
        // come back through the gate (the guard's ring settles), and those
        // only it held are counted.
        let policy = routed.policy;
        // The routes a lane waits on alone, and those that submitted now.
        let mut stalls = [false; MAX_ROUTES];
        let mut submitted = [false; MAX_ROUTES];
        for lane in 0..self.readers.len() {
            if let Some(stall) = routed
                .sender
                .sole_holder(lane)
                .and_then(|route| stalls.get_mut(route))
            {
                *stall = true;
            }
        }
        for track in gate.tracks.iter() {
            for (any, sent) in submitted.iter_mut().zip(&track.sent) {
                *any |= *sent;
            }
        }
        for index in 0..routed.routes.len() {
            // The other paths that can send now: live and not returning (a
            // returning path is not live until it submits, RP-9; #350
            // review). One of them must remain for a path to leave.
            let others = routed
                .routes
                .iter()
                .enumerate()
                .filter(|(other, route)| *other != index && !route.left && !route.returning)
                .count();
            let Some(slot) = routed.routes.get_mut(index) else {
                continue;
            };
            if slot.left {
                // RP-9: back after its backoff, on its open queue, from the
                // current selection point; live once it submits again.
                let due = slot
                    .left_at
                    .checked_add(slot.backoff)
                    .is_some_and(|due| now >= due);
                if due {
                    slot.left = false;
                    slot.returning = true;
                    slot.window = PathWindow::default();
                    bump_path(&mut slot.counters.entries, &mut slot.counters.overflowed);
                    routed.sender.set_live(index, true);
                    // A fault exit's queues are retried by the control
                    // path below, now that it is back (`retry_queue` clears
                    // faults only; a refusal waits for the endpoint reset).
                }
                continue;
            }
            if submitted.get(index).is_some_and(|sent| *sent) {
                if std::mem::take(&mut slot.returning) {
                    slot.live_since = Some(now);
                }
                // Live long enough, its wait starts over (RP-9).
                if slot.live_since.is_some_and(|since| {
                    now.checked_sub(since)
                        .is_some_and(|live| live >= policy.backoff_reset)
                }) {
                    slot.backoff = 0;
                    slot.live_since = None;
                }
            }
            let Some((selected, skipped)) = slot.window.sums(now, policy.lag_limit) else {
                slot.counters.overflowed = true;
                continue;
            };
            let degraded = skipped > 0;
            if degraded && !slot.degraded {
                bump_path(&mut slot.counters.degraded, &mut slot.counters.overflowed);
            }
            slot.degraded = degraded;
            let share = skipped.checked_mul(100);
            let limit = selected.checked_mul(u64::from(policy.skip_percent));
            let lagging = selected >= policy.skip_min_bytes
                && matches!((share, limit), (Some(share), Some(limit)) if share > limit);
            // A stall is lag in time: past `path_lag_limit` with the lane
            // waiting on it alone, it leaves; a submit ends it.
            let stalled = stalls.get(index).is_some_and(|stall| *stall)
                && !submitted.get(index).is_some_and(|sent| *sent);
            if !stalled {
                slot.stall_since = None;
            }
            let since = if stalled {
                Some(*slot.stall_since.get_or_insert(now))
            } else {
                None
            };
            let stalled_long = since
                .and_then(|since| now.checked_sub(since))
                .is_some_and(|stalled| stalled > policy.lag_limit);
            // A faulted route leaves too (RP-8), and comes back by
            // `retry_queue` after its backoff (RP-9).
            let faulted = slot.needs_reset
                || (0..self.readers.len())
                    .any(|lane| routed.sender.needs_control(lane, index) == Some(true));
            if !(lagging || stalled_long || faulted) || others == 0 {
                continue;
            }
            if leave(
                &mut routed.sender,
                &mut routed.routes,
                index,
                self.readers.len(),
                (policy, now),
                &mut lent,
                &mut gate,
            ) {
                self.counters.bump(|c| &mut c.queue_failures, 1);
            }
        }
        // Once a cycle, even with nothing flushed, so a close becomes
        // effective with no pending traffic (DN 3.1 step 10); then the
        // aborted lanes' copies come back on every route.
        if let Some(guard) = gate.guard.as_deref_mut() {
            guard.between_gates();
        }
        let mut cancelled = false;
        for lane in 0..self.readers.len() {
            let pending = (0..MAX_ROUTES)
                .filter_map(|route| routed.sender.pending(lane, route))
                .any(|held| held > 0);
            if !gate.aborting(lane) || !pending {
                continue;
            }
            // A detached route cannot cancel, and may never come back: its
            // copies are forgotten first, so the close does not wait for its
            // reopen (ACS 17049) and `cancel` counts none `uncancelled`. Its
            // queue still holds them, so it comes back only through a reset,
            // whose reopen replaces the queue.
            for (index, slot) in routed.routes.iter_mut().enumerate() {
                let held = routed
                    .sender
                    .pending(lane, index)
                    .is_some_and(|held| held > 0);
                if !held || lent.route(index).is_some() {
                    continue;
                }
                if routed.sender.forget(lane, index, &mut gate) > 0 {
                    slot.needs_reset = true;
                    cancelled = true;
                }
                if let Some(copies) = gate
                    .tracks
                    .get_mut(lane)
                    .and_then(|track| track.staged.get_mut(index))
                {
                    copies.clear();
                }
            }
            let pending = (0..MAX_ROUTES)
                .filter_map(|route| routed.sender.pending(lane, route))
                .any(|held| held > 0);
            if !pending {
                continue;
            }
            match routed.sender.cancel(&mut lent, lane, &mut gate) {
                Ok(()) => cancelled = true,
                Err(_) => {
                    cancelled = true;
                    self.counters.bump(|c| &mut c.queue_failures, 1);
                }
            }
        }
        if cancelled && let Some(guard) = gate.guard.as_deref_mut() {
            guard.between_gates();
        }
        work = work.checked_add(caught.submitted).ok_or(overflow.clone())?;
        // The control path per route (lane-sender.md, outcome table): a
        // failure resets only its route's endpoint; a faulted queue is
        // retried, keeping its copies; an unknown copy waits for the reset.
        let mut failed = routed.sender.take_failures();
        // A failure of the call itself is one route's when there is one
        // route, or the whole publication's (a DRR error): every route
        // resets, never only the founding one (#331 review).
        let whole = report.failure.or(caught.failure);
        for slot in failed.iter_mut().take(routed.routes.len()) {
            *slot = slot.or(whole);
        }
        for (index, slot) in routed.routes.iter_mut().enumerate() {
            // A route that submitted DATA this call is not idle (RP-3).
            let mut sent = false;
            for track in &mut routed.tracks {
                if let Some(flag) = track.sent.get_mut(index) {
                    let lane_sent = std::mem::take(flag);
                    sent |= lane_sent;
                    // Any DATA on the route restarts its lane's idle wait.
                    if lane_sent && let Some(idle) = track.idle_since.get_mut(index) {
                        *idle = Some(now);
                    }
                }
            }
            if sent {
                slot.last_sent = Some(now);
            }
            if failed.get(index).copied().flatten().is_some() {
                self.counters.bump(|c| &mut c.send_failures, 1);
                slot.needs_reset = true;
            }
            for lane in 0..self.readers.len() {
                let unknown = routed
                    .tracks
                    .get(lane)
                    .and_then(|track| track.unknown.get(index))
                    .is_some_and(|unknown| *unknown);
                if unknown {
                    slot.needs_reset = true;
                    continue;
                }
                // A left route's faults wait for its return (RP-9).
                if slot.left
                    || slot.needs_reset
                    || routed.sender.needs_control(lane, index) != Some(true)
                {
                    continue;
                }
                self.counters.bump(|c| &mut c.send_faults, 1);
                let queue = slot.queues.get(lane).copied();
                let tx = lent.route(index);
                let retried = match (queue, tx) {
                    (Some(queue), Some(tx)) => tx.retry_queue(queue).is_ok(),
                    _ => false,
                };
                if retried {
                    routed.sender.retry(lane, index);
                } else {
                    slot.needs_reset = true;
                }
            }
        }
        let Some(routed) = self.routed.as_deref_mut() else {
            return Ok(work);
        };
        for (lane, routed_track) in routed.tracks.iter_mut().enumerate() {
            if std::mem::take(&mut routed_track.mismatched) {
                self.counters.bump(|c| &mut c.mismatched, 1);
            }
            let Some(submitted) = routed_track.submitted.take() else {
                continue;
            };
            self.counters.bump(|c| &mut c.submitted, 1);
            if let Some(track) = self.tracks.get_mut(lane) {
                // The sent frontier: the highest position submitted on any
                // route, never decreasing.
                track.high = track.high.max(submitted);
            }
        }
        self.advance_registered(consumption);
        Ok(work)
    }
}

#[cfg(test)]
mod tests;
