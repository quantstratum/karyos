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
    Authority, BackendEpoch, Commit, Exposure, GateDecision, SenderGate, SenderToken, TxBackend,
    TxFrame, TxOptions, TxQueueConfig, TxQueueId, TxTicket,
};
use karyos_io::lanes::routes::{MAX_ROUTES, RoutedLaneSender, RoutedStaged, Routes};
use karyos_io::lanes::{LaneGate, Left, Staged};
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::lanes::drr::{Budget, DrrConfig};
use karyos_sys::log_buffer::{ReadError, ReadOrigin, ReadOutcome};

use super::super::{AgentError, AgentKind, EndpointId, Half};
use super::{Limit, Outbound, OutboundError, STAGED_PER_LANE, align_frame, messages_started};
use crate::guard_gate::{GateHead, GuardGate};

/// One path of a routed publication.
#[derive(Debug)]
pub(super) struct RouteSlot {
    endpoint: EndpointId,
    destination: SocketAddr,
    /// One queue per lane on this route's endpoint.
    queues: Vec<TxQueueId>,
    /// The endpoint epoch its queues were opened in.
    opened: Option<BackendEpoch>,
    /// This route's endpoint needs a reset before the route sends again: a
    /// failure of its half, an item of unknown exposure, or a fault its
    /// queue refused to retry. Its new epoch clears it.
    needs_reset: bool,
    /// The sender cycle of the last reset request posted for it.
    reset_requested: Option<u64>,
}

/// One lane's staged copies per route, in order, and what left.
#[derive(Debug)]
pub(super) struct RoutedTrack {
    /// Per route: the ticket of each staged copy and the position after it.
    staged: [VecDeque<(TxTicket, u64)>; MAX_ROUTES],
    /// The highest position a submitted copy reached, this call.
    submitted: Option<u64>,
    /// A copy left out of staging order, this call.
    mismatched: bool,
    /// Per route: a copy left with an unproven exposure; only that route's
    /// endpoint reset resolves it.
    unknown: [bool; MAX_ROUTES],
}

/// The routed part of an [`Outbound`].
#[derive(Debug)]
pub(super) struct Routed {
    sender: RoutedLaneSender,
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
        if routes.is_empty() || routes.len() > MAX_ROUTES {
            return Err(OutboundError::Lanes);
        }
        let placeholder = TxQueueId::new(BackendEpoch::FIRST, u16::MAX, NonZeroU32::MAX);
        let queues = vec![placeholder; lanes];
        let per_route: Vec<&[TxQueueId]> = routes.iter().map(|_| queues.as_slice()).collect();
        let bound = usize::from(STAGED_PER_LANE);
        let sender =
            RoutedLaneSender::new(config, &per_route, bound).map_err(|_| OutboundError::Lanes)?;
        Ok(Self {
            sender,
            routes: routes
                .iter()
                .map(|&(endpoint, destination)| RouteSlot {
                    endpoint,
                    destination,
                    queues: queues.clone(),
                    opened: None,
                    needs_reset: false,
                    reset_requested: None,
                })
                .collect(),
            tracks: (0..lanes)
                .map(|_| RoutedTrack {
                    staged: std::array::from_fn(|_| VecDeque::with_capacity(bound)),
                    submitted: None,
                    mismatched: false,
                    unknown: [false; MAX_ROUTES],
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

    /// Whether the founding route's queues are open in `epoch`.
    pub(super) fn founding_open(&self, epoch: BackendEpoch) -> bool {
        self.routes
            .first()
            .is_some_and(|route| route.opened == Some(epoch) && !route.needs_reset)
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
                Some((ticket, next)) if ticket == staged.ticket => {
                    copies.pop_front();
                    Some((route, next))
                }
                _ => None,
            });
        match (found, how) {
            (Some((_, next)), Left::Submitted) => {
                track.submitted = Some(track.submitted.map_or(next, |high| high.max(next)));
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

impl Outbound {
    /// The data path of the publication `alias` over redundant paths:
    /// `routes` names each path's endpoint and destination, the founding
    /// path first. Otherwise as [`Outbound::new`].
    ///
    /// # Errors
    ///
    /// [`OutboundError`].
    pub fn new_routed(
        routes: &[(EndpointId, SocketAddr)],
        alias: karyos_protocol::network::Alias,
        readers: Vec<super::LaneReader>,
        quanta: &karyos_protocol::network::Lanes<u64>,
        mtu: u32,
        reliable: bool,
    ) -> Result<Self, OutboundError> {
        let &(endpoint, destination) = routes.first().ok_or(OutboundError::Lanes)?;
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

    /// Lane `lane`'s sent frontier (tests).
    #[cfg(test)]
    pub(crate) fn sent_high(&self, lane: usize) -> Option<u64> {
        self.tracks.get(lane).map(|track| track.high)
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
            for (lane, reader) in self.readers.iter_mut().enumerate() {
                let others = (0..MAX_ROUTES)
                    .filter(|route| *route != index)
                    .filter_map(|route| routed.sender.pending(lane, route))
                    .any(|held| held > 0);
                if reopened && self.reliable && !others {
                    // A faulted reader cannot rewind: its lane already ended.
                    let _ = reader.rewind();
                }
            }
            // The repair queue, on the founding route and outside the lane
            // sender (repair stays on the founding path until rp-w6).
            if index == 0
                && let Some(repair) = self.repair.as_deref_mut()
            {
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
                repair.reopened(queue);
            }
            for (lane, queue) in slot.queues.iter().enumerate() {
                // A guarded lane reopens through its gate, which refunds what
                // only this route held.
                match self.guard.as_deref_mut() {
                    Some(guard) => guard.reopen_route(&mut routed.sender, lane, index, *queue),
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
                let (true, false, Some(_), Some(queue)) =
                    (room, slot.needs_reset, slot.opened, slot.queues.get(lane))
                else {
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
            for (route, frame) in frames.iter_mut().enumerate().take(routed.routes.len()) {
                // A route without a claimed frame skips this datagram (RP-8).
                let Some(mut frame) = frame.take() else {
                    routed.sender.skipped(route);
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
                    held.push_back((ticket, next));
                }
                copies = copies.checked_add(1).ok_or(overflow.clone())?;
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
                .checked_add(self.stage_routes(halves, lane, limit)?)
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
        let report = routed.sender.serve(&mut lent, &mut gate, budget);
        let caught = routed.sender.catch_up(&mut lent, &mut gate);
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
        if let Some(first) = failed.first_mut() {
            // One route: its failure stopped the call, as on one path.
            *first = first.or(report.failure).or(caught.failure);
        }
        for (index, slot) in routed.routes.iter_mut().enumerate() {
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
                if slot.needs_reset || routed.sender.needs_control(lane, index) != Some(true) {
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
