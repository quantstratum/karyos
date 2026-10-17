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
//! stays on the founding route (RP-11 is rp-w6). A guard is refused on a
//! routed publication ([`GateError::Routed`]) until every route's exposure
//! passes the guard gate (rp-w4b2), so no path can bypass a close.

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
use super::{Limit, Outbound, OutboundError, STAGED_PER_LANE, align_frame};

/// One path of a routed publication.
#[derive(Debug)]
pub(super) struct RouteSlot {
    endpoint: EndpointId,
    destination: SocketAddr,
    /// One queue per lane on this route's endpoint.
    queues: Vec<TxQueueId>,
    /// The endpoint epoch its queues were opened in.
    opened: Option<BackendEpoch>,
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
                })
                .collect(),
            tracks: (0..lanes)
                .map(|_| RoutedTrack {
                    staged: std::array::from_fn(|_| VecDeque::with_capacity(bound)),
                    submitted: None,
                    mismatched: false,
                })
                .collect(),
            scratch: vec![0; mtu],
        })
    }

    /// The routes' endpoints, in route order.
    pub(super) fn endpoints(&self) -> impl Iterator<Item = EndpointId> + '_ {
        self.routes.iter().map(|route| route.endpoint)
    }

    /// The routed sender, for diagnostics and tests.
    #[cfg(test)]
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

/// The routed data gate: every candidate is permitted (a routed
/// publication has no guard yet), and the lanes are held while a required
/// loss is unresolved. It records, per lane, the highest position a
/// submitted copy reached.
struct RoutedGate<'a> {
    tracks: &'a mut [RoutedTrack],
    held: bool,
}

impl SenderGate for RoutedGate<'_> {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
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
    fn admits(&mut self, _lane: usize) -> bool {
        !self.held
    }

    fn left(&mut self, lane: usize, staged: Staged, how: Left) {
        let Some(track) = self.tracks.get_mut(lane) else {
            return;
        };
        // Copies leave in staging order on their own route.
        let found = track
            .staged
            .iter_mut()
            .find_map(|copies| match copies.front().copied() {
                Some((ticket, next)) if ticket == staged.ticket => {
                    copies.pop_front();
                    Some(next)
                }
                _ => None,
            });
        match (found, how) {
            (Some(next), Left::Submitted) => {
                track.submitted = Some(track.submitted.map_or(next, |high| high.max(next)));
            }
            (Some(_), Left::Returned | Left::Unknown) => {}
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
            for (lane, queue) in slot.queues.iter().enumerate() {
                routed.sender.reopen(lane, index, *queue);
                if let Some(track) = routed.tracks.get_mut(lane)
                    && let Some(copies) = track.staged.get_mut(index)
                {
                    copies.clear();
                }
            }
            slot.opened = Some(epoch);
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
                let (true, Some(_), Some(queue)) = (room, slot.opened, slot.queues.get(lane))
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
                if routed.sender.staged(lane, route, copy).is_err() {
                    counters.bump(|c| &mut c.staged_refused, 1);
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
        };
        let report = routed.sender.serve(&mut lent, &mut gate, budget);
        let caught = routed.sender.catch_up(&mut lent, &mut gate);
        work = work.checked_add(caught.submitted).ok_or(overflow.clone())?;
        // Interim until rp-w4b1b's per-route control path: any route's
        // failure marks the publication as needing a reset.
        let failed = routed.sender.take_failures();
        if report.failure.is_some()
            || caught.failure.is_some()
            || failed.iter().any(Option::is_some)
        {
            self.needs_reset = true;
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
