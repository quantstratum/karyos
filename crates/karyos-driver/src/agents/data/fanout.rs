// SPDX-License-Identifier: Apache-2.0

//! A multi-destination publication's first sends (`quantstratum-docs:
//! karyos/design/multi-destination-unicast.md` sections 4 and 6;
//! ADR-0056, ADR-0082; karyos#630).
//!
//! A fan-out [`Outbound`] sends every datagram over unicast to each
//! destination of a fixed set (`control-mode=manual`), all on one endpoint.
//! Each destination is a [`Target`]: a backend route to its address, a TX
//! queue per lane and its own lane sender. Per lane the reader's cursor
//! reads a committed datagram once into scratch storage allocated with the
//! publication (MD-2), and the datagram is copied into each live target
//! whose own window admits it (MD-1: a target is held at its member's
//! edge, besides the strategy edge every target shares). The cursor moves
//! past a datagram only once every live target has it staged, so a target
//! whose queue is full holds the next datagram of every target until it
//! takes it. That is this step's limit: the removal of a slow optional
//! destination (MD-7) comes with the per-destination queues of the next
//! step, as does repair to the requester only (MD-8); a reliable channel
//! with destinations is refused until then.
//!
//! A target is live while its receiver is an active member of the
//! publication's membership, bound to the target's address: its SMs must
//! come from that address (MD-16). A target with no live member gets no
//! copy; a receiver that joins later starts at its join point and NAKs
//! what it missed (MD-15, with the next step's repair).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32};

use karyos_io::backend::{
    Authority, BackendEpoch, Commit, Exposure, GateDecision, RouteId, SenderGate, SenderToken,
    TxBackend, TxFrame, TxOptions, TxQueueConfig, TxQueueId, TxTicket,
};
use karyos_io::lanes::{LaneGate, LaneSender, Left, SenderFailure, Staged};
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::frame::Lane;
use karyos_protocol::lanes::drr::{Budget, DrrConfig};
use karyos_sys::log_buffer::{ReadError, ReadOrigin, ReadOutcome};

use super::removal::{EosSent, RemovalStep};
use super::{Limit, OPENED_QUEUES, Opened, Outbound, STAGED_PER_LANE, align_frame};
use crate::agents::{AgentError, AgentKind};
use crate::embedded::StreamTerms;

/// The most destinations of one publication (MD-6: `max_destinations`
/// defaults to 16, configurable up to 64; this step fixes it at 16).
pub const MAX_DESTINATIONS: usize = 16;

/// One target's lane: its staged heads, in order, and what left.
#[derive(Debug)]
struct TargetLane {
    /// Ticket and the stream position after it, per staged datagram.
    staged: VecDeque<(TxTicket, u64)>,
    /// The highest position a submitted head reached.
    high: u64,
    /// A head was returned unsent or of unknown exposure.
    unsent: bool,
    /// A head left out of staging order.
    mismatched: bool,
}

/// One destination (design section 2.1).
#[derive(Debug)]
pub(super) struct Target {
    address: SocketAddr,
    /// Named required by its endpoint at creation (MD-11, MD-17).
    required: bool,
    sender: LaneSender,
    queues: Vec<TxQueueId>,
    lanes: Vec<TargetLane>,
    route: Option<RouteId>,
    opened: Option<BackendEpoch>,
    /// Its member is active and live: it gets copies.
    live: bool,
    /// Per lane, since when it submitted nothing: its idle heartbeat is
    /// due `sender_heartbeat_interval` later.
    idle_since: [Option<u64>; 4],
    counters: TargetCounters,
}

/// What one destination sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TargetCounters {
    /// Datagrams staged for it.
    pub staged: u64,
    /// Datagrams it submitted.
    pub submitted: u64,
    /// Times its copy waited at its own edge.
    pub window_waits: u64,
    /// Times its full queue held the shared cursor.
    pub fanout_waits: u64,
}

/// A datagram read once and not yet staged for every live target.
#[derive(Debug, Clone, Copy)]
struct Pending {
    from: u64,
    next: u64,
    len: usize,
}

/// The fan-out state of a multi-destination publication.
#[derive(Debug)]
pub(super) struct Fanout {
    targets: Vec<Target>,
    /// Per lane, the datagram read and the targets that still need it.
    pending: Vec<Option<Pending>>,
    /// Per lane and target, whether the pending datagram is staged there.
    staged_for: Vec<Vec<bool>>,
    /// Per lane, one datagram of scratch (MD-2).
    scratch: Vec<Vec<u8>>,
    /// The rotating start of each cycle's target visits (MD-9).
    rotation: usize,
}

/// The gate of one target's first sends: every candidate is permitted,
/// unless a required loss holds them; it records what left.
struct TargetGate<'a> {
    lanes: &'a mut [TargetLane],
    held: bool,
}

impl SenderGate for TargetGate<'_> {
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

impl LaneGate for TargetGate<'_> {
    fn admits(&mut self, _lane: usize) -> bool {
        !self.held
    }

    fn aborting(&self, _lane: usize) -> bool {
        false
    }

    fn flushing(&mut self, _lane: usize) {}

    fn left(&mut self, lane: usize, staged: Staged, how: Left) {
        let Some(track) = self.lanes.get_mut(lane) else {
            return;
        };
        match track.staged.pop_front() {
            Some((ticket, next)) if ticket == staged.ticket => match how {
                Left::Submitted => track.high = track.high.max(next),
                Left::Returned | Left::Unknown => track.unsent = true,
            },
            _ => track.mismatched = true,
        }
    }
}

impl Fanout {
    /// The fan-out toward `destinations`, of which `required` are required,
    /// with `lanes` lanes of datagrams of at most `mtu` bytes served under
    /// `drr`, each lane starting at `joins[lane]`.
    pub(super) fn new(
        destinations: &[SocketAddr],
        required: &[SocketAddr],
        drr: DrrConfig,
        lanes: usize,
        mtu: usize,
        joins: &[u64],
    ) -> Option<Self> {
        let placeholder = TxQueueId::new(BackendEpoch::FIRST, u16::MAX, NonZeroU32::MAX);
        let bound = usize::from(STAGED_PER_LANE);
        let mut targets = Vec::with_capacity(destinations.len());
        for address in destinations {
            let queues = vec![placeholder; lanes];
            let sender = LaneSender::new(drr, &queues, bound).ok()?;
            targets.push(Target {
                address: *address,
                required: required.contains(address),
                sender,
                queues,
                lanes: (0..lanes)
                    .map(|lane| TargetLane {
                        staged: VecDeque::with_capacity(bound),
                        high: joins.get(lane).copied().unwrap_or(0),
                        unsent: false,
                        mismatched: false,
                    })
                    .collect(),
                route: None,
                opened: None,
                live: false,
                idle_since: [None; 4],
                counters: TargetCounters::default(),
            });
        }
        Some(Self {
            staged_for: vec![vec![false; targets.len()]; lanes],
            targets,
            pending: vec![None; lanes],
            scratch: (0..lanes).map(|_| vec![0; mtu]).collect(),
            rotation: 0,
        })
    }

    /// The destinations, in configuration order.
    pub(super) fn addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.targets.iter().map(|target| target.address)
    }

    /// Whether `address` is one of its destinations.
    pub(super) fn has(&self, address: SocketAddr) -> bool {
        self.targets.iter().any(|target| target.address == address)
    }

    /// The required destinations.
    pub(super) fn required(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.targets
            .iter()
            .filter(|target| target.required)
            .map(|target| target.address)
    }

    /// Whether every destination is live.
    pub(super) fn all_live(&self) -> bool {
        self.targets.iter().all(|target| target.live)
    }

    /// The destinations not live, which announce again.
    pub(super) fn not_live(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.targets
            .iter()
            .filter(|target| !target.live)
            .map(|target| target.address)
    }

    /// Each target's route and queues in its epoch.
    pub(super) fn opened_resources(
        &self,
        endpoint: crate::agents::EndpointId,
        held: &mut impl FnMut(Opened),
    ) {
        for target in &self.targets {
            let (Some(epoch), Some(route)) = (target.opened, target.route) else {
                continue;
            };
            let mut queues = [None; OPENED_QUEUES];
            for (slot, queue) in queues.iter_mut().zip(&target.queues) {
                *slot = Some(*queue);
            }
            held(Opened {
                endpoint,
                epoch,
                route,
                queues,
            });
        }
    }

    /// Whether `lane` has nothing read and nothing staged or pending on any
    /// target.
    fn idle(&self, lane: usize) -> bool {
        self.pending.get(lane).is_none_or(Option::is_none)
            && self.targets.iter().all(|target| {
                target
                    .lanes
                    .get(lane)
                    .is_none_or(|track| track.staged.is_empty())
                    && target.sender.pending(lane).unwrap_or(0) == 0
            })
    }

    /// `lane`'s sent frontier: the least position its live targets
    /// submitted (`sent_low`, design 4.3), or the most any target did when
    /// none is live.
    fn sent(&self, lane: usize) -> Option<u64> {
        let high = |target: &Target| target.lanes.get(lane).map(|track| track.high);
        self.targets
            .iter()
            .filter(|target| target.live)
            .filter_map(high)
            .min()
            .or_else(|| self.targets.iter().filter_map(high).max())
    }
}

impl<T: StreamTerms> Outbound<T> {
    /// The fan-out of a multi-destination publication toward
    /// `destinations`, `required` among them, replacing the single
    /// destination it was built with (control path, before it is posted).
    ///
    /// # Errors
    ///
    /// [`super::OutboundError::Routes`] for no destination, one named twice,
    /// or a required one that is not a destination.
    pub(crate) fn set_destinations(
        &mut self,
        destinations: &[SocketAddr],
        required: &[SocketAddr],
    ) -> Result<(), super::OutboundError> {
        let distinct = destinations.iter().enumerate().all(|(at, address)| {
            !destinations
                .iter()
                .skip(at + 1)
                .any(|other| other == address)
        });
        if destinations.is_empty()
            || !distinct
            || required
                .iter()
                .any(|address| !destinations.contains(address))
            || self.routed.is_some()
        {
            return Err(super::OutboundError::Routes);
        }
        let joins: Vec<u64> = self
            .readers
            .iter()
            .map(|reader| reader.position())
            .collect();
        let fanout = Fanout::new(
            destinations,
            required,
            self.drr,
            self.readers.len(),
            self.mtu,
            &joins,
        )
        .ok_or(super::OutboundError::Lanes)?;
        self.fanout = Some(Box::new(fanout));
        Ok(())
    }

    /// Its destinations, for a multi-destination publication.
    pub(crate) fn destinations(&self) -> Option<impl Iterator<Item = SocketAddr> + '_> {
        self.fanout.as_deref().map(Fanout::addresses)
    }

    /// Whether `address` is one of its destinations; `true` for any address
    /// of a publication with one destination, which checks it elsewhere.
    pub(crate) fn sends_to(&self, address: SocketAddr) -> bool {
        self.fanout
            .as_deref()
            .is_none_or(|fanout| fanout.has(address))
    }

    /// Its required destinations.
    pub(crate) fn required_destinations(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.fanout
            .as_deref()
            .into_iter()
            .flat_map(Fanout::required)
    }

    /// Its destinations that are not live, each announced to again; empty
    /// for a publication with one destination.
    pub(crate) fn destinations_not_live(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.fanout
            .as_deref()
            .into_iter()
            .flat_map(Fanout::not_live)
    }

    /// Whether every destination of a multi-destination publication is live
    /// (`true` for one with one destination).
    pub(crate) fn every_destination_live(&self) -> bool {
        self.fanout.as_deref().is_none_or(Fanout::all_live)
    }

    /// Opens each target's route and lane queues for the current epoch,
    /// once per epoch; a new epoch drops what the old one staged.
    fn open_targets<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>) -> bool {
        let epoch = tx.capabilities().epoch;
        let Some(fanout) = self.fanout.as_deref_mut() else {
            return false;
        };
        let mut reopened = false;
        for target in &mut fanout.targets {
            if target.opened == Some(epoch) {
                continue;
            }
            let Ok(route) = tx.add_route(target.address) else {
                self.counters.bump(|c| &mut c.route_failures, 1);
                return false;
            };
            for lane in 0..target.queues.len() {
                let opened = tx.open_queue(TxQueueConfig {
                    authority: Authority::FIRST,
                    route,
                    max_pending: NonZeroU16::new(STAGED_PER_LANE).unwrap_or(NonZeroU16::MIN),
                });
                let Ok(opened) = opened else {
                    self.counters.bump(|c| &mut c.queue_failures, 1);
                    for queue in target.queues.iter().take(lane) {
                        let _ = tx.close_queue(*queue, &mut self.report);
                        while self.report.pop_front().is_some() {}
                    }
                    let _ = tx.remove_route(route);
                    return false;
                };
                if let Some(queue) = target.queues.get_mut(lane) {
                    *queue = opened;
                }
            }
            for (lane, queue) in target.queues.iter().enumerate() {
                target.sender.reopen(lane, *queue);
            }
            for track in &mut target.lanes {
                track.staged.clear();
            }
            reopened |= target.opened.is_some();
            target.opened = Some(epoch);
            target.route = Some(route);
        }
        if reopened {
            // What the old epoch read but had not staged everywhere is
            // dropped: the receivers close the gap by their gap policy.
            fanout.pending.fill(None);
        }
        self.opened = Some(epoch);
        self.needs_reset = false;
        self.reset_requested = None;
        true
    }

    /// Marks each target live when its member is: an active member bound
    /// to the target's address (MD-16).
    fn refresh_targets(&mut self, now: u64) {
        let (Some(fanout), membership) = (self.fanout.as_deref_mut(), self.membership.as_deref())
        else {
            return;
        };
        for target in &mut fanout.targets {
            target.live =
                membership.is_some_and(|membership| membership.live_at(target.address, now));
        }
    }

    /// One fan-out cycle: stage each lane's committed datagrams into every
    /// live target, serve each target's lanes, and move the registered
    /// positions by the least that every live target submitted.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub(super) fn serve_fanout<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        budget: Budget,
        consumption: Option<&[u64]>,
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        if !self.open_targets(tx) {
            return Ok(0);
        }
        self.refresh_targets(now);
        let (limits, held) = self.limits(now);
        let mut work = 0u32;
        for lane in 0..self.readers.len() {
            let limit = limits.get(lane).copied().unwrap_or(Limit::Held);
            work = work
                .checked_add(self.stage_fanout(tx, lane, limit, now)?)
                .ok_or(overflow.clone())?;
        }
        let Some(fanout) = self.fanout.as_deref_mut() else {
            return Ok(work);
        };
        // Each live target is served in turn from a rotating start (MD-9).
        let count = fanout.targets.len();
        fanout.rotation = if count == 0 {
            0
        } else {
            fanout.rotation.wrapping_add(1) % count
        };
        let mut failure = None;
        for visit in 0..count {
            let at = (fanout.rotation + visit) % count;
            let Some(target) = fanout.targets.get_mut(at) else {
                continue;
            };
            let mut gate = TargetGate {
                lanes: &mut target.lanes,
                held,
            };
            let report = target.sender.serve(tx, &mut gate, budget);
            if report.failure.is_some() {
                failure = report.failure;
            }
            for track in &mut target.lanes {
                if std::mem::take(&mut track.unsent) {
                    self.counters.bump(|c| &mut c.unsent, 1);
                }
                if std::mem::take(&mut track.mismatched) {
                    self.counters.bump(|c| &mut c.mismatched, 1);
                }
            }
            // A faulted queue is retried; anything else needs a reset of
            // the shared endpoint (the next step keeps faults per
            // destination, MD-12).
            for lane in 0..target.queues.len() {
                if target.sender.suspended(lane) == Some(true) {
                    self.needs_reset = true;
                } else if target.sender.needs_control(lane) == Some(true) {
                    self.counters.bump(|c| &mut c.send_faults, 1);
                    let retried = target
                        .queues
                        .get(lane)
                        .is_some_and(|queue| tx.retry_queue(*queue).is_ok());
                    if retried {
                        target.sender.retry(lane);
                    } else {
                        self.needs_reset = true;
                    }
                }
            }
        }
        if let Some(
            SenderFailure::Backend { .. }
            | SenderFailure::Invariant { .. }
            | SenderFailure::Sender { .. }
            | SenderFailure::Drr(_),
        ) = failure
        {
            self.counters.bump(|c| &mut c.send_failures, 1);
            self.needs_reset = true;
        }
        // The publication's sent frontier per lane: what every live target
        // submitted. It moves the registered position and the membership's
        // sent bound as one destination's would.
        for lane in 0..self.readers.len() {
            let sent = self.fanout.as_deref().and_then(|fanout| fanout.sent(lane));
            if let (Some(sent), Some(track)) = (sent, self.tracks.get_mut(lane))
                && sent > track.high
            {
                track.high = sent;
                self.counters.bump(|c| &mut c.submitted, 1);
                if let Some(idle) = self.idle_since.get_mut(lane) {
                    *idle = Some(now);
                }
            }
        }
        self.advance_registered(consumption);
        Ok(work)
    }

    /// Reads `lane`'s committed datagrams once each and stages each into
    /// every live target, until a target cannot take one or nothing more
    /// is committed.
    fn stage_fanout<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        lane: usize,
        limit: Limit,
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        let mut staged = 0u32;
        loop {
            let Some(fanout) = self.fanout.as_deref_mut() else {
                return Ok(staged);
            };
            let Some(reader) = self.readers.get_mut(lane) else {
                return Ok(staged);
            };
            // A datagram to read, if none is pending: the strategy edge and
            // the required bound admit a whole frame from the cursor.
            if fanout.pending.get(lane).is_some_and(Option::is_none) {
                if !fanout.targets.iter().any(|target| target.live) {
                    return Ok(staged);
                }
                let from = reader.position();
                let fits = match limit {
                    Limit::Edge(edge) => from
                        .checked_add(self.max_frame)
                        .is_some_and(|end| end <= edge),
                    Limit::NoReceiverWindow | Limit::Held => false,
                };
                if !fits {
                    if let Some(track) = self.tracks.get_mut(lane)
                        && !std::mem::replace(&mut track.waiting, true)
                    {
                        self.counters.bump(|c| &mut c.window_waits, 1);
                    }
                    return Ok(staged);
                }
                let Some(scratch) = fanout.scratch.get_mut(lane) else {
                    return Ok(staged);
                };
                let (len, next, record) =
                    match reader.read_committed(from, ReadOrigin::Cursor, scratch) {
                        Ok(ReadOutcome::Copied { len, next }) => (len, next, false),
                        Ok(ReadOutcome::Canonical { next, record: _ }) => (32, next, true),
                        Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => return Ok(staged),
                        Err(_) => {
                            self.counters.bump(|c| &mut c.read_errors, 1);
                            return Ok(staged);
                        }
                    };
                if let Some(slot) = fanout.pending.get_mut(lane) {
                    *slot = Some(Pending { from, next, len });
                }
                if let Some(flags) = fanout.staged_for.get_mut(lane) {
                    flags.fill(false);
                }
                if let Some(track) = self.tracks.get_mut(lane) {
                    track.waiting = false;
                }
                self.counters.bump(
                    if record {
                        |c| &mut c.records
                    } else {
                        |c| &mut c.staged
                    },
                    1,
                );
                self.counters
                    .bump(|c| &mut c.bytes, u64::try_from(len).unwrap_or(0));
            }
            let Some(pending) = fanout.pending.get(lane).copied().flatten() else {
                return Ok(staged);
            };
            // Copy into each live target that does not have it and whose
            // own edge and queue admit it (MD-1).
            let lane_id = u8::try_from(lane).ok().and_then(|l| Lane::try_new(l).ok());
            let mut waiting = false;
            for (at, target) in fanout.targets.iter_mut().enumerate() {
                let done = fanout
                    .staged_for
                    .get(lane)
                    .and_then(|flags| flags.get(at))
                    .copied()
                    .unwrap_or(true);
                if done || !target.live {
                    continue;
                }
                let own = lane_id.and_then(|lane| {
                    self.membership
                        .as_deref()
                        .and_then(|membership| membership.edge_at(target.address, lane, now))
                });
                let fits = own.is_some_and(|edge| {
                    pending
                        .from
                        .checked_add(self.max_frame)
                        .is_some_and(|end| end <= edge)
                });
                if !fits {
                    target.counters.window_waits = target.counters.window_waits.saturating_add(1);
                    waiting = true;
                    continue;
                }
                let room = target
                    .sender
                    .pending(lane)
                    .is_some_and(|count| count < usize::from(STAGED_PER_LANE));
                let Some(queue) = target.queues.get(lane).copied().filter(|_| room) else {
                    target.counters.fanout_waits = target.counters.fanout_waits.saturating_add(1);
                    waiting = true;
                    continue;
                };
                let Ok(mut frame) = tx.claim_tx(queue, self.mtu) else {
                    waiting = true;
                    continue;
                };
                let (Some(out), Some(bytes)) = (
                    frame.bytes_mut().get_mut(..pending.len),
                    fanout
                        .scratch
                        .get(lane)
                        .and_then(|scratch| scratch.get(..pending.len)),
                ) else {
                    waiting = true;
                    continue;
                };
                out.copy_from_slice(bytes);
                let token = SenderToken::new(self.next_token);
                self.next_token = self.next_token.checked_add(1).ok_or(overflow.clone())?;
                let Ok(ticket) = frame.commit(Commit {
                    len: pending.len,
                    token,
                    options: TxOptions::none(),
                }) else {
                    self.counters.bump(|c| &mut c.queue_failures, 1);
                    waiting = true;
                    continue;
                };
                let charge = u32::try_from(pending.len)
                    .ok()
                    .and_then(|len| align_frame(len).ok())
                    .map(u64::from);
                let (Some(charge), Ok(len16)) = (charge, u16::try_from(pending.len)) else {
                    waiting = true;
                    continue;
                };
                if target
                    .sender
                    .staged(
                        lane,
                        Staged {
                            ticket,
                            charge,
                            len: len16,
                        },
                    )
                    .is_err()
                {
                    self.counters.bump(|c| &mut c.staged_refused, 1);
                    waiting = true;
                    continue;
                }
                if let Some(track) = target.lanes.get_mut(lane) {
                    track.staged.push_back((ticket, pending.next));
                }
                target.counters.staged = target.counters.staged.saturating_add(1);
                if let Some(flag) = fanout
                    .staged_for
                    .get_mut(lane)
                    .and_then(|flags| flags.get_mut(at))
                {
                    *flag = true;
                }
                staged = staged.checked_add(1).ok_or(overflow.clone())?;
            }
            if waiting {
                return Ok(staged);
            }
            // Every live target has it: the next one can be read.
            if let Some(slot) = fanout.pending.get_mut(lane) {
                *slot = None;
            }
        }
    }

    /// The idle heartbeats of a multi-destination publication: each live
    /// target's lane idle for `interval` sends one at the lane's next
    /// position, on that target's queue.
    pub(super) fn serve_fanout_heartbeats<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        now: u64,
        interval: u64,
    ) -> Option<u32> {
        if self.removing() {
            return Some(0);
        }
        let mut sent = 0u32;
        let count = self
            .fanout
            .as_deref()
            .map_or(0, |fanout| fanout.targets.len());
        for at in 0..count {
            for lane in 0..self.readers.len() {
                let Some(fanout) = self.fanout.as_deref_mut() else {
                    return Some(sent);
                };
                let idle_lane = fanout.idle(lane);
                let Some(target) = fanout.targets.get_mut(at) else {
                    continue;
                };
                let Some(since) = target.idle_since.get_mut(lane) else {
                    continue;
                };
                if !idle_lane || !target.live {
                    *since = Some(now);
                    continue;
                }
                let since_at = *since.get_or_insert(now);
                if now.checked_sub(since_at).is_none_or(|idle| idle < interval) {
                    continue;
                }
                let Some(queue) = target.queues.get(lane).copied() else {
                    continue;
                };
                let Some(position) = self.readers.get(lane).map(|reader| reader.position()) else {
                    continue;
                };
                if self.write_heartbeat_on(tx, queue, lane, position, false) {
                    if let Some(slot) = self
                        .fanout
                        .as_deref_mut()
                        .and_then(|fanout| fanout.targets.get_mut(at))
                        .and_then(|target| target.idle_since.get_mut(lane))
                    {
                        *slot = Some(now);
                    }
                    sent = sent.checked_add(1)?;
                }
            }
        }
        Some(sent)
    }

    /// The EOS frames of a removing multi-destination publication: a lane
    /// drained on every target sends its EOS to each.
    pub(crate) fn serve_fanout_removal<O: SocketOps>(
        &mut self,
        mut tx: Option<&mut SocketsTx<O>>,
        now: u64,
    ) -> RemovalStep {
        self.serve_removal_with(
            now,
            |outbound, lane| {
                let seal = outbound.readers.get(lane)?.seal_position()?;
                let fanout = outbound.fanout.as_deref()?;
                let sent = fanout.sent(lane)?;
                (fanout.idle(lane)
                    && sent >= seal
                    && outbound.readers.get(lane)?.position() >= seal)
                    .then_some(seal)
            },
            |outbound, lane, seal| {
                let Some(tx) = tx.as_deref_mut() else {
                    return EosSent::NotSent;
                };
                let count = outbound
                    .fanout
                    .as_deref()
                    .map_or(0, |fanout| fanout.targets.len());
                let mut any = false;
                for at in 0..count {
                    let queue = outbound
                        .fanout
                        .as_deref()
                        .and_then(|fanout| fanout.targets.get(at))
                        .and_then(|target| target.queues.get(lane).copied());
                    if let Some(queue) = queue {
                        any |= outbound.write_heartbeat_on(tx, queue, lane, seal, true);
                    }
                }
                if any {
                    EosSent::Submitted
                } else {
                    EosSent::NotSent
                }
            },
        )
    }
}
