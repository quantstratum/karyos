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
//! takes it. An optional target is removed at the first datagram its full
//! queue cannot take while the others take it (MD-7, decided: the
//! alternative, with no grace), counted in `removed_slow` and reported with
//! its reason; never while the publisher is held by a required loss, while
//! the shared socket pushes back (design 6.5), or while it bounds the
//! others under `min` or inside a `tagged` group (design 4.5). A required
//! one bounds the publisher, as it must. A send fault stays with its
//! target (MD-12): its queue is retried, and after
//! [`DESTINATION_FAULT_LIMIT`] consecutive faults an optional target is
//! removed and a required one held; a queue that refuses its retry goes to
//! the control path, which for a required target resets the endpoint.
//!
//! A reliable publication repairs per target (MD-8): each target has its
//! own repair path and repair queue on its route, with a share of the job
//! table, so a retransmission goes only to the destination that asked.
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
use karyos_protocol::lanes::drr::{Budget, DrrConfig, Stop};
use karyos_sys::log_buffer::{ReadError, ReadOrigin, ReadOutcome};

use super::removal::{EosSent, RemovalStep};
use super::{Limit, OPENED_QUEUES, Opened, Outbound, STAGED_PER_LANE, align_frame};
use crate::agents::{AgentError, AgentKind, EndpointId};
use crate::embedded::StreamTerms;

/// Consecutive send faults after which an optional destination is removed
/// and a required one held (MD-12).
pub const DESTINATION_FAULT_LIMIT: u8 = 3;

/// Why a destination was removed (design 4.5, 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RemovalReason {
    /// Its queue was full when a datagram had to be staged while the others
    /// took it (MD-7).
    Slow,
    /// Its sends faulted [`DESTINATION_FAULT_LIMIT`] times in a row (MD-12).
    Fault,
    /// Removed by `RemoveDestination` (MD-3).
    Command,
}

/// The outcome of a run-time destination change (MD-3, MD-14; ADR-0082).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DestinationChange {
    /// The destination was added: it is announced to and joins as an
    /// optional destination.
    Added,
    /// The destination was removed.
    Removed,
    /// Refused: the required destinations are fixed at creation (ADR-0082,
    /// M4); a required one is never removed or added.
    Required,
    /// Refused: it is already a destination.
    Present,
    /// Refused: it is not a destination.
    Absent,
    /// Refused: it was removed less than its quarantine ago (MD-14).
    Quarantined,
    /// Refused: the publication has [`MAX_DESTINATIONS`] destinations,
    /// counting those removed whose removal is not reported yet: a removal
    /// is reported at once, retired at its report, and its route and queues
    /// go to the close list then.
    Full,
    /// Refused: the publication is being removed.
    Removing,
    /// Refused: no multi-destination publication by that name, or an
    /// address of another family.
    Unknown,
}

/// The most destinations of one publication (MD-6: `max_destinations`
/// defaults to 16, configurable up to 64; this step fixes it at 16).
pub const MAX_DESTINATIONS: usize = 16;

/// The repair configuration of one destination of a multi-destination
/// publication: its share, for [`MAX_DESTINATIONS`], of each table sized
/// per publication, whatever the current count, so that adding a
/// destination at run time never overcommits a table and the paths of
/// every destination together stay within the configured tables (MD-8;
/// karyos#802). The job table (MD-8), the ERR linger entries, the job
/// linger entries and the step 8 replies are shared; requesters are per
/// job and stay as configured. A table below one entry per destination
/// is refused.
///
/// # Errors
///
/// [`RepairConfigError::DestinationShare`] for the job table, and
/// [`RepairConfigError::TableShare`] for another.
///
/// [`RepairConfigError::DestinationShare`]: crate::agents::repair::RepairConfigError::DestinationShare
/// [`RepairConfigError::TableShare`]: crate::agents::repair::RepairConfigError::TableShare
pub(crate) fn destination_share(
    config: &crate::agents::repair::RepairConfig,
) -> Result<crate::agents::repair::RepairConfig, crate::agents::repair::RepairConfigError> {
    use crate::agents::repair::RepairConfigError;
    let share = |value: usize| value / MAX_DESTINATIONS;
    let mut shared = *config;
    shared.jobs.repair_jobs = share(config.jobs.repair_jobs);
    if shared.jobs.repair_jobs == 0 {
        return Err(RepairConfigError::DestinationShare {
            repair_jobs: config.jobs.repair_jobs,
            destinations: MAX_DESTINATIONS,
        });
    }
    for (table, value, slot) in [
        (
            "err_linger_entries",
            config.err_linger_entries,
            &mut shared.err_linger_entries,
        ),
        (
            "repair_linger_entries",
            config.jobs.repair_linger_entries,
            &mut shared.jobs.repair_linger_entries,
        ),
        ("replies", config.replies, &mut shared.replies),
    ] {
        *slot = share(value);
        if *slot == 0 {
            return Err(RepairConfigError::TableShare {
                table,
                value,
                destinations: MAX_DESTINATIONS,
            });
        }
    }
    Ok(shared)
}

/// A destination's address, lane 0 catch-up, `high` and repair counts
/// (tests of MD-20).
#[cfg(test)]
pub(crate) type CatchUpView = (
    SocketAddr,
    Option<(u64, u64)>,
    u64,
    Option<crate::agents::repair::RepairCounts>,
);

/// One target's lane: its staged heads, in order, and what left.
#[derive(Debug)]
struct TargetLane {
    /// Ticket and the stream position after it, per staged datagram.
    staged: VecDeque<(TxTicket, u64)>,
    /// The highest position a submitted head reached.
    high: u64,
    /// A head was returned unsent or of unknown exposure.
    unsent: bool,
    /// Where the first head returned unsent in this epoch began (its
    /// `high` then): a later submitted head raises `high` past it, so a
    /// catch-up after a reset starts here, not at `high` (MD-20,
    /// karyos#802). A head of an earlier epoch reported after the reopen
    /// matches no staged ticket, as the reopen cleared them, so it never
    /// records one.
    hole: Option<u64>,
    /// A catch-up range waiting for a job in the destination's share.
    catch_up: Option<(u64, u64)>,
    /// The catch-up job now serving part of that range, if any.
    catch_up_job: Option<crate::repair::jobs::JobRef>,
    /// The end of the last catch-up queued: its jobs read up to it, above
    /// `high`, which only submitted heads raise.
    catch_up_to: u64,
    /// A head left out of staging order.
    mismatched: bool,
    /// A head was submitted this cycle.
    submitted: bool,
}

impl TargetLane {
    /// A staged head ending at `next` left `how`: a submitted one raises
    /// `high`; the first one returned unsent in the epoch records where it
    /// began, `high` then, as the lane's `hole` (MD-20, karyos#802).
    fn left(&mut self, next: u64, how: Left) {
        match how {
            Left::Submitted => {
                self.high = self.high.max(next);
                self.submitted = true;
            }
            Left::Returned | Left::Unknown => {
                self.unsent = true;
                let high = self.high;
                self.hole.get_or_insert(high);
            }
        }
    }

    /// After an endpoint reset with the readers at `position`: what this
    /// destination lacks of the lane, from where its own submissions stop
    /// (its `hole`, else `high`) to `position`, joins any catch-up still
    /// waiting (MD-20, karyos#802). Nothing when it has it all.
    fn catch_up_after_reset(&mut self, position: u64) {
        let start = self.hole.take().unwrap_or(self.high);
        let from = self
            .catch_up
            .map_or(start, |(pending, _)| pending.min(start));
        if from < position {
            self.catch_up = Some((from, position));
            self.catch_up_to = self.catch_up_to.max(position);
        }
    }
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
    /// Per lane, its member's edge this cycle (MD-1): a staged head is
    /// submitted only once it ends at or below it.
    edges: [u64; 4],
    /// Its member bounds the strategy edge (`min`, or inside the `tagged`
    /// group): it is never removed as slow (design 4.5).
    bounds: bool,
    /// Its last serve found nothing it could send while it had staged
    /// heads: it waits at its own edge, not on the socket or the budget.
    stalled: bool,
    /// Per lane, since when it submitted nothing: its idle heartbeat is
    /// due `sender_heartbeat_interval` later.
    idle_since: [Option<u64>; 4],
    /// When it last submitted DATA or a PATH_HB: its PATH_HB is due
    /// `path_heartbeat_interval` later (RP-3, karyos#859).
    path_sent: Option<u64>,
    counters: TargetCounters,
    /// Removed, why and when: it gets nothing more, and its SMs and NAKs
    /// are ignored.
    removed: Option<(RemovalReason, u64)>,
    /// Its removal was reported to the conductor.
    reported: bool,
    /// Consecutive send faults (MD-12), failed opens of its own included.
    faults: u8,
    /// When its last failed open counted as a fault: at most once per
    /// `setup_interval`.
    open_fault_at: Option<u64>,
    /// The epoch and time of its last failed open: it is retried once per
    /// `setup_interval` in that epoch, and at once in a new one.
    open_tried: Option<(BackendEpoch, u64)>,
    /// It was live once: it joined (MD-15).
    joined: bool,
    /// A reliable publication's repair path toward it (MD-8).
    repair: Option<Box<crate::agents::repair::RepairPath>>,
}

impl Target {
    /// A destination toward `address`, required or not, with `lanes.len()`
    /// lanes served under `drr`, each joining at its position in `joins`,
    /// and its repair path if the publication repairs.
    fn new(
        address: SocketAddr,
        required: bool,
        drr: DrrConfig,
        joins: &[u64],
        repair: Option<Box<crate::agents::repair::RepairPath>>,
    ) -> Option<Self> {
        let placeholder = TxQueueId::new(BackendEpoch::FIRST, u16::MAX, NonZeroU32::MAX);
        let bound = usize::from(STAGED_PER_LANE);
        let queues = vec![placeholder; joins.len()];
        let sender = LaneSender::new(drr, &queues, bound).ok()?;
        Some(Self {
            address,
            required,
            sender,
            queues,
            lanes: joins
                .iter()
                .map(|join| TargetLane {
                    staged: VecDeque::with_capacity(bound),
                    high: *join,
                    unsent: false,
                    hole: None,
                    catch_up: None,
                    catch_up_job: None,
                    catch_up_to: 0,
                    mismatched: false,
                    submitted: false,
                })
                .collect(),
            route: None,
            opened: None,
            live: false,
            edges: [0; 4],
            bounds: false,
            stalled: false,
            idle_since: [None; 4],
            path_sent: None,
            counters: TargetCounters::default(),
            removed: None,
            reported: false,
            faults: 0,
            open_fault_at: None,
            open_tried: None,
            joined: false,
            repair,
        })
    }
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
    /// Times its full queue held the shared cursor (a required one).
    pub fanout_waits: u64,
    /// Repair datagrams submitted to it.
    pub repairs: u64,
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
    /// The lanes' cursors for an addition, one per lane, reused by every
    /// command so none allocates for them.
    joins: Vec<u64>,
    /// Per lane and target, whether the pending datagram is staged there.
    staged_for: Vec<Vec<bool>>,
    /// Per lane, one datagram of scratch (MD-2).
    scratch: Vec<Vec<u8>>,
    /// The rotating start of each cycle's target visits (MD-9).
    rotation: usize,
    /// The last serve met backpressure on the shared socket, or an
    /// inactive endpoint: no target is slow then (design 6.5).
    backpressure: bool,
    /// How each target's repair path is built, once the publication repairs
    /// (MD-8): a destination added later gets its own.
    repair: Option<(
        crate::agents::repair::RepairConfig,
        u32,
        karyos_protocol::network::Alias,
        karyos_protocol::network::Identity,
    )>,
    /// What a target's lane sender is built with.
    drr: DrrConfig,
    mtu: usize,
    /// Retired destinations and when they were removed, kept for their
    /// quarantine (MD-14), at most [`MAX_DESTINATIONS`], oldest first.
    quarantined: VecDeque<(SocketAddr, u64)>,
    /// The quarantine of a removed destination (MD-14) and the spacing of
    /// counted open failures (`setup_interval`), from the sender's settings.
    quarantine: u64,
    open_spacing: u64,
    /// Whether its destinations are IPv4: every one shares the endpoint's
    /// family, fixed at creation.
    ipv4: bool,
    /// Retired targets' routes and queues, for the sender to close.
    retired: Vec<Opened>,
}

/// The gate of one target's first sends: every candidate is permitted,
/// unless a required loss holds them; it records what left.
struct TargetGate<'a> {
    lanes: &'a mut [TargetLane],
    held: bool,
    /// Per lane, the target's own edge (MD-1).
    edges: [u64; 4],
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
    fn admits(&mut self, lane: usize) -> bool {
        // The lane's next head waits until it fits the target's window:
        // past its edge it stays queued (design 4.2).
        let fits = self
            .lanes
            .get(lane)
            .and_then(|track| track.staged.front())
            .is_none_or(|(_, next)| self.edges.get(lane).is_some_and(|edge| next <= edge));
        !self.held && fits
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
            Some((ticket, next)) if ticket == staged.ticket => track.left(next, how),
            _ => track.mismatched = true,
        }
    }
}

impl Fanout {
    /// Names through `post` each live destination due a PATH_HB: it
    /// submitted nothing for `interval` ns at `now` (RP-3, karyos#859);
    /// its wait starts at the first look. `post` says whether it took it.
    pub(super) fn path_heartbeats(
        &mut self,
        endpoint: EndpointId,
        now: u64,
        interval: u64,
        mut post: impl FnMut(EndpointId, SocketAddr) -> bool,
    ) -> u32 {
        let mut posted = 0u32;
        for target in &mut self.targets {
            if !target.live || target.removed.is_some() {
                target.path_sent = Some(now);
                continue;
            }
            let since = *target.path_sent.get_or_insert(now);
            if now.checked_sub(since).is_none_or(|quiet| quiet < interval) {
                continue;
            }
            if post(endpoint, target.address) {
                // At most `MAX_DESTINATIONS`: no overflow.
                posted = posted.saturating_add(1);
            }
        }
        posted
    }

    /// Records a PATH_HB submitted to `destination` at `now`.
    pub(super) fn path_heartbeat_sent(&mut self, destination: SocketAddr, now: u64) {
        if let Some(target) = self
            .targets
            .iter_mut()
            .find(|target| target.address == destination)
        {
            target.path_sent = Some(now);
        }
    }

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
        ipv4: bool,
    ) -> Option<Self> {
        let joins: Vec<u64> = (0..lanes)
            .map(|lane| joins.get(lane).copied().unwrap_or(0))
            .collect();
        let mut targets = Vec::with_capacity(MAX_DESTINATIONS);
        for address in destinations {
            targets.push(Target::new(
                *address,
                required.contains(address),
                drr,
                &joins,
                None,
            )?);
        }
        Some(Self {
            staged_for: (0..lanes)
                .map(|_| {
                    let mut flags = Vec::with_capacity(MAX_DESTINATIONS);
                    flags.resize(targets.len(), false);
                    flags
                })
                .collect(),
            quarantined: VecDeque::with_capacity(MAX_DESTINATIONS),
            quarantine: 0,
            open_spacing: 0,
            ipv4,
            retired: Vec::with_capacity(MAX_DESTINATIONS),
            targets,
            pending: vec![None; lanes],
            joins: vec![0; lanes],
            scratch: (0..lanes).map(|_| vec![0; mtu]).collect(),
            rotation: 0,
            backpressure: false,
            repair: None,
            drr,
            mtu,
        })
    }

    /// The destinations, in configuration order.
    pub(super) fn addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.targets.iter().map(|target| target.address)
    }

    /// The retransmission window its destinations' repair paths keep (all
    /// alike), if they repair.
    fn retransmit_window(&self) -> Option<u32> {
        self.targets
            .iter()
            .find_map(|target| target.repair.as_deref())
            .map(crate::agents::repair::RepairPath::retransmit_window)
    }

    /// Whether a destination has a repair path.
    fn repairs(&self) -> bool {
        self.targets.iter().any(|target| target.repair.is_some())
    }

    /// Whether `address` is one of its destinations, not removed.
    pub(super) fn has(&self, address: SocketAddr) -> bool {
        self.targets
            .iter()
            .any(|target| target.address == address && target.removed.is_none())
    }

    fn target_at(&mut self, address: SocketAddr) -> Option<&mut Target> {
        self.targets
            .iter_mut()
            .find(|target| target.address == address && target.removed.is_none())
    }

    /// The required destinations.
    pub(super) fn required(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.targets
            .iter()
            .filter(|target| target.required)
            .map(|target| target.address)
    }

    /// Whether every destination not removed is live.
    pub(super) fn all_live(&self) -> bool {
        self.targets
            .iter()
            .all(|target| target.live || target.removed.is_some())
    }

    /// Retires the removed targets reported (design 3.7), as a removed
    /// publication's are: their route and queues, opened in `epoch` (the
    /// publication's open epoch; an older epoch's died with it and are
    /// dropped), go to `retired`, for the sender's close list, which
    /// returns their pending items as `QueueClosed` (counted in
    /// `removed_returned`) and closes the queues and the route. They leave
    /// `targets`, and their address is kept for its quarantine (MD-14),
    /// counted from its removal; `now` expires the records past theirs.
    /// Returns the targets retired and the quarantine records forgotten to
    /// make room.
    fn retire(
        &mut self,
        endpoint: crate::agents::EndpointId,
        epoch: Option<BackendEpoch>,
        now: u64,
    ) -> (u64, u64) {
        let mut retired = 0u64;
        let mut forgotten = 0u64;
        let fanout = self;
        let mut at = fanout.targets.len();
        while let Some(index) = at.checked_sub(1) {
            at = index;
            let room = fanout.retired.len() < fanout.retired.capacity();
            let Some(target) = fanout.targets.get_mut(index) else {
                continue;
            };
            if !(target.removed.is_some() && target.reported) {
                continue;
            }
            // Its route and queues, if opened in the publication's open
            // epoch: an older epoch's handles died with that epoch (the
            // reset dropped them), so they take no place in the lists.
            let held = target
                .opened
                .zip(target.route)
                .filter(|(opened, _)| Some(*opened) == epoch);
            // A slot is held until its route and queues leave `retired`
            // (`change_destination` counts both), so there is always room.
            debug_assert!(
                room || held.is_none(),
                "the retired list has a place per slot"
            );
            let target = fanout.targets.remove(index);
            for flags in &mut fanout.staged_for {
                if index < flags.len() {
                    let _ = flags.remove(index);
                }
            }
            // Its route and queues go to the sender's closing list, which
            // closes them whole (`close_removed`).
            if let Some((opened, route)) = held {
                let mut queues = [None; OPENED_QUEUES];
                for (slot, queue) in queues.iter_mut().zip(&target.queues) {
                    *slot = Some(*queue);
                }
                if let Some(slot) = queues.last_mut() {
                    *slot = target
                        .repair
                        .as_deref()
                        .and_then(|repair| repair.queue_on(0));
                }
                // A place per slot: never a reallocation.
                fanout.retired.push(Opened {
                    endpoint,
                    epoch: opened,
                    route,
                    queues,
                });
            }
            // Expired records go first; only one still in its quarantine
            // is counted when it must make room.
            let quarantine = fanout.quarantine;
            fanout.quarantined.retain(|(_, removed_at)| {
                now.checked_sub(*removed_at)
                    .is_none_or(|age| age < quarantine)
            });
            // The record removed earliest goes first, the incoming one
            // included: retirement order may differ from removal order.
            let removed_at = target.removed.map_or(now, |(_, time)| time);
            // A record already past its quarantine is not kept.
            let mut keep = now
                .checked_sub(removed_at)
                .is_none_or(|age| age < quarantine);
            if keep && fanout.quarantined.len() >= MAX_DESTINATIONS {
                let earliest = fanout
                    .quarantined
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(at, (_, removed))| (at, *removed));
                match earliest {
                    Some((at, earliest)) if earliest <= removed_at => {
                        let _ = fanout.quarantined.remove(at);
                    }
                    _ => keep = false,
                }
                forgotten = forgotten.saturating_add(1);
            }
            if keep {
                fanout.quarantined.push_back((target.address, removed_at));
            }
            retired = retired.saturating_add(1);
        }
        (retired, forgotten)
    }

    /// The destinations not live and not removed, which announce again.
    pub(super) fn not_live(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.targets
            .iter()
            .filter(|target| !target.live && target.removed.is_none())
            .map(|target| target.address)
    }

    /// The route and queues of the targets retired since the sender's last
    /// drain, which a publication removed before that drain closes too,
    /// then each target's in its epoch.
    pub(super) fn opened_resources(
        &self,
        endpoint: crate::agents::EndpointId,
        held: &mut impl FnMut(Opened),
    ) {
        for opened in &self.retired {
            held(*opened);
        }
        for target in &self.targets {
            let (Some(epoch), Some(route)) = (target.opened, target.route) else {
                continue;
            };
            let mut queues = [None; OPENED_QUEUES];
            for (slot, queue) in queues.iter_mut().zip(&target.queues) {
                *slot = Some(*queue);
            }
            if let Some(slot) = queues.last_mut() {
                *slot = target
                    .repair
                    .as_deref()
                    .and_then(|repair| repair.queue_on(0));
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
    /// target not removed.
    fn idle(&self, lane: usize) -> bool {
        self.pending.get(lane).is_none_or(Option::is_none)
            && self.targets.iter().all(|target| {
                target.removed.is_some()
                    || target
                        .lanes
                        .get(lane)
                        .is_none_or(|track| track.staged.is_empty())
                        && target.sender.pending(lane).unwrap_or(0) == 0
            })
    }

    /// `lane`'s sent frontier: the least position its live targets
    /// submitted (`sent_low`, design 4.3), or the most any target not
    /// removed did when none is live.
    fn sent(&self, lane: usize) -> Option<u64> {
        let high = |target: &Target| target.lanes.get(lane).map(|track| track.high);
        self.targets
            .iter()
            .filter(|target| target.live && target.removed.is_none())
            .filter_map(high)
            .min()
            .or_else(|| {
                self.targets
                    .iter()
                    .filter(|target| target.removed.is_none())
                    .filter_map(high)
                    .max()
            })
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
    /// a required one that is not a destination, an endpoint of unknown
    /// family (`ipv4` is `None`), or a destination of another family than
    /// the endpoint's: it could never open.
    pub(crate) fn set_destinations(
        &mut self,
        destinations: &[SocketAddr],
        required: &[SocketAddr],
        ipv4: Option<bool>,
    ) -> Result<(), super::OutboundError> {
        let Some(ipv4) = ipv4 else {
            return Err(super::OutboundError::Routes);
        };
        let distinct = destinations.iter().enumerate().all(|(at, address)| {
            !destinations
                .iter()
                .skip(at + 1)
                .any(|other| other == address)
        });
        if destinations.is_empty()
            || !distinct
            || destinations.iter().any(|address| address.is_ipv4() != ipv4)
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
            // Every destination shares the endpoint's address family, fixed
            // here: an addition of another family is `Unknown`, whatever is
            // left of the others.
            ipv4,
        )
        .ok_or(super::OutboundError::Lanes)?;
        self.fanout = Some(Box::new(fanout));
        Ok(())
    }

    /// The retransmission window of a reliable multi-destination
    /// publication's repair paths.
    pub(super) fn fanout_retransmit_window(&self) -> Option<u32> {
        self.fanout.as_deref().and_then(Fanout::retransmit_window)
    }

    /// Whether its destinations repair (a reliable multi-destination
    /// publication).
    pub(super) fn fanout_repairs(&self) -> bool {
        self.fanout.as_deref().is_some_and(Fanout::repairs)
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
    /// once per epoch; a new epoch drops what the old one staged. A removed
    /// target is never opened again, and one that fails to open is retried
    /// at the next call without holding the others (it gets nothing until
    /// it opens; a required one bounds the publisher meanwhile).
    /// [`Outbound::open_targets`], for tests outside this module.
    #[cfg(test)]
    pub(crate) fn open_destinations<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, now: u64) {
        let _ = self.open_targets(tx, now);
    }

    fn open_targets<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, now: u64) -> bool {
        let epoch = tx.capabilities().epoch;
        let Some(fanout) = self.fanout.as_deref_mut() else {
            return false;
        };
        // Once per epoch change, even when a target opens only later.
        let reopened = self.opened.is_some_and(|opened| opened != epoch);
        let spacing = fanout.open_spacing;
        let (mut route_failures, mut queue_failures, mut removed) = (0u64, 0u64, 0u64);
        let mut limits = 0u64;
        let mut limited = false;
        let endpoint = self.endpoint;
        for target in &mut fanout.targets {
            if target.opened == Some(epoch) || target.removed.is_some() {
                continue;
            }
            // A failed open waits `setup_interval` before its retry, which
            // costs system calls (`route_mtu`) and counts again.
            if target.open_tried.is_some_and(|(tried, at)| {
                tried == epoch && now.checked_sub(at).is_none_or(|age| age < spacing)
            }) {
                continue;
            }
            let route = match tx.add_route(target.address) {
                Ok(route) => route,
                Err(error) => {
                    target.open_tried = Some((epoch, now));
                    route_failures = route_failures.saturating_add(1);
                    if error == karyos_io::backend::RouteError::RouteLimit {
                        limits = limits.saturating_add(1);
                        limited = true;
                    }
                    if open_failed(target, route_own(error), (now, spacing)) {
                        removed = removed.saturating_add(1);
                    }
                    continue;
                }
            };
            // Its lane queues, then its repair queue on the same route
            // (MD-8): all open, or none and the route goes again.
            let repair = usize::from(target.repair.is_some());
            let mut failure = None;
            let mut repair_queue = None;
            for at in 0..target.queues.len().saturating_add(repair) {
                let lane = at < target.queues.len();
                let max_pending = if lane {
                    NonZeroU16::new(STAGED_PER_LANE).unwrap_or(NonZeroU16::MIN)
                } else {
                    NonZeroU16::MIN
                };
                match tx.open_queue(TxQueueConfig {
                    authority: Authority::FIRST,
                    route,
                    max_pending,
                }) {
                    Ok(opened) if lane => {
                        if let Some(queue) = target.queues.get_mut(at) {
                            *queue = opened;
                        }
                    }
                    Ok(opened) => repair_queue = Some(opened),
                    Err(error) => {
                        for queue in target.queues.iter().take(at) {
                            let _ = tx.close_queue(*queue, &mut self.report);
                            while self.report.pop_front().is_some() {}
                        }
                        let _ = tx.remove_route(route);
                        failure = Some(error);
                        break;
                    }
                }
            }
            if let Some(error) = failure {
                target.open_tried = Some((epoch, now));
                // No queue failure is the destination's own: the limits
                // are counted, the rest is a reset or a stale handle.
                queue_failures = queue_failures.saturating_add(1);
                if queue_limit(error) {
                    limits = limits.saturating_add(1);
                    limited = true;
                }
                continue;
            }
            for (lane, queue) in target.queues.iter().enumerate() {
                target.sender.reopen(lane, *queue);
            }
            if let Some(repair) = target.repair.as_deref_mut() {
                repair.reopened(repair_queue);
            }
            for track in &mut target.lanes {
                track.staged.clear();
            }
            // Opened: failed opens no longer count against it.
            target.open_tried = None;
            if target.open_fault_at.take().is_some() {
                target.faults = 0;
            }
            target.opened = Some(epoch);
            target.route = Some(route);
        }
        self.counters
            .bump(|c| &mut c.route_failures, route_failures);
        self.counters
            .bump(|c| &mut c.queue_failures, queue_failures);
        self.counters.bump(|c| &mut c.removed_fault, removed);
        self.counters.bump(|c| &mut c.endpoint_limits, limits);
        if limited {
            super::note_limited(&mut self.limited, endpoint, epoch);
        }
        let Some(fanout) = self.fanout.as_deref_mut() else {
            return false;
        };
        if reopened {
            // What the old epoch read but had not staged everywhere is
            // dropped. On a reliable publication with repair paths each
            // destination catches up alone (MD-20, karyos#802): one job per
            // lane over what it lacks, from where its own submissions stop
            // (`hole`, else `high`) to the readers' position, and nothing to
            // a destination that has it. Without repair paths a reliable
            // lane reads again from its restart position, so every target
            // gets it again (receivers drop copies). An unreliable one
            // leaves the gap to the receivers' gap policy.
            fanout.pending.fill(None);
            if self.reliable && fanout.repair.is_some() {
                for target in fanout.targets.iter_mut().filter(|t| t.removed.is_none()) {
                    for (track, reader) in target.lanes.iter_mut().zip(&self.readers) {
                        track.catch_up_after_reset(reader.position());
                    }
                }
            } else if self.reliable {
                for reader in &mut self.readers {
                    let _ = reader.rewind();
                }
            }
        }
        // A reset asked for is done only once the endpoint is in a new
        // epoch: one asked in this epoch stays for the sender to act on.
        if self.opened != Some(epoch) {
            self.needs_reset = false;
            self.reset_requested = None;
        }
        self.opened = Some(epoch);
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
            let was_live = target.live;
            target.live = target.removed.is_none()
                && membership.is_some_and(|membership| membership.live_at(target.address, now));
            if target.live && !was_live {
                join_at(target, self.readers.iter().map(|reader| reader.position()));
            }
            target.bounds =
                membership.is_some_and(|membership| membership.bounds_at(target.address, now));
            for (lane, edge) in target.edges.iter_mut().enumerate() {
                *edge = u8::try_from(lane)
                    .ok()
                    .and_then(|lane| Lane::try_new(lane).ok())
                    .and_then(|lane| {
                        membership
                            .and_then(|membership| membership.edge_at(target.address, lane, now))
                    })
                    .unwrap_or(0);
            }
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
        if !self.open_targets(tx, now) {
            return Ok(0);
        }
        self.refresh_targets(now);
        let (limits, held) = self.limits(now);
        let mut work = 0u32;
        for lane in 0..self.readers.len() {
            let limit = limits.get(lane).copied().unwrap_or(Limit::Held);
            work = work
                .checked_add(self.stage_fanout(tx, lane, (limit, held), now)?)
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
        let epoch = tx.capabilities().epoch;
        let mut failure = None;
        let mut backpressure = false;
        for visit in 0..count {
            let at = (fanout.rotation + visit) % count;
            let Some(target) = fanout.targets.get_mut(at) else {
                continue;
            };
            // A removed target is never served again: it waits for its
            // report, which retires it (design 3.7). One not open yet waits
            // for its open.
            if target.removed.is_some() {
                continue;
            }
            if target.opened != Some(epoch) {
                continue;
            }
            let mut gate = TargetGate {
                lanes: &mut target.lanes,
                held,
                edges: target.edges,
            };
            let report = target.sender.serve(tx, &mut gate, budget);
            if report.failure.is_some() {
                failure = report.failure;
            }
            backpressure |= report.inactive || matches!(report.drr.stop, Stop::Backpressure { .. });
            target.stalled = report.drr.stop == Stop::Idle
                && (0..target.queues.len())
                    .any(|lane| target.sender.pending(lane).unwrap_or(0) > 0);
            for track in &mut target.lanes {
                if std::mem::take(&mut track.unsent) {
                    self.counters.bump(|c| &mut c.unsent, 1);
                }
                if std::mem::take(&mut track.mismatched) {
                    self.counters.bump(|c| &mut c.mismatched, 1);
                }
            }
            // A faulted queue is retried and the fault stays with the
            // target (MD-12): after the limit an optional target is
            // removed and a required one held. Only an item of unknown
            // exposure needs a reset of the shared endpoint.
            let mut faulted = false;
            for lane in 0..target.queues.len() {
                if target.sender.suspended(lane) == Some(true) {
                    self.needs_reset = true;
                } else if target.sender.needs_control(lane) == Some(true) {
                    faulted = true;
                    self.counters.bump(|c| &mut c.send_faults, 1);
                    let retried = target
                        .queues
                        .get(lane)
                        .is_some_and(|queue| tx.retry_queue(*queue).is_ok());
                    if retried {
                        target.sender.retry(lane);
                    } else {
                        // A queue that refuses its retry (closed, unrouted)
                        // needs the control path: a required target would
                        // otherwise hold the publisher for good.
                        self.counters.bump(|c| &mut c.retries_refused, 1);
                        if target.required {
                            self.needs_reset = true;
                        }
                    }
                }
            }
            if faulted {
                target.faults = target.faults.saturating_add(1);
                if target.faults >= DESTINATION_FAULT_LIMIT && !target.required {
                    remove_target(target, RemovalReason::Fault, now);
                    self.counters.bump(|c| &mut c.removed_fault, 1);
                }
            } else if target.lanes.iter().any(|track| track.submitted) {
                target.faults = 0;
                // DATA left: its path's PATH_HB waits again.
                target.path_sent = Some(now);
            }
            for track in &mut target.lanes {
                track.submitted = false;
            }
        }
        fanout.backpressure = backpressure;
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
        (limit, held): (Limit, bool),
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        let epoch = tx.capabilities().epoch;
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
            let room = |target: &Target| {
                target
                    .sender
                    .pending(lane)
                    .is_some_and(|count| count < usize::from(STAGED_PER_LANE))
            };
            // Whether some live target takes datagrams: MD-7's "while the
            // others take it".
            let advancing = fanout
                .targets
                .iter()
                .filter(|target| target.live && target.opened == Some(epoch))
                .any(room);
            let backpressure = fanout.backpressure;
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
                if target.opened != Some(epoch) {
                    // Not open in this epoch yet: a required one bounds the
                    // publisher; an optional one misses it.
                    waiting |= target.required;
                    continue;
                }
                // Past its own edge it is staged anyway and waits in its
                // queue (design 4.2, the gate); a full queue decides below.
                if pending
                    .from
                    .checked_add(self.max_frame)
                    .is_some_and(|end| end > target.edges.get(lane).copied().unwrap_or(0))
                {
                    target.counters.window_waits = target.counters.window_waits.saturating_add(1);
                }
                let has_room = room(target);
                let Some(queue) = target.queues.get(lane).copied().filter(|_| has_room) else {
                    if slow(target, held, backpressure, advancing) {
                        // MD-7: removed at once, so the others never wait
                        // for it.
                        remove_target(target, RemovalReason::Slow, now);
                        self.counters.bump(|c| &mut c.removed_slow, 1);
                    } else {
                        // A required or bounding destination holds the
                        // publisher, as does a held publisher or a socket
                        // that pushes back.
                        target.counters.fanout_waits =
                            target.counters.fanout_waits.saturating_add(1);
                        waiting = true;
                    }
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
                if !idle_lane || !target.live || target.removed.is_some() {
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
                    // A removed destination gets nothing more, its EOS
                    // included.
                    let queue = outbound
                        .fanout
                        .as_deref()
                        .and_then(|fanout| fanout.targets.get(at))
                        .filter(|target| target.removed.is_none())
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

/// Whether an optional `target` whose queue cannot take a datagram is slow
/// (MD-7): it waits at its own edge while some live target takes
/// datagrams, the publisher is not held by a required loss, the shared
/// socket did not push back, and it does not bound the strategy edge
/// (design 4.5, 6.5).
fn slow(target: &Target, held: bool, backpressure: bool, advancing: bool) -> bool {
    !target.required && !target.bounds && target.stalled && !held && !backpressure && advancing
}

/// Moves a target that goes live to `positions`, the lanes' cursors, when
/// it joins (MD-15): what came before is not its own, so its sent frontier
/// starts there and never holds the publication's below it. A target live
/// before is moved only when it holds nothing staged or pending: one back
/// from a brief lapse keeps its frontier while it submits what it staged.
/// It does not get what the publication sent while it was not live: after
/// its staged datagrams it goes on at the cursor, so its frontier passes
/// that range, and the receiver's gap policy handles the loss (repair on
/// a reliable lane, a local gap on an unreliable one).
fn join_at(target: &mut Target, positions: impl Iterator<Item = u64>) {
    let idle = (0..target.lanes.len()).all(|lane| {
        target
            .lanes
            .get(lane)
            .is_none_or(|track| track.staged.is_empty())
            && target.sender.pending(lane).unwrap_or(0) == 0
    });
    if !target.joined || idle {
        for (track, position) in target.lanes.iter_mut().zip(positions) {
            track.high = track.high.max(position);
        }
    }
    target.joined = true;
}

/// A failed open of `target`'s route or queues at `now` counts as a send
/// fault (MD-12): an optional destination that cannot open is removed after
/// [`DESTINATION_FAULT_LIMIT`] tries, rather than answering `Added` and
/// failing for good; a required one keeps trying and bounds the publisher.
/// Only the destination's own failures count, never the endpoint's (one
/// resetting or retired, identities exhausted, a report not empty, its
/// route table, queue entries or TX slots full), and at
/// most once per `spacing` (`setup_interval`), so an endpoint reset never
/// removes a destination. Returns whether it removed `target`.
fn open_failed(target: &mut Target, own: bool, (now, spacing): (u64, u64)) -> bool {
    if !own {
        return false;
    }
    let due = target
        .open_fault_at
        .is_none_or(|at| now.checked_sub(at).is_some_and(|age| age >= spacing));
    if !due {
        return false;
    }
    target.open_fault_at = Some(now);
    target.faults = target.faults.saturating_add(1);
    if target.faults >= DESTINATION_FAULT_LIMIT && !target.required {
        remove_target(target, RemovalReason::Fault, now);
        return true;
    }
    false
}

/// Whether a route that would not open is the destination's own failure:
/// its address cannot be routed. The endpoint's route table being full
/// (`RouteLimit`) is endpoint-wide, as are a reset and exhausted
/// identities: none of them is the destination's.
const fn route_own(error: karyos_io::backend::RouteError) -> bool {
    use karyos_io::backend::RouteError;
    !matches!(
        error,
        RouteError::NotActive
            | RouteError::IdentityExhausted
            | RouteError::Unknown
            | RouteError::RouteLimit
    )
}

/// Whether a queue that would not open hit an endpoint-wide limit: its
/// queue entries or TX slots, shared with its other publications. No queue
/// failure is the destination's own; the others are not limits either: a
/// reset (`NotActive`, `NeedsReset`), identities exhausted, a report not
/// empty, or a stale handle.
pub(super) const fn queue_limit(error: karyos_io::backend::QueueError) -> bool {
    use karyos_io::backend::QueueError;
    matches!(
        error,
        QueueError::QueueLimit | QueueError::OverCommitted { .. }
    )
}

/// Removes `target` for `reason` at `now`: it gets nothing more, its
/// removal is reported in that cycle, and it is retired at the report as a
/// removed publication is (design 3.7): its queues and route go to the
/// sender's close list then, which frees its slot, and the next duty
/// returns what they hold as `QueueClosed` and closes them. Its receiver closes the gap by its gap
/// policy, and its image expires.
fn remove_target(target: &mut Target, reason: RemovalReason, now: u64) {
    if target.removed.is_some() {
        return;
    }
    target.removed = Some((reason, now));
    target.live = false;
    target.reported = false;
}

/// A destination's removal, for the conductor (design 4.5; MD-7, MD-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationRemoval {
    /// The destination.
    pub destination: SocketAddr,
    /// Why.
    pub reason: RemovalReason,
}

impl<T: StreamTerms> Outbound<T> {
    /// The first removed destination not reported yet.
    pub(crate) fn removal_unreported(&self) -> Option<DestinationRemoval> {
        self.fanout.as_deref().and_then(|fanout| {
            fanout.targets.iter().find_map(|target| {
                // Reported at once, whatever the publication's or the
                // queues' state; its report retires it in the same cycle.
                let (reason, _) = target.removed.filter(|_| !target.reported)?;
                Some(DestinationRemoval {
                    destination: target.address,
                    reason,
                })
            })
        })
    }

    /// Records `destination`'s removal as reported at `now`, and retires
    /// it in the same cycle, so a move retried after the report finds its
    /// slot free.
    pub(crate) fn removal_reported(&mut self, destination: SocketAddr, now: u64) {
        let Some(fanout) = self.fanout.as_deref_mut() else {
            return;
        };
        if let Some(target) = fanout.targets.iter_mut().find(|t| t.address == destination) {
            target.reported = true;
        }
        self.retire_reported(now);
    }

    /// Retires what was reported, counting it.
    fn retire_reported(&mut self, now: u64) {
        let (endpoint, epoch) = (self.endpoint, self.opened);
        let Some(fanout) = self.fanout.as_deref_mut() else {
            return;
        };
        let (retired, forgotten) = fanout.retire(endpoint, epoch, now);
        self.counters.bump(|c| &mut c.destinations_retired, retired);
        self.counters
            .bump(|c| &mut c.quarantine_forgotten, forgotten);
    }

    /// Its destinations' quarantine (MD-14) and the spacing of counted
    /// open failures (`setup_interval`), from the sender's settings.
    pub(crate) fn set_destination_timing(&mut self, quarantine: u64, setup_interval: u64) {
        self.open_spacing = setup_interval;
        if let Some(fanout) = self.fanout.as_deref_mut() {
            fanout.quarantine = quarantine;
            fanout.open_spacing = setup_interval;
        }
    }

    /// Hands the routes and queues of retired destinations to `closing`,
    /// the sender's list of what removed publications left, which closes
    /// each whole (design 3.7). The list empties at every duty and has room
    /// for every publication's routes and destinations twice over, so
    /// everything fits. Returns what did not (never): it waits in the
    /// publication for a later duty, and the caller counts it.
    pub(crate) fn drain_retired(&mut self, closing: &mut Vec<Opened>) -> u64 {
        let Some(fanout) = self.fanout.as_deref_mut() else {
            return 0;
        };
        debug_assert!(
            closing.capacity().saturating_sub(closing.len()) >= fanout.retired.len(),
            "the close list has room for every retired destination"
        );
        let room = closing.capacity().saturating_sub(closing.len());
        let taken = room.min(fanout.retired.len());
        closing.extend(fanout.retired.drain(..taken));
        u64::try_from(fanout.retired.len()).unwrap_or(u64::MAX)
    }

    /// The repair jobs every destination's table holds, summed (tests).
    #[cfg(test)]
    pub(crate) fn fanout_job_capacity(&self) -> usize {
        self.fanout.as_deref().map_or(0, |fanout| {
            fanout
                .targets
                .iter()
                .filter_map(|target| target.repair.as_deref())
                .map(|repair| repair.parts().1.capacity())
                .sum()
        })
    }

    /// Each destination's lane 0 catch-up, `high` and repair counts
    /// (tests of MD-20).
    #[cfg(test)]
    pub(crate) fn destination_catch_ups(&self) -> Vec<CatchUpView> {
        self.fanout
            .as_deref()
            .map(|fanout| {
                fanout
                    .targets
                    .iter()
                    .map(|target| {
                        let lane = target.lanes.first();
                        (
                            target.address,
                            lane.and_then(|lane| lane.catch_up),
                            lane.map_or(0, |lane| lane.high),
                            target.repair.as_deref().map(|repair| repair.counts()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Each destination's counters (tests).
    #[cfg(test)]
    pub(crate) fn destination_counters(&self) -> Vec<(SocketAddr, TargetCounters)> {
        self.fanout
            .as_deref()
            .map(|fanout| {
                fanout
                    .targets
                    .iter()
                    .map(|target| (target.address, target.counters))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Enables a repair path per destination, each with its share of the
    /// repair tables for [`MAX_DESTINATIONS`] (MD-8, karyos#802; control
    /// path, allocates).
    pub(super) fn enable_fanout_repair(
        &mut self,
        config: &crate::agents::repair::RepairConfig,
        term_length: u32,
        identity: karyos_protocol::network::Identity,
    ) -> Result<(), crate::agents::repair::RepairConfigError> {
        let (drr, mtu, alias) = (self.drr, self.mtu, self.alias);
        let Some(fanout) = self.fanout.as_deref_mut() else {
            return Ok(());
        };
        // MD-8: each destination's cap is the share of the job table for
        // `max_destinations`, whatever the current count, so additions never
        // overcommit it. A table below one job per destination is refused
        // (`RepairConfigError::DestinationShare`).
        let config = destination_share(config)?;
        fanout.repair = Some((config, term_length, alias, identity));
        for target in &mut fanout.targets {
            target.repair = Some(Box::new(crate::agents::repair::RepairPath::new(
                &config,
                drr,
                mtu,
                (term_length, alias, identity),
            )?));
        }
        Ok(())
    }

    /// Admits `nak` from the receiver at `source` into its destination's
    /// repair path (MD-8); dropped for a source that is no destination.
    pub(super) fn nak_from(
        &mut self,
        source: SocketAddr,
        nak: &karyos_protocol::network::Nak,
        requester: crate::repair::admission::Requester,
        now: u64,
    ) -> crate::agents::repair::NakOutcome {
        use crate::agents::repair::NakOutcome;

        let lane = usize::from(nak.range.lane.get());
        let lanes = u8::try_from(self.readers.len()).unwrap_or(u8::MAX);
        let reader = self.readers.get(lane);
        let Some(target) = self
            .fanout
            .as_deref_mut()
            .and_then(|fanout| fanout.target_at(source))
        else {
            return NakOutcome::Dropped;
        };
        let sent_high = target.lanes.get(lane).map_or(0, |track| track.high);
        match target.repair.as_deref_mut() {
            Some(repair) => repair.nak_on(nak, (requester, 0, true), reader, sent_high, lanes, now),
            None => NakOutcome::Dropped,
        }
    }

    /// Serves each destination's repairs on `tx` within `budget`, from a
    /// rotating start; returns the heads submitted.
    pub(super) fn serve_fanout_repair<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        budget: &mut crate::repair::scheduler::RepairBudget,
        now: u64,
    ) -> u32 {
        if !self.open_targets(tx, now) {
            return 0;
        }
        let max_frame = self.max_frame;
        let Some(fanout) = self.fanout.as_deref_mut() else {
            return 0;
        };
        let count = fanout.targets.len();
        let mut frames = 0u64;
        for visit in 0..count {
            let at = (fanout.rotation + visit) % count;
            let Some(target) = fanout.targets.get_mut(at) else {
                continue;
            };
            if target.removed.is_some() {
                continue;
            }
            let mut sent_high = [0u64; karyos_protocol::network::MAX_LANES];
            for ((high, track), edge) in sent_high.iter_mut().zip(&target.lanes).zip(target.edges) {
                // A catch-up reads up to its end, above what was submitted,
                // never past the destination's own edge (design 4.2).
                *high = track.high.max(track.catch_up_to.min(edge));
            }
            let closed = [false; karyos_protocol::network::MAX_LANES];
            let Some(repair) = target.repair.as_deref_mut() else {
                continue;
            };
            // A catch-up waiting for room in the destination's share, or
            // for its window: like new DATA, it is served only up to the
            // destination's own edge, and a job is taken only when a whole
            // maximum frame fits below that edge (or the range ends
            // first), the rest waiting for the window to open (design 4.2;
            // karyos#890 review). One job at a time per lane: the range
            // moves on only by what the job submitted, a frame boundary,
            // never to the job's end, so a job that stopped inside a frame
            // is taken up again from its last whole frame.
            for (lane, ((track, reader), edge)) in target
                .lanes
                .iter_mut()
                .zip(&self.readers)
                .zip(target.edges)
                .enumerate()
            {
                let Ok(lane) = u8::try_from(lane) else {
                    continue;
                };
                if let Some(job) = track.catch_up_job {
                    if repair.catch_up_pending(job) {
                        continue;
                    }
                    track.catch_up_job = None;
                    let through = repair.catch_up_through(lane);
                    track.catch_up = track
                        .catch_up
                        .filter(|(_, to)| through < *to)
                        .map(|(from, to)| (from.max(through), to));
                }
                let Some((from, to)) = track.catch_up else {
                    continue;
                };
                let end = to.min(edge);
                let whole = end == to
                    || from
                        .checked_add(max_frame)
                        .is_some_and(|frame| frame <= end);
                if end <= from || !whole {
                    continue;
                }
                track.catch_up = match repair.catch_up(lane, (from, end), reader.floor()) {
                    crate::agents::repair::CatchUp::Queued { from, job, .. } => {
                        track.catch_up_job = Some(job);
                        Some((from, to))
                    }
                    crate::agents::repair::CatchUp::Full { from } => Some((from, to)),
                    crate::agents::repair::CatchUp::Done => (end < to).then_some((end, to)),
                };
            }
            let before = repair.counts().submitted;
            let report = repair.serve_routes(
                &mut [Some(&mut *tx)],
                &mut self.readers,
                (&sent_high, &closed),
                budget,
                now,
            );
            let after = repair.counts().submitted;
            // What the catch-up submitted is the destination's: its
            // frontier moves there, so its NAKs, the retention and a later
            // reset's start follow (MD-20, karyos#890 review).
            for (lane, track) in target.lanes.iter_mut().enumerate() {
                if let Ok(lane) = u8::try_from(lane) {
                    track.high = track.high.max(repair.catch_up_through(lane));
                }
            }
            target.counters.repairs = target
                .counters
                .repairs
                .saturating_add(after.saturating_sub(before));
            frames = report
                .lanes
                .iter()
                .fold(frames, |sum, lane| sum.saturating_add(lane.served_frames));
        }
        u32::try_from(frames).unwrap_or(u32::MAX)
    }

    /// Hands each destination's step 8 ERRs to `send`.
    pub(super) fn drain_fanout_replies(
        &mut self,
        send: &mut impl FnMut(&karyos_protocol::network::NakReply),
    ) {
        if let Some(fanout) = self.fanout.as_deref_mut() {
            for target in &mut fanout.targets {
                if let Some(repair) = target.repair.as_deref_mut() {
                    repair.drain_replies(|reply| send(reply));
                }
            }
        }
    }
}

impl Fanout {
    /// A new optional target toward `address`, its lanes joining at
    /// `joins` (allocates: a run-time addition, MD-3), with its own repair
    /// path if the publication repairs: nothing of an earlier target
    /// toward the same address is reused (design 3.7).
    fn target(&self, address: SocketAddr, joins: &[u64]) -> Option<Target> {
        let repair = match self.repair {
            Some((config, term_length, alias, identity)) => Some(Box::new(
                crate::agents::repair::RepairPath::new(
                    &config,
                    self.drr,
                    self.mtu,
                    (term_length, alias, identity),
                )
                .ok()?,
            )),
            None => None,
        };
        Target::new(address, false, self.drr, joins, repair)
    }

    /// Whether `address` was retired less than `quarantine` before `now`
    /// (MD-14); an expired record is dropped.
    fn quarantined(&mut self, address: SocketAddr, now: u64, quarantine: u64) -> bool {
        let Some(at) = self
            .quarantined
            .iter()
            .position(|(retired, _)| *retired == address)
        else {
            return false;
        };
        let removed_at = self.quarantined.get(at).map_or(0, |(_, time)| *time);
        if now
            .checked_sub(removed_at)
            .is_none_or(|age| age < quarantine)
        {
            return true;
        }
        let _ = self.quarantined.remove(at);
        false
    }
}

impl<T: StreamTerms> Outbound<T> {
    /// Adds or removes the optional destination `destination` at `now`
    /// (MD-3): a required destination is fixed at creation (ADR-0082), and
    /// a destination removed less than `quarantine` ago cannot come back
    /// yet (MD-14). An optional destination moves by a removal and an
    /// addition. Allocates for an addition (a run-time command).
    pub(crate) fn change_destination(
        &mut self,
        destination: SocketAddr,
        add: bool,
        now: u64,
        quarantine: u64,
    ) -> DestinationChange {
        if self.fanout.is_none() {
            return DestinationChange::Unknown;
        }
        if self.removing() {
            return DestinationChange::Removing;
        }
        let Some(fanout) = self.fanout.as_deref_mut() else {
            return DestinationChange::Unknown;
        };
        let family = Some(fanout.ipv4);
        let found = fanout
            .targets
            .iter_mut()
            .find(|target| target.address == destination);
        match (found, add) {
            (Some(target), _) if target.required => DestinationChange::Required,
            (Some(target), false) if target.removed.is_none() => {
                remove_target(target, RemovalReason::Command, now);
                DestinationChange::Removed
            }
            // Removed and still draining: absent, and in its quarantine.
            (Some(_), false) => DestinationChange::Absent,
            (Some(target), true) if target.removed.is_none() => DestinationChange::Present,
            (Some(_), true) => DestinationChange::Quarantined,
            (None, false) => DestinationChange::Absent,
            (None, true) => {
                if family != Some(destination.is_ipv4()) {
                    return DestinationChange::Unknown;
                }
                if fanout.quarantined(destination, now, quarantine) {
                    return DestinationChange::Quarantined;
                }
                // A removed target holds its slot until its route and queues
                // pass to the close list, at its report: a move retried
                // after the removal shows in `network_removed_destinations`
                // finds the slot free, and the next duty closes the old
                // route before it opens the new one. While the conductor's
                // ring is full nothing is reported and nothing retires, so
                // churn never grows the targets, their flags or the retired
                // list past their capacity.
                if fanout.targets.len().saturating_add(fanout.retired.len()) >= MAX_DESTINATIONS {
                    return DestinationChange::Full;
                }
                // A fresh optional destination, joining at the cursor; its
                // target is built here (an addition allocates its queues
                // and repair path), nothing else does.
                for (join, reader) in fanout.joins.iter_mut().zip(&self.readers) {
                    *join = reader.position();
                }
                let Some(target) = fanout.target(destination, &fanout.joins) else {
                    return DestinationChange::Unknown;
                };
                fanout.targets.push(target);
                for flags in &mut fanout.staged_for {
                    // The pending datagram, if any, is not the new target's.
                    flags.push(true);
                }
                DestinationChange::Added
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    fn target(required: bool) -> Target {
        let address: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let drr = DrrConfig::new(&[1536], 1536).unwrap();
        let required = if required { vec![address] } else { Vec::new() };
        let mut fanout = Fanout::new(&[address], &required, drr, 1, 1500, &[0], true).unwrap();
        let mut target = fanout.targets.pop().unwrap();
        target.stalled = true;
        target
    }

    /// A ticket of a real committed datagram, from a scripted endpoint.
    fn ticket() -> TxTicket {
        use karyos_io::backend::{Commit, InstanceId, TxBackend, TxOptions};
        use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint};
        use karyos_io::sockets::scripted::ScriptedSocket;

        let config = SocketsConfig::new("127.0.0.1:7000".parse().unwrap());
        let endpoint =
            SocketsEndpoint::open(&config, InstanceId::FIRST, ScriptedSocket::new()).unwrap();
        let (mut tx, _rx) = endpoint.split().unwrap();
        let route = tx.add_route("127.0.0.1:7001".parse().unwrap()).unwrap();
        let queue = tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: NonZeroU16::MIN,
            })
            .unwrap();
        let frame = tx.claim_tx(queue, 8).unwrap();
        let ticket = frame
            .commit(Commit {
                len: 8,
                token: SenderToken::new(1),
                options: TxOptions::none(),
            })
            .unwrap();
        // The half is dropped with nothing pending.
        let mut report = karyos_io::backend::TxReport::new();
        let _ = tx.cancel_pending(queue, &mut report);
        ticket
    }

    /// A route and a queue really opened on a scripted endpoint, as a
    /// retired target leaves them.
    fn opened() -> Opened {
        use karyos_io::backend::{BackendEpoch, InstanceId};
        use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint};
        use karyos_io::sockets::scripted::ScriptedSocket;

        let config = SocketsConfig::new("127.0.0.1:7000".parse().unwrap());
        let endpoint =
            SocketsEndpoint::open(&config, InstanceId::FIRST, ScriptedSocket::new()).unwrap();
        let (mut tx, _rx) = endpoint.split().unwrap();
        let route = tx.add_route("127.0.0.1:7001".parse().unwrap()).unwrap();
        let queue = tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: NonZeroU16::MIN,
            })
            .unwrap();
        let mut queues = [None; OPENED_QUEUES];
        queues[0] = Some(queue);
        Opened {
            endpoint: crate::agents::EndpointId(1),
            epoch: BackendEpoch::FIRST,
            route,
            queues,
        }
    }

    /// A destination lane at `high`, nothing staged.
    fn lane_at(high: u64) -> TargetLane {
        TargetLane {
            staged: VecDeque::new(),
            high,
            unsent: false,
            hole: None,
            catch_up: None,
            catch_up_job: None,
            catch_up_to: 0,
            mismatched: false,
            submitted: false,
        }
    }

    /// MD-20 (karyos#802): after a reset with the readers at 6 000, each
    /// destination catches up over exactly what it lacks: one at 1 000
    /// from 1 000, one already at 6 000 nothing, and one whose head at
    /// 2 000 was returned unsent while a later one was submitted (its
    /// `high` 4 000 passed the hole) from 2 000, not from 4 000.
    #[test]
    fn a_reset_catches_up_each_destination_over_what_it_lacks() {
        let position = 6_000;
        let mut behind = lane_at(1_000);
        let mut caught_up = lane_at(6_000);
        let mut holed = lane_at(2_000);
        holed.left(3_000, Left::Returned);
        holed.left(4_000, Left::Submitted);
        assert_eq!((holed.high, holed.hole), (4_000, Some(2_000)));
        let mut unknown = lane_at(5_000);
        unknown.left(5_500, Left::Unknown);
        for lane in [&mut behind, &mut caught_up, &mut holed, &mut unknown] {
            lane.catch_up_after_reset(position);
        }
        assert_eq!(behind.catch_up, Some((1_000, 6_000)));
        assert_eq!(
            caught_up.catch_up, None,
            "nothing to a destination that has it"
        );
        assert_eq!(holed.catch_up, Some((2_000, 6_000)));
        assert_eq!(unknown.catch_up, Some((5_000, 6_000)));
        // The hole is used once; `high`, the publication's sent frontier,
        // never moves back.
        assert_eq!((holed.hole, holed.high), (None, 4_000));
        assert_eq!(holed.catch_up_to, 6_000);
        // A second reset before the first catch-up found room keeps the
        // lower start and the new end.
        holed.catch_up_after_reset(7_000);
        assert_eq!(holed.catch_up, Some((2_000, 7_000)));
        assert_eq!(holed.catch_up_to, 7_000);
    }

    /// karyos#890 review: an outcome of a head staged before a reset that
    /// is reported after the reopen (which clears the lane's staged heads)
    /// matches no staged ticket: it marks the lane `mismatched` and never
    /// records a `hole`, so no stale hole starts a later catch-up early.
    #[test]
    fn a_heads_outcome_after_the_reopen_records_no_hole() {
        use karyos_io::backend::{Commit, TxOptions};
        let mut tx = roomy_tx();
        let route = tx.add_route("127.0.0.1:7001".parse().unwrap()).unwrap();
        let queue = tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: NonZeroU16::MIN,
            })
            .unwrap();
        let frame = tx.claim_tx(queue, 1408).unwrap();
        let ticket = frame
            .commit(Commit {
                len: 64,
                token: SenderToken::new(1),
                options: TxOptions::none(),
            })
            .unwrap();
        let staged = Staged {
            ticket,
            charge: 64,
            len: 64,
        };
        let mut lanes = [lane_at(1_000)];
        lanes[0].staged.push_back((ticket, 2_000));
        // The reopen clears what was staged, as `open_targets` does.
        lanes[0].staged.clear();
        let mut gate = TargetGate {
            lanes: &mut lanes,
            held: false,
            edges: [u64::MAX; 4],
        };
        gate.left(0, staged, Left::Returned);
        assert_eq!(
            (lanes[0].hole, lanes[0].mismatched, lanes[0].high),
            (None, true, 1_000)
        );
        // Staged in the same epoch, the same outcome records its hole.
        let mut lanes = [lane_at(1_000)];
        lanes[0].staged.push_back((ticket, 2_000));
        let mut gate = TargetGate {
            lanes: &mut lanes,
            held: false,
            edges: [u64::MAX; 4],
        };
        gate.left(0, staged, Left::Returned);
        assert_eq!((lanes[0].hole, lanes[0].mismatched), (Some(1_000), false));
        // The committed item is never sent: a TX half dropped with it
        // pending asserts, so the test lets it go.
        std::mem::forget(tx);
    }

    /// The shares (MD-8, karyos#802): each table a destination's repair
    /// path holds, over every destination the publication may have, stays
    /// within the configured table; a table below one entry per
    /// destination is refused by name.
    #[test]
    fn each_repair_table_is_shared_out_within_its_configured_size() {
        use crate::agents::repair::{RepairConfig, RepairConfigError};
        let config = RepairConfig::default();
        let shared = destination_share(&config).unwrap();
        for (one, all) in [
            (shared.jobs.repair_jobs, config.jobs.repair_jobs),
            (shared.err_linger_entries, config.err_linger_entries),
            (
                shared.jobs.repair_linger_entries,
                config.jobs.repair_linger_entries,
            ),
            (shared.replies, config.replies),
        ] {
            assert!(one >= 1);
            assert!(
                one * MAX_DESTINATIONS <= all,
                "{one} x {MAX_DESTINATIONS} > {all}"
            );
        }
        // Requesters are per job.
        assert_eq!(
            shared.jobs.requesters_per_job,
            config.jobs.requesters_per_job
        );
        let small = |set: fn(&mut RepairConfig)| {
            let mut config = RepairConfig::default();
            set(&mut config);
            destination_share(&config)
        };
        assert_eq!(
            small(|c| c.replies = MAX_DESTINATIONS - 1),
            Err(RepairConfigError::TableShare {
                table: "replies",
                value: MAX_DESTINATIONS - 1,
                destinations: MAX_DESTINATIONS,
            })
        );
        assert!(matches!(
            small(|c| c.err_linger_entries = 1),
            Err(RepairConfigError::TableShare {
                table: "err_linger_entries",
                ..
            })
        ));
        assert!(matches!(
            small(|c| c.jobs.repair_linger_entries = 3),
            Err(RepairConfigError::TableShare {
                table: "repair_linger_entries",
                ..
            })
        ));
        assert!(matches!(
            small(|c| c.jobs.repair_jobs = 2),
            Err(RepairConfigError::DestinationShare { .. })
        ));
    }

    /// MD-20 (karyos#802): a catch-up takes a job in its destination's
    /// share with no admission; a full share leaves it to try again, and a
    /// part below the retention floor is counted lost, never read.
    #[test]
    fn a_catch_up_takes_a_job_waits_on_a_full_share_and_counts_what_is_below_the_floor() {
        use crate::agents::repair::{CatchUp, RepairConfig};
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut outbound = fanned(address(4000));
        let mut config = RepairConfig::default();
        // One job per destination.
        config.jobs.repair_jobs = MAX_DESTINATIONS;
        let identity = karyos_protocol::network::Identity {
            driver_id: [1, 2],
            registration_id: 1,
            incarnation: 1,
        };
        outbound.enable_repair(&config, 65_536, identity).unwrap();
        let fanout = outbound.fanout.as_deref_mut().unwrap();
        let repair = fanout.targets[0].repair.as_deref_mut().unwrap();
        let CatchUp::Queued { from, through, job } = repair.catch_up(0, (1_024, 4_096), 0) else {
            panic!("no job");
        };
        assert_eq!((from, through), (1_024, 4_096));
        assert!(repair.catch_up_pending(job));
        // The same range joins the pending job; another finds the share full.
        assert_eq!(
            repair.catch_up(0, (1_024, 4_096), 0),
            CatchUp::Queued {
                from: 1_024,
                through: 4_096,
                job
            }
        );
        assert_eq!(
            repair.catch_up(0, (8_192, 9_216), 0),
            CatchUp::Full { from: 8_192 }
        );
        // Below the floor: lost, counted, and only the rest is asked for.
        assert_eq!(repair.catch_up(0, (0, 512), 1_024), CatchUp::Done);
        let counts = repair.counts();
        assert_eq!(
            (
                counts.catch_ups,
                counts.catch_ups_full,
                counts.catch_up_lost
            ),
            (2, 1, 512)
        );
        // karyos#890 review (codex): while the share stays full, retrying
        // as the fanout does (from the start it was handed back) counts
        // the prefix below the floor once, not once per retry.
        let mut range = (0, 6_144);
        for _ in 0..3 {
            match repair.catch_up(0, range, 1_024) {
                CatchUp::Full { from } => range = (from, range.1),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(range, (1_024, 6_144));
        assert_eq!(repair.counts().catch_up_lost, 512 + 1_024);
    }

    /// karyos#802: with every destination's step 8 ERR list full in one
    /// cycle, the sender's list (`replies`, as the role sizes it) takes
    /// them all: the shares of the destinations sum within it, so nothing
    /// counts toward `nak_replies_dropped`.
    #[test]
    fn every_destinations_errs_fit_the_senders_list() {
        use crate::agents::repair::RepairConfig;
        use karyos_protocol::frame::Lane;
        use karyos_protocol::network::{Nak, NakRange, NakReply, NakReplyReason, Receiver};
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut outbound = fanned(address(4000));
        for port in 1..u16::try_from(MAX_DESTINATIONS).unwrap() {
            let _ = outbound.change_destination(address(4000 + port), true, 0, 0);
        }
        let config = RepairConfig::default();
        let identity = karyos_protocol::network::Identity {
            driver_id: [1, 2],
            registration_id: 1,
            incarnation: 1,
        };
        outbound.enable_repair(&config, 65_536, identity).unwrap();
        let nak = Nak {
            alias: karyos_protocol::network::Alias {
                session_id: 5,
                stream_id: 6,
            },
            identity,
            receiver: Receiver {
                receiver_boot_id: [7, 8],
                receiver_id: 1,
            },
            range: NakRange {
                lane: Lane::ZERO,
                length: 64,
                start: 0,
            },
        };
        let reply = NakReply::answering(&nak, NakReplyReason::RangeInvalid);
        let fanout = outbound.fanout.as_deref_mut().unwrap();
        assert_eq!(fanout.targets.len(), MAX_DESTINATIONS);
        let held: usize = fanout
            .targets
            .iter_mut()
            .map(|target| target.repair.as_deref_mut().unwrap().fill_replies(reply))
            .sum();
        assert_eq!(held, MAX_DESTINATIONS * (config.replies / MAX_DESTINATIONS));
        // The role's own list and its drop rule (roles.rs).
        let mut replies = Vec::with_capacity(config.replies);
        let mut dropped = 0u64;
        outbound.drain_repair_replies_on(|reply, endpoint| {
            if replies.len() < replies.capacity() {
                replies.push((endpoint, *reply));
            } else {
                dropped += 1;
            }
        });
        assert_eq!((replies.len(), dropped), (held, 0));
    }

    /// A multi-destination publication of one lane toward `first`.
    fn fanned(first: SocketAddr) -> Box<Outbound> {
        let term = karyos_protocol::network::TermParams {
            term_length: 65_536,
            initial_term_id: 9,
            mtu: 1408,
        };
        let alias = karyos_protocol::network::Alias {
            session_id: 5,
            stream_id: 6,
        };
        let (mut outbound, _log) = super::super::testing::outbound(
            crate::agents::EndpointId(1),
            alias,
            first,
            term,
            1,
            false,
        );
        outbound
            .set_destinations(&[first], &[], Some(true))
            .unwrap();
        outbound
    }

    /// Plan 157, point 1: a publication removed before the sender's next
    /// duty drained its retired targets still hands their routes and
    /// queues over, so its removal closes them.
    #[test]
    fn a_removal_hands_over_the_targets_retired_since_the_last_drain() {
        let mut outbound = fanned("127.0.0.1:4000".parse().unwrap());
        let retired = opened();
        outbound
            .fanout
            .as_deref_mut()
            .unwrap()
            .retired
            .push(retired);
        let mut held = Vec::new();
        outbound.opened_resources(|opened| held.push(opened));
        assert!(held.contains(&retired), "{held:?}");
    }

    /// A scripted endpoint's TX half with room for every destination's
    /// route and queues.
    fn roomy_tx() -> SocketsTx<karyos_io::sockets::scripted::ScriptedSocket> {
        use karyos_io::backend::InstanceId;
        use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint};
        use karyos_io::sockets::scripted::ScriptedSocket;

        let mut config = SocketsConfig::new("127.0.0.1:7000".parse().unwrap());
        config.max_routes = NonZeroU16::new(64).unwrap();
        config.max_queues = NonZeroU16::new(256).unwrap();
        config.tx_slots = NonZeroU16::new(4096).unwrap();
        let endpoint =
            SocketsEndpoint::open(&config, InstanceId::FIRST, ScriptedSocket::new()).unwrap();
        endpoint.split().unwrap().0
    }

    /// Removes the opened `destination`; returns the allocations the
    /// removal made.
    fn remove_opened(outbound: &mut Outbound, destination: SocketAddr) -> u64 {
        let (change, allocations) = karyos_sys::alloc_count::count_allocations(|| {
            outbound.change_destination(destination, false, 0, 0)
        });
        assert_eq!(change, DestinationChange::Removed);
        let fanout = outbound.fanout.as_deref_mut().unwrap();
        let target = fanout
            .targets
            .iter_mut()
            .find(|target| target.address == destination)
            .unwrap();
        assert!(target.opened.is_some(), "an opened target");
        allocations
    }

    /// Plan 157, point 2, and review B2 of #829: while removals cannot be
    /// reported (the conductor's ring is full), remove and add churn on
    /// opened destinations answers `Full` once the removed ones fill the
    /// table, and no per-destination vector grows; a removal, a refused
    /// addition, a report with its retirement and the drain allocate
    /// nothing (a retirement frees its target).
    #[test]
    fn churn_with_removals_unreported_never_grows_past_the_table() {
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut tx = roomy_tx();
        let mut outbound = fanned(address(4000));
        let _ = outbound.open_targets(&mut tx, 0);
        let capacities = |outbound: &Outbound| {
            let fanout = outbound.fanout.as_deref().unwrap();
            (
                fanout.targets.capacity(),
                fanout.staged_for[0].capacity(),
                fanout.retired.capacity(),
            )
        };
        let before = capacities(&outbound);
        let mut full = 0;
        for port in 1..=40u16 {
            let (change, allocations) = karyos_sys::alloc_count::count_allocations(|| {
                outbound.change_destination(address(4000 + port), true, 0, 0)
            });
            match change {
                DestinationChange::Added => {
                    let _ = outbound.open_targets(&mut tx, 0);
                    assert_eq!(remove_opened(&mut outbound, address(4000 + port)), 0);
                }
                DestinationChange::Full => {
                    full += 1;
                    assert_eq!(allocations, 0, "a refused addition allocates nothing");
                }
                other => panic!("{other:?}"),
            }
            let fanout = outbound.fanout.as_deref().unwrap();
            assert!(fanout.targets.len() <= MAX_DESTINATIONS);
            assert!(fanout.staged_for[0].len() <= MAX_DESTINATIONS);
        }
        assert!(full > 0, "the table filled");
        // The ring drains: each report retires its target, whose route and
        // queues go to the retired list and then to the close list.
        let mut closing = Vec::with_capacity(MAX_DESTINATIONS);
        while let Some(removal) = outbound.removal_unreported() {
            let (_, allocations) = karyos_sys::alloc_count::count_allocations(|| {
                outbound.removal_reported(removal.destination, 0);
            });
            assert_eq!(
                allocations, 0,
                "a report and its retirement allocate nothing"
            );
        }
        assert_eq!(
            outbound.fanout.as_deref().unwrap().retired.len(),
            MAX_DESTINATIONS - 1
        );
        let (_, allocations) =
            karyos_sys::alloc_count::count_allocations(|| outbound.drain_retired(&mut closing));
        assert_eq!(allocations, 0, "the drain allocates nothing");
        assert_eq!(closing.len(), MAX_DESTINATIONS - 1);
        assert_eq!(outbound.counters().destinations_retired, 15);
        assert_eq!(capacities(&outbound), before, "nothing reallocated");
    }

    /// Review B1 and C1 of #829: once a removal is reported (which it is
    /// at once, whatever its state), it is retired in that cycle, so a
    /// move at capacity right after the report is `Added`.
    #[test]
    fn an_addition_after_the_removal_is_reported_finds_the_slot_free() {
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut tx = roomy_tx();
        let mut outbound = fanned(address(4000));
        for port in 1..u16::try_from(MAX_DESTINATIONS).unwrap() {
            let change = outbound.change_destination(address(4000 + port), true, 0, 0);
            assert_eq!(change, DestinationChange::Added);
        }
        let _ = outbound.open_targets(&mut tx, 0);
        assert_eq!(
            outbound.change_destination(address(4100), true, 0, 0),
            DestinationChange::Full
        );
        let _ = outbound.change_destination(address(4001), false, 0, 0);
        assert_eq!(
            outbound.change_destination(address(4100), true, 0, 0),
            DestinationChange::Full,
            "the removed target holds its slot until its report"
        );
        // Its removal is reported at once, opened or not, and retired then.
        let removal = outbound.removal_unreported().unwrap();
        assert_eq!(removal.destination, address(4001));
        outbound.removal_reported(removal.destination, 0);
        assert_eq!(
            outbound.counters().destinations_retired,
            1,
            "retired in the cycle of its report"
        );
        assert_eq!(
            outbound.fanout.as_deref().unwrap().retired.len(),
            1,
            "its route and queues go to the close list"
        );
        // The next duty closes them before it serves commands.
        let mut closing = Vec::with_capacity(MAX_DESTINATIONS);
        outbound.drain_retired(&mut closing);
        assert_eq!(
            outbound.change_destination(address(4100), true, 0, 0),
            DestinationChange::Added
        );
    }

    /// Review E1 and G1 of #829, and should-fix 4: an endpoint really
    /// reset to a new epoch; a destination opened in the old one and
    /// removed after the publication opened in the new one is reported
    /// and retired at once, its dead handles dropped (they take no place in
    /// the lists), and its slot is free with no close to wait for.
    #[test]
    fn a_removal_after_a_reset_frees_its_slot() {
        use karyos_io::backend::{InstanceId, TxReport};
        use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint};
        use karyos_io::sockets::scripted::ScriptedSocket;

        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut config = SocketsConfig::new("127.0.0.1:7000".parse().unwrap());
        config.max_routes = NonZeroU16::new(64).unwrap();
        config.max_queues = NonZeroU16::new(256).unwrap();
        config.tx_slots = NonZeroU16::new(4096).unwrap();
        let endpoint =
            SocketsEndpoint::open(&config, InstanceId::FIRST, ScriptedSocket::new()).unwrap();
        let (mut tx, rx) = endpoint.split().unwrap();
        let mut outbound = fanned(address(4000));
        for port in 1..u16::try_from(MAX_DESTINATIONS).unwrap() {
            let _ = outbound.change_destination(address(4000 + port), true, 0, 0);
        }
        let _ = outbound.open_targets(&mut tx, 0);
        let first = tx.capabilities().epoch;
        // The reset: every handle of the first epoch dies.
        let mut endpoint = SocketsEndpoint::join(tx, rx).unwrap();
        let mut report = TxReport::new();
        while endpoint.reset(&mut report).more {
            while report.pop_front().is_some() {}
        }
        let _ = endpoint.reopen(&config).unwrap();
        let (mut tx, _rx) = endpoint.split().unwrap();
        assert_ne!(tx.capabilities().epoch, first, "a new epoch");
        // Removed after the reset and before the publication's next serve
        // reopens it: its handles are of the first epoch.
        let _ = outbound.change_destination(address(4003), false, 0, 0);
        let _ = outbound.open_targets(&mut tx, 1);
        let removal = outbound.removal_unreported().expect("reported at once");
        assert_eq!(removal.destination, address(4003));
        outbound.removal_reported(removal.destination, 1);
        let fanout = outbound.fanout.as_deref().unwrap();
        assert!(fanout.retired.is_empty(), "no dead handle in the lists");
        assert_eq!(outbound.counters().destinations_retired, 1);
        assert_eq!(
            outbound.change_destination(address(4100), true, 1, 0),
            DestinationChange::Added,
            "nothing to close first"
        );
    }

    /// Review G2 of #829: a destination retired at its report is
    /// quarantined from its removal, as a removed publication's address
    /// is (MD-14): re-added before its quarantine ends it answers
    /// `Quarantined`, after it `Added`.
    #[test]
    fn a_retired_destination_keeps_its_quarantine() {
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut tx = roomy_tx();
        let mut outbound = fanned(address(4000));
        let _ = outbound.change_destination(address(4001), true, 0, 0);
        let _ = outbound.open_targets(&mut tx, 0);
        let quarantine = 1_000;
        // The sender sets both from `receiver_timeout`.
        outbound.set_destination_timing(quarantine, 0);
        assert_eq!(
            outbound.change_destination(address(4001), false, 5_000, quarantine),
            DestinationChange::Removed
        );
        outbound.removal_reported(address(4001), 5_100);
        assert_eq!(outbound.counters().destinations_retired, 1, "at its report");
        outbound.drain_retired(&mut Vec::with_capacity(MAX_DESTINATIONS));
        assert_eq!(
            outbound.change_destination(address(4001), true, 5_999, quarantine),
            DestinationChange::Quarantined
        );
        assert_eq!(
            outbound.change_destination(address(4001), true, 6_000, quarantine),
            DestinationChange::Added
        );
    }

    /// Review E2 of #829: an opened destination removed while its
    /// publication is not served (its receivers gone) is reported and
    /// retired at once, so a move to another destination is no deadlock.
    #[test]
    fn a_removal_on_an_unserved_publication_frees_its_slot() {
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut tx = roomy_tx();
        let mut outbound = fanned(address(4000));
        for port in 1..u16::try_from(MAX_DESTINATIONS).unwrap() {
            let _ = outbound.change_destination(address(4000 + port), true, 0, 0);
        }
        // Opened once, then never served again.
        let _ = outbound.open_targets(&mut tx, 0);
        assert!(remove_opened(&mut outbound, address(4005)) == 0);
        let removal = outbound.removal_unreported().expect("no serve needed");
        outbound.removal_reported(removal.destination, 0);
        outbound.drain_retired(&mut Vec::with_capacity(MAX_DESTINATIONS));
        assert_eq!(
            outbound.change_destination(address(4100), true, 0, 0),
            DestinationChange::Added
        );
    }

    /// Review C1 of #829 (a regression at `18869058`): a publication not
    /// established has nothing to drain, so a removal before its
    /// establishment is reported in that cycle, and a move at capacity
    /// right after it is `Added`.
    #[test]
    fn a_removal_before_establishment_frees_its_slot_at_once() {
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        // Never served: none of its destinations opened.
        let mut outbound = fanned(address(4000));
        for port in 1..u16::try_from(MAX_DESTINATIONS).unwrap() {
            let change = outbound.change_destination(address(4000 + port), true, 0, 0);
            assert_eq!(change, DestinationChange::Added);
        }
        assert_eq!(
            outbound.change_destination(address(4100), true, 0, 0),
            DestinationChange::Full
        );
        assert_eq!(
            outbound.change_destination(address(4001), false, 0, 0),
            DestinationChange::Removed
        );
        let removal = outbound
            .removal_unreported()
            .expect("reported in this cycle");
        outbound.removal_reported(removal.destination, 0);
        assert_eq!(
            outbound.change_destination(address(4100), true, 0, 0),
            DestinationChange::Added
        );
    }

    /// Should-fix of #829: with the quarantine full, the record removed
    /// earliest makes room, whatever the order records were added in.
    #[test]
    fn a_full_quarantine_forgets_the_earliest_removal() {
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut outbound = fanned(address(4000));
        let _ = outbound.change_destination(address(4001), true, 0, 0);
        let fanout = outbound.fanout.as_deref_mut().unwrap();
        fanout.quarantine = 1_000_000;
        // Sixteen records, the earliest removal (at 10) added last.
        for index in 0..15u16 {
            fanout
                .quarantined
                .push_back((address(5000 + index), 100 + u64::from(index)));
        }
        fanout.quarantined.push_back((address(5100), 10));
        let _ = outbound.change_destination(address(4001), false, 500, 1_000_000);
        outbound.removal_reported(address(4001), 500);
        let fanout = outbound.fanout.as_deref().unwrap();
        assert!(
            !fanout
                .quarantined
                .iter()
                .any(|(at, _)| *at == address(5100)),
            "the earliest removal is forgotten"
        );
        assert!(
            fanout
                .quarantined
                .iter()
                .any(|(at, _)| *at == address(5000))
        );
        assert_eq!(outbound.counters().quarantine_forgotten, 1);
    }

    /// Should-fix of #829: the incoming record counts too: when it was
    /// removed before every record held, it is the one forgotten.
    #[test]
    fn a_full_quarantine_forgets_an_earlier_incoming_removal() {
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut outbound = fanned(address(4000));
        let _ = outbound.change_destination(address(4001), true, 0, 0);
        let fanout = outbound.fanout.as_deref_mut().unwrap();
        fanout.quarantine = 1_000_000;
        for index in 0..16u16 {
            fanout
                .quarantined
                .push_back((address(5000 + index), 1_000 + u64::from(index)));
        }
        let _ = outbound.change_destination(address(4001), false, 500, 1_000_000);
        outbound.removal_reported(address(4001), 2_000);
        let fanout = outbound.fanout.as_deref().unwrap();
        assert!(
            !fanout
                .quarantined
                .iter()
                .any(|(at, _)| *at == address(4001))
        );
        assert_eq!(fanout.quarantined.len(), 16, "every held record kept");
        assert_eq!(outbound.counters().quarantine_forgotten, 1);
    }

    /// The follow-up of #829's review, point 5: an incoming record already
    /// past its quarantine is not kept, and not counted as forgotten.
    #[test]
    fn an_expired_incoming_record_is_not_kept() {
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut outbound = fanned(address(4000));
        let _ = outbound.change_destination(address(4001), true, 0, 0);
        outbound.set_destination_timing(100, 0);
        let _ = outbound.change_destination(address(4001), false, 0, 100);
        outbound.removal_reported(address(4001), 1_000);
        let fanout = outbound.fanout.as_deref().unwrap();
        assert!(fanout.quarantined.is_empty());
        assert_eq!(outbound.counters().quarantine_forgotten, 0);
        assert_eq!(outbound.counters().destinations_retired, 1);
    }

    /// Review C3 and should-fix 5 of #829: retired routes and queues hold
    /// their slots until they leave for the close list, so a new
    /// destination never opens beside an old route still open; the drain
    /// takes every one (the follow-up of #829's review: the list always
    /// has room, so nothing is carried over).
    #[test]
    fn retired_routes_hold_their_slots_until_the_drain() {
        let address = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let mut tx = roomy_tx();
        let mut outbound = fanned(address(4000));
        for port in 1..u16::try_from(MAX_DESTINATIONS).unwrap() {
            let _ = outbound.change_destination(address(4000 + port), true, 0, 0);
        }
        let _ = outbound.open_targets(&mut tx, 0);
        for port in 0..u16::try_from(MAX_DESTINATIONS).unwrap() {
            let _ = remove_opened(&mut outbound, address(4000 + port));
            outbound.removal_reported(address(4000 + port), 0);
        }
        assert_eq!(outbound.counters().destinations_retired, 16);
        assert!(outbound.fanout.as_deref().unwrap().targets.is_empty());
        assert_eq!(
            outbound.change_destination(address(4100), true, 0, 0),
            DestinationChange::Full,
            "the old routes have not left yet"
        );
        let mut closing = Vec::with_capacity(2 * MAX_DESTINATIONS);
        outbound.drain_retired(&mut closing);
        assert_eq!(closing.len(), MAX_DESTINATIONS, "every one taken");
        assert_eq!(
            outbound.change_destination(address(4100), true, 0, 0),
            DestinationChange::Added
        );
    }

    /// MD-15, review N2: a destination moves to the cursor when it first
    /// joins, and when it comes back live holding nothing; one back from a
    /// brief lapse with data staged keeps its frontier while it submits
    /// that data (plan 157, point 5: what was sent while it was not live is
    /// the receiver's gap policy's).
    #[test]
    fn a_destination_moves_to_the_cursor_only_when_it_joins_or_holds_nothing() {
        let mut first = target(false);
        join_at(&mut first, [100].into_iter());
        assert_eq!(first.lanes[0].high, 100, "first join");
        join_at(&mut first, [200].into_iter());
        assert_eq!(first.lanes[0].high, 200, "back live, nothing held");
        first.lanes[0].staged.push_back((ticket(), 210));
        join_at(&mut first, [300].into_iter());
        assert_eq!(first.lanes[0].high, 200, "back live with data staged");
    }

    /// MD-12, review N3: only a destination's own open failures count, at
    /// most once per `setup_interval`: an endpoint resetting (`NotActive`)
    /// or out of identities never removes it, and a retry storm within one
    /// interval counts once.
    #[test]
    fn only_spaced_own_open_failures_count_against_a_destination() {
        use karyos_io::backend::{QueueError, RouteError};

        assert!(!route_own(RouteError::NotActive));
        assert!(!route_own(RouteError::IdentityExhausted));
        assert!(!route_own(RouteError::RouteLimit), "endpoint-wide");
        assert!(route_own(RouteError::FamilyMismatch));
        assert!(!queue_limit(QueueError::NotActive), "a reset");
        assert!(!queue_limit(QueueError::NeedsReset), "a reset");
        assert!(!queue_limit(QueueError::IdentityExhausted));
        assert!(!queue_limit(QueueError::UnknownQueue));
        assert!(queue_limit(QueueError::QueueLimit), "endpoint-wide");
        assert!(
            queue_limit(QueueError::OverCommitted {
                requested: 4,
                free: 1
            }),
            "endpoint-wide"
        );
        assert!(!queue_limit(QueueError::ReportNotEmpty));
        let mut optional = target(false);
        // An endpoint reset, twice per duty for a long while: nothing.
        for now in 0..100 {
            assert!(!open_failed(&mut optional, false, (now, 10)));
        }
        assert_eq!((optional.faults, optional.removed), (0, None));
        // Its own failures, many within one interval: one fault each
        // interval, removed at the third.
        for now in 0..9 {
            assert!(!open_failed(&mut optional, true, (now, 10)));
        }
        assert_eq!(optional.faults, 1);
        assert!(!open_failed(&mut optional, true, (10, 10)));
        assert!(open_failed(&mut optional, true, (20, 10)));
        assert_eq!(
            optional.removed.map(|(reason, _)| reason),
            Some(RemovalReason::Fault)
        );
        // A required one keeps trying.
        let mut required = target(true);
        for now in [0, 10, 20, 30] {
            assert!(!open_failed(&mut required, true, (now, 10)));
        }
        assert_eq!(required.removed, None);
    }

    /// Plan 157, points 3 and 4: an optional destination whose route
    /// cannot open because other publications filled the endpoint's route
    /// table is kept, its failures counted as the endpoint's limit, and its
    /// open is retried once per `setup_interval`, not at every serve.
    #[test]
    fn an_endpoint_limit_keeps_the_destination_and_spaces_its_retries() {
        use karyos_io::backend::InstanceId;
        use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint};
        use karyos_io::sockets::scripted::ScriptedSocket;

        let mut config = SocketsConfig::new("127.0.0.1:7000".parse().unwrap());
        config.max_routes = NonZeroU16::MIN;
        let endpoint =
            SocketsEndpoint::open(&config, InstanceId::FIRST, ScriptedSocket::new()).unwrap();
        let (mut tx, _rx) = endpoint.split().unwrap();
        // Another publication holds the only route.
        let _other = tx.add_route("127.0.0.1:7001".parse().unwrap()).unwrap();
        let mut outbound = fanned("127.0.0.1:4000".parse().unwrap());
        outbound.set_destination_timing(0, 10);
        for now in 0..100 {
            let _ = outbound.open_targets(&mut tx, now);
        }
        let fanout = outbound.fanout.as_deref().unwrap();
        assert_eq!(fanout.targets[0].removed, None, "kept");
        assert_eq!(fanout.targets[0].faults, 0);
        let counters = outbound.counters();
        assert_eq!(
            counters.route_failures, 10,
            "once per interval: {counters:?}"
        );
        assert_eq!(counters.endpoint_limits, 10);
        assert_eq!(counters.removed_fault, 0);
    }

    /// Plan 157, point 6: destinations of another family than the shared
    /// endpoint's, or on an endpoint whose address is unknown, are refused
    /// at creation: they could never open, and a required one would hold
    /// the publisher for good.
    #[test]
    fn destinations_of_another_family_are_refused_at_creation() {
        let v4: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let v6: SocketAddr = "[::1]:4000".parse().unwrap();
        for (destinations, family) in [
            (vec![v4], Some(false)),
            (vec![v6], Some(true)),
            (vec![v4], None),
        ] {
            let (mut outbound, _log) = super::super::testing::outbound(
                crate::agents::EndpointId(1),
                karyos_protocol::network::Alias {
                    session_id: 5,
                    stream_id: 6,
                },
                destinations[0],
                karyos_protocol::network::TermParams {
                    term_length: 65_536,
                    initial_term_id: 9,
                    mtu: 1408,
                },
                1,
                false,
            );
            assert!(
                outbound
                    .set_destinations(&destinations, &destinations, family)
                    .is_err(),
                "{destinations:?} on {family:?}"
            );
        }
    }

    /// MD-7: an optional destination stalled at its own edge while the
    /// others take datagrams is slow; it is not when it is required, when
    /// it bounds the strategy edge (`min`, or inside the `tagged` group),
    /// when the publisher is held by a required loss, when the shared
    /// socket pushed back, when nothing advances, or when its last serve
    /// was cut short rather than stalled (design 4.5, 6.5).
    #[test]
    fn only_an_optional_destination_stalled_at_its_own_edge_is_slow() {
        let optional = target(false);
        assert!(slow(&optional, false, false, true));
        assert!(!slow(&target(true), false, false, true), "required");
        let mut bounding = target(false);
        bounding.bounds = true;
        assert!(!slow(&bounding, false, false, true), "min or tagged");
        assert!(!slow(&optional, true, false, true), "held");
        assert!(!slow(&optional, false, true, true), "backpressure");
        assert!(!slow(&optional, false, false, false), "nothing advances");
        let mut busy = target(false);
        busy.stalled = false;
        assert!(!slow(&busy, false, false, true), "cut short, not stalled");
    }
}
