// SPDX-License-Identifier: Apache-2.0

//! The sender agent's first sends (`quantstratum-docs:
//! karyos/design/driver-network-agents.md` §3.1 steps 8 and 11; phase 5c).
//!
//! An [`Outbound`] publication owns one [`SenderRead`] per lane, one TX
//! queue per lane toward the channel destination and a [`LaneSender`] over
//! them. Each cycle after establishment it stages, per lane, committed
//! frames read at the reader's cursor straight into claimed TX frames
//! (copy staging, S2), then serves the lanes under the data DRR. A head the
//! backend reports `Submitted` moves the reader's registered position: on
//! a reliable channel to the lesser of what was submitted and what every
//! bound receiver consumed (SPEC §4 flow control), on an unreliable one to
//! what was submitted.
//!
//! - **Gate.** Every flush passes `DataGate`, private to this module, and
//!   only [`Outbound::serve`] uses it; control traffic has its own gate in
//!   [`super::control`]. An unguarded publication's gate permits every
//!   candidate. A guarded one ([`Outbound::guard`]) runs its guard's
//!   [`GuardGate`] (G-e2): the probe and the exposure both ask it, every
//!   head is staged and reopened through it, its between gates step runs
//!   once a cycle, and it publishes the applied epoch for the close
//!   acknowledgement. A close is local on sockets (guards-and-abort.md,
//!   "Trusted sockets in Phase 2", O-11 and GC-6): nothing more leaves the
//!   sender, first sends and repairs alike; no abort is sent, and the
//!   receivers' images end at their liveness timeout. There is no channel
//!   option asking for a remote abort; one would be refused fail-closed
//!   until decision 5.
//! - **Allocation.** The lane sender and the per-lane records are
//!   allocated when the publication is added. Queues and routes are opened
//!   on the first cycle of an endpoint epoch and handed to the lane sender
//!   with `reopen`, which allocates nothing.
//! - **Resets.** A new endpoint epoch drops what was staged and not
//!   submitted. A reliable lane rewinds its reader to its restart
//!   position, a block boundary between its retention hold and its
//!   registered position that follows the receivers' consumption, and
//!   sends from there again; an
//!   unreliable lane leaves the gap to the receiver's gap policy.
//! - **Flow control** (multicast-flow-control.md; MC-3, MC-7; ACS 15707).
//!   With its receivers' [`Membership`] attached, each lane stages a first
//!   send only while a whole maximum frame from the cursor stays within
//!   the lane's edge ([`Limit::Edge`]): a read cannot be undone, and a join
//!   window is at least the largest datagram, so this never stalls. With
//!   no receiver window ([`Limit::NoReceiverWindow`]) the lane stages
//!   nothing; while a required loss is unresolved ([`Limit::Held`]) no lane
//!   stages, and `admits` holds what was staged, in order. While a
//!   configured required member has not joined ([`Admission::NotJoined`])
//!   no lane stages either. Each lane's highest submitted position is the
//!   membership's `sent_high`; once a required member has joined, a lane's
//!   registered position follows the least position the required members
//!   consumed ([`Membership::retention`]), never above what was submitted.
//!   A receiver is not expected at its SETUP answer: the answer names no
//!   receiver id, so [`Membership::expect`] is not called and a NAK before
//!   the receiver's first SM counts as context only; an optional member's
//!   tombstone clears only after `receiver_timeout` of silence. This needs
//!   no wire change (coordinator, ACS 15872); a schema that carries the
//!   receiver id at the answer would change it.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32};
use std::sync::Arc;

use karyos_io::backend::{
    Authority, BackendEpoch, Commit, Exposure, GateDecision, RouteId, SenderGate, SenderToken,
    TxBackend, TxFrame, TxOptions, TxQueueConfig, TxQueueId, TxReport, TxTicket,
};
use karyos_io::lanes::routes::MAX_ROUTES;
use karyos_io::lanes::{LaneGate, LaneSender, Left, SenderFailure, Staged};
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::lanes::drr::{Budget, DrrConfig};
use karyos_protocol::network::{Alias, Identity, Lanes, MAX_LANES, Nak, NakReply};
use karyos_sys::log_buffer::{
    CanonicalKind, LogBuffer, ReadError, ReadOrigin, ReadOutcome, SenderRead,
};
use karyos_sys::sizing::align_frame;
use karyos_sys::term_bytes::HeapTerms;

use super::net_trace::{TracedLane, traced_frames, traced_frames_per_datagram};
use super::repair::{NakOutcome, RepairConfig, RepairConfigError, RepairPath};
use super::{AgentError, AgentKind, EndpointId};
use crate::embedded::StreamTerms;
use crate::guard_gate::{GateError, GateHead, GateLane, GuardGate};
use crate::membership::{Admission, Limit, Membership};
use crate::repair::admission::Requester;
use crate::repair::scheduler::RepairBudget;
use crate::schedule::{LaneFrame, ScheduleConsumer};
use crate::timed_gate::{LatePolicy, TimedLaneCounters, TimedState};
use karyos_protocol::frame::{Lane, TraceExtension};
use karyos_protocol::trace_hook::{NetPickup, NetworkTraceHook};

/// Membership timer actions per cycle.
const MEMBERSHIP_TIMER_ACTIONS: u32 = 16;

/// A publication's lane reader, over the driver's term backing.
pub type LaneReader<T = HeapTerms> = SenderRead<Arc<LogBuffer<T>>>;

/// Datagrams staged per lane queue at once.
const STAGED_PER_LANE: u16 = 8;

/// The gate of data traffic until phase 7: every candidate is permitted.
/// It records, per lane, the position each submitted head reached.
struct DataGate<'a> {
    lanes: &'a mut [LaneTrack],
    /// A required loss is unresolved: staged heads stay queued (MC-7).
    held: bool,
    /// A guarded publication's gate, which decides every exposure.
    guard: Option<&'a mut GuardGate>,
}

impl SenderGate for DataGate<'_> {
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

impl LaneGate for DataGate<'_> {
    fn admits(&mut self, lane: usize) -> bool {
        // The guard is asked even while held, so a close is seen at once.
        let guarded = self
            .guard
            .as_deref_mut()
            .is_none_or(|guard| guard.admits(lane));
        guarded && !self.held
    }

    // Read by a gate that wraps this one (a timed gate, G7); the lane
    // sender itself does not ask.
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
        let Some(track) = self.lanes.get_mut(lane) else {
            return;
        };
        // Heads leave in staging order.
        let ends = track.ends.pop_front().unwrap_or(false);
        let mut left_at = None;
        match track.staged.pop_front() {
            Some((ticket, next)) if ticket == staged.ticket => {
                match how {
                    Left::Submitted => track.submitted = Some(next),
                    Left::Returned | Left::Unknown => track.unsent = true,
                }
                left_at = Some(next);
            }
            _ => track.mismatched = true,
        }
        // A timed message's last fragment left (ScheduleConsumer::
        // message_left): sent or maybe sent, at the position its message
        // ends, which a reliable lane releases once acknowledged; returned
        // unsent, which an unreliable lane never sends again.
        let sent = matches!(how, Left::Submitted | Left::Unknown);
        track.started = !ends && (sent || track.started);
        if ends {
            match (how, left_at) {
                (Left::Submitted | Left::Unknown, Some(end))
                    if track.left_ends.len() < track.left_ends.capacity() =>
                {
                    track.left_ends.push_back(end);
                }
                _ => {
                    if let Some(returned) = track.returned_ends.checked_add(1) {
                        track.returned_ends = returned;
                    }
                }
            }
        }
    }
}

/// Sender cycles between two reset requests of a publication that still
/// needs a reset: one lost to a full event ring, or ignored while its
/// endpoint was busy, is asked again.
pub const RESET_REQUEST_CYCLES: u64 = 64;

/// One lane's staged heads, in order, and what left.
#[derive(Debug)]
struct LaneTrack {
    /// Ticket and the stream position after it, per staged datagram.
    staged: VecDeque<(TxTicket, u64)>,
    /// The position the last submitted head reached, this call.
    submitted: Option<u64>,
    /// The highest position any submitted head reached: a reliable lane's
    /// registered position follows the receivers' consumption up to it,
    /// also in cycles that submit nothing.
    high: u64,
    /// A head was returned or of unknown exposure, this call.
    unsent: bool,
    /// A head left out of staging order, this call.
    mismatched: bool,
    /// Staging stopped at the receivers' edge and has not staged since: a
    /// wait is counted once, not once per idle cycle.
    waiting: bool,
    /// A timed lane's staged datagrams, in step with `staged`: whether each
    /// carries its message's last fragment.
    ends: VecDeque<bool>,
    /// Where each timed message whose last fragment was sent (or may have
    /// been) this call ends, in order.
    left_ends: VecDeque<u64>,
    /// Timed messages whose last fragment was returned unsent this call.
    returned_ends: u32,
    /// A fragment of the timed message being sent left (submitted, or of
    /// unknown exposure) and its last fragment has not: a reliable reset
    /// counts that message as sent.
    started: bool,
}

/// A timed publication's schedule (`quantstratum-docs:
/// karyos/design/timed-tx.md`; P2.11 PR1, the software route): its timed
/// gate's record and each lane's reader of its schedule ring. A timed lane
/// stages one message per datagram, so each head waits for exactly its own
/// time, and only for it.
#[derive(Debug)]
struct Timed {
    state: TimedState,
    /// Per lane, the consumer of its ring; `None` for a lane with none.
    consumers: Vec<Option<ScheduleConsumer>>,
    /// A reliable publication's lanes, per lane: where each sent timed
    /// message ends, oldest first, until the registered position passes it
    /// and its entry is released (a reset rewinds to that position and
    /// reads the messages above it again). Sized by the lane's ring.
    unacknowledged: Vec<VecDeque<u64>>,
    /// Per lane, whether its consumer's violation was reported to the
    /// conductor (`AgentEvent::ScheduleViolated`, posted once).
    reported: Vec<bool>,
}

/// The counters of one outbound publication; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutboundCounters {
    /// Datagrams staged.
    pub staged: u64,
    /// Canonical PAD or ABORTED records staged.
    pub records: u64,
    /// Bytes of the datagrams and records staged (M2b).
    pub bytes: u64,
    /// Datagrams the backend submitted.
    pub submitted: u64,
    /// Calls in which a head was returned or of unknown exposure.
    pub unsent: u64,
    /// Calls in which a head left out of staging order: a broken
    /// invariant, counted.
    pub mismatched: u64,
    /// Read errors other than `Pending` (see the reader's counters).
    pub read_errors: u64,
    /// Queue setup failures (the partial open is closed again).
    pub queue_failures: u64,
    /// Route setup failures.
    pub route_failures: u64,
    /// Send faults reported for a lane's head.
    pub send_faults: u64,
    /// Invariant, sender or DRR failures.
    pub send_failures: u64,
    /// Committed datagrams the lane sender refused to record.
    pub staged_refused: u64,
    /// Times a lane's staging came to a stop at the receivers' edge or with
    /// no window, counted once per wait (not per cycle).
    pub window_waits: u64,
    /// Cycles held by an unresolved required loss.
    pub held: u64,
    /// Cycles whose first sends waited for a configured required member's
    /// join.
    pub not_joined: u64,
    /// Traced frames not recorded: their EXT did not decode or did not fit
    /// their frame (NT-2).
    pub trace_invalid: u64,
    /// Traced datagrams whose failed commit the lane could not remember
    /// (it holds one range): their frames are never recorded.
    pub trace_unpicked: u64,
    /// A timed lane's frames and its schedule entries disagreed, or its
    /// ring refused a release: a broken invariant, counted; the lane
    /// stages nothing more.
    pub schedule_faults: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

impl OutboundCounters {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64, by: u64) {
        let value = field(self);
        match value.checked_add(by) {
            Some(next) => *value = next,
            None => self.overflowed = true,
        }
    }
}

/// One publication's data path toward its channel destination.
#[derive(Debug)]
pub struct Outbound<T: StreamTerms = HeapTerms> {
    endpoint: EndpointId,
    alias: Alias,
    destination: SocketAddr,
    readers: Vec<LaneReader<T>>,
    reliable: bool,
    /// The largest datagram, the channel MTU.
    mtu: usize,
    /// The largest datagram's aligned charge.
    max_frame: u64,
    /// Its receivers, once attached (multicast-flow-control.md).
    membership: Option<Box<Membership>>,
    /// Whether a receiver's status messages are live: its readers' cells
    /// then count for the publication's connection (SPEC.md §4).
    receivers_live: bool,
    /// The data DRR's configuration, which repair reuses.
    drr: DrrConfig,
    /// A reliable publication's repair path, once enabled.
    repair: Option<Box<RepairPath>>,
    /// A guarded publication's gate (guards-and-abort.md; local close only
    /// on sockets, O-11 and GC-6).
    guard: Option<Box<GuardGate>>,
    sender: LaneSender,
    queues: Vec<TxQueueId>,
    tracks: Vec<LaneTrack>,
    /// The endpoint epoch its queues were opened in.
    opened: Option<BackendEpoch>,
    /// The route its queues were opened on, in that epoch.
    route: Option<RouteId>,
    /// See [`Outbound::needs_reset`].
    needs_reset: bool,
    /// The sender cycle its last reset request was posted in, while it
    /// needs a reset.
    reset_requested: Option<u64>,
    /// Report storage for closing queues (allocated at construction).
    report: TxReport,
    next_token: u64,
    counters: OutboundCounters,
    /// Each lane's open network journal, if any (P2.12 step 3).
    traced: [Option<TracedLane>; 4],
    /// The traced frames of the datagram being staged (allocated at
    /// construction, for the most one datagram can hold).
    picked: Vec<(TraceExtension, u64)>,
    /// The redundant paths of a routed publication ([`Outbound::new_routed`]).
    routed: Option<Box<routed::Routed>>,
    /// Per lane, since when it submitted no DATA nor heartbeat: its idle
    /// heartbeat is due `sender_heartbeat_interval` later (SPEC §6).
    idle_since: [Option<u64>; 4],
    /// Its removal linger, once removing (driver-network-agents.md §7).
    removal: Option<Box<removal::Removal>>,
    /// A timed publication's schedule ([`Outbound::set_timed`]).
    timed: Option<Box<Timed>>,
    /// Its counters' CnC cells (M2b), when the region had room for them:
    /// the sender agent is their only writer.
    cells: Option<crate::agents::AgentCells>,
}

/// The guard of a guarded publication, as the conductor hands it to the
/// sender agent: its guard word, the applied-epoch cell registered with
/// the guard's owner (`EmbeddedDriver::register_guard_sender`), the open
/// epoch its incarnation was admitted under and its rate policy.
#[derive(Clone)]
pub struct GuardSpec {
    /// The guard word, as word 0 (in the driver, a view of the guard's
    /// word in the guard words).
    pub word: Arc<dyn karyos_client::SharedWords>,
    /// The cell this publication's gate alone writes.
    pub cell: Arc<karyos_sys::applied_epoch::AppliedEpoch>,
    /// The open epoch.
    pub epoch: u64,
    /// The publication's rate policy.
    pub rate: Option<karyos_sys::rate_limit::RatePolicy>,
    /// The submission frontier its gate publishes for the walker, which
    /// records each lane's outcomes by it.
    pub frontier: Arc<karyos_sys::submission_frontier::SubmissionFrontier>,
}

impl std::fmt::Debug for GuardSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardSpec")
            .field("epoch", &self.epoch)
            .field("rate", &self.rate)
            .finish_non_exhaustive()
    }
}

/// The timed lane frame of a datagram holding one DATA frame read at
/// `position`, from its header's flags. A header that does not decode is
/// a continuation outside a message, which the consumer refuses.
fn data_frame(bytes: &[u8], position: u64) -> LaneFrame {
    use karyos_sys::frame::Word0;

    let word = bytes
        .get(..8)
        .and_then(|word| <[u8; 8]>::try_from(word).ok())
        .and_then(|raw| Word0::unpack(u64::from_le_bytes(raw)).ok());
    let (begin, end) = word.map_or((false, false), |word| {
        (word.flags().begin(), word.flags().end())
    });
    LaneFrame::Data {
        position,
        begin,
        end,
    }
}

/// The messages a datagram of whole frames starts: its DATA frames with the
/// begin flag. A malformed header ends the count (the read validated every
/// frame, so it does not happen).
fn messages_started(bytes: &[u8]) -> u64 {
    use karyos_sys::frame::{FrameType, Word0};

    let mut count = 0u64;
    let mut at = 0usize;
    while let Some(raw) = bytes
        .get(at..)
        .and_then(|rest| rest.get(..8))
        .and_then(|word| <[u8; 8]>::try_from(word).ok())
    {
        let Ok(word) = Word0::unpack(u64::from_le_bytes(raw)) else {
            break;
        };
        let Some(length) = u32::try_from(word.frame_length())
            .ok()
            .and_then(|length| align_frame(length).ok())
            .and_then(|aligned| usize::try_from(aligned).ok())
            .filter(|aligned| *aligned >= 32)
        else {
            break;
        };
        let data = FrameType::try_from_code(word.frame_type_code()) == Ok(FrameType::Data);
        if data && word.flags().begin() {
            // At most one per 32 bytes of the datagram.
            let Some(next) = count.checked_add(1) else {
                break;
            };
            count = next;
        }
        let Some(next) = at.checked_add(length) else {
            break;
        };
        at = next;
    }
    count
}

/// Why an outbound publication was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundError {
    /// No reader, more than four, or quanta of another count.
    Lanes,
    /// The DRR refused the quanta for this MTU.
    Quanta,
    /// The MTU is zero or does not fit a datagram.
    Mtu,
    /// No path, more than four, or two paths on one endpoint: a routed
    /// publication finds each route's TX half by its endpoint.
    Routes,
}

/// A sender that goes leaves its readers' cells not counting for the
/// connection before they are released (SPEC.md §4): the publication is
/// unconnected from then on, whatever its receivers did.
impl<T: StreamTerms> Drop for Outbound<T> {
    fn drop(&mut self) {
        for reader in &self.readers {
            let _ = reader.set_receivers_live(false);
        }
    }
}

impl<T: StreamTerms> Outbound<T> {
    /// The data path of the publication `alias` on `endpoint` toward
    /// `destination`, reading `readers` (one per lane, in lane order) into
    /// datagrams of at most `mtu` bytes, served with `quanta`. Allocates
    /// everything its cycles use.
    ///
    /// # Errors
    ///
    /// [`OutboundError`].
    pub fn new(
        endpoint: EndpointId,
        alias: Alias,
        destination: SocketAddr,
        readers: Vec<LaneReader<T>>,
        quanta: &Lanes<u64>,
        mtu: u32,
        reliable: bool,
    ) -> Result<Self, OutboundError> {
        let lanes = readers.len();
        if lanes == 0 || lanes != quanta.as_slice().len() {
            return Err(OutboundError::Lanes);
        }
        let max_charge = align_frame(mtu).map_err(|_| OutboundError::Mtu)?;
        let config = DrrConfig::new(quanta.as_slice(), u64::from(max_charge))
            .map_err(|_| OutboundError::Quanta)?;
        // Placeholders until the first cycle opens the real queues.
        let placeholder = TxQueueId::new(BackendEpoch::FIRST, u16::MAX, NonZeroU32::MAX);
        let queues = vec![placeholder; lanes];
        let bound = usize::from(STAGED_PER_LANE);
        let drr = config;
        let sender = LaneSender::new(config, &queues, bound).map_err(|_| OutboundError::Lanes)?;
        let tracks = (0..lanes)
            .map(|_| LaneTrack {
                staged: VecDeque::with_capacity(bound),
                submitted: None,
                high: 0,
                unsent: false,
                mismatched: false,
                waiting: false,
                ends: VecDeque::with_capacity(bound),
                left_ends: VecDeque::with_capacity(bound),
                returned_ends: 0,
                started: false,
            })
            .collect();
        Ok(Self {
            endpoint,
            alias,
            destination,
            readers,
            reliable,
            receivers_live: false,
            mtu: usize::try_from(mtu).map_err(|_| OutboundError::Mtu)?,
            max_frame: u64::from(max_charge),
            membership: None,
            drr,
            repair: None,
            guard: None,
            sender,
            queues,
            tracks,
            opened: None,
            needs_reset: false,
            reset_requested: None,
            report: TxReport::new(),
            next_token: 1,
            counters: OutboundCounters::default(),
            traced: [None; 4],
            picked: Vec::with_capacity(
                usize::try_from(mtu)
                    .ok()
                    .and_then(traced_frames_per_datagram)
                    .ok_or(OutboundError::Mtu)?,
            ),
            routed: None,
            route: None,
            idle_since: [None; 4],
            removal: None,
            timed: None,
            cells: None,
        })
    }

    /// With its counters' CnC cells, in `PUBLICATION_CELLS` order (M2b).
    pub(crate) fn set_cells(&mut self, cells: crate::agents::AgentCells) {
        self.cells = Some(cells);
    }

    /// Hands its cells back, for the conductor to free (M2b).
    pub(crate) fn take_cells(&mut self) -> Option<crate::agents::AgentCells> {
        self.cells.take()
    }

    /// Stores its counts that changed into its CnC cells, at the end of
    /// the sender's duty cycle (M2b).
    pub(crate) fn publish_cells(&mut self) {
        let Some(cells) = self.cells.as_mut() else {
            return;
        };
        let counters = &self.counters;
        let repair = self
            .repair
            .as_deref()
            .map(RepairPath::counts)
            .unwrap_or_default();
        // Every NAK the repair path took in, whatever became of it.
        let naks = [repair.jobs_joined, repair.lingering, repair.jobs_full]
            .into_iter()
            .try_fold(repair.jobs_created, u64::checked_add);
        let frames = counters.staged.checked_add(counters.records);
        // A sum past `u64::MAX` keeps the last value stored; no allocation
        // on the duty cycle.
        let counts = [frames, Some(counters.bytes), Some(repair.submitted), naks];
        let mut values = [0; crate::agents::PUBLICATION_CELLS.len()];
        for ((value, count), stored) in values.iter_mut().zip(counts).zip(cells.stored()) {
            *value = count.unwrap_or(*stored);
        }
        cells.publish(&values);
    }

    /// The endpoint it sends on.
    #[must_use]
    pub fn endpoint(&self) -> EndpointId {
        self.endpoint
    }

    /// Its alias.
    #[must_use]
    pub fn alias(&self) -> Alias {
        self.alias
    }

    /// Whether it is reliable.
    #[must_use]
    pub fn reliable(&self) -> bool {
        self.reliable
    }

    /// Its channel destination.
    #[must_use]
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> OutboundCounters {
        self.counters
    }

    /// The readers, in lane order.
    #[must_use]
    pub fn readers(&self) -> &[LaneReader<T>] {
        &self.readers
    }

    /// The readers, mutable (tests).
    #[cfg(test)]
    pub(crate) fn readers_mut(&mut self) -> &mut [LaneReader<T>] {
        &mut self.readers
    }

    /// Attaches its receivers' membership: from then on first sends follow
    /// their limits (control path). Each lane's `sent_high` starts at its
    /// reader's cursor, the join point receivers are answered with: a
    /// reader that joined above 0 never sends below it, and a receiver's
    /// first SM reports at least its join.
    pub fn attach_membership(&mut self, mut membership: Box<Membership>) {
        for (lane, (track, reader)) in self.tracks.iter_mut().zip(&self.readers).enumerate() {
            track.high = track.high.max(reader.position());
            if let Some(lane) = u8::try_from(lane).ok().and_then(|l| Lane::try_new(l).ok()) {
                let _ = membership.advance_sent(lane, track.high);
            }
        }
        self.membership = Some(membership);
    }

    /// Enables its repair path (a reliable publication of `term_length`
    /// terms, incarnation `identity`; control path, allocates).
    ///
    /// # Errors
    ///
    /// [`RepairConfigError`].
    pub fn enable_repair(
        &mut self,
        config: &RepairConfig,
        term_length: u32,
        identity: Identity,
    ) -> Result<(), RepairConfigError> {
        self.repair = Some(Box::new(RepairPath::new(
            config,
            self.drr,
            self.mtu,
            (term_length, self.alias, identity),
        )?));
        Ok(())
    }

    /// Guards it with `spec` at `now` (control path, allocates): from then
    /// on its guard's gate decides every exposure, and a close stops every
    /// submission, first sends and repairs alike. Nothing is sent to the
    /// receivers: on sockets a close is local (guards-and-abort.md,
    /// "Trusted sockets in Phase 2", O-11 and GC-6).
    ///
    /// # Errors
    ///
    /// [`GateError`].
    pub fn guard(&mut self, spec: GuardSpec, now: u64) -> Result<(), GateError> {
        let frontier = spec.frontier;
        let lanes: Vec<GateLane> = (0..self.readers.len())
            .filter_map(|lane| u8::try_from(lane).ok().and_then(|l| Lane::try_new(l).ok()))
            .map(|lane| GateLane {
                lane,
                epoch: spec.epoch,
                bound: usize::from(STAGED_PER_LANE),
            })
            .collect();
        let gate = match self.routed.as_deref() {
            Some(routed) => GuardGate::new_routed(
                spec.word,
                spec.cell,
                &lanes,
                routed.sender(),
                spec.rate,
                self.max_frame,
                now,
            )?,
            None => GuardGate::new(
                spec.word,
                spec.cell,
                &lanes,
                &self.sender,
                spec.rate,
                self.max_frame,
                now,
            )?,
        };
        let mut gate = gate;
        gate.set_frontier(frontier);
        self.guard = Some(Box::new(gate));
        Ok(())
    }

    /// Its removal is final for its guard's gate (drained or given up):
    /// the walker records what never left (control path).
    pub(crate) fn finish_removed(&mut self) {
        if let Some(guard) = self.guard.as_deref_mut() {
            guard.finish_removed();
        }
    }

    /// Returns, through the gate, the staged items of every lane its guard
    /// aborted: such a lane is never flushed again, so an item the kernel
    /// refused before the close (would block) would stay in flight and the
    /// close acknowledgement would never drain. The applied epoch is then
    /// published again with the work drained.
    fn cancel_aborted<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>) {
        let Self {
            guard: Some(guard),
            sender,
            tracks,
            readers,
            counters,
            timed,
            ..
        } = self
        else {
            return;
        };
        let mut cancelled = false;
        for lane in 0..readers.len() {
            if !LaneGate::aborting(&**guard, lane) || sender.pending(lane).unwrap_or(0) == 0 {
                continue;
            }
            let mut gate = DataGate {
                lanes: tracks,
                held: false,
                guard: Some(&mut **guard),
            };
            // A timed lane's heads leave its timed record too, as dropped.
            let cancelled_now = match timed.as_deref_mut() {
                Some(timed) => sender.cancel(tx, lane, &mut timed.state.view(&mut gate)),
                None => sender.cancel(tx, lane, &mut gate),
            };
            match cancelled_now {
                Ok(_) => cancelled = true,
                Err(_) => counters.bump(|c| &mut c.queue_failures, 1),
            }
        }
        if cancelled {
            guard.between_gates();
        }
    }

    /// The guard's between gates step at `now`, for a publication not
    /// served this cycle (not established yet): a close applies and its
    /// applied epoch is published all the same.
    pub fn guard_tick(&mut self, now: u64) {
        if let Some(guard) = self.guard.as_deref_mut() {
            guard.set_now(now);
            guard.between_gates();
        }
    }

    /// Its guard's gate, if guarded.
    #[must_use]
    pub fn guard_gate(&self) -> Option<&GuardGate> {
        self.guard.as_deref()
    }

    /// Its repair path, if enabled.
    #[must_use]
    pub fn repair(&self) -> Option<&RepairPath> {
        self.repair.as_deref()
    }

    /// Admits `nak` from a receiver bound to this publication, whose state
    /// on the lane is `requester`, at `now`. A publication with no repair
    /// path drops it.
    pub fn nak(&mut self, nak: &Nak, requester: Requester, now: u64) -> NakOutcome {
        self.nak_on(nak, requester, (0, true), now)
    }

    /// [`Outbound::nak`] for a NAK that arrived on route `route` (0 on one
    /// path). One from a `validated` receiver id is recorded to absorb its
    /// copies on other routes (RP-11); one whose receiver id is not
    /// validated yet takes no part in absorption.
    pub fn nak_on(
        &mut self,
        nak: &Nak,
        requester: Requester,
        (route, validated): (usize, bool),
        now: u64,
    ) -> NakOutcome {
        let lane = usize::from(nak.range.lane.get());
        let lanes = u8::try_from(self.readers.len()).unwrap_or(u8::MAX);
        let sent_high = self.tracks.get(lane).map_or(0, |track| track.high);
        match self.repair.as_deref_mut() {
            Some(repair) => repair.nak_on(
                nak,
                (requester, route, validated),
                self.readers.get(lane),
                sent_high,
                lanes,
                now,
            ),
            None => NakOutcome::Dropped,
        }
    }

    /// Whether `nak`, from a bound receiver, on route `route` at `now`, is
    /// a copy of one another route carried within `path_skew_window`: it
    /// is then absorbed, counted, and spends no NAK budget (RP-11).
    pub fn absorbs(&mut self, nak: &Nak, route: usize, now: u64) -> bool {
        self.repair
            .as_deref_mut()
            .is_some_and(|repair| repair.absorbs(nak, route, now))
    }

    /// The route `endpoint` serves: its index on a routed publication, 0
    /// on one path or for an endpoint it does not use.
    #[must_use]
    pub fn route_of(&self, endpoint: EndpointId) -> usize {
        self.routed
            .as_deref()
            .and_then(|routed| routed.endpoints().position(|held| held == endpoint))
            .unwrap_or(0)
    }

    /// Serves its repairs on `tx` within `budget`, which it spends, at
    /// `now`; returns the heads submitted. Step 8 ERRs wait for
    /// [`Outbound::drain_repair_replies`].
    pub fn serve_repair<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        budget: &mut RepairBudget,
        now: u64,
    ) -> u32 {
        // Over redundant paths `tx` is the founding route's half, as one
        // route of [`Outbound::serve_repair_routes`], which serves every
        // live route (RP-11).
        let open = match self.routed.as_deref() {
            Some(routed) => routed.repair_live(0, tx.capabilities().epoch),
            None => self.open(tx),
        };
        if !open {
            return 0;
        }
        self.serve_repair_with(&mut [Some(tx)], budget, now)
    }

    /// Serves its repairs on `routes`, the TX halves of its live routes by
    /// route (one path: its own), within `budget`, which it spends, at
    /// `now`; returns the heads submitted.
    pub(super) fn serve_repair_with<O: SocketOps>(
        &mut self,
        routes: &mut [Option<&mut SocketsTx<O>>],
        budget: &mut RepairBudget,
        now: u64,
    ) -> u32 {
        if self.repair.is_none() {
            return 0;
        }
        let mut sent_high = [0u64; MAX_LANES];
        for (high, track) in sent_high.iter_mut().zip(&self.tracks) {
            *high = track.high;
        }
        // A guard's close stops repairs too: they are submissions (GC-6).
        // The word is loaded now, so a close since the last cycle's first
        // sends holds every repair of this one.
        let mut closed = [false; MAX_LANES];
        if let Some(guard) = self.guard.as_deref_mut() {
            guard.set_now(now);
            guard.between_gates();
            for (lane, closed) in closed.iter_mut().enumerate() {
                *closed = LaneGate::aborting(&*guard, lane);
            }
        }
        let Some(repair) = self.repair.as_deref_mut() else {
            return 0;
        };
        let report = repair.serve_routes(
            routes,
            &mut self.readers,
            (&sent_high, &closed),
            budget,
            now,
        );
        let frames = report
            .lanes
            .iter()
            .try_fold(0u64, |sum, lane| sum.checked_add(lane.served_frames));
        // At most the cycle's word 0 loads, a u32.
        frames
            .and_then(|frames| u32::try_from(frames).ok())
            .unwrap_or(u32::MAX)
    }

    /// Hands each step 8 ERR waiting to `send`.
    pub fn drain_repair_replies(&mut self, mut send: impl FnMut(&NakReply)) {
        self.drain_repair_replies_on(|reply, _| send(reply));
    }

    /// [`Outbound::drain_repair_replies`] with the endpoint each ERR goes
    /// on: the route its requester asked on (RP-11), the publication's own
    /// endpoint on one path.
    pub fn drain_repair_replies_on(&mut self, mut send: impl FnMut(&NakReply, EndpointId)) {
        let founding = self.endpoint;
        let mut endpoints = [founding; MAX_ROUTES];
        if let Some(routed) = self.routed.as_deref() {
            for (slot, endpoint) in endpoints.iter_mut().zip(routed.endpoints()) {
                *slot = endpoint;
            }
        }
        if let Some(repair) = self.repair.as_deref_mut() {
            repair.drain_replies_on(|reply, route| {
                send(reply, endpoints.get(route).copied().unwrap_or(founding));
            });
        }
    }

    /// Its receivers' membership, if attached.
    pub fn membership_mut(&mut self) -> Option<&mut Membership> {
        self.membership.as_deref_mut()
    }

    /// Its receivers' membership, if attached.
    #[must_use]
    pub fn membership(&self) -> Option<&Membership> {
        self.membership.as_deref()
    }

    /// Records whether a receiver's status messages are live and, on a
    /// change only, makes its readers' cells count for the publication's
    /// connection or not (SPEC.md §4). Returns whether it changed.
    pub fn set_receivers_live(&mut self, live: bool) -> bool {
        if self.receivers_live == live {
            return false;
        }
        self.receivers_live = live;
        for reader in &self.readers {
            let _ = reader.set_receivers_live(live);
        }
        true
    }

    /// Whether a receiver's status messages were live at the last cycle.
    #[must_use]
    pub fn receivers_live(&self) -> bool {
        self.receivers_live
    }

    /// Whether its membership has a live member at `now` (`false` with no
    /// membership attached).
    #[must_use]
    pub fn connected(&self, now: u64) -> bool {
        self.membership
            .as_deref()
            .is_some_and(|membership| membership.connected(now))
    }

    /// The largest datagram's aligned charge: the least join window.
    #[must_use]
    pub fn max_frame(&self) -> u64 {
        self.max_frame
    }

    /// Each lane's join point for an answer now: where its next read
    /// starts.
    #[must_use]
    pub fn joins(&self) -> Option<Lanes<u64>> {
        let mut joins = [0u64; 4];
        for (join, reader) in joins.iter_mut().zip(&self.readers) {
            *join = reader.position();
        }
        Lanes::new(joins.get(..self.readers.len())?).ok()
    }

    /// Starts tracing `lane` for `publication`'s journal `number` from the
    /// lane's next position, which it returns (the start fact, §5). `None`
    /// for a lane it does not have or one already traced.
    pub(crate) fn trace(
        &mut self,
        lane: usize,
        publication: karyos_protocol::trace_hook::PublicationIdentity,
        number: u64,
    ) -> Option<u64> {
        let start = self.readers.get(lane)?.position();
        let slot = self.traced.get_mut(lane).filter(|slot| slot.is_none())?;
        *slot = Some(TracedLane {
            publication,
            number,
            start,
            boundary: start,
            unpicked: None,
        });
        Some(start)
    }

    /// Stops tracing `lane` if journal `number` observes it, and returns
    /// its facts.
    pub(crate) fn untrace(&mut self, lane: usize, number: u64) -> Option<TracedLane> {
        let slot = self.traced.get_mut(lane)?;
        if slot.is_some_and(|traced| traced.number == number) {
            slot.take()
        } else {
            None
        }
    }

    /// Stops tracing every lane, handing each one's lane and facts to
    /// `closed`.
    pub(crate) fn untrace_all(&mut self, mut closed: impl FnMut(usize, TracedLane)) {
        for (lane, slot) in self.traced.iter_mut().enumerate() {
            if let Some(traced) = slot.take() {
                closed(lane, traced);
            }
        }
    }

    /// Opens the route and the lane queues on `tx` for its current epoch,
    /// once per epoch; a new epoch drops what the old one staged.
    fn open<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>) -> bool {
        let epoch = tx.capabilities().epoch;
        if self.opened == Some(epoch) {
            return true;
        }
        let Ok(route) = tx.add_route(self.destination) else {
            self.counters.bump(|c| &mut c.route_failures, 1);
            return false;
        };
        // All or nothing: a partial open is closed again, so a failing
        // endpoint does not leak a route and queues every cycle.
        for lane in 0..self.queues.len() {
            let opened = tx.open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: NonZeroU16::new(STAGED_PER_LANE).unwrap_or(NonZeroU16::MIN),
            });
            let Ok(opened) = opened else {
                self.counters.bump(|c| &mut c.queue_failures, 1);
                for queue in self.queues.iter().take(lane) {
                    let _ = tx.close_queue(*queue, &mut self.report);
                    while self.report.pop_front().is_some() {}
                }
                let _ = tx.remove_route(route);
                return false;
            };
            if let Some(queue) = self.queues.get_mut(lane) {
                *queue = opened;
            }
        }
        // A reliable lane reads again what the reset returned (below).
        let rewound = self.opened.is_some() && self.reliable;
        for (lane, queue) in self.queues.iter().enumerate() {
            // A guarded lane reopens through its gate, which refunds what
            // the old queue held.
            match self.guard.as_deref_mut() {
                Some(guard) => guard.reopen(&mut self.sender, lane, *queue, rewound),
                None => self.sender.reopen(lane, *queue),
            }
        }
        // The repair queue, on the same route and outside the lane sender:
        // without it the publication sends first sends only, and its jobs
        // wait (their submissions report the queue broken).
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
            repair.reopened(queue);
        }
        // A timed lane's heads the reset returned. An unreliable lane sends
        // none of them again, so a message whose last fragment was among
        // them is done, and each is counted dropped. A reliable one reads
        // again from its restart position, below which every entry is
        // released, so its consumer rewinds to its oldest entry not
        // released, and nothing is done or dropped. Only the messages that
        // left (in whole, or in part) are resent at once; the ones only
        // read keep their time.
        let rewinding = self.opened.is_some() && self.reliable;
        if let Some(timed) = self.timed.as_deref_mut() {
            for (lane, track) in self.tracks.iter_mut().enumerate() {
                let _ = timed.state.forget(lane, !rewinding);
                if rewinding {
                    track.ends.clear();
                    let unacknowledged =
                        timed
                            .unacknowledged
                            .get_mut(lane)
                            .map_or(0, |unacknowledged| {
                                let sent = unacknowledged.len();
                                unacknowledged.clear();
                                sent
                            });
                    let sent = unacknowledged
                        .checked_add(track.left_ends.len())
                        .and_then(|sent| sent.checked_add(usize::from(track.started)));
                    track.left_ends.clear();
                    track.returned_ends = 0;
                    track.started = false;
                    if let Some(Some(consumer)) = timed.consumers.get_mut(lane) {
                        let rewound = sent.map(|sent| consumer.rewind(sent));
                        if !matches!(rewound, Some(Ok(()))) {
                            self.counters.bump(|c| &mut c.schedule_faults, 1);
                        }
                    }
                    continue;
                }
                let ended = track.ends.iter().filter(|ends| **ends).count();
                track.ends.clear();
                let ring = self
                    .readers
                    .get(lane)
                    .and_then(|reader| reader.subscription().buffer().schedule_ring());
                if let (Some(Some(consumer)), Some(ring)) = (timed.consumers.get_mut(lane), ring) {
                    for _ in 0..ended {
                        if consumer.message_left(ring).is_err() {
                            self.counters.bump(|c| &mut c.schedule_faults, 1);
                        }
                    }
                }
            }
        }
        for track in &mut self.tracks {
            track.staged.clear();
        }
        // A reset returned what was staged and not submitted. A reliable
        // lane reads it again from its restart position (a block
        // boundary, never below the floor); an unreliable one leaves the
        // gap to the receiver's gap policy (LaneSender::reopen).
        if self.opened.is_some() && self.reliable {
            for reader in &mut self.readers {
                // A faulted reader cannot rewind: its lane is already ended
                // (C-9) and its reads keep failing.
                let _ = reader.rewind();
            }
        }
        self.opened = Some(epoch);
        self.route = Some(route);
        self.needs_reset = false;
        self.reset_requested = None;
        true
    }

    /// What it holds open on its endpoints, given to `held` once per
    /// endpoint: the route, the lane queues and the repair queue it opened
    /// there, in that endpoint's epoch. A removed publication's sender closes
    /// them at its next duty (driver-network-agents.md §7: the sender drops
    /// its queues).
    pub(crate) fn opened_resources(&self, mut held: impl FnMut(Opened)) {
        if let Some(routed) = self.routed.as_deref() {
            routed.opened_resources(self.repair.as_deref(), &mut held);
            return;
        }
        let (Some(epoch), Some(route)) = (self.opened, self.route) else {
            return;
        };
        let mut queues = [None; OPENED_QUEUES];
        for (slot, queue) in queues.iter_mut().zip(&self.queues) {
            *slot = Some(*queue);
        }
        if let Some(slot) = queues.last_mut() {
            *slot = self.repair.as_deref().and_then(|repair| repair.queue_on(0));
        }
        held(Opened {
            endpoint: self.endpoint,
            epoch,
            route,
            queues,
        });
    }

    /// The first lane whose publisher breached its schedule ring's
    /// protocol and that was not reported yet (`quantstratum-docs:
    /// karyos/design/timed-tx.md`, section 11, TT-6).
    pub(crate) fn violation_unreported(&self) -> Option<usize> {
        let timed = self.timed.as_deref()?;
        timed
            .consumers
            .iter()
            .zip(&timed.reported)
            .position(|(consumer, reported)| {
                !*reported && consumer.as_ref().is_some_and(ScheduleConsumer::violated)
            })
    }

    /// `lane`'s violation was reported: it is not reported again.
    pub(crate) fn violation_reported(&mut self, lane: usize) {
        if let Some(reported) = self
            .timed
            .as_deref_mut()
            .and_then(|timed| timed.reported.get_mut(lane))
        {
            *reported = true;
        }
    }

    /// Makes its lanes timed (control path, before it is posted): each lane
    /// whose buffer has a schedule ring holds every head until its
    /// message's requested time, under `policies[lane]` (its tolerance),
    /// counting into `counters[lane]`; the gate's clock starts at `now`,
    /// the network clock.
    ///
    /// # Errors
    ///
    /// [`OutboundError::Lanes`] for a lane's ring that is not one.
    pub(crate) fn set_timed(
        &mut self,
        policies: &[LatePolicy],
        counters: Vec<Option<Arc<TimedLaneCounters>>>,
        now: u64,
    ) -> Result<(), OutboundError> {
        let mut consumers = Vec::with_capacity(self.readers.len());
        for (lane, reader) in self.readers.iter().enumerate() {
            let max_horizon = policies.get(lane).copied().unwrap_or_default().max_horizon;
            let consumer = match reader.subscription().buffer().schedule_ring() {
                Some(ring) => Some(
                    ScheduleConsumer::new(ring, max_horizon).map_err(|_| OutboundError::Lanes)?,
                ),
                None => None,
            };
            consumers.push(consumer);
        }
        let mut state = TimedState::new(policies, usize::from(STAGED_PER_LANE), now);
        state.set_resends_returned(self.reliable);
        for (lane, cells) in counters.into_iter().enumerate() {
            if let Some(cells) = cells {
                state.attach_counters(lane, cells);
            }
        }
        let mut unacknowledged = Vec::with_capacity(self.readers.len());
        for reader in &self.readers {
            let buffer = reader.subscription().buffer();
            let capacity = match (self.reliable, buffer.schedule_ring()) {
                (true, Some(_)) => usize::try_from(buffer.config().schedule_capacity)
                    .map_err(|_| OutboundError::Lanes)?,
                _ => 0,
            };
            unacknowledged.push(VecDeque::with_capacity(capacity));
        }
        let reported = vec![false; consumers.len()];
        self.timed = Some(Box::new(Timed {
            state,
            consumers,
            unacknowledged,
            reported,
        }));
        Ok(())
    }

    /// What its timed gate counted, if it is timed (tests).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn timed_counts(&self) -> Option<crate::timed_gate::TimedCounts> {
        self.timed.as_deref().map(|timed| timed.state.counts())
    }

    /// One cycle: stage what each lane has committed, serve the lanes
    /// within `budget`, and move each reader's registered position.
    /// `consumption` gives, per lane, the least position every bound
    /// receiver consumed: a reliable lane's restart position follows it
    /// (it bounds nothing). Returns the work done.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub fn serve<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        budget: Budget,
        consumption: Option<&[u64]>,
        now: u64,
    ) -> Result<u32, AgentError> {
        self.serve_traced(tx, budget, consumption, now, None)
    }

    /// [`Outbound::serve`] with the sender's network trace `hook`, which
    /// records a `SenderPickup` for each traced frame of a traced lane.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub(crate) fn serve_traced<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        budget: Budget,
        consumption: Option<&[u64]>,
        now: u64,
        mut hook: Option<&mut (dyn NetworkTraceHook + 'static)>,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        if !self.open(tx) {
            // No queues this cycle, but a guard close still applies.
            self.guard_tick(now);
            return Ok(0);
        }
        let (limits, held) = self.limits(now);
        // The schedule checks read the sender's clock (timed-tx.md section
        // 11, TT-6).
        if let Some(timed) = self.timed.as_deref_mut() {
            for consumer in timed.consumers.iter_mut().flatten() {
                consumer.set_now(now);
            }
        }
        let mut work = 0u32;
        for lane in 0..self.readers.len() {
            let limit = limits.get(lane).copied().unwrap_or(Limit::Held);
            work = work
                .checked_add(self.stage(tx, lane, limit, hook.as_deref_mut())?)
                .ok_or(overflow.clone())?;
        }
        if let Some(guard) = self.guard.as_deref_mut() {
            guard.set_now(now);
        }
        let mut gate = DataGate {
            lanes: &mut self.tracks,
            held,
            guard: self.guard.as_deref_mut(),
        };
        // A timed publication's heads wait for their time over the data
        // gate, which decides them once due (timed-tx.md section 4).
        let report = match self.timed.as_deref_mut() {
            Some(timed) => {
                timed.state.set_now(now);
                self.sender
                    .serve(tx, &mut timed.state.view(&mut gate), budget)
            }
            None => self.sender.serve(tx, &mut gate, budget),
        };
        // Once a cycle, even with nothing flushed, so a close becomes
        // effective with no pending traffic (DN 3.1 step 10).
        if let Some(guard) = self.guard.as_deref_mut() {
            guard.between_gates();
        }
        self.cancel_aborted(tx);
        // After the cancel, whose returned heads end their messages too.
        self.release_ended();
        self.handle_failure(tx, report.failure);
        for (track, idle) in self.tracks.iter_mut().zip(&mut self.idle_since) {
            if std::mem::take(&mut track.unsent) {
                self.counters.bump(|c| &mut c.unsent, 1);
            }
            if std::mem::take(&mut track.mismatched) {
                self.counters.bump(|c| &mut c.mismatched, 1);
            }
            if let Some(submitted) = track.submitted.take() {
                self.counters.bump(|c| &mut c.submitted, 1);
                track.high = track.high.max(submitted);
                // DATA left: the lane's idle heartbeat waits again.
                *idle = Some(now);
            }
        }
        self.advance_registered(consumption);
        self.release_acknowledged();
        Ok(work)
    }

    /// A timed message of `lane` whose last fragment never reached the
    /// queue: its own schedule entry, the newest read, is done; older
    /// messages still queued keep theirs.
    fn timed_message_lost(&mut self, lane: usize) {
        let ring = self
            .readers
            .get(lane)
            .and_then(|reader| reader.subscription().buffer().schedule_ring());
        let consumer = self
            .timed
            .as_deref_mut()
            .and_then(|timed| timed.consumers.get_mut(lane))
            .and_then(Option::as_mut);
        if let (Some(ring), Some(consumer)) = (ring, consumer)
            && consumer.message_lost(ring).is_err()
        {
            self.counters.bump(|c| &mut c.schedule_faults, 1);
        }
    }

    /// Frees the schedule entry of every timed message whose last fragment
    /// left this cycle, in order.
    fn release_ended(&mut self) {
        let Some(timed) = self.timed.as_deref_mut() else {
            return;
        };
        for (lane, track) in self.tracks.iter_mut().enumerate() {
            let returned = std::mem::take(&mut track.returned_ends);
            let ring = self
                .readers
                .get(lane)
                .and_then(|reader| reader.subscription().buffer().schedule_ring());
            let (Some(Some(consumer)), Some(ring)) = (timed.consumers.get_mut(lane), ring) else {
                track.left_ends.clear();
                continue;
            };
            // A reliable lane holds a sent message's entry until it is
            // acknowledged ([`Outbound::release_acknowledged`]); a message
            // returned unsent is read again after the reset.
            if self.reliable {
                if let Some(unacknowledged) = timed.unacknowledged.get_mut(lane) {
                    while let Some(end) = track.left_ends.pop_front() {
                        if unacknowledged.len() < unacknowledged.capacity() {
                            unacknowledged.push_back(end);
                        } else {
                            self.counters.bump(|c| &mut c.schedule_faults, 1);
                        }
                    }
                }
                continue;
            }
            let ended = track.left_ends.len();
            track.left_ends.clear();
            for _ in (0..ended).map(drop).chain((0..returned).map(drop)) {
                if consumer.message_left(ring).is_err() {
                    self.counters.bump(|c| &mut c.schedule_faults, 1);
                }
            }
        }
    }

    /// Frees, in order, the entry of every timed message of a reliable lane
    /// whose end its restart position passed: no reset reads it again.
    fn release_acknowledged(&mut self) {
        let Some(timed) = self.timed.as_deref_mut() else {
            return;
        };
        if !self.reliable {
            return;
        }
        for (lane, reader) in self.readers.iter().enumerate() {
            let acknowledged = reader.restart_position();
            let ring = reader.subscription().buffer().schedule_ring();
            let (Some(unacknowledged), Some(Some(consumer)), Some(ring)) = (
                timed.unacknowledged.get_mut(lane),
                timed.consumers.get_mut(lane),
                ring,
            ) else {
                continue;
            };
            while unacknowledged
                .front()
                .is_some_and(|end| *end <= acknowledged)
            {
                let _ = unacknowledged.pop_front();
                if consumer.message_left(ring).is_err() {
                    self.counters.bump(|c| &mut c.schedule_faults, 1);
                }
            }
        }
    }

    /// The receivers' limits this cycle, and whether a required loss holds
    /// every lane. With no membership attached, first sends are not gated.
    /// A lost required member holds every lane, staged heads included
    /// (MC-7); one not yet joined holds new staging only.
    fn limits(&mut self, now: u64) -> ([Limit; MAX_LANES], bool) {
        let mut limits = [Limit::Edge(u64::MAX); MAX_LANES];
        let mut admission = Admission::Open;
        if let Some(membership) = self.membership.as_deref_mut() {
            // Its events (joins, losses) are not drained yet, deliberately:
            // the conductor that reports them is not wired to the agents.
            // The queue is bounded; overflow is counted (`events_dropped`).
            let _ = membership.timers(now, MEMBERSHIP_TIMER_ACTIONS);
            admission = membership.admission(now);
            for (lane, limit) in limits.iter_mut().enumerate().take(self.readers.len()) {
                if let Some(lane) = u8::try_from(lane).ok().and_then(|l| Lane::try_new(l).ok()) {
                    *limit = membership.limit(lane, now);
                }
            }
        }
        let held = admission == Admission::LostRequired;
        match admission {
            Admission::Open => {}
            Admission::LostRequired => self.counters.bump(|c| &mut c.held, 1),
            Admission::NotJoined => {
                self.counters.bump(|c| &mut c.not_joined, 1);
                limits = [Limit::Held; MAX_LANES];
            }
        }
        (limits, held)
    }

    /// Moves each lane's registered position from its sent frontier, the
    /// publication's limit: to the lesser of what was submitted and what
    /// the required receivers consumed, or to what was submitted with none
    /// (`Membership::retention`); and on a reliable channel raises the
    /// lane's retention hold to `sent - retransmit_window`, lowered by the
    /// same required receivers (SPEC §4, §6; quantstratum-docs:
    /// karyos/design/retention-floor-optional-receivers.md). Optional
    /// receivers bound neither: under `max` a slow one no longer holds the
    /// publisher, and its holes below the floor are unrecoverable.
    /// `consumption`, every bound receiver's least, optional ones included,
    /// only moves a reliable lane's restart position, where a reset reads
    /// again (`SenderRead::restart_at`), so a reset still resends at once
    /// what they had not consumed. Tells the membership its sent bound.
    fn advance_registered(&mut self, consumption: Option<&[u64]>) {
        let retransmit_window = self
            .repair
            .as_deref()
            .filter(|_| self.reliable)
            .map(|repair| u64::from(repair.retransmit_window()));
        for (lane, (track, reader)) in self.tracks.iter_mut().zip(&mut self.readers).enumerate() {
            let submitted = track.high;
            // The membership's sent frontier (one path: `sent_high`), and
            // the required members' retention bound once one has joined.
            let mut retention = None;
            if let (Some(membership), Some(lane)) = (
                self.membership.as_deref_mut(),
                u8::try_from(lane).ok().and_then(|l| Lane::try_new(l).ok()),
            ) {
                let _ = membership.advance_sent(lane, submitted);
                retention = membership.retention(lane);
            }
            let target = retention.map_or(submitted, |retained| submitted.min(retained));
            // Only a block boundary the reader returned is registered: the
            // registered position is always a valid restart after a reset.
            if let Some(boundary) = reader.boundary_at_or_below(target) {
                let _ = reader.sent(boundary);
            }
            // The hold only grows (`SenderRead::hold_at`); below the
            // window's first bytes it stays at the publication's start,
            // where it was admitted.
            if let Some(held) = retransmit_window.and_then(|window| submitted.checked_sub(window)) {
                let held = retention.map_or(held, |retained| held.min(retained));
                let _ = reader.hold_at(held);
            }
            // With no bound receiver the restart stays at the hold.
            if let Some(consumed) = consumption.and_then(|positions| positions.get(lane)) {
                let _ = reader.restart_at(*consumed);
            }
        }
    }

    /// The control path of a send failure (lane-sender.md, outcome
    /// table): a faulted queue (the lane waits for the control path) is
    /// retried, keeping its items; a backend failure, an invariant, a
    /// sender bug, a queue that refuses the retry or an item of unknown
    /// exposure marks the publication as needing an endpoint reset
    /// ([`Outbound::needs_reset`]), which the sender agent counts and the
    /// endpoint table acts on (its own PR, ACS 15721).
    fn handle_failure<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        failure: Option<SenderFailure>,
    ) {
        match failure {
            None => {}
            // A backend failure (`Failed(Os)`: the half stopped, EBADF and
            // the like) is no send fault: retrying it would loop forever.
            Some(
                SenderFailure::Backend { .. }
                | SenderFailure::Invariant { .. }
                | SenderFailure::Sender { .. }
                | SenderFailure::Drr(_),
            ) => {
                self.counters.bump(|c| &mut c.send_failures, 1);
                self.needs_reset = true;
            }
        }
        for lane in 0..self.queues.len() {
            // An item of unknown exposure waits for the control path: only
            // an endpoint reset resolves it.
            if self.sender.suspended(lane) == Some(true) {
                self.needs_reset = true;
                continue;
            }
            // A faulted queue (the fault left the head pending) is retried,
            // unless the endpoint already needs a reset.
            if !self.needs_reset && self.sender.needs_control(lane) == Some(true) {
                self.counters.bump(|c| &mut c.send_faults, 1);
                let retried = self
                    .queues
                    .get(lane)
                    .is_some_and(|queue| tx.retry_queue(*queue).is_ok());
                if retried {
                    self.sender.retry(lane);
                } else {
                    self.needs_reset = true;
                }
            }
        }
    }

    /// Whether the endpoint needs a reset before this publication can send
    /// again (a send fault that cannot be retried, an invariant, or an item
    /// of unknown exposure). A new endpoint epoch clears it.
    /// Over redundant paths, whether any route's endpoint needs one.
    #[must_use]
    pub fn needs_reset(&self) -> bool {
        self.needs_reset
            || self
                .routed
                .as_deref()
                .is_some_and(|routed| routed.routes_needing_reset().next().is_some())
    }

    /// Posts, through `post` (which says whether the request was posted),
    /// the reset request of each endpoint that needs one and is due in
    /// sender cycle `cycle` ([`Outbound::reset_request_due`]): the
    /// publication's own, or each route's over redundant paths. Returns the
    /// requests posted and those `post` refused.
    pub fn post_reset_requests(
        &mut self,
        cycle: u64,
        mut post: impl FnMut(EndpointId) -> bool,
    ) -> (u64, u64) {
        let mut done = (0u64, 0u64);
        let mut tally = |posted: bool| {
            let count = if posted { &mut done.0 } else { &mut done.1 };
            if let Some(next) = count.checked_add(1) {
                *count = next;
            }
        };
        if let Some(routed) = self.routed.as_deref_mut() {
            for (endpoint, requested) in routed.reset_requests_due(cycle) {
                let posted = post(endpoint);
                if posted {
                    *requested = Some(cycle);
                }
                tally(posted);
            }
            return done;
        }
        if self.reset_request_due(cycle) {
            let posted = post(self.endpoint);
            if posted {
                self.reset_request_posted(cycle);
            }
            tally(posted);
        }
        done
    }

    /// Whether a reset request is due in sender cycle `cycle`: it needs a
    /// reset, and none was posted in the last [`RESET_REQUEST_CYCLES`].
    #[must_use]
    pub fn reset_request_due(&self, cycle: u64) -> bool {
        self.needs_reset
            && self.reset_requested.is_none_or(|at| {
                cycle
                    .checked_sub(at)
                    .is_none_or(|age| age >= RESET_REQUEST_CYCLES)
            })
    }

    /// Records a reset request posted in sender cycle `cycle`.
    pub fn reset_request_posted(&mut self, cycle: u64) {
        self.reset_requested = Some(cycle);
    }

    /// Marks the publication as needing a reset (tests).
    #[cfg(test)]
    pub(crate) fn force_needs_reset(&mut self) {
        self.needs_reset = true;
    }

    /// Stages `lane`'s committed frames, one datagram per claimed TX frame,
    /// until its queue is full or nothing more is committed.
    fn stage<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        lane: usize,
        limit: Limit,
        mut hook: Option<&mut (dyn NetworkTraceHook + 'static)>,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        let mut staged = 0u32;
        let (Some(queue), Some(reader)) =
            (self.queues.get(lane).copied(), self.readers.get_mut(lane))
        else {
            return Ok(0);
        };
        while self
            .sender
            .pending(lane)
            .is_some_and(|pending| pending < usize::from(STAGED_PER_LANE))
        {
            // A lane its guard closed reads nothing more: its cursor stays
            // where the close found it.
            if self
                .guard
                .as_deref()
                .is_some_and(|guard| guard.aborting(lane))
            {
                break;
            }
            // Nor does a timed lane whose publisher breached the schedule
            // ring's protocol, counted once in `schedule_faults` when it was
            // found; the sender reports it (`ScheduleViolated`), and the
            // conductor seals the lane and retires a remote client
            // (timed-tx.md section 11).
            if self
                .timed
                .as_deref()
                .and_then(|timed| timed.consumers.get(lane))
                .and_then(Option::as_ref)
                .is_some_and(ScheduleConsumer::violated)
            {
                break;
            }
            // The receivers' edge, before the read (it cannot be undone):
            // a whole maximum frame from the cursor must fit.
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
                break;
            }
            // A timed lane sends one frame per datagram: the first frame's
            // length, from a read that copies nothing and moves nothing,
            // bounds the copy, so each head waits for its own time only.
            let timed = self
                .timed
                .as_deref()
                .is_some_and(|timed| matches!(timed.consumers.get(lane), Some(Some(_))));
            let cap = if timed {
                match reader.read_committed(from, ReadOrigin::Cursor, &mut []) {
                    Err(ReadError::TooSmall { needed }) => needed.min(self.mtu),
                    Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => break,
                    Ok(_) | Err(_) => {
                        self.counters.bump(|c| &mut c.read_errors, 1);
                        break;
                    }
                }
            } else {
                self.mtu
            };
            let Ok(mut frame) = tx.claim_tx(queue, self.mtu) else {
                break;
            };
            let Some(out) = frame.bytes_mut().get_mut(..cap) else {
                break;
            };
            let (len, next, record) = match reader.read_committed(from, ReadOrigin::Cursor, out) {
                Ok(ReadOutcome::Copied { len, next }) => (len, next, None),
                Ok(ReadOutcome::Canonical { next, record }) => (32, next, Some(record)),
                // Dropping the unused frame frees its slot.
                Ok(ReadOutcome::Pending) => break,
                Err(ReadError::Retry) => break,
                Err(_) => {
                    self.counters.bump(|c| &mut c.read_errors, 1);
                    break;
                }
            };
            // A timed lane's frame takes its message's time from the ring:
            // a first fragment takes its entry, later fragments its time;
            // padding and aborted blocks carry none.
            let mut schedule = None;
            if timed {
                let lane_frame = match record {
                    Some(CanonicalKind::Pad) => LaneFrame::Pad,
                    Some(CanonicalKind::Aborted) => LaneFrame::Aborted { position: from },
                    None => data_frame(frame.bytes_mut().get(..len).unwrap_or_default(), from),
                };
                let ring = reader.subscription().buffer().schedule_ring();
                let consumer = self
                    .timed
                    .as_deref_mut()
                    .and_then(|timed| timed.consumers.get_mut(lane))
                    .and_then(Option::as_mut);
                let (Some(ring), Some(consumer)) = (ring, consumer) else {
                    break;
                };
                let Ok(scheduled) = consumer.frame_scheduled(ring, lane_frame) else {
                    self.counters.bump(|c| &mut c.schedule_faults, 1);
                    break;
                };
                let ends = matches!(lane_frame, LaneFrame::Data { end: true, .. });
                // A message a reliable reset read again was sent once: it
                // goes at once, outside the late policy, counted apart.
                let time = match scheduled {
                    Some(scheduled) if scheduled.replayed => {
                        if let (Some(timed), true) = (self.timed.as_deref_mut(), ends) {
                            timed.state.count_rewound();
                        }
                        None
                    }
                    scheduled => scheduled.map(|scheduled| scheduled.time),
                };
                schedule = Some((time, ends));
            }
            let record = record.is_some();
            // One branch per datagram without a hook.
            let traced = if hook.is_some() {
                self.traced.get(lane).copied().flatten()
            } else {
                None
            };
            if traced.is_some() {
                if record {
                    self.picked.clear();
                } else {
                    let skipped = traced_frames(
                        frame.bytes_mut().get(..len).unwrap_or_default(),
                        from,
                        &mut self.picked,
                    )
                    .ok_or(overflow.clone())?;
                    self.counters.bump(|c| &mut c.trace_invalid, skipped);
                }
            }
            // The messages it starts: a guard's message charge.
            let messages = if record || self.guard.is_none() {
                0
            } else {
                messages_started(frame.bytes_mut().get(..len).unwrap_or_default())
            };
            let token = SenderToken::new(self.next_token);
            self.next_token = self.next_token.checked_add(1).ok_or(overflow.clone())?;
            let Ok(ticket) = frame.commit(Commit {
                len,
                token,
                options: TxOptions::none(),
            }) else {
                // The cursor moved past a read that was not staged: a gap
                // the receiver closes by repair or by its gap policy. A
                // resend after a reset is then these frames' first pickup.
                self.counters.bump(|c| &mut c.queue_failures, 1);
                if traced.is_some() && !remember_unpicked(&mut self.traced, lane, from, next) {
                    self.counters.bump(|c| &mut c.trace_unpicked, 1);
                }
                if let Some((_, true)) = schedule {
                    self.timed_message_lost(lane);
                }
                break;
            };
            let charge = u32::try_from(len)
                .ok()
                .and_then(|len| align_frame(len).ok())
                .map(u64::from);
            let (Some(charge), Ok(len16)) = (charge, u16::try_from(len)) else {
                break;
            };
            // Unreachable: the lane's pending count was checked below its
            // bound and the charge is one aligned datagram of at most the
            // MTU. Counted if it ever happens; the committed item then
            // leaves unrecorded and shows as `mismatched`.
            let staged_head = Staged {
                ticket,
                charge,
                len: len16,
            };
            // A guarded lane stages through its gate, which records the head
            // in step with the sender; a timed one records it, with its
            // time, in the same step.
            let (guard, sender) = (self.guard.as_deref_mut(), &mut self.sender);
            let inner = || match guard {
                Some(guard) => guard
                    .stage(
                        sender,
                        lane,
                        staged_head,
                        GateHead {
                            token,
                            length: u64::from(len16),
                            messages,
                            start: from,
                            end: next,
                        },
                    )
                    .map_err(drop),
                None => sender.staged(lane, staged_head).map_err(drop),
            };
            let refused = match (schedule, self.timed.as_deref_mut()) {
                (Some((time, ends)), Some(timed)) => timed
                    .state
                    .stage_with(lane, (token, ticket), (time, ends), inner)
                    .is_err(),
                _ => inner().is_err(),
            };
            if refused {
                // A message whose last fragment is not staged never leaves:
                // its entry is done (the receiver closes the gap).
                if let Some((_, true)) = schedule {
                    self.timed_message_lost(lane);
                }
                self.counters.bump(|c| &mut c.staged_refused, 1);
                break;
            }
            if let Some(track) = self.tracks.get_mut(lane) {
                track.staged.push_back((ticket, next));
                if let Some((_, ends)) = schedule {
                    track.ends.push_back(ends);
                }
                track.waiting = false;
            }
            // The bytes are in TX storage (NT-2). Only a first pickup is
            // recorded: what a reset rewinds and sends again was picked up
            // before, unless its commit had failed.
            if let (Some(traced), Some(hook)) = (traced, hook.as_deref_mut()) {
                pick_up(
                    &self.picked,
                    &mut self.traced,
                    lane,
                    traced,
                    from..next,
                    hook,
                );
            }
            self.counters.bump(
                if record {
                    |c| &mut c.records
                } else {
                    |c| &mut c.staged
                },
                1,
            );
            self.counters.bump(|c| &mut c.bytes, u64::from(len16));
            staged = staged.checked_add(1).ok_or(overflow.clone())?;
        }
        Ok(staged)
    }
}

/// Remembers that the datagram of `lane` read over `from..next` never
/// reached TX storage. `false` when the lane already remembers a range
/// this one does not touch.
pub(super) fn remember_unpicked(
    traced_lanes: &mut [Option<TracedLane>; 4],
    lane: usize,
    from: u64,
    next: u64,
) -> bool {
    let Some(Some(traced)) = traced_lanes.get_mut(lane) else {
        return true;
    };
    traced.unpicked = match traced.unpicked {
        None => Some((from, next)),
        Some((low, high)) if from <= high && low <= next => Some((low.min(from), high.max(next))),
        Some(_) => return false,
    };
    true
}

/// Records the `SenderPickup` of each frame in `picked` from the datagram
/// of `lane` read over `span` that was never picked up before, then moves
/// the lane's pickup boundary and shrinks its unpicked range in
/// `traced_lanes`.
pub(super) fn pick_up(
    picked: &[(TraceExtension, u64)],
    traced_lanes: &mut [Option<TracedLane>; 4],
    lane: usize,
    traced: TracedLane,
    span: core::ops::Range<u64>,
    hook: &mut dyn NetworkTraceHook,
) {
    let Some(lane_id) = u8::try_from(lane)
        .ok()
        .and_then(|lane| Lane::try_new(lane).ok())
    else {
        return;
    };
    for (ext, position) in picked {
        if !traced.first_pickup(*position) {
            continue;
        }
        hook.on_sender_pickup(
            ext,
            &NetPickup {
                publication: traced.publication,
                lane: lane_id,
                position: *position,
                path: 0,
                attempt: 0,
            },
        );
    }
    if let Some(Some(slot)) = traced_lanes.get_mut(lane) {
        slot.boundary = slot.boundary.max(span.end);
        // A rewind resends in order: the range shrinks from its low end.
        slot.unpicked = slot.unpicked.and_then(|(low, high)| {
            let low = if span.contains(&low) { span.end } else { low };
            (low < high).then_some((low, high))
        });
    }
}

/// Test publications: real log buffers, one per lane, with their
/// publication and conductor handles, and the outbound path reading them.
#[cfg(test)]
pub(crate) mod testing {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test helpers, as ADR-0007 allows in tests"
    )]

    use std::net::SocketAddr;
    use std::sync::Arc;

    use karyos_protocol::frame::Lane;
    use karyos_protocol::network::{Alias, Lanes, TermParams};
    use karyos_sys::log_buffer::{
        AppendOptions, ConcurrentPublication, Conductor, DEFAULT_CLAIM_DEADLINE,
        DEFAULT_CORRUPT_RETRIES, LogBuffer, LogBufferConfig, Publication, PublicationMode, Role,
        SenderRead,
    };
    use karyos_sys::sizing::TermLength;
    use karyos_sys::term::TermId;

    use super::{EndpointId, Outbound};

    /// The publishing side of a test publication.
    pub(crate) struct TestLog {
        pub(crate) lanes: Vec<Arc<LogBuffer>>,
        pub(crate) publications: Vec<Publication<Arc<LogBuffer>>>,
        pub(crate) conductors: Vec<Conductor<Arc<LogBuffer>>>,
        /// A concurrent log's handles, per lane ([`outbound_concurrent`]);
        /// `publications` is then empty.
        pub(crate) concurrent: Vec<Vec<ConcurrentPublication<Arc<LogBuffer>>>>,
    }

    /// A publication of `lanes` lanes with `term`, read for `alias` on
    /// `endpoint` toward `destination`; each lane's quantum is four MTUs.
    pub(crate) fn outbound(
        endpoint: EndpointId,
        alias: Alias,
        destination: SocketAddr,
        term: TermParams,
        lanes: u8,
        reliable: bool,
    ) -> (Box<Outbound>, TestLog) {
        outbound_joined(endpoint, alias, destination, term, lanes, reliable, 0)
    }

    /// [`outbound`] of one lane with a schedule ring of `capacity`.
    pub(crate) fn outbound_timed(
        endpoint: EndpointId,
        alias: Alias,
        destination: SocketAddr,
        term: TermParams,
        capacity: u32,
    ) -> (Box<Outbound>, TestLog) {
        build(
            endpoint,
            alias,
            destination,
            term,
            1,
            false,
            0,
            None,
            None,
            capacity,
        )
    }

    /// [`outbound_timed`] over a reliable channel.
    pub(crate) fn outbound_timed_reliable(
        endpoint: EndpointId,
        alias: Alias,
        destination: SocketAddr,
        term: TermParams,
        capacity: u32,
    ) -> (Box<Outbound>, TestLog) {
        build(
            endpoint,
            alias,
            destination,
            term,
            1,
            true,
            0,
            None,
            None,
            capacity,
        )
    }

    /// [`outbound`], with `before` 1000-byte messages appended on each lane
    /// before its reader subscribes: the reader joins above 0.
    pub(crate) fn outbound_joined(
        endpoint: EndpointId,
        alias: Alias,
        destination: SocketAddr,
        term: TermParams,
        lanes: u8,
        reliable: bool,
        before: u8,
    ) -> (Box<Outbound>, TestLog) {
        build(
            endpoint,
            alias,
            destination,
            term,
            lanes,
            reliable,
            before,
            None,
            None,
            0,
        )
    }

    /// [`outbound`] over concurrent logs: `publishers` concurrent handles
    /// on each lane, in [`TestLog::concurrent`].
    pub(crate) fn outbound_concurrent(
        endpoint: EndpointId,
        alias: Alias,
        destination: SocketAddr,
        term: TermParams,
        lanes: u8,
        reliable: bool,
        publishers: u8,
    ) -> (Box<Outbound>, TestLog) {
        build(
            endpoint,
            alias,
            destination,
            term,
            lanes,
            reliable,
            0,
            None,
            Some(publishers),
            0,
        )
    }

    #[allow(clippy::too_many_arguments, reason = "a test helper")]
    fn build(
        endpoint: EndpointId,
        alias: Alias,
        destination: SocketAddr,
        term: TermParams,
        lanes: u8,
        reliable: bool,
        before: u8,
        routes: Option<&[(EndpointId, SocketAddr)]>,
        concurrent: Option<u8>,
        schedule: u32,
    ) -> (Box<Outbound>, TestLog) {
        let mut log = TestLog {
            lanes: Vec::new(),
            publications: Vec::new(),
            conductors: Vec::new(),
            concurrent: Vec::new(),
        };
        let mut readers = Vec::new();
        for lane in 0..lanes {
            let term_length = TermLength::try_new(term.term_length).unwrap();
            let buffer = Arc::new(
                LogBuffer::new(LogBufferConfig {
                    term_length,
                    // A concurrent log holds a credit per publisher.
                    spare_slots: 2 + concurrent.unwrap_or(1),
                    // A reliable lane's retention hold takes a cell.
                    max_subscribers: if reliable { 3 } else { 2 },
                    mtu: term.mtu,
                    max_reserved: term_length.get() / 8,
                    initial_term_id: TermId::new(term.initial_term_id.cast_unsigned()),
                    lane: Lane::try_new(lane).unwrap(),
                    session_id: alias.session_id,
                    stream_id: alias.stream_id,
                    publication: match concurrent {
                        Some(publishers) => PublicationMode::Concurrent {
                            publishers,
                            allow_non_lse: false,
                        },
                        None => PublicationMode::Exclusive,
                    },
                    claim_deadline: DEFAULT_CLAIM_DEADLINE,
                    schedule_capacity: schedule,
                })
                .unwrap(),
            );
            let mut conductor = buffer.conductor_owned().unwrap();
            if let Some(publishers) = concurrent {
                assert_eq!(before, 0, "a concurrent test log starts empty");
                log.concurrent.push(
                    (0..publishers)
                        .map(|_| conductor.concurrent_publication().unwrap().unwrap())
                        .collect(),
                );
            } else {
                let mut publication = buffer.publication_owned().unwrap().unwrap();
                for i in 0..before {
                    let _ = publication
                        .append(&[i; 1000], AppendOptions::default())
                        .unwrap();
                }
                log.publications.push(publication);
            }
            // A required participant on every channel, with its L_send
            // reservation (S2 2.1).
            let mut reader = SenderRead::new(
                conductor.subscribe_as(Role::Required, true, 1).unwrap(),
                DEFAULT_CORRUPT_RETRIES,
            )
            .unwrap();
            // A reliable lane's retention hold, as the driver admits it.
            if reliable {
                reader.with_hold(conductor.admit_hold(2).unwrap()).unwrap();
            }
            readers.push(reader);
            log.conductors.push(conductor);
            log.lanes.push(buffer);
        }
        let quanta = vec![u64::from(term.mtu) * 4; usize::from(lanes)];
        let outbound = match routes {
            Some(routes) => Outbound::new_routed(
                routes,
                alias,
                readers,
                &Lanes::new(&quanta).unwrap(),
                term.mtu,
                reliable,
            ),
            None => Outbound::new(
                endpoint,
                alias,
                destination,
                readers,
                &Lanes::new(&quanta).unwrap(),
                term.mtu,
                reliable,
            ),
        }
        .unwrap();
        (Box::new(outbound), log)
    }

    /// [`outbound`] over redundant paths: `routes` names each path's
    /// endpoint and destination, the founding path first.
    pub(crate) fn outbound_routed(
        routes: &[(EndpointId, SocketAddr)],
        alias: Alias,
        term: TermParams,
        lanes: u8,
        reliable: bool,
    ) -> (Box<Outbound>, TestLog) {
        let (endpoint, destination) = routes[0];
        build(
            endpoint,
            alias,
            destination,
            term,
            lanes,
            reliable,
            0,
            Some(routes),
            None,
            0,
        )
    }
}

/// A lane queue per lane, then the repair queue.
pub(crate) const OPENED_QUEUES: usize = 5;
const _: () = assert!(
    karyos_sys::frame::Lane::COUNT == 4,
    "OPENED_QUEUES is a queue per lane and the repair queue"
);

/// A publication's route and queues on one endpoint, in one epoch
/// ([`Outbound::opened_resources`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Opened {
    /// The endpoint.
    pub(crate) endpoint: EndpointId,
    /// The epoch they were opened in: a later one dropped them already.
    pub(crate) epoch: BackendEpoch,
    /// The route.
    pub(crate) route: RouteId,
    /// The lane queues, then the repair queue.
    pub(crate) queues: [Option<TxQueueId>; OPENED_QUEUES],
}

mod heartbeat;
mod removal;
mod routed;

pub use routed::{MAX_PATH_BACKOFF, MAX_PATH_COPY_ENTRIES, PathCounters, PathPolicy};

#[cfg(test)]
mod tests;
