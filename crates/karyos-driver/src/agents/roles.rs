// SPDX-License-Identifier: Apache-2.0

//! The network work of each agent (`quantstratum-docs:
//! karyos/design/driver-network-agents.md` §3.1, §3.2 and phase 4b-1): the
//! establishment control path. No image is created yet (phase 4b-2).
//!
//! - **Receiver.** For each RX half it holds, the receiver reads up to
//!   `rx_datagrams` datagrams and classifies them.
//!   - SETUP ANNOUNCE is challenged only for a stream this driver
//!     subscribes to on that endpoint (`AddSubscription`,
//!     network-control-schemas.md §6.2 step 2). The challenge goes only to
//!     the announcement's validated source (§7.3), within
//!     `rsp_setup_rate_per_destination` and the per-driver `rsp_setup_rate`
//!     (§7.4); the session table holds each resend to
//!     `challenge_resend_interval`.
//!   - SETUP ANSWER goes to its session table; an accepted one becomes a
//!     [`SessionEvent::CreateImage`] for the conductor, its whole command
//!     chain reserved before the session table commits it (S1). An
//!     announcement above the subscription's `max_image_term_length` is
//!     never challenged.
//!   - RSP_SETUP CHALLENGE and SOLICIT go to the sender ([`ControlItem`],
//!     DN-4), but only for an alias published on that endpoint
//!     (`AddPublishedAlias`): controls for anything else never reach the
//!     ring, so they cannot crowd out the rest.
//!   - SM is dropped and counted: it can only be validated against an
//!     installed binding and its receiver (§6.1), which phase 4b-2 brings.
//!   - DATA waits for phase 5.
//!   - RTT (reliable-transport.md, "RTT observations"; RC-1; ACS 15868).
//!     Each installed image probes its bound paths: after its SM, one
//!     RTTM REQUEST per path and `rtt_probe_interval`, at most one per path
//!     in the ring, with a report slot ([`ProbeSlot`]) the sender settles
//!     with the time it read before the submitting call. A REPLY counts
//!     only from a bound path, naming the image's identity and this
//!     receiver; the path's report is settled first, and the sample ends
//!     at the clock read at validation. A lost path is rebound in
//!     [`RttProbes`], so a late report of its probe is ignored. Probe ids
//!     are restocked on the image timer step, never per datagram: a
//!     `getrandom` call on the agent thread about once per 16 probes, a
//!     known deviation until the agents have a control thread
//!     (`rttm_id_draws`). A REQUEST for a published alias goes to the
//!     sender, stamped with when it was taken from the backend.
//! - **Sender.** It holds the publications it announces
//!   ([`SendSessions`]), their channel destinations and join points. Each
//!   cycle it sends the controls the receiver handed over, answers the
//!   challenges and solicits for its publications toward the channel
//!   destination (never a payload's address), and sends the announcements
//!   due. Its control routes are kept per endpoint in a table allocated at
//!   creation and forgotten when the endpoint is handed back. It answers
//!   an RTTM REQUEST from a receiver it answered on that endpoint, naming
//!   the publication's incarnation and its receiver id, within
//!   `rttm_reply_rate` per source ([`RttReplies`]); the REPLY echoes the
//!   probe id with the service delay since the request was taken.
//!
//! Every queue and table is allocated when the agents are created; drops
//! are counted, each under its own counter.

use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::sync::Arc;

use karyos_io::backend::{Budget, RxBackend, RxDatagram, RxDrop, RxHandler};
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::frame::{FRAME_ALIGNMENT, Lane};
use karyos_protocol::network::{
    Alias, Control, Datagram, Identity, LaneStatus, Lanes, MAX_WINDOW, Receiver, Rttm, RttmKind,
    SetupAnnounce, SetupAnswer, StatusMessage, classify,
};
use karyos_sys::host_clock::age_ns;
use karyos_sys::log_buffer::ReceiveError;
use karyos_sys::log_buffer::Received;
use karyos_sys::receive::{Heartbeat, ImageParams, Item, ValidatedDatagram, ValidatedFrame};
use karyos_sys::term::TermId;

use crate::paths::PathConfig;
use crate::paths::stats::{Arrival, Delivered, PathStats};
use karyos_sys::sizing::TermLength;

use super::chain::{ImageChain, SessionCommand, SessionEnd, SessionEvent};
use super::control::{
    ControlItem, ControlRoutes, ItemGuard, ProbeGuard, ProbeReport, ProbeSlot, RouteSlot, SmGuard,
    SmSlot,
};
use super::data::Outbound;

/// The data DRR's budget per publication and cycle: probes and bytes.
const DATA_BUDGET: karyos_protocol::lanes::drr::Budget = karyos_protocol::lanes::drr::Budget {
    work: 64,
    bytes: 1 << 20,
};
use super::ring::{self, Reservation, RingReceiver, RingSender};
use super::{AgentCommand, AgentConfig, AgentError, AgentEvent, AgentKind, EndpointId, Half};
use crate::membership::{Membership, MembershipConfig, Roles, SmKey};
use crate::rtt::{Probe, ReplyOutcome, RttConfig, RttProbes, RttReplies};
use crate::sessions::OsNonces;
use crate::sessions::rate::{EndpointRates, RateRefused, TotalRate, normalized};
use crate::sessions::receive::{
    AnnounceOutcome, AnswerOutcome, BindingKey, ReadyOutcome as ImageOutcome, ReceiveSessions,
    SessionConfigError, SlotRef,
};
use crate::sessions::send::{SendSessionError, SendSessions};
use crate::sm_schedule::{SmDue, SmSchedule};
use karyos_sys::log_buffer::ReceiveOwner;

/// The receiver's counters; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceiverCounters {
    /// Datagrams read.
    pub datagrams: u64,
    /// Datagrams dropped by the backend.
    pub backend_drops: u64,
    /// Datagrams that did not decode.
    pub decode_errors: u64,
    /// Controls handed to the sender.
    pub forwarded: u64,
    /// RSP_SETUP challenges dropped with the control ring full.
    pub ring_full_rsp_setup: u64,
    /// Received CHALLENGEs dropped with the control ring full.
    pub ring_full_challenge: u64,
    /// Received SOLICITs dropped with the control ring full.
    pub ring_full_solicit: u64,
    /// Challenges not sent: the source is not an answerable unicast
    /// endpoint (network-control-schemas.md §7.3).
    pub unanswerable_source: u64,
    /// Challenges not sent: `rsp_setup_rate_per_destination` (§7.4).
    pub rsp_setup_rate_limited: u64,
    /// Challenges not sent: the destination rate table is full.
    pub rsp_setup_destinations_full: u64,
    /// Challenges not sent: the per-driver `rsp_setup_rate` (§7.4).
    pub rsp_setup_total_limited: u64,
    /// Announcements for a stream not subscribed on the endpoint.
    pub unsubscribed: u64,
    /// Announcements whose term length is above the subscription's
    /// `max_image_term_length`.
    pub term_too_large: u64,
    /// CHALLENGE, SOLICIT and SM for an alias not published on the
    /// endpoint.
    pub not_published: u64,
    /// SMs sent for installed images.
    pub sm_sent: u64,
    /// Periodic SMs skipped: the control ring had no slot for them.
    pub sm_skipped: u64,
    /// Images retired at their liveness timeout.
    pub images_retired: u64,
    /// Installed images not kept (no SM slot, or no binding): retired at
    /// once so their storage is reclaimed.
    pub images_refused: u64,
    /// An image retired without its `RetireImage` unit, or installed without
    /// its binding: a broken invariant, counted.
    pub chain_invariant: u64,
    /// DATA frames committed to an image.
    pub data_committed: u64,
    /// DATA frames already committed, late, ahead or not ready: dropped
    /// (repair or the gap policy resolves them).
    pub data_dropped: u64,
    /// DATA frames the receive owner refused for a protocol rule.
    pub data_refused: u64,
    /// Fresh heartbeats (above the lane's highest seen position).
    pub heartbeats: u64,
    /// Heartbeats below the lane's highest seen position: replays,
    /// refreshing nothing.
    pub heartbeats_stale: u64,
    /// Heartbeats at the lane's highest seen position (an idle sender):
    /// alive only until `idle_image_timeout` after the last fresh evidence.
    pub heartbeats_stationary: u64,
    /// Heartbeats outside the image's receive window: rejected.
    pub heartbeats_rejected: u64,
    /// DATA datagrams from no binding: dropped.
    pub data_unbound: u64,
    /// DATA datagrams that failed validation for their image: dropped.
    pub data_invalid: u64,
    /// PATH_HB that refreshed a bound path.
    pub path_heartbeats: u64,
    /// PATH_HB from no bound path: dropped.
    pub path_heartbeats_unbound: u64,
    /// Images asked of the conductor.
    pub create_image: u64,
    /// Later paths bound to installed images (RP-1): no image asked.
    pub paths_bound: u64,
    /// RTTM REQUESTs handed to the sender (RC-1).
    pub rttm_requests: u64,
    /// RTTM REQUESTs dropped with the control ring full: not submitted.
    pub ring_full_rttm: u64,
    /// RTTM REPLYs that gave a sample.
    pub rttm_samples: u64,
    /// RTTM REPLYs for a bound path that gave no sample (duplicate,
    /// unmatched, late or invalid; the image's RTT counts tell which).
    pub rttm_replies_ignored: u64,
    /// RTTM REPLYs from no bound path, or naming another identity or
    /// receiver: dropped.
    pub rttm_replies_unbound: u64,
    /// RTTM REQUESTs forwarded to the sender dropped with the ring full.
    pub ring_full_rttm_request: u64,
    /// Probe id refills that drew from the operating system: a system call
    /// on the receiver agent's timer step, a known deviation until the
    /// agents have a control thread (ACS 15868).
    pub rttm_id_draws: u64,
    /// Data and controls this phase does not handle yet.
    pub unhandled: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

/// The sender's counters; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SenderCounters {
    /// Controls sent.
    pub sent: u64,
    /// Controls not sent (encoding, route, queue or kernel).
    pub send_failures: u64,
    /// Controls for an endpoint whose TX half the sender does not hold.
    pub no_endpoint: u64,
    /// Answers the session table refused (see its counters).
    pub refused: u64,
    /// SMs accepted from a bound receiver.
    pub sm_accepted: u64,
    /// SMs from no receiver this sender answered on that endpoint (source,
    /// alias, receiver boot id and incarnation), ignored.
    pub sm_unbound: u64,
    /// SMs from a bound receiver whose lane count or receiver id does not
    /// match, ignored.
    pub sm_mismatch: u64,
    /// Answered receivers not recorded: the binding table was full of
    /// confirmed bindings.
    pub bindings_full: u64,
    /// Publications whose endpoint needs a reset before they can send again
    /// (a gauge, recomputed each cycle); each asks the endpoint table for
    /// it (`AgentEvent::ResetRequested`).
    pub needs_reset: u64,
    /// Unconfirmed bindings evicted to make room for a new answer.
    pub bindings_evicted: u64,
    /// Bindings expired: unconfirmed past `setup_challenge_timeout`, or
    /// confirmed with no SM for `image_liveness_timeout`.
    pub bindings_expired: u64,
    /// SMs whose consumption is below one already reported (replayed or
    /// reordered): the higher value is kept.
    pub sm_stale: u64,
    /// Reset requests posted to the endpoint table.
    pub reset_requests: u64,
    /// Reset requests not posted: the event ring was full.
    pub reset_requests_full: u64,
    /// RTTM REPLYs sent (counted in `sent` too).
    pub rttm_replied: u64,
    /// RTTM REQUESTs from no receiver this sender answered (source, alias,
    /// receiver boot id and incarnation): ignored.
    pub rttm_unbound: u64,
    /// RTTM REQUESTs from a bound receiver naming another receiver id:
    /// ignored.
    pub rttm_mismatch: u64,
    /// RTTM REQUESTs over `rttm_reply_rate` or beyond the source table:
    /// dropped ([`SenderRole::rttm_reply_drops`] tells which).
    pub rttm_refused: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

/// A receiver this sender answered: where its SMs may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReceiverBinding {
    endpoint: EndpointId,
    alias: Alias,
    /// The challenge's source, normalized.
    source: SocketAddr,
    /// The receiver boot id of the challenge block.
    boot_id: [u64; 2],
    /// The publication incarnation answered.
    identity: Identity,
    /// The receiver id of its first SM since the last answer.
    receiver_id: Option<u64>,
    /// The receiver id before the last answer reset it: a membership to
    /// end if the next SM names another (ACS 15648).
    former: Option<u64>,
    /// Its highest reported status per lane (consumption and window).
    lanes: Option<Lanes<LaneStatus>>,
    /// The join points it was answered with: its bound until its first SM.
    joins: Lanes<u64>,
    /// When it was last answered.
    answered_at: u64,
    /// When it last sent an accepted SM: `None` while unconfirmed.
    last_sm: Option<u64>,
}

fn bump(value: &mut u64, overflowed: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *overflowed = true,
    }
}

/// The receiver agent's network state.
#[derive(Debug)]
pub struct ReceiverRole {
    /// The network trace hook (P2.12 step 3).
    trace: super::net_trace::ReceiverTrace,
    sessions: ReceiveSessions,
    nonces: OsNonces,
    to_sender: RingSender<ControlItem>,
    budget: Budget,
    /// Subscribed streams per endpoint, with their largest accepted image
    /// term length.
    subscriptions: Vec<(EndpointId, i32, u32)>,
    /// Aliases published per endpoint.
    published: Vec<(EndpointId, Alias)>,
    max_entries: usize,
    rsp_destinations: EndpointRates,
    rsp_total: TotalRate,
    /// The `RetireImage` unit and geometry of each answered challenge, by
    /// pending slot, until the conductor's reply (S1; at most
    /// `max_images`).
    chains: Vec<Chain>,
    /// Installed images (at most `max_images`, allocated at creation).
    /// DATA admission through them is phase 5c.
    images: Vec<Installed>,
    /// One SM slot flag per image, allocated at creation; an image takes
    /// one only the pool holds.
    sm_slots: Vec<Arc<SmSlot>>,
    sm_interval: u64,
    liveness_timeout: u64,
    idle_timeout: u64,
    /// The path statistics' configuration (redundant-paths.md section 5).
    path_config: PathConfig,
    /// Each image's RTT probes' settings.
    rtt: RttConfig,
    /// The clock read when a REPLY is validated.
    clock: fn() -> u64,
    counters: ReceiverCounters,
}

/// Terms a path's statistics track per lane: the image's slots, three
/// rotation slots and the default five spares.
const STAT_TERM_SLOTS: usize = 8;

/// Each lane's `(position, term count)` of `joins`, for
/// [`PathStats::path_bound`].
fn path_joins(joins: &Lanes<u64>, term_length: u32) -> [(u64, u64); 4] {
    let mut out = [(0u64, 0u64); 4];
    for (slot, join) in out.iter_mut().zip(joins.as_slice()) {
        let term = join.checked_div(u64::from(term_length)).unwrap_or(0);
        *slot = (*join, term);
    }
    out
}

/// Applies a datagram's evidence to `image`'s liveness at `now` (trusted
/// profile): fresh evidence keeps it alive and restarts the idle clock;
/// stationary heartbeats keep it alive only until `idle_timeout` after the
/// last fresh evidence; anything else changes nothing.
fn apply_evidence(
    image: &mut Installed,
    fresh: bool,
    stationary: bool,
    now: u64,
    idle_timeout: u64,
) {
    if fresh {
        image.evidence = now;
        image.last_fresh = now;
    } else if stationary && age_ns(now, image.last_fresh) < idle_timeout {
        image.evidence = now;
    }
}

/// What a heartbeat is to its image's liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeartbeatClass {
    /// Above the lane's highest seen position: fresh evidence.
    Fresh,
    /// At the lane's highest seen position: an idle sender.
    Stationary,
    /// Below it: a replay.
    Stale,
    /// Outside the image's receive window.
    Rejected,
}

/// Classifies `heartbeat` against the image's receive window and the
/// highest heartbeat position seen on its lane, which a fresh one raises.
fn classify_heartbeat(image: &mut Installed, heartbeat: &Heartbeat) -> HeartbeatClass {
    let lane = heartbeat.lane();
    let Some(position) = heartbeat
        .term_id()
        .count_from(image.initial_term_id)
        .ok()
        .and_then(|count| u64::from(count.get()).checked_mul(u64::from(image.term_length)))
        .and_then(|base| base.checked_add(u64::from(heartbeat.term_offset())))
    else {
        return HeartbeatClass::Rejected;
    };
    if !image.owner.within_window(lane, position).unwrap_or(false) {
        return HeartbeatClass::Rejected;
    }
    let Some(mark) = image.heartbeat_marks.get_mut(usize::from(lane.get())) else {
        return HeartbeatClass::Rejected;
    };
    match *mark {
        Some(seen) if position < seen => HeartbeatClass::Stale,
        Some(seen) if position == seen => HeartbeatClass::Stationary,
        _ => {
            *mark = Some(position);
            HeartbeatClass::Fresh
        }
    }
}

/// What the path statistics record of `frame` from `path`: its lane, term
/// count, stream position and extent. `None` off any bound path or for a
/// term outside the incarnation.
fn delivered(
    image: &Installed,
    frame: &ValidatedFrame<'_>,
    path: Option<(SlotRef, usize)>,
    now: u64,
) -> Option<Delivered> {
    let (_, path) = path?;
    let term = u64::from(
        frame
            .term_id()
            .count_from(image.initial_term_id)
            .ok()?
            .get(),
    );
    let position = term
        .checked_mul(u64::from(image.term_length))?
        .checked_add(u64::from(frame.term_offset()))?;
    Some(Delivered {
        path,
        lane: usize::from(frame.lane().get()),
        term,
        position,
        length: u64::from(frame.extent()),
        now,
    })
}

/// An answered challenge waiting for the conductor's reply.
#[derive(Debug)]
struct Chain {
    /// The pending slot.
    slot: SlotRef,
    /// Its `RetireImage` unit.
    retire: Reservation,
    lane_count: u8,
    term_length: u32,
    mtu: u32,
    initial_term_id: i32,
    /// The answer's join points: the first path's.
    joins: Lanes<u64>,
}

/// An installed image: its receive owner, binding, SM cadence and
/// liveness.
#[derive(Debug)]
struct Installed {
    /// The installed slot.
    slot: SlotRef,
    owner: Box<ReceiveOwner>,
    /// The `RetireImage` unit reserved at the answer.
    retire: Option<Reservation>,
    key: BindingKey,
    identity: Identity,
    lane_count: u8,
    /// What its datagrams are validated against.
    params: ImageParams,
    /// Its paths' statistics, whose freshness refreshes path liveness
    /// (redundant-paths.md RP-2).
    stats: PathStats,
    /// The term id of its first term, and its term length: a frame's term
    /// count and stream position.
    initial_term_id: TermId,
    term_length: u32,
    /// The highest heartbeat position seen per lane.
    heartbeat_marks: [Option<u64>; 4],
    /// The last fresh evidence: a committed frame or a fresh heartbeat.
    last_fresh: u64,
    /// The window each SM grants per lane.
    window: u32,
    /// When its SMs are due (multicast-flow-control.md MC-6): the join at
    /// once, then every `sm_interval` and on a quarter-window advance.
    schedule: SmSchedule,
    /// The control ring slot of its next SM, while none waits (S1: one SM
    /// slot per binding).
    sm_slot: Option<Reservation>,
    /// Whether its previous SM still waits in the ring.
    sm: Arc<SmSlot>,
    /// The last fresh evidence from the binding (DATA and heartbeats, phase
    /// 5c; until then, the install).
    evidence: u64,
    /// Its paths' RTT probes (RC-1), one entry per path index.
    rtt: RttProbes,
    /// Each path's REQUEST report slot and the probe it reports on.
    probes: Vec<PathProbe>,
}

/// One path's RTTM REQUEST in flight: its report slot (at most one
/// REQUEST per path in the ring) and the probe the report belongs to.
#[derive(Debug)]
struct PathProbe {
    slot: Arc<ProbeSlot>,
    pending: Option<Probe>,
}

/// The receiver id of the image at `slot` in its SMs and RTTM REQUESTs:
/// nonzero, since an installed generation is at least 1.
fn receiver_id(slot: SlotRef) -> u64 {
    (u64::from(slot.slot) << 32) | u64::from(slot.generation)
}

/// Adds one to a receiver counter; sticky on overflow.
fn tally(counters: &mut ReceiverCounters, field: fn(&mut ReceiverCounters) -> &mut u64) {
    let mut overflowed = counters.overflowed;
    bump(field(counters), &mut overflowed);
    counters.overflowed = overflowed;
}

/// Settles `probe`'s report into `rtt`, if the sender made one; `replied`
/// as in [`ProbeSlot::collect`].
fn collect_probe(rtt: &mut RttProbes, probe: &mut PathProbe, replied: bool) {
    let Some(report) = probe.slot.collect(replied) else {
        return;
    };
    // A probe of an older binding generation is ignored by `rtt`.
    if let Some(pending) = probe.pending.take() {
        match report {
            ProbeReport::Submitted(start) => rtt.submitted(pending, start),
            ProbeReport::NotSubmitted => rtt.not_submitted(pending),
        }
    }
}

/// The sender agent's network state.
#[derive(Debug)]
pub struct SenderRole {
    sessions: SendSessions,
    from_receiver: RingReceiver<ControlItem>,
    /// Each publication's data path: readers, channel destination, lane
    /// queues (at most `publications`, allocated at creation).
    publications: Vec<Outbound>,
    /// Control routes, one slot per endpoint the agent can hold.
    routes: Vec<RouteSlot>,
    budget: u32,
    /// The announcements due this cycle (allocated at creation).
    due: Vec<(EndpointId, SetupAnnounce)>,
    /// The receivers answered, at most `receiver_bindings` (allocated at
    /// creation).
    bindings: Vec<ReceiverBinding>,
    max_bindings: usize,
    /// An unconfirmed binding lives this long (`setup_challenge_timeout`).
    unconfirmed_timeout: u64,
    /// A confirmed binding lives this long without an SM
    /// (`image_liveness_timeout`).
    confirmed_timeout: u64,
    /// Duty cycles run, for the reset request cadence.
    cycle: u64,
    /// The driver's timing of each publication's membership.
    membership: MembershipTiming,
    /// The RTTM reply rate per source endpoint (RC-1).
    replies: RttReplies,
    /// The clock read immediately before a REQUEST's backend call.
    clock: fn() -> u64,
    counters: SenderCounters,
    /// The network trace hook and journals (P2.12 step 3).
    trace: super::net_trace::SenderTrace,
}

/// The driver settings a publication's membership follows: the receivers'
/// SM cadence and the liveness that the receive side applies to images.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MembershipTiming {
    /// The receivers' `sm_interval`.
    pub sm_interval: u64,
    /// A member silent this long expires: `image_liveness_timeout`, after
    /// which its binding and image are gone too.
    pub receiver_timeout: u64,
    /// A member whose SMs are stationary expires after this long:
    /// `idle_image_timeout`, as stationary heartbeats keep an image.
    pub pause_timeout: u64,
}

impl MembershipTiming {
    /// The timing of `config`.
    pub(super) const fn of(config: &AgentConfig) -> Self {
        Self {
            sm_interval: config.sm_interval,
            receiver_timeout: config.image_liveness_timeout,
            pause_timeout: config.idle_image_timeout,
        }
    }

    /// A publication's membership settings with this timing; a required
    /// member's join waits one `receiver_timeout`.
    pub(super) const fn config(
        &self,
        lane_count: u8,
        min_window: u32,
        max_window: u32,
    ) -> MembershipConfig {
        let mut config = MembershipConfig::new(lane_count, min_window, max_window);
        config.sm_interval = self.sm_interval;
        config.receiver_timeout = self.receiver_timeout;
        config.pause_timeout = self.pause_timeout;
        config.join_timeout = self.receiver_timeout;
        config
    }
}

/// Both roles and the control ring between them, sized by `config`.
pub(super) fn roles(config: &AgentConfig) -> Result<(SenderRole, ReceiverRole), AgentError> {
    let capacity = std::num::NonZeroUsize::new(config.control_capacity).ok_or(
        AgentError::InvalidConfig("control_capacity must be at least 1"),
    )?;
    let (to_sender, from_receiver) = ring::ring(capacity);
    let mut boot_id = [0u64; 2];
    karyos_sys::random::fill_u64s(&mut boot_id)
        .map_err(|_| AgentError::InvalidConfig("no random source for receiver_boot_id"))?;
    // An all-zero draw is not a valid boot id; draw once more.
    if boot_id == [0, 0] {
        karyos_sys::random::fill_u64s(&mut boot_id)
            .map_err(|_| AgentError::InvalidConfig("no random source for receiver_boot_id"))?;
    }
    let sessions = ReceiveSessions::new(config.sessions, boot_id)
        .map_err(|SessionConfigError(reason)| AgentError::InvalidConfig(reason))?;
    let send = SendSessions::new(
        config.publications,
        config.setup_interval,
        config.answer_rate,
    )
    .map_err(|_| AgentError::InvalidConfig("invalid sender session configuration"))?;
    let datagrams = config.rx_datagrams;
    let bytes = u64::from(datagrams)
        .checked_mul(u64::from(karyos_io::sockets::endpoint::MAX_DATAGRAM))
        .ok_or(AgentError::InvalidConfig("rx_datagrams too large"))?;
    // One receive call per datagram, plus the one that finds none.
    let ops = datagrams
        .checked_add(1)
        .ok_or(AgentError::InvalidConfig("rx_datagrams too large"))?;
    let rsp_destinations = EndpointRates::new(
        config.rsp_setup_per_destination,
        config.rsp_setup_destinations,
    )
    .ok_or(AgentError::InvalidConfig("rsp_setup rate or table is zero"))?;
    let rsp_total = TotalRate::new(config.rsp_setup_rate, 0)
        .ok_or(AgentError::InvalidConfig("rsp_setup_rate is zero"))?;
    let replies = RttReplies::new(&config.rtt)
        .map_err(|_| AgentError::InvalidConfig("invalid RTT configuration"))?;
    let routes = (0..config.max_endpoints)
        .map(|_| RouteSlot {
            endpoint: None,
            routes: ControlRoutes::new(config.control_routes),
        })
        .collect();
    Ok((
        SenderRole {
            sessions: send,
            from_receiver,
            publications: Vec::with_capacity(config.publications),
            routes,
            budget: u32::try_from(config.control_capacity).unwrap_or(u32::MAX),
            due: Vec::with_capacity(config.publications),
            bindings: Vec::with_capacity(config.receiver_bindings),
            max_bindings: config.receiver_bindings,
            unconfirmed_timeout: config.sessions.setup_challenge_timeout,
            confirmed_timeout: config.image_liveness_timeout,
            cycle: 0,
            membership: MembershipTiming::of(config),
            replies,
            clock: karyos_sys::host_clock::host_monotonic_ns,
            counters: SenderCounters::default(),
            trace: super::net_trace::SenderTrace::default(),
        },
        ReceiverRole {
            sessions,
            nonces: OsNonces,
            to_sender,
            budget: Budget::new(datagrams, bytes, ops),
            subscriptions: Vec::with_capacity(config.subscriptions),
            published: Vec::with_capacity(config.subscriptions),
            max_entries: config.subscriptions,
            rsp_destinations,
            rsp_total,
            chains: Vec::with_capacity(config.sessions.max_images),
            images: Vec::with_capacity(config.sessions.max_images),
            sm_slots: (0..config.sessions.max_images)
                .map(|_| Arc::new(SmSlot::default()))
                .collect(),
            sm_interval: config.sm_interval,
            liveness_timeout: config.image_liveness_timeout,
            idle_timeout: config.idle_image_timeout,
            path_config: PathConfig {
                max_paths: config.sessions.max_paths,
                ..PathConfig::default()
            },
            rtt: config.rtt,
            clock: karyos_sys::host_clock::host_monotonic_ns,
            counters: ReceiverCounters::default(),
            trace: super::net_trace::ReceiverTrace::default(),
        },
    ))
}

/// Reserves an image's whole command chain (S1): `CreateImage`, the
/// receiver's `RetireImage` and the conductor's units. `None`, with
/// nothing held, when a ring has no credit.
fn reserve_chain(sessions: &SessionEnd) -> Option<(Reservation, Reservation, ImageChain)> {
    let create = sessions.events.reserve()?;
    let reply = sessions.events.reserve()?;
    let retire = sessions.events.reserve()?;
    let command = sessions.credit.reserve()?;
    let reclaimed = sessions.credit.reserve()?;
    Some((
        create,
        retire,
        ImageChain {
            command,
            reply,
            reclaimed,
        },
    ))
}

/// Whether an RSP_SETUP may answer `source` (network-control-schemas.md
/// §7.3): a unicast address with a nonzero port; never a multicast,
/// broadcast or unspecified address, an IPv4-mapped one included.
fn answerable(source: SocketAddr) -> bool {
    let source = normalized(source);
    let ip = source.ip();
    let broadcast = match ip {
        std::net::IpAddr::V4(v4) => v4.is_broadcast(),
        std::net::IpAddr::V6(_) => false,
    };
    source.port() != 0 && !ip.is_multicast() && !ip.is_unspecified() && !broadcast
}

impl ReceiverRole {
    /// The receiver's commands: `AddSubscription` and `AddPublishedAlias`;
    /// the sender's are refused.
    pub(super) fn command<O: SocketOps>(
        &mut self,
        command: AgentCommand<O>,
    ) -> Option<(Reservation, AgentEvent<O>)> {
        let max = self.max_entries;
        let configured = |accepted| AgentEvent::Configured {
            agent: AgentKind::Receiver,
            accepted,
        };
        match command {
            AgentCommand::AddSubscription {
                reply,
                endpoint,
                stream_id,
                max_term_length,
            } => {
                let held = self
                    .subscriptions
                    .iter()
                    .position(|(held, stream, _)| (*held, *stream) == (endpoint, stream_id));
                let full = self.subscriptions.len() >= max;
                let accepted = match held.and_then(|index| self.subscriptions.get_mut(index)) {
                    // Two subscribers of one stream on one endpoint: the
                    // stricter limit holds for both.
                    Some(entry) => {
                        entry.2 = entry.2.min(max_term_length);
                        true
                    }
                    None if !full => {
                        self.subscriptions
                            .push((endpoint, stream_id, max_term_length));
                        true
                    }
                    None => false,
                };
                Some((reply, configured(accepted)))
            }
            AgentCommand::AddPublishedAlias {
                reply,
                endpoint,
                alias,
            } => {
                let entry = (endpoint, alias);
                let accepted = self.published.contains(&entry)
                    || (self.published.len() < max && {
                        self.published.push(entry);
                        true
                    });
                Some((reply, configured(accepted)))
            }
            AgentCommand::AddPublication {
                reply, publication, ..
            } => Some((
                reply,
                AgentEvent::PublicationRefused {
                    agent: AgentKind::Receiver,
                    endpoint: publication.endpoint,
                    alias: publication.alias,
                },
            )),
            command => self.trace.command(command),
        }
    }

    /// The session table's counters.
    #[must_use]
    pub fn session_counters(&self) -> crate::sessions::receive::SessionCounters {
        self.sessions.counters()
    }

    /// Live paths of the image at `slot` (tests).
    #[cfg(test)]
    pub(super) fn live_paths(&self, slot: SlotRef) -> usize {
        self.sessions.paths().live(slot)
    }

    /// The last image evidence of the image at `slot` (tests).
    #[cfg(test)]
    pub(super) fn image_evidence(&self, slot: SlotRef) -> Option<u64> {
        self.images
            .iter()
            .find(|image| image.slot == slot)
            .map(|image| image.evidence)
    }

    /// Hands the receiver a DATA heartbeat on lane 0 of the image at
    /// `slot`, `ahead` bytes above its contiguous prefix, as if it came
    /// from `source` on `endpoint` at `now` (tests).
    #[cfg(test)]
    pub(super) fn inject_heartbeat(
        &mut self,
        sessions: &SessionEnd,
        endpoint: EndpointId,
        source: SocketAddr,
        slot: SlotRef,
        ahead: u64,
        now: u64,
    ) {
        use karyos_protocol::frame::{Flags, FrameType, Word0};

        let image = self.images.iter().find(|image| image.slot == slot).unwrap();
        let position = image.owner.rebuild_position(Lane::ZERO).unwrap() + ahead;
        let term_length = u64::from(image.term_length);
        let term_id = image
            .initial_term_id
            .get()
            .checked_add(u32::try_from(position / term_length).unwrap())
            .unwrap();
        let term_offset = u32::try_from(position % term_length).unwrap();
        let alias = image.key.alias;
        let mut bytes = [0u8; 32];
        let word0 = Word0::new(
            32,
            Flags::new(true, true, false, false, Lane::ZERO),
            FrameType::Data,
        );
        bytes[..8].copy_from_slice(&word0.pack().to_le_bytes());
        bytes[8..12].copy_from_slice(&term_offset.to_le_bytes());
        bytes[12..16].copy_from_slice(&alias.session_id.to_le_bytes());
        bytes[16..20].copy_from_slice(&alias.stream_id.to_le_bytes());
        bytes[20..24].copy_from_slice(&term_id.to_le_bytes());
        let mut intake = Intake {
            endpoint,
            now,
            role: self,
            sessions,
            work: 0,
        };
        intake.data(source, alias, &bytes);
    }

    /// Whether the image installed at `slot` is held.
    #[must_use]
    pub fn has_image(&self, slot: SlotRef) -> bool {
        self.images.iter().any(|image| image.slot == slot)
    }

    /// Serves the conductor's session commands at `now` (S1), before any
    /// other command or datagram; at most one ring's worth per cycle.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub(super) fn serve_sessions(
        &mut self,
        sessions: &SessionEnd,
        now: u64,
    ) -> Result<u32, AgentError> {
        let mut served = 0u32;
        for _ in 0..sessions.events.capacity() {
            let Ok(Some(command)) = sessions.commands.try_take() else {
                break;
            };
            served = served
                .checked_add(1)
                .ok_or(AgentError::CountOverflow(AgentKind::Receiver))?;
            // An installed image the receiver could not keep: retired right
            // after its `ImageInstalled`, so the conductor reclaims it.
            let mut refused = None;
            let (reply, event) = match command {
                SessionCommand::InstallImage { reply, slot, owner } => {
                    let chain = self.take_chain(slot);
                    let event = match self.sessions.image_ready(slot, now) {
                        ImageOutcome::Installed(installed) => {
                            if let Err(retire) = self.install(installed, owner, chain, now) {
                                refused = Some((installed, retire));
                            }
                            SessionEvent::ImageInstalled { slot, installed }
                        }
                        // Dropping the owner drops the receiver's hold on
                        // the image, and `retire` frees its unit; the
                        // conductor frees the storage.
                        ImageOutcome::Release(_) => SessionEvent::ImageReleased { slot },
                    };
                    (reply, event)
                }
                SessionCommand::RefuseImage { reply, slot } => {
                    self.sessions.image_refused(slot);
                    drop(self.take_chain(slot));
                    (reply, SessionEvent::ImageReleased { slot })
                }
                SessionCommand::StorageReclaimed { slot } => {
                    self.sessions.storage_reclaimed(slot);
                    continue;
                }
            };
            // The conductor gone: the driver is stopping.
            let _ = sessions.events.post(reply, event);
            if let Some((installed, retire)) = refused {
                let _ = self.sessions.retire(installed, now);
                self.count(|c| &mut c.images_refused);
                match retire {
                    Some(unit) => {
                        let _ = sessions
                            .events
                            .post(unit, SessionEvent::RetireImage { slot: installed });
                    }
                    None => self.count(|c| &mut c.chain_invariant),
                }
            }
        }
        Ok(served)
    }

    /// The held chain of the answered challenge at `slot`.
    fn take_chain(&mut self, slot: SlotRef) -> Option<Chain> {
        let index = self.chains.iter().position(|chain| chain.slot == slot)?;
        Some(self.chains.swap_remove(index))
    }

    /// Records the image installed at `installed`: its first SM is due at
    /// once (S1 installation step 3).
    ///
    /// # Errors
    ///
    /// Without its binding, its chain or an SM slot, the image is not kept
    /// (its owner is dropped); the error holds its `RetireImage` unit, if
    /// any, for the caller to retire it.
    fn install(
        &mut self,
        installed: SlotRef,
        owner: Box<ReceiveOwner>,
        chain: Option<Chain>,
        now: u64,
    ) -> Result<(), Option<Reservation>> {
        let Some(chain) = chain else {
            self.count(|c| &mut c.chain_invariant);
            return Err(None);
        };
        let Some((key, identity)) = self.sessions.binding(installed) else {
            self.count(|c| &mut c.chain_invariant);
            return Err(Some(chain.retire));
        };
        // What its datagrams are validated against.
        let params = TermLength::try_new(chain.term_length)
            .ok()
            .and_then(|term_length| {
                ImageParams::new(
                    key.alias.session_id,
                    key.alias.stream_id,
                    chain.lane_count,
                    term_length,
                    chain.mtu,
                )
                .ok()
            });
        let Some(params) = params else {
            self.count(|c| &mut c.chain_invariant);
            return Err(Some(chain.retire));
        };
        // The image's path statistics: allocated here, once per image, on
        // the session command path; the first path is bound at its joins.
        let mut stats = PathStats::new(
            &self.path_config,
            usize::from(chain.lane_count),
            STAT_TERM_SLOTS,
        );
        if let Some((_, path)) = self.sessions.paths().lookup(key) {
            let joins = path_joins(&chain.joins, chain.term_length);
            stats.path_bound(
                path,
                joins.get(..usize::from(chain.lane_count)).unwrap_or(&[]),
            );
        }
        // S1: an image whose SM slot cannot be reserved is refused.
        let (Some(sm_slot), Some(sm)) = (
            self.to_sender.reserve(),
            self.sm_slots
                .iter()
                .find(|slot| Arc::strong_count(slot) == 1)
                .cloned(),
        ) else {
            return Err(Some(chain.retire));
        };
        // Half a term per SM: aligned, within the wire's window bound.
        let window = (chain.term_length / 2).min(MAX_WINDOW) & !(FRAME_ALIGNMENT - 1);
        let windows = [window; 4];
        let Some(schedule) = windows
            .get(..usize::from(chain.lane_count))
            .and_then(|windows| SmSchedule::new(self.sm_interval, windows).ok())
        else {
            return Err(Some(chain.retire));
        };
        // Its RTT probes, ids drawn now, on the session command path.
        let paths = usize::from(self.path_config.max_paths);
        let Ok(rtt) = RttProbes::new(self.rtt, paths) else {
            return Err(Some(chain.retire));
        };
        let probes = (0..paths)
            .map(|_| PathProbe {
                slot: Arc::new(ProbeSlot::default()),
                pending: None,
            })
            .collect();
        // The table holds a slot for every session, so it has room for
        // every installed image.
        self.images.push(Installed {
            slot: installed,
            owner,
            retire: Some(chain.retire),
            key,
            identity,
            lane_count: chain.lane_count,
            params,
            stats,
            initial_term_id: TermId::new(chain.initial_term_id.cast_unsigned()),
            term_length: chain.term_length,
            heartbeat_marks: [None; 4],
            last_fresh: now,
            window,
            schedule,
            sm_slot: Some(sm_slot),
            sm,
            evidence: now,
            rtt,
            probes,
        });
        Ok(())
    }

    /// The installed images' timers at `now`: retirement at the liveness
    /// timeout (S1 retirement), then the SMs due. Returns the work done.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    fn image_timers(&mut self, sessions: &SessionEnd, now: u64) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Receiver);
        let mut work = 0u32;
        let mut index = 0usize;
        while let Some(image) = self.images.get(index) {
            if age_ns(now, image.evidence) >= self.liveness_timeout {
                let image = self.images.swap_remove(index);
                self.retire(sessions, image, now);
                work = work.checked_add(1).ok_or(overflow.clone())?;
                continue;
            }
            // §3.2 step 5: the receive owner's bounded cleaning.
            let cleaned = self
                .images
                .get_mut(index)
                .is_some_and(|image| image.owner.duty());
            if cleaned {
                work = work.checked_add(1).ok_or(overflow.clone())?;
            }
            let Some(image) = self.images.get(index) else {
                break;
            };
            // Each lane's consumption: its rebuild position, or its least
            // required subscriber's position below it.
            let mut consumption = [0u64; 4];
            for (lane, position) in consumption
                .iter_mut()
                .take(usize::from(image.lane_count))
                .enumerate()
            {
                *position = u8::try_from(lane)
                    .ok()
                    .and_then(|lane| Lane::try_new(lane).ok())
                    .and_then(|lane| image.owner.consumption(lane))
                    .unwrap_or(0);
            }
            let due = self
                .images
                .get_mut(index)
                .and_then(|image| image.schedule.due(now, &consumption));
            if let Some(due) = due {
                self.send_sm(index, &due, now);
                work = work.checked_add(1).ok_or(overflow.clone())?;
            }
            // Its RTTM REQUESTs follow its SM (reliable-transport.md).
            work = work
                .checked_add(self.probe_paths(index, now)?)
                .ok_or(overflow.clone())?;
            index = index.checked_add(1).ok_or(overflow.clone())?;
        }
        Ok(work)
    }

    /// The RTTM REQUESTs due on the bound paths of the image at `index` at
    /// `now` (RC-1): each path's last report is settled first, then one
    /// REQUEST per path and interval goes to the path's source, at most one
    /// per path in the ring. Its probe ids are restocked here, on the timer
    /// step, never per datagram. Returns the REQUESTs handed over.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    fn probe_paths(&mut self, index: usize, now: u64) -> Result<u32, AgentError> {
        let Self {
            images,
            sessions,
            to_sender,
            counters,
            ..
        } = self;
        let Some(image) = images.get_mut(index) else {
            return Ok(0);
        };
        if image.rtt.refill_ids() {
            tally(counters, |c| &mut c.rttm_id_draws);
        }
        let receiver = Receiver {
            receiver_boot_id: sessions.boot_id(),
            receiver_id: receiver_id(image.slot),
        };
        let mut sent = 0u32;
        for (path, probe) in image.probes.iter_mut().enumerate() {
            collect_probe(&mut image.rtt, probe, false);
            let Some(key) = sessions.paths().key(image.slot, path) else {
                continue;
            };
            if probe.slot.busy() {
                continue;
            }
            let Some(due) = image.rtt.due(path, now) else {
                continue;
            };
            probe.pending = Some(due);
            let item = ControlItem::Outgoing {
                endpoint: key.endpoint,
                destination: key.source,
                control: Control::Rttm(Rttm {
                    alias: image.key.alias,
                    identity: image.identity,
                    receiver,
                    probe_id: due.probe_id,
                    kind: RttmKind::Request,
                }),
                guard: Some(ItemGuard::Probe(ProbeGuard::take(&probe.slot))),
            };
            // A dropped item drops its guard: reported not submitted.
            match to_sender.try_post(item) {
                Ok(()) => {
                    tally(counters, |c| &mut c.rttm_requests);
                    sent = sent
                        .checked_add(1)
                        .ok_or(AgentError::CountOverflow(AgentKind::Receiver))?;
                }
                Err(_) => tally(counters, |c| &mut c.ring_full_rttm),
            }
        }
        Ok(sent)
    }

    /// Retires `image` at `now`, in one transition: the binding goes, the
    /// identity is quarantined, the receive owner is dropped, and
    /// `RetireImage` is posted into its reserved unit.
    fn retire(&mut self, sessions: &SessionEnd, image: Installed, now: u64) {
        let Installed {
            slot,
            owner,
            retire,
            ..
        } = image;
        let _ = self.sessions.retire(slot, now);
        drop(owner);
        self.count(|c| &mut c.images_retired);
        match retire {
            // The conductor gone: the driver is stopping.
            Some(unit) => {
                let _ = sessions
                    .events
                    .post(unit, SessionEvent::RetireImage { slot });
            }
            None => self.count(|c| &mut c.chain_invariant),
        }
    }

    /// Sends the SM `due` of the image at `index`: every lane's
    /// consumption, never below what it reported, and window, from the
    /// receiver block of this boot. Only an SM posted to the sender is
    /// recorded as sent; a skipped one stays due.
    fn send_sm(&mut self, index: usize, due: &SmDue, now: u64) {
        let boot_id = self.sessions.boot_id();
        let Some(image) = self.images.get_mut(index) else {
            return;
        };
        let mut entries = [LaneStatus::default(); 4];
        let count = usize::from(image.lane_count);
        for (entry, consumption) in entries.iter_mut().take(count).zip(due.consumption) {
            *entry = LaneStatus {
                consumption,
                window: image.window,
            };
        }
        let Some(lanes) = entries
            .get(..count)
            .and_then(|lanes| Lanes::new(lanes).ok())
        else {
            return;
        };
        let receiver_id = receiver_id(image.slot);
        let status = StatusMessage {
            alias: image.key.alias,
            identity: image.identity,
            receiver: Receiver {
                receiver_boot_id: boot_id,
                receiver_id,
            },
            group_tag: 0,
            lanes,
        };
        // One slot per image (S1): a period whose previous SM still waits
        // is skipped, never given a second slot.
        if image.sm.busy() {
            self.count(|c| &mut c.sm_skipped);
            return;
        }
        let slot = image.sm_slot.take().or_else(|| self.to_sender.reserve());
        let Some(slot) = slot else {
            self.count(|c| &mut c.sm_skipped);
            return;
        };
        let item = ControlItem::Outgoing {
            endpoint: image.key.endpoint,
            destination: image.key.source,
            control: Control::Status(status),
            guard: Some(ItemGuard::Sm(SmGuard::take(&image.sm))),
        };
        // The sender gone: the driver is stopping. The SM is then recorded
        // as sent all the same: nothing will send another.
        let _ = self.to_sender.post(slot, item);
        if let Some(image) = self.images.get_mut(index) {
            image.schedule.sent(due, now);
        }
        self.count(|c| &mut c.sm_sent);
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> ReceiverCounters {
        self.counters
    }

    fn count(&mut self, field: fn(&mut ReceiverCounters) -> &mut u64) {
        let mut overflowed = self.counters.overflowed;
        bump(field(&mut self.counters), &mut overflowed);
        self.counters.overflowed = overflowed;
    }

    /// One cycle: the session timers, then every held RX half.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub(super) fn duty<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        sessions: &SessionEnd,
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Receiver);
        // A lost path stops being charged in its image's statistics from
        // the terms it was lost in (RP-6). The term is the contiguous
        // prefix's, deliberately: frames above a hole put the cut at the
        // hole, which charges the lost path less, never more.
        let images = &mut self.images;
        let mut work = self.sessions.timers_with(now, |slot, path, _| {
            if let Some(image) = images.iter_mut().find(|image| image.slot == slot) {
                let mut terms = [0u64; 4];
                for (lane, term) in terms.iter_mut().enumerate() {
                    *term = u8::try_from(lane)
                        .ok()
                        .and_then(|lane| Lane::try_new(lane).ok())
                        .and_then(|lane| image.owner.rebuild_position(lane))
                        .and_then(|position| position.checked_div(u64::from(image.term_length)))
                        .unwrap_or(0);
                }
                let lanes = usize::from(image.lane_count);
                image
                    .stats
                    .path_lost(path, terms.get(..lanes).unwrap_or(&[]));
                // A path bound again starts from `rtt_initial`; a report
                // of the lost binding's probe no longer matches.
                image.rtt.rebind(path);
            }
        });
        work = work
            .checked_add(self.image_timers(sessions, now)?)
            .ok_or(overflow.clone())?;
        for (endpoint, half) in halves.iter_mut() {
            let Half::Rx(rx) = half else {
                continue;
            };
            let budget = self.budget;
            let mut intake = Intake {
                endpoint: *endpoint,
                now,
                role: self,
                sessions,
                work: 0,
            };
            let _ = rx.poll_rx(budget, &mut intake);
            work = work.checked_add(intake.work).ok_or(overflow.clone())?;
        }
        Ok(work)
    }
}

/// The receiver's handler of one endpoint's datagrams.
struct Intake<'a> {
    endpoint: EndpointId,
    now: u64,
    role: &'a mut ReceiverRole,
    sessions: &'a SessionEnd,
    /// Datagrams read; one poll reads at most its budget's.
    work: u32,
}

impl Intake<'_> {
    /// Hands `item` to the sender; a full ring drops it, counted per kind
    /// so that a flood of one kind does not hide another.
    fn forward(&mut self, item: ControlItem) {
        let full: fn(&mut ReceiverCounters) -> &mut u64 = match item {
            ControlItem::Outgoing { .. } => |c| &mut c.ring_full_rsp_setup,
            ControlItem::Incoming {
                control: Control::Solicit(_),
                ..
            } => |c| &mut c.ring_full_solicit,
            ControlItem::Incoming {
                control: Control::Rttm(_),
                ..
            } => |c| &mut c.ring_full_rttm_request,
            ControlItem::Incoming { .. } => |c| &mut c.ring_full_challenge,
        };
        match self.role.to_sender.try_post(item) {
            Ok(()) => self.role.count(|c| &mut c.forwarded),
            Err(_) => self.role.count(full),
        }
    }

    /// An RTTM REPLY from `source` (RC-1): only from a bound path of an
    /// image it names exactly (identity and this receiver). The path's
    /// last REQUEST report is settled first, so a REPLY that overtakes the
    /// collection still matches; the sample ends at the clock read here,
    /// at validation.
    fn rttm_reply(&mut self, source: SocketAddr, rttm: &Rttm) {
        let key = BindingKey {
            endpoint: self.endpoint,
            source,
            alias: rttm.alias,
        };
        let boot_id = self.role.sessions.boot_id();
        let found = self
            .role
            .sessions
            .paths()
            .lookup(key)
            .and_then(|(slot, path)| {
                let index = self.role.images.iter().position(|image| {
                    image.slot == slot
                        && image.identity == rttm.identity
                        && rttm.receiver
                            == Receiver {
                                receiver_boot_id: boot_id,
                                receiver_id: receiver_id(slot),
                            }
                })?;
                Some((index, path))
            });
        let Some((index, path)) = found else {
            self.role.count(|c| &mut c.rttm_replies_unbound);
            return;
        };
        let seen = (self.role.clock)();
        let Some(image) = self.role.images.get_mut(index) else {
            return;
        };
        if let Some(probe) = image.probes.get_mut(path) {
            collect_probe(&mut image.rtt, probe, true);
        }
        let outcome = match image.rtt.generation(path) {
            Some(generation) => image.rtt.reply(path, generation, rttm.probe_id, seen),
            None => ReplyOutcome::Ignored,
        };
        match outcome {
            ReplyOutcome::Sample(_) => self.role.count(|c| &mut c.rttm_samples),
            ReplyOutcome::Ignored => self.role.count(|c| &mut c.rttm_replies_ignored),
        }
    }

    /// A DATA datagram from `source` (§3.2 step 2): only through its
    /// binding (the first path's key or a later path's, RP-1), rechecked
    /// active, validated against the image's parameters, each frame
    /// committed by the receive owner. Fresh evidence (a committed frame or
    /// a heartbeat) keeps the image and the path alive. Nothing allocates.
    fn data(&mut self, source: SocketAddr, alias: Alias, bytes: &[u8]) {
        let key = BindingKey {
            endpoint: self.endpoint,
            source,
            alias,
        };
        let role = &mut *self.role;
        // The session table's admission rule (a live path's key, or the
        // founding key of an image with no path rows), then the path's
        // index for its statistics.
        let bound = role.sessions.lookup(&key);
        let path = role.sessions.paths().lookup(key);
        let found = bound.and_then(|slot| {
            role.images
                .iter()
                .position(|image| image.slot == slot && role.sessions.is_active(slot))
        });
        let Some(image) = found.and_then(|index| role.images.get_mut(index)) else {
            role.count(|c| &mut c.data_unbound);
            return;
        };
        let Ok(datagram) = ValidatedDatagram::parse(bytes, &image.params) else {
            role.count(|c| &mut c.data_invalid);
            return;
        };
        // Per item: committed, dropped, refused, then fresh, stale,
        // stationary and rejected heartbeats. A datagram holds at most an
        // MTU of 32-byte records: no overflow.
        let mut outcomes = [0u32; 7];
        let mut path_fresh = false;
        for item in datagram.items() {
            let (outcome, arrival) = match item {
                Item::Frame(frame) => {
                    let delivered = delivered(image, &frame, path, self.now);
                    match image.owner.receive(&frame) {
                        Ok(Received::Committed { position, extent }) => {
                            // The heartbeat mark rises with committed data
                            // too: a replayed older heartbeat after a data
                            // period is never fresh.
                            let end = position.checked_add(u64::from(extent));
                            let lane = usize::from(frame.lane().get());
                            if let (Some(end), Some(mark)) =
                                (end, image.heartbeat_marks.get_mut(lane))
                            {
                                *mark = Some(mark.map_or(end, |seen| seen.max(end)));
                            }
                            (0, Some((delivered, Arrival::First)))
                        }
                        Ok(Received::Duplicate) => (1, Some((delivered, Arrival::Duplicate))),
                        Ok(Received::Late) => (1, Some((delivered, Arrival::Late))),
                        Ok(_) => (1, None),
                        Err(ReceiveError::Conflict { .. }) => {
                            (2, Some((delivered, Arrival::Conflict)))
                        }
                        Err(_) => (2, None),
                    }
                }
                // A heartbeat is image evidence only inside the receive
                // window and above the last one seen on its lane, so a
                // replay keeps nothing alive (network-sessions.md, owner P2).
                // It is never path evidence (RP-2: fresh frames and PATH_HB).
                Item::Heartbeat(heartbeat) => match classify_heartbeat(image, &heartbeat) {
                    HeartbeatClass::Fresh => (3, None),
                    HeartbeatClass::Stale => (4, None),
                    HeartbeatClass::Stationary => (5, None),
                    HeartbeatClass::Rejected => (6, None),
                },
            };
            if let Some((Some(delivered), arrival)) = arrival {
                let fresh = image.stats.arrived(delivered, arrival);
                // A conflicting copy is recorded, never path evidence.
                path_fresh |= fresh && arrival != Arrival::Conflict;
            }
            if let Some(count) = outcomes.get_mut(outcome)
                && let Some(next) = count.checked_add(1)
            {
                *count = next;
            }
        }
        let fields: [fn(&mut ReceiverCounters) -> &mut u64; 7] = [
            |c| &mut c.data_committed,
            |c| &mut c.data_dropped,
            |c| &mut c.data_refused,
            |c| &mut c.heartbeats,
            |c| &mut c.heartbeats_stale,
            |c| &mut c.heartbeats_stationary,
            |c| &mut c.heartbeats_rejected,
        ];
        let fresh = outcomes.first().is_some_and(|committed| *committed > 0)
            || outcomes.get(3).is_some_and(|heartbeats| *heartbeats > 0);
        // Image liveness, trusted profile (coordinator decision; an
        // authenticated channel still needs its profile's freshness proof):
        // fresh evidence (a committed frame or a heartbeat above the lane's
        // highest seen position) keeps the image alive; an idle sender's
        // stationary heartbeats keep it alive only until
        // `idle_image_timeout` after the last fresh evidence; a replay keeps
        // nothing alive.
        let stationary = outcomes.get(5).is_some_and(|count| *count > 0);
        apply_evidence(image, fresh, stationary, self.now, role.idle_timeout);
        if path_fresh && let Some((slot, path)) = path {
            // Fresh evidence on the path refreshes its liveness (RP-2),
            // never the image's.
            let _ = role.sessions.paths_mut().refresh(slot, path, self.now);
        }
        for (field, count) in fields.into_iter().zip(outcomes) {
            for _ in 0..count {
                role.count(field);
            }
        }
    }

    /// Sends `challenge` toward `source` if §7.3 and §7.4 allow it.
    fn challenge(&mut self, source: SocketAddr, control: Control) {
        // §7.3: an RSP_SETUP goes only to the trigger's validated source
        // endpoint, through the socket it arrived on.
        if !answerable(source) {
            self.role.count(|c| &mut c.unanswerable_source);
            return;
        }
        // §7.4: per destination, then per driver.
        match self.role.rsp_destinations.admit(source, self.now) {
            Ok(()) => {}
            Err(RateRefused::Limited) => {
                self.role.count(|c| &mut c.rsp_setup_rate_limited);
                return;
            }
            Err(RateRefused::TableFull) => {
                self.role.count(|c| &mut c.rsp_setup_destinations_full);
                return;
            }
        }
        if !self.role.rsp_total.admit(self.now) {
            self.role.count(|c| &mut c.rsp_setup_total_limited);
            return;
        }
        self.forward(ControlItem::Outgoing {
            endpoint: self.endpoint,
            destination: source,
            control,
            guard: None,
        });
    }

    fn control(&mut self, source: SocketAddr, control: Control) {
        let endpoint = self.endpoint;
        let now = self.now;
        match control {
            Control::SetupAnnounce(announce) => {
                // §6.2 step 2: only a stream subscribed on this endpoint.
                let Some(max_term_length) = self
                    .role
                    .subscriptions
                    .iter()
                    .find(|(held, stream, _)| {
                        (*held, *stream) == (endpoint, announce.alias.stream_id)
                    })
                    .map(|(.., max)| *max)
                else {
                    self.role.count(|c| &mut c.unsubscribed);
                    return;
                };
                // An image larger than the subscription accepts is never
                // challenged, so never allocated (S1 storage budget).
                if announce.term.term_length > max_term_length {
                    self.role.count(|c| &mut c.term_too_large);
                    return;
                }
                let key = BindingKey {
                    endpoint,
                    source,
                    alias: announce.alias,
                };
                let role = &mut *self.role;
                if let AnnounceOutcome::Challenge(challenge) =
                    role.sessions
                        .announce(key, &announce, now, &mut role.nonces)
                {
                    self.challenge(source, Control::Challenge(challenge));
                }
            }
            Control::SetupAnswer(answer) => {
                let key = BindingKey {
                    endpoint,
                    source,
                    alias: answer.alias,
                };
                // S1: the whole chain is reserved before the challenge is
                // marked answered; without it the answer is dropped and the
                // challenge stays pending.
                let mut reserved = None;
                let sessions = self.sessions;
                let outcome = self.role.sessions.answer(key, &answer, now, || {
                    reserved = reserve_chain(sessions);
                    reserved.is_some()
                });
                if let (
                    AnswerOutcome::CreateImage {
                        slot,
                        identity,
                        term,
                        joins,
                    },
                    Some((create, retire, chain)),
                ) = (outcome, reserved)
                {
                    let event = SessionEvent::CreateImage {
                        endpoint,
                        alias: answer.alias,
                        slot,
                        identity,
                        term,
                        joins,
                        chain,
                    };
                    // At most one per session slot, so within `max_images`.
                    self.role.chains.push(Chain {
                        slot,
                        retire,
                        lane_count: joins.count(),
                        term_length: term.term_length,
                        mtu: term.mtu,
                        initial_term_id: term.initial_term_id,
                        joins,
                    });
                    // The conductor gone: the driver is stopping.
                    let _ = sessions.events.post(create, event);
                    self.role.count(|c| &mut c.create_image);
                }
                if let AnswerOutcome::PathBound { image, path } = outcome {
                    self.role.count(|c| &mut c.paths_bound);
                    // The later path is charged and its freshness tracked
                    // from its own joins (RP-1).
                    let joins = self.role.sessions.paths().joins(image, path);
                    if let (Some(joins), Some(installed)) = (
                        joins,
                        self.role.images.iter_mut().find(|held| held.slot == image),
                    ) {
                        let joins = path_joins(&joins, installed.term_length);
                        installed.stats.path_bound(
                            path,
                            joins
                                .get(..usize::from(installed.lane_count))
                                .unwrap_or(&[]),
                        );
                    }
                }
            }
            Control::PathHeartbeat(heartbeat) => {
                let key = BindingKey {
                    endpoint,
                    source,
                    alias: heartbeat.alias,
                };
                // It refreshes only its own bound path; it creates nothing.
                match self.role.sessions.paths_mut().path_hb(key, now) {
                    Some(_) => self.role.count(|c| &mut c.path_heartbeats),
                    None => self.role.count(|c| &mut c.path_heartbeats_unbound),
                }
            }
            Control::Challenge(_) | Control::Solicit(_) | Control::Status(_) => {
                let alias = match control {
                    Control::Challenge(challenge) => challenge.alias,
                    Control::Solicit(solicit) => solicit.alias,
                    Control::Status(status) => status.alias,
                    _ => return,
                };
                // Only for a publication of this endpoint (DN-4 pre-filter).
                if !self.role.published.contains(&(endpoint, alias)) {
                    self.role.count(|c| &mut c.not_published);
                    return;
                }
                self.forward(ControlItem::Incoming {
                    endpoint,
                    source,
                    control,
                    seen: now,
                });
            }
            Control::Rttm(rttm) => match rttm.kind {
                // A REQUEST for a local publication: the sender replies.
                RttmKind::Request => {
                    if !self.role.published.contains(&(endpoint, rttm.alias)) {
                        self.role.count(|c| &mut c.not_published);
                        return;
                    }
                    self.forward(ControlItem::Incoming {
                        endpoint,
                        source,
                        control,
                        seen: now,
                    });
                }
                RttmKind::Reply { .. } => self.rttm_reply(source, &rttm),
            },
            _ => self.role.count(|c| &mut c.unhandled),
        }
    }
}

impl RxHandler for Intake<'_> {
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
        // At most the poll budget's datagrams: no overflow.
        self.work += 1;
        self.role.count(|c| &mut c.datagrams);
        let source = datagram.source();
        match classify(datagram.bytes()) {
            Ok(Datagram::Control(control)) => self.control(source, control),
            Ok(Datagram::DataBatch(data) | Datagram::Heartbeat(data)) => {
                self.data(source, data.alias(), data.bytes());
            }
            Err(_) => self.role.count(|c| &mut c.decode_errors),
        }
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, _drop: RxDrop) {
        self.role.count(|c| &mut c.backend_drops);
    }
}

impl SenderRole {
    /// The counters.
    #[must_use]
    pub fn counters(&self) -> SenderCounters {
        self.counters
    }

    /// The SETUP side's counters.
    #[must_use]
    pub fn session_counters(&self) -> crate::sessions::send::SendCounters {
        self.sessions.counters()
    }

    /// The data path of its `index`-th publication (tests).
    #[cfg(test)]
    pub(crate) fn outbound(&self, index: usize) -> Option<&Outbound> {
        self.publications.get(index)
    }

    /// The data path of its `index`-th publication, mutable (tests).
    #[cfg(test)]
    pub(crate) fn outbound_mut(&mut self, index: usize) -> Option<&mut Outbound> {
        self.publications.get_mut(index)
    }

    fn count(&mut self, field: fn(&mut SenderCounters) -> &mut u64) {
        let mut overflowed = self.counters.overflowed;
        bump(field(&mut self.counters), &mut overflowed);
        self.counters.overflowed = overflowed;
    }

    /// The sender's commands: `AddPublication`; the receiver's are
    /// answered `Unsupported`.
    pub(super) fn command<O: SocketOps>(
        &mut self,
        command: AgentCommand<O>,
    ) -> Option<(Reservation, AgentEvent<O>)> {
        let (reply, publication, outbound) = match command {
            AgentCommand::AddPublication {
                reply,
                publication,
                outbound,
            } => (reply, publication, outbound),
            AgentCommand::AddSubscription { reply, .. }
            | AgentCommand::AddPublishedAlias { reply, .. } => {
                return Some((
                    reply,
                    AgentEvent::Unsupported {
                        agent: AgentKind::Sender,
                    },
                ));
            }
            command => return self.trace.command(&mut self.publications, command),
        };
        let mut outbound = outbound;
        let matches = outbound.endpoint() == publication.endpoint
            && outbound.alias() == publication.alias
            && outbound.readers().len() == usize::from(publication.lane_count);
        // Its receivers' membership (multicast-flow-control.md): windows
        // from the largest datagram to half a term, as receivers grant, and
        // the driver's SM cadence and liveness; roles and tags are not
        // configurable yet, so no required member and the creation time (it
        // only times a required member's join) is 0.
        let max_window =
            (publication.term.term_length / 2).min(MAX_WINDOW) & !(FRAME_ALIGNMENT - 1);
        let membership = u32::try_from(outbound.max_frame())
            .ok()
            .and_then(|min_window| {
                Membership::new(
                    self.membership
                        .config(publication.lane_count, min_window, max_window),
                    publication.identity,
                    publication.alias,
                    &Roles::default(),
                    0,
                )
                .ok()
            });
        let added = match membership {
            Some(membership) if matches => {
                outbound.attach_membership(Box::new(membership));
                self.sessions.add(publication)
            }
            _ => Err(SendSessionError::InvalidConfig),
        };
        let event = match added {
            Ok(()) => {
                // `add` refuses past `publications` entries, the capacity.
                self.publications.push(*outbound);
                AgentEvent::PublicationAdded {
                    endpoint: publication.endpoint,
                    alias: publication.alias,
                }
            }
            Err(
                SendSessionError::Full
                | SendSessionError::DuplicateAlias
                | SendSessionError::InvalidConfig,
            ) => AgentEvent::PublicationRefused {
                agent: AgentKind::Sender,
                endpoint: publication.endpoint,
                alias: publication.alias,
            },
        };
        Some((reply, event))
    }

    /// Frees the route slots of endpoints the agent no longer holds: their
    /// cached ids belong to a half that was handed back.
    fn prune<O: SocketOps>(&mut self, halves: &[(EndpointId, Half<O>)]) {
        for slot in &mut self.routes {
            if let Some(endpoint) = slot.endpoint
                && !halves
                    .iter()
                    .any(|(held, half)| *held == endpoint && matches!(half, Half::Tx(_)))
            {
                slot.endpoint = None;
                slot.routes.clear();
            }
        }
    }

    /// Sends `control` on `endpoint` to `destination`.
    fn send<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
    ) -> bool {
        let tx = halves.iter_mut().find_map(|(held, half)| match half {
            Half::Tx(tx) if *held == endpoint => Some(tx),
            _ => None,
        });
        let Some(tx) = tx else {
            self.count(|c| &mut c.no_endpoint);
            return false;
        };
        let index = self
            .routes
            .iter()
            .position(|slot| slot.endpoint == Some(endpoint))
            .or_else(|| self.routes.iter().position(|slot| slot.endpoint.is_none()));
        let Some(slot) = index.and_then(|index| self.routes.get_mut(index)) else {
            // More held halves than slots: the agent holds at most
            // `max_endpoints`, so this does not happen.
            self.count(|c| &mut c.no_endpoint);
            return false;
        };
        slot.endpoint = Some(endpoint);
        match slot.routes.send(tx, destination, control) {
            Ok(()) => {
                self.count(|c| &mut c.sent);
                true
            }
            Err(_) => {
                self.count(|c| &mut c.send_failures);
                false
            }
        }
    }

    /// The publication's channel destination and join points.
    fn route_of(&self, endpoint: EndpointId, alias: Alias) -> Option<(SocketAddr, Lanes<u64>)> {
        let outbound = self
            .publications
            .iter()
            .find(|outbound| outbound.endpoint() == endpoint && outbound.alias() == alias)?;
        Some((outbound.destination(), outbound.joins()?))
    }

    /// One cycle: the controls the receiver handed over, then the
    /// announcements due.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub(super) fn duty<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        self.cycle = self.cycle.checked_add(1).ok_or(overflow.clone())?;
        self.prune(halves);
        // Bindings past their lifetime go even when nothing arrives.
        self.expire_bindings(now);
        let mut work = 0u32;
        for _ in 0..self.budget {
            let Ok(Some(item)) = self.from_receiver.try_take() else {
                break;
            };
            work = work.checked_add(1).ok_or(overflow.clone())?;
            match item {
                // §7.3: an RSP_SETUP to the trigger's validated source,
                // checked by the receiver.
                // An SM's guard drops after the send, freeing its slot.
                // An RTTM REQUEST's start is read immediately before the
                // backend call, and reported only if it submitted (RC-1).
                ControlItem::Outgoing {
                    endpoint,
                    destination,
                    control,
                    guard: Some(ItemGuard::Probe(guard)),
                } => {
                    let mut guard = guard;
                    guard.sending((self.clock)());
                    if self.send(halves, endpoint, destination, &control) {
                        guard.submitted();
                    }
                }
                ControlItem::Outgoing {
                    endpoint,
                    destination,
                    control,
                    guard,
                } => {
                    let _ = self.send(halves, endpoint, destination, &control);
                    drop(guard);
                }
                ControlItem::Incoming {
                    endpoint,
                    source,
                    control: Control::Status(status),
                    ..
                } => self.status(endpoint, source, &status, now),
                ControlItem::Incoming {
                    endpoint,
                    source,
                    control: Control::Rttm(request),
                    seen,
                } => {
                    if let Some(reply) = self.rttm_request(endpoint, source, &request, seen, now)
                        && self.send(halves, endpoint, source, &Control::Rttm(reply))
                    {
                        self.count(|c| &mut c.rttm_replied);
                    }
                }
                ControlItem::Incoming {
                    endpoint,
                    source,
                    control,
                    ..
                } => {
                    if let Some((destination, answer)) =
                        self.answer_for(endpoint, source, now, control)
                    {
                        let _ = self.send(halves, endpoint, destination, &answer);
                    }
                }
            }
        }
        let mut due = std::mem::take(&mut self.due);
        self.sessions
            .announce_due(now, |endpoint, announce| due.push((endpoint, announce)));
        for (endpoint, announce) in due.drain(..) {
            // An ANNOUNCE goes to the channel's configured destination
            // (§6.2).
            if let Some((destination, _)) = self.route_of(endpoint, announce.alias) {
                work = work.checked_add(1).ok_or(overflow.clone())?;
                let _ = self.send(
                    halves,
                    endpoint,
                    destination,
                    &Control::SetupAnnounce(announce),
                );
            }
        }
        // Its capacity stays for the next cycle.
        self.due = due;
        // First sends (§3.1 step 8), only after establishment (§4.3).
        let mut needing_reset = 0u64;
        for index in 0..self.publications.len() {
            let Some(outbound) = self.publications.get(index) else {
                break;
            };
            let (endpoint, alias) = (outbound.endpoint(), outbound.alias());
            if !self.sessions.is_established(endpoint, alias) {
                continue;
            }
            let consumption = self.consumption(endpoint, alias);
            let tx = halves.iter_mut().find_map(|(held, half)| match half {
                Half::Tx(tx) if *held == endpoint => Some(tx),
                _ => None,
            });
            let (Some(tx), Some(outbound)) = (tx, self.publications.get_mut(index)) else {
                continue;
            };
            let lanes = outbound.readers().len();
            let served = outbound.serve_traced(
                tx,
                DATA_BUDGET,
                consumption
                    .as_ref()
                    .and_then(|positions| positions.get(..lanes)),
                now,
                self.trace.hook(),
            )?;
            work = work.checked_add(served).ok_or(overflow.clone())?;
            if outbound.needs_reset() {
                needing_reset = needing_reset.checked_add(1).ok_or(overflow.clone())?;
            }
        }
        self.counters.needs_reset = needing_reset;
        Ok(work)
    }

    /// Asks for the reset of each endpoint a publication needs reset on,
    /// through `post` (which returns whether the request was posted): at
    /// most once per [`RESET_REQUEST_CYCLES`](super::data::RESET_REQUEST_CYCLES)
    /// per publication while the need holds. The cadence is per
    /// publication, so `N` publications on one endpoint post up to `N`
    /// requests per period; the endpoint table resets once and ignores the
    /// others while the reset is in flight. Nothing allocates.
    pub(super) fn request_resets(&mut self, mut post: impl FnMut(EndpointId) -> bool) {
        let cycle = self.cycle;
        for index in 0..self.publications.len() {
            let Some(outbound) = self.publications.get_mut(index) else {
                break;
            };
            if !outbound.reset_request_due(cycle) {
                continue;
            }
            if post(outbound.endpoint()) {
                outbound.reset_request_posted(cycle);
                self.count(|c| &mut c.reset_requests);
            } else {
                self.count(|c| &mut c.reset_requests_full);
            }
        }
    }

    /// The least position every receiver bound to `alias` on `endpoint`
    /// consumed, per lane: a reliable channel's bound (SPEC §4). A receiver
    /// answered but not yet heard from bounds at its join points. `None`
    /// with no bound receiver at all: a reliable lane then holds.
    fn consumption(&self, endpoint: EndpointId, alias: Alias) -> Option<[u64; 4]> {
        let mut least: Option<[u64; 4]> = None;
        for binding in &self.bindings {
            if binding.endpoint != endpoint || binding.alias != alias {
                continue;
            }
            let positions = least.get_or_insert([u64::MAX; 4]);
            match binding.lanes {
                Some(lanes) => {
                    for (position, status) in positions.iter_mut().zip(lanes.as_slice()) {
                        *position = (*position).min(status.consumption);
                    }
                }
                None => {
                    for (position, join) in positions.iter_mut().zip(binding.joins.as_slice()) {
                        *position = (*position).min(*join);
                    }
                }
            }
        }
        least
    }

    /// Records the receiver `answer` goes to: its challenge's `source` on
    /// `endpoint` and its boot id, where its SMs must come from.
    ///
    /// A new answer to a known tuple starts it over: unconfirmed, with no
    /// receiver id or status, so a reinstalled image binds again. A full
    /// table evicts its oldest unconfirmed binding first; one full of
    /// confirmed bindings refuses and counts.
    fn bind(&mut self, endpoint: EndpointId, source: SocketAddr, answer: &SetupAnswer, now: u64) {
        self.expire_bindings(now);
        let binding = ReceiverBinding {
            endpoint,
            alias: answer.alias,
            source: normalized(source),
            boot_id: answer.challenge.receiver_boot_id,
            identity: answer.identity,
            receiver_id: None,
            former: None,
            lanes: None,
            joins: answer.joins,
            answered_at: now,
            last_sm: None,
        };
        let tuple = |held: &ReceiverBinding| {
            (
                held.endpoint,
                held.alias,
                held.source,
                held.boot_id,
                held.identity,
            )
        };
        if let Some(held) = self
            .bindings
            .iter_mut()
            .find(|held| tuple(held) == tuple(&binding))
        {
            // The same receiver again: its consumption never moves back,
            // and the receiver id it had is remembered for the next SM.
            let lanes = held.lanes;
            let former = held.receiver_id.or(held.former);
            *held = ReceiverBinding {
                lanes,
                former,
                ..binding
            };
            return;
        }
        if self.bindings.len() >= self.max_bindings {
            let oldest = self
                .bindings
                .iter()
                .enumerate()
                .filter(|(_, held)| held.last_sm.is_none())
                .min_by_key(|(_, held)| held.answered_at)
                .map(|(index, _)| index);
            let Some(index) = oldest else {
                self.count(|c| &mut c.bindings_full);
                return;
            };
            let evicted = self.bindings.swap_remove(index);
            self.count(|c| &mut c.bindings_evicted);
            // A reset row keeps its former receiver id until its next SM:
            // that membership ends with the row (ACS 15648).
            if let Some(receiver_id) = evicted.receiver_id.or(evicted.former) {
                self.binding_gone(&evicted, receiver_id, now);
            }
        }
        self.bindings.push(binding);
    }

    /// Removes the bindings past their lifetime at `now`: an unconfirmed
    /// one after `setup_challenge_timeout`, a confirmed one with no SM for
    /// `image_liveness_timeout` (its image is retired by then).
    fn expire_bindings(&mut self, now: u64) {
        let (unconfirmed, confirmed) = (self.unconfirmed_timeout, self.confirmed_timeout);
        let mut index = 0usize;
        while let Some(binding) = self.bindings.get(index) {
            let live = match binding.last_sm {
                None => age_ns(now, binding.answered_at) < unconfirmed,
                Some(last) => age_ns(now, last) < confirmed,
            };
            if live {
                let Some(next) = index.checked_add(1) else {
                    break;
                };
                index = next;
                continue;
            }
            let binding = self.bindings.swap_remove(index);
            self.count(|c| &mut c.bindings_expired);
            // Synchronously, at the removal (ACS 15648); a reset row that
            // expires before its next SM ends its former receiver's.
            if let Some(receiver_id) = binding.receiver_id.or(binding.former) {
                self.binding_gone(&binding, receiver_id, now);
            }
        }
    }

    /// Tells `binding`'s publication that the binding of receiver
    /// `receiver_id` is gone (ACS 15648): its membership ends with its last
    /// binding.
    fn binding_gone(&mut self, binding: &ReceiverBinding, receiver_id: u64, now: u64) {
        let key = SmKey {
            endpoint: binding.endpoint,
            alias: binding.alias,
            source: binding.source,
            identity: binding.identity,
            receiver: Receiver {
                receiver_boot_id: binding.boot_id,
                receiver_id,
            },
        };
        if let Some(membership) = self
            .publications
            .iter_mut()
            .find(|outbound| outbound.endpoint() == key.endpoint && outbound.alias() == key.alias)
            .and_then(Outbound::membership_mut)
        {
            let _ = membership.binding_gone(&key, now);
        }
    }

    /// The REPLY to an RTTM `request` from `source`, seen at `seen` (RC-1):
    /// only for a receiver this sender answered on that endpoint, naming the
    /// publication's incarnation and its receiver id, within
    /// `rttm_reply_rate` per source. It echoes the probe id; its
    /// `service_delay_ns` is a bounded diagnostic the receiver never
    /// subtracts. The reply goes back to the REQUEST's source.
    fn rttm_request(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        request: &Rttm,
        seen: u64,
        now: u64,
    ) -> Option<Rttm> {
        self.expire_bindings(now);
        let normal = normalized(source);
        let Some(binding) = self.bindings.iter().find(|binding| {
            binding.endpoint == endpoint
                && binding.alias == request.alias
                && binding.source == normal
                && binding.boot_id == request.receiver.receiver_boot_id
                && binding.identity == request.identity
        }) else {
            self.count(|c| &mut c.rttm_unbound);
            return None;
        };
        let matches = binding
            .receiver_id
            .is_none_or(|id| id == request.receiver.receiver_id);
        if !matches {
            self.count(|c| &mut c.rttm_mismatch);
            return None;
        }
        if !self.replies.admit(normal, now) {
            self.count(|c| &mut c.rttm_refused);
            return None;
        }
        Some(Rttm {
            kind: RttmKind::Reply {
                service_delay_ns: RttReplies::service_delay(seen, (self.clock)()),
            },
            ..*request
        })
    }

    /// RTTM REQUESTs dropped over their source's rate, and dropped with the
    /// source table full.
    #[must_use]
    pub fn rttm_reply_drops(&self) -> (u64, u64) {
        (self.replies.dropped(), self.replies.sources_full())
    }

    /// An SM from `source` on `endpoint` (network-control-schemas.md §6.1):
    /// accepted only from a receiver this sender answered there, with the
    /// answered identity, the publication's lane count and, after the first,
    /// the same receiver id. The first accepted SM establishes the
    /// publication: its SETUP stops.
    fn status(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        status: &StatusMessage,
        now: u64,
    ) {
        self.expire_bindings(now);
        let source = normalized(source);
        let lane_count = self
            .publications
            .iter()
            .find(|outbound| outbound.endpoint() == endpoint && outbound.alias() == status.alias)
            .and_then(|outbound| u8::try_from(outbound.readers().len()).ok());
        // The incarnation is part of the binding: an earlier incarnation's
        // row from the same receiver never shadows the current one.
        let found = self.bindings.iter_mut().find(|binding| {
            binding.endpoint == endpoint
                && binding.alias == status.alias
                && binding.source == source
                && binding.boot_id == status.receiver.receiver_boot_id
                && binding.identity == status.identity
        });
        let Some(binding) = found else {
            self.count(|c| &mut c.sm_unbound);
            return;
        };
        let matches = binding.identity == status.identity
            && lane_count == Some(status.lanes.count())
            && binding
                .receiver_id
                .is_none_or(|id| id == status.receiver.receiver_id);
        if !matches {
            self.count(|c| &mut c.sm_mismatch);
            return;
        }
        // A reset binding whose next SM names another receiver: the former
        // one's membership ends first (ACS 15648).
        let gone = match (binding.receiver_id, binding.former.take()) {
            (None, Some(former)) if former != status.receiver.receiver_id => Some(former),
            _ => None,
        };
        let held = *binding;
        binding.receiver_id = Some(status.receiver.receiver_id);
        binding.last_sm = Some(now);
        // Consumption only moves forward: a replayed or reordered SM keeps
        // the higher value per lane, and is counted.
        let mut stale = false;
        let lanes = match binding.lanes {
            None => status.lanes,
            Some(held) => {
                let mut kept = [LaneStatus::default(); 4];
                for ((slot, old), new) in kept
                    .iter_mut()
                    .zip(held.as_slice())
                    .zip(status.lanes.as_slice())
                {
                    if new.consumption < old.consumption {
                        stale = true;
                        *slot = *old;
                    } else {
                        *slot = *new;
                    }
                }
                kept.get(..held.as_slice().len())
                    .and_then(|kept| Lanes::new(kept).ok())
                    .unwrap_or(held)
            }
        };
        binding.lanes = Some(lanes);
        let _ = self.sessions.status(endpoint, status);
        self.count(|c| &mut c.sm_accepted);
        if stale {
            self.count(|c| &mut c.sm_stale);
        }
        if let Some(former) = gone {
            self.binding_gone(&held, former, now);
        }
        // Accepted here, the SM goes to the publication's membership.
        let key = SmKey {
            endpoint,
            alias: status.alias,
            source,
            identity: status.identity,
            receiver: status.receiver,
        };
        if let Some(membership) = self
            .publications
            .iter_mut()
            .find(|outbound| outbound.endpoint() == endpoint && outbound.alias() == status.alias)
            .and_then(Outbound::membership_mut)
        {
            let _ = membership.status(&key, status, now);
        }
    }

    /// The SETUP ANSWER to a received control, and where it goes: §7.3 and
    /// §6.2/§6.3, an ANSWER follows the channel's configured route (the
    /// unicast endpoint, or the group on multicast), never the trigger's
    /// source, so a spoofed CHALLENGE or SOLICIT cannot steer it.
    fn answer_for(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        now: u64,
        control: Control,
    ) -> Option<(SocketAddr, Control)> {
        let alias = match control {
            Control::Challenge(challenge) => challenge.alias,
            Control::Solicit(solicit) => solicit.alias,
            _ => return None,
        };
        let Some((destination, joins)) = self.route_of(endpoint, alias) else {
            self.count(|c| &mut c.refused);
            return None;
        };
        let answer = match control {
            Control::Challenge(challenge) => {
                self.sessions
                    .challenge(endpoint, source, now, &challenge, |_| joins)
            }
            Control::Solicit(solicit) => {
                self.sessions
                    .solicit(endpoint, source, now, &solicit, |_| joins)
            }
            _ => return None,
        };
        match answer {
            Ok(answer) => {
                self.bind(endpoint, source, &answer, now);
                Some((destination, Control::SetupAnswer(answer)))
            }
            Err(_) => {
                self.count(|c| &mut c.refused);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests;
