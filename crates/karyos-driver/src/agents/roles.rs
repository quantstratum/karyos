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
//!     in the ring, with a report slot ([`ReportSlot`]) the sender settles
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
//!   Repair (R4, R5, R7; ACS 15920): a NAK the receiver hands over is
//!   admitted only from a receiver bound on that endpoint (source, boot
//!   id, incarnation and receiver id), at most `naks_per_cycle` a cycle;
//!   admission's ERR goes back to the NAK's source. After the control step
//!   and before first sends, the reliable publications serve their repair
//!   jobs in turn from a cursor that moves each cycle, within one repair
//!   budget per cycle, and their step 8 ERRs go to each requester's bound
//!   source ([`super::repair`]).
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
    Alias, Control, Datagram, Identity, LaneStatus, Lanes, MAX_WINDOW, Nak, NakReply, Receiver,
    Rttm, RttmKind, SetupAnnounce, SetupAnswer, StatusMessage, classify,
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
    ControlItem, ControlRoutes, ControlSendError, ItemGuard, ReportGuard, ReportSlot, RouteSlot,
    SendReport, SmGuard, SmSlot,
};
use super::data::Outbound;

/// The data DRR's budget per publication and cycle: probes and bytes.
const DATA_BUDGET: karyos_protocol::lanes::drr::Budget = karyos_protocol::lanes::drr::Budget {
    work: 64,
    bytes: 1 << 20,
};
use super::repair::{NakOutcome as NakIntake, RepairConfig};
use super::ring::{self, Reservation, RingReceiver, RingSender};
use super::{AgentCommand, AgentConfig, AgentError, AgentEvent, AgentKind, EndpointId, Half};
use crate::membership::{Membership, MembershipConfig, PublicationRoles, Roles, SmKey};
use crate::repair::admission::Requester;
use crate::repair::draw::{OsDelayDraw, Refill};
use crate::repair::loss::{
    Hole, ImageLoss, LossConfig, MulticastConfig, Observation, ReplyOutcome as NakOutcome,
};
use crate::rtt::{Probe, ReplyOutcome, RttConfig, RttProbes, RttReplies};
use crate::sessions::OsNonces;
use crate::sessions::rate::{EndpointRates, RateRefused, TotalRate, normalized};
use crate::sessions::receive::{
    AnnounceOutcome, AnswerOutcome, BindingKey, ReadyOutcome as ImageOutcome, ReceiveSessions,
    SessionConfigError, SlotRef, SolicitOutcome,
};
use crate::sessions::send::{SendSessionError, SendSessions};
use crate::sm_schedule::{SmDue, SmSchedule};
use karyos_sys::log_buffer::ReceiveOwner;
use karyos_sys::log_buffer::{CloseCause, SkipConfig, SkipPolicy};

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
    /// SM copies sent on a later path of an image (RP-7).
    pub sm_copies: u64,
    /// SM copies skipped: the control ring was full (a fault signal, since
    /// configuration sizes the ring for every path's copy).
    pub sm_copies_skipped: u64,
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
    /// NAKs for a local publication dropped with the ring full.
    pub ring_full_nak_forwarded: u64,
    /// Probe id refills that drew from the operating system: a system call
    /// on the receiver agent's timer step, a known deviation until the
    /// agents have a control thread (ACS 15868).
    pub rttm_id_draws: u64,
    /// NAK delay pool refills that drew from the operating system, on the
    /// timer step like `rttm_id_draws` (RC-2).
    pub nak_delay_draws: u64,
    /// NAK delay pool refills whose system call failed: the pool stays as
    /// it was, and an empty one draws the bound.
    pub nak_delay_refill_failures: u64,
    /// Multicast NAK delays drawn from an empty pool: the cycle's bound was
    /// used, so the NAK went at its latest deadline (RC-2). Counted in the
    /// timer step that drew them.
    pub nak_delay_empty: u64,
    /// Multicast NAK cycles started (RC-2): a hole's first, and each one
    /// after a window ended with the hole still there.
    pub nak_cycles: u64,
    /// Group NAKs from the control group that passed validation (RC-15).
    pub group_naks: u64,
    /// Of those, the ones that suppressed a cycle's local NAK (B).
    pub group_nak_suppressions: u64,
    /// Control group datagrams dropped: not a NAK (validation 1).
    pub group_nak_not_nak: u64,
    /// Group NAKs dropped: no image of this receiver has that incarnation
    /// or lane (validation 2).
    pub group_nak_unbound: u64,
    /// Group NAKs dropped: this receiver's own, looped back (validation 3).
    pub group_nak_own: u64,
    /// Group NAKs dropped: the range breaks the term rule (validation 4).
    pub group_nak_range: u64,
    /// Receiver cycles that read the whole `group_nak_budget`: datagrams
    /// past it wait for the next cycle, or the socket drops them.
    pub group_nak_budget_full: u64,
    /// NAK copies posted to the control group (RC-7).
    pub group_nak_copies: u64,
    /// NAK copies skipped: the control ring was full; never retried.
    pub group_nak_copies_skipped: u64,
    /// NAKs handed to the sender (phase 6, reliable images).
    pub naks: u64,
    /// NAKs not handed over: the control ring was full (each stays due).
    pub ring_full_nak: u64,
    /// NAK copies handed over on a later path of an image (RP-7).
    pub nak_copies: u64,
    /// NAK copies skipped: the control ring was full; never deferred.
    pub nak_copies_skipped: u64,
    /// NAK retries: a hole NAKed again (a reliable image whose sender
    /// never repairs, such as a `reliable=false` publication, shows here).
    pub nak_retries: u64,
    /// Endpoint resets requested for a route fault (RC-6).
    pub reset_requests: u64,
    /// Reset requests not posted: the event ring was full.
    pub reset_requests_full: u64,
    /// A second uncertain NAK of an image while one is unresolved (RC-6):
    /// its NAKs stop until the endpoint reset resolves them.
    pub nak_route_faults: u64,
    /// ERR NAK_REPLY controls for no installed image.
    pub nak_replies_unbound: u64,
    /// Images closed by repair: a range proven unrecoverable under
    /// `on_unrecoverable = close`, or `GapCannotResume`.
    pub images_closed_unrecoverable: u64,
    /// Images closed by `GapCannotResume` (a floor beyond the window).
    pub images_closed_cannot_resume: u64,
    /// Images closed by a protocol fault (`range_invalid_limit`
    /// consecutive RANGE_INVALID).
    pub images_closed_protocol_fault: u64,
    /// Gaps sealed by the skip policy (unreliable timers, or `skip`).
    pub gaps_sealed: u64,
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
    /// NAKs that reached admission (at most `naks_per_cycle` per cycle).
    pub naks: u64,
    /// NAKs dropped over `naks_per_cycle`: the receiver retries.
    pub nak_cycle_budget: u64,
    /// NAKs from no receiver bound on that endpoint (source, alias, boot
    /// id, incarnation and receiver id), or for no reliable publication.
    pub nak_unbound: u64,
    /// SMs whose declared tag is not the one configured for their receiver
    /// (MC-2): dropped whole before the binding.
    pub sm_tag_mismatch: u64,
    /// ERR NAK_REPLYs sent (admission's and step 8's).
    pub nak_replies: u64,
    /// Step 8 ERRs whose requester has no bound source: not sent.
    pub nak_replies_unbound: u64,
    /// Step 8 ERRs past the cycle's reply list: not sent. The list holds
    /// what one publication's path keeps, so this stays 0 unless that
    /// bound breaks.
    pub nak_replies_dropped: u64,
    /// Repair datagrams submitted.
    pub repairs: u64,
    /// NAK copies sent to a control group (RC-7; counted in `sent` too).
    pub group_nak_copies_sent: u64,
    /// NAK copies to a control group that failed or were uncertain:
    /// counted, never retried, no route fault.
    pub group_nak_copies_failed: u64,
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
    /// Publications whose receivers' status messages became live or
    /// lapsed: their connection changed (SPEC.md §4).
    pub connection_changes: u64,
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
    /// Test only: the DATA datagrams to drop at the intake, by their
    /// count since the hook was set (a lossy path).
    #[cfg(test)]
    drop_data: Vec<u64>,
    /// Test only: DATA datagrams seen since the hook was set.
    #[cfg(test)]
    data_seen: u64,
    /// Test only: every NAK handed to the sender.
    #[cfg(test)]
    posted_naks: Vec<Nak>,
    /// Test only: every RSP_SETUP handed to the sender, with its endpoint.
    #[cfg(test)]
    posted_challenges: Vec<(EndpointId, Control)>,
    /// Test only: NAKs handed over on an image's founding path.
    #[cfg(test)]
    founding_naks: u64,
    /// The epoch of each endpoint's RX half last seen, at most
    /// `max_endpoints` (allocated at creation): a new one is the endpoint's
    /// reset, which resolves its images' uncertain NAKs (RC-6).
    rx_epochs: Vec<(EndpointId, karyos_io::backend::BackendEpoch)>,
    /// The most endpoints the agent holds (`max_endpoints`).
    max_endpoints: usize,
    /// Duty cycles run, for the reset request cadence.
    cycle: u64,
    /// The network trace hook (P2.12 step 3).
    trace: super::net_trace::ReceiverTrace,
    sessions: ReceiveSessions,
    nonces: OsNonces,
    to_sender: RingSender<ControlItem>,
    budget: Budget,
    /// Subscribed streams: endpoint, stream, largest image term length,
    /// whether the channel is reliable (its `reliable` parameter), and
    /// whether the endpoint receives a multicast group.
    subscriptions: Vec<(EndpointId, i32, u32, bool, bool)>,
    /// The configured receiver identities of subscribed keys (MC-1, MC-2;
    /// at most one per key, allocated at start): their images name the
    /// configured `receiver_id` and declare its `group_tag`.
    identities: Vec<(EndpointId, i32, crate::membership::ReceiverIdentity)>,
    /// Whether a subscription was ever removed: from then on each cycle
    /// retires the images of streams no longer subscribed (bounded by the
    /// subscription table).
    unsubscribed: bool,
    /// Aliases published per endpoint.
    published: Vec<(EndpointId, Alias)>,
    /// The NAK control groups of subscriptions (RC-15): the data
    /// endpoint, the stream, the endpoint joined to the control group and
    /// the group's address.
    groups: Vec<(EndpointId, i32, EndpointId, SocketAddr)>,
    /// `group_nak_budget`.
    group_budget: u32,
    /// Where the next cycle's control group poll starts (rotating).
    group_start: usize,
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
    /// A multicast image's NAK timing.
    multicast: MulticastConfig,
    /// The multicast NAK delays, drawn from a pool restocked on the timer
    /// step (RC-2).
    delays: OsDelayDraw,
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
/// The stream position of `frame` in `image`, or `None` for a term outside
/// the incarnation.
fn frame_position(image: &Installed, frame: &ValidatedFrame<'_>) -> Option<u64> {
    let term = u64::from(
        frame
            .term_id()
            .count_from(image.initial_term_id)
            .ok()?
            .get(),
    );
    term.checked_mul(u64::from(image.term_length))?
        .checked_add(u64::from(frame.term_offset()))
}

/// The terms of `image` whose end each lane's rebuild position passed,
/// told to its path statistics as cleaned with their whole length (RP-6):
/// what a path did not deliver fresh in them is its missing bytes. At most
/// two terms per lane and call, so a step stays bounded.
///
/// Known limit: the whole term length counts as committed, since the
/// receive owner does not report a term's committed bytes. On an
/// unreliable image the bytes of a sealed gap, which no path delivered,
/// are then charged to every path as missing (redundant-paths.md section
/// 5 charges only committed bytes).
fn terms_complete(image: &mut Installed) {
    let term_length = u64::from(image.term_length);
    for at in 0..usize::from(image.lane_count) {
        let Some(lane) = u8::try_from(at).ok().and_then(|at| Lane::try_new(at).ok()) else {
            continue;
        };
        let Some(current) = image
            .owner
            .rebuild_position(lane)
            .and_then(|position| position.checked_div(term_length))
        else {
            continue;
        };
        for _ in 0..2 {
            let Some(next) = image.next_clean.get_mut(at) else {
                break;
            };
            if *next >= current {
                break;
            }
            image.stats.term_cleaned(at, *next, term_length);
            match next.checked_add(1) {
                Some(following) => *next = following,
                None => break,
            }
        }
    }
}

/// The report slot of the copy of lane `at` on path `path` (RP-7).
fn copy_index(image: &Installed, at: usize, path: usize) -> Option<usize> {
    at.checked_mul(image.routes.len())?.checked_add(path)
}

/// Whether a copy of lane `at`'s last NAK still waits for its report.
fn copies_busy(image: &Installed, at: usize) -> bool {
    (0..image.routes.len()).any(|path| {
        copy_index(image, at, path)
            .and_then(|index| image.copies.get(index))
            .is_some_and(|copy| copy.slot.busy())
    })
}

/// Settles the reports of lane `at`'s NAK copies on the later paths
/// (RP-7): the first submitted, or uncertain (RC-6: then counted as
/// submitted at its start), anchors the NAK unless another copy already
/// did; a copy not submitted leaves the NAK due unless one anchored it.
/// Uncertainty counts per path route: a second uncertain copy on one
/// route while its first is unresolved faults that route, which then
/// takes no copy until its endpoint is reset.
fn settle_copies(image: &mut Installed, counters: &mut ReceiverCounters, at: usize) {
    for path in 0..image.routes.len() {
        let Some(index) = copy_index(image, at, path) else {
            continue;
        };
        let Some(copy) = image.copies.get_mut(index) else {
            continue;
        };
        let Some(settled) = copy.slot.collect(false) else {
            continue;
        };
        let Some(nak) = copy.pending.take() else {
            continue;
        };
        if let (SendReport::Uncertain(_), Some(route)) = (settled, image.routes.get_mut(path)) {
            if route.uncertain {
                route.faulted = true;
                tally(counters, |c| &mut c.nak_route_faults);
            } else {
                route.uncertain = true;
            }
        }
        let anchored = image.anchored.get(at).copied().flatten() == Some(nak);
        match (settled, anchored) {
            (SendReport::Submitted(start) | SendReport::Uncertain(start), false) => {
                image.loss.submitted(&nak, start, &image.rtt);
                if let Some(anchor) = image.anchored.get_mut(at) {
                    *anchor = Some(nak);
                }
            }
            (SendReport::NotSubmitted, false) => image.loss.not_submitted(&nak),
            _ => {}
        }
    }
}

/// Posts a copy of `nak`, lane `at`'s NAK just handed over on the
/// founding path, on every other bound path whose route is not faulted
/// (RP-7). A copy the control ring cannot take is skipped and counted,
/// never deferred.
fn post_copies(
    image: &mut Installed,
    sessions: &ReceiveSessions,
    to_sender: &mut RingSender<ControlItem>,
    counters: &mut ReceiverCounters,
    at: usize,
    nak: Nak,
) {
    for path in 0..image.routes.len() {
        let Some(key) = sessions.paths().key(image.slot, path) else {
            continue;
        };
        if key == image.key || image.routes.get(path).is_some_and(|route| route.faulted) {
            continue;
        }
        let Some(index) = copy_index(image, at, path) else {
            continue;
        };
        let Some(copy) = image.copies.get_mut(index) else {
            continue;
        };
        let item = ControlItem::Outgoing {
            endpoint: key.endpoint,
            destination: key.source,
            control: Control::Nak(nak),
            guard: Some(ItemGuard::Report(ReportGuard::take(&copy.slot))),
        };
        match to_sender.try_post(item) {
            Ok(()) => {
                copy.pending = Some(nak);
                tally(counters, |c| &mut c.nak_copies);
            }
            Err(_) => tally(counters, |c| &mut c.nak_copies_skipped),
        }
    }
}

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

/// A later path route's uncertain state for NAK copies (RC-6, RP-7).
#[derive(Debug, Clone, Copy, Default)]
struct CopyRoute {
    /// An uncertain copy is unresolved.
    uncertain: bool,
    /// A second uncertain copy came while one was unresolved: the route
    /// takes no copy until its endpoint is reset.
    faulted: bool,
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
    /// Whether its channel is reliable: losses are NAKed, otherwise the
    /// skip policy seals them.
    reliable: bool,
    /// Its repair state (phase 6): each lane's earliest-gap decision.
    loss: ImageLoss,
    /// Its skip policy (GU-4 to GU-6): timer seals, unrecoverable ranges,
    /// far-window closes.
    skip: SkipPolicy,
    /// Each lane's NAK report slot and the NAK it reports on: at most one
    /// NAK per lane in the ring.
    naks: Vec<PendingNak>,
    /// The close repair decided, carried out by the next timer step.
    closing: Option<CloseReason>,
    /// Per lane, when a tail loss was first seen (the heartbeat mark above
    /// a rebuild position with nothing covered above it).
    tail_since: [Option<u64>; 4],
    /// The receiver cycle its last endpoint reset request was posted in,
    /// while a route fault holds its NAKs (RC-6).
    reset_requested: Option<u64>,
    /// Per lane, the next term the path statistics have not been told is
    /// complete (RP-6): a term is complete once the lane's rebuild position
    /// passed its end.
    next_clean: [u64; 4],
    /// The NAK copies on the later paths (RP-7), lane by lane, a report
    /// slot per path: lane `l`, path `p` at `l * max_paths + p`.
    copies: Vec<PendingNak>,
    /// Each path route's uncertain state for those copies (RC-6 per
    /// route); the founding route's is the loss state's own.
    routes: Vec<CopyRoute>,
    /// Per lane, the NAK whose submission round a copy already anchored.
    anchored: [Option<Nak>; 4],
    /// The founding path's subscription is gone while a later path keeps
    /// the image: control goes on the later paths only (#307 review P2-3).
    founding_gone: bool,
    /// Its subscription's NAK control group: the endpoint joined to it and
    /// the group's address (RC-7, RC-15).
    control_group: Option<(EndpointId, SocketAddr)>,
    /// The `receiver_id` it names in every RB block: its key's configured
    /// identity, else derived from its slot.
    receiver_id: u64,
    /// The `group_tag` its SMs declare (0 without a configured identity).
    group_tag: u64,
}

/// One lane's NAK in flight: its report slot (the RTTM probe's contract:
/// the sender reads the clock before the submitting call and reports
/// whether it submitted) and the NAK the report belongs to.
#[derive(Debug)]
struct PendingNak {
    slot: Arc<ReportSlot>,
    pending: Option<Nak>,
}

/// Why repair closes an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    /// A range proven unrecoverable, under `on_unrecoverable = close`.
    Unrecoverable,
    /// A floor beyond the receive window (RC-9, GU-6).
    CannotResume,
    /// `range_invalid_limit` consecutive RANGE_INVALID (RC-8).
    ProtocolFault,
}

impl From<CloseCause> for CloseReason {
    fn from(cause: CloseCause) -> Self {
        match cause {
            CloseCause::Unrecoverable => Self::Unrecoverable,
            CloseCause::GapCannotResume => Self::CannotResume,
        }
    }
}

/// A tail loss on `image`'s `lane` (ACS 15957 note 1, 15984): nothing above
/// the rebuild position is covered, yet the lane's heartbeat mark (the
/// sender's submitted position) is above it, and has been for one RTT.
/// The hole runs from the rebuild position to the mark, never past the
/// rebuild position's term: a NAK beyond the sender's position would be
/// answered RANGE_INVALID. The wait starts when the condition is first
/// seen and ends when it clears.
fn tail_hole(image: &mut Installed, lane: Lane, at: usize, now: u64) -> Option<Hole> {
    use crate::repair::loss::RttSource;

    let rebuild = image.owner.rebuild_position(lane)?;
    let mark = image.heartbeat_marks.get(at).copied().flatten();
    let Some(mark) = mark.filter(|mark| *mark > rebuild) else {
        if let Some(since) = image.tail_since.get_mut(at) {
            *since = None;
        }
        return None;
    };
    let since = image.tail_since.get_mut(at)?;
    let first = *since.get_or_insert(now);
    if age_ns(now, first) < image.rtt.rtt_snapshot(0) {
        return None;
    }
    let term = u64::from(image.term_length);
    let term_end = rebuild
        .checked_div(term)?
        .checked_add(1)?
        .checked_mul(term)?;
    let length = u32::try_from(mark.min(term_end).checked_sub(rebuild)?).ok()?;
    Some(Hole {
        start: rebuild,
        length,
    })
}

/// `hole` of `image`'s `lane` proven unrecoverable, with the sender's
/// lowest retained position: the skip policy seals it (`skip`) or decides
/// the image's close (`close`, or a floor beyond the window). The whole
/// hole is unrecoverable even when the floor lies inside it (RC-9), so the
/// policy is given the later of the floor and the hole's end: it seals
/// every hole starting below that.
fn unrecoverable(
    image: &mut Installed,
    counters: &mut ReceiverCounters,
    lane: Lane,
    hole: Hole,
    lowest_retained: u64,
    now: u64,
) {
    let floor = hole
        .start
        .checked_add(u64::from(hole.length))
        .map_or(lowest_retained, |end| lowest_retained.max(end));
    match image
        .skip
        .range_unavailable(&mut image.owner, lane, floor, now)
    {
        Ok(report) => {
            for _ in 0..report.sealed {
                tally(counters, |c| &mut c.gaps_sealed);
            }
            if let Some(close) = report.close {
                image.closing = Some(CloseReason::from(close.cause));
            }
        }
        Err(_) => tally(counters, |c| &mut c.chain_invariant),
    }
}

/// The end of `lane`'s receive window `{r, r + 1}` of `owner`: two terms
/// past the start of the rebuild position's term. `None` past `u64`.
fn window_end(owner: &ReceiveOwner, lane: Lane, term_length: u32) -> Option<u64> {
    let term = u64::from(term_length);
    let rebuild = owner.rebuild_position(lane)?;
    rebuild.checked_div(term)?.checked_add(2)?.checked_mul(term)
}

/// One path's RTTM REQUEST in flight: its report slot (at most one
/// REQUEST per path in the ring) and the probe the report belongs to.
#[derive(Debug)]
struct PathProbe {
    slot: Arc<ReportSlot>,
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
/// as in [`ReportSlot::collect`].
fn collect_probe(rtt: &mut RttProbes, probe: &mut PathProbe, replied: bool) {
    let Some(report) = probe.slot.collect(replied) else {
        return;
    };
    // A probe of an older binding generation is ignored by `rtt`.
    if let Some(pending) = probe.pending.take() {
        match report {
            SendReport::Submitted(start) => rtt.submitted(pending, start),
            // An uncertain probe yields no sample (RC-1).
            SendReport::NotSubmitted | SendReport::Uncertain(_) => rtt.not_submitted(pending),
        }
    }
}

/// What one control send did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    /// The backend submitted it.
    Submitted,
    /// It was not submitted.
    NotSubmitted,
    /// Its exposure is unknown.
    Uncertain,
}

impl Sent {
    fn submitted(self) -> bool {
        self == Self::Submitted
    }
}

/// The sender agent's network state.
#[derive(Debug)]
pub struct SenderRole {
    sessions: SendSessions,
    from_receiver: RingReceiver<ControlItem>,
    /// Each publication's data path: readers, channel destination, lane
    /// queues (at most `publications`, allocated at creation).
    publications: Vec<Box<Outbound>>,
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
    /// The repair settings (R4, R5, R7).
    repair: RepairConfig,
    /// NAKs admitted this cycle.
    naks_this_cycle: u32,
    /// The publication whose repairs run first next cycle.
    repair_cursor: usize,
    /// Step 8 ERRs drained this cycle, with their endpoint (allocated at
    /// creation).
    nak_replies: Vec<(EndpointId, NakReply)>,
    /// The clock read immediately before a REQUEST's backend call.
    clock: fn() -> u64,
    counters: SenderCounters,
    /// The network trace hook and journals (P2.12 step 3).
    trace: super::net_trace::SenderTrace,
    /// Test only: NAKs are dropped unread, as from a sender that never
    /// repairs (receiver rigs that answer NAKs themselves).
    #[cfg(test)]
    ignore_naks: bool,
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
    // A step starts at most one multicast cycle per lane of each image.
    let delays = OsDelayDraw::new(
        config.sessions.max_images,
        karyos_protocol::network::MAX_LANES,
    )
    .ok_or(AgentError::InvalidConfig("max_images too large"))?;
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
            repair: config.repair,
            naks_this_cycle: 0,
            repair_cursor: 0,
            nak_replies: Vec::with_capacity(config.repair.replies),
            clock: karyos_sys::host_clock::host_monotonic_ns,
            counters: SenderCounters::default(),
            trace: super::net_trace::SenderTrace::default(),
            #[cfg(test)]
            ignore_naks: false,
        },
        ReceiverRole {
            #[cfg(test)]
            drop_data: Vec::new(),
            #[cfg(test)]
            data_seen: 0,
            #[cfg(test)]
            posted_naks: Vec::new(),
            #[cfg(test)]
            posted_challenges: Vec::new(),
            #[cfg(test)]
            founding_naks: 0,
            rx_epochs: Vec::with_capacity(config.max_endpoints),
            max_endpoints: config.max_endpoints,
            cycle: 0,
            sessions,
            nonces: OsNonces,
            to_sender,
            budget: Budget::new(datagrams, bytes, ops),
            subscriptions: Vec::with_capacity(config.subscriptions),
            groups: Vec::with_capacity(config.subscriptions),
            group_budget: config.group_nak_budget,
            group_start: 0,
            identities: Vec::with_capacity(config.subscriptions),
            unsubscribed: false,
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
            multicast: config.multicast,
            delays,
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
    /// The configured identity of the key `(endpoint, stream_id)`
    /// (tests).
    #[cfg(test)]
    pub(crate) fn configured_identity(
        &self,
        endpoint: EndpointId,
        stream_id: i32,
    ) -> Option<crate::membership::ReceiverIdentity> {
        self.identities
            .iter()
            .find(|(held, stream, _)| (*held, *stream) == (endpoint, stream_id))
            .map(|(.., identity)| *identity)
    }

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
            subscription: None,
        };
        match command {
            AgentCommand::AddSubscription {
                reply,
                endpoint,
                stream_id,
                max_term_length,
                reliable,
                multicast,
                control_group,
                identity,
            } => {
                let held = self
                    .subscriptions
                    .iter()
                    .position(|(held, stream, ..)| (*held, *stream) == (endpoint, stream_id));
                let full = self.subscriptions.len() >= max;
                let accepted = match held.and_then(|index| self.subscriptions.get_mut(index)) {
                    // Two subscribers of one stream on one endpoint: the
                    // stricter limit and the stricter reliability (repair)
                    // hold for both.
                    Some(entry) => {
                        entry.2 = entry.2.min(max_term_length);
                        entry.3 |= reliable;
                        true
                    }
                    None if !full => {
                        self.subscriptions.push((
                            endpoint,
                            stream_id,
                            max_term_length,
                            reliable,
                            multicast,
                        ));
                        if let Some((control, group)) = control_group {
                            self.groups.push((endpoint, stream_id, control, group));
                        }
                        // A shared key's identity is its first
                        // subscription's: the conductor refuses another.
                        if let Some(identity) = identity {
                            self.identities.push((endpoint, stream_id, identity));
                        }
                        true
                    }
                    None => false,
                };
                Some((
                    reply,
                    AgentEvent::Configured {
                        agent: AgentKind::Receiver,
                        accepted,
                        subscription: Some((endpoint, stream_id)),
                    },
                ))
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
            AgentCommand::RemoveSubscription {
                reply,
                endpoint,
                stream_id,
            } => {
                let found = self
                    .subscriptions
                    .iter()
                    .position(|(held, stream, ..)| (*held, *stream) == (endpoint, stream_id));
                if let Some(index) = found {
                    self.subscriptions.swap_remove(index);
                    self.identities
                        .retain(|(held, stream, _)| (*held, *stream) != (endpoint, stream_id));
                    self.unsubscribed = true;
                }
                if let Some(index) = self
                    .groups
                    .iter()
                    .position(|(held, stream, ..)| (*held, *stream) == (endpoint, stream_id))
                {
                    self.groups.swap_remove(index);
                }
                Some((reply, configured(found.is_some())))
            }
            AgentCommand::RemovePublishedAlias {
                reply,
                endpoint,
                alias,
            } => {
                let entry = (endpoint, alias);
                let found = self.published.iter().position(|held| *held == entry);
                if let Some(index) = found {
                    self.published.swap_remove(index);
                }
                Some((reply, configured(found.is_some())))
            }
            AgentCommand::RemovePublication { reply, .. } => Some((
                reply,
                AgentEvent::Unsupported {
                    agent: AgentKind::Receiver,
                },
            )),
            AgentCommand::AddPublication {
                reply, publication, ..
            } => Some((
                reply,
                AgentEvent::PublicationRefused {
                    agent: AgentKind::Receiver,
                    endpoint: publication.endpoint,
                    alias: publication.alias,
                    registration: publication.identity.registration_id,
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

    /// Hands the receiver `control` from `source` on `endpoint` at `now`
    /// (tests).
    #[cfg(test)]
    pub(super) fn inject_control(
        &mut self,
        sessions: &SessionEnd,
        endpoint: EndpointId,
        source: SocketAddr,
        control: Control,
        now: u64,
    ) {
        let mut intake = Intake {
            endpoint,
            now,
            role: self,
            sessions,
            work: 0,
        };
        intake.control(source, control);
    }

    /// Hands the receiver `bytes` as a datagram of the control group
    /// endpoint `endpoint` at `now` (tests).
    #[cfg(test)]
    pub(super) fn inject_group(&mut self, endpoint: EndpointId, bytes: &[u8], now: u64) {
        let mut intake = GroupIntake {
            endpoint,
            now,
            role: self,
            work: 0,
        };
        intake.bytes(bytes);
    }

    /// The receiver block this receiver puts in the NAKs of the image at
    /// `slot` (tests).
    #[cfg(test)]
    pub(super) fn receiver_of(&self, slot: SlotRef) -> Receiver {
        let named = self
            .images
            .iter()
            .find(|image| image.slot == slot)
            .map_or(receiver_id(slot), |image| image.receiver_id);
        Receiver {
            receiver_boot_id: self.sessions.boot_id(),
            receiver_id: named,
        }
    }

    /// Hands the receiver `bytes` as a DATA datagram from `source` on
    /// `endpoint` at `now` (tests).
    #[cfg(test)]
    pub(super) fn inject_data(
        &mut self,
        sessions: &SessionEnd,
        endpoint: EndpointId,
        source: SocketAddr,
        alias: Alias,
        bytes: &[u8],
        now: u64,
    ) {
        let mut intake = Intake {
            endpoint,
            now,
            role: self,
            sessions,
            work: 0,
        };
        intake.data(source, alias, bytes);
    }

    /// Hands the receiver a DATA frame of `payload` bytes on lane 0 of the
    /// image at `slot`, at stream position `position`, from `source` on
    /// `endpoint` at `now` (tests).
    #[cfg(test)]
    #[expect(
        clippy::too_many_arguments,
        reason = "a test helper naming the frame's whole context"
    )]
    pub(super) fn inject_frame(
        &mut self,
        sessions: &SessionEnd,
        endpoint: EndpointId,
        source: SocketAddr,
        slot: SlotRef,
        position: u64,
        payload: usize,
        now: u64,
    ) {
        use karyos_protocol::frame::{Flags, FrameType, Word0};

        let image = self.images.iter().find(|image| image.slot == slot).unwrap();
        let term_length = u64::from(image.term_length);
        let term_id = image
            .initial_term_id
            .get()
            .checked_add(u32::try_from(position / term_length).unwrap())
            .unwrap();
        let term_offset = u32::try_from(position % term_length).unwrap();
        let alias = image.key.alias;
        let length = 32 + payload;
        let mut bytes = vec![0u8; length];
        let word0 = Word0::new(
            i32::try_from(length).unwrap(),
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

    /// Drops the DATA datagrams numbered `nth` (from 0) from now on at the
    /// intake, as a lossy path would (tests).
    #[cfg(test)]
    pub(super) fn drop_data(&mut self, nth: &[u64]) {
        self.drop_data = nth.to_vec();
        self.data_seen = 0;
    }

    /// Makes the image at `slot` hold a route fault: two uncertain NAKs,
    /// the second while the first is unresolved (tests).
    #[cfg(test)]
    pub(super) fn fault_naks(&mut self, slot: SlotRef, nak: &Nak) {
        struct Fixed;
        impl crate::repair::loss::RttSource for Fixed {
            fn rtt_snapshot(&self, _: usize) -> u64 {
                0
            }
        }
        let image = self
            .images
            .iter_mut()
            .find(|image| image.slot == slot)
            .unwrap();
        let _ = image.loss.uncertain(nak, 0, &Fixed);
        let _ = image.loss.uncertain(nak, 0, &Fixed);
    }

    /// Every NAK handed to the sender (tests).
    #[cfg(test)]
    pub(super) fn posted_naks(&self) -> &[Nak] {
        &self.posted_naks
    }

    /// The statistics of path `path` of the image at `slot` (tests).
    #[cfg(test)]
    pub(super) fn path_counts(
        &self,
        slot: SlotRef,
        path: usize,
    ) -> Option<crate::paths::stats::PathCounts> {
        self.images
            .iter()
            .find(|image| image.slot == slot)
            .and_then(|image| image.stats.counts(path).copied())
    }

    /// NAKs handed over on an image's founding path (tests).
    #[cfg(test)]
    pub(super) fn founding_naks(&self) -> u64 {
        self.founding_naks
    }

    /// Every RSP_SETUP handed to the sender, with its endpoint (tests).
    #[cfg(test)]
    pub(super) fn posted_challenges(&self) -> &[(EndpointId, Control)] {
        &self.posted_challenges
    }

    /// Replaces the receiver's clock (tests: a rig's virtual time).
    #[cfg(test)]
    pub(super) fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    /// Fixes the multicast NAK delay draw (tests): `delay`, or the
    /// cycle's bound if smaller.
    #[cfg(test)]
    pub(super) fn fix_nak_delay(&mut self, delay: u64) {
        self.delays.fix(delay);
    }

    /// Whether the entry for `stream_id` on `endpoint` is multicast, if
    /// there is one (tests).
    #[cfg(test)]
    pub(super) fn subscription_multicast(
        &self,
        endpoint: EndpointId,
        stream_id: i32,
    ) -> Option<bool> {
        self.subscriptions
            .iter()
            .find(|(held, stream, ..)| (*held, *stream) == (endpoint, stream_id))
            .map(|(.., multicast)| *multicast)
    }

    /// Empties the multicast NAK delay pool, and makes later refills fail
    /// or not (tests).
    #[cfg(test)]
    pub(super) fn drain_nak_delays(&mut self, fail_refills: bool) {
        self.delays.drain(fail_refills);
    }

    /// The bound of the last multicast NAK delay drawn (tests).
    #[cfg(test)]
    pub(super) fn last_nak_delay_bound(&self) -> Option<u64> {
        self.delays.last_bound()
    }

    /// The repair counters of the image at `slot` (tests).
    #[cfg(test)]
    pub(super) fn loss_counters(&self, slot: SlotRef) -> Option<crate::repair::loss::LossCounters> {
        self.images
            .iter()
            .find(|image| image.slot == slot)
            .map(|image| image.loss.counters())
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
                slot: Arc::new(ReportSlot::default()),
                pending: None,
            })
            .collect();
        // Its repair state, allocated here: reliability is the
        // subscription channel's (ACS 15984).
        let subscription = self
            .subscriptions
            .iter()
            .find(|(held, stream, ..)| (*held, *stream) == (key.endpoint, key.alias.stream_id));
        let reliable = subscription.is_none_or(|(_, _, _, reliable, _)| *reliable);
        let multicast = subscription.is_some_and(|(.., multicast)| *multicast);
        let control_group = self
            .groups
            .iter()
            .find(|(held, stream, ..)| (*held, *stream) == (key.endpoint, key.alias.stream_id))
            .map(|(_, _, control, group)| (*control, *group));
        // The configured identity of its key, else an id derived from the
        // slot and tag 0.
        let configured = self
            .identities
            .iter()
            .find(|(held, stream, _)| (*held, *stream) == (key.endpoint, key.alias.stream_id))
            .map(|(.., identity)| *identity);
        let (named, group_tag) = configured.map_or((receiver_id(installed), 0), |identity| {
            (identity.receiver_id.get(), identity.group_tag)
        });
        let receiver = Receiver {
            receiver_boot_id: self.sessions.boot_id(),
            receiver_id: named,
        };
        // A multicast image times its NAKs by cycle (RC-2).
        let loss = ImageLoss::new(
            LossConfig {
                skew_window_ns: self.path_config.path_skew_window,
                ..LossConfig::default()
            },
            key.alias,
            identity,
            receiver,
            chain.lane_count,
            0,
        )
        .and_then(|loss| {
            if multicast {
                loss.multicast(self.multicast)
            } else {
                Ok(loss)
            }
        });
        let Ok(loss) = loss else {
            return Err(Some(chain.retire));
        };
        // The skew window (RP-4): on an unreliable image the seal waits
        // the larger of it and the reorder interval, never their sum.
        let skip_config = SkipConfig {
            skew_window_ns: self.path_config.path_skew_window,
            ..if reliable {
                SkipConfig::reliable()
            } else {
                SkipConfig::unreliable()
            }
        };
        let Ok(skip) = SkipPolicy::new(skip_config, usize::from(chain.lane_count)) else {
            return Err(Some(chain.retire));
        };
        let naks = (0..chain.lane_count)
            .map(|_| PendingNak {
                slot: Arc::new(ReportSlot::default()),
                pending: None,
            })
            .collect();
        // The path statistics start counting complete terms from each
        // lane's current term (RP-6).
        let mut next_clean = [0u64; 4];
        for (at, next) in next_clean
            .iter_mut()
            .enumerate()
            .take(usize::from(chain.lane_count))
        {
            *next = u8::try_from(at)
                .ok()
                .and_then(|at| Lane::try_new(at).ok())
                .and_then(|lane| owner.rebuild_position(lane))
                .and_then(|position| position.checked_div(u64::from(chain.term_length)))
                .unwrap_or(0);
        }
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
            reliable,
            loss,
            skip,
            naks,
            closing: None,
            tail_since: [None; 4],
            reset_requested: None,
            next_clean,
            copies: (0..usize::from(chain.lane_count))
                .flat_map(|_| 0..paths)
                .map(|_| PendingNak {
                    slot: Arc::new(ReportSlot::default()),
                    pending: None,
                })
                .collect(),
            routes: vec![CopyRoute::default(); paths],
            anchored: [None; 4],
            founding_gone: false,
            control_group,
            receiver_id: named,
            group_tag,
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
        // The multicast NAK delays: restocked here, before this step's
        // draws, never per datagram.
        match self.delays.refill() {
            Refill::Full => {}
            Refill::Drew => self.count(|c| &mut c.nak_delay_draws),
            Refill::Failed => self.count(|c| &mut c.nak_delay_refill_failures),
        }
        let mut index = 0usize;
        while let Some(image) = self.images.get(index) {
            // An image stays while any of its bound paths' endpoints still
            // subscribes its stream (RP-2: removing one path's subscription
            // does not retire an image another path keeps).
            let stream_id = image.key.alias.stream_id;
            let subscribed = |endpoint: EndpointId| {
                self.subscriptions
                    .iter()
                    .any(|(held, stream, ..)| (*held, *stream) == (endpoint, stream_id))
            };
            let founding = !self.unsubscribed || subscribed(image.key.endpoint);
            let unsubscribed = !founding && {
                let paths = usize::from(self.path_config.max_paths);
                !(0..paths).any(|path| {
                    self.sessions
                        .paths()
                        .key(image.slot, path)
                        .is_some_and(|key| subscribed(key.endpoint))
                })
            };
            let (evidence, closing) = (image.evidence, image.closing);
            // A later path keeps the image after the founding path's
            // subscription went: its control goes on the live paths only,
            // never to the released founding endpoint (#307 review P2-3).
            if let Some(image) = self.images.get_mut(index) {
                image.founding_gone = !founding;
            }
            if unsubscribed || age_ns(now, evidence) >= self.liveness_timeout {
                let image = self.images.swap_remove(index);
                self.retire(sessions, image, now);
                work = work.checked_add(1).ok_or(overflow.clone())?;
                continue;
            }
            // A close repair decided (an ERR reply in the intake, or the
            // skip policy below on an earlier step).
            if let Some(reason) = closing {
                let field: fn(&mut ReceiverCounters) -> &mut u64 = match reason {
                    CloseReason::Unrecoverable => |c| &mut c.images_closed_unrecoverable,
                    CloseReason::CannotResume => |c| &mut c.images_closed_cannot_resume,
                    CloseReason::ProtocolFault => |c| &mut c.images_closed_protocol_fault,
                };
                self.count(field);
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
            if let Some(image) = self.images.get_mut(index) {
                terms_complete(image);
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
            // Then its repair: NAKs due, the skip policy's seals and
            // closes (phase 6).
            work = work
                .checked_add(self.repair(index, now)?)
                .ok_or(overflow.clone())?;
            index = index.checked_add(1).ok_or(overflow.clone())?;
        }
        // This step's draws from an empty pool, reported in this step.
        let (empty, overflowed) = self.delays.take_empty();
        match self.counters.nak_delay_empty.checked_add(empty) {
            Some(total) if !overflowed => self.counters.nak_delay_empty = total,
            _ => self.counters.overflowed = true,
        }
        Ok(work)
    }

    /// Asks for the reset of each endpoint whose image a route fault holds
    /// (RC-6), through `post` (which returns whether the request was
    /// posted): at most once per `RESET_REQUEST_CYCLES` per image while the
    /// fault holds; the reset's new epoch resolves it. Nothing allocates.
    pub(super) fn request_resets(&mut self, mut post: impl FnMut(EndpointId) -> bool) {
        let cycle = self.cycle;
        let Self {
            images, counters, ..
        } = self;
        for image in images.iter_mut() {
            // The founding route faulted; once its subscription went, its
            // endpoint is released and asks for no reset.
            if !image.loss.is_faulted() || image.founding_gone {
                continue;
            }
            let due = image.reset_requested.is_none_or(|at| {
                cycle
                    .checked_sub(at)
                    .is_none_or(|age| age >= super::data::RESET_REQUEST_CYCLES)
            });
            if !due {
                continue;
            }
            if post(image.key.endpoint) {
                image.reset_requested = Some(cycle);
                tally(counters, |c| &mut c.reset_requests);
            } else {
                tally(counters, |c| &mut c.reset_requests_full);
            }
        }
    }

    /// Records the epoch of `endpoint`'s RX half: a new one (the endpoint
    /// was reset and both halves reopened) resolves the uncertain NAKs of
    /// its images (RC-6), and their NAKs resume.
    fn rx_epoch(&mut self, endpoint: EndpointId, epoch: karyos_io::backend::BackendEpoch) {
        let room = self.rx_epochs.len() < self.max_endpoints;
        match self
            .rx_epochs
            .iter_mut()
            .find(|(held, _)| *held == endpoint)
        {
            Some((_, seen)) if *seen == epoch => {}
            Some((_, seen)) => {
                *seen = epoch;
                for image in &mut self.images {
                    if image.key.endpoint == endpoint {
                        image.loss.uncertain_resolved();
                        image.reset_requested = None;
                    }
                    // The later routes on that endpoint resolve too.
                    for (path, route) in image.routes.iter_mut().enumerate() {
                        if self
                            .sessions
                            .paths()
                            .key(image.slot, path)
                            .is_some_and(|key| key.endpoint == endpoint)
                        {
                            *route = CopyRoute::default();
                        }
                    }
                }
            }
            // At most `max_endpoints` halves: a full table is not reached.
            None if room => {
                self.rx_epochs.push((endpoint, epoch));
            }
            None => {}
        }
    }

    /// The repair step of the image at `index` at `now` (phase 6). On a
    /// reliable image each lane's last NAK report is settled, its first
    /// hole observed, and a due NAK handed to the sender, at most one per
    /// lane in the ring, to the binding's source. On a multicast image a
    /// hole's NAK is due only once its cycle's drawn delay has passed
    /// (RC-2), and the next cycle starts when the window ends with the hole
    /// still there; the delays come from a pool restocked on the timer
    /// step. With a control group, each NAK handed over is followed by
    /// one copy to the group (RC-7). Then the skip policy runs
    /// on every image: timer seals on an unreliable one, the far-window
    /// close. A close is carried out by the next timer step. Returns the
    /// NAKs handed over.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    fn repair(&mut self, index: usize, now: u64) -> Result<u32, AgentError> {
        let Self {
            images,
            sessions,
            to_sender,
            counters,
            delays,
            #[cfg(test)]
            posted_naks,
            #[cfg(test)]
            founding_naks,
            ..
        } = self;
        let Some(image) = images.get_mut(index) else {
            return Ok(0);
        };
        // RP-5: a gap detected now waits the skew window only with two or
        // more live paths.
        image.loss.set_live_paths(sessions.paths().live(image.slot));
        let mut sent = 0u32;
        let lanes = usize::from(image.lane_count);
        for at in 0..lanes {
            let Some(lane) = u8::try_from(at).ok().and_then(|at| Lane::try_new(at).ok()) else {
                continue;
            };
            let retries = image.loss.counters().retries;
            // The founding path's copy: RC-6 on the image's own route. A
            // NAK another path's copy already anchored records nothing
            // more (RP-7: the anchor is the first copy submitted).
            if let Some(report) = image.naks.get_mut(at)
                && let Some(settled) = report.slot.collect(false)
                && let Some(nak) = report.pending.take()
            {
                let anchored = image.anchored.get(at).copied().flatten() == Some(nak);
                match (settled, anchored) {
                    (SendReport::Submitted(start), false) => {
                        image.loss.submitted(&nak, start, &image.rtt);
                    }
                    (SendReport::NotSubmitted, false) => image.loss.not_submitted(&nak),
                    // RC-6: counts as submitted at its start; a second
                    // while one is unresolved is a route fault.
                    (SendReport::Uncertain(start), false) => {
                        if image.loss.uncertain(&nak, start, &image.rtt).is_err() {
                            tally(counters, |c| &mut c.nak_route_faults);
                        }
                    }
                    (SendReport::Uncertain(_), true) => {
                        if image.loss.route_uncertain().is_err() {
                            tally(counters, |c| &mut c.nak_route_faults);
                        }
                    }
                    (SendReport::Submitted(_) | SendReport::NotSubmitted, true) => {}
                }
                if let (SendReport::Submitted(_) | SendReport::Uncertain(_), Some(slot)) =
                    (settled, image.anchored.get_mut(at))
                {
                    *slot = Some(nak);
                }
            }
            // The later paths' copies (RP-7): the first submitted, or
            // uncertain, anchors the NAK; uncertainty and route faults
            // count per path route.
            settle_copies(image, counters, at);
            if image.loss.counters().retries > retries {
                tally(counters, |c| &mut c.nak_retries);
            }
            if !image.reliable {
                continue;
            }
            let first = image
                .owner
                .first_hole(lane)
                .ok()
                .flatten()
                .map(|(start, length)| Hole { start, length });
            // A covered hole ends any tail wait: a later tail waits its RTT
            // afresh.
            if first.is_some()
                && let Some(since) = image.tail_since.get_mut(at)
            {
                *since = None;
            }
            let hole = first.or_else(|| tail_hole(image, lane, at, now));
            if let Observation::Unrecoverable {
                hole,
                lowest_retained,
                ..
            } = image.loss.observe(lane, hole, now)
            {
                unrecoverable(image, counters, lane, hole, lowest_retained, now);
            }
            // A multicast hole's NAK waits for its cycle's drawn delay; a
            // no-op on a unicast image.
            let cycles = image.loss.counters().cycles;
            image.loss.cycle(lane, now, &image.rtt, delays);
            if image.loss.counters().cycles > cycles {
                tally(counters, |c| &mut c.nak_cycles);
            }
            // One NAK per lane in the ring: the next waits until every
            // copy of the last was reported.
            if copies_busy(image, at) {
                continue;
            }
            let Some(report) = image.naks.get_mut(at) else {
                continue;
            };
            if report.slot.busy() {
                continue;
            }
            let Some(nak) = image.loss.due(lane, now) else {
                continue;
            };
            // The founding path's subscription gone (P2-3): the NAK goes on
            // the later paths only, and their first copy submitted anchors
            // it.
            if image.founding_gone {
                if let Some(anchor) = image.anchored.get_mut(at) {
                    *anchor = None;
                }
                #[cfg(test)]
                posted_naks.push(nak);
                tally(counters, |c| &mut c.naks);
                post_copies(image, sessions, to_sender, counters, at, nak);
                sent = sent
                    .checked_add(1)
                    .ok_or(AgentError::CountOverflow(AgentKind::Receiver))?;
                continue;
            }
            let item = ControlItem::Outgoing {
                endpoint: image.key.endpoint,
                destination: image.key.source,
                control: Control::Nak(nak),
                guard: Some(ItemGuard::Report(ReportGuard::take(&report.slot))),
            };
            // A dropped item drops its guard: reported not submitted, and
            // the NAK stays due.
            match to_sender.try_post(item) {
                Ok(()) => {
                    report.pending = Some(nak);
                    #[cfg(test)]
                    posted_naks.push(nak);
                    #[cfg(test)]
                    {
                        *founding_naks += 1;
                    }
                    tally(counters, |c| &mut c.naks);
                    // A new submission round: its first copy submitted
                    // anchors it. Then a copy on every other bound path
                    // (RP-7), first live path first.
                    if let Some(anchor) = image.anchored.get_mut(at) {
                        *anchor = None;
                    }
                    post_copies(image, sessions, to_sender, counters, at, nak);
                    sent = sent
                        .checked_add(1)
                        .ok_or(AgentError::CountOverflow(AgentKind::Receiver))?;
                    // RC-7: on a trusted channel, one copy to the control
                    // group, after the unicast copy and with no report: it
                    // is never retried and raises no route fault. A full
                    // ring skips it, counted.
                    if let Some((control, group)) = image.control_group {
                        let copy = ControlItem::Outgoing {
                            endpoint: control,
                            destination: group,
                            control: Control::Nak(nak),
                            guard: None,
                        };
                        match to_sender.try_post(copy) {
                            Ok(()) => tally(counters, |c| &mut c.group_nak_copies),
                            Err(_) => tally(counters, |c| &mut c.group_nak_copies_skipped),
                        }
                    }
                }
                Err(_) => {
                    tally(counters, |c| &mut c.ring_full_nak);
                    image.loss.not_submitted(&nak);
                }
            }
        }
        // The skip policy's duty: timer seals and the far-window close on
        // an unreliable image; on a reliable one under `skip`, the holes
        // left below an unrecoverable range (at most a few per call).
        if image.closing.is_none() {
            match image.skip.duty(&mut image.owner, now) {
                Ok(report) => {
                    for _ in 0..report.sealed {
                        tally(counters, |c| &mut c.gaps_sealed);
                    }
                    if let Some(close) = report.close {
                        image.closing = Some(CloseReason::from(close.cause));
                    }
                }
                Err(_) => tally(counters, |c| &mut c.chain_invariant),
            }
        }
        Ok(sent)
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
            receiver_id: image.receiver_id,
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
                guard: Some(ItemGuard::Report(ReportGuard::take(&probe.slot))),
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
        let receiver_id = image.receiver_id;
        let status = StatusMessage {
            alias: image.key.alias,
            identity: image.identity,
            receiver: Receiver {
                receiver_boot_id: boot_id,
                receiver_id,
            },
            group_tag: image.group_tag,
            lanes,
        };
        // The founding path's subscription gone (P2-3): only the later
        // paths' copies go.
        if !image.founding_gone {
            // One slot per image (S1): a period whose previous SM still
            // waits is skipped, never given a second slot.
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
            // The sender gone: the driver is stopping. The SM is then
            // recorded as sent all the same: nothing will send another.
            let _ = self.to_sender.post(slot, item);
        }
        // RP-7: a copy on every other bound path, so a path that lost its
        // return direction does not cost the membership. A copy has no
        // slot of its own: one the ring cannot take is skipped and
        // counted, never deferred.
        let Some(image) = self.images.get(index) else {
            return;
        };
        let (slot_ref, founding) = (image.slot, image.key);
        for path in 0..usize::from(self.path_config.max_paths) {
            let Some(key) = self.sessions.paths().key(slot_ref, path) else {
                continue;
            };
            if key == founding {
                continue;
            }
            let copy = ControlItem::Outgoing {
                endpoint: key.endpoint,
                destination: key.source,
                control: Control::Status(status),
                guard: None,
            };
            match self.to_sender.try_post(copy) {
                Ok(()) => self.count(|c| &mut c.sm_copies),
                Err(_) => self.count(|c| &mut c.sm_copies_skipped),
            }
        }
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
        self.cycle = self.cycle.checked_add(1).ok_or(overflow.clone())?;
        work = work
            .checked_add(self.image_timers(sessions, now)?)
            .ok_or(overflow.clone())?;
        for (endpoint, half) in halves.iter() {
            if let Half::Rx(rx) = half {
                self.rx_epoch(*endpoint, rx.capabilities().epoch);
            }
        }
        for (endpoint, half) in halves.iter_mut() {
            let Half::Rx(rx) = half else {
                continue;
            };
            if self.is_control_endpoint(*endpoint) {
                continue;
            }
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
        work = work
            .checked_add(self.poll_control_groups(halves, now)?)
            .ok_or(overflow)?;
        Ok(work)
    }

    /// Whether `endpoint` is joined to a subscription's NAK control group.
    fn is_control_endpoint(&self, endpoint: EndpointId) -> bool {
        self.groups
            .iter()
            .any(|(.., control, _)| *control == endpoint)
    }

    /// The control group endpoints' datagrams (RC-15): one
    /// `group_nak_budget` per cycle, spent by every datagram the backend
    /// consumed (dropped ones too). The first endpoint polled rotates each
    /// cycle, so one busy group cannot starve the others. Returns the
    /// datagrams consumed.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    fn poll_control_groups<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Receiver);
        let count = halves.len();
        if count == 0 || self.groups.is_empty() {
            return Ok(0);
        }
        let start = self
            .group_start
            .checked_rem(count)
            .ok_or(overflow.clone())?;
        self.group_start = start.checked_add(1).ok_or(overflow.clone())?;
        let mut left = self.group_budget;
        let mut work = 0u32;
        for step in 0..count {
            let at = start
                .checked_add(step)
                .and_then(|at| at.checked_rem(count))
                .ok_or(overflow.clone())?;
            let Some((endpoint, Half::Rx(rx))) = halves.get_mut(at) else {
                continue;
            };
            if left == 0 || !self.is_control_endpoint(*endpoint) {
                continue;
            }
            let budget = Budget::new(
                left,
                u64::from(left)
                    .checked_mul(u64::from(karyos_io::sockets::endpoint::MAX_DATAGRAM))
                    .ok_or(overflow.clone())?,
                left.checked_add(1).ok_or(overflow.clone())?,
            );
            let mut intake = GroupIntake {
                endpoint: *endpoint,
                now,
                role: self,
                work: 0,
            };
            let spent = rx.poll_rx(budget, &mut intake).spent.datagrams;
            // A poll consumes at most its budget's datagrams.
            left = left.checked_sub(spent).ok_or(overflow.clone())?;
            if left == 0 {
                self.count(|c| &mut c.group_nak_budget_full);
            }
            work = work.checked_add(spent).ok_or(overflow.clone())?;
        }
        Ok(work)
    }
}

/// The receiver's handler of a control group endpoint's datagrams
/// (RC-15): only peer NAKs, validated in order and handed to the images'
/// suppression state. A group NAK never causes a send, a repair or a
/// reply, and never reaches the sender (loop rule).
struct GroupIntake<'a> {
    endpoint: EndpointId,
    now: u64,
    role: &'a mut ReceiverRole,
    /// Datagrams read; one poll reads at most its budget's.
    work: u32,
}

impl GroupIntake<'_> {
    /// Validation 1: a NAK, and nothing else.
    fn bytes(&mut self, bytes: &[u8]) {
        match classify(bytes) {
            Ok(Datagram::Control(Control::Nak(nak))) => self.nak(&nak),
            Ok(_) => self.role.count(|c| &mut c.group_nak_not_nak),
            Err(_) => self.role.count(|c| &mut c.decode_errors),
        }
    }

    /// Validation 2 to 4 of a group NAK, then B with C on its image.
    fn nak(&mut self, nak: &Nak) {
        let endpoint = self.endpoint;
        let role = &mut *self.role;
        let own = Receiver {
            receiver_boot_id: role.sessions.boot_id(),
            receiver_id: 0,
        };
        // 2. An image of this receiver bound to that incarnation, through
        // this control group, with that lane.
        let Some(image) = role.images.iter_mut().find(|image| {
            image
                .control_group
                .is_some_and(|(control, _)| control == endpoint)
                && image.key.alias == nak.alias
                && image.identity == nak.identity
        }) else {
            role.count(|c| &mut c.group_nak_unbound);
            return;
        };
        if nak.range.lane.get() >= image.lane_count {
            role.count(|c| &mut c.group_nak_unbound);
            return;
        }
        // 3. Never this receiver's own copy, looped back.
        let mine = Receiver {
            receiver_id: image.receiver_id,
            ..own
        };
        if nak.receiver == mine {
            role.count(|c| &mut c.group_nak_own);
            return;
        }
        // 4. The term rule for the bound term length.
        if !crate::repair::admission::in_one_term(
            nak.range.start,
            nak.range.length,
            image.term_length,
        ) {
            role.count(|c| &mut c.group_nak_range);
            return;
        }
        let suppressed = image.loss.peer_nak(nak, self.now);
        role.count(|c| &mut c.group_naks);
        if suppressed {
            role.count(|c| &mut c.group_nak_suppressions);
        }
    }
}

impl RxHandler for GroupIntake<'_> {
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
        let Some(work) = self.work.checked_add(1) else {
            return ControlFlow::Break(());
        };
        self.work = work;
        self.role.count(|c| &mut c.datagrams);
        self.bytes(datagram.bytes());
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, _drop: RxDrop) {
        self.role.count(|c| &mut c.backend_drops);
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
    fn forward(&mut self, item: ControlItem) -> bool {
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
            ControlItem::Incoming {
                control: Control::Nak(_),
                ..
            } => |c| &mut c.ring_full_nak_forwarded,
            ControlItem::Incoming { .. } => |c| &mut c.ring_full_challenge,
        };
        match self.role.to_sender.try_post(item) {
            Ok(()) => {
                self.role.count(|c| &mut c.forwarded);
                true
            }
            Err(_) => {
                self.role.count(full);
                false
            }
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
                                receiver_id: image.receiver_id,
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
        #[cfg(test)]
        {
            let seen = self.role.data_seen;
            if let Some(next) = seen.checked_add(1) {
                self.role.data_seen = next;
            }
            if self.role.drop_data.contains(&seen) {
                return;
            }
        }
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
            self.solicit(key);
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
                    let received = image.owner.receive(&frame);
                    // The skip policy's far-window clock (GU-6): a run of
                    // `Ahead` arrivals starts it, a committed one stops it.
                    if let Some(position) = frame_position(image, &frame) {
                        image
                            .skip
                            .arrived(frame.lane(), &received, position, self.now);
                    }
                    match received {
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
    /// Returns whether it was handed to the sender.
    fn challenge(&mut self, source: SocketAddr, control: Control) -> bool {
        // §7.3: an RSP_SETUP goes only to the trigger's validated source
        // endpoint, through the socket it arrived on.
        if !answerable(source) {
            self.role.count(|c| &mut c.unanswerable_source);
            return false;
        }
        // §7.4: per destination, then per driver.
        match self.role.rsp_destinations.admit(source, self.now) {
            Ok(()) => {}
            Err(RateRefused::Limited) => {
                self.role.count(|c| &mut c.rsp_setup_rate_limited);
                return false;
            }
            Err(RateRefused::TableFull) => {
                self.role.count(|c| &mut c.rsp_setup_destinations_full);
                return false;
            }
        }
        if !self.role.rsp_total.admit(self.now) {
            self.role.count(|c| &mut c.rsp_setup_total_limited);
            return false;
        }
        #[cfg(test)]
        self.role.posted_challenges.push((self.endpoint, control));
        self.forward(ControlItem::Outgoing {
            endpoint: self.endpoint,
            destination: source,
            control,
            guard: None,
        })
    }

    /// DATA for `key`, which has no active binding, on a subscribed stream
    /// (network-control-schemas.md §6.3): one SOLICIT per entry to the
    /// validated unicast source, under the RSP_SETUP limits. A source that
    /// could not be answered creates no entry.
    fn solicit(&mut self, key: BindingKey) {
        let subscribed = self
            .role
            .subscriptions
            .iter()
            .any(|(held, stream, ..)| (*held, *stream) == (key.endpoint, key.alias.stream_id));
        if !subscribed {
            return;
        }
        if !answerable(key.source) {
            self.role.count(|c| &mut c.unanswerable_source);
            return;
        }
        // §7.4 first, charging nothing: DATA arrives at line rate, and a
        // SOLICIT the rates would refuse must not draw a nonce and create
        // an entry per datagram only to withdraw it.
        match self.role.rsp_destinations.would_admit(key.source, self.now) {
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
        if !self.role.rsp_total.would_admit(self.now) {
            self.role.count(|c| &mut c.rsp_setup_total_limited);
            return;
        }
        let role = &mut *self.role;
        if let SolicitOutcome::Solicit(solicit) =
            role.sessions.solicit(key, self.now, &mut role.nonces)
        {
            if self.challenge(key.source, Control::Solicit(solicit)) {
                self.role.sessions.solicit_sent();
            } else {
                // Never sent (a rate or the ring refused it): a SOLICIT is
                // never resent, so the entry goes, with no holdoff, and the
                // next DATA asks again under the limits.
                self.role.sessions.withdraw_solicit(&key);
            }
        }
    }

    /// An ERR NAK_REPLY from `source` (phase 6): it reaches the image bound
    /// to its key, whose repair state accepts only an exact echo of an
    /// outstanding NAK. RANGE_UNAVAILABLE goes to the skip policy (seal or
    /// close, RC-9); a protocol fault (RC-8) closes the image.
    fn nak_reply(&mut self, source: SocketAddr, reply: &NakReply) {
        let key = BindingKey {
            endpoint: self.endpoint,
            source,
            alias: reply.alias,
        };
        let now = self.now;
        let role = &mut *self.role;
        let Some(slot) = role.sessions.lookup(&key) else {
            role.count(|c| &mut c.nak_replies_unbound);
            return;
        };
        let ReceiverRole {
            images, counters, ..
        } = role;
        let Some(image) = images.iter_mut().find(|image| image.slot == slot) else {
            tally(counters, |c| &mut c.nak_replies_unbound);
            return;
        };
        let lane = reply.range.lane;
        let Some(end) = window_end(&image.owner, lane, image.term_length) else {
            tally(counters, |c| &mut c.nak_replies_unbound);
            return;
        };
        match image.loss.reply(reply, end) {
            NakOutcome::Unrecoverable {
                lane,
                hole,
                lowest_retained,
            } => unrecoverable(image, counters, lane, hole, lowest_retained, now),
            // A floor beyond the window closes the image whatever the skip
            // policy (RC-9): its repair state is terminal already.
            NakOutcome::GapCannotResume { .. } => {
                image.closing = Some(CloseReason::CannotResume);
            }
            NakOutcome::ProtocolFault { .. } => {
                image.closing = Some(CloseReason::ProtocolFault);
            }
            NakOutcome::Unmatched | NakOutcome::StillDue => {}
        }
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
                    .find(|(held, stream, ..)| {
                        (*held, *stream) == (endpoint, announce.alias.stream_id)
                    })
                    .map(|(_, _, max, ..)| *max)
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
                // A solicited answer brings its own term parameters: the
                // subscription's term length bound applies here too (an
                // answer to a challenge restates the announced ones).
                let Some(max_term_length) = self
                    .role
                    .subscriptions
                    .iter()
                    .find(|(held, stream, ..)| {
                        (*held, *stream) == (endpoint, answer.alias.stream_id)
                    })
                    .map(|(_, _, max, ..)| *max)
                else {
                    self.role.count(|c| &mut c.unsubscribed);
                    return;
                };
                if answer.term.term_length > max_term_length {
                    self.role.count(|c| &mut c.term_too_large);
                    return;
                }
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
            Control::Challenge(_) | Control::Solicit(_) | Control::Status(_) | Control::Nak(_) => {
                let alias = match control {
                    Control::Challenge(challenge) => challenge.alias,
                    Control::Solicit(solicit) => solicit.alias,
                    Control::Status(status) => status.alias,
                    Control::Nak(nak) => nak.alias,
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
            Control::NakReply(reply) => self.nak_reply(source, &reply),
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
        self.publications.get(index).map(|outbound| &**outbound)
    }

    /// The data path of its `index`-th publication, mutable (tests).
    #[cfg(test)]
    pub(crate) fn outbound_mut(&mut self, index: usize) -> Option<&mut Outbound> {
        self.publications
            .get_mut(index)
            .map(|outbound| &mut **outbound)
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
        let (reply, publication, outbound, guard, roles) =
            match command {
                AgentCommand::AddPublication {
                    reply,
                    publication,
                    outbound,
                    guard,
                    roles,
                } => (reply, publication, outbound, guard, roles),
                AgentCommand::RemovePublication {
                    reply,
                    endpoint,
                    alias,
                    registration,
                } => return Some((reply, self.remove(endpoint, alias, registration))),
                #[cfg(test)]
                AgentCommand::ForceReset { endpoint, alias } => {
                    if let Some(outbound) = self.publications.iter_mut().find(|outbound| {
                        outbound.endpoint() == endpoint && outbound.alias() == alias
                    }) {
                        outbound.force_needs_reset();
                    }
                    return None;
                }
                AgentCommand::AddSubscription { reply, .. }
                | AgentCommand::AddPublishedAlias { reply, .. }
                | AgentCommand::RemovePublishedAlias { reply, .. }
                | AgentCommand::RemoveSubscription { reply, .. } => {
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
        // the driver's SM cadence and liveness; its configured roles, tags
        // and strategy (MC-1; none: `min` with no required or tagged
        // receiver), created now, which times the required set's join.
        let max_window =
            (publication.term.term_length / 2).min(MAX_WINDOW) & !(FRAME_ALIGNMENT - 1);
        let created = (self.clock)();
        let membership = u32::try_from(outbound.max_frame())
            .ok()
            .and_then(|min_window| {
                let mut config =
                    self.membership
                        .config(publication.lane_count, min_window, max_window);
                if let Some(roles) = roles.as_deref() {
                    config.strategy = roles.strategy;
                }
                Membership::new(
                    config,
                    publication.identity,
                    publication.alias,
                    &roles
                        .as_deref()
                        .map_or_else(Roles::default, PublicationRoles::roles),
                    created,
                )
                .ok()
            });
        let added = match membership {
            Some(membership) if matches => {
                outbound.attach_membership(Box::new(membership));
                // A reliable publication repairs (R4, R5, R7).
                let repairs = !outbound.reliable()
                    || outbound
                        .enable_repair(
                            &self.repair,
                            publication.term.term_length,
                            publication.identity,
                        )
                        .is_ok();
                // A guarded publication's gate decides every exposure.
                let guarded = guard.is_none_or(|spec| outbound.guard(spec, (self.clock)()).is_ok());
                if repairs && guarded {
                    self.sessions.add(publication)
                } else {
                    Err(SendSessionError::InvalidConfig)
                }
            }
            _ => Err(SendSessionError::InvalidConfig),
        };
        let event = match added {
            Ok(()) => {
                // `add` refuses past `publications` entries, the capacity.
                // Kept boxed: removal hands the box back without allocating.
                self.publications.push(outbound);
                AgentEvent::PublicationAdded {
                    endpoint: publication.endpoint,
                    alias: publication.alias,
                    registration: publication.identity.registration_id,
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
                registration: publication.identity.registration_id,
            },
        };
        Some((reply, event))
    }

    /// Stops the publication `alias` on `endpoint`: its SETUP side, its
    /// bindings and its data path, which goes back to the conductor.
    fn remove<O: SocketOps>(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        registration: u64,
    ) -> AgentEvent<O> {
        let _ = self.sessions.remove(endpoint, alias);
        self.bindings
            .retain(|binding| (binding.endpoint, binding.alias) != (endpoint, alias));
        let outbound = self
            .publications
            .iter()
            .position(|outbound| outbound.endpoint() == endpoint && outbound.alias() == alias)
            .map(|index| self.publications.swap_remove(index));
        AgentEvent::PublicationRemoved {
            endpoint,
            alias,
            registration,
            outbound,
        }
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
    ) -> Sent {
        let tx = halves.iter_mut().find_map(|(held, half)| match half {
            Half::Tx(tx) if *held == endpoint => Some(tx),
            _ => None,
        });
        let Some(tx) = tx else {
            self.count(|c| &mut c.no_endpoint);
            return Sent::NotSubmitted;
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
            return Sent::NotSubmitted;
        };
        slot.endpoint = Some(endpoint);
        match slot.routes.send(tx, destination, control) {
            Ok(()) => {
                self.count(|c| &mut c.sent);
                Sent::Submitted
            }
            Err(ControlSendError::Uncertain) => {
                self.count(|c| &mut c.send_failures);
                Sent::Uncertain
            }
            Err(_) => {
                self.count(|c| &mut c.send_failures);
                Sent::NotSubmitted
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
        self.naks_this_cycle = 0;
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
                    guard: Some(ItemGuard::Report(guard)),
                } => {
                    let mut guard = guard;
                    guard.sending((self.clock)());
                    match self.send(halves, endpoint, destination, &control) {
                        Sent::Submitted => guard.submitted(),
                        Sent::Uncertain => guard.uncertain(),
                        // Dropped unsettled: not submitted.
                        Sent::NotSubmitted => drop(guard),
                    }
                }
                ControlItem::Outgoing {
                    endpoint,
                    destination,
                    control,
                    guard,
                } => {
                    let sent = self.send(halves, endpoint, destination, &control);
                    // A NAK without a report is a receiver's copy to its
                    // control group (RC-7): its unicast NAKs carry one.
                    if matches!(control, Control::Nak(_)) {
                        if sent.submitted() {
                            self.count(|c| &mut c.group_nak_copies_sent);
                        } else {
                            self.count(|c| &mut c.group_nak_copies_failed);
                        }
                    }
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
                    control: Control::Nak(nak),
                    ..
                } => self.nak(halves, endpoint, source, &nak, now),
                ControlItem::Incoming {
                    endpoint,
                    source,
                    control: Control::Rttm(request),
                    seen,
                } => {
                    if let Some(reply) = self.rttm_request(endpoint, source, &request, seen, now)
                        && self
                            .send(halves, endpoint, source, &Control::Rttm(reply))
                            .submitted()
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
        // A publication with no live receiver (no live member and no
        // confirmed binding) announces again (ACS 15933), and is not
        // connected: its readers' cells stop counting for the connection
        // (SPEC.md §4) until a receiver's SMs are live again.
        let mut changes = 0u64;
        for outbound in &mut self.publications {
            let (endpoint, alias) = (outbound.endpoint(), outbound.alias());
            let bound = self.bindings.iter().any(|binding| {
                binding.endpoint == endpoint && binding.alias == alias && binding.last_sm.is_some()
            });
            let live = bound || outbound.connected(now);
            if outbound.set_receivers_live(live)
                && let Some(next) = changes.checked_add(1)
            {
                changes = next;
            }
            if !live {
                let _ = self.sessions.disconnected(endpoint, alias);
            }
        }
        for _ in 0..changes {
            self.count(|c| &mut c.connection_changes);
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
        // Repair, then first sends (reliable-transport.md, "Order in a
        // cycle"), each to its own budget.
        work = work
            .checked_add(self.serve_repairs(halves, now)?)
            .ok_or(overflow.clone())?;
        // First sends (§3.1 step 8), only after establishment (§4.3).
        let mut needing_reset = 0u64;
        for index in 0..self.publications.len() {
            let Some(outbound) = self.publications.get(index) else {
                break;
            };
            let (endpoint, alias) = (outbound.endpoint(), outbound.alias());
            if !self.sessions.is_established(endpoint, alias) {
                // Not served yet, but a guard close still applies (the
                // close acknowledgement waits for it).
                if let Some(outbound) = self.publications.get_mut(index) {
                    outbound.guard_tick(now);
                }
                continue;
            }
            let consumption = self.consumption(endpoint, alias);
            let tx = halves.iter_mut().find_map(|(held, half)| match half {
                Half::Tx(tx) if *held == endpoint => Some(tx),
                _ => None,
            });
            let Some(tx) = tx else {
                // No TX half this cycle (its endpoint is being reset): a
                // guard close still applies.
                if let Some(outbound) = self.publications.get_mut(index) {
                    outbound.guard_tick(now);
                }
                continue;
            };
            let Some(outbound) = self.publications.get_mut(index) else {
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

    /// Replaces the sender's clock (tests: a rig's virtual time).
    #[cfg(test)]
    pub(super) fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    /// The receiver ids the bindings of `alias` learned from their SMs
    /// (tests).
    #[cfg(test)]
    pub(super) fn bound_receivers(&self, alias: Alias) -> Vec<Option<u64>> {
        self.bindings
            .iter()
            .filter(|binding| binding.alias == alias)
            .map(|binding| binding.receiver_id)
            .collect()
    }

    /// The membership of the publication `alias` (tests).
    #[cfg(test)]
    pub(super) fn membership_of(&self, alias: Alias) -> Option<&Membership> {
        self.publications
            .iter()
            .find(|outbound| outbound.alias() == alias)
            .and_then(|outbound| outbound.membership())
    }

    /// Drops every NAK unread from now on, as a sender that never repairs
    /// (tests).
    #[cfg(test)]
    pub(super) fn ignore_naks(&mut self) {
        self.ignore_naks = true;
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
            .and_then(|outbound| outbound.membership_mut())
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

    /// A NAK from `source` on `endpoint` at `now` (R4): within the cycle's
    /// `naks_per_cycle`, only from a receiver bound there (source, boot id,
    /// incarnation and receiver id), for a reliable publication; then
    /// admission and the job table. An admission ERR goes back to the
    /// NAK's source.
    ///
    /// A binding answered but not yet confirmed by its first SM has no
    /// receiver id: until then it admits a NAK naming any receiver id from
    /// its source, boot id and incarnation. A step 8 ERR needs the id
    /// ([`Self::reply_nak`]), so one for such a binding is not sent and
    /// counts `nak_replies_unbound`.
    fn nak<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        source: SocketAddr,
        nak: &Nak,
        now: u64,
    ) {
        #[cfg(test)]
        if self.ignore_naks {
            return;
        }
        if self.naks_this_cycle >= self.repair.naks_per_cycle {
            self.count(|c| &mut c.nak_cycle_budget);
            return;
        }
        self.expire_bindings(now);
        let normal = normalized(source);
        let bound = self.bindings.iter().any(|binding| {
            binding.endpoint == endpoint
                && binding.alias == nak.alias
                && binding.source == normal
                && binding.boot_id == nak.receiver.receiver_boot_id
                && binding.identity == nak.identity
                && binding
                    .receiver_id
                    .is_none_or(|id| id == nak.receiver.receiver_id)
        });
        let index = self.publications.iter().position(|outbound| {
            outbound.endpoint() == endpoint
                && outbound.alias() == nak.alias
                && outbound.repair().is_some()
        });
        let (true, Some(index)) = (bound, index) else {
            self.count(|c| &mut c.nak_unbound);
            return;
        };
        // Counted against the cycle once it reaches admission; below
        // `naks_per_cycle`, a u32, so it cannot overflow.
        self.naks_this_cycle = self
            .naks_this_cycle
            .checked_add(1)
            .unwrap_or(self.naks_this_cycle);
        self.count(|c| &mut c.naks);
        let Some(outbound) = self.publications.get_mut(index) else {
            return;
        };
        let requester = outbound
            .membership_mut()
            .map_or(Requester::Unknown, |membership| {
                membership.requester(nak.receiver, nak.range.lane, now)
            });
        if let NakIntake::Reply(reply) = outbound.nak(nak, requester, now)
            && self
                .send(halves, endpoint, source, &Control::NakReply(reply))
                .submitted()
        {
            self.count(|c| &mut c.nak_replies);
        }
    }

    /// The cycle's repairs (R7): the publications in turn from a cursor
    /// that moves each cycle, all within one shared repair budget; each
    /// one's step 8 ERRs go to their requesters' bound sources. Returns the
    /// repair datagrams submitted.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    fn serve_repairs<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        now: u64,
    ) -> Result<u32, AgentError> {
        let count = self.publications.len();
        if count == 0 {
            return Ok(0);
        }
        let first = self.repair_cursor % count;
        self.repair_cursor = (first + 1) % count;
        let mut budget = self.repair.budget;
        let mut submitted = 0u32;
        let mut replies = std::mem::take(&mut self.nak_replies);
        for step in 0..count {
            if budget.bytes == 0 || budget.loads == 0 {
                break;
            }
            let index = (first + step) % count;
            let Some(outbound) = self.publications.get(index) else {
                break;
            };
            let (endpoint, alias) = (outbound.endpoint(), outbound.alias());
            if outbound.repair().is_none() || !self.sessions.is_established(endpoint, alias) {
                continue;
            }
            let tx = halves.iter_mut().find_map(|(held, half)| match half {
                Half::Tx(tx) if *held == endpoint => Some(tx),
                _ => None,
            });
            let (Some(tx), Some(outbound)) = (tx, self.publications.get_mut(index)) else {
                continue;
            };
            let served = outbound.serve_repair(tx, &mut budget, now);
            let Some(total) = submitted.checked_add(served) else {
                // The list goes back before the error: it is never
                // allocated again.
                self.nak_replies = replies;
                return Err(AgentError::CountOverflow(AgentKind::Sender));
            };
            submitted = total;
            let capacity = replies.capacity();
            let mut dropped: Option<u64> = Some(0);
            outbound.drain_repair_replies(|reply| {
                // Bounded by the list each path keeps, the same capacity.
                if replies.len() < capacity {
                    replies.push((endpoint, *reply));
                } else {
                    dropped = dropped.and_then(|count| count.checked_add(1));
                }
            });
            match dropped.and_then(|count| self.counters.nak_replies_dropped.checked_add(count)) {
                Some(total) => self.counters.nak_replies_dropped = total,
                None => self.counters.overflowed = true,
            }
            for (endpoint, reply) in replies.drain(..) {
                self.reply_nak(halves, endpoint, &reply);
            }
        }
        self.nak_replies = replies;
        match self.counters.repairs.checked_add(u64::from(submitted)) {
            Some(repairs) => self.counters.repairs = repairs,
            None => self.counters.overflowed = true,
        }
        Ok(submitted)
    }

    /// Sends a step 8 ERR to its requester's bound source on `endpoint`:
    /// the binding of its alias, incarnation, boot id and receiver id as
    /// they are now, which may have expired or moved to another receiver
    /// id since the NAK's admission (then `nak_replies_unbound`).
    fn reply_nak<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        reply: &NakReply,
    ) {
        let destination = self
            .bindings
            .iter()
            .find(|binding| {
                binding.endpoint == endpoint
                    && binding.alias == reply.alias
                    && binding.identity == reply.identity
                    && binding.boot_id == reply.receiver.receiver_boot_id
                    && binding.receiver_id == Some(reply.receiver.receiver_id)
            })
            .map(|binding| binding.source);
        match destination {
            Some(destination) => {
                if self
                    .send(halves, endpoint, destination, &Control::NakReply(*reply))
                    .submitted()
                {
                    self.count(|c| &mut c.nak_replies);
                }
            }
            None => self.count(|c| &mut c.nak_replies_unbound),
        }
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
        let publication = self
            .publications
            .iter()
            .find(|outbound| outbound.endpoint() == endpoint && outbound.alias() == status.alias);
        let lane_count =
            publication.and_then(|outbound| u8::try_from(outbound.readers().len()).ok());
        // MC-2: an SM whose declared tag is not the one configured for its
        // receiver is rejected whole before it touches the binding, so it
        // neither refreshes nor pins it, establishes the session, nor holds
        // retention through its consumption.
        let tag_ok = publication
            .and_then(|outbound| outbound.membership())
            .is_none_or(|membership| {
                membership.configured_tag(status.receiver.receiver_id) == status.group_tag
            });
        if !tag_ok {
            self.count(|c| &mut c.sm_tag_mismatch);
            return;
        }
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
            .and_then(|outbound| outbound.membership_mut())
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
