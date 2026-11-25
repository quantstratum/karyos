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
use karyos_io::lanes::routes::MAX_ROUTES;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::frame::{FRAME_ALIGNMENT, Lane};
use karyos_protocol::network::{
    Alias, Control, Datagram, Identity, LaneStatus, Lanes, MAX_WINDOW, Nak, NakReply,
    PathHeartbeat, Receiver, Rttm, RttmKind, SetupAnnounce, SetupAnswer, StatusMessage, classify,
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
    ControlItem, ControlRoutes, ControlSeal, ControlSendError, ItemGuard, ReportGuard, ReportSlot,
    RouteSlot, SealedBytes, SendReport, SharedSealer, SmGuard, SmSlot,
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
use crate::embedded::StreamTerms;
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
use karyos_sys::term_bytes::HeapTerms;

/// A `control-mode=dynamic` subscription key (design 3.2; karyos#644):
/// where it registers, when its next REGISTER is due and its backoff.
#[derive(Debug)]
struct Registering {
    endpoint: EndpointId,
    stream_id: i32,
    /// The `control` address it registers at.
    control: SocketAddr,
    /// The monotonic time its next REGISTER is due, in ns.
    due: u64,
    /// The spacing of its next REGISTER, in ns: `setup_interval`, doubled
    /// after each one up to [`REGISTER_BACKOFF_STEPS`] doublings, and
    /// `setup_interval` again on an accepted ANSWER from `control` or once
    /// its image is gone (karyos#941 item 1, karyos#947).
    interval: u64,
    /// The registration state it writes for the application (karyos#941
    /// item 3).
    status: Arc<crate::sessions::register::RegistrationStatus>,
}

/// The doublings of a dynamic subscription's REGISTER interval while
/// nothing binds it: from `setup_interval` (100 ms) to sixteen times it
/// (1.6 s), so a publisher that is absent or refusing costs at most one
/// REGISTER every 1.6 s per key after the first second and a half
/// (karyos#941 item 1).
const REGISTER_BACKOFF_STEPS: u32 = 4;

/// The spread of the keys' REGISTERs within an interval: key `i` is due
/// `i mod REGISTER_STAGGER` eighths of an interval later than the bare
/// interval, so keys at one `control` do not all send in one cycle
/// (karyos#941 item 1).
const REGISTER_STAGGER: u64 = 8;

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
    /// REGISTERs dropped because the sender ring was full (karyos#644).
    pub ring_full_register: u64,
    /// REGISTERs a `control-mode=dynamic` subscription sent to its
    /// `control` address (design 3.2; karyos#644).
    pub registers_sent: u64,
    /// REGISTERs due that did not go: the RSP_SETUP limits or the control
    /// ring refused them, or the key has no configured receiver identity;
    /// each is tried again at the next interval.
    pub registers_unsent: u64,
    /// ERR REGISTRATIONs read from a subscription's `control` address
    /// (`DESTINATIONS_FULL`): the subscription keeps registering, backing
    /// off.
    pub registration_refusals: u64,
    /// REGISTERs due that their `control` address's own bucket refused
    /// (karyos#941 item 1); also counted in `registers_unsent`.
    pub registers_rate_limited: u64,
    /// SETUP ANNOUNCEs and ANSWERs dropped on a `control-mode=dynamic`
    /// key because they came from another source than its `control`
    /// address (karyos#941 item 5).
    pub setup_not_from_control: u64,
    /// Received SOLICITs dropped with the control ring full.
    pub ring_full_solicit: u64,
    /// Challenges not sent: the source is not an answerable unicast
    /// endpoint (network-control-schemas.md §7.3).
    pub unanswerable_source: u64,
    /// Challenges of a multicast key sent from its arrival endpoint: the
    /// key has no unicast control endpoint, so they share the group
    /// port's `setup_answer_rate` bucket (ADR-0096 decision 1).
    pub challenges_from_arrival: u64,
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
    /// endpoint, and REGISTER for a stream not published on it.
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
    /// Traced frames whose EXT did not decode: committed, not traced
    /// (trace-network.md NT-2).
    pub net_trace_ext_invalid: u64,
    /// Network journals a retirement closed while the retired queue was
    /// full of unposted closes: their facts are lost (the conductor's
    /// close then finds none, and the journal is `Lost`).
    pub net_journals_retired_dropped: u64,
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
    /// Lane terminal bounds recorded from EOS: an EOS heartbeat, or an EOS
    /// flag on a DATA frame's last fragment (network-sessions.md, Liveness
    /// and terminal transitions).
    pub eos_bounds: u64,
    /// EOS naming a lane's bound again (repeated during the linger):
    /// idempotent.
    pub eos_repeated: u64,
    /// EOS refused: another bound than the one recorded, below the lane's
    /// complete prefix, under data already covered, or outside its receive
    /// window.
    pub eos_refused: u64,
    /// DATA frames past their lane's terminal bound: dropped.
    pub data_past_terminal: u64,
    /// Heartbeats naming a position past their lane's terminal bound: the
    /// sender moved past its EOS. Classified at the bound.
    pub heartbeats_past_terminal: u64,
    /// DATA datagrams from no binding: dropped.
    pub data_unbound: u64,
    /// Envelopes their image's key refused: a field, the tag or the replay
    /// window (ADR-0086 sections 2 and 6). Dropped; nothing else changed.
    pub auth_rejected: u64,
    /// Envelopes for no authenticated binding: dropped before any key or
    /// state is touched, with no SOLICIT.
    pub auth_unbound: u64,
    /// Images of an authenticated subscription whose keys could not be
    /// made: not installed (fail closed).
    pub auth_install_refused: u64,
    /// Sealed controls of a receiver for an authenticated publication on
    /// this driver that a full control ring dropped.
    pub ring_full_sealed: u64,
    /// Signed GUARD or SESSION_ABORT datagrams refused by the receive
    /// order (by reason in the signed intake).
    pub signed_refused: u64,
    /// Signed datagrams with no trusted authority configured: dropped.
    pub signed_unconfigured: u64,
    /// Images closed by a verified SESSION_ABORT.
    pub images_closed_aborted: u64,
    /// SESSION_ABORTs for no bound authenticated image, or for one already
    /// aborted: no state changed.
    pub aborts_refused: u64,
    /// SESSION_ABORT_ACKs sent, and resent on a digest cache hit.
    pub abort_acks_sent: u64,
    /// SESSION_ABORT_ACKs resent for an identical SESSION_ABORT.
    pub abort_acks_resent: u64,
    /// GUARD STATE or STATUS accepted by a followed guard.
    pub guard_changes: u64,
    /// GUARD STATE or STATUS a followed guard refused (by reason on the
    /// guard), or for no followed guard.
    pub guard_refused: u64,
    /// Guard STATUS_CHALLENGEs sent.
    pub guard_challenges: u64,
    /// Raw datagrams a full control ring dropped.
    pub ring_full_raw: u64,
    /// GUARD STATUS answers signed and handed to the sender.
    pub guard_statuses_sent: u64,
    /// STATUS_CHALLENGEs this authority refused (by reason on it).
    pub guard_challenges_refused: u64,
    /// Bare DATA, heartbeats, PATH_HB, ERR, RTTM REPLY, SETUP ANNOUNCE or
    /// SETUP ANSWER for an authenticated image (ADR-0086 section 2):
    /// dropped.
    pub auth_bare: u64,
    /// Envelopes that opened but whose inner frames are not a domain 1
    /// datagram of their own binding: dropped.
    pub auth_inner_invalid: u64,
    /// DATA datagrams of a multi-path image that a full path queue dropped
    /// (redundant-paths.md section 5): that path's copy only. It also
    /// counts one longer than a slab slot (`MAX_DATAGRAM`), which no
    /// endpoint delivers; it is dropped rather than delivered past its
    /// path's queued datagrams.
    pub path_queue_drops: u64,
    /// DATA datagrams of a multi-path image delivered at once, past the
    /// path queues, for lack of a free queue.
    pub path_queue_bypassed: u64,
    /// DATA datagrams of a multi-path image queued in their path's queue.
    pub path_queued: u64,
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
    /// NAK copies on a later path reported uncertain (RC-6 per route).
    pub nak_copies_uncertain: u64,
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
    /// A reliable image's hole the receive owner could not compute, a
    /// data hole (`first_hole`) or a heartbeat's tail (`heartbeat_tail`):
    /// a corrupt owner state or a mark off a frame boundary; no NAK for
    /// it. An unreliable image's skip duty reports these as its own error.
    /// A defect counter, read through the receiver's counters, not a CnC
    /// cell.
    pub hole_query_errors: u64,
    /// Images closed by repair: a range proven unrecoverable under
    /// `on_unrecoverable = close`, or `GapCannotResume`.
    pub images_closed_unrecoverable: u64,
    /// Images closed by `GapCannotResume` (a floor beyond the window).
    pub images_closed_cannot_resume: u64,
    /// Images closed by a protocol fault (`range_invalid_limit`
    /// consecutive RANGE_INVALID).
    pub images_closed_protocol_fault: u64,
    /// Images closed cleanly: every lane's complete prefix reached its
    /// terminal bound.
    pub images_closed_eos: u64,
    /// Images whose every lane reached its terminal bound, yet a lane
    /// dropped a frame past it: retired, not clean.
    pub images_closed_eos_dropped: u64,
    /// Gaps sealed by the skip policy (unreliable timers, or `skip`).
    pub gaps_sealed: u64,
    /// Due holes of a conflated lane held by its seal gate in a duty
    /// (conflated-network-images.md (b)): posted, not sealed yet.
    pub seals_gated: u64,
    /// Intervals posted to a conflated view's feeder.
    pub barrier_posts: u64,
    /// Seals permitted after the feeder's acknowledgement.
    pub barrier_acks: u64,
    /// Conflated lane seals permitted at once: no feeder attached yet.
    pub seals_unattached: u64,
    /// Acknowledgements past `barrier_ack_timeout`: the view's terminal
    /// cell published (design (c)).
    pub barrier_timeouts: u64,
    /// Gate answers Pending while the feeder's claimed terminal cell was
    /// not yet published (docs#120).
    pub barrier_claim_waits: u64,
    /// Posts a view's mailbox refused: the view closed as at a timeout.
    pub barrier_post_failures: u64,
    /// Installed images whose key's conflated lane is not one of their
    /// lanes: no gate, no view.
    pub conflated_lane_out_of_range: u64,
    /// Seal gates moved to a recreated view's link (`RelinkView`).
    pub views_relinked: u64,
    /// `RelinkView` commands that moved no gate: the image retired, the
    /// lane is not its conflated lane, or its view is still open.
    pub relinks_refused: u64,
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
    /// Controls of an authenticated image that could not be sealed: never
    /// sent bare (ADR-0086 section 2).
    pub seal_failures: u64,
    /// Sealed controls of an authenticated publication its keys refused
    /// (by reason on the publication; ADR-0086 sections 2 and 7).
    pub auth_rejected: u64,
    /// Bare controls of a receiver for an authenticated publication:
    /// dropped.
    pub auth_bare: u64,
    /// Sealed controls for no authenticated publication: dropped.
    pub auth_unbound: u64,
    /// Session sealers installed at a binding.
    pub auth_sealers_installed: u64,
    /// RSP_SETUPs of another receiver than an authenticated publication's
    /// single one: refused, nothing bound or replaced.
    pub auth_other_receiver: u64,
    /// SESSION_ABORTs signed and sent (one per bound receiver).
    pub aborts_sent: u64,
    /// SESSION_ABORT_ACKs verified in domain 4.
    pub abort_acks: u64,
    /// Raw datagrams (sealed or signed controls) sent.
    pub raw_sent: u64,
    /// Idle heartbeats submitted: header-only DATA frames of established
    /// lanes that sent nothing for `sender_heartbeat_interval` (SPEC §6),
    /// one per route of a redundant-path lane, each counted.
    pub heartbeats_sent: u64,
    /// Queues and routes of removed publications, and of retired
    /// destinations of a multi-destination publication, the sender closed
    /// at its next duty (driver-network-agents.md §7: the sender drops its
    /// queues; multi-destination-unicast.md 3.7); a repair queue counts as
    /// one, a route as one.
    pub removed_closed: u64,
    /// Items still pending in those queues when they closed, returned
    /// with `QueueClosed`.
    pub removed_returned: u64,
    /// Removed publications' routes or queues, or retired destinations',
    /// not recorded for closing: the preallocated close list was full
    /// (under sustained churn). A removed publication's are recorded as
    /// their endpoint's close failure, whose standing reset drops them; a
    /// retired destination's wait in the publication for a later duty.
    pub removed_unrecorded: u64,
    /// Entries of the close list dropped at their duty, each counted once:
    /// their endpoint's TX half was not held (in a reset, which drops them,
    /// or retired) or was in another epoch (whose reset dropped them).
    pub removed_dropped: u64,
    /// Entries of the close list (a route and its queues) with a live
    /// handle the endpoint would not close, each counted once; a handle
    /// already gone counts as closed, and one with frames in flight is
    /// closed again at each duty, failing only on a close error or after
    /// [`super::CLOSE_IN_FLIGHT_TIMEOUT`]. When the endpoint then refuses a route or a
    /// queue for its limit in the same epoch, its reset is asked for once,
    /// tagged with that epoch (the endpoint table keeps it and serves it in
    /// that epoch): the new epoch drops them.
    pub removed_close_failed: u64,
    /// Endpoints with a failed close not recorded, with no room for them
    /// (never, by its capacity): their limit then resets nothing.
    pub close_failures_full: u64,
    /// ANNOUNCEs that waited for a control route of their endpoint to
    /// finish closing, sent in order at the next send or duty (#838).
    pub controls_waiting: u64,
    /// Controls dropped because every cached control route of their
    /// endpoint was closing (#849), by kind: SMs, NAKs, SETUP answers, and
    /// the others (RTTM, PATH_HB, RSP_SETUP, ERR). Only an ANNOUNCE waits.
    pub blocked_status: u64,
    /// See [`SenderCounters::blocked_status`].
    pub blocked_naks: u64,
    /// See [`SenderCounters::blocked_status`].
    pub blocked_setup_answers: u64,
    /// See [`SenderCounters::blocked_status`].
    pub blocked_other: u64,
    /// ANNOUNCEs dropped with no room to wait (never, by the waiting
    /// room's bound; see [`SenderCounters::blocked_status`]).
    pub blocked_announces: u64,
    /// Removed publications' entries closed again at the next duty because
    /// a queue still had frames in flight (#838).
    pub removed_close_deferred: u64,
    /// Of those, the ones still in flight after
    /// [`super::CLOSE_IN_FLIGHT_TIMEOUT`]: counted as failed closes.
    pub removed_close_timeouts: u64,
    /// Duties at which an entry in flight found `closing_again` full and
    /// stayed in the close list for the next duty: never a failure.
    pub removed_close_overflow: u64,
    /// EOS frames a removed publication's lanes submitted at their seals
    /// (driver-network-agents.md §7), repeats included.
    pub eos_sent: u64,
    /// Removals with a lane not drained to its seal by the drain bound,
    /// `max(publication_linger, path_heartbeat_interval)` after the
    /// removal's start: the lane sent no EOS and the session was reported
    /// drained anyway. A lane its closed guard stopped is not counted here.
    pub removals_undrained: u64,
    /// Removals with a guarded lane whose guard closed: it sent no EOS
    /// (GC-6), whether it drained or was given up at the drain bound.
    pub removals_guard_closed: u64,
    /// Removals with no established receiver: ended at once, with no
    /// linger, since nobody would read their EOS.
    pub removals_unestablished: u64,
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
    /// Receivers not recorded, or a dynamic publication's CHALLENGE not
    /// answered, because the free bindings are kept for required receiver
    /// ids of dynamic publications that have not joined yet (karyos#941
    /// item 2).
    pub bindings_reserved: u64,
    /// A dynamic publication's CHALLENGEs not answered because the binding
    /// table had no room for their receiver: the receiver gets no ANSWER,
    /// so it keeps registering (karyos#941 item 2).
    pub challenges_unbound: u64,
    /// SMs from a second source of a bound receiver (sender endpoint,
    /// alias, boot id and incarnation) that adopted a binding of their own
    /// (plan 169).
    pub bindings_adopted: u64,
    /// SMs from a further source of a bound receiver refused: its binding
    /// has `MAX_ADOPTIONS` adoptions already. They leave no state.
    pub bindings_adoption_refused: u64,
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
    /// Reset requests posted to the endpoint table: a publication's route
    /// fault, and an endpoint at its route or queue limit after a failed
    /// close in that epoch.
    pub reset_requests: u64,
    /// Reset requests not posted: the event ring was full.
    pub reset_requests_full: u64,
    /// PATH_HBs submitted on idle paths of routed publications (RP-3).
    pub path_heartbeats_sent: u64,
    /// NAKs that reached admission (at most `naks_per_cycle` per cycle).
    pub naks: u64,
    /// NAKs dropped over `naks_per_cycle`: the receiver retries.
    pub nak_cycle_budget: u64,
    /// NAKs from no receiver bound on that endpoint (source, alias, boot
    /// id, incarnation and receiver id), or for no reliable publication.
    pub nak_unbound: u64,
    /// NAK copies absorbed: another path carried the same request within
    /// `path_skew_window` (RP-11). They spend no NAK budget.
    pub nak_copies_absorbed: u64,
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
    /// REGISTERs naming no `control-mode=dynamic` publication of their
    /// stream on their endpoint, or one being removed: dropped, no reply
    /// (design 3.2 step 1). The other drops are the driver's
    /// [`SenderRole::registration_counters`].
    pub registers_unknown: u64,
    /// The one SETUP ANNOUNCE or ERR REGISTRATION a REGISTER caused, not
    /// sent (no route or queue, or the kernel refused it).
    pub registration_replies_unsent: u64,
    /// Registrants whose first valid SM took an optional destination slot
    /// (design 3.2).
    pub registrants_joined: u64,
    /// Registrants whose first valid SM found the optional slots taken
    /// meanwhile: answered one ERR REGISTRATION `DESTINATIONS_FULL`, their
    /// binding dropped (design 3.2).
    pub registrants_full: u64,
    /// Registrants whose first valid SM could not take a slot for another
    /// reason (the address quarantined, the publication being removed, a
    /// required receiver id restarted or at a new port, the same receiver
    /// still live elsewhere): dropped with their binding, no reply.
    pub registrants_refused: u64,
    /// Optional memberships a registrant's first valid SM retired because
    /// its `receiver_id` came back with a new boot id (design 3.2 step 4,
    /// reason `restarted`).
    pub registrants_restarted: u64,
    /// Optional memberships moved to a registrant's new endpoint after
    /// `destination_move_quiet` (MD-19, reason `moved`).
    pub registrants_moved: u64,
    /// Optional registrants removed because their receiver sent no SM for
    /// `image_liveness_timeout` (design 3.7, reason `timeout`).
    pub registrants_timed_out: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

/// A receiver this sender answered: where its SMs may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReceiverBinding {
    /// Its number, unique in the sender's life: what its adoptions name.
    id: u64,
    /// The binding an ANSWER created that this one was adopted for, or
    /// `None` for one an ANSWER created (network-control-schemas.md §6.3).
    parent: Option<u64>,
    endpoint: EndpointId,
    alias: Alias,
    /// The challenge's source, normalized: what a new answer to the same
    /// receiver matches.
    solicited_from: SocketAddr,
    /// The source of its first accepted SM, normalized: set once, never
    /// changed; its NAKs, ERRs and RTTMs match and reply on it (plan 169).
    sm_source: Option<SocketAddr>,
    /// The receiver boot id of the challenge block.
    boot_id: [u64; 2],
    /// The receiver block of the REGISTER whose pending entry its last
    /// ANSWER took, for a dynamic publication's registrant: its first SM
    /// must name it (design 3.2; karyos#940). `None` for any other answer.
    registered: Option<Receiver>,
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

/// Which binding an SM belongs to ([`SenderRole::sm_binding`]).
#[derive(Debug, Clone, Copy)]
enum SmBinding {
    /// The binding at this index, whose SM source is the SM's.
    Bound(usize),
    /// The binding at this index, which has no SM source yet.
    Learn(usize),
    /// A new binding to adopt for the ANSWER-created one at this index.
    Adopt(usize),
}

impl ReceiverBinding {
    /// Where its SMs, NAKs and RTTMs come from and its replies go: its
    /// first SM's source, or until then its challenge's.
    fn source(&self) -> SocketAddr {
        self.sm_source.unwrap_or(self.solicited_from)
    }
}

/// The SM sources a binding an ANSWER created may adopt besides its own:
/// it and its adoptions cover at most one source per redundant path of a
/// channel, so one receiver cannot fill the table with bindings nothing
/// evicts (network-control-schemas.md §6.3, plan 169).
const MAX_ADOPTIONS: usize = karyos_protocol::channel::MAX_PATHS - 1;

pub(super) fn bump(value: &mut u64, overflowed: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *overflowed = true,
    }
}

/// An endpoint that failed to close something in its current epoch: when
/// one of its routes or queues is then refused for its limit, what did not
/// close may be what holds it there, so its reset is asked for, once per
/// epoch: the endpoint table keeps a deferred request and serves it when
/// its interval ends (QS-COORDINATOR on #838). A new epoch starts afresh.
#[derive(Debug, Clone, Copy)]
struct EndpointCloses {
    endpoint: EndpointId,
    epoch: karyos_io::backend::BackendEpoch,
    reset: CloseReset,
}

/// How a removed publication's entry closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryClosed {
    /// Every handle closed, or was gone already.
    Done,
    /// A queue still has frames in flight: closed again at each duty, up
    /// to [`super::CLOSE_IN_FLIGHT_TIMEOUT`].
    InFlight,
    /// A live handle did not close.
    Failed,
}

/// Where an [`EndpointCloses`]' reset stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReset {
    /// No limit refused yet.
    Idle,
    /// A limit was refused: the reset is to be asked for.
    Due,
    /// Asked for in this epoch, once: the endpoint table keeps it and
    /// serves it in that epoch.
    Asked,
}

/// Test only: positions and lengths a receiver lost on purpose, shared
/// with a sender that holds back only the NAKs for them (karyos#1067).
#[cfg(test)]
pub(crate) type HeldRanges = std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>;

/// Test only: the frame length, term offset and term id of the DATA frame
/// `bytes` starts with, from its header (word 0, the term offset at bytes 8
/// to 12, the term id at 20 to 24); `None` for another frame type or a
/// short datagram.
#[cfg(test)]
fn drop_tail_frame(bytes: &[u8]) -> Option<(i32, u32, u32)> {
    use karyos_sys::frame::{FrameType, Word0};

    let word0 = Word0::unpack(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?)).ok()?;
    if FrameType::try_from_code(word0.frame_type_code()).ok()? != FrameType::Data {
        return None;
    }
    let offset = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?);
    let term = u32::from_le_bytes(bytes.get(20..24)?.try_into().ok()?);
    Some((word0.frame_length(), offset, term))
}

/// Test only: a tail's first transmission lost (`ReceiverRole::drop_tail`):
/// what it lost and from which sources its heartbeat showed all of it.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct DropTail {
    /// The term offset the tail starts at.
    offset: u32,
    /// Whether it is lost from one source only.
    one_source: bool,
    /// That source, once chosen.
    chosen: Option<SocketAddr>,
    /// The end of the frames lost so far.
    end: u32,
    /// The term they are in: the first lost frame's.
    term: Option<u32>,
    /// The sources whose idle heartbeat at or past `end` arrived.
    done: [Option<SocketAddr>; 4],
}

/// The receiver agent's network state.
#[derive(Debug)]
pub struct ReceiverRole<T: StreamTerms = HeapTerms> {
    /// Test only: the DATA datagrams to drop at the intake, by their
    /// count since the hook was set (a lossy path).
    #[cfg(test)]
    drop_data: Vec<u64>,
    /// Test only: the positions and lengths of the DATA `drop_data` lost,
    /// shared with a sender that holds back only the NAKs for them
    /// (karyos#1067). First term positions: the term offset.
    #[cfg(test)]
    dropped: Option<HeldRanges>,
    /// Test only: term offsets of the first term whose DATA datagram is
    /// lost on every arrival until the test releases it (karyos#1067): a
    /// hole planted by position, which natural loss before it does not
    /// move and a repair for another receiver does not fill.
    #[cfg(test)]
    drop_once_at: Vec<u32>,
    /// Test only: DATA datagrams seen since the hook was set.
    #[cfg(test)]
    data_seen: u64,
    /// Test only: DATA datagrams from this count on arrive twice (a path
    /// that duplicates).
    #[cfg(test)]
    repeat_data_from: Option<u64>,
    /// Test only: a tail's first transmission lost: DATA datagrams with a
    /// payload at or past this term offset of the first term are lost
    /// from a source until that source's idle heartbeat at or past it
    /// arrives (so repairs after it pass), on every source or on the first
    /// such datagram's source only (a tail lost on one path). Heartbeats
    /// always arrive. The sources: the chosen one, and those done.
    #[cfg(test)]
    drop_tail: Option<DropTail>,
    /// Test only: every NAK handed to the sender.
    #[cfg(test)]
    posted_naks: Vec<Nak>,
    /// Test only: every RSP_SETUP handed to the sender, with its endpoint.
    #[cfg(test)]
    posted_challenges: Vec<(EndpointId, Control)>,
    /// Tests: what the receiver saw, for a failure message (karyos#1067).
    #[cfg(test)]
    debug_trace: Vec<String>,
    /// Tests: the term offset of the first DATA datagrams, as they arrive.
    #[cfg(test)]
    rx_offsets: Vec<u32>,
    #[cfg(test)]
    dropped_notes: u64,
    /// Test only: NAKs handed over on an image's founding path.
    #[cfg(test)]
    founding_naks: u64,
    /// Test only: SMs handed over on an image's founding path.
    #[cfg(test)]
    founding_sms: u64,
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
    /// The solicit entries due a retry this duty (plan 164), allocated at
    /// creation: `max_pending_challenges`.
    solicit_due: Vec<crate::sessions::receive::BindingKey>,
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
    /// Per subscription key, the endpoint its SOLICITs leave from (plan
    /// 164), allocated at creation.
    solicit_from: Vec<(EndpointId, i32, EndpointId)>,
    /// Per subscription key, its channel's `path-skew` in ns (karyos#1056),
    /// allocated at creation: its images' skew window.
    skews: Vec<(EndpointId, i32, u64)>,
    /// The `control-mode=dynamic` subscription keys (design 3.2;
    /// karyos#644). Allocated at creation: at most one per subscription
    /// key.
    registering: Vec<Registering>,
    /// `setup_interval`: the first spacing of a dynamic subscription's
    /// REGISTERs, which backs off from there (karyos#941 item 1).
    setup_interval: u64,
    /// The REGISTERs' own bucket per `control` address, the port ignored,
    /// apart from the RSP_SETUP limits its CHALLENGEs and SOLICITs draw on
    /// (karyos#941 item 1): `rsp_setup_per_destination` a second, for at
    /// most `subscriptions` addresses (allocated at creation).
    register_rates: EndpointRates,
    /// The conflated lane of subscribed keys (conflated-network-images.md
    /// (a); at most one per key, allocated at start): their images gate
    /// that lane's seals.
    conflated: Vec<(EndpointId, i32, Lane)>,
    /// `barrier_ack_timeout` of the conflated lanes' seal gates.
    barrier_ack_timeout: u64,
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
    images: Vec<Installed<T>>,
    /// One SM slot flag per image, allocated at creation; an image takes
    /// one only the pool holds.
    sm_slots: Vec<Arc<SmSlot>>,
    sm_interval: u64,
    liveness_timeout: u64,
    idle_timeout: u64,
    /// The path statistics' configuration (redundant-paths.md section 5).
    path_config: PathConfig,
    /// The path queues, allocated when the first later path is bound.
    path_intake: Option<Box<path_intake::PathIntake>>,
    /// Refused envelopes no authenticated binding owns (unbound, or too
    /// short to name one), by reason (ADR-0086 section 2).
    auth_unattributed: AuthRejections,
    /// The local authenticated publications, by endpoint and alias: their
    /// receivers' envelopes go to the sender agent undecoded, their bare
    /// controls are dropped.
    published_auth: Vec<(EndpointId, Alias)>,
    /// The authenticated subscriptions.
    subscription_auth: Vec<SubscriptionAuth>,
    /// A SETUP ANNOUNCE or ANSWER being handled verified under its
    /// subscription's SETUP proof.
    verified_setup: bool,
    /// The receive order of the signed domains, with the authorities this
    /// driver trusts; `None` until one is configured.
    signed: Option<Box<SignedIntake<AckResend>>>,
    /// The guards of other drivers this one follows.
    remote_guards: Vec<FollowedGuard>,
    /// Their durable epoch marks.
    guard_marks: Option<Box<dyn MarkStore + Send>>,
    /// The guard authority this driver is, answering STATUS_CHALLENGEs.
    guard_authority: Option<Box<crate::guard_authority::GuardAuthority>>,
    /// Each image's RTT probes' settings.
    rtt: RttConfig,
    /// A multicast image's NAK timing.
    multicast: MulticastConfig,
    /// A unicast image's retry slack (owner item 9).
    unicast_retry_slack: u64,
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
fn apply_evidence<T: StreamTerms>(
    image: &mut Installed<T>,
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
fn classify_heartbeat<T: StreamTerms>(
    image: &mut Installed<T>,
    heartbeat: &Heartbeat,
) -> HeartbeatClass {
    let lane = heartbeat.lane();
    let Some(position) = heartbeat_position(image, heartbeat) else {
        return HeartbeatClass::Rejected;
    };
    if !image.owner.within_window(lane, position).unwrap_or(false) {
        return HeartbeatClass::Rejected;
    }
    // Nothing past a recorded terminal bound is marked: the sender has
    // nothing there to repair.
    let position = match terminal_bound(image, lane) {
        Some(bound) => position.min(bound),
        None => position,
    };
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

/// The stream position `heartbeat` names in `image`, or `None` for a term
/// outside the incarnation.
fn heartbeat_position<T: StreamTerms>(image: &Installed<T>, heartbeat: &Heartbeat) -> Option<u64> {
    let count = heartbeat.term_id().count_from(image.initial_term_id).ok()?;
    u64::from(count.get())
        .checked_mul(u64::from(image.term_length))?
        .checked_add(u64::from(heartbeat.term_offset()))
}

/// What recording an EOS bound did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Terminal {
    /// The lane's bound is recorded.
    Recorded,
    /// The same bound again (the sender repeats it during its linger).
    Repeated,
    /// Refused: another bound than the recorded one, below the complete
    /// prefix, or under data already covered.
    Refused,
}

/// Records `bound` as `lane`'s terminal bound in `image`: the first EOS
/// decides, a repeat of it is idempotent, and no bound is accepted below
/// the lane's complete prefix or its covered data. EOS ahead of a hole is
/// recorded; the hole is still repaired before the image completes.
fn record_terminal<T: StreamTerms>(image: &mut Installed<T>, lane: Lane, bound: u64) -> Terminal {
    let (Some(rebuild), Some(high)) = (
        image.owner.rebuild_position(lane),
        image.owner.high_water(lane),
    ) else {
        return Terminal::Refused;
    };
    let Some(slot) = image.terminal.get_mut(usize::from(lane.get())) else {
        return Terminal::Refused;
    };
    match *slot {
        Some(recorded) if recorded == bound => Terminal::Repeated,
        Some(_) => Terminal::Refused,
        None if bound < rebuild || bound < high => Terminal::Refused,
        None => {
            *slot = Some(bound);
            Terminal::Recorded
        }
    }
}

/// Counts what recording an EOS bound did.
fn tally_terminal(counters: &mut ReceiverCounters, outcome: Terminal) {
    tally(
        counters,
        match outcome {
            Terminal::Recorded => |c| &mut c.eos_bounds,
            Terminal::Repeated => |c| &mut c.eos_repeated,
            Terminal::Refused => |c| &mut c.eos_refused,
        },
    );
}

/// `lane`'s terminal bound in `image`, once an EOS named it.
fn terminal_bound<T: StreamTerms>(image: &Installed<T>, lane: Lane) -> Option<u64> {
    image
        .terminal
        .get(usize::from(lane.get()))
        .copied()
        .flatten()
}

/// Whether `frame` ends past its lane's terminal bound in `image`: no
/// later position is accepted once EOS named the bound.
fn past_terminal<T: StreamTerms>(image: &Installed<T>, frame: &ValidatedFrame<'_>) -> bool {
    let Some(bound) = terminal_bound(image, frame.lane()) else {
        return false;
    };
    frame_position(image, frame)
        .and_then(|position| position.checked_add(u64::from(frame.extent())))
        .is_none_or(|end| end > bound)
}

/// Whether every lane of `image` reached its terminal bound through its
/// complete prefix: the image's end. It is clean only when no lane
/// dropped a frame past its bound ([`dropped_past_terminal`]).
fn terminal_reached<T: StreamTerms>(image: &Installed<T>) -> bool {
    (0..image.lane_count).all(|lane| {
        Lane::try_new(lane).ok().is_some_and(|lane| {
            terminal_bound(image, lane)
                .is_some_and(|bound| image.owner.rebuild_position(lane) == Some(bound))
        })
    })
}

/// Whether any lane of `image` dropped a frame past its terminal bound:
/// data its subscriber never reads, so the image does not end clean.
fn dropped_past_terminal<T: StreamTerms>(image: &Installed<T>) -> bool {
    image.dropped_past_terminal.iter().any(|dropped| *dropped)
}

/// What the path statistics record of `frame` from `path`: its lane, term
/// count, stream position and extent. `None` off any bound path or for a
/// term outside the incarnation.
/// The stream position of `frame` in `image`, or `None` for a term outside
/// the incarnation.
fn frame_position<T: StreamTerms>(image: &Installed<T>, frame: &ValidatedFrame<'_>) -> Option<u64> {
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
fn terms_complete<T: StreamTerms>(image: &mut Installed<T>) {
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
fn copy_index<T: StreamTerms>(image: &Installed<T>, at: usize, path: usize) -> Option<usize> {
    at.checked_mul(image.routes.len())?.checked_add(path)
}

/// Whether a copy of lane `at`'s last NAK still waits for its report.
fn copies_busy<T: StreamTerms>(image: &Installed<T>, at: usize) -> bool {
    (0..image.routes.len()).any(|path| {
        copy_index(image, at, path)
            .and_then(|index| image.copies.get(index))
            .is_some_and(|copy| copy.slot.busy())
    })
}

/// Settles the reports of lane `at`'s NAK copies on the later paths
/// (RP-7): the first submitted anchors the NAK unless another copy already
/// did; an uncertain one becomes the round's anchor candidate, used only
/// if no copy is submitted once all have reported; a copy not submitted
/// leaves the NAK due unless one anchored it.
/// Uncertainty counts per path route: a second uncertain copy on one
/// route while its first is unresolved faults that route, which then
/// takes no copy until its endpoint is reset.
fn settle_copies<T: StreamTerms>(
    image: &mut Installed<T>,
    counters: &mut ReceiverCounters,
    at: usize,
) {
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
        let mut route_ok = true;
        if let (SendReport::Uncertain(_), Some(route)) = (settled, image.routes.get_mut(path)) {
            tally(counters, |c| &mut c.nak_copies_uncertain);
            if route.uncertain {
                route.faulted = true;
                route_ok = false;
                tally(counters, |c| &mut c.nak_route_faults);
            } else {
                route.uncertain = true;
            }
        }
        let anchored = image.anchored.get(at).copied().flatten() == Some(nak);
        match (settled, anchored) {
            (SendReport::Submitted(start), false) => {
                image.loss.submitted(&nak, start, &image.rtt);
                // A NAK before the path's first sample probes early (owner item 9).
                let _ = image.rtt.expedite(start);
                if let Some(anchor) = image.anchored.get_mut(at) {
                    *anchor = Some(nak);
                }
                if let Some(candidate) = image.uncertain_at.get_mut(at) {
                    *candidate = None;
                }
            }
            (SendReport::Uncertain(start), false) if route_ok => {
                uncertain_candidate(image, at, nak, start);
            }
            (SendReport::NotSubmitted, false) => image.loss.not_submitted(&nak),
            _ => {}
        }
    }
}

/// Settles lane `at`'s NAK on the founding path: RC-6 on the image's own
/// route. A NAK another path's copy already anchored records nothing more
/// (RP-7: the anchor is the first copy submitted).
fn settle_founding<T: StreamTerms>(
    image: &mut Installed<T>,
    counters: &mut ReceiverCounters,
    at: usize,
) {
    let Some(report) = image.naks.get_mut(at) else {
        return;
    };
    let (Some(settled), Some(nak)) = (report.slot.collect(false), report.pending) else {
        return;
    };
    report.pending = None;
    let anchored = image.anchored.get(at).copied().flatten() == Some(nak);
    match (settled, anchored) {
        (SendReport::Submitted(start), false) => {
            image.loss.submitted(&nak, start, &image.rtt);
            // A NAK before the path's first sample probes early (owner item 9).
            let _ = image.rtt.expedite(start);
            if let Some(slot) = image.anchored.get_mut(at) {
                *slot = Some(nak);
            }
        }
        (SendReport::NotSubmitted, false) => image.loss.not_submitted(&nak),
        // RC-6 on the founding route: a second uncertain NAK while one is
        // unresolved is a route fault. An uncertain copy anchors only if no
        // copy of its round is submitted ([`anchor_uncertain`]).
        (SendReport::Uncertain(start), anchored) => {
            if image.loss.route_uncertain().is_err() {
                tally(counters, |c| &mut c.nak_route_faults);
            } else if !anchored {
                uncertain_candidate(image, at, nak, start);
            }
        }
        (SendReport::Submitted(_) | SendReport::NotSubmitted, true) => {}
    }
}

/// Once every copy of lane `at`'s round has reported and none was
/// submitted, anchors its NAK at the earliest uncertain copy, counted as
/// submitted at its start (RC-6; #310 review).
fn anchor_uncertain<T: StreamTerms>(image: &mut Installed<T>, at: usize) {
    let reported =
        !copies_busy(image, at) && image.naks.get(at).is_none_or(|report| !report.slot.busy());
    if reported
        && let Some((nak, start)) = image.uncertain_at.get_mut(at).and_then(Option::take)
        && image.anchored.get(at).copied().flatten() != Some(nak)
    {
        image.loss.submitted(&nak, start, &image.rtt);
        // A NAK before the path's first sample probes early (owner item 9).
        let _ = image.rtt.expedite(start);
        if let Some(slot) = image.anchored.get_mut(at) {
            *slot = Some(nak);
        }
    }
}

/// Records an uncertain copy of `nak` started at `start` as lane `at`'s
/// anchor candidate, keeping the earliest start of its round.
fn uncertain_candidate<T: StreamTerms>(image: &mut Installed<T>, at: usize, nak: Nak, start: u64) {
    if let Some(candidate) = image.uncertain_at.get_mut(at) {
        match candidate {
            Some((held, earlier)) if *held == nak && *earlier <= start => {}
            _ => *candidate = Some((nak, start)),
        }
    }
}

/// Posts a copy of `nak`, lane `at`'s NAK just handed over on the
/// founding path, on every other bound path whose route is not faulted
/// (RP-7). A copy the control ring cannot take is skipped and counted,
/// never deferred.
///
/// Copies draw from the control ring's unreserved units, as forwarded
/// controls do: a burst of copies can leave a later image's founding NAK
/// without room, which counts as `ring_full_nak` and stays due. A copy
/// still in the ring delays the lane's next NAK on every path
/// (`copies_busy`) until the sender reports it.
fn post_copies<T: StreamTerms>(
    image: &mut Installed<T>,
    key_of: impl Fn(usize) -> Option<BindingKey>,
    to_sender: &mut RingSender<ControlItem>,
    counters: &mut ReceiverCounters,
    at: usize,
    nak: Nak,
) -> u32 {
    let mut posted = 0u32;
    for path in 0..image.routes.len() {
        let Some(key) = key_of(path) else {
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
            seal: image.auth.as_deref().map(ImageAuth::sealer),
        };
        match to_sender.try_post(item) {
            Ok(()) => {
                copy.pending = Some(nak);
                tally(counters, |c| &mut c.nak_copies);
                // At most one copy per route: no overflow.
                if let Some(next) = posted.checked_add(1) {
                    posted = next;
                }
            }
            Err(_) => tally(counters, |c| &mut c.nak_copies_skipped),
        }
    }
    posted
}

fn delivered<T: StreamTerms>(
    image: &Installed<T>,
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
    /// The receiver cycle its last endpoint reset request was posted in,
    /// while it is faulted.
    reset_requested: Option<u64>,
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
    /// The establishment's challenge nonce: it salts the image's unicast
    /// session keys (ADR-0086 section 4).
    nonce: [u64; 2],
}

/// An installed image: its receive owner, binding, SM cadence and
/// liveness.
#[derive(Debug)]
struct Installed<T: StreamTerms = HeapTerms> {
    /// The installed slot.
    slot: SlotRef,
    owner: Box<ReceiveOwner<T>>,
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
    /// Per lane, the terminal bound its EOS named: no later position is
    /// accepted, and the image closes cleanly once every lane's complete
    /// prefix reaches its bound.
    terminal: [Option<u64>; 4],
    /// Per lane, whether a frame past its terminal bound was dropped: the
    /// publisher wrote past its EOS, so the lane cannot end clean.
    dropped_past_terminal: [bool; 4],
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
    /// Its loss counts' CnC cells (M2b), once the conductor attached them
    /// to its exposed stream: the receiver is their only writer.
    cells: Option<crate::agents::AgentCells>,
    /// The seal gate of its conflated lane, with a conflated view
    /// (conflated-network-images.md (b)).
    gate: Option<Box<super::conflated_gate::ConflatedGate>>,
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
    /// Per lane, the earliest uncertain copy of the round, with its start:
    /// it anchors the NAK only if no copy is submitted (#310 review).
    uncertain_at: [Option<(Nak, u64)>; 4],
    /// The founding path's subscription is gone while a later path keeps
    /// the image: control goes on the later paths only (#307 review P2-3).
    founding_gone: bool,
    /// Its subscription's NAK control group: the endpoint joined to it and
    /// the group's address (RC-7, RC-15).
    control_group: Option<(EndpointId, SocketAddr)>,
    /// Each later path's NAK control group, by path index, set when the
    /// path is bound from its own subscription entry (RC-15; karyos#1064).
    /// Allocated with the image, one slot per path.
    path_groups: Vec<Option<(EndpointId, SocketAddr)>>,
    /// The `receiver_id` it names in every RB block: its key's configured
    /// identity, else derived from its slot.
    receiver_id: u64,
    /// The `group_tag` its SMs declare (0 without a configured identity).
    group_tag: u64,
    /// The challenge nonce of the establishment that bound it: read when
    /// its keys are made, which only tests do until an authenticated
    /// channel can be opened.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no authenticated channel opens yet")
    )]
    nonce: [u64; 2],
    /// Its wire authentication on an authenticated channel (ADR-0086):
    /// its datagrams are opened before any inner frame is read and its
    /// controls sealed; `None` on a trusted channel.
    auth: Option<Box<ImageAuth>>,
    /// The `guard_epoch` of the SESSION_ABORT applied to it: a second one
    /// changes nothing.
    aborted: Option<u64>,
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
    /// A verified SESSION_ABORT (ADR-0086, domain 3).
    Aborted,
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
fn tail_hole<T: StreamTerms>(
    image: &mut Installed<T>,
    lane: Lane,
    at: usize,
    now: u64,
    counters: &mut ReceiverCounters,
) -> Option<Hole> {
    use crate::repair::loss::RttSource;

    let tail =
        match heartbeat_mark(image, lane, at).map(|mark| image.owner.heartbeat_tail(lane, mark)) {
            Some(Ok(tail)) => tail,
            Some(Err(_)) => {
                tally(counters, |c| &mut c.hole_query_errors);
                None
            }
            None => None,
        };
    let Some((start, length)) = tail else {
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
    Some(Hole { start, length })
}

/// `lane`'s heartbeat mark (at index `at`), the sender's next position,
/// never past a recorded terminal bound: the end of a tail no frame
/// revealed, which a reliable image NAKs and an unreliable one seals.
fn heartbeat_mark<T: StreamTerms>(image: &Installed<T>, lane: Lane, at: usize) -> Option<u64> {
    image
        .heartbeat_marks
        .get(at)
        .copied()
        .flatten()
        .map(|mark| terminal_bound(image, lane).map_or(mark, |bound| mark.min(bound)))
}

/// `hole` of `image`'s `lane` proven unrecoverable, with the sender's
/// lowest retained position: the skip policy seals it (`skip`) or decides
/// the image's close (`close`, or a floor beyond the window). The whole
/// hole is unrecoverable even when the floor lies inside it (RC-9), so the
/// policy is given the later of the floor and the hole's end: it seals
/// every hole starting below that.
fn unrecoverable<T: StreamTerms>(
    image: &mut Installed<T>,
    counters: &mut ReceiverCounters,
    trace: &mut super::net_trace::ReceiverTrace,
    lane: Lane,
    hole: Hole,
    lowest_retained: u64,
    now: u64,
) {
    let slot = image.slot;
    let floor = hole
        .start
        .checked_add(u64::from(hole.length))
        .map_or(lowest_retained, |end| lowest_retained.max(end));
    // Each committed seal reaches the lane's trace journal, if any (§5).
    let sealed = |lane, position, extent| trace.sealed(slot, lane, position, extent);
    let unavailable = match image.gate.as_deref_mut() {
        Some(gate) => {
            image
                .skip
                .range_unavailable_observed(&mut image.owner, lane, floor, now, gate, sealed)
        }
        None => image.skip.range_unavailable_observed(
            &mut image.owner,
            lane,
            floor,
            now,
            &mut karyos_sys::log_buffer::Ungated,
            sealed,
        ),
    };
    tally_gate(
        counters,
        image,
        unavailable.as_ref().map_or(0, |report| report.gated),
    );
    match unavailable {
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
fn window_end<T: StreamTerms>(
    owner: &ReceiveOwner<T>,
    lane: Lane,
    term_length: u32,
) -> Option<u64> {
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

/// The publication identity an image receives (trace-network.md §5).
fn publication_of<T: StreamTerms>(
    image: &Installed<T>,
) -> karyos_protocol::trace_hook::PublicationIdentity {
    karyos_protocol::trace_hook::PublicationIdentity {
        driver: image.identity.driver_id,
        registration: image.identity.registration_id,
        stream_id: image.key.alias.stream_id,
        session_id: image.key.alias.session_id,
        incarnation: image.identity.incarnation,
    }
}

/// The facts of a receiver journal at its close (§5): its start, the
/// lane's resolved prefix as the commit boundary, and the lane's first
/// sealed gap. Without the image's owner (it is gone), the boundary is
/// the start and no gap is known.
fn journal_facts<T: StreamTerms>(
    traced: super::net_trace::TracedImageLane,
    owner: Option<&ReceiveOwner<T>>,
) -> super::net_trace::JournalFacts {
    super::net_trace::JournalFacts {
        publication: traced.publication,
        number: traced.number,
        start: traced.start,
        boundary: owner
            .and_then(|owner| owner.rebuild_position(traced.lane))
            .unwrap_or(traced.start),
        first_gap: owner
            .and_then(|owner| owner.first_loss(traced.lane))
            .flatten(),
        gaps: Some(traced.gaps),
    }
}

/// Adds one to a receiver counter; sticky on overflow.
fn tally(counters: &mut ReceiverCounters, field: fn(&mut ReceiverCounters) -> &mut u64) {
    let mut overflowed = counters.overflowed;
    bump(field(counters), &mut overflowed);
    counters.overflowed = overflowed;
}

/// Adds `delta` to the counter `field` picks, checked as [`tally`].
fn tally_by(
    counters: &mut ReceiverCounters,
    field: fn(&mut ReceiverCounters) -> &mut u64,
    delta: u64,
) {
    let value = field(counters);
    match value.checked_add(delta) {
        Some(next) => *value = next,
        None => counters.overflowed = true,
    }
}

/// Settles what an image's seal gate did into the receiver's counters.
fn tally_gate<T: StreamTerms>(
    counters: &mut ReceiverCounters,
    image: &mut Installed<T>,
    gated: u32,
) {
    tally_by(counters, |c| &mut c.seals_gated, u64::from(gated));
    let Some(gate) = image.gate.as_deref_mut() else {
        return;
    };
    let counts = gate.take_counts();
    tally_by(counters, |c| &mut c.barrier_posts, counts.posted);
    tally_by(counters, |c| &mut c.barrier_acks, counts.acknowledged);
    tally_by(counters, |c| &mut c.seals_unattached, counts.unattached);
    tally_by(counters, |c| &mut c.barrier_timeouts, counts.timeouts);
    tally_by(counters, |c| &mut c.barrier_claim_waits, counts.claim_waits);
    tally_by(
        counters,
        |c| &mut c.barrier_post_failures,
        counts.post_failures,
    );
    if counts.overflowed {
        counters.overflowed = true;
    }
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

/// How [`SenderRole::send_with`] sends a control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Now, or dropped.
    Now,
    /// Now, or waiting in order while every cached route is closing.
    Wait,
    /// Now, on a transient route (karyos#977).
    Reply,
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
pub struct SenderRole<T: StreamTerms = HeapTerms> {
    sessions: SendSessions,
    from_receiver: RingReceiver<ControlItem>,
    /// Each publication's data path: readers, channel destination, lane
    /// queues (at most `publications`, allocated at creation).
    publications: Vec<Box<Outbound<T>>>,
    /// Control routes, one slot per endpoint the agent can hold.
    routes: Vec<RouteSlot>,
    budget: u32,
    /// The announcements due this cycle (allocated at creation).
    due: Vec<(EndpointId, SetupAnnounce)>,
    /// The authenticated publications' keys (ADR-0086).
    publication_auth: Vec<PublicationAuth>,
    /// SESSION_ABORTs requested, sent at the next duty.
    aborts: Vec<RequestedAbort>,
    /// The last SESSION_ABORT_ACK verified (tests).
    #[cfg(test)]
    last_abort_ack: Option<karyos_protocol::network::authenticated::AbortAck>,
    /// The last SESSION_ABORT sent, to resend it identically (tests).
    #[cfg(test)]
    last_abort: Option<(EndpointId, SocketAddr, SealedBytes)>,
    /// `path_heartbeat_interval` in ns (RP-3).
    path_heartbeat_interval: u64,
    /// `sender_heartbeat_interval` in ns (SPEC §6).
    sender_heartbeat_interval: u64,
    /// `setup_interval`: the spacing of a destination's counted open
    /// failures (karyos#630).
    setup_interval: u64,
    /// Removed publications' routes and queues, closed at the next duty
    /// with the TX halves (allocated at creation: `publications` routes'
    /// worth, the most removals can leave).
    closing: Vec<super::data::Opened>,
    /// Endpoints a close failed on, whose reset the sender asks for: the
    /// reset drops what would not close, which nothing else frees.
    close_failures: Vec<EndpointCloses>,
    /// Removed publications' entries whose queues still had frames in
    /// flight, with the duty that first found them so: closed again at each
    /// duty until they close, fail with a close error, or outlive
    /// [`super::CLOSE_IN_FLIGHT_TIMEOUT`] (allocated at creation, as
    /// `closing`).
    closing_again: Vec<(super::data::Opened, u64)>,
    /// Test only: the next closes of removed entries to report in flight,
    /// before touching any handle (the sockets backend has no such state
    /// a driver test can reach).
    #[cfg(test)]
    close_in_flight: u32,
    /// Report storage for those closes (allocated at creation).
    close_report: karyos_io::backend::TxReport,
    /// When a routed publication's path leaves the live set (RP-8).
    path_policy: super::data::PathPolicy,
    /// The receivers answered, at most `receiver_bindings` (allocated at
    /// creation).
    bindings: Vec<ReceiverBinding>,
    max_bindings: usize,
    /// The next binding's [`ReceiverBinding::id`].
    next_binding: u64,
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
    /// The driver's dynamic registrations, shared by its
    /// `control-mode=dynamic` publications: the `registration_rate`, the
    /// pending and the refusal tables (design 3.2; karyos#644).
    registrations: crate::sessions::register::Registrations,
    /// The network trace hook and journals (P2.12 step 3).
    trace: super::net_trace::SenderTrace,
    /// Test only: NAKs are dropped unread, as from a sender that never
    /// repairs (receiver rigs that answer NAKs themselves).
    #[cfg(test)]
    ignore_naks: bool,
    /// Test only: NAKs of this receiver boot id that ask for a range in
    /// the shared list are dropped unread, every other answered
    /// (karyos#1067).
    #[cfg(test)]
    ignore_naks_of: Option<([u64; 2], HeldRanges)>,
    /// Test only: the first 64 NAKs answered while `ignore_naks_of` was
    /// set, for a failure message.
    #[cfg(test)]
    nak_log: Vec<String>,
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
pub(super) fn roles<T: StreamTerms>(
    config: &AgentConfig,
) -> Result<(SenderRole<T>, ReceiverRole<T>), AgentError> {
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
    let registrations = crate::sessions::register::Registrations::new(config.registration, 0)
        .map_err(AgentError::Registration)?;
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
    let register_rates = EndpointRates::new(config.rsp_setup_per_destination, config.subscriptions)
        .ok_or(AgentError::InvalidConfig("rsp_setup rate or table is zero"))?;
    let replies = RttReplies::new(&config.rtt)
        .map_err(|_| AgentError::InvalidConfig("invalid RTT configuration"))?;
    let routes = (0..config.max_endpoints)
        .map(|_| RouteSlot {
            endpoint: None,
            // One ANNOUNCE waiting per publication and destination at most.
            routes: ControlRoutes::with_waiting(
                config.control_routes,
                config.publications.saturating_mul(config.max_destinations),
            ),
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
            publication_auth: Vec::new(),
            aborts: Vec::with_capacity(config.publications),
            #[cfg(test)]
            last_abort_ack: None,
            #[cfg(test)]
            last_abort: None,
            path_heartbeat_interval: config.path_heartbeat_interval,
            sender_heartbeat_interval: config.sender_heartbeat_interval,
            setup_interval: config.setup_interval,
            // Per publication: its routes, or its destinations and those
            // retired since the last drain, which a removal closes too; and
            // as many again for the entries in flight that wait here when
            // `closing_again` is full (#838), so a removal always finds
            // room.
            closing: Vec::with_capacity(
                config
                    .publications
                    .checked_mul(
                        karyos_io::lanes::routes::MAX_ROUTES
                            .saturating_add(config.max_destinations.saturating_mul(2)),
                    )
                    .and_then(|share| share.checked_mul(2))
                    .ok_or(AgentError::InvalidConfig("publications too large"))?,
            ),
            #[cfg(test)]
            close_in_flight: 0,
            closing_again: Vec::with_capacity(
                config
                    .publications
                    .checked_mul(
                        karyos_io::lanes::routes::MAX_ROUTES
                            .saturating_add(config.max_destinations.saturating_mul(2)),
                    )
                    .ok_or(AgentError::InvalidConfig("publications too large"))?,
            ),
            close_report: karyos_io::backend::TxReport::new(),
            // One record per held endpoint: another epoch's is dropped.
            close_failures: Vec::with_capacity(config.max_endpoints),

            path_policy: config.path_policy,
            bindings: Vec::with_capacity(config.receiver_bindings),
            max_bindings: config.receiver_bindings,
            next_binding: 0,
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
            registrations,
            trace: super::net_trace::SenderTrace::default(),
            #[cfg(test)]
            ignore_naks: false,
            #[cfg(test)]
            ignore_naks_of: None,
            #[cfg(test)]
            nak_log: Vec::new(),
        },
        ReceiverRole {
            #[cfg(test)]
            drop_data: Vec::new(),
            #[cfg(test)]
            data_seen: 0,
            #[cfg(test)]
            dropped: None,
            #[cfg(test)]
            drop_once_at: Vec::new(),
            #[cfg(test)]
            repeat_data_from: None,
            #[cfg(test)]
            drop_tail: None,
            #[cfg(test)]
            posted_naks: Vec::new(),
            #[cfg(test)]
            posted_challenges: Vec::new(),
            #[cfg(test)]
            debug_trace: Vec::new(),
            #[cfg(test)]
            rx_offsets: Vec::new(),
            #[cfg(test)]
            dropped_notes: 0,
            #[cfg(test)]
            founding_naks: 0,
            #[cfg(test)]
            founding_sms: 0,
            rx_epochs: Vec::with_capacity(config.max_endpoints),
            max_endpoints: config.max_endpoints,
            cycle: 0,
            solicit_due: Vec::with_capacity(config.sessions.max_pending_challenges),
            sessions,
            nonces: OsNonces,
            to_sender,
            budget: Budget::new(datagrams, bytes, ops),
            subscriptions: Vec::with_capacity(config.subscriptions),
            groups: Vec::with_capacity(config.subscriptions),
            group_budget: config.group_nak_budget,
            group_start: 0,
            identities: Vec::with_capacity(config.subscriptions),
            solicit_from: Vec::with_capacity(config.subscriptions),
            skews: Vec::with_capacity(config.subscriptions),
            registering: Vec::with_capacity(config.subscriptions),
            register_rates,
            setup_interval: config.setup_interval,
            conflated: Vec::with_capacity(config.subscriptions),
            barrier_ack_timeout: config.barrier_ack_timeout,
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
            path_config: receiver_path_config(config),
            path_intake: None,
            auth_unattributed: AuthRejections::default(),
            published_auth: Vec::new(),
            subscription_auth: Vec::new(),
            verified_setup: false,
            signed: None,
            remote_guards: Vec::new(),
            guard_marks: None,
            guard_authority: None,
            rtt: config.rtt,
            multicast: config.multicast,
            unicast_retry_slack: config.unicast_retry_slack,
            delays,
            clock: karyos_sys::host_clock::host_monotonic_ns,
            counters: ReceiverCounters::default(),
            // A journal per lane of each image, at most four lanes each;
            // a table too large for the address space traces nothing.
            trace: super::net_trace::ReceiverTrace::new(
                config.sessions.max_images.checked_mul(4).unwrap_or(0),
            ),
        },
    ))
}

/// Reserves an image's whole command chain (S1): `CreateImage`, the
/// receiver's `RetireImage` and the conductor's units. `None`, with
/// nothing held, when a ring has no credit.
fn reserve_chain<T: StreamTerms>(
    sessions: &SessionEnd<T>,
) -> Option<(Reservation, Reservation, ImageChain)> {
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

/// What [`SenderRole::make_room`] would do for one more binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Room {
    /// A free binding beyond those kept for required receiver ids.
    Free,
    /// None free: the unconfirmed binding at this index is evicted.
    Evict(usize),
    /// The free bindings are kept for required receiver ids that have not
    /// joined (karyos#941 item 2).
    Reserved,
    /// Full of confirmed bindings.
    Full,
}

/// Whether `binding` names `receiver_id`: the receiver block its REGISTER
/// named, the id its SMs bring, or the one it had before it was answered
/// again.
fn names(binding: &ReceiverBinding, receiver_id: u64) -> bool {
    binding
        .registered
        .is_some_and(|receiver| receiver.receiver_id == receiver_id)
        || binding.receiver_id == Some(receiver_id)
        || binding.former == Some(receiver_id)
}

/// When a dynamic subscription key at `index` is next due to REGISTER,
/// `interval` after `now` plus its stagger, `index mod REGISTER_STAGGER`
/// eighths of `interval` (karyos#941 item 1). Saturating: a clock past
/// `u64` (never) sends no more, which is the definition wanted.
fn next_register_due(now: u64, interval: u64, index: usize) -> u64 {
    let slot = u64::try_from(index).map_or(0, |index| index % REGISTER_STAGGER);
    let stagger = (interval / REGISTER_STAGGER).checked_mul(slot).unwrap_or(0);
    now.saturating_add(interval).saturating_add(stagger)
}

/// `interval` doubled, at most `setup_interval` doubled
/// [`REGISTER_BACKOFF_STEPS`] times (karyos#941 item 1).
fn backed_off(interval: u64, setup_interval: u64) -> u64 {
    let cap = setup_interval
        .checked_shl(REGISTER_BACKOFF_STEPS)
        .filter(|cap| cap >> REGISTER_BACKOFF_STEPS == setup_interval)
        .unwrap_or(u64::MAX);
    interval
        .checked_mul(2)
        .map_or(cap, |doubled| doubled.min(cap))
}

/// Whether an RSP_SETUP may answer `source` (network-control-schemas.md
/// §7.3): a unicast address with a nonzero port; never a multicast,
/// broadcast or unspecified address, an IPv4-mapped one included.
pub(crate) fn answerable(source: SocketAddr) -> bool {
    let source = normalized(source);
    let ip = source.ip();
    let broadcast = match ip {
        std::net::IpAddr::V4(v4) => v4.is_broadcast(),
        std::net::IpAddr::V6(_) => false,
    };
    source.port() != 0 && !ip.is_multicast() && !ip.is_unspecified() && !broadcast
}

impl<T: StreamTerms> ReceiverRole<T> {
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
        command: AgentCommand<O, T>,
    ) -> Option<(Reservation, AgentEvent<O, T>)> {
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
                conflated,
                solicit_from,
                register_at,
                path_skew,
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
                        // Likewise its conflated lane.
                        if let Some(lane) = conflated {
                            self.conflated.push((endpoint, stream_id, lane));
                        }
                        // And the endpoint its SOLICITs leave from.
                        if let Some(from) = solicit_from {
                            self.solicit_from.push((endpoint, stream_id, from));
                        }
                        // And its channel's skew window.
                        if let Some(skew) = path_skew {
                            self.skews.push((endpoint, stream_id, skew));
                        }
                        // And the address it registers at, due at once.
                        if let Some((control, status)) = register_at {
                            self.registering.push(Registering {
                                endpoint,
                                stream_id,
                                control,
                                due: 0,
                                interval: self.setup_interval,
                                status,
                            });
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
                    self.conflated
                        .retain(|(held, stream, _)| (*held, *stream) != (endpoint, stream_id));
                    self.solicit_from
                        .retain(|(held, stream, _)| (*held, *stream) != (endpoint, stream_id));
                    self.skews
                        .retain(|(held, stream, _)| (*held, *stream) != (endpoint, stream_id));
                    self.registering
                        .retain(|key| (key.endpoint, key.stream_id) != (endpoint, stream_id));
                    self.unsubscribed = true;
                }
                if let Some(index) = self
                    .groups
                    .iter()
                    .position(|(held, stream, ..)| (*held, *stream) == (endpoint, stream_id))
                {
                    let (.., control, _) = self.groups.swap_remove(index);
                    // A later path's group leaves its images with it
                    // (karyos#1064): its endpoint is released next.
                    for image in self
                        .images
                        .iter_mut()
                        .filter(|image| image.key.alias.stream_id == stream_id)
                    {
                        for slot in &mut image.path_groups {
                            if slot.is_some_and(|(held, _)| held == control) {
                                *slot = None;
                            }
                        }
                    }
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
            AgentCommand::RemovePublication { reply, .. }
            | AgentCommand::RemoveSenderSession { reply, .. }
            | AgentCommand::ChangeDestination { reply, .. } => Some((
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
            command => self.trace_command(command),
        }
    }

    /// The network trace commands (P2.12 step 3, PR 2; trace-network.md
    /// §4, §5): the hook, and one journal per lane of an installed image,
    /// whose start is the lane's next commit position when it arrives.
    fn trace_command<O: SocketOps>(
        &mut self,
        command: AgentCommand<O, T>,
    ) -> Option<(Reservation, AgentEvent<O, T>)> {
        let agent = AgentKind::Receiver;
        match command {
            AgentCommand::SetNetworkTrace { reply, hook } => {
                let (previous, closed) = self.trace.set_hook(hook);
                Some((
                    reply,
                    AgentEvent::NetworkTraceSet {
                        agent,
                        previous,
                        closed,
                    },
                ))
            }
            AgentCommand::OpenNetworkJournal { reply, journal, .. } => {
                let traced = self.images.iter().find_map(|image| {
                    let publication = publication_of(image);
                    (publication == journal.publication && journal.lane.get() < image.lane_count)
                        .then(|| {
                            image.owner.rebuild_position(journal.lane).map(|start| {
                                super::net_trace::TracedImageLane {
                                    slot: image.slot,
                                    lane: journal.lane,
                                    publication,
                                    number: journal.number,
                                    start,
                                    gaps: Box::default(),
                                }
                            })
                        })
                        .flatten()
                });
                let (publication, lane, number) =
                    (journal.publication, journal.lane, journal.number);
                let event = match traced {
                    Some(traced) => {
                        let start = traced.start;
                        match self.trace.open(traced, journal) {
                            Ok(()) => AgentEvent::NetworkJournalOpened {
                                agent,
                                publication,
                                lane,
                                number,
                                start,
                            },
                            Err(journal) => AgentEvent::NetworkJournalRefused { agent, journal },
                        }
                    }
                    None => AgentEvent::NetworkJournalRefused { agent, journal },
                };
                Some((reply, event))
            }
            AgentCommand::CloseNetworkJournal {
                reply,
                publication,
                lane,
                number,
            } => {
                let images = &self.images;
                let facts = self.trace.close(number, |traced| {
                    let owner = images
                        .iter()
                        .find(|image| image.slot == traced.slot)
                        .map(|image| &*image.owner);
                    journal_facts(traced, owner)
                });
                Some((
                    reply,
                    AgentEvent::NetworkJournalClosed {
                        agent,
                        publication,
                        lane,
                        number,
                        facts,
                    },
                ))
            }
            // No reply: its unit is released. An image retired meanwhile
            // drops the cells, which the allocator reuses.
            AgentCommand::AttachImageCells { slot, cells, .. } => {
                if let Some(image) = self.images.iter_mut().find(|image| image.slot == slot) {
                    image.cells = Some(cells);
                }
                None
            }
            AgentCommand::RelinkView {
                slot, lane, link, ..
            } => {
                let relinked = self
                    .images
                    .iter_mut()
                    .find(|image| image.slot == slot)
                    .and_then(|image| image.gate.as_mut())
                    .filter(|gate| gate.lane() == lane)
                    .is_some_and(|gate| gate.relink(link));
                if relinked {
                    self.count(|c| &mut c.views_relinked);
                } else {
                    self.count(|c| &mut c.relinks_refused);
                }
                None
            }
            _ => None,
        }
    }

    /// Hands its images' cells back into `cells`, at the close.
    pub(crate) fn take_stream_cells(&mut self, cells: &mut Vec<karyos_sys::counters::Counter>) {
        for image in &mut self.images {
            if let Some(mut taken) = image.cells.take() {
                cells.extend(taken.take());
            }
        }
    }

    /// Stores each image's changed loss counts into its CnC cells, at the
    /// end of a duty cycle (M2b).
    pub(crate) fn publish_stream_cells(&mut self) {
        for image in &mut self.images {
            if let Some(cells) = image.cells.as_mut() {
                let loss = image.loss.counters();
                cells.publish(&[loss.submitted, loss.detected, loss.repaired]);
            }
        }
    }

    /// The resolved prefix of `lane` of the image at `slot` (tests).
    #[cfg(test)]
    pub(super) fn rebuild_position(&self, slot: SlotRef, lane: Lane) -> Option<u64> {
        self.images
            .iter()
            .find(|image| image.slot == slot)?
            .owner
            .rebuild_position(lane)
    }

    /// Posts, through `post`, the closes of journals their image's
    /// retirement closed; a full ring keeps the rest for the next cycle.
    pub(super) fn post_retired_journals<O: SocketOps>(
        &mut self,
        mut post: impl FnMut(AgentEvent<O, T>) -> Option<AgentEvent<O, T>>,
    ) {
        self.trace.post_retired(|lane, facts| {
            let (publication, number) = (facts.publication, facts.number);
            let back = post(AgentEvent::NetworkJournalClosed {
                agent: AgentKind::Receiver,
                publication,
                lane,
                number,
                facts: Some(facts),
            });
            back.map_or(Ok(()), |event| {
                Err(match event {
                    AgentEvent::NetworkJournalClosed {
                        facts: Some(facts), ..
                    } => facts,
                    // Only the event posted above comes back.
                    _ => super::net_trace::JournalFacts {
                        publication,
                        number,
                        start: 0,
                        boundary: 0,
                        first_gap: None,
                        gaps: None,
                    },
                })
            })
        });
    }

    /// How often each reason made the receive sessions ignore a control
    /// (tests).
    #[cfg(test)]
    pub(crate) fn ignored_controls(&self) -> crate::sessions::receive::IgnoredCounts {
        self.sessions.ignored_counts()
    }

    /// The session table's counters, ignored controls and path counters
    /// (tests).
    #[cfg(test)]
    pub(crate) fn sessions_debug(&self) -> String {
        format!(
            "{:?} {:?} {:?} trace {:?} rx {:?}",
            self.sessions.counters(),
            self.sessions.ignored_counts(),
            self.sessions.paths().counters(),
            self.debug_trace,
            self.rx_offsets
        )
    }

    /// Tests: records `line`, the first 48 and then one in 64 of the rest.
    #[cfg(test)]
    fn note(&mut self, line: String) {
        self.dropped_notes = self.dropped_notes.wrapping_add(1);
        if self.debug_trace.len() < 48
            || self.dropped_notes.is_multiple_of(64) && self.debug_trace.len() < 160
        {
            self.debug_trace.push(line);
        }
    }

    /// This receiver's boot id (tests).
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "used by the Linux multicast tests (T9)")
    )]
    pub(crate) fn boot_id(&self) -> [u64; 2] {
        self.sessions.boot_id()
    }

    /// Refused envelopes no authenticated binding owns, by reason.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn unattributed_auth_rejections(&self) -> AuthRejections {
        self.auth_unattributed
    }

    /// The refusals of the authenticated image at `slot`, by reason;
    /// `None` for a trusted or unknown image.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn auth_rejections(&self, slot: SlotRef) -> Option<AuthRejections> {
        self.images
            .iter()
            .find(|image| image.slot == slot)
            .and_then(|image| image.auth.as_deref())
            .map(|auth| auth.rejections)
    }

    /// The session table's counters.
    #[must_use]
    pub fn session_counters(&self) -> crate::sessions::receive::SessionCounters {
        self.sessions.counters()
    }

    /// Whether `alias` is published on `endpoint` (tests).
    #[cfg(test)]
    pub(crate) fn is_published(&self, endpoint: EndpointId, alias: Alias) -> bool {
        self.published.contains(&(endpoint, alias))
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
        sessions: &SessionEnd<T>,
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

    /// Hands the receiver `bytes` as a unicast datagram from `source` on
    /// `endpoint` at `now`, as the backend would (tests).
    #[cfg(test)]
    pub(super) fn inject_datagram(
        &mut self,
        sessions: &SessionEnd<T>,
        endpoint: EndpointId,
        source: SocketAddr,
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
        intake.bytes_in(source, bytes);
    }

    /// Marks the local publication `alias` on `endpoint` authenticated
    /// (tests): its receivers' envelopes go to the sender undecoded and
    /// their bare controls are dropped.
    #[cfg(test)]
    pub(super) fn authenticate_published(&mut self, endpoint: EndpointId, alias: Alias) {
        self.published_auth.push((endpoint, alias));
    }

    /// A new duty cycle for the signed domains, and the followed guards'
    /// rounds that are due: a fresh nonce each, its STATUS_CHALLENGE sent
    /// bare to the authority's guard control address (design 4.2).
    fn guard_rounds(&mut self, now: u64) {
        use karyos_protocol::network::authenticated::AuthControl;

        if let Some(intake) = self.signed.as_deref_mut() {
            intake.new_cycle();
        }
        if let Some(authority) = self.guard_authority.as_deref_mut() {
            authority.new_cycle();
        }
        // A lapse closes the gates' word as a close does.
        self.publish_guard_words(now);
        let boot = self.sessions.boot_id();
        for at in 0..self.remote_guards.len() {
            let Some(followed) = self.remote_guards.get_mut(at) else {
                break;
            };
            if !followed.guard.round_due(now) {
                continue;
            }
            let receiver = Receiver {
                receiver_boot_id: boot,
                receiver_id: followed.receiver_id,
            };
            let Some(challenge) = followed.guard.challenge(receiver, now, &mut self.nonces) else {
                continue;
            };
            let (endpoint, destination) = (followed.endpoint, followed.authority);
            let mut bytes = [0u8; karyos_protocol::network::MAX_CONTROL_LENGTH];
            let raw = AuthControl::Challenge(challenge)
                .encode(&mut bytes)
                .ok()
                .and_then(|length| bytes.get(..length))
                .and_then(SealedBytes::copy);
            let Some(raw) = raw else {
                continue;
            };
            match self.to_sender.try_post(ControlItem::Raw {
                endpoint,
                destination,
                bytes: raw,
            }) {
                Ok(()) => self.count(|c| &mut c.guard_challenges),
                Err(_) => self.count(|c| &mut c.ring_full_raw),
            }
        }
    }

    /// Stores each followed guard's word for the sender gates that read
    /// it: open only while open and confirmed (Release, as a local close).
    fn publish_guard_words(&self, now: u64) {
        for followed in &self.remote_guards {
            if let Some(word) = followed
                .mirror
                .as_deref()
                .and_then(|words| words.words().first())
            {
                let next = followed.guard.word(now);
                if word.load(karyos_sys::sync::Ordering::Acquire) != next {
                    word.store(next, karyos_sys::sync::Ordering::Release);
                }
            }
        }
    }

    /// Trusts `authorities` for the signed domains (tests).
    #[cfg(test)]
    pub(super) fn trust_authorities(
        &mut self,
        authorities: Vec<signed_control::Authority>,
        now: u64,
    ) {
        self.signed = Some(Box::new(SignedIntake::new(authorities, now)));
    }

    /// Follows `guard` as `receiver_id`, its challenges going bare on
    /// `endpoint` to the authority's guard control address `authority`,
    /// its marks in `marks` (tests).
    #[cfg(test)]
    pub(super) fn follow_guard(
        &mut self,
        guard: crate::remote_guard::RemoteGuard,
        receiver_id: u64,
        endpoint: EndpointId,
        authority: SocketAddr,
        marks: Box<dyn MarkStore + Send>,
        mirror: Option<Arc<karyos_client::HeapWords>>,
    ) {
        self.remote_guards.push(FollowedGuard {
            guard,
            receiver_id,
            endpoint,
            authority,
            mirror,
        });
        self.guard_marks = Some(marks);
        self.publish_guard_words(0);
    }

    /// Makes this driver the guard authority `authority` (tests); `None`
    /// stops it answering.
    #[cfg(test)]
    pub(super) fn set_guard_authority(
        &mut self,
        authority: Option<crate::guard_authority::GuardAuthority>,
    ) {
        self.guard_authority = authority.map(Box::new);
    }

    /// The phase of the followed guard `guard_id` at `now` (tests).
    #[cfg(test)]
    pub(super) fn guard_phase(
        &self,
        guard_id: u64,
        now: u64,
    ) -> Option<crate::remote_guard::Phase> {
        self.remote_guards
            .iter()
            .find(|followed| followed.guard.guard_id() == guard_id)
            .map(|followed| followed.guard.phase(now))
    }

    /// Makes a subscription authenticated with `auth` (tests).
    #[cfg(test)]
    pub(super) fn authenticate_subscription(&mut self, auth: SubscriptionAuth) {
        self.subscription_auth.push(auth);
    }

    /// Hands `item` to the sender agent's ring (tests).
    #[cfg(test)]
    pub(super) fn post_to_sender(&mut self, item: ControlItem) {
        assert!(self.to_sender.try_post(item).is_ok(), "the ring has room");
    }

    /// Makes the image at `slot` authenticated (tests): its sender's
    /// datagrams verify under the channel key `channel` and its controls
    /// are sealed under the pairwise key `pairwise`, both for this
    /// establishment, read at the wall clock `wall`. Returns the sender's
    /// and the receiver's parties. Nothing else makes an image
    /// authenticated yet.
    #[cfg(test)]
    pub(super) fn authenticate_image(
        &mut self,
        slot: SlotRef,
        channel: &crate::wire_keys::KeyFile,
        pairwise: &crate::wire_keys::KeyFile,
        wall: fn() -> i64,
    ) -> Result<(crate::wire_auth::Party, crate::wire_auth::Party), crate::wire_auth::KeyError>
    {
        use crate::wire_auth::{KeyError, Party};

        let receiver_boot_id = self.sessions.boot_id();
        let image = self
            .images
            .iter_mut()
            .find(|image| image.slot == slot)
            .ok_or(KeyError::NoKey)?;
        let sender = Party::Sender {
            identity: image.identity,
            lane_count: image.lane_count,
            receiver_boot_id,
            nonce: image.nonce,
        };
        let receiver = Party::Receiver {
            identity: image.identity,
            receiver_boot_id,
            receiver_id: image.receiver_id,
        };
        let mut auth = ImageAuth::new([channel], pairwise, sender, receiver, image.key.alias)?;
        auth.set_wall(wall);
        image.auth = Some(Box::new(auth));
        Ok((sender, receiver))
    }

    /// Hands the receiver `bytes` as a DATA datagram from `source` on
    /// `endpoint` at `now` (tests).
    #[cfg(test)]
    pub(super) fn inject_data(
        &mut self,
        sessions: &SessionEnd<T>,
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
        sessions: &SessionEnd<T>,
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

    /// Loses every arrival of the DATA datagram at each term offset of
    /// `at`, in the first term, until called again (`&[]` releases)
    /// (tests).
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn drop_data_at(&mut self, at: &[u32]) {
        self.drop_once_at = at.to_vec();
    }

    /// Records into `held` the position and length of each DATA datagram
    /// `drop_data` loses from now on (tests).
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn share_dropped(&mut self, held: HeldRanges) {
        self.dropped = Some(held);
    }

    /// Loses every DATA datagram with a payload at or past `term_offset`
    /// of the first term: from every source, or from the first such
    /// datagram's source only when `one_source` (tests).
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "its tests need two real paths, on Linux")
    )]
    pub(super) fn drop_tail(&mut self, term_offset: u32, one_source: bool) {
        self.drop_tail = Some(DropTail {
            offset: term_offset,
            one_source,
            chosen: None,
            end: term_offset,
            term: None,
            done: [None; 4],
        });
    }

    /// The sources whose idle heartbeat past the lost tail arrived (tests).
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "its tests need two real paths, on Linux")
    )]
    pub(super) fn tail_heartbeat_sources(&self) -> usize {
        self.drop_tail
            .map_or(0, |tail| tail.done.iter().flatten().count())
    }

    /// Whether the path queues are allocated (tests).
    #[cfg(test)]
    pub(super) fn has_path_queues(&self) -> bool {
        self.path_intake.is_some()
    }

    /// Delivers every DATA datagram twice from the `from`th since
    /// [`Self::drop_data`] was set (tests).
    #[cfg(test)]
    pub(super) fn repeat_data_from(&mut self, from: u64) {
        self.repeat_data_from = Some(from);
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

    /// Faults route `path` of the image at `slot`, as two uncertain NAK
    /// copies on it would (tests).
    #[cfg(test)]
    pub(super) fn fault_route(&mut self, slot: SlotRef, path: usize) {
        let image = self
            .images
            .iter_mut()
            .find(|image| image.slot == slot)
            .unwrap();
        image.routes[path].uncertain = true;
        image.routes[path].faulted = true;
    }

    /// Whether route `path` of the image at `slot` is faulted (tests).
    #[cfg(test)]
    pub(super) fn route_faulted(&self, slot: SlotRef, path: usize) -> bool {
        self.images
            .iter()
            .find(|image| image.slot == slot)
            .is_some_and(|image| image.routes[path].faulted)
    }

    /// SMs handed over on an image's founding path (tests).
    #[cfg(test)]
    pub(super) fn founding_sms(&self) -> u64 {
        self.founding_sms
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
        sessions: &SessionEnd<T>,
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
        sessions: &SessionEnd<T>,
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
                            let freshness = match self.install(installed, owner, chain, now) {
                                Ok(freshness) => freshness,
                                Err(retire) => {
                                    refused = Some((installed, retire));
                                    None
                                }
                            };
                            SessionEvent::ImageInstalled {
                                slot,
                                installed,
                                freshness,
                            }
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
                        let _ = sessions.events.post(
                            unit,
                            SessionEvent::RetireImage {
                                slot: installed,
                                complete: false,
                                cells: None,
                            },
                        );
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
        owner: Box<ReceiveOwner<T>>,
        chain: Option<Chain>,
        now: u64,
    ) -> Result<Option<(Lane, karyos_sys::freshness::FreshnessLink)>, Option<Reservation>> {
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
        // Its channel's `path-skew`, else the receiver's (karyos#1056).
        let skew = self
            .skews
            .iter()
            .find(|(held, stream, _)| (*held, *stream) == (key.endpoint, key.alias.stream_id))
            .map_or(self.path_config.path_skew_window, |(.., skew)| *skew);
        let skewed = PathConfig {
            path_skew_window: skew,
            ..self.path_config
        };
        // A multicast image times its NAKs by cycle (RC-2).
        let loss = ImageLoss::new(
            LossConfig {
                skew_window_ns: skew,
                unicast_retry_slack_ns: self.unicast_retry_slack,
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
        let skip_config = image_skip_config(&skewed, reliable);
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
        // A conflated lane of its key: that lane's seals go through the
        // view's barrier mailbox, whose link the conductor gets with the
        // `ImageInstalled` (conflated-network-images.md (b)).
        let link = self
            .conflated
            .iter()
            .find(|(held, stream, _)| (*held, *stream) == (key.endpoint, key.alias.stream_id))
            .map(|(.., lane)| *lane);
        let in_range = link.filter(|lane| lane.get() < chain.lane_count);
        if link.is_some() && in_range.is_none() {
            self.count(|c| &mut c.conflated_lane_out_of_range);
        }
        let link = in_range.map(|lane| (lane, karyos_sys::freshness::FreshnessLink::new()));
        let gate = link.as_ref().map(|(lane, link)| {
            Box::new(super::conflated_gate::ConflatedGate::new(
                *lane,
                link.clone(),
                self.barrier_ack_timeout,
            ))
        });
        // An authenticated subscription's image derives its keys for this
        // establishment, or is not installed (fail closed).
        let auth = match self
            .subscription_auth
            .iter()
            .find(|auth| auth.endpoint == key.endpoint && auth.stream_id == key.alias.stream_id)
        {
            None => None,
            Some(subscription) => {
                let boot = self.sessions.boot_id();
                let sender = crate::wire_auth::Party::Sender {
                    identity,
                    lane_count: chain.lane_count,
                    receiver_boot_id: boot,
                    nonce: chain.nonce,
                };
                let receiver = crate::wire_auth::Party::Receiver {
                    identity,
                    receiver_boot_id: boot,
                    receiver_id: named,
                };
                match subscription.image(key.alias, sender, receiver) {
                    Ok(auth) => Some(Box::new(auth)),
                    Err(_) => {
                        self.count(|c| &mut c.auth_install_refused);
                        return Err(Some(chain.retire));
                    }
                }
            }
        };
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
            terminal: [None; 4],
            dropped_past_terminal: [false; 4],
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
            cells: None,
            gate,
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
            uncertain_at: [None; 4],
            founding_gone: false,
            control_group,
            path_groups: vec![None; paths],
            receiver_id: named,
            group_tag,
            nonce: chain.nonce,
            auth,
            aborted: None,
        });
        Ok(link)
    }

    /// The installed images' timers at `now`: retirement at the liveness
    /// timeout (S1 retirement), then the SMs due. Returns the work done.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    fn image_timers(&mut self, sessions: &SessionEnd<T>, now: u64) -> Result<u32, AgentError> {
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
                self.retire(sessions, image, false, now);
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
                    CloseReason::Aborted => |c| &mut c.images_closed_aborted,
                };
                self.count(field);
                let image = self.images.swap_remove(index);
                self.retire(sessions, image, false, now);
                work = work.checked_add(1).ok_or(overflow.clone())?;
                continue;
            }
            // Every lane reached its EOS bound through a complete prefix:
            // the image closes cleanly (network-sessions.md, Liveness and
            // terminal transitions), unless a lane dropped a frame past its
            // bound. Its local loans stay until released.
            if self.images.get(index).is_some_and(terminal_reached) {
                let clean = !self.images.get(index).is_some_and(dropped_past_terminal);
                if clean {
                    self.count(|c| &mut c.images_closed_eos);
                } else {
                    self.count(|c| &mut c.images_closed_eos_dropped);
                }
                let image = self.images.swap_remove(index);
                self.retire(sessions, image, clean, now);
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
    pub(super) fn request_resets(
        &mut self,
        mut post: impl FnMut(EndpointId, Option<karyos_io::backend::BackendEpoch>) -> bool,
    ) {
        let cycle = self.cycle;
        let Self {
            images,
            counters,
            sessions,
            ..
        } = self;
        let due_at = |requested: Option<u64>| {
            requested.is_none_or(|at| {
                cycle
                    .checked_sub(at)
                    .is_none_or(|age| age >= super::data::RESET_REQUEST_CYCLES)
            })
        };
        for image in images.iter_mut() {
            // A faulted later route asks for its own endpoint's reset,
            // which resolves it (RC-6 per route; #310 review).
            for path in 0..image.routes.len() {
                let Some(key) = sessions.paths().key(image.slot, path) else {
                    continue;
                };
                let Some(route) = image.routes.get_mut(path) else {
                    continue;
                };
                if key == image.key || !route.faulted || !due_at(route.reset_requested) {
                    continue;
                }
                if post(key.endpoint, None) {
                    route.reset_requested = Some(cycle);
                    tally(counters, |c| &mut c.reset_requests);
                } else {
                    tally(counters, |c| &mut c.reset_requests_full);
                }
            }
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
            if post(image.key.endpoint, None) {
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
            trace,
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
        // RC-6 per route: with a later route healthy, a fault of the
        // founding route silences only the founding copy.
        let healthy = (0..image.routes.len()).any(|path| {
            sessions
                .paths()
                .key(image.slot, path)
                .is_some_and(|key| key != image.key)
                && image.routes.get(path).is_some_and(|route| !route.faulted)
        });
        image.loss.set_other_route_healthy(healthy);
        let slot = image.slot;
        let mut sent = 0u32;
        let lanes = usize::from(image.lane_count);
        for at in 0..lanes {
            let Some(lane) = u8::try_from(at).ok().and_then(|at| Lane::try_new(at).ok()) else {
                continue;
            };
            let retries = image.loss.counters().retries;
            settle_founding(image, counters, at);
            // The later paths' copies (RP-7): the first submitted anchors
            // the NAK; uncertainty and route faults count per path route.
            settle_copies(image, counters, at);
            // Every copy of the round reported and none submitted: the
            // earliest uncertain one anchors it, counted as submitted at its
            // start (RC-6; #310 review).
            anchor_uncertain(image, at);
            if image.loss.counters().retries > retries {
                tally(counters, |c| &mut c.nak_retries);
            }
            if !image.reliable {
                continue;
            }
            let first = match image.owner.first_hole(lane) {
                Ok(hole) => hole.map(|(start, length)| Hole { start, length }),
                Err(_) => {
                    tally(counters, |c| &mut c.hole_query_errors);
                    None
                }
            };
            // A covered hole ends any tail wait: a later tail waits its RTT
            // afresh.
            if first.is_some()
                && let Some(since) = image.tail_since.get_mut(at)
            {
                *since = None;
            }
            let hole = first.or_else(|| tail_hole(image, lane, at, now, counters));
            if let Observation::Unrecoverable {
                hole,
                lowest_retained,
                ..
            } = image.loss.observe(lane, hole, now)
            {
                unrecoverable(image, counters, trace, lane, hole, lowest_retained, now);
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
            // The founding path's subscription gone (P2-3), or its route
            // faulted while a later one is healthy (#310 review): the NAK
            // goes on the later paths only, and their first copy submitted
            // anchors it.
            if image.founding_gone || image.loss.is_faulted() {
                if let Some(anchor) = image.anchored.get_mut(at) {
                    *anchor = None;
                }
                if let Some(candidate) = image.uncertain_at.get_mut(at) {
                    *candidate = None;
                }
                let posted = post_copies(
                    image,
                    |path| sessions.paths().key(slot, path),
                    to_sender,
                    counters,
                    at,
                    nak,
                );
                // Counted only when a copy went: none posted leaves the NAK
                // due (#312 review).
                if posted > 0 {
                    #[cfg(test)]
                    posted_naks.push(nak);
                    tally(counters, |c| &mut c.naks);
                    sent = sent
                        .checked_add(1)
                        .ok_or(AgentError::CountOverflow(AgentKind::Receiver))?;
                }
                continue;
            }
            let item = ControlItem::Outgoing {
                endpoint: image.key.endpoint,
                destination: image.key.source,
                control: Control::Nak(nak),
                guard: Some(ItemGuard::Report(ReportGuard::take(&report.slot))),
                seal: image.auth.as_deref().map(ImageAuth::sealer),
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
                    if let Some(candidate) = image.uncertain_at.get_mut(at) {
                        *candidate = None;
                    }
                    let _ = post_copies(
                        image,
                        |path| sessions.paths().key(slot, path),
                        to_sender,
                        counters,
                        at,
                        nak,
                    );
                    sent = sent
                        .checked_add(1)
                        .ok_or(AgentError::CountOverflow(AgentKind::Receiver))?;
                    // RC-7: on a trusted channel, one copy to the control
                    // group, after the unicast copy and with no report: it
                    // is never retried and raises no route fault. A full
                    // ring skips it, counted.
                    // Each later path's own group gets one too, once per
                    // distinct group (karyos#1064).
                    let founding = image.control_group;
                    for (index, group) in founding
                        .iter()
                        .chain(image.path_groups.iter().flatten())
                        .enumerate()
                    {
                        let (control, group) = *group;
                        let earlier = founding
                            .iter()
                            .chain(image.path_groups.iter().flatten())
                            .take(index)
                            .any(|(_, seen)| *seen == group);
                        if earlier {
                            continue;
                        }
                        // An authenticated image sends no group copy: its
                        // NAKs go sealed to the publisher only (unicast,
                        // ADR-0086 open point 6).
                        if image.auth.is_some() {
                            tally(counters, |c| &mut c.group_nak_copies_skipped);
                            continue;
                        }
                        let copy = ControlItem::Outgoing {
                            endpoint: control,
                            destination: group,
                            control: Control::Nak(nak),
                            guard: None,
                            seal: None,
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
            // An unreliable tail no frame revealed is sealed at its
            // deadline (SPEC §6, G1), up to the clamped mark.
            if !image.reliable {
                for (at, lane) in (0..image.lane_count)
                    .filter_map(|at| Some((usize::from(at), Lane::try_new(at).ok()?)))
                {
                    if let Some(mark) = heartbeat_mark(image, lane, at) {
                        image.skip.revealed(lane, mark);
                    }
                }
            }
            // Each committed seal reaches the lane's trace journal, if any
            // (§5).
            let slot = image.slot;
            let sealed = |lane, position, extent| trace.sealed(slot, lane, position, extent);
            let duty = match image.gate.as_deref_mut() {
                Some(gate) => image
                    .skip
                    .duty_observed(&mut image.owner, now, gate, sealed),
                None => image.skip.duty_observed(
                    &mut image.owner,
                    now,
                    &mut karyos_sys::log_buffer::Ungated,
                    sealed,
                ),
            };
            tally_gate(
                counters,
                image,
                duty.as_ref().map_or(0, |report| report.gated),
            );
            match duty {
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
                seal: image.auth.as_deref().map(ImageAuth::sealer),
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
    /// `RetireImage` is posted into its reserved unit, `complete` when
    /// every lane reached its EOS bound through a complete prefix.
    fn retire(&mut self, sessions: &SessionEnd<T>, image: Installed<T>, complete: bool, now: u64) {
        let Installed {
            slot,
            owner,
            retire,
            cells,
            ..
        } = image;
        // Its lanes' journals close now, with their facts, for the
        // conductor (trace-network.md §4: they close with the image).
        let counters = &mut self.counters;
        self.trace.retire(
            slot,
            |traced| journal_facts(traced, Some(&*owner)),
            || tally(counters, |c| &mut c.net_journals_retired_dropped),
        );
        let _ = self.sessions.retire(slot, now);
        drop(owner);
        self.count(|c| &mut c.images_retired);
        match retire {
            // The conductor gone: the driver is stopping.
            Some(unit) => {
                // Its cells go back with it, for the conductor to free.
                let _ = sessions.events.post(
                    unit,
                    SessionEvent::RetireImage {
                        slot,
                        complete,
                        cells,
                    },
                );
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
                seal: image.auth.as_deref().map(ImageAuth::sealer),
            };
            // The sender gone: the driver is stopping. The SM is then
            // recorded as sent all the same: nothing will send another.
            let _ = self.to_sender.post(slot, item);
            #[cfg(test)]
            {
                self.founding_sms += 1;
            }
        }
        // RP-7: a copy on every other bound path, so a path that lost its
        // return direction does not cost the membership. A copy has no
        // slot of its own: one the ring cannot take is skipped and
        // counted, never deferred.
        let Some(image) = self.images.get(index) else {
            return;
        };
        let (slot_ref, founding) = (image.slot, image.key);
        let seal = image.auth.as_deref().map(ImageAuth::sealer);
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
                seal: seal.clone(),
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

    /// Retired images whose `StorageReclaimed` this receiver handled, still
    /// in quarantine (tests).
    #[cfg(test)]
    pub(crate) fn reclaimed_tombstones(&self) -> usize {
        self.sessions.reclaimed_tombstones()
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
        sessions: &SessionEnd<T>,
        now: u64,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Receiver);
        self.guard_rounds(now);
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
                // A path bound again starts with a clean route (#310 review).
                if let Some(route) = image.routes.get_mut(path) {
                    *route = CopyRoute::default();
                }
            }
        });
        self.cycle = self.cycle.checked_add(1).ok_or(overflow.clone())?;
        work = work
            .checked_add(self.retry_solicits(sessions, now))
            .ok_or(overflow.clone())?;
        work = work
            .checked_add(self.send_registers(sessions, now))
            .ok_or(overflow.clone())?;
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
            .checked_add(self.drain_path_queues(sessions))
            .ok_or(overflow.clone())?;
        work = work
            .checked_add(self.poll_control_groups(halves, now)?)
            .ok_or(overflow)?;
        Ok(work)
    }

    /// Serves the path queues round robin, after every endpoint's poll: at
    /// most a poll budget's datagrams per queue, each delivered at its poll
    /// time. What is left waits for the next cycle. Returns the datagrams
    /// delivered.
    fn drain_path_queues(&mut self, sessions: &SessionEnd<T>) -> u32 {
        if self.path_intake.is_none() {
            return 0;
        }
        // A poll budget per queue; past `u32` (never: at most 16 paths of a
        // `u32` budget is checked), one poll budget.
        let per_queue = self.budget.datagrams();
        let limit = u32::from(self.path_config.max_paths)
            .checked_mul(per_queue)
            .unwrap_or(per_queue);
        let mut served = 0u32;
        // The slab is out while its datagrams are delivered: delivery
        // queues nothing.
        let slab = self
            .path_intake
            .as_deref_mut()
            .map(path_intake::PathIntake::take_slab)
            .unwrap_or_default();
        while served < limit {
            let Some((endpoint, entry)) = self
                .path_intake
                .as_deref_mut()
                .and_then(path_intake::PathIntake::pop)
            else {
                break;
            };
            let mut intake = Intake {
                endpoint,
                now: entry.now,
                role: self,
                sessions,
                work: 0,
            };
            intake.data(
                entry.source,
                entry.alias,
                path_intake::PathIntake::bytes(&entry, &slab),
            );
            if let Some(queues) = self.path_intake.as_deref_mut() {
                queues.release(entry);
            }
            let Some(next) = served.checked_add(1) else {
                break;
            };
            served = next;
        }
        if let Some(queues) = self.path_intake.as_deref_mut() {
            queues.put_slab(slab);
            queues.release_idle();
        }
        served
    }

    /// Retries the solicit entries whose ANSWER has not come
    /// (network-control-schemas.md §6.3, plan 164): each with its entry's
    /// nonce, through the RSP_SETUP limits of §7.4 like a first SOLICIT. A
    /// retry they refuse is not an attempt and waits for the next step.
    /// Returns the retries sent. Nothing allocates.
    fn retry_solicits(&mut self, sessions: &SessionEnd<T>, now: u64) -> u32 {
        let mut due = std::mem::take(&mut self.solicit_due);
        due.clear();
        self.sessions.due_solicits(now, &mut due);
        let mut sent = 0u32;
        for key in due.drain(..) {
            let Some(solicit) = self.sessions.retry_solicit(&key) else {
                continue;
            };
            let mut intake = Intake {
                endpoint: key.endpoint,
                now,
                role: self,
                sessions,
                work: 0,
            };
            let from = intake.solicit_endpoint(&key);
            if intake.challenge_from(from, key.source, Control::Solicit(solicit)) {
                self.sessions.solicit_retried(&key, now);
                sent = sent.saturating_add(1);
            } else {
                self.sessions.solicit_refused(&key, now);
            }
        }
        self.solicit_due = due;
        sent
    }

    /// Sends REGISTER for each `control-mode=dynamic` subscription key
    /// that is due and has no image of its stream from its `control`
    /// address (design 3.2: repeated until bound, then stopped; again once
    /// that image is gone). Each goes to the validated `control` address
    /// from the key's endpoint under the REGISTERs' own bucket per
    /// `control` address, never the RSP_SETUP limits its CHALLENGEs draw
    /// on, so REGISTERs cannot starve the CHALLENGE that answers its
    /// publisher's ANNOUNCE (karyos#941 item 1). A key's interval starts at
    /// `setup_interval` and doubles after each REGISTER, sent or not, up to
    /// [`REGISTER_BACKOFF_STEPS`] doublings; an accepted ANSWER from
    /// `control` or the loss of its image starts it over, an ANNOUNCE does
    /// not (karyos#947). Keys are spread within an
    /// interval ([`REGISTER_STAGGER`]). The receiver block is this boot's,
    /// with the key's configured `receiver_id`: a receiver id is configured
    /// and stable across restarts (design 2.3; multicast-flow-control.md
    /// M1), so a key with none sends nothing and counts each due REGISTER
    /// unsent. Each key's registration state follows (karyos#941 item 3).
    /// Returns the REGISTERs sent. Nothing allocates.
    fn send_registers(&mut self, sessions: &SessionEnd<T>, now: u64) -> u32 {
        use crate::sessions::register::RegistrationState;

        let mut sent = 0u32;
        for index in 0..self.registering.len() {
            let Some(key) = self.registering.get(index) else {
                break;
            };
            let (endpoint, stream_id, control, due) =
                (key.endpoint, key.stream_id, key.control, key.due);
            let bound = self.images.iter().any(|image| {
                image.key.endpoint == endpoint
                    && normalized(image.key.source) == normalized(control)
                    && image.key.alias.stream_id == stream_id
            });
            if bound {
                if let Some(key) = self.registering.get_mut(index) {
                    key.status.set(RegistrationState::Bound);
                    // Once the image goes, the first REGISTER is due at
                    // once and the backoff starts over.
                    key.due = now;
                    key.interval = self.setup_interval;
                }
                continue;
            }
            if let Some(key) = self.registering.get(index)
                && key.status.get() == RegistrationState::Bound
            {
                key.status.set(RegistrationState::Registering);
            }
            if now < due {
                continue;
            }
            let receiver_id = self
                .identities
                .iter()
                .find(|(held, stream, _)| (*held, *stream) == (endpoint, stream_id))
                .map(|(.., identity)| identity.receiver_id.get());
            let went = match receiver_id {
                Some(receiver_id) => {
                    let register = Control::Register(karyos_protocol::network::RspRegister {
                        stream_id,
                        receiver: Receiver {
                            receiver_boot_id: self.sessions.boot_id(),
                            receiver_id,
                        },
                    });
                    let mut intake = Intake {
                        endpoint,
                        now,
                        role: self,
                        sessions,
                        work: 0,
                    };
                    intake.register_to(control, register)
                }
                None => false,
            };
            if went {
                self.count(|c| &mut c.registers_sent);
                sent = sent.saturating_add(1);
            } else {
                self.count(|c| &mut c.registers_unsent);
            }
            let setup_interval = self.setup_interval;
            if let Some(key) = self.registering.get_mut(index) {
                key.due = next_register_due(now, key.interval, index);
                key.interval = backed_off(key.interval, setup_interval);
            }
        }
        sent
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
struct GroupIntake<'a, T: StreamTerms = HeapTerms> {
    endpoint: EndpointId,
    now: u64,
    role: &'a mut ReceiverRole<T>,
    /// Datagrams read; one poll reads at most its budget's.
    work: u32,
}

impl<T: StreamTerms> GroupIntake<'_, T> {
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
            (image
                .control_group
                .is_some_and(|(control, _)| control == endpoint)
                || image
                    .path_groups
                    .iter()
                    .flatten()
                    .any(|(control, _)| *control == endpoint))
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

impl<T: StreamTerms> RxHandler for GroupIntake<'_, T> {
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
struct Intake<'a, T: StreamTerms = HeapTerms> {
    endpoint: EndpointId,
    now: u64,
    role: &'a mut ReceiverRole<T>,
    sessions: &'a SessionEnd<T>,
    /// Datagrams read; one poll reads at most its budget's.
    work: u32,
}

impl<T: StreamTerms> Intake<'_, T> {
    /// Hands `item` to the sender; a full ring drops it, counted per kind
    /// so that a flood of one kind does not hide another.
    fn forward(&mut self, item: ControlItem) -> bool {
        let full: fn(&mut ReceiverCounters) -> &mut u64 = match item {
            ControlItem::Outgoing { .. } => |c| &mut c.ring_full_rsp_setup,
            ControlItem::Sealed { .. } => |c| &mut c.ring_full_sealed,
            ControlItem::Raw { .. } => |c| &mut c.ring_full_raw,
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
            ControlItem::Incoming {
                control: Control::Register(_),
                ..
            } => |c| &mut c.ring_full_register,
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
            if self.role.rx_offsets.len() < 96
                && let Some((_, at, _)) = drop_tail_frame(bytes)
            {
                self.role.rx_offsets.push(at);
            }
            let seen = self.role.data_seen;
            if let Some(next) = seen.checked_add(1) {
                self.role.data_seen = next;
            }
            if let Some((_, at, _)) = drop_tail_frame(bytes)
                && self.role.drop_once_at.contains(&at)
            {
                // Every arrival, repairs included, until the test releases
                // it: a repair B's NAK sends to the group must not fill it.
                if let (Some(dropped), Ok(length)) =
                    (self.role.dropped.as_ref(), u64::try_from(bytes.len()))
                    && let Ok(mut held) = dropped.lock()
                    && !held.iter().any(|&(start, _)| start == u64::from(at))
                {
                    held.push((u64::from(at), length));
                }
                return;
            }
            if self.role.drop_data.contains(&seen) {
                if let (Some(dropped), Some((_, at, _))) =
                    (self.role.dropped.as_ref(), drop_tail_frame(bytes))
                    && let (Ok(length), Ok(mut held)) = (u64::try_from(bytes.len()), dropped.lock())
                {
                    held.push((u64::from(at), length));
                }
                return;
            }
            // A DATA frame at or past the offset, decoded from its header:
            // word 0 (length, flags, type), then the term offset. A frame
            // with a payload is lost (from its source alone when
            // `one_source`); a header-only one at or past the end of what
            // was lost is the source's heartbeat showing the whole tail.
            // A negative length (padding) or another term is not the tail.
            if let Some(mut tail) = self.role.drop_tail
                && let Some((length, at, term)) = drop_tail_frame(bytes)
                && let Ok(length) = u32::try_from(length)
                && at >= tail.offset
                && tail.term.is_none_or(|lost| lost == term)
                && !tail.done.contains(&Some(source))
            {
                if length <= karyos_sys::frame::HEADER_LENGTH {
                    if tail.end > tail.offset
                        && at >= tail.end
                        && let Some(slot) = tail.done.iter_mut().find(|slot| slot.is_none())
                    {
                        *slot = Some(source);
                        self.role.drop_tail = Some(tail);
                    }
                } else if !tail.one_source || tail.chosen.is_none_or(|chosen| chosen == source) {
                    // The whole datagram is lost, every frame it carries.
                    let end = u32::try_from(bytes.len())
                        .ok()
                        .and_then(|len| at.checked_add(len));
                    tail.chosen = Some(source);
                    tail.term = Some(term);
                    tail.end = end.map_or(tail.end, |end| tail.end.max(end));
                    self.role.drop_tail = Some(tail);
                    return;
                }
            }
            if self.role.repeat_data_from.is_some_and(|from| seen >= from) {
                self.data_once(source, alias, bytes);
            }
        }
        self.data_once(source, alias, bytes);
    }

    /// Queues a DATA datagram of a multi-path image in its path's queue
    /// (redundant-paths.md section 5), stamped with this poll's time; one
    /// from an endpoint whose queue holds datagrams is queued too, so its
    /// path's order holds. Returns whether it was taken (queued, or dropped
    /// by a full queue); `false` delivers it now.
    fn enqueue(&mut self, source: SocketAddr, alias: Alias, bytes: &[u8]) -> bool {
        let key = BindingKey {
            endpoint: self.endpoint,
            source,
            alias,
        };
        let role = &mut *self.role;
        // A receiver with no queues (no later path ever bound) scans
        // nothing.
        if role.path_intake.is_none() {
            return false;
        }
        let paths = role.sessions.paths();
        let multi = paths
            .lookup(key)
            .is_some_and(|(slot, _)| paths.live(slot) > 1);
        let Some(intake) = role.path_intake.as_deref_mut() else {
            return false;
        };
        if !intake.takes(self.endpoint, multi) {
            return false;
        }
        match intake.push(self.endpoint, (source, alias, self.now), bytes) {
            path_intake::Queue::Queued => {
                role.count(|c| &mut c.path_queued);
                true
            }
            path_intake::Queue::Dropped => {
                role.count(|c| &mut c.path_queue_drops);
                true
            }
            path_intake::Queue::Bypass => {
                role.count(|c| &mut c.path_queue_bypassed);
                false
            }
        }
    }

    /// Delivers what this endpoint's path queue holds, in order, at each
    /// datagram's poll time.
    fn drain_own_queue(&mut self) {
        let endpoint = self.endpoint;
        let Some(intake) = self.role.path_intake.as_deref_mut() else {
            return;
        };
        if !intake.holds(endpoint) {
            return;
        }
        let slab = intake.take_slab();
        let now = self.now;
        while let Some(entry) = self
            .role
            .path_intake
            .as_deref_mut()
            .and_then(|intake| intake.pop_from(endpoint))
        {
            self.now = entry.now;
            self.data(
                entry.source,
                entry.alias,
                path_intake::PathIntake::bytes(&entry, &slab),
            );
            if let Some(intake) = self.role.path_intake.as_deref_mut() {
                intake.release(entry);
            }
        }
        self.now = now;
        if let Some(intake) = self.role.path_intake.as_deref_mut() {
            intake.put_slab(slab);
        }
    }

    /// One DATA datagram's intake ([`Self::data`]).
    fn data_once(&mut self, source: SocketAddr, alias: Alias, bytes: &[u8]) {
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
            #[cfg(test)]
            role.note(format!(
                "{} data unbound ep{} from {source}",
                self.now, key.endpoint.0
            ));
            self.solicit(key);
            return;
        };
        let Ok(datagram) = ValidatedDatagram::parse(bytes, &image.params) else {
            role.count(|c| &mut c.data_invalid);
            return;
        };
        // Per item: committed, dropped, refused, then fresh, stale,
        // stationary and rejected heartbeats, then frames past their lane's
        // terminal bound. A datagram holds at most an MTU of 32-byte
        // records: no overflow.
        let mut outcomes = [0u32; 8];
        let mut path_fresh = false;
        for item in datagram.items() {
            let (outcome, arrival) = match item {
                // Past the bound EOS named: dropped before the receive
                // owner, and neither image nor path evidence.
                Item::Frame(frame) if past_terminal(image, &frame) => {
                    if let Some(dropped) = image
                        .dropped_past_terminal
                        .get_mut(usize::from(frame.lane().get()))
                    {
                        *dropped = true;
                    }
                    (7, None)
                }
                Item::Frame(frame) => {
                    let delivered = delivered(image, &frame, path, self.now);
                    let received = image.owner.receive(&frame);
                    // An EOS flag on a message's last fragment names the
                    // lane's terminal bound, the frame's end, once the frame
                    // is in the image: committed now, or a copy of a
                    // committed frame. A dropped one names nothing.
                    if frame.image_word0().flags().eos()
                        && matches!(
                            received,
                            Ok(Received::Committed { .. } | Received::Duplicate)
                        )
                        && let Some(end) = frame_position(image, &frame)
                            .and_then(|position| position.checked_add(u64::from(frame.extent())))
                    {
                        let outcome = record_terminal(image, frame.lane(), end);
                        tally_terminal(&mut role.counters, outcome);
                    }
                    // The skip policy's far-window clock (GU-6): a run of
                    // `Ahead` arrivals starts it, a committed one stops it.
                    if let Some(position) = frame_position(image, &frame) {
                        image
                            .skip
                            .arrived(frame.lane(), &received, position, self.now);
                    }
                    // The commit point of a traced frame (NT-2): once per
                    // committed frame, naming the path of the copy.
                    if let Ok(Received::Committed { position, .. }) = received
                        && role.trace.any()
                        && let Some((traced_publication, traced_lane)) = role
                            .trace
                            .traced(image.slot, frame.lane())
                            .map(|traced| (traced.publication, traced.lane))
                    {
                        match super::net_trace::frame_extension(&frame) {
                            Some(Some(ext)) => {
                                let at = karyos_protocol::trace_hook::NetCommit {
                                    publication: traced_publication,
                                    lane: traced_lane,
                                    position,
                                    path: path
                                        .and_then(|(_, path)| u32::try_from(path).ok())
                                        .unwrap_or(0),
                                };
                                if let Some(hook) = role.trace.hook() {
                                    hook.on_receiver_commit(&ext, &at);
                                }
                            }
                            // Validation refuses an EXT that does not check, so this
                            // is defensive: counted, never traced.
                            Some(None) => {
                                tally(&mut role.counters, |c| &mut c.net_trace_ext_invalid)
                            }
                            None => {}
                        }
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
                Item::Heartbeat(heartbeat) => {
                    // An EOS heartbeat names its lane's terminal bound, its
                    // position, inside the receive window only. A refused
                    // one is rejected: no evidence, and no heartbeat mark.
                    let refused = heartbeat.flags().eos() && {
                        let lane = heartbeat.lane();
                        let outcome = match heartbeat_position(image, &heartbeat) {
                            Some(bound)
                                if image.owner.within_window(lane, bound).unwrap_or(false) =>
                            {
                                record_terminal(image, lane, bound)
                            }
                            _ => Terminal::Refused,
                        };
                        tally_terminal(&mut role.counters, outcome);
                        outcome == Terminal::Refused
                    };
                    if refused {
                        (6, None)
                    } else {
                        if let (Some(bound), Some(position)) = (
                            terminal_bound(image, heartbeat.lane()),
                            heartbeat_position(image, &heartbeat),
                        ) && position > bound
                        {
                            tally(&mut role.counters, |c| &mut c.heartbeats_past_terminal);
                        }
                        match classify_heartbeat(image, &heartbeat) {
                            HeartbeatClass::Fresh => (3, None),
                            HeartbeatClass::Stale => (4, None),
                            HeartbeatClass::Stationary => (5, None),
                            HeartbeatClass::Rejected => (6, None),
                        }
                    }
                }
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
        let fields: [fn(&mut ReceiverCounters) -> &mut u64; 8] = [
            |c| &mut c.data_committed,
            |c| &mut c.data_dropped,
            |c| &mut c.data_refused,
            |c| &mut c.heartbeats,
            |c| &mut c.heartbeats_stale,
            |c| &mut c.heartbeats_stationary,
            |c| &mut c.heartbeats_rejected,
            |c| &mut c.data_past_terminal,
        ];
        let fresh = outcomes.first().is_some_and(|committed| *committed > 0)
            || outcomes.get(3).is_some_and(|heartbeats| *heartbeats > 0);
        // Image liveness, trusted profile (owner item 1; an
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

    /// Sends `control` toward `source` from the intake's own endpoint if
    /// §7.3 and §7.4 allow it: the rate tests' entry point.
    #[cfg(test)]
    fn challenge(&mut self, source: SocketAddr, control: Control) -> bool {
        let endpoint = self.endpoint;
        self.challenge_from(endpoint, source, control)
    }

    /// The endpoint `key`'s SOLICITs leave from: its subscription's
    /// unicast control endpoint (plan 164), or the key's own endpoint.
    fn solicit_endpoint(&self, key: &BindingKey) -> EndpointId {
        self.role
            .solicit_from
            .iter()
            .find(|(held, stream, _)| (*held, *stream) == (key.endpoint, key.alias.stream_id))
            .map_or(key.endpoint, |(.., from)| *from)
    }

    /// Whether `key`'s subscription receives a multicast group.
    fn multicast_key(&self, key: &BindingKey) -> bool {
        self.role
            .subscriptions
            .iter()
            .any(|(held, stream, .., multicast)| {
                (*held, *stream) == (key.endpoint, key.alias.stream_id) && *multicast
            })
    }

    /// Sends an RSP_SETUP `control` from `endpoint` toward `source` if
    /// §7.3 and §7.4 allow it. Returns whether it was handed to the sender.
    fn challenge_from(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        control: Control,
    ) -> bool {
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
        self.role.posted_challenges.push((endpoint, control));
        #[cfg(test)]
        self.role.note(format!(
            "{} sent ep{} to {source} {}",
            self.now,
            endpoint.0,
            match control {
                Control::Challenge(_) => "challenge",
                Control::Solicit(_) => "solicit",
                _ => "other",
            }
        ));
        // An authenticated subscription's CHALLENGE or SOLICIT goes sealed
        // under its pairwise key's RSP_SETUP proof (domain 6), never bare.
        let alias = match control {
            Control::Challenge(challenge) => Some(challenge.alias),
            Control::Solicit(solicit) => Some(solicit.alias),
            _ => None,
        };
        let seal = alias.and_then(|alias| {
            self.role
                .subscription_auth
                .iter()
                .find(|auth| {
                    auth.stream_id == alias.stream_id
                        && (auth.endpoint == self.endpoint || auth.endpoint == endpoint)
                })
                .map(|auth| auth.rsp_sealer(alias))
        });
        self.forward(ControlItem::Outgoing {
            endpoint,
            destination: source,
            control,
            guard: None,
            seal,
        })
    }

    /// Whether a SETUP ANNOUNCE (`announce`) or ANSWER for `stream_id`
    /// from `source` may set up an image on this endpoint: on a
    /// `control-mode=dynamic` key only from the `control` address it
    /// registers at, port included, so no other host that reaches the
    /// key's port can announce an image of its stream (karyos#941 item 5);
    /// any source on another key, as before. A refused one is counted. An
    /// ANNOUNCE from `control` shows the key `Announced` (karyos#941 item
    /// 3) and leaves its REGISTER backoff as it is: a sender that announces
    /// but never answers the CHALLENGE, because it cannot bind the
    /// receiver, makes no progress, so the backoff keeps growing to its
    /// cap (karyos#947). An accepted ANSWER starts it over
    /// ([`Self::restart_register_backoff`]), as a bound image does.
    fn setup_from_control(
        &mut self,
        endpoint: EndpointId,
        stream_id: i32,
        source: SocketAddr,
        announce: bool,
    ) -> bool {
        use crate::sessions::register::RegistrationState;

        let Some(key) = self
            .role
            .registering
            .iter_mut()
            .find(|key| (key.endpoint, key.stream_id) == (endpoint, stream_id))
        else {
            return true;
        };
        if normalized(key.control) != normalized(source) {
            self.role.count(|c| &mut c.setup_not_from_control);
            return false;
        }
        if announce && key.status.get() != RegistrationState::Bound {
            key.status.set(RegistrationState::Announced);
        }
        true
    }

    /// Starts the REGISTER backoff of the `control-mode=dynamic` key of
    /// `stream_id` on `endpoint` over, its next REGISTER due one
    /// `setup_interval` on: its `control` address answered its CHALLENGE
    /// and an image is being created, progress past the CHALLENGE
    /// (karyos#941 item 1, karyos#947). Nothing for another key.
    fn restart_register_backoff(&mut self, endpoint: EndpointId, stream_id: i32) {
        let setup_interval = self.role.setup_interval;
        let now = self.now;
        if let Some(key) = self
            .role
            .registering
            .iter_mut()
            .find(|key| (key.endpoint, key.stream_id) == (endpoint, stream_id))
        {
            key.interval = setup_interval;
            key.due = key.due.min(now.saturating_add(setup_interval));
        }
    }

    /// Sends `register` from this endpoint to `control` under the
    /// REGISTERs' own bucket for `control`'s address, the port ignored
    /// (karyos#941 item 1); §7.3's source rule applies as to any RSP_SETUP.
    /// Returns whether it was handed to the sender.
    fn register_to(&mut self, control: SocketAddr, register: Control) -> bool {
        if !answerable(control) {
            self.role.count(|c| &mut c.unanswerable_source);
            return false;
        }
        let address = SocketAddr::new(normalized(control).ip(), 0);
        if self.role.register_rates.admit(address, self.now).is_err() {
            self.role.count(|c| &mut c.registers_rate_limited);
            return false;
        }
        #[cfg(test)]
        self.role.posted_challenges.push((self.endpoint, register));
        self.forward(ControlItem::Outgoing {
            endpoint: self.endpoint,
            destination: control,
            control: register,
            guard: None,
            seal: None,
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
            let from = self.solicit_endpoint(&key);
            if self.challenge_from(from, key.source, Control::Solicit(solicit)) {
                self.role.sessions.solicit_sent();
            } else {
                // The first SOLICIT never went out (a rate or the ring
                // refused it): the entry goes, with no holdoff, and the next
                // DATA asks again under the limits. Only a sent SOLICIT is
                // retried (plan 164).
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
            images,
            counters,
            trace,
            ..
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
            } => unrecoverable(image, counters, trace, lane, hole, lowest_retained, now),
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
                // A bare SETUP for an authenticated subscription or image is
                // refused before any challenge is created or consumed: an
                // unverified ANNOUNCE or ANSWER could otherwise bind a path.
                // One verified under the channel's SETUP proof (domain 5,
                // ADR-0086 section 7a) proceeds, a later path of an
                // authenticated image included: only a holder of the
                // channel key can make one.
                if !self.role.verified_setup
                    && (self.names_authenticated(announce.alias, announce.identity)
                        || self.subscription_authenticated(announce.alias.stream_id))
                {
                    self.role.count(|c| &mut c.auth_bare);
                    return;
                }
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
                // A registering key is set up by its `control` address
                // alone (karyos#941 item 5); an ANNOUNCE from there leaves
                // its REGISTER backoff as it is (karyos#947).
                if !self.setup_from_control(endpoint, announce.alias.stream_id, source, true) {
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
                    // A multicast key's CHALLENGE leaves from the driver's
                    // unicast control endpoint, as its SOLICITs do: the
                    // drivers of one host share the group port, and from it
                    // they would be one source to the publisher's
                    // `setup_answer_rate` (ADR-0096; karyos#1067).
                    let from = self.solicit_endpoint(&key);
                    // Counted only once handed to the sender: a refused
                    // one (§7.3, §7.4, a full ring) sent nothing.
                    if self.challenge_from(from, source, Control::Challenge(challenge))
                        && from == endpoint
                        && self.multicast_key(&key)
                    {
                        self.role.count(|c| &mut c.challenges_from_arrival);
                    }
                }
            }
            Control::SetupAnswer(answer) => {
                // A bare SETUP for an authenticated subscription or image is
                // refused before any challenge is created or consumed: an
                // unverified ANNOUNCE or ANSWER could otherwise bind a path.
                // One verified under the channel's SETUP proof (domain 5,
                // ADR-0086 section 7a) proceeds, a later path of an
                // authenticated image included: only a holder of the
                // channel key can make one.
                if !self.role.verified_setup
                    && (self.names_authenticated(answer.alias, answer.identity)
                        || self.subscription_authenticated(answer.alias.stream_id))
                {
                    self.role.count(|c| &mut c.auth_bare);
                    return;
                }
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
                if !self.setup_from_control(endpoint, answer.alias.stream_id, source, false) {
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
                #[cfg(test)]
                self.role.note(format!(
                    "{now} answer ep{} from {source} {outcome:?}",
                    endpoint.0
                ));
                if let (
                    AnswerOutcome::CreateImage {
                        slot,
                        identity,
                        term,
                        joins,
                        nonce,
                    },
                    Some((create, retire, chain)),
                ) = (outcome, reserved)
                {
                    let event = SessionEvent::CreateImage {
                        endpoint,
                        source,
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
                        nonce,
                    });
                    // The conductor gone: the driver is stopping.
                    let _ = sessions.events.post(create, event);
                    self.role.count(|c| &mut c.create_image);
                    self.restart_register_backoff(endpoint, answer.alias.stream_id);
                }
                if let AnswerOutcome::PathBound { image, path } = outcome {
                    self.role.count(|c| &mut c.paths_bound);
                    // The first later path: the path queues are allocated
                    // now, on the control path, and kept.
                    if self.role.path_intake.is_none() {
                        self.role.path_intake =
                            path_intake::PathIntake::new(&self.role.path_config).map(Box::new);
                    }
                    // The later path is charged and its freshness tracked
                    // from its own joins (RP-1).
                    // Its own control group, from its subscription
                    // entry (karyos#1064).
                    let group = self
                        .role
                        .groups
                        .iter()
                        .find(|(held, stream, ..)| {
                            (*held, *stream) == (endpoint, answer.alias.stream_id)
                        })
                        .map(|(_, _, control, group)| (*control, *group));
                    let joins = self.role.sessions.paths().joins(image, path);
                    if let (Some(joins), Some(installed)) = (
                        joins,
                        self.role.images.iter_mut().find(|held| held.slot == image),
                    ) {
                        let joins = path_joins(&joins, installed.term_length);
                        // A rebound path does not inherit its old route's
                        // fault (#310 review).
                        if let Some(route) = installed.routes.get_mut(path) {
                            *route = CopyRoute::default();
                        }
                        if let Some(slot) = installed.path_groups.get_mut(path) {
                            *slot = group;
                        }
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
                    None => {
                        #[cfg(test)]
                        self.role.note(format!(
                            "{now} path_hb unbound ep{} from {source}",
                            endpoint.0
                        ));
                        self.role.count(|c| &mut c.path_heartbeats_unbound);
                    }
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
                // A kind a later protocol version decodes: not served.
                _ => self.role.count(|c| &mut c.unhandled),
            },
            Control::NakReply(reply) => self.nak_reply(source, &reply),
            // A REGISTER names only its stream (design 2.5): it goes to the
            // sender for a stream published on this endpoint, which admits
            // it only for a `control-mode=dynamic` publication (design
            // 3.2).
            // An ERR REGISTRATION from the address a dynamic subscription
            // of its stream registers at: counted and shown as its state;
            // the subscription keeps registering, backing off (design 3.2;
            // karyos#941 items 1 and 3). From anywhere else it is
            // unhandled.
            Control::Registration(refusal) => {
                let registering = self.role.registering.iter().find(|key| {
                    key.endpoint == endpoint
                        && key.stream_id == refusal.stream_id
                        && normalized(key.control) == normalized(source)
                });
                if let Some(key) = registering {
                    // The application sees it (karyos#941 item 3); the
                    // key keeps backing off.
                    key.status
                        .set(crate::sessions::register::RegistrationState::Refused);
                    self.role.count(|c| &mut c.registration_refusals);
                } else {
                    self.role.count(|c| &mut c.unhandled);
                }
            }
            Control::Register(register) => {
                let published = self.role.published.iter().any(|(held, alias)| {
                    *held == endpoint && alias.stream_id == register.stream_id
                });
                if !published {
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
            _ => self.role.count(|c| &mut c.unhandled),
        }
    }
}

/// What a SESSION_ABORT's digest cache entry resends: the image's ACK,
/// re-sealed under a fresh sequence of its own domain 4 sealer, to the
/// binding it came from.
#[derive(Debug, Clone)]
struct AckResend {
    ack: karyos_protocol::network::authenticated::AbortAck,
    endpoint: EndpointId,
    destination: SocketAddr,
    sealer: SharedSealer,
}

/// The SESSION_ABORT_ACK of `image` aborted at `guard_epoch`, with its
/// lanes' delivered prefix and unresolved end; `None` for a trusted
/// image, whose ACK could not be sealed (fail closed).
fn abort_ack<T: StreamTerms>(
    image: &Installed<T>,
    receiver_boot_id: [u64; 2],
    guard_epoch: u64,
) -> Option<AckResend> {
    use karyos_protocol::network::authenticated::{AbortAck, AckLane};

    let sealer = image.auth.as_deref()?.sealer();
    let mut lanes = [AckLane::default(); 4];
    for (at, entry) in lanes
        .iter_mut()
        .enumerate()
        .take(usize::from(image.lane_count))
    {
        let delivered = u8::try_from(at)
            .ok()
            .and_then(|at| Lane::try_new(at).ok())
            .and_then(|lane| image.owner.rebuild_position(lane))
            .unwrap_or(0);
        let heard = image
            .heartbeat_marks
            .get(at)
            .copied()
            .flatten()
            .unwrap_or(0);
        *entry = AckLane {
            delivered,
            unresolved_end: heard.max(delivered),
        };
    }
    let lanes = Lanes::new(lanes.get(..usize::from(image.lane_count))?).ok()?;
    Some(AckResend {
        ack: AbortAck {
            alias: image.key.alias,
            identity: image.identity,
            receiver: Receiver {
                receiver_boot_id,
                receiver_id: image.receiver_id,
            },
            guard_epoch,
            lanes,
        },
        endpoint: image.key.endpoint,
        destination: image.key.source,
        sealer,
    })
}

/// A guard of another driver this one follows, as `receiver_id`.
#[derive(Debug)]
struct FollowedGuard {
    guard: crate::remote_guard::RemoteGuard,
    receiver_id: u64,
    /// The endpoint its challenges leave from.
    endpoint: EndpointId,
    /// The authority's guard control address.
    authority: SocketAddr,
    /// The guard word local sender gates read for it, written here on
    /// every change and lapse; `None` when no publication is guarded by it.
    mirror: Option<Arc<karyos_client::HeapWords>>,
}

/// A SESSION_ABORT requested of a publication.
#[derive(Debug, Clone, Copy)]
struct RequestedAbort {
    endpoint: EndpointId,
    alias: Alias,
    reason: u16,
    guard_epoch: u64,
}

/// The alias of a frame a sender authenticates in domain 1 that names an
/// image's binding (ADR-0086 section 7a): PATH_HB, ERR NAK_REPLY and RTTM
/// REPLY; `None` for any other control.
fn sender_frame_alias(control: &Control) -> Option<Alias> {
    match control {
        Control::PathHeartbeat(heartbeat) => Some(heartbeat.alias),
        Control::NakReply(reply) => Some(reply.alias),
        Control::Rttm(rttm) if matches!(rttm.kind, RttmKind::Reply { .. }) => Some(rttm.alias),
        _ => None,
    }
}

impl<T: StreamTerms> Intake<'_, T> {
    /// One unicast datagram. An envelope is opened by its binding's key
    /// before anything else (ADR-0086 section 2); a bare frame for a
    /// binding whose image is authenticated is refused; anything else
    /// takes the trusted path unchanged. A refusal changes nothing but its
    /// counter: no SOLICIT, no path queue, no state.
    fn bytes_in(&mut self, source: SocketAddr, bytes: &[u8]) {
        if receive_auth::is_envelope(bytes) {
            // The signed domains (GUARD 2, SESSION_ABORT 3) take their own
            // receive order (ADR-0086 section 2).
            if matches!(bytes.get(10).copied(), Some(2 | 3)) {
                self.signed_control(source, bytes);
                return;
            }
            let alias = receive_auth::envelope_alias(bytes);
            let domain = bytes.get(10).copied();
            if alias.is_some_and(|alias| self.published_authenticated(alias)) {
                self.sealed_for_publication(source, bytes);
            } else if domain
                == Some(karyos_protocol::protection::hmac_sha256::Domain::SetupProof as u8)
            {
                self.sealed_setup(source, bytes);
            } else {
                self.sealed(source, bytes);
            }
            return;
        }
        match classify(bytes) {
            Ok(Datagram::Control(control)) => {
                let bare_for_publication = receiver_control_alias(&control)
                    .is_some_and(|alias| self.published_authenticated(alias));
                if bare_for_publication
                    || sender_frame_alias(&control)
                        .is_some_and(|alias| self.authenticated(source, alias))
                {
                    self.role.count(|c| &mut c.auth_bare);
                    return;
                }
                // The path's queued DATA first: a reply this control causes
                // (an ERR) never overtakes it.
                self.drain_own_queue();
                self.control(source, control);
            }
            Ok(Datagram::DataBatch(data) | Datagram::Heartbeat(data)) => {
                if self.authenticated(source, data.alias()) {
                    self.role.count(|c| &mut c.auth_bare);
                    return;
                }
                self.deliver(source, data.alias(), data.bytes());
            }
            // A datagram kind a later protocol version decodes: not served.
            Ok(_) => self.role.count(|c| &mut c.unhandled),
            // A guard authority answers a bare STATUS_CHALLENGE (design
            // 4.2); anything else gated stays undecoded.
            Err(_) if self.status_challenge(source, bytes) => {}
            Err(_) => self.role.count(|c| &mut c.decode_errors),
        }
    }

    /// A bare datagram at a guard authority: answered with a signed
    /// STATUS to the receiver's configured endpoint when it is a
    /// STATUS_CHALLENGE the authority serves. Returns whether it was a
    /// STATUS_CHALLENGE, answered or refused.
    fn status_challenge(&mut self, source: SocketAddr, bytes: &[u8]) -> bool {
        use crate::guard_authority::ChallengeRefusal;

        let now = self.now;
        let Some(authority) = self.role.guard_authority.as_deref_mut() else {
            return false;
        };
        let answer = match authority.answer(bytes, source, now) {
            Ok(answer) => answer,
            Err(ChallengeRefusal::Malformed) => return false,
            Err(_) => {
                self.role.count(|c| &mut c.guard_challenges_refused);
                return true;
            }
        };
        let Some(raw) = SealedBytes::copy(answer.datagram()) else {
            self.role.count(|c| &mut c.guard_challenges_refused);
            return true;
        };
        if self.forward(ControlItem::Raw {
            endpoint: self.endpoint,
            destination: answer.destination,
            bytes: raw,
        }) {
            self.role.count(|c| &mut c.guard_statuses_sent);
        }
        true
    }

    /// A DATA datagram, through its path's queue when it has one.
    fn deliver(&mut self, source: SocketAddr, alias: Alias, bytes: &[u8]) {
        if !self.enqueue(source, alias, bytes) {
            self.data(source, alias, bytes);
        }
    }

    /// The installed image `source` and `alias` are bound to, by the
    /// session table's admission rule; reads only.
    fn bound_image(&self, source: SocketAddr, alias: Alias) -> Option<usize> {
        let key = BindingKey {
            endpoint: self.endpoint,
            source,
            alias,
        };
        let slot = self.role.sessions.lookup(&key)?;
        self.role.images.iter().position(|image| image.slot == slot)
    }

    /// Whether `source` and `alias` are bound to an authenticated image.
    fn authenticated(&self, source: SocketAddr, alias: Alias) -> bool {
        self.bound_image(source, alias)
            .and_then(|index| self.role.images.get(index))
            .is_some_and(|image| image.auth.is_some())
    }

    /// An envelope: only its `session_id`, `stream_id` and source are read
    /// to find the binding; its image's key checks the fields, the tag and
    /// the replay window, and only then are the inner frames classified,
    /// which must be a domain 1 datagram of that same binding.
    fn sealed(&mut self, source: SocketAddr, bytes: &[u8]) {
        let Some(alias) = receive_auth::envelope_alias(bytes) else {
            self.role.auth_unattributed.bump(AuthReason::Short);
            self.role.count(|c| &mut c.auth_unbound);
            return;
        };
        let found = self.bound_image(source, alias).and_then(|index| {
            let auth = self.role.images.get(index)?.auth.as_deref()?;
            let now = auth.now();
            Some((index, now, auth.check(bytes, now)))
        });
        let Some((index, now, checked)) = found else {
            self.role.auth_unattributed.bump(AuthReason::Unbound);
            self.role.count(|c| &mut c.auth_unbound);
            return;
        };
        let checked = match checked {
            Ok(checked) => checked,
            Err(refusal) => {
                self.reject(index, AuthReason::of(refusal));
                self.role.count(|c| &mut c.auth_rejected);
                return;
            }
        };
        let opened = checked.opened();
        let inner = bytes
            .get(opened.start..)
            .and_then(|rest| rest.get(..opened.frames));
        // The inner class and alias are checked before the sequence is
        // recorded or the epoch moves: a tagged datagram refused for its
        // inner frames consumes nothing.
        let accepted = match inner.map(classify) {
            Some(Ok(Datagram::DataBatch(data) | Datagram::Heartbeat(data)))
                if data.alias() == alias =>
            {
                Some(Ok(data.bytes()))
            }
            Some(Ok(Datagram::Control(control))) if sender_frame_alias(&control) == Some(alias) => {
                Some(Err(control))
            }
            _ => None,
        };
        let Some(accepted) = accepted else {
            self.reject(index, AuthReason::Inner);
            self.role.count(|c| &mut c.auth_inner_invalid);
            return;
        };
        let committed = self
            .role
            .images
            .get_mut(index)
            .and_then(|image| image.auth.as_deref_mut())
            .map(|auth| auth.commit(checked, now));
        match committed {
            Some(Ok(_)) => {}
            Some(Err(refusal)) => {
                self.reject(index, AuthReason::of(refusal));
                self.role.count(|c| &mut c.auth_rejected);
                return;
            }
            None => {
                self.role.auth_unattributed.bump(AuthReason::Unbound);
                self.role.count(|c| &mut c.auth_unbound);
                return;
            }
        }
        match accepted {
            Ok(data) => self.deliver(source, alias, data),
            Err(control) => {
                self.drain_own_queue();
                self.control(source, control);
            }
        }
    }

    /// Counts a refusal by `reason` on the image at `index`, whose binding
    /// is one key and one source.
    fn reject(&mut self, index: usize, reason: AuthReason) {
        if let Some(auth) = self
            .role
            .images
            .get_mut(index)
            .and_then(|image| image.auth.as_deref_mut())
        {
            auth.rejections.bump(reason);
        }
    }

    /// A signed GUARD or SESSION_ABORT envelope: the budget, the digest
    /// cache (a hit resends the ACK and changes nothing), `verify_strict`
    /// and the authority checks of [`SignedIntake`], then the epoch check
    /// and the state change here, and only after it the digest insert.
    fn signed_control(&mut self, source: SocketAddr, bytes: &[u8]) {
        use karyos_protocol::network::authenticated::AuthControl;
        use signed_control::Received;

        let now = self.now;
        let Some(intake) = self.role.signed.as_deref_mut() else {
            self.role.count(|c| &mut c.signed_unconfigured);
            return;
        };
        let verified = match intake.receive(source, bytes, now) {
            Ok(Received::Fresh(verified)) => verified,
            Ok(Received::Resend(resend)) => {
                if self.send_abort_ack(resend) {
                    self.role.count(|c| &mut c.abort_acks_resent);
                }
                return;
            }
            Err(_) => {
                self.role.count(|c| &mut c.signed_refused);
                return;
            }
        };
        match verified.control {
            AuthControl::Abort(abort) => {
                // The epoch check: only a bound, authenticated image of
                // that incarnation not yet aborted.
                let index = self.bound_image(source, abort.alias).filter(|index| {
                    self.role.images.get(*index).is_some_and(|image| {
                        image.identity == abort.identity
                            && image.auth.is_some()
                            && image.aborted.is_none()
                    })
                });
                let resend = index.and_then(|index| {
                    let image = self.role.images.get_mut(index)?;
                    image.aborted = Some(abort.guard_epoch);
                    image.closing = Some(CloseReason::Aborted);
                    abort_ack(image, self.role.sessions.boot_id(), abort.guard_epoch)
                });
                let Some(resend) = resend else {
                    self.role.count(|c| &mut c.aborts_refused);
                    return;
                };
                if self.send_abort_ack(resend.clone()) {
                    self.role.count(|c| &mut c.abort_acks_sent);
                }
                if let Some(intake) = self.role.signed.as_deref_mut() {
                    intake.applied(verified.digest, resend);
                }
            }
            AuthControl::State(state) => {
                let marks = self.role.guard_marks.as_deref_mut();
                let guard = self
                    .role
                    .remote_guards
                    .iter_mut()
                    .find(|followed| followed.guard.guard_id() == state.guard_id);
                let applied = match (guard, marks) {
                    (Some(followed), Some(marks)) => {
                        followed.guard.on_state(&state, now, marks).is_ok()
                    }
                    _ => false,
                };
                self.guard_outcome(applied);
                self.role.publish_guard_words(now);
            }
            AuthControl::Status(status) => {
                let boot = self.role.sessions.boot_id();
                let marks = self.role.guard_marks.as_deref_mut();
                let guard = self
                    .role
                    .remote_guards
                    .iter_mut()
                    .find(|followed| followed.guard.guard_id() == status.guard_id);
                let applied = match (guard, marks) {
                    (Some(followed), Some(marks)) => {
                        let receiver = Receiver {
                            receiver_boot_id: boot,
                            receiver_id: followed.receiver_id,
                        };
                        followed
                            .guard
                            .on_status(&status, receiver, now, marks)
                            .is_ok()
                    }
                    _ => false,
                };
                self.guard_outcome(applied);
                self.role.publish_guard_words(now);
            }
            _ => self.role.count(|c| &mut c.signed_refused),
        }
    }

    /// Counts a GUARD outcome. A STATE or STATUS changes no ACK, so it
    /// needs no digest entry: a resend runs the guard's own epoch and nonce
    /// checks again, which refuse it.
    fn guard_outcome(&mut self, applied: bool) {
        if applied {
            self.role.count(|c| &mut c.guard_changes);
        } else {
            self.role.count(|c| &mut c.guard_refused);
        }
    }

    /// Sends a SESSION_ABORT_ACK sealed in domain 4 under its image's
    /// sealer, a fresh envelope sequence for each transmission.
    fn send_abort_ack(&mut self, mut resend: AckResend) -> bool {
        use karyos_protocol::network::authenticated::AuthControl;

        let mut bytes =
            [0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + crate::wire_auth::ENVELOPE_LEN];
        let Some(plain) = bytes.get_mut(..karyos_protocol::network::MAX_CONTROL_LENGTH) else {
            return false;
        };
        let Ok(length) = AuthControl::Ack(resend.ack).encode(plain) else {
            return false;
        };
        let Some(sealed) = resend.sealer.seal_control(&mut bytes, length) else {
            return false;
        };
        let Some(raw) = bytes.get(..sealed).and_then(SealedBytes::copy) else {
            return false;
        };
        self.forward(ControlItem::Raw {
            endpoint: resend.endpoint,
            destination: resend.destination,
            bytes: raw,
        })
    }

    /// Whether `alias` is a local authenticated publication on this
    /// endpoint.
    fn published_authenticated(&self, alias: Alias) -> bool {
        self.role.published_auth.contains(&(self.endpoint, alias))
    }

    /// Whether the subscription to `stream_id` on this endpoint is
    /// authenticated.
    fn subscription_authenticated(&self, stream_id: i32) -> bool {
        self.role
            .subscription_auth
            .iter()
            .any(|auth| auth.endpoint == self.endpoint && auth.stream_id == stream_id)
    }

    /// An envelope for a local authenticated publication: handed to the
    /// sender agent undecoded, which verifies it under that publication's
    /// keys before anything reads it (ADR-0086 section 2).
    fn sealed_for_publication(&mut self, source: SocketAddr, bytes: &[u8]) {
        let Some(sealed) = SealedBytes::copy(bytes) else {
            self.role.auth_unattributed.bump(AuthReason::Length);
            self.role.count(|c| &mut c.auth_rejected);
            return;
        };
        let _ = self.forward(ControlItem::Sealed {
            endpoint: self.endpoint,
            source,
            bytes: sealed,
            seen: self.now,
        });
    }

    /// A SETUP ANNOUNCE or ANSWER envelope (domain 5): verified under the
    /// SETUP proof of its stream's authenticated subscription on this
    /// endpoint before its inner control is read, and handled only if
    /// that control is a SETUP of the envelope's own alias.
    fn sealed_setup(&mut self, source: SocketAddr, bytes: &[u8]) {
        let Some(alias) = receive_auth::envelope_alias(bytes) else {
            self.role.auth_unattributed.bump(AuthReason::Short);
            self.role.count(|c| &mut c.auth_unbound);
            return;
        };
        let endpoint = self.endpoint;
        let Some(index) = self
            .role
            .subscription_auth
            .iter()
            .position(|auth| auth.endpoint == endpoint && auth.stream_id == alias.stream_id)
        else {
            self.role.auth_unattributed.bump(AuthReason::Unbound);
            self.role.count(|c| &mut c.auth_unbound);
            return;
        };
        let verified = self
            .role
            .subscription_auth
            .get(index)
            .map(|auth| auth.verify_setup(alias, bytes));
        let reject = |intake: &mut Self, reason: AuthReason| {
            if let Some(auth) = intake.role.subscription_auth.get_mut(index) {
                auth.rejections.bump(reason);
            }
            intake.role.count(|c| &mut c.auth_rejected);
        };
        let proved = match verified {
            Some(Ok(proved)) => proved,
            Some(Err(rejection)) => {
                reject(
                    self,
                    AuthReason::of(crate::wire_auth::Refusal::Envelope(rejection)),
                );
                return;
            }
            None => return,
        };
        let inner = bytes
            .get(proved.opened.start..)
            .and_then(|rest| rest.get(..proved.opened.frames));
        let control = match inner.map(classify) {
            Some(Ok(Datagram::Control(control @ Control::SetupAnnounce(announce))))
                if announce.alias == alias =>
            {
                control
            }
            Some(Ok(Datagram::Control(control @ Control::SetupAnswer(answer))))
                if answer.alias == alias =>
            {
                control
            }
            _ => {
                reject(self, AuthReason::Inner);
                self.role.count(|c| &mut c.auth_inner_invalid);
                return;
            }
        };
        self.drain_own_queue();
        self.role.verified_setup = true;
        self.control(source, control);
        self.role.verified_setup = false;
    }

    /// Whether a bare SETUP ANNOUNCE or ANSWER names an authenticated
    /// image: its identity, or its alias on this endpoint.
    fn names_authenticated(&self, alias: Alias, identity: Identity) -> bool {
        self.role.images.iter().any(|image| {
            image.auth.is_some()
                && (image.identity == identity
                    || (image.key.endpoint == self.endpoint && image.key.alias == alias))
        })
    }
}

impl<T: StreamTerms> RxHandler for Intake<'_, T> {
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
        // At most the poll budget's datagrams: no overflow.
        self.work += 1;
        self.role.count(|c| &mut c.datagrams);
        let source = datagram.source();
        self.bytes_in(source, datagram.bytes());
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, _drop: RxDrop) {
        self.role.count(|c| &mut c.backend_drops);
    }
}

impl<T: StreamTerms> SenderRole<T> {
    /// The sender's publication at `index` (tests).
    #[cfg(test)]
    pub(super) fn publication_mut(&mut self, index: usize) -> Option<&mut Outbound<T>> {
        self.publications
            .get_mut(index)
            .map(|outbound| &mut **outbound)
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> SenderCounters {
        self.counters
    }

    /// Makes the publication `auth` names authenticated (tests); its
    /// `Outbound` must have been made authenticated too. Nothing else
    /// does yet.
    #[cfg(test)]
    pub(super) fn authenticate_publication(&mut self, auth: PublicationAuth) {
        self.publication_auth.push(auth);
    }

    /// Verifies a sealed control as the duty does, returning its control
    /// and establishment (tests).
    #[cfg(test)]
    pub(super) fn open_sealed_for(
        &mut self,
        endpoint: EndpointId,
        bytes: &[u8],
    ) -> Option<(Control, Option<Establishing>)> {
        self.open_sealed(endpoint, bytes)
    }

    /// Installs the sealer of a verified establishment, as the answer
    /// does (tests).
    #[cfg(test)]
    pub(super) fn establish_for(
        &mut self,
        endpoint: EndpointId,
        answer: &Control,
        establishing: Establishing,
    ) {
        self.establish(endpoint, answer, establishing);
    }

    /// Gives the authenticated publication `alias` on `endpoint` an abort
    /// authority (tests).
    #[cfg(test)]
    pub(super) fn set_abort_authority(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        authority: publish_auth::AbortAuthority,
    ) {
        if let Some(auth) = self
            .publication_auth_index(endpoint, alias)
            .and_then(|index| self.publication_auth.get_mut(index))
        {
            auth.abort = Some(authority);
        }
    }

    /// The last SESSION_ABORT_ACK verified (tests).
    #[cfg(test)]
    pub(super) fn last_abort_ack(
        &self,
    ) -> Option<karyos_protocol::network::authenticated::AbortAck> {
        self.last_abort_ack
    }

    /// The bytes of the last SESSION_ABORT sent (tests).
    #[cfg(test)]
    pub(super) fn last_abort_bytes(&self) -> Option<Vec<u8>> {
        self.last_abort.map(|(_, _, bytes)| bytes.get().to_vec())
    }

    /// Sends `control` as the publication's sender control would be sent
    /// (tests).
    #[cfg(test)]
    pub(super) fn send_sender_control_for<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
    ) -> bool {
        self.send_sender_control(halves, endpoint, destination, control)
            .submitted()
    }

    /// Takes the next control the receiver handed over, unsent (tests).
    #[cfg(test)]
    pub(super) fn take_control(&mut self) -> Option<ControlItem> {
        self.from_receiver.try_take().ok().flatten()
    }

    /// The SETUP side's counters.
    #[must_use]
    pub fn session_counters(&self) -> crate::sessions::send::SendCounters {
        self.sessions.counters()
    }

    /// The counters of the driver's dynamic registrations (design 3.2, 7).
    #[must_use]
    pub fn registration_counters(&self) -> crate::sessions::register::RegistrationCounters {
        self.registrations.counters()
    }

    /// The pending registrations for `stream_id`: REGISTERs answered with
    /// a SETUP and not yet joined, refused or expired (tests).
    #[cfg(test)]
    pub(crate) fn pending_registrations(&self, stream_id: i32) -> usize {
        self.registrations
            .pending()
            .iter()
            .filter(|entry| entry.stream_id == stream_id)
            .count()
    }

    /// Stores each publication's changed counts into its CnC cells, at
    /// the end of a duty cycle (M2b).
    pub(crate) fn publish_stream_cells(&mut self) {
        // Each publication's admission state too (karyos#637), observed
        // at one reading of the clock.
        let now = karyos_sys::host_clock::host_monotonic_ns();
        for outbound in &mut self.publications {
            outbound.observe_admission(now);
            outbound.publish_cells();
        }
    }

    /// Hands its publications' cells back into `cells`, at the close.
    pub(crate) fn take_stream_cells(&mut self, cells: &mut Vec<karyos_sys::counters::Counter>) {
        for outbound in &mut self.publications {
            if let Some(mut taken) = outbound.take_cells() {
                cells.extend(taken.take());
            }
        }
    }

    /// The data path of its `index`-th publication (tests).
    #[cfg(test)]
    pub(crate) fn outbound(&self, index: usize) -> Option<&Outbound<T>> {
        self.publications.get(index).map(|outbound| &**outbound)
    }

    /// The data path of its `index`-th publication, mutable (tests).
    #[cfg(test)]
    pub(crate) fn outbound_mut(&mut self, index: usize) -> Option<&mut Outbound<T>> {
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
        command: AgentCommand<O, T>,
    ) -> Option<(Reservation, AgentEvent<O, T>)> {
        let (reply, publication, outbound, guard, roles) = match command {
            AgentCommand::AddPublication {
                reply,
                publication,
                outbound,
                guard,
                roles,
            } => (reply, publication, outbound, guard, roles),
            AgentCommand::ChangeDestination {
                reply,
                endpoint,
                alias,
                registration,
                destination,
                add,
            } => {
                let now = (self.clock)();
                let quarantine = self.membership.receiver_timeout;
                let outcome = self
                    .publications
                    .iter_mut()
                    .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
                    .map_or(
                        crate::agents::data::DestinationChange::Unknown,
                        |outbound| outbound.change_destination(destination, add, now, quarantine),
                    );
                return Some((
                    reply,
                    AgentEvent::DestinationChanged {
                        endpoint,
                        alias,
                        registration,
                        destination,
                        add,
                        outcome,
                    },
                ));
            }
            AgentCommand::RemovePublication {
                reply,
                endpoint,
                alias,
                registration,
                linger,
            } => {
                return Some((
                    reply,
                    self.begin_remove(endpoint, alias, registration, linger),
                ));
            }
            AgentCommand::RemoveSenderSession {
                reply,
                endpoint,
                alias,
                registration,
            } => return Some((reply, self.remove(endpoint, alias, registration))),
            #[cfg(test)]
            AgentCommand::ForceReset { endpoint, alias } => {
                if let Some(outbound) = self
                    .publications
                    .iter_mut()
                    .find(|outbound| outbound.endpoint() == endpoint && outbound.alias() == alias)
                {
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
        // A REGISTER names only its stream (design 2.5): one control
        // endpoint holds at most one dynamic publication of a stream
        // (design 3.2 step 1).
        let second_dynamic = outbound.registration().is_some()
            && self.publications.iter().any(|held| {
                held.registration().is_some()
                    && held.alias().stream_id == publication.alias.stream_id
                    && held.serves(publication.endpoint)
            });
        let matches = matches && !second_dynamic;
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
                // Design 3.5 (MD-6, karyos#917): every destination can
                // CHALLENGE at once, so a multi-destination publication's
                // table holds a Pending entry and a member per destination.
                if let Some(destinations) = outbound
                    .destination_capacity()
                    .and_then(|max| u16::try_from(max).ok())
                {
                    config.max_pending = config.max_pending.max(destinations);
                    config.max_receivers = config.max_receivers.max(destinations);
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
            Some(mut membership) if matches => {
                // A multi-destination publication's required destinations,
                // by endpoint (MD-11, MD-17; karyos#630).
                let required: Vec<SocketAddr> = outbound.required_destinations().collect();
                membership.set_required_sources(&required);
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
                // Its paths leave the live set by the agent's policy (RP-8).
                outbound.set_path_policy(self.path_policy);
                if repairs && guarded {
                    add_sessions(&mut self.sessions, &publication, &outbound)
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
                let mut outbound = outbound;
                outbound
                    .set_destination_timing(self.membership.receiver_timeout, self.setup_interval);
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

    /// Starts removing the publication `alias` on `endpoint`
    /// (driver-network-agents.md §7): it announces no SETUP and admits no
    /// new receiver ([`SenderRole::route_of`]), while its incarnation,
    /// bindings, membership and repair stay for the drain and the
    /// `linger`. A repeated command keeps the first linger.
    fn begin_remove<O: SocketOps>(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        registration: u64,
        linger: u64,
    ) -> AgentEvent<O, T> {
        let interval = self.path_heartbeat_interval;
        let outbound = self
            .publications
            .iter_mut()
            .find(|outbound| outbound.endpoint() == endpoint && outbound.alias() == alias);
        let found = outbound.is_some();
        if let Some(outbound) = outbound {
            outbound.begin_removal(registration, linger, interval);
            // A draining publication announces nothing more (#849).
            for path in outbound.route_endpoints() {
                for slot in &mut self.routes {
                    if slot.endpoint == Some(path) {
                        slot.routes.purge_announces(alias, None);
                    }
                }
            }
        }
        AgentEvent::PublicationDraining {
            endpoint,
            alias,
            registration,
            found,
        }
    }

    /// Posts, through `post` (which says whether it was posted), the
    /// `SenderSessionDrained` of each publication whose linger is over,
    /// once; one the ring refused is posted again next cycle.
    pub(super) fn report_drained<O: SocketOps>(
        &mut self,
        mut post: impl FnMut(AgentEvent<O, T>) -> bool,
    ) {
        for outbound in &mut self.publications {
            let Some(registration) = outbound.drained_unreported() else {
                continue;
            };
            let event = AgentEvent::SenderSessionDrained {
                endpoint: outbound.endpoint(),
                alias: outbound.alias(),
                registration,
            };
            if !post(event) {
                return;
            }
            outbound.drained_reported();
        }
    }

    /// Posts, through `post`, a `DestinationRemoved` for each destination a
    /// multi-destination publication removed and did not report yet, after
    /// expiring its member, so it stops counting for the strategy edge
    /// (design 4.5; MD-7, MD-12). One the ring refused is posted again next
    /// cycle. A posted report retires the destination and hands its route
    /// and queues to the close list (design 3.7).
    /// Its control routes on `endpoint`, open and closing (tests).
    #[cfg(test)]
    pub(super) fn control_entries(&self, endpoint: EndpointId) -> usize {
        self.routes
            .iter()
            .find(|slot| slot.endpoint == Some(endpoint))
            .map_or(0, |slot| slot.routes.entries().0)
    }

    /// Posts each publication's endpoint limit change through `post`
    /// (karyos#859); one `post` refuses leaves the rest for the next cycle.
    pub(super) fn report_limits<O: SocketOps>(
        &mut self,
        mut post: impl FnMut(AgentEvent<O, T>) -> bool,
    ) {
        for outbound in &mut self.publications {
            let Some(limit) = outbound.limit_unreported() else {
                continue;
            };
            let (endpoint, alias) = (outbound.endpoint(), outbound.alias());
            let Some(identity) = self.sessions.identity(endpoint, alias) else {
                continue;
            };
            let event = AgentEvent::PublicationLimit {
                endpoint,
                alias,
                registration: identity.registration_id,
                limit,
            };
            if !post(event) {
                return;
            }
            outbound.limit_reported();
        }
    }

    pub(super) fn report_removals<O: SocketOps>(
        &mut self,
        mut post: impl FnMut(AgentEvent<O, T>) -> bool,
    ) {
        let now = (self.clock)();
        let mut unrecorded = 0u64;
        'publications: for outbound in &mut self.publications {
            while let Some(removal) = outbound.removal_unreported() {
                // Its member stops counting for the strategy edge before
                // the report is posted: with the conductor's ring full, a
                // slow member must not keep holding the publisher (#630).
                // Releasing it again on a retry is harmless: its SMs are
                // dropped once it is removed.
                if let Some(membership) = outbound.membership_mut() {
                    let _ = membership.release_source(removal.destination, now);
                }
                let (endpoint, alias) = (outbound.endpoint(), outbound.alias());
                let Some(identity) = self.sessions.identity(endpoint, alias) else {
                    break;
                };
                let event = AgentEvent::DestinationRemoved {
                    endpoint,
                    alias,
                    registration: identity.registration_id,
                    removal,
                };
                if !post(event) {
                    break 'publications;
                }
                outbound.removal_reported(removal.destination, now);
                // No ANNOUNCE to it waits any more.
                for slot in &mut self.routes {
                    if slot.endpoint == Some(endpoint) {
                        slot.routes
                            .purge_announces(alias, Some(removal.destination));
                    }
                }
                // Its route and queues go to the close list now, so the
                // next cycle's commands, served before its duty, find the
                // slot free; that duty closes them before it opens anything.
                let left = outbound.drain_retired(&mut self.closing);
                unrecorded = unrecorded.saturating_add(left);
            }
        }
        for _ in 0..unrecorded {
            self.count(|c| &mut c.removed_unrecorded);
        }
    }

    /// Posts, through `post` (which says whether it was posted), the
    /// `ScheduleViolated` of each timed lane whose publisher breached its
    /// ring's protocol, once per lane; one the ring refused is posted again
    /// next cycle. A publication with no session identity reports nothing.
    pub(super) fn report_violations<O: SocketOps>(
        &mut self,
        mut post: impl FnMut(AgentEvent<O, T>) -> bool,
    ) {
        for outbound in &mut self.publications {
            while let Some(lane) = outbound.violation_unreported() {
                let (endpoint, alias) = (outbound.endpoint(), outbound.alias());
                let Some(identity) = self.sessions.identity(endpoint, alias) else {
                    break;
                };
                let Ok(lane_index) = u8::try_from(lane) else {
                    break;
                };
                let event = AgentEvent::ScheduleViolated {
                    endpoint,
                    alias,
                    registration: identity.registration_id,
                    incarnation: identity.incarnation,
                    lane: lane_index,
                };
                if !post(event) {
                    return;
                }
                outbound.violation_reported(lane);
            }
        }
    }

    /// Stops the publication `alias` on `endpoint`: its SETUP side, its
    /// bindings and its data path, which goes back to the conductor.
    fn remove<O: SocketOps>(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        registration: u64,
    ) -> AgentEvent<O, T> {
        let mut outbound = self
            .publications
            .iter()
            .position(|outbound| outbound.endpoint() == endpoint && outbound.alias() == alias)
            .map(|index| self.publications.swap_remove(index));
        // Drained or given up, its gate decides nothing more: the walker
        // records what never left.
        if let Some(outbound) = outbound.as_deref_mut() {
            outbound.finish_removed();
        }
        // Its routes and queues close at the next duty, which holds the TX
        // halves (driver-network-agents.md §7).
        // One the close list has no room for (under sustained churn) is
        // counted, and recorded as its endpoint's close failure: the
        // standing reset it asks for drops it.
        if let Some(outbound) = outbound.as_deref() {
            let mut closing = std::mem::take(&mut self.closing);
            outbound.opened_resources(|opened| {
                if closing.len() < closing.capacity() {
                    closing.push(opened);
                } else {
                    self.count(|c| &mut c.removed_unrecorded);
                    self.note_close_failure(opened.endpoint, opened.epoch);
                }
            });
            self.closing = closing;
        }
        // Every path's SETUP side and bindings go with it.
        match outbound.as_deref() {
            Some(outbound) => {
                for path in outbound.route_endpoints() {
                    let _ = self.sessions.remove(path, alias);
                    for slot in &mut self.routes {
                        if slot.endpoint == Some(path) {
                            slot.routes.purge_announces(alias, None);
                        }
                    }
                }
                self.bindings.retain(|binding| {
                    !(outbound.serves(binding.endpoint) && binding.alias == alias)
                });
            }
            None => {
                let _ = self.sessions.remove(endpoint, alias);
                for slot in &mut self.routes {
                    if slot.endpoint == Some(endpoint) {
                        slot.routes.purge_announces(alias, None);
                    }
                }
                self.bindings
                    .retain(|binding| (binding.endpoint, binding.alias) != (endpoint, alias));
            }
        }
        // Lanes still traced (their close found no room before the removal)
        // close through the hook, so it closes their writers; the conductor
        // counts them `Lost`.
        if let Some(outbound) = outbound.as_mut() {
            let hook = &mut self.trace;
            outbound.untrace_all(|lane, traced| {
                if let (Some(hook), Some(lane)) = (
                    hook.hook(),
                    u8::try_from(lane)
                        .ok()
                        .and_then(|lane| Lane::try_new(lane).ok()),
                ) {
                    hook.close_journal(
                        karyos_protocol::trace_hook::NetSide::Sender,
                        &traced.publication,
                        lane,
                    );
                }
            });
        }
        AgentEvent::PublicationRemoved {
            endpoint,
            alias,
            registration,
            outbound,
        }
    }

    /// Closes the routes and queues removed publications left (see
    /// [`SenderRole::remove`]), on each endpoint whose TX half it holds in
    /// the same epoch. An endpoint whose half it does not hold, or now in
    /// another epoch, dropped them already (a reset or a retirement).
    fn close_removed<O: SocketOps>(&mut self, halves: &mut [(EndpointId, Half<O>)], now: u64) {
        // An endpoint whose half is gone (in a reset, or retired) or back
        // in another epoch starts afresh.
        self.close_failures.retain(|record| {
            halves.iter().any(|(held, half)| match half {
                Half::Tx(tx) => *held == record.endpoint && tx.capabilities().epoch == record.epoch,
                _ => false,
            })
        });
        // The control routes evicted with frames in flight, once per duty,
        // then the controls waiting for them.
        for index in 0..self.routes.len() {
            let Some(slot) = self.routes.get_mut(index) else {
                break;
            };
            let Some(endpoint) = slot.endpoint else {
                continue;
            };
            if let Some(tx) = halves.iter_mut().find_map(|(held, half)| match half {
                Half::Tx(tx) if *held == endpoint => Some(tx),
                _ => None,
            }) {
                slot.routes.close_lingering(tx, now);
            }
        }
        // The entries still in flight are closed again: closed, they go;
        // a close error, or the time bound in flight, fails them; else they
        // wait for the next duty.
        let mut index = 0;
        while let Some((mut opened, since)) = self.closing_again.get(index).copied() {
            let outcome = self.close_entry(halves, &mut opened);
            let late = super::close_late(since, now);
            match outcome {
                EntryClosed::Done => {
                    self.closing_again.swap_remove(index);
                }
                EntryClosed::InFlight if !late => {
                    if let Some(slot) = self.closing_again.get_mut(index) {
                        slot.0 = opened;
                    }
                    index += 1;
                }
                EntryClosed::InFlight | EntryClosed::Failed => {
                    if outcome == EntryClosed::InFlight {
                        self.count(|c| &mut c.removed_close_timeouts);
                    }
                    self.closing_again.swap_remove(index);
                    self.close_failed(opened.endpoint, opened.epoch);
                }
            }
        }
        // New entries: closed, they go; in flight, they wait in
        // `closing_again`; a close error fails them, once, and the endpoint
        // is reset when what did not close holds it at its limit. With
        // `closing_again` full (it holds every route a removal can leave,
        // so only removals faster than one bound can fill it), an entry in
        // flight stays in the close list for the next duty, counted, never
        // failed for want of room.
        let mut index = 0;
        while let Some(mut opened) = self.closing.get(index).copied() {
            match self.close_entry(halves, &mut opened) {
                EntryClosed::Done => {
                    self.closing.swap_remove(index);
                }
                EntryClosed::InFlight
                    if self.closing_again.len() < self.closing_again.capacity() =>
                {
                    self.count(|c| &mut c.removed_close_deferred);
                    self.closing.swap_remove(index);
                    self.closing_again.push((opened, now));
                }
                EntryClosed::InFlight => {
                    self.count(|c| &mut c.removed_close_overflow);
                    if let Some(slot) = self.closing.get_mut(index) {
                        *slot = opened;
                    }
                    index += 1;
                }
                EntryClosed::Failed => {
                    self.closing.swap_remove(index);
                    self.close_failed(opened.endpoint, opened.epoch);
                }
            }
        }
    }

    /// Records that a live route or queue of `endpoint` did not close in
    /// `epoch`.
    fn close_failed(&mut self, endpoint: EndpointId, epoch: karyos_io::backend::BackendEpoch) {
        self.count(|c| &mut c.removed_close_failed);
        self.note_close_failure(endpoint, epoch);
    }

    /// Keeps `endpoint`'s record of a close failure in `epoch`, once.
    fn note_close_failure(
        &mut self,
        endpoint: EndpointId,
        epoch: karyos_io::backend::BackendEpoch,
    ) {
        let known = self
            .close_failures
            .iter()
            .any(|record| record.endpoint == endpoint && record.epoch == epoch);
        if known {
            return;
        }
        if self.close_failures.len() < self.close_failures.capacity() {
            self.close_failures.push(EndpointCloses {
                endpoint,
                epoch,
                reset: CloseReset::Idle,
            });
        } else {
            self.count(|c| &mut c.close_failures_full);
        }
    }

    /// The endpoints that refused a route or a queue for their limit this
    /// cycle, on any open path or control route: one that failed a close in
    /// the epoch it refused in has its reset asked for, once per epoch.
    /// Without a failed close the refusal is an ordinary limit and resets
    /// nothing.
    fn reset_limited(&mut self) {
        // The control routes' failed closes and limits count as the
        // publications' do.
        for index in 0..self.routes.len() {
            let Some(slot) = self.routes.get_mut(index) else {
                break;
            };
            let (Some(endpoint), Some((epoch, refusal))) =
                (slot.endpoint, slot.routes.take_refusal())
            else {
                continue;
            };
            for _ in 0..refusal.close_failed {
                self.close_failed(endpoint, epoch);
            }
            if refusal.limited {
                self.limit_refused(endpoint, epoch);
            }
        }
        for index in 0..self.publications.len() {
            let Some(outbound) = self.publications.get_mut(index) else {
                break;
            };
            for (endpoint, epoch) in outbound.take_limited().into_iter().flatten() {
                self.limit_refused(endpoint, epoch);
            }
        }
    }

    /// `endpoint` refused a route or a queue for its limit in `epoch`.
    fn limit_refused(&mut self, endpoint: EndpointId, epoch: karyos_io::backend::BackendEpoch) {
        if let Some(record) = self
            .close_failures
            .iter_mut()
            .find(|record| record.endpoint == endpoint && record.epoch == epoch)
            && record.reset == CloseReset::Idle
        {
            record.reset = CloseReset::Due;
        }
    }

    /// Closes `opened` whole, clearing each queue that closed from it.
    fn close_entry<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        opened: &mut super::data::Opened,
    ) -> EntryClosed {
        #[cfg(test)]
        if self.close_in_flight > 0 {
            self.close_in_flight -= 1;
            return EntryClosed::InFlight;
        }
        use karyos_io::backend::{QueueError, RouteError};

        // A half not held now is in a reset or retired: the reset, done or
        // to come, drops these handles, and a retired half never comes
        // back. Dropped and counted, so nothing waits on what cannot close.
        let Some(tx) = halves.iter_mut().find_map(|(held, half)| match half {
            Half::Tx(tx) if *held == opened.endpoint => Some(tx),
            _ => None,
        }) else {
            self.count(|c| &mut c.removed_dropped);
            return EntryClosed::Done;
        };
        // An older epoch's handles died with its reset (an entry is never
        // of a later epoch than its half).
        let epoch = tx.capabilities().epoch;
        if epoch != opened.epoch {
            debug_assert!(opened.epoch < epoch, "an entry of a later epoch");
            self.count(|c| &mut c.removed_dropped);
            return EntryClosed::Done;
        }
        // A handle already gone counts as closed. Failed: a live handle did
        // not close. In flight: a queue still has frames the kernel holds.
        let (mut failed, mut in_flight) = (false, false);
        for held in &mut opened.queues {
            let Some(queue) = *held else {
                continue;
            };
            // A full report leaves items pending: emptied and called again
            // until none remains, each call returning at least one, so the
            // queue's depth bounds the loop.
            loop {
                match tx.close_queue(queue, &mut self.close_report) {
                    Ok(outcome) => {
                        while self.close_report.pop_front().is_some() {
                            self.count(|c| &mut c.removed_returned);
                        }
                        if !outcome.more {
                            self.count(|c| &mut c.removed_closed);
                            *held = None;
                            break;
                        }
                        if outcome.returned == 0 {
                            in_flight = true;
                            break;
                        }
                    }
                    Err(QueueError::UnknownQueue) => {
                        self.count(|c| &mut c.removed_closed);
                        *held = None;
                        break;
                    }
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
        }
        if failed {
            return EntryClosed::Failed;
        }
        // The route goes once its queues have: an open one still uses it.
        if in_flight {
            return EntryClosed::InFlight;
        }
        match tx.remove_route(opened.route) {
            Ok(()) | Err(RouteError::Unknown) => {
                self.count(|c| &mut c.removed_closed);
                EntryClosed::Done
            }
            Err(_) => EntryClosed::Failed,
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
    /// Sends a PATH_HB on each idle path of every established publication,
    /// on one path or routed (karyos#859); returns the count submitted.
    fn path_heartbeats<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        now: u64,
    ) -> u32 {
        let interval = self.path_heartbeat_interval;
        let mut submitted = 0u32;
        for index in 0..self.publications.len() {
            let Some(outbound) = self.publications.get(index) else {
                break;
            };
            let alias = outbound.alias();
            let identity = self.sessions.identity(outbound.endpoint(), alias);
            let (true, Some(identity)) = (established(&self.sessions, outbound), identity) else {
                continue;
            };
            let control = Control::PathHeartbeat(PathHeartbeat { alias, identity });
            let mut due = [None; MAX_ROUTES];
            let mut held = due.iter_mut();
            if let Some(outbound) = self.publications.get_mut(index) {
                let _ = outbound.path_heartbeats(now, interval, |endpoint, destination| {
                    held.next().is_some_and(|slot| {
                        *slot = Some((endpoint, destination));
                        true
                    })
                });
            }
            for (endpoint, destination) in due.into_iter().flatten() {
                if matches!(
                    self.send_sender_control(halves, endpoint, destination, &control),
                    Sent::Submitted
                ) {
                    if let Some(outbound) = self.publications.get_mut(index) {
                        outbound.path_heartbeat_sent(endpoint, destination, now);
                    }
                    self.count(|c| &mut c.path_heartbeats_sent);
                    if let Some(next) = submitted.checked_add(1) {
                        submitted = next;
                    }
                }
            }
        }
        submitted
    }

    fn send<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
    ) -> Sent {
        self.send_with(halves, endpoint, destination, control, Mode::Now, None)
    }

    /// Requests a SESSION_ABORT of the authenticated publication `alias` on
    /// `endpoint`, signed by its abort authority and sent to each of its
    /// bound receivers at the next duty (ADR-0086 domain 3; design
    /// section 5). Returns whether it was taken: only for a publication
    /// with an abort authority, and `reason` and `guard_epoch` at least 1.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no authenticated channel opens yet")
    )]
    pub(crate) fn request_abort(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        reason: u16,
        guard_epoch: u64,
    ) -> bool {
        let can = self
            .publication_auth_index(endpoint, alias)
            .and_then(|index| self.publication_auth.get(index))
            .is_some_and(|auth| auth.abort.is_some());
        if !can || reason == 0 || guard_epoch == 0 || self.aborts.len() >= self.aborts.capacity() {
            return false;
        }
        self.aborts.push(RequestedAbort {
            endpoint,
            alias,
            reason,
            guard_epoch,
        });
        true
    }

    /// Signs and sends the requested SESSION_ABORTs.
    fn send_aborts<O: SocketOps>(&mut self, halves: &mut [(EndpointId, Half<O>)]) {
        use karyos_protocol::network::authenticated::SessionAbort;

        while let Some(request) = self.aborts.pop() {
            let Some(identity) = self.sessions.identity(request.endpoint, request.alias) else {
                continue;
            };
            let Some(index) = self.publication_auth_index(request.endpoint, request.alias) else {
                continue;
            };
            for at in 0..self.bindings.len() {
                let Some(binding) = self.bindings.get(at) else {
                    break;
                };
                if binding.endpoint != request.endpoint || binding.alias != request.alias {
                    continue;
                }
                let destination = binding.source();
                let mut bytes = [0u8; karyos_protocol::network::MAX_CONTROL_LENGTH
                    + crate::wire_auth::ENVELOPE_LEN];
                let signed = self
                    .publication_auth
                    .get_mut(index)
                    .and_then(|auth| auth.abort.as_mut())
                    .and_then(|authority| {
                        let abort = SessionAbort {
                            alias: request.alias,
                            identity,
                            authority_id: authority.authority_id,
                            guard_id: 0,
                            guard_epoch: request.guard_epoch,
                            reason: request.reason,
                        };
                        authority.sign(&abort, &mut bytes)
                    });
                let Some(length) = signed else {
                    self.count(|c| &mut c.seal_failures);
                    continue;
                };
                let Some(sealed) = bytes.get(..length) else {
                    continue;
                };
                if self
                    .send_raw(halves, request.endpoint, destination, sealed)
                    .submitted()
                {
                    self.count(|c| &mut c.aborts_sent);
                }
                #[cfg(test)]
                {
                    self.last_abort = SealedBytes::copy(sealed)
                        .map(|bytes| (request.endpoint, destination, bytes));
                }
            }
        }
    }

    /// Sends prepared datagram bytes (a sealed or signed control) on
    /// `endpoint` to `destination`, now or not at all.
    fn send_raw<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        bytes: &[u8],
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
            self.count(|c| &mut c.no_endpoint);
            return Sent::NotSubmitted;
        };
        slot.endpoint = Some(endpoint);
        match slot.routes.send_raw(tx, destination, bytes) {
            Ok(()) => {
                self.count(|c| &mut c.raw_sent);
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

    /// The index of the authenticated publication `alias` on `endpoint`.
    fn publication_auth_index(&self, endpoint: EndpointId, alias: Alias) -> Option<usize> {
        self.publication_auth
            .iter()
            .position(|auth| auth.endpoint == endpoint && auth.alias == alias)
    }

    /// Verifies an envelope for a local authenticated publication under
    /// its keys and returns its control; `None` when refused (counted by
    /// reason), with nothing else changed.
    fn open_sealed(
        &mut self,
        endpoint: EndpointId,
        bytes: &[u8],
    ) -> Option<(Control, Option<Establishing>)> {
        let alias = receive_auth::envelope_alias(bytes);
        let index = alias.and_then(|alias| self.publication_auth_index(endpoint, alias));
        let (Some(alias), Some(index)) = (alias, index) else {
            self.count(|c| &mut c.auth_unbound);
            return None;
        };
        let identity = self.sessions.identity(endpoint, alias);
        let lane_count = self
            .publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            .and_then(|outbound| u8::try_from(outbound.readers().len()).ok());
        let (Some(identity), Some(lane_count)) = (identity, lane_count) else {
            self.count(|c| &mut c.auth_unbound);
            return None;
        };
        let opened = self
            .publication_auth
            .get_mut(index)
            .map(|auth| auth.open(bytes, identity, lane_count));
        match opened {
            Some(Ok(publish_auth::Opened::RspSetup(control, establishing))) => {
                Some((control, Some(establishing)))
            }
            Some(Ok(publish_auth::Opened::Receiver(control))) => Some((control, None)),
            Some(Ok(publish_auth::Opened::AbortAck(ack))) => {
                self.count(|c| &mut c.abort_acks);
                #[cfg(test)]
                {
                    self.last_abort_ack = Some(ack);
                }
                let _ = ack;
                None
            }
            Some(Err(reason)) => {
                if reason == AuthReason::OtherReceiver {
                    self.count(|c| &mut c.auth_other_receiver);
                }
                self.count(|c| &mut c.auth_rejected);
                None
            }
            None => {
                self.count(|c| &mut c.auth_rejected);
                None
            }
        }
    }

    /// Installs the session sealer of a verified establishment on the
    /// publication `answer` names: a new binding's, or the bound one's if
    /// none is installed yet. The bound establishment's own sealer is
    /// never replaced, so its envelope sequence is kept.
    fn establish(&mut self, endpoint: EndpointId, answer: &Control, establishing: Establishing) {
        let Control::SetupAnswer(answer) = answer else {
            return;
        };
        let Some(index) = self.publication_auth_index(endpoint, answer.alias) else {
            return;
        };
        let sealer = self
            .publication_auth
            .get(index)
            .and_then(|auth| auth.sealer(establishing.party).ok());
        let Some(sealer) = sealer else {
            return;
        };
        let installed = self
            .publications
            .iter_mut()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == answer.alias)
            .is_some_and(|outbound| outbound.install_sealer(sealer).is_ok());
        if installed {
            self.count(|c| &mut c.auth_sealers_installed);
        }
    }

    /// Sends a SETUP ANNOUNCE or ANSWER of the authenticated publication at
    /// `index`, sealed under its SETUP proof (domain 5), now or not at all.
    fn send_setup<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
        index: usize,
    ) -> Sent {
        // Moved out and back: allocates nothing.
        let mut auths = std::mem::take(&mut self.publication_auth);
        let sent = match auths.get_mut(index) {
            Some(auth) => self.send_with(
                halves,
                endpoint,
                destination,
                control,
                Mode::Now,
                Some(&mut auth.setup),
            ),
            None => Sent::NotSubmitted,
        };
        self.publication_auth = auths;
        sent
    }

    /// Sends a sender control of a publication (PATH_HB, ERR, RTTM REPLY):
    /// for an authenticated one sealed in domain 1 by its session sealer,
    /// or not at all while it has none; bare otherwise.
    fn send_sender_control<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
    ) -> Sent {
        let alias = match control {
            Control::PathHeartbeat(heartbeat) => Some(heartbeat.alias),
            Control::NakReply(reply) => Some(reply.alias),
            Control::Rttm(rttm) => Some(rttm.alias),
            _ => None,
        };
        let Some(alias) =
            alias.filter(|alias| self.publication_auth_index(endpoint, *alias).is_some())
        else {
            return self.send(halves, endpoint, destination, control);
        };
        let index = self
            .publications
            .iter()
            .position(|outbound| outbound.serves(endpoint) && outbound.alias() == alias);
        let sealer = index
            .and_then(|index| self.publications.get_mut(index))
            .and_then(|outbound| outbound.lend_sealer());
        let (Some(index), Some(mut sealer)) = (index, sealer) else {
            self.count(|c| &mut c.seal_failures);
            return Sent::NotSubmitted;
        };
        let sent = self.send_with(
            halves,
            endpoint,
            destination,
            control,
            Mode::Now,
            Some(&mut *sealer),
        );
        if let Some(outbound) = self.publications.get_mut(index) {
            outbound.return_sealer(sealer);
        }
        sent
    }

    /// [`SenderRole::send`] of a receiver's control: sealed under `seal`
    /// for an authenticated image, never bare; bare on a trusted channel.
    fn send_item<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
        seal: Option<SharedSealer>,
    ) -> Sent {
        match seal {
            None => self.send(halves, endpoint, destination, control),
            Some(mut seal) => self.send_with(
                halves,
                endpoint,
                destination,
                control,
                Mode::Now,
                Some(&mut seal),
            ),
        }
    }

    /// [`SenderRole::send`] of a reply to a REGISTER or a registrant's
    /// first SM, on a transient control route (karyos#977).
    fn send_reply<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
    ) -> Sent {
        self.send_with(halves, endpoint, destination, control, Mode::Reply, None)
    }

    /// [`SenderRole::send`] of a control that must reach its destination
    /// (an ANNOUNCE): refused while every cached route of the endpoint is
    /// closing, it waits in order and goes at the next send or duty (#838).
    fn send_or_wait<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
    ) -> Sent {
        self.send_with(halves, endpoint, destination, control, Mode::Wait, None)
    }

    fn send_with<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
        mode: Mode,
        seal: Option<&mut dyn ControlSeal>,
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
        let sealed = seal.is_some();
        let result = match (mode, seal) {
            (Mode::Now, Some(seal)) => slot
                .routes
                .send_sealed(tx, destination, control, seal)
                .map(|()| true),
            // Only a control sent now is ever sealed: anything else with a
            // seal is refused rather than sent bare.
            (_, Some(_)) => Err(ControlSendError::Encode),
            (Mode::Wait, None) => slot.routes.send_or_wait(tx, destination, control),
            (Mode::Now, None) => slot.routes.send(tx, destination, control).map(|()| true),
            (Mode::Reply, None) => slot
                .routes
                .send_reply(tx, destination, control)
                .map(|()| true),
        };
        match result {
            Ok(false) => {
                self.count(|c| &mut c.controls_waiting);
                Sent::NotSubmitted
            }
            Ok(true) => {
                self.count(|c| &mut c.sent);
                Sent::Submitted
            }
            Err(ControlSendError::Uncertain) => {
                self.count(|c| &mut c.send_failures);
                Sent::Uncertain
            }
            // Every cached route closing: an ANNOUNCE waited above; any
            // other control is dropped and counted by kind (#849): SMs and
            // NAKs are sent again periodically, a SETUP answer is solicited
            // again by its peer.
            Err(ControlSendError::Blocked) => {
                self.count(|c| &mut c.send_failures);
                match control {
                    Control::Status(_) => self.count(|c| &mut c.blocked_status),
                    Control::Nak(_) => self.count(|c| &mut c.blocked_naks),
                    Control::SetupAnswer(_) => self.count(|c| &mut c.blocked_setup_answers),
                    // Only past the waiting room's bound, which the
                    // per-key replacement keeps from being reached.
                    Control::SetupAnnounce(_) => self.count(|c| &mut c.blocked_announces),
                    _ => self.count(|c| &mut c.blocked_other),
                }
                Sent::NotSubmitted
            }
            Err(error) => {
                if sealed && error == ControlSendError::Encode {
                    self.count(|c| &mut c.seal_failures);
                }
                self.count(|c| &mut c.send_failures);
                Sent::NotSubmitted
            }
        }
    }

    /// Whether the publication `alias` on `endpoint` is a multi-destination
    /// one; `None` when there is no such publication.
    fn destinations_of(&self, endpoint: EndpointId, alias: Alias) -> Option<bool> {
        self.publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            .map(|outbound| outbound.destinations().is_some())
    }

    /// Whether the publication `alias` on `endpoint` sends to `address`.
    fn sends_to(&self, endpoint: EndpointId, alias: Alias, address: SocketAddr) -> bool {
        self.publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            .is_some_and(|outbound| outbound.sends_to(address))
    }

    /// The publication's channel destination and join points.
    fn route_of(&self, endpoint: EndpointId, alias: Alias) -> Option<(SocketAddr, Lanes<u64>)> {
        // A removing publication announces nothing and admits no new
        // receiver (driver-network-agents.md §7).
        let outbound = self.publications.iter().find(|outbound| {
            outbound.serves(endpoint) && outbound.alias() == alias && !outbound.removing()
        })?;
        Some((outbound.destination_on(endpoint)?, outbound.joins()?))
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
        let mut unrecorded = 0u64;
        for outbound in &mut self.publications {
            unrecorded = unrecorded.saturating_add(outbound.drain_retired(&mut self.closing));
        }
        for _ in 0..unrecorded {
            self.count(|c| &mut c.removed_unrecorded);
        }
        self.close_removed(halves, now);
        self.send_aborts(halves);
        self.naks_this_cycle = 0;
        // Bindings past their lifetime go even when nothing arrives.
        self.expire_bindings(now);
        let mut work = 0u32;
        for _ in 0..self.budget {
            let Ok(Some(item)) = self.from_receiver.try_take() else {
                break;
            };
            work = work.checked_add(1).ok_or(overflow.clone())?;
            // An authenticated publication's receiver controls are verified
            // under its keys before anything decodes them; a bare one is
            // dropped (ADR-0086 section 2).
            // A verified RSP_SETUP's establishment travels with its own
            // item, never in a field a later item could find.
            let (item, establishing) = match item {
                ControlItem::Sealed {
                    endpoint,
                    source,
                    bytes,
                    seen,
                } => match self.open_sealed(endpoint, bytes.get()) {
                    Some((control, establishing)) => (
                        ControlItem::Incoming {
                            endpoint,
                            source,
                            control,
                            seen,
                        },
                        establishing,
                    ),
                    None => continue,
                },
                ControlItem::Incoming {
                    endpoint,
                    ref control,
                    ..
                } if receiver_control_alias(control).is_some_and(|alias| {
                    self.publication_auth_index(endpoint, alias).is_some()
                }) =>
                {
                    self.count(|c| &mut c.auth_bare);
                    continue;
                }
                other => (other, None),
            };
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
                    seal,
                } => {
                    let mut guard = guard;
                    guard.sending((self.clock)());
                    match self.send_item(halves, endpoint, destination, &control, seal) {
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
                    seal,
                } => {
                    let sent = self.send_item(halves, endpoint, destination, &control, seal);
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
                } => {
                    // A registrant's first SM finding the slots taken is
                    // answered with one ERR REGISTRATION (design 3.2).
                    // Its send failure is counted as the REGISTER's ERR is
                    // (design 11.2, karyos#977).
                    if let Some((destination, reply)) = self.status(endpoint, source, &status, now)
                        && !self
                            .send_reply(halves, endpoint, destination, &reply)
                            .submitted()
                    {
                        self.count(|c| &mut c.registration_replies_unsent);
                    }
                }
                ControlItem::Incoming {
                    endpoint,
                    source,
                    control: Control::Register(register),
                    ..
                } => {
                    if let Some((destination, reply)) =
                        self.register(endpoint, source, &register, now)
                        && !self
                            .send_reply(halves, endpoint, destination, &reply)
                            .submitted()
                    {
                        self.count(|c| &mut c.registration_replies_unsent);
                    }
                }
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
                            .send_sender_control(halves, endpoint, source, &Control::Rttm(reply))
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
                    let authenticated = receiver_control_alias(&control)
                        .and_then(|alias| self.publication_auth_index(endpoint, alias));
                    // An authenticated publication answers only a verified
                    // RSP_SETUP (fail closed).
                    if authenticated.is_some() && establishing.is_none() {
                        self.count(|c| &mut c.auth_bare);
                        continue;
                    }
                    if let Some((destination, answer)) =
                        self.answer_for(endpoint, source, now, control)
                    {
                        match (authenticated, establishing) {
                            (Some(index), Some(establishing)) => {
                                self.establish(endpoint, &answer, establishing);
                                let _ =
                                    self.send_setup(halves, endpoint, destination, &answer, index);
                            }
                            _ => {
                                let _ = self.send(halves, endpoint, destination, &answer);
                            }
                        }
                    }
                }
                // Turned into `Incoming` or dropped above.
                ControlItem::Sealed { .. } => {}
                ControlItem::Raw {
                    endpoint,
                    destination,
                    bytes,
                } => {
                    let _ = self.send_raw(halves, endpoint, destination, bytes.get());
                }
            }
        }
        // A publication with no live receiver (no live member and no
        // confirmed binding) announces again (ACS 15933), and is not
        // connected: its readers' cells stop counting for the connection
        // (SPEC.md §4) until a receiver's SMs are live again.
        let mut changes = 0u64;
        for outbound in &mut self.publications {
            let alias = outbound.alias();
            // A confirmed binding on any of its paths keeps it live.
            let bound = self.bindings.iter().any(|binding| {
                outbound.serves(binding.endpoint)
                    && binding.alias == alias
                    && binding.last_sm.is_some()
            });
            let live = bound || outbound.connected(now);
            if outbound.set_receivers_live(live)
                && let Some(next) = changes.checked_add(1)
            {
                changes = next;
            }
            if !live {
                for path in outbound.route_endpoints() {
                    let _ = self.sessions.disconnected(path, alias);
                }
            }
            // A multi-destination publication keeps announcing while one of
            // its destinations has no live member.
            // A dynamic publication is never announced on the cadence, a
            // dead required slot included (design 9.2, 11.2; karyos#977).
            let silent = outbound.is_dynamic();
            for path in outbound.route_endpoints() {
                self.sessions
                    .set_announcing(path, alias, outbound.announces_destinations());
                self.sessions.set_silent(path, alias, silent);
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
                // A multi-destination publication announces to each of its
                // destinations that has no live member yet (design 3.6).
                let targets = self
                    .publications
                    .iter()
                    .find(|outbound| {
                        outbound.serves(endpoint) && outbound.alias() == announce.alias
                    })
                    .filter(|outbound| outbound.destinations().is_some())
                    .map(|outbound| {
                        let mut targets = [None; super::data::MAX_MAX_DESTINATIONS];
                        for (slot, address) in
                            targets.iter_mut().zip(outbound.destinations_not_live())
                        {
                            *slot = Some(address);
                        }
                        targets
                    });
                match targets {
                    Some(targets) => {
                        for address in targets.into_iter().flatten() {
                            work = work.checked_add(1).ok_or(overflow.clone())?;
                            let _ = self.send_or_wait(
                                halves,
                                endpoint,
                                address,
                                &Control::SetupAnnounce(announce),
                            );
                        }
                    }
                    None => {
                        work = work.checked_add(1).ok_or(overflow.clone())?;
                        // An authenticated publication's ANNOUNCE goes
                        // sealed now (domain 5) or not at all: the waiting
                        // room would send it bare. It is announced again.
                        match self.publication_auth_index(endpoint, announce.alias) {
                            Some(index) => {
                                let _ = self.send_setup(
                                    halves,
                                    endpoint,
                                    destination,
                                    &Control::SetupAnnounce(announce),
                                    index,
                                );
                            }
                            None => {
                                let _ = self.send_or_wait(
                                    halves,
                                    endpoint,
                                    destination,
                                    &Control::SetupAnnounce(announce),
                                );
                            }
                        }
                    }
                }
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
            let endpoint = outbound.endpoint();
            if !established(&self.sessions, outbound) {
                // Not served yet, but a guard close still applies (the
                // close acknowledgement waits for it).
                if let Some(outbound) = self.publications.get_mut(index) {
                    outbound.guard_tick(now);
                }
                continue;
            }
            let consumption = self.consumption(outbound);
            // A routed publication is served over every path's half
            // (redundant paths, RP-10).
            if let Some(outbound) = self.publications.get_mut(index)
                && outbound.is_routed()
            {
                let lanes = outbound.readers().len();
                let served = outbound.serve_routes(
                    halves,
                    DATA_BUDGET,
                    consumption
                        .as_ref()
                        .and_then(|positions| positions.get(..lanes)),
                    now,
                )?;
                work = work.checked_add(served).ok_or(overflow.clone())?;
                // An idle lane's heartbeat on every live path (SPEC §6,
                // karyos#834).
                let beats = outbound
                    .serve_routed_heartbeats(halves, now, self.sender_heartbeat_interval)
                    .ok_or(overflow.clone())?;
                work = work.checked_add(beats).ok_or(overflow.clone())?;
                let needs_reset = outbound.needs_reset();
                for _ in 0..beats {
                    self.count(|c| &mut c.heartbeats_sent);
                }
                if needs_reset {
                    needing_reset = needing_reset.checked_add(1).ok_or(overflow.clone())?;
                }
                continue;
            }
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
            // An idle lane's heartbeat (SPEC §6), after its first sends.
            let beats = outbound
                .serve_heartbeats(tx, now, self.sender_heartbeat_interval)
                .ok_or(overflow.clone())?;
            work = work.checked_add(beats).ok_or(overflow.clone())?;
            let needs_reset = outbound.needs_reset();
            for _ in 0..beats {
                self.count(|c| &mut c.heartbeats_sent);
            }
            if needs_reset {
                needing_reset = needing_reset.checked_add(1).ok_or(overflow.clone())?;
            }
        }
        self.counters.needs_reset = needing_reset;
        // An endpoint refused a route for its limit after a failed close:
        // its reset of the epoch.
        self.reset_limited();
        // Removing publications: each lane drained to its seal sends its
        // EOS, then the linger runs (driver-network-agents.md §7).
        work = work
            .checked_add(self.serve_removals(halves, now))
            .ok_or(overflow.clone())?;
        // A routed publication's paths still idle after the first sends keep
        // their bindings live at the receivers with a PATH_HB, a heartbeat
        // of the control budget (RP-3).
        work = work
            .checked_add(self.path_heartbeats(halves, now))
            .ok_or(overflow.clone())?;
        Ok(work)
    }

    /// The EOS frames and linger of every removing publication at `now`;
    /// returns the EOS frames submitted. One with no established receiver
    /// drains nothing and ends at once.
    fn serve_removals<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        now: u64,
    ) -> u32 {
        let mut sent = 0u32;
        for index in 0..self.publications.len() {
            let Some(outbound) = self.publications.get(index) else {
                break;
            };
            if !outbound.removing() {
                continue;
            }
            if !established(&self.sessions, outbound) {
                if self
                    .publications
                    .get_mut(index)
                    .is_some_and(|outbound| outbound.drain_now())
                {
                    self.count(|c| &mut c.removals_unestablished);
                }
                continue;
            }
            // A routed publication's EOS goes on every live path.
            let step = if outbound.is_routed() {
                let Some(outbound) = self.publications.get_mut(index) else {
                    continue;
                };
                outbound.serve_removal_routes(halves, now)
            } else {
                let endpoint = outbound.endpoint();
                // Without its TX half (an endpoint being reset) the drain bound
                // still runs: nothing waits for the half to come back.
                let tx = halves.iter_mut().find_map(|(held, half)| match half {
                    Half::Tx(tx) if *held == endpoint => Some(&mut **tx),
                    _ => None,
                });
                let Some(outbound) = self.publications.get_mut(index) else {
                    continue;
                };
                outbound.serve_removal(tx, now)
            };
            sent = sent.checked_add(step.sent).unwrap_or(sent);
            for _ in 0..step.sent {
                self.count(|c| &mut c.eos_sent);
            }
            if step.gave_up {
                self.count(|c| &mut c.removals_undrained);
            }
            if step.guard_closed {
                self.count(|c| &mut c.removals_guard_closed);
            }
        }
        sent
    }

    /// Asks for the reset of each endpoint a publication needs reset on,
    /// through `post` (which returns whether the request was posted): at
    /// most once per [`RESET_REQUEST_CYCLES`](super::data::RESET_REQUEST_CYCLES)
    /// per publication while the need holds. The cadence is per
    /// publication, so `N` publications on one endpoint post up to `N`
    /// requests per period; the endpoint table resets once and ignores the
    /// others while the reset is in flight. Nothing allocates.
    pub(super) fn request_resets(
        &mut self,
        mut post: impl FnMut(EndpointId, Option<karyos_io::backend::BackendEpoch>) -> bool,
    ) {
        let cycle = self.cycle;
        // An endpoint a failed close may hold at its limit: its one reset of
        // the epoch, a standing request the table keeps; asked again next
        // cycle only when the event ring was full.
        let (mut posted, mut refused) = (0u64, 0u64);
        for record in &mut self.close_failures {
            if record.reset != CloseReset::Due {
                continue;
            }
            if post(record.endpoint, Some(record.epoch)) {
                record.reset = CloseReset::Asked;
                posted = posted.saturating_add(1);
            } else {
                refused = refused.saturating_add(1);
            }
        }
        for _ in 0..posted {
            self.count(|c| &mut c.reset_requests);
        }
        for _ in 0..refused {
            self.count(|c| &mut c.reset_requests_full);
        }
        for index in 0..self.publications.len() {
            let Some(outbound) = self.publications.get_mut(index) else {
                break;
            };
            // Over redundant paths, each route's endpoint on its own.
            let (posted, refused) =
                outbound.post_reset_requests(cycle, &mut |endpoint| post(endpoint, None));
            for _ in 0..posted {
                self.count(|c| &mut c.reset_requests);
            }
            for _ in 0..refused {
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

    /// Drops the NAKs of receiver boot id `boot_id` unread, or none
    /// (tests).
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "used by the Linux multicast tests (T9)")
    )]
    pub(super) fn ignore_naks_of(&mut self, held: Option<([u64; 2], HeldRanges)>) {
        self.ignore_naks_of = held;
    }

    /// The held ranges and the NAKs answered while they were held (tests).
    #[cfg(test)]
    pub(crate) fn nak_debug(&self) -> String {
        let held = self.ignore_naks_of.as_ref().and_then(|(boot, held)| {
            held.lock()
                .ok()
                .map(|held| format!("{:x} {:?}", boot[0], *held))
        });
        format!("held {held:?} answered {:?}", self.nak_log)
    }

    /// The parts of `nak` to answer when [`SenderRole::ignore_naks_of`]
    /// holds part of it: the held receiver's NAK minus the first held range
    /// it overlaps; `None` for a NAK answered whole (tests).
    #[cfg(test)]
    fn held_nak_parts(&self, nak: &Nak) -> Option<[Option<Nak>; 2]> {
        let (boot_id, held) = self.ignore_naks_of.as_ref()?;
        if *boot_id != nak.receiver.receiver_boot_id {
            return None;
        }
        let start = nak.range.start;
        let end = start.saturating_add(u64::from(nak.range.length));
        let held = held.lock().ok()?;
        let &(at, length) = held
            .iter()
            .find(|&&(at, length)| at < end && start < at.saturating_add(length))?;
        let part = |from: u64, to: u64| {
            let length = u32::try_from(to.checked_sub(from)?)
                .ok()
                .filter(|l| *l > 0)?;
            let mut part = *nak;
            part.range.start = from;
            part.range.length = length;
            Some(part)
        };
        Some([part(start, at), part(at.saturating_add(length), end)])
    }

    /// Reads NAKs again after [`SenderRole::ignore_naks`] (tests).
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "used by the Linux multicast test (T9)")
    )]
    pub(super) fn heed_naks(&mut self) {
        self.ignore_naks = false;
    }

    /// Whether the publication `alias` on `endpoint` has an established
    /// send session: a removal sends its EOS only then (tests).
    #[cfg(test)]
    pub(crate) fn session_established(&self, endpoint: EndpointId, alias: Alias) -> bool {
        self.sessions.is_established(endpoint, alias)
    }

    /// The receivers bound to `alias` on `endpoint` whose SMs arrived
    /// (tests): a path's SMs reach the sender only when the receiver agent
    /// has the alias published on that path's endpoint.
    #[cfg(test)]
    pub(crate) fn confirmed_bindings(&self, endpoint: EndpointId, alias: Alias) -> usize {
        self.bindings
            .iter()
            .filter(|binding| {
                binding.endpoint == endpoint && binding.alias == alias && binding.last_sm.is_some()
            })
            .count()
    }

    /// [`Self::consumption`] of the publication `alias` on `endpoint`, any
    /// of its paths (tests).
    #[cfg(test)]
    fn consumption_at(&self, endpoint: EndpointId, alias: Alias) -> Option<[u64; 4]> {
        self.publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            .and_then(|outbound| self.consumption(outbound))
    }

    /// The least position every receiver bound to `outbound` on any of its
    /// paths consumed, per lane: a reliable channel's bound (SPEC §4). A
    /// receiver answered but not yet heard from bounds at its join points.
    /// `None` with no bound receiver at all: a reliable lane then holds.
    fn consumption(&self, outbound: &Outbound<T>) -> Option<[u64; 4]> {
        let mut least: Option<[u64; 4]> = None;
        // A receiver bound on any of its paths bounds it: one whose founding
        // path was lost still holds it at its consumption (#336 review).
        for binding in &self.bindings {
            if !outbound.serves(binding.endpoint) || binding.alias != outbound.alias() {
                continue;
            }
            // A destination a multi-destination publication removed bounds
            // nothing more (karyos#630).
            if !outbound.sends_to(binding.source()) {
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
    /// `endpoint` and its boot id. On a static publication its SMs then
    /// come from any source with that boot id and incarnation; the first
    /// sets the binding's SM source and the others adopt it
    /// ([`Self::status`]). On a dynamic publication its SM source is
    /// `source` alone and it adopts nothing (design 2.4, MD-16).
    ///
    /// A new answer to a known tuple starts it over: unconfirmed, with no
    /// receiver id or status, so a reinstalled image binds again; its SM
    /// source and its adoptions stay. A full table evicts its oldest
    /// unconfirmed binding first; one full of confirmed bindings refuses
    /// and counts.
    fn bind(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        answer: &SetupAnswer,
        registered: Option<Receiver>,
        now: u64,
    ) {
        self.expire_bindings(now);
        let tuple = |held: &ReceiverBinding| {
            (
                held.parent,
                held.endpoint,
                held.alias,
                held.solicited_from,
                held.boot_id,
                held.identity,
            )
        };
        let wanted = (
            None,
            endpoint,
            answer.alias,
            normalized(source),
            answer.challenge.receiver_boot_id,
            answer.identity,
        );
        if let Some(held) = self.bindings.iter_mut().find(|held| tuple(held) == wanted) {
            // The same receiver again: its consumption never moves back,
            // and the receiver id it had is remembered for the next SM.
            held.former = held.receiver_id.or(held.former);
            held.receiver_id = None;
            held.registered = registered;
            held.joins = answer.joins;
            held.answered_at = now;
            held.last_sm = None;
            // Its adoptions start over too: an image reinstalled at an
            // adopted source has a new receiver id, which its next SM
            // brings. Each keeps its SM source and its consumption.
            let parent = held.id;
            for adopted in self
                .bindings
                .iter_mut()
                .filter(|binding| binding.parent == Some(parent))
            {
                adopted.former = adopted.receiver_id.or(adopted.former);
                adopted.receiver_id = None;
            }
            return;
        }
        if !self.make_room(endpoint, answer.alias, registered, now) {
            return;
        }
        let id = self.next_binding;
        self.next_binding = id.wrapping_add(1);
        self.bindings.push(ReceiverBinding {
            id,
            parent: None,
            endpoint,
            alias: answer.alias,
            solicited_from: normalized(source),
            sm_source: None,
            boot_id: answer.challenge.receiver_boot_id,
            registered,
            identity: answer.identity,
            receiver_id: None,
            former: None,
            lanes: None,
            joins: answer.joins,
            answered_at: now,
            last_sm: None,
        });
    }

    /// Whether the table has room for one more binding, for the receiver
    /// `registered` of the publication `alias` on `endpoint`, keeping one
    /// free binding for each required receiver id of a dynamic publication
    /// that has not joined (karyos#941 item 2): a required id that has not
    /// joined uses its own. Without room, the oldest unconfirmed binding
    /// that holds no such required id is evicted, with its adoptions, and
    /// counted; without one, it refuses and counts `bindings_reserved`
    /// when the reservation decides, else `bindings_full`.
    fn make_room(
        &mut self,
        endpoint: EndpointId,
        alias: Alias,
        registered: Option<Receiver>,
        now: u64,
    ) -> bool {
        match self.room_for(endpoint, alias, registered) {
            Room::Free => true,
            Room::Evict(index) => {
                self.count(|c| &mut c.bindings_evicted);
                self.remove_binding(index, now, |c| &mut c.bindings_evicted);
                true
            }
            Room::Reserved => {
                self.count(|c| &mut c.bindings_reserved);
                false
            }
            Room::Full => {
                self.count(|c| &mut c.bindings_full);
                false
            }
        }
    }

    /// Whether a binding for `registered` of `alias` on `endpoint` would
    /// fit, as [`Self::make_room`] decides it, changing nothing.
    fn room_for(&self, endpoint: EndpointId, alias: Alias, registered: Option<Receiver>) -> Room {
        let own = registered
            .is_some_and(|receiver| self.unjoined_required(endpoint, alias, receiver.receiver_id));
        // The bindings kept for the others: a required id that has not
        // joined keeps one for itself, which this binding is when `own`.
        // `own` is set only for an id the count includes: saturating is
        // exact here and never floors a real count.
        let reserved = self
            .unjoined_required_count()
            .saturating_sub(usize::from(own));
        let held = self.bindings.len().checked_add(reserved);
        if held.is_some_and(|held| held < self.max_bindings) {
            return Room::Free;
        }
        // An eviction keeps the count: it makes room only when the table
        // is exactly full with the reservation kept, never out of a
        // reserved binding.
        let kept = held == Some(self.max_bindings);
        let oldest = self
            .bindings
            .iter()
            .enumerate()
            .filter(|(_, held)| held.last_sm.is_none() && !self.holds_required_registration(held))
            .min_by_key(|(_, held)| held.answered_at)
            .map(|(index, _)| index);
        match oldest {
            Some(index) if kept => Room::Evict(index),
            _ if self.bindings.len() < self.max_bindings => Room::Reserved,
            _ => Room::Full,
        }
    }

    /// Whether `receiver_id` is a required receiver id of the dynamic
    /// publication `alias` on `endpoint` that has not joined: it holds no
    /// required slot and no binding of that publication names it
    /// (karyos#941 item 2).
    fn unjoined_required(&self, endpoint: EndpointId, alias: Alias, receiver_id: u64) -> bool {
        self.publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            .is_some_and(|outbound| {
                outbound
                    .registration()
                    .is_some_and(|policy| policy.is_required(receiver_id))
                    && !outbound.holds_required(receiver_id)
                    && !self.bindings.iter().any(|held| {
                        outbound.serves(held.endpoint)
                            && held.alias == alias
                            && names(held, receiver_id)
                    })
            })
    }

    /// The required receiver ids of every dynamic publication that have
    /// not joined ([`Self::unjoined_required`]): one free binding is kept
    /// for each (karyos#941 item 2). Bounded by the publications and their
    /// required ids, at most `max_destinations` each.
    fn unjoined_required_count(&self) -> usize {
        self.publications
            .iter()
            .filter_map(|outbound| Some((outbound, outbound.registration()?)))
            .map(|(outbound, policy)| {
                policy
                    .required()
                    .iter()
                    .filter(|&&receiver_id| {
                        !outbound.holds_required(receiver_id)
                            && !self.bindings.iter().any(|held| {
                                outbound.serves(held.endpoint)
                                    && held.alias == outbound.alias()
                                    && names(held, receiver_id)
                            })
                    })
                    .count()
            })
            // At most the publications times `max_destinations`, far below
            // `usize::MAX`: saturating never applies, and a bound past it
            // would only keep more bindings free.
            .fold(0usize, usize::saturating_add)
    }

    /// Whether `binding` was answered for a REGISTER naming a required
    /// receiver id of its dynamic publication: no eviction takes it, and
    /// it is renamed to another receiver only with room for that id
    /// (karyos#941 item 2), which would otherwise hand on the binding
    /// kept for it.
    fn holds_required_registration(&self, binding: &ReceiverBinding) -> bool {
        let Some(receiver) = binding.registered else {
            return false;
        };
        self.publications
            .iter()
            .find(|outbound| outbound.serves(binding.endpoint) && outbound.alias() == binding.alias)
            .and_then(|outbound| outbound.registration())
            .is_some_and(|policy| policy.is_required(receiver.receiver_id))
    }

    /// Removes the binding at `index` and, for one an ANSWER created, its
    /// adoptions, each counted with `field`: an adoption never outlives
    /// the binding it was adopted for (plan 169). Each one's membership
    /// ends with it (ACS 15648).
    fn remove_binding(
        &mut self,
        index: usize,
        now: u64,
        field: fn(&mut SenderCounters) -> &mut u64,
    ) {
        if index >= self.bindings.len() {
            return;
        }
        let removed = self.bindings.swap_remove(index);
        // A reset row keeps its former receiver id until its next SM: that
        // membership ends with the row (ACS 15648).
        if let Some(receiver_id) = removed.receiver_id.or(removed.former) {
            self.binding_gone(&removed, receiver_id, now);
        }
        if removed.parent.is_some() {
            return;
        }
        while let Some(child) = self
            .bindings
            .iter()
            .position(|held| held.parent == Some(removed.id))
        {
            self.count(field);
            let child = self.bindings.swap_remove(child);
            if let Some(receiver_id) = child.receiver_id.or(child.former) {
                self.binding_gone(&child, receiver_id, now);
            }
        }
        self.retire_uncovered_registrants(removed.endpoint, removed.alias, now);
    }

    /// Removes the bindings past their lifetime at `now`: an unconfirmed
    /// one after `setup_challenge_timeout`, a confirmed one with no SM for
    /// `image_liveness_timeout` (its image is retired by then), each with
    /// its adoptions.
    fn expire_bindings(&mut self, now: u64) {
        let (unconfirmed, confirmed) = (self.unconfirmed_timeout, self.confirmed_timeout);
        let expired = |binding: &ReceiverBinding| match binding.last_sm {
            None => age_ns(now, binding.answered_at) >= unconfirmed,
            Some(last) => age_ns(now, last) >= confirmed,
        };
        while let Some(index) = self.bindings.iter().position(expired) {
            self.count(|c| &mut c.bindings_expired);
            self.remove_binding(index, now, |c| &mut c.bindings_expired);
        }
    }

    /// Frees each optional registrant slot of the dynamic publication of
    /// `alias` on `endpoint` that no binding covers any more, as a
    /// timeout (design 3.7, 8): run by [`Self::remove_binding`], the one
    /// place a binding goes, so the slot goes in the same step.
    ///
    /// The invariant it keeps: every optional registrant slot of a dynamic
    /// publication has a binding whose source ([`ReceiverBinding::source`])
    /// is the slot's address, and that binding expires with no SM
    /// ([`Self::expire_bindings`]). It holds because a slot is taken only
    /// through the binding at its address (`settle_registrant`), a
    /// dynamic binding's source never changes (it learns its SM source
    /// only where it was answered and adopts nothing), and every removal
    /// path (expiry, `make_room` eviction, a refused or full join, a
    /// restart or move, a child with its parent) runs through
    /// [`Self::remove_binding`]. Removing a publication drops its slots
    /// with its bindings. Static publications hold no registrant slot,
    /// so this changes nothing for them.
    fn retire_uncovered_registrants(&mut self, endpoint: EndpointId, alias: Alias, now: u64) {
        loop {
            let bindings = &self.bindings;
            let Some(outbound) = self
                .publications
                .iter_mut()
                .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            else {
                return;
            };
            let uncovered = outbound.uncovered_registrant(|address| {
                bindings.iter().any(|binding| {
                    outbound.serves(binding.endpoint)
                        && binding.alias == alias
                        && binding.source() == address
                })
            });
            let Some(address) = uncovered else {
                return;
            };
            if !outbound.retire_registrant(
                address,
                crate::agents::data::RemovalReason::Timeout,
                now,
            ) {
                return;
            }
            self.count(|c| &mut c.registrants_timed_out);
        }
    }

    /// Tells `binding`'s publication that the binding of receiver
    /// `receiver_id` is gone (ACS 15648): its membership ends with its last
    /// binding.
    fn binding_gone(&mut self, binding: &ReceiverBinding, receiver_id: u64, now: u64) {
        let key = SmKey {
            endpoint: binding.endpoint,
            alias: binding.alias,
            source: binding.source(),
            identity: binding.identity,
            receiver: Receiver {
                receiver_boot_id: binding.boot_id,
                receiver_id,
            },
        };
        if let Some(membership) = self
            .publications
            .iter_mut()
            .find(|outbound| outbound.serves(key.endpoint) && outbound.alias() == key.alias)
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
                && binding.source() == normal
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
        // The held receiver's NAK is answered without the held bytes: the
        // parts before and after them, each as its own NAK (karyos#1067).
        #[cfg(test)]
        if let Some(parts) = self.held_nak_parts(nak) {
            for part in parts.into_iter().flatten() {
                self.nak(halves, endpoint, source, &part, now);
            }
            return;
        }
        #[cfg(test)]
        if self.ignore_naks_of.is_some() && self.nak_log.len() < 64 {
            self.nak_log.push(format!(
                "boot {:x} start {} len {}",
                nak.receiver.receiver_boot_id[0], nak.range.start, nak.range.length
            ));
        }
        // RP-11's order: the binding, then the absorption of copies, then
        // the cycle's NAK budget, so an absorbed copy spends none.
        self.expire_bindings(now);
        let normal = normalized(source);
        let bound = self.bindings.iter().any(|binding| {
            binding.endpoint == endpoint
                && binding.alias == nak.alias
                && binding.source() == normal
                && binding.boot_id == nak.receiver.receiver_boot_id
                && binding.identity == nak.identity
                && binding
                    .receiver_id
                    .is_none_or(|id| id == nak.receiver.receiver_id)
        });
        let index = self.publications.iter().position(|outbound| {
            outbound.serves(endpoint) && outbound.alias() == nak.alias && outbound.repairs()
        });
        let (true, Some(index)) = (bound, index) else {
            self.count(|c| &mut c.nak_unbound);
            return;
        };
        // Absorption keys on the receiver id, so only one the binding has
        // validated takes part: a copy that fails validation never absorbs
        // a real NAK (RP-11).
        let validated = self.bindings.iter().any(|binding| {
            binding.endpoint == endpoint
                && binding.alias == nak.alias
                && binding.source() == normal
                && binding.boot_id == nak.receiver.receiver_boot_id
                && binding.identity == nak.identity
                && binding.receiver_id == Some(nak.receiver.receiver_id)
        });
        let Some(outbound) = self.publications.get_mut(index) else {
            return;
        };
        let route = outbound.route_of(endpoint);
        if validated && outbound.absorbs(nak, route, now) {
            self.count(|c| &mut c.nak_copies_absorbed);
            return;
        }
        if self.naks_this_cycle >= self.repair.naks_per_cycle {
            self.count(|c| &mut c.nak_cycle_budget);
            return;
        }
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
        let intake = outbound.nak_at(normal, nak, requester, (route, validated), now);
        if let NakIntake::Reply(reply) = intake
            && self
                .send_sender_control(halves, endpoint, source, &Control::NakReply(reply))
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
            let endpoint = outbound.endpoint();
            if !outbound.repairs() || !established(&self.sessions, outbound) {
                continue;
            }
            let routed = outbound.is_routed();
            let served = if routed {
                // Every live route carries every repair (RP-11).
                let Some(outbound) = self.publications.get_mut(index) else {
                    continue;
                };
                outbound.serve_repair_routes(halves, &mut budget, now)
            } else {
                let tx = halves.iter_mut().find_map(|(held, half)| match half {
                    Half::Tx(tx) if *held == endpoint => Some(tx),
                    _ => None,
                });
                let (Some(tx), Some(outbound)) = (tx, self.publications.get_mut(index)) else {
                    continue;
                };
                outbound.serve_repair(tx, &mut budget, now)
            };
            let Some(outbound) = self.publications.get_mut(index) else {
                continue;
            };
            let Some(total) = submitted.checked_add(served) else {
                // The list goes back before the error: it is never
                // allocated again.
                self.nak_replies = replies;
                return Err(AgentError::CountOverflow(AgentKind::Sender));
            };
            submitted = total;
            let capacity = replies.capacity();
            let mut dropped: Option<u64> = Some(0);
            outbound.drain_repair_replies_on(|reply, endpoint| {
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
            .map(ReceiverBinding::source);
        match destination {
            Some(destination) => {
                if self
                    .send_sender_control(halves, endpoint, destination, &Control::NakReply(*reply))
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
    ) -> Option<(SocketAddr, Control)> {
        self.expire_bindings(now);
        let source = normalized(source);
        let publication = self
            .publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == status.alias);
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
            return None;
        }
        // A removed destination's SMs are ignored: it rejoins nothing
        // (karyos#630). A dynamic publication's registrant is no
        // destination until its first valid SM takes a slot (design 3.2).
        let stranger = publication.is_some_and(|outbound| !outbound.sends_to(source));
        let dynamic = publication.is_some_and(|outbound| outbound.registration().is_some());
        if stranger && !dynamic {
            self.count(|c| &mut c.sm_unbound);
            return None;
        }
        // The incarnation is part of the binding: an earlier incarnation's
        // row from the same receiver never shadows the current one.
        let found = self.sm_binding(endpoint, source, status)?;
        // The SM is checked against its binding (an adoption has no
        // receiver id yet) before it sets a source or adopts anything.
        let receiver_id = match found {
            SmBinding::Bound(index) | SmBinding::Learn(index) => self
                .bindings
                .get(index)
                .and_then(|binding| binding.receiver_id),
            SmBinding::Adopt(_) => None,
        };
        let matches = lane_count == Some(status.lanes.count())
            && receiver_id.is_none_or(|id| id == status.receiver.receiver_id);
        if !matches {
            self.count(|c| &mut c.sm_mismatch);
            return None;
        }
        // Only the registrant this sender answered, at the source it
        // registered from, with no SM since its last ANSWER: a stranger
        // anything else is unbound. A binding answered again at its own
        // SM source is one too, so its next SM cannot rename the slot it
        // holds (karyos#940).
        let registrant = match found {
            SmBinding::Learn(index) | SmBinding::Bound(index) if dynamic => self
                .bindings
                .get(index)
                .filter(|binding| {
                    binding.parent.is_none()
                        && binding.solicited_from == source
                        && binding.receiver_id.is_none()
                })
                .map(|_| index),
            _ => None,
        };
        if stranger && registrant.is_none() {
            self.count(|c| &mut c.sm_unbound);
            return None;
        }
        // On a dynamic publication a binding learns its SM source only
        // from the source it was answered at, and adopts none: a
        // destination has one binding, whose source is its endpoint
        // (design 2.4, MD-16). An SM from another source, such as another
        // slot of the same host, would name a receiver id past
        // `settle_registrant`, and an adoption would share a slot's address
        // with a binding that can go without it (karyos#945 review).
        // Static publications adopt as before.
        let elsewhere = match found {
            SmBinding::Learn(index) => self
                .bindings
                .get(index)
                .is_some_and(|binding| binding.solicited_from != source),
            SmBinding::Adopt(_) => true,
            SmBinding::Bound(_) => false,
        };
        if dynamic && elsewhere {
            self.count(|c| &mut c.sm_unbound);
            return None;
        }
        // A dynamic publication's new membership settles what it replaces
        // (design 3.2 step 4); the bindings may move, so it is found again.
        let found = match registrant {
            Some(index) => {
                if let Some(refusal) =
                    self.settle_registrant(endpoint, source, status, index, stranger, now)
                {
                    return refusal;
                }
                self.sm_binding(endpoint, source, status)?
            }
            None => found,
        };
        let index = match found {
            SmBinding::Bound(index) => index,
            SmBinding::Learn(index) => {
                if let Some(binding) = self.bindings.get_mut(index) {
                    binding.sm_source = Some(source);
                }
                index
            }
            SmBinding::Adopt(parent) => self.adopt(parent, source, now)?,
        };
        let binding = self.bindings.get_mut(index)?;
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
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == status.alias)
            .and_then(|outbound| outbound.membership_mut())
        {
            let _ = membership.status(&key, status, now);
        }
        None
    }

    /// The first valid SM of the registrant answered through the binding at
    /// `index` (design 3.2): it takes a destination slot of its
    /// publication, a required receiver id its reserved one (MD-17), an
    /// optional one a slot of the optional quota. `None` when it joined;
    /// otherwise its binding is dropped and the outcome holds what to
    /// answer: one ERR REGISTRATION `DESTINATIONS_FULL` to `source` when
    /// the optional slots filled meanwhile, nothing for any other refusal.
    #[allow(
        clippy::option_option,
        reason = "joined, refused with a reply, or refused without one"
    )]
    fn join_registrant(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        status: &StatusMessage,
        index: usize,
        required: bool,
        now: u64,
    ) -> Option<Option<(SocketAddr, Control)>> {
        use crate::agents::data::DestinationChange;
        use karyos_protocol::network::{Registration, RegistrationReason};

        let quarantine = self.membership.receiver_timeout;
        let outcome = self
            .publications
            .iter_mut()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == status.alias)
            .map_or(DestinationChange::Unknown, |outbound| {
                outbound.join_registrant(
                    source,
                    (status.receiver.receiver_id, required),
                    now,
                    quarantine,
                )
            });
        match outcome {
            DestinationChange::Added => {
                self.count(|c| &mut c.registrants_joined);
                None
            }
            DestinationChange::Full => {
                self.count(|c| &mut c.registrants_full);
                self.remove_binding(index, now, |c| &mut c.registrants_full);
                Some(Some((
                    source,
                    Control::Registration(Registration {
                        stream_id: status.alias.stream_id,
                        reason: RegistrationReason::DestinationsFull,
                    }),
                )))
            }
            _ => {
                self.count(|c| &mut c.registrants_refused);
                self.remove_binding(index, now, |c| &mut c.registrants_refused);
                Some(None)
            }
        }
    }

    /// What a REGISTER from `source` on `endpoint` at `now` causes (design
    /// 3.2, 9.2): the one SETUP ANNOUNCE or ERR REGISTRATION to send to
    /// its validated source, or nothing. Only a `control-mode=dynamic`
    /// publication of its stream on that endpoint, not being removed,
    /// admits it, through the driver's registrations under that
    /// publication's policy. A receiver restarting at the endpoint of its
    /// own optional slot needs no new slot: it is not refused for a full
    /// table (design 3.2 step 4).
    fn register(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        register: &karyos_protocol::network::RspRegister,
        now: u64,
    ) -> Option<(SocketAddr, Control)> {
        use crate::sessions::register::RegisterOutcome;
        use karyos_protocol::network::{Registration, RegistrationReason};

        let Some(at) = self.publications.iter().position(|outbound| {
            outbound.serves(endpoint)
                && outbound.alias().stream_id == register.stream_id
                && outbound.registration().is_some()
                && !outbound.removing()
        }) else {
            self.count(|c| &mut c.registers_unknown);
            return None;
        };
        let outbound = self.publications.get(at)?;
        let alias = outbound.alias();
        let reused =
            outbound.registrant_at(normalized(source)) == Some(register.receiver.receiver_id);
        let capacity = if reused {
            crate::sessions::register::Capacity::Free
        } else {
            outbound.registration_capacity()
        };
        let required = outbound
            .registration()?
            .is_required(register.receiver.receiver_id);
        let existing = self.registrant_lookup(
            endpoint,
            alias,
            normalized(source),
            register.receiver,
            required,
            now,
        );
        let policy = self.publications.get_mut(at)?.registration_mut()?;
        let outcome =
            self.registrations
                .register(policy, source, register, (existing, capacity), now);
        match outcome {
            RegisterOutcome::Announce { source } => self
                .sessions
                .announcement(endpoint, alias)
                .map(|announce| (source, Control::SetupAnnounce(announce))),
            RegisterOutcome::Refuse { source } => Some((
                source,
                Control::Registration(Registration {
                    stream_id: register.stream_id,
                    reason: RegistrationReason::DestinationsFull,
                }),
            )),
            RegisterOutcome::Drop(_) => None,
        }
    }

    /// What the publication `alias` on `endpoint` holds of `receiver`,
    /// registering from `source` at `now` (design 2.3, 3.2 step 4): its
    /// confirmed bindings are its memberships, looked up by source, then
    /// by `receiver_id`. A source in its quarantine is dropped (design
    /// 3.7). A required receiver id is never restarted nor moved (owner
    /// decision M4, MD-19); an optional one restarts or moves once its old
    /// binding has accepted no SM for `destination_move_quiet`, so a host
    /// naming a live receiver's id cannot evict it (karyos#940).
    fn registrant_lookup(
        &self,
        endpoint: EndpointId,
        alias: Alias,
        source: SocketAddr,
        receiver: Receiver,
        required: bool,
        now: u64,
    ) -> crate::sessions::register::Existing {
        use crate::sessions::register::Existing;

        let identity = self.sessions.identity(endpoint, alias);
        let quiet = self.registrations.config().move_quiet;
        let quarantine = self.membership.receiver_timeout;
        let quarantined = self
            .publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
            .is_some_and(|outbound| outbound.in_quarantine(source, now, quarantine));
        if quarantined {
            return Existing::Quarantined;
        }
        let mut existing = Existing::None;
        for held in self.bindings.iter().filter(|held| {
            held.endpoint == endpoint
                && held.alias == alias
                && Some(held.identity) == identity
                && held.receiver_id.or(held.former) == Some(receiver.receiver_id)
        }) {
            let at_source = held.source() == source;
            let same_boot = held.boot_id == receiver.receiver_boot_id;
            let live = held.last_sm.is_none_or(|last| age_ns(now, last) < quiet);
            let decided = match (same_boot, at_source) {
                (true, true) => Existing::Bound,
                (false, _) if required => Existing::BootChanged,
                (false, _) if live => Existing::DuplicateReceiver,
                (false, _) => Existing::None,
                (true, false) if required || live => Existing::DuplicateReceiver,
                (true, false) => Existing::None,
            };
            if decided != Existing::None {
                existing = decided;
                break;
            }
        }
        // A required id with no binding left whose reserved slot is still
        // held: its `Membership` refuses it for the incarnation (design
        // 4.6, M5), so its REGISTER is dropped, at its own endpoint or any
        // other, before it is announced (karyos#945 review).
        if existing == Existing::None
            && required
            && self
                .publications
                .iter()
                .find(|outbound| outbound.serves(endpoint) && outbound.alias() == alias)
                .is_some_and(|outbound| outbound.holds_required(receiver.receiver_id))
        {
            existing = Existing::RequiredLost;
        }
        existing
    }

    /// Settles what the first valid SM of the registrant at `index`, from
    /// `source`, changes for the dynamic publication it names (design 3.2
    /// step 4): with the same `receiver_id` and a new boot id, an optional
    /// receiver's old membership retires (reason `restarted`); with the
    /// same receiver block at another endpoint quiet for
    /// `destination_move_quiet`, an optional membership moves (reason
    /// `moved`); a required receiver id is never restarted nor moved, and a
    /// receiver still live elsewhere is a `duplicate_receiver`. A
    /// `stranger`, not a destination yet, takes its slot first. `None`
    /// when settled; otherwise the outcome holds what to answer, and a
    /// stranger's binding is dropped, while one at a slot already held
    /// stays, reset, to expire it.
    #[allow(
        clippy::option_option,
        reason = "settled, refused with a reply, or refused without one"
    )]
    fn settle_registrant(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        status: &StatusMessage,
        index: usize,
        stranger: bool,
        now: u64,
    ) -> Option<Option<(SocketAddr, Control)>> {
        use crate::agents::data::RemovalReason;

        let Some(mine) = self.bindings.get(index).copied() else {
            return Some(None);
        };
        let receiver = status.receiver;
        let required = self
            .publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == status.alias)
            .and_then(|outbound| outbound.registration())
            .is_some_and(|policy| policy.is_required(receiver.receiver_id));
        let quiet = self.registrations.config().move_quiet;
        let other = |held: &ReceiverBinding| {
            held.id != mine.id
                && held.endpoint == endpoint
                && held.alias == status.alias
                && held.identity == status.identity
                && held.receiver_id.or(held.former) == Some(receiver.receiver_id)
        };
        // Decide first, change nothing yet. The SM must name the receiver
        // block its REGISTER named, and at a slot already held, that
        // slot's receiver id (karyos#940): an SM cannot claim an id, a
        // required one least of all, that its REGISTER did not.
        let unregistered = match mine.registered {
            Some(registered) => registered != receiver,
            None => stranger,
        };
        let foreign = !stranger
            && self
                .publications
                .iter()
                .find(|outbound| outbound.serves(endpoint) && outbound.alias() == status.alias)
                .and_then(|outbound| outbound.registrant_at(source))
                != Some(receiver.receiver_id);
        // Another binding of the id: a required id is never restarted nor
        // moved, and an optional one only once quiet (karyos#940).
        let refused = unregistered
            || foreign
            || self.bindings.iter().filter(|held| other(held)).any(|held| {
                let same_boot = held.boot_id == receiver.receiver_boot_id;
                let live = held.last_sm.is_none_or(|last| age_ns(now, last) < quiet);
                required || (live && !(same_boot && held.source() == source))
            });
        if refused {
            self.count(|c| &mut c.registrants_refused);
            // At a slot already held, the binding is the one that holds it
            // or one beside it: it stays, reset and unconfirmed, so it
            // expires at `setup_challenge_timeout` and the slot retires
            // with it (`retire_uncovered_registrants`, run by
            // `remove_binding` when the reset binding expires), unless its
            // own receiver's next SM confirms it first. Dropping it would leave the slot
            // with nothing to expire it (karyos#945 review).
            if stranger {
                self.remove_binding(index, now, |c| &mut c.registrants_refused);
            }
            return Some(None);
        }
        if stranger
            && let Some(refusal) =
                self.join_registrant(endpoint, source, status, index, required, now)
        {
            return Some(refusal);
        }
        // Then retire or move what it replaces.
        while let Some(at) = self.bindings.iter().position(&other) {
            let Some(held) = self.bindings.get(at).copied() else {
                break;
            };
            let old = held.source();
            let moved = held.boot_id == receiver.receiver_boot_id;
            let outbound = self
                .publications
                .iter_mut()
                .find(|outbound| outbound.serves(endpoint) && outbound.alias() == status.alias);
            if let Some(outbound) = outbound {
                if moved && let Some(membership) = outbound.membership_mut() {
                    let _ = membership.move_binding(receiver, endpoint, old, source);
                }
                let reason = if moved {
                    RemovalReason::Moved
                } else {
                    RemovalReason::Restarted
                };
                if old != source {
                    let _ = outbound.retire_registrant(old, reason, now);
                }
            }
            if moved {
                self.count(|c| &mut c.registrants_moved);
                self.remove_binding(at, now, |c| &mut c.registrants_moved);
            } else {
                self.count(|c| &mut c.registrants_restarted);
                self.remove_binding(at, now, |c| &mut c.registrants_restarted);
            }
        }
        None
    }

    /// Whether `control` is the CHALLENGE of a pending registrant of the
    /// `control-mode=dynamic` publication it names on `endpoint`, from the
    /// source it registered from (design 3.2, 9.2), so the ANSWER goes to
    /// that validated source and nowhere else. Changes nothing: the entry
    /// is taken by [`Self::registrant_taken`] once the ANSWER goes. A
    /// CHALLENGE naming another incarnation matches nothing.
    fn registrant_challenge(
        &self,
        endpoint: EndpointId,
        source: SocketAddr,
        control: &Control,
        now: u64,
    ) -> bool {
        let Control::Challenge(challenge) = control else {
            return false;
        };
        if self.sessions.identity(endpoint, challenge.alias) != Some(challenge.identity) {
            return false;
        }
        let Some(policy) = self
            .publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == challenge.alias)
            .and_then(|outbound| outbound.registration())
        else {
            return false;
        };
        self.registrations.would_challenge(
            policy,
            challenge.alias.stream_id,
            source,
            challenge.challenge.receiver_boot_id,
            now,
        )
    }

    /// Whether the publication `alias` on `endpoint` is a
    /// `control-mode=dynamic` one.
    fn registration_of(&self, endpoint: EndpointId, alias: Alias) -> bool {
        self.publications.iter().any(|outbound| {
            outbound.serves(endpoint)
                && outbound.alias() == alias
                && outbound.registration().is_some()
        })
    }

    /// Whether the ANSWER to the CHALLENGE `control` from `source` would
    /// leave a binding behind ([`Self::bind`]): its tuple is already bound,
    /// or [`Self::make_room`] would find room for its receiver, the one
    /// its pending entry names (karyos#941 item 2). Expires the bindings
    /// due by `now` first, as `bind` does.
    fn can_bind(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        control: &Control,
        now: u64,
    ) -> bool {
        let Control::Challenge(challenge) = control else {
            return true;
        };
        self.expire_bindings(now);
        let source = normalized(source);
        let bound = self
            .bindings
            .iter()
            .find(|held| {
                held.parent.is_none()
                    && held.endpoint == endpoint
                    && held.alias == challenge.alias
                    && held.solicited_from == source
                    && held.boot_id == challenge.challenge.receiver_boot_id
                    && held.identity == challenge.identity
            })
            .copied();
        let registered = self
            .publications
            .iter()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == challenge.alias)
            .and_then(|outbound| outbound.registration())
            .and_then(|policy| {
                self.registrations.challenge_receiver(
                    policy,
                    challenge.alias.stream_id,
                    source,
                    challenge.challenge.receiver_boot_id,
                    now,
                )
            });
        let room = match bound {
            // Answered again, its binding stays; it is renamed to this
            // receiver block. A required id's own binding renamed to
            // another receiver hands its kept binding on, so it needs one
            // more free binding for that id (karyos#941 item 2).
            Some(held) => {
                let renamed = held.registered.filter(|was| {
                    registered.map(|now| now.receiver_id) != Some(was.receiver_id)
                        && self.holds_required_registration(&held)
                });
                match renamed {
                    None => Room::Free,
                    Some(_) => {
                        let own = registered.is_some_and(|receiver| {
                            self.unjoined_required(endpoint, challenge.alias, receiver.receiver_id)
                        });
                        let after = self
                            .bindings
                            .len()
                            .checked_add(self.unjoined_required_count())
                            .and_then(|held| held.checked_add(1))
                            .and_then(|held| held.checked_sub(usize::from(own)));
                        if after.is_some_and(|after| after <= self.max_bindings) {
                            Room::Free
                        } else {
                            Room::Reserved
                        }
                    }
                }
            }
            None => self.room_for(endpoint, challenge.alias, registered),
        };
        match room {
            Room::Free | Room::Evict(_) => true,
            Room::Reserved => {
                self.count(|c| &mut c.bindings_reserved);
                false
            }
            Room::Full => {
                self.count(|c| &mut c.bindings_full);
                false
            }
        }
    }

    /// Takes the pending entry the CHALLENGE `control` from `source`
    /// answers, as [`Self::registrant_challenge`] matched it, once its
    /// ANSWER goes (design 3.2: the CHALLENGE moves it on), and returns the
    /// receiver block its REGISTER named; `None` when it took none.
    fn registrant_taken(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        control: &Control,
        now: u64,
    ) -> Option<Receiver> {
        let Control::Challenge(challenge) = control else {
            return None;
        };
        if self.sessions.identity(endpoint, challenge.alias) != Some(challenge.identity) {
            return None;
        }
        let policy = self
            .publications
            .iter_mut()
            .find(|outbound| outbound.serves(endpoint) && outbound.alias() == challenge.alias)
            .and_then(|outbound| outbound.registration_mut())?;
        self.registrations
            .challenged(
                policy,
                challenge.alias.stream_id,
                source,
                challenge.challenge.receiver_boot_id,
                now,
            )
            .map(|entry| entry.receiver)
    }

    /// Which binding an SM from `source` on `endpoint` belongs to (plan
    /// 169, network-control-schemas.md §6.3), deciding nothing yet: one of
    /// the receiver (sender endpoint, alias, boot id and incarnation) whose
    /// SM source is `source`; else one with no SM source yet, which would
    /// take `source`; else an adoption for the receiver's ANSWER-created
    /// binding, at most [`MAX_ADOPTIONS`] of them. An SM of a receiver with
    /// no binding counts `sm_unbound`, one past the adoptions
    /// `bindings_adoption_refused`.
    fn sm_binding(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        status: &StatusMessage,
    ) -> Option<SmBinding> {
        let receiver = |binding: &ReceiverBinding| {
            binding.endpoint == endpoint
                && binding.alias == status.alias
                && binding.boot_id == status.receiver.receiver_boot_id
                && binding.identity == status.identity
        };
        if let Some(index) = self
            .bindings
            .iter()
            .position(|binding| receiver(binding) && binding.sm_source == Some(source))
        {
            return Some(SmBinding::Bound(index));
        }
        if let Some(index) = self
            .bindings
            .iter()
            .position(|binding| receiver(binding) && binding.sm_source.is_none())
        {
            return Some(SmBinding::Learn(index));
        }
        // The receiver's first ANSWER-created binding is the parent: one
        // solicited from two sources has two, and every adoption counts
        // against the first, so the bound holds per parent.
        let Some(parent) = self
            .bindings
            .iter()
            .position(|binding| receiver(binding) && binding.parent.is_none())
        else {
            self.count(|c| &mut c.sm_unbound);
            return None;
        };
        let id = self.bindings.get(parent).map(|binding| binding.id);
        let adopted = self
            .bindings
            .iter()
            .filter(|binding| binding.parent.is_some() && binding.parent == id)
            .count();
        if adopted >= MAX_ADOPTIONS {
            self.count(|c| &mut c.bindings_adoption_refused);
            return None;
        }
        Some(SmBinding::Adopt(parent))
    }

    /// Adopts a binding for the receiver of the ANSWER-created binding at
    /// `parent` with SM source `source`, returning its index: in the
    /// bounded table, evicting as an answer does. Nothing is adopted if
    /// there is no room, or if the eviction took the parent (an unconfirmed
    /// one).
    fn adopt(&mut self, parent: usize, source: SocketAddr, now: u64) -> Option<usize> {
        let parent = *self.bindings.get(parent)?;
        // An adoption is of a static publication only, and names no
        // registered receiver: the reservation applies as to any other.
        if !self.make_room(parent.endpoint, parent.alias, None, now) {
            return None;
        }
        if !self.bindings.iter().any(|binding| binding.id == parent.id) {
            self.count(|c| &mut c.sm_unbound);
            return None;
        }
        let id = self.next_binding;
        self.next_binding = id.wrapping_add(1);
        self.bindings.push(ReceiverBinding {
            id,
            parent: Some(parent.id),
            sm_source: Some(source),
            receiver_id: None,
            former: None,
            lanes: None,
            last_sm: None,
            ..parent
        });
        self.count(|c| &mut c.bindings_adopted);
        self.bindings.len().checked_sub(1)
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
        // Whether it is a pending registrant's CHALLENGE, from the source
        // it registered from: decided once (karyos#945 review).
        let registrant = self.registrant_challenge(endpoint, normalized(source), &control, now);
        // A multi-destination publication answers only a configured
        // destination, at that destination (design 9.2; MD-16): a source
        // outside its set is refused, so it reflects nothing.
        let destination = match self.destinations_of(endpoint, alias) {
            None => destination,
            Some(fanout) if fanout => {
                let source = normalized(source);
                // A registrant's CHALLENGE answers even at a destination's
                // address: a receiver restarted there. Its pending entry is
                // taken only once the ANSWER goes (karyos#940).
                if !registrant && !self.sends_to(endpoint, alias, source) {
                    self.count(|c| &mut c.refused);
                    return None;
                }
                source
            }
            Some(_) => destination,
        };
        // A dynamic publication answers only a receiver it can bind
        // (karyos#941 item 2): one with no room gets no ANSWER, keeps its
        // pending entry, installs no image and so keeps registering, where
        // an ANSWER with no binding left it believing it was bound while
        // its SMs were dropped.
        if self.registration_of(endpoint, alias) && !self.can_bind(endpoint, source, &control, now)
        {
            self.count(|c| &mut c.challenges_unbound);
            return None;
        }
        // A registrant's CHALLENGE is charged to its address's bucket of
        // the registrations, not to the shared `setup_answer_rate` table
        // (karyos#945 review): a refused one keeps its pending entry.
        if registrant && !self.registrations.admit_challenge(source, now) {
            self.count(|c| &mut c.refused);
            return None;
        }
        let answer = match control {
            Control::Challenge(challenge) if registrant => {
                self.sessions
                    .registrant_challenge(endpoint, now, &challenge, |_| joins)
            }
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
                let registered = self.registrant_taken(endpoint, source, &control, now);
                self.bind(endpoint, source, &answer, registered, now);
                Some((destination, Control::SetupAnswer(answer)))
            }
            Err(_) => {
                self.count(|c| &mut c.refused);
                None
            }
        }
    }
}

/// Adds the SETUP side of `publication` on each of `outbound`'s paths, all
/// or nothing: a routed publication answers and announces on every path's
/// endpoint, and takes one session per path of the table's capacity.
fn add_sessions<T: StreamTerms>(
    sessions: &mut SendSessions,
    publication: &crate::sessions::send::Publication,
    outbound: &Outbound<T>,
) -> Result<(), SendSessionError> {
    let mut added = 0usize;
    for path in outbound.route_endpoints() {
        let result = sessions.add(crate::sessions::send::Publication {
            endpoint: path,
            ..*publication
        });
        if let Err(error) = result {
            for undo in outbound.route_endpoints().take(added) {
                let _ = sessions.remove(undo, publication.alias);
            }
            return Err(error);
        }
        // At most four paths: no overflow.
        if let Some(next) = added.checked_add(1) {
            added = next;
        }
    }
    Ok(())
}

/// Whether `outbound` is established on any of its paths: its first sends
/// go on every path once one receiver's SM has arrived on one.
fn established<T: StreamTerms>(sessions: &SendSessions, outbound: &Outbound<T>) -> bool {
    outbound
        .route_endpoints()
        .any(|path| sessions.is_established(path, outbound.alias()))
}

mod path_intake;
pub(crate) mod publish_auth;
pub(crate) mod receive_auth;

use publish_auth::{Establishing, PublicationAuth, receiver_control_alias};
use receive_auth::{AuthReason, AuthRejections, ImageAuth, SubscriptionAuth};

use crate::remote_guard::MarkStore;
use crate::signed_control::{self, SignedIntake};

/// The receiver's redundant path settings under `config`.
pub(crate) fn receiver_path_config(config: &AgentConfig) -> PathConfig {
    PathConfig {
        max_paths: config.sessions.max_paths,
        path_queue_datagrams: config.path_queue_datagrams,
        ..PathConfig::default()
    }
}

/// The skip policy settings of an image under `paths`. The skew window
/// (RP-4): on an unreliable image the seal waits the larger of it and the
/// reorder interval, never their sum.
pub(crate) fn image_skip_config(paths: &PathConfig, reliable: bool) -> SkipConfig {
    SkipConfig {
        skew_window_ns: paths.path_skew_window,
        ..if reliable {
            SkipConfig::reliable()
        } else {
            SkipConfig::unreliable()
        }
    }
}

#[cfg(test)]
mod tests;
