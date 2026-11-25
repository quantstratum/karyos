// SPDX-License-Identifier: Apache-2.0

//! Errors of the driver.

use karyos_client::ClientError;
use karyos_sys::conflation::ConflationError;
use karyos_sys::error::SysError;
use thiserror::Error;

/// Why `guard_stream` could not admit a stream's walker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WalkerUnavailable {
    /// Every spare-slot credit the stream's `spare_slots` allows is in
    /// use: size `spare_slots` for the readers plus one.
    #[error("no spare-slot credit")]
    NoSpareCredit,
    /// Every reader cell of the stream is taken.
    #[error("no reader cell")]
    NoReaderCell,
}

/// What a network publication's timed lanes do not support yet (P2.11
/// PR1, the software route; `quantstratum-docs:
/// karyos/design/timed-tx.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TimedNetworkUnsupported {
    /// A channel with redundant paths: each path submits its own copy, and
    /// when a timed head is selected once is not designed yet.
    #[error("redundant paths")]
    Routed,
    /// The `Tai` clock domain: the sender runs on the monotonic clock.
    #[error("the Tai clock domain")]
    TaiDomain,
    /// Cancel-on-deadline: the sealing it needs is the conductor's, which
    /// the sender agent does not hold.
    #[error("cancel-on-deadline")]
    CancelOnDeadline,
    /// A horizon that, with one heartbeat interval, reaches the image
    /// liveness timeout: a lane holding only a head that far ahead sends
    /// nothing (no DATA, and no idle heartbeat while a head is staged),
    /// and its last heartbeat can come one interval before, so its
    /// receivers' images would retire before it leaves. Receivers are
    /// assumed to use this driver's `image_liveness_timeout`.
    #[error("a horizon that, with a heartbeat interval, reaches the image liveness timeout")]
    HorizonPastLiveness,
    /// The `etf` route (ADR-0109) on a channel without an `etf`
    /// declaration (`etf-priority` and `etf-delta`).
    #[error("the etf route without the channel's etf declaration")]
    EtfUndeclared,
    /// An `etf` declaration on a channel whose publication is not timed on
    /// the `etf` route: nothing would use the leaf it names.
    #[error("an etf declaration without the etf route")]
    EtfWithoutRoute,
    /// The declared leaf's `delta` exceeds the publication's declared
    /// tolerated advance (ADR-0109 point 2): a datagram handed to the
    /// kernel at the advance could reach the leaf too late and be dropped.
    #[error("the etf leaf's delta exceeds the declared advance")]
    EtfDeltaAboveAdvance,
    /// Another `etf` publication of this driver declares the same priority
    /// on the same interface (ADR-0109 point 2, isolation): one could
    /// advance the shared leaf's clock and get the other's datagrams
    /// dropped.
    #[error("another etf publication declares this priority on this interface")]
    EtfPriorityShared,
    /// The `etf` route anywhere but on a unicast destination of a Linux
    /// driver (ADR-0109 point 5).
    #[error("the etf route off Linux or off a unicast destination")]
    EtfUnavailable,
    /// An `etf` declaration a URI could not give: a zero `delta` or one of
    /// 2^32 ns or more, no `interface` address, or an interface address
    /// this host cannot resolve to an interface (ADR-0109 point 2).
    #[error("an etf declaration with no valid delta or resolvable interface")]
    EtfDeclarationInvalid,
}

/// Errors returned by the embedded driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DriverError {
    /// A network agent failed or panicked; fatal for the driver (DN-9).
    #[error("the {agent:?} network agent failed")]
    NetworkAgent {
        /// The agent.
        agent: crate::agents::AgentKind,
    },
    /// A network agent thread could not start.
    #[error("cannot start the network agent threads")]
    NetworkStart,
    /// The driver has no network configured (`DriverConfig::network`).
    #[error("no network is configured")]
    NetworkUnavailable,
    /// The channel uses a feature this driver does not wire yet (multi
    /// destination, redundant paths, an interface name), or `fc=tagged:0`
    /// on a publication: a tagged group is never 0.
    #[error("unsupported network channel")]
    UnsupportedChannel,
    /// A multi-destination channel in `control-mode=dynamic`: refused by
    /// a publication or subscription call that carries no registration:
    /// dynamic mode needs an allowlist on the publisher and a receiver
    /// identity on the subscriber, so only
    /// `EmbeddedDriver::add_dynamic_network_publication` and
    /// `EmbeddedDriver::add_dynamic_network_subscription` take it
    /// (ADR-0082; karyos#644), and a client's URI is refused as an
    /// unsupported channel.
    #[error(
        "dynamic multi-destination registration needs the dynamic publication or subscription call"
    )]
    DynamicRegistrationUnsupported,
    /// A second `control-mode=dynamic` publication of one stream on one
    /// control endpoint: a REGISTER names only its stream, so one endpoint
    /// holds at most one dynamic publication of it (`quantstratum-docs:
    /// karyos/design/multi-destination-unicast.md` 3.2 step 1; karyos#644).
    #[error("stream {stream_id} already has a dynamic publication on this control endpoint")]
    DynamicPublicationExists {
        /// The stream.
        stream_id: i32,
    },
    /// A network publication's typed roles name another strategy than its
    /// channel's `fc`, the one source of the strategy (`min` without one;
    /// owner item 7, karyos#637).
    #[error("the roles' strategy is not the channel's fc")]
    StrategyConflict,
    /// A network publication's roles do not fit its membership: more
    /// required or tagged receivers than
    /// [`crate::membership::DEFAULT_MAX_RECEIVERS`], a `receiver_id` 0 or
    /// repeated, or a tag 0 (karyos#637).
    #[error("roles the membership cannot hold")]
    InvalidRoles,
    /// A second subscription of one endpoint and stream asks for another
    /// reliability than the first: they would share one receiver entry,
    /// and a reliable subscriber must not get gap-tolerant delivery.
    #[error("the stream is already subscribed with another reliability")]
    ReliabilityMismatch,
    /// A second subscription of one endpoint and stream names another
    /// receiver identity than the first, or one where the first has none,
    /// or none where the first has one: they would share one receiver
    /// entry, whose images name one identity (MC-1).
    #[error("the stream is already subscribed with another receiver identity")]
    ReceiverIdentityMismatch,
    /// A second subscription of one endpoint and stream asks for another
    /// conflated lane than the first, or one where the first has none, or
    /// none where the first has one: they would share one receiver entry,
    /// whose images gate one lane's seals (conflated-network-images.md).
    #[error("the stream is already subscribed with another conflated lane")]
    ConflationMismatch,
    /// A network endpoint could not be opened or its table is full.
    #[error("network endpoint unavailable")]
    NetworkEndpoint,
    /// A path of a paired unicast paths channel names an interface address
    /// this host does not have (`EADDRNOTAVAIL` at its bind), refused at
    /// channel admission (karyos#1043).
    #[error("no interface of this host has address {interface}")]
    UnknownInterface {
        /// The path's interface address.
        interface: std::net::IpAddr,
    },
    /// `AgentConfig::publications` network publications are held (being
    /// added, active or being removed).
    #[error("too many network publications")]
    NetworkPublicationsFull,
    /// An endpoint the publication would send on cannot hold it: with what
    /// its other publications hold and the control reserve, `needed`
    /// passes the endpoint's `capacity` of `limit` (karyos#859). A client
    /// that asks by channel URI sees `ErrorCode::ResourcesUnavailable`,
    /// with the detail word [`EndpointLimit::detail`].
    #[error("endpoint {limit:?}: {needed} needed, {capacity} held")]
    EndpointCapacity {
        /// The limit passed.
        limit: EndpointLimit,
        /// The endpoint's capacity of it.
        capacity: u32,
        /// What it would take with this publication.
        needed: u32,
    },
    /// `AgentConfig::subscriptions` distinct network subscriptions are
    /// held: the receiver's table is full.
    #[error("too many network subscriptions")]
    NetworkSubscriptionsFull,
    /// A network agent's command ring is full, or an endpoint at the
    /// fixed address an add needs is still retiring after its last
    /// publication or subscription went (karyos#994); retry later.
    #[error("network agent busy")]
    NetworkBusy,
    /// The driver's export and occupant ids are exhausted.
    #[error("export ids exhausted")]
    ExportIdsExhausted,
    /// A network publication's lanes cannot be reconfigured yet: the
    /// sender's readers follow one mapping.
    #[error("stream {stream} is a network publication; it cannot be reconfigured")]
    NetworkCutover {
        /// The stream.
        stream: u64,
    },
    /// The stream handle does not name a live stream of this driver.
    #[error("unknown stream {stream}")]
    UnknownStream {
        /// The handle's stream id.
        stream: u64,
    },
    /// The stream is being removed: it accepts no new publication or
    /// subscription.
    #[error("stream {stream} is retiring")]
    StreamRetiring {
        /// The handle's stream id.
        stream: u64,
    },
    /// `max_streams` streams are configured (active or retiring).
    #[error("too many streams")]
    TooManyStreams,
    /// A stream lane would take more than `DriverConfig::max_stream_bytes`
    /// (R-CORE-34); nothing was created.
    #[error("a stream lane of {bytes} bytes is above max_stream_bytes ({max})")]
    StreamTooLarge {
        /// The lane's bytes: its log buffer region and its table's.
        bytes: u64,
        /// The configured maximum.
        max: u64,
    },
    /// Stream identities are exhausted.
    #[error("stream identities exhausted")]
    StreamIdsExhausted,
    /// The stream is one lane of an aggregate of several: it is removed or
    /// reconfigured with its aggregate.
    #[error("stream {stream} is a lane of an aggregate; act on the aggregate")]
    LaneOfAggregate {
        /// The stream.
        stream: u64,
    },
    /// A stream with the same wire stream id and session already exists.
    /// That includes a removed network publication's lanes while its
    /// removal lingers (driver-network-agents.md §7): the key is refused
    /// until the removal ends, at worst `max(publication_linger,
    /// path_heartbeat_interval) + publication_linger` after the removal
    /// starts (about 10 s at the defaults), and a retry once the removal
    /// has ended succeeds. A client that asks by channel URI sees
    /// `ErrorCode::ResourcesUnavailable`.
    #[error("stream {stream_id} session {session_id} already exists")]
    DuplicateStream {
        /// Wire stream id.
        stream_id: i32,
        /// Session alias.
        session_id: i32,
    },
    /// A control-channel limit or size is invalid.
    #[error("invalid driver configuration")]
    InvalidConfig,
    /// A `control-mode=dynamic` publication's registration settings are
    /// refused, the field at fault named (karyos#941 item 7).
    #[error(transparent)]
    Registration(crate::sessions::register::RegistrationConfigError),
    /// One more `control-mode=dynamic` publication would take more
    /// destinations, `max_destinations` each, than the sender has
    /// `receiver_bindings` for (karyos#941 item 2).
    #[error("dynamic publications need {needed} receiver_bindings, {held} configured")]
    ReceiverBindings {
        /// The bindings the dynamic publications would need with this one.
        needed: usize,
        /// `receiver_bindings`.
        held: usize,
    },
    /// A `control-mode=dynamic` subscription's `control` address is not
    /// one a REGISTER can be sent to: a zero port, an unspecified,
    /// multicast or broadcast address (network-control-schemas.md §7.3;
    /// karyos#941 item 7).
    #[error("dynamic registration control address {control} is not a unicast endpoint")]
    InvalidRegistrationControl {
        /// The `control` address refused.
        control: std::net::SocketAddr,
    },
    /// A channel's `nak-control` maps a data group on a path to another
    /// control group than the driver's table already holds for it (owner
    /// item 8, karyos#654): one driver, one mapping.
    /// Only the data group is carried: the error stays `Copy` and small;
    /// the table holds the other mapping.
    #[error("nak-control conflicts with the control group held for data group {data_group}")]
    ControlGroupConflict {
        /// The channel's data group endpoint.
        data_group: std::net::SocketAddr,
    },
    /// A channel's `nak-control` needs more entries than the driver's
    /// control group table has free: it holds at most
    /// [`MAX_CONTROL_GROUPS`](crate::net::MAX_CONTROL_GROUPS) (karyos#654).
    #[error("the NAK control group table is full")]
    ControlGroupsFull,
    /// `barrier_ack_timeout` misses a bound: at driver start, the floor or
    /// the conductor duty periods; at a conflated subscription of an
    /// unreliable channel, the far-window timeout (SPEC.md §7.1;
    /// karyos#658).
    #[error("{0}")]
    BarrierAckTimeout(crate::agents::BarrierAckBound),
    /// `max_destinations` is outside 1 to 64, or above the endpoint's
    /// `max_routes` (MD-6; karyos#889).
    #[error("max_destinations {value} is outside 1 to 64 or above max_routes")]
    MaxDestinations {
        /// The value refused.
        value: usize,
    },
    /// A replay's feed wrote past the end it was finished at; its target
    /// retired.
    #[error("a replay finished at {end} but written to {written}")]
    ReplayOutstanding {
        /// The end asked for.
        end: u64,
        /// Where the feed wrote up to.
        written: u64,
    },
    /// A replay target of a lane other than 0: only lane 0 recordings are
    /// replayed (A5).
    #[error("a replay of lane {lane}: only lane 0 is replayed")]
    ReplayLane {
        /// The recorded lane.
        lane: u8,
    },
    /// No such guard: a foreign handle or an unknown id.
    #[error("unknown guard")]
    UnknownGuard,
    /// A guard of that name already exists.
    #[error("a guard of that name already exists")]
    DuplicateGuard,
    /// `max_guards` guards exist.
    #[error("too many guards")]
    TooManyGuards,
    /// Guard ids are exhausted; they are never reused.
    #[error("guard ids exhausted")]
    GuardIdsExhausted,
    /// The stream's guard is not open: a guarded publication is bound to
    /// an open epoch when it is issued.
    #[error("guard {guard} is not open")]
    GuardNotOpen {
        /// The guard id.
        guard: u64,
    },
    /// The stream was sealed by a guard close and the guard is open again,
    /// but the fresh incarnation could not be created yet: the sealed
    /// incarnation's publication has not released, or the stream is
    /// conflated or held by a remote client (remote incarnations: G-d2b).
    #[error("stream {stream} was sealed by a guard close")]
    GuardSealed {
        /// The stream id.
        stream: u64,
    },
    /// Every handle slot of a guarded concurrent stream's incarnation was
    /// issued (ADR-0092 decision 3): a slot is freed only when the
    /// incarnation ends, and a handle beyond `H` is never admitted
    /// unguarded.
    #[error("stream {stream} has issued all {handles} guarded handle slots")]
    GuardHandleSlotsExhausted {
        /// The stream id.
        stream: u64,
        /// `H`, its handle slots.
        handles: u64,
    },
    /// A lane of a guarded network publication that a guard close sealed
    /// is between incarnations after the reopen: the old incarnation's
    /// session is removed, and its alias stays quarantined for
    /// `alias_quarantine` (default 10 s) from that removal before the next
    /// incarnation is added under it (`quantstratum-docs:
    /// karyos/design/network-sessions.md`). Retry at `until_ns` on the
    /// network clock (the host monotonic clock). While the old session is
    /// still being removed it is an estimate, early by however long that
    /// removal still takes; a retry then refuses again with the exact end.
    #[error("stream {stream}'s alias is quarantined until {until_ns} ns")]
    QuarantinedAlias {
        /// The stream id.
        stream: u64,
        /// The earliest retry, in ns on the network clock.
        until_ns: u64,
    },
    /// `guard_stream` could not admit the stream's walker, a reader that
    /// holds one spare-slot credit for the stream's life
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`, The
    /// walker's credit).
    #[error("stream {stream}'s guard walker is unavailable: {reason}")]
    GuardWalkerUnavailable {
        /// The stream id.
        stream: u64,
        /// What is missing.
        reason: WalkerUnavailable,
    },
    /// A reliable network publication's lane could not admit its retention
    /// hold, a cell of the stream's registry that holds the retention floor
    /// at `sent - retransmit_window` (quantstratum-docs:
    /// karyos/design/retention-floor-optional-receivers.md): every cell is
    /// taken. Nothing is left configured.
    #[error("stream {stream}'s retention hold is unavailable")]
    RetentionHoldUnavailable {
        /// The stream id.
        stream: u64,
    },
    /// A channel's `retransmit-window` is above half of the stream's
    /// term (owner item 63), refused at channel creation before anything
    /// is configured.
    #[error("retransmit-window {window} is above half of the term {term_length}")]
    RetransmitWindowAboveHalfTerm {
        /// The channel's window, in bytes.
        window: u32,
        /// The stream's term length, in bytes.
        term_length: u32,
    },
    /// A rate limit names a scope other than the publication's, which
    /// Phase 2 does not support (GC-5).
    #[error("rate limits of scope {scope} are not supported")]
    RateScopeUnsupported {
        /// The scope named.
        scope: crate::guards::RateScope,
    },
    /// A rate limit policy was refused: a zero rate or burst, or a byte
    /// burst below the stream's largest frame.
    #[error(transparent)]
    InvalidRatePolicy(karyos_sys::rate_limit::RatePolicyError),
    /// A rate policy change was refused (R-CORE-21).
    #[error(transparent)]
    RateChange(crate::guards::RateChangeError),
    /// A lane guarded with a rate other than its publication's policy
    /// (R-CORE-21): only a policy change changes it.
    #[error("the lane's rate {requested:?} is not its publication's {held:?}")]
    RatePolicyConflict {
        /// The rate the lane was guarded with.
        requested: karyos_sys::rate_limit::RatePolicy,
        /// The publication's policy.
        held: karyos_sys::rate_limit::RatePolicy,
    },
    /// A rate policy change of an aggregate was refused by one of its
    /// guarded lanes, named, so nothing changed on any lane (R-CORE-21).
    #[error("lane {lane} refused the rate policy change: {refusal}")]
    RateChangeOnLane {
        /// The lane that refused.
        lane: u8,
        /// Its refusal.
        refusal: crate::guards::LaneRefusal,
    },
    /// Every sender slot of the guards' owner is taken
    /// (`DriverConfig::max_guard_senders`).
    #[error("too many guard senders")]
    TooManyGuardSenders,
    /// Guard sender ids are exhausted; they are never reused.
    #[error("guard sender ids exhausted")]
    GuardSenderIdsExhausted,
    /// The sender is not registered with this driver (never, or no more).
    #[error("unknown guard sender {sender}")]
    UnknownGuardSender {
        /// The sender id.
        sender: u64,
    },
    /// The stream is not a timed lane: its buffer has no schedule ring
    /// (`quantstratum-docs: karyos/design/timed-tx.md`).
    #[error("stream {stream} is not a timed lane")]
    NotTimed {
        /// The stream id.
        stream: u64,
    },
    /// A network publication's timed lanes cannot take this yet.
    #[error("a timed network publication does not support {reason}")]
    TimedNetworkUnsupported {
        /// What it does not support.
        reason: TimedNetworkUnsupported,
    },
    /// A cutover of a timed lane: its schedule ring belongs to one
    /// incarnation's buffer and is never carried to a successor
    /// (`quantstratum-docs: karyos/design/timed-tx.md`, section 2 step 5),
    /// so timed lanes take no cutover until a design covers it.
    #[error("stream {stream} is a timed lane, which takes no cutover yet")]
    TimedCutover {
        /// The stream id.
        stream: u64,
    },
    /// A cutover of a network image's lane: the lane follows the remote
    /// sender's geometry and the receive owner writes the mapping it was
    /// given, so an image takes no cutover (`quantstratum-docs:
    /// karyos/design/network-shared-terms.md`, N-4a).
    #[error("stream {stream} is a network image's lane, which takes no cutover")]
    ImageCutover {
        /// The stream id.
        stream: u64,
    },
    /// The stream's incarnation numbers are exhausted; they are never
    /// reused.
    #[error("stream {stream}'s incarnations are exhausted")]
    IncarnationsExhausted {
        /// The stream id.
        stream: u64,
    },
    /// A guarded publication's outcome ring could not be sized or written.
    #[error(transparent)]
    Outcomes(karyos_sys::outcome_ring::OutcomeError),
    /// A guard transition was refused (`karyos_sys::guard`).
    #[error(transparent)]
    Guard(#[from] karyos_sys::guard::GuardError),

    /// A cutover of the stream is in progress
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`): new handles wait for the
    /// successor, and a further reconfiguration waits for the cutover to
    /// end.
    #[error("stream {stream} has a cutover in progress")]
    CutoverPending {
        /// The stream id.
        stream: u64,
    },

    /// The successor would need generation `2^24`.
    #[error("mapping generations exhausted")]
    GenerationsExhausted,

    /// The successor could reach a stream position at or above `2^63`.
    #[error("stream positions exhausted")]
    PositionsExhausted,
    /// `max_clients` clients are admitted.
    #[error("too many clients")]
    TooManyClients,
    /// Client identities are exhausted.
    #[error("client identities exhausted")]
    ClientIdsExhausted,
    /// The driver is in its terminal state: its broadcast buffer is closed.
    #[error("the driver is in its terminal state")]
    Terminal,
    /// The driver stopped admitting clients
    /// ([`crate::EmbeddedDriver::stop_admitting`]).
    #[error("the driver is not admitting clients")]
    NotAdmitting,
    /// The process has used every driver identity.
    #[error("driver identities exhausted")]
    DriverIdsExhausted,
    /// Every trace number of this driver instance was handed out.
    #[error("trace numbers exhausted")]
    TraceNumbersExhausted,
    /// The driver has used every shared region identity.
    #[error("region identities exhausted")]
    RegionIdsExhausted,
    /// An IPC driver with a network could hold more descriptors than this
    /// process may open (`RLIMIT_NOFILE`): its image lanes, stream
    /// mappings and clients at their configured bounds. Checked at start.
    /// When `needed` is within `hard`, raising the soft limit is enough.
    #[error(
        "the driver may need {needed} descriptors, above the soft limit of {limit} (hard limit {hard:?})"
    )]
    DescriptorLimit {
        /// Descriptors the configured bounds can hold.
        needed: u64,
        /// The process's soft limit.
        limit: u64,
        /// The process's hard limit; `None` when unlimited.
        hard: Option<u64>,
    },
    /// Every publication the stream can issue is out: its exclusive
    /// publication, or all `P` publisher slots of a concurrent stream.
    #[error("the stream's publication has already been taken")]
    PublicationTaken,
    /// The requested publication kind does not match the stream's mode: an
    /// exclusive publication of a concurrent stream, or a concurrent
    /// handle of an exclusive one.
    #[error("the publication kind does not match the stream's mode")]
    InvalidPublicationMode,
    /// The stream has no keyed conflation table.
    #[error("the stream is not configured for conflation")]
    NotConflated,
    /// A network image lane's conflated view cannot be recreated: it is
    /// still open, or it was never closed by its terminal cell
    /// (karyos#658).
    #[error("the conflated view is not closed")]
    ViewNotClosed,
    /// A keyed conflation operation failed.
    #[error(transparent)]
    Conflation(#[from] ConflationError),
    /// A duty cycle's work count does not fit `u32`; the work was done
    /// and the count keeps its previous value.
    #[error("work count overflow: {count} + {delta}")]
    WorkCountOverflow {
        /// The count before the failed addition.
        count: u32,
        /// The work that did not fit.
        delta: u32,
    },
    /// A client-level error.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// A lower layer failed.
    #[error(transparent)]
    Sys(#[from] SysError),
}

/// An endpoint limit a publication may pass (karyos#859).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointLimit {
    /// TX slots (`tx_slots`).
    TxSlots = 1,
    /// TX queues (`max_queues`).
    Queues = 2,
    /// Routes (`max_routes`).
    Routes = 3,
}

impl EndpointLimit {
    /// The detail word of its refusal: the limit in the top byte, the
    /// capacity in the next three bytes (saturated), what it would take in
    /// the low four.
    #[must_use]
    pub fn detail(self, capacity: u32, needed: u32) -> u64 {
        (u64::from(self as u8) << 56)
            | (u64::from(capacity.min(0x00FF_FFFF)) << 32)
            | u64::from(needed)
    }
}
