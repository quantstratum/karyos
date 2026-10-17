// SPDX-License-Identifier: Apache-2.0

//! The driver's network agents (`quantstratum-docs:
//! karyos/design/driver-network-agents.md`, phase 2 of §10; decisions
//! DN-1, DN-2, DN-3, DN-8 and DN-9, coordinator ACS 15332): the sender and
//! receiver agent objects, the bounded rings that connect them to the
//! conductor, and the runner that gives them threads.
//!
//! - **Agents (DN-1).** [`SenderAgent`] and [`ReceiverAgent`] are plain
//!   structs with one duty entry point, `do_work(now) -> work count`. They
//!   own their state; the conductor reaches them only through their rings
//!   and their stop flag. This phase gives them no network work: they serve
//!   a ping, used by tests and by health checks.
//! - **Rings (DN-3).** Each agent has a command ring from the conductor and
//!   an event ring to it ([`ring`]). The conductor reserves the reply's
//!   event slot when it posts a command, so a reply never finds the ring
//!   full; the command is refused, and nothing posted, when either slot is
//!   unavailable.
//! - **Threading (DN-2, SPEC.md §3).** In [`ThreadingMode::Shared`] the
//!   caller drives [`NetworkAgents::do_work`] on its own thread, next to
//!   the conductor. [`AgentRunner`] owns the threads of the other modes:
//!   one per agent ([`ThreadingMode::Dedicated`]) or one for both
//!   ([`ThreadingMode::SharedNetwork`]). Whenever both agents share a
//!   thread the receiver runs first in each iteration. Optional core
//!   pinning in Dedicated mode (design §2.2) is not here; it comes with the
//!   standalone driver's runner configuration (phase 8).
//! - **Stop (DN-8).** Stop cannot be refused: each agent has a stop flag
//!   ([`AgentLink::request_stop`]) that it checks at the start of every
//!   cycle, whatever its rings hold. [`AgentRunner::stop`] sets both flags,
//!   joins the threads within a timeout and hands the agents back; a thread
//!   that does not stop in time is returned to the conductor
//!   ([`LateAgent`]), never detached silently.
//! - **Failure (DN-9).** An agent that returns an error or panics stops its
//!   thread; the runner reports it and still hands the agent back, so its
//!   resources can be released. The conductor treats it as fatal for the
//!   driver.

pub mod chain;
pub(crate) mod conflated_gate;
pub mod control;
pub mod data;
pub mod endpoints;
pub mod images;
pub mod net_trace;
pub mod repair;
pub mod ring;
pub mod roles;

use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use karyos_io::sockets::endpoint::{SocketsRx, SocketsTx};
use karyos_io::sockets::ops::SocketOps;
use ring::{PostError, Reservation, RingReceiver, RingSender};

/// Which network agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentKind {
    /// The sender agent.
    Sender,
    /// The receiver agent.
    Receiver,
}

/// The SPEC.md §3 threading modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadingMode {
    /// Conductor, sender and receiver each on its own thread.
    Dedicated,
    /// Conductor on one thread, sender and receiver on another.
    SharedNetwork,
    /// Every agent on the caller's thread.
    Shared,
}

/// Errors of the network agents and their runner.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentError {
    /// A configuration value is outside its range.
    #[error("invalid agent configuration: {0}")]
    InvalidConfig(&'static str),
    /// The command ring or the reply slot of the event ring is full.
    #[error("the {0:?} agent's rings are full")]
    Busy(AgentKind),
    /// The agent's rings are disconnected: it stopped or failed.
    #[error("the {0:?} agent is gone")]
    Gone(AgentKind),
    /// A ring invariant broke (a held slot found the ring full, or a
    /// reservation of another ring).
    #[error("ring invariant broken for the {0:?} agent")]
    Invariant(AgentKind),
    /// A work count overflowed.
    #[error("the {0:?} agent's work count overflowed")]
    CountOverflow(AgentKind),
    /// The runner could not start a thread.
    #[error("cannot start an agent thread: {0}")]
    Spawn(String),
    /// [`AgentRunner`] does not run [`ThreadingMode::Shared`]: the caller
    /// drives those agents.
    #[error("the Shared threading mode runs on the caller's thread")]
    SharedMode,
    /// An agent panicked; its thread stopped.
    #[error("the {0:?} agent panicked")]
    Panicked(AgentKind),
}

/// How an agent thread waits after an iteration without work. The driver
/// injects it; `karyos-tools` provides a backoff strategy.
pub trait IdleStrategy: Send {
    /// Called after each iteration with its work count.
    fn idle(&mut self, work: u32);
}

/// The default idle strategy: yields for a few idle iterations, then
/// sleeps up to 1 ms (`quantstratum-docs: karyos/design/sockets-backend.md`
/// 5.3).
#[derive(Debug, Clone, Default)]
pub struct YieldThenSleep {
    idle: u32,
}

impl IdleStrategy for YieldThenSleep {
    fn idle(&mut self, work: u32) {
        if work > 0 {
            self.idle = 0;
        } else if self.idle < 64 {
            self.idle += 1;
            std::thread::yield_now();
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Control ring entries kept for forwarded controls beyond the reserved
/// RSP_SETUP and SM slots (network-sessions.md S5 `control_queue_floor`).
const CONTROL_FLOOR: usize = 32;

/// Configuration of the agents and their rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentConfig {
    /// Entries of each agent's command ring, at least 1.
    pub command_capacity: usize,
    /// Entries of each agent's event ring, at least 1.
    pub event_capacity: usize,
    /// Entries of each session ring between the receiver and the conductor
    /// ([`chain`]), at least `3 * sessions.max_images` (network-sessions.md
    /// S1; default 192).
    pub session_command_capacity: usize,
    /// Commands an agent serves per duty cycle, at least 1.
    pub command_budget: u32,
    /// Endpoint halves each agent holds at once, at least 1.
    pub max_endpoints: usize,
    /// The receiver's session table (network-sessions.md S5).
    pub sessions: crate::sessions::receive::SessionConfig,
    /// Publications the sender announces at once, at least 1.
    pub publications: usize,
    /// `setup_interval` in ns (default 100 ms).
    pub setup_interval: u64,
    /// `setup_answer_rate` and its source table.
    pub answer_rate: crate::sessions::send::AnswerRate,
    /// Entries of the receiver-to-sender control ring, at least 1.
    pub control_capacity: usize,
    /// Control destinations the sender caches per endpoint, at least 1.
    pub control_routes: usize,
    /// Datagrams the receiver reads per endpoint and cycle, at least 1.
    pub rx_datagrams: u32,
    /// Subscribed streams and published aliases the receiver tracks, each
    /// at least 1.
    pub subscriptions: usize,
    /// `rsp_setup_rate_per_destination` (network-control-schemas.md §7.4,
    /// default 20 per second).
    pub rsp_setup_per_destination: u64,
    /// Destinations the per-destination RSP_SETUP rate tracks (default 64).
    pub rsp_setup_destinations: usize,
    /// `rsp_setup_rate` per driver (default 256 per second).
    pub rsp_setup_rate: u64,
    /// `sm_interval` in ns: an installed image's SM cadence (default 10 ms,
    /// multicast-flow-control.md MC-6).
    pub sm_interval: u64,
    /// `image_liveness_timeout` in ns: an image with no evidence from its
    /// binding for this long is retired (default 10 s, network-sessions.md
    /// S5).
    pub image_liveness_timeout: u64,
    /// Receiver bindings the sender tracks (the receivers it answered),
    /// at least 1 (default 64).
    pub receiver_bindings: usize,
    /// `idle_image_timeout` in ns: how long stationary heartbeats (an idle
    /// sender repeating its position) keep an image alive after its last
    /// fresh evidence (default 60 s, at least `image_liveness_timeout`;
    /// coordinator decision, trusted profile).
    pub idle_image_timeout: u64,
    /// The RTT settings: the receiver's probes and the sender's replies
    /// (reliable-transport.md, "RTT observations"; RC-1).
    pub rtt: crate::rtt::RttConfig,
    /// The repair settings of reliable publications (reliable-transport.md;
    /// R4, R5, R7).
    pub repair: repair::RepairConfig,
    /// A multicast image's NAK timing and suppression (reliable-transport.md,
    /// "Timers, retries and suppression"; RC-2 to RC-5, RC-14), with the
    /// design defaults: `nak_delay_scale` 16, `repair_linger` and
    /// `repair_slack` 1 ms, the `group` response domain.
    pub multicast: crate::repair::loss::MulticastConfig,
    /// `group_nak_budget`: control group datagrams the receiver reads per
    /// cycle, at least 1 (default 64, provisional, RC-15).
    pub group_nak_budget: u32,
    /// How long [`AgentRunner::stop`] waits for the agents
    /// (`agent_stop_timeout`).
    pub stop_timeout: Duration,
    /// `barrier_ack_timeout` in ns: how long a conflated image lane's seal
    /// waits for its view's feeder before the fail-safe closes the view
    /// (conflated-network-images.md (c); default 100 ms, an owner flag; at
    /// least ten idle sleeps of a duty loop, 10 ms).
    pub barrier_ack_timeout: u64,
}

impl Default for AgentConfig {
    /// DN-3 and DN-8 defaults: 64 entries per ring, 16 commands per cycle,
    /// 1 s to stop.
    fn default() -> Self {
        Self {
            command_capacity: 64,
            event_capacity: 64,
            session_command_capacity: 192,
            command_budget: 16,
            max_endpoints: 16,
            sessions: crate::sessions::receive::SessionConfig::default(),
            publications: 64,
            setup_interval: 100_000_000,
            answer_rate: crate::sessions::send::AnswerRate::default(),
            control_capacity: 512,
            control_routes: 8,
            rx_datagrams: 64,
            subscriptions: 64,
            rsp_setup_per_destination: 20,
            rsp_setup_destinations: 64,
            rsp_setup_rate: 256,
            sm_interval: 10_000_000,
            image_liveness_timeout: 10_000_000_000,
            receiver_bindings: 64,
            idle_image_timeout: 60_000_000_000,
            rtt: crate::rtt::RttConfig::default(),
            repair: repair::RepairConfig::default(),
            multicast: crate::repair::loss::MulticastConfig::default(),
            group_nak_budget: 64,
            stop_timeout: Duration::from_secs(1),
            barrier_ack_timeout: conflated_gate::DEFAULT_BARRIER_ACK_TIMEOUT_NS,
        }
    }
}

impl AgentConfig {
    /// The ring capacities, checked.
    fn validate(&self) -> Result<(NonZeroUsize, NonZeroUsize, NonZeroUsize), AgentError> {
        let commands = NonZeroUsize::new(self.command_capacity).ok_or(
            AgentError::InvalidConfig("command_capacity must be at least 1"),
        )?;
        let events = NonZeroUsize::new(self.event_capacity).ok_or(AgentError::InvalidConfig(
            "event_capacity must be at least 1",
        ))?;
        if self.command_budget == 0 {
            return Err(AgentError::InvalidConfig(
                "command_budget must be at least 1",
            ));
        }
        if self.publications == 0
            || self.control_capacity == 0
            || self.control_routes == 0
            || self.rx_datagrams == 0
            || self.subscriptions == 0
            || self.rsp_setup_per_destination == 0
            || self.rsp_setup_destinations == 0
            || self.rsp_setup_rate == 0
            || self.sm_interval == 0
            || self.image_liveness_timeout == 0
            || self.receiver_bindings == 0
        {
            return Err(AgentError::InvalidConfig(
                "a network capacity or budget is zero",
            ));
        }
        if self.max_endpoints == 0 {
            return Err(AgentError::InvalidConfig(
                "max_endpoints must be at least 1",
            ));
        }
        // Each publication's membership follows the SM cadence and the
        // image liveness (multicast-flow-control.md MC-6).
        roles::MembershipTiming::of(self)
            .config(1, 32, 32)
            .validate()
            .map_err(|_| {
                AgentError::InvalidConfig(
                    "image_liveness_timeout below ten sm_interval, or idle_image_timeout below it",
                )
            })?;
        self.rtt
            .validate()
            .map_err(|_| AgentError::InvalidConfig("invalid RTT configuration"))?;
        // RTT snapshots lie between the floor and the probe timeout (the
        // RTT configuration checks `rtt_floor <= rtt_initial <=
        // rtt_probe_timeout` above).
        self.multicast
            .validate_for(self.rtt.rtt_floor, self.rtt.rtt_probe_timeout)
            .map_err(|_| AgentError::InvalidConfig("invalid multicast NAK timing"))?;
        if self.group_nak_budget == 0 {
            return Err(AgentError::InvalidConfig(
                "group_nak_budget must be at least 1",
            ));
        }
        // S1: the control ring holds every pending challenge's RSP_SETUP
        // and an SM copy per path of every image (RP-7: an SM goes on each
        // live path), above a floor for forwarded controls.
        let control = self
            .sessions
            .max_images
            .checked_mul(usize::from(self.sessions.max_paths))
            .and_then(|units| units.checked_add(self.sessions.max_pending_challenges))
            .and_then(|units| units.checked_add(CONTROL_FLOOR))
            .ok_or(AgentError::InvalidConfig("max_images too large"))?;
        if self.control_capacity < control {
            return Err(AgentError::InvalidConfig(
                "control_capacity below max_pending_challenges + max_images * max_paths + 32",
            ));
        }
        if self.barrier_ack_timeout < conflated_gate::MIN_BARRIER_ACK_TIMEOUT_NS {
            return Err(AgentError::InvalidConfig(
                "barrier_ack_timeout must be at least 10 ms",
            ));
        }
        if self.idle_image_timeout < self.image_liveness_timeout {
            return Err(AgentError::InvalidConfig(
                "idle_image_timeout below image_liveness_timeout",
            ));
        }
        // S1: three units per image in flight on each session ring.
        let chains = self
            .sessions
            .max_images
            .checked_mul(3)
            .ok_or(AgentError::InvalidConfig("max_images too large"))?;
        let sessions = NonZeroUsize::new(self.session_command_capacity)
            .filter(|capacity| capacity.get() >= chains)
            .ok_or(AgentError::InvalidConfig(
                "session_command_capacity must be at least 3 * max_images",
            ))?;
        Ok((commands, events, sessions))
    }
}

/// Names an endpoint of the conductor's table: never reused within a
/// driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointId(pub u32);

/// One half of a split endpoint (`quantstratum-docs:
/// karyos/design/sockets-backend.md` 3.10): the sender agent holds TX
/// halves, the receiver agent RX halves. Boxed on the control path (open
/// and reset), so commands and events stay small; agents only move it.
#[derive(Debug)]
pub enum Half<O: SocketOps> {
    /// The TX half.
    Tx(Box<SocketsTx<O>>),
    /// The RX half.
    Rx(Box<SocketsRx<O>>),
}

impl<O: SocketOps> Half<O> {
    /// The agent that holds this half.
    #[must_use]
    pub fn agent(&self) -> AgentKind {
        match self {
            Half::Tx(_) => AgentKind::Sender,
            Half::Rx(_) => AgentKind::Receiver,
        }
    }
}

/// A conductor command. Each carries the reservation of its reply.
#[derive(Debug)]
pub enum AgentCommand<O: SocketOps> {
    /// Answer with [`AgentEvent::Pong`] carrying `token`.
    Ping {
        /// The reply's slot.
        reply: Reservation,
        /// Echoed in the reply.
        token: u64,
    },
    /// Hold `half` of `endpoint`: answer [`AgentEvent::Attached`], or
    /// [`AgentEvent::Refused`] with the half (the wrong agent's half, a
    /// full table or an endpoint already held).
    Attach {
        /// The reply's slot.
        reply: Reservation,
        /// The endpoint.
        endpoint: EndpointId,
        /// Its half for this agent.
        half: Half<O>,
    },
    /// Hand back the half of `endpoint`: answer [`AgentEvent::Detached`].
    Detach {
        /// The reply's slot.
        reply: Reservation,
        /// The endpoint.
        endpoint: EndpointId,
    },
    /// Receiver only: challenge SETUP for `stream_id` on `endpoint` (a
    /// stream this driver subscribes to, network-control-schemas.md §6.2
    /// step 2). Answer [`AgentEvent::Configured`].
    AddSubscription {
        /// The reply's slot.
        reply: Reservation,
        /// The endpoint.
        endpoint: EndpointId,
        /// The subscribed stream.
        stream_id: i32,
        /// The largest image term length this subscription accepts: an
        /// ANNOUNCE above it is refused before any challenge (the channel's
        /// `max_image_term_length`, or the driver default
        /// [`images::DEFAULT_MAX_IMAGE_TERM_LENGTH`]). A second
        /// subscription of the same stream on the same endpoint keeps the
        /// smaller of the two limits.
        max_term_length: u32,
        /// Whether the channel is reliable (its `reliable` URI parameter,
        /// SPEC §5, default true): its images repair losses with NAKs;
        /// otherwise the skip policy seals them. Two subscriptions of one
        /// stream on one endpoint are reliable if either is. A reliable
        /// subscription to a `reliable=false` publication is a
        /// configuration error: the sender drops its NAKs, and a loss
        /// stalls the image with counted NAK retries (`nak_retries`) until
        /// its liveness timeout. (The far-window close applies to
        /// unreliable images only, GU-6.)
        reliable: bool,
        /// Whether the endpoint receives a multicast group: its images
        /// time their NAKs by cycle (RC-2) with
        /// [`AgentConfig::multicast`].
        multicast: bool,
        /// The endpoint joined to the data group's NAK control group, and
        /// the group's address (RC-7, RC-15): its images send a copy of
        /// each NAK there and read their peers' NAKs from it. `None`
        /// without one: no peer suppression input.
        control_group: Option<(EndpointId, std::net::SocketAddr)>,
        /// The receiver identity its images name (MC-1, MC-2); `None` for
        /// an id derived from each image's slot and tag 0.
        identity: Option<crate::membership::ReceiverIdentity>,
        /// The lane of its images a conflated view reads
        /// (conflated-network-images.md (a)): the receiver gates that
        /// lane's seals through the view's barrier mailbox. `None`: no
        /// view, the seals as before.
        conflated: Option<karyos_sys::frame::Lane>,
    },
    /// Receiver only: `alias` on `endpoint` is a local publication, so
    /// controls for it go to the sender (the pre-filter of DN-4). Answer
    /// [`AgentEvent::Configured`].
    AddPublishedAlias {
        /// The reply's slot.
        reply: Reservation,
        /// The endpoint.
        endpoint: EndpointId,
        /// The publication's alias.
        alias: karyos_protocol::network::Alias,
    },
    /// Sender only: start announcing `publication` to `destination` (the
    /// channel route); `joins` are its join points until the sender reads
    /// its log (phase 5). Answer [`AgentEvent::PublicationAdded`] or
    /// [`AgentEvent::PublicationRefused`].
    AddPublication {
        /// The reply's slot.
        reply: Reservation,
        /// The publication incarnation.
        publication: crate::sessions::send::Publication,
        /// Its data path: one reader per lane, the channel destination and
        /// the lane quanta, built by the conductor ([`data::Outbound::new`]).
        outbound: Box<data::Outbound>,
        /// A guarded publication's guard ([`data::Outbound::guard`]);
        /// `None` for an unguarded one.
        guard: Option<data::GuardSpec>,
        /// Its receivers' configured roles and strategy (MC-1); `None` for
        /// the `min` strategy with no required or tagged receiver.
        roles: Option<Box<crate::membership::PublicationRoles>>,
    },
    /// Set the agent's network trace hook, or remove it with `None`
    /// (P2.12 step 3). Journals still open close through the previous hook
    /// first. Answer [`AgentEvent::NetworkTraceSet`].
    SetNetworkTrace {
        /// The reply's slot.
        reply: Reservation,
        /// The new hook.
        hook: Option<net_trace::TraceHook>,
    },
    /// Write `journal` for its publication and lane: on the sender, the
    /// publication `alias` on `endpoint`. Answer
    /// [`AgentEvent::NetworkJournalOpened`] with the start, or
    /// [`AgentEvent::NetworkJournalRefused`] with the journal (no hook, the
    /// wrong side, no such publication or lane, or a lane already traced).
    OpenNetworkJournal {
        /// The reply's slot.
        reply: Reservation,
        /// The endpoint.
        endpoint: EndpointId,
        /// The publication's alias.
        alias: karyos_protocol::network::Alias,
        /// The journal the conductor created.
        journal: karyos_protocol::trace_hook::NetJournal,
    },
    /// Close the journal of `lane` of `publication`. Answer
    /// [`AgentEvent::NetworkJournalClosed`].
    CloseNetworkJournal {
        /// The reply's slot.
        reply: Reservation,
        /// The publication.
        publication: karyos_protocol::trace_hook::PublicationIdentity,
        /// The lane.
        lane: karyos_protocol::frame::Lane,
    },
    /// Receiver only: stop subscribing `stream_id` on `endpoint`: no new
    /// image is challenged for it, and its images retire. Answer
    /// [`AgentEvent::Configured`], `accepted` when it was subscribed.
    RemoveSubscription {
        /// The reply's slot.
        reply: Reservation,
        /// The endpoint.
        endpoint: EndpointId,
        /// The stream.
        stream_id: i32,
    },
    /// Receiver only: `alias` on `endpoint` is no longer a local
    /// publication, so the pre-filter stops admitting its controls.
    /// Answer [`AgentEvent::Configured`], `accepted` when it was there.
    RemovePublishedAlias {
        /// The reply's slot.
        reply: Reservation,
        /// The endpoint.
        endpoint: EndpointId,
        /// The publication's alias.
        alias: karyos_protocol::network::Alias,
    },
    /// Sender only: stop sending `alias` on `endpoint` and hand its data
    /// path back (wiring note W-d), so its readers drop on the control
    /// path. Answer [`AgentEvent::PublicationRemoved`].
    RemovePublication {
        /// The reply's slot.
        reply: Reservation,
        /// The endpoint.
        endpoint: EndpointId,
        /// The publication's alias.
        alias: karyos_protocol::network::Alias,
        /// Its registration, echoed in the answer.
        registration: u64,
    },
    /// Test only: panic in the duty cycle.
    #[cfg(test)]
    Panic,
    /// Test only: block the duty cycle until the flag is cleared.
    #[cfg(test)]
    Block(Arc<AtomicBool>),
    /// Test only, sender: mark the publication `alias` on `endpoint` as
    /// needing an endpoint reset, as a send fault would (W4 E2).
    #[cfg(test)]
    ForceReset {
        /// The endpoint.
        endpoint: EndpointId,
        /// The publication's alias.
        alias: karyos_protocol::network::Alias,
    },
}

/// An agent's event to the conductor.
#[derive(Debug)]
pub enum AgentEvent<O: SocketOps> {
    /// The reply to a ping.
    Pong {
        /// The agent.
        agent: AgentKind,
        /// The ping's token.
        token: u64,
    },
    /// The agent saw its stop flag (best effort: posted only when the ring
    /// has a free slot; the runner's join is the authority).
    Stopped {
        /// The agent.
        agent: AgentKind,
    },
    /// The agent holds the endpoint's half.
    Attached {
        /// The agent.
        agent: AgentKind,
        /// The endpoint.
        endpoint: EndpointId,
    },
    /// The agent refused the half, which comes back.
    Refused {
        /// The agent.
        agent: AgentKind,
        /// The endpoint.
        endpoint: EndpointId,
        /// The refused half.
        half: Half<O>,
    },
    /// The agent handed back the endpoint's half; `None` if it held none.
    Detached {
        /// The agent.
        agent: AgentKind,
        /// The endpoint.
        endpoint: EndpointId,
        /// The half.
        half: Option<Half<O>>,
    },
    /// The sender announces the publication.
    PublicationAdded {
        /// The endpoint.
        endpoint: EndpointId,
        /// Its alias.
        alias: karyos_protocol::network::Alias,
        /// Its registration (`Identity::registration_id`).
        registration: u64,
    },
    /// The sender stopped the publication; `outbound` is its data path,
    /// `None` when it held no such publication.
    PublicationRemoved {
        /// The endpoint.
        endpoint: EndpointId,
        /// Its alias.
        alias: karyos_protocol::network::Alias,
        /// The registration the command named.
        registration: u64,
        /// The data path, dropped by the conductor.
        outbound: Option<Box<data::Outbound>>,
    },
    /// The agent refused the publication (the wrong agent, a full table or
    /// a duplicate alias).
    PublicationRefused {
        /// The agent.
        agent: AgentKind,
        /// The endpoint.
        endpoint: EndpointId,
        /// Its alias.
        alias: karyos_protocol::network::Alias,
        /// Its registration (`Identity::registration_id`).
        registration: u64,
    },
    /// The answer to a receiver configuration command: `accepted` is false
    /// when its table is full.
    Configured {
        /// The agent.
        agent: AgentKind,
        /// Whether the entry was added (or was already there).
        accepted: bool,
        /// The endpoint and stream of an `AddSubscription`'s answer; `None`
        /// for the other configuration commands.
        subscription: Option<(EndpointId, i32)>,
    },
    /// The agent holds the new network trace hook.
    NetworkTraceSet {
        /// The agent.
        agent: AgentKind,
        /// The hook it replaced, dropped on the control path.
        previous: Option<net_trace::TraceHook>,
        /// Journals still open that it closed through the previous hook,
        /// without facts; the conductor treats each as `Lost` (closed
        /// without a boundary). `None` if the count overflowed.
        closed: Option<u64>,
    },
    /// The agent writes the journal from `start`, its next position on the
    /// lane when the journal arrived (the start fact, trace-network.md §5).
    NetworkJournalOpened {
        /// The agent.
        agent: AgentKind,
        /// The publication.
        publication: karyos_protocol::trace_hook::PublicationIdentity,
        /// The lane.
        lane: karyos_protocol::frame::Lane,
        /// The journal number.
        number: u64,
        /// The start.
        start: u64,
    },
    /// The agent cannot write the journal, which comes back.
    NetworkJournalRefused {
        /// The agent.
        agent: AgentKind,
        /// The journal.
        journal: karyos_protocol::trace_hook::NetJournal,
    },
    /// The agent closed the journal; `facts` is `None` when it had none
    /// open for the publication and lane.
    NetworkJournalClosed {
        /// The agent.
        agent: AgentKind,
        /// The publication.
        publication: karyos_protocol::trace_hook::PublicationIdentity,
        /// The lane.
        lane: karyos_protocol::frame::Lane,
        /// Its start and boundary.
        facts: Option<net_trace::JournalFacts>,
    },
    /// The agent does not serve this command.
    Unsupported {
        /// The agent.
        agent: AgentKind,
    },
    /// An agent asks for an endpoint reset: on the sender, a publication on
    /// `endpoint` needs one before it can send again
    /// (`Outbound::needs_reset`); on the receiver, a route fault holds an
    /// image's NAKs (RC-6). Posted unsolicited into a free slot, and again
    /// every `RESET_REQUEST_CYCLES` cycles while the need holds; the
    /// endpoint table ignores it unless the endpoint is active.
    ResetRequested {
        /// The endpoint.
        endpoint: EndpointId,
    },
}

/// What an agent has from the conductor: its rings, its stop flag and its
/// state.
#[derive(Debug)]
struct AgentCore<O: SocketOps> {
    kind: AgentKind,
    commands: RingReceiver<AgentCommand<O>>,
    events: RingSender<AgentEvent<O>>,
    budget: u32,
    stop: Arc<AtomicBool>,
    stopped: bool,
    /// The endpoint halves this agent holds, at most `max_endpoints`
    /// (allocated at creation).
    halves: Vec<(EndpointId, Half<O>)>,
    /// The most halves the agent holds (`AgentConfig::max_endpoints`).
    max_endpoints: usize,
    /// Test only: records each duty cycle's agent, in call order.
    #[cfg(test)]
    calls: Option<Arc<std::sync::Mutex<Vec<AgentKind>>>>,
}

impl<O: SocketOps> AgentCore<O> {
    /// One duty cycle: the stop flag first, then up to the budget's
    /// commands; returns how many were served.
    fn serve_commands(
        &mut self,
        role: &mut dyn FnMut(AgentCommand<O>) -> Option<(Reservation, AgentEvent<O>)>,
    ) -> Result<u32, AgentError> {
        #[cfg(test)]
        if let Some(calls) = &self.calls
            && let Ok(mut calls) = calls.lock()
        {
            calls.push(self.kind);
        }
        if self.stopped {
            return Ok(0);
        }
        if self.stop.load(Ordering::Acquire) {
            self.stopped = true;
            // Informational: the runner's join decides that the agent
            // stopped.
            let _ = self
                .events
                .try_post(AgentEvent::Stopped { agent: self.kind });
            return Ok(0);
        }
        let mut served = 0u32;
        while served < self.budget {
            let command = match self.commands.try_take() {
                Ok(Some(command)) => command,
                Ok(None) => break,
                // The conductor is gone: stop, there is nobody to serve.
                Err(_) => {
                    self.stopped = true;
                    break;
                }
            };
            served = served
                .checked_add(1)
                .ok_or(AgentError::CountOverflow(self.kind))?;
            match command {
                AgentCommand::Ping { reply, token } => {
                    let event = AgentEvent::Pong {
                        agent: self.kind,
                        token,
                    };
                    if self.reply(reply, event)? {
                        break;
                    }
                }
                AgentCommand::Attach {
                    reply,
                    endpoint,
                    half,
                } => {
                    let event = if half.agent() != self.kind
                        || self.halves.len() >= self.max_endpoints
                        || self.halves.iter().any(|(held, _)| *held == endpoint)
                    {
                        AgentEvent::Refused {
                            agent: self.kind,
                            endpoint,
                            half,
                        }
                    } else {
                        self.halves.push((endpoint, half));
                        AgentEvent::Attached {
                            agent: self.kind,
                            endpoint,
                        }
                    };
                    if self.reply(reply, event)? {
                        break;
                    }
                }
                AgentCommand::Detach { reply, endpoint } => {
                    let half = self
                        .halves
                        .iter()
                        .position(|(held, _)| *held == endpoint)
                        .map(|index| self.halves.swap_remove(index).1);
                    let event = AgentEvent::Detached {
                        agent: self.kind,
                        endpoint,
                        half,
                    };
                    if self.reply(reply, event)? {
                        break;
                    }
                }
                command @ (AgentCommand::AddPublication { .. }
                | AgentCommand::RemovePublication { .. }
                | AgentCommand::RemovePublishedAlias { .. }
                | AgentCommand::RemoveSubscription { .. }
                | AgentCommand::AddSubscription { .. }
                | AgentCommand::AddPublishedAlias { .. }
                | AgentCommand::SetNetworkTrace { .. }
                | AgentCommand::OpenNetworkJournal { .. }
                | AgentCommand::CloseNetworkJournal { .. }) => {
                    if let Some((reply, event)) = role(command)
                        && self.reply(reply, event)?
                    {
                        break;
                    }
                }
                #[cfg(test)]
                AgentCommand::Panic => {
                    #[allow(clippy::panic, reason = "test-only command")]
                    {
                        panic!("agent panic requested by a test");
                    }
                }
                #[cfg(test)]
                AgentCommand::Block(flag) => {
                    while flag.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                }
                #[cfg(test)]
                command @ AgentCommand::ForceReset { .. } => {
                    let _ = role(command);
                }
            }
        }
        Ok(served)
    }

    /// Posts a reply into its reserved slot. Returns `true` when the
    /// conductor is gone: the agent stops (a half in the lost reply is
    /// dropped, which closes its descriptor).
    fn reply(&mut self, reply: Reservation, event: AgentEvent<O>) -> Result<bool, AgentError> {
        match self.events.post(reply, event) {
            Ok(()) => Ok(false),
            Err(PostError::Gone(_)) => {
                self.stopped = true;
                Ok(true)
            }
            Err(PostError::Full(_) | PostError::Foreign(_)) => {
                Err(AgentError::Invariant(self.kind))
            }
        }
    }

    /// Takes the halves of the commands still unread in the command ring:
    /// after a stop, an `Attach` the agent never served still carries its
    /// half.
    fn take_unread_halves(&mut self) -> Vec<(EndpointId, Half<O>)> {
        let mut halves = Vec::new();
        while let Ok(Some(command)) = self.commands.try_take() {
            if let AgentCommand::Attach { endpoint, half, .. } = command {
                halves.push((endpoint, half));
            }
        }
        halves
    }

    /// Hands back every half this agent holds.
    fn take_halves(&mut self) -> impl Iterator<Item = (EndpointId, Half<O>)> + '_ {
        self.halves.drain(..)
    }
}

/// The sender agent (`driver-network-agents.md` §3.1). This phase serves
/// conductor commands only.
#[derive(Debug)]
pub struct SenderAgent<O: SocketOps> {
    core: AgentCore<O>,
    role: roles::SenderRole,
}

/// The receiver agent (`driver-network-agents.md` §3.2). This phase
/// serves conductor commands only.
#[derive(Debug)]
pub struct ReceiverAgent<O: SocketOps> {
    core: AgentCore<O>,
    role: roles::ReceiverRole,
    sessions: chain::SessionEnd,
}

impl<O: SocketOps> ReceiverAgent<O> {
    /// The configured identity of the key `(endpoint, stream_id)`
    /// (tests).
    #[cfg(test)]
    pub(crate) fn configured_identity(
        &self,
        endpoint: EndpointId,
        stream_id: i32,
    ) -> Option<crate::membership::ReceiverIdentity> {
        self.role.configured_identity(endpoint, stream_id)
    }
}

impl<O: SocketOps> SenderAgent<O> {
    /// Drops every NAK unread from now on, as a sender that never repairs
    /// (tests).
    #[cfg(test)]
    pub(crate) fn ignore_naks(&mut self) {
        self.role.ignore_naks();
    }

    /// After a stop: the halves of `Attach` commands the agent never read
    /// (DN-8). The conductor reclaims them with the held ones.
    pub fn take_unread_halves(&mut self) -> Vec<(EndpointId, Half<O>)> {
        self.core.take_unread_halves()
    }

    /// Hands back every endpoint half the agent holds, for the conductor
    /// to join and retire after a stop (DN-8).
    pub fn take_halves(&mut self) -> impl Iterator<Item = (EndpointId, Half<O>)> + '_ {
        self.core.take_halves()
    }

    /// One duty cycle at `now` (driver clock, ns); returns its work count.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invariant`] or [`AgentError::CountOverflow`].
    pub fn do_work(&mut self, now: u64) -> Result<u32, AgentError> {
        let Self { core, role } = self;
        let served = core.serve_commands(&mut |command| role.command(command))?;
        if core.stopped {
            return Ok(served);
        }
        let work = role.duty(&mut core.halves, now)?;
        // A full ring drops the request; the next cycle asks again.
        let events = &core.events;
        role.request_resets(|endpoint| {
            events
                .try_post(AgentEvent::ResetRequested { endpoint })
                .is_ok()
        });
        served
            .checked_add(work)
            .ok_or(AgentError::CountOverflow(AgentKind::Sender))
    }

    /// The sender's counters.
    #[must_use]
    pub fn counters(&self) -> roles::SenderCounters {
        self.role.counters()
    }

    /// Whether the agent stopped: its flag was set or its conductor is
    /// gone.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.core.stopped
    }
}

impl<O: SocketOps> ReceiverAgent<O> {
    /// Drops the DATA datagrams numbered `nth` (from 0) from now on at the
    /// intake, as a lossy path would (tests).
    #[cfg(test)]
    pub(crate) fn drop_data(&mut self, nth: &[u64]) {
        self.role.drop_data(nth);
    }

    /// After a stop: the halves of `Attach` commands the agent never read
    /// (DN-8). The conductor reclaims them with the held ones.
    pub fn take_unread_halves(&mut self) -> Vec<(EndpointId, Half<O>)> {
        self.core.take_unread_halves()
    }

    /// Hands back every endpoint half the agent holds, for the conductor
    /// to join and retire after a stop (DN-8).
    pub fn take_halves(&mut self) -> impl Iterator<Item = (EndpointId, Half<O>)> + '_ {
        self.core.take_halves()
    }

    /// One duty cycle at `now` (driver clock, ns); returns its work count.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invariant`] or [`AgentError::CountOverflow`].
    pub fn do_work(&mut self, now: u64) -> Result<u32, AgentError> {
        let Self {
            core,
            role,
            sessions,
        } = self;
        let overflow = AgentError::CountOverflow(AgentKind::Receiver);
        // Session commands before conductor commands, and both before
        // queued datagrams (§3.2 step 1, S1).
        let chains = if core.stopped {
            0
        } else {
            role.serve_sessions(sessions, now)?
        };
        let served = core.serve_commands(&mut |command| role.command(command))?;
        let served = served.checked_add(chains).ok_or(overflow.clone())?;
        if core.stopped {
            return Ok(served);
        }
        let work = role.duty(&mut core.halves, sessions, now)?;
        // A route fault asks for the endpoint's reset (RC-6); a full ring
        // drops the request and a later cycle asks again.
        let events = &core.events;
        role.request_resets(|endpoint| {
            events
                .try_post(AgentEvent::ResetRequested { endpoint })
                .is_ok()
        });
        served.checked_add(work).ok_or(overflow)
    }

    /// The receiver's counters.
    #[must_use]
    pub fn counters(&self) -> roles::ReceiverCounters {
        self.role.counters()
    }

    /// Whether the receiver's entry for `stream_id` on `endpoint` is
    /// multicast, if it has one (tests).
    #[cfg(test)]
    pub(crate) fn subscription_multicast(
        &self,
        endpoint: EndpointId,
        stream_id: i32,
    ) -> Option<bool> {
        self.role.subscription_multicast(endpoint, stream_id)
    }

    /// Whether the agent stopped: its flag was set or its conductor is
    /// gone.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.core.stopped
    }
}

/// Both network agents, driven together: the Shared mode's object, and
/// the Shared network mode's thread. The receiver runs first, so control
/// it posts leaves in the same iteration.
#[derive(Debug)]
pub struct NetworkAgents<O: SocketOps> {
    /// The sender agent.
    pub sender: SenderAgent<O>,
    /// The receiver agent.
    pub receiver: ReceiverAgent<O>,
}

impl<O: SocketOps> NetworkAgents<O> {
    /// One iteration: the receiver's duty cycle, then the sender's.
    ///
    /// # Errors
    ///
    /// The first agent error.
    pub fn do_work(&mut self, now: u64) -> Result<u32, AgentError> {
        let received = self.receiver.do_work(now)?;
        let sent = self.sender.do_work(now)?;
        received
            .checked_add(sent)
            .ok_or(AgentError::CountOverflow(AgentKind::Sender))
    }

    /// Whether both agents stopped.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.sender.is_stopped() && self.receiver.is_stopped()
    }

    /// Test only: records every duty cycle's agent into `calls`.
    #[cfg(test)]
    fn record_calls(&mut self, calls: &Arc<std::sync::Mutex<Vec<AgentKind>>>) {
        self.sender.core.calls = Some(Arc::clone(calls));
        self.receiver.core.calls = Some(Arc::clone(calls));
    }
}

/// The conductor's end of one agent's rings and its stop flag.
#[derive(Debug)]
pub struct AgentLink<O: SocketOps> {
    kind: AgentKind,
    commands: RingSender<AgentCommand<O>>,
    events: RingSender<AgentEvent<O>>,
    received: RingReceiver<AgentEvent<O>>,
    stop: Arc<AtomicBool>,
}

impl<O: SocketOps> AgentLink<O> {
    /// Reserves a command slot and its reply slot, so that commands to
    /// several agents can be committed together or not at all.
    ///
    /// # Errors
    ///
    /// [`AgentError::Busy`] when either slot is missing.
    pub fn prepare(&self) -> Result<Prepared, AgentError> {
        let busy = AgentError::Busy(self.kind);
        let reply = self.events.reserve().ok_or(busy.clone())?;
        let slot = self.commands.reserve().ok_or(busy)?;
        Ok(Prepared { reply, slot })
    }

    /// Posts the command `make` builds around the reply's reservation into
    /// the prepared slot.
    ///
    /// # Errors
    ///
    /// [`AgentError::Gone`] when the agent is gone, [`AgentError::Invariant`]
    /// for a broken ring invariant.
    pub fn commit(
        &self,
        prepared: Prepared,
        make: impl FnOnce(Reservation) -> AgentCommand<O>,
    ) -> Result<(), AgentError> {
        self.commands
            .post(prepared.slot, make(prepared.reply))
            .map_err(|error| match error {
                PostError::Gone(_) => AgentError::Gone(self.kind),
                PostError::Full(_) | PostError::Foreign(_) => AgentError::Invariant(self.kind),
            })
    }

    /// Posts the command `make` builds around its reply's reservation.
    /// Nothing is posted when a slot is missing.
    ///
    /// # Errors
    ///
    /// [`AgentError::Busy`] when the command ring or the reply slot is
    /// full, [`AgentError::Gone`] when the agent is gone,
    /// [`AgentError::Invariant`] for a broken ring invariant.
    pub fn post(
        &self,
        make: impl FnOnce(Reservation) -> AgentCommand<O>,
    ) -> Result<(), AgentError> {
        let prepared = self.prepare()?;
        self.commit(prepared, make)
    }

    /// Posts a ping carrying `token`.
    ///
    /// # Errors
    ///
    /// As [`AgentLink::post`].
    pub fn ping(&self, token: u64) -> Result<(), AgentError> {
        self.post(|reply| AgentCommand::Ping { reply, token })
    }

    /// Asks the agent to stop at its next cycle. It cannot be refused: a
    /// flag, not a command.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// Takes the agent's oldest event.
    #[must_use]
    pub fn take_event(&self) -> Option<AgentEvent<O>> {
        self.received.try_take().ok().flatten()
    }

    /// The agent.
    #[must_use]
    pub fn kind(&self) -> AgentKind {
        self.kind
    }
}

/// A command slot and its reply slot, reserved by [`AgentLink::prepare`].
#[derive(Debug)]
pub struct Prepared {
    reply: Reservation,
    slot: Reservation,
}

/// The conductor's links to both agents.
#[derive(Debug)]
pub struct AgentLinks<O: SocketOps> {
    /// The sender agent's link.
    pub sender: AgentLink<O>,
    /// The receiver agent's link.
    pub receiver: AgentLink<O>,
    /// The session rings to the receiver ([`chain`]).
    pub sessions: chain::SessionLink,
}

/// Creates both agents and the conductor's links to them. Every ring is
/// allocated here; the duty cycles allocate nothing.
///
/// # Errors
///
/// [`AgentError::InvalidConfig`] for a zero capacity or budget.
pub fn network_agents<O: SocketOps>(
    config: AgentConfig,
) -> Result<(NetworkAgents<O>, AgentLinks<O>), AgentError> {
    let (command_capacity, event_capacity, session_command_capacity) = config.validate()?;
    let make = |kind| {
        let (commands, command_receiver) = ring::ring(command_capacity);
        let (events, event_receiver) = ring::ring(event_capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let core = AgentCore {
            kind,
            commands: command_receiver,
            events: events.clone_sender(),
            budget: config.command_budget,
            stop: Arc::clone(&stop),
            stopped: false,
            halves: Vec::with_capacity(config.max_endpoints),
            max_endpoints: config.max_endpoints,
            #[cfg(test)]
            calls: None,
        };
        let link = AgentLink {
            kind,
            commands,
            events,
            received: event_receiver,
            stop,
        };
        (core, link)
    };
    let (sender_core, sender_link) = make(AgentKind::Sender);
    let (receiver_core, receiver_link) = make(AgentKind::Receiver);
    let (sender_role, receiver_role) = roles::roles(&config)?;
    let (session_end, session_link) = chain::session_rings(session_command_capacity);
    Ok((
        NetworkAgents {
            sender: SenderAgent {
                core: sender_core,
                role: sender_role,
            },
            receiver: ReceiverAgent {
                core: receiver_core,
                role: receiver_role,
                sessions: session_end,
            },
        },
        AgentLinks {
            sender: sender_link,
            receiver: receiver_link,
            sessions: session_link,
        },
    ))
}

/// An agent's state as the runner publishes it.
const RUNNING: u8 = 0;
const STOPPED: u8 = 1;
const FAILED: u8 = 2;

/// What a runner thread drives.
#[derive(Debug)]
enum Work<O: SocketOps> {
    /// Every variant is boxed: the agents are large, and the runner builds
    /// this once, at start.
    Sender(Box<SenderAgent<O>>),
    Receiver(Box<ReceiverAgent<O>>),
    Both(Box<NetworkAgents<O>>),
}

/// Runs one agent's duty cycle, turning a panic into
/// [`AgentError::Panicked`] for that agent.
pub(crate) fn guarded(
    kind: AgentKind,
    cycle: impl FnOnce() -> Result<u32, AgentError>,
) -> Result<u32, AgentError> {
    catch_unwind(AssertUnwindSafe(cycle)).unwrap_or(Err(AgentError::Panicked(kind)))
}

impl<O: SocketOps> Work<O> {
    fn do_work(&mut self, now: u64) -> Result<u32, AgentError> {
        match self {
            Work::Sender(agent) => guarded(AgentKind::Sender, || agent.do_work(now)),
            Work::Receiver(agent) => guarded(AgentKind::Receiver, || agent.do_work(now)),
            Work::Both(agents) => {
                // The receiver first, as `NetworkAgents::do_work`.
                let received = guarded(AgentKind::Receiver, || agents.receiver.do_work(now))?;
                let sent = guarded(AgentKind::Sender, || agents.sender.do_work(now))?;
                received
                    .checked_add(sent)
                    .ok_or(AgentError::CountOverflow(AgentKind::Sender))
            }
        }
    }

    fn is_stopped(&self) -> bool {
        match self {
            Work::Sender(agent) => agent.is_stopped(),
            Work::Receiver(agent) => agent.is_stopped(),
            Work::Both(agents) => agents.is_stopped(),
        }
    }
}

/// A runner thread's result: its agents and the failure that stopped it,
/// if any. `None` when the thread was never given work.
type ThreadResult<O> = Option<(Work<O>, Option<AgentError>)>;

/// One runner thread: the agents it drives and its state cell.
#[derive(Debug)]
struct AgentThread<O: SocketOps> {
    kinds: Vec<AgentKind>,
    state: Arc<AtomicU8>,
    handle: JoinHandle<ThreadResult<O>>,
}

/// The threads of the Dedicated and Shared network modes (DN-2).
#[derive(Debug)]
pub struct AgentRunner<O: SocketOps> {
    threads: Vec<AgentThread<O>>,
    stops: [Arc<AtomicBool>; 2],
    stop_timeout: Duration,
}

/// Why [`AgentRunner::start`] failed. The agents come back, unstarted.
#[derive(Debug)]
pub struct StartError<O: SocketOps> {
    /// What failed.
    pub error: AgentError,
    /// The agents, as they were given ([`Stopped::into_agents`]).
    pub agents: Stopped<O>,
}

/// What [`AgentRunner::stop`] got back.
#[derive(Debug)]
pub struct Stopped<O: SocketOps> {
    /// The sender agent, unless its thread is late or lost it.
    pub sender: Option<SenderAgent<O>>,
    /// The receiver agent, unless its thread is late or lost it.
    pub receiver: Option<ReceiverAgent<O>>,
    /// The failures that stopped threads (DN-9).
    pub failures: Vec<AgentError>,
    /// Threads still running after the timeout, for the conductor to wait
    /// on or abandon.
    pub late: Vec<LateAgent<O>>,
}

impl<O: SocketOps> Default for Stopped<O> {
    fn default() -> Self {
        Self {
            sender: None,
            receiver: None,
            failures: Vec::new(),
            late: Vec::new(),
        }
    }
}

impl<O: SocketOps> Stopped<O> {
    /// Both agents, when both came back.
    #[must_use]
    pub fn into_agents(self) -> Option<NetworkAgents<O>> {
        Some(NetworkAgents {
            sender: self.sender?,
            receiver: self.receiver?,
        })
    }

    fn take(&mut self, work: Work<O>) {
        match work {
            Work::Sender(agent) => self.sender = Some(*agent),
            Work::Receiver(agent) => self.receiver = Some(*agent),
            Work::Both(agents) => {
                self.sender = Some(agents.sender);
                self.receiver = Some(agents.receiver);
            }
        }
    }

    fn absorb(&mut self, thread: AgentThread<O>) {
        let kind = thread.kinds.first().copied().unwrap_or(AgentKind::Receiver);
        match thread.handle.join() {
            Ok(Some((work, failure))) => {
                self.take(work);
                self.failures.extend(failure);
            }
            Ok(None) => {}
            // A panic outside a duty cycle: the agent is lost with it.
            Err(_) => self.failures.push(AgentError::Panicked(kind)),
        }
    }
}

/// A runner thread that did not stop within the timeout.
#[derive(Debug)]
pub struct LateAgent<O: SocketOps> {
    thread: AgentThread<O>,
}

impl<O: SocketOps> LateAgent<O> {
    /// The agents it drives.
    #[must_use]
    pub fn kinds(&self) -> &[AgentKind] {
        &self.thread.kinds
    }

    /// Whether it has stopped since.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.thread.handle.is_finished()
    }

    /// Waits for it to stop and takes its agents back.
    #[must_use]
    pub fn join(self) -> Stopped<O> {
        let mut stopped = Stopped::default();
        stopped.absorb(self.thread);
        stopped
    }
}

impl<O: SocketOps + Send + 'static> AgentRunner<O> {
    /// Starts the agents' threads in `mode`, each with an idle strategy
    /// from `idle`. Every thread is started before any agent is handed
    /// over, so a failed start leaves nothing running and returns the
    /// agents.
    ///
    /// # Errors
    ///
    /// [`StartError`] with [`AgentError::SharedMode`] for
    /// [`ThreadingMode::Shared`] (the caller drives those agents) or
    /// [`AgentError::Spawn`].
    #[expect(
        clippy::result_large_err,
        reason = "the agents come back by value, as the endpoint halves of SplitError; start is a cold control path call"
    )]
    pub fn start<I: IdleStrategy + 'static>(
        mode: ThreadingMode,
        agents: NetworkAgents<O>,
        config: AgentConfig,
        idle: impl Fn() -> I,
    ) -> Result<Self, StartError<O>> {
        let stops = [
            Arc::clone(&agents.sender.core.stop),
            Arc::clone(&agents.receiver.core.stop),
        ];
        let work = match mode {
            ThreadingMode::Shared => {
                return Err(StartError {
                    error: AgentError::SharedMode,
                    agents: Stopped {
                        sender: Some(agents.sender),
                        receiver: Some(agents.receiver),
                        ..Stopped::default()
                    },
                });
            }
            ThreadingMode::Dedicated => vec![
                (
                    vec![AgentKind::Receiver],
                    Work::Receiver(Box::new(agents.receiver)),
                ),
                (
                    vec![AgentKind::Sender],
                    Work::Sender(Box::new(agents.sender)),
                ),
            ],
            ThreadingMode::SharedNetwork => vec![(
                vec![AgentKind::Receiver, AgentKind::Sender],
                Work::Both(Box::new(agents)),
            )],
        };
        let mut threads = Vec::with_capacity(work.len());
        let mut handoffs = Vec::with_capacity(work.len());
        let mut failure = None;
        for (kinds, _) in &work {
            let state = Arc::new(AtomicU8::new(RUNNING));
            let thread_state = Arc::clone(&state);
            let strategy = idle();
            let (handoff, waiting) = mpsc::channel::<Work<O>>();
            let name = match kinds.as_slice() {
                [AgentKind::Sender] => "karyos-sender",
                [AgentKind::Receiver] => "karyos-receiver",
                _ => "karyos-network",
            };
            let spawned = std::thread::Builder::new()
                .name(name.to_owned())
                .spawn(move || {
                    // No work comes when another thread failed to start.
                    let work = waiting.recv().ok()?;
                    Some(run(work, strategy, &thread_state))
                });
            match spawned {
                Ok(handle) => {
                    threads.push(AgentThread {
                        kinds: kinds.clone(),
                        state,
                        handle,
                    });
                    handoffs.push(handoff);
                }
                Err(error) => {
                    failure = Some(AgentError::Spawn(error.to_string()));
                    break;
                }
            }
        }
        if let Some(error) = failure {
            // Release the started threads without work, and wait for them.
            drop(handoffs);
            for thread in threads {
                let _ = thread.handle.join();
            }
            let mut agents = Stopped::default();
            for (_, work) in work {
                agents.take(work);
            }
            return Err(StartError { error, agents });
        }
        for ((_, work), handoff) in work.into_iter().zip(&handoffs) {
            // The thread waits on its receiver, so the handoff succeeds.
            let _ = handoff.send(work);
        }
        Ok(Self {
            threads,
            stops,
            stop_timeout: config.stop_timeout,
        })
    }

    /// The agents whose thread failed (an error or a panic) so far.
    #[must_use]
    pub fn failed(&self) -> Vec<AgentKind> {
        self.threads
            .iter()
            .filter(|thread| thread.state.load(Ordering::Acquire) == FAILED)
            .flat_map(|thread| thread.kinds.iter().copied())
            .collect()
    }

    /// Stops both agents (DN-8): sets their stop flags, which no full ring
    /// can refuse, waits up to the configured timeout for their threads and
    /// hands the agents back. A thread still running is returned in
    /// [`Stopped::late`]; a `stop_timeout` too large for the clock waits
    /// without a deadline.
    #[must_use]
    pub fn stop(self) -> Stopped<O> {
        for stop in &self.stops {
            stop.store(true, Ordering::Release);
        }
        let deadline = Instant::now().checked_add(self.stop_timeout);
        while deadline.is_none_or(|deadline| Instant::now() < deadline)
            && !self
                .threads
                .iter()
                .all(|thread| thread.handle.is_finished())
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut stopped = Stopped::default();
        for thread in self.threads {
            if thread.handle.is_finished() {
                stopped.absorb(thread);
            } else {
                stopped.late.push(LateAgent { thread });
            }
        }
        stopped
    }
}

/// A runner thread's loop: duty cycles until the agents stop or fail; the
/// agents come back with the failure, if any.
fn run<O: SocketOps, I: IdleStrategy>(
    mut work: Work<O>,
    mut idle: I,
    state: &AtomicU8,
) -> (Work<O>, Option<AgentError>) {
    loop {
        let now = karyos_sys::host_clock::host_monotonic_ns();
        match work.do_work(now) {
            Ok(_) if work.is_stopped() => {
                state.store(STOPPED, Ordering::Release);
                return (work, None);
            }
            Ok(count) => idle.idle(count),
            Err(error) => {
                state.store(FAILED, Ordering::Release);
                return (work, Some(error));
            }
        }
    }
}

#[cfg(test)]
mod tests;
