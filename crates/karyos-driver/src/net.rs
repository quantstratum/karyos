// SPDX-License-Identifier: Apache-2.0

//! The conductor's side of the network agents (`quantstratum-docs:
//! karyos/design/driver-network-agents.md`; wiring note W-b, W-c and W-g,
//! coordinator ACS 15874).
//!
//! - **Ownership (W-b).** `Network` holds the agents' links, the
//!   endpoint table, the image table and the agents themselves: driven by
//!   the conductor's duty cycle in [`ThreadingMode::Shared`], or on their
//!   own threads in the other modes ([`AgentRunner`]).
//! - **Duty (W-c).** Each conductor cycle runs the agents when they share
//!   its thread, then drains their events into the endpoint and image
//!   tables. The network's time base is `host_monotonic_ns` in every
//!   mode: a shared cycle passes it to the agents and the endpoint table,
//!   as runner threads do. The agents also read it directly (their role
//!   clocks: an RTTM REQUEST's or a NAK's start, a reply's `seen`) and
//!   compare those with their cycles' `now`, so one base is required. The
//!   driver's injectable clock times claim deadlines only.
//! - **Failure (W-g, DN-9).** An agent that fails or panics is fatal for
//!   the driver: the duty cycle returns [`DriverError::NetworkAgent`] from
//!   then on, and the failed agents never run again. In `Shared` mode each
//!   agent's cycle is guarded as on a runner thread, so a panic becomes
//!   that error instead of unwinding through the conductor.
//! - **Shutdown (W-g).** `Network::close` stops the agents (their stop
//!   cannot be refused), reclaims every endpoint half and drains the image
//!   table. A thread that does not stop in time is kept, never detached,
//!   and reported. The driver's close stops admitting client commands and
//!   removes its streams around it once streams are wired (W2, W3).
//!
//! - **Publications (W-d, W2).** A network publication's data path goes to
//!   the sender agent with `AddPublication`, after the receiver learns its
//!   alias (`AddPublishedAlias`, the DN-4 pre-filter). Publications share
//!   one send endpoint per local bind, opened on first use and retired
//!   when its last publication is removed. Removing a publication takes
//!   its data path back (`RemovePublication`), so its lane readers drop on
//!   the control path.
//! - **Subscriptions and images (W-e, W3).** A network subscription binds
//!   its endpoint at the channel's receive address (or the group's port,
//!   joined) and posts `AddSubscription`; removing it posts
//!   `RemoveSubscription`, which retires its images. The image table's
//!   events go to the conductor, which exposes an installed image as the
//!   lane streams of one aggregate (per-source images, D2) and seals
//!   and retires them with the image. An image it cannot expose is still
//!   fed: its lane conductors are driven here until it retires.

use karyos_sys::frame::Lane;
use std::net::{IpAddr, SocketAddr};

use karyos_io::sockets::OsSocket;
use karyos_io::sockets::endpoint::{CapabilitySet, InterfaceSel, MulticastConfig, SocketsConfig};

pub use control_group::{ControlGroup, ControlGroups, MAX_CONTROL_GROUPS};
use karyos_protocol::network::Alias;

use crate::agents::data::{Outbound, TxDemand};
use crate::agents::{AgentCommand, AgentEvent, EndpointId};
use crate::sessions::send::Publication;

use crate::agents::endpoints::Endpoints;
use crate::agents::images::{ImageEvent, ImageTable, ImageTemplate, LaneSource};
use karyos_sys::counters::Counter;

use crate::agents::{
    AgentCells, AgentConfig, AgentError, AgentKind, AgentLinks, AgentRunner, LateAgent,
    NetworkAgents, ThreadingMode, YieldThenSleep, guarded, network_agents_over,
};
use crate::embedded::StreamTerms;
use crate::error::{DriverError, EndpointLimit};
use crate::sessions::receive::SlotRef;
use karyos_sys::log_buffer::{Conductor, LogBuffer};
use karyos_sys::term_bytes::HeapTerms;
use std::sync::Arc;

/// The network configuration of a driver (wiring note W-a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkConfig {
    /// The agents, their rings and their session limits.
    pub agents: AgentConfig,
    /// Where the agents run (SPEC.md §3).
    pub threading: ThreadingMode,
    /// The image log buffers. Its `spare_slots` (default 5) bound the
    /// optional and observer readers of each image lane: the receive
    /// owner holds three of the lane's credits, so the default admits one
    /// such reader, and another is refused with `ResourcesUnavailable`
    /// ([`ImageTemplate::spare_slots`]).
    pub images: ImageTemplate,
    /// The log of a network publication a client creates by channel URI
    /// (W5b): the URI's `term-length`, `mtu` and `lanes` override these.
    /// Validated at start.
    pub stream_defaults: NetworkStreamDefaults,
    /// The NAK control group of each multicast data group (RC-15; an
    /// interim driver-side table until a URI key, ACS 16103). Empty by
    /// default: multicast images then have no peer suppression input.
    pub nak_control_groups: ControlGroups,
    /// Network publications and subscriptions one client may create by
    /// channel URI at once, 1 to 4096;
    /// another is refused with `ResourcesUnavailable` and counted
    /// (`EmbeddedDriver::network_owned_refusals`).
    pub max_owned_per_client: usize,
    /// The tables of each endpoint the driver opens (karyos#859): its TX
    /// slots, queues and routes ([`EndpointTables`]). A publication its
    /// endpoint cannot hold is refused at the add
    /// (`DriverError::EndpointCapacity`).
    pub endpoint_tables: EndpointTables,
    /// The capabilities every endpoint the driver opens must have active
    /// (`[io] require`, R-CORE-43): an endpoint missing one fails to open
    /// (`DriverError::NetworkEndpoint`). Empty by default.
    pub require: CapabilitySet,
}

/// The tables of a network endpoint (karyos#859): what its publications
/// and the sender's control routes share. By default 1024 TX slots, 256
/// queues and 128 routes: about 110 reliable single-lane publications per
/// endpoint, about 1.4 MiB of TX pool (1408-byte datagrams). A reliable
/// single-lane publication takes 9 slots, 2 queues and a route; each
/// endpoint keeps `AgentConfig::control_routes` routes and queues of 4
/// slots for the control routes. Decided 2026-10-29 by QS-COORDINATOR
/// under owner delegation (plan 168's sizing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointTables {
    /// TX slots, 1 to 4096.
    pub tx_slots: std::num::NonZeroU16,
    /// TX queues, 1 to 1024.
    pub max_queues: std::num::NonZeroU16,
    /// Routes, 1 to 1024.
    pub max_routes: std::num::NonZeroU16,
}

impl Default for EndpointTables {
    fn default() -> Self {
        Self {
            tx_slots: std::num::NonZeroU16::new(1024).unwrap_or(std::num::NonZeroU16::MIN),
            max_queues: std::num::NonZeroU16::new(256).unwrap_or(std::num::NonZeroU16::MIN),
            max_routes: std::num::NonZeroU16::new(128).unwrap_or(std::num::NonZeroU16::MIN),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            agents: AgentConfig::default(),
            threading: ThreadingMode::Dedicated,
            images: ImageTemplate::default(),
            stream_defaults: NetworkStreamDefaults::default(),
            nak_control_groups: [None; MAX_CONTROL_GROUPS],
            max_owned_per_client: 16,
            endpoint_tables: EndpointTables::default(),
            require: CapabilitySet::EMPTY,
        }
    }
}

/// The log of a network publication a client creates by URI (W5b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkStreamDefaults {
    /// Term length in bytes, a power of two the log accepts, unless the
    /// URI names one.
    pub term_length: u32,
    /// Frame bytes per datagram, unless the URI names them.
    pub mtu: u32,
    /// Lanes, unless the URI names them.
    pub lanes: u8,
    /// Spare term slots.
    pub spare_slots: u8,
    /// Subscribers of each lane, the sender's reader included.
    pub max_subscribers: u8,
    /// How long a claim may stay open, in the driver clock's unit.
    pub claim_deadline: u64,
    /// `publication_linger` in ns (default 5 s; driver-level, for every
    /// network publication of the driver): how long a removed publication
    /// keeps its incarnation after each lane's EOS at its seal, repeating
    /// the EOS and serving repair (driver-network-agents.md §7). With an
    /// established receiver the linger always runs in full; a removal with
    /// none ends at once (`removals_unestablished`), since nobody would
    /// read its EOS. It also bounds the drain, as one timer from the
    /// removal's start, `max(linger, interval)` with the interval
    /// `AgentConfig::path_heartbeat_interval`: a lane not drained to its
    /// seal by then (a seal never positioned, a faulted reader, a closed
    /// flow-control window, a blocked socket or a detached route) sends no
    /// EOS, the removal is counted (`removals_undrained`, or
    /// `removals_guard_closed` for a lane its guard closed) and the session
    /// is reported drained anyway. The removal ends at the later of `start +
    /// linger` and the latest first EOS plus `linger`, so at worst at
    /// `start + max(linger, interval) + linger`. A linger of 0 still lets a
    /// tail drain within one interval: it sends one EOS on each lane
    /// drained by then, then frees; a lost EOS then falls back to the
    /// receivers' liveness timeout. While a removal lingers, its stream key
    /// stays in use: re-adding it is refused with `DuplicateStream` until
    /// the removal ends, at worst `max(linger, interval) + linger` after it
    /// starts (about 10 s at the defaults). At most 60 s
    /// ([`MAX_PUBLICATION_LINGER`]); a longer one is refused as
    /// `InvalidConfig`.
    pub publication_linger: u64,
    /// Tests only: the `initial_term_id` of every network publication, in
    /// place of the draw. `None`, the default, draws a random one on the
    /// control path for each publication (SPEC §4, initial state; §5).
    #[doc(hidden)]
    pub initial_term_id: Option<u32>,
    /// The streams whose network publications a client creates by URI are
    /// timed: each lane gets a schedule ring of that many entries, which
    /// the sender releases as it sends (karyosd `--timed-network`; owner
    /// item 65). A driver stream never is: [`EmbeddedDriver::add_stream`]
    /// refuses a schedule ring, which nothing would release. At most
    /// [`MAX_TIMED_NETWORK_STREAMS`]; a capacity of 0 or a stream given
    /// twice is refused at start as `InvalidConfig`.
    ///
    /// [`EmbeddedDriver::add_stream`]: crate::EmbeddedDriver::add_stream
    pub timed: [Option<TimedNetworkStream>; MAX_TIMED_NETWORK_STREAMS],
}

/// A stream whose network publications are timed
/// ([`NetworkStreamDefaults::timed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedNetworkStream {
    /// The wire stream id.
    pub stream_id: i32,
    /// Schedule ring entries of each lane, at least 1.
    pub schedule_capacity: u32,
}

/// The most timed network streams a driver configures.
pub const MAX_TIMED_NETWORK_STREAMS: usize = 8;

impl NetworkStreamDefaults {
    /// The schedule capacity of `stream_id`'s network publications, `None`
    /// for an untimed stream.
    #[must_use]
    pub fn timed_capacity(&self, stream_id: i32) -> Option<u32> {
        self.timed
            .iter()
            .flatten()
            .find(|timed| timed.stream_id == stream_id)
            .map(|timed| timed.schedule_capacity)
    }

    /// Whether the timed streams are valid: every capacity at least 1 and
    /// no stream twice.
    fn timed_valid(&self) -> bool {
        let timed: Vec<&TimedNetworkStream> = self.timed.iter().flatten().collect();
        timed.iter().enumerate().all(|(index, one)| {
            one.schedule_capacity > 0
                && timed
                    .iter()
                    .take(index)
                    .all(|other| other.stream_id != one.stream_id)
        })
    }
}

/// The longest `publication_linger` a network accepts (ns): 60 s. A
/// removal holds its stream key for up to about twice its linger.
pub const MAX_PUBLICATION_LINGER: u64 = 60_000_000_000;

impl Default for NetworkStreamDefaults {
    fn default() -> Self {
        Self {
            term_length: 1 << 20,
            mtu: karyos_sys::sizing::DEFAULT_MTU,
            lanes: 1,
            spare_slots: 3,
            max_subscribers: 8,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication_linger: 5_000_000_000,
            initial_term_id: None,
            timed: [None; MAX_TIMED_NETWORK_STREAMS],
        }
    }
}

/// Where the agents are.
#[derive(Debug)]
enum Agents<T: StreamTerms> {
    /// On the conductor's thread.
    Shared(Box<NetworkAgents<OsSocket, T>>),
    /// On their own threads.
    Threads(AgentRunner<OsSocket, T>),
    /// Stopped and reclaimed.
    Closed,
}

/// What closing the network left behind.
#[derive(Debug)]
pub struct NetworkShutdown<T: StreamTerms = HeapTerms> {
    /// Endpoints retired cleanly.
    pub endpoints_retired: usize,
    /// The agents' failures, as their threads reported them.
    pub failures: Vec<AgentError>,
    /// Threads that did not stop within `stop_timeout`; they still own
    /// their agents and can be joined.
    pub late: Vec<LateAgent<OsSocket, T>>,
    /// Whether every agent that was handed back saw its stop flag.
    pub agents_stopped: bool,
    /// Guard senders of network publications deregistered with the close,
    /// so no guard close waits on them.
    pub guard_senders_released: usize,
}

impl<T: StreamTerms> Default for NetworkShutdown<T> {
    fn default() -> Self {
        Self {
            endpoints_retired: 0,
            failures: Vec::new(),
            late: Vec::new(),
            agents_stopped: false,
            guard_senders_released: 0,
        }
    }
}

/// Where a network publication stands with the sender agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPublicationState {
    /// Posted, not answered yet.
    Adding,
    /// The sender announces it.
    Active,
    /// The sender refused it (a full table or a duplicate alias); its
    /// endpoint was released.
    Refused,
    /// Being removed: its data path has not come back yet.
    Removing,
    /// Accepted, but its sender cannot open its routes or queues on its
    /// endpoint: the endpoint limit that refused it (karyos#859). It sends
    /// nothing until it opens; it is retried every `setup_interval`.
    Limited(crate::error::EndpointLimit),
    /// Between incarnations after a guard reopen
    /// ([`EmbeddedDriver::publication`](crate::EmbeddedDriver::publication)):
    /// the old incarnation's session is being removed, or its alias waits
    /// out the quarantine before the next one is added.
    Reincarnating,
}

/// A network publication of this driver.
#[derive(Debug)]
struct NetPublication {
    /// The aggregate's registration.
    registration: u64,
    endpoint: EndpointId,
    /// The endpoints of its later paths (redundant-paths.md): each holds a
    /// send endpoint and the receiver's published alias, as `endpoint` does.
    later: [Option<EndpointId>; LATER_PATHS],
    alias: Alias,
    state: NetworkPublicationState,
    /// Whether `RemovePublication` is posted; retried while the ring is
    /// full.
    remove_posted: bool,
    /// Whether the sender reported the removal's linger over
    /// (`SenderSessionDrained`), or held no such publication.
    drained: bool,
    /// Whether `RemoveSenderSession` is posted; retried while the ring is
    /// full.
    session_posted: bool,
    /// A guarded publication's sender gate, registered with the guard's
    /// owner; released once the sender refused or returned it.
    guard_sender: Option<crate::guard_ack::GuardSenderId>,
    /// Its gate's submission frontier: superseded when the guard sender is
    /// released, so the walker ends lanes no gate will decide again.
    frontier: Option<SharedFrontier>,
    /// The identity its trace journals name (trace-network.md §5).
    traced: karyos_protocol::trace_hook::PublicationIdentity,
    /// Its lane count.
    lanes: u8,
    /// What it takes of each endpoint it sends on (karyos#859), held until
    /// its entry goes, when its removal has ended.
    demand: Vec<(EndpointId, TxDemand)>,
    /// What one destination added at run time takes of its endpoint, for
    /// a multi-destination publication (karyos#859).
    per_destination: Option<TxDemand>,
    /// The run-time destination additions posted and not answered yet:
    /// each holds `per_destination` in `demand` until its answer.
    adds_pending: Vec<std::net::SocketAddr>,
    /// `max_destinations` (MD-6): the most destination changes and
    /// removals kept, and additions in flight.
    max_destinations: usize,
    /// The endpoint limit its sender reported, until it opened.
    limited: Option<EndpointLimit>,
    /// Its open sender journals to close before `RemovePublication`, in the
    /// same ring (P2.12 step 3): `(lane, journal number)`.
    trace_closes: Vec<(Lane, u64)>,
    /// What its sender was added with, for the next incarnation; taken
    /// when a reincarnation starts.
    channel: Option<SenderChannel>,
    /// Removed for its next incarnation: no linger, and its removal ends
    /// in a [`Reincarnation`].
    /// The channel's `linger` in ns; `None` for the network's.
    linger: Option<u64>,
    reincarnating: bool,
    /// The destinations its sender removed, with why, the newest
    /// `max_destinations`, oldest first (karyos#630), and how many older
    /// ones were overwritten: a destination can be removed again after it
    /// is added back.
    removed_destinations: std::collections::VecDeque<crate::agents::data::DestinationRemoval>,
    removals_overwritten: u64,
    /// The answers to its run-time destination changes, oldest first, at
    /// most `max_destinations` (karyos#630).
    destination_changes:
        std::collections::VecDeque<(std::net::SocketAddr, crate::agents::data::DestinationChange)>,
    /// The slot its sender stores its admission state's code in each cycle
    /// (karyos#637; 0 before the first).
    admission: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

/// What a network publication's sender is added with, kept for the next
/// incarnation (control path).
#[derive(Debug, Clone)]
pub(crate) struct SenderChannel {
    /// Where it sends.
    pub(crate) destination: SocketAddr,
    /// A multi-destination channel's destinations (empty otherwise).
    pub(crate) destinations: Vec<SocketAddr>,
    /// The required ones among them, by endpoint (MD-11).
    pub(crate) required_destinations: Vec<SocketAddr>,
    /// The local address of each path's endpoint, the founding path first.
    pub(crate) binds: Vec<SocketAddr>,
    /// Whether it is reliable.
    pub(crate) reliable: bool,
    /// Its lanes' quanta.
    pub(crate) quanta: karyos_protocol::network::Lanes<u64>,
    /// Its guard.
    pub(crate) guard: Option<publish::NetworkGuard>,
    /// Its receivers' roles.
    pub(crate) roles: Option<Box<crate::membership::PublicationRoles>>,
    /// The channel's `retransmit-window`, checked against its term;
    /// `None` keeps the driver's repair setting.
    pub(crate) retransmit_window: Option<u32>,
    /// The channel's `linger` in ns, at most [`MAX_PUBLICATION_LINGER`];
    /// `None` keeps the network's `publication_linger` (karyos#652).
    pub(crate) linger: Option<u64>,
    /// The channel's `path-skew` in ns; `None` keeps the sender's
    /// `path_policy.skew_window` (karyos#1056).
    pub(crate) path_skew: Option<u64>,
    /// A `control-mode=dynamic` publication's registration policy
    /// (karyos#644); `None` otherwise.
    pub(crate) registration: Option<crate::sessions::register::RegistrationPolicy>,
}

/// A network publication between incarnations (guards-and-abort.md, On
/// the network): its old session is removed, then its alias waits out
/// `alias_quarantine` from that removal before the next incarnation is
/// added under the same alias. Remote receivers are assumed to quarantine
/// a retired identity for the same `alias_quarantine` as this driver's.
#[derive(Debug)]
struct Reincarnation {
    registration: u64,
    /// Its alias: its key on each held path stays reserved until the next
    /// incarnation is added, so no other publication takes it meanwhile.
    alias: Alias,
    /// One extra hold on each path's send endpoint, taken when the
    /// reincarnation starts, so the endpoints stay open for the next
    /// incarnation; released once its sender is posted.
    held: Vec<EndpointId>,
    /// When the old session's removal ended (`PublicationRemoved`), on the
    /// network clock.
    removed: Option<u64>,
    /// Whether the conductor already swapped in the next incarnation's
    /// lanes, so a later call only posts its sender.
    swapped: bool,
    channel: SenderChannel,
}

/// Where a reincarnating network publication stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReincarnationPhase {
    /// Its old alias is quarantined until `until_ns` on the network clock:
    /// an estimate while the old session is still being removed.
    Waiting { until_ns: u64 },
    /// The next incarnation can be added; `swapped` once its lanes are.
    Ready { swapped: bool },
}

/// An endpoint shared by the publications and subscriptions bound to one
/// address (and multicast group).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendEndpoint {
    bind: SocketAddr,
    multicast: Option<MulticastConfig>,
    /// What it is for: a data endpoint and the SOLICIT endpoint of one
    /// address are never shared (plan 169), so a publication with no
    /// interface, bound to the unspecified address on port 0, does not
    /// send the driver's SOLICITs or share their resets and tables.
    purpose: EndpointPurpose,
    endpoint: EndpointId,
    /// Publications and subscriptions that hold it.
    users: usize,
    /// Its routes, queues and TX slots, fixed at open (karyos#859).
    capacity: TxDemand,
}

/// What a [`SendEndpoint`] is for, part of its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointPurpose {
    /// Publications', subscriptions' and control groups' traffic.
    Data,
    /// The driver's unicast control endpoint for SOLICITs (plan 169).
    Solicit,
}

/// What every handle of one subscription key shares, as
/// [`Network::add_subscription`] takes it: the receiver identity, the
/// conflated lane and view configuration, the dynamic `control` address
/// and the channel's `path-skew` in ns.
pub(crate) type KeyOptions = (
    Option<crate::membership::ReceiverIdentity>,
    Option<(Lane, karyos_sys::conflation::ConflationConfig)>,
    Option<SocketAddr>,
    Option<u64>,
);

/// A network subscription of this driver (W3): the receiver holds one
/// entry per endpoint and stream, so the handles of one key are counted
/// (#283 P2).
#[derive(Debug, Clone)]
struct NetSubscription {
    endpoint: EndpointId,
    stream_id: i32,
    /// The channel's reliability, which every handle of this key shares.
    reliable: bool,
    /// The endpoint joined to the data group's NAK control group, if the
    /// table names one and its join succeeded (RC-15).
    control: Option<EndpointId>,
    /// The driver's unicast control endpoint of the key's family, held by
    /// a multicast key: its SOLICITs leave from there (plan 164).
    solicit: Option<EndpointId>,
    /// The receiver identity every handle of this key shares (MC-1).
    identity: Option<crate::membership::ReceiverIdentity>,
    /// The conflated lane and the view's table configuration every handle
    /// of this key shares (conflated-network-images.md (a)).
    conflated: Option<(Lane, karyos_sys::conflation::ConflationConfig)>,
    /// The `control` address of a `control-mode=dynamic` key, which every
    /// handle of it shares (design 3.2; karyos#644).
    register_at: Option<SocketAddr>,
    /// The channel's `path-skew` in ns, which every handle of the key
    /// shares (karyos#1056).
    path_skew: Option<u64>,
    /// The key's registration state, which its receiver writes
    /// (karyos#941 item 3); with `register_at` only.
    registration: Option<std::sync::Arc<crate::sessions::register::RegistrationStatus>>,
    /// The endpoints of the channel's later redundant paths, each with its
    /// own receiver entry (redundant-paths.md; the first path is
    /// `endpoint`).
    later: [Option<EndpointId>; LATER_PATHS],
    /// Each later path's NAK control group endpoint, joined from the
    /// driver's table for that path's interface (RC-15; karyos#1064).
    later_controls: [Option<EndpointId>; LATER_PATHS],
    /// The routes the channel asked for its later paths: a second handle
    /// of the key must ask for the same ones.
    later_routes: [Option<(SocketAddr, MulticastConfig)>; LATER_PATHS],
    /// The control group entries of the driver's table its paths joined,
    /// whether its own channel's `nak-control` added them or not, released
    /// with the key (karyos#1086).
    control_held: control_group::Held,
    /// The control group each admitted path's receiver entry runs with,
    /// first path first: `Some(None)` for an admitted path with none (no
    /// entry, a failed join, an unreliable key), `None` for a path not
    /// admitted. A second handle naming `nak-control` must ask for the same
    /// ones (karyos#1086 review).
    control_admitted: ControlAdmitted,
    /// Handles of this key; the receiver's entry goes with the last.
    users: usize,
}

impl NetSubscription {
    /// Whether this subscription's receiver entry for `stream_id` is on
    /// `endpoint`, as its first path or a later one.
    fn serves(&self, endpoint: EndpointId, stream_id: i32) -> bool {
        self.stream_id == stream_id
            && (self.endpoint == endpoint || self.later.contains(&Some(endpoint)))
    }

    /// The receiver entries it holds: its first path's and each later one's.
    fn entries(&self) -> Option<usize> {
        self.later.iter().flatten().count().checked_add(1)
    }
}

/// What the conflated views of network images did
/// (conflated-network-images.md). Increments are checked: one that would
/// overflow keeps its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkViewCounters {
    /// Views built over an exposed image lane.
    pub built: u64,
    /// Installed images with a conflated lane that got no view because the
    /// image was not exposed: its alias is a local stream's key, the stream
    /// table was full or its aggregate could not be built
    /// (`quantstratum-docs: karyos/design/per-source-images.md`, D2-6).
    /// Images of one alias from several sources each get a view.
    pub unbuilt_unexposed: u64,
    /// Views that could not be built over an exposed lane (the lane, the
    /// configuration, the table or the feeder's subscription failed); the
    /// cause of the last is kept in `last_build_failure`.
    pub unbuilt_failed: u64,
    /// The cause of the last view that could not be built.
    pub last_build_failure: Option<ViewBuildFailure>,
    /// Seal requests acknowledged after the loss was recorded.
    pub acked: u64,
    /// Seal requests whose acknowledgement was withheld while the barrier
    /// was full.
    pub withheld: u64,
    /// Ranges met in the log and recorded there as losses: a gap sealed
    /// before the attach, or any other range the poll skipped (every
    /// skip reason counts as a loss, conservatively).
    pub caught_up: u64,
    /// Views closed because their terminal cell was published (a timeout,
    /// exhaustion, a loss below the frontier or a lost feeder).
    pub closed_terminal: u64,
    /// Views closed because their image retired.
    pub closed_retired: u64,
    /// Feeders that could not read on: their view closed, the image stayed.
    pub feeders_lost: u64,
    /// Views recreated after their terminal cell closed them (karyos#658).
    pub recreated: u64,
    /// Slots of a closed view that read unstable when its recreation was
    /// seeded, so came back absent instead of `Stale`; never expected,
    /// the closed table having one closed writer.
    pub recreate_unstable: u64,
    /// Refresh and snapshot cycles completed by views that opt in
    /// (ADR-0080, karyos#634).
    pub cycles_completed: u64,
    /// Snapshot cycles among the completed ones.
    pub snapshots_completed: u64,
    /// Cycles aborted: cut by a loss, replaced by a new begin, ended with
    /// another begin position, count or scope, or meeting a refresh value
    /// or marker the view could not take. They restore nothing.
    pub cycles_aborted: u64,
    /// Keys restored by completed cycles.
    pub keys_restored: u64,
    /// Cycle markers whose payload did not decode; each aborts the open
    /// cycle.
    pub markers_malformed: u64,
}

/// Why a conflated view of a network image could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewBuildFailure {
    /// The image has no stream for the conflated lane.
    NoLane,
    /// The subscription's view configuration is gone.
    NoConfiguration,
    /// The table could not be created.
    Table(karyos_sys::conflation::ConflationError),
    /// The feeder's subscription of the lane could not be made.
    Subscription,
}

impl NetworkViewCounters {
    /// Adds `delta` to the counter `field` picks.
    pub(crate) fn add(&mut self, field: fn(&mut Self) -> &mut u64, delta: u64) {
        let value = field(self);
        if let Some(next) = value.checked_add(delta) {
            *value = next;
        }
    }
}

/// The later paths a network subscription holds beside its first: the
/// channel URI allows four paths (karyos-protocol `channel.rs`).
pub(crate) const LATER_PATHS: usize = 3;

/// The control group the table names for each path of a key, first path
/// first (karyos#1086 review).
pub(crate) type ControlAsked = [Option<SocketAddr>; LATER_PATHS + 1];

/// The control group each admitted path of a key runs with
/// (`NetSubscription::control_admitted`).
pub(crate) type ControlAdmitted = [Option<Option<SocketAddr>>; LATER_PATHS + 1];

/// A timed lane whose publisher breached its schedule ring's protocol, as
/// its sender reported it (`AgentEvent::ScheduleViolated`) for the live
/// publication, for the conductor to seal (`quantstratum-docs:
/// karyos/design/timed-tx.md`, section 11, TT-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScheduleViolation {
    /// The aggregate's registration.
    pub(crate) registration: u64,
    /// The incarnation the sender served.
    pub(crate) incarnation: u64,
    /// The lane.
    pub(crate) lane: u8,
}

/// Schedule violations for the conductor to apply, drained every serve:
/// at most one per lane of each tracked publication (allocated at start).
/// One past that, or a report that names no live publication, is dropped
/// and counted.
#[derive(Debug)]
struct ScheduleViolations {
    pending: Vec<ScheduleViolation>,
    dropped: u64,
}

impl ScheduleViolations {
    fn push(&mut self, violation: ScheduleViolation) {
        if self.pending.len() < self.pending.capacity() {
            self.pending.push(violation);
        } else {
            self.drop_one();
        }
    }

    fn drop_one(&mut self) {
        if let Some(count) = self.dropped.checked_add(1) {
            self.dropped = count;
        }
    }
}

/// Guard senders released for the conductor to deregister: at most one
/// per tracked publication (allocated at start). One past that is dropped
/// and counted, which the allocation makes unreachable.
#[derive(Debug)]
struct ReleasedGuards {
    ids: Vec<crate::guard_ack::GuardSenderId>,
    dropped: u64,
}

impl ReleasedGuards {
    fn push(&mut self, id: crate::guard_ack::GuardSenderId) {
        if self.ids.len() < self.ids.capacity() {
            self.ids.push(id);
        } else {
            if let Some(count) = self.dropped.checked_add(1) {
                self.dropped = count;
            }
        }
    }
}

/// Names a network subscription of one driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkSubscription {
    endpoint: EndpointId,
    stream_id: i32,
}

impl NetworkSubscription {
    /// The endpoint it receives on.
    pub(crate) fn endpoint(&self) -> EndpointId {
        self.endpoint
    }

    /// The stream it subscribes.
    pub(crate) fn stream_id(&self) -> i32 {
        self.stream_id
    }
}

/// Where an image comes from (`quantstratum-docs:
/// karyos/design/per-source-images.md`, D2-1): the endpoint it arrived
/// on, the datagram source its binding names, and the publication
/// incarnation. A later path's image keeps its founding source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImageSource {
    /// The endpoint it arrived on.
    pub(crate) endpoint: EndpointId,
    /// The datagram source its founding binding names.
    pub(crate) source: std::net::SocketAddr,
    /// The publication incarnation.
    pub(crate) identity: karyos_protocol::network::Identity,
}

/// An installed image and the aggregate that exposes it, if any.
#[derive(Debug)]
struct NetImage<T: StreamTerms> {
    slot: SlotRef,
    /// The endpoint it arrived on, which its subscription names.
    endpoint: EndpointId,
    /// The publication it receives, as its trace journals name it.
    traced: karyos_protocol::trace_hook::PublicationIdentity,
    /// Its lane count.
    lanes: usize,
    exposed: Option<crate::embedded::AggregateHandle>,
    /// An unexposed image's lane conductors, driven here so its terms are
    /// still prepared and it keeps being fed (ACS 15937); dropped when it
    /// retires.
    conductors: Vec<Conductor<Arc<LogBuffer<T>>>>,
}

/// The conductor's network state.
#[derive(Debug)]
pub(crate) struct Network<T: StreamTerms = HeapTerms> {
    links: AgentLinks<OsSocket, T>,
    endpoints: Endpoints<OsSocket>,
    images: ImageTable<T>,
    agents: Agents<T>,
    /// The first agent that failed (DN-9), latched.
    failed: Option<AgentKind>,
    /// `max_destinations` (MD-6; karyos#889), from the agents' settings.
    max_destinations: usize,
    /// `receiver_bindings`, from the agents' settings: the most
    /// destinations the driver's dynamic publications take together
    /// (karyos#941 item 2).
    receiver_bindings: usize,
    publications: Vec<NetPublication>,
    send_endpoints: Vec<SendEndpoint>,
    subscriptions: Vec<NetSubscription>,
    /// Subscriptions whose removal found the receiver's ring full: retried
    /// each cycle.
    pending_unsubscribe: Vec<NetworkSubscription>,
    /// The receiver's subscription table size (`AgentConfig::subscriptions`):
    /// the conductor, its only producer of `AddSubscription`, keeps no more
    /// distinct keys, so a full table is refused here, synchronously
    /// (ACS 16077).
    subscription_capacity: usize,
    /// `AddSubscription` answers the receiver refused anyway: a drift
    /// between the two tables, never expected.
    subscription_refusals: u64,
    /// Installed images, at most `max_images`.
    net_images: Vec<NetImage<T>>,
    /// The image table's events of the last cycle, for the conductor.
    image_events: Vec<ImageEvent>,
    /// The agents' network trace answers of the last cycle, and the
    /// publications that became active, for the conductor (P2.12 step 3).
    trace_events: Vec<trace::TraceEvent>,
    /// Endpoint resets completed (`EndpointEvent::Reopened`), for tests.
    #[cfg(test)]
    reopened: u64,
    /// Images installed but not exposed: their alias is a local stream's
    /// key, the stream table is full or their aggregate could not be built
    /// (`quantstratum-docs: karyos/design/per-source-images.md`, D2-1).
    images_unexposed: u64,
    /// Aliases the receiver still admits for a publication that is gone
    /// or was refused: `RemovePublishedAlias` is posted as the ring
    /// allows. Bounded by construction: an alias is queued only from a
    /// tracked publication, at most once, and a publication is admitted
    /// only while tracked publications and queued aliases together hold
    /// fewer than `capacity` distinct keys, the capacity reserved at start.
    stale_aliases: Vec<(EndpointId, Alias)>,
    /// Network publications and stale aliases held at once.
    capacity: usize,
    /// The tables of each endpoint it opens.
    endpoint_tables: EndpointTables,
    /// The capabilities each endpoint it opens must have active.
    require: CapabilitySet,
    /// What each send endpoint keeps for the sender's control routes
    /// (karyos#859): `control_routes` routes and queues of
    /// `CONTROL_QUEUE_DEPTH` slots each.
    control_reserve: TxDemand,
    /// `publication_linger` (ns), handed to the sender at each removal.
    publication_linger: u64,
    /// The receiver's `alias_quarantine` (ns): how long a reincarnating
    /// publication's alias waits after its old session's removal.
    alias_quarantine: u64,
    /// Publications between incarnations, at most one per tracked
    /// publication (allocated at start).
    reincarnations: Vec<Reincarnation>,
    /// Stale aliases that found the queue full: never, by construction;
    /// counted if it happens.
    stale_overflows: u64,
    /// The network's time base, the agents' role clock: `host_monotonic_ns`
    /// (module documentation, Duty).
    clock: fn() -> u64,
    /// Guard senders of publications the sender refused or returned, for
    /// the conductor to deregister (at most one per tracked publication,
    /// allocated at start).
    released_guards: ReleasedGuards,
    /// Schedule violations the senders reported, for the conductor.
    schedule_violations: ScheduleViolations,
    /// Guard senders the conductor failed to deregister (an unknown id):
    /// counted, never retried.
    guard_deregister_failures: u64,
    /// The NAK control groups of multicast data groups (RC-15).
    control_groups: ControlGroups,
    /// The users of each entry a channel's `nak-control` added
    /// (karyos#1086).
    control_group_uses: control_group::Uses,
    /// Control group joins that failed: those keys run without peer
    /// suppression input (RC-15).
    control_join_failures: u64,
    /// Unicast control endpoints that could not open (plan 164).
    solicit_endpoint_failures: u64,
    /// Whether the backend isolates redundant path sockets.
    paths_isolated: bool,
    /// Channels with `paths` refused because they cannot be isolated.
    paths_refused: u64,
    /// Later paths of subscriptions that could not be held.
    path_failures: u64,
    /// What the conflated views of network images did
    /// (conflated-network-images.md).
    views: NetworkViewCounters,
    /// The agents' CnC cells, taken back at the close for the conductor to
    /// free (M2).
    cells: Vec<Counter>,
    /// Whether `barrier_ack_timeout` fits an unreliable image's skip
    /// deadlines ([`crate::agents::BarrierAckBound::FarWindow`]), checked
    /// at start for the conflated subscriptions of unreliable channels.
    unreliable_view_bound: Result<(), crate::agents::BarrierAckBound>,
    /// `barrier_ack_timeout` and the receiver's path settings, for the
    /// far-window check of a channel with its own `path-skew`
    /// (karyos#1056).
    view_bound_inputs: (u64, crate::paths::PathConfig),
    /// Conflated views built from now on are not attached (tests).
    #[cfg(test)]
    defer_view_attach: bool,
}

impl<T: StreamTerms> Network<T> {
    /// The agents of `config`, started in its threading mode (control
    /// path, at driver start).
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidConfig`] for an agent configuration the agents
    /// refuse ([`DriverError::BarrierAckTimeout`] for a `barrier_ack_timeout`
    /// below a bound), a `publication_linger` above [`MAX_PUBLICATION_LINGER`] or
    /// invalid timed streams ([`NetworkStreamDefaults::timed`]);
    /// [`DriverError::NetworkStart`] when a thread cannot start.
    pub(crate) fn start(
        config: &NetworkConfig,
        cells: (AgentCells, AgentCells),
    ) -> Result<Self, DriverError>
    where
        T: 'static,
    {
        if config.stream_defaults.publication_linger > MAX_PUBLICATION_LINGER
            || !config.stream_defaults.timed_valid()
        {
            return Err(DriverError::InvalidConfig);
        }
        control_group::validate(&config.nak_control_groups)?;
        // MD-6, 3.5: one publication's destinations fit an endpoint's
        // route table (the sum over an endpoint's publications is
        // karyos#915).
        if config.agents.max_destinations > usize::from(config.endpoint_tables.max_routes.get()) {
            return Err(DriverError::MaxDestinations {
                value: config.agents.max_destinations,
            });
        }
        let (mut agents, links) =
            network_agents_over::<OsSocket, T>(config.agents).map_err(|error| match error {
                AgentError::BarrierAckTimeout(bound) => DriverError::BarrierAckTimeout(bound),
                AgentError::MaxDestinations { value } => DriverError::MaxDestinations { value },
                _ => DriverError::InvalidConfig,
            })?;
        // Each agent writes its own cells from its first cycle (M2).
        agents.attach_cells(cells.0, cells.1);
        let agents = match config.threading {
            ThreadingMode::Shared => Agents::Shared(Box::new(agents)),
            mode => Agents::Threads(
                AgentRunner::start(mode, agents, config.agents, YieldThenSleep::default)
                    .map_err(|_| DriverError::NetworkStart)?,
            ),
        };
        Ok(Self {
            links,
            endpoints: Endpoints::new(&config.agents),
            images: ImageTable::new(config.agents.sessions.max_images, config.images),
            agents,
            failed: None,
            max_destinations: config.agents.max_destinations,
            receiver_bindings: config.agents.receiver_bindings,
            publications: Vec::with_capacity(config.agents.publications),
            send_endpoints: Vec::with_capacity(config.agents.max_endpoints),
            subscriptions: Vec::with_capacity(config.agents.subscriptions),
            subscription_capacity: config.agents.subscriptions,
            pending_unsubscribe: Vec::with_capacity(config.agents.subscriptions),
            subscription_refusals: 0,
            net_images: Vec::with_capacity(config.agents.sessions.max_images),
            image_events: Vec::with_capacity(config.agents.sessions.max_images),
            // An answer per lane of every publication and image at once.
            trace_events: Vec::with_capacity(
                config
                    .agents
                    .publications
                    .checked_add(config.agents.sessions.max_images)
                    .and_then(|count| count.checked_mul(usize::from(Lane::COUNT)))
                    .unwrap_or(config.agents.publications),
            ),
            images_unexposed: 0,
            #[cfg(test)]
            reopened: 0,
            stale_aliases: Vec::with_capacity(config.agents.publications),
            capacity: config.agents.publications,
            endpoint_tables: config.endpoint_tables,
            require: config.require,
            control_reserve: {
                let routes = u32::try_from(config.agents.control_routes).unwrap_or(u32::MAX);
                TxDemand {
                    routes,
                    queues: routes,
                    slots: routes
                        .saturating_mul(u32::from(crate::agents::control::CONTROL_QUEUE_DEPTH)),
                }
            },
            publication_linger: config.stream_defaults.publication_linger,
            alias_quarantine: config.agents.sessions.alias_quarantine,
            reincarnations: Vec::with_capacity(config.agents.publications),
            stale_overflows: 0,
            clock: karyos_sys::host_clock::host_monotonic_ns,
            released_guards: ReleasedGuards {
                ids: Vec::with_capacity(config.agents.publications),
                dropped: 0,
            },
            schedule_violations: ScheduleViolations {
                pending: Vec::with_capacity(
                    config
                        .agents
                        .publications
                        .checked_mul(karyos_protocol::network::MAX_LANES)
                        .unwrap_or(config.agents.publications),
                ),
                dropped: 0,
            },
            guard_deregister_failures: 0,
            control_groups: config.nak_control_groups,
            control_group_uses: [None; MAX_CONTROL_GROUPS],
            control_join_failures: 0,
            solicit_endpoint_failures: 0,
            paths_isolated: <OsSocket as karyos_io::sockets::ops::SocketOps>::isolates_paths(),
            paths_refused: 0,
            path_failures: 0,
            views: NetworkViewCounters::default(),
            cells: Vec::new(),
            view_bound_inputs: (
                config.agents.barrier_ack_timeout,
                crate::agents::roles::receiver_path_config(&config.agents),
            ),
            unreliable_view_bound: crate::agents::conflated_gate::check_far_window(
                config.agents.barrier_ack_timeout,
                &crate::agents::roles::image_skip_config(
                    &crate::agents::roles::receiver_path_config(&config.agents),
                    false,
                ),
            ),
            #[cfg(test)]
            defer_view_attach: false,
        })
    }

    /// The send endpoint bound to `bind`, opened on first use; one more
    /// publication holds it.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkEndpoint`] when it cannot open.
    pub(crate) fn hold_send_endpoint(
        &mut self,
        bind: SocketAddr,
    ) -> Result<EndpointId, DriverError> {
        self.hold_endpoint(bind, None)
    }

    /// The data endpoint bound to `bind`, joined to `multicast` if any,
    /// opened on first use; one more user holds it.
    fn hold_endpoint(
        &mut self,
        bind: SocketAddr,
        multicast: Option<MulticastConfig>,
    ) -> Result<EndpointId, DriverError> {
        self.hold_for(bind, multicast, EndpointPurpose::Data, true)
    }

    /// [`Self::hold_endpoint`] for `purpose`: an entry of another purpose
    /// at the same address is never shared, and with `share` false no
    /// entry is (a new endpoint each time).
    fn hold_for(
        &mut self,
        bind: SocketAddr,
        multicast: Option<MulticastConfig>,
        purpose: EndpointPurpose,
        share: bool,
    ) -> Result<EndpointId, DriverError> {
        if let Some(entry) = self.send_endpoints.iter_mut().find(|entry| {
            share && (entry.bind, entry.multicast, entry.purpose) == (bind, multicast, purpose)
        }) {
            entry.users = entry
                .users
                .checked_add(1)
                .ok_or(DriverError::NetworkEndpoint)?;
            return Ok(entry.endpoint);
        }
        // An endpoint retiring at this fixed address still holds it: the
        // add is refused as retryable, and taken once it has retired
        // (karyos#994).
        if self.endpoints.retiring_at(bind) {
            return Err(DriverError::NetworkBusy);
        }
        let mut config = SocketsConfig::new(bind);
        config.multicast = multicast;
        config.tx_slots = self.endpoint_tables.tx_slots;
        config.max_queues = self.endpoint_tables.max_queues;
        config.max_routes = self.endpoint_tables.max_routes;
        config.require = self.require;
        let capacity = TxDemand {
            routes: u32::from(config.max_routes.get()),
            queues: u32::from(config.max_queues.get()),
            slots: u32::from(config.tx_slots.get()),
        };
        let endpoint = self
            .endpoints
            .open(&self.links, config, OsSocket::new())
            .map_err(|_| DriverError::NetworkEndpoint)?;
        self.send_endpoints.push(SendEndpoint {
            bind,
            multicast,
            purpose,
            endpoint,
            users: 1,
            capacity,
        });
        Ok(endpoint)
    }

    /// Subscribes `stream_id` on the endpoint bound to `bind` (joined to
    /// `multicast`): the receiver challenges its announcements and
    /// installs its images (control path). A second subscription of the
    /// same endpoint and stream shares the receiver's entry. The receiver's
    /// table is mirrored here: a new key beyond `AgentConfig::subscriptions`
    /// is refused before anything is posted.
    ///
    /// `reliable` is the channel's `reliable` parameter: the receiver
    /// repairs its images' losses with NAKs, otherwise its skip policy
    /// seals them. A second subscription of the same endpoint and stream
    /// shares the first's receiver entry, so it must ask for the same
    /// reliability ([`DriverError::ReliabilityMismatch`] otherwise), and
    /// the same receiver `identity`, configured or not
    /// ([`DriverError::ReceiverIdentityMismatch`] otherwise), and the same
    /// `conflated` lane ([`DriverError::ConflationMismatch`] otherwise).
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkSubscriptionsFull`],
    /// [`DriverError::NetworkEndpoint`], [`DriverError::NetworkBusy`],
    /// [`DriverError::ReliabilityMismatch`],
    /// [`DriverError::ReceiverIdentityMismatch`],
    /// [`DriverError::ConflationMismatch`],
    /// [`DriverError::ControlGroupConflict`] for a second handle whose
    /// channel names `nak-control` groups (`names_control`) other than
    /// those the key's paths joined.
    pub(crate) fn add_subscription(
        &mut self,
        stream_id: i32,
        (bind, multicast): (SocketAddr, Option<MulticastConfig>),
        later: &[(SocketAddr, MulticastConfig)],
        max_term_length: u32,
        (reliable, own_port, names_control): (bool, bool, bool),
        (identity, conflated, register_at, path_skew): KeyOptions,
    ) -> Result<NetworkSubscription, DriverError> {
        let group = multicast.is_some();
        // A URI subscription on port 0 (`own_port`) asks for an ephemeral
        // port of its own (karyos#656): never another's endpoint, which an
        // address with port 0 would otherwise match. The embedded calls
        // keep sharing a bind address's endpoint, port 0 included.
        let ephemeral = own_port && bind.port() == 0 && multicast.is_none();
        let endpoint = self.hold_for(bind, multicast, EndpointPurpose::Data, !ephemeral)?;
        let handle = NetworkSubscription {
            endpoint,
            stream_id,
        };
        let asked_controls = self.control_asked(bind, multicast, later);
        if let Some(entry) = self
            .subscriptions
            .iter_mut()
            .find(|entry| (entry.endpoint, entry.stream_id) == (endpoint, stream_id))
        {
            // One receiver entry per key: a reliable subscriber must not
            // share an unreliable one's delivery, nor the reverse.
            if entry.reliable != reliable {
                release(&mut self.send_endpoints, endpoint);
                return Err(DriverError::ReliabilityMismatch);
            }
            // A second handle shares the key's paths, so it must ask for the
            // same ones; other paths would be dropped unseen.
            let mut asked = [None; LATER_PATHS];
            for (slot, route) in asked.iter_mut().zip(later) {
                *slot = Some(*route);
            }
            if later.len() > LATER_PATHS || asked != entry.later_routes {
                release(&mut self.send_endpoints, endpoint);
                if let Some(count) = self.paths_refused.checked_add(1) {
                    self.paths_refused = count;
                }
                return Err(DriverError::UnsupportedChannel);
            }
            // Its images name one receiver identity: a subscriber must not
            // be counted under another's, nor under a derived one.
            if entry.identity != identity {
                release(&mut self.send_endpoints, endpoint);
                return Err(DriverError::ReceiverIdentityMismatch);
            }
            // Its images gate one lane's seals for one view.
            if entry.conflated != conflated {
                release(&mut self.send_endpoints, endpoint);
                return Err(DriverError::ConflationMismatch);
            }
            // It registers at one `control` address, or at none.
            if entry.register_at != register_at {
                release(&mut self.send_endpoints, endpoint);
                return Err(DriverError::UnsupportedChannel);
            }
            // Its images wait one skew window: a second handle must ask
            // for the same one (karyos#1056).
            if entry.path_skew != path_skew {
                release(&mut self.send_endpoints, endpoint);
                return Err(DriverError::UnsupportedChannel);
            }
            // Its admitted paths' receiver entries run with the control
            // groups they joined, and do not follow a later change: a second
            // handle whose own `nak-control` (`names_control`) asks for
            // others, or for one where a path joined none (a failed join, an
            // unreliable key), is refused (karyos#1086 review). A handle
            // without the key shares what the key joined.
            let admitted = entry
                .control_admitted
                .iter()
                .zip(asked_controls)
                .all(|(admitted, asked)| admitted.is_none_or(|admitted| admitted == asked));
            if names_control && !admitted {
                release(&mut self.send_endpoints, endpoint);
                return Err(DriverError::ControlGroupConflict {
                    data_group: SocketAddr::new(
                        multicast.map_or(bind.ip(), |config| config.group),
                        bind.port(),
                    ),
                });
            }
            let Some(users) = entry.users.checked_add(1) else {
                release(&mut self.send_endpoints, endpoint);
                return Err(DriverError::NetworkBusy);
            };
            entry.users = users;
            return Ok(handle);
        }
        // A first path on an endpoint that is already another
        // subscription's later path of the stream would share its receiver
        // entry: refused (#307 review P2-2).
        if self
            .subscriptions
            .iter()
            .any(|entry| entry.serves(endpoint, stream_id))
        {
            release(&mut self.send_endpoints, endpoint);
            return Err(DriverError::UnsupportedChannel);
        }
        // A new key: the receiver's table must have room for it and each of
        // its later paths, one entry each (#307 review P2-1).
        let total = self
            .subscriptions
            .iter()
            .try_fold(0usize, |held, entry| held.checked_add(entry.entries()?))
            .and_then(|held| held.checked_add(later.len()))
            .and_then(|held| held.checked_add(1));
        if total.is_none_or(|total| total > self.subscription_capacity) {
            release(&mut self.send_endpoints, endpoint);
            return Err(DriverError::NetworkSubscriptionsFull);
        }
        // The first subscriber of a multicast key joins its NAK control
        // group, if the table names one (RC-15). A failed join leaves the
        // key without peer suppression input, counted; it refuses nothing.
        let control = match (reliable, multicast) {
            (true, Some(config)) => self.hold_control_group(bind, config),
            _ => None,
        };
        // Every entry the table selects for its held paths is counted for
        // the key, joined or not, so it stays while the key uses it, even
        // when another channel's `nak-control` added it (karyos#1086
        // review).
        let mut control_held = [false; MAX_CONTROL_GROUPS];
        let first_slot = multicast
            .filter(|_| reliable)
            .and_then(|config| self.control_group_of(bind, config))
            .map(|(at, _)| at);
        // A multicast key sends its SOLICITs from the driver's unicast
        // control endpoint of its family (network-control-schemas.md §6.3,
        // plan 164): one per driver and family, held by every multicast key
        // and closed with the last.
        let solicit = multicast.and_then(|_| self.hold_solicit_endpoint(bind));
        // A dynamic key's registration state, shared with its receiver.
        let registration = register_at
            .map(|_| std::sync::Arc::new(crate::sessions::register::RegistrationStatus::default()));
        let posted = self
            .links
            .receiver
            .post(|reply| AgentCommand::AddSubscription {
                reply,
                endpoint,
                stream_id,
                max_term_length,
                reliable,
                multicast: group,
                control_group: control,
                identity,
                conflated: conflated.map(|(lane, _)| lane),
                solicit_from: solicit,
                register_at: register_at.zip(registration.clone()),
                path_skew,
            });
        if posted.is_err() {
            release(&mut self.send_endpoints, endpoint);
            if let Some((control, _)) = control {
                release(&mut self.send_endpoints, control);
            }
            if let Some(solicit) = solicit {
                release(&mut self.send_endpoints, solicit);
            }
            return Err(DriverError::NetworkBusy);
        }
        if let Some(slot) = first_slot {
            control_group::hold_slot(&mut self.control_group_uses, &mut control_held, slot);
        }
        // Each later path is a receiver entry of its own endpoint; the
        // receiver binds it to the image as a later path of the same
        // publication (RP-1). A path that cannot open or be posted leaves
        // the subscription with the paths it has, counted.
        let mut held = [None; LATER_PATHS];
        let mut later_routes = [None; LATER_PATHS];
        let mut later_controls = [None; LATER_PATHS];
        let mut control_admitted: ControlAdmitted = [None; LATER_PATHS + 1];
        if let Some(first) = control_admitted.first_mut() {
            *first = Some(control.map(|(_, group)| group));
        }
        for ((((slot, route), control_slot), admitted), (bind, config)) in held
            .iter_mut()
            .zip(later_routes.iter_mut())
            .zip(later_controls.iter_mut())
            .zip(control_admitted.iter_mut().skip(1))
            .zip(later)
        {
            *route = Some((*bind, *config));
            let Ok(path) = self.hold_endpoint(*bind, Some(*config)) else {
                self.count_path_failure();
                continue;
            };
            // A later path on an endpoint another subscription of the
            // stream already uses would merge their receiver entries, and
            // removing one would remove the other's: skipped, counted
            // (#307 review P2-2).
            if path == endpoint
                || self
                    .subscriptions
                    .iter()
                    .any(|entry| entry.serves(path, stream_id))
            {
                release(&mut self.send_endpoints, path);
                self.count_path_failure();
                continue;
            }
            // Its own NAK control group, if the table names one for its
            // interface (karyos#1064), as the first path's.
            let path_control = if reliable {
                self.hold_control_group(*bind, *config)
            } else {
                None
            };
            let path_slot = if reliable {
                self.control_group_of(*bind, *config).map(|(at, _)| at)
            } else {
                None
            };
            let posted = self
                .links
                .receiver
                .post(|reply| AgentCommand::AddSubscription {
                    reply,
                    endpoint: path,
                    stream_id,
                    max_term_length,
                    reliable,
                    multicast: true,
                    control_group: path_control,
                    identity,
                    conflated: conflated.map(|(lane, _)| lane),
                    solicit_from: solicit,
                    register_at: None,
                    path_skew,
                });
            if posted.is_err() {
                release(&mut self.send_endpoints, path);
                if let Some((control, _)) = path_control {
                    release(&mut self.send_endpoints, control);
                }
                self.count_path_failure();
                continue;
            }
            *slot = Some(path);
            if let Some(at) = path_slot {
                control_group::hold_slot(&mut self.control_group_uses, &mut control_held, at);
            }
            *control_slot = path_control.map(|(control, _)| control);
            *admitted = Some(path_control.map(|(_, group)| group));
        }
        self.subscriptions.push(NetSubscription {
            endpoint,
            stream_id,
            reliable,
            control: control.map(|(control, _)| control),
            solicit,
            identity,
            conflated,
            register_at,
            path_skew,
            registration,
            later: held,
            later_controls,
            later_routes,
            control_held,
            control_admitted,
            users: 1,
        });
        Ok(handle)
    }

    /// The registration state of `subscription`, a `control-mode=dynamic`
    /// one; `None` for any other (karyos#941 item 3).
    pub(crate) fn registration_state(
        &self,
        subscription: NetworkSubscription,
    ) -> Option<crate::sessions::register::RegistrationState> {
        self.subscriptions
            .iter()
            .find(|entry| {
                (entry.endpoint, entry.stream_id) == (subscription.endpoint, subscription.stream_id)
            })
            .and_then(|entry| entry.registration.as_deref())
            .map(crate::sessions::register::RegistrationStatus::get)
    }

    /// One later path of a subscription that could not be held.
    fn count_path_failure(&mut self) {
        if let Some(count) = self.path_failures.checked_add(1) {
            self.path_failures = count;
        }
    }

    /// `max_destinations` (MD-6; karyos#889).
    pub(crate) const fn max_destinations(&self) -> usize {
        self.max_destinations
    }

    /// Whether this driver can isolate the sockets of redundant paths
    /// ([`SocketOps::isolates_paths`]); a channel with `paths` is refused
    /// while it cannot.
    /// Enters `channel`'s `nak-control` groups, one per path, into the
    /// driver's one control group table (owner item 8, karyos#654), all
    /// or none, before the subscription joins its group; a channel
    /// without the key changes nothing. What it counts goes to the key
    /// (`keep_control_groups`), which also counts each entry its paths
    /// select; an entry a URI added leaves with the last key that counts
    /// it (karyos#1086).
    ///
    /// # Errors
    ///
    /// [`DriverError::ControlGroupConflict`],
    /// [`DriverError::ControlGroupsFull`], [`DriverError::InvalidConfig`],
    /// or [`DriverError::UnsupportedChannel`] for a key on a channel that
    /// is not multicast, a path named by interface name, or a count that
    /// is not one per path (a hand-built channel).
    pub(crate) fn map_nak_control(
        &mut self,
        channel: &karyos_protocol::channel::UdpConfig,
    ) -> Result<control_group::Held, DriverError> {
        use karyos_protocol::channel::{Destination, Interface};
        let Destination::Multicast { group, .. } = channel.destination else {
            return if channel.nak_control.is_empty() {
                Ok([false; MAX_CONTROL_GROUPS])
            } else {
                Err(DriverError::UnsupportedChannel)
            };
        };
        // Each path's interface as `hold_control_group` looks it up: an
        // address, `None` for the unspecified one or no interface.
        let interface = |one: Option<&Interface>| match one {
            None => Ok(None),
            Some(Interface::Address(address)) if address.is_unspecified() => Ok(None),
            Some(Interface::Address(address)) => Ok(Some(*address)),
            Some(_) => Err(DriverError::UnsupportedChannel),
        };
        let interfaces = if channel.paths.is_empty() {
            vec![interface(channel.interface.as_ref())?]
        } else {
            channel
                .paths
                .iter()
                .map(|path| interface(Some(path)))
                .collect::<Result<Vec<_>, _>>()?
        };
        if interfaces.len() != channel.nak_control.len() && !channel.nak_control.is_empty() {
            return Err(DriverError::UnsupportedChannel);
        }
        control_group::merge(
            &mut self.control_groups,
            &mut self.control_group_uses,
            interfaces
                .into_iter()
                .zip(channel.nak_control.iter())
                .map(|(interface, control)| ControlGroup {
                    data_group: group,
                    interface,
                    control_group: *control,
                }),
        )
    }

    /// Hands `held`, what [`Self::map_nak_control`] counted for the
    /// channel of `subscription`, to its key when the add opened the key:
    /// the entries its own `nak-control` named stay with it even where no
    /// path joined them, and one the key already counted for a path it
    /// joined is released once. A second handle of a key releases `held`
    /// at once (karyos#1086).
    pub(crate) fn keep_control_groups(
        &mut self,
        subscription: NetworkSubscription,
        held: control_group::Held,
    ) {
        let first = self.subscriptions.iter_mut().find(|entry| {
            (entry.endpoint, entry.stream_id) == (subscription.endpoint, subscription.stream_id)
                && entry.users == 1
        });
        let Some(entry) = first else {
            self.release_control_groups(&held);
            return;
        };
        let mut twice = [false; MAX_CONTROL_GROUPS];
        for ((mine, bridged), again) in entry.control_held.iter_mut().zip(held).zip(&mut twice) {
            if bridged {
                *again = *mine;
                *mine = true;
            }
        }
        self.release_control_groups(&twice);
    }

    /// Releases `held` (karyos#1086).
    pub(crate) fn release_control_groups(&mut self, held: &control_group::Held) {
        control_group::release(&mut self.control_groups, &mut self.control_group_uses, held);
    }

    /// The entries of the NAK control group table in use: configured, and
    /// added by channels' `nak-control` while a channel holds them.
    pub(crate) fn control_groups_in_use(&self) -> usize {
        self.control_groups.iter().flatten().count()
    }

    /// The driver's NAK control group table, as configured and as
    /// channels' `nak-control` keys extended it (tests).
    #[cfg(test)]
    pub(crate) fn control_groups(&self) -> &ControlGroups {
        &self.control_groups
    }

    pub(crate) fn paths_isolated(&self) -> bool {
        self.paths_isolated
    }

    /// Whether a conflated view of an unreliable channel may open: its
    /// `barrier_ack_timeout` fits the skip deadlines.
    ///
    /// # Errors
    ///
    /// [`crate::agents::BarrierAckBound::FarWindow`] when it does not.
    pub(crate) fn unreliable_view_bound(
        &self,
        path_skew: Option<u64>,
    ) -> Result<(), crate::agents::BarrierAckBound> {
        let Some(skew) = path_skew else {
            return self.unreliable_view_bound;
        };
        // A channel's own `path-skew`: the check at this subscription's
        // admission, with that skew (karyos#1056, the #658 note).
        let (timeout, paths) = self.view_bound_inputs;
        crate::agents::conflated_gate::check_far_window(
            timeout,
            &crate::agents::roles::image_skip_config(
                &crate::paths::PathConfig {
                    path_skew_window: skew,
                    ..paths
                },
                false,
            ),
        )
    }

    /// One channel with `paths` refused: the sockets cannot be isolated.
    pub(crate) fn count_paths_refused(&mut self) {
        if let Some(count) = self.paths_refused.checked_add(1) {
            self.paths_refused = count;
        }
    }

    /// Channels with `paths` refused, and later paths that could not be
    /// held.
    pub(crate) fn path_counters(&self) -> (u64, u64) {
        (self.paths_refused, self.path_failures)
    }

    /// Lets channels with `paths` through, as if the backend isolated their
    /// sockets (tests: on one interface every path sees every datagram).
    #[cfg(test)]
    pub(crate) fn assume_isolated_paths(&mut self) {
        self.paths_isolated = true;
    }

    /// The endpoint joined to the NAK control group of the data group
    /// `config` on `bind`'s port, and the group's address: `None` when the
    /// table names none, or when the join failed (counted, RC-15). The
    /// endpoint loops its own sends back, so co-hosted receivers see each
    /// other's NAKs; a receiver drops its own.
    fn hold_control_group(
        &mut self,
        bind: SocketAddr,
        config: MulticastConfig,
    ) -> Option<(EndpointId, SocketAddr)> {
        let (_, group) = self.control_group_of(bind, config)?;
        let control = MulticastConfig {
            group: group.ip(),
            loopback: true,
            ..config
        };
        let local = SocketAddr::new(bind.ip(), group.port());
        match self.hold_endpoint(local, Some(control)) {
            Ok(endpoint) => Some((endpoint, group)),
            Err(_) => {
                if let Some(count) = self.control_join_failures.checked_add(1) {
                    self.control_join_failures = count;
                }
                None
            }
        }
    }

    /// The table's entry for the data group `config` on `bind`'s port, on
    /// its interface: its slot and its control group.
    fn control_group_of(
        &self,
        bind: SocketAddr,
        config: MulticastConfig,
    ) -> Option<(usize, SocketAddr)> {
        let data_group = SocketAddr::new(config.group, bind.port());
        let interface = match config.interface {
            InterfaceSel::Address(address) if !address.is_unspecified() => {
                Some(IpAddr::V4(address))
            }
            _ => None,
        };
        control_group::lookup_slot(&self.control_groups, data_group, interface)
    }

    /// The control group the table names for each path of a key, reliable
    /// or not: none for a unicast one (karyos#1086 review).
    fn control_asked(
        &self,
        bind: SocketAddr,
        multicast: Option<MulticastConfig>,
        later: &[(SocketAddr, MulticastConfig)],
    ) -> ControlAsked {
        let mut asked = [None; LATER_PATHS + 1];
        let Some(config) = multicast else {
            return asked;
        };
        let routes = std::iter::once((bind, config)).chain(later.iter().copied());
        for (slot, (bind, config)) in asked.iter_mut().zip(routes) {
            *slot = self.control_group_of(bind, config).map(|(_, group)| group);
        }
        asked
    }

    /// The driver's unicast control endpoint of `bind`'s address family,
    /// bound to the unspecified address on an ephemeral port: opened on
    /// first use, one more key holds it (plan 164). `None` when it cannot
    /// open (counted): the key's SOLICITs then leave from its own endpoint.
    fn hold_solicit_endpoint(&mut self, bind: SocketAddr) -> Option<EndpointId> {
        let any = match bind {
            SocketAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };
        match self.hold_for(
            SocketAddr::new(any, 0),
            None,
            EndpointPurpose::Solicit,
            true,
        ) {
            Ok(endpoint) => Some(endpoint),
            Err(_) => {
                if let Some(count) = self.solicit_endpoint_failures.checked_add(1) {
                    self.solicit_endpoint_failures = count;
                }
                None
            }
        }
    }

    /// The driver's unicast control endpoints that send SOLICITs (plan
    /// 164), with their bound addresses: port and family. Empty with no
    /// multicast subscription.
    pub(crate) fn solicit_endpoints(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        let mut held: [Option<EndpointId>; 2] = [None; 2];
        for entry in &self.subscriptions {
            if let Some(solicit) = entry.solicit
                && !held.contains(&Some(solicit))
                && let Some(slot) = held.iter_mut().find(|slot| slot.is_none())
            {
                *slot = Some(solicit);
            }
        }
        held.into_iter()
            .flatten()
            .filter_map(|endpoint| self.endpoints.local_address(endpoint))
    }

    /// Unicast control endpoints that could not open (plan 164).
    pub(crate) fn solicit_endpoint_failures(&self) -> u64 {
        self.solicit_endpoint_failures
    }

    /// Stops `subscription`: its images retire and its endpoints, every
    /// path's, are released (control path). `false` when it is unknown.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkBusy`] when the receiver's ring is full. The
    /// table and the endpoints are then unchanged, but when the ring filled
    /// part way through a subscription with later paths, the removals of
    /// some later paths' receiver entries may already be posted. A retry
    /// posts them again, which the receiver answers as not found, and
    /// completes the removal.
    pub(crate) fn remove_subscription(
        &mut self,
        subscription: NetworkSubscription,
    ) -> Result<bool, DriverError> {
        let Some(index) = self.subscriptions.iter().position(|entry| {
            (entry.endpoint, entry.stream_id) == (subscription.endpoint, subscription.stream_id)
        }) else {
            return Ok(false);
        };
        let NetworkSubscription {
            endpoint,
            stream_id,
        } = subscription;
        match self.subscriptions.get_mut(index) {
            // Another handle still holds the receiver's entry.
            Some(entry) if entry.users > 1 => {
                if let Some(users) = entry.users.checked_sub(1) {
                    entry.users = users;
                }
            }
            _ => {
                // The later paths first: a removal posted again for a path
                // already removed is answered not found, which is harmless.
                let later = self
                    .subscriptions
                    .get(index)
                    .map_or([None; LATER_PATHS], |entry| entry.later);
                for path in later.into_iter().flatten() {
                    self.links
                        .receiver
                        .post(|reply| AgentCommand::RemoveSubscription {
                            reply,
                            endpoint: path,
                            stream_id,
                        })
                        .map_err(|_| DriverError::NetworkBusy)?;
                }
                self.links
                    .receiver
                    .post(|reply| AgentCommand::RemoveSubscription {
                        reply,
                        endpoint,
                        stream_id,
                    })
                    .map_err(|_| DriverError::NetworkBusy)?;
                let entry = self.subscriptions.swap_remove(index);
                self.release_control_groups(&entry.control_held);
                if let Some(control) = entry.control {
                    release(&mut self.send_endpoints, control);
                }
                if let Some(solicit) = entry.solicit {
                    release(&mut self.send_endpoints, solicit);
                }
                for path in entry.later.into_iter().flatten() {
                    release(&mut self.send_endpoints, path);
                }
                for control in entry.later_controls.into_iter().flatten() {
                    release(&mut self.send_endpoints, control);
                }
            }
        }
        release(&mut self.send_endpoints, endpoint);
        Ok(true)
    }

    /// Removes `subscription` now, or once the receiver's ring has room
    /// (a client's subscription ending with its client, W5b).
    pub(crate) fn remove_subscription_later(&mut self, subscription: NetworkSubscription) {
        if self.remove_subscription(subscription).is_err() {
            self.pending_unsubscribe.push(subscription);
        }
    }

    /// Unsubscriptions waiting for room in the receiver's ring.
    #[cfg(test)]
    pub(crate) fn pending_unsubscribes(&self) -> usize {
        self.pending_unsubscribe.len()
    }

    /// The capacity of the unsubscription buffer.
    #[cfg(test)]
    pub(crate) fn pending_unsubscribe_capacity(&self) -> usize {
        self.pending_unsubscribe.capacity()
    }

    /// The image events of the last cycle, for the conductor to apply;
    /// hand the buffer back with [`Network::return_image_events`].
    pub(crate) fn take_image_events(&mut self) -> Vec<ImageEvent> {
        core::mem::take(&mut self.image_events)
    }

    /// Gives the event buffer back, emptied, keeping its capacity.
    pub(crate) fn return_image_events(&mut self, mut events: Vec<ImageEvent>) {
        events.clear();
        self.image_events = events;
    }

    /// The lane buffers of the installed image `slot`.
    pub(crate) fn image_lanes(&self, slot: SlotRef) -> Option<Vec<Arc<LogBuffer<T>>>> {
        self.images.installed(slot).map(<[_]>::to_vec)
    }

    /// The conflated lane of the installed image `slot` and a clone of the
    /// link its view shares with the receiver's seal gate.
    #[must_use]
    pub(crate) fn image_freshness(
        &self,
        slot: SlotRef,
    ) -> Option<(Lane, karyos_sys::freshness::FreshnessLink)> {
        self.images
            .freshness(slot)
            .map(|(lane, link)| (lane, link.clone()))
    }

    /// Records the installed image `slot` and the aggregate exposing it;
    /// an unexposed image's lane conductors are taken from `lanes` and
    /// driven here.
    pub(crate) fn record_image(
        &mut self,
        slot: SlotRef,
        source: ImageSource,
        traced: karyos_protocol::trace_hook::PublicationIdentity,
        exposed: Option<crate::embedded::AggregateHandle>,
        lanes: &[Arc<LogBuffer<T>>],
    ) {
        let mut conductors = Vec::new();
        if exposed.is_none() {
            if let Some(count) = self.images_unexposed.checked_add(1) {
                self.images_unexposed = count;
            }
            conductors = lanes
                .iter()
                .filter_map(LogBuffer::<T>::conductor_owned)
                .collect();
        }
        self.net_images.push(NetImage {
            slot,
            endpoint: source.endpoint,
            traced,
            lanes: lanes.len(),
            exposed,
            conductors,
        });
    }

    /// Whether the aggregate `registration` is the network's: a network
    /// publication's or an exposed image's.
    pub(crate) fn is_network_aggregate(&self, registration: u64) -> bool {
        self.publications
            .iter()
            .any(|publication| publication.registration == registration)
            || self.net_images.iter().any(|image| {
                image
                    .exposed
                    .is_some_and(|handle| handle.registration() == registration)
            })
    }

    /// An index bound for [`Network::exposed_image_at`].
    pub(crate) fn image_slots(&self) -> usize {
        self.net_images.len()
    }

    /// The exposed image at `index` and the endpoint it arrived on; `None`
    /// past the end or for an image driven unexposed.
    pub(crate) fn exposed_image_at(
        &self,
        index: usize,
    ) -> Option<(EndpointId, crate::embedded::AggregateHandle)> {
        self.net_images
            .get(index)
            .and_then(|image| image.exposed.map(|handle| (image.endpoint, handle)))
    }

    /// The endpoint of the image `slot`.
    pub(crate) fn image_endpoint(&self, slot: SlotRef) -> Option<EndpointId> {
        self.net_images
            .iter()
            .find(|image| image.slot == slot)
            .map(|image| image.endpoint)
    }

    /// Drops the conductors of the unexposed image `slot`, which retires.
    pub(crate) fn retire_unexposed(&mut self, slot: SlotRef) {
        if let Some(image) = self.net_images.iter_mut().find(|image| image.slot == slot) {
            image.conductors.clear();
        }
    }

    /// The aggregate exposing the image `slot`, if any.
    pub(crate) fn image_aggregate(
        &self,
        slot: SlotRef,
    ) -> Option<crate::embedded::AggregateHandle> {
        self.net_images
            .iter()
            .find(|image| image.slot == slot)
            .and_then(|image| image.exposed)
    }

    /// The installed image that `handle` exposes.
    pub(crate) fn image_slot(&self, handle: &crate::embedded::AggregateHandle) -> Option<SlotRef> {
        self.net_images
            .iter()
            .find(|image| image.exposed.as_ref() == Some(handle))
            .map(|image| image.slot)
    }

    /// Moves the seal gate of `lane` of the installed image `slot`, and
    /// the conductor's record of its view link, to `link`: a recreated
    /// view's (karyos#658).
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkBusy`] when the receiver's command ring is
    /// full; nothing changes then.
    pub(crate) fn relink_view(
        &mut self,
        slot: SlotRef,
        lane: Lane,
        link: &karyos_sys::freshness::FreshnessLink,
    ) -> Result<(), DriverError> {
        self.links
            .receiver
            .post(|reply| AgentCommand::RelinkView {
                reply,
                slot,
                lane,
                link: link.clone(),
            })
            .map_err(|_| DriverError::NetworkBusy)?;
        let _ = self.images.relink(slot, link.clone());
        Ok(())
    }

    /// Forgets the reclaimed image `slot`.
    pub(crate) fn forget_image(&mut self, slot: SlotRef) {
        self.net_images.retain(|image| image.slot != slot);
    }

    /// Each exposed image's aggregate, in install order.
    #[cfg(test)]
    pub(crate) fn exposed_images(
        &self,
    ) -> impl Iterator<Item = crate::embedded::AggregateHandle> + '_ {
        self.net_images.iter().filter_map(|image| image.exposed)
    }

    /// The bound local address of `endpoint` in its current epoch.
    pub(crate) fn endpoint_address(&self, endpoint: EndpointId) -> Option<SocketAddr> {
        self.endpoints.local_address(endpoint)
    }

    /// The bound local address of the endpoint `stream_id`'s first
    /// subscription path is on, in its current epoch (a port 0 bind
    /// resolved by the kernel); `None` without such a subscription.
    pub(crate) fn subscription_address(&self, stream_id: i32) -> Option<SocketAddr> {
        let entry = self
            .subscriptions
            .iter()
            .find(|entry| entry.stream_id == stream_id)?;
        self.endpoints.local_address(entry.endpoint)
    }

    /// The exposed image aggregate that `matches`, the oldest first.
    pub(crate) fn exposed_image(
        &self,
        matches: impl Fn(&crate::embedded::AggregateHandle) -> bool,
    ) -> Option<crate::embedded::AggregateHandle> {
        self.net_images
            .iter()
            .filter_map(|image| image.exposed)
            .find(|handle| matches(handle))
    }

    /// `AddSubscription` answers the receiver refused despite the mirror:
    /// a drift between the tables, never expected.
    pub(crate) fn subscription_refusals(&self) -> u64 {
        self.subscription_refusals
    }

    /// Drops the receiver's DATA datagrams numbered `nth` (from 0) from
    /// now on, as a lossy path would (tests, Shared mode only).
    #[cfg(test)]
    pub(crate) fn drop_receiver_data(&mut self, nth: &[u64]) {
        if let Agents::Shared(agents) = &mut self.agents {
            agents.receiver.drop_data(nth);
        }
    }

    /// Loses the receiver's DATA with a payload at or past `term_offset`
    /// of the first term, from every path or from one (tests).
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "its tests need two real paths, on Linux")
    )]
    pub(crate) fn drop_receiver_tail(&mut self, term_offset: u32, one_source: bool) {
        if let Agents::Shared(agents) = &mut self.agents {
            agents.receiver.drop_tail(term_offset, one_source);
        }
    }

    /// The sources whose idle heartbeat past the lost tail arrived at the
    /// receiver (tests).
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "its tests need two real paths, on Linux")
    )]
    pub(crate) fn receiver_tail_heartbeat_sources(&self) -> usize {
        match &self.agents {
            Agents::Shared(agents) => agents.receiver.tail_heartbeat_sources(),
            _ => 0,
        }
    }

    /// Holds back the attach of the conflated views built from now on, as
    /// if their feeders attached late (tests).
    #[cfg(test)]
    pub(crate) fn defer_view_attach(&mut self) {
        self.defer_view_attach = true;
    }

    /// Whether views are attached late (always `false` outside tests).
    pub(crate) fn defers_view_attach(&self) -> bool {
        #[cfg(test)]
        return self.defer_view_attach;
        #[cfg(not(test))]
        false
    }

    /// What the conflated views of network images did.
    #[must_use]
    pub(crate) fn view_counters(&self) -> NetworkViewCounters {
        self.views
    }

    /// Counts into the views' counters with `count`.
    pub(crate) fn count_views(&mut self, count: impl FnOnce(&mut NetworkViewCounters)) {
        count(&mut self.views);
    }

    /// The conflated lane and table configuration of the subscription to
    /// `stream_id` on `endpoint`, the view an image of that key gets.
    ///
    /// An image installed on a later path's endpoint (its first path lost,
    /// then a path challenge) finds its subscription there too.
    #[must_use]
    pub(crate) fn conflation_of(
        &self,
        endpoint: EndpointId,
        stream_id: i32,
    ) -> Option<(Lane, karyos_sys::conflation::ConflationConfig)> {
        self.subscriptions
            .iter()
            .find(|entry| entry.serves(endpoint, stream_id))
            .and_then(|entry| entry.conflated)
    }

    /// Makes the sender drop every NAK unread (`true`) or read them again
    /// (`false`) (tests, Shared mode only).
    #[cfg(test)]
    pub(crate) fn sender_ignores_naks(&mut self, ignore: bool) {
        if let Agents::Shared(agents) = &mut self.agents {
            if ignore {
                agents.sender.ignore_naks();
            } else {
                agents.sender.heed_naks();
            }
        }
    }

    /// The message tokens of each publication's sender gate, in the
    /// sender's order (tests, Shared mode only).
    #[cfg(test)]
    pub(crate) fn gate_message_tokens(&self) -> Vec<Option<u64>> {
        let mut tokens = Vec::new();
        if let Agents::Shared(agents) = &self.agents {
            let mut index = 0;
            while let Some(gate) = agents.sender.gate_message_tokens(index) {
                tokens.push(gate);
                index += 1;
            }
        }
        tokens
    }

    /// Distinct network subscription keys held, for tests.
    #[cfg(test)]
    pub(crate) fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// The endpoint of each path of the subscription to `stream_id`, the
    /// first path first (tests).
    #[cfg(test)]
    pub(crate) fn subscription_endpoints(&self, stream_id: i32) -> Vec<EndpointId> {
        self.subscriptions
            .iter()
            .find(|entry| entry.stream_id == stream_id)
            .map(|entry| {
                core::iter::once(entry.endpoint)
                    .chain(entry.later.into_iter().flatten())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The configured identity the receiver holds for each path endpoint
    /// of the subscription to `stream_id`, the first path first (tests,
    /// Shared mode only).
    #[cfg(test)]
    pub(crate) fn path_identities(
        &self,
        stream_id: i32,
    ) -> Vec<Option<crate::membership::ReceiverIdentity>> {
        let (Some(entry), Agents::Shared(agents)) = (
            self.subscriptions
                .iter()
                .find(|entry| entry.stream_id == stream_id),
            &self.agents,
        ) else {
            return Vec::new();
        };
        core::iter::once(entry.endpoint)
            .chain(entry.later.into_iter().flatten())
            .map(|endpoint| agents.receiver.configured_identity(endpoint, stream_id))
            .collect()
    }

    /// Network publications tracked, for tests.
    #[cfg(test)]
    pub(crate) fn publication_count(&self) -> usize {
        self.publications.len()
    }

    /// Images installed but not exposed so far.
    pub(crate) fn images_unexposed(&self) -> u64 {
        self.images_unexposed
    }

    /// NAK control group joins that failed (RC-15): those keys run
    /// without peer suppression input.
    pub(crate) fn control_join_failures(&self) -> u64 {
        self.control_join_failures
    }

    /// Endpoints some publication or subscription holds (tests).
    #[cfg(test)]
    pub(crate) fn held_endpoints(&self) -> usize {
        self.send_endpoints
            .iter()
            .filter(|entry| entry.users > 0)
            .count()
    }

    /// One publication less holds `endpoint`; the last one retires it.
    pub(crate) fn release_send_endpoint(&mut self, endpoint: EndpointId) {
        release(&mut self.send_endpoints, endpoint);
    }

    /// Hands `publication` and its data path to the agents: the receiver
    /// learns its alias, then the sender announces it (control path). The
    /// caller holds its send endpoint.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkBusy`] when an agent's ring is full; nothing
    /// is posted to the sender then.
    pub(crate) fn add_publication(
        &mut self,
        registration: u64,
        publication: Publication,
        mut outbound: Box<Outbound<T>>,
        guard: Option<(
            crate::agents::data::GuardSpec,
            crate::guard_ack::GuardSenderId,
        )>,
        roles: Option<Box<crate::membership::PublicationRoles>>,
        channel: SenderChannel,
    ) -> Result<(), DriverError> {
        let (spec, guard_sender) = guard.map_or((None, None), |(spec, id)| (Some(spec), Some(id)));
        let frontier = spec
            .as_ref()
            .map(|spec| SharedFrontier(std::sync::Arc::clone(&spec.frontier)));
        let (endpoint, alias) = (publication.endpoint, publication.alias);
        // Its later paths: each endpoint publishes the alias, so the
        // receiver hands that path's SMs and NAKs to the sender.
        let mut later = [None; LATER_PATHS];
        for (slot, path) in later.iter_mut().zip(outbound.route_endpoints().skip(1)) {
            *slot = Some(path);
        }
        let paths = || core::iter::once(endpoint).chain(later.into_iter().flatten());
        let mine = |key: &(EndpointId, Alias)| key.1 == alias && paths().any(|path| path == key.0);
        let (traced, lanes) = (
            trace::identity(&publication.identity, alias),
            publication.lane_count,
        );
        // One tracked publication per key: the sender's answers then name
        // exactly one entry, and a key freed locally while its old
        // publication is still being removed waits for it (#279 P1).
        if self.publications.iter().any(|entry| {
            entry.alias == alias && entry.paths().any(|held| paths().any(|path| path == held))
        }) {
            return Err(DriverError::NetworkBusy);
        }
        // One control endpoint holds at most one dynamic publication of a
        // stream, since a REGISTER names only its stream (design 2.5, 3.2
        // step 1); the sender refuses it too, this names why.
        if channel.registration.is_some()
            && self.publications.iter().any(|entry| {
                entry.alias.stream_id == alias.stream_id
                    && entry
                        .channel
                        .as_ref()
                        .is_some_and(|held| held.registration.is_some())
                    && entry.paths().any(|held| held == endpoint)
            })
        {
            return Err(DriverError::DynamicPublicationExists {
                stream_id: alias.stream_id,
            });
        }
        // Every destination of a dynamic publication needs a binding at
        // the sender, so the driver's dynamic publications together fit
        // `receiver_bindings` (karyos#941 item 2); one still being removed
        // counts until it is gone.
        if channel.registration.is_some() {
            let dynamic = self
                .publications
                .iter()
                .filter(|entry| {
                    entry
                        .channel
                        .as_ref()
                        .is_some_and(|held| held.registration.is_some())
                })
                .count();
            let needed = dynamic
                .checked_add(1)
                .and_then(|count| count.checked_mul(self.max_destinations));
            if needed.is_none_or(|needed| needed > self.receiver_bindings) {
                return Err(DriverError::ReceiverBindings {
                    needed: needed.unwrap_or(usize::MAX),
                    held: self.receiver_bindings,
                });
            }
        }
        // A reincarnating publication's key stays reserved for its next
        // incarnation, the only add that takes it.
        let others = || {
            self.reincarnations
                .iter()
                .filter(move |next| next.registration != registration)
        };
        if others().any(|next| {
            next.alias == alias
                && next
                    .held
                    .iter()
                    .any(|held| paths().any(|path| path == *held))
        }) {
            return Err(DriverError::NetworkBusy);
        }
        // Each path's alias takes room, held or stale. A queued alias of
        // one of its keys is superseded by the add below, so it takes none.
        // A reincarnating publication's paths keep their room, so its next
        // incarnation's add is not refused for a full table: counted once,
        // by its old entry while that is still being removed.
        let held = self
            .publications
            .iter()
            .map(|entry| entry.paths().count())
            .chain(
                others()
                    .filter(|next| {
                        !self
                            .publications
                            .iter()
                            .any(|entry| entry.registration == next.registration)
                    })
                    .map(|next| next.held.len()),
            )
            .try_fold(0usize, usize::checked_add);
        let stale_only = self
            .stale_aliases
            .iter()
            .filter(|key| {
                !mine(key)
                    && !self.publications.iter().any(|entry| {
                        entry.alias == key.1 && entry.paths().any(|path| path == key.0)
                    })
            })
            .count();
        let total = held
            .and_then(|held| held.checked_add(stale_only))
            .and_then(|held| held.checked_add(paths().count()));
        if total.is_none_or(|total| total > self.capacity) {
            return Err(DriverError::NetworkPublicationsFull);
        }
        // Each endpoint it sends on must hold its routes, queues and TX
        // slots with what its other publications hold and the control
        // reserve, or it could never open and would send nothing
        // (karyos#859).
        let demand = outbound.tx_demand();
        let per_destination = outbound.destination_demand();
        for &(path, need) in &demand {
            self.endpoint_room(path, need)?;
        }
        let mut published = 0usize;
        for path in paths() {
            let posted = self
                .links
                .receiver
                .post(|reply| AgentCommand::AddPublishedAlias {
                    reply,
                    endpoint: path,
                    alias,
                });
            if posted.is_err() {
                // The paths already published are stale now; the capacity
                // check above leaves room for them.
                let mut stale = Stale {
                    queue: &mut self.stale_aliases,
                    overflows: &mut self.stale_overflows,
                };
                for path in paths().take(published) {
                    stale.queue_alias(path, alias);
                }
                return Err(DriverError::NetworkBusy);
            }
            // At most four paths: no overflow.
            if let Some(next) = published.checked_add(1) {
                published = next;
            }
        }
        // A key reused before its stale alias was posted: the new
        // `AddPublishedAlias`, now in the ring, supersedes it, and a removal
        // posted later would drop the new publication's alias. One posted
        // earlier precedes the add in the ring.
        self.stale_aliases.retain(|key| !mine(key));
        let admission = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
        outbound.set_admission_slot(std::sync::Arc::clone(&admission));
        let posted = self
            .links
            .sender
            .post(|reply| AgentCommand::AddPublication {
                reply,
                publication,
                outbound,
                guard: spec,
                roles,
            });
        if posted.is_err() {
            // The receiver learned the aliases: they are stale now. The
            // capacity check above leaves room for them.
            let mut stale = Stale {
                queue: &mut self.stale_aliases,
                overflows: &mut self.stale_overflows,
            };
            for path in paths() {
                stale.queue_alias(path, alias);
            }
            return Err(DriverError::NetworkBusy);
        }
        self.publications.push(NetPublication {
            registration,
            endpoint,
            later,
            alias,
            state: NetworkPublicationState::Adding,
            remove_posted: false,
            drained: false,
            session_posted: false,
            guard_sender,
            frontier,
            traced,
            lanes,
            demand,
            per_destination,
            adds_pending: Vec::with_capacity(self.max_destinations),
            max_destinations: self.max_destinations,
            limited: None,
            trace_closes: Vec::new(),
            linger: channel.linger,
            channel: Some(channel),
            reincarnating: false,
            removed_destinations: std::collections::VecDeque::with_capacity(self.max_destinations),
            removals_overwritten: 0,
            destination_changes: std::collections::VecDeque::new(),
            admission,
        });
        Ok(())
    }

    /// Whether `endpoint` holds `need` more with what its publications
    /// hold and the control reserve (karyos#859). An endpoint not in the
    /// send table (none opened it for sending) is not checked.
    ///
    /// # Errors
    ///
    /// [`DriverError::EndpointCapacity`]: the first limit that `need`
    /// passes, with the endpoint's capacity and what it would take.
    fn endpoint_room(&self, endpoint: EndpointId, need: TxDemand) -> Result<(), DriverError> {
        let Some(capacity) = self
            .send_endpoints
            .iter()
            .find(|entry| entry.endpoint == endpoint)
            .map(|entry| entry.capacity)
        else {
            return Ok(());
        };
        let held = self
            .publications
            .iter()
            .flat_map(|entry| entry.demand.iter())
            .filter(|(held, _)| *held == endpoint)
            .fold(self.control_reserve, |sum, (_, demand)| sum.plus(*demand));
        let total = held.plus(need);
        for (limit, capacity, needed) in [
            (EndpointLimit::TxSlots, capacity.slots, total.slots),
            (EndpointLimit::Queues, capacity.queues, total.queues),
            (EndpointLimit::Routes, capacity.routes, total.routes),
        ] {
            if needed > capacity {
                return Err(DriverError::EndpointCapacity {
                    limit,
                    capacity,
                    needed,
                });
            }
        }
        Ok(())
    }

    /// The next schedule violation a sender reported, for the conductor to
    /// apply (timed-tx.md section 11, TT-6).
    pub(crate) fn pop_schedule_violation(&mut self) -> Option<ScheduleViolation> {
        self.schedule_violations.pending.pop()
    }

    /// Schedule violation reports dropped since the last call, for the
    /// driver's `schedule violations dropped` counter: past the bound, or
    /// naming no live publication or incarnation.
    pub(crate) fn take_schedule_violations_dropped(&mut self) -> u64 {
        core::mem::take(&mut self.schedule_violations.dropped)
    }

    /// A report the conductor found stale: its lane is gone, or in another
    /// incarnation.
    pub(crate) fn count_stale_schedule_violation(&mut self) {
        self.schedule_violations.drop_one();
    }

    /// A released guard sender to deregister, each once.
    pub(crate) fn pop_released_guard(&mut self) -> Option<crate::guard_ack::GuardSenderId> {
        self.released_guards.ids.pop()
    }

    /// Starts removing the publication `registration`; `false` when it is
    /// not a network publication. Its data path comes back later.
    pub(crate) fn remove_publication(
        &mut self,
        registration: u64,
        trace_closes: Vec<(Lane, u64)>,
    ) -> bool {
        // A reincarnation ends with its publication: nothing is added.
        let reincarnating = self.end_reincarnation(registration);
        let Some(entry) = self
            .publications
            .iter_mut()
            .find(|entry| entry.registration == registration)
        else {
            return reincarnating;
        };
        entry.reincarnating = false;
        // Its sender journals close first, in the same ring; a repeated
        // removal adds to the closes still pending, never replaces them.
        entry.trace_closes.extend(trace_closes);
        if entry.state == NetworkPublicationState::Refused {
            // Nothing reached the sender; its endpoint is released.
            self.publications
                .retain(|entry| entry.registration != registration);
            return true;
        }
        entry.state = NetworkPublicationState::Removing;
        let mut stale = Stale {
            queue: &mut self.stale_aliases,
            overflows: &mut self.stale_overflows,
        };
        post_removals(
            &self.links,
            &mut self.publications,
            &mut stale,
            self.publication_linger,
        );
        true
    }

    /// Why no publication can be added any more: an agent failed, or the
    /// network closed; `None` while it can.
    pub(crate) fn unusable(&self) -> Option<DriverError> {
        if let Some(agent) = self.failed {
            return Some(DriverError::NetworkAgent { agent });
        }
        matches!(self.agents, Agents::Closed).then_some(DriverError::NetworkUnavailable)
    }

    /// The publication identity of the image `handle` exposes (tests).
    #[cfg(test)]
    pub(crate) fn image_traced(
        &self,
        handle: &crate::embedded::AggregateHandle,
    ) -> Option<karyos_protocol::trace_hook::PublicationIdentity> {
        self.net_images
            .iter()
            .find(|image| {
                image
                    .exposed
                    .is_some_and(|exposed| exposed.registration() == handle.registration())
            })
            .map(|image| image.traced)
    }

    /// The network clock's reading.
    pub(crate) fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Starts the reincarnation of the network publication `registration`
    /// after a guard reopen (control path): one extra hold on each of its
    /// send endpoints, then its old session's removal, with no linger.
    /// Returns the estimated end of its alias's quarantine.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkAgent`] once an agent failed,
    /// [`DriverError::NetworkUnavailable`] once the network closed,
    /// [`DriverError::NetworkPublicationsFull`] past the reserved records,
    /// and [`DriverError::UnknownStream`] (naming the lane `stream`) for a
    /// publication not tracked or not added (refused or being removed).
    /// Nothing changes on error.
    pub(crate) fn start_reincarnation(
        &mut self,
        registration: u64,
        stream: u64,
        trace_closes: Vec<(Lane, u64)>,
    ) -> Result<u64, DriverError> {
        if let Some(error) = self.unusable() {
            return Err(error);
        }
        // One record per tracked publication, within the room reserved at
        // start.
        if self.reincarnations.len() >= self.reincarnations.capacity() {
            return Err(DriverError::NetworkPublicationsFull);
        }
        let unknown = DriverError::UnknownStream { stream };
        let entry = self
            .publications
            .iter_mut()
            .find(|entry| entry.registration == registration)
            .filter(|entry| {
                matches!(
                    entry.state,
                    NetworkPublicationState::Adding | NetworkPublicationState::Active
                ) && entry.channel.is_some()
            })
            .ok_or(unknown)?;
        let mut held = Vec::with_capacity(entry.paths().count());
        for path in entry.paths() {
            let Some(endpoint) = self
                .send_endpoints
                .iter_mut()
                .find(|endpoint| endpoint.endpoint == path)
            else {
                continue;
            };
            let Some(users) = endpoint.users.checked_add(1) else {
                for path in held {
                    release(&mut self.send_endpoints, path);
                }
                return Err(DriverError::NetworkEndpoint);
            };
            endpoint.users = users;
            held.push(path);
        }
        let channel = entry.channel.take().ok_or(unknown)?;
        entry.state = NetworkPublicationState::Removing;
        entry.reincarnating = true;
        // Its sender journals close first, in the same ring.
        entry.trace_closes.extend(trace_closes);
        let alias = entry.alias;
        self.reincarnations.push(Reincarnation {
            registration,
            alias,
            held,
            removed: None,
            swapped: false,
            channel,
        });
        let mut stale = Stale {
            queue: &mut self.stale_aliases,
            overflows: &mut self.stale_overflows,
        };
        post_removals(
            &self.links,
            &mut self.publications,
            &mut stale,
            self.publication_linger,
        );
        self.now()
            .checked_add(self.alias_quarantine)
            .ok_or(DriverError::InvalidConfig)
    }

    /// Where the reincarnation of `registration` stands; `None` when it is
    /// not reincarnating.
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidConfig`] when the quarantine's end is past
    /// the clock's range.
    pub(crate) fn reincarnation(
        &self,
        registration: u64,
    ) -> Result<Option<ReincarnationPhase>, DriverError> {
        let Some(entry) = self
            .reincarnations
            .iter()
            .find(|entry| entry.registration == registration)
        else {
            return Ok(None);
        };
        let now = self.now();
        let until_ns = entry
            .removed
            .unwrap_or(now)
            .checked_add(self.alias_quarantine)
            .ok_or(DriverError::InvalidConfig)?;
        Ok(Some(if entry.removed.is_some() && now >= until_ns {
            ReincarnationPhase::Ready {
                swapped: entry.swapped,
            }
        } else {
            ReincarnationPhase::Waiting { until_ns }
        }))
    }

    /// Records that the conductor swapped in the next incarnation's lanes
    /// of `registration`, and returns what its sender is added with.
    pub(crate) fn reincarnation_swapped(&mut self, registration: u64) -> Option<SenderChannel> {
        let entry = self
            .reincarnations
            .iter_mut()
            .find(|entry| entry.registration == registration)?;
        entry.swapped = true;
        Some(entry.channel.clone())
    }

    /// Ends the reincarnation of `registration`: its sender was posted, or
    /// its publication is removed. Releases the extra endpoint holds;
    /// `false` when it was not reincarnating.
    pub(crate) fn end_reincarnation(&mut self, registration: u64) -> bool {
        let Some(index) = self
            .reincarnations
            .iter()
            .position(|entry| entry.registration == registration)
        else {
            return false;
        };
        let entry = self.reincarnations.swap_remove(index);
        for path in entry.held {
            release(&mut self.send_endpoints, path);
        }
        true
    }

    /// Ends every reincarnation: the agents failed or stopped, so no next
    /// incarnation is added.
    fn end_reincarnations(&mut self) {
        for entry in self.reincarnations.drain(..) {
            for path in entry.held {
                release(&mut self.send_endpoints, path);
            }
        }
    }

    /// The state of the network publication `registration`.
    /// The admission state the sender of the network publication
    /// `registration` last observed (karyos#637); `None` before its first
    /// cycle, and for no such publication.
    pub(crate) fn publication_admission(
        &self,
        registration: u64,
    ) -> Option<karyos_protocol::cnc::NetworkAdmission> {
        let entry = self
            .publications
            .iter()
            .find(|entry| entry.registration == registration)?;
        karyos_protocol::cnc::NetworkAdmission::from_code(u64::from(
            entry.admission.load(std::sync::atomic::Ordering::Relaxed),
        ))
    }

    /// Posts the addition (`add`) or removal of `destination` to the sender
    /// of the network publication `registration` (karyos#630).
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidConfig`] for no such active publication;
    /// [`DriverError::EndpointCapacity`] for an addition its endpoint
    /// cannot hold with what it holds and the additions not answered yet
    /// (karyos#859); [`DriverError::NetworkBusy`] when the sender's ring is
    /// full or `max_destinations`
    /// additions wait for their answer.
    pub(crate) fn change_destination(
        &mut self,
        registration: u64,
        destination: std::net::SocketAddr,
        add: bool,
    ) -> Result<(), DriverError> {
        let index = self
            .publications
            .iter()
            .position(|entry| {
                entry.registration == registration && entry.state == NetworkPublicationState::Active
            })
            .ok_or(DriverError::InvalidConfig)?;
        let (endpoint, alias, per_destination, waiting) = self
            .publications
            .get(index)
            .map(|entry| {
                (
                    entry.endpoint,
                    entry.alias,
                    entry.per_destination,
                    entry.adds_pending.len(),
                )
            })
            .ok_or(DriverError::InvalidConfig)?;
        // An addition takes a route, its queues and slots once it opens:
        // checked here as at the add, and held from the post to its answer
        // so that additions in flight count too.
        let hold = per_destination.filter(|_| add);
        if let Some(need) = hold {
            if waiting >= self.max_destinations {
                return Err(DriverError::NetworkBusy);
            }
            self.endpoint_room(endpoint, need)?;
        }
        self.links
            .sender
            .post(|reply| AgentCommand::ChangeDestination {
                reply,
                endpoint,
                alias,
                registration,
                destination,
                add,
            })
            .map_err(|_| DriverError::NetworkBusy)?;
        if let (Some(need), Some(entry)) = (hold, self.publications.get_mut(index)) {
            entry.adds_pending.push(destination);
            entry.hold(endpoint, need, true);
        }
        Ok(())
    }

    /// The answers to the run-time destination changes of the network
    /// publication `registration`, oldest first, taken.
    pub(crate) fn take_destination_changes(
        &mut self,
        registration: u64,
    ) -> Vec<(std::net::SocketAddr, crate::agents::data::DestinationChange)> {
        self.publications
            .iter_mut()
            .find(|entry| entry.registration == registration)
            .map(|entry| entry.destination_changes.drain(..).collect())
            .unwrap_or_default()
    }

    /// How many removals of the network publication `registration` were
    /// overwritten by newer ones in its history (karyos#630).
    pub(crate) fn removals_overwritten(&self, registration: u64) -> u64 {
        self.publications
            .iter()
            .find(|entry| entry.registration == registration)
            .map_or(0, |entry| entry.removals_overwritten)
    }

    /// The destinations the sender of the network publication
    /// `registration` removed, the newest `max_destinations` in order, with
    /// why (karyos#630).
    pub(crate) fn removed_destinations(
        &self,
        registration: u64,
    ) -> Vec<crate::agents::data::DestinationRemoval> {
        self.publications
            .iter()
            .find(|entry| entry.registration == registration)
            .map(|entry| entry.removed_destinations.iter().copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn publication_state(&self, registration: u64) -> Option<NetworkPublicationState> {
        if self
            .reincarnations
            .iter()
            .any(|entry| entry.registration == registration)
        {
            return Some(NetworkPublicationState::Reincarnating);
        }
        self.publications
            .iter()
            .find(|entry| entry.registration == registration)
            .map(|entry| match (entry.state, entry.limited) {
                (NetworkPublicationState::Active, Some(limit)) => {
                    NetworkPublicationState::Limited(limit)
                }
                (state, _) => state,
            })
    }

    /// One conductor cycle of network work at the network clock's reading:
    /// the agents when they share this thread, then their events. Returns
    /// the work done.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkAgent`] once an agent failed (DN-9), and on
    /// every later cycle; [`DriverError::WorkCountOverflow`].
    pub(crate) fn duty(&mut self, lanes: &mut LaneSource<'_>) -> Result<u32, DriverError> {
        let now = (self.clock)();
        if let Some(agent) = self.failed {
            return Err(DriverError::NetworkAgent { agent });
        }
        let work = match &mut self.agents {
            // The receiver first, as on a shared runner thread.
            Agents::Shared(agents) => guarded(AgentKind::Receiver, || agents.receiver.do_work(now))
                .map_err(|_| AgentKind::Receiver)
                .and_then(|received| {
                    guarded(AgentKind::Sender, || agents.sender.do_work(now))
                        .map_err(|_| AgentKind::Sender)
                        .map(|sent| (received, sent))
                }),
            Agents::Threads(runner) => match runner.failed().first() {
                Some(agent) => Err(*agent),
                None => Ok((0, 0)),
            },
            Agents::Closed => return Ok(0),
        };
        let (received, sent) = match work {
            Ok(work) => work,
            Err(agent) => {
                // A failed agent never answers again (DN-9): every tracked
                // guard sender is released, so no close waits on it. The
                // gates stopped only with the sender: a shared thread runs
                // neither agent again, while a dedicated sender thread runs
                // on after a receiver failure (#381 review P1). A thread
                // reads FAILED with Acquire, after its gate's last store.
                let gates_stopped = match &self.agents {
                    Agents::Threads(runner) => runner.failed().contains(&AgentKind::Sender),
                    Agents::Shared(_) | Agents::Closed => true,
                };
                self.failed = Some(agent);
                self.release_guard_senders(gates_stopped);
                self.end_reincarnations();
                return Err(DriverError::NetworkAgent { agent });
            }
        };
        // Unsubscriptions the full ring refused earlier.
        // (None in steady state: nothing is taken or freed then.)
        // Retried in place, keeping the preallocated buffer.
        let mut index = 0;
        while let Some(&subscription) = self.pending_unsubscribe.get(index) {
            if self.remove_subscription(subscription).is_ok() {
                self.pending_unsubscribe.swap_remove(index);
            } else {
                // Below the buffer's length, which fits in usize.
                let Some(next) = index.checked_add(1) else {
                    break;
                };
                index = next;
            }
        }
        // Removals the full ring refused earlier.
        let mut stale = Stale {
            queue: &mut self.stale_aliases,
            overflows: &mut self.stale_overflows,
        };
        post_removals(
            &self.links,
            &mut self.publications,
            &mut stale,
            self.publication_linger,
        );
        // Answers about endpoints go to the table, which also serves the
        // sender's reset requests at the network clock (W-f); publication
        // answers update the publications.
        let mut events = Some(0u32);
        #[cfg(test)]
        let mut reopened = Some(self.reopened);
        let mut refusals = self.subscription_refusals;
        let violations = &mut self.schedule_violations;
        let (publications, send_endpoints, released, trace_events, reincarnations, cells) = (
            &mut self.publications,
            &mut self.send_endpoints,
            &mut self.released_guards,
            &mut self.trace_events,
            &mut self.reincarnations,
            &mut self.cells,
        );
        // The removal's end is read when its answer is applied, not at the
        // cycle's start.
        let clock = self.clock;
        let mut stale = Stale {
            queue: &mut self.stale_aliases,
            overflows: &mut self.stale_overflows,
        };
        self.endpoints.poll(
            &self.links,
            now,
            |event| {
                #[cfg(test)]
                if matches!(
                    event,
                    crate::agents::endpoints::EndpointEvent::Reopened { .. }
                ) {
                    reopened = reopened.and_then(|count| count.checked_add(1));
                }
                #[cfg(not(test))]
                let _ = event;
                events = events.and_then(|count| count.checked_add(1));
            },
            |event| {
                if let AgentEvent::Configured {
                    accepted: false,
                    subscription: Some(_),
                    ..
                } = event
                    && let Some(count) = refusals.checked_add(1)
                {
                    refusals = count;
                }
                let Some(event) =
                    trace::TraceEvent::route(event, |traced| trace_events.push(traced))
                else {
                    return;
                };
                // What the trace journals need of a publication's answer:
                // its activation, and its identity once it is gone.
                let added = match &event {
                    AgentEvent::PublicationAdded { registration, .. } => Some(*registration),
                    _ => None,
                };
                if let AgentEvent::PublicationRemoved {
                    endpoint,
                    alias,
                    registration,
                    ..
                } = &event
                    && let Some(entry) = publications.iter().find(|entry| {
                        (entry.endpoint, entry.alias, entry.registration)
                            == (*endpoint, *alias, *registration)
                    })
                {
                    trace_events.push(trace::TraceEvent::PublicationRemoved {
                        traced: entry.traced,
                    });
                }
                publication_answer(
                    publications,
                    send_endpoints,
                    &mut stale,
                    (released, cells, &mut *violations),
                    (reincarnations, clock),
                    event,
                );
                if let Some(registration) = added
                    && publications.iter().any(|entry| {
                        entry.registration == registration
                            && entry.state == NetworkPublicationState::Active
                    })
                {
                    trace_events.push(trace::TraceEvent::PublicationActive { registration });
                }
            },
        );
        #[cfg(test)]
        if let Some(count) = reopened {
            self.reopened = count;
        }
        self.subscription_refusals = refusals;
        // A send endpoint no publication holds any more retires; one not
        // active yet is tried again next cycle.
        let (endpoints, links) = (&mut self.endpoints, &self.links);
        self.send_endpoints
            .retain(|entry| entry.users > 0 || endpoints.retire(links, entry.endpoint).is_err());
        // Unexposed images' terms are prepared here; exposed ones are
        // streams the conductor drives.
        for image in &mut self.net_images {
            for conductor in &mut image.conductors {
                let _ = conductor.duty_cycle();
            }
        }
        // Image events go to the conductor, which exposes and retires the
        // images' streams (W3).
        let image_events = &mut self.image_events;
        let images = self.images.poll(&self.links.sessions, lanes, |event| {
            image_events.push(event)
        });
        let overflow = DriverError::WorkCountOverflow {
            count: received,
            delta: sent,
        };
        [sent, events.ok_or(overflow)?, images]
            .into_iter()
            .try_fold(received, u32::checked_add)
            .ok_or(overflow)
    }

    /// Stops the agents, reclaims every endpoint and drains the image
    /// table at the network clock's reading (control path; at most once,
    /// later calls report nothing).
    pub(crate) fn close(&mut self, lanes: &mut LaneSource<'_>) -> NetworkShutdown<T> {
        let now = (self.clock)();
        let mut shutdown = NetworkShutdown::default();
        let agents = match core::mem::replace(&mut self.agents, Agents::Closed) {
            Agents::Shared(mut agents) => {
                self.links.sender.request_stop();
                self.links.receiver.request_stop();
                // The agents see their flags at the start of a cycle; a
                // failed agent is not run again.
                if self.failed.is_none() {
                    for (kind, cycle) in [
                        (AgentKind::Receiver, &mut agents.receiver as &mut dyn Stop),
                        (AgentKind::Sender, &mut agents.sender as &mut dyn Stop),
                    ] {
                        if let Err(error) = guarded(kind, || cycle.cycle(now)) {
                            shutdown.failures.push(error);
                        }
                    }
                }
                Some(*agents)
            }
            Agents::Threads(runner) => {
                let mut stopped = runner.stop();
                shutdown.failures.append(&mut stopped.failures);
                shutdown.late.append(&mut stopped.late);
                stopped.into_agents()
            }
            Agents::Closed => None,
        };
        if let Some(mut agents) = agents {
            self.cells.extend(agents.take_cells());
            shutdown.agents_stopped = agents.is_stopped();
            shutdown.endpoints_retired = self.endpoints.reclaim(&self.links, &mut agents, |_| {});
        }
        let _ = self.images.poll(&self.links.sessions, lanes, |_| {});
        // The agents are gone: every tracked guard sender is released for
        // the conductor to deregister. A sender thread still running past
        // the stop timeout may still run its gates, so they are left as
        // they are.
        let sender_late = shutdown
            .late
            .iter()
            .any(|late| late.kinds().contains(&AgentKind::Sender));
        self.release_guard_senders(!sender_late);
        self.end_reincarnations();
        shutdown
    }

    /// Each endpoint's effective capabilities of its current epoch, and the
    /// opens and reopens a required capability refused (M3).
    pub(crate) fn endpoint_capabilities(
        &self,
    ) -> (
        impl Iterator<
            Item = (
                EndpointId,
                &karyos_io::sockets::endpoint::CapabilitySnapshot,
            ),
        > + '_,
        u64,
    ) {
        (self.endpoints.capabilities(), self.endpoints.missing())
    }

    /// The agents' CnC cells taken back at the close, for the conductor to
    /// free; an agent that did not come back keeps its cells.
    pub(crate) fn take_cells(&mut self) -> Vec<Counter> {
        let mut cells = core::mem::take(&mut self.cells);
        cells.extend(self.images.take_released());
        cells
    }

    /// Moves the guard sender of every tracked publication to the released
    /// list (agents stopped or failed): the conductor deregisters them.
    /// With `gates_stopped`, no sender gate runs again, so each lane a gate
    /// did not finish is superseded.
    fn release_guard_senders(&mut self, gates_stopped: bool) {
        for entry in &mut self.publications {
            if let Some(id) = entry.release_guard(gates_stopped) {
                self.released_guards.push(id);
            }
        }
    }

    /// Counts a guard sender the conductor could not deregister.
    pub(crate) fn count_guard_deregister_failure(&mut self) {
        if let Some(count) = self.guard_deregister_failures.checked_add(1) {
            self.guard_deregister_failures = count;
        }
    }

    /// Released guard senders dropped for a full list, and deregistrations
    /// that failed (tests).
    #[cfg(test)]
    pub(crate) fn guard_release_counts(&self) -> (u64, u64) {
        (self.released_guards.dropped, self.guard_deregister_failures)
    }

    /// Whether the network publication `registration` still holds its
    /// stream: tracked, and the sender still serves it (its removal
    /// lingers until `PublicationRemoved`). A failed or stopped sender
    /// holds nothing (driver-network-agents.md §7: no linger).
    pub(crate) fn holds_publication(&self, registration: u64) -> bool {
        self.failed.is_none()
            && !matches!(self.agents, Agents::Closed)
            && self
                .publications
                .iter()
                .any(|entry| entry.registration == registration)
    }

    /// Whether the agents still run.
    #[cfg(test)]
    pub(crate) fn is_running(&self) -> bool {
        !matches!(self.agents, Agents::Closed)
    }

    /// The endpoint and alias of the network publication `registration`,
    /// for tests.
    #[cfg(test)]
    pub(crate) fn publication_route(&self, registration: u64) -> Option<(EndpointId, Alias)> {
        self.publications
            .iter()
            .find(|entry| entry.registration == registration)
            .map(|entry| (entry.endpoint, entry.alias))
    }

    /// The Shared agents' counters, for test diagnostics.
    #[cfg(test)]
    pub(crate) fn agent_counters(&self) -> String {
        match &self.agents {
            Agents::Shared(agents) => format!(
                "sender {:?} receiver {:?} images {:?}",
                agents.sender.counters(),
                agents.receiver.counters(),
                self.images.counters()
            ),
            _ => String::new(),
        }
    }

    /// Whether the Shared receiver's entry of `subscription` is multicast,
    /// once it has read the command (tests).
    #[cfg(test)]
    pub(crate) fn receiver_multicast(&self, subscription: NetworkSubscription) -> Option<bool> {
        match &self.agents {
            Agents::Shared(agents) => agents
                .receiver
                .subscription_multicast(subscription.endpoint, subscription.stream_id),
            _ => None,
        }
    }

    /// The Shared receiver agent's counters, for tests.
    #[cfg(test)]
    pub(crate) fn receiver_counters(&self) -> Option<crate::agents::roles::ReceiverCounters> {
        match &self.agents {
            Agents::Shared(agents) => Some(agents.receiver.counters()),
            _ => None,
        }
    }

    /// The Shared receiver's retired images whose `StorageReclaimed` it
    /// handled, for tests.
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "used by the Linux image process tests (n5)")
    )]
    pub(crate) fn receiver_reclaimed_tombstones(&self) -> Option<usize> {
        match &self.agents {
            Agents::Shared(agents) => Some(agents.receiver.reclaimed_tombstones()),
            _ => None,
        }
    }

    /// The driver's dynamic registration counters, in Shared mode (tests).
    #[cfg(test)]
    pub(crate) fn registration_counters(
        &self,
    ) -> Option<crate::sessions::register::RegistrationCounters> {
        match &self.agents {
            Agents::Shared(agents) => Some(agents.sender.registration_counters()),
            _ => None,
        }
    }

    /// The sender agent's counters, in Shared mode (tests).
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "used by the Linux multicast test (T9)")
    )]
    pub(crate) fn sender_counters(&self) -> Option<crate::agents::roles::SenderCounters> {
        match &self.agents {
            Agents::Shared(agents) => Some(agents.sender.counters()),
            _ => None,
        }
    }

    /// Per path of the network publication `registration`, the receivers
    /// whose SMs reached the sender there, in Shared mode (tests).
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "used by the Linux two-path test")
    )]
    pub(crate) fn publication_path_bindings(&self, registration: u64) -> Vec<usize> {
        let (Some(entry), Agents::Shared(agents)) = (
            self.publications
                .iter()
                .find(|entry| entry.registration == registration),
            &self.agents,
        ) else {
            return Vec::new();
        };
        entry
            .paths()
            .map(|path| agents.sender.confirmed_bindings(path, entry.alias))
            .collect()
    }

    /// Whether a path of the network publication `registration` has an
    /// established send session, in Shared mode (tests).
    #[cfg(test)]
    pub(crate) fn publication_established(&self, registration: u64) -> bool {
        let (Some(entry), Agents::Shared(agents)) = (
            self.publications
                .iter()
                .find(|entry| entry.registration == registration),
            &self.agents,
        ) else {
            return false;
        };
        entry
            .paths()
            .any(|path| agents.sender.session_established(path, entry.alias))
    }

    /// The endpoint of each path of the network publication
    /// `registration`, the founding one first (tests).
    #[cfg(test)]
    pub(crate) fn publication_paths(&self, registration: u64) -> Vec<EndpointId> {
        self.publications
            .iter()
            .find(|entry| entry.registration == registration)
            .map(|entry| entry.paths().collect())
            .unwrap_or_default()
    }

    /// Whether the Shared receiver has `alias` published on `endpoint`
    /// (tests).
    #[cfg(test)]
    pub(crate) fn receiver_published(&self, endpoint: EndpointId, alias: Alias) -> bool {
        match &self.agents {
            Agents::Shared(agents) => agents.receiver.is_published(endpoint, alias),
            _ => false,
        }
    }

    /// Endpoint resets completed so far, for tests.
    #[cfg(test)]
    pub(crate) fn reopened(&self) -> u64 {
        self.reopened
    }

    /// Images in the image table, for tests.
    #[cfg(test)]
    pub(crate) fn image_count(&self) -> usize {
        self.images.len()
    }

    /// Term bytes the image table charges to its storage budget, for
    /// tests.
    #[cfg(test)]
    pub(crate) fn image_charge(&self) -> u64 {
        self.images.charged()
    }

    /// The image table's counters, for tests.
    #[cfg(test)]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "used by the Linux image process tests (n5)")
    )]
    pub(crate) fn image_counters(&self) -> crate::agents::images::ImageCounters {
        self.images.counters()
    }

    /// Stale aliases that found the queue full, for tests.
    #[cfg(test)]
    pub(crate) fn stale_overflows(&self) -> u64 {
        self.stale_overflows
    }

    /// Stale aliases still queued, for tests.
    #[cfg(test)]
    pub(crate) fn stale_queued(&self) -> usize {
        self.stale_aliases.len()
    }

    /// Publications holding send endpoints, over all of them, for tests.
    #[cfg(test)]
    pub(crate) fn send_endpoint_users(&self) -> usize {
        self.send_endpoints.iter().map(|entry| entry.users).sum()
    }

    /// The send endpoints held, for tests.
    #[cfg(test)]
    pub(crate) fn send_endpoints(&self) -> usize {
        self.send_endpoints.len()
    }

    /// The links, for tests that talk to the agents directly.
    #[cfg(test)]
    pub(crate) fn links(&self) -> &AgentLinks<OsSocket, T> {
        &self.links
    }

    /// What its publications hold of each send endpoint, by the driver's
    /// accounting (tests, karyos#859): `(endpoint, demand)` per endpoint
    /// held.
    #[cfg(test)]
    pub(crate) fn reserved(&self) -> Vec<(EndpointId, TxDemand)> {
        self.send_endpoints
            .iter()
            .map(|entry| {
                let held = self
                    .publications
                    .iter()
                    .flat_map(|publication| publication.demand.iter())
                    .filter(|(held, _)| *held == entry.endpoint)
                    .fold(TxDemand::default(), |sum, (_, demand)| sum.plus(*demand));
                (entry.endpoint, held)
            })
            .collect()
    }

    /// The endpoint table, for tests.
    #[cfg(test)]
    pub(crate) fn endpoints_mut(&mut self) -> (&mut Endpoints<OsSocket>, &AgentLinks<OsSocket, T>) {
        (&mut self.endpoints, &self.links)
    }
}

/// One publication less holds `endpoint` in `table`.
fn release(table: &mut [SendEndpoint], endpoint: EndpointId) {
    if let Some(entry) = table.iter_mut().find(|entry| entry.endpoint == endpoint)
        && let Some(users) = entry.users.checked_sub(1)
    {
        entry.users = users;
    }
}

/// Posts `RemovePublication`, with the `linger`, for every publication
/// being removed that is not posted yet, after its sender journals'
/// closes; then `RemoveSenderSession` for every one whose linger is over,
/// queueing its alias as stale; then `RemovePublishedAlias` for every
/// stale alias. The receiver keeps admitting the alias's controls (SMs
/// and NAKs) through the linger. A full ring leaves the rest for the next
/// cycle.
fn post_removals<T: StreamTerms>(
    links: &AgentLinks<OsSocket, T>,
    publications: &mut [NetPublication],
    stale: &mut Stale<'_>,
    linger: u64,
) {
    'entries: for entry in publications
        .iter_mut()
        .filter(|entry| entry.state == NetworkPublicationState::Removing && !entry.remove_posted)
    {
        let publication = entry.traced;
        while let Some(&(lane, number)) = entry.trace_closes.last() {
            let posted = links
                .sender
                .post(|reply| AgentCommand::CloseNetworkJournal {
                    reply,
                    publication,
                    lane,
                    number,
                });
            if posted.is_err() {
                break 'entries;
            }
            let _ = entry.trace_closes.pop();
        }
        let (endpoint, alias, registration) = (entry.endpoint, entry.alias, entry.registration);
        // A reincarnating publication's guard closed its log: no EOS is
        // due, so it does not linger.
        let linger = if entry.reincarnating {
            0
        } else {
            // The channel's own `linger`, else the network's (karyos#652).
            entry.linger.unwrap_or(linger)
        };
        let posted = links.sender.post(|reply| AgentCommand::RemovePublication {
            reply,
            endpoint,
            alias,
            registration,
            linger,
        });
        if posted.is_err() {
            break;
        }
        entry.remove_posted = true;
    }
    for entry in publications.iter_mut().filter(|entry| {
        entry.state == NetworkPublicationState::Removing && entry.drained && !entry.session_posted
    }) {
        let (endpoint, alias, registration) = (entry.endpoint, entry.alias, entry.registration);
        let posted = links
            .sender
            .post(|reply| AgentCommand::RemoveSenderSession {
                reply,
                endpoint,
                alias,
                registration,
            });
        if posted.is_err() {
            break;
        }
        entry.session_posted = true;
        for path in entry.paths() {
            stale.queue_alias(path, alias);
        }
    }
    while let Some((endpoint, alias)) = stale.queue.last().copied() {
        let posted = links
            .receiver
            .post(|reply| AgentCommand::RemovePublishedAlias {
                reply,
                endpoint,
                alias,
            });
        if posted.is_err() {
            break;
        }
        let _ = stale.queue.pop();
    }
}

/// The stale-alias queue and its overflow count.
struct Stale<'a> {
    queue: &'a mut Vec<(EndpointId, Alias)>,
    overflows: &'a mut u64,
}

impl Stale<'_> {
    /// Queues the alias of a tracked publication, once, within the
    /// capacity reserved at start.
    fn queue_alias(&mut self, endpoint: EndpointId, alias: Alias) {
        if self.queue.contains(&(endpoint, alias)) {
            return;
        }
        if self.queue.len() < self.queue.capacity() {
            self.queue.push((endpoint, alias));
        } else if let Some(count) = self.overflows.checked_add(1) {
            *self.overflows = count;
        }
    }
}

impl NetPublication {
    /// The endpoint of each of its paths, the founding one first.
    fn paths(&self) -> impl Iterator<Item = EndpointId> + '_ {
        core::iter::once(self.endpoint).chain(self.later.into_iter().flatten())
    }

    /// Takes `need` more of `endpoint` into its demand (`take`), or gives
    /// it back (karyos#859).
    fn hold(&mut self, endpoint: EndpointId, need: TxDemand, take: bool) {
        if let Some((_, held)) = self.demand.iter_mut().find(|(path, _)| *path == endpoint) {
            *held = if take {
                held.plus(need)
            } else {
                held.minus(need)
            };
        } else if take {
            self.demand.push((endpoint, need));
        }
    }

    /// Releases its guard sender, once: the sender refused or returned it,
    /// or the agents stopped or failed. With `gate_stopped` its gate never
    /// runs again, so each lane it did not finish is superseded, once; a
    /// gate still running (a receiver failure on a dedicated runner) keeps
    /// its frontier until the agents stop.
    fn release_guard(&mut self, gate_stopped: bool) -> Option<crate::guard_ack::GuardSenderId> {
        if gate_stopped && let Some(SharedFrontier(frontier)) = self.frontier.take() {
            supersede(&frontier, self.lanes);
        }
        self.guard_sender.take()
    }
}

/// A publication's submission frontier, the same cell its gate writes:
/// equal only to itself.
#[derive(Debug, Clone)]
struct SharedFrontier(std::sync::Arc<karyos_sys::submission_frontier::SubmissionFrontier>);

impl PartialEq for SharedFrontier {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for SharedFrontier {}

/// Supersedes the first `lanes` lanes of `frontier` with
/// `DRIVER_SHUTDOWN`: their gate never runs again. A lane its gate
/// finished keeps its word (the first writer wins).
pub(crate) fn supersede(frontier: &karyos_sys::submission_frontier::SubmissionFrontier, lanes: u8) {
    for lane in (0..lanes).filter_map(|lane| karyos_sys::frame::Lane::try_new(lane).ok()) {
        // A nonzero reason below the superseded bit, on a lane in range:
        // never refused.
        let _ = frontier.supersede(lane, crate::guard_streams::REASON_DRIVER_SHUTDOWN);
    }
}

/// Applies the sender's answer about a publication.
fn publication_answer<T: StreamTerms>(
    publications: &mut Vec<NetPublication>,
    send_endpoints: &mut [SendEndpoint],
    stale: &mut Stale<'_>,
    (released, cells, violations): (
        &mut ReleasedGuards,
        &mut Vec<Counter>,
        &mut ScheduleViolations,
    ),
    (reincarnations, clock): (&mut [Reincarnation], fn() -> u64),
    event: AgentEvent<OsSocket, T>,
) {
    // Each tracked publication releases its guard sender once, and the
    // list holds one per tracked publication: it never grows past it.
    // The sender refused it (its gate never ran) or returned it (its gate
    // came back with the data path, through the event ring).
    let mut release_guard = |entry: &mut NetPublication| {
        if let Some(id) = entry.release_guard(true) {
            released.push(id);
        }
    };
    // Answers name the publication's registration (#279 P1), never only
    // its key.
    let find = |publications: &mut Vec<NetPublication>, endpoint, alias, registration| {
        publications.iter().position(|entry: &NetPublication| {
            (entry.endpoint, entry.alias, entry.registration) == (endpoint, alias, registration)
        })
    };
    match event {
        AgentEvent::PublicationAdded {
            endpoint,
            alias,
            registration,
        } => {
            if let Some(entry) = find(publications, endpoint, alias, registration)
                .and_then(|index| publications.get_mut(index))
                && entry.state == NetworkPublicationState::Adding
            {
                entry.state = NetworkPublicationState::Active;
            }
        }
        AgentEvent::PublicationRefused {
            agent: AgentKind::Sender,
            endpoint,
            alias,
            registration,
        } => {
            if let Some(index) = find(publications, endpoint, alias, registration) {
                if let Some(entry) = publications.get_mut(index) {
                    release_guard(entry);
                    // Every path: its send endpoint, and the alias the
                    // receiver learned before the refusal.
                    for path in entry.paths() {
                        release(send_endpoints, path);
                        stale.queue_alias(path, alias);
                    }
                }
                match publications.get_mut(index) {
                    // Removed before the answer: nothing is left to remove.
                    Some(entry) if entry.state == NetworkPublicationState::Removing => {
                        publications.swap_remove(index);
                    }
                    Some(entry) => entry.state = NetworkPublicationState::Refused,
                    None => {}
                }
            }
        }
        // The sender drains and lingers; a publication it did not hold has
        // nothing to drain.
        AgentEvent::PublicationDraining {
            endpoint,
            alias,
            registration,
            found,
        } => {
            if !found
                && let Some(entry) = find(publications, endpoint, alias, registration)
                    .and_then(|index| publications.get_mut(index))
            {
                entry.drained = true;
            }
        }
        // The linger is over: the next removal step posts
        // `RemoveSenderSession`.
        AgentEvent::SenderSessionDrained {
            endpoint,
            alias,
            registration,
        } => {
            if let Some(entry) = find(publications, endpoint, alias, registration)
                .and_then(|index| publications.get_mut(index))
                && entry.state == NetworkPublicationState::Removing
            {
                entry.drained = true;
            }
        }
        // A timed lane's publisher breached its ring: applied by the
        // conductor if it names the live publication.
        AgentEvent::ScheduleViolated {
            endpoint,
            alias,
            registration,
            incarnation,
            lane,
        } => {
            let live = find(publications, endpoint, alias, registration)
                .and_then(|index| publications.get(index))
                .is_some_and(|entry| {
                    entry.state == NetworkPublicationState::Active && lane < entry.lanes
                });
            if live {
                violations.push(ScheduleViolation {
                    registration,
                    incarnation,
                    lane,
                });
            } else {
                violations.drop_one();
            }
        }
        // The answer to a run-time destination change: the latest ones are
        // kept.
        AgentEvent::DestinationChanged {
            endpoint,
            alias,
            registration,
            destination,
            add,
            outcome,
        } => {
            if let Some(entry) = find(publications, endpoint, alias, registration)
                .and_then(|index| publications.get_mut(index))
            {
                // An addition refused gives back what its post held; one
                // added keeps it until its removal is reported (karyos#859).
                if let Some(at) = entry
                    .adds_pending
                    .iter()
                    .position(|pending| add && *pending == destination)
                {
                    let _ = entry.adds_pending.swap_remove(at);
                    if outcome != crate::agents::data::DestinationChange::Added
                        && let Some(need) = entry.per_destination
                    {
                        entry.hold(endpoint, need, false);
                    }
                }
                if entry.destination_changes.len() >= entry.max_destinations {
                    let _ = entry.destination_changes.pop_front();
                }
                entry.destination_changes.push_back((destination, outcome));
            }
        }
        // Its sender's endpoint limit, until it opens (karyos#859).
        AgentEvent::PublicationLimit {
            endpoint,
            alias,
            registration,
            limit,
        } => {
            if let Some(entry) = find(publications, endpoint, alias, registration)
                .and_then(|index| publications.get_mut(index))
            {
                entry.limited = limit;
            }
        }
        // A destination its sender removed: kept with the publication, the
        // newest `max_destinations`, an older one overwritten and counted.
        AgentEvent::DestinationRemoved {
            endpoint,
            alias,
            registration,
            removal,
        } => {
            if let Some(entry) = find(publications, endpoint, alias, registration)
                .and_then(|index| publications.get_mut(index))
            {
                // Its route and queues pass to the close list at this
                // report (karyos#859).
                if let Some(need) = entry.per_destination {
                    entry.hold(endpoint, need, false);
                }
                if entry.removed_destinations.len() >= entry.max_destinations {
                    let _ = entry.removed_destinations.pop_front();
                    entry.removals_overwritten = entry.removals_overwritten.saturating_add(1);
                }
                entry.removed_destinations.push_back(removal);
            }
        }
        AgentEvent::PublicationRemoved {
            endpoint,
            alias,
            registration,
            outbound,
        } => {
            // Its cells (M2b) go to the conductor to free; the lane readers
            // drop here, on the control path.
            if let Some(mut taken) = outbound.and_then(|mut outbound| outbound.take_cells()) {
                cells.extend(taken.take());
            }
            if let Some(index) = find(publications, endpoint, alias, registration) {
                let mut entry = publications.swap_remove(index);
                release_guard(&mut entry);
                for path in entry.paths() {
                    release(send_endpoints, path);
                }
                // The old session's terminal transition: its alias's
                // quarantine runs from here (network-sessions.md).
                if entry.reincarnating
                    && let Some(next) = reincarnations
                        .iter_mut()
                        .find(|next| next.registration == registration)
                {
                    next.removed = Some(clock());
                }
            }
        }
        _ => {}
    }
}

/// One duty cycle of either agent, for the final cycle of a close.
trait Stop {
    fn cycle(&mut self, now: u64) -> Result<u32, AgentError>;
}

impl<T: StreamTerms> Stop for crate::agents::SenderAgent<OsSocket, T> {
    fn cycle(&mut self, now: u64) -> Result<u32, AgentError> {
        self.do_work(now)
    }
}

impl<T: StreamTerms> Stop for crate::agents::ReceiverAgent<OsSocket, T> {
    fn cycle(&mut self, now: u64) -> Result<u32, AgentError> {
        self.do_work(now)
    }
}

pub(crate) mod client;

/// A stream configuration for tests (`net` submodules).
#[cfg(test)]
pub(crate) fn e2e_config(stream_id: i32) -> crate::embedded::StreamConfig {
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    crate::embedded::StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap_or_else(|_| unreachable!()),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: 100,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}
pub mod control_group;
mod publish;
mod subscribe;
pub(crate) mod trace;

#[cfg(test)]
mod e2e;
#[cfg(test)]
mod netem;

pub use publish::NetworkGuard;

#[cfg(test)]
mod tests;
