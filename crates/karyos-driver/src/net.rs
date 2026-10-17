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
//!   lane streams of one aggregate (interim keying, ACS 15937) and seals
//!   and retires them with the image. An image it cannot expose is still
//!   fed: its lane conductors are driven here until it retires.

use karyos_sys::frame::Lane;
use std::net::{IpAddr, SocketAddr};

use karyos_io::sockets::OsSocket;
use karyos_io::sockets::endpoint::{InterfaceSel, MulticastConfig, SocketsConfig};

pub use control_group::{ControlGroup, ControlGroups, MAX_CONTROL_GROUPS};
use karyos_protocol::network::Alias;

use crate::agents::data::Outbound;
use crate::agents::{AgentCommand, AgentEvent, EndpointId};
use crate::sessions::send::Publication;

use crate::agents::endpoints::Endpoints;
use crate::agents::images::{ImageEvent, ImageTable, ImageTemplate};
use crate::agents::{
    AgentConfig, AgentError, AgentKind, AgentLinks, AgentRunner, LateAgent, NetworkAgents,
    ThreadingMode, YieldThenSleep, guarded, network_agents,
};
use crate::error::DriverError;
use crate::sessions::receive::SlotRef;
use karyos_sys::log_buffer::{Conductor, LogBuffer};
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
}

impl Default for NetworkStreamDefaults {
    fn default() -> Self {
        Self {
            term_length: 1 << 20,
            mtu: karyos_sys::sizing::DEFAULT_MTU,
            lanes: 1,
            spare_slots: 3,
            max_subscribers: 8,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
        }
    }
}

/// Where the agents are.
#[derive(Debug)]
enum Agents {
    /// On the conductor's thread.
    Shared(Box<NetworkAgents<OsSocket>>),
    /// On their own threads.
    Threads(AgentRunner<OsSocket>),
    /// Stopped and reclaimed.
    Closed,
}

/// What closing the network left behind.
#[derive(Debug, Default)]
pub struct NetworkShutdown {
    /// Endpoints retired cleanly.
    pub endpoints_retired: usize,
    /// The agents' failures, as their threads reported them.
    pub failures: Vec<AgentError>,
    /// Threads that did not stop within `stop_timeout`; they still own
    /// their agents and can be joined.
    pub late: Vec<LateAgent<OsSocket>>,
    /// Whether every agent that was handed back saw its stop flag.
    pub agents_stopped: bool,
    /// Guard senders of network publications deregistered with the close,
    /// so no guard close waits on them.
    pub guard_senders_released: usize,
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
}

/// A network publication of this driver.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A guarded publication's sender gate, registered with the guard's
    /// owner; released once the sender refused or returned it.
    guard_sender: Option<crate::guard_ack::GuardSenderId>,
    /// The identity its trace journals name (trace-network.md §5).
    traced: karyos_protocol::trace_hook::PublicationIdentity,
    /// Its lane count.
    lanes: u8,
    /// Its open sender journals to close before `RemovePublication`, in the
    /// same ring (P2.12 step 3): `(lane, journal number)`.
    trace_closes: Vec<(Lane, u64)>,
}

/// An endpoint shared by the publications and subscriptions bound to one
/// address (and multicast group).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendEndpoint {
    bind: SocketAddr,
    multicast: Option<MulticastConfig>,
    endpoint: EndpointId,
    /// Publications and subscriptions that hold it.
    users: usize,
}

/// A network subscription of this driver (W3): the receiver holds one
/// entry per endpoint and stream, so the handles of one key are counted
/// (#283 P2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetSubscription {
    endpoint: EndpointId,
    stream_id: i32,
    /// The channel's reliability, which every handle of this key shares.
    reliable: bool,
    /// The endpoint joined to the data group's NAK control group, if the
    /// table names one and its join succeeded (RC-15).
    control: Option<EndpointId>,
    /// The receiver identity every handle of this key shares (MC-1).
    identity: Option<crate::membership::ReceiverIdentity>,
    /// The conflated lane and the view's table configuration every handle
    /// of this key shares (conflated-network-images.md (a)).
    conflated: Option<(Lane, karyos_sys::conflation::ConflationConfig)>,
    /// The endpoints of the channel's later redundant paths, each with its
    /// own receiver entry (redundant-paths.md; the first path is
    /// `endpoint`).
    later: [Option<EndpointId>; LATER_PATHS],
    /// The routes the channel asked for its later paths: a second handle
    /// of the key must ask for the same ones.
    later_routes: [Option<(SocketAddr, MulticastConfig)>; LATER_PATHS],
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
    /// image was not exposed (interim keying).
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

/// An installed image and the aggregate that exposes it, if any.
#[derive(Debug)]
struct NetImage {
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
    conductors: Vec<Conductor<Arc<LogBuffer>>>,
}

/// The conductor's network state.
#[derive(Debug)]
pub(crate) struct Network {
    links: AgentLinks<OsSocket>,
    endpoints: Endpoints<OsSocket>,
    images: ImageTable,
    agents: Agents,
    /// The first agent that failed (DN-9), latched.
    failed: Option<AgentKind>,
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
    net_images: Vec<NetImage>,
    /// The image table's events of the last cycle, for the conductor.
    image_events: Vec<ImageEvent>,
    /// The agents' network trace answers of the last cycle, and the
    /// publications that became active, for the conductor (P2.12 step 3).
    trace_events: Vec<trace::TraceEvent>,
    /// Endpoint resets completed (`EndpointEvent::Reopened`), for tests.
    #[cfg(test)]
    reopened: u64,
    /// Images installed but not exposed: their alias is in use (interim
    /// keying, ACS 15937) or the stream table is full.
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
    /// Guard senders the conductor failed to deregister (an unknown id):
    /// counted, never retried.
    guard_deregister_failures: u64,
    /// The NAK control groups of multicast data groups (RC-15).
    control_groups: ControlGroups,
    /// Control group joins that failed: those keys run without peer
    /// suppression input (RC-15).
    control_join_failures: u64,
    /// Whether the backend isolates redundant path sockets.
    paths_isolated: bool,
    /// Channels with `paths` refused because they cannot be isolated.
    paths_refused: u64,
    /// Later paths of subscriptions that could not be held.
    path_failures: u64,
    /// What the conflated views of network images did
    /// (conflated-network-images.md).
    views: NetworkViewCounters,
    /// Conflated views built from now on are not attached (tests).
    #[cfg(test)]
    defer_view_attach: bool,
}

impl Network {
    /// The agents of `config`, started in its threading mode (control
    /// path, at driver start).
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidConfig`] for an agent configuration the agents
    /// refuse; [`DriverError::NetworkStart`] when a thread cannot start.
    pub(crate) fn start(config: &NetworkConfig) -> Result<Self, DriverError> {
        control_group::validate(&config.nak_control_groups)?;
        let (agents, links) =
            network_agents::<OsSocket>(config.agents).map_err(|_| DriverError::InvalidConfig)?;
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
            stale_overflows: 0,
            clock: karyos_sys::host_clock::host_monotonic_ns,
            released_guards: ReleasedGuards {
                ids: Vec::with_capacity(config.agents.publications),
                dropped: 0,
            },
            guard_deregister_failures: 0,
            control_groups: config.nak_control_groups,
            control_join_failures: 0,
            paths_isolated: <OsSocket as karyos_io::sockets::ops::SocketOps>::isolates_paths(),
            paths_refused: 0,
            path_failures: 0,
            views: NetworkViewCounters::default(),
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

    /// The endpoint bound to `bind`, joined to `multicast` if any, opened
    /// on first use; one more user holds it.
    fn hold_endpoint(
        &mut self,
        bind: SocketAddr,
        multicast: Option<MulticastConfig>,
    ) -> Result<EndpointId, DriverError> {
        if let Some(entry) = self
            .send_endpoints
            .iter_mut()
            .find(|entry| (entry.bind, entry.multicast) == (bind, multicast))
        {
            entry.users = entry
                .users
                .checked_add(1)
                .ok_or(DriverError::NetworkEndpoint)?;
            return Ok(entry.endpoint);
        }
        let mut config = SocketsConfig::new(bind);
        config.multicast = multicast;
        let endpoint = self
            .endpoints
            .open(&self.links, config, OsSocket::new())
            .map_err(|_| DriverError::NetworkEndpoint)?;
        self.send_endpoints.push(SendEndpoint {
            bind,
            multicast,
            endpoint,
            users: 1,
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
    /// [`DriverError::ConflationMismatch`].
    pub(crate) fn add_subscription(
        &mut self,
        stream_id: i32,
        (bind, multicast): (SocketAddr, Option<MulticastConfig>),
        later: &[(SocketAddr, MulticastConfig)],
        max_term_length: u32,
        reliable: bool,
        (identity, conflated): (
            Option<crate::membership::ReceiverIdentity>,
            Option<(Lane, karyos_sys::conflation::ConflationConfig)>,
        ),
    ) -> Result<NetworkSubscription, DriverError> {
        let group = multicast.is_some();
        let endpoint = self.hold_endpoint(bind, multicast)?;
        let handle = NetworkSubscription {
            endpoint,
            stream_id,
        };
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
            });
        if posted.is_err() {
            release(&mut self.send_endpoints, endpoint);
            if let Some((control, _)) = control {
                release(&mut self.send_endpoints, control);
            }
            return Err(DriverError::NetworkBusy);
        }
        // Each later path is a receiver entry of its own endpoint; the
        // receiver binds it to the image as a later path of the same
        // publication (RP-1). A path that cannot open or be posted leaves
        // the subscription with the paths it has, counted.
        let mut held = [None; LATER_PATHS];
        let mut later_routes = [None; LATER_PATHS];
        for ((slot, route), (bind, config)) in
            held.iter_mut().zip(later_routes.iter_mut()).zip(later)
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
                    control_group: None,
                    identity,
                    conflated: conflated.map(|(lane, _)| lane),
                });
            if posted.is_err() {
                release(&mut self.send_endpoints, path);
                self.count_path_failure();
                continue;
            }
            *slot = Some(path);
        }
        self.subscriptions.push(NetSubscription {
            endpoint,
            stream_id,
            reliable,
            control: control.map(|(control, _)| control),
            identity,
            conflated,
            later: held,
            later_routes,
            users: 1,
        });
        Ok(handle)
    }

    /// One later path of a subscription that could not be held.
    fn count_path_failure(&mut self) {
        if let Some(count) = self.path_failures.checked_add(1) {
            self.path_failures = count;
        }
    }

    /// Whether this driver can isolate the sockets of redundant paths
    /// ([`SocketOps::isolates_paths`]); a channel with `paths` is refused
    /// while it cannot.
    pub(crate) fn paths_isolated(&self) -> bool {
        self.paths_isolated
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
        let data_group = SocketAddr::new(config.group, bind.port());
        let interface = match config.interface {
            InterfaceSel::Address(address) if !address.is_unspecified() => {
                Some(IpAddr::V4(address))
            }
            _ => None,
        };
        let group = control_group::lookup(&self.control_groups, data_group, interface)?;
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
                if let Some(control) = entry.control {
                    release(&mut self.send_endpoints, control);
                }
                for path in entry.later.into_iter().flatten() {
                    release(&mut self.send_endpoints, path);
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
    pub(crate) fn image_lanes(&self, slot: SlotRef) -> Option<Vec<Arc<LogBuffer>>> {
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
        endpoint: EndpointId,
        traced: karyos_protocol::trace_hook::PublicationIdentity,
        exposed: Option<crate::embedded::AggregateHandle>,
        lanes: &[Arc<LogBuffer>],
    ) {
        let mut conductors = Vec::new();
        if exposed.is_none() {
            if let Some(count) = self.images_unexposed.checked_add(1) {
                self.images_unexposed = count;
            }
            conductors = lanes
                .iter()
                .filter_map(LogBuffer::conductor_owned)
                .collect();
        }
        self.net_images.push(NetImage {
            slot,
            endpoint,
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

    /// Forgets the reclaimed image `slot`.
    pub(crate) fn forget_image(&mut self, slot: SlotRef) {
        self.net_images.retain(|image| image.slot != slot);
    }

    /// The exposed image aggregate that `matches`.
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
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "used by the Linux multicast test (T9)")
    )]
    pub(crate) fn sender_ignores_naks(&mut self, ignore: bool) {
        if let Agents::Shared(agents) = &mut self.agents {
            if ignore {
                agents.sender.ignore_naks();
            } else {
                agents.sender.heed_naks();
            }
        }
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
        outbound: Box<Outbound>,
        guard: Option<(
            crate::agents::data::GuardSpec,
            crate::guard_ack::GuardSenderId,
        )>,
        roles: Option<Box<crate::membership::PublicationRoles>>,
    ) -> Result<(), DriverError> {
        let (spec, guard_sender) = guard.map_or((None, None), |(spec, id)| (Some(spec), Some(id)));
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
        // Each path's alias takes room, held or stale. A queued alias of
        // one of its keys is superseded by the add below, so it takes none.
        let held = self.publications.iter().try_fold(0usize, |held, entry| {
            held.checked_add(entry.paths().count())
        });
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
            guard_sender,
            traced,
            lanes,
            trace_closes: Vec::new(),
        });
        Ok(())
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
        let Some(entry) = self
            .publications
            .iter_mut()
            .find(|entry| entry.registration == registration)
        else {
            return false;
        };
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
        post_removals(&self.links, &mut self.publications, &mut stale);
        true
    }

    /// The state of the network publication `registration`.
    pub(crate) fn publication_state(&self, registration: u64) -> Option<NetworkPublicationState> {
        self.publications
            .iter()
            .find(|entry| entry.registration == registration)
            .map(|entry| entry.state)
    }

    /// One conductor cycle of network work at the network clock's reading:
    /// the agents when they share this thread, then their events. Returns
    /// the work done.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkAgent`] once an agent failed (DN-9), and on
    /// every later cycle; [`DriverError::WorkCountOverflow`].
    pub(crate) fn duty(&mut self) -> Result<u32, DriverError> {
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
                // guard sender is released, so no close waits on it.
                self.failed = Some(agent);
                self.release_guard_senders();
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
        post_removals(&self.links, &mut self.publications, &mut stale);
        // Answers about endpoints go to the table, which also serves the
        // sender's reset requests at the network clock (W-f); publication
        // answers update the publications.
        let mut events = Some(0u32);
        #[cfg(test)]
        let mut reopened = Some(self.reopened);
        let mut refusals = self.subscription_refusals;
        let (publications, send_endpoints, released, trace_events) = (
            &mut self.publications,
            &mut self.send_endpoints,
            &mut self.released_guards,
            &mut self.trace_events,
        );
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
                publication_answer(publications, send_endpoints, &mut stale, released, event);
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
        let images = self
            .images
            .poll(&self.links.sessions, |event| image_events.push(event));
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
    pub(crate) fn close(&mut self) -> NetworkShutdown {
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
            shutdown.agents_stopped = agents.is_stopped();
            shutdown.endpoints_retired = self.endpoints.reclaim(&self.links, &mut agents, |_| {});
        }
        let _ = self.images.poll(&self.links.sessions, |_| {});
        // The agents are gone: every tracked guard sender is released for
        // the conductor to deregister.
        self.release_guard_senders();
        shutdown
    }

    /// Moves the guard sender of every tracked publication to the released
    /// list (agents stopped or failed): the conductor deregisters them.
    fn release_guard_senders(&mut self) {
        for entry in &mut self.publications {
            if let Some(id) = entry.guard_sender.take() {
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
    pub(crate) fn links(&self) -> &AgentLinks<OsSocket> {
        &self.links
    }

    /// The endpoint table, for tests.
    #[cfg(test)]
    pub(crate) fn endpoints_mut(&mut self) -> (&mut Endpoints<OsSocket>, &AgentLinks<OsSocket>) {
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

/// Posts `RemovePublication` for every publication being removed that
/// is not posted yet, after its sender journals' closes, queueing its
/// alias as stale, then `RemovePublishedAlias` for every stale alias; a
/// full ring leaves the rest for the next cycle.
fn post_removals(
    links: &AgentLinks<OsSocket>,
    publications: &mut [NetPublication],
    stale: &mut Stale<'_>,
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
        let posted = links.sender.post(|reply| AgentCommand::RemovePublication {
            reply,
            endpoint,
            alias,
            registration,
        });
        if posted.is_err() {
            break;
        }
        entry.remove_posted = true;
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
}

/// Applies the sender's answer about a publication.
fn publication_answer(
    publications: &mut Vec<NetPublication>,
    send_endpoints: &mut [SendEndpoint],
    stale: &mut Stale<'_>,
    released: &mut ReleasedGuards,
    event: AgentEvent<OsSocket>,
) {
    // Each tracked publication releases its guard sender once, and the
    // list holds one per tracked publication: it never grows past it.
    let mut release_guard = |entry: &mut NetPublication| {
        if let Some(id) = entry.guard_sender.take() {
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
        AgentEvent::PublicationRemoved {
            endpoint,
            alias,
            registration,
            outbound,
        } => {
            // The lane readers drop here, on the control path.
            drop(outbound);
            if let Some(index) = find(publications, endpoint, alias, registration) {
                let mut entry = publications.swap_remove(index);
                release_guard(&mut entry);
                for path in entry.paths() {
                    release(send_endpoints, path);
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

impl Stop for crate::agents::SenderAgent<OsSocket> {
    fn cycle(&mut self, now: u64) -> Result<u32, AgentError> {
        self.do_work(now)
    }
}

impl Stop for crate::agents::ReceiverAgent<OsSocket> {
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
