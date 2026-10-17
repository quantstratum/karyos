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
//!   tables. In `Shared` mode the agents get the driver clock's reading;
//!   their threads read `host_monotonic_ns`. An agent compares only its own
//!   timestamps, so the two never mix.
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

use std::net::SocketAddr;

use karyos_io::sockets::OsSocket;
use karyos_io::sockets::endpoint::{MulticastConfig, SocketsConfig};
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
    /// The image log buffers.
    pub images: ImageTemplate,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            agents: AgentConfig::default(),
            threading: ThreadingMode::Dedicated,
            images: ImageTemplate::default(),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetPublication {
    /// The aggregate's registration.
    registration: u64,
    endpoint: EndpointId,
    alias: Alias,
    state: NetworkPublicationState,
    /// Whether `RemovePublication` is posted; retried while the ring is
    /// full.
    remove_posted: bool,
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
    /// Handles of this key; the receiver's entry goes with the last.
    users: usize,
}

/// Names a network subscription of one driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkSubscription {
    endpoint: EndpointId,
    stream_id: i32,
}

/// An installed image and the aggregate that exposes it, if any.
#[derive(Debug)]
struct NetImage {
    slot: SlotRef,
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
    /// Installed images, at most `max_images`.
    net_images: Vec<NetImage>,
    /// The image table's events of the last cycle, for the conductor.
    image_events: Vec<ImageEvent>,
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
            net_images: Vec::with_capacity(config.agents.sessions.max_images),
            image_events: Vec::with_capacity(config.agents.sessions.max_images),
            images_unexposed: 0,
            #[cfg(test)]
            reopened: 0,
            stale_aliases: Vec::with_capacity(config.agents.publications),
            capacity: config.agents.publications,
            stale_overflows: 0,
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
    /// same endpoint and stream shares the receiver's entry. The
    /// receiver's answer is not awaited: a receiver whose subscription
    /// table is full (`AgentConfig::subscriptions`) answers
    /// `Configured { accepted: false }` and never challenges the stream,
    /// so no image appears for it.
    ///
    /// `reliable` is the channel's `reliable` parameter: the receiver
    /// repairs its images' losses with NAKs, otherwise its skip policy
    /// seals them. A second subscription of the same endpoint and stream
    /// shares the first's receiver entry, so it must ask for the same
    /// reliability ([`DriverError::ReliabilityMismatch`] otherwise).
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkEndpoint`], [`DriverError::NetworkBusy`],
    /// [`DriverError::ReliabilityMismatch`].
    pub(crate) fn add_subscription(
        &mut self,
        stream_id: i32,
        bind: SocketAddr,
        multicast: Option<MulticastConfig>,
        max_term_length: u32,
        reliable: bool,
    ) -> Result<NetworkSubscription, DriverError> {
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
            let Some(users) = entry.users.checked_add(1) else {
                release(&mut self.send_endpoints, endpoint);
                return Err(DriverError::NetworkBusy);
            };
            entry.users = users;
            return Ok(handle);
        }
        let posted = self
            .links
            .receiver
            .post(|reply| AgentCommand::AddSubscription {
                reply,
                endpoint,
                stream_id,
                max_term_length,
                reliable,
            });
        if posted.is_err() {
            release(&mut self.send_endpoints, endpoint);
            return Err(DriverError::NetworkBusy);
        }
        self.subscriptions.push(NetSubscription {
            endpoint,
            stream_id,
            reliable,
            users: 1,
        });
        Ok(handle)
    }

    /// Stops `subscription`: its images retire and its endpoint is
    /// released (control path). `false` when it is unknown.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkBusy`]; nothing changes then.
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
                self.links
                    .receiver
                    .post(|reply| AgentCommand::RemoveSubscription {
                        reply,
                        endpoint,
                        stream_id,
                    })
                    .map_err(|_| DriverError::NetworkBusy)?;
                self.subscriptions.swap_remove(index);
            }
        }
        release(&mut self.send_endpoints, endpoint);
        Ok(true)
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

    /// Records the installed image `slot` and the aggregate exposing it;
    /// an unexposed image's lane conductors are taken from `lanes` and
    /// driven here.
    pub(crate) fn record_image(
        &mut self,
        slot: SlotRef,
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
            exposed,
            conductors,
        });
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

    /// Images installed but not exposed so far.
    pub(crate) fn images_unexposed(&self) -> u64 {
        self.images_unexposed
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
    ) -> Result<(), DriverError> {
        let (endpoint, alias) = (publication.endpoint, publication.alias);
        // One tracked publication per key: the sender's answers then name
        // exactly one entry, and a key freed locally while its old
        // publication is still being removed waits for it (#279 P1).
        if self
            .publications
            .iter()
            .any(|entry| (entry.endpoint, entry.alias) == (endpoint, alias))
        {
            return Err(DriverError::NetworkBusy);
        }
        // A queued alias of this key is superseded by the add below, so it
        // takes no room.
        let stale_only = self
            .stale_aliases
            .iter()
            .filter(|key| {
                **key != (endpoint, alias)
                    && !self
                        .publications
                        .iter()
                        .any(|entry| (entry.endpoint, entry.alias) == **key)
            })
            .count();
        if self
            .publications
            .len()
            .checked_add(stale_only)
            .is_none_or(|held| held >= self.capacity)
        {
            return Err(DriverError::NetworkPublicationsFull);
        }
        self.links
            .receiver
            .post(|reply| AgentCommand::AddPublishedAlias {
                reply,
                endpoint,
                alias,
            })
            .map_err(|_| DriverError::NetworkBusy)?;
        // A key reused before its stale alias was posted: the new
        // `AddPublishedAlias`, now in the ring, supersedes it, and a removal
        // posted later would drop the new publication's alias. One posted
        // earlier precedes the add in the ring.
        self.stale_aliases.retain(|key| *key != (endpoint, alias));
        let posted = self
            .links
            .sender
            .post(|reply| AgentCommand::AddPublication {
                reply,
                publication,
                outbound,
            });
        if posted.is_err() {
            // The receiver learned the alias: it is stale now. The capacity
            // check above leaves room for it.
            Stale {
                queue: &mut self.stale_aliases,
                overflows: &mut self.stale_overflows,
            }
            .queue_alias(endpoint, alias);
            return Err(DriverError::NetworkBusy);
        }
        self.publications.push(NetPublication {
            registration,
            endpoint,
            alias,
            state: NetworkPublicationState::Adding,
            remove_posted: false,
        });
        Ok(())
    }

    /// Starts removing the publication `registration`; `false` when it is
    /// not a network publication. Its data path comes back later.
    pub(crate) fn remove_publication(&mut self, registration: u64) -> bool {
        let Some(entry) = self
            .publications
            .iter_mut()
            .find(|entry| entry.registration == registration)
        else {
            return false;
        };
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

    /// One conductor cycle of network work at `now`, in driver clock
    /// nanoseconds: the agents when they share this thread, then their
    /// events. Returns the work done.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkAgent`] once an agent failed (DN-9), and on
    /// every later cycle; [`DriverError::WorkCountOverflow`].
    pub(crate) fn duty(&mut self, now: u64) -> Result<u32, DriverError> {
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
        let (received, sent) = work.map_err(|agent| {
            self.failed = Some(agent);
            DriverError::NetworkAgent { agent }
        })?;
        // Removals the full ring refused earlier.
        let mut stale = Stale {
            queue: &mut self.stale_aliases,
            overflows: &mut self.stale_overflows,
        };
        post_removals(&self.links, &mut self.publications, &mut stale);
        // Answers about endpoints go to the table, which also serves the
        // sender's reset requests at the driver clock (W-f); publication
        // answers update the publications.
        let mut events = Some(0u32);
        #[cfg(test)]
        let mut reopened = Some(self.reopened);
        let (publications, send_endpoints) = (&mut self.publications, &mut self.send_endpoints);
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
            |event| publication_answer(publications, send_endpoints, &mut stale, event),
        );
        #[cfg(test)]
        if let Some(count) = reopened {
            self.reopened = count;
        }
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
    /// table at `now`, the driver clock's reading (control path; at most
    /// once, later calls report nothing).
    pub(crate) fn close(&mut self, now: u64) -> NetworkShutdown {
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
        shutdown
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

    /// The Shared receiver agent's counters, for tests.
    #[cfg(test)]
    pub(crate) fn receiver_counters(&self) -> Option<crate::agents::roles::ReceiverCounters> {
        match &self.agents {
            Agents::Shared(agents) => Some(agents.receiver.counters()),
            _ => None,
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
/// is not posted yet, queueing its alias as stale, then
/// `RemovePublishedAlias` for every stale alias; a full ring leaves the
/// rest for the next cycle.
fn post_removals(
    links: &AgentLinks<OsSocket>,
    publications: &mut [NetPublication],
    stale: &mut Stale<'_>,
) {
    for entry in publications
        .iter_mut()
        .filter(|entry| entry.state == NetworkPublicationState::Removing && !entry.remove_posted)
    {
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
        stale.queue_alias(endpoint, alias);
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

/// Applies the sender's answer about a publication.
fn publication_answer(
    publications: &mut Vec<NetPublication>,
    send_endpoints: &mut [SendEndpoint],
    stale: &mut Stale<'_>,
    event: AgentEvent<OsSocket>,
) {
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
                release(send_endpoints, endpoint);
                // The receiver learned the alias before the refusal.
                stale.queue_alias(endpoint, alias);
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
                publications.swap_remove(index);
                release(send_endpoints, endpoint);
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

mod publish;
mod subscribe;

#[cfg(test)]
mod e2e;
#[cfg(test)]
mod netem;
#[cfg(test)]
mod tests;
