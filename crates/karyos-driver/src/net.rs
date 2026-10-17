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
//!
//! Images follow in W3.

use std::net::SocketAddr;

use karyos_io::sockets::OsSocket;
use karyos_io::sockets::endpoint::SocketsConfig;
use karyos_protocol::network::Alias;

use crate::agents::data::Outbound;
use crate::agents::{AgentCommand, AgentEvent, EndpointId};
use crate::sessions::send::Publication;

use crate::agents::endpoints::Endpoints;
use crate::agents::images::{ImageTable, ImageTemplate};
use crate::agents::{
    AgentConfig, AgentError, AgentKind, AgentLinks, AgentRunner, LateAgent, NetworkAgents,
    ThreadingMode, YieldThenSleep, guarded, network_agents,
};
use crate::error::DriverError;

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

/// A send endpoint shared by the publications bound to one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendEndpoint {
    bind: SocketAddr,
    endpoint: EndpointId,
    /// Publications that hold it.
    users: usize,
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
        if let Some(entry) = self
            .send_endpoints
            .iter_mut()
            .find(|entry| entry.bind == bind)
        {
            entry.users = entry
                .users
                .checked_add(1)
                .ok_or(DriverError::NetworkEndpoint)?;
            return Ok(entry.endpoint);
        }
        let endpoint = self
            .endpoints
            .open(&self.links, SocketsConfig::new(bind), OsSocket::new())
            .map_err(|_| DriverError::NetworkEndpoint)?;
        self.send_endpoints.push(SendEndpoint {
            bind,
            endpoint,
            users: 1,
        });
        Ok(endpoint)
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
        let (publications, send_endpoints) = (&mut self.publications, &mut self.send_endpoints);
        let mut stale = Stale {
            queue: &mut self.stale_aliases,
            overflows: &mut self.stale_overflows,
        };
        self.endpoints.poll(
            &self.links,
            now,
            |_| events = events.and_then(|count| count.checked_add(1)),
            |event| publication_answer(publications, send_endpoints, &mut stale, event),
        );
        // A send endpoint no publication holds any more retires; one not
        // active yet is tried again next cycle.
        let (endpoints, links) = (&mut self.endpoints, &self.links);
        self.send_endpoints
            .retain(|entry| entry.users > 0 || endpoints.retire(links, entry.endpoint).is_err());
        let images = self.images.poll(&self.links.sessions, |_| {});
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

#[cfg(test)]
mod tests;
