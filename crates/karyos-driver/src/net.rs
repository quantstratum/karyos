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
//! This step wires no stream yet: publications and images follow (W2, W3).

use karyos_io::sockets::OsSocket;

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

/// The conductor's network state.
#[derive(Debug)]
pub(crate) struct Network {
    links: AgentLinks<OsSocket>,
    endpoints: Endpoints<OsSocket>,
    images: ImageTable,
    agents: Agents,
    /// The first agent that failed (DN-9), latched.
    failed: Option<AgentKind>,
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
        })
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
        // Answers about endpoints go to the table, which also serves the
        // sender's reset requests at the driver clock (W-f).
        // Other agent events have no consumer until publications (W2).
        let mut events = Some(0u32);
        self.endpoints.poll(
            &self.links,
            now,
            |_| events = events.and_then(|count| count.checked_add(1)),
            |_| {},
        );
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

#[cfg(test)]
mod tests;
