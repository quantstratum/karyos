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
//!   the driver: the duty cycle returns [`DriverError::NetworkAgent`].
//! - **Shutdown (W-g).** `Network::close` stops the agents (their stop
//!   cannot be refused), reclaims every endpoint half and drains the image
//!   table. A thread that does not stop in time is kept, never detached,
//!   and reported.
//!
//! This step wires no stream yet: publications and images follow (W2, W3).

use karyos_io::sockets::OsSocket;

use crate::agents::endpoints::Endpoints;
use crate::agents::images::{ImageTable, ImageTemplate};
use crate::agents::{
    AgentConfig, AgentError, AgentKind, AgentLinks, AgentRunner, LateAgent, NetworkAgents,
    ThreadingMode, YieldThenSleep, network_agents,
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
}

/// The conductor's network state.
#[derive(Debug)]
pub(crate) struct Network {
    links: AgentLinks<OsSocket>,
    endpoints: Endpoints<OsSocket>,
    images: ImageTable,
    agents: Agents,
}

impl Network {
    /// The agents of `config`, started in its threading mode (control
    /// path, at driver start).
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidConfig`] for an agent configuration the agents
    /// refuse; [`DriverError::NetworkAgent`] when a thread cannot start.
    pub(crate) fn start(config: &NetworkConfig) -> Result<Self, DriverError> {
        let (agents, links) =
            network_agents::<OsSocket>(config.agents).map_err(|_| DriverError::InvalidConfig)?;
        let agents = match config.threading {
            ThreadingMode::Shared => Agents::Shared(Box::new(agents)),
            mode => Agents::Threads(
                AgentRunner::start(mode, agents, config.agents, YieldThenSleep::default).map_err(
                    |_| DriverError::NetworkAgent {
                        agent: AgentKind::Sender,
                    },
                )?,
            ),
        };
        Ok(Self {
            links,
            endpoints: Endpoints::new(&config.agents),
            images: ImageTable::new(config.agents.sessions.max_images, config.images),
            agents,
        })
    }

    /// One conductor cycle of network work at `now`, in driver clock
    /// nanoseconds: the agents when they share this thread, then their
    /// events. Returns the work done.
    ///
    /// # Errors
    ///
    /// [`DriverError::NetworkAgent`] once an agent failed (DN-9).
    pub(crate) fn duty(&mut self, now: u64) -> Result<u32, DriverError> {
        let mut work = match &mut self.agents {
            Agents::Shared(agents) => {
                agents
                    .do_work(now)
                    .map_err(|error| DriverError::NetworkAgent {
                        agent: failed_kind(&error),
                    })?
            }
            Agents::Threads(runner) => {
                if let Some(agent) = runner.failed().first() {
                    return Err(DriverError::NetworkAgent { agent: *agent });
                }
                0
            }
            Agents::Closed => return Ok(0),
        };
        // Answers about endpoints go to the table, which also serves the
        // sender's reset requests at the driver clock (W-f); the others
        // have no consumer until publications are wired (W2).
        self.endpoints.poll(&self.links, now, |_| {}, |_| {});
        work = work.saturating_add(self.images.poll(&self.links.sessions, |_| {}));
        Ok(work)
    }

    /// Stops the agents, reclaims every endpoint and drains the image
    /// table (control path; at most once, later calls report nothing).
    pub(crate) fn close(&mut self) -> NetworkShutdown {
        let mut shutdown = NetworkShutdown::default();
        let agents = match core::mem::replace(&mut self.agents, Agents::Closed) {
            Agents::Shared(mut agents) => {
                self.links.sender.request_stop();
                self.links.receiver.request_stop();
                // The agents see their flags at the start of a cycle.
                if let Err(error) = agents.do_work(0) {
                    shutdown.failures.push(error);
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

/// The agent an error names.
fn failed_kind(error: &AgentError) -> AgentKind {
    match error {
        AgentError::Busy(kind)
        | AgentError::Gone(kind)
        | AgentError::Invariant(kind)
        | AgentError::CountOverflow(kind)
        | AgentError::Panicked(kind) => *kind,
        _ => AgentKind::Sender,
    }
}

#[cfg(test)]
mod tests;
