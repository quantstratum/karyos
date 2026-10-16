// SPDX-License-Identifier: Apache-2.0

//! The driver's network agents (`quantstratum-docs:
//! karyos/design/driver-network-agents.md`, phase 2 of §10; decisions
//! DN-1, DN-2, DN-3, DN-8 and DN-9, coordinator ACS 15332): the sender and
//! receiver agent objects, the bounded rings that connect them to the
//! conductor, and the runner that gives them threads.
//!
//! - **Agents (DN-1).** [`SenderAgent`] and [`ReceiverAgent`] are plain
//!   structs with one duty entry point, `do_work(now) -> work count`. They
//!   own their state; the conductor reaches them only through their rings.
//!   This phase gives them no network work: they serve conductor commands
//!   (a ping, used by tests and by health checks, and `Stop`).
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
//!   thread the receiver runs first in each iteration.
//! - **Stop (DN-8).** [`AgentRunner::stop`] posts `Stop` to both agents
//!   and joins their threads within a timeout; an agent that does not stop
//!   in time is reported and its thread detached.
//! - **Failure (DN-9).** An agent that returns an error or panics stops its
//!   thread; the runner reports it, and the conductor treats it as fatal
//!   for the driver.

pub mod ring;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ring::{Reservation, RingReceiver, RingSender};

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
    /// The command ring or the reply slot of the event ring is full.
    #[error("the {0:?} agent's rings are full")]
    Busy(AgentKind),
    /// The agent's rings are disconnected: it stopped or failed.
    #[error("the {0:?} agent is gone")]
    Gone(AgentKind),
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
    /// Agents that did not stop within the timeout; their threads were
    /// detached.
    #[error("agents did not stop in time: {0:?}")]
    StopTimeout(Vec<AgentKind>),
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

/// Configuration of the agents and their rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentConfig {
    /// Entries of each agent's command ring.
    pub command_capacity: usize,
    /// Entries of each agent's event ring.
    pub event_capacity: usize,
    /// Commands an agent serves per duty cycle.
    pub command_budget: u32,
    /// How long [`AgentRunner::stop`] waits for the agents
    /// (`agent_stop_timeout`).
    pub stop_timeout: Duration,
}

impl Default for AgentConfig {
    /// DN-3 and DN-8 defaults: 64 entries per ring, 16 commands per cycle,
    /// 1 s to stop.
    fn default() -> Self {
        Self {
            command_capacity: 64,
            event_capacity: 64,
            command_budget: 16,
            stop_timeout: Duration::from_secs(1),
        }
    }
}

/// A conductor command. Each carries the reservation of its reply.
#[derive(Debug)]
pub enum AgentCommand {
    /// Answer with [`AgentEvent::Pong`] carrying `token`.
    Ping {
        /// The reply's slot.
        reply: Reservation,
        /// Echoed in the reply.
        token: u64,
    },
    /// Stop: answer [`AgentEvent::Stopped`] and do no further work.
    Stop {
        /// The reply's slot.
        reply: Reservation,
    },
    /// Test only: panic in the duty cycle.
    #[cfg(test)]
    Panic,
    /// Test only: block the duty cycle until the flag is cleared.
    #[cfg(test)]
    Block(Arc<std::sync::atomic::AtomicBool>),
}

/// An agent's event to the conductor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentEvent {
    /// The reply to a ping.
    Pong {
        /// The agent.
        agent: AgentKind,
        /// The ping's token.
        token: u64,
    },
    /// The agent stopped.
    Stopped {
        /// The agent.
        agent: AgentKind,
    },
}

/// What an agent has from the conductor: its rings and its state.
#[derive(Debug)]
struct AgentCore {
    kind: AgentKind,
    commands: RingReceiver<AgentCommand>,
    events: RingSender<AgentEvent>,
    budget: u32,
    stopped: bool,
}

impl AgentCore {
    /// Serves up to the budget's commands; returns how many.
    fn serve_commands(&mut self) -> Result<u32, AgentError> {
        let mut served = 0u32;
        while served < self.budget && !self.stopped {
            let command = match self.commands.try_take() {
                Ok(Some(command)) => command,
                Ok(None) => break,
                // The conductor is gone: stop, there is nobody to serve.
                Err(_) => {
                    self.stopped = true;
                    break;
                }
            };
            served += 1;
            match command {
                AgentCommand::Ping { reply, token } => {
                    let event = AgentEvent::Pong {
                        agent: self.kind,
                        token,
                    };
                    self.events
                        .post(reply, event)
                        .map_err(|_| AgentError::Gone(self.kind))?;
                }
                AgentCommand::Stop { reply } => {
                    self.stopped = true;
                    // The conductor may already be gone at shutdown.
                    let _ = self
                        .events
                        .post(reply, AgentEvent::Stopped { agent: self.kind });
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
            }
        }
        Ok(served)
    }
}

/// The sender agent (`driver-network-agents.md` §3.1). This phase serves
/// conductor commands only.
#[derive(Debug)]
pub struct SenderAgent {
    core: AgentCore,
}

/// The receiver agent (`driver-network-agents.md` §3.2). This phase
/// serves conductor commands only.
#[derive(Debug)]
pub struct ReceiverAgent {
    core: AgentCore,
}

impl SenderAgent {
    /// One duty cycle at `now` (driver clock, ns); returns its work count.
    ///
    /// # Errors
    ///
    /// [`AgentError::Gone`] when the conductor's rings are gone.
    pub fn do_work(&mut self, now: u64) -> Result<u32, AgentError> {
        let _ = now;
        self.core.serve_commands()
    }

    /// Whether the agent served `Stop`.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.core.stopped
    }
}

impl ReceiverAgent {
    /// One duty cycle at `now` (driver clock, ns); returns its work count.
    ///
    /// # Errors
    ///
    /// [`AgentError::Gone`] when the conductor's rings are gone.
    pub fn do_work(&mut self, now: u64) -> Result<u32, AgentError> {
        let _ = now;
        self.core.serve_commands()
    }

    /// Whether the agent served `Stop`.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.core.stopped
    }
}

/// Both network agents, driven together: the Shared mode's object, and
/// the Shared network mode's thread. The receiver runs first, so control
/// it posts leaves in the same iteration.
#[derive(Debug)]
pub struct NetworkAgents {
    /// The sender agent.
    pub sender: SenderAgent,
    /// The receiver agent.
    pub receiver: ReceiverAgent,
}

impl NetworkAgents {
    /// One iteration: the receiver's duty cycle, then the sender's.
    ///
    /// # Errors
    ///
    /// The first agent error.
    pub fn do_work(&mut self, now: u64) -> Result<u32, AgentError> {
        let received = self.receiver.do_work(now)?;
        let sent = self.sender.do_work(now)?;
        Ok(received.saturating_add(sent))
    }

    /// Whether both agents stopped.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.sender.is_stopped() && self.receiver.is_stopped()
    }
}

/// The conductor's end of one agent's rings.
#[derive(Debug)]
pub struct AgentLink {
    kind: AgentKind,
    commands: RingSender<AgentCommand>,
    events: RingSender<AgentEvent>,
    received: RingReceiver<AgentEvent>,
}

impl AgentLink {
    /// Posts the command `make` builds around its reply's reservation.
    /// Nothing is posted when a slot is missing.
    ///
    /// # Errors
    ///
    /// [`AgentError::Busy`] when the command ring or the reply slot is
    /// full, [`AgentError::Gone`] when the agent is gone.
    pub fn post(&self, make: impl FnOnce(Reservation) -> AgentCommand) -> Result<(), AgentError> {
        let busy = AgentError::Busy(self.kind);
        let reply = self.events.reserve().ok_or(busy.clone())?;
        let slot = self.commands.reserve().ok_or(busy)?;
        self.commands
            .post(slot, make(reply))
            .map_err(|_| AgentError::Gone(self.kind))
    }

    /// Posts a ping carrying `token`.
    ///
    /// # Errors
    ///
    /// As [`AgentLink::post`].
    pub fn ping(&self, token: u64) -> Result<(), AgentError> {
        self.post(|reply| AgentCommand::Ping { reply, token })
    }

    /// Takes the agent's oldest event.
    #[must_use]
    pub fn take_event(&self) -> Option<AgentEvent> {
        self.received.try_take().ok().flatten()
    }

    /// The agent.
    #[must_use]
    pub fn kind(&self) -> AgentKind {
        self.kind
    }
}

/// The conductor's links to both agents.
#[derive(Debug)]
pub struct AgentLinks {
    /// The sender agent's link.
    pub sender: AgentLink,
    /// The receiver agent's link.
    pub receiver: AgentLink,
}

/// Creates both agents and the conductor's links to them. Every ring is
/// allocated here; the duty cycles allocate nothing.
#[must_use]
pub fn network_agents(config: AgentConfig) -> (NetworkAgents, AgentLinks) {
    let make = |kind| {
        let (commands, command_receiver) = ring::ring(config.command_capacity);
        let (events, event_receiver) = ring::ring(config.event_capacity);
        let core = AgentCore {
            kind,
            commands: command_receiver,
            events: events.clone_sender(),
            budget: config.command_budget,
            stopped: false,
        };
        let link = AgentLink {
            kind,
            commands,
            events,
            received: event_receiver,
        };
        (core, link)
    };
    let (sender_core, sender_link) = make(AgentKind::Sender);
    let (receiver_core, receiver_link) = make(AgentKind::Receiver);
    (
        NetworkAgents {
            sender: SenderAgent { core: sender_core },
            receiver: ReceiverAgent {
                core: receiver_core,
            },
        },
        AgentLinks {
            sender: sender_link,
            receiver: receiver_link,
        },
    )
}

/// An agent's state as the runner publishes it.
const RUNNING: u8 = 0;
const STOPPED: u8 = 1;
const FAILED: u8 = 2;

/// One runner thread: the agents it drives and its state cell.
#[derive(Debug)]
struct AgentThread {
    kinds: Vec<AgentKind>,
    state: Arc<AtomicU8>,
    handle: JoinHandle<Result<(), AgentError>>,
}

/// The threads of the Dedicated and Shared network modes (DN-2).
#[derive(Debug)]
pub struct AgentRunner {
    threads: Vec<AgentThread>,
    stop_timeout: Duration,
}

/// What a runner thread drives.
enum Work {
    Sender(SenderAgent),
    Receiver(ReceiverAgent),
    Both(NetworkAgents),
}

/// Runs one agent's duty cycle, turning a panic into
/// [`AgentError::Panicked`] for that agent.
fn guarded(
    kind: AgentKind,
    cycle: impl FnOnce() -> Result<u32, AgentError>,
) -> Result<u32, AgentError> {
    catch_unwind(AssertUnwindSafe(cycle)).unwrap_or(Err(AgentError::Panicked(kind)))
}

impl Work {
    fn do_work(&mut self, now: u64) -> Result<u32, AgentError> {
        match self {
            Work::Sender(agent) => guarded(AgentKind::Sender, || agent.do_work(now)),
            Work::Receiver(agent) => guarded(AgentKind::Receiver, || agent.do_work(now)),
            Work::Both(agents) => {
                // The receiver first, as `NetworkAgents::do_work`.
                let received = guarded(AgentKind::Receiver, || agents.receiver.do_work(now))?;
                let sent = guarded(AgentKind::Sender, || agents.sender.do_work(now))?;
                Ok(received.saturating_add(sent))
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

impl AgentRunner {
    /// Starts the agents' threads in `mode`, each with an idle strategy
    /// from `idle`. On error nothing is left running.
    ///
    /// # Errors
    ///
    /// [`AgentError::SharedMode`] for [`ThreadingMode::Shared`] (the
    /// caller drives those agents) and [`AgentError::Spawn`].
    pub fn start<I: IdleStrategy + 'static>(
        mode: ThreadingMode,
        agents: NetworkAgents,
        config: AgentConfig,
        idle: impl Fn() -> I,
    ) -> Result<Self, AgentError> {
        let work = match mode {
            ThreadingMode::Shared => return Err(AgentError::SharedMode),
            ThreadingMode::Dedicated => vec![
                (vec![AgentKind::Receiver], Work::Receiver(agents.receiver)),
                (vec![AgentKind::Sender], Work::Sender(agents.sender)),
            ],
            ThreadingMode::SharedNetwork => vec![(
                vec![AgentKind::Receiver, AgentKind::Sender],
                Work::Both(agents),
            )],
        };
        let mut runner = Self {
            threads: Vec::with_capacity(work.len()),
            stop_timeout: config.stop_timeout,
        };
        for (kinds, work) in work {
            let state = Arc::new(AtomicU8::new(RUNNING));
            let thread_state = Arc::clone(&state);
            let strategy = idle();
            let name = match kinds.as_slice() {
                [AgentKind::Sender] => "karyos-sender",
                [AgentKind::Receiver] => "karyos-receiver",
                _ => "karyos-network",
            };
            // On error, a thread already started stops once the caller
            // drops its links: its command ring disconnects.
            let handle = std::thread::Builder::new()
                .name(name.to_owned())
                .spawn(move || run(work, strategy, &thread_state))
                .map_err(|error| AgentError::Spawn(error.to_string()))?;
            runner.threads.push(AgentThread {
                kinds,
                state,
                handle,
            });
        }
        Ok(runner)
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

    /// Stops both agents (DN-8): posts `Stop` to each link, then joins the
    /// threads within the configured timeout.
    ///
    /// # Errors
    ///
    /// [`AgentError::StopTimeout`] naming the agents still running, whose
    /// threads are detached; otherwise the first agent failure
    /// ([`AgentError::Panicked`] or the agent's own error).
    pub fn stop(self, links: &AgentLinks) -> Result<(), AgentError> {
        for link in [&links.receiver, &links.sender] {
            // A failed agent's rings may be gone; its failure is reported
            // by its join below.
            let _ = link.post(|reply| AgentCommand::Stop { reply });
        }
        let deadline = Instant::now() + self.stop_timeout;
        while Instant::now() < deadline
            && !self
                .threads
                .iter()
                .all(|thread| thread.handle.is_finished())
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut late = Vec::new();
        let mut failure = None;
        for thread in self.threads {
            if !thread.handle.is_finished() {
                late.extend(thread.kinds);
                continue;
            }
            let kind = thread.kinds.first().copied().unwrap_or(AgentKind::Receiver);
            // A panic outside a duty cycle is still the thread's agent's.
            let result = thread
                .handle
                .join()
                .unwrap_or(Err(AgentError::Panicked(kind)));
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        if !late.is_empty() {
            return Err(AgentError::StopTimeout(late));
        }
        failure.map_or(Ok(()), Err)
    }
}

/// A runner thread's loop: duty cycles until the agents stop or fail.
fn run<I: IdleStrategy>(mut work: Work, mut idle: I, state: &AtomicU8) -> Result<(), AgentError> {
    loop {
        let now = karyos_sys::host_clock::host_monotonic_ns();
        match work.do_work(now) {
            Ok(_) if work.is_stopped() => {
                state.store(STOPPED, Ordering::Release);
                return Ok(());
            }
            Ok(count) => idle.idle(count),
            Err(error) => {
                state.store(FAILED, Ordering::Release);
                return Err(error);
            }
        }
    }
}

#[cfg(test)]
mod tests;
