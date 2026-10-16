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

pub mod ring;

use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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

/// Configuration of the agents and their rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentConfig {
    /// Entries of each agent's command ring, at least 1.
    pub command_capacity: usize,
    /// Entries of each agent's event ring, at least 1.
    pub event_capacity: usize,
    /// Commands an agent serves per duty cycle, at least 1.
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

impl AgentConfig {
    /// The ring capacities, checked.
    fn validate(&self) -> Result<(NonZeroUsize, NonZeroUsize), AgentError> {
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
        Ok((commands, events))
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
    /// Test only: panic in the duty cycle.
    #[cfg(test)]
    Panic,
    /// Test only: block the duty cycle until the flag is cleared.
    #[cfg(test)]
    Block(Arc<AtomicBool>),
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
    /// The agent saw its stop flag (best effort: posted only when the ring
    /// has a free slot; the runner's join is the authority).
    Stopped {
        /// The agent.
        agent: AgentKind,
    },
}

/// What an agent has from the conductor: its rings, its stop flag and its
/// state.
#[derive(Debug)]
struct AgentCore {
    kind: AgentKind,
    commands: RingReceiver<AgentCommand>,
    events: RingSender<AgentEvent>,
    budget: u32,
    stop: Arc<AtomicBool>,
    stopped: bool,
    /// Test only: records each duty cycle's agent, in call order.
    #[cfg(test)]
    calls: Option<Arc<std::sync::Mutex<Vec<AgentKind>>>>,
}

impl AgentCore {
    /// One duty cycle: the stop flag first, then up to the budget's
    /// commands; returns how many were served.
    fn serve_commands(&mut self) -> Result<u32, AgentError> {
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
                    match self.events.post(reply, event) {
                        Ok(()) => {}
                        // The conductor dropped its links: stop, nobody
                        // reads the reply.
                        Err(PostError::Gone(_)) => {
                            self.stopped = true;
                            break;
                        }
                        Err(PostError::Full(_) | PostError::Foreign(_)) => {
                            return Err(AgentError::Invariant(self.kind));
                        }
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
    /// [`AgentError::Invariant`] or [`AgentError::CountOverflow`].
    pub fn do_work(&mut self, now: u64) -> Result<u32, AgentError> {
        let _ = now;
        self.core.serve_commands()
    }

    /// Whether the agent stopped: its flag was set or its conductor is
    /// gone.
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
    /// [`AgentError::Invariant`] or [`AgentError::CountOverflow`].
    pub fn do_work(&mut self, now: u64) -> Result<u32, AgentError> {
        let _ = now;
        self.core.serve_commands()
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
pub struct AgentLink {
    kind: AgentKind,
    commands: RingSender<AgentCommand>,
    events: RingSender<AgentEvent>,
    received: RingReceiver<AgentEvent>,
    stop: Arc<AtomicBool>,
}

impl AgentLink {
    /// Posts the command `make` builds around its reply's reservation.
    /// Nothing is posted when a slot is missing.
    ///
    /// # Errors
    ///
    /// [`AgentError::Busy`] when the command ring or the reply slot is
    /// full, [`AgentError::Gone`] when the agent is gone,
    /// [`AgentError::Invariant`] for a broken ring invariant.
    pub fn post(&self, make: impl FnOnce(Reservation) -> AgentCommand) -> Result<(), AgentError> {
        let busy = AgentError::Busy(self.kind);
        let reply = self.events.reserve().ok_or(busy.clone())?;
        let slot = self.commands.reserve().ok_or(busy)?;
        self.commands
            .post(slot, make(reply))
            .map_err(|error| match error {
                PostError::Gone(_) => AgentError::Gone(self.kind),
                PostError::Full(_) | PostError::Foreign(_) => AgentError::Invariant(self.kind),
            })
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
///
/// # Errors
///
/// [`AgentError::InvalidConfig`] for a zero capacity or budget.
pub fn network_agents(config: AgentConfig) -> Result<(NetworkAgents, AgentLinks), AgentError> {
    let (command_capacity, event_capacity) = config.validate()?;
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
    Ok((
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
    ))
}

/// An agent's state as the runner publishes it.
const RUNNING: u8 = 0;
const STOPPED: u8 = 1;
const FAILED: u8 = 2;

/// What a runner thread drives.
#[derive(Debug)]
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
type ThreadResult = Option<(Work, Option<AgentError>)>;

/// One runner thread: the agents it drives and its state cell.
#[derive(Debug)]
struct AgentThread {
    kinds: Vec<AgentKind>,
    state: Arc<AtomicU8>,
    handle: JoinHandle<ThreadResult>,
}

/// The threads of the Dedicated and Shared network modes (DN-2).
#[derive(Debug)]
pub struct AgentRunner {
    threads: Vec<AgentThread>,
    stops: [Arc<AtomicBool>; 2],
    stop_timeout: Duration,
}

/// Why [`AgentRunner::start`] failed. The agents come back, unstarted.
#[derive(Debug)]
pub struct StartError {
    /// What failed.
    pub error: AgentError,
    /// The agents, as they were given ([`Stopped::into_agents`]).
    pub agents: Stopped,
}

/// What [`AgentRunner::stop`] got back.
#[derive(Debug, Default)]
pub struct Stopped {
    /// The sender agent, unless its thread is late or lost it.
    pub sender: Option<SenderAgent>,
    /// The receiver agent, unless its thread is late or lost it.
    pub receiver: Option<ReceiverAgent>,
    /// The failures that stopped threads (DN-9).
    pub failures: Vec<AgentError>,
    /// Threads still running after the timeout, for the conductor to wait
    /// on or abandon.
    pub late: Vec<LateAgent>,
}

impl Stopped {
    /// Both agents, when both came back.
    #[must_use]
    pub fn into_agents(self) -> Option<NetworkAgents> {
        Some(NetworkAgents {
            sender: self.sender?,
            receiver: self.receiver?,
        })
    }

    fn take(&mut self, work: Work) {
        match work {
            Work::Sender(agent) => self.sender = Some(agent),
            Work::Receiver(agent) => self.receiver = Some(agent),
            Work::Both(agents) => {
                self.sender = Some(agents.sender);
                self.receiver = Some(agents.receiver);
            }
        }
    }

    fn absorb(&mut self, thread: AgentThread) {
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
pub struct LateAgent {
    thread: AgentThread,
}

impl LateAgent {
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
    pub fn join(self) -> Stopped {
        let mut stopped = Stopped::default();
        stopped.absorb(self.thread);
        stopped
    }
}

impl AgentRunner {
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
        agents: NetworkAgents,
        config: AgentConfig,
        idle: impl Fn() -> I,
    ) -> Result<Self, StartError> {
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
                (vec![AgentKind::Receiver], Work::Receiver(agents.receiver)),
                (vec![AgentKind::Sender], Work::Sender(agents.sender)),
            ],
            ThreadingMode::SharedNetwork => vec![(
                vec![AgentKind::Receiver, AgentKind::Sender],
                Work::Both(agents),
            )],
        };
        let mut threads = Vec::with_capacity(work.len());
        let mut handoffs = Vec::with_capacity(work.len());
        let mut failure = None;
        for (kinds, _) in &work {
            let state = Arc::new(AtomicU8::new(RUNNING));
            let thread_state = Arc::clone(&state);
            let strategy = idle();
            let (handoff, waiting) = mpsc::channel::<Work>();
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
    pub fn stop(self) -> Stopped {
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
fn run<I: IdleStrategy>(
    mut work: Work,
    mut idle: I,
    state: &AtomicU8,
) -> (Work, Option<AgentError>) {
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
