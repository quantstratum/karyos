// SPDX-License-Identifier: Apache-2.0

//! The `ClusteredService` delivery path in the harness (C10, karyos#686):
//! a [`DeliveryServer`] runs a core over C4's log on its own disk, as
//! [`super::node::ServerNode`] does, and feeds its committed entries to
//! a [`ServiceContainer`]; a [`DeliveryClient`] registers, then sends its
//! commands under its session's epoch and sequence.
//!
//! - **Separate from the C5 nodes.** `ServerNode` and its `TestService`
//!   are what the frozen C5 workloads measure, so the delivery path has
//!   its own node (karyos#686, plan amendment of 2026-10-27). A core's
//!   adapter runs over both, which is how the adapters run over the
//!   delivery path (ADR-0043, Harness). Merging the two nodes is decided
//!   at C6 (karyos#064).
//! - **Proposing.** The node proposes through [`Propose`], which
//!   [`Proposer`] implements for any [`ConsensusCore`]. A proposal is not
//!   told its index: the node that took a request answers it when an
//!   entry with the request's client, epoch and sequence applies
//!   (decision E2).
//! - **Leader following** (decision D4). A follower that a client sends
//!   to forwards the message to the leader its core names, once, with
//!   the client's identity, epoch and sequence unchanged; the leader's
//!   answer comes back through it ([`Delivery::Forward`],
//!   [`Delivery::Relay`]). With no leader known, the client gets
//!   [`Delivery::NotLeader`] and tries again later.
//! - **Unknown outcomes** (decision D5). A server whose core stops
//!   leading, or moves to another term, answers every request it took
//!   [`Answer::Unknown`]: the entry may still commit. The client sends the
//!   same epoch and sequence again, which the session table answers if
//!   the entry applied, and reports [`Answer::Unknown`] itself only at its
//!   deadline, or for a session gone after an earlier attempt.
//! - **Timers and configuration** (decision D6). A leader proposes a
//!   [`Envelope::TimerFired`] for every scheduled timer due at its clock
//!   that it has not proposed in its leadership; a new leadership proposes
//!   them all again, and a firing that applies twice delivers once. A
//!   core's own configuration entries, which
//!   [`DeliveryServer::with_configurations`] recognises, reach the service
//!   as configuration changes when they apply. An operator's
//!   [`Delivery::Change`] goes to the core.
//! - **Restart.** A restart reopens the log, recovers the core, and
//!   rebuilds the container from the committed entries the core hands
//!   out again, as `ServerNode` rebuilds its service.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use karyos_archive::segment::Geometry;
use karyos_cluster::dedup::{Outcome, Request};
use karyos_cluster::service::{
    Applied, ApplyError, ClusteredService, ContainerConfig, Context, Envelope, NotLeader, Propose,
    ServiceContainer,
};
use karyos_cluster::{Entry, LogError, RaftLog};

use super::core::{Change, ConsensusCore, LogView, drive};
use super::node::LOG_DIR;
use crate::cluster::{Node, Outbox};
use crate::disk::{SimDisk, Survives};
use crate::net::NodeId;

/// The one message type of a delivery run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery<M> {
    /// Between cores.
    Core(M),
    /// A client asks for a session.
    Register,
    /// Its session opened: the epoch its requests carry.
    Registered {
        /// The epoch.
        epoch: u64,
    },
    /// No session opened: every slot is live, or the registration came
    /// out of log order.
    RegisterRefused,
    /// A client's command.
    Request {
        /// Its client, epoch, sequence and lowest unanswered sequence.
        request: Request,
        /// The command.
        command: Vec<u8>,
    },
    /// The outcome of a request.
    Answer {
        /// The request.
        request: Request,
        /// What became of it.
        answer: Answer,
    },
    /// This server does not lead.
    NotLeader {
        /// The leader it knows of.
        leader: Option<NodeId>,
    },
    /// A follower passes a client's registration or request to the
    /// leader it knows of, one hop (decision D4): the leader proposes it
    /// and sends the answer back through the follower.
    Forward {
        /// The client.
        client: NodeId,
        /// Its [`Delivery::Register`] or [`Delivery::Request`].
        message: Box<Self>,
    },
    /// An operator's membership change, for the core; nothing answers
    /// it. The service sees it when the core's entry for it applies.
    Change(Change),
    /// The leader's answer to a forwarded message, for the follower to
    /// pass to the client.
    Relay {
        /// The client.
        client: NodeId,
        /// The answer.
        message: Box<Self>,
    },
}

/// A request's outcome, owned, as the session table gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The command ran; its reply.
    Applied(Vec<u8>),
    /// Applied before; its retained reply.
    Retained(Vec<u8>),
    /// Applied before, its reply acknowledged and gone.
    Duplicate,
    /// The command ran; its reply did not fit.
    ReplyTooLarge,
    /// No live session holds the client and epoch.
    SessionExpired,
    /// The session's window is full.
    WindowFull,
    /// Past the sequence the session expects.
    OutOfOrder {
        /// The one it expects.
        expected: u64,
    },
    /// The request's fate cannot be determined: it may or may not have
    /// been applied (decision D5). A server gives it for the requests it
    /// took when it stops leading; a client gives it when it cannot
    /// resolve a request before its deadline. Never a guess.
    Unknown,
    /// An outcome this harness does not know.
    Other(String),
}

impl Answer {
    /// The reply bytes of an applied or retained request; empty otherwise.
    #[must_use]
    pub fn reply(&self) -> &[u8] {
        match self {
            Self::Applied(reply) | Self::Retained(reply) => reply,
            _ => &[],
        }
    }

    fn of(outcome: Outcome<'_>) -> Self {
        match outcome {
            Outcome::Applied(reply) => Self::Applied(reply.to_vec()),
            Outcome::Retained(reply) => Self::Retained(reply.to_vec()),
            Outcome::Duplicate => Self::Duplicate,
            Outcome::ReplyTooLarge => Self::ReplyTooLarge,
            Outcome::SessionExpired => Self::SessionExpired,
            Outcome::WindowFull => Self::WindowFull,
            Outcome::OutOfOrder { expected } => Self::OutOfOrder { expected },
            other => Self::Other(format!("{other:?}")),
        }
    }
}

/// [`Propose`] for a [`ConsensusCore`] and its log, for one call.
pub struct Proposer<'a, 'l, C> {
    core: &'a mut C,
    log: &'a mut LogView<'l>,
}

impl<'a, 'l, C: ConsensusCore> Proposer<'a, 'l, C> {
    /// Proposing to `core`, over `log`.
    pub fn new(core: &'a mut C, log: &'a mut LogView<'l>) -> Self {
        Self { core, log }
    }
}

impl<C: ConsensusCore> Propose for Proposer<'_, '_, C> {
    fn propose(&mut self, payload: Vec<u8>) -> Result<(), NotLeader> {
        self.core
            .propose(payload, self.log)
            .map_err(|refused| NotLeader::new(refused.leader.map(u64::from)))
    }
}

/// What a server answers when its entry applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Pending {
    /// A registration of this client.
    Register(u64),
    /// A request: client, epoch and sequence.
    Request(u64, u64, u64),
}

/// The key an applied envelope answers.
fn pending_of(envelope: &Envelope<'_>) -> Option<Pending> {
    match *envelope {
        Envelope::Register { client } => Some(Pending::Register(client)),
        Envelope::Request { request, .. } => Some(Pending::Request(
            request.client,
            request.epoch,
            request.sequence,
        )),
        _ => None,
    }
}

/// Who a server answers for a pending request: the node it sends the
/// answer to, and the client, who differ for a forwarded request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Taker {
    reply_to: NodeId,
    client: NodeId,
}

impl Taker {
    /// `message` for the client, wrapped for its follower if forwarded.
    fn wrap<M>(self, message: Delivery<M>) -> (NodeId, Delivery<M>) {
        if self.reply_to == self.client {
            (self.client, message)
        } else {
            (
                self.reply_to,
                Delivery::Relay {
                    client: self.client,
                    message: Box::new(message),
                },
            )
        }
    }
}

/// A server of the delivery path: a core over C4's log on its own disk,
/// and a service container.
pub struct DeliveryServer<C, S> {
    id: NodeId,
    peers: Vec<NodeId>,
    geometry: Geometry,
    disk: SimDisk,
    survives: Survives,
    running: Option<(C, RaftLog<SimDisk>)>,
    /// The service as it starts, for a rebuild.
    fresh: S,
    config: ContainerConfig,
    container: ServiceContainer<S>,
    /// Requests and registrations this server took, and who it answers.
    pending: BTreeMap<Pending, Taker>,
    /// Whether the core led, and its term, at the end of the last duty.
    led: Option<u64>,
    /// The timer firings this server proposed while leading, by timer
    /// and deadline; cleared when its leadership changes, so a new
    /// leader proposes every due timer again (decision D6).
    fired: BTreeSet<(u64, u64)>,
    /// Which of the core's own entries are configuration changes.
    configurations: fn(&[u8]) -> bool,
    /// Every entry applied since the last start: its index and kind.
    kinds: Vec<(u64, &'static str)>,
    /// Every entry applied since the last start: its index and outcome.
    outcomes: Vec<(u64, Option<Answer>)>,
    /// Why the container stopped, if it did.
    halted: Option<ApplyError>,
    /// Why the disk cannot come back, when its crash could not be taken.
    lost: Option<String>,
}

impl<C: ConsensusCore, S: ClusteredService + Clone> DeliveryServer<C, S> {
    /// Server `id` of `peers`, with a new log on `disk` and `service`; a
    /// crash keeps what `survives`.
    ///
    /// # Errors
    ///
    /// The log's refusal to be created.
    ///
    /// # Panics
    ///
    /// When `config`'s session table cannot be held.
    pub fn new(
        id: NodeId,
        peers: Vec<NodeId>,
        disk: SimDisk,
        survives: Survives,
        geometry: Geometry,
        service: S,
        config: ContainerConfig,
    ) -> Result<Self, LogError> {
        let mut log = RaftLog::create(disk.clone(), Path::new(LOG_DIR), geometry, 1)?;
        let core = C::recover(id, &peers, &mut LogView::new(&mut log));
        Ok(Self {
            id,
            peers,
            geometry,
            disk,
            survives,
            running: Some((core, log)),
            container: container(service.clone(), config),
            fresh: service,
            config,
            pending: BTreeMap::new(),
            led: None,
            fired: BTreeSet::new(),
            configurations: |_| false,
            kinds: Vec::new(),
            outcomes: Vec::new(),
            halted: None,
            lost: None,
        })
    }

    /// Delivers the core's own entries that `configurations` recognises
    /// to the service as configuration changes (decision D6), so a core
    /// that writes its membership in its own format does not stop the
    /// container. Every replica recognises the same entries.
    #[must_use]
    pub fn with_configurations(mut self, configurations: fn(&[u8]) -> bool) -> Self {
        self.configurations = configurations;
        self
    }

    /// Every entry applied since the last start, with its index and its
    /// kind: `register`, `close`, `request`, `timer`, `configuration` or
    /// `core`.
    #[must_use]
    pub fn kinds(&self) -> &[(u64, &'static str)] {
        &self.kinds
    }

    /// The timer firings it proposed in its leadership and has not seen
    /// apply.
    #[must_use]
    pub fn proposed_firings(&self) -> usize {
        self.fired.len()
    }

    /// Whether it is up.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.running.is_some()
    }

    /// The container.
    #[must_use]
    pub fn container(&self) -> &ServiceContainer<S> {
        &self.container
    }

    /// Every entry applied since the last start, with its index and, for
    /// a request, its outcome.
    #[must_use]
    pub fn outcomes(&self) -> &[(u64, Option<Answer>)] {
        &self.outcomes
    }

    /// The requests this server took and has not answered.
    #[must_use]
    pub fn pending_requests(&self) -> usize {
        self.pending
            .keys()
            .filter(|key| matches!(key, Pending::Request(..)))
            .count()
    }

    /// Why the container stopped, if it did.
    #[must_use]
    pub fn halted(&self) -> Option<ApplyError> {
        self.halted
    }

    /// The core, while up.
    #[must_use]
    pub fn core(&self) -> Option<&C> {
        self.running.as_ref().map(|(core, _)| core)
    }

    /// Proposes `envelope` for `taker`. A refusal is answered at once:
    /// a follower forwards a client's own message to the leader it knows
    /// of, one hop; otherwise the taker gets [`Delivery::NotLeader`].
    fn propose(
        &mut self,
        taker: Taker,
        envelope: Envelope<'_>,
        message: Delivery<C::Message>,
        out: &mut Outbox<Delivery<C::Message>>,
    ) {
        let Some((core, log)) = self.running.as_mut() else {
            return;
        };
        // A message schema 2 refuses (a zero client or epoch, a command too
        // long) is never proposed, and is not answered.
        let Ok(payload) = envelope.to_vec() else {
            return;
        };
        let mut view = LogView::new(log);
        let refused = match Proposer::new(core, &mut view).propose(payload) {
            Ok(()) => {
                if let Some(key) = pending_of(&envelope) {
                    let _ = self.pending.insert(key, taker);
                }
                return;
            }
            Err(refused) => refused.leader.and_then(|leader| u32::try_from(leader).ok()),
        };
        match refused {
            // Forwarded once: a message that came forwarded is answered.
            Some(leader) if leader != self.id && taker.reply_to == taker.client => out.push((
                leader,
                Delivery::Forward {
                    client: taker.client,
                    message: Box::new(message),
                },
            )),
            leader => out.push(taker.wrap(Delivery::NotLeader { leader })),
        }
    }

    /// Takes `message` from client `client`, answering `reply_to`.
    fn take(
        &mut self,
        reply_to: NodeId,
        client: NodeId,
        message: Delivery<C::Message>,
        out: &mut Outbox<Delivery<C::Message>>,
    ) {
        let taker = Taker { reply_to, client };
        match &message {
            Delivery::Register => {
                let envelope = Envelope::Register {
                    client: u64::from(client),
                };
                self.propose(taker, envelope, message.clone(), out);
            }
            // A client speaks for itself only.
            Delivery::Request { request, command } if request.client == u64::from(client) => {
                let command = command.clone();
                let envelope = Envelope::Request {
                    request: *request,
                    command: &command,
                };
                self.propose(taker, envelope, message.clone(), out);
            }
            _ => {}
        }
    }

    /// A core that stopped leading, or moved to another term, cannot know
    /// what becomes of the requests it took: each is answered
    /// [`Answer::Unknown`] (decision D5). A registration is dropped; the
    /// client registers again, and a session opened meanwhile expires
    /// unused.
    fn unknown_on_leadership_loss(&mut self, out: &mut Outbox<Delivery<C::Message>>) {
        let now = self
            .running
            .as_ref()
            .and_then(|(core, _)| core.leads().then(|| core.term()));
        if self.led.is_some() && self.led != now {
            for (key, taker) in std::mem::take(&mut self.pending) {
                if let Pending::Request(client, epoch, sequence) = key {
                    let request = Request::new(client, epoch, sequence, sequence);
                    out.push(taker.wrap(Delivery::Answer {
                        request,
                        answer: Answer::Unknown,
                    }));
                }
            }
        }
        if self.led != now {
            self.fired.clear();
        }
        self.led = now;
    }

    /// A leader proposes a firing for every scheduled timer due at its
    /// clock `now` that it has not proposed in its leadership. A firing
    /// its predecessor proposed too applies once (decision D6).
    fn propose_due(&mut self, now: u64) {
        let Some((core, log)) = self.running.as_mut() else {
            return;
        };
        if !core.leads() {
            return;
        }
        let due: Vec<_> = self
            .container
            .due(now)
            .filter(|envelope| match *envelope {
                Envelope::TimerFired { timer, deadline } => {
                    !self.fired.contains(&(timer, deadline))
                }
                _ => false,
            })
            .collect();
        let mut view = LogView::new(log);
        for envelope in due {
            if let Envelope::TimerFired { timer, deadline } = envelope
                && let Ok(payload) = envelope.to_vec()
                && Proposer::new(core, &mut view).propose(payload).is_ok()
            {
                let _ = self.fired.insert((timer, deadline));
            }
        }
    }

    /// Drives the core, applies what it committed, and answers what this
    /// server took.
    fn duty(&mut self, out: &mut Outbox<Delivery<C::Message>>) {
        let Some((mut core, mut log)) = self.running.take() else {
            return;
        };
        let mut committed = Vec::new();
        let driven = drive(
            &mut core,
            &mut log,
            &mut |to, message, _| out.push((to, Delivery::Core(message))),
            &mut |entry, _| committed.push(entry.clone()),
            &mut |_| {},
        );
        // A failed persistence stops the node until a restart, as for
        // `ServerNode`; what it committed before still applies.
        let failed = driven.is_err();
        for entry in &committed {
            self.apply(entry, out);
        }
        if !failed {
            self.running = Some((core, log));
        }
        self.unknown_on_leadership_loss(out);
    }

    fn apply(&mut self, entry: &Entry, out: &mut Outbox<Delivery<C::Message>>) {
        if self.halted.is_some() {
            return;
        }
        // A core's own configuration entry, as the service's change. One
        // that schema 2 cannot carry stays as it is, and stops the
        // container at it on every replica.
        let translated;
        let entry = if (self.configurations)(&entry.payload)
            && let Ok(payload) = Envelope::Configuration(&entry.payload).to_vec()
        {
            translated = Entry {
                payload,
                ..entry.clone()
            };
            &translated
        } else {
            entry
        };
        let kind = match Envelope::decode(&entry.payload) {
            _ if entry.payload.is_empty() => "core",
            Ok(Envelope::Register { .. }) => "register",
            Ok(Envelope::Close { .. }) => "close",
            Ok(Envelope::Request { .. }) => "request",
            Ok(Envelope::TimerFired { timer, deadline }) => {
                let _ = self.fired.remove(&(timer, deadline));
                "timer"
            }
            Ok(Envelope::Configuration(_)) => "configuration",
            _ => "unknown",
        };
        let key = Envelope::decode(&entry.payload)
            .ok()
            .and_then(|envelope| pending_of(&envelope));
        let answer = match self.container.apply(entry) {
            Ok(Applied::Registered(registered)) => Some(match registered {
                Ok(registered) => Delivery::Registered {
                    epoch: registered.epoch,
                },
                Err(_) => Delivery::RegisterRefused,
            }),
            Ok(Applied::Answered { request, outcome }) => Some(Delivery::Answer {
                request,
                answer: Answer::of(outcome),
            }),
            Ok(_) => None,
            Err(error) => {
                self.halted = Some(error);
                return;
            }
        };
        let outcome = match &answer {
            Some(Delivery::Answer { answer, .. }) => Some(answer.clone()),
            _ => None,
        };
        self.outcomes.push((entry.index, outcome));
        self.kinds.push((entry.index, kind));
        if let (Some(key), Some(answer)) = (key, answer)
            && let Some(taker) = self.pending.remove(&key)
        {
            out.push(taker.wrap(answer));
        }
    }

    /// Opens the log, recovers the core and rebuilds the container.
    fn start(&mut self) {
        if self.lost.is_some() {
            return;
        }
        let Ok(opened) = RaftLog::open(self.disk.clone(), Path::new(LOG_DIR), self.geometry) else {
            return;
        };
        let mut log = opened.log;
        let core = C::recover(self.id, &self.peers, &mut LogView::new(&mut log));
        self.container = container(self.fresh.clone(), self.config);
        self.outcomes.clear();
        self.kinds.clear();
        self.fired.clear();
        self.halted = None;
        self.running = Some((core, log));
    }
}

/// A container for `service`.
///
/// # Panics
///
/// When `config`'s session table cannot be held: a harness
/// configuration error.
#[expect(
    clippy::expect_used,
    reason = "a harness fixture: an unusable configuration is the test's bug"
)]
fn container<S: ClusteredService>(service: S, config: ContainerConfig) -> ServiceContainer<S> {
    ServiceContainer::new(service, config).expect("a session table the harness can hold")
}

impl<C: ConsensusCore, S: ClusteredService + Clone> Node<Delivery<C::Message>>
    for DeliveryServer<C, S>
{
    fn tick(&mut self, now: u64, out: &mut Outbox<Delivery<C::Message>>) {
        if let Some((core, log)) = self.running.as_mut() {
            core.tick(now, &mut LogView::new(log));
        }
        self.propose_due(now);
        self.duty(out);
    }

    fn deliver(
        &mut self,
        from: NodeId,
        message: Delivery<C::Message>,
        _now: u64,
        out: &mut Outbox<Delivery<C::Message>>,
    ) {
        match message {
            Delivery::Core(message) => {
                if let Some((core, log)) = self.running.as_mut() {
                    core.step(from, message, &mut LogView::new(log));
                }
            }
            Delivery::Forward { client, message } => self.take(from, client, *message, out),
            Delivery::Relay { client, message } => out.push((client, *message)),
            Delivery::Change(change) => {
                if let Some((core, log)) = self.running.as_mut() {
                    let _ = core.propose_change(change, &mut LogView::new(log));
                }
            }
            message @ (Delivery::Register | Delivery::Request { .. }) => {
                self.take(from, from, message, out);
            }
            _ => {}
        }
        self.duty(out);
    }

    fn crash(&mut self) {
        self.running = None;
        self.pending.clear();
        self.led = None;
        match self.disk.after_crash(self.survives) {
            Ok(disk) => self.disk = disk,
            Err(error) => self.lost = Some(error.to_string()),
        }
    }

    fn restart(&mut self, _now: u64) {
        self.start();
    }
}

/// Ticks a client waits for an answer before it sends the same request
/// again.
pub const RETRY_AFTER: u64 = 400;

/// Ticks a client tries one command, from its first send, before it
/// reports [`Answer::Unknown`].
pub const DEADLINE: u64 = 4000;

/// A client of the delivery path: it registers with `server`, then sends
/// its commands in order, one at a time, each until it is answered.
#[derive(Debug, Clone)]
pub struct DeliveryClient {
    id: NodeId,
    server: NodeId,
    commands: Vec<Vec<u8>>,
    epoch: Option<u64>,
    /// The next command's position, which is its sequence.
    next: usize,
    /// When the current registration or command was last sent.
    sent_at: Option<u64>,
    /// When the current command was first sent, and how often.
    first_sent: Option<u64>,
    attempts: u32,
    deadline: u64,
    /// [`Answer::Unknown`]s and [`Delivery::NotLeader`]s received, each
    /// followed by a retry.
    retries: u32,
    /// [`Answer::Unknown`]s a server gave.
    unknowns: u32,
    /// Each command is sent twice at once, as a client retry that races
    /// its first attempt.
    twice: bool,
    answers: Vec<(u64, Answer)>,
}

impl DeliveryClient {
    /// Client `id`, sending `commands` to `server`.
    #[must_use]
    pub fn new(id: NodeId, server: NodeId, commands: Vec<Vec<u8>>) -> Self {
        Self {
            id,
            server,
            commands,
            epoch: None,
            next: 0,
            sent_at: None,
            first_sent: None,
            attempts: 0,
            deadline: DEADLINE,
            retries: 0,
            unknowns: 0,
            twice: false,
            answers: Vec::new(),
        }
    }

    /// Sends every command twice at once.
    #[must_use]
    pub fn twice(mut self) -> Self {
        self.twice = true;
        self
    }

    /// Reports [`Answer::Unknown`] for a command not resolved `deadline`
    /// ticks after its first send.
    #[must_use]
    pub fn with_deadline(mut self, deadline: u64) -> Self {
        self.deadline = deadline;
        self
    }

    /// The server it sends to: the first one, or the leader a
    /// [`Delivery::NotLeader`] named.
    #[must_use]
    pub fn server(&self) -> NodeId {
        self.server
    }

    /// The retries an unknown outcome or a refusal caused.
    #[must_use]
    pub fn retries(&self) -> u32 {
        self.retries
    }

    /// The [`Answer::Unknown`]s servers gave it, each retried.
    #[must_use]
    pub fn unknowns(&self) -> u32 {
        self.unknowns
    }

    /// Records `answer` for the current command and moves to the next.
    fn resolve(&mut self, answer: Answer) {
        self.answers.push((self.sequence(), answer));
        self.next += 1;
        self.sent_at = None;
        self.first_sent = None;
        self.attempts = 0;
    }

    /// Its session's epoch, once registered.
    #[must_use]
    pub fn epoch(&self) -> Option<u64> {
        self.epoch
    }

    /// The answers, by sequence, in the order they came.
    #[must_use]
    pub fn answers(&self) -> &[(u64, Answer)] {
        &self.answers
    }

    /// Every command answered.
    #[must_use]
    pub fn done(&self) -> bool {
        self.next == self.commands.len()
    }

    fn sequence(&self) -> u64 {
        u64::try_from(self.next).unwrap_or(u64::MAX)
    }
}

impl<M> Node<Delivery<M>> for DeliveryClient {
    fn tick(&mut self, now: u64, out: &mut Outbox<Delivery<M>>) {
        if self
            .sent_at
            .is_some_and(|sent| now.saturating_sub(sent) < RETRY_AFTER)
        {
            return;
        }
        let Some(epoch) = self.epoch else {
            out.push((self.server, Delivery::Register));
            self.sent_at = Some(now);
            return;
        };
        let Some(command) = self.commands.get(self.next).cloned() else {
            return;
        };
        // The client cannot resolve it: it says so, and moves on.
        if self
            .first_sent
            .is_some_and(|first| now.saturating_sub(first) >= self.deadline)
        {
            self.resolve(Answer::Unknown);
            return;
        }
        let sequence = self.sequence();
        let request = Request::new(u64::from(self.id), epoch, sequence, sequence);
        let sends = if self.twice { 2 } else { 1 };
        for _ in 0..sends {
            out.push((
                self.server,
                Delivery::Request {
                    request,
                    command: command.clone(),
                },
            ));
        }
        self.sent_at = Some(now);
        self.first_sent.get_or_insert(now);
        self.attempts = self.attempts.saturating_add(1);
    }

    fn deliver(
        &mut self,
        _from: NodeId,
        message: Delivery<M>,
        _now: u64,
        _out: &mut Outbox<Delivery<M>>,
    ) {
        match message {
            Delivery::Registered { epoch } if self.epoch.is_none() => {
                self.epoch = Some(epoch);
                self.sent_at = None;
            }
            Delivery::Answer { request, answer }
                if Some(request.epoch) == self.epoch && request.sequence == self.sequence() =>
            {
                match answer {
                    // Its fate unknown at the server: the same epoch and
                    // sequence again, which the session table answers if
                    // it was applied.
                    Answer::Unknown => {
                        self.retries = self.retries.saturating_add(1);
                        self.unknowns = self.unknowns.saturating_add(1);
                        self.sent_at = None;
                    }
                    // A session gone after an earlier attempt: that attempt
                    // may have applied, so it is not known.
                    Answer::SessionExpired if self.attempts > 1 => self.resolve(Answer::Unknown),
                    answer => self.resolve(answer),
                }
            }
            Delivery::NotLeader { leader } => {
                self.retries = self.retries.saturating_add(1);
                if let Some(leader) = leader {
                    self.server = leader;
                    self.sent_at = None;
                }
            }
            _ => {}
        }
    }
}

/// A node of a delivery run.
pub enum DeliveryMember<C, S> {
    /// A server.
    Server(Box<DeliveryServer<C, S>>),
    /// A client.
    Client(DeliveryClient),
}

impl<C, S> DeliveryMember<C, S> {
    /// The server, if it is one.
    #[must_use]
    pub fn server(&self) -> Option<&DeliveryServer<C, S>> {
        match self {
            Self::Server(server) => Some(server),
            Self::Client(_) => None,
        }
    }

    /// The client, if it is one.
    #[must_use]
    pub fn client(&self) -> Option<&DeliveryClient> {
        match self {
            Self::Client(client) => Some(client),
            Self::Server(_) => None,
        }
    }
}

impl<C: ConsensusCore, S: ClusteredService + Clone> Node<Delivery<C::Message>>
    for DeliveryMember<C, S>
{
    fn tick(&mut self, now: u64, out: &mut Outbox<Delivery<C::Message>>) {
        match self {
            Self::Server(server) => server.tick(now, out),
            Self::Client(client) => client.tick(now, out),
        }
    }

    fn deliver(
        &mut self,
        from: NodeId,
        message: Delivery<C::Message>,
        now: u64,
        out: &mut Outbox<Delivery<C::Message>>,
    ) {
        match self {
            Self::Server(server) => server.deliver(from, message, now, out),
            Self::Client(client) => client.deliver(from, message, now, out),
        }
    }

    fn crash(&mut self) {
        if let Self::Server(server) = self {
            server.crash();
        }
    }

    fn restart(&mut self, now: u64) {
        if let Self::Server(server) = self {
            server.restart(now);
        }
    }
}

/// The delivery path's test service: an append-only register of `u64`s.
/// A command of 8 bytes is a value to append, and its reply is the count
/// after it, 8 bytes. A command of 17 bytes, `T` then a timer and a delay,
/// schedules that timer at the log time plus the delay, and replies
/// nothing. Any other command does nothing and replies nothing. Timers
/// fired and configuration changes are recorded with the index they
/// applied at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppendService {
    /// The values, in the order applied.
    pub values: Vec<u64>,
    /// Timers fired and configuration changes, with their index.
    pub events: Vec<(u64, String)>,
}

/// The [`AppendService`] command that schedules `timer` `after` log-time
/// units from the log time it applies at.
#[must_use]
pub fn schedule(timer: u64, after: u64) -> Vec<u8> {
    let mut command = vec![b'T'];
    command.extend_from_slice(&timer.to_le_bytes());
    command.extend_from_slice(&after.to_le_bytes());
    command
}

impl ClusteredService for AppendService {
    fn on_command(
        &mut self,
        context: &mut Context<'_>,
        _client: u64,
        command: &[u8],
        reply: &mut [u8],
    ) -> Option<usize> {
        if let Ok(value) = <[u8; 8]>::try_from(command) {
            self.values.push(u64::from_le_bytes(value));
            let count = u64::try_from(self.values.len()).unwrap_or(u64::MAX);
            reply.get_mut(..8)?.copy_from_slice(&count.to_le_bytes());
            return Some(8);
        }
        if let [b'T', rest @ ..] = command
            && let (Some(timer), Some(after)) = (rest.get(..8), rest.get(8..))
            && let (Ok(timer), Ok(after)) = (<[u8; 8]>::try_from(timer), <[u8; 8]>::try_from(after))
        {
            let deadline = context.log_time().saturating_add(u64::from_le_bytes(after));
            let _ = context.schedule(u64::from_le_bytes(timer), deadline);
        }
        Some(0)
    }

    fn on_timer(&mut self, context: &mut Context<'_>, timer: u64) {
        self.events
            .push((context.index(), format!("timer {timer}")));
    }

    fn on_configuration(&mut self, context: &mut Context<'_>, configuration: &[u8]) {
        self.events.push((
            context.index(),
            format!("configuration of {} bytes", configuration.len()),
        ));
    }
}
