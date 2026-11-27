// SPDX-License-Identifier: Apache-2.0

//! The shipped Cluster node (C6, quantstratum/karyos#681): a consensus core
//! behind [`ConsensusCore`] over C4's log on its own disk, driven with
//! persist then send ([`drive`]), feeding its committed entries to a
//! [`ServiceContainer`], whose C7a session table deduplicates. It was the
//! simulator's `DeliveryServer` (C10, karyos#686); the simulator now runs
//! this node behind its harness wrapper, so the delivery path's tests run
//! the shipped node. It is transport neutral and clock injected: its
//! caller sends what it puts in the outbox, feeds it what arrives, and
//! ticks it (a process and socket host is not part of C6).
//!
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
//!   [`Answer::Unknown`]: the entry may still commit.
//! - **Timers and configuration** (decision D6). A leader proposes a
//!   [`Envelope::TimerFired`] for every scheduled timer due at its clock
//!   that it has not proposed in its leadership; a new leadership proposes
//!   them all again, and a firing that applies twice delivers once. A
//!   core's own configuration entries, which
//!   [`ClusterNode::with_configurations`] recognises, reach the service
//!   as configuration changes when they apply. An operator's
//!   [`Delivery::Change`] goes to the core.
//! - **Session bounds** (karyos#927). A leader proposes its container's
//!   session bounds once per leadership while the log it applied carries
//!   none ([`ServiceContainer::propose_bounds`]), so the bounds are a log
//!   entry a restarted server reads back.
//! - **Restart.** [`ClusterNode::restart`] reopens the log, recovers the
//!   core, and rebuilds the container from the committed entries the core
//!   hands out again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use karyos_archive::disk::Disk;
use karyos_archive::segment::Geometry;

use crate::dedup::{ConfigError, Outcome, Request};
use crate::driver::{Change, ConsensusCore, LogView, NodeId, Refused, drive};
use crate::service::{
    Applied, ApplyError, ClusteredService, ContainerConfig, Envelope, NotLeader, Propose,
    ProposeRefused, ServiceContainer, SessionBounds,
};
use crate::{Entry, LogError, RaftLog};

/// What a node sends: to whom, and the message.
pub type Outbox<M> = Vec<(NodeId, M)>;

/// The longest a committed tail waits unsealed by default, in ticks.
pub const DEFAULT_SEAL_INTERVAL: u64 = 64;

/// Why a node could not be made.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// The log's refusal to be created.
    #[error("the node's log: {0}")]
    Log(#[from] LogError),
    /// A container configuration that cannot be held.
    #[error("the node's container: {0:?}")]
    Config(ConfigError),
}

impl From<ConfigError> for NodeError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

/// The messages of a Cluster node: between cores, and between clients
/// and servers.
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
    /// The identity applied before with another command (karyos#750).
    PayloadMismatch,
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
            Outcome::PayloadMismatch => Self::PayloadMismatch,
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
    fn leads(&self) -> bool {
        self.core.leads()
    }

    fn propose(&mut self, payload: Vec<u8>) -> Result<(), NotLeader> {
        self.core
            .propose(payload, self.log)
            .map_err(|refused| match refused {
                Refused::NotLeader(refused) => NotLeader::new(refused.leader.map(u64::from)),
                // The delivery cases declare no limits, so a core never
                // pushes back here; were it to, the container retries as
                // it does for a leader it does not know.
                Refused::Backpressure(_) => NotLeader::new(None),
            })
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

/// A Cluster node: a core over C4's log in its own directory on its own
/// disk, and a service container.
pub struct ClusterNode<C, S, D: Disk + Clone> {
    id: NodeId,
    peers: Vec<NodeId>,
    geometry: Geometry,
    disk: D,
    /// The log's directory on `disk`.
    dir: PathBuf,
    /// The longest a committed tail waits unsealed, in the node's ticks.
    seal_interval: u64,
    running: Option<(C, RaftLog<D>)>,
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
    /// Whether this server proposed the session bounds in its leadership
    /// (karyos#927); cleared when its leadership changes.
    bounds_proposed: bool,
    /// Registrations taken while leading before the session bounds
    /// applied (karyos#927): proposed once they apply. At most
    /// `held_capacity`; one more is answered `NotLeader` naming this
    /// server, so its client retries. On a loss of leadership each is
    /// answered, never dropped silently (D5).
    deferred: Vec<Taker>,
    /// The most registrations held: the session table's size by default.
    held_capacity: usize,
    /// Whether this server proposes the session bounds as a leader (a
    /// test turns it off to hold registrations deterministically).
    proposes_bounds: bool,
    /// Which of the core's own entries are configuration changes.
    configurations: fn(&[u8]) -> bool,
    /// Every entry applied since the last start: its index and kind.
    kinds: Vec<(u64, &'static str)>,
    /// Every entry applied since the last start: its index and outcome.
    outcomes: Vec<(u64, Option<Answer>)>,
    /// Why the container stopped, if it did.
    halted: Option<ApplyError>,
}

impl<C: ConsensusCore, S: ClusteredService + Clone, D: Disk + Clone> ClusterNode<C, S, D> {
    /// Server `id` of `peers`, with a new log in `dir` on `disk`, and
    /// `service`.
    ///
    /// # Errors
    ///
    /// [`NodeError::Log`], the log's refusal to be created, or
    /// [`NodeError::Config`], a container configuration that cannot be
    /// held.
    pub fn new(
        id: NodeId,
        peers: Vec<NodeId>,
        (disk, dir): (D, &Path),
        geometry: Geometry,
        service: S,
        config: ContainerConfig,
    ) -> Result<Self, NodeError> {
        let container = ServiceContainer::new(service.clone(), config)?;
        let mut log = RaftLog::create(disk.clone(), dir, geometry, 1)?;
        let core = C::recover(id, &peers, &mut LogView::new(&mut log));
        Ok(Self {
            id,
            peers,
            geometry,
            disk,
            dir: dir.to_path_buf(),
            seal_interval: DEFAULT_SEAL_INTERVAL,
            running: Some((core, log)),
            container,
            fresh: service,
            config,
            pending: BTreeMap::new(),
            led: None,
            fired: BTreeSet::new(),
            bounds_proposed: false,
            deferred: Vec::with_capacity(
                usize::try_from(config.dedup.sessions)
                    .unwrap_or(usize::MAX)
                    .min(4096),
            ),
            held_capacity: usize::try_from(config.dedup.sessions).unwrap_or(usize::MAX),
            proposes_bounds: true,
            configurations: |_| false,
            kinds: Vec::new(),
            outcomes: Vec::new(),
            halted: None,
        })
    }

    /// Seals a committed tail after at most `ticks` of the node's clock.
    #[must_use]
    pub fn with_seal_interval(mut self, ticks: u64) -> Self {
        self.seal_interval = ticks;
        self
    }

    /// Its disk.
    #[must_use]
    pub fn disk(&self) -> &D {
        &self.disk
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

    /// The registrations held until the session bounds apply.
    #[must_use]
    pub fn held_registrations(&self) -> usize {
        self.deferred.len()
    }

    /// Holds at most `capacity` registrations before the session bounds
    /// apply (karyos#927 review).
    #[must_use]
    pub fn with_held_registrations(mut self, capacity: usize) -> Self {
        self.held_capacity = capacity;
        self.deferred = Vec::with_capacity(capacity.min(4096));
        self
    }

    /// Never proposes the session bounds: registrations stay held, for a
    /// test of the holding itself.
    #[must_use]
    pub fn without_bounds_proposal(mut self) -> Self {
        self.proposes_bounds = false;
        self
    }

    /// Every entry applied since the last start, with its index and its
    /// kind: `register`, `close`, `request`, `timer`, `configuration`,
    /// `bounds` or `core`.
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

    /// A clean shutdown (karyos#1050 review): the server stops and its log
    /// closes, sealing its committed tail; its restart reopens it.
    ///
    /// # Errors
    ///
    /// The log's close error.
    pub fn shutdown(&mut self) -> Result<(), LogError> {
        match self.running.take() {
            Some((_, log)) => log.close(),
            None => Ok(()),
        }
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
        let mut view = LogView::new(log);
        let refused = match self
            .container
            .propose(&envelope, &mut Proposer::new(core, &mut view))
        {
            Ok(()) => {
                if let Some(key) = pending_of(&envelope) {
                    let _ = self.pending.insert(key, taker);
                }
                return;
            }
            // No registration before the cluster's session bounds have
            // applied (ADR-0087; the container's gate since karyos#1053):
            // a registration under this replica's own configuration could
            // apply under other limits on a replica with other startup
            // bounds. This host holds it, bounded, until the bounds apply;
            // past the bound it answers NotLeader naming itself, so the
            // client retries.
            Err(ProposeRefused::BoundsPending) => {
                if self.deferred.len() < self.held_capacity {
                    self.deferred.push(taker);
                } else {
                    out.push(taker.wrap(Delivery::NotLeader {
                        leader: Some(self.id),
                    }));
                }
                return;
            }
            // A message schema 2 refuses (a zero client or epoch, a command
            // too long) is never proposed, and is not answered.
            Err(ProposeRefused::Codec(_)) => return,
            Err(ProposeRefused::NotLeader(refused)) => {
                refused.leader.and_then(|leader| u32::try_from(leader).ok())
            }
            Err(_) => None,
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
            self.bounds_proposed = false;
            // A held registration is answered, never dropped silently:
            // proposing it now forwards it to the leader this core knows,
            // or answers NotLeader with that hint. A server that leads
            // again keeps it held until the bounds apply.
            if now.is_none() {
                for taker in std::mem::take(&mut self.deferred) {
                    let envelope = Envelope::Register {
                        client: u64::from(taker.client),
                    };
                    self.propose(taker, envelope, Delivery::Register, out);
                }
            }
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
        // The session bounds, once per leadership while the log carries
        // none (karyos#927).
        if self.proposes_bounds
            && !self.bounds_proposed
            && self
                .container
                .propose_bounds(&mut Proposer::new(core, &mut LogView::new(log)))
                == Ok(true)
        {
            self.bounds_proposed = true;
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
            _ if SessionBounds::decode(&entry.payload).is_ok() => "bounds",
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

    /// Stops at once, as a crash does: the core and the open log are
    /// dropped and nothing this server took is answered. [`Self::restart`]
    /// brings it back.
    pub fn crash(&mut self) {
        self.running = None;
        self.pending.clear();
        self.deferred.clear();
        self.led = None;
    }

    /// Restarts on `disk` (what survived): opens the log, recovers the core
    /// and rebuilds the container from the entries it hands out again.
    pub fn restart(&mut self, disk: D) {
        self.disk = disk;
        self.start();
    }

    /// Opens the log, recovers the core and rebuilds the container.
    fn start(&mut self) {
        let Ok(opened) = RaftLog::open(self.disk.clone(), &self.dir, self.geometry) else {
            return;
        };
        // Validated at `new`: the same configuration is held again.
        let Ok(container) = ServiceContainer::new(self.fresh.clone(), self.config) else {
            return;
        };
        let mut log = opened.log;
        let core = C::recover(self.id, &self.peers, &mut LogView::new(&mut log));
        self.container = container;
        self.outcomes.clear();
        self.kinds.clear();
        self.fired.clear();
        self.bounds_proposed = false;
        self.deferred.clear();
        self.halted = None;
        self.running = Some((core, log));
    }
}

impl<C: ConsensusCore, S: ClusteredService + Clone, D: Disk + Clone> ClusterNode<C, S, D> {
    /// Time passes: the node's clock reads `now`. The core ticks, the log
    /// seals a committed tail that waited its interval, due timers and
    /// held registrations are proposed, and the node does its duty.
    pub fn tick(&mut self, now: u64, out: &mut Outbox<Delivery<C::Message>>) {
        if let Some((core, log)) = self.running.as_mut() {
            core.tick(now, &mut LogView::new(log));
            // The log's seal duty on the harness clock (karyos#1050
            // review): a committed tail waits at most its seal interval
            // unsealed. A failed seal poisons the log; the next drive
            // stops the server.
            log.set_seal_interval(self.seal_interval);
            let _ = log.tick(now);
        }
        self.propose_due(now);
        // The registrations held for the bounds go once they apply.
        if self.container.bounds_logged() && !self.deferred.is_empty() {
            for taker in std::mem::take(&mut self.deferred) {
                let envelope = Envelope::Register {
                    client: u64::from(taker.client),
                };
                self.propose(taker, envelope, Delivery::Register, out);
            }
        }
        self.duty(out);
    }

    /// `message` from `from` arrives, and the node does its duty.
    pub fn deliver(
        &mut self,
        from: NodeId,
        message: Delivery<C::Message>,
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
}
