// SPDX-License-Identifier: Apache-2.0

//! The `ClusteredService` delivery path in the harness (C10, karyos#686):
//! a [`DeliveryServer`] runs the shipped node
//! ([`karyos_cluster::node::ClusterNode`], C6) on a simulated disk, with
//! the harness's crash and restart; a [`DeliveryClient`] registers, then
//! sends its commands under its session's epoch and sequence. The node's
//! behaviour (proposing, leader following, unknown outcomes, timers and
//! configuration, session bounds) is documented with the node.
//!
//! `ServerNode` and its `TestService` stay the frozen C5 measurement
//! subject; this path runs the shipped node.

use std::path::Path;

use karyos_archive::segment::Geometry;
use karyos_cluster::LogError;
use karyos_cluster::dedup::Request;
use karyos_cluster::node::{ClusterNode, NodeError};
use karyos_cluster::service::{ClusteredService, ContainerConfig, Context};

use super::core::ConsensusCore;
use super::node::{LOG_DIR, SEAL_TICKS};
use crate::cluster::{Node, Outbox};
use crate::disk::{SimDisk, Survives};
use crate::net::NodeId;

pub use karyos_cluster::node::{Answer, Delivery, Proposer};

/// A server of the delivery path: the shipped node on a simulated disk,
/// whose crash keeps what `survives`.
pub struct DeliveryServer<C, S> {
    node: ClusterNode<C, S, SimDisk>,
    survives: Survives,
    /// What survived the last crash: the disk the restart opens.
    survived: Option<SimDisk>,
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
    #[expect(
        clippy::panic,
        reason = "a harness fixture: an unusable configuration is the test's bug"
    )]
    pub fn new(
        id: NodeId,
        peers: Vec<NodeId>,
        disk: SimDisk,
        survives: Survives,
        geometry: Geometry,
        service: S,
        config: ContainerConfig,
    ) -> Result<Self, LogError> {
        let node = match ClusterNode::new(
            id,
            peers,
            (disk, Path::new(LOG_DIR)),
            geometry,
            service,
            config,
        ) {
            Ok(node) => node,
            Err(NodeError::Log(error)) => return Err(error),
            Err(NodeError::Config(error)) => {
                panic!("a session table the harness can hold: {error:?}")
            }
        };
        Ok(Self {
            node: node.with_seal_interval(SEAL_TICKS),
            survives,
            survived: None,
            lost: None,
        })
    }

    /// As [`ClusterNode::with_configurations`].
    #[must_use]
    pub fn with_configurations(mut self, configurations: fn(&[u8]) -> bool) -> Self {
        self.node = self.node.with_configurations(configurations);
        self
    }

    /// As [`ClusterNode::with_held_registrations`].
    #[must_use]
    pub fn with_held_registrations(mut self, capacity: usize) -> Self {
        self.node = self.node.with_held_registrations(capacity);
        self
    }

    /// As [`ClusterNode::without_bounds_proposal`].
    #[must_use]
    pub fn without_bounds_proposal(mut self) -> Self {
        self.node = self.node.without_bounds_proposal();
        self
    }

    /// The shipped node it runs.
    #[must_use]
    pub fn node(&self) -> &ClusterNode<C, S, SimDisk> {
        &self.node
    }
}

impl<C: ConsensusCore, S: ClusteredService + Clone> std::ops::Deref for DeliveryServer<C, S> {
    type Target = ClusterNode<C, S, SimDisk>;

    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

impl<C: ConsensusCore, S: ClusteredService + Clone> std::ops::DerefMut for DeliveryServer<C, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.node
    }
}

impl<C: ConsensusCore, S: ClusteredService + Clone> Node<Delivery<C::Message>>
    for DeliveryServer<C, S>
{
    fn tick(&mut self, now: u64, out: &mut Outbox<Delivery<C::Message>>) {
        self.node.tick(now, out);
    }

    fn deliver(
        &mut self,
        from: NodeId,
        message: Delivery<C::Message>,
        _now: u64,
        out: &mut Outbox<Delivery<C::Message>>,
    ) {
        self.node.deliver(from, message, out);
    }

    fn crash(&mut self) {
        self.node.crash();
        match self.node.disk().after_crash(self.survives) {
            Ok(disk) => self.survived = Some(disk),
            Err(error) => self.lost = Some(error.to_string()),
        }
    }

    fn restart(&mut self, _now: u64) {
        if let Some(disk) = self.survived.take() {
            self.node.restart(disk);
        }
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
