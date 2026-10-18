// SPDX-License-Identifier: Apache-2.0

//! The nodes a harness run is made of, over C1's [`ClusterSim`]: servers,
//! each a [`ConsensusCore`] over C4's log on its own simulated disk with
//! the deterministic test service, and scripted clients. They share one
//! wire type and report to one [`Recorder`].
//!
//! - **The test service** (ADR-0043, Workloads) is an append-only
//!   register: `Append(bytes)` adds a value, `Read` returns them all. It
//!   deduplicates a client's retried sequence number, keeps a state
//!   digest, and answers in canonical response bytes.
//! - **A crash** drops the server's core and log and keeps the disk C2's
//!   [`SimDisk::after_crash`] gives under the node's survival mode. **A
//!   restart** reopens the log and rebuilds the core from it
//!   ([`ConsensusCore::recover`]); a refused open is recorded as an
//!   [`Observation::OpenFailed`], and the node stays down.
//!
//! [`ClusterSim`]: crate::cluster::ClusterSim

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;

use karyos_archive::segment::Geometry;
use karyos_cluster::{Entry, RaftLog};

use super::core::{ConsensusCore, Recovered, Step, drive};
use crate::cluster::{Node, Outbox};
use crate::disk::{SimDisk, Survives};
use crate::lin::{self, History};
use crate::net::NodeId;

/// The directory of a server's log on its disk.
pub const LOG_DIR: &str = "/raft";

/// A client's operation on the test service.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Op {
    /// Appends a value.
    Append(Vec<u8>),
    /// Reads every value.
    Read,
}

/// What the test service answers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ret {
    /// The register's length after the append.
    Appended(u64),
    /// Every value, in order.
    Values(Vec<Vec<u8>>),
}

impl Ret {
    /// The canonical response bytes: a tag, then the length or the values,
    /// each length-prefixed, little endian.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::Appended(length) => {
                bytes.push(0);
                bytes.extend_from_slice(&length.to_le_bytes());
            }
            Self::Values(values) => {
                bytes.push(1);
                for value in values {
                    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
                    bytes.extend_from_slice(&length.to_le_bytes());
                    bytes.extend_from_slice(value);
                }
            }
        }
        bytes
    }
}

/// A client's request: who, which of its operations, and what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The client.
    pub client: NodeId,
    /// Its sequence number, from 1; a retry repeats it.
    pub sequence: u64,
    /// The operation.
    pub op: Op,
}

impl Command {
    /// Its bytes in the log: client, sequence, a tag, then the value.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.client.to_le_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        match &self.op {
            Op::Append(value) => {
                bytes.push(0);
                bytes.extend_from_slice(value);
            }
            Op::Read => bytes.push(1),
        }
        bytes
    }

    /// The command in a log entry's payload, if it is one.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (client, rest) = bytes.split_first_chunk::<4>()?;
        let (sequence, rest) = rest.split_first_chunk::<8>()?;
        let (tag, value) = rest.split_first()?;
        let op = match tag {
            0 => Op::Append(value.to_vec()),
            1 if value.is_empty() => Op::Read,
            _ => return None,
        };
        Some(Self {
            client: u32::from_le_bytes(*client),
            sequence: u64::from_le_bytes(*sequence),
            op,
        })
    }
}

/// The deterministic test service: an append-only register.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestService {
    values: Vec<Vec<u8>>,
    /// Per client, its last sequence applied and its answer.
    answered: BTreeMap<NodeId, (u64, Ret)>,
    applied: Option<u64>,
}

impl TestService {
    /// Applies the committed `entry`; returns the command and its answer,
    /// the earlier answer for a retried sequence. An entry that holds no
    /// command (a core's own entry) answers nothing.
    pub fn apply(&mut self, entry: &Entry) -> Option<(Command, Ret)> {
        self.applied = Some(entry.index);
        let command = Command::decode(&entry.payload)?;
        if let Some((sequence, ret)) = self.answered.get(&command.client)
            && *sequence == command.sequence
        {
            return Some((command, ret.clone()));
        }
        let ret = match &command.op {
            Op::Append(value) => {
                self.values.push(value.clone());
                Ret::Appended(u64::try_from(self.values.len()).unwrap_or(u64::MAX))
            }
            Op::Read => Ret::Values(self.values.clone()),
        };
        let _ = self
            .answered
            .insert(command.client, (command.sequence, ret.clone()));
        Some((command, ret))
    }

    /// The last index applied.
    #[must_use]
    pub fn applied(&self) -> Option<u64> {
        self.applied
    }

    /// A digest of the state: FNV-1a over the values (its multiplication
    /// wraps by the hash's definition).
    #[must_use]
    pub fn digest(&self) -> u64 {
        let mut digest = 0xCBF2_9CE4_8422_2325u64;
        for value in &self.values {
            for byte in value.iter().chain(&[0xFF]) {
                digest ^= u64::from(*byte);
                digest = digest.wrapping_mul(0x0000_0100_0000_01B3);
            }
        }
        digest
    }
}

/// The test service as C3's sequential model.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServiceModel;

impl lin::Model for ServiceModel {
    type State = Vec<Vec<u8>>;
    type Op = Op;
    type Ret = Ret;

    fn init(&self) -> Self::State {
        Vec::new()
    }

    fn step(&self, state: &Self::State, op: &Op) -> (Self::State, Ret) {
        match op {
            Op::Append(value) => {
                let mut next = state.clone();
                next.push(value.clone());
                let length = u64::try_from(next.len()).unwrap_or(u64::MAX);
                (next, Ret::Appended(length))
            }
            Op::Read => (state.clone(), Ret::Values(state.clone())),
        }
    }
}

/// What a node reports, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// A server's [`drive`] step.
    Drive {
        /// The server.
        node: NodeId,
        /// The step.
        step: Step,
    },
    /// A server's commit index moved.
    Commit {
        /// The server.
        node: NodeId,
        /// Its term then.
        term: u64,
        /// Whether it led then.
        leader: bool,
        /// The new commit index.
        index: u64,
        /// The term of the entry at it.
        entry_term: u64,
    },
    /// A server applied an entry.
    Applied {
        /// The server.
        node: NodeId,
        /// The entry.
        entry: Entry,
    },
    /// A client got a successful answer to the command at `index`.
    Success {
        /// The client.
        client: NodeId,
        /// The entry's index.
        index: u64,
    },
    /// A server's positions after a duty.
    Positions {
        /// The server.
        node: NodeId,
        /// Its positions.
        positions: Positions,
    },
    /// A server's log refused to open at a restart, or its persistence
    /// failed.
    OpenFailed {
        /// The server.
        node: NodeId,
        /// The error.
        error: String,
    },
}

/// A server's five positions (SPEC §9), as indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Positions {
    /// The highest index the core received.
    pub received: Option<u64>,
    /// The log's last index written.
    pub written: Option<u64>,
    /// The log's durable last index.
    pub durable: Option<u64>,
    /// The core's commit index.
    pub committed: Option<u64>,
    /// The service's last applied index.
    pub applied: Option<u64>,
}

/// Everything a run's nodes report: the observations, in order, and the
/// clients' history for C3.
#[derive(Debug, Default)]
pub struct Recorder {
    /// Every observation, in order.
    pub observations: Vec<Observation>,
    /// The clients' invocations and returns, in real-time order.
    pub history: History<Op, Ret>,
}

/// A recorder the nodes of one run share.
pub type Shared = Rc<RefCell<Recorder>>;

/// The one message type of a harness run.
#[derive(Debug, Clone, PartialEq)]
pub enum Wire<M> {
    /// Between cores.
    Core(M),
    /// A client's request.
    Request(Command),
    /// A server's answer: `ret` for the command at `index`.
    Response {
        /// The client's sequence number.
        sequence: u64,
        /// The answer.
        ret: Ret,
        /// The entry's index.
        index: u64,
    },
    /// A server cannot take the request.
    Refused {
        /// The client's sequence number.
        sequence: u64,
    },
}

/// A server: a core over C4's log on its own disk, and the test service.
pub struct ServerNode<C: ConsensusCore> {
    id: NodeId,
    peers: Vec<NodeId>,
    geometry: Geometry,
    disk: SimDisk,
    survives: Survives,
    running: Option<(C, RaftLog<SimDisk>)>,
    service: TestService,
    /// Requests this server took, by client and sequence: it answers them.
    pending: BTreeMap<(NodeId, u64), ()>,
    commit: Option<u64>,
    recorder: Shared,
}

impl<C: ConsensusCore> ServerNode<C> {
    /// Server `id` of `peers`, with a new log on `disk`; a crash keeps what
    /// `survives`.
    ///
    /// # Errors
    ///
    /// The log's refusal to be created.
    pub fn new(
        id: NodeId,
        peers: Vec<NodeId>,
        disk: SimDisk,
        survives: Survives,
        geometry: Geometry,
        recorder: Shared,
    ) -> Result<Self, karyos_cluster::LogError> {
        let log = RaftLog::create(disk.clone(), Path::new(LOG_DIR), geometry, 1)?;
        let core = C::recover(
            id,
            &peers,
            Recovered {
                first_index: 1,
                hard_state: None,
                entries: Vec::new(),
            },
        );
        Ok(Self {
            id,
            peers,
            geometry,
            disk,
            survives,
            running: Some((core, log)),
            service: TestService::default(),
            pending: BTreeMap::new(),
            commit: None,
            recorder,
        })
    }

    /// Whether it is up: its log open and its core running.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.running.is_some()
    }

    /// The core, while up.
    #[must_use]
    pub fn core(&self) -> Option<&C> {
        self.running.as_ref().map(|(core, _)| core)
    }

    /// The test service.
    #[must_use]
    pub fn service(&self) -> &TestService {
        &self.service
    }

    fn observe(&self, observation: Observation) {
        self.recorder.borrow_mut().observations.push(observation);
    }

    /// Drives the core, then records its commit and positions.
    fn duty(&mut self, out: &mut Outbox<Wire<C::Message>>) {
        let Some((mut core, mut log)) = self.running.take() else {
            return;
        };
        let mut steps = Vec::new();
        let mut applied = Vec::new();
        let driven = drive(
            &mut core,
            &mut log,
            &mut |to, message| out.push((to, Wire::Core(message))),
            &mut |entry| applied.push(entry.clone()),
            &mut |step| steps.push(step),
        );
        for step in steps {
            self.observe(Observation::Drive {
                node: self.id,
                step,
            });
        }
        if let Err(error) = driven {
            // Poisoned: the node stops until a restart reopens the log.
            self.observe(Observation::OpenFailed {
                node: self.id,
                error: error.to_string(),
            });
            return;
        }
        for entry in applied {
            if let Some((command, ret)) = self.service.apply(&entry)
                && self
                    .pending
                    .remove(&(command.client, command.sequence))
                    .is_some()
            {
                out.push((
                    command.client,
                    Wire::Response {
                        sequence: command.sequence,
                        ret,
                        index: entry.index,
                    },
                ));
            }
            self.observe(Observation::Applied {
                node: self.id,
                entry,
            });
        }
        let committed = core.committed();
        if committed > self.commit
            && let Some(index) = committed
        {
            let entry_term = log
                .term(index)
                .or_else(|| (index == 0).then_some(0))
                .unwrap_or(0);
            self.observe(Observation::Commit {
                node: self.id,
                term: core.term(),
                leader: core.leads(),
                index,
                entry_term,
            });
            self.commit = committed;
        }
        self.observe(Observation::Positions {
            node: self.id,
            positions: Positions {
                received: core.received(),
                written: log.last_index(),
                durable: log.durable_index(),
                committed,
                applied: self.service.applied(),
            },
        });
        self.running = Some((core, log));
    }
}

impl<C: ConsensusCore> Node<Wire<C::Message>> for ServerNode<C> {
    fn tick(&mut self, now: u64, out: &mut Outbox<Wire<C::Message>>) {
        if let Some((core, _)) = self.running.as_mut() {
            core.tick(now);
        }
        self.duty(out);
    }

    fn deliver(
        &mut self,
        from: NodeId,
        message: Wire<C::Message>,
        _now: u64,
        out: &mut Outbox<Wire<C::Message>>,
    ) {
        let Some((core, _)) = self.running.as_mut() else {
            return;
        };
        match message {
            Wire::Core(message) => core.step(from, message),
            Wire::Request(command) => {
                let key = (command.client, command.sequence);
                match core.propose(command.encode()) {
                    Ok(()) => {
                        let _ = self.pending.insert(key, ());
                    }
                    Err(_) => out.push((
                        command.client,
                        Wire::Refused {
                            sequence: command.sequence,
                        },
                    )),
                }
            }
            Wire::Response { .. } | Wire::Refused { .. } => {}
        }
        self.duty(out);
    }

    fn crash(&mut self) {
        self.running = None;
        self.pending.clear();
        match self.disk.after_crash(self.survives) {
            Ok(disk) => self.disk = disk,
            Err(error) => self.observe(Observation::OpenFailed {
                node: self.id,
                error: error.to_string(),
            }),
        }
    }

    fn restart(&mut self, _now: u64) {
        let opened = RaftLog::open(self.disk.clone(), Path::new(LOG_DIR), self.geometry);
        let mut log = match opened {
            Ok(opened) => opened.log,
            Err(error) => {
                self.observe(Observation::OpenFailed {
                    node: self.id,
                    error: error.to_string(),
                });
                return;
            }
        };
        let first_index = log.first_index();
        let entries = match log.last_index().and_then(|last| last.checked_add(1)) {
            Some(end) => match log.entries(first_index..end, u64::MAX) {
                Ok(entries) => entries,
                Err(error) => {
                    self.observe(Observation::OpenFailed {
                        node: self.id,
                        error: error.to_string(),
                    });
                    return;
                }
            },
            None => Vec::new(),
        };
        let core = C::recover(
            self.id,
            &self.peers,
            Recovered {
                first_index,
                hard_state: log.hard_state(),
                entries,
            },
        );
        // The service's state is rebuilt from the log as the core
        // commits again.
        self.service = TestService::default();
        self.commit = None;
        self.running = Some((core, log));
    }
}

/// A scripted client: each step, it sends its next request to its server
/// once the last one was answered.
#[derive(Debug, Clone)]
pub struct ClientNode {
    id: NodeId,
    server: NodeId,
    script: Vec<Op>,
    next: usize,
    open: Option<u64>,
    recorder: Shared,
}

impl ClientNode {
    /// Client `id`, sending `script` to `server` in order.
    #[must_use]
    pub fn new(id: NodeId, server: NodeId, script: Vec<Op>, recorder: Shared) -> Self {
        Self {
            id,
            server,
            script,
            next: 0,
            open: None,
            recorder,
        }
    }

    /// Whether every request of its script was answered.
    #[must_use]
    pub fn done(&self) -> bool {
        self.open.is_none() && self.next == self.script.len()
    }
}

impl<M> Node<Wire<M>> for ClientNode {
    fn tick(&mut self, _now: u64, out: &mut Outbox<Wire<M>>) {
        if self.open.is_some() {
            return;
        }
        let Some(op) = self.script.get(self.next).cloned() else {
            return;
        };
        let Some(sequence) = u64::try_from(self.next)
            .ok()
            .and_then(|next| next.checked_add(1))
        else {
            return;
        };
        // `next` indexes the script, so it is below `usize::MAX`.
        self.next += 1;
        self.open = Some(sequence);
        let _ = self
            .recorder
            .borrow_mut()
            .history
            .invoke(self.id, op.clone());
        out.push((
            self.server,
            Wire::Request(Command {
                client: self.id,
                sequence,
                op,
            }),
        ));
    }

    fn deliver(&mut self, _from: NodeId, message: Wire<M>, _now: u64, _out: &mut Outbox<Wire<M>>) {
        if let Wire::Response {
            sequence,
            ret,
            index,
        } = message
            && self.open == Some(sequence)
        {
            self.open = None;
            let mut recorder = self.recorder.borrow_mut();
            let _ = recorder.history.ret(self.id, ret);
            recorder.observations.push(Observation::Success {
                client: self.id,
                index,
            });
        }
    }
}

/// A member of a harness run: a server or a client, over one wire.
pub enum Member<C: ConsensusCore> {
    /// A server.
    Server(Box<ServerNode<C>>),
    /// A client.
    Client(ClientNode),
}

impl<C: ConsensusCore> Member<C> {
    /// The server, if it is one.
    #[must_use]
    pub fn server(&self) -> Option<&ServerNode<C>> {
        match self {
            Self::Server(server) => Some(server),
            Self::Client(_) => None,
        }
    }

    /// The client, if it is one.
    #[must_use]
    pub fn client(&self) -> Option<&ClientNode> {
        match self {
            Self::Client(client) => Some(client),
            Self::Server(_) => None,
        }
    }
}

impl<C: ConsensusCore> Node<Wire<C::Message>> for Member<C> {
    fn tick(&mut self, now: u64, out: &mut Outbox<Wire<C::Message>>) {
        match self {
            Self::Server(server) => server.tick(now, out),
            Self::Client(client) => client.tick(now, out),
        }
    }

    fn deliver(
        &mut self,
        from: NodeId,
        message: Wire<C::Message>,
        now: u64,
        out: &mut Outbox<Wire<C::Message>>,
    ) {
        match self {
            Self::Server(server) => server.deliver(from, message, now, out),
            Self::Client(client) => client.deliver(from, message, now, out),
        }
    }

    fn crash(&mut self) {
        match self {
            Self::Server(server) => server.crash(),
            Self::Client(client) => Node::<Wire<C::Message>>::crash(client),
        }
    }

    fn restart(&mut self, now: u64) {
        match self {
            Self::Server(server) => server.restart(now),
            Self::Client(client) => Node::<Wire<C::Message>>::restart(client, now),
        }
    }
}
