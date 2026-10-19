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
//! - **A log error** in [`drive`] stops the node until a restart. One the
//!   core caused by breaking C4's contract (an append that is not next, a
//!   term or commit going back, a truncation below the commit) is an
//!   [`Observation::Contract`], which the checks report as a violation;
//!   one of the disk is an [`Observation::OpenFailed`].
//! - **Positions** are indices, not the byte positions of SPEC.md §9:
//!   received is the core's last index, written or not; written and
//!   durable are the log's; committed is the core's; applied is the
//!   service's.
//!
//! [`ClusterSim`]: crate::cluster::ClusterSim

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::rc::Rc;

use karyos_archive::segment::Geometry;
use karyos_cluster::{Entry, LogError, RaftLog};

use super::core::{ConsensusCore, DriveError, LogView, Release, Step, drive};
use crate::cluster::{Node, Outbox};
use crate::disk::{SimDisk, Survives};
use crate::lin::{self, History};
use crate::net::NodeId;

/// The tag every command's bytes start with, so a core's own entries do
/// not decode as commands.
pub const COMMAND_MAGIC: [u8; 4] = *b"KC5\x01";

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
    /// Its bytes in the log: [`COMMAND_MAGIC`], client, sequence, a tag,
    /// then the value.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = COMMAND_MAGIC.to_vec();
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
        let rest = bytes.strip_prefix(&COMMAND_MAGIC)?;
        let (client, rest) = rest.split_first_chunk::<4>()?;
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
    /// A server sent a message that waited for persistence.
    Released {
        /// The server.
        node: NodeId,
        /// The receiver.
        to: NodeId,
        /// What it waited for, and what the log held at the send.
        release: Release,
    },
    /// A server released its reply to the client's command at `index`.
    Reply {
        /// The server.
        node: NodeId,
        /// The client.
        client: NodeId,
        /// The entry's index.
        index: u64,
        /// The entry's term.
        term: u64,
    },
    /// A server crashed: its positions are gone until its restart.
    Crashed {
        /// The server.
        node: NodeId,
    },
    /// A server's restart reopened its log.
    Recovered {
        /// The server.
        node: NodeId,
        /// Every entry the log holds: index and term.
        entries: Vec<(u64, u64)>,
        /// The log's durable last index.
        durable: Option<u64>,
    },
    /// A server's core broke C4's contract: the log refused its write.
    Contract {
        /// The server.
        node: NodeId,
        /// What it broke.
        breach: Breach,
        /// The log's error.
        error: String,
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
    /// A server's log refused to open at a restart, or its disk failed:
    /// the environment, not the core.
    OpenFailed {
        /// The server.
        node: NodeId,
        /// The error.
        error: String,
    },
}

/// What a core broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breach {
    /// An append that is not the next index.
    NotNext,
    /// An entry's term below the last.
    TermBack,
    /// An entry too large for the log.
    TooLarge,
    /// A read or truncation outside the log.
    OutOfRange,
    /// A prefix purge.
    PurgeUnsupported,
    /// A truncation that would remove committed entries.
    TruncateBelowCommit,
    /// A hard state the log refuses.
    HardState,
    /// A commit above the durable last index.
    CommitBeyondDurable,
    /// A commit going back.
    CommitBack,
    /// Still ready after [`super::core::MAX_READIES`] Readys.
    WorkBudget,
}

impl Breach {
    /// The breach `error` is, or `None` for the environment's error.
    #[must_use]
    pub fn of(error: &LogError) -> Option<Self> {
        Some(match error {
            LogError::NotNext { .. } => Self::NotNext,
            LogError::TermBack { .. } => Self::TermBack,
            LogError::TooLarge { .. } => Self::TooLarge,
            LogError::OutOfRange { .. } => Self::OutOfRange,
            LogError::PurgeUnsupported => Self::PurgeUnsupported,
            LogError::TruncateBelowCommit { .. } => Self::TruncateBelowCommit,
            LogError::HardState(_) => Self::HardState,
            LogError::CommitBeyondDurable { .. } => Self::CommitBeyondDurable,
            LogError::CommitBack { .. } => Self::CommitBack,
            _ => return None,
        })
    }
}

/// A server's five positions (after SPEC.md §9), as indices (see the
/// module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Positions {
    /// The core's last index, written or not.
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
    pending: BTreeSet<(NodeId, u64)>,
    commit: Option<u64>,
    /// Why the disk cannot come back, when its crash could not be taken.
    lost: Option<String>,
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
    ) -> Result<Self, LogError> {
        let mut log = RaftLog::create(disk.clone(), Path::new(LOG_DIR), geometry, 1)?;
        let core = C::recover(id, &peers, &mut LogView::new(&mut log));
        let commit = core.committed();
        Ok(Self {
            id,
            peers,
            geometry,
            disk,
            survives,
            running: Some((core, log)),
            service: TestService::default(),
            pending: BTreeSet::new(),
            commit,
            lost: None,
            recorder,
        })
    }

    /// Server `id` of `peers` over the log already on `disk`, started as
    /// a restart would; it is down if the log does not open.
    #[must_use]
    pub fn open(
        id: NodeId,
        peers: Vec<NodeId>,
        disk: SimDisk,
        survives: Survives,
        geometry: Geometry,
        recorder: Shared,
    ) -> Self {
        let mut server = Self {
            id,
            peers,
            geometry,
            disk,
            survives,
            running: None,
            service: TestService::default(),
            pending: BTreeSet::new(),
            commit: None,
            lost: None,
            recorder,
        };
        server.start();
        server
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
        let node = self.id;
        let recorder = Rc::clone(&self.recorder);
        let mut applied = Vec::new();
        let driven = drive(
            &mut core,
            &mut log,
            &mut |to, message, release| {
                if let Some(release) = release {
                    recorder
                        .borrow_mut()
                        .observations
                        .push(Observation::Released { node, to, release });
                }
                out.push((to, Wire::Core(message)));
            },
            &mut |entry| applied.push(entry.clone()),
            &mut |step| {
                recorder
                    .borrow_mut()
                    .observations
                    .push(Observation::Drive { node, step });
            },
        );
        if let Err(error) = driven {
            // The node stops until a restart reopens the log.
            let observation = match &error {
                DriveError::Log(error) => match Breach::of(error) {
                    Some(breach) => Observation::Contract {
                        node,
                        breach,
                        error: error.to_string(),
                    },
                    None => Observation::OpenFailed {
                        node,
                        error: error.to_string(),
                    },
                },
                DriveError::WorkBudget { readies } => Observation::Contract {
                    node,
                    breach: Breach::WorkBudget,
                    error: format!("still ready after {readies} Readys"),
                },
            };
            self.observe(observation);
            return;
        }
        for entry in applied {
            if let Some((command, ret)) = self.service.apply(&entry)
                && self.pending.remove(&(command.client, command.sequence))
            {
                self.observe(Observation::Reply {
                    node,
                    client: command.client,
                    index: entry.index,
                    term: entry.term,
                });
                out.push((
                    command.client,
                    Wire::Response {
                        sequence: command.sequence,
                        ret,
                        index: entry.index,
                    },
                ));
            }
            self.observe(Observation::Applied { node, entry });
        }
        let committed = core.committed();
        if committed > self.commit
            && let Some(index) = committed
        {
            self.observe(Observation::Commit {
                node,
                term: core.term(),
                leader: core.leads(),
                index,
                entry_term: log.term(index).unwrap_or(0),
            });
            self.commit = committed;
        }
        self.positions(&core, &log);
        self.running = Some((core, log));
    }

    fn positions(&self, core: &C, log: &RaftLog<SimDisk>) {
        self.observe(Observation::Positions {
            node: self.id,
            positions: Positions {
                received: core.received(),
                written: log.last_index(),
                durable: log.durable_index(),
                committed: core.committed(),
                applied: self.service.applied(),
            },
        });
    }

    /// Opens the log and recovers the core from it.
    fn start(&mut self) {
        if let Some(error) = self.lost.clone() {
            self.observe(Observation::OpenFailed {
                node: self.id,
                error,
            });
            return;
        }
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
        let first = log.first_index();
        let entries: Vec<(u64, u64)> = log
            .last_index()
            .map(|last| {
                (first..=last)
                    .filter_map(|index| log.term(index).map(|term| (index, term)))
                    .collect()
            })
            .unwrap_or_default();
        self.observe(Observation::Recovered {
            node: self.id,
            entries,
            durable: log.durable_index(),
        });
        let core = C::recover(self.id, &self.peers, &mut LogView::new(&mut log));
        // The service's state is rebuilt from the log as the core hands
        // out its committed entries again; the recovered commit is a
        // baseline, not a new commit.
        self.service = TestService::default();
        self.commit = core.committed();
        self.positions(&core, &log);
        self.running = Some((core, log));
    }
}

impl<C: ConsensusCore> Node<Wire<C::Message>> for ServerNode<C> {
    fn tick(&mut self, now: u64, out: &mut Outbox<Wire<C::Message>>) {
        if let Some((core, log)) = self.running.as_mut() {
            core.tick(now, &mut LogView::new(log));
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
        let Some((core, log)) = self.running.as_mut() else {
            return;
        };
        let mut view = LogView::new(log);
        match message {
            Wire::Core(message) => core.step(from, message, &mut view),
            Wire::Request(command) => {
                let key = (command.client, command.sequence);
                match core.propose(command.encode(), &mut view) {
                    Ok(()) => {
                        let _ = self.pending.insert(key);
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
        self.observe(Observation::Crashed { node: self.id });
        match self.disk.after_crash(self.survives) {
            Ok(disk) => self.disk = disk,
            // The pre-crash disk is no state to restart from: the node
            // stays down, and its restart reports why.
            Err(error) => self.lost = Some(error.to_string()),
        }
    }

    fn restart(&mut self, _now: u64) {
        self.start();
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
