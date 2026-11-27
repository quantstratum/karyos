// SPDX-License-Identifier: Apache-2.0

//! The shipped Cluster node (C6, quantstratum/karyos#681): a consensus core
//! behind [`ConsensusCore`] over C4's log on its own disk, driven with
//! persist then send ([`crate::driver::drive`]), feeding its committed entries to a
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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use karyos_archive::control::HoldState;
use karyos_archive::disk::Disk;
use karyos_archive::segment::Geometry;

use crate::dedup::{ConfigError, Outcome, Request};
use crate::driver::{
    Change, ConsensusCore, Detail, DriveFault, LogView, NodeId, ReadyBuf, Refused, Release,
    SnapshotBase, Step, drive_inner,
};
use crate::log::HoldSource;
use crate::service::{
    Applied, ApplyError, ClusteredService, ContainerConfig, Envelope, NotLeader, Propose,
    ProposeRefused, RestoreError, ServiceContainer, ServiceSnapshot, SessionBounds,
};
use crate::snapshot::{
    Section, SectionKind, SectionRead, SnapshotConfig, SnapshotError, SnapshotInfo, SnapshotStore,
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
    /// The snapshot store's refusal to open.
    #[error("the node's snapshot store: {0}")]
    Snapshot(#[from] SnapshotError),
    /// The container's refusal to restore the snapshot the log stands on.
    #[error("the node's snapshot restore: {0}")]
    Restore(#[from] RestoreError),
}

/// What [`ClusterNode::open`] reopens beside the log: the snapshot store
/// (its directory, policy and the service's parts, as
/// [`ClusterNode::with_snapshots`] takes them) and the Archive's hold.
#[derive(Default)]
pub struct Storage<'a> {
    /// The snapshot store, for a node that compacts.
    pub snapshots: Option<(&'a Path, SnapshotConfig, ServiceSnapshot)>,
    /// The Archive's hold on the log.
    pub hold: Option<Box<dyn HoldSource>>,
}

/// The version of the node's consensus section: the core's last applied
/// configuration entry, empty for the bootstrap configuration
/// (karyos#711).
pub const CONSENSUS_SECTION_VERSION: u64 = 1;

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
    /// The leader's latest snapshot, for a follower whose next entry its
    /// log no longer holds: the follower installs it.
    Snapshot {
        /// Its base.
        base: SnapshotBase,
        /// Its sections.
        sections: Vec<SectionRead>,
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

    /// The outcome, its reply copied into a buffer of `replies` when one
    /// is free.
    fn of(outcome: Outcome<'_>, replies: &mut Vec<Vec<u8>>) -> Self {
        let mut copied = |reply: &[u8]| {
            let mut buffer = replies.pop().unwrap_or_default();
            buffer.clear();
            buffer.extend_from_slice(reply);
            buffer
        };
        match outcome {
            Outcome::Applied(reply) => Self::Applied(copied(reply)),
            Outcome::Retained(reply) => Self::Retained(copied(reply)),
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
        self.propose_slice(&payload)
    }

    fn propose_slice(&mut self, payload: &[u8]) -> Result<(), NotLeader> {
        self.core
            .propose_slice(payload, self.log)
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

/// A node's snapshot store and its policy.
struct Snapshots<D: Disk + Clone> {
    store: SnapshotStore<D>,
    dir: PathBuf,
    config: SnapshotConfig,
    /// The service's parts, allocated once and reused.
    parts: ServiceSnapshot,
}

/// The Archive's hold as the log reads it: none without a source.
struct Hold<'a>(Option<&'a dyn HoldSource>);

impl HoldSource for Hold<'_> {
    fn hold_state(&self) -> HoldState {
        self.0.map_or(HoldState::None, HoldSource::hold_state)
    }
}

/// A Cluster node: a core over C4's log in its own directory on its own
/// disk, and a service container.
pub struct ClusterNode<C: ConsensusCore, S, D: Disk + Clone> {
    id: NodeId,
    peers: Vec<NodeId>,
    geometry: Geometry,
    disk: D,
    /// The log's directory on `disk`.
    dir: PathBuf,
    /// The longest a committed tail waits unsealed, in the node's ticks.
    seal_interval: u64,
    running: Option<(C, RaftLog<D>)>,
    /// The Ready the core fills in place, reused across duties.
    ready: ReadyBuf<C::Message>,
    /// The driver's injected fault: [`DriveFault::None`] outside tests.
    fault: DriveFault,
    /// Messages the driver released before what they wait for was
    /// durable: refused, never sent (persist then send).
    early: u64,
    /// The service as it starts, for a rebuild.
    fresh: S,
    config: ContainerConfig,
    container: ServiceContainer<S>,
    /// Requests and registrations this server took, and who it answers.
    /// Bounded by the session table: sessions times window.
    pending: Vec<(Pending, Taker)>,
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
    /// Whether it records every applied entry's kind and outcome (a
    /// harness's observation; off by default: it grows without bound).
    records: bool,
    /// The committed entries of a duty, and the pool their buffers go
    /// back to.
    committed: Vec<Entry>,
    spare: Vec<Entry>,
    /// Byte buffers for replies and commands: what the host gave back
    /// ([`ClusterNode::recycle`]) and the commands proposed.
    replies: Vec<Vec<u8>>,
    /// The envelope a proposal is encoded into.
    encoded: Vec<u8>,
    /// Its snapshot store, once it compacts.
    snapshots: Option<Snapshots<D>>,
    /// The snapshot its log stands on.
    base: Option<SnapshotBase>,
    /// The applied index the log bytes since the base were counted to,
    /// and those bytes.
    since: (u64, u64),
    /// The Archive's hold on the log (A2): a prefix purge never crosses
    /// it.
    hold: Option<Box<dyn HoldSource>>,
    /// Purges the hold refused.
    held_purges: u64,
    /// The core's last applied configuration entry (karyos#711).
    configuration: Option<Vec<u8>>,
    /// Stops right after an installed snapshot is published (tests).
    #[cfg(feature = "test-hooks")]
    stop_after_publish: bool,
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
        let mut node = Self::down(
            id,
            peers,
            (disk, dir),
            geometry,
            (service, container),
            config,
        );
        node.running = Some((core, log));
        Ok(node)
    }

    /// Server `id` of `peers` over the log in `dir` on `disk` that an
    /// earlier process left, with `service`: the snapshot store and the
    /// Archive's hold of `storage` are opened as
    /// [`ClusterNode::with_snapshots`] and [`ClusterNode::with_hold`] set
    /// them, then the node starts as a restart does, from the latest
    /// snapshot its log stands on and the entries after it.
    ///
    /// # Errors
    ///
    /// [`NodeError`]: the store, the log, the container configuration or
    /// the snapshot's restore refused.
    pub fn open(
        id: NodeId,
        peers: Vec<NodeId>,
        (disk, dir): (D, &Path),
        geometry: Geometry,
        service: S,
        config: ContainerConfig,
        storage: Storage<'_>,
    ) -> Result<Self, NodeError> {
        let container = ServiceContainer::new(service.clone(), config)?;
        let mut node = Self::down(
            id,
            peers,
            (disk, dir),
            geometry,
            (service, container),
            config,
        );
        node.hold = storage.hold;
        if let Some((snapshots, config, parts)) = storage.snapshots {
            node = node.with_snapshots(snapshots, config, parts)?;
        }
        node.start()?;
        Ok(node)
    }

    /// A node that is not running yet.
    fn down(
        id: NodeId,
        peers: Vec<NodeId>,
        (disk, dir): (D, &Path),
        geometry: Geometry,
        (service, container): (S, ServiceContainer<S>),
        config: ContainerConfig,
    ) -> Self {
        Self {
            id,
            peers,
            geometry,
            disk,
            dir: dir.to_path_buf(),
            seal_interval: DEFAULT_SEAL_INTERVAL,
            running: None,
            container,
            fresh: service,
            config,
            pending: Vec::with_capacity(
                usize::try_from(
                    u64::from(config.dedup.sessions).saturating_mul(u64::from(config.dedup.window)),
                )
                .unwrap_or(usize::MAX)
                .min(1 << 16),
            ),
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
            ready: ReadyBuf::default(),
            fault: DriveFault::None,
            early: 0,
            records: false,
            committed: Vec::new(),
            spare: Vec::new(),
            replies: Vec::new(),
            encoded: Vec::new(),
            snapshots: None,
            base: None,
            since: (0, 0),
            hold: None,
            held_purges: 0,
            configuration: None,
            #[cfg(feature = "test-hooks")]
            stop_after_publish: false,
        }
    }

    /// Stops right after an installed snapshot is published, before the
    /// log stands on it, as a crash there would (the `test-hooks`
    /// feature): the node goes down until a restart.
    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn with_stop_after_publish(mut self) -> Self {
        self.stop_after_publish = true;
        self
    }

    /// Its latest snapshot and its sections, as a leader sends it to a
    /// follower its log no longer serves.
    #[must_use]
    pub fn latest_snapshot(&self) -> Option<(SnapshotBase, Vec<SectionRead>)> {
        let snapshots = self.snapshots.as_ref()?;
        let info = snapshots.store.latest()?;
        let sections = snapshots.store.read(&info).ok()?;
        Some((
            SnapshotBase {
                index: info.index,
                term: info.term,
            },
            sections,
        ))
    }

    /// Compacts its log through a snapshot store in `dir` on its disk, at
    /// `config`'s policy: a snapshot of the container (and the core's
    /// configuration) when one is due, then a prefix purge below the
    /// policy's floor, never across the Archive's hold. `parts` holds the
    /// service's parts of each snapshot, reused.
    ///
    /// # Errors
    ///
    /// [`NodeError::Snapshot`]: the store's refusal to open.
    pub fn with_snapshots(
        mut self,
        dir: &Path,
        config: SnapshotConfig,
        parts: ServiceSnapshot,
    ) -> Result<Self, NodeError> {
        let store = SnapshotStore::open(self.disk.clone(), dir, self.geometry, config)?.store;
        self.snapshots = Some(Snapshots {
            store,
            dir: dir.to_path_buf(),
            config,
            parts,
        });
        Ok(self)
    }

    /// Records every applied entry's kind and outcome
    /// ([`ClusterNode::kinds`], [`ClusterNode::outcomes`]), for a test's
    /// observation.
    #[must_use]
    pub fn with_records(mut self) -> Self {
        self.records = true;
        self
    }

    /// Takes back a message the host is done with (sent, or encoded for
    /// the wire), so its buffers serve the next one: a node that gets its
    /// answers back allocates nothing for them once warm.
    pub fn recycle(&mut self, message: Delivery<C::Message>) {
        match message {
            Delivery::Answer {
                answer: Answer::Applied(reply) | Answer::Retained(reply),
                ..
            } => self.give_buffer(reply),
            Delivery::Relay { message, .. } | Delivery::Forward { message, .. } => {
                self.recycle(*message);
            }
            _ => {}
        }
    }

    /// Reads the Archive's hold on the log from `hold` (A2's purge floor):
    /// while it holds, or cannot be read, nothing is purged.
    #[must_use]
    pub fn with_hold(mut self, hold: Box<dyn HoldSource>) -> Self {
        self.hold = Some(hold);
        self
    }

    /// The snapshot its log stands on, if any.
    #[must_use]
    pub fn base(&self) -> Option<SnapshotBase> {
        self.base
    }

    /// Its snapshots, oldest first.
    #[must_use]
    pub fn snapshots(&self) -> &[SnapshotInfo] {
        self.snapshots
            .as_ref()
            .map_or(&[], |snapshots| snapshots.store.snapshots())
    }

    /// Its log's first index, while up.
    #[must_use]
    pub fn first_index(&self) -> Option<u64> {
        self.running.as_ref().map(|(_, log)| log.first_index())
    }

    /// Room in its log's index for `additional` more entries, so a run of
    /// that many grows nothing ([`RaftLog::reserve`]); without it the
    /// index grows by doubling, an allocation now and then.
    ///
    /// # Errors
    ///
    /// [`LogError::IndexFull`], or [`LogError::Poisoned`] for a node that
    /// is down.
    pub fn reserve(&mut self, additional: usize) -> Result<(), LogError> {
        match self.running.as_mut() {
            Some((_, log)) => log.reserve(additional),
            None => Err(LogError::Poisoned),
        }
    }

    /// The prefix purges the Archive's hold refused.
    #[must_use]
    pub fn held_purges(&self) -> u64 {
        self.held_purges
    }

    /// Seals a committed tail after at most `ticks` of the node's clock.
    #[must_use]
    pub fn with_seal_interval(mut self, ticks: u64) -> Self {
        self.seal_interval = ticks;
        self
    }

    /// Drives with `fault` injected, so a test shows the node refuses what
    /// a faulty driver releases early (the `test-hooks` feature).
    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn with_drive_fault(mut self, fault: DriveFault) -> Self {
        self.fault = fault;
        self
    }

    /// The messages refused because the driver released them before what
    /// they wait for was durable: zero for a correct driver.
    #[must_use]
    pub fn early_sends(&self) -> u64 {
        self.early
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
            .iter()
            .filter(|(key, _)| matches!(key, Pending::Request(..)))
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
        message: &Delivery<C::Message>,
        out: &mut Outbox<Delivery<C::Message>>,
    ) {
        let base = self.base;
        let Some((core, log)) = self.running.as_mut() else {
            return;
        };
        let mut view = LogView::new(log).with_base(base);
        let refused = match self.container.propose_with(
            &envelope,
            &mut Proposer::new(core, &mut view),
            &mut self.encoded,
        ) {
            Ok(()) => {
                if let Some(key) = pending_of(&envelope) {
                    match self.pending.iter_mut().find(|(held, _)| *held == key) {
                        Some(held) => held.1 = taker,
                        None => self.pending.push((key, taker)),
                    }
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
                    message: Box::new(message.clone()),
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
                self.propose(taker, envelope, &message, out);
            }
            // A client speaks for itself only.
            Delivery::Request { request, command } if request.client == u64::from(client) => {
                let envelope = Envelope::Request {
                    request: *request,
                    command,
                };
                self.propose(taker, envelope, &message, out);
            }
            _ => {}
        }
        // The command is in the log: its buffer serves the next message.
        if let Delivery::Request { command, .. } = message {
            self.give_buffer(command);
        }
    }

    /// A byte buffer from the node's pool, empty: what a transport decodes
    /// a client's command into, so the node takes it back once proposed
    /// and allocates nothing for it once warm.
    pub fn buffer(&mut self) -> Vec<u8> {
        let mut buffer = self.replies.pop().unwrap_or_default();
        buffer.clear();
        buffer
    }

    /// Keeps `buffer` for a later message, up to the pool's bound.
    fn give_buffer(&mut self, buffer: Vec<u8>) {
        if self.replies.len() < self.pending.capacity().max(64) {
            self.replies.push(buffer);
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
            for (key, taker) in self.pending.drain(..) {
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
                    self.propose(taker, envelope, &Delivery::Register, out);
                }
            }
        }
        self.led = now;
    }

    /// A leader proposes a firing for every scheduled timer due at its
    /// clock `now` that it has not proposed in its leadership. A firing
    /// its predecessor proposed too applies once (decision D6).
    fn propose_due(&mut self, now: u64) {
        let base = self.base;
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
            && self.container.propose_bounds(&mut Proposer::new(
                core,
                &mut LogView::new(log).with_base(base),
            )) == Ok(true)
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
        let mut view = LogView::new(log).with_base(base);
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
        let mut committed = std::mem::take(&mut self.committed);
        let mut spare = std::mem::take(&mut self.spare);
        let mut snapshot_to = Vec::new();
        let mut ready = std::mem::take(&mut self.ready);
        let early = &mut self.early;
        let driven = drive_inner(
            &mut core,
            &mut log,
            &mut ready,
            (None, self.base, self.fault, Detail::Lean),
            &mut |to, message, release| {
                if release.is_some_and(|release| !durable(&release)) {
                    *early = early.saturating_add(1);
                } else {
                    out.push((to, Delivery::Core(message)));
                }
            },
            &mut |entry, _| {
                let mut copy = spare.pop().unwrap_or_else(|| Entry {
                    index: 0,
                    term: 0,
                    event_time: 0,
                    payload: Vec::new(),
                });
                copy.index = entry.index;
                copy.term = entry.term;
                copy.event_time = entry.event_time;
                copy.payload.clear();
                copy.payload.extend_from_slice(&entry.payload);
                committed.push(copy);
            },
            &mut |step| {
                if let Step::SnapshotTo(to) = step {
                    snapshot_to.push(to);
                }
            },
        );
        self.ready = ready;
        // A failed persistence stops the node until a restart, as for
        // `ServerNode`; what it committed before still applies.
        let failed = driven.is_err();
        for entry in &committed {
            self.apply(entry, out);
        }
        spare.append(&mut committed);
        self.committed = committed;
        self.spare = spare;
        if !failed {
            self.compact(&mut core, &mut log);
            self.running = Some((core, log));
        }
        for to in snapshot_to {
            self.send_snapshot(to, out);
        }
        self.unknown_on_leadership_loss(out);
    }

    /// Takes a snapshot of the container when the store's policy says one
    /// is due ([`SnapshotConfig::due`]: entries or log bytes applied since
    /// the base), then purges the log below [`SnapshotConfig::log_floor`]
    /// unless the Archive holds it, and tells the core.
    fn compact(&mut self, core: &mut C, log: &mut RaftLog<D>) {
        let (Some(snapshots), Some(applied)) = (self.snapshots.as_mut(), self.container.applied())
        else {
            return;
        };
        let from = self.base.map_or(0, |base| base.index);
        let Some(entries) = applied.checked_sub(from) else {
            return;
        };
        // The log bytes since the base, counted once per entry.
        let (counted_to, mut bytes) = self.since;
        let start = counted_to.max(from);
        if start != counted_to {
            bytes = 0;
        }
        let held = log.first_index();
        for index in start.saturating_add(1)..=applied {
            match log.frame_span(index) {
                Some(span) => bytes = bytes.saturating_add(span),
                // Below the log's first index after an install.
                None if index < held => {}
                None => return,
            }
        }
        self.since = (applied, bytes);
        if !snapshots.config.due(entries, bytes) {
            return;
        }
        let Some(term) = log.term(applied) else {
            return;
        };
        let Ok(composed) = self.container.snapshot(&mut snapshots.parts) else {
            return;
        };
        let configuration = self.configuration.as_deref().unwrap_or_default();
        let mut sections = composed.sections();
        sections.push(Section::new(
            SectionKind::Consensus,
            CONSENSUS_SECTION_VERSION,
            configuration,
        ));
        if snapshots.store.write(applied, term, &sections).is_err() {
            return;
        }
        let base = SnapshotBase {
            index: applied,
            term,
        };
        self.base = Some(base);
        self.since = (applied, 0);
        // Below the oldest kept snapshot, but the allowance's bytes.
        let oldest = snapshots
            .store
            .snapshots()
            .first()
            .map_or(applied, |info| info.index);
        let first = log.first_index();
        let floor = snapshots.config.log_floor(first, oldest, |index| {
            // Where entry `index` starts, relative to the first: the
            // spans below it summed.
            (first..index).try_fold(0u64, |at, below| {
                log.frame_span(below).map(|span| at.saturating_add(span))
            })
        });
        // A2's purge floor: the Archive's hold, read right before the
        // purge, refuses it whole (C8b).
        if let Err(LogError::ArchiveHeld { .. }) =
            log.purge_prefix_under(floor, &Hold(self.hold.as_deref()))
        {
            self.held_purges = self.held_purges.saturating_add(1);
        }
        let _ = core.compacted(base, &mut LogView::new(log).with_base(Some(base)));
    }

    /// Sends `to` its latest snapshot, which its core asked for.
    fn send_snapshot(&self, to: NodeId, out: &mut Outbox<Delivery<C::Message>>) {
        if let Some((base, sections)) = self.latest_snapshot() {
            out.push((to, Delivery::Snapshot { base, sections }));
        }
    }

    /// Installs a leader's snapshot at `base`: it goes to the store, a
    /// fresh container restores it, the log starts after it, and the core
    /// is told. A node without a snapshot store, or one the snapshot does
    /// not move, keeps running unchanged; a log the install fails stops
    /// the node until a restart, which recovers from what is durable.
    fn install(&mut self, base: SnapshotBase, sections: &[SectionRead]) {
        if self.snapshots.is_none()
            || self
                .container
                .applied()
                .is_some_and(|applied| applied >= base.index)
        {
            return;
        }
        let Some((mut core, mut log)) = self.running.take() else {
            return;
        };
        if self.install_into(&mut core, &mut log, base, sections) {
            self.running = Some((core, log));
        }
    }

    /// [`ClusterNode::install`] over the node's core and log: whether the
    /// node keeps running.
    fn install_into(
        &mut self,
        core: &mut C,
        log: &mut RaftLog<D>,
        base: SnapshotBase,
        sections: &[SectionRead],
    ) -> bool {
        // A log that holds the base's entry keeps the entries after it,
        // which the leader may already count (Raft's figure 13, step 6):
        // it installs nothing, and the entries apply as they commit.
        if log.term(base.index) == Some(base.term) {
            return true;
        }
        // The core's admission before anything changes, with no other call
        // to it until the install it then reports (a leader, or a commit at
        // the base, refuses).
        if core.can_install(base).is_err() {
            return true;
        }
        // The Archive's hold before anything is published: the leader asks
        // again, and the same snapshot installs once the hold clears.
        let hold = Hold(self.hold.as_deref());
        if hold.hold_state() != HoldState::None {
            return true;
        }
        let Some(container) = ServiceContainer::new(self.fresh.clone(), self.config)
            .ok()
            .and_then(|mut container| {
                container.restore(base.index, sections).ok()?;
                Some(container)
            })
        else {
            return true;
        };
        let Some(snapshots) = self.snapshots.as_mut() else {
            return true;
        };
        // Published unless an earlier attempt published it, keeping the
        // snapshot the node stands on until the install is durable.
        let published = snapshots
            .store
            .latest()
            .is_some_and(|info| info.index == base.index && info.term == base.term);
        if !published {
            let pin = self.base.and_then(|active| {
                snapshots
                    .store
                    .snapshots()
                    .iter()
                    .find(|kept| kept.index == active.index && kept.term == active.term)
                    .map(|kept| kept.id)
            });
            if publish(&mut snapshots.store, base, sections, pin).is_err() {
                return true;
            }
        }
        #[cfg(feature = "test-hooks")]
        if self.stop_after_publish {
            return false;
        }
        match log.install_under(base.index, base.term, &snapshots.store, &hold) {
            Ok(()) => {}
            // Refused whole, changing nothing: the leader asks again.
            Err(
                LogError::ArchiveHeld { .. }
                | LogError::InstallStale { .. }
                | LogError::InstallUnverified { .. },
            ) => return true,
            // The log is poisoned: down until a restart.
            Err(_) => return false,
        }
        self.container = container;
        self.configuration = consensus_section(sections);
        self.base = Some(base);
        self.since = (base.index, 0);
        // Admitted above, so never refused; were it, the core would not
        // stand on the log, and a restart recovers both from the disk.
        core.install(
            base,
            &mut LogView::new(log)
                .with_base(Some(base))
                .with_base_time(Some(self.container.sessions().log_time()))
                .with_base_configuration(self.configuration.clone()),
        )
        .is_ok()
    }

    fn apply(&mut self, entry: &Entry, out: &mut Outbox<Delivery<C::Message>>) {
        // An entry the snapshot it stands on holds: a recovered core hands
        // out the log from its first index, which a purge keeps below the
        // latest snapshot by the allowance.
        if self.halted.is_some() || self.base.is_some_and(|base| entry.index <= base.index) {
            return;
        }
        // The core's configuration, which a snapshot carries (karyos#711).
        if C::is_configuration_entry(&entry.payload) {
            self.configuration = Some(entry.payload.clone());
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
        // An answer is built for a taker waiting here, or a record: a
        // replica that took nothing answers nothing.
        let waiting = key.and_then(|key| self.pending.iter().position(|(held, _)| *held == key));
        let answers = waiting.is_some() || self.records;
        let answer = match self.container.apply(entry) {
            Ok(Applied::Registered(registered)) => Some(match registered {
                Ok(registered) => Delivery::Registered {
                    epoch: registered.epoch,
                },
                Err(_) => Delivery::RegisterRefused,
            }),
            Ok(Applied::Answered { request, outcome }) if answers => Some(Delivery::Answer {
                request,
                answer: Answer::of(outcome, &mut self.replies),
            }),
            Ok(_) => None,
            Err(error) => {
                self.halted = Some(error);
                return;
            }
        };
        let outcome = match &answer {
            _ if !self.records => None,
            Some(Delivery::Answer { answer, .. }) => Some(answer.clone()),
            _ => None,
        };
        if self.records {
            self.outcomes.push((entry.index, outcome));
            self.kinds.push((entry.index, kind));
        }
        if let (Some(at), Some(answer)) = (waiting, answer) {
            let (_, taker) = self.pending.swap_remove(at);
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
        // A node that cannot start stays down: what failed is durable, and
        // the next restart tries again.
        let _ = self.start();
    }

    /// Opens the snapshot store and the log, restores the container from
    /// the snapshot the log stands on, recovers the core and rebuilds the
    /// container from the entries it hands out again.
    fn start(&mut self) -> Result<(), NodeError> {
        if let Some(snapshots) = self.snapshots.as_mut() {
            // A store a crash cut short reopens without what it left
            // unpublished.
            snapshots.store = SnapshotStore::open(
                self.disk.clone(),
                &snapshots.dir,
                self.geometry,
                snapshots.config,
            )?
            .store;
        }
        let store = self.snapshots.as_ref().map(|snapshots| &snapshots.store);
        let opened = RaftLog::open_with_under(
            self.disk.clone(),
            &self.dir,
            self.geometry,
            store,
            &Hold(self.hold.as_deref()),
        )?;
        let mut log = opened.log;
        let mut container = ServiceContainer::new(self.fresh.clone(), self.config)?;
        // The snapshot the log stands on: the newest its commit reaches.
        // One past the commit is an install a crash cut short.
        let commit = log.hard_state().and_then(|state| state.commit);
        let active = store.and_then(|store| {
            let info = store
                .snapshots()
                .iter()
                .rev()
                .find(|info| commit.is_some_and(|commit| info.index <= commit))
                .copied()?;
            Some((info, store.read(&info).ok()?))
        });
        let mut base = None;
        let mut configuration = None;
        if let Some((info, sections)) = active {
            container.restore(info.index, &sections)?;
            base = Some(SnapshotBase {
                index: info.index,
                term: info.term,
            });
            configuration = consensus_section(&sections);
        }
        let core = C::recover(
            self.id,
            &self.peers,
            &mut LogView::new(&mut log)
                .with_base(base)
                .with_base_time(base.map(|_| container.sessions().log_time()))
                .with_base_configuration(configuration.clone()),
        );
        self.base = base;
        self.since = (base.map_or(0, |base| base.index), 0);
        self.configuration = configuration;
        self.container = container;
        self.outcomes.clear();
        self.kinds.clear();
        self.fired.clear();
        self.bounds_proposed = false;
        self.deferred.clear();
        self.halted = None;
        self.running = Some((core, log));
        Ok(())
    }
}

impl<C: ConsensusCore, S: ClusteredService + Clone, D: Disk + Clone> ClusterNode<C, S, D> {
    /// Time passes: the node's clock reads `now`. The core ticks, the log
    /// seals a committed tail that waited its interval, due timers and
    /// held registrations are proposed, and the node does its duty.
    pub fn tick(&mut self, now: u64, out: &mut Outbox<Delivery<C::Message>>) {
        if let Some((core, log)) = self.running.as_mut() {
            core.tick(now, &mut LogView::new(log).with_base(self.base));
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
                self.propose(taker, envelope, &Delivery::Register, out);
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
        let base = self.base;
        match message {
            Delivery::Core(message) => {
                if let Some((core, log)) = self.running.as_mut() {
                    core.step(from, message, &mut LogView::new(log).with_base(base));
                }
            }
            Delivery::Snapshot { base, sections } => self.install(base, &sections),
            Delivery::Forward { client, message } => self.take(from, client, *message, out),
            Delivery::Relay { client, message } => out.push((client, *message)),
            Delivery::Change(change) => {
                if let Some((core, log)) = self.running.as_mut() {
                    let _ = core.propose_change(change, &mut LogView::new(log).with_base(base));
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

/// Whether what an `after_persist` message waits for was durable when it
/// was released: its Ready's last entry and its hard state.
fn durable(release: &Release) -> bool {
    release.needs <= release.durable
        && (release.needs_state.is_none() || release.needs_state == release.stored_state)
}

/// The core's configuration entry a snapshot's consensus section holds:
/// none when it is empty or missing (the bootstrap configuration).
/// Publishes a leader's snapshot at `base` from its `sections`, keeping
/// the kept snapshot `pin` from the purge (the one the node stands on
/// until the new one is installed). An unfinished one is abandoned.
fn publish<D: Disk + Clone>(
    store: &mut SnapshotStore<D>,
    base: SnapshotBase,
    sections: &[SectionRead],
    pin: Option<u64>,
) -> Result<SnapshotInfo, SnapshotError> {
    let mut pending = store.begin(base.index, base.term)?;
    let written = sections.iter().try_for_each(|section| {
        let length = u64::try_from(section.bytes.len()).map_err(|_| SnapshotError::Failed)?;
        pending.section(section.kind, section.version, length)?;
        pending.write(&section.bytes)
    });
    if let Err(error) = written {
        let _ = store.abandon(pending);
        return Err(error);
    }
    let sealed = store.seal(pending)?;
    store.publish_sealed(sealed, pin)
}

fn consensus_section(sections: &[SectionRead]) -> Option<Vec<u8>> {
    sections
        .iter()
        .find(|section| section.kind == SectionKind::Consensus && !section.bytes.is_empty())
        .map(|section| section.bytes.clone())
}
