// SPDX-License-Identifier: Apache-2.0

//! The consensus core a harness node drives, and the one driver that
//! orders its persistence.
//!
//! [`ConsensusCore`] is a **test-harness trait, not the product API**: it
//! lets ADR-0043's candidates (and the harness's own fixtures) run under
//! the same node, log and checks. The Cluster's consensus module (C6) may
//! expose something else.
//!
//! The trait is caller-driven, after raft-rs's `RawNode`: the node feeds
//! it proposals, messages and ticks, takes a [`Ready`], persists what it
//! names, and reports back with [`ConsensusCore::advance`]; [`drive`]
//! takes at most [`MAX_READIES`] Readys per call, the work budget of a
//! duty. [`Ready`] is
//! the harness's own type, shaped after raft-rs's split between messages
//! sendable at once and messages that depend on persistence; it holds no
//! raft-rs type.
//!
//! **openraft.** openraft persists through `RaftLogStorage::append(entries,
//! callback)` and expects its `IOFlushed` callback once the entries are
//! durable. Its adapter keeps the callback, lets [`drive`] persist the
//! entries (C4 `append`, then `sync`), and fires it when the executor
//! polls the next [`ConsensusCore::ready`] after [`ConsensusCore::advance`]
//! reported the durable index: `IOFlushed` maps to `advance(persisted)`,
//! never to a write's completion (cluster-gap-analysis.md, C4 decisions,
//! the candidate mapping table). Its `save_vote` maps to a [`Ready`]
//! carrying the vote in `hard_state` and the vote's reply in
//! `after_persist`, so the reply waits for the vote to be durable. Its
//! apply completes when [`drive`] has applied a Ready's `committed`: the
//! next [`ConsensusCore::ready`] call implies it.
//!
//! **Membership** (phase 5, ADR-0054; quantstratum-docs:
//! karyos/design/phase-5-cluster-scenarios.md, H1). A core that changes
//! its membership reports its [`Configuration`] and takes [`Change`]s
//! through two provided methods; their defaults describe static
//! membership, so a phase 4 core implements neither. The harness never
//! decodes a configuration entry: it asks the core.
//!
//! **The log.** Every call gets a [`LogView`], a read-only view of C4's
//! log (entries, terms, indices, the hard state), as raft-rs's `Storage`
//! and openraft's log reader would read it; only [`drive`] writes the log.
//!
//! **Limits** (W2; karyos#687). A core started with
//! [`ConsensusCore::recover_with`] is given the declared [`Limits`] and
//! refuses what passes them with a typed [`Refused::Backpressure`], never
//! by dropping it. The log-read limit is the harness's to enforce: a
//! metered [`LogView`] answers [`ReadError::Budget`] once a duty has read
//! its bytes. A core that takes no limits answers [`Unsupported`], the
//! default, and the harness reports its W2 cases as not demonstrated,
//! never as passed.

use std::cell::Cell;
use std::fmt::Debug;
use std::ops::Range;
use std::rc::Rc;

use karyos_archive::disk::Disk;
use karyos_cluster::{Entry, HardState, LogError, RaftLog};

use crate::net::NodeId;

/// A core's read-only view of its node's C4 log: what is written, what is
/// durable, and the stored hard state. Only [`drive`] writes the log.
///
/// It is borrowed for each call: an adapter whose library owns its storage
/// (raft-rs's `RawNode`, openraft's log reader) copies what it needs. The
/// C5 adapters give the core an owned read-only handle over a shared log
/// instead (`Rc<RefCell<RaftLog>>`; the simulation is single-threaded),
/// which [`drive`] borrows mutably only between core calls.
///
/// Its reads are disk operations: they count toward [`SimDisk`](crate::disk::SimDisk)'s crash
/// budget and appear in its trace, so a budget crash can land in a core's
/// read. A core handles a read error; it does not unwrap it.
pub struct LogView<'a> {
    log: &'a mut dyn LogSource,
    /// The duty's read budget, when the log-read limit applies.
    budget: Option<&'a ReadBudget>,
    /// The latest snapshot the node holds, if any (W5).
    base: Option<SnapshotBase>,
}

/// What a [`LogView`] reads: C4's log over any disk, so the same core runs
/// over the simulator's disk and over real files (an adapter's real
/// processes; karyos#956 review).
trait LogSource {
    fn entries(&mut self, range: Range<u64>, max_bytes: u64) -> Result<Vec<Entry>, LogError>;
    fn frame_span(&self, index: u64) -> Option<u64>;
    fn term(&self, index: u64) -> Option<u64>;
    fn first_index(&self) -> u64;
    fn last_index(&self) -> Option<u64>;
    fn durable_index(&self) -> Option<u64>;
    fn hard_state(&self) -> Option<HardState>;
}

impl<D: Disk + Clone> LogSource for RaftLog<D> {
    fn entries(&mut self, range: Range<u64>, max_bytes: u64) -> Result<Vec<Entry>, LogError> {
        RaftLog::entries(self, range, max_bytes)
    }

    fn frame_span(&self, index: u64) -> Option<u64> {
        RaftLog::frame_span(self, index)
    }

    fn term(&self, index: u64) -> Option<u64> {
        RaftLog::term(self, index)
    }

    fn first_index(&self) -> u64 {
        RaftLog::first_index(self)
    }

    fn last_index(&self) -> Option<u64> {
        RaftLog::last_index(self)
    }

    fn durable_index(&self) -> Option<u64> {
        RaftLog::durable_index(self)
    }

    fn hard_state(&self) -> Option<HardState> {
        RaftLog::hard_state(self)
    }
}

/// A snapshot's base: the last log index it includes and that entry's
/// term (W5; karyos#687).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotBase {
    /// The last index it includes.
    pub index: u64,
    /// That entry's term.
    pub term: u64,
}

/// Why a core refused to hand its leadership over (W5's leader change;
/// karyos#687).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferRefused {
    /// The core cannot hand its leadership over: W5's retries across a
    /// leader change are not demonstrated for it.
    Unsupported,
    /// It does not lead.
    NotLeader(NotLeader),
    /// The target is not a voter, or is itself.
    Invalid,
    /// The target is behind the leader's log by `behind` entries.
    Lagging {
        /// Entries it is behind.
        behind: u64,
    },
}

/// Why a core refused to install a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallRefused {
    /// The core does not take snapshots: its W5 snapshot cases are not
    /// demonstrated.
    Unsupported,
    /// It already holds the snapshot's base or more.
    Stale,
}

/// A duty's log-read budget (W2's log-read limit): the log bytes a core
/// may still read through its [`LogView`]s this duty, counted in whole
/// frames as the log lays them out ([`RaftLog::frame_span`]).
#[derive(Debug, Clone, Default)]
pub struct ReadBudget {
    /// Bytes left this duty.
    left: Rc<Cell<u64>>,
}

impl ReadBudget {
    /// A budget refilled to `bytes` at each [`ReadBudget::refill`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A new duty: `bytes` to read.
    pub fn refill(&self, bytes: u64) {
        self.left.set(bytes);
    }

    /// Bytes left this duty.
    #[must_use]
    pub fn left(&self) -> u64 {
        self.left.get()
    }
}

/// Why a [`LogView`] read gave no entries.
#[derive(Debug)]
pub enum ReadError {
    /// The log's read error.
    Log(LogError),
    /// The duty's read budget is spent (W2's log-read limit): the read is
    /// refused, never blocked; the next duty reads again.
    Budget,
}

impl From<LogError> for ReadError {
    fn from(error: LogError) -> Self {
        Self::Log(error)
    }
}

impl<'a> LogView<'a> {
    /// A view of `log`, unmetered.
    pub fn new<D: Disk + Clone + 'a>(log: &'a mut RaftLog<D>) -> Self {
        Self {
            log,
            budget: None,
            base: None,
        }
    }

    /// A view of `log` whose reads spend `budget`.
    pub fn metered<D: Disk + Clone + 'a>(
        log: &'a mut RaftLog<D>,
        budget: Option<&'a ReadBudget>,
    ) -> Self {
        Self {
            log,
            budget,
            base: None,
        }
    }

    /// Entries in `range`, up to `max_bytes` of frames (at least one).
    /// Metered, it takes only the frames that fit in the duty's budget
    /// left, sized from the log's index before anything is read
    /// ([`RaftLog::frame_span`]), and spends their bytes before reading,
    /// so a read that fails part-way is charged too: a duty never reads
    /// past its budget, and a refused read reads nothing (karyos#899
    /// review, codex). An empty range reads and spends nothing.
    ///
    /// # Errors
    ///
    /// [`ReadError::Budget`] when not one frame fits in the budget left,
    /// and the log's read error.
    pub fn entries(&mut self, range: Range<u64>, max_bytes: u64) -> Result<Vec<Entry>, ReadError> {
        let Some(budget) = self.budget else {
            return Ok(self.log.entries(range, max_bytes)?);
        };
        // An empty range asks for nothing: no read, no charge.
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let left = budget.left();
        let (mut end, mut spent) = (range.start, 0u64);
        while end < range.end {
            let Some(next) = self
                .log
                .frame_span(end)
                .and_then(|span| spent.checked_add(span))
                .filter(|next| *next <= left && (end == range.start || *next <= max_bytes))
            else {
                break;
            };
            spent = next;
            end = end.checked_add(1).ok_or(ReadError::Budget)?;
        }
        if end == range.start {
            // Nothing fits, or the log holds nothing there: a log that
            // holds the entry refuses it for the budget, unread.
            if self.log.frame_span(range.start).is_some() {
                return Err(ReadError::Budget);
            }
            return Ok(Vec::new());
        }
        // Charged before the read: a read that fails part-way still
        // examined those bytes, and its retries stay within the budget
        // (ADR-0008; karyos#899 review).
        budget
            .left
            .set(left.checked_sub(spent).ok_or(ReadError::Budget)?);
        Ok(self.log.entries(range.start..end, u64::MAX)?)
    }

    /// It, with `base` as the node's latest snapshot.
    #[must_use]
    pub fn with_base(mut self, base: Option<SnapshotBase>) -> Self {
        self.base = base;
        self
    }

    /// The node's latest snapshot, if any: the log holds no entry at or
    /// below its index that a core may need, and that entry's term is the
    /// base's.
    #[must_use]
    pub fn base(&self) -> Option<SnapshotBase> {
        self.base
    }

    /// The term of entry `index`, if the log holds it, or the snapshot's
    /// base names it.
    #[must_use]
    pub fn term(&self, index: u64) -> Option<u64> {
        self.log.term(index).or_else(|| {
            self.base
                .filter(|base| base.index == index)
                .map(|base| base.term)
        })
    }

    /// The first index.
    #[must_use]
    pub fn first_index(&self) -> u64 {
        self.log.first_index()
    }

    /// The last index written.
    #[must_use]
    pub fn last_index(&self) -> Option<u64> {
        self.log.last_index()
    }

    /// The durable last index.
    #[must_use]
    pub fn durable_index(&self) -> Option<u64> {
        self.log.durable_index()
    }

    /// The stored term, vote and commit.
    #[must_use]
    pub fn hard_state(&self) -> Option<HardState> {
        self.log.hard_state()
    }
}

/// A proposal refused: this core does not lead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotLeader {
    /// The leader it knows of, if any.
    pub leader: Option<NodeId>,
}

/// The limits a core is declared (W2; quantstratum-docs:
/// karyos/evaluations/c5-raft-comparison-v1.md, Workloads and bounds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Entries sent to one follower and not acknowledged, at most.
    pub in_flight_entries: u64,
    /// Payload bytes sent to one follower and not acknowledged, at most.
    pub in_flight_bytes: u64,
    /// Client requests a server holds, proposed and not committed, at most.
    pub queue: u64,
    /// Log bytes a server reads per duty, in whole frames, at most (the
    /// harness enforces it: [`ReadBudget`]). A frame larger than this is
    /// never read, so a case whose entries do not fit is refused before it
    /// runs ([`super::workloads::RunError::Unreadable`]).
    pub log_read_bytes: u64,
}

impl Limits {
    /// The manifest's W2 limits: 64 entries or 1 MiB in flight per
    /// follower, a queue of 1024 per server, 1 MiB read per duty.
    pub const W2: Self = Self {
        in_flight_entries: 64,
        in_flight_bytes: 1024 * 1024,
        queue: 1024,
        log_read_bytes: 1024 * 1024,
    };
}

/// Which limit a refusal names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// [`Limits::in_flight_entries`].
    InFlightEntries,
    /// [`Limits::in_flight_bytes`].
    InFlightBytes,
    /// [`Limits::queue`].
    Queue,
    /// [`Limits::log_read_bytes`].
    LogRead,
}

/// Why a core refused a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// It does not lead.
    NotLeader(NotLeader),
    /// Taking it would pass a declared limit: typed, so the client knows
    /// to retry, and nothing is dropped silently.
    Backpressure(Limit),
}

impl From<NotLeader> for Refused {
    fn from(not_leader: NotLeader) -> Self {
        Self::NotLeader(not_leader)
    }
}

/// A capability the core does not have: the harness reports what needs
/// it as not demonstrated, never as passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsupported;

/// What a core asks its node to do, in [`drive`]'s order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready<M> {
    /// Messages sendable at once, before anything below is persisted.
    pub messages: Vec<(NodeId, M)>,
    /// Remove entry `index` and every later one, before appending.
    pub truncate_from: Option<u64>,
    /// Entries to append and make durable.
    pub entries: Vec<Entry>,
    /// A term, vote and commit to save durably.
    pub hard_state: Option<HardState>,
    /// Messages released only once everything above is durable.
    pub after_persist: Vec<(NodeId, M)>,
    /// Committed entries to apply, in order.
    pub committed: Vec<Entry>,
    /// Followers to send the node's latest snapshot to: they need entries
    /// the log no longer holds (W5).
    pub snapshot_to: Vec<NodeId>,
}

impl<M> Default for Ready<M> {
    fn default() -> Self {
        Self {
            messages: Vec::new(),
            truncate_from: None,
            entries: Vec::new(),
            hard_state: None,
            after_persist: Vec::new(),
            committed: Vec::new(),
            snapshot_to: Vec::new(),
        }
    }
}

/// A [`Ready`] the node keeps across calls, for the borrowed form
/// [`ConsensusCore::ready_into`] (plan issue 073, karyos#691): its vectors
/// keep their capacity, and the entries [`drive`] is done with go back to a
/// pool, so a core that fills it in place hands its work over without
/// allocating once the buffers have grown.
#[derive(Debug)]
pub struct ReadyBuf<M> {
    /// The Ready being filled; empty after [`ReadyBuf::recycle`].
    pub ready: Ready<M>,
    /// Entries [`drive`] is done with, their payload buffers kept.
    spare: Vec<Entry>,
}

impl<M> Default for ReadyBuf<M> {
    fn default() -> Self {
        Self {
            ready: Ready::default(),
            spare: Vec::new(),
        }
    }
}

impl<M> ReadyBuf<M> {
    /// An entry with these fields, its payload copied into a buffer from
    /// the pool when one is free: no allocation once the pool holds an
    /// entry whose buffer is large enough.
    #[must_use]
    pub fn entry(&mut self, index: u64, term: u64, event_time: u64, payload: &[u8]) -> Entry {
        let mut entry = self.spare.pop().unwrap_or(Entry {
            index,
            term,
            event_time,
            payload: Vec::new(),
        });
        entry.index = index;
        entry.term = term;
        entry.event_time = event_time;
        entry.payload.clear();
        entry.payload.extend_from_slice(payload);
        entry
    }

    /// Moves the pool's entries to `into`, for a core that converts its
    /// entries before [`ConsensusCore::ready_into`] runs and keeps a pool of
    /// its own.
    pub fn take_spare(&mut self, into: &mut Vec<Entry>) {
        into.append(&mut self.spare);
    }

    /// Drops the pool: for a core that never draws from it.
    pub fn release_spare(&mut self) {
        self.spare = Vec::new();
    }

    /// Empties the Ready, keeping every vector's capacity and returning its
    /// entries to the pool.
    pub fn recycle(&mut self) {
        let ready = &mut self.ready;
        ready.messages.clear();
        ready.truncate_from = None;
        ready.hard_state = None;
        ready.after_persist.clear();
        ready.snapshot_to.clear();
        self.spare.append(&mut ready.entries);
        self.spare.append(&mut ready.committed);
    }

    /// Whether the Ready asks for nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let ready = &self.ready;
        ready.messages.is_empty()
            && ready.truncate_from.is_none()
            && ready.entries.is_empty()
            && ready.hard_state.is_none()
            && ready.after_persist.is_empty()
            && ready.committed.is_empty()
            && ready.snapshot_to.is_empty()
    }
}

/// What a [`Ready`]'s persistence made durable, reported to the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Persisted {
    /// The log's durable last index after the sync.
    pub durable: Option<u64>,
    /// The hard state saved, if one was.
    pub hard_state: Option<HardState>,
}

/// A consensus core under the harness: a test-harness trait, not the
/// product API (see the module). Every call gets a read-only view of the
/// node's log; the core keeps only what is not written yet.
pub trait ConsensusCore: Sized {
    /// Its messages between nodes.
    type Message: Clone + Debug + PartialEq;

    /// The core of node `id` among `peers` (itself included), over what
    /// its log holds: at the first start and after every restart.
    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self;

    /// [`ConsensusCore::recover`] under declared `limits` (W2), which the
    /// core honours: it refuses with [`Refused::Backpressure`] what would
    /// pass them.
    ///
    /// # Errors
    ///
    /// [`Unsupported`], the default, for a core that takes no limits: it
    /// is never started without them, so its W2 cases are not
    /// demonstrated.
    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        let _ = (id, peers, limits, log);
        Err(Unsupported)
    }

    /// Proposes `command` for the log.
    ///
    /// # Errors
    ///
    /// [`Refused`]: the core does not lead, or the proposal would pass a
    /// declared limit.
    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused>;

    /// [`ConsensusCore::propose`], borrowing `command` (plan issue 073,
    /// karyos#691): the node keeps its buffer, so a core that copies only
    /// what it keeps is not charged for the node's. The default copies it
    /// into an owned command.
    ///
    /// # Errors
    ///
    /// As [`ConsensusCore::propose`].
    fn propose_slice(&mut self, command: &[u8], log: &mut LogView<'_>) -> Result<(), Refused> {
        self.propose(command.to_vec(), log)
    }

    /// `message` from `from` arrives.
    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>);

    /// Time passes: the node's clock reads `now`.
    fn tick(&mut self, now: u64, log: &mut LogView<'_>);

    /// What the node should do now, if anything.
    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>>;

    /// [`ConsensusCore::ready`], filled into the node's `out`, which
    /// [`drive`] hands over empty ([`ReadyBuf::recycle`]) (plan issue 073,
    /// karyos#691): whether the core had anything ready. A core that fills
    /// `out` in place, its entries through [`ReadyBuf::entry`], allocates
    /// nothing for the Ready itself once the buffers have grown. The
    /// default moves [`ConsensusCore::ready`]'s Ready into it and releases
    /// the pool, which a core that does not draw from it never empties.
    fn ready_into(&mut self, out: &mut ReadyBuf<Self::Message>, log: &mut LogView<'_>) -> bool {
        out.release_spare();
        match self.ready(log) {
            Some(ready) => {
                out.ready = ready;
                true
            }
            None => false,
        }
    }

    /// The last [`Ready`]'s persistence is done.
    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>);

    /// The core's current term.
    fn term(&self) -> u64;

    /// Whether the core leads its term.
    fn leads(&self) -> bool;

    /// The highest index the core holds, written or not (the harness's
    /// received position).
    fn received(&self) -> Option<u64>;

    /// The core's commit index.
    fn committed(&self) -> Option<u64>;

    /// The configuration the core acts under, for a core that changes its
    /// membership (phase 5, ADR-0054); `None`, the default, for one with
    /// static membership.
    fn configuration(&self) -> Option<Configuration> {
        None
    }

    /// The node compacted its log below a snapshot at `base`: entries at
    /// or below it may no longer be in the log (W5).
    ///
    /// # Errors
    ///
    /// [`Unsupported`], the default, for a core that takes no snapshots:
    /// the harness never compacts under it, and its W5 snapshot cases are
    /// not demonstrated.
    fn compacted(&mut self, base: SnapshotBase, log: &mut LogView<'_>) -> Result<(), Unsupported> {
        let _ = (base, log);
        Err(Unsupported)
    }

    /// The node installed a leader's snapshot at `base`: its service holds
    /// the state up to `base.index`, and its log starts after it (W5).
    ///
    /// # Errors
    ///
    /// [`InstallRefused::Unsupported`], the default, for a core that takes
    /// no snapshots; [`InstallRefused::Stale`] when it already holds
    /// `base` or more.
    fn install(&mut self, base: SnapshotBase, log: &mut LogView<'_>) -> Result<(), InstallRefused> {
        let _ = (base, log);
        Err(InstallRefused::Unsupported)
    }

    /// Hands the leadership over to `to`, which leads the next term once
    /// it holds the whole log (W5's leader change).
    ///
    /// # Errors
    ///
    /// [`TransferRefused::Unsupported`], the default, for a core that
    /// cannot: its W5 retry cases are not demonstrated; otherwise why it
    /// refused.
    fn transfer_leadership(
        &mut self,
        to: NodeId,
        log: &mut LogView<'_>,
    ) -> Result<(), TransferRefused> {
        let _ = (to, log);
        Err(TransferRefused::Unsupported)
    }

    /// Proposes one membership change.
    ///
    /// # Errors
    ///
    /// [`ChangeRefused`]; [`ChangeRefused::Unsupported`], the default, for
    /// a core with static membership.
    fn propose_change(
        &mut self,
        change: Change,
        log: &mut LogView<'_>,
    ) -> Result<(), ChangeRefused> {
        let _ = (change, log);
        Err(ChangeRefused::Unsupported)
    }
}

/// The membership a core acts under: the latest configuration in its log,
/// committed or not (Raft's rule), or the bootstrap one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    /// The index of the entry that set it; `None` for the bootstrap
    /// configuration, the `peers` given to [`ConsensusCore::recover`].
    pub index: Option<u64>,
    /// The voting members, ascending.
    pub voters: Vec<NodeId>,
    /// Under joint consensus, the outgoing voters while a change runs: a
    /// commit needs a majority of both sets. Empty otherwise.
    pub outgoing: Vec<NodeId>,
    /// The non-voting members, ascending: they replicate the log and never
    /// count toward a quorum.
    pub learners: Vec<NodeId>,
}

/// One membership change (ADR-0054: a new member joins as a learner and is
/// promoted once it has caught up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Adds a non-voting member.
    AddLearner(NodeId),
    /// Makes a learner a voter.
    Promote(NodeId),
    /// Removes a member.
    Remove(NodeId),
}

/// Why a core refused a membership change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeRefused {
    /// The core does not lead.
    NotLeader(NotLeader),
    /// An earlier change is not committed yet, or the leader has not yet
    /// committed an entry of its term (the single-server errata).
    InProgress,
    /// The learner is further behind the leader's commit than the core's
    /// promotion lag.
    Lagging {
        /// Entries it is behind.
        behind: u64,
    },
    /// The change does not apply to the current configuration: adding a
    /// member, promoting a voter, removing a stranger, or a change the
    /// core cannot make.
    Invalid,
    /// The core's membership is static.
    Unsupported,
}

/// What [`drive`] reports, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A [`Ready`] asks for the node's latest snapshot to be sent to a
    /// follower ([`Ready::snapshot_to`]), before anything else of it.
    SnapshotTo(NodeId),
    /// A [`Ready`]'s truncation, entries and hard state are durable.
    Persisted {
        /// What the core was told.
        persisted: Persisted,
        /// The first index removed, if the Ready truncated.
        truncated_from: Option<u64>,
        /// The entries appended: index and term.
        appended: Vec<(u64, u64)>,
    },
}

/// What an `after_persist` message depends on, and what the log held when
/// it was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Release {
    /// The last index its Ready appended.
    pub needs: Option<u64>,
    /// The hard state its Ready saved.
    pub needs_state: Option<HardState>,
    /// The log's durable last index at the send.
    pub durable: Option<u64>,
    /// The log's stored hard state at the send.
    pub stored_state: Option<HardState>,
}

/// What the log held when an entry was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applying {
    /// The log's durable last index.
    pub durable: Option<u64>,
    /// The term of the log's entry at that index, if it holds one.
    pub logged_term: Option<u64>,
}

/// The [`Ready`]s one [`drive`] call takes at most: a core that is always
/// ready breaks the work budget of a duty instead of hanging the run.
pub const MAX_READIES: usize = 64;

/// Why [`drive`] stopped.
#[derive(Debug)]
pub enum DriveError {
    /// The log refused a write or failed.
    Log(LogError),
    /// The core was still ready after [`MAX_READIES`] Readys.
    WorkBudget {
        /// The Readys taken.
        readies: usize,
    },
}

impl From<LogError> for DriveError {
    fn from(error: LogError) -> Self {
        Self::Log(error)
    }
}

/// Drives `core` until it has nothing ready, in the one order the harness
/// allows for each [`Ready`]:
///
/// 1. send `messages`;
/// 2. truncate, append and `sync` when the Ready writes entries, and save
///    the hard state, on `log`;
/// 3. report the durable index to the core ([`ConsensusCore::advance`]);
/// 4. release `after_persist`;
/// 5. apply `committed`.
///
/// `send` gets every message, with the [`Release`] it waited for when it
/// is an `after_persist` one; `apply` gets every committed entry, with
/// what the log held then ([`Applying`]); and
/// `observe` each [`Step`]. A failed persistence returns at once: nothing
/// that depends on it leaves, and the log is poisoned until it is
/// reopened.
///
/// # Errors
///
/// [`DriveError::Log`] for the log's error at step 2, and
/// [`DriveError::WorkBudget`] after [`MAX_READIES`] Readys.
pub fn drive<C: ConsensusCore, D: Disk + Clone>(
    core: &mut C,
    log: &mut RaftLog<D>,
    send: &mut dyn FnMut(NodeId, C::Message, Option<Release>),
    apply: &mut dyn FnMut(&Entry, Applying),
    observe: &mut dyn FnMut(Step),
) -> Result<(), DriveError> {
    drive_metered(core, log, (None, None), send, apply, observe)
}

/// A fault injected into the driver (the `test-hooks` feature), so the harness checks can be
/// shown to catch what a faulty driver or disk would do with a real core
/// behind it (karyos#1038). Tests only: every production path drives with
/// [`DriveFault::None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DriveFault {
    /// None: the five steps in order.
    #[default]
    None,
    /// Messages that wait for persistence leave before it (step 4 before
    /// step 2).
    #[cfg(feature = "test-hooks")]
    ReleaseEarly,
    /// A Ready's fresh entries are applied before they are written, as a
    /// driver that took them for committed would.
    #[cfg(feature = "test-hooks")]
    ApplyFresh,
}

/// [`drive`], the core's reads spending `budget` when one is given, and
/// its views naming `base` as the node's latest snapshot.
///
/// # Errors
///
/// As [`drive`].
pub fn drive_metered<C: ConsensusCore, D: Disk + Clone>(
    core: &mut C,
    log: &mut RaftLog<D>,
    (budget, base): (Option<&ReadBudget>, Option<SnapshotBase>),
    send: &mut dyn FnMut(NodeId, C::Message, Option<Release>),
    apply: &mut dyn FnMut(&Entry, Applying),
    observe: &mut dyn FnMut(Step),
) -> Result<(), DriveError> {
    drive_inner(
        core,
        log,
        &mut ReadyBuf::default(),
        (budget, base, DriveFault::None),
        send,
        apply,
        observe,
    )
}

/// [`drive_metered`] through the borrowed form [`ConsensusCore::ready_into`]
/// and the node's `buf`, which it leaves empty (plan issue 073,
/// karyos#691).
///
/// # Errors
///
/// As [`drive`].
pub fn drive_into<C: ConsensusCore, D: Disk + Clone>(
    core: &mut C,
    log: &mut RaftLog<D>,
    buf: &mut ReadyBuf<C::Message>,
    (budget, base): (Option<&ReadBudget>, Option<SnapshotBase>),
    send: &mut dyn FnMut(NodeId, C::Message, Option<Release>),
    apply: &mut dyn FnMut(&Entry, Applying),
    observe: &mut dyn FnMut(Step),
) -> Result<(), DriveError> {
    drive_inner(
        core,
        log,
        buf,
        (budget, base, DriveFault::None),
        send,
        apply,
        observe,
    )
}

/// [`drive_metered`]'s steps, with `fault` injected; only
/// [`DriveFault::None`] exists without the `test-hooks` feature
/// (karyos#1038).
pub(crate) fn drive_inner<C: ConsensusCore, D: Disk + Clone>(
    core: &mut C,
    log: &mut RaftLog<D>,
    buf: &mut ReadyBuf<C::Message>,
    (budget, base, fault): (Option<&ReadBudget>, Option<SnapshotBase>, DriveFault),
    send: &mut dyn FnMut(NodeId, C::Message, Option<Release>),
    apply: &mut dyn FnMut(&Entry, Applying),
    observe: &mut dyn FnMut(Step),
) -> Result<(), DriveError> {
    let mut readies = 0usize;
    buf.recycle();
    while core.ready_into(buf, &mut LogView::metered(log, budget).with_base(base)) {
        if readies == MAX_READIES {
            buf.recycle();
            return Err(DriveError::WorkBudget { readies });
        }
        // Below MAX_READIES, so it does not overflow.
        readies += 1;
        let result = take(
            core,
            log,
            buf,
            (budget, base, fault),
            (send, apply, observe),
        );
        buf.recycle();
        result?;
    }
    Ok(())
}

/// What [`drive`] does with one Ready, in its order; the Ready's vectors
/// are drained, not moved, so they keep their capacity.
#[allow(clippy::type_complexity)]
fn take<C: ConsensusCore, D: Disk + Clone>(
    core: &mut C,
    log: &mut RaftLog<D>,
    buf: &mut ReadyBuf<C::Message>,
    (budget, base, fault): (Option<&ReadBudget>, Option<SnapshotBase>, DriveFault),
    (send, apply, observe): (
        &mut dyn FnMut(NodeId, C::Message, Option<Release>),
        &mut dyn FnMut(&Entry, Applying),
        &mut dyn FnMut(Step),
    ),
) -> Result<(), DriveError> {
    let ready = &mut buf.ready;
    {
        // 1. What depends on nothing.
        for to in ready.snapshot_to.drain(..) {
            observe(Step::SnapshotTo(to));
        }
        for (to, message) in ready.messages.drain(..) {
            send(to, message, None);
        }
        let needs = ready.entries.last().map(|entry| entry.index);
        // Faults that act before persistence (tests).
        #[cfg(not(feature = "test-hooks"))]
        let DriveFault::None = fault;
        #[cfg(feature = "test-hooks")]
        match fault {
            DriveFault::ReleaseEarly => {
                for (to, message) in ready.after_persist.drain(..) {
                    let release = Release {
                        needs,
                        needs_state: ready.hard_state,
                        durable: log.durable_index(),
                        stored_state: log.hard_state(),
                    };
                    send(to, message, Some(release));
                }
            }
            DriveFault::ApplyFresh => {
                for entry in &ready.entries {
                    let applying = Applying {
                        durable: log.durable_index(),
                        logged_term: log.term(entry.index),
                    };
                    apply(entry, applying);
                }
            }
            DriveFault::None => {}
        }
        // 2. Persistence.
        if let Some(from) = ready.truncate_from {
            log.truncate_suffix(from)?;
        }
        let durable = if ready.entries.is_empty() && ready.truncate_from.is_none() {
            log.durable_index()
        } else {
            if !ready.entries.is_empty() {
                let _ = log.append(&ready.entries)?;
            }
            log.sync()?
        };
        if let Some(state) = ready.hard_state {
            log.save_hard_state(state)?;
        }
        // 3. Reported to the core.
        let persisted = Persisted {
            durable,
            hard_state: ready.hard_state,
        };
        core.advance(
            persisted,
            &mut LogView::metered(log, budget).with_base(base),
        );
        observe(Step::Persisted {
            persisted,
            truncated_from: ready.truncate_from,
            appended: ready
                .entries
                .iter()
                .map(|entry| (entry.index, entry.term))
                .collect(),
        });
        // 4. What depends on it.
        for (to, message) in ready.after_persist.drain(..) {
            let release = Release {
                needs,
                needs_state: ready.hard_state,
                durable: log.durable_index(),
                stored_state: log.hard_state(),
            };
            send(to, message, Some(release));
        }
        // 5. Application.
        for entry in &ready.committed {
            let applying = Applying {
                durable: log.durable_index(),
                logged_term: log.term(entry.index),
            };
            apply(entry, applying);
        }
    }
    Ok(())
}
