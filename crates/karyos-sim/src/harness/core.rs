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
//! **The log.** Every call gets a [`LogView`], a read-only view of C4's
//! log (entries, terms, indices, the hard state), as raft-rs's `Storage`
//! and openraft's log reader would read it; only [`drive`] writes the log.

use std::fmt::Debug;
use std::ops::Range;

use karyos_cluster::{Entry, HardState, LogError, RaftLog};

use crate::disk::SimDisk;
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
/// Its reads are disk operations: they count toward [`SimDisk`]'s crash
/// budget and appear in its trace, so a budget crash can land in a core's
/// read. A core handles a read error; it does not unwrap it.
pub struct LogView<'a> {
    log: &'a mut RaftLog<SimDisk>,
}

impl<'a> LogView<'a> {
    /// A view of `log`.
    pub fn new(log: &'a mut RaftLog<SimDisk>) -> Self {
        Self { log }
    }

    /// Entries in `range`, up to `max_bytes` of frames (at least one).
    ///
    /// # Errors
    ///
    /// The log's read error.
    pub fn entries(&mut self, range: Range<u64>, max_bytes: u64) -> Result<Vec<Entry>, LogError> {
        self.log.entries(range, max_bytes)
    }

    /// The term of entry `index`, if the log holds it.
    #[must_use]
    pub fn term(&self, index: u64) -> Option<u64> {
        self.log.term(index)
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
        }
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

    /// Proposes `command` for the log.
    ///
    /// # Errors
    ///
    /// [`NotLeader`] when this core cannot take proposals.
    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), NotLeader>;

    /// `message` from `from` arrives.
    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>);

    /// Time passes: the node's clock reads `now`.
    fn tick(&mut self, now: u64, log: &mut LogView<'_>);

    /// What the node should do now, if anything.
    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>>;

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
}

/// What [`drive`] reports, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
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
pub fn drive<C: ConsensusCore>(
    core: &mut C,
    log: &mut RaftLog<SimDisk>,
    send: &mut dyn FnMut(NodeId, C::Message, Option<Release>),
    apply: &mut dyn FnMut(&Entry, Applying),
    observe: &mut dyn FnMut(Step),
) -> Result<(), DriveError> {
    let mut readies = 0usize;
    while let Some(ready) = core.ready(&mut LogView::new(log)) {
        if readies == MAX_READIES {
            return Err(DriveError::WorkBudget { readies });
        }
        // Below MAX_READIES, so it does not overflow.
        readies += 1;
        // 1. What depends on nothing.
        for (to, message) in ready.messages {
            send(to, message, None);
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
        core.advance(persisted, &mut LogView::new(log));
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
        let needs = ready.entries.last().map(|entry| entry.index);
        for (to, message) in ready.after_persist {
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
