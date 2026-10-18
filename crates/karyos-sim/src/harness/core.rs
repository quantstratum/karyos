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
//! names, and reports back with [`ConsensusCore::advance`]. [`Ready`] is
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
//! the candidate mapping table).

use std::fmt::Debug;

use karyos_cluster::{Entry, HardState, LogError, RaftLog};

use crate::disk::SimDisk;
use crate::net::NodeId;

/// What a server node read back from its log at a start or a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    /// The log's first index.
    pub first_index: u64,
    /// The stored term, vote and commit.
    pub hard_state: Option<HardState>,
    /// Every entry the log holds, in order.
    pub entries: Vec<Entry>,
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
/// product API (see the module).
pub trait ConsensusCore: Sized {
    /// Its messages between nodes.
    type Message: Clone + Debug + PartialEq;

    /// The core of node `id` among `peers` (itself included), from what
    /// its log holds: at the first start and after every restart.
    fn recover(id: NodeId, peers: &[NodeId], recovered: Recovered) -> Self;

    /// Proposes `command` for the log.
    ///
    /// # Errors
    ///
    /// [`NotLeader`] when this core cannot take proposals.
    fn propose(&mut self, command: Vec<u8>) -> Result<(), NotLeader>;

    /// `message` from `from` arrives.
    fn step(&mut self, from: NodeId, message: Self::Message);

    /// Time passes: the node's clock reads `now`.
    fn tick(&mut self, now: u64);

    /// What the node should do now, if anything.
    fn ready(&mut self) -> Option<Ready<Self::Message>>;

    /// The last [`Ready`]'s persistence is done.
    fn advance(&mut self, persisted: Persisted);

    /// The core's current term.
    fn term(&self) -> u64;

    /// Whether the core leads its term.
    fn leads(&self) -> bool;

    /// The highest index the core has received (the transport's position).
    fn received(&self) -> Option<u64>;

    /// The core's commit index.
    fn committed(&self) -> Option<u64>;
}

/// What [`drive`] reports, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A [`Ready`]'s entries and hard state are durable.
    Persisted(Persisted),
    /// Its `after_persist` messages left: `count` of them.
    Released {
        /// How many.
        count: usize,
    },
}

/// Drives `core` until it has nothing ready, in the one order the harness
/// allows for each [`Ready`]:
///
/// 1. send `messages`;
/// 2. truncate, append, `sync`, and save the hard state, on `log`;
/// 3. report the durable index to the core ([`ConsensusCore::advance`]);
/// 4. release `after_persist`;
/// 5. apply `committed`.
///
/// `send` gets every message, `apply` every committed entry, and `observe`
/// each [`Step`]. A failed persistence returns at once: nothing that
/// depends on it leaves, and the log is poisoned until it is reopened.
///
/// # Errors
///
/// The log's error at step 2.
pub fn drive<C: ConsensusCore>(
    core: &mut C,
    log: &mut RaftLog<SimDisk>,
    send: &mut dyn FnMut(NodeId, C::Message),
    apply: &mut dyn FnMut(&Entry),
    observe: &mut dyn FnMut(Step),
) -> Result<(), LogError> {
    while let Some(ready) = core.ready() {
        // 1. What depends on nothing.
        for (to, message) in ready.messages {
            send(to, message);
        }
        // 2. Persistence.
        if let Some(from) = ready.truncate_from {
            log.truncate_suffix(from)?;
        }
        if !ready.entries.is_empty() {
            let _ = log.append(&ready.entries)?;
        }
        let durable = log.sync()?;
        if let Some(state) = ready.hard_state {
            log.save_hard_state(state)?;
        }
        // 3. Reported to the core.
        let persisted = Persisted {
            durable,
            hard_state: ready.hard_state,
        };
        core.advance(persisted);
        observe(Step::Persisted(persisted));
        // 4. What depends on it.
        let count = ready.after_persist.len();
        for (to, message) in ready.after_persist {
            send(to, message);
        }
        observe(Step::Released { count });
        // 5. Application.
        for entry in &ready.committed {
            apply(entry);
        }
    }
    Ok(())
}
