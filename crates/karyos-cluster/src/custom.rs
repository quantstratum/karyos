// SPDX-License-Identifier: Apache-2.0

//! The custom Raft core (ADR-0105) behind [`ConsensusCore`]: parts (d)
//! and (e) of quantstratum/karyos#681.
//!
//! [`crate::consensus`] is the core: a pure [`Core`] that reads the log
//! through [`LogTerms`] and acts through [`Effects`]. This module puts it
//! behind [`ConsensusCore`], the interface [`crate::driver`] drives with
//! persist then send. The shipped node runs it, and `karyos-sim`'s harness
//! re-exports it (`karyos_sim::harness::custom`), so the evaluation and the
//! shipped path run one adapter and one state machine.
//!
//! **Mapping.**
//!
//! - Node ids: the harness numbers servers from 0, the core's voter ids
//!   start at 1, so core id = node id + 1. The hard state stores node ids.
//! - The log view: the core sees the node's written log, minus a pending
//!   truncation, plus the entries not yet handed to
//!   [`drive`](crate::driver::drive) (proposals, a new leader's no-op, a
//!   follower's received suffix). An entry's size is its payload's, which
//!   W2's in-flight byte cap bounds; its read cost is its frame's
//!   (`RaftLog::frame_span`), which the harness's metered log charges a
//!   duty, and nothing for an entry not yet written, which no read
//!   touches.
//! - Effects: [`Effects::persist`] and [`Effects::commit`] become the
//!   Ready's hard state; [`Effects::write`] truncates and takes the
//!   stepped append's entries; [`Effects::append`] adds the no-op;
//!   [`Effects::send`] goes in `messages` and
//!   [`Effects::send_after_persist`] in `after_persist`, which
//!   [`drive`](crate::driver::drive) releases once the Ready is durable
//!   (persist then send); [`Effects::send_snapshot`] goes in
//!   `snapshot_to`.
//! - Appends: the core sends positions and counts. Each append is filled
//!   with its entries as soon as the core emits it, from the same view
//!   the core read: the pending entries, or C4's log through the duty's
//!   metered [`LogView`]. An append whose entries the budget refuses is
//!   not sent, as if the network lost it, and the core's window recovers
//!   it as it recovers a loss (a heartbeat's rejection rewinds it).
//! - Committed entries are handed to apply in order, each once, as many
//!   per Ready as the duty's read budget covers; the rest follow in the
//!   next. After a restart they are applied again from the log's start,
//!   as the node rebuilds its state.
//! - Limits: [`Limits`] map to the core's: `log_read_bytes` is
//!   [`CoreLimits::read_bytes`], charged in frame bytes, and a proposal
//!   whose frame is larger is refused with [`Limit::LogRead`]; the core's
//!   lookup count is unbounded here (the harness has no such limit).
//!   Every entry of a harness log is admitted by `propose` under the same
//!   limits or is a new leader's empty no-op, so the core's send-alone
//!   exception for an entry larger than the byte window never applies.
//! - Time: the first tick sets the clock's baseline; each later tick runs
//!   the core once per unit of time passed, at most
//!   [`MAX_TICKS_PER_CALL`] per call, and the rest in the next calls.
//!   Its entries, proposals and a new leader's no-op alike, are stamped
//!   with [`crate::stamp`]: the latest reading clamped to the
//!   log's watermark (contract C-TIME, ADR-0111), which is the last
//!   entry's event time; after a restart, the largest event time of the
//!   recovered log's entries and the snapshot's log time.
//!
//! **Buffers.** Entries and their vectors come from one pool per thread,
//! shared by every node the simulation runs on it: what a follower is
//! done with (a message's entries, a Ready's recycled ones) goes back to
//! it, and a leader's next append takes from it. It stands for a
//! transport that hands a sent buffer back, so after the warm-up nothing
//! on the replication path allocates (ADR-0105, decision 3). The pool is
//! bounded, and prefilled once, from the declared limits ([`Bounds`]).
//!
//! **Snapshots** (W5, #682): the node's compactions go to
//! [`Core::compacted`]; a leader's [`Effects::send_snapshot`] asks the
//! node to send its latest snapshot (`Ready::snapshot_to`); a follower's
//! install is reported to [`Core::install`] once the node has written the
//! snapshot and restarted its log after the base, and a restart over a
//! snapshot recovers with [`Core::with_snapshot`]. Committed entries are
//! handed out from the log's first index after a restart, and from the
//! base after an install: below them the snapshot holds the state. A
//! refused install (the core holds the base or more, or leads) is
//! [`InstallRefused::Stale`].
//!
//! **Membership** (karyos#711): the core's single-server changes.
//! [`ConsensusCore::propose_change`] maps to [`Core::propose_change`],
//! whose configuration entry ([`MembershipEntry`]) the leader writes like
//! any proposal; a follower reports each configuration entry it receives
//! to [`Core::configured`] as its write takes it, and a restart replays
//! those its log holds, over the configuration its snapshot recorded
//! ([`LogView::base_configuration`], given back by
//! [`Core::restore_membership`], as after an install). A server that is
//! not a bootstrap voter starts as a joining one ([`Config::joining`]). A
//! promotion is refused while the learner is more than
//! [`PROMOTION_LAG`] entries behind the commit.
//!
//! **Not taken:** leadership transfer answers
//! [`TransferRefused::Unsupported`](crate::driver::TransferRefused::Unsupported); C5 version 2's W5 retry changes the
//! leader by a crash, which needs no handover.

use std::cell::RefCell;

use crate::consensus::{
    Backpressure, ChangeError, Config, Core, Effects, Limits as CoreLimits, LogTerms,
    Message as CoreMessage, ProposeError, Role, TermVote,
};
use crate::membership::{MEMBERSHIP, Membership, MembershipChange, MembershipEntry};
use crate::{Entry, HardState, stamp};

use crate::driver::{
    Change, ChangeRefused, Configuration, ConsensusCore, InstallRefused, Limit, Limits, LogView,
    NodeId, NotLeader, Persisted, Ready, ReadyBuf, Refused, SnapshotBase, Unsupported,
};

/// The shortest election timeout, in ticks: the C5 manifest's timing
/// (version 1, kept by version 2), one harness step per tick.
pub const ELECTION_MIN: u32 = 15;
/// The election timeouts are drawn uniformly from
/// `ELECTION_MIN..ELECTION_MAX`, again at every reset, from the core's
/// seeded source.
pub const ELECTION_MAX: u32 = 30;
/// Entries a learner may be behind the leader's commit and be promoted:
/// the harness's promotion lag, the reference's.
pub const PROMOTION_LAG: u64 = 4;
/// Ticks between a leader's heartbeats.
pub const HEARTBEAT: u32 = 5;
/// Entries per append at most: W1's primary batch limit.
pub const BATCH: u64 = 16;
/// Ticks one [`ConsensusCore::tick`] call runs at most.
pub const MAX_TICKS_PER_CALL: u64 = 64;
/// The bytes C4's log reads at once at most (`RaftLog`'s read window).
pub const READ_WINDOW: usize = 1 << 20;
/// Messages one Ready holds, at once and after persistence, before its
/// vectors grow: reserved when the core starts. Unlike the entries, no
/// declared limit bounds them; the tests check no run passes it.
pub const READY_MESSAGES: usize = 256;
/// The limits the adapter takes as its own when the harness declares
/// none (W1): the manifest's W2 limits, which no W1 case reaches (its
/// tests check it), so that every buffer the replication path uses has a
/// bound to be preallocated from.
pub const DEFAULT_LIMITS: Limits = Limits::W2;
/// The most bytes of entry buffers a thread's pool preallocates; a
/// configuration whose bound passes it is refused ([`Unsupported`]).
pub const MAX_POOL_BYTES: usize = 256 * 1024 * 1024;

/// What the replication path holds at once, from the declared limits
/// (`limits`) and the voters: the sizes the adapter reserves, so nothing
/// on that path allocates after initialisation (ADR-0105, decision 3).
///
/// - A Ready's new entries: a leader's uncommitted ones, at most
///   `queue` and its no-op, or a follower's received ones, at most
///   `in_flight_entries`.
/// - A Ready's committed entries: at most `in_flight_entries` (the rest
///   follow in the next).
/// - Entries out of the pool at once: for the leader, its pending entries,
///   one Ready's committed ones and the previous Ready's, returned
///   through the node (2 (queue + 1) + 2 in_flight_entries); for each
///   follower, the same with in_flight_entries pending (4
///   in_flight_entries); and in the network, each follower's in-flight
///   window ((voters - 1) in_flight_entries).
/// - Each entry's payload capacity: `in_flight_bytes /
///   in_flight_entries`, the most a full window's entries hold on average.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// New entries in one Ready.
    pub ready_entries: usize,
    /// Committed entries in one Ready.
    pub committed: usize,
    /// Entries out of the thread's pool at once.
    pub pool_entries: usize,
    /// Payload bytes each pooled entry is preallocated with.
    pub payload: usize,
    /// Entry vectors in flight at once: one per append in a window.
    pub vectors: usize,
}

impl Bounds {
    /// The bounds of `limits` over `voters` servers; `None` when one does
    /// not fit a `usize` or the pool would pass [`MAX_POOL_BYTES`].
    #[must_use]
    pub fn of(limits: &Limits, voters: usize) -> Option<Self> {
        let window = usize::try_from(limits.in_flight_entries).ok()?.max(1);
        let queue = usize::try_from(limits.queue).ok()?;
        let followers = voters.checked_sub(1)?;
        let leader = queue
            .checked_add(1)?
            .checked_mul(2)?
            .checked_add(window.checked_mul(2)?)?;
        let pool_entries = leader.checked_add(followers.checked_mul(window)?.checked_mul(5)?)?;
        let payload =
            usize::try_from(limits.in_flight_bytes / limits.in_flight_entries.max(1)).ok()?;
        if pool_entries.checked_mul(payload)? > MAX_POOL_BYTES {
            return None;
        }
        Some(Self {
            ready_entries: queue.checked_add(1)?.checked_add(window)?,
            committed: window,
            pool_entries,
            payload,
            vectors: followers.checked_mul(window)?.checked_add(voters)?,
        })
    }
}

/// What a thread's pool and the adapters on it have shown, for the tests
/// and the run record ([`pool_stats`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Entries preallocated.
    pub prefilled: usize,
    /// Entries ever made, preallocated or not: more than `prefilled`
    /// means the bound was passed and the path allocated.
    pub created: usize,
    /// The most entries out of the pool at once since the last reset.
    pub peak_out: usize,
    /// Payload bytes each preallocated entry holds.
    pub payload: usize,
    /// Appends that found no vector large enough in the pool.
    pub vector_misses: usize,
    /// Entries that found no payload buffer large enough in the pool.
    pub payload_misses: usize,
    /// The largest Ready since the last reset: messages, messages after
    /// persistence, new entries, committed entries.
    pub peak_ready: [usize; 4],
    /// The most a leader had in flight to one follower since the last
    /// reset, as (entries, bytes).
    pub peak_window: (u64, u64),
}

/// The adapter's messages: the core's, and an append's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The core's message.
    pub core: CoreMessage,
    /// The entries a [`CoreMessage::Append`] carries; empty otherwise.
    pub entries: Vec<Entry>,
}

/// The thread's buffers (see the module).
#[derive(Default)]
struct Pool {
    entries: Vec<Entry>,
    vectors: Vec<Vec<Entry>>,
    stats: PoolStats,
    /// The entries and vectors it keeps at most: the bounds it was filled
    /// to.
    keep: (usize, usize),
}

thread_local! {
    static POOL: RefCell<Pool> = RefCell::new(Pool::default());
}

/// The thread's pool and adapter statistics.
#[must_use]
pub fn pool_stats() -> PoolStats {
    POOL.with_borrow(|pool| pool.stats)
}

/// Resets the peaks of [`pool_stats`], before a run that measures them.
pub fn reset_pool_peaks() {
    POOL.with_borrow_mut(|pool| {
        pool.stats.peak_out = 0;
        pool.stats.vector_misses = 0;
        pool.stats.payload_misses = 0;
        pool.stats.peak_ready = [0; 4];
        pool.stats.peak_window = (0, 0);
    });
}

/// Fills the thread's pool to `bounds`, at initialisation (every core's
/// start, a restart included): everything the
/// replication path takes from it after that was allocated here. A pool
/// filled for smaller bounds grows to these; one filled for larger keeps
/// them.
fn prefill(bounds: &Bounds) {
    POOL.with_borrow_mut(|pool| {
        let entries = bounds.pool_entries.max(pool.keep.0);
        let vectors = bounds.vectors.max(pool.keep.1);
        let payload = bounds.payload.max(pool.stats.payload);
        pool.keep = (entries, vectors);
        pool.entries
            .reserve_exact(entries.saturating_sub(pool.entries.len()));
        pool.vectors
            .reserve_exact(vectors.saturating_sub(pool.vectors.len()));
        for entry in &mut pool.entries {
            entry
                .payload
                .reserve_exact(payload.saturating_sub(entry.payload.len()));
        }
        // Topped up at every start: a crashed node's buffers never come
        // back, and a restart is an initialisation.
        while pool.entries.len() < entries {
            pool.entries.push(Entry {
                index: 0,
                term: 0,
                event_time: 0,
                payload: Vec::with_capacity(payload),
            });
            pool.stats.prefilled += 1;
            pool.stats.created += 1;
        }
        let batch = usize::try_from(BATCH).unwrap_or(0);
        while pool.vectors.len() < vectors {
            pool.vectors.push(Vec::with_capacity(batch));
        }
        pool.stats.payload = payload;
    });
}

/// The position, nearest the top of the pool, of an item whose capacity
/// is at least `needed`. The simulated network delivers clones, whose
/// buffers are exactly as large as what they hold; the pool hands each use
/// one that fits, so a clone of a short vector or an empty entry is never
/// grown.
fn fitting<T>(items: &[T], needed: usize, capacity: impl Fn(&T) -> usize) -> Option<usize> {
    items.iter().rposition(|item| capacity(item) >= needed)
}

/// An entry with these fields, its buffer from the pool when one is free.
fn pooled(index: u64, term: u64, event_time: u64, payload: &[u8]) -> Entry {
    let mut entry = POOL
        .with_borrow_mut(|pool| {
            let fit = fitting(&pool.entries, payload.len(), |entry| {
                entry.payload.capacity()
            });
            let entry = match fit {
                Some(at) => Some(pool.entries.swap_remove(at)),
                None => {
                    if !pool.entries.is_empty() {
                        pool.stats.payload_misses += 1;
                    }
                    pool.entries.pop()
                }
            };
            if entry.is_none() {
                pool.stats.created += 1;
            }
            let out = pool.stats.created.saturating_sub(pool.entries.len());
            pool.stats.peak_out = pool.stats.peak_out.max(out);
            entry
        })
        .unwrap_or(Entry {
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

/// Gives `entries` back to the pool, leaving it empty.
fn release(entries: &mut Vec<Entry>) {
    POOL.with_borrow_mut(|pool| {
        let room = pool.keep.0.saturating_sub(pool.entries.len());
        let keep = entries.len().min(room);
        pool.entries.extend(entries.drain(..keep));
    });
    entries.clear();
}

/// An empty vector from the pool, holding `entries` without growing.
fn vector(entries: usize) -> Vec<Entry> {
    POOL.with_borrow_mut(|pool| {
        let vector =
            fitting(&pool.vectors, entries, Vec::capacity).map(|at| pool.vectors.swap_remove(at));
        if vector.is_none() {
            pool.stats.vector_misses += 1;
        }
        vector
    })
    .unwrap_or_default()
}

/// Gives `entries`, emptied, back to the pool.
fn recycle(mut entries: Vec<Entry>) {
    release(&mut entries);
    if entries.capacity() > 0 {
        POOL.with_borrow_mut(|pool| {
            if pool.vectors.len() < pool.keep.1 {
                pool.vectors.push(entries);
            }
        });
    }
}

/// The custom core under the harness (see the module).
#[derive(Debug)]
pub struct Custom {
    id: NodeId,
    core: Core,
    /// The proposal size limit by frame: W2's `log_read_bytes`.
    read_bytes: u64,
    /// Entries not yet handed to the node to persist, consecutive.
    pending: Vec<Entry>,
    /// The first index to remove before they are written.
    truncate: Option<u64>,
    /// The term and vote as the core last persisted them.
    term_vote: TermVote,
    /// The hard state needs saving.
    dirty: bool,
    /// The last index handed out to apply.
    handed: u64,
    /// Messages to send at once, and after persistence, filled.
    outgoing: Vec<(NodeId, Message)>,
    /// Followers the core asked a snapshot for, for the next Ready.
    snapshot_to: Vec<NodeId>,
    after: Vec<(NodeId, Message)>,
    /// What one core call sent, before it is filled.
    sent: Vec<(u64, CoreMessage)>,
    sent_after: Vec<(u64, CoreMessage)>,
    /// The latest clock reading: the raw event time of its entries.
    now: u64,
    /// The C-TIME watermark (ADR-0111): the event time of its log's last
    /// entry, written or not, or its snapshot's log time.
    watermark: u64,
    /// The clock the core has ticked up to; `None` before the first tick.
    ticked: Option<u64>,
    /// The last index, written or not, after the last call.
    received: Option<u64>,
    /// Scratch: an append's entry terms, the log's read window, and the
    /// entries the node is done with on their way to the pool.
    terms: Vec<u64>,
    window: Vec<u8>,
    spare: Vec<Entry>,
    /// What the replication path holds at once, from the limits.
    bounds: Bounds,
    /// Vectors reserved at start, swapped into the node's Ready when its
    /// own are smaller (see [`Bounds`] and [`READY_MESSAGES`]).
    reserved: Ready<Message>,
    /// The messages the node gave back once it sent them
    /// ([`ReadyBuf::take_sent`]), on their way to the pool: their entries
    /// and entry vectors are the pool's (C5 v3).
    returned: Vec<Message>,
}

/// What one core call asked for, applied after it.
struct Sink<'a> {
    sent: &'a mut Vec<(u64, CoreMessage)>,
    sent_after: &'a mut Vec<(u64, CoreMessage)>,
    persist: Option<TermVote>,
    commit: Option<u64>,
    write: Option<(u64, u64)>,
    append: Option<(u64, u64)>,
    snapshot_to: &'a mut Vec<NodeId>,
}

impl Effects for Sink<'_> {
    fn persist(&mut self, term_vote: TermVote) {
        self.persist = Some(term_vote);
    }

    fn write(&mut self, index: u64, skip: u64) {
        self.write = Some((index, skip));
    }

    fn append(&mut self, index: u64, term: u64) {
        self.append = Some((index, term));
    }

    fn send(&mut self, to: u64, message: CoreMessage) {
        self.sent.push((to, message));
    }

    fn send_after_persist(&mut self, to: u64, message: CoreMessage) {
        self.sent_after.push((to, message));
    }

    fn commit(&mut self, index: u64) {
        self.commit = Some(index);
    }

    fn send_snapshot(&mut self, to: u64) {
        // One request per follower per Ready: the core asks at most once
        // per election timeout, and a duplicate would only resend.
        if let Some(to) = node_id(to)
            && !self.snapshot_to.contains(&to)
        {
            self.snapshot_to.push(to);
        }
    }
}

/// The core's view of the node's log: written, minus a pending
/// truncation, plus the pending entries.
struct View<'a, 'b> {
    log: &'a LogView<'b>,
    pending: &'a [Entry],
    truncate: Option<u64>,
}

impl View<'_, '_> {
    fn pending(&self, index: u64) -> Option<&Entry> {
        let first = self.pending.first()?.index;
        let at = usize::try_from(index.checked_sub(first)?).ok()?;
        self.pending.get(at)
    }

    fn written(&self, index: u64) -> bool {
        self.truncate.is_none_or(|from| index < from)
            && self.log.last_index().is_some_and(|last| index <= last)
    }
}

impl LogTerms for View<'_, '_> {
    fn last_index(&self) -> u64 {
        if let Some(entry) = self.pending.last() {
            return entry.index;
        }
        match self.truncate {
            Some(from) => from.saturating_sub(1),
            None => self
                .log
                .last_index()
                .or_else(|| self.log.base().map(|base| base.index))
                .unwrap_or(0),
        }
    }

    fn term(&self, index: u64) -> Option<u64> {
        if index == 0 {
            return Some(0);
        }
        if let Some(entry) = self.pending(index) {
            return Some(entry.term);
        }
        if self.written(index) {
            return self.log.term(index);
        }
        None
    }

    fn size(&self, index: u64) -> Option<u64> {
        if let Some(entry) = self.pending(index) {
            return u64::try_from(entry.payload.len()).ok();
        }
        if self.written(index) {
            // The frame less its header: the payload, without a read.
            let header = frame_len(0)?;
            return self.log.frame_span(index)?.checked_sub(header);
        }
        None
    }

    fn cost(&self, index: u64) -> Option<u64> {
        if self.pending(index).is_some() {
            return Some(0);
        }
        if self.written(index) {
            return self.log.frame_span(index);
        }
        None
    }
}

const fn core_id(id: NodeId) -> u64 {
    // NodeId is u32: + 1 never overflows a u64.
    id as u64 + 1
}

fn node_id(id: u64) -> Option<NodeId> {
    NodeId::try_from(id.checked_sub(1)?).ok()
}

/// The membership a configuration entry's payload carries, if it is one.
fn membership_of(payload: &[u8]) -> Option<Membership> {
    MembershipEntry::decode(payload).ok().map(|entry| entry.0)
}

/// Reports every configuration entry `log` holds to `core`, in order: a
/// restart's (karyos#711). Recovery reads the whole log once.
fn replay_configurations(core: &mut Core, log: &mut LogView<'_>) {
    let Some(last) = log.last_index() else {
        return;
    };
    let first = log.first_index();
    let mut entries = Vec::new();
    let mut window = Vec::new();
    let mut found = Vec::new();
    let mut next = first;
    while next <= last {
        if log
            .entries_into(
                next..last.saturating_add(1),
                u64::MAX,
                &mut entries,
                &mut window,
            )
            .is_err()
            || entries.is_empty()
        {
            break;
        }
        for entry in &entries {
            if let Some(membership) = membership_of(&entry.payload) {
                found.push((entry.index, membership));
            }
        }
        next = entries
            .last()
            .map_or(last, |entry| entry.index)
            .saturating_add(1);
    }
    let view = View {
        log,
        pending: &[],
        truncate: None,
    };
    for (index, membership) in found {
        core.configured(index, membership, &view);
    }
}

/// A harness change in the core's ids.
const fn core_change(change: Change) -> MembershipChange {
    match change {
        Change::AddLearner(node) => MembershipChange::AddLearner(core_id(node)),
        Change::Promote(node) => MembershipChange::Promote(core_id(node)),
        Change::Remove(node) => MembershipChange::Remove(core_id(node)),
    }
}

/// `ids` as node ids.
fn node_ids(ids: impl Iterator<Item = u64>) -> Vec<NodeId> {
    ids.filter_map(node_id).collect()
}

/// An entry's frame size for a payload of `payload` bytes.
fn frame_len(payload: usize) -> Option<u64> {
    let empty = Entry {
        index: 0,
        term: 0,
        event_time: 0,
        payload: Vec::new(),
    };
    empty
        .encoded_len()?
        .checked_add(u64::try_from(payload).ok()?)
}

impl Custom {
    fn start(
        id: NodeId,
        peers: &[NodeId],
        limits: Option<&Limits>,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        let voters: Vec<u64> = peers.iter().map(|&peer| core_id(peer)).collect();
        let limits = Some(limits.unwrap_or(&DEFAULT_LIMITS));
        let bounds = limits
            .and_then(|limits| Bounds::of(limits, peers.len()))
            .ok_or(Unsupported)?;
        // A batch never larger than the entries a follower may have in
        // flight.
        let batch = limits.map_or(BATCH, |limits| BATCH.min(limits.in_flight_entries));
        // Seeded by the run and the node: the same run reproduces the same
        // timeouts, and another seed draws others (`core::run_seed`).
        // A server that is not a bootstrap voter joins.
        let config = Config::joining(
            core_id(id),
            &voters,
            ELECTION_MIN,
            ELECTION_MAX,
            HEARTBEAT,
            batch,
            crate::driver::node_seed(crate::driver::run_seed(), u64::from(id)),
        )
        .map_err(|_| Unsupported)?;
        let config = match limits {
            Some(limits) => config
                .with_limits(CoreLimits {
                    in_flight_entries: limits.in_flight_entries,
                    in_flight_bytes: limits.in_flight_bytes,
                    queue: limits.queue,
                    reads: u64::MAX,
                    read_bytes: limits.log_read_bytes,
                })
                .map_err(|_| Unsupported)?,
            None => config,
        };
        prefill(&bounds);
        let stored = log.hard_state();
        let term_vote = stored.map_or_else(TermVote::default, |state| TermVote {
            term: state.current_term,
            voted_for: state
                .voted_for
                .and_then(|vote| NodeId::try_from(vote).ok())
                .map(core_id),
        });
        let commit = stored.and_then(|state| state.commit).unwrap_or(0);
        // Over the node's latest snapshot, if it holds one, and the
        // configuration it recorded; then each configuration entry the
        // log holds, in order.
        let mut core = match log.base() {
            Some(base) => {
                let mut core =
                    Core::new(config, term_vote, commit).with_snapshot(base.index, base.term);
                if let Some(membership) = log.base_configuration().and_then(membership_of) {
                    core.restore_membership(base.index, membership);
                }
                core
            }
            None => Core::new(config, term_vote, commit),
        };
        replay_configurations(&mut core, log);
        Ok(Self {
            id,
            core,
            read_bytes: limits.map_or(u64::MAX, |limits| limits.log_read_bytes),
            pending: Vec::with_capacity(bounds.ready_entries),
            truncate: None,
            term_vote,
            dirty: false,
            // The node applies from its log's start after a restart.
            // The node applies from its log's start after a restart: below
            // it, its snapshot holds the state.
            handed: log.first_index().saturating_sub(1),
            outgoing: Vec::with_capacity(READY_MESSAGES),
            snapshot_to: Vec::with_capacity(voters.len()),
            after: Vec::with_capacity(READY_MESSAGES),
            sent: Vec::with_capacity(READY_MESSAGES),
            sent_after: Vec::with_capacity(READY_MESSAGES),
            now: 0,
            // The largest event time of the recovered log's entries and
            // the snapshot's log time.
            watermark: log.watermark().unwrap_or(0),
            ticked: None,
            received: log
                .last_index()
                .or_else(|| log.base().map(|base| base.index)),
            terms: Vec::with_capacity(usize::try_from(batch).unwrap_or(0)),
            // The log's largest read window (1 MiB), so its first read
            // after the warm-up does not allocate.
            window: Vec::with_capacity(READ_WINDOW),
            spare: Vec::with_capacity(bounds.ready_entries.saturating_add(bounds.committed)),
            bounds,
            reserved: Ready {
                messages: Vec::with_capacity(READY_MESSAGES),
                entries: Vec::with_capacity(bounds.ready_entries),
                after_persist: Vec::with_capacity(READY_MESSAGES),
                committed: Vec::with_capacity(bounds.committed),
                snapshot_to: Vec::with_capacity(voters.len()),
                ..Ready::default()
            },
            returned: Vec::with_capacity(READY_MESSAGES.saturating_mul(2)),
        })
    }

    /// Runs one core call over the node's view, applies what it asked
    /// for, and fills what it sent; `incoming` is the stepped append's
    /// entries.
    fn call<R>(
        &mut self,
        log: &mut LogView<'_>,
        incoming: &mut Vec<Entry>,
        run: impl FnOnce(&mut Core, &View<'_, '_>, &mut Sink<'_>) -> R,
    ) -> R {
        let mut sink = Sink {
            sent: &mut self.sent,
            sent_after: &mut self.sent_after,
            persist: None,
            commit: None,
            write: None,
            append: None,
            snapshot_to: &mut self.snapshot_to,
        };
        let view = View {
            log,
            pending: &self.pending,
            truncate: self.truncate,
        };
        let result = run(&mut self.core, &view, &mut sink);
        let Sink {
            persist,
            commit,
            write,
            append,
            ..
        } = sink;
        let written = log.last_index().unwrap_or(0);
        if let Some(term_vote) = persist {
            self.term_vote = term_vote;
            self.dirty = true;
        }
        if commit.is_some() {
            self.dirty = true;
        }
        if let Some((index, skip)) = write {
            let keep = self
                .pending
                .iter()
                .position(|entry| entry.index >= index)
                .unwrap_or(self.pending.len());
            let mut dropped = self.pending.split_off(keep);
            release(&mut dropped);
            if index <= written && self.pending.is_empty() {
                self.truncate = Some(self.truncate.map_or(index, |from| from.min(index)));
            }
            let skip = usize::try_from(skip)
                .unwrap_or(usize::MAX)
                .min(incoming.len());
            let from = self.pending.len();
            self.pending.extend(incoming.drain(skip..));
            if let Some(last) = self.pending.last() {
                self.watermark = last.event_time;
            }
            // Each configuration entry written takes effect now.
            let view = View {
                log,
                pending: &self.pending,
                truncate: self.truncate,
            };
            for entry in self.pending.get(from..).unwrap_or(&[]) {
                if let Some(membership) = membership_of(&entry.payload) {
                    self.core.configured(entry.index, membership, &view);
                }
            }
        }
        if let Some((index, term)) = append {
            self.watermark = stamp(self.now, self.watermark);
            self.pending.push(pooled(index, term, self.watermark, &[]));
        }
        // Each append filled now, from the view the core just read.
        let mut sent = std::mem::take(&mut self.sent);
        for (to, message) in sent.drain(..) {
            let Some(to) = node_id(to) else {
                continue;
            };
            // Only an append with entries takes a vector: a heartbeat or a
            // reply carries an empty one, which allocates nothing.
            let mut entries = Vec::new();
            if let CoreMessage::Append {
                prev_index,
                entries: count,
                ..
            } = message
                && count > 0
            {
                entries = vector(usize::try_from(count).unwrap_or(usize::MAX));
                let first = prev_index.saturating_add(1);
                if self.fill(log, (first, count), &mut entries) != count {
                    // Refused by the duty's budget or the log: lost.
                    recycle(entries);
                    continue;
                }
            }
            self.outgoing.push((
                to,
                Message {
                    core: message,
                    entries,
                },
            ));
        }
        self.sent = sent;
        for (to, message) in self.sent_after.drain(..) {
            if let Some(to) = node_id(to) {
                self.after.push((
                    to,
                    Message {
                        core: message,
                        entries: Vec::new(),
                    },
                ));
            }
        }
        self.received =
            self.pending
                .last()
                .map(|entry| entry.index)
                .or_else(|| match self.truncate {
                    Some(from) => from.checked_sub(1).filter(|last| *last > 0),
                    None => log
                        .last_index()
                        .or_else(|| log.base().map(|base| base.index)),
                });
        result
    }

    /// Fills `out` with the entries from `first`, at most `count`, in
    /// order: written ones read through the duty's metered log, pending
    /// ones copied; how many it holds. A read the budget or the log
    /// refuses stops it there.
    fn fill(
        &mut self,
        log: &mut LogView<'_>,
        (first, count): (u64, u64),
        out: &mut Vec<Entry>,
    ) -> u64 {
        release(out);
        let end = first.saturating_add(count);
        let pending_first = self.pending.first().map_or(u64::MAX, |entry| entry.index);
        let written_end = end.min(pending_first);
        if first < written_end {
            // Entries from the pool, for the read to reuse.
            let wanted = usize::try_from(written_end - first).unwrap_or(0);
            while out.len() < wanted {
                out.push(pooled(0, 0, 0, &[]));
            }
            if log
                .entries_into(first..written_end, u64::MAX, out, &mut self.window)
                .is_err()
            {
                release(out);
                return 0;
            }
            if out.len() != wanted {
                return u64::try_from(out.len()).unwrap_or(0);
            }
        }
        for index in first.max(pending_first)..end {
            let at = usize::try_from(index - pending_first).unwrap_or(usize::MAX);
            let Some(entry) = self.pending.get(at) else {
                break;
            };
            out.push(pooled(
                entry.index,
                entry.term,
                entry.event_time,
                &entry.payload,
            ));
        }
        u64::try_from(out.len()).unwrap_or(0)
    }

    /// The most this core, leading, has in flight to one follower now.
    fn peak_window(&self) -> (u64, u64) {
        let voters = u64::try_from(crate::consensus::MAX_VOTERS).unwrap_or(0);
        (1..=voters)
            .filter_map(|id| self.core.in_flight(id))
            .fold((0, 0), |(entries, bytes), (e, b)| {
                (entries.max(e), bytes.max(b))
            })
    }

    fn leading(&self) -> bool {
        self.core.role() == Role::Leader
    }

    fn not_leader(&self) -> NotLeader {
        let leader = match self.core.role() {
            Role::Follower { leader } => leader.and_then(node_id),
            Role::Leader => Some(self.id),
            Role::PreCandidate | Role::Candidate => None,
        };
        NotLeader { leader }
    }
}

impl ConsensusCore for Custom {
    type Message = Message;

    fn is_configuration_entry(payload: &[u8]) -> bool {
        MembershipEntry::is_one(payload)
    }

    fn configuration_stamp(&self) -> Option<u64> {
        Some(self.core.configuration_changes())
    }

    fn configuration(&self) -> Option<Configuration> {
        let membership = self.core.membership();
        Some(Configuration {
            index: self.core.configuration_index(),
            voters: node_ids(membership.voters()),
            outgoing: Vec::new(),
            learners: node_ids(membership.learners()),
        })
    }

    fn propose_change(
        &mut self,
        change: Change,
        log: &mut LogView<'_>,
    ) -> Result<(), ChangeRefused> {
        // Every configuration entry is the template's fixed length.
        let size = u64::from(MEMBERSHIP.max_length);
        if frame_len(MEMBERSHIP.max_length as usize).is_none_or(|frame| frame > self.read_bytes) {
            return Err(ChangeRefused::Invalid);
        }
        let mut none = Vec::new();
        let change = core_change(change);
        let proposed = self.call(log, &mut none, |core, view, sink| {
            core.propose_change(change, size, PROMOTION_LAG, view, sink)
        });
        let (index, term, membership) = proposed.map_err(|error| match error {
            ChangeError::NotLeader(_) => ChangeRefused::NotLeader(self.not_leader()),
            ChangeError::InProgress => ChangeRefused::InProgress,
            ChangeError::Lagging { behind } => ChangeRefused::Lagging { behind },
            ChangeError::Invalid | ChangeError::Backpressure(_) => ChangeRefused::Invalid,
        })?;
        self.watermark = stamp(self.now, self.watermark);
        let payload = MembershipEntry(membership).to_vec();
        self.pending
            .push(pooled(index, term, self.watermark, &payload));
        self.call(log, &mut none, |core, view, sink| {
            core.replicate(view, sink)
        });
        Ok(())
    }

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        // A membership the core refuses (not 3 or 5 voters) starts a
        // follower over a 3-voter view of itself: the others are not
        // there, so it never leads and the harness reports no progress,
        // never a pass.
        let inert = [id, id.wrapping_add(1), id.wrapping_add(2)];
        let mut core = Self::start(id, peers, None, log);
        if core.is_err() {
            core = Self::start(id, &inert, None, log);
        }
        // Three distinct voters, one of them the node: always valid.
        #[allow(clippy::expect_used)]
        core.expect("a 3-voter configuration is valid")
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        Self::start(id, peers, Some(limits), log)
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.propose_slice(&command, log)
    }

    fn propose_slice(&mut self, command: &[u8], log: &mut LogView<'_>) -> Result<(), Refused> {
        let size = u64::try_from(command.len())
            .map_err(|_| Refused::Backpressure(Limit::InFlightBytes))?;
        let mut none = Vec::new();
        let proposed = self.call(log, &mut none, |core, view, _| core.propose(size, view));
        let (index, term) = proposed.map_err(|error| match error {
            ProposeError::NotLeader(_) => Refused::NotLeader(self.not_leader()),
            ProposeError::Backpressure(Backpressure::InFlightBytes) => {
                Refused::Backpressure(Limit::InFlightBytes)
            }
            ProposeError::Backpressure(Backpressure::Queue) => Refused::Backpressure(Limit::Queue),
            ProposeError::Backpressure(Backpressure::LogRead) => {
                Refused::Backpressure(Limit::LogRead)
            }
        })?;
        // A frame no duty could read to send it.
        if frame_len(command.len()).is_none_or(|frame| frame > self.read_bytes) {
            return Err(Refused::Backpressure(Limit::LogRead));
        }
        self.watermark = stamp(self.now, self.watermark);
        self.pending
            .push(pooled(index, term, self.watermark, command));
        self.call(log, &mut none, |core, view, sink| {
            core.replicate(view, sink)
        });
        Ok(())
    }

    fn step(&mut self, from: NodeId, message: Message, log: &mut LogView<'_>) {
        let Message { core, mut entries } = message;
        self.terms.clear();
        self.terms.extend(entries.iter().map(|entry| entry.term));
        let terms = std::mem::take(&mut self.terms);
        // A refused message changes nothing: the harness's checks catch
        // what a faulty leader sent.
        let _ = self.call(log, &mut entries, |state, view, sink| {
            state.step(core_id(from), core, &terms, view, sink)
        });
        self.terms = terms;
        recycle(entries);
    }

    /// The lent append's entries copied into entries of the thread's pool,
    /// which the core keeps; the node takes the lent message back whole
    /// (C5 v3): nothing of it is freed here.
    fn step_lent(&mut self, from: NodeId, message: &mut Message, log: &mut LogView<'_>) {
        let mut entries = vector(message.entries.len());
        for entry in &message.entries {
            entries.push(pooled(
                entry.index,
                entry.term,
                entry.event_time,
                &entry.payload,
            ));
        }
        self.step(
            from,
            Message {
                core: message.core,
                entries,
            },
            log,
        );
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.now = self.now.max(now);
        let Some(ticked) = self.ticked else {
            // The first reading is the baseline.
            self.ticked = Some(now);
            return;
        };
        let ticks = now.saturating_sub(ticked).min(MAX_TICKS_PER_CALL);
        self.ticked = Some(ticked.saturating_add(ticks));
        let mut none = Vec::new();
        for _ in 0..ticks {
            self.call(log, &mut none, |core, view, sink| core.tick(view, sink));
        }
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        let mut out = ReadyBuf::default();
        self.ready_into(&mut out, log)
            .then(|| std::mem::take(&mut out.ready))
    }

    fn ready_into(&mut self, out: &mut ReadyBuf<Message>, log: &mut LogView<'_>) -> bool {
        // What the node is done with goes back to the thread's pool: the
        // entries it persisted and applied, and the messages it sent, whose
        // entries and vectors the pool gave out (C5 v3).
        out.take_spare(&mut self.spare);
        release(&mut self.spare);
        // Room for a Ready's entries going back once it is done, at the
        // first call: the recycling is the Ready stage's (C5 v3 coverage).
        out.reserve_spare(
            self.bounds
                .ready_entries
                .saturating_add(self.bounds.committed),
        );
        out.take_sent(&mut self.returned);
        for message in self.returned.drain(..) {
            recycle(message.entries);
        }
        // The node's vectors, grown to the reserved ones' size once.
        let (ready, reserved) = (&mut out.ready, &mut self.reserved);
        if ready.messages.capacity() < reserved.messages.capacity() {
            std::mem::swap(&mut ready.messages, &mut reserved.messages);
        }
        if ready.after_persist.capacity() < reserved.after_persist.capacity() {
            std::mem::swap(&mut ready.after_persist, &mut reserved.after_persist);
        }
        if ready.entries.capacity() < reserved.entries.capacity() {
            std::mem::swap(&mut ready.entries, &mut reserved.entries);
        }
        if ready.committed.capacity() < reserved.committed.capacity() {
            std::mem::swap(&mut ready.committed, &mut reserved.committed);
        }
        if ready.snapshot_to.capacity() < reserved.snapshot_to.capacity() {
            std::mem::swap(&mut ready.snapshot_to, &mut reserved.snapshot_to);
        }
        out.ready.messages.append(&mut self.outgoing);
        out.ready.after_persist.append(&mut self.after);
        out.ready.snapshot_to.append(&mut self.snapshot_to);
        // Committed entries, written or in this Ready, from the last
        // handed out, as many as the duty's reads cover: `drive` applies
        // them once this Ready is durable.
        let commit = self.core.commit();
        if commit > self.handed {
            let first = self.handed.saturating_add(1);
            let mut committed = std::mem::take(&mut out.ready.committed);
            // At most a Ready's bound: the rest in the next.
            let most = (commit - self.handed)
                .min(u64::try_from(self.bounds.committed).unwrap_or(u64::MAX));
            let filled = self.fill(log, (first, most), &mut committed);
            self.handed = self.handed.saturating_add(filled);
            out.ready.committed = committed;
        }
        out.ready.truncate_from = self.truncate.take();
        out.ready.entries.append(&mut self.pending);
        if self.dirty {
            self.dirty = false;
            let commit = self.core.commit();
            out.ready.hard_state = Some(HardState {
                current_term: self.term_vote.term,
                voted_for: self.term_vote.voted_for.and_then(node_id).map(u64::from),
                commit: (commit > 0).then_some(commit),
            });
        }
        let ready = &out.ready;
        let sizes = [
            ready.messages.len(),
            ready.after_persist.len(),
            ready.entries.len(),
            ready.committed.len(),
        ];
        let window = self.peak_window();
        POOL.with_borrow_mut(|pool| {
            for (peak, size) in pool.stats.peak_ready.iter_mut().zip(sizes) {
                *peak = (*peak).max(size);
            }
            let (entries, bytes) = &mut pool.stats.peak_window;
            *entries = (*entries).max(window.0);
            *bytes = (*bytes).max(window.1);
        });
        !out.is_empty()
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        let Some(durable) = persisted.durable else {
            return;
        };
        let mut none = Vec::new();
        self.call(log, &mut none, |core, view, sink| {
            core.persisted(durable, view, sink);
        });
    }

    fn term(&self) -> u64 {
        self.core.term_vote().term
    }

    fn leads(&self) -> bool {
        self.leading()
    }

    fn received(&self) -> Option<u64> {
        self.received
    }

    fn committed(&self) -> Option<u64> {
        let commit = self.core.commit();
        (commit > 0).then_some(commit)
    }

    fn compacted(&mut self, base: SnapshotBase, log: &mut LogView<'_>) -> Result<(), Unsupported> {
        let _ = log;
        // The node compacts only what it applied, which the core
        // committed: an uncommitted base would be the node's error, and the
        // core keeps its own base then.
        let _ = self.core.compacted(base.index, base.term);
        Ok(())
    }

    fn can_install(&self, base: SnapshotBase) -> Result<(), InstallRefused> {
        self.core
            .can_install(base.index)
            .map_err(|_| InstallRefused::Stale)
    }

    fn install(&mut self, base: SnapshotBase, log: &mut LogView<'_>) -> Result<(), InstallRefused> {
        self.core
            .can_install(base.index)
            .map_err(|_| InstallRefused::Stale)?;
        let mut none = Vec::new();
        self.call(log, &mut none, |core, _, sink| {
            core.install(base.index, base.term, sink)
        })
        .map_err(|_| InstallRefused::Stale)?;
        if let Some(membership) = log.base_configuration().and_then(membership_of) {
            self.core.restore_membership(base.index, membership);
        }
        // The log restarted after the base: what was pending at or below
        // it is gone with it, and the service holds the state up to it.
        let keep = self
            .pending
            .iter()
            .position(|entry| entry.index > base.index)
            .unwrap_or(self.pending.len());
        let mut dropped: Vec<Entry> = self.pending.drain(..keep).collect();
        release(&mut dropped);
        self.truncate = None;
        self.handed = self.handed.max(base.index);
        // What is left pending follows the base; with nothing, the
        // watermark is the snapshot's log time.
        match self.pending.last() {
            Some(last) => self.watermark = last.event_time,
            None => {
                if let Some(log_time) = log.base_time() {
                    self.watermark = log_time;
                }
            }
        }
        Ok(())
    }
}
