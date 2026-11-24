// SPDX-License-Identifier: Apache-2.0

//! The custom Raft core (ADR-0105) behind the harness's [`ConsensusCore`]:
//! part (d) of quantstratum/karyos#681.
//!
//! The shipped interface is [`karyos_cluster::consensus`]'s: a pure
//! [`Core`] that reads the log through [`LogTerms`] and acts through
//! [`Effects`]. `karyos-sim` depends on `karyos-cluster`, so the harness
//! trait cannot be the shipped one; this module is the simulator-side
//! adapter over it, and the evaluation and the shipped path run the same
//! state machine.
//!
//! **Mapping.**
//!
//! - Node ids: the harness numbers servers from 0, the core's voter ids
//!   start at 1, so core id = node id + 1. The hard state stores node ids.
//! - The log view: the core sees the node's written log, minus a pending
//!   truncation, plus the entries not yet handed to
//!   [`drive`](super::core::drive) (proposals, a new leader's no-op, a
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
//!   [`drive`](super::core::drive) releases once the Ready is durable
//!   (persist then send).
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
//!
//! **Buffers.** Entries and their vectors come from one pool per thread,
//! shared by every node the simulation runs on it: what a follower is
//! done with (a message's entries, a Ready's recycled ones) goes back to
//! it, and a leader's next append takes from it. It stands for a
//! transport that hands a sent buffer back, so after the warm-up nothing
//! on the replication path allocates (ADR-0105, decision 3). The pool is
//! bounded ([`MAX_POOLED_ENTRIES`], [`MAX_POOLED_VECTORS`]).
//!
//! **Not taken yet:** snapshots, compaction and leadership transfer (W5)
//! answer [`Unsupported`], which the harness reports as not
//! demonstrated, until the core's snapshot install (#682).

use std::cell::RefCell;

use karyos_cluster::consensus::{
    Backpressure, Config, Core, Effects, Limits as CoreLimits, LogTerms, Message as CoreMessage,
    ProposeError, Role, TermVote,
};
use karyos_cluster::{Entry, HardState};

use super::core::{
    ConsensusCore, Limit, Limits, LogView, NotLeader, Persisted, Ready, ReadyBuf, Refused,
    Unsupported,
};
use crate::net::NodeId;

/// The shortest election timeout, in ticks (version 1's timing).
pub const ELECTION_MIN: u32 = 10;
/// The election timeouts are drawn from `ELECTION_MIN..ELECTION_MAX`.
pub const ELECTION_MAX: u32 = 20;
/// Ticks between a leader's heartbeats.
pub const HEARTBEAT: u32 = 2;
/// Entries per append at most: W1's primary batch limit.
pub const BATCH: u64 = 16;
/// Ticks one [`ConsensusCore::tick`] call runs at most.
pub const MAX_TICKS_PER_CALL: u64 = 64;
/// Entries the thread's pool keeps at most.
pub const MAX_POOLED_ENTRIES: usize = 4096;
/// Entry vectors the thread's pool keeps at most.
pub const MAX_POOLED_VECTORS: usize = 1024;
/// Entries the thread's pool is filled with before the first core
/// starts, and the payload bytes each holds: W1's largest command
/// (16,000 bytes) fits, so no buffer grows on the replication path.
pub const PREFILLED_ENTRIES: usize = 1024;
/// See [`PREFILLED_ENTRIES`].
pub const PREFILLED_PAYLOAD: usize = 16 * 1024;
/// The bytes C4's log reads at once at most (`RaftLog`'s read window).
pub const READ_WINDOW: usize = 1 << 20;
/// Messages, entries and committed entries one Ready holds before its
/// vectors grow: reserved when the core starts, so a node's first Ready
/// after the warm-up does not allocate.
pub const READY_CAPACITY: usize = 256;
/// Entry vectors the pool is filled with, each holding [`BATCH`].
pub const PREFILLED_VECTORS: usize = 256;

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
    filled: bool,
}

thread_local! {
    static POOL: RefCell<Pool> = RefCell::new(Pool::default());
}

/// Fills the thread's pool once, at initialisation: everything the
/// replication path takes from it after that was allocated here.
fn prefill() {
    POOL.with_borrow_mut(|pool| {
        if pool.filled {
            return;
        }
        pool.filled = true;
        pool.entries.reserve_exact(MAX_POOLED_ENTRIES);
        pool.vectors.reserve_exact(MAX_POOLED_VECTORS);
        for _ in 0..PREFILLED_ENTRIES {
            pool.entries.push(Entry {
                index: 0,
                term: 0,
                event_time: 0,
                payload: Vec::with_capacity(PREFILLED_PAYLOAD),
            });
        }
        let batch = usize::try_from(BATCH).unwrap_or(0);
        for _ in 0..PREFILLED_VECTORS {
            pool.vectors.push(Vec::with_capacity(batch));
        }
    });
}

/// An entry with these fields, its buffer from the pool when one is free.
fn pooled(index: u64, term: u64, event_time: u64, payload: &[u8]) -> Entry {
    let mut entry = POOL
        .with_borrow_mut(|pool| pool.entries.pop())
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
        let room = MAX_POOLED_ENTRIES.saturating_sub(pool.entries.len());
        let keep = entries.len().min(room);
        pool.entries.extend(entries.drain(..keep));
    });
    entries.clear();
}

/// An empty vector from the pool.
fn vector() -> Vec<Entry> {
    POOL.with_borrow_mut(|pool| pool.vectors.pop())
        .unwrap_or_default()
}

/// Gives `entries`, emptied, back to the pool.
fn recycle(mut entries: Vec<Entry>) {
    release(&mut entries);
    if entries.capacity() > 0 {
        POOL.with_borrow_mut(|pool| {
            if pool.vectors.len() < MAX_POOLED_VECTORS {
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
    after: Vec<(NodeId, Message)>,
    /// What one core call sent, before it is filled.
    sent: Vec<(u64, CoreMessage)>,
    sent_after: Vec<(u64, CoreMessage)>,
    /// The latest clock reading: the event time of its entries.
    now: u64,
    /// The clock the core has ticked up to; `None` before the first tick.
    ticked: Option<u64>,
    /// The last index, written or not, after the last call.
    received: Option<u64>,
    /// Scratch: an append's entry terms, the log's read window, and the
    /// entries the node is done with on their way to the pool.
    terms: Vec<u64>,
    window: Vec<u8>,
    spare: Vec<Entry>,
    /// Vectors reserved at start, swapped into the node's Ready when its
    /// own are smaller (see [`READY_CAPACITY`]).
    reserved: Ready<Message>,
}

/// What one core call asked for, applied after it.
struct Sink<'a> {
    sent: &'a mut Vec<(u64, CoreMessage)>,
    sent_after: &'a mut Vec<(u64, CoreMessage)>,
    persist: Option<TermVote>,
    commit: Option<u64>,
    write: Option<(u64, u64)>,
    append: Option<(u64, u64)>,
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
            None => self.log.last_index().unwrap_or(0),
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
        // A batch never larger than the entries a follower may have in
        // flight.
        let batch = limits.map_or(BATCH, |limits| BATCH.min(limits.in_flight_entries));
        // Seeded by the node: the same run reproduces the same timeouts.
        let config = Config::new(
            core_id(id),
            &voters,
            ELECTION_MIN,
            ELECTION_MAX,
            HEARTBEAT,
            batch,
            u64::from(id),
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
        prefill();
        let stored = log.hard_state();
        let term_vote = stored.map_or_else(TermVote::default, |state| TermVote {
            term: state.current_term,
            voted_for: state
                .voted_for
                .and_then(|vote| NodeId::try_from(vote).ok())
                .map(core_id),
        });
        let commit = stored.and_then(|state| state.commit).unwrap_or(0);
        Ok(Self {
            id,
            core: Core::new(config, term_vote, commit),
            read_bytes: limits.map_or(u64::MAX, |limits| limits.log_read_bytes),
            pending: Vec::with_capacity(READY_CAPACITY),
            truncate: None,
            term_vote,
            dirty: false,
            // The node applies from its log's start after a restart.
            handed: 0,
            outgoing: Vec::with_capacity(READY_CAPACITY),
            after: Vec::with_capacity(READY_CAPACITY),
            sent: Vec::with_capacity(READY_CAPACITY),
            sent_after: Vec::with_capacity(READY_CAPACITY),
            now: 0,
            ticked: None,
            received: log.last_index(),
            terms: Vec::new(),
            // The log's largest read window (1 MiB), so its first read
            // after the warm-up does not allocate.
            window: Vec::with_capacity(READ_WINDOW),
            spare: Vec::with_capacity(READY_CAPACITY),
            reserved: Ready {
                messages: Vec::with_capacity(READY_CAPACITY),
                entries: Vec::with_capacity(READY_CAPACITY),
                after_persist: Vec::with_capacity(READY_CAPACITY),
                committed: Vec::with_capacity(READY_CAPACITY),
                ..Ready::default()
            },
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
            self.pending.extend(incoming.drain(skip..));
        }
        if let Some((index, term)) = append {
            self.pending.push(pooled(index, term, self.now, &[]));
        }
        // Each append filled now, from the view the core just read.
        let mut sent = std::mem::take(&mut self.sent);
        for (to, message) in sent.drain(..) {
            let Some(to) = node_id(to) else {
                continue;
            };
            let mut entries = vector();
            if let CoreMessage::Append {
                prev_index,
                entries: count,
                ..
            } = message
                && count > 0
            {
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
                    None => log.last_index(),
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
        self.pending.push(pooled(index, term, self.now, command));
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
        // What the node is done with goes back to the thread's pool.
        out.take_spare(&mut self.spare);
        release(&mut self.spare);
        // The node's vectors, grown to the reserved ones' size once.
        let (ready, reserved) = (&mut out.ready, &mut self.reserved);
        if ready.messages.capacity() < READY_CAPACITY {
            std::mem::swap(&mut ready.messages, &mut reserved.messages);
        }
        if ready.after_persist.capacity() < READY_CAPACITY {
            std::mem::swap(&mut ready.after_persist, &mut reserved.after_persist);
        }
        if ready.entries.capacity() < READY_CAPACITY {
            std::mem::swap(&mut ready.entries, &mut reserved.entries);
        }
        if ready.committed.capacity() < READY_CAPACITY {
            std::mem::swap(&mut ready.committed, &mut reserved.committed);
        }
        out.ready.messages.append(&mut self.outgoing);
        out.ready.after_persist.append(&mut self.after);
        // Committed entries, written or in this Ready, from the last
        // handed out, as many as the duty's reads cover: `drive` applies
        // them once this Ready is durable.
        let commit = self.core.commit();
        if commit > self.handed {
            let first = self.handed.saturating_add(1);
            let mut committed = std::mem::take(&mut out.ready.committed);
            // At most a reserved Ready's worth: the rest in the next.
            let most =
                (commit - self.handed).min(u64::try_from(READY_CAPACITY).unwrap_or(u64::MAX));
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
}
