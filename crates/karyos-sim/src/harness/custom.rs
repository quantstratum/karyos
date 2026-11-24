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
//!   truncation, plus the entries not yet handed to [`drive`]
//!   (proposals, a new leader's no-op, a follower's received suffix). An
//!   entry's size is its frame's (`RaftLog::frame_span`, or
//!   `Entry::encoded_len` before it is written): what the duty reads to
//!   send it, and at least its payload, so the in-flight byte cap on
//!   payloads holds.
//! - Effects: [`Effects::persist`] and [`Effects::commit`] become the
//!   Ready's hard state; [`Effects::write`] truncates and takes the
//!   stepped append's entries; [`Effects::append`] adds the no-op;
//!   [`Effects::send`] goes in `messages`, [`Effects::send_after_persist`]
//!   in `after_persist`, which [`drive`] releases once the Ready is
//!   durable (persist then send).
//! - Appends: the core sends positions and counts. Building the Ready,
//!   the adapter fills each append with its entries, from the pending
//!   ones or read from C4's log through the duty's metered [`LogView`];
//!   an append whose entries the budget refuses is not sent, as if the
//!   network lost it, and the core's window recovers it as it recovers a
//!   loss (a heartbeat's rejection rewinds it).
//! - Limits: [`Limits`] map one to one: `log_read_bytes` is the core's
//!   [`CoreLimits::read_bytes`]; each core call is a duty for its size
//!   lookups. Refusals map to [`Limit`].
//! - Time: one harness tick is one core tick, at most
//!   [`MAX_TICKS_PER_CALL`] per call.
//!
//! **Not taken yet:** snapshots, compaction and leadership transfer (W5)
//! answer [`Unsupported`], which the harness reports as not
//! demonstrated, until the core's snapshot install (#682).

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

/// The adapter's messages: the core's, and an append's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The core's message.
    pub core: CoreMessage,
    /// The entries a [`CoreMessage::Append`] carries; empty otherwise.
    pub entries: Vec<Entry>,
}

/// The custom core under the harness (see the module).
#[derive(Debug)]
pub struct Custom {
    id: NodeId,
    core: Core,
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
    /// Core messages to send at once, and after persistence.
    outgoing: Vec<(u64, CoreMessage)>,
    after: Vec<(u64, CoreMessage)>,
    /// The clock at the last tick.
    now: u64,
    /// The last index, written or not, after the last call.
    received: Option<u64>,
    /// Entries whose buffers are free, from the node's pool.
    spare: Vec<Entry>,
    /// Entry vectors free for appends.
    vectors: Vec<Vec<Entry>>,
    /// Scratch: an append's entry terms, and the log's read window.
    terms: Vec<u64>,
    window: Vec<u8>,
}

/// What one core call asked for, applied after it.
#[derive(Default)]
struct Sink<'a> {
    outgoing: Option<&'a mut Vec<(u64, CoreMessage)>>,
    after: Option<&'a mut Vec<(u64, CoreMessage)>>,
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
        if let Some(outgoing) = self.outgoing.as_mut() {
            outgoing.push((to, message));
        }
    }

    fn send_after_persist(&mut self, to: u64, message: CoreMessage) {
        if let Some(after) = self.after.as_mut() {
            after.push((to, message));
        }
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
            return entry.encoded_len();
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

/// An entry's frame size before it is written.
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
                    reads: limits.in_flight_entries.saturating_mul(2).max(1),
                    read_bytes: limits.log_read_bytes,
                })
                .map_err(|_| Unsupported)?,
            None => config,
        };
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
            pending: Vec::new(),
            truncate: None,
            term_vote,
            dirty: false,
            // The node applies from its log's start after a restart.
            handed: 0,
            outgoing: Vec::new(),
            after: Vec::new(),
            now: 0,
            received: log.last_index(),
            spare: Vec::new(),
            vectors: Vec::new(),
            terms: Vec::new(),
            window: Vec::new(),
        })
    }

    /// Runs one core call over the node's view, then applies what it
    /// asked for; `incoming` is the stepped append's entries.
    fn call<R>(
        &mut self,
        log: &LogView<'_>,
        incoming: &mut Vec<Entry>,
        run: impl FnOnce(&mut Core, &View<'_, '_>, &mut Sink<'_>) -> R,
    ) -> R {
        let mut sink = Sink {
            outgoing: Some(&mut self.outgoing),
            after: Some(&mut self.after),
            ..Sink::default()
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
            self.pending.retain(|entry| entry.index < index);
            if index <= written && self.pending.is_empty() {
                self.truncate = Some(self.truncate.map_or(index, |from| from.min(index)));
            }
            let skip = usize::try_from(skip)
                .unwrap_or(usize::MAX)
                .min(incoming.len());
            self.pending.extend(incoming.drain(skip..));
        }
        if let Some((index, term)) = append {
            let mut entry = self.spare.pop().unwrap_or(Entry {
                index,
                term,
                event_time: self.now,
                payload: Vec::new(),
            });
            entry.index = index;
            entry.term = term;
            entry.event_time = self.now;
            entry.payload.clear();
            self.pending.push(entry);
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

    /// Fills `entries` with `first..first + count`: pending ones copied,
    /// written ones read through the duty's metered log. False when the
    /// budget or the log refuses any of them.
    fn fill(
        &mut self,
        out: &mut ReadyBuf<Message>,
        log: &mut LogView<'_>,
        (first, count): (u64, u64),
        entries: &mut Vec<Entry>,
    ) -> bool {
        entries.clear();
        let Some(end) = first.checked_add(count) else {
            return false;
        };
        let pending_first = self.pending.first().map_or(u64::MAX, |entry| entry.index);
        let written_end = end.min(pending_first);
        if first < written_end {
            if log
                .entries_into(first..written_end, u64::MAX, entries, &mut self.window)
                .is_err()
            {
                return false;
            }
            let read = u64::try_from(entries.len()).unwrap_or(0);
            if read != written_end - first {
                return false;
            }
        }
        for index in first.max(pending_first)..end {
            let Some(entry) = self
                .pending
                .get(usize::try_from(index - pending_first).unwrap_or(usize::MAX))
            else {
                return false;
            };
            entries.push(out.entry(entry.index, entry.term, entry.event_time, &entry.payload));
        }
        true
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
        // A membership the core refuses (not 3 or 5 voters) starts an
        // inert follower over a 3-voter view of itself: it never leads,
        // so the harness reports no progress, never a pass.
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
        let size = frame_len(command.len()).ok_or(Refused::Backpressure(Limit::InFlightBytes))?;
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
        let mut entry = self.spare.pop().unwrap_or(Entry {
            index,
            term,
            event_time: self.now,
            payload: Vec::new(),
        });
        entry.index = index;
        entry.term = term;
        entry.event_time = self.now;
        entry.payload.clear();
        entry.payload.extend_from_slice(command);
        self.pending.push(entry);
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
        self.spare.append(&mut entries);
        self.vectors.push(entries);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        let ticks = now.saturating_sub(self.now).min(MAX_TICKS_PER_CALL);
        self.now = self.now.max(now);
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
        out.take_spare(&mut self.spare);
        let outgoing = std::mem::take(&mut self.outgoing);
        for &(to, message) in &outgoing {
            let Some(to) = node_id(to) else {
                continue;
            };
            let mut entries = self.vectors.pop().unwrap_or_default();
            if let CoreMessage::Append {
                prev_index,
                entries: count,
                ..
            } = message
                && count > 0
                && !self.fill(
                    out,
                    log,
                    (prev_index.saturating_add(1), count),
                    &mut entries,
                )
            {
                // Refused by the duty's budget or the log: lost.
                self.spare.append(&mut entries);
                self.vectors.push(entries);
                continue;
            }
            out.ready.messages.push((
                to,
                Message {
                    core: message,
                    entries,
                },
            ));
        }
        self.outgoing = outgoing;
        self.outgoing.clear();
        for (to, message) in self.after.drain(..) {
            if let Some(to) = node_id(to) {
                out.ready.after_persist.push((
                    to,
                    Message {
                        core: message,
                        entries: Vec::new(),
                    },
                ));
            }
        }
        // Committed entries, written or in this Ready, from the last
        // handed out: `drive` applies them once this Ready is durable.
        let commit = self.core.commit();
        if commit > self.handed {
            let first = self.handed.saturating_add(1);
            let mut committed = std::mem::take(&mut out.ready.committed);
            if self.fill(out, log, (first, commit - self.handed), &mut committed) {
                self.handed = commit;
            } else {
                // A refused read applies none; the next Ready retries.
                self.spare.append(&mut committed);
            }
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
