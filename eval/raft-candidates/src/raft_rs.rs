// SPDX-License-Identifier: Apache-2.0

//! `raft` 0.7.0 behind [`ConsensusCore`] (plan issue 060, karyos#678).
//!
//! raft-rs is caller driven, which is the shape the harness's trait was
//! written after: [`ConsensusCore::ready`] takes a `RawNode` Ready,
//! [`drive`](karyos_sim::harness::core::drive) persists it to C4's log,
//! and [`ConsensusCore::advance`] hands it back; the `LightReady` that
//! `advance` returns (the commit, entries committed and messages that
//! needed the persistence) is the next [`Ready`].
//!
//! **Storage.** raft-rs owns its `Storage` and reads it inside its own
//! calls, so it cannot read through the borrowed [`LogView`]. The adapter
//! gives it a `MemStorage` mirror of what C4's log made durable, filled at
//! [`ConsensusCore::recover`] from the log and updated at each
//! [`ConsensusCore::advance`], after the persistence it mirrors. C4's log
//! stays the only durable copy: a restart rebuilds the mirror from it. A
//! consequence the evaluation reports: raft-rs's reads (entries for a
//! follower, committed entries to apply) come from the mirror, so the
//! harness's metered [`LogView`] does not see them on their own. Under
//! declared limits the adapter therefore reads every entry an outgoing
//! append carries from C4's log again, through the duty's metered
//! [`LogView`], before the append leaves (`RaftCore::meter`,
//! karyos#975): an append whose logged entries the budget cannot cover
//! is not sent this duty, as if the network lost it, and raft-rs resends
//! it as it does after a loss. The log-read limit is then the measured
//! bytes the harness charges, not the mirror's.
//!
//! **Timing and determinism** (C5 v2 manifest, Timing: heartbeat 5
//! ticks, election timeouts in `[15, 30)` ticks from a seeded source).
//! One harness step is one raft-rs tick. raft-rs draws each election
//! timeout with `rand::thread_rng()` from `[min_election_tick,
//! max_election_tick)`, a source the adapter cannot seed, so it takes the
//! manifest's fallback: the adapter sets `max = min + 1`, so the draw has
//! one value and the run is reproducible from its seed, and gives each
//! server a fixed value in `[15, 30)`, spread evenly by its position in
//! the voter set ([`election_ticks`]), no two equal. The report names
//! that as this adapter's deviation from the frozen timing; raft-rs keeps
//! the value at every reset.
//!
//! **Pre-vote** (SPEC.md §9, "pre-vote") is raft-rs's own `pre_vote`, on
//! in [`RaftRs`] and off only in [`RaftRsNoPreVote`], the negative
//! control. `check_quorum` is on, so a leader that has lost its quorum
//! steps down.
//!
//! **Declared limits** (W2, karyos#679): `recover_with` takes them. One
//! entry per append (`max_size_per_msg = 0`) and at most
//! `in_flight_entries` appends unacknowledged (`max_inflight_msgs`); the
//! queue and the in-flight bytes are refused in `propose`
//! ([`refuse_past`], the byte cap kept by entry size); an entry cap outside
//! `1..=MAX_IN_FLIGHT_ENTRIES` is `Unsupported`. Two gaps are findings:
//! raft-rs frees a window slot when a heartbeat answer arrives while the
//! window is full (its recovery from lost acknowledgements), so the caps
//! hold strictly only while acknowledgements are not delayed past a
//! heartbeat. Log reads come from the `MemStorage` mirror, and are
//! charged to the metered log by `RaftCore::meter` before an append
//! leaves (karyos#975).
//!
//! **Not taken here:** snapshots and compaction (W5, karyos#679): they
//! answer `Unsupported`, which the harness reports as not demonstrated.
//!
//! **Panics.** raft-rs asserts its own invariants (`assert!`, `fatal!`)
//! and unwraps its `MemStorage` lock. The adapter never panics itself;
//! a panic inside the candidate is a finding of the evaluation, not
//! something the adapter hides.

use karyos_cluster::{Entry, HardState};
use karyos_sim::harness::core::{
    ConsensusCore, Limit, Limits, LogView, NotLeader, Persisted, Ready, ReadyBuf, Refused,
    TransferRefused, Unsupported,
};
use karyos_sim::net::NodeId;
use raft::eraftpb::{self, ConfState, Snapshot};
use raft::storage::MemStorage;
use raft::{Config, RawNode, StateRole, Storage};

use crate::variant::Variant;

/// The build of `raft` this adapter runs: the admitted release, unpatched.
pub const VARIANT: Variant = Variant::Baseline;

/// Ticks between a leader's heartbeats: one harness step is one tick
/// (C5 v2 manifest, Timing).
pub const HEARTBEAT_TICKS: usize = 5;

/// The shortest election timeout, in ticks (C5 v2 manifest, Timing).
pub const ELECTION_TICKS: usize = 15;

/// One past the longest election timeout, in ticks: timeouts are in
/// `ELECTION_TICKS..ELECTION_END` (C5 v2 manifest, Timing).
pub const ELECTION_END: usize = 30;

/// Ticks one [`ConsensusCore::tick`] call runs at most: a clock that
/// jumps never makes a single call unbounded.
pub const MAX_TICKS_PER_CALL: u64 = 64;

/// Bytes of entries per append message.
pub const MAX_SIZE_PER_MSG: u64 = 1024 * 1024;

/// Append messages in flight per follower.
pub const MAX_INFLIGHT_MSGS: usize = 256;

/// `raft` 0.7.0 with pre-vote on: the evaluated core.
pub type RaftRs = RaftCore<true>;

/// `raft` 0.7.0 with pre-vote off: only the negative control of the
/// pre-vote test, never evaluated.
pub type RaftRsNoPreVote = RaftCore<false>;

/// [`RaftRs`] with a batch entry cap of 16, W1's primary batch limit
/// (quantstratum-docs: karyos/evaluations/c5-raft-comparison-v1.md, W1;
/// karyos#691), for W1's allocation case of [`BATCH_PAYLOAD`]-byte
/// payloads. raft-rs caps an append by bytes (`max_size_per_msg`), not by
/// entries, so the configuration sets the cap, from startup, to `BATCH`
/// encoded entries of that case's command at index 1 and term 1, the
/// smallest such an entry is: an append then holds at most 16 of them,
/// fewer at larger indices. It is not an entry count: entries smaller than
/// the case's (a new leader's empty entry) could let more through, which
/// the append observation test (`tests/batch.rs`) would catch.
pub type RaftRsBatch16 = RaftCore<true, 16>;

/// The entries an outgoing message appends and their payload bytes, for a
/// test that observes appends (karyos#691); `None` for any other message.
#[must_use]
pub fn append_shape(message: &eraftpb::Message) -> Option<(usize, u64)> {
    (message.get_msg_type() == eraftpb::MessageType::MsgAppend).then(|| {
        let bytes = message.entries.iter().fold(0u64, |sum, entry| {
            sum.saturating_add(u64::try_from(entry.data.len()).unwrap_or(u64::MAX))
        });
        (message.entries.len(), bytes)
    })
}

/// An append's leader term and its entries as (index, payload bytes),
/// read from the message itself for an oracle that never trusts the
/// adapter's counters (C5 version 2's W2 byte case; karyos#691); `None`
/// for any other message.
#[must_use]
pub fn append_entries(message: &eraftpb::Message) -> Option<(u64, Vec<(u64, u64)>)> {
    (message.get_msg_type() == eraftpb::MessageType::MsgAppend).then(|| {
        let entries = message
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.index,
                    u64::try_from(entry.data.len()).unwrap_or(u64::MAX),
                )
            })
            .collect();
        (message.term, entries)
    })
}

/// The term and index an accepted append response acknowledges; `None`
/// for any other message, a rejection or a heartbeat's answer (which
/// proves no matching prefix).
#[must_use]
pub fn append_ack(message: &eraftpb::Message) -> Option<(u64, u64)> {
    (message.get_msg_type() == eraftpb::MessageType::MsgAppendResponse && !message.reject)
        .then_some((message.term, message.index))
}

/// Node `id`'s election timeout among `voters`, `[min, max)` in ticks:
/// one value, so raft-rs's `thread_rng` draw is deterministic, in
/// `ELECTION_TICKS..ELECTION_END`, spread evenly by the node's position
/// among the voters (and itself) in id order, so no two of up to 15
/// voters share a timeout and elections do not split forever, whatever
/// the ids (karyos#956 review). Past 15 voters, positions share the last
/// value; the comparison runs 3 and 5.
#[must_use]
pub fn election_ticks(id: NodeId, voters: &[NodeId]) -> (usize, usize) {
    let position = voters.iter().filter(|&&voter| voter < id).count();
    let span = ELECTION_END - ELECTION_TICKS;
    let step = (span / voters.len().max(1)).max(1);
    let min = ELECTION_TICKS
        .saturating_add(position.saturating_mul(step))
        .min(ELECTION_END - 1);
    (min, min.saturating_add(1))
}

/// The largest entry cap either adapter takes: raft-rs allocates its
/// in-flight window eagerly (`Inflights::new`), so a cap past this would
/// panic on allocation or, where it does not fit a `usize`, start an inert
/// core; both adapters refuse it as `Unsupported` before startup
/// (karyos#963 review). W2's caps are 4 (skeleton) and 64 (manifest).
pub const MAX_IN_FLIGHT_ENTRIES: u64 = 1 << 16;

/// Whether both adapters take `limits`: an entry cap in
/// `1..=MAX_IN_FLIGHT_ENTRIES` that fits a `usize`.
#[must_use]
pub fn limits_supported(limits: &Limits) -> bool {
    (1..=MAX_IN_FLIGHT_ENTRIES).contains(&limits.in_flight_entries)
        && usize::try_from(limits.in_flight_entries).is_ok()
}

/// The W2 refusal of a proposal of `command` by a leader whose log ends
/// at `last` and commits `committed`: a command larger than its share of
/// the in-flight bytes, or one past the queue of proposals held and not
/// committed. A count that does not fit fails closed, as a full queue.
///
/// Neither candidate meters the bytes it has in flight to a follower:
/// each caps only the entries (raft-rs one entry per append and at most
/// `in_flight_entries` appends unacknowledged; OpenRaft one append of at
/// most `in_flight_entries` entries). So the byte cap is kept by the
/// entries' size instead: no command passes `in_flight_bytes /
/// in_flight_entries`, and a follower's full window of entries never
/// passes `in_flight_bytes` however many commands queue behind it
/// (karyos#963 review). A command within the cap but over its share is
/// refused: a finding of the comparison.
///
/// # Errors
///
/// [`Refused::Backpressure`] naming the limit.
pub fn refuse_past(
    limits: &Limits,
    command: &[u8],
    last: u64,
    committed: u64,
) -> Result<(), Refused> {
    let share = limits
        .in_flight_bytes
        .checked_div(limits.in_flight_entries)
        .unwrap_or(0);
    if u64::try_from(command.len()).map_or(true, |bytes| bytes > share) {
        return Err(Refused::Backpressure(Limit::InFlightBytes));
    }
    let held = last.checked_sub(committed);
    if held.is_none_or(|held| held >= limits.queue) {
        return Err(Refused::Backpressure(Limit::Queue));
    }
    Ok(())
}

/// raft-rs's id of harness node `id`: raft-rs refuses 0.
#[must_use]
pub fn raft_id(id: NodeId) -> u64 {
    // A u32 plus one always fits a u64.
    u64::from(id).saturating_add(1)
}

/// The harness node of raft-rs id `id`, if it names one.
#[must_use]
pub fn node_id(id: u64) -> Option<NodeId> {
    id.checked_sub(1).and_then(|id| NodeId::try_from(id).ok())
}

/// A harness entry as raft-rs holds it: the event time travels in the
/// entry's context.
#[must_use]
pub fn to_raft(entry: &Entry) -> eraftpb::Entry {
    eraftpb::Entry {
        index: entry.index,
        term: entry.term,
        data: entry.payload.clone().into(),
        context: entry.event_time.to_le_bytes().to_vec().into(),
        ..eraftpb::Entry::default()
    }
}

/// A raft-rs entry as the harness logs it.
#[must_use]
pub fn from_raft(entry: &eraftpb::Entry) -> Entry {
    let context: &[u8] = entry.context.as_ref();
    let event_time = <[u8; 8]>::try_from(context).map_or(0, u64::from_le_bytes);
    Entry {
        index: entry.index,
        term: entry.term,
        event_time,
        payload: entry.data.to_vec(),
    }
}

/// [`from_raft`] into a buffer of `out`'s pool (plan issue 073,
/// karyos#691): the payload is copied into a kept buffer, not a new one.
fn from_raft_into<M>(out: &mut ReadyBuf<M>, entry: &eraftpb::Entry) -> Entry {
    let context: &[u8] = entry.context.as_ref();
    let event_time = <[u8; 8]>::try_from(context).map_or(0, u64::from_le_bytes);
    out.entry(entry.index, entry.term, event_time, entry.data.as_ref())
}

/// Whether the entries of an outgoing append, `sent`, that C4's log holds
/// were read back through the metered `log` within the duty's budget and
/// equal the log's (karyos#975, karyos#1040): both adapters send an append
/// only when this holds. Entries past the log (a leader's own, sent
/// before its persistence) are no log read; a read the budget cut short,
/// a read error or a mismatch is not a read back.
pub(crate) fn read_back(sent: &[Entry], log: &mut LogView<'_>, reads: &mut ReadBack) -> bool {
    let (Some(first), Some(last)) = (sent.first(), sent.last()) else {
        return true;
    };
    let Some(end) = last.index.checked_add(1) else {
        return false;
    };
    // The borrowed read, into the adapter's kept buffers (C5 v2,
    // "Borrowed forms": no variant is charged for the owned vectors of
    // `LogView::entries`).
    if log
        .entries_into(
            first.index..end,
            u64::MAX,
            &mut reads.read,
            &mut reads.window,
        )
        .is_err()
    {
        return false;
    }
    let read = &reads.read;
    let matches = read.iter().zip(sent).all(|(logged, sent)| logged == sent);
    // Every entry past what was read must be one the log does not hold
    // yet: a shorter read cut by the budget is not a read back.
    let unread = sent.get(read.len()).map(|entry| entry.index);
    let held = unread.is_some_and(|index| log.last_index().is_some_and(|last| index <= last));
    matches && !held
}

/// The buffers of [`read_back`], kept by an adapter across duties: the
/// entries read back and the log's read window, reused by
/// `LogView::entries_into` once they fit (C5 v2, "Borrowed forms").
#[derive(Debug, Default)]
pub(crate) struct ReadBack {
    /// The entries the last read back took from the log.
    read: Vec<Entry>,
    /// The log's read window.
    window: Vec<u8>,
}

/// The W1 payload [`RaftRsBatch16`]'s byte cap is sized for (W1's
/// allocation case, `W1 n=3 payload=32 clients=32`).
pub const BATCH_PAYLOAD: usize = 32;

/// The command a client of W1's allocation case proposes: an append of a
/// [`BATCH_PAYLOAD`]-byte value; its encoded length does not depend on the
/// client or the sequence number.
fn batch_command() -> Vec<u8> {
    karyos_sim::harness::node::Command {
        client: 0,
        sequence: 1,
        op: karyos_sim::harness::node::Op::Append(vec![0u8; BATCH_PAYLOAD]),
    }
    .encode()
}

/// The append byte cap that holds `entries` entries carrying `command`,
/// each sized at index 1 and term 1 with the adapter's 8-byte event time
/// context: the smallest such an entry can be.
fn batch_cap(entries: u64, command: &[u8]) -> u64 {
    use protobuf::Message as _;
    entries.saturating_mul(u64::from(sized_entry(1, command).compute_size()))
}

/// An entry of term 1 at `index` carrying `command` and an 8-byte context,
/// as the adapter proposes it: what [`batch_cap`] sizes.
fn sized_entry(index: u64, command: &[u8]) -> eraftpb::Entry {
    eraftpb::Entry {
        term: 1,
        index,
        data: command.to_vec().into(),
        context: vec![0u8; 8].into(),
        ..eraftpb::Entry::default()
    }
}

/// raft-rs's hard state as C4 stores it.
fn hard_state_of(state: &eraftpb::HardState) -> HardState {
    HardState {
        current_term: state.term,
        voted_for: (state.vote != 0)
            .then(|| node_id(state.vote))
            .flatten()
            .map(u64::from),
        commit: (state.commit != 0).then_some(state.commit),
    }
}

/// C4's stored hard state as raft-rs holds it.
fn raft_hard_state(state: &HardState) -> eraftpb::HardState {
    eraftpb::HardState {
        term: state.current_term,
        vote: state
            .voted_for
            .and_then(|vote| NodeId::try_from(vote).ok())
            .map_or(0, raft_id),
        commit: state.commit.unwrap_or(0),
        ..eraftpb::HardState::default()
    }
}

fn push_messages(out: &mut Vec<(NodeId, eraftpb::Message)>, messages: Vec<eraftpb::Message>) {
    out.extend(
        messages
            .into_iter()
            .filter_map(|message| Some((node_id(message.to)?, message))),
    );
}

/// `raft` 0.7.0's `RawNode` behind [`ConsensusCore`], pre-vote on when
/// `PRE_VOTE` (see the module).
pub struct RaftCore<const PRE_VOTE: bool, const BATCH: u64 = 0> {
    /// `None` when the log could not be read or raft-rs refused its
    /// configuration at recovery: the node stays silent (it never votes,
    /// leads or answers), which is safe, and the harness sees it as down.
    node: Option<RawNode<MemStorage>>,
    /// The raft-rs Ready handed out and not yet advanced.
    pending: Option<raft::Ready>,
    /// What raft-rs released after the last persistence, not handed out,
    /// with the hard state its commit advance asks to save.
    light: Option<(raft::LightReady, Option<HardState>)>,
    /// The clock at the last tick.
    last_tick: Option<u64>,
    /// The clock at the last tick, as the event time of what it proposes.
    now: u64,
    /// The declared limits (W2), when started with them.
    limits: Option<Limits>,
    /// The kept buffers of the metered read back ([`read_back`]).
    reads: ReadBack,
}

impl<const PRE_VOTE: bool, const BATCH: u64> std::fmt::Debug for RaftCore<PRE_VOTE, BATCH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaftCore")
            .field("pre_vote", &PRE_VOTE)
            .field("term", &self.term())
            .field("leads", &self.leads())
            .field("committed", &self.committed())
            .finish_non_exhaustive()
    }
}

impl<const PRE_VOTE: bool, const BATCH: u64> RaftCore<PRE_VOTE, BATCH> {
    /// Whether the core is running: its log was read and raft-rs took its
    /// configuration.
    #[must_use]
    pub fn running(&self) -> bool {
        self.node.is_some()
    }

    /// The leader raft-rs knows of, if any.
    #[must_use]
    pub fn leader(&self) -> Option<NodeId> {
        self.node
            .as_ref()
            .and_then(|node| node_id(node.raft.leader_id))
    }

    /// The mirror's last index.
    fn mirrored_last(&self) -> Option<u64> {
        let node = self.node.as_ref()?;
        node.store().last_index().ok()
    }

    /// Under declared limits, `messages` with every append whose entries
    /// C4's log holds read again through the metered `log` (karyos#975):
    /// an append is kept only when each of its entries the log holds was
    /// read within the duty's budget and matches the mirror's; otherwise
    /// it is held back this duty, as a lost message, and raft-rs resends
    /// it. Entries the log does not hold yet (a leader's own, sent before
    /// its persistence) are not a log read. Unmetered, `messages` as is.
    fn meter(
        limited: bool,
        reads: &mut ReadBack,
        messages: &mut Vec<(NodeId, eraftpb::Message)>,
        log: &mut LogView<'_>,
    ) {
        if limited {
            messages.retain(|(_, message)| Self::read_back(message, log, reads));
        }
    }

    /// Whether `message`'s logged entries were read back through `log`,
    /// into the kept `reads`.
    fn read_back(message: &eraftpb::Message, log: &mut LogView<'_>, reads: &mut ReadBack) -> bool {
        if message.get_msg_type() != eraftpb::MessageType::MsgAppend {
            return true;
        }
        let sent: Vec<Entry> = message.entries.iter().map(from_raft).collect();
        read_back(&sent, log, reads)
    }

    /// Stops the core: a mirror write failed, so raft-rs's view of its
    /// storage is no longer the log's.
    fn fault(&mut self) {
        self.node = None;
        self.pending = None;
        self.light = None;
    }

    fn build(
        id: NodeId,
        peers: &[NodeId],
        limits: Option<&Limits>,
        log: &mut LogView<'_>,
    ) -> Option<RawNode<MemStorage>> {
        let voters: Vec<u64> = peers.iter().copied().map(raft_id).collect();
        let storage = MemStorage::new_with_conf_state(ConfState::from((voters.clone(), vec![])));
        let mut applied = 0;
        if let Some(base) = log.base() {
            let mut snapshot = Snapshot::default();
            snapshot.mut_metadata().index = base.index;
            snapshot.mut_metadata().term = base.term;
            *snapshot.mut_metadata().mut_conf_state() = ConfState::from((voters, vec![]));
            storage.wl().apply_snapshot(snapshot).ok()?;
            applied = base.index;
        }
        if let Some(last) = log.last_index() {
            let end = last.checked_add(1)?;
            // Entries the snapshot covers stay out of the mirror: raft-rs
            // refuses to overwrite what its snapshot compacted.
            let first = log.first_index().max(applied.checked_add(1)?);
            if first < end {
                let entries = log.entries(first..end, u64::MAX).ok()?;
                let raft: Vec<eraftpb::Entry> = entries.iter().map(to_raft).collect();
                storage.wl().append(&raft).ok()?;
            }
        }
        if let Some(state) = log.hard_state() {
            storage.wl().set_hardstate(raft_hard_state(&state));
        }
        let (min, max) = election_ticks(id, peers);
        let config = Config {
            id: raft_id(id),
            election_tick: ELECTION_TICKS,
            heartbeat_tick: HEARTBEAT_TICKS,
            min_election_tick: min,
            max_election_tick: max,
            // Under declared limits, one entry per append (raft-rs keeps at
            // least one whatever the size cap) and at most the in-flight
            // entries' count of appends in raft-rs's window. Not strict:
            // raft-rs frees a full window's slot when a heartbeat answer
            // arrives, so with acknowledgements delayed past a heartbeat
            // more appends, and their bytes, are unacknowledged than the
            // caps (`window::a_heartbeat_answer_frees_a_full_window_slot`,
            // karyos#975).
            max_size_per_msg: if limits.is_some() {
                0
            } else if BATCH > 0 {
                batch_cap(BATCH, &batch_command())
            } else {
                MAX_SIZE_PER_MSG
            },
            max_inflight_msgs: limits.map_or(Some(MAX_INFLIGHT_MSGS), |limits| {
                usize::try_from(limits.in_flight_entries).ok()
            })?,
            check_quorum: true,
            pre_vote: PRE_VOTE,
            applied,
            ..Config::default()
        };
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        RawNode::new(&config, storage, &logger).ok()
    }
}

impl<const PRE_VOTE: bool, const BATCH: u64> ConsensusCore for RaftCore<PRE_VOTE, BATCH> {
    type Message = eraftpb::Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self {
            node: Self::build(id, peers, None, log),
            pending: None,
            light: None,
            last_tick: None,
            now: 0,
            limits: None,
            reads: ReadBack::default(),
        }
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        // No entry in flight is no replication, and a window too large to
        // allocate would panic: refused before startup, not a core without
        // Raft (karyos#963 review).
        if !limits_supported(limits) {
            return Err(Unsupported);
        }
        Ok(Self {
            node: Self::build(id, peers, Some(limits), log),
            pending: None,
            light: None,
            last_tick: None,
            now: 0,
            limits: Some(*limits),
            reads: ReadBack::default(),
        })
    }

    fn propose(&mut self, command: Vec<u8>, _log: &mut LogView<'_>) -> Result<(), Refused> {
        let leader = self.leader();
        let Some(node) = self.node.as_mut() else {
            return Err(NotLeader { leader: None }.into());
        };
        if node.raft.state != StateRole::Leader {
            return Err(NotLeader { leader }.into());
        }
        if let Some(limits) = self.limits {
            refuse_past(
                &limits,
                &command,
                node.raft.raft_log.last_index(),
                node.raft.raft_log.committed,
            )?;
        }
        // Dropped while it hands its leadership over, or past raft-rs's
        // own uncommitted limit: either way, not taken.
        node.propose(self.now.to_le_bytes().to_vec(), command)
            .map_err(|_| Refused::NotLeader(NotLeader { leader }))
    }

    fn step(&mut self, _from: NodeId, message: Self::Message, _log: &mut LogView<'_>) {
        if let Some(node) = self.node.as_mut() {
            // A message raft-rs refuses (a stale or local one) is dropped,
            // as a network would.
            let _ = node.step(message);
        }
    }

    /// raft-rs's `RawNode::step` takes its message by value: the lent one
    /// is moved out, and raft-rs's own types free it inside the call (C5
    /// v3: the library's, counted).
    fn step_lent(&mut self, from: NodeId, message: &mut Self::Message, log: &mut LogView<'_>) {
        self.step(from, std::mem::take(message), log);
    }

    fn tick(&mut self, now: u64, _log: &mut LogView<'_>) {
        let ticks = self
            .last_tick
            .map_or(0, |last| now.saturating_sub(last).min(MAX_TICKS_PER_CALL));
        self.last_tick = Some(now);
        self.now = now;
        if let Some(node) = self.node.as_mut() {
            for _ in 0..ticks {
                let _ = node.tick();
            }
        }
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        let mut out = ReadyBuf::default();
        self.ready_into(&mut out, log).then_some(out.ready)
    }

    /// raft-rs's Ready copied into `out` in place: its messages moved over,
    /// its entries' payloads copied into `out`'s kept buffers.
    fn ready_into(&mut self, out: &mut ReadyBuf<Self::Message>, log: &mut LogView<'_>) -> bool {
        if let Some((mut light, hard_state)) = self.light.take() {
            push_messages(&mut out.ready.messages, light.take_messages());
            Self::meter(
                self.limits.is_some(),
                &mut self.reads,
                &mut out.ready.messages,
                log,
            );
            out.ready.hard_state = hard_state;
            for entry in &light.take_committed_entries() {
                let entry = from_raft_into(out, entry);
                out.ready.committed.push(entry);
            }
            return true;
        }
        if self.pending.is_some() {
            return false;
        }
        let mirrored = self.mirrored_last();
        let Some(node) = self.node.as_mut() else {
            return false;
        };
        if !node.has_ready() {
            return false;
        }
        let mut raw = node.ready();
        let first = raw.entries().first().map(|entry| entry.index);
        push_messages(&mut out.ready.messages, raw.take_messages());
        let limited = self.limits.is_some();
        Self::meter(limited, &mut self.reads, &mut out.ready.messages, log);
        push_messages(&mut out.ready.after_persist, raw.take_persisted_messages());
        Self::meter(limited, &mut self.reads, &mut out.ready.after_persist, log);
        out.ready.truncate_from = first.filter(|first| mirrored.is_some_and(|last| *first <= last));
        for entry in raw.entries() {
            let entry = from_raft_into(out, entry);
            out.ready.entries.push(entry);
        }
        out.ready.hard_state = raw.hs().map(hard_state_of);
        for entry in &raw.take_committed_entries() {
            let entry = from_raft_into(out, entry);
            out.ready.committed.push(entry);
        }
        self.pending = Some(raw);
        true
    }

    fn advance(&mut self, _persisted: Persisted, _log: &mut LogView<'_>) {
        let Some(raw) = self.pending.take() else {
            return;
        };
        let Some(node) = self.node.as_mut() else {
            return;
        };
        // The mirror follows what the log made durable.
        let mirrored = {
            let store = node.store();
            let mut core = store.wl();
            let appended = core.append(raw.entries()).is_ok();
            if let Some(state) = raw.hs() {
                core.set_hardstate(state.clone());
            }
            appended
        };
        if !mirrored {
            self.fault();
            return;
        }
        let light = node.advance(raw);
        let hard_state = light.commit_index().map(|commit| {
            let mut state = node.raft.hard_state();
            state.commit = commit;
            hard_state_of(&state)
        });
        let committed = !light.committed_entries().is_empty();
        if committed {
            node.advance_apply();
        }
        // Handed out by the next `ready_into`, converted there.
        if committed || hard_state.is_some() || !light.messages().is_empty() {
            self.light = Some((light, hard_state));
        }
    }

    fn term(&self) -> u64 {
        self.node.as_ref().map_or(0, |node| node.raft.term)
    }

    fn leads(&self) -> bool {
        self.node
            .as_ref()
            .is_some_and(|node| node.raft.state == StateRole::Leader)
    }

    fn received(&self) -> Option<u64> {
        let last = self.node.as_ref()?.raft.raft_log.last_index();
        (last != 0).then_some(last)
    }

    fn committed(&self) -> Option<u64> {
        let committed = self.node.as_ref()?.raft.raft_log.committed;
        (committed != 0).then_some(committed)
    }

    fn transfer_leadership(
        &mut self,
        to: NodeId,
        _log: &mut LogView<'_>,
    ) -> Result<(), TransferRefused> {
        let leader = self.leader();
        let node = self
            .node
            .as_mut()
            .ok_or(TransferRefused::NotLeader(NotLeader { leader: None }))?;
        if node.raft.state != StateRole::Leader {
            return Err(TransferRefused::NotLeader(NotLeader { leader }));
        }
        let target = raft_id(to);
        if target == node.raft.id || !node.raft.prs().conf().voters().contains(target) {
            return Err(TransferRefused::Invalid);
        }
        node.transfer_leader(target);
        Ok(())
    }
}

impl<const PRE_VOTE: bool, const BATCH: u64> crate::process::Wire for RaftCore<PRE_VOTE, BATCH> {
    fn encode_into(message: &eraftpb::Message, out: &mut Vec<u8>) -> bool {
        out.clear();
        protobuf::Message::write_to_vec(message, out).is_ok()
    }

    fn decode(bytes: &[u8]) -> Option<eraftpb::Message> {
        protobuf::Message::parse_from_bytes(bytes).ok()
    }

    /// raft-rs's messages are `protobuf` values that its `step` takes by
    /// value: each is decoded into a new one, its entries' `Bytes`
    /// included (the library's types; C5 v3).
    type Decoder = Option<eraftpb::Message>;

    fn decoder() -> Self::Decoder {
        None
    }

    fn decode_lent<'a>(
        decoder: &'a mut Self::Decoder,
        bytes: &[u8],
    ) -> Option<&'a mut eraftpb::Message> {
        *decoder = protobuf::Message::parse_from_bytes(bytes).ok();
        decoder.as_mut()
    }

    fn appended(message: &eraftpb::Message) -> Option<(u64, Vec<(u64, u64)>)> {
        append_entries(message)
    }

    fn acknowledged(message: &eraftpb::Message) -> Option<(u64, u64)> {
        append_ack(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// raft-rs's messages into the runner's reused buffer, longer before:
    /// the bytes `protobuf` gives, and decoded into the runner's slot, the
    /// same message (C5 v3).
    #[test]
    fn messages_encode_into_a_reused_buffer() {
        use crate::process::Wire as _;
        let mut message = eraftpb::Message::default();
        message.set_msg_type(eraftpb::MessageType::MsgAppend);
        message.term = 4;
        message.entries.push(eraftpb::Entry {
            index: 5,
            data: vec![7; 40].into(),
            ..eraftpb::Entry::default()
        });
        let bytes = protobuf::Message::write_to_bytes(&message).unwrap();
        let mut out = vec![0xAA; bytes.len() + 64];
        assert!(RaftRs::encode_into(&message, &mut out));
        assert_eq!(out, bytes);
        let mut decoder = RaftRs::decoder();
        assert_eq!(
            RaftRs::decode_lent(&mut decoder, &out).cloned(),
            Some(message)
        );
    }

    /// The oracle's reading of raft-rs's appends (karyos#691): each
    /// entry's index and payload bytes, an accepted answer's index, and
    /// nothing from a rejection or a heartbeat's answer.
    #[test]
    fn appends_and_their_answers_are_read_from_the_message() {
        let mut append = eraftpb::Message::default();
        append.set_msg_type(eraftpb::MessageType::MsgAppend);
        append.term = 4;
        for (index, bytes) in [(5_u64, 100_usize), (6, 0)] {
            append.entries.push(eraftpb::Entry {
                index,
                data: vec![1; bytes].into(),
                ..eraftpb::Entry::default()
            });
        }
        assert_eq!(append_entries(&append), Some((4, vec![(5, 100), (6, 0)])));
        let mut reply = eraftpb::Message::default();
        reply.set_msg_type(eraftpb::MessageType::MsgAppendResponse);
        reply.term = 4;
        reply.index = 6;
        assert_eq!(append_ack(&reply), Some((4, 6)));
        reply.reject = true;
        assert_eq!(append_ack(&reply), None);
        let mut beat = eraftpb::Message::default();
        beat.set_msg_type(eraftpb::MessageType::MsgHeartbeatResponse);
        beat.term = 4;
        assert_eq!(append_ack(&beat), None);
        assert_eq!(append_entries(&beat), None);
    }

    /// The batch cap of [`RaftRsBatch16`] keeps an append at 16 entries or
    /// fewer of the command it was sized for, at any index (karyos#691).
    #[test]
    fn the_batch_cap_holds_at_most_sixteen_entries() {
        let command = batch_command();
        let cap = batch_cap(16, &command);
        for first in [1u64, 200, 70_000] {
            let mut entries: Vec<eraftpb::Entry> = (first..first + 40)
                .map(|index| sized_entry(index, &command))
                .collect();
            raft::util::limit_size(&mut entries, Some(cap));
            assert!(
                (1..=16).contains(&entries.len()),
                "{first}: {}",
                entries.len()
            );
        }
        // Entries of the size it was computed for: exactly 16.
        let mut sized: Vec<eraftpb::Entry> = (0..40).map(|_| sized_entry(1, &command)).collect();
        raft::util::limit_size(&mut sized, Some(cap));
        assert_eq!(sized.len(), 16);
    }

    #[test]
    fn an_entry_round_trips_through_raft_rs_with_its_event_time() {
        let entry = Entry {
            index: 7,
            term: 3,
            event_time: 0xDEAD_BEEF,
            payload: vec![1, 2, 3],
        };
        assert_eq!(from_raft(&to_raft(&entry)), entry);
    }

    #[test]
    fn node_ids_map_to_nonzero_raft_ids_and_back() {
        for id in [0, 1, 2, NodeId::MAX] {
            assert_ne!(raft_id(id), 0);
            assert_eq!(node_id(raft_id(id)), Some(id));
        }
        assert_eq!(node_id(0), None);
    }

    #[test]
    fn each_election_timeout_has_one_value_so_the_draw_is_deterministic() {
        let voters: Vec<NodeId> = (0..8).collect();
        for &id in &voters {
            let (min, max) = election_ticks(id, &voters);
            assert!(min >= ELECTION_TICKS);
            assert!(max <= ELECTION_END, "{id}: {min}..{max}");
            assert_eq!(max, min + 1);
        }
    }

    /// The karyos#956 review: ids with the same remainder must not share
    /// a timeout, or synchronized voters split every election.
    #[test]
    fn no_two_voters_share_an_election_timeout() {
        let fifteen: Vec<NodeId> = (0..15).collect();
        for voters in [vec![0, 3, 6], vec![1, 4, 7, 10, 13], vec![0, 1, 2], fifteen] {
            let ticks: BTreeSet<(usize, usize)> = voters
                .iter()
                .map(|&id| election_ticks(id, &voters))
                .collect();
            assert_eq!(ticks.len(), voters.len(), "{voters:?}");
        }
    }

    #[test]
    fn a_hard_state_round_trips_through_raft_rs() {
        let state = HardState {
            current_term: 4,
            voted_for: Some(0),
            commit: Some(9),
        };
        assert_eq!(hard_state_of(&raft_hard_state(&state)), state);
        let empty = HardState {
            current_term: 1,
            voted_for: None,
            commit: None,
        };
        assert_eq!(hard_state_of(&raft_hard_state(&empty)), empty);
    }

    /// karyos#975: an append's logged entries are read back through the
    /// metered view, and held back when the budget cannot cover them; a
    /// leader's own entries, not in the log yet, are no log read.
    #[test]
    fn an_append_leaves_only_once_its_logged_entries_are_read_within_the_budget() {
        use karyos_cluster::RaftLog;
        use karyos_sim::disk::SimDisk;
        use karyos_sim::harness::core::ReadBudget;
        use karyos_sim::harness::workloads;

        let entry = |index| Entry {
            index,
            term: 1,
            event_time: index,
            payload: vec![7; 100],
        };
        let mut log = RaftLog::create(
            SimDisk::new(),
            std::path::Path::new("log"),
            workloads::geometry().unwrap(),
            1,
        )
        .unwrap();
        let _ = log.append(&[entry(1), entry(2)]).unwrap();
        let _ = log.sync().unwrap();
        let append = |entries: &[Entry]| {
            let mut message = eraftpb::Message::default();
            message.set_msg_type(eraftpb::MessageType::MsgAppend);
            message.entries = entries.iter().map(to_raft).collect();
            message
        };
        let span = log.frame_span(1).unwrap();
        let budget = ReadBudget::new();
        // Both logged entries within the budget: sent, and charged.
        budget.refill(2 * span);
        let mut reads = ReadBack::default();
        let mut view = LogView::metered(&mut log, Some(&budget));
        assert!(RaftRs::read_back(
            &append(&[entry(1), entry(2)]),
            &mut view,
            &mut reads
        ));
        assert_eq!(budget.left(), 0);
        // The borrowed read keeps its buffers: a second read back of the
        // same entries reuses them, with no new vector (C5 v2, "Borrowed
        // forms").
        let kept = (
            reads.read.as_ptr(),
            reads.read.capacity(),
            reads.window.as_ptr(),
        );
        assert!(kept.1 >= 2);
        budget.refill(2 * span);
        let mut view = LogView::metered(&mut log, Some(&budget));
        assert!(RaftRs::read_back(
            &append(&[entry(1), entry(2)]),
            &mut view,
            &mut reads
        ));
        assert_eq!(
            (
                reads.read.as_ptr(),
                reads.read.capacity(),
                reads.window.as_ptr()
            ),
            kept
        );
        // One entry's budget for two logged entries: held back.
        budget.refill(span);
        let mut view = LogView::metered(&mut log, Some(&budget));
        assert!(!RaftRs::read_back(
            &append(&[entry(1), entry(2)]),
            &mut view,
            &mut reads
        ));
        // Nothing left: held back, nothing read.
        budget.refill(0);
        let mut view = LogView::metered(&mut log, Some(&budget));
        assert!(!RaftRs::read_back(
            &append(&[entry(2)]),
            &mut view,
            &mut reads
        ));
        // A leader's fresh entry, past the log: no read, sent.
        assert!(RaftRs::read_back(
            &append(&[entry(3)]),
            &mut view,
            &mut reads
        ));
        // An entry that differs from the log's: held back.
        budget.refill(span);
        let mut view = LogView::metered(&mut log, Some(&budget));
        let mut other = entry(1);
        other.payload = vec![8; 100];
        assert!(!RaftRs::read_back(&append(&[other]), &mut view, &mut reads));
    }

    #[test]
    fn the_evaluated_build_is_the_unpatched_release() {
        assert_eq!(VARIANT, Variant::Baseline);
        assert!(VARIANT.patches().is_empty());
    }
}

/// raft-rs's in-flight window under a delayed acknowledgement (karyos#963
/// review): pinned as a finding of the comparison, not enforced by the
/// adapter.
#[cfg(test)]
mod window {
    use raft::eraftpb::{ConfState, Message, MessageType};
    use raft::storage::MemStorage;
    use raft::{Config, RawNode};

    /// Runs every Ready, persisting into the store as `drive` would, and
    /// returns the messages released.
    fn drain(node: &mut RawNode<MemStorage>) -> Vec<Message> {
        let mut out = Vec::new();
        while node.has_ready() {
            let mut ready = node.ready();
            out.extend(ready.take_messages());
            {
                let store = node.store().clone();
                let mut core = store.wl();
                core.append(ready.entries()).unwrap();
                if let Some(state) = ready.hs() {
                    core.set_hardstate(state.clone());
                }
            }
            out.extend(ready.take_persisted_messages());
            let mut light = node.advance(ready);
            out.extend(light.take_messages());
            node.advance_apply();
        }
        out
    }

    fn from_follower(kind: MessageType, term: u64, index: u64) -> Message {
        let mut message = Message::default();
        message.set_msg_type(kind);
        message.from = 2;
        message.to = 1;
        message.term = term;
        message.index = index;
        message
    }

    /// With one append allowed in flight, the leader sends command A; a
    /// heartbeat answer arrives while A's acknowledgement is delayed, and
    /// raft-rs frees the window's slot and sends command B: two appends
    /// unacknowledged against a cap of one. This is how raft-rs recovers
    /// from lost acknowledgements (`handle_heartbeat_response`), so the
    /// adapter leaves it: the declared in-flight caps hold strictly only
    /// while acknowledgements are not delayed past a heartbeat.
    #[test]
    fn a_heartbeat_answer_frees_a_full_window_slot() {
        let storage = MemStorage::new_with_conf_state(ConfState::from((vec![1, 2], vec![])));
        let config = Config {
            id: 1,
            max_size_per_msg: 0,
            max_inflight_msgs: 1,
            ..Config::default()
        };
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let mut node = RawNode::new(&config, storage, &logger).unwrap();
        node.campaign().unwrap();
        let _ = drain(&mut node);
        let term = node.raft.term;
        node.step(from_follower(MessageType::MsgRequestVoteResponse, term, 0))
            .unwrap();
        let _ = drain(&mut node);
        assert_eq!(node.raft.state, raft::StateRole::Leader);
        // The follower takes the leader's first entry: replicating.
        let last = node.raft.raft_log.last_index();
        node.step(from_follower(MessageType::MsgAppendResponse, term, last))
            .unwrap();
        let _ = drain(&mut node);
        let appends = |messages: &[Message]| {
            messages
                .iter()
                .filter(|m| m.get_msg_type() == MessageType::MsgAppend && !m.entries.is_empty())
                .count()
        };
        node.propose(vec![], b"A".to_vec()).unwrap();
        node.propose(vec![], b"B".to_vec()).unwrap();
        let sent = appends(&drain(&mut node));
        assert_eq!(sent, 1, "the window holds one append");
        // A's acknowledgement is delayed; a heartbeat answer arrives.
        node.step(from_follower(MessageType::MsgHeartbeatResponse, term, 0))
            .unwrap();
        let more = appends(&drain(&mut node));
        assert_eq!(
            sent + more,
            2,
            "a second append left before the first was acknowledged"
        );
    }
}
