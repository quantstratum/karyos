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
//! harness's metered [`LogView`] does not see them.
//!
//! **Determinism.** raft-rs draws each election timeout with
//! `rand::thread_rng()` from `[min_election_tick, max_election_tick)`.
//! The adapter sets `max = min + 1`, so the draw has one value and the
//! run is reproducible from its seed; to keep elections from splitting,
//! each node's timeout is staggered by its position in the voter set
//! ([`election_ticks`]), so no two voters share one.
//!
//! **Pre-vote** (SPEC.md §9, "pre-vote") is raft-rs's own `pre_vote`, on
//! in [`RaftRs`] and off only in [`RaftRsNoPreVote`], the negative
//! control. `check_quorum` is on, so a leader that has lost its quorum
//! steps down.
//!
//! **Not taken here:** declared limits, snapshots and compaction (W2 and
//! W5, karyos#679): their defaults answer `Unsupported`, which the
//! harness reports as not demonstrated.
//!
//! **Panics.** raft-rs asserts its own invariants (`assert!`, `fatal!`)
//! and unwraps its `MemStorage` lock. The adapter never panics itself;
//! a panic inside the candidate is a finding of the evaluation, not
//! something the adapter hides.

use karyos_cluster::{Entry, HardState};
use karyos_sim::harness::core::{
    ConsensusCore, LogView, NotLeader, Persisted, Ready, Refused, TransferRefused,
};
use karyos_sim::net::NodeId;
use raft::eraftpb::{self, ConfState, Snapshot};
use raft::storage::MemStorage;
use raft::{Config, RawNode, StateRole, Storage};

use crate::variant::Variant;

/// The build of `raft` this adapter runs: the admitted release, unpatched.
pub const VARIANT: Variant = Variant::Baseline;

/// Ticks between a leader's heartbeats: one harness step is one tick.
pub const HEARTBEAT_TICKS: usize = 2;

/// The shortest election timeout, in ticks.
pub const ELECTION_TICKS: usize = 10;

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

/// Node `id`'s election timeout among `voters`, `[min, max)` in ticks:
/// one value, so raft-rs's `thread_rng` draw is deterministic, staggered
/// by the node's position among the voters (and itself) in id order, so
/// no two voters share a timeout and elections do not split forever,
/// whatever the ids (karyos#956 review).
#[must_use]
pub fn election_ticks(id: NodeId, voters: &[NodeId]) -> (usize, usize) {
    let position = voters.iter().filter(|&&voter| voter < id).count();
    let stagger = position.saturating_mul(3);
    let min = ELECTION_TICKS.saturating_add(stagger);
    (min, min.saturating_add(1))
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

fn messages_of(messages: Vec<eraftpb::Message>) -> Vec<(NodeId, eraftpb::Message)> {
    messages
        .into_iter()
        .filter_map(|message| Some((node_id(message.to)?, message)))
        .collect()
}

/// `raft` 0.7.0's `RawNode` behind [`ConsensusCore`], pre-vote on when
/// `PRE_VOTE` (see the module).
pub struct RaftCore<const PRE_VOTE: bool> {
    /// `None` when the log could not be read or raft-rs refused its
    /// configuration at recovery: the node stays silent (it never votes,
    /// leads or answers), which is safe, and the harness sees it as down.
    node: Option<RawNode<MemStorage>>,
    /// The raft-rs Ready handed out and not yet advanced.
    pending: Option<raft::Ready>,
    /// What raft-rs released after the last persistence, not handed out.
    light: Option<Ready<eraftpb::Message>>,
    /// The clock at the last tick.
    last_tick: Option<u64>,
    /// The clock at the last tick, as the event time of what it proposes.
    now: u64,
}

impl<const PRE_VOTE: bool> std::fmt::Debug for RaftCore<PRE_VOTE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaftCore")
            .field("pre_vote", &PRE_VOTE)
            .field("term", &self.term())
            .field("leads", &self.leads())
            .field("committed", &self.committed())
            .finish_non_exhaustive()
    }
}

impl<const PRE_VOTE: bool> RaftCore<PRE_VOTE> {
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

    /// Stops the core: a mirror write failed, so raft-rs's view of its
    /// storage is no longer the log's.
    fn fault(&mut self) {
        self.node = None;
        self.pending = None;
        self.light = None;
    }

    fn build(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Option<RawNode<MemStorage>> {
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
            max_size_per_msg: MAX_SIZE_PER_MSG,
            max_inflight_msgs: MAX_INFLIGHT_MSGS,
            check_quorum: true,
            pre_vote: PRE_VOTE,
            applied,
            ..Config::default()
        };
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        RawNode::new(&config, storage, &logger).ok()
    }
}

impl<const PRE_VOTE: bool> ConsensusCore for RaftCore<PRE_VOTE> {
    type Message = eraftpb::Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self {
            node: Self::build(id, peers, log),
            pending: None,
            light: None,
            last_tick: None,
            now: 0,
        }
    }

    fn propose(&mut self, command: Vec<u8>, _log: &mut LogView<'_>) -> Result<(), Refused> {
        let leader = self.leader();
        let Some(node) = self.node.as_mut() else {
            return Err(NotLeader { leader: None }.into());
        };
        if node.raft.state != StateRole::Leader {
            return Err(NotLeader { leader }.into());
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

    fn ready(&mut self, _log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        if let Some(light) = self.light.take() {
            return Some(light);
        }
        if self.pending.is_some() {
            return None;
        }
        let mirrored = self.mirrored_last();
        let node = self.node.as_mut()?;
        if !node.has_ready() {
            return None;
        }
        let mut raw = node.ready();
        let first = raw.entries().first().map(|entry| entry.index);
        let ready = Ready {
            messages: messages_of(raw.take_messages()),
            truncate_from: first.filter(|first| mirrored.is_some_and(|last| *first <= last)),
            entries: raw.entries().iter().map(from_raft).collect(),
            hard_state: raw.hs().map(hard_state_of),
            after_persist: messages_of(raw.take_persisted_messages()),
            committed: raw.take_committed_entries().iter().map(from_raft).collect(),
            snapshot_to: Vec::new(),
        };
        self.pending = Some(raw);
        Some(ready)
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
        let mut light = node.advance(raw);
        let hard_state = light.commit_index().map(|commit| {
            let mut state = node.raft.hard_state();
            state.commit = commit;
            hard_state_of(&state)
        });
        let ready = Ready {
            messages: messages_of(light.take_messages()),
            hard_state,
            committed: light
                .take_committed_entries()
                .iter()
                .map(from_raft)
                .collect(),
            ..Ready::default()
        };
        if !ready.committed.is_empty() {
            node.advance_apply();
        }
        if ready != Ready::default() {
            self.light = Some(ready);
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

impl<const PRE_VOTE: bool> crate::process::Wire for RaftCore<PRE_VOTE> {
    fn encode(message: &eraftpb::Message) -> Option<Vec<u8>> {
        protobuf::Message::write_to_bytes(message).ok()
    }

    fn decode(bytes: &[u8]) -> Option<eraftpb::Message> {
        protobuf::Message::parse_from_bytes(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
            assert_eq!(max, min + 1);
        }
    }

    /// The karyos#956 review: ids with the same remainder must not share
    /// a timeout, or synchronized voters split every election.
    #[test]
    fn no_two_voters_share_an_election_timeout() {
        for voters in [vec![0, 3, 6], vec![1, 4, 7, 10, 13], vec![0, 1, 2]] {
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

    #[test]
    fn the_evaluated_build_is_the_unpatched_release() {
        assert_eq!(VARIANT, Variant::Baseline);
        assert!(VARIANT.patches().is_empty());
    }
}
