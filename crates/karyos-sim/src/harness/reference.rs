// SPDX-License-Identifier: Apache-2.0

//! The harness's reference core: a fixed leader, no elections, commit
//! only on a durable-majority acknowledgement.
//!
//! **A harness fixture only.** It exists to exercise the harness, its
//! workloads and its checks with a core whose behaviour is known; it makes
//! no ADR-0039 custom-core claim and is no candidate of ADR-0043. With no
//! elections, a crash of its leader stops all progress: the workloads
//! report that as a liveness gap ([`super::workloads::Liveness`]), apart
//! from safety [`super::check::Violation`]s.
//!
//! Server [`LEADER`] leads [`TERM`] forever. It appends proposals, and
//! every [`RESEND`] ticks sends each follower the written entries after
//! the last index that follower acknowledged, read through the
//! [`LogView`], in batches of at most [`BATCH_BYTES`] frame bytes, with
//! its commit index. It keeps only what is not written yet. A follower appends what continues its log and
//! acknowledges its last index in `after_persist`, so [`super::core::drive`]
//! releases the acknowledgement only once that index is durable. The
//! leader commits the highest index a majority holds durably (itself
//! counted once its own persistence is reported), if that entry is of its
//! term. Every server saves its vote for the leader at its first Ready,
//! and its hard state at each commit change.
//!
//! **Limits** (W2; karyos#687). Started with [`Limits`], it honours them:
//! a proposal past [`Limits::queue`] requests held and not committed is
//! refused with [`Limit::Queue`]; each append message carries at most
//! [`Limits::in_flight_entries`] entries and [`Limits::in_flight_bytes`]
//! bytes, and since it resends from what a follower acknowledged, that is
//! all a follower has in flight; its log reads are held to the harness's
//! read budget, and a refused read sends nothing until the next resend.
//! As a fixture, it labels what it shows harness validation.
//!
//! **Membership** (phase 5; quantstratum-docs:
//! karyos/design/phase-5-cluster-scenarios.md, P5-S1). The leader takes
//! one [`Change`] at a time, once the last configuration entry is
//! committed, as a configuration entry ([`encode_configuration`]) that
//! takes effect when it is appended, committed or not, on every server
//! that holds it. A learner is promoted only within [`PROMOTION_LAG`]
//! entries of the leader's commit, as the leader knows its durable index.
//! The leader replicates to voters and learners and commits on a durable
//! majority of the voters alone. It cannot remove itself: there is no
//! election to replace it. A restart rebuilds the configuration from the
//! log.

use std::collections::BTreeMap;

use karyos_cluster::{Entry, HardState};

use super::core::{
    Change, ChangeRefused, Configuration, ConsensusCore, Limit, Limits, LogView, NotLeader,
    Persisted, Ready, Refused, Unsupported,
};
use crate::net::NodeId;

/// The fixed leader of a group whose servers are numbered from 0. A group
/// is led by the lowest id of its bootstrap peers, so a standby group
/// (phase 5, P5-S2) has its own.
pub const LEADER: NodeId = 0;
/// Its only term.
pub const TERM: u64 = 1;
/// Ticks between the leader's resends.
pub const RESEND: u64 = 4;
/// Frame bytes per append message at most (at least one entry).
pub const BATCH_BYTES: u64 = 16 * 1024;
/// Entries a learner may be behind the leader's commit and be promoted.
pub const PROMOTION_LAG: u64 = 4;
/// The tag every configuration entry's bytes start with, so it does not
/// decode as a command.
pub const CONFIG_MAGIC: [u8; 4] = *b"KR5C";

/// A configuration entry's bytes: [`CONFIG_MAGIC`], then the voters and
/// the learners, each a count and the ids, little endian.
#[must_use]
pub fn encode_configuration(voters: &[NodeId], learners: &[NodeId]) -> Vec<u8> {
    let mut bytes = CONFIG_MAGIC.to_vec();
    for members in [voters, learners] {
        let count = u32::try_from(members.len()).unwrap_or(u32::MAX);
        bytes.extend_from_slice(&count.to_le_bytes());
        for member in members {
            bytes.extend_from_slice(&member.to_le_bytes());
        }
    }
    bytes
}

/// The voters and learners of a configuration entry's payload, if it is
/// one.
#[must_use]
pub fn decode_configuration(bytes: &[u8]) -> Option<(Vec<NodeId>, Vec<NodeId>)> {
    let mut rest = bytes.strip_prefix(&CONFIG_MAGIC)?;
    let mut sets = [Vec::new(), Vec::new()];
    for set in &mut sets {
        let (count, tail) = rest.split_first_chunk::<4>()?;
        rest = tail;
        for _ in 0..u32::from_le_bytes(*count) {
            let (member, tail) = rest.split_first_chunk::<4>()?;
            set.push(NodeId::from_le_bytes(*member));
            rest = tail;
        }
    }
    let [voters, learners] = sets;
    rest.is_empty().then_some((voters, learners))
}

/// A configuration in the log: the entry's index, the voters and the
/// learners.
type Logged = (u64, Vec<NodeId>, Vec<NodeId>);

/// The reference core's messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// The leader's entries from some index, and its commit index.
    Append {
        /// The entries, consecutive.
        entries: Vec<Entry>,
        /// The leader's commit index.
        commit: Option<u64>,
    },
    /// A follower holds every entry up to `index` durably.
    Ack {
        /// Its last index.
        index: Option<u64>,
    },
}

/// The reference core (see the module).
#[derive(Debug, Clone)]
pub struct Reference {
    id: NodeId,
    /// The fixed leader: the lowest id of the bootstrap peers.
    leader: NodeId,
    /// The bootstrap voters, ascending.
    peers: Vec<NodeId>,
    /// The configurations in the log, written or not, ascending.
    configs: Vec<Logged>,
    /// Entries not yet handed to the node to persist.
    unpersisted: Vec<Entry>,
    /// The first index to remove before they are written.
    truncate: Option<u64>,
    /// The leader's view of each server's durable index.
    acked: BTreeMap<NodeId, Option<u64>>,
    commit: Option<u64>,
    /// The hard state needs saving.
    dirty: bool,
    /// The last index handed out to apply.
    handed: Option<u64>,
    messages: Vec<(NodeId, Message)>,
    after_persist: Vec<(NodeId, Message)>,
    waiting: bool,
    /// The last index, written or not, after the last call.
    received: Option<u64>,
    /// Its clock at its last tick: the event time of the entries it
    /// proposes (karyos#686, decision E1).
    now: u64,
    /// The limits it was started with, if any.
    limits: Option<Limits>,
}

impl Reference {
    fn leading(&self) -> bool {
        self.id == self.leader
    }

    fn last(&self, log: &LogView<'_>) -> Option<u64> {
        if let Some(entry) = self.unpersisted.last() {
            return Some(entry.index);
        }
        match self.truncate {
            Some(from) => from
                .checked_sub(1)
                .filter(|last| *last >= log.first_index()),
            None => log.last_index(),
        }
    }

    fn next(&self, log: &LogView<'_>) -> Option<u64> {
        self.last(log)
            .map_or(Some(log.first_index()), |last| last.checked_add(1))
    }

    fn term_at(&self, log: &LogView<'_>, index: u64) -> Option<u64> {
        if let Some(entry) = self.unpersisted.iter().find(|entry| entry.index == index) {
            return Some(entry.term);
        }
        if self.truncate.is_some_and(|from| index >= from) {
            return None;
        }
        log.term(index)
    }

    /// The current voters and learners.
    fn members(&self) -> (&[NodeId], &[NodeId]) {
        match self.configs.last() {
            Some((_, voters, learners)) => (voters, learners),
            None => (&self.peers, &[]),
        }
    }

    /// Takes in a configuration that `entry` holds.
    fn note(&mut self, entry: &Entry) {
        if let Some((voters, learners)) = decode_configuration(&entry.payload) {
            self.configs.push((entry.index, voters, learners));
        }
    }

    /// Forgets the configurations from `index` on, as their entries are.
    fn forget_from(&mut self, index: u64) {
        self.configs.retain(|(logged, ..)| *logged < index);
    }

    /// Entries `member` is behind the commit, as the leader knows.
    fn behind(&self, member: NodeId) -> u64 {
        let durable = self.acked.get(&member).copied().flatten().unwrap_or(0);
        self.commit.unwrap_or(0).saturating_sub(durable)
    }

    fn recompute_commit(&mut self, log: &LogView<'_>) {
        let (voters, _) = self.members();
        let mut durable: Vec<Option<u64>> = voters
            .iter()
            .map(|voter| self.acked.get(voter).copied().flatten())
            .collect();
        durable.sort_unstable_by(|a, b| b.cmp(a));
        let majority = voters.len() / 2;
        let candidate = durable.get(majority).copied().flatten();
        if candidate > self.commit
            && let Some(index) = candidate
            && self.term_at(log, index) == Some(TERM)
        {
            self.commit = candidate;
            self.dirty = true;
        }
    }

    fn settle(&mut self, log: &LogView<'_>) {
        self.received = self.last(log);
    }
}

impl ConsensusCore for Reference {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        // The configurations its log holds, written or durable. A failed
        // read leaves the bootstrap configuration, which the harness's
        // checks compare with the log.
        let first = log.first_index();
        let entries = log
            .last_index()
            .and_then(|last| last.checked_add(1))
            .filter(|end| first < *end)
            .and_then(|end| log.entries(first..end, u64::MAX).ok())
            .unwrap_or_default();
        let configs: Vec<Logged> = entries
            .iter()
            .filter_map(|entry| {
                let (voters, learners) = decode_configuration(&entry.payload)?;
                Some((entry.index, voters, learners))
            })
            .collect();
        let mut acked: BTreeMap<NodeId, Option<u64>> =
            peers.iter().map(|peer| (*peer, None)).collect();
        for (_, voters, learners) in &configs {
            for member in voters.iter().chain(learners) {
                let _ = acked.entry(*member).or_insert(None);
            }
        }
        let _ = acked.insert(id, log.durable_index());
        let stored = log.hard_state();
        let mut peers = peers.to_vec();
        peers.sort_unstable();
        let leader = peers.first().copied().unwrap_or(id);
        Self {
            id,
            leader,
            peers,
            configs,
            unpersisted: Vec::new(),
            truncate: None,
            acked,
            commit: stored.and_then(|state| state.commit),
            // The vote for the fixed leader is saved at the first Ready.
            dirty: stored.is_none(),
            handed: None,
            messages: Vec::new(),
            after_persist: Vec::new(),
            waiting: false,
            received: log.last_index(),
            // Until its first tick; the log time never goes back, as it
            // is the highest event time applied.
            now: 0,
            limits: None,
        }
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        let mut core = Self::recover(id, peers, log);
        core.limits = Some(*limits);
        Ok(core)
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        let not_leader = NotLeader {
            leader: Some(self.leader),
        };
        if !self.leading() {
            return Err(not_leader.into());
        }
        // The last index is u64::MAX: the log takes no more.
        let Some(index) = self.next(log) else {
            return Err(not_leader.into());
        };
        // Held and not committed: what it proposed past its commit. A
        // count it cannot take fails closed, refused as a full queue.
        let held = self
            .commit
            .map_or(Some(log.first_index()), |commit| commit.checked_add(1))
            .and_then(|first| index.checked_sub(first));
        if self
            .limits
            .is_some_and(|limits| held.is_none_or(|held| held >= limits.queue))
        {
            return Err(Refused::Backpressure(Limit::Queue));
        }
        self.unpersisted.push(Entry {
            index,
            term: TERM,
            event_time: self.now,
            payload: command,
        });
        self.settle(log);
        Ok(())
    }

    fn step(&mut self, from: NodeId, message: Message, log: &mut LogView<'_>) {
        match message {
            Message::Append { entries, commit } if !self.leading() => {
                for entry in entries {
                    let Some(next) = self.next(log) else {
                        break;
                    };
                    if entry.index < next {
                        if self.term_at(log, entry.index) == Some(entry.term) {
                            continue;
                        }
                        // A stale entry of another term: remove it and
                        // everything after it.
                        self.unpersisted.retain(|kept| kept.index < entry.index);
                        self.forget_from(entry.index);
                        if self.unpersisted.is_empty() {
                            self.truncate =
                                Some(self.truncate.map_or(entry.index, |t| t.min(entry.index)));
                        }
                        self.note(&entry);
                        self.unpersisted.push(entry);
                    } else if entry.index == next {
                        self.note(&entry);
                        self.unpersisted.push(entry);
                    } else {
                        break;
                    }
                }
                let commit = commit.min(self.last(log)).max(self.commit);
                if commit > self.commit {
                    self.commit = commit;
                    self.dirty = true;
                }
                // Released only once `drive` made these entries durable.
                let index = self.last(log);
                self.after_persist
                    .push((self.leader, Message::Ack { index }));
            }
            Message::Ack { index } if self.leading() => {
                let known = self.acked.entry(from).or_insert(None);
                *known = index.max(*known);
                self.recompute_commit(log);
            }
            Message::Append { .. } | Message::Ack { .. } => {}
        }
        self.settle(log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.now = now;
        if !self.leading() || !now.is_multiple_of(RESEND) {
            return;
        }
        let Some(end) = log.last_index().and_then(|last| last.checked_add(1)) else {
            return;
        };
        let (voters, learners) = self.members();
        let members: Vec<NodeId> = voters
            .iter()
            .chain(learners)
            .copied()
            .filter(|member| *member != self.id)
            .collect();
        for peer in members {
            let from = self
                .acked
                .get(&peer)
                .copied()
                .flatten()
                .map_or(Some(log.first_index()), |index| index.checked_add(1))
                .unwrap_or(end);
            // Within the in-flight limits: it resends from the follower's
            // acknowledgement, so one message is all it has in flight.
            let (end, bytes) = match self.limits {
                Some(limits) => (
                    // Past u64::MAX the cap is no bound: `end` is.
                    from.checked_add(limits.in_flight_entries)
                        .map_or(end, |cap| end.min(cap)),
                    BATCH_BYTES.min(limits.in_flight_bytes),
                ),
                None => (end, BATCH_BYTES),
            };
            let entries = if from < end {
                // A failed or refused read sends none; the next resend
                // retries.
                log.entries(from..end, bytes).unwrap_or_default()
            } else {
                Vec::new()
            };
            self.messages.push((
                peer,
                Message::Append {
                    entries,
                    commit: self.commit,
                },
            ));
        }
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        if self.waiting {
            return None;
        }
        // Committed entries, written or in this Ready: `drive` applies
        // them after persisting it.
        let start = self
            .handed
            .map_or(Some(log.first_index()), |handed| handed.checked_add(1));
        let written = match self.truncate {
            Some(from) => from
                .checked_sub(1)
                .filter(|last| *last >= log.first_index()),
            None => log.last_index(),
        };
        let end = self
            .commit
            .min(written)
            .and_then(|last| last.checked_add(1));
        let mut committed = match (start, end) {
            // A failed read applies none; the next Ready retries.
            (Some(start), Some(end)) if start < end => {
                log.entries(start..end, u64::MAX).unwrap_or_default()
            }
            _ => Vec::new(),
        };
        let next = committed
            .last()
            .map(|entry| entry.index.checked_add(1))
            .unwrap_or(start);
        // Only what continues the entries above, so nothing is skipped.
        let mut expected = next;
        for entry in &self.unpersisted {
            if Some(entry.index) > self.commit {
                break;
            }
            if Some(entry.index) < expected {
                continue;
            }
            if Some(entry.index) != expected {
                break;
            }
            committed.push(entry.clone());
            expected = entry.index.checked_add(1);
        }
        let hard_state = self.dirty.then_some(HardState {
            current_term: TERM,
            voted_for: Some(u64::from(self.leader)),
            commit: self.commit,
        });
        if self.messages.is_empty()
            && self.unpersisted.is_empty()
            && self.truncate.is_none()
            && hard_state.is_none()
            && self.after_persist.is_empty()
            && committed.is_empty()
        {
            return None;
        }
        if let Some(last) = committed.last() {
            self.handed = Some(last.index);
        }
        self.dirty = false;
        self.waiting = true;
        Some(Ready {
            messages: std::mem::take(&mut self.messages),
            truncate_from: self.truncate.take(),
            entries: std::mem::take(&mut self.unpersisted),
            hard_state,
            after_persist: std::mem::take(&mut self.after_persist),
            committed,
        })
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.waiting = false;
        let _ = self.acked.insert(self.id, persisted.durable);
        if self.leading() {
            self.recompute_commit(log);
        }
        self.settle(log);
    }

    fn term(&self) -> u64 {
        TERM
    }

    fn leads(&self) -> bool {
        self.leading()
    }

    fn received(&self) -> Option<u64> {
        self.received
    }

    fn committed(&self) -> Option<u64> {
        self.commit
    }

    fn configuration(&self) -> Option<Configuration> {
        let (voters, learners) = self.members();
        Some(Configuration {
            index: self.configs.last().map(|(index, ..)| *index),
            voters: voters.to_vec(),
            outgoing: Vec::new(),
            learners: learners.to_vec(),
        })
    }

    fn propose_change(
        &mut self,
        change: Change,
        log: &mut LogView<'_>,
    ) -> Result<(), ChangeRefused> {
        if !self.leading() {
            return Err(ChangeRefused::NotLeader(NotLeader {
                leader: Some(self.leader),
            }));
        }
        // One change at a time: the last one must be committed.
        if self
            .configs
            .last()
            .is_some_and(|(index, ..)| Some(*index) > self.commit)
        {
            return Err(ChangeRefused::InProgress);
        }
        let (voters, learners) = self.members();
        let (mut voters, mut learners) = (voters.to_vec(), learners.to_vec());
        let member = |node: NodeId| voters.contains(&node) || learners.contains(&node);
        match change {
            Change::AddLearner(node) => {
                if member(node) {
                    return Err(ChangeRefused::Invalid);
                }
                learners.push(node);
            }
            Change::Promote(node) => {
                if !learners.contains(&node) {
                    return Err(ChangeRefused::Invalid);
                }
                let behind = self.behind(node);
                if behind > PROMOTION_LAG {
                    return Err(ChangeRefused::Lagging { behind });
                }
                learners.retain(|learner| *learner != node);
                voters.push(node);
            }
            Change::Remove(node) => {
                // The fixed leader cannot be replaced.
                if node == self.id || !member(node) {
                    return Err(ChangeRefused::Invalid);
                }
                voters.retain(|voter| *voter != node);
                learners.retain(|learner| *learner != node);
            }
        }
        voters.sort_unstable();
        learners.sort_unstable();
        // The last index is u64::MAX: the log takes no more.
        let Some(index) = self.next(log) else {
            return Err(ChangeRefused::Invalid);
        };
        for member in voters.iter().chain(&learners) {
            let _ = self.acked.entry(*member).or_insert(None);
        }
        self.unpersisted.push(Entry {
            index,
            term: TERM,
            event_time: self.now,
            payload: encode_configuration(&voters, &learners),
        });
        self.configs.push((index, voters, learners));
        // A removal can leave a smaller majority that already holds more.
        self.recompute_commit(log);
        self.settle(log);
        Ok(())
    }
}
