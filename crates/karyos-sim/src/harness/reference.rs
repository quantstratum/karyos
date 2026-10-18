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

use std::collections::BTreeMap;

use karyos_cluster::{Entry, HardState};

use super::core::{ConsensusCore, LogView, NotLeader, Persisted, Ready};
use crate::net::NodeId;

/// The fixed leader.
pub const LEADER: NodeId = 0;
/// Its only term.
pub const TERM: u64 = 1;
/// Ticks between the leader's resends.
pub const RESEND: u64 = 4;
/// Frame bytes per append message at most (at least one entry).
pub const BATCH_BYTES: u64 = 16 * 1024;

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
    peers: Vec<NodeId>,
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
}

impl Reference {
    fn leading(&self) -> bool {
        self.id == LEADER
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

    fn recompute_commit(&mut self, log: &LogView<'_>) {
        let mut durable: Vec<Option<u64>> = self.acked.values().copied().collect();
        durable.sort_unstable_by(|a, b| b.cmp(a));
        let majority = self.peers.len() / 2;
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
        let mut acked: BTreeMap<NodeId, Option<u64>> =
            peers.iter().map(|peer| (*peer, None)).collect();
        let _ = acked.insert(id, log.durable_index());
        let stored = log.hard_state();
        Self {
            id,
            peers: peers.to_vec(),
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
        }
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), NotLeader> {
        if !self.leading() {
            return Err(NotLeader {
                leader: Some(LEADER),
            });
        }
        // The last index is u64::MAX: the log takes no more.
        let Some(index) = self.next(log) else {
            return Err(NotLeader {
                leader: Some(LEADER),
            });
        };
        self.unpersisted.push(Entry {
            index,
            term: TERM,
            event_time: 0,
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
                        if self.unpersisted.is_empty() {
                            self.truncate =
                                Some(self.truncate.map_or(entry.index, |t| t.min(entry.index)));
                        }
                        self.unpersisted.push(entry);
                    } else if entry.index == next {
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
                self.after_persist.push((LEADER, Message::Ack { index }));
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
        if !self.leading() || !now.is_multiple_of(RESEND) {
            return;
        }
        let Some(end) = log.last_index().and_then(|last| last.checked_add(1)) else {
            return;
        };
        for peer in self.peers.clone() {
            if peer == self.id {
                continue;
            }
            let from = self
                .acked
                .get(&peer)
                .copied()
                .flatten()
                .map_or(Some(log.first_index()), |index| index.checked_add(1))
                .unwrap_or(end);
            let entries = if from < end {
                // A failed read sends none; the next resend retries.
                log.entries(from..end, BATCH_BYTES).unwrap_or_default()
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
            voted_for: Some(u64::from(LEADER)),
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
}
