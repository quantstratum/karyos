// SPDX-License-Identifier: Apache-2.0

//! The harness skeleton (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C5), with a test-only core
//! that has a fixed leader and no elections, and reads its log through
//! the harness's read-only view:
//!
//! - a healthy run passes every check, also with slow replies to the
//!   client (a leader that commits on a minority fails it);
//! - `drive` persists before it releases what depends on persistence: a
//!   follower whose sync fails never acknowledges, so nothing succeeds;
//! - a crashed server's restart reopens C4's log and recovers its core
//!   from it, and a follower's stale entry of another term is truncated
//!   and replaced, its hard state saved along the way;
//! - each check catches its violation in a hand-built record.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;

use karyos_archive::segment::Geometry;
use karyos_cluster::{Entry, HardState, RaftLog};
use karyos_sim::cluster::ClusterSim;
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::harness::check::{self, Violation};
use karyos_sim::harness::core::{
    ConsensusCore, LogView, NotLeader, Persisted, Ready, Release, Step,
};
use karyos_sim::harness::node::{
    Breach, ClientNode, LOG_DIR, Member, Observation, Op, Positions, Recorder, Ret, ServerNode,
    Shared, Wire,
};
use karyos_sim::lin::History;
use karyos_sim::net::{LinkConfig, NodeId};
use karyos_sim::scenarios;

/// The fixed leader.
const LEADER: NodeId = 0;
/// Its only term.
const TERM: u64 = 1;
/// Ticks between the leader's resends.
const RESEND: u64 = 4;
/// Frame bytes per append message at most.
const BATCH_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, PartialEq)]
enum Msg {
    /// The leader's entries from some index, and its commit index.
    Append {
        entries: Vec<Entry>,
        commit: Option<u64>,
    },
    /// A follower holds every entry up to `index` durably.
    Ack { index: Option<u64> },
}

/// A fixed leader replicating to followers: commit on a durable majority.
/// It keeps only what is not written yet; the rest it reads from the log.
struct Fixed {
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
    messages: Vec<(NodeId, Msg)>,
    after_persist: Vec<(NodeId, Msg)>,
    waiting: bool,
    /// The last index, written or not, after the last call.
    received: Option<u64>,
}

impl Fixed {
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

    fn next(&self, log: &LogView<'_>) -> u64 {
        self.last(log).map_or(log.first_index(), |last| last + 1)
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

impl ConsensusCore for Fixed {
    type Message = Msg;

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
        let index = self.next(log);
        self.unpersisted.push(Entry {
            index,
            term: TERM,
            event_time: 0,
            payload: command,
        });
        self.settle(log);
        Ok(())
    }

    fn step(&mut self, from: NodeId, message: Msg, log: &mut LogView<'_>) {
        match message {
            Msg::Append { entries, commit } if !self.leading() => {
                for entry in entries {
                    let next = self.next(log);
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
                self.after_persist.push((LEADER, Msg::Ack { index }));
            }
            Msg::Ack { index } if self.leading() => {
                let known = self.acked.entry(from).or_insert(None);
                *known = index.max(*known);
                self.recompute_commit(log);
            }
            Msg::Append { .. } | Msg::Ack { .. } => {}
        }
        self.settle(log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        if !self.leading() || !now.is_multiple_of(RESEND) {
            return;
        }
        let Some(end) = log.last_index().map(|last| last + 1) else {
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
                .map_or(log.first_index(), |index| index + 1);
            let entries = if from < end {
                log.entries(from..end, BATCH_BYTES).unwrap()
            } else {
                Vec::new()
            };
            self.messages.push((
                peer,
                Msg::Append {
                    entries,
                    commit: self.commit,
                },
            ));
        }
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Msg>> {
        if self.waiting {
            return None;
        }
        // Committed entries are applied once durable here.
        let start = self.handed.map_or(log.first_index(), |handed| handed + 1);
        let end = self.commit.min(log.durable_index()).map(|last| last + 1);
        let committed = match end {
            Some(end) if start < end => log.entries(start..end, u64::MAX).unwrap(),
            _ => Vec::new(),
        };
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

type Sim = ClusterSim<Member<Fixed>, Wire<Msg>>;

fn geometry() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

fn server(id: NodeId, servers: u32, disk: SimDisk, recorder: &Shared) -> ServerNode<Fixed> {
    ServerNode::new(
        id,
        (0..servers).collect(),
        disk,
        Survives::Synced,
        geometry(),
        Rc::clone(recorder),
    )
    .unwrap()
}

/// A run of `servers` and one client sending `script` to the leader; the
/// client is the last node.
fn cluster(
    seed: u64,
    servers: Vec<ServerNode<Fixed>>,
    recorder: &Shared,
    script: Vec<Op>,
) -> (Sim, NodeId) {
    let mut sim = Sim::new("harness", seed, LinkConfig::default()).unwrap();
    let count = u32::try_from(servers.len()).unwrap();
    for (id, server) in (0..count).zip(servers) {
        let added = sim
            .add_node(Member::Server(Box::new(server)), 0, 0)
            .unwrap();
        assert_eq!(added, id);
    }
    let client = ClientNode::new(count, LEADER, script, Rc::clone(recorder));
    let added = sim.add_node(Member::Client(client), 0, 0).unwrap();
    assert_eq!(added, count);
    (sim, count)
}

fn fresh(seed: u64, disks: Vec<SimDisk>, script: Vec<Op>) -> (Sim, Shared, NodeId) {
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    let count = u32::try_from(disks.len()).unwrap();
    let servers = (0..count)
        .zip(disks)
        .map(|(id, disk)| server(id, count, disk, &recorder))
        .collect();
    let (sim, client) = cluster(seed, servers, &recorder, script);
    (sim, recorder, client)
}

fn appends(count: u8) -> Vec<Op> {
    (0..count).map(|value| Op::Append(vec![value])).collect()
}

/// The flushes a new log's creation takes, so a test can fail the next.
fn creation_syncs() -> u64 {
    (1..64)
        .find(|first| {
            let disk = SimDisk::new().with_failed_syncs(*first..1000);
            let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
            ServerNode::<Fixed>::new(1, vec![0, 1], disk, Survives::Synced, geometry(), recorder)
                .is_ok()
        })
        .unwrap()
        - 1
}

fn count(recorder: &Shared, wanted: fn(&Observation) -> bool) -> usize {
    recorder
        .borrow()
        .observations
        .iter()
        .filter(|o| wanted(o))
        .count()
}

fn all_checks(recorder: &Shared, servers: usize) {
    let recorder = recorder.borrow();
    check::all(&recorder.observations, &recorder.history, servers).unwrap();
}

#[test]
fn healthy_cluster_passes_every_check() {
    for seed in scenarios::seeds() {
        let disks = vec![SimDisk::new(), SimDisk::new(), SimDisk::new()];
        let mut script = appends(5);
        script.push(Op::Read);
        let (mut sim, recorder, client) = fresh(seed, disks, script);
        sim.run_for(400).unwrap();
        assert!(
            sim.node(client).and_then(Member::client).unwrap().done(),
            "seed {seed}"
        );
        // The hard state is saved: the vote at the start, then commits.
        assert!(
            count(&recorder, |o| matches!(
                o,
                Observation::Drive {
                    step: Step::Persisted {
                        persisted: Persisted {
                            hard_state: Some(_),
                            ..
                        },
                        ..
                    },
                    ..
                }
            )) > 3,
            "seed {seed}"
        );
        all_checks(&recorder, 3);
    }
}

#[test]
fn slow_replies_pass_every_check() {
    // Replies take 8 steps to reach the client: the followers persist
    // before a reply lands, so only the server-side check catches a
    // leader that commits without a durable majority.
    for seed in scenarios::seeds() {
        let disks = vec![SimDisk::new(), SimDisk::new(), SimDisk::new()];
        let mut script = appends(5);
        script.push(Op::Read);
        let (mut sim, recorder, client) = fresh(seed, disks, script);
        let slow = LinkConfig {
            min_delay: 8,
            max_delay: 8,
            ..LinkConfig::default()
        };
        sim.net_mut().configure(LEADER, client, slow).unwrap();
        sim.run_for(500).unwrap();
        assert!(
            sim.node(client).and_then(Member::client).unwrap().done(),
            "seed {seed}"
        );
        all_checks(&recorder, 3);
    }
}

#[test]
fn drive_persists_before_it_releases() {
    // Two servers: a majority needs the follower, whose syncs fail after
    // its log's creation. `drive` never releases its ack, so the
    // client's request never succeeds.
    let first_failure = creation_syncs() + 1;
    for seed in scenarios::seeds() {
        let follower = SimDisk::new().with_failed_syncs(first_failure..first_failure + 1000);
        let (mut sim, recorder, _) = fresh(seed, vec![SimDisk::new(), follower], appends(1));
        sim.run_for(200).unwrap();
        assert!(
            count(&recorder, |o| matches!(
                o,
                Observation::OpenFailed { node: 1, .. }
            )) > 0,
            "seed {seed}: the follower's sync did not fail"
        );
        assert_eq!(
            count(&recorder, |o| matches!(o, Observation::Success { .. })),
            0
        );
        all_checks(&recorder, 2);
    }
}

#[test]
fn restart_reopens_the_log() {
    for seed in scenarios::seeds() {
        let disks = vec![SimDisk::new(), SimDisk::new(), SimDisk::new()];
        let (mut sim, recorder, client) = fresh(seed, disks, appends(6));
        sim.run_for(80).unwrap();
        let held = sim
            .node(2)
            .and_then(Member::server)
            .and_then(ServerNode::core)
            .and_then(ConsensusCore::received);
        assert!(held.is_some(), "seed {seed}: nothing replicated");
        sim.crash(2).unwrap();
        assert!(!sim.node(2).and_then(Member::server).unwrap().is_up());
        sim.run_for(40).unwrap();
        sim.restart(2).unwrap();
        let server = sim.node(2).and_then(Member::server).unwrap();
        assert!(server.is_up(), "seed {seed}: the log did not reopen");
        // Survives::Synced keeps what the follower acknowledged.
        let reopened = server.core().and_then(ConsensusCore::received);
        assert!(reopened >= held.min(reopened), "seed {seed}");
        assert!(reopened.is_some(), "seed {seed}: the reopened log is empty");
        sim.run_for(400).unwrap();
        // The checks first: a breach is reported as the violation it is.
        all_checks(&recorder, 3);
        assert!(
            sim.node(client).and_then(Member::client).unwrap().done(),
            "seed {seed}"
        );
        assert_eq!(
            count(&recorder, |o| matches!(
                o,
                Observation::OpenFailed { .. } | Observation::Contract { .. }
            )),
            0,
            "seed {seed}"
        );
        assert_eq!(
            count(&recorder, |o| matches!(
                o,
                Observation::Recovered { node: 2, .. }
            )),
            1
        );
        // Node 2 applied again from index 1 after its restart.
        let applied_by_2 = count(&recorder, |o| {
            matches!(o, Observation::Applied { node: 2, .. })
        });
        assert!(applied_by_2 > 6, "seed {seed}: {applied_by_2}");
    }
}

#[test]
fn a_stale_entry_is_truncated_and_replaced() {
    // Follower 2 starts with an entry of term 0 at index 1: the leader's
    // entry 1 of term 1 replaces it through `truncate_from`.
    for seed in scenarios::seeds() {
        let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
        let stale = SimDisk::new();
        let mut log = RaftLog::create(stale.clone(), Path::new(LOG_DIR), geometry(), 1).unwrap();
        let _ = log
            .append(&[Entry {
                index: 1,
                term: 0,
                event_time: 0,
                payload: vec![0xEE],
            }])
            .unwrap();
        let _ = log.sync().unwrap();
        drop(log);
        let follower = ServerNode::open(
            2,
            vec![0, 1, 2],
            stale,
            Survives::Synced,
            geometry(),
            Rc::clone(&recorder),
        );
        assert!(follower.is_up());
        let servers = vec![
            server(0, 3, SimDisk::new(), &recorder),
            server(1, 3, SimDisk::new(), &recorder),
            follower,
        ];
        let (mut sim, client) = cluster(seed, servers, &recorder, appends(3));
        sim.run_for(300).unwrap();
        all_checks(&recorder, 3);
        assert!(
            sim.node(client).and_then(Member::client).unwrap().done(),
            "seed {seed}"
        );
        assert!(
            count(&recorder, |o| matches!(
                o,
                Observation::Drive {
                    node: 2,
                    step: Step::Persisted {
                        truncated_from: Some(1),
                        ..
                    },
                }
            )) == 1,
            "seed {seed}"
        );
        let applied_by_2 = count(&recorder, |o| {
            matches!(o, Observation::Applied { node: 2, .. })
        });
        assert_eq!(applied_by_2, 3, "seed {seed}");
    }
}

fn entry(index: u64, term: u64, payload: u8) -> Entry {
    Entry {
        index,
        term,
        event_time: 0,
        payload: vec![payload],
    }
}

fn positions(durable: Option<u64>) -> Positions {
    Positions {
        received: Some(1),
        written: Some(1),
        durable,
        committed: None,
        applied: None,
    }
}

fn persisted(node: NodeId, truncated_from: Option<u64>, appended: Vec<(u64, u64)>) -> Observation {
    let durable = appended.last().map(|(index, _)| *index);
    Observation::Drive {
        node,
        step: Step::Persisted {
            persisted: Persisted {
                durable,
                hard_state: None,
            },
            truncated_from,
            appended,
        },
    }
}

#[test]
fn a_history_that_is_not_linearizable_is_caught() {
    let mut history = History::new();
    let _ = history
        .invoke(1, Op::Append(vec![7]))
        .ret(1, Ret::Appended(1))
        .invoke(2, Op::Read)
        .ret(2, Ret::Values(Vec::new()));
    assert!(matches!(
        check::linearizable(&history),
        Err(Violation::NotLinearizable(_))
    ));
    let mut fine = History::new();
    let _ = fine
        .invoke(1, Op::Append(vec![7]))
        .ret(1, Ret::Appended(1))
        .invoke(2, Op::Read)
        .ret(2, Ret::Values(vec![vec![7]]));
    check::linearizable(&fine).unwrap();
}

#[test]
fn divergent_committed_prefixes_are_caught() {
    let observations = vec![
        Observation::Applied {
            node: 0,
            entry: entry(1, 1, 1),
        },
        Observation::Applied {
            node: 1,
            entry: entry(1, 1, 1),
        },
        Observation::Applied {
            node: 1,
            entry: entry(2, 1, 2),
        },
        Observation::Applied {
            node: 0,
            entry: entry(2, 1, 3),
        },
    ];
    check::committed_prefixes_agree(&observations[..3]).unwrap();
    assert_eq!(
        check::committed_prefixes_agree(&observations),
        Err(Violation::DivergentPrefix {
            index: 2,
            first: (1, entry(2, 1, 2)),
            second: (0, entry(2, 1, 3)),
        })
    );
}

#[test]
fn an_old_term_direct_commit_is_caught() {
    let commit = |leader, entry_term| Observation::Commit {
        node: 0,
        term: 2,
        leader,
        index: 4,
        entry_term,
    };
    // A follower's commit may land on an old entry; a leader's may not.
    check::no_old_term_direct_commit(&[commit(false, 1), commit(true, 2)]).unwrap();
    assert!(matches!(
        check::no_old_term_direct_commit(&[commit(true, 1)]),
        Err(Violation::OldTermCommit { entry_term: 1, .. })
    ));
}

#[test]
fn a_reply_before_a_durable_majority_is_caught() {
    let reply = Observation::Reply {
        node: 0,
        client: 3,
        index: 1,
        term: 2,
    };
    // Three servers: when the leader replies, only it holds entry 1 of
    // term 2; server 1 holds a stale entry 1 of term 1, which does not
    // count.
    let early = vec![
        persisted(0, None, vec![(1, 2)]),
        persisted(1, None, vec![(1, 1)]),
        reply.clone(),
        persisted(2, None, vec![(1, 2)]),
    ];
    assert_eq!(
        check::durable_majority_before_reply(&early, 3),
        Err(Violation::ReplyBeforeDurableMajority {
            node: 0,
            client: 3,
            index: 1,
            term: 2,
            durable: 1,
            servers: 3,
        })
    );
    let in_time = vec![
        persisted(0, None, vec![(1, 2)]),
        persisted(1, None, vec![(1, 1)]),
        persisted(1, Some(1), vec![(1, 2)]),
        reply,
    ];
    check::durable_majority_before_reply(&in_time, 3).unwrap();
}

#[test]
fn positions_out_of_order_are_caught() {
    let at = |positions| Observation::Positions { node: 0, positions };
    check::positions_ordered(&[at(positions(Some(1)))]).unwrap();
    let durable_ahead = Positions {
        durable: Some(2),
        ..positions(Some(1))
    };
    let applied_ahead = Positions {
        applied: Some(1),
        ..positions(Some(1))
    };
    for bad in [durable_ahead, applied_ahead] {
        assert_eq!(
            check::positions_ordered(&[at(bad)]),
            Err(Violation::PositionsOutOfOrder {
                node: 0,
                positions: bad,
            })
        );
    }
}

#[test]
fn a_release_before_persistence_is_caught() {
    let state = HardState {
        current_term: 1,
        voted_for: Some(0),
        commit: Some(2),
    };
    let released = |release| Observation::Released {
        node: 1,
        to: 0,
        release,
    };
    let fine = Release {
        needs: Some(3),
        needs_state: Some(state),
        durable: Some(3),
        stored_state: Some(state),
    };
    check::released_after_persistence(&[released(fine)]).unwrap();
    let early = Release {
        durable: Some(2),
        ..fine
    };
    let unsaved = Release {
        stored_state: None,
        ..fine
    };
    for bad in [early, unsaved] {
        assert_eq!(
            check::released_after_persistence(&[released(bad)]),
            Err(Violation::ReleasedBeforePersisted {
                node: 1,
                to: 0,
                release: bad,
            })
        );
    }
}

#[test]
fn a_contract_breach_is_caught() {
    let breach = Observation::Contract {
        node: 2,
        breach: Breach::NotNext,
        error: "an append at index 4; the next index is 3".into(),
    };
    assert!(matches!(
        check::no_contract_breach(&[breach]),
        Err(Violation::Contract {
            node: 2,
            breach: Breach::NotNext,
            ..
        })
    ));
}

#[test]
fn lost_durable_entries_are_caught() {
    let recovered = |entries: Vec<(u64, u64)>| Observation::Recovered {
        node: 1,
        durable: entries.last().map(|(index, _)| *index),
        entries,
    };
    let before = vec![
        persisted(1, None, vec![(1, 1), (2, 1)]),
        Observation::Crashed { node: 1 },
    ];
    let mut kept = before.clone();
    kept.push(recovered(vec![(1, 1), (2, 1)]));
    check::durable_kept(&kept).unwrap();
    let mut lost = before;
    lost.push(recovered(vec![(1, 1)]));
    assert_eq!(
        check::durable_kept(&lost),
        Err(Violation::DurableLost {
            node: 1,
            index: 2,
            term: 1,
        })
    );
    // Truncating an entry the cluster applied.
    let truncated = vec![
        persisted(1, None, vec![(1, 1), (2, 1)]),
        Observation::Applied {
            node: 0,
            entry: entry(2, 1, 9),
        },
        persisted(1, Some(2), vec![(2, 3)]),
    ];
    assert_eq!(
        check::durable_kept(&truncated),
        Err(Violation::CommittedTruncated { node: 1, index: 2 })
    );
}
