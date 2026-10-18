// SPDX-License-Identifier: Apache-2.0

//! The harness skeleton (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C5), with a test-only core
//! that has a fixed leader and no elections:
//!
//! - `drive` persists before it releases what depends on persistence: a
//!   follower whose sync fails never acknowledges, so nothing succeeds
//!   (the send-before-persist mutant of `drive` fails this test);
//! - a crashed server's restart reopens C4's log and recovers its core
//!   from what the log held;
//! - each check catches its violation in a hand-built record: a history
//!   that is not linearizable, divergent committed prefixes, an old-term
//!   direct commit, a success before a durable majority, positions out of
//!   order, and a release before persistence.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use karyos_archive::segment::Geometry;
use karyos_cluster::Entry;
use karyos_sim::cluster::ClusterSim;
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::harness::check::{self, Violation};
use karyos_sim::harness::core::{ConsensusCore, NotLeader, Persisted, Ready, Recovered, Step};
use karyos_sim::harness::node::{
    ClientNode, Member, Observation, Op, Positions, Recorder, Ret, ServerNode, Shared, Wire,
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
struct Fixed {
    id: NodeId,
    peers: Vec<NodeId>,
    log: Vec<Entry>,
    /// Entries not yet handed to the node to persist.
    unpersisted: Vec<Entry>,
    durable: Option<u64>,
    /// The leader's view of each server's durable index.
    acked: BTreeMap<NodeId, Option<u64>>,
    commit: Option<u64>,
    /// The leader's commit index as a follower knows it.
    leader_commit: Option<u64>,
    /// The last index handed out to apply.
    handed: Option<u64>,
    messages: Vec<(NodeId, Msg)>,
    after_persist: Vec<(NodeId, Msg)>,
    waiting: bool,
}

impl Fixed {
    fn last(&self) -> Option<u64> {
        self.log.last().map(|entry| entry.index)
    }

    fn entry(&self, index: u64) -> Option<&Entry> {
        self.log.iter().find(|entry| entry.index == index)
    }

    fn leading(&self) -> bool {
        self.id == LEADER
    }

    fn recompute_commit(&mut self) {
        let mut durable: Vec<Option<u64>> = self.acked.values().copied().collect();
        durable.sort_unstable_by(|a, b| b.cmp(a));
        let majority = self.peers.len() / 2;
        let candidate = durable.get(majority).copied().flatten();
        if candidate > self.commit
            && let Some(index) = candidate
            && self.entry(index).is_some_and(|entry| entry.term == TERM)
        {
            self.commit = candidate;
        }
    }
}

impl ConsensusCore for Fixed {
    type Message = Msg;

    fn recover(id: NodeId, peers: &[NodeId], recovered: Recovered) -> Self {
        let durable = recovered.entries.last().map(|entry| entry.index);
        let mut acked: BTreeMap<NodeId, Option<u64>> =
            peers.iter().map(|peer| (*peer, None)).collect();
        let _ = acked.insert(id, durable);
        Self {
            id,
            peers: peers.to_vec(),
            log: recovered.entries,
            unpersisted: Vec::new(),
            durable,
            acked,
            commit: None,
            leader_commit: None,
            handed: None,
            messages: Vec::new(),
            after_persist: Vec::new(),
            waiting: false,
        }
    }

    fn propose(&mut self, command: Vec<u8>) -> Result<(), NotLeader> {
        if !self.leading() {
            return Err(NotLeader {
                leader: Some(LEADER),
            });
        }
        let index = self.last().map_or(1, |last| last + 1);
        let entry = Entry {
            index,
            term: TERM,
            event_time: 0,
            payload: command,
        };
        self.log.push(entry.clone());
        self.unpersisted.push(entry);
        Ok(())
    }

    fn step(&mut self, from: NodeId, message: Msg) {
        match message {
            Msg::Append { entries, commit } if !self.leading() => {
                for entry in entries {
                    let next = self.last().map_or(1, |last| last + 1);
                    if entry.index == next {
                        self.log.push(entry.clone());
                        self.unpersisted.push(entry);
                    } else if entry.index > next {
                        break;
                    }
                }
                self.leader_commit = commit;
                self.commit = commit.min(self.last()).max(self.commit);
                // Released only once `drive` made these entries durable.
                let index = self.last();
                self.after_persist.push((LEADER, Msg::Ack { index }));
            }
            Msg::Ack { index } if self.leading() => {
                let known = self.acked.entry(from).or_insert(None);
                *known = index.max(*known);
                self.recompute_commit();
            }
            Msg::Append { .. } | Msg::Ack { .. } => {}
        }
    }

    fn tick(&mut self, now: u64) {
        if !self.leading() || !now.is_multiple_of(RESEND) {
            return;
        }
        for peer in self.peers.clone() {
            if peer == self.id {
                continue;
            }
            let from = self
                .acked
                .get(&peer)
                .copied()
                .flatten()
                .map_or(1, |i| i + 1);
            let entries: Vec<Entry> = self
                .log
                .iter()
                .filter(|entry| entry.index >= from)
                .cloned()
                .collect();
            self.messages.push((
                peer,
                Msg::Append {
                    entries,
                    commit: self.commit,
                },
            ));
        }
    }

    fn ready(&mut self) -> Option<Ready<Msg>> {
        if self.waiting {
            return None;
        }
        let start = self.handed.map_or(1, |handed| handed + 1);
        let committed: Vec<Entry> = self
            .log
            .iter()
            .filter(|entry| entry.index >= start && Some(entry.index) <= self.commit)
            .cloned()
            .collect();
        if self.messages.is_empty()
            && self.unpersisted.is_empty()
            && self.after_persist.is_empty()
            && committed.is_empty()
        {
            return None;
        }
        if let Some(last) = committed.last() {
            self.handed = Some(last.index);
        }
        self.waiting = true;
        Some(Ready {
            messages: std::mem::take(&mut self.messages),
            truncate_from: None,
            entries: std::mem::take(&mut self.unpersisted),
            hard_state: None,
            after_persist: std::mem::take(&mut self.after_persist),
            committed,
        })
    }

    fn advance(&mut self, persisted: Persisted) {
        self.waiting = false;
        self.durable = persisted.durable;
        let _ = self.acked.insert(self.id, persisted.durable);
        if self.leading() {
            self.recompute_commit();
        }
    }

    fn term(&self) -> u64 {
        TERM
    }

    fn leads(&self) -> bool {
        self.leading()
    }

    fn received(&self) -> Option<u64> {
        self.last()
    }

    fn committed(&self) -> Option<u64> {
        self.commit
    }
}

type Sim = ClusterSim<Member<Fixed>, Wire<Msg>>;

fn geometry() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

/// A run of `servers` servers on `disks` and one client sending `script`
/// to the leader; the client is the last node.
fn cluster(seed: u64, disks: Vec<SimDisk>, script: Vec<Op>) -> (Sim, Shared, NodeId) {
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    let mut sim = Sim::new("harness", seed, LinkConfig::default()).unwrap();
    let peers: Vec<NodeId> = (0..u32::try_from(disks.len()).unwrap()).collect();
    for (id, disk) in peers.clone().into_iter().zip(disks) {
        let server = ServerNode::new(
            id,
            peers.clone(),
            disk,
            Survives::Synced,
            geometry(),
            Rc::clone(&recorder),
        )
        .unwrap();
        let added = sim
            .add_node(Member::Server(Box::new(server)), 0, 0)
            .unwrap();
        assert_eq!(added, id);
    }
    let client_id = u32::try_from(peers.len()).unwrap();
    let client = ClientNode::new(client_id, LEADER, script, Rc::clone(&recorder));
    let added = sim.add_node(Member::Client(client), 0, 0).unwrap();
    assert_eq!(added, client_id);
    (sim, recorder, client_id)
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

fn successes(recorder: &Shared) -> usize {
    recorder
        .borrow()
        .observations
        .iter()
        .filter(|observation| matches!(observation, Observation::Success { .. }))
        .count()
}

#[test]
fn healthy_cluster_passes_every_check() {
    for seed in scenarios::seeds() {
        let disks = vec![SimDisk::new(), SimDisk::new(), SimDisk::new()];
        let mut script = appends(5);
        script.push(Op::Read);
        let (mut sim, recorder, client) = cluster(seed, disks, script);
        sim.run_for(400).unwrap();
        assert!(
            sim.node(client).and_then(Member::client).unwrap().done(),
            "seed {seed}"
        );
        let recorder = recorder.borrow();
        check::all(&recorder.observations, &recorder.history, 3).unwrap();
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
        let (mut sim, recorder, _) = cluster(seed, vec![SimDisk::new(), follower], appends(1));
        sim.run_for(200).unwrap();
        let recorded = recorder.borrow();
        assert!(
            recorded
                .observations
                .iter()
                .any(|observation| matches!(observation, Observation::OpenFailed { node: 1, .. })),
            "seed {seed}: the follower's sync did not fail"
        );
        check::released_after_persistence(&recorded.observations).unwrap();
        check::durable_majority_before_success(&recorded.observations, 2).unwrap();
        drop(recorded);
        assert_eq!(successes(&recorder), 0, "seed {seed}");
    }
}

#[test]
fn restart_reopens_the_log() {
    for seed in scenarios::seeds() {
        let disks = vec![SimDisk::new(), SimDisk::new(), SimDisk::new()];
        let (mut sim, recorder, client) = cluster(seed, disks, appends(6));
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
        // Survives::Synced keeps what the follower acknowledged at least.
        let reopened = server.core().and_then(ConsensusCore::received);
        assert!(
            reopened >= server.core().and_then(|core| core.durable),
            "seed {seed}"
        );
        assert!(reopened.is_some(), "seed {seed}: the reopened log is empty");
        sim.run_for(400).unwrap();
        assert!(
            sim.node(client).and_then(Member::client).unwrap().done(),
            "seed {seed}"
        );
        let recorder = recorder.borrow();
        assert!(
            !recorder
                .observations
                .iter()
                .any(|observation| matches!(observation, Observation::OpenFailed { .. })),
            "seed {seed}"
        );
        // Node 2 applied again from index 1 after its restart.
        let applied_by_2 = recorder
            .observations
            .iter()
            .filter(|observation| matches!(observation, Observation::Applied { node: 2, .. }))
            .count();
        assert!(applied_by_2 > 6, "seed {seed}: {applied_by_2}");
        check::all(&recorder.observations, &recorder.history, 3).unwrap();
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
fn a_success_before_a_durable_majority_is_caught() {
    let durable = |node, index| Observation::Positions {
        node,
        positions: positions(index),
    };
    let success = Observation::Success {
        client: 3,
        index: 1,
    };
    // Three servers: only the leader holds index 1 when the client hears.
    let early = vec![
        durable(0, Some(1)),
        durable(1, None),
        success.clone(),
        durable(2, Some(1)),
    ];
    assert_eq!(
        check::durable_majority_before_success(&early, 3),
        Err(Violation::SuccessBeforeDurableMajority {
            client: 3,
            index: 1,
            durable: 1,
            servers: 3,
        })
    );
    let in_time = vec![durable(0, Some(1)), durable(2, Some(1)), success];
    check::durable_majority_before_success(&in_time, 3).unwrap();
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
    let persisted = Step::Persisted(Persisted {
        durable: Some(1),
        hard_state: None,
    });
    let drive = |step| Observation::Drive { node: 1, step };
    check::released_after_persistence(&[
        drive(persisted.clone()),
        drive(Step::Released { count: 1 }),
        drive(Step::Released { count: 0 }),
    ])
    .unwrap();
    assert_eq!(
        check::released_after_persistence(&[
            drive(persisted),
            drive(Step::Released { count: 1 }),
            drive(Step::Released { count: 1 }),
        ]),
        Err(Violation::ReleasedBeforePersisted { node: 1, count: 1 })
    );
}
