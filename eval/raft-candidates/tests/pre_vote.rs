// SPDX-License-Identifier: Apache-2.0

//! Pre-vote (SPEC.md §9, "pre-vote"; plan issue 060, karyos#678): a
//! follower cut off from a healthy leader and its quorum, then let back,
//! does not depose that leader. Without pre-vote the same run does: the
//! election it would start is possible, and pre-vote is what prevents it.
//!
//! Three cores over C4 logs on simulated disks, driven by the harness's
//! own [`drive`], with a hand-run network that can cut one node off.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::path::Path;

use karyos_cluster::RaftLog;
use karyos_raft_eval::openraft_core::{OpenRaft, OpenRaftCore, OpenRaftNoPreVote};
use karyos_raft_eval::raft_rs::{RaftCore, RaftRs, RaftRsNoPreVote};
use karyos_sim::disk::SimDisk;
use karyos_sim::harness::core::{ConsensusCore, LogView, drive};
use karyos_sim::harness::workloads;
use karyos_sim::net::NodeId;

const SERVERS: NodeId = 3;

struct Mini<C: ConsensusCore> {
    cores: Vec<C>,
    logs: Vec<RaftLog<SimDisk>>,
    queue: Vec<(NodeId, NodeId, C::Message)>,
    cut: Option<NodeId>,
    now: u64,
}

impl<C: ConsensusCore> Mini<C> {
    fn new() -> Self {
        let peers: Vec<NodeId> = (0..SERVERS).collect();
        let mut logs: Vec<RaftLog<SimDisk>> = peers
            .iter()
            .map(|_| {
                RaftLog::create(
                    SimDisk::new(),
                    Path::new("log"),
                    workloads::geometry().unwrap(),
                    1,
                )
                .unwrap()
            })
            .collect();
        let cores = peers
            .iter()
            .zip(&mut logs)
            .map(|(id, log)| C::recover(*id, &peers, &mut LogView::new(log)))
            .collect();
        Self {
            cores,
            logs,
            queue: Vec::new(),
            cut: None,
            now: 0,
        }
    }

    fn drive(&mut self, id: NodeId) {
        let index = usize::try_from(id).unwrap();
        let mut sent = Vec::new();
        drive(
            &mut self.cores[index],
            &mut self.logs[index],
            &mut |to, message, _| sent.push((id, to, message)),
            &mut |_, _| {},
            &mut |_| {},
        )
        .unwrap();
        self.queue.extend(sent);
    }

    fn step(&mut self) {
        self.now += 1;
        for id in 0..SERVERS {
            let index = usize::try_from(id).unwrap();
            self.cores[index].tick(self.now, &mut LogView::new(&mut self.logs[index]));
            self.drive(id);
        }
        for (from, to, message) in std::mem::take(&mut self.queue) {
            if self.cut.is_some_and(|cut| cut == from || cut == to) {
                continue;
            }
            let index = usize::try_from(to).unwrap();
            self.cores[index].step(from, message, &mut LogView::new(&mut self.logs[index]));
            self.drive(to);
        }
    }

    fn run(&mut self, steps: u64) {
        for _ in 0..steps {
            self.step();
        }
    }

    fn leader(&self) -> Option<(NodeId, u64)> {
        (0..SERVERS)
            .zip(&self.cores)
            .find(|(_, core)| core.leads())
            .map(|(id, core)| (id, core.term()))
    }
}

/// Elects a leader, cuts a follower off for long past its election
/// timeout, lets it back, and returns (the leader and its term before,
/// the cut follower's term while cut off, the leader and its term after).
fn isolate_and_return<C: ConsensusCore>() -> ((NodeId, u64), u64, Option<(NodeId, u64)>) {
    let mut mini = Mini::<C>::new();
    mini.run(100);
    let before = mini.leader().unwrap();
    let follower = (0..SERVERS).find(|id| *id != before.0).unwrap();
    mini.cut = Some(follower);
    mini.run(200);
    let cut_term = mini.cores[usize::try_from(follower).unwrap()].term();
    mini.cut = None;
    mini.run(100);
    (before, cut_term, mini.leader())
}

fn with_pre_vote<C: ConsensusCore>() {
    let (before, cut_term, after) = isolate_and_return::<C>();
    // Cut off, its pre-votes failed and its term never moved.
    assert_eq!(cut_term, before.1);
    assert_eq!(after, Some(before));
}

/// The negative control: the same run without pre-vote. Cut off, the
/// follower campaigns and raises its term; back, its higher term deposes
/// the leader, and the cluster leads a later term.
fn without_pre_vote<C: ConsensusCore>() {
    let (before, cut_term, after) = isolate_and_return::<C>();
    assert!(cut_term > before.1, "{cut_term} after {before:?}");
    let after = after.unwrap();
    assert!(after.1 > before.1, "{after:?} after {before:?}");
}

#[test]
fn raft_a_returning_follower_does_not_depose_the_leader_with_pre_vote() {
    with_pre_vote::<RaftRs>();
}

#[test]
fn raft_without_pre_vote_the_returning_follower_forces_an_election() {
    without_pre_vote::<RaftRsNoPreVote>();
}

/// OpenRaft's pre-vote is its own handler on the receiving node, reached
/// through the adapter's network, never the trait's default that
/// synthesises a grant: with that default the cut-off follower's
/// pre-vote would pass on its own and it would raise its term.
#[test]
fn openraft_a_returning_follower_does_not_depose_the_leader_with_pre_vote() {
    with_pre_vote::<OpenRaft>();
}

#[test]
fn openraft_without_pre_vote_the_returning_follower_forces_an_election() {
    without_pre_vote::<OpenRaftNoPreVote>();
}

/// The same calls reproduce every node's executor interleaving.
#[test]
fn openraft_runs_reproduce_their_executor_interleaving() {
    let digests = || {
        let mut mini = Mini::<OpenRaft>::new();
        mini.run(150);
        mini.cores
            .iter()
            .map(|core| {
                (
                    core.executor().trace_digest(),
                    core.executor().polls(),
                    core.overruns(),
                )
            })
            .collect::<Vec<_>>()
    };
    let first = digests();
    assert_eq!(first, digests());
    assert!(
        first
            .iter()
            .all(|(_, polls, overruns)| *polls > 0 && *overruns == 0),
        "{first:?}"
    );
}

#[test]
fn the_evaluated_cores_run_with_pre_vote() {
    assert_eq!(
        std::any::type_name::<OpenRaft>(),
        std::any::type_name::<OpenRaftCore<true>>()
    );
    // RaftRs is the pre-vote build; the build without it is only the
    // control above.
    assert_eq!(
        std::any::type_name::<RaftRs>(),
        std::any::type_name::<RaftCore<true>>()
    );
    assert_ne!(
        std::any::type_name::<RaftRsNoPreVote>(),
        std::any::type_name::<RaftRs>()
    );
}
