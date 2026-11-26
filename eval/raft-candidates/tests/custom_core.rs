// SPDX-License-Identifier: Apache-2.0

//! The harness's checks shown to catch their violations with the custom
//! Raft core (ADR-0105) behind the adapter (quantstratum/karyos#681, part
//! (d)): faults injected around the real core, a mutant that drops the
//! declared limits, and the allocation probe over W1.

#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_sim::harness::check::Violation;
use karyos_sim::harness::core::{
    ConsensusCore, DriveFault, Limit, Limits, LogView, Persisted, Ready, ReadyBuf, Refused,
    Unsupported,
};
use karyos_sim::harness::custom::{Custom, Message};
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::probe::{Stage, measure};
use karyos_sim::harness::workloads::{self, Case, W1, W2};
use karyos_sim::net::NodeId;
use karyos_sys::alloc_count::CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn case() -> Case {
    W1::skeleton().cases().into_iter().nth(1).unwrap()
}

fn faulty(node: NodeId, fault: DriveFault) -> Violation {
    let mut case = case();
    case.faults = workloads::Faults {
        drive: vec![(node, fault)],
        ..workloads::Faults::default()
    };
    workloads::run::<Custom>(&case, 1)
        .unwrap()
        .safety
        .unwrap_err()
}

#[test]
fn the_unmutated_core_passes_the_case() {
    let case = case();
    let outcome = workloads::run::<Custom>(&case, 1).unwrap();
    assert_eq!(workloads::pass(&case, &outcome), Ok(None));
}

#[test]
fn a_driver_that_releases_before_persistence_is_caught() {
    let violation = faulty(1, DriveFault::ReleaseEarly);
    assert!(
        matches!(violation, Violation::ReleasedBeforePersisted { .. }),
        "{violation:?}"
    );
}

/// Applying fresh entries before they are durable: on a follower the
/// applied-not-durable check catches it; on the leader the reply it
/// sends is caught first, before a durable majority.
#[test]
fn a_driver_that_applies_fresh_entries_is_caught() {
    let violations: Vec<Violation> = (0..3)
        .map(|node| faulty(node, DriveFault::ApplyFresh))
        .collect();
    assert!(
        violations
            .iter()
            .any(|violation| matches!(violation, Violation::AppliedNotDurable { .. })),
        "{violations:?}"
    );
    assert!(
        violations.iter().all(|violation| matches!(
            violation,
            Violation::AppliedNotDurable { .. } | Violation::ReplyBeforeDurableMajority { .. }
        )),
        "{violations:?}"
    );
}

/// The custom core started without the declared limits.
struct NoLimits(Custom);

impl ConsensusCore for NoLimits {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self(Custom::recover(id, peers, log))
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        _limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        Ok(Self::recover(id, peers, log))
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.0.propose(command, log)
    }

    fn propose_slice(&mut self, command: &[u8], log: &mut LogView<'_>) -> Result<(), Refused> {
        self.0.propose_slice(command, log)
    }

    fn step(&mut self, from: NodeId, message: Message, log: &mut LogView<'_>) {
        self.0.step(from, message, log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.0.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        self.0.ready(log)
    }

    fn ready_into(&mut self, out: &mut ReadyBuf<Message>, log: &mut LogView<'_>) -> bool {
        self.0.ready_into(out, log)
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.0.advance(persisted, log);
    }

    fn term(&self) -> u64 {
        self.0.term()
    }

    fn leads(&self) -> bool {
        self.0.leads()
    }

    fn received(&self) -> Option<u64> {
        self.0.received()
    }

    fn committed(&self) -> Option<u64> {
        self.0.committed()
    }
}

fn queue_refusals<C: ConsensusCore>() -> usize {
    let cases = W2::skeleton().cases().unwrap();
    let burst = cases
        .iter()
        .find(|case| case.name.contains("burst 4x queue"))
        .unwrap();
    let outcome = workloads::run::<C>(burst, 1).unwrap();
    outcome
        .observations
        .iter()
        .filter(|observation| {
            matches!(
                observation,
                Observation::Backpressure {
                    limit: Limit::Queue,
                    ..
                }
            )
        })
        .count()
}

/// The queue's burst is refused by the core's declared queue, and only
/// because of it: started without the limits, nothing is refused.
#[test]
fn the_queue_burst_is_refused_by_the_declared_limit() {
    assert!(queue_refusals::<Custom>() > 0);
    assert_eq!(queue_refusals::<NoLimits>(), 0);
}

/// The allocation gate's probe over W1's largest case: past the warm-up,
/// the replication path allocates and frees nothing (ADR-0105, decision
/// 3).
#[test]
#[allow(
    clippy::print_stdout,
    reason = "the measurement's raw line, for the run record"
)]
fn the_replication_path_allocates_nothing_after_the_warm_up() {
    let cases = W1::skeleton().cases();
    let case = cases
        .iter()
        .max_by_key(|case| case.clients * case.operations)
        .unwrap();
    let report = measure::<Custom>(case, 1).unwrap();
    assert!(report.entries > 0, "nothing past the warm-up");
    println!("custom W1 {}: {report:?}", case.name);
    // The driver's persistence counts in the Advance stage (C5 v3): in the
    // simulator it runs on SimDisk, whose crash model journals every write
    // (the same for every variant, declared in the run record), so Advance
    // is measured on processes, over the real disk. Every other stage is
    // the core's and the harness's, and allocates nothing.
    for (stage, counts) in &report.stages {
        if matches!(stage, Stage::AdvanceLeader | Stage::AdvanceFollower) {
            continue;
        }
        assert_eq!(
            (counts.allocations, counts.frees),
            (0, 0),
            "stage {}: {report:?}",
            stage.name()
        );
    }
}
