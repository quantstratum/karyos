// SPDX-License-Identifier: Apache-2.0

//! The custom Raft core (ADR-0105) through the harness's `ConsensusCore`
//! adapter (quantstratum/karyos#681, part (d)): W1 to W4 and W6 over the
//! same seeds as the candidates' suite, each verdict asserted.

#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_sim::harness::core::Limit;
use karyos_sim::harness::custom::Custom;
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::workloads::{self, Liveness, W1, W2, W3, W3Fault, W4, W6};

/// Seeds every sweep runs: the candidates' suite's.
const SEEDS: [u64; 4] = [1, 0xC5, 0x0043, 0xDEAD_BEEF];

#[test]
fn w1_passes() {
    for seed in SEEDS {
        for case in W1::skeleton().cases() {
            let outcome = workloads::run::<Custom>(&case, seed).unwrap();
            assert_eq!(
                workloads::pass(&case, &outcome),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

#[test]
fn w3_safety_holds_and_only_the_unrestarted_crash_is_a_gap() {
    for seed in SEEDS {
        for (fault, case) in W3::skeleton().faults.iter().zip(W3::skeleton().cases()) {
            let outcome = workloads::run::<Custom>(&case, seed).unwrap();
            let result = workloads::pass(&case, &outcome);
            match fault {
                W3Fault::LeaderCrash => assert!(
                    matches!(result, Ok(None | Some(Liveness::Stalled { .. }))),
                    "{} seed {seed}: {result:?}",
                    case.name
                ),
                _ => assert_eq!(result, Ok(None), "{} seed {seed}", case.name),
            }
        }
    }
}

#[test]
fn w4_passes_and_a_lost_majority_is_a_gap() {
    for seed in SEEDS {
        for case in W4::skeleton(seed).cases() {
            let outcome = workloads::run::<Custom>(&case, seed).unwrap();
            let result = workloads::pass(&case, &outcome);
            if case.name.contains("FailedFlushes") {
                assert_eq!(
                    result,
                    Ok(Some(Liveness::NoLeader)),
                    "{} seed {seed}",
                    case.name
                );
            } else {
                assert_eq!(result, Ok(None), "{} seed {seed}", case.name);
            }
        }
    }
}

#[test]
fn w6_replays_every_seed() {
    let w6 = W6::skeleton();
    for case in w6.cases() {
        for seed in SEEDS {
            assert_eq!(
                w6.pass::<Custom>(&case, seed).unwrap(),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

#[test]
fn a_seed_reproduces_its_run() {
    let mut cases = W1::skeleton().cases();
    cases.extend(W3::skeleton().cases());
    let mut cases: Vec<_> = cases.into_iter().step_by(3).collect();
    cases.extend(W2::skeleton().cases().unwrap());
    for case in &cases {
        for seed in SEEDS {
            let first = workloads::run::<Custom>(case, seed).unwrap();
            let second = workloads::run::<Custom>(case, seed).unwrap();
            assert_eq!(first, second, "{} seed {seed}", case.name);
        }
    }
}

/// W2 under the declared limits: every case keeps safety and passes, and
/// the queue's burst is refused with a typed `Backpressure(Queue)` only.
#[test]
fn w2_passes_and_its_burst_is_refused_by_the_queue() {
    for case in &W2::skeleton().cases().unwrap() {
        let outcome = workloads::run::<Custom>(case, 1).unwrap();
        assert!(outcome.safety.is_ok(), "{}", case.name);
        let pushed: Vec<_> = outcome
            .observations
            .iter()
            .filter_map(|observation| match observation {
                Observation::Backpressure { limit, .. } => Some(*limit),
                _ => None,
            })
            .collect();
        if case.name.contains("burst 4x queue") {
            assert!(!pushed.is_empty(), "{}", case.name);
            assert!(
                pushed.iter().all(|limit| *limit == Limit::Queue),
                "{}",
                case.name
            );
        }
        assert_eq!(workloads::pass(case, &outcome), Ok(None), "{}", case.name);
    }
}

/// The custom core with its persistence-gated messages sent at once: the
/// harness's persist-then-send check must catch it with the real core
/// behind the adapter, not only with a fixture (#681).
struct SendsEarly(Custom);

impl karyos_sim::harness::core::ConsensusCore for SendsEarly {
    type Message = <Custom as karyos_sim::harness::core::ConsensusCore>::Message;

    fn recover(
        id: karyos_sim::net::NodeId,
        peers: &[karyos_sim::net::NodeId],
        log: &mut karyos_sim::harness::core::LogView<'_>,
    ) -> Self {
        Self(Custom::recover(id, peers, log))
    }

    fn propose(
        &mut self,
        command: Vec<u8>,
        log: &mut karyos_sim::harness::core::LogView<'_>,
    ) -> Result<(), karyos_sim::harness::core::Refused> {
        self.0.propose(command, log)
    }

    fn step(
        &mut self,
        from: karyos_sim::net::NodeId,
        message: Self::Message,
        log: &mut karyos_sim::harness::core::LogView<'_>,
    ) {
        self.0.step(from, message, log);
    }

    fn tick(&mut self, now: u64, log: &mut karyos_sim::harness::core::LogView<'_>) {
        self.0.tick(now, log);
    }

    fn ready(
        &mut self,
        log: &mut karyos_sim::harness::core::LogView<'_>,
    ) -> Option<karyos_sim::harness::core::Ready<Self::Message>> {
        let mut ready = self.0.ready(log)?;
        let early = std::mem::take(&mut ready.after_persist);
        ready.messages.extend(early);
        Some(ready)
    }

    fn advance(
        &mut self,
        persisted: karyos_sim::harness::core::Persisted,
        log: &mut karyos_sim::harness::core::LogView<'_>,
    ) {
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

#[test]
fn a_reply_sent_before_persisting_is_caught_with_the_real_core() {
    use karyos_sim::harness::core::ConsensusCore as _;
    let _ = Custom::recover;
    let caught = SEEDS.iter().any(|&seed| {
        // Failed flushes: an acknowledgement sent before its write is
        // durable counts a follower that never held the entry.
        W4::skeleton(seed).cases().iter().any(|case| {
            let outcome = workloads::run::<SendsEarly>(case, seed).unwrap();
            outcome.safety.is_err()
        })
    });
    assert!(caught, "the persist-then-send check missed an early reply");
}
