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

/// C5 version 2's W5 retry, relative to whoever leads: the custom core
/// passes it on every seed, and a deadline before the cut can act makes
/// it fail as not shown, never pass.
#[test]
fn the_lost_reply_whoever_leads_passes_and_an_unreached_trigger_fails() {
    use karyos_sim::harness::workloads::{Failed, W5};
    let case = W5::manifest().lost_reply_whoever_leads();
    for seed in SEEDS {
        let outcome = workloads::run::<Custom>(&case, seed).unwrap();
        assert_eq!(
            workloads::pass(&case, &outcome),
            Ok(None),
            "{} seed {seed}",
            case.name
        );
    }
    let mut late = case.clone();
    if let Some(lost) = late.lost_reply.as_mut() {
        lost.deadline = lost.from - 1;
    }
    let outcome = workloads::run::<Custom>(&late, 1).unwrap();
    assert_eq!(
        workloads::pass(&late, &outcome),
        Err(Failed::NotShown("lost reply"))
    );
}
