// SPDX-License-Identifier: Apache-2.0

//! ADR-0043's workloads over the reference core (cluster-gap-analysis.md
//! §6, C5), over a fixed corpus of seeds plus `scenarios::seeds()`
//! (`KARYOS_SIM_SEEDS` widens it):
//!
//! - the reference passes W1, W4 and W6, and W3's safety predicates;
//! - W3's leader crash, and W4's lost durable majority, show a liveness
//!   gap, not a violation;
//! - a retried command is applied twice and answered once, by the
//!   service's deduplication, and the state digest is the linearized
//!   history's;
//! - W2 and W5 are typed as not yet runnable.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::workloads::{
    self, ADR_0043, Liveness, Progress, W1, W3, W3Fault, W4, W4Cut, W6,
};
use karyos_sim::scenarios;

/// Seeds every sweep runs besides `scenarios::seeds()`.
const CORPUS: [u64; 4] = [0xC5, 0x0043, 0xDEAD_BEEF, u64::MAX];

fn corpus() -> Vec<u64> {
    let mut seeds = CORPUS.to_vec();
    seeds.extend(scenarios::seeds());
    seeds
}

#[test]
fn the_module_records_its_adr_revision() {
    assert!(ADR_0043.contains("03ffb394"));
    assert!(ADR_0043.contains("Proposed"));
    assert_eq!(workloads::w2().unwrap_err().workload, "W2");
    assert_eq!(workloads::w5().unwrap_err().workload, "W5");
}

#[test]
fn w1_passes() {
    let cases = W1::skeleton().cases();
    assert_eq!(cases.len(), 16);
    // The full sweep for a few seeds; the widest case for the rest.
    for seed in corpus() {
        let chosen: Vec<_> = if CORPUS.contains(&seed) {
            cases.iter().collect()
        } else {
            cases
                .iter()
                .filter(|case| case.servers == 5)
                .take(2)
                .collect()
        };
        for case in chosen {
            let outcome = workloads::run::<Reference>(case, seed).unwrap();
            assert_eq!(
                workloads::pass(case, &outcome),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

#[test]
fn w3_safety_holds_and_a_leader_crash_is_a_gap() {
    let w3 = W3::skeleton();
    for seed in corpus() {
        for (fault, case) in w3.faults.iter().zip(w3.cases()) {
            let outcome = workloads::run::<Reference>(&case, seed).unwrap();
            let expected = if *fault == W3Fault::LeaderCrash {
                Some(Liveness::NoLeader)
            } else {
                None
            };
            assert_eq!(
                workloads::pass(&case, &outcome),
                Ok(expected),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

#[test]
fn w4_passes_and_a_lost_majority_is_a_gap() {
    for seed in corpus() {
        let w4 = W4::skeleton(seed);
        let cases = w4.cases();
        let modes = w4.survives.len();
        for (index, case) in cases.iter().enumerate() {
            let cut = w4.cuts[index / modes];
            let outcome = workloads::run::<Reference>(case, seed).unwrap();
            let verdict = workloads::pass(case, &outcome);
            match cut {
                W4Cut::FailedFlushes { .. } => assert!(
                    matches!(verdict, Ok(Some(Liveness::Stalled { .. }))),
                    "{} seed {seed}: {verdict:?}",
                    case.name
                ),
                W4Cut::LeaderCrash { .. } => {
                    assert_eq!(case.progress, Progress::MayStop);
                    assert!(verdict.is_ok(), "{} seed {seed}: {verdict:?}", case.name);
                }
                W4Cut::FollowerCrash { .. } | W4Cut::FailedFlush { .. } => {
                    assert_eq!(verdict, Ok(None), "{} seed {seed}", case.name);
                }
            }
        }
    }
}

#[test]
fn slow_replies_are_retried_and_deduplicated() {
    let case = W6::skeleton()
        .cases()
        .into_iter()
        .find(|case| case.name == "W6 slow replies")
        .unwrap();
    for seed in corpus() {
        let outcome = workloads::run::<Reference>(&case, seed).unwrap();
        assert_eq!(workloads::pass(&case, &outcome), Ok(None), "seed {seed}");
        assert!(outcome.deduplicated > 0, "seed {seed}: nothing retried");
    }
}

#[test]
fn w6_replays_every_seed() {
    let w6 = W6::skeleton();
    for seed in corpus() {
        for case in w6.cases() {
            assert_eq!(
                w6.pass::<Reference>(&case, seed).unwrap(),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}
