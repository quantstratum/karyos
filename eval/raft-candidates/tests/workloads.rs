// SPDX-License-Identifier: Apache-2.0

//! ADR-0043's workloads W1 to W6 over the `raft` 0.7.0 adapter (plan
//! issue 060, karyos#678), as the harness's own tests run them over the
//! reference core: what passes, which gaps are allowed, and what is not
//! demonstrated yet, each asserted rather than assumed.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_raft_eval::raft_rs::RaftRs;
use karyos_sim::harness::core::Unsupported;
use karyos_sim::harness::workloads::{
    self, Failed, Liveness, RunError, W1, W2, W3, W3Fault, W4, W5, W6,
};

/// Seeds every sweep runs.
const SEEDS: [u64; 4] = [1, 0xC5, 0x0043, 0xDEAD_BEEF];

#[test]
fn w1_passes() {
    for seed in SEEDS {
        for case in W1::skeleton().cases() {
            let outcome = workloads::run::<RaftRs>(&case, seed).unwrap();
            assert_eq!(
                workloads::pass(&case, &outcome),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

/// W3: every fault keeps safety, and every case but the leader crash
/// completes. The leader crash is a liveness gap of the harness's client,
/// not of the core: server 0 crashes at step 2 and never restarts, the
/// clients start on it and re-target only when a server redirects them,
/// so they never reach the leader servers 1 and 2 elect.
#[test]
fn w3_safety_holds_and_only_the_unrestarted_crash_is_a_gap() {
    for seed in SEEDS {
        for (fault, case) in W3::skeleton().faults.iter().zip(W3::skeleton().cases()) {
            let outcome = workloads::run::<RaftRs>(&case, seed).unwrap();
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

/// W4: every cut keeps safety; a single failed flush recovers, and the
/// repeated failed flushes (a lost durable majority) are a gap with no
/// leader, as with the reference.
#[test]
fn w4_passes_and_a_lost_majority_is_a_gap() {
    for seed in SEEDS {
        for case in W4::skeleton(seed).cases() {
            let outcome = workloads::run::<RaftRs>(&case, seed).unwrap();
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
                w6.pass::<RaftRs>(&case, seed).unwrap(),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

/// The same seed reproduces the same run, observations included: raft-rs's
/// election timeout draw has one value (see the adapter).
#[test]
fn a_seed_reproduces_its_run() {
    let mut cases = W1::skeleton().cases();
    cases.extend(W3::skeleton().cases());
    for case in cases.iter().step_by(3) {
        for seed in SEEDS {
            let first = workloads::run::<RaftRs>(case, seed).unwrap();
            let second = workloads::run::<RaftRs>(case, seed).unwrap();
            assert_eq!(first, second, "{} seed {seed}", case.name);
        }
    }
}

/// W2 needs declared limits, which this adapter does not take yet
/// (karyos#679): every case is refused as not demonstrated, never run as
/// a pass.
#[test]
fn w2_is_not_demonstrated_yet() {
    for case in W2::skeleton().cases().unwrap() {
        assert!(
            matches!(
                workloads::run::<RaftRs>(&case, 1),
                Err(RunError::Unsupported(Unsupported))
            ),
            "{}",
            case.name
        );
    }
}

/// W5's snapshot cases need compaction and install, which this adapter
/// does not take yet (karyos#679), and are refused as not demonstrated;
/// its retry after a leader change runs, and its retry is not shown.
#[test]
fn w5_is_not_demonstrated_yet() {
    for case in W5::skeleton().cases().unwrap() {
        let run = workloads::run::<RaftRs>(&case, 1);
        if case.compaction.is_some() {
            assert!(
                matches!(run, Err(RunError::Unsupported(Unsupported))),
                "{}",
                case.name
            );
        } else {
            let outcome = run.unwrap();
            assert!(outcome.safety.is_ok(), "{}", case.name);
            assert!(
                matches!(
                    workloads::pass(&case, &outcome),
                    Ok(None) | Err(Failed::NotShown(_))
                ),
                "{}",
                case.name
            );
        }
    }
}
