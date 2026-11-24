// SPDX-License-Identifier: Apache-2.0

//! Differential tests of the custom Raft core against the `raft` 0.7.0
//! adapter (C5 version 2; ADR-0105 decision 4, ADR-0039's extra
//! conditions for a custom core): on W1 to W4, the same cases and seeds,
//! and equal safety outcomes asserted, not equal schedules. Each core
//! elects and replicates as it does; what must agree is the verdict.

#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_raft_eval::raft_rs::RaftRs;
use karyos_sim::harness::core::ConsensusCore;
use karyos_sim::harness::custom::Custom;
use karyos_sim::harness::workloads::{self, Case, Failed, Liveness, W1, W2, W3, W4};

/// Seeds every sweep runs: the candidates' suite's.
const SEEDS: [u64; 4] = [1, 0xC5, 0x0043, 0xDEAD_BEEF];

/// What a run's safety and pass verdict are, without its schedule: the
/// safety result's kind, and the pass result as passed, a named gap, or a
/// failure's kind.
fn verdict<C: ConsensusCore>(case: &Case, seed: u64) -> (bool, String) {
    let outcome = workloads::run::<C>(case, seed).unwrap();
    let safe = outcome.safety.is_ok();
    let pass = match workloads::pass(case, &outcome) {
        Ok(None) => "pass".to_owned(),
        Ok(Some(Liveness::NoLeader)) => "gap: no leader".to_owned(),
        Ok(Some(Liveness::Stalled { .. })) => "gap: stalled".to_owned(),
        Err(Failed::Safety(violation)) => format!("unsafe: {violation:?}"),
        Err(failed) => format!("failed: {failed:?}"),
    };
    (safe, pass)
}

/// The safety outcomes of both cores agree on every case: each is safe,
/// and neither has a violation the other does not. Liveness may differ:
/// each core elects on its own schedule, and a stall or a gap is reported
/// apart from safety.
fn differ(cases: &[Case], seed: u64) {
    for case in cases {
        let raft = verdict::<RaftRs>(case, seed);
        let custom = verdict::<Custom>(case, seed);
        assert_eq!(
            raft.0, custom.0,
            "{} seed {seed}: raft {raft:?}, custom {custom:?}",
            case.name
        );
        assert!(custom.0, "{} seed {seed}: {custom:?}", case.name);
    }
}

#[test]
fn w1_safety_outcomes_agree() {
    for seed in SEEDS {
        differ(&W1::skeleton().cases(), seed);
    }
}

#[test]
fn w2_safety_outcomes_agree() {
    differ(&W2::skeleton().cases().unwrap(), 1);
}

#[test]
fn w3_safety_outcomes_agree() {
    for seed in SEEDS {
        differ(&W3::skeleton().cases(), seed);
    }
}

#[test]
fn w4_safety_outcomes_agree() {
    for seed in SEEDS {
        differ(&W4::skeleton(seed).cases(), seed);
    }
}
