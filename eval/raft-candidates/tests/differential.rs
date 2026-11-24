// SPDX-License-Identifier: Apache-2.0

//! Differential tests of the custom Raft core against the `raft` 0.7.0
//! adapter (C5 version 2; ADR-0105 decision 4, ADR-0039's extra
//! conditions for a custom core): on W1 to W4, W2's version 2 byte case
//! included, the same cases and seeds, and equal safety outcomes
//! asserted, not equal schedules. Each core elects and replicates as it
//! does; what must agree is every verdict on safety and state, while
//! liveness may differ.

#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_raft_eval::raft_rs::RaftRs;
use karyos_sim::harness::core::ConsensusCore;
use karyos_sim::harness::custom::Custom;
use karyos_sim::harness::workloads::{self, Case, Failed, W1, W2, W3, W4};

mod v2;

/// Seeds every sweep runs: the candidates' suite's.
const SEEDS: [u64; 4] = [1, 0xC5, 0x0043, 0xDEAD_BEEF];

/// A run's safety verdict, typed: safe, or the kind of the safety or state
/// failure the pass predicate found. A liveness gap, a stall or a case
/// that did not show what it needed is not a safety verdict: each core
/// elects on its own schedule.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Safe,
    Unsafe(String),
    Diverged,
    NotReplayed,
    WrongState,
}

fn verdict<C: ConsensusCore>(case: &Case, seed: u64) -> Verdict {
    let outcome = workloads::run::<C>(case, seed).unwrap();
    if let Err(violation) = &outcome.safety {
        let kind = format!("{violation:?}");
        let kind = kind
            .split([' ', '(', '{'])
            .next()
            .unwrap_or_default()
            .to_owned();
        return Verdict::Unsafe(kind);
    }
    match workloads::pass(case, &outcome) {
        Ok(_) | Err(Failed::Liveness(_) | Failed::NotShown(_) | Failed::NotBehind { .. }) => {
            Verdict::Safe
        }
        Err(Failed::Safety(violation)) => Verdict::Unsafe(format!("{violation:?}")),
        Err(Failed::Diverged(_)) => Verdict::Diverged,
        Err(Failed::NotReplayed) => Verdict::NotReplayed,
        Err(Failed::WrongState { .. }) => Verdict::WrongState,
    }
}

/// Both cores give the same safety verdict on every case, and it is safe.
fn differ(cases: &[Case], seed: u64) {
    for case in cases {
        let raft = verdict::<RaftRs>(case, seed);
        let custom = verdict::<Custom>(case, seed);
        assert_eq!(raft, custom, "{} seed {seed}", case.name);
        assert_eq!(custom, Verdict::Safe, "{} seed {seed}", case.name);
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
    let mut cases = W2::skeleton().cases().unwrap();
    cases.push(v2::byte_case());
    for seed in SEEDS {
        differ(&cases, seed);
    }
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
