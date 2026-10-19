// SPDX-License-Identifier: Apache-2.0

//! Every scenario over the seed list; a failure prints its seed and trace.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::panic)]

use karyos_sim::{run, scenarios};

fn sweep(name: &str) {
    let scenario = scenarios::all()
        .into_iter()
        .find(|scenario| scenario.name == name)
        .unwrap_or_else(|| panic!("no scenario {name}"));
    let mut accepted = 0;
    for seed in scenarios::seeds() {
        match run(&scenario, seed) {
            Ok(report) => accepted += report.accepted,
            Err(failure) => panic!("{failure}"),
        }
    }
    assert!(accepted > 0, "scenario {name} accepted nothing");
}

#[test]
fn steady() {
    sweep("steady");
}

#[test]
fn pauses() {
    sweep("pauses");
}

#[test]
fn driver_pauses() {
    sweep("driver-pauses");
}

#[test]
fn forgotten() {
    sweep("forgotten");
}

#[test]
fn removal() {
    sweep("removal");
}

#[test]
fn cutover() {
    sweep("cutover");
}

#[test]
fn mixed() {
    sweep("mixed");
}

/// A stall scenario: the sweep passes, and the driver revoked a client's
/// reader in some seed, so the loss path ran.
fn stall_sweep(name: &str) {
    let scenario = scenarios::all()
        .into_iter()
        .find(|scenario| scenario.name == name)
        .unwrap_or_else(|| panic!("no scenario {name}"));
    let (mut accepted, mut revoked) = (0, 0);
    for seed in scenarios::seeds() {
        match run(&scenario, seed) {
            Ok(report) => {
                accepted += report.accepted;
                revoked += report.revoked;
            }
            Err(failure) => panic!("{failure}"),
        }
    }
    assert!(accepted > 0, "scenario {name} accepted nothing");
    assert!(revoked > 0, "scenario {name} revoked no client");
}

#[test]
fn stall_hold() {
    stall_sweep("stall-hold");
}

#[test]
fn stall_continue() {
    stall_sweep("stall-continue");
}

#[test]
fn stall_abort() {
    stall_sweep("stall-abort");
}

/// A conflated stream with paused views and writers that keep updating:
/// versions never go backwards and every key ends at its latest accepted
/// value (conflation-end-to-end.md, Tests).
#[test]
fn conflated() {
    sweep("conflated");
}

#[test]
fn a_seed_reproduces_its_run() {
    for scenario in scenarios::all() {
        let first = run(&scenario, 7).unwrap_or_else(|failure| panic!("{failure}"));
        let second = run(&scenario, 7).unwrap_or_else(|failure| panic!("{failure}"));
        assert_eq!(first, second, "scenario {}", scenario.name);
        let other = run(&scenario, 8).unwrap_or_else(|failure| panic!("{failure}"));
        assert_ne!(first.digest, other.digest, "scenario {}", scenario.name);
    }
}
