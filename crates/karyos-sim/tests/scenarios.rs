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
