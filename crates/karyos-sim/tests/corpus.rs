// SPDX-License-Identifier: Apache-2.0

//! The C5 comparison's CI corpus (seeds 1 to 1,000, quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v1.md, Corpora) over the
//! workloads the harness has, of the `Reference` fixture: harness
//! validation, not C5 evidence, as every line it writes says. Ignored by
//! default, as it takes long; run with
//! `cargo test --release -p karyos-sim --test corpus -- --ignored --nocapture`.
//! `KARYOS_C5_OUT` names the JSON lines file (default: the target
//! directory's `c5-corpus-reference.jsonl`); `KARYOS_C5_SEEDS=FIRST..=LAST`
//! narrows the seeds. It prints the runs, the time taken and the bytes
//! written, and fails on a failed check or a run that could not be set up.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::BufWriter;
use std::path::PathBuf;
use std::time::Instant;

use karyos_sim::harness::corpus::{Evidence, run_corpus};
use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::workloads::{W1, W3, W4, W6};

/// The manifest's CI seeds.
const CI_SEEDS: std::ops::RangeInclusive<u64> = 1..=1_000;

fn seeds() -> std::ops::RangeInclusive<u64> {
    std::env::var("KARYOS_C5_SEEDS")
        .ok()
        .map_or(CI_SEEDS, |range| {
            let (first, last) = range.split_once("..=").unwrap();
            first.parse().unwrap()..=last.parse().unwrap()
        })
}

#[test]
#[ignore = "the CI corpus takes long; run on request"]
#[allow(
    clippy::print_stdout,
    reason = "the run's timing and size, for the coordinator's estimate"
)]
fn the_ci_corpus_of_the_reference_fixture() {
    let out = std::env::var_os("KARYOS_C5_OUT").map_or_else(
        || PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("c5-corpus-reference.jsonl"),
        PathBuf::from,
    );
    let w1 = |_seed: u64| W1::skeleton().cases();
    let w3 = |_seed: u64| W3::skeleton().cases();
    let w4 = |seed: u64| W4::skeleton(seed).cases();
    let w6 = |_seed: u64| W6::skeleton().cases();
    let counts = (w1(1).len(), w3(1).len(), w4(1).len(), w6(1).len());
    let workloads: [karyos_sim::harness::corpus::Workload<'_>; 4] =
        [("W1", &w1), ("W3", &w3), ("W4", &w4), ("W6", &w6)];
    let seeds = seeds();
    let start = Instant::now();
    let mut file = BufWriter::new(std::fs::File::create(&out).unwrap());
    let summary = run_corpus::<Reference>(
        "reference",
        Evidence::HarnessValidation,
        &workloads,
        seeds.clone(),
        &mut file,
    )
    .unwrap();
    drop(file);
    let elapsed = start.elapsed();
    let bytes = std::fs::metadata(&out).unwrap().len();
    println!(
        "c5 corpus: reference, seeds {seeds:?}, cases W1 {} W3 {} W4 {} W6 {}, runs {}, passed {}, liveness gaps {}, step bound {}, failed {}, errors {}, {:.1} s, {bytes} bytes, {}",
        counts.0,
        counts.1,
        counts.2,
        counts.3,
        summary.runs,
        summary.passed,
        summary.liveness_gaps,
        summary.step_bound,
        summary.failed.len(),
        summary.errors,
        elapsed.as_secs_f64(),
        out.display()
    );
    assert!(summary.failed.is_empty(), "{:?}", summary.failed);
    assert_eq!(summary.errors, 0);
}
