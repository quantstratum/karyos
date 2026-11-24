// SPDX-License-Identifier: Apache-2.0

//! The C5 comparison's corpus runner over its three cores (version 2;
//! karyos#691, karyos#681; quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v1.md, Seed corpora and Hard
//! gates): `raft` 0.7.0, `openraft` 0.10.0-alpha.37 and the custom core
//! (ADR-0105), each over every case of W1 to W6 and every seed of the
//! corpus, through `karyos_sim::harness::corpus::run_corpus`. Each core
//! writes its own JSON lines file, one line per run, marked C5 version 2
//! evidence and naming the core and its build ([`Variant`]); the lines are
//! the raw results the report publishes and scores the hard gates from
//! (safety and durability over W3 to W5, determinism over W6 with
//! repetitions, recovery over W5), a run a core cannot take being
//! `not_demonstrated`, never passed.
//!
//! Ignored by default, as it takes long; run with
//! `cargo test --release --locked --test corpus -- --ignored --nocapture`
//! in `eval/raft-candidates`. `KARYOS_C5_SEEDS=FIRST..=LAST` picks the
//! seeds (default: the CI corpus, 1 to 1,000; the nightly corpus is 1,001
//! to 101,000, split by range across processes), `KARYOS_C5_CORES` a
//! comma-separated subset of `raft,openraft,custom`,
//! `KARYOS_C5_REPETITIONS` the determinism mode's repetitions per seed
//! (default 1), and `KARYOS_C5_OUT` the directory the files go in
//! (default: the target directory), named
//! `c5-v2-<core>-<first>-<last>.jsonl`. It prints each core's summary and
//! fails on nothing: a failed gate is a result to report, not a broken
//! run. The test that is not ignored checks the runner itself on one seed.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::BufWriter;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::time::Instant;

use karyos_raft_eval::openraft_core::{self, OpenRaft};
use karyos_raft_eval::raft_rs::{self, RaftRs};
use karyos_raft_eval::variant::{CUSTOM, Variant};
use karyos_sim::harness::core::ConsensusCore;
use karyos_sim::harness::corpus::{Evidence, Summary, Workload, run_corpus};
use karyos_sim::harness::custom::Custom;
use karyos_sim::harness::workloads::{Case, W1, W2, W3, W4, W5, W6};

/// The manifest's CI seeds.
const CI_SEEDS: RangeInclusive<u64> = 1..=1_000;

/// The cores of version 2, by name: each with its build.
const CORES: [(&str, Variant); 3] = [
    ("raft", raft_rs::VARIANT),
    ("openraft", openraft_core::VARIANT),
    ("custom", CUSTOM),
];

fn seeds() -> RangeInclusive<u64> {
    std::env::var("KARYOS_C5_SEEDS")
        .ok()
        .map_or(CI_SEEDS, |range| {
            let (first, last) = range.split_once("..=").unwrap();
            first.parse().unwrap()..=last.parse().unwrap()
        })
}

fn w1(_seed: u64) -> Vec<Case> {
    W1::skeleton().cases()
}
fn w2(_seed: u64) -> Vec<Case> {
    W2::skeleton().cases().unwrap()
}
fn w3(_seed: u64) -> Vec<Case> {
    W3::skeleton().cases()
}
fn w4(seed: u64) -> Vec<Case> {
    W4::skeleton(seed).cases()
}
fn w5(_seed: u64) -> Vec<Case> {
    W5::skeleton().cases().unwrap()
}
fn w6(_seed: u64) -> Vec<Case> {
    W6::skeleton().cases()
}

/// Every workload of the comparison.
const WORKLOADS: [Workload<'static>; 6] = [
    ("W1", &w1),
    ("W2", &w2),
    ("W3", &w3),
    ("W4", &w4),
    ("W5", &w5),
    ("W6", &w6),
];

/// The name a line gives a core: its name and its build.
fn label(name: &str, variant: Variant) -> String {
    format!("{name} ({})", variant.label())
}

/// Runs `workloads` of core `name` over `seeds` into `out`.
fn corpus(
    name: &str,
    workloads: &[Workload<'_>],
    seeds: RangeInclusive<u64>,
    repetitions: u32,
    out: &Path,
) -> Summary {
    let variant = CORES
        .iter()
        .find(|(core, _)| *core == name)
        .map(|(_, variant)| *variant)
        .unwrap();
    let core = label(name, variant);
    let mut file = BufWriter::new(std::fs::File::create(out).unwrap());
    let range = (seeds, repetitions);
    let summary = match name {
        "raft" => run::<RaftRs>(&core, workloads, range, &mut file),
        "openraft" => run::<OpenRaft>(&core, workloads, range, &mut file),
        "custom" => run::<Custom>(&core, workloads, range, &mut file),
        _ => panic!("unknown core {name}"),
    };
    drop(file);
    summary
}

fn run<C: ConsensusCore>(
    core: &str,
    workloads: &[Workload<'_>],
    range: (RangeInclusive<u64>, u32),
    out: &mut impl std::io::Write,
) -> Summary {
    run_corpus::<C>(core, Evidence::C5Version2, workloads, range, out).unwrap()
}

#[test]
#[ignore = "the corpus takes long; run on request"]
#[allow(
    clippy::print_stdout,
    reason = "each core's summary and timing, for the report"
)]
fn the_c5_version_2_corpus_over_every_core() {
    let seeds = seeds();
    let repetitions = std::env::var("KARYOS_C5_REPETITIONS")
        .ok()
        .map_or(1, |text| text.parse().unwrap());
    let dir = std::env::var_os("KARYOS_C5_OUT")
        .map_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")), PathBuf::from);
    let wanted = std::env::var("KARYOS_C5_CORES").unwrap_or_else(|_| "raft,openraft,custom".into());
    for name in wanted.split(',') {
        let out = dir.join(format!(
            "c5-v2-{name}-{}-{}.jsonl",
            seeds.start(),
            seeds.end()
        ));
        let start = Instant::now();
        let summary = corpus(name, &WORKLOADS, seeds.clone(), repetitions, &out);
        println!(
            "c5 v2 corpus: {name}, seeds {seeds:?}, repetitions {repetitions}, runs {}, passed {}, liveness gaps {}, step bound {}, failed {}, errors {}, not demonstrated {}, {:.1} s, {}",
            summary.runs,
            summary.passed,
            summary.liveness_gaps,
            summary.step_bound,
            summary.failed.len(),
            summary.errors,
            summary.not_demonstrated,
            start.elapsed().as_secs_f64(),
            out.display()
        );
        for (workload, case, seed) in &summary.failed {
            println!("  failed: {workload} {case} seed {seed}");
        }
    }
}

/// The runner on one seed of W5 for every core: one line per case and
/// core, each marked C5 version 2 evidence and naming its core and build.
#[test]
fn every_core_writes_one_marked_line_per_run() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let workloads: [Workload<'_>; 1] = [("W5", &w5)];
    let cases = u64::try_from(w5(1).len()).unwrap();
    for (name, variant) in CORES {
        let out = dir.join(format!("c5-v2-check-{name}.jsonl"));
        let summary = corpus(name, &workloads, 1..=1, 1, &out);
        assert_eq!(summary.runs, cases, "{name}");
        let text = std::fs::read_to_string(&out).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(u64::try_from(lines.len()).unwrap(), cases, "{name}");
        let core = format!("\"core\":\"{}\"", label(name, variant));
        let evidence = format!("\"evidence\":\"{}\"", Evidence::C5Version2.text());
        for line in lines {
            assert!(line.contains(&core), "{line}");
            assert!(line.contains(&evidence), "{line}");
            assert!(line.contains("\"workload\":\"W5\""), "{line}");
        }
    }
    assert_eq!(label("custom", CUSTOM), "custom (in-tree)");
}
