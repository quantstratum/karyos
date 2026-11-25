// SPDX-License-Identifier: Apache-2.0

//! The C5 comparison's corpus runner over its three cores (version 2;
//! karyos#691, karyos#681; quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v1.md and -v2.md, Seed corpora
//! and Hard gates): `raft` 0.7.0, `openraft` 0.10.0-alpha.37 and the
//! custom core (ADR-0105), each over every case of W1 to W6 and every seed
//! of the corpus, through `karyos_sim::harness::corpus::run_corpus`.
//!
//! **Profiles.** W2 and W5 run their manifest values (W2's 10,000-entry
//! catch-up, W5's compaction every 1,000 entries keeping 100) and W2 adds
//! version 2's in-flight byte case (`tests/v2/mod.rs`, the very case
//! `tests/w2_bytes.rs` checks with its message oracle); W1, W3, W4 and W6
//! have one profile, their skeleton. `KARYOS_C5_PROFILE=skeleton` runs
//! W2's and W5's skeletons instead, for a quick look; its lines say so.
//!
//! **Lines.** Each core writes its own JSON lines file, one line per run,
//! marked `"evidence":"C5 version 2"`, naming the core, its build
//! ([`Variant`]), the profile and the `karyos` revision it ran at, with
//! `-dirty` when the checkout had changes. A line's verdict is the
//! harness's (`pass`, `liveness_gap`, `failed_*`, `error`,
//! `not_demonstrated`); the byte case's oracle is `tests/w2_bytes.rs`'s,
//! not a line's. `"repetitions"` is the determinism mode: with 1, a W6 run
//! is not replayed, and the report scores determinism from a run with 2 or
//! more (`KARYOS_C5_REPETITIONS`).
//!
//! Ignored by default, as it takes long; run with
//! `cargo test --release --locked --test corpus -- --ignored --nocapture`
//! in `eval/raft-candidates`. `KARYOS_C5_SEEDS=FIRST..=LAST` picks the
//! seeds (default: the CI corpus, 1 to 1,000; the nightly corpus is 1,001
//! to 101,000, split by range across processes), `KARYOS_C5_CORES` a
//! comma-separated subset of `raft,openraft,custom`, and `KARYOS_C5_OUT`
//! the directory the files go in (default: Cargo's `CARGO_TARGET_TMPDIR`
//! for this test), named `c5-v2-<core>-<first>-<last>.jsonl`. A gate's
//! failure is a result in the lines, never a failed test; the test fails
//! only when the runner cannot run or write them.

#![allow(clippy::unwrap_used, clippy::panic)]

mod v2;

use std::io::{BufWriter, Write as _};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::process::Command;
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

/// The seeds: `KARYOS_C5_SEEDS`, or the CI corpus; an empty range is
/// refused.
fn seeds() -> RangeInclusive<u64> {
    let seeds = std::env::var("KARYOS_C5_SEEDS")
        .ok()
        .map_or(CI_SEEDS, |range| {
            let (first, last) = range.split_once("..=").unwrap();
            first.parse().unwrap()..=last.parse().unwrap()
        });
    assert!(!seeds.is_empty(), "an empty seed range: {seeds:?}");
    seeds
}

/// The `karyos` revision the run is at, `-dirty` when the checkout has
/// changes, or `unknown` without git.
fn revision() -> String {
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    let Some(head) = git(&["rev-parse", "--short=12", "HEAD"]) else {
        return "unknown".to_owned();
    };
    let dirty = git(&["status", "--porcelain"]).is_some_and(|status| !status.is_empty());
    if dirty { format!("{head}-dirty") } else { head }
}

fn w1(_seed: u64) -> Vec<Case> {
    W1::skeleton().cases()
}
fn w2(_seed: u64) -> Vec<Case> {
    let mut cases = W2::manifest().cases().unwrap();
    cases.push(v2::byte_case());
    cases
}
fn w2_skeleton(_seed: u64) -> Vec<Case> {
    let mut cases = W2::skeleton().cases().unwrap();
    cases.push(v2::byte_case());
    cases
}
fn w3(_seed: u64) -> Vec<Case> {
    W3::skeleton().cases()
}
fn w4(seed: u64) -> Vec<Case> {
    W4::skeleton(seed).cases()
}
fn w5(_seed: u64) -> Vec<Case> {
    W5::manifest().cases().unwrap()
}
fn w5_skeleton(_seed: u64) -> Vec<Case> {
    W5::skeleton().cases().unwrap()
}
fn w6(_seed: u64) -> Vec<Case> {
    W6::skeleton().cases()
}

/// Every workload of the comparison, in the `manifest` profile or the
/// skeleton one.
fn workloads(manifest: bool) -> [Workload<'static>; 6] {
    if manifest {
        [
            ("W1", &w1),
            ("W2", &w2),
            ("W3", &w3),
            ("W4", &w4),
            ("W5", &w5),
            ("W6", &w6),
        ]
    } else {
        [
            ("W1", &w1),
            ("W2", &w2_skeleton),
            ("W3", &w3),
            ("W4", &w4),
            ("W5", &w5_skeleton),
            ("W6", &w6),
        ]
    }
}

/// The name a line gives a core: its name, its build, the profile and
/// the revision.
fn label(name: &str, variant: Variant, profile: &str, revision: &str) -> String {
    format!("{name} ({}) {profile} @{revision}", variant.label())
}

/// Runs `workloads` of core `name` over `seeds` into `out`, flushed and
/// synced before it returns.
fn corpus(
    name: &str,
    core: &str,
    workloads: &[Workload<'_>],
    range: (RangeInclusive<u64>, u32),
    out: &Path,
) -> Summary {
    let file = std::fs::File::create(out).unwrap();
    let mut writer = BufWriter::new(file);
    let summary = match name {
        "raft" => run::<RaftRs>(core, workloads, range, &mut writer),
        "openraft" => run::<OpenRaft>(core, workloads, range, &mut writer),
        "custom" => run::<Custom>(core, workloads, range, &mut writer),
        _ => panic!("unknown core {name}: raft, openraft or custom"),
    };
    writer.flush().unwrap();
    writer.into_inner().unwrap().sync_all().unwrap();
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

/// A core's build by name.
fn variant(name: &str) -> Variant {
    CORES
        .iter()
        .find(|(core, _)| *core == name)
        .map(|(_, variant)| *variant)
        .unwrap_or_else(|| panic!("unknown core {name}: raft, openraft or custom"))
}

#[test]
#[ignore = "the corpus takes long; run on request"]
#[allow(
    clippy::print_stdout,
    reason = "each core's summary and timing, for the report"
)]
fn the_c5_version_2_corpus_over_every_core() {
    let seeds = seeds();
    let repetitions: u32 = std::env::var("KARYOS_C5_REPETITIONS")
        .ok()
        .map_or(1, |text| text.parse().unwrap());
    let profile = std::env::var("KARYOS_C5_PROFILE").unwrap_or_else(|_| "manifest".into());
    assert!(
        profile == "manifest" || profile == "skeleton",
        "KARYOS_C5_PROFILE: manifest or skeleton, not {profile}"
    );
    let dir = std::env::var_os("KARYOS_C5_OUT")
        .map_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")), PathBuf::from);
    let wanted = std::env::var("KARYOS_C5_CORES").unwrap_or_else(|_| "raft,openraft,custom".into());
    let revision = revision();
    let workloads = workloads(profile == "manifest");
    for name in wanted.split(',') {
        let core = label(name, variant(name), &profile, &revision);
        let out = dir.join(format!(
            "c5-v2-{name}-{}-{}.jsonl",
            seeds.start(),
            seeds.end()
        ));
        let start = Instant::now();
        let summary = corpus(name, &core, &workloads, (seeds.clone(), repetitions), &out);
        println!(
            "c5 v2 corpus: {core}, seeds {seeds:?}, repetitions {repetitions}{}, runs {}, passed {}, liveness gaps {}, step bound {}, failed {}, errors {}, not demonstrated {}, {:.1} s, {}",
            if repetitions < 2 {
                " (determinism not replayed)"
            } else {
                ""
            },
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
            println!("  failed: {workload} {case} seed {seed} (its line carries the minimised run)");
        }
        for ((workload, fault), [before, during, after]) in &summary.coverage {
            println!(
                "  coverage: {workload} {fault}: before first commit {before}, during replication {during}, after last commit {after}"
            );
        }
    }
}

/// A field of a line, as its raw JSON text up to the next field.
fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\":");
    let (_, rest) = line.split_once(key.as_str()).unwrap();
    let end = match rest.strip_prefix('"') {
        Some(text) => text.find('"').unwrap() + 2,
        None => rest.find([',', '}']).unwrap(),
    };
    rest.get(..end).unwrap()
}

/// The runner on one seed of W5's skeleton for every core: one line per
/// case and core, in order, each marked C5 version 2 evidence, naming its
/// core, build, profile and revision, its workload, case and seed, and a
/// verdict of the harness's; the custom core's W5 runs are never errors.
#[test]
fn every_core_writes_one_marked_line_per_run() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let workloads: [Workload<'_>; 1] = [("W5", &w5_skeleton)];
    let cases = w5_skeleton(1);
    let revision = revision();
    assert_ne!(revision, "unknown", "the checkout's revision");
    for (name, variant) in CORES {
        let out = dir.join(format!("c5-v2-check-{name}.jsonl"));
        let core = label(name, variant, "skeleton", &revision);
        let summary = corpus(name, &core, &workloads, (1..=1, 1), &out);
        assert_eq!(summary.runs, u64::try_from(cases.len()).unwrap(), "{name}");
        let text = std::fs::read_to_string(&out).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), cases.len(), "{name}");
        for (line, case) in lines.iter().zip(&cases) {
            assert_eq!(field(line, "evidence"), "\"C5 version 2\"", "{line}");
            assert_eq!(field(line, "core"), format!("\"{core}\""), "{line}");
            assert_eq!(field(line, "workload"), "\"W5\"", "{line}");
            assert_eq!(field(line, "case"), format!("\"{}\"", case.name), "{line}");
            assert_eq!(field(line, "seed"), "1", "{line}");
            assert_eq!(field(line, "repetitions"), "1", "{line}");
            let verdict = field(line, "verdict");
            assert!(
                verdict == "\"pass\""
                    || verdict == "\"liveness_gap\""
                    || verdict == "\"not_demonstrated\""
                    || verdict.starts_with("\"failed_")
                    || verdict == "\"error\"",
                "{line}"
            );
            if name == "custom" {
                assert_ne!(verdict, "\"error\"", "{line}");
            }
            assert!(line.contains("\"coverage\":["), "{line}");
            // Seed 1 is named: a run that ran carries its trace; one not
            // demonstrated, or not set up, has none to carry.
            let ran = verdict != "\"not_demonstrated\"" && verdict != "\"error\"";
            assert_eq!(
                field(line, "trace").starts_with("null"),
                !ran,
                "seed 1 is named: {line}"
            );
        }
    }
    assert_eq!(
        label("custom", CUSTOM, "manifest", "abc"),
        "custom (in-tree) manifest @abc"
    );
}

/// The manifest profile carries W2's and W5's manifest cases and the
/// version 2 byte case, the very one its oracle checks.
#[test]
fn the_manifest_profile_runs_the_frozen_cases() {
    let w2_cases = w2(1);
    assert_eq!(w2_cases.last(), Some(&v2::byte_case()));
    assert_eq!(
        w2_cases.get(..w2_cases.len() - 1),
        Some(W2::manifest().cases().unwrap().as_slice())
    );
    assert_eq!(w5(1), W5::manifest().cases().unwrap());
    assert_ne!(w5(1), w5_skeleton(1));
}
