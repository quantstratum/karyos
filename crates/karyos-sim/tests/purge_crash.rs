// SPDX-License-Identifier: Apache-2.0

//! C8b's prefix purge of the Raft log (karyos-cluster `RaftLog::purge_prefix`
//! over A2's `SegmentStore::purge_before`) on C2's crashing disk
//! (quantstratum-docs: karyos/design/cluster-dedup-and-snapshots.md §3, S4).
//!
//! The workload appends entries of 300 bytes over 4 KiB segments, so they
//! span segments, commits them, purges a prefix, appends more and purges
//! again. It runs once per disk operation with the disk crashing at that
//! operation (and once after the last), and once per flush with that flush
//! failing; each run is reopened under every survival mode of
//! [`Survives`]: `Synced` and `Everything` once, `Subset` and `Torn` once
//! per seed of [`scenarios::seeds`].
//!
//! The invariant, checked at every crash point:
//!
//! 1. the log opens;
//! 2. its first index is the last completed purge's, or the one in flight
//!    when it stopped: never another, never below a completed purge;
//! 3. every entry it reported durable from the first index on is present,
//!    byte for byte;
//! 4. it opens again the same, and appends.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::BTreeMap;
use std::path::Path;

use karyos_archive::segment::Geometry;
use karyos_cluster::{Entry, HardState, RaftLog};
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::rng::Rng;
use karyos_sim::scenarios;

const DIR: &str = "/raft";

fn geometry() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

fn entry(index: u64) -> Entry {
    let payload = (0..300u64)
        .map(|at| u8::try_from((at * 31 + index * 7) % 251).unwrap())
        .collect();
    Entry {
        index,
        term: 1,
        event_time: index * 1_000,
        payload,
    }
}

/// One step of the workload.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// Appends entries from the next index to this one, syncs them and
    /// commits them.
    Commit(u64),
    /// Purges below this index.
    Purge(u64),
}

const STEPS: [Step; 4] = [
    Step::Commit(30),
    Step::Purge(22),
    Step::Commit(45),
    Step::Purge(40),
];

/// What the workload knew when it stopped.
#[derive(Debug, Default)]
struct Model {
    /// Entries reported durable.
    durable: BTreeMap<u64, Entry>,
    /// The first index after the last purge that returned.
    first: u64,
    /// The first index of a purge in flight.
    purging: Option<u64>,
    completed: bool,
}

fn run(disk: SimDisk) -> Model {
    let mut model = Model {
        first: 1,
        ..Model::default()
    };
    let Ok(mut log) = RaftLog::create(disk, Path::new(DIR), geometry(), 1) else {
        return model;
    };
    let mut next = 1;
    for step in STEPS {
        match step {
            Step::Commit(to) => {
                let batch: Vec<Entry> = (next..=to).map(entry).collect();
                if log.append(&batch).is_err() {
                    return model;
                }
                let Ok(durable) = log.sync() else {
                    return model;
                };
                for written in &batch {
                    if durable.is_some_and(|durable| written.index <= durable) {
                        let _ = model.durable.insert(written.index, written.clone());
                    }
                }
                let state = HardState {
                    current_term: 1,
                    voted_for: None,
                    commit: Some(to),
                };
                if log.save_hard_state(state).is_err() {
                    return model;
                }
                next = to + 1;
            }
            Step::Purge(below) => {
                model.purging = Some(below);
                match log.purge_prefix(below) {
                    Ok(first) => {
                        assert_eq!(first, below);
                        model.first = first;
                        model.purging = None;
                    }
                    Err(_) => return model,
                }
            }
        }
    }
    model.completed = true;
    model
}

fn check(disk: &SimDisk, survives: Survives, model: &Model) -> Result<(), String> {
    let restarted = disk
        .after_crash(survives)
        .map_err(|error| error.to_string())?;
    let opened = match RaftLog::open(restarted.clone(), Path::new(DIR), geometry()) {
        Ok(opened) => opened,
        // A creation that never wrote its first-index file is no log.
        Err(_) if model.durable.is_empty() && model.first == 1 => return Ok(()),
        Err(error) => return Err(format!("open: {error}")),
    };
    let mut log = opened.log;
    let first = log.first_index();
    if first != model.first && Some(first) != model.purging {
        return Err(format!(
            "first index {first}, expected {} or {:?}",
            model.first, model.purging
        ));
    }
    for (index, entry) in model.durable.range(first..) {
        let got = log
            .entries(*index..index + 1, u64::MAX)
            .map_err(|error| format!("read {index}: {error}"))?;
        if got.first() != Some(entry) {
            return Err(format!("entry {index} differs"));
        }
    }
    let last = log.last_index();
    drop(log);
    let mut log = RaftLog::open(restarted, Path::new(DIR), geometry())
        .map_err(|error| format!("second open: {error}"))?
        .log;
    if (log.first_index(), log.last_index()) != (first, last) {
        return Err("the second open differs".into());
    }
    let next = last.map_or(first, |last| last + 1);
    let mut more = entry(next);
    more.index = next;
    log.append(&[more])
        .map_err(|error| format!("append after reopen: {error}"))?;
    Ok(())
}

fn check_all(disk: &SimDisk, model: &Model, point: u64, label: &str, failures: &mut Vec<String>) {
    let mut modes = vec![(Survives::Synced, None), (Survives::Everything, None)];
    for seed in scenarios::seeds() {
        let mixed = Rng::new(seed ^ point.rotate_left(32)).next_u64();
        modes.push((Survives::Subset { seed: mixed }, Some(seed)));
        modes.push((Survives::Torn { seed: mixed }, Some(seed)));
    }
    for (survives, base) in modes {
        if let Err(broken) = check(disk, survives, model) {
            let seed = base.map_or_else(String::new, |seed| format!(" (KARYOS_SIM_SEED={seed})"));
            failures.push(format!("{label} under {survives:?}{seed}: {broken}"));
        }
    }
}

#[test]
fn every_crash_point_of_a_purge_recovers_the_log() {
    let whole = SimDisk::new();
    let model = run(whole.clone());
    assert!(model.completed, "the run without a crash stopped early");
    assert_eq!(model.first, 40);
    let operations = whole.used();
    let mut failures = Vec::new();
    for budget in 0..=operations {
        let disk = SimDisk::with_budget(budget);
        let model = run(disk.clone());
        if budget < operations {
            assert!(disk.has_crashed(), "budget {budget} did not crash");
        }
        let label = format!("crash at operation {}", budget + 1);
        check_all(&disk, &model, budget, &label, &mut failures);
    }
    assert!(
        failures.is_empty(),
        "{} failures over {} crash points:\n{}",
        failures.len(),
        operations + 1,
        failures.join("\n")
    );
}

#[test]
fn every_failed_flush_recovers_the_log() {
    let mut failures = Vec::new();
    let mut flush = 1;
    loop {
        let disk = SimDisk::new().with_failed_syncs([flush]);
        let model = run(disk.clone());
        if model.completed {
            break;
        }
        let label = format!("flush {flush} failing");
        check_all(&disk, &model, flush, &label, &mut failures);
        flush += 1;
    }
    assert!(flush > 10, "only {flush} flushes");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
