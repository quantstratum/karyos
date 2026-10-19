// SPDX-License-Identifier: Apache-2.0

//! C8a's snapshot store (karyos-cluster `snapshot`) over C2's crashing
//! disk (quantstratum-docs: karyos/design/cluster-dedup-and-snapshots.md
//! §3 and §4, W4): a workload writes three snapshots of two segments
//! each, keeping two, so the third write purges. It runs once per disk
//! operation with the disk crashing at that operation (and once after the
//! last), and once per flush with that flush failing; each run is reopened
//! under every survival mode of [`Survives`]: `Synced` and `Everything`
//! once, `Subset` and `Torn` once per seed of [`scenarios::seeds`].
//!
//! The invariant, checked at every crash point:
//!
//! 1. the store opens, and reports nothing damaged;
//! 2. its snapshots are the newest two of those published, the write in
//!    flight counting as published or not: never an unpublished one, never
//!    an older set;
//! 3. each reads back whole, with the sections written for its index;
//! 4. only the kept snapshots' files remain, beside the manifest;
//! 5. the reopened store writes and publishes a further snapshot (under
//!    `Synced` and `Everything`).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_archive::disk::Disk;
use karyos_archive::segment::Geometry;
use karyos_cluster::snapshot::{
    MANIFEST_FILE, Section, SectionKind, SnapshotConfig, SnapshotInfo, SnapshotStore,
};
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::rng::Rng;
use karyos_sim::scenarios;

const DIR: &str = "/snapshots";
const WRITES: u64 = 3;

/// 4 KiB segments: each snapshot spans two.
fn geometry() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

fn config() -> SnapshotConfig {
    SnapshotConfig::default()
}

/// The sections written for snapshot `index`.
fn sections(index: u64) -> Vec<(SectionKind, u64, Vec<u8>)> {
    let fill = |kind: u64, length: u64| {
        (0..length)
            .map(|at| u8::try_from((at * 31 + index * 7 + kind) % 251).unwrap())
            .collect::<Vec<u8>>()
    };
    vec![
        (SectionKind::Consensus, 1, fill(1, 48)),
        (SectionKind::Sessions, 1, fill(2, 1200 + index * 20)),
        (SectionKind::Service, 7, fill(3, 3000)),
    ]
}

/// What the workload knew when it stopped.
#[derive(Debug, Default)]
struct Model {
    /// Indices whose write returned `Ok`, in order.
    published: Vec<u64>,
    /// The index whose write was in flight.
    writing: Option<u64>,
    completed: bool,
}

fn write(store: &mut SnapshotStore<SimDisk>, index: u64) -> bool {
    let held = sections(index);
    let sections: Vec<Section<'_>> = held
        .iter()
        .map(|(kind, version, bytes)| Section::new(*kind, *version, bytes))
        .collect();
    store.write(index, 1, &sections).is_ok()
}

fn run(disk: SimDisk) -> Model {
    let mut model = Model::default();
    let Ok(opened) = SnapshotStore::open(disk, Path::new(DIR), geometry(), config()) else {
        return model;
    };
    let mut store = opened.store;
    for index in (1..=WRITES).map(|n| n * 10) {
        model.writing = Some(index);
        if !write(&mut store, index) {
            return model;
        }
        model.writing = None;
        model.published.push(index);
    }
    model.completed = true;
    model
}

/// The newest `keep` of `published`.
fn newest(published: &[u64]) -> Vec<u64> {
    let keep = usize::try_from(config().keep).unwrap();
    let mut newest: Vec<u64> = published.iter().rev().take(keep).copied().collect();
    newest.reverse();
    newest
}

fn check(disk: &SimDisk, survives: Survives, model: &Model) -> Result<(), String> {
    let restarted = disk
        .after_crash(survives)
        .map_err(|error| error.to_string())?;
    let opened = SnapshotStore::open(restarted.clone(), Path::new(DIR), geometry(), config())
        .map_err(|error| format!("open: {error}"))?;
    if !opened.damaged.is_empty() {
        return Err(format!("damaged: {:?}", opened.damaged));
    }
    let mut store = opened.store;
    let kept: Vec<u64> = store.snapshots().iter().map(|info| info.index).collect();
    let without = newest(&model.published);
    let with = model.writing.map(|index| {
        let mut all = model.published.clone();
        all.push(index);
        newest(&all)
    });
    if kept != without && Some(&kept) != with.as_ref() {
        return Err(format!("kept {kept:?}, expected {without:?} or {with:?}"));
    }
    for info in store.snapshots() {
        let read = store
            .read(info)
            .map_err(|error| format!("read {}: {error}", info.index))?;
        let got: Vec<_> = read
            .iter()
            .map(|section| (section.kind, section.version, section.bytes.clone()))
            .collect();
        if got != sections(info.index) {
            return Err(format!("snapshot {} reads other sections", info.index));
        }
    }
    let ids: Vec<u64> = store
        .snapshots()
        .iter()
        .map(|info: &SnapshotInfo| info.id)
        .collect();
    let mut lister = restarted.clone();
    for name in lister
        .list(Path::new(DIR))
        .map_err(|error| error.to_string())?
    {
        if name == MANIFEST_FILE || name.ends_with(".tmp") {
            continue;
        }
        let id = name
            .split_once('-')
            .and_then(|(id, _)| u64::from_str_radix(id, 16).ok());
        if !id.is_some_and(|id| ids.contains(&id)) {
            return Err(format!("{name} is left"));
        }
    }
    // The further write, under the unseeded modes only: it is the same
    // code path whatever the seed kept.
    if !matches!(survives, Survives::Synced | Survives::Everything) {
        return Ok(());
    }
    if !write(&mut store, 1000) {
        return Err("the reopened store did not write".into());
    }
    let reopened = SnapshotStore::open(restarted, Path::new(DIR), geometry(), config())
        .map_err(|error| format!("second open: {error}"))?;
    if reopened.store.latest().map(|info| info.index) != Some(1000) {
        return Err("the further snapshot was not published".into());
    }
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
fn every_crash_point_recovers_the_published_snapshots() {
    let whole = SimDisk::new();
    let model = run(whole.clone());
    assert!(model.completed, "the run without a crash stopped early");
    assert_eq!(model.published.len(), 3);
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
        "{} of {} crash points failed:\n{}",
        failures.len(),
        operations + 1,
        failures.join("\n")
    );
}

#[test]
fn every_failed_flush_poisons_and_recovers() {
    let mut failures = Vec::new();
    let mut flush = 1;
    loop {
        let disk = SimDisk::new().with_failed_syncs([flush]);
        let model = run(disk.clone());
        if model.completed {
            // No flush of that number: every one was swept.
            break;
        }
        let label = format!("flush {flush} failing");
        check_all(&disk, &model, flush, &label, &mut failures);
        flush += 1;
    }
    assert!(flush > 10, "only {flush} flushes");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A failed flush poisons the store: a later write on the same store is
/// refused, until a reopen (REVIEWER-02's P2 on #463).
#[test]
fn a_failed_write_poisons_the_store_until_reopened() {
    use karyos_cluster::snapshot::SnapshotError;

    let disk = SimDisk::new().with_failed_syncs([1]);
    let mut store = SnapshotStore::open(disk.clone(), Path::new(DIR), geometry(), config())
        .unwrap()
        .store;
    assert!(!write(&mut store, 10));
    let held = sections(20);
    let sections: Vec<Section<'_>> = held
        .iter()
        .map(|(kind, version, bytes)| Section::new(*kind, *version, bytes))
        .collect();
    assert!(matches!(
        store.write(20, 1, &sections),
        Err(SnapshotError::Failed)
    ));
    // A reopen clears it.
    let mut reopened = SnapshotStore::open(disk, Path::new(DIR), geometry(), config())
        .unwrap()
        .store;
    assert!(write(&mut reopened, 20));
}
