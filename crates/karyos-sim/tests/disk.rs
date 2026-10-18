// SPDX-License-Identifier: Apache-2.0

//! The segment store over the simulator's disk (cluster-gap-analysis.md
//! C2): `SegmentStore::recover` and `truncate` under every crash point and
//! every survival mode, failed flushes, and one seed giving one trace.
//! Recovery keeps a prefix of what was appended, at least up to what the
//! store reported durable, and the store continues after it.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_archive::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};
use karyos_sim::disk::{SimDisk, Survives};

const DIR: &str = "/archive";
const RECORDING: u64 = 7;

fn geometry() -> Geometry {
    Geometry::new(1024, 2048).unwrap()
}

/// The stream every workload appends, a byte pattern.
fn stream(length: usize) -> Vec<u8> {
    (0..length)
        .map(|at| u8::try_from((at * 7 + 3) % 251).unwrap())
        .collect()
}

#[derive(Debug, Clone, Copy)]
enum Step {
    Append(usize),
    Sync,
    /// Back to this offset of the stream; later appends write the same
    /// stream from there.
    Truncate(u64),
}

/// The workload's total stream length.
fn total(steps: &[Step]) -> usize {
    let mut end = 0usize;
    let mut longest = 0usize;
    for step in steps {
        match *step {
            Step::Append(length) => {
                end += length;
                longest = longest.max(end);
            }
            Step::Truncate(offset) => end = usize::try_from(offset).unwrap(),
            Step::Sync => {}
        }
    }
    longest
}

/// What the store reported before it failed or closed.
#[derive(Debug, Clone, Copy)]
struct Reported {
    created: bool,
    durable: u64,
}

fn run(disk: SimDisk, steps: &[Step]) -> Reported {
    let Ok(mut store) = SegmentStore::create(
        disk,
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    ) else {
        return Reported {
            created: false,
            durable: 0,
        };
    };
    let bytes = stream(total(steps));
    let mut reported = Reported {
        created: true,
        durable: store.durable(),
    };
    let mut position = 0u64;
    for step in steps {
        let result = match *step {
            Step::Append(length) => {
                let from = usize::try_from(position).unwrap();
                store
                    .append(position, &bytes[from..from + length])
                    .map(|written| position = written)
            }
            Step::Sync => store.sync().map(drop),
            Step::Truncate(offset) => store.truncate(offset).map(|_| position = offset),
        };
        // A claim made before a failure must hold too.
        reported.durable = store.durable();
        if result.is_err() {
            return reported;
        }
    }
    let durable = store.durable();
    reported.durable = store.close().unwrap_or(durable);
    reported
}

/// Recovers `crashed` under `survives`; `Err` names the first property
/// that fails.
fn check(
    crashed: &SimDisk,
    survives: Survives,
    reported: Reported,
    total: usize,
) -> Result<(), String> {
    let disk = crashed
        .after_crash(survives)
        .map_err(|error| error.to_string())?;
    let recovered = match SegmentStore::recover(
        disk,
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
    ) {
        Ok(recovered) => recovered,
        Err(SegmentError::NotFound { .. }) if !reported.created || reported.durable == 0 => {
            return Ok(());
        }
        Err(error) => return Err(format!("recovery failed: {error}")),
    };
    let mut store = recovered.store;
    let written = store.written();
    if written < reported.durable {
        return Err(format!(
            "written {written} below the reported durable {}",
            reported.durable
        ));
    }
    let bytes = stream(total);
    let kept = usize::try_from(written).unwrap();
    if kept > total {
        return Err(format!("written {written} past the stream"));
    }
    let mut read = vec![0u8; kept];
    store
        .read(0, &mut read)
        .map_err(|error| error.to_string())?;
    if read != bytes[..kept] {
        return Err("the kept bytes differ from the stream".to_owned());
    }
    // The store continues: the rest of the stream, then all of it back.
    store
        .append(written, &bytes[kept..])
        .map_err(|error| error.to_string())?;
    let mut all = vec![0u8; total];
    store.read(0, &mut all).map_err(|error| error.to_string())?;
    if all != bytes {
        return Err("the continued stream differs".to_owned());
    }
    Ok(())
}

/// Every survival mode a crash is checked under.
fn modes() -> Vec<Survives> {
    let mut modes = vec![Survives::Synced, Survives::Everything];
    modes.extend((1..=4).map(|seed| Survives::Subset { seed }));
    modes.extend((1..=2).map(|seed| Survives::Torn { seed }));
    modes
}

/// Crashes `steps` after every operation, from none to all of them,
/// under every mode; returns the failures.
fn crash_everywhere(steps: &[Step]) -> Vec<String> {
    let free = SimDisk::new();
    let _ = run(free.clone(), steps);
    // Every crash point is a real one: the workload makes dozens of disk
    // operations (each workload here makes more than 20).
    assert!(free.used() > 20, "only {} operations", free.used());
    let total = total(steps);
    let mut failures = Vec::new();
    for budget in 0..=free.used() {
        let disk = SimDisk::with_budget(budget);
        let reported = run(disk.clone(), steps);
        for survives in modes() {
            if let Err(failure) = check(&disk, survives, reported, total) {
                failures.push(format!("budget {budget}, {survives:?}: {failure}"));
            }
        }
    }
    failures
}

#[test]
fn recovery_keeps_the_durable_prefix_at_every_crash_point() {
    // Three segments, an append across a roll, explicit syncs.
    let steps = [
        Step::Append(600),
        Step::Sync,
        Step::Append(900),
        Step::Append(1200),
        Step::Sync,
        Step::Append(300),
    ];
    let failures = crash_everywhere(&steps);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A truncation crashed anywhere, its `set_len` before its sync
/// included: recovery finds the old end or the new one, never a torn
/// one, and the store continues.
#[test]
fn a_truncate_is_whole_at_every_crash_point() {
    let steps = [
        Step::Append(1500),
        Step::Sync,
        Step::Append(1500),
        Step::Sync,
        Step::Truncate(1200),
        Step::Append(400),
        Step::Sync,
    ];
    let failures = crash_everywhere(&steps);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Each flush failing in turn: the store reports the failure, its
/// durable position does not pass what a flush made durable, and
/// recovery after a crash holds.
#[test]
fn a_failed_flush_is_reported_and_recovers() {
    let steps = [
        Step::Append(600),
        Step::Sync,
        Step::Append(900),
        Step::Sync,
        Step::Append(300),
        Step::Sync,
    ];
    let total = total(&steps);
    // Count the flushes of a clean run: one per sync and directory sync.
    let mut failures = Vec::new();
    for failing in 1..=12u64 {
        let disk = SimDisk::new().with_failed_syncs([failing]);
        let reported = run(disk.clone(), &steps);
        for survives in modes() {
            if let Err(failure) = check(&disk, survives, reported, total) {
                failures.push(format!("flush {failing}, {survives:?}: {failure}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// One seed gives one trace, crash and restart included.
#[test]
fn one_seed_gives_one_trace() {
    let steps = [Step::Append(1500), Step::Sync, Step::Append(900)];
    let trace = || {
        let disk = SimDisk::with_budget(20);
        let _ = run(disk.clone(), &steps);
        disk.after_crash(Survives::Subset { seed: 9 })
            .unwrap()
            .trace()
    };
    let first = trace();
    assert!(!first.is_empty());
    assert_eq!(first, trace());
}
