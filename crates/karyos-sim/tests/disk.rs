// SPDX-License-Identifier: Apache-2.0

//! The segment store over the simulator's disk (cluster-gap-analysis.md
//! C2): `SegmentStore::recover` and `truncate` under every crash point and
//! every survival mode, failed flushes, and one seed giving one trace.
//! Recovery keeps a prefix of what was appended, at least up to what the
//! store reported durable, and the store continues after it; a truncation
//! leaves the old end or the new one, exactly.

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
/// The seeds every seeded mode is checked under: a fixed corpus.
const SEEDS: std::ops::Range<u64> = 0..64;

fn geometry() -> Geometry {
    Geometry::new(1024, 2048).unwrap()
}

/// A byte pattern, one per `salt`: what is appended after a truncation is
/// another one, so bytes cut and wrongly kept show.
fn stream(length: usize, salt: usize) -> Vec<u8> {
    (0..length)
        .map(|at| u8::try_from((at * 7 + 3 + salt * 101) % 251).unwrap())
        .collect()
}

#[derive(Debug, Clone, Copy)]
enum Step {
    Append(usize),
    Sync,
    /// Back to this position; later appends write another stream.
    Truncate(u64),
}

/// The recording's bytes a workload means: before its truncation (the old
/// content) and at its end (the new one, the same without a truncation).
fn intended(steps: &[Step]) -> (Vec<u8>, Vec<u8>) {
    let mut content = Vec::new();
    let mut before = None;
    let mut salt = 0;
    for step in steps {
        match *step {
            Step::Append(length) => {
                let from = content.len();
                content.extend_from_slice(&stream(from + length, salt)[from..]);
            }
            Step::Truncate(position) => {
                before = Some(content.clone());
                content.truncate(usize::try_from(position).unwrap());
                salt += 1;
            }
            Step::Sync => {}
        }
    }
    (before.unwrap_or_else(|| content.clone()), content)
}

/// What the store reported before it failed or closed.
#[derive(Debug, Clone, Copy, Default)]
struct Reported {
    created: bool,
    durable: u64,
    /// A truncation was called, and whether it returned.
    truncate: Option<(u64, bool)>,
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
        return Reported::default();
    };
    let (before, after) = intended(steps);
    let mut reported = Reported {
        created: true,
        durable: store.durable(),
        truncate: None,
    };
    let mut position = 0u64;
    for step in steps {
        let result = match *step {
            Step::Append(length) => {
                let from = usize::try_from(position).unwrap();
                // Before a truncation the old content, after it the new.
                let source = if reported.truncate.is_some() {
                    &after
                } else {
                    &before
                };
                store
                    .append(position, &source[from..from + length])
                    .map(|written| position = written)
            }
            Step::Sync => store.sync().map(drop),
            Step::Truncate(to) => {
                reported.truncate = Some((to, false));
                store.truncate(to).map(|_| {
                    position = to;
                    reported.truncate = Some((to, true));
                })
            }
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
    steps: &[Step],
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
        Err(SegmentError::NotFound { .. }) if !reported.created => return Ok(()),
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
    let (before, after) = intended(steps);
    let kept = usize::try_from(written).unwrap();
    let mut read = vec![0u8; kept];
    store
        .read(0, &mut read)
        .map_err(|error| error.to_string())?;
    let prefix_of = |content: &[u8]| kept <= content.len() && read == content[..kept];
    let valid = match reported.truncate {
        // No truncation began: a prefix of the old content.
        None => prefix_of(&before),
        // It began and did not return: the old end exactly, or the new
        // content from the new end on.
        Some((to, false)) => {
            (kept == before.len() && read == before) || (written >= to && prefix_of(&after))
        }
        // It returned: the new content.
        Some((_, true)) => prefix_of(&after),
    };
    if !valid {
        return Err(format!(
            "recovered {written} bytes that are neither the old end nor the new content \
             (truncate {:?})",
            reported.truncate
        ));
    }
    // The store continues: one more append, read back.
    let more = stream(64, 9);
    store
        .append(written, &more)
        .map_err(|error| error.to_string())?;
    let mut tail = vec![0u8; more.len()];
    store
        .read(written, &mut tail)
        .map_err(|error| error.to_string())?;
    if tail != more {
        return Err("the continued append differs".to_owned());
    }
    Ok(())
}

/// Every survival mode a crash is checked under.
fn modes() -> Vec<Survives> {
    let mut modes = vec![Survives::Synced, Survives::Everything];
    modes.extend(SEEDS.map(|seed| Survives::Subset { seed }));
    modes.extend(SEEDS.map(|seed| Survives::Torn { seed }));
    modes
}

/// Crashes `steps` after every operation, from none to all of them,
/// under every mode; returns the failures.
fn crash_everywhere(steps: &[Step]) -> Vec<String> {
    let free = SimDisk::new();
    let clean = run(free.clone(), steps);
    // The clean run does what the workload says, its truncation included.
    assert!(
        clean.truncate.is_none_or(|(_, returned)| returned),
        "a clean run's truncation failed: the position is not a write boundary"
    );
    // Every crash point is a real one: each workload makes more than 20
    // disk operations.
    assert!(free.used() > 20, "only {} operations", free.used());
    let mut failures = Vec::new();
    for budget in 0..=free.used() {
        let disk = SimDisk::with_budget(budget);
        let reported = run(disk.clone(), steps);
        for survives in modes() {
            if let Err(failure) = check(&disk, survives, reported, steps) {
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
    assert!(
        failures.is_empty(),
        "{} failures: {failures:#?}",
        failures.len()
    );
}

/// A truncation crashed anywhere, its `set_len` before its sync
/// included: recovery finds the old end or the new one, exactly, and the
/// store continues. The bytes appended after it differ from those cut.
#[test]
fn a_truncate_is_whole_at_every_crash_point() {
    let steps = [
        Step::Append(1500),
        Step::Sync,
        Step::Append(1500),
        Step::Sync,
        Step::Truncate(1500),
        Step::Append(400),
        Step::Sync,
    ];
    let failures = crash_everywhere(&steps);
    assert!(
        failures.is_empty(),
        "{} failures: {failures:#?}",
        failures.len()
    );
}

/// Each flush failing in turn: the store reports the failure, its
/// durable position does not pass what a flush made durable, and
/// recovery after a crash holds, in the default (fsyncgate) model and the
/// optimistic one.
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
    let mut failures = Vec::new();
    for optimistic in [false, true] {
        for failing in 1..=12u64 {
            let disk = SimDisk::new().with_failed_syncs([failing]);
            let disk = if optimistic {
                disk.with_optimistic_flushes()
            } else {
                disk
            };
            let reported = run(disk.clone(), &steps);
            for survives in modes() {
                if let Err(failure) = check(&disk, survives, reported, &steps) {
                    failures.push(format!(
                        "optimistic {optimistic}, flush {failing}, {survives:?}: {failure}"
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures: {failures:#?}",
        failures.len()
    );
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
