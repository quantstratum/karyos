// SPDX-License-Identifier: Apache-2.0

//! The log's hot path allocates nothing per entry (karyos#691, a finding
//! of the C5 v3 evaluation: 2.76 allocations and 2.00 frees per entry on
//! `StdDisk` before): once warm, an append, a sync and a hard state save
//! make no allocation, reallocation or free on `StdDisk`. Each entry is
//! framed into a buffer the log keeps, and the hard state is replaced
//! through paths built once, its crash-safe steps unchanged (written to a
//! temporary file, synced, renamed over the record, the directory synced).

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use karyos_archive::disk::StdDisk;
use karyos_archive::segment::Geometry;
use karyos_cluster::{Entry, HardState, LogError, RaftLog};
use karyos_sys::alloc_count::{CountingAllocator, count};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("karyos-log-alloc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Entries of the same payload size, one per call, as a leader appends.
fn entry(index: u64, payload: &[u8]) -> Entry {
    Entry {
        index,
        term: 1,
        event_time: index,
        payload: payload.to_vec(),
    }
}

#[test]
fn append_sync_and_hard_state_save_allocate_nothing_once_warm() {
    const WARM: u64 = 64;
    const MEASURED: u64 = 256;
    let dir = TempDir::new("hot");
    // Segments far longer than the run: no roll inside the window.
    let geometry = Geometry::with_default_length(1 << 24).unwrap();
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry, 1).unwrap();
    let payload = [0x5a_u8; 128];
    // The entries are built before the window: the caller's own.
    let all: Vec<[Entry; 1]> = (1..=WARM + MEASURED)
        .map(|index| [entry(index, &payload)])
        .collect();
    log.reserve(usize::try_from(WARM + MEASURED).unwrap())
        .unwrap();
    let step = |log: &mut RaftLog<StdDisk>, batch: &[Entry; 1]| {
        let index = batch[0].index;
        log.append(batch).unwrap();
        log.sync().unwrap();
        log.save_hard_state(HardState {
            current_term: 1,
            voted_for: Some(1),
            commit: Some(index),
        })
        .unwrap();
    };
    let (warm, measured) = all.split_at(usize::try_from(WARM).unwrap());
    for batch in warm {
        step(&mut log, batch);
    }
    let ((), seen) = count(|| {
        for batch in measured {
            step(&mut log, batch);
        }
    });
    assert_eq!(
        seen, 0,
        "{seen} allocations, reallocations and frees over {MEASURED} entries"
    );
    assert_eq!(log.durable_index(), Some(WARM + MEASURED));
    drop(log);
    // The saves left a whole record that a reopen reads back.
    let reopened = RaftLog::open(StdDisk, &dir.0, geometry).unwrap().log;
    assert_eq!(
        reopened.hard_state().and_then(|state| state.commit),
        Some(WARM + MEASURED)
    );
}

/// impl-c2's measurement of karyos#691, exactly: batches of four 64-byte
/// entries, each batch appended, synced and its first index saved as the
/// commit; 25 batches warm, 50 measured, on `StdDisk` with the harness's
/// geometry. Before this change: 2.76 allocations and 2.00 frees per entry.
#[test]
fn the_c5_measurement_workload_allocates_nothing_once_warm() {
    const WARM: u64 = 25;
    const MEASURED: u64 = 50;
    let dir = TempDir::new("c5");
    // `karyos_sim::harness::workloads::geometry()`.
    let geometry = Geometry::new(64 * 1024, 1024 * 1024).unwrap();
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry, 1).unwrap();
    let batch = |from: u64| -> Vec<Entry> {
        (from..from + 4)
            .map(|index| Entry {
                index,
                term: 1,
                event_time: index,
                payload: vec![7; 64],
            })
            .collect()
    };
    let batches: Vec<Vec<Entry>> = (0..WARM + MEASURED).map(|at| batch(1 + 4 * at)).collect();
    log.reserve(usize::try_from(4 * (WARM + MEASURED)).unwrap())
        .unwrap();
    let step = |log: &mut RaftLog<StdDisk>, batch: &[Entry]| {
        log.append(batch).unwrap();
        log.sync().unwrap();
        log.save_hard_state(HardState {
            current_term: 1,
            voted_for: None,
            commit: Some(batch[0].index),
        })
        .unwrap();
    };
    let (warm, measured) = batches.split_at(usize::try_from(WARM).unwrap());
    for batch in warm {
        step(&mut log, batch);
    }
    let ((), seen) = count(|| {
        for batch in measured {
            step(&mut log, batch);
        }
    });
    assert_eq!(seen, 0, "{seen} allocations, reallocations and frees");
    assert_eq!(log.durable_index(), Some(4 * (WARM + MEASURED)));
}

/// karyos#1285 review: a reservation the index cannot hold is a typed
/// refusal, not a panic, and the log appends on after it.
#[test]
fn an_impossible_reservation_is_refused() {
    let dir = TempDir::new("reserve");
    let mut log = RaftLog::create(
        StdDisk,
        &dir.0,
        Geometry::with_default_length(65_536).unwrap(),
        1,
    )
    .unwrap();
    assert!(matches!(
        log.reserve(usize::MAX),
        Err(LogError::IndexFull {
            additional: usize::MAX
        })
    ));
    assert_eq!(log.append(&[entry(1, b"after")]).unwrap(), Some(1));
}
