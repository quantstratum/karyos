// SPDX-License-Identifier: Apache-2.0

//! Loom models of the counter seqlock of `karyos_sys::counters`, over the
//! production `CellWords`. A concurrent reader must never pair one
//! allocation's metadata with a value written for another allocation.
//!
//! Two focused models, explored with one preemption (see `builder`): one
//! where the allocator's own thread increments A and then reallocates the
//! cell as B, and one where B's capability is handed to a separate updater
//! thread that sets a gauge.
//! In both, the reader asserts before any join, and a quiescent read after
//! the joins must succeed.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::counters::{CellRead, CellWords, CounterMetadata, META_WORDS};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

struct Cell {
    meta: Vec<AtomicU64>,
    value: AtomicU64,
    /// Hands B's capability to the updater thread.
    handed_off: AtomicU64,
}

impl Cell {
    /// A cell holding allocation A with the sentinel value 10.
    fn with_a() -> Arc<Self> {
        let cell = Arc::new(Self {
            meta: (0..META_WORDS).map(|_| AtomicU64::new(0)).collect(),
            value: AtomicU64::new(0),
            handed_off: AtomicU64::new(0),
        });
        cell.words().allocate(&metadata_a()).unwrap();
        cell.words().set(10);
        cell
    }

    fn words(&self) -> CellWords<'_> {
        CellWords::new(&self.meta, &self.value).unwrap()
    }
}

fn metadata_a() -> CounterMetadata {
    CounterMetadata::new(1, 10, &"a".repeat(64)).unwrap()
}

fn metadata_b() -> CounterMetadata {
    CounterMetadata::new(2, 20, &"b".repeat(64)).unwrap()
}

/// Checks a concurrent read: A's metadata only with A's values, B's only
/// with B's.
fn check(read: CellRead, a_values: &[u64], b_values: &[u64]) {
    match read {
        CellRead::Allocated {
            metadata, value, ..
        } => match metadata.registration_id {
            1 => {
                assert_eq!(metadata, metadata_a());
                assert!(a_values.contains(&value), "A read value {value}");
            }
            2 => {
                assert_eq!(metadata, metadata_b());
                assert!(b_values.contains(&value), "B read value {value}");
            }
            other => panic!("unknown registration {other}"),
        },
        CellRead::Changing => {}
        CellRead::Free => panic!("the cell is never free"),
    }
}

fn quiescent_b(cell: &Cell, value: u64) {
    assert_eq!(
        cell.words().read(),
        CellRead::Allocated {
            metadata: metadata_b(),
            value,
            release_pending: false,
        }
    );
}

/// Scope: one preemption. With the production reader (four seqlock
/// attempts over 64-byte metadata) bounds 2 and 3 did not finish in review
/// runs of 90 s to over 20 minutes, which are not counted as passes. Bound 1
/// finishes and still fails for each known defect (gauge `set` as a plain
/// store, either seqlock fence removed); bound 0 misses the gauge defect.
fn builder() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(1);
    builder
}

/// The allocator's thread increments A (checked CAS), then reallocates the
/// cell as B and increments B.
#[test]
fn increments_and_reallocation_are_never_mixed() {
    builder().check(|| {
        let cell = Cell::with_a();
        let reader_cell = Arc::clone(&cell);
        let reader = thread::spawn(move || check(reader_cell.words().read(), &[10, 11], &[0, 100]));

        let words = cell.words();
        words.increment(1).unwrap();
        words.allocate(&metadata_b()).unwrap();
        words.increment(100).unwrap();
        reader.join().unwrap();
        quiescent_b(&cell, 100);
    });
}

/// The allocator reallocates A as B and hands B's capability to a separate
/// updater thread, which sets a gauge value.
#[test]
fn a_transferred_gauge_is_never_mixed() {
    builder().check(|| {
        let cell = Cell::with_a();
        let reader_cell = Arc::clone(&cell);
        let reader = thread::spawn(move || check(reader_cell.words().read(), &[10], &[0, 77]));
        let updater_cell = Arc::clone(&cell);
        let updater = thread::spawn(move || {
            let received = updater_cell.handed_off.load(Ordering::Acquire) == 1;
            if received {
                updater_cell.words().set(77);
            }
            received
        });

        cell.words().allocate(&metadata_b()).unwrap();
        cell.handed_off.store(1, Ordering::Release);
        reader.join().unwrap();
        let set = updater.join().unwrap();
        quiescent_b(&cell, if set { 77 } else { 0 });
    });
}
