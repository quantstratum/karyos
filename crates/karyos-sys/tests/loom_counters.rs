// SPDX-License-Identifier: Apache-2.0

//! Loom model of the counter seqlock of `karyos_sys::counters`, over the
//! production `CellWords`: allocation A (value 10, then 11) is replaced by
//! allocation B, whose capability is handed to a separate updater thread
//! that sets a gauge value. A concurrent reader must never pair one
//! allocation's metadata with a value written for the other.
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
    fn words(&self) -> CellWords<'_> {
        CellWords::new(&self.meta, &self.value).unwrap()
    }
}

fn labels() -> (String, String) {
    ("a".repeat(64), "b".repeat(64))
}

fn check(read: CellRead) {
    let (label_a, label_b) = labels();
    match read {
        CellRead::Allocated {
            metadata, value, ..
        } => match metadata.registration_id {
            1 => {
                assert_eq!(metadata.type_id, 10);
                assert_eq!(metadata.label(), label_a.as_bytes());
                assert!(value == 10 || value == 11, "A read value {value}");
            }
            2 => {
                assert_eq!(metadata.type_id, 20);
                assert_eq!(metadata.label(), label_b.as_bytes());
                assert!(value == 0 || value == 77, "B read value {value}");
            }
            other => panic!("unknown registration {other}"),
        },
        CellRead::Changing => {}
        CellRead::Free => panic!("the cell is never free"),
    }
}

#[test]
fn a_reader_never_mixes_two_allocations() {
    // Each side touches about 15 words; an unbounded search does not
    // finish. Three preemptions cover a reader interrupted before, inside
    // and after either write section and the hand-off.
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(|| {
        let (label_a, label_b) = labels();
        let cell = Arc::new(Cell {
            meta: (0..META_WORDS).map(|_| AtomicU64::new(0)).collect(),
            value: AtomicU64::new(0),
            handed_off: AtomicU64::new(0),
        });
        let first = CounterMetadata::new(1, 10, &label_a).unwrap();
        let second = CounterMetadata::new(2, 20, &label_b).unwrap();
        cell.words().allocate(&first).unwrap();
        cell.words().set(10);

        let writer_cell = Arc::clone(&cell);
        let writer = thread::spawn(move || {
            let words = writer_cell.words();
            words.increment(1).unwrap();
            // A's capability is gone; the allocator reuses the cell.
            words.allocate(&second).unwrap();
            writer_cell.handed_off.store(1, Ordering::Release);
        });
        let updater_cell = Arc::clone(&cell);
        let updater = thread::spawn(move || {
            if updater_cell.handed_off.load(Ordering::Acquire) == 1 {
                updater_cell.words().set(77);
            }
        });
        let reader_cell = Arc::clone(&cell);
        let reader = thread::spawn(move || check(reader_cell.words().read()));
        writer.join().unwrap();
        updater.join().unwrap();
        reader.join().unwrap();

        // Quiescent: the read must succeed and see B.
        let CellRead::Allocated { metadata, .. } = cell.words().read() else {
            panic!("a quiescent read must succeed");
        };
        assert_eq!(metadata.registration_id, 2);
    });
}
