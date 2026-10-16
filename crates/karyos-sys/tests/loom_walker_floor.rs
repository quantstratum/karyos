// SPDX-License-Identifier: Apache-2.0

//! Loom model of the walker's hold on the retention floor
//! (`quantstratum-docs: karyos/design/guards-and-abort.md`, "Local
//! streams"; coordinator, ACS 15161), over the production
//! `participant::reader_minima`.
//!
//! A fast required reader advances its position twice while the driver's
//! walker reads from position 0 and advances once, and the conductor
//! computes and publishes the floor twice as `publish_floor_and_limit`
//! does: the bounding minimum, lowered to the walker's position, never
//! decreasing. The walker checks, after each step, that its position is
//! not below the published floor: it is never lapped. The limit's bound
//! must stay the required reader's, never the walker's.
//!
//! Negative control, which must fail: the walker's cell counted as an
//! observer (the floor ignores it), so the floor follows the required
//! reader past the walker.
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a test model, as ADR-0007 allows in tests"
)]

use karyos_sys::participant::{CELL_OBSERVER, CELL_REQUIRED, CELL_WALKER, reader_minima};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

struct Cells {
    required: (AtomicU64, AtomicU64),
    walker: (AtomicU64, AtomicU64),
    floor: AtomicU64,
}

/// One conductor step: the floor from the readers, published with Release.
fn publish_floor(cells: &Cells) {
    let pairs = [
        (&cells.required.0, &cells.required.1),
        (&cells.walker.0, &cells.walker.1),
    ];
    let (bound, held) = reader_minima(pairs);
    let bound = bound.unwrap();
    // The limit's bound is a position of the required reader (0, 100 or
    // 200), never the walker's (50 or 80).
    assert_eq!(bound % 100, 0, "the walker bounded the limit");
    let floor = held.map_or(bound, |held| bound.min(held));
    let floor = floor.max(cells.floor.load(Ordering::Relaxed));
    cells.floor.store(floor, Ordering::Release);
}

fn model(walker_state: u64) {
    loom::model(move || {
        let cells = Arc::new(Cells {
            required: (AtomicU64::new(CELL_REQUIRED), AtomicU64::new(0)),
            walker: (AtomicU64::new(walker_state), AtomicU64::new(0)),
            floor: AtomicU64::new(0),
        });
        let reader = {
            let cells = Arc::clone(&cells);
            thread::spawn(move || {
                cells.required.1.store(100, Ordering::Release);
                cells.required.1.store(200, Ordering::Release);
            })
        };
        let walker = {
            let cells = Arc::clone(&cells);
            thread::spawn(move || {
                for next in [50, 80] {
                    let position = cells.walker.1.load(Ordering::Relaxed);
                    assert!(
                        position >= cells.floor.load(Ordering::Acquire),
                        "the walker was lapped"
                    );
                    cells.walker.1.store(next, Ordering::Release);
                }
                let position = cells.walker.1.load(Ordering::Relaxed);
                assert!(
                    position >= cells.floor.load(Ordering::Acquire),
                    "the walker was lapped"
                );
            })
        };
        publish_floor(&cells);
        publish_floor(&cells);
        reader.join().unwrap();
        walker.join().unwrap();
    });
}

#[test]
fn the_walker_holds_the_floor() {
    model(CELL_WALKER);
}

#[test]
#[should_panic(expected = "the walker was lapped")]
fn control_a_walker_counted_as_an_observer_is_lapped() {
    model(CELL_OBSERVER);
}
