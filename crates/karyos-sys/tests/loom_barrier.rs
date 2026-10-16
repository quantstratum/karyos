// SPDX-License-Identifier: Apache-2.0

//! Loom model of the production loss barrier
//! ([`karyos_sys::freshness`]): the writer order that
//! `tests/loom_freshness.rs` checks as a design model, now over
//! [`BarrierWords`], [`BarrierSnapshot`] and [`TerminalCell`]. The slot is
//! still model-local (its two freshness words are not in the conflation
//! layout yet): a seqlock of `[version, loss_applied, stale_since]`.
//!
//! The writer appends two losses into a ring of two records, with a marker
//! (the owner's gap commitment) after the first. It reconciles the slot
//! after each loss and retires that loss only then. The reader observes the
//! marker, takes a snapshot, copies the slot and classifies: a value inside
//! the first gap is never Fresh once the marker is seen. The terminal cell's
//! body is complete when published.
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test model, as ADR-0007 allows in tests"
)]

use karyos_sys::freshness::{
    BarrierSnapshot, BarrierWords, Freshness, STALE, SlotFreshness, TERMINAL_WORDS, Terminal,
    TerminalCell, barrier_words,
};
use karyos_sys::sync::{AtomicU64, Ordering, fence};
use loom::sync::Arc;
use loom::thread;

const RING: usize = 2;
/// The value's position, inside the first gap.
const POSITION: u64 = 10;

struct Table {
    barrier: Vec<AtomicU64>,
    /// `[version, loss_applied, stale_since]`.
    slot: [AtomicU64; 3],
    marker: AtomicU64,
    terminal: Vec<AtomicU64>,
}

fn reconcile(slot: &[AtomicU64; 3], seq: u64) {
    let version = slot[0].load(Ordering::Relaxed);
    slot[0].store(version + 1, Ordering::Relaxed);
    fence(Ordering::Release);
    slot[1].store(seq | STALE, Ordering::Relaxed);
    slot[2].store(8, Ordering::Relaxed);
    slot[0].store(version + 2, Ordering::Release);
}

fn read_slot(slot: &[AtomicU64; 3]) -> Option<SlotFreshness> {
    let first = slot[0].load(Ordering::Acquire);
    if first % 2 == 1 {
        return None;
    }
    let copy = SlotFreshness {
        loss_applied: slot[1].load(Ordering::Relaxed),
        stale_since: slot[2].load(Ordering::Relaxed),
    };
    fence(Ordering::Acquire);
    (slot[0].load(Ordering::Relaxed) == first).then_some(copy)
}

#[test]
fn a_reader_never_sees_a_lost_value_fresh() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(|| {
        let table = Arc::new(Table {
            barrier: (0..barrier_words(RING).unwrap())
                .map(|_| AtomicU64::new(0))
                .collect(),
            slot: std::array::from_fn(|_| AtomicU64::new(0)),
            marker: AtomicU64::new(0),
            terminal: (0..TERMINAL_WORDS).map(|_| AtomicU64::new(0)).collect(),
        });
        let writer = {
            let table = Arc::clone(&table);
            thread::spawn(move || {
                let barrier = BarrierWords::new(&table.barrier, RING).unwrap();
                assert_eq!(barrier.append_loss(8, 16), Ok(1));
                table.marker.store(1, Ordering::Release);
                reconcile(&table.slot, 1);
                barrier.retire_through(1).unwrap();
                assert_eq!(barrier.append_loss(24, 32), Ok(2));
                reconcile(&table.slot, 2);
                barrier.retire_through(2).unwrap();
                let cell = TerminalCell::new(&table.terminal).unwrap();
                assert!(cell.publish(Terminal {
                    start: 8,
                    end: 16,
                    reason: 1,
                }));
            })
        };
        let reader = {
            let table = Arc::clone(&table);
            thread::spawn(move || {
                let marked = table.marker.load(Ordering::Acquire) == 1;
                let words = table.barrier.as_slice();
                let Some(snapshot) = BarrierSnapshot::take(&words) else {
                    return;
                };
                let Some(slot) = read_slot(&table.slot) else {
                    return;
                };
                let freshness = snapshot.classify(&words, RING, slot, POSITION);
                if marked {
                    assert_ne!(freshness, Freshness::Fresh, "fresh after a committed gap");
                }
                if let Freshness::Stale { since } = freshness {
                    assert_eq!(since, 8, "stale since the first gap");
                }
                if let Some(terminal) = TerminalCell::read(&table.terminal.as_slice()) {
                    assert_eq!(
                        (terminal.start, terminal.end),
                        (8, 16),
                        "incomplete terminal"
                    );
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();
    });
}
