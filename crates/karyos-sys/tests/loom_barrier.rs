// SPDX-License-Identifier: Apache-2.0

//! Loom model of the production loss barrier
//! ([`karyos_sys::freshness`]): the writer order that
//! `tests/loom_freshness.rs` checks as a design model, now over
//! [`BarrierWords`], [`BarrierSnapshot`] and [`TerminalCell`]. The slot is
//! still model-local (a seqlock of `[version, loss_applied, stale_since]`).
//!
//! The writer appends two losses into a ring of two records, with a marker
//! (the owner's gap commitment) after the first, reconciles the slot
//! through both and retires them; then a third loss reuses the first one's
//! record, and is reconciled and retired. The writer is this compact so
//! that Loom's bounded store history still holds the first version when the
//! record is reused. The value lies before every gap, so each gap makes it
//! stale since the first gap's start.
//!
//! - With the marker, a reader never classifies the value Fresh.
//! - Without it, an accepted classification comes from a coherent snapshot:
//!   the loss and retired sequences match the version, and the value is
//!   stale since the first gap's start, never since a reused record's.
//!
//! The controls run a model-local reader that removes one ordering: the
//! snapshot's Acquire, or the Acquire fence before the revalidation. Each
//! must fail.
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
/// The gaps, in commit order; the third reuses the first one's record.
const GAPS: [(u64, u64); 3] = [(8, 16), (24, 32), (40, 48)];
/// The value's position: before every gap.
const POSITION: u64 = 2;

/// Which reader runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reader {
    /// The production reader, after the marker.
    Marked,
    /// The production reader, without the marker.
    Unmarked,
    /// Control: the snapshot's version load is Relaxed.
    RelaxedTake,
    /// Control: no Acquire fence before the revalidation.
    NoRevalidationFence,
}

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
    slot[2].store(GAPS[0].0, Ordering::Relaxed);
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

/// The loss and retired sequences at each even barrier version, in the
/// writer's order: append 1, append 2, retire 2, append 3, retire 3.
const EXPECTED: [(u64, u64); 6] = [(0, 0), (1, 0), (2, 0), (2, 2), (3, 2), (3, 3)];

fn expected(version: u64) -> (u64, u64) {
    EXPECTED[usize::try_from(version / 2).unwrap()]
}

/// The production reader's classification, with its snapshot's sequences.
fn production(table: &Table) -> Option<(Freshness, u64, u64, u64)> {
    let words = table.barrier.as_slice();
    let snapshot = BarrierSnapshot::take(&words, RING).ok()?;
    let slot = read_slot(&table.slot)?;
    let freshness = snapshot.classify(&words, slot, POSITION);
    Some((
        freshness,
        snapshot.version(),
        snapshot.loss_seq(),
        snapshot.retired_through(),
    ))
}

/// A model-local reader removing one ordering: the same steps as the
/// production one over the raw words.
fn faulty(
    table: &Table,
    relaxed_take: bool,
    revalidation_fence: bool,
) -> Option<(Freshness, u64, u64, u64)> {
    let w = &table.barrier;
    let order = if relaxed_take {
        Ordering::Relaxed
    } else {
        Ordering::Acquire
    };
    let version = w[0].load(order);
    if version % 2 == 1 {
        return None;
    }
    let (loss_seq, retired) = (w[1].load(Ordering::Relaxed), w[2].load(Ordering::Relaxed));
    let slot = read_slot(&table.slot)?;
    let applied = slot.loss_applied & !STALE;
    let mut freshness = if applied > loss_seq || applied < retired {
        Freshness::Retry
    } else {
        let mut since = (slot.loss_applied & STALE != 0).then_some(slot.stale_since);
        let mut gone = false;
        for seq in applied + 1..=loss_seq {
            let record = 3 + 3 * (seq as usize % RING);
            let (found, start, end) = (
                w[record].load(Ordering::Relaxed),
                w[record + 1].load(Ordering::Relaxed),
                w[record + 2].load(Ordering::Relaxed),
            );
            if found != seq {
                gone = true;
            } else if POSITION < end {
                since = Some(since.map_or(start, |since| since.min(start)));
            }
        }
        match (gone, since) {
            (true, _) => Freshness::Retry,
            (false, Some(since)) => Freshness::Stale { since },
            (false, None) => Freshness::Fresh,
        }
    };
    if revalidation_fence {
        fence(Ordering::Acquire);
    }
    if w[0].load(Ordering::Relaxed) != version {
        freshness = Freshness::Retry;
    }
    Some((freshness, version, loss_seq, retired))
}

fn model(reader: Reader) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
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
                assert_eq!(barrier.append_loss(GAPS[0].0, GAPS[0].1), Ok(1));
                table.marker.store(1, Ordering::Release);
                assert_eq!(barrier.append_loss(GAPS[1].0, GAPS[1].1), Ok(2));
                reconcile(&table.slot, 2);
                barrier.retire_through(2).unwrap();
                // Reuses the record of loss 1.
                assert_eq!(barrier.append_loss(GAPS[2].0, GAPS[2].1), Ok(3));
                reconcile(&table.slot, 3);
                barrier.retire_through(3).unwrap();
                let cell = TerminalCell::new(&table.terminal).unwrap();
                assert!(cell.publish(Terminal {
                    start: GAPS[0].0,
                    end: GAPS[0].1,
                    reason: 1,
                }));
            })
        };
        let reading = {
            let table = Arc::clone(&table);
            thread::spawn(move || {
                let marked = table.marker.load(Ordering::Acquire) == 1;
                let read = match reader {
                    Reader::Marked | Reader::Unmarked => production(&table),
                    Reader::RelaxedTake => faulty(&table, true, true),
                    Reader::NoRevalidationFence => faulty(&table, false, false),
                };
                let Some((freshness, version, loss_seq, retired)) = read else {
                    return;
                };
                if reader == Reader::Marked && marked {
                    assert_ne!(freshness, Freshness::Fresh, "fresh after a committed gap");
                }
                if freshness != Freshness::Retry {
                    assert_eq!(
                        (loss_seq, retired),
                        expected(version),
                        "incoherent snapshot"
                    );
                }
                if let Freshness::Stale { since } = freshness {
                    assert_eq!(since, GAPS[0].0, "stale since a reused record");
                }
                if let Some(terminal) = TerminalCell::read(&table.terminal.as_slice()) {
                    assert_eq!(
                        (terminal.start, terminal.end),
                        GAPS[0],
                        "incomplete terminal"
                    );
                }
            })
        };
        writer.join().unwrap();
        reading.join().unwrap();
    });
}

#[test]
fn a_marked_reader_never_sees_a_lost_value_fresh() {
    model(Reader::Marked);
}

#[test]
fn an_accepted_classification_comes_from_a_coherent_snapshot() {
    model(Reader::Unmarked);
}

#[test]
#[should_panic(expected = "incoherent snapshot")]
fn control_a_relaxed_snapshot_is_incoherent() {
    model(Reader::RelaxedTake);
}

#[test]
#[should_panic(expected = "stale since a reused record")]
fn control_without_the_revalidation_fence_a_reused_record_is_accepted() {
    model(Reader::NoRevalidationFence);
}
