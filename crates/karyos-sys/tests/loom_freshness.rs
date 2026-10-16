// SPDX-License-Identifier: Apache-2.0

//! Loom model of the proposed conflation freshness protocol
//! (`quantstratum-docs: karyos/design/gaps-and-unreliable-delivery.md`,
//! "One-lane conflation freshness", GU-8): the design-review step before any
//! production g3e code. The layout does not exist yet, so the model defines
//! the proposed words itself, with Loom atomics, and checks the protocol the
//! design states:
//!
//! - **Barrier header**: a seqlock (odd version while written, Release
//!   fence, Relaxed words, even version with Release) holding the loss
//!   sequence, the retired-through sequence and a one-record loss ring
//!   (`G = 1`: sequence, `[s, e)`).
//! - **Slots**: two, in the existing slot seqlock shape, each holding the
//!   value version, the value's position, the loss sequence the slot is
//!   reconciled through (bit 63 set while stale) and the stale start.
//! - **Marker**: the receive owner's gap commitment, published only after
//!   the barrier (the mailbox acknowledgement is folded into the writer's
//!   program order).
//! - **Terminal cell**: a one-shot publication word over an immutable body.
//!
//! The feeder, the single writer, handles two losses. For each it publishes
//! the barrier, lets the marker be committed (the first loss), reconciles
//! the first slot, then the second, and retires the record; the second loss
//! is published only after the first record retired (the ring-full rule:
//! a record is never overwritten before it retires). It then publishes the
//! terminal cell. A reader observes the marker, takes a validated barrier
//! snapshot, copies the second slot, revalidates the barrier and classifies
//! the value. Properties:
//!
//! - after observing a committed gap, the affected old value is never
//!   Fresh: a gap makes every value below its end stale (GU-9), so the
//!   value read lies before the first gap;
//! - a value stale through a record is stale since the first gap's start,
//!   never a later gap's;
//! - a reader that sees a record retired sees the slot metadata that
//!   replaced it, in every slot;
//! - an accepted combination never pairs a slot with a barrier older than
//!   the one the slot was reconciled through;
//! - a stale slot names the start of the gap that made it stale;
//! - a published terminal cell's body is complete.
//!
//! Negative controls, each removing one rule, must fail: the marker
//! committed before the barrier, the record retired before the slots were
//! reconciled, the record retired after the first slot only, the second
//! loss overwriting the unretired first record (the reader then dates the
//! loss from the later gap), the final barrier
//! validation skipped, and the terminal cell published before its body.
//!
//! The retirement needs no ordering of its own here: with one writer, the
//! slot seqlock's Release fence precedes the retirement, so a reader that
//! sees the retirement sees at least the slot's odd version and retries. A
//! control that only weakened the retirement's Release cannot fail; what
//! the property needs is the order of the steps.
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test model, as ADR-0007 allows in tests"
)]

use karyos_sys::sync::{AtomicU64, Ordering, fence};
use loom::sync::Arc;
use loom::thread;

/// Bit 63 of the reconciled sequence: the slot is stale.
const STALE: u64 = 1 << 63;
/// The first gap `[GAP_START, GAP_END)`: both values lie below its end.
const GAP_START: u64 = 8;
const GAP_END: u64 = 16;
/// The second gap, above both values.
const SECOND_START: u64 = 24;
const SECOND_END: u64 = 32;
/// The values' stream positions, one per slot: the first inside the first
/// gap, the second (the one read) before it.
const POSITIONS: [u64; 2] = [10, 2];

/// Which rule a control removes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    MarkerBeforeBarrier,
    RetireBeforeReconcile,
    RetireAfterFirstSlot,
    OverwriteUnretired,
    NoFinalValidation,
    TerminalBeforeBody,
}

/// The barrier header: `[version, loss_seq, retired_through, rec_seq,
/// rec_start, rec_end]`.
struct Header([AtomicU64; 6]);

/// A slot: `[version, position, reconciled, stale_since]`.
struct Slot([AtomicU64; 4]);

struct Table {
    header: Header,
    slots: [Slot; 2],
    marker: AtomicU64,
    terminal: AtomicU64,
    terminal_body: [AtomicU64; 2],
}

/// A seqlock write of `words[1..]` (`values`), as keyed-conflation.md's
/// writer does.
fn seqlock_write(words: &[AtomicU64], values: &[(usize, u64)]) {
    let version = words[0].load(Ordering::Relaxed);
    words[0].store(version + 1, Ordering::Relaxed);
    fence(Ordering::Release);
    for &(index, value) in values {
        words[index].store(value, Ordering::Relaxed);
    }
    words[0].store(version + 2, Ordering::Release);
}

/// A seqlock read: `None` while written or torn.
fn seqlock_read<const N: usize>(words: &[AtomicU64; N]) -> Option<(u64, [u64; N])> {
    let first = words[0].load(Ordering::Acquire);
    if first % 2 == 1 {
        return None;
    }
    let mut copy = [0u64; N];
    for (out, word) in copy.iter_mut().zip(words.iter()).skip(1) {
        *out = word.load(Ordering::Relaxed);
    }
    fence(Ordering::Acquire);
    let second = words[0].load(Ordering::Relaxed);
    (first == second).then_some((first, copy))
}

#[derive(Debug, PartialEq, Eq)]
enum Freshness {
    Fresh,
    Stale,
    /// Required history is gone or the combination changed: bounded retry.
    Retry,
}

/// Publishes loss `seq` with its one ring record `[start, end)`.
fn barrier(table: &Table, seq: u64, start: u64, end: u64) {
    seqlock_write(&table.header.0, &[(1, seq), (3, seq), (4, start), (5, end)]);
}

/// Reconciles slot `index` through loss `seq`: both values lie in the
/// first gap, so the slot is stale from its start on.
fn reconcile(table: &Table, index: usize, seq: u64) {
    seqlock_write(&table.slots[index].0, &[(2, seq | STALE), (3, GAP_START)]);
}

/// Retires the record of loss `seq`: every slot incorporated it.
fn retire(table: &Table, seq: u64) {
    seqlock_write(&table.header.0, &[(2, seq)]);
}

fn writer(table: &Table, fault: Fault) {
    if fault == Fault::MarkerBeforeBarrier {
        table.marker.store(1, Ordering::Release);
        barrier(table, 1, GAP_START, GAP_END);
    } else {
        // The barrier, then the owner's commitment of the gap.
        barrier(table, 1, GAP_START, GAP_END);
        table.marker.store(1, Ordering::Release);
    }
    if fault == Fault::OverwriteUnretired {
        // The second loss overwrites the ring before the first retired.
        barrier(table, 2, SECOND_START, SECOND_END);
    }
    // The bounded reconciliation of every slot, then the retirement.
    match fault {
        Fault::RetireBeforeReconcile => {
            retire(table, 1);
            reconcile(table, 0, 1);
            reconcile(table, 1, 1);
        }
        Fault::RetireAfterFirstSlot => {
            reconcile(table, 0, 1);
            retire(table, 1);
            reconcile(table, 1, 1);
        }
        _ => {
            reconcile(table, 0, 1);
            reconcile(table, 1, 1);
            retire(table, 1);
        }
    }
    // The second loss only once the first record retired.
    if fault != Fault::OverwriteUnretired {
        barrier(table, 2, SECOND_START, SECOND_END);
    }
    reconcile(table, 0, 2);
    reconcile(table, 1, 2);
    retire(table, 2);
    // The one-shot terminal cell.
    if fault == Fault::TerminalBeforeBody {
        table.terminal.store(1, Ordering::Release);
    }
    table.terminal_body[0].store(GAP_START, Ordering::Relaxed);
    table.terminal_body[1].store(GAP_END, Ordering::Relaxed);
    if fault != Fault::TerminalBeforeBody {
        table.terminal.store(1, Ordering::Release);
    }
}

fn reader(table: &Table, fault: Fault) {
    let marked = table.marker.load(Ordering::Acquire) == 1;
    let Some((version, header)) = seqlock_read(&table.header.0) else {
        return;
    };
    // The second slot: reconciled last.
    let Some((_, slot)) = seqlock_read(&table.slots[1].0) else {
        return;
    };
    if fault != Fault::NoFinalValidation && table.header.0[0].load(Ordering::Acquire) != version {
        // The barrier changed: retry.
        return;
    }
    let [_, loss_seq, retired_through, rec_seq, rec_start, rec_end] = header;
    let [_, position, reconciled, stale_since] = slot;
    let applied = reconciled & !STALE;
    // An accepted combination never pairs a slot with an older barrier
    // than the one it was reconciled through.
    assert!(applied <= loss_seq, "slot newer than its barrier");
    // A reader that sees a record retired sees the slot metadata that
    // replaced it.
    assert!(
        applied >= retired_through,
        "retired history without its slot"
    );
    let freshness = if reconciled & STALE != 0 {
        assert_eq!(stale_since, GAP_START, "stale slot without its gap start");
        Freshness::Stale
    } else if loss_seq > applied {
        if retired_through >= loss_seq || rec_seq != loss_seq {
            Freshness::Retry
        } else if position < rec_end {
            // Stale since the record's start: the earliest gap only if the
            // records the slot needs were all retained.
            assert_eq!(rec_start, GAP_START, "stale since a later gap");
            Freshness::Stale
        } else {
            Freshness::Fresh
        }
    } else {
        Freshness::Fresh
    };
    if marked {
        assert_ne!(freshness, Freshness::Fresh, "fresh after a committed gap");
    }
    // The terminal cell: its body is read only after the publication's
    // Acquire, and it is complete.
    if table.terminal.load(Ordering::Acquire) == 1 {
        let body = [
            table.terminal_body[0].load(Ordering::Relaxed),
            table.terminal_body[1].load(Ordering::Relaxed),
        ];
        assert_eq!(body, [GAP_START, GAP_END], "incomplete terminal cell");
    }
}

fn model(fault: Fault) {
    // Two preemptions cover the interleavings each rule guards (one
    // reader pause between two writer steps); unbounded, the model does
    // not finish in 25 minutes.
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let slot = |position: u64| {
            // The value at `position`, version 2, reconciled through 0.
            Slot([
                AtomicU64::new(2),
                AtomicU64::new(position),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ])
        };
        let table = Arc::new(Table {
            // Version 0, no loss.
            header: Header(std::array::from_fn(|_| AtomicU64::new(0))),
            slots: [slot(POSITIONS[0]), slot(POSITIONS[1])],
            marker: AtomicU64::new(0),
            terminal: AtomicU64::new(0),
            terminal_body: [AtomicU64::new(0), AtomicU64::new(0)],
        });
        let writing = {
            let table = Arc::clone(&table);
            thread::spawn(move || writer(&table, fault))
        };
        let reading = {
            let table = Arc::clone(&table);
            thread::spawn(move || reader(&table, fault))
        };
        writing.join().unwrap();
        reading.join().unwrap();
    });
}

#[test]
fn a_reader_never_sees_a_lost_value_fresh() {
    model(Fault::None);
}

#[test]
#[should_panic(expected = "fresh after a committed gap")]
fn control_a_marker_before_its_barrier_shows_a_lost_value_fresh() {
    model(Fault::MarkerBeforeBarrier);
}

#[test]
#[should_panic(expected = "retired history without its slot")]
fn control_a_record_retired_before_its_slot_hides_the_slot_metadata() {
    model(Fault::RetireBeforeReconcile);
}

#[test]
#[should_panic(expected = "retired history without its slot")]
fn control_a_record_retired_after_the_first_slot_hides_the_second() {
    model(Fault::RetireAfterFirstSlot);
}

#[test]
#[should_panic(expected = "stale since a later gap")]
fn control_overwriting_an_unretired_record_loses_the_earlier_gap() {
    model(Fault::OverwriteUnretired);
}

#[test]
#[should_panic(expected = "slot newer than its barrier")]
fn control_without_the_final_validation_a_newer_slot_is_accepted() {
    model(Fault::NoFinalValidation);
}

#[test]
#[should_panic(expected = "incomplete terminal cell")]
fn control_a_terminal_cell_published_before_its_body_is_incomplete() {
    model(Fault::TerminalBeforeBody);
}
