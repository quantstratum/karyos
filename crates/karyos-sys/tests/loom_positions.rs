// SPDX-License-Identifier: Apache-2.0

//! Loom model of the positions sampling pass (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Per-stream positions") over
//! the production epoch protocol of `karyos_sys::counters`: the writer's
//! `begin_pass` and `end_pass`, and the reader's `read_pass`.
//!
//! The driver runs two passes. Within each, it sets a subscriber position,
//! the floor and then the head, read from live values in that order, so a
//! pass never shows a subscriber or the floor above the head; between the
//! passes the stream advances. A reader that accepts a pass as consistent
//! must see, per lane, the subscriber position and the floor at most the
//! head, and the lag never underflows. Negative control: passes without the
//! odd epoch let the reader accept a mix of two passes.
//!
//! Membership: a subscriber cell added, a stream's cell removed, and a
//! released cell reused under a new key, each inside the second pass while
//! a reader scans. A reader that accepts a pass never sees a new cell with
//! its allocation value of zero, a removed cell still allocated, or a reused
//! cell under its previous key. Negative control: the same changes without
//! the odd epoch are accepted mixed. The membership models explore the
//! counter cells' own seqlocks too, so they are slow and run under `make
//! loom-full`.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::counters::{
    CellRead, CellWords, CounterKeys, CounterMetadata, META_WORDS, PassRead, TYPE_POSITION,
    read_pass,
};
use karyos_sys::sync::AtomicU64;
use loom::sync::Arc;
use loom::thread;

struct Cell {
    meta: Vec<AtomicU64>,
    value: AtomicU64,
}

impl Cell {
    fn new() -> Self {
        Self {
            meta: (0..META_WORDS).map(|_| AtomicU64::new(0)).collect(),
            value: AtomicU64::new(0),
        }
    }

    fn words(&self) -> CellWords<'_> {
        CellWords::new(&self.meta, &self.value).unwrap()
    }
}

/// The pass's cells: epoch, subscriber position, floor and head.
struct Pass {
    epoch: Cell,
    subscriber: Cell,
    floor: Cell,
    head: Cell,
}

/// The live values of pass `k`: (subscriber, floor, head), each within a
/// pass at most the head, and all growing between passes.
fn live(k: u64) -> (u64, u64, u64) {
    (10 * k, 5 * k, 20 * k)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Epoch {
    Odd,
    Skipped,
}

fn model(epoch: Epoch) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let pass = Arc::new(Pass {
            epoch: Cell::new(),
            subscriber: Cell::new(),
            floor: Cell::new(),
            head: Cell::new(),
        });
        let writer = {
            let pass = Arc::clone(&pass);
            thread::spawn(move || {
                for k in 1..=2u64 {
                    let (subscriber, floor, head) = live(k);
                    if epoch == Epoch::Odd {
                        pass.epoch.words().begin_pass(2 * k - 1);
                    }
                    pass.subscriber.words().set(subscriber);
                    pass.floor.words().set(floor);
                    pass.head.words().set(head);
                    pass.epoch.words().end_pass(2 * k);
                }
            })
        };
        let read = read_pass(
            || pass.epoch.words().load_value(),
            || {
                // A tool reads in any order; this one reads the head first,
                // so a mixed sample can show a later subscriber position.
                let head = pass.head.words().load_value();
                let subscriber = pass.subscriber.words().load_value();
                let floor = pass.floor.words().load_value();
                (subscriber, floor, head)
            },
            2,
        );
        if let PassRead::Consistent((subscriber, floor, head)) = read {
            assert!(
                subscriber <= head,
                "an accepted pass shows a lag below zero"
            );
            assert!(
                floor <= head,
                "an accepted pass shows the floor above the head"
            );
            assert!(head.checked_sub(subscriber).is_some());
        }
        writer.join().unwrap();
    });
}

#[test]
fn an_accepted_pass_is_never_mixed() {
    model(Epoch::Odd);
}

#[test]
#[should_panic(expected = "an accepted pass shows")]
fn control_a_pass_without_the_odd_epoch_can_be_mixed() {
    model(Epoch::Skipped);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Membership {
    /// A subscriber's cell is allocated and set in the second pass.
    Added,
    /// A removed stream's cell is freed in the second pass.
    Removed,
    /// A released cell is freed and allocated to a new subscriber, then
    /// set, in the second pass.
    Reused,
}

/// A subscriber position cell's metadata for registration `registration`.
fn subscriber(registration: u64) -> CounterMetadata {
    CounterMetadata::new(registration, TYPE_POSITION, "subscriber position")
        .unwrap()
        .with_keys(CounterKeys {
            stream: 1,
            lane: 0,
            kind: karyos_sys::counters::KIND_SUBSCRIBER,
            participant: registration,
        })
}

/// What the cell holds as an accepted pass may show it: free, or a
/// registration and its value.
fn shown(read: CellRead) -> Option<(u64, u64)> {
    match read {
        CellRead::Free => None,
        CellRead::Allocated {
            metadata, value, ..
        } => Some((metadata.keys.participant, value)),
        CellRead::Changing => panic!("an accepted pass shows a cell being changed"),
    }
}

/// The first pass (epoch 2, head 20) is complete before the reader starts;
/// the second (head 40) changes the cell's membership while the reader
/// scans the head first, then the cell.
fn membership_model(change: Membership, epoch: Epoch) {
    let mut builder = loom::model::Builder::new();
    // One preemption is enough for a reader between its two loads.
    builder.preemption_bound = Some(1);
    builder.check(move || {
        let pass = Arc::new(Pass {
            epoch: Cell::new(),
            subscriber: Cell::new(),
            floor: Cell::new(),
            head: Cell::new(),
        });
        // Pass 1: the cell of registration 1 exists unless it is added in
        // pass 2.
        pass.epoch.words().begin_pass(1);
        if change != Membership::Added {
            pass.subscriber.words().allocate(&subscriber(1)).unwrap();
            pass.subscriber.words().set(100);
        }
        pass.head.words().set(20);
        pass.epoch.words().end_pass(2);
        let writer = {
            let pass = Arc::clone(&pass);
            thread::spawn(move || {
                if epoch == Epoch::Odd {
                    pass.epoch.words().begin_pass(3);
                }
                let cell = pass.subscriber.words();
                match change {
                    Membership::Added => {
                        cell.allocate(&subscriber(1)).unwrap();
                        cell.set(7);
                    }
                    Membership::Removed => cell.free().unwrap(),
                    Membership::Reused => {
                        cell.free().unwrap();
                        cell.allocate(&subscriber(2)).unwrap();
                        cell.set(5);
                    }
                }
                pass.head.words().set(40);
                pass.epoch.words().end_pass(4);
            })
        };
        let read = read_pass(
            || pass.epoch.words().load_value(),
            || {
                let head = pass.head.words().load_value();
                (head, pass.subscriber.words().read())
            },
            1,
        );
        if let PassRead::Consistent((head, cell)) = read {
            let cell = shown(cell);
            let expected = match (change, head) {
                (Membership::Added, 20) | (Membership::Removed, 40) => None,
                (Membership::Added, 40) => Some((1, 7)),
                (Membership::Removed | Membership::Reused, 20) => Some((1, 100)),
                (Membership::Reused, 40) => Some((2, 5)),
                (_, other) => panic!("head {other}"),
            };
            assert_eq!(
                cell, expected,
                "an accepted pass shows a cell of another pass ({change:?}, head {head})"
            );
        }
        writer.join().unwrap();
    });
}

#[test]
#[ignore = "slow: run by make loom-full"]
fn an_added_cell_is_never_seen_before_its_pass_set_it() {
    membership_model(Membership::Added, Epoch::Odd);
}

#[test]
#[ignore = "slow: run by make loom-full"]
fn a_removed_cell_is_never_seen_in_the_pass_that_removed_it() {
    membership_model(Membership::Removed, Epoch::Odd);
}

#[test]
#[ignore = "slow: run by make loom-full"]
fn a_reused_cell_is_never_seen_under_its_previous_key() {
    membership_model(Membership::Reused, Epoch::Odd);
}

#[test]
#[ignore = "slow: run by make loom-full"]
#[should_panic(expected = "an accepted pass shows a cell of another pass")]
fn control_membership_without_the_odd_epoch_can_be_mixed() {
    membership_model(Membership::Reused, Epoch::Skipped);
}
