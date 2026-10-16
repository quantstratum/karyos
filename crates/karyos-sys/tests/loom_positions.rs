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
//! the odd epoch are accepted mixed. The cells' own seqlocks are modelled
//! in `loom_counters`; here a member cell is its key and value words.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::counters::{CellWords, META_WORDS, PassRead, read_pass};
use karyos_sys::sync::{AtomicU64, Ordering};
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

/// A position cell as the pass sees its membership: the registration its
/// key names (0 for a free cell) and its value. The cell's own seqlock is
/// modelled in `loom_counters`; here each word is a plain Relaxed access,
/// so the pass's epoch alone must keep a reader from mixing passes.
struct Member {
    key: AtomicU64,
    value: AtomicU64,
}

/// The pass's epoch, one member cell and the head.
struct Membered {
    epoch: Cell,
    member: Member,
    head: AtomicU64,
}

/// The first pass (epoch 2, head 20) is complete before the reader starts;
/// the second (head 40) changes the cell's membership, writing the key
/// first and the value after it, as an allocation does, while the reader
/// loads the head, then the cell. A mixed read needs the reader preempted
/// between its loads and the writer before its even epoch, so the bound is
/// two preemptions.
fn membership_model(change: Membership, epoch: Epoch) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let pass = Arc::new(Membered {
            epoch: Cell::new(),
            member: Member {
                key: AtomicU64::new(0),
                value: AtomicU64::new(0),
            },
            head: AtomicU64::new(0),
        });
        // Pass 1: the cell of registration 1 exists unless it is added in
        // pass 2.
        pass.epoch.words().begin_pass(1);
        if change != Membership::Added {
            pass.member.key.store(1, Ordering::Relaxed);
            pass.member.value.store(100, Ordering::Relaxed);
        }
        pass.head.store(20, Ordering::Relaxed);
        pass.epoch.words().end_pass(2);
        let writer = {
            let pass = Arc::clone(&pass);
            thread::spawn(move || {
                if epoch == Epoch::Odd {
                    pass.epoch.words().begin_pass(3);
                }
                let (key, value) = match change {
                    Membership::Added => (1, 7),
                    Membership::Removed => (0, 0),
                    Membership::Reused => (2, 5),
                };
                pass.member.key.store(key, Ordering::Relaxed);
                pass.member.value.store(value, Ordering::Relaxed);
                pass.head.store(40, Ordering::Relaxed);
                pass.epoch.words().end_pass(4);
            })
        };
        let read = read_pass(
            || pass.epoch.words().load_value(),
            || {
                let head = pass.head.load(Ordering::Relaxed);
                let key = pass.member.key.load(Ordering::Relaxed);
                let value = pass.member.value.load(Ordering::Relaxed);
                (head, key, value)
            },
            1,
        );
        if let PassRead::Consistent((head, key, value)) = read {
            let cell = (key != 0).then_some((key, value));
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
fn an_added_cell_is_never_seen_before_its_pass_set_it() {
    membership_model(Membership::Added, Epoch::Odd);
}

#[test]
fn a_removed_cell_is_never_seen_in_the_pass_that_removed_it() {
    membership_model(Membership::Removed, Epoch::Odd);
}

#[test]
fn a_reused_cell_is_never_seen_under_its_previous_key() {
    membership_model(Membership::Reused, Epoch::Odd);
}

#[test]
#[should_panic(expected = "an accepted pass shows a cell of another pass")]
fn control_an_added_cell_without_the_odd_epoch_can_be_mixed() {
    membership_model(Membership::Added, Epoch::Skipped);
}

#[test]
#[should_panic(expected = "an accepted pass shows a cell of another pass")]
fn control_a_removed_cell_without_the_odd_epoch_can_be_mixed() {
    membership_model(Membership::Removed, Epoch::Skipped);
}

#[test]
#[should_panic(expected = "an accepted pass shows a cell of another pass")]
fn control_membership_without_the_odd_epoch_can_be_mixed() {
    membership_model(Membership::Reused, Epoch::Skipped);
}
