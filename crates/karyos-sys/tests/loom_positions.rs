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
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::counters::{CellWords, META_WORDS, PassRead, read_pass};
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
