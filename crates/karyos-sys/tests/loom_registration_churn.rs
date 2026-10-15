// SPDX-License-Identifier: Apache-2.0

//! Loom model of registration churn (SPEC.md §13 "Registration churn";
//! `quantstratum-docs: karyos/design/concurrent-publication.md`, Handles
//! and their handoff), over the production publisher-slot helpers
//! (`acquire_publisher_slot`, `reissue_from`, `release_publisher_slot`).
//!
//! A concurrent buffer with two publisher slots at the registration bound
//! (`term_length + P × max_reserved = 2^31 - 32`, the largest the
//! creation check accepts) has a term that fills and stays unrotated: its
//! raw tail starts where one reservation still fits and the next crosses,
//! and the active count never moves. Two handles, one per slot, reserve concurrently and close; the
//! conductor meanwhile registers a new handle on whichever slot is free,
//! twice, and each reissued handle reserves from the term the production
//! reissue rule gives it and closes in turn. Every reservation follows
//! the production order: load the tail, refuse a full term without a
//! `fetch_add`, then one `fetch_add` of `max_reserved`.
//!
//! Checks: every value the tail takes keeps its term-id half and an
//! offset half below `2^31`; each publisher slot makes at most one
//! end-crossing reservation in the term, whatever the churn; the final
//! offset is within `term_length + P × max_reserved`.
//!
//! The configuration is the tightest the registration inequality allows
//! (production term lengths are powers of two up to `2^30`, which leave
//! more room); its term length is not a power of two, which the tail
//! arithmetic does not use. Four reservations in the term reach `2^31`,
//! so the negative controls (no full-term check before the `fetch_add`
//! and a reissue that ignores `t_close`) fail: with the per-slot check
//! off, on the offset half itself; with it on, on a second crossing by
//! one slot, which Loom reaches first.
//!
//! Exploration: default Loom bounds; two holders and the conductor.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::publication::{acquire_publisher_slot, reissue_from, release_publisher_slot};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

/// Publisher slots (`P`).
const PUBLISHERS: usize = 2;
/// `max_reserved`, a multiple of the frame alignment.
const SIZE: u64 = 214_748_352;
/// The term length: `TERM + P × SIZE = 2^31 - 32`.
const TERM: u64 = 1_717_986_912;
/// The term id of the unrotated term, at the top of the 32-bit range.
const TERM_ID: u64 = u32::MAX as u64;
/// The tail's starting offset: one reservation fits, the next crosses.
const START: u64 = TERM - SIZE - 32;
/// The offset half's bound.
const OFFSET_LIMIT: u64 = 1 << 31;

// The configuration passes the creation checks of a concurrent buffer.
const _: () = assert!(TERM + PUBLISHERS as u64 * SIZE < OFFSET_LIMIT);
const _: () = assert!(PUBLISHERS as u64 * SIZE <= TERM / 2);
const _: () = assert!(SIZE <= TERM / 8 && SIZE.is_multiple_of(32) && TERM.is_multiple_of(32));
// One reservation more than the per-slot bound allows reaches `2^31`.
const _: () = assert!(START + (PUBLISHERS as u64 + 2) * SIZE >= OFFSET_LIMIT);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    /// The production reservation and reissue.
    Production,
    /// No full-term check before the `fetch_add`, and a reissue that
    /// ignores the closing term.
    Unprotected,
}

struct Buffer {
    tail: AtomicU64,
    active: AtomicU64,
    publishers: [AtomicU64; PUBLISHERS],
    /// End-crossing reservations per publisher slot.
    crossings: [AtomicU64; PUBLISHERS],
}

impl Buffer {
    fn crossed(&self) -> bool {
        let raw = self.tail.load(Ordering::Acquire);
        raw >> 32 != TERM_ID || raw & u64::from(u32::MAX) >= TERM
    }

    /// One reservation attempt of a handle on publisher slot `index`.
    fn reserve(&self, index: usize, policy: Policy) {
        if policy == Policy::Production
            && self.tail.load(Ordering::Acquire) & u64::from(u32::MAX) >= TERM
        {
            // Full: no reservation here.
            return;
        }
        let old = self.tail.fetch_add(SIZE, Ordering::AcqRel);
        let new = old + SIZE;
        assert!(
            new & u64::from(u32::MAX) < OFFSET_LIMIT,
            "the offset half reached 2^31"
        );
        assert_eq!(new >> 32, TERM_ID, "the term-id half changed");
        if (old & u64::from(u32::MAX)) + SIZE > TERM {
            self.crossings
                .get(index)
                .unwrap()
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Closes the handle on slot `index`, recording `t_close`.
    fn close(&self, index: usize) {
        let t_close = self.active.load(Ordering::Acquire) as u32;
        release_publisher_slot(self.publishers.get(index).unwrap(), t_close);
    }
}

/// `per_slot` enables the per-slot crossing check; the first control turns
/// it off so that the offset-half check alone must catch the churn.
fn model(policy: Policy, per_slot: bool) {
    loom::model(move || {
        let buffer = Arc::new(Buffer {
            tail: AtomicU64::new(TERM_ID << 32 | START),
            active: AtomicU64::new(0),
            publishers: [AtomicU64::new(0), AtomicU64::new(0)],
            crossings: [AtomicU64::new(0), AtomicU64::new(0)],
        });
        // The first two handles are registered on never-used slots.
        for word in &buffer.publishers {
            assert_eq!(acquire_publisher_slot(word), Some(None));
        }
        let holders: Vec<_> = (0..PUBLISHERS)
            .map(|index| {
                let buffer = Arc::clone(&buffer);
                thread::spawn(move || {
                    buffer.reserve(index, policy);
                    buffer.close(index);
                })
            })
            .collect();
        let conductor = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || {
                for _ in 0..2 {
                    // Register a new handle on the first free slot.
                    let issued = buffer
                        .publishers
                        .iter()
                        .enumerate()
                        .find_map(|(index, word)| {
                            acquire_publisher_slot(word).map(|previous| (index, previous))
                        });
                    let Some((index, previous)) = issued else {
                        continue;
                    };
                    let n = buffer.active.load(Ordering::Acquire) as u32;
                    let from = match policy {
                        Policy::Production => reissue_from(previous, n, || buffer.crossed()),
                        Policy::Unprotected => n,
                    };
                    // A handle that must wait for a later term makes no
                    // reservation in this one, which never rotates.
                    if from == n {
                        buffer.reserve(index, policy);
                    }
                    buffer.close(index);
                }
            })
        };
        for holder in holders {
            holder.join().unwrap();
        }
        conductor.join().unwrap();
        if per_slot {
            for crossings in &buffer.crossings {
                assert!(
                    crossings.load(Ordering::Relaxed) <= 1,
                    "a slot crossed one term twice"
                );
            }
        }
        let offset = buffer.tail.load(Ordering::Acquire) & u64::from(u32::MAX);
        assert!(offset <= TERM + PUBLISHERS as u64 * SIZE);
    });
}

#[test]
fn churning_handles_cross_a_term_once_per_slot_below_2_31() {
    model(Policy::Production, true);
}

#[test]
#[should_panic(expected = "the offset half reached 2^31")]
fn control_unprotected_churn_reaches_2_31_fails() {
    model(Policy::Unprotected, false);
}

#[test]
#[should_panic(expected = "a slot crossed one term twice")]
fn control_unprotected_churn_crosses_twice_fails() {
    model(Policy::Unprotected, true);
}
