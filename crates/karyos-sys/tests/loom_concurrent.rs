// SPDX-License-Identifier: Apache-2.0

//! Loom models of concurrent publication (`quantstratum-docs: karyos/design/concurrent-publication.md`,
//! batch a), over the production helpers of `karyos_sys::publication`:
//!
//! - two publishers reserve with one `fetch_add` each on a shared raw
//!   tail; their blocks are disjoint and contiguous; each marks its block,
//!   writes a plain payload witness and an interior word 0, and commits
//!   with the commit compare-exchange; a reader that sees a committed
//!   block sees its witness and its interior word;
//! - the publisher-slot handoff over the production helpers
//!   (`acquire_publisher_slot`, `release_publisher_slot`, `reissue_from`):
//!   a holder that made its end-crossing reservation in the still active
//!   term closes; the slot is reissued twice, and no holder makes a second
//!   end-crossing reservation in that term.
//!
//! Negative controls must fail: a reservation by load and store instead of
//! `fetch_add` (overlapping blocks), a commit by Relaxed store (payload
//! not ordered), and a reissue that ignores the closing term.
//!
//! Exploration: default Loom bounds; two publishers and one reader, or one
//! holder and one conductor.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::publication::{
    acquire_publisher_slot, commit_block, load_interior, mark_block, observe_block, reissue_from,
    release_publisher_slot, store_interior,
};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

const BLOCKS: usize = 2;

fn reserved() -> Word0 {
    Word0::new(
        -64,
        Flags::new(true, false, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

fn committed(index: usize) -> Word0 {
    Word0::new(
        40 + index as i32,
        Flags::new(true, false, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

fn interior() -> Word0 {
    Word0::new(
        40,
        Flags::new(false, true, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reserve {
    FetchAdd,
    LoadStore,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Commit {
    CompareExchange,
    RelaxedStore,
}

struct Term {
    tail: AtomicU64,
    first: [AtomicU64; BLOCKS],
    interior: [AtomicU64; BLOCKS],
    payload: [UnsafeCell<u64>; BLOCKS],
}

fn reservations_model(reserve: Reserve, commit: Commit) {
    loom::model(move || {
        let term = Arc::new(Term {
            tail: AtomicU64::new(0),
            first: [AtomicU64::new(0), AtomicU64::new(0)],
            interior: [AtomicU64::new(0), AtomicU64::new(0)],
            payload: [UnsafeCell::new(0), UnsafeCell::new(0)],
        });
        let publishers: Vec<_> = (0..2)
            .map(|_| {
                let term = Arc::clone(&term);
                thread::spawn(move || {
                    let start = match reserve {
                        Reserve::FetchAdd => term.tail.fetch_add(1, Ordering::AcqRel),
                        Reserve::LoadStore => {
                            let start = term.tail.load(Ordering::Acquire);
                            term.tail.store(start + 1, Ordering::Release);
                            start
                        }
                    } as usize;
                    assert!(start < BLOCKS, "block past the modelled term");
                    let first = &term.first[start];
                    assert!(mark_block(first, reserved()), "block already marked");
                    term.payload[start].with_mut(|payload| {
                        // SAFETY: the pointer comes from a live `UnsafeCell`;
                        // Loom checks that no access races with this write.
                        unsafe { *payload = 0x100 + start as u64 }
                    });
                    store_interior(&term.interior[start], interior());
                    match commit {
                        Commit::CompareExchange => {
                            assert!(commit_block(first, reserved(), committed(start)));
                        }
                        Commit::RelaxedStore => {
                            first.store(committed(start).pack().to_le(), Ordering::Relaxed);
                        }
                    }
                    start
                })
            })
            .collect();
        let reader = {
            let term = Arc::clone(&term);
            thread::spawn(move || {
                for index in 0..BLOCKS {
                    if observe_block(&term.first[index]) == committed(index).pack() {
                        assert_eq!(
                            load_interior(&term.interior[index]),
                            interior().pack(),
                            "committed block not visible"
                        );
                        let payload = term.payload[index].with(|payload| {
                            // SAFETY: as above; ordered after the writer's
                            // write only through the commit and this Acquire.
                            unsafe { *payload }
                        });
                        assert_eq!(payload, 0x100 + index as u64);
                    }
                }
            })
        };
        let mut starts: Vec<usize> = publishers
            .into_iter()
            .map(|publisher| publisher.join().unwrap())
            .collect();
        reader.join().unwrap();
        // Disjoint and contiguous.
        starts.sort_unstable();
        assert_eq!(starts, [0, 1], "reservations overlap or leave a gap");
    });
}

#[test]
fn concurrent_reservations_are_disjoint_and_ordered() {
    reservations_model(Reserve::FetchAdd, Commit::CompareExchange);
}

#[test]
#[should_panic(expected = "block already marked")]
fn control_reservation_by_load_and_store_fails() {
    reservations_model(Reserve::LoadStore, Commit::CompareExchange);
}

#[test]
#[should_panic(expected = "committed block not visible")]
fn control_relaxed_commit_fails() {
    reservations_model(Reserve::FetchAdd, Commit::RelaxedStore);
}

/// Term length in reservation units; a reservation of 2 from offset 2
/// ends past it.
const TERM: u64 = 3;
const SIZE: u64 = 2;

/// The handoff over the production helpers: a holder crosses term 0 and
/// closes; the conductor reissues the slot twice (FREE to HELD, then the
/// second holder closes and the slot is reissued again) while term 0 stays
/// active (rotation delayed). Every holder reserves only from the term
/// `eligible` returns.
fn handoff_model(eligible: fn(Option<u32>, u32, &AtomicU64) -> u32) {
    loom::model(move || {
        let active = Arc::new(AtomicU64::new(0));
        let tail = Arc::new(AtomicU64::new(2));
        let slot = Arc::new(AtomicU64::new(0));
        let crossings = Arc::new(AtomicU64::new(0));
        let reserve = {
            let tail = Arc::clone(&tail);
            let crossings = Arc::clone(&crossings);
            move || {
                let start = tail.fetch_add(SIZE, Ordering::AcqRel);
                if start + SIZE > TERM {
                    crossings.fetch_add(1, Ordering::Relaxed);
                }
            }
        };
        // The first holder: issued, crosses term 0, closes.
        assert_eq!(acquire_publisher_slot(&slot), Some(None));
        let holder = {
            let active = Arc::clone(&active);
            let slot = Arc::clone(&slot);
            let reserve = reserve.clone();
            thread::spawn(move || {
                reserve();
                release_publisher_slot(&slot, active.load(Ordering::Acquire) as u32);
            })
        };
        let conductor = {
            let active = Arc::clone(&active);
            let slot = Arc::clone(&slot);
            let tail = Arc::clone(&tail);
            thread::spawn(move || {
                for _ in 0..2 {
                    let Some(previous) = acquire_publisher_slot(&slot) else {
                        return;
                    };
                    let n = active.load(Ordering::Acquire) as u32;
                    // A reissued holder reserves only when its first term is
                    // the active one, then closes in turn.
                    if eligible(previous, n, &tail) == n {
                        reserve();
                    }
                    release_publisher_slot(&slot, n);
                }
            })
        };
        holder.join().unwrap();
        conductor.join().unwrap();
        assert!(
            crossings.load(Ordering::Relaxed) <= 1,
            "a slot crossed one term twice"
        );
    });
}

fn production(previous: Option<u32>, active: u32, tail: &AtomicU64) -> u32 {
    reissue_from(previous, active, || tail.load(Ordering::Acquire) >= TERM)
}

fn ignoring_t_close(_: Option<u32>, active: u32, _: &AtomicU64) -> u32 {
    active
}

#[test]
fn a_reissued_slot_crosses_a_term_at_most_once() {
    handoff_model(production);
}

#[test]
#[should_panic(expected = "a slot crossed one term twice")]
fn control_reissue_ignoring_t_close_fails() {
    handoff_model(ignoring_t_close);
}
