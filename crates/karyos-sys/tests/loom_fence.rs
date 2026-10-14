// SPDX-License-Identifier: Apache-2.0

//! Loom models of the concurrent fence (`quantstratum-docs: karyos/design/mapping-generations.md`),
//! over the production helpers of `karyos_sys::publication` and
//! `karyos_sys::loan`:
//!
//! - two concurrent publishers reserve with `fetch_add` on one term's tail,
//!   each after an Acquire check of the limit, while the conductor seals and
//!   fences. The seal position (the fenced tail's old offset) is the end of
//!   the last granted reservation, and a publisher that lands past the end
//!   observes the seal;
//! - a publisher rotates to the next term (`rotate_to`) and then reserves in
//!   the term it reads as active, while the conductor fences: every grant is
//!   in the fenced term, at or below the seal position.
//!
//! Negative controls must fail: the tail fence as a plain load and store;
//! the seal stored after the fence; the rotation stop as a plain load and
//! store; the fence without the rotation stop.
//!
//! Exploration: preemption bound 3; at most two grants per publisher in the
//! first model, one rotation and one grant in the second.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::loan::rotate_to;
use karyos_sys::publication::{
    ROTATION_FENCE, SEAL_POSITIONED, active_term_count, fence_rotation, fence_tail, observe_seal,
    position_seal, seal,
};
use karyos_sys::slot::{Descriptor, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::sync::Arc;
use loom::thread;

/// Bounded exploration, as the other models with spin loops.
fn builder() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder
}

/// The term length of the models: no grant reaches it.
const TERM: u32 = 100;
/// A limit no grant reaches either.
const OPEN: u64 = 50;
const GRANTS: u64 = 2;

fn seal_position(word: &AtomicU64) -> Option<u64> {
    let raw = word.load(Ordering::Acquire);
    (raw & SEAL_POSITIONED != 0).then_some(raw & (SEAL_POSITIONED - 1))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fence {
    Correct,
    PlainTailFence,
    SealAfterFence,
}

struct Shared {
    tail: AtomicU64,
    limit: AtomicU64,
    seal: AtomicU64,
    active: AtomicU64,
    /// Highest granted end seen by the publishers.
    granted: AtomicU64,
}

fn reservation_model(variant: Fence) {
    builder().check(move || {
        let shared = Arc::new(Shared {
            tail: AtomicU64::new(0),
            limit: AtomicU64::new(OPEN),
            seal: AtomicU64::new(0),
            active: AtomicU64::new(0),
            granted: AtomicU64::new(0),
        });
        let publishers: Vec<_> = (0..2)
            .map(|_| {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    for _ in 0..GRANTS {
                        // The production check: head plus one within the
                        // limit, then one `fetch_add`.
                        let head = shared.tail.load(Ordering::Acquire) as u32;
                        if u64::from(head) + 1 > shared.limit.load(Ordering::Acquire) {
                            return;
                        }
                        let old = shared.tail.fetch_add(1, Ordering::AcqRel) as u32;
                        if old >= TERM {
                            assert!(
                                observe_seal(&shared.seal),
                                "landed past the end without seeing the seal"
                            );
                            return;
                        }
                        let _ = shared
                            .granted
                            .fetch_max(u64::from(old) + 1, Ordering::AcqRel);
                    }
                })
            })
            .collect();
        let conductor = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                if variant != Fence::SealAfterFence {
                    seal(&shared.seal, &shared.limit);
                }
                let _ = fence_rotation(&shared.active);
                let old = match variant {
                    Fence::PlainTailFence => {
                        let old = shared.tail.load(Ordering::Acquire);
                        shared.tail.store(old + u64::from(TERM), Ordering::Release);
                        old
                    }
                    _ => fence_tail(&shared.tail, TERM),
                };
                if variant == Fence::SealAfterFence {
                    seal(&shared.seal, &shared.limit);
                }
                position_seal(&shared.seal, (old as u32).min(TERM).into());
            })
        };
        for publisher in publishers {
            publisher.join().unwrap();
        }
        conductor.join().unwrap();
        let position = seal_position(&shared.seal).unwrap();
        let granted = shared.granted.load(Ordering::Acquire);
        assert!(
            granted <= position,
            "a reservation was granted above the seal position"
        );
        assert_eq!(granted, position, "the seal position is not the last end");
    });
}

#[test]
fn the_fence_positions_at_the_last_grant() {
    reservation_model(Fence::Correct);
}

#[test]
#[should_panic(expected = "a reservation was granted above the seal position")]
fn control_a_plain_tail_fence() {
    reservation_model(Fence::PlainTailFence);
}

#[test]
#[should_panic(expected = "landed past the end without seeing the seal")]
fn control_the_seal_after_the_fence() {
    reservation_model(Fence::SealAfterFence);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    Correct,
    PlainRotationStop,
    NoRotationStop,
}

fn generation() -> Generation {
    Generation::try_new(1).unwrap()
}

fn term(count: u32) -> TermId {
    TermId::new(7).advanced_by(TermCount::try_new(count).unwrap())
}

struct Terms {
    active: AtomicU64,
    /// Term 1's slot descriptor, `READY` until the rotation.
    next: AtomicU64,
    tails: [AtomicU64; 2],
    limit: AtomicU64,
    seal: AtomicU64,
    /// `(term + 1) << 32 | end` of the publisher's grant, or 0.
    grant: AtomicU64,
}

fn rotation_model(variant: Stop) {
    builder().check(move || {
        let shared = Arc::new(Terms {
            active: AtomicU64::new(0),
            next: AtomicU64::new(Descriptor::new(term(1), generation(), SlotState::Ready).encode()),
            // Term 0 is full: the publisher's rotation is due.
            tails: [AtomicU64::new(u64::from(TERM)), AtomicU64::new(0)],
            limit: AtomicU64::new(u64::from(TERM) + OPEN),
            seal: AtomicU64::new(0),
            grant: AtomicU64::new(0),
        });
        let publisher = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let one = TermCount::try_new(1).unwrap();
                let _ =
                    rotate_to(&shared.next, &shared.active, term(1), generation(), one).unwrap();
                let active = active_term_count(shared.active.load(Ordering::Acquire));
                let Some(tail) = shared.tails.get(active as usize) else {
                    return;
                };
                let head = u64::from(active) * u64::from(TERM)
                    + u64::from(tail.load(Ordering::Acquire) as u32);
                if head + 1 > shared.limit.load(Ordering::Acquire) {
                    return;
                }
                let old = tail.fetch_add(1, Ordering::AcqRel) as u32;
                if old < TERM {
                    shared.grant.store(
                        (u64::from(active) + 1) << 32 | (u64::from(old) + 1),
                        Ordering::Release,
                    );
                }
            })
        };
        let conductor = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                seal(&shared.seal, &shared.limit);
                let count = match variant {
                    Stop::Correct => fence_rotation(&shared.active),
                    Stop::PlainRotationStop => {
                        let raw = shared.active.load(Ordering::Acquire);
                        shared.active.store(raw | ROTATION_FENCE, Ordering::Release);
                        active_term_count(raw)
                    }
                    Stop::NoRotationStop => {
                        active_term_count(shared.active.load(Ordering::Acquire))
                    }
                };
                let old = fence_tail(&shared.tails[count as usize], TERM) as u32;
                let position = u64::from(count) * u64::from(TERM) + u64::from(old.min(TERM));
                position_seal(&shared.seal, position);
            })
        };
        publisher.join().unwrap();
        conductor.join().unwrap();
        let position = seal_position(&shared.seal).unwrap();
        let grant = shared.grant.load(Ordering::Acquire);
        if grant != 0 {
            let end = ((grant >> 32) - 1) * u64::from(TERM) + (grant & 0xffff_ffff);
            assert!(end <= position, "a grant in a later term escaped the fence");
        }
    });
}

#[test]
fn the_fence_stops_rotation() {
    rotation_model(Stop::Correct);
}

#[test]
#[should_panic(expected = "a grant in a later term escaped the fence")]
fn control_a_plain_rotation_stop() {
    rotation_model(Stop::PlainRotationStop);
}

#[test]
#[should_panic(expected = "a grant in a later term escaped the fence")]
fn control_no_rotation_stop() {
    rotation_model(Stop::NoRotationStop);
}
