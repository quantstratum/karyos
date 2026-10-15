// SPDX-License-Identifier: Apache-2.0

//! Loom model of the first three rotations of a fresh log buffer
//! (SPEC.md §13 "First start and identity limits" and "Rotation helpers";
//! issue #67), over the production helpers of `karyos_sys::loan`.
//!
//! The buffer starts as `LogBuffer::initialise` leaves it, with `t0` two
//! terms below the end of the 32-bit range, so the three rotations reach
//! term ids `u32::MAX`, `0` and `1`: slot 0 `ACTIVE(t0)`, slot 1
//! `READY(t0 + 1)`, slot 2 `FREE`; every tail but slot 0's names `t0 + 1`,
//! which is stale for any later term. Three threads:
//!
//! - the conductor initialises slot 2's tail and publishes `READY(t0 + 2)`;
//!   once term 0 is no longer active and no loan pins it, it reclaims and
//!   cleans slot 0, initialises its tail and publishes `READY(t0 + 3)`;
//! - a producer owns the rotations: in each term it takes its write loan,
//!   reads the tail, fills the term with one `fetch_add`, releases the loan
//!   and rotates to the next term, retrying while the conductor is behind;
//! - a delayed helper, a producer whose reservation crossed: for terms 1
//!   and 2, when it sees the previous term full it makes one rotation
//!   attempt at any later point, including after the producer has used
//!   the new term.
//!
//! Checks: the producer never sees a term before its tail is initialised
//! (its tail read and its `fetch_add` both name the term it holds a loan
//! on), so no reservation is lost to a later term; a helper attempt
//! completes the rotation or finds it superseded, and never moves the
//! active count back; the run ends with term 3 active in slot 0.
//!
//! The negative control publishes `READY` before initialising the tail: a
//! producer that reaches the term then reads the stale tail.
//!
//! Exploration: preemption bound 2 (three threads, each with retry loops).
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::loan::{
    LoanOutcome, LoanTarget, Rotation, begin_cleaning, begin_reclaim, loan_held, publish,
    release_loan, rotate_to, take_loan,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::sync::Arc;
use loom::thread;

/// Term length in the model's units: one `fetch_add` fills a term.
const TERM: u64 = 2;

fn initial() -> TermId {
    TermId::new(u32::MAX - 1)
}

fn generation() -> Generation {
    Generation::try_new(1).unwrap()
}

fn count(value: u32) -> TermCount {
    TermCount::try_new(value).unwrap()
}

fn term(value: u32) -> TermId {
    initial().advanced_by(count(value))
}

/// The slot of term count `value` with three slots: 0, 1, 2, then slot 0
/// again once it is reclaimed.
fn slot_of(value: u32) -> usize {
    (value % 3) as usize
}

fn descriptor(value: u32, state: SlotState) -> Descriptor {
    Descriptor::new(term(value), generation(), state)
}

/// A tail word at offset 0 of term count `value`.
fn tail_of(value: u32) -> u64 {
    u64::from(term(value).get()) << 32
}

struct Buffer {
    descriptors: [AtomicU64; 3],
    tails: [AtomicU64; 3],
    active: AtomicU64,
    loans: [AtomicU64; 1],
    revoked: AtomicU64,
}

impl Buffer {
    /// The state `LogBuffer::initialise` writes.
    fn fresh() -> Self {
        Self {
            descriptors: [
                AtomicU64::new(descriptor(0, SlotState::Active).encode()),
                AtomicU64::new(descriptor(1, SlotState::Ready).encode()),
                AtomicU64::new(descriptor(0, SlotState::Free).encode()),
            ],
            tails: [
                AtomicU64::new(tail_of(0)),
                AtomicU64::new(tail_of(1)),
                AtomicU64::new(tail_of(1)),
            ],
            active: AtomicU64::new(0),
            loans: [AtomicU64::new(0)],
            revoked: AtomicU64::new(0),
        }
    }

    fn rotate(&self, next: u32) -> Rotation {
        rotate_to(
            &self.descriptors[slot_of(next)],
            &self.active,
            term(next),
            generation(),
            count(next),
        )
        .unwrap()
    }

    /// The conductor prepares term count `value` in its free slot.
    fn prepare(&self, value: u32, order: Order) {
        let slot = slot_of(value);
        if order == Order::ReadyBeforeTail {
            publish(&self.descriptors[slot], descriptor(value, SlotState::Ready));
            self.tails[slot].store(tail_of(value), Ordering::Relaxed);
        } else {
            // Production order: the tail, then the Release publication.
            self.tails[slot].store(tail_of(value), Ordering::Relaxed);
            publish(&self.descriptors[slot], descriptor(value, SlotState::Ready));
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    TailBeforeReady,
    ReadyBeforeTail,
}

fn builder() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder
}

fn model(order: Order) {
    builder().check(move || {
        let buffer = Arc::new(Buffer::fresh());
        let conductor = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || {
                buffer.prepare(2, order);
                // Term 0 leaves the active position, then its slot is
                // reclaimed once no loan pins it.
                while buffer.active.load(Ordering::Acquire) < 1 {
                    thread::yield_now();
                }
                let slot = SlotIndex::try_new(0).unwrap();
                let reclaiming =
                    begin_reclaim(&buffer.descriptors[0], descriptor(0, SlotState::Active))
                        .unwrap();
                while loan_held(&buffer.loans, slot, reclaiming).unwrap() {
                    thread::yield_now();
                }
                let cleaning = begin_cleaning(&buffer.descriptors[0], reclaiming).unwrap();
                publish(&buffer.descriptors[0], cleaning.with_state(SlotState::Free));
                buffer.prepare(3, order);
            })
        };
        let helper = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || {
                for next in [1, 2] {
                    // A producer that crossed: it saw the term full, then
                    // makes its one rotation attempt after any delay.
                    let full = tail_of(next - 1) + TERM;
                    if buffer.tails[slot_of(next - 1)].load(Ordering::Acquire) != full {
                        continue;
                    }
                    let outcome = buffer.rotate(next);
                    // Term 1 is READY from the start; term 2 may not be
                    // prepared yet.
                    assert!(
                        outcome != Rotation::NotReady || next == 2,
                        "a ready rotation was not done"
                    );
                }
            })
        };
        // The producer.
        for value in 0..=3 {
            let slot = slot_of(value);
            let target = LoanTarget::new(
                SlotIndex::try_new(slot as u8).unwrap(),
                generation(),
                initial(),
                count(value),
            );
            let [word] = &buffer.loans;
            assert_eq!(
                buffer.active.load(Ordering::Acquire),
                u64::from(value),
                "the active count moved without the producer"
            );
            assert_eq!(
                take_loan(word, &buffer.revoked, &buffer.descriptors[slot], target).unwrap(),
                LoanOutcome::Granted
            );
            let tail = &buffer.tails[slot];
            assert_eq!(
                tail.load(Ordering::Acquire),
                tail_of(value),
                "a producer read an uninitialised tail"
            );
            let old = tail.fetch_add(TERM, Ordering::AcqRel);
            assert_eq!(
                old,
                tail_of(value),
                "a producer reserved in an uninitialised tail"
            );
            release_loan(word);
            if value < 3 {
                while buffer.rotate(value + 1) == Rotation::NotReady {
                    thread::yield_now();
                }
            }
        }
        conductor.join().unwrap();
        helper.join().unwrap();
        assert_eq!(
            buffer.active.load(Ordering::Acquire),
            3,
            "active count moved back"
        );
        assert_eq!(
            buffer.descriptors[0].load(Ordering::Acquire),
            descriptor(3, SlotState::Active).encode()
        );
        assert_eq!(term(2).get(), 0, "the model crosses the 32-bit rollover");
    });
}

#[test]
fn first_three_rotations_from_a_fresh_buffer_near_rollover() {
    model(Order::TailBeforeReady);
}

#[test]
#[should_panic(expected = "uninitialised tail")]
fn control_ready_before_the_tail_fails() {
    model(Order::ReadyBeforeTail);
}
