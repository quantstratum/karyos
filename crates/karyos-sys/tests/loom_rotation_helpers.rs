// SPDX-License-Identifier: Apache-2.0

//! Loom models of rotation helpers (SPEC.md §13 "Rotation helpers";
//! `quantstratum-docs: karyos/design/concurrent-publication.md`, State),
//! over the production helpers of `karyos_sys::loan`, the conductor's
//! slot preparation (`prepare_slot`, which `Conductor::prepare_next`
//! calls) included:
//!
//! - the tail is initialised once, before `READY`: the conductor prepares
//!   the next term and then repeats the preparation, as a later duty
//!   cycle would, while a producer rotates into the term and reserves;
//!   the producer always reads the initialised tail and its reservation
//!   is never undone by a second initialisation;
//! - the owner's pause between activation and count advance, pinned with
//!   the `RotationActivated` pause point of `test_pause`: the owner of
//!   the rotation to `t + 1` stops right after activating the descriptor;
//!   a producer then sees `ACTIVE(t + 1)` with the count still at `t`,
//!   reserves in `t + 1`, completes the half-done rotation and rotates
//!   to `t + 2` (prepared concurrently by the conductor) before the owner
//!   resumes; the owner then finds its rotation superseded and never
//!   moves the active count back;
//! - a producer paused before its `fetch_add` across three real
//!   rotations: it holds its write loan on `t` and waits (by joining the
//!   rotator) while other producers rotate to `t + 1`, `t + 2` and
//!   `t + 3` through slots the conductor prepares concurrently; the
//!   conductor reclaims `t`'s slot and reassigns it to `t + 4` only after
//!   the loan scan; the producer's reservation always lands in `t`.
//!
//! Negative controls must fail: a preparation that publishes `READY`
//! before the tail, one that does not check the slot is still `FREE`
//! (the repeat reinitialises the tail), an owner that advances the count
//! by a plain store after the same pinned pause, and a conductor that
//! reassigns the paused producer's slot without the loan scan.
//!
//! Exploration: default Loom bounds. The three-rotation model has no
//! wait loops: each rotation is attempted once and the conductor makes
//! one duty cycle, so executions where the conductor is behind end with
//! fewer rotations (all checked); with wait loops Loom exceeded its
//! branch limit at preemption bound 2.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::loan::{
    LoanOutcome, LoanTarget, Rotation, activate, begin_cleaning, begin_reclaim, loan_held,
    prepare_slot, publish, release_loan, rotate_to, take_loan,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use karyos_sys::test_pause::{self, PausePoint};
use loom::sync::Arc;
use loom::thread;

/// One reservation in the model's units.
const SIZE: u64 = 32;

fn generation() -> Generation {
    Generation::try_new(1).unwrap()
}

fn count(value: u32) -> TermCount {
    TermCount::try_new(value).unwrap()
}

fn initial() -> TermId {
    TermId::new(7)
}

fn term(value: u32) -> TermId {
    initial().advanced_by(count(value))
}

fn descriptor(value: u32, state: SlotState) -> Descriptor {
    Descriptor::new(term(value), generation(), state)
}

/// A tail word at offset 0 of term count `value`.
fn tail_of(value: u32) -> u64 {
    u64::from(term(value).get()) << 32
}

/// A slot that held no term of this incarnation yet.
fn never_used() -> Descriptor {
    descriptor(0, SlotState::Free)
}

/// A stale tail, as `LogBuffer::initialise` leaves unused slots.
const STALE: u64 = 0xDEAD;

struct Buffer {
    descriptors: Vec<AtomicU64>,
    tails: Vec<AtomicU64>,
    active: AtomicU64,
    loans: [AtomicU64; 1],
    revoked: AtomicU64,
}

impl Buffer {
    fn new(descriptors: &[Descriptor], tails: &[u64]) -> Self {
        Self {
            descriptors: descriptors
                .iter()
                .map(|value| AtomicU64::new(value.encode()))
                .collect(),
            tails: tails.iter().map(|value| AtomicU64::new(*value)).collect(),
            active: AtomicU64::new(0),
            loans: [AtomicU64::new(0)],
            revoked: AtomicU64::new(0),
        }
    }

    fn descriptor(&self, slot: usize) -> &AtomicU64 {
        self.descriptors.get(slot).unwrap()
    }

    fn tail(&self, slot: usize) -> &AtomicU64 {
        self.tails.get(slot).unwrap()
    }

    fn rotate(&self, slot: usize, next: u32) -> Rotation {
        rotate_to(
            self.descriptor(slot),
            &self.active,
            term(next),
            generation(),
            count(next),
        )
        .unwrap()
    }

    fn loan(&self, slot: usize, value: u32) -> LoanOutcome {
        let target = LoanTarget::new(
            SlotIndex::try_new(slot as u8).unwrap(),
            generation(),
            initial(),
            count(value),
        );
        let [word] = &self.loans;
        take_loan(word, &self.revoked, self.descriptor(slot), target).unwrap()
    }

    fn release(&self) {
        let [word] = &self.loans;
        release_loan(word);
    }
}

// Tail initialised once, before READY.

#[derive(Clone, Copy, PartialEq, Eq)]
enum Prepare {
    /// The production `prepare_slot`.
    Production,
    /// `READY` published before the tail is initialised.
    ReadyFirst,
    /// No check that the slot is still `FREE`.
    Unguarded,
}

impl Prepare {
    /// One preparation attempt of term count `value` in `slot`.
    fn run(self, buffer: &Buffer, slot: usize, value: u32) {
        let ready = descriptor(value, SlotState::Ready);
        match self {
            Prepare::Production => {
                let _ = prepare_slot(
                    buffer.descriptor(slot),
                    buffer.tail(slot),
                    never_used(),
                    ready,
                );
            }
            Prepare::ReadyFirst => {
                // Guarded like the production helper; only the order of
                // the two stores differs.
                if buffer.descriptor(slot).load(Ordering::Acquire) == never_used().encode() {
                    publish(buffer.descriptor(slot), ready);
                    buffer.tail(slot).store(tail_of(value), Ordering::Relaxed);
                }
            }
            Prepare::Unguarded => {
                buffer.tail(slot).store(tail_of(value), Ordering::Relaxed);
                publish(buffer.descriptor(slot), ready);
            }
        }
    }
}

fn prepare_model(prepare: Prepare) {
    loom::model(move || {
        // Term 0 is active and full in slot 0; slot 1 is free.
        let buffer = Arc::new(Buffer::new(
            &[descriptor(0, SlotState::Active), never_used()],
            &[tail_of(0), STALE],
        ));
        let conductor = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || {
                // Two duty cycles: the second finds the slot taken.
                for _ in 0..2 {
                    prepare.run(&buffer, 1, 1);
                }
            })
        };
        let producer = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || {
                // Rotate into term 1 and take a loan there, retrying while
                // the conductor is behind.
                loop {
                    if buffer.rotate(1, 1) != Rotation::NotReady
                        && buffer.loan(1, 1) == LoanOutcome::Granted
                    {
                        break;
                    }
                    thread::yield_now();
                }
                let tail = buffer.tail(1);
                assert_eq!(
                    tail.load(Ordering::Acquire),
                    tail_of(1),
                    "a producer read an uninitialised tail"
                );
                let old = tail.fetch_add(SIZE, Ordering::AcqRel);
                assert_eq!(
                    old,
                    tail_of(1),
                    "a producer reserved in an uninitialised tail"
                );
                buffer.release();
            })
        };
        conductor.join().unwrap();
        producer.join().unwrap();
        assert_eq!(
            buffer.tail(1).load(Ordering::Acquire),
            tail_of(1) + SIZE,
            "a reservation was lost to a second initialisation"
        );
        assert_eq!(buffer.active.load(Ordering::Acquire), 1);
    });
}

#[test]
fn the_conductor_initialises_a_tail_once_before_ready() {
    prepare_model(Prepare::Production);
}

#[test]
#[should_panic(expected = "uninitialised tail")]
fn control_ready_before_the_tail_fails() {
    prepare_model(Prepare::ReadyFirst);
}

#[test]
#[should_panic(expected = "a reservation was lost to a second initialisation")]
fn control_unguarded_preparation_fails() {
    prepare_model(Prepare::Unguarded);
}

// The owner's pause between activation and count advance, pinned.

loom::lazy_static! {
    /// Set by the owner at its pause point.
    static ref PAUSED: AtomicU64 = AtomicU64::new(0);
    /// Set by the producer to let the owner resume.
    static ref RESUME: AtomicU64 = AtomicU64::new(0);
}

/// The owner's pause: reports it, then waits until the producer lets it
/// resume.
fn hold(_: PausePoint) {
    PAUSED.store(1, Ordering::Release);
    while RESUME.load(Ordering::Acquire) == 0 {
        thread::yield_now();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// The production `rotate_to`, paused at `RotationActivated`.
    Production,
    /// Activation, the same pause, then the count advanced by a plain
    /// store.
    PlainStore,
}

fn owner_pause_model(owner: Owner) {
    loom::model(move || {
        // Slot 0 holds the active term 0, slot 1 the prepared term 1, slot
        // 2 is free for term 2.
        let buffer = Arc::new(Buffer::new(
            &[
                descriptor(0, SlotState::Active),
                descriptor(1, SlotState::Ready),
                never_used(),
            ],
            &[tail_of(0), tail_of(1), STALE],
        ));
        // Armed in every execution; only this test's OS thread sees it.
        // The control pauses by itself, so that the producer's own
        // activation of term 2 never takes the hook.
        if owner == Owner::Production {
            test_pause::arm(PausePoint::RotationActivated, hold);
        }
        let owner_thread = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || match owner {
                Owner::Production => Some(buffer.rotate(1, 1)),
                Owner::PlainStore => {
                    let _ =
                        activate(buffer.descriptor(1), descriptor(1, SlotState::Ready)).unwrap();
                    hold(PausePoint::RotationActivated);
                    buffer.active.store(1, Ordering::Release);
                    None
                }
            })
        };
        let conductor = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || {
                let _ = prepare_slot(
                    buffer.descriptor(2),
                    buffer.tail(2),
                    never_used(),
                    descriptor(2, SlotState::Ready),
                )
                .unwrap();
            })
        };
        let producer = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || {
                while PAUSED.load(Ordering::Acquire) == 0 {
                    thread::yield_now();
                }
                // The pinned state: term 1 active, the count still at 0.
                assert_eq!(
                    buffer.descriptor(1).load(Ordering::Acquire),
                    descriptor(1, SlotState::Active).encode(),
                    "the owner paused before activating"
                );
                assert_eq!(
                    buffer.active.load(Ordering::Acquire),
                    0,
                    "the owner paused after advancing the count"
                );
                // A producer uses term 1 at once.
                assert_eq!(buffer.loan(1, 1), LoanOutcome::Granted);
                let old = buffer.tail(1).fetch_add(SIZE, Ordering::AcqRel);
                assert_eq!(old, tail_of(1), "a reservation in term 1 was lost");
                buffer.release();
                // It completes the half-done rotation, then rotates on.
                assert_eq!(
                    buffer.rotate(1, 1),
                    Rotation::Completed,
                    "a half-done rotation was not completed"
                );
                while buffer.rotate(2, 2) == Rotation::NotReady {
                    thread::yield_now();
                }
                assert_eq!(buffer.loan(2, 2), LoanOutcome::Granted);
                assert_eq!(buffer.tail(2).load(Ordering::Acquire), tail_of(2));
                buffer.release();
                RESUME.store(1, Ordering::Release);
            })
        };
        let outcome = owner_thread.join().unwrap();
        conductor.join().unwrap();
        producer.join().unwrap();
        if let Some(outcome) = outcome {
            assert_eq!(outcome, Rotation::Superseded);
        }
        assert_eq!(
            buffer.active.load(Ordering::Acquire),
            2,
            "active count moved back"
        );
        assert_eq!(
            buffer.descriptor(2).load(Ordering::Acquire),
            descriptor(2, SlotState::Active).encode()
        );
    });
}

#[test]
fn an_owner_paused_after_activation_is_completed_and_superseded() {
    owner_pause_model(Owner::Production);
}

#[test]
#[should_panic(expected = "active count moved back")]
fn control_owner_advancing_by_plain_store_fails() {
    owner_pause_model(Owner::PlainStore);
}

// A producer paused before its fetch_add across three rotations.

fn paused_producer_model(scan_loans: bool) {
    loom::model(move || {
        // Four slots: term 0 active in slot 0, term 1 prepared in slot 1,
        // slots 2 and 3 free for terms 2 and 3. Term 4 can only reuse
        // slot 0.
        let buffer = Arc::new(Buffer::new(
            &[
                descriptor(0, SlotState::Active),
                descriptor(1, SlotState::Ready),
                never_used(),
                never_used(),
            ],
            &[tail_of(0), tail_of(1), STALE, STALE],
        ));
        // The producer's standing write loan on term 0.
        assert_eq!(buffer.loan(0, 0), LoanOutcome::Granted);
        let conductor = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || {
                for value in [2, 3] {
                    let slot = value as usize;
                    let _ = prepare_slot(
                        buffer.descriptor(slot),
                        buffer.tail(slot),
                        never_used(),
                        descriptor(value, SlotState::Ready),
                    )
                    .unwrap();
                }
                // Once term 0 is below the active term, reclaim its slot
                // and reassign it to term 4, unless a loan pins it.
                if buffer.active.load(Ordering::Acquire) < 1 {
                    return;
                }
                let slot = SlotIndex::try_new(0).unwrap();
                let reclaiming =
                    begin_reclaim(buffer.descriptor(0), descriptor(0, SlotState::Active)).unwrap();
                if scan_loans && loan_held(&buffer.loans, slot, reclaiming).unwrap() {
                    // Quarantined: the next duty cycle rescans.
                    return;
                }
                let cleaning = begin_cleaning(buffer.descriptor(0), reclaiming).unwrap();
                let free = cleaning.with_state(SlotState::Free);
                publish(buffer.descriptor(0), free);
                let _ = prepare_slot(
                    buffer.descriptor(0),
                    buffer.tail(0),
                    free,
                    descriptor(4, SlotState::Ready),
                )
                .unwrap();
            })
        };
        // Other producers fill terms 1, 2 and 3 and rotate: one attempt
        // per term, in order, stopping where the conductor is behind.
        let rotator = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || {
                for next in 1..=3 {
                    if buffer.rotate(next as usize, next) == Rotation::NotReady {
                        break;
                    }
                }
            })
        };
        let producer = {
            let buffer = Arc::clone(&buffer);
            thread::spawn(move || {
                // Paused before its fetch_add until the rotator is done:
                // in the executions that matter, three rotations passed.
                rotator.join().unwrap();
                let rotations = buffer.active.load(Ordering::Acquire);
                let old = buffer.tail(0).fetch_add(SIZE, Ordering::AcqRel);
                buffer.release();
                (rotations, old)
            })
        };
        let (rotations, old) = producer.join().unwrap();
        conductor.join().unwrap();
        assert!(rotations <= 3);
        // The control checks only the executions where all three
        // rotations passed, so it must fail in one of those.
        if scan_loans || rotations == 3 {
            assert_eq!(
                old >> 32,
                u64::from(term(0).get()),
                "a paused producer reserved in a later term after {rotations} rotations"
            );
        }
    });
}
#[test]
fn a_producer_paused_across_three_rotations_reserves_in_its_own_term() {
    paused_producer_model(true);
}

#[test]
#[should_panic(expected = "a paused producer reserved in a later term after 3 rotations")]
fn control_three_rotations_reassignment_without_the_loan_scan_fails() {
    paused_producer_model(false);
}
