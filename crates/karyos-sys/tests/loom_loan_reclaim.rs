// SPDX-License-Identifier: Apache-2.0

//! Loom model of the phase 1 contract "Loan versus reclaim" (SPEC.md §13):
//! a participant takes a loan while the driver reclaims, cleans and reassigns
//! the slot, in every interleaving. No loan may be granted once the slot is
//! `RECLAIMING`, `CLEANING`, `FREE` or reassigned, and cleaning never starts
//! while a loan for the term remains.
//!
//! Term bytes are modelled as a plain value in a Loom `UnsafeCell`, accessed
//! non-atomically like real payload bytes. Loom reports any read and write of
//! it that are not ordered by happens-before, so the models check the
//! synchronization the protocol provides, not only the values observed.
//!
//! Run with `RUSTFLAGS="--cfg loom" cargo test -p karyos-sys --test
//! loom_loan_reclaim --release`.

#![cfg(loom)]

use karyos_sys::loan::{
    LoanOutcome, LoanTarget, activate, begin_cleaning, begin_reclaim, loan_held,
    participant_quiescent, publish, release_loan, revoke, take_loan,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

/// Payload value written while the slot holds the loaned term.
const TERM_BYTES: u64 = 7;
/// Value the cleaner zeroes the slot to.
const CLEANED_BYTES: u64 = 0;
/// Value written after the slot is reassigned to a later term.
const REASSIGNED_BYTES: u64 = 9;

struct Slot {
    descriptor: AtomicU64,
    loan_words: [AtomicU64; 1],
    revoked: AtomicU64,
    bytes: UnsafeCell<u64>,
}

impl Slot {
    /// A plain read of the term bytes.
    fn read_bytes(&self) -> u64 {
        self.bytes.with(|bytes| {
            // SAFETY: the pointer comes from a live `UnsafeCell` owned by
            // `self`; Loom checks that no write races with this read.
            unsafe { *bytes }
        })
    }

    /// A plain write of the term bytes, as cleaning or a new term does.
    fn write_bytes(&self, value: u64) {
        self.bytes.with_mut(|bytes| {
            // SAFETY: the pointer comes from a live `UnsafeCell` owned by
            // `self`; Loom checks that no other access races with this write.
            unsafe { *bytes = value }
        });
    }
}

fn fixture() -> (Arc<Slot>, LoanTarget, Descriptor) {
    let slot = SlotIndex::try_new(2).unwrap();
    let generation = Generation::try_new(1).unwrap();
    let initial = TermId::new(u32::MAX);
    let count = TermCount::try_new(1).unwrap();
    let target = LoanTarget::new(slot, generation, initial, count);
    let active = Descriptor::new(target.term_id(), generation, SlotState::Active);
    let shared = Arc::new(Slot {
        descriptor: AtomicU64::new(active.encode()),
        loan_words: [AtomicU64::new(0)],
        revoked: AtomicU64::new(0),
        bytes: UnsafeCell::new(TERM_BYTES),
    });
    (shared, target, active)
}

/// The participant: if its loan is granted, the term's bytes must stay
/// unchanged until it releases the loan.
fn participant(shared: &Slot, target: LoanTarget) {
    let [word] = &shared.loan_words;
    match take_loan(word, &shared.revoked, &shared.descriptor, target).unwrap() {
        LoanOutcome::Granted => {
            assert_eq!(shared.read_bytes(), TERM_BYTES);
            assert_eq!(shared.read_bytes(), TERM_BYTES);
            release_loan(word);
        }
        LoanOutcome::Overrun | LoanOutcome::Retry | LoanOutcome::Revoked => {
            assert_eq!(word.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn loan_versus_reclaim_and_cleaning() {
    loom::model(|| {
        let (shared, target, active) = fixture();
        let reader = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || participant(&shared, target))
        };

        let reclaiming = begin_reclaim(&shared.descriptor, active).unwrap();
        if !loan_held(&shared.loan_words, target.slot(), reclaiming).unwrap() {
            let cleaning = begin_cleaning(&shared.descriptor, reclaiming).unwrap();
            shared.write_bytes(CLEANED_BYTES);
            publish(&shared.descriptor, cleaning.with_state(SlotState::Free));
        }

        reader.join().unwrap();
    });
}

#[test]
fn loan_versus_reassignment() {
    loom::model(|| {
        let (shared, target, active) = fixture();
        let reader = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || participant(&shared, target))
        };

        // The driver reclaims, cleans and reassigns the slot to a later term,
        // which it then activates and writes.
        let reclaiming = begin_reclaim(&shared.descriptor, active).unwrap();
        if !loan_held(&shared.loan_words, target.slot(), reclaiming).unwrap() {
            let cleaning = begin_cleaning(&shared.descriptor, reclaiming).unwrap();
            shared.write_bytes(CLEANED_BYTES);
            publish(&shared.descriptor, cleaning.with_state(SlotState::Free));

            let later =
                TermId::new(target.term_id().get()).advanced_by(TermCount::try_new(3).unwrap());
            let ready = Descriptor::new(later, active.generation(), SlotState::Ready);
            publish(&shared.descriptor, ready);
            activate(&shared.descriptor, ready).unwrap();
            shared.write_bytes(REASSIGNED_BYTES);
        }

        reader.join().unwrap();
    });
}

#[test]
fn quarantined_slot_is_cleaned_after_release() {
    loom::model(|| {
        let (shared, target, active) = fixture();
        let reader = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || participant(&shared, target))
        };

        let reclaiming = begin_reclaim(&shared.descriptor, active).unwrap();
        // Rescan concurrently until the quarantine ends; cleaning must then be
        // ordered after the participant's accesses by the protocol alone,
        // not by joining its thread.
        while loan_held(&shared.loan_words, target.slot(), reclaiming).unwrap() {
            thread::yield_now();
        }
        let cleaning = begin_cleaning(&shared.descriptor, reclaiming).unwrap();
        shared.write_bytes(CLEANED_BYTES);
        publish(&shared.descriptor, cleaning.with_state(SlotState::Free));
        reader.join().unwrap();
    });
}

/// Contract "Required participant revocation" (SPEC.md §13): the reader may
/// pause just before storing its loan word while the driver revokes it. Once
/// the driver sees the participant quiescent it withdraws the participant's
/// bound, after which the publisher may overwrite the term; the reader's
/// acquisition must then fail.
#[test]
fn revocation_versus_paused_acquisition() {
    loom::model(|| {
        let (shared, target, _active) = fixture();
        let reader = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || participant(&shared, target))
        };

        if revoke(&shared.revoked, &shared.loan_words).unwrap() {
            // Bound withdrawn: the publisher laps the reader.
            shared.write_bytes(CLEANED_BYTES);
        }

        reader.join().unwrap();
        // The registration is kept: after the reader is done, a rescan must
        // find it quiescent and its flag still set.
        assert!(participant_quiescent(&shared.loan_words).unwrap());
        assert_ne!(shared.revoked.load(Ordering::SeqCst), 0);
    });
}
