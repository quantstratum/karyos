// SPDX-License-Identifier: Apache-2.0

//! Loom model of the phase 1 contract "Loan versus reclaim" (SPEC.md §13):
//! a participant takes a loan while the driver reclaims, cleans and reassigns
//! the slot, in every interleaving. No loan may be granted once the slot is
//! `RECLAIMING`, `CLEANING`, `FREE` or reassigned, and cleaning never starts
//! while a loan for the term remains.
//!
//! Run with `RUSTFLAGS="--cfg loom" cargo test -p karyos-sys --test
//! loom_loan_reclaim --release`.

#![cfg(loom)]

use karyos_sys::loan::{
    LoanOutcome, LoanTarget, activate, begin_cleaning, begin_reclaim, loan_held, publish,
    release_loan, take_loan,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
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
    bytes: AtomicU64,
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
        bytes: AtomicU64::new(TERM_BYTES),
    });
    (shared, target, active)
}

/// The participant: if its loan is granted, the term's bytes must stay
/// unchanged until it releases the loan.
fn participant(shared: &Slot, target: LoanTarget) {
    let [word] = &shared.loan_words;
    match take_loan(word, &shared.descriptor, target).unwrap() {
        LoanOutcome::Granted => {
            assert_eq!(shared.bytes.load(Ordering::Relaxed), TERM_BYTES);
            assert_eq!(shared.bytes.load(Ordering::Relaxed), TERM_BYTES);
            release_loan(word);
        }
        LoanOutcome::Overrun | LoanOutcome::Retry => {
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
            shared.bytes.store(CLEANED_BYTES, Ordering::Relaxed);
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
            shared.bytes.store(CLEANED_BYTES, Ordering::Relaxed);
            publish(&shared.descriptor, cleaning.with_state(SlotState::Free));

            let later =
                TermId::new(target.term_id().get()).advanced_by(TermCount::try_new(3).unwrap());
            let ready = Descriptor::new(later, active.generation(), SlotState::Ready);
            publish(&shared.descriptor, ready);
            activate(&shared.descriptor, ready).unwrap();
            shared.bytes.store(REASSIGNED_BYTES, Ordering::Relaxed);
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
        // Rescan after the participant finished: the quarantine must end.
        reader.join().unwrap();
        assert!(!loan_held(&shared.loan_words, target.slot(), reclaiming).unwrap());
        let cleaning = begin_cleaning(&shared.descriptor, reclaiming).unwrap();
        shared.bytes.store(CLEANED_BYTES, Ordering::Relaxed);
        publish(&shared.descriptor, cleaning.with_state(SlotState::Free));
    });
}
