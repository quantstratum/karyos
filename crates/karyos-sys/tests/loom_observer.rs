// SPDX-License-Identifier: Apache-2.0

//! Loom model of the observer role (`quantstratum-docs: karyos/design/observer-role.md`,
//! SPEC.md §13 "Observer race freedom") over the production loan helpers.
//!
//! An observer copies a two-word frame of term `t` under its loan, and may
//! pause between the words. Meanwhile the publisher has moved on, so `t`
//! lies below the retention floor and the driver reclaims its slot: it
//! moves the slot to `RECLAIMING`, scans the loan words, and cleans and
//! reuses the slot only when no loan remains. Checks: the observer copies
//! only under a granted loan; every word it copies is the committed value;
//! while its loan is held the slot stays `RECLAIMING` and is never cleaned;
//! once it releases, the slot is cleaned and reused.
//!
//! The negative control releases the loan before the second word is
//! copied: the model then finds the slot cleaned under the copy, which
//! Loom reports as a data race on the term bytes.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::loan::{
    LoanOutcome, LoanTarget, begin_cleaning, begin_reclaim, loan_held, publish, release_loan,
    take_loan,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

/// The committed frame's two words.
const COMMITTED: [u64; 2] = [7, 8];

struct Slot {
    descriptor: AtomicU64,
    loan_words: [AtomicU64; 1],
    revoked: AtomicU64,
    bytes: [UnsafeCell<u64>; 2],
}

impl Slot {
    fn read(&self, word: usize) -> u64 {
        self.bytes[word].with(|bytes| {
            // SAFETY: the pointer comes from a live `UnsafeCell` owned by
            // `self`; Loom checks that no write races with this read.
            unsafe { *bytes }
        })
    }

    fn write(&self, word: usize, value: u64) {
        self.bytes[word].with_mut(|bytes| {
            // SAFETY: as in `read`; Loom checks that no other access races
            // with this write.
            unsafe { *bytes = value }
        });
    }

    fn state(&self) -> SlotState {
        Descriptor::decode(self.descriptor.load(Ordering::SeqCst))
            .unwrap()
            .state()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Release {
    AfterTheCopy,
    BeforeTheSecondWord,
}

fn model(release: Release) {
    loom::model(move || {
        let slot = SlotIndex::try_new(0).unwrap();
        let generation = Generation::try_new(1).unwrap();
        let target = LoanTarget::new(slot, generation, TermId::new(3), TermCount::ZERO);
        let active = Descriptor::new(target.term_id(), generation, SlotState::Active);
        let shared = Arc::new(Slot {
            descriptor: AtomicU64::new(active.encode()),
            loan_words: [AtomicU64::new(0)],
            revoked: AtomicU64::new(0),
            bytes: [UnsafeCell::new(COMMITTED[0]), UnsafeCell::new(COMMITTED[1])],
        });
        let observer = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let [word] = &shared.loan_words;
                if take_loan(word, &shared.revoked, &shared.descriptor, target).unwrap()
                    != LoanOutcome::Granted
                {
                    // No loan, no copy.
                    return;
                }
                let first = shared.read(0);
                if release == Release::BeforeTheSecondWord {
                    release_loan(word);
                }
                // The observer may pause here, inside its copy.
                let second = shared.read(1);
                if release == Release::AfterTheCopy {
                    release_loan(word);
                }
                assert_eq!([first, second], COMMITTED);
            })
        };
        // The driver: term `t` is below the floor.
        let reclaiming = begin_reclaim(&shared.descriptor, active).unwrap();
        let mut cleaned = false;
        if !loan_held(&shared.loan_words, slot, reclaiming).unwrap() {
            let cleaning = begin_cleaning(&shared.descriptor, reclaiming).unwrap();
            shared.write(0, 0);
            shared.write(1, 0);
            publish(&shared.descriptor, cleaning.with_state(SlotState::Free));
            cleaned = true;
        } else {
            // Quarantined while the loan is held.
            assert_eq!(shared.state(), SlotState::Reclaiming);
        }
        observer.join().unwrap();
        if !cleaned {
            // Released: the rescan finds no loan and cleans.
            assert!(!loan_held(&shared.loan_words, slot, reclaiming).unwrap());
            let cleaning = begin_cleaning(&shared.descriptor, reclaiming).unwrap();
            shared.write(0, 0);
            shared.write(1, 0);
            publish(&shared.descriptor, cleaning.with_state(SlotState::Free));
        }
        assert_eq!(shared.state(), SlotState::Free);
    });
}

#[test]
fn observer_copies_while_publisher_writes_and_driver_reclaims() {
    model(Release::AfterTheCopy);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_observer_releases_before_the_copy_ends_fails() {
    model(Release::BeforeTheSecondWord);
}
