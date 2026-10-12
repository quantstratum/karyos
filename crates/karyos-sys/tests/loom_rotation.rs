// SPDX-License-Identifier: Apache-2.0

//! Loom models of rotation by publishers (`quantstratum-docs: karyos/design/concurrent-publication.md`,
//! batch b; SPEC.md §4 rotation and superseded rotations), over the
//! production helpers of `karyos_sys::loan`:
//!
//! - a helper whose rotation attempt to term 1 runs at any point while
//!   another rotator completes it, two more rotations pass and term 1's
//!   slot is reclaimed and reassigned to term 4: the helper never moves the
//!   active count back or rewrites the reassigned descriptor;
//! - a producer paused before its `fetch_add` while three rotations pass:
//!   its write loan keeps its slot from being reassigned, so its reservation
//!   always lands in its own term.
//!
//! Negative controls must fail: a helper that rotates by plain stores, and
//! a conductor that reassigns the producer's slot without the loan scan.
//!
//! Exploration: default Loom bounds, two threads per model.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::loan::{
    LoanOutcome, LoanTarget, begin_cleaning, begin_reclaim, loan_held, publish, release_loan,
    rotate_to, take_loan,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::sync::Arc;
use loom::thread;

fn generation() -> Generation {
    Generation::try_new(1).unwrap()
}

fn term(count: u32) -> TermId {
    TermId::new(7).advanced_by(TermCount::try_new(count).unwrap())
}

fn descriptor(count: u32, state: SlotState) -> Descriptor {
    Descriptor::new(term(count), generation(), state)
}

fn one() -> TermCount {
    TermCount::try_new(1).unwrap()
}

fn helper_model(by_stores: bool) {
    loom::model(move || {
        let slot = Arc::new(AtomicU64::new(descriptor(1, SlotState::Ready).encode()));
        let active = Arc::new(AtomicU64::new(0));
        let helper = {
            let (slot, active) = (Arc::clone(&slot), Arc::clone(&active));
            thread::spawn(move || {
                if by_stores {
                    slot.store(descriptor(1, SlotState::Active).encode(), Ordering::Release);
                    active.store(1, Ordering::Release);
                } else {
                    let _ = rotate_to(&slot, &active, term(1), generation(), one()).unwrap();
                }
            })
        };
        let history = {
            let (slot, active) = (Arc::clone(&slot), Arc::clone(&active));
            thread::spawn(move || {
                let _ = rotate_to(&slot, &active, term(1), generation(), one()).unwrap();
                // Two more rotations through other slots.
                assert!(
                    active
                        .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                );
                assert!(
                    active
                        .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                );
                // Term 1's slot is reclaimed, cleaned and reassigned to term 4.
                let reclaiming = begin_reclaim(&slot, descriptor(1, SlotState::Active)).unwrap();
                let cleaning = begin_cleaning(&slot, reclaiming).unwrap();
                publish(&slot, cleaning.with_state(SlotState::Free));
                publish(&slot, descriptor(4, SlotState::Ready));
            })
        };
        helper.join().unwrap();
        history.join().unwrap();
        assert_eq!(active.load(Ordering::Acquire), 3, "active count moved back");
        assert_eq!(
            slot.load(Ordering::Acquire),
            descriptor(4, SlotState::Ready).encode(),
            "reassigned slot rewritten"
        );
    });
}

#[test]
fn a_paused_rotation_helper_is_superseded() {
    helper_model(false);
}

#[test]
#[should_panic(expected = "active count moved back")]
fn control_rotation_by_plain_stores_fails() {
    helper_model(true);
}

fn producer_model(scan_loans: bool) {
    loom::model(move || {
        let slot_index = SlotIndex::try_new(0).unwrap();
        let target = LoanTarget::new(slot_index, generation(), TermId::new(7), TermCount::ZERO);
        let slot = Arc::new(AtomicU64::new(descriptor(0, SlotState::Active).encode()));
        let tail = Arc::new(AtomicU64::new(u64::from(term(0).get()) << 32));
        let loans = Arc::new([AtomicU64::new(0)]);
        let revoked = Arc::new(AtomicU64::new(0));
        // The producer holds its standing write loan on term 0.
        assert_eq!(
            take_loan(&loans[0], &revoked, &slot, target).unwrap(),
            LoanOutcome::Granted
        );
        let producer = {
            let (tail, loans) = (Arc::clone(&tail), Arc::clone(&loans));
            thread::spawn(move || {
                // Paused before its fetch_add for any number of rotations.
                let old = tail.fetch_add(32, Ordering::AcqRel);
                release_loan(&loans[0]);
                old
            })
        };
        let conductor = {
            let (slot, tail, loans) = (Arc::clone(&slot), Arc::clone(&tail), Arc::clone(&loans));
            thread::spawn(move || {
                // Term 0 is full and three rotations have passed; the
                // conductor tries to reclaim and reassign its slot.
                let reclaiming = begin_reclaim(&slot, descriptor(0, SlotState::Active)).unwrap();
                let held = scan_loans && loan_held(&*loans, slot_index, reclaiming).unwrap();
                if !held {
                    let cleaning = begin_cleaning(&slot, reclaiming).unwrap();
                    tail.store(u64::from(term(3).get()) << 32, Ordering::Relaxed);
                    publish(&slot, cleaning.with_state(SlotState::Free));
                    publish(&slot, descriptor(3, SlotState::Ready));
                }
            })
        };
        let old = producer.join().unwrap();
        conductor.join().unwrap();
        assert_eq!(
            old >> 32,
            u64::from(term(0).get()),
            "a paused producer reserved in a later term"
        );
    });
}

#[test]
fn a_paused_producer_reserves_only_in_its_own_term() {
    producer_model(true);
}

#[test]
#[should_panic(expected = "a paused producer reserved in a later term")]
fn control_reassignment_without_the_loan_scan_fails() {
    producer_model(false);
}
