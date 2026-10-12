// SPDX-License-Identifier: Apache-2.0

//! Loom model of slot reuse composed from the production helpers: a writer
//! publishes term A in a slot under its write loan and releases it; a reader
//! loans term A and copies the payload; the conductor reclaims, cleans
//! (atomic word 0, plain payload), frees, prepares and activates term C in
//! the same slot, then writes it as the new writer. Loom checks that every
//! plain access to the reused payload is ordered by the loan protocol.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::loan::{
    LoanOutcome, LoanTarget, activate, begin_cleaning, begin_reclaim, loan_held, publish,
    release_loan, take_loan,
};
use karyos_sys::publication::{clear_word, observe_block, publish_block};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::AtomicU64;
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

const PAYLOAD_A: u64 = 0xAAAA;
const PAYLOAD_C: u64 = 0xCCCC;

struct Slot {
    descriptor: AtomicU64,
    word0: AtomicU64,
    payload: UnsafeCell<u64>,
    /// Loan words: the writer's cell and the reader's cell.
    loans: [AtomicU64; 2],
    revoked: [AtomicU64; 2],
}

impl Slot {
    fn write_payload(&self, value: u64) {
        self.payload.with_mut(|payload| {
            // SAFETY: the pointer comes from a live `UnsafeCell`; Loom checks
            // that no other access races with this write.
            unsafe { *payload = value }
        });
    }

    fn read_payload(&self) -> u64 {
        self.payload.with(|payload| {
            // SAFETY: as above, for a read.
            unsafe { *payload }
        })
    }
}

fn target(count: u32) -> LoanTarget {
    LoanTarget::new(
        SlotIndex::try_new(0).unwrap(),
        Generation::default(),
        TermId::new(u32::MAX),
        TermCount::try_new(count).unwrap(),
    )
}

fn descriptor(count: u32, state: SlotState) -> Descriptor {
    Descriptor::new(target(count).term_id(), Generation::default(), state)
}

fn data_word() -> Word0 {
    Word0::new(
        40,
        Flags::new(true, true, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

#[test]
fn reuse_after_reclaim_is_ordered_by_loans() {
    loom::model(|| {
        let slot = Arc::new(Slot {
            descriptor: AtomicU64::new(descriptor(0, SlotState::Active).encode()),
            word0: AtomicU64::new(0),
            payload: UnsafeCell::new(0),
            loans: [AtomicU64::new(0), AtomicU64::new(0)],
            revoked: [AtomicU64::new(0), AtomicU64::new(0)],
        });
        // The writer's standing loan on term A is taken before it runs.
        assert_eq!(
            take_loan(
                &slot.loans[0],
                &slot.revoked[0],
                &slot.descriptor,
                target(0)
            ),
            Ok(LoanOutcome::Granted)
        );

        let writer = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || {
                slot.write_payload(PAYLOAD_A);
                publish_block(&slot.word0, data_word());
                release_loan(&slot.loans[0]);
            })
        };
        let reader = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || {
                let outcome = take_loan(
                    &slot.loans[1],
                    &slot.revoked[1],
                    &slot.descriptor,
                    target(0),
                )
                .unwrap();
                if outcome == LoanOutcome::Granted {
                    if observe_block(&slot.word0) != 0 {
                        assert_eq!(slot.read_payload(), PAYLOAD_A);
                    }
                    release_loan(&slot.loans[1]);
                }
            })
        };

        // Conductor: reclaim A if no loan remains, clean, free, prepare and
        // activate C in the same slot, then write it under a new write loan.
        let active = descriptor(0, SlotState::Active);
        let reclaiming = begin_reclaim(&slot.descriptor, active).unwrap();
        let index = SlotIndex::try_new(0).unwrap();
        if !loan_held(&slot.loans, index, reclaiming).unwrap() {
            let cleaning = begin_cleaning(&slot.descriptor, reclaiming).unwrap();
            clear_word(&slot.word0);
            slot.write_payload(0);
            publish(&slot.descriptor, cleaning.with_state(SlotState::Free));
            let ready = descriptor(3, SlotState::Ready);
            publish(&slot.descriptor, ready);
            activate(&slot.descriptor, ready).unwrap();
            let granted = take_loan(
                &slot.loans[0],
                &slot.revoked[0],
                &slot.descriptor,
                target(3),
            )
            .unwrap();
            assert_eq!(granted, LoanOutcome::Granted);
            slot.write_payload(PAYLOAD_C);
            publish_block(&slot.word0, data_word());
            release_loan(&slot.loans[0]);
        }

        writer.join().unwrap();
        reader.join().unwrap();
    });
}

/// The conductor cleans a released slot and hands it to term C through
/// `FREE`, `READY` and `ACTIVE`; a different writer thread and a reader
/// thread use term C. No join or channel orders them: only the descriptor
/// publications and the loans do.
#[test]
fn handoff_of_a_cleaned_slot_to_another_writer() {
    loom::model(|| {
        let slot = Arc::new(Slot {
            descriptor: AtomicU64::new(descriptor(0, SlotState::Active).encode()),
            word0: AtomicU64::new(data_word().pack()),
            payload: UnsafeCell::new(PAYLOAD_A),
            loans: [AtomicU64::new(0), AtomicU64::new(0)],
            revoked: [AtomicU64::new(0), AtomicU64::new(0)],
        });

        let writer = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || {
                let outcome = take_loan(
                    &slot.loans[0],
                    &slot.revoked[0],
                    &slot.descriptor,
                    target(3),
                )
                .unwrap();
                if outcome == LoanOutcome::Granted {
                    slot.write_payload(PAYLOAD_C);
                    publish_block(&slot.word0, data_word());
                    release_loan(&slot.loans[0]);
                }
            })
        };
        let reader = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || {
                let outcome = take_loan(
                    &slot.loans[1],
                    &slot.revoked[1],
                    &slot.descriptor,
                    target(3),
                )
                .unwrap();
                if outcome == LoanOutcome::Granted {
                    if observe_block(&slot.word0) != 0 {
                        assert_eq!(slot.read_payload(), PAYLOAD_C);
                    }
                    release_loan(&slot.loans[1]);
                }
            })
        };

        // Conductor: term A has no loans; reclaim, clean, free, prepare C.
        let reclaiming = begin_reclaim(&slot.descriptor, descriptor(0, SlotState::Active)).unwrap();
        let index = SlotIndex::try_new(0).unwrap();
        assert!(!loan_held(&slot.loans, index, reclaiming).unwrap());
        let cleaning = begin_cleaning(&slot.descriptor, reclaiming).unwrap();
        clear_word(&slot.word0);
        slot.write_payload(0);
        publish(&slot.descriptor, cleaning.with_state(SlotState::Free));
        let ready = descriptor(3, SlotState::Ready);
        publish(&slot.descriptor, ready);
        activate(&slot.descriptor, ready).unwrap();

        writer.join().unwrap();
        reader.join().unwrap();
    });
}
