// SPDX-License-Identifier: Apache-2.0

//! Loom models of the sender read capability (`quantstratum-docs:
//! karyos/design/network-sessions-sender.md` S2 2.7; driver network agents
//! phase 5a) over the production helpers of `karyos_sys::loan` and
//! `karyos_sys::publication`, composed in `SenderRead::read_committed`'s
//! order: the floor (step 1), the loan on the exact term (step 3), the
//! block's word 0 with Acquire and its bytes under the loan (step 4), and
//! the release (step 6).
//!
//! - **loan against reclamation**: the conductor reclaims the term while
//!   the sender reads it; it scans the loan word after moving the slot to
//!   `RECLAIMING` and reuses the slot only when no loan holds it. Either the
//!   sender's loan is refused or the conductor keeps the slot. Control: a
//!   sender that reads without its loan races the reuse.
//! - **revocation**: the conductor revokes the sender's loan bank while the
//!   sender pauses between the floor check and its loan; either the sender
//!   gets `Revoked` or the conductor sees the loan word held, never both
//!   missed. Control: a sender that loads the revoked flag before it
//!   stores its loan word misses the revocation.
//! - **aborted claim**: a concurrent claim aborted by its deadline while
//!   its writer still writes inside the extent; the sender reads only the
//!   ABORTED word 0, never the extent. Control: reading the extent races
//!   the writer.
//!
//! Payload bytes are plain values in Loom `UnsafeCell`s, where Loom reports
//! any read and write not ordered by happens-before.
//!
//! Limits: `log_buffer` is not built under Loom, so these models compose
//! the production helpers in `SenderRead`'s order rather than run it.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::loan::{
    LoanOutcome, LoanTarget, REVOKED, activate, begin_cleaning, begin_reclaim, loan_held,
    participant_quiescent, publish, release_loan, revoke, take_loan,
};
use karyos_sys::publication::{
    clear_word, deadline_abort, mark_block, observe_block, publish_block,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

/// The payload of term A (count 0) and of the later term C (count 2).
const A: u64 = 0xA1;
const C: u64 = 0xC1;
/// The reserved extent of the block.
const FRAME: u32 = 64;

/// A plain payload value.
struct Payload(UnsafeCell<u64>);

impl Payload {
    fn new(value: u64) -> Self {
        Self(UnsafeCell::new(value))
    }

    fn read(&self) -> u64 {
        self.0.with(|value| {
            // SAFETY: the pointer comes from a live `UnsafeCell`; Loom checks
            // that no write races with this read.
            unsafe { *value }
        })
    }

    fn write(&self, value: u64) {
        self.0.with_mut(|cell| {
            // SAFETY: as in `read`, for a write.
            unsafe { *cell = value }
        });
    }
}

/// One slot holding one committed block, the sender's loan bank (one word,
/// `L_send = 1`) and its revoked flag.
struct Slot {
    descriptor: AtomicU64,
    loan: [AtomicU64; 1],
    revoked: AtomicU64,
    floor: AtomicU64,
    word0: AtomicU64,
    payload: Payload,
}

fn block() -> Word0 {
    Word0::new(
        FRAME as i32 - 7,
        Flags::new(true, true, false, false, Lane::ZERO),
        FrameType::Data,
    )
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

/// Term A active in the slot with its committed block.
fn committed_slot() -> Arc<Slot> {
    Arc::new(Slot {
        descriptor: AtomicU64::new(descriptor(0, SlotState::Active).encode()),
        loan: [AtomicU64::new(0)],
        revoked: AtomicU64::new(0),
        floor: AtomicU64::new(0),
        word0: AtomicU64::new(block().pack().to_le()),
        payload: Payload::new(A),
    })
}

/// `SenderRead::read_committed` at position 0 of term A: the floor, the
/// loan on term A, the block's word 0 with Acquire and its payload under
/// the loan, then the release. `None` when nothing is read.
fn read(slot: &Slot, with_loan: bool) -> Option<u64> {
    if slot.floor.load(Ordering::Acquire) > 0 {
        return None;
    }
    let [loan] = &slot.loan;
    if with_loan {
        match take_loan(loan, &slot.revoked, &slot.descriptor, target(0)).unwrap() {
            LoanOutcome::Granted => {}
            LoanOutcome::Retry | LoanOutcome::Overrun | LoanOutcome::Revoked => return None,
        }
    }
    let read = (observe_block(&slot.word0) as u32 as i32 > 0).then(|| slot.payload.read());
    if with_loan {
        release_loan(loan);
    }
    read
}

/// The conductor reclaims term A and reuses the slot for term C, unless a
/// loan quarantines it.
fn reclaim(slot: &Slot) {
    let active = descriptor(0, SlotState::Active);
    let reclaiming = begin_reclaim(&slot.descriptor, active).unwrap();
    if loan_held(&slot.loan, SlotIndex::try_new(0).unwrap(), reclaiming).unwrap() {
        return;
    }
    let cleaning = begin_cleaning(&slot.descriptor, reclaiming).unwrap();
    clear_word(&slot.word0);
    slot.payload.write(0);
    publish(&slot.descriptor, cleaning.with_state(SlotState::Free));
    let ready = descriptor(2, SlotState::Ready);
    publish(&slot.descriptor, ready);
    activate(&slot.descriptor, ready).unwrap();
    slot.payload.write(C);
    publish_block(&slot.word0, block());
}

fn reclaim_model(with_loan: bool) {
    loom::model(move || {
        let slot = committed_slot();
        let conductor = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || reclaim(&slot))
        };
        if let Some(value) = read(&slot, with_loan) {
            assert_eq!(value, A, "a read of term A returned another term's bytes");
        }
        conductor.join().unwrap();
    });
}

#[test]
fn a_sender_loan_holds_its_term_against_reclamation() {
    reclaim_model(true);
}

/// Loom's first failing schedule reads the reused slot while the conductor
/// writes it.
#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_a_sender_read_without_its_loan_races_the_reuse() {
    reclaim_model(false);
}

/// The sender pauses between the floor check (step 1) and its loan (step
/// 3) while the conductor revokes its bank. `correct` takes the loan with
/// `take_loan`; the control loads the revoked flag before it stores the
/// loan word.
fn revocation_model(correct: bool) {
    loom::model(move || {
        let slot = committed_slot();
        let conductor = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || revoke(&slot.revoked, &slot.loan).unwrap())
        };
        // Step 1: the floor.
        assert_eq!(slot.floor.load(Ordering::Acquire), 0);
        let [loan] = &slot.loan;
        let granted = if correct {
            take_loan(loan, &slot.revoked, &slot.descriptor, target(0)).unwrap()
                == LoanOutcome::Granted
        } else if slot.revoked.load(Ordering::SeqCst) != REVOKED {
            loan.store(target(0).loan().encode(), Ordering::SeqCst);
            true
        } else {
            false
        };
        // Held across the conductor's scan, as a paused copy would hold it.
        let quiescent = conductor.join().unwrap();
        assert!(
            !(granted && quiescent),
            "the sender holds a loan the revocation reported quiescent"
        );
        if granted {
            release_loan(loan);
            assert!(participant_quiescent(&slot.loan).unwrap());
        }
    });
}

#[test]
fn a_revocation_never_misses_a_sender_loan() {
    revocation_model(true);
}

#[test]
#[should_panic(expected = "the sender holds a loan the revocation reported quiescent")]
fn control_a_flag_loaded_before_the_loan_word_misses_the_revocation() {
    revocation_model(false);
}

/// A concurrent claim aborted by its deadline while its writer still
/// writes inside the extent. The sender reads the block's word 0 with
/// Acquire: committed DATA would be copied, an ABORTED record yields only
/// its canonical record. The control also reads the extent.
fn aborted_model(read_extent: bool) {
    loom::model(move || {
        let slot = Arc::new(Slot {
            descriptor: AtomicU64::new(descriptor(0, SlotState::Active).encode()),
            loan: [AtomicU64::new(0)],
            revoked: AtomicU64::new(0),
            floor: AtomicU64::new(0),
            word0: AtomicU64::new(0),
            payload: Payload::new(0),
        });
        let reserved = Word0::new(
            -(FRAME as i32),
            Flags::new(true, true, false, false, Lane::ZERO),
            FrameType::Data,
        );
        let aborted = Word0::new(FRAME as i32, Flags::NONE, FrameType::Aborted);
        assert!(mark_block(&slot.word0, reserved));
        let writer = {
            let slot = Arc::clone(&slot);
            // The claimant, late: it writes after its deadline passed.
            thread::spawn(move || slot.payload.write(A))
        };
        // The conductor's deadline abort wins the block.
        assert!(deadline_abort(&slot.word0, FRAME, Lane::ZERO, aborted));
        let [loan] = &slot.loan;
        assert_eq!(
            take_loan(loan, &slot.revoked, &slot.descriptor, target(0)).unwrap(),
            LoanOutcome::Granted
        );
        let raw = observe_block(&slot.word0);
        let word = Word0::unpack(raw).unwrap();
        assert_eq!(word.frame_type_code(), FrameType::Aborted.code());
        if read_extent {
            let _ = slot.payload.read();
        }
        release_loan(loan);
        writer.join().unwrap();
    });
}

#[test]
fn an_aborted_claim_yields_only_its_record() {
    aborted_model(false);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_reading_an_aborted_extent_races_its_writer() {
    aborted_model(true);
}
