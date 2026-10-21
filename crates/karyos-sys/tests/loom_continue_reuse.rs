// SPDX-License-Identifier: Apache-2.0

//! Loom models of a required reader revoked under `continue` (SPEC.md §13,
//! "Required participant revocation"; `quantstratum-docs:
//! karyos/design/required-participant-loss.md`), over the production steps
//! of `karyos_sys::participant` and `karyos_sys::loan`:
//!
//! - reuse: the cell goes `REQUIRED_RESERVED` to `LOST_RESERVED`, its bound
//!   withdrawn at once and its credit kept. While its holder may still store
//!   its loan word, the cell is not reassigned; after the holder's detach
//!   store, the next admission sees a zero loan word, a clear flag, and is
//!   not overwritten by the old holder;
//! - the pinned bound: the revoked holder, paused around its acquisitions,
//!   pins only the slot its one loan names. The driver reclaims and cleans
//!   another slot meanwhile, a loaned slot is cleaned only after its loan
//!   ends, and an acquisition that resumes after the revocation is refused.
//!
//! The `hold` counterparts are in `loom_participant.rs` and
//! `loom_loan_reclaim.rs`. Each model has a negative control that drops the
//! rule it checks and must fail.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::loan::{
    Loan, LoanOutcome, LoanTarget, begin_cleaning, begin_reclaim, loan_held, publish, release_loan,
    take_loan,
};
use karyos_sys::participant::{
    CELL_FREE, CELL_LOST_RESERVED, CELL_REQUIRED_RESERVED, admit, bounds, leave, revoke_cell,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

/// An occupant id as an in-process subscriber gets it.
const LOCAL: u64 = 3;
/// An occupant id as a remote grant's export (nonzero, below FENCED).
const REMOTE: u64 = 1 << 40;
/// Payload value of a term while it is loaned out.
const TERM_BYTES: u64 = 7;
/// Value the cleaner zeroes a slot to.
const CLEANED_BYTES: u64 = 0;

/// One term slot: its descriptor and its bytes, accessed non-atomically
/// like real payload bytes, so Loom reports a read racing the cleaner.
struct Slot {
    target: LoanTarget,
    active: Descriptor,
    descriptor: AtomicU64,
    bytes: UnsafeCell<u64>,
}

impl Slot {
    fn new(index: u8, term: u32) -> Self {
        let generation = Generation::try_new(1).unwrap();
        let target = LoanTarget::new(
            SlotIndex::try_new(index).unwrap(),
            generation,
            TermId::new(term),
            TermCount::try_new(1).unwrap(),
        );
        let active = Descriptor::new(target.term_id(), generation, SlotState::Active);
        Self {
            target,
            active,
            descriptor: AtomicU64::new(active.encode()),
            bytes: UnsafeCell::new(TERM_BYTES),
        }
    }

    fn read_bytes(&self) -> u64 {
        self.bytes.with(|bytes| {
            // SAFETY: the pointer comes from a live `UnsafeCell` owned by
            // `self`; Loom checks that no write races with this read.
            unsafe { *bytes }
        })
    }

    fn write_bytes(&self, value: u64) {
        self.bytes.with_mut(|bytes| {
            // SAFETY: the pointer comes from a live `UnsafeCell` owned by
            // `self`; Loom checks that no other access races with this write.
            unsafe { *bytes = value }
        });
    }
}

/// A participant cell and the slots it may loan.
struct Shared {
    state: AtomicU64,
    revoked: AtomicU64,
    loan: AtomicU64,
    registration: AtomicU64,
    slots: [Slot; 2],
}

fn shared() -> Arc<Shared> {
    Arc::new(Shared {
        state: AtomicU64::new(CELL_REQUIRED_RESERVED),
        revoked: AtomicU64::new(0),
        loan: AtomicU64::new(0),
        registration: AtomicU64::new(LOCAL),
        slots: [Slot::new(1, 7), Slot::new(2, 8)],
    })
}

fn builder() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder
}

/// One acquisition of `slot`'s term: if granted, its bytes stay unchanged
/// until the release.
fn read_under_loan(shared: &Shared, slot: &Slot) {
    if take_loan(&shared.loan, &shared.revoked, &slot.descriptor, slot.target).unwrap()
        == LoanOutcome::Granted
    {
        assert_eq!(slot.read_bytes(), TERM_BYTES);
        assert_eq!(slot.read_bytes(), TERM_BYTES);
        release_loan(&shared.loan);
    }
}

/// The driver's `continue` revocation: from `REQUIRED_RESERVED` to
/// `LOST_RESERVED`, the bound withdrawn at once. Returns whether the cell
/// moved: `false` when the holder's detach stored `FREE` first, so it left
/// and nothing was lost.
fn revoke_continue(shared: &Shared) -> bool {
    let moved = revoke_cell(
        &shared.state,
        &shared.revoked,
        &shared.loan,
        CELL_REQUIRED_RESERVED,
        CELL_LOST_RESERVED,
    )
    .unwrap()
    .is_some();
    // Revoked or left, the cell bounds nothing from here on, whatever the
    // loan word holds.
    assert!(!bounds(shared.state.load(Ordering::Acquire)));
    moved
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reuse {
    Correct,
    /// Reassigns the cell as soon as it is `LOST_RESERVED`, before the
    /// holder left.
    BeforeDetach,
}

fn reuse_model(variant: Reuse) {
    builder().check(move || {
        let shared = shared();
        let holding = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                read_under_loan(&shared, &shared.slots[0]);
                leave(&shared.state, &shared.registration);
            })
        };
        let _ = revoke_continue(&shared);
        // A bounded number of duty cycles: the holder may not have left.
        // A holder that left first leaves the cell `FREE`, reusable.
        let mut reused = false;
        for _ in 0..2 {
            let state = shared.state.load(Ordering::Acquire);
            let reusable = match variant {
                Reuse::Correct => state == CELL_FREE,
                Reuse::BeforeDetach => state != CELL_REQUIRED_RESERVED,
            };
            if reusable {
                // The previous holder's last loan access happened before
                // this reuse: its word is zero.
                assert_eq!(
                    shared.loan.load(Ordering::Relaxed),
                    0,
                    "reused under a live loan word"
                );
                admit(
                    &shared.state,
                    &shared.revoked,
                    &shared.registration,
                    REMOTE,
                    CELL_REQUIRED_RESERVED,
                );
                reused = true;
                break;
            }
            thread::yield_now();
        }
        holding.join().unwrap();
        if reused {
            assert_eq!(shared.revoked.load(Ordering::Relaxed), 0);
            assert_eq!(shared.registration.load(Ordering::Relaxed), REMOTE);
            assert_eq!(
                shared.state.load(Ordering::Acquire),
                CELL_REQUIRED_RESERVED,
                "the old holder's detach overwrote the new occupant"
            );
        } else {
            assert_eq!(shared.state.load(Ordering::Acquire), CELL_FREE);
        }
    });
}

#[test]
fn a_continue_lost_cell_is_reused_only_after_its_holder_left() {
    reuse_model(Reuse::Correct);
}

#[test]
#[should_panic(expected = "the old holder's detach overwrote the new occupant")]
fn control_continue_reuse_before_the_detach_store() {
    reuse_model(Reuse::BeforeDetach);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Clean {
    Correct,
    /// Cleans the loaned slot without waiting for its loan to end.
    WithoutTheLoanScan,
}

/// Set, across Loom's executions, when one cleaned slot 1 while the loan
/// word named slot 0: the interleaving the pinned model exists for.
static CLEANED_WHILE_THE_OTHER_WAS_LOANED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The revoked holder reads slot 0, then slot 1, each under its one loan,
/// concurrently with its revocation; then, once it has seen the revocation
/// complete, it tries slot 0 again. The driver revokes under `continue` and
/// reclaims both slots, slot 1 first: each is cleaned once no loan holds
/// it, so the holder pins only the slot its loan names, and the other is
/// reclaimed meanwhile.
fn pinned_model(variant: Clean) {
    builder().check(move || {
        let shared = shared();
        let revoked = Arc::new(AtomicU64::new(0));
        let holding = {
            let shared = Arc::clone(&shared);
            let revoked = Arc::clone(&revoked);
            thread::spawn(move || {
                read_under_loan(&shared, &shared.slots[0]);
                read_under_loan(&shared, &shared.slots[1]);
                // Paused until the revocation completed, then resumed.
                while revoked.load(Ordering::Acquire) == 0 {
                    thread::yield_now();
                }
                let slot = &shared.slots[0];
                let outcome =
                    take_loan(&shared.loan, &shared.revoked, &slot.descriptor, slot.target)
                        .unwrap();
                assert_eq!(
                    outcome,
                    LoanOutcome::Revoked,
                    "the resumed acquisition was granted"
                );
                assert_eq!(shared.loan.load(Ordering::SeqCst), 0);
                leave(&shared.state, &shared.registration);
            })
        };
        // The holder leaves only after this revocation.
        assert!(
            revoke_continue(&shared),
            "the holder left before its revocation"
        );
        revoked.store(1, Ordering::Release);
        // Both terms fall below the floor at once: the cell no longer bounds.
        for slot in [&shared.slots[1], &shared.slots[0]] {
            let reclaiming = begin_reclaim(&slot.descriptor, slot.active).unwrap();
            if variant == Clean::Correct {
                while loan_held(
                    core::slice::from_ref(&shared.loan),
                    slot.target.slot(),
                    reclaiming,
                )
                .unwrap()
                {
                    thread::yield_now();
                }
            }
            let cleaning = begin_cleaning(&slot.descriptor, reclaiming).unwrap();
            if core::ptr::eq(slot, &shared.slots[1])
                && Loan::decode(shared.loan.load(Ordering::SeqCst))
                    .unwrap()
                    .is_some_and(|loan| loan.slot() == shared.slots[0].target.slot())
            {
                CLEANED_WHILE_THE_OTHER_WAS_LOANED
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
            slot.write_bytes(CLEANED_BYTES);
            publish(&slot.descriptor, cleaning.with_state(SlotState::Free));
        }
        holding.join().unwrap();
        assert_eq!(shared.state.load(Ordering::Acquire), CELL_FREE);
        assert_ne!(shared.revoked.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn a_continue_revoked_holder_pins_only_the_slot_its_loan_names() {
    pinned_model(Clean::Correct);
    // Some execution cleaned slot 1 while the holder's loan pinned slot 0.
    assert!(
        CLEANED_WHILE_THE_OTHER_WAS_LOANED.load(std::sync::atomic::Ordering::Relaxed),
        "no execution reclaimed one slot while the other was loaned"
    );
}

/// Negative control: cleaning a slot without the loan scan lets the
/// revoked holder read bytes the cleaner is writing, which Loom reports.
#[test]
#[should_panic(expected = "Causality violation")]
fn control_continue_cleaning_without_the_loan_scan() {
    pinned_model(Clean::WithoutTheLoanScan);
}
