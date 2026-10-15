// SPDX-License-Identifier: Apache-2.0

//! Loom models of a participant cell's loss transitions
//! (`quantstratum-docs: karyos/design/required-participant-loss.md`, Tests,
//! Loom p4a), over the production steps of `karyos_sys::participant`:
//!
//! - reuse: a lost cell is not reassigned while its holder may still store
//!   its loan word; after the holder's detach store, the next admission
//!   sees a zero loan word and a fresh flag;
//! - stale work across occupants: a `hold` rescan decided for occupant 1
//!   runs after occupant 1 left and occupant 2 was admitted as `REQUIRED`,
//!   and leaves occupant 2's state, flag and bound untouched, once with a
//!   local occupant 1 and a remote occupant 2 and once the reverse;
//! - detach racing the loss transition: either order ends `FREE` with no
//!   bound left.
//!
//! Each has a negative control that drops the rule it checks and must fail.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::loan::{LoanOutcome, LoanTarget, release_loan, take_loan};
use karyos_sys::participant::{
    CELL_FREE, CELL_LOST, CELL_LOST_HOLDING, CELL_REQUIRED, admit, bounds, leave, revoke_cell,
    withdraw, withdraw_if_quiescent,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::sync::Arc;
use loom::thread;

/// An occupant id as an in-process subscriber gets it.
const LOCAL: u64 = 3;
/// An occupant id as a remote grant's export (nonzero, below FENCED).
const REMOTE: u64 = 1 << 40;

struct Cell {
    state: AtomicU64,
    revoked: AtomicU64,
    loan: AtomicU64,
    registration: AtomicU64,
    descriptor: AtomicU64,
}

fn target() -> LoanTarget {
    LoanTarget::new(
        SlotIndex::try_new(1).unwrap(),
        Generation::try_new(1).unwrap(),
        TermId::new(7),
        TermCount::try_new(1).unwrap(),
    )
}

fn cell(state: u64, occupant: u64) -> Arc<Cell> {
    let target = target();
    let active = Descriptor::new(
        target.term_id(),
        Generation::try_new(1).unwrap(),
        SlotState::Active,
    );
    Arc::new(Cell {
        state: AtomicU64::new(state),
        revoked: AtomicU64::new(0),
        loan: AtomicU64::new(0),
        registration: AtomicU64::new(occupant),
        descriptor: AtomicU64::new(active.encode()),
    })
}

fn builder() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder
}

/// The holder of occupant 1: one acquisition attempt, its release, then
/// its detach store.
fn holder(cell: &Cell) {
    if take_loan(&cell.loan, &cell.revoked, &cell.descriptor, target()).unwrap()
        == LoanOutcome::Granted
    {
        release_loan(&cell.loan);
    }
    leave(&cell.state, &cell.registration);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reuse {
    Correct,
    /// Reassigns the cell as soon as it is lost, before the holder left.
    BeforeDetach,
}

fn reuse_model(variant: Reuse) {
    builder().check(move || {
        let shared = cell(CELL_REQUIRED, LOCAL);
        let holding = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || holder(&shared))
        };
        // The driver revokes under `hold`, rescans until withdrawn, then
        // reuses the cell for occupant 2.
        let _ = revoke_cell(
            &shared.state,
            &shared.revoked,
            &shared.loan,
            CELL_REQUIRED,
            CELL_LOST_HOLDING,
        )
        .unwrap();
        // A bounded number of duty cycles: the holder may not have left.
        let mut reused = false;
        for _ in 0..2 {
            let _ = withdraw_if_quiescent(&shared.state, &shared.loan).unwrap();
            let state = shared.state.load(Ordering::Acquire);
            let reusable = match variant {
                Reuse::Correct => state == CELL_FREE,
                Reuse::BeforeDetach => state != CELL_REQUIRED,
            };
            if reusable {
                // The previous holder's last loan access happened before
                // this reuse: its word is zero, and the new occupant starts
                // fresh.
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
                    CELL_REQUIRED,
                );
                reused = true;
                break;
            }
            thread::yield_now();
        }
        holding.join().unwrap();
        if reused {
            assert_eq!(shared.revoked.load(Ordering::Relaxed), 0);
            assert_eq!(
                shared.state.load(Ordering::Acquire),
                CELL_REQUIRED,
                "the old holder's detach overwrote the new occupant"
            );
        }
    });
}

#[test]
fn a_lost_cell_is_reused_only_after_its_holder_left() {
    reuse_model(Reuse::Correct);
}

#[test]
#[should_panic]
fn control_reuse_before_the_detach_store() {
    reuse_model(Reuse::BeforeDetach);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rescan {
    Correct,
    /// Withdraws with a plain store instead of the compare-exchange.
    PlainStore,
}

/// Occupant 1 is revoked under `hold` holding its loan; the conductor
/// decides a rescan, then (occupant 1 having released and left) admits
/// occupant 2 and only then runs the pending withdrawal.
fn stale_rescan_model(variant: Rescan, first: u64, second: u64) {
    builder().check(move || {
        let shared = cell(CELL_LOST_HOLDING, first);
        // Occupant 1 took a loan before its revocation and still holds it
        // when the rescan is decided.
        assert_eq!(
            take_loan(&shared.loan, &shared.revoked, &shared.descriptor, target()).unwrap(),
            LoanOutcome::Granted
        );
        shared.revoked.store(1, Ordering::SeqCst);
        let leaving = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                release_loan(&shared.loan);
                leave(&shared.state, &shared.registration);
            })
        };
        // The conductor: the rescan saw LOST_HOLDING; occupant 2 comes in
        // once the cell is free; then the stale withdrawal runs.
        let decided = shared.state.load(Ordering::Acquire) == CELL_LOST_HOLDING;
        while shared.state.load(Ordering::Acquire) != CELL_FREE {
            thread::yield_now();
        }
        admit(
            &shared.state,
            &shared.revoked,
            &shared.registration,
            second,
            CELL_REQUIRED,
        );
        if decided {
            match variant {
                Rescan::Correct => {
                    let _ = withdraw(&shared.state);
                }
                Rescan::PlainStore => shared.state.store(CELL_LOST, Ordering::Release),
            }
        }
        leaving.join().unwrap();
        let state = shared.state.load(Ordering::Acquire);
        assert_eq!(state, CELL_REQUIRED, "stale rescan touched occupant 2");
        assert!(bounds(state));
        assert_eq!(shared.revoked.load(Ordering::Relaxed), 0);
        assert_eq!(shared.registration.load(Ordering::Relaxed), second);
    });
}

#[test]
fn a_stale_rescan_leaves_a_remote_successor_untouched() {
    stale_rescan_model(Rescan::Correct, LOCAL, REMOTE);
}

#[test]
fn a_stale_rescan_leaves_a_local_successor_untouched() {
    stale_rescan_model(Rescan::Correct, REMOTE, LOCAL);
}

#[test]
#[should_panic]
fn control_a_stale_rescan_with_a_plain_store() {
    stale_rescan_model(Rescan::PlainStore, LOCAL, REMOTE);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Loss {
    Correct,
    /// Moves to the lost state with a plain store instead of the
    /// compare-exchange from the expected state.
    PlainStore,
}

fn detach_versus_loss_model(variant: Loss) {
    builder().check(move || {
        let shared = cell(CELL_REQUIRED, LOCAL);
        let leaving = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || leave(&shared.state, &shared.registration))
        };
        // The driver's loss transition for the participant it timed out.
        match variant {
            Loss::Correct => {
                let _ = revoke_cell(
                    &shared.state,
                    &shared.revoked,
                    &shared.loan,
                    CELL_REQUIRED,
                    CELL_LOST_HOLDING,
                )
                .unwrap();
            }
            Loss::PlainStore => {
                if shared.state.load(Ordering::Acquire) == CELL_REQUIRED {
                    shared.revoked.store(1, Ordering::SeqCst);
                    shared.state.store(CELL_LOST_HOLDING, Ordering::Release);
                }
            }
        }
        leaving.join().unwrap();
        let state = shared.state.load(Ordering::Acquire);
        assert_eq!(state, CELL_FREE, "the cell did not end free");
        assert!(!bounds(state), "a bound was left");
    });
}

#[test]
fn a_detach_racing_the_loss_ends_free_with_no_bound() {
    detach_versus_loss_model(Loss::Correct);
}

#[test]
#[should_panic]
fn control_a_loss_with_a_plain_store() {
    detach_versus_loss_model(Loss::PlainStore);
}
