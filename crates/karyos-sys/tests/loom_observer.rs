// SPDX-License-Identifier: Apache-2.0

//! Loom model of the observer role (`quantstratum-docs: karyos/design/observer-role.md`,
//! SPEC.md §13 "Observer race freedom") over the production loan, rotation
//! and publication helpers: a three-way race between a publisher, an
//! observer and the driver's reclaim.
//!
//! Term `t` (slot 0) is full and holds a committed two-word frame; term
//! `t + 1` (slot 1) is `READY`. Three threads:
//!
//! - the publisher, holding its standing write loan on `t`, rotates to
//!   `t + 1`, moves its loan there, writes the next frame's payload and
//!   publishes its word 0 with `Release`;
//! - the observer copies the frame of `t` under a loan, and may pause
//!   between the words; it then copies the next frame of `t + 1` if its
//!   loan is granted and the frame is committed; its handler then runs
//!   with the copies and no loan held;
//! - the driver, if it sees `t` below the active term, moves its slot to
//!   `RECLAIMING` at once, racing both threads, scans every loan word and
//!   cleans the slot only when no loan pins it; a quarantined slot (or a
//!   slot whose term was still active) is reclaimed after both threads
//!   end, as the driver's next duty cycle would.
//!
//! Checks: no data race on any term byte (Loom checks every access); the
//! observer copies only under a granted loan, and every word it copies is
//! the committed value; while a loan pins `t` its slot stays
//! `RECLAIMING`; the handler pins nothing, so the driver always frees `t`
//! once the copies end.
//!
//! Negative controls must fail: an observer that releases its loan before
//! the second word is copied (the cleaning races the copy), and a
//! publisher that commits the next frame with a `Relaxed` store (the copy
//! races the payload write).
//!
//! Exploration: default Loom bounds (no preemption bound); three
//! threads, no wait loops.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::loan::{
    LoanOutcome, LoanTarget, Rotation, begin_cleaning, begin_reclaim, loan_held, publish,
    release_loan, rotate_to, take_loan,
};
use karyos_sys::publication::{observe_block, publish_block};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

/// The committed frame of term `t`, two words.
const COMMITTED: [u64; 2] = [7, 8];
/// The payload of the next frame, in term `t + 1`.
const NEXT: u64 = 9;
/// The loan words: the observer's, then the publisher's.
const OBSERVER: usize = 0;
const PUBLISHER: usize = 1;

fn generation() -> Generation {
    Generation::try_new(1).unwrap()
}

fn count(value: u32) -> TermCount {
    TermCount::try_new(value).unwrap()
}

fn initial() -> TermId {
    TermId::new(3)
}

fn descriptor(value: u32, state: SlotState) -> Descriptor {
    Descriptor::new(initial().advanced_by(count(value)), generation(), state)
}

/// Term count `value` lives in slot `value`.
fn target(value: u32) -> LoanTarget {
    LoanTarget::new(
        SlotIndex::try_new(value as u8).unwrap(),
        generation(),
        initial(),
        count(value),
    )
}

fn next_word0() -> Word0 {
    Word0::new(
        40,
        Flags::new(true, true, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

struct Shared {
    descriptors: [AtomicU64; 2],
    active: AtomicU64,
    loans: [AtomicU64; 2],
    revoked: AtomicU64,
    /// The frame of `t`, in slot 0.
    old: [UnsafeCell<u64>; 2],
    /// The next frame of `t + 1`, in slot 1: word 0 and payload.
    next_first: AtomicU64,
    next_payload: UnsafeCell<u64>,
}

impl Shared {
    fn read_old(&self, word: usize) -> u64 {
        self.old[word].with(|bytes| {
            // SAFETY: the pointer comes from a live `UnsafeCell` owned by
            // `self`; Loom checks that no write races with this read.
            unsafe { *bytes }
        })
    }

    fn clean_old(&self) {
        for word in &self.old {
            word.with_mut(|bytes| {
                // SAFETY: as in `read_old`; Loom checks that no other
                // access races with this write.
                unsafe { *bytes = 0 }
            });
        }
    }

    fn state(&self, slot: usize) -> SlotState {
        Descriptor::decode(self.descriptors[slot].load(Ordering::SeqCst))
            .unwrap()
            .state()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Release {
    AfterTheCopy,
    BeforeTheSecondWord,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Commit {
    Release,
    RelaxedStore,
}

fn model(release: Release, commit: Commit) {
    loom::model(move || {
        let shared = Arc::new(Shared {
            descriptors: [
                AtomicU64::new(descriptor(0, SlotState::Active).encode()),
                AtomicU64::new(descriptor(1, SlotState::Ready).encode()),
            ],
            active: AtomicU64::new(0),
            loans: [AtomicU64::new(0), AtomicU64::new(0)],
            revoked: AtomicU64::new(0),
            old: [UnsafeCell::new(COMMITTED[0]), UnsafeCell::new(COMMITTED[1])],
            next_first: AtomicU64::new(0),
            next_payload: UnsafeCell::new(0),
        });
        // The publisher's standing write loan on `t`.
        assert_eq!(
            take_loan(
                &shared.loans[PUBLISHER],
                &shared.revoked,
                &shared.descriptors[0],
                target(0)
            )
            .unwrap(),
            LoanOutcome::Granted
        );
        let publisher = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let word = &shared.loans[PUBLISHER];
                // Term `t` is full: rotate to `t + 1` (READY from the start).
                let rotation = rotate_to(
                    &shared.descriptors[1],
                    &shared.active,
                    initial().advanced_by(count(1)),
                    generation(),
                    count(1),
                )
                .unwrap();
                assert_eq!(rotation, Rotation::Completed);
                release_loan(word);
                assert_eq!(
                    take_loan(word, &shared.revoked, &shared.descriptors[1], target(1)).unwrap(),
                    LoanOutcome::Granted
                );
                shared.next_payload.with_mut(|payload| {
                    // SAFETY: the pointer comes from a live `UnsafeCell`;
                    // Loom checks that no access races with this write.
                    unsafe { *payload = NEXT }
                });
                match commit {
                    Commit::Release => publish_block(&shared.next_first, next_word0()),
                    Commit::RelaxedStore => shared
                        .next_first
                        .store(next_word0().pack().to_le(), Ordering::Relaxed),
                }
                release_loan(word);
            })
        };
        let observer = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let word = &shared.loans[OBSERVER];
                // The frame of `t`.
                if take_loan(word, &shared.revoked, &shared.descriptors[0], target(0)).unwrap()
                    == LoanOutcome::Granted
                {
                    let first = shared.read_old(0);
                    if release == Release::BeforeTheSecondWord {
                        release_loan(word);
                    }
                    // The observer may pause here, inside its copy.
                    let second = shared.read_old(1);
                    if release == Release::AfterTheCopy {
                        release_loan(word);
                    }
                    assert_eq!([first, second], COMMITTED, "a copied word changed");
                }
                // The next frame, which the publisher may be writing.
                if take_loan(word, &shared.revoked, &shared.descriptors[1], target(1)).unwrap()
                    == LoanOutcome::Granted
                {
                    if observe_block(&shared.next_first) == next_word0().pack() {
                        let payload = shared.next_payload.with(|payload| {
                            // SAFETY: as above; ordered after the
                            // publisher's write only through its commit
                            // and this Acquire.
                            unsafe { *payload }
                        });
                        assert_eq!(payload, NEXT, "a committed frame was not visible");
                    }
                    release_loan(word);
                }
                // The handler then runs with the copies and no loan.
            })
        };
        // The driver: if `t` is already below the active term, reclaim its
        // slot now, racing both threads; otherwise after they end. It
        // yields first: without a yield, Loom never schedules the
        // publisher's rotation before this first load, and the concurrent
        // reclaim would go unexplored.
        thread::yield_now();
        let slot = SlotIndex::try_new(0).unwrap();
        let mut reclaiming = None;
        let mut cleaned = false;
        if shared.active.load(Ordering::Acquire) >= 1 {
            let quarantined =
                begin_reclaim(&shared.descriptors[0], descriptor(0, SlotState::Active)).unwrap();
            if loan_held(&shared.loans, slot, quarantined).unwrap() {
                // Quarantined while a loan is held.
                assert_eq!(shared.state(0), SlotState::Reclaiming);
            } else {
                let cleaning = begin_cleaning(&shared.descriptors[0], quarantined).unwrap();
                shared.clean_old();
                publish(&shared.descriptors[0], cleaning.with_state(SlotState::Free));
                cleaned = true;
            }
            reclaiming = Some(quarantined);
        }
        publisher.join().unwrap();
        observer.join().unwrap();
        if !cleaned {
            let quarantined = reclaiming.unwrap_or_else(|| {
                begin_reclaim(&shared.descriptors[0], descriptor(0, SlotState::Active)).unwrap()
            });
            // Copies done, handler running: no loan pins `t`.
            assert!(!loan_held(&shared.loans, slot, quarantined).unwrap());
            let cleaning = begin_cleaning(&shared.descriptors[0], quarantined).unwrap();
            shared.clean_old();
            publish(&shared.descriptors[0], cleaning.with_state(SlotState::Free));
        }
        assert_eq!(shared.state(0), SlotState::Free);
        assert_eq!(shared.state(1), SlotState::Active);
    });
}

#[test]
fn observer_copies_while_publisher_writes_and_driver_reclaims() {
    model(Release::AfterTheCopy, Commit::Release);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_observer_releases_before_the_copy_ends_fails() {
    model(Release::BeforeTheSecondWord, Commit::Release);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_publisher_commits_by_relaxed_store_fails() {
    model(Release::AfterTheCopy, Commit::RelaxedStore);
}
