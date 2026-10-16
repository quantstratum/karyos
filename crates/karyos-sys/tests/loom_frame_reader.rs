// SPDX-License-Identifier: Apache-2.0

//! Loom models of the resumable frame-level reader (`quantstratum-docs:
//! karyos/design/frame-level-service.md`, "Evidence before merge") over
//! the production helpers of `karyos_sys::loan` and
//! `karyos_sys::publication`. `FrameReader` reads one fragment per call and
//! keeps a partial assembly across calls; these models compose the same
//! steps, with a reader that serves a two-fragment message in two calls:
//!
//! - **term splice**: a reader paused between its two calls while the
//!   driver reclaims the slot and reuses it for a later term. Its second
//!   loan targets the assembly's term, so it is refused, and no message
//!   mixes two terms. Control: a loan that targets the slot alone (whatever
//!   term it holds) completes a spliced message, or races the new term's
//!   writes.
//! - **retention floor**: a floor published before the reader's second call
//!   passes the assembly's start, and the reader ends instead of
//!   delivering. Control: without the floor check it delivers below the
//!   floor.
//! - **image resume**: each fragment is its own publication; the resumed
//!   fragment's word 0 is loaded with Acquire before its bytes. Control: a
//!   Relaxed load of the resumed fragment's word 0 races its payload.
//! - **publication resume**, exclusive and concurrent: one Release of the
//!   block's first word 0 publishes every fragment; the interior is read in
//!   a later call, ordered by the first call's Acquire. Control: reading
//!   the interior without that Acquire races.
//! - **aborted claim**: a concurrent claim aborted by its deadline while
//!   the reader is between calls; the reader reads only word 0 of the
//!   ABORTED record, never the extent a paused claimant may still write.
//!   Control: reading inside the aborted extent races the claimant.
//!
//! Payload bytes are plain values in Loom `UnsafeCell`s, where Loom reports
//! any read and write not ordered by happens-before.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::loan::{
    LoanOutcome, LoanTarget, activate, begin_cleaning, begin_reclaim, loan_held, publish,
    release_loan, take_loan,
};
use karyos_sys::publication::{
    clear_word, commit_block, deadline_abort, load_interior, mark_block, observe_block,
    publish_block, store_interior,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

/// The two fragments' payloads of term A and of the later term C.
const A: [u64; 2] = [0xA1, 0xA2];
const C: [u64; 2] = [0xC1, 0xC2];
/// The reserved extent of each fragment.
const FRAGMENT: u32 = 64;

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

/// One slot holding a two-fragment message: the fragments' word 0s and
/// payloads, the slot descriptor and the reader's loan word.
struct Slot {
    descriptor: AtomicU64,
    loan: [AtomicU64; 1],
    revoked: AtomicU64,
    floor: AtomicU64,
    /// Set by the driver once its floor store is done (the floor model).
    published: AtomicU64,
    word0: [AtomicU64; 2],
    payload: [Payload; 2],
}

fn first() -> Word0 {
    Word0::new(
        FRAGMENT as i32 - 7,
        Flags::new(true, false, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

fn last() -> Word0 {
    Word0::new(
        FRAGMENT as i32 - 7,
        Flags::new(false, true, false, false, Lane::ZERO),
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

/// Term A (count 0) active in the slot with its committed message.
fn committed_slot() -> Arc<Slot> {
    Arc::new(Slot {
        descriptor: AtomicU64::new(descriptor(0, SlotState::Active).encode()),
        loan: [AtomicU64::new(0)],
        revoked: AtomicU64::new(0),
        floor: AtomicU64::new(0),
        published: AtomicU64::new(0),
        word0: [
            AtomicU64::new(first().pack().to_le()),
            AtomicU64::new(last().pack().to_le()),
        ],
        payload: [Payload::new(A[0]), Payload::new(A[1])],
    })
}

/// One call of the reader: under a loan of `target`, reads fragment
/// `index` (its word 0 Acquire at the block start, Relaxed inside the
/// block) and its payload. `None` when the loan is refused.
fn serve(slot: &Slot, target: LoanTarget, index: usize) -> Option<u64> {
    let [loan] = &slot.loan;
    match take_loan(loan, &slot.revoked, &slot.descriptor, target).unwrap() {
        LoanOutcome::Granted => {}
        LoanOutcome::Retry | LoanOutcome::Overrun | LoanOutcome::Revoked => return None,
    }
    let raw = if index == 0 {
        observe_block(&slot.word0[0])
    } else {
        load_interior(&slot.word0[1])
    };
    let read = (raw as u32 as i32 > 0).then(|| slot.payload[index].read());
    release_loan(loan);
    read
}

/// The driver reclaims term A, cleans the slot and reuses it for term C
/// (count 2), which it writes and publishes, unless a loan quarantines it.
fn reuse(slot: &Slot) {
    let active = descriptor(0, SlotState::Active);
    let reclaiming = begin_reclaim(&slot.descriptor, active).unwrap();
    if loan_held(&slot.loan, SlotIndex::try_new(0).unwrap(), reclaiming).unwrap() {
        return;
    }
    let cleaning = begin_cleaning(&slot.descriptor, reclaiming).unwrap();
    for (word0, payload) in slot.word0.iter().zip(&slot.payload) {
        clear_word(word0);
        payload.write(0);
    }
    publish(&slot.descriptor, cleaning.with_state(SlotState::Free));
    let ready = descriptor(2, SlotState::Ready);
    publish(&slot.descriptor, ready);
    activate(&slot.descriptor, ready).unwrap();
    slot.payload[0].write(C[0]);
    slot.payload[1].write(C[1]);
    store_interior(&slot.word0[1], last());
    publish_block(&slot.word0[0], first());
}

fn splice_model(slot_alone: bool) {
    loom::model(move || {
        let slot = committed_slot();
        let driver = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || reuse(&slot))
        };
        if let Some(head) = serve(&slot, target(0), 0) {
            // Paused between the calls; the second targets the assembly's
            // term, or, in the control, whatever term the slot holds.
            let tail = serve(&slot, target(0), 1).or_else(|| {
                if slot_alone {
                    serve(&slot, target(2), 1)
                } else {
                    None
                }
            });
            if let Some(tail) = tail {
                let message = [head, tail];
                assert!(message == A || message == C, "spliced message {message:x?}");
            }
        }
        driver.join().unwrap();
    });
}

#[test]
fn a_resumed_assembly_never_mixes_two_terms() {
    splice_model(false);
}

#[test]
#[should_panic]
fn control_a_loan_on_the_slot_alone_splices_terms() {
    splice_model(true);
}

fn floor_model(check_floor: bool) {
    loom::model(move || {
        let slot = committed_slot();
        let driver = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || {
                // The retention floor passes the message at position 0.
                slot.floor.store(u64::from(FRAGMENT), Ordering::Release);
                slot.published.store(1, Ordering::Release);
            })
        };
        let start = 0u64;
        let mut delivered = false;
        if serve(&slot, target(0), 0).is_some() {
            while slot.published.load(Ordering::Acquire) == 0 {
                thread::yield_now();
            }
            // The second call: the floor is checked after the loan.
            let [loan] = &slot.loan;
            if take_loan(loan, &slot.revoked, &slot.descriptor, target(0)).unwrap()
                == LoanOutcome::Granted
            {
                if !check_floor || start >= slot.floor.load(Ordering::Acquire) {
                    let _ = slot.payload[1].read();
                    delivered = true;
                }
                release_loan(loan);
            }
        }
        assert!(!delivered, "delivered below the retention floor");
        driver.join().unwrap();
    });
}

#[test]
fn a_floor_past_the_assembly_ends_it() {
    floor_model(true);
}

#[test]
#[should_panic(expected = "delivered below the retention floor")]
fn control_without_the_floor_check_delivers_below_it() {
    floor_model(false);
}

/// An image: the receive owner publishes each fragment by its own Release;
/// the reader serves the first in one call and resumes at the second in a
/// later one.
fn image_model(relaxed_resume: bool) {
    loom::model(move || {
        let slot = Arc::new(Slot {
            descriptor: AtomicU64::new(descriptor(0, SlotState::Active).encode()),
            loan: [AtomicU64::new(0)],
            revoked: AtomicU64::new(0),
            floor: AtomicU64::new(0),
            published: AtomicU64::new(0),
            word0: [AtomicU64::new(0), AtomicU64::new(0)],
            payload: [Payload::new(0), Payload::new(0)],
        });
        let owner = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || {
                slot.payload[0].write(A[0]);
                publish_block(&slot.word0[0], first());
                slot.payload[1].write(A[1]);
                publish_block(&slot.word0[1], last());
            })
        };
        if observe_block(&slot.word0[0]) as u32 as i32 > 0 {
            let head = slot.payload[0].read();
            // A later call resumes at the second fragment.
            let raw = if relaxed_resume {
                u64::from_le(slot.word0[1].load(Ordering::Relaxed))
            } else {
                observe_block(&slot.word0[1])
            };
            if raw as u32 as i32 > 0 {
                assert_eq!([head, slot.payload[1].read()], A);
            }
        }
        owner.join().unwrap();
    });
}

#[test]
fn an_image_fragment_is_resumed_after_its_acquire() {
    image_model(false);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_a_relaxed_resumed_image_fragment_races() {
    image_model(true);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Writer {
    Exclusive,
    Concurrent,
}

/// A publication block of two fragments, published by one Release of its
/// first word 0 (exclusive) or by the claim's commit (concurrent); the
/// reader observes the block start in one call and reads the interior in a
/// later one.
fn publication_model(writer: Writer, skip_acquire: bool) {
    loom::model(move || {
        let slot = Arc::new(Slot {
            descriptor: AtomicU64::new(descriptor(0, SlotState::Active).encode()),
            loan: [AtomicU64::new(0)],
            revoked: AtomicU64::new(0),
            floor: AtomicU64::new(0),
            published: AtomicU64::new(0),
            word0: [AtomicU64::new(0), AtomicU64::new(0)],
            payload: [Payload::new(0), Payload::new(0)],
        });
        let publisher = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || {
                let reserved = Word0::new(
                    -(2 * FRAGMENT as i32),
                    Flags::new(true, true, false, false, Lane::ZERO),
                    FrameType::Data,
                );
                if writer == Writer::Concurrent {
                    assert!(mark_block(&slot.word0[0], reserved));
                }
                slot.payload[0].write(A[0]);
                slot.payload[1].write(A[1]);
                store_interior(&slot.word0[1], last());
                match writer {
                    Writer::Exclusive => publish_block(&slot.word0[0], first()),
                    Writer::Concurrent => {
                        assert!(commit_block(&slot.word0[0], reserved, first()));
                    }
                }
            })
        };
        if skip_acquire {
            // The control: the interior read without the block start's
            // Acquire.
            if load_interior(&slot.word0[1]) as u32 as i32 > 0 {
                let _ = slot.payload[1].read();
            }
        } else if observe_block(&slot.word0[0]) as u32 as i32 > 0 {
            // The first call: the block start observed with Acquire.
            let head = slot.payload[0].read();
            // A later call: the interior loaded Relaxed, ordered by the
            // earlier Acquire on this reader.
            let raw = load_interior(&slot.word0[1]);
            assert!(
                raw as u32 as i32 > 0,
                "an interior fragment of a committed block"
            );
            assert_eq!([head, slot.payload[1].read()], A);
        }
        publisher.join().unwrap();
    });
}

#[test]
fn an_exclusive_block_is_resumed_inside_its_acquire() {
    publication_model(Writer::Exclusive, false);
}

#[test]
fn a_concurrent_block_is_resumed_inside_its_acquire() {
    publication_model(Writer::Concurrent, false);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_an_exclusive_interior_without_the_acquire_races() {
    publication_model(Writer::Exclusive, true);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_a_concurrent_interior_without_the_acquire_races() {
    publication_model(Writer::Concurrent, true);
}

/// A concurrent claim aborted by its deadline while a reader is between
/// calls: the claimant may still be writing inside its extent after the
/// abort won.
fn aborted_model(read_inside: bool) {
    loom::model(move || {
        let slot = Arc::new(Slot {
            descriptor: AtomicU64::new(descriptor(0, SlotState::Active).encode()),
            loan: [AtomicU64::new(0)],
            revoked: AtomicU64::new(0),
            floor: AtomicU64::new(0),
            published: AtomicU64::new(0),
            word0: [AtomicU64::new(0), AtomicU64::new(0)],
            payload: [Payload::new(0), Payload::new(0)],
        });
        let extent = 2 * FRAGMENT;
        // A claim's reserved word: BEGIN and END over its whole extent.
        let reserved = Word0::new(
            -(extent as i32),
            Flags::new(true, true, false, false, Lane::ZERO),
            FrameType::Data,
        );
        let aborted = Word0::new(extent as i32, Flags::NONE, FrameType::Aborted);
        let claimant = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || {
                if mark_block(&slot.word0[0], reserved) {
                    // Paused inside its extent; its commit fails if the
                    // deadline won.
                    slot.payload[1].write(A[1]);
                    let _ = commit_block(&slot.word0[0], reserved, first());
                }
            })
        };
        let deadline = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || {
                let _ = deadline_abort(&slot.word0[0], extent, Lane::ZERO, aborted);
            })
        };
        let raw = observe_block(&slot.word0[0]);
        if raw as u32 as i32 > 0 {
            let word0 = Word0::unpack(raw).unwrap();
            if word0.frame_type_code() == FrameType::Aborted.code() {
                // Only word 0 of an ABORTED record is read.
                if read_inside {
                    let _ = slot.payload[1].read();
                }
            } else {
                // A committed block: its interior is ordered by the commit.
                assert_eq!(slot.payload[1].read(), A[1]);
            }
        }
        claimant.join().unwrap();
        deadline.join().unwrap();
    });
}

#[test]
fn an_aborted_claim_is_stepped_over_by_its_word0_alone() {
    aborted_model(false);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_reading_inside_an_aborted_claim_races() {
    aborted_model(true);
}
