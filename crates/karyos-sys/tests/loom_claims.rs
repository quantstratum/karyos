// SPDX-License-Identifier: Apache-2.0

//! Loom model of the claim decision word (`quantstratum-docs: karyos/design/claims.md`) over the
//! production helpers of `karyos_sys::publication`. A writer marks the
//! block, writes a plain payload witness and commits; another thread aborts
//! the same decision word (standing in for the driver's future deadline
//! abort); a third thread polls it and then, acting as the cleaner, reuses
//! the payload bytes once the writer's loan is released. Exactly one
//! terminal value wins; a reader that sees DATA sees the whole payload; the
//! payload is never reused while the writer can still access it.
//!
//! Negative controls replace one production step and must fail: the
//! commit compare-exchange by a plain store, the reader's Acquire by a
//! Relaxed load, and the loan release moved before the writer's last
//! access.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::publication::{abort_block, commit_block, mark_block, observe_block};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::sync::atomic::AtomicBool;
use loom::thread;

const PAYLOAD: u64 = 0x5A5A;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Production,
    CommitByStore,
    RelaxedReader,
    EarlyLoanRelease,
}

struct Block {
    first: AtomicU64,
    payload: UnsafeCell<u64>,
    /// The writer's standing write loan.
    loan: AtomicBool,
}

fn flags() -> Flags {
    Flags::new(true, true, false, false, Lane::ZERO)
}

fn reserved() -> Word0 {
    Word0::new(-64, flags(), FrameType::Data)
}

fn committed() -> Word0 {
    Word0::new(40, flags(), FrameType::Data)
}

fn aborted() -> Word0 {
    Word0::new(64, Flags::NONE, FrameType::Aborted)
}

fn write_payload(block: &Block, value: u64) {
    block.payload.with_mut(|payload| {
        // SAFETY: the pointer comes from a live `UnsafeCell`; Loom checks
        // that no access races with this write.
        unsafe { *payload = value }
    });
}

fn model(variant: Variant) {
    loom::model(move || {
        let block = Arc::new(Block {
            first: AtomicU64::new(0),
            payload: UnsafeCell::new(0),
            loan: AtomicBool::new(true),
        });
        let writer = {
            let block = Arc::clone(&block);
            thread::spawn(move || {
                // The aborter acts only on a marked word, so marking wins.
                assert!(mark_block(&block.first, reserved()));
                write_payload(&block, PAYLOAD);
                if variant == Variant::EarlyLoanRelease {
                    block.loan.store(false, Ordering::SeqCst);
                    // Still writing after an abort may have won.
                    write_payload(&block, PAYLOAD);
                }
                let won = if variant == Variant::CommitByStore {
                    block
                        .first
                        .store(committed().pack().to_le(), Ordering::Release);
                    true
                } else {
                    commit_block(&block.first, reserved(), committed())
                };
                if variant != Variant::EarlyLoanRelease {
                    // After the writer's last access to the block.
                    block.loan.store(false, Ordering::SeqCst);
                }
                won
            })
        };
        let aborter = {
            let block = Arc::clone(&block);
            thread::spawn(move || abort_block(&block.first, reserved(), aborted()))
        };
        let reader = {
            let block = Arc::clone(&block);
            thread::spawn(move || {
                let word = if variant == Variant::RelaxedReader {
                    u64::from_le(block.first.load(Ordering::Relaxed))
                } else {
                    observe_block(&block.first)
                };
                if word == committed().pack() {
                    let payload = block.payload.with(|payload| {
                        // SAFETY: as in `write_payload`; ordered after the
                        // writer's write only through the commit's Release
                        // and this Acquire.
                        unsafe { *payload }
                    });
                    assert_eq!(payload, PAYLOAD);
                }
                // An ABORTED or pending word: only word 0 is read.
                // As the cleaner: reuse the bytes once the loan is gone.
                if !block.loan.load(Ordering::SeqCst) {
                    write_payload(&block, 0);
                }
            })
        };
        let commit_won = writer.join().unwrap();
        let abort_won = aborter.join().unwrap();
        reader.join().unwrap();
        // Exactly one terminal outcome, and the word states it.
        assert!(commit_won != abort_won, "both or neither outcome won");
        let last = u64::from_le(block.first.load(Ordering::Acquire));
        let expected = if commit_won { committed() } else { aborted() };
        assert_eq!(last, expected.pack());
    });
}

#[test]
fn claim_decision_is_terminal_and_payload_ordered() {
    model(Variant::Production);
}

#[test]
#[should_panic(expected = "both or neither outcome won")]
fn control_commit_by_plain_store_fails() {
    model(Variant::CommitByStore);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_relaxed_reader_fails() {
    model(Variant::RelaxedReader);
}

#[test]
#[should_panic(expected = "Concurrent write accesses")]
fn control_early_loan_release_fails() {
    model(Variant::EarlyLoanRelease);
}
