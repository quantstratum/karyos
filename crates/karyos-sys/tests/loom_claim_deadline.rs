// SPDX-License-Identifier: Apache-2.0

//! Loom models of the commit-deadline abort of exclusive claims
//! (`quantstratum-docs: karyos/design/claim-deadline.md`), over the production helpers of
//! `karyos_sys::publication`:
//!
//! - the claim record's seqlock never yields a torn snapshot: every
//!   accepted serial carries the record written with it;
//! - a writer marked and then paused forever is always aborted, even when
//!   the conductor first loads 0 and loses its first compare-exchange to
//!   the mark;
//! - a writer that marks, writes a plain payload witness and commits races
//!   the conductor's abort: exactly one terminal outcome; a writer whose
//!   mark loses writes nothing; the conductor, acting as cleaner, reuses the
//!   payload only after the loan release, and after that cleaning never
//!   again sees the old claim's record.
//!
//! Negative controls must fail: a record written without the seqlock, a
//! single compare-exchange attempt, an abort by plain store, and the loan
//! released before the record is cleared.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::publication::{
    commit_block, deadline_abort, mark_block, read_claim_record, write_claim_record,
};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::sync::atomic::AtomicBool;
use loom::thread;

const EXTENT: u32 = 64;
const RECORD: u64 = 0xABC;
const PAYLOAD: u64 = 0x5A5A;

fn flags() -> Flags {
    Flags::new(true, true, true, false, Lane::ZERO)
}

fn reserved() -> Word0 {
    Word0::new(-(EXTENT as i32), flags(), FrameType::Data)
}

fn committed() -> Word0 {
    Word0::new(40, flags(), FrameType::Data)
}

fn aborted() -> Word0 {
    Word0::new(EXTENT as i32, Flags::NONE, FrameType::Aborted)
}

/// Seqlock: the record rewritten as set, clear, set (an equal record of a
/// later claim) while the conductor snapshots it.
fn record_model(seqlock: bool) {
    loom::model(move || {
        let serial = Arc::new(AtomicU64::new(0));
        let record = Arc::new(AtomicU64::new(0));
        let writer = {
            let (serial, record) = (Arc::clone(&serial), Arc::clone(&record));
            thread::spawn(move || {
                for value in [RECORD, 0, RECORD + 1] {
                    if seqlock {
                        write_claim_record(&serial, &record, value);
                    } else {
                        let current = serial.load(Ordering::Relaxed);
                        serial.store(current + 2, Ordering::Release);
                        record.store(value, Ordering::Relaxed);
                    }
                }
            })
        };
        let reader = {
            let (serial, record) = (Arc::clone(&serial), Arc::clone(&record));
            thread::spawn(move || {
                if let Some((seen, value)) = read_claim_record(&serial, &record) {
                    let expected = match seen {
                        0 => 0,
                        2 => RECORD,
                        4 => 0,
                        6 => RECORD + 1,
                        other => panic!("odd or unknown serial {other}"),
                    };
                    assert_eq!(value, expected, "torn claim record");
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();
    });
}

#[test]
fn claim_record_snapshots_are_consistent() {
    record_model(true);
}

#[test]
#[should_panic(expected = "torn claim record")]
fn control_record_without_seqlock_fails() {
    record_model(false);
}

/// The single-attempt variant of the negative control.
fn single_attempt(first: &AtomicU64) -> bool {
    first
        .compare_exchange(
            0,
            aborted().pack().to_le(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// A writer that marks and then pauses forever.
fn paused_writer_model(two_attempts: bool) {
    loom::model(move || {
        let first = Arc::new(AtomicU64::new(0));
        let writer = {
            let first = Arc::clone(&first);
            thread::spawn(move || mark_block(&first, reserved()))
        };
        let conductor = {
            let first = Arc::clone(&first);
            thread::spawn(move || {
                if two_attempts {
                    deadline_abort(&first, EXTENT, Lane::ZERO, aborted())
                } else {
                    single_attempt(&first)
                }
            })
        };
        let marked = writer.join().unwrap();
        let won = conductor.join().unwrap();
        assert!(won, "an expired claim was left pending");
        let last = u64::from_le(first.load(Ordering::Acquire));
        assert_eq!(last, aborted().pack());
        // A writer whose mark lost wrote nothing; one that marked lost later.
        let _ = marked;
    });
}

#[test]
fn a_paused_claim_is_always_aborted() {
    paused_writer_model(true);
}

#[test]
#[should_panic(expected = "an expired claim was left pending")]
fn control_single_attempt_fails() {
    paused_writer_model(false);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Production,
    AbortByStore,
    ReleaseBeforeClear,
}

struct Shared {
    serial: AtomicU64,
    record: AtomicU64,
    first: AtomicU64,
    payload: UnsafeCell<u64>,
    loan: AtomicBool,
}

fn write_payload(shared: &Shared, value: u64) {
    shared.payload.with_mut(|payload| {
        // SAFETY: the pointer comes from a live `UnsafeCell`; Loom checks
        // that no access races with this write.
        unsafe { *payload = value }
    });
}

fn race_model(variant: Variant) {
    loom::model(move || {
        let shared = Arc::new(Shared {
            serial: AtomicU64::new(0),
            record: AtomicU64::new(0),
            first: AtomicU64::new(0),
            payload: UnsafeCell::new(0),
            loan: AtomicBool::new(true),
        });
        let writer = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                write_claim_record(&shared.serial, &shared.record, RECORD);
                let mut committed_ok = false;
                let marked = mark_block(&shared.first, reserved());
                if marked {
                    write_payload(&shared, PAYLOAD);
                    committed_ok = commit_block(&shared.first, reserved(), committed());
                }
                if variant == Variant::ReleaseBeforeClear {
                    shared.loan.store(false, Ordering::SeqCst);
                    write_claim_record(&shared.serial, &shared.record, 0);
                } else {
                    // Terminal, then the record goes, then the loan.
                    write_claim_record(&shared.serial, &shared.record, 0);
                    shared.loan.store(false, Ordering::SeqCst);
                }
                (marked, committed_ok)
            })
        };
        let conductor = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let mut won = false;
                if let Some((_, RECORD)) = read_claim_record(&shared.serial, &shared.record) {
                    won = if variant == Variant::AbortByStore {
                        shared
                            .first
                            .store(aborted().pack().to_le(), Ordering::Release);
                        true
                    } else {
                        deadline_abort(&shared.first, EXTENT, Lane::ZERO, aborted())
                    };
                }
                // As the cleaner, in a later duty cycle.
                if !shared.loan.load(Ordering::SeqCst) {
                    write_payload(&shared, 0);
                    let again = read_claim_record(&shared.serial, &shared.record);
                    assert!(
                        !matches!(again, Some((_, RECORD))),
                        "a cleaned block's record was seen again"
                    );
                }
                won
            })
        };
        let (marked, committed_ok) = writer.join().unwrap();
        let won = conductor.join().unwrap();
        assert!(!(committed_ok && won), "both outcomes won");
        if marked {
            assert!(committed_ok || won, "a marked claim was left pending");
        } else {
            assert!(won, "a mark lost to nobody");
        }
    });
}

#[test]
fn deadline_abort_races_the_writer() {
    race_model(Variant::Production);
}

#[test]
#[should_panic(expected = "both outcomes won")]
fn control_abort_by_plain_store_fails() {
    race_model(Variant::AbortByStore);
}

#[test]
#[should_panic(expected = "a cleaned block's record was seen again")]
fn control_release_before_clear_fails() {
    race_model(Variant::ReleaseBeforeClear);
}
