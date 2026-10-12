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
//! - the cross-call chain over the real loan primitives: the publication
//!   clears the record after the terminal compare-exchange and before
//!   `release_loan`; the single conductor aborts, reclaims with
//!   `begin_reclaim` and `loan_held`, cleans, reassigns the slot to a later
//!   term in which the publication claims the same offset and extent again,
//!   and never acts on the old claim's serial afterwards (explored with
//!   three preemptions);
//! - a claim paused after its mark stays abortable: its record is only
//!   cleared after its terminal compare-exchange.
//!
//! Negative controls must fail: a record written without the seqlock, a
//! single compare-exchange attempt, an abort by plain store, the loan
//! released before the record is cleared, and the record cleared before
//! the terminal compare-exchange.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::loan::{
    LoanOutcome, LoanTarget, activate, begin_cleaning, begin_reclaim, loan_held, publish,
    release_loan, take_loan,
};
use karyos_sys::publication::{
    commit_block, deadline_abort, mark_block, read_claim_record, write_claim_record,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Chain {
    Production,
    ReleaseBeforeClear,
}

struct Term {
    serial: AtomicU64,
    record: AtomicU64,
    first: AtomicU64,
    payload: UnsafeCell<u64>,
    descriptor: AtomicU64,
    loans: [AtomicU64; 1],
    revoked: AtomicU64,
}

impl Term {
    fn write_payload(&self, value: u64) {
        self.payload.with_mut(|payload| {
            // SAFETY: the pointer comes from a live `UnsafeCell`; Loom checks
            // that no access races with this write.
            unsafe { *payload = value }
        });
    }
}

fn target(count: u32) -> LoanTarget {
    LoanTarget::new(
        SlotIndex::try_new(1).unwrap(),
        Generation::try_new(1).unwrap(),
        TermId::new(0),
        TermCount::try_new(count).unwrap(),
    )
}

/// The publication claims in term 1, commits, clears its record and
/// releases its loan; in term 2 of the same slot it claims the same offset
/// and extent again and pauses. The single conductor aborts what its
/// snapshot names, reclaims term 1 when no loan matches it, cleans and
/// reassigns the slot, and takes a later snapshot.
///
/// Scope: three preemptions (the model has a publication with two terms
/// and a conductor that reclaims and reassigns; unbounded exploration does
/// not finish in reasonable time).
fn chain_model(variant: Chain) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(move || {
        let first_term = target(1);
        let active = Descriptor::new(
            first_term.term_id(),
            Generation::try_new(1).unwrap(),
            SlotState::Active,
        );
        let term = Arc::new(Term {
            serial: AtomicU64::new(0),
            record: AtomicU64::new(0),
            first: AtomicU64::new(0),
            payload: UnsafeCell::new(0),
            descriptor: AtomicU64::new(active.encode()),
            loans: [AtomicU64::new(0)],
            revoked: AtomicU64::new(0),
        });
        let [loan] = &term.loans;
        assert_eq!(
            take_loan(loan, &term.revoked, &term.descriptor, first_term).unwrap(),
            LoanOutcome::Granted
        );
        let publication = {
            let term = Arc::clone(&term);
            thread::spawn(move || {
                let [loan] = &term.loans;
                write_claim_record(&term.serial, &term.record, RECORD);
                if mark_block(&term.first, reserved()) {
                    term.write_payload(PAYLOAD);
                    let _ = commit_block(&term.first, reserved(), committed());
                }
                if variant == Chain::ReleaseBeforeClear {
                    release_loan(loan);
                    write_claim_record(&term.serial, &term.record, 0);
                } else {
                    write_claim_record(&term.serial, &term.record, 0);
                    release_loan(loan);
                }
                // The same offset and extent in the reused slot, if the
                // conductor has reassigned it already.
                if take_loan(loan, &term.revoked, &term.descriptor, target(2)).unwrap()
                    == LoanOutcome::Granted
                {
                    write_claim_record(&term.serial, &term.record, RECORD);
                    let _ = mark_block(&term.first, reserved());
                }
            })
        };
        // The single conductor, in three calls, on its own thread.
        let conductor = {
            let term = Arc::clone(&term);
            thread::spawn(move || {
                let old = read_claim_record(&term.serial, &term.record)
                    .filter(|(_, value)| *value == RECORD)
                    .map(|(serial, _)| serial);
                if old.is_some() {
                    let _ = deadline_abort(&term.first, EXTENT, Lane::ZERO, aborted());
                }
                let reclaiming = begin_reclaim(&term.descriptor, active).unwrap();
                if !loan_held(&term.loans, first_term.slot(), reclaiming).unwrap() {
                    let cleaning = begin_cleaning(&term.descriptor, reclaiming).unwrap();
                    term.write_payload(0);
                    term.first.store(0, Ordering::Relaxed);
                    publish(&term.descriptor, cleaning.with_state(SlotState::Free));
                    let ready =
                        Descriptor::new(target(2).term_id(), active.generation(), SlotState::Ready);
                    publish(&term.descriptor, ready);
                    activate(&term.descriptor, ready).unwrap();
                    // A later call: the old claim's serial never names the reused
                    // slot, so its timer and authority are gone.
                    if let (Some(old), Some((serial, RECORD))) =
                        (old, read_claim_record(&term.serial, &term.record))
                    {
                        assert_ne!(serial, old, "a cleaned claim's serial was seen again");
                    }
                    let stale = read_claim_record(&term.serial, &term.record);
                    assert!(
                        !matches!(stale, Some((2, RECORD))),
                        "a cleaned claim's serial was seen again"
                    );
                }
            })
        };
        conductor.join().unwrap();
        publication.join().unwrap();
    });
}

#[test]
fn the_record_chain_survives_cleaning_and_reuse() {
    chain_model(Chain::Production);
}

#[test]
#[should_panic(expected = "a cleaned claim's serial was seen again")]
fn control_chain_release_before_clear_fails() {
    chain_model(Chain::ReleaseBeforeClear);
}

/// A claim paused after its mark keeps its record until a terminal
/// compare-exchange, so the conductor still finds and aborts it.
fn paused_record_model(clear_before_terminal: bool) {
    loom::model(move || {
        let serial = Arc::new(AtomicU64::new(0));
        let record = Arc::new(AtomicU64::new(0));
        let first = Arc::new(AtomicU64::new(0));
        let writer = {
            let (serial, record, first) =
                (Arc::clone(&serial), Arc::clone(&record), Arc::clone(&first));
            thread::spawn(move || {
                write_claim_record(&serial, &record, RECORD);
                let marked = mark_block(&first, reserved());
                if clear_before_terminal {
                    write_claim_record(&serial, &record, 0);
                }
                marked
            })
        };
        let conductor = {
            let (serial, record, first) =
                (Arc::clone(&serial), Arc::clone(&record), Arc::clone(&first));
            thread::spawn(move || {
                matches!(read_claim_record(&serial, &record), Some((_, RECORD)))
                    && deadline_abort(&first, EXTENT, Lane::ZERO, aborted())
            })
        };
        let marked = writer.join().unwrap();
        let won = conductor.join().unwrap();
        // The writer is paused for good and never reached a terminal word:
        // either it marked and the word is still reserved, or the conductor
        // already won.
        let word = u64::from_le(first.load(Ordering::Acquire));
        assert!(won || (marked && word == reserved().pack()));
        // A later call, once the writer is paused for good.
        let later = won
            || (matches!(read_claim_record(&serial, &record), Some((_, RECORD)))
                && deadline_abort(&first, EXTENT, Lane::ZERO, aborted()));
        assert!(later, "a paused claim lost its abort");
        assert_eq!(
            u64::from_le(first.load(Ordering::Acquire)),
            aborted().pack()
        );
    });
}

#[test]
fn a_paused_claim_keeps_its_record() {
    paused_record_model(false);
}

#[test]
#[should_panic(expected = "a paused claim lost its abort")]
fn control_clear_before_terminal_fails() {
    paused_record_model(true);
}
