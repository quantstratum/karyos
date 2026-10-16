// SPDX-License-Identifier: Apache-2.0

//! Loom models of sealing (`quantstratum-docs: karyos/design/publication-seal.md`), over the
//! production helpers of `karyos_sys::publication`:
//!
//! - two concurrent publishers reserve with `fetch_add` on a shared tail
//!   while the conductor seals; each publisher, on an attempt the limit
//!   refuses, observes the seal and releases its publisher slot; the
//!   conductor positions the seal once both slots are free. The seal
//!   position equals the end of the last granted reservation, and no
//!   reservation is granted above it;
//! - one exclusive writer racing the seal, with the same property over
//!   `reserved_head` and the release flag;
//! - the exclusive issuance racing the seal: either the issuer is refused,
//!   or positioning waits for the issued writer's release;
//! - a seal for a cutover racing an issuer's read and a reader: every load
//!   that sees the seal sees its successor mark, and positioning keeps it;
//! - a seal with a reason racing a reader and the positioning: every load
//!   that sees the seal, sealed or positioned, then reads the reason.
//!
//! Negative controls must fail: a concurrent release stored before the
//! last `fetch_add`; positioning that loads the slot and the tail Relaxed;
//! an exclusive release stored before the last `reserved_head` store; an
//! issuance whose take and seal read are plain Acquire and Release
//! accesses instead of read-modify-writes; and a reason stored after the
//! seal's swap.
//!
//! Exploration: preemption bound 3; at most two granted reservations per
//! publisher, one conductor.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::publication::{
    PUBLISHER_HELD, SEAL_POSITION_MASK, SEAL_POSITIONED, SEAL_SEALED, SEAL_SUCCESSOR,
    issuer_sees_seal, observe_seal, position_seal, publication_released, publication_taken,
    publisher_slot_free, release_publication, release_publisher_slot, seal, seal_for_cutover,
    seal_has_successor, seal_reason, seal_with_reason, take_publication,
};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

/// Bounded exploration, as the other models with spin loops.
fn builder() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder
}

/// A limit no granted reservation reaches in these models.
const OPEN: u64 = 100;
const GRANTS: u64 = 2;

fn position(word: &AtomicU64) -> Option<u64> {
    let raw = word.load(Ordering::Acquire);
    (raw & SEAL_POSITIONED != 0).then_some(raw & SEAL_POSITION_MASK)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Concurrent {
    Correct,
    ReleaseBeforeLastReservation,
    RelaxedPositioning,
}

struct Shared {
    tail: AtomicU64,
    limit: AtomicU64,
    seal: AtomicU64,
    slots: [AtomicU64; 2],
}

fn concurrent_model(variant: Concurrent) {
    builder().check(move || {
        let shared = Arc::new(Shared {
            tail: AtomicU64::new(0),
            limit: AtomicU64::new(OPEN),
            seal: AtomicU64::new(0),
            slots: [
                AtomicU64::new(PUBLISHER_HELD),
                AtomicU64::new(PUBLISHER_HELD),
            ],
        });
        let publishers: Vec<_> = (0..2)
            .map(|index| {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    let slot = &shared.slots[index];
                    let mut granted = 0;
                    loop {
                        // The production check: head plus one within the
                        // limit, then one `fetch_add`.
                        let head = shared.tail.load(Ordering::Acquire);
                        if granted < GRANTS && head + 1 <= shared.limit.load(Ordering::Acquire) {
                            if variant == Concurrent::ReleaseBeforeLastReservation
                                && granted + 1 == GRANTS
                            {
                                release_publisher_slot(slot, 0);
                                let _ = shared.tail.fetch_add(1, Ordering::AcqRel);
                                return;
                            }
                            let _ = shared.tail.fetch_add(1, Ordering::AcqRel);
                            granted += 1;
                            continue;
                        }
                        if granted == GRANTS || observe_seal(&shared.seal) {
                            // Closed, or done and dropped: the last access.
                            release_publisher_slot(slot, 0);
                            return;
                        }
                        thread::yield_now();
                    }
                })
            })
            .collect();
        let conductor = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                seal(&shared.seal, &shared.limit);
                loop {
                    let free = match variant {
                        Concurrent::RelaxedPositioning => shared
                            .slots
                            .iter()
                            .all(|word| word.load(Ordering::Relaxed) & PUBLISHER_HELD == 0),
                        _ => shared.slots.iter().all(publisher_slot_free),
                    };
                    if free {
                        let ordering = match variant {
                            Concurrent::RelaxedPositioning => Ordering::Relaxed,
                            _ => Ordering::Acquire,
                        };
                        position_seal(&shared.seal, shared.tail.load(ordering));
                        return;
                    }
                    thread::yield_now();
                }
            })
        };
        for publisher in publishers {
            publisher.join().unwrap();
        }
        conductor.join().unwrap();
        let sealed_at = position(&shared.seal).unwrap();
        assert_eq!(
            sealed_at,
            shared.tail.load(Ordering::Acquire),
            "a reservation was granted above the seal position"
        );
    });
}

#[test]
fn the_concurrent_seal_position_is_the_last_granted_end() {
    concurrent_model(Concurrent::Correct);
}

#[test]
#[should_panic(expected = "a reservation was granted above the seal position")]
fn control_a_release_before_the_last_reservation() {
    concurrent_model(Concurrent::ReleaseBeforeLastReservation);
}

#[test]
#[should_panic(expected = "a reservation was granted above the seal position")]
fn control_relaxed_positioning() {
    concurrent_model(Concurrent::RelaxedPositioning);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Exclusive {
    Correct,
    ReleaseBeforeLastHead,
}

struct Writer {
    head: AtomicU64,
    limit: AtomicU64,
    seal: AtomicU64,
    released: AtomicU64,
}

fn exclusive_model(variant: Exclusive) {
    builder().check(move || {
        let shared = Arc::new(Writer {
            head: AtomicU64::new(0),
            limit: AtomicU64::new(OPEN),
            seal: AtomicU64::new(0),
            released: AtomicU64::new(0),
        });
        let writer = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                // The writer's own head: plain program state in production.
                let mut end = 0;
                loop {
                    if end < GRANTS && end + 1 <= shared.limit.load(Ordering::Acquire) {
                        end += 1;
                        if variant == Exclusive::ReleaseBeforeLastHead && end == GRANTS {
                            release_publication(&shared.released);
                            shared.head.store(end, Ordering::Release);
                            return;
                        }
                        shared.head.store(end, Ordering::Release);
                        continue;
                    }
                    if end == GRANTS || observe_seal(&shared.seal) {
                        release_publication(&shared.released);
                        return;
                    }
                    thread::yield_now();
                }
            })
        };
        let conductor = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                seal(&shared.seal, &shared.limit);
                while !publication_released(&shared.released) {
                    thread::yield_now();
                }
                position_seal(&shared.seal, shared.head.load(Ordering::Acquire));
            })
        };
        writer.join().unwrap();
        conductor.join().unwrap();
        assert_eq!(
            position(&shared.seal).unwrap(),
            shared.head.load(Ordering::Acquire),
            "a reservation was granted above the seal position"
        );
    });
}

#[test]
fn the_exclusive_seal_position_is_the_last_granted_end() {
    exclusive_model(Exclusive::Correct);
}

#[test]
#[should_panic(expected = "a reservation was granted above the seal position")]
fn control_an_exclusive_release_before_the_last_head() {
    exclusive_model(Exclusive::ReleaseBeforeLastHead);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Issuance {
    ReadModifyWrite,
    PlainAccesses,
}

struct Issued {
    taken: AtomicU64,
    head: AtomicU64,
    limit: AtomicU64,
    seal: AtomicU64,
    released: AtomicU64,
}

fn issuance_model(variant: Issuance) {
    builder().check(move || {
        let shared = Arc::new(Issued {
            taken: AtomicU64::new(0),
            head: AtomicU64::new(0),
            limit: AtomicU64::new(OPEN),
            seal: AtomicU64::new(0),
            released: AtomicU64::new(0),
        });
        let issuer = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let refused = match variant {
                    Issuance::ReadModifyWrite => {
                        assert!(take_publication(&shared.taken));
                        issuer_sees_seal(&shared.seal)
                    }
                    Issuance::PlainAccesses => {
                        shared.taken.store(1, Ordering::Release);
                        shared.seal.load(Ordering::Acquire) != 0
                    }
                };
                if refused {
                    release_publication(&shared.released);
                    return;
                }
                // Issued: one reservation if the limit admits it, then
                // attempts until the seal is observed.
                if shared.limit.load(Ordering::Acquire) >= 1 {
                    shared.head.store(1, Ordering::Release);
                }
                while !observe_seal(&shared.seal) {
                    thread::yield_now();
                }
                release_publication(&shared.released);
            })
        };
        let conductor = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                match variant {
                    Issuance::ReadModifyWrite => seal(&shared.seal, &shared.limit),
                    Issuance::PlainAccesses => {
                        shared.seal.store(1 << 63, Ordering::Release);
                        shared.limit.store(0, Ordering::Release);
                    }
                }
                loop {
                    let taken = match variant {
                        Issuance::ReadModifyWrite => publication_taken(&shared.taken),
                        Issuance::PlainAccesses => shared.taken.load(Ordering::Acquire) != 0,
                    };
                    if !taken || publication_released(&shared.released) {
                        position_seal(&shared.seal, shared.head.load(Ordering::Acquire));
                        return;
                    }
                    thread::yield_now();
                }
            })
        };
        issuer.join().unwrap();
        conductor.join().unwrap();
        assert_eq!(
            position(&shared.seal).unwrap(),
            shared.head.load(Ordering::Acquire),
            "the issued writer reserved above the seal position"
        );
    });
}

#[test]
fn issuance_and_seal_observe_each_other() {
    issuance_model(Issuance::ReadModifyWrite);
}

#[test]
#[should_panic(expected = "the issued writer reserved above the seal position")]
fn control_plain_issuance_accesses() {
    issuance_model(Issuance::PlainAccesses);
}

/// A cutover seal and its positioning race an issuer's read-modify-write
/// and a reader: whenever a load sees the seal, it sees the successor mark
/// in the same load, and the positioned word keeps the mark and the exact
/// position.
#[test]
fn a_cutover_seal_is_seen_with_its_successor_and_positioning_keeps_it() {
    builder().check(|| {
        let shared = Arc::new(Shared {
            tail: AtomicU64::new(0),
            limit: AtomicU64::new(OPEN),
            seal: AtomicU64::new(0),
            slots: [AtomicU64::new(0), AtomicU64::new(0)],
        });
        let conductor = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                seal_for_cutover(&shared.seal, &shared.limit);
                position_seal(&shared.seal, 7);
            })
        };
        let issuer = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let _ = issuer_sees_seal(&shared.seal);
            })
        };
        for _ in 0..2 {
            let raw = shared.seal.load(Ordering::Acquire);
            if raw & SEAL_SEALED != 0 {
                assert!(seal_has_successor(raw), "a seal seen without its mark");
            }
            thread::yield_now();
        }
        conductor.join().unwrap();
        issuer.join().unwrap();
        let raw = shared.seal.load(Ordering::Acquire);
        assert_eq!(
            raw,
            SEAL_SEALED | SEAL_POSITIONED | SEAL_SUCCESSOR | 7,
            "positioning lost the mark or the position"
        );
        assert_eq!(position(&shared.seal), Some(7));
    });
}

/// A final seal never carries the mark.
#[test]
fn a_final_seal_has_no_successor() {
    builder().check(|| {
        let word = AtomicU64::new(0);
        let limit = AtomicU64::new(OPEN);
        seal(&word, &limit);
        assert!(!seal_has_successor(word.load(Ordering::Acquire)));
        position_seal(&word, 3);
        assert!(!seal_has_successor(word.load(Ordering::Acquire)));
        assert_eq!(position(&word), Some(3));
    });
}

/// Negative control: positioning with a plain swap of the positioned value,
/// as before the successor mark, loses the mark.
#[test]
#[should_panic(expected = "positioning lost the mark")]
fn control_positioning_with_a_plain_swap() {
    builder().check(|| {
        let word = AtomicU64::new(0);
        let limit = AtomicU64::new(OPEN);
        seal_for_cutover(&word, &limit);
        let _ = word.swap(SEAL_SEALED | SEAL_POSITIONED | 7, Ordering::AcqRel);
        assert!(
            seal_has_successor(word.load(Ordering::Acquire)),
            "positioning lost the mark"
        );
    });
}

#[derive(Clone, Copy)]
enum Reason {
    /// The production order: the reason, then the seal's swap.
    BeforeTheSwap,
    /// Negative control: the swap, then the reason.
    AfterTheSwap,
}

/// The conductor seals with reason code 2 and then positions the seal; a
/// reader polls the seal word by Acquire. Whenever it sees the seal, sealed
/// or already positioned, it reads the reason.
fn reason_model(order: Reason) {
    reason_model_with(order, 2);
}

/// As [`reason_model`], with reason `code`.
fn reason_model_with(order: Reason, code: u64) {
    builder().check(move || {
        let words = Arc::new((AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(1)));
        let reader = {
            let words = Arc::clone(&words);
            thread::spawn(move || {
                let (seal_word, reason_word, _) = &*words;
                if seal_word.load(Ordering::Acquire) & SEAL_SEALED != 0 {
                    assert_eq!(
                        seal_reason(reason_word),
                        code,
                        "the seal was seen without its reason"
                    );
                }
            })
        };
        let (seal_word, reason_word, limit) = &*words;
        match order {
            Reason::BeforeTheSwap => seal_with_reason(seal_word, reason_word, limit, code),
            Reason::AfterTheSwap => {
                seal(seal_word, limit);
                reason_word.store(code, Ordering::Relaxed);
            }
        }
        position_seal(seal_word, 64);
        reader.join().unwrap();
    });
}

#[test]
fn a_seal_is_never_seen_without_its_reason() {
    reason_model(Reason::BeforeTheSwap);
}

#[test]
#[should_panic(expected = "the seal was seen without its reason")]
fn control_a_reason_stored_after_the_swap() {
    reason_model(Reason::AfterTheSwap);
}

/// A guard close seals with `GuardClosed` (5): an offer that finds the seal
/// always reads the gate reason, so it reports `Gated`, never `Closed`
/// (guards-and-abort.md, GC-8).
#[test]
fn a_guard_seal_is_never_seen_without_its_reason() {
    reason_model_with(Reason::BeforeTheSwap, 5);
}

#[test]
#[should_panic(expected = "the seal was seen without its reason")]
fn control_a_guard_reason_stored_after_the_swap() {
    reason_model_with(Reason::AfterTheSwap, 5);
}
