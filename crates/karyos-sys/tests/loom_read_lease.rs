// SPDX-License-Identifier: Apache-2.0

//! Loom model of the read lease (R-CORE-45; SPEC.md §16.6, §16.7): a lease
//! is a loan held past the call that took it and ended by a release from
//! another thread, as a backend's completion or a NIC driver's free
//! callback does. Reclaim races a lease released on another thread and a
//! second lease taken concurrently on the same term; in every
//! interleaving, a granted lease reads the term's bytes unchanged until it
//! ends, and cleaning never starts while a lease of the term is live.
//!
//! Term bytes are a plain value in a Loom `UnsafeCell`, as in
//! `loom_loan_reclaim`: Loom reports any access not ordered by
//! happens-before, so the model checks the synchronization, not only the
//! values.
//!
//! Run with `RUSTFLAGS="--cfg loom" cargo test -p karyos-sys --test
//! loom_read_lease --release`.

#![cfg(loom)]

use karyos_sys::loan::{
    LoanOutcome, LoanTarget, begin_cleaning, begin_reclaim, claim_lease, loan_held, publish,
    release_loan,
};
use karyos_sys::slot::{Descriptor, SlotIndex, SlotState};
use karyos_sys::sync::{AtomicU64, Ordering};
use karyos_sys::term::{Generation, TermCount, TermId};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

/// Payload value of the leased term.
const TERM_BYTES: u64 = 7;
/// Value the cleaner zeroes the slot to.
const CLEANED_BYTES: u64 = 0;

struct Slot {
    descriptor: AtomicU64,
    /// A bank of two lease words.
    leases: [AtomicU64; 2],
    revoked: AtomicU64,
    bytes: UnsafeCell<u64>,
}

impl Slot {
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

fn fixture() -> (Arc<Slot>, LoanTarget, Descriptor) {
    let slot = SlotIndex::try_new(1).unwrap();
    let generation = Generation::try_new(1).unwrap();
    let initial = TermId::new(5);
    let count = TermCount::try_new(0).unwrap();
    let target = LoanTarget::new(slot, generation, initial, count);
    let active = Descriptor::new(target.term_id(), generation, SlotState::Active);
    let shared = Arc::new(Slot {
        descriptor: AtomicU64::new(active.encode()),
        leases: [AtomicU64::new(0), AtomicU64::new(0)],
        revoked: AtomicU64::new(0),
        bytes: UnsafeCell::new(TERM_BYTES),
    });
    (shared, target, active)
}

/// Takes a lease in the first free word of the bank; `Some(word)` when it
/// is granted.
fn lease(shared: &Slot, target: LoanTarget) -> Option<usize> {
    for (index, word) in shared.leases.iter().enumerate() {
        match claim_lease(word, &shared.revoked, &shared.descriptor, target).unwrap() {
            None => {}
            Some(LoanOutcome::Granted) => return Some(index),
            // Refused: `claim_lease` emptied the word (another taker may
            // claim it again at once).
            Some(_) => return None,
        }
    }
    None
}

/// The driver's reclaim: cleans only when no lease pins the term.
fn reclaim(shared: &Slot, target: LoanTarget, active: Descriptor) -> bool {
    let reclaiming = begin_reclaim(&shared.descriptor, active).unwrap();
    if loan_held(&shared.leases, target.slot(), reclaiming).unwrap() {
        return false;
    }
    let cleaning = begin_cleaning(&shared.descriptor, reclaiming).unwrap();
    shared.write_bytes(CLEANED_BYTES);
    publish(&shared.descriptor, cleaning.with_state(SlotState::Free));
    true
}

/// A lease taken on one thread and released on another (the backend's
/// completion) against reclaim, with a second lease taken and released
/// concurrently on the same term.
#[test]
fn a_lease_released_elsewhere_and_a_concurrent_lease_versus_reclaim() {
    loom::model(|| {
        let (shared, target, active) = fixture();
        let sender = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let Some(index) = lease(&shared, target) else {
                    return;
                };
                // Handed to the backend, which reads and then releases.
                let backend = {
                    let shared = Arc::clone(&shared);
                    thread::spawn(move || {
                        assert_eq!(shared.read_bytes(), TERM_BYTES);
                        release_loan(&shared.leases[index]);
                    })
                };
                backend.join().unwrap();
            })
        };
        let second = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                if let Some(index) = lease(&shared, target) {
                    assert_eq!(shared.read_bytes(), TERM_BYTES);
                    release_loan(&shared.leases[index]);
                }
            })
        };
        let _ = reclaim(&shared, target, active);
        sender.join().unwrap();
        second.join().unwrap();
    });
}

/// A slot quarantined by a live lease is cleaned once the lease, released
/// on another thread, ends: the reclaim retried after it never races the
/// lease's reads.
#[test]
fn a_quarantined_term_is_cleaned_after_the_lease_ends() {
    loom::model(|| {
        let (shared, target, active) = fixture();
        let index = lease(&shared, target).expect("granted before any reclaim");
        let backend = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                assert_eq!(shared.read_bytes(), TERM_BYTES);
                release_loan(&shared.leases[index]);
            })
        };
        let reclaiming = begin_reclaim(&shared.descriptor, active).unwrap();
        while loan_held(&shared.leases, target.slot(), reclaiming).unwrap() {
            thread::yield_now();
        }
        let cleaning = begin_cleaning(&shared.descriptor, reclaiming).unwrap();
        shared.write_bytes(CLEANED_BYTES);
        publish(&shared.descriptor, cleaning.with_state(SlotState::Free));
        backend.join().unwrap();
    });
}

/// A lease asked after reclaim began is refused, and leaves its word empty.
#[test]
fn no_lease_is_granted_once_reclaiming() {
    loom::model(|| {
        let (shared, target, active) = fixture();
        let _ = begin_reclaim(&shared.descriptor, active).unwrap();
        let taker = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || lease(&shared, target))
        };
        assert_eq!(taker.join().unwrap(), None);
        assert!(
            shared
                .leases
                .iter()
                .all(|word| word.load(Ordering::SeqCst) == 0)
        );
    });
}
