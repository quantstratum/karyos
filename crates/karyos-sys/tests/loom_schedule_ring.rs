// SPDX-License-Identifier: Apache-2.0

//! Loom model of a timed lane's schedule ring (`karyos_sys::schedule_ring`;
//! `quantstratum-docs: karyos/design/timed-tx.md`, section 2 and section
//! 8 "Schedule ring", TT-1), over the production publisher and reader.
//!
//! A ring of two entries: the publisher schedules three messages, so the
//! ring wraps. For each message it checks room (the head with Acquire),
//! pushes the entry (Relaxed words, then the tail with Release) and then
//! commits the message, modelled by a commit count stored with Release.
//! The harness waits for room with Relaxed loads, so only the publisher's
//! own Acquire of the head orders a slot's reuse. The sender takes each
//! committed message (the commit count with Acquire), reads its entry and
//! releases it. The sender also reads the ring before it looks at the
//! commit: a read that finds nothing is retried after the commit is seen,
//! and one that finds an entry must find the message's own, never a stale
//! one left in the slot by an earlier lap. Each slot has an ownership witness (a Loom `UnsafeCell`)
//! written by `push` and read by `peek`, with no other synchronization.
//!
//! Every committed message the sender sees must find its own entry, whole.
//!
//! Negative controls, each of which must fail: the frame committed before
//! its entry is pushed ("entry missing" or a torn entry); the publisher's
//! head loaded Relaxed (a race on the witness: a slot rewritten while the
//! sender reads it); and the sender storing the head before it has read the
//! entry, so the publisher can overwrite it mid-read (the same race).
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test model, as ADR-0007 allows in tests"
)]

use karyos_sys::schedule_ring::{
    Entry, SchedulePublisher, ScheduleReader, Witness, init, ring_words,
};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

const CAPACITY: u64 = 2;
const MESSAGES: u64 = 3;

fn entry(n: u64) -> Entry {
    Entry {
        position: n * 64,
        time: 1_000 + n,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Production,
    /// Negative control: the message is committed before its entry.
    CommitFirst,
    /// Negative control: the publisher loads the head Relaxed.
    RelaxedHead,
    /// Negative control: the sender stores the head before reading.
    ReleaseFirst,
}

fn model(variant: Variant) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(move || {
        let words = ring_words(usize::try_from(CAPACITY).unwrap()).unwrap();
        let ring: Arc<Vec<AtomicU64>> = Arc::new((0..words).map(|_| AtomicU64::new(0)).collect());
        init(&ring, CAPACITY).unwrap();
        let committed = Arc::new(AtomicU64::new(0));
        let witness: Witness = Arc::new((0..CAPACITY).map(|_| UnsafeCell::new(0)).collect());
        let sender = {
            let ring = Arc::clone(&ring);
            let committed = Arc::clone(&committed);
            let witness = Arc::clone(&witness);
            thread::spawn(move || {
                let mut reader = ScheduleReader::attach(&ring).unwrap().with_witness(witness);
                if variant == Variant::ReleaseFirst {
                    reader = reader.with_release_first();
                }
                let mut next = 0;
                while next < MESSAGES {
                    // A read before the commit is seen: nothing, or the
                    // message's own entry, never a stale one.
                    let early = if variant == Variant::ReleaseFirst {
                        None
                    } else {
                        reader.peek(&ring).unwrap()
                    };
                    if let Some(early) = early {
                        assert_eq!(early, entry(next), "stale entry");
                    }
                    if committed.load(Ordering::Acquire) > next {
                        // Retried after the commit, never consumed early.
                        let read = reader
                            .peek(&ring)
                            .unwrap()
                            .unwrap_or_else(|| panic!("entry missing for message {next}"));
                        assert_eq!(read, entry(next), "torn entry");
                        reader.release(&ring).unwrap();
                        next += 1;
                    }
                    thread::yield_now();
                }
            })
        };
        let mut publisher = SchedulePublisher::attach(&ring)
            .unwrap()
            .with_witness(Arc::clone(&witness));
        if variant == Variant::RelaxedHead {
            publisher = publisher.with_head_load(Ordering::Relaxed);
        }
        for n in 0..MESSAGES {
            // Wait for room with Relaxed loads: they order nothing.
            while !publisher.has_room(&ring).unwrap() {
                thread::yield_now();
            }
            if variant == Variant::CommitFirst {
                committed.store(n + 1, Ordering::Release);
                publisher.push(&ring, entry(n)).unwrap();
            } else {
                publisher.push(&ring, entry(n)).unwrap();
                committed.store(n + 1, Ordering::Release);
            }
        }
        sender.join().unwrap();
    });
}

#[test]
fn every_committed_message_finds_its_entry() {
    model(Variant::Production);
}

#[test]
#[should_panic(expected = "entry missing")]
fn control_the_message_committed_before_its_entry() {
    model(Variant::CommitFirst);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn control_a_relaxed_head_load() {
    model(Variant::RelaxedHead);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn control_the_head_released_before_the_read() {
    model(Variant::ReleaseFirst);
}
