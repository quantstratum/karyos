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
//! sender reads it); and the sender releasing past its read cursor, so the
//! publisher can overwrite an entry before or while it is read (the same
//! race).
//!
//! A third model has the sender read ahead of what it releases, as it does
//! when it stages a message's first frame and frees its entry only after
//! the last fragment left (timed-tx.md section 2 step 4): it reads two
//! entries ahead, releases them in order across a wrap, and every entry it
//! reads is whole.
//!
//! A second model joins the ring to the block publication of the append
//! path (`karyos_sys::publication::publish_block` and `observe_block`, the
//! production commit store and its observation): the entry is pushed after
//! the reservation and before the block's first word is published, so a
//! sender that observes the committed block finds its entry (review of the
//! T1 step 3b design, ACS 15421). Its control publishes the block first.
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test model, as ADR-0007 allows in tests"
)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::publication::{observe_block, publish_block};
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
    /// Negative control: the sender releases past its read cursor, freeing
    /// a slot before reading its entry.
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
                    reader = reader.with_unchecked_release();
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
                        if variant == Variant::ReleaseFirst {
                            reader.release(&ring).unwrap();
                        }
                        // Retried after the commit, never consumed early.
                        let read = reader
                            .peek(&ring)
                            .unwrap()
                            .unwrap_or_else(|| panic!("entry missing for message {next}"));
                        assert_eq!(read, entry(next), "torn entry");
                        reader.advance(&ring).unwrap();
                        if variant != Variant::ReleaseFirst {
                            reader.release(&ring).unwrap();
                        }
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
fn control_a_release_past_the_read_cursor() {
    model(Variant::ReleaseFirst);
}

fn first_word() -> Word0 {
    Word0::new(
        48,
        Flags::new(true, true, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

/// The append path's order: entry, then the block's commit store.
fn commit_model(block_first: bool) {
    loom::model(move || {
        let words = ring_words(usize::try_from(CAPACITY).unwrap()).unwrap();
        let ring: Arc<Vec<AtomicU64>> = Arc::new((0..words).map(|_| AtomicU64::new(0)).collect());
        init(&ring, CAPACITY).unwrap();
        let block = Arc::new(AtomicU64::new(0));
        let writer = {
            let ring = Arc::clone(&ring);
            let block = Arc::clone(&block);
            thread::spawn(move || {
                let mut publisher = SchedulePublisher::attach(&ring).unwrap();
                assert!(publisher.has_room(&ring).unwrap());
                if block_first {
                    publish_block(&block, first_word());
                    publisher.push(&ring, entry(0)).unwrap();
                } else {
                    publisher.push(&ring, entry(0)).unwrap();
                    publish_block(&block, first_word());
                }
            })
        };
        let reader = ScheduleReader::attach(&ring).unwrap();
        if observe_block(&block) != 0 {
            let read = reader
                .peek(&ring)
                .unwrap()
                .unwrap_or_else(|| panic!("entry missing for a committed block"));
            assert_eq!(read, entry(0));
        }
        writer.join().unwrap();
    });
}

#[test]
fn a_committed_block_finds_its_entry() {
    commit_model(false);
}

#[test]
#[should_panic(expected = "entry missing")]
fn control_the_block_committed_before_its_entry() {
    commit_model(true);
}

/// The sender reads up to two entries ahead and releases in order; four
/// messages wrap a ring of two. With `past_cursor`, the negative control
/// releases one entry beyond what it read.
fn read_ahead_model(past_cursor: bool) {
    read_ahead_model_with(past_cursor, None, false);
}

/// The read-ahead model, with a rewind after each release when `rewind`
/// is set (`Some(true)` rewinds past `head`, the control): a rewind to
/// `head` reads again only entries still the ones written, whatever the
/// publisher does meanwhile, because a slot not released is never reused.
/// With `before_release`, it also rewinds right after reading ahead, with
/// nothing released since the last pass.
fn read_ahead_model_with(past_cursor: bool, rewind: Option<bool>, before_release: bool) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(move || {
        const AHEAD: u64 = 4;
        let words = ring_words(usize::try_from(CAPACITY).unwrap()).unwrap();
        let ring: Arc<Vec<AtomicU64>> = Arc::new((0..words).map(|_| AtomicU64::new(0)).collect());
        init(&ring, CAPACITY).unwrap();
        let witness: Witness = Arc::new((0..CAPACITY).map(|_| UnsafeCell::new(0)).collect());
        let sender = {
            let ring = Arc::clone(&ring);
            let witness = Arc::clone(&witness);
            thread::spawn(move || {
                let mut reader = ScheduleReader::attach(&ring).unwrap().with_witness(witness);
                if past_cursor {
                    reader = reader.with_unchecked_release();
                }
                if rewind == Some(true) {
                    reader = reader.with_rewind_past_head();
                }
                let mut read = 0;
                while reader.released() < AHEAD {
                    // Read ahead while entries are there.
                    while let Some(found) = reader.peek(&ring).unwrap() {
                        assert_eq!(found, entry(read), "torn entry");
                        reader.advance(&ring).unwrap();
                        read += 1;
                    }
                    if before_release && reader.read() > reader.released() {
                        reader.rewind_to_released();
                        read = reader.read();
                        while let Some(found) = reader.peek(&ring).unwrap() {
                            assert_eq!(found, entry(read), "torn entry");
                            reader.advance(&ring).unwrap();
                            read += 1;
                        }
                    }
                    // Free the oldest read entry, never past the cursor; the
                    // control frees one more.
                    let limit = reader.read() + u64::from(past_cursor);
                    if reader.released() < limit && reader.released() < AHEAD {
                        reader.release(&ring).unwrap();
                        if rewind.is_some() {
                            // A reliable sender's reset: read again from
                            // the oldest entry not released.
                            reader.rewind_to_released();
                            read = reader.read();
                        }
                    }
                    thread::yield_now();
                }
            })
        };
        let mut publisher = SchedulePublisher::attach(&ring)
            .unwrap()
            .with_witness(Arc::clone(&witness));
        for n in 0..AHEAD {
            while !publisher.has_room(&ring).unwrap() {
                thread::yield_now();
            }
            publisher.push(&ring, entry(n)).unwrap();
        }
        sender.join().unwrap();
    });
}

#[test]
fn reading_ahead_releases_in_order_across_a_wrap() {
    read_ahead_model(false);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn control_reading_ahead_with_a_release_past_the_cursor() {
    read_ahead_model(true);
}

#[test]
fn a_rewind_reads_only_entries_never_reused() {
    read_ahead_model_with(false, Some(false), false);
}

#[test]
fn a_rewind_after_reading_ahead_with_no_release_reads_the_same_entries() {
    read_ahead_model_with(false, Some(false), true);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn control_a_rewind_past_head() {
    read_ahead_model_with(false, Some(true), false);
}
