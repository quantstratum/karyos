// SPDX-License-Identifier: Apache-2.0

//! Loom models of the record journal of `karyos_sys::record_journal`, over
//! the production `JournalWords`.
//!
//! - **Slot reuse.** A two-slot journal and three records, so a slot is
//!   reused. Each slot has an ownership witness (a Loom `UnsafeCell`) that
//!   the writer writes at its reuse point and the consumer reads during its
//!   copy, with no other synchronization: a weakened `head` or `consumed`
//!   handoff shows up as a race on the witness or a torn record.
//! - **Range eviction.** One drop-range entry, so every new range evicts the
//!   previous one into the watermark while a reader takes a loss snapshot:
//!   every dropped sequence below the snapshot's horizon is covered by an
//!   accepted range or the watermark, or the snapshot reports an unstable
//!   entry.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::record_journal::{
    Append, CONTROL_WORDS, DropRange, JournalWords, Next, RANGE_WORDS, Stamp,
};
use karyos_sys::sync::AtomicU64;
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

struct Journal {
    records: Vec<AtomicU64>,
    control: Vec<AtomicU64>,
    ranges: Vec<AtomicU64>,
    witness: Vec<UnsafeCell<u64>>,
}

impl Journal {
    fn new(capacity: usize, payload_words: usize, ranges: usize) -> Arc<Self> {
        let words = |count: usize| (0..count).map(|_| AtomicU64::new(0)).collect();
        Arc::new(Self {
            records: words(capacity * (payload_words + 1)),
            control: words(CONTROL_WORDS),
            ranges: words(ranges * RANGE_WORDS),
            witness: (0..capacity).map(|_| UnsafeCell::new(u64::MAX)).collect(),
        })
    }

    fn words(&self, payload_words: usize) -> JournalWords<'_> {
        JournalWords::new(&self.records, &self.control, &self.ranges, payload_words)
            .unwrap()
            .with_witness(&self.witness)
    }
}

fn stamp(time: u64, epoch: u64) -> Stamp {
    Stamp {
        time,
        clock: 1,
        epoch,
    }
}

#[test]
fn reused_slots_are_never_overwritten_while_read() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(|| {
        let journal = Journal::new(2, 1, 1);
        let writer = {
            let journal = Arc::clone(&journal);
            thread::spawn(move || {
                let words = journal.words(1);
                let mut stored = 0;
                let mut time = 0;
                while stored < 3 {
                    time += 1;
                    match words.append(&[100 + stored], stamp(time, 0)).unwrap() {
                        Append::Stored { .. } => stored += 1,
                        Append::Dropped { .. } => thread::yield_now(),
                    }
                }
            })
        };
        let consumer = {
            let journal = Arc::clone(&journal);
            thread::spawn(move || {
                let words = journal.words(1);
                let mut out = [0u64; 1];
                let mut received = 0;
                while received < 3 {
                    match words.take(&mut out).unwrap() {
                        Next::Record { .. } => {
                            assert_eq!(out[0], 100 + received, "records arrive whole, in order");
                            received += 1;
                        }
                        Next::Empty | Next::Closed => thread::yield_now(),
                    }
                }
            })
        };
        writer.join().unwrap();
        consumer.join().unwrap();
    });
}

#[test]
fn evicted_ranges_stay_covered() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(|| {
        let journal = Journal::new(1, 1, 1);
        // Sequence 0 fills the only slot; 1 and 2 are dropped, each in a
        // new epoch, so the second range evicts the first into the
        // watermark.
        journal.words(1).append(&[0], stamp(0, 0)).unwrap();
        let writer = {
            let journal = Arc::clone(&journal);
            thread::spawn(move || {
                let words = journal.words(1);
                for sequence in 1..3 {
                    assert_eq!(
                        words.append(&[sequence], stamp(sequence, sequence)),
                        Ok(Append::Dropped { sequence })
                    );
                }
            })
        };
        // The reader runs on its own thread: Loom explores too little when
        // the racing side runs on the model's main thread.
        let reader = {
            let journal = Arc::clone(&journal);
            thread::spawn(move || {
                let words = journal.words(1);
                let mut ranges = [DropRange::default(); 1];
                let snapshot = words.losses(&mut ranges);
                if snapshot.unstable == 0 {
                    for sequence in 1..snapshot.attempted {
                        let in_range = ranges[..snapshot.ranges]
                            .iter()
                            .any(|range| (range.first..=range.last).contains(&sequence));
                        let below_watermark =
                            snapshot.lost_before.is_some_and(|mark| sequence < mark);
                        assert!(
                            in_range || below_watermark,
                            "dropped sequence {sequence} below the horizon {} is not covered",
                            snapshot.attempted
                        );
                    }
                }
            })
        };
        reader.join().unwrap();
        writer.join().unwrap();
    });
}
