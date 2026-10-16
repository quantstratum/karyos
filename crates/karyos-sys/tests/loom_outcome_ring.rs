// SPDX-License-Identifier: Apache-2.0

//! Loom model of the outcome ring of `karyos_sys::outcome_ring`
//! (`quantstratum-docs: karyos/design/guards-and-abort.md`, G5 and GC-4),
//! over the production writer and reader.
//!
//! A ring of two slots (one ordinary record of room plus the reserved
//! slot): the driver writes three records, each only once the client's
//! reservation allows it (the consumed count shows room), so the ring
//! wraps twice. A concurrent client polls and publishes its consumed
//! count. Every record it delivers must be whole (its fields belong to the
//! sequence it was read as) and in order, and the writer never faults a
//! protocol-following client. Negative control: a writer that stores the
//! sequence before the fields lets the client read a torn record.
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a test model, as ADR-0007 allows in tests"
)]

use karyos_sys::outcome_ring::{
    HEADER_WORDS, Kind, OutcomeReader, OutcomeWriter, Produced, RECORD_WORDS, Record, init,
    ring_words,
};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

const CAPACITY: u64 = 2;
const RECORDS: u64 = 3;

fn record(sequence: u64) -> Record {
    Record {
        kind: Kind::Submitted,
        lane: 0,
        receiver: 0,
        incarnation: 1,
        start: sequence * 64,
        end: sequence * 64 + 64,
        epoch: 2,
        reason: 0,
        lost: 0,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Writer {
    Production,
    /// Negative control: the sequence is stored before the fields.
    SequenceFirst,
}

/// Writes `record` as `sequence` with the sequence first (the control).
fn write_sequence_first(ring: &[AtomicU64], sequence: u64, record: Record) {
    let slot = usize::try_from((sequence - 1) % CAPACITY).unwrap();
    let base = HEADER_WORDS + slot * RECORD_WORDS;
    ring[base].store(sequence, Ordering::Release);
    let fields = [
        u64::from(record.kind as u8),
        record.incarnation,
        record.start,
        record.end,
        record.epoch,
        record.reason,
        record.lost,
    ];
    for (offset, value) in fields.into_iter().enumerate() {
        ring[base + 1 + offset].store(value, Ordering::Relaxed);
    }
}

fn model(writer_kind: Writer) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(move || {
        let words = ring_words(usize::try_from(CAPACITY).unwrap()).unwrap();
        let ring: Arc<Vec<AtomicU64>> = Arc::new((0..words).map(|_| AtomicU64::new(0)).collect());
        init(&ring, CAPACITY).unwrap();
        let consumed = Arc::new(AtomicU64::new(0));
        let client = {
            let ring = Arc::clone(&ring);
            let consumed = Arc::clone(&consumed);
            thread::spawn(move || {
                let mut reader = OutcomeReader::attach(&ring.as_slice(), 1).unwrap();
                let mut next = 1;
                while next <= RECORDS {
                    let _ = reader
                        .poll(&ring.as_slice(), &consumed, 1, |sequence, read| {
                            assert_eq!(sequence, next, "out of order");
                            assert_eq!(read, record(sequence), "torn record");
                            next += 1;
                        })
                        .unwrap_or_else(|error| panic!("torn record: {error}"));
                    thread::yield_now();
                }
            })
        };
        let mut writer = OutcomeWriter::new(CAPACITY).unwrap();
        for sequence in 1..=RECORDS {
            // The client's reservation: at most `CAPACITY - 1` unread.
            while consumed.load(Ordering::Acquire) + (CAPACITY - 1) < sequence {
                thread::yield_now();
            }
            match writer_kind {
                Writer::Production => assert_eq!(
                    writer.produce(&ring, &consumed, record(sequence)).unwrap(),
                    Produced::Written(sequence),
                    "a protocol-following client was faulted"
                ),
                Writer::SequenceFirst => write_sequence_first(&ring, sequence, record(sequence)),
            }
        }
        client.join().unwrap();
    });
}

#[test]
fn the_client_reads_whole_records_in_order() {
    model(Writer::Production);
}

#[test]
#[should_panic(expected = "torn record")]
fn control_the_sequence_stored_before_the_fields() {
    model(Writer::SequenceFirst);
}
