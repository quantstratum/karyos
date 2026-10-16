// SPDX-License-Identifier: Apache-2.0

//! Loom model of the outcome ring of `karyos_sys::outcome_ring`
//! (`quantstratum-docs: karyos/design/guards-and-abort.md`, G5 and GC-4),
//! over the production writer and reader.
//!
//! A ring of two slots (one ordinary record of room plus the reserved
//! slot): the driver writes three records, each only once the client's
//! reservation allows it, so the ring wraps twice. The harness waits for
//! that reservation with a Relaxed load, so only the writer's own Acquire
//! load of the consumed count orders a slot's reuse. A concurrent client
//! polls and publishes its consumed count. Each slot has an ownership
//! witness (a Loom `UnsafeCell`) that the writer writes after validating
//! the room and before storing the record, and the reader reads before
//! publishing its count, with no other synchronization. Every record the
//! client delivers must be whole and in order, and the writer never faults
//! a protocol-following client.
//!
//! Negative controls, each of which must fail: the sequence stored before
//! the fields (a torn record); the writer's consumed load weakened to
//! Relaxed, and the client's consumed store weakened to Relaxed (a race on
//! the witness: a slot rewritten while its record is read).
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    unsafe_code,
    reason = "a test model, as ADR-0007 allows in tests"
)]

use karyos_sys::outcome_ring::{
    HEADER_WORDS, Kind, OutcomeReader, OutcomeWriter, Produced, RECORD_WORDS, Record, Witness,
    init, ring_words,
};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::cell::UnsafeCell;
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
enum Variant {
    Production,
    /// Negative control: the sequence is stored before the fields.
    SequenceFirst,
    /// Negative control: the writer loads the consumed count Relaxed.
    RelaxedLoad,
    /// Negative control: the client stores the consumed count Relaxed.
    RelaxedStore,
}

/// Writes `record` as `sequence` with the sequence first (the control).
/// The control writes the slot's witness as `produce` does, after an
/// Acquire load of the consumed count, so only the store order differs
/// from production and only a torn record can fail it.
fn write_sequence_first(
    ring: &[AtomicU64],
    consumed: &AtomicU64,
    witness: &Witness,
    sequence: u64,
    record: Record,
) {
    let _ = consumed.load(Ordering::Acquire);
    let slot = usize::try_from((sequence - 1) % CAPACITY).unwrap();
    // SAFETY: as the writer's witness write; Loom checks the order.
    witness[slot].with_mut(|value| unsafe { *value = sequence });
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

fn model(variant: Variant) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(move || {
        let words = ring_words(usize::try_from(CAPACITY).unwrap()).unwrap();
        let ring: Arc<Vec<AtomicU64>> = Arc::new((0..words).map(|_| AtomicU64::new(0)).collect());
        init(&ring, CAPACITY).unwrap();
        let consumed = Arc::new(AtomicU64::new(0));
        let witness: Witness = Arc::new((0..CAPACITY).map(|_| UnsafeCell::new(0)).collect());
        let client = {
            let ring = Arc::clone(&ring);
            let consumed = Arc::clone(&consumed);
            let witness = Arc::clone(&witness);
            thread::spawn(move || {
                let mut reader = OutcomeReader::attach(&ring.as_slice(), 1)
                    .unwrap()
                    .with_witness(witness);
                if variant == Variant::RelaxedStore {
                    reader = reader.with_consumed_store(Ordering::Relaxed);
                }
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
        let mut writer = OutcomeWriter::new(CAPACITY)
            .unwrap()
            .with_witness(Arc::clone(&witness));
        if variant == Variant::RelaxedLoad {
            writer = writer.with_consumed_load(Ordering::Relaxed);
        }
        for sequence in 1..=RECORDS {
            // The client's reservation: at most `CAPACITY - 1` unread. A
            // Relaxed wait, so it orders nothing.
            while consumed.load(Ordering::Relaxed) + (CAPACITY - 1) < sequence {
                thread::yield_now();
            }
            if variant == Variant::SequenceFirst {
                write_sequence_first(&ring, &consumed, &witness, sequence, record(sequence));
            } else {
                assert_eq!(
                    writer.produce(&ring, &consumed, record(sequence)).unwrap(),
                    Produced::Written(sequence),
                    "a protocol-following client was faulted"
                );
            }
        }
        client.join().unwrap();
    });
}

#[test]
fn the_client_reads_whole_records_in_order() {
    model(Variant::Production);
}

#[test]
#[should_panic(expected = "torn record")]
fn control_the_sequence_stored_before_the_fields() {
    model(Variant::SequenceFirst);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn control_a_relaxed_consumed_load() {
    model(Variant::RelaxedLoad);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn control_a_relaxed_consumed_store() {
    model(Variant::RelaxedStore);
}
