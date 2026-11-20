// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use super::*;
use crate::outcome_ring::ring_words;

/// O-1's binding: `H = 3`, `C_m = 4`, `max_receivers = 2`, one lane.
const O1: SharedBinding = SharedBinding {
    messages: 4,
    ranges: 3,
    guard_index: 5,
    epoch: 7 + 1,
    handles: 3,
};

fn ring(binding: &SharedBinding) -> Vec<AtomicU64> {
    let capacity = usize::try_from(binding.capacity().unwrap()).unwrap();
    (0..ring_words(capacity).unwrap())
        .map(|_| AtomicU64::new(0))
        .collect()
}

fn words(ring: &[AtomicU64]) -> Vec<u64> {
    ring.iter()
        .take(HEADER_WORDS)
        .map(|word| word.load(Ordering::Relaxed))
        .collect()
}

fn le_bytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// ADR-0092 O-1: the header of a version 3 ring. The vector's epoch is 7;
/// a ring's epoch is open (even), so the header test writes 7 directly and
/// the binding check is exercised with the open epoch 8.
#[test]
fn o1_the_header_of_a_version_3_ring() {
    let binding = SharedBinding { epoch: 7, ..O1 };
    let ring = ring(&O1);
    init(&ring, &binding).unwrap();
    let header = words(&ring);
    assert_eq!(header, [3, 18, 4, 3, 5, 7, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0]);
    let expected: Vec<u8> = "03 00 00 00 00 00 00 00 12 00 00 00 00 00 00 00 \
        04 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 \
        05 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 \
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
        03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect();
    assert_eq!(le_bytes(&header), expected);
    // The client's check: an open epoch binds, the slot count must match.
    let ring = self::ring(&O1);
    init(&ring, &O1).unwrap();
    assert_eq!(binding_of(&ring), Ok(O1));
    ring[CAPACITY].store(17, Ordering::Relaxed);
    assert_eq!(binding_of(&ring), Err(OutcomeError::Layout));
}

fn binding_of(ring: &[AtomicU64]) -> Result<SharedBinding, OutcomeError> {
    super::binding(&ring, 8)
}

/// ADR-0092 O-2: word 1 of the `OutcomesLost` record naming slot 1.
#[test]
fn o2_the_outcomes_lost_word_names_its_slot() {
    assert_eq!(lost_word1(1), Some(0x0000_0002_0000_0013));
    assert_eq!(
        lost_word1(1).unwrap().to_le_bytes(),
        [0x13, 0, 0, 0, 0x02, 0, 0, 0]
    );
    assert_eq!(lost_fields(1).unwrap()[6], LOST_UNKNOWN);
    assert_eq!(lost_word1(MAX_HANDLES), None);
}

fn message(start: u64) -> Record {
    Record {
        kind: Kind::Submitted,
        lane: 0,
        receiver: 0,
        incarnation: 1,
        start,
        end: start + 64,
        epoch: 8,
        reason: 0,
        lost: 0,
    }
}

/// A writer over O-1's ring with every slot attached, `written` records
/// already written, and each cell at its count of `counts`.
fn writer_at(
    written: u64,
    counts: [u64; 3],
) -> (SharedOutcomeWriter, Vec<AtomicU64>, [AtomicU64; 3]) {
    let ring = ring(&O1);
    init(&ring, &O1).unwrap();
    let mut writer = SharedOutcomeWriter::new(&O1).unwrap();
    for slot in 0..3 {
        assert_eq!(writer.attach(slot), Ok(0));
    }
    let cells = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
    for sequence in 1..=written {
        // Each cell moves on to its target count and stays there, so the
        // counts are monotonic and the setup never faults.
        for (cell, count) in cells.iter().zip(counts) {
            cell.store((sequence - 1).min(count), Ordering::Relaxed);
        }
        let refs = [&cells[0], &cells[1], &cells[2]];
        assert_eq!(
            writer.produce(&ring, &refs, message(sequence * 64)),
            Ok(SharedProduced::Written(sequence))
        );
    }
    (writer, ring, cells)
}

/// The kind and handle field of record `sequence`.
fn kind_and_handle(ring: &[AtomicU64], sequence: u64) -> (u64, u64) {
    let base = slot_base(18, sequence).unwrap();
    assert_eq!(ring[base].load(Ordering::Relaxed), sequence);
    let word1 = ring[base + 1].load(Ordering::Relaxed);
    (word1 & 0xFF, word1 >> 32)
}

/// ADR-0092 O-3a: unread 14 is below 15, so record 19 is written.
#[test]
fn o3a_a_record_with_room_is_written() {
    let (mut writer, ring, cells) = writer_at(18, [10, 4, 12]);
    let refs = [&cells[0], &cells[1], &cells[2]];
    assert_eq!(
        writer.produce(&ring, &refs, message(0)),
        Ok(SharedProduced::Written(19))
    );
    assert!(!(0..3).any(|slot| writer.faulted(slot)));
}

/// ADR-0092 O-3b: no room at 15 unread; slot 1 is faulted with record 20,
/// and the pending record is 21 against the new minimum 10.
#[test]
fn o3b_the_handle_at_the_minimum_is_faulted_first() {
    let (mut writer, ring, cells) = writer_at(19, [10, 4, 12]);
    let refs = [&cells[0], &cells[1], &cells[2]];
    assert_eq!(
        writer.produce(&ring, &refs, message(0)),
        Ok(SharedProduced::Written(21))
    );
    assert_eq!(kind_and_handle(&ring, 20), (19, 2));
    assert_eq!(kind_and_handle(&ring, 21), (1, 0));
    assert_eq!(
        (writer.faulted(0), writer.faulted(1), writer.faulted(2)),
        (false, true, false)
    );
}

/// ADR-0092 O-3c: a tie at the minimum faults both, in slot order (records
/// 20 and 21), and the pending record is 22.
#[test]
fn o3c_a_tie_at_the_minimum_faults_every_tied_handle() {
    let (mut writer, ring, cells) = writer_at(19, [4, 4, 12]);
    let refs = [&cells[0], &cells[1], &cells[2]];
    assert_eq!(
        writer.produce(&ring, &refs, message(0)),
        Ok(SharedProduced::Written(22))
    );
    assert_eq!(kind_and_handle(&ring, 20), (19, 1));
    assert_eq!(kind_and_handle(&ring, 21), (19, 2));
    assert_eq!(kind_and_handle(&ring, 22), (1, 0));
}

/// An invalid consumed count faults its handle at once; with no handle
/// left a record is counted, not written; a slot is never reused.
#[test]
fn invalid_counts_detach_and_slot_reuse() {
    let (mut writer, ring, cells) = writer_at(2, [2, 2, 2]);
    cells[0].store(9, Ordering::Relaxed);
    let refs = [&cells[0], &cells[1], &cells[2]];
    assert_eq!(
        writer.produce(&ring, &refs, message(0)),
        Ok(SharedProduced::Written(4))
    );
    assert_eq!(kind_and_handle(&ring, 3), (19, 1));
    writer.detach(1);
    writer.detach(2);
    assert_eq!(
        writer.produce(&ring, &refs, message(0)),
        Ok(SharedProduced::Unread)
    );
    assert_eq!(writer.unread(), 1);
    assert_eq!(writer.attach(1), Err(OutcomeError::Layout));
    let lost = Record {
        kind: Kind::OutcomesLost,
        ..message(0)
    };
    assert_eq!(
        writer.produce(&ring, &refs, lost),
        Err(OutcomeError::Layout)
    );
}

fn write_record(ring: &[AtomicU64], sequence: u64, word1: u64, start: u64) {
    let fields = [
        word1,
        1,
        start,
        start + 64,
        8,
        0,
        if word1 & 0xFF == 19 { LOST_UNKNOWN } else { 0 },
    ];
    assert!(write(ring, 18, sequence, fields));
}

fn delivered(reader: &mut SharedOutcomeReader, ring: &[AtomicU64]) -> Vec<u64> {
    let cell = AtomicU64::new(0);
    let mut out = Vec::new();
    let _ = reader
        .poll(&ring, &cell, 16, |sequence, record| {
            if matches!(record, SharedRecord::Delivered(_)) {
                out.push(sequence);
            }
        })
        .unwrap();
    out
}

/// ADR-0092 O-4: A (slot 0) reserved lane 0 starts 0 and 128, B (slot 1)
/// start 64; records 1 `Submitted` 0, 2 `Submitted` 64, 3 `Aborted` 128,
/// 4 `Range`, 5 `OutcomesLost` naming slot 1, 6 `Ended`.
#[test]
fn o4_each_handle_delivers_its_own_records() {
    let ring = ring(&O1);
    init(&ring, &O1).unwrap();
    write_record(&ring, 1, 1, 0);
    write_record(&ring, 2, 1, 64);
    write_record(&ring, 3, 5, 128);
    write_record(&ring, 4, 16, 0);
    write_record(&ring, 5, 19 | (2 << 32), 0);
    write_record(&ring, 6, 18, 0);
    let mut a = SharedOutcomeReader::attach(&ring.as_slice(), 1, 0, 0).unwrap();
    assert!(a.reserve(0, 0) && a.reserve(0, 128));
    let mut b = SharedOutcomeReader::attach(&ring.as_slice(), 1, 1, 0).unwrap();
    assert!(b.reserve(0, 64));
    assert_eq!(delivered(&mut a, &ring), [1, 3, 4, 6]);
    assert_eq!((a.outstanding(), a.ended()), (0, false));
    assert_eq!(delivered(&mut b, &ring), [2, 4, 5]);
    assert!(b.ended());
}

/// The quota bounds a handle's reserved set; an `OutcomesLost` record
/// naming no slot, or a handle field on another kind, is corrupt.
#[test]
fn the_quota_and_corrupt_handle_fields() {
    let ring = ring(&O1);
    init(&ring, &O1).unwrap();
    let mut reader = SharedOutcomeReader::attach(&ring.as_slice(), 1, 2, 0).unwrap();
    for start in 0..4 {
        assert!(reader.reserve(0, start));
    }
    assert!(!reader.reserve(0, 4));
    assert_eq!(
        SharedOutcomeReader::attach(&ring.as_slice(), 1, 3, 0).err(),
        Some(OutcomeError::Layout)
    );
    write_record(&ring, 1, 19 | (4 << 32), 0);
    let cell = AtomicU64::new(0);
    assert_eq!(
        reader.poll(&ring.as_slice(), &cell, 4, |_, _| {}),
        Err(OutcomeError::Corrupt { sequence: 1 })
    );
    let ring = self::ring(&O1);
    init(&ring, &O1).unwrap();
    write_record(&ring, 1, 1 | (1 << 32), 0);
    let mut reader = SharedOutcomeReader::attach(&ring.as_slice(), 1, 0, 0).unwrap();
    assert_eq!(
        reader.poll(&ring.as_slice(), &cell, 4, |_, _| {}),
        Err(OutcomeError::Corrupt { sequence: 1 })
    );
}
