// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use super::*;

fn ring(capacity: u64) -> Vec<AtomicU64> {
    let words = ring_words(usize::try_from(capacity).unwrap()).unwrap();
    let ring: Vec<AtomicU64> = (0..words).map(|_| AtomicU64::new(0)).collect();
    init(&ring, capacity).unwrap();
    ring
}

fn message(kind: Kind, start: u64) -> Record {
    Record {
        kind,
        lane: 1,
        receiver: 0,
        incarnation: 7,
        start,
        end: start + 64,
        epoch: 2,
        reason: 0,
        lost: 0,
    }
}

fn read_all(
    reader: &mut OutcomeReader,
    ring: &[AtomicU64],
    consumed: &AtomicU64,
) -> Vec<(u64, Record)> {
    let mut seen = Vec::new();
    let _ = reader
        .poll(&ring, consumed, usize::MAX, |sequence, record| {
            seen.push((sequence, record));
        })
        .unwrap();
    seen
}

#[test]
fn records_round_trip_in_sequence_order() {
    let ring = ring(4);
    let consumed = AtomicU64::new(0);
    let mut writer = OutcomeWriter::new(4).unwrap();
    let mut reader = OutcomeReader::attach(&ring.as_slice(), 2).unwrap();
    let records = [
        message(Kind::Submitted, 0),
        message(Kind::Rejected, 64),
        Record {
            kind: Kind::Range,
            receiver: 3,
            ..message(Kind::Range, 128)
        },
    ];
    for (index, record) in records.iter().enumerate() {
        let sequence = u64::try_from(index).unwrap() + 1;
        assert_eq!(
            writer.produce(&ring, &consumed, *record).unwrap(),
            Produced::Written(sequence)
        );
    }
    let seen = read_all(&mut reader, &ring, &consumed);
    assert_eq!(seen.len(), 3);
    for ((sequence, record), (index, expected)) in seen.iter().zip(records.iter().enumerate()) {
        assert_eq!(*sequence, u64::try_from(index).unwrap() + 1);
        assert_eq!(record, expected);
    }
    assert_eq!(consumed.load(Ordering::Relaxed), 3);
}

#[test]
fn the_ring_wraps_once_records_are_consumed() {
    let ring = ring(3);
    let consumed = AtomicU64::new(0);
    let mut writer = OutcomeWriter::new(3).unwrap();
    let mut reader = OutcomeReader::attach(&ring.as_slice(), 2).unwrap();
    for round in 0..5u64 {
        for step in 0..2u64 {
            let start = (round * 2 + step) * 64;
            assert!(matches!(
                writer
                    .produce(&ring, &consumed, message(Kind::Submitted, start))
                    .unwrap(),
                Produced::Written(_)
            ));
        }
        assert_eq!(read_all(&mut reader, &ring, &consumed).len(), 2);
    }
    assert_eq!(consumed.load(Ordering::Relaxed), 10);
    assert_eq!(writer.faulted(), None);
}

#[test]
fn the_reserved_slot_is_never_used_by_an_ordinary_record() {
    // Capacity 3: two ordinary records fill the room; the third would make
    // the unread records exceed C_m + C_r and faults the lagging client.
    let ring = ring(3);
    let consumed = AtomicU64::new(0);
    let mut writer = OutcomeWriter::new(3).unwrap();
    for start in [0, 64] {
        assert!(matches!(
            writer
                .produce(&ring, &consumed, message(Kind::Submitted, start))
                .unwrap(),
            Produced::Written(_)
        ));
    }
    assert_eq!(
        writer
            .produce(&ring, &consumed, message(Kind::Submitted, 128))
            .unwrap(),
        Produced::Lost
    );
    assert_eq!(writer.faulted(), Some(1));
    let mut reader = OutcomeReader::attach(&ring.as_slice(), 2).unwrap();
    let seen = read_all(&mut reader, &ring, &consumed);
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[2].1.kind, Kind::OutcomesLost);
    assert_eq!(seen[2].1.lost, 1, "the record that faulted the client");
    assert!(reader.ended());
    // Later records are only counted.
    assert_eq!(
        writer
            .produce(&ring, &consumed, message(Kind::Submitted, 192))
            .unwrap(),
        Produced::Lost
    );
    assert_eq!(writer.faulted(), Some(2));
}

#[test]
fn an_invalid_consumed_count_faults_the_client() {
    for bad in [9, u64::MAX] {
        let ring = ring(4);
        let consumed = AtomicU64::new(0);
        let mut writer = OutcomeWriter::new(4).unwrap();
        assert_eq!(
            writer
                .produce(&ring, &consumed, message(Kind::Submitted, 0))
                .unwrap(),
            Produced::Written(1)
        );
        // Ahead of what was written.
        consumed.store(bad, Ordering::Relaxed);
        assert_eq!(
            writer
                .produce(&ring, &consumed, message(Kind::Submitted, 64))
                .unwrap(),
            Produced::Lost
        );
        assert!(writer.faulted().is_some());
        // The final record sits after the last validated count.
        consumed.store(0, Ordering::Relaxed);
        let mut reader = OutcomeReader::attach(&ring.as_slice(), 2).unwrap();
        let seen = read_all(&mut reader, &ring, &consumed);
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].1.kind, Kind::OutcomesLost);
        assert_eq!(seen[1].1.lost, 1);
        assert_eq!(writer.faulted(), Some(1));
    }
}

#[test]
fn a_late_consumed_count_faults_with_the_exact_count() {
    // Capacity 4: three records fill the room. The client read them but
    // has not published its count, so the fourth faults it.
    let ring = ring(4);
    let consumed = AtomicU64::new(0);
    let mut writer = OutcomeWriter::new(4).unwrap();
    for start in [0, 64, 128] {
        assert!(matches!(
            writer
                .produce(&ring, &consumed, message(Kind::Submitted, start))
                .unwrap(),
            Produced::Written(_)
        ));
    }
    for start in [192, 256] {
        assert_eq!(
            writer
                .produce(&ring, &consumed, message(Kind::Submitted, start))
                .unwrap(),
            Produced::Lost
        );
    }
    assert_eq!(writer.faulted(), Some(2));
    let mut reader = OutcomeReader::attach(&ring.as_slice(), 2).unwrap();
    let seen = read_all(&mut reader, &ring, &consumed);
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[3].0, 4, "the reserved slot");
    assert_eq!(seen[3].1.kind, Kind::OutcomesLost);
    assert_eq!(seen[3].1.lost, 1, "counted when it was written");
    // Nothing follows it, even once the count is published.
    assert_eq!(read_all(&mut reader, &ring, &consumed).len(), 0);
}

#[test]
fn a_count_that_goes_back_faults_the_client() {
    let ring = ring(4);
    let consumed = AtomicU64::new(0);
    let mut writer = OutcomeWriter::new(4).unwrap();
    let mut reader = OutcomeReader::attach(&ring.as_slice(), 2).unwrap();
    for start in [0, 64] {
        let _ = writer
            .produce(&ring, &consumed, message(Kind::Submitted, start))
            .unwrap();
    }
    assert_eq!(read_all(&mut reader, &ring, &consumed).len(), 2);
    let _ = writer
        .produce(&ring, &consumed, message(Kind::Submitted, 128))
        .unwrap();
    consumed.store(1, Ordering::Relaxed);
    assert_eq!(
        writer
            .produce(&ring, &consumed, message(Kind::Submitted, 192))
            .unwrap(),
        Produced::Lost
    );
    assert!(writer.faulted().is_some());
}

#[test]
fn a_panicking_handler_gets_the_record_again() {
    let ring = ring(4);
    let consumed = AtomicU64::new(0);
    let mut writer = OutcomeWriter::new(4).unwrap();
    let _ = writer
        .produce(&ring, &consumed, message(Kind::Submitted, 0))
        .unwrap();
    let mut reader = OutcomeReader::attach(&ring.as_slice(), 2).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reader.poll(&ring.as_slice(), &consumed, 1, |_, _| panic!("handler"))
    }));
    assert!(result.is_err());
    assert_eq!(consumed.load(Ordering::Relaxed), 0, "not consumed");
    let seen = read_all(&mut reader, &ring, &consumed);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, 1);
}

#[test]
fn a_reader_refuses_another_layout_version() {
    let ring = ring(4);
    ring[VERSION].store(2, Ordering::Relaxed);
    assert_eq!(
        OutcomeReader::attach(&ring.as_slice(), 2).unwrap_err(),
        OutcomeError::Version(2)
    );
}

#[test]
fn layouts_are_checked() {
    let short: Vec<AtomicU64> = (0..HEADER_WORDS).map(|_| AtomicU64::new(0)).collect();
    assert_eq!(init(&short, 2), Err(OutcomeError::Layout));
    let ring = ring(4);
    assert_eq!(init(&ring, 1), Err(OutcomeError::Layout));
    assert_eq!(OutcomeWriter::new(1).unwrap_err(), OutcomeError::Layout);
    assert_eq!(
        OutcomeReader::attach(&ring.as_slice(), 0).unwrap_err(),
        OutcomeError::Layout
    );
    assert_eq!(capacity(4, 5), Some(10));
    assert_eq!(capacity(u64::MAX, 1), None);
}

#[test]
fn a_record_that_breaks_the_layout_is_refused_before_assignment() {
    let ring = ring(4);
    let consumed = AtomicU64::new(0);
    let mut writer = OutcomeWriter::new(4).unwrap();
    for record in [
        Record {
            lane: 4,
            ..message(Kind::Submitted, 0)
        },
        Record {
            receiver: 1,
            ..message(Kind::Submitted, 0)
        },
        Record {
            lost: 1,
            ..message(Kind::Aborted, 0)
        },
    ] {
        assert_eq!(
            writer.produce(&ring, &consumed, record),
            Err(OutcomeError::Layout)
        );
    }
    assert_eq!(
        writer
            .produce(&ring, &consumed, message(Kind::Submitted, 0))
            .unwrap(),
        Produced::Written(1),
        "no sequence was consumed"
    );
}

#[test]
fn a_corrupt_record_is_an_error_never_skipped() {
    let consumed = AtomicU64::new(0);
    for (word, value) in [
        (1, 99),            // unknown kind
        (1, 1 | (2 << 8)),  // lane 2 of a two-lane publication
        (1, 1 | (1 << 16)), // a receiver on a message record
        (1, 1 | (1 << 40)), // reserved bits
        (7, 5),             // a lost count on a message record
        (0, 2),             // a sequence ahead of the expected one
        (0, u64::MAX),      // a sequence no round can hold
    ] {
        let ring = ring(4);
        let mut writer = OutcomeWriter::new(4).unwrap();
        let _ = writer
            .produce(&ring, &consumed, message(Kind::Submitted, 0))
            .unwrap();
        ring[HEADER_WORDS + word].store(value, Ordering::Relaxed);
        let mut reader = OutcomeReader::attach(&ring.as_slice(), 2).unwrap();
        assert_eq!(
            reader.poll(&ring.as_slice(), &consumed, 4, |_, _| {}),
            Err(OutcomeError::Corrupt { sequence: 1 }),
            "word {word} = {value:#x}"
        );
    }
}

#[test]
fn an_unwritten_slot_is_pending() {
    let ring = ring(4);
    let consumed = AtomicU64::new(0);
    let mut reader = OutcomeReader::attach(&ring.as_slice(), 2).unwrap();
    assert_eq!(read_all(&mut reader, &ring, &consumed).len(), 0);
}

#[test]
fn only_the_replaced_record_is_pending() {
    // Capacity 2: record 2 lives in slot 1, which holds 0 before it is
    // written; record 3 lives in slot 0, which holds record 1 until then.
    let ring = ring(2);
    let consumed = AtomicU64::new(0);
    let mut writer = OutcomeWriter::new(2).unwrap();
    let mut reader = OutcomeReader::attach(&ring.as_slice(), 2).unwrap();
    let _ = writer
        .produce(&ring, &consumed, message(Kind::Submitted, 0))
        .unwrap();
    assert_eq!(read_all(&mut reader, &ring, &consumed).len(), 1);
    // Slot 1 holding anything but 0 or 2 is corrupt.
    ring[HEADER_WORDS + RECORD_WORDS].store(1, Ordering::Relaxed);
    assert_eq!(
        reader.poll(&ring.as_slice(), &consumed, 1, |_, _| {}),
        Err(OutcomeError::Corrupt { sequence: 2 })
    );
    ring[HEADER_WORDS + RECORD_WORDS].store(0, Ordering::Relaxed);
    let _ = writer
        .produce(&ring, &consumed, message(Kind::Submitted, 64))
        .unwrap();
    assert_eq!(read_all(&mut reader, &ring, &consumed).len(), 1);
    // Slot 0 still holds record 1: pending.
    assert_eq!(read_all(&mut reader, &ring, &consumed).len(), 0);
}
