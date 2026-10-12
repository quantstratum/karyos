// SPDX-License-Identifier: Apache-2.0

use super::*;

fn stamp(time: u64) -> Stamp {
    Stamp {
        time,
        clock: 1,
        epoch: 0,
    }
}

/// A taken record as owned values: sequence, gap and payload.
type Owned = (u64, Option<(u64, u64)>, Vec<u64>);

/// Takes one record as owned values.
fn take(consumer: &mut JournalConsumer) -> Option<Owned> {
    match consumer.take() {
        Taken::Record(record) => Some((record.sequence, record.gap, record.payload.to_vec())),
        Taken::Empty | Taken::Closed => None,
    }
}

fn payload(sequence: u64) -> [u64; 3] {
    [sequence, sequence ^ 0xFFFF, sequence.wrapping_mul(31)]
}

#[test]
fn configuration_is_checked() {
    assert!(record_journal(0, 3, 4).is_err());
    assert!(record_journal(6, 3, 4).is_err());
    assert!(record_journal(8, 0, 4).is_err());
    assert!(record_journal(8, 3, 0).is_err());
    assert!(record_journal(usize::MAX / 2 + 1, 3, 4).is_err());
}

#[test]
fn payload_length_is_checked_and_not_counted() {
    let (mut writer, mut consumer) = record_journal(4, 3, 4).unwrap();
    assert_eq!(
        writer.append(&[1, 2], stamp(0)),
        Err(JournalError::PayloadLength {
            length: 2,
            expected: 3
        })
    );
    assert_eq!(consumer.losses().attempted, 0);
}

#[test]
fn fill_drop_release_and_refill() {
    let (mut writer, mut consumer) = record_journal(4, 3, 4).unwrap();
    for sequence in 0..4 {
        assert_eq!(
            writer.append(&payload(sequence), stamp(sequence)),
            Ok(Append::Stored { sequence })
        );
    }
    // Full: dropped, never overwritten.
    for sequence in 4..7 {
        assert_eq!(
            writer.append(&payload(sequence), stamp(sequence)),
            Ok(Append::Dropped { sequence })
        );
    }
    for sequence in 0..2 {
        let (taken, gap, data) = take(&mut consumer).unwrap();
        assert_eq!(taken, sequence);
        assert_eq!(gap, None);
        assert_eq!(data, payload(sequence));
    }
    for sequence in 7..9 {
        assert_eq!(
            writer.append(&payload(sequence), stamp(sequence)),
            Ok(Append::Stored { sequence })
        );
    }
    let mut seen = Vec::new();
    while let Some((sequence, gap, data)) = take(&mut consumer) {
        assert_eq!(data, payload(sequence));
        seen.push((sequence, gap));
    }
    assert_eq!(
        seen,
        vec![(2, None), (3, None), (7, Some((4, 7))), (8, None)]
    );
    let losses = consumer.losses();
    assert_eq!(losses.attempted, 9);
    assert_eq!(
        losses.ranges,
        &[DropRange {
            first: 4,
            last: 6,
            first_time: 4,
            last_time: 6,
            clock: 1,
            epoch: 0,
        }]
    );
    assert_eq!(losses.lost_before, None);
}

/// SPEC.md §13: every record unconsumed and no later append; the loss is
/// still readable.
#[test]
fn loss_is_visible_without_a_later_record() {
    let (mut writer, mut consumer) = record_journal(2, 3, 4).unwrap();
    for sequence in 0..5 {
        writer
            .append(&payload(sequence), stamp(10 + sequence))
            .unwrap();
    }
    let losses = consumer.losses();
    assert_eq!(losses.attempted, 5);
    assert_eq!(losses.ranges.len(), 1);
    assert_eq!((losses.ranges[0].first, losses.ranges[0].last), (2, 4));
    assert_eq!(
        (losses.ranges[0].first_time, losses.ranges[0].last_time),
        (12, 14)
    );
}

#[test]
fn a_clock_or_epoch_change_starts_a_range() {
    let (mut writer, mut consumer) = record_journal(1, 3, 4).unwrap();
    writer.append(&payload(0), stamp(0)).unwrap();
    writer.append(&payload(1), stamp(1)).unwrap();
    writer
        .append(
            &payload(2),
            Stamp {
                time: 2,
                clock: 1,
                epoch: 1,
            },
        )
        .unwrap();
    writer
        .append(
            &payload(3),
            Stamp {
                time: 3,
                clock: 2,
                epoch: 1,
            },
        )
        .unwrap();
    let losses = consumer.losses();
    let spans: Vec<_> = losses
        .ranges
        .iter()
        .map(|range| (range.first, range.last, range.clock, range.epoch))
        .collect();
    assert_eq!(spans, vec![(1, 1, 1, 0), (2, 2, 1, 1), (3, 3, 2, 1)]);
}

/// A drop range does not continue across a stored record.
#[test]
fn a_stored_record_ends_the_range() {
    let (mut writer, mut consumer) = record_journal(1, 3, 4).unwrap();
    writer.append(&payload(0), stamp(0)).unwrap();
    writer.append(&payload(1), stamp(1)).unwrap();
    assert_eq!(take(&mut consumer).unwrap().0, 0);
    writer.append(&payload(2), stamp(2)).unwrap();
    writer.append(&payload(3), stamp(3)).unwrap();
    let spans: Vec<_> = consumer
        .losses()
        .ranges
        .iter()
        .map(|range| (range.first, range.last))
        .collect();
    assert_eq!(spans, vec![(1, 1), (3, 3)]);
}

#[test]
fn range_ring_overflow_raises_the_watermark() {
    let (mut writer, mut consumer) = record_journal(1, 3, 2).unwrap();
    writer.append(&payload(0), stamp(0)).unwrap();
    // Each drop is separated by an epoch change, so each starts a range.
    for sequence in 1..6 {
        writer
            .append(
                &payload(sequence),
                Stamp {
                    time: sequence,
                    clock: 1,
                    epoch: sequence,
                },
            )
            .unwrap();
    }
    let losses = consumer.losses();
    let mut spans: Vec<_> = losses.ranges.iter().map(|range| range.first).collect();
    spans.sort_unstable();
    assert_eq!(spans, vec![4, 5]);
    // Ranges 1, 2 and 3 were evicted in turn.
    assert_eq!(losses.lost_before, Some(4));
}

#[test]
fn sequence_exhaustion_closes() {
    let (mut writer, mut consumer) = record_journal(4, 3, 2).unwrap();
    writer.seed_attempted(u64::MAX - 1);
    assert_eq!(
        writer.append(&payload(1), stamp(0)),
        Ok(Append::Stored {
            sequence: u64::MAX - 1
        })
    );
    assert_eq!(
        writer.append(&payload(2), stamp(0)),
        Err(JournalError::Exhausted)
    );
    assert_eq!(
        writer.append(&payload(3), stamp(0)),
        Err(JournalError::Closed)
    );
    assert!(consumer.is_closed());
    assert_eq!(consumer.losses().attempted, u64::MAX);
    assert_eq!(take(&mut consumer).unwrap().0, u64::MAX - 1);
    assert_eq!(consumer.take(), Taken::Closed);
}

#[test]
fn dropping_the_writer_closes_and_records_stay_readable() {
    let (mut writer, mut consumer) = record_journal(4, 3, 2).unwrap();
    writer.append(&payload(0), stamp(0)).unwrap();
    drop(writer);
    assert!(consumer.is_closed());
    assert_eq!(take(&mut consumer).unwrap().2, payload(0));
    assert_eq!(consumer.take(), Taken::Closed);
    // Losses stay readable after the close.
    assert_eq!(consumer.losses().attempted, 1);
}

/// A fast writer and a slow consumer: every stored record arrives once,
/// in order and intact, and stored plus dropped equals attempted.
#[test]
fn concurrent_writer_and_consumer_account_for_every_attempt() {
    let total: u64 = if cfg!(miri) { 200 } else { 20_000 };
    let (mut writer, mut consumer) = record_journal(8, 3, 4).unwrap();
    let (stored, dropped) = std::thread::scope(|scope| {
        let writer_thread = scope.spawn(move || {
            let (mut stored, mut dropped) = (0u64, 0u64);
            for sequence in 0..total {
                match writer.append(&payload(sequence), stamp(sequence)).unwrap() {
                    Append::Stored { .. } => stored += 1,
                    Append::Dropped { .. } => dropped += 1,
                }
            }
            (stored, dropped)
            // The writer drops here and closes the journal.
        });
        let mut received = 0u64;
        let mut last = None;
        loop {
            match consumer.take() {
                Taken::Record(record) => {
                    assert_eq!(record.payload, &payload(record.sequence)[..]);
                    if let Some(previous) = last {
                        assert!(record.sequence > previous);
                    }
                    last = Some(record.sequence);
                    received += 1;
                }
                Taken::Closed => break,
                Taken::Empty => std::thread::yield_now(),
            }
        }
        let (stored, dropped) = writer_thread.join().unwrap();
        assert_eq!(received, stored);
        (stored, dropped)
    });
    assert_eq!(stored + dropped, total);
    assert_eq!(consumer.losses().attempted, total);
}

#[test]
fn a_stamp_regression_is_refused_and_not_counted() {
    let (mut writer, mut consumer) = record_journal(4, 3, 2).unwrap();
    writer.append(&payload(0), stamp(10)).unwrap();
    assert_eq!(
        writer.append(&payload(1), stamp(9)),
        Err(JournalError::StampRegression)
    );
    // Equal time is fine; a new epoch may restart its time.
    writer.append(&payload(1), stamp(10)).unwrap();
    writer
        .append(
            &payload(2),
            Stamp {
                time: 0,
                clock: 1,
                epoch: 1,
            },
        )
        .unwrap();
    assert_eq!(consumer.losses().attempted, 3);
}

/// A drop-range version that would overflow closes the journal before
/// anything is stored or counted, keeping the old range coherent.
#[test]
fn range_version_exhaustion_closes_without_mutation() {
    let (mut writer, mut consumer) = record_journal(1, 3, 1).unwrap();
    writer.append(&payload(0), stamp(0)).unwrap();
    writer.append(&payload(1), stamp(1)).unwrap();
    // The single range entry (holding sequence 1) is at the end of its
    // version space; extending it would overflow.
    writer.seed_range_version(0, u64::MAX - 1);
    assert_eq!(
        writer.append(&payload(2), stamp(2)),
        Err(JournalError::Exhausted)
    );
    assert_eq!(
        writer.append(&payload(3), stamp(3)),
        Err(JournalError::Closed)
    );
    let losses = consumer.losses();
    assert_eq!(losses.attempted, 2);
    assert_eq!(losses.ranges.len(), 1);
    assert_eq!((losses.ranges[0].first, losses.ranges[0].last), (1, 1));
}

/// The terminal gap uses the stored count read after the horizon: after
/// draining every stored record, sequences below the horizon that were
/// never received were dropped.
#[test]
fn the_terminal_gap_is_derived_after_the_horizon() {
    let (mut writer, mut consumer) = record_journal(2, 3, 2).unwrap();
    for sequence in 0..4 {
        writer.append(&payload(sequence), stamp(sequence)).unwrap();
    }
    let mut received = 0;
    while take(&mut consumer).is_some() {
        received += 1;
    }
    let losses = consumer.losses();
    assert_eq!(received, losses.stored);
    assert_eq!(losses.attempted - losses.stored, 2);
}
