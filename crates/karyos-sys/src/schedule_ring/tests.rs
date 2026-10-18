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

fn entry(n: u64) -> Entry {
    Entry {
        position: n * 64,
        time: 1_000 + n,
    }
}

#[test]
fn the_layout_is_checked() {
    let words: Vec<AtomicU64> = (0..ring_words(2).unwrap())
        .map(|_| AtomicU64::new(0))
        .collect();
    assert_eq!(init(&words, 0), Err(ScheduleError::Layout));
    let three: Vec<AtomicU64> = (0..ring_words(3).unwrap())
        .map(|_| AtomicU64::new(0))
        .collect();
    assert_eq!(
        init(&three, 3),
        Err(ScheduleError::Layout),
        "not a power of two"
    );
    assert_eq!(init(&words, 3), Err(ScheduleError::Layout));
    init(&words, 2).unwrap();
    assert!(SchedulePublisher::attach(&words).is_ok());
    assert_eq!(
        SchedulePublisher::attach(&words[..words.len() - 1]).err(),
        Some(ScheduleError::Layout)
    );
    assert_eq!(ring_words(usize::MAX), None);
}

/// Entries come out in order across wraparound, and a full ring refuses
/// room until the sender releases.
#[test]
fn entries_pass_in_order_and_a_full_ring_backpressures() {
    let ring = ring(2);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    assert_eq!(reader.peek(&ring), Ok(None));
    for n in 0..2 {
        assert_eq!(publisher.has_room(&ring), Ok(true));
        publisher.push(&ring, entry(n)).unwrap();
    }
    assert_eq!(publisher.has_room(&ring), Ok(false), "full: back pressure");
    assert_eq!(
        publisher.push(&ring, entry(2)),
        Err(ScheduleError::Invariant)
    );
    for n in 2..7 {
        assert_eq!(reader.peek(&ring), Ok(Some(entry(n - 2))));
        reader.advance(&ring).unwrap();
        reader.release(&ring).unwrap();
        assert_eq!(publisher.has_room(&ring), Ok(true));
        publisher.push(&ring, entry(n)).unwrap();
    }
    assert_eq!(reader.peek(&ring), Ok(Some(entry(5))));
    reader.advance(&ring).unwrap();
    reader.release(&ring).unwrap();
    assert_eq!(reader.peek(&ring), Ok(Some(entry(6))));
    reader.advance(&ring).unwrap();
    reader.release(&ring).unwrap();
    assert_eq!(reader.peek(&ring), Ok(None));
    assert_eq!(reader.release(&ring), Err(ScheduleError::Invariant));
    assert_eq!(reader.released(), 7);
}

/// A push needs its own room check; one check admits one push.
#[test]
fn every_push_needs_a_room_check() {
    let ring = ring(4);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    assert_eq!(
        publisher.push(&ring, entry(0)),
        Err(ScheduleError::Invariant)
    );
    assert_eq!(publisher.has_room(&ring), Ok(true));
    publisher.push(&ring, entry(0)).unwrap();
    assert_eq!(
        publisher.push(&ring, entry(1)),
        Err(ScheduleError::Invariant)
    );
}

/// Counts that contradict each other are an invariant breach, never a
/// guess; the tail never wraps.
#[test]
fn inconsistent_counts_are_refused() {
    let ring = ring(2);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let reader = ScheduleReader::attach(&ring).unwrap();
    ring[HEAD].store(1, Ordering::Relaxed);
    assert_eq!(publisher.has_room(&ring), Err(ScheduleError::Invariant));
    ring[HEAD].store(0, Ordering::Relaxed);
    ring[TAIL].store(3, Ordering::Relaxed);
    assert_eq!(reader.peek(&ring), Err(ScheduleError::Invariant));
    // A publisher at the end of the count is exhausted, not wrapped.
    let ring = self::ring(1);
    ring[TAIL].store(u64::MAX, Ordering::Relaxed);
    ring[HEAD].store(u64::MAX, Ordering::Relaxed);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    // Refused at the room check, before any message is reserved.
    assert_eq!(publisher.has_room(&ring), Err(ScheduleError::Exhausted));
    assert_eq!(
        publisher.push(&ring, entry(0)),
        Err(ScheduleError::Invariant)
    );
}

/// The reader reads ahead of what it frees: releases go in order and never
/// pass the read cursor, and the publisher sees only the released count.
#[test]
fn the_reader_reads_ahead_and_releases_in_order() {
    let ring = ring(2);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    assert_eq!(reader.release(&ring), Err(ScheduleError::Invariant));
    assert_eq!(reader.advance(&ring), Err(ScheduleError::Invariant));
    for n in 0..2 {
        assert_eq!(publisher.has_room(&ring), Ok(true));
        publisher.push(&ring, entry(n)).unwrap();
    }
    // Read both ahead: the ring is still full for the publisher.
    for n in 0..2 {
        assert_eq!(reader.peek(&ring), Ok(Some(entry(n))));
        reader.advance(&ring).unwrap();
    }
    assert_eq!(reader.peek(&ring), Ok(None));
    assert_eq!(reader.read(), 2);
    assert_eq!(publisher.has_room(&ring), Ok(false));
    reader.release(&ring).unwrap();
    assert_eq!(publisher.has_room(&ring), Ok(true));
    publisher.push(&ring, entry(2)).unwrap();
    reader.release(&ring).unwrap();
    // Nothing read is left to free: the third entry was not read yet.
    assert_eq!(reader.release(&ring), Err(ScheduleError::Invariant));
    assert_eq!(reader.peek(&ring), Ok(Some(entry(2))));
}

/// A rewind reads again, in order, every entry read and not released;
/// the released ones stay released, and the publisher still has no room
/// for a slot not freed.
#[test]
fn a_rewind_reads_the_unreleased_entries_again() {
    let ring = ring(4);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    for n in 0..4 {
        assert_eq!(publisher.has_room(&ring), Ok(true));
        publisher.push(&ring, entry(n)).unwrap();
    }
    for _ in 0..4 {
        reader.advance(&ring).unwrap();
    }
    reader.release(&ring).unwrap();
    reader.rewind_to_released();
    assert_eq!((reader.read(), reader.released()), (1, 1));
    for n in 1..4 {
        assert_eq!(reader.peek(&ring), Ok(Some(entry(n))));
        reader.advance(&ring).unwrap();
    }
    assert_eq!(reader.peek(&ring), Ok(None));
    // One slot freed, one pushed: full again until the next release.
    assert_eq!(publisher.has_room(&ring), Ok(true));
    publisher.push(&ring, entry(4)).unwrap();
    assert_eq!(publisher.has_room(&ring), Ok(false));
    // A rewind with nothing read past `head` changes nothing.
    let mut fresh = ScheduleReader::attach(&ring).unwrap();
    fresh.rewind_to_released();
    assert_eq!(fresh.read(), fresh.released());
}
