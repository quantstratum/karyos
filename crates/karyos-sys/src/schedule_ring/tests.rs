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
    assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(None));
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
        assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(Some(entry(n - 2))));
        reader.advance().unwrap();
        reader.release(&ring).unwrap();
        assert_eq!(publisher.has_room(&ring), Ok(true));
        publisher.push(&ring, entry(n)).unwrap();
    }
    assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(Some(entry(5))));
    reader.advance().unwrap();
    reader.release(&ring).unwrap();
    assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(Some(entry(6))));
    reader.advance().unwrap();
    reader.release(&ring).unwrap();
    assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(None));
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
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    ring[HEAD].store(1, Ordering::Relaxed);
    assert_eq!(publisher.has_room(&ring), Err(ScheduleError::Invariant));
    ring[HEAD].store(0, Ordering::Relaxed);
    ring[TAIL].store(3, Ordering::Relaxed);
    assert_eq!(
        reader.peek(&ring, 0, u64::MAX),
        Err(ScheduleError::Violation)
    );
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
    assert_eq!(reader.advance(), Err(ScheduleError::Invariant));
    for n in 0..2 {
        assert_eq!(publisher.has_room(&ring), Ok(true));
        publisher.push(&ring, entry(n)).unwrap();
    }
    // Read both ahead: the ring is still full for the publisher.
    for n in 0..2 {
        assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(Some(entry(n))));
        reader.advance().unwrap();
    }
    assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(None));
    assert_eq!(reader.read(), 2);
    assert_eq!(publisher.has_room(&ring), Ok(false));
    reader.release(&ring).unwrap();
    assert_eq!(publisher.has_room(&ring), Ok(true));
    publisher.push(&ring, entry(2)).unwrap();
    reader.release(&ring).unwrap();
    // Nothing read is left to free: the third entry was not read yet.
    assert_eq!(reader.release(&ring), Err(ScheduleError::Invariant));
    assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(Some(entry(2))));
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
    for n in 0..4 {
        assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(Some(entry(n))));
        reader.advance().unwrap();
    }
    reader.release(&ring).unwrap();
    reader.rewind_to_released();
    assert_eq!((reader.read(), reader.released()), (1, 1));
    for n in 1..4 {
        assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(Some(entry(n))));
        reader.advance().unwrap();
    }
    assert_eq!(reader.peek(&ring, 0, u64::MAX), Ok(None));
    // One slot freed, one pushed: full again until the next release.
    assert_eq!(publisher.has_room(&ring), Ok(true));
    publisher.push(&ring, entry(4)).unwrap();
    assert_eq!(publisher.has_room(&ring), Ok(false));
    // A rewind with nothing read past `head` changes nothing.
    let mut fresh = ScheduleReader::attach(&ring).unwrap();
    fresh.rewind_to_released();
    assert_eq!(fresh.read(), fresh.released());
}

/// A reader with every entry in reach of its checks: the time bound is
/// `u64::MAX`.
fn peek(reader: &mut ScheduleReader, ring: &[AtomicU64]) -> Result<Option<Entry>, ScheduleError> {
    reader.peek(ring, 0, u64::MAX)
}

/// Pushes `entries` through the publisher's checks.
fn push_all(ring: &[AtomicU64], entries: impl IntoIterator<Item = Entry>) {
    let mut publisher = SchedulePublisher::attach(ring).unwrap();
    for entry in entries {
        assert_eq!(publisher.has_room(ring), Ok(true));
        publisher.push(ring, entry).unwrap();
    }
}

/// A violation is for good: every later read and advance is refused the
/// same way, whatever the ring holds then.
fn assert_sealed(reader: &mut ScheduleReader, ring: &[AtomicU64]) {
    assert!(reader.violated());
    assert_eq!(peek(reader, ring), Err(ScheduleError::Violation));
    assert_eq!(reader.advance(), Err(ScheduleError::Violation));
}

/// A tail below the last valid copy is a violation (timed-tx.md section
/// 11, TT-6), never a rewind of the sender's counts.
#[test]
fn a_tail_that_goes_back_is_a_violation() {
    let ring = ring(4);
    push_all(&ring, [entry(0), entry(1)]);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    assert_eq!(peek(&mut reader, &ring), Ok(Some(entry(0))));
    reader.advance().unwrap();
    assert_eq!(peek(&mut reader, &ring), Ok(Some(entry(1))));
    reader.advance().unwrap();
    // The next slot holds a valid entry, so only the tail check refuses.
    let base = HEADER_WORDS + 2 * ENTRY_WORDS;
    ring[base].store(entry(2).position, Ordering::Relaxed);
    ring[base + 1].store(entry(2).time, Ordering::Relaxed);
    ring[TAIL].store(1, Ordering::Release);
    assert_eq!(peek(&mut reader, &ring), Err(ScheduleError::Violation));
    ring[TAIL].store(2, Ordering::Release);
    assert_sealed(&mut reader, &ring);
}

/// A tail at `head + capacity` is valid; one past it is a violation, also
/// at the end of the count, compared without wrapping.
#[test]
fn a_tail_past_head_plus_capacity_is_a_violation() {
    let ring = ring(2);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    ring[TAIL].store(2, Ordering::Release);
    assert_eq!(
        peek(&mut reader, &ring),
        Ok(Some(Entry {
            position: 0,
            time: 0
        }))
    );
    let ring = self::ring(2);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    ring[TAIL].store(3, Ordering::Release);
    assert_eq!(peek(&mut reader, &ring), Err(ScheduleError::Violation));
    assert_sealed(&mut reader, &ring);
    let ring = self::ring(2);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    ring[TAIL].store(u64::MAX, Ordering::Release);
    assert_eq!(peek(&mut reader, &ring), Err(ScheduleError::Violation));
}

/// The sender never loads `head` back: a publisher that overwrites it
/// changes nothing for the sender, which keeps releasing from its own.
#[test]
fn an_overwritten_head_changes_nothing_for_the_sender() {
    let ring = ring(2);
    push_all(&ring, [entry(0)]);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    ring[HEAD].store(1_000, Ordering::Relaxed);
    assert_eq!(peek(&mut reader, &ring), Ok(Some(entry(0))));
    reader.advance().unwrap();
    reader.release(&ring).unwrap();
    assert_eq!(reader.released(), 1);
    assert_eq!(ring[HEAD].load(Ordering::Relaxed), 1);
}

/// An entry's time below the last accepted one is a violation; an equal
/// time is valid.
#[test]
fn a_time_that_goes_back_is_a_violation() {
    let ring = ring(4);
    let at = |position, time| Entry { position, time };
    push_all(&ring, [at(0, 10), at(64, 10), at(128, 9)]);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    for expected in [at(0, 10), at(64, 10)] {
        assert_eq!(peek(&mut reader, &ring), Ok(Some(expected)));
        reader.advance().unwrap();
    }
    assert_eq!(peek(&mut reader, &ring), Err(ScheduleError::Violation));
    assert_sealed(&mut reader, &ring);
}

/// An entry's time is at most the sender's `now + max_horizon` when it is
/// copied: at the bound it is valid, one past it a violation; a bound past
/// 2^64 bounds nothing.
#[test]
fn a_time_past_the_horizon_is_a_violation() {
    let at = |time| Entry { position: 0, time };
    let ring = ring(2);
    push_all(&ring, [at(150)]);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    assert_eq!(reader.peek(&ring, 100, 50), Ok(Some(at(150))));
    let ring = self::ring(2);
    push_all(&ring, [at(151)]);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    assert_eq!(reader.peek(&ring, 100, 50), Err(ScheduleError::Violation));
    assert_sealed(&mut reader, &ring);
    let ring = self::ring(2);
    push_all(&ring, [at(u64::MAX)]);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    assert_eq!(reader.peek(&ring, 1, u64::MAX), Ok(Some(at(u64::MAX))));
}

/// The time bound is checked once, when the entry is copied: a later read
/// with an earlier `now` serves the copy.
#[test]
fn the_horizon_is_checked_once_at_the_copy() {
    let ring = ring(2);
    push_all(&ring, [entry(0)]);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    assert_eq!(reader.peek(&ring, 1_000, 0), Ok(Some(entry(0))));
    assert_eq!(reader.peek(&ring, 0, 0), Ok(Some(entry(0))));
}

/// Words the publisher rewrites after the copy change nothing: a peek
/// again and a rewind serve the copies.
#[test]
fn a_rewritten_entry_changes_nothing_after_the_copy() {
    let ring = ring(2);
    push_all(&ring, [entry(0), entry(1)]);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    for n in 0..2 {
        assert_eq!(peek(&mut reader, &ring), Ok(Some(entry(n))));
        reader.advance().unwrap();
    }
    for word in &ring[HEADER_WORDS..] {
        word.store(7, Ordering::Relaxed);
    }
    reader.rewind_to_released();
    for n in 0..2 {
        assert_eq!(peek(&mut reader, &ring), Ok(Some(entry(n))));
        reader.advance().unwrap();
    }
    assert!(!reader.violated());
}

/// The driver writes the binding; the publisher reads it back. A flag this
/// build does not know is a layout error, and the sender's reads never
/// depend on the binding.
#[test]
fn the_binding_round_trips_and_unknown_flags_are_refused() {
    let ring = ring(2);
    assert_eq!(
        binding(&ring),
        Ok(Binding {
            domain: 0,
            max_horizon: 0,
            lateness_tolerance: 0,
            cancel_on_deadline: false,
            etf_advance: 0,
        })
    );
    for (cancel_on_deadline, etf_advance) in [(true, 0), (false, 250_000), (true, u64::MAX)] {
        let written = Binding {
            domain: 1,
            max_horizon: 1_000_000_000,
            lateness_tolerance: u64::MAX,
            cancel_on_deadline,
            etf_advance,
        };
        write_binding(&ring, written).unwrap();
        assert_eq!(binding(&ring), Ok(written));
    }
    ring[FLAGS].store(2, Ordering::Release);
    assert_eq!(binding(&ring), Err(ScheduleError::Layout));
    assert_eq!(
        write_binding(&ring[..HEADER_WORDS], binding_default()),
        Err(ScheduleError::Layout)
    );
    // The sender reads nothing of it.
    for word in &ring[DOMAIN..HEADER_WORDS] {
        word.store(u64::MAX, Ordering::Release);
    }
    push_all(&ring, [entry(0)]);
    let mut reader = ScheduleReader::attach(&ring).unwrap();
    assert_eq!(reader.peek(&ring, 0, 2_000), Ok(Some(entry(0))));
}

fn binding_default() -> Binding {
    Binding {
        domain: 0,
        max_horizon: 0,
        lateness_tolerance: 0,
        cancel_on_deadline: false,
        etf_advance: 0,
    }
}

/// The header is eight words, and the binding's words follow the counts.
#[test]
fn the_header_is_eight_words() {
    assert_eq!(HEADER_WORDS, 8);
    assert_eq!(ring_words(4), Some(16));
    assert_eq!(
        (DOMAIN, MAX_HORIZON, LATENESS_TOLERANCE, FLAGS),
        (3, 4, 5, 6)
    );
}

mod arbitrary {
    //! Arbitrary words written over the ring (timed-tx.md section 11,
    //! T-x1): the sender only ever reads valid copies or seals cleanly.

    use super::*;
    use proptest::prelude::*;

    /// One step of a hostile publisher, or of the sender.
    #[derive(Debug, Clone)]
    enum Step {
        /// Stores `value` into word `index` of the ring.
        Write { index: usize, value: u64 },
        /// The sender peeks, and advances on an entry.
        Read,
        /// The sender releases its oldest read entry.
        Release,
        /// The sender rewinds to the oldest entry not released.
        Rewind,
    }

    const CAPACITY: u64 = 4;
    const HORIZON: u64 = 1_000;

    fn value() -> impl Strategy<Value = u64> {
        prop_oneof![
            0..16u64,
            Just(u64::MAX),
            Just(u64::MAX - 1),
            any::<u64>(),
            990..1_010u64,
        ]
    }

    fn step() -> impl Strategy<Value = Step> {
        let words = ring_words(4).unwrap_or(0);
        prop_oneof![
            3 => (0..words, value()).prop_map(|(index, value)| Step::Write { index, value }),
            3 => Just(Step::Read),
            1 => Just(Step::Release),
            1 => Just(Step::Rewind),
        ]
    }

    proptest! {
        #![proptest_config(if cfg!(miri) {
            crate::receive::tests_config()
        } else {
            ProptestConfig::with_cases(512)
        })]

        /// Whatever the publisher writes, every entry the sender reads
        /// passed its checks when copied, an entry read again is the same
        /// copy, and a violation seals the reader for good.
        #[test]
        fn the_sender_reads_valid_copies_or_seals(
            steps in proptest::collection::vec(step(), 1..64),
            now in 0..2_000u64,
        ) {
            let ring = ring(CAPACITY);
            let mut reader = ScheduleReader::attach(&ring).unwrap();
            // Every entry the sender read, by count: never another value.
            let mut seen: Vec<Entry> = Vec::new();
            let mut last_time = 0;
            for step in steps {
                match step {
                    Step::Write { index, value } => ring[index].store(value, Ordering::Release),
                    Step::Read => match reader.peek(&ring, now, HORIZON) {
                        Ok(Some(found)) => {
                            prop_assert!(!reader.violated());
                            let count = usize::try_from(reader.read()).unwrap();
                            if let Some(earlier) = seen.get(count) {
                                prop_assert_eq!(*earlier, found);
                            } else {
                                prop_assert_eq!(seen.len(), count);
                                prop_assert!(found.time >= last_time);
                                prop_assert!(found.time <= now + HORIZON);
                                last_time = found.time;
                                seen.push(found);
                            }
                            reader.advance().unwrap();
                        }
                        Ok(None) => prop_assert!(!reader.violated()),
                        Err(error) => {
                            prop_assert_eq!(error, ScheduleError::Violation);
                            prop_assert!(reader.violated());
                        }
                    },
                    Step::Release => {
                        let before = reader.released();
                        match reader.release(&ring) {
                            Ok(()) => {
                                prop_assert!(before < reader.read());
                                prop_assert_eq!(
                                    ring[HEAD].load(Ordering::Acquire),
                                    reader.released()
                                );
                            }
                            Err(error) => {
                                prop_assert_eq!(error, ScheduleError::Invariant);
                                prop_assert_eq!(before, reader.read());
                            }
                        }
                    }
                    Step::Rewind => reader.rewind_to_released(),
                }
                prop_assert!(reader.released() <= reader.read());
                prop_assert!(reader.read() - reader.released() <= CAPACITY);
                if reader.violated() {
                    prop_assert_eq!(
                        reader.peek(&ring, now, HORIZON),
                        Err(ScheduleError::Violation)
                    );
                }
            }
        }
    }
}
