// SPDX-License-Identifier: Apache-2.0

//! The diagnostic record rings under the error log and the loss report
//! (`quantstratum-docs: karyos/design/observability-and-tools.md`, "Error
//! log" and "Loss report"): one writer, any number of readers, overwrite
//! when full.
//!
//! - **Layout.** A header of one stride (16 words): word 0 the record
//!   count (capacity), word 1 `next_seq`, the sequence the next new record
//!   will take. Then `capacity` records of `record_words` words; record
//!   `seq` lives in slot `seq mod capacity`. Record word 0 is its seqlock
//!   version (odd while written), word 1 its sequence, the rest its fields.
//! - **Writing.** A new record or an in-place update stores the version
//!   odd, issues a Release fence, writes the words (Relaxed), and stores
//!   the version even with Release. For a new record `next_seq` is then
//!   stored with Release. The writer never waits for a reader.
//! - **The boundary.** The records retained are exactly those with
//!   `next_seq - capacity <= seq < next_seq`, from one Acquire load of
//!   `next_seq`. A reader learns that it missed records only from that
//!   boundary, never from a busy slot.
//! - **Reading** issues only `Relaxed` loads and `Acquire` fences, so it
//!   works over a read-only mapping ([`crate::atomic_view::ReadOnlyWords`]).
//!
//! Every word is accessed only atomically. The writer is [`RingWriter`]
//! over writable words; the reader is [`RingReader`] over load functions.

use crate::sync::{AtomicU64, Ordering, fence};

/// Words per stride: 128 bytes.
pub const STRIDE_WORDS: usize = 16;
/// Header word: the record count.
const CAPACITY: usize = 0;
/// Header word: the sequence the next new record will take.
const NEXT_SEQ: usize = 1;
/// Record word: the seqlock version.
const VERSION: usize = 0;
/// Record word: the record's sequence.
const SEQUENCE: usize = 1;
/// Index of a record's first field word.
pub const FIELDS: usize = 2;
/// Attempts a reader makes on a slot before reporting it busy.
pub const READ_ATTEMPTS: usize = 8;

/// Words of a ring of `capacity` records of `record_words` words, header
/// included; `None` on overflow.
#[must_use]
pub const fn ring_words(capacity: usize, record_words: usize) -> Option<usize> {
    match capacity.checked_mul(record_words) {
        Some(records) => records.checked_add(STRIDE_WORDS),
        None => None,
    }
}

/// The retained range `[first, next)`: `first` is the oldest sequence
/// still held and `next` the sequence the next new record will take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// The oldest retained sequence.
    pub first: u64,
    /// The sequence of the next new record.
    pub next: u64,
}

impl Bounds {
    /// Whether `seq` is retained.
    #[must_use]
    pub const fn contains(&self, seq: u64) -> bool {
        seq >= self.first && seq < self.next
    }
}

/// What a new record displaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    /// The new record's sequence.
    pub seq: u64,
    /// The sequence of the record it overwrote, if the ring was full.
    pub overwrote: Option<u64>,
}

/// The single writer of a ring.
#[derive(Debug)]
pub struct RingWriter<'a> {
    words: &'a [AtomicU64],
    capacity: usize,
    record_words: usize,
    /// The writer's copy of `next_seq`.
    next: u64,
}

impl<'a> RingWriter<'a> {
    /// Takes `words` as a new, zeroed ring of `capacity` records of
    /// `record_words` words, and stores the capacity. `None` when the words
    /// do not match that size, `capacity` is zero or a record has no field.
    #[must_use]
    pub fn create(words: &'a [AtomicU64], capacity: usize, record_words: usize) -> Option<Self> {
        if capacity == 0 || record_words <= FIELDS {
            return None;
        }
        if ring_words(capacity, record_words) != Some(words.len()) {
            return None;
        }
        words
            .get(CAPACITY)?
            .store(u64::try_from(capacity).ok()?, Ordering::Release);
        Some(Self {
            words,
            capacity,
            record_words,
            next: 0,
        })
    }

    /// Takes over a ring that a previous writer of this process created,
    /// reading its capacity and `next_seq`. The caller guarantees that the
    /// previous writer is gone, so there is still one writer.
    #[must_use]
    pub fn resume(words: &'a [AtomicU64], record_words: usize) -> Option<Self> {
        let capacity = usize::try_from(words.get(CAPACITY)?.load(Ordering::Acquire)).ok()?;
        if capacity == 0
            || record_words <= FIELDS
            || ring_words(capacity, record_words) != Some(words.len())
        {
            return None;
        }
        let next = words.get(NEXT_SEQ)?.load(Ordering::Acquire);
        Some(Self {
            words,
            capacity,
            record_words,
            next,
        })
    }

    /// Field words per record.
    #[must_use]
    pub fn fields(&self) -> usize {
        self.record_words - FIELDS
    }

    /// The writer's retained range.
    #[must_use]
    pub fn bounds(&self) -> Bounds {
        Bounds {
            first: self.next.saturating_sub(self.capacity as u64),
            next: self.next,
        }
    }

    /// Writes a new record with `fields` (missing words are zero, extra
    /// words are ignored) and publishes it; reports the record it
    /// overwrote when the ring was full. `None` once the sequences are
    /// exhausted.
    pub fn append(&mut self, fields: &[u64]) -> Option<Appended> {
        let seq = self.next;
        let next = seq.checked_add(1)?;
        let overwrote = seq.checked_sub(self.capacity as u64);
        self.write(seq, fields)?;
        self.next = next;
        self.words.get(NEXT_SEQ)?.store(next, Ordering::Release);
        Some(Appended { seq, overwrote })
    }

    /// Rewrites the fields of retained record `seq` in place; `false` when
    /// it is no longer retained.
    pub fn update(&mut self, seq: u64, fields: &[u64]) -> bool {
        self.bounds().contains(seq) && self.write(seq, fields).is_some()
    }

    fn write(&self, seq: u64, fields: &[u64]) -> Option<()> {
        let slot = usize::try_from(seq % self.capacity as u64).ok()?;
        let start = STRIDE_WORDS.checked_add(slot.checked_mul(self.record_words)?)?;
        let record = self
            .words
            .get(start..start.checked_add(self.record_words)?)?;
        let version = record.get(VERSION)?;
        let odd = version.load(Ordering::Relaxed).wrapping_add(1) | 1;
        version.store(odd, Ordering::Relaxed);
        fence(Ordering::Release);
        record.get(SEQUENCE)?.store(seq, Ordering::Relaxed);
        for (index, word) in record.iter().enumerate().skip(FIELDS) {
            let value = fields.get(index - FIELDS).copied().unwrap_or(0);
            word.store(value, Ordering::Relaxed);
        }
        version.store(odd.wrapping_add(1), Ordering::Release);
        Some(())
    }
}

/// What a reader found in a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotRead {
    /// A stable copy of the expected record, in the output.
    Record,
    /// A stable copy of a later record: the expected one was overwritten.
    Overwritten,
    /// The slot was being written on every attempt.
    Busy,
}

/// A reader of a ring over a load function: `load(index)` returns word
/// `index` with a `Relaxed` load, `None` out of range.
#[derive(Debug, Clone, Copy)]
pub struct RingReader<L> {
    load: L,
    capacity: u64,
    record_words: usize,
}

impl<L: Fn(usize) -> Option<u64>> RingReader<L> {
    /// A reader of a ring of `record_words`-word records, whose capacity
    /// it reads from the header (Acquire); `None` when the header holds no
    /// capacity.
    pub fn new(load: L, record_words: usize) -> Option<Self> {
        let capacity = load(CAPACITY)?;
        fence(Ordering::Acquire);
        if capacity == 0 || record_words <= FIELDS {
            return None;
        }
        Some(Self {
            load,
            capacity,
            record_words,
        })
    }

    /// Field words per record.
    #[must_use]
    pub fn fields(&self) -> usize {
        self.record_words - FIELDS
    }

    /// The retained range, from one Acquire load of `next_seq`.
    pub fn bounds(&self) -> Option<Bounds> {
        let next = (self.load)(NEXT_SEQ)?;
        fence(Ordering::Acquire);
        Some(Bounds {
            first: next.saturating_sub(self.capacity),
            next,
        })
    }

    /// Copies record `seq`'s fields into `out` under the seqlock, with at
    /// most [`READ_ATTEMPTS`] attempts.
    pub fn read(&self, seq: u64, out: &mut [u64]) -> SlotRead {
        let Some(start) = usize::try_from(seq % self.capacity)
            .ok()
            .and_then(|slot| slot.checked_mul(self.record_words))
            .and_then(|offset| offset.checked_add(STRIDE_WORDS))
        else {
            return SlotRead::Busy;
        };
        for _ in 0..READ_ATTEMPTS {
            let Some(before) = (self.load)(start + VERSION) else {
                return SlotRead::Busy;
            };
            fence(Ordering::Acquire);
            if before % 2 == 1 {
                continue;
            }
            let found = (self.load)(start + SEQUENCE).unwrap_or(0);
            for (index, slot) in out.iter_mut().take(self.fields()).enumerate() {
                *slot = (self.load)(start + FIELDS + index).unwrap_or(0);
            }
            fence(Ordering::Acquire);
            if (self.load)(start + VERSION) != Some(before) {
                continue;
            }
            return match found.cmp(&seq) {
                core::cmp::Ordering::Equal if before != 0 => SlotRead::Record,
                core::cmp::Ordering::Greater => SlotRead::Overwritten,
                // Not written yet as `seq`: a stale copy of an earlier
                // record, or the slot before its first write.
                _ => SlotRead::Busy,
            };
        }
        SlotRead::Busy
    }
}

/// Why a scan stopped before the end of the retained range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStop {
    /// The slot at the cursor was busy on every attempt; the next scan
    /// retries it.
    Busy,
    /// The record at the cursor was overwritten during the scan; the next
    /// scan's boundary proves it.
    Overwritten,
}

/// The result of one scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scan {
    /// Sequences the boundary proved overwritten before the reader saw
    /// them.
    pub overwritten: u64,
    /// Records delivered.
    pub delivered: u64,
    /// Why the scan stopped early, if it did.
    pub stopped: Option<ScanStop>,
}

/// Scans from `cursor`: reports the sequences the boundary proves
/// overwritten, moves the cursor to the oldest retained record, then
/// delivers each retained record in order to `deliver` (its sequence and
/// fields) and moves the cursor past it. Stops at the first busy or
/// overwritten slot, leaving the cursor on it. `buffer` holds one record's
/// fields.
pub fn scan<L: Fn(usize) -> Option<u64>>(
    reader: &RingReader<L>,
    cursor: &mut u64,
    buffer: &mut [u64],
    deliver: impl FnMut(u64, &[u64]),
) -> Scan {
    scan_at_most(reader, cursor, buffer, u64::MAX, deliver)
}

/// [`scan`], delivering at most `max` records: the cursor stays on the
/// first one left, which is not read, so the work of one call is bounded
/// by `max` and not by the ring's capacity.
pub fn scan_at_most<L: Fn(usize) -> Option<u64>>(
    reader: &RingReader<L>,
    cursor: &mut u64,
    buffer: &mut [u64],
    max: u64,
    mut deliver: impl FnMut(u64, &[u64]),
) -> Scan {
    let mut result = Scan {
        overwritten: 0,
        delivered: 0,
        stopped: None,
    };
    let Some(bounds) = reader.bounds() else {
        result.stopped = Some(ScanStop::Busy);
        return result;
    };
    if *cursor < bounds.first {
        result.overwritten = bounds.first - *cursor;
        *cursor = bounds.first;
    }
    let fields = reader.fields().min(buffer.len());
    while *cursor < bounds.next && result.delivered < max {
        match reader.read(*cursor, buffer) {
            SlotRead::Record => {
                deliver(*cursor, buffer.get(..fields).unwrap_or(&[]));
                result.delivered += 1;
                *cursor += 1;
            }
            SlotRead::Overwritten => {
                result.stopped = Some(ScanStop::Overwritten);
                break;
            }
            SlotRead::Busy => {
                result.stopped = Some(ScanStop::Busy);
                break;
            }
        }
    }
    result
}

#[cfg(all(test, not(loom)))]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]
mod tests {
    use super::*;
    use crate::atomic_view::HeapWords;

    fn ring(capacity: usize, record_words: usize) -> HeapWords {
        HeapWords::zeroed(ring_words(capacity, record_words).unwrap()).unwrap()
    }

    fn reader(heap: &HeapWords, record_words: usize) -> RingReader<impl Fn(usize) -> Option<u64>> {
        let words = heap.words();
        RingReader::new(
            move |index| words.get(index).map(|word| word.load(Ordering::Relaxed)),
            record_words,
        )
        .unwrap()
    }

    fn collect(
        reader: &RingReader<impl Fn(usize) -> Option<u64>>,
        cursor: &mut u64,
    ) -> (Vec<(u64, u64)>, Scan) {
        let mut seen = Vec::new();
        let mut buffer = [0u64; 16];
        let scan = scan(reader, cursor, &mut buffer, |seq, fields| {
            seen.push((seq, fields[0]));
        });
        (seen, scan)
    }

    #[test]
    fn records_are_read_in_order_and_overwrites_are_proven() {
        let heap = ring(4, 16);
        let mut writer = RingWriter::create(heap.words().as_slice(), 4, 16).unwrap();
        let reader = reader(&heap, 16);
        let mut cursor = 0;
        for value in 0..3u64 {
            let appended = writer.append(&[100 + value]).unwrap();
            assert_eq!(appended.overwrote, None);
        }
        let (seen, scan) = collect(&reader, &mut cursor);
        assert_eq!(seen, vec![(0, 100), (1, 101), (2, 102)]);
        assert_eq!((scan.overwritten, scan.stopped), (0, None));
        // Wrap past the reader: 3..=8 written, 0..=4 overwritten.
        for value in 3..9u64 {
            let appended = writer.append(&[100 + value]).unwrap();
            assert_eq!(appended.overwrote, value.checked_sub(4));
        }
        let (seen, scan) = collect(&reader, &mut cursor);
        assert_eq!(scan.overwritten, 2, "3 and 4 were overwritten unseen");
        assert_eq!(seen, vec![(5, 105), (6, 106), (7, 107), (8, 108)]);
        assert_eq!(cursor, 9);
    }

    /// A bounded scan reads no further than its bound: the cursor stays
    /// on the first record left, and the next scan delivers it.
    #[test]
    fn a_bounded_scan_stops_at_its_bound() {
        let heap = ring(8, 16);
        let mut writer = RingWriter::create(heap.words().as_slice(), 8, 16).unwrap();
        let reader = reader(&heap, 16);
        for value in 0..5u64 {
            let _ = writer.append(&[100 + value]).unwrap();
        }
        let mut buffer = [0u64; 16];
        let mut cursor = 0;
        let mut seen = Vec::new();
        let scan = scan_at_most(&reader, &mut cursor, &mut buffer, 2, |seq, _| {
            seen.push(seq)
        });
        assert_eq!(
            (seen.as_slice(), cursor, scan.delivered),
            (&[0, 1][..], 2, 2)
        );
        assert_eq!(scan.stopped, None);
        let scan = scan_at_most(&reader, &mut cursor, &mut buffer, 0, |seq, _| {
            seen.push(seq)
        });
        assert_eq!((cursor, scan.delivered), (2, 0));
        let _ = scan_at_most(&reader, &mut cursor, &mut buffer, 9, |seq, _| {
            seen.push(seq)
        });
        assert_eq!((seen, cursor), (vec![0, 1, 2, 3, 4], 5));
    }

    #[test]
    fn updates_in_place_keep_the_sequence() {
        let heap = ring(2, 16);
        let mut writer = RingWriter::create(heap.words().as_slice(), 2, 16).unwrap();
        let reader = reader(&heap, 16);
        let first = writer.append(&[1]).unwrap().seq;
        assert!(writer.update(first, &[7]));
        let mut cursor = 0;
        let (seen, _) = collect(&reader, &mut cursor);
        assert_eq!(seen, vec![(0, 7)]);
        let _ = writer.append(&[2]).unwrap();
        let _ = writer.append(&[3]).unwrap();
        assert!(
            !writer.update(first, &[9]),
            "record 0 is no longer retained"
        );
    }

    #[test]
    fn a_slot_being_written_is_busy_never_overwritten() {
        let heap = ring(2, 16);
        let mut writer = RingWriter::create(heap.words().as_slice(), 2, 16).unwrap();
        let reader = reader(&heap, 16);
        let _ = writer.append(&[1]).unwrap();
        // Leave the slot odd, as a writer paused mid-record would.
        let version = heap.words().get(STRIDE_WORDS).unwrap();
        let even = version.load(Ordering::Relaxed);
        version.store(even + 1, Ordering::Relaxed);
        let mut cursor = 0;
        let (seen, scan) = collect(&reader, &mut cursor);
        assert!(seen.is_empty());
        assert_eq!(scan.stopped, Some(ScanStop::Busy));
        assert_eq!((scan.overwritten, cursor), (0, 0));
        version.store(even, Ordering::Relaxed);
        let (seen, _) = collect(&reader, &mut cursor);
        assert_eq!(seen, vec![(0, 1)]);
    }

    #[test]
    fn creation_validates_the_size() {
        let heap = ring(4, 16);
        assert!(RingWriter::create(heap.words().as_slice(), 3, 16).is_none());
        assert!(RingWriter::create(heap.words().as_slice(), 4, 2).is_none());
        assert!(RingWriter::create(heap.words().as_slice(), 0, 16).is_none());
        let empty = HeapWords::zeroed(16).unwrap();
        let words = empty.words();
        assert!(
            RingReader::new(
                |index| words.get(index).map(|word| word.load(Ordering::Relaxed)),
                16
            )
            .is_none(),
            "a header without capacity is not a ring"
        );
    }
}
