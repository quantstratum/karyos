// SPDX-License-Identifier: Apache-2.0

//! The trace mirror (`quantstratum-docs:
//! karyos/design/trace-journal-region.md`, J1): the driver drains every
//! client trace journal and copies its records here, into one region only
//! the driver writes (A2 seals) and tools map read-only (A1). It holds two
//! parts:
//!
//! - **The journal table**: a fixed number of entries, each written only by
//!   the driver under a seqlock (the algorithm of the error log's records:
//!   odd version, Release fence, Relaxed words, even version with Release).
//!   An entry names a journal, its client, its state (open, closed, writer
//!   lost), its join position, its final delivery boundary, the ring
//!   sequence of its last mirrored record, and its loss accounting as read
//!   with `losses`: the horizon, the stored count, at most
//!   [`MIRROR_RANGES`] drop ranges and the watermark. Membership and
//!   terminal facts live only here, never in the ring (J3).
//! - **The record ring**: a [`crate::diag_ring`] of observation records
//!   (journal number, journal sequence, payload), with the error log's
//!   seqlock, boundary and overwrite rules.
//!
//! Layout (structure words): a header stride (entries, words per entry,
//! words per ring record, ring capacity), then the entries of
//! [`ENTRY_WORDS`] words, then the ring (its own header stride and records
//! of [`MIRROR_RECORD_WORDS`] words).
//!
//! | Entry word | Field |
//! | --- | --- |
//! | 0 | Seqlock version |
//! | 1 | Journal number (0: the entry is free) |
//! | 2 | Client |
//! | 3 | State (bits 0..8: 1 open, 2 closed, 3 writer lost), flags (bits 8..16: join, boundary, last record, watermark), drop range count (bits 16..24) |
//! | 4, 5 | Join position (valid when its flag is set), final delivery boundary |
//! | 6 | Ring sequence of the journal's last mirrored record |
//! | 7, 8 | Payload words and capacity of the journal |
//! | 9, 10, 11 | Attempted horizon, stored count, records mirrored |
//! | 12, 13 | Watermark (`lost_before`), unstable loss entries |
//! | 14, 15 | Observed subscription's registration and its stream's registration (both 0 for a publisher-side journal) |
//! | 16 to 63 | Drop ranges: first, last, first time, last time, clock, epoch |
//!
//! Readers issue only `Relaxed` loads and `Acquire` fences, so they work
//! over a read-only mapping.

use std::sync::Arc;

use crate::atomic_view::{HeapWords, WORD_BYTES};
use crate::diag::Store;
use crate::diag_ring::{
    Appended, Bounds, FIELDS, RingReader, RingWriter, STRIDE_WORDS, Scan, ring_words, scan,
};
use crate::error::SysError;
use crate::record_journal::DropRange;
use crate::sync::{AtomicU64, Ordering, fence};

/// Words of one journal table entry: four strides.
pub const ENTRY_WORDS: usize = 64;
/// Words of one ring record: two strides.
pub const MIRROR_RECORD_WORDS: usize = 32;
/// Drop ranges an entry holds; a mirrored journal has at most this many.
pub const MIRROR_RANGES: usize = 8;
/// Payload words a ring record holds; a mirrored journal's records have at
/// most this many.
pub const MAX_MIRROR_PAYLOAD: usize = MIRROR_RECORD_WORDS - FIELDS - 3;
/// Layout version of the trace mirror's structure.
pub const MIRROR_LAYOUT_VERSION: u64 = 1;

/// Header words.
const HEADER_ENTRIES: usize = 0;
const HEADER_ENTRY_WORDS: usize = 1;
const HEADER_RECORD_WORDS: usize = 2;
const HEADER_CAPACITY: usize = 3;
/// Entry word of the drop ranges.
const RANGES: usize = 16;
/// Words of one drop range in an entry.
const RANGE_FIELDS: usize = 6;
/// Attempts a reader makes on an entry before reporting it busy.
const READ_ATTEMPTS: usize = 8;
/// Entry flags.
const HAS_JOIN: u64 = 1;
const HAS_BOUNDARY: u64 = 2;
const HAS_LAST: u64 = 4;
const HAS_WATERMARK: u64 = 8;

// The ranges fit an entry.
const _: () = assert!(RANGES + MIRROR_RANGES * RANGE_FIELDS <= ENTRY_WORDS);

/// The state of a journal in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JournalState {
    /// Its writer may still append.
    Open,
    /// Its writer closed it and the driver drained it to its end.
    Closed,
    /// Its writer is gone without closing it (its client exited or broke
    /// the journal's protocol): its boundary, if any, is the last known.
    WriterLost,
}

impl JournalState {
    const fn code(self) -> u64 {
        match self {
            Self::Open => 1,
            Self::Closed => 2,
            Self::WriterLost => 3,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Open),
            2 => Some(Self::Closed),
            3 => Some(Self::WriterLost),
            _ => None,
        }
    }
}

/// One journal of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalEntry {
    /// The journal number (nonzero), never reused within the driver
    /// instance.
    pub journal: u64,
    /// The client that holds it.
    pub client: u64,
    /// Its state.
    pub state: JournalState,
    /// The registration of the subscription it observes; 0 for a
    /// publisher-side journal.
    pub subscription: u64,
    /// The registration of that subscription's stream; 0 for a
    /// publisher-side journal.
    pub stream: u64,
    /// The join position of its subscription, as the driver recorded it;
    /// `None` for a publisher-side journal, which has none (the join flag
    /// of word 3 is clear).
    pub join: Option<u64>,
    /// Its final delivery boundary (`CloseJournal`), when known.
    pub boundary: Option<u64>,
    /// The ring sequence of its last mirrored record, if any.
    pub last_record: Option<u64>,
    /// Payload words of its records.
    pub payload_words: u64,
    /// Records it holds.
    pub capacity: u64,
    /// The horizon of its loss accounting: every sequence below it was
    /// attempted.
    pub attempted: u64,
    /// Records it stored, read after the horizon.
    pub stored: u64,
    /// Records the driver mirrored into the ring.
    pub mirrored: u64,
    /// Every sequence below it that is not a stored record may have been
    /// lost; `None` if no drop range was evicted.
    pub lost_before: Option<u64>,
    /// Drop-range or watermark entries that kept changing; when nonzero the
    /// loss accounting is partial.
    pub unstable: u64,
    /// Its drop ranges; the first `range_count` are valid.
    pub ranges: [DropRange; MIRROR_RANGES],
    /// Valid drop ranges.
    pub range_count: usize,
}

impl JournalEntry {
    /// A new open entry of `journal`, held by `client`.
    #[must_use]
    pub fn open(journal: u64, client: u64, payload_words: u64, capacity: u64) -> Self {
        Self {
            journal,
            client,
            state: JournalState::Open,
            subscription: 0,
            stream: 0,
            join: None,
            boundary: None,
            last_record: None,
            payload_words,
            capacity,
            attempted: 0,
            stored: 0,
            mirrored: 0,
            lost_before: None,
            unstable: 0,
            ranges: [DropRange::default(); MIRROR_RANGES],
            range_count: 0,
        }
    }

    /// The valid drop ranges.
    #[must_use]
    pub fn ranges(&self) -> &[DropRange] {
        self.ranges.get(..self.range_count).unwrap_or(&[])
    }

    fn encode(&self) -> [u64; ENTRY_WORDS] {
        let mut words = [0u64; ENTRY_WORDS];
        let flag = |present: bool, bit: u64| if present { bit } else { 0 };
        let flags = flag(self.join.is_some(), HAS_JOIN)
            | flag(self.boundary.is_some(), HAS_BOUNDARY)
            | flag(self.last_record.is_some(), HAS_LAST)
            | flag(self.lost_before.is_some(), HAS_WATERMARK);
        let count = self.range_count.min(MIRROR_RANGES) as u64;
        let fixed = [
            0,
            self.journal,
            self.client,
            self.state.code() | flags << 8 | count << 16,
            self.join.unwrap_or(0),
            self.boundary.unwrap_or(0),
            self.last_record.unwrap_or(0),
            self.payload_words,
            self.capacity,
            self.attempted,
            self.stored,
            self.mirrored,
            self.lost_before.unwrap_or(0),
            self.unstable,
            self.subscription,
            self.stream,
        ];
        for (word, value) in words.iter_mut().zip(fixed) {
            *word = value;
        }
        for (chunk, range) in words
            .get_mut(RANGES..)
            .unwrap_or(&mut [])
            .as_chunks_mut::<RANGE_FIELDS>()
            .0
            .iter_mut()
            .zip(self.ranges())
        {
            let fields = [
                range.first,
                range.last,
                range.first_time,
                range.last_time,
                range.clock,
                range.epoch,
            ];
            for (word, value) in chunk.iter_mut().zip(fields) {
                *word = value;
            }
        }
        words
    }

    /// Decodes stable entry words; `None` for a free entry or words no
    /// driver writes.
    fn decode(words: &[u64; ENTRY_WORDS]) -> Option<Self> {
        let word = |index: usize| words.get(index).copied().unwrap_or(0);
        let journal = word(1);
        if journal == 0 {
            return None;
        }
        let packed = word(3);
        let state = JournalState::from_code(packed & 0xFF)?;
        let flags = (packed >> 8) & 0xFF;
        let range_count = usize::try_from((packed >> 16) & 0xFF)
            .ok()
            .filter(|count| *count <= MIRROR_RANGES)?;
        let when = |bit: u64, value: u64| (flags & bit != 0).then_some(value);
        let mut ranges = [DropRange::default(); MIRROR_RANGES];
        for (range, chunk) in ranges
            .iter_mut()
            .zip(
                words
                    .get(RANGES..)
                    .unwrap_or(&[])
                    .as_chunks::<RANGE_FIELDS>()
                    .0,
            )
            .take(range_count)
        {
            let field = |index: usize| chunk.get(index).copied().unwrap_or(0);
            *range = DropRange {
                first: field(0),
                last: field(1),
                first_time: field(2),
                last_time: field(3),
                clock: field(4),
                epoch: field(5),
            };
        }
        Some(Self {
            journal,
            client: word(2),
            state,
            subscription: word(14),
            stream: word(15),
            join: when(HAS_JOIN, word(4)),
            boundary: when(HAS_BOUNDARY, word(5)),
            last_record: when(HAS_LAST, word(6)),
            payload_words: word(7),
            capacity: word(8),
            attempted: word(9),
            stored: word(10),
            mirrored: word(11),
            lost_before: when(HAS_WATERMARK, word(12)),
            unstable: word(13),
            ranges,
            range_count,
        })
    }
}

/// What a reader found in a table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "read on the control path and consumed at once; boxing would allocate per read"
)]
pub enum EntryRead {
    /// The entry holds no journal.
    Free,
    /// A stable copy of the entry.
    Entry(JournalEntry),
    /// The entry was being written on every attempt.
    Busy,
}

/// One observation record of the ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorRecord<'a> {
    /// Its ring sequence.
    pub seq: u64,
    /// The journal it was drained from.
    pub journal: u64,
    /// Its sequence in that journal.
    pub sequence: u64,
    /// Its payload words.
    pub payload: &'a [u64],
}

/// The sizes of a mirror of `entries` table entries and a ring of
/// `capacity` records: (structure words, ring offset); `None` on overflow
/// or a zero size.
fn geometry(entries: usize, capacity: usize) -> Option<(usize, usize)> {
    if entries == 0 || capacity == 0 {
        return None;
    }
    let ring = STRIDE_WORDS.checked_add(entries.checked_mul(ENTRY_WORDS)?)?;
    let total = ring.checked_add(ring_words(capacity, MIRROR_RECORD_WORDS)?)?;
    total.checked_mul(WORD_BYTES)?;
    Some((total, ring))
}

/// The driver's writer of the trace mirror: the conductor's.
#[derive(Debug)]
pub struct TraceMirror {
    store: Arc<Store>,
    entries: usize,
    ring: usize,
}

impl TraceMirror {
    fn new(store: Store, entries: usize, capacity: usize) -> Result<Self, SysError> {
        let invalid = SysError::InvalidRegion { address: 0, len: 0 };
        let (total, ring) = geometry(entries, capacity).ok_or(invalid)?;
        let words = store.words();
        if words.len() != total {
            return Err(invalid);
        }
        // The ring's header first, then the mirror's.
        RingWriter::create(
            words.get(ring..).ok_or(invalid)?,
            capacity,
            MIRROR_RECORD_WORDS,
        )
        .ok_or(invalid)?;
        for (index, value) in [
            (HEADER_ENTRIES, entries),
            (HEADER_ENTRY_WORDS, ENTRY_WORDS),
            (HEADER_RECORD_WORDS, MIRROR_RECORD_WORDS),
            (HEADER_CAPACITY, capacity),
        ] {
            words
                .get(index)
                .ok_or(invalid)?
                .store(value as u64, Ordering::Release);
        }
        Ok(Self {
            store: Arc::new(store),
            entries,
            ring,
        })
    }

    fn ring(&self) -> Option<RingWriter<'_>> {
        RingWriter::resume(self.store.words().get(self.ring..)?, MIRROR_RECORD_WORDS)
    }

    /// Table entries.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.entries
    }

    /// Writes table entry `index` under its seqlock: `entry`, or a free
    /// entry for `None`. `false` for an index out of range.
    pub fn write_entry(&mut self, index: usize, entry: Option<&JournalEntry>) -> bool {
        let Some(words) = index
            .checked_mul(ENTRY_WORDS)
            .and_then(|offset| offset.checked_add(STRIDE_WORDS))
            .filter(|_| index < self.entries)
            .and_then(|start| self.store.words().get(start..start + ENTRY_WORDS))
        else {
            return false;
        };
        let values = entry.map_or([0u64; ENTRY_WORDS], JournalEntry::encode);
        write_seqlocked(words, &values);
        true
    }

    /// Appends one observation record of `journal` with its journal
    /// `sequence` and `payload`; reports the record it overwrote when the
    /// ring was full. `None` for a payload longer than
    /// [`MAX_MIRROR_PAYLOAD`] or once the ring's sequences are exhausted.
    pub fn append(&mut self, journal: u64, sequence: u64, payload: &[u64]) -> Option<Appended> {
        if payload.len() > MAX_MIRROR_PAYLOAD {
            return None;
        }
        let mut fields = [0u64; MIRROR_RECORD_WORDS - FIELDS];
        let (head, tail) = fields.split_at_mut(3);
        head.copy_from_slice(&[journal, sequence, payload.len() as u64]);
        for (word, value) in tail.iter_mut().zip(payload) {
            *word = *value;
        }
        self.ring()?.append(&fields)
    }

    /// The ring's retained range.
    #[must_use]
    pub fn bounds(&self) -> Bounds {
        self.ring()
            .map_or(Bounds { first: 0, next: 0 }, |ring| ring.bounds())
    }

    /// A reader of this mirror.
    #[must_use]
    pub fn reader(&self) -> TraceMirrorReader {
        TraceMirrorReader {
            store: Arc::clone(&self.store),
            entries: self.entries,
            ring: self.ring,
        }
    }

    /// The shared region, to pass its descriptor; `None` on the heap.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn region(&self) -> Option<&crate::ipc::Region> {
        match &*self.store {
            Store::Mapped(region) => Some(region),
            _ => None,
        }
    }
}

/// Writes `values` into `words` under the seqlock of word 0.
fn write_seqlocked(words: &[AtomicU64], values: &[u64; ENTRY_WORDS]) {
    let Some(version) = words.first() else {
        return;
    };
    let odd = version.load(Ordering::Relaxed).wrapping_add(1) | 1;
    version.store(odd, Ordering::Relaxed);
    fence(Ordering::Release);
    for (word, value) in words.iter().zip(values).skip(1) {
        word.store(*value, Ordering::Relaxed);
    }
    version.store(odd.wrapping_add(1), Ordering::Release);
}

/// Creates a trace mirror of `entries` table entries and `capacity` ring
/// records on the heap.
///
/// # Errors
///
/// [`SysError::InvalidRegion`] for a zero or oversized size.
pub fn trace_mirror(entries: usize, capacity: usize) -> Result<TraceMirror, SysError> {
    let (total, _) =
        geometry(entries, capacity).ok_or(SysError::InvalidRegion { address: 0, len: 0 })?;
    TraceMirror::new(Store::Heap(HeapWords::zeroed(total)?), entries, capacity)
}

/// Creates a trace mirror in a new driver-only shared region of kind
/// `TraceMirror` (A2 seals).
///
/// # Errors
///
/// As [`trace_mirror`], and the errors of
/// [`crate::ipc::Region::create_driver_only`].
#[cfg(target_os = "linux")]
pub fn trace_mirror_in(
    instance: u128,
    region: u64,
    entries: usize,
    capacity: usize,
) -> Result<TraceMirror, SysError> {
    let invalid = SysError::InvalidRegion { address: 0, len: 0 };
    let (total, _) = geometry(entries, capacity).ok_or(invalid)?;
    let mapped = crate::ipc::Region::create_driver_only(crate::ipc::RegionRecord {
        instance,
        region,
        kind: crate::ipc::RegionKind::TraceMirror,
        generation: 0,
        layout: MIRROR_LAYOUT_VERSION,
        structure_length: total.checked_mul(WORD_BYTES).ok_or(invalid)?,
    })?;
    TraceMirror::new(Store::Mapped(mapped), entries, capacity)
}

/// A reader of a trace mirror: the driver's own, or a tool's over a
/// read-only mapping.
#[derive(Debug, Clone)]
pub struct TraceMirrorReader {
    store: Arc<Store>,
    entries: usize,
    ring: usize,
}

impl TraceMirrorReader {
    /// A reader of a trace mirror region mapped read-only (a tool): checks
    /// the kind, the layout version and the header against the size.
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidRegion`] for another kind, layout or size.
    #[cfg(target_os = "linux")]
    pub fn attach_read_only(region: crate::ipc::ReadOnlyRegion) -> Result<Self, SysError> {
        let record = region.record();
        let invalid = SysError::InvalidRegion {
            address: 0,
            len: record.structure_length,
        };
        if record.kind != crate::ipc::RegionKind::TraceMirror
            || record.layout != MIRROR_LAYOUT_VERSION
            || record.generation != 0
        {
            return Err(invalid);
        }
        let header = |index: usize| {
            region
                .structure()
                .load_acquire(index)
                .and_then(|value| usize::try_from(value).ok())
        };
        let (Some(entries), Some(ENTRY_WORDS), Some(MIRROR_RECORD_WORDS), Some(capacity)) = (
            header(HEADER_ENTRIES),
            header(HEADER_ENTRY_WORDS),
            header(HEADER_RECORD_WORDS),
            header(HEADER_CAPACITY),
        ) else {
            return Err(invalid);
        };
        let (total, ring) = geometry(entries, capacity).ok_or(invalid)?;
        if total.checked_mul(WORD_BYTES) != Some(record.structure_length) {
            return Err(invalid);
        }
        Ok(Self {
            store: Arc::new(Store::ReadOnly(region)),
            entries,
            ring,
        })
    }

    /// Table entries.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.entries
    }

    /// Reads table entry `index` under its seqlock, with a bounded number
    /// of attempts. An index out of range reads as free.
    #[must_use]
    pub fn entry(&self, index: usize) -> EntryRead {
        let Some(start) = index
            .checked_mul(ENTRY_WORDS)
            .and_then(|offset| offset.checked_add(STRIDE_WORDS))
            .filter(|_| index < self.entries)
        else {
            return EntryRead::Free;
        };
        let mut words = [0u64; ENTRY_WORDS];
        for _ in 0..READ_ATTEMPTS {
            let Some(before) = self.store.load(start) else {
                return EntryRead::Free;
            };
            fence(Ordering::Acquire);
            if before % 2 == 1 {
                continue;
            }
            for (offset, word) in words.iter_mut().enumerate().skip(1) {
                *word = self.store.load(start + offset).unwrap_or(0);
            }
            fence(Ordering::Acquire);
            if self.store.load(start) != Some(before) {
                continue;
            }
            return JournalEntry::decode(&words).map_or(EntryRead::Free, EntryRead::Entry);
        }
        EntryRead::Busy
    }

    fn ring_reader(&self) -> Option<RingReader<impl Fn(usize) -> Option<u64> + '_>> {
        let offset = self.ring;
        RingReader::new(
            move |index| self.store.load(offset.checked_add(index)?),
            MIRROR_RECORD_WORDS,
        )
    }

    /// The ring's retained range, from one Acquire load of its `next_seq`.
    #[must_use]
    pub fn bounds(&self) -> Option<Bounds> {
        self.ring_reader()?.bounds()
    }

    /// Scans the ring from `cursor` (see [`crate::diag_ring::scan`]),
    /// delivering each retained observation record in order. A record whose
    /// length word exceeds [`MAX_MIRROR_PAYLOAD`] is delivered with the
    /// payload cut to it.
    pub fn scan(&self, cursor: &mut u64, mut deliver: impl FnMut(MirrorRecord<'_>)) -> Scan {
        let Some(reader) = self.ring_reader() else {
            return Scan {
                overwritten: 0,
                delivered: 0,
                stopped: Some(crate::diag_ring::ScanStop::Busy),
            };
        };
        let mut buffer = [0u64; MIRROR_RECORD_WORDS - FIELDS];
        scan(&reader, cursor, &mut buffer, |seq, fields| {
            let field = |index: usize| fields.get(index).copied().unwrap_or(0);
            let length = usize::try_from(field(2))
                .unwrap_or(MAX_MIRROR_PAYLOAD)
                .min(MAX_MIRROR_PAYLOAD);
            deliver(MirrorRecord {
                seq,
                journal: field(0),
                sequence: field(1),
                payload: fields.get(3..3 + length).unwrap_or(&[]),
            });
        })
    }
}

#[cfg(test)]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]
mod tests {
    use super::*;

    fn entry(journal: u64) -> JournalEntry {
        let mut entry = JournalEntry::open(journal, 7, 25, 64);
        entry.subscription = 12;
        entry.stream = 3;
        entry.join = Some(0);
        entry.boundary = Some(4096);
        entry.last_record = Some(3);
        entry.lost_before = Some(2);
        entry.attempted = 10;
        entry.stored = 8;
        entry.mirrored = 8;
        entry.range_count = 2;
        entry.ranges[0] = DropRange {
            first: 3,
            last: 3,
            first_time: 30,
            last_time: 30,
            clock: 1,
            epoch: 2,
        };
        entry.ranges[1] = DropRange {
            first: 6,
            last: 6,
            ..entry.ranges[0]
        };
        entry
    }

    #[test]
    fn entries_round_trip_and_free_entries_read_free() {
        let mut mirror = trace_mirror(3, 4).unwrap();
        let reader = mirror.reader();
        assert_eq!(reader.entries(), 3);
        assert_eq!(reader.entry(0), EntryRead::Free);
        let written = entry(5);
        assert!(mirror.write_entry(1, Some(&written)));
        assert_eq!(reader.entry(1), EntryRead::Entry(written));
        assert_eq!(reader.entry(1).clone(), EntryRead::Entry(written));
        let EntryRead::Entry(read) = reader.entry(1) else {
            panic!("entry");
        };
        assert_eq!(read.ranges().len(), 2);
        // A join at position 0 is told apart from no join by its flag.
        assert_eq!(
            (read.join, read.subscription, read.stream),
            (Some(0), 12, 3)
        );
        let mut publisher = written;
        (publisher.join, publisher.subscription, publisher.stream) = (None, 0, 0);
        assert!(mirror.write_entry(1, Some(&publisher)));
        let EntryRead::Entry(read) = reader.entry(1) else {
            panic!("entry");
        };
        assert_eq!(read.join, None);
        assert!(mirror.write_entry(1, None));
        assert_eq!(reader.entry(1), EntryRead::Free);
        assert!(!mirror.write_entry(3, Some(&written)));
        assert_eq!(reader.entry(3), EntryRead::Free);
    }

    #[test]
    fn a_busy_entry_is_never_read_as_a_value() {
        let mut mirror = trace_mirror(1, 4).unwrap();
        mirror.write_entry(0, Some(&entry(1)));
        let version = &mirror.store.words()[STRIDE_WORDS];
        let even = version.load(Ordering::Relaxed);
        version.store(even + 1, Ordering::Relaxed);
        assert_eq!(mirror.reader().entry(0), EntryRead::Busy);
        version.store(even, Ordering::Relaxed);
        assert!(matches!(mirror.reader().entry(0), EntryRead::Entry(_)));
    }

    #[test]
    fn records_are_scanned_with_their_journal_and_overwrites_proven() {
        let mut mirror = trace_mirror(1, 2).unwrap();
        let reader = mirror.reader();
        assert_eq!(mirror.append(4, 0, &[1, 2, 3]).unwrap().seq, 0);
        assert!(mirror.append(4, 1, &[0; MAX_MIRROR_PAYLOAD + 1]).is_none());
        mirror.append(4, 2, &[7; MAX_MIRROR_PAYLOAD]).unwrap();
        let appended = mirror.append(9, 0, &[]).unwrap();
        assert_eq!(appended.overwrote, Some(0));
        assert_eq!(mirror.bounds(), Bounds { first: 1, next: 3 });
        let mut cursor = 0;
        let mut seen = Vec::new();
        let scan = reader.scan(&mut cursor, |record| {
            seen.push((
                record.seq,
                record.journal,
                record.sequence,
                record.payload.to_vec(),
            ));
        });
        assert_eq!(scan.overwritten, 1, "ring record 0 is mirror loss");
        assert_eq!(
            seen,
            vec![
                (1, 4, 2, vec![7; MAX_MIRROR_PAYLOAD]),
                (2, 9, 0, Vec::new())
            ]
        );
        assert_eq!(reader.bounds(), Some(Bounds { first: 1, next: 3 }));
    }

    #[test]
    fn sizes_are_checked() {
        assert!(trace_mirror(0, 4).is_err());
        assert!(trace_mirror(4, 0).is_err());
        assert!(trace_mirror(usize::MAX / 2, 4).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_tool_reads_the_mirror_read_only() {
        use crate::ipc::{ReadOnlyRegion, RegionKind, SealProfile};

        let mut mirror = trace_mirror_in(5, 3, 2, 8).unwrap();
        mirror.write_entry(0, Some(&entry(11)));
        mirror.append(11, 0, &[42]).unwrap();
        let region = mirror.region().unwrap();
        let fd = region.read_only_descriptor().unwrap();
        let read_only =
            ReadOnlyRegion::attach(fd, region.record(), SealProfile::DriverOnly).unwrap();
        let reader = TraceMirrorReader::attach_read_only(read_only).unwrap();
        assert_eq!(reader.entry(0), EntryRead::Entry(entry(11)));
        let mut payloads = Vec::new();
        reader.scan(&mut 0, |record| payloads.push(record.payload.to_vec()));
        assert_eq!(payloads, vec![vec![42]]);
        // Another kind's reader refuses it.
        let fd = region.read_only_descriptor().unwrap();
        let mut record = region.record();
        record.kind = RegionKind::TraceMirror;
        let read_only = ReadOnlyRegion::attach(fd, record, SealProfile::DriverOnly).unwrap();
        assert!(crate::diag::ErrorLogReader::attach_read_only(read_only).is_err());
    }
}
