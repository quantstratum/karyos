// SPDX-License-Identifier: Apache-2.0

//! The trace mirror (`quantstratum-docs:
//! karyos/design/trace-journal-region.md`, J1; amended by T2, T4 and T5 of
//! `trace-tool.md`): the driver drains every client trace journal and
//! copies its records here, into one region only the driver writes (A2
//! seals) and tools map read-only (A1). It holds three parts:
//!
//! - **The journal table**: a fixed number of entries, each written only by
//!   the driver under a seqlock (the algorithm of the error log's records:
//!   odd version, Release fence, Relaxed words, even version with Release).
//!   An entry names a journal, its client, its state (open, closed, writer
//!   lost), its kind (subscriber or publisher), the registration it
//!   observes, its stream's registration and the publication's
//!   incarnation (so the entry alone names the publication), the time
//!   namespace word and the clock provenance word, its join position, its
//!   final delivery boundary, the ring sequence of its last mirrored
//!   record, and its loss accounting as read with `losses`: the horizon,
//!   the stored count, at most [`MIRROR_RANGES`] drop ranges and the
//!   watermark. Membership and terminal facts live only here, never in the
//!   ring (J3).
//! - **The recycle log**, in the header: a fixed number of entries under
//!   the same seqlock, one per recycled subscriber entry whose publication
//!   may still have a `Publish` record pending or retained (T5): the
//!   subscriber journal, its publication (stream registration and
//!   incarnation; the driver instance is implicit), its final state and
//!   boundary, and the publisher journals the driver noted when it ended
//!   with their attempted counts at that moment, at most
//!   [`MAX_RECYCLE_PAIRS`]. The driver writes a log entry before it reuses
//!   the table entry, so a reader that reads the table and then the log
//!   never misses a subscriber journal that is in neither.
//! - **The record ring**: a [`crate::diag_ring`] of observation records
//!   (journal number, journal sequence, payload), with the error log's
//!   seqlock, boundary and overwrite rules.
//!
//! Layout (structure words): a header stride (table entries, words per
//! entry, words per ring record, ring capacity, log entries, words per log
//! entry), then the log entries of [`LOG_ENTRY_WORDS`] words, then the
//! table entries of [`ENTRY_WORDS`] words, then the ring (its own header
//! stride and records of [`MIRROR_RECORD_WORDS`] words).
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
//! | 14, 15 | Observed registration (the subscription of a subscriber journal, the publication of a publisher journal) and its stream's registration |
//! | 16 | Kind: 1 subscriber, 2 publisher |
//! | 17 | Incarnation of the publication |
//! | 18 | Time namespace: 0 unknown, 1 the driver's, 2 another |
//! | 19 | Clock provenance, as the client sent it (opaque to the driver) |
//! | 20 to 67 | Drop ranges: first, last, first time, last time, clock, epoch |
//! | 68 to 79 | Reserved, zero |
//!
//! | Log entry word | Field |
//! | --- | --- |
//! | 0 | Seqlock version |
//! | 1 | Recycled subscriber journal number (0: the log entry is free) |
//! | 2, 3 | Its publication: stream registration, incarnation |
//! | 4 | Final state (bits 0..8: 2 closed, 3 writer lost), flags (bits 8..16: boundary), noted pair count (bits 16..24) |
//! | 5 | Final delivery boundary (valid when its flag is set) |
//! | 6 to 31 | Noted pairs: publisher journal number, its attempted count when the subscriber journal ended |
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

/// Words of one journal table entry: five strides.
pub const ENTRY_WORDS: usize = 80;
/// Words of one recycle log entry: two strides.
pub const LOG_ENTRY_WORDS: usize = 32;
/// Noted publisher journals a recycle log entry holds. A subscriber entry
/// whose publication had more publisher journals in the table when it
/// ended is never logged: it is reused only once it is covered.
pub const MAX_RECYCLE_PAIRS: usize = (LOG_ENTRY_WORDS - PAIRS) / 2;
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
const HEADER_LOG_ENTRIES: usize = 4;
const HEADER_LOG_WORDS: usize = 5;
/// Entry word of the drop ranges.
const RANGES: usize = 20;
/// Log entry word of the noted pairs.
const PAIRS: usize = 6;
/// Words of one drop range in an entry.
const RANGE_FIELDS: usize = 6;
/// Attempts a reader makes on an entry before reporting it busy.
const READ_ATTEMPTS: usize = 8;
/// Entry flags.
const HAS_JOIN: u64 = 1;
const HAS_BOUNDARY: u64 = 2;
const HAS_LAST: u64 = 4;
const HAS_WATERMARK: u64 = 8;

// The ranges fit an entry, and the pairs a log entry.
const _: () = assert!(RANGES + MIRROR_RANGES * RANGE_FIELDS <= ENTRY_WORDS);
const _: () = assert!(PAIRS + MAX_RECYCLE_PAIRS * 2 <= LOG_ENTRY_WORDS);

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

/// What a journal observes (T4): the registration in its entry names a
/// subscription or a publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JournalKind {
    /// A subscriber journal: it observes one of its client's
    /// subscriptions, and joins the expected set of every message of the
    /// publication from its join position up to its boundary.
    Subscriber,
    /// A publisher journal: it observes one of its client's publications
    /// and records that publication's `Publish` observations.
    Publisher,
}

impl JournalKind {
    const fn code(self) -> u64 {
        match self {
            Self::Subscriber => 1,
            Self::Publisher => 2,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Subscriber),
            2 => Some(Self::Publisher),
            _ => None,
        }
    }
}

/// How a journal's client stands to the driver's time namespace (T2):
/// two `HostMonotonic` clocks read the same `CLOCK_MONOTONIC` only within
/// one Linux time namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeNamespace {
    /// The driver could not tell: not Linux, a kernel without time
    /// namespaces, or a process it could not inspect.
    Unknown,
    /// The client is in the driver's time namespace.
    Same,
    /// The client is in another time namespace.
    Different,
}

impl TimeNamespace {
    /// The word an entry stores.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Unknown => 0,
            Self::Same => 1,
            Self::Different => 2,
        }
    }

    /// The namespace of an entry's word; `None` for a word no driver
    /// writes.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Unknown),
            1 => Some(Self::Same),
            2 => Some(Self::Different),
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
    /// What it observes.
    pub kind: JournalKind,
    /// The registration it observes: a subscription of its client for a
    /// subscriber journal, a publication of its client for a publisher
    /// journal.
    pub registration: u64,
    /// The registration of the observed registration's stream: with
    /// `incarnation` and the driver instance it names the publication
    /// `(driver_id, registration, incarnation)`.
    pub stream: u64,
    /// The incarnation of that publication; a mapping cutover keeps it.
    pub incarnation: u64,
    /// The client's time namespace against the driver's, checked when the
    /// journal was created.
    pub time_namespace: TimeNamespace,
    /// The clock provenance word the client sent with `TraceJournal`; the
    /// driver records it without interpreting it.
    pub provenance: u64,
    /// The join position of its subscription, as the driver recorded it;
    /// `None` for a publisher journal, which has none (the join flag of
    /// word 3 is clear).
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
    /// A new open entry of `journal` of `kind`, held by `client`; the
    /// observed registration, its stream and incarnation are 0, the time
    /// namespace unknown and the provenance 0 until set.
    #[must_use]
    pub fn open(
        journal: u64,
        client: u64,
        kind: JournalKind,
        payload_words: u64,
        capacity: u64,
    ) -> Self {
        Self {
            journal,
            client,
            state: JournalState::Open,
            kind,
            registration: 0,
            stream: 0,
            incarnation: 0,
            time_namespace: TimeNamespace::Unknown,
            provenance: 0,
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
            self.registration,
            self.stream,
            self.kind.code(),
            self.incarnation,
            self.time_namespace.code(),
            self.provenance,
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
        let kind = JournalKind::from_code(word(16))?;
        let time_namespace = TimeNamespace::from_code(word(18))?;
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
            kind,
            registration: word(14),
            stream: word(15),
            incarnation: word(17),
            time_namespace,
            provenance: word(19),
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

/// A publisher journal the driver noted when a subscriber journal ended,
/// with its attempted count at that moment: every `Publish` the
/// subscriber journal could have been expected for has a journal sequence
/// below it (`trace-tool.md`, "Recycled entries").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NotedPublisher {
    /// The publisher journal's number.
    pub journal: u64,
    /// Its attempted count when the subscriber journal ended (final for a
    /// journal that had already ended).
    pub attempted: u64,
}

/// One recycle log entry: a subscriber journal whose table entry was
/// reused while a `Publish` that could need it may still be pending or
/// retained. A tool treats the messages of its publication at positions at
/// or below its boundary as out of scope (`trace-tool.md`, T5); for an
/// entry without a boundary (writer lost), every message of its
/// publication is out of scope while the log entry stays
/// (`trace-journal-region.md`, "Recycling").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecycledJournal {
    /// The recycled subscriber journal's number (nonzero).
    pub journal: u64,
    /// Its publication's stream registration.
    pub stream: u64,
    /// Its publication's incarnation.
    pub incarnation: u64,
    /// Its final state: closed or writer lost.
    pub state: JournalState,
    /// Its final delivery boundary, when known.
    pub boundary: Option<u64>,
    /// The noted publisher journals; the first `pair_count` are valid.
    pub pairs: [NotedPublisher; MAX_RECYCLE_PAIRS],
    /// Valid noted pairs.
    pub pair_count: usize,
}

impl RecycledJournal {
    /// The valid noted pairs.
    #[must_use]
    pub fn pairs(&self) -> &[NotedPublisher] {
        self.pairs.get(..self.pair_count).unwrap_or(&[])
    }

    fn encode(&self) -> [u64; LOG_ENTRY_WORDS] {
        let mut words = [0u64; LOG_ENTRY_WORDS];
        let flags = if self.boundary.is_some() {
            HAS_BOUNDARY
        } else {
            0
        };
        let count = self.pair_count.min(MAX_RECYCLE_PAIRS) as u64;
        let fixed = [
            0,
            self.journal,
            self.stream,
            self.incarnation,
            self.state.code() | flags << 8 | count << 16,
            self.boundary.unwrap_or(0),
        ];
        for (word, value) in words.iter_mut().zip(fixed) {
            *word = value;
        }
        for (chunk, pair) in words
            .get_mut(PAIRS..)
            .unwrap_or(&mut [])
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .zip(self.pairs())
        {
            *chunk = [pair.journal, pair.attempted];
        }
        words
    }

    /// Decodes stable log entry words; `None` for a free entry or words no
    /// driver writes.
    fn decode(words: &[u64; LOG_ENTRY_WORDS]) -> Option<Self> {
        let word = |index: usize| words.get(index).copied().unwrap_or(0);
        let journal = word(1);
        if journal == 0 {
            return None;
        }
        let packed = word(4);
        let state =
            JournalState::from_code(packed & 0xFF).filter(|state| *state != JournalState::Open)?;
        let flags = (packed >> 8) & 0xFF;
        let pair_count = usize::try_from((packed >> 16) & 0xFF)
            .ok()
            .filter(|count| *count <= MAX_RECYCLE_PAIRS)?;
        let mut pairs = [NotedPublisher::default(); MAX_RECYCLE_PAIRS];
        for (pair, chunk) in pairs
            .iter_mut()
            .zip(words.get(PAIRS..).unwrap_or(&[]).as_chunks::<2>().0)
            .take(pair_count)
        {
            let [journal, attempted] = *chunk;
            *pair = NotedPublisher { journal, attempted };
        }
        Some(Self {
            journal,
            stream: word(2),
            incarnation: word(3),
            state,
            boundary: (flags & HAS_BOUNDARY != 0).then_some(word(5)),
            pairs,
            pair_count,
        })
    }
}

/// What a reader found in a recycle log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "read on the control path and consumed at once; boxing would allocate per read"
)]
pub enum LogRead {
    /// The log entry holds nothing.
    Free,
    /// A stable copy of the log entry.
    Entry(RecycledJournal),
    /// The log entry was being written on every attempt.
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

/// The sizes of a mirror of `entries` table entries, `log` recycle log
/// entries and a ring of `capacity` records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    /// Structure words.
    total: usize,
    /// Word of the first table entry.
    table: usize,
    /// Word of the ring's header.
    ring: usize,
}

/// The [`Geometry`] of a mirror; `None` on overflow or a zero size.
fn geometry(entries: usize, log: usize, capacity: usize) -> Option<Geometry> {
    if entries == 0 || log == 0 || capacity == 0 {
        return None;
    }
    let table = STRIDE_WORDS.checked_add(log.checked_mul(LOG_ENTRY_WORDS)?)?;
    let ring = table.checked_add(entries.checked_mul(ENTRY_WORDS)?)?;
    let total = ring.checked_add(ring_words(capacity, MIRROR_RECORD_WORDS)?)?;
    total.checked_mul(WORD_BYTES)?;
    Some(Geometry { total, table, ring })
}

/// The first word of slot `index` of `count` slots of `words` words from
/// `base`; `None` out of range.
fn slot_start(base: usize, index: usize, count: usize, words: usize) -> Option<usize> {
    index
        .checked_mul(words)
        .and_then(|offset| offset.checked_add(base))
        .filter(|_| index < count)
}

/// The driver's writer of the trace mirror: the conductor's.
#[derive(Debug)]
pub struct TraceMirror {
    store: Arc<Store>,
    entries: usize,
    log: usize,
    geometry: Geometry,
}

impl TraceMirror {
    fn new(store: Store, entries: usize, log: usize, capacity: usize) -> Result<Self, SysError> {
        let invalid = SysError::InvalidRegion { address: 0, len: 0 };
        let geometry = geometry(entries, log, capacity).ok_or(invalid)?;
        let ring = geometry.ring;
        let words = store.words();
        if words.len() != geometry.total {
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
            (HEADER_LOG_ENTRIES, log),
            (HEADER_LOG_WORDS, LOG_ENTRY_WORDS),
        ] {
            words
                .get(index)
                .ok_or(invalid)?
                .store(value as u64, Ordering::Release);
        }
        Ok(Self {
            store: Arc::new(store),
            entries,
            log,
            geometry,
        })
    }

    fn ring(&self) -> Option<RingWriter<'_>> {
        RingWriter::resume(
            self.store.words().get(self.geometry.ring..)?,
            MIRROR_RECORD_WORDS,
        )
    }

    /// Table entries.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.entries
    }

    /// Recycle log entries.
    #[must_use]
    pub fn log_entries(&self) -> usize {
        self.log
    }

    /// Writes table entry `index` under its seqlock: `entry`, or a free
    /// entry for `None`. `false` for an index out of range.
    pub fn write_entry(&mut self, index: usize, entry: Option<&JournalEntry>) -> bool {
        let Some(words) = slot_start(self.geometry.table, index, self.entries, ENTRY_WORDS)
            .and_then(|start| {
                self.store
                    .words()
                    .get(start..start.checked_add(ENTRY_WORDS)?)
            })
        else {
            return false;
        };
        let values = entry.map_or([0u64; ENTRY_WORDS], JournalEntry::encode);
        write_seqlocked(words, &values);
        true
    }

    /// Writes recycle log entry `index` under its seqlock: `entry`, or a
    /// free log entry for `None`. `false` for an index out of range.
    pub fn write_log(&mut self, index: usize, entry: Option<&RecycledJournal>) -> bool {
        let Some(words) =
            slot_start(STRIDE_WORDS, index, self.log, LOG_ENTRY_WORDS).and_then(|start| {
                self.store
                    .words()
                    .get(start..start.checked_add(LOG_ENTRY_WORDS)?)
            })
        else {
            return false;
        };
        let values = entry.map_or([0u64; LOG_ENTRY_WORDS], RecycledJournal::encode);
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
            log: self.log,
            geometry: self.geometry,
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
fn write_seqlocked(words: &[AtomicU64], values: &[u64]) {
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

/// Creates a trace mirror of `entries` table entries, `log` recycle log
/// entries and `capacity` ring records on the heap.
///
/// # Errors
///
/// [`SysError::InvalidRegion`] for a zero or oversized size.
pub fn trace_mirror(entries: usize, log: usize, capacity: usize) -> Result<TraceMirror, SysError> {
    let geometry =
        geometry(entries, log, capacity).ok_or(SysError::InvalidRegion { address: 0, len: 0 })?;
    TraceMirror::new(
        Store::Heap(HeapWords::zeroed(geometry.total)?),
        entries,
        log,
        capacity,
    )
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
    log: usize,
    capacity: usize,
) -> Result<TraceMirror, SysError> {
    let invalid = SysError::InvalidRegion { address: 0, len: 0 };
    let total = geometry(entries, log, capacity).ok_or(invalid)?.total;
    let mapped = crate::ipc::Region::create_driver_only(crate::ipc::RegionRecord {
        instance,
        region,
        kind: crate::ipc::RegionKind::TraceMirror,
        generation: 0,
        layout: MIRROR_LAYOUT_VERSION,
        structure_length: total.checked_mul(WORD_BYTES).ok_or(invalid)?,
    })?;
    TraceMirror::new(Store::Mapped(mapped), entries, log, capacity)
}

/// A reader of a trace mirror: the driver's own, or a tool's over a
/// read-only mapping.
///
/// A reader that needs every subscriber journal the driver still accounts
/// for reads the table first and then the recycle log: the driver writes a
/// log entry before it reuses the table entry it describes.
#[derive(Debug, Clone)]
pub struct TraceMirrorReader {
    store: Arc<Store>,
    entries: usize,
    log: usize,
    geometry: Geometry,
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
        let (
            Some(entries),
            Some(ENTRY_WORDS),
            Some(MIRROR_RECORD_WORDS),
            Some(capacity),
            Some(log),
            Some(LOG_ENTRY_WORDS),
        ) = (
            header(HEADER_ENTRIES),
            header(HEADER_ENTRY_WORDS),
            header(HEADER_RECORD_WORDS),
            header(HEADER_CAPACITY),
            header(HEADER_LOG_ENTRIES),
            header(HEADER_LOG_WORDS),
        )
        else {
            return Err(invalid);
        };
        let geometry = geometry(entries, log, capacity).ok_or(invalid)?;
        if geometry.total.checked_mul(WORD_BYTES) != Some(record.structure_length) {
            return Err(invalid);
        }
        Ok(Self {
            store: Arc::new(Store::ReadOnly(region)),
            entries,
            log,
            geometry,
        })
    }

    /// Table entries.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.entries
    }

    /// Recycle log entries.
    #[must_use]
    pub fn log_entries(&self) -> usize {
        self.log
    }

    /// Reads table entry `index` under its seqlock, with a bounded number
    /// of attempts. An index out of range reads as free.
    #[must_use]
    pub fn entry(&self, index: usize) -> EntryRead {
        let Some(start) = slot_start(self.geometry.table, index, self.entries, ENTRY_WORDS) else {
            return EntryRead::Free;
        };
        match self.read_seqlocked::<ENTRY_WORDS>(start) {
            Seqlocked::Gone => EntryRead::Free,
            Seqlocked::Busy => EntryRead::Busy,
            Seqlocked::Stable(words) => {
                JournalEntry::decode(&words).map_or(EntryRead::Free, EntryRead::Entry)
            }
        }
    }

    /// Reads recycle log entry `index` under its seqlock, with a bounded
    /// number of attempts. An index out of range reads as free.
    #[must_use]
    pub fn log_entry(&self, index: usize) -> LogRead {
        let Some(start) = slot_start(STRIDE_WORDS, index, self.log, LOG_ENTRY_WORDS) else {
            return LogRead::Free;
        };
        match self.read_seqlocked::<LOG_ENTRY_WORDS>(start) {
            Seqlocked::Gone => LogRead::Free,
            Seqlocked::Busy => LogRead::Busy,
            Seqlocked::Stable(words) => {
                RecycledJournal::decode(&words).map_or(LogRead::Free, LogRead::Entry)
            }
        }
    }

    /// A stable copy of the `N` words at `start` under the seqlock of their
    /// first word.
    fn read_seqlocked<const N: usize>(&self, start: usize) -> Seqlocked<N> {
        let mut words = [0u64; N];
        for _ in 0..READ_ATTEMPTS {
            let Some(before) = self.store.load(start) else {
                return Seqlocked::Gone;
            };
            fence(Ordering::Acquire);
            if before % 2 == 1 {
                continue;
            }
            for (offset, word) in words.iter_mut().enumerate().skip(1) {
                *word = start
                    .checked_add(offset)
                    .and_then(|index| self.store.load(index))
                    .unwrap_or(0);
            }
            fence(Ordering::Acquire);
            if self.store.load(start) != Some(before) {
                continue;
            }
            return Seqlocked::Stable(words);
        }
        Seqlocked::Busy
    }

    fn ring_reader(&self) -> Option<RingReader<impl Fn(usize) -> Option<u64> + '_>> {
        let offset = self.geometry.ring;
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

/// What a seqlocked read found.
enum Seqlocked<const N: usize> {
    /// The words are outside the store.
    Gone,
    /// The words were being written on every attempt.
    Busy,
    /// A stable copy.
    Stable([u64; N]),
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
        let mut entry = JournalEntry::open(journal, 7, JournalKind::Subscriber, 25, 64);
        entry.registration = 12;
        entry.stream = 3;
        entry.incarnation = 1;
        entry.time_namespace = TimeNamespace::Same;
        entry.provenance = 0xFEED;
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

    fn recycled(journal: u64, pairs: usize) -> RecycledJournal {
        let mut log = RecycledJournal {
            journal,
            stream: 3,
            incarnation: 1,
            state: JournalState::Closed,
            boundary: Some(4096),
            pairs: [NotedPublisher::default(); MAX_RECYCLE_PAIRS],
            pair_count: pairs,
        };
        for (index, pair) in log.pairs.iter_mut().take(pairs).enumerate() {
            *pair = NotedPublisher {
                journal: 100 + index as u64,
                attempted: 10 * index as u64,
            };
        }
        log
    }

    #[test]
    fn entries_round_trip_and_free_entries_read_free() {
        let mut mirror = trace_mirror(3, 1, 4).unwrap();
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
            (read.join, read.registration, read.stream, read.incarnation),
            (Some(0), 12, 3, 1)
        );
        assert_eq!(
            (read.kind, read.time_namespace, read.provenance),
            (JournalKind::Subscriber, TimeNamespace::Same, 0xFEED)
        );
        let mut publisher = written;
        publisher.kind = JournalKind::Publisher;
        publisher.join = None;
        publisher.time_namespace = TimeNamespace::Different;
        assert!(mirror.write_entry(1, Some(&publisher)));
        let EntryRead::Entry(read) = reader.entry(1) else {
            panic!("entry");
        };
        assert_eq!(
            (read.kind, read.join, read.time_namespace),
            (JournalKind::Publisher, None, TimeNamespace::Different)
        );
        publisher.time_namespace = TimeNamespace::Unknown;
        assert!(mirror.write_entry(1, Some(&publisher)));
        assert_eq!(reader.entry(1), EntryRead::Entry(publisher));
        assert!(mirror.write_entry(1, None));
        assert_eq!(reader.entry(1), EntryRead::Free);
        assert!(!mirror.write_entry(3, Some(&written)));
        assert_eq!(reader.entry(3), EntryRead::Free);
    }

    /// Words no driver writes (an unknown kind or time namespace code)
    /// read as free, never as a value.
    #[test]
    fn unknown_codes_read_free() {
        let mut mirror = trace_mirror(1, 1, 4).unwrap();
        let table = mirror.geometry.table;
        for (word, value) in [(16, 3), (16, 0), (18, 3)] {
            mirror.write_entry(0, Some(&entry(1)));
            mirror.store.words()[table + word].store(value, Ordering::Relaxed);
            assert_eq!(mirror.reader().entry(0), EntryRead::Free, "word {word}");
        }
    }

    /// The recycle log: entries round trip with their pairs, free entries
    /// read free, an open state or too many pairs read free, a busy entry
    /// is never read as a value, and the log sits apart from the table.
    #[test]
    fn recycle_log_entries_round_trip() {
        let mut mirror = trace_mirror(2, 2, 4).unwrap();
        let reader = mirror.reader();
        assert_eq!(reader.log_entries(), 2);
        assert_eq!(mirror.log_entries(), 2);
        assert_eq!(reader.log_entry(0), LogRead::Free);
        let full = recycled(9, MAX_RECYCLE_PAIRS);
        assert!(mirror.write_log(1, Some(&full)));
        assert_eq!(reader.log_entry(1), LogRead::Entry(full));
        let LogRead::Entry(read) = reader.log_entry(1) else {
            panic!("log entry");
        };
        assert_eq!(read.pairs().len(), MAX_RECYCLE_PAIRS);
        assert_eq!(
            read.pairs()[MAX_RECYCLE_PAIRS - 1],
            NotedPublisher {
                journal: 100 + MAX_RECYCLE_PAIRS as u64 - 1,
                attempted: 10 * (MAX_RECYCLE_PAIRS as u64 - 1)
            }
        );
        // Writer lost, without a boundary and without pairs.
        let mut lost = recycled(10, 0);
        (lost.state, lost.boundary) = (JournalState::WriterLost, None);
        assert!(mirror.write_log(0, Some(&lost)));
        assert_eq!(reader.log_entry(0), LogRead::Entry(lost));
        // The table is untouched by the log.
        assert_eq!(reader.entry(0), EntryRead::Free);
        assert!(mirror.write_entry(0, Some(&entry(4))));
        assert_eq!(reader.log_entry(0), LogRead::Entry(lost));
        assert!(mirror.write_log(0, None));
        assert_eq!(reader.log_entry(0), LogRead::Free);
        assert!(!mirror.write_log(2, Some(&lost)));
        assert_eq!(reader.log_entry(2), LogRead::Free);
        // Words no driver writes read free: an open state, too many pairs.
        let words = mirror.store.words();
        let start = STRIDE_WORDS + LOG_ENTRY_WORDS;
        let packed = words[start + 4].load(Ordering::Relaxed);
        words[start + 4].store(packed & !0xFF | 1, Ordering::Relaxed);
        assert_eq!(reader.log_entry(1), LogRead::Free);
        words[start + 4].store(
            packed | ((MAX_RECYCLE_PAIRS as u64 + 1) << 16),
            Ordering::Relaxed,
        );
        assert_eq!(reader.log_entry(1), LogRead::Free);
        words[start + 4].store(packed, Ordering::Relaxed);
        // Busy while its version is odd.
        let version = &words[start];
        let even = version.load(Ordering::Relaxed);
        version.store(even + 1, Ordering::Relaxed);
        assert_eq!(reader.log_entry(1), LogRead::Busy);
        version.store(even, Ordering::Relaxed);
        assert_eq!(reader.log_entry(1), LogRead::Entry(full));
    }

    #[test]
    fn a_busy_entry_is_never_read_as_a_value() {
        let mut mirror = trace_mirror(1, 1, 4).unwrap();
        mirror.write_entry(0, Some(&entry(1)));
        let version = &mirror.store.words()[mirror.geometry.table];
        let even = version.load(Ordering::Relaxed);
        version.store(even + 1, Ordering::Relaxed);
        assert_eq!(mirror.reader().entry(0), EntryRead::Busy);
        version.store(even, Ordering::Relaxed);
        assert!(matches!(mirror.reader().entry(0), EntryRead::Entry(_)));
    }

    #[test]
    fn records_are_scanned_with_their_journal_and_overwrites_proven() {
        let mut mirror = trace_mirror(1, 1, 2).unwrap();
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
        assert!(trace_mirror(0, 1, 4).is_err());
        assert!(trace_mirror(4, 0, 4).is_err());
        assert!(trace_mirror(4, 1, 0).is_err());
        assert!(trace_mirror(usize::MAX / 2, 1, 4).is_err());
        assert!(trace_mirror(1, usize::MAX / 2, 4).is_err());
        // The log comes first, then the table, then the ring.
        let geometry = geometry(3, 2, 4).unwrap();
        assert_eq!(geometry.table, STRIDE_WORDS + 2 * LOG_ENTRY_WORDS);
        assert_eq!(geometry.ring, geometry.table + 3 * ENTRY_WORDS);
        assert_eq!(
            geometry.total,
            geometry.ring + ring_words(4, MIRROR_RECORD_WORDS).unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_tool_reads_the_mirror_read_only() {
        use crate::ipc::{ReadOnlyRegion, RegionKind, SealProfile};

        let mut mirror = trace_mirror_in(5, 3, 2, 2, 8).unwrap();
        mirror.write_entry(0, Some(&entry(11)));
        mirror.write_log(1, Some(&recycled(12, 2)));
        mirror.append(11, 0, &[42]).unwrap();
        let region = mirror.region().unwrap();
        let fd = region.read_only_descriptor().unwrap();
        let read_only =
            ReadOnlyRegion::attach(fd, region.record(), SealProfile::DriverOnly).unwrap();
        let reader = TraceMirrorReader::attach_read_only(read_only).unwrap();
        assert_eq!(reader.entry(0), EntryRead::Entry(entry(11)));
        assert_eq!(reader.log_entries(), 2);
        assert_eq!(reader.log_entry(1), LogRead::Entry(recycled(12, 2)));
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
