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
//! entry, in word 6 the highest mirror sequence assigned so far, T7, and in
//! word 7 the count of network journals refused, `trace-network.md` §5),
//! then the log entries of [`LOG_ENTRY_WORDS`] words, then the
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
//! | 14, 15 | Observed registration (the subscription of a subscriber journal, the publication of a publisher journal, the publication of a network sender journal, the image of a network receiver journal) and its stream's registration (for a network journal, on the sender's driver) |
//! | 16 | Kind: 1 subscriber, 2 publisher, 3 network sender, 4 network receiver |
//! | 17 | Incarnation of the publication |
//! | 18 | Time namespace: 0 unknown, 1 the driver's, 2 another |
//! | 19 | Clock provenance, as the client sent it (opaque to the driver) |
//! | 20 to 67 | Drop ranges: first, last, first time, last time, clock, epoch |
//! | 68 | Mirror sequence: the journal's place among the journals the driver created, from 1, dense (T7) |
//! | 69 | Lane of the observed registration, below 4: with word 15 it names the aggregate lane (`aggregate-ownership.md`) |
//! | 70, 71 | Network journals: the sender's `driver_id`, low and high; zero for kinds 1 and 2 |
//! | 72 | Kind 3: pickup start; kind 4: image join |
//! | 73 | Kind 3: pickup boundary; kind 4: commit boundary |
//! | 74 | Kind 4: start of the image's first sealed gap |
//! | 75 | Network flags: bit 0 word 72, bit 1 word 73, bit 2 word 74 valid |
//! | 76 to 79 | Reserved, zero |
//!
//! A network journal (kinds 3 and 4, `trace-network.md` §5) is written by
//! the driver itself: its client word is zero, and its join and boundary
//! live in words 72 and 73, with words 4 and 5 and their flags clear.
//!
//! | Log entry word | Field |
//! | --- | --- |
//! | 0 | Seqlock version |
//! | 1 | Recycled subscriber journal number (0: the log entry is free) |
//! | 2, 3 | Its publication: stream registration, incarnation |
//! | 4 | Final state (bits 0..8: 2 closed, 3 writer lost), flags (bits 8..16: boundary), noted pair count (bits 16..24) |
//! | 5 | Final delivery boundary (valid when its flag is set) |
//! | 6 | Mirror sequence of the recycled subscriber journal (T7) |
//! | 7 to 30 | Noted pairs: publisher journal number, its attempted count when the subscriber journal ended |
//! | 31 | Lane of its publication, below 4 |
//!
//! Readers issue only `Relaxed` loads and `Acquire` fences, so they work
//! over a read-only mapping.

use std::sync::Arc;

use crate::atomic_view::{HeapWords, WORD_BYTES};
use crate::diag::Store;
use crate::diag_ring::{
    Appended, Bounds, FIELDS, RingReader, RingWriter, STRIDE_WORDS, Scan, ring_words, scan_at_most,
};
use crate::error::SysError;
use crate::frame::Lane;
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
/// Header word of the highest mirror sequence assigned so far (T7).
const HEADER_SEQUENCE: usize = 6;
/// Header word of the count of network journals refused
/// (`trace-network.md` §5).
const HEADER_NETWORK_REFUSED: usize = 7;
/// Entry word of the drop ranges.
const RANGES: usize = 20;
/// Entry word of the mirror sequence.
const ENTRY_SEQUENCE: usize = 68;
/// Entry word of the observed lane.
const ENTRY_LANE: usize = 69;
/// Entry words of a network journal's facts: the sender's `driver_id`
/// (two words), start, boundary, first gap, and their flags.
const ENTRY_NET_DRIVER: usize = 70;
const ENTRY_NET_START: usize = 72;
const ENTRY_NET_BOUNDARY: usize = 73;
const ENTRY_NET_GAP: usize = 74;
const ENTRY_NET_FLAGS: usize = 75;
/// The first reserved entry word.
const ENTRY_RESERVED: usize = 76;
/// Log entry word of the mirror sequence.
const LOG_SEQUENCE: usize = 6;
/// Log entry word of the publication's lane.
const LOG_LANE: usize = 31;
/// Log entry word of the noted pairs.
const PAIRS: usize = 7;
/// Words of one drop range in an entry.
const RANGE_FIELDS: usize = 6;
/// Attempts a reader makes on an entry before reporting it busy.
const READ_ATTEMPTS: usize = 8;
/// Entry flags.
const HAS_JOIN: u64 = 1;
const HAS_BOUNDARY: u64 = 2;
const HAS_LAST: u64 = 4;
const HAS_WATERMARK: u64 = 8;
/// Network fact flags (entry word 75).
const NET_START: u64 = 1;
const NET_BOUNDARY: u64 = 2;
const NET_GAP: u64 = 4;

// The ranges fit an entry, and the pairs a log entry.
const _: () = assert!(RANGES + MIRROR_RANGES * RANGE_FIELDS <= ENTRY_WORDS);
const _: () = assert!(PAIRS + MAX_RECYCLE_PAIRS * 2 <= LOG_ENTRY_WORDS);
const _: () = assert!(ENTRY_SEQUENCE >= RANGES + MIRROR_RANGES * RANGE_FIELDS);
const _: () = assert!(ENTRY_SEQUENCE < ENTRY_WORDS && LOG_SEQUENCE < PAIRS);
const _: () = assert!(ENTRY_LANE < ENTRY_NET_DRIVER && ENTRY_RESERVED < ENTRY_WORDS);
const _: () = assert!(HEADER_NETWORK_REFUSED < STRIDE_WORDS);

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
    /// A network sender journal (`trace-network.md`, NT-3): the driver's
    /// sender agent records its `SenderPickup` observations of one lane of
    /// a publication incarnation.
    NetworkSender,
    /// A network receiver journal: the driver's receiver agent records its
    /// `ReceiverCommit` observations of one lane of an image.
    NetworkReceiver,
}

impl JournalKind {
    const fn code(self) -> u64 {
        match self {
            Self::Subscriber => 1,
            Self::Publisher => 2,
            Self::NetworkSender => 3,
            Self::NetworkReceiver => 4,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Subscriber),
            2 => Some(Self::Publisher),
            3 => Some(Self::NetworkSender),
            4 => Some(Self::NetworkReceiver),
            _ => None,
        }
    }

    /// Whether the driver writes the journal itself (kinds 3 and 4).
    #[must_use]
    pub const fn is_network(self) -> bool {
        matches!(self, Self::NetworkSender | Self::NetworkReceiver)
    }
}

/// The membership facts of a network journal (`trace-network.md` §5,
/// NT-4), in entry words 70 to 75.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkFacts {
    /// The sender's `driver_id`, low and high, in the order of the trace
    /// record's words 1 and 2: this driver's for a sender journal.
    pub sender_driver: [u64; 2],
    /// Sender: the pickup start; receiver: the image join.
    pub start: Option<u64>,
    /// Sender: the pickup boundary; receiver: the commit boundary.
    pub boundary: Option<u64>,
    /// Receiver only: the start of the image's first sealed gap.
    pub first_gap: Option<u64>,
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
    /// The lane of the observed registration: the publication is the
    /// aggregate `stream` on this lane, and journals pair within a lane.
    pub lane: Lane,
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
    /// The mirror sequence (`trace-tool.md`, T7): the driver numbers the
    /// journals it creates 1, 2, 3 and so on, with no gap and from its own
    /// counter, unlike the journal number, which shares the trace number
    /// space. A tool detects a journal it never saw from a gap in it. 0
    /// until set.
    pub sequence: u64,
    /// The facts of a network journal: present exactly for kinds 3 and 4.
    pub network: Option<NetworkFacts>,
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
            lane: Lane::ZERO,
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
            sequence: 0,
            network: None,
        }
    }

    /// Whether the entry keeps the rules of its kind, which both the
    /// writer and the reader check: a client journal has no network facts;
    /// a network journal has them, no client, no join or boundary in words
    /// 4 and 5, and a first gap only on the receiver side.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        match (self.kind.is_network(), self.network) {
            (false, None) => true,
            (true, Some(facts)) => {
                self.client == 0
                    && self.join.is_none()
                    && self.boundary.is_none()
                    && (self.kind == JournalKind::NetworkReceiver || facts.first_gap.is_none())
            }
            _ => false,
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
        if let Some(word) = words.get_mut(ENTRY_SEQUENCE) {
            *word = self.sequence;
        }
        if let Some(word) = words.get_mut(ENTRY_LANE) {
            *word = u64::from(self.lane.get());
        }
        if let Some(facts) = self.network {
            let flags = flag(facts.start.is_some(), NET_START)
                | flag(facts.boundary.is_some(), NET_BOUNDARY)
                | flag(facts.first_gap.is_some(), NET_GAP);
            let values = [
                facts.sender_driver[0],
                facts.sender_driver[1],
                facts.start.unwrap_or(0),
                facts.boundary.unwrap_or(0),
                facts.first_gap.unwrap_or(0),
                flags,
            ];
            for (word, value) in words
                .get_mut(ENTRY_NET_DRIVER..ENTRY_RESERVED)
                .unwrap_or(&mut [])
                .iter_mut()
                .zip(values)
            {
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
        let lane = lane_from(word(ENTRY_LANE))?;
        let flags = (packed >> 8) & 0xFF;
        let range_count = usize::try_from((packed >> 16) & 0xFF)
            .ok()
            .filter(|count| *count <= MIRROR_RANGES)?;
        let when = |bit: u64, value: u64| (flags & bit != 0).then_some(value);
        // Words no driver writes: the reserved words, and network facts
        // with an unknown flag.
        let reserved = words.get(ENTRY_RESERVED..).unwrap_or(&[]);
        let net_flags = word(ENTRY_NET_FLAGS);
        if reserved.iter().any(|word| *word != 0)
            || net_flags & !(NET_START | NET_BOUNDARY | NET_GAP) != 0
        {
            return None;
        }
        let net_words = words.get(ENTRY_NET_DRIVER..ENTRY_RESERVED).unwrap_or(&[]);
        let network = if kind.is_network() {
            let net = |bit: u64, index: usize| (net_flags & bit != 0).then_some(word(index));
            Some(NetworkFacts {
                sender_driver: [word(ENTRY_NET_DRIVER), word(ENTRY_NET_DRIVER + 1)],
                start: net(NET_START, ENTRY_NET_START),
                boundary: net(NET_BOUNDARY, ENTRY_NET_BOUNDARY),
                first_gap: net(NET_GAP, ENTRY_NET_GAP),
            })
        } else if net_words.iter().any(|word| *word != 0) {
            return None;
        } else {
            None
        };
        // A network entry keeps words 4 and 5 zero with their flags clear.
        if kind.is_network() && (word(4) != 0 || word(5) != 0) {
            return None;
        }
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
            lane,
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
            sequence: word(ENTRY_SEQUENCE),
            network,
        })
        .filter(Self::is_valid)
    }
}

/// The lane of a lane word; `None` for a value no driver writes.
fn lane_from(word: u64) -> Option<Lane> {
    u8::try_from(word)
        .ok()
        .and_then(|lane| Lane::try_new(lane).ok())
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
    /// Its publication's lane.
    pub lane: Lane,
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
    /// The recycled journal's mirror sequence ([`JournalEntry::sequence`]).
    pub sequence: u64,
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
            self.sequence,
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
        if let Some(word) = words.get_mut(LOG_LANE) {
            *word = u64::from(self.lane.get());
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
        let lane = lane_from(word(LOG_LANE))?;
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
            lane,
            incarnation: word(3),
            state,
            boundary: (flags & HAS_BOUNDARY != 0).then_some(word(5)),
            pairs,
            pair_count,
            sequence: word(LOG_SEQUENCE),
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
    /// Its length word passed [`MAX_MIRROR_PAYLOAD`]: `payload` is cut to
    /// it, so the record is malformed, not whole.
    pub truncated: bool,
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

    /// Publishes `sequence` as the highest mirror sequence assigned so far
    /// (T7), with Release. The driver calls it before it writes the table
    /// entry of the journal that sequence numbers, so a reader that loads
    /// it (Acquire) before reading the table and the log never misses a
    /// journal below it: one it does not find there was recycled unseen.
    pub fn assign_sequence(&mut self, sequence: u64) {
        if let Some(word) = self.store.words().get(HEADER_SEQUENCE) {
            word.store(sequence, Ordering::Release);
        }
    }

    /// Counts one refused network journal in header word 7, with Release
    /// (`trace-network.md` §4): a tool that sees it rise puts its held
    /// messages that are not final out of scope. The driver is the only
    /// writer. `false`, and nothing written, if the count would overflow.
    pub fn refuse_network_journal(&mut self) -> bool {
        let Some(word) = self.store.words().get(HEADER_NETWORK_REFUSED) else {
            return false;
        };
        let Some(next) = word.load(Ordering::Relaxed).checked_add(1) else {
            return false;
        };
        word.store(next, Ordering::Release);
        true
    }

    /// Writes table entry `index` under its seqlock: `entry`, or a free
    /// entry for `None`. `false` for an index out of range, or for an
    /// entry that breaks the rules of its kind
    /// ([`JournalEntry::is_valid`]), which writes nothing.
    pub fn write_entry(&mut self, index: usize, entry: Option<&JournalEntry>) -> bool {
        if entry.is_some_and(|entry| !entry.is_valid()) {
            return false;
        }
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

    /// Test hook: holds table entry `index` mid-write (its seqlock odd)
    /// when `held`, so every read of it is busy; `false` releases it. A
    /// dependent crate's test of a busy entry.
    #[cfg(feature = "test-hooks")]
    pub fn hold_entry(&mut self, index: usize, held: bool) -> bool {
        let Some(version) = slot_start(self.geometry.table, index, self.entries, ENTRY_WORDS)
            .and_then(|start| self.store.words().get(start))
        else {
            return false;
        };
        let now = version.load(Ordering::Relaxed);
        let odd = now % 2 == 1;
        if odd != held {
            version.store(now.wrapping_add(1), Ordering::Release);
        }
        true
    }

    /// Test hook: appends a record whose length word is `length` whatever
    /// `payload` holds, as a broken writer would; a dependent crate's test
    /// of a malformed record.
    #[cfg(feature = "test-hooks")]
    pub fn append_with_length(
        &mut self,
        journal: u64,
        sequence: u64,
        payload: &[u64],
        length: u64,
    ) -> Option<Appended> {
        let mut fields = [0u64; MIRROR_RECORD_WORDS - FIELDS];
        let (head, tail) = fields.split_at_mut(3);
        head.copy_from_slice(&[journal, sequence, length]);
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

/// Bytes of a trace mirror region's structure for `entries` table entries,
/// a recycle log of `log` entries and `capacity` records (R-CORE-34): the
/// size it is created with, after the region header.
#[cfg(target_os = "linux")]
#[must_use]
pub fn structure_length(entries: usize, log: usize, capacity: usize) -> Option<usize> {
    geometry(entries, log, capacity)?
        .total
        .checked_mul(WORD_BYTES)
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
    let mapped = crate::ipc::Region::create_driver_only(crate::ipc::RegionRecord {
        instance,
        region,
        kind: crate::ipc::RegionKind::TraceMirror,
        generation: 0,
        layout: MIRROR_LAYOUT_VERSION,
        structure_length: structure_length(entries, log, capacity).ok_or(invalid)?,
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
        if structure_length(entries, log, capacity) != Some(record.structure_length) {
            return Err(invalid);
        }
        let geometry = geometry(entries, log, capacity).ok_or(invalid)?;
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

    /// The highest mirror sequence the driver assigned so far (T7), 0
    /// before the first journal, loaded with Acquire. A tool reads it
    /// before the table and the log: every sequence at or below it whose
    /// journal is in neither was created and recycled unseen. Read after
    /// the table instead, a journal created between the two reads would
    /// look missed, which is only conservative.
    #[must_use]
    pub fn assigned_sequence(&self) -> u64 {
        let value = self.store.load(HEADER_SEQUENCE).unwrap_or(0);
        fence(Ordering::Acquire);
        value
    }

    /// The count of network journals the driver refused (header word 7,
    /// `trace-network.md` §5), loaded with Acquire.
    #[must_use]
    pub fn network_journals_refused(&self) -> u64 {
        let value = self.store.load(HEADER_NETWORK_REFUSED).unwrap_or(0);
        fence(Ordering::Acquire);
        value
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
    /// payload cut to it and marked `truncated`.
    pub fn scan(&self, cursor: &mut u64, deliver: impl FnMut(MirrorRecord<'_>)) -> Scan {
        self.scan_at_most(cursor, u64::MAX, deliver)
    }

    /// [`TraceMirrorReader::scan`], delivering at most `max` records (see
    /// [`crate::diag_ring::scan_at_most`]).
    pub fn scan_at_most(
        &self,
        cursor: &mut u64,
        max: u64,
        mut deliver: impl FnMut(MirrorRecord<'_>),
    ) -> Scan {
        let Some(reader) = self.ring_reader() else {
            return Scan {
                overwritten: 0,
                delivered: 0,
                stopped: Some(crate::diag_ring::ScanStop::Busy),
            };
        };
        let mut buffer = [0u64; MIRROR_RECORD_WORDS - FIELDS];
        scan_at_most(&reader, cursor, &mut buffer, max, |seq, fields| {
            let field = |index: usize| fields.get(index).copied().unwrap_or(0);
            let written = usize::try_from(field(2)).unwrap_or(usize::MAX);
            let length = written.min(MAX_MIRROR_PAYLOAD);
            deliver(MirrorRecord {
                seq,
                journal: field(0),
                sequence: field(1),
                payload: fields.get(3..3 + length).unwrap_or(&[]),
                truncated: written > MAX_MIRROR_PAYLOAD,
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
        entry.lane = Lane::try_new(2).unwrap();
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
        entry.sequence = 0xABC;
        entry
    }

    fn recycled(journal: u64, pairs: usize) -> RecycledJournal {
        let mut log = RecycledJournal {
            journal,
            stream: 3,
            lane: Lane::try_new(3).unwrap(),
            incarnation: 1,
            state: JournalState::Closed,
            boundary: Some(4096),
            pairs: [NotedPublisher::default(); MAX_RECYCLE_PAIRS],
            pair_count: pairs,
            sequence: 0x5EC,
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
        assert_eq!(read.lane.get(), 2);
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

    /// The mirror sequence (T7) sits in entry word 68 and log entry word 6,
    /// and the lane in entry word 69 and log entry word 31; the noted pairs
    /// fill words 7 to 30, twelve of them, and entry words 70 to 79 stay
    /// zero for a client journal.
    #[test]
    fn the_mirror_sequence_has_its_own_words() {
        assert_eq!(MAX_RECYCLE_PAIRS, 12);
        let mut mirror = trace_mirror(1, 1, 4).unwrap();
        assert!(mirror.write_entry(0, Some(&entry(5))));
        let full = recycled(9, MAX_RECYCLE_PAIRS);
        assert!(mirror.write_log(0, Some(&full)));
        let words = mirror.store.words();
        let table = mirror.geometry.table;
        let load = |index: usize| words[index].load(Ordering::Relaxed);
        assert_eq!(load(table + 68), 0xABC);
        assert_eq!(load(table + 69), 2);
        assert!((70..ENTRY_WORDS).all(|word| load(table + word) == 0));
        let log = STRIDE_WORDS;
        assert_eq!(load(log + 6), 0x5EC);
        assert_eq!((load(log + 7), load(log + 8)), (100, 0));
        assert_eq!((load(log + 29), load(log + 30)), (111, 110));
        assert_eq!(load(log + 31), 3);
        let reader = mirror.reader();
        let EntryRead::Entry(read) = reader.entry(0) else {
            panic!("entry");
        };
        assert_eq!(read.sequence, 0xABC);
        let LogRead::Entry(read) = reader.log_entry(0) else {
            panic!("log entry");
        };
        assert_eq!(read.sequence, 0x5EC);
        // The high-water mark sits in header word 6, apart from the rest.
        assert_eq!(reader.assigned_sequence(), 0);
        mirror.assign_sequence(7);
        assert_eq!(reader.assigned_sequence(), 7);
        let words = mirror.store.words();
        assert_eq!(words[6].load(Ordering::Relaxed), 7);
        assert_eq!(words[5].load(Ordering::Relaxed), LOG_ENTRY_WORDS as u64);
    }

    fn network(journal: u64, kind: JournalKind) -> JournalEntry {
        let mut entry = JournalEntry::open(journal, 0, kind, 22, 4096);
        entry.registration = 12;
        entry.stream = 3;
        entry.lane = Lane::try_new(1).unwrap();
        entry.incarnation = 2;
        entry.time_namespace = TimeNamespace::Same;
        entry.sequence = 9;
        entry.network = Some(NetworkFacts {
            sender_driver: [u64::MAX, 0x1D],
            start: Some(0),
            boundary: None,
            first_gap: None,
        });
        entry
    }

    /// Network journals (kinds 3 and 4) keep their facts in words 70 to
    /// 75 and leave 76 to 79 zero; a start at 0 is told apart from none
    /// by its flag (`trace-network.md` §5).
    #[test]
    fn network_entries_round_trip_with_their_facts() {
        let mut mirror = trace_mirror(2, 1, 4).unwrap();
        let reader = mirror.reader();
        let sender = network(5, JournalKind::NetworkSender);
        assert!(mirror.write_entry(0, Some(&sender)));
        assert_eq!(reader.entry(0), EntryRead::Entry(sender));
        let mut receiver = network(6, JournalKind::NetworkReceiver);
        receiver.network = Some(NetworkFacts {
            sender_driver: [4, 5],
            start: Some(64),
            boundary: Some(4096),
            first_gap: Some(1024),
        });
        receiver.state = JournalState::Closed;
        assert!(mirror.write_entry(1, Some(&receiver)));
        assert_eq!(reader.entry(1), EntryRead::Entry(receiver));
        let words = mirror.store.words();
        let table = mirror.geometry.table;
        let load = |index: usize| words[index].load(Ordering::Relaxed);
        assert_eq!(load(table + 16), 3);
        assert_eq!(
            (70..76).map(|word| load(table + word)).collect::<Vec<_>>(),
            [u64::MAX, 0x1D, 0, 0, 0, 1]
        );
        let second = table + ENTRY_WORDS;
        assert_eq!(load(second + 16), 4);
        assert_eq!(
            (70..76).map(|word| load(second + word)).collect::<Vec<_>>(),
            [4, 5, 64, 4096, 1024, 7]
        );
        for start in [table, second] {
            // No client, no join or boundary in words 4 and 5.
            assert_eq!(
                (load(start + 2), load(start + 4), load(start + 5)),
                (0, 0, 0)
            );
            assert!((76..ENTRY_WORDS).all(|word| load(start + word) == 0));
        }
    }

    /// An entry that breaks the rules of its kind is refused by the writer
    /// and read as free by the reader.
    #[test]
    fn entries_that_break_their_kind_are_refused_on_both_sides() {
        let mut mirror = trace_mirror(1, 1, 4).unwrap();
        let reader = mirror.reader();
        let mut facts = entry(1);
        facts.network = network(1, JournalKind::NetworkSender).network;
        let mut bare = network(1, JournalKind::NetworkSender);
        bare.network = None;
        let mut client = network(1, JournalKind::NetworkSender);
        client.client = 7;
        let mut join = network(1, JournalKind::NetworkReceiver);
        join.join = Some(0);
        let mut boundary = network(1, JournalKind::NetworkReceiver);
        boundary.boundary = Some(8);
        let mut gap = network(1, JournalKind::NetworkSender);
        gap.network = Some(NetworkFacts {
            first_gap: Some(0),
            ..gap.network.unwrap()
        });
        for wrong in [facts, bare, client, join, boundary, gap] {
            assert!(!wrong.is_valid(), "{wrong:?}");
            assert!(!mirror.write_entry(0, Some(&wrong)), "{wrong:?}");
            assert_eq!(reader.entry(0), EntryRead::Free);
        }
        let table = mirror.geometry.table;
        let poke = |mirror: &mut TraceMirror, written: &JournalEntry, word: usize, value: u64| {
            assert!(mirror.write_entry(0, Some(written)));
            mirror.store.words()[table + word].store(value, Ordering::Relaxed);
            mirror.reader().entry(0)
        };
        // A client journal with network words, and any reserved word.
        for word in [70, 71, 72, 75, 76, 79] {
            assert_eq!(
                poke(&mut mirror, &entry(1), word, 1),
                EntryRead::Free,
                "{word}"
            );
        }
        let sender = network(1, JournalKind::NetworkSender);
        // A network journal with a client, words 4 or 5, a join or
        // boundary flag, an unknown network flag, or a reserved word.
        for (word, value) in [
            (2, 7),
            (4, 1),
            (5, 1),
            (3, 1 | HAS_JOIN << 8),
            (3, 1 | HAS_BOUNDARY << 8),
            (75, 8),
            (77, 1),
        ] {
            assert_eq!(
                poke(&mut mirror, &sender, word, value),
                EntryRead::Free,
                "{word}"
            );
        }
        // A first gap on the sender side.
        assert_eq!(poke(&mut mirror, &sender, 75, NET_GAP), EntryRead::Free);
    }

    /// Header word 7 counts refused network journals; the count never
    /// wraps.
    #[test]
    fn refused_network_journals_are_counted_in_header_word_7() {
        let mut mirror = trace_mirror(1, 1, 4).unwrap();
        let reader = mirror.reader();
        assert_eq!(reader.network_journals_refused(), 0);
        for _ in 0..3 {
            assert!(mirror.refuse_network_journal());
        }
        assert_eq!(reader.network_journals_refused(), 3);
        let words = mirror.store.words();
        assert_eq!(words[HEADER_NETWORK_REFUSED].load(Ordering::Relaxed), 3);
        assert_eq!(words[HEADER_SEQUENCE].load(Ordering::Relaxed), 0);
        words[HEADER_NETWORK_REFUSED].store(u64::MAX, Ordering::Relaxed);
        assert!(!mirror.refuse_network_journal());
        assert_eq!(reader.network_journals_refused(), u64::MAX);
    }

    /// Words no driver writes (an unknown kind or time namespace code, a
    /// lane of 4 or more) read as free, never as a value.
    #[test]
    fn unknown_codes_read_free() {
        let mut mirror = trace_mirror(1, 1, 4).unwrap();
        let table = mirror.geometry.table;
        for (word, value) in [(16, 5), (16, 0), (18, 3), (69, 4), (69, 1 << 8)] {
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
        // A lane of 4 or more.
        words[start + LOG_LANE].store(4, Ordering::Relaxed);
        assert_eq!(reader.log_entry(1), LogRead::Free);
        words[start + LOG_LANE].store(3, Ordering::Relaxed);
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
