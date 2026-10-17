// SPDX-License-Identifier: Apache-2.0

//! The tool's reader of a driver's trace mirror (`quantstratum-docs:
//! karyos/design/trace-tool.md`; the mirror is `trace-journal-region.md`'s
//! J1). It lives here, not in `karyos-trace`, because SPEC.md §14 has
//! `karyos-trace` depend on `karyos-protocol` only, while the mirror reader
//! is `karyos-sys`'s; `karyos-trace` keeps the generic
//! [`JournalSource`] (T1) and this module implements it.
//!
//! [`MirrorTool`] follows the mirror across scans. Each [`MirrorTool::scan`]
//! scans the ring from its cursor, then reads the journal table, then the
//! recycle log (the driver writes a log entry before it reuses the table
//! entry it describes), and keeps what it learned:
//!
//! - **Membership from the table (T4).** A journal's kind, publication
//!   `(driver_id, stream registration, incarnation)` and join come from its
//!   entry only. Records only confirm the entry: a record naming another
//!   publication, or a point of the other kind (`Publish` in a subscriber
//!   journal, `SubscriberPoll` in a publisher journal), makes the journal
//!   **malformed**, which is treated like writer lost: it delivers nothing
//!   from that record on, and every trace it could be expected in becomes
//!   final `Incomplete`. It never drops out of an expected set.
//! - **Attach horizon.** For a journal in the table at the first scan, the
//!   first journal sequence that scan delivered of it; when it delivered
//!   none, the entry's attempted count if the journal had mirrored records
//!   (they were overwritten before the attach), 0 otherwise. A journal
//!   first seen later starts at 0: every record it mirrored came after the
//!   attach. Records below the horizon are never delivered; the report
//!   puts the messages they could hold out of scope.
//! - **Gaps and losses.** A journal sequence skipped between two delivered
//!   records is a gap: the journal dropped it, or the ring overwrote it
//!   before a scan read it (mirror loss). Once every mirrored record of a
//!   journal was scanned (its last ring record is below the cursor and the
//!   driver mirrored every stored record), sequences from the next
//!   expected one up to `attempted - 1` were lost at the tail. Sequences in
//!   the journal's own drop ranges, or below its `lost_before` watermark,
//!   are journal loss, attributed to the stream; the rest are mirror loss,
//!   never attributed to it. Both make the traces that could lie there
//!   final `Incomplete`, never `Complete`.
//! - **Terminal close.** An entry closed with a boundary closes its source
//!   with that boundary, once every mirrored record of it was scanned; a
//!   closed subscriber entry without a boundary, a writer lost entry, a
//!   malformed journal and an open entry that left the table unseen are
//!   [`SourceState::Lost`].
//! - **Entries kept.** The tool keeps every entry it has seen, with the
//!   records it read, for its whole life (the design asks only until the
//!   ring no longer retains their records): `--follow` builds the report
//!   again from all of them at each rescan.
//! - **Recycle log (T5).** Every log entry the tool ever read stays in
//!   force for the tool's life: the messages of its publication at
//!   positions at or below its boundary, or every message of it for a
//!   writer lost entry, are out of scope.
//!
//! - **Trace horizon (T6).** A trace can be `Complete` only if the tool
//!   observed its root, a `Publish` record with the `root` flag; every
//!   other trace that would be `Complete` is out of scope.
//! - **Missed journals (T7, ACS 13973).** The driver numbers the journals
//!   it creates with a dense mirror sequence (not the journal number,
//!   which shares the trace number space) and publishes the highest one
//!   assigned in the mirror header before it writes that journal's entry.
//!   Each scan reads that high-water mark first (Acquire), then the table,
//!   then the log. Sequences at or below the mark read at the first scan
//!   are never gaps; after that, every sequence above the previous scan's
//!   mark and at or below this one's that the table and the log both
//!   lack is a missed journal, which puts every held message whose trace
//!   was not final after the previous scan out of scope, for every
//!   publication, for the tool's life. Read in the other order, a journal
//!   created between the two reads would count as missed, which is only
//!   conservative.
//!
//! - **Network journals (`trace-network.md` §5).** A network sender or
//!   receiver entry (kinds 3 and 4) is read as a network source of its
//!   lane, named by its sender's `driver_id`, expected from its start
//!   (word 72) and up to its boundary (word 73) once it closed; a closed one
//!   without a boundary is lost. Gaps are not mirrored, so every frame of a
//!   receiver journal stays expected, and one lost to a gap makes its trace
//!   `Incomplete`, never a false `Complete`.
//! - **Refused network journals.** Header word 7 counts the network
//!   journals the driver refused, read before and again after the table;
//!   a rise since the last scan (any count at the attach) puts every held
//!   message whose trace was not final out of scope, as for a missed
//!   journal. The word does not name the publication, and a refused journal
//!   never exists, so a message published later would not expect it: from
//!   the first refusal on, the tool reports no final `Complete` for its
//!   life, each such trace out of scope and counted (ACS 15805).
//!
//! The tool cannot bound a trace's span in a journal, so the report's
//! attribution uses `D = u64::MAX` (`quantstratum-docs:
//! karyos/design/trace-attribution.md`): any loss in a journal makes every
//! trace it holds `Incomplete`.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use karyos_protocol::journal::{DropRange, JournalError};
use karyos_protocol::trace_hook::NetSide;
use karyos_sys::trace_mirror::{
    EntryRead, JournalEntry, JournalKind, JournalState, LogRead, RecycledJournal, TimeNamespace,
    TraceMirrorReader,
};
use karyos_trace::{
    AttributionConfig, ClockProvenance, Collected, HistogramConfig, JournalClock, JournalSource,
    ObserverId, Point, PublicationKey, RECORD_WORDS, SourceLosses, SourceState, TraceAnswer,
    TraceError, TraceRecord, TraceReport, decode_record,
};

/// Loss intervals each journal's attributor keeps. With `D = u64::MAX` a
/// single loss already makes every trace of the journal `Incomplete`.
const MAX_INTERVALS: usize = 16;

/// The latency histograms of the tool's report: three significant digits,
/// nanoseconds up to 2^40 (about 18 minutes).
pub const HISTOGRAM: HistogramConfig = HistogramConfig {
    digits: 3,
    highest: 1 << 40,
    unit: 1,
};

/// The driver instance as two words, high then low, as records carry it.
#[must_use]
pub fn driver_words(instance: u128) -> [u64; 2] {
    [(instance >> 64) as u64, instance as u64]
}

/// One journal the tool has seen in the table.
#[derive(Debug, Clone)]
struct Tracked {
    /// Its table entry as last read.
    entry: JournalEntry,
    /// The table index it was last read at.
    index: usize,
    /// It was in the table at the last read.
    present: bool,
    /// The first sequence the tool delivers (the attach horizon).
    start: u64,
    /// The next sequence expected.
    next: u64,
    /// The records delivered, in sequence order.
    items: Vec<Collected>,
    /// Sequences `[from, to)` skipped before delivered records.
    gaps: Vec<(u64, u64)>,
    /// A record contradicted the entry.
    malformed: bool,
}

impl Tracked {
    fn new(entry: JournalEntry, index: usize, start: u64) -> Self {
        Self {
            entry,
            index,
            present: true,
            start,
            next: start,
            items: Vec::new(),
            gaps: Vec::new(),
            malformed: false,
        }
    }

    /// The publication the entry names: a network journal names its
    /// sender's driver, the others this driver.
    fn publication(&self, driver: [u64; 2]) -> PublicationKey {
        PublicationKey {
            driver: self
                .entry
                .network
                .map_or(driver, |facts| facts.sender_driver),
            registration: self.entry.stream,
            incarnation: self.entry.incarnation,
        }
    }

    /// Whether `record` contradicts the entry (T4): another publication,
    /// another lane, or a point of the other side.
    fn contradicts(&self, record: &TraceRecord, driver: [u64; 2]) -> bool {
        PublicationKey::from(record.publication) != self.publication(driver)
            || record.lane != self.entry.lane.get()
            || match self.entry.kind {
                JournalKind::Subscriber => record.point == Point::Publish,
                JournalKind::Publisher => record.point == Point::SubscriberPoll,
                JournalKind::NetworkSender => record.point != Point::SenderPickup,
                JournalKind::NetworkReceiver => record.point != Point::ReceiverCommit,
            }
    }

    /// Delivers the ring record of journal sequence `sequence`.
    fn deliver(&mut self, sequence: u64, payload: &[u64], driver: [u64; 2]) {
        if self.malformed || sequence < self.next {
            return;
        }
        let gap = (sequence > self.next).then_some((self.next, sequence));
        let item = match decoded(payload) {
            Ok((record, collected)) => {
                if self.contradicts(&record, driver) {
                    self.malformed = true;
                    return;
                }
                Collected::Record {
                    sequence,
                    gap,
                    record,
                    collected,
                }
            }
            Err(error) => Collected::Corrupt {
                sequence,
                gap,
                error,
            },
        };
        if let Some(gap) = gap {
            self.gaps.push(gap);
        }
        self.next = sequence.checked_add(1).unwrap_or(sequence);
        self.items.push(item);
    }

    /// Whether every record the journal mirrored was scanned or lost: its
    /// last ring record is below `cursor` and the driver mirrored every
    /// record the journal stored.
    fn caught_up(&self, cursor: u64) -> bool {
        self.entry.last_record.is_none_or(|last| last < cursor)
            && self.entry.mirrored >= self.entry.stored
    }

    /// The source's terminal state; `recycled` is the journal's recycle
    /// log entry, if the tool read one.
    fn state(&self, cursor: u64, recycled: Option<&RecycledJournal>) -> SourceState {
        if self.malformed {
            return SourceState::Lost;
        }
        let (state, boundary) = match recycled {
            Some(log) if !self.present => (log.state, log.boundary),
            // Ended and reused between two reads, unseen.
            _ if !self.present && self.entry.state == JournalState::Open => {
                return SourceState::Lost;
            }
            _ => (self.entry.state, self.entry.boundary),
        };
        match state {
            JournalState::Open => SourceState::Open,
            JournalState::WriterLost => SourceState::Lost,
            // Records mirrored after the scan are still to come.
            JournalState::Closed if !self.caught_up(cursor) => SourceState::Open,
            JournalState::Closed => match self.entry.network {
                // A network journal's boundary is in its facts (word 73);
                // without one its membership is undecided: lost.
                Some(facts) => match facts.boundary {
                    None => SourceState::Lost,
                    boundary => SourceState::Closed { boundary },
                },
                None => match (self.entry.kind, boundary) {
                    // J3: no boundary, no decided membership.
                    (JournalKind::Subscriber, None) => SourceState::Lost,
                    (_, boundary) => SourceState::Closed { boundary },
                },
            },
        }
    }

    /// The loss accounting from the entry, with the gaps classified.
    fn losses(&self, cursor: u64) -> SourceLosses {
        let caught_up = self.caught_up(cursor);
        let mut gaps = self.gaps.clone();
        if caught_up && self.entry.attempted > self.next {
            gaps.push((self.next, self.entry.attempted));
        }
        let ranges = self.entry.ranges().to_vec();
        let delivered = self.items.len() as u64;
        SourceLosses {
            attempted: self.entry.attempted,
            // Until every mirrored record was scanned, more are to come.
            stored: if caught_up { delivered } else { delivered + 1 },
            lost_before: self.entry.lost_before,
            mirror_ranges: mirror_ranges(&gaps, &ranges, self.entry.lost_before),
            ranges,
        }
    }
}

/// Decodes a ring payload as a trace record.
fn decoded(payload: &[u64]) -> Result<(TraceRecord, karyos_protocol::journal::Stamp), TraceError> {
    let words: &[u64; RECORD_WORDS] = payload.try_into().map_err(|_| {
        TraceError::Journal(JournalError::PayloadLength {
            length: payload.len(),
            expected: RECORD_WORDS,
        })
    })?;
    decode_record(words)
}

/// The parts of `gaps` (`[from, to)`) outside the journal's own drop
/// ranges and below its watermark: mirror loss, as inclusive ranges.
fn mirror_ranges(
    gaps: &[(u64, u64)],
    ranges: &[DropRange],
    lost_before: Option<u64>,
) -> Vec<(u64, u64)> {
    let mut owned: Vec<(u64, u64)> = ranges
        .iter()
        .map(|range| (range.first, range.last))
        .collect();
    if let Some(watermark) = lost_before.and_then(|watermark| watermark.checked_sub(1)) {
        owned.push((0, watermark));
    }
    owned.sort_unstable();
    let mut out = Vec::new();
    for &(from, to) in gaps {
        let Some(last) = to.checked_sub(1).filter(|last| *last >= from) else {
            continue;
        };
        let mut low = Some(from);
        for &(first, end) in &owned {
            let Some(current) = low else {
                break;
            };
            if end < current || first > last {
                continue;
            }
            if first > current {
                out.push((current, first - 1));
            }
            low = end.checked_add(1).filter(|next| *next <= last);
        }
        if let Some(current) = low {
            out.push((current, last));
        }
    }
    out
}

/// The sequences in inclusive `ranges` (a diagnostic count, saturating).
fn count(ranges: &[(u64, u64)]) -> u64 {
    ranges
        .iter()
        .map(|(first, last)| last.saturating_sub(*first).saturating_add(1))
        .fold(0u64, u64::saturating_add)
}

/// One journal of the mirror as a [`JournalSource`]: its records from the
/// ring scans, its accounting and terminal state from its table entry.
#[derive(Debug)]
pub struct MirrorSource {
    observer: ObserverId,
    start: u64,
    items: std::vec::IntoIter<Collected>,
    losses: SourceLosses,
    state: SourceState,
}

impl JournalSource for MirrorSource {
    fn observer(&self) -> ObserverId {
        self.observer
    }

    fn start(&self) -> u64 {
        self.start
    }

    fn take(&mut self) -> Collected {
        match self.items.next() {
            Some(item) => item,
            None if self.state == SourceState::Open => Collected::Empty,
            None => Collected::Closed,
        }
    }

    fn losses(&mut self) -> SourceLosses {
        self.losses.clone()
    }

    fn state(&self) -> SourceState {
        self.state
    }
}

/// What one [`MirrorTool::scan`] saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanReport {
    /// Ring records delivered.
    pub delivered: u64,
    /// Ring records overwritten before this scan read them (before the
    /// attach, for the first scan).
    pub overwritten: u64,
    /// Journal numbers this scan missed (T7).
    pub missed: u64,
}

/// The tool's view of a trace mirror, followed across scans.
#[derive(Debug)]
pub struct MirrorTool {
    driver: [u64; 2],
    cursor: u64,
    scans: u64,
    journals: BTreeMap<u64, Tracked>,
    recycled: BTreeMap<u64, RecycledJournal>,
    /// Ring records overwritten after the attach before a scan read them.
    overwritten: u64,
    /// Delivered ring records of a journal the tool never saw in the
    /// table: overwritten during the scan, so mirror loss.
    unattributed: u64,
    /// The mirror's high-water mark of assigned sequences as the last scan
    /// read it (T7); `None` before the first scan.
    highest: Option<u64>,
    /// Scans that found missed journals, and the numbers missed.
    missed_events: u64,
    missed_numbers: u64,
    /// Messages a missed journal put out of scope.
    missed_scope: HashSet<(PublicationKey, u8, u64)>,
    /// Messages whose trace had a final answer after the last scan.
    finals: HashSet<(PublicationKey, u8, u64)>,
    /// The mirror's count of refused network journals as the last scan
    /// read it; `None` before the first scan.
    refused: Option<u64>,
    /// Scans that saw that count rise.
    refused_rises: u64,
    /// That count of scans could not rise further.
    refused_rises_overflowed: bool,
}

impl MirrorTool {
    /// A tool of the driver instance `instance` (from `ToolAdmitted`) that
    /// has not scanned yet.
    #[must_use]
    pub fn new(instance: u128) -> Self {
        Self {
            driver: driver_words(instance),
            cursor: 0,
            scans: 0,
            journals: BTreeMap::new(),
            recycled: BTreeMap::new(),
            overwritten: 0,
            unattributed: 0,
            highest: None,
            missed_events: 0,
            missed_numbers: 0,
            missed_scope: HashSet::new(),
            finals: HashSet::new(),
            refused: None,
            refused_rises: 0,
            refused_rises_overflowed: false,
        }
    }

    /// Scans the ring from the cursor, then reads the table and the recycle
    /// log. The first scan is the attach: it sets each journal's horizon.
    pub fn scan(&mut self, reader: &TraceMirrorReader) -> ScanReport {
        let attach = self.scans == 0;
        self.scans += 1;
        // T7: the high-water mark before the table and the log.
        let assigned = reader.assigned_sequence();
        let refused = reader.network_journals_refused();
        let mut delivered: Vec<(u64, u64, Vec<u64>)> = Vec::new();
        let scan = reader.scan(&mut self.cursor, |record| {
            delivered.push((record.journal, record.sequence, record.payload.to_vec()));
        });
        if !attach {
            self.overwritten = self.overwritten.saturating_add(scan.overwritten);
        }
        // The table after the ring, then the log.
        for tracked in self.journals.values_mut() {
            tracked.present = false;
        }
        // Mirror sequences this scan shows in the table or the log (T7).
        let mut shown: BTreeSet<u64> = BTreeSet::new();
        for index in 0..reader.entries() {
            match reader.entry(index) {
                EntryRead::Entry(entry) => {
                    let start = if attach {
                        delivered
                            .iter()
                            .filter(|(journal, _, _)| *journal == entry.journal)
                            .map(|(_, sequence, _)| *sequence)
                            .min()
                            .unwrap_or(if entry.last_record.is_some() {
                                entry.attempted
                            } else {
                                0
                            })
                    } else {
                        0
                    };
                    let tracked = self
                        .journals
                        .entry(entry.journal)
                        .or_insert_with(|| Tracked::new(entry, index, start));
                    tracked.entry = entry;
                    tracked.index = index;
                    tracked.present = true;
                    shown.insert(entry.sequence);
                }
                // Being written: what the tool last read there stands.
                EntryRead::Busy => {
                    for tracked in self.journals.values_mut() {
                        if tracked.index == index && tracked.entry.state == JournalState::Open {
                            tracked.present = true;
                        }
                    }
                }
                EntryRead::Free => {}
            }
        }
        for index in 0..reader.log_entries() {
            if let LogRead::Entry(entry) = reader.log_entry(index) {
                shown.insert(entry.sequence);
                self.recycled.insert(entry.journal, entry);
            }
        }
        let count = delivered.len() as u64;
        for (journal, sequence, payload) in delivered {
            match self.journals.get_mut(&journal) {
                Some(tracked) => tracked.deliver(sequence, &payload, self.driver),
                None => self.unattributed = self.unattributed.saturating_add(1),
            }
        }
        let missed = self.missed_journals(assigned, &shown);
        if missed > 0 {
            self.missed_events = self.missed_events.saturating_add(1);
            self.missed_numbers = self.missed_numbers.saturating_add(missed);
        }
        // Read again after the table and the log: a refusal during the scan
        // counts in this scan, not the next.
        let refused = refused.max(reader.network_journals_refused());
        // Any refusal at the attach, or a rise since the last scan.
        let rose = refused > self.refused.unwrap_or(0);
        self.refused = Some(refused);
        if rose {
            match self.refused_rises.checked_add(1) {
                Some(rises) => self.refused_rises = rises,
                None => self.refused_rises_overflowed = true,
            }
        }
        if missed > 0 || rose {
            // Every held message whose trace was not final after the last
            // scan, with those this scan delivered: the missed or refused
            // journal may have been expected for any of them, of any
            // publication.
            if let Ok(report) = self.report() {
                for held in report.messages() {
                    let key = (held.publication, held.lane, held.position);
                    if !self.finals.contains(&key) {
                        self.missed_scope.insert(key);
                    }
                }
            }
        }
        self.finals = self
            .report()
            .map(|report| {
                report
                    .messages()
                    .into_iter()
                    .filter(|held| matches!(held.answer, TraceAnswer::Final(_)))
                    .map(|held| (held.publication, held.lane, held.position))
                    .collect()
            })
            .unwrap_or_default();
        ScanReport {
            delivered: count,
            overwritten: scan.overwritten,
            missed,
        }
    }

    /// The mirror sequences this scan missed (T7): the driver assigns
    /// them densely and publishes the high-water mark `assigned` before
    /// the entry, so a sequence above the previous scan's mark and at or
    /// below `assigned` that this scan `shown` neither in the table nor in
    /// the log belongs to a journal created, ended and recycled between
    /// two scans. Sequences at or below the first scan's mark are never
    /// gaps: a journal recycled before the attach without a log entry was
    /// covered.
    fn missed_journals(&mut self, assigned: u64, shown: &BTreeSet<u64>) -> u64 {
        let Some(previous) = self.highest else {
            self.highest = Some(assigned);
            return 0;
        };
        if assigned <= previous {
            return 0;
        }
        self.highest = Some(assigned);
        let seen = shown.range(previous + 1..=assigned).count() as u64;
        (assigned - previous).saturating_sub(seen)
    }

    /// Scans that saw the mirror's count of refused network journals rise
    /// (any count at the attach), and that count as last read.
    #[must_use]
    pub fn network_refused(&self) -> (u64, u64) {
        (self.refused_rises, self.refused.unwrap_or(0))
    }

    /// Whether the count of scans that saw a rise stopped rising.
    #[must_use]
    pub fn network_refused_overflowed(&self) -> bool {
        self.refused_rises_overflowed
    }

    /// Scans that found missed journals, and the journal numbers missed
    /// over the tool's life (T7).
    #[must_use]
    pub fn missed(&self) -> (u64, u64) {
        (self.missed_events, self.missed_numbers)
    }

    /// The driver instance as two words.
    #[must_use]
    pub fn driver(&self) -> [u64; 2] {
        self.driver
    }

    /// Ring records overwritten after the attach before a scan read them,
    /// with the delivered records whose journal had already left the
    /// table: the mirror loss of the tool's life.
    #[must_use]
    pub fn overwritten(&self) -> u64 {
        self.overwritten.saturating_add(self.unattributed)
    }

    /// Journal sequences lost to the mirror over every journal (never
    /// attributed to a stream).
    #[must_use]
    pub fn mirror_lost(&self) -> u64 {
        self.journals
            .values()
            .map(|tracked| count(&tracked.losses(self.cursor).mirror_ranges))
            .fold(0u64, u64::saturating_add)
    }

    /// The journals excluded as malformed, by number.
    #[must_use]
    pub fn malformed(&self) -> Vec<u64> {
        self.journals
            .values()
            .filter(|tracked| tracked.malformed)
            .map(|tracked| tracked.entry.journal)
            .collect()
    }

    /// The loss accounting of journal `journal` as its source reports it.
    #[must_use]
    pub fn losses(&self, journal: u64) -> Option<SourceLosses> {
        self.journals
            .get(&journal)
            .map(|tracked| tracked.losses(self.cursor))
    }

    /// The source of journal `journal`, with its kind, publication, join
    /// and clock.
    fn source(&self, tracked: &Tracked) -> MirrorSource {
        MirrorSource {
            observer: ObserverId {
                driver: self.driver,
                journal: tracked.entry.journal,
            },
            start: tracked.start,
            items: tracked.items.clone().into_iter(),
            losses: tracked.losses(self.cursor),
            state: tracked.state(self.cursor, self.recycled.get(&tracked.entry.journal)),
        }
    }

    /// Builds and drains a report over every journal the tool has seen,
    /// with the recycle log's scope.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::Attribution`] when an attributor's tables
    /// cannot be allocated.
    pub fn report(&self) -> Result<TraceReport, TraceError> {
        let max_traces = self
            .journals
            .values()
            .map(|tracked| tracked.items.len())
            .max()
            .unwrap_or(0)
            .max(1);
        let mut report = TraceReport::new(
            AttributionConfig {
                span: u64::MAX,
                max_traces,
                max_intervals: MAX_INTERVALS,
            },
            HISTOGRAM,
        );
        for tracked in self.journals.values() {
            let source = self.source(tracked);
            let clock = JournalClock {
                provenance: ClockProvenance::from_word(tracked.entry.provenance),
                driver_time_namespace: tracked.entry.time_namespace == TimeNamespace::Same,
            };
            let publication = tracked.publication(self.driver);
            match tracked.entry.kind {
                JournalKind::Publisher => {
                    report.add_publisher_source(source, clock, publication)?;
                }
                JournalKind::Subscriber => {
                    // A subscriber entry always has its join; without one it
                    // is taken as expected from the stream's start.
                    let join = tracked.entry.join.unwrap_or(0);
                    report.add_subscriber_source(source, clock, publication, join)?;
                }
                JournalKind::NetworkSender | JournalKind::NetworkReceiver => {
                    let side = if tracked.entry.kind == JournalKind::NetworkSender {
                        NetSide::Sender
                    } else {
                        NetSide::Receiver
                    };
                    let start = tracked.entry.network.and_then(|facts| facts.start);
                    report.add_network_source(
                        source,
                        clock,
                        publication,
                        side,
                        tracked.entry.lane.get(),
                        start,
                    )?;
                }
            }
        }
        for recycled in self.recycled.values() {
            let through = match recycled.state {
                JournalState::Closed => recycled.boundary,
                JournalState::Open | JournalState::WriterLost => None,
            };
            report.out_of_scope(
                PublicationKey {
                    driver: self.driver,
                    registration: recycled.stream,
                    incarnation: recycled.incarnation,
                },
                through,
            );
        }
        for (publication, lane, position) in &self.missed_scope {
            report.out_of_scope_message(*publication, *lane, *position);
        }
        report.require_roots();
        // The mirror's count does not name the refused publication.
        if let Some(refused) = self.refused {
            report.withhold_complete(refused);
        }
        report.drain()?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
