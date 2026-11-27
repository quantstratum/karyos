// SPDX-License-Identifier: Apache-2.0

//! `karyosd`'s trace recording (ADR-0117, point 1): with
//! `--archive-trace-record <stream_id>:<session_id>`, the daemon adds that
//! stream, publishes its driver's trace mirror on it as the messages of
//! [`karyos_trace::stream`], and records it at boot through the `--record`
//! path in `required` mode, like any boot recording.
//!
//! The publisher reads the mirror each duty cycle: the ring's records
//! first, then the journal table, so the facts in force for a record are
//! read after it. It publishes the self message first, a facts message for
//! each journal the first time it is seen and at each change of its kind,
//! namespace or provenance (with the journal's next facts generation), a
//! record message for each record with the generation in force, and a
//! loss message for what the ring overwrote before it was read. It blocks
//! rather than drop: a message the stream does not accept stays queued,
//! the mirror is not read again until the queue is empty, and what the
//! ring overwrites meanwhile is a loss message. A full ring is so a
//! recorded loss, never a silent one.
//!
//! `--trace-network` sets the driver's network trace hooks to
//! [`karyos_trace::NetworkTraceAgent`]s, so the network journals (kinds 3
//! and 4) are mirrored, and recorded, too.

use std::collections::{BTreeMap, VecDeque};

use karyos_client::{ClientPublication, OfferOutcome};
use karyos_sys::term_bytes::SharedTerms;
use karyos_sys::trace_mirror::{EntryRead, TraceMirrorReader};
use karyos_trace::RECORD_WORDS;
use karyos_trace::stream::{
    DriverSelf, JournalFacts, MAX_MESSAGE_BYTES, StreamLoss, StreamMessage, StreamRecord,
    TimeRequirement,
};

/// Ring records the publisher reads in one cycle at most.
pub const READ_BUDGET: u64 = 1024;

/// What the stream refuses to take: the publisher keeps it and tries again.
pub trait TraceSink {
    /// Offers one message; true once it is accepted.
    fn offer(&mut self, message: &[u8]) -> bool;
}

impl TraceSink for ClientPublication<SharedTerms> {
    fn offer(&mut self, message: &[u8]) -> bool {
        matches!(
            ClientPublication::offer(self, message),
            Ok(OfferOutcome::Accepted { .. })
        )
    }
}

/// What a [`MirrorSource`] scan delivers each record to: its ring
/// sequence, journal, journal sequence and payload.
pub type Deliver<'a> = dyn FnMut(u64, u64, u64, Option<&[u64; RECORD_WORDS]>) + 'a;

/// A journal's table entry, as the publisher reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalRead {
    /// The journal number.
    pub journal: u64,
    /// Its facts: kind, time namespace word, provenance word.
    pub facts: [u64; 3],
    /// Records the driver mirrored into the ring.
    pub mirrored: u64,
    /// The ring sequence of its last mirrored record, if any.
    pub last_record: Option<u64>,
    /// Its attempted horizon: every journal sequence below it was
    /// attempted.
    pub attempted: u64,
}

/// Where the publisher reads the trace mirror.
pub trait MirrorSource {
    /// Scans the ring from `cursor`, at most `max` records: each record's
    /// journal, sequence and payload (`None` when it is not one whole
    /// trace record); returns the ring sequences proven overwritten
    /// before the cursor reached them.
    fn scan(&mut self, cursor: &mut u64, max: u64, deliver: &mut Deliver<'_>) -> u64;

    /// Each journal of the table. An entry being written on every attempt
    /// is skipped, and read again at the next cycle.
    fn journals(&mut self, each: &mut dyn FnMut(JournalRead));

    /// The ring sequence after the newest record, if readable.
    fn end(&mut self) -> Option<u64>;
}

impl MirrorSource for TraceMirrorReader {
    fn scan(&mut self, cursor: &mut u64, max: u64, deliver: &mut Deliver<'_>) -> u64 {
        self.scan_at_most(cursor, max, |record| {
            let words = if record.truncated {
                None
            } else {
                <&[u64; RECORD_WORDS]>::try_from(record.payload).ok()
            };
            deliver(record.seq, record.journal, record.sequence, words);
        })
        .overwritten
    }

    fn end(&mut self) -> Option<u64> {
        self.bounds().map(|bounds| bounds.next)
    }

    fn journals(&mut self, each: &mut dyn FnMut(JournalRead)) {
        for index in 0..self.entries() {
            if let EntryRead::Entry(entry) = self.entry(index)
                && entry.journal != 0
            {
                each(JournalRead {
                    journal: entry.journal,
                    facts: [
                        entry.kind.code(),
                        entry.time_namespace.code(),
                        entry.provenance,
                    ],
                    mirrored: entry.mirrored,
                    last_record: entry.last_record,
                    attempted: entry.attempted,
                });
            }
        }
    }
}

/// One journal as the publisher knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Known {
    generation: u64,
    facts: [u64; 3],
    /// Records read of it.
    read: u64,
    /// Records the driver mirrored of it, as last read in the table.
    mirrored: u64,
    /// The ring sequence of the last record of it read or reported lost.
    accounted: Option<u64>,
}

/// What the publisher counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublisherCounts {
    /// Messages accepted by the stream.
    pub published: u64,
    /// Loss messages queued.
    pub losses: u64,
}

/// The trace mirror's publisher.
#[derive(Debug)]
pub struct TracePublisher<S, M> {
    sink: S,
    mirror: M,
    queue: VecDeque<StreamMessage>,
    cursor: u64,
    journals: BTreeMap<u64, Known>,
    /// Each journal's last sequence read, for its gaps.
    last: BTreeMap<u64, u64>,
    budget: u64,
    counts: PublisherCounts,
    /// Ring records overwritten before they were read, in total, and the
    /// ring sequence ranges not yet attributed to a journal.
    overwritten: u64,
    unattributed: Vec<(u64, u64)>,
    /// The overwritten ranges already reported against journal 0.
    reported: Vec<(u64, u64)>,
    /// Overwritten records already reported against journal 0.
    unknown: u64,
}

impl<S: TraceSink, M: MirrorSource> TracePublisher<S, M> {
    /// A publisher of `mirror` on `sink`, its self message `own` queued
    /// first.
    #[must_use]
    pub fn new(sink: S, mirror: M, own: DriverSelf) -> Self {
        Self::with_requirements(sink, mirror, own, &[])
    }

    /// [`TracePublisher::new`], its self message followed by the
    /// operator's time `requirements`, one per clock domain, which the
    /// recording so carries.
    #[must_use]
    pub fn with_requirements(
        sink: S,
        mirror: M,
        own: DriverSelf,
        requirements: &[TimeRequirement],
    ) -> Self {
        let mut queue = VecDeque::new();
        queue.push_back(StreamMessage::DriverSelf(own));
        queue.extend(requirements.iter().copied().map(StreamMessage::Requirement));
        Self {
            sink,
            mirror,
            queue,
            cursor: 0,
            journals: BTreeMap::new(),
            last: BTreeMap::new(),
            budget: READ_BUDGET,
            counts: PublisherCounts::default(),
            overwritten: 0,
            unattributed: Vec::new(),
            reported: Vec::new(),
            unknown: 0,
        }
    }

    /// The publisher reading at most `budget` ring records a cycle, at
    /// least 1.
    #[must_use]
    pub fn with_budget(mut self, budget: u64) -> Self {
        self.budget = budget.max(1);
        self
    }

    /// What it counted.
    #[must_use]
    pub fn counts(&self) -> PublisherCounts {
        self.counts
    }

    /// Messages read and not yet accepted by the stream.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// The sink.
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// One cycle: offers what is queued; once nothing is, reads the mirror
    /// and offers that. Returns whether a message was accepted.
    pub fn publish(&mut self) -> bool {
        let mut worked = self.flush();
        if self.queue.is_empty() {
            self.read();
            worked |= self.flush();
        }
        worked
    }

    /// Offers the queue in order, stopping at the first message the stream
    /// does not accept.
    fn flush(&mut self) -> bool {
        let mut worked = false;
        let mut out = [0u8; MAX_MESSAGE_BYTES];
        while let Some(message) = self.queue.front() {
            let accepted = match message.encode(&mut out) {
                Ok(length) => self.sink.offer(out.get(..length).unwrap_or_default()),
                // A message this codec refuses is never built: a record
                // whose journal is 0 does not exist in the mirror.
                Err(error) => {
                    tracing::error!(%error, "trace stream message not encoded");
                    true
                }
            };
            if !accepted {
                break;
            }
            let _ = self.queue.pop_front();
            self.counts.published = self.counts.published.wrapping_add(1);
            worked = true;
        }
        worked
    }

    /// Reads the ring, then the table, and queues their messages.
    fn read(&mut self) {
        let before = self.cursor;
        let mut records: Vec<(u64, u64, u64, Option<[u64; RECORD_WORDS]>)> = Vec::new();
        let overwritten = self.mirror.scan(
            &mut self.cursor,
            self.budget,
            &mut |ring, journal, sequence, words| {
                records.push((ring, journal, sequence, words.copied()));
            },
        );
        if overwritten > 0 {
            self.overwritten = self.overwritten.saturating_add(overwritten);
            let range = (before, before.saturating_add(overwritten - 1));
            // Adjacent overwrites merge; disjoint ones stay apart, so a
            // range never covers records read between them.
            match self.unattributed.last_mut() {
                Some(last) if last.1.checked_add(1) == Some(range.0) => last.1 = range.1,
                _ => self.unattributed.push(range),
            }
        }
        let mut table = Vec::new();
        self.mirror.journals(&mut |read| table.push(read));
        // The generation in force when the records were scanned: a facts
        // change read in the table now applies after them, so its message
        // follows them (the facts in force for a record are read after it).
        let scanned: BTreeMap<u64, u64> = self
            .journals
            .iter()
            .filter(|(_, known)| known.generation > 0)
            .map(|(journal, known)| (*journal, known.generation))
            .collect();
        let mut changes = Vec::new();
        for read in &table {
            let journal = read.journal;
            let facts = read.facts;
            let known = self.journals.entry(journal).or_insert(Known {
                generation: 0,
                facts,
                read: 0,
                mirrored: 0,
                accounted: None,
            });
            known.mirrored = known.mirrored.max(read.mirrored);
            let generation = match known.generation {
                0 => 1,
                _ if known.facts == facts => continue,
                generation => generation.saturating_add(1),
            };
            known.generation = generation;
            known.facts = facts;
            let [kind, time_namespace, provenance] = facts;
            let message = StreamMessage::Facts(JournalFacts {
                journal,
                generation,
                kind,
                time_namespace,
                provenance,
            });
            // A journal seen for the first time: its facts were set when it
            // was created, before any of its records; a change follows them.
            if generation == 1 {
                self.queue.push_back(message);
            } else {
                changes.push(message);
            }
        }
        for (ring, journal, sequence, words) in records {
            if let Some(known) = self.journals.get_mut(&journal) {
                known.read = known.read.saturating_add(1);
                known.accounted = Some(ring);
            }
            // A journal's sequences start at 0: one not read before this
            // record was lost, the journal's first ones included.
            let expected = self
                .last
                .get(&journal)
                .map_or(0, |last| last.saturating_add(1));
            if sequence > expected {
                self.loss(journal, expected, sequence - 1);
            }
            let last = self.last.entry(journal).or_insert(sequence);
            *last = (*last).max(sequence);
            let generation = scanned.get(&journal).copied().unwrap_or_else(|| {
                self.journals
                    .get(&journal)
                    .map_or(0, |known| known.generation)
            });
            match words {
                Some(words) if journal != 0 => {
                    self.queue.push_back(StreamMessage::Record(StreamRecord {
                        journal,
                        generation,
                        sequence,
                        words,
                    }));
                }
                // Not one whole trace record: it cannot be carried, so it
                // is lost, and said so.
                _ => self.loss(journal, sequence, sequence),
            }
        }
        self.queue.extend(changes);
        if self.overwritten > 0 {
            self.attribute(&table);
        }
    }

    /// Attributes what the ring overwrote to its journals (ADR-0117,
    /// point 1). A journal whose table entry names a last mirrored record
    /// the cursor has passed, past the last of its records read, lost its
    /// records after that one: a loss of that journal, from the sequence
    /// after its last one read to the last its horizon allows (the
    /// overwritten records carried their sequences; the entry keeps only
    /// the horizon). A gap before a later record is already a loss of its
    /// journal. What the journals known do not account for belonged to
    /// journals whose entries were recycled before the records were read:
    /// nothing names their journal any more, so it is a loss of journal 0,
    /// by ring sequence, one loss per disjoint overwritten range, reported
    /// as soon as the overwrite is read: a busy journal with records the
    /// cursor has not passed never holds it back.
    fn attribute(&mut self, table: &[JournalRead]) {
        let cursor = self.cursor;
        let mut pending = false;
        for read in table {
            let Some(known) = self.journals.get_mut(&read.journal) else {
                continue;
            };
            match read.last_record {
                Some(last) if last >= cursor => pending = true,
                Some(last) if known.accounted.is_none_or(|accounted| accounted < last) => {
                    known.accounted = Some(last);
                    let first = self
                        .last
                        .get(&read.journal)
                        .map_or(0, |last| last.saturating_add(1));
                    // `attempted <= first` (the range `[first, first]`)
                    // arises only when a record really was overwritten:
                    // `accounted < last < cursor` here.
                    let end = read.attempted.saturating_sub(1).max(first);
                    let _ = self.last.insert(read.journal, end);
                    self.loss(read.journal, first, end);
                }
                _ => {}
            }
        }
        // Each known journal's lost records: mirrored, not read, and not
        // still in the ring ahead of the cursor, counted by reading that
        // window without consuming it. The rest of what was overwritten
        // belonged to journals no longer known: exact, whether or not a
        // busy journal has records the cursor has not passed.
        let mut unread: BTreeMap<u64, u64> = BTreeMap::new();
        if let Some(end) = self.mirror.end() {
            let mut at = self.cursor;
            let _ = self.mirror.scan(
                &mut at,
                end.saturating_sub(self.cursor),
                &mut |_, journal, _, _| {
                    let count = unread.entry(journal).or_default();
                    *count = count.saturating_add(1);
                },
            );
        }
        let attributed: u64 = self
            .journals
            .iter()
            .map(|(journal, known)| {
                known
                    .mirrored
                    .saturating_sub(known.read)
                    .saturating_sub(unread.get(journal).copied().unwrap_or(0))
            })
            .sum();
        let unknown = self.overwritten.saturating_sub(attributed);
        if unknown > self.unknown {
            self.unknown = unknown;
            let ranges = match self.unattributed.is_empty() {
                // Proven later, of ranges already given: the last of them.
                true => self.reported.last().copied().into_iter().collect(),
                false => std::mem::take(&mut self.unattributed),
            };
            for (first, last) in ranges {
                self.loss(0, first, last);
                self.reported.push((first, last));
            }
        } else if !pending {
            // Every overwritten record is accounted to a known journal.
            self.unattributed.clear();
        }
    }

    /// The ring sequence after the mirror's newest record, if readable.
    pub fn mirror_end(&mut self) -> Option<u64> {
        self.mirror.end()
    }

    /// The ring sequence the publisher reads next.
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Gives up on the ring records from the cursor up to `end` (a stop
    /// whose deadline passed, ADR-0117): they are a loss of journal 0, by
    /// ring sequence, never silently dropped; offered once more.
    pub fn abandon(&mut self, end: u64) {
        if end > self.cursor {
            self.loss(0, self.cursor, end - 1);
            self.cursor = end;
        }
        let _ = self.flush();
    }

    fn loss(&mut self, journal: u64, first: u64, last: u64) {
        self.counts.losses = self.counts.losses.wrapping_add(1);
        self.queue.push_back(StreamMessage::Loss(StreamLoss {
            journal,
            first,
            last,
        }));
    }
}

#[cfg(test)]
mod tests;
