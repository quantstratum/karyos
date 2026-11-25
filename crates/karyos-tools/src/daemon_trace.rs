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

/// What a [`MirrorSource`] scan delivers each record to: its journal,
/// sequence and payload.
pub type Deliver<'a> = dyn FnMut(u64, u64, Option<&[u64; RECORD_WORDS]>) + 'a;

/// Where the publisher reads the trace mirror.
pub trait MirrorSource {
    /// Scans the ring from `cursor`, at most `max` records: each record's
    /// journal, sequence and payload (`None` when it is not one whole
    /// trace record); returns the ring sequences proven overwritten
    /// before the cursor reached them.
    fn scan(&mut self, cursor: &mut u64, max: u64, deliver: &mut Deliver<'_>) -> u64;

    /// Each journal of the table: its number and facts (kind, time
    /// namespace word, provenance word). An entry being written on every
    /// attempt is skipped, and read again at the next cycle.
    fn journals(&mut self, each: &mut dyn FnMut(u64, [u64; 3]));
}

impl MirrorSource for TraceMirrorReader {
    fn scan(&mut self, cursor: &mut u64, max: u64, deliver: &mut Deliver<'_>) -> u64 {
        self.scan_at_most(cursor, max, |record| {
            let words = if record.truncated {
                None
            } else {
                <&[u64; RECORD_WORDS]>::try_from(record.payload).ok()
            };
            deliver(record.journal, record.sequence, words);
        })
        .overwritten
    }

    fn journals(&mut self, each: &mut dyn FnMut(u64, [u64; 3])) {
        for index in 0..self.entries() {
            if let EntryRead::Entry(entry) = self.entry(index)
                && entry.journal != 0
            {
                each(
                    entry.journal,
                    [
                        entry.kind.code(),
                        entry.time_namespace.code(),
                        entry.provenance,
                    ],
                );
            }
        }
    }
}

/// One journal as the publisher knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Known {
    generation: u64,
    facts: [u64; 3],
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
        let mut records: Vec<(u64, u64, Option<[u64; RECORD_WORDS]>)> = Vec::new();
        let overwritten = self.mirror.scan(
            &mut self.cursor,
            self.budget,
            &mut |journal, sequence, words| {
                records.push((journal, sequence, words.copied()));
            },
        );
        if overwritten > 0 {
            self.loss(0, before, before.saturating_add(overwritten - 1));
        }
        let mut changed = Vec::new();
        self.mirror.journals(&mut |journal, facts| {
            changed.push((journal, facts));
        });
        for (journal, facts) in changed {
            let generation = match self.journals.get(&journal) {
                Some(known) if known.facts == facts => continue,
                Some(known) => known.generation.saturating_add(1),
                None => 1,
            };
            self.journals.insert(journal, Known { generation, facts });
            let [kind, time_namespace, provenance] = facts;
            self.queue.push_back(StreamMessage::Facts(JournalFacts {
                journal,
                generation,
                kind,
                time_namespace,
                provenance,
            }));
        }
        for (journal, sequence, words) in records {
            if let Some(&last) = self.last.get(&journal)
                && sequence > last.saturating_add(1)
            {
                self.loss(journal, last.saturating_add(1), sequence - 1);
            }
            let last = self.last.entry(journal).or_insert(sequence);
            *last = (*last).max(sequence);
            let generation = self
                .journals
                .get(&journal)
                .map_or(0, |known| known.generation);
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
