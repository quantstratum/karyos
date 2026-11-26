// SPDX-License-Identifier: Apache-2.0

//! The trace publisher over a fake mirror and stream (ADR-0117, point 1).

use super::*;

/// A stream that accepts while `open`, keeping what it took.
#[derive(Debug, Default)]
struct Stream {
    open: bool,
    taken: Vec<StreamMessage>,
}

impl TraceSink for Stream {
    fn offer(&mut self, message: &[u8]) -> bool {
        if self.open {
            self.taken.push(StreamMessage::decode(message).unwrap());
        }
        self.open
    }
}

/// A mirror whose ring holds `ring` from ring sequence `oldest` on, and
/// whose table is `table`; `stats` counts what was mirrored of each
/// journal (records, last ring sequence, attempted horizon).
#[derive(Debug, Default)]
struct Mirror {
    oldest: u64,
    ring: Vec<(u64, u64, Option<[u64; RECORD_WORDS]>)>,
    table: Vec<(u64, [u64; 3])>,
    stats: BTreeMap<u64, (u64, u64, u64)>,
}

impl Mirror {
    fn new(
        table: Vec<(u64, [u64; 3])>,
        records: &[(u64, u64, Option<[u64; RECORD_WORDS]>)],
    ) -> Self {
        let mut mirror = Self {
            table,
            ..Self::default()
        };
        for &(journal, sequence, words) in records {
            mirror.push(journal, sequence, words);
        }
        mirror
    }

    /// Mirrors one record.
    fn push(&mut self, journal: u64, sequence: u64, words: Option<[u64; RECORD_WORDS]>) {
        let ring = self.oldest + self.ring.len() as u64;
        self.ring.push((journal, sequence, words));
        let stat = self.stats.entry(journal).or_default();
        *stat = (stat.0 + 1, ring, sequence + 1);
    }

    /// The ring overwrites its `count` oldest records.
    fn lap(&mut self, count: usize) {
        self.ring.drain(..count);
        self.oldest += count as u64;
    }
}

impl MirrorSource for Mirror {
    fn scan(&mut self, cursor: &mut u64, max: u64, deliver: &mut Deliver<'_>) -> u64 {
        let overwritten = self.oldest.saturating_sub(*cursor);
        *cursor = (*cursor).max(self.oldest);
        let end = self.oldest + self.ring.len() as u64;
        let mut delivered = 0;
        while *cursor < end && delivered < max {
            let (journal, sequence, words) = self.ring[(*cursor - self.oldest) as usize];
            deliver(*cursor, journal, sequence, words.as_ref());
            *cursor += 1;
            delivered += 1;
        }
        overwritten
    }

    fn end(&mut self) -> Option<u64> {
        Some(self.oldest + self.ring.len() as u64)
    }

    fn journals(&mut self, each: &mut dyn FnMut(JournalRead)) {
        for &(journal, facts) in &self.table {
            let (mirrored, last, attempted) = self.stats.get(&journal).copied().unwrap_or_default();
            each(JournalRead {
                journal,
                facts,
                mirrored,
                last_record: (mirrored > 0).then_some(last),
                attempted,
            });
        }
    }
}

const OWN: DriverSelf = DriverSelf {
    namespace: 1,
    namespace_inode: 4_026_531_834,
    clock: [0, 0, 0, 5, 77],
    granularity: 1000,
};

fn words(tag: u64) -> Option<[u64; RECORD_WORDS]> {
    Some([tag; RECORD_WORDS])
}

fn facts(journal: u64, generation: u64, facts: [u64; 3]) -> StreamMessage {
    let [kind, time_namespace, provenance] = facts;
    StreamMessage::Facts(JournalFacts {
        journal,
        generation,
        kind,
        time_namespace,
        provenance,
    })
}

fn record(journal: u64, generation: u64, sequence: u64) -> StreamMessage {
    StreamMessage::Record(StreamRecord {
        journal,
        generation,
        sequence,
        words: words(sequence).unwrap(),
    })
}

fn loss(journal: u64, first: u64, last: u64) -> StreamMessage {
    StreamMessage::Loss(StreamLoss {
        journal,
        first,
        last,
    })
}

/// Self first, then the facts read with the records, then the records with
/// the generation in force; a change of facts is the next generation.
#[test]
fn self_facts_and_records_are_published_in_order() {
    let mirror = Mirror::new(vec![(7, [2, 1, 2])], &[(7, 0, words(0)), (7, 1, words(1))]);
    let stream = Stream {
        open: true,
        taken: Vec::new(),
    };
    let mut publisher = TracePublisher::new(stream, mirror, OWN);
    assert!(publisher.publish());
    publisher.mirror.push(7, 2, words(2));
    // The same facts: no new facts message.
    assert!(publisher.publish());
    publisher.mirror.table = vec![(7, [2, 2, 2])];
    publisher.mirror.push(7, 3, words(3));
    assert!(publisher.publish());
    assert_eq!(
        publisher.sink.taken,
        [
            StreamMessage::DriverSelf(OWN),
            facts(7, 1, [2, 1, 2]),
            record(7, 1, 0),
            record(7, 1, 1),
            record(7, 1, 2),
            // Scanned before the table showed the change: the generation
            // in force then, and the new facts after it.
            record(7, 1, 3),
            facts(7, 2, [2, 2, 2]),
        ]
    );
    assert_eq!(publisher.counts().published, 7);
    assert_eq!(publisher.counts().losses, 0);
}

/// A stream that refuses blocks the publisher: nothing is dropped, the
/// mirror is not read meanwhile, and what the ring overwrote is a loss,
/// both by ring sequence and by the journal's gap.
#[test]
fn a_refusing_stream_blocks_and_an_overwrite_is_a_loss() {
    let mirror = Mirror::new(vec![(7, [1, 1, 2])], &[(7, 0, words(0))]);
    let mut publisher = TracePublisher::new(Stream::default(), mirror, OWN);
    assert!(!publisher.publish());
    assert!(!publisher.publish());
    // Only the self message waits: the mirror was not read.
    assert_eq!(publisher.queued(), 1);
    publisher.sink.open = true;
    assert!(publisher.publish());
    publisher.sink.open = false;
    // The ring laps past ring sequences 1 and 2 (journal 7's 1 and 2).
    for sequence in 1..=3 {
        publisher.mirror.push(7, sequence, words(sequence));
    }
    publisher.mirror.push(7, 4, None);
    publisher.mirror.lap(3);
    assert!(!publisher.publish());
    publisher.sink.open = true;
    assert!(publisher.publish());
    assert_eq!(
        publisher.sink.taken,
        [
            StreamMessage::DriverSelf(OWN),
            facts(7, 1, [1, 1, 2]),
            record(7, 1, 0),
            // Its journal is known: never journal 0.
            loss(7, 1, 2),
            record(7, 1, 3),
            // Not a whole trace record: lost, and said so.
            loss(7, 4, 4),
        ]
    );
    assert_eq!(publisher.counts().losses, 2);
}

/// karyos#1128: the requirements follow the self message, before anything
/// the mirror holds.
#[test]
fn the_requirements_follow_the_self_message() {
    let requirement = karyos_trace::stream::TimeRequirement {
        domain: 5,
        max_divergence_ns: 1_000_000,
        max_granularity_ns: 1000,
    };
    let mirror = Mirror::new(vec![(7, [2, 1, 2])], &[(7, 0, words(0))]);
    let stream = Stream {
        open: true,
        taken: Vec::new(),
    };
    let mut publisher = TracePublisher::with_requirements(stream, mirror, OWN, &[requirement]);
    assert!(publisher.publish());
    assert_eq!(
        publisher.sink.taken[..3],
        [
            StreamMessage::DriverSelf(OWN),
            StreamMessage::Requirement(requirement),
            facts(7, 1, [2, 1, 2]),
        ]
    );
}

/// A record whose journal's facts were never read is published with
/// generation 0, which no facts message names.
#[test]
fn a_record_without_facts_has_generation_zero() {
    let mirror = Mirror::new(Vec::new(), &[(9, 5, words(5))]);
    let stream = Stream {
        open: true,
        taken: Vec::new(),
    };
    let mut publisher = TracePublisher::new(stream, mirror, OWN).with_budget(1);
    assert!(publisher.publish());
    assert_eq!(
        publisher.sink.taken,
        [
            StreamMessage::DriverSelf(OWN),
            // Its sequences before 5 were never read: lost.
            loss(9, 0, 4),
            record(9, 0, 5)
        ]
    );
}

/// ADR-0117 point 1: records the ring overwrote after a journal's last one
/// read are a loss of that journal, named by its entry: from the sequence
/// after its last one read to its horizon.
#[test]
fn an_overwritten_tail_is_a_loss_of_its_journal() {
    let mirror = Mirror::new(vec![(7, [2, 1, 2]), (8, [2, 1, 2])], &[(7, 0, words(0))]);
    let stream = Stream {
        open: true,
        taken: Vec::new(),
    };
    let mut publisher = TracePublisher::new(stream, mirror, OWN);
    assert!(publisher.publish());
    // Journal 7's 1 to 3 and journal 8's 0 and 1 mirrored, then lapped by
    // journal 8's 2.
    for sequence in 1..=3 {
        publisher.mirror.push(7, sequence, words(sequence));
    }
    publisher.mirror.push(8, 0, words(0));
    publisher.mirror.push(8, 1, words(1));
    publisher.mirror.push(8, 2, words(2));
    publisher.mirror.lap(5);
    assert!(publisher.publish());
    assert_eq!(
        publisher.sink.taken[4..],
        [
            loss(8, 0, 0),
            record(8, 1, 1),
            record(8, 1, 2),
            loss(7, 1, 3)
        ]
    );
    // Accounted once.
    assert!(!publisher.publish());
    assert_eq!(publisher.counts().losses, 2);
}

/// Only records of a journal whose table entry was recycled before they
/// were read are a loss of journal 0, by ring sequence: nothing names
/// their journal any more.
#[test]
fn only_a_recycled_journals_records_are_a_loss_of_journal_zero() {
    let mirror = Mirror::new(vec![(7, [2, 1, 2])], &[]);
    let stream = Stream {
        open: true,
        taken: Vec::new(),
    };
    let mut publisher = TracePublisher::new(stream, mirror, OWN);
    assert!(publisher.publish());
    // Journal 9 mirrors two records and its entry is recycled before the
    // publisher reads them; journal 7's record laps them.
    publisher.mirror.push(9, 0, words(0));
    publisher.mirror.push(9, 1, words(1));
    publisher.mirror.push(7, 0, words(0));
    publisher.mirror.lap(2);
    assert!(publisher.publish());
    assert_eq!(
        publisher.sink.taken[1..],
        [facts(7, 1, [2, 1, 2]), record(7, 1, 0), loss(0, 0, 1)]
    );
}

/// Codex review of #1278, P1: a busy journal whose records the cursor has
/// not passed never holds back a recycled journal's proven loss.
#[test]
fn a_busy_journal_never_holds_back_a_recycled_journals_loss() {
    let mirror = Mirror::new(vec![(7, [2, 1, 2])], &[]);
    let stream = Stream {
        open: true,
        taken: Vec::new(),
    };
    let mut publisher = TracePublisher::new(stream, mirror, OWN).with_budget(1);
    assert!(publisher.publish());
    // Journal 9 mirrors two records, its entry recycled; journal 7 keeps
    // the ring busy ahead of a cursor that reads one record a cycle.
    publisher.mirror.push(9, 0, words(0));
    publisher.mirror.push(9, 1, words(1));
    for sequence in 0..4 {
        publisher.mirror.push(7, sequence, words(sequence));
    }
    publisher.mirror.lap(2);
    assert!(publisher.publish());
    assert!(
        publisher.sink.taken.contains(&loss(0, 0, 1)),
        "{:?}",
        publisher.sink.taken
    );
    // Journal 7's unread records are not losses.
    assert!(
        !publisher
            .sink
            .taken
            .iter()
            .any(|message| matches!(message, StreamMessage::Loss(loss) if loss.journal == 7)),
        "{:?}",
        publisher.sink.taken
    );
}

/// Codex review of #1278, P2: two disjoint overwrites of recycled
/// journals are two losses, never one range over the record read between.
#[test]
fn disjoint_overwrites_stay_separate_losses() {
    let mirror = Mirror::new(vec![(7, [2, 1, 2])], &[]);
    let stream = Stream {
        open: true,
        taken: Vec::new(),
    };
    let mut publisher = TracePublisher::new(stream, mirror, OWN);
    assert!(publisher.publish());
    // Ring 0: journal 9 (recycled), lapped; ring 1: journal 7, read.
    publisher.mirror.push(9, 0, words(0));
    publisher.mirror.push(7, 0, words(0));
    publisher.mirror.lap(1);
    assert!(publisher.publish());
    // Ring 2: journal 8 (recycled), lapped; ring 3: journal 7, read.
    publisher.mirror.push(8, 0, words(0));
    publisher.mirror.push(7, 1, words(1));
    publisher.mirror.lap(2);
    assert!(publisher.publish());
    let zero: Vec<&StreamMessage> = publisher
        .sink
        .taken
        .iter()
        .filter(|message| matches!(message, StreamMessage::Loss(loss) if loss.journal == 0))
        .collect();
    assert_eq!(zero, [&loss(0, 0, 0), &loss(0, 2, 2)]);
}

/// Codex review of #1278, P1: a stop reads the mirror to its end over as
/// many cycles as the budget needs; what a deadline leaves unread is a
/// loss of journal 0 by ring sequence, never dropped silently.
#[test]
fn a_stop_reads_to_the_mirror_end_or_reports_the_rest() {
    let records: Vec<(u64, u64, Option<[u64; RECORD_WORDS]>)> = (0..5)
        .map(|sequence| (7, sequence, words(sequence)))
        .collect();
    let mirror = Mirror::new(vec![(7, [2, 1, 2])], &records);
    let stream = Stream {
        open: true,
        taken: Vec::new(),
    };
    let mut publisher = TracePublisher::new(stream, mirror, OWN).with_budget(2);
    let end = publisher.mirror_end().unwrap();
    assert_eq!(end, 5);
    let mut cycles = 0;
    while publisher.cursor() < end || publisher.queued() > 0 {
        let _ = publisher.publish();
        cycles += 1;
    }
    assert_eq!(cycles, 3, "one read takes at most its budget");
    assert_eq!(publisher.counts().losses, 0);
    // A deadline that passes with records unread: a loss of the rest.
    for sequence in 5..8 {
        publisher.mirror.push(7, sequence, words(sequence));
    }
    let end = publisher.mirror_end().unwrap();
    publisher.abandon(end);
    assert_eq!(publisher.sink.taken.last(), Some(&loss(0, 5, 7)));
    assert_eq!(publisher.cursor(), end);
}
