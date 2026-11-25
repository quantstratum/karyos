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
/// whose table is `table`.
#[derive(Debug, Default)]
struct Mirror {
    oldest: u64,
    ring: Vec<(u64, u64, Option<[u64; RECORD_WORDS]>)>,
    table: Vec<(u64, [u64; 3])>,
}

impl MirrorSource for Mirror {
    fn scan(&mut self, cursor: &mut u64, max: u64, deliver: &mut Deliver<'_>) -> u64 {
        let overwritten = self.oldest.saturating_sub(*cursor);
        *cursor = (*cursor).max(self.oldest);
        let end = self.oldest + self.ring.len() as u64;
        let mut delivered = 0;
        while *cursor < end && delivered < max {
            let (journal, sequence, words) = self.ring[(*cursor - self.oldest) as usize];
            deliver(journal, sequence, words.as_ref());
            *cursor += 1;
            delivered += 1;
        }
        overwritten
    }

    fn journals(&mut self, each: &mut dyn FnMut(u64, [u64; 3])) {
        for &(journal, facts) in &self.table {
            each(journal, facts);
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
    let mirror = Mirror {
        oldest: 0,
        ring: vec![(7, 0, words(0)), (7, 1, words(1))],
        table: vec![(7, [2, 1, 2])],
    };
    let stream = Stream {
        open: true,
        taken: Vec::new(),
    };
    let mut publisher = TracePublisher::new(stream, mirror, OWN);
    assert!(publisher.publish());
    publisher.mirror.ring.push((7, 2, words(2)));
    // The same facts: no new facts message.
    assert!(publisher.publish());
    publisher.mirror.table = vec![(7, [2, 2, 2])];
    publisher.mirror.ring.push((7, 3, words(3)));
    assert!(publisher.publish());
    assert_eq!(
        publisher.sink.taken,
        [
            StreamMessage::DriverSelf(OWN),
            facts(7, 1, [2, 1, 2]),
            record(7, 1, 0),
            record(7, 1, 1),
            record(7, 1, 2),
            facts(7, 2, [2, 2, 2]),
            record(7, 2, 3),
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
    let mirror = Mirror {
        oldest: 0,
        ring: vec![(7, 0, words(0))],
        table: vec![(7, [1, 1, 2])],
    };
    let mut publisher = TracePublisher::new(Stream::default(), mirror, OWN);
    assert!(!publisher.publish());
    assert!(!publisher.publish());
    // Only the self message waits: the mirror was not read.
    assert_eq!(publisher.queued(), 1);
    publisher.sink.open = true;
    assert!(publisher.publish());
    publisher.sink.open = false;
    // The ring laps past ring sequences 1 and 2 (journal 7's 1 and 2).
    publisher.mirror.oldest = 3;
    publisher.mirror.ring = vec![(7, 3, words(3)), (7, 4, None)];
    assert!(!publisher.publish());
    publisher.sink.open = true;
    assert!(publisher.publish());
    assert_eq!(
        publisher.sink.taken,
        [
            StreamMessage::DriverSelf(OWN),
            facts(7, 1, [1, 1, 2]),
            record(7, 1, 0),
            loss(0, 1, 2),
            loss(7, 1, 2),
            record(7, 1, 3),
            // Not a whole trace record: lost, and said so.
            loss(7, 4, 4),
        ]
    );
    assert_eq!(publisher.counts().losses, 3);
}

/// A record whose journal's facts were never read is published with
/// generation 0, which no facts message names.
#[test]
fn a_record_without_facts_has_generation_zero() {
    let mirror = Mirror {
        oldest: 0,
        ring: vec![(9, 5, words(5))],
        table: Vec::new(),
    };
    let stream = Stream {
        open: true,
        taken: Vec::new(),
    };
    let mut publisher = TracePublisher::new(stream, mirror, OWN).with_budget(1);
    assert!(publisher.publish());
    assert_eq!(
        publisher.sink.taken,
        [StreamMessage::DriverSelf(OWN), record(9, 0, 5)]
    );
}
