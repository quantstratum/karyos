// SPDX-License-Identifier: Apache-2.0

// Tests of the network trace agent (`quantstratum-docs:
// karyos/design/trace-network.md` §8, "Granularity" and the agent's side of
// "Records").

use karyos_protocol::journal::{JournalConsumer, Taken, record_journal};

use super::*;
use crate::record::{RECORD_WORDS, decode_record};
use crate::trace_clock::MonotonicClock;

const DRIVER: [u64; 2] = [5, 6];

const PUBLICATION: PublicationIdentity = PublicationIdentity {
    driver: [1, 2],
    registration: 3,
    stream_id: 10,
    session_id: -4,
    incarnation: 1,
};

fn lane(lane: u8) -> Lane {
    Lane::try_new(lane).unwrap()
}

fn ext(message: u64) -> TraceExtension {
    TraceExtension {
        extension_flags: 0,
        trace_id: [7, 8],
        span_id: 9,
        parent_span_id: 0,
        message_id: message,
    }
}

/// A journal of trace records for `side` on `lane`, numbered `number`,
/// with its consumer.
fn journal(side: NetSide, lane: Lane, number: u64) -> (NetJournal, JournalConsumer) {
    let (writer, consumer) = record_journal(16, RECORD_WORDS, 2).unwrap();
    (
        NetJournal {
            side,
            publication: PUBLICATION,
            lane,
            number,
            writer,
        },
        consumer,
    )
}

/// Every record the consumer holds, decoded; then whether it is closed.
fn records(consumer: &mut JournalConsumer) -> (Vec<TraceRecord>, bool) {
    let mut out = Vec::new();
    loop {
        match consumer.take() {
            Taken::Record(record) => {
                let words: [u64; RECORD_WORDS] = record.payload.try_into().unwrap();
                out.push(decode_record(&words).unwrap().0);
            }
            Taken::Empty => return (out, false),
            Taken::Closed => return (out, true),
        }
    }
}

fn agent(journals: usize) -> NetworkTraceAgent<MonotonicClock> {
    NetworkTraceAgent::new(DRIVER, MonotonicClock::new(11), journals)
}

fn pickup(position: u64, path: u32, attempt: u32) -> NetPickup {
    NetPickup {
        publication: PUBLICATION,
        lane: lane(1),
        position,
        path,
        attempt,
    }
}

fn commit(position: u64, path: u32) -> NetCommit {
    NetCommit {
        publication: PUBLICATION,
        lane: lane(1),
        position,
        path,
    }
}

/// A `k` fragment message gives `k` pickup records per path and attempt,
/// each naming its frame, path and attempt; a retransmission records a
/// pickup with an attempt above 0. Network points never set `root`.
#[test]
fn every_fragment_is_picked_up_per_path_and_attempt() {
    let mut agent = agent(2);
    let (sender, mut consumer) = journal(NetSide::Sender, lane(1), 4);
    agent.open_journal(sender);
    let frames = [0, 1408, 2816];
    for path in [0, 1] {
        for position in frames {
            agent.on_sender_pickup(&ext(42), &pickup(position, path, 0));
        }
    }
    // A repair of the middle frame on path 1.
    agent.on_sender_pickup(&ext(42), &pickup(1408, 1, 1));
    let (records, closed) = records(&mut consumer);
    assert!(!closed);
    let seen: Vec<(u64, u32, u32)> = records
        .iter()
        .map(|record| {
            let network = record.network.unwrap();
            (record.position, network.path, network.attempt)
        })
        .collect();
    assert_eq!(
        seen,
        [
            (0, 0, 0),
            (1408, 0, 0),
            (2816, 0, 0),
            (0, 1, 0),
            (1408, 1, 0),
            (2816, 1, 0),
            (1408, 1, 1),
        ]
    );
    for record in &records {
        assert_eq!(record.point, Point::SenderPickup);
        assert_eq!((record.lane, record.ids.message_id), (1, 42));
        assert_eq!(record.publication, PUBLICATION.into());
        assert!(!record.root && record.packet.is_none());
    }
    assert_eq!(agent.counts().stored, 7);
}

/// A receiver records one commit per frame with the winning path and no
/// attempt; closing its journal closes the writer, and later observations
/// are unjournaled.
#[test]
fn commits_name_their_path_and_close_with_the_journal() {
    let mut agent = agent(2);
    let (receiver, mut consumer) = journal(NetSide::Receiver, lane(1), 5);
    agent.open_journal(receiver);
    agent.on_receiver_commit(&ext(42), &commit(0, 1));
    agent.on_receiver_commit(&ext(42), &commit(1408, 0));
    // Another side, lane or publication: no journal.
    agent.on_sender_pickup(&ext(42), &pickup(0, 0, 0));
    agent.on_receiver_commit(
        &ext(42),
        &NetCommit {
            lane: lane(2),
            ..commit(0, 0)
        },
    );
    agent.close_journal(NetSide::Receiver, &PUBLICATION, lane(1));
    agent.on_receiver_commit(&ext(42), &commit(2816, 0));
    let (records, closed) = records(&mut consumer);
    assert!(closed);
    let seen: Vec<(Point, u64, u32, u32)> = records
        .iter()
        .map(|record| {
            let network = record.network.unwrap();
            (record.point, record.position, network.path, network.attempt)
        })
        .collect();
    assert_eq!(
        seen,
        [
            (Point::ReceiverCommit, 0, 1, 0),
            (Point::ReceiverCommit, 1408, 0, 0),
        ]
    );
    let counts = agent.counts();
    assert_eq!((counts.stored, counts.unjournaled), (2, 3));
}

/// The table is allocated at construction: a journal beyond it is closed at
/// once and counted, and one whose records are not trace records is
/// refused; a freed place takes the next journal.
#[test]
fn a_journal_beyond_the_table_is_closed_and_counted() {
    let mut agent = agent(1);
    let (first, _first) = journal(NetSide::Sender, lane(0), 1);
    agent.open_journal(first);
    let (second, mut second_consumer) = journal(NetSide::Sender, lane(1), 2);
    agent.open_journal(second);
    assert_eq!(records(&mut second_consumer), (Vec::new(), true));
    assert_eq!(agent.counts().journals_refused, 1);
    let (writer, _) = record_journal(4, 2, 1).unwrap();
    agent.close_journal(NetSide::Sender, &PUBLICATION, lane(0));
    agent.open_journal(NetJournal {
        side: NetSide::Sender,
        publication: PUBLICATION,
        lane: lane(2),
        number: 3,
        writer,
    });
    assert_eq!(agent.counts().journals_refused, 2);
    let (third, mut third_consumer) = journal(NetSide::Sender, lane(3), 4);
    agent.open_journal(third);
    agent.on_sender_pickup(
        &ext(1),
        &NetPickup {
            lane: lane(3),
            ..pickup(0, 0, 0)
        },
    );
    assert_eq!(records(&mut third_consumer).0.len(), 1);
}

/// A count that would overflow keeps its value and is reported.
#[test]
fn a_counter_never_wraps() {
    let mut counts = NetworkCounts {
        unjournaled: u64::MAX,
        ..NetworkCounts::default()
    };
    counts.count(NetworkCounter::Unjournaled);
    counts.count(NetworkCounter::Stored);
    assert_eq!(counts.unjournaled, u64::MAX);
    assert_eq!(counts.stored, 1);
    assert_eq!(counts.overflowed, Some(NetworkCounter::Unjournaled));
}
