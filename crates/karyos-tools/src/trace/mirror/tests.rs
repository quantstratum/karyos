// SPDX-License-Identifier: Apache-2.0

// The tool's mirror reader over synthetic mirrors on the heap
// (`quantstratum-docs: karyos/design/trace-tool.md` and
// `trace-journal-region.md`, Tests): the driver's writer API stands in for
// the driver, so every case runs on every platform. The Linux tests of
// `tests/karyos_trace.rs` run the same cases against a real driver.

use karyos_protocol::journal::{Append, DropRange, Stamp, Taken, record_journal};
use karyos_protocol::trace_hook::NetSide;
use karyos_sys::trace_mirror::{
    JournalEntry, JournalKind, JournalState, MAX_RECYCLE_PAIRS, NetworkFacts, NotedPublisher,
    RecycledJournal, TimeNamespace, TraceMirror, trace_mirror,
};
use karyos_trace::{
    AttributionConfig, ClockProvenance, HostMonotonicClock, ObservedTime, Point, PublicationId,
    RECORD_WORDS, SubscriberId, TraceAnswer, TraceIds, TraceRecord, TraceReport, Verdict,
    decode_record, encode_record, trace_journal,
};

use super::*;

/// The driver instance of these tests: words `[1, 2]`.
const INSTANCE: u128 = (1 << 64) | 2;

/// The traced publication: stream registration 3, incarnation 1.
const PUBLICATION: PublicationId = PublicationId {
    driver: [1, 2],
    registration: 3,
    stream_id: 5,
    session_id: 1,
    incarnation: 1,
};

/// Another publication of the same driver.
const OTHER: PublicationId = PublicationId {
    driver: [1, 2],
    registration: 4,
    stream_id: 6,
    session_id: 1,
    incarnation: 1,
};

/// A message of `publication` at `position` in trace `[trace, 1]`,
/// observed at `point` at host time `time`.
fn observation(
    publication: PublicationId,
    point: Point,
    position: u64,
    trace: u64,
    time: u64,
) -> TraceRecord {
    TraceRecord {
        point,
        publication,
        lane: 0,
        position,
        ids: TraceIds {
            trace_id: [trace, 1],
            span_id: 1,
            parent_span_id: 0,
            message_id: position,
        },
        observed: ObservedTime {
            time,
            clock: 1,
            epoch: HostMonotonicClock::EPOCH,
            uncertainty: 10,
        },
        subscriber: (point == Point::SubscriberPoll).then_some(SubscriberId {
            driver: publication.driver,
            registration: 9,
            incarnation: 1,
        }),
        packet: None,
        network: None,
        // Every Publish of these tests starts its own trace.
        root: point == Point::Publish,
    }
}

fn publish(position: u64, trace: u64, time: u64) -> TraceRecord {
    observation(PUBLICATION, Point::Publish, position, trace, time)
}

fn poll(position: u64, trace: u64, time: u64) -> TraceRecord {
    observation(PUBLICATION, Point::SubscriberPoll, position, trace, time)
}

/// The collection stamp of `record`: its observation time.
fn stamp(record: &TraceRecord) -> Stamp {
    Stamp {
        time: record.observed.time,
        clock: record.observed.clock,
        epoch: record.observed.epoch,
    }
}

fn words(record: &TraceRecord) -> [u64; RECORD_WORDS] {
    encode_record(record, stamp(record)).unwrap()
}

/// A mirror that the test writes as the driver would.
struct Driver {
    mirror: TraceMirror,
    entries: Vec<Option<JournalEntry>>,
    /// The next mirror sequence (T7).
    next_sequence: u64,
}

impl Driver {
    fn new(entries: usize, log: usize, ring: usize) -> Self {
        Self {
            mirror: trace_mirror(entries, log, ring).unwrap(),
            entries: vec![None; entries],
            next_sequence: 1,
        }
    }

    /// Assigns the next mirror sequence and publishes the high-water mark,
    /// as the driver does before it writes the entry.
    fn assign(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.mirror.assign_sequence(sequence);
        sequence
    }

    /// A journal created and recycled, covered, before anyone saw it: its
    /// sequence is assigned and never shown.
    fn unseen(&mut self) {
        let _ = self.assign();
    }

    fn entry(&mut self, index: usize) -> &mut JournalEntry {
        self.entries[index].as_mut().unwrap()
    }

    fn write(&mut self, index: usize) {
        let entry = self.entries[index];
        assert!(self.mirror.write_entry(index, entry.as_ref()));
    }

    /// Opens journal `journal` of `kind` on `publication` at `index`, in
    /// the driver's time namespace with a host clock.
    fn open(&mut self, index: usize, journal: u64, kind: JournalKind, publication: PublicationId) {
        let mut entry = JournalEntry::open(journal, 1, kind, RECORD_WORDS as u64, 8);
        entry.registration = 100 + journal;
        entry.stream = publication.registration;
        entry.incarnation = publication.incarnation;
        entry.time_namespace = TimeNamespace::Same;
        entry.provenance = ClockProvenance::HostMonotonic.word();
        entry.join = (kind == JournalKind::Subscriber).then_some(0);
        entry.sequence = self.assign();
        self.entries[index] = Some(entry);
        self.write(index);
    }

    /// The journal at `index` stores `record` and the driver mirrors it.
    fn store(&mut self, index: usize, record: &TraceRecord) {
        self.store_words(index, &words(record));
    }

    /// The journal at `index` stores the record `words` as given.
    fn store_words(&mut self, index: usize, words: &[u64]) {
        let entry = *self.entry(index);
        let appended = self
            .mirror
            .append(entry.journal, entry.attempted, words)
            .unwrap();
        let entry = self.entry(index);
        entry.attempted += 1;
        entry.stored += 1;
        entry.mirrored += 1;
        entry.last_record = Some(appended.seq);
        self.write(index);
    }

    /// The journal at `index` drops a record (the driver reads the drop in
    /// its loss accounting).
    fn drop_record(&mut self, index: usize) {
        let entry = self.entry(index);
        let sequence = entry.attempted;
        entry.attempted += 1;
        let count = entry.range_count;
        if count > 0 && entry.ranges[count - 1].last + 1 == sequence {
            entry.ranges[count - 1].last = sequence;
        } else {
            entry.ranges[count] = DropRange {
                first: sequence,
                last: sequence,
                first_time: 0,
                last_time: 0,
                clock: 1,
                epoch: HostMonotonicClock::EPOCH,
            };
            entry.range_count += 1;
        }
        self.write(index);
    }

    /// The journal at `index` ends in `state`, with `boundary`.
    fn end(&mut self, index: usize, state: JournalState, boundary: Option<u64>) {
        let entry = self.entry(index);
        entry.state = state;
        entry.boundary = boundary;
        self.write(index);
    }

    /// Reuses table entry `index`, logging what it held first.
    fn recycle(&mut self, index: usize, log: usize) {
        let old = self.entries[index].take().unwrap();
        let mut pairs = [NotedPublisher::default(); MAX_RECYCLE_PAIRS];
        pairs[0] = NotedPublisher {
            journal: 1,
            attempted: 1,
        };
        assert!(self.mirror.write_log(
            log,
            Some(&RecycledJournal {
                journal: old.journal,
                stream: old.stream,
                lane: old.lane,
                incarnation: old.incarnation,
                state: old.state,
                boundary: old.boundary,
                pairs,
                pair_count: 1,
                sequence: old.sequence,
            })
        ));
        self.write(index);
    }

    fn scan(&self, tool: &mut MirrorTool) -> ScanReport {
        tool.scan(&self.mirror.reader())
    }
}

fn answer(report: &TraceReport, trace: u64) -> TraceAnswer {
    report.trace([trace, 1])
}

/// Two identical journals: one read by a collector in process, the other
/// drained by a stand in for the driver into a mirror.
struct Pair {
    collector_side: karyos_trace::TraceWriter,
    collector: Option<karyos_trace::TraceCollector>,
    raw: karyos_protocol::journal::JournalWriter,
    consumer: karyos_protocol::journal::JournalConsumer,
}

impl Pair {
    fn new(journal: u64, capacity: usize) -> Self {
        let observer = ObserverId {
            driver: PUBLICATION.driver,
            journal,
        };
        let (collector_side, collector) = trace_journal(capacity, 4, observer, 1).unwrap();
        let (raw, consumer) = record_journal(capacity, RECORD_WORDS, 4).unwrap();
        Self {
            collector_side,
            collector: Some(collector),
            raw,
            consumer,
        }
    }

    fn record(&mut self, record: &TraceRecord) {
        let a = self.collector_side.record(record, stamp(record)).unwrap();
        let b = self.raw.append(&words(record), stamp(record)).unwrap();
        assert_eq!(
            matches!(a, Append::Stored { .. }),
            matches!(b, Append::Stored { .. })
        );
    }

    /// Closes both writers and drains the raw journal into the mirror
    /// entry at `index`, as the driver's drain does.
    fn close_and_mirror(&mut self, driver: &mut Driver, index: usize, boundary: Option<u64>) {
        self.collector_side.close();
        self.raw.close();
        let journal = driver.entry(index).journal;
        loop {
            match self.consumer.take() {
                Taken::Record(record) => {
                    let appended = driver
                        .mirror
                        .append(journal, record.sequence, record.payload)
                        .unwrap();
                    let entry = driver.entry(index);
                    entry.last_record = Some(appended.seq);
                    entry.mirrored += 1;
                }
                Taken::Empty => panic!("closed journals drain to their end"),
                Taken::Closed => break,
            }
        }
        let losses = self.consumer.losses();
        let (attempted, stored, lost_before) =
            (losses.attempted, losses.stored, losses.lost_before);
        let ranges = losses.ranges.to_vec();
        let entry = driver.entry(index);
        entry.attempted = attempted;
        entry.stored = stored;
        entry.lost_before = lost_before;
        entry.range_count = ranges.len();
        for (target, range) in entry.ranges.iter_mut().zip(&ranges) {
            *target = *range;
        }
        driver.end(index, JournalState::Closed, boundary);
    }
}

/// Publishes and polls `messages` (position, trace, publish time, poll
/// time) through a collector report and through the mirror, with journals
/// of the given capacities, and checks both give the same answers,
/// summaries and histograms.
fn compare(messages: &[(u64, u64, u64, u64)], publisher: usize, subscriber: usize) {
    let mut driver = Driver::new(4, 2, 64);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    let mut publishing = Pair::new(1, publisher);
    let mut polling = Pair::new(2, subscriber);
    for &(position, trace, published, _) in messages {
        publishing.record(&publish(position, trace, published));
    }
    for &(position, trace, _, polled) in messages {
        polling.record(&poll(position, trace, polled));
    }
    let boundary = messages.iter().map(|m| m.0 + 1).max().unwrap_or(0);
    publishing.close_and_mirror(&mut driver, 0, None);
    polling.close_and_mirror(&mut driver, 1, Some(boundary));

    let mut collected = TraceReport::new(
        AttributionConfig {
            span: u64::MAX,
            max_traces: 64,
            max_intervals: MAX_INTERVALS,
        },
        HISTOGRAM,
    );
    let host = ClockProvenance::HostMonotonic;
    let pub_id = collected
        .add_publisher(publishing.collector.take().unwrap(), host, PUBLICATION)
        .unwrap();
    let sub_id = collected
        .add_subscriber(polling.collector.take().unwrap(), host, PUBLICATION, 0)
        .unwrap();
    collected.closed(pub_id, None);
    collected.closed(sub_id, Some(boundary));
    collected.drain().unwrap();

    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    let mirrored = tool.report().unwrap();

    for &(_, trace, _, _) in messages {
        assert_eq!(
            answer(&collected, trace),
            answer(&mirrored, trace),
            "trace {trace}"
        );
    }
    assert_eq!(collected.summary(), mirrored.summary());
    let (a, b) = (
        collected.latencies().unwrap(),
        mirrored.latencies().unwrap(),
    );
    assert_eq!(a.len(), b.len());
    for ((pa, ha), (pb, hb)) in a.iter().zip(&b) {
        assert_eq!(pa, pb);
        assert_eq!(ha.available(), hb.available());
        for (n, d) in [(0, 1), (1, 2), (99, 100), (999, 1000), (1, 1)] {
            assert_eq!(ha.quantile(n, d).unwrap(), hb.quantile(n, d).unwrap());
        }
    }
}

/// A mirror source and a collector over the same records give the same
/// verdicts and histograms: without loss (every trace Complete, latencies
/// calibrated), and with a journal that dropped records (Incomplete).
#[test]
fn a_mirror_source_and_a_collector_agree() {
    let messages = [
        (0, 1, 1_000, 1_300),
        (64, 2, 2_000, 2_500),
        (128, 3, 3_000, 3_200),
        (192, 4, 4_000, 4_900),
    ];
    compare(&messages, 8, 8);
    // The subscriber journal holds two records: the last two polls drop.
    compare(&messages, 8, 2);
    // The publisher journal holds one: three Publish records drop.
    compare(&messages, 1, 8);
}

/// The no-loss comparison above really is Complete and calibrated.
#[test]
fn the_mirror_report_is_complete_without_loss() {
    let mut driver = Driver::new(4, 2, 64);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.store(0, &publish(0, 1, 1_000));
    driver.store(1, &poll(0, 1, 1_400));
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, Some(1));
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    let report = tool.report().unwrap();
    assert_eq!(answer(&report, 1), TraceAnswer::Final(Verdict::Complete));
    let latencies = report.latencies().unwrap();
    assert_eq!(latencies[0].1.available(), 1);
    assert_eq!((tool.overwritten(), tool.mirror_lost()), (0, 0));
}

/// A network entry of `kind` for `PUBLICATION` (this driver's), expected
/// from `start`.
fn network_entry(driver: &mut Driver, index: usize, journal: u64, kind: JournalKind, start: u64) {
    let mut network = JournalEntry::open(journal, 0, kind, RECORD_WORDS as u64, 8);
    network.registration = PUBLICATION.registration;
    network.stream = PUBLICATION.registration;
    network.incarnation = PUBLICATION.incarnation;
    network.time_namespace = TimeNamespace::Same;
    network.provenance = ClockProvenance::HostMonotonic.word();
    network.network = Some(NetworkFacts {
        sender_driver: PUBLICATION.driver,
        start: Some(start),
        boundary: None,
        first_gap: None,
    });
    network.sequence = driver.assign();
    driver.entries[index] = Some(network);
    driver.write(index);
}

/// The network entry at `index` closes with `boundary` in its facts.
fn end_network(driver: &mut Driver, index: usize, boundary: Option<u64>) {
    let entry = driver.entry(index);
    entry.state = JournalState::Closed;
    if let Some(facts) = entry.network.as_mut() {
        facts.boundary = boundary;
    }
    driver.write(index);
}

/// The network record of message `position` at `point`.
fn network_record(point: Point, position: u64, trace: u64, time: u64) -> TraceRecord {
    TraceRecord {
        network: Some(karyos_trace::NetworkPath {
            path: 0,
            attempt: 0,
        }),
        ..observation(PUBLICATION, point, position, trace, time)
    }
}

/// Network journals (kinds 3 and 4) are read as network sources: an
/// expected one that holds the message completes its trace, one closed
/// without it makes it Incomplete, and one closed without a boundary is
/// lost; a record of the other side's point contradicts the entry.
#[test]
fn network_journals_are_read_as_network_sources() {
    for (kind, point) in [
        (JournalKind::NetworkSender, Point::SenderPickup),
        (JournalKind::NetworkReceiver, Point::ReceiverCommit),
    ] {
        for (holds, boundary, expected) in [
            (true, Some(1), TraceAnswer::Final(Verdict::Complete)),
            (false, Some(1), TraceAnswer::Final(Verdict::Incomplete)),
            (true, None, TraceAnswer::Final(Verdict::Incomplete)),
            // The message lies beyond the boundary: not expected.
            (false, Some(0), TraceAnswer::Final(Verdict::Complete)),
        ] {
            let mut driver = Driver::new(4, 2, 64);
            driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
            driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
            network_entry(&mut driver, 2, 3, kind, 0);
            driver.store(0, &publish(0, 1, 1_000));
            driver.store(1, &poll(0, 1, 1_400));
            if holds {
                driver.store(2, &network_record(point, 0, 1, 1_200));
            }
            driver.end(0, JournalState::Closed, None);
            driver.end(1, JournalState::Closed, Some(1));
            end_network(&mut driver, 2, boundary);
            let mut tool = MirrorTool::new(INSTANCE);
            let _ = driver.scan(&mut tool);
            let report = tool.report().unwrap();
            assert_eq!(
                answer(&report, 1),
                expected,
                "{kind:?} {holds} {boundary:?}"
            );
        }
        let mut driver = Driver::new(4, 2, 64);
        network_entry(&mut driver, 0, 3, kind, 0);
        let mut tool = MirrorTool::new(INSTANCE);
        let _ = driver.scan(&mut tool);
        let tracked = &tool.journals[&3];
        assert!(!tracked.contradicts(&network_record(point, 0, 1, 1_000), [1, 2]));
        assert!(tracked.contradicts(&publish(0, 1, 1_000), [1, 2]));
    }
}

/// A network sender journal mirrored and the same records collected in
/// process give the same verdicts: without loss, and with a network journal
/// that dropped records.
#[test]
fn a_mirror_and_a_collector_agree_on_network_journals() {
    let messages = [(0, 1, 1_000, 1_300), (64, 2, 2_000, 2_500)];
    for network_capacity in [8, 1] {
        let mut driver = Driver::new(4, 2, 64);
        driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
        driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
        network_entry(&mut driver, 2, 3, JournalKind::NetworkSender, 0);
        let mut publishing = Pair::new(1, 8);
        let mut polling = Pair::new(2, 8);
        let mut sending = Pair::new(3, network_capacity);
        for &(position, trace, published, polled) in &messages {
            publishing.record(&publish(position, trace, published));
            sending.record(&network_record(
                Point::SenderPickup,
                position,
                trace,
                published + 100,
            ));
            polling.record(&poll(position, trace, polled));
        }
        let boundary = 65;
        publishing.close_and_mirror(&mut driver, 0, None);
        polling.close_and_mirror(&mut driver, 1, Some(boundary));
        sending.close_and_mirror(&mut driver, 2, None);
        end_network(&mut driver, 2, Some(boundary));

        let mut collected = TraceReport::new(
            AttributionConfig {
                span: u64::MAX,
                max_traces: 64,
                max_intervals: MAX_INTERVALS,
            },
            HISTOGRAM,
        );
        let host = ClockProvenance::HostMonotonic;
        let ids = [
            collected
                .add_publisher(publishing.collector.take().unwrap(), host, PUBLICATION)
                .unwrap(),
            collected
                .add_subscriber(polling.collector.take().unwrap(), host, PUBLICATION, 0)
                .unwrap(),
            collected
                .add_network(
                    sending.collector.take().unwrap(),
                    host,
                    PUBLICATION,
                    NetSide::Sender,
                    0,
                    Some(0),
                )
                .unwrap(),
        ];
        collected.closed(ids[0], None);
        collected.closed(ids[1], Some(boundary));
        collected.closed(ids[2], Some(boundary));
        collected.drain().unwrap();

        let mut tool = MirrorTool::new(INSTANCE);
        let _ = driver.scan(&mut tool);
        let mirrored = tool.report().unwrap();
        for &(_, trace, _, _) in &messages {
            assert_eq!(
                answer(&collected, trace),
                answer(&mirrored, trace),
                "capacity {network_capacity}, trace {trace}"
            );
        }
        let expected = if network_capacity == 8 {
            TraceAnswer::Final(Verdict::Complete)
        } else {
            TraceAnswer::Final(Verdict::Incomplete)
        };
        assert_eq!(answer(&mirrored, 1), expected);
        assert_eq!(collected.summary(), mirrored.summary());
    }
}

/// A rise in the mirror's count of refused network journals (header word
/// 7), or any count at the attach, puts every held message whose trace was
/// not final out of scope; a final trace keeps its answer.
#[test]
fn refused_network_journals_put_held_messages_out_of_scope() {
    let mut driver = Driver::new(4, 2, 64);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.store(0, &publish(0, 1, 1_000));
    driver.store(1, &poll(0, 1, 1_400));
    // The subscriber never polls trace 2: Incomplete once it closes.
    driver.store(0, &publish(64, 2, 1_100));
    driver.end(0, JournalState::Closed, None);
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    assert_eq!(tool.network_refused(), (0, 0));
    assert_eq!(answer(&tool.report().unwrap(), 1), TraceAnswer::Provisional);
    assert!(driver.mirror.refuse_network_journal());
    driver.end(1, JournalState::Closed, Some(65));
    let _ = driver.scan(&mut tool);
    assert_eq!(tool.network_refused(), (1, 1));
    let report = tool.report().unwrap();
    // Provisional at the rise: out of scope for the tool's life.
    assert_eq!(answer(&report, 1), TraceAnswer::OutOfScope);
    assert_eq!(answer(&report, 2), TraceAnswer::OutOfScope);
    // No further rise: no further scope loss.
    let _ = driver.scan(&mut tool);
    assert_eq!(tool.network_refused(), (1, 1));

    // A count already there at the attach: nothing held is final yet.
    let mut driver = Driver::new(4, 2, 64);
    assert!(driver.mirror.refuse_network_journal());
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.store(0, &publish(0, 1, 1_000));
    driver.store(1, &poll(0, 1, 1_400));
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, Some(1));
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    assert_eq!(tool.network_refused(), (1, 1));
    assert_eq!(answer(&tool.report().unwrap(), 1), TraceAnswer::OutOfScope);
}

/// Batch C of #121 at unit level: the report reads the drop ranges and
/// `lost_before` from the table, and a trace with an observation in a
/// dropped range is final Incomplete.
#[test]
fn journal_drop_ranges_come_from_the_table() {
    let mut driver = Driver::new(4, 2, 64);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.store(0, &publish(0, 1, 10));
    driver.drop_record(0); // Publish of trace 2.
    driver.store(0, &publish(128, 3, 30));
    driver.entry(0).lost_before = Some(1);
    driver.write(0);
    for (position, trace) in [(0, 1), (64, 2), (128, 3)] {
        driver.store(1, &poll(position, trace, 40 + trace));
    }
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, Some(129));
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    let losses = tool.losses(1).unwrap();
    assert_eq!(
        (losses.attempted, losses.lost_before, losses.ranges.len()),
        (3, Some(1), 1)
    );
    assert_eq!((losses.ranges[0].first, losses.ranges[0].last), (1, 1));
    // Journal loss, never mirror loss.
    assert!(losses.mirror_ranges.is_empty());
    let report = tool.report().unwrap();
    assert_eq!(answer(&report, 2), TraceAnswer::Final(Verdict::Incomplete));
}

/// A mirror overwrite during the tool's life is mirror loss (never journal
/// loss) and makes the traces it covers Incomplete; a trace older than the
/// attach horizon is out of scope, never a verdict.
#[test]
fn a_mirror_overwrite_is_incomplete_and_older_traces_are_out_of_scope() {
    let mut driver = Driver::new(4, 2, 8);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    // Before the attach: trace 1's Publish is overwritten, its poll kept.
    driver.store(0, &publish(0, 1, 10));
    driver.store(0, &publish(64, 2, 20));
    driver.store(1, &poll(0, 1, 15));
    driver.store(1, &poll(64, 2, 25));
    for (n, position) in (3..=7).zip((128..).step_by(64)) {
        driver.store(0, &publish(position, n, 10 * n));
    }
    let mut tool = MirrorTool::new(INSTANCE);
    let attach = driver.scan(&mut tool);
    assert_eq!(attach.overwritten, 1);
    // During the tool's life: polls of traces 3 to 7, then fillers, more
    // than the ring holds before the next scan.
    for (n, position) in (3..=7).zip((128..).step_by(64)) {
        driver.store(1, &poll(position, n, 10 * n + 5));
    }
    for (n, position) in (8..=12).zip((448..).step_by(64)) {
        driver.store(0, &publish(position, n, 10 * n));
        driver.store(1, &poll(position, n, 10 * n + 5));
    }
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, Some(1000));
    let scan = driver.scan(&mut tool);
    assert!(scan.overwritten > 0);
    assert_eq!(tool.overwritten(), scan.overwritten);
    let losses = tool.losses(2).unwrap();
    assert!(losses.ranges.is_empty(), "no journal loss");
    assert!(!losses.mirror_ranges.is_empty());
    assert!(tool.mirror_lost() > 0);
    let report = tool.report().unwrap();
    // Trace 1's Publish was below the publisher journal's horizon.
    assert_eq!(answer(&report, 1), TraceAnswer::OutOfScope);
    // Trace 3's poll was overwritten during the tool's life.
    assert_eq!(answer(&report, 3), TraceAnswer::Final(Verdict::Incomplete));
    for trace in 2..=12 {
        assert_ne!(
            answer(&report, trace),
            TraceAnswer::Final(Verdict::Complete),
            "trace {trace}"
        );
    }
}

/// A journal whose records were all overwritten before the attach starts
/// at its attempted count: what it mirrors later is read from there, and
/// the messages it could have observed before are out of scope.
#[test]
fn a_journal_overwritten_before_the_attach_starts_at_its_attempted_count() {
    let mut driver = Driver::new(4, 2, 4);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.open(2, 3, JournalKind::Publisher, OTHER);
    driver.store(1, &poll(0, 1, 15));
    for n in 0..4 {
        driver.store(2, &observation(OTHER, Point::Publish, 64 * n, 50 + n, n));
    }
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    driver.store(0, &publish(0, 1, 10));
    driver.store(0, &publish(64, 2, 20));
    driver.store(1, &poll(64, 2, 25));
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, Some(65));
    driver.end(2, JournalState::Closed, None);
    let _ = driver.scan(&mut tool);
    let report = tool.report().unwrap();
    // The poll of trace 1 lay below the subscriber journal's horizon.
    assert_eq!(answer(&report, 1), TraceAnswer::OutOfScope);
    assert_eq!(answer(&report, 2), TraceAnswer::Final(Verdict::Complete));
}

/// A subscriber journal whose every record was overwritten still makes
/// the traces it was expected in Incomplete: membership comes from its
/// entry.
#[test]
fn a_subscriber_journal_with_every_record_overwritten_still_counts() {
    let mut driver = Driver::new(4, 2, 4);
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.open(2, 3, JournalKind::Publisher, OTHER);
    driver.store(1, &poll(0, 1, 15));
    driver.end(1, JournalState::Closed, Some(1));
    // Another publication's records push the poll out of the ring, then
    // the Publish is mirrored and retained.
    for n in 0..4 {
        driver.store(2, &observation(OTHER, Point::Publish, 64 * n, 50 + n, n));
    }
    driver.store(0, &publish(0, 1, 10));
    driver.end(0, JournalState::Closed, None);
    driver.end(2, JournalState::Closed, None);
    let _ = driver.scan(&mut tool);
    assert_eq!(tool.losses(2).unwrap().mirror_ranges, [(0, 0)]);
    let report = tool.report().unwrap();
    assert_eq!(answer(&report, 1), TraceAnswer::Final(Verdict::Incomplete));
}

/// A journal whose records contradict its entry (another publication,
/// another lane, or a point of the other kind) is malformed: treated as writer lost, its
/// traces are Incomplete and it stays in their expected sets. A record that
/// differs only outside the publication key (the wire ids) still names
/// the entry's publication, as across a successor mapping, which keeps the
/// stream registration and the incarnation.
#[test]
fn a_contradicting_journal_is_malformed_and_its_traces_incomplete() {
    for (contradiction, malformed) in [
        (observation(OTHER, Point::SubscriberPoll, 0, 1, 15), true),
        (observation(PUBLICATION, Point::Publish, 0, 1, 15), true),
        (
            TraceRecord {
                lane: 1,
                ..observation(PUBLICATION, Point::SubscriberPoll, 0, 1, 15)
            },
            true,
        ),
        (
            observation(
                PublicationId {
                    stream_id: 77,
                    session_id: 9,
                    ..PUBLICATION
                },
                Point::SubscriberPoll,
                0,
                1,
                15,
            ),
            false,
        ),
    ] {
        let mut driver = Driver::new(4, 2, 64);
        driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
        driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
        driver.store(0, &publish(0, 1, 10));
        driver.store(1, &contradiction);
        driver.end(0, JournalState::Closed, None);
        driver.end(1, JournalState::Closed, Some(1));
        let mut tool = MirrorTool::new(INSTANCE);
        let _ = driver.scan(&mut tool);
        let report = tool.report().unwrap();
        if malformed {
            assert_eq!(tool.malformed(), [2]);
            assert_eq!(answer(&report, 1), TraceAnswer::Final(Verdict::Incomplete));
        } else {
            assert!(tool.malformed().is_empty());
            assert_eq!(answer(&report, 1), TraceAnswer::Final(Verdict::Complete));
        }
    }
}

/// Host clocks are calibrated only when both entries say the driver's
/// time namespace; another or an unknown namespace, or an opaque clock,
/// leaves the latency unavailable.
#[test]
fn clocks_in_different_time_namespaces_are_not_calibrated() {
    let host = ClockProvenance::HostMonotonic.word();
    for (namespace, provenance, available) in [
        (TimeNamespace::Same, host, true),
        (TimeNamespace::Different, host, false),
        (TimeNamespace::Unknown, host, false),
        (TimeNamespace::Same, ClockProvenance::Opaque.word(), false),
        (TimeNamespace::Same, 99, false),
    ] {
        let mut driver = Driver::new(4, 2, 64);
        driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
        driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
        driver.entry(1).time_namespace = namespace;
        driver.entry(1).provenance = provenance;
        driver.write(1);
        driver.store(0, &publish(0, 1, 1_000));
        driver.store(1, &poll(0, 1, 1_250));
        driver.end(0, JournalState::Closed, None);
        driver.end(1, JournalState::Closed, Some(1));
        let mut tool = MirrorTool::new(INSTANCE);
        let _ = driver.scan(&mut tool);
        let latencies = tool.report().unwrap().latencies().unwrap();
        assert_eq!(
            latencies[0].1.available(),
            u64::from(available),
            "{namespace:?} {provenance}"
        );
    }
}

/// A subscriber journal mirrored before a message's Publish, ended and
/// recycled while that Publish is retained, never lets the message be
/// Complete: a tool attaching after the recycle, and one that scanned
/// before the journal existed and next after its table life, both report
/// it out of scope, and keep doing so once the log entry is dropped.
#[test]
fn a_recycled_subscriber_journal_puts_its_messages_out_of_scope() {
    let mut driver = Driver::new(2, 2, 4);
    let mut following = MirrorTool::new(INSTANCE);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    let _ = driver.scan(&mut following);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.store(1, &poll(0, 1, 15));
    driver.end(1, JournalState::Closed, Some(1));
    // Fillers push the poll out of the ring; the Publish stays.
    for _ in 0..3 {
        driver.store(0, &publish(512, 9, 5));
    }
    driver.store(0, &publish(0, 1, 10));
    driver.end(0, JournalState::Closed, None);
    // The entry is reused for another publication's journal.
    driver.recycle(1, 0);
    driver.open(1, 3, JournalKind::Publisher, OTHER);
    driver.end(1, JournalState::Closed, None);

    let mut late = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut late);
    let _ = driver.scan(&mut following);
    for tool in [&late, &following] {
        let report = tool.report().unwrap();
        assert_eq!(answer(&report, 1), TraceAnswer::OutOfScope);
    }
    // Covered: the driver drops the log entry; the tool keeps its scope.
    assert!(driver.mirror.write_log(0, None));
    let _ = driver.scan(&mut following);
    let report = following.report().unwrap();
    assert_eq!(answer(&report, 1), TraceAnswer::OutOfScope);
}

/// A writer lost subscriber journal in the recycle log has no boundary:
/// every message of its publication is out of scope while the tool knows
/// the entry.
#[test]
fn a_writer_lost_log_entry_puts_its_whole_publication_out_of_scope() {
    let mut driver = Driver::new(2, 2, 8);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.end(1, JournalState::WriterLost, None);
    driver.recycle(1, 0);
    driver.store(0, &publish(1 << 20, 1, 10));
    driver.end(0, JournalState::Closed, None);
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    let report = tool.report().unwrap();
    assert_eq!(answer(&report, 1), TraceAnswer::OutOfScope);
}

/// A writer lost entry, and a closed subscriber entry without a boundary,
/// make the traces they could be expected in Incomplete (J3, J4).
#[test]
fn ended_entries_without_a_boundary_make_their_traces_incomplete() {
    for (state, boundary) in [
        (JournalState::WriterLost, None),
        (JournalState::WriterLost, Some(1)),
        (JournalState::Closed, None),
    ] {
        let mut driver = Driver::new(4, 2, 64);
        driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
        driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
        driver.store(0, &publish(0, 1, 10));
        driver.store(1, &poll(0, 1, 15));
        driver.end(0, JournalState::Closed, None);
        driver.end(1, state, boundary);
        let mut tool = MirrorTool::new(INSTANCE);
        let _ = driver.scan(&mut tool);
        let report = tool.report().unwrap();
        assert_eq!(
            answer(&report, 1),
            TraceAnswer::Final(Verdict::Incomplete),
            "{state:?} {boundary:?}"
        );
    }
}

/// An open journal keeps its traces provisional; a closed entry whose last
/// records were mirrored after the scan is not terminal until a scan reads
/// them.
#[test]
fn open_and_unscanned_journals_keep_traces_provisional() {
    let mut driver = Driver::new(4, 2, 64);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.store(0, &publish(0, 1, 10));
    driver.store(1, &poll(0, 1, 15));
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    assert_eq!(answer(&tool.report().unwrap(), 1), TraceAnswer::Provisional);
    // As if the closing entry were read after a scan that missed its last
    // record.
    let tracked = tool.journals.get_mut(&2).unwrap();
    tracked.entry.state = JournalState::Closed;
    tracked.entry.boundary = Some(1);
    tracked.entry.last_record = Some(tool.cursor);
    let state = tool.journals[&2].state(tool.cursor, None);
    assert_eq!(state, SourceState::Open);
    let state = tool.journals[&2].state(tool.cursor + 1, None);
    assert_eq!(state, SourceState::Closed { boundary: Some(1) });
}

#[test]
fn mirror_ranges_leave_out_the_journal_ranges_and_watermark() {
    let range = |first, last| DropRange {
        first,
        last,
        first_time: 0,
        last_time: 0,
        clock: 1,
        epoch: 1,
    };
    assert_eq!(mirror_ranges(&[(2, 10)], &[], None), [(2, 9)]);
    assert_eq!(
        mirror_ranges(&[(2, 10)], &[range(4, 5), range(8, 20)], Some(3)),
        [(3, 3), (6, 7)]
    );
    assert_eq!(mirror_ranges(&[(2, 4)], &[range(0, 9)], None), []);
    assert_eq!(mirror_ranges(&[(5, 5)], &[], None), []);
    assert_eq!(count(&[(3, 3), (6, 7)]), 3);
}

/// A message of trace `[trace, 1]` that is not its root: a child of span 1,
/// or with `parentless` a join without a parent edge.
fn non_root(position: u64, trace: u64, time: u64, parentless: bool) -> TraceRecord {
    let mut record = publish(position, trace, time);
    record.root = false;
    record.ids.span_id = 2;
    record.ids.parent_span_id = if parentless { 0 } else { 1 };
    record
}

/// T6: a trace whose root Publish lies below the attach horizon is out of
/// scope even though its later message was delivered in full. Negative
/// control (verified by disabling `require_roots`): Complete.
#[test]
fn a_trace_whose_root_is_below_the_horizon_is_out_of_scope() {
    let mut driver = Driver::new(4, 2, 2);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    // The root and its poll are overwritten before the attach; the child
    // and its poll are retained.
    driver.store(0, &publish(0, 1, 10));
    driver.store(1, &poll(0, 1, 15));
    driver.store(0, &non_root(64, 1, 20, false));
    driver.store(1, &poll(64, 1, 25));
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, Some(128));
    let mut tool = MirrorTool::new(INSTANCE);
    let attach = driver.scan(&mut tool);
    assert_eq!(attach.overwritten, 2);
    let report = tool.report().unwrap();
    assert_eq!(answer(&report, 1), TraceAnswer::OutOfScope);
}

/// T6: a parentless join (zero `parent_span_id`, no `root` flag) above the
/// horizon is not taken for the root, nor is a version 1 `Publish`; the
/// same trace with a root-flagged `Publish` is Complete.
#[test]
fn only_a_root_flagged_publish_counts_as_the_root() {
    let join = non_root(0, 1, 10, true);
    let mut v1 = words(&publish(0, 1, 10));
    v1[0] = v1[0] & !(0xFF | 1 << 56) | 1;
    assert!(!decode_record(&v1).unwrap().0.root);
    for (published, root) in [
        (words(&join), false),
        (v1, false),
        (words(&publish(0, 1, 10)), true),
    ] {
        let mut driver = Driver::new(4, 2, 64);
        driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
        driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
        driver.store_words(0, &published);
        driver.store(1, &poll(0, 1, 15));
        driver.end(0, JournalState::Closed, None);
        driver.end(1, JournalState::Closed, Some(1));
        let mut tool = MirrorTool::new(INSTANCE);
        let _ = driver.scan(&mut tool);
        let report = tool.report().unwrap();
        let expected = if root {
            TraceAnswer::Final(Verdict::Complete)
        } else {
            TraceAnswer::OutOfScope
        };
        assert_eq!(answer(&report, 1), expected, "root {root}");
    }
}

/// T7: a following tool holds a `Publish` while a subscriber journal
/// expected for it is created, ended and recycled between two scans, its
/// log entry dropped once covered: the gap in journal numbers puts the
/// message out of scope and is counted. Negative control (verified by not
/// declaring the missed messages out of scope): Complete.
#[test]
fn a_missed_journal_puts_the_held_messages_out_of_scope() {
    let mut driver = Driver::new(2, 1, 2);
    let mut tool = MirrorTool::new(INSTANCE);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    let _ = driver.scan(&mut tool);
    driver.store(0, &publish(0, 1, 10));
    let _ = driver.scan(&mut tool);
    assert_eq!(answer(&tool.report().unwrap(), 1), TraceAnswer::Provisional);
    // Between two scans: the subscriber journal polls the message, ends,
    // and its entry is reused while its record and the Publish leave the
    // ring; it is covered, so its log entry is dropped too.
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.store(1, &poll(0, 1, 15));
    driver.end(1, JournalState::Closed, Some(64));
    driver.recycle(1, 0);
    driver.open(1, 3, JournalKind::Publisher, OTHER);
    driver.store(1, &observation(OTHER, Point::Publish, 0, 50, 20));
    driver.store(1, &observation(OTHER, Point::Publish, 64, 51, 30));
    assert!(driver.mirror.write_log(0, None));
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, None);
    let scan = driver.scan(&mut tool);
    let report = tool.report().unwrap();
    assert_eq!(answer(&report, 1), TraceAnswer::OutOfScope);
    assert_eq!(scan.missed, 1);
    assert_eq!(tool.missed(), (1, 1));
    // A message the gap's scan delivered is held at the gap too: the missed
    // journal could have observed any publication.
    assert_eq!(answer(&report, 51), TraceAnswer::OutOfScope);
    // The scope stays narrowed at later scans.
    let _ = driver.scan(&mut tool);
    assert_eq!(answer(&tool.report().unwrap(), 1), TraceAnswer::OutOfScope);
    assert_eq!(tool.missed(), (1, 1));
}

/// T7: sequences at or below the high-water mark read at the first scan
/// are never gaps: a tool attaching to a driver whose table and log skip
/// sequences (journals recycled, covered, before the attach) puts nothing
/// out of scope, then or later.
#[test]
fn skipped_sequences_before_the_attach_are_not_missed_journals() {
    let mut driver = Driver::new(4, 2, 64);
    driver.unseen();
    driver.open(0, 4, JournalKind::Publisher, PUBLICATION);
    driver.unseen();
    driver.open(2, 6, JournalKind::Subscriber, OTHER);
    driver.end(2, JournalState::Closed, Some(0));
    driver.recycle(2, 0);
    driver.unseen();
    driver.open(1, 9, JournalKind::Subscriber, PUBLICATION);
    driver.unseen();
    driver.store(0, &publish(0, 1, 10));
    driver.store(1, &poll(0, 1, 15));
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, Some(1));
    assert_eq!(driver.mirror.reader().assigned_sequence(), 7);
    let mut tool = MirrorTool::new(INSTANCE);
    assert_eq!(driver.scan(&mut tool).missed, 0);
    assert_eq!(driver.scan(&mut tool).missed, 0);
    assert_eq!(tool.missed(), (0, 0));
    assert_eq!(
        answer(&tool.report().unwrap(), 1),
        TraceAnswer::Final(Verdict::Complete)
    );
}

/// T7 (REVIEWER-02, #149): the newest journal, a subscriber journal
/// expected for a held `Publish`, is created, ended, covered and recycled
/// without a log entry between two scans, and nothing newer exists. The
/// table and the log show nothing above the previous scan's mark; the
/// header's high-water mark still reveals the missed sequence, so the
/// message is out of scope, never Complete. Negative control (verified by
/// counting gaps only up to the highest sequence shown): Complete.
#[test]
fn the_newest_missed_journal_is_counted_from_the_header() {
    let mut driver = Driver::new(2, 1, 2);
    let mut tool = MirrorTool::new(INSTANCE);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.store(0, &publish(0, 1, 10));
    let _ = driver.scan(&mut tool);
    assert_eq!(answer(&tool.report().unwrap(), 1), TraceAnswer::Provisional);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.store(1, &poll(0, 1, 15));
    driver.end(1, JournalState::Closed, Some(64));
    // Covered: later messages push the poll and the Publish out of the
    // ring, and the entry is freed without a log entry.
    driver.store(0, &publish(1 << 20, 60, 20));
    driver.store(0, &publish((1 << 20) + 64, 61, 30));
    driver.end(0, JournalState::Closed, None);
    driver.entries[1] = None;
    driver.write(1);
    let scan = driver.scan(&mut tool);
    assert_eq!(answer(&tool.report().unwrap(), 1), TraceAnswer::OutOfScope);
    assert_eq!(scan.missed, 1);
    assert_eq!(tool.missed(), (1, 1));
}

/// T7: a trace already final before the gap keeps its answer.
#[test]
fn a_final_answer_survives_a_missed_journal() {
    let mut driver = Driver::new(2, 1, 8);
    let mut tool = MirrorTool::new(INSTANCE);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.store(0, &publish(0, 1, 10));
    driver.end(0, JournalState::Closed, None);
    let _ = driver.scan(&mut tool);
    let _ = driver.scan(&mut tool);
    assert_eq!(
        answer(&tool.report().unwrap(), 1),
        TraceAnswer::Final(Verdict::Complete)
    );
    // A journal lives and goes between two scans unseen.
    driver.unseen();
    driver.open(1, 3, JournalKind::Publisher, OTHER);
    driver.end(1, JournalState::Closed, None);
    let scan = driver.scan(&mut tool);
    assert_eq!(scan.missed, 1);
    assert_eq!(
        answer(&tool.report().unwrap(), 1),
        TraceAnswer::Final(Verdict::Complete)
    );
}

/// From the first refused network journal on, no trace is reported a
/// final Complete, also one published after the refusal, which never
/// expected the journal that was never created (ACS 15805).
#[test]
fn complete_is_withheld_after_a_refusal() {
    let mut driver = Driver::new(4, 2, 64);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    assert!(driver.mirror.refuse_network_journal());
    let _ = driver.scan(&mut tool);
    // Published and polled after the refusal.
    driver.store(0, &publish(0, 3, 1_000));
    driver.store(1, &poll(0, 3, 1_400));
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, Some(1));
    let _ = driver.scan(&mut tool);
    let report = tool.report().unwrap();
    assert_eq!(answer(&report, 3), TraceAnswer::OutOfScope);
    assert_eq!(report.withheld_complete(), Some((1, 1)));
    // Without a refusal the same trace is Complete.
    let mut driver = Driver::new(4, 2, 64);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    driver.store(0, &publish(0, 3, 1_000));
    driver.store(1, &poll(0, 3, 1_400));
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, Some(1));
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    let report = tool.report().unwrap();
    assert_eq!(answer(&report, 3), TraceAnswer::Final(Verdict::Complete));
    assert_eq!(report.withheld_complete(), None);
}

/// A network entry's start comes from word 72: a receiver journal whose
/// image joined after the message is not expected for it.
#[test]
fn a_network_journal_is_expected_from_its_start() {
    for (start, expected) in [
        (128, TraceAnswer::Final(Verdict::Complete)),
        (0, TraceAnswer::Final(Verdict::Incomplete)),
    ] {
        let mut driver = Driver::new(4, 2, 64);
        driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
        driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
        network_entry(&mut driver, 2, 3, JournalKind::NetworkReceiver, start);
        driver.store(0, &publish(0, 1, 1_000));
        driver.store(1, &poll(0, 1, 1_400));
        driver.end(0, JournalState::Closed, None);
        driver.end(1, JournalState::Closed, Some(1));
        end_network(&mut driver, 2, Some(1 << 20));
        let mut tool = MirrorTool::new(INSTANCE);
        let _ = driver.scan(&mut tool);
        assert_eq!(
            answer(&tool.report().unwrap(), 1),
            expected,
            "start {start}"
        );
    }
}

/// A network entry's lane comes from word 69: on lane 1, with messages on
/// lane 1, a journal closed without the message makes it Incomplete.
#[test]
fn a_network_journal_observes_its_lane() {
    let on_lane = |record: TraceRecord| TraceRecord { lane: 1, ..record };
    let mut driver = Driver::new(4, 2, 64);
    driver.open(0, 1, JournalKind::Publisher, PUBLICATION);
    driver.open(1, 2, JournalKind::Subscriber, PUBLICATION);
    network_entry(&mut driver, 2, 3, JournalKind::NetworkSender, 0);
    for index in 0..3 {
        driver.entry(index).lane = karyos_sys::frame::Lane::try_new(1).unwrap();
        driver.write(index);
    }
    driver.store(0, &on_lane(publish(0, 1, 1_000)));
    driver.store(1, &on_lane(poll(0, 1, 1_400)));
    driver.end(0, JournalState::Closed, None);
    driver.end(1, JournalState::Closed, Some(1));
    end_network(&mut driver, 2, Some(1 << 20));
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    assert_eq!(
        answer(&tool.report().unwrap(), 1),
        TraceAnswer::Final(Verdict::Incomplete)
    );
}

/// A receiver journal of a remote publication names it by its sender's
/// driver (word 70 and 71), not this one: its records do not contradict
/// the entry (`trace-network.md` §8).
#[test]
fn a_remote_receiver_journal_names_its_sender_driver() {
    let remote = PublicationId {
        driver: [9, 9],
        ..PUBLICATION
    };
    let mut driver = Driver::new(4, 2, 64);
    network_entry(&mut driver, 0, 3, JournalKind::NetworkReceiver, 0);
    let entry = driver.entry(0);
    entry.network = Some(NetworkFacts {
        sender_driver: remote.driver,
        ..entry.network.unwrap()
    });
    driver.write(0);
    driver.store(
        0,
        &TraceRecord {
            network: Some(karyos_trace::NetworkPath {
                path: 0,
                attempt: 0,
            }),
            ..observation(remote, Point::ReceiverCommit, 0, 1, 1_000)
        },
    );
    end_network(&mut driver, 0, Some(1 << 20));
    let mut tool = MirrorTool::new(INSTANCE);
    let _ = driver.scan(&mut tool);
    assert!(tool.malformed().is_empty(), "{:?}", tool.malformed());
    let _ = tool.report().unwrap();
}
