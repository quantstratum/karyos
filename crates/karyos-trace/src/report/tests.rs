// SPDX-License-Identifier: Apache-2.0

// The report (`quantstratum-docs: karyos/design/trace-data-path.md`,
// "Tests"), over real agents and journals.

use karyos_protocol::frame::{Lane, TraceExtension};
use karyos_protocol::trace_hook::{
    Committed, Delivered, PublicationIdentity, PublishContext, SubscriberIdentity, TraceHook,
};

use super::*;
use crate::agent::TraceAgent;
use crate::clocks::Unavailable;
use crate::error::TraceError;
use crate::ids::{BufferedIds, OsRandom};
use crate::journal::trace_journal;
use crate::record::ObservedTime;
use crate::sampling::Sampling;
use crate::trace_clock::{ClockProvenance, MonotonicClock, TraceClock};

const IDENTITY: PublicationIdentity = PublicationIdentity {
    driver: [1, 2],
    registration: 3,
    stream_id: 10,
    session_id: 1,
    incarnation: 1,
};

const IDENTITY_B: PublicationIdentity = PublicationIdentity {
    driver: [1, 2],
    registration: 4,
    stream_id: 11,
    session_id: 2,
    incarnation: 1,
};

const ATTRIBUTION: AttributionConfig = AttributionConfig {
    span: u64::MAX,
    max_traces: 64,
    max_intervals: 16,
};

const HISTOGRAM: HistogramConfig = HistogramConfig {
    digits: 2,
    highest: 1 << 40,
    unit: 1,
};

/// An application clock: opaque, fixed times.
struct Fixed(u64);

impl TraceClock for Fixed {
    fn now(&mut self) -> ObservedTime {
        ObservedTime {
            time: 1000,
            clock: self.0,
            epoch: 1,
            uncertainty: 1,
        }
    }
}

type Agent<C> = TraceAgent<OsRandom, C>;

fn agent<C: TraceClock>(
    report: &mut TraceReport,
    number: u64,
    capacity: usize,
    clock: C,
    domain: u64,
    subscriber_join: Option<u64>,
) -> (Agent<C>, JournalId) {
    ranged_agent(report, number, capacity, 4, clock, domain, subscriber_join)
}

/// An agent whose journal keeps `drop_ranges` drop-range entries.
fn ranged_agent<C: TraceClock>(
    report: &mut TraceReport,
    number: u64,
    capacity: usize,
    drop_ranges: usize,
    clock: C,
    domain: u64,
    subscriber_join: Option<u64>,
) -> (Agent<C>, JournalId) {
    let observer = ObserverId {
        driver: IDENTITY.driver,
        journal: number,
    };
    let (writer, collector) = trace_journal(capacity, drop_ranges, observer, domain).unwrap();
    let provenance = clock.provenance();
    let ids = BufferedIds::new(64, OsRandom).unwrap();
    let agent = TraceAgent::new(Sampling::All, ids, clock, writer);
    let publication = PublicationId::from(IDENTITY);
    let id = match subscriber_join {
        None => report.add_publisher(collector, provenance, publication),
        Some(join) => report.add_subscriber(collector, provenance, publication, Lane::ZERO, join),
    }
    .unwrap();
    (agent, id)
}

fn std_agent(
    report: &mut TraceReport,
    number: u64,
    capacity: usize,
    join: Option<u64>,
) -> (Agent<MonotonicClock>, JournalId) {
    agent(
        report,
        number,
        capacity,
        MonotonicClock::new(number),
        number,
        join,
    )
}

fn publish<C: TraceClock>(agent: &mut Agent<C>, position: u64) -> TraceExtension {
    let ext = agent
        .on_publish(
            None,
            &PublishContext {
                publication: IDENTITY,
                lane: Lane::ZERO,
            },
        )
        .unwrap();
    agent.on_committed(
        &ext,
        &Committed {
            publication: IDENTITY,
            lane: Lane::ZERO,
            position,
        },
    );
    ext
}

fn deliver<C: TraceClock>(
    agent: &mut Agent<C>,
    ext: &TraceExtension,
    registration: u64,
    position: u64,
) {
    agent.on_delivered(
        ext,
        &Delivered {
            publication: IDENTITY,
            subscriber: SubscriberIdentity {
                driver: IDENTITY.driver,
                registration,
                incarnation: 1,
            },
            lane: Lane::ZERO,
            position,
        },
    );
}

#[test]
fn test_trace_publish_and_poll_records_match() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher, _) = std_agent(&mut report, 1, 8, None);
    let (mut subscriber, _) = std_agent(&mut report, 2, 8, Some(0));
    let ext = publish(&mut publisher, 64);
    deliver(&mut subscriber, &ext, 9, 64);
    report.drain().unwrap();
    let latencies = report.latencies().unwrap();
    let [(publication, histogram)] = &latencies[..] else {
        panic!("one publication");
    };
    assert_eq!(*publication, PublicationId::from(IDENTITY));
    // Both standard clocks of this process: calibrated automatically.
    assert_eq!(histogram.available(), 1);
}

#[test]
fn test_trace_custom_clock_gets_no_automatic_calibration() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher, _) = std_agent(&mut report, 1, 8, None);
    let (mut subscriber, _) = agent(&mut report, 2, 8, Fixed(2), 2, Some(0));
    let ext = publish(&mut publisher, 64);
    deliver(&mut subscriber, &ext, 9, 64);
    report.drain().unwrap();
    let latencies = report.latencies().unwrap();
    let [(_, histogram)] = &latencies[..] else {
        panic!("one publication");
    };
    assert_eq!(histogram.available(), 0);
    assert_eq!(histogram.unavailable(Unavailable::NoCalibration), 1);
}

#[test]
fn test_trace_report_open_journal_is_provisional() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher, pub_id) = std_agent(&mut report, 1, 8, None);
    let (mut subscriber, sub_id) = std_agent(&mut report, 2, 8, Some(0));
    let ext = publish(&mut publisher, 64);
    deliver(&mut subscriber, &ext, 9, 64);
    report.drain().unwrap();
    // Every journal drained, the subscription still open: provisional.
    assert_eq!(report.trace(ext.trace_id), TraceAnswer::Provisional);
    publisher.close();
    report.closed(pub_id, None);
    report.drain().unwrap();
    assert_eq!(report.trace(ext.trace_id), TraceAnswer::Provisional);
    subscriber.close();
    report.closed(sub_id, Some(65));
    report.drain().unwrap();
    assert_eq!(
        report.trace(ext.trace_id),
        TraceAnswer::Final(Verdict::Complete)
    );
    assert_eq!(report.trace([9, 9]), TraceAnswer::Unknown);
}

#[test]
fn test_trace_report_missing_expected_journal_is_incomplete() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher, pub_id) = std_agent(&mut report, 1, 8, None);
    let (mut subscriber, sub_id) = std_agent(&mut report, 2, 8, Some(0));
    let ext = publish(&mut publisher, 64);
    // The subscription attempted the message (boundary passed it) but
    // never recorded it.
    publisher.close();
    subscriber.close();
    report.closed(pub_id, None);
    report.closed(sub_id, Some(65));
    report.drain().unwrap();
    assert_eq!(
        report.trace(ext.trace_id),
        TraceAnswer::Final(Verdict::Incomplete)
    );
}

#[test]
fn test_trace_late_subscriber_not_expected_for_earlier_claim() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher, pub_id) = std_agent(&mut report, 1, 8, None);
    // A claim reserved [64, 128); the subscription joined at 128.
    let (mut late, late_id) = std_agent(&mut report, 2, 8, Some(128));
    let ext = publish(&mut publisher, 64);
    publisher.close();
    late.close();
    report.closed(pub_id, None);
    report.closed(late_id, Some(0));
    report.drain().unwrap();
    assert_eq!(
        report.trace(ext.trace_id),
        TraceAnswer::Final(Verdict::Complete)
    );
}

#[test]
fn test_trace_subscriber_closed_before_the_message_is_not_expected() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher, pub_id) = std_agent(&mut report, 1, 8, None);
    let (mut early, early_id) = std_agent(&mut report, 2, 8, Some(0));
    let ext = publish(&mut publisher, 64);
    publisher.close();
    early.close();
    report.closed(pub_id, None);
    // Closed having attempted nothing at or after 64.
    report.closed(early_id, Some(64));
    report.drain().unwrap();
    assert_eq!(
        report.trace(ext.trace_id),
        TraceAnswer::Final(Verdict::Complete)
    );
}

#[test]
fn test_trace_lost_poll_record_with_panic_and_drop_is_incomplete() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher, pub_id) = std_agent(&mut report, 1, 8, None);
    // A one-record journal: its second record is dropped.
    let (mut subscriber, sub_id) = std_agent(&mut report, 2, 1, Some(0));
    let first = publish(&mut publisher, 0);
    let second = publish(&mut publisher, 64);
    deliver(&mut subscriber, &first, 9, 0);
    deliver(&mut subscriber, &second, 9, 64);
    assert_eq!(subscriber.counts().dropped, 1);
    // The handler panicked and the subscription was dropped without a
    // redelivery: its boundary passed 64 all the same.
    publisher.close();
    subscriber.close();
    report.closed(pub_id, None);
    report.closed(sub_id, Some(65));
    report.drain().unwrap();
    assert_eq!(
        report.trace(second.trace_id),
        TraceAnswer::Final(Verdict::Incomplete)
    );
}

#[test]
fn test_trace_missing_publish_record_is_incomplete() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher, pub_id) = std_agent(&mut report, 1, 1, None);
    let (mut subscriber, sub_id) = std_agent(&mut report, 2, 8, Some(0));
    let first = publish(&mut publisher, 0);
    let second = publish(&mut publisher, 64);
    assert_eq!(publisher.counts().dropped, 1);
    deliver(&mut subscriber, &first, 9, 0);
    deliver(&mut subscriber, &second, 9, 64);
    publisher.close();
    subscriber.close();
    report.closed(pub_id, None);
    report.closed(sub_id, Some(65));
    report.drain().unwrap();
    assert_eq!(
        report.trace(second.trace_id),
        TraceAnswer::Final(Verdict::Incomplete)
    );
}

/// Two messages of one trace, a subscription eligible for both that
/// recorded only the first: Incomplete, though the journal holds the trace
/// (review finding on #93).
#[test]
fn test_trace_each_message_needs_its_own_poll_record() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher, pub_id) = std_agent(&mut report, 1, 8, None);
    let (mut subscriber, sub_id) = std_agent(&mut report, 2, 8, Some(0));
    let root = publish(&mut publisher, 64);
    // A child in the same trace, at 128.
    let child = publisher
        .on_publish(
            Some(&root),
            &PublishContext {
                publication: IDENTITY,
                lane: Lane::ZERO,
            },
        )
        .unwrap();
    assert_eq!(child.trace_id, root.trace_id);
    publisher.on_committed(
        &child,
        &Committed {
            publication: IDENTITY,
            lane: Lane::ZERO,
            position: 128,
        },
    );
    deliver(&mut subscriber, &root, 9, 64);
    publisher.close();
    subscriber.close();
    report.closed(pub_id, None);
    report.closed(sub_id, Some(192));
    report.drain().unwrap();
    assert_eq!(
        report.trace(root.trace_id),
        TraceAnswer::Final(Verdict::Incomplete)
    );
}

/// A trace stays provisional while any registered journal is open: an open
/// publisher can still add a child to it after its root's journals closed
/// (review finding on #93; coordinator decision ACS 12662).
#[test]
fn test_trace_an_open_publisher_keeps_the_answer_provisional() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher_a, a_id) = std_agent(&mut report, 1, 8, None);
    let (mut subscriber_a, sub_a_id) = std_agent(&mut report, 2, 8, Some(0));
    // Publication B and its subscription, registered from the start.
    let observer = |journal| ObserverId {
        driver: IDENTITY.driver,
        journal,
    };
    let (writer_b, collector_b) = trace_journal(8, 4, observer(3), 3).unwrap();
    let mut publisher_b = TraceAgent::new(
        Sampling::All,
        BufferedIds::new(64, OsRandom).unwrap(),
        MonotonicClock::new(3),
        writer_b,
    );
    let b_id = report
        .add_publisher(
            collector_b,
            ClockProvenance::StdMonotonic,
            PublicationId::from(IDENTITY_B),
        )
        .unwrap();
    let (writer_sb, collector_sb) = trace_journal(8, 4, observer(4), 4).unwrap();
    let sub_b_id = report
        .add_subscriber(
            collector_sb,
            ClockProvenance::StdMonotonic,
            PublicationId::from(IDENTITY_B),
            Lane::ZERO,
            0,
        )
        .unwrap();
    let root = publish(&mut publisher_a, 64);
    deliver(&mut subscriber_a, &root, 9, 64);
    publisher_a.close();
    subscriber_a.close();
    report.closed(a_id, None);
    report.closed(sub_a_id, Some(65));
    report.drain().unwrap();
    // A's journals are closed and complete, but B is open: not final.
    assert_eq!(report.trace(root.trace_id), TraceAnswer::Provisional);
    // B publishes a child of the root; its subscriber never records it.
    let child = publisher_b
        .on_publish(
            Some(&root),
            &PublishContext {
                publication: IDENTITY_B,
                lane: Lane::ZERO,
            },
        )
        .unwrap();
    publisher_b.on_committed(
        &child,
        &Committed {
            publication: IDENTITY_B,
            lane: Lane::ZERO,
            position: 0,
        },
    );
    report.drain().unwrap();
    assert_eq!(report.trace(root.trace_id), TraceAnswer::Provisional);
    publisher_b.close();
    drop(writer_sb);
    report.closed(b_id, None);
    report.closed(sub_b_id, Some(1));
    report.drain().unwrap();
    assert_eq!(
        report.trace(root.trace_id),
        TraceAnswer::Final(Verdict::Incomplete)
    );
}

/// Once the report gave a final answer, no journal can be added: the set it
/// answered for stays frozen (coordinator decision ACS 12667). An early
/// Incomplete freezes it too.
#[test]
fn test_trace_registration_after_a_final_answer_is_refused() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    let (mut publisher, pub_id) = std_agent(&mut report, 1, 8, None);
    let (mut subscriber, sub_id) = std_agent(&mut report, 2, 8, Some(0));
    let ext = publish(&mut publisher, 64);
    deliver(&mut subscriber, &ext, 9, 64);
    report.drain().unwrap();
    // Provisional answers do not freeze.
    assert_eq!(report.trace(ext.trace_id), TraceAnswer::Provisional);
    let (mut late, late_id) = std_agent(&mut report, 3, 8, Some(0));
    publisher.close();
    subscriber.close();
    late.close();
    report.closed(pub_id, None);
    report.closed(sub_id, Some(65));
    report.closed(late_id, Some(0));
    report.drain().unwrap();
    assert_eq!(
        report.trace(ext.trace_id),
        TraceAnswer::Final(Verdict::Complete)
    );
    let (_writer, collector) = trace_journal(
        8,
        4,
        ObserverId {
            driver: IDENTITY.driver,
            journal: 4,
        },
        4,
    )
    .unwrap();
    assert!(matches!(
        report.add_subscriber(
            collector,
            ClockProvenance::StdMonotonic,
            PublicationId::from(IDENTITY),
            Lane::ZERO,
            0
        ),
        Err(TraceError::MembershipFrozen)
    ));
    // The answer is unchanged.
    assert_eq!(
        report.trace(ext.trace_id),
        TraceAnswer::Final(Verdict::Complete)
    );
}

/// A source over records held in memory, as a tool's would be.
#[derive(Debug)]
struct Recorded {
    observer: ObserverId,
    start: u64,
    items: std::collections::VecDeque<Collected>,
    attempted: u64,
    state: crate::source::SourceState,
}

impl crate::source::JournalSource for Recorded {
    fn observer(&self) -> ObserverId {
        self.observer
    }

    fn start(&self) -> u64 {
        self.start
    }

    fn take(&mut self) -> Collected {
        match self.items.pop_front() {
            Some(item) => item,
            None if self.state == crate::source::SourceState::Open => Collected::Empty,
            None => Collected::Closed,
        }
    }

    fn losses(&mut self) -> crate::source::SourceLosses {
        crate::source::SourceLosses {
            attempted: self.attempted,
            stored: 0,
            ..Default::default()
        }
    }

    fn state(&self) -> crate::source::SourceState {
        self.state
    }
}

/// `point` of message `position` in trace `trace`, at host time `time`.
fn observation(point: Point, position: u64, trace: u64, time: u64) -> crate::record::TraceRecord {
    crate::record::TraceRecord {
        point,
        publication: PublicationId::from(IDENTITY),
        lane: 0,
        position,
        ids: crate::record::TraceIds {
            trace_id: [trace, 1],
            span_id: 1,
            parent_span_id: 0,
            message_id: position,
        },
        observed: ObservedTime {
            time,
            clock: 1,
            epoch: crate::trace_clock::HostMonotonicClock::EPOCH,
            uncertainty: 10,
        },
        subscriber: (point == Point::SubscriberPoll).then_some(crate::record::SubscriberId {
            driver: IDENTITY.driver,
            registration: 9,
            incarnation: 1,
        }),
        packet: None,
        network: None,
        root: point == Point::Publish,
    }
}

/// A closed source of `records` from sequence `start` on, without gaps.
fn recorded(
    journal: u64,
    start: u64,
    records: &[crate::record::TraceRecord],
    state: crate::source::SourceState,
) -> Recorded {
    let items = records
        .iter()
        .zip(start..)
        .map(|(record, sequence)| Collected::Record {
            sequence,
            gap: None,
            record: *record,
            collected: karyos_protocol::journal::Stamp {
                time: record.observed.time,
                clock: record.observed.clock,
                epoch: record.observed.epoch,
            },
        })
        .collect();
    Recorded {
        observer: ObserverId {
            driver: IDENTITY.driver,
            journal,
        },
        start,
        items,
        attempted: start + records.len() as u64,
        state,
    }
}

fn host(driver_time_namespace: bool) -> JournalClock {
    JournalClock {
        provenance: ClockProvenance::HostMonotonic,
        driver_time_namespace,
    }
}

const CLOSED: crate::source::SourceState = crate::source::SourceState::Closed { boundary: None };

fn closed_at(boundary: u64) -> crate::source::SourceState {
    crate::source::SourceState::Closed {
        boundary: Some(boundary),
    }
}

/// Two host clocks of different journals (processes) in the driver's time
/// namespace are calibrated with zero offset; one outside it, or an opaque
/// clock, is not (T2).
#[test]
fn host_clocks_calibrate_only_within_the_driver_time_namespace() {
    let key = PublicationKey::from(PublicationId::from(IDENTITY));
    for (publisher, subscriber, available) in [
        (host(true), host(true), true),
        (host(true), host(false), false),
        (host(false), host(false), false),
        (ClockProvenance::Opaque.into(), host(true), false),
    ] {
        let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
        let publish = observation(Point::Publish, 64, 1, 1_000);
        let poll = observation(Point::SubscriberPoll, 64, 1, 1_500);
        report
            .add_publisher_source(recorded(1, 0, &[publish], CLOSED), publisher, key)
            .unwrap();
        report
            .add_subscriber_source(
                recorded(2, 0, &[poll], closed_at(65)),
                subscriber,
                key,
                Lane::ZERO,
                0,
            )
            .unwrap();
        report.drain().unwrap();
        assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
        let latencies = report.latencies().unwrap();
        let [(_, histogram)] = &latencies[..] else {
            panic!("one publication");
        };
        if available {
            assert_eq!(histogram.available(), 1);
            // 500 ns, widened by both observations' and both resolutions'
            // uncertainty, never narrower.
            match histogram.quantile(1, 2).unwrap() {
                crate::histogram::Quantile::Interval {
                    low: Some(low),
                    high: Some(high),
                } => assert!(low <= 500 && high >= 500, "{low} {high}"),
                other => panic!("{other:?}"),
            }
        } else {
            assert_eq!(histogram.unavailable(Unavailable::NoCalibration), 1);
        }
    }
}

/// A lost subscriber journal (writer gone without a boundary, or
/// malformed) is expected for every message from its join on and makes
/// those traces final Incomplete, with or without records; a lost
/// publisher journal makes a message without its Publish Incomplete.
#[test]
fn a_lost_journal_makes_its_traces_incomplete() {
    let key = PublicationKey::from(PublicationId::from(IDENTITY));
    let lost = crate::source::SourceState::Lost;
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    report
        .add_publisher_source(
            recorded(1, 0, &[observation(Point::Publish, 64, 1, 10)], CLOSED),
            host(true),
            key,
        )
        .unwrap();
    report
        .add_subscriber_source(recorded(2, 0, &[], lost), host(true), key, Lane::ZERO, 0)
        .unwrap();
    report.drain().unwrap();
    assert_eq!(
        report.trace([1, 1]),
        TraceAnswer::Final(Verdict::Incomplete)
    );

    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    report
        .add_publisher_source(recorded(1, 0, &[], lost), host(true), key)
        .unwrap();
    report
        .add_subscriber_source(
            recorded(
                2,
                0,
                &[observation(Point::SubscriberPoll, 64, 1, 20)],
                closed_at(65),
            ),
            host(true),
            key,
            Lane::ZERO,
            0,
        )
        .unwrap();
    report.drain().unwrap();
    assert_eq!(
        report.trace([1, 1]),
        TraceAnswer::Final(Verdict::Incomplete)
    );
}

/// A source that starts mid-journal (a tool's attach horizon): a message
/// below the first position it delivered whose observation it lacks is out
/// of scope; one at or after it gets a verdict, read as a journal that
/// begins at the start.
#[test]
fn observations_below_a_source_start_are_out_of_scope() {
    let key = PublicationKey::from(PublicationId::from(IDENTITY));
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    // The publisher journal read from its start: Publish of 0, 64, 128.
    report
        .add_publisher_source(
            recorded(
                1,
                0,
                &[
                    observation(Point::Publish, 0, 1, 10),
                    observation(Point::Publish, 64, 2, 20),
                    observation(Point::Publish, 128, 3, 30),
                ],
                CLOSED,
            ),
            host(true),
            key,
        )
        .unwrap();
    // The subscriber journal read from sequence 5 on: its polls of 0 and
    // 64 were below its start; 128 is the first it delivered.
    report
        .add_subscriber_source(
            recorded(
                2,
                5,
                &[observation(Point::SubscriberPoll, 128, 3, 40)],
                closed_at(192),
            ),
            host(true),
            key,
            Lane::ZERO,
            0,
        )
        .unwrap();
    report.drain().unwrap();
    assert_eq!(report.trace([1, 1]), TraceAnswer::OutOfScope);
    assert_eq!(report.trace([2, 1]), TraceAnswer::OutOfScope);
    assert_eq!(report.trace([3, 1]), TraceAnswer::Final(Verdict::Complete));
    let [summary] = &report.summary()[..] else {
        panic!("one publication");
    };
    assert_eq!(
        (
            summary.messages,
            summary.complete,
            summary.incomplete,
            summary.provisional,
            summary.out_of_scope
        ),
        (3, 1, 0, 0, 2)
    );
}

/// Declared ranges of a publication are out of scope, every message for
/// `None` (a tool's recycle log, T5); other publications are not.
#[test]
fn declared_publication_ranges_are_out_of_scope() {
    let key = PublicationKey::from(PublicationId::from(IDENTITY));
    let build = |through: Option<u64>| {
        let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
        report
            .add_publisher_source(
                recorded(
                    1,
                    0,
                    &[
                        observation(Point::Publish, 0, 1, 10),
                        observation(Point::Publish, 64, 2, 20),
                    ],
                    CLOSED,
                ),
                host(true),
                key,
            )
            .unwrap();
        report.out_of_scope(key, None, through);
        report.out_of_scope(
            PublicationKey::from(PublicationId::from(IDENTITY_B)),
            None,
            None,
        );
        report.drain().unwrap();
        report
    };
    let report = build(Some(32));
    assert_eq!(report.trace([1, 1]), TraceAnswer::OutOfScope);
    assert_eq!(report.trace([2, 1]), TraceAnswer::Final(Verdict::Complete));
    let report = build(None);
    assert_eq!(report.trace([2, 1]), TraceAnswer::OutOfScope);
}

/// karyos#185: a declaration that names a lane scopes only that lane's
/// messages: a recycled subscriber journal of lane 1 leaves lane 0's
/// message at the same position in scope; one with no lane scopes both.
#[test]
fn a_lane_scoped_declaration_leaves_other_lanes_in_scope() {
    let key = PublicationKey::from(PublicationId::from(IDENTITY));
    let build = |lane: Option<Lane>| {
        let mut other_lane = observation(Point::Publish, 0, 2, 20);
        other_lane.lane = 1;
        let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
        report
            .add_publisher_source(
                recorded(
                    1,
                    0,
                    &[observation(Point::Publish, 0, 1, 10), other_lane],
                    CLOSED,
                ),
                host(true),
                key,
            )
            .unwrap();
        report.out_of_scope(key, lane, Some(32));
        report.drain().unwrap();
        report
    };
    let report = build(Some(Lane::try_new(1).unwrap()));
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
    assert_eq!(report.trace([2, 1]), TraceAnswer::OutOfScope);
    let report = build(None);
    assert_eq!(report.trace([1, 1]), TraceAnswer::OutOfScope);
    assert_eq!(report.trace([2, 1]), TraceAnswer::OutOfScope);
}

/// A source that is still open keeps its traces provisional, and the
/// summary counts them so.
#[test]
fn an_open_source_keeps_its_traces_provisional() {
    let key = PublicationKey::from(PublicationId::from(IDENTITY));
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    report
        .add_publisher_source(
            recorded(1, 0, &[observation(Point::Publish, 0, 1, 10)], CLOSED),
            host(true),
            key,
        )
        .unwrap();
    report
        .add_subscriber_source(
            recorded(
                2,
                0,
                &[observation(Point::SubscriberPoll, 0, 1, 20)],
                crate::source::SourceState::Open,
            ),
            host(true),
            key,
            Lane::ZERO,
            0,
        )
        .unwrap();
    report.drain().unwrap();
    assert_eq!(report.trace([1, 1]), TraceAnswer::Provisional);
    assert_eq!(report.summary()[0].provisional, 1);
}

/// T6 in the report: with roots required, a trace that would be Complete
/// without a root-flagged Publish is out of scope, an Incomplete one stays
/// Incomplete; without the requirement (the in-process report, which has
/// no horizon) the answer is unchanged.
#[test]
fn required_roots_put_rootless_complete_traces_out_of_scope() {
    let key = PublicationKey::from(PublicationId::from(IDENTITY));
    let build = |required: bool, polled: bool| {
        let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
        let mut publish = observation(Point::Publish, 0, 1, 10);
        publish.root = false;
        report
            .add_publisher_source(recorded(1, 0, &[publish], CLOSED), host(true), key)
            .unwrap();
        let polls: &[crate::record::TraceRecord] = if polled {
            &[observation(Point::SubscriberPoll, 0, 1, 20)]
        } else {
            &[]
        };
        report
            .add_subscriber_source(
                recorded(2, 0, polls, closed_at(1)),
                host(true),
                key,
                Lane::ZERO,
                0,
            )
            .unwrap();
        if required {
            report.require_roots();
        }
        report.drain().unwrap();
        report.trace([1, 1])
    };
    assert_eq!(build(false, true), TraceAnswer::Final(Verdict::Complete));
    assert_eq!(build(true, true), TraceAnswer::OutOfScope);
    assert_eq!(build(true, false), TraceAnswer::Final(Verdict::Incomplete));
}

/// A message declared out of scope puts its trace out of scope.
#[test]
fn a_declared_message_is_out_of_scope() {
    let key = PublicationKey::from(PublicationId::from(IDENTITY));
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    report
        .add_publisher_source(
            recorded(
                1,
                0,
                &[
                    observation(Point::Publish, 0, 1, 10),
                    observation(Point::Publish, 64, 2, 20),
                ],
                CLOSED,
            ),
            host(true),
            key,
        )
        .unwrap();
    report.out_of_scope_message(key, 0, 64);
    report.drain().unwrap();
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
    assert_eq!(report.trace([2, 1]), TraceAnswer::OutOfScope);
    let held = report.messages();
    assert_eq!(held.len(), 2);
}

// Network journals (`quantstratum-docs: karyos/design/trace-network.md`
// §5 and §8, "Membership"): fragments joined to their messages by
// `message_id`, membership per message, parking, refusals.

use karyos_protocol::trace_hook::NetSide;

use crate::record::NetworkPath;

/// The fragment of message `message` (its BEGIN position and id) at frame
/// `frame`, observed at `point` on `path` at host time `time`.
fn fragment(
    point: Point,
    message: u64,
    frame: u64,
    trace: u64,
    time: u64,
    path: u32,
) -> crate::record::TraceRecord {
    crate::record::TraceRecord {
        position: frame,
        ids: crate::record::TraceIds {
            message_id: message,
            ..observation(point, message, trace, time).ids
        },
        subscriber: None,
        network: Some(NetworkPath { path, attempt: 0 }),
        root: false,
        ..observation(point, message, trace, time)
    }
}

fn key() -> PublicationKey {
    PublicationKey::from(PublicationId::from(IDENTITY))
}

/// A report over the publisher journal (Publish of `messages` in trace 1),
/// a subscriber journal that polled them, and the given network journals:
/// `(side, start, records, state)`, registered before the client journals
/// when `network_first`, so their fragments drain before any Publish.
fn network_report(
    attribution: AttributionConfig,
    messages: &[u64],
    network: Vec<(
        NetSide,
        Option<u64>,
        Vec<crate::record::TraceRecord>,
        crate::source::SourceState,
    )>,
    network_first: bool,
) -> TraceReport {
    let mut report = TraceReport::new(attribution, HISTOGRAM);
    let publishes: Vec<_> = messages
        .iter()
        .map(|position| observation(Point::Publish, *position, 1, 10))
        .collect();
    let polls: Vec<_> = messages
        .iter()
        .map(|position| observation(Point::SubscriberPoll, *position, 1, 90))
        .collect();
    let add_network = |report: &mut TraceReport| {
        for (index, (side, start, records, state)) in network.iter().enumerate() {
            report
                .add_network_source(
                    recorded(10 + index as u64, 0, records, *state),
                    host(true),
                    key(),
                    *side,
                    0,
                    *start,
                )
                .unwrap();
        }
    };
    if network_first {
        add_network(&mut report);
    }
    report
        .add_publisher_source(recorded(1, 0, &publishes, CLOSED), host(true), key())
        .unwrap();
    report
        .add_subscriber_source(
            recorded(2, 0, &polls, closed_at(1 << 20)),
            host(true),
            key(),
            Lane::ZERO,
            0,
        )
        .unwrap();
    if !network_first {
        add_network(&mut report);
    }
    report.drain().unwrap();
    report
}

/// Every fragment joins its message by `message_id`, whichever journal
/// drains first: a message of two fragments observed by the sender and the
/// receiver completes its trace, and no fragment becomes a message.
#[test]
fn network_fragments_join_their_message() {
    for network_first in [false, true] {
        let sender = vec![
            fragment(Point::SenderPickup, 64, 64, 1, 20, 0),
            fragment(Point::SenderPickup, 64, 1472, 1, 21, 0),
        ];
        let receiver = vec![
            fragment(Point::ReceiverCommit, 64, 64, 1, 40, 1),
            fragment(Point::ReceiverCommit, 64, 1472, 1, 41, 1),
        ];
        let report = network_report(
            ATTRIBUTION,
            &[64],
            vec![
                (NetSide::Sender, Some(0), sender, closed_at(2880)),
                (NetSide::Receiver, Some(0), receiver, closed_at(2880)),
            ],
            network_first,
        );
        assert_eq!(
            report.trace([1, 1]),
            TraceAnswer::Final(Verdict::Complete),
            "network first: {network_first}"
        );
        assert_eq!(report.messages().len(), 1);
        assert_eq!(report.parked(), ParkedCounts::default());
    }
}

/// An expected network journal closed without any record of the message
/// makes its trace Incomplete; one that is still open keeps it
/// provisional.
#[test]
fn an_expected_network_journal_without_the_message_is_incomplete() {
    let report = network_report(
        ATTRIBUTION,
        &[64],
        vec![(NetSide::Receiver, Some(0), Vec::new(), closed_at(2880))],
        false,
    );
    assert_eq!(
        report.trace([1, 1]),
        TraceAnswer::Final(Verdict::Incomplete)
    );
    let report = network_report(
        ATTRIBUTION,
        &[64],
        vec![(
            NetSide::Sender,
            Some(0),
            Vec::new(),
            crate::source::SourceState::Open,
        )],
        false,
    );
    assert_eq!(report.trace([1, 1]), TraceAnswer::Provisional);
}

/// A network journal is not expected for a message below its start, at or
/// beyond its boundary, or in a recorded gap; it is expected whenever it
/// holds part of the message, even below its start.
#[test]
fn network_membership_follows_start_boundary_and_gaps() {
    for (start, boundary) in [(Some(128), 2880), (Some(0), 64)] {
        let report = network_report(
            ATTRIBUTION,
            &[64],
            vec![(NetSide::Receiver, start, Vec::new(), closed_at(boundary))],
            false,
        );
        assert_eq!(
            report.trace([1, 1]),
            TraceAnswer::Final(Verdict::Complete),
            "{start:?} {boundary}"
        );
    }
    // A recorded gap: the message's frame never committed.
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    report
        .add_publisher_source(
            recorded(1, 0, &[observation(Point::Publish, 64, 1, 10)], CLOSED),
            host(true),
            key(),
        )
        .unwrap();
    let receiver = report
        .add_network_source(
            recorded(3, 0, &[], closed_at(2880)),
            host(true),
            key(),
            NetSide::Receiver,
            0,
            Some(0),
        )
        .unwrap();
    report.drain().unwrap();
    assert_eq!(
        report.trace([1, 1]),
        TraceAnswer::Final(Verdict::Incomplete)
    );
    report.network_gaps(receiver, &[(0, 1408)]);
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
    // Holding a fragment of the message: expected, and observed.
    let report = network_report(
        ATTRIBUTION,
        &[64],
        vec![(
            NetSide::Sender,
            Some(1000),
            vec![fragment(Point::SenderPickup, 64, 1472, 1, 20, 0)],
            closed_at(2880),
        )],
        false,
    );
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
}

/// A publication with refused network journals never has a final
/// `Complete`: its observations were never recorded.
#[test]
fn a_refused_network_journal_keeps_its_publication_from_complete() {
    let mut report = network_report(ATTRIBUTION, &[64], Vec::new(), false);
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
    let mut report_refused = network_report(ATTRIBUTION, &[64], Vec::new(), false);
    report_refused.network_refused(key(), 1);
    assert_eq!(report_refused.trace([1, 1]), TraceAnswer::OutOfScope);
    // No refusal, or another publication's: unchanged.
    report.network_refused(key(), 0);
    report.network_refused(PublicationKey::from(PublicationId::from(IDENTITY_B)), 1);
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
}

/// The parking area is bounded: an overflow is counted, keeps the final
/// answers of its publication's traces and puts the others out of scope.
#[test]
fn a_parking_overflow_puts_the_publication_out_of_scope() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    // Trace 1 at 0 and trace 3 at 1 << 20.
    report
        .add_publisher_source(
            recorded(
                1,
                0,
                &[
                    observation(Point::Publish, 0, 1, 10),
                    observation(Point::Publish, 1 << 20, 3, 10),
                ],
                CLOSED,
            ),
            host(true),
            key(),
        )
        .unwrap();
    // The subscriber was expected for trace 1 and never polled it: final
    // Incomplete. Trace 3 lies past its boundary.
    report
        .add_subscriber_source(
            recorded(2, 0, &[], closed_at(65)),
            host(true),
            key(),
            Lane::ZERO,
            0,
        )
        .unwrap();
    // An open sender journal with one fragment more than the area holds,
    // of a message whose Publish never comes.
    let overflowing: Vec<_> = (0..=MAX_PARKED as u64)
        .map(|frame| fragment(Point::SenderPickup, 1 << 30, frame, 2, 20, 0))
        .collect();
    report
        .add_network_source(
            recorded(3, 0, &overflowing, crate::source::SourceState::Open),
            host(true),
            key(),
            NetSide::Sender,
            0,
            Some(1 << 21),
        )
        .unwrap();
    report.drain().unwrap();
    assert_eq!(report.parked().overflowed, 1);
    assert_eq!(
        report.trace([1, 1]),
        TraceAnswer::Final(Verdict::Incomplete)
    );
    assert_eq!(report.trace([3, 1]), TraceAnswer::OutOfScope);
}

/// A source like `recorded` whose journal also lost one record after
/// them: every trace it holds is then Incomplete (`D` unbounded).
fn lossy(
    journal: u64,
    records: &[crate::record::TraceRecord],
    state: crate::source::SourceState,
) -> Recorded {
    let mut source = recorded(journal, 0, records, state);
    source.attempted += 1;
    source
}

/// A network journal registered with `report` from `source`.
fn add_network_source(
    report: &mut TraceReport,
    source: Recorded,
    side: NetSide,
    lane: u8,
    start: Option<u64>,
) -> JournalId {
    report
        .add_network_source(source, host(true), key(), side, lane, start)
        .unwrap()
}

/// The coordinator's #262 scenario: a parked fragment's message is
/// published in another journal. The verdict is the same whichever journal
/// drains first, and a fragment ages out only once its message can no
/// longer appear.
#[test]
fn the_drain_order_never_changes_a_verdict() {
    let attribution = AttributionConfig {
        span: 100,
        ..ATTRIBUTION
    };
    let network = || {
        recorded(
            3,
            0,
            &[
                fragment(Point::SenderPickup, 64, 64, 1, 20, 0),
                fragment(Point::SenderPickup, 4096, 4096, 2, 500, 0),
            ],
            closed_at(1 << 20),
        )
    };
    let publisher = || recorded(1, 0, &[observation(Point::Publish, 64, 1, 10)], CLOSED);
    let mut answers = Vec::new();
    for network_first in [false, true] {
        let mut report = TraceReport::new(attribution, HISTOGRAM);
        if network_first {
            add_network_source(&mut report, network(), NetSide::Sender, 0, Some(0));
        }
        report
            .add_publisher_source(publisher(), host(true), key())
            .unwrap();
        if !network_first {
            add_network_source(&mut report, network(), NetSide::Sender, 0, Some(0));
        }
        report.drain().unwrap();
        // The fragment of message 4096 can never be named: aged out.
        assert_eq!(
            report.parked(),
            ParkedCounts {
                overflowed: 0,
                aged: 1
            }
        );
        answers.push(report.trace([1, 1]));
    }
    assert_eq!(answers, [TraceAnswer::Final(Verdict::Complete); 2]);
}

/// A parked fragment waits while a client journal of its publication is
/// open, and ages out once all of them are terminal; with none
/// registered it waits.
#[test]
fn a_parked_fragment_ages_out_only_when_its_message_cannot_appear() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    add_network_source(
        &mut report,
        recorded(
            3,
            0,
            &[fragment(Point::SenderPickup, 64, 64, 2, 10, 0)],
            crate::source::SourceState::Open,
        ),
        NetSide::Sender,
        0,
        Some(0),
    );
    report.drain().unwrap();
    // No client journal of the publication: it waits.
    assert_eq!(report.parked(), ParkedCounts::default());
    let publisher = report
        .add_publisher(
            trace_journal(
                4,
                4,
                ObserverId {
                    driver: IDENTITY.driver,
                    journal: 9,
                },
                1,
            )
            .unwrap()
            .1,
            ClockProvenance::HostMonotonic,
            PublicationId::from(IDENTITY),
        )
        .unwrap();
    report.drain().unwrap();
    // An open publisher journal could still publish it.
    assert_eq!(report.parked().aged, 0);
    report.closed(publisher, None);
    report.drain().unwrap();
    assert_eq!(report.parked().aged, 1);
}

/// A network journal that holds part of a message is expected for it even
/// below its start: its loss makes the trace Incomplete.
#[test]
fn a_journal_holding_the_message_is_expected_below_its_start() {
    let report = network_report(ATTRIBUTION, &[64], Vec::new(), false);
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
    let mut report = network_report(ATTRIBUTION, &[64], Vec::new(), false);
    // Not expected by its start (1000), but it holds a fragment of the
    // message and lost a record: expected, so Incomplete.
    let _ = report.add_network_source(
        lossy(
            3,
            &[fragment(Point::SenderPickup, 64, 1472, 1, 20, 0)],
            closed_at(2880),
        ),
        host(true),
        key(),
        NetSide::Sender,
        0,
        Some(1000),
    );
    report.drain().unwrap();
    assert_eq!(
        report.trace([1, 1]),
        TraceAnswer::Final(Verdict::Incomplete)
    );
}

/// Gap and lane edges: a message at a gap's start or in a second gap is
/// not expected, one at a gap's end is; a journal of another lane is
/// never expected.
#[test]
fn gap_and_lane_edges_decide_membership() {
    let receiver = |report: &mut TraceReport, lane: u8| {
        add_network_source(
            report,
            recorded(3, 0, &[], closed_at(1 << 20)),
            NetSide::Receiver,
            lane,
            Some(0),
        )
    };
    let gaps = [(64, 128), (512, 1024)];
    for (position, expected) in [
        (64, TraceAnswer::Final(Verdict::Complete)),
        (128, TraceAnswer::Final(Verdict::Incomplete)),
        (640, TraceAnswer::Final(Verdict::Complete)),
    ] {
        let mut report = network_report(ATTRIBUTION, &[position], Vec::new(), false);
        let journal = receiver(&mut report, 0);
        report.network_gaps(journal, &gaps);
        report.drain().unwrap();
        assert_eq!(report.trace([1, 1]), expected, "position {position}");
    }
    let mut report = network_report(ATTRIBUTION, &[64], Vec::new(), false);
    let _ = receiver(&mut report, 2);
    report.drain().unwrap();
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
}

/// A poll can name the message first: network, then subscriber, then
/// publisher journals complete the trace with one message and nothing
/// parked.
#[test]
fn a_poll_first_names_the_message() {
    let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
    add_network_source(
        &mut report,
        recorded(
            3,
            0,
            &[
                fragment(Point::SenderPickup, 64, 64, 1, 20, 0),
                fragment(Point::SenderPickup, 64, 1472, 1, 21, 0),
            ],
            closed_at(2880),
        ),
        NetSide::Sender,
        0,
        Some(0),
    );
    report
        .add_subscriber_source(
            recorded(
                2,
                0,
                &[observation(Point::SubscriberPoll, 64, 1, 90)],
                closed_at(1 << 20),
            ),
            host(true),
            key(),
            Lane::ZERO,
            0,
        )
        .unwrap();
    report
        .add_publisher_source(
            recorded(1, 0, &[observation(Point::Publish, 64, 1, 10)], CLOSED),
            host(true),
            key(),
        )
        .unwrap();
    report.drain().unwrap();
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
    assert_eq!(report.messages().len(), 1);
    assert_eq!(report.parked(), ParkedCounts::default());
}

/// A network journal closed without a boundary is lost, as a subscriber
/// journal without one is: its traces are Incomplete, never provisional
/// for ever.
#[test]
fn a_network_journal_closed_without_a_boundary_is_lost() {
    let report = network_report(
        ATTRIBUTION,
        &[64],
        vec![(
            NetSide::Sender,
            Some(0),
            vec![fragment(Point::SenderPickup, 64, 64, 1, 20, 0)],
            CLOSED,
        )],
        false,
    );
    assert_eq!(
        report.trace([1, 1]),
        TraceAnswer::Final(Verdict::Incomplete)
    );
}

// Journal loss attribution end to end (SPEC.md §13, "Journal loss
// attribution"): a subscriber's one-record journal held full while its
// polls are dropped.

/// Attribution with a finite span, so a loss within one epoch reaches only
/// the traces near it.
const NEAR: AttributionConfig = AttributionConfig {
    span: 10,
    ..ATTRIBUTION
};

/// An application clock whose time and epoch the test sets.
struct Settable(std::sync::Arc<std::sync::Mutex<(u64, u64)>>, u64);

impl TraceClock for Settable {
    fn now(&mut self) -> ObservedTime {
        let (time, epoch) = *self.0.lock().unwrap();
        ObservedTime {
            time,
            clock: self.1,
            epoch,
            uncertainty: 1,
        }
    }
}

/// A publisher and a subscriber whose journal holds one record and two
/// drop ranges, its clock set through the returned cell.
struct Lossy {
    report: TraceReport,
    publisher: Agent<MonotonicClock>,
    pub_id: JournalId,
    subscriber: Agent<Settable>,
    sub_id: JournalId,
    clock: std::sync::Arc<std::sync::Mutex<(u64, u64)>>,
    next: u64,
}

impl Lossy {
    fn new() -> Self {
        let mut report = TraceReport::new(NEAR, HISTOGRAM);
        let (publisher, pub_id) = std_agent(&mut report, 1, 64, None);
        let clock = std::sync::Arc::new(std::sync::Mutex::new((1000, 1)));
        let (subscriber, sub_id) = ranged_agent(
            &mut report,
            2,
            1,
            2,
            Settable(std::sync::Arc::clone(&clock), 2),
            2,
            Some(0),
        );
        Self {
            report,
            publisher,
            pub_id,
            subscriber,
            sub_id,
            clock,
            next: 0,
        }
    }

    /// Publishes and delivers one message at the subscriber's `(time,
    /// epoch)`; returns its trace.
    fn message(&mut self, time: u64, epoch: u64) -> [u64; 2] {
        *self.clock.lock().unwrap() = (time, epoch);
        let ext = publish(&mut self.publisher, self.next);
        deliver(&mut self.subscriber, &ext, 9, self.next);
        self.next += 64;
        ext.trace_id
    }

    fn close(&mut self) {
        self.publisher.close();
        self.subscriber.close();
        self.report.closed(self.pub_id, None);
        self.report.closed(self.sub_id, Some(self.next));
        self.report.drain().unwrap();
    }
}

/// Polls of traces 1 to 4 at positions 0 to 192, the second lost: a
/// sequence gap between the first poll, in epoch 1, and the third, in
/// `epoch_after`; the fourth is far later in time. Returns the report.
fn a_gap_then_a_later_trace(epoch_after: u64) -> TraceReport {
    let key = PublicationKey::from(PublicationId::from(IDENTITY));
    let mut report = TraceReport::new(NEAR, HISTOGRAM);
    let publishes: Vec<_> = (0..4)
        .map(|n| observation(Point::Publish, 64 * n, n + 1, 1000))
        .collect();
    report
        .add_publisher_source(recorded(1, 0, &publishes, CLOSED), host(true), key)
        .unwrap();
    let mut polls = recorded(2, 0, &[], closed_at(193));
    for (sequence, trace, time, epoch) in [
        (0, 1, 1000, 1),
        (2, 3, 1000, epoch_after),
        (3, 4, 1_000_000, epoch_after),
    ] {
        let mut record = observation(Point::SubscriberPoll, 64 * (trace - 1), trace, time);
        record.observed.epoch = epoch;
        polls.items.push_back(Collected::Record {
            sequence,
            gap: (sequence == 2).then_some((1, 2)),
            record,
            collected: karyos_protocol::journal::Stamp {
                time,
                clock: record.observed.clock,
                epoch,
            },
        });
    }
    polls.attempted = 4;
    report
        .add_subscriber_source(polls, host(true), key, Lane::ZERO, 0)
        .unwrap();
    report.drain().unwrap();
    report
}

#[test]
fn a_loss_within_one_epoch_marks_only_the_traces_near_it() {
    let report = a_gap_then_a_later_trace(1);
    for trace in 1..4 {
        assert_eq!(
            report.trace([trace, 1]),
            TraceAnswer::Final(Verdict::Incomplete)
        );
    }
    assert_eq!(report.trace([4, 1]), TraceAnswer::Final(Verdict::Complete));
}

#[test]
fn a_loss_across_an_epoch_change_marks_the_whole_cohort() {
    let report = a_gap_then_a_later_trace(2);
    // Times of different epochs are not comparable: every trace of the
    // journal, the one far later included.
    for trace in 1..5 {
        assert_eq!(
            report.trace([trace, 1]),
            TraceAnswer::Final(Verdict::Incomplete)
        );
    }
}

/// A drop-range overflow loses no attribution. The report attributes loss
/// from sequence gaps and the loss snapshot's horizon and stored count,
/// never from the ring or its `lost_before` watermark, so a trace whose range
/// was evicted is still marked. The watermark itself is checked in
/// `karyos-sys`: `range_ring_overflow_raises_the_watermark`. In one thread,
/// a record is dropped only while the journal is full and only a drain frees
/// it, so every loss is a tail loss at that drain and marks the cohort.
#[test]
fn a_drop_range_overflow_loses_no_attribution() {
    let mut lossy = Lossy::new();
    let mut traces = vec![lossy.message(1000, 1)];
    // The one record stays held while four polls are dropped, each in its
    // own epoch: four drop ranges for a ring of two, so the oldest are
    // folded into the journal's lost-before watermark.
    for epoch in 2..6 {
        traces.push(lossy.message(1000, epoch));
    }
    assert_eq!(lossy.subscriber.counts().dropped, 4);
    lossy.report.drain().unwrap();
    traces.push(lossy.message(1_000_000, 6));
    lossy.report.drain().unwrap();
    traces.push(lossy.message(2_000_000, 6));
    lossy.close();
    assert_eq!(lossy.subscriber.counts().dropped, 4);
    for trace in traces {
        assert_eq!(
            lossy.report.trace(trace),
            TraceAnswer::Final(Verdict::Incomplete)
        );
    }
}

/// karyos#992: a subscriber journal is expected only for messages of its
/// own lane. On a two-lane aggregate, a lane-0 subscriber that polled the
/// lane-0 message is not expected for the lane-1 message at the same
/// position, which stays `Complete`; a lane-1 subscriber that polled
/// nothing leaves the lane-1 message `Incomplete` and lane 0's alone.
#[test]
fn a_subscriber_journal_is_expected_only_for_its_lane() {
    let key = PublicationKey::from(PublicationId::from(IDENTITY));
    let build = |lane: Lane, polls: &[crate::record::TraceRecord]| {
        let mut other_lane = observation(Point::Publish, 0, 2, 20);
        other_lane.lane = 1;
        let mut report = TraceReport::new(ATTRIBUTION, HISTOGRAM);
        report
            .add_publisher_source(
                recorded(
                    1,
                    0,
                    &[observation(Point::Publish, 0, 1, 10), other_lane],
                    CLOSED,
                ),
                host(true),
                key,
            )
            .unwrap();
        report
            .add_subscriber_source(
                recorded(2, 0, polls, closed_at(65)),
                host(true),
                key,
                lane,
                0,
            )
            .unwrap();
        report.drain().unwrap();
        report
    };
    let report = build(Lane::ZERO, &[observation(Point::SubscriberPoll, 0, 1, 30)]);
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
    assert_eq!(report.trace([2, 1]), TraceAnswer::Final(Verdict::Complete));
    let report = build(Lane::try_new(1).unwrap(), &[]);
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
    assert_eq!(
        report.trace([2, 1]),
        TraceAnswer::Final(Verdict::Incomplete)
    );
}
