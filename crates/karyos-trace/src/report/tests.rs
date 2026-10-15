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
    let observer = ObserverId {
        driver: IDENTITY.driver,
        journal: number,
    };
    let (writer, collector) = trace_journal(capacity, 4, observer, domain).unwrap();
    let provenance = clock.provenance();
    let ids = BufferedIds::new(64, OsRandom).unwrap();
    let agent = TraceAgent::new(Sampling::All, ids, clock, writer);
    let publication = PublicationId::from(IDENTITY);
    let id = match subscriber_join {
        None => report.add_publisher(collector, provenance, publication),
        Some(join) => report.add_subscriber(collector, provenance, publication, join),
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
