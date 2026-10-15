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
use crate::ids::{BufferedIds, OsRandom};
use crate::journal::trace_journal;
use crate::record::ObservedTime;
use crate::sampling::Sampling;
use crate::trace_clock::{MonotonicClock, TraceClock};

const IDENTITY: PublicationIdentity = PublicationIdentity {
    driver: [1, 2],
    registration: 3,
    stream_id: 10,
    session_id: 1,
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
