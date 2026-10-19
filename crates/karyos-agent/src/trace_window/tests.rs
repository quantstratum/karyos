// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_trace::{ObservedTime, PublicationId, SubscriberId, TraceIds};

use super::*;

const HOST: JournalClock = JournalClock {
    provenance: ClockProvenance::HostMonotonic,
    same_namespace: true,
};
const PUBLISHER: u64 = 10;
const SUBSCRIBER: u64 = 11;

/// A window of 60 ns in 6 slices, so tests choose slices by time.
fn window(max_pending: usize) -> TraceWindow {
    let mut window = TraceWindow::new(
        WindowConfig::default()
            .with_window(60, 6)
            .with_bounds(8, max_pending, 4, 4),
        [1, 2],
    );
    window.journal(PUBLISHER, Some(HOST));
    window.journal(SUBSCRIBER, Some(HOST));
    window
}

fn record(point: Point, position: u64, time: u64) -> TraceRecord {
    TraceRecord {
        point,
        publication: PublicationId {
            driver: [1, 2],
            registration: 5,
            stream_id: 7,
            session_id: 1,
            incarnation: 1,
        },
        lane: 0,
        position,
        ids: TraceIds {
            trace_id: [1, position + 1],
            span_id: 1,
            parent_span_id: 0,
            message_id: position + 1,
        },
        observed: ObservedTime {
            time,
            clock: 1,
            epoch: 3,
            uncertainty: 2,
        },
        subscriber: (point == Point::SubscriberPoll).then_some(SubscriberId {
            driver: [1, 2],
            registration: 9,
            incarnation: 1,
        }),
        packet: None,
        network: None,
        root: point == Point::Publish,
    }
}

fn lane(window: &TraceWindow, now: u64) -> LaneLatency {
    let (lanes, _) = window.view(now);
    assert_eq!(lanes.len(), 1, "{lanes:?}");
    lanes[0].clone()
}

#[test]
fn a_publish_then_a_poll_and_the_reverse_give_the_same_interval() {
    for poll_first in [false, true] {
        let mut window = window(8);
        let publish = record(Point::Publish, 0, 1000);
        let poll = record(Point::SubscriberPoll, 0, 1500);
        if poll_first {
            window.observe(SUBSCRIBER, &poll, 1);
            window.observe(PUBLISHER, &publish, 1);
        } else {
            window.observe(PUBLISHER, &publish, 1);
            window.observe(SUBSCRIBER, &poll, 1);
        }
        let lane = lane(&window, 1);
        assert_eq!((lane.stream, lane.incarnation, lane.lane), (5, 1, 0));
        assert_eq!((lane.available, lane.unavailable), (1, 0));
        // 500 ns, widened by the two uncertainties (2 each) and the
        // calibration's (4): [492, 508], within the histogram's
        // resolution.
        let median = lane.p50.unwrap();
        assert!(
            median.low.unwrap() <= 492 && median.high.unwrap() >= 508,
            "{median:?}"
        );
        assert!(median.high.unwrap() < 520, "{median:?}");
    }
}

#[test]
fn clocks_that_share_no_source_give_an_unavailable_pair() {
    let mut window = window(8);
    window.journals.insert(
        SUBSCRIBER,
        Some(JournalClock {
            provenance: ClockProvenance::HostMonotonic,
            same_namespace: false,
        }),
    );
    window.observe(PUBLISHER, &record(Point::Publish, 0, 1000), 1);
    window.observe(SUBSCRIBER, &record(Point::SubscriberPoll, 0, 1500), 1);
    let lane = lane(&window, 1);
    assert_eq!((lane.available, lane.unavailable), (0, 1));
    assert_eq!(lane.p50, None);
}

#[test]
fn every_bound_counts_what_it_refuses() {
    let mut window = window(1);
    window.observe(PUBLISHER, &record(Point::Publish, 0, 1000), 1);
    // A second message past the pending bound.
    window.observe(PUBLISHER, &record(Point::Publish, 1, 1000), 1);
    // A journal never seen, and a network point.
    window.observe(99, &record(Point::Publish, 2, 1000), 1);
    window.observe(PUBLISHER, &record(Point::SenderPickup, 0, 1000), 1);
    // Polls past four of one message, before its publish arrives.
    let mut fresh = self::window(8);
    for _ in 0..6 {
        fresh.observe(SUBSCRIBER, &record(Point::SubscriberPoll, 0, 1500), 1);
    }
    let (_, counts) = window.view(1);
    assert_eq!(
        (
            counts.records,
            counts.pending_dropped,
            counts.unknown_journal,
            counts.network_ignored,
            counts.pending
        ),
        (4, 1, 1, 1, 1)
    );
    assert_eq!(fresh.view(1).1.polls_dropped, 2);
}

#[test]
fn an_unmatched_message_ages_out_of_the_window() {
    let mut window = window(8);
    window.observe(PUBLISHER, &record(Point::Publish, 0, 1000), 1);
    window.age(60);
    assert_eq!(window.view(60).1.pending, 1);
    window.age(61);
    let (_, counts) = window.view(61);
    assert_eq!((counts.pending, counts.aged_out), (0, 1));
}

#[test]
fn the_window_forgets_pairs_older_than_it() {
    let mut window = window(8);
    window.observe(PUBLISHER, &record(Point::Publish, 0, 1000), 5);
    window.observe(SUBSCRIBER, &record(Point::SubscriberPoll, 0, 1500), 5);
    window.observe(PUBLISHER, &record(Point::Publish, 1, 1000), 35);
    window.observe(SUBSCRIBER, &record(Point::SubscriberPoll, 1, 1500), 35);
    // Both pairs within the window of slices 0 to 5.
    assert_eq!(lane(&window, 59).available, 2);
    // At 65 slice 0 has left the window; at 95 slice 3 too.
    assert_eq!(lane(&window, 65).available, 1);
    assert!(window.view(95).0.is_empty());
}

mod mirror {
    //! Against an embedded driver's trace mirror.

    use karyos_client::{ClientConductor, ClientJournal, ConductorError, Outcome};
    use karyos_driver::{DriverConfig, EmbeddedDriver, LossPolicy, StreamConfig};
    use karyos_protocol::cnc::{StreamKey, SubscriberRole};
    use karyos_protocol::journal::Stamp;
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
    use karyos_sys::record_journal::JournalLayout;
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;
    use karyos_trace::{HostMonotonicClock, TraceClock, TraceWriter, trace_writer};

    use super::*;

    const KEY: StreamKey = StreamKey {
        stream_id: 5,
        session_id: 1,
    };

    fn complete(
        driver: &mut EmbeddedDriver,
        conductor: &mut ClientConductor,
        submit: impl FnOnce(&mut ClientConductor) -> Result<u64, ConductorError>,
    ) -> Outcome {
        let _ = submit(conductor).unwrap();
        let _ = driver.do_work().unwrap();
        let mut outcome = None;
        let _ = conductor.poll(usize::MAX, |completion| outcome = Some(completion.outcome));
        outcome.unwrap()
    }

    fn journal(
        driver: &mut EmbeddedDriver,
        conductor: &mut ClientConductor,
        registration: u64,
    ) -> ClientJournal {
        let layout = JournalLayout {
            capacity: 16,
            payload_words: RECORD_WORDS,
            drop_ranges: 2,
        };
        match complete(driver, conductor, |conductor| {
            conductor.trace_journal(layout, registration, ClockProvenance::HostMonotonic.word())
        }) {
            Outcome::Journal(journal) => journal,
            other => panic!("expected a journal, got {other:?}"),
        }
    }

    /// A driver of `config` with one stream, a publisher journal and a
    /// subscriber journal, as writers.
    struct Traced {
        driver: EmbeddedDriver,
        publication: PublicationId,
        driver_id: [u64; 2],
        publisher: TraceWriter,
        subscriber: TraceWriter,
        _conductor: ClientConductor,
    }

    fn traced(config: DriverConfig) -> Traced {
        let mut driver = EmbeddedDriver::with_config(config).unwrap();
        let stream = driver
            .add_stream(StreamConfig {
                buffer: LogBufferConfig {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 8,
                    max_subscribers: 4,
                    mtu: DEFAULT_MTU,
                    max_reserved: MIN_TERM_LENGTH / 8,
                    initial_term_id: TermId::new(7),
                    lane: Lane::ZERO,
                    session_id: KEY.session_id,
                    stream_id: KEY.stream_id,
                    claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                    publication: PublicationMode::Exclusive,
                    schedule_capacity: 0,
                },
                allow_unconnected: true,
                on_required_loss: LossPolicy::Hold,
                conflation: None,
            })
            .unwrap();
        let publication = PublicationId::from(driver.trace_identity(stream).unwrap());
        let driver_id = driver.driver_id();
        let mut conductor = driver.connect().unwrap();
        let Outcome::Publication(publishing) = complete(&mut driver, &mut conductor, |conductor| {
            conductor.add_publication(KEY, true)
        }) else {
            panic!("expected a publication");
        };
        let publisher = journal(
            &mut driver,
            &mut conductor,
            publishing.origin().unwrap().registration(),
        );
        let Outcome::Subscription(subscription) =
            complete(&mut driver, &mut conductor, |conductor| {
                conductor.add_subscription(KEY, SubscriberRole::Optional)
            })
        else {
            panic!("expected a subscription");
        };
        let subscriber = journal(
            &mut driver,
            &mut conductor,
            subscription.origin().unwrap().registration(),
        );
        let writer = |journal: ClientJournal| {
            let (number, raw) = journal.into_parts();
            trace_writer(
                raw,
                ObserverId {
                    driver: driver_id,
                    journal: number,
                },
                1,
            )
            .unwrap()
        };
        Traced {
            publisher: writer(publisher),
            subscriber: writer(subscriber),
            driver,
            publication,
            driver_id,
            _conductor: conductor,
        }
    }

    /// Writes `point` of the message at `position` to `writer`.
    fn write(writer: &mut TraceWriter, publication: PublicationId, point: Point, position: u64) {
        let observed = HostMonotonicClock::new(1).now();
        let mut traced = record(point, position, observed.time);
        traced.publication = publication;
        traced.observed = observed;
        let stamp = Stamp {
            time: observed.time,
            clock: observed.clock,
            epoch: observed.epoch,
        };
        let _ = writer.record(&traced, stamp).unwrap();
    }

    /// A publisher journal's `Publish` and a subscriber journal's
    /// `SubscriberPoll` of one message make one pair in the publication's
    /// lane.
    #[test]
    fn a_publish_pairs_with_its_poll() {
        let mut traced = traced(DriverConfig::default());
        let publication = traced.publication;
        write(&mut traced.publisher, publication, Point::Publish, 0);
        write(
            &mut traced.subscriber,
            publication,
            Point::SubscriberPoll,
            0,
        );
        for _ in 0..8 {
            let _ = traced.driver.do_work().unwrap();
        }
        let mut window = TraceWindow::new(WindowConfig::default(), traced.driver_id);
        window.scan(&traced.driver.trace_mirror(), 1);
        let (lanes, counts) = window.view(1);
        assert_eq!((counts.records, counts.pending), (2, 1), "{counts:?}");
        assert_eq!(lanes.len(), 1, "{lanes:?}");
        let lane = &lanes[0];
        assert_eq!(
            (lane.stream, lane.incarnation, lane.lane),
            (publication.registration, publication.incarnation, 0)
        );
        // One pair: an interval where the driver knows both clients share
        // its time namespace, unavailable where it cannot tell.
        assert_eq!(lane.available + lane.unavailable, 1);
    }

    /// Ten records through a mirror ring of four between two scans: the
    /// window counts the six it never read.
    #[test]
    fn a_lapped_mirror_cursor_is_counted() {
        let config = DriverConfig {
            trace_mirror_records: 4,
            ..DriverConfig::default()
        };
        let mut traced = traced(config);
        let mut window = TraceWindow::new(WindowConfig::default(), traced.driver_id);
        window.scan(&traced.driver.trace_mirror(), 1);
        let publication = traced.publication;
        for position in 0..10 {
            write(&mut traced.publisher, publication, Point::Publish, position);
        }
        for _ in 0..8 {
            let _ = traced.driver.do_work().unwrap();
        }
        window.scan(&traced.driver.trace_mirror(), 2);
        let (_, counts) = window.view(2);
        assert_eq!(
            (counts.records, counts.mirror_overwritten),
            (4, 6),
            "{counts:?}"
        );
    }
}
