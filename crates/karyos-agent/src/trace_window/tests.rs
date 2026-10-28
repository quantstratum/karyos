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
    window.journal(PUBLISHER, Some(HOST), 0);
    window.journal(SUBSCRIBER, Some(HOST), 0);
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
        (
            Some(JournalClock {
                provenance: ClockProvenance::HostMonotonic,
                same_namespace: false,
            }),
            0,
        ),
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
            counts.points_ignored,
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

/// DESIGN's P2-1 on #475: journals opened and closed in turn, more than
/// the bound over the run, are all matched: a journal leaves the map one
/// window after it left the table.
#[test]
fn journals_past_the_bound_over_a_run_are_forgotten_not_refused() {
    let mut window = window(8);
    window.age(100);
    for journal in 0..20u64 {
        let now = 100 * (journal + 2);
        window.journal(1000 + journal, Some(HOST), now);
        window.journal(2000 + journal, Some(HOST), now);
        window.observe(1000 + journal, &record(Point::Publish, journal, 1000), now);
        window.observe(
            2000 + journal,
            &record(Point::SubscriberPoll, journal, 1500),
            now,
        );
        window.age(now + 1);
    }
    let (_, counts) = window.view(2100);
    assert_eq!(
        (counts.journals_dropped, counts.unknown_journal),
        (0, 0),
        "{counts:?}"
    );
    assert!(window.journals.len() <= 8);
}

/// DESIGN's P2-2 on #475: successive incarnations, more lanes than the
/// bound over the run, each get their histogram: a lane leaves the map one
/// window after its last pair.
#[test]
fn lanes_past_the_bound_over_a_run_are_forgotten_not_refused() {
    let mut window = window(8);
    for incarnation in 1..=10u64 {
        let now = 100 * incarnation;
        window.journal(PUBLISHER, Some(HOST), now);
        window.journal(SUBSCRIBER, Some(HOST), now);
        let mut publish = record(Point::Publish, 0, 1000);
        let mut poll = record(Point::SubscriberPoll, 0, 1500);
        publish.publication.incarnation = incarnation;
        poll.publication.incarnation = incarnation;
        window.observe(PUBLISHER, &publish, now);
        window.observe(SUBSCRIBER, &poll, now);
        assert_eq!(lane(&window, now).incarnation, incarnation);
        window.age(now + 99);
    }
    assert_eq!(window.view(1000).1.lanes_dropped, 0);
    assert!(window.lanes.len() <= 4);
}

#[test]
fn a_second_publish_of_a_message_is_counted() {
    let mut window = window(8);
    window.observe(PUBLISHER, &record(Point::Publish, 0, 1000), 1);
    window.observe(PUBLISHER, &record(Point::Publish, 0, 1100), 1);
    assert_eq!(window.view(1).1.duplicates, 1);
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

/// One matched pair of message `position`, made by a scan at `now`: the
/// slice is closed first, as `scan` does.
fn pair(window: &mut TraceWindow, position: u64, now: u64) {
    window.close_slices(now);
    window.observe(PUBLISHER, &record(Point::Publish, position, 1000), now);
    window.observe(
        SUBSCRIBER,
        &record(Point::SubscriberPoll, position, 1500),
        now,
    );
}

/// The available pairs of every lane of `buckets`.
fn available(buckets: &[crate::api::TraceBucket]) -> Vec<u64> {
    buckets
        .iter()
        .map(|bucket| bucket.lanes.iter().map(|lane| lane.counts.available).sum())
        .collect()
}

/// R-CORE-23: consecutive buckets share no pair. Pairs made in slices 0,
/// 1 and 3 (none in 2) are in exactly one bucket each, the empty slice is
/// an empty bucket, and the counts add up to the pairs made; the slice
/// still current is no bucket yet.
#[test]
fn consecutive_buckets_share_no_pair_and_add_up() {
    let mut window = window(64);
    let mut position = 0;
    for (now, pairs) in [(1, 3u64), (12, 2), (35, 4)] {
        for _ in 0..pairs {
            pair(&mut window, position, now);
            position += 1;
        }
    }
    window.close_slices(41);
    let read = window.buckets(0, 10, None).unwrap();
    assert_eq!(read.current, 4);
    assert_eq!(read.slice_ns, 10);
    assert_eq!(
        read.buckets.iter().map(|b| b.number).collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    assert_eq!(available(&read.buckets), [3, 2, 0, 4]);
    assert_eq!(available(&read.buckets).iter().sum::<u64>(), position);
    // Merged, the buckets give one histogram of every pair.
    let like = Histogram::new(DIGITS, HIGHEST, 1).unwrap();
    let mut merged = Histogram::new(DIGITS, HIGHEST, 1).unwrap();
    for lane in read.buckets.iter().flat_map(|b| &b.lanes) {
        merged
            .merge(&Histogram::from_counts(&lane.counts, &like).unwrap())
            .unwrap();
    }
    assert_eq!(merged.available(), position);
    assert!(read.buckets.iter().all(|bucket| !bucket.incomplete));
    // The rolling view is unchanged: it still merges the last window.
    assert_eq!(lane(&window, 41).available, 9);
}

/// R-CORE-23: what is lost while a slice is current makes its bucket
/// incomplete, with the loss named; never a clean bucket.
#[test]
fn a_bucket_that_lost_pairs_is_incomplete_with_its_reason() {
    // Two pending keys: the first pair's, which stays pending, and one more.
    let mut window = window(2);
    pair(&mut window, 0, 1);
    window.close_slices(12);
    window.observe(PUBLISHER, &record(Point::Publish, 5, 1000), 12);
    // Past the pending bound of one.
    window.observe(PUBLISHER, &record(Point::Publish, 6, 1000), 12);
    window.close_slices(25);
    let read = window.buckets(0, 10, None).unwrap();
    assert!(!read.buckets[0].incomplete);
    assert!(read.buckets[1].incomplete);
    assert_eq!(read.buckets[1].loss.pending_dropped, 1);
}

/// R-CORE-23: reading consumes nothing. A second reader reads the same
/// buckets, and a reader that crashed after reading reads the same bucket
/// again; a cursor of another run is refused, never served as a
/// continuation.
#[test]
fn readers_share_buckets_and_a_crashed_reader_reads_again() {
    let mut window = window(64);
    pair(&mut window, 0, 1);
    pair(&mut window, 1, 12);
    window.close_slices(25);
    let first = window.buckets(0, 10, Some(window.epoch())).unwrap();
    let second = window.buckets(0, 10, None).unwrap();
    assert_eq!(first.buckets, second.buckets);
    // Crashed after reading bucket 0: it asks for 0 again.
    let again = window.buckets(0, 1, Some(first.epoch)).unwrap();
    assert_eq!(again.buckets[..], first.buckets[..1]);
    // A cursor from another run.
    let restarted = self::window(64);
    assert!(matches!(
        restarted.buckets(1, 1, Some(first.epoch)),
        Err(BucketRefusal::EpochChanged { .. })
    ));
}

/// R-CORE-23 (E3): the retained buckets never hold more than the budget;
/// the oldest is evicted first, and a read of it is refused as expired.
/// A bucket larger than the whole budget is not kept, evicts nothing, and
/// a read of its number is refused as over budget.
#[test]
fn the_bucket_budget_holds_and_refuses_with_its_reason() {
    let budget = 2_000;
    let mut window = TraceWindow::new(
        WindowConfig::default()
            .with_window(60, 6)
            .with_bounds(8, 64, 4, 4)
            .with_bucket_budget(budget),
        [1, 2],
    );
    window.journal(PUBLISHER, Some(HOST), 0);
    window.journal(SUBSCRIBER, Some(HOST), 0);
    let mut position = 0;
    for slice in 0..40u64 {
        pair(&mut window, position, slice * 10 + 1);
        position += 1;
        assert!(window.bucket_bytes() <= budget, "{}", window.bucket_bytes());
    }
    window.close_slices(401);
    let (_, counts) = window.view(401);
    assert!(counts.buckets_evicted > 0);
    assert!(matches!(
        window.buckets(0, 1, None),
        Err(BucketRefusal::Expired { .. })
    ));
    let read = window.buckets(0, 1, None).err().unwrap();
    let BucketRefusal::Expired { oldest } = read else {
        panic!("{read:?}");
    };
    assert_eq!(
        window.buckets(oldest, 1, None).unwrap().buckets[0].number,
        oldest
    );
    // A budget below one bucket: nothing is kept or evicted for it.
    let mut tiny = TraceWindow::new(
        WindowConfig::default()
            .with_window(60, 6)
            .with_bounds(8, 64, 4, 4)
            .with_bucket_budget(100),
        [1, 2],
    );
    tiny.journal(PUBLISHER, Some(HOST), 0);
    tiny.journal(SUBSCRIBER, Some(HOST), 0);
    pair(&mut tiny, 0, 1);
    tiny.close_slices(12);
    assert_eq!(tiny.bucket_bytes(), 0);
    assert_eq!(
        tiny.buckets(0, 1, None).err(),
        Some(BucketRefusal::OverBudget { number: 0 })
    );
    let (_, counts) = tiny.view(12);
    assert_eq!((counts.buckets_over_budget, counts.buckets_evicted), (1, 0));
}

/// R-CORE-23: a view longer than the window, assembled from buckets. An
/// hour of 10-second slices is 360 buckets; here 30 slices of a 6-slice
/// window give every pair once, which the rolling view (6 slices) cannot.
#[test]
fn a_view_longer_than_the_window_is_assembled_from_buckets() {
    let mut window = window(256);
    for slice in 0..30u64 {
        pair(&mut window, slice, slice * 10 + 1);
    }
    window.close_slices(301);
    let read = window.buckets(0, 30, None).unwrap();
    assert_eq!(read.buckets.len(), 30);
    assert_eq!(available(&read.buckets).iter().sum::<u64>(), 30);
    // The rolling view holds only its last window: slices 25 to 29.
    assert_eq!(lane(&window, 301).available, 5);
}
