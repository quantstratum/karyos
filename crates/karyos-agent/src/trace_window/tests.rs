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

pub(crate) mod mirror {
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
    pub(crate) struct Traced {
        pub(crate) driver: EmbeddedDriver,
        pub(crate) publication: PublicationId,
        pub(crate) driver_id: [u64; 2],
        pub(crate) publisher: TraceWriter,
        pub(crate) subscriber: TraceWriter,
        _conductor: ClientConductor,
    }

    pub(crate) fn traced(config: DriverConfig) -> Traced {
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
    pub(crate) fn write(
        writer: &mut TraceWriter,
        publication: PublicationId,
        point: Point,
        position: u64,
    ) {
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

    /// Review B3 of #817: what a scan loses is charged to the bucket its
    /// surviving records land in, not to the one it closes. A ring of two
    /// records laps the window between two scans: the slice closed by the
    /// second scan stays clean, and the next bucket reports the overwritten
    /// records.
    #[test]
    fn a_scans_loss_lands_in_the_bucket_missing_the_pairs() {
        let mut traced = traced(DriverConfig {
            trace_mirror_records: 2,
            ..DriverConfig::default()
        });
        let publication = traced.publication;
        let mut window =
            TraceWindow::new(WindowConfig::default().with_window(60, 6), traced.driver_id);
        window.scan(&traced.driver.trace_mirror(), 1);
        for position in 0..4 {
            write(
                &mut traced.publisher,
                publication,
                Point::Publish,
                position * 64,
            );
        }
        for _ in 0..8 {
            let _ = traced.driver.do_work().unwrap();
        }
        window.scan(&traced.driver.trace_mirror(), 12);
        window.scan(&traced.driver.trace_mirror(), 25);
        let read = read(&window, 0, 2, None).unwrap();
        assert!(!read.buckets[0].incomplete, "{:?}", read.buckets[0]);
        assert!(read.buckets[1].incomplete);
        assert_eq!(read.buckets[1].loss.unwrap().mirror_overwritten, 2);
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
    let read = read(&window, 0, 10, None).unwrap();
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
    let read = read(&window, 0, 10, None).unwrap();
    assert!(!read.buckets[0].incomplete);
    assert!(read.buckets[1].incomplete);
    assert_eq!(read.buckets[1].loss.unwrap().pending_dropped, 1);
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
    let first = read(&window, 0, 10, Some(window.epoch())).unwrap();
    let second = read(&window, 0, 10, None).unwrap();
    assert_eq!(first.buckets, second.buckets);
    // Crashed after reading bucket 0: it asks for 0 again.
    let again = read(&window, 0, 1, Some(first.epoch)).unwrap();
    assert_eq!(again.buckets[..], first.buckets[..1]);
    // A cursor from another run.
    let restarted = self::window(64);
    assert!(matches!(
        read(&restarted, 1, 1, Some(first.epoch)),
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
    for slice in 0..40u64 {
        pair(&mut window, slice, slice * 10 + 1);
        assert!(window.bucket_bytes() <= budget, "{}", window.bucket_bytes());
    }
    window.close_slices(401);
    let (_, counts) = window.view(401);
    assert!(counts.buckets_evicted > 0);
    assert!(matches!(
        read(&window, 0, 1, None),
        Err(BucketRefusal::Expired { .. })
    ));
    let refused = read(&window, 0, 1, None).err().unwrap();
    let BucketRefusal::Expired { oldest } = refused else {
        panic!("{refused:?}");
    };
    assert_eq!(
        read(&window, oldest, 1, None).unwrap().buckets[0].number,
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
        read(&tiny, 0, 1, None).err(),
        Some(BucketRefusal::OverBudget { number: 0 })
    );
    let (_, counts) = tiny.view(12);
    assert_eq!((counts.buckets_over_budget, counts.buckets_evicted), (1, 0));
}

/// R-CORE-23: a view longer than the window, assembled from buckets: an
/// hour of the default minute window's 10-second slices is 360 buckets,
/// read in pages, with every pair once, which the rolling view (the last
/// minute) cannot give.
#[test]
fn an_hour_is_assembled_from_buckets() {
    const SECOND: u64 = 1_000_000_000;
    let mut window = TraceWindow::new(WindowConfig::default(), [1, 2]);
    window.journal(PUBLISHER, Some(HOST), 0);
    window.journal(SUBSCRIBER, Some(HOST), 0);
    for slice in 0..360u64 {
        pair(&mut window, slice, slice * 10 * SECOND + 1);
    }
    let hour = 3600 * SECOND;
    window.close_slices(hour + 1);
    let mut buckets = Vec::new();
    let mut from = 0;
    while from < 360 {
        let read = read(&window, from, crate::api::BUCKETS_MAX, None).unwrap();
        from += u64::try_from(read.buckets.len()).unwrap();
        buckets.extend(read.buckets);
    }
    assert_eq!(buckets.len(), 360);
    assert_eq!(available(&buckets).iter().sum::<u64>(), 360);
    assert!(buckets.iter().all(|bucket| !bucket.incomplete));
    // The rolling view holds only its last minute: the last 6 slices.
    assert_eq!(lane(&window, hour + 1).available, 5);
}

/// One matched pair of message `position` whose latency is `latency` ns,
/// made by a scan at `now`.
fn pair_with(window: &mut TraceWindow, position: u64, now: u64, latency: u64) {
    window.close_slices(now);
    window.observe(PUBLISHER, &record(Point::Publish, position, 1000), now);
    window.observe(
        SUBSCRIBER,
        &record(Point::SubscriberPoll, position, 1000 + latency),
        now,
    );
}

/// A window of 60 ns in 6 slices under a bucket budget of `budget` bytes.
fn budgeted(budget: usize) -> TraceWindow {
    let mut window = TraceWindow::new(
        WindowConfig::default()
            .with_window(60, 6)
            .with_bounds(8, 1 << 20, 4, 4)
            .with_bucket_budget(budget),
        [1, 2],
    );
    window.journal(PUBLISHER, Some(HOST), 0);
    window.journal(SUBSCRIBER, Some(HOST), 0);
    window
}

/// Review B1 of #817: an over-budget number older than the retained
/// buckets never lowers the floor. Once eviction passes it, it and every
/// evicted number are refused as expired, never served as empty buckets.
#[test]
fn eviction_past_an_over_budget_bucket_expires_it() {
    // Room for about two one-latency buckets; a bucket of 200 latencies
    // is over the budget.
    let mut window = budgeted(1_000);
    pair(&mut window, 0, 1);
    for spread in 0..200 {
        pair_with(&mut window, 1 + spread, 11, 1 + spread * 1000);
    }
    for slice in 2..12u64 {
        pair(&mut window, 1_000 + slice, slice * 10 + 1);
    }
    window.close_slices(121);
    let (_, counts) = window.view(121);
    assert_eq!(counts.buckets_over_budget, 1);
    assert!(counts.buckets_evicted > 0);
    let Err(BucketRefusal::Expired { oldest }) = read(&window, 0, 1, None) else {
        panic!("bucket 0 was evicted");
    };
    assert!(oldest > 2, "{oldest}");
    // The over-budget number is below the floor: expired too.
    assert_eq!(
        read(&window, 1, 1, None).err(),
        Some(BucketRefusal::Expired { oldest })
    );
    // Every number from the floor on is a kept bucket with its pair.
    let read = read(&window, oldest, 60, None).unwrap();
    assert_eq!(read.oldest, oldest);
    assert!(read.buckets.iter().all(|bucket| bucket.lanes.len() == 1));
}

/// Review B2 of #817: past the over-budget numbers the window remembers,
/// the oldest is forgotten and the floor moves past it, so a read of it is
/// refused as expired, never served as an empty bucket, even with a kept
/// bucket older than it.
#[test]
fn a_forgotten_over_budget_number_is_expired() {
    let mut window = budgeted(1_000);
    // Bucket 0 is kept; buckets 1 to 65 are each over the budget.
    pair(&mut window, 0, 1);
    let kept = u64::try_from(OVER_BUDGET_KEPT).unwrap();
    let mut position = 1;
    for slice in 1..=kept + 1 {
        for spread in 0..200 {
            pair_with(&mut window, position, slice * 10 + 1, 1 + spread * 1000);
            position += 1;
        }
    }
    window.close_slices((kept + 2) * 10 + 1);
    let (_, counts) = window.view((kept + 2) * 10 + 1);
    assert_eq!(counts.buckets_over_budget, kept + 1);
    // Number 1 is forgotten: expired, and so is bucket 0 below it.
    for number in [0, 1] {
        assert_eq!(
            read(&window, number, 1, None).err(),
            Some(BucketRefusal::Expired { oldest: 2 }),
            "{number}"
        );
    }
    assert_eq!(
        read(&window, 2, 1, None).err(),
        Some(BucketRefusal::OverBudget { number: 2 })
    );
}

/// Review B3 of #817: a record of a journal not in the table, or one that
/// does not decode, may have paired: the bucket of the scan that met it is
/// incomplete, with the reason.
#[test]
fn an_unknown_journal_or_a_malformed_record_makes_its_bucket_incomplete() {
    let mut window = window(64);
    pair(&mut window, 0, 1);
    window.close_slices(12);
    window.observe(99, &record(Point::Publish, 7, 1000), 12);
    window.close_slices(25);
    window.counts.malformed += 1;
    window.close_slices(35);
    let read = read(&window, 0, 10, None).unwrap();
    assert!(!read.buckets[0].incomplete);
    assert!(read.buckets[1].incomplete);
    assert_eq!(read.buckets[1].loss.unwrap().unknown_journal, 1);
    assert!(read.buckets[2].incomplete);
    assert_eq!(read.buckets[2].loss.unwrap().malformed, 1);
}

/// Up to `count` buckets of `window` from number `from`, lane 0, with no
/// byte bound.
fn read(
    window: &TraceWindow,
    from: u64,
    count: usize,
    epoch: Option<u64>,
) -> Result<BucketRead, BucketRefusal> {
    window.buckets(BucketCursor::new(from, 0), count, epoch, usize::MAX)
}

/// One matched pair of message `position` on the publication of
/// `registration` (a lane of its own), made by a scan at `now`.
fn pair_on(window: &mut TraceWindow, registration: u64, position: u64, now: u64) {
    let on = |mut record: TraceRecord| {
        record.publication.registration = registration;
        record
    };
    window.close_slices(now);
    window.observe(PUBLISHER, &on(record(Point::Publish, position, 1000)), now);
    window.observe(
        SUBSCRIBER,
        &on(record(Point::SubscriberPoll, position, 1500)),
        now,
    );
}

/// R-CORE-23, paging by lane (QS-COORDINATOR, ACS 33179 and 33400): a
/// bucket larger than the reply bound comes in pages of whole lanes, each
/// reply within the bound plus one lane; `next` names the bucket and the
/// lane, and the pages hold every lane once. No page holds a bucket's
/// header alone, and its loss is on its first page only.
#[test]
fn a_bucket_over_the_bound_is_read_in_pages_of_lanes() {
    let mut window = TraceWindow::new(
        WindowConfig::default()
            .with_window(60, 6)
            .with_bounds(8, 64, 4, 8),
        [1, 2],
    );
    window.journal(PUBLISHER, Some(HOST), 0);
    window.journal(SUBSCRIBER, Some(HOST), 0);
    for registration in 0..6 {
        pair_on(&mut window, 100 + registration, registration, 1);
    }
    pair(&mut window, 99, 12);
    window.close_slices(25);
    let whole = read(&window, 0, 2, None).unwrap();
    assert_eq!(whole.buckets[0].lanes.len(), 6);
    assert_eq!(whole.next, None);
    let lane_bytes = crate::json::bucket_lane_len(&whole.buckets[0].lanes[0]);
    // Room for the reply, the header and two lanes.
    let bound = crate::json::BUCKET_REPLY_OVERHEAD + 400 + 2 * lane_bytes;
    let mut from = BucketCursor::new(0, 0);
    let mut lanes = Vec::new();
    let epoch = Some(window.epoch());
    loop {
        let page = window.buckets(from, 2, epoch, bound).unwrap();
        let text = crate::json::trace_buckets(&page);
        assert!(text.len() <= bound + lane_bytes, "{} > {bound}", text.len());
        for bucket in &page.buckets {
            assert_eq!(bucket.lanes_total, if bucket.number == 0 { 6 } else { 1 });
            // Never a header alone; the loss on the first page only.
            assert!(!bucket.lanes.is_empty(), "{bucket:?}");
            assert_eq!(bucket.loss.is_some(), bucket.first_lane == 0, "{bucket:?}");
            for (offset, lane) in bucket.lanes.iter().enumerate() {
                lanes.push((bucket.number, bucket.first_lane + offset, lane.stream));
            }
        }
        match page.next {
            Some(next) => {
                assert!(next > from, "{next:?} after {from:?}");
                from = next;
            }
            None => break,
        }
    }
    let streams: Vec<_> = lanes
        .iter()
        .map(|&(number, lane, _)| (number, lane))
        .collect();
    assert_eq!(
        streams,
        [(0, 0), (0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (1, 0)]
    );
}

/// R-CORE-23 (ACS 33179, condition 2): a bucket evicted between two
/// pages of it is refused as expired on the continuation; a reader never
/// gets a bucket with lanes missing as if it were whole.
#[test]
fn a_bucket_evicted_between_its_pages_is_expired() {
    let mut window = TraceWindow::new(
        WindowConfig::default()
            .with_window(60, 6)
            .with_bounds(8, 64, 4, 8)
            .with_bucket_budget(4_000),
        [1, 2],
    );
    window.journal(PUBLISHER, Some(HOST), 0);
    window.journal(SUBSCRIBER, Some(HOST), 0);
    for registration in 0..3 {
        pair_on(&mut window, 100 + registration, registration, 1);
    }
    window.close_slices(12);
    let first = window.buckets(BucketCursor::new(0, 0), 1, None, 1).unwrap();
    assert_eq!(first.buckets[0].lanes.len(), 1);
    let next = first.next.unwrap();
    assert_eq!(next, BucketCursor::new(0, 1));
    // Later buckets evict bucket 0 before the reader comes back.
    for slice in 1..20u64 {
        for registration in 0..3 {
            pair_on(
                &mut window,
                100 + registration,
                slice * 10 + registration,
                slice * 10 + 1,
            );
        }
    }
    window.close_slices(201);
    let (_, counts) = window.view(201);
    assert!(counts.buckets_evicted > 0);
    assert!(matches!(
        window.buckets(next, 1, Some(first.epoch), usize::MAX),
        Err(BucketRefusal::Expired { .. })
    ));
}

/// R-CORE-40, karyos#741: the clocks read lists each local journal's
/// clock with the domain and epoch of its last record and the largest
/// uncertainty of that epoch, which a new epoch starts over. With no
/// calibration source each reads unavailable, `no_calibration`, never a
/// number; a network journal has no clock of this host and is not listed.
#[test]
fn the_clocks_read_lists_epochs_and_uncertainties_and_no_calibration() {
    let mut window = window(8);
    window.journal(12, None, 0);
    let mut wide = record(Point::Publish, 0, 1000);
    wide.observed.uncertainty = 9;
    window.observe(PUBLISHER, &wide, 1);
    window.observe(PUBLISHER, &record(Point::Publish, 1, 1100), 1);
    // The subscriber's clock moves to epoch 4: its uncertainty starts over.
    window.observe(SUBSCRIBER, &wide, 1);
    let mut next = record(Point::SubscriberPoll, 0, 50);
    next.observed.epoch = 4;
    window.observe(SUBSCRIBER, &next, 1);
    let (clocks, calibrations) = window.clocks(&[]);
    assert!(calibrations.is_empty());
    let none = CalibrationState::Unavailable {
        reason: CalibrationUnavailable::NoCalibration,
    };
    assert_eq!(
        clocks,
        [
            ClockState {
                journal: PUBLISHER,
                provenance: "host_monotonic",
                same_namespace: true,
                domain: Some(1),
                epoch: Some(3),
                time: Some(1100),
                uncertainty: Some(9),
                calibration: none,
            },
            ClockState {
                journal: SUBSCRIBER,
                provenance: "host_monotonic",
                same_namespace: true,
                domain: Some(1),
                epoch: Some(4),
                time: Some(50),
                uncertainty: Some(2),
                calibration: none,
            },
        ]
    );
    // A journal with no record yet is listed with nothing observed.
    window.journal(13, Some(HOST), 0);
    let (clocks, _) = window.clocks(&[]);
    let fresh = clocks.iter().find(|clock| clock.journal == 13).unwrap();
    assert_eq!(
        (fresh.epoch, fresh.uncertainty, fresh.calibration),
        (None, None, none)
    );
    // A journal that left the table is forgotten, its clock with it.
    window.age(1000);
    assert!(window.clocks(&[]).0.is_empty());
    assert!(window.observed.is_empty());
}

/// R-CORE-40: a calibration from a journal's clock is checked at that
/// clock's last observed time: valid inside its range, expired past it,
/// and shown with its range either way.
#[test]
fn a_calibration_is_checked_at_its_clocks_last_time() {
    let mut window = window(8);
    window.observe(PUBLISHER, &record(Point::Publish, 0, 1000), 1);
    let clock = |journal| ClockKey {
        observer: ObserverId {
            driver: [1, 2],
            journal,
        },
        domain: 1,
        epoch: 3,
    };
    let calibration = |valid_to| Calibration {
        from: clock(PUBLISHER),
        to: clock(SUBSCRIBER),
        reference: 900,
        offset: 5,
        offset_uncertainty: 1,
        drift: 0,
        drift_uncertainty: 0,
        valid_from: 900,
        valid_to,
    };
    let (clocks, views) = window.clocks(&[calibration(2000)]);
    let publisher = clocks.iter().find(|c| c.journal == PUBLISHER).unwrap();
    assert_eq!(publisher.calibration, CalibrationState::Valid { count: 1 });
    assert_eq!(views[0].state, "valid");
    assert_eq!(views[0].calibration.valid_to, 2000);
    let (clocks, views) = window.clocks(&[calibration(999)]);
    let publisher = clocks.iter().find(|c| c.journal == PUBLISHER).unwrap();
    assert_eq!(
        publisher.calibration,
        CalibrationState::Unavailable {
            reason: CalibrationUnavailable::Expired
        }
    );
    assert_eq!(views[0].state, "expired");
    // The subscriber has no record: its calibration has no time to hold at.
    let mut reverse = calibration(2000);
    reverse.from = clock(SUBSCRIBER);
    reverse.to = clock(PUBLISHER);
    let (clocks, views) = window.clocks(&[reverse]);
    let subscriber = clocks.iter().find(|c| c.journal == SUBSCRIBER).unwrap();
    assert_eq!(
        subscriber.calibration,
        CalibrationState::Unavailable {
            reason: CalibrationUnavailable::NotObserved
        }
    );
    assert_eq!(views[0].state, "not_observed");
}
