// SPDX-License-Identifier: Apache-2.0

//! The tool's missed-journal check (`quantstratum-docs:
//! karyos/design/trace-tool.md`, T7; ACS 13973) against an embedded
//! driver on every platform: an application that draws trace numbers
//! (`EmbeddedDriver::next_trace_number`) and creates trace journals in
//! between leaves gaps in the journal numbers but none in the mirror
//! sequence, so a tool following the mirror reports no missed journal and
//! the trace stays `Complete`.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_client::{ClientConductor, ClientJournal, ConductorError, Outcome};
use karyos_driver::{DriverConfig, EmbeddedDriver, LossPolicy, StreamConfig};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_protocol::journal::Stamp;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::record_journal::JournalLayout;
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_tools::trace::mirror::MirrorTool;
use karyos_trace::{
    ClockProvenance, HostMonotonicClock, ObserverId, Point, PublicationId, RECORD_WORDS,
    SubscriberId, TraceAnswer, TraceClock, TraceIds, TraceRecord, TraceWriter, Verdict,
    trace_writer,
};

const KEY: StreamKey = StreamKey {
    stream_id: 5,
    session_id: 1,
};

/// Submits `submit`, runs one duty cycle and returns the outcome.
fn complete(
    driver: &mut EmbeddedDriver,
    conductor: &mut ClientConductor,
    submit: impl FnOnce(&mut ClientConductor) -> Result<u64, ConductorError>,
) -> Outcome {
    let sequence = submit(conductor).unwrap();
    let _ = driver.do_work().unwrap();
    let mut outcome = None;
    let _ = conductor.poll(usize::MAX, |completion| {
        assert_eq!(completion.sequence, sequence);
        outcome = Some(completion.outcome);
    });
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

/// Records `point` of the message at position 0 of trace `[1, 1]`.
fn record(
    journal: ClientJournal,
    driver_id: [u64; 2],
    point: Point,
    publication: PublicationId,
) -> (u64, TraceWriter) {
    let (number, raw) = journal.into_parts();
    let observer = ObserverId {
        driver: driver_id,
        journal: number,
    };
    let mut writer = trace_writer(raw, observer, 1).unwrap();
    let observed = HostMonotonicClock::new(1).now();
    let record = TraceRecord {
        point,
        publication,
        lane: 0,
        position: 0,
        ids: TraceIds {
            trace_id: [1, 1],
            span_id: 1,
            parent_span_id: 0,
            message_id: 1,
        },
        observed,
        subscriber: (point == Point::SubscriberPoll).then_some(SubscriberId {
            driver: driver_id,
            registration: 9,
            incarnation: 1,
        }),
        packet: None,
        root: point == Point::Publish,
    };
    let stamp = Stamp {
        time: observed.time,
        clock: observed.clock,
        epoch: observed.epoch,
    };
    let _ = writer.record(&record, stamp).unwrap();
    (number, writer)
}

#[test]
fn trace_numbers_drawn_between_journals_are_not_missed_journals() {
    let mut driver = EmbeddedDriver::with_config(DriverConfig::default()).unwrap();
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
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        })
        .unwrap();
    let publication = PublicationId::from(driver.trace_identity(stream).unwrap());
    let driver_id = driver.driver_id();
    let instance = (u128::from(driver_id[0]) << 64) | u128::from(driver_id[1]);
    let mut tool = MirrorTool::new(instance);
    let _ = tool.scan(&driver.trace_mirror());

    let mut conductor = driver.connect().unwrap();
    let Outcome::Publication(_publishing) = complete(&mut driver, &mut conductor, |conductor| {
        conductor.add_publication(KEY, true)
    }) else {
        panic!("expected a publication");
    };
    let registration = _publishing.origin().unwrap().registration();
    for _ in 0..2 {
        let _ = driver.next_trace_number().unwrap();
    }
    let publisher = journal(&mut driver, &mut conductor, registration);
    let _ = tool.scan(&driver.trace_mirror());
    for _ in 0..3 {
        let _ = driver.next_trace_number().unwrap();
    }
    let Outcome::Subscription(_subscription) = complete(&mut driver, &mut conductor, |conductor| {
        conductor.add_subscription(KEY, SubscriberRole::Optional)
    }) else {
        panic!("expected a subscription");
    };
    let observed = _subscription.origin().unwrap().registration();
    let subscriber = journal(&mut driver, &mut conductor, observed);
    let _ = driver.next_trace_number().unwrap();
    assert!(
        subscriber.journal() > publisher.journal() + 1,
        "the journal numbers have a gap"
    );
    let _ = tool.scan(&driver.trace_mirror());

    let writers = [
        record(publisher, driver_id, Point::Publish, publication),
        record(subscriber, driver_id, Point::SubscriberPoll, publication),
    ];
    for number in writers.iter().map(|(number, _)| *number) {
        assert!(matches!(
            complete(&mut driver, &mut conductor, |conductor| {
                conductor.close_journal(number, 64)
            }),
            Outcome::Succeeded
        ));
    }
    // Dropping the writers closes the journals.
    drop(writers);
    for _ in 0..8 {
        let _ = driver.do_work().unwrap();
    }
    let scan = tool.scan(&driver.trace_mirror());
    assert_eq!(scan.missed, 0);
    assert_eq!(tool.missed(), (0, 0));
    assert_eq!(driver.trace_mirror().assigned_sequence(), 2);
    let report = tool.report().unwrap();
    assert_eq!(report.trace([1, 1]), TraceAnswer::Final(Verdict::Complete));
}
