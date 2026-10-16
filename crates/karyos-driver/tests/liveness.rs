// SPDX-License-Identifier: Apache-2.0

//! Heartbeats and liveness (roadmap P4, batch p4b; quantstratum-docs:
//! `karyos/design/required-participant-loss.md`): the driver times out a
//! client whose heartbeat stopped, on the driver's clock, and a client
//! presumes the driver lost when the driver's heartbeat stops, on the
//! client's clock.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use karyos_client::{
    ClientConductor, ClientSubscription, ConductorError, ConflatedSubscription, MessageLimit,
    OfferOutcome, Outcome, PollSummary,
};
use karyos_driver::{
    DriverConfig, EmbeddedDriver, LossPolicy, MonotonicClock, SealReason, SealState, StreamConfig,
};
use karyos_protocol::cnc::{CloseReason, Event, LossPolicyCode, StreamKey, SubscriberRole};
use karyos_sys::conflation::ConflationConfig;
use karyos_sys::counters::CellRead;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

#[derive(Debug, Clone, Default)]
struct ManualClock {
    now: Arc<AtomicU64>,
    reads: Arc<AtomicU64>,
}

impl ManualClock {
    fn set(&self, now: u64) {
        self.now.store(now, Ordering::Relaxed);
    }

    fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }
}

impl MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.now.load(Ordering::Relaxed)
    }
}

const INTERVAL: u64 = 10;
const TIMEOUT: u64 = 100;

fn driver() -> (EmbeddedDriver, ManualClock) {
    let clock = ManualClock::default();
    let config = DriverConfig {
        heartbeat_interval: INTERVAL,
        client_liveness_timeout: TIMEOUT,
        ..DriverConfig::default()
    };
    let driver = EmbeddedDriver::with_clock(config, Box::new(clock.clone())).unwrap();
    (driver, clock)
}

fn counter(driver: &EmbeddedDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

fn subscribe(client: &mut ClientConductor) -> Result<u64, ConductorError> {
    client.add_subscription(
        StreamKey {
            stream_id: 99,
            session_id: 1,
        },
        SubscriberRole::Optional,
    )
}

/// A client beats on every poll, so the driver's manual clock alone
/// decides when it is late.
fn beating(driver: &mut EmbeddedDriver) -> ClientConductor {
    let mut client = driver.connect().unwrap();
    client.set_liveness(Duration::ZERO, Duration::from_secs(3600));
    client
}

#[test]
fn test_driver_liveness_a_silent_client_times_out_at_exactly_the_timeout() {
    let (mut driver, clock) = driver();
    let mut client = driver.connect().unwrap();
    // First sample at 0: the client's heartbeat never changes after it.
    let _ = driver.do_work().unwrap();
    clock.set(TIMEOUT - 1);
    assert_eq!(driver.do_work().unwrap(), 0);
    assert_eq!(counter(&driver, "clients timed out"), 0);
    assert!(subscribe(&mut client).is_ok());
    clock.set(TIMEOUT);
    // The served command above and the time-out are this cycle's work.
    let _ = driver.do_work().unwrap();
    assert_eq!(counter(&driver, "clients timed out"), 1);
    assert_eq!(counter(&driver, "clients faulty"), 0);
    // Its ring is closed: it learns it was disconnected and must connect
    // again. Timing out is not a detach proof: the slot stays charged until
    // the client closes.
    assert_eq!(subscribe(&mut client), Err(ConductorError::Closed));
    assert_eq!(driver.clients(), 1);
    drop(client);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.clients(), 0);
}

#[test]
fn test_driver_liveness_a_close_at_the_deadline_is_a_retirement_not_a_time_out() {
    let (mut driver, clock) = driver();
    let client = driver.connect().unwrap();
    let _ = driver.do_work().unwrap();
    clock.set(TIMEOUT);
    client.close();
    let _ = driver.do_work().unwrap();
    assert_eq!(counter(&driver, "clients timed out"), 0);
    assert_eq!(counter(&driver, "clients retired"), 1);
    assert_eq!(driver.clients(), 0);
}

#[test]
fn test_driver_liveness_a_beating_client_never_times_out() {
    let (mut driver, clock) = driver();
    let mut client = beating(&mut driver);
    for step in 0..50 {
        clock.set(step * (TIMEOUT / 2));
        let _ = client.poll(usize::MAX, |_| {});
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(counter(&driver, "clients timed out"), 0);
    assert!(subscribe(&mut client).is_ok());
}

#[test]
fn test_driver_liveness_a_paused_driver_does_not_time_out_a_client_that_kept_beating() {
    let (mut driver, clock) = driver();
    let mut client = beating(&mut driver);
    let _ = client.poll(usize::MAX, |_| {});
    let _ = driver.do_work().unwrap();
    // The driver pauses far past the timeout while the client keeps beating.
    let _ = client.poll(usize::MAX, |_| {});
    clock.set(10 * TIMEOUT);
    let _ = driver.do_work().unwrap();
    assert_eq!(counter(&driver, "clients timed out"), 0);
    assert!(subscribe(&mut client).is_ok());
}

#[test]
fn test_driver_liveness_the_clock_is_read_only_while_a_client_is_admitted() {
    let (mut driver, clock) = driver();
    let _ = driver.do_work().unwrap();
    assert_eq!(clock.reads(), 0);
    let client = driver.connect().unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(clock.reads(), 1);
    drop(client);
    let _ = driver.do_work().unwrap();
    let reads = clock.reads();
    let _ = driver.do_work().unwrap();
    assert_eq!(clock.reads(), reads);
}

#[test]
fn test_client_liveness_a_silent_driver_is_presumed_lost() {
    let (mut driver, _clock) = driver();
    let mut client = driver.connect().unwrap();
    client.set_liveness(Duration::from_millis(1), Duration::from_millis(10));
    // The driver's heartbeat never moves: it runs no duty.
    let _ = client.poll(usize::MAX, |_| {});
    assert!(!client.driver_lost());
    std::thread::sleep(Duration::from_millis(20));
    let _ = client.poll(usize::MAX, |_| {});
    assert!(client.driver_lost());
    assert_eq!(subscribe(&mut client), Err(ConductorError::Closed));
}

#[test]
fn test_client_liveness_a_beating_driver_is_never_lost() {
    let (mut driver, clock) = driver();
    let mut client = driver.connect().unwrap();
    client.set_liveness(Duration::from_millis(1), Duration::from_millis(10));
    for step in 0..20 {
        // Each driver cycle is one heartbeat interval later.
        clock.set(step * INTERVAL);
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |_| {});
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(!client.driver_lost());
}

// ---- p4b-2a: a lost client's subscribers under the stream's policy ----

fn stream_config(policy: LossPolicy) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
        },
        allow_unconnected: true,
        on_required_loss: policy,
        conflation: None,
    }
}

/// A client takes a required subscription to stream 2 and then goes
/// silent; the driver times it out. Returns the subscription the client
/// still holds.
fn lost_required_subscriber(
    driver: &mut EmbeddedDriver,
    clock: &ManualClock,
) -> (ClientConductor, ClientSubscription) {
    let mut client = beating(driver);
    let sequence = client
        .add_subscription(
            StreamKey {
                stream_id: 2,
                session_id: 1,
            },
            SubscriberRole::Required,
        )
        .unwrap();
    let mut done = Vec::new();
    while done.is_empty() {
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    let completion = done.remove(0);
    assert_eq!(completion.sequence, sequence);
    let Outcome::Subscription(subscription) = completion.outcome else {
        panic!("expected a subscription, got {:?}", completion.outcome);
    };
    // The client stops beating; the driver times it out.
    let _ = driver.do_work().unwrap();
    clock.set(clock.now.load(Ordering::Relaxed) + TIMEOUT);
    let _ = driver.do_work().unwrap();
    assert_eq!(counter(driver, "clients timed out"), 1);
    (client, subscription)
}

/// Every loss record the driver's loss report retains.
fn losses(driver: &EmbeddedDriver) -> Vec<karyos_sys::diag::LossRecord> {
    let mut records = Vec::new();
    let scan = driver
        .loss_report()
        .scan(&mut 0, |_, record| records.push(record));
    assert_eq!((scan.overwritten, scan.stopped), (0, None));
    records
}

fn poll_once(subscription: &mut ClientSubscription) -> PollSummary {
    subscription.poll(|_, _| {}, MessageLimit::new(16)).unwrap()
}

/// required-participant-loss.md, Tests: a timed-out client that resumes
/// gets `Disconnected` (its command ring is closed: every new request is
/// refused) and `Revoked`, and can only rejoin through a new admission.
#[test]
fn test_driver_loss_a_resumed_client_is_disconnected_and_revoked() {
    for policy in [LossPolicy::Hold, LossPolicy::Continue, LossPolicy::Abort] {
        let (mut driver, clock) = driver();
        let _stream = driver.add_stream(stream_config(policy)).unwrap();
        let (mut client, mut subscription) = lost_required_subscriber(&mut driver, &clock);
        // The client resumes.
        let refused = client.add_subscription(
            StreamKey {
                stream_id: 2,
                session_id: 1,
            },
            SubscriberRole::Optional,
        );
        assert!(
            matches!(refused, Err(ConductorError::Closed)),
            "{policy:?}: {refused:?}"
        );
        assert!(
            poll_once(&mut subscription).revoked.is_some(),
            "{policy:?}: not revoked"
        );
        // A new admission is a new client.
        let mut again = beating(&mut driver);
        assert!(
            again
                .add_subscription(
                    StreamKey {
                        stream_id: 2,
                        session_id: 1,
                    },
                    SubscriberRole::Optional,
                )
                .is_ok(),
            "{policy:?}"
        );
    }
}

#[test]
fn test_driver_loss_hold_revokes_a_lost_clients_required_subscriber() {
    let (mut driver, clock) = driver();
    let stream = driver.add_stream(stream_config(LossPolicy::Hold)).unwrap();
    let (_client, mut subscription) = lost_required_subscriber(&mut driver, &clock);
    assert_eq!(counter(&driver, "participants revoked"), 1);
    assert_eq!(counter(&driver, "required participants lost"), 1);
    // No loan was held: the bound is withdrawn at once and the reader is
    // told it was revoked.
    assert!(poll_once(&mut subscription).revoked.is_some());
    assert_eq!(driver.seal_state(stream).unwrap(), SealState::Active);
    // The publisher is not bounded by the lost reader any more.
    let mut publication = driver.publication(stream).unwrap();
    let data = vec![3u8; 1000];
    for _ in 0..200 {
        let _ = driver.do_work().unwrap();
        assert!(!matches!(
            publication.offer(&data).unwrap(),
            OfferOutcome::BackPressured
        ));
    }
}

#[test]
fn test_driver_loss_continue_admits_with_a_reservation_and_revokes() {
    let (mut driver, clock) = driver();
    let stream = driver
        .add_stream(stream_config(LossPolicy::Continue))
        .unwrap();
    let (_client, mut subscription) = lost_required_subscriber(&mut driver, &clock);
    assert_eq!(counter(&driver, "required participants lost"), 1);
    assert!(poll_once(&mut subscription).revoked.is_some());
    assert_eq!(driver.seal_state(stream).unwrap(), SealState::Active);
    // Only the lost participant is reported: the incarnation goes on.
    let records = losses(&driver);
    assert_eq!(records.len(), 1);
    assert_eq!((records[0].kind, records[0].applied_policy), (2, 2));
}

#[test]
fn test_driver_loss_abort_seals_the_stream() {
    let (mut driver, clock) = driver();
    let stream = driver.add_stream(stream_config(LossPolicy::Abort)).unwrap();
    let (_client, _subscription) = lost_required_subscriber(&mut driver, &clock);
    assert_eq!(counter(&driver, "required participants lost"), 1);
    assert_ne!(driver.seal_state(stream).unwrap(), SealState::Active);
    // The loss report names the lost participant, then the aborted
    // incarnation, both under the abort policy (code 3).
    let records = losses(&driver);
    let kinds: Vec<_> = records.iter().map(|record| record.kind).collect();
    assert_eq!(kinds, [2, 3]);
    let identity = driver.trace_identity(stream).unwrap();
    for record in &records {
        assert_eq!((record.configured_policy, record.applied_policy), (3, 3));
        assert_eq!(
            record.instance,
            u128::from(identity.driver[0]) << 64 | u128::from(identity.driver[1])
        );
        assert_eq!(record.stream_registration, identity.registration);
        assert_eq!(record.incarnation, identity.incarnation);
        assert_eq!(record.stream_id, 2);
        assert_ne!((record.participant, record.client), (0, 0));
        assert!(record.time > 0);
    }
}

#[test]
fn test_abort_seal_closes_conflation_table_after_feeder_reaches_end() {
    let (mut driver, clock) = driver();
    let mut config = stream_config(LossPolicy::Abort);
    config.conflation = Some(ConflationConfig {
        keys: 4,
        value_capacity: 8,
        journal_capacity: 1024,
    });
    let stream = driver.add_stream(config).unwrap();
    let mut conflated: ConflatedSubscription = driver.subscribe_conflated(stream).unwrap();
    let (_client, _subscription) = lost_required_subscriber(&mut driver, &clock);
    assert_ne!(driver.seal_state(stream).unwrap(), SealState::Active);

    let mut report = conflated.poll_changed(|_, _| {});
    for _ in 0..8 {
        let _ = driver.do_work().unwrap();
        report = conflated.poll_changed(|_, _| {});
        if report.closed {
            break;
        }
    }
    assert!(report.closed, "Abort seal must close the conflation writer");
}

// ---- p4b-2b: the driver reports losses as events ----

const LOST_STREAM: StreamKey = StreamKey {
    stream_id: 2,
    session_id: 1,
};

/// A driver cycle that the observing client survives: it beats first and
/// takes what the driver broadcast after.
fn observed_work(driver: &mut EmbeddedDriver, observer: &mut ClientConductor) -> Vec<Event> {
    let _ = observer.poll(usize::MAX, |_| {});
    let _ = driver.do_work().unwrap();
    let _ = observer.poll(usize::MAX, |_| {});
    observer.take_events().collect()
}

/// Admits a required subscriber of stream 2 for a second client that the
/// test later times out, while `observer` keeps beating.
fn required_subscriber(
    driver: &mut EmbeddedDriver,
    observer: &mut ClientConductor,
) -> (ClientConductor, ClientSubscription) {
    let mut client = beating(driver);
    let _ = client
        .add_subscription(LOST_STREAM, SubscriberRole::Required)
        .unwrap();
    let mut done = Vec::new();
    while done.is_empty() {
        assert!(observed_work(driver, observer).is_empty());
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    let Outcome::Subscription(subscription) = done.remove(0).outcome else {
        panic!("expected a subscription");
    };
    // The driver samples the client's last beat at this time.
    assert!(observed_work(driver, observer).is_empty());
    (client, subscription)
}

fn time_out(clock: &ManualClock) {
    clock.set(clock.now.load(Ordering::Relaxed) + TIMEOUT);
}

fn assert_lost(event: &Event, expected: LossPolicyCode) {
    let Event::ParticipantLost { stream, policy, .. } = event else {
        panic!("expected ParticipantLost, got {event:?}");
    };
    assert_eq!(*stream, LOST_STREAM);
    assert_eq!(*policy, expected);
}

#[test]
fn test_driver_events_hold_without_a_loan_reports_the_loss_and_the_withdrawal_at_once() {
    let (mut driver, clock) = driver();
    let _stream = driver.add_stream(stream_config(LossPolicy::Hold)).unwrap();
    let mut observer = beating(&mut driver);
    let (_client, _subscription) = required_subscriber(&mut driver, &mut observer);
    time_out(&clock);
    let events = observed_work(&mut driver, &mut observer);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_lost(&events[0], LossPolicyCode::Hold);
    assert!(matches!(
        events[1],
        Event::RequiredBoundWithdrawn {
            stream: LOST_STREAM,
            ..
        }
    ));
    assert_eq!(counter(&driver, "events not sent"), 0);
}

#[test]
fn test_driver_events_continue_reports_only_the_loss() {
    let (mut driver, clock) = driver();
    let _stream = driver
        .add_stream(stream_config(LossPolicy::Continue))
        .unwrap();
    let mut observer = beating(&mut driver);
    let (_client, _subscription) = required_subscriber(&mut driver, &mut observer);
    time_out(&clock);
    let events = observed_work(&mut driver, &mut observer);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_lost(&events[0], LossPolicyCode::Continue);
}

#[test]
fn test_driver_events_abort_reports_the_loss_and_the_closed_publication() {
    let (mut driver, clock) = driver();
    let _stream = driver.add_stream(stream_config(LossPolicy::Abort)).unwrap();
    let mut observer = beating(&mut driver);
    let (_client, _subscription) = required_subscriber(&mut driver, &mut observer);
    time_out(&clock);
    let events = observed_work(&mut driver, &mut observer);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_lost(&events[0], LossPolicyCode::Abort);
    assert_eq!(
        events[1],
        Event::PublicationClosed {
            stream: LOST_STREAM,
            lane: Lane::ZERO,
            reason: CloseReason::RequiredParticipantLost,
        }
    );
}

#[test]
fn test_driver_events_an_optional_subscriber_loss_reports_nothing() {
    let (mut driver, clock) = driver();
    let _stream = driver.add_stream(stream_config(LossPolicy::Abort)).unwrap();
    let mut observer = beating(&mut driver);
    let mut client = beating(&mut driver);
    let _ = client
        .add_subscription(LOST_STREAM, SubscriberRole::Optional)
        .unwrap();
    let mut done = Vec::new();
    while done.is_empty() {
        let _ = observed_work(&mut driver, &mut observer);
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    let _ = observed_work(&mut driver, &mut observer);
    time_out(&clock);
    assert!(observed_work(&mut driver, &mut observer).is_empty());
    assert_eq!(counter(&driver, "participants revoked"), 1);
}

#[test]
fn test_driver_events_an_orderly_close_at_the_deadline_is_not_a_loss() {
    let (mut driver, clock) = driver();
    let stream = driver.add_stream(stream_config(LossPolicy::Abort)).unwrap();
    let mut observer = beating(&mut driver);
    let (client, subscription) = required_subscriber(&mut driver, &mut observer);
    time_out(&clock);
    drop(subscription);
    client.close();
    assert!(observed_work(&mut driver, &mut observer).is_empty());
    assert_eq!(counter(&driver, "clients timed out"), 0);
    assert_eq!(counter(&driver, "required participants lost"), 0);
    assert_eq!(driver.seal_state(stream).unwrap(), SealState::Active);
}

#[test]
fn test_driver_events_abort_reports_one_closing_for_two_lost_participants() {
    let (mut driver, clock) = driver();
    let _stream = driver.add_stream(stream_config(LossPolicy::Abort)).unwrap();
    let mut observer = beating(&mut driver);
    let mut client = beating(&mut driver);
    for _ in 0..2 {
        let _ = client
            .add_subscription(LOST_STREAM, SubscriberRole::Required)
            .unwrap();
    }
    let mut done = Vec::new();
    while done.len() < 2 {
        assert!(observed_work(&mut driver, &mut observer).is_empty());
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    assert!(observed_work(&mut driver, &mut observer).is_empty());
    time_out(&clock);
    let events = observed_work(&mut driver, &mut observer);
    assert_eq!(events.len(), 3, "{events:?}");
    assert_lost(&events[0], LossPolicyCode::Abort);
    let closings = events
        .iter()
        .filter(|event| matches!(event, Event::PublicationClosed { .. }))
        .count();
    assert_eq!(closings, 1, "{events:?}");
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::ParticipantLost { .. }))
            .count(),
        2
    );
}

// ---- #96: the typed seal reason ----

/// Polls `reader` until it reports the end, running the driver between
/// polls so that it positions the seal.
fn read_to_end(driver: &mut EmbeddedDriver, reader: &mut ClientSubscription) -> PollSummary {
    for _ in 0..100 {
        let summary = poll_once(reader);
        if summary.closed.is_some() {
            return summary;
        }
        let _ = driver.do_work().unwrap();
    }
    panic!("the reader never reached the end");
}

/// An `abort` seal carries its reason to an in-process reader at the seal
/// position; a later removal keeps it.
#[test]
fn test_seal_reason_abort_reaches_a_reader_and_survives_removal() {
    let (mut driver, clock) = driver();
    let stream = driver.add_stream(stream_config(LossPolicy::Abort)).unwrap();
    let mut reader = driver.subscribe(stream, Role::Optional).unwrap();
    assert_eq!(driver.seal_reason(stream).unwrap(), None);
    let (_client, _subscription) = lost_required_subscriber(&mut driver, &clock);
    assert_eq!(
        driver.seal_reason(stream).unwrap(),
        Some(SealReason::RequiredParticipantLost)
    );
    let summary = read_to_end(&mut driver, &mut reader);
    assert_eq!(
        summary.close_reason,
        Some(SealReason::RequiredParticipantLost)
    );
    driver.remove_stream(stream).unwrap();
    assert_eq!(
        driver.seal_reason(stream).unwrap(),
        Some(SealReason::RequiredParticipantLost)
    );
}

/// A removal seals with `StreamRemoved`, which readers and the closed
/// publisher see, and reports the closing once to every client.
#[test]
fn test_seal_reason_removal_reaches_handles_and_is_reported_once() {
    let (mut driver, _clock) = driver();
    let stream = driver.add_stream(stream_config(LossPolicy::Hold)).unwrap();
    let mut observer = beating(&mut driver);
    assert!(observed_work(&mut driver, &mut observer).is_empty());
    let mut reader = driver.subscribe(stream, Role::Optional).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    assert!(matches!(
        publication.offer(b"last").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    driver.remove_stream(stream).unwrap();
    driver.remove_stream(stream).unwrap();
    assert_eq!(
        observed_work(&mut driver, &mut observer),
        [Event::PublicationClosed {
            stream: LOST_STREAM,
            lane: Lane::ZERO,
            reason: CloseReason::StreamRemoved,
        }]
    );
    assert_eq!(
        driver.seal_reason(stream).unwrap(),
        Some(SealReason::StreamRemoved)
    );
    assert_eq!(publication.seal_reason(), None);
    assert_eq!(publication.offer(b"late").unwrap(), OfferOutcome::Closed);
    assert_eq!(publication.seal_reason(), Some(SealReason::StreamRemoved));
    drop(publication);
    let summary = read_to_end(&mut driver, &mut reader);
    assert_eq!(summary.close_reason, Some(SealReason::StreamRemoved));
    assert!(observed_work(&mut driver, &mut observer).is_empty());
}
