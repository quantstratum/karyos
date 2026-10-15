// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests of client commands and driver responses
//! (quantstratum-docs: karyos/design/client-commands.md).

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use karyos_client::{
    ClientConductor, ClientPublication, ClientSubscription, Completion, ConductorError,
    MessageLimit, OfferOutcome, Outcome,
};
use karyos_driver::{DriverConfig, EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_protocol::cnc::{ErrorCode, StreamKey, SubscriberRole};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::LogBufferConfig;
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

fn stream_config(stream_id: i32) -> StreamConfig {
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
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
        },
        allow_unconnected: false,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation: None,
    }
}

fn key(stream_id: i32) -> StreamKey {
    StreamKey {
        stream_id,
        session_id: 1,
    }
}

fn driver_with(config: DriverConfig) -> (EmbeddedDriver, StreamHandle) {
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    (driver, stream)
}

/// Runs a duty cycle, then drains the client: the m = 1 pattern.
fn cycle(driver: &mut EmbeddedDriver, client: &mut ClientConductor) -> Vec<Completion> {
    let _ = driver.do_work().unwrap();
    let mut done = Vec::new();
    let report = client.poll(usize::MAX, |completion| done.push(completion));
    assert!(report.drained);
    done
}

/// Runs `count` duty cycles, draining the client after each.
fn cycles(
    driver: &mut EmbeddedDriver,
    client: &mut ClientConductor,
    count: usize,
) -> Vec<Completion> {
    (0..count).flat_map(|_| cycle(driver, client)).collect()
}

fn publication(outcome: Outcome) -> ClientPublication {
    match outcome {
        Outcome::Publication(publication) => publication,
        other => panic!("expected a publication, got {other:?}"),
    }
}

fn subscription(outcome: Outcome) -> ClientSubscription {
    match outcome {
        Outcome::Subscription(subscription) => subscription,
        other => panic!("expected a subscription, got {other:?}"),
    }
}

#[test]
fn requests_round_trip_and_data_flows() {
    let (mut driver, stream) = driver_with(DriverConfig::default());
    let mut client = driver.connect().unwrap();
    let sub_request = client
        .add_subscription(key(2), SubscriberRole::Required)
        .unwrap();
    let pub_request = client.add_publication(key(2), false).unwrap();
    // One command per ring per cycle; held until the client takes them:
    // two live leases.
    let _ = driver.do_work().unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.live_leases(stream).unwrap(), 2);
    let mut done = Vec::new();
    let _ = client.poll(usize::MAX, |completion| done.push(completion));
    assert_eq!(done.len(), 2);
    let mut publication_handle = None;
    let mut subscription_handle = None;
    for completion in done {
        if completion.sequence == pub_request {
            publication_handle = Some(publication(completion.outcome));
        } else {
            assert_eq!(completion.sequence, sub_request);
            subscription_handle = Some(subscription(completion.outcome));
        }
    }
    let mut publication_handle = publication_handle.unwrap();
    let mut subscription_handle = subscription_handle.unwrap();
    assert_eq!(driver.live_leases(stream).unwrap(), 2);

    assert!(matches!(
        publication_handle.offer(b"hello").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let mut seen = Vec::new();
    let _ = subscription_handle
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(4))
        .unwrap();
    assert_eq!(seen, vec![b"hello".to_vec()]);

    let remove_pub = client.remove_publication(publication_handle).unwrap();
    let remove_sub = client.remove_subscription(subscription_handle).unwrap();
    assert_eq!(driver.live_leases(stream).unwrap(), 0);
    let done = cycles(&mut driver, &mut client, 2);
    assert_eq!(done.len(), 2);
    for completion in done {
        assert!([remove_pub, remove_sub].contains(&completion.sequence));
        assert!(matches!(completion.outcome, Outcome::Succeeded));
    }
}

#[test]
fn an_observer_subscription_delivers_and_never_bounds_the_publisher() {
    let (mut driver, stream) = driver_with(DriverConfig::default());
    let mut client = driver.connect().unwrap();
    let sub_request = client
        .add_subscription(key(2), SubscriberRole::Observer)
        .unwrap();
    let pub_request = client.add_publication(key(2), false).unwrap();
    let mut publication_handle = None;
    let mut observer = None;
    for completion in cycles(&mut driver, &mut client, 2) {
        if completion.sequence == pub_request {
            publication_handle = Some(publication(completion.outcome));
        } else {
            assert_eq!(completion.sequence, sub_request);
            observer = Some(subscription(completion.outcome));
        }
    }
    let mut publication_handle = publication_handle.unwrap();
    let mut observer = observer.unwrap();
    // The observer keeps the publication connected and receives.
    assert!(matches!(
        publication_handle.offer(b"seen").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let mut seen = Vec::new();
    let _ = observer
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(4))
        .unwrap();
    assert_eq!(seen, vec![b"seen".to_vec()]);
    // Stalled, it never back-pressures the publisher: many terms go by.
    let data = vec![5u8; 7000];
    for _ in 0..60 {
        let mut accepted = false;
        for _ in 0..100 {
            if matches!(
                publication_handle.offer(&data).unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                accepted = true;
                break;
            }
            let _ = driver.do_work().unwrap();
        }
        assert!(accepted, "an observer bounded the publisher");
        let _ = driver.do_work().unwrap();
    }
    let summary = observer.poll(|_, _| {}, MessageLimit::new(4)).unwrap();
    assert!(summary.overrun.is_some(), "the stalled observer was lapped");
    assert_eq!(driver.live_leases(stream).unwrap(), 2);
}

#[test]
fn refusals_have_no_effect() {
    let (mut driver, stream) = driver_with(DriverConfig::default());
    let mut client = driver.connect().unwrap();
    let first = client.add_publication(key(2), false).unwrap();
    let second = client.add_publication(key(2), false).unwrap();
    let unknown = client
        .add_subscription(key(99), SubscriberRole::Optional)
        .unwrap();
    let mut outcomes = cycles(&mut driver, &mut client, 3);
    outcomes.sort_by_key(|completion| completion.sequence);
    assert_eq!(
        outcomes.iter().map(|c| c.sequence).collect::<Vec<_>>(),
        vec![first, second, unknown]
    );
    assert!(matches!(outcomes[0].outcome, Outcome::Publication(_)));
    assert!(matches!(
        outcomes[1].outcome,
        Outcome::Refused {
            code: ErrorCode::PublicationTaken,
            ..
        }
    ));
    assert!(matches!(
        outcomes[2].outcome,
        Outcome::Refused {
            code: ErrorCode::UnknownStream,
            detail: 99
        }
    ));
    // Only the accepted request holds a lease.
    assert_eq!(driver.live_leases(stream).unwrap(), 1);
}

#[test]
fn a_foreign_handle_cannot_be_removed() {
    let (mut driver, _) = driver_with(DriverConfig::default());
    let mut owner = driver.connect().unwrap();
    let mut other = driver.connect().unwrap();
    let _ = owner.add_publication(key(2), false).unwrap();
    let handle = publication(cycle(&mut driver, &mut owner).pop().unwrap().outcome);
    let (handle, error) = other.remove_publication(handle).unwrap_err();
    assert_eq!(error, ConductorError::ForeignHandle);
    // A handle from the direct API has no origin either.
    let other_stream = driver_stream(&mut driver);
    let direct = driver
        .subscribe(other_stream, karyos_sys::log_buffer::Role::Optional)
        .unwrap();
    assert!(matches!(
        owner.remove_subscription(direct),
        Err((_, ConductorError::ForeignHandle))
    ));
    drop(handle);
}

fn driver_stream(driver: &mut EmbeddedDriver) -> StreamHandle {
    driver.add_stream(stream_config(3)).unwrap()
}

#[test]
fn remove_on_a_full_ring_returns_the_handle() {
    let config = DriverConfig {
        max_pending_per_client: 64,
        ..DriverConfig::default()
    };
    let (mut driver, stream) = driver_with(config);
    let mut client = driver.connect().unwrap();
    let _ = client.add_publication(key(2), false).unwrap();
    let handle = publication(cycle(&mut driver, &mut client).pop().unwrap().outcome);
    // Fill the ring with requests the driver has not served yet.
    while client
        .add_subscription(key(99), SubscriberRole::Optional)
        .is_ok()
    {}
    let (handle, error) = client.remove_publication(handle).unwrap_err();
    assert_eq!(error, ConductorError::Full);
    assert_eq!(driver.live_leases(stream).unwrap(), 1);
    // Drain, then retry.
    for _ in 0..64 {
        let _ = cycle(&mut driver, &mut client);
    }
    let removed = client.remove_publication(handle).unwrap();
    let done = cycle(&mut driver, &mut client);
    assert!(
        done.iter()
            .any(|c| c.sequence == removed && matches!(c.outcome, Outcome::Succeeded))
    );
    assert_eq!(driver.live_leases(stream).unwrap(), 0);
}

#[test]
fn a_paused_client_does_not_delay_another() {
    let config = DriverConfig {
        max_pending_per_client: 64,
        ..DriverConfig::default()
    };
    let (mut driver, _) = driver_with(config);
    let mut paused = driver.connect().unwrap();
    let mut active = driver.connect().unwrap();
    // The paused client fills its ring and never polls.
    while paused
        .add_subscription(key(99), SubscriberRole::Optional)
        .is_ok()
    {}
    let request = active.add_publication(key(2), false).unwrap();
    let mut done = Vec::new();
    for _ in 0..4 {
        done.extend(cycle(&mut driver, &mut active));
        if !done.is_empty() {
            break;
        }
    }
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].sequence, request);
    assert!(matches!(done[0].outcome, Outcome::Publication(_)));
}

#[test]
fn a_budget_of_one_serves_rings_in_turn() {
    let config = DriverConfig {
        command_budget: 1,
        cycles_between_drains: 1,
        broadcast_capacity: 1024,
        ..DriverConfig::default()
    };
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let _ = driver.add_stream(stream_config(2)).unwrap();
    let mut clients: Vec<_> = (0..3).map(|_| driver.connect().unwrap()).collect();
    for client in &mut clients {
        let _ = client.add_subscription(key(2), SubscriberRole::Optional);
        let _ = client.add_subscription(key(99), SubscriberRole::Optional);
    }
    // Six commands, one per cycle, alternating rings: every client gets its
    // first answer within the first three cycles.
    let mut answered = [0usize; 3];
    for cycle_index in 0..6 {
        let _ = driver.do_work().unwrap();
        for (index, client) in clients.iter_mut().enumerate() {
            let _ = client.poll(usize::MAX, |_| answered[index] += 1);
        }
        if cycle_index == 2 {
            assert_eq!(answered, [1, 1, 1]);
        }
    }
    assert_eq!(answered, [2, 2, 2]);
}

#[test]
fn a_lapped_client_reports_unknown_and_ignores_late_responses() {
    let config = DriverConfig {
        command_budget: 1,
        cycles_between_drains: 1,
        broadcast_capacity: 1024,
        max_pending_per_client: 64,
        ..DriverConfig::default()
    };
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let _ = driver.add_stream(stream_config(2)).unwrap();
    let mut slow = driver.connect().unwrap();
    let mut busy = driver.connect().unwrap();
    let request = slow
        .add_subscription(key(99), SubscriberRole::Optional)
        .unwrap();
    // The busy client's responses overrun the slow client's receiver.
    for _ in 0..60 {
        let _ = busy.add_subscription(key(99), SubscriberRole::Optional);
        let _ = cycle(&mut driver, &mut busy);
    }
    let mut done = Vec::new();
    let _ = slow.poll(usize::MAX, |completion| done.push(completion));
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].sequence, request);
    assert!(matches!(done[0].outcome, Outcome::Unknown));
    assert_eq!(slow.pending(), 0);
}

#[test]
fn poll_returns_within_its_limit() {
    let config = DriverConfig {
        max_pending_per_client: 64,
        ..DriverConfig::default()
    };
    let (mut driver, _) = driver_with(config);
    let mut reader = driver.connect().unwrap();
    let mut writer = driver.connect().unwrap();
    for _ in 0..20 {
        let _ = writer.add_subscription(key(99), SubscriberRole::Optional);
        let _ = driver.do_work().unwrap();
    }
    let report = reader.poll(5, |_| panic!("no response for this client"));
    assert_eq!(report.records, 5);
    assert!(!report.drained);
    let report = reader.poll(usize::MAX, |_| {});
    assert!(report.drained);
}

#[test]
fn close_while_full_retires_the_client_but_not_live_handles() {
    let config = DriverConfig {
        max_pending_per_client: 64,
        max_clients: 1,
        ..DriverConfig::default()
    };
    let (mut driver, stream) = driver_with(config);
    let mut client = driver.connect().unwrap();
    let _ = client.add_publication(key(2), false).unwrap();
    let mut handle = publication(cycle(&mut driver, &mut client).pop().unwrap().outcome);
    let _ = client
        .add_subscription(key(2), SubscriberRole::Optional)
        .unwrap();
    // Served but not taken: a held entry.
    let _ = driver.do_work().unwrap();
    while client
        .add_subscription(key(99), SubscriberRole::Optional)
        .is_ok()
    {}
    assert!(driver.connect().is_err());
    assert_eq!(driver.live_leases(stream).unwrap(), 2);

    client.close();
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.clients(), 0);
    // The held entry was dropped; the taken handle keeps its lease and works.
    assert_eq!(driver.live_leases(stream).unwrap(), 1);
    assert!(matches!(
        handle.offer(b"x").unwrap(),
        OfferOutcome::Accepted { .. } | OfferOutcome::NotConnected
    ));
    drop(handle);
    assert_eq!(driver.live_leases(stream).unwrap(), 0);
    // The admission slot is free again.
    assert!(driver.connect().is_ok());
}

#[test]
fn a_dropped_driver_makes_submitted_requests_unknown() {
    let (mut driver, _) = driver_with(DriverConfig::default());
    let mut client = driver.connect().unwrap();
    let request = client.add_publication(key(2), false).unwrap();
    drop(driver);
    let mut done = Vec::new();
    let report = client.poll(usize::MAX, |completion| done.push(completion));
    assert!(report.drained);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].sequence, request);
    assert!(matches!(done[0].outcome, Outcome::Unknown));
    assert_eq!(
        client.add_publication(key(2), false),
        Err(ConductorError::Closed)
    );
}

#[test]
fn a_response_taken_after_the_driver_dropped_is_unknown() {
    let (mut driver, _) = driver_with(DriverConfig::default());
    let mut client = driver.connect().unwrap();
    let request = client.add_publication(key(2), false).unwrap();
    // Served and answered, but the driver goes away before the take.
    let _ = driver.do_work().unwrap();
    drop(driver);
    let mut done = Vec::new();
    let _ = client.poll(usize::MAX, |completion| done.push(completion));
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].sequence, request);
    assert!(matches!(done[0].outcome, Outcome::Unknown));
}

#[test]
fn invalid_configurations_are_rejected() {
    let small = DriverConfig {
        broadcast_capacity: 1024,
        ..DriverConfig::default()
    };
    assert!(EmbeddedDriver::with_config(small).is_err());
    let zero = DriverConfig {
        command_budget: 0,
        ..DriverConfig::default()
    };
    assert!(EmbeddedDriver::with_config(zero).is_err());
    let ring = DriverConfig {
        ring_capacity: 1000,
        ..DriverConfig::default()
    };
    assert!(EmbeddedDriver::with_config(ring).is_err());
}

#[test]
fn a_panicking_callback_loses_no_unknown_notification() {
    let (mut driver, _) = driver_with(DriverConfig::default());
    let mut client = driver.connect().unwrap();
    let first = client.add_publication(key(2), false).unwrap();
    let second = client
        .add_subscription(key(2), SubscriberRole::Optional)
        .unwrap();
    drop(driver);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = client.poll(usize::MAX, |_| panic!("callback failed"));
    }));
    assert!(panicked.is_err());
    // Both are terminal; neither notification was lost. The one whose
    // callback panicked is delivered again.
    assert_eq!(client.pending(), 2);
    let mut done = Vec::new();
    let _ = client.poll(usize::MAX, |completion| done.push(completion));
    let mut sequences: Vec<_> = done.iter().map(|c| c.sequence).collect();
    sequences.sort_unstable();
    assert_eq!(sequences, vec![first, second]);
    assert!(done.iter().all(|c| matches!(c.outcome, Outcome::Unknown)));
    assert_eq!(client.pending(), 0);
}
