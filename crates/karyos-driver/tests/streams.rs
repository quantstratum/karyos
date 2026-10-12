// SPDX-License-Identifier: Apache-2.0

//! Stream removal and reclamation (quantstratum-docs: karyos/design/stream-lifecycle.md).

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use karyos_client::{ClientConductor, Completion, OfferOutcome, Outcome};
use karyos_driver::{
    DriverConfig, DriverError, EmbeddedDriver, StreamConfig, StreamHandle, StreamState,
};
use karyos_protocol::cnc::{ErrorCode, StreamKey, SubscriberRole};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, Role};
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
        },
        allow_unconnected: true,
    }
}

fn key(stream_id: i32) -> StreamKey {
    StreamKey {
        stream_id,
        session_id: 1,
    }
}

fn drain(client: &mut ClientConductor) -> Vec<Completion> {
    let mut done = Vec::new();
    let _ = client.poll(usize::MAX, |completion| done.push(completion));
    done
}

fn state(driver: &EmbeddedDriver, stream: StreamHandle) -> StreamState {
    driver.stream_state(stream).unwrap()
}

#[test]
fn a_stream_is_freed_only_after_every_capability_is_gone() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let mut client = driver.connect().unwrap();
    // A direct publication, a command subscription, and a held entry.
    let mut direct = driver.publication(stream).unwrap();
    let _ = client
        .add_subscription(key(2), SubscriberRole::Required)
        .unwrap();
    let _ = driver.do_work().unwrap();
    let subscription = match drain(&mut client).pop().unwrap().outcome {
        Outcome::Subscription(subscription) => subscription,
        other => panic!("unexpected {other:?}"),
    };
    let _ = client
        .add_subscription(key(2), SubscriberRole::Optional)
        .unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.live_leases(stream).unwrap(), 3);

    driver.remove_stream(stream).unwrap();
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    // Live capabilities keep working while retiring.
    assert!(matches!(
        direct.offer(b"x").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    drop(direct);
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    drop(subscription);
    let _ = driver.do_work().unwrap();
    // The held (never taken) entry still holds a lease.
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    assert_eq!(driver.live_leases(stream).unwrap(), 1);
    // Closing the client drops it.
    client.close();
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Freed);
    assert!(matches!(
        driver.live_leases(stream),
        Err(DriverError::UnknownStream { .. })
    ));
}

#[test]
fn a_retiring_stream_refuses_new_capabilities_and_its_key() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let mut client = driver.connect().unwrap();
    let _kept = driver.subscribe(stream, Role::Optional).unwrap();
    driver.remove_stream(stream).unwrap();
    // Idempotent while retiring.
    driver.remove_stream(stream).unwrap();
    assert!(matches!(
        driver.publication(stream),
        Err(DriverError::StreamRetiring { .. })
    ));
    let request = client.add_publication(key(2), false).unwrap();
    let _ = driver.do_work().unwrap();
    let done = drain(&mut client);
    assert_eq!(done[0].sequence, request);
    assert!(matches!(
        done[0].outcome,
        Outcome::Refused {
            code: ErrorCode::UnknownStream,
            ..
        }
    ));
    assert!(matches!(
        driver.add_stream(stream_config(2)),
        Err(DriverError::DuplicateStream { .. })
    ));
    drop(_kept);
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Freed);
    // Freed: the key can be added again; the old handle stays freed.
    let renewed = driver.add_stream(stream_config(2)).unwrap();
    assert_ne!(renewed, stream);
    assert_eq!(state(&driver, stream), StreamState::Freed);
    assert_eq!(state(&driver, renewed), StreamState::Active);
    assert!(matches!(
        driver.remove_stream(stream),
        Err(DriverError::UnknownStream { .. })
    ));
    assert!(driver.subscribe(stream, Role::Optional).is_err());
}

#[test]
fn foreign_handles_are_refused() {
    let mut first = EmbeddedDriver::new().unwrap();
    let mut second = EmbeddedDriver::new().unwrap();
    let stream = first.add_stream(stream_config(2)).unwrap();
    let _ = second.add_stream(stream_config(2)).unwrap();
    assert!(matches!(
        second.remove_stream(stream),
        Err(DriverError::UnknownStream { .. })
    ));
    assert!(second.stream_state(stream).is_err());
    assert_eq!(first.stream_state(stream).unwrap(), StreamState::Active);
}

#[test]
fn a_queued_remove_keeps_a_retiring_stream_until_served() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let mut client = driver.connect().unwrap();
    let _ = client
        .add_subscription(key(2), SubscriberRole::Required)
        .unwrap();
    let _ = driver.do_work().unwrap();
    let subscription = match drain(&mut client).pop().unwrap().outcome {
        Outcome::Subscription(subscription) => subscription,
        other => panic!("unexpected {other:?}"),
    };
    let remove = client.remove_subscription(subscription).unwrap();
    driver.remove_stream(stream).unwrap();
    // This cycle frees nothing (the queued Remove keeps its registration),
    // then serves the Remove.
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    let done = drain(&mut client);
    assert_eq!(done[0].sequence, remove);
    assert!(matches!(done[0].outcome, Outcome::Succeeded));
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Freed);
}

#[test]
fn a_queued_add_binds_to_the_stream_under_its_key_at_execution() {
    let config = DriverConfig {
        command_budget: 1,
        cycles_between_drains: 1,
        broadcast_capacity: 1024,
        ..DriverConfig::default()
    };
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let old = driver.add_stream(stream_config(2)).unwrap();
    // The scan starts at the first client admitted.
    let mut other = driver.connect().unwrap();
    let mut client = driver.connect().unwrap();
    // Queue an Add for key 2 behind another client's command (budget 1).
    let _ = other
        .add_subscription(key(99), SubscriberRole::Optional)
        .unwrap();
    let request = client
        .add_subscription(key(2), SubscriberRole::Optional)
        .unwrap();
    driver.remove_stream(old).unwrap();
    // Cycle 1 frees the old stream and serves the other client.
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, old), StreamState::Freed);
    let renewed = driver.add_stream(stream_config(2)).unwrap();
    // Cycle 2 serves the queued Add against the new stream.
    let _ = driver.do_work().unwrap();
    let done = drain(&mut client);
    assert_eq!(done[0].sequence, request);
    assert!(matches!(done[0].outcome, Outcome::Subscription(_)));
    drop(done);
    assert_eq!(state(&driver, renewed), StreamState::Active);
}

#[test]
fn unknown_outcomes_leave_only_what_actually_executed() {
    let config = DriverConfig {
        command_budget: 1,
        cycles_between_drains: 1,
        broadcast_capacity: 1024,
        ..DriverConfig::default()
    };
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let mut slow = driver.connect().unwrap();
    let mut busy = driver.connect().unwrap();
    // An Add that executes, then a refused one, both answered while the
    // slow client never polls.
    let _ = slow
        .add_subscription(key(2), SubscriberRole::Optional)
        .unwrap();
    let _ = slow
        .add_subscription(key(99), SubscriberRole::Optional)
        .unwrap();
    // Lap the slow client.
    for _ in 0..60 {
        let _ = busy.add_subscription(key(99), SubscriberRole::Optional);
        let _ = driver.do_work().unwrap();
        let _ = drain(&mut busy);
    }
    let done = drain(&mut slow);
    assert_eq!(done.len(), 2);
    assert!(done.iter().all(|c| matches!(c.outcome, Outcome::Unknown)));
    // The executed Add left a held entry: one lease, until the client
    // closes. The refused one left nothing.
    assert_eq!(driver.live_leases(stream).unwrap(), 1);
    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    slow.close();
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Freed);
}

#[test]
fn max_streams_counts_retiring_streams_until_freed() {
    let config = DriverConfig {
        max_streams: 1,
        ..DriverConfig::default()
    };
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    assert!(matches!(
        driver.add_stream(stream_config(3)),
        Err(DriverError::TooManyStreams)
    ));
    let kept = driver.subscribe(stream, Role::Optional).unwrap();
    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    assert!(matches!(
        driver.add_stream(stream_config(3)),
        Err(DriverError::TooManyStreams)
    ));
    // The retiring key is reported as a duplicate before the quota.
    assert!(matches!(
        driver.add_stream(stream_config(2)),
        Err(DriverError::DuplicateStream { .. })
    ));
    drop(kept);
    let _ = driver.do_work().unwrap();
    assert!(driver.add_stream(stream_config(3)).is_ok());
}

#[test]
fn a_held_entry_taken_after_retirement_still_frees_on_drop() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let mut client = driver.connect().unwrap();
    let _ = client
        .add_subscription(key(2), SubscriberRole::Required)
        .unwrap();
    let _ = driver.do_work().unwrap();
    // Held, then the stream retires, then the client takes it.
    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    let subscription = match drain(&mut client).pop().unwrap().outcome {
        Outcome::Subscription(subscription) => subscription,
        other => panic!("unexpected {other:?}"),
    };
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    drop(subscription);
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Freed);
}

#[test]
fn a_queued_remove_with_zero_leases_still_blocks_freeing() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let mut client = driver.connect().unwrap();
    let _ = client.add_publication(key(2), false).unwrap();
    let _ = driver.do_work().unwrap();
    let publication = match drain(&mut client).pop().unwrap().outcome {
        Outcome::Publication(publication) => publication,
        other => panic!("unexpected {other:?}"),
    };
    let _ = client.remove_publication(publication).unwrap();
    assert_eq!(driver.live_leases(stream).unwrap(), 0);
    driver.remove_stream(stream).unwrap();
    // Leases are zero, but the queued Remove's registration remains until
    // this cycle serves it, after the freeing check.
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Freed);
}

#[test]
fn repeated_remove_and_re_add_keeps_no_history() {
    let config = DriverConfig {
        max_streams: 1,
        ..DriverConfig::default()
    };
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let mut previous = Vec::new();
    for _ in 0..100 {
        let stream = driver.add_stream(stream_config(2)).unwrap();
        let publication = driver.publication(stream).unwrap();
        drop(publication);
        driver.remove_stream(stream).unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(state(&driver, stream), StreamState::Freed);
        previous.push(stream);
    }
    // Every old handle stays freed; none names the live stream.
    let live = driver.add_stream(stream_config(2)).unwrap();
    assert!(previous.iter().all(|&old| old != live));
    assert!(
        previous
            .iter()
            .all(|&old| driver.stream_state(old).unwrap() == StreamState::Freed)
    );
}

#[test]
fn a_retiring_stream_keeps_conductor_duty_through_rotations() {
    use karyos_client::MessageLimit;

    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    driver.remove_stream(stream).unwrap();
    // Far more than three terms of data: rotation, reclamation and cleaning
    // must keep running while the stream retires.
    let payload = vec![7u8; 1500];
    let mut received = 0usize;
    for _ in 0..400 {
        // Bounded: without conductor duty the offer would never be
        // accepted again after the prepared terms are used up.
        let mut attempts = 0;
        loop {
            attempts += 1;
            assert!(attempts < 10_000, "no progress: conductor duty stopped");
            match publication.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => break,
                _ => {
                    let _ = driver.do_work().unwrap();
                    let _ = subscription
                        .poll(|_, _| received += 1, MessageLimit::new(16))
                        .unwrap();
                }
            }
        }
        let _ = driver.do_work().unwrap();
        let _ = subscription
            .poll(|_, _| received += 1, MessageLimit::new(16))
            .unwrap();
    }
    for _ in 0..10_000 {
        if received == 400 {
            break;
        }
        let _ = driver.do_work().unwrap();
        let _ = subscription
            .poll(|_, _| received += 1, MessageLimit::new(16))
            .unwrap();
    }
    assert_eq!(received, 400);
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    drop(publication);
    drop(subscription);
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Freed);
}
