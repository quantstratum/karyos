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
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
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
    // Live capabilities are not revoked; the seal closes a publication on
    // its next attempt (`quantstratum-docs: karyos/design/publication-seal.md`).
    assert_eq!(direct.offer(b"x").unwrap(), OfferOutcome::Closed);
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
#[cfg_attr(
    miri,
    ignore = "hundreds of kilobytes through several rotations is too slow under Miri"
)]
fn a_retiring_stream_keeps_conductor_duty_until_its_seal_is_positioned() {
    use karyos_client::MessageLimit;
    use karyos_driver::SealState;

    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    // Far more than three terms of data before the removal: rotation,
    // reclamation and cleaning run, and a backlog is left unread.
    let payload = vec![7u8; 1500];
    let mut received = 0usize;
    for sent in 0..400 {
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
        if sent < 390 {
            let _ = subscription
                .poll(|_, _| received += 1, MessageLimit::new(16))
                .unwrap();
        }
    }
    driver.remove_stream(stream).unwrap();
    assert_eq!(publication.offer(&payload).unwrap(), OfferOutcome::Closed);
    // Positioning needs the retiring stream's conductor duty.
    let _ = driver.do_work().unwrap();
    let SealState::Positioned { position } = driver.seal_state(stream).unwrap() else {
        panic!("the seal was not positioned");
    };
    let mut closed = None;
    for _ in 0..10_000 {
        let summary = subscription
            .poll(|_, _| received += 1, MessageLimit::new(16))
            .unwrap();
        if summary.closed.is_some() {
            closed = summary.closed;
            break;
        }
    }
    assert_eq!(received, 400);
    assert_eq!(closed, Some(position));
    assert_eq!(
        driver.seal_state(stream).unwrap(),
        SealState::Retired { position }
    );
    drop(publication);
    drop(subscription);
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Freed);
}

#[test]
#[cfg_attr(miri, ignore = "forgets a handle on purpose; Miri reports the leak")]
fn a_forgotten_handle_pins_a_retiring_stream() {
    let config = DriverConfig {
        max_streams: 1,
        ..DriverConfig::default()
    };
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let forgotten = driver.subscribe(stream, Role::Optional).unwrap();
    std::mem::forget(forgotten);
    driver.remove_stream(stream).unwrap();
    for _ in 0..10 {
        let _ = driver.do_work().unwrap();
    }
    // Its lease never ends: the stream is never freed and keeps its slot.
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    assert_eq!(driver.live_leases(stream).unwrap(), 1);
    assert!(matches!(
        driver.add_stream(stream_config(3)),
        Err(DriverError::TooManyStreams)
    ));
}

fn lapping_config() -> DriverConfig {
    DriverConfig {
        command_budget: 1,
        cycles_between_drains: 1,
        broadcast_capacity: 1024,
        max_pending_per_client: 32,
        ..DriverConfig::default()
    }
}

/// Takes one required subscription for `client`.
fn subscribed(
    driver: &mut EmbeddedDriver,
    client: &mut ClientConductor,
) -> karyos_client::ClientSubscription {
    let _ = client
        .add_subscription(key(2), SubscriberRole::Required)
        .unwrap();
    for _ in 0..4 {
        let _ = driver.do_work().unwrap();
        if let Some(completion) = drain(client).pop() {
            match completion.outcome {
                Outcome::Subscription(subscription) => return subscription,
                other => panic!("unexpected {other:?}"),
            }
        }
    }
    panic!("no subscription");
}

#[test]
fn an_unknown_remove_that_executed_leaves_nothing() {
    let mut driver = EmbeddedDriver::with_config(lapping_config()).unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let mut slow = driver.connect().unwrap();
    let mut busy = driver.connect().unwrap();
    let subscription = subscribed(&mut driver, &mut slow);
    let remove = slow.remove_subscription(subscription).unwrap();
    // Served, then its response is lapped away.
    for _ in 0..60 {
        let _ = busy.add_subscription(key(99), SubscriberRole::Optional);
        let _ = driver.do_work().unwrap();
        let _ = drain(&mut busy);
    }
    let done = drain(&mut slow);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].sequence, remove);
    assert!(matches!(done[0].outcome, Outcome::Unknown));
    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(state(&driver, stream), StreamState::Freed);
}

#[test]
fn an_unknown_remove_still_queued_keeps_its_registration_until_served() {
    let mut driver = EmbeddedDriver::with_config(lapping_config()).unwrap();
    let stream = driver.add_stream(stream_config(2)).unwrap();
    let mut slow = driver.connect().unwrap();
    let mut busy = driver.connect().unwrap();
    let subscription = subscribed(&mut driver, &mut slow);
    // Twenty refused requests ahead of the Remove in the slow ring.
    for _ in 0..20 {
        let _ = slow
            .add_subscription(key(99), SubscriberRole::Optional)
            .unwrap();
    }
    let remove = slow.remove_subscription(subscription).unwrap();
    driver.remove_stream(stream).unwrap();
    // Lap the slow client before its Remove is served: with a budget of
    // one and two rings, the Remove (21st in its ring) needs about 42
    // cycles, while about 26 responses already lap a 1 KiB broadcast.
    for _ in 0..30 {
        let _ = busy.add_subscription(key(99), SubscriberRole::Optional);
        let _ = driver.do_work().unwrap();
        let _ = drain(&mut busy);
    }
    let lapped = drain(&mut slow);
    // Every pending request, the Remove included, is Unknown...
    assert!(lapped.iter().any(|c| c.sequence == remove));
    assert!(lapped.iter().all(|c| matches!(c.outcome, Outcome::Unknown)));
    // ...but the Remove is still queued: its registration keeps the stream.
    assert_eq!(driver.live_leases(stream).unwrap(), 0);
    assert_eq!(state(&driver, stream), StreamState::Retiring);
    for _ in 0..60 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(state(&driver, stream), StreamState::Freed);
}
