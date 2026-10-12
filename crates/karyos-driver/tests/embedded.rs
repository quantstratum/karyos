// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests of the embedded publication and subscription API.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use karyos_client::{ClientError, MessageLimit, OfferOutcome};
use karyos_driver::{DriverError, EmbeddedDriver, StreamConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{AppendOptions, LogBufferConfig, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

fn config(allow_unconnected: bool) -> StreamConfig {
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
        },
        allow_unconnected,
    }
}

fn message(sequence: u32) -> Vec<u8> {
    let len = 16 + (sequence as usize * 97) % 2000;
    let mut data: Vec<u8> = (0..len).map(|i| (i as u8) ^ (sequence as u8)).collect();
    data[..4].copy_from_slice(&sequence.to_le_bytes());
    data
}

fn offer_retrying(
    driver: &mut EmbeddedDriver,
    publication: &mut karyos_client::ClientPublication,
    data: &[u8],
) {
    for _ in 0..10_000 {
        match publication.offer(data).unwrap() {
            OfferOutcome::Accepted { .. } => return,
            _ => {
                let _ = driver.do_work().unwrap();
            }
        }
    }
    panic!("offer never accepted");
}

#[test]
fn not_connected_without_subscribers_unless_allowed() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let strict = driver.add_stream(config(false)).unwrap();
    let mut publication = driver.publication(strict).unwrap();
    assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::NotConnected);
    let _subscription = driver.subscribe(strict, Role::Optional).unwrap();
    // The NotConnected offer reserved nothing: the first accepted message
    // starts at position 0.
    assert_eq!(
        publication.offer(b"x").unwrap(),
        OfferOutcome::Accepted {
            lane: Lane::ZERO,
            position: 0
        }
    );

    let mut open_config = config(true);
    open_config.buffer.stream_id = 3;
    let open = driver.add_stream(open_config).unwrap();
    let mut publication = driver.publication(open).unwrap();
    assert!(matches!(
        publication.offer(b"x").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert!(driver.publication(open).is_err());
    assert_eq!(publication.offer(&[]), Err(ClientError::EmptyMessage));
    let too_big = vec![0u8; publication.max_message_length() as usize + 1];
    assert!(matches!(
        publication.offer(&too_big),
        Err(ClientError::MessageTooLarge { .. })
    ));
}

#[test]
fn messages_flow_through_many_rotations_with_limits() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(config(false)).unwrap();
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let total = 600u32;
    let mut received = Vec::new();
    for sequence in 0..total {
        offer_retrying(&mut driver, &mut publication, &message(sequence));
        // At most 3 messages per poll.
        let summary = subscription
            .poll(
                |bytes, _| received.push(bytes.to_vec()),
                MessageLimit::new(3),
            )
            .unwrap();
        assert!(summary.delivered <= 3);
    }
    while (received.len() as u32) < total {
        let _ = driver.do_work().unwrap();
        let _ = subscription
            .poll(
                |bytes, _| received.push(bytes.to_vec()),
                MessageLimit::new(10),
            )
            .unwrap();
    }
    for (sequence, bytes) in received.iter().enumerate() {
        assert_eq!(bytes, &message(sequence as u32));
    }
}

#[test]
fn a_panicking_required_handler_gets_the_message_again() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(config(false)).unwrap();
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    assert!(matches!(
        publication.offer(b"first").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert!(matches!(
        publication.offer(b"second").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = subscription.poll(|_, _| panic!("handler failed"), MessageLimit::new(10));
    }));
    assert!(panicked.is_err());
    let mut seen = Vec::new();
    let summary = subscription
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(10))
        .unwrap();
    assert_eq!(summary.delivered, 2);
    assert_eq!(seen, vec![b"first".to_vec(), b"second".to_vec()]);
}

#[test]
fn optional_overruns_are_reported_and_extensions_pass_through() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(config(false)).unwrap();
    let mut lagging = driver.subscribe(stream, Role::Optional).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    for sequence in 0..300 {
        offer_retrying(&mut driver, &mut publication, &message(sequence));
        let _ = driver.do_work().unwrap();
    }
    let summary = lagging.poll(|_, _| {}, MessageLimit::new(10)).unwrap();
    // The poll stops at the overrun: nothing else was delivered with it.
    assert_eq!(summary.delivered, 0);
    let overrun = summary.overrun.expect("the lagging reader was overrun");
    assert_eq!(overrun.from, 0);
    assert!(overrun.lost_to > 0 && overrun.lost_to <= overrun.resume);

    let extension = [9u8; 64];
    let options = AppendOptions {
        extension: Some(extension),
        ..AppendOptions::default()
    };
    assert!(matches!(
        publication.offer_with(b"traced", options).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let mut info = None;
    let _ = lagging
        .poll(|_, i| info = Some(i), MessageLimit::new(1))
        .unwrap();
    assert_eq!(info.and_then(|i| i.extension), Some(extension));
}

#[test]
fn publisher_and_subscribers_on_threads_with_manual_duty() {
    let total: u32 = 2000;
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(config(false)).unwrap();
    let mut required = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let done_driver = Arc::clone(&done);
        scope.spawn(move || {
            while !done_driver.load(Ordering::Acquire) {
                let _ = driver.do_work().unwrap();
                std::thread::yield_now();
            }
        });
        scope.spawn(move || {
            for sequence in 0..total {
                let data = message(sequence);
                while !matches!(
                    publication.offer(&data).unwrap(),
                    OfferOutcome::Accepted { .. }
                ) {
                    std::thread::yield_now();
                }
            }
        });
        let reader = scope.spawn(move || {
            let mut next = 0u32;
            while next < total {
                let _ = required
                    .poll(
                        |bytes, _| {
                            assert_eq!(bytes, &message(next)[..]);
                            next += 1;
                        },
                        MessageLimit::new(16),
                    )
                    .unwrap();
                std::thread::yield_now();
            }
            next
        });
        assert_eq!(reader.join().unwrap(), total);
        done.store(true, Ordering::Release);
    });
}

#[test]
fn an_optional_handler_panic_is_not_replayed() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(config(false)).unwrap();
    let mut subscription = driver.subscribe(stream, Role::Optional).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    assert!(matches!(
        publication.offer(b"first").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert!(matches!(
        publication.offer(b"second").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = subscription.poll(|_, _| panic!("handler failed"), MessageLimit::new(10));
    }));
    assert!(panicked.is_err());
    let mut seen = Vec::new();
    let _ = subscription
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(10))
        .unwrap();
    assert_eq!(seen, vec![b"second".to_vec()]);
}

#[test]
fn limits_handles_and_maximum_sizes() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(config(false)).unwrap();
    // Duplicate wire identity and foreign handles are rejected.
    assert!(matches!(
        driver.add_stream(config(false)),
        Err(DriverError::DuplicateStream { .. })
    ));
    let mut other = EmbeddedDriver::new().unwrap();
    assert!(matches!(
        other.subscribe(stream, Role::Optional),
        Err(DriverError::UnknownStream { .. })
    ));
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    // A message of exactly the maximum size round-trips.
    let max = vec![0xABu8; publication.max_message_length() as usize];
    assert!(matches!(
        publication.offer(&max).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    // A limit of 0 does nothing.
    let summary = subscription
        .poll(|_, _| panic!("no delivery expected"), MessageLimit::new(0))
        .unwrap();
    assert_eq!(summary.delivered, 0);
    let mut seen = Vec::new();
    let _ = subscription
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(1))
        .unwrap();
    assert_eq!(seen, vec![max]);
}

#[test]
fn streams_are_isolated_and_subscriber_cells_are_bounded() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let first = driver.add_stream(config(false)).unwrap();
    let mut second_config = config(false);
    second_config.buffer.stream_id = 9;
    let second = driver.add_stream(second_config).unwrap();
    assert_ne!(first, second);

    let mut first_sub = driver.subscribe(first, Role::Required).unwrap();
    let mut second_sub = driver.subscribe(second, Role::Required).unwrap();
    let mut first_pub = driver.publication(first).unwrap();
    let mut second_pub = driver.publication(second).unwrap();
    assert!(matches!(
        first_pub.offer(b"one").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let mut seen = Vec::new();
    let summary = second_sub
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(10))
        .unwrap();
    assert_eq!(summary.delivered, 0);
    assert!(matches!(
        second_pub.offer(b"two").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let _ = first_sub
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(10))
        .unwrap();
    let _ = second_sub
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(10))
        .unwrap();
    assert_eq!(seen, vec![b"one".to_vec(), b"two".to_vec()]);

    // max_subscribers = 4 registry cells; one is used above.
    let _more: Vec<_> = (0..3)
        .map(|_| driver.subscribe(first, Role::Required).unwrap())
        .collect();
    assert!(matches!(
        driver.subscribe(first, Role::Required),
        Err(DriverError::Sys(_))
    ));
    // Exhausting one stream leaves the other unaffected. Optional
    // subscribers also need a slot credit: S - C = 2, one held by the
    // publication, so exactly one optional subscriber fits.
    let _optional = driver.subscribe(second, Role::Optional).unwrap();
    assert!(matches!(
        driver.subscribe(second, Role::Optional),
        Err(DriverError::Sys(_))
    ));
}

#[test]
fn a_poll_delivers_exactly_its_limit_from_a_longer_queue() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(config(false)).unwrap();
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    for sequence in 0..5 {
        assert!(matches!(
            publication.offer(&message(sequence)).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    let mut seen = Vec::new();
    for (limit, expected) in [(2, 2), (2, 2), (10, 1), (10, 0)] {
        let summary = subscription
            .poll(
                |bytes, _| seen.push(bytes.to_vec()),
                MessageLimit::new(limit),
            )
            .unwrap();
        assert_eq!(summary.delivered, expected);
    }
    let expected: Vec<_> = (0..5).map(message).collect();
    assert_eq!(seen, expected);
}
