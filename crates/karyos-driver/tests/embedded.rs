// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests of the embedded publication and subscription API.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use karyos_client::{ClientError, OfferOutcome};
use karyos_driver::{EmbeddedDriver, StreamConfig};
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
    let mut driver = EmbeddedDriver::new();
    let strict = driver.add_stream(config(false)).unwrap();
    let mut publication = driver.publication(strict).unwrap();
    assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::NotConnected);
    let _subscription = driver.subscribe(strict, Role::Optional).unwrap();
    assert!(matches!(
        publication.offer(b"x").unwrap(),
        OfferOutcome::Accepted { .. }
    ));

    let open = driver.add_stream(config(true)).unwrap();
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
    let mut driver = EmbeddedDriver::new();
    let stream = driver.add_stream(config(false)).unwrap();
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let total = 600u32;
    let mut received = Vec::new();
    for sequence in 0..total {
        offer_retrying(&mut driver, &mut publication, &message(sequence));
        // At most 3 messages per poll.
        let summary = subscription
            .poll(|bytes, _| received.push(bytes.to_vec()), 3)
            .unwrap();
        assert!(summary.delivered <= 3);
    }
    while (received.len() as u32) < total {
        let _ = driver.do_work().unwrap();
        let _ = subscription
            .poll(|bytes, _| received.push(bytes.to_vec()), 10)
            .unwrap();
    }
    for (sequence, bytes) in received.iter().enumerate() {
        assert_eq!(bytes, &message(sequence as u32));
    }
}

#[test]
fn a_panicking_required_handler_gets_the_message_again() {
    let mut driver = EmbeddedDriver::new();
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
        let _ = subscription.poll(|_, _| panic!("handler failed"), 10);
    }));
    assert!(panicked.is_err());
    let mut seen = Vec::new();
    let summary = subscription
        .poll(|bytes, _| seen.push(bytes.to_vec()), 10)
        .unwrap();
    assert_eq!(summary.delivered, 2);
    assert_eq!(seen, vec![b"first".to_vec(), b"second".to_vec()]);
}

#[test]
fn optional_overruns_are_reported_and_extensions_pass_through() {
    let mut driver = EmbeddedDriver::new();
    let stream = driver.add_stream(config(false)).unwrap();
    let mut lagging = driver.subscribe(stream, Role::Optional).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    for sequence in 0..300 {
        offer_retrying(&mut driver, &mut publication, &message(sequence));
        let _ = driver.do_work().unwrap();
    }
    let summary = lagging.poll(|_, _| {}, 1).unwrap();
    let overrun = summary
        .last_overrun
        .expect("the lagging reader was overrun");
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
    let _ = lagging.poll(|_, i| info = Some(i), 1).unwrap();
    assert_eq!(info.and_then(|i| i.extension), Some(extension));
}

#[test]
fn publisher_and_subscribers_on_threads_with_manual_duty() {
    let total: u32 = 2000;
    let mut driver = EmbeddedDriver::new();
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
                        16,
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
