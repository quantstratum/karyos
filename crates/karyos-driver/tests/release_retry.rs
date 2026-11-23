// SPDX-License-Identifier: Apache-2.0

//! karyos#1067: a subscription release the client cannot submit now (its
//! pending requests at their limit, or its command ring full) is kept and
//! tried again at the next service, never dropped with its registration
//! left in the driver until the client ends.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use karyos_client::{Client, Context, IdleStrategy};
use karyos_driver::{DriverConfig, EmbeddedDriver, StreamConfig};
use karyos_protocol::cnc::StreamId;
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
            schedule_capacity: 0,
        },
        allow_unconnected: false,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation: None,
    }
}

/// Serves `client` until `done`, bounded by a deadline.
fn until(
    client: &mut Client<karyos_client::ClientConductor>,
    done: impl Fn(&Client<karyos_client::ClientConductor>) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !done(client) {
        assert!(Instant::now() < deadline, "not reached");
        let _ = client.poll();
        std::thread::sleep(Duration::from_micros(100));
    }
}

#[test]
fn a_release_refused_for_now_is_retried_not_dropped() {
    // One pending request per client: with the driver paused, a second
    // removal cannot be submitted.
    let config = DriverConfig {
        max_pending_per_client: 1,
        ..DriverConfig::default()
    };
    let paused = Arc::new(AtomicBool::new(false));
    let parked = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let leases = Arc::new(AtomicU64::new(u64::MAX));
    let (send, receive) = std::sync::mpsc::channel();
    let thread = {
        let (paused, parked, stop, leases) = (
            Arc::clone(&paused),
            Arc::clone(&parked),
            Arc::clone(&stop),
            Arc::clone(&leases),
        );
        std::thread::spawn(move || {
            let mut driver = EmbeddedDriver::with_config(config).unwrap();
            let stream = driver.add_stream(stream_config(2)).unwrap();
            send.send(driver.connect().unwrap()).unwrap();
            while !stop.load(Ordering::Acquire) {
                if paused.load(Ordering::Acquire) {
                    parked.store(true, Ordering::Release);
                } else {
                    parked.store(false, Ordering::Release);
                    let _ = driver.do_work().unwrap();
                    leases.store(driver.live_leases(stream).unwrap(), Ordering::Release);
                }
                std::thread::sleep(Duration::from_micros(50));
            }
        })
    };
    let context = Context::builder()
        .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap();
    let mut client = Client::with_conductor(receive.recv().unwrap(), context);
    let first = client
        .add_subscription("karyos:ipc", StreamId::new(2))
        .unwrap();
    let second = client
        .add_subscription("karyos:ipc", StreamId::new(2))
        .unwrap();
    let held = leases.load(Ordering::Acquire);
    // The driver stops serving: nothing pending completes.
    paused.store(true, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(120);
    while !parked.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "the driver never paused");
        std::thread::sleep(Duration::from_micros(100));
    }
    // The first removal takes the one pending slot; the second cannot be
    // submitted now. Before karyos#1067 it was dropped and counted failed,
    // its registration left until the client ended.
    client.remove_subscription(first);
    client.remove_subscription(second);
    assert_eq!(client.pending_releases(), 1);
    assert_eq!(client.subscription_releases_failed(), 0);
    // Served again: the held release is retried and submitted.
    paused.store(false, Ordering::Release);
    until(&mut client, |client| client.pending_releases() == 0);
    let deadline = Instant::now() + Duration::from_secs(120);
    while leases.load(Ordering::Acquire) >= held {
        assert!(
            Instant::now() < deadline,
            "the registrations were never removed"
        );
        let _ = client.poll();
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(client.subscription_releases_failed(), 0);
    stop.store(true, Ordering::Release);
    thread.join().unwrap();
}
