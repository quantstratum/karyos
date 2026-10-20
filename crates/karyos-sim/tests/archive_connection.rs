// SPDX-License-Identifier: Apache-2.0

//! A requester's `ArchiveConnection` over a facade client of an embedded
//! driver (quantstratum-docs: karyos/design/ffi-archive.md, F9-0): a
//! request it sends reaches the request stream's reader, an answer
//! published on the response stream reaches it, and a request stream that
//! is not concurrent refuses the connection.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use karyos_archive::client::connection::{ArchiveConnection, ControlStreams, OpenError};
use karyos_archive::client::{ControlRequests, ControlResponses};
use karyos_client::{Client, Context, MessageLimit, OfferOutcome};
use karyos_driver::embedded::{DriverConfig, EmbeddedDriver, StreamConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

const REQUESTS: i32 = 30;
const RESPONSES: i32 = 31;

fn stream(stream_id: i32, publication: PublicationMode) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 6,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// The driver on its own thread, until dropped.
struct Driven {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Driven {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn drive(mut driver: EmbeddedDriver) -> Driven {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    Driven {
        stop,
        thread: Some(std::thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                let _ = driver.do_work().unwrap();
                std::thread::yield_now();
            }
        })),
    }
}

fn driver() -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        client_liveness_timeout: 3_600_000_000_000,
        ..DriverConfig::default()
    })
    .unwrap()
}

fn context() -> Context {
    Context::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

#[test]
fn a_connection_sends_requests_and_reads_answers() {
    let mut driver = driver();
    let requests = driver
        .add_stream(stream(
            REQUESTS,
            PublicationMode::Concurrent {
                publishers: 4,
                allow_non_lse: true,
            },
        ))
        .unwrap();
    let responses = driver
        .add_stream(stream(RESPONSES, PublicationMode::Exclusive))
        .unwrap();
    // The Archive's side of the streams, as its host holds them.
    let mut reader = driver.subscribe(requests, Role::Required).unwrap();
    let mut answers = driver.publication(responses).unwrap();
    let conductor = driver.connect().unwrap();
    let _driven = drive(driver);

    let mut client = Client::with_conductor(conductor, context());
    let connection =
        ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES)).unwrap();
    let (mut sending, mut receiving) = connection.into_transports();

    let start = Instant::now();
    while !sending.send(b"a request") {
        assert!(start.elapsed() < Duration::from_secs(10), "never sent");
        let _ = client.poll();
        std::thread::yield_now();
    }
    let mut got = Vec::new();
    while got.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(10), "never read");
        let _ = reader.poll(
            |bytes, _| got.extend_from_slice(bytes),
            MessageLimit::new(1),
        );
        std::thread::yield_now();
    }
    assert_eq!(got, b"a request");

    while !matches!(
        answers.offer(b"an answer").unwrap(),
        OfferOutcome::Accepted { .. }
    ) {
        assert!(start.elapsed() < Duration::from_secs(10), "never answered");
        std::thread::yield_now();
    }
    let mut out = [0u8; 64];
    let length = loop {
        assert!(start.elapsed() < Duration::from_secs(10), "never received");
        let _ = client.poll();
        if let Some(length) = receiving.next(&mut out) {
            break length;
        }
        std::thread::yield_now();
    };
    assert_eq!(&out[..length], b"an answer");
    // An answer longer than the caller's buffer is skipped, not truncated.
    while !matches!(
        answers.offer(&[7u8; 100]).unwrap(),
        OfferOutcome::Accepted { .. }
    ) {
        std::thread::yield_now();
    }
    let mut small = [0u8; 8];
    let mut skipped = false;
    while !skipped {
        assert!(start.elapsed() < Duration::from_secs(10), "never polled");
        let _ = client.poll();
        // The poll consumes the message whether it fit or not.
        skipped = receiving.next(&mut small).is_none() && answers_left(&mut receiving);
        std::thread::yield_now();
    }
}

/// Whether nothing is left to read: one more poll with room finds none.
fn answers_left(receiving: &mut impl ControlResponses) -> bool {
    let mut out = [0u8; 256];
    receiving.next(&mut out).is_none()
}

/// A request stream the host did not make concurrent refuses the
/// connection: every requester shares it.
#[test]
fn an_exclusive_request_stream_refuses_the_connection() {
    let mut driver = driver();
    let _ = driver
        .add_stream(stream(REQUESTS, PublicationMode::Exclusive))
        .unwrap();
    let _ = driver
        .add_stream(stream(RESPONSES, PublicationMode::Exclusive))
        .unwrap();
    let conductor = driver.connect().unwrap();
    let _driven = drive(driver);
    let mut client = Client::with_conductor(conductor, context());
    assert!(matches!(
        ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES)),
        Err(OpenError::Requests(_))
    ));
}
