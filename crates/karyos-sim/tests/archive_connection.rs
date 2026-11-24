// SPDX-License-Identifier: Apache-2.0

//! A requester's `ArchiveConnection` over a facade client of an embedded
//! driver (quantstratum-docs: karyos/design/ffi-archive.md, F9-0): a
//! request it sends reaches the request stream's reader, an answer
//! published on the response stream reaches it, and a request stream that
//! is not concurrent refuses the connection. A failed or closed connection
//! holds no publisher slot, and one that stops reading answers does not
//! hold back another's.

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
    assert_eq!(receiving.oversized(), 1);
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

fn concurrent(publishers: u8) -> PublicationMode {
    PublicationMode::Concurrent {
        publishers,
        allow_non_lse: true,
    }
}

/// A request stream of one publisher slot: an open that fails on the
/// response stream gives its publication back, and so does a close, so the
/// next open on the same client succeeds.
#[test]
fn a_failed_or_closed_connection_holds_no_publisher_slot() {
    let mut driver = driver();
    let _ = driver.add_stream(stream(REQUESTS, concurrent(1))).unwrap();
    let _ = driver
        .add_stream(stream(RESPONSES, PublicationMode::Exclusive))
        .unwrap();
    let conductor = driver.connect().unwrap();
    let _driven = drive(driver);
    let mut client = Client::with_conductor(conductor, context());

    // No stream 99: the subscription fails after the publication is taken.
    assert!(matches!(
        ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, 99)),
        Err(OpenError::Responses(_))
    ));
    let connection =
        ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES)).unwrap();
    // The one slot is taken now.
    assert!(matches!(
        ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES)),
        Err(OpenError::Requests(_))
    ));
    connection.close(&mut client);
    let (requests, responses) =
        ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES))
            .unwrap()
            .into_transports();
    requests.close(&mut client);
    responses.close(&mut client);
    let _ = ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES)).unwrap();
}

/// A requester that never reads its answers is lapped: the Archive's
/// answers go on, and another requester reads them, past several terms.
#[test]
fn a_requester_that_stops_reading_does_not_hold_back_the_answers() {
    let mut driver = driver();
    let _ = driver.add_stream(stream(REQUESTS, concurrent(4))).unwrap();
    let responses = driver
        .add_stream(stream(RESPONSES, PublicationMode::Exclusive))
        .unwrap();
    let mut answers = driver.publication(responses).unwrap();
    let conductor = driver.connect().unwrap();
    let _driven = drive(driver);
    let mut client = Client::with_conductor(conductor, context());

    let streams = ControlStreams::new(REQUESTS, RESPONSES);
    let (_stalled_requests, _stalled) = ArchiveConnection::open(&mut client, streams)
        .unwrap()
        .into_transports();
    let (_requests, mut reading) = ArchiveConnection::open(&mut client, streams)
        .unwrap()
        .into_transports();

    // Four terms of answers, the last one marked.
    let count = 4 * MIN_TERM_LENGTH as usize / 128;
    let start = Instant::now();
    let mut out = [0u8; 256];
    let mut last = None;
    for index in 0..count {
        let answer = [u8::from(index + 1 == count); 100];
        while !matches!(
            answers.offer(&answer).unwrap(),
            OfferOutcome::Accepted { .. }
        ) {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "held back at answer {index} of {count}"
            );
            let _ = client.poll();
            while reading.next(&mut out).is_some() {}
            std::thread::yield_now();
        }
    }
    while last.is_none() {
        assert!(start.elapsed() < Duration::from_secs(30), "never read");
        let _ = client.poll();
        if let Some(length) = reading.next(&mut out)
            && out[..length] == [1u8; 100]
        {
            last = Some(length);
        }
        std::thread::yield_now();
    }
}

/// The same slot accounting for a remote client, whose dropped concurrent
/// handle would hold its slot until the client ends (Linux).
#[cfg(target_os = "linux")]
mod remote {
    use super::*;

    use karyos_driver::{IpcConfig, SystemClock};
    use karyos_sys::term_bytes::SharedTerms;

    #[test]
    fn a_remote_failed_or_closed_connection_holds_no_publisher_slot() {
        let dir = std::env::temp_dir().join(format!("karyos-f90a-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let (ready, started) = std::sync::mpsc::channel();
        let path = dir.clone();
        let thread = std::thread::spawn(move || {
            let mut driver: EmbeddedDriver<SharedTerms> = EmbeddedDriver::with_ipc(
                DriverConfig::default(),
                IpcConfig {
                    dir: path,
                    max_pending_hellos: 2,
                    hello_timeout: 5_000_000_000,
                    max_outbound_per_client: 8,
                    fetch_deadline: 5_000_000_000,
                    max_exports_per_client: 16,
                    max_fetches_per_client: 4,
                    max_regions_per_fetch: 4,
                    max_fetch_bytes: 1 << 30,
                    max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
                    client_send_buffer: None,
                },
                Box::new(SystemClock::new()),
            )
            .unwrap();
            let _ = driver.add_stream(stream(REQUESTS, concurrent(1))).unwrap();
            let _ = driver
                .add_stream(stream(RESPONSES, PublicationMode::Exclusive))
                .unwrap();
            ready.send(()).unwrap();
            while !flag.load(Ordering::Acquire) {
                let _ = driver.do_work().unwrap();
                std::thread::sleep(Duration::from_micros(50));
            }
        });
        started.recv().unwrap();
        let _driven = Driven {
            stop,
            thread: Some(thread),
        };
        let mut client = Client::connect(
            Context::builder()
                .dir(&dir)
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
        )
        .unwrap();

        for _ in 0..3 {
            assert!(matches!(
                ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, 99)),
                Err(OpenError::Responses(_))
            ));
        }
        let connection =
            ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES)).unwrap();
        assert!(matches!(
            ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES)),
            Err(OpenError::Requests(_))
        ));
        connection.close(&mut client);
        let (requests, responses) =
            ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES))
                .unwrap()
                .into_transports();
        requests.close(&mut client);
        responses.close(&mut client);
        let _ =
            ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES)).unwrap();
        drop(client);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
