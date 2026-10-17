// SPDX-License-Identifier: Apache-2.0

//! The SPEC §10 client facade (W7) against real drivers: in process, with
//! each driver on its own thread, over loopback UDP; and remote, over the
//! admission socket of an IPC driver (Linux).

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use karyos_client::{
    Client, ClientConductor, ClientError, Context, IdleStrategy, MessageLimit, OfferOutcome,
};
use karyos_driver::agents::ThreadingMode;
use karyos_driver::net::NetworkConfig;
use karyos_driver::{DriverConfig, EmbeddedDriver};
use karyos_protocol::cnc::StreamId;

/// An in-process driver driven on its own thread until dropped.
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

/// A network driver on its own thread, and `clients` conductors of it.
fn driven(clients: usize, image_liveness: Option<u64>) -> (Driven, Vec<ClientConductor>) {
    let stop = Arc::new(AtomicBool::new(false));
    let (send, receive) = mpsc::channel();
    let flag = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        let mut network = NetworkConfig {
            threading: ThreadingMode::Shared,
            ..NetworkConfig::default()
        };
        network.stream_defaults.term_length = 64 * 1024;
        if let Some(timeout) = image_liveness {
            network.agents.image_liveness_timeout = timeout;
        }
        let mut driver = EmbeddedDriver::with_config(DriverConfig {
            network: Some(network),
            ..DriverConfig::default()
        })
        .unwrap();
        for _ in 0..clients {
            send.send(driver.connect().unwrap()).unwrap();
        }
        while !flag.load(Ordering::Acquire) {
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(50));
        }
    });
    let conductors = (0..clients).map(|_| receive.recv().unwrap()).collect();
    (
        Driven {
            stop,
            thread: Some(thread),
        },
        conductors,
    )
}

fn context() -> Context {
    Context::builder()
        .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn port() -> u16 {
    UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Serves `clients` until `done`, or panics after 20 s.
fn until<C: karyos_client::Connection>(
    clients: &mut [&mut Client<C>],
    mut done: impl FnMut() -> bool,
) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(20), "not reached");
        for client in clients.iter_mut() {
            let _ = client.poll();
        }
        std::thread::sleep(Duration::from_micros(100));
    }
}

/// SPEC §10 end to end in process: a publication and a subscription named
/// by `karyos:udp` URIs, the subscription reading the image it attaches
/// and dropping it once it retires.
#[test]
fn a_udp_publication_reaches_a_udp_subscription() {
    let (_a, mut a) = driven(1, None);
    // The receiver retires an image half a second after its sender goes.
    let (_b, mut b) = driven(1, Some(500_000_000));
    let mut publisher = Client::with_conductor(a.remove(0), context());
    let mut subscriber = Client::with_conductor(b.remove(0), context());
    let port = port();
    let mut reading = subscriber
        .add_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(7),
        )
        .unwrap();
    assert!(reading.registration().is_some());
    let mut publication = publisher
        .add_exclusive_publication(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1"),
            StreamId::new(7),
        )
        .unwrap();
    // The image joins at the position it is attached at: messages offered
    // before it is attached are not delivered to it. A network
    // publication counts its sender as a subscriber, so offers are
    // accepted before any receiver attaches.
    until(&mut [&mut subscriber, &mut publisher], || {
        let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
        reading.image_count() == 1
    });
    let (mut sent, mut seen) = (0u32, 0u32);
    let start = Instant::now();
    while seen < 64 {
        assert!(start.elapsed() < Duration::from_secs(20), "seen {seen}");
        let _ = publisher.poll();
        let _ = subscriber.poll();
        while sent < 64 {
            match publication.offer(&sent.to_le_bytes()).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reading
            .poll(
                |bytes, _| {
                    assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), seen);
                    seen += 1;
                },
                MessageLimit::new(16),
            )
            .unwrap();
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(reading.image_count(), 1);
    assert_eq!(reading.images_refused(), 0);
    // The publication goes: its image retires and leaves the subscription.
    drop(publication);
    until(&mut [&mut subscriber, &mut publisher], || {
        let _ = reading.poll(|_, _| {}, MessageLimit::new(16));
        reading.image_count() == 0
    });
}

/// Two images are polled in turn under one limit, starting after the
/// image the last poll ended at, so neither starves.
#[test]
fn a_network_subscription_polls_its_images_in_turn() {
    let (_a, mut a) = driven(2, None);
    let (_b, mut b) = driven(1, None);
    let mut first = Client::with_conductor(a.remove(0), context());
    let mut second = Client::with_conductor(a.remove(0), context());
    let mut subscriber = Client::with_conductor(b.remove(0), context());
    let port = port();
    let mut reading = subscriber
        .add_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(8),
        )
        .unwrap();
    let uri = format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1");
    let mut one = first
        .add_exclusive_publication(&uri, StreamId::new(8))
        .unwrap();
    let mut two = second
        .add_exclusive_publication(&uri, StreamId::new(8))
        .unwrap();
    until(&mut [&mut subscriber, &mut first, &mut second], || {
        let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
        reading.image_count() == 2
    });
    // Each image holds messages of its publication only.
    let mut offered = [0u32; 2];
    let start = Instant::now();
    while offered != [8, 8] {
        assert!(start.elapsed() < Duration::from_secs(20), "{offered:?}");
        let _ = (first.poll(), second.poll(), subscriber.poll());
        for (index, (publication, tag)) in
            [(&mut one, b"1"), (&mut two, b"2")].into_iter().enumerate()
        {
            if offered[index] < 8
                && matches!(
                    publication.offer(tag).unwrap(),
                    OfferOutcome::Accepted { .. }
                )
            {
                offered[index] += 1;
            }
        }
    }
    // Wait until both images have messages to read, then read one at a
    // time: the images alternate.
    let mut seen: Vec<u8> = Vec::new();
    let start = Instant::now();
    while seen.len() < 16 {
        assert!(start.elapsed() < Duration::from_secs(20), "{seen:?}");
        let _ = (first.poll(), second.poll(), subscriber.poll());
        let poll = reading
            .poll(|bytes, _| seen.push(bytes[0]), MessageLimit::new(1))
            .unwrap();
        assert!(poll.delivered <= 1, "the limit is a total over the images");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(seen.iter().filter(|tag| **tag == b'1').count(), 8);
    // Once both have arrived, no image is read twice in a row while the
    // other has messages: the first 8 reads alternate.
    let pairs = seen[..8]
        .chunks(2)
        .filter(|pair| pair[0] != pair[1])
        .count();
    assert!(pairs >= 3, "the images are read in turn: {seen:?}");
}

/// An image beyond the context's `max_images` is refused and counted,
/// never attached.
#[test]
fn an_image_beyond_the_bound_is_refused_and_counted() {
    let (_a, mut a) = driven(2, None);
    let (_b, mut b) = driven(1, None);
    let mut first = Client::with_conductor(a.remove(0), context());
    let mut second = Client::with_conductor(a.remove(0), context());
    let mut subscriber = Client::with_conductor(
        b.remove(0),
        Context::builder()
            .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
            .max_images(1)
            .build()
            .unwrap(),
    );
    let port = port();
    let mut reading = subscriber
        .add_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(9),
        )
        .unwrap();
    let uri = format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1");
    let _one = first
        .add_exclusive_publication(&uri, StreamId::new(9))
        .unwrap();
    let _two = second
        .add_exclusive_publication(&uri, StreamId::new(9))
        .unwrap();
    until(&mut [&mut subscriber, &mut first, &mut second], || {
        let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
        reading.image_count() == 1 && reading.images_refused() == 1
    });
}

/// A driver driven on the caller's thread cannot answer a control call:
/// it returns `Timeout` at the context's timeout instead of hanging.
#[test]
fn a_driver_on_the_same_thread_times_out_a_control_call() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let conductor = driver.connect().unwrap();
    let mut client = Client::with_conductor(
        conductor,
        Context::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap(),
    );
    let start = Instant::now();
    assert_eq!(
        client
            .add_exclusive_publication("karyos:ipc", StreamId::new(1))
            .err(),
        Some(ClientError::Timeout)
    );
    assert!(start.elapsed() >= Duration::from_millis(50));
    assert!(start.elapsed() < Duration::from_secs(5));
    drop(driver);
}

/// The configuration of a one-lane heap stream of `stream_id`.
fn heap_stream(stream_id: i32) -> karyos_driver::StreamConfig {
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;
    karyos_driver::StreamConfig {
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
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: karyos_driver::LossPolicy::Hold,
        conflation: None,
    }
}

/// A grant that arrives after its request timed out is released at once
/// and counted: its lease ends, so repeated timeouts hold nothing.
#[test]
fn a_late_grant_is_released() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(heap_stream(1)).unwrap();
    let conductor = driver.connect().unwrap();
    let mut client = Client::with_conductor(
        conductor,
        Context::builder()
            .timeout(Duration::from_millis(20))
            .build()
            .unwrap(),
    );
    // A publication, then two subscriptions: each times out, as the
    // driver runs on this thread, and is released once it is answered.
    for late in 1..=3u64 {
        let refused = if late == 1 {
            client
                .add_exclusive_publication("karyos:ipc", StreamId::new(1))
                .err()
        } else {
            client
                .add_subscription("karyos:ipc", StreamId::new(1))
                .err()
        };
        assert_eq!(refused, Some(ClientError::Timeout));
        let start = Instant::now();
        while client.late_grants_released() < late {
            assert!(start.elapsed() < Duration::from_secs(5), "late {late}");
            let _ = driver.do_work().unwrap();
            let _ = client.poll();
        }
    }
    let start = Instant::now();
    while driver.live_leases(stream).unwrap() > 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a released grant holds a lease"
        );
        let _ = driver.do_work().unwrap();
        let _ = client.poll();
    }
}

/// A context with a zero bound is refused.
#[test]
fn invalid_contexts_are_refused() {
    for builder in [
        Context::builder().timeout(Duration::ZERO),
        Context::builder().max_pending(0),
        Context::builder().max_images(0),
    ] {
        assert!(matches!(
            builder.build(),
            Err(ClientError::InvalidContext { .. })
        ));
    }
}

#[cfg(target_os = "linux")]
mod remote {
    use super::*;

    use karyos_driver::{IpcConfig, LossPolicy, StreamConfig, SystemClock};
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;
    use karyos_sys::term_bytes::SharedTerms;

    /// An IPC driver on its own thread, with one stream of id 3, whose
    /// admission socket is in the returned directory.
    fn ipc_driver(name: &str) -> (Driven, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("karyos-facade-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let stop = Arc::new(AtomicBool::new(false));
        let (ready, started) = mpsc::channel();
        let flag = Arc::clone(&stop);
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
                },
                Box::new(SystemClock::new()),
            )
            .unwrap();
            let _ = driver
                .add_stream(StreamConfig {
                    buffer: LogBufferConfig {
                        term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                        spare_slots: 3,
                        max_subscribers: 4,
                        mtu: DEFAULT_MTU,
                        max_reserved: MIN_TERM_LENGTH / 8,
                        initial_term_id: TermId::new(7),
                        lane: Lane::ZERO,
                        session_id: 1,
                        stream_id: 3,
                        claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                        publication: PublicationMode::Exclusive,
                        schedule_capacity: 0,
                    },
                    allow_unconnected: false,
                    on_required_loss: LossPolicy::Hold,
                    conflation: None,
                })
                .unwrap();
            ready.send(()).unwrap();
            while !flag.load(Ordering::Acquire) {
                let _ = driver.do_work().unwrap();
                std::thread::sleep(Duration::from_micros(50));
            }
        });
        started.recv().unwrap();
        (
            Driven {
                stop,
                thread: Some(thread),
            },
            dir,
        )
    }

    fn connect(dir: &std::path::Path) -> Client<karyos_client::ipc::RemoteClient> {
        Client::connect(
            Context::builder()
                .dir(dir)
                .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
                .build()
                .unwrap(),
        )
        .unwrap()
    }

    /// SPEC §10 remote: a client attaches by directory, publishes and
    /// subscribes by `karyos:ipc`, and reads what it offered.
    #[test]
    fn a_remote_client_exchanges_over_an_ipc_uri() {
        let (_driver, dir) = ipc_driver("ipc");
        let mut client = connect(&dir);
        let mut reading = client
            .add_subscription("karyos:ipc", StreamId::new(3))
            .unwrap();
        assert_eq!(reading.registration(), None);
        let mut publication = client
            .add_exclusive_publication("karyos:ipc", StreamId::new(3))
            .unwrap();
        let (mut sent, mut seen) = (0u32, 0u32);
        let start = Instant::now();
        while seen < 32 {
            assert!(start.elapsed() < Duration::from_secs(20), "seen {seen}");
            let _ = client.poll();
            while sent < 32 {
                match publication.offer(&sent.to_le_bytes()).unwrap() {
                    OfferOutcome::Accepted { .. } => sent += 1,
                    _ => break,
                }
            }
            let _ = reading
                .poll(
                    |bytes, _| {
                        assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), seen);
                        seen += 1;
                    },
                    MessageLimit::new(8),
                )
                .unwrap();
        }
        // An id with no stream is refused.
        assert!(matches!(
            client
                .add_subscription("karyos:ipc", StreamId::new(99))
                .err(),
            Some(ClientError::Refused { .. })
        ));
    }

    /// A remote client's `karyos:udp` is refused with `UnsupportedChannel`:
    /// the driver serves network channels on heap terms only (D3).
    #[test]
    fn a_remote_udp_channel_is_unsupported() {
        let (_driver, dir) = ipc_driver("udp");
        let mut client = connect(&dir);
        let uri = "karyos:udp?endpoint=127.0.0.1:40777";
        assert!(matches!(
            client
                .add_exclusive_publication(uri, StreamId::new(3))
                .err(),
            Some(ClientError::UnsupportedChannel { .. })
        ));
        assert!(matches!(
            client.add_subscription(uri, StreamId::new(3)).err(),
            Some(ClientError::UnsupportedChannel { .. })
        ));
    }

    /// `connect` needs the driver's directory.
    #[test]
    fn connect_needs_a_directory() {
        assert!(matches!(
            Client::connect(Context::builder().build().unwrap()).err(),
            Some(ClientError::NoDirectory)
        ));
    }
}
