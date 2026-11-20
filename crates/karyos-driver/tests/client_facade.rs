// SPDX-License-Identifier: Apache-2.0

//! The SPEC §10 client facade (W7) against real drivers: in process, with
//! each driver on its own thread, over loopback UDP; and remote, over the
//! admission socket of an IPC driver (Linux).

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use karyos_client::{
    Client, ClientConductor, ClientError, ConductorError, Context, CounterKind, IdleStrategy,
    MessageLimit, OfferError,
};
use karyos_driver::agents::ThreadingMode;
use karyos_driver::net::NetworkConfig;
use karyos_driver::{DriverConfig, EmbeddedDriver};
use karyos_protocol::cnc::{ErrorCode, StreamId};
use karyos_sys::counters::{TYPE_APPLICATION_EVENT, TYPE_APPLICATION_GAUGE};

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
    test_port()
}

/// A loopback UDP port no socket holds now, picked below every ephemeral
/// range (Linux 32768 to 60999, macOS 49152 to 65535), so no bind to port
/// 0 can take it before the driver binds it (karyos#520). As karyos-driver's
/// `test_ports`: a process starts at its own offset and walks the range,
/// skipping ports it cannot bind. Owner item 26 (an `endpoint=host:0`
/// subscription that reports its port) would remove the race.
fn test_port() -> u16 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    const FIRST: u32 = 20_000;
    const COUNT: u32 = 12_000;
    let start = std::process::id().wrapping_mul(2_654_435_761) % COUNT;
    loop {
        let taken = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(taken < COUNT, "no free test port left in the range");
        let port = u16::try_from(FIRST + (start + taken) % COUNT).unwrap();
        if std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
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
            match publication.offer(&sent.to_le_bytes()) {
                Ok(_) => sent += 1,
                Err(
                    OfferError::BackPressured | OfferError::AdminAction | OfferError::NotConnected,
                ) => break,
                Err(error) => panic!("{error}"),
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

/// Decision row 26: a network subscription's handle reports the address
/// its endpoint bound, exactly the URI's address and port, over IPv4 and,
/// where the host has it, IPv6 loopback.
#[test]
fn a_network_subscription_reports_its_bound_address() {
    let (_b, mut b) = driven(1, None);
    let mut subscriber = Client::with_conductor(b.remove(0), context());
    let port = port();
    let reading = subscriber
        .add_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(7),
        )
        .unwrap();
    assert_eq!(
        reading.bound_address(),
        Some(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    );
    let v6 = std::net::Ipv6Addr::LOCALHOST;
    if std::net::UdpSocket::bind((v6, 0)).is_err() {
        // The IPv6 part is skipped: no IPv6 loopback on this host.
        return;
    }
    let port = loop {
        let candidate = test_port();
        if std::net::UdpSocket::bind((v6, candidate)).is_ok() {
            break candidate;
        }
    };
    let reading = subscriber
        .add_subscription(
            &format!("karyos:udp?endpoint=[::1]:{port}"),
            StreamId::new(8),
        )
        .unwrap();
    assert_eq!(reading.bound_address(), Some(SocketAddr::from((v6, port))));
}

/// Two images are polled in turn under one limit, starting after the
/// image the last poll ended at, so neither starves. A second subscription
/// of the channel witnesses that both images hold every message before the
/// first is read one at a time (plan 167, karyos#853): under load, an
/// image's datagrams may arrive after the reads begin, and the first reads
/// then rightly take the only image with data.
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
    // The witness proves something about `reading` because both read the
    // same images: a driver keeps one image per publication session and
    // stream, which every subscription of the channel attaches to (its
    // log buffer), so the messages the witness read are in the buffers
    // `reading` polls.
    let mut witness = subscriber
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
        let _ = witness.poll(|_, _| {}, MessageLimit::new(0));
        reading.image_count() == 2 && witness.image_count() == 2
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
            if offered[index] < 8 && publication.offer(tag).is_ok() {
                offered[index] += 1;
            }
        }
    }
    // Wait until both images hold every message: the witness reads all
    // 16, 8 of each publication.
    let mut witnessed = [0u32; 2];
    let start = Instant::now();
    while witnessed != [8, 8] {
        assert!(start.elapsed() < Duration::from_secs(20), "{witnessed:?}");
        let _ = (first.poll(), second.poll(), subscriber.poll());
        let _ = witness
            .poll(
                |bytes, _| witnessed[usize::from(bytes[0] == b'2')] += 1,
                MessageLimit::new(16),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    // Then read one at a time: the images alternate.
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

/// A network driver driven by the caller.
fn network_driver() -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading: ThreadingMode::Shared,
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap()
}

/// Two images of one alias (`quantstratum-docs:
/// karyos/design/per-source-images.md`, D2-5): two publishers on two
/// drivers use the same stream and session to one subscription. Both
/// images are attached, two slots, each delivering its own publisher's
/// messages in order; when one publisher goes, its `ImageUnavailable`
/// drops only its image, and the other keeps delivering.
#[test]
fn a_network_subscription_reads_two_images_of_one_alias() {
    use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
    use karyos_sys::frame::Lane;

    // The receiver retires an image half a second after its sender goes.
    let (_b, mut b) = driven(1, Some(500_000_000));
    let mut subscriber = Client::with_conductor(b.remove(0), context());
    let port = port();
    let mut reading = subscriber
        .add_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(8),
        )
        .unwrap();
    let channel = UdpConfig {
        retransmit_window: None,
        nak_control: Vec::new(),
        linger: None,
        destination: Destination::Unicast(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
        interface: Some(Interface::Address(Ipv4Addr::LOCALHOST.into())),
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    // One alias, (8, 1), from two sources.
    let mut publishers = [network_driver(), network_driver()];
    let handles = publishers.each_mut().map(|driver| {
        driver
            .add_network_publication(heap_aggregate(8, 1), &channel)
            .unwrap()
    });
    let serve = |publishers: &mut [EmbeddedDriver; 2], subscriber: &mut Client<ClientConductor>| {
        for driver in publishers.iter_mut() {
            let _ = driver.do_work().unwrap();
        }
        let _ = subscriber.poll();
        std::thread::sleep(Duration::from_micros(100));
    };
    let start = Instant::now();
    while reading.image_count() < 2 {
        assert!(start.elapsed() < Duration::from_secs(20), "two images");
        serve(&mut publishers, &mut subscriber);
        let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
    }
    let [first, second] = &mut publishers;
    let mut lanes = [
        first
            .publication(handles[0].lane(Lane::ZERO).unwrap())
            .unwrap(),
        second
            .publication(handles[1].lane(Lane::ZERO).unwrap())
            .unwrap(),
    ];
    let mut offered = [0u8; 2];
    let mut seen: Vec<[u8; 2]> = Vec::new();
    let start = Instant::now();
    while seen.len() < 16 {
        assert!(start.elapsed() < Duration::from_secs(20), "{seen:?}");
        for (publisher, lane) in lanes.iter_mut().enumerate() {
            if offered[publisher] < 8
                && matches!(
                    lane.offer(&[u8::try_from(publisher).unwrap(), offered[publisher]]),
                    Ok(karyos_client::OfferOutcome::Accepted { .. })
                )
            {
                offered[publisher] += 1;
            }
        }
        serve(&mut publishers, &mut subscriber);
        let _ = reading
            .poll(
                |bytes, _| seen.push([bytes[0], bytes[1]]),
                MessageLimit::new(64),
            )
            .unwrap();
    }
    for publisher in 0..2u8 {
        let own: Vec<u8> = seen
            .iter()
            .filter(|[from, _]| *from == publisher)
            .map(|[_, index]| *index)
            .collect();
        assert_eq!(own, (0..8).collect::<Vec<u8>>(), "publisher {publisher}");
    }
    // The second publisher goes: only its image is dropped.
    let [mut lane, second] = lanes;
    drop(second);
    publishers[1].remove_aggregate(&handles[1]).unwrap();
    let start = Instant::now();
    while reading.image_count() > 1 {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "one image retires"
        );
        serve(&mut publishers, &mut subscriber);
        let _ = reading.poll(|_, _| {}, MessageLimit::new(64));
    }
    assert_eq!(reading.image_count(), 1);
    assert_eq!(reading.images_refused(), 0);
    // The image left is the first publisher's: it still delivers.
    let mut later = Vec::new();
    let start = Instant::now();
    while later.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(20), "the first image");
        let _ = lane.offer(&[0, 99]);
        serve(&mut publishers, &mut subscriber);
        let _ = reading
            .poll(
                |bytes, _| later.push([bytes[0], bytes[1]]),
                MessageLimit::new(64),
            )
            .unwrap();
    }
    assert_eq!(later[0], [0, 99]);
}

/// An image beyond the context's `max_images` is refused and counted,
/// never attached; a refused image holds no slot, so its retirement frees
/// none (#306 review P1: A attached, B refused, B retired, C refused).
#[test]
fn an_image_beyond_the_bound_is_refused_and_counted() {
    let (_a, mut a) = driven(3, None);
    // The receiver retires an image half a second after its sender goes.
    let (_b, mut b) = driven(1, Some(500_000_000));
    let mut first = Client::with_conductor(a.remove(0), context());
    let mut second = Client::with_conductor(a.remove(0), context());
    let mut third = Client::with_conductor(a.remove(0), context());
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
    let mut one = first
        .add_exclusive_publication(&uri, StreamId::new(9))
        .unwrap();
    until(&mut [&mut subscriber, &mut first], || {
        let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
        reading.image_count() == 1
    });
    let two = second
        .add_exclusive_publication(&uri, StreamId::new(9))
        .unwrap();
    until(&mut [&mut subscriber, &mut first, &mut second], || {
        let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
        reading.images_refused() == 1
    });
    // B goes: its image retires, which frees no slot. A keeps sending so
    // its image stays live.
    drop(two);
    let retired = Instant::now();
    while retired.elapsed() < Duration::from_millis(1500) {
        let _ = (first.poll(), subscriber.poll());
        let _ = one.offer(b"a");
        let _ = reading.poll(|_, _| {}, MessageLimit::new(64));
        assert_eq!(reading.image_count(), 1);
        std::thread::sleep(Duration::from_millis(1));
    }
    let _three = third
        .add_exclusive_publication(&uri, StreamId::new(9))
        .unwrap();
    until(&mut [&mut subscriber, &mut first, &mut third], || {
        let _ = one.offer(b"a");
        let _ = reading.poll(|_, _| {}, MessageLimit::new(64));
        assert!(reading.image_count() <= 1, "max_images is a bound");
        reading.images_refused() == 2
    });
    assert_eq!(reading.image_count(), 1);
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
        let (driven, dir, _) = ipc_driver_with(name, 16, DriverConfig::default());
        (driven, dir)
    }

    /// As [`ipc_driver`], with a network whose receiver retires an image
    /// `image_liveness` ns after its sender goes silent.
    fn ipc_network_driver(name: &str, image_liveness: u64) -> (Driven, std::path::PathBuf) {
        let mut network = NetworkConfig {
            threading: ThreadingMode::Shared,
            ..NetworkConfig::default()
        };
        network.stream_defaults.term_length = 64 * 1024;
        network.agents.image_liveness_timeout = image_liveness;
        let config = DriverConfig {
            network: Some(network),
            ..DriverConfig::default()
        };
        let (driven, dir, _) = ipc_driver_with(name, 16, config);
        (driven, dir)
    }

    /// A switch that pauses a driver's duty cycle, and the driver's
    /// acknowledgement that it is paused.
    #[derive(Clone)]
    struct Pause {
        asked: Arc<AtomicBool>,
        holding: Arc<AtomicBool>,
    }

    impl Pause {
        /// Pauses the driver once its current cycle is over.
        fn hold(&self) {
            self.asked.store(true, Ordering::Release);
            while !self.holding.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        }

        fn resume(&self) {
            self.asked.store(false, Ordering::Release);
        }
    }

    /// As [`ipc_driver`], with at most `max_exports` grants per client,
    /// the driver `config`, and a pause switch.
    fn ipc_driver_with(
        name: &str,
        max_exports: usize,
        config: DriverConfig,
    ) -> (Driven, std::path::PathBuf, Pause) {
        let paused = Pause {
            asked: Arc::new(AtomicBool::new(false)),
            holding: Arc::new(AtomicBool::new(false)),
        };
        let pause = paused.clone();
        let dir = std::env::temp_dir().join(format!("karyos-facade-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let stop = Arc::new(AtomicBool::new(false));
        let (ready, started) = mpsc::channel();
        let flag = Arc::clone(&stop);
        let path = dir.clone();
        let thread = std::thread::spawn(move || {
            let mut driver: EmbeddedDriver<SharedTerms> = EmbeddedDriver::with_ipc(
                config,
                IpcConfig {
                    dir: path,
                    max_pending_hellos: 2,
                    hello_timeout: 5_000_000_000,
                    max_outbound_per_client: 8,
                    fetch_deadline: 5_000_000_000,
                    max_exports_per_client: max_exports,
                    max_fetches_per_client: 4,
                    max_regions_per_fetch: 4,
                    max_fetch_bytes: 1 << 30,
                    max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
                },
                Box::new(SystemClock::new()),
            )
            .unwrap();
            let stream = StreamConfig {
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
            };
            let _ = driver.add_stream(stream).unwrap();
            // Stream 4 is shared by concurrent publishers (M11).
            let mut shared = stream;
            shared.buffer.stream_id = 4;
            shared.buffer.publication = PublicationMode::Concurrent {
                publishers: 2,
                allow_non_lse: true,
            };
            let _ = driver.add_stream(shared).unwrap();
            // Stream 5 has a conflation table of 4 keys (F7b-2c).
            let mut keyed = stream;
            keyed.buffer.stream_id = 5;
            keyed.conflation = Some(karyos_sys::conflation::ConflationConfig {
                keys: 4,
                value_capacity: 8,
                journal_capacity: 1024,
                refresh: false,
            });
            let _ = driver.add_stream(keyed).unwrap();
            ready.send(()).unwrap();
            while !flag.load(Ordering::Acquire) {
                let held = pause.asked.load(Ordering::Acquire);
                pause.holding.store(held, Ordering::Release);
                if !held {
                    let _ = driver.do_work().unwrap();
                }
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
            paused,
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

    /// #420 review P1: a remote facade client that subscribes by
    /// `karyos:ipc` and drops each subscription is never refused at the
    /// export bound (16): each dropped handle detaches its grant, and the
    /// driver reclaims the registration. Twenty cycles are all admitted,
    /// and the client can still publish; a removed one is admitted too.
    #[test]
    fn subscribe_and_drop_cycles_are_never_refused_at_the_export_bound() {
        let (_driver, dir) = ipc_driver("cycles");
        let mut client = connect(&dir);
        for cycle in 0..20 {
            let subscription = client
                .add_subscription("karyos:ipc", StreamId::new(3))
                .unwrap_or_else(|error| panic!("cycle {cycle}: {error:?}"));
            drop(subscription);
            // The Detach and the reclaim run on the driver's thread.
            for _ in 0..20 {
                let _ = client.poll();
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let removed = client
            .add_subscription("karyos:ipc", StreamId::new(3))
            .unwrap();
        client.remove_subscription(removed);
        assert_eq!(client.subscription_releases_failed(), 0);
        let _publication = client
            .add_exclusive_publication("karyos:ipc", StreamId::new(3))
            .unwrap();
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
        assert_eq!(reading.bound_address(), None);
        let mut publication = client
            .add_exclusive_publication("karyos:ipc", StreamId::new(3))
            .unwrap();
        let (mut sent, mut seen) = (0u32, 0u32);
        let start = Instant::now();
        while seen < 32 {
            assert!(start.elapsed() < Duration::from_secs(20), "seen {seen}");
            let _ = client.poll();
            while sent < 32 {
                match publication.offer(&sent.to_le_bytes()) {
                    Ok(_) => sent += 1,
                    Err(
                        OfferError::BackPressured
                        | OfferError::AdminAction
                        | OfferError::NotConnected,
                    ) => break,
                    Err(error) => panic!("{error}"),
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

    /// M11 remote: two clients take concurrent handles on the shared
    /// `karyos:ipc` stream 4 by URI and both reach its subscriber; the
    /// exclusive stream 3 refuses a concurrent handle.
    #[test]
    fn remote_clients_share_a_concurrent_stream_by_uri() {
        use karyos_client::ConcurrentOfferOutcome;
        use karyos_protocol::cnc::ErrorCode;

        let (_driver, dir) = ipc_driver("concurrent");
        let mut reader = connect(&dir);
        let mut reading = reader
            .add_subscription("karyos:ipc", StreamId::new(4))
            .unwrap();
        let mut clients = [connect(&dir), connect(&dir)];
        let mut publications = clients.each_mut().map(|client| {
            client
                .add_concurrent_publication("karyos:ipc", StreamId::new(4))
                .unwrap()
        });
        let mut sent = [false; 2];
        let mut seen = Vec::new();
        let start = Instant::now();
        while seen.len() < 2 {
            assert!(start.elapsed() < Duration::from_secs(20), "{seen:?}");
            for client in &mut clients {
                let _ = client.poll();
            }
            let _ = reader.poll();
            for ((publication, sent), byte) in publications.iter_mut().zip(&mut sent).zip([1u8, 2])
            {
                if !*sent {
                    *sent = matches!(
                        publication.offer(&[byte; 8]),
                        Ok(ConcurrentOfferOutcome::Accepted { .. })
                    );
                }
            }
            let _ = reading
                .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
                .unwrap();
        }
        seen.sort();
        assert_eq!(seen, [vec![1; 8], vec![2; 8]]);
        assert!(matches!(
            clients[0].add_concurrent_publication("karyos:ipc", StreamId::new(3)),
            Err(ClientError::Refused {
                code: ErrorCode::InvalidPublicationMode,
                ..
            })
        ));
    }

    /// `Client::remove_concurrent_publication` remote: the removal frees the
    /// handle's publisher slot at the driver, so a client at the stream's
    /// bound of two takes a third handle once it removed one.
    #[test]
    fn a_remote_removed_concurrent_handle_frees_its_slot() {
        use karyos_protocol::cnc::ErrorCode;

        let (_driver, dir) = ipc_driver("concurrent-remove");
        let mut client = connect(&dir);
        let first = client
            .add_concurrent_publication("karyos:ipc", StreamId::new(4))
            .unwrap();
        let _second = client
            .add_concurrent_publication("karyos:ipc", StreamId::new(4))
            .unwrap();
        assert!(matches!(
            client.add_concurrent_publication("karyos:ipc", StreamId::new(4)),
            Err(ClientError::Refused {
                code: ErrorCode::PublicationTaken,
                ..
            })
        ));
        client.remove_concurrent_publication(first);
        assert_eq!(client.publication_releases_failed(), 0);
        let start = Instant::now();
        let _third = loop {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "slot never freed"
            );
            let _ = client.poll();
            match client.add_concurrent_publication("karyos:ipc", StreamId::new(4)) {
                Ok(publication) => break publication,
                Err(ClientError::Refused {
                    code: ErrorCode::PublicationTaken,
                    ..
                }) => std::thread::sleep(Duration::from_millis(1)),
                Err(error) => panic!("{error:?}"),
            }
        };
    }

    /// SPEC §10 remote over the network (network-shared-terms n4): on two
    /// IPC drivers, a remote client publishes by `karyos:udp` and another
    /// subscribes by it; the subscriber reads the exact sequence from the
    /// image, whose lanes it fetched as regions, and drops the image once
    /// the publisher removes its publication: the removal ends the image at
    /// its EOS while the publisher stays connected.
    #[test]
    fn a_remote_udp_publication_reaches_a_remote_udp_subscription() {
        let (_a, a_dir) = ipc_network_driver("udp-pub", 500_000_000);
        // A minute: within the wait below, the image can end only at its
        // EOS, never at its liveness timeout.
        let (_b, b_dir) = ipc_network_driver("udp-sub", 60_000_000_000);
        let mut publisher = connect(&a_dir);
        let mut subscriber = connect(&b_dir);
        let port = port();
        let mut reading = subscriber
            .add_subscription(
                &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
                StreamId::new(7),
            )
            .unwrap();
        assert!(reading.registration().is_some());
        // Decision row 26: the grant carried the bound address over the
        // broadcast buffer.
        assert_eq!(
            reading.bound_address(),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        );
        let mut publication = publisher
            .add_exclusive_publication(
                &format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1"),
                StreamId::new(7),
            )
            .unwrap();
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
                match publication.offer(&sent.to_le_bytes()) {
                    Ok(_) => sent += 1,
                    Err(
                        OfferError::BackPressured
                        | OfferError::AdminAction
                        | OfferError::NotConnected,
                    ) => break,
                    Err(error) => panic!("{error}"),
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
        // The publication goes, its client stays: the driver removes the
        // network publication the client created by URI, which ends the
        // image at its EOS.
        publisher.remove_publication(publication);
        until(&mut [&mut subscriber, &mut publisher], || {
            let _ = reading.poll(|_, _| {}, MessageLimit::new(16));
            reading.image_count() == 0
        });
        // Still served.
        let _ = publisher
            .add_subscription("karyos:ipc", StreamId::new(3))
            .unwrap();
    }

    /// Releasing a remote client's `karyos:ipc` publication removes only its
    /// registration: the stream stays, and a subscription of it reads every
    /// message offered before the release.
    #[test]
    fn a_released_remote_ipc_publication_leaves_its_stream() {
        let (_driver, dir) = ipc_driver("ipc-release");
        let mut client = connect(&dir);
        let mut reading = client
            .add_subscription("karyos:ipc", StreamId::new(3))
            .unwrap();
        let mut publication = client
            .add_exclusive_publication("karyos:ipc", StreamId::new(3))
            .unwrap();
        let mut sent = 0u32;
        let start = Instant::now();
        while sent < 16 {
            assert!(start.elapsed() < Duration::from_secs(20), "sent {sent}");
            let _ = client.poll();
            match publication.offer(&sent.to_le_bytes()) {
                Ok(_) => sent += 1,
                Err(
                    OfferError::BackPressured | OfferError::AdminAction | OfferError::NotConnected,
                ) => std::thread::sleep(Duration::from_micros(100)),
                Err(error) => panic!("{error}"),
            }
        }
        client.remove_publication(publication);
        let mut seen = 0u32;
        let start = Instant::now();
        while seen < sent {
            assert!(start.elapsed() < Duration::from_secs(20), "seen {seen}");
            let _ = client.poll();
            let _ = reading
                .poll(
                    |bytes, _| {
                        assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), seen);
                        seen += 1;
                    },
                    MessageLimit::new(8),
                )
                .unwrap();
            std::thread::sleep(Duration::from_micros(100));
        }
        // The stream is still there, and the client still served.
        let _ = client
            .add_subscription("karyos:ipc", StreamId::new(3))
            .unwrap();
    }

    /// `connect` needs the driver's directory.
    #[test]
    fn connect_needs_a_directory() {
        assert!(matches!(
            Client::connect(Context::builder().build().unwrap()).err(),
            Some(ClientError::NoDirectory)
        ));
    }

    /// Plan 166 (karyos#851): `Client::connect` waits the attach timeout,
    /// not the control call's: with the driver paused past a 50 ms call
    /// timeout, a 10 s attach timeout attaches once the driver resumes, and
    /// one left at 50 ms does not. Once attached, the session's socket waits
    /// the 50 ms call timeout, so a fetch still expires at 50 ms.
    #[test]
    fn connect_waits_the_attach_timeout_and_fetches_the_call_timeout() {
        let (_driver, dir, paused) = ipc_driver_with("attach-timeout", 1, DriverConfig::default());
        let call = Duration::from_millis(50);
        paused.hold();
        assert!(matches!(
            karyos_client::ipc::attach_with(&dir, call, call, 4).err(),
            Some(karyos_client::ipc::AttachError::Timeout)
        ));
        let resume = paused.clone();
        let resumer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            resume.resume();
        });
        let remote =
            karyos_client::ipc::attach_with(&dir, Duration::from_secs(10), call, 4).unwrap();
        resumer.join().unwrap();
        let socket = remote.admission_socket().unwrap();
        assert_eq!(
            karyos_sys::ipc::receive_timeout(socket).unwrap(),
            Some(call),
            "the session's fetches wait the call timeout"
        );
    }

    /// A remote publication grant that arrives after its request timed out
    /// is taken and removed at once: a `karyos:udp` publication the client
    /// created by URI ends, so with room for one owned network resource
    /// per client, the next one is granted.
    #[test]
    fn a_remote_late_publication_grant_is_removed() {
        let mut network = NetworkConfig {
            threading: ThreadingMode::Shared,
            max_owned_per_client: 1,
            ..NetworkConfig::default()
        };
        network.stream_defaults.term_length = 64 * 1024;
        let config = DriverConfig {
            network: Some(network),
            ..DriverConfig::default()
        };
        let (_driver, dir, paused) = ipc_driver_with("late-pub", 16, config);
        let mut client = Client::connect(
            Context::builder()
                .dir(&dir)
                .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
                .timeout(Duration::from_millis(50))
                // 50 ms is for the paused request to time out; the attach
                // is the setup and waits as a client's would: under load,
                // 50 ms timed it out (plan 166). The session's fetches keep
                // the 50 ms.
                .attach_timeout(karyos_client::DEFAULT_TIMEOUT)
                .build()
                .unwrap(),
        )
        .unwrap();
        let uri = |port: u16| format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1");
        paused.hold();
        assert_eq!(
            client
                .add_exclusive_publication(&uri(port()), StreamId::new(7))
                .err(),
            Some(ClientError::Timeout)
        );
        paused.resume();
        let start = Instant::now();
        while client.late_grants_released() == 0 {
            assert!(start.elapsed() < Duration::from_secs(10), "not released");
            let _ = client.poll();
            std::thread::sleep(Duration::from_millis(1));
        }
        // The only owned resource is free again.
        let mut granted = None;
        let start = Instant::now();
        while granted.is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the late publication is still owned"
            );
            match client.add_exclusive_publication(&uri(port()), StreamId::new(8)) {
                Ok(publication) => granted = Some(publication),
                // Refused while the late grant is released, or timed out
                // under load: the request's own 50 ms, or its fetch's
                // (plan 166, karyos#851).
                Err(
                    ClientError::Refused { .. }
                    | ClientError::Timeout
                    | ClientError::Attach(karyos_client::ipc::AttachError::Timeout),
                ) => {
                    let _ = client.poll();
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        }
    }

    /// A remote grant that arrives after its request timed out is taken
    /// and dropped at once, so its export is free again: with one export
    /// per client, the next subscription is granted.
    #[test]
    fn a_remote_late_grant_is_released() {
        let (_driver, dir, paused) = ipc_driver_with("late", 1, DriverConfig::default());
        let mut client = Client::connect(
            Context::builder()
                .dir(&dir)
                .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
                .timeout(Duration::from_millis(50))
                // 50 ms is for the paused request to time out; the attach
                // is the setup and waits as a client's would: under load,
                // 50 ms timed it out (plan 166). The session's fetches keep
                // the 50 ms.
                .attach_timeout(karyos_client::DEFAULT_TIMEOUT)
                .build()
                .unwrap(),
        )
        .unwrap();
        paused.hold();
        assert_eq!(
            client
                .add_subscription("karyos:ipc", StreamId::new(3))
                .err(),
            Some(ClientError::Timeout)
        );
        paused.resume();
        let start = Instant::now();
        while client.late_grants_released() == 0 {
            assert!(start.elapsed() < Duration::from_secs(10), "not released");
            let _ = client.poll();
            std::thread::sleep(Duration::from_millis(1));
        }
        // The only export is free again.
        let mut granted = None;
        let start = Instant::now();
        while granted.is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the export is still held"
            );
            match client.add_subscription("karyos:ipc", StreamId::new(3)) {
                Ok(subscription) => granted = Some(subscription),
                // Refused while the late grant is released, or timed out
                // under load: the request's own 50 ms, or its fetch's
                // (plan 166, karyos#851).
                Err(
                    ClientError::Refused { .. }
                    | ClientError::Timeout
                    | ClientError::Attach(karyos_client::ipc::AttachError::Timeout),
                ) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        }
    }

    /// F7b-2c: a remote facade client's conflated view of a `karyos:ipc`
    /// stream reads each key's latest value; a stream without a table is
    /// refused by the driver, and another channel before any request.
    #[test]
    fn a_remote_client_reads_a_conflated_view() {
        let (_driver, dir) = ipc_driver("conflated");
        let mut client = connect(&dir);
        assert!(matches!(
            client.add_conflated_subscription("karyos:udp?endpoint=127.0.0.1:1", StreamId::new(5)),
            Err(ClientError::UnsupportedChannel { .. })
        ));
        assert!(matches!(
            client.add_conflated_subscription("karyos:ipc", StreamId::new(3)),
            Err(ClientError::Refused { .. })
        ));
        let mut view = client
            .add_conflated_subscription("karyos:ipc", StreamId::new(5))
            .unwrap();
        assert_eq!(view.config().keys, 4);
        let mut publication = client
            .add_exclusive_publication("karyos:ipc", StreamId::new(5))
            .unwrap();
        let start = Instant::now();
        for (key, value) in [(1, b"old".as_slice()), (1, b"new"), (2, b"two")] {
            let options = karyos_client::OfferOptions::new().with_reserved_value(key);
            while publication
                .offer_on_with(Lane::ZERO, value, options)
                .is_err()
            {
                assert!(start.elapsed() < Duration::from_secs(10), "never accepted");
                let _ = client.poll();
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let mut latest: Vec<(u32, Vec<u8>)> = Vec::new();
        while latest != [(1, b"new".to_vec()), (2, b"two".to_vec())] {
            assert!(start.elapsed() < Duration::from_secs(10), "{latest:?}");
            let _ = view.poll_changed(|key, value| {
                latest.retain(|(seen, _)| *seen != key);
                latest.push((key, value.payload().to_vec()));
            });
            latest.sort();
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// #523, F7b-2c-2: a remote client's publication of a conflated stream
    /// reads the table's shape from the buffer it attached, as an
    /// in-process one does, and refuses a key outside the table, or a
    /// value larger than its capacity, before anything is appended: the
    /// next key inside the table is the stream's first message.
    #[test]
    fn a_remote_publication_refuses_a_key_outside_its_table() {
        let (_driver, dir) = ipc_driver("remote-key");
        let mut client = connect(&dir);
        let mut subscription = client
            .add_subscription("karyos:ipc", StreamId::new(5))
            .unwrap();
        let mut publication = client
            .add_exclusive_publication("karyos:ipc", StreamId::new(5))
            .unwrap();
        let keyed = |key| karyos_client::OfferOptions::new().with_reserved_value(key);
        for (key, value) in [(4, b"v".as_slice()), (-1, b"v"), (0, b"too-long!")] {
            assert!(
                matches!(
                    publication.offer_on_with(Lane::ZERO, value, keyed(key)),
                    Err(karyos_client::OfferError::Client(ClientError::Conflation(
                        _
                    )))
                ),
                "key {key}, {} bytes accepted",
                value.len()
            );
        }
        let start = Instant::now();
        let accepted = loop {
            match publication.offer_on_with(Lane::ZERO, b"first", keyed(3)) {
                Ok(accepted) => break accepted,
                Err(_) => {
                    assert!(start.elapsed() < Duration::from_secs(10), "never accepted");
                    let _ = client.poll();
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        assert_eq!(accepted.position(), 0);
        let mut seen = Vec::new();
        while seen.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(10), "nothing read");
            let _ = subscription.poll(
                |bytes, info| seen.push((bytes.to_vec(), info.reserved_value)),
                karyos_client::MessageLimit::new(8),
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(seen, [(b"first".to_vec(), 3)]);
    }

    /// F7b-2c: a conflated grant that arrives after its request timed out
    /// is taken and dropped, which sends its `Detach`: with one export per
    /// client, the next view is granted.
    #[test]
    fn a_remote_late_conflated_grant_is_released() {
        let (_driver, dir, paused) = ipc_driver_with("late-view", 1, DriverConfig::default());
        let mut client = Client::connect(
            Context::builder()
                .dir(&dir)
                .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
                .timeout(Duration::from_millis(50))
                // 50 ms is for the paused request to time out; the attach
                // is the setup and waits as a client's would: under load,
                // 50 ms timed it out (plan 166). The session's fetches keep
                // the 50 ms.
                .attach_timeout(karyos_client::DEFAULT_TIMEOUT)
                .build()
                .unwrap(),
        )
        .unwrap();
        paused.hold();
        assert_eq!(
            client
                .add_conflated_subscription("karyos:ipc", StreamId::new(5))
                .err(),
            Some(ClientError::Timeout)
        );
        paused.resume();
        let start = Instant::now();
        while client.late_grants_released() == 0 {
            assert!(start.elapsed() < Duration::from_secs(10), "not released");
            let _ = client.poll();
            std::thread::sleep(Duration::from_millis(1));
        }
        // The only export is free again.
        let mut granted = None;
        let start = Instant::now();
        while granted.is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the export is still held"
            );
            match client.add_conflated_subscription("karyos:ipc", StreamId::new(5)) {
                Ok(view) => granted = Some(view),
                // Refused while the late grant is released, or timed out
                // under load: the request's own 50 ms, or its fetch's
                // (plan 166, karyos#851).
                Err(
                    ClientError::Refused { .. }
                    | ClientError::Timeout
                    | ClientError::Attach(karyos_client::ipc::AttachError::Timeout),
                ) => {
                    let _ = client.poll();
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        }
    }
}

/// Runs `work` on another thread while `driver` is served here, and
/// returns what it returns.
fn serve<R: Send>(driver: &mut EmbeddedDriver, work: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(work);
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(50));
        }
        handle.join().unwrap()
    })
}

/// A heap aggregate of `stream_id` with `lanes` lanes.
fn heap_aggregate(stream_id: i32, lanes: usize) -> karyos_driver::AggregateConfig {
    karyos_driver::AggregateConfig {
        stream: heap_stream(stream_id),
        quanta: vec![u64::from(karyos_sys::sizing::DEFAULT_MTU) * 4; lanes],
    }
}

/// SPEC §10 (W8): offers and claims return `Result<Accepted, OfferError>`;
/// a claim dropped uncommitted aborts its frame, which is never delivered;
/// the errors map to their `OfferError` variants.
#[test]
fn offers_and_claims_have_the_spec_shape() {
    use karyos_client::MessageLength;
    use karyos_sys::frame::Lane;

    let mut driver = EmbeddedDriver::new().unwrap();
    let _ = driver.add_stream(heap_stream(1)).unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    serve(&mut driver, || {
        let mut reading = client
            .add_subscription("karyos:ipc", StreamId::new(1))
            .unwrap();
        let mut publication = client
            .add_exclusive_publication("karyos:ipc", StreamId::new(1))
            .unwrap();
        assert_eq!(publication.lane_count(), 1);
        let length = MessageLength::try_new(8).unwrap();
        // Dropped uncommitted: aborted.
        {
            let mut claim = publication.try_claim(length).unwrap();
            claim.payload().fill(1);
        }
        let mut claim = publication.try_claim(length).unwrap();
        claim.payload().fill(2);
        let committed = claim.commit().unwrap();
        assert_eq!(committed.lane(), Lane::ZERO);
        // An explicit abort, then an offer.
        publication.try_claim(length).unwrap().abort();
        let offered = publication.offer(&[3; 8]).unwrap();
        assert!(offered.position() > committed.position());
        // Errors.
        assert_eq!(
            publication.offer_on(Lane::try_new(1).unwrap(), b"x"),
            Err(OfferError::InvalidLane {
                lane: Lane::try_new(1).unwrap()
            })
        );
        assert_eq!(
            publication.offer(&[]),
            Err(OfferError::Client(ClientError::EmptyMessage))
        );
        let max = publication.max_message_length(Lane::ZERO).unwrap();
        assert!(matches!(
            publication.offer(&vec![0; max as usize + 1]),
            Err(OfferError::MessageTooLarge { .. })
        ));
        assert_eq!(MessageLength::try_new(0), Err(ClientError::EmptyMessage));
        // Only the committed frame and the offer are delivered; the poll
        // reports the aborted blocks it stepped over.
        let mut seen = Vec::new();
        let mut aborted = 0;
        let start = Instant::now();
        while seen.len() < 2 {
            assert!(start.elapsed() < Duration::from_secs(10), "{seen:?}");
            let _ = client.poll();
            let poll = reading
                .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
                .unwrap();
            if poll
                .stopped
                .is_some_and(|stop| stop.summary.aborted.is_some())
            {
                aborted += 1;
            }
        }
        assert_eq!(seen, [vec![2; 8], vec![3; 8]]);
        assert!(aborted > 0, "the aborted frames were stepped over");
    });
}

/// `offer_at_on` (timed-tx.md; owner item 57): a timed lane granted over
/// the in-process command ring is bound to the schedule its driver wrote,
/// so the facade offers on it with a time. A plain offer, a time below the
/// lane's last, one past the horizon and an unconfigured lane are refused
/// before anything is reserved; the accepted message is delivered. Since
/// owner item 65 a timed lane is a network publication's: the client adds
/// one by URI on a stream the driver configures timed
/// (`NetworkStreamDefaults::timed`), and reads it back over loopback.
#[test]
fn a_timed_lane_is_offered_at_its_time() {
    use karyos_client::schedule::{ClockDomain, ScheduleOptions, now};
    use karyos_driver::net::TimedNetworkStream;
    use karyos_sys::frame::Lane;

    let horizon = ScheduleOptions::default().max_horizon;
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.stream_defaults.timed[0] = Some(TimedNetworkStream {
        stream_id: 3,
        schedule_capacity: 4,
    });
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let uri = format!("karyos:udp?endpoint=127.0.0.1:{}", port());
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    serve(&mut driver, || {
        let mut reading = client.add_subscription(&uri, StreamId::new(3)).unwrap();
        let mut publication = client
            .add_exclusive_publication(&uri, StreamId::new(3))
            .unwrap();
        // Accepted once the loopback receiver's status messages connect it.
        let start = Instant::now();
        let (at, accepted) = loop {
            let at = now(ClockDomain::Monotonic).unwrap();
            match publication.offer_at_on(Lane::ZERO, b"timed", at) {
                Err(OfferError::NotConnected) => {
                    assert!(start.elapsed() < Duration::from_secs(10), "never connected");
                    let _ = client.poll();
                    std::thread::sleep(Duration::from_millis(1));
                }
                other => break (at, other.unwrap()),
            }
        };
        assert_eq!(accepted.lane(), Lane::ZERO);
        assert!(matches!(
            publication.offer_on(Lane::ZERO, b"plain"),
            Err(OfferError::InvalidSchedule { .. })
        ));
        assert!(matches!(
            publication.offer_at_on(Lane::ZERO, b"back", at - 1),
            Err(OfferError::InvalidSchedule { .. })
        ));
        assert!(matches!(
            publication.offer_at_on(Lane::ZERO, b"far", at + 10 * horizon),
            Err(OfferError::Client(ClientError::ScheduleTooFar { .. }))
        ));
        assert_eq!(
            publication.offer_at_on(Lane::try_new(1).unwrap(), b"x", at),
            Err(OfferError::InvalidLane {
                lane: Lane::try_new(1).unwrap()
            })
        );
        let mut seen = Vec::new();
        let start = Instant::now();
        while seen.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(10), "never read");
            let _ = client.poll();
            let _ = reading
                .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
                .unwrap();
        }
        assert_eq!(seen, [b"timed".to_vec()]);
    });
}

/// A publication holds every lane its aggregate configures: `offer_on`
/// reaches the lane's own handle, and a lane beyond them is refused.
#[test]
fn a_publication_holds_every_lane_of_its_aggregate() {
    use karyos_sys::frame::Lane;

    let mut driver = EmbeddedDriver::new().unwrap();
    // Not allow_unconnected: a client's publication takes the stream's
    // policy, and lane 1 must report that it has no subscriber.
    let mut config = heap_aggregate(2, 2);
    config.stream.allow_unconnected = false;
    let aggregate = driver.add_aggregate(config).unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    let publication = serve(&mut driver, || {
        // A subscriber on lane 0 only.
        let _reading = client
            .add_subscription("karyos:ipc", StreamId::new(2))
            .unwrap();
        let mut publication = client
            .add_exclusive_publication("karyos:ipc", StreamId::new(2))
            .unwrap();
        assert_eq!(publication.lane_count(), 2);
        assert_eq!(publication.offer(b"zero").unwrap().lane(), Lane::ZERO);
        // Lane 1 has its own handle, with no subscriber yet.
        assert_eq!(
            publication.offer_on(Lane::try_new(1).unwrap(), b"one"),
            Err(OfferError::NotConnected)
        );
        publication
    });
    // A reader of lane 1: its offers are accepted on lane 1.
    let _lane_one = driver
        .subscribe(
            aggregate.lane(Lane::try_new(1).unwrap()).unwrap(),
            karyos_sys::log_buffer::Role::Required,
        )
        .unwrap();
    let mut publication = publication;
    let accepted = publication
        .offer_on(Lane::try_new(1).unwrap(), b"one")
        .unwrap();
    assert_eq!(accepted.lane(), Lane::try_new(1).unwrap());
    serve(&mut driver, || {
        assert!(matches!(
            publication.offer_on(Lane::try_new(2).unwrap(), b"two"),
            Err(OfferError::InvalidLane { .. })
        ));
        client.remove_publication(publication);
    });
}

/// The lanes are taken all or nothing: a lane already taken refuses the
/// publication, and the lanes granted before it are released.
#[test]
fn a_refused_lane_releases_the_lanes_already_granted() {
    use karyos_sys::frame::Lane;

    let mut driver = EmbeddedDriver::new().unwrap();
    let aggregate = driver.add_aggregate(heap_aggregate(3, 2)).unwrap();
    let first = aggregate.lane(Lane::ZERO).unwrap();
    // Another client holds lane 1's exclusive publication.
    let mut other = driver.connect().unwrap();
    let key = karyos_protocol::cnc::StreamKey {
        stream_id: 3,
        session_id: 1,
    };
    let sequence = other
        .add_publication_on_lane(key, Lane::try_new(1).unwrap(), true)
        .unwrap();
    let mut held = None;
    let start = Instant::now();
    while held.is_none() {
        assert!(start.elapsed() < Duration::from_secs(5));
        let _ = driver.do_work().unwrap();
        let _ = other.poll(usize::MAX, |completion| {
            assert_eq!(completion.sequence, sequence);
            held = Some(completion.outcome);
        });
    }
    assert!(matches!(held, Some(karyos_client::Outcome::Publication(_))));
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    let refused = serve(&mut driver, || {
        client
            .add_exclusive_publication("karyos:ipc", StreamId::new(3))
            .err()
    });
    assert!(matches!(
        refused,
        Some(ClientError::Refused {
            code: karyos_protocol::cnc::ErrorCode::PublicationTaken,
            ..
        })
    ));
    // Lane 0's grant was released.
    let start = Instant::now();
    while driver.live_leases(first).unwrap() > 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "lane 0 is still held"
        );
        let _ = driver.do_work().unwrap();
        let _ = client.poll();
    }
}

/// A URI that names `lanes` takes exactly that many: the driver refuses
/// another count with `LaneMismatch` before granting anything, so nothing
/// is held and the stream's publication can be asked for again with the
/// right count.
#[test]
fn a_named_lane_count_is_taken_exactly() {
    use karyos_sys::frame::Lane;

    let mut driver = EmbeddedDriver::new().unwrap();
    let aggregate = driver.add_aggregate(heap_aggregate(4, 2)).unwrap();
    let lanes = [Lane::ZERO, Lane::try_new(1).unwrap()].map(|lane| aggregate.lane(lane).unwrap());
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    let refused = serve(&mut driver, || {
        client
            .add_exclusive_publication("karyos:ipc?lanes=4", StreamId::new(4))
            .err()
    });
    assert_eq!(
        refused,
        Some(ClientError::Refused {
            code: karyos_protocol::cnc::ErrorCode::LaneMismatch,
            detail: 2,
        })
    );
    for lane in lanes {
        assert_eq!(driver.live_leases(lane).unwrap(), 0, "nothing was granted");
    }
    // The incarnation was not spent: the right count is granted.
    let publication = serve(&mut driver, || {
        client.add_exclusive_publication("karyos:ipc?lanes=2", StreamId::new(4))
    });
    assert_eq!(publication.unwrap().lane_count(), 2);
}

/// A publication released whose removal cannot be sent is dropped and
/// counted (#402 review P3): client B releasing client A's publication
/// gets `ForeignHandle` from its own connection, so B counts one failed
/// release; A's release of its own publication is sent and counts none.
#[test]
fn a_release_whose_removal_cannot_be_sent_is_counted() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let _ = driver.add_stream(heap_stream(5)).unwrap();
    let _ = driver.add_stream(heap_stream(6)).unwrap();
    let mut a = Client::with_conductor(driver.connect().unwrap(), context());
    let mut b = Client::with_conductor(driver.connect().unwrap(), context());
    serve(&mut driver, || {
        let foreign = a
            .add_exclusive_publication("karyos:ipc", StreamId::new(5))
            .unwrap();
        b.remove_publication(foreign);
        assert_eq!(b.publication_releases_failed(), 1);
        assert_eq!(a.publication_releases_failed(), 0);
        let own = a
            .add_exclusive_publication("karyos:ipc", StreamId::new(6))
            .unwrap();
        a.remove_publication(own);
        assert_eq!(a.publication_releases_failed(), 0);
    });
}

/// Task 2 (A7d-3): a network subscription reports each image it attaches
/// and retires, in order, with its attach id: a publication that goes and
/// one that comes back are two images. Polling without draining keeps
/// the latest `3 * max_images` changes and counts the ones dropped.
#[test]
fn a_network_subscription_reports_its_image_changes() {
    for drain in [true, false] {
        let (_a, mut a) = driven(2, None);
        let (_b, mut b) = driven(1, Some(500_000_000));
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
                StreamId::new(11),
            )
            .unwrap();
        let uri = format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1");
        let mut changes = Vec::new();
        let take = |reading: &mut karyos_client::Subscription<_>,
                    changes: &mut Vec<karyos_client::ImageChange>| {
            if drain {
                reading.image_changes(&mut |change| changes.push(change));
            } else {
                let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
            }
        };
        let one = first
            .add_exclusive_publication(&uri, StreamId::new(11))
            .unwrap();
        until(&mut [&mut subscriber, &mut first], || {
            take(&mut reading, &mut changes);
            reading.image_count() == 1
        });
        drop(one);
        until(&mut [&mut subscriber, &mut first], || {
            take(&mut reading, &mut changes);
            reading.image_count() == 0
        });
        let two = second
            .add_exclusive_publication(&uri, StreamId::new(11))
            .unwrap();
        until(&mut [&mut subscriber, &mut second], || {
            take(&mut reading, &mut changes);
            reading.image_count() == 1
        });
        if !drain {
            // A fourth change: one more than the queue holds.
            drop(two);
            until(&mut [&mut subscriber, &mut second], || {
                take(&mut reading, &mut changes);
                reading.image_count() == 0
            });
        }
        if drain {
            let seen: Vec<_> = changes.iter().map(|change| change.available).collect();
            assert_eq!(seen, [true, false, true]);
            assert_eq!(changes[0].image_id, changes[1].image_id);
            assert_ne!(changes[1].image_id, changes[2].image_id, "a new image");
            assert_eq!(reading.image_changes_lost(), 0);
        } else {
            // Room for three: the first attach was dropped, counted.
            // Taken one at a time.
            while let Some(change) = reading.next_image_change() {
                changes.push(change);
            }
            let seen: Vec<_> = changes.iter().map(|change| change.available).collect();
            assert_eq!(seen, [false, true, false]);
            assert_eq!(reading.image_changes_lost(), 1);
        }
    }
}

/// A7d-3: `poll_taking` over a network subscription's images. A decline
/// in one image stops the poll; that message is the next one delivered,
/// from that image, and is then taken once; what the other image
/// delivered stays taken. Each message carries its image's session.
#[test]
fn a_network_subscription_takes_messages_and_declines_one() {
    let (_a, mut a) = driven(2, None);
    let (_b, mut b) = driven(1, None);
    let mut first = Client::with_conductor(a.remove(0), context());
    let mut second = Client::with_conductor(a.remove(0), context());
    let mut subscriber = Client::with_conductor(b.remove(0), context());
    let port = port();
    let mut reading = subscriber
        .add_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(12),
        )
        .unwrap();
    let uri = format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1");
    let mut one = first
        .add_exclusive_publication(&uri, StreamId::new(12))
        .unwrap();
    let mut two = second
        .add_exclusive_publication(&uri, StreamId::new(12))
        .unwrap();
    until(&mut [&mut subscriber, &mut first, &mut second], || {
        let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
        reading.image_count() == 2
    });
    let mut offered = [0u8; 2];
    let start = Instant::now();
    while offered != [8, 8] {
        assert!(start.elapsed() < Duration::from_secs(20), "{offered:?}");
        let _ = (first.poll(), second.poll(), subscriber.poll());
        for (index, (publication, tag)) in
            [(&mut one, b'1'), (&mut two, b'2')].into_iter().enumerate()
        {
            if offered[index] < 8 && publication.offer(&[tag, offered[index]]).is_ok() {
                offered[index] += 1;
            }
        }
    }
    // Every delivery, declined or taken, with its session; one a poll, so
    // the images alternate and both hold messages at the decline.
    let mut delivered: Vec<(u8, u8, i32, bool)> = Vec::new();
    let mut declined = false;
    let start = Instant::now();
    while delivered.iter().filter(|(.., taken)| *taken).count() < 16 {
        assert!(start.elapsed() < Duration::from_secs(20), "{delivered:?}");
        let _ = (first.poll(), second.poll(), subscriber.poll());
        let _ = reading
            .poll_taking(
                |bytes, info| {
                    let take = declined || (bytes[0], bytes[1]) != (b'2', 3);
                    if !take {
                        declined = true;
                    }
                    delivered.push((bytes[0], bytes[1], info.session_id, take));
                    take
                },
                MessageLimit::new(1),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    let at = delivered
        .iter()
        .position(|(tag, index, _, taken)| (*tag, *index, *taken) == (b'2', 3, false))
        .expect("the decline happened");
    // The declined message comes next, from its image, and is taken.
    assert_eq!(
        (
            delivered[at + 1].0,
            delivered[at + 1].1,
            delivered[at + 1].3
        ),
        (b'2', 3, true)
    );
    for tag in *b"12" {
        let taken: Vec<u8> = delivered
            .iter()
            .filter(|(t, .., taken)| *t == tag && *taken)
            .map(|(_, index, ..)| *index)
            .collect();
        assert_eq!(taken, (0..8).collect::<Vec<u8>>(), "image {}", tag as char);
        let sessions: std::collections::BTreeSet<i32> = delivered
            .iter()
            .filter(|(t, ..)| *t == tag)
            .map(|(_, _, session, _)| *session)
            .collect();
        assert_eq!(sessions.len(), 1, "one session per image");
    }
    let session = |tag| delivered.iter().find(|(t, ..)| *t == tag).unwrap().2;
    assert_ne!(session(b'1'), session(b'2'));
}

/// M11: `add_concurrent_publication` takes a concurrent handle on lane 0
/// of a `karyos:ipc` stream configured concurrent, by URI, shared with the
/// stream's other publishers; an exclusive stream refuses it with
/// `InvalidPublicationMode`, a `karyos:udp` channel with
/// `UnsupportedChannel`.
#[test]
fn a_concurrent_publication_is_taken_by_uri() {
    use karyos_client::ConcurrentOfferOutcome;
    use karyos_protocol::cnc::ErrorCode;
    use karyos_sys::log_buffer::PublicationMode;

    let mut driver = EmbeddedDriver::new().unwrap();
    let mut shared = heap_stream(4);
    shared.buffer.publication = PublicationMode::Concurrent {
        publishers: 2,
        allow_non_lse: true,
    };
    let _ = driver.add_stream(shared).unwrap();
    let _ = driver.add_stream(heap_stream(5)).unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    serve(&mut driver, || {
        let mut reading = client
            .add_subscription("karyos:ipc", StreamId::new(4))
            .unwrap();
        // Two handles at once: the stream is shared.
        let mut first = client
            .add_concurrent_publication("karyos:ipc", StreamId::new(4))
            .unwrap();
        let mut second = client
            .add_concurrent_publication("karyos:ipc", StreamId::new(4))
            .unwrap();
        for (publication, byte) in [(&mut first, 1u8), (&mut second, 2)] {
            assert!(matches!(
                publication.offer(&[byte; 8]).unwrap(),
                ConcurrentOfferOutcome::Accepted { .. }
            ));
        }
        let mut seen = Vec::new();
        let start = Instant::now();
        while seen.len() < 2 {
            assert!(start.elapsed() < Duration::from_secs(10), "{seen:?}");
            let _ = client.poll();
            let _ = reading
                .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
                .unwrap();
        }
        assert_eq!(seen, [vec![1; 8], vec![2; 8]]);
        // An exclusive stream, and a network channel, refuse it.
        assert!(matches!(
            client.add_concurrent_publication("karyos:ipc", StreamId::new(5)),
            Err(ClientError::Refused {
                code: ErrorCode::InvalidPublicationMode,
                ..
            })
        ));
        assert!(matches!(
            client.add_concurrent_publication("karyos:udp?endpoint=127.0.0.1:9", StreamId::new(4)),
            Err(ClientError::UnsupportedChannel { .. })
        ));
    });
}

/// `Client::remove_concurrent_publication` frees the handle's publisher
/// slot: on a stream of two publishers, a third handle is refused while two
/// are held, and taken once one is removed.
#[test]
fn a_removed_concurrent_handle_frees_its_slot() {
    use karyos_protocol::cnc::ErrorCode;
    use karyos_sys::log_buffer::PublicationMode;

    let mut driver = EmbeddedDriver::new().unwrap();
    let mut shared = heap_stream(4);
    shared.buffer.publication = PublicationMode::Concurrent {
        publishers: 2,
        allow_non_lse: true,
    };
    let _ = driver.add_stream(shared).unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    serve(&mut driver, || {
        let first = client
            .add_concurrent_publication("karyos:ipc", StreamId::new(4))
            .unwrap();
        let _second = client
            .add_concurrent_publication("karyos:ipc", StreamId::new(4))
            .unwrap();
        assert!(matches!(
            client.add_concurrent_publication("karyos:ipc", StreamId::new(4)),
            Err(ClientError::Refused {
                code: ErrorCode::PublicationTaken,
                ..
            })
        ));
        client.remove_concurrent_publication(first);
        assert_eq!(client.publication_releases_failed(), 0);
        // The removal is served on the driver's thread; then the slot is
        // free again.
        let start = Instant::now();
        let _third = loop {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "slot never freed"
            );
            let _ = client.poll();
            match client.add_concurrent_publication("karyos:ipc", StreamId::new(4)) {
                Ok(publication) => break publication,
                Err(ClientError::Refused {
                    code: ErrorCode::PublicationTaken,
                    ..
                }) => std::thread::sleep(Duration::from_millis(1)),
                Err(error) => panic!("{error:?}"),
            }
        };
    });
}

/// karyos#490: one driver holds both ends of a `karyos:udp` endpoint. Its
/// own network publication's loopback image shares the publication's key,
/// and is exposed beside it: a subscription of the driver reads what a
/// publication of the same driver offers. Dropping the publication retires
/// the image (its EOS), and the subscription lets it go.
#[test]
fn one_driver_carries_its_own_udp_publication_to_its_subscription() {
    let (_driver, mut conductors) = driven(2, Some(500_000_000));
    let mut subscriber = Client::with_conductor(conductors.remove(0), context());
    let mut publisher = Client::with_conductor(conductors.remove(0), context());
    let port = port();
    let mut reading = subscriber
        .add_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(7),
        )
        .unwrap();
    let mut publication = publisher
        .add_exclusive_publication(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1"),
            StreamId::new(7),
        )
        .unwrap();
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
            match publication.offer(&sent.to_le_bytes()) {
                Ok(_) => sent += 1,
                Err(
                    OfferError::BackPressured | OfferError::AdminAction | OfferError::NotConnected,
                ) => break,
                Err(error) => panic!("{error}"),
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
    assert_eq!(reading.images_refused(), 0);
    // The local publication goes: its loopback image retires and leaves
    // the subscription, which stays usable.
    drop(publication);
    until(&mut [&mut subscriber, &mut publisher], || {
        let _ = reading.poll(|_, _| {}, MessageLimit::new(16));
        reading.image_count() == 0
    });
}

/// Item 57 (FFI F4): a reader that polls as the C ABI does (`adopt`, then
/// `poll_adopted`, and one more round when it stopped at a seal) follows
/// a cutover to a larger term within its calls: every message arrives in
/// order, none longer than the largest it read after adopting, and the
/// driver's fence never fires (the predecessor is freed: its reader
/// moved). A reconfiguration keeps the MTU and `max_reserved`, so the
/// largest message stays the same here; the unit tests of karyos-client
/// cover a successor whose largest message grows.
#[test]
fn a_reader_that_adopts_follows_a_cutover() {
    use karyos_client::Subscription;
    use karyos_driver::Reconfiguration;
    use karyos_sys::sizing::{MIN_TERM_LENGTH, TermLength};

    /// One call of the C ABI's poll: at most one extra round at a seal.
    fn ffi_poll(
        reading: &mut Subscription<karyos_sys::term_bytes::HeapTerms>,
        seen: &mut Vec<Vec<u8>>,
    ) -> usize {
        let mut largest = 0;
        for _ in 0..2 {
            reading.adopt();
            largest = largest.max(reading.max_message_length() as usize);
            let poll = reading
                .poll_adopted(
                    |bytes, _| {
                        assert!(bytes.len() <= largest, "a message past the largest");
                        seen.push(bytes.to_vec());
                    },
                    MessageLimit::new(8),
                )
                .unwrap();
            if !poll.stopped_at_seal {
                break;
            }
        }
        largest
    }

    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(heap_stream(11)).unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    let mut reading = serve(&mut driver, || {
        client
            .add_subscription("karyos:ipc", StreamId::new(11))
            .unwrap()
    });
    let mut writer = driver.publication(stream).unwrap();
    let mut seen = Vec::new();
    assert!(matches!(
        writer.offer(b"one").unwrap(),
        karyos_client::OfferOutcome::Accepted { .. }
    ));
    let before = ffi_poll(&mut reading, &mut seen);
    let _ = driver
        .reconfigure_stream(
            stream,
            Reconfiguration {
                term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                spare_slots: 3,
            },
        )
        .unwrap();
    // The writer moves to the successor (its offers answer AdminAction
    // until then) and writes its largest message there.
    let mut written = vec![b"one".to_vec()];
    let start = Instant::now();
    while written.len() < 2 {
        assert!(start.elapsed() < Duration::from_secs(10), "no move");
        let _ = driver.do_work().unwrap();
        let _ = client.poll();
        let message = vec![7u8; writer.max_message_length() as usize];
        if matches!(
            writer.offer(&message).unwrap(),
            karyos_client::OfferOutcome::Accepted { .. }
        ) {
            written.push(message);
        }
        let _ = ffi_poll(&mut reading, &mut seen);
    }
    let start = Instant::now();
    while seen.len() < written.len() {
        assert!(start.elapsed() < Duration::from_secs(10), "{}", seen.len());
        let _ = driver.do_work().unwrap();
        let _ = client.poll();
        let _ = ffi_poll(&mut reading, &mut seen);
    }
    assert_eq!(seen, written, "every message, in order");
    assert_eq!(written[1].len(), before, "the largest message, unchanged");
    // The reader moved: the predecessor goes once nothing holds it.
    let start = Instant::now();
    while driver.generations(stream).unwrap().len() > 1 {
        assert!(start.elapsed() < Duration::from_secs(10), "not freed");
        let _ = driver.do_work().unwrap();
        let _ = ffi_poll(&mut reading, &mut seen);
    }
    assert_eq!(seen.len(), written.len());
}

/// `Client::add_subscription_with` (owner item 57): an optional reader does
/// not bound its publisher, so offers run past it while it reads nothing;
/// under the `Close` policy its next poll reports the overrun that closed
/// it, and it stays closed. A required reader of the same stream bounds
/// the publisher instead.
#[test]
fn an_optional_reader_under_close_is_closed_by_its_overrun() {
    use karyos_client::{RejoinPolicy, SubscriberRole, SubscriptionOptions};

    let mut driver = EmbeddedDriver::new().unwrap();
    let _ = driver.add_stream(heap_stream(1)).unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    serve(&mut driver, || {
        let mut optional = client
            .add_subscription_with(
                "karyos:ipc",
                StreamId::new(1),
                SubscriptionOptions::new(SubscriberRole::Optional, RejoinPolicy::Close),
            )
            .unwrap();
        let mut publication = client
            .add_exclusive_publication("karyos:ipc", StreamId::new(1))
            .unwrap();
        // Far more than the reader's window, unread: the publisher's limit
        // moves on without it (back pressure only until the driver's next
        // duty cycle advances the limit).
        let message = [7u8; 1024];
        let terms = karyos_sys::sizing::MIN_TERM_LENGTH as usize * 4;
        let start = Instant::now();
        for _ in 0..terms / message.len() {
            while publication.offer(&message).is_err() {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "held by an optional reader"
                );
                std::thread::sleep(Duration::from_micros(50));
            }
        }
        let poll = optional.poll(|_, _| {}, MessageLimit::new(1024)).unwrap();
        let summary = poll.stopped.expect("the overrun stops the poll").summary;
        assert!(summary.closed_by_overrun.is_some(), "{summary:?}");
        // Closed for good: nothing more is delivered.
        let again = optional.poll(
            |_, _| panic!("delivered after its close"),
            MessageLimit::new(8),
        );
        assert!(
            again.is_err() || again.as_ref().is_ok_and(|poll| poll.delivered == 0),
            "{again:?}"
        );
    });
}

/// A required reader (the default options) bounds its publisher: offers
/// past its window are back pressured until it reads.
#[test]
fn a_required_reader_bounds_its_publisher() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let _ = driver.add_stream(heap_stream(1)).unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    serve(&mut driver, || {
        let _required = client
            .add_subscription_with(
                "karyos:ipc",
                StreamId::new(1),
                karyos_client::SubscriptionOptions::default(),
            )
            .unwrap();
        let mut publication = client
            .add_exclusive_publication("karyos:ipc", StreamId::new(1))
            .unwrap();
        let message = [7u8; 1024];
        let terms = karyos_sys::sizing::MIN_TERM_LENGTH as usize * 4;
        let refused = (0..terms / message.len())
            .map(|_| publication.offer(&message))
            .filter(Result::is_err)
            .count();
        assert!(
            refused > 0,
            "an unread required reader holds the publisher back"
        );
    });
}

/// A snapshot rejoin serves one stream: a network subscription refuses it
/// before anything is requested.
#[test]
fn a_network_subscription_refuses_a_snapshot_rejoin() {
    use karyos_client::{
        Overrun, RejoinPolicy, SnapshotFailed, SnapshotSource, SubscriberRole, SubscriptionOptions,
    };

    struct Source;
    impl SnapshotSource for Source {
        fn rebuild(&mut self, _: &Overrun) -> Result<(), SnapshotFailed> {
            Ok(())
        }
    }
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    let refused = client.add_subscription_with(
        &format!("karyos:udp?endpoint=127.0.0.1:{}", port()),
        StreamId::new(1),
        SubscriptionOptions::new(
            SubscriberRole::Optional,
            RejoinPolicy::Snapshot(Box::new(Source)),
        ),
    );
    assert!(
        matches!(refused, Err(ClientError::InvalidOptions { .. })),
        "{refused:?}"
    );
    let _ = driver.do_work();
}

/// A network subscription's options reach its images: an optional reader
/// under `Close` attaches its image with that role and a copy of the policy
/// (the driver accepts the role), and reads its messages.
#[test]
fn a_network_subscription_attaches_its_images_with_its_options() {
    use karyos_client::{RejoinPolicy, SubscriberRole, SubscriptionOptions};

    let (_a, mut a) = driven(1, None);
    let (_b, mut b) = driven(1, None);
    let mut publisher = Client::with_conductor(a.remove(0), context());
    let mut subscriber = Client::with_conductor(b.remove(0), context());
    let port = port();
    let mut reading = subscriber
        .add_subscription_with(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(7),
            SubscriptionOptions::new(SubscriberRole::Optional, RejoinPolicy::Close),
        )
        .unwrap();
    let mut publication = publisher
        .add_exclusive_publication(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1"),
            StreamId::new(7),
        )
        .unwrap();
    until(&mut [&mut subscriber, &mut publisher], || {
        let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
        reading.image_count() == 1
    });
    assert_eq!(reading.images_refused(), 0);
    let (mut sent, mut seen) = (0u32, 0u32);
    let start = Instant::now();
    while seen < 16 {
        assert!(start.elapsed() < Duration::from_secs(20), "seen {seen}");
        let _ = publisher.poll();
        let _ = subscriber.poll();
        while sent < 16 {
            match publication.offer(&sent.to_le_bytes()) {
                Ok(_) => sent += 1,
                Err(
                    OfferError::BackPressured | OfferError::AdminAction | OfferError::NotConnected,
                ) => break,
                Err(error) => panic!("{error}"),
            }
        }
        let _ = reading
            .poll(|_, _| seen += 1, MessageLimit::new(16))
            .unwrap();
        std::thread::sleep(Duration::from_micros(100));
    }
}

/// An image takes a copy of its network subscription's policy: an
/// optional reader under `Close` that never polls is lapped as its image
/// fills past its window, and the poll then reports the overrun that
/// closed it.
#[test]
fn a_network_image_is_closed_by_its_copied_policy() {
    use karyos_client::{RejoinPolicy, SubscriberRole, SubscriptionOptions};

    let (_a, mut a) = driven(1, None);
    let (_b, mut b) = driven(1, None);
    let mut publisher = Client::with_conductor(a.remove(0), context());
    let mut subscriber = Client::with_conductor(b.remove(0), context());
    let port = port();
    let mut reading = subscriber
        .add_subscription_with(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(7),
            SubscriptionOptions::new(SubscriberRole::Optional, RejoinPolicy::Close),
        )
        .unwrap();
    let mut publication = publisher
        .add_exclusive_publication(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1"),
            StreamId::new(7),
        )
        .unwrap();
    until(&mut [&mut subscriber, &mut publisher], || {
        let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
        reading.image_count() == 1
    });
    // Four terms (64 KiB each in `driven`) offered, none read.
    let message = [7u8; 1024];
    let mut sent = 0usize;
    let start = Instant::now();
    while sent < 4 * 64 {
        assert!(start.elapsed() < Duration::from_secs(20), "sent {sent}");
        let _ = publisher.poll();
        let _ = subscriber.poll();
        match publication.offer(&message) {
            Ok(_) => sent += 1,
            Err(OfferError::BackPressured | OfferError::AdminAction | OfferError::NotConnected) => {
                std::thread::sleep(Duration::from_micros(100));
            }
            Err(error) => panic!("{error}"),
        }
    }
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(20), "never closed");
        let _ = subscriber.poll();
        let poll = reading.poll(|_, _| {}, MessageLimit::new(4096));
        if let Ok(poll) = poll
            && let Some(stop) = poll.stopped
            && stop.summary.closed_by_overrun.is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// The cells of the client counters region that hold an allocation.
fn allocated(driver: &EmbeddedDriver) -> Vec<karyos_sys::counters::CounterMetadata> {
    let reader = driver.client_counters();
    (0..reader.capacity())
        .filter_map(|cell| match reader.read(cell) {
            karyos_sys::counters::CellRead::Allocated { metadata, .. } => Some(metadata),
            _ => None,
        })
        .collect()
}

/// R-CORE-3: an application registers a named counter without a stream,
/// keyed to its client, of its kind's type id; the label is written as
/// given, and one too long is refused before anything is requested.
#[test]
fn an_application_registers_counters_without_a_stream() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    let longest = "l".repeat(64);
    let (orders, depth, full, refused) = serve(&mut driver, || {
        let orders = client.add_counter("orders processed", CounterKind::Event);
        let depth = client.add_counter("queue depth", CounterKind::Gauge);
        let full = client.add_counter(&longest, CounterKind::Event);
        let refused = client.add_counter(&"l".repeat(65), CounterKind::Event);
        (
            orders.unwrap(),
            depth.unwrap(),
            full.unwrap(),
            refused.err(),
        )
    });
    assert_eq!(
        refused,
        Some(ClientError::Conductor(ConductorError::LabelTooLong))
    );
    assert_eq!(orders.increment(5), Ok(5));
    assert_eq!(orders.increment(2), Ok(7));
    depth.set(11);
    let reader = driver.client_counters();
    for (handle, type_id, label, value) in [
        (&orders, TYPE_APPLICATION_EVENT, "orders processed", 7),
        (&depth, TYPE_APPLICATION_GAUGE, "queue depth", 11),
        (&full, TYPE_APPLICATION_EVENT, longest.as_str(), 0),
    ] {
        let karyos_sys::counters::CellRead::Allocated {
            metadata,
            value: read,
            ..
        } = reader.read(handle.cell())
        else {
            panic!("{label}: not allocated");
        };
        assert_eq!(metadata.type_id, type_id, "{label}");
        assert_eq!(metadata.label(), label.as_bytes());
        assert_eq!(metadata.keys.stream, 0, "{label}");
        assert_eq!(
            metadata.keys.kind,
            karyos_sys::counters::KIND_CLIENT,
            "{label}"
        );
        assert_eq!(read, value, "{label}");
    }
}

/// R-CORE-3: the bound is the driver's `max_counters_per_client`, 64 by
/// default and shared with the client's other counters; the 65th is
/// refused with a typed error. A client that goes frees every cell it
/// held, so the region does not leak across its lifetime.
#[test]
fn the_65th_counter_is_refused_and_a_client_that_goes_frees_its_cells() {
    let mut driver = EmbeddedDriver::new().unwrap();
    assert!(allocated(&driver).is_empty());
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    let (handles, refused) = serve(&mut driver, || {
        let handles: Vec<_> = (0..64)
            .map(|index| {
                client
                    .add_counter(&format!("application {index}"), CounterKind::Event)
                    .unwrap()
            })
            .collect();
        let refused = client.add_counter("one too many", CounterKind::Gauge);
        (handles, refused.err())
    });
    assert!(
        matches!(
            refused,
            Some(ClientError::Refused {
                code: ErrorCode::ResourcesUnavailable,
                ..
            })
        ),
        "{refused:?}"
    );
    assert_eq!(allocated(&driver).len(), 64);
    drop(handles);
    drop(client);
    let start = Instant::now();
    while !allocated(&driver).is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{} cells still held",
            allocated(&driver).len()
        );
        let _ = driver.do_work().unwrap();
    }
}

/// R-CORE-3 review: a client holds at most one live application counter
/// per label and kind, so its export never repeats a series (Prometheus
/// refuses a scrape that does). Another kind of the same label is a
/// different series; once the first is released, the label is free again.
#[test]
fn a_second_live_counter_of_the_same_label_and_kind_is_refused() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    serve(&mut driver, || {
        let first = client.add_counter("orders", CounterKind::Event).unwrap();
        assert_eq!(
            client.add_counter("orders", CounterKind::Event).err(),
            Some(ClientError::DuplicateCounter)
        );
        let gauge = client.add_counter("orders", CounterKind::Gauge).unwrap();
        first.release();
        let again = client.add_counter("orders", CounterKind::Event).unwrap();
        drop((gauge, again));
    });
}
