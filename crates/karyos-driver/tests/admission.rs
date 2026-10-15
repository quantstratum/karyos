// SPDX-License-Identifier: Apache-2.0

//! The admission server and the remote client in one process, over real
//! sockets, descriptors and regions (Linux;
//! `quantstratum-docs: karyos/design/ipc-admission-server.md`). The exit-proof test runs this
//! test binary again as a child process that attaches and exits without
//! `Leave`.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use karyos_client::ipc::{AttachError, RemoteClient, attach};
use karyos_client::{
    ClientPublication, ClientSubscription, Completion, MessageLimit, OfferOutcome, Outcome,
};
use karyos_driver::{
    DriverConfig, EmbeddedDriver, IpcConfig, LossPolicy, MonotonicClock, Reconfiguration,
    StreamConfig, SystemClock,
};
use karyos_protocol::admission::{MAX_MESSAGE_LENGTH, Message, VERSION, refusal};
use karyos_protocol::cnc::{ErrorCode, StreamKey, SubscriberRole};
use karyos_sys::frame::Lane;
use karyos_sys::ipc::{self, PidFd, Recv, Sent};
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

const CHILD: &str = "KARYOS_ADMISSION_CHILD";

#[derive(Debug, Clone, Default)]
struct ManualClock {
    now: Arc<AtomicU64>,
}

impl MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

/// The driver of these tests: IPC mode, every stream in a shared region.
type IpcDriver = EmbeddedDriver<SharedTerms>;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-adm-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The admission settings with both timeouts set to `timeout`.
fn ipc_config(dir: &Path, timeout: u64) -> IpcConfig {
    IpcConfig {
        dir: dir.to_path_buf(),
        max_pending_hellos: 2,
        hello_timeout: timeout,
        max_outbound_per_client: 8,
        fetch_deadline: timeout,
        max_exports_per_client: 16,
        max_fetches_per_client: 4,
        max_regions_per_fetch: 4,
        max_fetch_bytes: 1 << 30,
    }
}

fn driver(dir: &Path, clock: Box<dyn MonotonicClock>) -> IpcDriver {
    EmbeddedDriver::with_ipc(DriverConfig::default(), ipc_config(dir, 100), clock).unwrap()
}

/// A driver on the system clock (nanoseconds) with timeouts of 5 s.
fn system_driver(dir: &Path) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        ipc_config(dir, 5_000_000_000),
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

/// Attaches on another thread while this one runs duty cycles.
fn attach_serving(driver: &mut IpcDriver, dir: &Path) -> Result<RemoteClient, AttachError> {
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| attach(dir, Duration::from_secs(5), 16));
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
        handle.join().unwrap()
    })
}

/// Duty cycles until `done` or a bound passes. The bound is generous: the
/// suite runs tests and child processes in parallel on few CPUs, and it
/// only limits a failing test.
fn serve_until(driver: &mut IpcDriver, mut done: impl FnMut(&IpcDriver) -> bool) {
    let start = Instant::now();
    while !done(driver) {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "timed out with {} clients",
            driver.clients()
        );
        let _ = driver.do_work().unwrap();
        std::thread::yield_now();
    }
}

fn encode(message: &Message) -> Vec<u8> {
    let mut out = [0u8; MAX_MESSAGE_LENGTH];
    let length = message.encode(&mut out).unwrap();
    out[..length].to_vec()
}

/// Sends a raw first datagram and returns the driver's answer, if any,
/// before the connection closes.
fn raw_hello(
    driver: &mut IpcDriver,
    dir: &Path,
    bytes: &[u8],
    fd: Option<&OwnedFd>,
) -> Option<Message> {
    let socket = ipc::connect(dir, Duration::from_millis(20)).unwrap();
    assert_eq!(
        ipc::send(socket.as_fd(), bytes, fd.map(AsFd::as_fd)).unwrap(),
        Sent::Sent
    );
    let start = Instant::now();
    loop {
        let _ = driver.do_work().unwrap();
        let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
        match ipc::recv(socket.as_fd(), &mut buffer) {
            Ok(Recv::Message(received)) => {
                return Some(Message::decode(&buffer[..received.len]).unwrap());
            }
            Ok(Recv::PeerClosed) => return None,
            Ok(Recv::WouldBlock) | Err(_) => {
                assert!(start.elapsed() < Duration::from_secs(5), "timed out");
            }
        }
    }
}

#[test]
fn a_remote_client_is_admitted_served_and_leaves() {
    let dir = dir("serve");
    let mut driver = system_driver(&dir);
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    assert_eq!(Some(client.instance()), driver.instance());
    assert_eq!(driver.clients(), 1);
    // A command round trip through the shared ring and broadcast buffer.
    let sequence = client
        .add_subscription(
            StreamKey {
                stream_id: 99,
                session_id: 1,
            },
            SubscriberRole::Optional,
        )
        .unwrap();
    let mut done: Vec<Completion> = Vec::new();
    let start = Instant::now();
    while done.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "timed out");
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    assert_eq!(done[0].sequence, sequence);
    assert!(matches!(
        done[0].outcome,
        Outcome::Refused {
            code: ErrorCode::UnknownStream,
            detail: 99
        }
    ));
    // The counters are readable through the attached region.
    assert!(client.counter_capacity() > 0);
    // Leave releases the slot.
    drop(client);
    serve_until(&mut driver, |driver| driver.clients() == 0);
}

#[test]
fn hellos_that_break_the_profile_are_refused() {
    let dir = dir("hello");
    let mut driver = system_driver(&dir);
    let hello = encode(&Message::Hello { version: VERSION });
    let refused = |code| Some(Message::Refused { fetch: 0, code });
    // No descriptor.
    assert_eq!(
        raw_hello(&mut driver, &dir, &hello, None),
        refused(refusal::PROFILE)
    );
    // A descriptor that is not a pidfd.
    let socket = ipc::seqpacket_pair().unwrap().0;
    assert_eq!(
        raw_hello(&mut driver, &dir, &hello, Some(&socket)),
        refused(refusal::PROFILE)
    );
    // A pidfd of another live process: its pid is not the peer's.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let other = other_pidfd(child.id());
    assert_eq!(
        raw_hello(&mut driver, &dir, &hello, Some(&other)),
        refused(refusal::PROFILE)
    );
    child.kill().unwrap();
    child.wait().unwrap();
    // Another protocol version, even one with a longer Hello.
    let own = own_pidfd();
    let mut future = encode(&Message::Hello { version: 2 });
    future.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        raw_hello(&mut driver, &dir, &future, Some(&own)),
        refused(refusal::INCOMPATIBLE_VERSION)
    );
    // Not a Hello: closed without an answer.
    assert_eq!(
        raw_hello(&mut driver, &dir, &encode(&Message::Leave), None),
        None
    );
    assert_eq!(driver.clients(), 0);
}

#[test]
fn a_silent_connection_is_closed_at_the_hello_timeout() {
    let dir = dir("timeout");
    let clock = ManualClock::default();
    let mut driver = driver(&dir, Box::new(clock.clone()));
    let socket = ipc::connect(&dir, Duration::from_millis(20)).unwrap();
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    let mut buffer = [0u8; 8];
    assert!(matches!(
        ipc::recv(socket.as_fd(), &mut buffer),
        Ok(Recv::WouldBlock)
    ));
    clock.now.store(100, Ordering::Relaxed);
    let _ = driver.do_work().unwrap();
    assert!(matches!(
        ipc::recv(socket.as_fd(), &mut buffer),
        Ok(Recv::PeerClosed)
    ));
}

#[test]
fn a_closed_socket_keeps_the_slot_until_the_exit_proof() {
    let dir = dir("closed");
    let mut driver = system_driver(&dir);
    // This process stays alive: a socket closed without Leave keeps the
    // client charged.
    let socket = ipc::connect(&dir, Duration::from_millis(20)).unwrap();
    let own = own_pidfd();
    let hello = encode(&Message::Hello { version: VERSION });
    assert_eq!(
        ipc::send(socket.as_fd(), &hello, Some(own.as_fd())).unwrap(),
        Sent::Sent
    );
    serve_until(&mut driver, |driver| driver.clients() == 1);
    drop(socket);
    for _ in 0..20 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(driver.clients(), 1);

    // A child process that attaches and exits without Leave is released
    // by its exit proof.
    let admitted = counter(&driver, "clients admitted");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_attaches_and_exits", "--nocapture"])
        .env(CHILD, &dir)
        .spawn()
        .unwrap();
    // The child can attach and exit within one duty cycle, so the second
    // client is observed through the admission counter, not the count.
    serve_until(&mut driver, |driver| {
        counter(driver, "clients admitted") == admitted + 1
    });
    serve_until(&mut driver, |driver| driver.clients() == 1);
    assert!(child.wait().unwrap().success());
}

/// Runs only as the child of `a_closed_socket_keeps_the_slot_until_the_exit_proof`.
#[test]
fn child_attaches_and_exits() {
    let Some(dir) = std::env::var_os(CHILD) else {
        return;
    };
    let client = attach(Path::new(&dir), Duration::from_secs(5), 16).unwrap();
    // Exit without dropping the client: no Leave is sent.
    std::mem::forget(client);
    std::process::exit(0);
}

#[test]
fn a_client_that_stops_reading_is_retired() {
    let dir = dir("flood");
    let mut driver = system_driver(&dir);
    let socket = ipc::connect(&dir, Duration::from_millis(20)).unwrap();
    let own = own_pidfd();
    let hello = encode(&Message::Hello { version: VERSION });
    assert_eq!(
        ipc::send(socket.as_fd(), &hello, Some(own.as_fd())).unwrap(),
        Sent::Sent
    );
    serve_until(&mut driver, |driver| driver.clients() == 1);
    // Fetches are refused; never read the refusals. The driver's queue
    // fills once the socket buffer is full, and the client is retired: its
    // socket is closed (the slot stays charged, this process lives on).
    let mut fetch = 1u64;
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(10), "never retired");
        let message = encode(&Message::Fetch { fetch, key: 1 });
        match ipc::send(socket.as_fd(), &message, None) {
            Ok(Sent::Sent) => fetch += 1,
            Ok(Sent::WouldBlock) => {}
            Err(_) => break,
        }
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(driver.clients(), 1);
}

fn own_pidfd() -> OwnedFd {
    PidFd::of_self()
        .unwrap()
        .as_fd()
        .try_clone_to_owned()
        .unwrap()
}

fn other_pidfd(pid: u32) -> OwnedFd {
    let pidfd = PidFd::open(i32::try_from(pid).unwrap()).unwrap();
    pidfd.as_fd().try_clone_to_owned().unwrap()
}

/// In IPC mode every stream lives in a shared region, and the driver's
/// in-process handles use the same shared terms (`quantstratum-docs:
/// karyos/design/ipc-data-path.md`, Terms in the types).
#[test]
fn an_ipc_driver_keeps_its_streams_in_shared_regions() {
    let dir = dir("streams");
    let mut driver = system_driver(&dir);
    let stream = driver.add_stream(shared_stream_config()).unwrap();
    let mut subscription: ClientSubscription<SharedTerms> =
        driver.subscribe(stream, Role::Required).unwrap();
    let mut publication: ClientPublication<SharedTerms> = driver.publication(stream).unwrap();
    let mut sent = 0;
    while sent < 3 {
        let _ = driver.do_work().unwrap();
        if matches!(
            publication.offer(&[sent; 40]).unwrap(),
            OfferOutcome::Accepted { .. }
        ) {
            sent += 1;
        }
    }
    let mut received = Vec::new();
    let _ = subscription
        .poll(
            |payload, _| received.push(payload.to_vec()),
            MessageLimit::new(8),
        )
        .unwrap();
    assert_eq!(received, vec![vec![0u8; 40], vec![1u8; 40], vec![2u8; 40]]);
}

fn shared_stream_config() -> StreamConfig {
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
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
        },
        allow_unconnected: false,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// A reconfiguration of an IPC stream creates its successor in a new shared
/// region, and in-process handles move to it across the cutover.
#[test]
fn an_ipc_stream_moves_to_a_successor_in_a_new_shared_region() {
    let dir = dir("cutover");
    let mut driver = system_driver(&dir);
    let stream = driver.add_stream(shared_stream_config()).unwrap();
    let mut subscription: ClientSubscription<SharedTerms> =
        driver.subscribe(stream, Role::Required).unwrap();
    let mut publication: ClientPublication<SharedTerms> = driver.publication(stream).unwrap();
    assert!(matches!(
        publication.offer(b"one").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let _ = driver
        .reconfigure_stream(
            stream,
            Reconfiguration {
                term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                spare_slots: 5,
            },
        )
        .unwrap();
    // The writer moves to the successor and publishes there.
    let mut moved = false;
    for _ in 0..16 {
        let _ = driver.do_work().unwrap();
        if matches!(
            publication.offer(b"two").unwrap(),
            OfferOutcome::Accepted { .. }
        ) {
            moved = true;
            break;
        }
    }
    assert!(moved, "the writer never reached the successor");
    let generations = driver.generations(stream).unwrap();
    assert_eq!(generations.last().unwrap().generation.get(), 1);
    let mut received = Vec::new();
    for _ in 0..4 {
        let _ = subscription
            .poll(
                |payload, _| received.push(payload.to_vec()),
                MessageLimit::new(8),
            )
            .unwrap();
    }
    assert_eq!(received, vec![b"one".to_vec(), b"two".to_vec()]);
}

fn counter(driver: &IpcDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            karyos_sys::counters::CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

/// The next message on `socket`, serving the driver while none is there.
fn next_message(driver: &mut IpcDriver, socket: BorrowedFd<'_>) -> (Message, Option<OwnedFd>) {
    let start = Instant::now();
    loop {
        let _ = driver.do_work().unwrap();
        let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
        match ipc::recv(socket, &mut buffer).unwrap() {
            Recv::Message(received) => {
                return (
                    Message::decode(&buffer[..received.len]).unwrap(),
                    received.fd,
                );
            }
            Recv::WouldBlock => assert!(start.elapsed() < Duration::from_secs(5), "no message"),
            Recv::PeerClosed => panic!("the driver closed the socket"),
        }
    }
}

/// A remote client's `Fetch` exports its subscription grant: one
/// `Manifest` and one `Region` with the log buffer's descriptor, which the
/// client attaches and adopts under the record's export id, and then reads
/// what an in-process publisher writes (`quantstratum-docs:
/// karyos/design/ipc-data-path.md`, Grants and the export ledger).
#[test]
fn a_fetched_subscription_reads_what_an_in_process_publisher_writes() {
    let dir = dir("fetch");
    let mut driver = system_driver(&dir);
    let stream = driver.add_stream(shared_stream_config()).unwrap();
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let _ = client
        .add_subscription(
            StreamKey {
                stream_id: 2,
                session_id: 1,
            },
            SubscriberRole::Required,
        )
        .unwrap();
    let mut done: Vec<Completion> = Vec::new();
    let start = Instant::now();
    while done.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "no completion");
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    // A remote client gets no in-process capability; the first
    // registration of a fresh driver has key 1.
    let socket = client.admission_socket().unwrap();
    let fetch = encode(&Message::Fetch { fetch: 1, key: 1 });
    assert_eq!(ipc::send(socket, &fetch, None).unwrap(), Sent::Sent);
    let (manifest, none) = next_message(&mut driver, socket);
    assert!(none.is_none());
    let Message::Manifest {
        fetch: 1,
        key: 1,
        registration: 1,
        records,
    } = manifest
    else {
        panic!("expected the manifest of fetch 1, got {manifest:?}");
    };
    let [record] = records[..] else {
        panic!("one record");
    };
    assert_eq!(
        record.kind,
        karyos_protocol::admission::RegionKind::LogBuffer
    );
    assert_eq!((record.stream_id, record.session_id), (2, 1));
    let karyos_protocol::admission::Capability::RequiredSubscriber { cell } = record.capability
    else {
        panic!("a required subscriber record");
    };
    let (region, fd) = next_message(&mut driver, socket);
    assert_eq!(region, Message::Region { fetch: 1, index: 0 });
    assert_eq!(counter(&driver, "grants exported"), 1);
    let region = karyos_sys::ipc::Region::attach(
        fd.unwrap(),
        karyos_sys::ipc::RegionRecord {
            instance: driver.instance().unwrap(),
            region: record.region,
            kind: karyos_sys::ipc::RegionKind::LogBuffer,
            generation: record.generation,
            layout: u64::from(record.layout),
            structure_length: usize::try_from(record.structure_length).unwrap(),
        },
    )
    .unwrap();
    let buffer = karyos_sys::log_buffer::LogBuffer::attach(region).unwrap();
    let mut adopted = karyos_sys::log_buffer::Subscription::adopt(
        &buffer,
        usize::try_from(cell).unwrap(),
        Role::Required,
        record.export,
    )
    .unwrap();
    let mut publication: ClientPublication<SharedTerms> = driver.publication(stream).unwrap();
    let start = Instant::now();
    while !matches!(
        publication.offer(b"across").unwrap(),
        OfferOutcome::Accepted { .. }
    ) {
        assert!(start.elapsed() < Duration::from_secs(5), "never accepted");
        let _ = driver.do_work().unwrap();
    }
    let mut out = [0u8; 64];
    let karyos_sys::log_buffer::PollOutcome::Message { length, .. } =
        adopted.poll(&mut out).unwrap()
    else {
        panic!("no message");
    };
    assert_eq!(&out[..length as usize], b"across");
    adopted.acknowledge();
    // The key is spent: a second fetch of it is refused, and so is a
    // fetch id that does not grow.
    let again = encode(&Message::Fetch { fetch: 2, key: 1 });
    assert_eq!(ipc::send(socket, &again, None).unwrap(), Sent::Sent);
    assert_eq!(
        next_message(&mut driver, socket).0,
        Message::Refused {
            fetch: 2,
            code: refusal::UNKNOWN_KEY
        }
    );
    let reused = encode(&Message::Fetch { fetch: 2, key: 1 });
    assert_eq!(ipc::send(socket, &reused, None).unwrap(), Sent::Sent);
    assert_eq!(
        next_message(&mut driver, socket).0,
        Message::Refused {
            fetch: 2,
            code: refusal::LIMIT
        }
    );
    let unknown = encode(&Message::Fetch { fetch: 3, key: 77 });
    assert_eq!(ipc::send(socket, &unknown, None).unwrap(), Sent::Sent);
    assert_eq!(
        next_message(&mut driver, socket).0,
        Message::Refused {
            fetch: 3,
            code: refusal::UNKNOWN_KEY
        }
    );
}

/// A grant no fetch could carry (its region exceeds `max_fetch_bytes`) is
/// refused at its command instead of being handed a key.
#[test]
fn an_unfetchable_grant_is_refused_at_its_command() {
    let dir = dir("unfetchable");
    let mut driver = EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        IpcConfig {
            max_fetch_bytes: 128,
            ..ipc_config(&dir, 5_000_000_000)
        },
        Box::new(SystemClock::new()),
    )
    .unwrap();
    let _stream = driver.add_stream(shared_stream_config()).unwrap();
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let _ = client
        .add_subscription(
            StreamKey {
                stream_id: 2,
                session_id: 1,
            },
            SubscriberRole::Required,
        )
        .unwrap();
    let mut done: Vec<Completion> = Vec::new();
    let start = Instant::now();
    while done.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "no completion");
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    assert!(matches!(
        done[0].outcome,
        Outcome::Refused {
            code: ErrorCode::ResourcesUnavailable,
            ..
        }
    ));
    assert_eq!(counter(&driver, "grants reserved"), 0);
}

/// Admits a remote client, takes a required subscription on stream 2 and
/// fetches it with fetch id 1; returns the client, the export and the
/// region's descriptor (the client's mapping stand-in).
fn fetched_subscription(driver: &mut IpcDriver, dir: &Path) -> (RemoteClient, u64, OwnedFd) {
    let mut client = attach_serving(driver, dir).unwrap();
    let _ = client
        .add_subscription(
            StreamKey {
                stream_id: 2,
                session_id: 1,
            },
            SubscriberRole::Required,
        )
        .unwrap();
    let mut done: Vec<Completion> = Vec::new();
    let start = Instant::now();
    while done.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "no completion");
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    let socket = client.admission_socket().unwrap();
    let fetch = encode(&Message::Fetch { fetch: 1, key: 1 });
    assert_eq!(ipc::send(socket, &fetch, None).unwrap(), Sent::Sent);
    let (Message::Manifest { records, .. }, _) = next_message(driver, socket) else {
        panic!("no manifest");
    };
    let (_, fd) = next_message(driver, socket);
    (client, records[0].export, fd.unwrap())
}

/// The fetch id high-water mark moves before the key and bounds are
/// checked, so a refused id stays consumed; a refusal changes no grant, and
/// the next id fetches the same grant (`quantstratum-docs:
/// karyos/design/ipc-data-path.md`, Grants and the export ledger).
#[test]
fn a_refused_fetch_id_stays_consumed_and_the_grant_stays_held() {
    let dir = dir("refused-id");
    let mut driver = system_driver(&dir);
    let _stream = driver.add_stream(shared_stream_config()).unwrap();
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let _ = client
        .add_subscription(
            StreamKey {
                stream_id: 2,
                session_id: 1,
            },
            SubscriberRole::Required,
        )
        .unwrap();
    let mut done: Vec<Completion> = Vec::new();
    let start = Instant::now();
    while done.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "no completion");
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    let socket = client.admission_socket().unwrap();
    let mut exchange = |fetch: u64, key: u64| {
        let message = encode(&Message::Fetch { fetch, key });
        assert_eq!(ipc::send(socket, &message, None).unwrap(), Sent::Sent);
        next_message(&mut driver, socket)
    };
    assert_eq!(
        exchange(8, 77).0,
        Message::Refused {
            fetch: 8,
            code: refusal::UNKNOWN_KEY
        }
    );
    // The same id with the right key: consumed, refused.
    assert_eq!(
        exchange(8, 1).0,
        Message::Refused {
            fetch: 8,
            code: refusal::LIMIT
        }
    );
    // The grant is still Held: the next id fetches it.
    assert!(matches!(
        exchange(9, 1).0,
        Message::Manifest {
            fetch: 9,
            key: 1,
            ..
        }
    ));
    let (region, fd) = next_message(&mut driver, socket);
    assert_eq!(region, Message::Region { fetch: 9, index: 0 });
    assert!(fd.is_some());
    assert_eq!(counter(&driver, "grants exported"), 1);
    // A refusal of the consumed key leaves it exported.
    let again = encode(&Message::Fetch { fetch: 10, key: 1 });
    assert_eq!(ipc::send(socket, &again, None).unwrap(), Sent::Sent);
    assert_eq!(
        next_message(&mut driver, socket).0,
        Message::Refused {
            fetch: 10,
            code: refusal::UNKNOWN_KEY
        }
    );
    assert_eq!(counter(&driver, "grants exported"), 1);
}

/// `max_fetch_bytes` counts whole regions, header included: a grant whose
/// region is exactly the bound is fetched, one header byte over is refused
/// at its command.
#[test]
fn the_fetch_byte_bound_counts_the_region_header() {
    // The region size of this stream's log buffer.
    let probe_dir = dir("bytes-probe");
    let mut probe = system_driver(&probe_dir);
    let _stream = probe.add_stream(shared_stream_config()).unwrap();
    let (_client, _export, fd) = fetched_subscription(&mut probe, &probe_dir);
    let size = std::fs::File::from(fd).metadata().unwrap().len();
    for (bound, accepted) in [(size, true), (size - 1, false)] {
        let dir = dir(if accepted {
            "bytes-exact"
        } else {
            "bytes-over"
        });
        let mut driver = EmbeddedDriver::with_ipc(
            DriverConfig::default(),
            IpcConfig {
                max_fetch_bytes: bound,
                ..ipc_config(&dir, 5_000_000_000)
            },
            Box::new(SystemClock::new()),
        )
        .unwrap();
        let _stream = driver.add_stream(shared_stream_config()).unwrap();
        let mut client = attach_serving(&mut driver, &dir).unwrap();
        let _ = client
            .add_subscription(
                StreamKey {
                    stream_id: 2,
                    session_id: 1,
                },
                SubscriberRole::Required,
            )
            .unwrap();
        let mut done: Vec<Completion> = Vec::new();
        let start = Instant::now();
        while done.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(5), "no completion");
            let _ = driver.do_work().unwrap();
            let _ = client.poll(usize::MAX, |completion| done.push(completion));
        }
        let refused = matches!(
            done[0].outcome,
            Outcome::Refused {
                code: ErrorCode::ResourcesUnavailable,
                ..
            }
        );
        assert_eq!(refused, !accepted, "bound {bound} for a region of {size}");
    }
}

/// Serves until the driver closes `socket` (the client was retired or
/// left).
fn serve_until_closed(driver: &mut IpcDriver, socket: BorrowedFd<'_>) {
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(5), "never closed");
        let _ = driver.do_work().unwrap();
        let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
        match ipc::recv(socket, &mut buffer) {
            Ok(Recv::PeerClosed) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// `Detach` of an exported grant ends its registration; `Leave` is then
/// accepted and releases the client.
#[test]
fn a_detach_ends_an_exported_grant_and_then_leave_is_accepted() {
    let dir = dir("detach");
    let mut driver = system_driver(&dir);
    let _stream = driver.add_stream(shared_stream_config()).unwrap();
    let (client, export, fd) = fetched_subscription(&mut driver, &dir);
    // The client unmapped the region: then it detaches.
    drop(fd);
    let socket = client.admission_socket().unwrap();
    let detach = encode(&Message::Detach { export });
    assert_eq!(ipc::send(socket, &detach, None).unwrap(), Sent::Sent);
    serve_until(&mut driver, |driver| {
        counter(driver, "grants detached") == 1
    });
    assert_eq!(counter(&driver, "grants ended"), 1);
    let leave = encode(&Message::Leave);
    assert_eq!(ipc::send(socket, &leave, None).unwrap(), Sent::Sent);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    drop(client);
}

/// `Leave` with an export left, and `Detach` of an export the client does
/// not own, are protocol errors: the client is retired and its exported
/// grant stays charged until the exit proof.
#[test]
fn leave_with_an_export_left_and_a_foreign_detach_retire_the_client() {
    for message in [Message::Leave, Message::Detach { export: 1 << 40 }] {
        let dir = dir("early-leave");
        let mut driver = system_driver(&dir);
        let _stream = driver.add_stream(shared_stream_config()).unwrap();
        let (client, _export, _fd) = fetched_subscription(&mut driver, &dir);
        let socket = client.admission_socket().unwrap();
        assert_eq!(
            ipc::send(socket, &encode(&message), None).unwrap(),
            Sent::Sent
        );
        serve_until_closed(&mut driver, socket);
        // This process lives on: the slot and the grant stay charged.
        for _ in 0..4 {
            let _ = driver.do_work().unwrap();
        }
        assert_eq!(driver.clients(), 1);
        assert_eq!(counter(&driver, "grants ended"), 0);
        drop(client);
    }
}

/// Serves the driver while `client` runs on another thread; returns its
/// result once it finished.
fn serve_while<R: Send>(driver: &mut IpcDriver, client: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(client);
        let start = Instant::now();
        while !handle.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "client stuck");
            let _ = driver.do_work().unwrap();
            // Leave CPU to the client thread and to other tests.
            std::thread::sleep(Duration::from_micros(200));
        }
        handle.join().unwrap()
    })
}

/// A remote client takes a subscription and a publication through fetches
/// (`quantstratum-docs: karyos/design/ipc-data-path.md`, The client): each
/// handle owns its own mapping, they exchange a message through the shared
/// stream, dropping them detaches both grants, and dropping the client then
/// sends a Leave the driver accepts.
#[test]
fn a_remote_client_takes_handles_that_exchange_and_detach_on_drop() {
    let dir = dir("take");
    let mut driver = system_driver(&dir);
    let _stream = driver.add_stream(shared_stream_config()).unwrap();
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let key = StreamKey {
        stream_id: 2,
        session_id: 1,
    };
    let received = serve_while(&mut driver, move || {
        let _ = client
            .add_subscription(key, SubscriberRole::Required)
            .unwrap();
        let _ = client.add_publication(key, false).unwrap();
        let mut fetchable = Vec::new();
        let start = Instant::now();
        while fetchable.len() < 2 {
            assert!(start.elapsed() < Duration::from_secs(5), "no completions");
            let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                Outcome::Fetchable(grant) => fetchable.push(grant),
                other => panic!("expected a fetchable grant, got {other:?}"),
            });
        }
        // A grant of another kind than requested is refused before any
        // fetch.
        assert_eq!(
            client.take_publication(&fetchable[0]).err(),
            Some(AttachError::Protocol)
        );
        let mut subscription = client.take_subscription(&fetchable[0]).unwrap();
        let mut publication = client.take_publication(&fetchable[1]).unwrap();
        let start = Instant::now();
        while !matches!(
            publication.offer(b"remote").unwrap(),
            OfferOutcome::Accepted { .. }
        ) {
            assert!(start.elapsed() < Duration::from_secs(5), "never accepted");
        }
        let mut received = Vec::new();
        let start = Instant::now();
        while received.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(5), "never received");
            let _ = subscription
                .poll(
                    |payload, _| received.push(payload.to_vec()),
                    MessageLimit::new(8),
                )
                .unwrap();
        }
        drop(subscription);
        drop(publication);
        drop(client);
        received
    });
    assert_eq!(received, vec![b"remote".to_vec()]);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(counter(&driver, "grants exported"), 2);
    assert_eq!(counter(&driver, "grants detached"), 2);
}

/// A manifest that does not answer the request (here, another
/// registration than the `Ready` response's) aborts the fetch: its region
/// is still received, closed and detached, so nothing stays charged and the
/// client can still leave.
#[test]
fn an_aborted_fetch_detaches_what_arrived() {
    let dir = dir("abort");
    let mut driver = system_driver(&dir);
    let _stream = driver.add_stream(shared_stream_config()).unwrap();
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    serve_while(&mut driver, move || {
        let _ = client
            .add_subscription(
                StreamKey {
                    stream_id: 2,
                    session_id: 1,
                },
                SubscriberRole::Optional,
            )
            .unwrap();
        let mut fetchable = None;
        let start = Instant::now();
        while fetchable.is_none() {
            assert!(start.elapsed() < Duration::from_secs(5), "no completion");
            let _ = client.poll(usize::MAX, |completion| {
                if let Outcome::Fetchable(grant) = completion.outcome {
                    fetchable = Some(grant);
                }
            });
        }
        let mut forged = fetchable.unwrap();
        forged.registration += 1;
        assert_eq!(
            client.take_subscription(&forged).err(),
            Some(AttachError::Protocol)
        );
        drop(client);
    });
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(counter(&driver, "grants detached"), 1);
}

/// Two threads take grants of one client at once: the session serializes
/// the fetch exchanges, so both handles are delivered, both grants are
/// detached when they drop, and the client still leaves.
#[test]
fn concurrent_takes_share_one_session() {
    let dir = dir("concurrent-take");
    let mut driver = system_driver(&dir);
    let _stream = driver.add_stream(shared_stream_config()).unwrap();
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let key = StreamKey {
        stream_id: 2,
        session_id: 1,
    };
    serve_while(&mut driver, move || {
        for _ in 0..2 {
            let _ = client
                .add_subscription(key, SubscriberRole::Required)
                .unwrap();
        }
        let mut fetchable = Vec::new();
        let start = Instant::now();
        while fetchable.len() < 2 {
            assert!(start.elapsed() < Duration::from_secs(5), "no completions");
            let _ = client.poll(usize::MAX, |completion| {
                if let Outcome::Fetchable(grant) = completion.outcome {
                    fetchable.push(grant);
                }
            });
        }
        let client = &client;
        std::thread::scope(|scope| {
            let takes: Vec<_> = fetchable
                .iter()
                .map(|grant| scope.spawn(move || client.take_subscription(grant)))
                .collect();
            for take in takes {
                assert!(take.join().unwrap().is_ok());
            }
        });
    });
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(counter(&driver, "grants exported"), 2);
    assert_eq!(counter(&driver, "grants detached"), 2);
}

/// A driver on the system clock with a short cutover deadline.
fn cutover_driver(dir: &Path, deadline_ns: u64) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig {
            cutover_deadline: deadline_ns,
            ..DriverConfig::default()
        },
        ipc_config(dir, 5_000_000_000),
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

/// A remote client takes a required subscription; returns it with the
/// subscription handle.
fn remote_subscriber(
    driver: &mut IpcDriver,
    dir: &Path,
) -> (RemoteClient, ClientSubscription<SharedTerms>) {
    let mut client = attach_serving(driver, dir).unwrap();
    serve_while(driver, move || {
        let _ = client
            .add_subscription(
                StreamKey {
                    stream_id: 2,
                    session_id: 1,
                },
                SubscriberRole::Required,
            )
            .unwrap();
        let mut fetchable = None;
        let start = Instant::now();
        while fetchable.is_none() {
            assert!(start.elapsed() < Duration::from_secs(5), "no grant");
            let _ = client.poll(usize::MAX, |completion| {
                if let Outcome::Fetchable(grant) = completion.outcome {
                    fetchable = Some(grant);
                }
            });
        }
        let subscription = client.take_subscription(&fetchable.unwrap()).unwrap();
        (client, subscription)
    })
}

/// Polls `client` until it receives `SuccessorReady` or `Fenced` for any
/// registration.
fn cutover_event(client: &mut RemoteClient) -> karyos_protocol::cnc::Event {
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(5), "no cutover event");
        let _ = client.poll(usize::MAX, |_| {});
        if let Some(event) = client.take_events().into_iter().find(|event| {
            matches!(
                event,
                karyos_protocol::cnc::Event::SuccessorReady { .. }
                    | karyos_protocol::cnc::Event::Fenced { .. }
            )
        }) {
            return event;
        }
        std::thread::yield_now();
    }
}

/// A remote subscriber that does not take its successor is fenced at the
/// cutover deadline and told so; the never-sent successor grant ends.
#[test]
fn a_remote_subscriber_that_does_not_move_is_fenced() {
    let dir = dir("fence");
    let mut driver = cutover_driver(&dir, 50_000_000);
    let stream = driver.add_stream(shared_stream_config()).unwrap();
    let (mut client, subscription) = remote_subscriber(&mut driver, &dir);
    let _ = driver
        .reconfigure_stream(
            stream,
            karyos_driver::Reconfiguration {
                term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                spare_slots: 5,
            },
        )
        .unwrap();
    let events = serve_while(&mut driver, move || {
        let first = cutover_event(&mut client);
        let second = cutover_event(&mut client);
        std::mem::forget(subscription);
        std::mem::forget(client);
        (first, second)
    });
    assert!(matches!(
        events.0,
        karyos_protocol::cnc::Event::SuccessorReady { .. }
    ));
    assert!(matches!(
        events.1,
        karyos_protocol::cnc::Event::Fenced { .. }
    ));
    assert_eq!(counter(&driver, "grants fenced"), 1);
}

/// A successor whose region exceeds the client's `max_fetch_bytes` could
/// never be fetched: it is not reserved, and the client is told `Fenced`
/// at once, as a command would be refused.
#[test]
fn a_successor_no_fetch_could_carry_is_fenced_at_once() {
    // The region size of this stream's log buffer.
    let probe_dir = dir("successor-bytes-probe");
    let mut probe = system_driver(&probe_dir);
    let _stream = probe.add_stream(shared_stream_config()).unwrap();
    let (_client, _export, fd) = fetched_subscription(&mut probe, &probe_dir);
    let size = std::fs::File::from(fd).metadata().unwrap().len();
    let dir = dir("successor-bytes");
    let mut driver = EmbeddedDriver::with_ipc(
        DriverConfig {
            cutover_deadline: 5_000_000_000,
            ..DriverConfig::default()
        },
        IpcConfig {
            max_fetch_bytes: size,
            ..ipc_config(&dir, 5_000_000_000)
        },
        Box::new(SystemClock::new()),
    )
    .unwrap();
    let stream = driver.add_stream(shared_stream_config()).unwrap();
    let (mut client, subscription) = remote_subscriber(&mut driver, &dir);
    let _ = driver
        .reconfigure_stream(
            stream,
            karyos_driver::Reconfiguration {
                term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                spare_slots: 5,
            },
        )
        .unwrap();
    let event = serve_while(&mut driver, move || {
        let event = cutover_event(&mut client);
        std::mem::forget(subscription);
        std::mem::forget(client);
        event
    });
    // Told long before the 5 s deadline, and nothing was reserved.
    assert!(
        matches!(event, karyos_protocol::cnc::Event::Fenced { .. }),
        "{event:?}"
    );
    assert_eq!(counter(&driver, "grants reserved"), 1);
    assert_eq!(counter(&driver, "grants fenced"), 0);
}

/// Session (`quantstratum-docs: karyos/design/ipc-data-path.md`, Tests,
/// d3): a remote handle dropped after its `RemoteClient`, with the process
/// still alive, sends its `Detach` and then the session's `Leave`; the
/// driver releases the client without any exit proof and without counting
/// a fault.
#[test]
fn a_handle_dropped_after_its_client_detaches_then_leaves() {
    let dir = dir("handle-after-client");
    let mut driver = system_driver(&dir);
    let _stream = driver.add_stream(shared_stream_config()).unwrap();
    let (client, subscription) = remote_subscriber(&mut driver, &dir);
    // The client goes first: its handle keeps the session, so the driver
    // keeps the client and its grant.
    drop(client);
    for _ in 0..20 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(driver.clients(), 1);
    assert_eq!(counter(&driver, "grants detached"), 0);
    // The handle goes last: Detach, then Leave.
    drop(subscription);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(counter(&driver, "grants detached"), 1);
    assert_eq!(counter(&driver, "clients faulty"), 0);
}
