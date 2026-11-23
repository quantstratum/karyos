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
    SealState, StreamConfig, SystemClock,
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
        max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
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

/// M10: a remote client closes and reopens a guard for an operator. Each
/// completes as the guard's state, a stale reopen is refused with the
/// current word, and the driver audits the client, the operator's uid and
/// the request's digest.
#[test]
fn a_remote_client_closes_and_reopens_a_guard_for_an_operator() {
    use karyos_driver::guards::Requester;
    use karyos_sys::guard::GuardState;
    let dir = dir("guard-ops");
    let mut driver = system_driver(&dir);
    let guard = driver.add_guard("orders").unwrap();
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let id = client.client();
    let complete = |driver: &mut IpcDriver, client: &mut RemoteClient, sequence: u64| {
        let mut done: Vec<Completion> = Vec::new();
        let start = Instant::now();
        while done.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(5), "timed out");
            let _ = driver.do_work().unwrap();
            let _ = client.poll(usize::MAX, |completion| done.push(completion));
        }
        assert_eq!(done[0].sequence, sequence);
        done.remove(0).outcome
    };
    let sequence = client
        .guard_reopen(guard.id(), 1, 40, Some(1000), b"start of day")
        .unwrap();
    assert!(matches!(
        complete(&mut driver, &mut client, sequence),
        Outcome::GuardState { guard: g, state: GuardState { epoch: 2, open: true } } if g == guard.id()
    ));
    let sequence = client.guard_close(guard.id(), 41, Some(1000), b"").unwrap();
    assert!(matches!(
        complete(&mut driver, &mut client, sequence),
        Outcome::GuardState {
            state: GuardState {
                epoch: 3,
                open: false
            },
            ..
        }
    ));
    // A stale reopen: refused with the current word (epoch 3, closed).
    let sequence = client.guard_reopen(guard.id(), 1, 42, None, b"").unwrap();
    assert!(matches!(
        complete(&mut driver, &mut client, sequence),
        Outcome::Refused {
            code: ErrorCode::GuardNotClosedAt,
            detail: 6
        }
    ));
    assert_eq!(
        client.guard_reopen(guard.id(), 2, 43, None, b""),
        Err(karyos_client::ConductorError::InvalidGuardEpoch)
    );
    let audit: Vec<_> = driver
        .guard_audit()
        .records
        .iter()
        .map(|record| (record.operation, record.requester, record.parameters))
        .collect();
    let digest = karyos_protocol::cnc::guard_parameters;
    let operator = Requester::Operator {
        client: id,
        uid: 1000,
    };
    assert_eq!(
        audit,
        [
            (
                40,
                operator,
                digest(guard.id(), 1, 40, 1000, b"start of day")
            ),
            (41, operator, digest(guard.id(), 0, 41, 1000, b"")),
            (
                42,
                Requester::Client(id),
                digest(guard.id(), 1, 42, karyos_protocol::cnc::NO_OPERATOR, b"")
            ),
        ]
    );
    drop(client);
    serve_until(&mut driver, |driver| driver.clients() == 0);
}

/// karyos#740 (R-CORE-21): a remote client changes a guarded stream's rate
/// policy over the control path. A tightening on the safety path and a
/// loosening by an administrator complete as the new version; a stale
/// version is refused with the current one; a byte limit the command
/// cannot carry is refused before sending; the driver audits the client,
/// the operator and the request's digest.
#[test]
fn a_remote_client_changes_a_rate_policy_by_version() {
    use karyos_driver::guards::Requester;
    use karyos_driver::{AuditOutcome, GuardRate, RateAuthority};
    use karyos_protocol::cnc::{NO_OPERATOR, RateAuthority as Wire, rate_parameters};
    use karyos_sys::rate_limit::{Rate, RatePolicy};
    let dir = dir("rate-change");
    let mut driver = system_driver(&dir);
    let stream = driver.add_stream(shared_stream_config()).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    let policy = |per_second, burst| RatePolicy {
        messages: Rate { per_second, burst },
        bytes: None,
    };
    driver
        .guard_stream(
            stream,
            guard,
            4,
            Some(GuardRate::publication(policy(100, 10))),
        )
        .unwrap();
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let id = client.client();
    let complete = |driver: &mut IpcDriver, client: &mut RemoteClient, sequence: u64| {
        let mut done: Vec<Completion> = Vec::new();
        let start = Instant::now();
        while done.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(5), "timed out");
            let _ = driver.do_work().unwrap();
            let _ = client.poll(usize::MAX, |completion| done.push(completion));
        }
        assert_eq!(done[0].sequence, sequence);
        done.remove(0).outcome
    };
    let key = StreamKey {
        stream_id: 2,
        session_id: 1,
    };
    let sequence = client
        .rate_change(key, 1, policy(50, 10), Wire::Safety, 60, Some(1000))
        .unwrap();
    assert!(matches!(
        complete(&mut driver, &mut client, sequence),
        Outcome::RateState { stream, version: 2 } if stream == key
    ));
    let sequence = client
        .rate_change(key, 1, policy(40, 10), Wire::Safety, 61, None)
        .unwrap();
    assert!(matches!(
        complete(&mut driver, &mut client, sequence),
        Outcome::Refused {
            code: ErrorCode::RateVersionMismatch,
            detail: 2
        }
    ));
    let sequence = client
        .rate_change(key, 2, policy(200, 20), Wire::Administrator, 62, None)
        .unwrap();
    assert!(matches!(
        complete(&mut driver, &mut client, sequence),
        Outcome::RateState { version: 3, .. }
    ));
    let mut zero_bytes = policy(10, 10);
    zero_bytes.bytes = Some(Rate {
        per_second: 0,
        burst: 4096,
    });
    assert_eq!(
        client.rate_change(key, 3, zero_bytes, Wire::Administrator, 63, None),
        Err(karyos_client::ConductorError::InvalidRatePolicy)
    );
    let audit: Vec<_> = driver
        .guard_audit()
        .records
        .iter()
        .map(|record| {
            (
                record.operation,
                record.requester,
                record.outcome,
                record.parameters,
            )
        })
        .collect();
    let operator = Requester::Operator {
        client: id,
        uid: 1000,
    };
    assert_eq!(
        audit,
        [
            (
                60,
                operator,
                AuditOutcome::RateChanged {
                    authority: RateAuthority::Safety
                },
                rate_parameters(key, 1, Wire::Safety, 60, 1000, &policy(50, 10))
            ),
            (
                61,
                Requester::Client(id),
                AuditOutcome::Refused(ErrorCode::RateVersionMismatch),
                rate_parameters(key, 1, Wire::Safety, 61, NO_OPERATOR, &policy(40, 10))
            ),
            (
                62,
                Requester::Client(id),
                AuditOutcome::RateChanged {
                    authority: RateAuthority::Administrator
                },
                rate_parameters(
                    key,
                    2,
                    Wire::Administrator,
                    62,
                    NO_OPERATOR,
                    &policy(200, 20)
                )
            ),
        ]
    );
    drop(client);
    serve_until(&mut driver, |driver| driver.clients() == 0);
}

/// A remote client maps the client counters region writable: a counter it
/// writes is read by the driver, and while it lives the client does not
/// send `Leave`, so its cell stays charged; once it is gone, `Leave`
/// releases the slot and the cell.
#[test]
fn a_remote_client_counter_is_written_and_outlives_its_client() {
    let dir = dir("counter");
    let mut driver = system_driver(&dir);
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let id = client.client();
    let sequence = client.allocate_counter(9, "remote events", 0, 0).unwrap();
    let mut done: Vec<Completion> = Vec::new();
    let start = Instant::now();
    while done.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "timed out");
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    let completion = done.pop().unwrap();
    assert_eq!(completion.sequence, sequence);
    let Outcome::Counter(counter) = completion.outcome else {
        panic!("expected a counter, got {:?}", completion.outcome);
    };
    assert_eq!(counter.increment(6), Ok(6));
    let reader = driver.client_counters();
    let karyos_sys::counters::CellRead::Allocated {
        metadata, value, ..
    } = reader.read(counter.cell())
    else {
        panic!("expected an allocated cell");
    };
    assert_eq!(value, 6);
    assert_eq!(metadata.registration_id, counter.registration());
    assert_eq!(metadata.keys.participant, id);
    // The client is closed while its counter lives: no Leave yet.
    drop(client);
    for _ in 0..10 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(driver.clients(), 1);
    assert_eq!(counter.increment(1), Ok(7));
    let cell = counter.cell();
    drop(counter);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(reader.read(cell), karyos_sys::counters::CellRead::Free);
}

#[test]
fn hellos_that_break_the_profile_are_refused() {
    let dir = dir("hello");
    let mut driver = system_driver(&dir);
    let hello = encode(&Message::Hello { version: VERSION });
    // A version refusal states this driver's version (karyos#879).
    let refused = |code| {
        Some(match core::num::NonZeroU64::new(VERSION) {
            Some(version) if code == refusal::INCOMPATIBLE_VERSION => {
                Message::incompatible_version(version)
            }
            _ => Message::Refused { fetch: 0, code },
        })
    };
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
    // Another protocol version, even one with a longer Hello: a later one,
    // and version 1, the build before the trace journal kinds.
    let own = own_pidfd();
    let mut future = encode(&Message::Hello {
        version: VERSION + 1,
    });
    future.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        raw_hello(&mut driver, &dir, &future, Some(&own)),
        refused(refusal::INCOMPATIBLE_VERSION)
    );
    assert_eq!(
        raw_hello(
            &mut driver,
            &dir,
            &encode(&Message::Hello { version: 1 }),
            Some(&own)
        ),
        refused(refusal::INCOMPATIBLE_VERSION)
    );
    // Version 2, an alpha.2 client's (karyos#637: version 3 since the
    // roles commands).
    assert_eq!(VERSION, 5);
    assert_eq!(
        raw_hello(
            &mut driver,
            &dir,
            &encode(&Message::Hello { version: 2 }),
            Some(&own)
        ),
        refused(refusal::INCOMPATIBLE_VERSION)
    );
    // Version 3, an alpha.3 client's (karyos#740: version 4 since the rate
    // change command), and version 4, an unreleased build's before
    // karyos#844 (ADR-0100: version 5 since the parent-aware image attach).
    assert_eq!(
        raw_hello(
            &mut driver,
            &dir,
            &encode(&Message::Hello { version: 3 }),
            Some(&own)
        ),
        refused(refusal::INCOMPATIBLE_VERSION)
    );
    assert_eq!(
        raw_hello(
            &mut driver,
            &dir,
            &encode(&Message::Hello { version: 4 }),
            Some(&own)
        ),
        refused(refusal::INCOMPATIBLE_VERSION)
    );
    // Not a Hello: closed without an answer.
    assert_eq!(
        raw_hello(&mut driver, &dir, &encode(&Message::Leave), None),
        None
    );
    assert_eq!(driver.clients(), 0);
    // Each refusal reached the error log, keyed by its code: three
    // profile refusals and five version refusals (P7 o3).
    let mut occurrences = std::collections::HashMap::new();
    let _ = driver.error_log().scan(&mut 0, |record| {
        assert_eq!(
            record.code,
            karyos_driver::diagnostics::ErrorCode::HelloRejected as u32
        );
        *occurrences.entry(record.key).or_insert(0) += record.occurrences;
    });
    assert_eq!(occurrences.get(&[0, refusal::PROFILE]), Some(&3));
    assert_eq!(
        occurrences.get(&[0, refusal::INCOMPATIBLE_VERSION]),
        Some(&5)
    );
    assert_eq!(occurrences.len(), 2);
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
    // On a loaded host the three duty cycles above may not have taken the
    // connection yet (karyos#993): its hello timeout then counts from a
    // later tick. Advance the clock by one timeout per cycle until the
    // close is seen, within a wall-clock bound.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut now = 0;
    loop {
        now += 100;
        clock.now.store(now, Ordering::Relaxed);
        let _ = driver.do_work().unwrap();
        match ipc::recv(socket.as_fd(), &mut buffer) {
            Ok(Recv::PeerClosed) => break,
            Ok(Recv::WouldBlock) => {}
            other => panic!("unexpected {other:?}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "never closed at the hello timeout"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
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
            schedule_capacity: 0,
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
        stream_registration,
        incarnation,
        base: 0,
        records,
    } = manifest
    else {
        panic!("expected the manifest of fetch 1, got {manifest:?}");
    };
    // The grant names its stream's publication identity; a first
    // incarnation's mapping starts at position 0.
    let identity = driver.trace_identity(stream).unwrap();
    assert_eq!(
        (stream_registration, incarnation),
        (identity.registration, identity.incarnation)
    );
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

/// `Leave` with an export left (a fetch the client abandoned, or a grant
/// it did not detach) is a clean leave, counted in `fetches abandoned at
/// leave`, never a fault (QS-COORDINATOR, karyos#851); `Detach` of an
/// export the client does not own is a protocol error. Either way the
/// client is no longer served and its exported grant stays charged until
/// the exit proof.
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
        let leave = matches!(message, Message::Leave);
        assert_eq!(counter(&driver, "clients faulty"), u64::from(!leave));
        assert_eq!(
            counter(&driver, "fetches abandoned at leave"),
            u64::from(leave)
        );
        drop(client);
    }
}

/// karyos#851 (decided 2026-10-28 by QS-COORDINATOR): a client that
/// fetched and left without reading the reply (a fetch it abandoned) leaves
/// cleanly: `clients faulty` stays 0 and `fetches abandoned at leave`
/// counts one; what the fetch exported stays charged until the exit proof.
#[test]
fn a_leave_with_an_abandoned_fetch_is_not_a_fault() {
    let dir = dir("abandoned-leave");
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
    // The fetch, then a Leave before its reply is read.
    let fetch = encode(&Message::Fetch { fetch: 1, key: 1 });
    assert_eq!(ipc::send(socket, &fetch, None).unwrap(), Sent::Sent);
    let leave = encode(&Message::Leave);
    assert_eq!(ipc::send(socket, &leave, None).unwrap(), Sent::Sent);
    serve_until(&mut driver, |driver| {
        counter(driver, "fetches abandoned at leave") == 1
    });
    assert_eq!(counter(&driver, "clients faulty"), 0);
    // This process lives on: the slot and the grant stay charged.
    for _ in 0..4 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(driver.clients(), 1);
    assert_eq!(counter(&driver, "grants ended"), 0);
    drop(client);
}

/// karyos#851 (QS-COORDINATOR, team bus message 35171): when the take of
/// a late grant times out and the client removes the registration, the
/// driver ends the grant once the client drains the abandoned fetch's
/// reply and detaches its export: nothing stays held. The take times out
/// because the driver serves nothing while it waits.
#[test]
fn an_abandoned_take_ends_its_grant_once_drained() {
    let dir = dir("abandoned-take");
    let mut driver = system_driver(&dir);
    let _stream = driver.add_stream(shared_stream_config()).unwrap();
    let mut client = std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            karyos_client::ipc::attach_with(
                &dir,
                Duration::from_secs(5),
                Duration::from_millis(20),
                16,
            )
        });
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
        handle.join().unwrap()
    })
    .unwrap();
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
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| {
            if let Outcome::Fetchable(grant) = completion.outcome {
                fetchable = Some(grant);
            }
        });
    }
    let fetchable = fetchable.unwrap();
    // The driver serves nothing: the take's fetch times out, abandoned.
    assert!(matches!(
        client.take_subscription(&fetchable),
        Err(AttachError::Timeout)
    ));
    assert!(client.remove_abandoned(&fetchable));
    let ended = counter(&driver, "grants ended");
    // The driver serves the fetch (its regions sent) and the removal: the
    // grant was sent, so it is held until its Detach.
    for _ in 0..64 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(
        counter(&driver, "grants ended"),
        ended,
        "ended before its Detach"
    );
    // The client's next poll drains the reply and detaches the export.
    let start = Instant::now();
    while counter(&driver, "grants ended") == ended {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the grant stayed held"
        );
        client.drain_abandoned();
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(counter(&driver, "grants detached"), 1);
    drop(client);
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

/// A stream's `allow_unconnected` reaches a remote client's publication
/// through its grant's record (quantstratum-docs:
/// karyos/design/ipc-admission.md, Unconnected offers): with no subscriber,
/// an exclusive or a concurrent handle offers when its request or its
/// stream allows it, and is not connected when neither does.
#[test]
fn a_streams_allow_unconnected_reaches_a_remote_publication() {
    // (stream allows, request asks): the OR of the two, not either alone.
    let cases = [(false, false), (true, false), (false, true)];
    for concurrent in [false, true] {
        for (allow, request) in cases {
            let dir = dir(&format!("unconnected-{concurrent}-{allow}-{request}"));
            let mut driver = system_driver(&dir);
            let mut config = shared_stream_config();
            config.allow_unconnected = allow;
            if concurrent {
                config.buffer.publication = PublicationMode::Concurrent {
                    publishers: 1,
                    allow_non_lse: true,
                };
            }
            let _stream = driver.add_stream(config).unwrap();
            let mut client = attach_serving(&mut driver, &dir).unwrap();
            let key = StreamKey {
                stream_id: 2,
                session_id: 1,
            };
            let accepted = serve_while(&mut driver, move || {
                if concurrent {
                    let _ = client.add_concurrent_publication(key, request).unwrap();
                } else {
                    let _ = client.add_publication(key, request).unwrap();
                }
                let mut fetchable = None;
                let start = Instant::now();
                while fetchable.is_none() {
                    assert!(start.elapsed() < Duration::from_secs(5), "no completion");
                    let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                        Outcome::Fetchable(grant) => fetchable = Some(grant),
                        other => panic!("expected a fetchable grant, got {other:?}"),
                    });
                }
                let grant = fetchable.unwrap();
                let accepted = if concurrent {
                    let mut publication = client.take_concurrent_publication(&grant).unwrap();
                    let outcome = publication.offer(b"alone").unwrap();
                    assert!(
                        matches!(
                            outcome,
                            karyos_client::ConcurrentOfferOutcome::Accepted { .. }
                                | karyos_client::ConcurrentOfferOutcome::NotConnected
                        ),
                        "{outcome:?}"
                    );
                    matches!(
                        outcome,
                        karyos_client::ConcurrentOfferOutcome::Accepted { .. }
                    )
                } else {
                    let mut publication = client.take_publication(&grant).unwrap();
                    let outcome = publication.offer(b"alone").unwrap();
                    assert!(
                        matches!(
                            outcome,
                            OfferOutcome::Accepted { .. } | OfferOutcome::NotConnected
                        ),
                        "{outcome:?}"
                    );
                    matches!(outcome, OfferOutcome::Accepted { .. })
                };
                drop(client);
                accepted
            });
            assert_eq!(
                accepted,
                allow || request,
                "concurrent {concurrent}, allow {allow}, request {request}"
            );
            serve_until(&mut driver, |driver| driver.clients() == 0);
        }
    }
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
    let (client, subscription, _) = remote_subscriber_as(driver, dir, SubscriberRole::Required);
    (client, subscription)
}

/// A remote client takes a subscription with `role`; returns it with the
/// subscription handle and its registration.
fn remote_subscriber_as(
    driver: &mut IpcDriver,
    dir: &Path,
    role: SubscriberRole,
) -> (RemoteClient, ClientSubscription<SharedTerms>, u64) {
    let mut client = attach_serving(driver, dir).unwrap();
    serve_while(driver, move || {
        let _ = client
            .add_subscription(
                StreamKey {
                    stream_id: 2,
                    session_id: 1,
                },
                role,
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
        let fetchable = fetchable.unwrap();
        let subscription = client.take_subscription(&fetchable).unwrap();
        (client, subscription, fetchable.registration)
    })
}

/// The driver's `driver_id` as one 128-bit value: `[high, low]` packed
/// `high << 64 | low`, as a loss record's instance.
fn driver_instance(driver: &IpcDriver) -> u128 {
    let [high, low] = driver.driver_id();
    u128::from(high) << 64 | u128::from(low)
}

/// The driver_id is the single per-instance id (ACS 13555): the instance of
/// `Admitted`, which every CnC region header the client attached carries
/// (attach compares each header with it), equals the driver's `driver_id`.
#[test]
fn the_admitted_instance_is_the_driver_id() {
    let dir = dir("instance");
    let mut driver = system_driver(&dir);
    let instance = driver_instance(&driver);
    assert_ne!(instance, 0);
    assert_eq!(driver.instance(), Some(instance));
    let client = attach_serving(&mut driver, &dir).unwrap();
    assert_eq!(client.instance(), instance);
    // A raw Admitted carries it too, low word first.
    let socket = ipc::connect(&dir, Duration::from_millis(200)).unwrap();
    let pidfd = own_pidfd();
    let hello = encode(&Message::Hello { version: VERSION });
    assert_eq!(
        ipc::send(socket.as_fd(), &hello, Some(pidfd.as_fd())).unwrap(),
        Sent::Sent
    );
    let (admitted, none) = next_message(&mut driver, socket.as_fd());
    assert!(none.is_none());
    let Message::Admitted { instance: got, .. } = admitted else {
        panic!("expected Admitted, got {admitted:?}");
    };
    assert_eq!(got, instance);
    drop(client);
}

/// A remote optional subscriber that is overrun reports its loss as an
/// in-process one does: the driver records one verified overrun whose
/// instance is its `driver_id`, with the stream registration and
/// incarnation the grant's manifest carried, the subscription's
/// registration and the remote client.
#[test]
fn an_overrun_remote_subscriber_records_one_verified_loss() {
    let dir = dir("loss");
    let mut driver = system_driver(&dir);
    let stream = driver
        .add_stream(StreamConfig {
            allow_unconnected: true,
            ..shared_stream_config()
        })
        .unwrap();
    let (mut client, subscription, registration) =
        remote_subscriber_as(&mut driver, &dir, SubscriberRole::Optional);
    let mut subscription = subscription.with_rejoin(karyos_client::RejoinPolicy::RejoinAtHead);
    let mut publication: ClientPublication<SharedTerms> = driver.publication(stream).unwrap();
    // Lap the subscriber that never reads.
    for _ in 0..300 {
        let start = Instant::now();
        while !matches!(
            publication.offer(&[7u8; 512]).unwrap(),
            OfferOutcome::Accepted { .. }
        ) {
            assert!(start.elapsed() < Duration::from_secs(5), "never accepted");
            let _ = driver.do_work().unwrap();
        }
        let _ = driver.do_work().unwrap();
    }
    let summary = subscription.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
    let lost = summary.overrun.unwrap();
    assert_eq!(
        summary.rejoin,
        Some(karyos_client::RejoinOutcome::ResumedAtHead)
    );
    assert!(lost.from < lost.lost_to);
    assert_eq!(client.loss_reports_queued(), 1);
    // The remote client's poll sends the ReportLoss through its ring.
    let mut records = Vec::new();
    let start = Instant::now();
    while records.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "no loss record");
        let _ = client.poll(usize::MAX, |completion| {
            panic!("unexpected completion {completion:?}");
        });
        let _ = driver.do_work().unwrap();
        let _ = driver
            .loss_report()
            .scan(&mut 0, |_, record| records.push(record));
    }
    let [record] = records[..] else {
        panic!("expected exactly one loss record");
    };
    let identity = driver.trace_identity(stream).unwrap();
    assert_eq!(
        karyos_sys::diag::LossRecord { time: 0, ..record },
        karyos_sys::diag::LossRecord {
            time: 0,
            kind: 1,
            reason: 0,
            lane: 0,
            configured_policy: 1,
            applied_policy: 1,
            flags: 0,
            instance: driver_instance(&driver),
            stream_registration: identity.registration,
            incarnation: karyos_driver::FIRST_INCARNATION,
            stream_id: 2,
            from: lost.from,
            to: lost.lost_to,
            participant: registration,
            client: client.client(),
        }
    );
    assert_eq!(counter(&driver, "overruns rejoin at head"), 1);
    assert_eq!(counter(&driver, "loss reports unverified"), 0);
    assert_eq!(counter(&driver, "clients faulty"), 0);
    assert_eq!(client.loss_reports_queued(), 0);
    assert_eq!(client.loss_reports_dropped(), 0);
    drop(publication);
    serve_while(&mut driver, move || {
        drop(subscription);
        drop(client);
    });
    serve_until(&mut driver, |driver| driver.clients() == 0);
}

/// G-d2c: a remote subscriber of a fresh incarnation maps its buffer at the
/// manifest's base, the seal of the replaced incarnation, so its positions
/// and the loss it reports are absolute stream positions, which the driver
/// verifies against the incarnation the manifest named.
#[test]
fn a_remote_subscriber_of_a_fresh_incarnation_reads_absolute_positions() {
    let dir = dir("fresh-base");
    let mut driver = system_driver(&dir);
    let mut config = StreamConfig {
        allow_unconnected: true,
        ..shared_stream_config()
    };
    // The walker takes a spare-slot credit; the optional reader needs one
    // more.
    config.buffer.spare_slots = 8;
    config.buffer.max_subscribers = 8;
    let stream = driver.add_stream(config).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(stream, guard, 4, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let mut publication: ClientPublication<SharedTerms> = driver.publication(stream).unwrap();
    for _ in 0..3 {
        assert!(matches!(
            publication.offer(&[1u8; 512]).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    assert!(driver.close_guard(guard, 2).is_ok());
    drop(publication);
    let _ = driver.do_work().unwrap();
    let seal = match driver.seal_state(stream).unwrap() {
        SealState::Positioned { position } | SealState::Retired { position } => position,
        other => panic!("not positioned: {other:?}"),
    };
    assert!(seal > 0);
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    let mut publication: ClientPublication<SharedTerms> = driver.publication(stream).unwrap();
    assert_eq!(driver.trace_identity(stream).unwrap().incarnation, 2);
    let (mut client, subscription, registration) =
        remote_subscriber_as(&mut driver, &dir, SubscriberRole::Optional);
    let mut subscription = subscription.with_rejoin(karyos_client::RejoinPolicy::RejoinAtHead);
    assert_eq!(
        subscription.position(),
        seal,
        "the mapping starts at the seal"
    );
    // Lap the subscriber that never reads.
    for _ in 0..300 {
        let start = Instant::now();
        while !matches!(
            publication.offer(&[7u8; 512]).unwrap(),
            OfferOutcome::Accepted { .. }
        ) {
            assert!(start.elapsed() < Duration::from_secs(5), "never accepted");
            let _ = driver.do_work().unwrap();
            // A guarded handle's outcome ring is drained by its owner.
            let _ = publication.poll_outcomes(64, |_, _| {}).unwrap();
        }
        let _ = driver.do_work().unwrap();
        let _ = publication.poll_outcomes(64, |_, _| {}).unwrap();
    }
    let summary = subscription.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
    let lost = summary.overrun.unwrap();
    assert!(seal <= lost.from && lost.from < lost.lost_to);
    let mut records = Vec::new();
    let start = Instant::now();
    while records.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "no loss record");
        let _ = client.poll(usize::MAX, |completion| {
            panic!("unexpected completion {completion:?}");
        });
        let _ = driver.do_work().unwrap();
        let _ = driver
            .loss_report()
            .scan(&mut 0, |_, record| records.push(record));
    }
    let [record] = records[..] else {
        panic!("expected exactly one loss record");
    };
    assert_eq!(
        (
            record.incarnation,
            record.from,
            record.to,
            record.participant
        ),
        (2, lost.from, lost.lost_to, registration)
    );
    assert_eq!(counter(&driver, "loss reports unverified"), 0);
    assert_eq!(counter(&driver, "clients faulty"), 0);
    drop(publication);
    serve_while(&mut driver, move || {
        drop(subscription);
        drop(client);
    });
    serve_until(&mut driver, |driver| driver.clients() == 0);
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

/// A tool attached over the admission socket (`quantstratum-docs:
/// karyos/design/observability-and-tools.md`, Tool attach) reads, through
/// its read-only mappings, what the driver writes: the driver counters
/// cell for cell, a client counter a remote client wrote, the error record
/// of a refused hello and the loss record of an overrun remote subscriber;
/// a later error shows through the same mapping. It holds no client slot,
/// and it notices the driver's exit when the socket closes, after which
/// its mappings stay readable.
#[test]
fn a_tool_reads_the_diagnostics_the_driver_writes() {
    let dir = dir("tool-reads");
    let mut driver = system_driver(&dir);
    let stream = driver
        .add_stream(StreamConfig {
            allow_unconnected: true,
            ..shared_stream_config()
        })
        .unwrap();
    // An error record: a hello without its pidfd.
    let hello = encode(&Message::Hello { version: VERSION });
    assert_eq!(
        raw_hello(&mut driver, &dir, &hello, None),
        Some(Message::Refused {
            fetch: 0,
            code: refusal::PROFILE
        })
    );
    // A loss record: an optional remote subscriber that is overrun.
    let (mut client, subscription, registration) =
        remote_subscriber_as(&mut driver, &dir, SubscriberRole::Optional);
    // A client counter written by the remote client.
    let _ = client.allocate_counter(9, "tool visible", 0, 0).unwrap();
    let mut done: Vec<Completion> = Vec::new();
    let start = Instant::now();
    while done.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "timed out");
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    let Outcome::Counter(handle) = done.pop().unwrap().outcome else {
        panic!("expected a counter");
    };
    assert_eq!(handle.increment(41), Ok(41));
    let mut subscription = subscription.with_rejoin(karyos_client::RejoinPolicy::RejoinAtHead);
    let mut publication: ClientPublication<SharedTerms> = driver.publication(stream).unwrap();
    for _ in 0..300 {
        let start = Instant::now();
        while !matches!(
            publication.offer(&[7u8; 512]).unwrap(),
            OfferOutcome::Accepted { .. }
        ) {
            assert!(start.elapsed() < Duration::from_secs(5), "never accepted");
            let _ = driver.do_work().unwrap();
        }
        let _ = driver.do_work().unwrap();
    }
    let summary = subscription.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
    assert!(summary.overrun.is_some());
    let mut losses = Vec::new();
    let start = Instant::now();
    while losses.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "no loss record");
        let _ = client.poll(usize::MAX, |completion| {
            panic!("unexpected completion {completion:?}");
        });
        let _ = driver.do_work().unwrap();
        let _ = driver
            .loss_report()
            .scan(&mut 0, |_, record| losses.push(record));
    }

    let mut tool = serve_while(&mut driver, || {
        karyos_client::tool::attach_tool(&dir, Duration::from_secs(5))
    })
    .unwrap();
    assert_eq!(tool.instance(), driver_instance(&driver));
    assert_eq!(driver.tools(), 1);
    assert_eq!(driver.clients(), 1);
    // The driver counters, cell for cell (nothing runs between the reads).
    let own = driver.counters();
    assert_eq!(tool.counters().capacity(), own.capacity());
    for index in 0..own.capacity() {
        assert_eq!(tool.counters().read(index), own.read(index), "cell {index}");
    }
    assert_eq!(
        (0..tool.counters().capacity()).find_map(|index| match tool.counters().read(index) {
            karyos_sys::counters::CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == b"clients admitted" => Some(value),
            _ => None,
        }),
        Some(counter(&driver, "clients admitted"))
    );
    // The client counter.
    let karyos_sys::counters::CellRead::Allocated {
        metadata, value, ..
    } = tool.client_counters().read(handle.cell())
    else {
        panic!("expected the client's cell");
    };
    assert_eq!((value, metadata.label()), (41, &b"tool visible"[..]));
    // The error log.
    let mut errors = Vec::new();
    let mut cursor = 0;
    let _ = tool
        .error_log()
        .scan(&mut cursor, |record| errors.push(record));
    let [error] = &errors[..] else {
        panic!("expected one error record, got {errors:?}");
    };
    assert_eq!(
        (error.code, error.key, error.occurrences),
        (
            karyos_driver::diagnostics::ErrorCode::HelloRejected as u32,
            [0, refusal::PROFILE],
            1
        )
    );
    // The loss report.
    let mut seen = Vec::new();
    let _ = tool
        .loss_report()
        .scan(&mut 0, |_, record| seen.push(record));
    assert_eq!(seen, losses);
    assert_eq!(seen[0].participant, registration);
    // A later error shows through the same mapping.
    let _ = raw_hello(&mut driver, &dir, &hello, None);
    let mut again = Vec::new();
    let _ = tool.error_log().scan(&mut 0, |record| again.push(record));
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].occurrences, 2);

    drop(publication);
    serve_while(&mut driver, move || {
        drop(handle);
        drop(subscription);
        drop(client);
    });
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert!(!tool.driver_closed().unwrap());
    assert_eq!(driver.tools(), 1);
    drop(driver);
    // Another test's spawned child can hold a copy of the driver's socket
    // between its fork and exec, so the close can take a moment.
    let start = Instant::now();
    while !tool.driver_closed().unwrap() {
        assert!(start.elapsed() < Duration::from_secs(5), "never closed");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(tool.loss_report().scan(&mut 0, |_, _| {}).delivered, 1);
}

/// Resolution 9 (network streams over shared terms): a `Fetch` of a
/// `Held` grant whose stream is retiring is served, since the grant keeps
/// the stream and its mapping (`free_retired_streams`); the fetched
/// subscriber delivers the backlog to the removal's seal and then reports
/// closed there, never open. An image's `RetireImage` seals its lanes the
/// same way, with `SealReason::ImageRetired`.
#[test]
fn a_held_grant_fetched_on_a_retiring_stream_reports_closed_at_the_seal() {
    let dir = dir("retiring-fetch");
    let mut driver = system_driver(&dir);
    let stream = driver
        .add_stream(StreamConfig {
            allow_unconnected: true,
            ..shared_stream_config()
        })
        .unwrap();
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
    // One message, then the stream is removed while the grant is held.
    let mut publication: ClientPublication<SharedTerms> = driver.publication(stream).unwrap();
    let start = Instant::now();
    while !matches!(
        publication.offer(b"backlog").unwrap(),
        OfferOutcome::Accepted { .. }
    ) {
        assert!(start.elapsed() < Duration::from_secs(5), "never accepted");
        let _ = driver.do_work().unwrap();
    }
    drop(publication);
    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(
        driver.stream_state(stream).unwrap(),
        karyos_driver::StreamState::Retiring
    );
    let socket = client.admission_socket().unwrap();
    let fetch = encode(&Message::Fetch { fetch: 1, key: 1 });
    assert_eq!(ipc::send(socket, &fetch, None).unwrap(), Sent::Sent);
    let (manifest, _) = next_message(&mut driver, socket);
    let Message::Manifest { records, .. } = manifest else {
        panic!("a fetch on a retiring stream is served, got {manifest:?}");
    };
    let [record] = records[..] else {
        panic!("one record");
    };
    let karyos_protocol::admission::Capability::RequiredSubscriber { cell } = record.capability
    else {
        panic!("a required subscriber record");
    };
    let (region, fd) = next_message(&mut driver, socket);
    assert_eq!(region, Message::Region { fetch: 1, index: 0 });
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
    let mut out = [0u8; 64];
    let karyos_sys::log_buffer::PollOutcome::Message { length, .. } =
        adopted.poll(&mut out).unwrap()
    else {
        panic!("the backlog first");
    };
    assert_eq!(&out[..length as usize], b"backlog");
    adopted.acknowledge();
    for _ in 0..2 {
        let outcome = adopted.poll(&mut out).unwrap();
        assert!(
            matches!(
                outcome,
                karyos_sys::log_buffer::PollOutcome::Closed {
                    reason: karyos_driver::SealReason::StreamRemoved,
                    ..
                }
            ),
            "{outcome:?}"
        );
    }
    // The fetched grant still names the stream: it is not freed under the
    // client's mapping.
    for _ in 0..10 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(
        driver.stream_state(stream).unwrap(),
        karyos_driver::StreamState::Retiring
    );
}

/// Resolution 4 (network streams over shared terms): an IPC driver with a
/// network checks its descriptor limit at start. Bounds no `RLIMIT_NOFILE`
/// can cover fail with the typed error naming the needed count and the soft
/// and hard limits; the default bounds start (496 descriptors, under any
/// usual soft limit).
#[test]
fn an_ipc_driver_with_a_network_checks_its_descriptor_limit_at_start() {
    let network = karyos_driver::net::NetworkConfig {
        threading: karyos_driver::agents::ThreadingMode::Shared,
        ..karyos_driver::net::NetworkConfig::default()
    };
    let (limit, hard) = karyos_sys::ipc::descriptor_limits();
    let over_dir = dir("descriptors-over");
    let over = EmbeddedDriver::<SharedTerms>::with_ipc(
        DriverConfig {
            network: Some(network),
            max_streams: 1 << 40,
            ..DriverConfig::default()
        },
        ipc_config(&over_dir, 100),
        Box::new(ManualClock::default()),
    );
    match limit {
        Some(limit) => assert!(
            matches!(
                over,
                Err(karyos_driver::DriverError::DescriptorLimit { needed, limit: l, hard: h })
                    if l == limit && h == hard && needed == 64 * 4 + (1u64 << 40) * 3 + 16 * 3
            ),
            "{over:?}"
        ),
        None => assert!(over.is_ok(), "an unlimited process starts"),
    }
    let fits_dir = dir("descriptors-default");
    let mut fits = EmbeddedDriver::<SharedTerms>::with_ipc(
        DriverConfig {
            network: Some(network),
            ..DriverConfig::default()
        },
        ipc_config(&fits_dir, 100),
        Box::new(ManualClock::default()),
    )
    .unwrap();
    let _ = fits.close_network();
}

const DRAIN_CHILD: &str = "KARYOS_ADMISSION_DRAIN_CHILD";

/// The `Fetch` messages the drain child queues in front of its `Detach`
/// messages: more than `ipc_config`'s `max_fetches_per_client` (4).
const DRAIN_FETCHES: u64 = 12;

/// karyos#827: what a client queued on its socket before it exited is
/// read before its exit proof releases it, and nothing is served for the
/// dead client. The child holds two exported grants and a third, held
/// and never fetched; it sends 12 `Fetch` messages of the held grant, more
/// than it may have open, then both `Detach` messages, and exits while the
/// driver does not run. One duty
/// cycle used to read one datagram and then release the client, so the
/// second `Detach` went unread and its grant ended as a release at exit.
/// Now both count as detached, the `Fetch` messages are dropped and
/// counted without pushing a `Detach` out (no third export), and no grant
/// whose descriptor left is released at exit:
/// the held one never left.
#[test]
fn an_exited_clients_queued_detaches_are_served_before_its_release() {
    let dir = dir("drain-exited");
    let mut driver = system_driver(&dir);
    let mut second = shared_stream_config();
    second.buffer.stream_id = 3;
    let mut third = shared_stream_config();
    third.buffer.stream_id = 4;
    let _streams = (
        driver.add_stream(shared_stream_config()).unwrap(),
        driver.add_stream(second).unwrap(),
        driver.add_stream(third).unwrap(),
    );
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_detaches_twice_fetches_and_exits",
            "--nocapture",
        ])
        .env(DRAIN_CHILD, &dir)
        .spawn()
        .unwrap();
    // Served until both grants are exported; then the driver stops, so
    // whatever the child sends next is still queued when it exits.
    serve_until(&mut driver, |driver| {
        counter(driver, "grants exported") == 2
    });
    assert!(child.wait().unwrap().success());
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(counter(&driver, "grants detached"), 2);
    assert_eq!(
        counter(&driver, "grants exported"),
        2,
        "a fetch served after the exit"
    );
    assert_eq!(counter(&driver, "fetches dropped at exit"), DRAIN_FETCHES);
    assert_eq!(counter(&driver, "grants released at exit"), 0);
    assert_eq!(counter(&driver, "admission messages dropped at exit"), 0);
}

/// Runs only as the child of
/// `an_exited_clients_queued_detaches_are_served_before_its_release`.
#[test]
fn child_detaches_twice_fetches_and_exits() {
    let Some(dir) = std::env::var_os(DRAIN_CHILD) else {
        return;
    };
    let mut client = attach(Path::new(&dir), Duration::from_secs(5), 16).unwrap();
    for stream_id in [2, 3, 4] {
        let _ = client
            .add_subscription(
                StreamKey {
                    stream_id,
                    session_id: 1,
                },
                SubscriberRole::Required,
            )
            .unwrap();
    }
    let mut keys = Vec::new();
    let start = Instant::now();
    while keys.len() < 3 {
        assert!(start.elapsed() < Duration::from_secs(10), "no grants");
        let _ = client.poll(usize::MAX, |completion| {
            if let Outcome::Fetchable(fetchable) = completion.outcome {
                keys.push(fetchable.key);
            }
        });
        std::thread::sleep(Duration::from_millis(1));
    }
    let socket = client.admission_socket().unwrap();
    // The next message on the socket, waiting for the parent's driver.
    let receive = || {
        let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
        let start = Instant::now();
        loop {
            assert!(start.elapsed() < Duration::from_secs(10), "no message");
            if let Ok(Recv::Message(received)) = ipc::recv(socket, &mut buffer) {
                let message = Message::decode(&buffer[..received.len]).unwrap();
                return (message, received.fd);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    let held = keys.pop().unwrap();
    let mut exports = Vec::new();
    for (fetch, key) in (1..).zip(keys) {
        let message = encode(&Message::Fetch { fetch, key });
        assert_eq!(ipc::send(socket, &message, None).unwrap(), Sent::Sent);
        let (Message::Manifest { records, .. }, _) = receive() else {
            panic!("no manifest");
        };
        // The region's descriptor, closed at once: nothing stays mapped.
        let _ = receive();
        exports.push(records[0].export);
    }
    // More `Fetch` messages than the client may have open, in front of the
    // `Detach` messages: discarded unread, they must not push a `Detach`
    // out of the drain.
    for fetch in 3..3 + DRAIN_FETCHES {
        let message = encode(&Message::Fetch { fetch, key: held });
        assert_eq!(ipc::send(socket, &message, None).unwrap(), Sent::Sent);
    }
    for export in exports {
        let message = encode(&Message::Detach { export });
        assert_eq!(ipc::send(socket, &message, None).unwrap(), Sent::Sent);
    }
    // Exit without dropping the client: no Leave, and the driver has not
    // run since the last region.
    std::mem::forget(client);
    std::process::exit(0);
}

const GONE_CHILD: &str = "KARYOS_ADMISSION_GONE_CHILD";

/// karyos#827: Linux closes a dying process's descriptors before its pidfd
/// reads exited, so the driver can find a client's socket gone first. The
/// child stands for that window: it holds one exported grant and one held
/// grant, queues a `Fetch` of the held one and a `Detach` of the exported
/// one after shutting its socket's receiving side, and stays alive until
/// the parent tells it to exit. Serving the `Fetch` queues a reply whose
/// send fails with `EPIPE`, which counts as an exit for the drain
/// (QS-COORDINATOR, 2026-10-28): the reply is dropped and counted, the
/// `Detach` behind it is drained and counted as a detach, and the client
/// is retired, not as faulty, its slot kept until its exit proof.
#[test]
fn a_client_whose_socket_closes_before_its_exit_is_drained_then() {
    let dir = dir("gone-before-exit");
    let mut driver = system_driver(&dir);
    let mut second = shared_stream_config();
    second.buffer.stream_id = 3;
    let _streams = (
        driver.add_stream(shared_stream_config()).unwrap(),
        driver.add_stream(second).unwrap(),
    );
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_closes_its_socket_then_waits_to_exit",
            "--nocapture",
        ])
        .env(GONE_CHILD, &dir)
        .spawn()
        .unwrap();
    let closed = dir.join("child-closed");
    let faulty = counter(&driver, "clients faulty");
    // Served until the child holds its export; then the driver waits, so
    // the child's `Fetch` and `Detach` are both queued before it reads
    // either.
    serve_until(&mut driver, |driver| {
        counter(driver, "grants exported") == 1
    });
    let start = Instant::now();
    while !closed.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the child never closed"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    serve_until(&mut driver, |driver| {
        counter(driver, "clients closed before their exit") == 1
    });
    // Drained before its exit proof: the `Detach` counts and the reply does
    // not go.
    assert_eq!(counter(&driver, "grants detached"), 1);
    assert!(counter(&driver, "admission messages not sent at exit") >= 1);
    assert_eq!(driver.clients(), 1, "released before its exit proof");
    assert_eq!(
        counter(&driver, "clients faulty"),
        faulty,
        "retired as faulty"
    );
    std::fs::write(dir.join("child-exit"), b"").unwrap();
    assert!(child.wait().unwrap().success());
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(counter(&driver, "grants detached"), 1);
    assert_eq!(counter(&driver, "grants exported"), 1);
    assert!(counter(&driver, "admission messages not sent at exit") >= 1);
    assert_eq!(counter(&driver, "grants released at exit"), 0);
    assert_eq!(counter(&driver, "clients faulty"), faulty);
}

/// Runs only as the child of
/// `a_client_whose_socket_closes_before_its_exit_is_drained_then`.
#[test]
fn child_closes_its_socket_then_waits_to_exit() {
    let Some(dir) = std::env::var_os(GONE_CHILD) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let mut client = attach(&dir, Duration::from_secs(5), 16).unwrap();
    for stream_id in [2, 3] {
        let _ = client
            .add_subscription(
                StreamKey {
                    stream_id,
                    session_id: 1,
                },
                SubscriberRole::Required,
            )
            .unwrap();
    }
    let mut keys = Vec::new();
    let start = Instant::now();
    while keys.len() < 2 {
        assert!(start.elapsed() < Duration::from_secs(10), "no grants");
        let _ = client.poll(usize::MAX, |completion| {
            if let Outcome::Fetchable(fetchable) = completion.outcome {
                keys.push(fetchable.key);
            }
        });
        std::thread::sleep(Duration::from_millis(1));
    }
    let socket = client.admission_socket().unwrap();
    let message = encode(&Message::Fetch {
        fetch: 1,
        key: keys[0],
    });
    assert_eq!(ipc::send(socket, &message, None).unwrap(), Sent::Sent);
    let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
    let start = Instant::now();
    let export = loop {
        assert!(start.elapsed() < Duration::from_secs(10), "no manifest");
        if let Ok(Recv::Message(received)) = ipc::recv(socket, &mut buffer)
            && let Ok(Message::Manifest { records, .. }) = Message::decode(&buffer[..received.len])
        {
            break records[0].export;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    // The region's descriptor, closed at once: nothing stays mapped.
    let start = Instant::now();
    while !matches!(ipc::recv(socket, &mut buffer), Ok(Recv::Message(_))) {
        assert!(start.elapsed() < Duration::from_secs(10), "no region");
        std::thread::sleep(Duration::from_millis(1));
    }
    // Its receiving side closes first, so the reply to the next `Fetch`
    // cannot be delivered, whenever the driver serves it.
    ipc::shutdown_read(socket).unwrap();
    for message in [
        Message::Fetch {
            fetch: 2,
            key: keys[1],
        },
        Message::Detach { export },
    ] {
        assert_eq!(
            ipc::send(socket, &encode(&message), None).unwrap(),
            Sent::Sent
        );
    }
    std::fs::write(dir.join("child-closed"), b"").unwrap();
    let start = Instant::now();
    while !dir.join("child-exit").exists() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "never told to exit"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    std::mem::forget(client);
    std::process::exit(0);
}

const UNREAD_CHILD: &str = "KARYOS_ADMISSION_UNREAD_CHILD";

/// karyos#827: a client that dies with a reply unread leaves the driver's
/// socket in error (`ECONNRESET`, reported once, before any datagram), and
/// the drain must still read what the client queued behind it. The child
/// holds one exported grant and one held grant, queues a `Fetch` of the
/// held one and a `Detach` of the exported one, and exits once the driver
/// has sent the reply to the `Fetch`, without reading it. The `Detach`
/// counts as a detach.
#[test]
fn a_client_that_exits_with_a_reply_unread_is_drained() {
    let dir = dir("unread-reply");
    let mut driver = system_driver(&dir);
    let mut second = shared_stream_config();
    second.buffer.stream_id = 3;
    let _streams = (
        driver.add_stream(shared_stream_config()).unwrap(),
        driver.add_stream(second).unwrap(),
    );
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_exits_with_a_reply_unread", "--nocapture"])
        .env(UNREAD_CHILD, &dir)
        .spawn()
        .unwrap();
    serve_until(&mut driver, |driver| {
        counter(driver, "grants exported") == 1
    });
    // The driver waits until both messages are queued, then serves the
    // `Fetch` alone: one datagram a step, and the step that sends its
    // reply ends the wait.
    let queued = dir.join("child-queued");
    let start = Instant::now();
    while !queued.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the child never queued"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    serve_until(&mut driver, |driver| {
        counter(driver, "grants exported") == 2
    });
    assert_eq!(
        counter(&driver, "grants detached"),
        0,
        "the Detach was served live"
    );
    std::fs::write(dir.join("child-exit"), b"").unwrap();
    assert!(child.wait().unwrap().success());
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(counter(&driver, "grants detached"), 1);
    assert_eq!(
        counter(&driver, "grants released at exit"),
        1,
        "the unread grant"
    );
}

/// Runs only as the child of
/// `a_client_that_exits_with_a_reply_unread_is_drained`.
#[test]
fn child_exits_with_a_reply_unread() {
    let Some(dir) = std::env::var_os(UNREAD_CHILD) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let mut client = attach(&dir, Duration::from_secs(5), 16).unwrap();
    for stream_id in [2, 3] {
        let _ = client
            .add_subscription(
                StreamKey {
                    stream_id,
                    session_id: 1,
                },
                SubscriberRole::Required,
            )
            .unwrap();
    }
    let mut keys = Vec::new();
    let start = Instant::now();
    while keys.len() < 2 {
        assert!(start.elapsed() < Duration::from_secs(10), "no grants");
        let _ = client.poll(usize::MAX, |completion| {
            if let Outcome::Fetchable(fetchable) = completion.outcome {
                keys.push(fetchable.key);
            }
        });
        std::thread::sleep(Duration::from_millis(1));
    }
    let socket = client.admission_socket().unwrap();
    let message = encode(&Message::Fetch {
        fetch: 1,
        key: keys[0],
    });
    assert_eq!(ipc::send(socket, &message, None).unwrap(), Sent::Sent);
    let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
    let start = Instant::now();
    let export = loop {
        assert!(start.elapsed() < Duration::from_secs(10), "no manifest");
        if let Ok(Recv::Message(received)) = ipc::recv(socket, &mut buffer)
            && let Ok(Message::Manifest { records, .. }) = Message::decode(&buffer[..received.len])
        {
            break records[0].export;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let start = Instant::now();
    while !matches!(ipc::recv(socket, &mut buffer), Ok(Recv::Message(_))) {
        assert!(start.elapsed() < Duration::from_secs(10), "no region");
        std::thread::sleep(Duration::from_millis(1));
    }
    for message in [
        Message::Fetch {
            fetch: 2,
            key: keys[1],
        },
        Message::Detach { export },
    ] {
        assert_eq!(
            ipc::send(socket, &encode(&message), None).unwrap(),
            Sent::Sent
        );
    }
    std::fs::write(dir.join("child-queued"), b"").unwrap();
    let start = Instant::now();
    while !dir.join("child-exit").exists() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "never told to exit"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // The reply to the second `Fetch` stays unread.
    std::mem::forget(client);
    std::process::exit(0);
}

/// The #831 review, points 1 and 7: the drain of a client found gone reads
/// a 0-byte datagram queued before its close as a datagram, not as the end
/// of the stream, so the `Detach` behind it is still served. The client
/// shuts its receiving side, so the reply to its `Fetch` fails with
/// `EPIPE` (the driver finds it gone), then queues a 0-byte datagram and a
/// `Detach`, and shuts its sending side.
#[test]
fn a_zero_byte_datagram_before_a_close_does_not_hide_a_detach() {
    let dir = dir("zero-before-close");
    let mut driver = system_driver(&dir);
    let _stream = driver.add_stream(shared_stream_config()).unwrap();
    let (client, export, fd) = fetched_subscription(&mut driver, &dir);
    drop(fd);
    let socket = client.admission_socket().unwrap();
    ipc::shutdown_read(socket).unwrap();
    // A fetch of no grant: its refusal is the reply that cannot be sent.
    let fetch = encode(&Message::Fetch { fetch: 2, key: 999 });
    assert_eq!(ipc::send(socket, &fetch, None).unwrap(), Sent::Sent);
    // A 0-byte datagram, which `ipc::send` refuses, through a duplicate of
    // the socket.
    let raw = std::os::unix::net::UnixDatagram::from(socket.try_clone_to_owned().unwrap());
    assert_eq!(raw.send(&[]).unwrap(), 0);
    let detach = encode(&Message::Detach { export });
    assert_eq!(ipc::send(socket, &detach, None).unwrap(), Sent::Sent);
    ipc::shutdown_write(socket).unwrap();
    serve_until(&mut driver, |driver| {
        counter(driver, "clients closed before their exit") == 1
    });
    assert_eq!(
        counter(&driver, "grants detached"),
        1,
        "the Detach was hidden"
    );
    assert_eq!(counter(&driver, "admission messages dropped at exit"), 1);
    drop(raw);
    drop(client);
}

/// karyos#827 (QS-COORDINATOR, 2026-10-28): a live client that shuts its
/// socket down without exiting is retired as closed, not as faulty, and
/// its slot stays charged. With no exit proof within its bound (1 s), it
/// counts as faulty, once, and its slot is still held: closing and
/// reconnecting frees no slot. A 0-byte datagram is told apart from such a
/// close by `POLLRDHUP`.
#[test]
fn a_live_client_that_closes_is_faulty_after_the_fetch_deadline() {
    let dir = dir("closed-alive");
    let clock = ManualClock::default();
    let mut driver = driver(&dir, Box::new(clock.clone()));
    // This process stays alive: its own pidfd never reads exited.
    let socket = ipc::connect(&dir, Duration::from_millis(20)).unwrap();
    let own = own_pidfd();
    let hello = encode(&Message::Hello { version: VERSION });
    assert_eq!(
        ipc::send(socket.as_fd(), &hello, Some(own.as_fd())).unwrap(),
        Sent::Sent
    );
    let start = Instant::now();
    while driver.clients() != 1 {
        assert!(start.elapsed() < Duration::from_secs(5), "not admitted");
        let _ = driver.do_work().unwrap();
    }
    let faulty = counter(&driver, "clients faulty");
    ipc::shutdown_write(socket.as_fd()).unwrap();
    let start = Instant::now();
    while counter(&driver, "clients closed before their exit") != 1 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the close was not seen"
        );
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(
        counter(&driver, "clients faulty"),
        faulty,
        "faulty at the close"
    );
    assert_eq!(driver.clients(), 1, "the slot was freed at the close");
    // Past the exit proof's bound (1 s, its own since the #831 review's
    // point 3; the fetch deadline is 100 ticks here) with no exit proof.
    let _ = clock.now.fetch_add(1_000_000_001, Ordering::Relaxed);
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(counter(&driver, "clients faulty"), faulty + 1);
    assert_eq!(
        driver.clients(),
        1,
        "the slot was freed without an exit proof"
    );
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(
        counter(&driver, "clients faulty"),
        faulty + 1,
        "counted twice"
    );
}
