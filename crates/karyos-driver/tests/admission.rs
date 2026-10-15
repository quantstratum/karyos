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

use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use karyos_client::ipc::{AttachError, RemoteClient, attach};
use karyos_client::{Completion, Outcome};
use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, MonotonicClock, SystemClock};
use karyos_protocol::admission::{MAX_MESSAGE_LENGTH, Message, VERSION, refusal};
use karyos_protocol::cnc::{ErrorCode, StreamKey, SubscriberRole};
use karyos_sys::ipc::{self, PidFd, Recv, Sent};

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
    }
}

fn driver(dir: &Path, clock: Box<dyn MonotonicClock>) -> EmbeddedDriver {
    EmbeddedDriver::with_ipc(DriverConfig::default(), ipc_config(dir, 100), clock).unwrap()
}

/// A driver on the system clock (nanoseconds) with timeouts of 5 s.
fn system_driver(dir: &Path) -> EmbeddedDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        ipc_config(dir, 5_000_000_000),
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

/// Attaches on another thread while this one runs duty cycles.
fn attach_serving(driver: &mut EmbeddedDriver, dir: &Path) -> Result<RemoteClient, AttachError> {
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| attach(dir, Duration::from_secs(5), 16));
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
        handle.join().unwrap()
    })
}

/// Duty cycles until `done` or a few seconds pass.
fn serve_until(driver: &mut EmbeddedDriver, mut done: impl FnMut(&EmbeddedDriver) -> bool) {
    let start = Instant::now();
    while !done(driver) {
        assert!(start.elapsed() < Duration::from_secs(5), "timed out");
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
    driver: &mut EmbeddedDriver,
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
    let conductor = client.conductor().unwrap();
    let sequence = conductor
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
        let _ = client
            .conductor()
            .unwrap()
            .poll(usize::MAX, |completion| done.push(completion));
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
    assert!(client.counters().unwrap().capacity() > 0);
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
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_attaches_and_exits", "--nocapture"])
        .env(CHILD, &dir)
        .spawn()
        .unwrap();
    serve_until(&mut driver, |driver| driver.clients() == 2);
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
