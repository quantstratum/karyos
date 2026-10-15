// SPDX-License-Identifier: Apache-2.0

//! Platform checks of the admission socket and its regions (Linux;
//! quantstratum-docs: karyos/design/ipc-admission.md, design/ipc-implementation.md,
//! i4): directory and socket modes and owners, stale and foreign files at
//! the socket path, a full accept backlog, an unserved driver, regions that
//! refuse a resize, and descriptor counts. The tests share one lock: the
//! descriptor count reads `/proc/self/fd`, so nothing else may open or
//! close descriptors while it runs.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use karyos_client::ipc::{AttachError, RemoteClient, attach};
use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, MonotonicClock};
use karyos_protocol::admission::{MAX_MESSAGE_LENGTH, Message, VERSION};
use karyos_sys::ipc::{self, PidFd, Recv, SOCKET_NAME, Sent};

static SERIAL: Mutex<()> = Mutex::new(());

/// Serializes the tests of this binary (see the module documentation).
fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

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
    let dir = std::env::temp_dir().join(format!("karyos-plat-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn config(dir: &Path, pending: usize) -> IpcConfig {
    IpcConfig {
        dir: dir.to_path_buf(),
        max_pending_hellos: pending,
        hello_timeout: 100,
        max_outbound_per_client: 8,
        fetch_deadline: 100,
    }
}

fn driver_with(dir: &Path, pending: usize, clock: &ManualClock) -> EmbeddedDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        config(dir, pending),
        Box::new(clock.clone()),
    )
    .unwrap()
}

fn try_driver(dir: &Path) -> bool {
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        config(dir, 2),
        Box::new(ManualClock::default()),
    )
    .is_ok()
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

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map_or(0, Iterator::count)
}

fn is_root() -> bool {
    ipc::own_uid() == 0
}

#[test]
fn test_admission_dir_with_wrong_mode_is_refused() {
    let _serial = serial();
    let dir = dir("dirmode");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!try_driver(&dir));
    // Nothing was created or changed.
    assert!(!dir.join(SOCKET_NAME).exists());
    assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o755);
}

#[test]
fn test_admission_dir_of_another_uid_is_refused() {
    let _serial = serial();
    // Changing a directory's owner needs root (the Docker runs of
    // scripts/linux-test.sh); an unprivileged run checks nothing here.
    if !is_root() {
        return;
    }
    let dir = dir("dirowner");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::chown(&dir, Some(65_534), Some(65_534)).unwrap();
    assert!(!try_driver(&dir));
    assert!(!dir.join(SOCKET_NAME).exists());
}

#[test]
fn test_admission_socket_with_wrong_mode_or_owner_is_refused_by_the_client() {
    let _serial = serial();
    let dir = dir("sockmode");
    let mut driver = driver_with(&dir, 2, &ManualClock::default());
    let socket = dir.join(SOCKET_NAME);
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        attach(&dir, Duration::from_millis(200), 16),
        Err(AttachError::Sys(_))
    ));
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    if is_root() {
        std::os::unix::fs::chown(&socket, Some(65_534), None).unwrap();
        assert!(matches!(
            attach(&dir, Duration::from_millis(200), 16),
            Err(AttachError::Sys(_))
        ));
        std::os::unix::fs::chown(&socket, Some(0), None).unwrap();
    }
    // Restored: the same driver admits the client.
    let client = attach_serving(&mut driver, &dir).unwrap();
    drop(client);
    serve_until(&mut driver, |driver| driver.clients() == 0);
}

#[test]
fn test_admission_stale_socket_of_a_dead_driver_is_replaced() {
    let _serial = serial();
    let dir = dir("stale");
    let first = driver_with(&dir, 2, &ManualClock::default());
    drop(first);
    // The socket file stays behind with nobody listening on it.
    assert!(dir.join(SOCKET_NAME).exists());
    let mut second = driver_with(&dir, 2, &ManualClock::default());
    let client = attach_serving(&mut second, &dir).unwrap();
    assert_eq!(Some(client.instance()), second.instance());
    drop(client);
    serve_until(&mut second, |driver| driver.clients() == 0);
}

#[test]
fn test_admission_live_driver_socket_is_not_replaced() {
    let _serial = serial();
    let dir = dir("live");
    let mut first = driver_with(&dir, 2, &ManualClock::default());
    assert!(!try_driver(&dir));
    // The first driver still owns the socket and serves.
    let client = attach_serving(&mut first, &dir).unwrap();
    assert_eq!(Some(client.instance()), first.instance());
    drop(client);
    serve_until(&mut first, |driver| driver.clients() == 0);
}

#[test]
fn test_admission_regular_file_at_the_socket_path_is_kept() {
    let _serial = serial();
    let dir = dir("regular");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join(SOCKET_NAME);
    std::fs::write(&path, b"not a socket").unwrap();
    // A file the driver did not create is never deleted.
    assert!(!try_driver(&dir));
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
}

#[test]
fn test_admission_symlink_at_the_socket_path_is_kept() {
    let _serial = serial();
    let dir = dir("symlink");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = std::env::temp_dir().join(format!("karyos-plat-{}-target", std::process::id()));
    std::fs::write(&target, b"target").unwrap();
    let path = dir.join(SOCKET_NAME);
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(!try_driver(&dir));
    assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
    assert_eq!(std::fs::read(&target).unwrap(), b"target");
    std::fs::remove_file(&target).unwrap();
}

#[test]
fn test_admission_unserved_driver_makes_attach_time_out() {
    let _serial = serial();
    let dir = dir("unserved");
    let driver = driver_with(&dir, 2, &ManualClock::default());
    // The connection waits in the backlog; no duty cycle answers it.
    let start = Instant::now();
    assert!(matches!(
        attach(&dir, Duration::from_millis(200), 16),
        Err(AttachError::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_secs(5));
    drop(driver);
}

#[test]
fn test_admission_full_backlog_bounds_connect_until_served() {
    let _serial = serial();
    let dir = dir("backlog");
    let clock = ManualClock::default();
    // A backlog of 1: the kernel queues at most two unaccepted
    // connections on a Unix socket; no duty cycle accepts them.
    let mut driver = driver_with(&dir, 1, &clock);
    let bound = Duration::from_millis(100);
    let first = ipc::connect(&dir, bound).unwrap();
    let second = ipc::connect(&dir, bound).unwrap();
    // The third finds the backlog full: connect retries until its bound and
    // then fails, instead of blocking.
    let start = Instant::now();
    assert!(ipc::connect(&dir, bound).is_err());
    let waited = start.elapsed();
    assert!(waited >= bound, "gave up after {waited:?}");
    assert!(waited < Duration::from_secs(5), "waited {waited:?}");
    // Served: the silent connections are accepted and closed at the hello
    // timeout, which empties the backlog.
    for _ in 0..4 {
        let _ = driver.do_work().unwrap();
        clock.now.fetch_add(100, Ordering::Relaxed);
    }
    let _ = driver.do_work().unwrap();
    drop((first, second));
    // The driver admits a real client afterwards.
    let client = attach_serving(&mut driver, &dir).unwrap();
    drop(client);
    serve_until(&mut driver, |driver| driver.clients() == 0);
}

#[test]
fn test_admission_handed_out_regions_refuse_resize() {
    let _serial = serial();
    let dir = dir("resize");
    let mut driver = driver_with(&dir, 2, &ManualClock::default());
    // A raw admission: Hello with this process's pidfd, then the bootstrap
    // (Admitted and one Region per CnC region, each with its descriptor).
    // An attached client keeps no descriptor, so the descriptors are taken
    // here as the driver passes them.
    let socket = ipc::connect(&dir, Duration::from_millis(20)).unwrap();
    let pidfd = PidFd::of_self().unwrap();
    let mut hello = [0u8; MAX_MESSAGE_LENGTH];
    let length = Message::Hello { version: VERSION }
        .encode(&mut hello)
        .unwrap();
    assert_eq!(
        ipc::send(socket.as_fd(), &hello[..length], Some(pidfd.as_fd())).unwrap(),
        Sent::Sent
    );
    let mut regions = Vec::new();
    let mut admitted = false;
    let start = Instant::now();
    while regions.len() < 3 {
        assert!(start.elapsed() < Duration::from_secs(5), "timed out");
        let _ = driver.do_work().unwrap();
        let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
        match ipc::recv(socket.as_fd(), &mut buffer).unwrap() {
            Recv::Message(received) => match Message::decode(&buffer[..received.len]).unwrap() {
                Message::Admitted { .. } => admitted = true,
                Message::Region { .. } => regions.push(received.fd.unwrap()),
                other => panic!("unexpected {other:?}"),
            },
            Recv::WouldBlock => {}
            Recv::PeerClosed => panic!("closed during the bootstrap"),
        }
    }
    assert!(admitted);
    for fd in regions {
        let file = std::fs::File::from(fd);
        let length = file.metadata().unwrap().len();
        for size in [0, length / 2, length * 2] {
            let error = file.set_len(size).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(1), "EPERM for size {size}");
        }
        assert_eq!(file.metadata().unwrap().len(), length);
    }
    // Leave releases the client.
    let mut leave = [0u8; MAX_MESSAGE_LENGTH];
    let length = Message::Leave.encode(&mut leave).unwrap();
    assert_eq!(
        ipc::send(socket.as_fd(), &leave[..length], None).unwrap(),
        Sent::Sent
    );
    serve_until(&mut driver, |driver| driver.clients() == 0);
}

#[test]
fn test_admission_descriptors_do_not_leak() {
    let _serial = serial();
    let dir = dir("fds");
    let clock = ManualClock::default();
    let mut driver = driver_with(&dir, 2, &clock);
    let baseline = open_fds();
    for _ in 0..8 {
        // An admitted client that leaves.
        let client = attach_serving(&mut driver, &dir).unwrap();
        drop(client);
        serve_until(&mut driver, |driver| driver.clients() == 0);
        // A Hello with a descriptor that is not a pidfd, refused.
        let socket = ipc::connect(&dir, Duration::from_millis(20)).unwrap();
        let mut hello = [0u8; MAX_MESSAGE_LENGTH];
        let length = Message::Hello { version: VERSION }
            .encode(&mut hello)
            .unwrap();
        let not_a_pidfd = ipc::seqpacket_pair().unwrap();
        assert_eq!(
            ipc::send(
                socket.as_fd(),
                &hello[..length],
                Some(not_a_pidfd.0.as_fd())
            )
            .unwrap(),
            Sent::Sent
        );
        drop(not_a_pidfd);
        let start = Instant::now();
        loop {
            assert!(start.elapsed() < Duration::from_secs(5), "timed out");
            let _ = driver.do_work().unwrap();
            let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
            match ipc::recv(socket.as_fd(), &mut buffer).unwrap() {
                Recv::Message(_) | Recv::PeerClosed => break,
                Recv::WouldBlock => {}
            }
        }
        drop(socket);
        // A silent connection closed at the hello timeout.
        let silent = ipc::connect(&dir, Duration::from_millis(20)).unwrap();
        let _ = driver.do_work().unwrap();
        clock.now.fetch_add(100, Ordering::Relaxed);
        let _ = driver.do_work().unwrap();
        drop(silent);
        // Retired descriptors are closed by the next duty cycles.
        for _ in 0..4 {
            let _ = driver.do_work().unwrap();
        }
    }
    assert_eq!(open_fds(), baseline, "descriptors leaked");
}
