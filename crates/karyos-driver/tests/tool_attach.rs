// SPDX-License-Identifier: Apache-2.0

//! Tool attach (Linux; `quantstratum-docs:
//! karyos/design/observability-and-tools.md`, Tool attach, Owner decision
//! Q7 and Tests, "Tool attach (Linux)"): a tool receives exactly the four
//! diagnostic regions, read-only (A1), and nothing that lets it act as a
//! client; a driver-only region a client receives cannot be mapped
//! writable either (A2); `max_tools` bounds the tool connections; and a
//! bootstrap with a missing, duplicate, unexpected or wrong-instance region
//! rolls the attach back with every mapping and descriptor released,
//! against a fake driver that plays the admission socket.
//!
//! The tests share one lock: the rollback checks count this process's
//! descriptors and mappings, so nothing else may open or map while they
//! run.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use karyos_client::ipc::AttachError;
use karyos_client::tool::{RemoteTool, attach_tool};
use karyos_driver::{DriverConfig, DriverError, EmbeddedDriver, IpcConfig, SystemClock};
use karyos_protocol::admission::{
    Capability, MAX_MESSAGE_LENGTH, Message, Record, RegionKind as WireKind, VERSION, refusal,
};
use karyos_sys::ipc::{self, PidFd, Recv, Region, RegionKind, Sent, probe};
use karyos_sys::term_bytes::SharedTerms;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The driver of these tests: IPC mode.
type IpcDriver = EmbeddedDriver<SharedTerms>;

const EACCES: i32 = 13;
const EPERM: i32 = 1;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-tool-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The admission settings: timeouts of 5 s on the system clock.
fn config(dir: &Path, max_tools: usize) -> IpcConfig {
    IpcConfig {
        dir: dir.to_path_buf(),
        max_pending_hellos: 4,
        hello_timeout: 5_000_000_000,
        max_outbound_per_client: 8,
        fetch_deadline: 5_000_000_000,
        max_exports_per_client: 16,
        max_fetches_per_client: 4,
        max_regions_per_fetch: 4,
        max_fetch_bytes: 1 << 30,
        max_tools,
    }
}

fn driver(dir: &Path, max_tools: usize) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        config(dir, max_tools),
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

/// Serves the driver while `work` runs on another thread; returns its
/// result once it finished.
fn serve_while<R: Send>(driver: &mut IpcDriver, work: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(work);
        let start = Instant::now();
        while !handle.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        handle.join().unwrap()
    })
}

fn serve_until(driver: &mut IpcDriver, mut done: impl FnMut(&IpcDriver) -> bool) {
    let start = Instant::now();
    while !done(driver) {
        assert!(start.elapsed() < Duration::from_secs(30), "timed out");
        let _ = driver.do_work().unwrap();
        std::thread::yield_now();
    }
}

fn encode(message: &Message) -> Vec<u8> {
    let mut out = [0u8; MAX_MESSAGE_LENGTH];
    let length = message.encode(&mut out).unwrap();
    out[..length].to_vec()
}

fn send(socket: BorrowedFd<'_>, message: &Message, fd: Option<BorrowedFd<'_>>) {
    assert_eq!(ipc::send(socket, &encode(message), fd).unwrap(), Sent::Sent);
}

/// What arrived on a raw connection while the driver was served.
#[derive(Debug)]
enum Arrived {
    Message(Message, Option<OwnedFd>),
    Closed,
}

/// The next message on `socket`, or its close, serving the driver while
/// nothing is there.
fn next(driver: &mut IpcDriver, socket: BorrowedFd<'_>) -> Arrived {
    let start = Instant::now();
    loop {
        let _ = driver.do_work().unwrap();
        let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
        match ipc::recv(socket, &mut buffer) {
            Ok(Recv::Message(received)) => {
                return Arrived::Message(
                    Message::decode(&buffer[..received.len]).unwrap(),
                    received.fd,
                );
            }
            Ok(Recv::PeerClosed) | Err(_) => return Arrived::Closed,
            Ok(Recv::WouldBlock) => {
                assert!(start.elapsed() < Duration::from_secs(5), "nothing arrived");
            }
        }
    }
}

fn next_message(driver: &mut IpcDriver, socket: BorrowedFd<'_>) -> (Message, Option<OwnedFd>) {
    match next(driver, socket) {
        Arrived::Message(message, fd) => (message, fd),
        Arrived::Closed => panic!("the driver closed the connection"),
    }
}

/// A raw connection that sent `ToolHello` and received its whole
/// bootstrap: the records and one descriptor per record.
fn raw_tool(driver: &mut IpcDriver, dir: &Path) -> (OwnedFd, u128, Vec<Record>, Vec<OwnedFd>) {
    let socket = ipc::connect(dir, Duration::from_millis(20)).unwrap();
    send(
        socket.as_fd(),
        &Message::ToolHello { version: VERSION },
        None,
    );
    let (admitted, none) = next_message(driver, socket.as_fd());
    assert!(none.is_none());
    let Message::ToolAdmitted {
        instance,
        version,
        records,
    } = admitted
    else {
        panic!("expected ToolAdmitted, got {admitted:?}");
    };
    assert_eq!(version, VERSION);
    let mut fds = Vec::new();
    for index in 0..records.len() as u64 {
        let (region, fd) = next_message(driver, socket.as_fd());
        assert_eq!(region, Message::Region { fetch: 0, index });
        fds.push(fd.unwrap());
    }
    (socket, instance, records, fds)
}

/// A raw first datagram and the driver's answer, if any, before the
/// connection closes.
fn raw_hello(
    driver: &mut IpcDriver,
    dir: &Path,
    bytes: &[u8],
    fd: Option<BorrowedFd<'_>>,
) -> Option<Message> {
    let socket = ipc::connect(dir, Duration::from_millis(20)).unwrap();
    assert_eq!(ipc::send(socket.as_fd(), bytes, fd).unwrap(), Sent::Sent);
    match next(driver, socket.as_fd()) {
        Arrived::Message(message, None) => Some(message),
        Arrived::Message(message, Some(_)) => panic!("a descriptor with {message:?}"),
        Arrived::Closed => None,
    }
}

fn attach_serving(driver: &mut IpcDriver, dir: &Path) -> Result<RemoteTool, AttachError> {
    serve_while(driver, || attach_tool(dir, Duration::from_secs(5)))
}

fn hello_rejections(driver: &IpcDriver, code: u64) -> u64 {
    let mut occurrences = 0;
    let _ = driver.error_log().scan(&mut 0, |record| {
        if record.code == karyos_driver::diagnostics::ErrorCode::HelloRejected as u32
            && record.key == [0, code]
        {
            occurrences += record.occurrences;
        }
    });
    occurrences
}

/// A tool receives exactly the four diagnostic regions, each once, without
/// a capability, under the driver's instance, and nothing after them; it
/// takes no client slot. Every descriptor it received is read-only (A1):
/// the kernel refuses a shared writable mapping of it and write access
/// added by `mprotect`, with `EACCES`, whether the region is driver-only
/// or shared with clients.
#[test]
fn a_tool_receives_the_four_diagnostic_regions_read_only() {
    let _serial = serial();
    let dir = dir("four");
    let mut driver = driver(&dir, 4);
    let (socket, instance, records, fds) = raw_tool(&mut driver, &dir);
    assert_eq!(Some(instance), driver.instance());
    let kinds: Vec<WireKind> = records.iter().map(|record| record.kind).collect();
    assert_eq!(
        kinds,
        [
            WireKind::Counters,
            WireKind::ClientCounters,
            WireKind::ErrorLog,
            WireKind::LossReport
        ]
    );
    assert!(
        records
            .iter()
            .all(|record| record.capability == Capability::None && record.export != 0)
    );
    for fd in &fds {
        assert_eq!(probe::writable_mapping(fd.as_fd()).unwrap(), Some(EACCES));
        assert_eq!(probe::mprotect_writable(fd.as_fd()).unwrap(), Some(EACCES));
    }
    // Nothing follows the bootstrap, and the connection stays open.
    for _ in 0..20 {
        let _ = driver.do_work().unwrap();
    }
    let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
    assert!(matches!(
        ipc::recv(socket.as_fd(), &mut buffer),
        Ok(Recv::WouldBlock)
    ));
    assert_eq!((driver.tools(), driver.clients()), (1, 0));
    // Closing the socket frees the connection.
    drop(socket);
    serve_until(&mut driver, |driver| driver.tools() == 0);
}

/// A tool cannot obtain a command ring or a capability through its
/// connection: a `Fetch` or a client `Hello` sent after `ToolAdmitted`
/// closes the connection without an answer, and no client is admitted.
#[test]
fn a_tool_cannot_act_as_a_client() {
    let _serial = serial();
    let dir = dir("client");
    let mut driver = driver(&dir, 4);
    let pidfd = PidFd::of_self().unwrap();
    for (message, fd) in [
        (Message::Fetch { fetch: 1, key: 1 }, None),
        (Message::Hello { version: VERSION }, Some(pidfd.as_fd())),
        (Message::Leave, None),
    ] {
        let (socket, _, records, fds) = raw_tool(&mut driver, &dir);
        assert!(records.iter().all(|record| !matches!(
            record.kind,
            WireKind::CommandRing | WireKind::Broadcast | WireKind::LogBuffer
        )));
        drop(fds);
        send(socket.as_fd(), &message, fd);
        assert!(matches!(next(&mut driver, socket.as_fd()), Arrived::Closed));
        assert_eq!((driver.tools(), driver.clients()), (0, 0));
    }
}

/// A2: the driver counters region a client receives is driver-only, so a
/// shared writable mapping of its descriptor is refused (`EPERM`, by the
/// `F_SEAL_FUTURE_WRITE` seal), while the client counters region, which
/// clients write, maps writable.
#[test]
fn a_driver_only_region_a_client_receives_refuses_a_writable_mapping() {
    let _serial = serial();
    let dir = dir("a2");
    let mut driver = driver(&dir, 4);
    let socket = ipc::connect(&dir, Duration::from_millis(20)).unwrap();
    let pidfd = PidFd::of_self().unwrap();
    send(
        socket.as_fd(),
        &Message::Hello { version: VERSION },
        Some(pidfd.as_fd()),
    );
    let (admitted, _) = next_message(&mut driver, socket.as_fd());
    let Message::Admitted { records, .. } = admitted else {
        panic!("expected Admitted, got {admitted:?}");
    };
    let mut checked = 0;
    for (index, record) in (0u64..).zip(&records) {
        let (region, fd) = next_message(&mut driver, socket.as_fd());
        assert_eq!(region, Message::Region { fetch: 0, index });
        let fd = fd.unwrap();
        match record.kind {
            WireKind::Counters => {
                assert_eq!(probe::writable_mapping(fd.as_fd()).unwrap(), Some(EPERM));
                checked += 1;
            }
            WireKind::ClientCounters => {
                assert_eq!(probe::writable_mapping(fd.as_fd()).unwrap(), None);
                checked += 1;
            }
            _ => {}
        }
    }
    assert_eq!(checked, 2);
    // Every descriptor is closed: Leave releases the client.
    send(socket.as_fd(), &Message::Leave, None);
    serve_until(&mut driver, |driver| driver.clients() == 0);
}

/// Tools beyond `max_tools` are refused with `LIMIT`, and the refusal
/// reaches the error log as a rejected hello; a closed tool frees its
/// connection for the next. A zero `max_tools` is an invalid
/// configuration.
#[test]
fn tools_beyond_max_tools_are_refused() {
    let _serial = serial();
    let dir = dir("limit");
    let mut driver = driver(&dir, 2);
    let first = attach_serving(&mut driver, &dir).unwrap();
    let second = attach_serving(&mut driver, &dir).unwrap();
    assert_eq!(driver.tools(), 2);
    assert!(matches!(
        attach_serving(&mut driver, &dir),
        Err(AttachError::Refused {
            code: refusal::LIMIT
        })
    ));
    assert_eq!(hello_rejections(&driver, refusal::LIMIT), 1);
    assert_eq!((driver.tools(), driver.clients()), (2, 0));
    drop(first);
    serve_until(&mut driver, |driver| driver.tools() == 1);
    let third = attach_serving(&mut driver, &dir).unwrap();
    assert_eq!(third.instance(), second.instance());
    assert_eq!(driver.tools(), 2);

    assert!(matches!(
        EmbeddedDriver::<SharedTerms>::with_ipc(
            DriverConfig::default(),
            config(&self::dir("zero"), 0),
            Box::new(SystemClock::new()),
        ),
        Err(DriverError::InvalidConfig)
    ));
}

/// A `ToolHello` of another version, even a longer one, is refused with
/// `IncompatibleVersion`; one that carries a descriptor, or that is
/// malformed at this version, is refused with `Profile`. Each refusal
/// reaches the error log.
#[test]
fn tool_hellos_that_break_the_profile_are_refused() {
    let _serial = serial();
    let dir = dir("profile");
    let mut driver = driver(&dir, 4);
    let refused = |code| Some(Message::Refused { fetch: 0, code });
    let mut future = encode(&Message::ToolHello {
        version: VERSION + 1,
    });
    future.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        raw_hello(&mut driver, &dir, &future, None),
        refused(refusal::INCOMPATIBLE_VERSION)
    );
    let hello = encode(&Message::ToolHello { version: VERSION });
    let pidfd = PidFd::of_self().unwrap();
    assert_eq!(
        raw_hello(&mut driver, &dir, &hello, Some(pidfd.as_fd())),
        refused(refusal::PROFILE)
    );
    let mut longer = hello.clone();
    longer.extend_from_slice(&[0u8; 8]);
    assert_eq!(
        raw_hello(&mut driver, &dir, &longer, None),
        refused(refusal::PROFILE)
    );
    assert_eq!(driver.tools(), 0);
    assert_eq!(hello_rejections(&driver, refusal::INCOMPATIBLE_VERSION), 1);
    assert_eq!(hello_rejections(&driver, refusal::PROFILE), 2);
}

/// A tool notices the driver's exit: its socket closes, and its mappings
/// stay readable.
#[test]
fn a_tool_notices_the_driver_exit() {
    let _serial = serial();
    let dir = dir("exit");
    let mut driver = driver(&dir, 4);
    let mut tool = attach_serving(&mut driver, &dir).unwrap();
    let capacity = driver.counters().capacity();
    assert!(!tool.driver_closed().unwrap());
    drop(driver);
    let start = Instant::now();
    while !tool.driver_closed().unwrap() {
        assert!(start.elapsed() < Duration::from_secs(5), "never closed");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(tool.driver_closed().unwrap());
    assert_eq!(tool.counters().capacity(), capacity);
}

// ---- Rollback against a fake driver ----

/// The four diagnostic regions of a fake driver, made by the same
/// constructors as the driver's.
struct Fake {
    instance: u128,
    counters: (
        karyos_sys::counters::CountersManager,
        karyos_sys::counters::CountersReader,
    ),
    client: (
        karyos_sys::counters::CountersManager,
        karyos_sys::counters::CountersReader,
        karyos_sys::counters::ClientCells,
    ),
    errors: karyos_sys::diag::ErrorLog,
    losses: karyos_sys::diag::LossReport,
}

impl Fake {
    fn new(instance: u128) -> Self {
        Self {
            instance,
            counters: karyos_sys::counters::counters_in(instance, 2, 4).unwrap(),
            client: karyos_sys::counters::client_counters_in(instance, 3, 4).unwrap(),
            errors: karyos_sys::diag::error_log_in(instance, 4, 8, 1).unwrap(),
            losses: karyos_sys::diag::loss_report_in(instance, 5, 8).unwrap(),
        }
    }

    fn regions(&self) -> [&Region; 4] {
        [
            self.counters.1.region().unwrap(),
            self.client.1.region().unwrap(),
            self.errors.region().unwrap(),
            self.losses.region().unwrap(),
        ]
    }

    /// The wire records of its regions, exports 1 to 4.
    fn records(&self) -> Vec<Record> {
        (1u64..)
            .zip(self.regions())
            .map(|(export, region)| wire(region, export))
            .collect()
    }
}

fn wire(region: &Region, export: u64) -> Record {
    let header = region.record();
    Record {
        region: header.region,
        export,
        kind: match header.kind {
            RegionKind::Counters => WireKind::Counters,
            RegionKind::ClientCounters => WireKind::ClientCounters,
            RegionKind::ErrorLog => WireKind::ErrorLog,
            RegionKind::LossReport => WireKind::LossReport,
            other => panic!("not a diagnostic region: {other:?}"),
        },
        layout: u32::try_from(header.layout).unwrap(),
        structure_length: header.structure_length as u64,
        generation: header.generation,
        stream_id: 0,
        session_id: 0,
        lane: 0,
        capability: Capability::None,
    }
}

/// Sends one message of a fake driver. A tool that already gave up has
/// closed its end, so a failed send is not an error of the fake.
fn offer(socket: BorrowedFd<'_>, message: &Message, fd: Option<BorrowedFd<'_>>) {
    let _ = ipc::send(socket, &encode(message), fd);
}

/// Sends `ToolAdmitted` with `records` under `instance`.
fn admitted(socket: &OwnedFd, instance: u128, records: Vec<Record>) {
    offer(
        socket.as_fd(),
        &Message::ToolAdmitted {
            instance,
            version: VERSION,
            records,
        },
        None,
    );
}

/// Sends `Region { fetch: 0, index }` with a read-only descriptor of
/// `region` (A1, as the driver does).
fn region(socket: &OwnedFd, index: u64, region: &Region) {
    let fd = region.read_only_descriptor().unwrap();
    offer(
        socket.as_fd(),
        &Message::Region { fetch: 0, index },
        Some(fd.as_fd()),
    );
}

/// This process's open descriptors.
fn descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

/// This process's mappings of region memfds.
fn region_mappings() -> usize {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .filter(|line| line.contains("karyos-region"))
        .count()
}

/// Runs `attach_tool` against a fake driver in `dir` that answers the
/// tool's `ToolHello` with `script` and then closes the connection.
fn against_fake(
    dir: &Path,
    fake: &Fake,
    script: impl FnOnce(&OwnedFd, &Fake) + Send,
) -> Result<RemoteTool, AttachError> {
    let listener = ipc::listen(dir, 4).unwrap();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            let start = Instant::now();
            let socket = loop {
                assert!(start.elapsed() < Duration::from_secs(5), "no connection");
                if let Some(socket) = ipc::accept(listener.as_fd()).unwrap() {
                    break socket;
                }
                std::thread::sleep(Duration::from_micros(100));
            };
            let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
            loop {
                assert!(start.elapsed() < Duration::from_secs(5), "no ToolHello");
                match ipc::recv(socket.as_fd(), &mut buffer).unwrap() {
                    Recv::Message(received) => {
                        assert!(received.fd.is_none());
                        assert_eq!(
                            Message::decode(&buffer[..received.len]),
                            Ok(Message::ToolHello { version: VERSION })
                        );
                        break;
                    }
                    Recv::WouldBlock => std::thread::sleep(Duration::from_micros(100)),
                    Recv::PeerClosed => panic!("the tool closed first"),
                }
            }
            script(&socket, fake);
        });
        let tool = attach_tool(dir, Duration::from_secs(5));
        server.join().unwrap();
        tool
    })
}

/// A fake driver that sends what a driver sends is attached: the control
/// for the rollback cases below.
#[test]
fn a_tool_attaches_to_a_fake_driver_and_releases_everything_on_drop() {
    let _serial = serial();
    let fake = Fake::new(0xABCD);
    let dir = dir("fake");
    let before = (descriptors(), region_mappings());
    let mut tool = against_fake(&dir, &fake, |socket, fake| {
        admitted(socket, fake.instance, fake.records());
        for (index, one) in (0u64..).zip(fake.regions()) {
            region(socket, index, one);
        }
    })
    .unwrap();
    assert_eq!(tool.instance(), 0xABCD);
    assert_eq!(tool.counters().capacity(), 4);
    assert_eq!(tool.client_counters().capacity(), 4);
    // The fake closed its end once its script ran.
    assert!(tool.driver_closed().unwrap());
    assert_eq!(region_mappings(), before.1 + 4);
    drop(tool);
    assert_eq!((descriptors(), region_mappings()), before);
}

/// Every bootstrap that breaks the rules rolls the attach back: the error
/// is reported, and every mapping staged and every descriptor received is
/// released (the descriptor and mapping counts are back where they were).
#[test]
fn a_bad_tool_bootstrap_rolls_back_with_every_descriptor_closed() {
    let _serial = serial();
    let fake = Fake::new(0xABCD);
    let other = Fake::new(0xABCE);
    type Script<'a> = Box<dyn FnOnce(&OwnedFd, &Fake) + Send + 'a>;
    type Case<'a> = (&'static str, Script<'a>, fn(&AttachError) -> bool);
    let full = |socket: &OwnedFd, fake: &Fake, count: usize| {
        for (index, one) in (0u64..).zip(fake.regions()).take(count) {
            region(socket, index, one);
        }
    };
    let cases: Vec<Case<'_>> = vec![
        (
            "a missing region: the connection closes after three",
            Box::new(move |socket, fake| {
                admitted(socket, fake.instance, fake.records());
                full(socket, fake, 3);
            }),
            |error| matches!(error, AttachError::Protocol),
        ),
        (
            "a missing kind: three records",
            Box::new(move |socket, fake| {
                let mut records = fake.records();
                records.pop();
                admitted(socket, fake.instance, records);
                full(socket, fake, 3);
            }),
            |error| matches!(error, AttachError::Protocol),
        ),
        (
            "a duplicate kind",
            Box::new(move |socket, fake| {
                let mut records = fake.records();
                records[3] = Record {
                    export: 4,
                    ..records[2]
                };
                admitted(socket, fake.instance, records);
                full(socket, fake, 3);
                region(socket, 3, fake.regions()[2]);
            }),
            |error| matches!(error, AttachError::Protocol),
        ),
        (
            "a duplicate region: index 1 twice",
            Box::new(move |socket, fake| {
                admitted(socket, fake.instance, fake.records());
                full(socket, fake, 2);
                region(socket, 1, fake.regions()[1]);
                region(socket, 3, fake.regions()[3]);
            }),
            |error| matches!(error, AttachError::Protocol),
        ),
        (
            "an unexpected kind: a command ring",
            Box::new(move |socket, fake| {
                let mut records = fake.records();
                records[3].kind = WireKind::CommandRing;
                admitted(socket, fake.instance, records);
                full(socket, fake, 4);
            }),
            |error| matches!(error, AttachError::Protocol),
        ),
        (
            "an unexpected fifth record",
            Box::new(move |socket, fake| {
                let mut records = fake.records();
                records.push(Record {
                    export: 5,
                    kind: WireKind::Broadcast,
                    ..records[0]
                });
                admitted(socket, fake.instance, records);
                full(socket, fake, 4);
                region(socket, 4, fake.regions()[0]);
            }),
            |error| matches!(error, AttachError::Protocol),
        ),
        (
            "a wrong instance in ToolAdmitted",
            Box::new(move |socket, fake| {
                admitted(socket, fake.instance + 1, fake.records());
                full(socket, fake, 4);
            }),
            |error| matches!(error, AttachError::Sys(_)),
        ),
        (
            "the last region of another instance",
            Box::new(|socket, fake| {
                let mut records = fake.records();
                records[3] = Record {
                    export: 4,
                    ..wire(other.regions()[3], 4)
                };
                admitted(socket, fake.instance, records);
                full(socket, fake, 3);
                region(socket, 3, other.regions()[3]);
            }),
            |error| matches!(error, AttachError::Sys(_)),
        ),
        (
            "a region for the wrong record: the error log for the loss report",
            Box::new(move |socket, fake| {
                admitted(socket, fake.instance, fake.records());
                full(socket, fake, 3);
                region(socket, 3, fake.regions()[2]);
            }),
            |error| matches!(error, AttachError::Sys(_)),
        ),
        (
            "a region without its descriptor",
            Box::new(move |socket, fake| {
                admitted(socket, fake.instance, fake.records());
                full(socket, fake, 2);
                offer(
                    socket.as_fd(),
                    &Message::Region { fetch: 0, index: 2 },
                    None,
                );
            }),
            |error| matches!(error, AttachError::Protocol),
        ),
        (
            "a region of another fetch",
            Box::new(move |socket, fake| {
                admitted(socket, fake.instance, fake.records());
                full(socket, fake, 1);
                let fd = fake.regions()[1].read_only_descriptor().unwrap();
                offer(
                    socket.as_fd(),
                    &Message::Region { fetch: 1, index: 1 },
                    Some(fd.as_fd()),
                );
            }),
            |error| matches!(error, AttachError::Protocol),
        ),
        (
            "another version",
            Box::new(move |socket, fake| {
                offer(
                    socket.as_fd(),
                    &Message::ToolAdmitted {
                        instance: fake.instance,
                        version: VERSION + 1,
                        records: fake.records(),
                    },
                    None,
                );
                full(socket, fake, 4);
            }),
            |error| {
                matches!(
                    error,
                    AttachError::IncompatibleVersion {
                        driver: Some(version)
                    } if *version == VERSION + 1
                )
            },
        ),
        (
            "a client's Admitted",
            Box::new(move |socket, fake| {
                offer(
                    socket.as_fd(),
                    &Message::Admitted {
                        instance: fake.instance,
                        version: VERSION,
                        client: 1,
                        records: fake.records(),
                    },
                    None,
                );
                full(socket, fake, 4);
            }),
            |error| matches!(error, AttachError::Protocol),
        ),
        (
            "a refusal",
            Box::new(move |socket, _| {
                offer(
                    socket.as_fd(),
                    &Message::Refused {
                        fetch: 0,
                        code: refusal::LIMIT,
                    },
                    None,
                );
            }),
            |error| {
                matches!(
                    error,
                    AttachError::Refused {
                        code: refusal::LIMIT
                    }
                )
            },
        ),
    ];
    for (index, (case, script, expected)) in cases.into_iter().enumerate() {
        let dir = dir(&format!("rollback-{index}"));
        let before = (descriptors(), region_mappings());
        let error = against_fake(&dir, &fake, script).unwrap_err();
        assert!(expected(&error), "{case}: {error:?}");
        assert_eq!((descriptors(), region_mappings()), before, "{case}");
    }
}
