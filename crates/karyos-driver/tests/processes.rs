// SPDX-License-Identifier: Apache-2.0

//! Multi-process tests (IPC batch i4, Linux): clients in separate
//! processes against one driver, over the admission socket and the CnC
//! regions (quantstratum-docs: karyos/`design/ipc-implementation.md`, i4;
//! quantstratum-docs: karyos/`design/ipc-admission.md`). Each child is this test binary run
//! again with `--exact <child test>`; it reports on stdout, one line per
//! step, and the parent runs the driver's duty cycles meanwhile.
//!
//! Remote clients also take log buffer grants (issue #2, batch d4;
//! quantstratum-docs: karyos/`design/ipc-data-path.md`, Tests): a
//! publisher and a subscriber in two processes exchange messages through a
//! stream's shared region, and a killed holder is released by its exit
//! proof.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use karyos_client::ipc::{RemoteClient, attach};
use karyos_client::{Completion, Fetchable, MessageLimit, OfferOutcome, Outcome};
use karyos_driver::{
    DriverConfig, EmbeddedDriver, IpcConfig, LossPolicy, SealState, StreamConfig, StreamHandle,
    SystemClock,
};
use karyos_protocol::cnc::{ErrorCode, StreamKey, SubscriberRole};
use karyos_sys::counters::CellRead;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

const SCENARIO: &str = "KARYOS_PROCESS_SCENARIO";
const DIR: &str = "KARYOS_PROCESS_DIR";

/// The driver of these tests: IPC mode, every stream in a shared region.
type IpcDriver = EmbeddedDriver<SharedTerms>;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-proc-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A driver listening in `dir`. A process that another test forks holds
/// a copy of a just-dropped listener until its exec (close-on-exec acts
/// only there), so a restart retries briefly while the old socket still
/// answers.
fn driver(dir: &Path) -> IpcDriver {
    driver_with(dir, DriverConfig::default())
}

/// As [`driver`], with `config`.
fn driver_with(dir: &Path, config: DriverConfig) -> IpcDriver {
    let start = Instant::now();
    loop {
        let created = EmbeddedDriver::with_ipc(
            config,
            IpcConfig {
                dir: dir.to_path_buf(),
                max_pending_hellos: 4,
                hello_timeout: 5_000_000_000,
                max_outbound_per_client: 16,
                fetch_deadline: 5_000_000_000,
                max_exports_per_client: 16,
                max_fetches_per_client: 4,
                max_regions_per_fetch: 4,
                max_fetch_bytes: 1 << 30,
                max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
            },
            Box::new(SystemClock::new()),
        );
        match created {
            Ok(driver) => return driver,
            Err(_) if start.elapsed() < Duration::from_secs(2) => std::thread::yield_now(),
            Err(error) => panic!("{error:?}"),
        }
    }
}

/// A child process, killed when the test ends however it ends.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A child running `scenario` against the driver in `dir`, its stdout
/// lines delivered on a channel.
fn spawn(scenario: &str, dir: &Path) -> (Guard, Receiver<String>) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child", "--nocapture", "--test-threads", "1"])
        .env(SCENARIO, scenario)
        .env(DIR, dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            // libtest may print `test child ... ` on the same line first.
            if let Some(at) = line.find("child: ") {
                let _ = sender.send(line[at + "child: ".len()..].to_string());
            }
        }
    });
    (Guard(child), receiver)
}

/// Runs duty cycles until the child reports `expected`, or until `limit`.
fn serve_until_report(driver: &mut IpcDriver, reports: &Receiver<String>, expected: &str) {
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no report {expected}; clients {}",
            driver.clients()
        );
        let _ = driver.do_work().unwrap();
        if let Ok(report) = reports.try_recv() {
            assert_eq!(report, expected);
            return;
        }
        std::thread::yield_now();
    }
}

fn serve_until(driver: &mut IpcDriver, mut done: impl FnMut(&IpcDriver) -> bool) {
    let start = Instant::now();
    while !done(driver) {
        assert!(start.elapsed() < Duration::from_secs(10), "timed out");
        let _ = driver.do_work().unwrap();
        std::thread::yield_now();
    }
}

/// Sends a signal by name with the system `kill` tool (no libc).
fn signal(child: &Child, name: &str) {
    let status = Command::new("kill")
        .args([format!("-{name}"), child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

/// Tells the child to continue past its next wait.
fn release(child: &mut Child) {
    writeln!(child.stdin.as_mut().unwrap(), "go").unwrap();
}

/// The stream the data tests use: stream 2, session 1, exclusive.
const KEY: StreamKey = StreamKey {
    stream_id: 2,
    session_id: 1,
};
/// Messages one data test sends.
const MESSAGES: u32 = 200;

fn add_stream(driver: &mut IpcDriver) -> StreamHandle {
    add_stream_with(
        driver,
        PublicationMode::Exclusive,
        karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
    )
}

fn add_stream_with(
    driver: &mut IpcDriver,
    publication: PublicationMode,
    claim_deadline: u64,
) -> StreamHandle {
    driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: KEY.session_id,
                stream_id: KEY.stream_id,
                claim_deadline,
                publication,
                schedule_capacity: 0,
            },
            allow_unconnected: false,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        })
        .unwrap()
}

fn counter(driver: &IpcDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

/// Descriptors open in this process.
fn open_descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

/// A publisher process and a subscriber process exchange a sequence
/// through the stream's shared region: the subscriber gets every message,
/// in order and with its payload, and both detach and leave.
#[test]
fn test_ipc_data_a_publisher_and_a_subscriber_process_exchange_in_order() {
    let dir = dir("exchange");
    let mut driver = driver(&dir);
    let _stream = add_stream(&mut driver);
    let (mut subscriber, subscriber_reports) = spawn("subscribe", &dir);
    serve_until_report(&mut driver, &subscriber_reports, "subscribed");
    let (mut publisher, publisher_reports) = spawn("publish", &dir);
    serve_until_report(&mut driver, &publisher_reports, &format!("sent {MESSAGES}"));
    serve_until_report(
        &mut driver,
        &subscriber_reports,
        &format!("received {MESSAGES} in order"),
    );
    serve_until(&mut driver, |driver| driver.clients() == 0);
    release(&mut subscriber.0);
    release(&mut publisher.0);
    assert!(subscriber.0.wait().unwrap().success());
    assert!(publisher.0.wait().unwrap().success());
    assert_eq!(counter(&driver, "grants exported"), 2);
    assert_eq!(counter(&driver, "grants detached"), 2);
}

/// A subscriber process killed while it holds its cell: the exit proof
/// ends its registration and frees the cell, and a new subscriber takes
/// its place.
#[test]
fn test_ipc_data_a_killed_subscriber_is_released_and_replaced() {
    let dir = dir("killed-subscriber");
    let mut driver = driver(&dir);
    let _stream = add_stream(&mut driver);
    let (mut first, reports) = spawn("subscribe-then-wait", &dir);
    serve_until_report(&mut driver, &reports, "subscribed");
    assert_eq!(counter(&driver, "grants ended"), 0);
    first.0.kill().unwrap();
    serve_until(&mut driver, |driver| driver.clients() == 0);
    let _ = first.0.wait();
    assert_eq!(counter(&driver, "grants ended"), 1);
    let (mut second, reports) = spawn("subscribe-then-leave", &dir);
    serve_until_report(&mut driver, &reports, "subscribed");
    serve_until(&mut driver, |driver| driver.clients() == 0);
    release(&mut second.0);
    assert!(second.0.wait().unwrap().success());
}

/// Many fetch, adopt and detach rounds leave the driver's descriptor count
/// where it started. The driver runs in a child process of its own, which
/// spawns the clients, so no other test's descriptors are counted.
#[test]
fn test_ipc_data_descriptor_counts_are_stable_over_many_grants() {
    let dir = dir("descriptors");
    let (mut child, reports) = spawn("descriptor-driver", &dir);
    let report = reports.recv_timeout(Duration::from_secs(60)).unwrap();
    assert_eq!(report, "descriptors stable");
    assert!(child.0.wait().unwrap().success());
}

/// The driver side of the descriptor test, in its own process.
fn descriptor_driver(dir: &Path) {
    let mut driver = driver(dir);
    let _stream = add_stream(&mut driver);
    // Warm up: the first client creates what the driver keeps.
    let (mut warm, reports) = spawn("subscribe-then-leave", dir);
    serve_until_report(&mut driver, &reports, "subscribed");
    serve_until(&mut driver, |driver| driver.clients() == 0);
    release(&mut warm.0);
    assert!(warm.0.wait().unwrap().success());
    // Its stdout reader thread closes the pipe at EOF, asynchronously; the
    // thread drops its sender only after the pipe, so a disconnected
    // channel proves the pipe is closed before the count.
    while reports.recv().is_ok() {}
    let before = open_descriptors();
    let (mut client, reports) = spawn("subscribe-many", dir);
    serve_until_report(&mut driver, &reports, "rounds done");
    serve_until(&mut driver, |driver| driver.clients() == 0);
    release(&mut client.0);
    assert!(client.0.wait().unwrap().success());
    // The reader thread of the client's stdout closes its pipe once it
    // sees the end: let it finish.
    let start = Instant::now();
    let mut after = open_descriptors();
    while after != before && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
        after = open_descriptors();
    }
    if after != before || counter(&driver, "grants detached") != 1 + ROUNDS {
        report(&format!(
            "descriptors before {before} after {after}, detached {}, ended {}, exported {}, faulty {}, timed out {}",
            counter(&driver, "grants detached"),
            counter(&driver, "grants ended"),
            counter(&driver, "grants exported"),
            counter(&driver, "clients faulty"),
            counter(&driver, "clients timed out"),
        ));
        return;
    }
    report("descriptors stable");
}

/// Polls an in-process subscription until `want` messages or an abort
/// arrive; returns the payloads and whether an aborted block was skipped.
fn read_local(
    driver: &mut IpcDriver,
    subscription: &mut karyos_client::ClientSubscription<SharedTerms>,
    want: usize,
) -> (Vec<Vec<u8>>, bool) {
    let mut received = Vec::new();
    let mut aborted = false;
    let start = Instant::now();
    while received.len() < want {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "read {received:?}"
        );
        let _ = driver.do_work().unwrap();
        let summary = subscription
            .poll(
                |payload, _| received.push(payload.to_vec()),
                MessageLimit::new(32),
            )
            .unwrap();
        aborted |= summary.aborted.is_some();
        std::thread::yield_now();
    }
    (received, aborted)
}

/// An exclusive publisher process killed with a claim open: its exit
/// proof ends its registration at once, aborting the claimed block, so
/// readers skip it; the publication is released for good.
#[test]
fn test_ipc_data_an_exclusive_publisher_killed_mid_claim_is_resolved_at_its_exit() {
    let dir = dir("killed-claim");
    let mut driver = driver(&dir);
    let stream = add_stream(&mut driver);
    let mut subscription = driver
        .subscribe(stream, karyos_sys::log_buffer::Role::Required)
        .unwrap();
    let (mut child, reports) = spawn("publish-then-claim", &dir);
    serve_until_report(&mut driver, &reports, "claimed");
    child.0.kill().unwrap();
    serve_until(&mut driver, |driver| driver.clients() == 0);
    let _ = child.0.wait();
    assert_eq!(counter(&driver, "grants ended"), 1);
    let (received, mut aborted) = read_local(&mut driver, &mut subscription, 1);
    assert_eq!(received, vec![b"before".to_vec()]);
    // The claimed block was aborted: the reader moves past it (maybe in
    // the same poll that delivered the message).
    let start = Instant::now();
    while !aborted {
        assert!(start.elapsed() < Duration::from_secs(10), "never aborted");
        let _ = driver.do_work().unwrap();
        aborted = subscription
            .poll(|_, _| {}, MessageLimit::new(8))
            .unwrap()
            .aborted
            .is_some();
    }
    assert!(driver.publication(stream).is_err());
}

/// SPEC.md §13 "Commit versus abort", forgotten claim in a live process:
/// a publisher process forgets a claim (never commits, aborts or drops it)
/// and stays alive. Its next call aborts the forgotten claim first and only
/// then reserves: readers get the message before the claim, the aborted
/// block and the message after it, in order, and the client is neither
/// faulted nor released until it leaves.
#[test]
fn test_ipc_data_a_live_publisher_that_forgets_a_claim_aborts_it_at_its_next_call() {
    let dir = dir("forgotten-live");
    let mut driver = driver(&dir);
    let stream = add_stream(&mut driver);
    let mut subscription = driver
        .subscribe(stream, karyos_sys::log_buffer::Role::Required)
        .unwrap();
    let (mut child, reports) = spawn("forget-claim-then-offer", &dir);
    serve_until_report(&mut driver, &reports, "after accepted");
    // The process is alive and still attached: nothing ended its grant.
    assert_eq!(driver.clients(), 1);
    assert_eq!(counter(&driver, "grants ended"), 0);
    let (received, aborted) = read_local(&mut driver, &mut subscription, 2);
    assert_eq!(received, vec![b"before".to_vec(), b"after".to_vec()]);
    assert!(aborted, "the forgotten claim was not aborted");
    release(&mut child.0);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert!(child.0.wait().unwrap().success());
    assert_eq!(counter(&driver, "clients faulty"), 0);
}

/// SPEC.md §15 phase 1 gate, process crash and restart with a claim open:
/// the only publisher slot of a concurrent stream belongs to a process
/// that is killed with a claim open. A restarted publisher process
/// attaches as a new client and gets that slot back once the dead block is
/// resolved; readers get the dead writer's message, its aborted block and
/// then the restarted writer's message, in order.
#[test]
fn test_ipc_data_a_publisher_restarted_after_a_crash_with_a_claim_open_takes_over() {
    let dir = dir("restart-claim");
    let mut driver = driver(&dir);
    let stream = add_stream_with(
        &mut driver,
        PublicationMode::Concurrent {
            publishers: 1,
            allow_non_lse: true,
        },
        // 100 ms of the system clock.
        100_000_000,
    );
    let mut subscription = driver
        .subscribe(stream, karyos_sys::log_buffer::Role::Required)
        .unwrap();
    let (mut crashed, reports) = spawn("concurrent-offer-then-claim", &dir);
    serve_until_report(&mut driver, &reports, "claimed");
    crashed.0.kill().unwrap();
    serve_until(&mut driver, |driver| driver.clients() == 0);
    let _ = crashed.0.wait();
    let (mut restarted, reports) = spawn("concurrent-restart", &dir);
    // The restarted client may be refused while the dead block is still
    // unresolved; it retries until the slot is released to it.
    let start = Instant::now();
    let granted = loop {
        assert!(start.elapsed() < Duration::from_secs(10), "never granted");
        let _ = driver.do_work().unwrap();
        if let Ok(report) = reports.try_recv() {
            break report;
        }
    };
    assert!(granted.starts_with("granted after "), "{granted}");
    serve_until_report(&mut driver, &reports, "restarted accepted");
    let (received, aborted) = read_local(&mut driver, &mut subscription, 2);
    assert_eq!(
        received,
        vec![b"before the crash".to_vec(), b"after the restart".to_vec()]
    );
    assert!(aborted, "the dead block was not aborted");
    release(&mut restarted.0);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert!(restarted.0.wait().unwrap().success());
}

/// An exclusive writer process stopped (SIGSTOP) with a claim open
/// (`quantstratum-docs: karyos/design/ipc-data-path.md`, Tests): readers are
/// not blocked beyond the commit deadline, which aborts the claim, and
/// after SIGCONT the writer's commit reports the abort.
#[test]
fn test_ipc_data_a_stopped_writer_holding_a_claim_is_aborted_at_the_deadline() {
    let dir = dir("stopped-claim");
    let mut driver = driver(&dir);
    // 100 ms of the system clock.
    let stream = add_stream_with(&mut driver, PublicationMode::Exclusive, 100_000_000);
    let mut subscription = driver
        .subscribe(stream, karyos_sys::log_buffer::Role::Required)
        .unwrap();
    let (mut child, reports) = spawn("claim-wait-commit", &dir);
    serve_until_report(&mut driver, &reports, "claimed");
    signal(&child.0, "STOP");
    // The reader gets the message before the claim, then the claimed block
    // aborted by the deadline, while the writer stays stopped.
    let (received, mut aborted) = read_local(&mut driver, &mut subscription, 1);
    assert_eq!(received, vec![b"before".to_vec()]);
    let start = Instant::now();
    while !aborted {
        assert!(start.elapsed() < Duration::from_secs(10), "never aborted");
        let _ = driver.do_work().unwrap();
        aborted = subscription
            .poll(|_, _| {}, MessageLimit::new(8))
            .unwrap()
            .aborted
            .is_some();
    }
    signal(&child.0, "CONT");
    release(&mut child.0);
    serve_until_report(&mut driver, &reports, "commit aborted");
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert!(child.0.wait().unwrap().success());
}

/// Runs duty cycles and polls `subscription` until it reports nothing new
/// for a while; returns the messages and whether an aborted block was
/// reported. Every duty cycle must succeed.
fn drain_local(
    driver: &mut IpcDriver,
    subscription: &mut karyos_client::ClientSubscription<SharedTerms>,
) -> (Vec<Vec<u8>>, bool) {
    let mut received = Vec::new();
    let mut aborted = false;
    let mut quiet = 0;
    let start = Instant::now();
    while quiet < 200 {
        assert!(start.elapsed() < Duration::from_secs(10), "never quiet");
        let _ = driver.do_work().unwrap();
        let summary = subscription
            .poll(
                |payload, _| received.push(payload.to_vec()),
                MessageLimit::new(32),
            )
            .unwrap();
        aborted |= summary.aborted.is_some();
        if summary.delivered == 0 && summary.aborted.is_none() {
            quiet += 1;
        } else {
            quiet = 0;
        }
        std::thread::yield_now();
    }
    (received, aborted)
}

/// An exclusive publisher process killed at `scenario`'s pause point: its
/// exit proof ends its registration at once and the publication is never
/// issued again; returns what a local reader then drains.
fn kill_paused_writer(name: &str, scenario: &str) -> (Vec<Vec<u8>>, bool) {
    let dir = dir(name);
    let mut driver = driver(&dir);
    let stream = add_stream(&mut driver);
    let mut subscription = driver
        .subscribe(stream, karyos_sys::log_buffer::Role::Required)
        .unwrap();
    let (mut child, reports) = spawn(scenario, &dir);
    // The required reader keeps reading while the writer runs to its
    // pause, so it is never back-pressured short of it.
    let mut received = Vec::new();
    let mut aborted = false;
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(10), "never paused");
        let _ = driver.do_work().unwrap();
        let summary = subscription
            .poll(
                |payload, _| received.push(payload.to_vec()),
                MessageLimit::new(32),
            )
            .unwrap();
        aborted |= summary.aborted.is_some();
        if let Ok(report) = reports.try_recv() {
            assert_eq!(report, "paused");
            break;
        }
        std::thread::yield_now();
    }
    child.0.kill().unwrap();
    serve_until(&mut driver, |driver| driver.clients() == 0);
    let _ = child.0.wait();
    assert_eq!(counter(&driver, "grants ended"), 1);
    let (rest, rest_aborted) = drain_local(&mut driver, &mut subscription);
    received.extend(rest);
    assert!(driver.publication(stream).is_err());
    (received, aborted || rest_aborted)
}

/// Killed after reserving a block and before writing any of it
/// (`quantstratum-docs: karyos/design/ipc-data-path.md`, Tests, d4): the
/// exit proof aborts exactly the reserved block; the reader gets every
/// message before it and then skips it.
#[test]
fn test_ipc_data_an_exclusive_publisher_killed_mid_offer_is_aborted_at_its_exit() {
    let (received, aborted) = kill_paused_writer("killed-mid-offer", "kill-at-reserved");
    assert_eq!(received, vec![b"before".to_vec()]);
    assert!(aborted, "the reserved block was not aborted");
}

/// Killed while updating its claim record, its serial odd: the exit proof
/// invalidates the torn record without reading it, nothing was reserved,
/// so nothing is aborted, and every later duty cycle succeeds.
#[test]
fn test_ipc_data_an_exclusive_publisher_killed_mid_record_update_leaves_no_torn_state() {
    let (received, aborted) = kill_paused_writer("killed-mid-record", "kill-at-record");
    assert_eq!(received, vec![b"before".to_vec()]);
    assert!(!aborted, "a block was aborted with nothing reserved");
}

/// Killed after reserving the rest of its term and before writing the
/// `PAD`: the exit proof closes the range as `PAD`, so the reader gets
/// every message and crosses into the next term with nothing aborted.
#[test]
fn test_ipc_data_an_exclusive_publisher_killed_across_the_term_end_is_padded() {
    let (received, aborted) = kill_paused_writer("killed-term-end", "kill-at-term-end");
    assert!(received.len() > 1, "{}", received.len());
    for (index, message) in received.iter().enumerate() {
        assert_eq!(
            message.as_slice(),
            filler(index).as_slice(),
            "message {index}"
        );
    }
    assert!(!aborted, "the padded range was reported aborted");
}

/// The messages of the term-end scenario: large enough that a term holds
/// only a few dozen.
fn filler(index: usize) -> Vec<u8> {
    vec![index as u8; 1500]
}

/// Reports the pause and waits to be killed.
fn pause_here(_: karyos_sys::test_pause::PausePoint) {
    report("paused");
    std::thread::sleep(Duration::from_secs(30));
    std::process::exit(1);
}

/// A concurrent publisher process killed with an open block while an
/// in-process publisher keeps writing in the same term: the live
/// publisher's messages are never aborted, the dead block is aborted by
/// the commit deadline, and then the dead publisher's slot is free again.
#[test]
fn test_ipc_data_a_concurrent_publisher_killed_with_an_open_block_waits_for_the_deadline() {
    let dir = dir("killed-concurrent");
    let mut driver = driver(&dir);
    let stream = add_stream_with(
        &mut driver,
        PublicationMode::Concurrent {
            publishers: 2,
            allow_non_lse: true,
        },
        // 100 ms of the system clock.
        100_000_000,
    );
    let mut subscription = driver
        .subscribe(stream, karyos_sys::log_buffer::Role::Required)
        .unwrap();
    let (mut child, reports) = spawn("concurrent-claim", &dir);
    serve_until_report(&mut driver, &reports, "claimed");
    let mut live = driver.concurrent_publication(stream).unwrap();
    for index in 0u8..4 {
        let start = Instant::now();
        while !matches!(
            live.offer(&[index; 24]).unwrap(),
            karyos_client::ConcurrentOfferOutcome::Accepted { .. }
        ) {
            assert!(start.elapsed() < Duration::from_secs(10), "live offer");
            let _ = driver.do_work().unwrap();
        }
    }
    child.0.kill().unwrap();
    serve_until(&mut driver, |driver| driver.clients() == 0);
    let _ = child.0.wait();
    // The deadline aborts the dead block; every live message arrives.
    let (received, aborted) = read_local(&mut driver, &mut subscription, 4);
    assert!(aborted, "the dead block was not aborted");
    let expected: Vec<Vec<u8>> = (0u8..4).map(|index| vec![index; 24]).collect();
    assert_eq!(received, expected);
    // Its slot is released after the deadline: a second handle can be
    // issued beside the live one.
    let start = Instant::now();
    let second = loop {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "slot never freed"
        );
        let _ = driver.do_work().unwrap();
        if let Ok(handle) = driver.concurrent_publication(stream) {
            break handle;
        }
    };
    drop(second);
    drop(live);
}

/// A required subscriber process stopped with SIGSTOP keeps its position:
/// an in-process publisher is back-pressured instead of overrunning it;
/// after SIGCONT the subscriber reads and leaves.
#[test]
fn test_ipc_data_a_stopped_required_subscriber_back_pressures_the_publisher() {
    let dir = dir("stopped-subscriber");
    let mut driver = driver(&dir);
    let stream = add_stream(&mut driver);
    let (mut child, reports) = spawn("subscribe-stop-read", &dir);
    serve_until_report(&mut driver, &reports, "subscribed");
    signal(&child.0, "STOP");
    let mut publication = driver.publication(stream).unwrap();
    let payload = [7u8; 1000];
    let mut accepted = 0u32;
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "never back-pressured"
        );
        let _ = driver.do_work().unwrap();
        match publication.offer(&payload).unwrap() {
            OfferOutcome::Accepted { .. } => accepted += 1,
            OfferOutcome::BackPressured => break,
            _ => {}
        }
    }
    assert!(accepted > 0);
    signal(&child.0, "CONT");
    release(&mut child.0);
    serve_until_report(&mut driver, &reports, "read some");
    serve_until(&mut driver, |driver| driver.clients() == 0);
    release(&mut child.0);
    assert!(child.0.wait().unwrap().success());
}

/// How a stopped required subscriber's test ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// SIGCONT: the resumed client finds itself revoked and disconnected.
    Resumed,
    /// SIGKILL: the exit proof frees its cell.
    Killed,
}

/// p4c (`quantstratum-docs: karyos/design/required-participant-loss.md`,
/// Cross-process): a required subscriber process stopped with SIGSTOP
/// until the driver times its client out, under `policy`, then resumed or
/// killed.
fn stopped_required_subscriber(policy: LossPolicy, ending: Ending) {
    let name = format!("stopped-{policy:?}-{ending:?}").to_lowercase();
    let dir = dir(&name);
    // A short liveness timeout of the system clock: ten driver heartbeat
    // intervals of 50 ms, beyond the client's 100 ms beat.
    let mut driver = driver_with(
        &dir,
        DriverConfig {
            heartbeat_interval: 50_000_000,
            client_liveness_timeout: 500_000_000,
            ..DriverConfig::default()
        },
    );
    let stream = add_stream_with_policy(&mut driver, policy);
    let (mut child, reports) = spawn("subscribe-until-revoked", &dir);
    serve_until_report(&mut driver, &reports, "subscribed");
    signal(&child.0, "STOP");
    serve_until(&mut driver, |driver| {
        counter(driver, "clients timed out") == 1
    });
    assert_eq!(counter(&driver, "required participants lost"), 1);
    match policy {
        // The bound may wait for a loan the stopped reader holds; the loss
        // itself is enough here.
        LossPolicy::Hold => {}
        // The bound is withdrawn at once: the writer is never held back.
        LossPolicy::Continue => {
            let mut publication = driver.publication(stream).unwrap();
            let payload = [9u8; 1000];
            let mut accepted = 0u32;
            let start = Instant::now();
            while accepted < 500 {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "held at {accepted}"
                );
                let _ = driver.do_work().unwrap();
                if let OfferOutcome::Accepted { .. } = publication.offer(&payload).unwrap() {
                    accepted += 1;
                }
            }
        }
        LossPolicy::Abort => {
            assert_ne!(driver.seal_state(stream).unwrap(), SealState::Active);
        }
    }
    match ending {
        Ending::Resumed => {
            signal(&child.0, "CONT");
            serve_until_report(&mut driver, &reports, "revoked and disconnected");
            assert!(child.0.wait().unwrap().success());
        }
        Ending::Killed => {
            child.0.kill().unwrap();
            let _ = child.0.wait();
            serve_until(&mut driver, |driver| driver.clients() == 0);
            // The exit proof ended its grant and freed its cell.
            assert_eq!(counter(&driver, "grants ended"), 1);
        }
    }
}

#[test]
fn test_ipc_loss_a_stopped_required_subscriber_under_hold() {
    stopped_required_subscriber(LossPolicy::Hold, Ending::Resumed);
    stopped_required_subscriber(LossPolicy::Hold, Ending::Killed);
}

#[test]
fn test_ipc_loss_a_stopped_required_subscriber_under_continue() {
    stopped_required_subscriber(LossPolicy::Continue, Ending::Resumed);
    stopped_required_subscriber(LossPolicy::Continue, Ending::Killed);
}

#[test]
fn test_ipc_loss_a_stopped_required_subscriber_under_abort() {
    stopped_required_subscriber(LossPolicy::Abort, Ending::Resumed);
    stopped_required_subscriber(LossPolicy::Abort, Ending::Killed);
}

fn add_stream_with_policy(driver: &mut IpcDriver, policy: LossPolicy) -> StreamHandle {
    driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: KEY.session_id,
                stream_id: KEY.stream_id,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: policy,
            conflation: None,
        })
        .unwrap()
}

/// The driver is dropped while a remote subscription is mapped: the
/// client's mapping stays readable and its handle drops without blocking
/// past the timeout; it then attaches to the new driver instance.
#[test]
fn test_ipc_data_a_driver_restart_leaves_a_remote_mapping_readable() {
    let dir = dir("restart-data");
    let mut first = driver(&dir);
    let _stream = add_stream(&mut first);
    let (mut child, reports) = spawn("subscribe-across-restart", &dir);
    serve_until_report(&mut first, &reports, "subscribed");
    drop(first);
    let mut second = driver(&dir);
    release(&mut child.0);
    serve_until_report(&mut second, &reports, "mapping readable");
    serve_until_report(&mut second, &reports, "reattached");
    serve_until(&mut second, |driver| driver.clients() == 0);
    assert!(child.0.wait().unwrap().success());
}

/// Fetch, adopt and detach rounds of the descriptor test.
const ROUNDS: u64 = 50;

/// §13 "Shared-memory lifecycle", process kill: a remote client that has
/// served a command round trip is killed with SIGKILL; the driver releases
/// its slot through the exit proof, without any `Leave`.
#[test]
fn test_ipc_client_killed_is_released_by_its_exit_proof() {
    let dir = dir("kill");
    let mut driver = driver(&dir);
    let (mut child, reports) = spawn("round-trip-then-wait", &dir);
    serve_until_report(&mut driver, &reports, "refused unknown stream");
    assert_eq!(driver.clients(), 1);
    child.0.kill().unwrap();
    serve_until(&mut driver, |driver| driver.clients() == 0);
    let _ = child.0.wait().unwrap();
}

/// A remote client stopped with SIGSTOP stays admitted (a paused process
/// is not an exited one) and, after SIGCONT, completes another round trip
/// and leaves.
#[test]
fn test_ipc_client_stopped_keeps_its_slot_and_resumes() {
    let dir = dir("stop");
    let mut driver = driver(&dir);
    let (mut child, reports) = spawn("round-trip-wait-round-trip", &dir);
    serve_until_report(&mut driver, &reports, "refused unknown stream");
    signal(&child.0, "STOP");
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(300) {
        let _ = driver.do_work().unwrap();
        assert_eq!(driver.clients(), 1, "a stopped client was released");
    }
    signal(&child.0, "CONT");
    release(&mut child.0);
    serve_until_report(&mut driver, &reports, "refused unknown stream");
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert!(child.0.wait().unwrap().success());
}

/// A driver restart while a client is attached: the client's mapping of
/// the old instance's counters stays readable with the values the old
/// driver last wrote, and the client attaches to the new driver, which has
/// a new instance id.
#[test]
fn test_ipc_driver_restart_new_instance_old_mappings_stay() {
    let dir = dir("restart");
    let mut first = driver(&dir);
    let (mut child, reports) = spawn("restart", &dir);
    serve_until_report(&mut first, &reports, "refused unknown stream");
    serve_until_report(&mut first, &reports, "attached");
    let old = first.instance().unwrap();
    drop(first);
    let mut second = driver(&dir);
    let new = second.instance().unwrap();
    assert_ne!(old, new);
    release(&mut child.0);
    serve_until_report(&mut second, &reports, "old mappings readable");
    serve_until_report(&mut second, &reports, &format!("reattached {new:x}"));
    serve_until(&mut second, |driver| driver.clients() == 0);
    assert!(child.0.wait().unwrap().success());
}

// ---- the child side ----

fn report(line: &str) {
    // A newline first: libtest may have started a line without ending it.
    let mut stdout = std::io::stdout();
    writeln!(stdout, "\nchild: {line}").unwrap();
    stdout.flush().unwrap();
}

fn wait_for_go() {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
}

/// One command round trip: an unknown stream is refused.
fn round_trip(client: &mut RemoteClient) {
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
        assert!(start.elapsed() < Duration::from_secs(10), "no response");
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        std::thread::yield_now();
    }
    assert_eq!(done[0].sequence, sequence);
    assert!(matches!(
        done[0].outcome,
        Outcome::Refused {
            code: ErrorCode::UnknownStream,
            ..
        }
    ));
    report("refused unknown stream");
}

/// Requests `request` and waits for its fetchable grant.
fn grant(client: &mut RemoteClient, subscribe: bool) -> Fetchable {
    if subscribe {
        let _ = client
            .add_subscription(KEY, SubscriberRole::Required)
            .unwrap();
    } else {
        let _ = client.add_publication(KEY, false).unwrap();
    }
    let mut fetchable = None;
    let start = Instant::now();
    while fetchable.is_none() {
        assert!(start.elapsed() < Duration::from_secs(10), "no grant");
        let _ = client.poll(usize::MAX, |completion| match completion.outcome {
            Outcome::Fetchable(grant) => fetchable = Some(grant),
            other => panic!("expected a grant, got {other:?}"),
        });
        std::thread::yield_now();
    }
    fetchable.unwrap()
}

/// The conflated stream of the view test: keys 0 to 3.
const TABLE: karyos_sys::conflation::ConflationConfig = karyos_sys::conflation::ConflationConfig {
    keys: 4,
    value_capacity: 8,
    journal_capacity: 1024,
};
/// Rounds of updates to every key.
const VIEW_ROUNDS: u8 = 50;

/// A remote view of a conflated stream's table in another process
/// (`quantstratum-docs: karyos/design/conflation-end-to-end.md`,
/// Cross-process views, Tests): the child maps the table read-only, sees
/// the latest value of every key with versions never going backwards, and
/// `closed` once the stream is removed; its reader-side counts reach the
/// client counter cells it allocated, which the driver reads; the view's
/// drop detaches its grant.
#[test]
fn test_conflated_a_view_in_another_process_reads_the_latest_values() {
    let dir = dir("conflated-view");
    let mut driver = driver(&dir);
    let stream = driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: KEY.session_id,
                stream_id: KEY.stream_id,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: false,
            on_required_loss: LossPolicy::Hold,
            conflation: Some(TABLE),
        })
        .unwrap();
    let (mut child, reports) = spawn("conflated-view", &dir);
    let cells = serve_until_prefix(&mut driver, &reports, "viewing cells ");
    let cells: Vec<usize> = cells.split(' ').map(|cell| cell.parse().unwrap()).collect();
    let mut publication = driver.publication(stream).unwrap();
    for round in 0..VIEW_ROUNDS {
        for key in 0..4u8 {
            let options = karyos_sys::log_buffer::AppendOptions {
                reserved_value: i64::from(key),
                ..karyos_sys::log_buffer::AppendOptions::default()
            };
            let value = [key, round];
            let start = Instant::now();
            while !matches!(
                publication.offer_with(&value, options).unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                assert!(start.elapsed() < Duration::from_secs(10), "never accepted");
                let _ = driver.do_work().unwrap();
            }
        }
        let _ = driver.do_work().unwrap();
    }
    serve_until_report(&mut driver, &reports, "latest");
    drop(publication);
    driver.remove_stream(stream).unwrap();
    serve_until_report(&mut driver, &reports, "closed");
    // The child's reader counts reached its cells: a one-key budget runs
    // out while the view catches up.
    let reader = driver.client_counters();
    let value = |cell: usize, label: &str| match reader.read(cell) {
        CellRead::Allocated {
            metadata, value, ..
        } => {
            assert_eq!(metadata.label(), label.as_bytes());
            value
        }
        other => panic!("{other:?}"),
    };
    assert!(value(cells[1], karyos_client::CONFLATION_BUDGETS_EXHAUSTED) > 0);
    let _ = value(cells[0], karyos_client::CONFLATION_SKIPS);
    release(&mut child.0);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    release(&mut child.0);
    assert!(child.0.wait().unwrap().success());
    assert_eq!(counter(&driver, "grants exported"), 1);
    assert_eq!(counter(&driver, "grants detached"), 1);
}

/// Runs duty cycles until the child reports a line that starts with
/// `prefix`; returns the rest of it.
fn serve_until_prefix(driver: &mut IpcDriver, reports: &Receiver<String>, prefix: &str) -> String {
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no report {prefix}"
        );
        let _ = driver.do_work().unwrap();
        if let Ok(report) = reports.try_recv() {
            return report.strip_prefix(prefix).unwrap().to_string();
        }
        std::thread::yield_now();
    }
}

/// The child of the conflated view test.
fn conflated_view(dir: &Path, timeout: Duration) {
    use karyos_client::ipc::ConflatedLimits;
    use karyos_client::{CONFLATION_BUDGETS_EXHAUSTED, CONFLATION_SKIPS, ClientCounterHandle};
    let mut client = attach(dir, timeout, 16).unwrap();
    let next = |client: &mut RemoteClient| -> Outcome {
        let mut outcome = None;
        let start = Instant::now();
        while outcome.is_none() {
            assert!(start.elapsed() < Duration::from_secs(10), "no completion");
            let _ = client.poll(usize::MAX, |completion| outcome = Some(completion.outcome));
            std::thread::yield_now();
        }
        outcome.unwrap()
    };
    let allocate = |client: &mut RemoteClient, label: &str| -> ClientCounterHandle {
        let _ = client
            .allocate_counter(karyos_driver::counters::TYPE_EVENTS, label, 0, 0)
            .unwrap();
        let Outcome::Counter(handle) = next(client) else {
            panic!("no counter");
        };
        handle
    };
    let skips = allocate(&mut client, CONFLATION_SKIPS);
    let exhausted = allocate(&mut client, CONFLATION_BUDGETS_EXHAUSTED);
    let cells = format!("{} {}", skips.cell(), exhausted.cell());
    let _ = client.add_conflated_subscription(KEY).unwrap();
    let Outcome::FetchableConflated(fetchable) = next(&mut client) else {
        panic!("no view");
    };
    let budget = karyos_sys::conflation::Budget {
        keys: 1,
        retries: 1,
    };
    let mut view = client
        .take_conflated(&fetchable, budget, ConflatedLimits::default())
        .unwrap()
        .with_counters(skips, exhausted);
    report(&format!("viewing cells {cells}"));
    let mut versions = [0u64; 4];
    let mut values = [[0u8; 2]; 4];
    let last = VIEW_ROUNDS - 1;
    let start = Instant::now();
    while values.iter().any(|value| value[1] != last) {
        assert!(start.elapsed() < Duration::from_secs(20), "saw {values:?}");
        let _ = view.poll_changed_with(budget, |key, found| {
            let (version, value) = (found.version(), found.payload());
            let key = key as usize;
            assert!(version > versions[key], "key {key} went back");
            versions[key] = version;
            values[key].copy_from_slice(value);
        });
        std::thread::yield_now();
    }
    for (key, value) in values.iter().enumerate() {
        assert_eq!(usize::from(value[0]), key);
    }
    report("latest");
    let start = Instant::now();
    while !view.poll_changed(|_, _| {}).unwrap().closed {
        assert!(start.elapsed() < Duration::from_secs(10), "never closed");
        std::thread::yield_now();
    }
    report("closed");
    // The parent reads the counter cells before the drops below release
    // them.
    wait_for_go();
    drop(view);
    drop(client);
    wait_for_go();
}

/// Runs only as a child process of the tests above.
#[test]
fn child() {
    let (Some(scenario), Some(dir)) = (std::env::var_os(SCENARIO), std::env::var_os(DIR)) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let timeout = Duration::from_secs(5);
    match scenario.to_str().unwrap() {
        "conflated-view" => conflated_view(&dir, timeout),
        "round-trip-then-wait" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            round_trip(&mut client);
            // Wait to be killed; never leaves. A bounded wait, so a failed
            // parent never leaves this process behind.
            std::mem::forget(client);
            std::thread::sleep(Duration::from_secs(30));
            std::process::exit(1);
        }
        "round-trip-wait-round-trip" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            round_trip(&mut client);
            wait_for_go();
            round_trip(&mut client);
            drop(client);
        }
        "restart" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let old = client.instance();
            round_trip(&mut client);
            let read = |client: &RemoteClient| -> Vec<CellRead> {
                (0..client.counter_capacity())
                    .map(|index| client.read_counter(index))
                    .collect()
            };
            let before = read(&client);
            // The old driver counted this client and its command.
            assert!(before.iter().any(|cell| matches!(
                cell,
                CellRead::Allocated { value, .. } if *value > 0
            )));
            report("attached");
            wait_for_go();
            // The old instance's counters region is still mapped after its
            // driver is gone: every counter it had allocated is still there
            // with its label, and no event count went backwards (the old
            // driver may have written more before it was dropped).
            let after = read(&client);
            for (was, is) in before.iter().zip(&after) {
                match (was, is) {
                    (
                        CellRead::Allocated {
                            metadata: m0,
                            value: v0,
                            ..
                        },
                        CellRead::Allocated {
                            metadata: m1,
                            value: v1,
                            ..
                        },
                    ) => {
                        assert_eq!(m0.label(), m1.label());
                        assert!(v1 >= v0 || m0.type_id != 1, "{:?} went back", m0.label());
                    }
                    (CellRead::Allocated { .. }, other) => panic!("lost {other:?}"),
                    _ => {}
                }
            }
            report("old mappings readable");
            let again = attach(&dir, timeout, 16).unwrap();
            assert_ne!(again.instance(), old);
            report(&format!("reattached {:x}", again.instance()));
            drop(client);
            drop(again);
        }
        "subscribe" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, true);
            let mut subscription = client.take_subscription(&fetchable).unwrap();
            report("subscribed");
            let mut next = 0u32;
            let start = Instant::now();
            while next < MESSAGES {
                assert!(
                    start.elapsed() < Duration::from_secs(20),
                    "stalled at {next}"
                );
                let _ = subscription
                    .poll(
                        |payload, _| {
                            assert_eq!(payload, next.to_le_bytes().repeat(8).as_slice());
                            next += 1;
                        },
                        MessageLimit::new(32),
                    )
                    .unwrap();
                std::thread::yield_now();
            }
            report(&format!("received {MESSAGES} in order"));
            drop(subscription);
            drop(client);
            // Alive until the driver released this client through its
            // Leave, not through the exit proof.
            wait_for_go();
        }
        "publish" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, false);
            let mut publication = client.take_publication(&fetchable).unwrap();
            let start = Instant::now();
            let mut sent = 0u32;
            while sent < MESSAGES {
                assert!(
                    start.elapsed() < Duration::from_secs(20),
                    "stalled at {sent}"
                );
                match publication.offer(&sent.to_le_bytes().repeat(8)).unwrap() {
                    OfferOutcome::Accepted { .. } => sent += 1,
                    _ => std::thread::yield_now(),
                }
            }
            report(&format!("sent {MESSAGES}"));
            drop(publication);
            drop(client);
            // Alive until the driver released this client through its
            // Leave, not through the exit proof.
            wait_for_go();
        }
        "subscribe-then-wait" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, true);
            let subscription = client.take_subscription(&fetchable).unwrap();
            report("subscribed");
            // Wait to be killed, holding the cell; bounded.
            std::mem::forget(subscription);
            std::mem::forget(client);
            std::thread::sleep(Duration::from_secs(30));
            std::process::exit(1);
        }
        "subscribe-then-leave" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, true);
            let subscription = client.take_subscription(&fetchable).unwrap();
            report("subscribed");
            drop(subscription);
            drop(client);
            // Alive until the driver released this client through its
            // Leave, not through the exit proof.
            wait_for_go();
        }
        "publish-then-claim" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, false);
            let mut publication = client.take_publication(&fetchable).unwrap();
            let start = Instant::now();
            while !matches!(
                publication.offer(b"before").unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                assert!(start.elapsed() < Duration::from_secs(10), "offer");
            }
            let karyos_client::ClaimOutcome::Claimed(claim) = publication.try_claim(64).unwrap()
            else {
                panic!("not claimed");
            };
            // Killed with the block claimed and never committed.
            std::mem::forget(claim);
            report("claimed");
            std::mem::forget(publication);
            std::mem::forget(client);
            std::thread::sleep(Duration::from_secs(30));
            std::process::exit(1);
        }
        "kill-at-reserved" | "kill-at-record" | "kill-at-term-end" => {
            use karyos_sys::test_pause::{PausePoint, arm};
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, false);
            let mut publication = client.take_publication(&fetchable).unwrap();
            let offer = |publication: &mut karyos_client::ClientPublication<SharedTerms>,
                         payload: &[u8]| {
                let start = Instant::now();
                while !matches!(
                    publication.offer(payload).unwrap(),
                    OfferOutcome::Accepted { .. }
                ) {
                    assert!(start.elapsed() < Duration::from_secs(10), "offer");
                }
            };
            match scenario.to_str().unwrap() {
                "kill-at-reserved" => {
                    offer(&mut publication, b"before");
                    arm(PausePoint::ExclusiveReserved, pause_here);
                    offer(&mut publication, b"never written");
                }
                "kill-at-record" => {
                    offer(&mut publication, b"before");
                    arm(PausePoint::ClaimRecordOdd, pause_here);
                    let _ = publication.try_claim(64);
                }
                _ => {
                    arm(PausePoint::TermEndReserved, pause_here);
                    // At most a term's worth: the term end comes first.
                    for index in 0..1000 {
                        offer(&mut publication, &filler(index));
                    }
                }
            }
            panic!("never paused");
        }
        "claim-wait-commit" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, false);
            let mut publication = client.take_publication(&fetchable).unwrap();
            let start = Instant::now();
            while !matches!(
                publication.offer(b"before").unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                assert!(start.elapsed() < Duration::from_secs(10), "offer");
            }
            let karyos_client::ClaimOutcome::Claimed(mut claim) =
                publication.try_claim(64).unwrap()
            else {
                panic!("not claimed");
            };
            claim.payload().fill(0xAB);
            report("claimed");
            // Stopped here by the parent; the deadline aborts the claim.
            wait_for_go();
            match claim.commit() {
                karyos_client::CommitOutcome::Aborted { .. } => report("commit aborted"),
                karyos_client::CommitOutcome::Accepted { .. } => report("commit accepted"),
            }
            drop(publication);
            drop(client);
        }
        "forget-claim-then-offer" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, false);
            let mut publication = client.take_publication(&fetchable).unwrap();
            let start = Instant::now();
            while !matches!(
                publication.offer(b"before").unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                assert!(start.elapsed() < Duration::from_secs(10), "offer");
            }
            let karyos_client::ClaimOutcome::Claimed(mut claim) =
                publication.try_claim(64).unwrap()
            else {
                panic!("not claimed");
            };
            claim.payload().fill(0xAB);
            // Forgotten: never committed, aborted or dropped.
            std::mem::forget(claim);
            // The next call resolves it, then offers.
            let start = Instant::now();
            while !matches!(
                publication.offer(b"after").unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                assert!(start.elapsed() < Duration::from_secs(10), "offer after");
            }
            report("after accepted");
            wait_for_go();
            drop(publication);
            drop(client);
        }
        "concurrent-offer-then-claim" | "concurrent-restart" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let _ = client.add_concurrent_publication(KEY, true).unwrap();
            let mut fetchable = None;
            let mut refusals = 0u32;
            let start = Instant::now();
            while fetchable.is_none() {
                // The restarted client asks again while the dead writer's
                // slot is not yet resolved, as a restarting process would.
                assert!(start.elapsed() < Duration::from_secs(10), "no grant");
                let mut refused = false;
                let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                    Outcome::Fetchable(grant) => fetchable = Some(grant),
                    Outcome::Refused { .. } if scenario == "concurrent-restart" => refused = true,
                    other => panic!("expected a grant, got {other:?}"),
                });
                if refused {
                    refusals += 1;
                    std::thread::sleep(Duration::from_millis(5));
                    let _ = client.add_concurrent_publication(KEY, true).unwrap();
                }
                std::thread::yield_now();
            }
            if scenario == "concurrent-restart" {
                report(&format!("granted after {refusals} refusals"));
            }
            let mut publication = client
                .take_concurrent_publication(&fetchable.unwrap())
                .unwrap();
            let payload: &[u8] = if scenario == "concurrent-restart" {
                b"after the restart"
            } else {
                b"before the crash"
            };
            let start = Instant::now();
            while !matches!(
                publication.offer(payload).unwrap(),
                karyos_client::ConcurrentOfferOutcome::Accepted { .. }
            ) {
                assert!(start.elapsed() < Duration::from_secs(10), "offer");
            }
            if scenario == "concurrent-restart" {
                report("restarted accepted");
                wait_for_go();
                drop(publication);
                drop(client);
            } else {
                let karyos_client::ConcurrentClaimOutcome::Claimed(claim) =
                    publication.try_claim(64).unwrap()
                else {
                    panic!("not claimed");
                };
                // Killed with the block claimed and never committed.
                std::mem::forget(claim);
                report("claimed");
                std::mem::forget(publication);
                std::mem::forget(client);
                std::thread::sleep(Duration::from_secs(30));
                std::process::exit(1);
            }
        }
        "concurrent-claim" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let _ = client.add_concurrent_publication(KEY, true).unwrap();
            let mut fetchable = None;
            let start = Instant::now();
            while fetchable.is_none() {
                assert!(start.elapsed() < Duration::from_secs(10), "no grant");
                let _ = client.poll(usize::MAX, |completion| {
                    if let Outcome::Fetchable(grant) = completion.outcome {
                        fetchable = Some(grant);
                    }
                });
            }
            let mut publication = client
                .take_concurrent_publication(&fetchable.unwrap())
                .unwrap();
            let karyos_client::ConcurrentClaimOutcome::Claimed(claim) =
                publication.try_claim(64).unwrap()
            else {
                panic!("not claimed");
            };
            std::mem::forget(claim);
            report("claimed");
            std::mem::forget(publication);
            std::mem::forget(client);
            std::thread::sleep(Duration::from_secs(30));
            std::process::exit(1);
        }
        "subscribe-until-revoked" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, true);
            let mut subscription = client.take_subscription(&fetchable).unwrap();
            report("subscribed");
            // Beat and poll until the driver's verdict reaches this
            // process; the parent stops it in between.
            let start = Instant::now();
            loop {
                assert!(start.elapsed() < Duration::from_secs(20), "never revoked");
                let _ = client.poll(usize::MAX, |_| {});
                let summary = match subscription.poll(|_, _| {}, MessageLimit::new(8)) {
                    Ok(summary) => summary,
                    Err(error) => {
                        report(&format!("poll failed: {:?}", error.cause));
                        std::process::exit(2);
                    }
                };
                let ended = if summary.revoked.is_some() {
                    Some("revoked")
                } else {
                    summary.closed.map(|_| "ended")
                };
                if let Some(ended) = ended {
                    // Its ring is closed: no new request gets through.
                    let refused = client.add_subscription(KEY, SubscriberRole::Optional);
                    assert!(
                        matches!(refused, Err(karyos_client::ConductorError::Closed)),
                        "{refused:?}"
                    );
                    report(&format!("{ended} and disconnected"));
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(subscription);
            drop(client);
        }
        "subscribe-stop-read" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, true);
            let mut subscription = client.take_subscription(&fetchable).unwrap();
            report("subscribed");
            // Stopped here by the parent, then released.
            wait_for_go();
            let mut read = 0;
            let start = Instant::now();
            while read == 0 {
                assert!(start.elapsed() < Duration::from_secs(10), "nothing to read");
                let summary = subscription.poll(|_, _| {}, MessageLimit::new(64)).unwrap();
                read += summary.delivered;
            }
            report("read some");
            drop(subscription);
            drop(client);
            wait_for_go();
        }
        "subscribe-across-restart" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let fetchable = grant(&mut client, true);
            let mut subscription = client.take_subscription(&fetchable).unwrap();
            report("subscribed");
            wait_for_go();
            // The driver that exported it is gone: the mapping still reads.
            let _ = subscription.poll(|_, _| {}, MessageLimit::new(8)).unwrap();
            report("mapping readable");
            // Its Detach and Leave go to a closed socket: bounded, no hang.
            drop(subscription);
            drop(client);
            let again = attach(&dir, timeout, 16).unwrap();
            report("reattached");
            drop(again);
        }
        "descriptor-driver" => descriptor_driver(&dir),
        "subscribe-many" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            // Warm up: the first take maps what the client keeps.
            let fetchable = grant(&mut client, true);
            drop(client.take_subscription(&fetchable).unwrap());
            let before = open_descriptors();
            for _ in 1..ROUNDS {
                let fetchable = grant(&mut client, true);
                // Only dropped: the Detach ends the last grant, so the
                // driver reclaims the registration and more rounds than
                // `max_exports_per_client` are admitted.
                drop(client.take_subscription(&fetchable).unwrap());
            }
            // Every received descriptor was closed: the client's count is
            // where it started too.
            let after = open_descriptors();
            if after == before {
                report("rounds done");
            } else {
                report(&format!(
                    "client descriptors before {before}, after {after}"
                ));
            }
            drop(client);
            // Alive until the driver released this client through its
            // Leave, not through the exit proof.
            wait_for_go();
        }
        other => panic!("unknown scenario {other}"),
    }
}
