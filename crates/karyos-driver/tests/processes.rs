// SPDX-License-Identifier: Apache-2.0

//! Multi-process tests (IPC batch i4, Linux): clients in separate
//! processes against one driver, over the admission socket and the CnC
//! regions (quantstratum-docs: karyos/`design/ipc-implementation.md`, i4;
//! quantstratum-docs: karyos/`design/ipc-admission.md`). Each child is this test binary run
//! again with `--exact <child test>`; it reports on stdout, one line per
//! step, and the parent runs the driver's duty cycles meanwhile.
//!
//! In the alpha a remote client uses the control channel only (command
//! ring, broadcast buffer, counters); log buffers shared between processes
//! come with i3 step 2.

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
use karyos_client::{Completion, Outcome};
use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, SystemClock};
use karyos_protocol::cnc::{ErrorCode, StreamKey, SubscriberRole};
use karyos_sys::counters::CellRead;
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
    let start = Instant::now();
    loop {
        let created = EmbeddedDriver::with_ipc(
            DriverConfig::default(),
            IpcConfig {
                dir: dir.to_path_buf(),
                max_pending_hellos: 4,
                hello_timeout: 5_000_000_000,
                max_outbound_per_client: 16,
                fetch_deadline: 5_000_000_000,
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

/// Runs only as a child process of the tests above.
#[test]
fn child() {
    let (Some(scenario), Some(dir)) = (std::env::var_os(SCENARIO), std::env::var_os(DIR)) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let timeout = Duration::from_secs(5);
    match scenario.to_str().unwrap() {
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
        other => panic!("unknown scenario {other}"),
    }
}
