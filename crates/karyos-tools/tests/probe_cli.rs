// SPDX-License-Identifier: Apache-2.0

//! `karyos-tools probe` (Linux; R-CORE-35): its line and exit status for a
//! starting and a ready driver, no driver, and a driver that predates
//! probes and closes the connection without an answer.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, SystemClock};
use karyos_sys::term_bytes::SharedTerms;
use karyos_tools::probe::{EXIT_INCOMPATIBLE, EXIT_READY, EXIT_UNREACHABLE, EXIT_WAIT, run};

type IpcDriver = EmbeddedDriver<SharedTerms>;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-probe-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn driver(dir: &Path) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
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
            max_tools: 1,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

/// Runs the command against `dir`, serving `driver` meanwhile when given;
/// its line and status.
fn command(dir: &Path, driver: Option<&mut IpcDriver>) -> (String, u8) {
    let args = ["--dir", dir.to_str().unwrap(), "--timeout", "2000"];
    let invoke = || {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = run(args.iter().map(Into::into), &mut out, &mut err);
        (String::from_utf8(out).unwrap(), status)
    };
    match driver {
        None => invoke(),
        Some(driver) => std::thread::scope(|scope| {
            let handle = scope.spawn(invoke);
            while !handle.is_finished() {
                let _ = driver.do_work().unwrap();
                std::thread::yield_now();
            }
            handle.join().unwrap()
        }),
    }
}

#[test]
fn the_command_exits_by_state() {
    let dir = dir("states");
    let mut driver = driver(&dir);
    assert_eq!(
        command(&dir, Some(&mut driver)),
        ("starting\n".to_owned(), EXIT_WAIT)
    );
    assert!(driver.startup_complete());
    assert_eq!(
        command(&dir, Some(&mut driver)),
        ("ready\n".to_owned(), EXIT_READY)
    );
    drop(driver);
    let (line, status) = command(&dir, None);
    assert_eq!(status, EXIT_UNREACHABLE, "{line}");
    assert!(line.starts_with("unreachable"), "{line}");
}

/// A driver that does not know `ProbeHello` closes the connection without
/// an answer: incompatible, never unreachable or ready.
#[test]
fn a_driver_that_predates_probes_is_incompatible() {
    let dir = dir("old");
    let listener = karyos_sys::ipc::listen(&dir, 4).unwrap();
    let (line, status) = std::thread::scope(|scope| {
        let handle = scope.spawn(|| command(&dir, None));
        // Accept and close, as an older driver does with an unknown first
        // datagram.
        let start = std::time::Instant::now();
        while !handle.is_finished() {
            if let Ok(Some(socket)) = karyos_sys::ipc::accept(listener.as_fd()) {
                // It reads the first datagram, finds no type it knows and
                // drops the connection.
                let mut buffer = [0u8; 64];
                let read = std::time::Instant::now();
                while !matches!(
                    karyos_sys::ipc::recv(socket.as_fd(), &mut buffer),
                    Ok(karyos_sys::ipc::Recv::Message(_))
                ) {
                    assert!(read.elapsed() < Duration::from_secs(5), "no datagram");
                    std::thread::yield_now();
                }
                drop(socket);
            }
            assert!(start.elapsed() < Duration::from_secs(10), "stuck");
            std::thread::yield_now();
        }
        handle.join().unwrap()
    });
    assert_eq!(
        (line.as_str(), status),
        ("incompatible driver\n", EXIT_INCOMPATIBLE)
    );
}
