// SPDX-License-Identifier: Apache-2.0

//! The `karyos-stat` and `karyos-errors` binaries against a running
//! `karyosd` (Linux; `quantstratum-docs:
//! karyos/design/observability-and-tools.md`, Binaries and its tests):
//! `karyos-stat --once` prints the driver counters and the configured
//! stream's positions, `karyos-errors` prints the error record of a refused
//! hello, and both keep running until the driver exits, then exit 0.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use karyos_client::ipc::{AttachError, RemoteClient, attach};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-tools-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A child process, killed when the test ends however it ends.
struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Process {
    /// Waits at most `limit` for the exit.
    fn wait(&mut self, limit: Duration) -> ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(start.elapsed() < limit, "the process did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Sends `SIGTERM` (no libc: the system `kill` tool).
    fn terminate(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }
}

/// Starts `karyosd` on `dir` with stream 2:1 and room for one client.
fn karyosd(dir: &Path) -> Process {
    let child = Command::new(env!("CARGO_BIN_EXE_karyosd"))
        .arg("--dir")
        .arg(dir)
        .args([
            "--stream",
            "2:1",
            "--term-length",
            "64k",
            "--max-clients",
            "1",
            "--shutdown-linger",
            "5s",
            "--log-level",
            "warn",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Process(child)
}

/// Attaches once the daemon's socket answers, within a bounded wait.
fn attach_when_ready(dir: &Path) -> RemoteClient {
    let start = Instant::now();
    loop {
        match attach(dir, Duration::from_secs(5), 16) {
            Ok(client) => return client,
            Err(error) => {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "attach failed: {error:?}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn run(binary: &str, dir: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .arg("--dir")
        .arg(dir)
        .args(args)
        .output()
        .unwrap()
}

fn spawn(binary: &str, dir: &Path, args: &[&str]) -> Process {
    let child = Command::new(binary)
        .arg("--dir")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Process(child)
}

#[test]
fn the_tools_report_a_running_driver_and_exit_with_it() {
    let dir = dir("report");
    let mut daemon = karyosd(&dir);
    let client = attach_when_ready(&dir);
    // The second client is refused (one client at most): an error record.
    assert!(matches!(
        attach(&dir, Duration::from_secs(5), 16),
        Err(AttachError::Refused { .. })
    ));

    // A sampling pass runs every 10 ms: the stream lane appears.
    let start = Instant::now();
    let stat = loop {
        let output = run(env!("CARGO_BIN_EXE_karyos-stat"), &dir, &["--once"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        if text.contains(" lane 0: limit ") {
            break text;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "{text}");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(stat.starts_with("sample: age "), "{stat}");
    assert!(stat.contains("    clients admitted"), "{stat}");
    assert!(
        stat.contains("    streams active                           1"),
        "{stat}"
    );

    let output = run(env!("CARGO_BIN_EXE_karyos-errors"), &dir, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let errors = String::from_utf8(output.stdout).unwrap();
    // HelloRejected is code 2.
    assert!(errors.starts_with("error #0 code 2 "), "{errors}");

    // Both keep running until the driver exits.
    let mut stat = spawn(
        env!("CARGO_BIN_EXE_karyos-stat"),
        &dir,
        &["--interval", "20ms"],
    );
    let mut follow = spawn(
        env!("CARGO_BIN_EXE_karyos-errors"),
        &dir,
        &["--follow", "--interval", "20ms"],
    );
    std::thread::sleep(Duration::from_millis(100));
    drop(client);
    daemon.terminate();
    assert_eq!(daemon.wait(Duration::from_secs(10)).code(), Some(0));
    assert_eq!(stat.wait(Duration::from_secs(5)).code(), Some(0));
    assert_eq!(follow.wait(Duration::from_secs(5)).code(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_tools_exit_2_without_a_driver_or_a_directory() {
    let dir = dir("absent");
    for binary in [
        env!("CARGO_BIN_EXE_karyos-stat"),
        env!("CARGO_BIN_EXE_karyos-errors"),
    ] {
        let output = run(binary, &dir, &[]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let output = Command::new(binary).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("--dir"), "{stderr}");
    }
}
