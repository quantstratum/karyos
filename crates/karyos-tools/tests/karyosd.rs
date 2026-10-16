// SPDX-License-Identifier: Apache-2.0

//! The `karyosd` binary (Linux; `quantstratum-docs:
//! karyos/design/observability-and-tools.md`, Binaries and its tests): it
//! starts, admits a client process (this test process), and exits 0 on
//! `SIGTERM` after the client leaves and 3 when a client stays attached
//! past the linger; a startup error exits 2. Signals are sent with the
//! system `kill` tool, so the tests need no new dependency.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use karyos_client::Outcome;
use karyos_client::ipc::{RemoteClient, attach};
use karyos_protocol::cnc::StreamKey;

/// The stream `karyosd` configures in these tests.
const KEY: StreamKey = StreamKey {
    stream_id: 2,
    session_id: 1,
};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyosd-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A `karyosd` process, killed when the test ends however it ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    /// Sends `SIGTERM` (no libc: the system `kill` tool).
    fn terminate(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Waits at most `limit` for the exit.
    fn wait(&mut self, limit: Duration) -> ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(start.elapsed() < limit, "karyosd did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Starts `karyosd` on `dir` with one stream and `linger`.
fn start(dir: &Path, linger: &str) -> Daemon {
    let child = Command::new(env!("CARGO_BIN_EXE_karyosd"))
        .arg("--dir")
        .arg(dir)
        .args([
            "--stream",
            &format!("{}:{}", KEY.stream_id, KEY.session_id),
            "--term-length",
            "64k",
            "--shutdown-linger",
            linger,
            "--log-level",
            "warn",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Daemon(child)
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

/// Takes the stream's publication through a grant, so that the stream has
/// a registration and an export to retire, then drops it.
fn publish_once(client: &mut RemoteClient) {
    let _ = client.add_publication(KEY, true).unwrap();
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
    let publication = client.take_publication(&fetchable.unwrap()).unwrap();
    drop(publication);
}

#[test]
fn karyosd_exits_0_on_sigterm_after_the_client_leaves() {
    let dir = dir("clean");
    let mut daemon = start(&dir, "5s");
    let mut client = attach_when_ready(&dir);
    publish_once(&mut client);
    drop(client);
    daemon.terminate();
    let status = daemon.wait(Duration::from_secs(10));
    assert_eq!(status.code(), Some(0), "{status:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn karyosd_exits_3_when_a_client_stays_past_the_linger() {
    let dir = dir("linger");
    let mut daemon = start(&dir, "200ms");
    let mut client = attach_when_ready(&dir);
    publish_once(&mut client);
    daemon.terminate();
    let status = daemon.wait(Duration::from_secs(10));
    assert_eq!(status.code(), Some(3), "{status:?}");
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn karyosd_refuses_new_clients_once_shutting_down() {
    let dir = dir("refuse");
    let mut daemon = start(&dir, "5s");
    let client = attach_when_ready(&dir);
    daemon.terminate();
    // The daemon stays up while the first client is attached; a new
    // client is refused within the linger.
    let start = Instant::now();
    loop {
        match attach(&dir, Duration::from_secs(5), 16) {
            Err(karyos_client::ipc::AttachError::Refused { code }) => {
                assert_eq!(
                    code,
                    karyos_protocol::admission::refusal::SHUTTING_DOWN,
                    "refused for another reason"
                );
                break;
            }
            Ok(late) => drop(late),
            Err(error) => panic!("{error:?}"),
        }
        assert!(start.elapsed() < Duration::from_secs(4), "never refused");
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(client);
    let status = daemon.wait(Duration::from_secs(10));
    assert_eq!(status.code(), Some(0), "{status:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn karyosd_exits_2_on_a_startup_error() {
    // The driver refuses a zero client limit.
    let dir = dir("startup");
    let output = Command::new(env!("CARGO_BIN_EXE_karyosd"))
        .arg("--dir")
        .arg(&dir)
        .args(["--max-clients", "0"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with("karyosd: "), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
