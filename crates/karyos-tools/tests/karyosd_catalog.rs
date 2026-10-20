// SPDX-License-Identifier: Apache-2.0

//! `karyos-catalog list` against `karyosd --archive` (Linux;
//! quantstratum-docs: karyos/design/archive-host.md, H4 and H4b): the
//! daemon records a stream at boot and a client process (this test)
//! publishes on it.
//!
//! - `list --live` lists the recording over the Archive's control streams,
//!   as text and as JSON; and [`karyos_tools::catalog::list_live`] lists it
//!   more times over one client than the Archive admits requesters at
//!   once: each listing closes its connection.
//! - `list DIR` reads the same catalog offline beside the running Archive.
//! - Once the daemon has stopped, the offline listing shows the recording
//!   stopped, and `--live` cannot reach the Archive (exit status 2).

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use karyos_client::{Client, Context, OfferError, StreamId};

/// The recorded stream: `--stream 2:1`.
const STREAM: i32 = 2;
const SESSION: i32 = 1;
/// The Archive's control streams.
const REQUESTS: i32 = 100;
const RESPONSES: i32 = 101;
/// Messages the client publishes.
const MESSAGES: u32 = 20;
/// Listings run in a row: more than the 7 requesters `karyosd` admits at
/// once (#531), so a listing that held its connection would be refused.
const LISTINGS: usize = 10;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyosd-catalog-{}-{name}", std::process::id()));
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
    /// Starts `karyosd` on `dir`, recording stream 2:1 in `archive`; its log
    /// goes to `log`.
    fn start(dir: &Path, archive: &Path, log: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_karyosd"))
            .arg("--dir")
            .arg(dir)
            .arg("--archive")
            .arg(archive)
            .args([
                "--archive-control",
                &format!("{REQUESTS},{RESPONSES}"),
                "--archive-min-free",
                "0",
                "--stream",
                &format!("{STREAM}:{SESSION}"),
                "--record",
                &format!("{STREAM}:{SESSION}"),
                "--term-length",
                "64k",
                "--shutdown-linger",
                "5s",
                "--log-level",
                "info",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(log).unwrap())
            .spawn()
            .unwrap();
        Self(child)
    }

    /// Sends `SIGTERM` and waits for the exit.
    fn stop(&mut self) -> ExitStatus {
        let status = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "karyosd did not exit"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// A client of the daemon in `dir`, once its socket answers.
fn connect(dir: &Path) -> Client<karyos_client::ipc::RemoteClient> {
    let start = Instant::now();
    loop {
        let context = Context::builder()
            .dir(dir)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        match Client::connect(context) {
            Ok(client) => return client,
            Err(error) => {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "connect: {error}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Runs `karyos-catalog list` with `args`.
fn list(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_karyos-catalog"))
        .arg("list")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn karyos_catalog_lists_a_karyosd_archive_live_and_offline() {
    let dir = dir("list");
    let archive = dir.with_extension("archive");
    let _ = std::fs::remove_dir_all(&archive);
    std::fs::create_dir_all(&archive).unwrap();
    let log = dir.with_extension("log");
    let mut daemon = Daemon::start(&dir, &archive, &log);
    let mut client = connect(&dir);
    let mut publication = client
        .add_exclusive_publication("karyos:ipc", StreamId::new(STREAM))
        .unwrap();
    let (mut sent, start) = (0u32, Instant::now());
    while sent < MESSAGES {
        assert!(start.elapsed() < Duration::from_secs(10), "sent {sent}");
        let _ = client.poll();
        match publication.offer(&sent.to_le_bytes()) {
            Ok(_) => sent += 1,
            Err(OfferError::NotConnected | OfferError::BackPressured | OfferError::AdminAction) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("offer: {error}"),
        }
    }
    let live = format!("{}={REQUESTS},{RESPONSES}", dir.display());
    let recording = format!("1  stream {STREAM}  session {SESSION}  channel ");

    // Live, as text: the one recording, still recording. Listed more
    // times than the Archive admits requesters at once.
    for _ in 0..LISTINGS {
        let output = list(&["--live", &live]);
        let shown = text(&output);
        assert!(
            output.status.success(),
            "{shown}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let lines: Vec<&str> = shown.lines().collect();
        assert_eq!(lines.len(), 2, "{shown}");
        assert!(
            lines[0].starts_with(&format!(
                "1 recording(s) of the Archive on {} (control streams {REQUESTS}, {RESPONSES})",
                dir.display()
            )),
            "{shown}"
        );
        assert!(lines[1].starts_with(&recording), "{shown}");
        assert!(lines[1].contains("  recording, written to "), "{shown}");
    }
    // In one process, over one client, as many listings: each closes its
    // connection, so none is refused for a requester slot it holds.
    let archive_streams = karyos_tools::args::parse_live(&live).unwrap();
    for listing in 0..LISTINGS {
        let listed =
            karyos_tools::catalog::list_live(&mut client, &archive_streams, Duration::from_secs(5))
                .unwrap_or_else(|error| panic!("listing {listing}: {error}"));
        assert_eq!(listed.recordings.len(), 1);
    }
    // Live, as JSON.
    let output = list(&["--live", &live, "--json"]);
    let shown = text(&output);
    assert!(output.status.success(), "{shown}");
    assert!(
        shown.starts_with(&format!(
            "{{\"live\":{{\"dir\":\"{}\",\"requests\":{REQUESTS},\"responses\":{RESPONSES}}},\"left_out\":0,\"recordings\":[{{\"id\":1,\"stream_id\":{STREAM},\"session_id\":{SESSION},",
            dir.display()
        )),
        "{shown}"
    );
    assert!(shown.contains("\"recording\":{\"written\":"), "{shown}");
    assert!(shown.ends_with(",\"stop\":null}]}\n"), "{shown}");

    // Offline, beside the running Archive: the same recording, from its
    // catalog file, read only.
    let offline = archive.display().to_string();
    let output = list(&[&offline]);
    let shown = text(&output);
    assert!(output.status.success(), "{shown}");
    assert!(shown.starts_with("1 recording(s) in "), "{shown}");
    assert!(
        shown.lines().nth(1).unwrap().starts_with(&recording),
        "{shown}"
    );
    assert!(
        shown.lines().nth(1).unwrap().ends_with("  recording"),
        "{shown}"
    );

    // Stopped: the catalog shows the recording stopped, and there is no
    // Archive to ask any more.
    drop(publication);
    drop(client);
    assert!(daemon.stop().success());
    let output = list(&[&offline]);
    let shown = text(&output);
    assert!(output.status.success(), "{shown}");
    assert!(
        shown.lines().nth(1).unwrap().contains("  stopped at "),
        "{shown}"
    );
    let output = list(&["--live", &live, "--timeout-ms", "500"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .starts_with("karyos-catalog: cannot reach the Archive"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&archive);
    let _ = std::fs::remove_file(&log);
}
