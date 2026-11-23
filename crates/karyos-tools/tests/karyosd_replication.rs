// SPDX-License-Identifier: Apache-2.0

//! Two `karyosd` processes replicate a recording over a Karyos stream
//! (Linux; quantstratum-docs: karyos/adr/0102-replication-pushed-from-the-source.md
//! Validation; karyos#1113): the source records a stream at boot and
//! pushes it to the replica on a reliable UDP publication; the replica
//! counts each range only after its seal verified on its own bytes, and
//! records it with the profile it arrived under. A restart of the replica
//! receives the recording again from the source's start and changes
//! nothing it already counted.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::copies::{ArrivalProfile, CopyCatalog, CopyState};
use karyos_archive::integrity::journal::IntegrityJournal;
use karyos_client::{Client, Context, OfferError, StreamId};

/// The recorded stream: `--stream 2:1`.
const STREAM: i32 = 2;
const SESSION: i32 = 1;
/// The forwarding stream.
const FORWARD: i32 = 40;
/// The source's first recording.
const RECORDING: u64 = 1;
/// Messages the client publishes.
const MESSAGES: u32 = 200;
/// The replica's copy location.
const LOCATION: &str = "abababababababababababababababababababababababababababababababab";

fn dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("karyosd-replication-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A free loopback UDP port, released for the replica to bind.
fn free_port() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
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
    fn start(dir: &Path, archive: &Path, extra: &[String], log: &Path) -> Self {
        std::fs::create_dir_all(archive).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_karyosd"))
            .arg("--dir")
            .arg(dir)
            .arg("--archive")
            .arg(archive)
            .args([
                "--archive-control",
                "100,101",
                "--archive-anchor-interval",
                "3600s",
                "--archive-min-free",
                "0",
                "--archive-seal-interval",
                "100ms",
                "--term-length",
                "64k",
                "--network",
                "on",
                "--replication-trusted-network",
                "--shutdown-linger",
                "5s",
                "--log-level",
                "info",
            ])
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(log).unwrap())
            .spawn()
            .unwrap();
        Self(child)
    }

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

fn log(path: &Path) -> String {
    let mut text = String::new();
    if let Ok(mut file) = std::fs::File::open(path) {
        let _ = file.read_to_string(&mut text);
    }
    text
}

/// Whether `line` shows `count` times in the log at `path` within 30 s.
fn seen(path: &Path, line: &str, count: usize) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        if log(path).matches(line).count() >= count {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Waits until `line` shows `count` times in the log at `path`; on a
/// timeout, `also` is shown too.
fn wait_for(path: &Path, line: &str, count: usize, what: &str, also: &Path) {
    let start = Instant::now();
    loop {
        let text = log(path);
        if text.matches(line).count() >= count {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{what}: {line:?} not seen {count} times:\n{text}\n--- {}:\n{}",
            also.display(),
            log(also)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The replica's counted ranges of the recording, and their profiles,
/// read once the replica stopped.
fn counted(archive: &Path) -> Vec<(u64, u64, ArrivalProfile)> {
    let dir = archive.join("replicas").join(RECORDING.to_string());
    let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
    let copies = CopyCatalog::open(StdDisk, &dir, &mut journal).unwrap();
    copies
        .current()
        .unwrap()
        .into_iter()
        .filter(|copy| copy.recording == RECORDING && copy.state == CopyState::Verified)
        .map(|copy| (copy.start, copy.end, copy.profile))
        .collect()
}

/// ADR-0102 Validation: a recording replicates between two `karyosd` and
/// counts only after verifying; a restarted replica receives it again
/// from the source's start and its counted ranges stay as they were.
#[test]
fn a_recording_replicates_between_two_daemons_and_counts_only_after_verifying() {
    let (source_dir, replica_dir) = (dir("source"), dir("replica"));
    let (source_archive, replica_archive) = (
        source_dir.with_extension("archive"),
        replica_dir.with_extension("archive"),
    );
    for archive in [&source_archive, &replica_archive] {
        let _ = std::fs::remove_dir_all(archive);
    }
    let (source_log, replica_log) = (
        source_dir.with_extension("log"),
        replica_dir.with_extension("log"),
    );
    let endpoint = free_port();
    let replica_args = vec![
        "--replica".to_owned(),
        format!("{RECORDING},127.0.0.1,{endpoint},{FORWARD}"),
        "--archive-copy-location".to_owned(),
        LOCATION.to_owned(),
    ];
    let mut replica = Daemon::start(&replica_dir, &replica_archive, &replica_args, &replica_log);
    let mut source = Daemon::start(
        &source_dir,
        &source_archive,
        &[
            "--stream".to_owned(),
            format!("{STREAM}:{SESSION}"),
            // Synced every 10 ms: a seal covers only durable bytes.
            "--record".to_owned(),
            format!("{STREAM}:{SESSION}:10ms"),
            "--replicate".to_owned(),
            format!("{RECORDING},{endpoint},{FORWARD},110,111"),
        ],
        &source_log,
    );
    // The client publishes on the recorded stream.
    let mut client = connect(&source_dir);
    let mut publication = client
        .add_exclusive_publication("karyos:ipc", StreamId::new(STREAM))
        .unwrap();
    let (mut sent, start) = (0u32, Instant::now());
    while sent < MESSAGES {
        assert!(start.elapsed() < Duration::from_secs(10), "sent {sent}");
        let _ = client.poll();
        match publication.offer(&[u8::try_from(sent % 251).unwrap(); 64]) {
            Ok(_) => sent += 1,
            Err(OfferError::NotConnected | OfferError::BackPressured | OfferError::AdminAction) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("offer: {error}"),
        }
    }
    // The replica follows the source's incarnation and counts what
    // verified.
    wait_for(
        &source_log,
        "replication requested",
        1,
        "source",
        &replica_log,
    );
    wait_for(
        &replica_log,
        "replica follows the source's newest incarnation",
        1,
        "replica",
        &source_log,
    );
    if !seen(&replica_log, "replica range counted", 1) {
        let _ = replica.stop();
        let _ = source.stop();
        panic!(
            "no range counted:\n{}\n--- source:\n{}",
            log(&replica_log),
            log(&source_log)
        );
    }
    assert!(replica.stop().success());
    let first = counted(&replica_archive);
    assert!(!first.is_empty());
    assert!(
        first
            .iter()
            .all(|(start, end, profile)| start < end && *profile == ArrivalProfile::Trusted),
        "{first:?}"
    );
    let text = log(&replica_log);
    for refused in [
        "replica bytes differ from the stored bytes",
        "replica seal does not verify on its bytes",
    ] {
        assert!(!text.contains(refused), "{refused:?} in the log:\n{text}");
    }
    // The source sees the replica gone before it comes back.
    wait_for(
        &source_log,
        "replica connection lost",
        1,
        "source",
        &replica_log,
    );
    // A restarted replica receives the recording again from the source's
    // start: identical bytes and verified seals change nothing.
    let second_log = replica_dir.with_extension("second.log");
    let mut replica = Daemon::start(&replica_dir, &replica_archive, &replica_args, &second_log);
    wait_for(
        &second_log,
        "replica follows the source's newest incarnation",
        1,
        "restarted replica",
        &source_log,
    );
    // The source's next request, after it saw the connection come back.
    let deadline = Instant::now() + Duration::from_secs(30);
    while log(&source_log).matches("replication requested").count() < 2 {
        assert!(Instant::now() < deadline, "{}", log(&source_log));
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_secs(2));
    assert!(replica.stop().success());
    let again = counted(&replica_archive);
    assert!(
        first.iter().all(|range| again.contains(range)),
        "a counted range changed: {first:?} then {again:?}"
    );
    let text = log(&second_log);
    for refused in [
        "replica bytes differ from the stored bytes",
        "replica seal does not verify on its bytes",
    ] {
        assert!(!text.contains(refused), "{refused:?} in the log:\n{text}");
    }
    client.remove_publication(publication);
    drop(client);
    assert!(source.stop().success());
    for path in [&source_log, &replica_log, &second_log] {
        let _ = std::fs::remove_file(path);
    }
    for path in [&source_archive, &replica_archive, &source_dir, &replica_dir] {
        let _ = std::fs::remove_dir_all(path);
    }
}
