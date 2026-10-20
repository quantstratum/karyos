// SPDX-License-Identifier: Apache-2.0

//! `karyos-replay start` and `stop` end to end against `karyosd --archive`
//! (Linux; quantstratum-docs: karyos/design/archive-host.md, H6): the
//! daemon records a stream at boot, a client process (this test)
//! publishes on it, `karyos-replay start` asks for a replay of what was
//! recorded and prints its target, and a remote subscriber that joins
//! after the answer reads every message back in order. A second replay is
//! stopped by `karyos-replay stop` before anyone reads it, and stopping it
//! again is refused with exit status 2.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use karyos_archive::client::connection::{ArchiveConnection, ControlStreams};
use karyos_archive::client::list::{ListPoll, ListerConfig, Listing, RecordingLister};
use karyos_archive::control::RecordingState;
use karyos_archive::server::replay_session_id;
use karyos_client::Outcome;
use karyos_client::{Client, Context, MessageLimit, OfferError, StreamId};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};

/// The recorded stream: `--stream 2:1`.
const STREAM: i32 = 2;
const SESSION: i32 = 1;
/// The Archive's control streams.
const REQUESTS: i32 = 100;
const RESPONSES: i32 = 101;
/// Messages the client publishes.
const MESSAGES: u32 = 20;
/// The stream a replay is written to.
const TARGET: i32 = 300;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyosd-archive-{}-{name}", std::process::id()));
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
    /// Starts `karyosd` on `dir`, recording in `archive`, with `extra`
    /// arguments; its log goes to `log`.
    fn start(dir: &Path, archive: &Path, extra: &[&str], log: &Path) -> Self {
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
                "--term-length",
                "64k",
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

/// Lists the recordings over the control streams.
fn list(client: &mut Client<karyos_client::ipc::RemoteClient>) -> Listing {
    let (requests, responses) =
        ArchiveConnection::open(client, ControlStreams::new(REQUESTS, RESPONSES))
            .unwrap()
            .into_transports();
    let mut lister = RecordingLister::new(ListerConfig::new(0xC1), requests, responses);
    lister.start();
    let start = Instant::now();
    let listing = loop {
        assert!(start.elapsed() < Duration::from_secs(10), "no listing");
        let _ = client.poll();
        match lister.poll() {
            ListPoll::Done(listing) => break listing,
            ListPoll::Pending => std::thread::sleep(Duration::from_millis(1)),
            other => panic!("listing: {other:?}"),
        }
    };
    let (requests, responses) = lister.into_transports();
    requests.close(client);
    responses.close(client);
    listing
}

/// Runs `karyos-replay` with `args`.
fn karyos_replay(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_karyos-replay"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// The value of `name=` in `line`.
fn field(line: &str, name: &str) -> String {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(name)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("no {name} in {line:?}"))
        .to_owned()
}

/// Reads `count` messages of replay `replay_id`'s target as a remote
/// subscriber that joins only now, after the answer.
fn read_replay(dir: &Path, replay_id: u64, count: u32) -> Vec<u32> {
    let mut client = karyos_client::ipc::attach(dir, Duration::from_secs(5), 16).unwrap();
    let key = StreamKey {
        stream_id: TARGET,
        session_id: replay_session_id(replay_id),
    };
    let _ = client
        .add_subscription(key, SubscriberRole::Required)
        .unwrap();
    let start = Instant::now();
    let mut grant = None;
    while grant.is_none() {
        assert!(start.elapsed() < Duration::from_secs(10), "no target grant");
        let _ = client.poll(usize::MAX, |completion| match completion.outcome {
            Outcome::Fetchable(fetchable) => grant = Some(fetchable),
            other => panic!("expected the target's grant, got {other:?}"),
        });
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut subscription = client.take_subscription(&grant.unwrap()).unwrap();
    let mut read = Vec::new();
    while read.len() < count as usize {
        assert!(start.elapsed() < Duration::from_secs(10), "read {read:?}");
        let _ = subscription.poll(
            |bytes, _| read.push(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
            MessageLimit::new(16),
        );
        std::thread::yield_now();
    }
    read
}

#[test]
fn karyos_replay_starts_and_stops_replays_of_a_karyosd_recording() {
    let dir = dir("replay");
    let archive = dir.with_extension("archive");
    let _ = std::fs::remove_dir_all(&archive);
    std::fs::create_dir_all(&archive).unwrap();
    let path = dir.with_extension("log");
    let mut daemon = Daemon::start(
        &dir,
        &archive,
        &["--record", &format!("{STREAM}:{SESSION}")],
        &path,
    );
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
    // Listed until what it wrote is stable: the recorder has caught up.
    let written = |listing: &Listing| {
        listing
            .recordings
            .first()
            .map(|recorded| match recorded.state {
                RecordingState::Recording { written, .. } => written,
                _ => 0,
            })
    };
    let mut listing = list(&mut client);
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(10), "{listing:?}");
        std::thread::sleep(Duration::from_millis(50));
        let again = list(&mut client);
        let stable = written(&again).is_some() && written(&again) == written(&listing);
        listing = again;
        if stable {
            break;
        }
    }
    let recorded = &listing.recordings[0];
    let length = written(&listing).unwrap() - recorded.start;
    let live = format!("{}={REQUESTS},{RESPONSES}", dir.display());
    let (recording, from, length) = (
        recorded.recording_id.to_string(),
        recorded.start.to_string(),
        length.to_string(),
    );
    let target = TARGET.to_string();

    // `start` answers the replay and its target; a reader that joins now
    // reads every message, in order.
    let started = karyos_replay(&[
        "start",
        "--live",
        &live,
        "--recording",
        &recording,
        "--from",
        &from,
        "--length",
        &length,
        "--to-stream",
        &target,
    ]);
    let stdout = String::from_utf8(started.stdout).unwrap();
    assert!(
        started.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let replay: u64 = field(&stdout, "replay").parse().unwrap();
    assert_eq!(field(&stdout, "stream"), target);
    assert_eq!(
        field(&stdout, "session"),
        replay_session_id(replay).to_string()
    );
    assert_eq!(
        read_replay(&dir, replay, MESSAGES),
        (0..MESSAGES).collect::<Vec<_>>()
    );

    // A second replay, stopped while it waits for its first reader.
    let started = karyos_replay(&[
        "start",
        "--live",
        &live,
        "--recording",
        &recording,
        "--to-stream",
        &target,
    ]);
    assert!(started.status.success());
    let second = field(&String::from_utf8(started.stdout).unwrap(), "replay");
    let stopped = karyos_replay(&["stop", "--live", &live, "--replay", &second]);
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert_eq!(
        String::from_utf8(stopped.stdout).unwrap().trim(),
        format!("stopped replay={second}")
    );
    // Stopped already: the Archive refuses, and the exit status is 2.
    let again = karyos_replay(&["stop", "--live", &live, "--replay", &second]);
    assert_eq!(again.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("UnknownReplay"),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );

    client.remove_publication(publication);
    drop(client);
    assert!(daemon.stop().success());
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&archive);
    let _ = std::fs::remove_dir_all(&dir);
}
