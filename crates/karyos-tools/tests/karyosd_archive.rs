// SPDX-License-Identifier: Apache-2.0

//! `karyosd --archive` end to end (Linux; quantstratum-docs:
//! karyos/design/archive-host.md, H3): the daemon starts the recording a
//! `--record` names at boot through its control path, a client process
//! (this test) publishes on the recorded stream, a live listing over the
//! control streams shows the recording, a replay of it read by a remote
//! subscriber that joins after the Replay answer (H2b's replay gate) gives
//! every message back in order, and after a restart on the same archive
//! directory the catalog still lists it, stopped. The audit trail names the
//! grants on the control streams and the requests.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use karyos_archive::client::list::{ListPoll, ListerConfig, Listing, RecordingLister};
use karyos_archive::client::{ControlRequests, ControlResponses};
use karyos_archive::control::{ControlMessage, RecordingState, ReplayRate, ResponseCode};
use karyos_archive::server::{MAX_ANSWER, MAX_REQUEST, replay_session_id};
use karyos_client::Outcome;
use karyos_client::{
    Client, ClientConcurrentPublication, ConcurrentOfferOutcome, Context, MessageLimit, OfferError,
    StreamId, Subscription,
};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::term_bytes::SharedTerms;

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
                "--archive-anchor-interval",
                "3600s",
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

/// The request stream, through the client's concurrent handle.
struct Requests(ClientConcurrentPublication<SharedTerms>);

impl ControlRequests for Requests {
    fn send(&mut self, message: &[u8]) -> bool {
        matches!(
            self.0.offer(message),
            Ok(ConcurrentOfferOutcome::Accepted { .. })
        )
    }
}

/// The response stream, through the client's subscription.
struct Responses(Subscription<SharedTerms>);

impl ControlResponses for Responses {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut length = None;
        let _ = self.0.poll(
            |bytes, _| {
                if let Some(to) = out.get_mut(..bytes.len()) {
                    to.copy_from_slice(bytes);
                    length = Some(bytes.len());
                }
            },
            MessageLimit::new(1),
        );
        length
    }
}

/// Lists the recordings over the control streams, as the management agent
/// and `karyos-catalog list --live` do.
fn list(client: &mut Client<karyos_client::ipc::RemoteClient>) -> Listing {
    let requests = client
        .add_concurrent_publication("karyos:ipc", StreamId::new(REQUESTS))
        .unwrap();
    let responses = client
        .add_subscription("karyos:ipc", StreamId::new(RESPONSES))
        .unwrap();
    let mut lister = RecordingLister::new(
        ListerConfig::new(0xC1),
        Requests(requests),
        Responses(responses),
    );
    lister.start();
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(10), "no listing");
        let _ = client.poll();
        match lister.poll() {
            ListPoll::Done(listing) => return listing,
            ListPoll::Pending => std::thread::sleep(Duration::from_millis(1)),
            other => panic!("listing: {other:?}"),
        }
    }
}

/// Asks for a replay of `[start, start + length)` of `recording` onto
/// [`TARGET`] over the control streams; returns the replay id from the
/// answer.
fn replay(
    client: &mut Client<karyos_client::ipc::RemoteClient>,
    recording: u64,
    start: u64,
    length: u64,
) -> u64 {
    const CORRELATION: u64 = (0xC2 << 32) | 1;
    let mut requests = Requests(
        client
            .add_concurrent_publication("karyos:ipc", StreamId::new(REQUESTS))
            .unwrap(),
    );
    let mut responses = Responses(
        client
            .add_subscription("karyos:ipc", StreamId::new(RESPONSES))
            .unwrap(),
    );
    let mut out = vec![0u8; MAX_REQUEST];
    let length = ControlMessage::Replay(karyos_archive::control::Replay {
        correlation_id: CORRELATION,
        recording_id: recording,
        position: start,
        length,
        rate: ReplayRate::Full,
        target_stream_id: TARGET,
        target_channel: "karyos:ipc",
    })
    .encode(&mut out)
    .unwrap();
    let start = Instant::now();
    while !requests.send(&out[..length]) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "request not sent"
        );
        let _ = client.poll();
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut answer = vec![0u8; MAX_ANSWER];
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no replay answer"
        );
        let _ = client.poll();
        if let Some(read) = responses.next(&mut answer)
            && let Ok(ControlMessage::ControlResponse(response)) =
                ControlMessage::decode(&answer[..read])
            && response.correlation_id == CORRELATION
        {
            assert_eq!(response.code, ResponseCode::Ok, "{}", response.message);
            return response.id;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
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

/// The log written so far.
fn log(path: &Path) -> String {
    let mut text = String::new();
    std::fs::File::open(path)
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    text
}

/// H3: a boot recording, a published stream, a live listing, the audit
/// trail, and the catalog across a restart.
#[test]
fn karyosd_records_at_boot_lists_live_and_keeps_the_catalog() {
    let dir = dir("run");
    let archive = dir.with_extension("archive");
    let _ = std::fs::remove_dir_all(&archive);
    std::fs::create_dir_all(&archive).unwrap();
    let first_log = dir.with_extension("first.log");
    let mut daemon = Daemon::start(
        &dir,
        &archive,
        &["--record", &format!("{STREAM}:{SESSION}")],
        &first_log,
    );
    let mut client = connect(&dir);
    let mut publication = client
        .add_exclusive_publication("karyos:ipc", StreamId::new(STREAM))
        .unwrap();
    // The recording is the stream's required subscriber, so offers are
    // accepted once it has started.
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
    // Listed until what it wrote is stable: the recorder has caught up
    // with every accepted message.
    let mut listing = list(&mut client);
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(10), "{listing:?}");
        std::thread::sleep(Duration::from_millis(50));
        let again = list(&mut client);
        let written = |listing: &Listing| {
            listing
                .recordings
                .first()
                .map(|recorded| match recorded.state {
                    RecordingState::Recording { written, .. } => written,
                    _ => 0,
                })
        };
        let stable = written(&again).is_some() && written(&again) == written(&listing);
        listing = again;
        if stable {
            break;
        }
    }
    assert_eq!(listing.recordings.len(), 1, "{listing:?}");
    let recorded = &listing.recordings[0];
    assert_eq!((recorded.stream_id, recorded.session_id), (STREAM, SESSION));
    assert!(
        matches!(recorded.state, RecordingState::Recording { .. }),
        "{:?}",
        recorded.state
    );
    let recording_id = recorded.recording_id;
    let RecordingState::Recording { written, .. } = recorded.state else {
        unreachable!()
    };
    // A replay of what was recorded, read by a subscriber that joins after
    // the answer: every message, in order.
    let replay_id = replay(
        &mut client,
        recording_id,
        recorded.start,
        written - recorded.start,
    );
    assert_eq!(
        read_replay(&dir, replay_id, MESSAGES),
        (0..MESSAGES).collect::<Vec<_>>()
    );
    client.remove_publication(publication);
    drop(client);
    assert!(daemon.stop().success());
    let text = log(&first_log);
    for line in [
        "boot recording started",
        "archive control stream granted",
        "archive request (requester half unauthenticated)",
        "archive request served",
        "boot recording stopped",
        "archive stopped",
    ] {
        assert!(text.contains(line), "{line:?} not in the log:\n{text}");
    }
    // A restart on the same archive lists the recording, stopped.
    let second_log = dir.with_extension("second.log");
    let mut daemon = Daemon::start(&dir, &archive, &[], &second_log);
    let mut client = connect(&dir);
    let listing = list(&mut client);
    assert_eq!(listing.recordings.len(), 1, "{listing:?}");
    assert_eq!(listing.recordings[0].recording_id, recording_id);
    assert!(
        matches!(listing.recordings[0].state, RecordingState::Stopped(_)),
        "{:?}",
        listing.recordings[0].state
    );
    drop(client);
    assert!(daemon.stop().success());
    for path in [&first_log, &second_log] {
        let _ = std::fs::remove_file(path);
    }
    let _ = std::fs::remove_dir_all(&archive);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A recording asked for below the free-space floor is refused and
/// logged; the daemon goes on.
#[test]
fn karyosd_refuses_a_boot_recording_below_its_free_space_floor() {
    let dir = dir("floor");
    let archive = dir.with_extension("archive");
    let _ = std::fs::remove_dir_all(&archive);
    std::fs::create_dir_all(&archive).unwrap();
    let path = dir.with_extension("log");
    let mut daemon = Daemon::start(
        &dir,
        &archive,
        &[
            "--record",
            &format!("{STREAM}:{SESSION}"),
            // Later options win: no file system has this much free.
            "--archive-min-free",
            "1000000g",
        ],
        &path,
    );
    let client = connect(&dir);
    let start = Instant::now();
    while !log(&path).contains("boot recording refused") {
        assert!(start.elapsed() < Duration::from_secs(10), "{}", log(&path));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(log(&path).contains("below its free-space floor"));
    drop(client);
    assert!(daemon.stop().success());
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&archive);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every requester the request stream admits can read the response stream
/// at once, beside the daemon's own requester for a boot recording: each
/// `ArchiveConnection` reads it as an optional reader, which takes a
/// spare-slot credit, and lists the recording through it.
#[test]
fn karyosd_admits_as_many_archive_connections_as_request_publishers() {
    use karyos_archive::client::connection::{ArchiveConnection, ControlStreams};
    use karyos_tools::daemon_archive::REQUEST_PUBLISHERS;

    let dir = dir("readers");
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
    // The daemon's requester may still hold its handles: one of each.
    let connections: Vec<_> = (1..REQUEST_PUBLISHERS)
        .map(|index| {
            ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES))
                .unwrap_or_else(|error| panic!("connection {index}: {error}"))
        })
        .collect();
    // Each lists the boot recording.
    for (index, connection) in connections.into_iter().enumerate() {
        let (requests, responses) = connection.into_transports();
        let mut lister = RecordingLister::new(
            ListerConfig::new(0xD0 + u32::try_from(index).unwrap()),
            requests,
            responses,
        );
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
        assert_eq!(listing.recordings.len(), 1, "{listing:?}");
    }
    drop(client);
    assert!(daemon.stop().success());
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&archive);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The management agent lists a karyosd Archive's catalog over its
/// control streams, as an operator sees it: the boot recording, live.
#[test]
fn the_management_agent_lists_a_karyosd_archive() {
    use karyos_agent::catalog::{ArchiveStreams, CatalogConfig};
    use karyos_agent::{Agent, AgentConfig};

    let dir = dir("agent");
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
    // The socket answers: the daemon is up.
    drop(connect(&dir));
    let mut agent = Agent::new(
        AgentConfig::new(vec![dir.clone()])
            .with_attach_timeout(Duration::from_secs(5))
            .with_archive(
                dir.clone(),
                CatalogConfig::new(ArchiveStreams::new(REQUESTS, RESPONSES)).with_timing(
                    Duration::from_secs(2),
                    Duration::from_secs(5),
                    Duration::from_millis(50),
                ),
            ),
    );
    let start = Instant::now();
    let catalog = loop {
        agent.refresh();
        let catalog = agent.view().drivers[0].catalog.clone().unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "no listing: {catalog:?}"
        );
        if catalog.listings > 0 && !catalog.recordings.is_empty() {
            break catalog;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(catalog.recordings.len(), 1, "{catalog:?}");
    let recorded = &catalog.recordings[0];
    assert_eq!((recorded.stream_id, recorded.session_id), (STREAM, SESSION));
    assert!(recorded.recording, "{recorded:?}");
    drop(agent);
    assert!(daemon.stop().success());
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&archive);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0088 (karyos#967): the management agent's retention backend holds,
/// purges and releases a karyosd Archive's recording through its control
/// streams, answered by the Archive's own retention engine: the hold is
/// evidenced, a purge under it is refused `legal_hold`, the release is
/// done, and with no purge policy configured a purge is refused
/// `no_policy`.
#[test]
fn the_retention_backend_holds_a_karyosd_recording() {
    use karyos_agent::archive_retention::ArchiveRetention;
    use karyos_agent::catalog::ArchiveStreams;
    use karyos_agent::retention::{RetentionBackend, RetentionReply};

    let dir = dir("retention");
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
    drop(connect(&dir));
    let mut backend = ArchiveRetention::new(dir.clone(), ArchiveStreams::new(REQUESTS, RESPONSES))
        .with_deadline(Duration::from_secs(10));
    let refused = |reason: &str| RetentionReply::Refused {
        code: 8,
        reason: reason.to_owned(),
    };
    let fmt = |reply: RetentionReply| format!("{reply:?}");
    assert_eq!(
        fmt(backend.hold(1, 1, 1000)),
        fmt(RetentionReply::Done { evidenced: true })
    );
    assert_eq!(
        fmt(backend.purge(1, 64, 2, 1000)),
        fmt(refused("legal_hold"))
    );
    assert_eq!(
        fmt(backend.release(1, 3, 1000)),
        fmt(RetentionReply::Done { evidenced: true })
    );
    assert_eq!(
        fmt(backend.purge(1, 64, 4, 1000)),
        fmt(refused("no_policy"))
    );
    assert!(daemon.stop().success());
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&archive);
    let _ = std::fs::remove_dir_all(&dir);
}

/// karyos#1093: with `--archive-retain-for`, `--archive-purge`,
/// `--archive-min-copies` and `--archive-copy-location`, a karyosd
/// Archive's purges run through its retention policy over the control
/// streams: refused `legal_hold` under a hold, then `no_close_time` while
/// the recording records (ADR-0093).
#[test]
fn a_karyosd_retention_policy_refuses_an_early_purge() {
    use karyos_agent::archive_retention::ArchiveRetention;
    use karyos_agent::catalog::ArchiveStreams;
    use karyos_agent::retention::{RetentionBackend, RetentionReply};

    let dir = dir("policy");
    let archive = dir.with_extension("archive");
    let _ = std::fs::remove_dir_all(&archive);
    std::fs::create_dir_all(&archive).unwrap();
    let path = dir.with_extension("log");
    let location = "05".repeat(32);
    let mut daemon = Daemon::start(
        &dir,
        &archive,
        &[
            "--record",
            &format!("{STREAM}:{SESSION}"),
            "--archive-copy-location",
            &location,
            "--archive-retain-for",
            "3600s",
            "--archive-purge",
            "manual",
            "--archive-min-copies",
            "1",
        ],
        &path,
    );
    drop(connect(&dir));
    let mut backend = ArchiveRetention::new(dir.clone(), ArchiveStreams::new(REQUESTS, RESPONSES))
        .with_deadline(Duration::from_secs(10));
    let refused = |reason: &str| RetentionReply::Refused {
        code: 8,
        reason: reason.to_owned(),
    };
    let fmt = |reply: RetentionReply| format!("{reply:?}");
    assert_eq!(
        fmt(backend.hold(1, 1, 1000)),
        fmt(RetentionReply::Done { evidenced: true })
    );
    assert_eq!(
        fmt(backend.purge(1, 64, 2, 1000)),
        fmt(refused("legal_hold"))
    );
    assert_eq!(
        fmt(backend.release(1, 3, 1000)),
        fmt(RetentionReply::Done { evidenced: true })
    );
    assert_eq!(
        fmt(backend.purge(1, 64, 4, 1000)),
        fmt(refused("no_close_time"))
    );
    assert!(daemon.stop().success());
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&archive);
    let _ = std::fs::remove_dir_all(&dir);
}
