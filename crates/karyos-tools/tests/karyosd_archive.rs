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
                start.elapsed() < Duration::from_secs(40),
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

/// One record's 18 words, as `karyos-tools calibrate append` arguments.
fn record_words(words: &[u64; karyos_trace::clocks::CALIBRATION_WORDS]) -> Vec<String> {
    words.iter().map(u64::to_string).collect()
}

/// The calibration journal end to end (karyos#991, #1065, #1128): a
/// `karyosd --archive-time-evidence --archive-calibration-journal` run
/// while a producer appends a synthetic calibration and UTC reference
/// record with `karyos-tools calibrate append`, then `karyos-catalog
/// verify --time-requirement` on its archive. The daemon has no recording
/// group, the only producer of time evidence entries (ADR-0098), so the
/// store it makes holds none and the verdict is `no_evidence`, never
/// `met`, and reported apart from the integrity outcome.
#[test]
fn karyosd_reports_no_time_evidence_without_a_group_from_its_calibration_journal() {
    use karyos_archive::disk::StdDisk;
    use karyos_archive::integrity::{calibration_journal, time_evidence};
    use karyos_trace::clocks::utc::{Scale, Source, SyncState, UtcReference};
    use karyos_trace::clocks::{Calibration, ClockKey};
    use karyos_trace::journal::ObserverId;

    let dir = dir("calibration");
    let archive = dir.with_extension("archive");
    let journal = dir.with_extension("calibration-journal");
    let anchors = dir.with_extension("anchors");
    for path in [&archive, &journal, &anchors] {
        let _ = std::fs::remove_dir_all(path);
    }
    std::fs::create_dir_all(&archive).unwrap();
    std::fs::create_dir_all(&anchors).unwrap();
    let log_path = dir.with_extension("calibration.log");
    let mut daemon = Daemon::start(
        &dir,
        &archive,
        &[
            "--record",
            &format!("{STREAM}:{SESSION}"),
            "--archive-time-evidence",
            "--archive-calibration-journal",
            journal.to_str().unwrap(),
        ],
        &log_path,
    );
    let client = connect(&dir);
    // The daemon made the store before its agent started.
    let entries_dir = time_evidence::entries_dir(&archive);
    assert!(entries_dir.is_dir(), "{}", entries_dir.display());

    // A synthetic calibration of a clock A to a UTC-traceable clock B, and
    // a UTC reference record of B, appended while the daemon runs.
    let clock = |domain| ClockKey {
        observer: ObserverId {
            driver: [1, 0],
            journal: 2,
        },
        domain,
        epoch: 1,
    };
    let calibration = Calibration {
        from: clock(3),
        to: clock(9),
        reference: 0,
        offset: 10,
        offset_uncertainty: 2,
        drift: 0,
        drift_uncertainty: 0,
        valid_from: 0,
        valid_to: u64::MAX / 4,
    }
    .encode()
    .unwrap();
    let reference = UtcReference {
        clock: clock(9),
        source: Source::Gnss,
        sync_state: SyncState::Synchronised,
        bound: 100,
        valid_from: 0,
        valid_to: u64::MAX / 2,
        tick_fs: 1_000_000,
        scale: Scale::Tai,
        origin: 0,
        origin_scale_ns: 2_000_000_000_000_000_000,
        leap_table: 69,
        transform_uncertainty_ns: 0,
    }
    .encode()
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_karyos-tools"))
        .args(["calibrate", "append", "--journal"])
        .arg(&journal)
        .args(record_words(&calibration))
        .args(record_words(&reference))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(client);
    assert!(daemon.stop().success());
    let text = log(&log_path);
    for line in ["boot recording started", "archive stopped"] {
        assert!(text.contains(line), "{line:?} not in the log:\n{text}");
    }

    // The journal the daemon was given holds both records, lossless.
    let records = calibration_journal::read(StdDisk, &journal).unwrap();
    assert_ne!(records.generation, 0);
    assert!(records.lossless);
    assert_eq!(records.records, [calibration, reference]);
    // No group, so no entry: the store is there and empty.
    assert_eq!(time_evidence::read_sealed(StdDisk, &archive).unwrap(), []);

    // The verdict, apart from integrity: no evidence, never met. With no
    // trust root the integrity evidence is untrusted (1), never an error.
    let verify = |json: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_karyos-catalog"));
        command.arg("verify");
        if json {
            command.arg("--json");
        }
        command
            .args(["--time-requirement", "1000:1000", "--time-anchors"])
            .arg(format!("{}={}", "ab".repeat(32), anchors.display()))
            .arg(&archive)
            .output()
            .unwrap()
    };
    let output = verify(false);
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(1), "{shown}");
    assert!(shown.ends_with("time verdict: no_evidence\n"), "{shown}");
    assert!(!shown.contains(" met\n"), "{shown}");
    assert!(!shown.contains("corruption"), "{shown}");
    let output = verify(true);
    let shown = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(output.status.code(), Some(1), "{shown}");
    assert!(
        shown.contains("\"time\":{\"verdict\":\"no_evidence\",\"entries\":[],"),
        "{shown}"
    );
    assert!(shown.contains("\"untrusted_evidence\""), "{shown}");
    assert!(!shown.contains("\"met\""), "{shown}");

    let _ = std::fs::remove_file(&log_path);
    for path in [&archive, &journal, &anchors, &dir] {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// The environment variable that makes [`signer_process`] the Ed25519
/// signer program of the trace evidence test.
const SIGNER: &str = "KARYOSD_TEST_SIGNER";

/// The test signer's seed, and the authority's that endorses its key.
const SIGNER_SEED: [u8; 32] = [9; 32];
const AUTHORITY_SEED: [u8; 32] = [1; 32];
/// The Archive's identity in the trust file.
const ARCHIVE_ID: [u8; 32] = [0x42; 32];
/// The operator's anchor store location.
const OPERATOR: [u8; 32] = [0x0A; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Not a test of its own: with [`SIGNER`] set, this process is the
/// `--archive-signer` program (`<program> sign`): the head's signed bytes
/// in hex on standard input, the Ed25519 signature in hex on standard
/// output, a real signature with the test key.
#[test]
fn signer_process() {
    use std::io::{BufRead as _, Write as _};
    if std::env::var_os(SIGNER).is_none() {
        return;
    }
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
    let line = line.trim();
    let bytes: Vec<u8> = (0..line.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&line[at..at + 2], 16).unwrap())
        .collect();
    let key = karyos_archive::integrity::test_key::TestKey::from_seed(SIGNER_SEED);
    let mut out = std::io::stdout().lock();
    // On a line of its own: the harness prints the test's name before it.
    writeln!(out, "\n{}", hex(&key.sign_bytes(&bytes))).unwrap();
    out.flush().unwrap();
}

/// Registers the signer's key in the integrity journal of `dir`, endorsed
/// by the authority, before the daemon opens it.
fn register_signer(dir: &Path) {
    use karyos_archive::disk::StdDisk;
    use karyos_archive::integrity::journal::IntegrityJournal;
    use karyos_archive::integrity::ledger::Ledger;
    use karyos_archive::integrity::test_key::TestKey;
    use karyos_archive::integrity::trust::{
        Algorithm, Custody, KEYS_FILE, KeyRegistry, REGISTRY_ENTRY_LENGTH, RegistryAction,
        RegistryEntry, TrustRoot, key_id,
    };
    std::fs::create_dir_all(dir).unwrap();
    let mut journal = IntegrityJournal::open(StdDisk, dir).unwrap().journal;
    let authority = TestKey::from_seed(AUTHORITY_SEED);
    let public = TestKey::from_seed(SIGNER_SEED).public();
    let mut entry = RegistryEntry {
        action: RegistryAction::Register,
        algorithm: Algorithm::Ed25519,
        custody: Custody::Declared,
        sequence: 0,
        key_id: key_id(&public),
        public,
        effective: u64::try_from(journal.records().unwrap().len()).unwrap(),
        evidence: [0; 32],
        endorsement: [0; 64],
    };
    entry.endorsement = authority.sign_bytes(&entry.endorsement_bytes(&ARCHIVE_ID));
    let trust = TrustRoot {
        archive_id: ARCHIVE_ID,
        authorities: vec![authority.public()],
    };
    let mut keys = Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(StdDisk, dir, KEYS_FILE).unwrap();
    KeyRegistry::new(trust)
        .append(&entry, &mut journal, &mut keys)
        .unwrap();
}

/// The last signed head of `dir`'s journal, and whether it covers the
/// journal's last record.
fn last_head(dir: &Path) -> (Option<karyos_archive::integrity::trust::SignedHead>, bool) {
    use karyos_archive::disk::StdDisk;
    use karyos_archive::integrity::journal::read_records;
    use karyos_archive::integrity::ledger::read_entries;
    use karyos_archive::integrity::trust::{HEADS_FILE, SIGNED_HEAD_LENGTH, SignedHead};
    let (records, _) = read_records(&mut StdDisk, dir).unwrap();
    let heads: Vec<[u8; SIGNED_HEAD_LENGTH]> = read_entries(&mut StdDisk, dir, HEADS_FILE).unwrap();
    let head = heads.last().map(|bytes| SignedHead::decode(bytes).unwrap());
    let covered = match (head, records.last()) {
        (Some(head), Some(last)) => head.head.counter >= last.counter,
        _ => false,
    };
    (head, covered)
}

/// Runs `karyos-tools` with `args`; returns its standard output, asserting
/// success.
fn tools(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_karyos-tools"))
        .args(args)
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{args:?}: {out}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    out
}

/// The 18 words of the `record` line a calibrate tool printed.
fn printed_record(out: &str) -> Vec<String> {
    out.lines()
        .find_map(|line| line.strip_prefix("record "))
        .unwrap_or_else(|| panic!("no record in {out}"))
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// `calibrate realtime --from monotonic --epoch boot` of the trace clock
/// (domain 5), valid `extension_ms` past its reads, appended to `journal`;
/// retried when a slew within the run refuses it. Returns its validity's
/// end, in ns of `CLOCK_MONOTONIC`.
fn calibrate_monotonic(journal: &Path, extension_ms: u64) -> u64 {
    use karyos_trace::clocks::record::ClockRecord;
    for _ in 0..10 {
        let output = Command::new(env!("CARGO_BIN_EXE_karyos-tools"))
            .args([
                "calibrate",
                "realtime",
                "--from",
                "monotonic",
                "--source-domain",
                "5",
                "--epoch",
                "boot",
                "--reads",
                "256",
                "--interval-us",
                "100",
                "--extension-ms",
                &extension_ms.to_string(),
            ])
            .output()
            .unwrap();
        if !output.status.success() {
            continue;
        }
        let words = printed_record(&String::from_utf8_lossy(&output.stdout));
        let mut append = vec![
            "calibrate",
            "append",
            "--journal",
            journal.to_str().unwrap(),
        ];
        append.extend(words.iter().map(String::as_str));
        let _ = tools(&append);
        // Printed in hex with `0x`.
        let parsed: Vec<u64> = words
            .iter()
            .map(|word| u64::from_str_radix(word.trim_start_matches("0x"), 16).unwrap())
            .collect();
        let Ok(ClockRecord::Calibration(calibration)) =
            ClockRecord::decode(&parsed.try_into().unwrap())
        else {
            panic!("not a calibration");
        };
        return calibration.valid_to;
    }
    panic!("calibrate realtime refused every run");
}

/// `calibrate utc --epoch boot` from a synthetic synchronised chrony
/// state sampled now, valid `window_ms`, appended to `journal`.
fn reference_now(journal: &Path, tracking: &Path, window_ms: u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string();
    let out = tools(&[
        "calibrate",
        "utc",
        "--tracking",
        tracking.to_str().unwrap(),
        "--sampled-at-ns",
        &now,
        "--window-ms",
        &window_ms.to_string(),
        "--epoch",
        "boot",
    ]);
    let words = printed_record(&out);
    let mut append = vec![
        "calibrate",
        "append",
        "--journal",
        journal.to_str().unwrap(),
    ];
    append.extend(words.iter().map(String::as_str));
    let _ = tools(&append);
}

/// Waits until `CLOCK_MONOTONIC` is past `instant`.
fn monotonic_past(instant: u64) {
    while karyos_sys::host_clock::host_monotonic_ns() <= instant {
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A publication of stream [`STREAM`] traced by a `TraceAgent` with the
/// host clock, through a trace journal of the daemon in `dir`.
struct Traced {
    client: karyos_client::ipc::RemoteClient,
    publication: karyos_client::ClientPublication<SharedTerms>,
}

impl Traced {
    fn new(dir: &Path) -> Self {
        use karyos_sys::record_journal::JournalLayout;
        use karyos_trace::{
            BufferedIds, ClockProvenance, HostMonotonicClock, OsRandom, RECORD_WORDS, Sampling,
            TraceAgent, journal::ObserverId, trace_writer,
        };
        // Once the daemon's socket answers.
        let start = Instant::now();
        let mut client = loop {
            match karyos_client::ipc::attach(dir, Duration::from_secs(5), 16) {
                Ok(client) => break client,
                Err(error) => {
                    assert!(start.elapsed() < Duration::from_secs(10), "attach: {error}");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        let key = StreamKey {
            stream_id: STREAM,
            session_id: SESSION,
        };
        let _ = client.add_publication(key, false).unwrap();
        let start = Instant::now();
        let mut grant = None;
        while grant.is_none() {
            assert!(start.elapsed() < Duration::from_secs(10), "no grant");
            let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                Outcome::Fetchable(fetchable) => grant = Some(fetchable),
                other => panic!("expected a grant, got {other:?}"),
            });
            std::thread::sleep(Duration::from_millis(1));
        }
        let grant = grant.unwrap();
        let layout = JournalLayout {
            capacity: 1024,
            payload_words: RECORD_WORDS,
            drop_ranges: 2,
        };
        let _ = client
            .trace_journal(
                layout,
                grant.registration,
                ClockProvenance::HostMonotonic.word(),
            )
            .unwrap();
        let mut fetchable = None;
        while fetchable.is_none() {
            assert!(start.elapsed() < Duration::from_secs(10), "no journal");
            let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                Outcome::FetchableJournal(journal) => fetchable = Some(journal),
                other => panic!("expected a journal, got {other:?}"),
            });
            std::thread::sleep(Duration::from_millis(1));
        }
        let (number, raw) = client
            .take_journal(&fetchable.unwrap())
            .unwrap()
            .into_parts();
        let instance = client.instance();
        let driver = [(instance >> 64) as u64, instance as u64];
        let writer = trace_writer(
            raw,
            ObserverId {
                driver,
                journal: number,
            },
            1,
        )
        .unwrap();
        let agent = TraceAgent::new(
            Sampling::All,
            BufferedIds::new(4096, OsRandom).unwrap(),
            HostMonotonicClock::new(1),
            writer,
        );
        let identity = karyos_client::PublicationIdentity {
            driver,
            registration: grant.registration,
            stream_id: STREAM,
            session_id: SESSION,
            incarnation: 1,
        };
        let publication = client
            .take_publication(&grant)
            .unwrap()
            .with_trace(Box::new(agent), identity);
        Self {
            client,
            publication,
        }
    }

    /// Offers one untraced message, once the recording takes it: the
    /// stream is recorded before any observation is made.
    fn connected(&mut self) {
        let start = Instant::now();
        loop {
            assert!(start.elapsed() < Duration::from_secs(10), "not recorded");
            let _ = self.client.poll(usize::MAX, |_| {});
            if let Ok(karyos_client::OfferOutcome::Accepted { .. }) = self.publication.offer(b"x") {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Offers `count` traced messages, each once the recording takes it.
    fn publish(&mut self, count: u32) {
        let start = Instant::now();
        let mut sent = 0;
        while sent < count {
            assert!(start.elapsed() < Duration::from_secs(10), "sent {sent}");
            let _ = self.client.poll(usize::MAX, |_| {});
            let decision = self.publication.trace_message(None);
            match self
                .publication
                .offer_with_trace(&sent.to_le_bytes(), &decision)
            {
                Ok(karyos_client::OfferOutcome::Accepted { .. }) => sent += 1,
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    }
}

/// ADR-0117 end to end (karyos#991, #1065, #1128): a karyosd with a real
/// Ed25519 signer, a trust file and the calibration journal records its
/// trace journal as an Archive recording while a client traced with the
/// host clock publishes across a calibration boundary; the calibrations
/// (C1, C2 across the boundary, a later C3) and UTC references come from
/// `karyos-tools calibrate realtime --from monotonic --epoch boot` and
/// `calibrate utc --epoch boot`. After the stop, the heads are signed (the
/// daemon restarted until they are) and anchored by the operator, and
/// `karyos-catalog verify --trust --anchors --time-requirement` exits 0
/// with entries citing both calibrations, each `met`, and no uncovered
/// range; a stricter requirement is `not_met`.
#[test]
fn karyosd_records_its_trace_journal_with_time_evidence() {
    use karyos_archive::disk::StdDisk;
    use karyos_archive::integrity::anchor::{LedgerAnchorStore, publish_due};
    use karyos_archive::integrity::time_evidence::{NO_BOUND, entries_dir, read_sealed};

    if karyos_sys::host_clock::time_identity().is_err() {
        return;
    }
    let dir = dir("trace-evidence");
    let root = dir.with_extension("root");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let archive = root.join("archive");
    let journal = root.join("calibrations");
    let anchors = root.join("anchors");
    let time_anchors = root.join("time-anchors");
    for path in [&archive, &anchors, &time_anchors] {
        std::fs::create_dir_all(path).unwrap();
    }
    register_signer(&archive);
    register_signer(&entries_dir(&archive));
    let authority = karyos_archive::integrity::test_key::TestKey::from_seed(AUTHORITY_SEED);
    let trust = root.join("trust");
    std::fs::write(
        &trust,
        format!(
            "archive {}\nauthority {}\njournal 0\ntime-journal 1\n",
            hex(&ARCHIVE_ID),
            hex(&authority.public())
        ),
    )
    .unwrap();
    let signer = root.join("signer.sh");
    std::fs::write(
        &signer,
        format!(
            "#!/bin/sh\n{SIGNER}=1 \"{}\" --exact signer_process --nocapture --test-threads=1 2>/dev/null | grep -E '^[0-9a-f]{{128}}$'\n",
            std::env::current_exe().unwrap().display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&signer, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let tracking = root.join("tracking");
    std::fs::write(
        &tracking,
        "A29FC87B,ntp.example,2,1700000000.0,0.000001,0,0,0,0.001,0.002,0.0001,0.0002,64,Normal\n",
    )
    .unwrap();
    let public =
        hex(&karyos_archive::integrity::test_key::TestKey::from_seed(SIGNER_SEED).public());
    let signing = [
        "--archive-signer",
        signer.to_str().unwrap(),
        "--archive-signer-key",
        &public,
        "--archive-trust",
        trust.to_str().unwrap(),
        "--archive-time-evidence",
        "--archive-calibration-journal",
        journal.to_str().unwrap(),
    ];
    let record = format!("{STREAM}:{SESSION}");
    let mut args: Vec<&str> = vec!["--record", &record];
    args.extend(signing);
    args.extend([
        "--archive-trace-record",
        "50:1",
        "--archive-trace-clock",
        "5:boot:1000",
        "--archive-time-requirement",
        "5:1000000000:1000",
        "--archive-calibration-wait",
        "10s",
        "--archive-seal-interval",
        "200ms",
    ]);
    let log_path = root.join("first.log");
    let mut daemon = Daemon::start(&dir, &archive, &args, &log_path);
    let mut traced = Traced::new(&dir);
    // The recording of the stream is attached before the calibrations,
    // and nothing is observed before C1.
    traced.connected();

    // C1 and a UTC reference valid over the whole run, then traffic
    // within C1.
    reference_now(&journal, &tracking, 60_000);
    let c1 = calibrate_monotonic(&journal, 5_000);
    traced.publish(20);
    assert!(karyos_sys::host_clock::host_monotonic_ns() < c1, "C1 ended");
    // The boundary: C2 starts after C1 ends; traffic within C2.
    monotonic_past(c1);
    let c2 = calibrate_monotonic(&journal, 5_000);
    traced.publish(20);
    assert!(karyos_sys::host_clock::host_monotonic_ns() < c2, "C2 ended");
    // The later records: C3 and a UTC reference past every observation.
    monotonic_past(c2);
    let _ = calibrate_monotonic(&journal, 5_000);
    reference_now(&journal, &tracking, 10_000);
    std::thread::sleep(Duration::from_millis(1_500));
    drop(traced);
    assert!(daemon.stop().success(), "{}", log(&log_path));
    let text = log(&log_path);
    assert!(text.contains("trace mirror published"), "{text}");

    // The clean shutdown waited for the last heads' signatures: the
    // operator's anchors cover them, with no second run.
    for journal_dir in [archive.clone(), entries_dir(&archive)] {
        assert!(
            last_head(&journal_dir).1,
            "{} is not signed",
            journal_dir.display()
        );
    }
    for (journal_dir, store) in [
        (archive.clone(), &anchors),
        (entries_dir(&archive), &time_anchors),
    ] {
        let (Some(head), true) = last_head(&journal_dir) else {
            panic!("{} is not covered", journal_dir.display());
        };
        let mut anchored = LedgerAnchorStore::open(StdDisk, store, OPERATOR).unwrap();
        publish_due(
            &mut anchored,
            None,
            Some(&head),
            std::num::NonZeroU64::new(1).unwrap(),
        )
        .unwrap()
        .unwrap();
    }

    // Two entries cite different calibrations, each bounded.
    let entries = read_sealed(StdDisk, &archive).unwrap();
    let bounded: Vec<_> = entries
        .iter()
        .filter(|entry| entry.bound_max_ns != NO_BOUND)
        .collect();
    let mut digests: Vec<[u8; 32]> = bounded.iter().map(|entry| entry.calibration).collect();
    digests.sort_unstable();
    digests.dedup();
    assert!(digests.len() >= 2, "{entries:#?}");

    let verify = |requirement: Option<&str>| {
        let output = Command::new(env!("CARGO_BIN_EXE_karyos-catalog"))
            .arg("verify")
            .arg(&archive)
            .arg("--trust")
            .arg(&trust)
            .arg("--anchors")
            .arg(format!("{}={}", hex(&OPERATOR), anchors.display()))
            .args(
                requirement
                    .map(|requirement| ["--time-requirement", requirement])
                    .into_iter()
                    .flatten(),
            )
            .arg("--time-anchors")
            .arg(format!("{}={}", hex(&OPERATOR), time_anchors.display()))
            .output()
            .unwrap();
        (
            output.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    };
    // No --time-requirement: the recording carries the operator's
    // requirement for clock domain 5 (karyos#1128).
    let (code, shown) = verify(None);
    assert!(
        shown.contains(
            "clock domain 5: declared 1000000000:1000, applied 1000000000:1000 (recorded)"
        ),
        "{shown}"
    );
    assert_eq!(code, Some(0), "{shown}");
    for entry in &bounded {
        let [.., domain, epoch] = entry.clock;
        let line = format!(
            "time recording {} [{}, {}) clock {domain}:{epoch} met",
            entry.recording, entry.start, entry.end
        );
        assert!(shown.contains(&line), "{line:?} not in\n{shown}");
    }
    assert!(!shown.contains("uncovered"), "{shown}");
    assert!(!shown.contains(" loss "), "{shown}");
    assert!(shown.ends_with("time verdict: met\n"), "{shown}");
    // A stricter requirement: 1 ns of divergence.
    // The verifier's own, stricter requirement overrides it.
    let (code, shown) = verify(Some("1:1000"));
    assert_eq!(code, Some(0), "{shown}");
    assert!(
        shown.contains("declared 1000000000:1000, applied 1:1000 (--time-requirement)"),
        "{shown}"
    );
    assert!(!shown.contains("looser"), "{shown}");
    assert!(shown.ends_with("time verdict: not_met\n"), "{shown}");

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0117 point 5, end to end: a real ring overwrite. karyosd's trace
/// mirror holds two records while the driver drains a traced client's
/// burst into it, so the ring overwrites records before the publisher
/// reads them; the publisher reports them as losses of the client's own
/// journal, and `karyos-catalog verify --time-requirement` reports each
/// affected sealed range `no_evidence` with the lost journal and
/// sequences, and the recording's verdict `no_evidence` for capture,
/// never `met`.
#[test]
fn a_ring_overwrite_reaches_verify_as_no_evidence() {
    use karyos_archive::disk::StdDisk;
    use karyos_archive::integrity::anchor::LedgerAnchorStore;

    if karyos_sys::host_clock::time_identity().is_err() {
        return;
    }
    let dir = dir("ring-overwrite");
    let root = dir.with_extension("root");
    let _ = std::fs::remove_dir_all(&root);
    let archive = root.join("archive");
    let journal = root.join("calibrations");
    let time_anchors = root.join("time-anchors");
    for path in [&archive, &time_anchors] {
        std::fs::create_dir_all(path).unwrap();
    }
    // The entries' anchor store must be there for verify to read it.
    drop(LedgerAnchorStore::open(StdDisk, &time_anchors, OPERATOR).unwrap());
    let record = format!("{STREAM}:{SESSION}");
    let log_path = root.join("daemon.log");
    let mut daemon = Daemon::start(
        &dir,
        &archive,
        &[
            "--record",
            &record,
            "--archive-time-evidence",
            "--archive-calibration-journal",
            journal.to_str().unwrap(),
            "--archive-trace-record",
            "50:1",
            "--archive-trace-clock",
            "5:boot:1000",
            "--archive-calibration-wait",
            "0s",
            "--archive-seal-interval",
            "200ms",
            "--trace-mirror-records",
            "2",
        ],
        &log_path,
    );
    let mut traced = Traced::new(&dir);
    traced.connected();
    // Bursts the driver drains many records of at once into two slots.
    for _ in 0..20 {
        traced.publish(50);
    }
    std::thread::sleep(Duration::from_millis(500));
    drop(traced);
    assert!(daemon.stop().success(), "{}", log(&log_path));
    let text = log(&log_path);
    let losses: u64 = text
        .lines()
        .find(|line| line.contains("trace mirror published"))
        .and_then(|line| line.split("losses=").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("{text}"));
    assert!(losses > 0, "no overwrite: {text}");

    let output = Command::new(env!("CARGO_BIN_EXE_karyos-catalog"))
        .arg("verify")
        .arg(&archive)
        .args(["--time-requirement", "1000000000:1000", "--time-anchors"])
        .arg(format!("{}={}", hex(&OPERATOR), time_anchors.display()))
        .output()
        .unwrap();
    let shown = String::from_utf8_lossy(&output.stdout).into_owned();
    let lines: Vec<&str> = shown
        .lines()
        .filter(|line| line.contains(" loss journal "))
        .collect();
    assert!(
        !lines.is_empty(),
        "{shown}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for line in &lines {
        assert!(line.ends_with(" no_evidence"), "{line}");
        // Each overwrite's journal is known: the client's, never 0.
        assert!(!line.contains(" loss journal 0 "), "{line}");
    }
    assert!(
        shown.contains("time verdict: no_evidence (capture incomplete: "),
        "{shown}"
    );
    assert!(!shown.contains(" met\n"), "{shown}");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&dir);
}
