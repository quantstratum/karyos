// SPDX-License-Identifier: Apache-2.0

//! A recording group over a driver, end to end (quantstratum-docs:
//! karyos/design/recording-group-gateway.md, section 11). The Archive
//! records a stream as `required`; a strict group's Gateway takes the same
//! stream's messages from a subscription, places the large payloads by
//! reference to that recording through its word and the small ones
//! inline, and the group's journal, once durable and recovered, holds
//! every message in order with its position and extent.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karyos_archive::agent::{AgentConfig, ArchiveHandle, NewGroup, StartGroup, StartRecording};
use karyos_archive::catalog::StreamFormat;
use karyos_archive::disk::StdDisk;
use karyos_archive::group::capture::CaptureConfig;
use karyos_archive::group::gateway::live::{Gateway, Port, SourceIdentity};
use karyos_archive::group::gateway::{
    ClaimCommit, DeliveryOutcome, Dispatched, Effects, Event, GroupGateway, Handler, PublicationId,
    TimerId,
};
use karyos_archive::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use karyos_archive::group::prefix::{Coverage, recover};
use karyos_archive::group::record::{Capture, GroupRecord, Outcome, Payload};
use karyos_archive::group::replay::gateway::{Archive, GatewayConfig, ReplayGateway};
use karyos_archive::group::replay::{CursorConfig, ReplayConfig, ReplayCursor};
use karyos_archive::recorder::Mode;
use karyos_archive::segment::{Geometry, SyncPolicy};
use karyos_archive::source::Guarded;
use karyos_client::OfferOutcome;
use karyos_driver::embedded::{EmbeddedDriver, StreamConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

/// A temporary archive directory, removed when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        // Unique within the process too: an elapsed time read at once is
        // about 0 for every caller.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "karyos-sim-group-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The handlers here act on nothing.
struct Inert;

impl Port for Inert {
    fn publication(&self, _: PublicationId) -> (i32, i32) {
        (0, 0)
    }
    fn offer(&mut self, _: PublicationId, _: &[u8]) -> Outcome {
        Outcome::BackPressured
    }
    fn claim(
        &mut self,
        _: PublicationId,
        _: usize,
        _: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> ClaimCommit {
        ClaimCommit::new(Outcome::BackPressured, None)
    }
    fn poll_outcomes(
        &mut self,
        _: PublicationId,
        _: u32,
        _: &mut dyn FnMut(&DeliveryOutcome),
    ) -> u32 {
        0
    }
    fn schedule(&mut self, _: TimerId, _: u64) {}
    fn cancel(&mut self, _: TimerId) {}
}

/// Coverage that vouches for every reference: the recording is closed
/// and holds every frame.
struct All;
impl Coverage for All {
    fn positions(&self, _: u64) -> Option<(u64, u64)> {
        Some((u64::MAX, u64::MAX))
    }
    fn ended(&self, _: u64) -> Option<u64> {
        None
    }
}

const STREAM: i32 = 42;
const MESSAGES: u64 = 24;
const JOURNAL: JournalConfig =
    JournalConfig::new(MIN_SEGMENT_LENGTH, SyncPolicy::Every { interval_ns: 0 });

fn stream() -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 6,
            max_subscribers: 8,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: STREAM,
            claim_deadline: 1_000_000_000,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

fn format() -> StreamFormat {
    StreamFormat {
        lane: Lane::ZERO,
        initial_term_id: 7,
        mtu: core::num::NonZeroU32::new(DEFAULT_MTU).unwrap(),
        source: karyos_archive::catalog::SourceIncarnation {
            driver: [1, 2],
            registration: 3,
            incarnation: 1,
        },
    }
}

/// The payload of message `index`: large ones go by reference.
fn payload(index: u64) -> Vec<u8> {
    let byte = u8::try_from(index % 251).unwrap();
    if index.is_multiple_of(2) {
        vec![byte; 32]
    } else {
        vec![byte; 600]
    }
}

#[test]
fn a_strict_group_records_a_driver_stream_end_to_end() {
    let dir = TempDir::new("e2e");
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(&groups).unwrap();
    let mut driver = EmbeddedDriver::new().unwrap();
    let archive = ArchiveHandle::spawn(StdDisk, dir.path(), AgentConfig::default()).unwrap();
    let handle = driver.add_stream(stream()).unwrap();
    let (reader, lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
    let recording = archive
        .start(StartRecording::new(
            STREAM,
            1,
            b"karyos:ipc".to_vec(),
            Geometry::new(MIN_TERM_LENGTH, 2 * u64::from(MIN_TERM_LENGTH)).unwrap(),
            SyncPolicy::Every { interval_ns: 0 },
            Mode::Required,
            format(),
            Box::new(Guarded::new(reader, lease)),
        ))
        .unwrap();
    let word = archive
        .recording_word(STREAM, 1, Lane::ZERO)
        .unwrap()
        .unwrap();
    assert_eq!(word.read().map(|(id, _)| id), Some(recording));
    let sender = archive
        .start_group({
            let mut value = StartGroup::new(
                1,
                groups.clone(),
                JOURNAL,
                CaptureConfig::new(1 << 16, 4096, 64),
            );
            value.new = Some(NewGroup::new(1, 64, Capture::Strict, b"e2e".to_vec()));
            value
        })
        .unwrap();
    let waiter = sender.waiter();
    let started = Instant::now();
    let clock = move || u64::try_from(started.elapsed().as_nanos()).unwrap();
    let mut gateway = Gateway::new(Inert, clock, sender, Capture::Strict, 1, 4096, 4).unwrap();
    gateway.set_inline_threshold(64);
    let subscription = driver.subscribe(handle, Role::Required).unwrap();
    let identity = SourceIdentity::new(1, STREAM, 1, Lane::ZERO);
    let _ = gateway
        .add_subscription(Box::new(subscription), identity, word)
        .unwrap();
    let mut publication = driver.publication(handle).unwrap();
    let mut seen = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
        if let Event::Message {
            position,
            length,
            extent,
            payload: presented,
            ..
        } = event
        {
            let index = u64::try_from(seen.len()).unwrap();
            let expected = payload(index);
            assert_eq!(
                usize::try_from(*length).unwrap(),
                expected.len(),
                "length {index}"
            );
            // Its frames: the payload behind a 32-byte header, aligned.
            assert!(
                usize::try_from(*extent).unwrap() >= expected.len() + 32,
                "extent {index}: {extent}"
            );
            match presented {
                karyos_archive::group::gateway::MessagePayload::Bytes(bytes) => {
                    assert_eq!(*bytes, &expected[..], "bytes {index}");
                }
                other => panic!("{index}: {other:?}"),
            }
            seen.push(*position);
        }
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut published = 0;
    let mut dispatched = 0;
    while dispatched < MESSAGES {
        if published < MESSAGES {
            match publication.offer(&payload(published)).unwrap() {
                OfferOutcome::Accepted { .. } => published += 1,
                OfferOutcome::BackPressured | OfferOutcome::AdminAction => {}
                other => panic!("{other:?}"),
            }
        }
        driver.do_work().unwrap();
        match gateway.dispatch(&mut handler) {
            Ok(Dispatched::Event { .. }) => dispatched += 1,
            Ok(_) | Err(karyos_archive::group::gateway::GatewayError::Refused(_)) => {}
            Err(error) => panic!("{error:?}"),
        }
        assert!(
            Instant::now() < deadline,
            "the group never took every message"
        );
    }
    // Durable once the recording holds and has synced every referenced
    // frame, and the journal has synced every event.
    let durable = loop {
        driver.do_work().unwrap();
        match waiter.wait_durable(MESSAGES, Duration::from_millis(20)) {
            Ok(durable) => break durable,
            Err(_) => assert!(Instant::now() < deadline, "the group never became durable"),
        }
    };
    assert_eq!(durable, MESSAGES);
    archive.stop_group(1).unwrap();
    drop(publication);
    drop(gateway);
    archive.shutdown().unwrap();

    let mut journal = GroupJournal::recover(StdDisk, &groups, 1, JOURNAL)
        .unwrap()
        .journal;
    let mut messages = Vec::new();
    journal
        .walk(0, |_, _, record| {
            if let GroupRecord::Message(message) = record {
                let by_reference = match message.payload {
                    Payload::Reference { recording_id, .. } => {
                        assert_eq!(recording_id, recording);
                        true
                    }
                    Payload::Inline(_) => false,
                    Payload::Unavailable { .. } => panic!("unavailable"),
                    other => panic!("unexpected {other:?}"),
                };
                messages.push((
                    message.group_seq,
                    message.position,
                    message.extent,
                    by_reference,
                ));
            }
            true
        })
        .unwrap();
    assert_eq!(messages.len(), usize::try_from(MESSAGES).unwrap());
    for (index, (group_seq, position, _, by_reference)) in messages.iter().enumerate() {
        assert_eq!(*group_seq, u64::try_from(index).unwrap() + 1);
        assert_eq!(*position, seen[index]);
        // The large ones, every other message, by reference.
        assert_eq!(*by_reference, index % 2 == 1, "message {index}");
    }
    for pair in messages.windows(2) {
        assert_eq!(pair[0].1 + u64::from(pair[0].2), pair[1].1);
    }

    // Replay the journal: every message as published, the references read
    // back from the recording.
    let mut journal = GroupJournal::recover(StdDisk, &groups, 1, JOURNAL)
        .unwrap()
        .journal;
    let recovery = recover(&mut journal, &All, 64).unwrap();
    let cursor = ReplayCursor::open(
        journal,
        &recovery,
        &ReplayConfig::new(b"e2e"),
        CursorConfig::new(1 << 16, 64),
    )
    .unwrap();
    let mut replay = ReplayGateway::new(
        cursor,
        &GatewayConfig::new()
            .with_subscriptions(&[(STREAM, 1, Lane::ZERO)])
            .with_max_claim(64)
            .with_max_payload(4096),
        Some(Archive::new(
            StdDisk,
            dir.path().to_path_buf(),
            vec![(
                recording,
                Geometry::new(MIN_TERM_LENGTH, 2 * u64::from(MIN_TERM_LENGTH)).unwrap(),
            )],
        )),
    )
    .unwrap();
    let mut replayed = Vec::new();
    let mut probe = |event: &Event<'_>, _: &mut dyn Effects| {
        if let Event::Message {
            position,
            length,
            extent,
            payload: karyos_archive::group::gateway::MessagePayload::Bytes(bytes),
            ..
        } = event
        {
            replayed.push((*position, *length, *extent, bytes.to_vec()));
        }
    };
    loop {
        match replay.dispatch(&mut probe) {
            Ok(Dispatched::Event { .. }) => {}
            Ok(Dispatched::End) => break,
            other => panic!("replay: {other:?} after {}", replayed.len()),
        }
    }
    assert_eq!(replayed.len(), messages.len());
    for (index, (position, length, extent, bytes)) in replayed.iter().enumerate() {
        assert_eq!(*position, messages[index].1, "position {index}");
        assert_eq!(*extent, messages[index].2, "extent {index}");
        assert_eq!(
            usize::try_from(*length).unwrap(),
            bytes.len(),
            "length {index}"
        );
        assert_eq!(
            bytes,
            &payload(u64::try_from(index).unwrap()),
            "bytes {index}"
        );
    }
}

/// The output stream the isolation test's handler acts on.
const OUT: i32 = 43;

/// The real output publication, shared by the live port and the test,
/// which keeps it open through the replay.
type Shared = std::sync::Arc<std::sync::Mutex<karyos_client::ClientPublication>>;

/// The live Gateway's port over the driver's real output publication.
struct DriverPort(Shared);

/// A client offer's outcome as the group records it.
fn recorded(outcome: OfferOutcome) -> Outcome {
    match outcome {
        OfferOutcome::Accepted { lane, position } => Outcome::Accepted { lane, position },
        OfferOutcome::BackPressured => Outcome::BackPressured,
        OfferOutcome::AdminAction => Outcome::AdminAction,
        OfferOutcome::NotConnected => Outcome::NotConnected,
        other => panic!("{other:?}"),
    }
}

impl Port for DriverPort {
    fn publication(&self, _: PublicationId) -> (i32, i32) {
        (OUT, 1)
    }
    fn offer(&mut self, _: PublicationId, payload: &[u8]) -> Outcome {
        recorded(self.0.lock().unwrap().offer(payload).unwrap())
    }
    fn claim(
        &mut self,
        _: PublicationId,
        length: usize,
        write: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> ClaimCommit {
        use karyos_client::{ClaimOutcome, CommitOutcome};
        let mut publication = self.0.lock().unwrap();
        match publication
            .try_claim(u32::try_from(length).unwrap())
            .unwrap()
        {
            ClaimOutcome::Claimed(mut claim) => {
                let (lane, position) = (claim.lane(), claim.position());
                if write(claim.payload()) {
                    let commit = match claim.commit() {
                        CommitOutcome::Accepted { lane, position } => {
                            Outcome::Accepted { lane, position }
                        }
                        CommitOutcome::Aborted { lane, position } => {
                            Outcome::Aborted { lane, position }
                        }
                    };
                    ClaimCommit::new(Outcome::Accepted { lane, position }, Some(commit))
                } else {
                    claim.abort();
                    ClaimCommit::new(
                        Outcome::Accepted { lane, position },
                        Some(Outcome::Aborted { lane, position }),
                    )
                }
            }
            ClaimOutcome::BackPressured => ClaimCommit::new(Outcome::BackPressured, None),
            ClaimOutcome::AdminAction => ClaimCommit::new(Outcome::AdminAction, None),
            other => panic!("{other:?}"),
        }
    }
    fn poll_outcomes(
        &mut self,
        _: PublicationId,
        _: u32,
        _: &mut dyn FnMut(&DeliveryOutcome),
    ) -> u32 {
        0
    }
    fn schedule(&mut self, _: TimerId, _: u64) {}
    fn cancel(&mut self, _: TimerId) {}
}

/// The handler of the isolation test: every message is answered by one
/// offer and one claimed, committed message on the output publication.
fn answer(event: &Event<'_>, effects: &mut dyn Effects) {
    if let Event::Message { position, .. } = event {
        let _ = effects.offer(PublicationId(0), &position.to_le_bytes());
        let _ = effects.claim(PublicationId(0), 8, &mut |bytes| {
            bytes.copy_from_slice(&position.to_le_bytes());
            true
        });
    }
}

/// What the driver's counters show of its streams, positions and
/// clients: every cell but the sampling pass's own epoch and time.
fn driver_cells(driver: &EmbeddedDriver) -> Vec<(usize, String, u64)> {
    use karyos_sys::counters::CellRead;
    let reader = driver.counters();
    (0..reader.capacity())
        .filter_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } => {
                let label = String::from_utf8_lossy(metadata.label()).into_owned();
                // The sampling pass and the duty time move with every duty
                // cycle, replay or not.
                (!label.starts_with("positions ") && label != "conductor duty at")
                    .then_some((index, label, value))
            }
            _ => None,
        })
        .collect()
}

/// The value of the driver's counter `label`.
fn driver_counter(cells: &[(usize, String, u64)], label: &str) -> Vec<u64> {
    cells
        .iter()
        .filter(|(_, name, _)| name.starts_with(label))
        .map(|(_, _, value)| *value)
        .collect()
}

/// Isolation of external effects (SPEC §15, phase 3; the phase 3 gate
/// status, gap 5): a group whose handler offers and claims on a driver's
/// publication is recorded live, then replayed from its first event over
/// the same driver, running. Replay answers every offer and claim from
/// the record, so nothing reaches the driver: every one of its counters
/// (the output stream's head, limit and floor, its subscriber's
/// position, the streams, leases, clients, commands and claims) reads as
/// before the replay, and the output subscriber receives nothing. The
/// cells that moved while recording (each stream's head and limit, the
/// output subscriber's position among them) are checked one by one, so
/// none passes by never moving.
#[test]
fn a_replayed_group_reaches_nothing_of_a_running_driver() {
    use karyos_archive::group::prefix::{Coverage, recover};
    use karyos_archive::group::record::MAX_RECORD;
    use karyos_archive::group::replay::gateway::{GatewayConfig, ReplayGateway};
    use karyos_archive::group::replay::{CursorConfig, ReplayConfig, ReplayCursor};
    use karyos_client::MessageLimit;

    /// Every payload is inline: no recording vouches for a reference.
    struct Inline;
    impl Coverage for Inline {
        fn positions(&self, _: u64) -> Option<(u64, u64)> {
            None
        }
        fn ended(&self, _: u64) -> Option<u64> {
            None
        }
    }

    let dir = TempDir::new("isolation");
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(&groups).unwrap();
    // Positions sampled every cycle (every 1 ns), so an offer shows at
    // once.
    let mut driver = EmbeddedDriver::with_config(karyos_driver::DriverConfig {
        position_sample_interval: 1,
        ..karyos_driver::DriverConfig::default()
    })
    .unwrap();
    let archive = ArchiveHandle::spawn(StdDisk, dir.path(), AgentConfig::default()).unwrap();
    let input = driver.add_stream(stream()).unwrap();
    let output = driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                stream_id: OUT,
                ..stream().buffer
            },
            ..stream()
        })
        .unwrap();
    let sender = archive
        .start_group({
            let mut value = StartGroup::new(
                1,
                groups.clone(),
                JOURNAL,
                CaptureConfig::new(1 << 16, 4096, 64),
            );
            value.new = Some(NewGroup::new(1, 4096, Capture::Strict, b"iso".to_vec()));
            value
        })
        .unwrap();
    let waiter = sender.waiter();
    let started = Instant::now();
    let clock = move || u64::try_from(started.elapsed().as_nanos()).unwrap();
    // Open through the replay: a replay that reached it would publish.
    let real: Shared =
        std::sync::Arc::new(std::sync::Mutex::new(driver.publication(output).unwrap()));
    let port = DriverPort(std::sync::Arc::clone(&real));
    let mut gateway = Gateway::new(port, clock, sender, Capture::Strict, 1, 4096, 4).unwrap();
    let mut out_reader = driver.subscribe(output, Role::Required).unwrap();
    let identity = SourceIdentity::new(1, STREAM, 1, Lane::ZERO);
    let word = archive
        .recording_word(STREAM, 1, Lane::ZERO)
        .unwrap()
        .unwrap_or_default();
    let _ = gateway
        .add_subscription(
            Box::new(driver.subscribe(input, Role::Required).unwrap()),
            identity,
            word,
        )
        .unwrap();
    let mut publication = driver.publication(input).unwrap();
    // The cells as recording starts: the replay check compares the ones
    // that move while recording, so none of them passes by never moving.
    for _ in 0..10 {
        driver.do_work().unwrap();
    }
    let at_start = driver_cells(&driver);
    // Live: the handler's effects reach the driver, two per message.
    let deadline = Instant::now() + Duration::from_secs(30);
    let (mut published, mut dispatched, mut answered) = (0, 0, 0u64);
    let mut handler = answer;
    while dispatched < MESSAGES || answered < 2 * MESSAGES {
        if published < MESSAGES
            && let OfferOutcome::Accepted { .. } = publication.offer(&payload(published)).unwrap()
        {
            published += 1;
        }
        driver.do_work().unwrap();
        if let Ok(Dispatched::Event { .. }) = gateway.dispatch(&mut handler) {
            dispatched += 1;
        }
        let _ = out_reader
            .poll(|_, _| answered += 1, MessageLimit::new(16))
            .unwrap();
        assert!(Instant::now() < deadline, "live: {dispatched} {answered}");
    }
    let durable = loop {
        driver.do_work().unwrap();
        match waiter.wait_durable(MESSAGES, Duration::from_millis(20)) {
            Ok(durable) => break durable,
            Err(_) => assert!(Instant::now() < deadline, "never durable"),
        }
    };
    assert_eq!(durable, MESSAGES);
    archive.stop_group(1).unwrap();
    drop(publication);
    drop(gateway);
    archive.shutdown().unwrap();

    // Replay over the same driver, running: the output stream and its
    // subscriber stay; the driver settles first so its cells are stable.
    for _ in 0..100 {
        driver.do_work().unwrap();
    }
    let before = driver_cells(&driver);
    let moved: Vec<&(usize, String, u64)> = before
        .iter()
        .filter(|cell| {
            at_start
                .iter()
                .find(|start| start.0 == cell.0 && start.1 == cell.1)
                .is_none_or(|start| start.2 != cell.2)
        })
        .collect();
    // What the handler's offers and claims move: each stream's head and
    // limit, and the output subscriber's position.
    for label in ["stream head", "stream limit", "subscriber position"] {
        assert!(
            moved.iter().any(|(_, name, _)| name.starts_with(label)),
            "no {label} cell moved while recording: {moved:?}"
        );
    }
    // Exactly: one offer and one claim of 8 bytes per message, each a
    // 64-byte frame (its 32-byte header and payload, aligned), on the
    // output stream from 0; its subscriber read them all.
    let answers = 2 * MESSAGES * 64;
    let from_zero = |label: &str| {
        moved.iter().any(|(index, name, value)| {
            name.starts_with(label)
                && *value == answers
                && at_start
                    .iter()
                    .any(|start| start.0 == *index && start.2 == 0)
        })
    };
    assert!(from_zero("stream head"), "output head: {moved:?}");
    assert!(from_zero("subscriber position"), "output reader: {moved:?}");
    // `commands served` counts CnC commands; every call here is the
    // embedded driver's own, so it reads 0 throughout, and the full
    // comparison below holds it there.
    assert_eq!(driver_counter(&before, "commands served"), [0]);
    let mut journal = GroupJournal::recover(StdDisk, &groups, 1, JOURNAL)
        .unwrap()
        .journal;
    let recovery = recover(&mut journal, &Inline, 64).unwrap();
    let cursor = ReplayCursor::open(
        journal,
        &recovery,
        &ReplayConfig::new(b"iso"),
        CursorConfig::new(8 * MAX_RECORD, 8),
    )
    .unwrap();
    let mut replay = ReplayGateway::new(
        cursor,
        &GatewayConfig::new()
            .with_publications(&[(OUT, 1)])
            .with_subscriptions(&[(STREAM, 1, Lane::ZERO)])
            .with_max_claim(8)
            .with_max_payload(4096),
        None,
    )
    .unwrap();
    let mut replayed = 0u64;
    loop {
        driver.do_work().unwrap();
        match replay.dispatch(&mut handler) {
            Ok(Dispatched::Event { .. }) => replayed += 1,
            Ok(Dispatched::End) => break,
            other => panic!("replay: {other:?}"),
        }
        assert!(Instant::now() < deadline, "replay never ended");
    }
    assert_eq!(replayed, MESSAGES);
    for _ in 0..100 {
        driver.do_work().unwrap();
    }
    let mut extra = 0u64;
    let _ = out_reader
        .poll(|_, _| extra += 1, MessageLimit::new(64))
        .unwrap();
    assert_eq!(extra, 0, "replay published on the driver");
    let after = driver_cells(&driver);
    assert_eq!(
        driver_counter(&after, "stream head"),
        driver_counter(&before, "stream head")
    );
    for (index, label, value) in &moved {
        let now = after
            .iter()
            .find(|cell| cell.0 == *index && cell.1 == *label);
        assert_eq!(
            now.map(|cell| cell.2),
            Some(*value),
            "{label} moved during replay"
        );
    }
    assert_eq!(after, before, "the driver's counters moved during replay");
    drop(real);
}

/// The application's state in the checkpoint test: the messages it saw
/// and the sum of their payloads' first bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Tally {
    count: u64,
    sum: u64,
}

impl Tally {
    fn write(self, out: &mut [u8]) -> usize {
        out[..8].copy_from_slice(&self.count.to_le_bytes());
        out[8..16].copy_from_slice(&self.sum.to_le_bytes());
        16
    }
}

impl Handler for Tally {
    fn on_event(&mut self, event: &Event<'_>, effects: &mut dyn Effects) {
        if let Event::Message {
            payload: karyos_archive::group::gateway::MessagePayload::Bytes(bytes),
            ..
        } = event
        {
            self.count += 1;
            self.sum += u64::from(bytes[0]);
            // One observation per message, for replay to compare.
            let _ = effects.offer(PublicationId(0), &self.count.to_le_bytes());
        }
    }

    fn checkpoint(&mut self, out: &mut [u8]) -> Option<usize> {
        Some(self.write(out))
    }

    fn restore(&mut self, state: &[u8]) -> bool {
        let Ok(state) = <[u8; 16]>::try_from(state) else {
            return false;
        };
        self.count = u64::from_le_bytes(state[..8].try_into().unwrap());
        self.sum = u64::from_le_bytes(state[8..].try_into().unwrap());
        true
    }
}

/// A9: a strict group over a driver takes a checkpoint after event
/// `AT`; replay opens at that checkpoint, the application restores its
/// state from it, and the events after it bring the state to the live
/// run's. A checkpoint naming any other event than the last dispatched
/// leaves the replayed state off by one message.
#[test]
fn replay_from_a_checkpoint_reaches_the_live_state() {
    use karyos_archive::agent::GroupCheckpoints;
    use karyos_archive::group::checkpoint::{
        CheckpointStore, LastCheckpoint, recorded_end, store_dir,
    };
    use karyos_archive::group::prefix::{CheckpointHeld, Coverage, recover};
    use karyos_archive::group::record::MAX_RECORD;
    use karyos_archive::group::replay::gateway::{GatewayConfig, ReplayGateway};
    use karyos_archive::group::replay::{CursorConfig, ReplayConfig, ReplayCursor};

    const AT: u64 = 12;
    // A second checkpoint, which replay from the first compares.
    const SECOND: u64 = 18;
    let mut second = false;
    let dir = TempDir::new("checkpoint");
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(store_dir(&groups)).unwrap();
    let mut driver = EmbeddedDriver::new().unwrap();
    let archive = ArchiveHandle::spawn(StdDisk, dir.path(), AgentConfig::default()).unwrap();
    let handle = driver.add_stream(stream()).unwrap();
    let (reader, lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
    let _ = archive
        .start(StartRecording::new(
            STREAM,
            1,
            b"karyos:ipc".to_vec(),
            Geometry::new(MIN_TERM_LENGTH, 2 * u64::from(MIN_TERM_LENGTH)).unwrap(),
            SyncPolicy::Every { interval_ns: 0 },
            Mode::Required,
            format(),
            Box::new(Guarded::new(reader, lease)),
        ))
        .unwrap();
    let word = archive
        .recording_word(STREAM, 1, Lane::ZERO)
        .unwrap()
        .unwrap();
    let sender = archive
        .start_group({
            let mut value = StartGroup::new(
                1,
                groups.clone(),
                JOURNAL,
                CaptureConfig::new(1 << 16, 4096, 64),
            );
            value.new = Some(NewGroup::new(1, 4096, Capture::Strict, b"e2e".to_vec()));
            value.checkpoints = Some(GroupCheckpoints::new(64));
            value
        })
        .unwrap();
    let waiter = sender.waiter();
    let started = Instant::now();
    let clock = move || u64::try_from(started.elapsed().as_nanos()).unwrap();
    let mut gateway = Gateway::new(Inert, clock, sender, Capture::Strict, 1, 4096, 4).unwrap();
    gateway.set_inline_threshold(4096);
    let subscription = driver.subscribe(handle, Role::Required).unwrap();
    let identity = SourceIdentity::new(1, STREAM, 1, Lane::ZERO);
    let _ = gateway
        .add_subscription(Box::new(subscription), identity, word)
        .unwrap();
    let mut publication = driver.publication(handle).unwrap();
    let mut live = Tally::default();
    let mut at_checkpoint = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut published = 0;
    let mut dispatched = 0;
    while dispatched < MESSAGES {
        if published < MESSAGES {
            match publication
                .offer(&[u8::try_from(published + 1).unwrap(); 32])
                .unwrap()
            {
                OfferOutcome::Accepted { .. } => published += 1,
                OfferOutcome::BackPressured | OfferOutcome::AdminAction => {}
                other => panic!("{other:?}"),
            }
        }
        driver.do_work().unwrap();
        match gateway.dispatch(&mut live) {
            Ok(Dispatched::Event { .. }) => dispatched += 1,
            Ok(_) | Err(karyos_archive::group::gateway::GatewayError::Refused(_)) => {}
            Err(error) => panic!("{error:?}"),
        }
        if dispatched == AT && at_checkpoint.is_none() {
            gateway.checkpoint(1, |out| live.write(out)).unwrap();
            at_checkpoint = Some(live);
        }
        if dispatched == SECOND && !second {
            // The first is recorded before the second is taken: one in
            // flight.
            while !matches!(gateway.last_checkpoint(), Some(LastCheckpoint::Recorded(_))) {
                driver.do_work().unwrap();
                assert!(
                    Instant::now() < deadline,
                    "the first checkpoint never ended"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            gateway.checkpoint(1, |out| live.write(out)).unwrap();
            second = true;
        }
        assert!(
            Instant::now() < deadline,
            "the group never took every message"
        );
    }
    let last = loop {
        driver.do_work().unwrap();
        match gateway.last_checkpoint() {
            Some(LastCheckpoint::Recorded(record)) if record.group_seq == SECOND => break record,
            Some(failed @ LastCheckpoint::Failed { .. }) => panic!("{failed:?}"),
            _ => assert!(Instant::now() < deadline, "the checkpoint never ended"),
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    // Ids run from 1: the first checkpoint is 1, the second 2.
    assert_eq!(last.checkpoint_id, 2);
    let first_id = 1;
    let durable = loop {
        driver.do_work().unwrap();
        match waiter.wait_durable(MESSAGES, Duration::from_millis(20)) {
            Ok(durable) => break durable,
            Err(_) => assert!(Instant::now() < deadline, "the group never became durable"),
        }
    };
    assert_eq!(durable, MESSAGES);
    archive.stop_group(1).unwrap();
    drop(publication);
    drop(gateway);
    archive.shutdown().unwrap();

    struct Held<'a>(&'a CheckpointStore<StdDisk>);
    impl Coverage for Held<'_> {
        fn positions(&self, _: u64) -> Option<(u64, u64)> {
            None
        }
        fn ended(&self, _: u64) -> Option<u64> {
            None
        }
        fn checkpoint(&self, position: u64, end: u64) -> CheckpointHeld {
            self.0.holds(position, end)
        }
    }
    let mut journal = GroupJournal::recover(StdDisk, &groups, 1, JOURNAL)
        .unwrap()
        .journal;
    let end = recorded_end(&mut journal).unwrap();
    let mut store =
        CheckpointStore::recover(StdDisk, &store_dir(&groups), 1, JOURNAL, end).unwrap();
    let recovery = recover(&mut journal, &Held(&store), 64).unwrap();
    let mut snapshot = [0u8; 64];
    let (cursor, record) = ReplayCursor::open_at_checkpoint(
        journal,
        &recovery,
        &[],
        &mut store,
        first_id,
        &ReplayConfig::new(b"e2e"),
        CursorConfig::new(4 * MAX_RECORD, 8),
        &mut snapshot,
    )
    .unwrap();
    let mut replayed = Tally::default();
    assert_eq!(
        record.group_seq, AT,
        "the first checkpoint names event {AT}"
    );
    let mut gateway = ReplayGateway::new(
        cursor,
        &GatewayConfig::new()
            .with_publications(&[(0, 0)])
            .with_subscriptions(&[(STREAM, 1, Lane::ZERO)]),
        None,
    )
    .unwrap()
    .with_state(64)
    .unwrap();
    // Replay restores the handler's state from the snapshot, before the
    // first dispatch.
    let length = usize::try_from(record.length).unwrap();
    gateway
        .restore(&record, &snapshot[..length], &mut replayed)
        .unwrap();
    assert_eq!(Some(replayed), at_checkpoint);
    let mut events = Vec::new();
    loop {
        match gateway.dispatch(&mut replayed).unwrap() {
            Dispatched::Event { group_seq } => events.push(group_seq),
            Dispatched::End => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(events, (AT + 1..=MESSAGES).collect::<Vec<_>>());
    assert_eq!(replayed, live);
}

/// A loopback UDP port no socket holds now, picked below every ephemeral
/// range (Linux 32768 to 60999, macOS 49152 to 65535), so no bind to port
/// 0 can take it before the driver binds it (karyos#520). As karyos-driver's
/// `test_ports` (#552): a process starts at its own offset and walks the
/// range, skipping ports it cannot bind.
fn test_port() -> u16 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    const FIRST: u32 = 20_000;
    const COUNT: u32 = 12_000;
    let start = std::process::id().wrapping_mul(2_654_435_761) % COUNT;
    loop {
        let taken = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(taken < COUNT, "no free test port left in the range");
        let port = u16::try_from(FIRST + (start + taken) % COUNT).unwrap();
        if std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}

/// A driver with a network, its agents run by the caller's duty cycles,
/// its positions sampled every cycle.
fn network_driver() -> EmbeddedDriver {
    EmbeddedDriver::with_config(karyos_driver::DriverConfig {
        network: Some(karyos_driver::net::NetworkConfig {
            threading: karyos_driver::agents::ThreadingMode::Shared,
            ..karyos_driver::net::NetworkConfig::default()
        }),
        position_sample_interval: 1,
        ..karyos_driver::DriverConfig::default()
    })
    .unwrap()
}

/// A reliable loopback channel to `port`.
fn loopback(port: u16) -> karyos_protocol::channel::UdpConfig {
    use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
    use std::net::{Ipv4Addr, SocketAddr};
    UdpConfig {
        retransmit_window: None,
        nak_control: Vec::new(),
        nak_control: Vec::new(),
        destination: Destination::Unicast(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
        interface: Some(Interface::Address(Ipv4Addr::LOCALHOST.into())),
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    }
}

/// How long the replay's "nothing reaches the network" is watched after
/// the replay ended, the drivers' duty cycles running throughout: far past
/// a loopback round trip and the sender's idle heartbeat.
const SETTLE: Duration = Duration::from_millis(500);

/// Isolation of external effects over the network (SPEC §15, phase 3;
/// contract-traceability-phase-3.md, the row's minor): a group whose
/// handler answers each message on a network publication of driver A is
/// recorded live while driver B's network subscription reads every
/// answer; then the group is replayed over the same two drivers, running.
/// Replay answers from the record, so nothing reaches the network: B's
/// reader receives nothing new over [`SETTLE`], and neither A's stream
/// heads nor B's subscriber positions move. The live phase is the control:
/// the same answers do cross the network.
#[test]
fn a_replayed_group_reaches_no_network_output() {
    use karyos_archive::group::record::MAX_RECORD;
    use karyos_archive::group::replay::gateway::{GatewayConfig, ReplayGateway};
    use karyos_archive::group::replay::{CursorConfig, ReplayConfig, ReplayCursor};
    use karyos_protocol::lanes::drr::Budget;

    /// Every payload is inline: no recording vouches for a reference.
    struct Inline;
    impl Coverage for Inline {
        fn positions(&self, _: u64) -> Option<(u64, u64)> {
            None
        }
        fn ended(&self, _: u64) -> Option<u64> {
            None
        }
    }
    let budget = Budget {
        work: 256,
        bytes: 1 << 20,
    };
    let work = |a: &mut EmbeddedDriver, b: &mut EmbeddedDriver| {
        a.do_work().unwrap();
        b.do_work().unwrap();
    };

    let dir = TempDir::new("network-isolation");
    let groups = dir.path().join("groups");
    std::fs::create_dir_all(&groups).unwrap();
    let mut driver = network_driver();
    let mut remote = network_driver();
    let archive = ArchiveHandle::spawn(StdDisk, dir.path(), AgentConfig::default()).unwrap();
    let input = driver.add_stream(stream()).unwrap();
    // The handler's output: a network publication of A, read by B.
    let port = test_port();
    let _ = remote
        .add_network_subscription(OUT, &loopback(port))
        .unwrap();
    let output = driver
        .add_network_publication(
            karyos_driver::AggregateConfig {
                stream: StreamConfig {
                    buffer: LogBufferConfig {
                        stream_id: OUT,
                        ..stream().buffer
                    },
                    ..stream()
                },
                quanta: vec![u64::from(DEFAULT_MTU) * 4],
            },
            &loopback(port),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let image = loop {
        work(&mut driver, &mut remote);
        if let Some(image) = remote.network_image(OUT, 1) {
            break image;
        }
        assert!(Instant::now() < deadline, "no image of the output on B");
    };
    let mut out_reader = remote.subscribe_aggregate(&image, Role::Required).unwrap();
    let sender = archive
        .start_group({
            let mut value = StartGroup::new(
                1,
                groups.clone(),
                JOURNAL,
                CaptureConfig::new(1 << 16, 4096, 64),
            );
            value.new = Some(NewGroup::new(1, 4096, Capture::Strict, b"net".to_vec()));
            value
        })
        .unwrap();
    let waiter = sender.waiter();
    let started = Instant::now();
    let clock = move || u64::try_from(started.elapsed().as_nanos()).unwrap();
    let real: Shared = std::sync::Arc::new(std::sync::Mutex::new(
        driver
            .publication(output.lane(Lane::ZERO).unwrap())
            .unwrap(),
    ));
    let port = DriverPort(std::sync::Arc::clone(&real));
    let mut gateway = Gateway::new(port, clock, sender, Capture::Strict, 1, 4096, 4).unwrap();
    let identity = SourceIdentity::new(1, STREAM, 1, Lane::ZERO);
    let word = archive
        .recording_word(STREAM, 1, Lane::ZERO)
        .unwrap()
        .unwrap_or_default();
    let _ = gateway
        .add_subscription(
            Box::new(driver.subscribe(input, Role::Required).unwrap()),
            identity,
            word,
        )
        .unwrap();
    let mut publication = driver.publication(input).unwrap();

    // Live: the handler's answers cross the network, two per message.
    let (mut published, mut dispatched, mut answered) = (0, 0, 0u64);
    let mut handler = answer;
    while dispatched < MESSAGES || answered < 2 * MESSAGES {
        if published < MESSAGES
            && let OfferOutcome::Accepted { .. } = publication.offer(&payload(published)).unwrap()
        {
            published += 1;
        }
        work(&mut driver, &mut remote);
        if let Ok(Dispatched::Event { .. }) = gateway.dispatch(&mut handler) {
            dispatched += 1;
        }
        let _ = out_reader.poll(|_, _, _| answered += 1, budget);
        assert!(Instant::now() < deadline, "live: {dispatched} {answered}");
    }
    assert_eq!(
        answered,
        2 * MESSAGES,
        "the live answers crossed the network"
    );
    let durable = loop {
        work(&mut driver, &mut remote);
        match waiter.wait_durable(MESSAGES, Duration::from_millis(20)) {
            Ok(durable) => break durable,
            Err(_) => assert!(Instant::now() < deadline, "never durable"),
        }
    };
    assert_eq!(durable, MESSAGES);
    archive.stop_group(1).unwrap();
    drop(publication);
    drop(gateway);
    archive.shutdown().unwrap();

    // Replay over the same drivers, running; the network output and B's
    // reader stay. The drivers settle first, so their positions are stable.
    for _ in 0..100 {
        work(&mut driver, &mut remote);
    }
    let heads = driver_counter(&driver_cells(&driver), "stream head");
    let positions = driver_counter(&driver_cells(&remote), "subscriber position");
    let mut journal = GroupJournal::recover(StdDisk, &groups, 1, JOURNAL)
        .unwrap()
        .journal;
    let recovery = recover(&mut journal, &Inline, 64).unwrap();
    let cursor = ReplayCursor::open(
        journal,
        &recovery,
        &ReplayConfig::new(b"net"),
        CursorConfig::new(8 * MAX_RECORD, 8),
    )
    .unwrap();
    let mut replay = ReplayGateway::new(
        cursor,
        &GatewayConfig::new()
            .with_publications(&[(OUT, 1)])
            .with_subscriptions(&[(STREAM, 1, Lane::ZERO)])
            .with_max_claim(8)
            .with_max_payload(4096),
        None,
    )
    .unwrap();
    let mut replayed = 0u64;
    loop {
        work(&mut driver, &mut remote);
        match replay.dispatch(&mut handler) {
            Ok(Dispatched::Event { .. }) => replayed += 1,
            Ok(Dispatched::End) => break,
            other => panic!("replay: {other:?}"),
        }
        assert!(Instant::now() < deadline, "replay never ended");
    }
    assert_eq!(replayed, MESSAGES);
    // Nothing reaches B over the settle window, the drivers running.
    let mut extra = 0u64;
    let settled = Instant::now() + SETTLE;
    while Instant::now() < settled {
        work(&mut driver, &mut remote);
        let _ = out_reader.poll(|_, _, _| extra += 1, budget);
        std::thread::sleep(Duration::from_micros(200));
    }
    assert_eq!(extra, 0, "replay published on the network");
    assert_eq!(
        driver_counter(&driver_cells(&driver), "stream head"),
        heads,
        "a stream head of A moved during replay"
    );
    assert_eq!(
        driver_counter(&driver_cells(&remote), "subscriber position"),
        positions,
        "a subscriber position of B moved during replay"
    );
    // The control: the same output still reaches B, so the silence above
    // is the replay's, not a dead path.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !matches!(
        real.lock().unwrap().offer(&[7u8; 8]).unwrap(),
        OfferOutcome::Accepted { .. }
    ) {
        work(&mut driver, &mut remote);
        assert!(Instant::now() < deadline, "the output refused an offer");
    }
    let mut after = 0u64;
    while after == 0 {
        work(&mut driver, &mut remote);
        let _ = out_reader.poll(|_, _, _| after += 1, budget);
        assert!(Instant::now() < deadline, "the output no longer reaches B");
    }
    drop(real);
}
