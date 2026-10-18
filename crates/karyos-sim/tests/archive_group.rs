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
    ClaimCommit, DeliveryOutcome, Dispatched, Effects, Event, GroupGateway, PublicationId, TimerId,
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
        ClaimCommit {
            claim: Outcome::BackPressured,
            commit: None,
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
const JOURNAL: JournalConfig = JournalConfig {
    segment_length: MIN_SEGMENT_LENGTH,
    policy: SyncPolicy::Every { interval_ns: 0 },
};

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
        .start(StartRecording {
            stream_id: STREAM,
            session_id: 1,
            channel: b"karyos:ipc".to_vec(),
            geometry: Geometry::new(MIN_TERM_LENGTH, 2 * u64::from(MIN_TERM_LENGTH)).unwrap(),
            policy: SyncPolicy::Every { interval_ns: 0 },
            mode: Mode::Required,
            format: format(),
            source: Box::new(Guarded::new(reader, lease)),
        })
        .unwrap();
    let word = archive
        .recording_word(STREAM, 1, Lane::ZERO)
        .unwrap()
        .unwrap();
    assert_eq!(word.read().map(|(id, _)| id), Some(recording));
    let sender = archive
        .start_group(StartGroup {
            group_id: 1,
            dir: groups.clone(),
            new: Some(NewGroup {
                first_group_seq: 1,
                inline_threshold: 64,
                capture: Capture::Strict,
                manifest: b"e2e".to_vec(),
            }),
            journal: JOURNAL,
            capture: CaptureConfig {
                ring_capacity: 1 << 16,
                max_event: 4096,
                in_flight: 64,
            },
            checkpoints: None,
        })
        .unwrap();
    let waiter = sender.waiter();
    let started = Instant::now();
    let clock = move || u64::try_from(started.elapsed().as_nanos()).unwrap();
    let mut gateway = Gateway::new(Inert, clock, sender, Capture::Strict, 1, 4096, 4).unwrap();
    gateway.set_inline_threshold(64);
    let subscription = driver.subscribe(handle, Role::Required).unwrap();
    let identity = SourceIdentity {
        incarnation: 1,
        stream_id: STREAM,
        session_id: 1,
        lane: Lane::ZERO,
    };
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
        &ReplayConfig {
            manifest: b"e2e",
            accept_manifest: false,
        },
        CursorConfig {
            bytes: 1 << 16,
            records: 64,
        },
    )
    .unwrap();
    let mut replay = ReplayGateway::new(
        cursor,
        &GatewayConfig {
            publications: &[],
            subscriptions: &[(STREAM, 1)],
            conflated: &[],
            max_claim: 64,
            max_payload: 4096,
            present_unavailable: false,
        },
        Some(Archive {
            disk: StdDisk,
            dir: dir.path().to_path_buf(),
            recordings: vec![(
                recording,
                Geometry::new(MIN_TERM_LENGTH, 2 * u64::from(MIN_TERM_LENGTH)).unwrap(),
            )],
        }),
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
