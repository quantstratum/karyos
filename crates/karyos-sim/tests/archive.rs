// SPDX-License-Identifier: Apache-2.0

//! The Archive recording a driver's streams end to end (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A4c). The host wiring of §4: the
//! driver hands out a lane's reader, its generation link and the lease
//! that keeps its stream (`recording_reader`, `into_following_parts`), the
//! host passes them to the Archive's agent as a `Guarded` source over a
//! `Following` reader, which follows the stream's cutovers, and the agent
//! records it on its own thread.
//!
//! - A required recording of fragmented messages, an aborted claim and a
//!   term end: the segments hold every block where the log does,
//!   byte-exact against a second reader of the same log, and the abort and
//!   the padding are fills.
//! - An async recording lapped before it reads: it records the gap,
//!   rejoins at the head and records what follows.
//! - A restart of the agent lists both, stopped at their seals.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use karyos_archive::agent::{AgentConfig, ArchiveHandle, Event, StartRecording};
use karyos_archive::catalog::{StopReason, StreamFormat};
use karyos_archive::disk::StdDisk;
use karyos_archive::recorder::{FrameSource, Frames, Mode, OnLap, SourceError};
use karyos_archive::segment::{Geometry, SegmentStore, SyncPolicy};
use karyos_archive::source::{Following, Guarded};
use karyos_client::{ClaimOutcome, ClientPublication, OfferOutcome};
use karyos_driver::embedded::{EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    CanonicalKind, LogBufferConfig, LossPolicy, PublicationMode, ReadError, ReadOrigin,
    ReadOutcome, Role, SealState,
};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::HeapTerms;

const TERM: usize = MIN_TERM_LENGTH as usize;

/// A temporary archive directory, removed when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "karyos-sim-archive-{name}-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
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

/// The recorded streams' format, as the host knows it from their config.
fn format() -> StreamFormat {
    StreamFormat {
        lane: karyos_sys::frame::Lane::ZERO,
        initial_term_id: 7,
        mtu: core::num::NonZeroU32::new(karyos_sys::sizing::DEFAULT_MTU).unwrap(),
        source: karyos_archive::catalog::SourceIncarnation {
            driver: [1, 2],
            registration: 3,
            incarnation: 1,
        },
    }
}

fn stream(stream_id: i32) -> StreamConfig {
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
            stream_id,
            claim_deadline: 1_000_000_000,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

fn geometry() -> Geometry {
    Geometry::new(MIN_TERM_LENGTH, 2 * u64::from(MIN_TERM_LENGTH)).unwrap()
}

/// One block a reader met: where, and the bytes the log holds there (a
/// copy's frames, or a fill's canonical record).
#[derive(Debug)]
struct Block {
    position: u64,
    bytes: Vec<u8>,
    fill: Option<CanonicalKind>,
}

/// Reads and acknowledges everything committed; returns whether the
/// reader stands at the seal.
fn drain(reader: &mut karyos_driver::agents::data::LaneReader, blocks: &mut Vec<Block>) -> bool {
    let mut out = vec![0u8; TERM];
    loop {
        let from = reader.position();
        match reader.read_committed(from, ReadOrigin::Cursor, &mut out) {
            Ok(ReadOutcome::Copied { len, next }) => {
                blocks.push(Block {
                    position: from,
                    bytes: out[..len].to_vec(),
                    fill: None,
                });
                reader.sent(next).unwrap();
            }
            Ok(ReadOutcome::Canonical { record, next }) => {
                blocks.push(Block {
                    position: from,
                    bytes: out[..32].to_vec(),
                    fill: Some(record),
                });
                reader.sent(next).unwrap();
            }
            Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => {
                return reader.seal_position() == Some(reader.position());
            }
            Err(error) => panic!("{error:?}"),
        }
    }
}

/// Offers `payload`, draining the shadow reader and running the driver
/// while the publisher is held back.
fn offer(
    driver: &mut EmbeddedDriver<HeapTerms>,
    publication: &mut ClientPublication,
    shadow: &mut karyos_driver::agents::data::LaneReader,
    blocks: &mut Vec<Block>,
    payload: &[u8],
) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match publication.offer(payload).unwrap() {
            OfferOutcome::Accepted { .. } => return,
            OfferOutcome::BackPressured | OfferOutcome::AdminAction => {
                drain(shadow, blocks);
                driver.do_work().unwrap();
                assert!(Instant::now() < deadline, "the publisher never moved");
                std::thread::yield_now();
            }
            other => panic!("{other:?}"),
        }
    }
}

/// A source that publishes where it resumed after a lap, so the test
/// publishes what must follow the rejoin only once it happened.
struct Watched<S> {
    source: S,
    resumed: Arc<AtomicU64>,
}

impl<S: FrameSource> FrameSource for Watched<S> {
    fn position(&self) -> u64 {
        self.source.position()
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        self.source.read(out)
    }

    fn consumed(&mut self, position: u64) -> Result<(), SourceError> {
        self.source.consumed(position)
    }

    fn resume(&mut self, to: u64) -> Result<u64, SourceError> {
        let resumed = self.source.resume(to)?;
        self.resumed.store(resumed, Ordering::Release);
        Ok(resumed)
    }
}

/// Offers `payload` on a publication no reader bounds, running the driver
/// through term rotations.
fn offer_free(
    driver: &mut EmbeddedDriver<HeapTerms>,
    publication: &mut ClientPublication,
    payload: &[u8],
) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match publication.offer(payload).unwrap() {
            OfferOutcome::Accepted { .. } => break,
            OfferOutcome::AdminAction | OfferOutcome::BackPressured => {
                assert!(Instant::now() < deadline, "the publisher never moved");
            }
            other => panic!("{other:?}"),
        }
        driver.do_work().unwrap();
    }
    driver.do_work().unwrap();
}

/// Removes the stream (its buffer is sealed) and waits for the agent's
/// `Ended` event of `id`; returns it with the seal position the stream's
/// conductor set (the recording's lease keeps the stream until then).
fn seal_and_wait(
    driver: &mut EmbeddedDriver<HeapTerms>,
    handle: StreamHandle,
    archive: &ArchiveHandle,
    id: u64,
) -> (karyos_archive::recorder::Ended, Option<u64>) {
    driver.remove_stream(handle).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut seal = None;
    loop {
        driver.do_work().unwrap();
        if let Ok(SealState::Positioned { position } | SealState::Retired { position }) =
            driver.seal_state(handle)
        {
            seal = Some(position);
        }
        match archive.event(Duration::from_millis(10)) {
            Some(Event::Ended {
                id: ended_id,
                ended,
            }) if ended_id == id => return (ended, seal),
            Some(Event::Failed { id, failure, .. }) => {
                panic!("recording {id} failed: {failure:?}")
            }
            _ => assert!(Instant::now() < deadline, "recording {id} never ended"),
        }
    }
}

#[test]
fn the_archive_records_driver_streams_end_to_end() {
    let dir = TempDir::new("e2e");
    let mut driver = EmbeddedDriver::new().unwrap();
    let archive = ArchiveHandle::spawn(StdDisk, dir.path(), AgentConfig::default()).unwrap();

    // A required recording, and the test's own reader of the same log.
    let required = driver.add_stream(stream(42)).unwrap();
    let (mut shadow, shadow_lease) = driver
        .recording_reader(required, Role::Required)
        .unwrap()
        .into_parts();
    let (reader, link, base, lease) = driver
        .recording_reader(required, Role::Required)
        .unwrap()
        .into_following_parts();
    let first = archive
        .start(StartRecording {
            stream_id: 42,
            session_id: 1,
            channel: b"karyos:ipc".to_vec(),
            geometry: geometry(),
            policy: SyncPolicy::PerSegment,
            mode: Mode::Required,
            format: format(),
            source: Box::new(Guarded::new(Following::new(reader, link, base), lease)),
        })
        .unwrap();
    let mut publication = driver.publication(required).unwrap();
    let mut blocks = Vec::new();
    // Fragmented and whole messages across three terms, with aborted
    // claims among them.
    let mut published = 0;
    let mut index = 0u8;
    while published < 3 * TERM {
        index = index.wrapping_add(1);
        let length = [100, 5000, 900, 2900][usize::from(index) % 4];
        offer(
            &mut driver,
            &mut publication,
            &mut shadow,
            &mut blocks,
            &vec![index; length],
        );
        published += length;
        if index.is_multiple_of(7) {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match publication.try_claim(200).unwrap() {
                    ClaimOutcome::Claimed(claim) => {
                        claim.abort();
                        break;
                    }
                    ClaimOutcome::BackPressured | ClaimOutcome::AdminAction => {
                        drain(&mut shadow, &mut blocks);
                        driver.do_work().unwrap();
                        assert!(Instant::now() < deadline, "the publisher never moved");
                        std::thread::yield_now();
                    }
                    other => panic!("{other:?}"),
                }
            }
        }
    }
    drop(publication);
    let (ended, _) = seal_and_wait(&mut driver, required, &archive, first);
    while !drain(&mut shadow, &mut blocks) {
        driver.do_work().unwrap();
    }
    assert_eq!(ended.reason, StopReason::Normal);
    assert!(!ended.incomplete);
    assert_eq!(Some(ended.position), shadow.seal_position());
    drop((shadow, shadow_lease));

    // An async recording whose reader is lapped before the agent reads it.
    let lapped = driver.add_stream(stream(43)).unwrap();
    let (reader, link, base, lease) = driver
        .recording_reader(lapped, Role::Optional)
        .unwrap()
        .into_following_parts();
    let mut publication = driver.publication(lapped).unwrap();
    let resumed = Arc::new(AtomicU64::new(u64::MAX));
    for i in 0..5 * TERM / 1000 {
        offer_free(
            &mut driver,
            &mut publication,
            &[u8::try_from(i % 251).unwrap(); 1000],
        );
    }
    let second = archive
        .start(StartRecording {
            stream_id: 43,
            session_id: 1,
            channel: b"karyos:ipc".to_vec(),
            geometry: geometry(),
            policy: SyncPolicy::PerSegment,
            mode: Mode::Async {
                on_lap: OnLap::Resume,
            },
            format: format(),
            source: Box::new(Watched {
                source: Guarded::new(Following::new(reader, link, base), lease),
                resumed: Arc::clone(&resumed),
            }),
        })
        .unwrap();
    // What follows the rejoin is recorded.
    let deadline = Instant::now() + Duration::from_secs(30);
    while resumed.load(Ordering::Acquire) == u64::MAX {
        driver.do_work().unwrap();
        assert!(Instant::now() < deadline, "the recording never rejoined");
        std::thread::sleep(Duration::from_millis(1));
    }
    let rejoined = resumed.load(Ordering::Acquire);
    let tail = [0xEEu8; 700];
    offer_free(&mut driver, &mut publication, &tail);
    drop(publication);
    let (lapped_end, lapped_seal) = seal_and_wait(&mut driver, lapped, &archive, second);
    assert_eq!(
        Some(lapped_end.position),
        lapped_seal,
        "ends at stream 43's seal"
    );
    assert_eq!(lapped_end.reason, StopReason::Normal);
    assert!(lapped_end.incomplete, "the lap is a recorded loss");
    archive.shutdown().unwrap();

    // The required recording: every block where the log holds it.
    let mut store = SegmentStore::recover(
        StdDisk,
        dir.path(),
        first,
        geometry(),
        SyncPolicy::PerSegment,
    )
    .unwrap()
    .store;
    assert!(store.gaps().is_empty());
    let mut aborted = 0;
    let mut padding = 0;
    for block in &blocks {
        let mut held = vec![0u8; block.bytes.len()];
        store.read(block.position, &mut held).unwrap();
        assert_eq!(held, block.bytes, "block at {}", block.position);
        match block.fill {
            Some(CanonicalKind::Aborted) => aborted += 1,
            Some(CanonicalKind::Pad) => padding += 1,
            None => {}
        }
    }
    assert!(aborted > 0, "an abort was recorded as a fill");
    assert!(padding > 0, "a term end was recorded as a fill");
    assert!(
        blocks.iter().any(|block| block.bytes.len() > 5000),
        "fragments"
    );

    // The async recording: a gap from its start, then the tail.
    let mut store = SegmentStore::recover(
        StdDisk,
        dir.path(),
        second,
        geometry(),
        SyncPolicy::PerSegment,
    )
    .unwrap()
    .store;
    let gaps = store.gaps().to_vec();
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    let (from, to) = gaps[0];
    assert_eq!((from, to), (0, rejoined), "one gap, up to the rejoin");
    assert!(
        to > 4 * u64::try_from(TERM).unwrap(),
        "lapped by five terms: {to}"
    );
    let mut after = vec![0u8; usize::try_from(lapped_end.position - to).unwrap()];
    store.read(to, &mut after).unwrap();
    assert!(
        after.windows(tail.len()).any(|window| window == tail),
        "the message after the rejoin is recorded"
    );

    // A restart lists both, stopped at their seals.
    let archive = ArchiveHandle::spawn(StdDisk, dir.path(), AgentConfig::default()).unwrap();
    let recordings = archive.recordings().unwrap();
    assert_eq!(recordings.len(), 2);
    let stops: Vec<_> = recordings
        .iter()
        .map(|recording| {
            let stop = recording.stop.unwrap();
            (
                recording.id,
                recording.stream_id,
                stop.position,
                stop.reason,
            )
        })
        .collect();
    assert_eq!(
        stops,
        vec![
            (first, 42, ended.position, StopReason::Normal),
            (second, 43, lapped_end.position, StopReason::Normal),
        ]
    );
    archive.shutdown().unwrap();
}
