// SPDX-License-Identifier: Apache-2.0

//! An Archive recording across a mapping cutover (SPEC.md §13 "Cutover
//! with backlog", the Archive half; quantstratum-docs:
//! karyos/design/mapping-generations.md, "Recordings"), with a manual
//! clock. An `async` recording that lags by up to its window when the
//! mapping is sealed drains to the seal and continues on the successor,
//! every byte at its stream position; one paused past the cutover deadline
//! is fenced, without delaying the cutover, and ends at the seal.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_archive::catalog::StopReason;
use karyos_archive::disk::StdDisk;
use karyos_archive::recorder::{Mode, OnLap, Recorder};
use karyos_archive::segment::{Geometry, SegmentStore, SyncPolicy};
use karyos_archive::source::Following;
use karyos_client::OfferOutcome;
use karyos_driver::{
    DriverConfig, EmbeddedDriver, MonotonicClock, Reconfiguration, StreamConfig, StreamHandle,
};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

const DEADLINE: u64 = 100;
/// A message: a 32-byte header and this payload make one 1024-byte frame.
const PAYLOAD: usize = 992;
const FRAME: u64 = 1024;

#[derive(Debug, Clone, Default)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::Relaxed);
    }
}

impl MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A temporary directory, removed when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "karyos-sim-cutover-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
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

fn driver() -> (EmbeddedDriver, ManualClock) {
    let clock = ManualClock::default();
    let config = DriverConfig {
        cutover_deadline: DEADLINE,
        ..DriverConfig::default()
    };
    let driver = EmbeddedDriver::with_clock(config, Box::new(clock.clone())).unwrap();
    (driver, clock)
}

fn stream(driver: &mut EmbeddedDriver) -> StreamHandle {
    driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 6,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 11,
                claim_deadline: 50,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        })
        .unwrap()
}

fn larger() -> Reconfiguration {
    Reconfiguration {
        term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
        spare_slots: 5,
    }
}

fn payload(index: u64) -> Vec<u8> {
    vec![u8::try_from(index % 251).unwrap(); PAYLOAD]
}

/// An `async` recording of `stream` from its reader, with its link.
fn recording(
    driver: &mut EmbeddedDriver,
    stream: StreamHandle,
    dir: &Path,
    budget: u64,
) -> Recorder<StdDisk, Following> {
    let reader = driver.recording_reader(stream, Role::Optional).unwrap();
    let (link, base) = (Arc::clone(reader.link()), reader.base());
    let (reader, lease) = reader.into_parts();
    // The stream's lease lives as long as the test's driver.
    std::mem::forget(lease);
    let store =
        SegmentStore::create(StdDisk, dir, 1, geometry(), SyncPolicy::PerSegment, base).unwrap();
    Recorder::new(
        store,
        Following::new(reader, link, base),
        Mode::Async {
            on_lap: OnLap::Resume,
        },
        // The copy buffer: one frame at least, as `budget` is.
        usize::try_from(budget.min(1 << 16)).unwrap(),
        budget,
    )
    .unwrap()
}

/// Offers `index`'s payload until accepted, running the driver; returns
/// its stream position.
fn publish(
    driver: &mut EmbeddedDriver,
    writer: &mut karyos_client::ClientPublication,
    index: u64,
) -> u64 {
    loop {
        match writer.offer(&payload(index)).unwrap() {
            OfferOutcome::Accepted { position, .. } => return position,
            OfferOutcome::BackPressured | OfferOutcome::AdminAction => {
                let _ = driver.do_work().unwrap();
            }
            other => panic!("{other:?}"),
        }
    }
}

fn geometry() -> Geometry {
    Geometry::new(MIN_TERM_LENGTH, 4 * u64::from(MIN_TERM_LENGTH)).unwrap()
}

/// The payload recorded at stream position `position`, read once the
/// recorder is dropped.
fn recorded(dir: &Path, position: u64) -> Vec<u8> {
    recorded_in(dir, 1, position)
}

/// [`recorded`], of recording `id`.
fn recorded_in(dir: &Path, id: u64, position: u64) -> Vec<u8> {
    let mut store = SegmentStore::recover(StdDisk, dir, id, geometry(), SyncPolicy::PerSegment)
        .unwrap()
        .store;
    let mut bytes = vec![0u8; PAYLOAD];
    store.read(position + 32, &mut bytes).unwrap();
    bytes
}

#[test]
fn a_lagging_async_recording_drains_to_the_seal_and_continues_on_the_successor() {
    let dir = TempDir::new("follow");
    let (mut driver, _clock) = driver();
    let stream = stream(&mut driver);
    let mut recorder = recording(&mut driver, stream, dir.path(), 1 << 20);
    let mut writer = driver.publication(stream).unwrap();
    // The recording reads nothing while the writer fills its whole window.
    let window = u64::from(MIN_TERM_LENGTH / 2);
    let before = window / FRAME;
    for index in 0..before {
        assert_eq!(publish(&mut driver, &mut writer, index), index * FRAME);
        let _ = driver.do_work().unwrap();
    }
    let _ = driver.reconfigure_stream(stream, larger()).unwrap();
    // The writer moves to the successor once the seal is positioned.
    let after = 8u64;
    let mut positions = Vec::new();
    for index in before..before + after {
        positions.push(publish(&mut driver, &mut writer, index));
    }
    let seal = driver.generations(stream).unwrap()[0].seal.unwrap();
    assert_eq!(seal, window, "the recording lagged its whole window");
    assert_eq!(positions[0], seal, "the successor starts at the seal");
    // The recording drains the backlog to the seal and follows.
    let end = positions[positions.len() - 1] + FRAME;
    for _ in 0..64 {
        let duty = recorder.duty(0).unwrap();
        assert_eq!(duty.ended, None);
        assert!(!duty.fenced);
        let _ = driver.do_work().unwrap();
        if recorder.store().written() == end {
            break;
        }
    }
    assert_eq!(recorder.store().written(), end);
    assert!(recorder.store().gaps().is_empty());
    drop(recorder);
    for index in 0..before {
        assert_eq!(recorded(dir.path(), index * FRAME), payload(index));
    }
    for (offset, &position) in positions.iter().enumerate() {
        let index = before + u64::try_from(offset).unwrap();
        assert_eq!(recorded(dir.path(), position), payload(index));
    }
    // Admitted: the predecessor is released.
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.generations(stream).unwrap().len(), 1);
}

#[test]
fn a_paused_recording_is_fenced_without_delaying_the_cutover() {
    let dir = TempDir::new("fenced");
    let (mut driver, clock) = driver();
    let stream = stream(&mut driver);
    let mut recorder = recording(&mut driver, stream, dir.path(), 1 << 20);
    let mut writer = driver.publication(stream).unwrap();
    let before = 4u64;
    for index in 0..before {
        let _ = publish(&mut driver, &mut writer, index);
    }
    let _ = driver.reconfigure_stream(stream, larger()).unwrap();
    // The writer moves while the recording is paused: the cutover opens
    // without it.
    let first = publish(&mut driver, &mut writer, before);
    let seal = driver.generations(stream).unwrap()[0].seal.unwrap();
    assert_eq!(first, seal);
    // A deadline with no progress: fenced.
    clock.set(DEADLINE);
    let _ = driver.do_work().unwrap();
    // It resumes: it records the predecessor to the seal, then ends there.
    let mut ended = None;
    let mut fenced = false;
    for _ in 0..16 {
        let duty = recorder.duty(0).unwrap();
        fenced |= duty.fenced;
        if duty.ended.is_some() {
            ended = duty.ended;
            break;
        }
    }
    assert!(fenced);
    let ended = ended.unwrap();
    assert_eq!(
        (ended.position, ended.reason, ended.incomplete),
        (seal, StopReason::Lapped, true)
    );
    drop(recorder);
    for index in 0..before {
        assert_eq!(recorded(dir.path(), index * FRAME), payload(index));
    }
    // The writer went on meanwhile, on the successor.
    let next = publish(&mut driver, &mut writer, before + 1);
    assert_eq!(next, seal + FRAME);
}

/// The cutover deadline is the recording's progress lease: a recording
/// that drains its backlog one frame per duty, across several deadlines,
/// renews it at each step and is admitted, never fenced.
#[test]
fn a_recording_draining_across_deadlines_keeps_its_lease() {
    let dir = TempDir::new("lease");
    let (mut driver, clock) = driver();
    let stream = stream(&mut driver);
    let mut recorder = recording(&mut driver, stream, dir.path(), FRAME);
    let mut writer = driver.publication(stream).unwrap();
    let before = 6u64;
    for index in 0..before {
        let _ = publish(&mut driver, &mut writer, index);
    }
    let _ = driver.reconfigure_stream(stream, larger()).unwrap();
    let first = publish(&mut driver, &mut writer, before);
    let seal = driver.generations(stream).unwrap()[0].seal.unwrap();
    // One frame per duty, a little less than a deadline apart.
    let mut now = 0;
    for _ in 0..before + 2 {
        now += DEADLINE - 1;
        clock.set(now);
        let duty = recorder.duty(0).unwrap();
        assert!(!duty.fenced, "fenced while draining");
        assert_eq!(duty.ended, None);
        let _ = driver.do_work().unwrap();
    }
    assert!(now > 2 * DEADLINE, "the drain spanned several deadlines");
    assert_eq!(recorder.store().written(), first + FRAME);
    assert!(recorder.store().gaps().is_empty());
    assert_eq!(first, seal);
}

/// The documented host wiring, through the Archive's agent: a
/// `Guarded` source over a `Following` reader, from
/// `into_following_parts`, records across a cutover on the agent's own
/// thread, every byte at its stream position and no gap, and no fence is
/// counted.
#[test]
fn the_agent_records_across_a_cutover_through_its_documented_wiring() {
    use std::time::{Duration, Instant};

    use karyos_archive::agent::{AgentConfig, ArchiveHandle, StartRecording};
    use karyos_archive::catalog::{SourceIncarnation, StreamFormat};
    use karyos_archive::source::Guarded;

    let dir = TempDir::new("agent");
    let (mut driver, _clock) = driver();
    let stream = stream(&mut driver);
    let (reader, link, base, lease) = driver
        .recording_reader(stream, Role::Optional)
        .unwrap()
        .into_following_parts();
    let archive = ArchiveHandle::spawn(StdDisk, dir.path(), AgentConfig::default()).unwrap();
    let id = archive
        .start(StartRecording::new(
            11,
            1,
            b"karyos:ipc".to_vec(),
            geometry(),
            SyncPolicy::PerSegment,
            Mode::Async {
                on_lap: OnLap::Resume,
            },
            StreamFormat {
                lane: Lane::ZERO,
                initial_term_id: 7,
                mtu: core::num::NonZeroU32::new(DEFAULT_MTU).unwrap(),
                source: SourceIncarnation {
                    driver: [1, 2],
                    registration: 3,
                    incarnation: 1,
                },
            },
            Box::new(Guarded::new(Following::new(reader, link, base), lease)),
        ))
        .unwrap();
    let mut writer = driver.publication(stream).unwrap();
    let before = 6u64;
    for index in 0..before {
        let _ = publish(&mut driver, &mut writer, index);
    }
    let _ = driver.reconfigure_stream(stream, larger()).unwrap();
    let mut positions = Vec::new();
    for index in before..before + 6 {
        positions.push(publish(&mut driver, &mut writer, index));
    }
    let seal = driver.generations(stream).unwrap()[0].seal.unwrap();
    assert_eq!(positions[0], seal);
    let end = positions[positions.len() - 1] + FRAME;
    let deadline = Instant::now() + Duration::from_secs(30);
    while archive.describe(id).unwrap().end < end {
        let _ = driver.do_work().unwrap();
        assert!(Instant::now() < deadline, "the agent never reached {end}");
        std::thread::sleep(Duration::from_millis(1));
    }
    let ended = archive.stop(id).unwrap();
    assert_eq!((ended.position, ended.incomplete), (end, false));
    assert_eq!(archive.fenced_recordings(), 0);
    archive.shutdown().unwrap();
    for index in 0..before {
        assert_eq!(recorded_in(dir.path(), id, index * FRAME), payload(index));
    }
    for (offset, &position) in positions.iter().enumerate() {
        let index = before + u64::try_from(offset).unwrap();
        assert_eq!(recorded_in(dir.path(), id, position), payload(index));
    }
}
