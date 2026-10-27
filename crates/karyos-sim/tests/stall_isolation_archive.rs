// SPDX-License-Identifier: Apache-2.0

//! SPEC.md §13 "Stall isolation and capacity" with the asynchronous
//! Archive among the stalled holders (karyos#673): two optional readers
//! and an observer paused inside their copies, an `async` Archive
//! recording paused inside its read, every loan held, and a paused claim,
//! on one concurrent lane, while an in-process publisher runs ten terms;
//! then one more admission arrives. No reader of the lane reads in order
//! for the publisher (no sender, no required reader), so the paused claim
//! holds no one (SPEC.md §13, clarified 2026-10-27).
//!
//! The readers pause through `PausePoint::ReadLoanHeld` and the recording
//! through `PausePoint::LaneReadLoanHeld`, hooks armed for the whole
//! process, so this test has its own binary.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    reason = "tests, as ADR-0007 allows; the log records what the run did"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use karyos_archive::disk::StdDisk;
use karyos_archive::recorder::{Mode, OnLap, Recorder};
use karyos_archive::segment::{Geometry, SegmentStore, SyncPolicy};
use karyos_archive::source::Following;
use karyos_client::concurrent::{ConcurrentClaimOutcome, ConcurrentOfferOutcome};
use karyos_client::{ClientSubscription, MessageLimit};
use karyos_driver::{DriverError, EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_sys::counters::CellRead;
use karyos_sys::error::SysError;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::test_pause::{self, PausePoint};

/// Spare slots `S`. Credits: two concurrent publishers, two optional
/// readers, the observer and the `async` recording make six, `S - 1` (one
/// slot of cleaning headroom): the lane is full, and one more admission is
/// refused.
const SPARES: u8 = 7;
const TERM: u64 = MIN_TERM_LENGTH as u64;
const PAYLOAD: usize = 1000;
/// A message's frame: its 32-byte header and payload, aligned to 32.
const FRAME: u64 = 1056;

/// Holders paused inside their copies.
static HOLDING: AtomicUsize = AtomicUsize::new(0);
/// Set once the run is over: the paused holders go on.
static GO: AtomicBool = AtomicBool::new(false);

/// The hook of both pause points: counts the pause and waits for [`GO`],
/// the holder's loan held.
fn hold_here(_: PausePoint) {
    HOLDING.fetch_add(1, Ordering::SeqCst);
    while !GO.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Waits until `count` holders paused.
fn paused(count: usize, what: &str) {
    for _ in 0..5000 {
        if HOLDING.load(Ordering::SeqCst) >= count {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("{what} did not pause");
}

/// A temporary directory, removed when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("karyos-sim-stall-{name}-{}", std::process::id()));
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

/// One concurrent lane of two publishers, `S` = 7, room for four readers,
/// and a claim deadline no run reaches, so the paused claim stays open.
fn stream(driver: &mut EmbeddedDriver) -> StreamHandle {
    driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: SPARES,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 11,
                claim_deadline: u64::MAX / 2,
                publication: PublicationMode::Concurrent {
                    publishers: 2,
                    allow_non_lse: true,
                },
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        })
        .unwrap()
}

fn geometry() -> Geometry {
    Geometry::new(MIN_TERM_LENGTH, 4 * TERM).unwrap()
}

/// The "slots quarantined" gauge: slots held out of rotation by a loan.
fn quarantined(driver: &EmbeddedDriver) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == b"slots quarantined" => Some(value),
            _ => None,
        })
        .unwrap()
}

/// A stalled reader: pauses inside its first copy with its loan held,
/// then, once released, polls until it is lapped. Returns the first
/// message it read and whether it was lapped.
fn stalled_reader(mut reader: ClientSubscription) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut first = None;
        for _ in 0..100_000 {
            let summary = reader
                .poll(
                    |bytes, _| {
                        if first.is_none() {
                            first = Some(bytes.to_vec());
                        }
                    },
                    MessageLimit::new(1),
                )
                .unwrap();
            if summary.overrun.is_some() {
                return (first.unwrap_or_default(), true);
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        (first.unwrap_or_default(), false)
    })
}

/// The `async` recording, stalled: its first duty pauses inside its read
/// with the loan held; once released it records on until it is lapped,
/// which an `async` recording marks as a gap and resumes past. Returns
/// whether it was lapped.
fn stalled_recording(mut recorder: Recorder<StdDisk, Following>) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || {
        for now in 0..100_000u64 {
            let _ = recorder.duty(now).unwrap();
            if !recorder.store().gaps().is_empty() {
                return true;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        false
    })
}

/// SPEC.md §13 "Stall isolation and capacity" with an asynchronous Archive
/// among the stalled holders: the publisher never gets `BackPressured` or
/// an error; slots held out of rotation never exceed `S`; the extra
/// admission is `ResourcesUnavailable`; every stalled holder, the
/// recording included, reads the bytes committed before the run
/// unchanged, and then is lapped.
#[test]
fn test_stall_isolation_an_asynchronous_archive_among_the_stalled_holders() {
    let dir = TempDir::new("archive");
    let mut driver = EmbeddedDriver::new().unwrap();
    let lane = stream(&mut driver);
    let mut running = driver.concurrent_publication(lane).unwrap();
    let mut paused_claim = driver.concurrent_publication(lane).unwrap();

    // The holders join at the head, then the message every one of them
    // copies first is committed.
    let readers: Vec<_> = [Role::Optional, Role::Optional, Role::Observer]
        .into_iter()
        .map(|role| driver.subscribe(lane, role).unwrap())
        .collect();
    let reader = driver.recording_reader(lane, Role::Optional).unwrap();
    let (link, base) = (Arc::clone(reader.link()), reader.base());
    let (reader, lease) = reader.into_parts();
    let store = SegmentStore::create(
        StdDisk,
        dir.path(),
        1,
        geometry(),
        SyncPolicy::PerSegment,
        base,
    )
    .unwrap();
    let recorder = Recorder::new(
        store,
        Following::new(reader, link, base),
        Mode::Async {
            on_lap: OnLap::Resume,
        },
        usize::try_from(TERM).unwrap(),
        TERM,
    )
    .unwrap();
    let first = [0x5au8; PAYLOAD];
    assert!(matches!(
        running.offer(&first).unwrap(),
        ConcurrentOfferOutcome::Accepted { position: 0, .. }
    ));

    // Each holder pauses in its copy of it, its loan held; each point is
    // armed again once the holder before paused, and nothing else reads.
    let mut stalled = Vec::new();
    for (index, reader) in readers.into_iter().enumerate() {
        test_pause::arm(PausePoint::ReadLoanHeld, hold_here);
        stalled.push(stalled_reader(reader));
        paused(index + 1, "a reader");
    }
    test_pause::arm(PausePoint::LaneReadLoanHeld, hold_here);
    let recording = stalled_recording(recorder);
    paused(4, "the recording");
    // The paused claim: reserved, never committed during the run.
    let ConcurrentClaimOutcome::Claimed(claim) = paused_claim.try_claim(64).unwrap() else {
        panic!("the claim was not granted");
    };

    // Ten terms from the in-process publisher.
    let messages = u32::try_from(10 * TERM / FRAME).unwrap();
    let mut sent = 0u32;
    let mut most_quarantined = 0;
    while sent < messages {
        let mut payload = [0u8; PAYLOAD];
        payload[..4].copy_from_slice(&sent.to_le_bytes());
        match running.offer(&payload) {
            Ok(ConcurrentOfferOutcome::Accepted { .. }) => sent += 1,
            Ok(ConcurrentOfferOutcome::AdminAction) => {}
            Ok(other) => panic!("message {sent}: {other:?} with stalled holders"),
            Err(error) => panic!("message {sent}: {error:?} with stalled holders"),
        }
        let _ = driver.do_work().unwrap();
        let held = quarantined(&driver);
        assert!(
            held <= u64::from(SPARES),
            "{held} slots held out of rotation"
        );
        most_quarantined = most_quarantined.max(held);
    }
    assert!(most_quarantined >= 1, "the held loans quarantined no slot");

    // One more admission: the lane's credits are spent.
    assert!(
        matches!(
            driver.subscribe(lane, Role::Optional),
            Err(DriverError::Sys(SysError::ResourcesUnavailable))
        ),
        "the extra admission is refused"
    );
    println!(
        "{messages} messages over ten terms past four stalled holders and a paused claim; \
         at most {most_quarantined} slots quarantined of {SPARES}"
    );

    // The stalled holders go on: each read the first message unchanged,
    // and is then lapped.
    GO.store(true, Ordering::SeqCst);
    for (index, reader) in stalled.into_iter().enumerate() {
        let (bytes, lapped) = reader.join().unwrap();
        assert_eq!(bytes, first, "reader {index} read the bytes it held");
        assert!(lapped, "reader {index} was not lapped");
    }
    assert!(recording.join().unwrap(), "the recording was not lapped");
    let mut store =
        SegmentStore::recover(StdDisk, dir.path(), 1, geometry(), SyncPolicy::PerSegment)
            .unwrap()
            .store;
    let mut recorded = vec![0u8; PAYLOAD];
    store.read(base + 32, &mut recorded).unwrap();
    assert_eq!(recorded, first, "the recording wrote the bytes it held");
    drop((claim, lease));
}
