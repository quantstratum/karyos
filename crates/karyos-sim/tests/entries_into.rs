// SPDX-License-Identifier: Apache-2.0

//! The borrowed log read (karyos#681, ADR-0105): a second
//! [`RaftLog::entries_into`] or [`LogView::entries_into`] of the same range
//! into the buffers the first one filled allocates nothing, and reads what
//! [`RaftLog::entries`] reads.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use karyos_archive::disk::StdDisk;
use karyos_archive::segment::Geometry;
use karyos_cluster::{Entry, RaftLog};
use karyos_sim::harness::core::{LogView, ReadBudget};
use karyos_sys::alloc_count::{CountingAllocator, SetCounts, enroll, window};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("karyos-entries-into-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A log of 40 entries of varied sizes in one segment, so a read takes
/// both the window path and the last frame's read alone. One segment: a
/// read that crosses segments reopens the store's reader file, which
/// allocates its path; that is the segment store's, not this read's.
fn log(dir: &TempDir) -> (RaftLog<StdDisk>, Vec<Entry>) {
    let geometry = Geometry::with_default_length(65_536).unwrap();
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry, 1).unwrap();
    let written: Vec<Entry> = (1..=40u64)
        .map(|index| Entry {
            index,
            term: 1 + index / 16,
            event_time: index * 1_000,
            payload: vec![u8::try_from(index).unwrap(); usize::try_from(index * 37).unwrap()],
        })
        .collect();
    assert_eq!(log.append(&written).unwrap(), Some(40));
    log.sync().unwrap();
    (log, written)
}

const NOTHING: SetCounts = SetCounts {
    allocations: 0,
    frees: 0,
};

#[test]
fn a_second_read_of_the_same_range_allocates_nothing() {
    let _serial = serial();
    let dir = TempDir::new("log");
    let (mut log, written) = log(&dir);
    let (mut out, mut buffer) = (Vec::new(), Vec::new());
    log.entries_into(1..41, u64::MAX, &mut out, &mut buffer)
        .unwrap();
    assert_eq!(out, written);
    assert_eq!(out, log.entries(1..41, u64::MAX).unwrap());
    let (read, counts) = window(|| {
        let _enrolled = enroll();
        log.entries_into(1..41, u64::MAX, &mut out, &mut buffer)
    })
    .unwrap();
    read.unwrap();
    assert_eq!(counts, NOTHING);
    assert_eq!(out, written);
    // A shorter read after it reuses the pool and ends with its own.
    log.entries_into(3..5, u64::MAX, &mut out, &mut buffer)
        .unwrap();
    assert_eq!(out, written.get(2..4).unwrap());
    // A byte budget stops where `entries` stops.
    log.entries_into(1..41, 600, &mut out, &mut buffer).unwrap();
    assert_eq!(out, log.entries(1..41, 600).unwrap());
}

#[test]
fn a_second_metered_view_read_allocates_nothing() {
    let _serial = serial();
    let dir = TempDir::new("view");
    let (mut log, written) = log(&dir);
    let budget = ReadBudget::new();
    let (mut out, mut buffer) = (Vec::new(), Vec::new());
    budget.refill(u64::MAX);
    LogView::metered(&mut log, Some(&budget))
        .entries_into(1..41, u64::MAX, &mut out, &mut buffer)
        .unwrap();
    assert_eq!(out, written);
    budget.refill(u64::MAX);
    let (read, counts) = window(|| {
        let _enrolled = enroll();
        LogView::metered(&mut log, Some(&budget)).entries_into(
            1..41,
            u64::MAX,
            &mut out,
            &mut buffer,
        )
    })
    .unwrap();
    read.unwrap();
    assert_eq!(counts, NOTHING);
    assert_eq!(out, written);
    // A refused read leaves nothing behind.
    budget.refill(0);
    assert!(
        LogView::metered(&mut log, Some(&budget))
            .entries_into(1..41, u64::MAX, &mut out, &mut buffer)
            .is_err()
    );
    assert!(out.is_empty());
}

/// Reads that cross segments still allocate (the store reopens its reader
/// file per crossing, with its path; ADR-0105's (c) removes it), but
/// per crossing, never per entry: 400 entries over a few 4 KiB segments
/// must count far fewer allocations than entries.
#[test]
fn a_read_across_segments_allocates_per_crossing_not_per_entry() {
    let _serial = serial();
    let dir = TempDir::new("cross");
    let geometry = Geometry::new(4096, 4096).unwrap();
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry, 1).unwrap();
    let written: Vec<Entry> = (1..=400u64)
        .map(|index| Entry {
            index,
            term: 1,
            event_time: index,
            payload: vec![7; 60],
        })
        .collect();
    assert_eq!(log.append(&written).unwrap(), Some(400));
    log.sync().unwrap();
    let bytes: u64 = written
        .iter()
        .map(|entry| entry.encoded_len().unwrap())
        .sum();
    let segments = bytes / 4096 + 1;
    let (mut out, mut buffer) = (Vec::new(), Vec::new());
    log.entries_into(1..401, u64::MAX, &mut out, &mut buffer)
        .unwrap();
    let (read, counts) = window(|| {
        let _enrolled = enroll();
        log.entries_into(1..401, u64::MAX, &mut out, &mut buffer)
    })
    .unwrap();
    read.unwrap();
    assert_eq!(out, written);
    // At most a few allocations per segment the read enters.
    assert!(
        counts.allocations <= 8 * segments,
        "{counts:?} over {segments} segments"
    );
    assert!(8 * segments < 400 / 2);
}

/// A byte budget that admits exactly `out`'s capacity in entries, with
/// another entry after them, takes no slot for the one it stops at: the
/// read allocates nothing (karyos#1209 review).
#[test]
fn a_budget_that_stops_at_the_pool_capacity_allocates_nothing() {
    let _serial = serial();
    let dir = TempDir::new("capacity");
    let (mut log, written) = log(&dir);
    let budget: u64 = written
        .iter()
        .skip(36)
        .take(3)
        .map(|entry| entry.encoded_len().unwrap())
        .sum();
    let (mut out, mut buffer) = (Vec::new(), Vec::new());
    // Stops at entry 40, the log's last, read alone: its header is
    // checked, then the budget refuses it.
    log.entries_into(37..41, budget, &mut out, &mut buffer)
        .unwrap();
    assert_eq!(out.len(), 3);
    out.shrink_to_fit();
    assert_eq!(out.capacity(), 3);
    let (read, counts) = window(|| {
        let _enrolled = enroll();
        log.entries_into(37..41, budget, &mut out, &mut buffer)
    })
    .unwrap();
    read.unwrap();
    assert_eq!(counts, NOTHING);
    assert_eq!(out, written.get(36..39).unwrap());
}

/// A frame that fails its check after valid ones leaves nothing in
/// `out`, through the log and through a metered view, whose budget stays
/// charged (karyos#1209 review).
#[test]
fn a_failure_after_valid_frames_leaves_nothing() {
    let _serial = serial();
    let dir = TempDir::new("failure");
    let (mut log, written) = log(&dir);
    // Entry 40's payload is 1480 bytes of 40: flip one of them on disk.
    let run = vec![40u8; 1480];
    let segment = std::fs::read_dir(&dir.0)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "seg"))
        .unwrap();
    let mut bytes = std::fs::read(&segment).unwrap();
    let at = bytes
        .windows(run.len())
        .position(|window| window == run.as_slice())
        .unwrap();
    *bytes.get_mut(at + 100).unwrap() ^= 0xff;
    std::fs::write(&segment, &bytes).unwrap();
    let (mut out, mut buffer) = (written.clone(), Vec::new());
    assert!(
        log.entries_into(1..41, u64::MAX, &mut out, &mut buffer)
            .is_err()
    );
    assert!(out.is_empty());
    let budget = ReadBudget::new();
    budget.refill(u64::MAX);
    out.clone_from(&written);
    assert!(
        LogView::metered(&mut log, Some(&budget))
            .entries_into(1..41, u64::MAX, &mut out, &mut buffer)
            .is_err()
    );
    assert!(out.is_empty());
    assert!(budget.left() < u64::MAX);
}
