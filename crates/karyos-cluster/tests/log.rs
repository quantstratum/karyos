// SPDX-License-Identifier: Apache-2.0

//! The durable Raft log and its hard state over the standard disk, in a
//! temporary directory (C4; the crash cases wait for C2's simulated disk,
//! listed in the `log` module):
//!
//! - round trips, across a reopen and across segments;
//! - written and durable positions, before and after a sync;
//! - suffix truncation and re-append, refused out-of-order appends;
//! - the hard state's round trip, a torn or damaged record refused, a
//!   commit above the durable index refused, a failed flush poisoning;
//! - a frame that breaks the chain refused at recovery, a torn tail cut.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use karyos_archive::disk::{Disk, StdDisk};
use karyos_archive::segment::{Geometry, SegmentStore, SyncPolicy};
use karyos_cluster::hard_state::{HARD_STATE_FILE, HardStateProblem};
use karyos_cluster::log::{FRAME_HEADER, LOG_RECORDING};
use karyos_cluster::{ChainProblem, Entry, HardState, LogError, RaftLog};

/// A test's directory, removed when it ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("karyos-c4-{}-{name}", std::process::id()));
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

fn geometry() -> Geometry {
    Geometry::with_default_length(65_536).unwrap()
}

/// One term per segment of 4 KiB: frames of a few KiB span segments.
fn small() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

fn entry(index: u64, term: u64, payload: &[u8]) -> Entry {
    Entry {
        index,
        term,
        event_time: index * 1_000,
        payload: payload.to_vec(),
    }
}

fn entries(range: std::ops::Range<u64>, term: u64) -> Vec<Entry> {
    range
        .map(|index| entry(index, term, format!("command {index}").as_bytes()))
        .collect()
}

fn open<D: Disk + Clone>(disk: D, dir: &Path, geometry: Geometry) -> RaftLog<D> {
    let opened = RaftLog::open(disk, dir, geometry).unwrap();
    assert_eq!(opened.cut, None);
    opened.log
}

#[test]
fn entries_round_trip_across_a_reopen() {
    let dir = TempDir::new("round-trip");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    assert_eq!((log.first_index(), log.last_index()), (1, 0));
    let mut written = entries(1..4, 1);
    written.extend(entries(4..6, 3));
    assert_eq!(log.append(&written).unwrap(), 5);
    assert_eq!(log.entries(1..6, u64::MAX).unwrap(), written);
    assert_eq!(log.entries(2..4, u64::MAX).unwrap(), written[1..3].to_vec());
    assert_eq!(
        (log.term(3), log.term(4), log.term(6), log.term(0)),
        (Some(1), Some(3), None, None)
    );
    log.sync().unwrap();
    drop(log);
    let mut log = open(StdDisk, &dir.0, geometry());
    assert_eq!(
        (log.first_index(), log.last_index(), log.durable_index()),
        (1, 5, 5)
    );
    assert_eq!(log.entries(1..6, u64::MAX).unwrap(), written);
}

#[test]
fn a_log_may_start_at_any_index() {
    let dir = TempDir::new("start");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 100).unwrap();
    assert_eq!(log.last_index(), 99);
    assert!(matches!(
        log.append(&entries(1..2, 1)),
        Err(LogError::NotNext {
            expected: 100,
            got: 1
        })
    ));
    assert_eq!(log.append(&entries(100..103, 1)).unwrap(), 102);
    log.truncate_suffix(100).unwrap();
    drop(log);
    // Emptied, it keeps its first index.
    let log = open(StdDisk, &dir.0, geometry());
    assert_eq!((log.first_index(), log.last_index()), (100, 99));
}

#[test]
fn entries_spanning_segments_round_trip_and_truncate() {
    let dir = TempDir::new("segments");
    let mut log = RaftLog::create(StdDisk, &dir.0, small(), 1).unwrap();
    let big: Vec<Entry> = (1..8)
        .map(|index| entry(index, 1, &[index as u8; 3000]))
        .collect();
    log.append(&big).unwrap();
    log.sync().unwrap();
    assert_eq!(log.entries(1..8, u64::MAX).unwrap(), big);
    log.truncate_suffix(4).unwrap();
    assert_eq!(log.last_index(), 3);
    log.append(&[entry(4, 2, &[9; 3000])]).unwrap();
    log.sync().unwrap();
    drop(log);
    let mut log = open(StdDisk, &dir.0, small());
    let mut expected = big[..3].to_vec();
    expected.push(entry(4, 2, &[9; 3000]));
    assert_eq!(log.entries(1..5, u64::MAX).unwrap(), expected);
}

/// `append` advances only the written position, `sync` the durable one,
/// each exactly to the frames' end.
#[test]
fn written_and_durable_positions_are_separate() {
    let dir = TempDir::new("positions");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    let written = entries(1..4, 1);
    let bytes: u64 = written
        .iter()
        .map(|entry| (FRAME_HEADER + entry.payload.len()) as u64)
        .sum();
    log.append(&written).unwrap();
    assert_eq!((log.written(), log.durable()), (bytes, 0));
    assert_eq!((log.last_index(), log.durable_index()), (3, 0));
    assert_eq!(log.sync().unwrap(), 3);
    assert_eq!((log.written(), log.durable()), (bytes, bytes));
    assert_eq!(log.durable_index(), 3);
    log.append(&entries(4..5, 1)).unwrap();
    assert_eq!((log.last_index(), log.durable_index()), (4, 3));
}

#[test]
fn a_truncated_suffix_is_appended_again() {
    let dir = TempDir::new("truncate");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    log.append(&entries(1..6, 1)).unwrap();
    log.truncate_suffix(3).unwrap();
    assert_eq!((log.last_index(), log.term(3)), (2, None));
    assert_eq!(log.durable_index(), 2, "what is kept is durable");
    assert!(matches!(
        log.append(&entries(5..6, 2)),
        Err(LogError::NotNext {
            expected: 3,
            got: 5
        })
    ));
    let rewritten = entries(3..5, 2);
    log.append(&rewritten).unwrap();
    log.sync().unwrap();
    assert!(matches!(
        log.truncate_suffix(9),
        Err(LogError::OutOfRange {
            index: 9,
            first: 1,
            last: 4
        })
    ));
    assert!(matches!(
        log.truncate_suffix(0),
        Err(LogError::OutOfRange { index: 0, .. })
    ));
    // At last_index + 1: nothing to remove.
    log.truncate_suffix(5).unwrap();
    drop(log);
    let mut log = open(StdDisk, &dir.0, geometry());
    let mut expected = entries(1..3, 1);
    expected.extend(rewritten);
    assert_eq!(log.entries(1..10, u64::MAX).unwrap(), expected);
}

#[test]
fn out_of_order_appends_are_refused_before_anything_is_written() {
    let dir = TempDir::new("order");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    log.append(&entries(1..3, 2)).unwrap();
    let written = log.written();
    // A gap after a valid entry: nothing of the batch is written.
    let mut batch = entries(3..4, 2);
    batch.extend(entries(5..6, 2));
    assert!(matches!(
        log.append(&batch),
        Err(LogError::NotNext {
            expected: 4,
            got: 5
        })
    ));
    assert!(matches!(
        log.append(&entries(3..4, 1)),
        Err(LogError::TermBack {
            index: 3,
            last: 2,
            got: 1
        })
    ));
    assert!(matches!(
        log.append(&entries(2..3, 2)),
        Err(LogError::NotNext {
            expected: 3,
            got: 2
        })
    ));
    assert_eq!((log.written(), log.last_index()), (written, 2));
    assert!(matches!(
        log.purge_prefix(2),
        Err(LogError::PurgeUnsupported)
    ));
}

#[test]
fn entries_stop_at_max_bytes_but_always_return_one() {
    let dir = TempDir::new("max-bytes");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    let written: Vec<Entry> = (1..5).map(|index| entry(index, 1, &[0; 100])).collect();
    log.append(&written).unwrap();
    assert_eq!(log.entries(1..5, 250).unwrap(), written[..2].to_vec());
    assert_eq!(log.entries(1..5, 200).unwrap(), written[..2].to_vec());
    assert_eq!(log.entries(1..5, 0).unwrap(), written[..1].to_vec());
    assert!(log.entries(5..9, u64::MAX).unwrap().is_empty());
}

#[test]
fn the_hard_state_round_trips() {
    let dir = TempDir::new("hard-state");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    assert_eq!(log.hard_state(), None);
    log.append(&entries(1..4, 1)).unwrap();
    log.sync().unwrap();
    let state = HardState {
        current_term: 7,
        voted_for: Some(3),
        commit: Some(2),
    };
    log.save_hard_state(state).unwrap();
    assert_eq!(log.hard_state(), Some(state));
    drop(log);
    let log = open(StdDisk, &dir.0, geometry());
    assert_eq!(log.hard_state(), Some(state));
    let none = HardState {
        current_term: 8,
        voted_for: None,
        commit: None,
    };
    assert_eq!(HardState::decode(&none.encode()), Ok(none));
}

/// A record the test writes torn, or damages, is refused at open, never
/// defaulted.
#[test]
fn a_torn_or_damaged_hard_state_is_refused() {
    let dir = TempDir::new("torn");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    log.save_hard_state(HardState {
        current_term: 4,
        voted_for: Some(1),
        commit: None,
    })
    .unwrap();
    drop(log);
    let path = dir.0.join(HARD_STATE_FILE);
    let whole = std::fs::read(&path).unwrap();
    std::fs::write(&path, &whole[..20]).unwrap();
    assert!(matches!(
        RaftLog::open(StdDisk, &dir.0, geometry()),
        Err(LogError::HardState(HardStateProblem::Length(20)))
    ));
    let mut damaged = whole.clone();
    damaged[9] ^= 1;
    std::fs::write(&path, &damaged).unwrap();
    assert!(matches!(
        RaftLog::open(StdDisk, &dir.0, geometry()),
        Err(LogError::HardState(HardStateProblem::Checksum))
    ));
    std::fs::write(&path, &whole).unwrap();
    assert!(RaftLog::open(StdDisk, &dir.0, geometry()).is_ok());
}

#[test]
fn a_commit_above_the_durable_index_is_refused() {
    let dir = TempDir::new("commit");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    log.append(&entries(1..4, 1)).unwrap();
    let state = HardState {
        current_term: 1,
        voted_for: None,
        commit: Some(2),
    };
    assert!(matches!(
        log.save_hard_state(state),
        Err(LogError::CommitBeyondDurable {
            commit: 2,
            durable: 0
        })
    ));
    assert_eq!(log.hard_state(), None, "nothing saved");
    log.sync().unwrap();
    log.save_hard_state(state).unwrap();
    assert!(matches!(
        log.save_hard_state(HardState {
            commit: Some(4),
            ..state
        }),
        Err(LogError::CommitBeyondDurable {
            commit: 4,
            durable: 3
        })
    ));
    // A stored commit above the log found at open is refused too: the
    // record is replaced behind the log's back.
    drop(log);
    let higher = HardState {
        commit: Some(9),
        ..state
    };
    std::fs::write(dir.0.join(HARD_STATE_FILE), higher.encode()).unwrap();
    assert!(matches!(
        RaftLog::open(StdDisk, &dir.0, geometry()),
        Err(LogError::CommitBeyondDurable {
            commit: 9,
            durable: 3
        })
    ));
}

/// Committed entries are never removed: a truncation at or below the
/// stored commit is refused, with nothing changed.
#[test]
fn a_truncation_below_the_commit_is_refused() {
    let dir = TempDir::new("below-commit");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    log.append(&entries(1..6, 1)).unwrap();
    log.sync().unwrap();
    log.save_hard_state(HardState {
        current_term: 1,
        voted_for: None,
        commit: Some(3),
    })
    .unwrap();
    let written = log.written();
    for from in [1, 3] {
        assert!(matches!(
            log.truncate_suffix(from),
            Err(LogError::TruncateBelowCommit { from: f, commit: 3 }) if f == from
        ));
    }
    assert_eq!((log.last_index(), log.written()), (5, written));
    log.truncate_suffix(4).unwrap();
    assert_eq!(log.last_index(), 3);
    assert_eq!(
        LogError::TruncateBelowCommit { from: 2, commit: 3 }.to_string(),
        "truncating from 2 would remove committed entries up to 3"
    );
}

/// The standard disk, whose syncs fail while `fail` is set.
#[derive(Debug, Clone, Default)]
struct FlakyDisk {
    fail: Arc<AtomicBool>,
}

impl FlakyDisk {
    fn check(&self) -> io::Result<()> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("sync failed"));
        }
        Ok(())
    }
}

impl Disk for FlakyDisk {
    type File = std::fs::File;

    fn create(&mut self, path: &Path) -> io::Result<Self::File> {
        StdDisk.create(path)
    }

    fn open(&mut self, path: &Path) -> io::Result<Self::File> {
        StdDisk.open(path)
    }

    fn open_read(&mut self, path: &Path) -> io::Result<Self::File> {
        StdDisk.open_read(path)
    }

    fn write_at(&mut self, file: &Self::File, offset: u64, bytes: &[u8]) -> io::Result<()> {
        StdDisk.write_at(file, offset, bytes)
    }

    fn read_at(&mut self, file: &Self::File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        StdDisk.read_at(file, offset, buf)
    }

    fn len(&mut self, file: &Self::File) -> io::Result<u64> {
        StdDisk.len(file)
    }

    fn set_len(&mut self, file: &Self::File, len: u64) -> io::Result<()> {
        StdDisk.set_len(file, len)
    }

    fn sync(&mut self, file: &Self::File) -> io::Result<()> {
        self.check()?;
        StdDisk.sync(file)
    }

    fn sync_dir(&mut self, dir: &Path) -> io::Result<()> {
        self.check()?;
        StdDisk.sync_dir(dir)
    }

    fn list(&mut self, dir: &Path) -> io::Result<Vec<String>> {
        StdDisk.list(dir)
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        StdDisk.remove(path)
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        StdDisk.rename(from, to)
    }
}

/// A failed flush of a hard-state save returns the error and poisons the
/// log: every later write is refused until it is reopened. A failed log
/// sync fails the store the same way.
#[test]
fn a_failed_flush_poisons_until_reopened() {
    let dir = TempDir::new("poison");
    let disk = FlakyDisk::default();
    let mut log = RaftLog::create(disk.clone(), &dir.0, geometry(), 1).unwrap();
    log.append(&entries(1..3, 1)).unwrap();
    log.sync().unwrap();
    let state = HardState {
        current_term: 2,
        voted_for: Some(1),
        commit: Some(1),
    };
    disk.fail.store(true, Ordering::Relaxed);
    assert!(matches!(log.save_hard_state(state), Err(LogError::Io(_))));
    disk.fail.store(false, Ordering::Relaxed);
    assert!(matches!(
        log.save_hard_state(state),
        Err(LogError::Poisoned)
    ));
    assert!(matches!(
        log.append(&entries(3..4, 1)),
        Err(LogError::Poisoned)
    ));
    assert!(matches!(log.truncate_suffix(2), Err(LogError::Poisoned)));
    assert_eq!(log.hard_state(), None);
    drop(log);
    let mut log = open(disk.clone(), &dir.0, geometry());
    log.save_hard_state(state).unwrap();
    // A failed log sync poisons the same way.
    log.append(&entries(3..4, 1)).unwrap();
    disk.fail.store(true, Ordering::Relaxed);
    assert!(matches!(log.sync(), Err(LogError::Store(_))));
    disk.fail.store(false, Ordering::Relaxed);
    assert!(matches!(
        log.append(&entries(4..5, 1)),
        Err(LogError::Poisoned)
    ));
    assert!(matches!(log.truncate_suffix(3), Err(LogError::Poisoned)));
    assert!(matches!(
        log.save_hard_state(state),
        Err(LogError::Poisoned)
    ));
    assert!(matches!(log.sync(), Err(LogError::Poisoned)));
    drop(log);
    let mut log = open(disk.clone(), &dir.0, geometry());
    let next = log.last_index() + 1;
    log.append(&entries(next..next + 1, 1)).unwrap();
    log.sync().unwrap();
}

/// Appends raw frames after the log's end through the segment store.
fn append_raw(dir: &Path, frames: &[Vec<u8>]) -> Vec<u64> {
    let mut store = SegmentStore::recover(
        StdDisk,
        dir,
        LOG_RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
    )
    .unwrap()
    .store;
    let mut at = Vec::new();
    for frame in frames {
        let position = store.written();
        at.push(position);
        store.append(position, frame).unwrap();
    }
    store.sync().unwrap();
    at
}

fn three_entries(name: &str) -> TempDir {
    let dir = TempDir::new(name);
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    log.append(&entries(1..4, 2)).unwrap();
    log.sync().unwrap();
    dir
}

/// A frame in the middle of the chain with the wrong index is refused at
/// open, with its position: never cut silently.
#[test]
fn a_mid_chain_index_gap_is_refused() {
    let dir = three_entries("gap");
    let frames = [
        entry(5, 2, b"skips 4").frame().unwrap(),
        entry(6, 2, b"after").frame().unwrap(),
    ];
    let at = append_raw(&dir.0, &frames);
    match RaftLog::open(StdDisk, &dir.0, geometry()) {
        Err(LogError::Chain { position, problem }) => {
            assert_eq!(position, at[0]);
            assert_eq!(
                problem,
                ChainProblem::Index {
                    expected: 4,
                    got: 5
                }
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_mid_chain_term_going_back_is_refused() {
    let dir = three_entries("term-back");
    let frames = [
        entry(4, 1, b"older term").frame().unwrap(),
        entry(5, 2, b"after").frame().unwrap(),
    ];
    let at = append_raw(&dir.0, &frames);
    match RaftLog::open(StdDisk, &dir.0, geometry()) {
        Err(LogError::Chain { position, problem }) => {
            assert_eq!(position, at[0]);
            assert_eq!(problem, ChainProblem::TermBack { last: 2, got: 1 });
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_damaged_frame_is_refused() {
    let dir = three_entries("damaged");
    let mut frame = entry(4, 2, b"payload").frame().unwrap();
    let last = frame.len() - 1;
    frame[last] ^= 1;
    let at = append_raw(
        &dir.0,
        &[
            frame,
            b"not a frame at all, longer than a header....".to_vec(),
        ],
    );
    match RaftLog::open(StdDisk, &dir.0, geometry()) {
        Err(LogError::Chain { position, problem }) => {
            assert_eq!((position, problem), (at[0], ChainProblem::Checksum));
        }
        other => panic!("{other:?}"),
    }
}

/// A frame the recovered bytes end inside is the torn tail: cut at its
/// start, the entries before it kept.
#[test]
fn a_torn_tail_is_cut() {
    let dir = three_entries("tail");
    let frame = entry(4, 2, &[7; 500]).frame().unwrap();
    let at = append_raw(&dir.0, &[frame[..FRAME_HEADER + 100].to_vec()]);
    let opened = RaftLog::open(StdDisk, &dir.0, geometry()).unwrap();
    assert_eq!(opened.cut, Some(at[0]));
    let mut log = opened.log;
    assert_eq!((log.last_index(), log.written()), (3, at[0]));
    log.append(&[entry(4, 2, b"again")]).unwrap();
}
