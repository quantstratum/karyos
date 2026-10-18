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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use karyos_archive::crc32c::crc32c;
use karyos_archive::disk::{Disk, StdDisk};
use karyos_archive::segment::{Geometry, SegmentStore, SyncPolicy};
use karyos_cluster::hard_state::{HARD_STATE_FILE, HARD_STATE_LEN, HardStateProblem};
use karyos_cluster::log::{FIRST_INDEX_FILE, FRAME_HEADER, LOG_RECORDING};
use karyos_cluster::{ChainProblem, Corruption, Entry, HardState, LogError, RaftLog};

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
    assert_eq!((log.first_index(), log.last_index()), (1, None));
    let mut written = entries(1..4, 1);
    written.extend(entries(4..6, 3));
    assert_eq!(log.append(&written).unwrap(), Some(5));
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
        (1, Some(5), Some(5))
    );
    assert_eq!(log.entries(1..6, u64::MAX).unwrap(), written);
}

#[test]
fn a_log_may_start_at_any_index() {
    let dir = TempDir::new("start");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 100).unwrap();
    assert_eq!(log.last_index(), None);
    assert!(matches!(
        log.append(&entries(1..2, 1)),
        Err(LogError::NotNext {
            expected: 100,
            got: 1
        })
    ));
    assert_eq!(log.append(&entries(100..103, 1)).unwrap(), Some(102));
    log.truncate_suffix(100).unwrap();
    drop(log);
    // Emptied, it keeps its first index.
    let log = open(StdDisk, &dir.0, geometry());
    assert_eq!((log.first_index(), log.last_index()), (100, None));
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
    assert_eq!(log.last_index(), Some(3));
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
    assert_eq!((log.last_index(), log.durable_index()), (Some(3), None));
    assert_eq!(log.sync().unwrap(), Some(3));
    assert_eq!((log.written(), log.durable()), (bytes, bytes));
    assert_eq!(log.durable_index(), Some(3));
    log.append(&entries(4..5, 1)).unwrap();
    assert_eq!((log.last_index(), log.durable_index()), (Some(4), Some(3)));
}

#[test]
fn a_truncated_suffix_is_appended_again() {
    let dir = TempDir::new("truncate");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    log.append(&entries(1..6, 1)).unwrap();
    log.truncate_suffix(3).unwrap();
    assert_eq!((log.last_index(), log.term(3)), (Some(2), None));
    assert_eq!(log.durable_index(), Some(2), "what is kept is durable");
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
            last: Some(4)
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
    assert_eq!((log.written(), log.last_index()), (written, Some(2)));
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
    // Each entry is 136 bytes encoded: 36 of header, 100 of payload.
    assert_eq!(written[0].encoded_len(), 136);
    assert_eq!(log.entries(1..5, 272).unwrap(), written[..2].to_vec());
    assert_eq!(log.entries(1..5, 271).unwrap(), written[..1].to_vec());
    assert_eq!(log.entries(1..5, 0).unwrap(), written[..1].to_vec());
    assert!(log.entries(5..9, u64::MAX).unwrap().is_empty());
    // Empty payloads count their header too.
    let empty: Vec<Entry> = (5..1005).map(|index| entry(index, 1, b"")).collect();
    log.append(&empty).unwrap();
    assert_eq!(log.entries(5..1005, 1).unwrap().len(), 1);
    assert_eq!(log.entries(5..1005, 360).unwrap().len(), 10);
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
            durable: None
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
            durable: Some(3)
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
            durable: Some(3)
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
    assert_eq!((log.last_index(), log.written()), (Some(5), written));
    log.truncate_suffix(4).unwrap();
    assert_eq!(log.last_index(), Some(3));
    assert_eq!(
        LogError::TruncateBelowCommit { from: 2, commit: 3 }.to_string(),
        "truncating from 2 would remove committed entries up to 3"
    );
}

/// The standard disk, whose syncs fail while `fail` is set, after
/// `skip` more syncs succeed.
#[derive(Debug, Clone, Default)]
struct FlakyDisk {
    fail: Arc<AtomicBool>,
    skip: Arc<AtomicU64>,
}

impl FlakyDisk {
    /// Fails every sync after the next `skip`.
    fn fail_after(&self, skip: u64) {
        self.skip.store(skip, Ordering::Relaxed);
        self.fail.store(true, Ordering::Relaxed);
    }

    fn check(&self) -> io::Result<()> {
        if self.fail.load(Ordering::Relaxed) {
            let skip = self.skip.load(Ordering::Relaxed);
            if skip > 0 {
                self.skip.store(skip - 1, Ordering::Relaxed);
                return Ok(());
            }
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
    let next = log.next_index();
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

/// The name of segment `base`'s index file.
fn index_file(dir: &Path, base: u64) -> PathBuf {
    dir.join(format!("{LOG_RECORDING:016x}-{base:016x}.idx"))
}

fn data_file(dir: &Path, base: u64) -> PathBuf {
    dir.join(format!("{LOG_RECORDING:016x}-{base:016x}.seg"))
}

/// Two 3000-byte entries over 4 KiB segments: the second spans the
/// segment at 4096, with its second chunk indexed there as the first
/// entry (bytes 48..80 of that index file). Returns the second's start.
fn spanning(name: &str) -> (TempDir, u64) {
    let dir = TempDir::new(name);
    let mut log = RaftLog::create(StdDisk, &dir.0, small(), 1).unwrap();
    log.append(&[entry(1, 1, &[1; 3000])]).unwrap();
    let second = log.written();
    log.append(&[entry(2, 1, &[2; 3000])]).unwrap();
    log.sync().unwrap();
    (dir, second)
}

/// The real torn tail: an entry spanning two segments whose second chunk
/// was lost (its index entry never written). Cut at the entry's start,
/// the entries before it kept.
#[test]
fn a_torn_tail_is_cut() {
    let (dir, second) = spanning("tail");
    let index = index_file(&dir.0, 4096);
    let mut bytes = std::fs::read(&index).unwrap();
    bytes[48..80].fill(0);
    std::fs::write(&index, &bytes).unwrap();
    let opened = RaftLog::open(StdDisk, &dir.0, small()).unwrap();
    assert_eq!(opened.cut, Some(second));
    let mut log = opened.log;
    assert_eq!((log.last_index(), log.written()), (Some(1), second));
    log.append(&[entry(2, 2, b"again")]).unwrap();
}

/// A torn tail holding a committed entry is refused before anything is
/// removed: once the stored commit is gone, the same files open and cut.
#[test]
fn a_torn_tail_below_the_commit_is_refused() {
    let (dir, second) = spanning("tail-commit");
    let index = index_file(&dir.0, 4096);
    let mut bytes = std::fs::read(&index).unwrap();
    bytes[48..80].fill(0);
    std::fs::write(&index, &bytes).unwrap();
    let committed = HardState {
        current_term: 1,
        voted_for: None,
        commit: Some(2),
    };
    std::fs::write(dir.0.join(HARD_STATE_FILE), committed.encode()).unwrap();
    assert!(matches!(
        RaftLog::open(StdDisk, &dir.0, small()),
        Err(LogError::TornBelowCommit {
            index: 2,
            commit: 2
        })
    ));
    std::fs::remove_file(dir.0.join(HARD_STATE_FILE)).unwrap();
    let opened = RaftLog::open(StdDisk, &dir.0, small()).unwrap();
    assert_eq!(opened.cut, Some(second));
}

/// A complete write whose frame claims a length past the end, followed by
/// valid frames, is not a torn tail: Chain, with nothing removed.
#[test]
fn a_length_past_the_end_mid_chain_is_refused() {
    let dir = three_entries("past-end");
    let mut bad = entry(4, 2, b"payload").frame().unwrap();
    bad[4..8].copy_from_slice(&10_000u32.to_le_bytes());
    let frames = [bad, entry(5, 2, b"e").frame().unwrap()];
    let at = append_raw(&dir.0, &frames);
    let written = std::fs::metadata(data_file(&dir.0, 0)).unwrap().len();
    for _ in 0..2 {
        match RaftLog::open(StdDisk, &dir.0, geometry()) {
            Err(LogError::Chain { position, problem }) => {
                assert_eq!((position, problem), (at[0], ChainProblem::PastEnd));
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(
        std::fs::metadata(data_file(&dir.0, 0)).unwrap().len(),
        written
    );
}

/// A bit flip in a middle segment: A2's recovery cuts there and drops the
/// later segments, which is more than a torn last write: Corruption.
#[test]
fn a_flip_in_a_middle_segment_is_corruption() {
    let dir = TempDir::new("flip-middle");
    let mut log = RaftLog::create(StdDisk, &dir.0, small(), 1).unwrap();
    let batch: Vec<Entry> = (1..=8)
        .map(|index| entry(index, 1, &[index as u8; 2012]))
        .collect();
    log.append(&batch).unwrap();
    log.sync().unwrap();
    drop(log);
    let segment = data_file(&dir.0, 4096);
    let mut bytes = std::fs::read(&segment).unwrap();
    bytes[100] ^= 1;
    std::fs::write(&segment, &bytes).unwrap();
    match RaftLog::open(StdDisk, &dir.0, small()) {
        Err(LogError::Corruption(Corruption::Dropped { cut, last_write })) => {
            assert_eq!(cut, 4096);
            assert!(last_write > cut, "{last_write}");
        }
        other => panic!("{other:?}"),
    }
}

/// A flip inside one segment, with writes after it in the same segment:
/// Corruption too, not a cut.
#[test]
fn a_flip_mid_segment_is_corruption() {
    let dir = TempDir::new("flip-mid");
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry(), 1).unwrap();
    log.append(&entries(1..6, 1)).unwrap();
    log.sync().unwrap();
    let second = log.entries(1..2, u64::MAX).unwrap()[0].encoded_len();
    drop(log);
    let segment = data_file(&dir.0, 0);
    let mut bytes = std::fs::read(&segment).unwrap();
    bytes[usize::try_from(second).unwrap() + FRAME_HEADER] ^= 1;
    std::fs::write(&segment, &bytes).unwrap();
    assert!(matches!(
        RaftLog::open(StdDisk, &dir.0, geometry()),
        Err(LogError::Corruption(Corruption::Dropped { cut, .. })) if cut == second
    ));
}

/// A lost middle segment: A2 recovers up to it and drops the segments
/// after it, which hold whole writes: Corruption.
#[test]
fn a_lost_segment_is_corruption() {
    let dir = TempDir::new("lost-segment");
    let mut log = RaftLog::create(StdDisk, &dir.0, small(), 1).unwrap();
    let batch: Vec<Entry> = (1..=8)
        .map(|index| entry(index, 1, &[index as u8; 2012]))
        .collect();
    log.append(&batch).unwrap();
    log.sync().unwrap();
    drop(log);
    std::fs::remove_file(data_file(&dir.0, 4096)).unwrap();
    std::fs::remove_file(index_file(&dir.0, 4096)).unwrap();
    match RaftLog::open(StdDisk, &dir.0, small()) {
        Err(LogError::Corruption(corruption)) => assert_eq!(
            corruption,
            Corruption::Dropped {
                cut: 4096,
                last_write: 14_336
            }
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_foreign_frame_mid_chain_is_refused() {
    let dir = three_entries("foreign");
    let mut foreign = entry(4, 2, b"payload").frame().unwrap();
    foreign[..4].copy_from_slice(b"XXXX");
    let at = append_raw(&dir.0, &[foreign, entry(5, 2, b"e").frame().unwrap()]);
    match RaftLog::open(StdDisk, &dir.0, geometry()) {
        Err(LogError::Chain { position, problem }) => {
            assert_eq!((position, problem), (at[0], ChainProblem::Foreign));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_damaged_first_index_file_is_refused() {
    let dir = three_entries("first-index");
    let path = dir.0.join(FIRST_INDEX_FILE);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        RaftLog::open(StdDisk, &dir.0, geometry()),
        Err(LogError::FirstIndex)
    ));
    std::fs::write(&path, vec![0u8; 4096]).unwrap();
    assert!(matches!(
        RaftLog::open(StdDisk, &dir.0, geometry()),
        Err(LogError::FirstIndex)
    ));
}

/// A record whose CRC holds but whose flags, unset values or reserved
/// bytes are not as written: Malformed.
#[test]
fn malformed_hard_state_flags_are_refused() {
    let state = HardState {
        current_term: 3,
        voted_for: None,
        commit: None,
    };
    let sealed = |mut bytes: [u8; HARD_STATE_LEN]| {
        let crc = crc32c(&bytes[..40]);
        bytes[40..].copy_from_slice(&crc.to_le_bytes());
        bytes
    };
    let mut flag = state.encode();
    flag[16] = 2;
    let mut unset = state.encode();
    unset[17] = 5;
    let mut reserved = state.encode();
    reserved[35] = 1;
    for bytes in [flag, unset, reserved] {
        assert_eq!(
            HardState::decode(&sealed(bytes)),
            Err(HardStateProblem::Malformed)
        );
    }
    let mut foreign = state.encode();
    foreign[0] = b'X';
    assert_eq!(
        HardState::decode(&sealed(foreign)),
        Err(HardStateProblem::Foreign)
    );
    // Too long a file is refused by its length, unread.
    let dir = three_entries("long-hard-state");
    std::fs::write(dir.0.join(HARD_STATE_FILE), vec![0u8; 1 << 20]).unwrap();
    assert!(matches!(
        RaftLog::open(StdDisk, &dir.0, geometry()),
        Err(LogError::HardState(HardStateProblem::Length(1_048_576)))
    ));
}

/// Logs from index 0 and from 1: empty, appended, emptied by a
/// truncation, and reopened at each step.
#[test]
fn logs_start_at_zero_or_one() {
    for first in [0u64, 1] {
        let dir = TempDir::new(&format!("first-{first}"));
        let log = RaftLog::create(StdDisk, &dir.0, geometry(), first).unwrap();
        assert_eq!(
            (log.last_index(), log.next_index(), log.term(first)),
            (None, first, None)
        );
        drop(log);
        let mut log = open(StdDisk, &dir.0, geometry());
        assert_eq!(log.last_index(), None);
        assert!(matches!(
            log.append(&entries(first + 1..first + 2, 1)),
            Err(LogError::NotNext { expected, got }) if expected == first && got == first + 1
        ));
        assert_eq!(
            log.append(&entries(first..first + 3, 1)).unwrap(),
            Some(first + 2)
        );
        assert!(matches!(
            log.append(&entries(first..first + 1, 1)),
            Err(LogError::NotNext { expected, .. }) if expected == first + 3
        ));
        assert_eq!(log.sync().unwrap(), Some(first + 2));
        assert_eq!((log.term(first), log.term(first + 3)), (Some(1), None));
        drop(log);
        let mut log = open(StdDisk, &dir.0, geometry());
        assert_eq!(
            log.entries(first..first + 3, u64::MAX).unwrap(),
            entries(first..first + 3, 1)
        );
        log.truncate_suffix(first).unwrap();
        assert_eq!((log.last_index(), log.durable_index()), (None, None));
        drop(log);
        let mut log = open(StdDisk, &dir.0, geometry());
        assert_eq!((log.first_index(), log.last_index()), (first, None));
        assert_eq!(
            log.append(&entries(first..first + 1, 2)).unwrap(),
            Some(first)
        );
    }
}

#[test]
fn the_stored_commit_only_moves_forward() {
    let dir = three_entries("commit-forward");
    let mut log = open(StdDisk, &dir.0, geometry());
    let state = HardState {
        current_term: 2,
        voted_for: Some(1),
        commit: Some(2),
    };
    log.save_hard_state(state).unwrap();
    assert!(matches!(
        log.save_hard_state(HardState {
            commit: Some(1),
            ..state
        }),
        Err(LogError::CommitBack {
            stored: 2,
            got: Some(1)
        })
    ));
    assert!(matches!(
        log.save_hard_state(HardState {
            commit: None,
            ..state
        }),
        Err(LogError::CommitBack {
            stored: 2,
            got: None
        })
    ));
    assert_eq!(log.hard_state(), Some(state));
    // A new vote carries the stored commit.
    log.save_hard_state(HardState {
        current_term: 3,
        voted_for: Some(2),
        commit: Some(2),
    })
    .unwrap();
    log.save_hard_state(HardState {
        commit: Some(3),
        ..state
    })
    .unwrap();
}

/// A sync that fails inside an append's segment roll poisons the log; the
/// index keeps what A2 still holds, and reads still work.
#[test]
fn a_failed_roll_sync_poisons() {
    let dir = TempDir::new("roll-sync");
    let disk = FlakyDisk::default();
    let mut log = RaftLog::create(disk.clone(), &dir.0, small(), 1).unwrap();
    log.append(&[entry(1, 1, &[1; 3000])]).unwrap();
    disk.fail_after(0);
    assert!(matches!(
        log.append(&[entry(2, 1, &[2; 3000])]),
        Err(LogError::Store(_))
    ));
    disk.fail.store(false, Ordering::Relaxed);
    assert!(matches!(
        log.append(&[entry(2, 1, b"x")]),
        Err(LogError::Poisoned)
    ));
    assert!(matches!(log.sync(), Err(LogError::Poisoned)));
    assert!(matches!(
        log.save_hard_state(HardState::default()),
        Err(LogError::Poisoned)
    ));
    assert_eq!((log.last_index(), log.term(1)), (Some(1), Some(1)));
    assert_eq!(log.entries(1..3, u64::MAX).unwrap().len(), 1);
}

/// A sync that fails inside a truncation poisons the log, and the index
/// agrees with what A2 holds.
#[test]
fn a_failed_truncation_poisons() {
    let dir = TempDir::new("truncate-sync");
    let disk = FlakyDisk::default();
    let mut log = RaftLog::create(disk.clone(), &dir.0, geometry(), 1).unwrap();
    log.append(&entries(1..4, 1)).unwrap();
    log.sync().unwrap();
    disk.fail_after(1);
    assert!(matches!(log.truncate_suffix(2), Err(LogError::Store(_))));
    disk.fail.store(false, Ordering::Relaxed);
    assert!(matches!(
        log.append(&entries(2..3, 2)),
        Err(LogError::Poisoned)
    ));
    assert!(matches!(log.truncate_suffix(2), Err(LogError::Poisoned)));
    let held = log.entries(1..4, u64::MAX).unwrap();
    assert_eq!(held.len() as u64, log.last_index().unwrap());
    let end: u64 = held.iter().map(Entry::encoded_len).sum();
    assert!(end <= log.written(), "{end} {}", log.written());
}

/// A creation stopped after its first-index file opens as an empty log,
/// and can also be created again.
#[test]
fn a_creation_cut_short_is_finished() {
    let dir = TempDir::new("create-cut");
    let log = RaftLog::create(StdDisk, &dir.0, geometry(), 5).unwrap();
    drop(log);
    for name in std::fs::read_dir(&dir.0).unwrap() {
        let name = name.unwrap().path();
        if name
            .extension()
            .is_some_and(|ext| ext == "seg" || ext == "idx")
        {
            std::fs::remove_file(name).unwrap();
        }
    }
    let mut log = open(StdDisk, &dir.0, geometry());
    assert_eq!((log.first_index(), log.last_index()), (5, None));
    assert_eq!(log.append(&entries(5..6, 1)).unwrap(), Some(5));
    drop(log);
    // A log there: create refuses and changes nothing.
    assert!(matches!(
        RaftLog::create(StdDisk, &dir.0, geometry(), 9),
        Err(LogError::Store(_))
    ));
    assert_eq!(open(StdDisk, &dir.0, geometry()).first_index(), 5);
}

/// A damaged index header of a middle segment: A2 refuses it, and so does
/// the log, naming the segment.
#[test]
fn a_damaged_segment_header_is_corruption() {
    let dir = TempDir::new("bad-header");
    let mut log = RaftLog::create(StdDisk, &dir.0, small(), 1).unwrap();
    let batch: Vec<Entry> = (1..=8)
        .map(|index| entry(index, 1, &[index as u8; 2012]))
        .collect();
    log.append(&batch).unwrap();
    log.sync().unwrap();
    drop(log);
    let index = index_file(&dir.0, 4096);
    let mut bytes = std::fs::read(&index).unwrap();
    bytes[10] ^= 1;
    std::fs::write(&index, &bytes).unwrap();
    assert!(matches!(
        RaftLog::open(StdDisk, &dir.0, small()),
        Err(LogError::Corruption(Corruption::Segment { base: 4096 }))
    ));
}
