// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::PathBuf;

use karyos_trace::clocks::utc::{Scale, Source, SyncState, UtcReference};
use karyos_trace::clocks::{Calibration, ClockKey};
use karyos_trace::journal::ObserverId;

use super::*;
use crate::disk::StdDisk;
use crate::integrity::time_producer::{Event, EventClock};

/// Records per segment under the test geometry.
const PER_SEGMENT: usize = (TERM_RECORDS as usize) * (SEGMENT_TERMS as usize);

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-calibration-journal-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key([low, high, journal, domain, epoch]: [u64; 5]) -> ClockKey {
    ClockKey {
        observer: ObserverId {
            driver: [low, high],
            journal,
        },
        domain,
        epoch,
    }
}

const A: [u64; 5] = [1, 0, 2, 3, 4];
const B: [u64; 5] = [9, 0, 9, 9, 9];

fn calibration_of(from: [u64; 5], valid_from: u64, valid_to: u64) -> [u64; CALIBRATION_WORDS] {
    Calibration {
        from: key(from),
        to: key(B),
        reference: valid_from,
        offset: 10,
        offset_uncertainty: 2,
        drift: 0,
        drift_uncertainty: 0,
        valid_from,
        valid_to,
    }
    .encode()
    .unwrap()
}

fn calibration(valid_from: u64, valid_to: u64) -> [u64; CALIBRATION_WORDS] {
    calibration_of(A, valid_from, valid_to)
}

/// A synthetic UTC reference record: no hardware here is UTC traceable.
fn reference(valid_from: u64, valid_to: u64) -> [u64; CALIBRATION_WORDS] {
    UtcReference {
        clock: key(B),
        source: Source::Gnss,
        sync_state: SyncState::Synchronised,
        bound: 100,
        valid_from,
        valid_to,
        tick_fs: 1_000_000,
        scale: Scale::Tai,
        origin: 0,
        origin_scale_ns: 2_000_000_000_000_000_000,
        leap_table: 69,
        transform_uncertainty_ns: 0,
    }
    .encode()
    .unwrap()
}

/// A record of a type this build does not know (word 0's low byte 7).
fn unknown(fill: u64) -> [u64; CALIBRATION_WORDS] {
    let mut words = [fill; CALIBRATION_WORDS];
    words[0] = 7;
    words
}

/// The store's files of `dir` with `extension`, in position order.
fn files(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|found| found == extension))
        .collect();
    found.sort();
    found
}

fn last_file(dir: &Path, extension: &str) -> PathBuf {
    files(dir, extension).pop().unwrap()
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

/// Writes `words` into the store and syncs it, without committing: a
/// writer that crashed between the store's sync and the commit.
fn uncommitted(dir: &Path, words: &[u64; CALIBRATION_WORDS]) {
    let mut store = SegmentStore::recover(
        StdDisk,
        dir,
        RECORDING,
        geometry().unwrap(),
        SyncPolicy::None,
    )
    .unwrap()
    .store;
    let mut bytes = Vec::new();
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let at = store.written();
    store.append(at, &bytes).unwrap();
    store.sync().unwrap();
}

/// What the agent's producer proves from a snapshot: the event at 1 of
/// clock `A` is covered.
fn proves(snapshot: &Snapshot) -> bool {
    let clock = EventClock {
        clock: A,
        granularity: 1,
    };
    snapshot.reaches(
        &clock,
        &[Event {
            start: 0,
            end: 1,
            time: 1,
            in_session: true,
        }],
    )
}

#[test]
fn records_round_trip_and_survive_a_reopen() {
    let dir = temp_dir("round-trip");
    assert_eq!(
        read(StdDisk, &dir).unwrap(),
        Records {
            generation: 0,
            records: Vec::new(),
            lossless: true
        }
    );
    let written = [calibration(0, 100), reference(0, 1999), unknown(0x5A)];
    let generation = {
        let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
        let outcomes = journal.append_batch(&written).unwrap();
        assert_eq!(
            outcomes,
            [
                Appended::At(0),
                Appended::At(RECORD_LENGTH as u64),
                Appended::At(2 * RECORD_LENGTH as u64)
            ]
        );
        journal.durable().generation
    };
    assert_ne!(generation, 0);
    let read_back = read(StdDisk, &dir).unwrap();
    assert!(read_back.lossless);
    assert_eq!(read_back.generation, generation);
    assert_eq!(read_back.records, written);
    let (known, skipped) = ClockRecord::decode_all(&read_back.records).unwrap();
    assert_eq!((known.len(), skipped), (2, 1));
    // A reopened writer keeps the generation and appends after them.
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    assert_eq!(journal.durable().generation, generation);
    assert_eq!(
        journal.append(&calibration(1000, 2000)).unwrap(),
        Appended::At(3 * RECORD_LENGTH as u64)
    );
    drop(journal);
    assert_eq!(read(StdDisk, &dir).unwrap().records.len(), 4);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_record_its_type_refuses_is_never_appended() {
    let dir = temp_dir("refused");
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    let mut bad = calibration(0, 100);
    // valid_from > valid_to.
    bad[16] = 200;
    match journal.append_batch(&[calibration(0, 100), bad]) {
        Err(JournalError::Refused(refused)) => {
            assert_eq!(refused.len(), 1);
            assert_eq!(refused[0].0, 1);
            assert!(matches!(refused[0].1, Refusal::Record(_)));
        }
        other => panic!("{other:?}"),
    }
    drop(journal);
    assert!(read(StdDisk, &dir).unwrap().records.is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// ADR-0098's completeness boundary: a `valid_from` not after the last
/// of its type and clock is refused, and refuses the whole batch; other
/// clocks and the other record type are ordered on their own.
#[test]
fn an_out_of_order_valid_from_is_refused() {
    let dir = temp_dir("order");
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    journal
        .append_batch(&[calibration(1000, 2000), reference(2000, 3000)])
        .unwrap();
    match journal.append_batch(&[
        calibration_of([5, 0, 5, 5, 5], 0, 100),
        calibration(1000, 1500),
        reference(0, 10),
    ]) {
        Err(JournalError::Refused(refused)) => assert_eq!(
            refused,
            [
                (
                    1,
                    Refusal::OutOfOrder {
                        valid_from: 1000,
                        last: 1000
                    }
                ),
                (
                    2,
                    Refusal::OutOfOrder {
                        valid_from: 0,
                        last: 2000
                    }
                )
            ]
        ),
        other => panic!("{other:?}"),
    }
    // Inside one batch too.
    assert!(matches!(
        journal.append_batch(&[calibration(3000, 4000), calibration(2500, 2600)]),
        Err(JournalError::Refused(_))
    ));
    assert_eq!(read(StdDisk, &dir).unwrap().records.len(), 2);
    // Another clock, and a later time, are accepted.
    journal
        .append_batch(&[
            calibration_of([5, 0, 5, 5, 5], 0, 100),
            calibration(3000, 4000),
        ])
        .unwrap();
    drop(journal);
    // The order survives a reopen.
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    assert!(matches!(
        journal.append(&calibration(2999, 5000)),
        Err(JournalError::Refused(_))
    ));
    drop(journal);
    assert_eq!(read(StdDisk, &dir).unwrap().records.len(), 4);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A retried, partly applied batch never duplicates: a record identical
/// to a stored one is skipped, reported already present.
#[test]
fn a_duplicate_is_skipped() {
    let dir = temp_dir("duplicate");
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    journal
        .append_batch(&[calibration(0, 100), unknown(1)])
        .unwrap();
    drop(journal);
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    assert_eq!(
        journal
            .append_batch(&[
                calibration(0, 100),
                unknown(1),
                reference(0, 1999),
                reference(0, 1999)
            ])
            .unwrap(),
        [
            Appended::AlreadyPresent,
            Appended::AlreadyPresent,
            Appended::At(2 * RECORD_LENGTH as u64),
            Appended::AlreadyPresent
        ]
    );
    assert_eq!(
        journal.append(&reference(0, 1999)).unwrap(),
        Appended::AlreadyPresent
    );
    drop(journal);
    assert_eq!(read(StdDisk, &dir).unwrap().records.len(), 3);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn one_writer_at_a_time() {
    let dir = temp_dir("locked");
    let journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    assert!(matches!(
        CalibrationJournal::open(StdDisk, &dir),
        Err(JournalError::Locked)
    ));
    drop(journal);
    drop(CalibrationJournal::open(StdDisk, &dir).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A disk whose lock answers `WouldBlock` for the first `busy` tries, as
/// a lock that a spawned child still holds a copy of looks, then takes the
/// real lock.
#[derive(Debug, Clone)]
struct BusyLock {
    busy: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

impl BusyLock {
    fn new(busy: u32) -> Self {
        Self {
            busy: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(busy)),
        }
    }
}

impl crate::disk::Disk for BusyLock {
    type File = std::fs::File;

    fn create(&mut self, path: &std::path::Path) -> std::io::Result<Self::File> {
        StdDisk.create(path)
    }

    fn open(&mut self, path: &std::path::Path) -> std::io::Result<Self::File> {
        StdDisk.open(path)
    }

    fn open_read(&mut self, path: &std::path::Path) -> std::io::Result<Self::File> {
        StdDisk.open_read(path)
    }

    fn write_at(&mut self, file: &Self::File, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        StdDisk.write_at(file, offset, bytes)
    }

    fn read_at(&mut self, file: &Self::File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        StdDisk.read_at(file, offset, buf)
    }

    fn len(&mut self, file: &Self::File) -> std::io::Result<u64> {
        StdDisk.len(file)
    }

    fn set_len(&mut self, file: &Self::File, len: u64) -> std::io::Result<()> {
        StdDisk.set_len(file, len)
    }

    fn sync(&mut self, file: &Self::File) -> std::io::Result<()> {
        StdDisk.sync(file)
    }

    fn sync_dir(&mut self, dir: &std::path::Path) -> std::io::Result<()> {
        StdDisk.sync_dir(dir)
    }

    fn list(&mut self, dir: &std::path::Path) -> std::io::Result<Vec<String>> {
        StdDisk.list(dir)
    }

    fn remove(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        StdDisk.remove(path)
    }

    fn rename(&mut self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
        StdDisk.rename(from, to)
    }

    fn lock(&mut self, file: &Self::File) -> std::io::Result<()> {
        let left = self.busy.load(std::sync::atomic::Ordering::SeqCst);
        if left > 0 {
            self.busy
                .store(left - 1, std::sync::atomic::Ordering::SeqCst);
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        StdDisk.lock(file)
    }
}

/// A lock a spawned child holds for a moment (a copy of the lock until its
/// exec, karyos_sys::spawn_window) is tried again, not answered `Locked`:
/// the first tries are refused, deterministically, and the open succeeds.
#[test]
fn a_lock_held_for_a_moment_is_waited_for() {
    let dir = temp_dir("lock-moment");
    let disk = BusyLock::new(3);
    let opened = CalibrationJournal::open(disk.clone(), &dir);
    assert!(opened.is_ok(), "{:?}", opened.err());
    assert_eq!(
        disk.busy.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "it was retried"
    );
    drop(opened);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A lock still held after the spawn window is another writer's: `Locked`.
#[test]
fn a_lock_held_past_the_window_is_locked() {
    let dir = temp_dir("lock-past");
    let disk = BusyLock::new(u32::MAX);
    assert!(matches!(
        CalibrationJournal::open(disk, &dir),
        Err(JournalError::Locked)
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A torn tail past the committed position is never read, by a reader
/// nor by the writer that recovers it.
#[test]
fn a_torn_tail_is_ignored_until_complete() {
    let dir = temp_dir("torn");
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    journal
        .append_batch(&[calibration(0, 100), reference(0, 1999)])
        .unwrap();
    drop(journal);
    append_bytes(&last_file(&dir, "seg"), &[0xEE; RECORD_LENGTH / 2]);
    append_bytes(&last_file(&dir, "idx"), &[0x11; 7]);
    let torn = read(StdDisk, &dir).unwrap();
    assert_eq!(torn.records, [calibration(0, 100), reference(0, 1999)]);
    assert!(torn.lossless);
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    journal.append(&calibration(1000, 2000)).unwrap();
    drop(journal);
    assert_eq!(
        read(StdDisk, &dir).unwrap().records,
        [
            calibration(0, 100),
            reference(0, 1999),
            calibration(1000, 2000)
        ]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A record the store holds but the committed position does not cover (a
/// crash between the store's sync and the commit) is invisible, and the
/// next writer cuts it.
#[test]
fn a_record_past_the_committed_position_is_unseen() {
    let dir = temp_dir("past-durable");
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    journal.append(&calibration(0, 100)).unwrap();
    drop(journal);
    uncommitted(&dir, &calibration(1000, 2000));
    let records = read(StdDisk, &dir).unwrap();
    assert_eq!(records.records, [calibration(0, 100)]);
    assert!(records.lossless);
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    // Cut: the same record is new again, at the same position.
    assert_eq!(
        journal.append(&calibration(1000, 2000)).unwrap(),
        Appended::At(RECORD_LENGTH as u64)
    );
    drop(journal);
    assert_eq!(read(StdDisk, &dir).unwrap().records.len(), 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A committed record the store lost (its bytes no longer match their
/// CRC, so verification cuts there) is a loss, never a shorter lossless
/// journal; the writer refuses to repair it.
#[test]
fn interior_corruption_is_a_loss() {
    let dir = temp_dir("interior");
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    journal
        .append_batch(&[
            calibration(0, 100),
            reference(0, 1999),
            calibration(1000, 2000),
        ])
        .unwrap();
    drop(journal);
    let data = files(&dir, "seg").remove(0);
    let file = std::fs::OpenOptions::new().write(true).open(&data).unwrap();
    std::os::unix::fs::FileExt::write_all_at(&file, &[0xFF], 40).unwrap();
    drop(file);
    let records = read(StdDisk, &dir).unwrap();
    assert!(!records.lossless);
    assert!(records.records.len() < 3);
    let mut source = JournalSource::new(StdDisk, &dir);
    assert!(!proves(&source.snapshot()));
    assert!(matches!(
        CalibrationJournal::open(StdDisk, &dir),
        Err(JournalError::Damaged(_))
    ));
    // A committed position that does not decode is damage too.
    std::fs::write(dir.join(DURABLE_FILE), [0u8; 20]).unwrap();
    assert!(matches!(read(StdDisk, &dir), Err(JournalError::Damaged(_))));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Records never straddle a segment: a segment holds whole records, and
/// a crash while the next segment's first record is written leaves every
/// committed record readable.
#[test]
fn a_crash_at_a_segment_boundary_keeps_whole_records() {
    let dir = temp_dir("boundary");
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    let full: Vec<_> = (0..PER_SEGMENT as u64)
        .map(|index| calibration(index * 10, index * 10 + 5))
        .collect();
    journal.append_batch(&full).unwrap();
    drop(journal);
    let segments = files(&dir, "seg");
    assert_eq!(segments.len(), 1);
    assert_eq!(
        std::fs::metadata(&segments[0]).unwrap().len(),
        (PER_SEGMENT * RECORD_LENGTH) as u64
    );
    // The next record starts the next segment; the crash tears it.
    let next = calibration(PER_SEGMENT as u64 * 10, PER_SEGMENT as u64 * 10 + 5);
    uncommitted(&dir, &next);
    assert_eq!(files(&dir, "seg").len(), 2);
    let second = last_file(&dir, "seg");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&second)
        .unwrap();
    file.set_len((RECORD_LENGTH / 2) as u64).unwrap();
    drop(file);
    let records = read(StdDisk, &dir).unwrap();
    assert!(records.lossless);
    assert_eq!(records.records, full);
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    assert_eq!(
        journal.append(&next).unwrap(),
        Appended::At((PER_SEGMENT * RECORD_LENGTH) as u64)
    );
    drop(journal);
    let records = read(StdDisk, &dir).unwrap();
    assert_eq!(records.records.len(), PER_SEGMENT + 1);
    assert_eq!(records.records.last(), Some(&next));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The agent's source reads the journal at each snapshot: records a
/// producer commits while it runs are seen, a snapshot proves coverage
/// only once the producer's later records are committed, and another
/// journal generation in the same path is a loss.
#[test]
fn a_source_sees_records_appended_while_it_reads() {
    let dir = temp_dir("tail");
    let mut source = JournalSource::new(StdDisk, &dir);
    assert!(!proves(&source.snapshot()));
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    journal
        .append_batch(&[calibration(0, 100), reference(0, 1999)])
        .unwrap();
    assert!(!proves(&source.snapshot()));
    journal
        .append_batch(&[unknown(3), calibration(1000, 2000)])
        .unwrap();
    assert!(!proves(&source.snapshot()));
    journal.append(&reference(2000, 3000)).unwrap();
    assert!(proves(&source.snapshot()));

    let writer = std::thread::spawn(move || {
        for index in 0..60u64 {
            let at = 10_000 + index * 10;
            journal.append(&calibration(at, at + 5)).unwrap();
        }
    });
    let mut seen = 0usize;
    loop {
        let finished = writer.is_finished();
        let records = read(StdDisk, &dir).unwrap();
        assert!(records.lossless);
        assert!(records.records.len() >= seen);
        seen = records.records.len();
        for (index, words) in records.records.iter().enumerate().skip(5) {
            let at = 10_000 + (index as u64 - 5) * 10;
            assert_eq!(*words, calibration(at, at + 5));
        }
        if finished {
            assert_eq!(seen, 65);
            break;
        }
    }
    writer.join().unwrap();
    assert!(proves(&source.snapshot()));
    assert_eq!(source.failures(), 0);

    // The directory replaced by another journal: a loss for this source.
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    let mut other = CalibrationJournal::open(StdDisk, &dir).unwrap();
    other
        .append_batch(&[
            calibration(0, 100),
            reference(0, 1999),
            calibration(1000, 2000),
            reference(2000, 3000),
        ])
        .unwrap();
    drop(other);
    assert!(!proves(&source.snapshot()));
    assert_eq!(source.failures(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_generation_is_claimed_exclusively_and_a_collision_takes_the_next() {
    let parent = temp_dir("generation-claim");
    // A forced collision: the first two candidates are the same value.
    let mut candidates = [7_u64, 7, 9].into_iter();
    let first = super::claim_generation(&parent, || candidates.next().unwrap_or(11)).unwrap();
    let second = super::claim_generation(&parent, || candidates.next().unwrap_or(11)).unwrap();
    assert_eq!(
        (first, second),
        (7, 9),
        "the second claim skips the taken 7"
    );
    assert!(
        parent
            .join(super::GENERATIONS_DIR)
            .join(format!("{:016x}", 7))
            .is_dir()
    );
    // Every candidate taken: refused, never a shared generation.
    assert!(matches!(
        super::claim_generation(&parent, || 7),
        Err(super::JournalError::Generation)
    ));
    // Two journals made in one parent never share a generation.
    for name in ["a", "b"] {
        std::fs::create_dir_all(parent.join(name)).unwrap();
    }
    let a = super::CalibrationJournal::open(StdDisk, &parent.join("a")).unwrap();
    let b = super::CalibrationJournal::open(StdDisk, &parent.join("b")).unwrap();
    assert_ne!(a.durable().generation, b.durable().generation);
    let _ = std::fs::remove_dir_all(&parent);
}
