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

fn calibration(valid_from: u64, valid_to: u64) -> [u64; CALIBRATION_WORDS] {
    Calibration {
        from: key(A),
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
fn unknown() -> [u64; CALIBRATION_WORDS] {
    let mut words = [0x5Au64; CALIBRATION_WORDS];
    words[0] = 7;
    words
}

/// The store's index file of `dir`.
fn file(dir: &Path, extension: &str) -> PathBuf {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|found| found == extension))
        .unwrap()
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
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
            records: Vec::new(),
            lossless: true
        }
    );
    let written = [calibration(0, 100), reference(0, 1999), unknown()];
    {
        let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
        for (index, words) in written.iter().enumerate() {
            assert_eq!(
                journal.append(words).unwrap(),
                (index * RECORD_LENGTH) as u64
            );
        }
    }
    let read_back = read(StdDisk, &dir).unwrap();
    assert!(read_back.lossless);
    assert_eq!(read_back.records, written);
    // The unknown type is kept on disk and skipped by the decoder.
    let (known, skipped) = ClockRecord::decode_all(&read_back.records).unwrap();
    assert_eq!((known.len(), skipped), (2, 1));
    // A reopened writer appends after them.
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    assert_eq!(
        journal.append(&calibration(1000, 2000)).unwrap(),
        (3 * RECORD_LENGTH) as u64
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
    assert!(matches!(journal.append(&bad), Err(JournalError::Record(_))));
    drop(journal);
    assert!(read(StdDisk, &dir).unwrap().records.is_empty());
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

/// A torn tail (a record's data, or its index entry, cut short) is never
/// read, by a reader while it is torn nor by the writer that recovers it;
/// a record whose bytes no longer match its CRC is cut, never misread.
#[test]
fn a_torn_tail_is_ignored_until_complete() {
    let dir = temp_dir("torn");
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    journal.append(&calibration(0, 100)).unwrap();
    journal.append(&reference(0, 1999)).unwrap();
    drop(journal);
    // A crash part way through a third: half its data, and a partial
    // index entry.
    append_bytes(&file(&dir, "seg"), &[0xEE; RECORD_LENGTH / 2]);
    append_bytes(&file(&dir, "idx"), &[0x11; 7]);
    let torn = read(StdDisk, &dir).unwrap();
    assert_eq!(torn.records, [calibration(0, 100), reference(0, 1999)]);
    assert!(torn.lossless);
    // The next writer cuts the tail and appends whole records after it.
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
    // The last record's bytes changed under its CRC: cut, not misread.
    let data = file(&dir, "seg");
    let file = std::fs::OpenOptions::new().write(true).open(&data).unwrap();
    std::os::unix::fs::FileExt::write_all_at(&file, &[0xFF], (2 * RECORD_LENGTH + 40) as u64)
        .unwrap();
    drop(file);
    assert_eq!(read(StdDisk, &dir).unwrap().records.len(), 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The agent's source reads the journal at each snapshot: records a
/// producer appends while it runs are seen, and a snapshot proves
/// coverage only once the producer's later records are durable.
#[test]
fn a_source_sees_records_appended_while_it_reads() {
    let dir = temp_dir("tail");
    let mut source = JournalSource::new(StdDisk, &dir);
    assert!(!proves(&source.snapshot()));
    let mut journal = CalibrationJournal::open(StdDisk, &dir).unwrap();
    journal.append(&calibration(0, 100)).unwrap();
    journal.append(&reference(0, 1999)).unwrap();
    // No completeness boundary yet: the producer has not published past.
    assert!(!proves(&source.snapshot()));
    journal.append(&unknown()).unwrap();
    journal.append(&calibration(1000, 2000)).unwrap();
    assert!(!proves(&source.snapshot()));
    journal.append(&reference(2000, 3000)).unwrap();
    assert!(proves(&source.snapshot()));

    // A writer appending on one thread while a reader reads on another:
    // every read is a whole prefix of what was written.
    let writer = std::thread::spawn(move || {
        for index in 0..200u64 {
            let at = 10_000 + index * 10;
            journal.append(&calibration(at, at + 5)).unwrap();
        }
    });
    let mut seen = 0usize;
    loop {
        let finished = writer.is_finished();
        let records = read(StdDisk, &dir).unwrap();
        assert!(records.records.len() >= seen);
        seen = records.records.len();
        for (index, words) in records.records.iter().enumerate().skip(5) {
            let at = 10_000 + (index as u64 - 5) * 10;
            assert_eq!(*words, calibration(at, at + 5));
        }
        if finished {
            assert_eq!(seen, 205);
            break;
        }
    }
    writer.join().unwrap();
    assert_eq!(source.failures(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}
