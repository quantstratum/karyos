// SPDX-License-Identifier: Apache-2.0

//! Tests of sealing and the hash chain (karyos#662): one named
//! inconsistency per kind of tampering, one record kind per chained
//! change, the commit index bound, the virtual clock bound of
//! `seal_interval`, the backlog, and recovery at every crash point in the
//! style of the segment store's gate (`segment/tests.rs`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::num::NonZeroU64;
use std::path::Path;

use proptest::prelude::*;

use super::journal::{IntegrityError, IntegrityJournal};
use super::sealer::{SealBacklog, SealSource, Sealer, run};
use super::*;
use crate::disk::Disk;
use crate::fault::{FaultDisk, Survives};

const DIR: &str = "/archive";
const RECORDING: u64 = 7;

fn open(disk: FaultDisk) -> IntegrityJournal<FaultDisk> {
    IntegrityJournal::open(disk, Path::new(DIR))
        .unwrap()
        .journal
}

fn payload(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 251).unwrap() ^ seed)
        .collect()
}

/// A journal with three sealed ranges of one recording.
fn three_seals() -> (IntegrityJournal<FaultDisk>, Vec<Vec<u8>>) {
    let mut journal = open(FaultDisk::default());
    let ranges = vec![payload(40, 1), payload(64, 2), payload(9, 3)];
    let mut start = 0u64;
    for (index, bytes) in ranges.iter().enumerate() {
        journal
            .seal_segment(RECORDING, start, bytes, index == 2)
            .unwrap();
        start += u64::try_from(bytes.len()).unwrap();
    }
    (journal, ranges)
}

#[test]
fn a_record_round_trips_through_its_bytes() {
    let record = SealRecord {
        kind: SealKind::Purge,
        counter: 9,
        subject: 3,
        start: 100,
        end: 228,
        content: digest(b"segment"),
        previous: digest(b"previous"),
    };
    let bytes = record.encode();
    assert_eq!(SealRecord::decode(&bytes), Ok(record));
}

#[test]
fn a_record_with_an_unknown_version_kind_or_reserved_field_is_refused() {
    let record = three_seals().0.records().unwrap()[0];
    let refused = |offset: usize, value: u8| {
        let mut bytes = record.encode();
        bytes[offset] = value;
        let crc = crate::crc32c::crc32c(&bytes[..104]);
        bytes[104..108].copy_from_slice(&crc.to_le_bytes());
        SealRecord::decode(&bytes).unwrap_err()
    };
    assert_eq!(refused(0, 2), DecodeError::Version { version: 2 });
    assert_eq!(refused(2, 99), DecodeError::Kind { kind: 99 });
    assert_eq!(refused(4, 1), DecodeError::Reserved);
    let mut tail = record.encode();
    tail[111] = 1;
    assert_eq!(SealRecord::decode(&tail), Err(DecodeError::Reserved));
    assert_eq!(
        SealRecord::decode(&tail[..50]),
        Err(DecodeError::Short { length: 50 })
    );
}

#[test]
fn the_record_digest_is_domain_separated_from_a_plain_digest() {
    let record = three_seals().0.records().unwrap()[0];
    assert_ne!(record.digest(), digest(&record.encode()[..104]));
}

#[test]
fn an_altered_byte_in_a_sealed_segment_is_a_digest_mismatch() {
    let (mut journal, mut ranges) = three_seals();
    let records = journal.records().unwrap();
    for (record, bytes) in records.iter().zip(&ranges) {
        assert_eq!(verify_range(record, bytes), Ok(()));
    }
    ranges[1][17] ^= 0x01;
    assert_eq!(
        verify_range(&records[1], &ranges[1]),
        Err(Inconsistency::DigestMismatch { counter: 1 })
    );
    // A shortened range is a mismatch too, not a pass on a prefix.
    assert_eq!(
        verify_range(&records[0], &ranges[0][..39]),
        Err(Inconsistency::DigestMismatch { counter: 0 })
    );
}

#[test]
fn a_removed_seal_record_is_detected() {
    let mut records = three_seals().0.records().unwrap();
    records.remove(1);
    assert_eq!(
        verify_chain(&records).unwrap_err(),
        Inconsistency::CounterGap {
            expected: 1,
            found: 2
        }
    );
}

#[test]
fn a_removed_record_with_the_rest_renumbered_breaks_the_link() {
    let mut records = three_seals().0.records().unwrap();
    records.remove(1);
    records[1].counter = 1;
    assert_eq!(
        verify_chain(&records).unwrap_err(),
        Inconsistency::BrokenLink { counter: 1 }
    );
}

#[test]
fn a_reordered_seal_record_is_detected() {
    let mut records = three_seals().0.records().unwrap();
    records.swap(1, 2);
    assert_eq!(
        verify_chain(&records).unwrap_err(),
        Inconsistency::CounterGap {
            expected: 1,
            found: 2
        }
    );
}

#[test]
fn a_gap_in_the_counter_is_detected_even_when_the_link_is_rewritten() {
    let mut records = three_seals().0.records().unwrap();
    // An attacker drops record 1 and relinks record 2 to record 0, but
    // cannot also renumber it without rewriting every later digest.
    records.remove(1);
    records[1].previous = records[0].digest();
    assert_eq!(
        verify_chain(&records).unwrap_err(),
        Inconsistency::CounterGap {
            expected: 1,
            found: 2
        }
    );
}

#[test]
fn a_rewritten_record_breaks_its_successor_link() {
    let mut records = three_seals().0.records().unwrap();
    records[0].content[0] ^= 1;
    assert_eq!(
        verify_chain(&records).unwrap_err(),
        Inconsistency::BrokenLink { counter: 1 }
    );
}

#[test]
fn a_record_removed_from_the_file_fails_the_reopen() {
    let records = three_seals().0.records().unwrap();
    let disk = FaultDisk::default();
    let mut writer = disk.clone();
    let path = IntegrityJournal::<FaultDisk>::path(Path::new(DIR));
    let file = writer.create(&path).unwrap();
    for (offset, record) in [0u64, 112].into_iter().zip([records[0], records[2]]) {
        writer.write_at(&file, offset, &record.encode()).unwrap();
    }
    let error = IntegrityJournal::open(disk, Path::new(DIR)).unwrap_err();
    assert!(matches!(
        error,
        IntegrityError::Inconsistent(Inconsistency::CounterGap {
            expected: 1,
            found: 2
        })
    ));
}

#[test]
fn a_corrupted_record_before_the_tail_is_malformed_not_truncated() {
    let mut journal = three_seals().0;
    let records = journal.records().unwrap();
    let disk = FaultDisk::default();
    let mut writer = disk.clone();
    let file = writer
        .create(&IntegrityJournal::<FaultDisk>::path(Path::new(DIR)))
        .unwrap();
    for (index, record) in records.iter().enumerate() {
        let mut bytes = record.encode();
        if index == 1 {
            bytes[30] ^= 1;
        }
        let offset = u64::try_from(index * SEAL_RECORD_LENGTH).unwrap();
        writer.write_at(&file, offset, &bytes).unwrap();
    }
    let error = IntegrityJournal::open(disk, Path::new(DIR)).unwrap_err();
    assert!(matches!(
        error,
        IntegrityError::Inconsistent(Inconsistency::Malformed { index: 1, .. })
    ));
}

#[test]
fn a_range_that_skips_bytes_is_refused_with_nothing_written() {
    let mut journal = three_seals().0;
    let before = journal.next_counter();
    let error = journal.seal_segment(RECORDING, 500, b"late", false);
    assert!(matches!(
        error,
        Err(IntegrityError::Inconsistent(Inconsistency::RangeGap {
            subject: RECORDING,
            expected: 113,
            found: 500,
            ..
        }))
    ));
    assert_eq!(journal.next_counter(), before);
    assert_eq!(journal.records().unwrap().len(), 3);
}

/// Appends one change of `kind` after a sealed range and checks it is in
/// the chain, with the digest of its canonical bytes.
fn chained(kind: SealKind, append: impl FnOnce(&mut IntegrityJournal<FaultDisk>) -> SealRecord) {
    let mut journal = three_seals().0;
    let record = append(&mut journal);
    let records = journal.records().unwrap();
    assert_eq!(records.last(), Some(&record));
    assert_eq!(record.kind, kind);
    assert_eq!(record.counter, 3);
    assert_eq!(record.previous, records[2].digest());
    let check = verify_chain(&records).unwrap();
    assert_eq!(check.head(), journal.head());
    // A rewrite of the change moves the head a signed head would carry.
    let mut tampered = records;
    tampered[3].content[5] ^= 1;
    assert_ne!(verify_chain(&tampered).unwrap().head(), journal.head());
}

#[test]
fn a_catalog_change_appears_in_the_chain() {
    chained(SealKind::Catalog, |journal| {
        let record = journal
            .record_catalog_change(RECORDING, 4, b"catalog: stop recording 7")
            .unwrap();
        assert_eq!(record.content, digest(b"catalog: stop recording 7"));
        assert_eq!((record.subject, record.start), (RECORDING, 4));
        record
    });
}

#[test]
fn a_policy_version_change_appears_in_the_chain() {
    chained(SealKind::Policy, |journal| {
        let record = journal
            .record_policy_version(11, 2, b"retain_for=7y min_copies=2")
            .unwrap();
        assert_eq!((record.subject, record.start, record.end), (11, 2, 2));
        record
    });
}

#[test]
fn a_key_registry_append_appears_in_the_chain() {
    chained(SealKind::KeyRegistry, |journal| {
        let key_id = digest(b"public key");
        let record = journal
            .record_key_registry(&key_id, 1, b"ed25519 declared")
            .unwrap();
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&key_id[..8]);
        assert_eq!(record.subject, u64::from_le_bytes(prefix));
        record
    });
}

#[test]
fn a_purge_appears_in_the_chain_with_the_segment_digest() {
    chained(SealKind::Purge, |journal| {
        let segment = digest(&payload(113, 0));
        let record = journal.record_purge(RECORDING, 0, 113, segment).unwrap();
        assert_eq!(record.content, segment);
        assert_eq!((record.start, record.end), (0, 113));
        record
    });
}

#[test]
fn a_cluster_log_is_never_sealed_above_its_commit_index() {
    let mut journal = open(FaultDisk::default());
    let log = payload(100, 5);
    let first = journal.seal_cluster_log(3, 0, &log, 60).unwrap().unwrap();
    assert_eq!((first.start, first.end), (0, 60));
    assert_eq!(first.content, digest(&log[..60]));
    // Nothing committed beyond: no record.
    assert_eq!(
        journal.seal_cluster_log(3, 60, &log[60..], 60).unwrap(),
        None
    );
    assert_eq!(
        journal.seal_cluster_log(3, 60, &log[60..], 10).unwrap(),
        None
    );
    let second = journal
        .seal_cluster_log(3, 60, &log[60..], 500)
        .unwrap()
        .unwrap();
    assert_eq!((second.start, second.end), (60, 100));
    assert_eq!(second.kind, SealKind::ClusterLog);
}

proptest! {
    /// Whatever the range and the commit, a Cluster log seal ends at or
    /// below the commit and covers exactly the committed bytes.
    #[test]
    fn a_cluster_log_seal_never_covers_an_entry_above_the_commit(
        start in 0u64..1_000,
        length in 0usize..300,
        commit in 0u64..1_500,
    ) {
        let mut journal = open(FaultDisk::default());
        let bytes = payload(length, 9);
        match journal.seal_cluster_log(1, start, &bytes, commit).unwrap() {
            Some(record) => {
                prop_assert!(record.end <= commit);
                prop_assert!(record.start < record.end);
                let covered = usize::try_from(record.end - start).unwrap();
                prop_assert_eq!(record.content, digest(&bytes[..covered]));
            }
            None => prop_assert!(commit <= start || length == 0),
        }
    }

    /// Decoding arbitrary bytes never panics, and whatever decodes
    /// re-encodes to the same bytes.
    #[test]
    fn decoding_arbitrary_bytes_is_total(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(record) = SealRecord::decode(&bytes) {
            prop_assert_eq!(&record.encode()[..], &bytes[..SEAL_RECORD_LENGTH]);
        }
    }
}

const INTERVAL: NonZeroU64 = NonZeroU64::new(1_000).unwrap();

/// Reads `[start, end)` of the recording `payload` holds.
fn reader(bytes: &[u8]) -> impl FnMut(u64, u64, u64) -> std::io::Result<Vec<u8>> + '_ {
    |_, start, end| {
        let range = usize::try_from(start).unwrap()..usize::try_from(end).unwrap();
        Ok(bytes[range].to_vec())
    }
}

#[test]
fn an_open_segment_is_sealed_within_its_seal_interval_on_a_virtual_clock() {
    let mut journal = open(FaultDisk::default());
    let mut sealer = Sealer::new(INTERVAL);
    let bytes = payload(300, 4);
    sealer.track(RECORDING, SealSource::Segments, 0).unwrap();
    sealer.written(RECORDING, 100, 5_000).unwrap();
    assert_eq!(sealer.next_deadline_ns(), Some(6_000));
    // One ns early: nothing is due.
    assert_eq!(
        run(&mut sealer, &mut journal, 5_999, reader(&bytes)).unwrap(),
        0
    );
    assert_eq!(journal.next_counter(), 0);
    // More bytes do not push the deadline back.
    sealer.written(RECORDING, 180, 5_500).unwrap();
    assert_eq!(
        run(&mut sealer, &mut journal, 6_000, reader(&bytes)).unwrap(),
        1
    );
    let records = journal.records().unwrap();
    assert_eq!(
        (records[0].kind, records[0].start, records[0].end),
        (SealKind::OpenSegment, 0, 180)
    );
    assert_eq!(sealer.backlog(6_000), SealBacklog::default());
    assert_eq!(sealer.next_deadline_ns(), None);
    // The next window starts at the next write.
    sealer.written(RECORDING, 250, 9_000).unwrap();
    assert_eq!(
        run(&mut sealer, &mut journal, 9_999, reader(&bytes)).unwrap(),
        0
    );
    assert_eq!(
        run(&mut sealer, &mut journal, 10_000, reader(&bytes)).unwrap(),
        1
    );
    let records = journal.records().unwrap();
    assert_eq!((records[1].start, records[1].end), (180, 250));
    for record in &records {
        let range = usize::try_from(record.start).unwrap()..usize::try_from(record.end).unwrap();
        verify_range(record, &bytes[range]).unwrap();
    }
}

#[test]
fn a_closed_segment_is_sealed_at_once_and_stops_being_tracked() {
    let mut journal = open(FaultDisk::default());
    let mut sealer = Sealer::new(INTERVAL);
    let bytes = payload(64, 8);
    sealer.track(RECORDING, SealSource::Segments, 0).unwrap();
    sealer.close(RECORDING, 64, 1).unwrap();
    assert_eq!(
        run(&mut sealer, &mut journal, 1, reader(&bytes)).unwrap(),
        1
    );
    assert_eq!(journal.records().unwrap()[0].kind, SealKind::ClosedSegment);
    assert_eq!(
        sealer.written(RECORDING, 64, 2),
        Err(sealer::SealerError::Untracked {
            recording: RECORDING
        })
    );
}

#[test]
fn the_sealing_backlog_is_observable() {
    let mut sealer = Sealer::new(INTERVAL);
    assert_eq!(sealer.backlog(0), SealBacklog::default());
    sealer.track(1, SealSource::Segments, 0).unwrap();
    sealer.track(2, SealSource::Segments, 10).unwrap();
    sealer.written(1, 50, 100).unwrap();
    sealer.written(2, 40, 600).unwrap();
    assert_eq!(
        sealer.backlog(1_100),
        SealBacklog {
            ranges: 2,
            bytes: 80,
            overdue: 1,
            oldest_age_ns: Some(1_000),
        }
    );
    // A failed journal leaves the backlog where it was.
    let mut journal = open(FaultDisk::default());
    let failed = run(&mut sealer, &mut journal, 1_100, |_, _, _| {
        Err(std::io::Error::other("read failed"))
    });
    assert!(matches!(failed, Err(IntegrityError::Io(_))));
    assert_eq!(sealer.backlog(1_100).bytes, 80);
}

#[test]
fn a_cluster_log_is_sealed_through_the_schedule_up_to_its_commit_only() {
    let mut journal = open(FaultDisk::default());
    let mut sealer = Sealer::new(INTERVAL);
    let log = payload(90, 6);
    sealer.track(3, SealSource::ClusterLog, 0).unwrap();
    // The caller reports the commit position, never the appended end.
    sealer.written(3, 30, 0).unwrap();
    assert_eq!(
        run(&mut sealer, &mut journal, 1_000, reader(&log)).unwrap(),
        1
    );
    let record = journal.records().unwrap()[0];
    assert_eq!((record.kind, record.end), (SealKind::ClusterLog, 30));
}

#[test]
fn a_schedule_step_out_of_order_is_refused() {
    let mut sealer = Sealer::new(INTERVAL);
    sealer.track(1, SealSource::Segments, 0).unwrap();
    assert_eq!(
        sealer.track(1, SealSource::Segments, 0),
        Err(sealer::SealerError::Tracked { recording: 1 })
    );
    sealer.written(1, 20, 0).unwrap();
    assert_eq!(
        sealer.written(1, 10, 1),
        Err(sealer::SealerError::Backwards {
            recording: 1,
            written: 20,
            got: 10
        })
    );
    let due = sealer.due(1_000)[0];
    sealer.sealed(&due, 20).unwrap();
    sealer.written(1, 30, 1_001).unwrap();
    assert_eq!(
        sealer.sealed(&due, 20),
        Err(sealer::SealerError::Stale {
            recording: 1,
            sealed: 20,
            start: 0
        })
    );
}

// Crash points, in the style of `segment/tests.rs`: a workload that seals
// ranges and chains changes runs on a disk that crashes after every
// possible amount of work; for each crash, under both crash models,
// recovery must keep every record reported appended, chain, and continue.

/// One step of the crash workload.
#[derive(Debug, Clone, Copy)]
enum Step {
    Seal(usize, bool),
    Catalog(u64),
    Policy(u64),
    Key(u64),
    Purge,
}

fn workload() -> Vec<Step> {
    vec![
        Step::Seal(40, false),
        Step::Catalog(1),
        Step::Seal(25, false),
        Step::Policy(1),
        Step::Key(1),
        Step::Seal(7, true),
        Step::Purge,
        Step::Catalog(2),
    ]
}

fn apply(
    journal: &mut IntegrityJournal<FaultDisk>,
    step: Step,
) -> Result<SealRecord, IntegrityError> {
    let start = journal.sealed_end(RECORDING).unwrap_or(0);
    match step {
        Step::Seal(length, closes) => {
            journal.seal_segment(RECORDING, start, &payload(length, 1), closes)
        }
        Step::Catalog(generation) => {
            journal.record_catalog_change(RECORDING, generation, b"catalog")
        }
        Step::Policy(version) => journal.record_policy_version(1, version, b"policy"),
        Step::Key(sequence) => journal.record_key_registry(&digest(b"key"), sequence, b"registry"),
        Step::Purge => journal.record_purge(RECORDING, 0, start, digest(b"segment")),
    }
}

/// Runs the workload from `done` steps; returns the steps reported done.
fn run_steps(journal: &mut IntegrityJournal<FaultDisk>, done: usize) -> usize {
    let mut done = done;
    for &step in workload().iter().skip(done) {
        if apply(journal, step).is_err() {
            break;
        }
        done += 1;
    }
    done
}

#[test]
fn a_crash_while_sealing_leaves_a_chain_recovery_can_continue_at_every_crash_point() {
    let free = FaultDisk::default();
    let mut journal = open(free.clone());
    assert_eq!(run_steps(&mut journal, 0), workload().len());
    let total = free.used();
    let expected = journal.records().unwrap();
    let mut crashes = 0u64;
    for budget in 0..=total {
        let disk = FaultDisk::with_budget(budget);
        let reported = match IntegrityJournal::open(disk.clone(), Path::new(DIR)) {
            Ok(opened) => {
                let mut journal = opened.journal;
                run_steps(&mut journal, 0)
            }
            Err(_) => 0,
        };
        if !disk.has_crashed() {
            continue;
        }
        crashes += 1;
        for survives in [Survives::Synced, Survives::Everything] {
            let restarted = disk.after_crash(survives);
            let opened = IntegrityJournal::open(restarted, Path::new(DIR))
                .unwrap_or_else(|error| panic!("budget {budget} {survives:?}: {error}"));
            let mut journal = opened.journal;
            let kept = usize::try_from(journal.next_counter()).unwrap();
            assert!(
                kept >= reported,
                "budget {budget} {survives:?}: kept {kept} of {reported} reported"
            );
            assert!(
                kept <= reported + 1,
                "budget {budget} {survives:?}: kept {kept}"
            );
            // The recovered records are the workload's own prefix.
            let records = journal.records().unwrap();
            assert_eq!(
                records[..],
                expected[..kept],
                "budget {budget} {survives:?}"
            );
            // Recovery continues the chain to the end of the workload.
            assert_eq!(run_steps(&mut journal, kept), workload().len());
            let records = journal.records().unwrap();
            assert_eq!(records, expected, "budget {budget} {survives:?}");
            verify_chain(&records).unwrap();
        }
    }
    assert!(crashes > u64::try_from(workload().len()).unwrap());
}

#[test]
fn a_failed_append_poisons_the_journal_until_it_is_reopened() {
    let free = FaultDisk::default();
    let mut journal = open(free.clone());
    apply(&mut journal, Step::Seal(10, false)).unwrap();
    let used = free.used();
    // Crash inside the second record's write.
    let disk = FaultDisk::with_budget(used + 50);
    let mut journal = open(disk.clone());
    apply(&mut journal, Step::Seal(10, false)).unwrap();
    assert!(apply(&mut journal, Step::Catalog(1)).is_err());
    assert!(matches!(
        apply(&mut journal, Step::Catalog(1)),
        Err(IntegrityError::Poisoned)
    ));
    let opened =
        IntegrityJournal::open(disk.after_crash(Survives::Everything), Path::new(DIR)).unwrap();
    assert!(opened.truncated > 0);
    assert_eq!(opened.journal.next_counter(), 1);
}

#[test]
fn a_partial_seal_keeps_the_age_of_the_bytes_still_pending() {
    let mut sealer = Sealer::new(INTERVAL);
    sealer.track(RECORDING, SealSource::ClusterLog, 0).unwrap();
    sealer.written(RECORDING, 100, 0).unwrap();
    let due = sealer.due(1_000)[0];
    sealer.sealed(&due, 50).unwrap();
    assert_eq!(
        sealer.backlog(1_000),
        SealBacklog {
            ranges: 1,
            bytes: 50,
            overdue: 1,
            oldest_age_ns: Some(1_000),
        }
    );
    assert_eq!(sealer.next_deadline_ns(), Some(1_000));
}

#[test]
fn a_close_reported_after_a_seal_was_found_due_stays_due() {
    let mut journal = open(FaultDisk::default());
    let mut sealer = Sealer::new(INTERVAL);
    let bytes = payload(100, 5);
    sealer.track(RECORDING, SealSource::Segments, 0).unwrap();
    sealer.written(RECORDING, 100, 0).unwrap();
    let due = sealer.due(1_000)[0];
    assert!(!due.closes);
    sealer.close(RECORDING, 100, 1_001).unwrap();
    journal.seal_segment(RECORDING, 0, &bytes, false).unwrap();
    sealer.sealed(&due, 100).unwrap();
    let pending = sealer.due(1_001);
    assert_eq!(pending.len(), 1);
    assert!(pending[0].closes);
    assert_eq!(
        run(&mut sealer, &mut journal, 1_001, reader(&bytes)).unwrap(),
        1
    );
    assert_eq!(journal.records().unwrap()[1].kind, SealKind::ClosedSegment);
    assert!(sealer.due(1_002).is_empty());
}

#[test]
fn a_read_of_the_wrong_length_changes_neither_the_journal_nor_the_schedule() {
    for length in [50usize, 101] {
        let mut journal = open(FaultDisk::default());
        let mut sealer = Sealer::new(INTERVAL);
        sealer.track(RECORDING, SealSource::Segments, 0).unwrap();
        sealer.written(RECORDING, 100, 0).unwrap();
        let failed = run(&mut sealer, &mut journal, 1_000, |_, _, _| {
            Ok(payload(length, 9))
        });
        assert_eq!(
            failed.unwrap_err().to_string(),
            IntegrityError::from(sealer::SealerError::ReadLength {
                recording: RECORDING,
                expected: 100,
                got: u64::try_from(length).unwrap(),
            })
            .to_string()
        );
        assert_eq!(journal.next_counter(), 0);
        assert_eq!(sealer.backlog(1_000).bytes, 100);
        assert_eq!(sealer.next_deadline_ns(), Some(1_000));
        let bytes = payload(100, 9);
        assert_eq!(
            run(&mut sealer, &mut journal, 1_000, reader(&bytes)).unwrap(),
            1
        );
    }
}

/// karyos#1031: `records_from` reads only the records past those a caller
/// holds, so a poll that keeps them never rereads the journal.
#[test]
fn records_from_reads_only_the_new_records() {
    let (mut journal, records) = super::test_support::chain(5);
    assert_eq!(journal.records_from(0).unwrap(), records);
    assert_eq!(journal.records_from(3).unwrap(), records[3..]);
    assert!(journal.records_from(5).unwrap().is_empty());
    journal.seal_segment(3, 40, b"more", false).unwrap();
    let new = journal.records_from(5).unwrap();
    assert_eq!(new.len(), 1);
    assert_eq!(new[0].start, 40);
}
