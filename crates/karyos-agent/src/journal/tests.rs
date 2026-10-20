// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::PathBuf;

use super::*;

/// A fresh journal directory for test `name`.
fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-journal-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn request(kind: Kind, time: u64, guard: u64) -> JournalRecord {
    let mut record = JournalRecord::new(kind, time);
    record.guard = guard;
    record.operation = time;
    record.operator = 1000;
    record.parameters = 0xD16E57;
    record.reason = b"drill".to_vec();
    record
}

/// A record reads back field for field, its reason cut to the bound; a
/// payload of another layout is not a record.
#[test]
fn a_record_round_trips() {
    let mut record = request(Kind::ReopenOutcome, 7, 3);
    record.expected = 5;
    record.code = 9;
    record.word = 6;
    assert_eq!(
        JournalRecord::decode(&record.encode()),
        Some(record.clone())
    );
    record.reason = vec![b'r'; MAX_REASON + 10];
    let decoded = JournalRecord::decode(&record.encode()).unwrap();
    assert_eq!(decoded.reason.len(), MAX_REASON);
    let mut other = record.encode();
    other[0] = 2;
    assert_eq!(JournalRecord::decode(&other), None);
    assert_eq!(JournalRecord::decode(&[]), None);
}

/// A journal resumes its recording across restarts: records of a run with
/// every request answered leave no unknown interval.
#[test]
fn a_journal_resumes_its_recording() {
    let dir = dir("resume");
    let mut journal = Journal::open(&dir, 10).unwrap();
    let recording = journal.recording();
    assert_eq!(journal.gap(), None);
    let first = journal
        .append(&request(Kind::CloseRequest, 11, 3), 11)
        .unwrap();
    assert_eq!(first, 0);
    let second = journal
        .append_durable(&request(Kind::CloseOutcome, 12, 3), 12)
        .unwrap();
    assert!(second > first);
    drop(journal);
    let journal = Journal::open(&dir, 20).unwrap();
    assert_eq!(journal.recording(), recording);
    assert_eq!(journal.gap(), None);
    assert_eq!(journal.failed_appends(), 0);
    assert!(!journal.unavailable());
}

/// A request with no outcome after it means an operation may have taken
/// effect unrecorded: the next start records an unknown interval from the
/// request's time, which stays open across restarts until an
/// administrator acknowledges that very interval.
#[test]
fn an_unanswered_request_opens_an_unknown_interval_until_acknowledged() {
    let dir = dir("gap");
    let mut journal = Journal::open(&dir, 10).unwrap();
    let _ = journal
        .append_durable(&request(Kind::ReopenRequest, 15, 3), 15)
        .unwrap();
    drop(journal);
    let journal = Journal::open(&dir, 100).unwrap();
    let gap = journal.gap().unwrap();
    assert_eq!((gap.from, gap.to), (15, 100));
    drop(journal);
    // Still open after another start, and not recorded twice.
    let mut journal = Journal::open(&dir, 200).unwrap();
    assert_eq!(journal.gap(), Some(gap));
    assert!(matches!(
        journal.acknowledge_gap(gap.position + 1, 0, 210),
        Err(JournalError::NoGap)
    ));
    journal.acknowledge_gap(gap.position, 0, 210).unwrap();
    assert_eq!(journal.gap(), None);
    assert!(matches!(
        journal.acknowledge_gap(gap.position, 0, 211),
        Err(JournalError::NoGap)
    ));
    drop(journal);
    let journal = Journal::open(&dir, 300).unwrap();
    assert_eq!(journal.gap(), None);
}

/// Records written across a term end, with the padding block a log puts
/// there, are all read back at the next start.
#[test]
fn a_journal_reads_back_across_terms() {
    let dir = dir("terms");
    let mut journal = Journal::open(&dir, 1).unwrap();
    // About 64 KiB of records: more than one term.
    for time in 2..400 {
        let mut record = request(Kind::CloseRequest, time, 3);
        record.reason = vec![b'x'; MAX_REASON];
        let _ = journal.append(&record, time).unwrap();
        let _ = journal
            .append(&request(Kind::CloseOutcome, time, 3), time)
            .unwrap();
    }
    let _ = journal
        .append_durable(&request(Kind::ReopenRequest, 500, 3), 500)
        .unwrap();
    drop(journal);
    let journal = Journal::open(&dir, 600).unwrap();
    let gap = journal.gap().unwrap();
    assert_eq!((gap.from, gap.to), (500, 600));
    assert!(gap.position > u64::from(TERM_LENGTH));
}

/// A journal recording stopped by another hand is not resumed: a new one
/// starts, and since what happened in between is not known, it opens with
/// an unknown interval from the last record's time.
#[test]
fn a_stopped_journal_is_followed_by_a_new_one_with_an_unknown_interval() {
    let dir = dir("stopped");
    let mut journal = Journal::open(&dir, 10).unwrap();
    let first = journal.recording();
    let _ = journal
        .append_durable(&request(Kind::CloseOutcome, 11, 3), 11)
        .unwrap();
    drop(journal);
    let mut catalog = Catalog::open(StdDisk, &dir).unwrap().catalog;
    catalog
        .stop(
            first,
            0,
            12,
            karyos_archive::catalog::StopReason::Stopped,
            false,
        )
        .unwrap();
    drop(catalog);
    let journal = Journal::open(&dir, 50).unwrap();
    assert_ne!(journal.recording(), first);
    let gap = journal.gap().unwrap();
    assert_eq!((gap.position, gap.from, gap.to), (0, 0, 50));
}
