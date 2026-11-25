// SPDX-License-Identifier: Apache-2.0

//! R-CORE-14's acceptance criteria (karyos#725), one test each.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::PathBuf;

use super::super::{GapReason, JournalRetention};
use super::*;
use karyos_sys::frame::FRAME_ALIGNMENT;

/// The time the server lets one connection take to write its reply
/// (`server::WRITE_DEADLINE`, on Linux only).
const WRITE_DEADLINE: std::time::Duration = std::time::Duration::from_millis(250);

/// A fresh journal directory for test `name`.
fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-journal-history-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A close request on guard `guard` at `time`, durable.
fn close(journal: &mut Journal, guard: u64, time: u64) -> u64 {
    let mut record = JournalRecord::new(Kind::CloseRequest, time);
    record.guard = guard;
    record.reason = b"drill".to_vec();
    journal.append_durable(&record, time).unwrap()
}

/// Every record from `from` on, page by page of `count`, checking that
/// each record's position is the previous one's `next` and each page
/// starts where the last ended.
fn follow(journal: &mut Journal, from: Option<HistoryCursor>, count: usize) -> Vec<HistoryRecord> {
    let mut cursor = from;
    let mut all: Vec<HistoryRecord> = Vec::new();
    loop {
        let page = journal.history(cursor, count).unwrap();
        assert!(page.records.len() <= count);
        let mut expected = cursor.map_or(page.floor, |cursor| cursor.position);
        for record in &page.records {
            // Padding may precede a record, never another record.
            assert!(record.position >= expected, "{record:?} before {expected}");
            if let Some(last) = all.last() {
                assert_eq!(last.next, record.position, "a gap in the sequence");
            }
            expected = record.next;
            all.push(record.clone());
        }
        if let Some(last) = page.records.last() {
            assert_eq!(last.next, page.next);
        }
        if page.next == page.head && page.records.is_empty() {
            return all;
        }
        cursor = Some(HistoryCursor::new(page.recording, page.next));
    }
}

fn kinds(records: &[HistoryRecord]) -> Vec<Kind> {
    records
        .iter()
        .map(|record| record.record.as_ref().unwrap().kind)
        .collect()
}

/// Read in pages, the history holds every durable record once, in order,
/// each record's `next` the following one's position, across terms and
/// their padding.
#[test]
fn pages_hold_every_record_once_in_sequence() {
    let dir = dir("sequence");
    let mut journal = Journal::open(&dir, 1).unwrap();
    let mut written = Vec::new();
    // Past a term, so padding sits between two records.
    let mut time = 10;
    while journal.head().unwrap().position < u64::from(super::super::TERM_LENGTH) + 4096 {
        written.push(close(&mut journal, time, time));
        time += 1;
    }
    let all = follow(&mut journal, None, 7);
    let positions: Vec<u64> = all.iter().map(|record| record.position).collect();
    // The journal's own start record, then every close.
    assert_eq!(kinds(&all[..1]), [Kind::AgentStarted]);
    assert_eq!(positions[1..], written[..]);
    assert_eq!(all.last().unwrap().next, journal.head().unwrap().position);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The snapshot-to-change handoff: a reader that takes the head with the
/// view and follows the history from it sees every record written after,
/// and none written before.
#[test]
fn the_handoff_misses_and_repeats_nothing() {
    let dir = dir("handoff");
    let mut journal = Journal::open(&dir, 1).unwrap();
    let before: Vec<u64> = (0..5).map(|n| close(&mut journal, n, 10 + n)).collect();
    let head = journal.head().unwrap();
    let after: Vec<u64> = (0..5).map(|n| close(&mut journal, n, 20 + n)).collect();
    let read: Vec<u64> = follow(&mut journal, Some(head), 2)
        .iter()
        .map(|record| record.position)
        .collect();
    assert_eq!(read, after);
    assert!(before.iter().all(|position| *position < head.position));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A record not yet durable is not in the history, so no page names a
/// position a crash could cut; it is once a durable append covers it.
#[test]
fn only_durable_records_are_served() {
    let dir = dir("durable");
    let mut journal = Journal::open(&dir, 1).unwrap();
    let head = journal.head().unwrap();
    let mut record = JournalRecord::new(Kind::CloseRequest, 5);
    record.guard = 3;
    let position = journal.append(&record, 5).unwrap();
    let page = journal.history(Some(head), HISTORY_MAX).unwrap();
    assert!(page.records.is_empty(), "{page:?}");
    assert_eq!(page.next, head.position);
    let _ = close(&mut journal, 4, 6);
    let page = journal.history(Some(head), HISTORY_MAX).unwrap();
    assert_eq!(page.records[0].position, position);
    assert_eq!(page.records.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cursor survives the agent's restart, clean or not: after an unclean
/// stop the history goes on from it with the unknown interval the
/// journal recorded, in place, listed in the page.
#[test]
fn a_cursor_survives_a_restart_and_crosses_its_unknown_interval() {
    let dir = dir("restart");
    let mut journal = Journal::open(&dir, 1).unwrap();
    let _ = close(&mut journal, 1, 10);
    let cursor = journal.head().unwrap();
    let _ = close(&mut journal, 2, 11);
    // A clean stop and restart: the cursor goes on.
    journal.stop(12).unwrap();
    drop(journal);
    let mut journal = Journal::open(&dir, 13).unwrap();
    let read = follow(&mut journal, Some(cursor), HISTORY_MAX);
    assert_eq!(
        kinds(&read),
        [Kind::CloseRequest, Kind::AgentStopped, Kind::AgentStarted]
    );
    let cursor = journal.head().unwrap();
    // An unclean one, a request its outcome never followed: the next
    // start records an unknown interval, which the history serves as
    // itself.
    let _ = close(&mut journal, 3, 14);
    drop(journal);
    let mut journal = Journal::open_with(&dir, 15, JournalRetention::default()).unwrap();
    let page = journal.history(Some(cursor), HISTORY_MAX).unwrap();
    assert_eq!(
        kinds(&page.records),
        [
            Kind::CloseRequest,
            Kind::UnknownInterval,
            Kind::AgentStarted
        ]
    );
    let interval = &page.records[1];
    assert_eq!(page.unknown_intervals(), [interval.position]);
    let record = interval.record.as_ref().unwrap();
    assert_eq!(
        GapReason::from_code(record.code),
        GapReason::RequestWithoutOutcome
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cursor that cannot be read is refused, typed, never answered with
/// an empty page: another recording, past the durable end, not at a
/// record.
#[test]
fn a_cursor_that_cannot_be_read_is_refused_typed() {
    let dir = dir("refused");
    let mut journal = Journal::open(&dir, 1).unwrap();
    let _ = close(&mut journal, 1, 10);
    let head = journal.head().unwrap();
    let recording = head.recording;
    assert_eq!(
        journal.history(Some(HistoryCursor::new(recording + 1, 0)), 1),
        Err(HistoryRefusal::RecordingChanged {
            recording,
            floor: 0
        })
    );
    assert_eq!(
        journal.history(Some(HistoryCursor::new(recording, head.position + 64)), 1),
        Err(HistoryRefusal::Ahead {
            recording,
            head: head.position
        })
    );
    assert_eq!(
        journal.history(Some(HistoryCursor::new(recording, 3)), 1),
        Err(HistoryRefusal::NotARecord { position: 3 })
    );
    journal.break_recorder();
    assert_eq!(journal.history(None, 1), Err(HistoryRefusal::Unavailable));
    assert_eq!(journal.head(), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A full page is bounded work: reading [`HISTORY_MAX`] records, the
/// most one request reads, holds the polling thread far less than the
/// time the server already lets one connection take to answer.
#[test]
fn a_full_page_is_bounded_work() {
    let dir = dir("bounded");
    let mut journal = Journal::open(&dir, 1).unwrap();
    for n in 0..(2 * HISTORY_MAX as u64) {
        let mut record = JournalRecord::new(Kind::CloseRequest, n);
        record.reason = vec![b'r'; super::super::MAX_REASON];
        let _ = journal.append(&record, n).unwrap();
    }
    let _ = close(&mut journal, 0, 1_000);
    let mut slowest = std::time::Duration::ZERO;
    for _ in 0..16 {
        let started = std::time::Instant::now();
        let page = journal.history(None, HISTORY_MAX).unwrap();
        slowest = slowest.max(started.elapsed());
        assert_eq!(page.records.len(), HISTORY_MAX);
    }
    assert!(
        slowest < WRITE_DEADLINE,
        "a full page took {slowest:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex on #1274: an aligned cursor inside a record is not a record,
/// found by walking the frames of its term, never read as a header; a
/// head that padding now starts at still is one.
#[test]
fn a_cursor_inside_a_record_is_not_a_record() {
    let dir = dir("inside");
    let mut journal = Journal::open(&dir, 1).unwrap();
    let position = close(&mut journal, 1, 10);
    let recording = journal.recording();
    let inside = position + u64::from(FRAME_ALIGNMENT);
    assert_eq!(
        journal.history(Some(HistoryCursor::new(recording, inside)), 1),
        Err(HistoryRefusal::NotARecord { position: inside })
    );
    // Heads given out while the journal grew past a term: each reads on,
    // padding included.
    let mut heads = Vec::new();
    let mut time = 11;
    while journal.head().unwrap().position < u64::from(super::super::TERM_LENGTH) + 1024 {
        heads.push(journal.head().unwrap());
        let _ = close(&mut journal, time, time);
        time += 1;
    }
    for head in heads {
        let page = journal.history(Some(head), 1).unwrap();
        assert_eq!(page.records.len(), 1, "{head:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex on #1274: a damaged frame length is refused `corrupt` at its
/// position before anything is read on it, never allocated.
#[test]
fn a_damaged_frame_length_is_corrupt() {
    let dir = dir("damaged");
    let mut journal = Journal::open(&dir, 1).unwrap();
    let position = close(&mut journal, 1, 10);
    let _ = close(&mut journal, 2, 11);
    // The length's third byte: some 16 MiB, past any term.
    journal.damage(position + 2);
    assert_eq!(
        journal.history(None, HISTORY_MAX),
        Err(HistoryRefusal::Corrupt { position })
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex on #1274: the head the view takes follows every record written
/// before it, a close's record not yet durable included, once the
/// journal is settled.
#[test]
fn a_settled_head_follows_every_record_written() {
    let dir = dir("settle");
    let mut journal = Journal::open(&dir, 1).unwrap();
    let mut record = JournalRecord::new(Kind::CloseOutcome, 5);
    record.guard = 3;
    let position = journal.append(&record, 5).unwrap();
    assert!(journal.head().unwrap().position <= position);
    journal.settle(6);
    let head = journal.head().unwrap();
    assert!(head.position > position);
    assert!(!journal.unavailable());
    // Nothing written since: settling again changes nothing.
    journal.settle(7);
    assert_eq!(journal.head(), Some(head));
    assert!(
        journal
            .history(Some(head), HISTORY_MAX)
            .unwrap()
            .records
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
