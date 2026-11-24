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

/// A relayed request's record keeps the relay apart from the operator
/// (karyos#708); a record no relay carried is byte for byte the layout
/// before relays, and anything but one relay word after the reason is
/// not a record.
#[test]
fn a_relay_is_recorded_apart_from_the_operator() {
    let local = request(Kind::CloseRequest, 7, 3);
    assert_eq!(local.encode().len(), WORDS * 8 + b"drill".len());
    let mut relayed = local.clone();
    relayed.relay = 7;
    relayed.operator = 50_001;
    let bytes = relayed.encode();
    assert_eq!(bytes.len(), WORDS * 8 + b"drill".len() + 8);
    let decoded = JournalRecord::decode(&bytes).unwrap();
    assert_eq!((decoded.operator, decoded.relay), (50_001, 7));
    assert_eq!(decoded, relayed);
    let mut torn = bytes.clone();
    torn.pop();
    assert_eq!(JournalRecord::decode(&torn), None);
    let mut longer = bytes;
    longer.push(0);
    assert_eq!(JournalRecord::decode(&longer), None);
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
    // After the run's `agent started` record.
    assert!(first > 0);
    let second = journal
        .append_durable(&request(Kind::CloseOutcome, 12, 3), 12)
        .unwrap();
    assert!(second > first);
    journal.stop(13).unwrap();
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
    let mut journal = Journal::open(&dir, 100).unwrap();
    let gap = journal.gap().unwrap();
    assert_eq!((gap.from, gap.to), (15, 100));
    assert_eq!(gap.reason, GapReason::RequestWithoutOutcome);
    journal.stop(101).unwrap();
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
    journal.stop(212).unwrap();
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

/// Once an append failed, the journal refuses every append, counts each,
/// and keeps the time of the first; the next start recovers it.
#[test]
fn a_failed_journal_refuses_appends_until_it_reopens() {
    let dir = dir("failed");
    let mut journal = Journal::open(&dir, 10).unwrap();
    journal.break_recorder();
    for now in [20, 30] {
        assert!(matches!(
            journal.append(&request(Kind::CloseRequest, now, 3), now),
            Err(JournalError::Unavailable)
        ));
    }
    assert!(journal.unavailable());
    assert_eq!(
        (journal.failed_appends(), journal.failed_at()),
        (2, Some(20))
    );
    drop(journal);
    let journal = Journal::open(&dir, 40).unwrap();
    assert!(!journal.unavailable());
    assert_eq!(journal.failed_at(), None);
    // The failed run could not record its stop: an unclean stop.
    assert_eq!(
        journal.gap().map(|gap| gap.reason),
        Some(GapReason::UncleanStop)
    );
}

/// Kind 7 (DESIGN, karyos#490 follow-up): a run that ends with
/// `agent stopped` leaves no unknown interval; one that ends otherwise,
/// even with every request answered, leaves an unclean stop, with the last
/// record's time as its start. An empty journal is no gap.
#[test]
fn a_run_without_a_clean_stop_leaves_an_unclean_stop() {
    let dir = dir("unclean");
    let mut journal = Journal::open(&dir, 10).unwrap();
    assert_eq!(journal.gap(), None, "an empty journal");
    let _ = journal
        .append(&request(Kind::CloseRequest, 11, 3), 11)
        .unwrap();
    let _ = journal
        .append_durable(&request(Kind::CloseOutcome, 12, 3), 12)
        .unwrap();
    // A crash: no stop.
    drop(journal);
    let mut journal = Journal::open(&dir, 50).unwrap();
    let gap = journal.gap().unwrap();
    assert_eq!(
        (gap.reason, gap.from, gap.to),
        (GapReason::UncleanStop, 12, 50)
    );
    journal.acknowledge_gap(gap.position, 0, 51).unwrap();
    journal.stop(52).unwrap();
    drop(journal);
    let journal = Journal::open(&dir, 60).unwrap();
    assert_eq!(journal.gap(), None, "a clean stop");
}

/// A journal that failed cannot record its stop: the next start records
/// the unclean stop, so a close made while it was down, which has no
/// record, falls in an unknown interval.
#[test]
fn a_failed_journal_cannot_stop_cleanly() {
    let dir = dir("unstoppable");
    let mut journal = Journal::open(&dir, 10).unwrap();
    journal.break_recorder();
    // A close while the journal is down: its request is not written.
    assert!(
        journal
            .append(&request(Kind::CloseRequest, 20, 3), 20)
            .is_err()
    );
    assert!(journal.stop(30).is_err());
    drop(journal);
    let journal = Journal::open(&dir, 40).unwrap();
    assert_eq!(
        journal.gap().map(|gap| gap.reason),
        Some(GapReason::UncleanStop)
    );
}

/// Reason codes round-trip, an unknown one reading as an unclean stop.
#[test]
fn gap_reasons_round_trip() {
    for reason in [
        GapReason::RequestWithoutOutcome,
        GapReason::TornTail,
        GapReason::UncleanStop,
        GapReason::JournalReplaced,
        GapReason::JournalUnavailableAtStart,
    ] {
        assert_eq!(GapReason::from_code(reason.code()), reason);
    }
    assert_eq!(GapReason::from_code(99), GapReason::UncleanStop);
}

/// The retention kinds (M12) take new codes: every existing code still
/// decodes to its kind, so an older journal reads unchanged.
#[test]
fn the_retention_kinds_keep_the_existing_codes() {
    let existing = [
        Kind::CloseRequest,
        Kind::CloseOutcome,
        Kind::ReopenRequest,
        Kind::ReopenOutcome,
        Kind::UnknownInterval,
        Kind::GapAcknowledged,
        Kind::AgentStopped,
        Kind::AgentStarted,
    ];
    for (code, kind) in (1u64..).zip(existing) {
        assert_eq!(kind.code(), code);
        assert_eq!(Kind::from_code(code), Some(kind));
    }
    for code in 9..=16 {
        let kind = Kind::from_code(code).unwrap();
        assert_eq!(kind.code(), code);
        let record = request(kind, 5, 7);
        assert_eq!(JournalRecord::decode(&record.encode()), Some(record));
    }
    // 17 and 18 are the rate change's (karyos#740), 19 a submit's
    // (karyos#738); 20 to 22 a Cluster admin command's (karyos#772); 23
    // is no kind yet.
    assert_eq!(Kind::from_code(19), Some(Kind::Submitted));
    assert_eq!(Kind::Submitted.code(), 19);
    for (code, kind) in (20u64..).zip([
        Kind::ClusterRequest,
        Kind::ClusterOutcome,
        Kind::ClusterRefused,
    ]) {
        assert_eq!(kind.code(), code);
        assert_eq!(Kind::from_code(code), Some(kind));
    }
    assert_eq!(Kind::from_code(23), None);
}

/// karyos#985: each durable append seals the recording to its durable end,
/// across a restart, and the sealed bytes verify against their seals.
#[test]
fn durable_appends_are_sealed_and_verify() {
    use karyos_archive::integrity::journal::read_records;
    use karyos_archive::integrity::{SealKind, verify_chain, verify_range};
    use karyos_archive::segment::{SegmentStore, SyncPolicy};

    let dir = dir("sealed");
    let mut journal = Journal::open(&dir, 10).unwrap();
    let recording = journal.recording();
    let _ = journal
        .append_durable(&request(Kind::CloseRequest, 11, 3), 11)
        .unwrap();
    journal.stop(12).unwrap();
    assert_eq!(journal.failed_seals(), 0);
    drop(journal);
    let mut journal = Journal::open(&dir, 20).unwrap();
    let _ = journal
        .append_durable(&request(Kind::ReopenRequest, 21, 3), 21)
        .unwrap();
    assert_eq!(journal.failed_seals(), 0);
    drop(journal);

    let (records, fault) = read_records(&mut StdDisk, &dir).unwrap();
    assert_eq!(fault, None);
    verify_chain(&records).unwrap();
    let ranges: Vec<_> = records
        .iter()
        .filter(|record| record.kind == SealKind::OpenSegment && record.subject == recording)
        .collect();
    assert!(ranges.len() >= 4, "{ranges:?}");
    assert_eq!(ranges[0].start, 0);
    let mut store = SegmentStore::recover(
        StdDisk,
        &dir,
        recording,
        karyos_archive::segment::Geometry::with_default_length(TERM_LENGTH).unwrap(),
        SyncPolicy::PerSegment,
    )
    .unwrap()
    .store;
    assert_eq!(ranges.last().unwrap().end, store.written());
    for range in ranges {
        let mut bytes = vec![0u8; usize::try_from(range.end - range.start).unwrap()];
        store.read(range.start, &mut bytes).unwrap();
        verify_range(range, &bytes).unwrap();
    }
}

/// R-CORE-21 (karyos#740): a rate change's records, kinds 17 and 18, read
/// back with the stream word, the version replaced and the version after;
/// the request is one an outcome must answer.
#[test]
fn rate_change_records_round_trip() {
    let mut record = request(Kind::RateRequest, 7, 3);
    record.guard = (1_u64 << 32) | 2;
    record.expected = 4;
    assert_eq!(
        JournalRecord::decode(&record.encode()),
        Some(record.clone())
    );
    assert_eq!(record.encode()[8], 17);
    assert!(Kind::RateRequest.is_request());
    let mut outcome = request(Kind::RateOutcome, 8, 3);
    outcome.expected = 4;
    outcome.word = 5;
    assert_eq!(outcome.encode()[8], 18);
    assert!(!Kind::RateOutcome.is_request());
    assert_eq!(JournalRecord::decode(&outcome.encode()), Some(outcome));
}

/// karyos#1071: an unsealed journal larger than one chunk is sealed in
/// chunks, each read on its own, and the chunks verify.
#[test]
fn a_large_unsealed_journal_is_sealed_in_bounded_chunks() {
    use karyos_archive::integrity::journal::{IntegrityJournal, read_records};
    use karyos_archive::integrity::{SealKind, verify_chain};

    let dir = dir("chunked");
    let mut journal = Journal::open(&dir, 10).unwrap();
    // Appends that are not durable leave the journal unsealed past its
    // first records.
    for time in 11..200 {
        let _ = journal
            .append(&request(Kind::CloseRequest, time, 3), time)
            .unwrap();
    }
    drop(journal);
    // A journal from before sealing: its integrity journal is gone.
    std::fs::remove_file(IntegrityJournal::<StdDisk>::path(&dir)).unwrap();
    let chunk = 512;
    let mut journal = Journal::open_chunked(&dir, 300, chunk).unwrap();
    let _ = journal
        .append_durable(&request(Kind::CloseOutcome, 301, 3), 301)
        .unwrap();
    assert_eq!(journal.failed_seals(), 0);
    // The buffer never held more than a chunk.
    assert!(
        journal.seal_capacity() <= 512 * 2,
        "{}",
        journal.seal_capacity()
    );
    drop(journal);
    let (records, fault) = read_records(&mut StdDisk, &dir).unwrap();
    assert_eq!(fault, None);
    verify_chain(&records).unwrap();
    let ranges: Vec<_> = records
        .iter()
        .filter(|record| record.kind == SealKind::OpenSegment)
        .collect();
    assert!(ranges.len() > 4, "{}", ranges.len());
    assert!(ranges.iter().all(|range| range.end - range.start <= chunk));
}
