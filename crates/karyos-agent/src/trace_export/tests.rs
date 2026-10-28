// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_sys::frame::Lane;
use karyos_sys::trace_mirror::{
    JournalEntry, JournalKind, JournalState, MAX_RECYCLE_PAIRS, NotedPublisher, RecycledJournal,
    TraceMirror, trace_mirror,
};

use super::*;

/// [`export`] with no byte bound.
fn read_page(
    mirror: &karyos_sys::trace_mirror::TraceMirrorReader,
    epoch: u128,
    from: u64,
    count: usize,
    asked: Option<u128>,
) -> Result<ExportPage, ExportRefusal> {
    export(mirror, epoch, from, count, asked, usize::MAX)
}

const EPOCH: u128 = 0x0123_4567_89ab_cdef_0011_2233_4455_6677;

/// A mirror of 4 table entries, 4 log entries and `capacity` records, with
/// journal 10 in the table.
fn mirror(capacity: usize) -> TraceMirror {
    let mut mirror = trace_mirror(4, 4, capacity).unwrap();
    let entry = JournalEntry::open(10, 1, JournalKind::Publisher, 2, 16);
    assert!(mirror.write_entry(0, Some(&entry)));
    mirror
}

/// Appends records `range` of journal 10, each payload its journal
/// sequence and that sequence's complement.
fn append(mirror: &mut TraceMirror, range: std::ops::Range<u64>) {
    for sequence in range {
        let _ = mirror.append(10, sequence, &[sequence, !sequence]).unwrap();
    }
}

fn seqs(page: &ExportPage) -> Vec<u64> {
    page.records.iter().map(|record| record.seq).collect()
}

/// Pages of three resume where the last ended: every record once, in
/// order, whatever reader (a restarted one included) holds the cursor.
#[test]
fn pages_resume_with_no_duplicate_and_no_gap() {
    let mut mirror = mirror(16);
    append(&mut mirror, 0..10);
    let reader = mirror.reader();
    let mut cursor = 0;
    let mut seen = Vec::new();
    loop {
        // A fresh reader each page: the agent keeps nothing per cursor.
        let page = read_page(&mirror.reader(), EPOCH, cursor, 3, Some(EPOCH)).unwrap();
        assert!(page.lost.is_empty(), "{:?}", page.lost);
        assert!(page.records.len() <= 3);
        seen.extend(seqs(&page));
        assert_eq!(page.head, 10);
        if page.next == cursor {
            break;
        }
        cursor = page.next;
    }
    assert_eq!(seen, (0..10).collect::<Vec<_>>());
    // The records are whole, with their journal sequence.
    let page = read_page(&reader, EPOCH, 4, 1, None).unwrap();
    let record = &page.records[0];
    assert_eq!(
        (record.journal, record.sequence, record.payload.as_slice()),
        (10, 4, &[4, !4][..])
    );
    assert_eq!(page.next, 5);
}

/// A cursor behind the ring's retention gets the oldest records, with the
/// lost range stated first.
#[test]
fn a_cursor_behind_retention_reports_the_lost_range() {
    let mut mirror = mirror(4);
    append(&mut mirror, 0..10);
    let page = read_page(&mirror.reader(), EPOCH, 1, 16, Some(EPOCH)).unwrap();
    assert_eq!(page.lost, vec![ExportLoss { first: 1, last: 5 }]);
    assert_eq!(seqs(&page), vec![6, 7, 8, 9]);
    assert_eq!((page.from, page.next, page.head), (1, 10, 10));
    // Up to date: nothing lost, nothing new.
    let page = read_page(&mirror.reader(), EPOCH, 10, 16, Some(EPOCH)).unwrap();
    assert!(page.lost.is_empty() && page.records.is_empty());
    assert_eq!(page.next, 10);
}

/// A cursor of another driver instance is refused, with this one; no
/// epoch (a first read) or this one is served.
#[test]
fn another_instance_is_refused_with_this_one() {
    let mut mirror = mirror(4);
    append(&mut mirror, 0..2);
    let reader = mirror.reader();
    assert_eq!(
        read_page(&reader, EPOCH, 1, 4, Some(EPOCH + 1)),
        Err(ExportRefusal::EpochChanged { epoch: EPOCH })
    );
    assert_eq!(read_page(&reader, EPOCH, 0, 4, None).unwrap().epoch, EPOCH);
    assert_eq!(
        read_page(&reader, EPOCH, 0, 4, Some(EPOCH))
            .unwrap()
            .records
            .len(),
        2
    );
}

/// Each journal a page names is there once: from the table, from the
/// recycle log, or unknown.
#[test]
fn a_page_names_its_journals() {
    let mut mirror = mirror(16);
    let recycled = RecycledJournal {
        journal: 11,
        stream: 3,
        lane: Lane::ZERO,
        incarnation: 1,
        state: JournalState::Closed,
        boundary: Some(64),
        pairs: [NotedPublisher {
            journal: 0,
            attempted: 0,
        }; MAX_RECYCLE_PAIRS],
        pair_count: 0,
        sequence: 2,
    };
    assert!(mirror.write_log(0, Some(&recycled)));
    for journal in [10, 11, 12, 10] {
        let _ = mirror.append(journal, 0, &[0, 0]).unwrap();
    }
    let page = read_page(&mirror.reader(), EPOCH, 0, 16, None).unwrap();
    assert_eq!(page.journals.len(), 3, "{:?}", page.journals);
    assert!(matches!(&page.journals[0], ExportJournal::Live(entry) if entry.journal == 10));
    assert_eq!(
        page.journals[1],
        ExportJournal::Recycled(Box::new(recycled))
    );
    assert_eq!(page.journals[2], ExportJournal::Unknown { journal: 12 });
}

/// Against a writer that keeps appending: every record delivered is
/// whole and in order, none twice, and what is not delivered is stated
/// lost, so the two add up to everything written.
#[test]
fn a_concurrent_writer_never_tears_a_record() {
    const WRITTEN: u64 = 200_000;
    let mut mirror = mirror(64);
    let reader = mirror.reader();
    let writer = std::thread::spawn(move || append(&mut mirror, 0..WRITTEN));
    let mut cursor = 0;
    let (mut delivered, mut lost) = (0u64, 0u64);
    loop {
        let page = read_page(&reader, EPOCH, cursor, 16, Some(EPOCH)).unwrap();
        let mut expect = cursor;
        for loss in &page.lost {
            assert!(loss.first >= expect && loss.last >= loss.first, "{loss:?}");
            lost += loss.last - loss.first + 1;
            expect = loss.last + 1;
        }
        for record in &page.records {
            assert!(record.seq >= expect, "{record:?} before {expect}");
            assert_eq!(record.seq, record.sequence, "{record:?}");
            assert_eq!(record.payload, [record.sequence, !record.sequence]);
            expect = record.seq + 1;
        }
        delivered += u64::try_from(page.records.len()).unwrap();
        cursor = page.next;
        if cursor == WRITTEN {
            break;
        }
    }
    writer.join().unwrap();
    assert_eq!(delivered + lost, WRITTEN);
    assert!(delivered > 0);
}

mod mirror {
    //! Against an embedded driver's trace mirror: records that decode with
    //! the journals' calibration, and a new instance.

    use karyos_driver::{DriverConfig, EmbeddedDriver};
    use karyos_trace::{ClockProvenance, RECORD_WORDS, decode_record};

    use super::*;
    use crate::trace_window::tests::mirror::{traced, write};

    fn epoch(driver: &EmbeddedDriver) -> u128 {
        let [high, low] = driver.driver_id();
        u128::from(high) << 64 | u128::from(low)
    }

    #[test]
    fn records_decode_with_their_journals_calibration() {
        let mut first = traced(DriverConfig::default());
        let publication = first.publication;
        for position in [0, 64] {
            write(
                &mut first.publisher,
                publication,
                karyos_trace::Point::Publish,
                position,
            );
        }
        for _ in 0..8 {
            let _ = first.driver.do_work().unwrap();
        }
        let instance = epoch(&first.driver);
        let page = read_page(&first.driver.trace_mirror(), instance, 0, 16, None).unwrap();
        assert_eq!(page.records.len(), 2, "{page:?}");
        for record in &page.records {
            let words = <&[u64; RECORD_WORDS]>::try_from(record.payload.as_slice()).unwrap();
            let (decoded, _) = decode_record(words).unwrap();
            assert_eq!(decoded.publication, publication);
            let journal = page
                .journals
                .iter()
                .find_map(|journal| match journal {
                    ExportJournal::Live(entry) if entry.journal == record.journal => Some(entry),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                ClockProvenance::from_word(journal.provenance),
                ClockProvenance::HostMonotonic
            );
        }
        // Another driver is another instance: the cursor is refused.
        let other = traced(DriverConfig::default());
        assert_eq!(
            read_page(
                &other.driver.trace_mirror(),
                epoch(&other.driver),
                page.next,
                16,
                Some(instance)
            ),
            Err(ExportRefusal::EpochChanged {
                epoch: epoch(&other.driver)
            })
        );
    }
}

/// Review B2 of #826: a cursor beyond the ring's next sequence is refused
/// with the ring's head, never served as caught up; the head is the
/// ring's, not the cursor.
#[test]
fn a_cursor_ahead_of_the_ring_is_refused() {
    let mut mirror = mirror(16);
    append(&mut mirror, 0..10);
    assert_eq!(
        read_page(&mirror.reader(), EPOCH, 5000, 16, None),
        Err(ExportRefusal::Ahead { head: 10 })
    );
    let page = read_page(&mirror.reader(), EPOCH, 10, 16, None).unwrap();
    assert_eq!((page.next, page.head), (10, 10));
}

/// Review B3 of #826: a journal whose table entry is busy on every attempt
/// cannot be named, so the page ends before its first record, which the
/// next read delivers once the entry reads.
#[test]
fn a_busy_journal_entry_ends_the_page_before_its_records() {
    let mut mirror = mirror(16);
    let other = JournalEntry::open(11, 1, JournalKind::Publisher, 2, 16);
    assert!(mirror.write_entry(1, Some(&other)));
    for (seq, journal) in [(0, 10), (1, 11), (2, 10)] {
        let _ = mirror.append(journal, seq, &[seq, !seq]).unwrap();
    }
    assert!(mirror.hold_entry(1, true));
    let page = read_page(&mirror.reader(), EPOCH, 0, 16, None).unwrap();
    assert_eq!(seqs(&page), [0]);
    assert_eq!(page.next, 1);
    assert!(
        page.journals
            .iter()
            .all(|journal| !matches!(journal, ExportJournal::Unknown { .. }))
    );
    assert!(mirror.hold_entry(1, false));
    let page = read_page(&mirror.reader(), EPOCH, 1, 16, None).unwrap();
    assert_eq!(seqs(&page), [1, 2]);
    assert_eq!(page.journals.len(), 2);
}

/// Review B4 of #826: a record whose length word passes the payload bound
/// is malformed: never delivered, stated as lost when it starts the page,
/// and ending the page before it otherwise.
#[test]
fn a_malformed_record_is_lost_not_delivered() {
    use karyos_sys::trace_mirror::MAX_MIRROR_PAYLOAD;

    let mut mirror = mirror(16);
    let long = u64::try_from(MAX_MIRROR_PAYLOAD).unwrap() + 1;
    let _ = mirror.append_with_length(10, 0, &[0, 0], long).unwrap();
    append(&mut mirror, 1..3);
    let _ = mirror.append_with_length(10, 3, &[3, 3], long).unwrap();
    append(&mut mirror, 4..5);
    let page = read_page(&mirror.reader(), EPOCH, 0, 16, None).unwrap();
    assert_eq!(page.lost, vec![ExportLoss { first: 0, last: 0 }]);
    assert_eq!(seqs(&page), [1, 2]);
    assert_eq!(page.next, 3);
    let page = read_page(&mirror.reader(), EPOCH, 3, 16, None).unwrap();
    assert_eq!(page.lost, vec![ExportLoss { first: 3, last: 3 }]);
    assert_eq!(seqs(&page), [4]);
}

/// Review of #826: the read is bounded by bytes, so a page of a small
/// bound holds few records, `next` naming the first left out, and the
/// count is clamped to `EXPORT_MAX` whatever the caller asks.
#[test]
fn the_read_is_bounded_by_bytes_and_count() {
    let mut mirror = mirror(64);
    append(&mut mirror, 0..40);
    let reader = mirror.reader();
    let page = export(&reader, EPOCH, 0, usize::MAX, None, 1).unwrap();
    assert_eq!(seqs(&page), [0]);
    assert_eq!(page.next, 1);
    let bound = crate::json::EXPORT_REPLY_OVERHEAD
        + crate::api::MAX_JOURNAL_REPLY
        + 5 * crate::json::export_record_len(&page.records[0]);
    let page = export(&reader, EPOCH, 0, usize::MAX, None, bound).unwrap();
    assert_eq!(page.records.len(), 5);
    assert_eq!(page.next, 5);
    let page = export(&reader, EPOCH, 0, usize::MAX, None, usize::MAX).unwrap();
    assert_eq!(page.records.len(), 40);
}
