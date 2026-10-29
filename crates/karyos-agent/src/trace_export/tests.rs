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
use crate::api::LossReason;

/// [`export`] with no byte bound.
fn read_page(
    mirror: &karyos_sys::trace_mirror::TraceMirrorReader,
    epoch: u128,
    from: u64,
    count: usize,
    asked: Option<u128>,
) -> Result<ExportPage, ExportRefusal> {
    export(mirror, None, epoch, from, count, asked, usize::MAX)
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
    assert_eq!(
        page.lost,
        vec![ExportLoss {
            first: 1,
            last: 5,
            reason: LossReason::Overwritten
        }]
    );
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
    // Journal 12 is gone for good (every entry read): its record is
    // delivered, counted as one without calibration.
    assert_eq!(page.unknown_records, 1);
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
        Err(ExportRefusal::Ahead { next: 10 })
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

/// Review B4 of #826 (QS-COORDINATOR, ACS 33476): a record whose length
/// word passes the payload bound is malformed. It is never delivered, cut
/// or whole: it is lost, with its exact sequence and reason `malformed`,
/// and the page goes on past it.
#[test]
fn a_malformed_record_is_lost_and_the_page_goes_on() {
    use karyos_sys::trace_mirror::MAX_MIRROR_PAYLOAD;

    let mut mirror = mirror(16);
    let long = u64::try_from(MAX_MIRROR_PAYLOAD).unwrap() + 1;
    let _ = mirror.append_with_length(10, 0, &[0, 0], long).unwrap();
    append(&mut mirror, 1..3);
    let _ = mirror.append_with_length(10, 3, &[3, 3], long).unwrap();
    append(&mut mirror, 4..5);
    let page = read_page(&mirror.reader(), EPOCH, 0, 16, None).unwrap();
    let malformed = |seq| ExportLoss {
        first: seq,
        last: seq,
        reason: LossReason::Malformed,
    };
    assert_eq!(page.lost, vec![malformed(0), malformed(3)]);
    assert_eq!(seqs(&page), [1, 2, 4]);
    assert_eq!(page.next, 5);
}

/// Review of #826: the read is bounded by bytes, so a page of a small
/// bound holds few records, `next` naming the first left out, and the
/// count is clamped to `EXPORT_MAX` whatever the caller asks.
#[test]
fn the_read_is_bounded_by_bytes_and_count() {
    let mut mirror = mirror(64);
    append(&mut mirror, 0..40);
    let reader = mirror.reader();
    let page = export(&reader, None, EPOCH, 0, usize::MAX, None, 1).unwrap();
    assert_eq!(seqs(&page), [0]);
    assert_eq!(page.next, 1);
    let bound = crate::json::EXPORT_REPLY_OVERHEAD
        + crate::api::MAX_JOURNAL_REPLY
        + 5 * crate::json::export_record_len(&page.records[0]);
    let page = export(&reader, None, EPOCH, 0, usize::MAX, None, bound).unwrap();
    assert_eq!(page.records.len(), 5);
    assert_eq!(page.next, 5);
    let page = export(&reader, None, EPOCH, 0, usize::MAX, None, usize::MAX).unwrap();
    assert_eq!(page.records.len(), 40);
}

/// Re-review F1 of #826: a page that ends before a busy journal's record
/// states nothing past its end: a malformed record after the cut is lost
/// on the next page, not on this one.
#[test]
fn nothing_is_lost_past_where_the_page_ends() {
    use karyos_sys::trace_mirror::MAX_MIRROR_PAYLOAD;

    let mut mirror = mirror(16);
    let other = JournalEntry::open(11, 1, JournalKind::Publisher, 2, 16);
    assert!(mirror.write_entry(1, Some(&other)));
    let long = u64::try_from(MAX_MIRROR_PAYLOAD).unwrap() + 1;
    let _ = mirror.append(10, 0, &[0, !0]).unwrap();
    let _ = mirror.append(11, 1, &[1, !1]).unwrap();
    let _ = mirror.append_with_length(10, 2, &[2, 2], long).unwrap();
    let _ = mirror.append(10, 3, &[3, !3]).unwrap();
    assert!(mirror.hold_entry(1, true));
    let page = read_page(&mirror.reader(), EPOCH, 0, 16, None).unwrap();
    assert_eq!((seqs(&page), page.next), (vec![0], 1));
    assert!(page.lost.is_empty(), "{:?}", page.lost);
    assert!(mirror.hold_entry(1, false));
    let page = read_page(&mirror.reader(), EPOCH, 1, 16, None).unwrap();
    assert_eq!(seqs(&page), [1, 3]);
    assert_eq!(
        page.lost,
        vec![ExportLoss {
            first: 2,
            last: 2,
            reason: LossReason::Malformed
        }]
    );
}

/// Re-review of #826 (QS-REVIEWER's design point, ACS 33673): an entry
/// busy on every attempt while the page's first record is its journal's
/// never stalls the cursor and loses nothing: its records go out without
/// calibration, the journal `unreadable`, counted in `unreadable_records`.
#[test]
fn a_stuck_entry_is_delivered_uncalibrated_not_lost() {
    let mut mirror = mirror(16);
    let other = JournalEntry::open(11, 1, JournalKind::Publisher, 2, 16);
    assert!(mirror.write_entry(1, Some(&other)));
    let _ = mirror.append(11, 0, &[0, !0]).unwrap();
    let _ = mirror.append(10, 1, &[1, !1]).unwrap();
    let _ = mirror.append(11, 2, &[2, !2]).unwrap();
    assert!(mirror.hold_entry(1, true));
    let page = read_page(&mirror.reader(), EPOCH, 0, 16, None).unwrap();
    // Journal 11's records (0 and 2) go out uncalibrated, in one page.
    assert_eq!(seqs(&page), [0, 1, 2]);
    assert_eq!(page.next, 3);
    assert!(page.lost.is_empty());
    assert!(
        page.journals
            .contains(&ExportJournal::Unreadable { journal: 11 })
    );
    assert_eq!(page.unreadable_records, 2);
}

/// QS-COORDINATOR, ACS 33663 (F1): across pages cut by bytes and by a busy
/// journal, every sequence the ring held is delivered or lost exactly
/// once, and every lost range of a page is below its `next`.
#[test]
fn every_sequence_is_delivered_or_lost_exactly_once() {
    use karyos_sys::trace_mirror::MAX_MIRROR_PAYLOAD;

    let mut mirror = mirror(64);
    let other = JournalEntry::open(11, 1, JournalKind::Publisher, 2, 16);
    assert!(mirror.write_entry(1, Some(&other)));
    let long = u64::try_from(MAX_MIRROR_PAYLOAD).unwrap() + 1;
    for seq in 0..40u64 {
        let journal = if seq % 7 == 3 { 11 } else { 10 };
        let _ = if seq % 5 == 2 {
            mirror.append_with_length(journal, seq, &[seq, seq], long)
        } else {
            mirror.append(journal, seq, &[seq, !seq])
        }
        .unwrap();
    }
    let reader = mirror.reader();
    let bound = crate::json::EXPORT_REPLY_OVERHEAD + crate::api::MAX_JOURNAL_REPLY + 300;
    let mut seen = vec![0u32; 40];
    let mut cursor = 0;
    let mut pages = 0;
    while cursor < 40 {
        // The busy entry holds for the first pages only.
        assert!(mirror_hold(&mut mirror, pages < 3));
        let page = export(&reader, None, EPOCH, cursor, usize::MAX, None, bound).unwrap();
        for loss in &page.lost {
            assert!(loss.last < page.next, "{loss:?} past {}", page.next);
            for seq in loss.first..=loss.last {
                seen[usize::try_from(seq).unwrap()] += 1;
            }
        }
        for record in &page.records {
            assert!(record.seq < page.next);
            seen[usize::try_from(record.seq).unwrap()] += 1;
        }
        assert!(page.next > cursor || page.records.is_empty() && page.lost.is_empty());
        cursor = page.next;
        pages += 1;
        assert!(pages < 200, "no progress at {cursor}");
    }
    assert!(seen.iter().all(|count| *count == 1), "{seen:?}");
}

/// Holds or releases table entry 1 of `mirror`.
fn mirror_hold(mirror: &mut TraceMirror, held: bool) -> bool {
    mirror.hold_entry(1, held)
}

/// Re-review U2 of #826: against a writer that keeps appending to a small
/// ring, pages of the most records a request may ask for (several batches
/// each, which the writer may lap mid-page; that a mid-page lap ends the
/// page is `a_page_lapped_after_its_first_records_ends_there`'s, made
/// deterministic there) deliver or lose every sequence
/// exactly once, every loss below its page's `next`, and every record
/// whole.
#[test]
fn full_count_pages_against_a_writer_cover_every_sequence_once() {
    const WRITTEN: u64 = 300_000;
    // Written past the ring's capacity before the first read, so the
    // first page has a loss to state whatever the threads' timing.
    const AHEAD: u64 = 1_000;
    let mut mirror = mirror(64);
    append(&mut mirror, 0..AHEAD);
    let reader = mirror.reader();
    let writer = std::thread::spawn(move || append(&mut mirror, AHEAD..WRITTEN));
    let mut seen = vec![0u8; usize::try_from(WRITTEN).unwrap()];
    let mut lost = 0u64;
    let mut cursor = 0;
    while cursor < WRITTEN {
        let page = export(
            &reader,
            None,
            EPOCH,
            cursor,
            crate::api::EXPORT_MAX,
            Some(EPOCH),
            usize::MAX,
        )
        .unwrap();
        for loss in &page.lost {
            assert!(loss.last < page.next, "{loss:?} past {}", page.next);
            lost += loss.last - loss.first + 1;
            for seq in loss.first..=loss.last {
                seen[usize::try_from(seq).unwrap()] += 1;
            }
        }
        for record in &page.records {
            assert!(record.seq < page.next);
            assert_eq!(record.payload, [record.sequence, !record.sequence]);
            seen[usize::try_from(record.seq).unwrap()] += 1;
        }
        cursor = page.next;
    }
    writer.join().unwrap();
    assert!(seen.iter().all(|count| *count == 1));
    // The records written ahead of the reader were lost, stated so.
    assert!(lost >= AHEAD - 64);
}

/// Re-review U2 of #826: a full page, the most records of the largest
/// payload, encodes within `MAX_EXPORT_REPLY` plus one record and one
/// journal, and leaves the rest for the next page.
#[test]
fn a_full_page_stays_within_the_reply_bound() {
    use crate::api::{EXPORT_MAX, MAX_EXPORT_REPLY, MAX_JOURNAL_REPLY, MAX_RECORD_REPLY};
    use karyos_sys::trace_mirror::MAX_MIRROR_PAYLOAD;

    let mut mirror = mirror(EXPORT_MAX);
    for seq in 0..u64::try_from(EXPORT_MAX).unwrap() {
        let _ = mirror
            .append(10, u64::MAX - seq, &[u64::MAX; MAX_MIRROR_PAYLOAD])
            .unwrap();
    }
    let page = export(
        &mirror.reader(),
        None,
        EPOCH,
        0,
        EXPORT_MAX,
        None,
        MAX_EXPORT_REPLY,
    )
    .unwrap();
    let reply = crate::json::trace_export(&page);
    assert!(
        reply.len() <= MAX_EXPORT_REPLY + MAX_RECORD_REPLY + MAX_JOURNAL_REPLY,
        "{}",
        reply.len()
    );
    assert!(page.records.len() > 1);
    assert_eq!(page.next, u64::try_from(page.records.len()).unwrap());
    assert!(page.next < u64::try_from(EXPORT_MAX).unwrap());
}

/// QS-COORDINATOR, ACS 33839 (U1): an entry busy for less than the wait
/// budget is waited out, and its journal's records come out calibrated,
/// never unreadable.
#[test]
fn a_transient_busy_entry_is_waited_for() {
    let mut mirror = mirror(16);
    let other = JournalEntry::open(11, 1, JournalKind::Publisher, 2, 16);
    assert!(mirror.write_entry(1, Some(&other)));
    let _ = mirror.append(11, 0, &[0, !0]).unwrap();
    assert!(mirror.hold_entry(1, true));
    let reader = mirror.reader();
    // Released well within the budget the read waits.
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(mirror.hold_entry(1, false));
        mirror
    });
    let page = export_within(
        &reader,
        None,
        (EPOCH, None),
        0,
        16,
        usize::MAX,
        Waits {
            busy_budget: std::time::Duration::from_secs(5),
            max_lost_ranges: MAX_LOST_RANGES,
        },
    )
    .unwrap();
    let _mirror = writer.join().unwrap();
    assert_eq!(seqs(&page), [0]);
    assert!(matches!(&page.journals[..], [ExportJournal::Live(entry)] if entry.journal == 11));
    assert_eq!(page.unreadable_records, 0);
}

/// ACS 33839 (U2): one page of more records than one batch reads them all,
/// in order, across its batches.
#[test]
fn a_page_spans_several_batches() {
    let mut mirror = mirror(256);
    append(&mut mirror, 0..200);
    let page = read_page(&mirror.reader(), EPOCH, 0, 200, None).unwrap();
    assert_eq!(seqs(&page), (0..200).collect::<Vec<_>>());
    assert_eq!(page.next, 200);
}

/// ACS 33839 (U2): a page fills up exactly at its byte bound: the records
/// that fit are in it, and one byte less leaves the last of them out.
#[test]
fn a_page_fills_exactly_at_its_bound() {
    let mut mirror = mirror(16);
    append(&mut mirror, 0..10);
    let reader = mirror.reader();
    // The records all encode alike but for their sequence digits.
    let lens: Vec<usize> = (0..5u64)
        .map(|seq| crate::json::export_record_len_of(seq, 10, seq, &[seq, !seq]))
        .collect();
    let bound = crate::json::EXPORT_REPLY_OVERHEAD
        + crate::api::MAX_JOURNAL_REPLY
        + lens.iter().sum::<usize>();
    let page = export(&reader, None, EPOCH, 0, 16, None, bound).unwrap();
    assert_eq!(seqs(&page), [0, 1, 2, 3, 4]);
    assert_eq!(page.next, 5);
    let page = export(&reader, None, EPOCH, 0, 16, None, bound - 1).unwrap();
    assert_eq!(seqs(&page), [0, 1, 2, 3]);
    assert_eq!(page.next, 4);
}

/// ACS 33839 (U2): a page lapped by the ring after its first records (here
/// between its first and second batches) ends where it was, stating no
/// loss after its records; the next page states the lost range first.
#[test]
fn a_page_lapped_after_its_first_records_ends_there() {
    let mirror = std::rc::Rc::new(std::cell::RefCell::new(mirror(64)));
    append(&mut mirror.borrow_mut(), 0..64);
    let reader = mirror.borrow().reader();
    let writer = std::rc::Rc::clone(&mirror);
    BETWEEN_BATCHES.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || append(&mut writer.borrow_mut(), 64..164)));
    });
    let page = read_page(&reader, EPOCH, 0, 200, None);
    BETWEEN_BATCHES.with(|hook| *hook.borrow_mut() = None);
    let page = page.unwrap();
    assert_eq!(seqs(&page), (0..64).collect::<Vec<_>>());
    assert!(page.lost.is_empty(), "{:?}", page.lost);
    assert_eq!(page.next, 64);
    let page = read_page(&reader, EPOCH, 64, 200, None).unwrap();
    assert_eq!(
        page.lost,
        vec![ExportLoss {
            first: 64,
            last: 99,
            reason: LossReason::Overwritten
        }]
    );
    assert_eq!(seqs(&page), (100..164).collect::<Vec<_>>());
}

/// Re-review W1 of #826: a journal recycled while its busy table entry is
/// waited for is found in the recycle log, read after the table, never
/// left unknown: the driver writes the log entry before it reuses the
/// table's.
#[test]
fn a_journal_recycled_during_the_wait_is_found_in_the_log() {
    let mirror = std::rc::Rc::new(std::cell::RefCell::new(mirror(16)));
    {
        let mut mirror = mirror.borrow_mut();
        let other = JournalEntry::open(11, 1, JournalKind::Subscriber, 2, 16);
        assert!(mirror.write_entry(1, Some(&other)));
        let _ = mirror.append(11, 0, &[0, !0]).unwrap();
        // A record of the journal that takes the entry over.
        let _ = mirror.append(12, 1, &[1, !1]).unwrap();
        assert!(mirror.hold_entry(1, true));
    }
    let reader = mirror.borrow().reader();
    let recycler = std::rc::Rc::clone(&mirror);
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
    DURING_TABLE_WAIT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let mut mirror = recycler.borrow_mut();
            // The driver's order: the log entry first, then the table
            // entry reused for another journal.
            assert!(mirror.write_log(0, Some(&recycled)));
            let next = JournalEntry::open(12, 1, JournalKind::Publisher, 2, 16);
            assert!(mirror.write_entry(1, Some(&next)));
        }));
    });
    let page = export_within(
        &reader,
        None,
        (EPOCH, None),
        0,
        16,
        usize::MAX,
        Waits {
            busy_budget: std::time::Duration::from_secs(5),
            max_lost_ranges: MAX_LOST_RANGES,
        },
    );
    DURING_TABLE_WAIT.with(|hook| *hook.borrow_mut() = None);
    let page = page.unwrap();
    assert_eq!(seqs(&page), [0, 1]);
    // The recycled journal from the log, the new one calibrated against
    // its table entry.
    assert!(
        matches!(
            &page.journals[..],
            [ExportJournal::Recycled(old), ExportJournal::Live(new)]
                if old.journal == 11 && new.journal == 12
        ),
        "{:?}",
        page.journals
    );
    assert_eq!((page.unknown_records, page.unreadable_records), (0, 0));
}

/// Re-review of #826: a page states at most `max_lost_ranges` overwritten
/// ranges, its reply's overhead; it ends at the last it can state.
#[test]
fn a_page_ends_at_the_overwritten_ranges_it_can_state() {
    let mut mirror = mirror(128);
    append(&mut mirror, 0..300);
    let reader = mirror.reader();
    let waits = |max_lost_ranges| Waits {
        busy_budget: BUSY_BUDGET,
        max_lost_ranges,
    };
    // One range allowed: the page ends after the batch that stated it.
    let page = export_within(&reader, None, (EPOCH, None), 0, 200, usize::MAX, waits(1)).unwrap();
    assert_eq!(page.lost.len(), 1);
    assert_eq!(page.next, 172 + 64);
    // The default allows it to go on to its count.
    let page = export_within(
        &reader,
        None,
        (EPOCH, None),
        0,
        200,
        usize::MAX,
        waits(MAX_LOST_RANGES),
    )
    .unwrap();
    assert_eq!(page.next, 300);
}

/// QS-COORDINATOR, ACS 33989 (W2), and point 1 of the #826 review: with
/// journal A busy past the wait and first in the page, and journal B
/// readable, A's records go out unreadable, all of them in the page, so a
/// stuck entry never splits pages into runs; B's records are calibrated.
#[test]
fn only_the_busy_first_journals_records_are_unreadable() {
    let mut mirror = mirror(16);
    let a = JournalEntry::open(11, 1, JournalKind::Publisher, 2, 16);
    assert!(mirror.write_entry(1, Some(&a)));
    // Journal 10 (B) is entry 0, readable.
    for (seq, journal) in [(0, 11), (1, 11), (2, 10), (3, 10), (4, 11), (5, 10)] {
        let _ = mirror.append(journal, seq, &[seq, !seq]).unwrap();
    }
    assert!(mirror.hold_entry(1, true));
    let page = read_page(&mirror.reader(), EPOCH, 0, 16, None).unwrap();
    assert_eq!(seqs(&page), [0, 1, 2, 3, 4, 5]);
    assert_eq!(page.next, 6);
    assert_eq!(page.unreadable_records, 3);
    assert!(matches!(
        &page.journals[..],
        [ExportJournal::Live(b), ExportJournal::Unreadable { journal: 11 }] if b.journal == 10
    ));
}

/// Point 7 of the #826 review: lapped again between batches while the page
/// has no record yet (every record malformed), a page states one
/// overwritten range per lap up to its cap, and ends at the last.
#[test]
fn a_page_stops_at_its_cap_across_several_laps() {
    use karyos_sys::trace_mirror::MAX_MIRROR_PAYLOAD;

    fn malformed(mirror: &mut TraceMirror, range: std::ops::Range<u64>) {
        let long = u64::try_from(MAX_MIRROR_PAYLOAD).unwrap() + 1;
        for seq in range {
            let _ = mirror.append_with_length(10, seq, &[seq], long).unwrap();
        }
    }
    for cap in [2usize, 3] {
        let mirror = std::rc::Rc::new(std::cell::RefCell::new(mirror(64)));
        malformed(&mut mirror.borrow_mut(), 0..100);
        let reader = mirror.borrow().reader();
        let writer = std::rc::Rc::clone(&mirror);
        let mut written = 100;
        BETWEEN_BATCHES.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                malformed(&mut writer.borrow_mut(), written..written + 100);
                written += 100;
            }));
        });
        let page = export_within(
            &reader,
            None,
            (EPOCH, None),
            0,
            1_000,
            usize::MAX,
            Waits {
                busy_budget: BUSY_BUDGET,
                max_lost_ranges: cap,
            },
        );
        BETWEEN_BATCHES.with(|hook| *hook.borrow_mut() = None);
        let page = page.unwrap();
        let overwritten = page
            .lost
            .iter()
            .filter(|loss| loss.reason == LossReason::Overwritten)
            .count();
        assert_eq!(overwritten, cap, "{:?}", page.lost);
        assert!(page.records.is_empty());
        assert!(page.lost.iter().all(|loss| loss.last < page.next));
    }
}

/// Points 2 and 4 of the #826 review: with a table entry stuck for the
/// whole of the table's wait, a recycle log entry busy for less than the
/// log's own wait is still waited out, and the journal it holds is found
/// there, calibrated. The log entry is released from inside the log's wait
/// (a hook), so the test needs no sleep: under one budget shared with the
/// table, that wait would never run. Each part retries its busy entries
/// at least once, so the hook runs whatever the clock says.
#[test]
fn the_log_waits_with_its_own_budget_after_a_stuck_table() {
    let mirror = std::rc::Rc::new(std::cell::RefCell::new(mirror(16)));
    let stuck = JournalEntry::open(12, 1, JournalKind::Publisher, 2, 16);
    assert!(mirror.borrow_mut().write_entry(1, Some(&stuck)));
    let gone = RecycledJournal {
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
    assert!(mirror.borrow_mut().write_log(0, Some(&gone)));
    let _ = mirror.borrow_mut().append(11, 0, &[0, !0]).unwrap();
    assert!(mirror.borrow_mut().hold_entry(1, true));
    assert!(mirror.borrow_mut().hold_log(0, true));
    let reader = mirror.borrow().reader();
    let writer = std::rc::Rc::clone(&mirror);
    DURING_LOG_WAIT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            assert!(writer.borrow_mut().hold_log(0, false));
        }));
    });
    let page = export_within(
        &reader,
        None,
        (EPOCH, None),
        0,
        16,
        usize::MAX,
        Waits {
            busy_budget: std::time::Duration::ZERO,
            max_lost_ranges: MAX_LOST_RANGES,
        },
    );
    DURING_LOG_WAIT.with(|hook| *hook.borrow_mut() = None);
    let page = page.unwrap();
    assert_eq!(seqs(&page), [0]);
    assert_eq!(page.journals, [ExportJournal::Recycled(Box::new(gone))]);
    assert_eq!(page.unreadable_records, 0);
}

/// The #845 review: the log's wait has a budget of its own, not only the
/// one retry every part gets. With the table's entry stuck for the whole of
/// its 200 ms, a log entry released at the log's second retry is still
/// found; under one budget shared with the table, the log would get its one
/// retry and no second.
#[test]
fn the_log_has_a_budget_of_its_own_past_the_first_retry() {
    let mirror = std::rc::Rc::new(std::cell::RefCell::new(mirror(16)));
    let stuck = JournalEntry::open(12, 1, JournalKind::Publisher, 2, 16);
    assert!(mirror.borrow_mut().write_entry(1, Some(&stuck)));
    let gone = RecycledJournal {
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
    assert!(mirror.borrow_mut().write_log(0, Some(&gone)));
    let _ = mirror.borrow_mut().append(11, 0, &[0, !0]).unwrap();
    assert!(mirror.borrow_mut().hold_entry(1, true));
    assert!(mirror.borrow_mut().hold_log(0, true));
    let reader = mirror.borrow().reader();
    let writer = std::rc::Rc::clone(&mirror);
    let mut retries = 0;
    DURING_LOG_WAIT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            // Released at the log's second retry: past the one every part
            // gets, so only a budget of the log's own reaches it.
            retries += 1;
            if retries == 2 {
                assert!(writer.borrow_mut().hold_log(0, false));
            }
        }));
    });
    let page = export_within(
        &reader,
        None,
        (EPOCH, None),
        0,
        16,
        usize::MAX,
        Waits {
            busy_budget: std::time::Duration::from_millis(200),
            max_lost_ranges: MAX_LOST_RANGES,
        },
    );
    DURING_LOG_WAIT.with(|hook| *hook.borrow_mut() = None);
    let page = page.unwrap();
    assert_eq!(seqs(&page), [0]);
    assert_eq!(page.journals, [ExportJournal::Recycled(Box::new(gone))]);
    assert_eq!(page.unreadable_records, 0);
}

/// An application point's payload (layout version 4, code 9): word 0 and
/// word 16 as the karyos-trace encoder writes them, the rest zero.
fn application_payload(id: u16) -> [u64; 25] {
    let mut payload = [0u64; 25];
    payload[0] = 4 | (9 << 8);
    payload[16] = u64::from(id);
    payload
}

/// A client counters region holding trace point cells: label, client, id.
fn point_cells(
    cells: &[(&str, u64, u16)],
) -> (karyos_sys::counters::CountersManager, CountersReader) {
    let (mut manager, reader, _) = karyos_sys::counters::client_counters(8).unwrap();
    for (label, client, id) in cells {
        let keys = karyos_sys::counters::CounterKeys {
            stream: 0,
            lane: 0,
            kind: karyos_sys::counters::KIND_CLIENT,
            participant: *client,
        };
        // The capability is dropped at once; its cell stays allocated,
        // pending release, as a reader sees it.
        let counter = manager
            .allocate_valued_where(TYPE_TRACE_POINT, label, keys, u64::from(*id), |_| true)
            .unwrap();
        std::mem::forget(counter);
    }
    (manager, reader)
}

/// R-CORE-1: a page names the application points its records reference,
/// once each, from the single cell of the records' client holding the id;
/// a released or unknown id, an id claimed by two cells, and a cell of
/// another client stay unnamed, never misattributed. Driver records name
/// no point.
#[test]
fn a_page_names_the_application_points_its_records_reference() {
    let mut mirror = mirror(16);
    // Journal 10 is client 1's.
    for (sequence, id) in [(0, 1u16), (1, 1), (2, 2), (3, 3), (4, 4)] {
        let _ = mirror
            .append(10, sequence, &application_payload(id))
            .unwrap();
    }
    let _ = mirror.append(10, 5, &[5, !5]).unwrap();
    let (_manager, cells) = point_cells(&[
        ("order \"received\" \\ é", 1, 1),
        // Id 2 claimed twice.
        ("first", 1, 2),
        ("second", 1, 2),
        // Id 3 is another client's.
        ("theirs", 7, 3),
    ]);
    let page = export(
        &mirror.reader(),
        Some(&cells),
        EPOCH,
        0,
        16,
        None,
        usize::MAX,
    )
    .unwrap();
    assert_eq!(page.records.len(), 6);
    let named = |id: u16, label: Option<&str>, client: Option<u64>| ExportPoint {
        id,
        label: label.map(str::to_owned),
        client,
    };
    assert_eq!(
        page.points,
        vec![
            named(1, Some("order \"received\" \\ é"), Some(1)),
            named(2, None, None),
            named(3, None, None),
            // Id 4 has no cell: released, or never seen.
            named(4, None, None),
        ]
    );
    // The label is escaped in the reply.
    let reply = crate::json::trace_export(&page);
    assert!(
        reply.contains(r#""points":[{"id":1,"label":"order \"received\" \\ é","client":1},{"id":2,"label":null,"client":null}"#),
        "{reply}"
    );
    // Without the region, every point goes out unnamed.
    let page = export(&mirror.reader(), None, EPOCH, 0, 16, None, usize::MAX).unwrap();
    assert!(page.points.iter().all(|point| point.label.is_none()));
    // A page of driver records names none.
    let page = export(
        &mirror.reader(),
        Some(&cells),
        EPOCH,
        5,
        16,
        None,
        usize::MAX,
    )
    .unwrap();
    assert!(page.points.is_empty());
}

/// R-CORE-1: a point counts in the byte bound the first time a record
/// references it, at `MAX_POINT_REPLY`, so a reply stays within the bound
/// plus one record, one journal and one point.
#[test]
fn a_point_counts_once_in_the_byte_bound() {
    let mut mirror = mirror(16);
    for sequence in 0..4 {
        let id = u16::try_from(sequence + 1).unwrap();
        let _ = mirror
            .append(10, sequence, &application_payload(id))
            .unwrap();
    }
    let record = crate::json::export_record_len_of(0, 10, 0, &application_payload(1));
    // Room for the overhead, the journal, two records and one point.
    let bound = crate::json::EXPORT_REPLY_OVERHEAD
        + crate::api::MAX_JOURNAL_REPLY
        + 2 * record
        + crate::api::MAX_POINT_REPLY;
    let page = export(&mirror.reader(), None, EPOCH, 0, 16, None, bound).unwrap();
    // The second record brings a second point, which no longer fits.
    assert_eq!(seqs(&page), vec![0]);
    assert_eq!(page.next, 1);
    // A label of 64 bytes, each escaped to two, fits the point's share.
    let longest = "\"".repeat(64);
    let (_manager, cells) = point_cells(&[(longest.as_str(), 1, 1)]);
    let page = export(
        &mirror.reader(),
        Some(&cells),
        EPOCH,
        0,
        1,
        None,
        usize::MAX,
    )
    .unwrap();
    let reply = crate::json::trace_export(&page);
    let empty = crate::json::trace_export(&ExportPage {
        points: Vec::new(),
        ..page.clone()
    });
    assert!(
        reply.len() - empty.len() <= crate::api::MAX_POINT_REPLY,
        "{reply}"
    );
}
