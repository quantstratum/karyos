// SPDX-License-Identifier: Apache-2.0

//! The etf drop ledger (ADR-0109 points 6 to 8).

use super::*;

/// A drop report drops every entry of its time, and coalesces: a second
/// report of the same time finds none and is late. A reliable lane's
/// ranges wait for their catch-up in position order, merged.
#[test]
fn a_report_drops_every_entry_of_its_time() {
    let mut ledger = EtfLedger::new(1, 8, (true, false), 1_000);
    assert!(ledger.reserve(0, 100, (0, 64)));
    assert!(ledger.reserve(0, 100, (64, 128)));
    assert!(ledger.reserve(0, 200, (128, 192)));
    assert_eq!(ledger.drained(0, 100), 2);
    assert_eq!(ledger.in_flight(0), 1);
    assert_eq!(ledger.next_catch_up(0), Some((0, 128)), "merged");
    assert_eq!(ledger.drained(0, 100), 0, "coalesced");
    assert_eq!(ledger.counts().late_drop_reports, 1);
    assert_eq!(
        ledger.peek_late(),
        Some(LateReport {
            lane: 0,
            txtime: 100,
            unrecorded: 0
        })
    );
    ledger.pop_late();
    assert_eq!(ledger.peek_late(), None, "posted once");
    assert_eq!(ledger.counts().dropped, 2);
    assert_eq!(ledger.counts().gaps, 0);
}

/// Catch-ups go in position order, whatever the order of the reports, and
/// a range shrinks as its catch-up covers it.
#[test]
fn catch_ups_go_in_position_order() {
    let mut ledger = EtfLedger::new(1, 8, (true, false), 1_000);
    assert!(ledger.reserve(0, 100, (0, 64)));
    assert!(ledger.reserve(0, 300, (256, 320)));
    assert!(ledger.reserve(0, 200, (128, 192)));
    assert_eq!(ledger.drained(0, 300), 1);
    assert_eq!(ledger.drained(0, 100), 1);
    assert_eq!(ledger.drained(0, 200), 1);
    assert_eq!(ledger.take_catch_up(0), Some((0, 64)));
    // A job that sent half gives the rest back, first again.
    ledger.give_back(0, (32, 64));
    assert_eq!(ledger.take_catch_up(0), Some((32, 64)));
    assert_eq!(ledger.take_catch_up(0), Some((128, 192)));
    assert_eq!(ledger.take_catch_up(0), Some((256, 320)));
    assert_eq!(ledger.take_catch_up(0), None);
}

/// An unreliable lane's drop is a gap, counted; nothing is caught up.
#[test]
fn an_unreliable_drop_is_a_counted_gap() {
    let mut ledger = EtfLedger::new(2, 4, (false, false), 1_000);
    assert!(ledger.reserve(1, 100, (0, 64)));
    assert_eq!(ledger.drained(1, 100), 1);
    assert_eq!(ledger.counts().gaps, 1);
    assert_eq!(ledger.next_catch_up(1), None);
    // A report on another lane's time is late there.
    assert_eq!(ledger.drained(0, 100), 0);
    assert_eq!(ledger.counts().late_drop_reports, 1);
}

/// A full list refuses the next entry, counted held; an entry leaving
/// makes room.
#[test]
fn a_full_list_holds_the_next_head() {
    let mut ledger = EtfLedger::new(1, 2, (true, false), 1_000);
    assert!(ledger.has_room(0));
    assert!(ledger.reserve(0, 100, (0, 64)));
    assert!(ledger.reserve(0, 200, (64, 128)));
    assert!(!ledger.has_room(0));
    assert!(!ledger.reserve(0, 300, (128, 192)));
    assert_eq!(ledger.counts().held_full, 2);
    assert_eq!(ledger.drained(0, 100), 1);
    assert!(ledger.has_room(0));
}

/// Expiry retires an entry as sent once `txtime + advance + margin` has
/// passed, not before; a report that arrives after is late and drops
/// nothing.
#[test]
fn expiry_retires_as_sent_and_a_later_report_is_late() {
    let advance = 1_000;
    let mut ledger = EtfLedger::new(1, 4, (true, false), advance);
    assert!(ledger.reserve(0, 100, (0, 64)));
    assert!(ledger.reserve(0, 500, (64, 128)));
    let edge = 100 + advance + EXPIRY_MARGIN;
    assert_eq!(ledger.expire(edge), 0, "at the edge it waits");
    assert_eq!(ledger.expire(edge + 1), 1);
    assert_eq!(ledger.counts().expired, 1);
    assert_eq!(ledger.drained(0, 100), 0);
    assert_eq!(ledger.counts().late_drop_reports, 1);
    assert_eq!(ledger.next_catch_up(0), None, "nothing resubmitted");
    assert_eq!(ledger.in_flight(0), 1);
}

/// A reset forgets a lane's entries and catch-ups.
#[test]
fn a_reset_forgets_the_lane() {
    let mut ledger = EtfLedger::new(1, 4, (true, false), 1_000);
    assert!(ledger.reserve(0, 100, (0, 64)));
    assert!(ledger.reserve(0, 200, (64, 128)));
    assert_eq!(ledger.drained(0, 100), 1);
    ledger.forget(0);
    assert_eq!((ledger.in_flight(0), ledger.next_catch_up(0)), (0, None));
}

/// Merging keeps ranges ordered and disjoint.
#[test]
fn ranges_merge_where_they_touch() {
    let mut ranges = VecDeque::with_capacity(8);
    for range in [(10, 20), (40, 50), (20, 30), (0, 5), (45, 60), (5, 10)] {
        insert_merged(&mut ranges, range);
    }
    assert_eq!(ranges, VecDeque::from([(0, 30), (40, 60)]));
}

/// Codex review of #1265 (P1): a drop below the range a catch-up is
/// working on waits on its own; the job's progress settles only its own
/// range, and what it did not send goes back in position order.
#[test]
fn an_earlier_drop_during_a_catch_up_stays_pending() {
    let mut ledger = EtfLedger::new(1, 8, (true, false), 1_000);
    assert!(ledger.reserve(0, 100, (0, 64)));
    assert!(ledger.reserve(0, 200, (128, 192)));
    assert_eq!(ledger.drained(0, 200), 1);
    assert_eq!(ledger.take_catch_up(0), Some((128, 192)));
    // While that job runs, the earlier datagram's report arrives.
    assert_eq!(ledger.drained(0, 100), 1);
    // The job sent all of its range: nothing goes back, and the earlier
    // range is still to send.
    ledger.give_back(0, (192, 192));
    assert_eq!(ledger.take_catch_up(0), Some((0, 64)));
    assert_eq!(ledger.take_catch_up(0), None);
}

/// Codex review of #1265 (P2): pending catch-ups never grow past their
/// allocation; a range that cannot get a slot of its own joins its
/// nearest neighbour, so nothing dropped is forgotten.
#[test]
fn pending_catch_ups_stay_within_their_allocation() {
    let mut ledger = EtfLedger::new(1, 2, (true, false), 1_000);
    let capacity = ledger.lanes[0].catch_ups.capacity();
    for index in 0..(capacity as u64 + 5) {
        ledger.give_back(0, (index * 100, index * 100 + 10));
    }
    let ranges = &ledger.lanes[0].catch_ups;
    assert!(ranges.len() <= capacity);
    assert_eq!(ranges.capacity(), capacity, "never reallocated");
    for index in 0..(capacity as u64 + 5) {
        let start = index * 100;
        assert!(
            ranges
                .iter()
                .any(|(from, to)| *from <= start && start + 10 <= *to),
            "{start} is covered: {ranges:?}"
        );
    }
    let ordered = ranges
        .iter()
        .zip(ranges.iter().skip(1))
        .all(|(a, b)| a.1 < b.0);
    assert!(ordered, "{ranges:?}");
}

/// Codex review of #1265 (P2): late reports past the waiting bound are
/// counted, and handed over as a count once the kept ones are posted, so
/// the publication's count misses none.
#[test]
fn late_reports_past_the_bound_are_still_counted() {
    let mut ledger = EtfLedger::new(1, 1, (true, false), 1_000);
    let total = DRAIN_BATCH as u64 + 6;
    for time in 0..total {
        assert_eq!(ledger.drained(0, time), 0);
    }
    assert_eq!(ledger.counts().late_drop_reports, total);
    let mut handed = 0u64;
    assert_eq!(ledger.take_unrecorded(), 0, "kept ones go first");
    while let Some(report) = ledger.peek_late() {
        handed += 1 + report.unrecorded;
        ledger.pop_late();
    }
    handed += ledger.take_unrecorded();
    assert_eq!(handed, total);
    // A refused count is put back.
    ledger.restore_unrecorded(3);
    assert_eq!(ledger.take_unrecorded(), 3);
}

/// Under cancel-on-deadline a drop aborts: no catch-up and no gap.
#[test]
fn a_drop_under_cancel_aborts() {
    for reliable in [true, false] {
        let mut ledger = EtfLedger::new(1, 4, (reliable, true), 1_000);
        assert!(ledger.reserve(0, 100, (0, 64)));
        assert_eq!(ledger.drained(0, 100), 1);
        let counts = ledger.counts();
        assert_eq!((counts.aborts, counts.caught_up, counts.gaps), (1, 0, 0));
        assert_eq!(ledger.next_catch_up(0), None);
    }
}
