// SPDX-License-Identifier: Apache-2.0

//! The etf drop ledger (ADR-0109 points 6 to 8).

use super::*;

/// A drop report drops every entry of its time, and coalesces: a second
/// report of the same time finds none and is late. A reliable lane's
/// ranges wait for their catch-up in position order, merged.
#[test]
fn a_report_drops_every_entry_of_its_time() {
    let mut ledger = EtfLedger::new(1, 8, true, 1_000);
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
            txtime: 100
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
    let mut ledger = EtfLedger::new(1, 8, true, 1_000);
    assert!(ledger.reserve(0, 100, (0, 64)));
    assert!(ledger.reserve(0, 300, (256, 320)));
    assert!(ledger.reserve(0, 200, (128, 192)));
    assert_eq!(ledger.drained(0, 300), 1);
    assert_eq!(ledger.drained(0, 100), 1);
    assert_eq!(ledger.drained(0, 200), 1);
    assert_eq!(ledger.next_catch_up(0), Some((0, 64)));
    ledger.caught_up_through(0, 32);
    assert_eq!(ledger.next_catch_up(0), Some((32, 64)));
    ledger.caught_up_through(0, 64);
    assert_eq!(ledger.next_catch_up(0), Some((128, 192)));
    ledger.caught_up_through(0, 192);
    assert_eq!(ledger.next_catch_up(0), Some((256, 320)));
    ledger.caught_up_through(0, 400);
    assert_eq!(ledger.next_catch_up(0), None);
}

/// An unreliable lane's drop is a gap, counted; nothing is caught up.
#[test]
fn an_unreliable_drop_is_a_counted_gap() {
    let mut ledger = EtfLedger::new(2, 4, false, 1_000);
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
    let mut ledger = EtfLedger::new(1, 2, true, 1_000);
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
    let mut ledger = EtfLedger::new(1, 4, true, advance);
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
    let mut ledger = EtfLedger::new(1, 4, true, 1_000);
    assert!(ledger.reserve(0, 100, (0, 64)));
    assert!(ledger.reserve(0, 200, (64, 128)));
    assert_eq!(ledger.drained(0, 100), 1);
    ledger.forget(0);
    assert_eq!((ledger.in_flight(0), ledger.next_catch_up(0)), (0, None));
}

/// Merging keeps ranges ordered and disjoint.
#[test]
fn ranges_merge_where_they_touch() {
    let mut ranges = VecDeque::new();
    for range in [(10, 20), (40, 50), (20, 30), (0, 5), (45, 60), (5, 10)] {
        insert_merged(&mut ranges, range);
    }
    assert_eq!(ranges, VecDeque::from([(0, 30), (40, 60)]));
}
