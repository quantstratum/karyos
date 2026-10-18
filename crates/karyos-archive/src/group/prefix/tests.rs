// SPDX-License-Identifier: Apache-2.0

// The three prefixes: ADR-0024's validation cases (a journal durable while
// a payload is missing, and the reverse order; a flush failure), the stops
// at an incomplete event and at a gap, the bounded queue, and recovery.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use karyos_sys::frame::Lane;

use super::*;
use crate::fault::{FaultDisk, Survives};
use crate::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use crate::group::record::{
    Capture, Clock, EventEnd, GapMarker, GapReason, JournalHeader, MAX_RECORD, MessageEvent,
    TimerEvent,
};
use crate::segment::SyncPolicy;

/// Recordings' positions, set by the test.
#[derive(Default)]
struct Recordings(RefCell<BTreeMap<u64, (u64, u64)>>);

impl Recordings {
    fn set(&self, recording: u64, written: u64, durable: u64) {
        self.0.borrow_mut().insert(recording, (written, durable));
    }
}

impl Coverage for Recordings {
    fn positions(&self, recording_id: u64) -> Option<(u64, u64)> {
        self.0.borrow().get(&recording_id).copied()
    }
}

fn header(first: u64, capture: Capture) -> JournalHeader<'static> {
    JournalHeader {
        group_id: 1,
        first_group_seq: first,
        inline_threshold: 4096,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture,
        manifest: b"m",
    }
}

/// A message event naming `recording`'s frames `[0, 64)`, or inline.
fn message(seq: u64, recording: Option<u64>) -> GroupRecord<'static> {
    GroupRecord::Message(MessageEvent {
        group_seq: seq,
        logical_time: seq,
        incarnation: 1,
        position: 0,
        extent: 64,
        stream_id: 1,
        session_id: 1,
        lane: Lane::ZERO,
        reserved_value: 0,
        end_of_stream: false,
        extension: None,
        payload: match recording {
            Some(recording_id) => Payload::Reference {
                recording_id,
                length: 10,
            },
            None => Payload::Inline(b"x"),
        },
    })
}

fn end(seq: u64, outcome: EndOutcome) -> GroupRecord<'static> {
    GroupRecord::End(EventEnd {
        group_seq: seq,
        observations: 0,
        outcome,
    })
}

/// Feeds `records`, each ending 100 bytes after the previous one.
fn feed(tracker: &mut PrefixTracker, records: &[GroupRecord<'_>]) -> u64 {
    let mut at = 0;
    for record in records {
        at += 100;
        tracker.record(record, at).unwrap();
    }
    at
}

#[test]
fn inline_events_follow_the_journal_written_and_durable() {
    let none = Recordings::default();
    let mut tracker = PrefixTracker::new(8);
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(5, Capture::Strict)),
            message(5, None),
            end(5, EndOutcome::Complete),
            message(6, None),
            end(6, EndOutcome::Complete),
        ],
    );
    assert_eq!(tracker.advance(0, 0, &none), (4, 4), "nothing written");
    assert_eq!(tracker.advance(300, 0, &none), (5, 4), "event 5 written");
    assert_eq!(tracker.complete_end(), 300);
    assert_eq!(tracker.advance(500, 300, &none), (6, 5));
    assert_eq!(tracker.advance(500, 500, &none), (6, 6));
    assert_eq!(tracker.complete_end(), 500);
}

/// ADR-0024: the journal durable while a payload is missing, and the
/// reverse; neither prefix advances without every part.
#[test]
fn a_prefix_needs_the_journal_and_the_payload() {
    let recordings = Recordings::default();
    let mut tracker = PrefixTracker::new(8);
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::Strict)),
            message(1, Some(7)),
            end(1, EndOutcome::Complete),
        ],
    );
    // The journal durable, the recording unknown, then short.
    assert_eq!(tracker.advance(300, 300, &recordings), (0, 0));
    recordings.set(7, 63, 63);
    assert_eq!(tracker.advance(300, 300, &recordings), (0, 0));
    // The payload written, not durable: complete only.
    recordings.set(7, 64, 0);
    assert_eq!(tracker.advance(300, 300, &recordings), (1, 0));
    recordings.set(7, 64, 64);
    assert_eq!(tracker.advance(300, 300, &recordings), (1, 1));

    // The reverse: the payload durable, the journal not yet.
    let mut tracker = PrefixTracker::new(8);
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::Strict)),
            message(1, Some(7)),
            end(1, EndOutcome::Complete),
        ],
    );
    assert_eq!(tracker.advance(299, 0, &recordings), (0, 0));
    assert_eq!(tracker.advance(300, 299, &recordings), (1, 0));
    assert_eq!(tracker.advance(300, 300, &recordings), (1, 1));
}

/// An event's records not all written (its end missing) is not complete.
#[test]
fn an_open_event_is_not_complete() {
    let none = Recordings::default();
    let mut tracker = PrefixTracker::new(8);
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::Strict)),
            message(1, None),
        ],
    );
    assert_eq!(tracker.advance(u64::MAX, u64::MAX, &none), (0, 0));
}

#[test]
fn an_incomplete_event_or_a_gap_stops_the_prefixes() {
    let none = Recordings::default();
    let mut tracker = PrefixTracker::new(8);
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::BestEffort)),
            message(1, None),
            end(1, EndOutcome::Complete),
            message(2, None),
            end(2, EndOutcome::Incomplete),
            message(3, None),
            end(3, EndOutcome::Complete),
        ],
    );
    assert!(tracker.stopped());
    assert_eq!(tracker.advance(u64::MAX, u64::MAX, &none), (1, 1));
    let mut tracker = PrefixTracker::new(8);
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::BestEffort)),
            message(1, None),
            end(1, EndOutcome::Complete),
            GroupRecord::Gap(GapMarker {
                from_seq: 2,
                to_seq: 4,
                reason: GapReason::RingFull,
            }),
            message(5, None),
            end(5, EndOutcome::Complete),
        ],
    );
    assert_eq!(tracker.advance(u64::MAX, u64::MAX, &none), (1, 1));
}

/// The queue of events not yet durable is bounded: one more is refused
/// with nothing changed, and room comes back as events become durable.
#[test]
fn the_queue_is_bounded() {
    let none = Recordings::default();
    let mut tracker = PrefixTracker::new(2);
    let at = feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::Strict)),
            message(1, None),
            end(1, EndOutcome::Complete),
            message(2, None),
            end(2, EndOutcome::Complete),
            message(3, None),
        ],
    );
    assert!(!tracker.has_room());
    assert_eq!(
        tracker.record(&end(3, EndOutcome::Complete), at + 100),
        Err(PrefixError::Full { capacity: 2 })
    );
    assert_eq!(tracker.advance(300, 300, &none), (1, 1));
    assert!(tracker.has_room());
    tracker
        .record(&end(3, EndOutcome::Complete), at + 100)
        .unwrap();
    assert_eq!(tracker.advance(at + 100, at + 100, &none), (3, 3));
}

#[test]
fn records_out_of_order_are_refused() {
    let mut tracker = PrefixTracker::new(2);
    assert_eq!(
        tracker.record(&message(1, None), 100),
        Err(PrefixError::OutOfOrder)
    );
    tracker
        .record(&GroupRecord::Header(header(1, Capture::Strict)), 100)
        .unwrap();
    for record in [
        GroupRecord::Header(header(1, Capture::Strict)),
        end(1, EndOutcome::Complete),
    ] {
        assert_eq!(tracker.record(&record, 200), Err(PrefixError::OutOfOrder));
    }
    tracker.record(&message(1, None), 200).unwrap();
    assert_eq!(
        tracker.record(&message(2, None), 300),
        Err(PrefixError::OutOfOrder)
    );
    assert_eq!(
        tracker.record(&end(2, EndOutcome::Complete), 300),
        Err(PrefixError::OutOfOrder)
    );
}

#[test]
fn the_view_publishes_the_three_values() {
    let none = Recordings::default();
    let mut tracker = PrefixTracker::new(4);
    let view = tracker.view();
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(10, Capture::Strict)),
            message(10, None),
            end(10, EndOutcome::Complete),
        ],
    );
    assert_eq!(
        (
            view.delivered_seq(),
            view.complete_recording_seq(),
            view.durable_group_seq()
        ),
        (9, 9, 9)
    );
    tracker.delivered(10);
    let _ = tracker.advance(300, 0, &none);
    assert_eq!(
        (
            view.delivered_seq(),
            view.complete_recording_seq(),
            view.durable_group_seq()
        ),
        (10, 10, 9)
    );
    // Delivered never goes back.
    tracker.delivered(3);
    assert_eq!(view.delivered_seq(), 10);
}

fn encode(record: &GroupRecord<'_>) -> Vec<u8> {
    let mut out = vec![0u8; MAX_RECORD];
    let length = record.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

/// ADR-0024: a flush failure leaves the durable prefix where the journal's
/// durable position is; the complete prefix still follows what is written.
#[test]
fn a_flush_failure_holds_the_durable_prefix() {
    let none = Recordings::default();
    let config = JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::None,
    };
    // A budget that lets the header and the event be written, not synced.
    let free = FaultDisk::default();
    let mut journal = GroupJournal::create(
        free.clone(),
        Path::new("/g"),
        &header(1, Capture::Strict),
        config,
    )
    .unwrap();
    let records = [message(1, None), end(1, EndOutcome::Complete)];
    let bytes: Vec<u8> = records.iter().flat_map(encode).collect();
    journal.append(&bytes).unwrap();
    let before_sync = free.used();
    let disk = FaultDisk::with_budget(before_sync);
    let mut journal =
        GroupJournal::create(disk, Path::new("/g"), &header(1, Capture::Strict), config).unwrap();
    let mut tracker = PrefixTracker::new(4);
    tracker
        .record(
            &GroupRecord::Header(header(1, Capture::Strict)),
            journal.written(),
        )
        .unwrap();
    journal.append(&bytes).unwrap();
    let mut at = journal.written() - u64::try_from(bytes.len()).unwrap();
    for record in &records {
        at += u64::try_from(encode(record).len()).unwrap();
        tracker.record(record, at).unwrap();
    }
    assert!(journal.sync().is_err(), "the sync crashes");
    assert_eq!(
        tracker.advance(journal.written(), journal.durable(), &none),
        (1, 0)
    );
}

/// After a restart the prefixes are recomputed from what the journal kept:
/// a strict journal cut inside an event keeps the events before it; a
/// referenced payload not durable holds the durable prefix.
#[test]
fn recovery_recomputes_the_prefixes() {
    let recordings = Recordings::default();
    recordings.set(7, 64, 0);
    let config = JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::PerSegment,
    };
    let disk = FaultDisk::default();
    let mut journal = GroupJournal::create(
        disk.clone(),
        Path::new("/g"),
        &header(1, Capture::Strict),
        config,
    )
    .unwrap();
    let records = [
        message(1, None),
        end(1, EndOutcome::Complete),
        message(2, Some(7)),
        end(2, EndOutcome::Complete),
        GroupRecord::Timer(TimerEvent {
            group_seq: 3,
            logical_time: 3,
            timer_id: 1,
        }),
    ];
    for record in &records {
        journal.append(&encode(record)).unwrap();
    }
    journal.close().unwrap();
    let mut journal = GroupJournal::recover(
        disk.after_crash(Survives::Synced),
        Path::new("/g"),
        1,
        config,
    )
    .unwrap()
    .journal;
    let recovery = recover(&mut journal, &recordings, 8).unwrap();
    assert_eq!(recovery.last_seen, 3);
    assert_eq!(recovery.tracker.complete_recording_seq(), 2);
    assert_eq!(recovery.tracker.durable_group_seq(), 1);
    // The complete prefix ends at event 2's end, before event 3's record.
    let mut ends = Vec::new();
    journal
        .walk(0, |_, end, record| {
            if matches!(record, GroupRecord::End(_)) {
                ends.push(end);
            }
            true
        })
        .unwrap();
    assert_eq!(recovery.tracker.complete_end(), ends[1]);
}

/// #384 review P2-1: under version 1, `Coverage` answers only for a
/// `required` recording. A reference to an async recording, which may
/// have recorded a lost range as a gap with its written position past it,
/// gets `None` and keeps the event out of both prefixes.
#[test]
fn a_reference_to_an_async_recording_never_completes() {
    /// A required recording 7 written to 4096; async recording 8 is not
    /// answered, whatever its written position.
    struct RequiredOnly;
    impl Coverage for RequiredOnly {
        fn positions(&self, recording_id: u64) -> Option<(u64, u64)> {
            (recording_id == 7).then_some((4096, 4096))
        }
    }
    let mut tracker = PrefixTracker::new(8);
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::Strict)),
            message(1, Some(8)),
            end(1, EndOutcome::Complete),
        ],
    );
    assert_eq!(tracker.advance(300, 300, &RequiredOnly), (0, 0));
    let mut tracker = PrefixTracker::new(8);
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::Strict)),
            message(1, Some(7)),
            end(1, EndOutcome::Complete),
        ],
    );
    assert_eq!(tracker.advance(300, 300, &RequiredOnly), (1, 1));
}

/// #384 review P2-2: the complete prefix is a prefix: a later event,
/// written and inline, does not complete past an earlier one still
/// waiting on its payload.
#[test]
fn the_complete_prefix_waits_for_an_earlier_payload() {
    let recordings = Recordings::default();
    let mut tracker = PrefixTracker::new(8);
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::Strict)),
            message(1, Some(7)),
            end(1, EndOutcome::Complete),
            message(2, None),
            end(2, EndOutcome::Complete),
        ],
    );
    assert_eq!(tracker.advance(500, 0, &recordings), (0, 0));
    recordings.set(7, 64, 0);
    assert_eq!(tracker.advance(500, 0, &recordings), (2, 0));
}

/// #384 review P3: a full queue at an end leaves the tracker in the event;
/// the same end is taken again once there is room.
#[test]
fn a_full_end_is_taken_again_once_there_is_room() {
    let recordings = Recordings::default();
    let mut tracker = PrefixTracker::new(1);
    let at = feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::Strict)),
            message(1, Some(7)),
            end(1, EndOutcome::Complete),
            message(2, None),
        ],
    );
    assert_eq!(
        tracker.record(&end(2, EndOutcome::Complete), at + 100),
        Err(PrefixError::Full { capacity: 1 })
    );
    assert_eq!(
        tracker.record(&message(3, None), at + 200),
        Err(PrefixError::OutOfOrder)
    );
    recordings.set(7, 64, 64);
    assert_eq!(tracker.advance(at, at, &recordings), (1, 1));
    tracker
        .record(&end(2, EndOutcome::Complete), at + 100)
        .unwrap();
    tracker.record(&message(3, None), at + 200).unwrap();
}

/// #384 review P3: the tracker refuses a gap inside an event and an
/// observation outside one by itself.
#[test]
fn a_gap_inside_an_event_or_an_observation_outside_one_is_refused() {
    use crate::group::record::{Operation, Outcome, OutcomeObservation};
    let observation = GroupRecord::Outcome(OutcomeObservation {
        group_seq: 1,
        index: 0,
        stream_id: 1,
        session_id: 1,
        operation: Operation::Offer,
        outcome: Outcome::BackPressured,
    });
    let mut tracker = PrefixTracker::new(2);
    tracker
        .record(&GroupRecord::Header(header(1, Capture::BestEffort)), 100)
        .unwrap();
    assert_eq!(
        tracker.record(&observation, 200),
        Err(PrefixError::OutOfOrder)
    );
    tracker.record(&message(1, None), 200).unwrap();
    assert_eq!(
        tracker.record(
            &GroupRecord::Gap(GapMarker {
                from_seq: 2,
                to_seq: 2,
                reason: GapReason::RingFull,
            }),
            300,
        ),
        Err(PrefixError::OutOfOrder)
    );
}

/// #384 review P3: a snapshot never shows durable above complete.
#[test]
fn a_snapshot_keeps_durable_at_most_complete() {
    let none = Recordings::default();
    let mut tracker = PrefixTracker::new(4);
    let view = tracker.view();
    feed(
        &mut tracker,
        &[
            GroupRecord::Header(header(1, Capture::Strict)),
            message(1, None),
            end(1, EndOutcome::Complete),
        ],
    );
    let _ = tracker.advance(300, 300, &none);
    let (_, complete, durable) = view.snapshot();
    assert!(durable <= complete);
    assert_eq!((complete, durable), (1, 1));
}
