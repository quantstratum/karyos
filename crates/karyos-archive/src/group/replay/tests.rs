// SPDX-License-Identifier: Apache-2.0

// The first part of replay: the header check, the cursor over the complete
// prefix and its typed stops, its fixed buffer, and the capture journal.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_sys::frame::Lane;

use super::*;
use crate::fault::{FaultDisk, Survives};
use crate::group::journal::MIN_SEGMENT_LENGTH;
use crate::group::prefix::{Coverage, recover};
use crate::group::record::{
    CONTRACT_VERSION, Capture, EventEnd, GapReason, MessageEvent, Payload, TimerAction, TimerEvent,
    TimerObservation,
};
use crate::segment::SyncPolicy;

const MANIFEST: &[u8] = b"build 1";
const CONFIG: JournalConfig = JournalConfig {
    segment_length: MIN_SEGMENT_LENGTH,
    policy: SyncPolicy::PerSegment,
};
const ROOM: CursorConfig = CursorConfig {
    bytes: 4 * MAX_RECORD,
    records: 4,
};

/// Only recording 7, written and durable to 4096; none has ended.
struct Seven;

impl Coverage for Seven {
    fn positions(&self, recording_id: u64) -> Option<(u64, u64)> {
        (recording_id == 7).then_some((4096, 4096))
    }

    fn ended(&self, _recording_id: u64) -> Option<u64> {
        None
    }
}

fn header(capture: Capture) -> JournalHeader<'static> {
    JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: CONTRACT_VERSION,
        clock: Clock::HostMonotonic,
        capture,
        manifest: MANIFEST,
    }
}

fn expected() -> Expected<'static> {
    Expected {
        contract_version: CONTRACT_VERSION,
        clock: Clock::HostMonotonic,
        manifest: MANIFEST,
    }
}

/// A message event, inline, or naming `recording`'s frames `[0, 64)`.
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

fn timer(seq: u64) -> GroupRecord<'static> {
    GroupRecord::Timer(TimerEvent {
        group_seq: seq,
        logical_time: seq,
        timer_id: 1,
    })
}

fn created(seq: u64, index: u32) -> GroupRecord<'static> {
    GroupRecord::TimerOperation(TimerObservation {
        group_seq: seq,
        index,
        timer_id: 2,
        deadline: 100,
        action: TimerAction::Create,
    })
}

fn end(seq: u64, observations: u32, outcome: EndOutcome) -> GroupRecord<'static> {
    GroupRecord::End(EventEnd {
        group_seq: seq,
        observations,
        outcome,
    })
}

fn encode(record: &GroupRecord<'_>) -> Vec<u8> {
    let mut out = vec![0u8; MAX_RECORD];
    let length = record.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

/// A journal of `header` then `records`, closed, recovered, and its
/// prefixes recomputed against [`Seven`].
fn recorded(
    header: &JournalHeader<'_>,
    records: &[GroupRecord<'_>],
) -> (GroupJournal<FaultDisk>, Recovery) {
    let disk = FaultDisk::default();
    let mut journal = GroupJournal::create(disk.clone(), Path::new("/g"), header, CONFIG).unwrap();
    for record in records {
        journal.append(&encode(record)).unwrap();
    }
    journal.close().unwrap();
    let mut journal = GroupJournal::recover(
        disk.after_crash(Survives::Synced),
        Path::new("/g"),
        header.group_id,
        CONFIG,
    )
    .unwrap()
    .journal;
    let recovery = recover(&mut journal, &Seven, 8).unwrap();
    (journal, recovery)
}

fn cursor(records: &[GroupRecord<'_>], capture: Capture) -> ReplayCursor<FaultDisk> {
    let (journal, recovery) = recorded(&header(capture), records);
    ReplayCursor::open(journal, &recovery, &expected(), ROOM).unwrap()
}

/// The next step's event, as `(group_seq, records)`.
fn event(cursor: &mut ReplayCursor<FaultDisk>) -> (u64, Vec<Vec<u8>>) {
    match cursor.step().unwrap() {
        Step::Event(event) => (
            event.group_seq(),
            event
                .records()
                .map(|record| encode(&record.unwrap()))
                .collect(),
        ),
        Step::Stop(stop) => panic!("a stop: {stop:?}"),
    }
}

fn stop(cursor: &mut ReplayCursor<FaultDisk>) -> Stop {
    match cursor.step().unwrap() {
        Step::Stop(stop) => stop,
        Step::Event(event) => panic!("event {}", event.group_seq()),
    }
}

#[test]
fn the_header_check_takes_the_contract_the_clock_and_the_manifest() {
    let header = header(Capture::Strict);
    assert_eq!(check_header(&header, &expected()), Ok(()));
    let other = Expected {
        contract_version: CONTRACT_VERSION + 1,
        ..expected()
    };
    assert_eq!(
        check_header(&header, &other),
        Err(HeaderMismatch::Contract {
            found: CONTRACT_VERSION,
            expected: CONTRACT_VERSION + 1,
        })
    );
    // One byte more, one byte less, one byte changed.
    for manifest in [&b"build 12"[..], b"build ", b"build 2"] {
        let other = Expected {
            manifest,
            ..expected()
        };
        assert_eq!(check_header(&header, &other), Err(HeaderMismatch::Manifest));
    }
}

#[test]
fn a_cursor_opens_only_on_its_manifest() {
    let (journal, recovery) = recorded(&header(Capture::Strict), &[]);
    let other = Expected {
        manifest: b"build 2",
        ..expected()
    };
    assert!(matches!(
        ReplayCursor::open(journal, &recovery, &other, ROOM),
        Err(ReplayError::Header(HeaderMismatch::Manifest))
    ));
}

#[test]
fn the_cursor_gives_each_event_whole_then_the_end_of_the_prefix() {
    let records = [
        message(1, None),
        end(1, 0, EndOutcome::Complete),
        timer(2),
        created(2, 0),
        created(2, 1),
        end(2, 2, EndOutcome::Complete),
        message(3, Some(7)),
        end(3, 0, EndOutcome::Complete),
    ];
    let mut cursor = cursor(&records, Capture::Strict);
    assert_eq!(
        event(&mut cursor),
        (1, vec![encode(&records[0]), encode(&records[1])])
    );
    assert_eq!(
        event(&mut cursor),
        (2, records[2..6].iter().map(encode).collect())
    );
    assert_eq!(
        event(&mut cursor),
        (3, vec![encode(&records[6]), encode(&records[7])])
    );
    let last = Stop::EndOfPrefix {
        complete_recording_seq: 3,
    };
    assert_eq!(stop(&mut cursor), last);
    assert!(last.is_final());
    assert_eq!(stop(&mut cursor), last);
}

/// An event whose payload is not covered is complete in the journal but
/// outside the prefix: the cursor stops before it.
#[test]
fn the_cursor_stops_before_an_event_waiting_on_its_payload() {
    let records = [
        message(1, None),
        end(1, 0, EndOutcome::Complete),
        message(2, Some(8)),
        end(2, 0, EndOutcome::Complete),
        message(3, None),
        end(3, 0, EndOutcome::Complete),
    ];
    let mut cursor = cursor(&records, Capture::Strict);
    assert_eq!(event(&mut cursor).0, 1);
    assert_eq!(
        stop(&mut cursor),
        Stop::EndOfPrefix {
            complete_recording_seq: 1,
        }
    );
}

#[test]
fn an_incomplete_event_stops_the_cursor() {
    let records = [
        message(1, None),
        end(1, 0, EndOutcome::Complete),
        message(2, None),
        end(2, 0, EndOutcome::Incomplete),
    ];
    let mut cursor = cursor(&records, Capture::Strict);
    assert_eq!(event(&mut cursor).0, 1);
    assert_eq!(stop(&mut cursor), Stop::Incomplete { group_seq: 2 });
}

#[test]
fn a_gap_stops_the_cursor() {
    let gap = GapMarker {
        from_seq: 2,
        to_seq: 4,
        reason: GapReason::RingFull,
    };
    let records = [
        message(1, None),
        end(1, 0, EndOutcome::Complete),
        GroupRecord::Gap(gap),
        message(5, None),
        end(5, 0, EndOutcome::Complete),
    ];
    let mut cursor = cursor(&records, Capture::BestEffort);
    assert_eq!(event(&mut cursor).0, 1);
    let stopped = stop(&mut cursor);
    assert_eq!(stopped, Stop::Gap(gap));
    assert!(stopped.is_final());
}

/// A reference unavailable, which only a best-effort journal holds,
/// completes its event and is told after it: the cursor goes on.
#[test]
fn a_reference_unavailable_is_told_and_the_cursor_goes_on() {
    let unavailable = ReferenceUnavailable {
        group_seq: 1,
        recording_id: 8,
    };
    let records = [
        message(1, Some(8)),
        end(1, 0, EndOutcome::Complete),
        GroupRecord::Unavailable(unavailable),
        message(2, None),
        end(2, 0, EndOutcome::Complete),
    ];
    let mut cursor = cursor(&records, Capture::BestEffort);
    assert_eq!(event(&mut cursor).0, 1);
    let told = stop(&mut cursor);
    assert_eq!(told, Stop::ReferenceUnavailable(unavailable));
    assert!(!told.is_final());
    assert_eq!(event(&mut cursor).0, 2);
    assert_eq!(
        stop(&mut cursor),
        Stop::EndOfPrefix {
            complete_recording_seq: 2,
        }
    );
}

/// The unavailable record of the prefix's last event lies past the
/// prefix's end; the cursor still tells it.
#[test]
fn the_last_events_reference_unavailable_is_told() {
    let unavailable = ReferenceUnavailable {
        group_seq: 1,
        recording_id: 8,
    };
    let records = [
        message(1, Some(8)),
        end(1, 0, EndOutcome::Complete),
        GroupRecord::Unavailable(unavailable),
    ];
    let mut cursor = cursor(&records, Capture::BestEffort);
    assert_eq!(event(&mut cursor).0, 1);
    assert_eq!(stop(&mut cursor), Stop::ReferenceUnavailable(unavailable));
    assert_eq!(
        stop(&mut cursor),
        Stop::EndOfPrefix {
            complete_recording_seq: 1,
        }
    );
}

/// An event larger than the buffer is refused and not consumed.
#[test]
fn an_event_larger_than_the_buffer_is_refused() {
    let records = [
        timer(1),
        created(1, 0),
        created(1, 1),
        created(1, 2),
        end(1, 3, EndOutcome::Complete),
    ];
    let (journal, recovery) = recorded(&header(Capture::Strict), &records);
    let mut cursor = ReplayCursor::open(journal, &recovery, &expected(), ROOM).unwrap();
    assert!(matches!(
        cursor.step(),
        Err(ReplayError::Records { capacity: 4 })
    ));
    assert!(matches!(
        cursor.step(),
        Err(ReplayError::Records { capacity: 4 })
    ));
    let (journal, recovery) = recorded(&header(Capture::Strict), &records);
    let small = CursorConfig {
        bytes: encode(&records[0]).len() + 1,
        records: 8,
    };
    let mut cursor = ReplayCursor::open(journal, &recovery, &expected(), small).unwrap();
    assert!(matches!(cursor.step(), Err(ReplayError::Bytes { .. })));
}

/// Replaying into a capture journal with the recorded header gives back
/// the recorded records.
#[test]
fn a_capture_journal_takes_what_the_replay_gives() {
    let records = [
        message(1, None),
        end(1, 0, EndOutcome::Complete),
        timer(2),
        created(2, 0),
        end(2, 1, EndOutcome::Complete),
    ];
    let header = header(Capture::Strict);
    let (journal, recovery) = recorded(&header, &records);
    let mut cursor = ReplayCursor::open(journal, &recovery, &expected(), ROOM).unwrap();
    let mut capture =
        CaptureJournal::create(FaultDisk::default(), Path::new("/c"), &header, CONFIG).unwrap();
    while let Step::Event(event) = cursor.step().unwrap() {
        for record in event.records() {
            let _ = capture.append(&record.unwrap()).unwrap();
        }
    }
    let mut captured = capture.into_journal();
    let mut replayed = Vec::new();
    let _ = captured
        .walk(0, |_, _, record| {
            replayed.push(encode(record));
            true
        })
        .unwrap();
    let mut wanted = vec![encode(&GroupRecord::Header(header))];
    wanted.extend(records.iter().map(encode));
    assert_eq!(replayed, wanted);
    // The order rules hold: an end without its event is refused.
    let mut capture =
        CaptureJournal::create(FaultDisk::default(), Path::new("/d"), &header, CONFIG).unwrap();
    assert!(matches!(
        capture.append(&end(1, 0, EndOutcome::Complete)),
        Err(JournalError::Order(_))
    ));
}
