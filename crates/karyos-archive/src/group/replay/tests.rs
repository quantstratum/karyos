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
    CONTRACT_VERSION, Capture, EventEnd, GapReason, Loss, LossEvent, MessageEvent, Payload,
    ReferenceUnavailable, TimerAction, TimerEvent, TimerObservation,
};
use crate::segment::{SegmentError, SyncPolicy};

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
        reopen_hold: 0,
        manifest: MANIFEST,
    }
}

fn expected() -> ReplayConfig<'static> {
    ReplayConfig {
        manifest: MANIFEST,
        accept_manifest: false,
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

/// Every step until a stop, as `(group_seq, reference_unavailable)`, and
/// the stop.
fn steps<D: crate::disk::Disk>(cursor: &mut ReplayCursor<D>) -> (Vec<(u64, bool)>, Stop) {
    let mut events = Vec::new();
    loop {
        match cursor.step().unwrap() {
            Step::Event(event) => events.push((event.group_seq(), event.reference_unavailable())),
            // These journals hold no checkpoint.
            Step::Checkpoint(checkpoint) | Step::LateCheckpoint(checkpoint) => {
                panic!("a checkpoint: {checkpoint:?}")
            }
            Step::Stop(stop) => return (events, stop),
        }
    }
}

fn cursor(records: &[GroupRecord<'_>], capture: Capture) -> ReplayCursor<FaultDisk> {
    let (journal, recovery) = recorded(&header(capture), records);
    ReplayCursor::open(journal, &recovery, &expected(), ROOM).unwrap()
}

/// The next step's event, as `(group_seq, records)`.
fn event<D: crate::disk::Disk>(cursor: &mut ReplayCursor<D>) -> (u64, Vec<Vec<u8>>) {
    match cursor.step().unwrap() {
        Step::Event(event) => (
            event.group_seq(),
            event
                .records()
                .map(|record| encode(&record.unwrap()))
                .collect(),
        ),
        Step::Stop(stop) => panic!("a stop: {stop:?}"),
        Step::Checkpoint(checkpoint) | Step::LateCheckpoint(checkpoint) => {
            panic!("a checkpoint: {checkpoint:?}")
        }
    }
}

fn stop(cursor: &mut ReplayCursor<FaultDisk>) -> Stop {
    match cursor.step().unwrap() {
        Step::Stop(stop) => stop,
        Step::Event(event) => panic!("event {}", event.group_seq()),
        Step::Checkpoint(checkpoint) | Step::LateCheckpoint(checkpoint) => {
            panic!("a checkpoint: {checkpoint:?}")
        }
    }
}

#[test]
fn the_header_check_takes_the_contract_the_clock_and_the_manifest() {
    let header = header(Capture::Strict);
    assert_eq!(check_header(&header, &expected()), Ok(()));
    // The contract is this build's, whatever the caller accepts.
    let other = JournalHeader {
        contract_version: CONTRACT_VERSION + 1,
        ..header
    };
    let accepting = ReplayConfig {
        accept_manifest: true,
        ..expected()
    };
    assert_eq!(
        check_header(&other, &accepting),
        Err(HeaderMismatch::Contract {
            found: CONTRACT_VERSION + 1,
            expected: CONTRACT_VERSION,
        })
    );
    // One byte more, one byte less, one byte changed: refused unless
    // accepted.
    for manifest in [&b"build 12"[..], b"build ", b"build 2"] {
        let other = ReplayConfig {
            manifest,
            ..expected()
        };
        assert_eq!(check_header(&header, &other), Err(HeaderMismatch::Manifest));
        let accepted = ReplayConfig {
            accept_manifest: true,
            ..other
        };
        assert_eq!(check_header(&header, &accepted), Ok(()));
    }
}

#[test]
fn a_cursor_opens_only_on_its_manifest_unless_accepted() {
    let (journal, recovery) = recorded(&header(Capture::Strict), &[]);
    let other = ReplayConfig {
        manifest: b"build 2",
        ..expected()
    };
    assert!(matches!(
        ReplayCursor::open(journal, &recovery, &other, ROOM),
        Err(ReplayError::Header(HeaderMismatch::Manifest))
    ));
    let (journal, recovery) = recorded(&header(Capture::Strict), &[]);
    let accepted = ReplayConfig {
        accept_manifest: true,
        ..other
    };
    assert!(ReplayCursor::open(journal, &recovery, &accepted, ROOM).is_ok());
}

/// A configuration with fewer than two records, or one that cannot be
/// allocated, is refused at open; so is a recovery whose feed stopped.
#[test]
fn a_cursor_refuses_a_bad_configuration_or_a_truncated_recovery() {
    for room in [
        CursorConfig {
            bytes: 1024,
            records: 1,
        },
        CursorConfig {
            bytes: 1024,
            records: usize::MAX,
        },
        CursorConfig {
            bytes: usize::MAX,
            records: 4,
        },
    ] {
        let (journal, recovery) = recorded(&header(Capture::Strict), &[]);
        assert!(matches!(
            ReplayCursor::open(journal, &recovery, &expected(), room),
            Err(ReplayError::InvalidConfig)
        ));
    }
    // Two events waiting on recording 8, which is not covered, with room
    // for one: the feed stops at the second.
    let records = [
        message(1, Some(8)),
        end(1, 0, EndOutcome::Complete),
        message(2, Some(8)),
        end(2, 0, EndOutcome::Complete),
    ];
    let (mut journal, _) = recorded(&header(Capture::Strict), &records);
    let recovery = recover(&mut journal, &Seven, 1).unwrap();
    assert!(recovery.full);
    assert!(matches!(
        ReplayCursor::open(journal, &recovery, &expected(), ROOM),
        Err(ReplayError::Truncated)
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
    // The incomplete event comes once, with its records, then the stop.
    match cursor.step().unwrap() {
        Step::Event(event) => {
            assert_eq!((event.group_seq(), event.incomplete()), (2, true));
            assert_eq!(event.len(), 2);
        }
        Step::Stop(stop) => panic!("{stop:?}"),
        Step::Checkpoint(checkpoint) | Step::LateCheckpoint(checkpoint) => {
            panic!("a checkpoint: {checkpoint:?}")
        }
    }
    assert_eq!(stop(&mut cursor), Stop::Incomplete { group_seq: 2 });
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
    assert_eq!(stop(&mut cursor), stopped);
}

/// A reference unavailable (only a best-effort journal holds one) names
/// its event wherever it lies after it: right after it, after a later
/// event, after a gap or after an incomplete event (the #413 review's
/// probes). The event says so before it is presented, and the record is
/// no event.
#[test]
fn an_event_says_a_reference_unavailable_names_it() {
    let unavailable = GroupRecord::Unavailable(ReferenceUnavailable {
        group_seq: 1,
        recording_id: 8,
    });
    let right_after = [
        message(1, Some(8)),
        end(1, 0, EndOutcome::Complete),
        unavailable,
        message(2, None),
        end(2, 0, EndOutcome::Complete),
    ];
    let mut c = cursor(&right_after, Capture::BestEffort);
    assert_eq!(
        steps(&mut c),
        (
            vec![(1, true), (2, false)],
            Stop::EndOfPrefix {
                complete_recording_seq: 2
            }
        )
    );
    // After a later event that waits on another recording.
    let after_a_waiting_event = [
        message(1, Some(8)),
        end(1, 0, EndOutcome::Complete),
        message(2, Some(9)),
        end(2, 0, EndOutcome::Complete),
        unavailable,
    ];
    let mut c = cursor(&after_a_waiting_event, Capture::BestEffort);
    assert_eq!(
        steps(&mut c),
        (
            vec![(1, true)],
            Stop::EndOfPrefix {
                complete_recording_seq: 1
            }
        )
    );
    let gap = GapMarker {
        from_seq: 2,
        to_seq: 3,
        reason: GapReason::RingFull,
    };
    let after_a_gap = [
        message(1, Some(8)),
        end(1, 0, EndOutcome::Complete),
        GroupRecord::Gap(gap),
        message(4, None),
        end(4, 0, EndOutcome::Complete),
        unavailable,
    ];
    let mut c = cursor(&after_a_gap, Capture::BestEffort);
    assert_eq!(steps(&mut c), (vec![(1, true)], Stop::Gap(gap)));
    let after_an_incomplete_event = [
        message(1, Some(8)),
        end(1, 0, EndOutcome::Complete),
        message(2, None),
        end(2, 0, EndOutcome::Incomplete),
        unavailable,
    ];
    let mut c = cursor(&after_an_incomplete_event, Capture::BestEffort);
    assert_eq!(
        steps(&mut c),
        (
            vec![(1, true), (2, false)],
            Stop::Incomplete { group_seq: 2 }
        )
    );
}

/// A message whose payload was not captured (payload 3) and a loss event
/// are events like any other.
#[test]
fn an_uncaptured_message_and_a_loss_are_events() {
    let uncaptured = GroupRecord::Message(MessageEvent {
        group_seq: 1,
        logical_time: 1,
        incarnation: 1,
        position: 0,
        extent: 70_080,
        stream_id: 1,
        session_id: 1,
        lane: Lane::ZERO,
        reserved_value: 0,
        end_of_stream: false,
        extension: None,
        payload: Payload::Unavailable { length: 70_000 },
    });
    let loss = GroupRecord::Loss(LossEvent {
        group_seq: 2,
        logical_time: 2,
        incarnation: 1,
        from: 12_288,
        lost_to: 12_544,
        resume: 12_544,
        stream_id: 1,
        session_id: 1,
        lane: Lane::ZERO,
        loss: Loss::Aborted,
    });
    let records = [
        uncaptured,
        end(1, 0, EndOutcome::Complete),
        loss,
        end(2, 0, EndOutcome::Complete),
    ];
    let mut cursor = cursor(&records, Capture::BestEffort);
    assert_eq!(
        event(&mut cursor),
        (1, vec![encode(&records[0]), encode(&records[1])])
    );
    assert_eq!(
        event(&mut cursor),
        (2, vec![encode(&records[2]), encode(&records[3])])
    );
    assert_eq!(
        stop(&mut cursor),
        Stop::EndOfPrefix {
            complete_recording_seq: 2
        }
    );
}

/// A buffer of exactly an event's bytes and records holds it; one byte or
/// one record less does not.
#[test]
fn an_event_fits_a_buffer_of_exactly_its_size() {
    let records = [timer(1), created(1, 0), end(1, 1, EndOutcome::Complete)];
    let total: usize = records.iter().map(|record| encode(record).len()).sum();
    for (bytes, records_room, fits) in [(total, 3, true), (total - 1, 3, false), (total, 2, false)]
    {
        let (journal, recovery) = recorded(&header(Capture::Strict), &records);
        let room = CursorConfig {
            bytes,
            records: records_room,
        };
        let mut cursor = ReplayCursor::open(journal, &recovery, &expected(), room).unwrap();
        match cursor.step() {
            Ok(Step::Event(event)) => assert!(fits, "{bytes} {records_room}: {event:?}"),
            Err(ReplayError::Bytes { .. } | ReplayError::Records { .. }) => assert!(!fits),
            other => panic!("{other:?}"),
        }
    }
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
    let mut capture = CaptureJournal::create(
        FaultDisk::default(),
        Path::new("/c"),
        &header,
        b"build 2",
        CONFIG,
    )
    .unwrap();
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
    // The capture's header names the replaying caller's manifest.
    let mut wanted = vec![encode(&GroupRecord::Header(JournalHeader {
        reopen_hold: 0,
        manifest: b"build 2",
        ..header
    }))];
    wanted.extend(records.iter().map(encode));
    assert_eq!(replayed, wanted);
    // The order rules hold: an end without its event is refused.
    let mut capture = CaptureJournal::create(
        FaultDisk::default(),
        Path::new("/d"),
        &header,
        MANIFEST,
        CONFIG,
    )
    .unwrap();
    assert!(matches!(
        capture.append(&end(1, 0, EndOutcome::Complete)),
        Err(JournalError::Order(_))
    ));
}

/// A capture goes to its own directory: the original's holds the group's
/// journal, and is refused.
#[test]
fn a_capture_in_the_originals_directory_is_refused() {
    let disk = FaultDisk::default();
    let header = header(Capture::Strict);
    let _original = GroupJournal::create(disk.clone(), Path::new("/g"), &header, CONFIG).unwrap();
    assert!(matches!(
        CaptureJournal::create(disk, Path::new("/g"), &header, MANIFEST, CONFIG),
        Err(JournalError::Segment(SegmentError::Exists { .. }))
    ));
}

/// Marks out of order: each named event is flagged, the others not (the
/// #413 re-check's probe; a sort that is skipped fails it).
#[test]
fn marks_out_of_order_flag_their_events() {
    let mark = |group_seq| {
        GroupRecord::Unavailable(ReferenceUnavailable {
            group_seq,
            recording_id: 8,
        })
    };
    let records = [
        message(1, Some(8)),
        end(1, 0, EndOutcome::Complete),
        message(2, None),
        end(2, 0, EndOutcome::Complete),
        message(3, Some(8)),
        end(3, 0, EndOutcome::Complete),
        mark(3),
        mark(1),
        message(4, None),
        end(4, 0, EndOutcome::Complete),
    ];
    let mut c = cursor(&records, Capture::BestEffort);
    assert_eq!(
        steps(&mut c),
        (
            vec![(1, true), (2, false), (3, true), (4, false)],
            Stop::EndOfPrefix {
                complete_recording_seq: 4
            }
        )
    );
}

/// A recovery of another journal, whose prefix has an event where this
/// journal has a gap: the cursor refuses it typed.
#[test]
fn a_record_that_starts_no_event_is_refused() {
    let other = [
        message(1, None),
        end(1, 0, EndOutcome::Complete),
        message(2, None),
        end(2, 0, EndOutcome::Complete),
        message(3, None),
        end(3, 0, EndOutcome::Complete),
    ];
    let (_, recovery) = recorded(&header(Capture::BestEffort), &other);
    let records = [
        message(1, None),
        end(1, 0, EndOutcome::Complete),
        GroupRecord::Gap(GapMarker {
            from_seq: 2,
            to_seq: 2,
            reason: GapReason::RingFull,
        }),
        message(3, None),
        end(3, 0, EndOutcome::Complete),
    ];
    let (journal, _) = recorded(&header(Capture::BestEffort), &records);
    let mut cursor = ReplayCursor::open(journal, &recovery, &expected(), ROOM).unwrap();
    assert_eq!(event(&mut cursor).0, 1);
    assert!(matches!(cursor.step(), Err(ReplayError::NotAnEvent { .. })));
}

/// A closed journal recovers through a read-only disk, and a cursor reads
/// it: what a tool that writes nothing does. A journal whose recovery
/// would repair it fails instead.
#[test]
fn a_closed_journal_recovers_read_only() {
    use crate::disk::ReadOnly;

    let records = [message(1, None), end(1, 0, EndOutcome::Complete)];
    let disk = FaultDisk::default();
    let header = header(Capture::Strict);
    let mut journal = GroupJournal::create(disk.clone(), Path::new("/g"), &header, CONFIG).unwrap();
    for record in &records {
        journal.append(&encode(record)).unwrap();
    }
    journal.close().unwrap();
    let mut journal = GroupJournal::recover(ReadOnly(disk.clone()), Path::new("/g"), 1, CONFIG)
        .unwrap()
        .journal;
    let recovery = recover(&mut journal, &Seven, 8).unwrap();
    let mut cursor = ReplayCursor::open(journal, &recovery, &expected(), ROOM).unwrap();
    assert_eq!(event(&mut cursor).0, 1);
    assert_eq!(
        crate::segment::recorded_geometry(&mut ReadOnly(disk), Path::new("/g"), 1).unwrap(),
        Some(
            crate::segment::Geometry::new(MIN_SEGMENT_LENGTH, u64::from(MIN_SEGMENT_LENGTH))
                .unwrap()
        )
    );
    // A torn tail (the data of an unsynced append lost, its index entry
    // kept): recovery would cut it; read only, it fails.
    let disk = FaultDisk::default();
    let mut journal = GroupJournal::create(disk.clone(), Path::new("/g"), &header, CONFIG).unwrap();
    journal.append(&encode(&records[0])).unwrap();
    let crashed = disk.after_crash(Survives::TornData);
    let read_only = GroupJournal::recover(ReadOnly(crashed), Path::new("/g"), 1, CONFIG);
    assert!(matches!(
        read_only,
        Err(JournalError::Segment(crate::segment::SegmentError::Io(error)))
            if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
}

/// The journal `disk` holds now, as a reader in another process sees it
/// after the writer's last sync: recovered from what is durable, and its
/// prefixes recomputed.
fn read_now(disk: &FaultDisk, header: &JournalHeader<'_>) -> (GroupJournal<FaultDisk>, Recovery) {
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

/// Appends events `seqs`, each a message and its end, and syncs.
fn write_events(journal: &mut GroupJournal<FaultDisk>, seqs: std::ops::RangeInclusive<u64>) {
    for seq in seqs {
        journal.append(&encode(&message(seq, None))).unwrap();
        journal
            .append(&encode(&end(seq, 0, EndOutcome::Complete)))
            .unwrap();
    }
    let _ = journal.sync().unwrap();
}

/// R-CORE-46 (karyos#881): a follower over a group still being written
/// gives the complete prefix, waits at its end, resumes from where it
/// stopped as the prefix advances, without reopening, and ends at the
/// sealed group's end, having seen what a replay of the closed group sees.
#[test]
fn a_follower_resumes_as_the_prefix_advances_and_ends_as_closed_replay_does() {
    let header = header(Capture::Strict);
    let disk = FaultDisk::default();
    let mut writer = GroupJournal::create(disk.clone(), Path::new("/g"), &header, CONFIG).unwrap();
    write_events(&mut writer, 1..=3);
    let (journal, recovery) = read_now(&disk, &header);
    let mut follower = ReplayCursor::open(journal, &recovery, &expected(), ROOM).unwrap();
    let (mut seen, stop) = steps(&mut follower);
    assert_eq!(seen, vec![(1, false), (2, false), (3, false)]);
    assert_eq!(
        stop,
        Stop::EndOfPrefix {
            complete_recording_seq: 3
        }
    );
    // Nothing new yet: following the same prefix gives the same stop.
    let (journal, recovery) = read_now(&disk, &header);
    follower.follow(journal, &recovery, &expected()).unwrap();
    let (none, stop) = steps(&mut follower);
    assert!(none.is_empty());
    assert_eq!(
        stop,
        Stop::EndOfPrefix {
            complete_recording_seq: 3
        }
    );
    // The writer goes on; the follower resumes after event 3.
    write_events(&mut writer, 4..=5);
    let (journal, recovery) = read_now(&disk, &header);
    follower.follow(journal, &recovery, &expected()).unwrap();
    let (more, _) = steps(&mut follower);
    assert_eq!(more, vec![(4, false), (5, false)]);
    seen.extend(more);
    // Sealed: the writer finishes, and the follower ends where a replay
    // of the closed group ends, having seen the same events.
    write_events(&mut writer, 6..=6);
    writer.close().unwrap();
    let (journal, recovery) = read_now(&disk, &header);
    follower.follow(journal, &recovery, &expected()).unwrap();
    let (last, followed_stop) = steps(&mut follower);
    seen.extend(last);
    let (journal, recovery) = read_now(&disk, &header);
    let mut closed = ReplayCursor::open(journal, &recovery, &expected(), ROOM).unwrap();
    assert_eq!(steps(&mut closed), (seen, followed_stop));
}

/// A gap is final: no later prefix extends past it, and following one is
/// refused, the cursor left as it was.
#[test]
fn following_past_a_final_stop_is_refused() {
    let gap = GapMarker {
        from_seq: 2,
        to_seq: 2,
        reason: GapReason::RingFull,
    };
    let records = [
        message(1, None),
        end(1, 0, EndOutcome::Complete),
        GroupRecord::Gap(gap),
    ];
    let (journal, recovery) = recorded(&header(Capture::BestEffort), &records);
    let mut cursor = ReplayCursor::open(journal, &recovery, &expected(), ROOM).unwrap();
    let (_, stopped) = steps(&mut cursor);
    assert_eq!(stopped, Stop::Gap(gap));
    let (journal, recovery) = recorded(&header(Capture::BestEffort), &records);
    assert!(matches!(
        cursor.follow(journal, &recovery, &expected()),
        Err(ReplayError::FinalStop { stop: Stop::Gap(_) })
    ));
    assert_eq!(stop(&mut cursor), Stop::Gap(gap));
}

/// A journal whose prefix ends before what the cursor gave is not a later
/// state of the same recording.
#[test]
fn following_a_shorter_prefix_is_refused() {
    let long = [
        message(1, None),
        end(1, 0, EndOutcome::Complete),
        message(2, None),
        end(2, 0, EndOutcome::Complete),
    ];
    let mut cursor = cursor(&long, Capture::Strict);
    let _ = steps(&mut cursor);
    let (journal, recovery) = recorded(&header(Capture::Strict), &long[..2]);
    assert!(matches!(
        cursor.follow(journal, &recovery, &expected()),
        Err(ReplayError::PrefixBehind {
            replayed: 2,
            found: 1
        })
    ));
}

/// karyos#881 review P1: a poll of a journal a live writer still owns
/// recovers it through a read-only disk, which never modifies it. The
/// follower advances while the writer keeps appending, and the writer's
/// journal is unchanged by the polls.
#[test]
fn a_live_journal_is_polled_read_only() {
    use crate::disk::ReadOnly;

    let header = header(Capture::Strict);
    let disk = FaultDisk::default();
    let mut writer = GroupJournal::create(disk.clone(), Path::new("/g"), &header, CONFIG).unwrap();
    write_events(&mut writer, 1..=2);
    let poll = || {
        let mut journal = GroupJournal::recover(
            ReadOnly(disk.clone()),
            Path::new("/g"),
            header.group_id,
            CONFIG,
        )
        .unwrap()
        .journal;
        let recovery = recover(&mut journal, &Seven, 8).unwrap();
        (journal, recovery)
    };
    let (journal, recovery) = poll();
    let mut follower = ReplayCursor::open(journal, &recovery, &expected(), ROOM).unwrap();
    let (seen, _) = steps(&mut follower);
    assert_eq!(seen, vec![(1, false), (2, false)]);
    // The writer, never closed, goes on appending after the poll.
    write_events(&mut writer, 3..=4);
    let (journal, recovery) = poll();
    follower.follow(journal, &recovery, &expected()).unwrap();
    let (more, _) = steps(&mut follower);
    assert_eq!(more, vec![(3, false), (4, false)]);
    write_events(&mut writer, 5..=5);
    writer.close().unwrap();
}
