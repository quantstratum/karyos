// SPDX-License-Identifier: Apache-2.0

// Replay with checkpoints (A9-2, recording-group-checkpoints.md sections
// 6 and 8): replay from a checkpoint gives the same events, from that
// point, as replay from the start; each recorded checkpoint is given
// right after its event, and a state that differs there diverges; a
// corrupt, unknown or out-of-prefix checkpoint is not comparable; in best
// effort, the range after a gap replays from its checkpoint.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use super::*;
use crate::fault::{FaultDisk, Survives};
use crate::group::checkpoint::{CheckpointSlot, CheckpointWriter, recorded_end};
use crate::group::journal::MIN_SEGMENT_LENGTH;
use crate::group::prefix::{Coverage, recover};
use crate::group::record::{Capture, EventEnd, GapReason, TimerEvent};
use crate::segment::SyncPolicy;

const JOURNALS: &str = "/groups";
const CHECKPOINTS: &str = "/checkpoints";
const GROUP: u64 = 9;
const MANIFEST: &[u8] = b"m";
const ROOM: CursorConfig = CursorConfig {
    bytes: 4 * MAX_RECORD,
    records: 4,
};

fn config() -> JournalConfig {
    JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::PerSegment,
    }
}

fn header(capture: Capture) -> JournalHeader<'static> {
    JournalHeader {
        group_id: GROUP,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: CONTRACT_VERSION,
        clock: CLOCK,
        capture,
        manifest: MANIFEST,
    }
}

fn replay_config() -> ReplayConfig<'static> {
    ReplayConfig {
        manifest: MANIFEST,
        accept_manifest: false,
    }
}

fn encode(record: &GroupRecord<'_>) -> Vec<u8> {
    let mut out = vec![0u8; MAX_RECORD];
    let length = record.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

/// Event `seq`, complete or not: a timer and its end.
fn event(seq: u64, outcome: EndOutcome) -> Vec<u8> {
    let mut bytes = encode(&GroupRecord::Timer(TimerEvent {
        group_seq: seq,
        logical_time: seq,
        timer_id: seq,
    }));
    bytes.extend(encode(&GroupRecord::End(EventEnd {
        group_seq: seq,
        observations: 0,
        outcome,
    })));
    bytes
}

fn gap(from_seq: u64, to_seq: u64) -> Vec<u8> {
    encode(&GroupRecord::Gap(GapMarker {
        from_seq,
        to_seq,
        reason: GapReason::RingFull,
    }))
}

/// One step of a journal being written.
enum Write<'a> {
    Records(Vec<u8>),
    Checkpoint(u64, &'a [u8]),
}

/// The checkpoint store, as the prefixes' coverage.
struct Held<'a>(&'a CheckpointStore<FaultDisk>);

impl Coverage for Held<'_> {
    fn positions(&self, _recording_id: u64) -> Option<(u64, u64)> {
        None
    }

    fn ended(&self, _recording_id: u64) -> Option<u64> {
        None
    }

    fn checkpoint(&self, position: u64, end: u64) -> CheckpointHeld {
        self.0.holds(position, end)
    }
}

/// A recovered journal of `capture` written by `writes`, with its store
/// and recovery.
struct Recorded {
    disk: FaultDisk,
}

impl Recorded {
    fn new(capture: Capture, writes: &[Write<'_>]) -> Self {
        let disk = FaultDisk::default();
        let mut journal = GroupJournal::create(
            disk.clone(),
            Path::new(JOURNALS),
            &header(capture),
            config(),
        )
        .unwrap();
        let store =
            CheckpointStore::create(disk.clone(), Path::new(CHECKPOINTS), GROUP, config()).unwrap();
        let mut writer = CheckpointWriter::new(store, &journal).unwrap();
        let mut slot = CheckpointSlot::new(4096);
        for write in writes {
            match write {
                Write::Records(bytes) => {
                    let _ = journal.append(bytes).unwrap();
                }
                Write::Checkpoint(seq, bytes) => {
                    let request = slot
                        .take(*seq, 7, |buffer| {
                            buffer[..bytes.len()].copy_from_slice(bytes);
                            bytes.len()
                        })
                        .unwrap();
                    let result = writer.write(&mut journal, &request);
                    slot.returned(request, &result);
                    let _ = result.unwrap();
                }
            }
        }
        let _ = journal.close().unwrap();
        let _ = writer.store_mut().sync().unwrap();
        Self {
            disk: disk.after_crash(Survives::Synced),
        }
    }

    fn journal(&self) -> GroupJournal<FaultDisk> {
        GroupJournal::recover(self.disk.clone(), Path::new(JOURNALS), GROUP, config())
            .unwrap()
            .journal
    }

    fn store(&self) -> CheckpointStore<FaultDisk> {
        let end = recorded_end(&mut self.journal()).unwrap();
        CheckpointStore::recover(
            self.disk.clone(),
            Path::new(CHECKPOINTS),
            GROUP,
            config(),
            end,
        )
        .unwrap()
    }

    fn recovery(&self, store: &CheckpointStore<FaultDisk>) -> Recovery {
        recover(&mut self.journal(), &Held(store), 8).unwrap()
    }

    fn replay_from_start(&self) -> Vec<Seen> {
        let store = self.store();
        let recovery = self.recovery(&store);
        let cursor = ReplayCursor::open(self.journal(), &recovery, &replay_config(), ROOM).unwrap();
        steps(cursor)
    }

    /// The snapshot and the steps from checkpoint `id`.
    fn replay_from_checkpoint(&self, id: u64) -> Result<(Vec<u8>, Vec<Seen>), ReplayError> {
        let mut store = self.store();
        let recovery = self.recovery(&store);
        let mut snapshot = vec![0u8; 4096];
        let (cursor, record) = ReplayCursor::open_at_checkpoint(
            self.journal(),
            &recovery,
            &mut store,
            id,
            &replay_config(),
            ROOM,
            &mut snapshot,
        )?;
        snapshot.truncate(usize::try_from(record.length).unwrap());
        Ok((snapshot, steps(cursor)))
    }
}

/// What a step gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    /// An event: its `group_seq` and its records' bytes.
    Event(u64, Vec<u8>),
    /// A checkpoint: its `group_seq` and id.
    Checkpoint(u64, u64),
    Stop(Stop),
}

fn steps(mut cursor: ReplayCursor<FaultDisk>) -> Vec<Seen> {
    let mut seen = Vec::new();
    loop {
        match cursor.step().unwrap() {
            Step::Event(event) => seen.push(Seen::Event(event.group_seq(), event.bytes().to_vec())),
            Step::Checkpoint(checkpoint) => seen.push(Seen::Checkpoint(
                checkpoint.group_seq,
                checkpoint.checkpoint_id,
            )),
            Step::Stop(stop) => {
                seen.push(Seen::Stop(stop));
                return seen;
            }
        }
    }
}

fn kinds(seen: &[Seen]) -> Vec<String> {
    seen.iter()
        .map(|seen| match seen {
            Seen::Event(seq, _) => format!("e{seq}"),
            Seen::Checkpoint(seq, id) => format!("c{seq}#{id}"),
            Seen::Stop(stop) => format!("{stop:?}"),
        })
        .collect()
}

/// Replay from a checkpoint gives the same events, from the event after
/// it, as replay from the start; each recorded checkpoint is given right
/// after the event it names, also when its record lags in the journal.
#[test]
fn replay_from_a_checkpoint_matches_replay_from_the_start() {
    let recorded = Recorded::new(
        Capture::Strict,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(event(2, EndOutcome::Complete)),
            Write::Records(event(3, EndOutcome::Complete)),
            // Its record lags: event 3 came first.
            Write::Checkpoint(2, b"state at 2"),
            Write::Records(event(4, EndOutcome::Complete)),
            Write::Checkpoint(4, b"state at 4"),
        ],
    );
    let all = recorded.replay_from_start();
    assert_eq!(
        kinds(&all),
        [
            "e1",
            "e2",
            "c2#1",
            "e3",
            "e4",
            "c4#2",
            "EndOfPrefix { complete_recording_seq: 4 }"
        ]
    );
    let (snapshot, from) = recorded.replay_from_checkpoint(1).unwrap();
    assert_eq!(snapshot, b"state at 2");
    assert_eq!(
        kinds(&from),
        [
            "e3",
            "e4",
            "c4#2",
            "EndOfPrefix { complete_recording_seq: 4 }"
        ]
    );
    // The same events, byte for byte, from that point.
    assert_eq!(&all[3..], &from[..]);
    let (snapshot, last) = recorded.replay_from_checkpoint(2).unwrap();
    assert_eq!(snapshot, b"state at 4");
    assert_eq!(kinds(&last), ["EndOfPrefix { complete_recording_seq: 4 }"]);
}

/// The state compared at a checkpoint: the same bytes give the capture's
/// record, at the capture position with the replay's digest, which the
/// capture journal takes; other bytes diverge, kind `state checkpoint`,
/// at the checkpoint's `group_seq`.
#[test]
fn a_state_that_differs_at_a_checkpoint_diverges_there() {
    let recorded = CheckpointRecord {
        group_seq: 2,
        checkpoint_id: 1,
        position: 0,
        length: 10,
        crc32c: crc32c(b"state at 2"),
        format: 7,
    };
    let capture = compare_state(&recorded, b"state at 2").unwrap();
    assert_eq!(capture.position, CAPTURE_POSITION);
    assert_eq!(capture.end(), None);
    assert_eq!((capture.length, capture.crc32c), (10, recorded.crc32c));
    let mut journal = CaptureJournal::create(
        FaultDisk::default(),
        Path::new(JOURNALS),
        &header(Capture::Strict),
        MANIFEST,
        config(),
    )
    .unwrap();
    for seq in 1..=2 {
        let mut bytes = event(seq, EndOutcome::Complete);
        while !bytes.is_empty() {
            let length =
                usize::try_from(karyos_codec::Envelope::read(&bytes).unwrap().message_length)
                    .unwrap();
            let _ = journal
                .append(&GroupRecord::decode(&bytes[..length]).unwrap())
                .unwrap();
            bytes.drain(..length);
        }
    }
    let _ = journal.append(&GroupRecord::Checkpoint(capture)).unwrap();
    let divergence = compare_state(&recorded, b"state at 3").unwrap_err();
    assert_eq!(divergence.group_seq, 2);
    assert_eq!(divergence.length, 10);
    assert_ne!(divergence.crc32c, recorded.crc32c);
    assert!(divergence.to_string().starts_with("state checkpoint at 2"));
    assert!(compare_state(&recorded, b"state").is_err());
    // The same digest with another length still differs.
    let longer = CheckpointRecord {
        length: 11,
        ..recorded
    };
    assert_eq!(
        compare_state(&longer, b"state at 2")
            .unwrap_err()
            .recorded_length,
        11
    );
}

/// Not comparable: an unknown checkpoint, one whose bytes differ from its
/// digest, one past the complete prefix or in a middle range, and a
/// snapshot buffer too short.
#[test]
fn a_corrupt_or_unknown_checkpoint_is_not_comparable() {
    let recorded = Recorded::new(
        Capture::Strict,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Checkpoint(1, b"state at 1"),
        ],
    );
    assert!(matches!(
        recorded.replay_from_checkpoint(9),
        Err(ReplayError::UnknownCheckpoint { checkpoint_id: 9 })
    ));
    let mut store = recorded.store();
    let recovery = recorded.recovery(&store);
    let mut short = [0u8; 4];
    assert!(matches!(
        ReplayCursor::open_at_checkpoint(
            recorded.journal(),
            &recovery,
            &mut store,
            1,
            &replay_config(),
            ROOM,
            &mut short,
        ),
        Err(ReplayError::SnapshotTooSmall {
            length: 10,
            capacity: 4
        })
    ));
    // A record whose digest is not its bytes'.
    let corrupt = Recorded::new(
        Capture::Strict,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Checkpoint(1, b"state at 1"),
            Write::Records(event(2, EndOutcome::Complete)),
            Write::Records(encode(&GroupRecord::Checkpoint(CheckpointRecord {
                group_seq: 2,
                checkpoint_id: 2,
                position: 0,
                length: 10,
                crc32c: crc32c(b"state at 2"),
                format: 7,
            }))),
        ],
    );
    assert!(matches!(
        corrupt.replay_from_checkpoint(2),
        Err(ReplayError::CheckpointCorrupt { checkpoint_id: 2 })
    ));
    // A record whose bytes the store never got: recovery marks them lost.
    let lost = Recorded::new(
        Capture::Strict,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(encode(&GroupRecord::Checkpoint(CheckpointRecord {
                group_seq: 1,
                checkpoint_id: 1,
                position: 0,
                length: 10,
                crc32c: crc32c(b"state at 1"),
                format: 7,
            }))),
        ],
    );
    assert!(matches!(
        lost.replay_from_checkpoint(1),
        Err(ReplayError::CheckpointCorrupt { checkpoint_id: 1 })
    ));
    // Lost before too small: not comparable, whatever the buffer.
    let mut store = lost.store();
    let recovery = lost.recovery(&store);
    assert!(matches!(
        ReplayCursor::open_at_checkpoint(
            lost.journal(),
            &recovery,
            &mut store,
            1,
            &replay_config(),
            ROOM,
            &mut [0u8; 2],
        ),
        Err(ReplayError::CheckpointCorrupt { checkpoint_id: 1 })
    ));
    // In best effort: range 2 (from checkpoint 1) ends at the incomplete
    // event 3, and checkpoint 2 opens range 3: range 2 is a middle range.
    let ranges = Recorded::new(
        Capture::BestEffort,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(gap(2, 2)),
            Write::Checkpoint(2, b"state at 2"),
            Write::Records(event(3, EndOutcome::Incomplete)),
            Write::Checkpoint(3, b"state at 3"),
            Write::Records(event(4, EndOutcome::Complete)),
        ],
    );
    assert!(matches!(
        ranges.replay_from_checkpoint(1),
        Err(ReplayError::NotInPrefix { checkpoint_id: 1 })
    ));
    let (_, last) = ranges.replay_from_checkpoint(2).unwrap();
    assert_eq!(
        kinds(&last),
        ["e4", "EndOfPrefix { complete_recording_seq: 4 }"]
    );
}

/// In best effort, the range after a gap replays from its checkpoint, up
/// to its end; replay from the start stops at the gap, and gives none of
/// that range's checkpoints.
#[test]
fn the_range_after_a_gap_replays_from_its_checkpoint() {
    let recorded = Recorded::new(
        Capture::BestEffort,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(gap(2, 2)),
            Write::Checkpoint(2, b"state at 2"),
            Write::Records(event(3, EndOutcome::Complete)),
            Write::Checkpoint(3, b"state at 3"),
            Write::Records(event(4, EndOutcome::Complete)),
        ],
    );
    let from_start = recorded.replay_from_start();
    assert_eq!(kinds(&from_start)[..1], ["e1"]);
    assert!(matches!(
        from_start.last(),
        Some(Seen::Stop(Stop::Gap(GapMarker { from_seq: 2, .. })))
    ));
    let (snapshot, range) = recorded.replay_from_checkpoint(1).unwrap();
    assert_eq!(snapshot, b"state at 2");
    assert_eq!(
        kinds(&range),
        [
            "e3",
            "c3#2",
            "e4",
            "EndOfPrefix { complete_recording_seq: 4 }"
        ]
    );
    let (_, later) = recorded.replay_from_checkpoint(2).unwrap();
    assert_eq!(&range[2..], &later[..]);
}

/// #422 review P1, probe A: a checkpoint opens a range whose record lags
/// an incomplete event; replay from it stops there, giving that event
/// marked incomplete, never as a complete one.
#[test]
fn replay_from_a_checkpoint_stops_at_the_range_end_before_its_record() {
    let recorded = Recorded::new(
        Capture::BestEffort,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(gap(2, 2)),
            Write::Records(event(3, EndOutcome::Complete)),
            Write::Records(event(4, EndOutcome::Incomplete)),
            Write::Checkpoint(3, b"state at 3"),
        ],
    );
    let store = recorded.store();
    let recovery = recorded.recovery(&store);
    let mut store = store;
    let mut snapshot = vec![0u8; 64];
    let (mut cursor, _) = ReplayCursor::open_at_checkpoint(
        recorded.journal(),
        &recovery,
        &mut store,
        1,
        &replay_config(),
        ROOM,
        &mut snapshot,
    )
    .unwrap();
    match cursor.step().unwrap() {
        Step::Event(event) => assert_eq!((event.group_seq(), event.incomplete()), (4, true)),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        cursor.step().unwrap(),
        Step::Stop(Stop::Incomplete { group_seq: 4 })
    ));
}

/// #422 review P1, probe E: an event past the range's complete prefix
/// that waits on its payload (its recording never covers it), before the
/// checkpoint's record: replay from the checkpoint ends before it.
#[test]
fn replay_from_a_checkpoint_never_gives_an_event_past_its_prefix() {
    use crate::group::record::{MessageEvent, Payload};

    let mut waiting = encode(&GroupRecord::Message(MessageEvent {
        group_seq: 4,
        logical_time: 4,
        incarnation: 1,
        position: 0,
        extent: 64,
        stream_id: 1,
        session_id: 1,
        lane: karyos_sys::frame::Lane::ZERO,
        reserved_value: 0,
        end_of_stream: false,
        extension: None,
        payload: Payload::Reference {
            recording_id: 7,
            length: 10,
        },
    }));
    waiting.extend(encode(&GroupRecord::End(EventEnd {
        group_seq: 4,
        observations: 0,
        outcome: EndOutcome::Complete,
    })));
    let recorded = Recorded::new(
        Capture::BestEffort,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(gap(2, 2)),
            Write::Records(event(3, EndOutcome::Complete)),
            Write::Records(waiting),
            Write::Checkpoint(3, b"state at 3"),
        ],
    );
    let (_, from) = recorded.replay_from_checkpoint(1).unwrap();
    assert_eq!(kinds(&from), ["EndOfPrefix { complete_recording_seq: 3 }"]);
}

/// #422 review P2 (mutants e2, m): a checkpoint of the first range,
/// replayed after a later range opened, replays the first range up to
/// its stop.
#[test]
fn a_first_range_checkpoint_replays_that_range_after_another_opened() {
    let recorded = Recorded::new(
        Capture::BestEffort,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Checkpoint(1, b"state at 1"),
            Write::Records(event(2, EndOutcome::Complete)),
            Write::Records(gap(3, 3)),
            Write::Checkpoint(3, b"state at 3"),
            Write::Records(event(4, EndOutcome::Complete)),
        ],
    );
    let (snapshot, first) = recorded.replay_from_checkpoint(1).unwrap();
    assert_eq!(snapshot, b"state at 1");
    assert_eq!(kinds(&first)[..1], ["e2"]);
    assert!(matches!(
        first.last(),
        Some(Seen::Stop(Stop::Gap(GapMarker { from_seq: 3, .. })))
    ));
    let (_, later) = recorded.replay_from_checkpoint(2).unwrap();
    assert_eq!(
        kinds(&later),
        ["e4", "EndOfPrefix { complete_recording_seq: 4 }"]
    );
}

/// #422 review P2 (mutant e3): the current range stops at a later gap;
/// replay from its checkpoint stops there.
#[test]
fn replay_from_the_current_range_stops_at_its_gap() {
    let recorded = Recorded::new(
        Capture::BestEffort,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(gap(2, 2)),
            Write::Checkpoint(2, b"state at 2"),
            Write::Records(event(3, EndOutcome::Complete)),
            Write::Records(gap(4, 4)),
            Write::Records(event(5, EndOutcome::Complete)),
        ],
    );
    let (_, range) = recorded.replay_from_checkpoint(1).unwrap();
    assert_eq!(kinds(&range)[..1], ["e3"]);
    assert!(matches!(
        range.last(),
        Some(Seen::Stop(Stop::Gap(GapMarker { from_seq: 4, .. })))
    ));
}

/// #422 re-check P3: an event past the range's prefix is never read, so
/// one larger than the cursor's buffer (5 records, the room 4), whose
/// payload waits on a recording that never covers it, still gives the
/// stop, not a buffer error.
#[test]
fn an_oversized_event_past_the_prefix_gives_the_stop() {
    use crate::group::record::{MessageEvent, Payload, TimerAction, TimerObservation};

    let mut big = encode(&GroupRecord::Message(MessageEvent {
        group_seq: 4,
        logical_time: 4,
        incarnation: 1,
        position: 0,
        extent: 64,
        stream_id: 1,
        session_id: 1,
        lane: karyos_sys::frame::Lane::ZERO,
        reserved_value: 0,
        end_of_stream: false,
        extension: None,
        payload: Payload::Reference {
            recording_id: 7,
            length: 10,
        },
    }));
    for index in 0..3 {
        big.extend(encode(&GroupRecord::TimerOperation(TimerObservation {
            group_seq: 4,
            index,
            timer_id: 9,
            deadline: 10,
            action: TimerAction::Create,
        })));
    }
    big.extend(encode(&GroupRecord::End(EventEnd {
        group_seq: 4,
        observations: 3,
        outcome: EndOutcome::Complete,
    })));
    let recorded = Recorded::new(
        Capture::BestEffort,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(gap(2, 2)),
            Write::Records(event(3, EndOutcome::Complete)),
            Write::Records(big),
            Write::Checkpoint(3, b"state at 3"),
        ],
    );
    let (_, from) = recorded.replay_from_checkpoint(1).unwrap();
    assert_eq!(kinds(&from), ["EndOfPrefix { complete_recording_seq: 3 }"]);
}

/// #422 re-check P3: a capture from a checkpoint starts after it.
#[test]
fn a_capture_from_a_checkpoint_starts_after_it() {
    let mut capture = CaptureJournal::create_from(
        FaultDisk::default(),
        Path::new("/capture"),
        &header(Capture::Strict),
        b"replay",
        3,
        config(),
    )
    .unwrap();
    // Event 3 is the first; event 1 is refused.
    let records = [
        GroupRecord::Timer(TimerEvent {
            group_seq: 1,
            logical_time: 1,
            timer_id: 1,
        }),
        GroupRecord::Timer(TimerEvent {
            group_seq: 3,
            logical_time: 3,
            timer_id: 3,
        }),
    ];
    assert!(capture.append(&records[0]).is_err());
    let _ = capture.append(&records[1]).unwrap();
}

/// #422 re-check: `step_from` skips the checkpoints of the events it
/// skips, and gives those at or past its start after their events.
#[test]
fn step_from_skips_checkpoints_below_its_start() {
    let recorded = Recorded::new(
        Capture::Strict,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Checkpoint(1, b"state at 1"),
            Write::Records(event(2, EndOutcome::Complete)),
            Write::Records(event(3, EndOutcome::Complete)),
            Write::Checkpoint(3, b"state at 3"),
        ],
    );
    let store = recorded.store();
    let recovery = recorded.recovery(&store);
    let mut cursor =
        ReplayCursor::open(recorded.journal(), &recovery, &replay_config(), ROOM).unwrap();
    let mut seen = Vec::new();
    loop {
        match cursor.step_from(3).unwrap() {
            Step::Event(event) => seen.push(format!("e{}", event.group_seq())),
            Step::Checkpoint(checkpoint) => seen.push(format!("c{}", checkpoint.group_seq)),
            Step::Stop(_) => break,
        }
    }
    assert_eq!(seen, ["e3", "c3"]);
}
