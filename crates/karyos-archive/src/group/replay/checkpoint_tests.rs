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
use crate::group::gateway::{Dispatched, Effects, Event, GatewayError, GroupGateway, Handler};
use crate::group::journal::MIN_SEGMENT_LENGTH;
use crate::group::prefix::{Coverage, recover};
use crate::group::record::{Capture, EventEnd, GapReason, TimerEvent};
use crate::group::replay::gateway::{GatewayConfig, ReplayGateway};
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
        reopen_hold: 0,
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
#[derive(Clone)]
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
        let (recovery, ranges) =
            crate::group::prefix::recover_ranges(&mut self.journal(), &Held(&store), 8).unwrap();
        let mut snapshot = vec![0u8; 4096];
        let (cursor, record) = ReplayCursor::open_at_checkpoint(
            self.journal(),
            &recovery,
            &ranges,
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
    /// A late checkpoint (karyos#1003): its `group_seq` and id.
    Late(u64, u64),
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
            Step::LateCheckpoint(checkpoint) => {
                seen.push(Seen::Late(checkpoint.group_seq, checkpoint.checkpoint_id));
            }
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
            Seen::Late(seq, id) => format!("late c{seq}#{id}"),
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
            &[],
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
            &[],
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
    // A8 middle ranges: range 2 replays from its checkpoint, to its
    // incomplete event.
    let (_, middle) = ranges.replay_from_checkpoint(1).unwrap();
    assert_eq!(kinds(&middle), ["e3", "Incomplete { group_seq: 3 }"]);
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
        &[],
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
            Step::Checkpoint(checkpoint) | Step::LateCheckpoint(checkpoint) => {
                seen.push(format!("c{}", checkpoint.group_seq));
            }
            Step::Stop(_) => break,
        }
    }
    assert_eq!(seen, ["e3", "c3"]);
}

/// A handler that records its restores and counts its events, and accepts a
/// snapshot equal to `accepted`.
struct Restoring {
    accepted: &'static [u8],
    restored: Vec<Vec<u8>>,
    events: u32,
}

impl Handler for Restoring {
    fn on_event(&mut self, _event: &Event<'_>, _effects: &mut dyn Effects) {
        self.events += 1;
    }

    fn restore(&mut self, state: &[u8]) -> bool {
        self.restored.push(state.to_vec());
        state == self.accepted
    }
}

impl Recorded {
    /// A gateway over a cursor opened at checkpoint `id`, its record and
    /// snapshot.
    fn gateway_at(&self, id: u64) -> (ReplayGateway<FaultDisk>, CheckpointRecord, Vec<u8>) {
        let mut store = self.store();
        let recovery = self.recovery(&store);
        let mut snapshot = vec![0u8; 4096];
        let (cursor, record) = ReplayCursor::open_at_checkpoint(
            self.journal(),
            &recovery,
            &[],
            &mut store,
            id,
            &replay_config(),
            ROOM,
            &mut snapshot,
        )
        .unwrap();
        snapshot.truncate(usize::try_from(record.length).unwrap());
        let gateway = ReplayGateway::new(
            cursor,
            &GatewayConfig {
                publications: &[],
                subscriptions: &[],
                network: &[],
                conflated: &[],
                max_claim: 64,
                max_payload: 256,
                present_unavailable: false,
            },
            None,
        )
        .unwrap();
        (gateway, record, snapshot)
    }
}

fn handler() -> Restoring {
    Restoring {
        accepted: b"state at 2",
        restored: Vec::new(),
        events: 0,
    }
}

/// #431: `from_checkpoint` is `open_at_checkpoint` then `restore`: the
/// handler gets the snapshot once, and the first event it sees is the
/// one after the checkpoint. A snapshot it refuses stops replay, not
/// reproducible at the checkpoint.
#[test]
fn replay_from_a_checkpoint_restores_then_dispatches_the_next_event() {
    let recorded = Recorded::new(
        Capture::Strict,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(event(2, EndOutcome::Complete)),
            Write::Checkpoint(2, b"state at 2"),
            Write::Records(event(3, EndOutcome::Complete)),
        ],
    );
    let (mut gateway, record, snapshot) = recorded.gateway_at(1);
    let mut accepting = handler();
    assert_eq!(gateway.restore(&record, &snapshot, &mut accepting), Ok(()));
    assert_eq!(accepting.restored, [b"state at 2".to_vec()]);
    assert_eq!(
        gateway.dispatch(&mut accepting),
        Ok(Dispatched::Event { group_seq: 3 })
    );
    assert_eq!(accepting.events, 1);
    let (mut gateway, record, snapshot) = recorded.gateway_at(1);
    let mut refusing = Restoring {
        accepted: b"another state",
        ..handler()
    };
    let refused = GatewayError::NotReproducible { group_seq: 2 };
    assert_eq!(
        gateway.restore(&record, &snapshot, &mut refusing),
        Err(refused)
    );
    assert_eq!(gateway.dispatch(&mut refusing), Err(refused));
    assert_eq!(refusing.events, 0);
}

/// #431: a restore out of order, or of a snapshot that is not its
/// record's, is refused typed without calling the handler, and stops
/// replay; on a stopped gateway it returns that stop.
#[test]
fn a_restore_out_of_order_or_corrupt_is_refused() {
    let recorded = Recorded::new(
        Capture::Strict,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Checkpoint(1, b"state at 1"),
            Write::Records(event(2, EndOutcome::Complete)),
            Write::Checkpoint(2, b"state at 2"),
            Write::Records(event(3, EndOutcome::Complete)),
        ],
    );
    let order = |group_seq| Err(GatewayError::RestoreOrder { group_seq });
    // After the first dispatch.
    let (mut gateway, record, snapshot) = recorded.gateway_at(2);
    let mut seen = handler();
    assert_eq!(gateway.restore(&record, &snapshot, &mut seen), Ok(()));
    assert!(gateway.dispatch(&mut seen).is_ok());
    assert_eq!(gateway.restore(&record, &snapshot, &mut seen), order(2));
    // A second restore.
    let (mut gateway, record, snapshot) = recorded.gateway_at(2);
    assert_eq!(gateway.restore(&record, &snapshot, &mut seen), Ok(()));
    assert_eq!(gateway.restore(&record, &snapshot, &mut seen), order(2));
    assert_eq!(
        gateway.dispatch(&mut seen),
        Err(GatewayError::RestoreOrder { group_seq: 2 })
    );
    // Another checkpoint than the one the cursor was opened at.
    let (mut gateway, _, _) = recorded.gateway_at(2);
    let (_, first, first_snapshot) = recorded.gateway_at(1);
    assert_eq!(
        gateway.restore(&first, &first_snapshot, &mut seen),
        order(1)
    );
    // A snapshot that is not its record's: another crc32c, then the
    // same bytes under a record of another length.
    let corrupt = Err(GatewayError::CheckpointCorrupt { group_seq: 2 });
    let (mut gateway, record, _) = recorded.gateway_at(2);
    assert_eq!(gateway.restore(&record, b"state at 3", &mut seen), corrupt);
    let (mut gateway, record, _) = recorded.gateway_at(2);
    let longer = CheckpointRecord {
        length: record.length + 1,
        ..record
    };
    assert_eq!(gateway.restore(&longer, &snapshot, &mut seen), corrupt);
    // On a stopped gateway, its stop.
    assert_eq!(gateway.restore(&record, &snapshot, &mut seen), corrupt);
    // Only the two restores in order reached the handler.
    assert_eq!(
        seen.restored,
        [b"state at 2".to_vec(), b"state at 2".to_vec()]
    );
}

/// #431 re-check: a replay opened at a checkpoint never dispatches from
/// the handler's empty state; without a restore its first dispatch is
/// refused and stops replay. A restore after replay ended is refused,
/// that end kept.
#[test]
fn a_replay_opened_at_a_checkpoint_dispatches_only_after_its_restore() {
    let recorded = Recorded::new(
        Capture::Strict,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Checkpoint(1, b"state at 2"),
            Write::Records(event(2, EndOutcome::Complete)),
        ],
    );
    let order = Err(GatewayError::RestoreOrder { group_seq: 1 });
    let (mut gateway, record, snapshot) = recorded.gateway_at(1);
    let mut seen = handler();
    assert_eq!(gateway.dispatch(&mut seen), order);
    assert_eq!(gateway.dispatch(&mut seen), order);
    assert_eq!(seen.events, 0);
    let (mut gateway, record_again, _) = recorded.gateway_at(1);
    assert_eq!(record_again, record);
    assert_eq!(gateway.restore(&record, &snapshot, &mut seen), Ok(()));
    assert_eq!(
        gateway.dispatch(&mut seen),
        Ok(Dispatched::Event { group_seq: 2 })
    );
    let end = gateway.dispatch(&mut seen);
    assert!(matches!(end, Ok(Dispatched::End)), "{end:?}");
    assert_eq!(
        gateway.restore(&record, &snapshot, &mut seen),
        Err(GatewayError::RestoreOrder { group_seq: 1 })
    );
    assert_eq!(gateway.dispatch(&mut seen), end);
}

/// A8 middle ranges (A9 section 6): a best-effort journal of three
/// ranges, two gaps between. Replay from the middle range's checkpoint
/// gives its events and stops at the next gap; from a later checkpoint
/// in that range, the events after it; from the current range's, its
/// own. Without the derived ranges, the middle one is refused.
#[test]
fn a_middle_range_replays_from_its_checkpoint() {
    let recorded = Recorded::new(
        Capture::BestEffort,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(gap(2, 2)),
            Write::Checkpoint(2, b"A"),
            Write::Records(event(3, EndOutcome::Complete)),
            Write::Checkpoint(3, b"A3"),
            Write::Records(event(4, EndOutcome::Complete)),
            Write::Records(gap(5, 5)),
            Write::Checkpoint(5, b"B"),
            Write::Records(event(6, EndOutcome::Complete)),
            Write::Records(event(7, EndOutcome::Complete)),
        ],
    );
    let stop_at = |seen: &[Seen]| match seen.last() {
        Some(Seen::Stop(Stop::Gap(GapMarker { from_seq, .. }))) => Some(*from_seq),
        _ => None,
    };
    let (snapshot, middle) = recorded.replay_from_checkpoint(1).unwrap();
    assert_eq!(snapshot, b"A");
    assert_eq!(kinds(&middle)[..3], ["e3", "c3#2", "e4"]);
    assert_eq!(stop_at(&middle), Some(5), "{:?}", kinds(&middle));
    let (_, later) = recorded.replay_from_checkpoint(2).unwrap();
    assert_eq!(kinds(&later)[..1], ["e4"]);
    assert_eq!(stop_at(&later), Some(5));
    let (_, current) = recorded.replay_from_checkpoint(3).unwrap();
    assert_eq!(
        kinds(&current),
        ["e6", "e7", "EndOfPrefix { complete_recording_seq: 7 }"]
    );
    // Without the derived ranges, the middle range is not replayable.
    let mut store = recorded.store();
    let recovery = recorded.recovery(&store);
    let mut snapshot = vec![0u8; 64];
    assert!(matches!(
        ReplayCursor::open_at_checkpoint(
            recorded.journal(),
            &recovery,
            &[],
            &mut store,
            1,
            &replay_config(),
            ROOM,
            &mut snapshot,
        ),
        Err(ReplayError::NotInPrefix { checkpoint_id: 1 })
    ));
}

/// A middle range whose complete prefix ends at its opening checkpoint:
/// the next gap comes right after it. Replay from it gives no event.
#[test]
fn an_empty_middle_range_replays_nothing() {
    let recorded = Recorded::new(
        Capture::BestEffort,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(gap(2, 2)),
            Write::Checkpoint(2, b"A"),
            Write::Records(gap(3, 3)),
            Write::Checkpoint(3, b"B"),
            Write::Records(event(4, EndOutcome::Complete)),
        ],
    );
    let (_, middle) = recorded.replay_from_checkpoint(1).unwrap();
    assert!(
        matches!(
            middle[..],
            [Seen::Stop(Stop::Gap(GapMarker { from_seq: 3, .. }))]
        ),
        "{:?}",
        kinds(&middle)
    );
}

/// Several middle ranges: each replays its own event from its own
/// checkpoint, none off by one.
#[test]
fn several_middle_ranges_each_replay_their_own() {
    let mut writes = vec![Write::Records(event(1, EndOutcome::Complete))];
    // Ranges opened at 2, 4, 6, 8: each holds one event, then a gap.
    for opener in [2u64, 4, 6, 8] {
        writes.push(Write::Records(gap(opener, opener)));
        writes.push(Write::Checkpoint(opener, b"s"));
        writes.push(Write::Records(event(opener + 1, EndOutcome::Complete)));
    }
    let recorded = Recorded::new(Capture::BestEffort, &writes);
    for (id, opener) in [(1u64, 2u64), (2, 4), (3, 6)] {
        let (_, seen) = recorded.replay_from_checkpoint(id).unwrap();
        let events: Vec<_> = kinds(&seen)
            .into_iter()
            .filter(|kind| kind.starts_with('e') && !kind.starts_with("End"))
            .collect();
        assert_eq!(events, [format!("e{}", opener + 1)], "checkpoint {id}");
        assert!(
            matches!(seen.last(), Some(Seen::Stop(Stop::Gap(GapMarker { from_seq, .. }))) if *from_seq == opener + 2),
            "checkpoint {id}: {:?}",
            kinds(&seen)
        );
    }
    let (_, last) = recorded.replay_from_checkpoint(4).unwrap();
    assert_eq!(
        kinds(&last),
        ["e9", "EndOfPrefix { complete_recording_seq: 9 }"]
    );
}

/// A8 middle ranges, #437 decision (1): recovery advances after each
/// checkpoint record, as the run's job advances between records. A
/// checkpoint B recorded after a gap while A is still pending: the run
/// opens A's range before B takes over, and so does recovery. A tracker
/// fed record by record, advancing after each (the run), and recovery
/// agree on the current range, and recovery derives A's range.
#[test]
fn recovery_opens_a_range_as_the_run_does() {
    use crate::group::prefix::{PrefixTracker, recover_ranges};

    let recorded = Recorded::new(
        Capture::BestEffort,
        &[
            Write::Records(event(1, EndOutcome::Complete)),
            Write::Records(gap(2, 2)),
            Write::Checkpoint(2, b"A"),
            Write::Records(gap(3, 3)),
            Write::Checkpoint(3, b"B"),
            Write::Records(event(4, EndOutcome::Complete)),
        ],
    );
    let store = recorded.store();
    // The run: every record, then an advance.
    let mut run = PrefixTracker::new(8);
    let mut journal = recorded.journal();
    let written = journal.written();
    journal
        .walk(0, |_, end, record| {
            run.record(record, end).unwrap();
            let _ = run.advance(end, end, &Held(&store));
            true
        })
        .unwrap();
    let _ = run.advance(written, written, &Held(&store));
    let (recovery, ranges) = recover_ranges(&mut recorded.journal(), &Held(&store), 8).unwrap();
    assert_eq!(recovery.tracker.range(), run.range());
    assert_eq!(
        ranges
            .iter()
            .map(|range| range.start.group_seq)
            .collect::<Vec<_>>(),
        [2],
        "A's range, between the two stops"
    );
}

/// karyos#881 review P2: a cursor opened at a checkpoint keeps its range
/// when it follows a later state of the journal in which a gap closed that
/// range and another opened: it stops at the gap, as replay from the same
/// checkpoint of the later journal does, never past it.
#[test]
fn following_from_a_checkpoint_keeps_its_range_across_a_gap() {
    let early = [
        Write::Records(event(1, EndOutcome::Complete)),
        Write::Checkpoint(1, b"state at 1"),
        Write::Records(event(2, EndOutcome::Complete)),
    ];
    let before = Recorded::new(Capture::BestEffort, &early);
    let mut later_writes = early.to_vec();
    later_writes.extend([
        Write::Records(gap(3, 3)),
        Write::Checkpoint(3, b"state at 3"),
        Write::Records(event(4, EndOutcome::Complete)),
    ]);
    let after = Recorded::new(Capture::BestEffort, &later_writes);

    let mut store = before.store();
    let (recovery, ranges) =
        crate::group::prefix::recover_ranges(&mut before.journal(), &Held(&store), 8).unwrap();
    let mut snapshot = vec![0u8; 4096];
    let (mut cursor, _) = ReplayCursor::open_at_checkpoint(
        before.journal(),
        &recovery,
        &ranges,
        &mut store,
        1,
        &replay_config(),
        ROOM,
        &mut snapshot,
    )
    .unwrap();
    // Before its first stop, the cursor follows the later journal.
    let later_store = after.store();
    let later = after.recovery(&later_store);
    cursor
        .follow(after.journal(), &later, &replay_config())
        .unwrap();
    let (_, expected) = after.replay_from_checkpoint(1).unwrap();
    assert_eq!(steps(cursor), expected);
    assert!(matches!(
        expected.last(),
        Some(Seen::Stop(Stop::Gap(GapMarker { from_seq: 3, .. })))
    ));
}

/// karyos#1003: a writer records a checkpoint for event 2 after event 3,
/// once a follower gave event 3. The prefix does not advance, but
/// `Recovery::checkpoints` does, so a poll sees it; the follow gives it
/// marked late, before event 4, where a closed replay gives it right
/// after event 2.
#[test]
fn a_late_checkpoint_is_discovered_by_a_poll_and_given_marked_late() {
    let early = [
        Write::Records(event(1, EndOutcome::Complete)),
        Write::Records(event(2, EndOutcome::Complete)),
        Write::Records(event(3, EndOutcome::Complete)),
    ];
    let before = Recorded::new(Capture::BestEffort, &early);
    let store = before.store();
    let first = before.recovery(&store);
    let mut cursor = ReplayCursor::open(before.journal(), &first, &replay_config(), ROOM).unwrap();
    let mut given = Vec::new();
    loop {
        match cursor.step().unwrap() {
            Step::Event(event) => given.push(event.group_seq()),
            Step::Stop(Stop::EndOfPrefix { .. }) => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(given, [1, 2, 3]);

    let mut with_late = early.to_vec();
    with_late.push(Write::Checkpoint(2, b"state at 2"));
    let late = Recorded::new(Capture::BestEffort, &with_late);
    let late_store = late.store();
    let poll = late.recovery(&late_store);
    // The poll: the prefix did not advance, the checkpoints did.
    assert_eq!(
        poll.tracker.complete_recording_seq(),
        first.tracker.complete_recording_seq()
    );
    assert_eq!((first.checkpoints, poll.checkpoints), (0, 1));
    cursor
        .follow(late.journal(), &poll, &replay_config())
        .unwrap();
    // Never due for the event just given: the step gives it, marked.
    assert_eq!(cursor.due_checkpoint().unwrap(), None);
    let seen = kinds(&steps(cursor));
    assert_eq!(
        seen.first().map(String::as_str),
        Some("late c2#1"),
        "{seen:?}"
    );
    assert_eq!(seen.len(), 2, "{seen:?}");
    // The closed replay gives it in place.
    let closed = kinds(&late.replay_from_start());
    assert_eq!(&closed[..3], ["e1", "e2", "c2#1"], "{closed:?}");
}

/// A checkpoint for the last event given, found by a follow, is not late:
/// it comes where a closed replay gives it.
#[test]
fn a_checkpoint_for_the_last_event_given_is_not_late() {
    let early = [
        Write::Records(event(1, EndOutcome::Complete)),
        Write::Records(event(2, EndOutcome::Complete)),
    ];
    let before = Recorded::new(Capture::BestEffort, &early);
    let store = before.store();
    let first = before.recovery(&store);
    let mut cursor = ReplayCursor::open(before.journal(), &first, &replay_config(), ROOM).unwrap();
    while !matches!(cursor.step().unwrap(), Step::Stop(_)) {}
    let mut with = early.to_vec();
    with.push(Write::Checkpoint(2, b"state at 2"));
    let later = Recorded::new(Capture::BestEffort, &with);
    let later_store = later.store();
    let poll = later.recovery(&later_store);
    cursor
        .follow(later.journal(), &poll, &replay_config())
        .unwrap();
    let seen = kinds(&steps(cursor));
    assert_eq!(seen.first().map(String::as_str), Some("c2#1"), "{seen:?}");
}
