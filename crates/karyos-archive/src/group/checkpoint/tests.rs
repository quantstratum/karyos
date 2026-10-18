// SPDX-License-Identifier: Apache-2.0

// Checkpoints (A9-1): a checkpoint is written, then recorded, and read
// back exactly; the handoff's refusals are typed and counted, with nothing
// recorded; a failed write leaves no record and its retry may name the
// same event; the range a checkpoint opens past a stop, in the tracker;
// and the crash gate: at every crash point the journal and the store
// recover consistent, every recorded checkpoint either reads back exactly
// or reads as lost, and the next checkpoint goes on.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::cell::Cell;
use std::path::Path;

use super::*;
use crate::fault::{FaultDisk, Survives};
use crate::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use crate::group::order::OrderRule;
use crate::group::prefix::{CheckpointHeld, Coverage, DurableFor, PrefixTracker, RangeStart};
use crate::group::record::{
    Capture, Clock, EndOutcome, EventEnd, GapMarker, GapReason, JournalHeader, MAX_RECORD,
    TimerEvent,
};
use crate::segment::SyncPolicy;

const JOURNALS: &str = "/groups";

thread_local! {
    /// The chunk the tests' checkpoints are written in, or whole.
    static CHUNK: Cell<Option<usize>> = const { Cell::new(None) };
}
const CHECKPOINTS: &str = "/checkpoints";
const GROUP: u64 = 9;

fn config(policy: SyncPolicy) -> JournalConfig {
    JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy,
    }
}

fn header(capture: Capture) -> JournalHeader<'static> {
    JournalHeader {
        group_id: GROUP,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture,
        manifest: b"m",
    }
}

fn encode(record: &GroupRecord<'_>) -> Vec<u8> {
    let mut out = vec![0u8; MAX_RECORD];
    let length = record.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

/// Event `seq`: a timer and its end.
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

/// A snapshot of `length` bytes, distinct per `seed`.
fn snapshot(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| seed.wrapping_add(u8::try_from(i % 251).unwrap()))
        .collect()
}

struct Group {
    journal: GroupJournal<FaultDisk>,
    writer: CheckpointWriter<FaultDisk>,
    slot: CheckpointSlot,
}

impl Group {
    fn create(disk: &FaultDisk, capture: Capture, max: usize) -> Self {
        let journal = GroupJournal::create(
            disk.clone(),
            Path::new(JOURNALS),
            &header(capture),
            config(SyncPolicy::PerSegment),
        )
        .unwrap();
        let store = CheckpointStore::create(
            disk.clone(),
            Path::new(CHECKPOINTS),
            GROUP,
            config(SyncPolicy::PerSegment),
        )
        .unwrap();
        let writer = CheckpointWriter::new(store, &journal).unwrap();
        Self {
            journal,
            writer,
            slot: CheckpointSlot::new(max),
        }
    }

    /// Takes and writes a checkpoint of `bytes` after event `seq`: whole,
    /// or in chunks of [`CHUNK`] bytes when set.
    fn checkpoint(&mut self, seq: u64, bytes: &[u8]) -> Result<CheckpointRecord, CheckpointError> {
        let request = self.slot.take(seq, 7, |buffer| {
            buffer[..bytes.len()].copy_from_slice(bytes);
            bytes.len()
        })?;
        let result = match CHUNK.get() {
            None => self.writer.write(&mut self.journal, &request),
            Some(chunk) => self.chunked(&request, chunk),
        };
        self.slot.returned(request, &result);
        result
    }

    fn chunked(
        &mut self,
        request: &CheckpointRequest,
        chunk: usize,
    ) -> Result<CheckpointRecord, CheckpointError> {
        self.writer.begin(&self.journal, request)?;
        loop {
            match self.writer.advance(&mut self.journal, request, chunk)? {
                Progress::Writing { .. } => {}
                Progress::Recorded(record) => return Ok(record),
            }
        }
    }

    fn records(&mut self) -> Vec<CheckpointRecord> {
        let mut found = Vec::new();
        let _ = self
            .journal
            .walk(0, |_, _, record| {
                if let GroupRecord::Checkpoint(checkpoint) = record {
                    found.push(*checkpoint);
                }
                true
            })
            .unwrap();
        found
    }
}

fn read(store: &mut CheckpointStore<FaultDisk>, record: &CheckpointRecord) -> Vec<u8> {
    let mut bytes = vec![0u8; usize::try_from(record.length).unwrap()];
    store.read(record.position, &mut bytes).unwrap();
    bytes
}

/// A checkpoint between events is written, then recorded after the
/// events already appended, and its bytes read back exactly, also after a
/// close and recovery; ids increase, positions follow each other.
#[test]
fn a_checkpoint_is_written_then_recorded_and_read_back() {
    let disk = FaultDisk::default();
    let mut group = Group::create(&disk, Capture::Strict, 300_000);
    let _ = group
        .journal
        .append(&event(1, EndOutcome::Complete))
        .unwrap();
    let first = snapshot(1, 1000);
    let record = group.checkpoint(1, &first).unwrap();
    assert_eq!(
        (record.group_seq, record.checkpoint_id, record.position),
        (1, 1, 0)
    );
    assert_eq!(record.crc32c, crc32c(&first));
    let _ = group
        .journal
        .append(&event(2, EndOutcome::Complete))
        .unwrap();
    // Across segments.
    let second = snapshot(2, 200_000);
    let record = group.checkpoint(2, &second).unwrap();
    assert_eq!((record.checkpoint_id, record.position), (2, 1000));
    let records = group.records();
    assert_eq!(records.len(), 2);
    assert_eq!(read(group.writer.store_mut(), &records[0]), first);
    assert_eq!(read(group.writer.store_mut(), &records[1]), second);
    assert_eq!(
        group.slot.last_checkpoint(),
        Some(LastCheckpoint::Recorded(records[1]))
    );
    assert_eq!(
        (group.slot.stats().taken, group.slot.stats().recorded),
        (2, 2)
    );
    let Group {
        journal, writer, ..
    } = group;
    let _ = journal.close().unwrap();
    let _ = writer.store.close().unwrap();
    let mut journal = GroupJournal::recover(
        disk.after_crash(Survives::Synced),
        Path::new(JOURNALS),
        GROUP,
        config(SyncPolicy::PerSegment),
    )
    .unwrap()
    .journal;
    let end = recorded_end(&mut journal).unwrap();
    assert_eq!(end, 201_000);
    let mut store = CheckpointStore::recover(
        disk.after_crash(Survives::Synced),
        Path::new(CHECKPOINTS),
        GROUP,
        config(SyncPolicy::PerSegment),
        end,
    )
    .unwrap();
    assert_eq!(read(&mut store, &records[1]), second);
    let mut writer = CheckpointWriter::new(store, &journal).unwrap();
    let request = CheckpointSlot::new(16).take(2, 7, |b| {
        b[0] = 1;
        1
    });
    // Not above the last recorded checkpoint: refused, nothing written.
    assert!(matches!(
        writer.write(&mut journal, &request.unwrap()),
        Err(CheckpointError::Order(OrderError {
            rule: OrderRule::Checkpoint,
            ..
        }))
    ));
    assert_eq!(writer.store().written(), 201_000);
}

/// The handoff's refusals: one in flight, one over `max_checkpoint`, an
/// empty one, and any after a strict journal's end, each typed, counted,
/// with the buffer kept and nothing recorded.
#[test]
fn the_handoff_refuses_in_flight_too_large_and_ended() {
    let disk = FaultDisk::default();
    let mut group = Group::create(&disk, Capture::Strict, 64);
    let _ = group
        .journal
        .append(&event(1, EndOutcome::Complete))
        .unwrap();
    let away = group.slot.take(1, 7, |_| 8).unwrap();
    assert!(matches!(
        group.slot.take(1, 7, |_| 8),
        Err(CheckpointError::InFlight)
    ));
    let result = group.writer.write(&mut group.journal, &away);
    group.slot.returned(away, &result);
    assert!(matches!(
        group.slot.take(1, 7, |_| 65),
        Err(CheckpointError::TooLarge {
            length: 65,
            max: 64
        })
    ));
    assert!(matches!(
        group.slot.take(1, 7, |_| 0),
        Err(CheckpointError::Empty)
    ));
    // A strict journal ends at an incomplete event: the order rules refuse
    // a checkpoint after it, and so does the slot once told.
    let _ = group
        .journal
        .append(&event(2, EndOutcome::Incomplete))
        .unwrap();
    let late = group.slot.take(2, 7, |_| 8).unwrap();
    let result = group.writer.write(&mut group.journal, &late);
    assert!(matches!(
        result,
        Err(CheckpointError::Order(OrderError {
            rule: OrderRule::AfterIncomplete,
            ..
        }))
    ));
    group.slot.returned(late, &result);
    group.slot.end();
    assert!(matches!(
        group.slot.take(2, 7, |_| 8),
        Err(CheckpointError::Ended)
    ));
    let stats = group.slot.stats();
    assert_eq!(
        (
            stats.in_flight,
            stats.too_large,
            stats.ended,
            stats.recorded,
            stats.failed
        ),
        (1, 2, 1, 1, 1)
    );
    assert_eq!(group.records().len(), 1);
}

/// A failed write is reported, with no record, and writes nothing; a
/// retry may name the same `group_seq`. A checkpoint naming an event not
/// ended, or inside one, is refused the same way.
#[test]
fn a_failed_write_leaves_no_record_and_may_be_retried() {
    let disk = FaultDisk::default();
    let mut group = Group::create(&disk, Capture::Strict, 64);
    let _ = group
        .journal
        .append(&event(1, EndOutcome::Complete))
        .unwrap();
    assert!(matches!(
        group.checkpoint(2, b"state"),
        Err(CheckpointError::Order(OrderError {
            rule: OrderRule::Checkpoint,
            ..
        }))
    ));
    assert_eq!(
        group.slot.last_checkpoint(),
        Some(LastCheckpoint::Failed { group_seq: 2 })
    );
    // Inside event 2.
    let _ = group
        .journal
        .append(&encode(&GroupRecord::Timer(TimerEvent {
            group_seq: 2,
            logical_time: 2,
            timer_id: 2,
        })))
        .unwrap();
    assert!(matches!(
        group.checkpoint(1, b"state"),
        Err(CheckpointError::Order(OrderError {
            rule: OrderRule::Nested,
            ..
        }))
    ));
    assert_eq!(group.writer.store().written(), 0);
    assert!(group.records().is_empty());
    let _ = group
        .journal
        .append(&encode(&GroupRecord::End(EventEnd {
            group_seq: 2,
            observations: 0,
            outcome: EndOutcome::Complete,
        })))
        .unwrap();
    // The retry names the same event.
    let record = group.checkpoint(2, b"state").unwrap();
    assert_eq!((record.group_seq, record.checkpoint_id), (2, 1));
    assert_eq!(group.slot.stats().failed, 2);
}

/// The checkpoint store's holdings, set by the test.
#[derive(Default)]
struct Store {
    written: Cell<u64>,
    durable: Cell<u64>,
    /// Ranges starting here are lost.
    lost: Cell<Option<u64>>,
}

impl Coverage for Store {
    fn positions(&self, _recording_id: u64) -> Option<(u64, u64)> {
        None
    }

    fn ended(&self, _recording_id: u64) -> Option<u64> {
        None
    }

    fn checkpoint(&self, position: u64, end: u64) -> CheckpointHeld {
        if self.lost.get() == Some(position) {
            CheckpointHeld::Lost
        } else if end > self.written.get() {
            CheckpointHeld::Missing
        } else if end <= self.durable.get() {
            CheckpointHeld::Durable
        } else {
            CheckpointHeld::Written
        }
    }
}

/// Feeds `bytes`, whole records, to `tracker`; returns the journal end.
fn feed(tracker: &mut PrefixTracker, bytes: &[u8], mut at: u64) -> u64 {
    let mut offset = 0;
    while offset < bytes.len() {
        let length = usize::try_from(
            karyos_codec::Envelope::read(&bytes[offset..])
                .unwrap()
                .message_length,
        )
        .unwrap();
        let record = GroupRecord::decode(&bytes[offset..offset + length]).unwrap();
        at += u64::try_from(length).unwrap();
        tracker.record(&record, at).unwrap();
        offset += length;
    }
    at
}

fn checkpoint_record(seq: u64, id: u64, position: u64) -> Vec<u8> {
    encode(&GroupRecord::Checkpoint(CheckpointRecord {
        group_seq: seq,
        checkpoint_id: id,
        position,
        length: 100,
        crc32c: 0,
        format: 7,
    }))
}

/// In best effort, a gap stops the prefixes and a checkpoint after it
/// opens a new range. The record lags the write: events after its
/// `group_seq` come before it, and the range's prefixes start only at the
/// record, complete once it is written and the store holds the bytes,
/// durable once both are durable. The tracker reports the range.
#[test]
fn a_checkpoint_after_a_gap_opens_a_range_at_its_record() {
    let mut tracker = PrefixTracker::new(8);
    let store = Store::default();
    let mut at = feed(
        &mut tracker,
        &encode(&GroupRecord::Header(header(Capture::BestEffort))),
        0,
    );
    at = feed(&mut tracker, &event(1, EndOutcome::Complete), at);
    at = feed(&mut tracker, &gap(2, 2), at);
    at = feed(&mut tracker, &event(3, EndOutcome::Complete), at);
    at = feed(&mut tracker, &event(4, EndOutcome::Complete), at);
    assert_eq!(tracker.advance(at, at, &store), (1, 1));
    assert!(tracker.stopped());
    // The bytes of checkpoint 1 at event 2 are written; its record is not:
    // the written events 3 and 4 do not count.
    store.written.set(100);
    assert_eq!(tracker.advance(at, at, &store), (1, 1));
    at = feed(&mut tracker, &checkpoint_record(2, 1, 0), at);
    assert_eq!(tracker.advance(at, at, &store), (4, 1));
    assert_eq!(
        tracker.range().start,
        Some(RangeStart {
            checkpoint_id: 1,
            group_seq: 2
        })
    );
    assert!(!tracker.stopped());
    store.durable.set(100);
    assert_eq!(tracker.advance(at, at, &store), (4, 4));
    at = feed(&mut tracker, &event(5, EndOutcome::Complete), at);
    assert_eq!(tracker.advance(at, at, &store), (5, 5));
    let range = tracker.range();
    assert_eq!((range.complete, range.durable), (5, 5));
}

/// A checkpoint inside a range, even one whose bytes the store does not
/// hold, holds back neither prefix and opens nothing; a checkpoint below
/// the stop is inside the stopped range.
#[test]
fn a_checkpoint_inside_a_range_holds_back_nothing() {
    let mut tracker = PrefixTracker::new(8);
    let store = Store::default();
    let mut at = feed(
        &mut tracker,
        &encode(&GroupRecord::Header(header(Capture::BestEffort))),
        0,
    );
    at = feed(&mut tracker, &event(1, EndOutcome::Complete), at);
    at = feed(&mut tracker, &checkpoint_record(1, 1, 0), at);
    at = feed(&mut tracker, &event(2, EndOutcome::Complete), at);
    assert_eq!(tracker.advance(at, at, &store), (2, 2));
    assert_eq!(tracker.range().start, None);
    at = feed(&mut tracker, &gap(3, 4), at);
    at = feed(&mut tracker, &checkpoint_record(2, 2, 100), at);
    at = feed(&mut tracker, &event(5, EndOutcome::Complete), at);
    store.written.set(200);
    store.durable.set(200);
    assert_eq!(tracker.advance(at, at, &store), (2, 2));
    assert!(tracker.stopped());
    assert_eq!(tracker.range().start, None);
}

/// A range a checkpoint opens ends at the next stop, and a later
/// checkpoint opens the next; one whose bytes the store lost never opens
/// its range's prefixes.
#[test]
fn ranges_follow_each_other_and_a_lost_checkpoint_opens_nothing() {
    let mut tracker = PrefixTracker::new(8);
    let store = Store::default();
    let mut at = feed(
        &mut tracker,
        &encode(&GroupRecord::Header(header(Capture::BestEffort))),
        0,
    );
    at = feed(&mut tracker, &gap(1, 1), at);
    at = feed(&mut tracker, &event(2, EndOutcome::Complete), at);
    at = feed(&mut tracker, &event(3, EndOutcome::Incomplete), at);
    at = feed(&mut tracker, &event(4, EndOutcome::Complete), at);
    // Checkpoint 1 at event 1: its range holds event 2, then stops at 3.
    at = feed(&mut tracker, &checkpoint_record(1, 1, 0), at);
    store.written.set(100);
    store.durable.set(100);
    assert_eq!(tracker.advance(at, at, &store), (2, 2));
    assert!(tracker.stopped());
    // Checkpoint 2 at event 3: until the store answers for its bytes it
    // opens nothing; lost, it never does.
    at = feed(&mut tracker, &checkpoint_record(3, 2, 100), at);
    assert_eq!(tracker.advance(at, at, &store), (2, 2));
    assert_eq!(tracker.range().start.unwrap().checkpoint_id, 1);
    store.lost.set(Some(100));
    assert_eq!(tracker.advance(at, at, &store), (2, 2));
    assert_eq!(tracker.range().start.unwrap().checkpoint_id, 1);
    assert!(tracker.stopped());
    // Checkpoint 3 at event 4 opens the range.
    at = feed(&mut tracker, &checkpoint_record(4, 3, 200), at);
    store.written.set(300);
    store.durable.set(300);
    assert_eq!(tracker.advance(at, at, &store), (4, 4));
    assert_eq!(tracker.range().start.unwrap().checkpoint_id, 3);
}

/// The workload of the crash gate: events, a checkpoint across segments,
/// another; returns the checkpoints recorded, as reported.
fn run(disk: &FaultDisk, snapshots: &[Vec<u8>]) -> bool {
    let Ok(journal) = GroupJournal::create(
        disk.clone(),
        Path::new(JOURNALS),
        &header(Capture::Strict),
        config(SyncPolicy::PerSegment),
    ) else {
        return false;
    };
    let Ok(store) = CheckpointStore::create(
        disk.clone(),
        Path::new(CHECKPOINTS),
        GROUP,
        config(SyncPolicy::PerSegment),
    ) else {
        return true;
    };
    let mut group = Group {
        writer: CheckpointWriter::new(store, &journal).unwrap(),
        journal,
        slot: CheckpointSlot::new(300_000),
    };
    for (index, bytes) in snapshots.iter().enumerate() {
        let seq = u64::try_from(index).unwrap() + 1;
        if group
            .journal
            .append(&event(seq, EndOutcome::Complete))
            .is_err()
            || group.checkpoint(seq, bytes).is_err()
        {
            return true;
        }
    }
    let Group {
        journal, writer, ..
    } = group;
    let _ = journal.close();
    let _ = writer.store.close();
    true
}

/// Recovers what `crashed` left under `survives`; `Err` names the first
/// property that fails.
fn check(crashed: &FaultDisk, survives: Survives, snapshots: &[Vec<u8>]) -> Result<(), String> {
    let disk = crashed.after_crash(survives);
    let mut journal = match GroupJournal::recover(
        disk.clone(),
        Path::new(JOURNALS),
        GROUP,
        config(SyncPolicy::PerSegment),
    ) {
        Ok(recovered) => recovered.journal,
        Err(JournalError::Segment(SegmentError::NotFound { .. })) => return Ok(()),
        Err(error) => return Err(format!("journal recovery: {error}")),
    };
    let end = recorded_end(&mut journal).map_err(|e| format!("walk: {e}"))?;
    // Opened for reading first, over a disk that refuses writes: it sees
    // what recovery then leaves, and changes nothing.
    let verified = match CheckpointStore::open_verified(
        crate::disk::ReadOnly(disk.clone()),
        Path::new(CHECKPOINTS),
        GROUP,
        config(SyncPolicy::PerSegment),
        end,
    ) {
        Ok(verified) => Some(verified),
        Err(SegmentError::NotFound { .. }) => None,
        Err(error) => return Err(format!("store open_verified: {error}")),
    };
    let recovered = CheckpointStore::recover(
        disk.clone(),
        Path::new(CHECKPOINTS),
        GROUP,
        config(SyncPolicy::PerSegment),
        end,
    );
    // Both find the store, or neither does.
    if verified.is_none() != matches!(recovered, Err(SegmentError::NotFound { .. })) {
        return Err(format!(
            "open_verified found a store: {}, recovery: {}",
            verified.is_some(),
            recovered.is_ok()
        ));
    }
    let store = match recovered {
        Ok(store) => store,
        Err(SegmentError::NotFound { .. }) => {
            if end > 0 {
                return Err("records with no store".into());
            }
            CheckpointStore::create(
                disk,
                Path::new(CHECKPOINTS),
                GROUP,
                config(SyncPolicy::PerSegment),
            )
            .map_err(|e| format!("store create: {e}"))?
        }
        Err(error) => return Err(format!("store recovery: {error}")),
    };
    let mut group = Group {
        writer: CheckpointWriter::new(store, &journal).map_err(|e| format!("writer: {e}"))?,
        journal,
        slot: CheckpointSlot::new(300_000),
    };
    if group.writer.store().written() != end {
        return Err(format!(
            "store at {}, records end at {end}",
            group.writer.store().written()
        ));
    }
    if let Some(verified) = &verified
        && verified.written() != end
    {
        return Err(format!(
            "open_verified at {}, records end at {end}",
            verified.written()
        ));
    }
    let records = group.records();
    for record in &records {
        let Some(end) = record.end() else {
            return Err("a recorded checkpoint with no range".into());
        };
        let held = group.writer.store().holds(record.position, end);
        if let Some(verified) = &verified
            && verified.holds(record.position, end) != held
        {
            return Err(format!(
                "checkpoint {}: open_verified holds {:?}, recovery {held:?}",
                record.checkpoint_id,
                verified.holds(record.position, end)
            ));
        }
        let expected = &snapshots[usize::try_from(record.checkpoint_id - 1).unwrap()];
        match group.writer.store().holds(record.position, end) {
            CheckpointHeld::Written | CheckpointHeld::Durable => {
                let mut bytes = vec![0u8; expected.len()];
                group
                    .writer
                    .store_mut()
                    .read(record.position, &mut bytes)
                    .map_err(|e| format!("read: {e}"))?;
                if &bytes != expected || crc32c(&bytes) != record.crc32c {
                    return Err(format!("checkpoint {} differs", record.checkpoint_id));
                }
            }
            // The bytes are synced before the record: under every crash
            // model, a kept record names bytes the store kept.
            held => {
                return Err(format!(
                    "checkpoint {} recorded, its bytes {held:?}",
                    record.checkpoint_id
                ));
            }
        }
    }
    // It goes on: the next event and a checkpoint of it.
    let next = group.journal.order().next_seq();
    if group.journal.order().at_boundary() {
        group
            .journal
            .append(&event(next, EndOutcome::Complete))
            .map_err(|e| format!("append: {e}"))?;
        let record = group
            .checkpoint(next, b"after")
            .map_err(|e| format!("checkpoint after recovery: {e}"))?;
        if record.position < end {
            return Err("a range reused".into());
        }
        let mut bytes = [0u8; 5];
        group
            .writer
            .store_mut()
            .read(record.position, &mut bytes)
            .map_err(|e| format!("read after: {e}"))?;
        if &bytes != b"after" {
            return Err("the next checkpoint differs".into());
        }
    }
    Ok(())
}

/// The gate: at about 600 crash points over the workload and each of the
/// first 64 units, under the three crash models.
#[test]
fn crash_points_keep_the_journal_and_the_store_consistent() {
    let snapshots = vec![snapshot(1, 3000), snapshot(2, 200_000), snapshot(3, 100)];
    let free = FaultDisk::default();
    assert!(run(&free, &snapshots));
    let step = usize::try_from(free.used() / 600).unwrap().max(1);
    let mut failures = Vec::new();
    for budget in (0..=free.used()).step_by(step).chain(0..64) {
        let disk = FaultDisk::with_budget(budget);
        let _ = run(&disk, &snapshots);
        for survives in [Survives::Everything, Survives::Synced, Survives::TornData] {
            if let Err(failure) = check(&disk, survives, &snapshots) {
                failures.push(format!("budget {budget}, {survives:?}: {failure}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The gate again with each checkpoint written in 4 kB chunks, as the
/// agent writes it under its cycle's budget (A9-3): a crash between two
/// chunks leaves no record, and recovery cuts the bytes written.
#[test]
fn crash_points_keep_the_store_consistent_with_chunked_writes() {
    CHUNK.set(Some(4096));
    let snapshots = vec![snapshot(1, 3000), snapshot(2, 200_000), snapshot(3, 100)];
    let free = FaultDisk::default();
    assert!(run(&free, &snapshots));
    let step = usize::try_from(free.used() / 600).unwrap().max(1);
    let mut failures = Vec::new();
    for budget in (0..=free.used()).step_by(step).chain(0..64) {
        let disk = FaultDisk::with_budget(budget);
        let _ = run(&disk, &snapshots);
        for survives in [Survives::Everything, Survives::Synced, Survives::TornData] {
            if let Err(failure) = check(&disk, survives, &snapshots) {
                failures.push(format!("budget {budget}, {survives:?}: {failure}"));
            }
        }
    }
    CHUNK.set(None);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Chunks: a request other than the one begun, or none begun, is refused,
/// and the checkpoint let go; the bytes come in budget-sized writes and
/// the record only once they are all in.
#[test]
fn a_chunked_write_records_only_once_whole() {
    let disk = FaultDisk::default();
    let mut group = Group::create(&disk, Capture::Strict, 64);
    let _ = group
        .journal
        .append(&event(1, EndOutcome::Complete))
        .unwrap();
    let request = group
        .slot
        .take(1, 7, |buffer| {
            buffer[..10].copy_from_slice(b"0123456789");
            10
        })
        .unwrap();
    assert!(matches!(
        group.writer.advance(&mut group.journal, &request, 4),
        Err(CheckpointError::NotStarted)
    ));
    group.writer.begin(&group.journal, &request).unwrap();
    assert_eq!(
        group
            .writer
            .advance(&mut group.journal, &request, 4)
            .unwrap(),
        Progress::Writing { written: 4 }
    );
    assert_eq!(
        group
            .writer
            .advance(&mut group.journal, &request, 4)
            .unwrap(),
        Progress::Writing { written: 8 }
    );
    assert!(
        group.records().is_empty(),
        "no record before the last chunk"
    );
    let Progress::Recorded(record) = group
        .writer
        .advance(&mut group.journal, &request, 4)
        .unwrap()
    else {
        panic!("not recorded");
    };
    assert_eq!(read(group.writer.store_mut(), &record), b"0123456789");
    assert!(!group.writer.writing());
    group.slot.returned(request, &Ok(record));
    let other = group.slot.take(1, 7, |_| 3).unwrap();
    assert!(matches!(
        group.writer.advance(&mut group.journal, &other, 4),
        Err(CheckpointError::NotStarted)
    ));
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

/// Recovery (the coordinator's case): the journal holds events after the
/// checkpoint's `group_seq` before its record, since the record lags the
/// write. A crash between the write and the record recovers the stopped
/// range only, the unnamed bytes cut; with the record, the new range from
/// the checkpoint, its prefixes starting at the record.
#[test]
fn recovery_starts_a_range_only_at_its_record() {
    let recover = |recorded: bool| {
        let disk = FaultDisk::default();
        let mut group = Group::create(&disk, Capture::BestEffort, 64);
        let _ = group
            .journal
            .append(&event(1, EndOutcome::Complete))
            .unwrap();
        let _ = group.journal.append(&gap(2, 2)).unwrap();
        let _ = group
            .journal
            .append(&event(3, EndOutcome::Complete))
            .unwrap();
        let _ = group
            .journal
            .append(&event(4, EndOutcome::Complete))
            .unwrap();
        if recorded {
            let _ = group.checkpoint(2, b"state at 2").unwrap();
            let _ = group
                .journal
                .append(&event(5, EndOutcome::Complete))
                .unwrap();
        } else {
            // The bytes, and no record.
            let _ = group.writer.store.store.append(0, b"state at 2").unwrap();
        }
        let Group {
            journal, writer, ..
        } = group;
        let _ = journal.close().unwrap();
        let _ = writer.store.close().unwrap();
        let disk = disk.after_crash(Survives::Synced);
        let mut journal = GroupJournal::recover(
            disk.clone(),
            Path::new(JOURNALS),
            GROUP,
            config(SyncPolicy::PerSegment),
        )
        .unwrap()
        .journal;
        let end = recorded_end(&mut journal).unwrap();
        let store = CheckpointStore::recover(
            disk,
            Path::new(CHECKPOINTS),
            GROUP,
            config(SyncPolicy::PerSegment),
            end,
        )
        .unwrap();
        assert_eq!(store.written(), end, "unnamed bytes are cut");
        let recovered = crate::group::prefix::recover(&mut journal, &Held(&store), 8).unwrap();
        recovered.tracker.range()
    };
    let unrecorded = recover(false);
    assert_eq!(
        (unrecorded.start, unrecorded.complete, unrecorded.durable),
        (None, 1, 1)
    );
    let recorded = recover(true);
    assert_eq!(
        recorded.start,
        Some(RangeStart {
            checkpoint_id: 1,
            group_seq: 2
        })
    );
    assert_eq!((recorded.complete, recorded.durable), (5, 5));
}

/// Past a stop, the events a checkpoint may take are bounded: when more
/// end than the tracker holds before the record, the range it opens stays
/// at the checkpoint, never claiming what it let go; a later checkpoint
/// opens the next.
#[test]
fn a_range_past_more_events_than_the_tracker_holds_stays_at_its_checkpoint() {
    let mut tracker = PrefixTracker::new(2);
    let store = Store::default();
    store.written.set(200);
    store.durable.set(200);
    let mut at = feed(
        &mut tracker,
        &encode(&GroupRecord::Header(header(Capture::BestEffort))),
        0,
    );
    at = feed(&mut tracker, &gap(1, 1), at);
    for seq in 2..=5 {
        at = feed(&mut tracker, &event(seq, EndOutcome::Complete), at);
    }
    // Events 2 and 3 were let go: a range from 1 cannot reach 4.
    at = feed(&mut tracker, &checkpoint_record(1, 1, 0), at);
    assert_eq!(tracker.advance(at, at, &store), (1, 1));
    assert!(tracker.stopped());
    at = feed(&mut tracker, &event(6, EndOutcome::Complete), at);
    at = feed(&mut tracker, &checkpoint_record(5, 2, 100), at);
    assert_eq!(tracker.advance(at, at, &store), (6, 6));
}

/// #414 review P1: the bytes are synced before the record. With the
/// journal synced and the store's policy never syncing on its own, a
/// crash keeps the record and its bytes both: the checkpoint is durable,
/// read back, and opens its range.
#[test]
fn a_recorded_checkpoint_is_durable_by_construction() {
    let disk = FaultDisk::default();
    let journal = GroupJournal::create(
        disk.clone(),
        Path::new(JOURNALS),
        &header(Capture::BestEffort),
        config(SyncPolicy::None),
    )
    .unwrap();
    let store = CheckpointStore::create(
        disk.clone(),
        Path::new(CHECKPOINTS),
        GROUP,
        config(SyncPolicy::None),
    )
    .unwrap();
    let mut group = Group {
        writer: CheckpointWriter::new(store, &journal).unwrap(),
        journal,
        slot: CheckpointSlot::new(64),
    };
    let _ = group.journal.append(&gap(1, 1)).unwrap();
    let record = group.checkpoint(1, b"kept state").unwrap();
    assert_eq!(
        group
            .writer
            .store()
            .holds(record.position, record.end().unwrap()),
        CheckpointHeld::Durable
    );
    let _ = group
        .journal
        .append(&event(2, EndOutcome::Complete))
        .unwrap();
    let _ = group.journal.sync().unwrap();
    let disk = disk.after_crash(Survives::Synced);
    let mut journal = GroupJournal::recover(
        disk.clone(),
        Path::new(JOURNALS),
        GROUP,
        config(SyncPolicy::None),
    )
    .unwrap()
    .journal;
    let end = recorded_end(&mut journal).unwrap();
    let mut store = CheckpointStore::recover(
        disk,
        Path::new(CHECKPOINTS),
        GROUP,
        config(SyncPolicy::None),
        end,
    )
    .unwrap();
    assert_eq!(store.holds(record.position, end), CheckpointHeld::Durable);
    assert_eq!(read(&mut store, &record), b"kept state");
    let recovered = crate::group::prefix::recover(&mut journal, &Held(&store), 8).unwrap();
    let range = recovered.tracker.range();
    assert_eq!((range.complete, range.durable), (2, 2));
    assert_eq!(range.start.unwrap().checkpoint_id, 1);
}

/// #414 review P1, a real loss: a record kept whose bytes the store does
/// not hold (its files damaged). Recovery marks the range lost: it reads
/// as lost and never opens its range, the next valid checkpoint does, and
/// the next write goes past the lost range, never reusing it.
#[test]
fn a_lost_checkpoint_opens_nothing_and_the_next_one_does() {
    let disk = FaultDisk::default();
    let mut group = Group::create(&disk, Capture::BestEffort, 64);
    let _ = group.journal.append(&gap(1, 2)).unwrap();
    // A record naming 10 bytes the store never got.
    let _ = group
        .journal
        .append(&encode(&GroupRecord::Checkpoint(CheckpointRecord {
            group_seq: 2,
            checkpoint_id: 1,
            position: 0,
            length: 10,
            crc32c: crc32c(b"lost state"),
            format: 7,
        })))
        .unwrap();
    let _ = group
        .journal
        .append(&event(3, EndOutcome::Complete))
        .unwrap();
    let Group {
        journal, writer, ..
    } = group;
    let _ = journal.close().unwrap();
    let _ = writer.store.close().unwrap();
    let disk = disk.after_crash(Survives::Synced);
    let mut journal = GroupJournal::recover(
        disk.clone(),
        Path::new(JOURNALS),
        GROUP,
        config(SyncPolicy::PerSegment),
    )
    .unwrap()
    .journal;
    let end = recorded_end(&mut journal).unwrap();
    let store = CheckpointStore::recover(
        disk,
        Path::new(CHECKPOINTS),
        GROUP,
        config(SyncPolicy::PerSegment),
        end,
    )
    .unwrap();
    assert_eq!(store.holds(0, 10), CheckpointHeld::Lost);
    let recovered = crate::group::prefix::recover(&mut journal, &Held(&store), 8).unwrap();
    assert!(!recovered.full);
    assert_eq!(
        recovered.tracker.range().start,
        None,
        "the lost one opens nothing"
    );
    assert!(recovered.tracker.stopped());
    // The next one, after event 3, opens the range; its bytes go past the
    // lost range.
    let mut group = Group {
        writer: CheckpointWriter::new(store, &journal).unwrap(),
        journal,
        slot: CheckpointSlot::new(64),
    };
    let record = group.checkpoint(3, b"state at 3").unwrap();
    assert_eq!((record.checkpoint_id, record.position), (2, 10));
    let mut tracker = recovered.tracker;
    tracker
        .record(&GroupRecord::Checkpoint(record), group.journal.written())
        .unwrap();
    let written = group.journal.written();
    let _ = group.journal.sync().unwrap();
    let (complete, durable) = tracker.advance(written, written, &Held(group.writer.store()));
    assert_eq!((complete, durable), (3, 3));
    assert_eq!(tracker.range().start.unwrap().checkpoint_id, 2);
}

/// #414 review P1: a reopened range never claims the old range's events.
/// In best effort, event 1's payload is by reference to recording 7,
/// whose frames are never written; a gap at 2; a checkpoint at 2, held.
/// The new range starts at 2, but event 1 is not durable: the view
/// answers it from the first range's final values, never durable.
#[test]
fn a_reopened_range_does_not_claim_old_events_durable() {
    use karyos_sys::frame::Lane;

    use crate::group::record::{MessageEvent, Payload};

    let mut tracker = PrefixTracker::new(8);
    let view = tracker.view();
    let store = Store::default();
    let mut at = feed(
        &mut tracker,
        &encode(&GroupRecord::Header(header(Capture::BestEffort))),
        0,
    );
    let mut first = encode(&GroupRecord::Message(MessageEvent {
        group_seq: 1,
        logical_time: 1,
        incarnation: 1,
        position: 0,
        extent: 64,
        stream_id: 1,
        session_id: 1,
        lane: Lane::ZERO,
        reserved_value: 0,
        end_of_stream: false,
        extension: None,
        payload: Payload::Reference {
            recording_id: 7,
            length: 10,
        },
    }));
    first.extend(encode(&GroupRecord::End(EventEnd {
        group_seq: 1,
        observations: 0,
        outcome: EndOutcome::Complete,
    })));
    at = feed(&mut tracker, &first, at);
    at = feed(&mut tracker, &gap(2, 2), at);
    at = feed(&mut tracker, &checkpoint_record(2, 1, 0), at);
    store.written.set(100);
    store.durable.set(100);
    assert_eq!(tracker.advance(at, at, &store), (2, 2));
    let first_range = tracker.first_range().unwrap();
    assert_eq!((first_range.complete, first_range.durable), (0, 0));
    // Event 1 still settles in the first range (its recording may yet
    // cover it): pending there, never claimed by the new range.
    assert_eq!(view.durable_for(1), DurableFor::Pending(0));
    assert_eq!(view.durable_for(2), DurableFor::Never(0));
    at = feed(&mut tracker, &event(3, EndOutcome::Complete), at);
    let _ = tracker.advance(at, at, &store);
    assert_eq!(view.durable_for(3), DurableFor::Reached(3));
    assert_eq!(view.durable_for(4), DurableFor::Pending(3));
}

/// #414 review mutant d1: a range waits for its opening record's own
/// journal position, not only for the store: with the journal written
/// short of the record, nothing of the range counts.
#[test]
fn a_range_waits_for_its_record_in_the_journal() {
    let mut tracker = PrefixTracker::new(8);
    let store = Store::default();
    store.written.set(100);
    store.durable.set(100);
    let mut at = feed(
        &mut tracker,
        &encode(&GroupRecord::Header(header(Capture::BestEffort))),
        0,
    );
    at = feed(&mut tracker, &gap(1, 1), at);
    let before = at;
    at = feed(&mut tracker, &checkpoint_record(1, 1, 0), at);
    assert_eq!(tracker.advance(before, before, &store), (0, 0));
    assert_eq!(tracker.advance(at, before, &store), (1, 0));
    assert_eq!(tracker.advance(at, at, &store), (1, 1));
}

/// #414 review mutant e: a real store I/O failure, on a disk of its own,
/// fails the write with no record, and the slot reports it.
#[test]
fn a_store_failure_leaves_no_record() {
    let journals = FaultDisk::default();
    let mut journal = GroupJournal::create(
        journals,
        Path::new(JOURNALS),
        &header(Capture::Strict),
        config(SyncPolicy::PerSegment),
    )
    .unwrap();
    let _ = journal.append(&event(1, EndOutcome::Complete)).unwrap();
    let records = journal.order().records();
    // The store's disk crashes inside the write: its budget covers the
    // creation and 1000 units more.
    let probe = FaultDisk::default();
    let _ = CheckpointStore::create(
        probe.clone(),
        Path::new(CHECKPOINTS),
        GROUP,
        config(SyncPolicy::PerSegment),
    )
    .unwrap();
    let checkpoints = FaultDisk::with_budget(probe.used() + 1000);
    let store = CheckpointStore::create(
        checkpoints.clone(),
        Path::new(CHECKPOINTS),
        GROUP,
        config(SyncPolicy::PerSegment),
    )
    .unwrap();
    let mut group = Group {
        writer: CheckpointWriter::new(store, &journal).unwrap(),
        journal,
        slot: CheckpointSlot::new(300_000),
    };
    // The append's own error, not a later call's on a failed store.
    let result = group.checkpoint(1, &snapshot(1, 200_000));
    assert!(
        matches!(result, Err(CheckpointError::Store(ref error)) if !matches!(error, SegmentError::Failed)),
        "{result:?}"
    );
    assert_eq!(group.journal.order().records(), records, "no record");
    assert!(group.records().is_empty());
    assert_eq!(
        group.slot.last_checkpoint(),
        Some(LastCheckpoint::Failed { group_seq: 1 })
    );
}

/// Replays `journal` from its start; returns the events' `group_seq`s and
/// the stop.
fn replay_from_start(
    journal: GroupJournal<FaultDisk>,
    store: &CheckpointStore<FaultDisk>,
    mut recovered_journal: GroupJournal<FaultDisk>,
) -> (Vec<u64>, crate::group::replay::Stop) {
    use crate::group::replay::{CursorConfig, ReplayConfig, ReplayCursor, Step};

    let recovery = crate::group::prefix::recover(&mut recovered_journal, &Held(store), 8).unwrap();
    drop(recovered_journal);
    let mut cursor = ReplayCursor::open(
        journal,
        &recovery,
        &ReplayConfig {
            manifest: b"m",
            accept_manifest: false,
        },
        CursorConfig {
            bytes: 4 * MAX_RECORD,
            records: 4,
        },
    )
    .unwrap();
    let mut seen = Vec::new();
    loop {
        match cursor.step().unwrap() {
            Step::Event(event) => seen.push(event.group_seq()),
            Step::Checkpoint(_) => {}
            Step::Stop(stop) => return (seen, stop),
        }
    }
}

/// #414 review P2: the replay cursor reads journals that hold template
/// 30. A strict journal with a checkpoint between its events replays them
/// all; a best-effort one whose later range a checkpoint opened replays
/// from its start up to the gap, the first range's end.
#[test]
fn replay_from_the_start_skips_checkpoints_and_stops_at_the_first_range() {
    use crate::group::replay::Stop;

    for capture in [Capture::Strict, Capture::BestEffort] {
        let disk = FaultDisk::default();
        let mut group = Group::create(&disk, capture, 64);
        let _ = group
            .journal
            .append(&event(1, EndOutcome::Complete))
            .unwrap();
        let _ = group.checkpoint(1, b"state at 1").unwrap();
        if capture == Capture::BestEffort {
            let _ = group.journal.append(&gap(2, 2)).unwrap();
            let _ = group.checkpoint(2, b"state at 2").unwrap();
            let _ = group
                .journal
                .append(&event(3, EndOutcome::Complete))
                .unwrap();
        } else {
            let _ = group
                .journal
                .append(&event(2, EndOutcome::Complete))
                .unwrap();
        }
        let Group {
            journal, writer, ..
        } = group;
        let _ = journal.close().unwrap();
        let _ = writer.store.close().unwrap();
        let disk = disk.after_crash(Survives::Synced);
        let recover = || {
            GroupJournal::recover(
                disk.clone(),
                Path::new(JOURNALS),
                GROUP,
                config(SyncPolicy::PerSegment),
            )
            .unwrap()
            .journal
        };
        let mut journal = recover();
        let end = recorded_end(&mut journal).unwrap();
        let store = CheckpointStore::recover(
            disk.clone(),
            Path::new(CHECKPOINTS),
            GROUP,
            config(SyncPolicy::PerSegment),
            end,
        )
        .unwrap();
        let (seen, stop) = replay_from_start(journal, &store, recover());
        if capture == Capture::Strict {
            assert_eq!(seen, [1, 2]);
            assert_eq!(
                stop,
                Stop::EndOfPrefix {
                    complete_recording_seq: 2
                }
            );
        } else {
            assert_eq!(seen, [1]);
            assert!(
                matches!(stop, Stop::Gap(GapMarker { from_seq: 2, .. })),
                "{stop:?}"
            );
        }
    }
}

/// #414 re-check P2 2: the first range's events still waiting when a
/// checkpoint opens another keep settling into its frozen values. Event 1
/// is complete, not yet durable, when the range opens; once the journal
/// is durable past it, the first range's durable value follows, and a
/// wait for event 1 is reached.
#[test]
fn the_first_range_keeps_settling_after_a_range_opens() {
    let mut tracker = PrefixTracker::new(8);
    let view = tracker.view();
    let store = Store::default();
    store.written.set(100);
    store.durable.set(100);
    let mut at = feed(
        &mut tracker,
        &encode(&GroupRecord::Header(header(Capture::BestEffort))),
        0,
    );
    let header_end = at;
    at = feed(&mut tracker, &event(1, EndOutcome::Complete), at);
    let event_end = at;
    at = feed(&mut tracker, &gap(2, 2), at);
    at = feed(&mut tracker, &checkpoint_record(2, 1, 0), at);
    // Written to the record's end, durable only to the header.
    assert_eq!(tracker.advance(at, header_end, &store), (2, 0));
    assert_eq!(tracker.first_range().unwrap().durable, 0);
    // Still settling: not yet, rather than never.
    assert_eq!(view.durable_for(1), DurableFor::Pending(0));
    assert_eq!(view.durable_for(2), DurableFor::Never(0));
    // Durable past event 1, not yet past the record.
    let _ = tracker.advance(at, event_end, &store);
    let first = tracker.first_range().unwrap();
    assert_eq!((first.complete, first.durable), (1, 1));
    assert_eq!(view.durable_for(1), DurableFor::Reached(1));
    assert_eq!(view.durable_for(2), DurableFor::Never(1));
    assert_eq!(tracker.advance(at, at, &store), (2, 2));
}

/// #414 re-check P2 4: under `SyncPolicy::None`, a 200 kB checkpoint
/// crossing a segment is durable before its record, or refused with no
/// record: never recorded with its bytes short of durable.
#[test]
fn a_checkpoint_is_durable_before_its_record_under_no_policy() {
    let disk = FaultDisk::default();
    let journal = GroupJournal::create(
        disk.clone(),
        Path::new(JOURNALS),
        &header(Capture::Strict),
        config(SyncPolicy::None),
    )
    .unwrap();
    let store = CheckpointStore::create(
        disk.clone(),
        Path::new(CHECKPOINTS),
        GROUP,
        config(SyncPolicy::None),
    )
    .unwrap();
    let mut group = Group {
        writer: CheckpointWriter::new(store, &journal).unwrap(),
        journal,
        slot: CheckpointSlot::new(300_000),
    };
    let _ = group
        .journal
        .append(&event(1, EndOutcome::Complete))
        .unwrap();
    match group.checkpoint(1, &snapshot(4, 200_000)) {
        Ok(record) => assert_eq!(
            group
                .writer
                .store()
                .holds(record.position, record.end().unwrap()),
            CheckpointHeld::Durable
        ),
        Err(CheckpointError::NotDurable { .. }) => assert!(group.records().is_empty()),
        Err(error) => panic!("{error}"),
    }
}

/// #426 review P2: the reopening window has its own capacity. With room
/// for 2 events in flight, 6 end while the checkpoint is written: a hold
/// of 8 keeps them all and the range opens over them; the default hold
/// (the capacity) lets the first go, the range stays at the checkpoint,
/// and the failed reopen is counted.
#[test]
fn the_reopen_hold_keeps_the_events_a_checkpoint_write_spans() {
    let run = |hold: Option<usize>| {
        let mut tracker = PrefixTracker::new(2);
        if let Some(hold) = hold {
            tracker.reserve_reopen_hold(hold).unwrap();
        }
        let store = Store::default();
        store.written.set(100);
        store.durable.set(100);
        let mut at = feed(
            &mut tracker,
            &encode(&GroupRecord::Header(header(Capture::BestEffort))),
            0,
        );
        at = feed(&mut tracker, &gap(1, 1), at);
        for seq in 2..=7 {
            at = feed(&mut tracker, &event(seq, EndOutcome::Complete), at);
        }
        at = feed(&mut tracker, &checkpoint_record(1, 1, 0), at);
        (tracker.advance(at, at, &store), tracker.failed_reopens())
    };
    assert_eq!(run(Some(8)), ((7, 7), 0), "fits");
    assert_eq!(run(None), ((1, 1), 1), "overflows, counted");
}

/// #426 re-check h5: a hold below the tracker's capacity is taken as the
/// capacity. With room for 2 in flight and a hold of 1, the 2 events
/// that end while the checkpoint is written are both kept.
#[test]
fn a_hold_below_the_capacity_is_the_capacity() {
    let mut tracker = PrefixTracker::new(2);
    tracker.reserve_reopen_hold(1).unwrap();
    let store = Store::default();
    store.written.set(100);
    store.durable.set(100);
    let mut at = feed(
        &mut tracker,
        &encode(&GroupRecord::Header(header(Capture::BestEffort))),
        0,
    );
    at = feed(&mut tracker, &gap(1, 1), at);
    for seq in 2..=3 {
        at = feed(&mut tracker, &event(seq, EndOutcome::Complete), at);
    }
    at = feed(&mut tracker, &checkpoint_record(1, 1, 0), at);
    assert_eq!(tracker.advance(at, at, &store), (3, 3));
    assert_eq!(tracker.failed_reopens(), 0);
}
