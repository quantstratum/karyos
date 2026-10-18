// SPDX-License-Identifier: Apache-2.0

//! A9-1: after configuration, a checkpoint allocates nothing: the
//! Gateway's slot hands its buffer to the writer and gets it back, the
//! writer appends the bytes and the record, all over a counting global
//! allocator and the real disk.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::PathBuf;

use karyos_archive::disk::StdDisk;
use karyos_archive::group::checkpoint::{CheckpointSlot, CheckpointStore, CheckpointWriter};
use karyos_archive::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use karyos_archive::group::record::{
    Capture, Clock, EndOutcome, EventEnd, GroupRecord, JournalHeader, TimerEvent,
};
use karyos_archive::segment::SyncPolicy;
use karyos_sys::alloc_count::{CountingAllocator, count};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-checkpoint-alloc-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn event(seq: u64, out: &mut Vec<u8>) {
    let mut buf = [0u8; 64];
    for record in [
        GroupRecord::Timer(TimerEvent {
            group_seq: seq,
            logical_time: seq,
            timer_id: seq,
        }),
        GroupRecord::End(EventEnd {
            group_seq: seq,
            observations: 0,
            outcome: EndOutcome::Complete,
        }),
    ] {
        let length = record.encode(&mut buf).unwrap();
        out.extend_from_slice(&buf[..length]);
    }
}

#[test]
fn a_checkpoint_allocates_nothing_after_configuration() {
    let config = JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::None,
    };
    let (journals, checkpoints) = (dir("journals"), dir("checkpoints"));
    let header = JournalHeader {
        group_id: 3,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: Capture::Strict,
        manifest: b"m",
    };
    let mut journal = GroupJournal::create(StdDisk, &journals, &header, config).unwrap();
    let store = CheckpointStore::create(StdDisk, &checkpoints, 3, config).unwrap();
    let mut writer = CheckpointWriter::new(store, &journal).unwrap();
    let mut slot = CheckpointSlot::new(4096);
    let mut events = Vec::new();
    for seq in 1..=8 {
        event(seq, &mut events);
    }
    let _ = journal.append(&events).unwrap();
    for seq in 1..=8u64 {
        let (recorded, allocations) = count(|| {
            let request = slot
                .take(seq, 1, |buffer| {
                    buffer[..1000].fill(u8::try_from(seq).unwrap());
                    1000
                })
                .unwrap();
            let result = writer.write(&mut journal, &request);
            slot.returned(request, &result);
            result.is_ok()
        });
        assert!(recorded);
        assert_eq!(allocations, 0, "checkpoint {seq}");
    }
    // A refusal allocates nothing either.
    let (refused, allocations) = count(|| slot.take(9, 1, |_| 5000).is_err());
    assert!(refused);
    assert_eq!(allocations, 0);
    let _ = std::fs::remove_dir_all(&journals);
    let _ = std::fs::remove_dir_all(&checkpoints);
}

/// A9-2: once opened at a checkpoint, a replay's steps allocate nothing,
/// its checkpoint steps and the state compare included.
#[test]
fn replay_from_a_checkpoint_steps_without_allocating() {
    use karyos_archive::group::checkpoint::recorded_end;
    use karyos_archive::group::prefix::{CheckpointHeld, Coverage, recover};
    use karyos_archive::group::record::MAX_RECORD;
    use karyos_archive::group::replay::{
        CursorConfig, ReplayConfig, ReplayCursor, Step, compare_state,
    };

    struct Held<'a>(&'a CheckpointStore<StdDisk>);
    impl Coverage for Held<'_> {
        fn positions(&self, _: u64) -> Option<(u64, u64)> {
            None
        }
        fn ended(&self, _: u64) -> Option<u64> {
            None
        }
        fn checkpoint(&self, position: u64, end: u64) -> CheckpointHeld {
            self.0.holds(position, end)
        }
    }

    let config = JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::PerSegment,
    };
    let (journals, checkpoints) = (dir("replay-journals"), dir("replay-checkpoints"));
    let header = JournalHeader {
        group_id: 4,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: Capture::Strict,
        manifest: b"m",
    };
    let mut journal = GroupJournal::create(StdDisk, &journals, &header, config).unwrap();
    let store = CheckpointStore::create(StdDisk, &checkpoints, 4, config).unwrap();
    let mut writer = CheckpointWriter::new(store, &journal).unwrap();
    let mut slot = CheckpointSlot::new(64);
    for seq in 1..=8u64 {
        let mut events = Vec::new();
        event(seq, &mut events);
        let _ = journal.append(&events).unwrap();
        let request = slot
            .take(seq, 1, |buffer| {
                buffer[0] = u8::try_from(seq).unwrap();
                1
            })
            .unwrap();
        let result = writer.write(&mut journal, &request);
        slot.returned(request, &result);
        let _ = result.unwrap();
    }
    let _ = journal.close().unwrap();
    let _ = writer.store_mut().sync().unwrap();
    drop(writer);
    let mut journal = GroupJournal::recover(StdDisk, &journals, 4, config)
        .unwrap()
        .journal;
    let end = recorded_end(&mut journal).unwrap();
    let mut store = CheckpointStore::recover(StdDisk, &checkpoints, 4, config, end).unwrap();
    let recovery = recover(&mut journal, &Held(&store), 16).unwrap();
    let mut snapshot = [0u8; 64];
    let (mut cursor, _) = ReplayCursor::open_at_checkpoint(
        journal,
        &recovery,
        &mut store,
        2,
        &ReplayConfig {
            manifest: b"m",
            accept_manifest: false,
        },
        CursorConfig {
            bytes: 4 * MAX_RECORD,
            records: 4,
        },
        &mut snapshot,
    )
    .unwrap();
    let mut seen = (0u32, 0u32);
    loop {
        let (step, allocations) = count(|| match cursor.step().unwrap() {
            Step::Event(_) => Some(true),
            Step::Checkpoint(checkpoint) => {
                let state = [u8::try_from(checkpoint.group_seq).unwrap()];
                assert!(compare_state(&checkpoint, &state).is_ok());
                Some(false)
            }
            Step::Stop(_) => None,
        });
        assert_eq!(allocations, 0, "a step allocated");
        match step {
            Some(true) => seen.0 += 1,
            Some(false) => seen.1 += 1,
            None => break,
        }
    }
    assert_eq!(seen, (6, 6), "events 3 to 8, each with its checkpoint");
    let _ = std::fs::remove_dir_all(&journals);
    let _ = std::fs::remove_dir_all(&checkpoints);
}

/// A9-3: the handoff between the Gateway's and the Archive's ends moves
/// the buffer both ways without allocating, the chunked write included.
#[test]
fn the_handoff_and_a_chunked_write_allocate_nothing() {
    use karyos_archive::group::checkpoint::{LastCheckpoint, Progress, handoff};

    let config = JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::None,
    };
    let (journals, checkpoints) = (dir("handoff-journals"), dir("handoff-checkpoints"));
    let header = JournalHeader {
        group_id: 5,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: Capture::Strict,
        manifest: b"m",
    };
    let mut journal = GroupJournal::create(StdDisk, &journals, &header, config).unwrap();
    let store = CheckpointStore::create(StdDisk, &checkpoints, 5, config).unwrap();
    let mut writer = CheckpointWriter::new(store, &journal).unwrap();
    let (mut handle, inbox) = handoff(4096);
    let mut events = Vec::new();
    for seq in 1..=4 {
        event(seq, &mut events);
    }
    let _ = journal.append(&events).unwrap();
    for seq in 1..=4u64 {
        let (recorded, allocations) = count(|| {
            handle
                .checkpoint(seq, 1, |buffer| {
                    buffer[..1000].fill(1);
                    1000
                })
                .unwrap();
            let request = inbox.take().unwrap();
            writer.begin(&journal, &request).unwrap();
            let record = loop {
                match writer.advance(&mut journal, &request, 300).unwrap() {
                    Progress::Writing { .. } => {}
                    Progress::Recorded(record) => break record,
                }
            };
            inbox.give_back(request, Ok(record));
            handle.poll();
            matches!(handle.last_checkpoint(), Some(LastCheckpoint::Recorded(_)))
        });
        assert!(recorded);
        assert_eq!(allocations, 0, "checkpoint {seq}");
    }
    let _ = std::fs::remove_dir_all(&journals);
    let _ = std::fs::remove_dir_all(&checkpoints);
}

/// #426 re-check h2: the reopening window, sized at configuration, keeps
/// the events a checkpoint write spans and opens the range over them
/// without allocating.
#[test]
fn the_reopen_hold_allocates_nothing_after_configuration() {
    use karyos_archive::group::prefix::{CheckpointHeld, Coverage, PrefixTracker};
    use karyos_archive::group::record::{CheckpointRecord, GapMarker, GapReason};

    struct Written;
    impl Coverage for Written {
        fn positions(&self, _: u64) -> Option<(u64, u64)> {
            None
        }
        fn ended(&self, _: u64) -> Option<u64> {
            None
        }
        fn checkpoint(&self, _: u64, _: u64) -> CheckpointHeld {
            CheckpointHeld::Durable
        }
    }

    let mut tracker = PrefixTracker::new(2);
    tracker.reserve_reopen_hold(8).unwrap();
    let mut records = vec![GroupRecord::Header(JournalHeader {
        group_id: 4,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: Capture::BestEffort,
        manifest: b"m",
    })];
    records.push(GroupRecord::Gap(GapMarker {
        from_seq: 1,
        to_seq: 1,
        reason: GapReason::RingFull,
    }));
    for seq in 2..=7u64 {
        records.push(GroupRecord::Timer(TimerEvent {
            group_seq: seq,
            logical_time: seq,
            timer_id: seq,
        }));
        records.push(GroupRecord::End(EventEnd {
            group_seq: seq,
            observations: 0,
            outcome: EndOutcome::Complete,
        }));
    }
    records.push(GroupRecord::Checkpoint(CheckpointRecord {
        group_seq: 1,
        checkpoint_id: 1,
        position: 0,
        length: 100,
        crc32c: 0,
        format: 7,
    }));
    let (prefix, allocations) = count(|| {
        let mut at = 0u64;
        for record in &records {
            at += 64;
            tracker.record(record, at).unwrap();
        }
        tracker.advance(at, at, &Written)
    });
    assert_eq!(prefix, (7, 7), "the range opens over the held events");
    assert_eq!(tracker.failed_reopens(), 0);
    assert_eq!(allocations, 0, "the hold allocated");
}
