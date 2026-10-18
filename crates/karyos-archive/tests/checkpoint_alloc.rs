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
