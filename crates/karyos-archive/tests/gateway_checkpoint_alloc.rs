//! A9-4: the live Gateway's checkpoint path, its refusals,
//! last_checkpoint and checkpoint_stats allocate nothing after configuration.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::time::{Duration, Instant};

use karyos_archive::agent::{AgentConfig, ArchiveHandle, GroupCheckpoints, NewGroup, StartGroup};
use karyos_archive::disk::StdDisk;
use karyos_archive::group::capture::CaptureConfig;
use karyos_archive::group::checkpoint::{CheckpointError, LastCheckpoint, store_dir};
use karyos_archive::group::gateway::live::{Gateway, Port};
use karyos_archive::group::gateway::{
    ClaimCommit, DeliveryOutcome, Effects, Event, GroupGateway, PublicationId, TimerId,
};
use karyos_archive::group::journal::{JournalConfig, MIN_SEGMENT_LENGTH};
use karyos_archive::group::record::{Capture, Outcome};
use karyos_archive::segment::SyncPolicy;
use karyos_sys::alloc_count::{CountingAllocator, count};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Inert;

impl Port for Inert {
    fn publication(&self, _: PublicationId) -> (i32, i32) {
        (1, 1)
    }
    fn offer(&mut self, _: PublicationId, _: &[u8]) -> Outcome {
        Outcome::BackPressured
    }
    fn claim(
        &mut self,
        _: PublicationId,
        _: usize,
        _: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> ClaimCommit {
        ClaimCommit::new(Outcome::BackPressured, None)
    }
    fn poll_outcomes(
        &mut self,
        _: PublicationId,
        _: u32,
        _: &mut dyn FnMut(&DeliveryOutcome),
    ) -> u32 {
        0
    }
    fn schedule(&mut self, _: TimerId, _: u64) {}
    fn cancel(&mut self, _: TimerId) {}
}

#[test]
fn the_gateway_checkpoint_path_allocates_nothing() {
    let dir = std::env::temp_dir().join(format!(
        "karyos-gateway-checkpoint-alloc-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let groups = dir.join("groups");
    std::fs::create_dir_all(store_dir(&groups)).unwrap();
    let archive = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let sender = archive
        .start_group({
            let mut value = StartGroup::new(
                1,
                groups.clone(),
                JournalConfig::new(MIN_SEGMENT_LENGTH, SyncPolicy::Every { interval_ns: 0 }),
                CaptureConfig::new(1 << 16, 4096, 64),
            );
            value.new = Some(NewGroup::new(1, 4096, Capture::Strict, b"probe".to_vec()));
            value.checkpoints = Some(GroupCheckpoints::new(64));
            value
        })
        .unwrap();
    let mut gateway = Gateway::new(Inert, || 1u64, sender, Capture::Strict, 1, 4096, 4).unwrap();
    let mut handler = |_: &Event<'_>, _: &mut dyn Effects| {};
    let (refused, allocations) = count(|| gateway.checkpoint(1, |_| 1));
    assert!(matches!(refused, Err(CheckpointError::NothingDispatched)));
    assert_eq!(allocations, 0, "NothingDispatched");
    let deadline = Instant::now() + Duration::from_secs(30);
    for expected in 1..=4u64 {
        gateway.deliver_external(1, b"x", &mut handler).unwrap();
        let (taken, allocations) = count(|| {
            gateway.checkpoint(7, |out| {
                out[..4].copy_from_slice(b"abcd");
                4
            })
        });
        taken.unwrap();
        assert_eq!(allocations, 0, "checkpoint {expected}");
        loop {
            let (last, allocations) = count(|| gateway.last_checkpoint());
            assert_eq!(allocations, 0, "last_checkpoint {expected}");
            match last {
                Some(LastCheckpoint::Recorded(record)) if record.group_seq == expected => break,
                Some(LastCheckpoint::Failed { group_seq }) if group_seq == expected => {
                    panic!("checkpoint {expected} failed")
                }
                _ => assert!(
                    Instant::now() < deadline,
                    "checkpoint {expected} never ended"
                ),
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let (stats, allocations) = count(|| gateway.checkpoint_stats());
        assert_eq!(allocations, 0, "stats {expected}");
        assert_eq!(stats.recorded, expected);
    }
    archive.stop_group(1).unwrap();
    let (stopped, allocations) = count(|| gateway.checkpoint(1, |_| 1));
    assert!(
        matches!(stopped, Err(CheckpointError::Stopped)),
        "{stopped:?}"
    );
    assert_eq!(allocations, 0, "Stopped");
    drop(gateway);
    archive.shutdown().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
