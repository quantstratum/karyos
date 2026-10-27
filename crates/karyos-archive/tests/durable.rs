// SPDX-License-Identifier: Apache-2.0

//! R-CORE-12 from outside the crate (quantstratum-docs:
//! karyos/design/archive-durable-acknowledgement.md): a recording's
//! durable position through the crate root, with no `group::` path in the
//! imports; never ahead of what was written; equal to the stop once
//! stopped; and never behind an earlier answer after a restart.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use karyos_archive::agent::{AgentConfig, ArchiveHandle, StartRecording};
use karyos_archive::catalog::{SourceIncarnation, StreamFormat};
use karyos_archive::disk::StdDisk;
use karyos_archive::durable::{DurablePosition, DurableState, DurableSync};
use karyos_archive::recorder::{FrameSource, Frames, Mode, SourceError};
use karyos_archive::segment::{Geometry, SyncPolicy};

/// Chunks from position 0, then pending; `drained` once read.
struct Chunks {
    position: u64,
    chunks: VecDeque<Vec<u8>>,
    drained: Arc<AtomicBool>,
}

impl FrameSource for Chunks {
    fn position(&self) -> u64 {
        self.position
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        let Some(chunk) = self.chunks.pop_front() else {
            self.drained.store(true, Ordering::Release);
            return Ok(Frames::Pending);
        };
        let position = self.position;
        let Some(target) = out.get_mut(..chunk.len()) else {
            panic!("a chunk larger than the read");
        };
        target.copy_from_slice(&chunk);
        self.position += u64::try_from(chunk.len()).unwrap();
        Ok(Frames::Copied {
            position,
            len: chunk.len(),
            next: self.position,
        })
    }

    fn consumed(&mut self, _position: u64) -> Result<(), SourceError> {
        Ok(())
    }

    fn resume(&mut self, to: u64) -> Result<u64, SourceError> {
        self.position = to;
        Ok(to)
    }
}

fn temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-archive-durable-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

#[test]
fn test_durable_position_is_public_and_never_behind_an_answer() {
    let dir = temp_dir();
    let mut config = AgentConfig::default();
    config.idle = Duration::from_millis(1);
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    let drained = Arc::new(AtomicBool::new(false));
    let id = agent
        .start(StartRecording::new(
            10,
            3,
            b"karyos:ipc".to_vec(),
            Geometry::new(4096, 8192).unwrap(),
            SyncPolicy::PerSegment,
            Mode::Required,
            StreamFormat {
                lane: karyos_sys::frame::Lane::ZERO,
                initial_term_id: 0,
                mtu: core::num::NonZeroU32::new(1408).unwrap(),
                source: SourceIncarnation {
                    driver: [1, 2],
                    registration: 3,
                    incarnation: 1,
                },
            },
            Box::new(Chunks {
                position: 0,
                chunks: vec![vec![1u8; 3000], vec![2u8; 3000], vec![3u8; 3000]].into(),
                drained: Arc::clone(&drained),
            }),
        ))
        .unwrap();
    for _ in 0..5000 {
        if drained.load(Ordering::Acquire) && agent.describe(id).unwrap().end == 9000 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let recording: DurablePosition = agent.durable_position(id).unwrap();
    assert_eq!(
        (recording.state, recording.sync, recording.written),
        (DurableState::Recording, DurableSync::PerSegment, 9000)
    );
    // Per segment of 8192 bytes: the first segment is durable, the rest
    // is written only.
    assert!(recording.start <= recording.durable && recording.durable <= recording.written);
    assert!(recording.covers(recording.durable));
    let ended = agent.stop(id).unwrap();
    let stopped = agent.durable_position(id).unwrap();
    assert_eq!(
        (stopped.state, stopped.written, stopped.durable),
        (DurableState::Stopped, ended.position, ended.position)
    );
    assert!(stopped.durable >= recording.durable);
    agent.shutdown().unwrap();

    let restarted = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    let recovered = restarted.durable_position(id).unwrap();
    assert_eq!(
        recovered.durable, stopped.durable,
        "unchanged across a restart"
    );
    restarted.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
