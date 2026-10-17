// SPDX-License-Identifier: Apache-2.0

// The agent on the real disk: recordings start, end at the seal or a stop,
// are stopped in the catalog, and a restarted agent lists them.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;
use crate::catalog::StopReason;
use crate::disk::StdDisk;
use crate::recorder::{Frames, SourceError};

/// A source of `chunks` from `position`, sealed after them when `seal`.
struct Chunks {
    position: u64,
    chunks: VecDeque<Vec<u8>>,
    seal: bool,
    /// Set once every chunk was read.
    drained: Arc<AtomicBool>,
}

/// Waits until `flag` is set, at most five seconds.
fn wait(flag: &AtomicBool) {
    for _ in 0..5000 {
        if flag.load(Ordering::Acquire) {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("the source was not drained");
}

impl FrameSource for Chunks {
    fn position(&self) -> u64 {
        self.position
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        let Some(chunk) = self.chunks.pop_front() else {
            self.drained.store(true, Ordering::Release);
            return Ok(if self.seal {
                Frames::Sealed { at: self.position }
            } else {
                Frames::Pending
            });
        };
        let position = self.position;
        out[..chunk.len()].copy_from_slice(&chunk);
        self.position += chunk.len() as u64;
        Ok(Frames::Copied {
            position,
            len: chunk.len(),
            next: self.position,
        })
    }

    fn consumed(&mut self, _position: u64) -> Result<(), SourceError> {
        Ok(())
    }

    fn resume(&mut self, to: u64) -> Result<(), SourceError> {
        self.position = to;
        Ok(())
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-archive-agent-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

fn start(source: Chunks) -> StartRecording {
    StartRecording {
        stream_id: 10,
        session_id: 3,
        channel: b"karyos:ipc".to_vec(),
        geometry: Geometry::new(4096, 8192).unwrap(),
        policy: SyncPolicy::PerSegment,
        mode: Mode::Required,
        source: Box::new(source),
    }
}

/// A recording ends at its seal and is stopped in the catalog; another is
/// stopped by command; a restarted agent lists both, stopped.
#[test]
fn recordings_end_and_survive_a_restart() {
    let dir = temp_dir("restart");
    let config = AgentConfig {
        idle: Duration::from_millis(1),
        ..AgentConfig::default()
    };
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    let sealed = agent
        .start(start(Chunks {
            position: 0,
            chunks: vec![vec![1u8; 3000], vec![2u8; 3000], vec![3u8; 3000]].into(),
            seal: true,
            drained: Arc::default(),
        }))
        .unwrap();
    let event = agent.event(Duration::from_secs(5)).unwrap();
    assert_eq!(
        event,
        Event::Ended {
            id: sealed,
            ended: Ended {
                position: 9000,
                reason: StopReason::Normal,
                incomplete: false
            }
        }
    );
    let drained = Arc::new(AtomicBool::new(false));
    let open = agent
        .start(start(Chunks {
            position: 64,
            chunks: vec![vec![4u8; 100]].into(),
            seal: false,
            drained: Arc::clone(&drained),
        }))
        .unwrap();
    assert_ne!(open, sealed);
    // Once its source is drained, its duty recorded the chunk; the stop is
    // served before the next duty.
    wait(&drained);
    let ended = agent.stop(open).unwrap();
    assert_eq!(ended.position, 164);
    assert!(matches!(
        agent.stop(open),
        Err(AgentError::NotRecording { .. })
    ));
    agent.shutdown().unwrap();

    let restarted = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    let recordings = restarted.recordings().unwrap();
    assert_eq!(recordings.len(), 2);
    assert_eq!(recordings[0].stop.unwrap().position, 9000);
    assert_eq!(recordings[1].start, 64);
    assert_eq!(recordings[1].stop.unwrap().position, 164);
    restarted.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Shutting down stops what still records, at its written position.
#[test]
fn a_shutdown_stops_what_records() {
    let dir = temp_dir("shutdown");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let drained = Arc::new(AtomicBool::new(false));
    let id = agent
        .start(start(Chunks {
            position: 0,
            chunks: vec![vec![9u8; 500]].into(),
            seal: false,
            drained: Arc::clone(&drained),
        }))
        .unwrap();
    wait(&drained);
    agent.shutdown().unwrap();
    let restarted = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let recording = restarted.recordings().unwrap().pop().unwrap();
    assert_eq!(recording.id, id);
    assert_eq!(recording.stop.unwrap().position, 500);
    drop(restarted);
    std::fs::remove_dir_all(&dir).unwrap();
}
