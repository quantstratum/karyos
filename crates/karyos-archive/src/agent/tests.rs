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

/// A source of `chunks` from `position`, sealed after them when `seal`,
/// revoked after them when `fail`.
#[derive(Default)]
struct Chunks {
    position: u64,
    chunks: VecDeque<Vec<u8>>,
    seal: bool,
    fail: bool,
    /// Reads nothing until set.
    gate: Option<Arc<AtomicBool>>,
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
        if self
            .gate
            .as_ref()
            .is_some_and(|gate| !gate.load(Ordering::Acquire))
        {
            return Ok(Frames::Pending);
        }
        let Some(chunk) = self.chunks.pop_front() else {
            self.drained.store(true, Ordering::Release);
            if self.fail {
                return Err(SourceError::Revoked);
            }
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

    fn resume(&mut self, to: u64) -> Result<u64, SourceError> {
        self.position = to;
        Ok(to)
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
            fail: false,
            gate: None,
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
            fail: false,
            gate: None,
            drained: Arc::clone(&drained),
        }))
        .unwrap();
    assert_ne!(open, sealed);
    // Once its source is drained, its duty recorded the chunk; the stop is
    // served before the next duty.
    wait(&drained);
    let ended = agent.stop(open).unwrap();
    assert_eq!(ended.position, 164);
    assert_eq!(ended.reason, StopReason::Stopped);
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
    assert_eq!(recordings[0].stop.unwrap().reason, StopReason::Normal);
    assert_eq!(recordings[1].stop.unwrap().reason, StopReason::Stopped);
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
            fail: false,
            gate: None,
            drained: Arc::clone(&drained),
        }))
        .unwrap();
    wait(&drained);
    agent.shutdown().unwrap();
    let restarted = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let recording = restarted.recordings().unwrap().pop().unwrap();
    assert_eq!(recording.id, id);
    assert_eq!(recording.stop.unwrap().position, 500);
    assert_eq!(recording.stop.unwrap().reason, StopReason::Shutdown);
    drop(restarted);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// #341 review P2: a source that fails ends its recording, closed and
/// stopped with a typed reason, and the other recordings go on.
#[test]
fn a_failed_source_is_stopped_and_the_others_record_on() {
    let dir = temp_dir("failed-source");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    // Both read from the same duty on, so the failure meets the other
    // recording mid-flight.
    let gate = Arc::new(AtomicBool::new(false));
    let failing = agent
        .start(start(Chunks {
            chunks: vec![vec![5u8; 700]].into(),
            fail: true,
            gate: Some(Arc::clone(&gate)),
            ..Chunks::default()
        }))
        .unwrap();
    let sealed = agent
        .start(start(Chunks {
            chunks: (0..8).map(|i| vec![i; 900]).collect(),
            seal: true,
            gate: Some(Arc::clone(&gate)),
            ..Chunks::default()
        }))
        .unwrap();
    gate.store(true, Ordering::Release);
    let mut events = Vec::new();
    while events.len() < 2 {
        events.push(agent.event(Duration::from_secs(5)).unwrap());
    }
    assert!(events.contains(&Event::Ended {
        id: failing,
        ended: Ended {
            position: 700,
            reason: StopReason::Failed(crate::catalog::FailKind::Source),
            incomplete: false,
        }
    }));
    assert!(events.contains(&Event::Ended {
        id: sealed,
        ended: Ended {
            position: 7200,
            reason: StopReason::Normal,
            incomplete: false,
        }
    }));
    let recordings = agent.recordings().unwrap();
    assert_eq!(
        recordings[0].stop.map(|stop| stop.reason),
        Some(StopReason::Failed(crate::catalog::FailKind::Source))
    );
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A source that holds its second chunk until `gate` is set.
struct Gated {
    position: u64,
    chunks: VecDeque<Vec<u8>>,
    gate: Arc<AtomicBool>,
    waiting: Arc<AtomicBool>,
}

impl FrameSource for Gated {
    fn position(&self) -> u64 {
        self.position
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        let held = self.chunks.len() == 1 && !self.gate.load(Ordering::Acquire);
        let chunk = match self.chunks.front() {
            Some(_) if held => None,
            Some(_) => self.chunks.pop_front(),
            None => None,
        };
        let Some(chunk) = chunk else {
            self.waiting.store(true, Ordering::Release);
            return Ok(Frames::Pending);
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

    fn resume(&mut self, to: u64) -> Result<u64, SourceError> {
        self.position = to;
        Ok(to)
    }
}

/// #341 review P2: a store that fails leaves its recording open for the
/// next start to settle, says so with a typed event, and refuses a stop
/// as failed; the restart stops it at what its segments hold.
#[test]
fn a_failed_store_is_left_to_settle() {
    let dir = temp_dir("failed-store");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let gate = Arc::new(AtomicBool::new(false));
    let waiting = Arc::new(AtomicBool::new(false));
    let id = agent
        .start(StartRecording {
            source: Box::new(Gated {
                position: 0,
                // A whole first segment, then a write that must roll.
                chunks: vec![vec![6u8; 8192], vec![7u8; 100]].into(),
                gate: Arc::clone(&gate),
                waiting: Arc::clone(&waiting),
            }),
            ..start(Chunks::default())
        })
        .unwrap();
    wait(&waiting);
    // The next segment cannot be created where the directory was.
    let moved = dir.with_extension("moved");
    std::fs::rename(&dir, &moved).unwrap();
    gate.store(true, Ordering::Release);
    let event = agent.event(Duration::from_secs(5)).unwrap();
    std::fs::rename(&moved, &dir).unwrap();
    assert_eq!(
        event,
        Event::Failed {
            id,
            failure: Failure::Store
        }
    );
    assert!(matches!(
        agent.stop(id),
        Err(AgentError::RecordingFailed { id: failed }) if failed == id
    ));
    assert!(agent.recordings().unwrap()[0].stop.is_none());
    agent.shutdown().unwrap();
    let restarted = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let stop = restarted.recordings().unwrap()[0].stop.unwrap();
    assert_eq!((stop.position, stop.reason), (8192, StopReason::Recovered));
    restarted.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A source that panics on its first read, taking the agent's thread with
/// it.
struct Panics;

impl FrameSource for Panics {
    fn position(&self) -> u64 {
        0
    }

    fn read(&mut self, _out: &mut [u8]) -> Result<Frames, SourceError> {
        panic!("the source panics on the agent's thread");
    }

    fn consumed(&mut self, _position: u64) -> Result<(), SourceError> {
        Ok(())
    }

    fn resume(&mut self, to: u64) -> Result<u64, SourceError> {
        Ok(to)
    }
}

/// A command to an agent whose thread is gone returns `Gone` at once: the
/// blocking send and the reply both see the closed channel.
#[test]
fn a_command_to_a_dead_agent_is_gone() {
    let dir = temp_dir("dead");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    // The start is answered before the first duty, which panics.
    let _ = agent.start(StartRecording {
        source: Box::new(Panics),
        ..start(Chunks::default())
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match agent.recordings() {
            Err(AgentError::Gone) => break,
            Ok(_) => assert!(std::time::Instant::now() < deadline, "the agent never died"),
            Err(error) => panic!("{error:?}"),
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(matches!(agent.stop(1), Err(AgentError::Gone)));
    assert!(matches!(agent.shutdown(), Err(AgentError::Gone)));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A command stop whose close fails (a no-sync segment it cannot reopen)
/// returns the error, leaves the recording to settle, and a second stop
/// is refused as failed.
#[test]
fn a_failed_stop_is_remembered() {
    let dir = temp_dir("failed-stop");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let drained = Arc::new(AtomicBool::new(false));
    let id = agent
        .start(StartRecording {
            policy: SyncPolicy::None,
            ..start(Chunks {
                // A whole first segment finished unsynced, then a roll.
                chunks: vec![vec![1u8; 8192], vec![2u8; 100]].into(),
                drained: Arc::clone(&drained),
                ..Chunks::default()
            })
        })
        .unwrap();
    wait(&drained);
    let moved = dir.with_extension("moved");
    std::fs::rename(&dir, &moved).unwrap();
    let first = agent.stop(id);
    std::fs::rename(&moved, &dir).unwrap();
    assert!(first.is_err(), "{first:?}");
    assert!(matches!(
        agent.stop(id),
        Err(AgentError::RecordingFailed { id: failed }) if failed == id
    ));
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
