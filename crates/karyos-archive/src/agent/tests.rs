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

fn format() -> crate::catalog::StreamFormat {
    crate::catalog::StreamFormat {
        lane: karyos_sys::frame::Lane::ZERO,
        initial_term_id: 0,
        mtu: core::num::NonZeroU32::new(1408).unwrap(),
        source: crate::catalog::SourceIncarnation {
            driver: [1, 2],
            registration: 3,
            incarnation: 1,
        },
    }
}

fn start(source: Chunks) -> StartRecording {
    StartRecording {
        stream_id: 10,
        session_id: 3,
        channel: b"karyos:ipc".to_vec(),
        geometry: Geometry::new(4096, 8192).unwrap(),
        policy: SyncPolicy::PerSegment,
        mode: Mode::Required,
        format: format(),
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
    // The whole first segment was written before the roll failed.
    assert_eq!(
        event,
        Event::Failed {
            id,
            failure: Failure::Store,
            position: 8192,
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

/// Frames of 96 bytes each (a multiple of the 32-byte alignment), with
/// their length in their first word and `fill` after it.
fn frames(count: usize, fill: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..count {
        let mut frame = vec![fill; 96];
        frame[..4].copy_from_slice(&96i32.to_le_bytes());
        bytes.extend_from_slice(&frame);
    }
    bytes
}

/// What a sink saw, shared with the test.
#[derive(Default)]
struct Seen {
    bytes: Vec<u8>,
    calls: usize,
    finished: Option<(u64, bool)>,
}

/// A sink that refuses its first `refuse` steps for lack of room, then
/// takes them while `open` is set; closed when `closed` is.
struct Sink {
    seen: Arc<std::sync::Mutex<Seen>>,
    refuse: usize,
    open: Arc<AtomicBool>,
    closed: bool,
}

impl Sink {
    fn new(seen: &Arc<std::sync::Mutex<Seen>>) -> Self {
        Self {
            seen: Arc::clone(seen),
            refuse: 0,
            open: Arc::new(AtomicBool::new(true)),
            closed: false,
        }
    }

    fn take(&mut self, position: u64, bytes: &[u8]) -> Result<bool, SinkClosed> {
        if self.closed {
            return Err(SinkClosed);
        }
        let mut seen = self.seen.lock().unwrap();
        seen.calls += 1;
        if self.refuse > 0 || !self.open.load(Ordering::Acquire) {
            self.refuse = self.refuse.saturating_sub(1);
            return Ok(false);
        }
        assert_eq!(position, seen.bytes.len() as u64);
        seen.bytes.extend_from_slice(bytes);
        Ok(true)
    }
}

impl ReplaySink for Sink {
    fn frames(&mut self, position: u64, bytes: &[u8]) -> Result<bool, SinkClosed> {
        self.take(position, bytes)
    }

    fn fill(&mut self, position: u64, record: &[u8], _extent: u32) -> Result<bool, SinkClosed> {
        self.take(position, record)
    }

    fn gap(&mut self, _from: u64, _to: u64) -> Result<bool, SinkClosed> {
        panic!("no gap was recorded");
    }

    fn finish(&mut self, end: u64, complete: bool) {
        self.seen.lock().unwrap().finished = Some((end, complete));
    }
}

/// A recording of three chunks of two frames each, ended at its seal.
fn sealed_recording(agent: &ArchiveHandle) -> (u64, Vec<u8>) {
    let chunks: Vec<Vec<u8>> = (1..=3).map(|fill| frames(2, fill)).collect();
    let all = chunks.concat();
    let id = agent
        .start(start(Chunks {
            chunks: chunks.into(),
            seal: true,
            ..Chunks::default()
        }))
        .unwrap();
    assert!(matches!(
        agent.event(Duration::from_secs(5)).unwrap(),
        Event::Ended { .. }
    ));
    (id, all)
}

/// The next replay that ended, waiting up to five seconds.
fn replay_ended(agent: &ArchiveHandle) -> ReplayEnded {
    for _ in 0..5000 {
        if let Some(ended) = agent.try_replay_ended() {
            return ended;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("no replay ended");
}

fn replay_of(recording_id: u64, to: u64, sink: Sink) -> StartReplay {
    StartReplay {
        recording_id,
        from: 0,
        to,
        rate: Rate::Full,
        sink: Box::new(sink),
    }
}

/// A recording replays into its sink byte for byte, in order, and the
/// replay ends complete; a sink without room is given the same step again.
#[test]
fn a_recording_replays_into_its_sink() {
    let dir = temp_dir("replay");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let (recording, all) = sealed_recording(&agent);
    let end = all.len() as u64;
    assert_eq!(agent.describe(recording).unwrap().end, end);
    for refuse in [0, 3] {
        let seen = Arc::default();
        let id = agent
            .replay(replay_of(
                recording,
                end,
                Sink {
                    refuse,
                    ..Sink::new(&seen)
                },
            ))
            .unwrap();
        assert_eq!(
            replay_ended(&agent),
            ReplayEnded {
                id,
                position: end,
                outcome: ReplayOutcome::Complete
            }
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.bytes, all, "refusing {refuse}");
        assert_eq!(seen.finished, Some((end, true)));
        assert!(seen.calls > refuse);
    }
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A stopped replay finishes its sink incomplete where it is and reports
/// no event; a closed sink fails its replay.
#[test]
fn a_replay_stops_by_command_or_when_its_sink_closes() {
    let dir = temp_dir("replay-stop");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let (recording, all) = sealed_recording(&agent);
    let end = all.len() as u64;
    let seen = Arc::default();
    let sink = Sink::new(&seen);
    sink.open.store(false, Ordering::Release);
    let id = agent.replay(replay_of(recording, end, sink)).unwrap();
    // Asked at least once, refused.
    for _ in 0..5000 {
        if seen.lock().unwrap().calls > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(agent.stop_replay(id).unwrap(), 0);
    assert_eq!(seen.lock().unwrap().finished, Some((0, false)));
    assert!(matches!(
        agent.stop_replay(id),
        Err(AgentError::Unknown { .. })
    ));
    assert_eq!(agent.try_event(), None);
    assert_eq!(agent.try_replay_ended(), None);

    let seen = Arc::default();
    let closed = Sink {
        closed: true,
        ..Sink::new(&seen)
    };
    let id = agent.replay(replay_of(recording, end, closed)).unwrap();
    assert_eq!(
        replay_ended(&agent),
        ReplayEnded {
            id,
            position: 0,
            outcome: ReplayOutcome::Failed
        }
    );
    assert_eq!(seen.lock().unwrap().finished, Some((0, false)));
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A replay of an unknown recording or an unreadable range is refused, its
/// sink finished incomplete; an open recording ends at its written
/// position; a shutdown finishes the replays that run.
#[test]
fn replays_are_refused_described_and_shut_down() {
    let dir = temp_dir("replay-refused");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let (recording, all) = sealed_recording(&agent);
    let end = all.len() as u64;
    let seen = Arc::default();
    assert!(matches!(
        agent.replay(replay_of(recording + 1, end, Sink::new(&seen))),
        Err(AgentError::Unknown { .. })
    ));
    assert_eq!(seen.lock().unwrap().finished, Some((0, false)));
    let seen = Arc::default();
    assert!(matches!(
        agent.replay(StartReplay {
            from: 32,
            ..replay_of(recording, end, Sink::new(&seen))
        }),
        Err(AgentError::Replay(ReplayError::NotAFrameBoundary { .. }))
    ));
    assert_eq!(seen.lock().unwrap().finished, Some((32, false)));
    assert!(matches!(
        agent.describe(recording + 1),
        Err(AgentError::Unknown { .. })
    ));

    let drained = Arc::new(AtomicBool::new(false));
    let open = agent
        .start(start(Chunks {
            position: 0,
            chunks: vec![frames(1, 7)].into(),
            drained: Arc::clone(&drained),
            ..Chunks::default()
        }))
        .unwrap();
    wait(&drained);
    let described = agent.describe(open).unwrap();
    assert_eq!(described.end, 96);
    assert_eq!(described.recording.stop, None);

    let seen = Arc::default();
    let sink = Sink::new(&seen);
    sink.open.store(false, Ordering::Release);
    agent.replay(replay_of(recording, end, sink)).unwrap();
    agent.shutdown().unwrap();
    assert_eq!(seen.lock().unwrap().finished, Some((0, false)));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A posted command's answer, waiting up to five seconds.
fn answer<T>(posted: Result<Posted<T>, AgentError>) -> Result<T, AgentError> {
    let posted = posted.unwrap();
    for _ in 0..5000 {
        if let Some(answer) = posted.try_answer() {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("no answer");
}

/// #387 review P2: recordings and replays at once are capped. A start or a
/// replay past the cap is refused, typed and counted, and a refused
/// replay's sink is finished; a prepared replay counts.
#[test]
fn recordings_and_replays_are_capped() {
    let dir = temp_dir("caps");
    let config = AgentConfig {
        max_recordings: 1,
        max_replays: 1,
        ..AgentConfig::default()
    };
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    // Ended: no longer counted.
    let (recording, all) = sealed_recording(&agent);
    let end = all.len() as u64;
    let open = agent.start(start(Chunks::default())).unwrap();
    assert!(matches!(
        agent.start(start(Chunks::default())),
        Err(AgentError::Full {
            what: "recordings",
            max: 1
        })
    ));
    assert_eq!(agent.refused(), 1);
    // A replay that waits for room holds the one slot.
    let seen = Arc::default();
    let sink = Sink::new(&seen);
    sink.open.store(false, Ordering::Release);
    let running = agent.replay(replay_of(recording, end, sink)).unwrap();
    let refused = Arc::default();
    assert!(matches!(
        agent.replay(replay_of(recording, end, Sink::new(&refused))),
        Err(AgentError::Full {
            what: "replays",
            max: 1
        })
    ));
    assert_eq!(refused.lock().unwrap().finished, Some((0, false)));
    agent.stop_replay(running).unwrap();
    let prepare = PrepareReplay {
        recording_id: recording,
        position: 0,
        length: u64::MAX,
        rate: Rate::Full,
    };
    answer(agent.post_prepare_replay(prepare)).unwrap();
    assert!(matches!(
        answer(agent.post_prepare_replay(prepare)),
        Err(AgentError::Full { .. })
    ));
    assert_eq!(agent.refused(), 3);
    agent.stop(open).unwrap();
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// #387 review P2: a replay is prepared before any target exists. Its range
/// is checked against the recording's start, its end and its index; a
/// prepared replay runs once its sink is attached, and is dropped when
/// stopped, after which a sink attached to it is finished.
#[test]
fn a_replay_is_prepared_then_attached() {
    let dir = temp_dir("prepare");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let (recording, all) = sealed_recording(&agent);
    let end = all.len() as u64;
    let prepare = |recording_id, position, length| PrepareReplay {
        recording_id,
        position,
        length,
        rate: Rate::Full,
    };
    for (position, length) in [(32, 96), (0, end + 96), (end, u64::MAX), (0, 0)] {
        let refused = answer(agent.post_prepare_replay(prepare(recording, position, length)));
        assert!(
            matches!(
                refused,
                Err(AgentError::Replay(
                    ReplayError::NotAFrameBoundary { .. } | ReplayError::OutOfRange { .. }
                ))
            ),
            "{position}, {length}: {refused:?}"
        );
    }
    assert!(matches!(
        answer(agent.post_prepare_replay(prepare(recording + 1, 0, 96))),
        Err(AgentError::Unknown { .. })
    ));
    // A recording that starts at 192 has nothing below it.
    let later = agent
        .start(start(Chunks {
            position: 192,
            chunks: vec![frames(1, 9)].into(),
            seal: true,
            ..Chunks::default()
        }))
        .unwrap();
    assert!(matches!(
        agent.event(Duration::from_secs(5)).unwrap(),
        Event::Ended { .. }
    ));
    assert!(matches!(
        answer(agent.post_prepare_replay(prepare(later, 96, 192))),
        Err(AgentError::Replay(ReplayError::OutOfRange { .. }))
    ));
    let prepared = answer(agent.post_prepare_replay(prepare(recording, 0, u64::MAX))).unwrap();
    assert_eq!(
        (prepared.recording.id, prepared.from, prepared.to),
        (recording, 0, end)
    );
    let seen = Arc::default();
    let id = answer(agent.post_attach_replay(prepared.replay_id, 0, Box::new(Sink::new(&seen))))
        .unwrap();
    assert_eq!(id, prepared.replay_id);
    assert_eq!(
        replay_ended(&agent),
        ReplayEnded {
            id,
            position: end,
            outcome: ReplayOutcome::Complete
        }
    );
    assert_eq!(seen.lock().unwrap().bytes, all);
    let prepared = answer(agent.post_prepare_replay(prepare(recording, 192, 192))).unwrap();
    assert_eq!(prepared.to, 384);
    assert_eq!(
        answer(agent.post_stop_replay(prepared.replay_id)).unwrap(),
        192
    );
    let seen = Arc::default();
    assert!(matches!(
        answer(agent.post_attach_replay(prepared.replay_id, 192, Box::new(Sink::new(&seen)))),
        Err(AgentError::Unknown { .. })
    ));
    assert_eq!(seen.lock().unwrap().finished, Some((192, false)));
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A sink that logs its tag for each step it takes, once `open`.
struct Tagged {
    tag: char,
    log: Arc<std::sync::Mutex<Vec<char>>>,
    open: Arc<AtomicBool>,
}

impl Tagged {
    fn take(&mut self) -> Result<bool, SinkClosed> {
        if !self.open.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.log.lock().unwrap().push(self.tag);
        Ok(true)
    }
}

impl ReplaySink for Tagged {
    fn frames(&mut self, _position: u64, _bytes: &[u8]) -> Result<bool, SinkClosed> {
        self.take()
    }

    fn fill(&mut self, _position: u64, _record: &[u8], _extent: u32) -> Result<bool, SinkClosed> {
        self.take()
    }

    fn gap(&mut self, _from: u64, _to: u64) -> Result<bool, SinkClosed> {
        self.take()
    }

    fn finish(&mut self, _end: u64, _complete: bool) {}
}

/// #387 review P2: the replays share one budget per cycle, in turn. With
/// room for one step a cycle, two replays alternate, step for step.
#[test]
fn replays_share_a_budget_in_turn() {
    let dir = temp_dir("share");
    let config = AgentConfig {
        replay_budget: 1,
        ..AgentConfig::default()
    };
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    let (recording, all) = sealed_recording(&agent);
    let end = all.len() as u64;
    let log = Arc::default();
    let open = Arc::new(AtomicBool::new(false));
    for tag in ['a', 'b'] {
        agent
            .replay(StartReplay {
                recording_id: recording,
                from: 0,
                to: end,
                rate: Rate::Full,
                sink: Box::new(Tagged {
                    tag,
                    log: Arc::clone(&log),
                    open: Arc::clone(&open),
                }),
            })
            .unwrap();
    }
    open.store(true, Ordering::Release);
    replay_ended(&agent);
    replay_ended(&agent);
    let log = log.lock().unwrap();
    // Three entries each, taken one a cycle, by turns while both have one
    // left. The cycle the sinks open in may give the second replay the
    // first step and its turn next, so the turns are counted from the
    // second step.
    assert_eq!(log.len(), 6);
    let both = ['a', 'b']
        .iter()
        .map(|tag| log.iter().rposition(|taken| taken == tag).unwrap())
        .min()
        .unwrap();
    assert!(
        log[1..=both].windows(2).all(|pair| pair[0] != pair[1]),
        "{log:?}"
    );
    drop(log);
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// #387 review P3: a recording whose store cannot be created is stopped
/// empty at its start, never left open; the next one records.
#[test]
fn a_recording_whose_store_cannot_be_created_stops_empty() {
    let dir = temp_dir("store-create");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    // Recording 1's first segment name is taken.
    let taken = dir.join(format!("{:016x}-{:016x}.seg", 1, 0));
    std::fs::create_dir(&taken).unwrap();
    assert!(matches!(
        agent.start(start(Chunks::default())),
        Err(AgentError::Segment(_))
    ));
    let stop = agent.recordings().unwrap()[0].stop.unwrap();
    assert_eq!((stop.position, stop.reason), (0, StopReason::Empty));
    assert!(matches!(
        agent.stop(1),
        Err(AgentError::NotRecording { id: 1 })
    ));
    std::fs::remove_dir(&taken).unwrap();
    assert_eq!(agent.start(start(Chunks::default())).unwrap(), 2);
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// #387 re-check P3-1: a prepared replay whose sink never comes, its
/// attach or stop lost, is dropped after the timeout: its slot is free
/// again, and a late attach finds it gone and finishes its sink.
#[test]
fn a_prepared_replay_never_attached_expires() {
    let dir = temp_dir("expire");
    let config = AgentConfig {
        max_replays: 1,
        prepared_timeout: Duration::from_millis(200),
        ..AgentConfig::default()
    };
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    let (recording, _) = sealed_recording(&agent);
    let prepare = PrepareReplay {
        recording_id: recording,
        position: 0,
        length: u64::MAX,
        rate: Rate::Full,
    };
    let lost = answer(agent.post_prepare_replay(prepare)).unwrap();
    assert!(matches!(
        answer(agent.post_prepare_replay(prepare)),
        Err(AgentError::Full { .. })
    ));
    // Refused while the lost one holds the slot, then taken once it
    // expired: at most five seconds.
    let begun = std::time::Instant::now();
    let again = loop {
        match answer(agent.post_prepare_replay(prepare)) {
            Ok(again) => break again,
            Err(AgentError::Full { .. }) => {
                assert!(begun.elapsed() < Duration::from_secs(5), "never expired");
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("{error:?}"),
        }
    };
    assert!(begun.elapsed() >= Duration::from_millis(100));
    assert_ne!(again.replay_id, lost.replay_id);
    let seen = Arc::default();
    assert!(matches!(
        answer(agent.post_attach_replay(lost.replay_id, 0, Box::new(Sink::new(&seen)))),
        Err(AgentError::Unknown { .. })
    ));
    assert_eq!(seen.lock().unwrap().finished, Some((0, false)));
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

mod groups {
    //! A7d-1c: recording groups the agent captures, their references
    //! covered by the recordings it keeps, settled when a recording ends,
    //! and recovered after a restart.

    use super::*;
    use crate::group::capture::{CaptureConfig, GroupState, Refusal};
    use crate::group::journal::{JournalConfig, MIN_SEGMENT_LENGTH};
    use crate::group::record::{
        Capture, EndOutcome, EventEnd, GroupRecord, MAX_RECORD, MessageEvent, Payload,
    };

    const GROUP: u64 = 5;

    fn chunks(bytes: usize, seal: bool, drained: &Arc<AtomicBool>) -> Chunks {
        Chunks {
            position: 0,
            chunks: vec![vec![7u8; bytes]].into(),
            seal,
            fail: false,
            gate: None,
            drained: Arc::clone(drained),
        }
    }

    fn start_group(dir: &Path, capture: Option<Capture>) -> StartGroup {
        StartGroup {
            group_id: GROUP,
            dir: dir.to_path_buf(),
            new: capture.map(|capture| NewGroup {
                first_group_seq: 1,
                inline_threshold: 4096,
                capture,
                manifest: b"m".to_vec(),
            }),
            journal: JournalConfig {
                segment_length: MIN_SEGMENT_LENGTH,
                policy: SyncPolicy::Every { interval_ns: 0 },
            },
            capture: CaptureConfig {
                ring_capacity: 1 << 16,
                max_event: 4096,
                in_flight: 64,
            },
        }
    }

    /// Event `seq`: a message naming `recording`'s frames `[0, 64)`.
    fn referencing(seq: u64, recording: u64) -> Vec<u8> {
        let mut out = vec![0u8; MAX_RECORD];
        let mut bytes = Vec::new();
        for record in [
            GroupRecord::Message(MessageEvent {
                group_seq: seq,
                logical_time: seq,
                incarnation: 1,
                position: 0,
                extent: 64,
                stream_id: 10,
                session_id: 3,
                lane: karyos_sys::frame::Lane::ZERO,
                reserved_value: 0,
                end_of_stream: false,
                extension: None,
                payload: Payload::Reference {
                    recording_id: recording,
                    length: 10,
                },
            }),
            GroupRecord::End(EventEnd {
                group_seq: seq,
                observations: 0,
                outcome: EndOutcome::Complete,
            }),
        ] {
            let length = record.encode(&mut out).unwrap();
            bytes.extend_from_slice(&out[..length]);
        }
        bytes
    }

    fn groups_dir(dir: &Path) -> PathBuf {
        let groups = dir.join("groups");
        std::fs::create_dir(&groups).unwrap();
        groups
    }

    /// A group refers to a `required` recording's frames: complete once
    /// written, durable once the recording's stop made them durable; and a
    /// restarted agent recovers the group with the reference covered by
    /// the stopped recording the catalog keeps as `required`.
    #[test]
    fn a_covered_reference_survives_a_restart() {
        let dir = temp_dir("group-restart");
        let groups = groups_dir(&dir);
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let drained = Arc::new(AtomicBool::new(false));
        let recording = agent.start(start(chunks(3000, false, &drained))).unwrap();
        wait(&drained);
        let mut sender = agent
            .start_group(start_group(&groups, Some(Capture::Strict)))
            .unwrap();
        sender.admit().unwrap();
        sender.send(&referencing(1, recording), 1).unwrap();
        let waiter = sender.waiter();
        // The recording's frames are written, not durable yet: the event
        // is complete, not durable.
        for _ in 0..5000 {
            if sender.view().complete_recording_seq() == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            (sender.view().snapshot(), sender.state()),
            ((1, 1, 0), GroupState::Running)
        );
        // The stop closes the store, durable to 3000, which covers it.
        assert_eq!(agent.stop(recording).unwrap().position, 3000);
        assert_eq!(waiter.wait_durable(1, Duration::from_secs(5)), Ok(1));
        agent.shutdown().unwrap();
        assert_eq!(sender.state(), GroupState::Ended);
        let restarted = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        assert!(restarted.recordings().unwrap()[0].required);
        let recovered = restarted.start_group(start_group(&groups, None)).unwrap();
        assert_eq!(recovered.view().snapshot(), (1, 1, 1));
        restarted.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A reference its recording stops short of: a strict group ends, a
    /// best-effort one marks it and goes on.
    #[test]
    fn a_recording_that_stops_short_settles_its_references() {
        for capture in [Capture::Strict, Capture::BestEffort] {
            let dir = temp_dir("group-short");
            let groups = groups_dir(&dir);
            let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
            let drained = Arc::new(AtomicBool::new(false));
            let recording = agent.start(start(chunks(32, false, &drained))).unwrap();
            wait(&drained);
            let mut sender = agent
                .start_group(start_group(&groups, Some(capture)))
                .unwrap();
            sender.send(&referencing(1, recording), 1).unwrap();
            let waiter = sender.waiter();
            assert_eq!(agent.stop(recording).unwrap().position, 32);
            match capture {
                Capture::Strict => {
                    assert!(matches!(
                        waiter.wait_durable(1, Duration::from_secs(5)),
                        Err(crate::group::capture::WaitError::Stopped {
                            state: GroupState::Ended,
                            ..
                        })
                    ));
                    assert_eq!(sender.admit(), Err(Refusal::Ended));
                }
                Capture::BestEffort => {
                    assert_eq!(waiter.wait_durable(1, Duration::from_secs(5)), Ok(1));
                    assert_eq!(sender.state(), GroupState::Running);
                }
            }
            agent.shutdown().unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// An `async` recording vouches for nothing: the catalog keeps it as
    /// `async`, a reference to it never completes while it records, and
    /// its stop marks the reference unavailable whatever it wrote.
    #[test]
    fn an_async_recording_covers_no_reference() {
        let dir = temp_dir("group-async");
        let groups = groups_dir(&dir);
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let drained = Arc::new(AtomicBool::new(false));
        let recording = agent
            .start(StartRecording {
                mode: Mode::Async {
                    on_lap: crate::recorder::OnLap::Resume,
                },
                ..start(chunks(3000, false, &drained))
            })
            .unwrap();
        wait(&drained);
        assert!(!agent.recordings().unwrap()[0].required);
        let mut sender = agent
            .start_group(start_group(&groups, Some(Capture::BestEffort)))
            .unwrap();
        sender.send(&referencing(1, recording), 1).unwrap();
        for _ in 0..5000 {
            if sender.view().delivered_seq() == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        // Drained, and never complete: the recording vouches for nothing.
        for _ in 0..200 {
            assert_eq!(sender.view().snapshot(), (1, 0, 0));
            std::thread::sleep(Duration::from_millis(1));
        }
        agent.stop(recording).unwrap();
        assert_eq!(
            sender.waiter().wait_durable(1, Duration::from_secs(5)),
            Ok(1)
        );
        agent.shutdown().unwrap();
        // Marked, not covered: after a restart the event still completes,
        // though the recording vouches for nothing.
        let restarted = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let recovered = restarted.start_group(start_group(&groups, None)).unwrap();
        assert_eq!(recovered.view().snapshot(), (1, 1, 1));
        restarted.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A reference sent after its `async` recording ended is marked
    /// unavailable, whatever the recording wrote: it vouches for nothing.
    #[test]
    fn a_late_reference_to_an_ended_async_recording_is_marked() {
        let dir = temp_dir("group-late-async");
        let groups = groups_dir(&dir);
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let drained = Arc::new(AtomicBool::new(false));
        let recording = agent
            .start(StartRecording {
                mode: Mode::Async {
                    on_lap: crate::recorder::OnLap::Resume,
                },
                ..start(chunks(3000, false, &drained))
            })
            .unwrap();
        wait(&drained);
        agent.stop(recording).unwrap();
        let mut sender = agent
            .start_group(start_group(&groups, Some(Capture::BestEffort)))
            .unwrap();
        sender.send(&referencing(1, recording), 1).unwrap();
        assert_eq!(
            sender.waiter().wait_durable(1, Duration::from_secs(5)),
            Ok(1)
        );
        agent.shutdown().unwrap();
        let restarted = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let recovered = restarted.start_group(start_group(&groups, None)).unwrap();
        assert_eq!(recovered.view().snapshot(), (1, 1, 1), "marked");
        restarted.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The operating system's files, failing every write and sync to a
    /// recording's segments once `fail` is set; group journals, in their
    /// own directory, and the catalog keep working.
    #[derive(Debug, Clone)]
    struct Failing {
        fail: Arc<AtomicBool>,
    }

    #[derive(Debug)]
    struct FailingFile {
        file: std::fs::File,
        segment: bool,
    }

    impl Failing {
        fn check(&self, file: &FailingFile) -> std::io::Result<()> {
            if file.segment && self.fail.load(Ordering::Acquire) {
                Err(std::io::Error::other("failing"))
            } else {
                Ok(())
            }
        }
    }

    fn segment(path: &Path) -> bool {
        path.extension().is_some_and(|extension| extension == "seg")
            && !path.components().any(|part| part.as_os_str() == "groups")
    }

    impl Disk for Failing {
        type File = FailingFile;

        fn create(&mut self, path: &Path) -> std::io::Result<FailingFile> {
            Ok(FailingFile {
                file: StdDisk.create(path)?,
                segment: segment(path),
            })
        }

        fn open(&mut self, path: &Path) -> std::io::Result<FailingFile> {
            Ok(FailingFile {
                file: StdDisk.open(path)?,
                segment: segment(path),
            })
        }

        fn open_read(&mut self, path: &Path) -> std::io::Result<FailingFile> {
            Ok(FailingFile {
                file: StdDisk.open_read(path)?,
                segment: segment(path),
            })
        }

        fn write_at(
            &mut self,
            file: &FailingFile,
            offset: u64,
            bytes: &[u8],
        ) -> std::io::Result<()> {
            self.check(file)?;
            StdDisk.write_at(&file.file, offset, bytes)
        }

        fn read_at(
            &mut self,
            file: &FailingFile,
            offset: u64,
            buf: &mut [u8],
        ) -> std::io::Result<()> {
            StdDisk.read_at(&file.file, offset, buf)
        }

        fn len(&mut self, file: &FailingFile) -> std::io::Result<u64> {
            StdDisk.len(&file.file)
        }

        fn set_len(&mut self, file: &FailingFile, len: u64) -> std::io::Result<()> {
            self.check(file)?;
            StdDisk.set_len(&file.file, len)
        }

        fn sync(&mut self, file: &FailingFile) -> std::io::Result<()> {
            self.check(file)?;
            StdDisk.sync(&file.file)
        }

        fn sync_dir(&mut self, dir: &Path) -> std::io::Result<()> {
            StdDisk.sync_dir(dir)
        }

        fn list(&mut self, dir: &Path) -> std::io::Result<Vec<String>> {
            StdDisk.list(dir)
        }

        fn remove(&mut self, path: &Path) -> std::io::Result<()> {
            StdDisk.remove(path)
        }

        fn rename(&mut self, from: &Path, to: &Path) -> std::io::Result<()> {
            StdDisk.rename(from, to)
        }
    }

    /// A stop whose close fails leaves no stop in the catalog: the agent
    /// settles the groups' references by what was durable before it, here
    /// nothing, so a strict group ends.
    #[test]
    fn a_failed_stop_settles_by_what_was_durable() {
        let dir = temp_dir("group-failed-stop");
        let groups = groups_dir(&dir);
        let fail = Arc::new(AtomicBool::new(false));
        let disk = Failing {
            fail: Arc::clone(&fail),
        };
        let agent = ArchiveHandle::spawn(disk, &dir, AgentConfig::default()).unwrap();
        let drained = Arc::new(AtomicBool::new(false));
        let recording = agent.start(start(chunks(3000, false, &drained))).unwrap();
        wait(&drained);
        let mut sender = agent
            .start_group(start_group(&groups, Some(Capture::Strict)))
            .unwrap();
        sender.send(&referencing(1, recording), 1).unwrap();
        for _ in 0..5000 {
            if sender.view().complete_recording_seq() == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(sender.view().complete_recording_seq(), 1);
        fail.store(true, Ordering::Release);
        assert!(agent.stop(recording).is_err());
        assert!(matches!(
            sender.waiter().wait_durable(1, Duration::from_secs(5)),
            Err(crate::group::capture::WaitError::Stopped {
                state: GroupState::Ended,
                ..
            })
        ));
        drop(agent);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A recording whose store fails while it records leaves no stop in
    /// the catalog: the agent settles the groups' references by what was
    /// durable before, here nothing, so a strict group ends.
    #[test]
    fn a_store_failure_settles_by_what_was_durable() {
        let dir = temp_dir("group-store-failure");
        let groups = groups_dir(&dir);
        let fail = Arc::new(AtomicBool::new(false));
        let disk = Failing {
            fail: Arc::clone(&fail),
        };
        let agent = ArchiveHandle::spawn(disk, &dir, AgentConfig::default()).unwrap();
        let gate = Arc::new(AtomicBool::new(false));
        let drained = Arc::new(AtomicBool::new(false));
        let recording = agent
            .start(start(Chunks {
                gate: Some(Arc::clone(&gate)),
                ..chunks(3000, false, &drained)
            }))
            .unwrap();
        let mut sender = agent
            .start_group(start_group(&groups, Some(Capture::Strict)))
            .unwrap();
        sender.send(&referencing(1, recording), 1).unwrap();
        for _ in 0..5000 {
            if sender.view().delivered_seq() == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        // The recording's first write fails.
        fail.store(true, Ordering::Release);
        gate.store(true, Ordering::Release);
        assert!(matches!(
            sender.waiter().wait_durable(1, Duration::from_secs(5)),
            Err(crate::group::capture::WaitError::Stopped {
                state: GroupState::Ended,
                ..
            })
        ));
        drop(agent);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A source that hands out its chunks as they are released.
    struct Released {
        position: u64,
        chunks: VecDeque<Vec<u8>>,
        released: Arc<std::sync::atomic::AtomicUsize>,
        read: usize,
    }

    impl FrameSource for Released {
        fn position(&self) -> u64 {
            self.position
        }

        fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
            if self.read >= self.released.load(Ordering::Acquire) {
                return Ok(Frames::Pending);
            }
            let Some(chunk) = self.chunks.pop_front() else {
                return Ok(Frames::Pending);
            };
            self.read += 1;
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

    /// An `async` recording whose store fails vouches for nothing, even
    /// with its frames durable past a reference: a strict group ends.
    #[test]
    fn an_async_store_failure_covers_no_reference() {
        let dir = temp_dir("group-async-failure");
        let groups = groups_dir(&dir);
        let fail = Arc::new(AtomicBool::new(false));
        let disk = Failing {
            fail: Arc::clone(&fail),
        };
        let agent = ArchiveHandle::spawn(disk, &dir, AgentConfig::default()).unwrap();
        let released = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let recording = agent
            .start(StartRecording {
                mode: Mode::Async {
                    on_lap: crate::recorder::OnLap::Resume,
                },
                policy: SyncPolicy::Every { interval_ns: 0 },
                source: Box::new(Released {
                    position: 0,
                    chunks: vec![vec![7u8; 3000], vec![8u8; 3000]].into(),
                    released: Arc::clone(&released),
                    read: 0,
                }),
                ..start(chunks(0, false, &Arc::default()))
            })
            .unwrap();
        // The first chunk is durable.
        for _ in 0..5000 {
            if agent.describe(recording).unwrap().end == 3000 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(agent.describe(recording).unwrap().end, 3000);
        let mut sender = agent
            .start_group(start_group(&groups, Some(Capture::Strict)))
            .unwrap();
        sender.send(&referencing(1, recording), 1).unwrap();
        for _ in 0..5000 {
            if sender.view().delivered_seq() == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        // The second chunk's write fails.
        fail.store(true, Ordering::Release);
        released.store(2, Ordering::Release);
        assert!(matches!(
            sender.waiter().wait_durable(1, Duration::from_secs(5)),
            Err(crate::group::capture::WaitError::Stopped {
                state: GroupState::Ended,
                ..
            })
        ));
        drop(agent);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A group is captured once, within the agent's bound, and stopped by
    /// id: its journal closed and its sender then refusing.
    #[test]
    fn groups_start_once_and_stop_by_id() {
        let dir = temp_dir("group-commands");
        let groups = groups_dir(&dir);
        let config = AgentConfig {
            max_groups: 1,
            ..AgentConfig::default()
        };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
        let sender = agent
            .start_group(start_group(&groups, Some(Capture::Strict)))
            .unwrap();
        assert!(matches!(
            agent.start_group(start_group(&groups, Some(Capture::Strict))),
            Err(AgentError::Full { what: "groups", .. })
        ));
        assert!(matches!(
            agent.stop_group(GROUP + 1),
            Err(AgentError::Unknown { .. })
        ));
        agent.stop_group(GROUP).unwrap();
        assert_eq!(sender.admit(), Err(Refusal::Ended));
        let config = AgentConfig::default();
        drop(agent);
        let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
        let _first = agent.start_group(start_group(&groups, None)).unwrap();
        assert!(matches!(
            agent.start_group(start_group(&groups, None)),
            Err(AgentError::GroupCaptured { id: GROUP })
        ));
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
