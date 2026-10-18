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
            checkpoints: None,
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
        assert_eq!(agent.refused(), 1);
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

    /// Settings that cannot work are refused before the journal exists,
    /// so a retry with the same new group starts it.
    #[test]
    fn a_refused_group_start_leaves_no_journal() {
        let dir = temp_dir("group-refused");
        let groups = groups_dir(&dir);
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let mut refused = start_group(&groups, Some(Capture::Strict));
        refused.capture.in_flight = 0;
        assert!(matches!(
            agent.start_group(refused),
            Err(AgentError::Capture(CaptureError::InFlight))
        ));
        let mut unsynced = start_group(&groups, Some(Capture::Strict));
        unsynced.journal.policy = SyncPolicy::None;
        assert!(matches!(
            agent.start_group(unsynced),
            Err(AgentError::Capture(CaptureError::NoSync))
        ));
        agent
            .start_group(start_group(&groups, Some(Capture::Strict)))
            .unwrap();
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A reference drained after its recording failed, past the frames
    /// durable at the failure: marked in best effort, and a strict group
    /// ends.
    #[test]
    fn a_late_uncovered_reference_to_a_failed_recording_is_settled() {
        for capture in [Capture::BestEffort, Capture::Strict] {
            let dir = temp_dir("probe-late-uncovered");
            let groups = groups_dir(&dir);
            let fail = Arc::new(AtomicBool::new(false));
            let (agent, recording, released) = failing_required(&dir, &fail);
            let mut sender = agent
                .start_group(start_group(&groups, Some(capture)))
                .unwrap();
            fail.store(true, Ordering::Release);
            released.store(2, Ordering::Release);
            let event = agent.event(Duration::from_secs(5));
            assert!(matches!(event, Some(Event::Failed { .. })), "{event:?}");
            let mut out = vec![0u8; MAX_RECORD];
            let mut bytes = Vec::new();
            for record in [
                GroupRecord::Message(MessageEvent {
                    group_seq: 1,
                    logical_time: 1,
                    incarnation: 1,
                    position: 3000,
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
                    group_seq: 1,
                    observations: 0,
                    outcome: EndOutcome::Complete,
                }),
            ] {
                let length = record.encode(&mut out).unwrap();
                bytes.extend_from_slice(&out[..length]);
            }
            sender.send(&bytes, 1).unwrap();
            let result = sender.waiter().wait_durable(1, Duration::from_secs(3));
            match capture {
                Capture::BestEffort => assert_eq!(result, Ok(1)),
                Capture::Strict => assert!(matches!(
                    result,
                    Err(crate::group::capture::WaitError::Stopped {
                        state: GroupState::Ended,
                        ..
                    })
                )),
            }
            drop(agent);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// `stop_group` returns promptly while a best-effort sender, past its
    /// in-flight bound, keeps sending: the sender is refused as closing.
    #[test]
    #[allow(clippy::too_many_lines, reason = "one scenario")]
    fn stop_group_refuses_a_live_sender() {
        let dir = temp_dir("probe-live-sender");
        let groups = groups_dir(&dir);
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let drained = Arc::new(AtomicBool::new(false));
        let recording = agent.start(start(chunks(3000, false, &drained))).unwrap();
        wait(&drained);
        agent.stop(recording).unwrap();
        let mut sender = agent
            .start_group(start_group(&groups, Some(Capture::BestEffort)))
            .unwrap();
        // Event 1 ends incomplete: the best-effort prefixes stop, and the
        // in-flight bound no longer holds the sender back.
        let mut first = referencing(1, recording);
        let mut out = vec![0u8; MAX_RECORD];
        let end = GroupRecord::End(EventEnd {
            group_seq: 1,
            observations: 0,
            outcome: EndOutcome::Incomplete,
        });
        let length = end.encode(&mut out).unwrap();
        let complete_len = {
            let complete = GroupRecord::End(EventEnd {
                group_seq: 1,
                observations: 0,
                outcome: EndOutcome::Complete,
            });
            complete.encode(&mut vec![0u8; MAX_RECORD]).unwrap()
        };
        first.truncate(first.len() - complete_len);
        first.extend_from_slice(&out[..length]);
        sender.admit().unwrap();
        sender.send(&first, 1).unwrap();
        let halt = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let producer = {
            let halt = Arc::clone(&halt);
            let sent = Arc::clone(&sent);
            std::thread::spawn(move || {
                let mut seq = 2u64;
                while !halt.load(Ordering::Acquire) {
                    match sender.admit() {
                        Ok(()) => {
                            if let Err(refusal) = sender.send(&referencing(seq, recording), seq) {
                                return Some(refusal);
                            }
                            sent.store(seq, Ordering::Release);
                            seq += 1;
                        }
                        Err(refusal @ (Refusal::Ended | Refusal::Failed | Refusal::Closing)) => {
                            return Some(refusal);
                        }
                        Err(_) => std::thread::yield_now(),
                    }
                }
                None
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        let fired = Arc::new(AtomicBool::new(false));
        let watchdog = {
            let halt = Arc::clone(&halt);
            let fired = Arc::clone(&fired);
            std::thread::spawn(move || {
                // Stops the sender if the stop hangs; ends early once it
                // returned.
                for _ in 0..1500 {
                    if halt.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !halt.swap(true, Ordering::AcqRel) {
                    fired.store(true, Ordering::Release);
                }
            })
        };
        let begun = std::time::Instant::now();
        let result = agent.stop_group(GROUP);
        let took = begun.elapsed();
        // The closed group refuses the sender, which then stops on its own.
        let state = producer.join().unwrap();
        halt.store(true, Ordering::Release);
        watchdog.join().unwrap();
        result.unwrap();
        assert!(!fired.load(Ordering::Acquire), "took {took:?}");
        assert!(took < Duration::from_secs(5), "took {took:?}");
        assert!(sent.load(Ordering::Acquire) > 1);
        // Refused as closing, or as ended once the close was done.
        assert!(
            matches!(state, Some(Refusal::Closing | Refusal::Ended)),
            "{state:?}"
        );
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Failures arrive one after another, more than the recording cap,
    /// while a group runs: each failed entry is dropped, when a start needs
    /// its slot, once the group has read its ring empty after the failure,
    /// so the cap's slots come back. A reference sent after the latest
    /// failure settles by its durable frames; one to a reclaimed entry is
    /// settled as uncovered, never left waiting.
    #[test]
    fn failed_entries_last_until_the_groups_have_read_past_them() {
        let dir = temp_dir("group-many-failures");
        let groups = groups_dir(&dir);
        let fail = Arc::new(AtomicBool::new(false));
        let disk = Failing {
            fail: Arc::clone(&fail),
        };
        let config = AgentConfig {
            max_recordings: 2,
            ..AgentConfig::default()
        };
        let agent = ArchiveHandle::spawn(disk, &dir, config).unwrap();
        let mut sender = agent
            .start_group(start_group(&groups, Some(Capture::BestEffort)))
            .unwrap();
        let mut first = None;
        let mut last = 0;
        for round in 0..6 {
            fail.store(false, Ordering::Release);
            let released = Arc::new(std::sync::atomic::AtomicUsize::new(1));
            // A start can meet the slot of the previous failure until the
            // group has read past it: retried, never refused for good.
            let mut started = None;
            for _ in 0..5000 {
                match agent.start(StartRecording {
                    policy: SyncPolicy::Every { interval_ns: 0 },
                    source: Box::new(Released {
                        position: 0,
                        chunks: vec![vec![7u8; 3000], vec![8u8; 3000]].into(),
                        released: Arc::clone(&released),
                        read: 0,
                    }),
                    ..start(chunks(0, false, &Arc::default()))
                }) {
                    Ok(id) => {
                        started = Some(id);
                        break;
                    }
                    Err(AgentError::Full { .. }) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("{error:?}"),
                }
            }
            last = started.unwrap_or_else(|| panic!("round {round}: refused for good"));
            first.get_or_insert(last);
            for _ in 0..5000 {
                if agent.describe(last).unwrap().end == 3000 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            fail.store(true, Ordering::Release);
            released.store(2, Ordering::Release);
            let event = agent.event(Duration::from_secs(5));
            assert!(matches!(event, Some(Event::Failed { .. })), "{event:?}");
        }
        // The latest failure's entry is kept: its durable frames cover.
        sender.send(&referencing(1, last), 1).unwrap();
        assert_eq!(
            sender.waiter().wait_durable(1, Duration::from_secs(5)),
            Ok(1)
        );
        // The first one's was reclaimed: a reference that raced it covers
        // nothing, and is marked rather than left waiting.
        sender.send(&referencing(2, first.unwrap()), 2).unwrap();
        assert_eq!(
            sender.waiter().wait_durable(2, Duration::from_secs(5)),
            Ok(2)
        );
        assert_eq!(sender.state(), GroupState::Running);
        drop(agent);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn failing_required(
        dir: &Path,
        fail: &Arc<AtomicBool>,
    ) -> (ArchiveHandle, u64, Arc<std::sync::atomic::AtomicUsize>) {
        let disk = Failing {
            fail: Arc::clone(fail),
        };
        let agent = ArchiveHandle::spawn(disk, dir, AgentConfig::default()).unwrap();
        let released = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let recording = agent
            .start(StartRecording {
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
        for _ in 0..5000 {
            if agent.describe(recording).unwrap().end == 3000 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        (agent, recording, released)
    }

    /// A reference drained after its `required` recording failed is
    /// settled by the frames durable at the failure: covered, in each mode.
    #[test]
    fn a_late_reference_to_a_failed_recording_is_settled() {
        for capture in [Capture::BestEffort, Capture::Strict] {
            let dir = temp_dir("probe-late-failed");
            let groups = groups_dir(&dir);
            let fail = Arc::new(AtomicBool::new(false));
            let (agent, recording, released) = failing_required(&dir, &fail);
            let mut sender = agent
                .start_group(start_group(&groups, Some(capture)))
                .unwrap();
            fail.store(true, Ordering::Release);
            released.store(2, Ordering::Release);
            let event = agent.event(Duration::from_secs(5));
            assert!(matches!(event, Some(Event::Failed { .. })), "{event:?}");
            // Sent before the failure was known, drained after it.
            sender.send(&referencing(1, recording), 1).unwrap();
            let result = sender.waiter().wait_durable(1, Duration::from_secs(5));
            assert_eq!(result, Ok(1), "{capture:?}");
            assert_eq!(sender.view().snapshot(), (1, 1, 1), "{capture:?}");
            assert_eq!(sender.state(), GroupState::Running, "{capture:?}");
            drop(agent);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// After a restart, a stopped `async` recording still vouches for
    /// nothing: a strict group that referred to it stays ended.
    #[test]
    fn a_stopped_async_recording_covers_nothing_after_a_restart() {
        let dir = temp_dir("probe-async-restart");
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
        let mut sender = agent
            .start_group(start_group(&groups, Some(Capture::Strict)))
            .unwrap();
        sender.send(&referencing(1, recording), 1).unwrap();
        agent.stop(recording).unwrap();
        let live = sender.waiter().wait_durable(1, Duration::from_secs(5));
        assert!(
            matches!(
                live,
                Err(crate::group::capture::WaitError::Stopped {
                    state: GroupState::Ended,
                    ..
                })
            ),
            "{live:?}"
        );
        agent.shutdown().unwrap();
        let restarted = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let recovered = restarted.start_group(start_group(&groups, None)).unwrap();
        let again = recovered.waiter().wait_durable(1, Duration::from_secs(2));
        assert!(
            matches!(
                again,
                Err(crate::group::capture::WaitError::Stopped {
                    state: GroupState::Ended,
                    ..
                })
            ),
            "{again:?}"
        );
        restarted.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A `required` recording fails with a waiting reference its durable
    /// frames cover: settled covered, and the strict group runs on.
    #[test]
    fn a_failed_required_recording_covers_by_its_durable_frames() {
        let dir = temp_dir("probe-failed-covers");
        let groups = groups_dir(&dir);
        let fail = Arc::new(AtomicBool::new(false));
        let (agent, recording, released) = failing_required(&dir, &fail);
        let mut start = start_group(&groups, Some(Capture::Strict));
        start.journal.policy = SyncPolicy::PerSegment;
        let mut sender = agent.start_group(start).unwrap();
        sender.send(&referencing(1, recording), 1).unwrap();
        for _ in 0..5000 {
            if sender.view().complete_recording_seq() == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(sender.view().snapshot(), (1, 1, 0));
        fail.store(true, Ordering::Release);
        released.store(2, Ordering::Release);
        let event = agent.event(Duration::from_secs(5));
        assert!(matches!(event, Some(Event::Failed { .. })), "{event:?}");
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(sender.state(), GroupState::Running);
        assert_eq!(sender.view().complete_recording_seq(), 1);
        drop(agent);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A store failure with frames written and not durable settles by the
    /// durable ones, none here: a strict group ends.
    #[test]
    fn a_store_failure_settles_by_durable_not_written() {
        let dir = temp_dir("probe-written");
        let groups = groups_dir(&dir);
        let fail = Arc::new(AtomicBool::new(false));
        let disk = Failing {
            fail: Arc::clone(&fail),
        };
        let agent = ArchiveHandle::spawn(disk, &dir, AgentConfig::default()).unwrap();
        let released = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let recording = agent
            .start(StartRecording {
                source: Box::new(Released {
                    position: 0,
                    chunks: vec![vec![7u8; 3000], vec![8u8; 3000]].into(),
                    released: Arc::clone(&released),
                    read: 0,
                }),
                ..start(chunks(0, false, &Arc::default()))
            })
            .unwrap();
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
        assert_eq!(sender.view().snapshot(), (1, 1, 0));
        fail.store(true, Ordering::Release);
        released.store(2, Ordering::Release);
        let event = agent.event(Duration::from_secs(5));
        assert!(matches!(event, Some(Event::Failed { .. })), "{event:?}");
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(sender.state(), GroupState::Ended);
        drop(agent);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An event sent right before `stop_group` is drained into the journal
    /// before it closes.
    #[test]
    fn stop_group_drains_the_ring() {
        for _ in 0..20 {
            let dir = temp_dir("probe-stop-group");
            let groups = groups_dir(&dir);
            let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
            let drained = Arc::new(AtomicBool::new(false));
            let recording = agent.start(start(chunks(3000, false, &drained))).unwrap();
            wait(&drained);
            agent.stop(recording).unwrap();
            let mut sender = agent
                .start_group(start_group(&groups, Some(Capture::Strict)))
                .unwrap();
            sender.admit().unwrap();
            sender.send(&referencing(1, recording), 1).unwrap();
            agent.stop_group(GROUP).unwrap();
            agent.shutdown().unwrap();
            let restarted = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
            let recovered = restarted.start_group(start_group(&groups, None)).unwrap();
            assert_eq!(recovered.view().snapshot(), (1, 1, 1));
            restarted.shutdown().unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

mod checkpoints {
    //! A9-3: a group's checkpoints through the agent: written in chunks
    //! under the cycle's byte budget, recorded, read back after a restart,
    //! and a range they open waking the waiters on events it let go.

    use super::*;
    use crate::group::capture::{CaptureConfig, GroupState, WaitError};
    use crate::group::checkpoint::{LastCheckpoint, recorded_end, store_dir};
    use crate::group::journal::{JournalConfig, MIN_SEGMENT_LENGTH};
    use crate::group::record::{
        Capture, EndOutcome, EventEnd, GapMarker, GapReason, GroupRecord, MAX_RECORD, TimerEvent,
    };

    const GROUP: u64 = 6;

    fn journal_config(policy: SyncPolicy) -> JournalConfig {
        JournalConfig {
            segment_length: MIN_SEGMENT_LENGTH,
            policy,
        }
    }

    fn start(
        dir: &Path,
        capture: Option<Capture>,
        policy: SyncPolicy,
        in_flight: usize,
    ) -> StartGroup {
        StartGroup {
            group_id: GROUP,
            dir: dir.join("groups"),
            new: capture.map(|capture| NewGroup {
                first_group_seq: 1,
                inline_threshold: 4096,
                capture,
                manifest: b"m".to_vec(),
            }),
            journal: journal_config(policy),
            capture: CaptureConfig {
                ring_capacity: 1 << 16,
                max_event: 4096,
                in_flight,
            },
            checkpoints: Some(GroupCheckpoints {
                max_checkpoint: 300_000,
                reopen_hold: None,
            }),
        }
    }

    fn dirs(name: &str) -> PathBuf {
        let dir = temp_dir(name);
        std::fs::create_dir(dir.join("groups")).unwrap();
        std::fs::create_dir(store_dir(&dir.join("groups"))).unwrap();
        dir
    }

    fn encode(records: &[GroupRecord<'_>]) -> Vec<u8> {
        let mut out = vec![0u8; MAX_RECORD];
        let mut bytes = Vec::new();
        for record in records {
            let length = record.encode(&mut out).unwrap();
            bytes.extend_from_slice(&out[..length]);
        }
        bytes
    }

    fn event(seq: u64) -> Vec<u8> {
        encode(&[
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
        ])
    }

    fn gap(seq: u64) -> Vec<u8> {
        encode(&[GroupRecord::Gap(GapMarker {
            from_seq: seq,
            to_seq: seq,
            reason: GapReason::RingFull,
        })])
    }

    /// Polls `handle` until its last checkpoint ended.
    fn ended(handle: &mut crate::group::checkpoint::CheckpointHandle) -> LastCheckpoint {
        for _ in 0..10_000 {
            handle.poll();
            if let Some(last) = handle.last_checkpoint() {
                return last;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("the checkpoint never ended");
    }

    /// A 200 kB checkpoint through the handle, written 16 kB a cycle: it
    /// is recorded once whole, the buffer comes back, and after a restart
    /// the group and its store recover, the bytes read back exactly.
    #[test]
    fn a_checkpoint_through_the_handle_is_recorded_and_survives_a_restart() {
        let dir = dirs("checkpoint-restart");
        let config = AgentConfig {
            checkpoint_budget: 16 * 1024,
            ..AgentConfig::default()
        };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let mut sender = agent
            .start_group(start(&dir, Some(Capture::Strict), policy, 64))
            .unwrap();
        let mut handle = sender.take_checkpoints().unwrap();
        assert!(sender.take_checkpoints().is_none(), "taken once");
        for seq in 1..=2 {
            sender.admit().unwrap();
            sender.send(&event(seq), seq).unwrap();
        }
        let snapshot: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        handle
            .checkpoint(2, 7, |buffer| {
                buffer[..snapshot.len()].copy_from_slice(&snapshot);
                snapshot.len()
            })
            .unwrap();
        let LastCheckpoint::Recorded(record) = ended(&mut handle) else {
            panic!("not recorded: {:?}", handle.last_checkpoint());
        };
        assert_eq!(
            (record.group_seq, record.checkpoint_id, record.length),
            (2, 1, 200_000)
        );
        assert_eq!(handle.stats().recorded, 1);
        // The buffer is back: another checkpoint is taken.
        sender.admit().unwrap();
        sender.send(&event(3), 3).unwrap();
        handle
            .checkpoint(3, 7, |buffer| {
                buffer[0] = 3;
                1
            })
            .unwrap();
        assert!(matches!(ended(&mut handle), LastCheckpoint::Recorded(_)));
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        let restarted = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
        let mut recovered = restarted
            .start_group(start(&dir, None, policy, 64))
            .unwrap();
        assert_eq!(recovered.state(), GroupState::Running);
        assert!(recovered.take_checkpoints().is_some());
        restarted.stop_group(GROUP).unwrap();
        restarted.shutdown().unwrap();
        // The bytes, read back from the recovered store.
        let mut journal =
            GroupJournal::recover(StdDisk, &dir.join("groups"), GROUP, journal_config(policy))
                .unwrap()
                .journal;
        let end = recorded_end(&mut journal).unwrap();
        let mut store = CheckpointStore::recover(
            StdDisk,
            &store_dir(&dir.join("groups")),
            GROUP,
            journal_config(policy),
            end,
        )
        .unwrap();
        let mut bytes = vec![0u8; 200_000];
        store.read(record.position, &mut bytes).unwrap();
        assert_eq!(bytes, snapshot);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A best-effort group: event 1, then a gap at 2. A
    /// waiter on event 2 hears at once when the checkpoint at 2 opens a
    /// range: Stopped, never durable, not at its deadline. The range then
    /// takes events again, the in-flight bound back.
    #[test]
    fn a_range_opened_through_the_agent_wakes_a_waiter_and_lifts_the_stop() {
        let dir = dirs("checkpoint-range");
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let mut sender = agent
            .start_group(start(
                &dir,
                Some(Capture::BestEffort),
                SyncPolicy::Every { interval_ns: 0 },
                8,
            ))
            .unwrap();
        let mut handle = sender.take_checkpoints().unwrap();
        sender.admit().unwrap();
        sender.send(&event(1), 1).unwrap();
        sender.room().unwrap();
        sender.send(&gap(2), 2).unwrap();
        let waiter = sender.waiter();
        let waiting = std::thread::spawn(move || {
            let begun = Instant::now();
            (
                waiter.wait_durable(2, Duration::from_secs(20)),
                begun.elapsed(),
            )
        });
        std::thread::sleep(Duration::from_millis(50));
        handle
            .checkpoint(2, 7, |buffer| {
                buffer[..5].copy_from_slice(b"state");
                5
            })
            .unwrap();
        assert!(matches!(ended(&mut handle), LastCheckpoint::Recorded(_)));
        let (woke, after) = waiting.join().unwrap();
        assert!(matches!(woke, Err(WaitError::Stopped { .. })), "{woke:?}");
        assert!(after < Duration::from_secs(10), "{after:?}");
        sender.admit().unwrap();
        sender.send(&event(3), 3).unwrap();
        // The new range's events become durable, its checkpoint held.
        assert_eq!(
            sender.waiter().wait_durable(3, Duration::from_secs(10)),
            Ok(3)
        );
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        assert_ne!(sender.state(), GroupState::Failed);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn start_with(dir: &Path, capture: Option<Capture>, policy: SyncPolicy) -> StartGroup {
        start(dir, capture, policy, 64)
    }

    /// Waits until `sender` admits an event.
    fn admitted(sender: &crate::group::capture::CaptureSender) {
        for _ in 0..10_000 {
            if sender.admit().is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("never admitted");
    }

    /// #426 re-check P1 and h4: with room for 2 events in flight, 6 end
    /// while a checkpoint reopening the range is written 1 byte a cycle.
    /// The reopening window holds them, configured (8) or by default
    /// (four times `in_flight`): the range opens over them, durable to 8,
    /// and a restart recovers it so, its recovery sized to the same hold.
    #[test]
    fn the_reopen_hold_spans_a_chunked_write_and_a_restart() {
        for (name, hold) in [("configured", Some(8)), ("default", None)] {
            let dir = dirs(&format!("checkpoint-hold-{name}"));
            let policy = SyncPolicy::Every { interval_ns: 0 };
            let started = |dir: &Path, capture: Option<Capture>| StartGroup {
                checkpoints: Some(GroupCheckpoints {
                    max_checkpoint: 300_000,
                    reopen_hold: hold,
                }),
                ..start(dir, capture, policy, 2)
            };
            let slow = AgentConfig {
                checkpoint_budget: 1,
                ..AgentConfig::default()
            };
            let agent = ArchiveHandle::spawn(StdDisk, &dir, slow).unwrap();
            let mut sender = agent
                .start_group(started(&dir, Some(Capture::BestEffort)))
                .unwrap();
            let mut handle = sender.take_checkpoints().unwrap();
            sender.admit().unwrap();
            sender.send(&event(1), 1).unwrap();
            sender.room().unwrap();
            sender.send(&gap(2), 2).unwrap();
            handle
                .checkpoint(2, 7, |buffer| {
                    buffer[..20_000].fill(5);
                    20_000
                })
                .unwrap();
            for seq in 3..=8 {
                admitted(&sender);
                sender.send(&event(seq), seq).unwrap();
            }
            handle.poll();
            assert!(
                handle.last_checkpoint().is_none(),
                "{name}: the events must end while the checkpoint is written"
            );
            assert!(matches!(ended(&mut handle), LastCheckpoint::Recorded(_)));
            assert_eq!(
                sender.waiter().wait_durable(8, Duration::from_secs(10)),
                Ok(8),
                "{name}"
            );
            agent.stop_group(GROUP).unwrap();
            agent.shutdown().unwrap();
            let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
            let recovered = agent.start_group(started(&dir, None)).unwrap();
            assert_eq!(recovered.view().durable_group_seq(), 8, "{name}: recovered");
            agent.stop_group(GROUP).unwrap();
            agent.shutdown().unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Every path under `dir`, files and directories, relative to it.
    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(at) = stack.pop() {
            for entry in std::fs::read_dir(&at).unwrap() {
                let path = entry.unwrap().path();
                out.push(path.strip_prefix(dir).unwrap().to_path_buf());
                if path.is_dir() {
                    stack.push(path);
                }
            }
        }
        out
    }

    /// A group whose checkpoints keep `hold` events, `in_flight` events
    /// in flight.
    fn holding(
        dir: &Path,
        capture: Option<Capture>,
        in_flight: usize,
        hold: Option<usize>,
    ) -> StartGroup {
        StartGroup {
            checkpoints: Some(GroupCheckpoints {
                max_checkpoint: 300_000,
                reopen_hold: hold,
            }),
            ..start(
                dir,
                capture,
                SyncPolicy::Every { interval_ns: 0 },
                in_flight,
            )
        }
    }

    /// The shrink scenario of the #426 re-check: a best-effort group with
    /// room for 2 in flight and a hold of 8; event 1, gap 2, a checkpoint
    /// at 2 written 1 byte a cycle while events 3 to 8 end. The range
    /// opens over them: durable to 8. Returns the directory.
    fn reopened_over_six(name: &str) -> PathBuf {
        let dir = dirs(name);
        let slow = AgentConfig {
            checkpoint_budget: 1,
            ..AgentConfig::default()
        };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, slow).unwrap();
        let mut sender = agent
            .start_group(holding(&dir, Some(Capture::BestEffort), 2, Some(8)))
            .unwrap();
        let mut handle = sender.take_checkpoints().unwrap();
        sender.admit().unwrap();
        sender.send(&event(1), 1).unwrap();
        sender.room().unwrap();
        sender.send(&gap(2), 2).unwrap();
        handle
            .checkpoint(2, 7, |buffer| {
                buffer[..20_000].fill(5);
                20_000
            })
            .unwrap();
        for seq in 3..=8 {
            admitted(&sender);
            sender.send(&event(seq), seq).unwrap();
        }
        assert!(matches!(ended(&mut handle), LastCheckpoint::Recorded(_)));
        assert_eq!(
            sender.waiter().wait_durable(8, Duration::from_secs(10)),
            Ok(8)
        );
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        dir
    }

    /// Every file under `dir` with its length.
    fn files(dir: &Path) -> Vec<(PathBuf, u64)> {
        let mut files: Vec<_> = walk(dir)
            .into_iter()
            .map(|path| {
                let length = std::fs::metadata(dir.join(&path)).unwrap().len();
                (path, length)
            })
            .collect();
        files.sort();
        files
    }

    /// A9-5: the reopen hold is the journal header's, fixed per group. A
    /// restart with the same settings, with no hold named, or with a
    /// lower `in_flight` recovers the range at 8; one naming a smaller or
    /// larger hold, or an `in_flight` above the recorded hold, is
    /// refused, typed, and writes nothing.
    #[test]
    fn a_restart_takes_the_recorded_hold() {
        let dir = reopened_over_six("checkpoint-hold-recorded");
        let refused = |start: StartGroup, what: &str| {
            let before = files(&dir);
            let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
            assert!(
                matches!(agent.start_group(start), Err(AgentError::CheckpointConfig)),
                "{what}"
            );
            agent.shutdown().unwrap();
            assert_eq!(files(&dir), before, "{what}: something was written");
        };
        refused(holding(&dir, None, 2, Some(4)), "a smaller hold");
        refused(holding(&dir, None, 2, Some(16)), "a larger hold");
        refused(holding(&dir, None, 9, None), "in_flight above the hold");
        refused(
            StartGroup {
                checkpoints: None,
                ..holding(&dir, None, 2, None)
            },
            "checkpoints off",
        );
        for (what, start) in [
            ("the same settings", holding(&dir, None, 2, Some(8))),
            ("no hold named", holding(&dir, None, 2, None)),
            ("a lower in_flight", holding(&dir, None, 1, None)),
            // The effective window, max(4, 8), is the recorded 8.
            ("a hold below in_flight", holding(&dir, None, 8, Some(4))),
        ] {
            let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
            let recovered = agent.start_group(start).unwrap();
            assert_eq!(recovered.view().durable_group_seq(), 8, "{what}");
            agent.stop_group(GROUP).unwrap();
            agent.shutdown().unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #437 review P3: a journal whose header was never written. A restart
    /// is refused, typed, before the store is touched; started as new, the
    /// group writes its header into it and runs.
    #[test]
    fn a_headerless_journal_is_started_as_new() {
        let dir = dirs("checkpoint-headerless");
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let config = journal_config(policy);
        let geometry =
            crate::segment::Geometry::new(config.segment_length, u64::from(config.segment_length))
                .unwrap();
        let store = crate::segment::SegmentStore::create(
            StdDisk,
            &dir.join("groups"),
            GROUP,
            geometry,
            policy,
            0,
        )
        .unwrap();
        drop(store);
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let before = files(&dir);
        assert!(matches!(
            agent.start_group(start_with(&dir, None, policy)),
            Err(AgentError::NoHeader { id: GROUP })
        ));
        assert_eq!(files(&dir), before, "the store was touched");
        let mut sender = agent
            .start_group(start_with(&dir, Some(Capture::Strict), policy))
            .unwrap();
        assert_eq!(sender.state(), GroupState::Running);
        sender.admit().unwrap();
        sender.send(&event(1), 1).unwrap();
        assert_eq!(
            sender.waiter().wait_durable(1, Duration::from_secs(10)),
            Ok(1)
        );
        agent.stop_group(GROUP).unwrap();
        // Its header now there, starting it as new again is refused.
        assert!(
            agent
                .start_group(start_with(&dir, Some(Capture::Strict), policy))
                .is_err()
        );
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #437 review M6: a hold below `in_flight` is recorded as `in_flight`.
    #[test]
    fn a_hold_below_in_flight_is_recorded_as_in_flight() {
        let dir = dirs("checkpoint-hold-recorded-in-flight");
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let sender = agent
            .start_group(holding(&dir, Some(Capture::Strict), 4, Some(1)))
            .unwrap();
        drop(sender);
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let mut journal =
            GroupJournal::recover(StdDisk, &dir.join("groups"), GROUP, journal_config(policy))
                .unwrap()
                .journal;
        assert_eq!(journal.reopen_hold().unwrap(), Some(4));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #437 review P3: the default hold is computed only when the group is
    /// made: a restart naming no hold, with an `in_flight` whose default
    /// would pass the cap, takes the recorded hold.
    #[test]
    fn a_restart_computes_no_default_hold() {
        let dir = dirs("checkpoint-hold-no-default");
        let in_flight = MAX_REOPEN_HOLD / 4 + 1;
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let sender = agent
            .start_group(holding(
                &dir,
                Some(Capture::Strict),
                in_flight,
                Some(MAX_REOPEN_HOLD),
            ))
            .unwrap();
        drop(sender);
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let recovered = agent
            .start_group(holding(&dir, None, in_flight, None))
            .unwrap();
        assert_eq!(recovered.state(), GroupState::Running);
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A9-5: a group made without checkpoints records a hold of 0, and a
    /// restart with checkpoints is refused, typed.
    #[test]
    fn checkpoints_cannot_be_turned_on_at_a_restart() {
        let dir = dirs("checkpoint-hold-off-on");
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let without = StartGroup {
            checkpoints: None,
            ..start_with(&dir, Some(Capture::Strict), policy)
        };
        let mut sender = agent.start_group(without).unwrap();
        sender.admit().unwrap();
        sender.send(&event(1), 1).unwrap();
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        assert!(matches!(
            agent.start_group(start_with(&dir, None, policy)),
            Err(AgentError::CheckpointConfig)
        ));
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #426 re-check P2 (pre-existing): an `in_flight` above
    /// `MAX_IN_FLIGHT` is refused, typed, and the agent keeps running.
    #[test]
    fn a_huge_in_flight_is_refused_and_the_agent_survives() {
        let dir = dirs("checkpoint-huge-in-flight");
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        for in_flight in [1 << 60, crate::group::capture::MAX_IN_FLIGHT + 1] {
            let huge = StartGroup {
                checkpoints: None,
                ..start(&dir, Some(Capture::Strict), policy, in_flight)
            };
            assert!(
                matches!(
                    agent.start_group(huge),
                    Err(AgentError::Capture(
                        crate::group::capture::CaptureError::InFlight
                    ))
                ),
                "{in_flight}"
            );
        }
        let sender = agent
            .start_group(start_with(&dir, Some(Capture::Strict), policy))
            .unwrap();
        assert_eq!(sender.state(), GroupState::Running);
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #426 re-check P2: a reopen hold too large to allocate is refused,
    /// typed, before the journal exists; the agent keeps running and
    /// starts the group with a hold it can take.
    #[test]
    fn an_oversized_reopen_hold_is_refused_and_the_agent_survives() {
        let dir = dirs("checkpoint-hold-oversized");
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        // The host made `groups/` and its stores' directory (`dirs`); a
        // refused start leaves the tree as it was.
        let tree = |dir: &Path| {
            let mut names: Vec<_> = walk(dir);
            names.sort();
            names
        };
        let before = tree(&dir);
        for hold in [usize::MAX, MAX_REOPEN_HOLD + 1] {
            let start = StartGroup {
                checkpoints: Some(GroupCheckpoints {
                    max_checkpoint: 64,
                    reopen_hold: Some(hold),
                }),
                ..start_with(&dir, Some(Capture::BestEffort), policy)
            };
            assert!(
                matches!(agent.start_group(start), Err(AgentError::CheckpointConfig)),
                "{hold}"
            );
        }
        assert_eq!(tree(&dir), before, "a refused start made something");
        let start = StartGroup {
            checkpoints: Some(GroupCheckpoints {
                max_checkpoint: 64,
                reopen_hold: Some(MAX_REOPEN_HOLD),
            }),
            ..start_with(&dir, Some(Capture::BestEffort), policy)
        };
        let sender = agent.start_group(start).unwrap();
        assert_eq!(sender.state(), GroupState::Running);
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #426 re-check f: a best-effort group whose missing store held the
    /// checkpoint that reopened its range (event 1, gap 2, checkpoint 2,
    /// event 3) starts with that range lost: durable stays at 1, and the
    /// next checkpoint goes past the lost bytes and reopens it.
    #[test]
    fn a_missing_store_loses_a_best_effort_reopening() {
        let dir = dirs("checkpoint-missing-best-effort");
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let mut sender = agent
            .start_group(start_with(&dir, Some(Capture::BestEffort), policy))
            .unwrap();
        let mut handle = sender.take_checkpoints().unwrap();
        sender.admit().unwrap();
        sender.send(&event(1), 1).unwrap();
        sender.room().unwrap();
        sender.send(&gap(2), 2).unwrap();
        handle
            .checkpoint(2, 7, |buffer| {
                buffer[..5].copy_from_slice(b"state");
                5
            })
            .unwrap();
        let LastCheckpoint::Recorded(record) = ended(&mut handle) else {
            panic!("not recorded");
        };
        sender.admit().unwrap();
        sender.send(&event(3), 3).unwrap();
        assert_eq!(
            sender.waiter().wait_durable(3, Duration::from_secs(10)),
            Ok(3)
        );
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        let stores = store_dir(&dir.join("groups"));
        std::fs::remove_dir_all(&stores).unwrap();
        std::fs::create_dir(&stores).unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let mut recovered = agent.start_group(start_with(&dir, None, policy)).unwrap();
        assert_eq!(recovered.state(), GroupState::Running);
        assert_eq!(recovered.view().durable_group_seq(), 1, "the range is lost");
        let mut handle = recovered.take_checkpoints().unwrap();
        handle
            .checkpoint(3, 7, |buffer| {
                buffer[..5].copy_from_slice(b"after");
                5
            })
            .unwrap();
        let LastCheckpoint::Recorded(next) = ended(&mut handle) else {
            panic!("not recorded: {:?}", handle.last_checkpoint());
        };
        assert_eq!(next.position, record.end().unwrap());
        for _ in 0..5000 {
            if recovered.view().durable_group_seq() >= 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(recovered.view().durable_group_seq(), 3, "reopened at 3");
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #426 review P1, with recovery's coverage (mutant g): a restart
    /// whose journal ends at a gap, then the checkpoint that reopens the
    /// range. The sender counts the gap's events as sent, so it admits
    /// events again; and a second restart recovers the range the
    /// checkpoint opened, its store answering the coverage.
    #[test]
    fn a_restart_at_a_gap_reopens_through_a_checkpoint() {
        let dir = dirs("checkpoint-gap-restart");
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let mut sender = agent
            .start_group(start_with(&dir, Some(Capture::BestEffort), policy))
            .unwrap();
        sender.admit().unwrap();
        sender.send(&event(1), 1).unwrap();
        sender.room().unwrap();
        sender.send(&gap(2), 2).unwrap();
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let mut sender = agent.start_group(start(&dir, None, policy, 2)).unwrap();
        let mut handle = sender.take_checkpoints().unwrap();
        handle
            .checkpoint(2, 7, |buffer| {
                buffer[..5].copy_from_slice(b"state");
                5
            })
            .unwrap();
        assert!(matches!(ended(&mut handle), LastCheckpoint::Recorded(_)));
        // The range is open at 2, durable: the gap's events were sent.
        for _ in 0..5000 {
            if sender.view().durable_group_seq() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(sender.view().durable_group_seq(), 2);
        // Ten events through an in-flight bound of 2: admitted as the
        // earlier ones become durable.
        for seq in 3..=12 {
            admitted(&sender);
            sender.send(&event(seq), seq).unwrap();
        }
        assert_eq!(
            sender.waiter().wait_durable(12, Duration::from_secs(10)),
            Ok(12)
        );
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let recovered = agent.start_group(start(&dir, None, policy, 2)).unwrap();
        assert_eq!(
            recovered.view().durable_group_seq(),
            12,
            "the range recovered"
        );
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #426 review P2 and P3: a checkpoint after the group stopped is
    /// refused, typed, its buffer kept; one being written at the stop
    /// comes back the same way. Written 1 byte a cycle, a 200 kB one is
    /// still being written once taken (mutant a: the cycle's budget).
    #[test]
    fn a_checkpoint_at_or_after_the_stop_is_refused_with_its_buffer() {
        let dir = dirs("checkpoint-stop");
        let config = AgentConfig {
            checkpoint_budget: 1,
            ..AgentConfig::default()
        };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let mut sender = agent
            .start_group(start_with(&dir, Some(Capture::Strict), policy))
            .unwrap();
        let mut handle = sender.take_checkpoints().unwrap();
        sender.admit().unwrap();
        sender.send(&event(1), 1).unwrap();
        // The journal holds event 1: the write begins once taken.
        for _ in 0..5000 {
            if sender.view().complete_recording_seq() >= 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        handle
            .checkpoint(1, 7, |buffer| {
                buffer[..200_000].fill(3);
                200_000
            })
            .unwrap();
        for _ in 0..5000 {
            if !handle.pending() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!handle.pending(), "taken");
        agent.stop_group(GROUP).unwrap();
        assert_eq!(
            ended(&mut handle),
            LastCheckpoint::Failed { group_seq: 1 },
            "still being written at the stop"
        );
        assert!(matches!(
            handle.checkpoint(1, 7, |_| 1),
            Err(crate::group::checkpoint::CheckpointError::Stopped)
        ));
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #426 review P3: a group that ends answers what it holds, typed, and
    /// refuses what comes after.
    #[test]
    fn an_ended_group_refuses_its_checkpoints() {
        let dir = dirs("checkpoint-ended");
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let mut sender = agent
            .start_group(start_with(&dir, Some(Capture::Strict), policy))
            .unwrap();
        let mut handle = sender.take_checkpoints().unwrap();
        sender.admit().unwrap();
        sender
            .send(
                &encode(&[
                    GroupRecord::Timer(TimerEvent {
                        group_seq: 1,
                        logical_time: 1,
                        timer_id: 1,
                    }),
                    GroupRecord::End(EventEnd {
                        group_seq: 1,
                        observations: 0,
                        outcome: EndOutcome::Incomplete,
                    }),
                ]),
                1,
            )
            .unwrap();
        for _ in 0..5000 {
            if sender.state() == GroupState::Ended {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(sender.state(), GroupState::Ended);
        let mut refused = false;
        for _ in 0..5000 {
            if matches!(
                handle.checkpoint(1, 7, |_| 1),
                Err(crate::group::checkpoint::CheckpointError::Stopped)
            ) {
                refused = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(refused, "{:?}", handle.last_checkpoint());
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #426 review P3: checkpoints of size 0, or an agent writing 0 bytes a
    /// cycle, are refused before anything is made; the store's directory
    /// is never the journals'.
    #[test]
    fn checkpoint_settings_that_cannot_work_are_refused() {
        let dir = dirs("checkpoint-config");
        assert_ne!(store_dir(&dir.join("groups")), dir.join("groups"));
        let agent = ArchiveHandle::spawn(
            StdDisk,
            &dir,
            AgentConfig {
                checkpoint_budget: 0,
                ..AgentConfig::default()
            },
        )
        .unwrap();
        let policy = SyncPolicy::Every { interval_ns: 0 };
        assert!(matches!(
            agent.start_group(start_with(&dir, Some(Capture::Strict), policy)),
            Err(AgentError::CheckpointConfig)
        ));
        agent.shutdown().unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let mut zero = start_with(&dir, Some(Capture::Strict), policy);
        zero.checkpoints.as_mut().unwrap().max_checkpoint = 0;
        assert!(matches!(
            agent.start_group(zero),
            Err(AgentError::CheckpointConfig)
        ));
        assert!(
            std::fs::read_dir(dir.join("groups"))
                .unwrap()
                .all(|entry| { entry.unwrap().file_type().unwrap().is_dir() }),
            "no journal made"
        );
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #426 review P3 (A9 section 2): a store gone while the journal's
    /// records name checkpoints: the group starts, those ranges lost.
    #[test]
    fn a_missing_store_marks_its_checkpoints_lost() {
        let dir = dirs("checkpoint-missing");
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let mut sender = agent
            .start_group(start_with(&dir, Some(Capture::Strict), policy))
            .unwrap();
        let mut handle = sender.take_checkpoints().unwrap();
        sender.admit().unwrap();
        sender.send(&event(1), 1).unwrap();
        handle
            .checkpoint(1, 7, |buffer| {
                buffer[..5].copy_from_slice(b"state");
                5
            })
            .unwrap();
        let LastCheckpoint::Recorded(record) = ended(&mut handle) else {
            panic!("not recorded");
        };
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        let stores = store_dir(&dir.join("groups"));
        std::fs::remove_dir_all(&stores).unwrap();
        std::fs::create_dir(&stores).unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let mut recovered = agent.start_group(start_with(&dir, None, policy)).unwrap();
        assert_eq!(recovered.state(), GroupState::Running);
        // The next checkpoint goes past the lost range, never reusing it.
        let mut handle = recovered.take_checkpoints().unwrap();
        recovered.admit().unwrap();
        recovered.send(&event(2), 2).unwrap();
        handle
            .checkpoint(2, 7, |buffer| {
                buffer[..5].copy_from_slice(b"after");
                5
            })
            .unwrap();
        let LastCheckpoint::Recorded(next) = ended(&mut handle) else {
            panic!("not recorded: {:?}", handle.last_checkpoint());
        };
        assert_eq!(next.position, record.end().unwrap());
        agent.stop_group(GROUP).unwrap();
        agent.shutdown().unwrap();
        let mut journal =
            GroupJournal::recover(StdDisk, &dir.join("groups"), GROUP, journal_config(policy))
                .unwrap()
                .journal;
        let end = recorded_end(&mut journal).unwrap();
        let store =
            CheckpointStore::recover(StdDisk, &stores, GROUP, journal_config(policy), end).unwrap();
        assert_eq!(
            store.holds(record.position, record.end().unwrap()),
            crate::group::prefix::CheckpointHeld::Lost
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
