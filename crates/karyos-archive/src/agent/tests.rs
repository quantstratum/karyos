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
        origin: RecordedFrom::Local,
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
    replay_of_sink(recording_id, to, Box::new(sink))
}

fn replay_of_sink(recording_id: u64, to: u64, sink: Box<dyn ReplaySink + Send>) -> StartReplay {
    StartReplay {
        recording_id,
        from: 0,
        to,
        rate: Rate::Full,
        sink,
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

/// A sink whose target waits for its first reader: not ready until the
/// test opens it.
struct Unjoined {
    sink: Sink,
    joined: Arc<AtomicBool>,
}

impl ReplaySink for Unjoined {
    fn frames(&mut self, position: u64, bytes: &[u8]) -> Result<bool, SinkClosed> {
        self.sink.frames(position, bytes)
    }

    fn fill(&mut self, position: u64, record: &[u8], extent: u32) -> Result<bool, SinkClosed> {
        self.sink.fill(position, record, extent)
    }

    fn gap(&mut self, from: u64, to: u64) -> Result<bool, SinkClosed> {
        self.sink.gap(from, to)
    }

    fn finish(&mut self, end: u64, complete: bool) {
        self.sink.finish(end, complete);
    }

    fn ready(&mut self) -> bool {
        self.joined.load(Ordering::Acquire)
    }
}

/// A replay steps nothing into a sink that is not ready (H2b): one that
/// becomes ready within the attach deadline replays everything from its
/// first position, and one that never does ends `NoSubscriber` at the
/// deadline, finished incomplete where it began, its sink never written.
#[test]
fn a_replay_waits_for_its_target_until_the_attach_deadline() {
    let dir = temp_dir("replay-attach");
    let config = AgentConfig {
        attach_deadline: Duration::from_millis(200),
        ..AgentConfig::default()
    };
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    let (recording, all) = sealed_recording(&agent);
    let end = all.len() as u64;

    // Joined within the deadline: everything, from the first position.
    let seen = Arc::default();
    let joined = Arc::new(AtomicBool::new(false));
    let id = agent
        .replay(replay_of_sink(
            recording,
            end,
            Box::new(Unjoined {
                sink: Sink::new(&seen),
                joined: Arc::clone(&joined),
            }),
        ))
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(seen.lock().unwrap().calls, 0, "nothing before the reader");
    joined.store(true, Ordering::Release);
    assert_eq!(
        replay_ended(&agent),
        ReplayEnded {
            id,
            position: end,
            outcome: ReplayOutcome::Complete
        }
    );
    assert_eq!(seen.lock().unwrap().bytes, all);

    // Never joined: unattended at the deadline, nothing written.
    let seen = Arc::default();
    let started = std::time::Instant::now();
    let id = agent
        .replay(replay_of_sink(
            recording,
            end,
            Box::new(Unjoined {
                sink: Sink::new(&seen),
                joined: Arc::new(AtomicBool::new(false)),
            }),
        ))
        .unwrap();
    assert_eq!(
        replay_ended(&agent),
        ReplayEnded {
            id,
            position: 0,
            outcome: ReplayOutcome::NoSubscriber
        }
    );
    assert!(started.elapsed() >= Duration::from_millis(200));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.calls, 0);
    assert!(seen.bytes.is_empty());
    assert_eq!(seen.finished, Some((0, false)));
    drop(seen);
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

    /// A `required` recording's word names it and its start while it
    /// records, and is cleared once it stops; an `async` recording has
    /// none, nor does a stream not recorded, nor another lane of the
    /// recorded stream: recordings are per lane.
    #[test]
    fn a_required_recording_has_a_word_until_it_stops() {
        use karyos_sys::frame::Lane;
        let lane1 = Lane::try_new(1).unwrap();
        let dir = temp_dir("group-word");
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let drained = Arc::new(AtomicBool::new(false));
        let recording = agent.start(start(chunks(3000, false, &drained))).unwrap();
        let word = agent.recording_word(10, 3, Lane::ZERO).unwrap().unwrap();
        assert_eq!(word.read(), Some((recording, 0)));
        assert!(agent.recording_word(10, 4, Lane::ZERO).unwrap().is_none());
        assert!(agent.recording_word(10, 3, lane1).unwrap().is_none());
        // Lane 1 of the same stream and session, recorded on its own.
        let second = Arc::new(AtomicBool::new(false));
        let mut on_lane1 = start(chunks(3000, false, &second));
        on_lane1.format.lane = lane1;
        let lane1_recording = agent.start(on_lane1).unwrap();
        let lane1_word = agent.recording_word(10, 3, lane1).unwrap().unwrap();
        assert_eq!(lane1_word.read(), Some((lane1_recording, 0)));
        assert_eq!(
            agent
                .recording_word(10, 3, Lane::ZERO)
                .unwrap()
                .unwrap()
                .read(),
            Some((recording, 0))
        );
        agent.stop(recording).unwrap();
        assert_eq!(word.read(), None);
        assert!(agent.recording_word(10, 3, Lane::ZERO).unwrap().is_none());
        assert_eq!(lane1_word.read(), Some((lane1_recording, 0)));
        agent.stop(lane1_recording).unwrap();
        let other = Arc::new(AtomicBool::new(false));
        let _ = agent
            .start(StartRecording {
                mode: Mode::Async {
                    on_lap: crate::recorder::OnLap::Resume,
                },
                ..start(chunks(3000, false, &other))
            })
            .unwrap();
        assert!(agent.recording_word(10, 3, Lane::ZERO).unwrap().is_none());
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// karyos#490: a host recording its own network publication beside
    /// that publication's loopback image has two `required` recordings of
    /// one stream, session and lane, with the same channel and format. The
    /// local stream's word answers, whichever started first; with only the
    /// image's recording, its word answers.
    #[test]
    fn a_local_recording_answers_its_key_before_an_image() {
        use karyos_sys::frame::Lane;
        let dir = temp_dir("group-word-origin");
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let drained = Arc::new(AtomicBool::new(false));
        let image = agent
            .start(start(chunks(3000, false, &drained)).with_origin(RecordedFrom::Image))
            .unwrap();
        let word = agent.recording_word(10, 3, Lane::ZERO).unwrap().unwrap();
        assert_eq!(word.read(), Some((image, 0)), "only the image's");
        let second = Arc::new(AtomicBool::new(false));
        let local = agent.start(start(chunks(3000, false, &second))).unwrap();
        let word = agent.recording_word(10, 3, Lane::ZERO).unwrap().unwrap();
        assert_eq!(word.read(), Some((local, 0)), "the local stream's first");
        agent.stop(local).unwrap();
        let word = agent.recording_word(10, 3, Lane::ZERO).unwrap().unwrap();
        assert_eq!(word.read(), Some((image, 0)), "the image's again");
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
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
                image: 0,
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

    /// karyos#1088: with sealing on, a group's journal is sealed in the
    /// integrity journal of its directory, and its sealed bytes verify.
    #[test]
    fn a_group_journal_is_sealed_in_its_directory() {
        use crate::group::journal::GroupJournal;
        use crate::integrity::journal::read_records;
        use crate::integrity::{SealKind, verify_chain, verify_range};
        let dir = temp_dir("group-sealed");
        let groups = groups_dir(&dir);
        let config = AgentConfig {
            seal_interval: Some(Duration::from_millis(1)),
            ..AgentConfig::default()
        };
        let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
        let drained = Arc::new(AtomicBool::new(false));
        let recording = agent.start(start(chunks(3000, false, &drained))).unwrap();
        wait(&drained);
        let mut sender = agent
            .start_group(start_group(&groups, Some(Capture::Strict)))
            .unwrap();
        sender.admit().unwrap();
        sender.send(&referencing(1, recording), 1).unwrap();
        let waiter = sender.waiter();
        assert_eq!(agent.stop(recording).unwrap().position, 3000);
        assert_eq!(waiter.wait_durable(1, Duration::from_secs(5)), Ok(1));
        // A duty after the event's durability seals it.
        std::thread::sleep(Duration::from_millis(50));
        agent.shutdown().unwrap();

        let (records, fault) = read_records(&mut StdDisk, &groups).unwrap();
        assert_eq!(fault, None);
        verify_chain(&records).unwrap();
        let ranges: Vec<_> = records
            .iter()
            .filter(|record| record.kind == SealKind::OpenSegment && record.subject == GROUP)
            .collect();
        assert!(!ranges.is_empty(), "the group journal is sealed");
        assert_eq!(ranges[0].start, 0);
        let mut journal =
            GroupJournal::recover(StdDisk, &groups, GROUP, start_group(&groups, None).journal)
                .unwrap()
                .journal;
        for range in ranges {
            let mut bytes = vec![0u8; usize::try_from(range.end - range.start).unwrap()];
            journal.read_bytes(range.start, &mut bytes).unwrap();
            verify_range(range, &bytes).unwrap();
        }
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
                    image: 0,
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

    /// A journal of group `GROUP` in `dir` whose header was never written.
    fn headerless(dir: &Path, policy: SyncPolicy) {
        let config = journal_config(policy);
        let geometry =
            crate::segment::Geometry::new(config.segment_length, u64::from(config.segment_length))
                .unwrap();
        drop(
            crate::segment::SegmentStore::create(
                StdDisk,
                &dir.join("groups"),
                GROUP,
                geometry,
                policy,
                0,
            )
            .unwrap(),
        );
    }

    /// #437 re-check t1: the crash after the journal and the store were
    /// made, before the header: started as new, the empty store is opened
    /// as a restart opens one, and the group runs; restarted, it recovers.
    #[test]
    fn a_takeover_opens_the_store_the_crash_left() {
        let dir = dirs("checkpoint-takeover-store");
        let policy = SyncPolicy::Every { interval_ns: 0 };
        headerless(&dir, policy);
        drop(
            crate::group::checkpoint::CheckpointStore::create(
                StdDisk,
                &store_dir(&dir.join("groups")),
                GROUP,
                journal_config(policy),
            )
            .unwrap(),
        );
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let mut sender = agent
            .start_group(start_with(&dir, Some(Capture::Strict), policy))
            .unwrap();
        sender.admit().unwrap();
        sender.send(&event(1), 1).unwrap();
        assert_eq!(
            sender.waiter().wait_durable(1, Duration::from_secs(10)),
            Ok(1)
        );
        agent.stop_group(GROUP).unwrap();
        let restarted = agent.start_group(start_with(&dir, None, policy)).unwrap();
        assert_eq!(restarted.view().durable_group_seq(), 1);
        agent.stop_group(GROUP).unwrap();
        // Mtake: a journal with its header is not taken over.
        assert!(matches!(
            agent.start_group(start_with(&dir, Some(Capture::Strict), policy)),
            Err(AgentError::Journal(JournalError::Segment(
                SegmentError::Exists { .. }
            )))
        ));
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #437 re-check Morder: the header is written only once the store is
    /// open. A takeover whose store cannot be opened leaves the journal
    /// as it was, headerless, and fails.
    #[test]
    fn a_takeover_whose_store_fails_writes_no_header() {
        let dir = dirs("checkpoint-takeover-store-fails");
        let policy = SyncPolicy::Every { interval_ns: 0 };
        headerless(&dir, policy);
        // The store's directory is a file: the store cannot be opened.
        let stores = store_dir(&dir.join("groups"));
        std::fs::remove_dir_all(&stores).unwrap();
        std::fs::write(&stores, b"not a directory").unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let before = files(&dir);
        assert!(
            agent
                .start_group(start_with(&dir, Some(Capture::Strict), policy))
                .is_err()
        );
        assert_eq!(files(&dir), before, "the journal changed");
        agent.shutdown().unwrap();
        let plan =
            GroupJournal::verify(StdDisk, &dir.join("groups"), GROUP, journal_config(policy))
                .unwrap();
        assert_eq!(
            plan.kept.map(|kept| kept.written),
            Some(0),
            "still headerless"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #437 re-check t2: a journal durable to 8 whose header is damaged:
    /// recovery cuts it all. Neither a restart nor a new start takes it;
    /// both are refused as a cut header, and nothing is written.
    #[test]
    fn a_cut_header_is_refused_both_ways() {
        let dir = reopened_over_six("checkpoint-header-cut");
        let segment = walk(&dir)
            .into_iter()
            .find(|path| path.extension().is_some_and(|ext| ext == "seg"))
            .unwrap();
        let path = dir.join(segment);
        let mut bytes = std::fs::read(&path).unwrap();
        // Inside the header record, past its frame: its checksum fails.
        bytes[40] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        // Every refusal, the first too, leaves the journal byte for byte
        // as it was: nothing is cut, and the operator may copy it.
        let before = std::fs::read(&path).unwrap();
        let tree = files(&dir);
        for start in [
            holding(&dir, None, 2, Some(8)),
            holding(&dir, Some(Capture::BestEffort), 2, Some(8)),
            holding(&dir, None, 2, Some(8)),
        ] {
            let refused = agent.start_group(start);
            assert!(
                matches!(refused, Err(AgentError::HeaderCut { id: GROUP, .. })),
                "{refused:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), before, "the journal changed");
            assert_eq!(files(&dir), tree, "a refusal wrote");
        }
        agent.shutdown().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// #437 re-check: a crash while the header was written tears that one
    /// write, with nothing after it. A restart finds no header (typed);
    /// a new start takes the journal over, as never written.
    #[test]
    fn a_torn_header_alone_is_taken_over() {
        let dir = dirs("checkpoint-torn-header");
        let policy = SyncPolicy::Every { interval_ns: 0 };
        let header = crate::group::record::JournalHeader {
            group_id: GROUP,
            first_group_seq: 1,
            inline_threshold: 4096,
            contract_version: crate::group::record::CONTRACT_VERSION,
            clock: crate::group::record::Clock::HostMonotonic,
            capture: Capture::Strict,
            reopen_hold: 0,
            manifest: b"m",
        };
        let journal = GroupJournal::create(
            StdDisk,
            &dir.join("groups"),
            &header,
            journal_config(policy),
        )
        .unwrap();
        let _ = journal.close().unwrap();
        let segment = walk(&dir)
            .into_iter()
            .find(|path| path.extension().is_some_and(|ext| ext == "seg"))
            .unwrap();
        let path = dir.join(segment);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[20] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        assert!(matches!(
            agent.start_group(start_with(&dir, None, policy)),
            Err(AgentError::NoHeader { id: GROUP })
        ));
        let sender = agent
            .start_group(start_with(&dir, Some(Capture::Strict), policy))
            .unwrap();
        assert_eq!(sender.state(), GroupState::Running);
        agent.stop_group(GROUP).unwrap();
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

/// A source of one chunk, then fenced at a cutover where it ends.
struct FencedAfter {
    position: u64,
    chunk: Option<Vec<u8>>,
}

impl FrameSource for FencedAfter {
    fn position(&self) -> u64 {
        self.position
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        let Some(chunk) = self.chunk.take() else {
            return Ok(Frames::Fenced { at: self.position });
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

/// Gap 6: a recording fenced at a cutover ends there, incomplete, and the
/// agent counts it, so the cause is known without a format change.
#[test]
fn a_fenced_recording_is_counted() {
    let dir = temp_dir("fenced");
    let config = AgentConfig {
        idle: Duration::from_millis(1),
        ..AgentConfig::default()
    };
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    assert_eq!(agent.fenced_recordings(), 0);
    let fenced = agent
        .start(StartRecording {
            source: Box::new(FencedAfter {
                position: 0,
                chunk: Some(vec![5u8; 3000]),
            }),
            ..start(Chunks::default())
        })
        .unwrap();
    let event = agent.event(Duration::from_secs(5)).unwrap();
    assert_eq!(
        event,
        Event::Ended {
            id: fenced,
            ended: Ended {
                position: 3000,
                reason: StopReason::Lapped,
                incomplete: true
            }
        }
    );
    assert_eq!(agent.fenced_recordings(), 1);
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// With a `seal_interval`, the running agent seals every byte of a
/// recording, its last range closing, and chains the catalog's start and
/// stop, without the test calling the integrity APIs (A10; karyos#961).
#[test]
fn a_recording_is_sealed_and_its_catalog_changes_chained() {
    use crate::integrity::journal::IntegrityJournal;
    use crate::integrity::{SealKind, verify_chain, verify_range};

    let dir = temp_dir("sealed");
    let config = AgentConfig {
        idle: Duration::from_millis(1),
        seal_interval: Some(Duration::from_millis(1)),
        ..AgentConfig::default()
    };
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    let (id, all) = sealed_recording(&agent);
    agent.shutdown().unwrap();

    let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
    let records = journal.records().unwrap();
    assert!(verify_chain(records.iter()).is_ok());
    let ranges: Vec<_> = records
        .iter()
        .filter(|record| record.kind.is_range() && record.subject == id)
        .collect();
    assert!(!ranges.is_empty());
    assert_eq!(ranges.first().unwrap().start, 0);
    let last = ranges.last().unwrap();
    assert_eq!(last.end, all.len() as u64);
    assert_eq!(last.kind, SealKind::ClosedSegment);
    for range in &ranges {
        let bytes = &all[range.start as usize..range.end as usize];
        assert!(verify_range(range, bytes).is_ok());
    }
    let catalog: Vec<_> = records
        .iter()
        .filter(|record| record.kind == SealKind::Catalog && record.subject == id)
        .collect();
    assert_eq!(catalog.len(), 2, "the start and the stop");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Without a `seal_interval` the agent keeps no integrity journal.
#[test]
fn without_a_seal_interval_nothing_is_sealed() {
    let dir = temp_dir("unsealed");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let _ = sealed_recording(&agent);
    agent.shutdown().unwrap();
    assert!(!crate::integrity::journal::IntegrityJournal::<StdDisk>::path(&dir).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The seals and catalog changes of `id` in the archive at `dir`: whether
/// its sealed ranges cover `[0, end)` closing, each matching `bytes`, and
/// how many catalog changes are chained for it.
fn sealed_and_chained(dir: &std::path::Path, id: u64, bytes: &[u8]) -> (bool, usize) {
    use crate::integrity::journal::IntegrityJournal;
    use crate::integrity::{SealKind, verify_chain, verify_range};

    let mut journal = IntegrityJournal::open(StdDisk, dir).unwrap().journal;
    let records = journal.records().unwrap();
    assert!(verify_chain(records.iter()).is_ok());
    let ranges: Vec<_> = records
        .iter()
        .filter(|record| record.kind.is_range() && record.subject == id)
        .collect();
    let covered = ranges.first().is_some_and(|first| first.start == 0)
        && ranges.last().is_some_and(|last| {
            last.end == bytes.len() as u64 && last.kind == SealKind::ClosedSegment
        })
        && ranges.iter().all(|range| {
            verify_range(range, &bytes[range.start as usize..range.end as usize]).is_ok()
        });
    let chained = records
        .iter()
        .filter(|record| record.kind == SealKind::Catalog && record.subject == id)
        .count();
    (covered, chained)
}

fn sealing() -> AgentConfig {
    AgentConfig {
        idle: Duration::from_millis(1),
        seal_interval: Some(Duration::from_millis(1)),
        ..AgentConfig::default()
    }
}

/// A shutdown seals each active recording's last range under its own id
/// and chains its stop before the reply (karyos#961).
#[test]
fn a_shutdown_seals_and_chains_every_active_recording() {
    let dir = temp_dir("sealed-shutdown");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, sealing()).unwrap();
    let mut recordings = Vec::new();
    for fill in 1..=2u8 {
        let drained = Arc::new(AtomicBool::new(false));
        let bytes = frames(3, fill);
        let id = agent
            .start(start(Chunks {
                chunks: vec![bytes.clone()].into(),
                drained: Arc::clone(&drained),
                ..Chunks::default()
            }))
            .unwrap();
        wait(&drained);
        recordings.push((id, bytes));
    }
    agent.shutdown().unwrap();
    for (id, bytes) in recordings {
        assert_eq!(sealed_and_chained(&dir, id, &bytes), (true, 2), "{id}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A recording whose source failed, its store whole, has its last range
/// sealed like any other stop.
#[test]
fn a_failed_source_still_seals_its_last_range() {
    let dir = temp_dir("sealed-failed-source");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, sealing()).unwrap();
    let bytes = frames(2, 7);
    let id = agent
        .start(start(Chunks {
            chunks: vec![bytes.clone()].into(),
            fail: true,
            ..Chunks::default()
        }))
        .unwrap();
    assert!(matches!(
        agent.event(Duration::from_secs(5)).unwrap(),
        Event::Ended { .. }
    ));
    agent.shutdown().unwrap();
    assert_eq!(sealed_and_chained(&dir, id, &bytes), (true, 2));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A recording a crash left open, its writes sealed: written by hand, two
/// 4 KiB writes, both sealed. The agent's thread needs a `Send` disk, so
/// this is a real directory; the `FaultDisk` injection is in
/// `integrity::damage`'s tests. Returns the directory and the recording.
fn crashed_sealed_recording(name: &str) -> (PathBuf, u64) {
    use crate::catalog::{Catalog, NewRecording};
    use crate::integrity::journal::IntegrityJournal;

    let disk = StdDisk;
    let root = temp_dir(name);
    let dir = root.as_path();
    let mut catalog = Catalog::open(disk, dir).unwrap().catalog;
    let geometry = Geometry::new(4096, 8192).unwrap();
    let id = catalog
        .start(NewRecording {
            stream_id: 10,
            session_id: 3,
            channel: b"karyos:ipc",
            start: 0,
            start_time_ns: 0,
            geometry,
            policy: SyncPolicy::PerSegment,
            format: format(),
            required: false,
        })
        .unwrap();
    let mut store =
        SegmentStore::create(disk, dir, id, geometry, SyncPolicy::PerSegment, 0).unwrap();
    let mut journal = IntegrityJournal::open(disk, dir).unwrap().journal;
    for (index, fill) in [1u8, 2].into_iter().enumerate() {
        let bytes = vec![fill; 4096];
        let at = index as u64 * 4096;
        store.append(at, &bytes).unwrap();
        journal.seal_segment(id, at, &bytes, false).unwrap();
    }
    store.sync().unwrap();
    // The crash: the store and the catalog are left as they are.
    (root, id)
}

/// An index shortened by media damage below its seals is reported at a
/// restart with the lost range, and counted (karyos#671).
#[test]
fn an_index_shortened_below_its_seals_is_reported_at_restart() {
    use crate::disk::Disk as _;
    use crate::integrity::damage::ShortenedIndex;

    let (dir, id) = crashed_sealed_recording("shortened");
    let mut disk = StdDisk;
    // The damage, written by the test: the index loses its second entry.
    let index = dir.join(format!("{id:016x}-{:016x}.idx", 0));
    let file = disk.open(&index).unwrap();
    let length = disk.len(&file).unwrap();
    disk.set_len(&file, length - 32).unwrap();

    let config = AgentConfig {
        idle: Duration::from_millis(1),
        seal_interval: Some(Duration::from_millis(1)),
        ..AgentConfig::default()
    };
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    assert_eq!(
        agent.event(Duration::from_secs(5)),
        Some(Event::IndexShortened(ShortenedIndex {
            recording: id,
            written: 4096,
            sealed_end: 8192,
            counter: 1,
        }))
    );
    assert_eq!(agent.shortened_indexes(), 1);
    // Kept whole after start, whatever the event queue dropped (karyos#671
    // review).
    assert_eq!(
        agent.shortened_index_reports(),
        [ShortenedIndex {
            recording: id,
            written: 4096,
            sealed_end: 8192,
            counter: 1,
        }]
    );
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A recovered recording whose seals end at or below its written end is
/// not reported: an unindexed tail above the last seal stays an
/// unacknowledged write.
#[test]
fn a_recovered_recording_within_its_seals_is_not_reported() {
    let (dir, _) = crashed_sealed_recording("within-seals");
    let config = AgentConfig {
        idle: Duration::from_millis(1),
        seal_interval: Some(Duration::from_millis(1)),
        ..AgentConfig::default()
    };
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config).unwrap();
    assert_eq!(agent.event(Duration::from_millis(200)), None);
    assert_eq!(agent.shortened_indexes(), 0);
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// karyos#671 review P2: the damage check runs before a recording's stop
/// is written, so a check that fails ends the settle with the recording
/// still open, and a later start checks it again.
#[test]
fn a_failed_damage_check_leaves_the_recording_open() {
    use crate::catalog::{Catalog, CatalogError};

    let (dir, id) = crashed_sealed_recording("check-fails");
    let mut catalog = Catalog::open(StdDisk, &dir).unwrap().catalog;
    let failed = catalog.settle_checked(0, |_, _, _| Err(CatalogError::IdsExhausted));
    assert!(matches!(failed, Err(CatalogError::IdsExhausted)));
    drop(catalog);
    let mut catalog = Catalog::open(StdDisk, &dir).unwrap().catalog;
    let mut checked = Vec::new();
    let settled = catalog
        .settle_checked(0, |recording, _, _| {
            checked.push(recording);
            Ok::<_, CatalogError>(())
        })
        .unwrap();
    assert_eq!(checked, [id], "the recording was still open");
    assert_eq!(settled.len(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// With a signer, the running agent signs the integrity journal's heads
/// on its control path and records them in `heads.kyh`, trusted under the
/// registry, the last one covering the chain's last record (karyos#966).
#[test]
fn a_signing_agent_records_trusted_heads_covering_the_chain() {
    use crate::integrity::journal::IntegrityJournal;
    use crate::integrity::ledger::{Ledger, read_entries};
    use crate::integrity::signing::{BacklogPolicy, SigningConfig};
    use crate::integrity::test_key::TestKey;
    use crate::integrity::trust::{
        Algorithm, Custody, HEADS_FILE, HeadVerdict, KEYS_FILE, KeyRegistry, REGISTRY_ENTRY_LENGTH,
        RegistryAction, RegistryEntry, SIGNED_HEAD_LENGTH, SignedHead, TrustRoot, key_id,
    };

    let dir = temp_dir("signing");
    let archive = [7u8; 32];
    let authority = TestKey::from_seed([1; 32]);
    let archival = TestKey::from_seed([9; 32]);
    let trust = TrustRoot {
        archive_id: archive,
        authorities: vec![authority.public()],
    };
    // The operator registers the archival key before the Archive runs.
    {
        let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
        let mut keys = Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(StdDisk, &dir, KEYS_FILE).unwrap();
        let mut entry = RegistryEntry {
            action: RegistryAction::Register,
            algorithm: Algorithm::Ed25519,
            custody: Custody::Declared,
            sequence: 0,
            key_id: key_id(&archival.public()),
            public: archival.public(),
            effective: 0,
            evidence: [0; 32],
            endorsement: [0; 64],
        };
        entry.endorsement = authority.sign_bytes(&entry.endorsement_bytes(&archive));
        KeyRegistry::new(trust.clone())
            .append(&entry, &mut journal, &mut keys)
            .unwrap();
    }
    let signing = ArchiveSigning {
        trust: trust.clone(),
        journal_id: 1,
        config: SigningConfig::new(Some(60_000_000_000), BacklogPolicy::Coalesce).unwrap(),
        signer: Box::new(archival),
    };
    let agent = ArchiveHandle::spawn_signing(StdDisk, &dir, sealing(), signing).unwrap();
    let _ = sealed_recording(&agent);
    // Two signing polls, a second apart, after the recording sealed.
    std::thread::sleep(Duration::from_millis(2_500));
    // The polls published their status (karyos#1031): read incrementally,
    // the last seal is covered and nothing is overdue.
    let lag = agent.signing_lag().unwrap();
    assert!(!lag.alarm, "{lag:?}");
    agent.shutdown().unwrap();

    let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
    let records = journal.records().unwrap();
    let mut disk = StdDisk;
    let keys: Vec<[u8; REGISTRY_ENTRY_LENGTH]> = read_entries(&mut disk, &dir, KEYS_FILE).unwrap();
    let registry = KeyRegistry::replay(trust, &records, &keys).unwrap().0;
    let heads: Vec<[u8; SIGNED_HEAD_LENGTH]> = read_entries(&mut disk, &dir, HEADS_FILE).unwrap();
    assert!(!heads.is_empty(), "no head was signed");
    let last = SignedHead::decode(heads.last().unwrap()).unwrap();
    assert!(matches!(
        registry.verify(&last, None),
        HeadVerdict::Trusted { .. }
    ));
    let sealed = records
        .iter()
        .filter(|record| record.kind.is_range())
        .map(|record| record.counter)
        .max()
        .unwrap();
    assert!(last.head.counter >= sealed, "the last seal is covered");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Signing without sealing is refused at spawn.
#[test]
fn signing_without_a_seal_interval_is_refused() {
    use crate::integrity::signing::{BacklogPolicy, SigningConfig};
    use crate::integrity::test_key::TestKey;
    use crate::integrity::trust::TrustRoot;

    let dir = temp_dir("signing-unsealed");
    let signing = ArchiveSigning {
        trust: TrustRoot {
            archive_id: [7; 32],
            authorities: Vec::new(),
        },
        journal_id: 1,
        config: SigningConfig::new(Some(1), BacklogPolicy::Coalesce).unwrap(),
        signer: Box::new(TestKey::from_seed([9; 32])),
    };
    assert!(matches!(
        ArchiveHandle::spawn_signing(StdDisk, &dir, AgentConfig::default(), signing),
        Err(AgentError::SigningWithoutSealing)
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The operator's registered archival key in `dir`'s registry, for the
/// signing duty tests: the trust root and the key.
fn registered_archival(
    dir: &Path,
) -> (
    crate::integrity::trust::TrustRoot,
    crate::integrity::test_key::TestKey,
) {
    use crate::integrity::journal::IntegrityJournal;
    use crate::integrity::ledger::Ledger;
    use crate::integrity::test_key::TestKey;
    use crate::integrity::trust::{
        Algorithm, Custody, KEYS_FILE, KeyRegistry, REGISTRY_ENTRY_LENGTH, RegistryAction,
        RegistryEntry, TrustRoot, key_id,
    };

    let archive = [7u8; 32];
    let authority = TestKey::from_seed([1; 32]);
    let archival = TestKey::from_seed([9; 32]);
    let trust = TrustRoot {
        archive_id: archive,
        authorities: vec![authority.public()],
    };
    let mut journal = IntegrityJournal::open(StdDisk, dir).unwrap().journal;
    let mut keys = Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(StdDisk, dir, KEYS_FILE).unwrap();
    let mut entry = RegistryEntry {
        action: RegistryAction::Register,
        algorithm: Algorithm::Ed25519,
        custody: Custody::Declared,
        sequence: 0,
        key_id: key_id(&archival.public()),
        public: archival.public(),
        effective: 0,
        evidence: [0; 32],
        endorsement: [0; 64],
    };
    entry.endorsement = authority.sign_bytes(&entry.endorsement_bytes(&archive));
    KeyRegistry::new(trust.clone())
        .append(&entry, &mut journal, &mut keys)
        .unwrap();
    (trust, archival)
}

/// A signer that answers a head only on its `asks`-th request for that
/// same head, and only while `open`: a remote signer slower than sealing.
struct SlowSigner {
    key: crate::integrity::test_key::TestKey,
    asks: u32,
    open: std::sync::Arc<std::sync::atomic::AtomicBool>,
    seen: std::collections::HashMap<u64, u32>,
}

impl crate::integrity::signing::HeadSigner for SlowSigner {
    fn key_id(&self) -> crate::integrity::Digest {
        self.key.key_id()
    }

    fn custody(&self) -> crate::integrity::trust::Custody {
        self.key.custody()
    }

    fn sign(
        &mut self,
        head: &crate::integrity::trust::ChainHead,
    ) -> Result<[u8; crate::integrity::trust::SIGNATURE_LENGTH], SignerUnavailable> {
        if !self.open.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(SignerUnavailable);
        }
        let asked = self.seen.entry(head.counter).or_insert(0);
        *asked += 1;
        if *asked < self.asks {
            return Err(SignerUnavailable);
        }
        self.key.sign(head)
    }
}

/// The counters of the heads `dir`'s `heads.kyh` records.
fn signed_counters(dir: &Path) -> Vec<u64> {
    use crate::integrity::ledger::read_entries;
    use crate::integrity::trust::{HEADS_FILE, SIGNED_HEAD_LENGTH, SignedHead};
    let mut disk = StdDisk;
    let heads: Vec<[u8; SIGNED_HEAD_LENGTH]> = read_entries(&mut disk, dir, HEADS_FILE).unwrap();
    heads
        .iter()
        .map(|head| SignedHead::decode(head).unwrap().head.counter)
        .collect()
}

/// karyos#966 review P1: with the journal's head advancing at every poll
/// and a signer that needs several asks for one head, the head given to
/// the signer is kept until it is signed, so coverage progresses; the
/// newer heads wait behind it and coalesce into the latest.
#[test]
fn a_slow_signer_still_signs_while_heads_advance() {
    use crate::integrity::journal::IntegrityJournal;
    use crate::integrity::signing::{BacklogPolicy, SigningConfig};

    let dir = temp_dir("signing-slow");
    let (trust, key) = registered_archival(&dir);
    let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
    let setup = ArchiveSigning {
        trust,
        journal_id: 1,
        config: SigningConfig::new(Some(60_000_000_000), BacklogPolicy::Coalesce).unwrap(),
        signer: Box::new(SlowSigner {
            key,
            asks: 3,
            open: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            seen: std::collections::HashMap::new(),
        }),
    };
    let mut signing = Signing::open(StdDisk, &dir, setup, &mut journal, Arc::default()).unwrap();
    for poll in 1..=12u64 {
        let _ = journal
            .record_policy_version(1, poll, &poll.to_le_bytes())
            .unwrap();
        signing.duty(&mut journal, poll * SIGNING_POLL);
    }
    let signed = signed_counters(&dir);
    assert!(signed.len() >= 2, "coverage progressed: {signed:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// karyos#966 review P2: a head the backlog refused is offered again at
/// the next duty, so the final seal is signed once the signer recovers,
/// without another seal arriving.
#[test]
fn a_refused_head_is_offered_again() {
    use crate::integrity::journal::IntegrityJournal;
    use crate::integrity::signing::{BacklogPolicy, SigningConfig};

    let dir = temp_dir("signing-refused");
    let (trust, key) = registered_archival(&dir);
    let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
    let open = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let setup = ArchiveSigning {
        trust,
        journal_id: 1,
        config: SigningConfig::new(
            Some(60_000_000_000),
            BacklogPolicy::Refuse {
                capacity: std::num::NonZeroUsize::MIN,
            },
        )
        .unwrap(),
        signer: Box::new(SlowSigner {
            key,
            asks: 1,
            open: std::sync::Arc::clone(&open),
            seen: std::collections::HashMap::new(),
        }),
    };
    let mut signing = Signing::open(StdDisk, &dir, setup, &mut journal, Arc::default()).unwrap();
    // The first head queues; the final one is refused, the backlog full.
    let _ = journal.record_policy_version(1, 1, b"first").unwrap();
    signing.duty(&mut journal, SIGNING_POLL);
    let last = journal.record_policy_version(1, 2, b"final").unwrap();
    signing.duty(&mut journal, 2 * SIGNING_POLL);
    // The signer recovers; no seal arrives after.
    open.store(true, std::sync::atomic::Ordering::Relaxed);
    signing.duty(&mut journal, 3 * SIGNING_POLL);
    signing.duty(&mut journal, 4 * SIGNING_POLL);
    let signed = signed_counters(&dir);
    assert_eq!(signed.last(), Some(&last.counter), "{signed:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A signer that refuses, as unavailable, every head before `effective`,
/// as an operator's signer may for a key not yet in force.
struct EffectiveSigner {
    key: crate::integrity::test_key::TestKey,
    effective: u64,
}

impl crate::integrity::signing::HeadSigner for EffectiveSigner {
    fn key_id(&self) -> crate::integrity::Digest {
        self.key.key_id()
    }

    fn custody(&self) -> crate::integrity::trust::Custody {
        self.key.custody()
    }

    fn sign(
        &mut self,
        head: &crate::integrity::trust::ChainHead,
    ) -> Result<[u8; crate::integrity::trust::SIGNATURE_LENGTH], SignerUnavailable> {
        if head.counter < self.effective {
            return Err(SignerUnavailable);
        }
        self.key.sign(head)
    }
}

/// karyos#966 review P1: a head before the key's effective counter is
/// never offered, so it cannot pin the backlog under either policy, even
/// when the signer refuses it as unavailable (no `KeyNotYetValid` verdict
/// ever comes back); the first eligible head is signed.
#[test]
fn a_head_before_the_keys_validity_never_pins_the_backlog() {
    use crate::integrity::journal::IntegrityJournal;
    use crate::integrity::ledger::Ledger;
    use crate::integrity::signing::{BacklogPolicy, SigningConfig};
    use crate::integrity::test_key::TestKey;
    use crate::integrity::trust::{
        Algorithm, Custody, KEYS_FILE, KeyRegistry, REGISTRY_ENTRY_LENGTH, RegistryAction,
        RegistryEntry, TrustRoot, key_id,
    };

    for (name, policy) in [
        ("coalesce", BacklogPolicy::Coalesce),
        (
            "refuse",
            BacklogPolicy::Refuse {
                capacity: std::num::NonZeroUsize::MIN,
            },
        ),
    ] {
        let dir = temp_dir(&format!("signing-not-yet-valid-{name}"));
        let archive = [7u8; 32];
        let authority = TestKey::from_seed([1; 32]);
        let archival = TestKey::from_seed([9; 32]);
        let trust = TrustRoot {
            archive_id: archive,
            authorities: vec![authority.public()],
        };
        let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
        let effective = 8;
        {
            let mut keys =
                Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(StdDisk, &dir, KEYS_FILE).unwrap();
            let mut entry = RegistryEntry {
                action: RegistryAction::Register,
                algorithm: Algorithm::Ed25519,
                custody: Custody::Declared,
                sequence: 0,
                key_id: key_id(&archival.public()),
                public: archival.public(),
                effective,
                evidence: [0; 32],
                endorsement: [0; 64],
            };
            entry.endorsement = authority.sign_bytes(&entry.endorsement_bytes(&archive));
            KeyRegistry::new(trust.clone())
                .append(&entry, &mut journal, &mut keys)
                .unwrap();
        }
        let setup = ArchiveSigning {
            trust,
            journal_id: 1,
            config: SigningConfig::new(Some(60_000_000_000), policy).unwrap(),
            signer: Box::new(EffectiveSigner {
                key: archival,
                effective,
            }),
        };
        let mut signing =
            Signing::open(StdDisk, &dir, setup, &mut journal, Arc::default()).unwrap();
        let mut poll = 1u64;
        // Heads before the key's validity: none is signed or held.
        while journal.records().unwrap().last().unwrap().counter < effective - 1 {
            let _ = journal
                .record_policy_version(1, poll, &poll.to_le_bytes())
                .unwrap();
            signing.duty(&mut journal, poll * SIGNING_POLL);
            poll += 1;
        }
        assert!(signed_counters(&dir).is_empty(), "{name}");
        // Seals pass the effective counter; the first eligible head goes.
        for _ in 0..3 {
            let _ = journal
                .record_policy_version(1, poll, &poll.to_le_bytes())
                .unwrap();
            signing.duty(&mut journal, poll * SIGNING_POLL);
            poll += 1;
        }
        signing.duty(&mut journal, poll * SIGNING_POLL);
        let signed = signed_counters(&dir);
        assert!(
            signed.last().is_some_and(|&counter| counter >= effective),
            "{name}: {signed:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// karyos#1024: with a copy location, a recording that closes sealed is
/// recorded as a verified local copy over its whole range, with the
/// enforcement that applies (none here: no immutable attribute without
/// `CAP_LINUX_IMMUTABLE`, and none off Linux) and its seals' digest.
#[test]
fn a_closed_sealed_recording_is_recorded_as_a_local_copy() {
    use crate::integrity::copies::{CopyCatalog, CopyState, Enforcement};
    let dir = temp_dir("local-copy");
    let location = [5u8; 32];
    let agent =
        ArchiveHandle::spawn(StdDisk, &dir, sealing().with_copy_location(Some(location))).unwrap();
    let (id, all) = sealed_recording(&agent);
    agent.shutdown().unwrap();

    let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
    let records = journal.records().unwrap();
    let copies = CopyCatalog::open(StdDisk, &dir, &mut journal).unwrap();
    let current = copies.current().unwrap();
    assert_eq!(current.len(), 1, "{current:?}");
    let copy = current[0];
    let end = u64::try_from(all.len()).unwrap();
    assert_eq!(
        (
            copy.recording,
            copy.start,
            copy.end,
            copy.location,
            copy.state
        ),
        (id, 0, end, location, CopyState::Verified)
    );
    assert_eq!(
        copy.digest,
        crate::integrity::retention::seals_digest(&records, id, 0, end)
    );
    // No test host grants the attribute: never a protection not there.
    assert!(matches!(
        copy.enforcement,
        Enforcement::Unsupported | Enforcement::ImmutableAttribute
    ));
    if copy.enforcement == Enforcement::ImmutableAttribute {
        // Not expected under test; release so the directory can go.
        return;
    }
    assert_eq!(copies.verified_copies(id, 0, end).unwrap(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Without a copy location, nothing is recorded as a copy.
#[test]
fn without_a_copy_location_no_copy_is_recorded() {
    use crate::integrity::copies::CopyCatalog;
    let dir = temp_dir("no-local-copy");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, sealing()).unwrap();
    let _ = sealed_recording(&agent);
    agent.shutdown().unwrap();
    let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
    let copies = CopyCatalog::open(StdDisk, &dir, &mut journal).unwrap();
    assert!(copies.current().unwrap().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// karyos#1024 review: a local copy records the immutable attribute only
/// over a non-empty file list that every file took; an empty list (as an
/// unreadable one becomes) or one refused file records none.
#[test]
fn a_local_copy_claims_the_attribute_only_when_every_file_took_it() {
    use crate::integrity::copies::{Enforcement, ImmutabilityBackend};
    use std::path::{Path, PathBuf};

    struct Takes(Vec<bool>);
    impl ImmutabilityBackend for Takes {
        fn enforce(&mut self, _path: &Path, _until: u64) -> std::io::Result<Enforcement> {
            Ok(if self.0.pop().unwrap_or(false) {
                Enforcement::ImmutableAttribute
            } else {
                Enforcement::Unsupported
            })
        }
    }
    let files = [PathBuf::from("a"), PathBuf::from("b")];
    assert_eq!(
        super::local_enforcement(&mut Takes(vec![true, true]), &[]),
        Enforcement::Unsupported
    );
    assert_eq!(
        super::local_enforcement(&mut Takes(vec![true, true]), &files),
        Enforcement::ImmutableAttribute
    );
    assert_eq!(
        super::local_enforcement(&mut Takes(vec![true, false]), &files),
        Enforcement::Unsupported
    );
}

/// A disk whose reads on the verification worker's thread wait while its
/// gate is shut (karyos#1111): every other thread reads at once.
#[derive(Clone)]
struct GatedVerify(Arc<AtomicBool>);

impl GatedVerify {
    fn wait(&self) {
        let on_worker = std::thread::current().name() == Some(super::retention::VERIFY_THREAD);
        while on_worker && self.0.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Disk for GatedVerify {
    type File = std::fs::File;

    fn create(&mut self, path: &Path) -> std::io::Result<Self::File> {
        StdDisk.create(path)
    }

    fn create_new(&mut self, path: &Path) -> std::io::Result<Self::File> {
        StdDisk.create_new(path)
    }

    fn open(&mut self, path: &Path) -> std::io::Result<Self::File> {
        StdDisk.open(path)
    }

    fn open_read(&mut self, path: &Path) -> std::io::Result<Self::File> {
        StdDisk.open_read(path)
    }

    fn write_at(&mut self, file: &Self::File, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        StdDisk.write_at(file, offset, bytes)
    }

    fn read_at(&mut self, file: &Self::File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.wait();
        StdDisk.read_at(file, offset, buf)
    }

    fn len(&mut self, file: &Self::File) -> std::io::Result<u64> {
        StdDisk.len(file)
    }

    fn set_len(&mut self, file: &Self::File, len: u64) -> std::io::Result<()> {
        StdDisk.set_len(file, len)
    }

    fn sync(&mut self, file: &Self::File) -> std::io::Result<()> {
        StdDisk.sync(file)
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

    fn lock(&mut self, file: &Self::File) -> std::io::Result<()> {
        StdDisk.lock(file)
    }
}

/// karyos#1111: a verification runs off the agent's thread. While its
/// worker's reads are held, a replay of the same recording runs to its
/// end and a second verification is refused to retry; once released, the
/// verification answers the recording's sealed ranges.
#[test]
fn a_verification_never_holds_a_replay() {
    let dir = temp_dir("verify-worker");
    let gate = Arc::new(AtomicBool::new(true));
    let agent = ArchiveHandle::spawn(GatedVerify(Arc::clone(&gate)), &dir, sealing()).unwrap();
    let (id, all) = sealed_recording(&agent);
    let end = u64::try_from(all.len()).unwrap();
    let verify = agent.post_verify(id).unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Seen::default()));
    let replay = agent.replay(replay_of(id, end, Sink::new(&seen))).unwrap();
    assert_eq!(
        replay_ended(&agent),
        ReplayEnded {
            id: replay,
            position: end,
            outcome: ReplayOutcome::Complete
        }
    );
    assert_eq!(seen.lock().unwrap().bytes, all);
    assert!(verify.try_answer().is_none(), "the verification is held");
    let second = agent.post_verify(id).unwrap();
    let mut refused = None;
    for _ in 0..5000 {
        refused = second.try_answer();
        if refused.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(matches!(
        refused,
        Some(Ok(Err(crate::server::RetentionAnswer::Error(_))))
    ));
    gate.store(false, Ordering::Release);
    let mut verified = None;
    for _ in 0..5000 {
        verified = verify.try_answer();
        if verified.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let ranges = verified.unwrap().unwrap().unwrap();
    assert!(!ranges.is_empty());
    assert_eq!(ranges.first().unwrap().start, 0);
    assert_eq!(ranges.last().unwrap().end, end);
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The answer to a posted retention command, waiting up to five seconds.
fn answered<T>(posted: Result<Posted<T>, AgentError>) -> T {
    let posted = posted.unwrap();
    for _ in 0..5000 {
        if let Some(answer) = posted.try_answer() {
            return answer.unwrap();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("no answer");
}

/// karyos#1093: with a retention policy, a purge runs through the
/// retention engine against the recording's store: refused `legal_hold`
/// under a hold, `not_expired` before its retention ran (a backdated
/// segment time included: ADR-0093), `no_close_time` while it records, and
/// `below_min_copies` without a verified copy elsewhere; with one, and the
/// retention run, the recording is purged.
#[test]
fn a_configured_policy_purges_through_the_engine() {
    use crate::integrity::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
    use crate::integrity::retention::{PurgeMode, RetentionPolicy};
    use crate::server::RetentionAnswer;

    let dir = temp_dir("purge-policy");
    let location = [5u8; 32];
    let policy = |retain_for_ns| RetentionPolicy {
        policy: 1,
        version: 1,
        retain_for_ns,
        min_copies: std::num::NonZeroU32::MIN,
        storage_tier: 0,
        purge: PurgeMode::Manual,
    };
    let config = |retain_for_ns| {
        sealing()
            .with_copy_location(Some(location))
            .with_retention_policy(Some(policy(retain_for_ns)))
    };
    let refused = |reason: &str| RetentionAnswer::Refused(reason.to_owned());
    let agent = ArchiveHandle::spawn(StdDisk, &dir, config(3_600_000_000_000)).unwrap();
    let (id, all) = sealed_recording(&agent);
    let end = u64::try_from(all.len()).unwrap();
    assert_eq!(answered(agent.post_hold(id)), RetentionAnswer::Done);
    assert_eq!(
        answered(agent.post_purge(id, end, 1, 9)),
        refused("legal_hold")
    );
    assert_eq!(answered(agent.post_release(id)), RetentionAnswer::Done);
    assert_eq!(
        answered(agent.post_purge(id, end, 2, 9)),
        refused("not_expired")
    );
    // ADR-0093: a backdated segment time never makes a purge early; the
    // recorded close time stands.
    let old = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "seg") {
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
    }
    assert_eq!(
        answered(agent.post_purge(id, end, 5, 9)),
        refused("not_expired")
    );
    // A recording that still records has no close time.
    let drained = Arc::new(AtomicBool::new(false));
    let live = agent
        .start(start(Chunks {
            chunks: vec![frames(1, 9)].into(),
            drained: Arc::clone(&drained),
            ..Chunks::default()
        }))
        .unwrap();
    wait(&drained);
    assert_eq!(
        answered(agent.post_purge(live, 96, 6, 9)),
        refused("no_close_time")
    );
    agent.shutdown().unwrap();

    let agent = ArchiveHandle::spawn(StdDisk, &dir, config(0)).unwrap();
    assert_eq!(
        answered(agent.post_purge(id, end, 3, 9)),
        refused("below_min_copies")
    );
    agent.shutdown().unwrap();

    // A verified copy elsewhere, as a replica's verification records it.
    let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
    let records = journal.records().unwrap();
    let mut copies = CopyCatalog::open(StdDisk, &dir, &mut journal).unwrap();
    let local = copies.current().unwrap();
    if local
        .iter()
        .any(|copy| copy.enforcement == Enforcement::ImmutableAttribute)
    {
        // Not expected under test: a purge would need the attribute's
        // release, which this host's process may not have.
        return;
    }
    copies
        .record(
            CopyRecord {
                sequence: 0,
                recording: id,
                start: 0,
                end,
                location: [6u8; 32],
                digest: crate::integrity::retention::seals_digest(&records, id, 0, end),
                retain_until_ns: 0,
                state: CopyState::Verified,
                enforcement: Enforcement::Unsupported,
            },
            &mut journal,
        )
        .unwrap();
    drop(copies);
    drop(journal);

    let agent = ArchiveHandle::spawn(StdDisk, &dir, config(0)).unwrap();
    assert_eq!(
        answered(agent.post_purge(id, end, 4, 9)),
        RetentionAnswer::Done
    );
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// karyos#1093: a retention policy needs the copy catalog.
#[test]
fn a_policy_without_a_copy_location_is_refused() {
    let dir = temp_dir("policy-no-copies");
    let policy = crate::integrity::retention::RetentionPolicy {
        policy: 1,
        version: 1,
        retain_for_ns: 0,
        min_copies: std::num::NonZeroU32::MIN,
        storage_tier: 0,
        purge: crate::integrity::retention::PurgeMode::Manual,
    };
    let spawned =
        ArchiveHandle::spawn(StdDisk, &dir, sealing().with_retention_policy(Some(policy)));
    assert!(matches!(spawned, Err(AgentError::PolicyWithoutCopies)));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// karyos#1124 review: a purge of a recording a verification reads is
/// refused `verification_running`, so the worker never reads files being
/// deleted; once the verification answers, the purge goes to the engine.
#[test]
fn a_purge_waits_for_the_verification_of_its_recording() {
    use crate::integrity::retention::{PurgeMode, RetentionPolicy};
    use crate::server::RetentionAnswer;

    let dir = temp_dir("purge-while-verifying");
    let gate = Arc::new(AtomicBool::new(true));
    let policy = RetentionPolicy {
        policy: 1,
        version: 1,
        retain_for_ns: 3_600_000_000_000,
        min_copies: std::num::NonZeroU32::MIN,
        storage_tier: 0,
        purge: PurgeMode::Manual,
    };
    let config = sealing()
        .with_copy_location(Some([5u8; 32]))
        .with_retention_policy(Some(policy));
    let agent = ArchiveHandle::spawn(GatedVerify(Arc::clone(&gate)), &dir, config).unwrap();
    let (id, all) = sealed_recording(&agent);
    let end = u64::try_from(all.len()).unwrap();
    let verify = agent.post_verify(id).unwrap();
    assert_eq!(
        answered(agent.post_purge(id, end, 1, 9)),
        RetentionAnswer::Refused(super::retention::VERIFICATION_RUNNING.to_owned())
    );
    gate.store(false, Ordering::Release);
    for _ in 0..5000 {
        if verify.try_answer().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // The flag clears just after the answer is sent.
    let mut answer = RetentionAnswer::Done;
    for request in 2..5000 {
        answer = answered(agent.post_purge(id, end, request, 9));
        if answer != RetentionAnswer::Refused(super::retention::VERIFICATION_RUNNING.to_owned()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(answer, RetentionAnswer::Refused("not_expired".to_owned()));
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A disk that counts modification time reads and, while `immutable` is
/// set, refuses to open a segment data file for writing, as the immutable
/// attribute a local copy sets does (karyos#1121 review).
#[derive(Clone, Default)]
struct Probe {
    immutable: Arc<AtomicBool>,
    /// While set, a segment data file cannot be opened at all.
    unreadable: Arc<AtomicBool>,
    modified: Arc<std::sync::atomic::AtomicU64>,
}

impl Disk for Probe {
    type File = std::fs::File;

    fn modified(&mut self, path: &Path) -> std::io::Result<u64> {
        self.modified.fetch_add(1, Ordering::AcqRel);
        StdDisk.modified(path)
    }

    fn create(&mut self, path: &Path) -> std::io::Result<Self::File> {
        StdDisk.create(path)
    }

    fn create_new(&mut self, path: &Path) -> std::io::Result<Self::File> {
        StdDisk.create_new(path)
    }

    fn open(&mut self, path: &Path) -> std::io::Result<Self::File> {
        if self.immutable.load(Ordering::Acquire)
            && path.extension().is_some_and(|extension| extension == "seg")
        {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        StdDisk.open(path)
    }

    fn open_read(&mut self, path: &Path) -> std::io::Result<Self::File> {
        if self.unreadable.load(Ordering::Acquire)
            && path.extension().is_some_and(|extension| extension == "seg")
        {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        StdDisk.open_read(path)
    }

    fn write_at(&mut self, file: &Self::File, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        StdDisk.write_at(file, offset, bytes)
    }

    fn read_at(&mut self, file: &Self::File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        StdDisk.read_at(file, offset, buf)
    }

    fn len(&mut self, file: &Self::File) -> std::io::Result<u64> {
        StdDisk.len(file)
    }

    fn set_len(&mut self, file: &Self::File, len: u64) -> std::io::Result<()> {
        StdDisk.set_len(file, len)
    }

    fn sync(&mut self, file: &Self::File) -> std::io::Result<()> {
        StdDisk.sync(file)
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

    fn lock(&mut self, file: &Self::File) -> std::io::Result<()> {
        StdDisk.lock(file)
    }
}

/// A purge policy of `retain_for_ns` with one copy required, and the
/// sealing config that carries it with a copy location.
fn purge_config(retain_for_ns: u64) -> AgentConfig {
    use crate::integrity::retention::{PurgeMode, RetentionPolicy};
    sealing()
        .with_copy_location(Some([5u8; 32]))
        .with_retention_policy(Some(RetentionPolicy {
            policy: 1,
            version: 1,
            retain_for_ns,
            min_copies: std::num::NonZeroU32::MIN,
            storage_tier: 0,
            purge: PurgeMode::Manual,
        }))
}

/// Records a verified copy of `id`'s `[0, end)` at another location, as a
/// replica's verification does; false when the local copy took the
/// immutable attribute, which this host's process may not release.
fn copy_elsewhere(dir: &Path, id: u64, end: u64) -> bool {
    use crate::integrity::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
    let mut journal = IntegrityJournal::open(StdDisk, dir).unwrap().journal;
    let records = journal.records().unwrap();
    let mut copies = CopyCatalog::open(StdDisk, dir, &mut journal).unwrap();
    if copies
        .current()
        .unwrap()
        .iter()
        .any(|copy| copy.enforcement == Enforcement::ImmutableAttribute)
    {
        return false;
    }
    copies
        .record(
            CopyRecord {
                sequence: 0,
                recording: id,
                start: 0,
                end,
                location: [6u8; 32],
                digest: crate::integrity::retention::seals_digest(&records, id, 0, end),
                retain_until_ns: 0,
                state: CopyState::Verified,
                enforcement: Enforcement::Unsupported,
            },
            &mut journal,
        )
        .unwrap();
    true
}

/// The segment data files in `dir`, each with its length.
fn segment_lengths(dir: &Path) -> Vec<(PathBuf, u64)> {
    let mut files: Vec<(PathBuf, u64)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "seg"))
        .map(|path| {
            let length = std::fs::metadata(&path).unwrap().len();
            (path, length)
        })
        .collect();
    files.sort();
    files
}

/// karyos#1121 review: segments a local copy made immutable cannot be
/// opened for writing, so a purge validates against a read-only view of
/// the stopped store and still reaches the engine, which purges.
#[test]
fn a_purge_opens_immutable_segments_read_only() {
    use crate::server::RetentionAnswer;

    let dir = temp_dir("purge-immutable");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, purge_config(0)).unwrap();
    let (id, all) = sealed_recording(&agent);
    let end = u64::try_from(all.len()).unwrap();
    agent.shutdown().unwrap();
    if !copy_elsewhere(&dir, id, end) {
        return;
    }
    let probe = Probe::default();
    let agent = ArchiveHandle::spawn(probe.clone(), &dir, purge_config(0)).unwrap();
    probe.immutable.store(true, Ordering::Release);
    assert_eq!(
        answered(agent.post_purge(id, end, 1, 9)),
        RetentionAnswer::Done
    );
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// karyos#1121 review: a purge refused under a legal hold changes no
/// file, even of a recording whose tail recovery would cut: the refusal
/// path never runs a destructive recovery.
#[test]
fn a_refused_purge_never_cuts_a_damaged_tail() {
    use crate::server::RetentionAnswer;

    let dir = temp_dir("purge-damaged-hold");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, purge_config(0)).unwrap();
    let (id, all) = sealed_recording(&agent);
    let end = u64::try_from(all.len()).unwrap();
    // Bytes past the last indexed write: recovery would cut them.
    let (last, _) = segment_lengths(&dir).pop().unwrap();
    let length = std::fs::metadata(&last).unwrap().len();
    std::fs::File::options()
        .write(true)
        .open(&last)
        .unwrap()
        .set_len(length + 64)
        .unwrap();
    let before = segment_lengths(&dir);
    assert_eq!(answered(agent.post_hold(id)), RetentionAnswer::Done);
    assert_eq!(
        answered(agent.post_purge(id, end, 1, 9)),
        RetentionAnswer::Refused("legal_hold".to_owned())
    );
    assert_eq!(segment_lengths(&dir), before);
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// karyos#1121 review: a cutoff past the recording's written end is
/// refused `not_a_write_start` before any segment file is listed, however
/// far past it lies.
#[test]
fn a_cutoff_past_the_written_end_lists_no_file() {
    use crate::server::RetentionAnswer;

    let dir = temp_dir("purge-past-end");
    let probe = Probe::default();
    let agent = ArchiveHandle::spawn(probe.clone(), &dir, purge_config(0)).unwrap();
    let (id, all) = sealed_recording(&agent);
    let end = u64::try_from(all.len()).unwrap();
    // A thousand segments of the test geometry past the end.
    let past = end + 1000 * 8192;
    for (request, before) in [(1, end + 1), (2, past), (3, u64::MAX)] {
        let read = probe.modified.load(Ordering::Acquire);
        assert_eq!(
            answered(agent.post_purge(id, before, request, 9)),
            RetentionAnswer::Refused("not_a_write_start".to_owned())
        );
        assert_eq!(probe.modified.load(Ordering::Acquire), read, "{before}");
    }
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Journals a purge intent of `id` before `before`, as a purge does right
/// before its deletion, from start 0.
fn journal_intent(dir: &Path, request: u64, id: u64, before: u64) {
    use crate::integrity::retention::{
        OPERATION_LENGTH, OPERATIONS_FILE, Operation, OperationsJournal, PurgeSource,
    };
    let mut operations =
        Ledger::<StdDisk, OPERATION_LENGTH>::open(StdDisk, dir, OPERATIONS_FILE).unwrap();
    OperationsJournal::append(
        &mut operations,
        &Operation::PurgeIntent {
            id: request,
            recording: id,
            before,
            operator: 9,
            closed_ns: 1,
            source: PurgeSource::Operator,
            from: 0,
        },
    )
    .unwrap();
}

/// karyos#1121 review: a crash after a purge advanced the store's floor
/// but before its integrity purge record leaves the intent outstanding.
/// The next start reconciles it before serving any request: the purge
/// record is written and the intent completes, so its id is free again.
#[test]
fn a_start_records_a_purge_a_crash_left_unrecorded() {
    use crate::integrity::SealKind;
    use crate::server::RetentionAnswer;

    let dir = temp_dir("purge-crash-recorded");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, purge_config(0)).unwrap();
    let (id, all) = sealed_recording(&agent);
    let end = u64::try_from(all.len()).unwrap();
    agent.shutdown().unwrap();
    journal_intent(&dir, 1, id, end);
    let recording = Catalog::open(StdDisk, &dir)
        .unwrap()
        .catalog
        .get(id)
        .cloned()
        .unwrap();
    let mut store = SegmentStore::recover(StdDisk, &dir, id, recording.geometry, recording.policy)
        .unwrap()
        .store;
    assert_eq!(store.purge_before(end).unwrap(), end);
    drop(store);

    let agent = ArchiveHandle::spawn(StdDisk, &dir, purge_config(0)).unwrap();
    let answer = answered(agent.post_purge(id, end, 1, 9));
    assert_ne!(answer, RetentionAnswer::Refused("duplicate_id".to_owned()));
    agent.shutdown().unwrap();
    let records = IntegrityJournal::open(StdDisk, &dir)
        .unwrap()
        .journal
        .records()
        .unwrap();
    assert!(records.iter().any(|record| record.kind == SealKind::Purge
        && record.subject == id
        && record.start == 0
        && record.end == end));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// karyos#1121 review: an intent a crash left before its deletion is
/// rechecked at the next start against the holds now in force: under a
/// hold it is cancelled and nothing is deleted, so a retry of its id is
/// answered `legal_hold`, never `duplicate_id`.
#[test]
fn a_start_cancels_an_unfinished_purge_under_a_hold() {
    use crate::server::RetentionAnswer;

    let dir = temp_dir("purge-crash-held");
    let agent = ArchiveHandle::spawn(StdDisk, &dir, purge_config(0)).unwrap();
    let (id, all) = sealed_recording(&agent);
    let end = u64::try_from(all.len()).unwrap();
    assert_eq!(answered(agent.post_hold(id)), RetentionAnswer::Done);
    agent.shutdown().unwrap();
    journal_intent(&dir, 7, id, end);
    let before = segment_lengths(&dir);

    let agent = ArchiveHandle::spawn(StdDisk, &dir, purge_config(0)).unwrap();
    assert_eq!(
        answered(agent.post_purge(id, end, 7, 9)),
        RetentionAnswer::Refused("legal_hold".to_owned())
    );
    assert_eq!(segment_lengths(&dir), before);
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// karyos#1121 review: a held recording whose segment files cannot be
/// opened is answered `legal_hold`, never the store's error: holds are
/// checked before the store is opened.
#[test]
fn a_held_purge_is_refused_before_the_store_opens() {
    use crate::server::RetentionAnswer;

    let dir = temp_dir("purge-held-unreadable");
    let probe = Probe::default();
    let agent = ArchiveHandle::spawn(probe.clone(), &dir, purge_config(0)).unwrap();
    let (id, all) = sealed_recording(&agent);
    let end = u64::try_from(all.len()).unwrap();
    assert_eq!(answered(agent.post_hold(id)), RetentionAnswer::Done);
    probe.unreadable.store(true, Ordering::Release);
    assert_eq!(
        answered(agent.post_purge(id, end, 1, 9)),
        RetentionAnswer::Refused("legal_hold".to_owned())
    );
    probe.unreadable.store(false, Ordering::Release);
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// karyos#1121 review: a purge a crash left before its deletion is
/// rechecked at the next start against the segments' modification times
/// as they are now, not the close time its intent saved (ADR-0093,
/// decision 3): segments written within the retention keep it unexpired,
/// so the intent is cancelled and nothing is deleted.
#[test]
fn a_resumed_purge_rechecks_the_segment_times() {
    use crate::server::RetentionAnswer;

    let dir = temp_dir("purge-crash-mtime");
    let hour = 3_600_000_000_000;
    let agent = ArchiveHandle::spawn(StdDisk, &dir, purge_config(hour)).unwrap();
    let (id, all) = sealed_recording(&agent);
    let end = u64::try_from(all.len()).unwrap();
    agent.shutdown().unwrap();
    if !copy_elsewhere(&dir, id, end) {
        return;
    }
    // The intent saved a close time long past.
    journal_intent(&dir, 3, id, end);
    let before = segment_lengths(&dir);

    let agent = ArchiveHandle::spawn(StdDisk, &dir, purge_config(hour)).unwrap();
    assert_eq!(
        answered(agent.post_purge(id, end, 3, 9)),
        RetentionAnswer::Refused("not_expired".to_owned())
    );
    assert_eq!(segment_lengths(&dir), before);
    assert!(
        !dir.join(format!("{id:016x}.floor")).exists(),
        "the floor never moved"
    );
    agent.shutdown().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
