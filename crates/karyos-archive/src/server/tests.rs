// SPDX-License-Identifier: Apache-2.0

// The control server over a fake host, on the real disk: requests in,
// answers and signals out, in order, with their correlation ids; replays
// into the host's sinks; refusals typed; a full response stream holds the
// next request back.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::agent::{AgentConfig, SinkClosed};
use crate::catalog::StopReason;
use crate::disk::StdDisk;
use crate::durable::{DurableState, DurableSync};
use crate::recorder::{Frames, Mode, SourceError};
use crate::segment::SyncPolicy;

const TERM: u32 = 4096;

/// Frames of 96 bytes each, with their length in their first word.
fn frames(count: usize, fill: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..count {
        let mut frame = vec![fill; 96];
        frame[..4].copy_from_slice(&96i32.to_le_bytes());
        bytes.extend_from_slice(&frame);
    }
    bytes
}

/// A lane: `bytes` from 0 in one copy, then sealed once `seal` is set.
/// While `gate` is shut, a read blocks the agent's thread.
struct Lane {
    position: u64,
    bytes: Option<Vec<u8>>,
    seal: Arc<AtomicBool>,
    gate: Arc<AtomicBool>,
}

impl FrameSource for Lane {
    fn position(&self) -> u64 {
        self.position
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        while !self.gate.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
        let Some(bytes) = self.bytes.take() else {
            return Ok(if self.seal.load(Ordering::Acquire) {
                Frames::Sealed { at: self.position }
            } else {
                Frames::Pending
            });
        };
        let position = self.position;
        out[..bytes.len()].copy_from_slice(&bytes);
        self.position += bytes.len() as u64;
        Ok(Frames::Copied {
            position,
            len: bytes.len(),
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

/// What a replay's sink was given; it takes nothing while `held`.
#[derive(Default)]
struct Replayed {
    bytes: Vec<u8>,
    finished: Option<(u64, bool)>,
    held: bool,
}

struct Sink(Arc<Mutex<Replayed>>);

impl ReplaySink for Sink {
    fn frames(&mut self, _position: u64, bytes: &[u8]) -> Result<bool, SinkClosed> {
        let mut replayed = self.0.lock().unwrap();
        if replayed.held {
            return Ok(false);
        }
        replayed.bytes.extend_from_slice(bytes);
        Ok(true)
    }

    fn fill(&mut self, _position: u64, _record: &[u8], _extent: u32) -> Result<bool, SinkClosed> {
        Ok(true)
    }

    fn gap(&mut self, _from: u64, _to: u64) -> Result<bool, SinkClosed> {
        Ok(true)
    }

    fn finish(&mut self, end: u64, complete: bool) {
        self.0.lock().unwrap().finished = Some((end, complete));
    }
}

/// A host whose lanes hold `lane`, seal once `seal` is set and read once
/// `gate` is open; it refuses with `refuse` when set, and its sinks start
/// `held` when `hold` is.
struct Host {
    lane: Vec<u8>,
    seal: Arc<AtomicBool>,
    gate: Arc<AtomicBool>,
    refuse: Option<String>,
    hold: bool,
    replays: Vec<(u64, Arc<Mutex<Replayed>>)>,
    /// The retention state stream (ADR-0101): stream 77 of `karyos:ipc`,
    /// when given.
    answers: Option<Responses>,
}

impl Default for Host {
    fn default() -> Self {
        Self {
            lane: Vec::new(),
            seal: Arc::default(),
            gate: Arc::new(AtomicBool::new(true)),
            refuse: None,
            hold: false,
            replays: Vec::new(),
            answers: None,
        }
    }
}

impl Host {
    /// A host whose lanes hold `lane` and seal at once when `seal`.
    fn of(lane: Vec<u8>, seal: bool) -> Self {
        Self {
            lane,
            seal: Arc::new(AtomicBool::new(seal)),
            ..Self::default()
        }
    }
}

impl ArchiveHost for Host {
    fn open_recording(
        &mut self,
        _request: &control::StartRecording<'_>,
    ) -> Result<HostRecording, HostRefusal> {
        if let Some(why) = &self.refuse {
            return Err(HostRefusal(why.clone()));
        }
        Ok(HostRecording {
            source: Box::new(Lane {
                position: 0,
                bytes: Some(self.lane.clone()),
                seal: Arc::clone(&self.seal),
                gate: Arc::clone(&self.gate),
            }),
            term_length: TERM,
            format: crate::catalog::StreamFormat {
                lane: karyos_sys::frame::Lane::ZERO,
                initial_term_id: 0,
                mtu: core::num::NonZeroU32::new(1408).unwrap(),
                source: crate::catalog::SourceIncarnation {
                    driver: [1, 2],
                    registration: 3,
                    incarnation: 1,
                },
            },
            origin: crate::agent::RecordedFrom::Local,
        })
    }

    fn open_replay(
        &mut self,
        _request: &control::Replay<'_>,
        _recording: &Recording,
        _replay_id: u64,
        from: u64,
        _to: u64,
    ) -> Result<Box<dyn ReplaySink + Send>, HostRefusal> {
        if let Some(why) = &self.refuse {
            return Err(HostRefusal(why.clone()));
        }
        let replayed = Arc::new(Mutex::new(Replayed {
            held: self.hold,
            ..Replayed::default()
        }));
        self.replays.push((from, Arc::clone(&replayed)));
        Ok(Box::new(Sink(replayed)))
    }

    fn open_response(
        &mut self,
        stream_id: i32,
        channel: &str,
    ) -> Result<Box<dyn ResponseSink + Send>, HostRefusal> {
        match &self.answers {
            Some(answers) if stream_id == 77 && channel == "karyos:ipc" => {
                Ok(Box::new(answers.clone()))
            }
            _ => Err(HostRefusal(NO_RESPONSE_STREAM.to_owned())),
        }
    }

    fn free_space(&self) -> (u64, u64) {
        (1 << 30, 8 << 30)
    }
}

/// The request stream, fed by the test.
#[derive(Clone, Default)]
struct Requests(Arc<Mutex<VecDeque<Vec<u8>>>>);

impl RequestSource for Requests {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let request = self.0.lock().unwrap().pop_front()?;
        out[..request.len()].copy_from_slice(&request);
        Some(request.len())
    }
}

/// The response stream, with room for `room` more messages.
#[derive(Clone)]
struct Responses {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    room: Arc<AtomicUsize>,
    /// The longest replication message it takes.
    max: Arc<AtomicUsize>,
    /// Whether it keeps what it is sent; when not, it only counts, so a
    /// test can measure the server's own allocations (karyos#1113).
    keep: Arc<std::sync::atomic::AtomicBool>,
    /// Replication messages sent while not kept.
    counted: Arc<AtomicUsize>,
    /// `RecordingBytes` among them.
    chunks: Arc<AtomicUsize>,
}

impl ResponseSink for Responses {
    fn send(&mut self, message: &[u8]) -> bool {
        if self.room.load(Ordering::Acquire) == 0 {
            return false;
        }
        self.room.fetch_sub(1, Ordering::AcqRel);
        let max = self.max.load(Ordering::Acquire);
        let replication =
            message.get(..2) == Some(&crate::replication::SCHEMA_ID.to_le_bytes()[..]);
        assert!(
            !replication || message.len() <= max,
            "{} > {max}",
            message.len()
        );
        if self.keep.load(Ordering::Acquire) {
            self.sent.lock().unwrap().push(message.to_vec());
        } else if replication {
            self.counted.fetch_add(1, Ordering::AcqRel);
            // Template 101, `RecordingBytes`, at bytes 2 to 4.
            if message.get(2..4) == Some(&101u16.to_le_bytes()[..]) {
                self.chunks.fetch_add(1, Ordering::AcqRel);
            }
        }
        true
    }

    fn max_message(&self) -> usize {
        self.max.load(Ordering::Acquire)
    }
}

struct Rig {
    server: ControlServer<Host, Requests, Responses>,
    requests: Requests,
    responses: Responses,
    dir: PathBuf,
}

impl Rig {
    fn new(name: &str, host: Host) -> Self {
        Self::with(name, host, AgentConfig::default(), ServerConfig::default())
    }

    fn with(name: &str, host: Host, agent: AgentConfig, config: ServerConfig) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "karyos-archive-server-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, agent).unwrap();
        let requests = Requests::default();
        let responses = Responses {
            sent: Arc::default(),
            room: Arc::new(AtomicUsize::new(usize::MAX)),
            max: Arc::new(AtomicUsize::new(usize::MAX)),
            keep: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            counted: Arc::default(),
            chunks: Arc::default(),
        };
        let server = ControlServer::new(agent, host, requests.clone(), responses.clone())
            .with_config(config);
        Self {
            server,
            requests,
            responses,
            dir,
        }
    }

    fn request(&self, message: &ControlMessage<'_>) {
        let mut out = vec![0u8; MAX_REQUEST];
        let length = message.encode(&mut out).unwrap();
        out.truncate(length);
        self.requests.0.lock().unwrap().push_back(out);
    }

    fn raw(&self, bytes: Vec<u8>) {
        self.requests.0.lock().unwrap().push_back(bytes);
    }

    /// Runs duties until `count` messages were sent in all, at most five
    /// seconds; returns them all.
    fn sent(&mut self, count: usize) -> Vec<Vec<u8>> {
        for _ in 0..5000 {
            self.server.duty();
            if self.responses.sent.lock().unwrap().len() >= count {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let sent = self.responses.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), count, "messages sent");
        sent
    }

    fn finish(self) {
        self.server.shutdown().unwrap();
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

fn decoded(bytes: &[u8]) -> ControlMessage<'_> {
    ControlMessage::decode(bytes).unwrap()
}

fn response(bytes: &[u8]) -> ControlResponse<'_> {
    match decoded(bytes) {
        ControlMessage::ControlResponse(response) => response,
        other => panic!("{other:?}"),
    }
}

fn start(correlation_id: u64) -> ControlMessage<'static> {
    ControlMessage::StartRecording(control::StartRecording {
        correlation_id,
        stream_id: 10,
        session_id: 3,
        mode: Mode::Required,
        sync_policy: SyncPolicy::PerSegment,
        segment_length: 0,
        channel: "karyos:ipc",
    })
}

fn replay(
    correlation_id: u64,
    recording_id: u64,
    position: u64,
    length: u64,
) -> ControlMessage<'static> {
    ControlMessage::Replay(control::Replay {
        correlation_id,
        recording_id,
        position,
        length,
        rate: ReplayRate::Full,
        target_stream_id: 20,
        target_channel: "karyos:ipc",
    })
}

/// A recording starts, is signalled with its request's correlation id,
/// ends at its seal with a signal for every reader, and is listed.
#[test]
fn a_recording_starts_ends_and_is_listed() {
    let lane = frames(4, 1);
    let end = lane.len() as u64;
    let mut rig = Rig::new("start", Host::of(lane, true));
    rig.request(&start(7));
    let sent = rig.sent(3);
    assert_eq!(
        response(&sent[0]),
        ControlResponse {
            correlation_id: 7,
            id: 1,
            code: ResponseCode::Ok,
            message: ""
        }
    );
    assert_eq!(
        decoded(&sent[1]),
        ControlMessage::RecordingSignal(RecordingSignal {
            correlation_id: 7,
            recording_id: 1,
            position: 0,
            signal: Signal::Started,
        })
    );
    assert_eq!(
        decoded(&sent[2]),
        ControlMessage::RecordingSignal(RecordingSignal {
            correlation_id: 0,
            recording_id: 1,
            position: end,
            signal: Signal::Stopped {
                reason: StopReason::Normal,
                incomplete: false,
            },
        })
    );
    rig.request(&ControlMessage::ListRecordings(control::ListRecordings {
        correlation_id: 8,
        from_id: 0,
        max_count: 10,
    }));
    let sent = rig.sent(5);
    let ControlMessage::RecordingDescriptor(descriptor) = decoded(&sent[3]) else {
        panic!("a descriptor");
    };
    assert_eq!(descriptor.correlation_id, 8);
    assert_eq!(descriptor.recording_id, 1);
    assert_eq!(descriptor.channel, "karyos:ipc");
    assert_eq!(descriptor.geometry.term_length(), TERM);
    assert!(matches!(
        descriptor.state,
        RecordingState::Stopped(stop) if stop.position == end
    ));
    // The source the host gave, for a live merge to match.
    assert_eq!(
        descriptor.source,
        crate::catalog::SourceIncarnation {
            driver: [1, 2],
            registration: 3,
            incarnation: 1,
        }
    );
    assert_eq!(response(&sent[4]).id, 1);
    // From an id past the last: none, and a count of 0.
    rig.request(&ControlMessage::ListRecordings(control::ListRecordings {
        correlation_id: 9,
        from_id: 2,
        max_count: 10,
    }));
    let sent = rig.sent(6);
    let none = response(&sent[5]);
    assert_eq!((none.correlation_id, none.id), (9, 0));
    rig.finish();
}

/// A recording stopped by request is answered, then signalled stopped;
/// one still recording is listed as recording; a second stop is refused.
#[test]
fn a_recording_stops_by_request() {
    let mut rig = Rig::new("stop", Host::of(frames(2, 2), false));
    rig.request(&start(1));
    rig.sent(2);
    // Once the agent wrote the lane's two frames.
    for _ in 0..5000 {
        if rig.server.agent().describe(1).unwrap().end == 192 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    rig.request(&ControlMessage::ListRecordings(control::ListRecordings {
        correlation_id: 2,
        from_id: 1,
        max_count: 1,
    }));
    let sent = rig.sent(4);
    let ControlMessage::RecordingDescriptor(descriptor) = decoded(&sent[2]) else {
        panic!("a descriptor");
    };
    assert_eq!(
        descriptor.state,
        RecordingState::Recording {
            written: 192,
            incomplete: false
        }
    );
    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 3,
        recording_id: 1,
    }));
    let sent = rig.sent(6);
    assert_eq!(response(&sent[4]).code, ResponseCode::Ok);
    assert!(matches!(
        decoded(&sent[5]),
        ControlMessage::RecordingSignal(RecordingSignal {
            correlation_id: 0,
            signal: Signal::Stopped {
                reason: StopReason::Stopped,
                ..
            },
            ..
        })
    ));
    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 4,
        recording_id: 1,
    }));
    let sent = rig.sent(7);
    let refused = response(&sent[6]);
    assert_eq!(
        (refused.correlation_id, refused.id, refused.code),
        (4, 0, ResponseCode::UnknownRecording)
    );
    rig.finish();
}

/// A replay goes into the host's sink whole, from its position to the
/// recording's end; its range is checked first.
#[test]
fn a_replay_reaches_the_hosts_sink() {
    let lane = frames(4, 3);
    let end = lane.len() as u64;
    let mut rig = Rig::new("replay", Host::of(lane.clone(), true));
    rig.request(&start(1));
    rig.sent(3);
    rig.request(&replay(2, 1, 96, u64::MAX));
    let sent = rig.sent(4);
    let started = response(&sent[3]);
    assert_eq!(
        (started.correlation_id, started.code),
        (2, ResponseCode::Ok)
    );
    let (from, replayed) = rig.server.host().replays[0].clone();
    assert_eq!(from, 96);
    for _ in 0..5000 {
        if replayed.lock().unwrap().finished.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let replayed = replayed.lock().unwrap();
    assert_eq!(replayed.bytes, lane[96..]);
    assert_eq!(replayed.finished, Some((end, true)));
    drop(replayed);
    // Past the end, empty, an unknown recording, an unknown replay.
    rig.request(&replay(3, 1, 0, end + 96));
    rig.request(&replay(4, 1, end, u64::MAX));
    rig.request(&replay(5, 9, 0, 96));
    rig.request(&ControlMessage::StopReplay(control::StopReplay {
        correlation_id: 6,
        replay_id: 9,
    }));
    let sent = rig.sent(8);
    let codes: Vec<(u64, ResponseCode)> = sent[4..]
        .iter()
        .map(|bytes| {
            let response = response(bytes);
            (response.correlation_id, response.code)
        })
        .collect();
    assert_eq!(
        codes,
        [
            (3, ResponseCode::InvalidRequest),
            (4, ResponseCode::InvalidRequest),
            (5, ResponseCode::UnknownRecording),
            (6, ResponseCode::UnknownReplay),
        ]
    );
    assert_eq!(rig.server.host().replays.len(), 1);
    rig.finish();
}

/// Requests that do not decode are answered with the correlation id their
/// block holds; a response is not a request; the host's refusal is sent,
/// cut to the longest message.
#[test]
fn refusals_are_typed_and_correlated() {
    let mut rig = Rig::new("refusals", Host::default());
    // A StopRecording with recording id 0, an unknown schema, a response,
    // and four bytes.
    let mut bytes = vec![0u8; 28];
    let encoded = ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 11,
        recording_id: 1,
    });
    encoded.encode(&mut bytes).unwrap();
    bytes[20..28].fill(0);
    rig.raw(bytes.clone());
    let mut other = bytes.clone();
    other[0] = 2;
    other[12..20].copy_from_slice(&12u64.to_le_bytes());
    rig.raw(other);
    let mut out = vec![0u8; 64];
    let length = ControlMessage::ControlResponse(ControlResponse {
        correlation_id: 13,
        id: 1,
        code: ResponseCode::Ok,
        message: "",
    })
    .encode(&mut out)
    .unwrap();
    rig.raw(out[..length].to_vec());
    rig.raw(vec![1, 0, 2, 0]);
    let sent = rig.sent(4);
    let answers: Vec<(u64, ResponseCode)> = sent
        .iter()
        .map(|bytes| {
            let response = response(bytes);
            assert_eq!(response.id, 0);
            assert!(!response.message.is_empty());
            (response.correlation_id, response.code)
        })
        .collect();
    assert_eq!(
        answers,
        [
            (11, ResponseCode::InvalidRequest),
            (12, ResponseCode::UnsupportedSchema),
            (13, ResponseCode::InvalidRequest),
            (0, ResponseCode::InvalidRequest),
        ]
    );
    rig.server.host_mut().refuse = Some("é".repeat(200));
    rig.request(&start(14));
    let sent = rig.sent(5);
    let refused = response(&sent[4]);
    assert_eq!(refused.code, ResponseCode::Error);
    assert_eq!(refused.message, "é".repeat(128));
    rig.finish();
}

/// While the response stream has no room, answers wait in order and no
/// further request is read.
#[test]
fn a_full_response_stream_holds_the_next_request() {
    let mut rig = Rig::new("backpressure", Host::of(frames(1, 4), false));
    rig.responses.room.store(1, Ordering::Release);
    rig.request(&start(1));
    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 2,
        recording_id: 1,
    }));
    rig.sent(1);
    for _ in 0..10 {
        rig.server.duty();
    }
    // The start's answer went out; its signal waits; the stop is unread.
    assert_eq!(rig.responses.sent.lock().unwrap().len(), 1);
    assert_eq!(rig.server.pending(), 1);
    assert_eq!(rig.requests.0.lock().unwrap().len(), 1);
    rig.responses.room.store(usize::MAX, Ordering::Release);
    let sent = rig.sent(4);
    assert!(matches!(
        decoded(&sent[1]),
        ControlMessage::RecordingSignal(RecordingSignal {
            signal: Signal::Started,
            ..
        })
    ));
    assert_eq!(response(&sent[2]).correlation_id, 2);
    rig.finish();
}

/// #387 review P2: a replay whose start is not a frame boundary, or lies
/// before the recording, is refused before the host opens any target.
#[test]
fn a_bad_replay_start_opens_no_target() {
    let lane = frames(4, 5);
    let end = lane.len() as u64;
    let mut rig = Rig::new("bad-start", Host::of(lane, true));
    rig.request(&start(1));
    rig.sent(3);
    rig.request(&replay(2, 1, 32, 96));
    rig.request(&replay(3, 1, 0, end + 96));
    let sent = rig.sent(5);
    for (bytes, correlation_id) in sent[3..].iter().zip([2, 3]) {
        let refused = response(bytes);
        assert_eq!(
            (refused.correlation_id, refused.code),
            (correlation_id, ResponseCode::InvalidRequest)
        );
    }
    assert!(rig.server.host().replays.is_empty());
    rig.finish();
}

/// #387 review P3: a running replay stopped by request is answered with
/// its id, and its target is finished, incomplete.
#[test]
fn a_running_replay_stops_by_request() {
    let lane = frames(4, 6);
    let mut rig = Rig::new(
        "stop-replay",
        Host {
            hold: true,
            ..Host::of(lane, true)
        },
    );
    rig.request(&start(1));
    rig.sent(3);
    rig.request(&replay(2, 1, 0, u64::MAX));
    let sent = rig.sent(4);
    let started = response(&sent[3]);
    assert_eq!(started.code, ResponseCode::Ok);
    rig.request(&ControlMessage::StopReplay(control::StopReplay {
        correlation_id: 3,
        replay_id: started.id,
    }));
    let sent = rig.sent(5);
    let stopped = response(&sent[4]);
    assert_eq!(
        (stopped.correlation_id, stopped.id, stopped.code),
        (3, started.id, ResponseCode::Ok)
    );
    let (_, replayed) = &rig.server.host().replays[0];
    assert_eq!(replayed.lock().unwrap().finished, Some((0, false)));
    rig.finish();
}

/// #387 review P2: a replay past the agent's cap is refused with an
/// error, counted, and opens no target.
#[test]
fn a_replay_past_the_cap_is_refused() {
    let lane = frames(4, 7);
    let mut rig = Rig::with(
        "replay-cap",
        Host {
            hold: true,
            ..Host::of(lane, true)
        },
        AgentConfig {
            max_replays: 1,
            ..AgentConfig::default()
        },
        ServerConfig::default(),
    );
    rig.request(&start(1));
    rig.sent(3);
    rig.request(&replay(2, 1, 0, u64::MAX));
    rig.request(&replay(3, 1, 0, u64::MAX));
    let sent = rig.sent(5);
    assert_eq!(response(&sent[3]).code, ResponseCode::Ok);
    let refused = response(&sent[4]);
    assert_eq!(
        (refused.correlation_id, refused.code),
        (3, ResponseCode::Error)
    );
    assert!(refused.message.contains("at most 1 replays"));
    assert_eq!(rig.server.agent().refused(), 1);
    assert_eq!(rig.server.host().replays.len(), 1);
    rig.finish();
}

/// #387 review P2: signals waiting for room are capped; more are dropped
/// and counted, never the answers to a request.
#[test]
fn waiting_signals_are_capped() {
    let host = Host::of(frames(1, 8), false);
    let seal = Arc::clone(&host.seal);
    let mut rig = Rig::with(
        "signal-cap",
        host,
        AgentConfig::default(),
        ServerConfig {
            max_pending_signals: 1,
        },
    );
    for correlation_id in 1..=3 {
        rig.request(&start(correlation_id));
    }
    rig.sent(6);
    // Three recordings end with no room for their signals.
    rig.responses.room.store(0, Ordering::Release);
    seal.store(true, Ordering::Release);
    for _ in 0..5000 {
        rig.server.duty();
        if rig.server.dropped_signals() == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(rig.server.dropped_signals(), 2);
    assert_eq!(rig.server.pending(), 1);
    assert_eq!(rig.server.dropped_events(), 0);
    rig.responses.room.store(usize::MAX, Ordering::Release);
    let sent = rig.sent(7);
    assert!(matches!(
        decoded(&sent[6]),
        ControlMessage::RecordingSignal(RecordingSignal {
            signal: Signal::Stopped { .. },
            ..
        })
    ));
    rig.finish();
}

/// #387 review P2: the server never waits for the agent. With the agent's
/// thread blocked in a recording's read, a duty posts the stop and returns
/// at once; the answer goes out in a later duty, once the agent is free.
#[test]
fn the_server_never_waits_for_the_agent() {
    let host = Host::of(frames(1, 9), false);
    let gate = Arc::clone(&host.gate);
    let mut rig = Rig::new("never-blocks", host);
    rig.request(&start(1));
    rig.sent(2);
    // Dropped before the rig: a failed assertion opens the gate, so the
    // rig's shutdown does not wait on a read the gate holds.
    let _open = OpenOnDrop(Arc::clone(&gate));
    gate.store(false, Ordering::Release);
    // Let the agent's thread reach the read and block there.
    std::thread::sleep(Duration::from_millis(50));
    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 2,
        recording_id: 1,
    }));
    let begun = std::time::Instant::now();
    for _ in 0..10 {
        rig.server.duty();
    }
    assert!(begun.elapsed() < Duration::from_millis(500));
    assert!(rig.server.is_waiting());
    assert_eq!(rig.responses.sent.lock().unwrap().len(), 2);
    gate.store(true, Ordering::Release);
    let sent = rig.sent(4);
    assert_eq!(response(&sent[2]).correlation_id, 2);
    rig.finish();
}

/// Opens a gate when dropped.
struct OpenOnDrop(Arc<AtomicBool>);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// The longest answer is a descriptor with the longest channel.
#[test]
fn the_longest_answer_is_a_descriptor() {
    let longest = [
        control::CONTROL_RESPONSE,
        control::RECORDING_DESCRIPTOR,
        control::RECORDING_SIGNAL,
    ]
    .iter()
    .map(|template| template.max_length)
    .max()
    .unwrap();
    assert_eq!(MAX_ANSWER, longest as usize);
}

/// #387 review P3: a replay the archive cannot read for a fault of its
/// own, here a recording whose segment's data file is gone, is an error,
/// not an invalid request.
#[test]
fn a_storage_fault_is_an_error() {
    let mut rig = Rig::new("storage-fault", Host::of(frames(4, 10), true));
    rig.request(&start(1));
    rig.sent(3);
    for entry in std::fs::read_dir(&rig.dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "seg") {
            std::fs::remove_file(path).unwrap();
        }
    }
    rig.request(&replay(2, 1, 0, u64::MAX));
    let sent = rig.sent(4);
    let refused = response(&sent[3]);
    assert_eq!(refused.code, ResponseCode::Error, "{}", refused.message);
    assert!(rig.server.host().replays.is_empty());
    rig.finish();
}

/// A replay target's session id is the replay id's low 32 bits.
#[test]
fn a_replay_session_is_the_ids_low_half() {
    assert_eq!(replay_session_id(7), 7);
    assert_eq!(replay_session_id(0x1_0000_0002), 2);
    assert_eq!(replay_session_id(0xFFFF_FFFF), -1);
    assert_eq!(replay_session_id(0x8000_0000), i32::MIN);
}

fn durable_query(correlation_id: u64, recording_id: u64) -> Vec<u8> {
    let mut out = vec![0u8; MAX_REQUEST];
    let length = durable::QueryDurable {
        correlation_id,
        recording_id,
    }
    .encode(&mut out)
    .unwrap();
    out.truncate(length);
    out
}

fn durable_answer(bytes: &[u8]) -> DurableAnswer {
    match DurabilityMessage::decode(bytes).unwrap() {
        DurabilityMessage::DurablePosition(answer) => answer,
        other => panic!("{other:?}"),
    }
}

/// R-CORE-12 over the control streams: a schema 4 query is answered with
/// the recording's durable position, never ahead of what it wrote, and,
/// once stopped, equal to its stop; an unknown recording and an unknown
/// schema 4 version are refused, typed and correlated; an answer sent as
/// a request is refused.
#[test]
fn test_server_durable_query_answers_the_durable_position() {
    let mut rig = Rig::new("durable", Host::of(frames(2, 2), false));
    rig.request(&start(1));
    rig.sent(2);
    for _ in 0..5000 {
        if rig.server.agent().describe(1).unwrap().end == 192 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    rig.raw(durable_query(2, 1));
    let sent = rig.sent(3);
    let answer = durable_answer(&sent[2]);
    assert_eq!(answer.correlation_id, 2);
    let position = answer.position;
    assert_eq!(
        (
            position.recording_id,
            position.written,
            position.state,
            position.sync
        ),
        (1, 192, DurableState::Recording, DurableSync::PerSegment)
    );
    assert!(position.start <= position.durable && position.durable <= position.written);
    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 3,
        recording_id: 1,
    }));
    rig.sent(5);
    rig.raw(durable_query(4, 1));
    let sent = rig.sent(6);
    let stopped = durable_answer(&sent[5]).position;
    assert_eq!(
        (stopped.state, stopped.written, stopped.durable),
        (DurableState::Stopped, 192, 192)
    );
    assert!(
        stopped.durable >= position.durable,
        "never behind an answer"
    );
    rig.raw(durable_query(5, 99));
    let sent = rig.sent(7);
    let unknown = response(&sent[6]);
    assert_eq!(
        (unknown.correlation_id, unknown.code),
        (5, ResponseCode::UnknownRecording)
    );
    let mut later = durable_query(6, 1);
    later[4] = 2;
    rig.raw(later);
    let sent = rig.sent(8);
    let unsupported = response(&sent[7]);
    assert_eq!(
        (unsupported.correlation_id, unsupported.code),
        (6, ResponseCode::UnsupportedSchema)
    );
    rig.raw(sent[5].clone());
    let sent = rig.sent(9);
    let not_a_request = response(&sent[8]);
    assert_eq!(
        (not_a_request.correlation_id, not_a_request.code),
        (4, ResponseCode::InvalidRequest)
    );
    rig.finish();
}

/// A fake retention engine: recording 42 is held, so its purge is refused
/// with `legal_hold`; recording 7 is unknown; a verification of 42 has two
/// ranges.
#[derive(Default)]
struct Engine {
    calls: Arc<Mutex<Vec<String>>>,
}

impl RetentionControl for Engine {
    fn hold(&mut self, recording: u64) -> RetentionAnswer {
        self.calls.lock().unwrap().push(format!("hold {recording}"));
        if recording == 7 {
            RetentionAnswer::UnknownRecording
        } else {
            RetentionAnswer::HeldWithoutEvidence
        }
    }

    fn release(&mut self, recording: u64) -> RetentionAnswer {
        self.calls
            .lock()
            .unwrap()
            .push(format!("release {recording}"));
        RetentionAnswer::Done
    }

    fn purge(
        &mut self,
        recording: u64,
        before: u64,
        request_id: u64,
        operator: u64,
    ) -> RetentionAnswer {
        self.calls.lock().unwrap().push(format!(
            "purge {recording} {before} {request_id} {operator}"
        ));
        RetentionAnswer::Refused("legal_hold".to_owned())
    }

    fn verify(&mut self, recording: u64) -> Result<Vec<control::RangeOutcome>, RetentionAnswer> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("verify {recording}"));
        let range = |start, end, outcome| control::RangeOutcome {
            correlation_id: 0,
            recording_id: recording,
            start,
            end,
            first_inconsistent: control::NO_INCONSISTENT,
            reasons: 0,
            outcome,
        };
        Ok(vec![
            range(0, 4096, control::IntegrityOutcome::Verified),
            range(4096, 8192, control::IntegrityOutcome::Unsealed),
        ])
    }
}

/// ADR-0088 (karyos#967): the retention requests reach the attached
/// engine with their fields and are answered with its codes and refusal
/// names verbatim; a verification sends its ranges under the request's
/// correlation id, then their count. Without one attached, the agent's
/// engine answers: here the recording is unknown.
#[test]
fn retention_requests_reach_the_engine_and_are_answered_verbatim() {
    let mut rig = Rig::new("retention", Host::default());
    let mut sent = 0;
    for request in [
        ControlMessage::HoldRecording(control::HoldRecording {
            correlation_id: 1,
            recording_id: 42,
        }),
        ControlMessage::VerifyRecording(control::VerifyRecording {
            correlation_id: 2,
            recording_id: 42,
        }),
    ] {
        rig.request(&request);
        sent += 1;
        let answers = rig.sent(sent);
        let answer = response(answers.last().unwrap());
        assert_eq!(
            (answer.correlation_id, answer.code, answer.message),
            (
                request_id(&request),
                ResponseCode::UnknownRecording,
                "no such recording"
            )
        );
    }
    let engine = Engine::default();
    let calls = Arc::clone(&engine.calls);
    rig.server = rig.server.with_retention(Box::new(engine));
    rig.request(&ControlMessage::HoldRecording(control::HoldRecording {
        correlation_id: 3,
        recording_id: 42,
    }));
    rig.request(&ControlMessage::HoldRecording(control::HoldRecording {
        correlation_id: 4,
        recording_id: 7,
    }));
    rig.request(&ControlMessage::ReleaseHold(control::ReleaseHold {
        correlation_id: 5,
        recording_id: 42,
    }));
    rig.request(&ControlMessage::PurgeRecording(control::PurgeRecording {
        correlation_id: 6,
        recording_id: 42,
        before: 4096,
        request_id: 9,
        operator: 1000,
    }));
    rig.request(&ControlMessage::VerifyRecording(control::VerifyRecording {
        correlation_id: 8,
        recording_id: 42,
    }));
    let all = rig.sent(sent + 7);
    let answers: Vec<_> = all[sent..].iter().map(|bytes| decoded(bytes)).collect();
    let summary: Vec<(u64, u64, ResponseCode, &str)> = answers[..4]
        .iter()
        .map(|message| match message {
            ControlMessage::ControlResponse(response) => (
                response.correlation_id,
                response.id,
                response.code,
                response.message,
            ),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        summary,
        [
            (3, 0, ResponseCode::HeldWithoutEvidence, ""),
            (4, 0, ResponseCode::UnknownRecording, "no such recording"),
            (5, 42, ResponseCode::Ok, ""),
            (6, 0, ResponseCode::Refused, "legal_hold"),
        ]
    );
    let ranges: Vec<_> = answers[4..6]
        .iter()
        .map(|message| match message {
            ControlMessage::RangeOutcome(range) => (range.correlation_id, range.start, range.end),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(ranges, [(8, 0, 4096), (8, 4096, 8192)]);
    let count = response(&all[sent + 6]);
    assert_eq!(
        (count.correlation_id, count.id, count.code),
        (8, 2, ResponseCode::Ok)
    );
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "hold 42",
            "hold 7",
            "release 42",
            "purge 42 4096 9 1000",
            "verify 42"
        ]
    );
    rig.finish();
}

fn request_id(message: &ControlMessage<'_>) -> u64 {
    match message {
        ControlMessage::HoldRecording(request) | ControlMessage::VerifyRecording(request) => {
            request.correlation_id
        }
        ControlMessage::ReleaseHold(request) => request.correlation_id,
        ControlMessage::PurgeRecording(request) => request.correlation_id,
        other => panic!("{other:?}"),
    }
}

/// ADR-0088 (karyos#967): without an attached engine, the agent's own
/// retention engine and verifier answer through the control streams. A
/// hold is evidenced (code 0) and blocks a purge (`legal_hold`); a release
/// is done once, then refused `no_evidence`; with no policy configured a
/// purge is refused `no_policy`; a verification reports the recording's
/// sealed ranges once it stopped, with no trust root
/// `untrusted_evidence`.
#[test]
fn the_agents_engine_answers_retention_requests() {
    let agent = AgentConfig {
        seal_interval: Some(Duration::from_millis(1)),
        ..AgentConfig::default()
    };
    let mut rig = Rig::with(
        "agent-retention",
        Host::of(frames(2, 2), false),
        agent,
        ServerConfig::default(),
    );
    rig.request(&start(1));
    rig.sent(2);
    for _ in 0..5000 {
        if rig.server.agent().describe(1).unwrap().durable == 192 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let purge = |correlation_id| {
        ControlMessage::PurgeRecording(control::PurgeRecording {
            correlation_id,
            recording_id: 1,
            before: 96,
            request_id: correlation_id,
            operator: 9,
        })
    };
    let expected = [
        (
            ControlMessage::HoldRecording(control::HoldRecording {
                correlation_id: 2,
                recording_id: 1,
            }),
            ResponseCode::Ok,
            "",
        ),
        (purge(3), ResponseCode::Refused, "legal_hold"),
        (
            ControlMessage::ReleaseHold(control::ReleaseHold {
                correlation_id: 4,
                recording_id: 1,
            }),
            ResponseCode::Ok,
            "",
        ),
        (
            ControlMessage::ReleaseHold(control::ReleaseHold {
                correlation_id: 5,
                recording_id: 1,
            }),
            ResponseCode::Refused,
            "no_evidence",
        ),
        (purge(6), ResponseCode::Refused, "no_policy"),
        (
            ControlMessage::HoldRecording(control::HoldRecording {
                correlation_id: 7,
                recording_id: 99,
            }),
            ResponseCode::UnknownRecording,
            "no such recording",
        ),
    ];
    let mut sent = 2;
    for (request, code, message) in expected {
        rig.request(&request);
        sent += 1;
        let answers = rig.sent(sent);
        let answer = response(answers.last().unwrap());
        assert_eq!(
            (answer.correlation_id, answer.code, answer.message),
            (request_id(&request), code, message)
        );
    }
    // Stopped, its last range sealed as its segment closes; the verifier
    // reads it from the store reopened for reading.
    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 20,
        recording_id: 1,
    }));
    let stopped = rig.sent(sent + 2);
    assert_eq!(response(stopped.get(sent).unwrap()).code, ResponseCode::Ok);
    let verify = ControlMessage::VerifyRecording(control::VerifyRecording {
        correlation_id: 8,
        recording_id: 1,
    });
    let mut ranges = Vec::new();
    for _ in 0..5000 {
        rig.request(&verify);
        let before = rig.responses.sent.lock().unwrap().len();
        let mut answers = Vec::new();
        for _ in 0..5000 {
            rig.server.duty();
            answers = rig.responses.sent.lock().unwrap().clone();
            if answers
                .get(before..)
                .unwrap()
                .iter()
                .any(|bytes| matches!(decoded(bytes), ControlMessage::ControlResponse(_)))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        ranges = answers
            .get(before..)
            .unwrap()
            .iter()
            .filter_map(|bytes| match decoded(bytes) {
                ControlMessage::RangeOutcome(range) => Some(range),
                _ => None,
            })
            .collect::<Vec<_>>();
        let done = response(answers.last().unwrap());
        assert_eq!((done.correlation_id, done.code), (8, ResponseCode::Ok));
        assert_eq!(done.id, u64::try_from(ranges.len()).unwrap());
        if ranges.last().is_some_and(|range| {
            range.outcome != control::IntegrityOutcome::Unsealed && range.end == 192
        }) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!ranges.is_empty());
    for range in &ranges {
        assert_eq!((range.correlation_id, range.recording_id), (8, 1));
        // No trust root: untrusted evidence (bit 0), never corruption
        // (bit 6), and so never verified.
        assert_eq!(
            range.outcome,
            control::IntegrityOutcome::Inconsistent,
            "{range:?}"
        );
        assert_ne!(range.reasons & 1, 0, "{range:?}");
        assert_eq!(range.reasons & (1 << 6), 0, "{range:?}");
    }
    assert_eq!(ranges.first().unwrap().start, 0);
    assert_eq!(ranges.last().unwrap().end, 192);
    rig.finish();
}

/// karyos#1113 review: replication over the control streams. While the
/// response stream has no room, the server holds few answers and the rest
/// wait in the agent; each bytes message fits the stream's longest
/// message; once there is room, the recording's bytes all arrive, in
/// order. A stream too short for any bytes refuses the request.
#[test]
fn replication_keeps_backpressure_and_fits_the_stream() {
    use crate::replication::{self, Mode, ReplicateRecording, ReplicationMessage};
    let agent = AgentConfig {
        seal_interval: Some(Duration::from_millis(1)),
        ..AgentConfig::default()
    };
    let mut rig = Rig::with(
        "replication",
        Host::of(frames(64, 3), false),
        agent,
        ServerConfig::default(),
    );
    rig.responses.max.store(1024, Ordering::Release);
    rig.request(&start(1));
    let all = frames(64, 3);
    let length = u64::try_from(all.len()).unwrap();
    let ended_before = rig.sent(2).len();
    for _ in 0..5000 {
        if rig.server.agent().describe(1).unwrap().durable == length {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // Stopped, so each range is sealed; its answer and signal go out.
    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 2,
        recording_id: 1,
    }));
    // The stop ends with the recording's `Stopped` signal: waited for, so
    // a slow host never measures `ended` before it went out.
    let stopped = |sent: &[Vec<u8>]| {
        sent.iter().any(|message| {
            matches!(
                decoded(message),
                ControlMessage::RecordingSignal(RecordingSignal {
                    recording_id: 1,
                    signal: Signal::Stopped { .. },
                    ..
                })
            )
        })
    };
    let begun = std::time::Instant::now();
    while !stopped(&rig.responses.sent.lock().unwrap()) {
        assert!(begun.elapsed() < Duration::from_secs(30), "never stopped");
        rig.server.duty();
        std::thread::sleep(Duration::from_millis(1));
    }
    let ended = rig.responses.sent.lock().unwrap().len();
    assert!(ended > ended_before);
    let encode = |message: ReplicationMessage<'_>| {
        let mut out = vec![0u8; 256];
        let length = message.encode(&mut out).unwrap();
        out.truncate(length);
        out
    };
    let request = || {
        ReplicationMessage::ReplicateRecording(ReplicateRecording {
            correlation_id: 9,
            recording_id: 1,
            from: 0,
            until: u64::MAX,
            mode: Mode::OnDemand,
        })
    };
    rig.responses.room.store(0, Ordering::Release);
    rig.raw(encode(request()));
    // Back-pressured for certain: the server holds an answer the full
    // stream refused, then keeps its bound for a while (#1067 review: a
    // slow agent could have produced nothing yet).
    let begun = std::time::Instant::now();
    while rig.server.pending() == 0 {
        rig.server.duty();
        assert!(rig.server.pending() <= super::REPLICATION_FORWARD);
        assert!(begun.elapsed() < Duration::from_secs(30), "never held");
        std::thread::sleep(Duration::from_micros(200));
    }
    for _ in 0..2000 {
        rig.server.duty();
        assert!(rig.server.pending() <= super::REPLICATION_FORWARD);
        std::thread::sleep(Duration::from_micros(200));
    }
    assert_eq!(rig.responses.sent.lock().unwrap().len(), ended);
    rig.responses.room.store(usize::MAX, Ordering::Release);
    let mut bytes = Vec::new();
    let mut done = false;
    for _ in 0..10_000 {
        rig.server.duty();
        let sent = rig.responses.sent.lock().unwrap().clone();
        bytes.clear();
        done = false;
        for message in &sent[ended..] {
            match ReplicationMessage::decode(message).unwrap() {
                ReplicationMessage::RecordingBytes(chunk) => {
                    assert_eq!(chunk.start, u64::try_from(bytes.len()).unwrap());
                    bytes.extend_from_slice(chunk.bytes);
                }
                ReplicationMessage::ReplicationStatus(status) => {
                    done |= status.state != replication::State::Streaming;
                }
                _ => {}
            }
        }
        if done {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(done, "a final status");
    assert!(!bytes.is_empty());
    assert_eq!(bytes[..], all[..bytes.len()]);
    let mut short = Rig::with(
        "replication-short",
        Host::of(frames(1, 3), true),
        AgentConfig::default(),
        ServerConfig::default(),
    );
    short.responses.max.store(30, Ordering::Release);
    short.raw(encode(request()));
    let refused = short.sent(1);
    assert_eq!(response(&refused[0]).code, ResponseCode::InvalidRequest);
    short.finish();
    rig.finish();
}

/// A response stream of the test's, with room for `room` messages.
fn answer_stream(room: usize) -> Responses {
    Responses {
        sent: Arc::default(),
        room: Arc::new(AtomicUsize::new(room)),
        max: Arc::new(AtomicUsize::new(usize::MAX)),
        keep: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        counted: Arc::default(),
        chunks: Arc::default(),
    }
}

fn retention_query(correlation_id: u64, stream_id: i32) -> ControlMessage<'static> {
    ControlMessage::RetentionState(control::RetentionState {
        correlation_id,
        from_id: 0,
        max_count: 100,
        response_stream_id: stream_id,
        response_channel: "karyos:ipc",
    })
}

/// An Archive with a retention policy, two stopped recordings and a hold
/// on the first, its rig and its answer stream.
fn retention_rig(name: &str, room: usize) -> (Rig, Responses) {
    use crate::integrity::retention::{PurgeMode, RetentionPolicy};
    let answers = answer_stream(room);
    let host = Host {
        answers: Some(answers.clone()),
        ..Host::of(frames(2, 1), true)
    };
    let policy = RetentionPolicy {
        policy: 1,
        version: 2,
        retain_for_ns: 1_000,
        min_copies: core::num::NonZeroU32::MIN,
        storage_tier: 0,
        purge: PurgeMode::Manual,
    };
    let agent = AgentConfig {
        idle: Duration::from_millis(1),
        seal_interval: Some(Duration::from_millis(1)),
        ..AgentConfig::default()
    }
    .with_copy_location(Some([5u8; 32]))
    .with_retention_policy(Some(policy));
    let mut rig = Rig::with(name, host, agent, ServerConfig::default());
    rig.request(&start(7));
    rig.sent(3);
    rig.request(&start(8));
    rig.sent(6);
    rig.request(&ControlMessage::HoldRecording(control::HoldRecording {
        correlation_id: 9,
        recording_id: 1,
    }));
    let sent = rig.sent(7);
    assert_eq!(response(&sent[6]).code, ResponseCode::Ok);
    (rig, answers)
}

/// ADR-0101: a retention state query is answered on the stream it names,
/// by a descriptor per recording (the hold, the close time, the earliest
/// expiry from it, the policy) and the summary with their count and the
/// host's floor and free space; the shared stream carries no version 2
/// frame.
#[test]
fn a_retention_state_query_is_answered_on_its_own_stream() {
    let (mut rig, answers) = retention_rig("retention-state", usize::MAX);
    rig.request(&retention_query(11, 77));
    for _ in 0..5000 {
        rig.server.duty();
        if answers.sent.lock().unwrap().len() >= 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let own = answers.sent.lock().unwrap().clone();
    assert_eq!(own.len(), 3);
    let descriptors: Vec<control::RetentionDescriptor> = own[..2]
        .iter()
        .map(|bytes| match decoded(bytes) {
            ControlMessage::RetentionDescriptor(descriptor) => descriptor,
            other => panic!("{other:?}"),
        })
        .collect();
    for (descriptor, (id, hold)) in descriptors
        .iter()
        .zip([(1, control::HoldState::Held), (2, control::HoldState::None)])
    {
        assert_eq!(
            (
                descriptor.correlation_id,
                descriptor.recording_id,
                descriptor.hold
            ),
            (11, id, hold)
        );
        assert_ne!(descriptor.close_time_ns, 0, "{descriptor:?}");
        assert_eq!(
            descriptor.earliest_expiry_ns,
            descriptor.close_time_ns + 1_000
        );
        assert_eq!((descriptor.policy, descriptor.policy_version), (1, 2));
        assert_eq!(descriptor.hold_since_ns, 0);
    }
    assert_eq!(
        decoded(&own[2]),
        ControlMessage::RetentionSummary(control::RetentionSummary {
            correlation_id: 11,
            count: 2,
            min_free_bytes: 1 << 30,
            free_bytes: 8 << 30,
        })
    );
    // Nothing more on the shared stream, and no version 2 frame there.
    let shared = rig.sent(7);
    assert!(shared.iter().all(|bytes| bytes[4] == 1));
    // One recording: `from_id` it and `max_count` 1.
    rig.request(&ControlMessage::RetentionState(control::RetentionState {
        correlation_id: 12,
        from_id: 2,
        max_count: 1,
        response_stream_id: 77,
        response_channel: "karyos:ipc",
    }));
    for _ in 0..5000 {
        rig.server.duty();
        if answers.sent.lock().unwrap().len() >= 5 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let own = answers.sent.lock().unwrap().clone();
    assert!(matches!(
        decoded(&own[3]),
        ControlMessage::RetentionDescriptor(control::RetentionDescriptor {
            correlation_id: 12,
            recording_id: 2,
            ..
        })
    ));
    rig.finish();
}

/// ADR-0101: a query naming a stream the host has not is refused with
/// code 1 on the shared stream, one frame; the request is version 2, the
/// refusal version 1.
#[test]
fn a_retention_state_query_without_its_stream_is_refused_on_the_shared_stream() {
    let mut rig = Rig::new("retention-no-stream", Host::default());
    rig.request(&retention_query(3, 77));
    let sent = rig.sent(1);
    assert_eq!(
        response(&sent[0]),
        ControlResponse {
            correlation_id: 3,
            id: 0,
            code: ResponseCode::Error,
            message: NO_RESPONSE_STREAM,
        }
    );
    assert_eq!(sent[0][4], 1, "a version 1 refusal");
    rig.finish();
}

/// ADR-0101, isolation: a retention state answer its own stream holds back
/// never holds back the shared stream: a version 1 request after it is
/// answered at once, while the version 2 answer waits; a second query
/// meanwhile is refused with code 1; the waiting answer goes once there is
/// room.
#[test]
fn a_stalled_retention_answer_never_holds_the_shared_stream() {
    let (mut rig, answers) = retention_rig("retention-stalled", 0);
    rig.request(&retention_query(11, 77));
    rig.request(&ControlMessage::ListRecordings(control::ListRecordings {
        correlation_id: 12,
        from_id: 0,
        max_count: 10,
    }));
    // The list's two descriptors and its count.
    let sent = rig.sent(10);
    assert_eq!(response(&sent[9]).correlation_id, 12);
    assert!(answers.sent.lock().unwrap().is_empty());
    rig.request(&retention_query(13, 77));
    let sent = rig.sent(11);
    assert_eq!(
        (
            response(&sent[10]).correlation_id,
            response(&sent[10]).message
        ),
        (13, RETENTION_ANSWER_BUSY)
    );
    assert!(sent.iter().all(|bytes| bytes[4] == 1));
    answers.room.store(usize::MAX, Ordering::Release);
    for _ in 0..5000 {
        rig.server.duty();
        if answers.sent.lock().unwrap().len() >= 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(answers.sent.lock().unwrap().len(), 3);
    rig.finish();
}

/// A reader of a test response stream: each reader sees every message
/// sent, from its own cursor, as a subscriber of the stream would.
struct Reader {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    next: usize,
}

impl crate::client::ControlResponses for Reader {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let sent = self.sent.lock().unwrap();
        let message = sent.get(self.next)?;
        out[..message.len()].copy_from_slice(message);
        self.next += 1;
        Some(message.len())
    }
}

/// The request stream as a requester writes it.
struct Asking(Requests);

impl crate::client::ControlRequests for Asking {
    fn send(&mut self, message: &[u8]) -> bool {
        self.0.0.lock().unwrap().push_back(message.to_vec());
        true
    }
}

/// ADR-0101's mixed-version validation: a version 1 replay client (the
/// real `Replayer`) and a version 2 agent's requester (the real
/// `RetentionStateRequester`) share one Archive's request and response
/// streams. The agent pages the retention state of 1000 recordings to its
/// own stream while the replay client starts a replay on the shared one:
/// no version 2 frame reaches the shared stream, the replay's start is
/// answered within the replay client's deadline, and the replay finishes.
#[test]
fn a_version_1_replay_and_a_version_2_page_share_one_archive() {
    use crate::client::replay::{ReplaySpec, Replayer, ReplayerConfig, ReplayerEvent};
    use crate::client::retention_state::{RetentionStatePoll, RetentionStateRequester};

    const RECORDINGS: usize = 1000;
    let answers = answer_stream(usize::MAX);
    let host = Host {
        answers: Some(answers.clone()),
        ..Host::of(frames(2, 1), true)
    };
    let mut rig = Rig::new("mixed-versions", host);
    // 1000 stopped recordings: each start, its started and stopped signals.
    for index in 0..RECORDINGS {
        rig.request(&start(index as u64 + 1));
    }
    // Their signals come from the Archive's agent thread, which a loaded
    // host slows: wait on the signals themselves, bounded by a deadline
    // far above any load seen, not by a count of duties (karyos#967).
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    while rig.responses.sent.lock().unwrap().len() < 3 * RECORDINGS
        && std::time::Instant::now() < deadline
    {
        rig.server.duty();
        std::thread::sleep(Duration::from_micros(200));
    }
    let before = rig.responses.sent.lock().unwrap().len();
    assert_eq!(before, 3 * RECORDINGS, "the recordings started and stopped");
    let shared = |next| Reader {
        sent: Arc::clone(&rig.responses.sent),
        next,
    };
    let mut replayer = Replayer::new(
        ReplayerConfig::new(0x5250),
        Asking(rig.requests.clone()),
        shared(before),
    );
    let mut agent = RetentionStateRequester::new(0x4b52_5354, 77, "karyos:ipc");
    let mut agent_requests = Asking(rig.requests.clone());
    let mut agent_shared = shared(before);
    let mut agent_own = Reader {
        sent: Arc::clone(&answers.sent),
        next: 0,
    };
    let mut ask = |agent: &mut RetentionStateRequester| {
        agent.poll(&mut agent_requests, &mut agent_shared, Some(&mut agent_own))
    };
    // The agent's query first, then the replay behind it.
    agent.start(0, 1000);
    assert_eq!(ask(&mut agent), RetentionStatePoll::Pending);
    let asked = std::time::Instant::now();
    replayer.start(&ReplaySpec::new(1, 0, 20), asked).unwrap();
    let mut page = None;
    let mut started = None;
    let begun = std::time::Instant::now();
    while (page.is_none() || started.is_none()) && begun.elapsed() < Duration::from_secs(120) {
        rig.server.duty();
        if page.is_none() {
            match ask(&mut agent) {
                RetentionStatePoll::Pending => {}
                RetentionStatePoll::Answered {
                    descriptors,
                    summary,
                } => page = Some((descriptors.len(), summary.count)),
                other => panic!("{other:?}"),
            }
        }
        if started.is_none()
            && let Some(event) = replayer.poll(std::time::Instant::now())
        {
            started = Some((event, asked.elapsed()));
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    assert_eq!(page, Some((RECORDINGS, RECORDINGS as u64)), "the full page");
    let (event, took) = started.unwrap();
    assert!(
        matches!(event, ReplayerEvent::Started { .. }),
        "{event:?} after {took:?}"
    );
    assert!(took < ReplayerConfig::new(0x5250).deadline, "{took:?}");
    // The replay finishes into its target.
    let replayed = Arc::clone(&rig.server.host().replays[0].1);
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while replayed.lock().unwrap().finished.is_none() && std::time::Instant::now() < deadline {
        rig.server.duty();
        std::thread::sleep(Duration::from_millis(1));
    }
    let finished = replayed.lock().unwrap().finished;
    assert!(
        matches!(finished, Some((end, _)) if end == frames(2, 1).len() as u64),
        "{finished:?}"
    );
    // No version 2 frame on the shared stream; all 1001 on the agent's.
    let shared = rig.responses.sent.lock().unwrap().clone();
    assert!(shared.iter().all(|bytes| bytes[4] == 1));
    assert_eq!(answers.sent.lock().unwrap().len(), RECORDINGS + 1);
    rig.finish();
}

/// karyos#1113: forwarding a running replication allocates nothing on
/// the server: its answers' buffers and its batch are reused. The sink
/// only counts while measured, so the count is the server's own.
#[test]
fn forwarding_a_steady_replication_allocates_nothing() {
    use crate::replication::{self, Mode, ReplicateRecording, ReplicationMessage};
    let agent = AgentConfig {
        seal_interval: Some(Duration::from_millis(1)),
        ..AgentConfig::default()
    };
    // Within one 64 KiB term of the test lane.
    let all = frames(600, 5);
    let mut rig = Rig::with(
        "replication-alloc",
        Host::of(all.clone(), false),
        agent,
        ServerConfig::default(),
    );
    // Small messages: many forwarding passes for one recording.
    rig.responses.max.store(256, Ordering::Release);
    rig.request(&start(1));
    let length = u64::try_from(all.len()).unwrap();
    for _ in 0..10_000 {
        let _ = rig.server.duty();
        if rig
            .server
            .agent()
            .describe(1)
            .is_ok_and(|described| described.durable == length)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 2,
        recording_id: 1,
    }));
    // Until the whole recording is sealed: an on-demand replication sends
    // only sealed ranges and ends caught up at the sealed end, so one
    // requested before the tail's seal sends too little to fill a batch.
    // A probe replication is repeated until its final status names the
    // full length, bounded by a deadline (karyos#1067): before, 500 duties
    // stood in for the seal, too few on a loaded host.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let mut probe = 100;
    'sealed: loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the recording was never sealed to its end"
        );
        probe += 1;
        let mut out = vec![0u8; 256];
        let written = ReplicationMessage::ReplicateRecording(ReplicateRecording {
            correlation_id: probe,
            recording_id: 1,
            from: 0,
            until: u64::MAX,
            mode: Mode::OnDemand,
        })
        .encode(&mut out)
        .unwrap();
        out.truncate(written);
        let seen = rig.responses.sent.lock().unwrap().len();
        rig.raw(out);
        while std::time::Instant::now() < deadline {
            rig.server.duty();
            let sent = rig.responses.sent.lock().unwrap().clone();
            let status =
                sent[seen..]
                    .iter()
                    .find_map(|message| match ReplicationMessage::decode(message) {
                        Ok(ReplicationMessage::ReplicationStatus(status))
                            if status.correlation_id == probe
                                && status.state != replication::State::Streaming =>
                        {
                            Some(status.sealed_end)
                        }
                        _ => None,
                    });
            if let Some(sealed_end) = status {
                if sealed_end == length {
                    break 'sealed;
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut out = vec![0u8; 256];
    let request = ReplicationMessage::ReplicateRecording(ReplicateRecording {
        correlation_id: 9,
        recording_id: 1,
        from: 0,
        until: u64::MAX,
        mode: Mode::OnDemand,
    });
    let written = request.encode(&mut out).unwrap();
    out.truncate(written);
    rig.responses.keep.store(false, Ordering::Release);
    rig.raw(out);
    // Two messages a duty: the replication runs over many duties, at the
    // sink's pace. Warm up, bounded in time: a full pending batch, then
    // flushed outside the measurement, so the spare buffers and the batch
    // have reached their size before it starts.
    rig.responses.room.store(0, Ordering::Release);
    let warm = std::time::Instant::now();
    while rig.server.pending() < super::REPLICATION_FORWARD {
        // 120 s: a loaded host fills the batch slowly (karyos#1067).
        assert!(
            warm.elapsed() < Duration::from_secs(120),
            "no full batch: {} pending",
            rig.server.pending()
        );
        rig.server.duty();
        std::thread::sleep(Duration::from_micros(200));
    }
    rig.responses
        .room
        .store(super::REPLICATION_FORWARD, Ordering::Release);
    rig.server.duty();
    for _ in 0..10 {
        rig.responses.room.store(2, Ordering::Release);
        rig.server.duty();
        std::thread::sleep(Duration::from_micros(200));
    }
    let before = rig.responses.chunks.load(Ordering::Acquire);
    let mut allocations = 0;
    for _ in 0..60 {
        rig.responses.room.store(2, Ordering::Release);
        let ((), made) = karyos_sys::alloc_count::count(|| {
            let _ = rig.server.duty();
        });
        allocations += made;
        std::thread::sleep(Duration::from_micros(200));
    }
    let forwarded = rig.responses.chunks.load(Ordering::Acquire) - before;
    assert!(
        forwarded > 0,
        "recording bytes went on during the measurement"
    );
    assert_eq!(allocations, 0, "forwarded {forwarded} chunks");
    rig.finish();
}
