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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::agent::{AgentConfig, SinkClosed};
use crate::catalog::StopReason;
use crate::disk::StdDisk;
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

/// A lane: `bytes` from 0 in one copy, then sealed when `seal`.
struct Lane {
    position: u64,
    bytes: Option<Vec<u8>>,
    seal: bool,
}

impl FrameSource for Lane {
    fn position(&self) -> u64 {
        self.position
    }

    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError> {
        let Some(bytes) = self.bytes.take() else {
            return Ok(if self.seal {
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

/// What a replay's sink was given.
#[derive(Default)]
struct Replayed {
    bytes: Vec<u8>,
    finished: Option<(u64, bool)>,
}

struct Sink(Arc<Mutex<Replayed>>);

impl ReplaySink for Sink {
    fn frames(&mut self, _position: u64, bytes: &[u8]) -> Result<bool, SinkClosed> {
        self.0.lock().unwrap().bytes.extend_from_slice(bytes);
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

/// A host whose lanes hold `lane` and seal when `seal`, and which refuses
/// with `refuse` when set.
#[derive(Default)]
struct Host {
    lane: Vec<u8>,
    seal: bool,
    refuse: Option<String>,
    replays: Vec<(u64, Arc<Mutex<Replayed>>)>,
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
                seal: self.seal,
            }),
            term_length: TERM,
            format: crate::catalog::StreamFormat {
                lane: karyos_sys::frame::Lane::ZERO,
                initial_term_id: 0,
                mtu: 1408,
            },
        })
    }

    fn open_replay(
        &mut self,
        _request: &control::Replay<'_>,
        _recording: &Recording,
        from: u64,
        _to: u64,
    ) -> Result<Box<dyn ReplaySink + Send>, HostRefusal> {
        if let Some(why) = &self.refuse {
            return Err(HostRefusal(why.clone()));
        }
        let replayed = Arc::default();
        self.replays.push((from, Arc::clone(&replayed)));
        Ok(Box::new(Sink(replayed)))
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
}

impl ResponseSink for Responses {
    fn send(&mut self, message: &[u8]) -> bool {
        if self.room.load(Ordering::Acquire) == 0 {
            return false;
        }
        self.room.fetch_sub(1, Ordering::AcqRel);
        self.sent.lock().unwrap().push(message.to_vec());
        true
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
        let dir = std::env::temp_dir().join(format!(
            "karyos-archive-server-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let requests = Requests::default();
        let responses = Responses {
            sent: Arc::default(),
            room: Arc::new(AtomicUsize::new(usize::MAX)),
        };
        let server = ControlServer::new(agent, host, requests.clone(), responses.clone());
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
    let mut rig = Rig::new(
        "start",
        Host {
            lane,
            seal: true,
            ..Host::default()
        },
    );
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
    let mut rig = Rig::new(
        "stop",
        Host {
            lane: frames(2, 2),
            ..Host::default()
        },
    );
    rig.request(&start(1));
    rig.sent(2);
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
        RecordingState::Recording { incomplete: false }
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
    let mut rig = Rig::new(
        "replay",
        Host {
            lane: lane.clone(),
            seal: true,
            ..Host::default()
        },
    );
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
    let mut rig = Rig::new(
        "backpressure",
        Host {
            lane: frames(1, 4),
            ..Host::default()
        },
    );
    rig.responses.room.store(1, Ordering::Release);
    rig.request(&start(1));
    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 2,
        recording_id: 1,
    }));
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
