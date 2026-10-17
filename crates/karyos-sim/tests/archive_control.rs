// SPDX-License-Identifier: Apache-2.0

//! The Archive controlled over Karyos streams end to end (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A5c; archive-control-codec.md
//! §7a). A client sends A1's requests on a request stream and reads the
//! answers on a response stream; the control server serves them with the
//! agent, and the host opens the driver's streams behind `ArchiveHost`: a
//! lane's reader to record, a replay target to replay into.
//!
//! - A recording is started, fed, stopped and listed by request, with its
//!   signals.
//! - A replay of the whole recording delivers every message at its
//!   recorded position, byte-exact, and ends at the recording's end with a
//!   clean EOS; a replay of a range delivers that range.
//! - Pacing (as recorded and scaled) is covered where its clock can be
//!   set: `ReplaySource`'s tests in karyos-archive. The agent paces on its
//!   own monotonic clock.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use karyos_archive::agent::{AgentConfig, ArchiveHandle, ReplaySink, SinkClosed};
use karyos_archive::catalog::{Recording, StopReason, StreamFormat};
use karyos_archive::control::{
    self, ControlMessage, ControlResponse, RecordingSignal, ReplayRate, ResponseCode, Signal,
};
use karyos_archive::disk::StdDisk;
use karyos_archive::recorder::Mode;
use karyos_archive::segment::SyncPolicy;
use karyos_archive::server::{
    ArchiveHost, ControlServer, HostRecording, HostRefusal, MAX_REQUEST, RequestSource,
    ResponseSink,
};
use karyos_archive::source::Guarded;
use karyos_client::aggregate::LaneEnd;
use karyos_client::{ClientPublication, ClientSubscription, MessageLimit, OfferOutcome};
use karyos_driver::embedded::{AggregateHandle, EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_driver::replay::{ReplayFeed, ReplayTargetConfig};
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role, SealReason};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::HeapTerms;

const DATA: i32 = 42;
const REQUESTS: i32 = 100;
const RESPONSES: i32 = 101;
const TARGET: i32 = 200;
const INITIAL_TERM_ID: i32 = 7;
const BUDGET: Budget = Budget {
    work: 256,
    bytes: 1 << 22,
};

fn stream(stream_id: i32) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 6,
            max_subscribers: 8,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(INITIAL_TERM_ID.cast_unsigned()),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: 1_000_000_000,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// A replay that ended, for the host to finish on its thread.
struct Ended {
    handle: AggregateHandle,
    feed: ReplayFeed<HeapTerms>,
    to: u64,
}

/// The host: the driver, the stream to record, and the replay targets.
struct Host {
    driver: EmbeddedDriver,
    data: StreamHandle,
    next_session: i32,
    /// Each replay target's reader, subscribed before the replay starts.
    targets: Vec<karyos_client::aggregate::AggregateSubscription<HeapTerms>>,
    ended: (Sender<Ended>, Receiver<Ended>),
}

impl Host {
    /// Finishes the replays that ended: their targets seal.
    fn finish_ended(&mut self) {
        while let Ok(ended) = self.ended.1.try_recv() {
            self.driver
                .finish_replay(ended.handle, ended.feed, ended.to)
                .unwrap();
        }
    }
}

impl ArchiveHost for Host {
    fn open_recording(
        &mut self,
        request: &control::StartRecording<'_>,
    ) -> Result<HostRecording, HostRefusal> {
        if request.stream_id != DATA {
            return Err(HostRefusal("no such stream".to_owned()));
        }
        let (reader, lease) = self
            .driver
            .recording_reader(self.data, Role::Required)
            .map_err(|error| HostRefusal(error.to_string()))?
            .into_parts();
        Ok(HostRecording {
            source: Box::new(Guarded::new(reader, lease)),
            term_length: MIN_TERM_LENGTH,
            format: StreamFormat {
                lane: Lane::ZERO,
                initial_term_id: INITIAL_TERM_ID,
                mtu: DEFAULT_MTU,
            },
        })
    }

    fn open_replay(
        &mut self,
        request: &control::Replay<'_>,
        recording: &Recording,
        from: u64,
        to: u64,
    ) -> Result<Box<dyn ReplaySink + Send>, HostRefusal> {
        self.next_session += 1;
        let (handle, feed) = self
            .driver
            .replay_target(ReplayTargetConfig {
                stream_id: request.target_stream_id,
                session_id: self.next_session,
                term_length: recording.geometry.term_length(),
                initial_term_id: recording.format.initial_term_id,
                mtu: recording.format.mtu,
                join: from,
                lane: recording.format.lane,
            })
            .map_err(|error| HostRefusal(error.to_string()))?;
        let reader = self
            .driver
            .subscribe_aggregate(&handle, Role::Required)
            .map_err(|error| HostRefusal(error.to_string()))?;
        self.targets.push(reader);
        Ok(Box::new(Sink {
            feed: Some(feed),
            handle,
            to,
            ended: self.ended.0.clone(),
        }))
    }
}

/// A replay's sink on the agent's thread: the target's feed, handed back
/// to the host at the end.
struct Sink {
    feed: Option<ReplayFeed<HeapTerms>>,
    handle: AggregateHandle,
    to: u64,
    ended: Sender<Ended>,
}

impl Sink {
    fn feed(&mut self) -> Result<&mut ReplayFeed<HeapTerms>, SinkClosed> {
        self.feed.as_mut().ok_or(SinkClosed)
    }
}

impl ReplaySink for Sink {
    fn frames(&mut self, position: u64, bytes: &[u8]) -> Result<bool, SinkClosed> {
        self.feed()?.frames(position, bytes).map_err(|_| SinkClosed)
    }

    fn fill(&mut self, position: u64, record: &[u8], extent: u32) -> Result<bool, SinkClosed> {
        self.feed()?
            .fill(position, record, extent)
            .map_err(|_| SinkClosed)
    }

    fn gap(&mut self, from: u64, to: u64) -> Result<bool, SinkClosed> {
        self.feed()?.gap(from, to).map_err(|_| SinkClosed)
    }

    fn finish(&mut self, _end: u64, _complete: bool) {
        if let Some(feed) = self.feed.take() {
            let _ = self.ended.send(Ended {
                handle: self.handle,
                feed,
                to: self.to,
            });
        }
    }
}

/// The request stream, read by the server.
struct Requests(ClientSubscription);

impl RequestSource for Requests {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut length = None;
        let _ = self.0.poll(
            |bytes, _| {
                out[..bytes.len()].copy_from_slice(bytes);
                length = Some(bytes.len());
            },
            MessageLimit::new(1),
        );
        length
    }
}

/// The response stream, written by the server.
struct Responses(ClientPublication);

impl ResponseSink for Responses {
    fn send(&mut self, message: &[u8]) -> bool {
        matches!(self.0.offer(message), Ok(OfferOutcome::Accepted { .. }))
    }
}

/// The client: requests out, answers in.
struct Client {
    requests: ClientPublication,
    responses: ClientSubscription,
}

struct Rig {
    server: ControlServer<Host, Requests, Responses>,
    client: Client,
    dir: PathBuf,
}

impl Rig {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("karyos-sim-archive-control-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let mut driver = EmbeddedDriver::new().unwrap();
        let data = driver.add_stream(stream(DATA)).unwrap();
        let requests = driver.add_stream(stream(REQUESTS)).unwrap();
        let responses = driver.add_stream(stream(RESPONSES)).unwrap();
        let client = Client {
            requests: driver.publication(requests).unwrap(),
            responses: driver.subscribe(responses, Role::Required).unwrap(),
        };
        let server_requests = Requests(driver.subscribe(requests, Role::Required).unwrap());
        let server_responses = Responses(driver.publication(responses).unwrap());
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let host = Host {
            driver,
            data,
            next_session: 1,
            targets: Vec::new(),
            ended: channel(),
        };
        Self {
            server: ControlServer::new(agent, host, server_requests, server_responses),
            client,
            dir,
        }
    }

    fn driver(&mut self) -> &mut EmbeddedDriver {
        &mut self.server.host_mut().driver
    }

    /// One cycle: the driver, the server, the replays that ended.
    fn cycle(&mut self) {
        self.driver().do_work().unwrap();
        self.server.duty();
        self.server.host_mut().finish_ended();
    }

    fn request(&mut self, message: &ControlMessage<'_>) {
        let mut out = vec![0u8; MAX_REQUEST];
        let length = message.encode(&mut out).unwrap();
        loop {
            if let Ok(OfferOutcome::Accepted { .. }) = self.client.requests.offer(&out[..length]) {
                return;
            }
            self.cycle();
        }
    }

    /// The next `count` answers and signals, as bytes.
    fn answers(&mut self, count: usize) -> Vec<Vec<u8>> {
        let start = Instant::now();
        let mut answers = Vec::new();
        while answers.len() < count {
            assert!(start.elapsed() < Duration::from_secs(10), "no answer");
            self.cycle();
            let _ = self.client.responses.poll(
                |bytes, _| answers.push(bytes.to_vec()),
                MessageLimit::new(16),
            );
        }
        assert_eq!(answers.len(), count);
        answers
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn response(bytes: &[u8]) -> ControlResponse<'_> {
    match ControlMessage::decode(bytes).unwrap() {
        ControlMessage::ControlResponse(response) => response,
        other => panic!("{other:?}"),
    }
}

fn signal(bytes: &[u8]) -> RecordingSignal {
    match ControlMessage::decode(bytes).unwrap() {
        ControlMessage::RecordingSignal(signal) => signal,
        other => panic!("{other:?}"),
    }
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
        target_stream_id: TARGET,
        target_channel: "karyos:ipc",
    })
}

/// Reads the newest replay target to its terminal; returns its messages
/// with their positions, and how its lane ended.
fn read_target(rig: &mut Rig) -> (Vec<(u64, Vec<u8>)>, LaneEnd, bool) {
    let mut reader = rig.server.host_mut().targets.pop().unwrap();
    let mut messages = Vec::new();
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(20), "no terminal");
        rig.cycle();
        let poll = reader.poll(
            |bytes, _, info| messages.push((info.position, bytes.to_vec())),
            BUDGET,
        );
        if let Some(terminal) = poll.terminal {
            return (messages, poll.lanes[0].end.unwrap(), terminal.clean);
        }
    }
}

/// A recording made and replayed by request over streams: every message
/// comes back at its recorded position, byte-exact, whole or by range.
#[test]
fn a_recording_is_made_and_replayed_by_request() {
    let mut rig = Rig::new();
    // Reads the data stream as the recording does, for the expected
    // messages and positions.
    let data = rig.server.host().data;
    let mut witness = rig.driver().subscribe(data, Role::Required).unwrap();
    let mut publication = rig.driver().publication(data).unwrap();

    rig.request(&ControlMessage::StartRecording(control::StartRecording {
        correlation_id: 1,
        stream_id: DATA,
        session_id: 1,
        mode: Mode::Required,
        sync_policy: SyncPolicy::PerSegment,
        segment_length: 0,
        channel: "karyos:ipc",
    }));
    let answers = rig.answers(2);
    let started = response(&answers[0]);
    assert_eq!(
        (started.correlation_id, started.code),
        (1, ResponseCode::Ok)
    );
    let recording_id = started.id;
    assert_eq!(signal(&answers[1]).signal, Signal::Started);

    // Messages of several sizes, some fragmented, over three terms.
    let mut expected = Vec::new();
    let mut sent = 0u32;
    let start = Instant::now();
    while expected
        .last()
        .is_none_or(|(position, _)| *position < 3 * u64::from(MIN_TERM_LENGTH))
    {
        assert!(start.elapsed() < Duration::from_secs(20), "not published");
        let length = [100usize, 1400, 3000][usize::try_from(sent % 3).unwrap()];
        let mut message = vec![u8::try_from(sent % 251).unwrap(); length];
        message[..4].copy_from_slice(&sent.to_le_bytes());
        if let Ok(OfferOutcome::Accepted { .. }) = publication.offer(&message) {
            sent += 1;
        }
        rig.cycle();
        let _ = witness.poll(
            |bytes, info| expected.push((info.position, bytes.to_vec())),
            MessageLimit::new(64),
        );
    }

    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 2,
        recording_id,
    }));
    let answers = rig.answers(2);
    assert_eq!(response(&answers[0]).code, ResponseCode::Ok);
    let stopped = signal(&answers[1]);
    assert!(matches!(
        stopped.signal,
        Signal::Stopped {
            reason: StopReason::Stopped,
            incomplete: false
        }
    ));
    let end = stopped.position;
    expected.retain(|(position, _)| *position <= end);

    // The whole recording.
    rig.request(&replay(3, recording_id, 0, u64::MAX));
    let answers = rig.answers(1);
    assert_eq!(response(&answers[0]).code, ResponseCode::Ok);
    let (messages, lane_end, clean) = read_target(&mut rig);
    assert_eq!(messages.len(), expected.len());
    assert!(messages == expected, "byte-exact at the recorded positions");
    assert_eq!(
        lane_end,
        LaneEnd::Closed {
            position: end,
            reason: SealReason::EndOfStream
        }
    );
    assert!(clean);

    // The second term only: it starts and ends at term boundaries.
    let term = u64::from(MIN_TERM_LENGTH);
    rig.request(&replay(4, recording_id, term, term));
    let answers = rig.answers(1);
    assert_eq!(response(&answers[0]).code, ResponseCode::Ok);
    let (messages, lane_end, clean) = read_target(&mut rig);
    assert!(!messages.is_empty());
    let first = expected
        .iter()
        .position(|message| *message == messages[0])
        .unwrap();
    assert_eq!(expected[first..first + messages.len()], messages[..]);
    assert!(
        messages
            .iter()
            .all(|(position, _)| (term..=2 * term).contains(position))
    );
    assert_eq!(
        lane_end,
        LaneEnd::Closed {
            position: 2 * term,
            reason: SealReason::EndOfStream
        }
    );
    assert!(clean);

    // A range past the recording's end is refused.
    rig.request(&replay(5, recording_id, 0, end + term));
    let answers = rig.answers(1);
    assert_eq!(response(&answers[0]).code, ResponseCode::InvalidRequest);
    drop(witness);
    drop(publication);
}
