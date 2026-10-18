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
//!   clean EOS; a replay of a range delivers that range. The same holds
//!   for a recording whose terms cross the term id wrap: the target takes
//!   the recording's first term id, not one of its own.
//! - Pacing (as recorded and scaled) is covered where its clock can be
//!   set: `ReplaySource`'s tests in karyos-archive. The agent paces on its
//!   own monotonic clock.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use karyos_archive::agent::{AgentConfig, ArchiveHandle, ReplaySink, SinkClosed};
use karyos_archive::catalog::{Recording, SourceIncarnation, StopReason, StreamFormat};
use karyos_archive::control::{
    self, ControlMessage, ControlResponse, RecordingSignal, ReplayRate, ResponseCode, Signal,
};
use karyos_archive::disk::StdDisk;
use karyos_archive::recorder::Mode;
use karyos_archive::segment::SyncPolicy;
use karyos_archive::server::{
    ArchiveHost, ControlServer, HostRecording, HostRefusal, MAX_REQUEST, RequestSource,
    ResponseSink, replay_session_id,
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
/// This client's correlation ids: its own id in the high 32 bits, so they
/// never collide with another requester's (§7a).
const CLIENT: u64 = 0xC1 << 32;
const INITIAL_TERM_ID: u32 = 7;
/// Two terms below the term id wrap: a recording of three terms crosses
/// it.
const WRAPPING_TERM_ID: u32 = u32::MAX - 1;
const BUDGET: Budget = Budget {
    work: 256,
    bytes: 1 << 22,
};

fn stream(stream_id: i32, initial_term_id: u32) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 6,
            max_subscribers: 8,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(initial_term_id),
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
    /// Each replay target's stream and session ids, as opened.
    opened: Vec<(i32, i32)>,
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
        // The source's incarnation, from the driver's identity of the
        // stream recorded.
        let identity = self
            .driver
            .trace_identity(self.data)
            .map_err(|error| HostRefusal(error.to_string()))?;
        // The recorded lane's format, from its reader: the driver drew its
        // initial term id.
        let recording = self
            .driver
            .recording_reader(self.data, Role::Required)
            .map_err(|error| HostRefusal(error.to_string()))?;
        let format = recording.format();
        let (reader, lease) = recording.into_parts();
        Ok(HostRecording {
            source: Box::new(Guarded::new(reader, lease)),
            term_length: format.term_length,
            format: StreamFormat {
                lane: format.lane,
                initial_term_id: format.initial_term_id,
                mtu: NonZeroU32::new(format.mtu)
                    .ok_or_else(|| HostRefusal("an mtu of 0".to_owned()))?,
                source: SourceIncarnation {
                    driver: identity.driver,
                    registration: identity.registration,
                    incarnation: identity.incarnation,
                },
            },
        })
    }

    fn open_replay(
        &mut self,
        request: &control::Replay<'_>,
        recording: &Recording,
        replay_id: u64,
        from: u64,
        to: u64,
    ) -> Result<Box<dyn ReplaySink + Send>, HostRefusal> {
        let (handle, feed) = self
            .driver
            .replay_target(ReplayTargetConfig {
                stream_id: request.target_stream_id,
                // Where the requester finds it.
                session_id: replay_session_id(replay_id),
                term_length: recording.geometry.term_length(),
                initial_term_id: recording.format.initial_term_id,
                mtu: recording.format.mtu.get(),
                join: from,
                lane: recording.format.lane,
                source_stream_id: recording.stream_id,
                source_session_id: recording.session_id,
            })
            .map_err(|error| HostRefusal(error.to_string()))?;
        self.opened
            .push((request.target_stream_id, replay_session_id(replay_id)));
        let reader = match self.driver.subscribe_aggregate(&handle, Role::Required) {
            Ok(reader) => reader,
            Err(error) => {
                // Nothing was written, so ending the replay at `to` retires
                // the target (ImageRetired) rather than leave it open.
                let _ = self.driver.finish_replay(handle, feed, to);
                return Err(HostRefusal(error.to_string()));
            }
        };
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
    /// A rig whose recorded stream starts at `initial_term_id`.
    fn new(initial_term_id: u32) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "karyos-sim-archive-control-{}-{initial_term_id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        // The driver draws each stream's initial term id; the override
        // starts the recorded stream at `initial_term_id` (the wrap test).
        let mut driver = EmbeddedDriver::with_config(karyos_driver::DriverConfig {
            initial_term_id: Some(initial_term_id),
            ..karyos_driver::DriverConfig::default()
        })
        .unwrap();
        let data = driver.add_stream(stream(DATA, initial_term_id)).unwrap();
        let requests = driver
            .add_stream(stream(REQUESTS, INITIAL_TERM_ID))
            .unwrap();
        let responses = driver
            .add_stream(stream(RESPONSES, INITIAL_TERM_ID))
            .unwrap();
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
            opened: Vec::new(),
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

    /// The next `count` messages for the request `correlation_id`, as
    /// bytes: as archive-control-codec.md §7a has a requester read the
    /// shared response stream, it keeps its own answers and the signals for
    /// every reader (correlation id 0), and skips the rest.
    fn answers(&mut self, correlation_id: u64, count: usize) -> Vec<Vec<u8>> {
        let start = Instant::now();
        let mut answers = Vec::new();
        while answers.len() < count {
            assert!(start.elapsed() < Duration::from_secs(10), "no answer");
            self.cycle();
            let _ = self.client.responses.poll(
                |bytes, _| {
                    if [correlation_id, 0].contains(&correlation(bytes)) {
                        answers.push(bytes.to_vec());
                    }
                },
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

/// A response's correlation id.
fn correlation(bytes: &[u8]) -> u64 {
    match ControlMessage::decode(bytes).unwrap() {
        ControlMessage::ControlResponse(ControlResponse { correlation_id, .. })
        | ControlMessage::RecordingDescriptor(control::RecordingDescriptor {
            correlation_id,
            ..
        })
        | ControlMessage::RecordingSignal(RecordingSignal { correlation_id, .. }) => correlation_id,
        other => panic!("not a response: {other:?}"),
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
    made_and_replayed(INITIAL_TERM_ID);
}

/// A recording whose terms cross the term id wrap replays as one that
/// does not: the target takes its first term id from the recording, so
/// every frame lands at its recorded position.
#[test]
fn a_recording_across_the_term_id_wrap_is_replayed_by_request() {
    made_and_replayed(WRAPPING_TERM_ID);
}

/// Records about three terms of a stream starting at `initial_term_id`
/// and replays them by request, whole and by range.
fn made_and_replayed(initial_term_id: u32) {
    let mut rig = Rig::new(initial_term_id);
    // Reads the data stream as the recording does, for the expected
    // messages and positions.
    let data = rig.server.host().data;
    let mut witness = rig.driver().subscribe(data, Role::Required).unwrap();
    let mut publication = rig.driver().publication(data).unwrap();

    rig.request(&ControlMessage::StartRecording(control::StartRecording {
        correlation_id: CLIENT + 1,
        stream_id: DATA,
        session_id: 1,
        mode: Mode::Required,
        sync_policy: SyncPolicy::PerSegment,
        segment_length: 0,
        channel: "karyos:ipc",
    }));
    let answers = rig.answers(CLIENT + 1, 2);
    let started = response(&answers[0]);
    assert_eq!(
        (started.correlation_id, started.code),
        (CLIENT + 1, ResponseCode::Ok)
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
        correlation_id: CLIENT + 2,
        recording_id,
    }));
    let answers = rig.answers(CLIENT + 2, 2);
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
    let recorded = rig.server.agent().describe(recording_id).unwrap().recording;
    assert_eq!(
        recorded.format.initial_term_id,
        initial_term_id.cast_signed()
    );
    let identity = rig.driver().trace_identity(data).unwrap();
    assert_eq!(
        recorded.format.source,
        SourceIncarnation {
            driver: identity.driver,
            registration: identity.registration,
            incarnation: identity.incarnation,
        }
    );
    // Positions are where messages start: one starting at the end is not
    // recorded.
    expected.retain(|(position, _)| *position < end);

    // The first replay's id is 1, the recorded stream's session: a target
    // on the recorded stream's id would collide with it, and is refused.
    rig.request(&ControlMessage::Replay(control::Replay {
        target_stream_id: DATA,
        ..match replay(CLIENT + 6, recording_id, 0, u64::MAX) {
            ControlMessage::Replay(request) => request,
            _ => unreachable!(),
        }
    }));
    let answers = rig.answers(CLIENT + 6, 1);
    let refused = response(&answers[0]);
    assert_eq!(refused.code, ResponseCode::Error, "{}", refused.message);
    assert!(rig.server.host().opened.is_empty());

    // The whole recording.
    rig.request(&replay(CLIENT + 3, recording_id, 0, u64::MAX));
    let answers = rig.answers(CLIENT + 3, 1);
    let started = response(&answers[0]);
    assert_eq!(started.code, ResponseCode::Ok);
    // The target is at the requested stream, its session the replay id's
    // low 32 bits.
    assert_eq!(
        rig.server.host().opened.last(),
        Some(&(TARGET, i32::try_from(started.id).unwrap()))
    );
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
    rig.request(&replay(CLIENT + 4, recording_id, term, term));
    let answers = rig.answers(CLIENT + 4, 1);
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
            .all(|(position, _)| (term..2 * term).contains(position))
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
    rig.request(&replay(CLIENT + 5, recording_id, 0, end + term));
    let answers = rig.answers(CLIENT + 5, 1);
    assert_eq!(response(&answers[0]).code, ResponseCode::InvalidRequest);
    drop(witness);
    drop(publication);
}
