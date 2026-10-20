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
//! - The `replay` rejoin through the Archive (A6d): a lapped optional
//!   reader in a `ReplayRejoin`, with the Archive's client as its
//!   provider, recovers its gap from the recording over the control
//!   streams and merges back into the live stream at its resume, every
//!   message once, in order, byte-exact. A gap in the recording is
//!   reported as the replay's local gap, and what follows it merges. With
//!   no recording of the stream, the secondary policy applies, with
//!   `NoRecording`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use karyos_archive::agent::{AgentConfig, ArchiveHandle, ReplaySink, SinkClosed};
use karyos_archive::catalog::{Recording, SourceIncarnation, StopReason, StreamFormat};
use karyos_archive::client::list::{ListPoll, ListerConfig, RecordingLister};
use karyos_archive::client::{
    ArchiveClient, ClientConfig, ControlRequests, ControlResponses, ReplayTargets,
};
use karyos_archive::control::{
    self, ControlMessage, ControlResponse, RecordingSignal, ReplayRate, ResponseCode, Signal,
};
use karyos_archive::disk::StdDisk;
use karyos_archive::recorder::{Mode, OnLap};
use karyos_archive::segment::SyncPolicy;
use karyos_archive::server::{
    ArchiveHost, ControlServer, HostRecording, HostRefusal, MAX_REQUEST, RequestSource,
    ResponseSink, replay_session_id,
};
use karyos_archive::source::Guarded;
use karyos_client::aggregate::LaneEnd;
use karyos_client::{
    ClientConcurrentPublication, ClientPublication, ClientSubscription, ConcurrentOfferOutcome,
    MessageLimit, OfferOutcome, PollSummary, RejoinOutcome, RejoinPolicy, ReplayFallbackReason,
    ReplayRejoin, Secondary, SecondaryOutcome,
};
use karyos_driver::DriverError;
use karyos_driver::embedded::{AggregateHandle, EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_driver::recording::RecordingReader;
use karyos_driver::replay::{ReplayFeed, ReplayTargetConfig};
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    LogBufferConfig, LossPolicy, PublicationMode, Role, SealReason, SkipReason,
};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::HeapTerms;

const DATA: i32 = 42;
const REQUESTS: i32 = 100;
const RESPONSES: i32 = 101;
const TARGET: i32 = 200;
/// The stream the Archive's client asks its replays onto (A6d).
const REPLAYS: i32 = 201;
/// The stream replays are written to for a facade client, which subscribes
/// to each target itself (`Client::replay_targets`): the host only opens
/// it, and its replay waits for that reader.
const FACADE_REPLAYS: i32 = 202;
/// The Archive's client's id, the high half of its correlation ids.
const ARCHIVE_CLIENT: u32 = 0xA6;
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
    /// The targets of replays onto [`REPLAYS`], for the Archive's client.
    replays: Replays,
    /// A recording reader made before its recording starts, which the next
    /// recording takes instead of a new one: it can be lapped before the
    /// agent reads it.
    prepared: Option<RecordingReader>,
    ended: (Sender<Ended>, Receiver<Ended>),
}

/// The targets of replays onto [`REPLAYS`], by stream and session: the
/// host puts each lane 0 reader in as it opens the target, and the
/// Archive's client takes it.
#[derive(Clone, Default)]
struct Replays(Arc<Mutex<HashMap<(i32, i32), ClientSubscription>>>);

impl ReplayTargets for Replays {
    fn subscribe(&mut self, stream_id: i32, session_id: i32) -> Option<ClientSubscription> {
        self.0.lock().unwrap().remove(&(stream_id, session_id))
    }
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
        // initial term id. An async recording reads as an optional
        // participant.
        let recording = match self.prepared.take() {
            Some(recording) => recording,
            None => {
                let role = match request.mode {
                    Mode::Required => Role::Required,
                    Mode::Async { .. } => Role::Optional,
                };
                self.driver
                    .recording_reader(self.data, role)
                    .map_err(|error| HostRefusal(error.to_string()))?
            }
        };
        let format = recording.format();
        let (reader, lease) = recording.into_parts();
        Ok(HostRecording::new(
            Box::new(Guarded::new(reader, lease)),
            format.term_length,
            StreamFormat {
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
        ))
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
        let subscribed = if request.target_stream_id == FACADE_REPLAYS {
            Ok(())
        } else if request.target_stream_id == REPLAYS {
            // The Archive's client's: lane 0's reader, which it finds by
            // the target's stream and session.
            let key = (request.target_stream_id, replay_session_id(replay_id));
            handle
                .lane(recording.format.lane)
                .ok_or(DriverError::InvalidConfig)
                .and_then(|lane| self.driver.subscribe(lane, Role::Required))
                .map(|reader| {
                    self.replays.0.lock().unwrap().insert(key, reader);
                })
        } else {
            self.driver
                .subscribe_aggregate(&handle, Role::Required)
                .map(|reader| self.targets.push(reader))
        };
        if let Err(error) = subscribed {
            // Nothing was written, so ending the replay at `to` retires
            // the target (ImageRetired) rather than leave it open.
            let _ = self.driver.finish_replay(handle, feed, to);
            return Err(HostRefusal(error.to_string()));
        }
        Ok(Box::new(Sink {
            feed: Some(feed),
            handle,
            to,
            ended: self.ended.0.clone(),
            gated: request.target_stream_id == FACADE_REPLAYS,
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
    /// Whether the replay waits for its target's first reader (H2b), as a
    /// target its requester subscribes itself needs.
    gated: bool,
}

impl Sink {
    fn feed(&mut self) -> Result<&mut ReplayFeed<HeapTerms>, SinkClosed> {
        self.feed.as_mut().ok_or(SinkClosed)
    }
}

impl ReplaySink for Sink {
    fn ready(&mut self) -> bool {
        !self.gated || self.feed.as_ref().is_some_and(ReplayFeed::has_subscriber)
    }

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

/// A control stream's reading end: the request stream as the server
/// reads it, the response stream as the Archive's client does.
struct Reading(ClientSubscription);

impl Reading {
    fn read(&mut self, out: &mut [u8]) -> Option<usize> {
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

impl RequestSource for Reading {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        self.read(out)
    }
}

impl ControlResponses for Reading {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        self.read(out)
    }
}

/// A control stream's writing end: the response stream as the server
/// writes it, the request stream as the Archive's client does.
struct Writing(ClientPublication);

impl Writing {
    fn write(&mut self, message: &[u8]) -> bool {
        matches!(self.0.offer(message), Ok(OfferOutcome::Accepted { .. }))
    }
}

impl ResponseSink for Writing {
    fn send(&mut self, message: &[u8]) -> bool {
        self.write(message)
    }
}

/// A requester's handle on the shared request stream, concurrent as
/// archive-control-codec.md §7a has the host configure it.
struct Asking(ClientConcurrentPublication);

impl ControlRequests for Asking {
    fn send(&mut self, message: &[u8]) -> bool {
        matches!(
            self.0.offer(message),
            Ok(ConcurrentOfferOutcome::Accepted { .. })
        )
    }
}

/// The client: requests out, answers in.
struct Client {
    requests: ClientConcurrentPublication,
    responses: ClientSubscription,
}

struct Rig {
    server: ControlServer<Host, Reading, Writing>,
    /// The rig's own requests, until the Archive's client takes its
    /// streams.
    client: Option<Client>,
    dir: PathBuf,
}

impl Rig {
    /// A rig whose recorded stream starts at `initial_term_id`.
    fn new(initial_term_id: u32) -> Self {
        // A directory of its own: the tests run in parallel.
        static RIGS: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "karyos-sim-archive-control-{}-{}",
            std::process::id(),
            RIGS.fetch_add(1, Ordering::Relaxed)
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
        // Shared by every requester (§7a): the rig's own, and a facade
        // client's `ArchiveConnection`.
        let mut shared = stream(REQUESTS, INITIAL_TERM_ID);
        shared.buffer.publication = PublicationMode::Concurrent {
            publishers: 4,
            allow_non_lse: true,
        };
        let requests = driver.add_stream(shared).unwrap();
        let responses = driver
            .add_stream(stream(RESPONSES, INITIAL_TERM_ID))
            .unwrap();
        let client = Client {
            requests: driver.concurrent_publication(requests).unwrap(),
            responses: driver.subscribe(responses, Role::Required).unwrap(),
        };
        let server_requests = Reading(driver.subscribe(requests, Role::Required).unwrap());
        let server_responses = Writing(driver.publication(responses).unwrap());
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let host = Host {
            driver,
            data,
            opened: Vec::new(),
            targets: Vec::new(),
            replays: Replays::default(),
            prepared: None,
            ended: channel(),
        };
        Self {
            server: ControlServer::new(agent, host, server_requests, server_responses),
            client: Some(client),
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
            let requests = &mut self.client.as_mut().unwrap().requests;
            if let Ok(ConcurrentOfferOutcome::Accepted { .. }) = requests.offer(&out[..length]) {
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
            let _ = self.client.as_mut().unwrap().responses.poll(
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

    /// Starts recording the data stream in `mode`; returns its id.
    fn start_recording(&mut self, mode: Mode) -> u64 {
        self.request(&ControlMessage::StartRecording(control::StartRecording {
            correlation_id: CLIENT + 1,
            stream_id: DATA,
            session_id: 1,
            mode,
            sync_policy: SyncPolicy::PerSegment,
            segment_length: 0,
            channel: "karyos:ipc",
        }));
        let answers = self.answers(CLIENT + 1, 2);
        let started = response(&answers[0]);
        assert_eq!(started.code, ResponseCode::Ok, "{}", started.message);
        assert_eq!(signal(&answers[1]).signal, Signal::Started);
        started.id
    }

    /// The Archive's client, on the rig's request and response streams,
    /// asking its replays onto [`REPLAYS`]: the rig sends no more requests
    /// of its own.
    fn archive_client(&mut self) -> ArchiveClient<Asking, Reading, Replays> {
        let Client {
            requests,
            responses,
        } = self.client.take().unwrap();
        let mut config = ClientConfig::new(ARCHIVE_CLIENT, REPLAYS);
        config.deadline = Duration::from_secs(10);
        let replays = self.server.host().replays.clone();
        ArchiveClient::new(config, Asking(requests), Reading(responses), replays).unwrap()
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

/// A message published: where it starts, and its bytes.
type Sent = (u64, Vec<u8>);

/// Publishes messages of several sizes, some fragmented, cycling the rig,
/// until the stream reaches `to`, or `count` messages when `to` is 0.
/// Each message carries its sequence in its first four bytes.
fn publish(
    rig: &mut Rig,
    publication: &mut ClientPublication,
    sent: &mut Vec<Sent>,
    to: u64,
    count: usize,
) {
    let goal = sent.len() + count;
    let start = Instant::now();
    while if to == 0 {
        sent.len() < goal
    } else {
        sent.last().is_none_or(|(position, _)| *position < to)
    } {
        assert!(start.elapsed() < Duration::from_secs(20), "not published");
        let sequence = u32::try_from(sent.len()).unwrap();
        let length = [100usize, 1400, 3000][sent.len() % 3];
        let mut message = vec![u8::try_from(sequence % 251).unwrap(); length];
        message[..4].copy_from_slice(&sequence.to_le_bytes());
        if let Ok(OfferOutcome::Accepted { position, .. }) = publication.offer(&message) {
            sent.push((position, message));
        }
        rig.cycle();
    }
}

/// Polls `rejoin`, cycling the rig, until `done` holds of a poll's report
/// and the count of messages delivered so far; returns every report that
/// was not empty.
fn rejoin_until(
    rig: &mut Rig,
    rejoin: &mut ReplayRejoin,
    seen: &mut Vec<Sent>,
    mut done: impl FnMut(&PollSummary, usize) -> bool,
) -> Vec<PollSummary> {
    let mut reports = Vec::new();
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "not done: {reports:?}"
        );
        rig.cycle();
        let summary = rejoin
            .poll(
                |bytes, info| seen.push((info.position, bytes.to_vec())),
                MessageLimit::new(64),
            )
            .unwrap();
        let finished = done(&summary, seen.len());
        if summary != PollSummary::default() {
            reports.push(summary);
        }
        if finished {
            return reports;
        }
    }
}

/// Publishes `count` messages one at a time, polling `rejoin` until each
/// is delivered and every overrun it reported resolved; returns the
/// reports that were not empty.
fn publish_polled(
    rig: &mut Rig,
    publication: &mut ClientPublication,
    rejoin: &mut ReplayRejoin,
    sent: &mut Vec<Sent>,
    seen: &mut Vec<Sent>,
    count: usize,
) -> Vec<PollSummary> {
    let mut reports = Vec::new();
    for _ in 0..count {
        publish(rig, publication, sent, 0, 1);
        let next = seen.len() + 1;
        let mut recovering = false;
        reports.extend(rejoin_until(rig, rejoin, seen, |report, count| {
            if let Some(outcome) = report.rejoin {
                recovering = outcome == RejoinOutcome::Replaying;
            }
            count >= next && !recovering
        }));
    }
    reports
}

/// The outcomes `reports` carry, in order.
fn outcomes(reports: &[PollSummary]) -> Vec<RejoinOutcome> {
    reports.iter().filter_map(|report| report.rejoin).collect()
}

/// A lapped optional reader recovers its gap through the Archive: its
/// rejoin asks the Archive's client for the gap, which lists the
/// recording, asks for its replay over the request stream and finds the
/// target; the replay merges back into the live stream at the resume.
/// Every message comes once, in order, byte-exact, at its position, also
/// across the overruns that follow, each recovered the same way.
#[test]
fn a_lapped_reader_recovers_its_gap_through_the_archive() {
    let mut rig = Rig::new(INITIAL_TERM_ID);
    let data = rig.server.host().data;
    let mut publication = rig.driver().publication(data).unwrap();
    let live = rig.driver().subscribe(data, Role::Optional).unwrap();
    let source = rig.driver().trace_identity(data).unwrap();
    let _ = rig.start_recording(Mode::Required);
    let archive = rig.archive_client();
    let mut rejoin = ReplayRejoin::new(live, source, Box::new(archive), Secondary::RejoinAtHead);

    // Five terms: the live reader, not polled, is lapped; the recording,
    // required, keeps every message.
    let mut sent = Vec::new();
    publish(
        &mut rig,
        &mut publication,
        &mut sent,
        5 * u64::from(MIN_TERM_LENGTH),
        0,
    );
    let mut seen = Vec::new();
    let reports = rejoin_until(&mut rig, &mut rejoin, &mut seen, |report, _| {
        matches!(report.rejoin, Some(RejoinOutcome::Replayed { .. }))
    });
    let overrun = reports.iter().find_map(|report| report.overrun).unwrap();
    assert_eq!(overrun.from, 0);
    assert_eq!(
        outcomes(&reports),
        [
            RejoinOutcome::Replaying,
            RejoinOutcome::Replayed {
                cutover: overrun.resume
            }
        ]
    );
    assert!(reports.iter().all(|report| report.skipped.is_none()));
    assert!(!rejoin.is_recovering());

    // The live reader goes on. Behind the required recording it is
    // overrun as soon as the recording reads past it (the retention
    // floor follows the recording), and each overrun is recovered the
    // same way.
    let reports = publish_polled(
        &mut rig,
        &mut publication,
        &mut rejoin,
        &mut sent,
        &mut seen,
        20,
    );
    let later = outcomes(&reports);
    assert!(
        later.chunks(2).all(|pair| matches!(
            pair,
            [RejoinOutcome::Replaying, RejoinOutcome::Replayed { .. }]
        )),
        "{later:?}"
    );
    assert_eq!(seen.len(), sent.len());
    assert!(seen == sent, "once, in order, byte-exact, at its position");
    drop(publication);
}

/// F9-0 (ffi-archive.md): the same recovery through the facade. A
/// `Client`'s subscription of the stream, taken over the command ring,
/// becomes a rejoin with `Subscription::rejoin_with` and the Archive's
/// client as its provider; lapped, it reports the replay and its merge,
/// and every message comes once, in order, byte-exact.
#[test]
fn a_facade_subscription_recovers_its_gap_through_the_archive() {
    use karyos_client::{Client, Context, StreamId, SubscriberRole, SubscriptionOptions};

    let mut rig = Rig::new(INITIAL_TERM_ID);
    let data = rig.server.host().data;
    let mut publication = rig.driver().publication(data).unwrap();
    let conductor = rig.driver().connect().unwrap();
    let mut client = Client::with_conductor(
        conductor,
        Context::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
    );
    // The add waits for the driver, which this thread runs meanwhile.
    let subscription = std::thread::scope(|scope| {
        let adding = scope.spawn(|| {
            client.add_subscription_with(
                "karyos:ipc",
                StreamId::new(DATA),
                SubscriptionOptions::new(SubscriberRole::Optional, RejoinPolicy::RejoinAtHead),
            )
        });
        while !adding.is_finished() {
            rig.cycle();
        }
        adding.join().unwrap().unwrap()
    });
    let _ = rig.start_recording(Mode::Required);
    let archive = rig.archive_client();
    let mut rejoin = subscription
        .rejoin_with(Box::new(archive), Secondary::RejoinAtHead)
        .unwrap();

    let mut sent = Vec::new();
    publish(
        &mut rig,
        &mut publication,
        &mut sent,
        5 * u64::from(MIN_TERM_LENGTH),
        0,
    );
    let mut seen: Vec<Sent> = Vec::new();
    let mut outcomes = Vec::new();
    let start = Instant::now();
    while !matches!(outcomes.last(), Some(RejoinOutcome::Replayed { .. })) {
        assert!(start.elapsed() < Duration::from_secs(20), "{outcomes:?}");
        rig.cycle();
        let poll = rejoin
            .poll(
                |bytes, info| seen.push((info.position, bytes.to_vec())),
                MessageLimit::new(64),
            )
            .unwrap();
        if let Some(outcome) = poll.stopped.and_then(|stop| stop.summary.rejoin) {
            outcomes.push(outcome);
        }
    }
    assert_eq!(outcomes[0], RejoinOutcome::Replaying);
    assert!(!rejoin.is_recovering());
    assert_eq!(rejoin.merge_failure(), None);
    // Drained to the end: every message once, in order, byte-exact.
    let start = Instant::now();
    while seen.len() < sent.len() {
        assert!(start.elapsed() < Duration::from_secs(20), "{}", seen.len());
        rig.cycle();
        let _ = rejoin
            .poll(
                |bytes, info| seen.push((info.position, bytes.to_vec())),
                MessageLimit::new(64),
            )
            .unwrap();
    }
    assert!(seen == sent, "once, in order, byte-exact, at its position");
    let back = rejoin.into_subscription().unwrap();
    drop(back);
    drop(publication);
}

/// F9b (ffi-archive.md): a replay target subscribed through a facade
/// client without blocking. A target not there yet is refused and asked
/// again; once it exists the grant comes through the client's polls. A
/// grant withdrawn before it was taken is released by the client: the
/// target's single reader slot is free again; so is one left to a
/// subscriber when it is dropped.
#[test]
fn a_replay_target_is_subscribed_through_the_facade_client_without_blocking() {
    use karyos_client::{Client, Context, ReplayTargetSubscriber};

    const SOLO: i32 = 300;
    let mut rig = Rig::new(INITIAL_TERM_ID);
    let conductor = rig.driver().connect().unwrap();
    let mut client = Client::with_conductor(
        conductor,
        Context::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
    );
    let mut targets = client.replay_targets();
    let serve = |rig: &mut Rig, client: &mut Client<_>| {
        rig.cycle();
        let _ = client.poll();
    };
    // Not there yet: refused, and asked again on each call.
    for _ in 0..20 {
        assert!(targets.subscribe(SOLO, 1).is_none());
        serve(&mut rig, &mut client);
    }
    // One reader at most.
    let mut solo = stream(SOLO, INITIAL_TERM_ID);
    solo.buffer.max_subscribers = 1;
    let _ = rig.driver().add_stream(solo).unwrap();
    let granted =
        |rig: &mut Rig, client: &mut Client<_>, targets: &mut ReplayTargetSubscriber<_>| {
            let start = Instant::now();
            loop {
                assert!(start.elapsed() < Duration::from_secs(10), "never granted");
                if let Some(subscription) = targets.subscribe(SOLO, 1) {
                    return subscription;
                }
                serve(rig, client);
            }
        };
    let first = granted(&mut rig, &mut client, &mut targets);
    assert_eq!(first.lane(), Some(Lane::ZERO));
    drop(first);
    // Asked for, granted, never taken, then withdrawn by asking for another
    // target: the client releases the grant.
    assert!(targets.subscribe(SOLO, 1).is_none());
    for _ in 0..50 {
        serve(&mut rig, &mut client);
    }
    assert!(targets.subscribe(SOLO + 1, 1).is_none());
    for _ in 0..50 {
        serve(&mut rig, &mut client);
    }
    // The slot is free: the target is granted again.
    let again = granted(&mut rig, &mut client, &mut targets);
    drop(again);
    // A subscriber dropped with a grant never taken: the client releases
    // it, and the slot is free once more.
    let mut other = client.replay_targets();
    assert!(other.subscribe(SOLO, 1).is_none());
    for _ in 0..50 {
        serve(&mut rig, &mut client);
    }
    drop(other);
    for _ in 0..50 {
        serve(&mut rig, &mut client);
    }
    drop(granted(&mut rig, &mut client, &mut targets));
    // Every withdrawn grant went through the client's release, none failed.
    assert_eq!(client.subscription_releases_failed(), 0);
}

/// F9b: a facade subscription whose Archive client is built only from the
/// facade client (`ArchiveConnection` and `Client::replay_targets`)
/// recovers its gap, polled as the C ABI polls: adopt, read the largest
/// message, then `poll_adopted`. No message is longer than what the
/// adoption said, and every message comes once, in order, byte-exact.
#[test]
fn a_facade_rejoin_recovers_through_its_own_archive_client_polled_adopted() {
    use karyos_archive::client::connection::{ArchiveConnection, ControlStreams};
    use karyos_client::{Client, Context, StreamId, SubscriberRole, SubscriptionOptions};

    let mut rig = Rig::new(INITIAL_TERM_ID);
    let data = rig.server.host().data;
    let mut publication = rig.driver().publication(data).unwrap();
    let conductor = rig.driver().connect().unwrap();
    let mut client = Client::with_conductor(
        conductor,
        Context::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
    );
    // The adds wait for the driver, which this thread runs meanwhile.
    let (subscription, connection) = std::thread::scope(|scope| {
        let adding = scope.spawn(|| {
            let subscription = client
                .add_subscription_with(
                    "karyos:ipc",
                    StreamId::new(DATA),
                    SubscriptionOptions::new(SubscriberRole::Optional, RejoinPolicy::RejoinAtHead),
                )
                .unwrap();
            let connection =
                ArchiveConnection::open(&mut client, ControlStreams::new(REQUESTS, RESPONSES))
                    .unwrap();
            (subscription, connection)
        });
        while !adding.is_finished() {
            rig.cycle();
        }
        adding.join().unwrap()
    });
    let _ = rig.start_recording(Mode::Required);
    let (requests, responses) = connection.into_transports();
    let mut config = ClientConfig::new(ARCHIVE_CLIENT + 1, FACADE_REPLAYS);
    config.deadline = Duration::from_secs(10);
    let archive = ArchiveClient::new(config, requests, responses, client.replay_targets()).unwrap();
    let mut rejoin = subscription
        .rejoin_with(Box::new(archive), Secondary::RejoinAtHead)
        .unwrap();

    let mut sent = Vec::new();
    publish(
        &mut rig,
        &mut publication,
        &mut sent,
        5 * u64::from(MIN_TERM_LENGTH),
        0,
    );
    let mut seen: Vec<Sent> = Vec::new();
    let mut outcomes = Vec::new();
    let round = |rig: &mut Rig,
                 client: &mut Client<_>,
                 rejoin: &mut karyos_client::RejoiningSubscription<_>,
                 seen: &mut Vec<Sent>| {
        rig.cycle();
        let _ = client.poll();
        rejoin.adopt();
        let largest = rejoin.max_message_length() as usize;
        let poll = rejoin
            .poll_adopted(
                |bytes, info| {
                    assert!(bytes.len() <= largest, "{} > {largest}", bytes.len());
                    seen.push((info.position, bytes.to_vec()));
                },
                MessageLimit::new(64),
            )
            .unwrap();
        poll.stopped.and_then(|stop| stop.summary.rejoin)
    };
    let start = Instant::now();
    while !matches!(outcomes.last(), Some(RejoinOutcome::Replayed { .. })) {
        assert!(start.elapsed() < Duration::from_secs(20), "{outcomes:?}");
        if let Some(outcome) = round(&mut rig, &mut client, &mut rejoin, &mut seen) {
            outcomes.push(outcome);
        }
    }
    assert_eq!(outcomes[0], RejoinOutcome::Replaying);
    assert_eq!(rejoin.merge_failure(), None);
    let start = Instant::now();
    while seen.len() < sent.len() {
        assert!(start.elapsed() < Duration::from_secs(20), "{}", seen.len());
        let _ = round(&mut rig, &mut client, &mut rejoin, &mut seen);
    }
    assert!(seen == sent, "once, in order, byte-exact, at its position");
    drop(rejoin);
    drop(publication);
}

/// A gap in the recording: its reader was lapped before the agent read
/// it, so the recording holds a gap from the stream's start. A lapped
/// reader's replay reports the gap as its local gap and merges what
/// follows it; every message past the gap comes once, in order.
#[test]
fn a_gap_in_the_recording_is_reported_and_what_follows_merges() {
    let mut rig = Rig::new(INITIAL_TERM_ID);
    let data = rig.server.host().data;
    let mut publication = rig.driver().publication(data).unwrap();
    let live = rig.driver().subscribe(data, Role::Optional).unwrap();
    let source = rig.driver().trace_identity(data).unwrap();
    let prepared = rig.driver().recording_reader(data, Role::Optional).unwrap();
    rig.server.host_mut().prepared = Some(prepared);

    // Five terms with no required reader: the recording's reader and the
    // live reader are both lapped.
    let mut sent = Vec::new();
    let term = u64::from(MIN_TERM_LENGTH);
    publish(&mut rig, &mut publication, &mut sent, 5 * term, 0);
    let lost = sent.len();
    let recording = rig.start_recording(Mode::Async {
        on_lap: OnLap::Resume,
    });
    // The recording rejoins at the head, where the next message starts.
    let start = Instant::now();
    while !rig.server.agent().describe(recording).unwrap().incomplete {
        assert!(start.elapsed() < Duration::from_secs(20), "never lapped");
        rig.cycle();
    }
    // Less than a term, which the recording keeps.
    publish(&mut rig, &mut publication, &mut sent, 0, 20);
    let archive = rig.archive_client();
    let mut rejoin = ReplayRejoin::new(live, source, Box::new(archive), Secondary::RejoinAtHead);

    let mut seen = Vec::new();
    let reports = rejoin_until(&mut rig, &mut rejoin, &mut seen, |report, _| {
        matches!(report.rejoin, Some(RejoinOutcome::Replayed { .. }))
    });
    let overrun = reports.iter().find_map(|report| report.overrun).unwrap();
    assert_eq!(overrun.from, 0);
    assert_eq!(
        outcomes(&reports),
        [
            RejoinOutcome::Replaying,
            RejoinOutcome::Replayed {
                cutover: overrun.resume
            }
        ]
    );
    // The recording's gap, reported from the stream's start, in reports
    // that follow one another, up to where the recording rejoined; the
    // replay merges the messages that follow it.
    let mut gap = 0;
    for skipped in reports.iter().filter_map(|report| report.skipped) {
        assert!(
            matches!(skipped.reason, SkipReason::LocalGap(_)),
            "{skipped:?}"
        );
        assert_eq!(skipped.position, gap);
        gap += u64::from(skipped.extent);
    }
    assert_eq!(gap, sent[lost].0);
    assert!(seen == sent[lost..], "the replay's, past the gap");

    // The live reader goes on alone.
    let reports = publish_polled(
        &mut rig,
        &mut publication,
        &mut rejoin,
        &mut sent,
        &mut seen,
        20,
    );
    assert!(outcomes(&reports).is_empty(), "{reports:?}");
    assert!(
        seen == sent[lost..],
        "past the gap: once, in order, byte-exact"
    );
    drop(publication);
}

/// No recording of the stream: the Archive's client finds none, and the
/// secondary policy applies to the gap with `NoRecording`; the live reader
/// goes on from its resume.
#[test]
fn a_stream_with_no_recording_falls_back_to_the_secondary() {
    let mut rig = Rig::new(INITIAL_TERM_ID);
    let data = rig.server.host().data;
    let mut publication = rig.driver().publication(data).unwrap();
    let live = rig.driver().subscribe(data, Role::Optional).unwrap();
    let source = rig.driver().trace_identity(data).unwrap();
    let archive = rig.archive_client();
    let mut rejoin = ReplayRejoin::new(live, source, Box::new(archive), Secondary::RejoinAtHead);

    let mut sent = Vec::new();
    publish(
        &mut rig,
        &mut publication,
        &mut sent,
        5 * u64::from(MIN_TERM_LENGTH),
        0,
    );
    let mut seen = Vec::new();
    let reports = rejoin_until(&mut rig, &mut rejoin, &mut seen, |report, _| {
        matches!(report.rejoin, Some(RejoinOutcome::ReplayFallback { .. }))
    });
    assert_eq!(
        outcomes(&reports),
        [
            RejoinOutcome::Replaying,
            RejoinOutcome::ReplayFallback {
                reason: ReplayFallbackReason::NoRecording,
                secondary: SecondaryOutcome::ResumedAtHead,
            }
        ]
    );
    assert!(seen.is_empty());
    assert!(
        rig.server.host().opened.is_empty(),
        "no replay was asked for"
    );

    let before = sent.len();
    let reports = publish_polled(
        &mut rig,
        &mut publication,
        &mut rejoin,
        &mut sent,
        &mut seen,
        20,
    );
    assert!(outcomes(&reports).is_empty(), "{reports:?}");
    assert!(seen == sent[before..], "from the resume on");
    drop(publication);
}

/// M11: the agent's lister reads the catalog through the real control
/// server, page by page: a full page of one, then an empty one.
#[test]
fn the_catalog_is_listed_page_by_page_through_the_control_streams() {
    let mut rig = Rig::new(INITIAL_TERM_ID);
    let recording_id = rig.start_recording(Mode::Required);
    let Client {
        requests,
        responses,
    } = rig.client.take().unwrap();
    let mut lister = RecordingLister::new(
        ListerConfig::new(0xA7).with_bounds(1, 16),
        Asking(requests),
        Reading(responses),
    );
    lister.start();
    let start = Instant::now();
    let listing = loop {
        assert!(start.elapsed() < Duration::from_secs(10), "no listing");
        rig.cycle();
        match lister.poll() {
            ListPoll::Pending => {}
            ListPoll::Done(listing) => break listing,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(listing.left_out, 0);
    let [recording] = listing.recordings.as_slice() else {
        panic!("{listing:?}")
    };
    assert_eq!(recording.recording_id, recording_id);
    assert_eq!((recording.stream_id, recording.session_id), (DATA, 1));
    assert_eq!(recording.channel, "karyos:ipc");
}
