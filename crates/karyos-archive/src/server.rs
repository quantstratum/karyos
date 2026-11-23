// SPDX-License-Identifier: Apache-2.0

//! The Archive's control server (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A5; archive-control-codec.md
//! §7a): the requests of [`crate::control`] read from a request stream,
//! served by the agent, and answered on a response stream.
//!
//! The server runs on the host's thread and owns the [`ArchiveHandle`].
//! What touches the driver stays with the host, behind [`ArchiveHost`]: it
//! opens a recorded lane's reader and a replay's target stream. The server
//! neither knows the driver nor the transport; [`RequestSource`] and
//! [`ResponseSink`] are the two fixed streams.
//!
//! - **Requests.** One at a time, and only once every answer to the last
//!   one has been sent: a response stream without room holds the next
//!   request back. A request that does not decode is answered with its
//!   correlation id when its block holds one (bytes 12 to 20), else 0.
//! - **Never blocking.** The host's thread may be the driver's. The server
//!   posts its commands to the agent and answers when the agent's answer
//!   arrives, in a later duty; a list is one snapshot. A replay is
//!   prepared first, its range checked against the recording's index, and
//!   only then does the host open its target.
//! - **Signals.** A recording's start is signalled with its start
//!   request's correlation id; its stop or failure with 0, for every
//!   reader. A replay's end has no signal in version 1: its target stream's
//!   seal says it. Signals waiting for room are capped
//!   ([`ServerConfig::max_pending_signals`]); one more is dropped and
//!   counted.
//!
//! - **Retention (ADR-0088; karyos#967).** A hold, a release, a purge and
//!   a seal verification are posted to the agent, whose retention engine
//!   and verifier answer them like any other command
//!   ([`ArchiveHandle::post_hold`] and the rest). A host that attaches its
//!   own [`RetentionControl`] ([`ControlServer::with_retention`]) is
//!   served by it instead, on the server's thread, its refusal names
//!   verbatim.
//!
//! - **Retention state (ADR-0101).** A version 2 `RetentionState` is
//!   answered only on the stream it names, which the host opens
//!   ([`ArchiveHost::open_response`]): a descriptor per recording, then
//!   the summary with the host's free space ([`ArchiveHost::free_space`]).
//!   The shared response stream carries at most a refusal, so no version 1
//!   reader of it decodes a version 2 page. That answer is sent beside the
//!   shared stream and never holds it back; a second query while one is
//!   still being sent is refused with code 1.
//!
//! This is the control path: it allocates (the queued answers, the boxed
//! host objects); the replayed frames do not pass through it.

use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, TryRecvError};

use karyos_codec::CodecError;

use crate::agent::{
    self, AgentError, ArchiveHandle, Described, Event, Posted, PrepareReplay, Prepared,
    ReplayOutcome, ReplaySink,
};
use crate::catalog::{Recording, StreamFormat};
use crate::control::{
    self, ControlMessage, ControlResponse, MAX_CHANNEL, MAX_RESPONSE_MESSAGE, RecordingDescriptor,
    RecordingSignal, RecordingState, ReplayRate, ResponseCode, Signal,
};
use crate::durable::{self, DurabilityMessage, DurableAnswer, DurablePosition};
use crate::recorder::{Ended, FrameSource};
use crate::replay::{Rate, ReplayError};
use crate::replication::transport::Outgoing;
use crate::replication::{self, RecordingBytes, ReplicationMessage, SourceSeal};
use crate::segment::Geometry;

#[cfg(test)]
mod tests;

/// The longest request: a `Replay` with the longest channel.
pub const MAX_REQUEST: usize = 1079;

/// The longest message the server sends: a `RecordingDescriptor` with the
/// longest channel (the envelope, its block, and the channel's length and
/// bytes).
pub const MAX_ANSWER: usize = 12 + 110 + 2 + MAX_CHANNEL;

/// The message of a retention request's answer when no
/// [`RetentionControl`] is attached.
pub const NO_RETENTION: &str = "no retention engine attached";

/// What the Archive's retention engine answered to a hold, a release or a
/// purge (ADR-0088).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionAnswer {
    /// Done: a hold applied with evidence, a release, a purge.
    Done,
    /// A hold in force whose pending marker is durable, without the
    /// operations journal's record.
    HeldWithoutEvidence,
    /// A hold in force in this process only.
    HeldInMemoryOnly,
    /// No such recording.
    UnknownRecording,
    /// Refused, for the reason named: `legal_hold`, `not_expired`,
    /// `below_min_copies`, `no_evidence` and the like, verbatim.
    Refused(String),
    /// Failed, for the reason given.
    Error(String),
}

/// The Archive's retention engine and verifier, as the control server
/// reaches them (ADR-0088). Called on the server's thread.
pub trait RetentionControl: Send {
    /// Applies a legal hold on `recording`.
    fn hold(&mut self, recording: u64) -> RetentionAnswer;
    /// Releases the legal hold on `recording`.
    fn release(&mut self, recording: u64) -> RetentionAnswer;
    /// Purges `recording` below `before`, as purge `request_id` for
    /// `operator`, authorised by the control path (ADR-0088, decision 4).
    fn purge(
        &mut self,
        recording: u64,
        before: u64,
        request_id: u64,
        operator: u64,
    ) -> RetentionAnswer;
    /// Verifies `recording`'s seals: each range's outcome, its
    /// `correlation_id` set by the server; or why not.
    ///
    /// # Errors
    ///
    /// A [`RetentionAnswer`] other than `Done` for a verification that
    /// could not run.
    fn verify(&mut self, recording: u64) -> Result<Vec<control::RangeOutcome>, RetentionAnswer>;
}

/// The host's side of the Archive: the driver's streams.
pub trait ArchiveHost {
    /// Opens the lane `request` names for recording: its reader, positioned
    /// where the recording starts, and its term length.
    ///
    /// # Errors
    ///
    /// A [`HostRefusal`] the requester is told.
    fn open_recording(
        &mut self,
        request: &control::StartRecording<'_>,
    ) -> Result<HostRecording, HostRefusal>;

    /// Opens the target stream of replay `replay_id` of `recording` over
    /// `[from, to)`, a range the agent found readable: an image that keeps
    /// the recorded positions, at the request's `target_stream_id` with
    /// the replay id's low 32 bits as its session id, where the requester
    /// finds it (archive-control-codec.md section 4.1). A target whose
    /// stream and session collide with a stream the host has is refused.
    /// The sink's `finish` names where the replay ended; it reached its
    /// end only at `to`.
    ///
    /// # Errors
    ///
    /// A [`HostRefusal`] the requester is told.
    fn open_replay(
        &mut self,
        request: &control::Replay<'_>,
        recording: &Recording,
        replay_id: u64,
        from: u64,
        to: u64,
    ) -> Result<Box<dyn ReplaySink + Send>, HostRefusal>;

    /// Opens the stream a [`control::RetentionState`] names for its
    /// answer (ADR-0101): stream `stream_id` of `channel`, which the
    /// requester subscribed to before it asked. The answer goes only
    /// there, never to the shared response stream, so no version 1 reader
    /// of that stream decodes it. A host with no such stream refuses, and
    /// the requester is told with code 1 on the shared stream.
    ///
    /// # Errors
    ///
    /// A [`HostRefusal`] the requester is told.
    fn open_response(
        &mut self,
        stream_id: i32,
        channel: &str,
    ) -> Result<Box<dyn ResponseSink + Send>, HostRefusal> {
        let _ = (stream_id, channel);
        Err(HostRefusal(NO_RESPONSE_STREAM.to_owned()))
    }

    /// The archive's free-space floor (`--archive-min-free`, 0 for none)
    /// and its file system's free bytes now ([`control::FREE_UNKNOWN`]
    /// when not known), for a [`control::RetentionSummary`] (ADR-0101).
    fn free_space(&self) -> (u64, u64) {
        (0, control::FREE_UNKNOWN)
    }
}

/// The refusal of a retention state query by a host with no stream of the
/// requester's.
pub const NO_RESPONSE_STREAM: &str = "no response stream of the requester's";

/// The refusal of a retention state query while the last one's answer is
/// still being sent on its own stream.
pub const RETENTION_ANSWER_BUSY: &str = "a retention state answer is still being sent";

/// A recorded lane the host opened.
#[non_exhaustive]
pub struct HostRecording {
    /// Its reader, positioned at the recording's start.
    pub source: Box<dyn FrameSource + Send>,
    /// Its term length.
    pub term_length: u32,
    /// The recorded stream's format, kept in the catalog for its replays.
    pub format: StreamFormat,
    /// What the source reads: a local stream unless the host says it is a
    /// network image ([`HostRecording::with_origin`]; karyos#490).
    pub origin: crate::agent::RecordedFrom,
}

impl HostRecording {
    /// A recording the host hands over: its source, term length and
    /// format.
    #[must_use]
    pub fn new(
        source: Box<dyn FrameSource + Send>,
        term_length: u32,
        format: StreamFormat,
    ) -> Self {
        Self {
            source,
            term_length,
            format,
            origin: crate::agent::RecordedFrom::Local,
        }
    }

    /// The same, reading `origin`: a host that opens a network image to
    /// record passes [`RecordedFrom::Image`](crate::agent::RecordedFrom).
    #[must_use]
    pub fn with_origin(mut self, origin: crate::agent::RecordedFrom) -> Self {
        self.origin = origin;
        self
    }
}

impl core::fmt::Debug for HostRecording {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HostRecording")
            .field("position", &self.source.position())
            .field("term_length", &self.term_length)
            .finish_non_exhaustive()
    }
}

/// Why the host could not open a stream; sent to the requester, cut to
/// [`MAX_RESPONSE_MESSAGE`] bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRefusal(pub String);

/// The request stream.
pub trait RequestSource {
    /// Copies the next request into `out` and returns its length, or `None`
    /// when there is none. A request longer than `out` is the source's to
    /// drop.
    fn next(&mut self, out: &mut [u8]) -> Option<usize>;
}

/// The response stream.
pub trait ResponseSink {
    /// Sends one message; `false` when there is no room yet, and the same
    /// message is offered again later.
    fn send(&mut self, message: &[u8]) -> bool;

    /// The longest message [`ResponseSink::send`] ever accepts; a
    /// replication's chunks are cut to fit it (karyos#1113).
    fn max_message(&self) -> usize {
        usize::MAX
    }
}

/// A [`RecordingBytes`] message's length beyond its bytes.
const RECORDING_BYTES_OVERHEAD: usize =
    replication::RECORDING_BYTES.max_length as usize - replication::MAX_CHUNK;

/// Replication messages taken from the agent per duty at most, and only
/// while fewer than this many answers wait: the rest stay in the agent's
/// bounded channel, so a slow reader holds the agent back (karyos#1113).
const REPLICATION_FORWARD: usize = 8;

/// The server's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerConfig {
    /// Signals waiting for room on the response stream at most; one more is
    /// dropped and counted ([`ControlServer::dropped_signals`]). A
    /// request's own answers always wait: at most a list's descriptors and
    /// its count.
    pub max_pending_signals: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_pending_signals: 1024,
        }
    }
}

/// A request waiting for the agent's answer.
enum Waiting {
    Start {
        correlation_id: u64,
        start: u64,
        answer: Posted<u64>,
    },
    Stop {
        correlation_id: u64,
        recording_id: u64,
        answer: Posted<Ended>,
    },
    List {
        correlation_id: u64,
        answer: Posted<Vec<Described>>,
    },
    /// The request's bytes stay in the server's buffer, `length` long,
    /// for the host's `open_replay`: no request is read while one waits.
    Prepare {
        correlation_id: u64,
        length: usize,
        answer: Posted<Prepared>,
    },
    Attach {
        correlation_id: u64,
        answer: Posted<u64>,
    },
    StopReplay {
        correlation_id: u64,
        replay_id: u64,
        answer: Posted<u64>,
    },
    /// A hold, a release or a purge (ADR-0088).
    Retain {
        correlation_id: u64,
        recording_id: u64,
        answer: Posted<RetentionAnswer>,
    },
    /// A seal verification (ADR-0088).
    Verify {
        correlation_id: u64,
        recording_id: u64,
        answer: Posted<agent::Verified>,
    },
    /// A durability query (schema 4, R-CORE-12).
    Durable {
        correlation_id: u64,
        answer: Posted<Described>,
    },
    /// A replica's request (schema 6, ADR-0091).
    Replicate {
        correlation_id: u64,
        recording_id: u64,
        answer: Posted<Receiver<Outgoing>>,
    },
    /// A replica's stop.
    StopReplication { answer: Posted<()> },
    /// A retention state query (ADR-0101): answered on `sink`, the
    /// stream it named.
    RetentionState {
        correlation_id: u64,
        sink: Box<dyn ResponseSink + Send>,
        answer: Posted<Vec<control::RetentionDescriptor>>,
    },
}

/// The control server: requests in, the agent's work, answers out.
pub struct ControlServer<H, Q, R> {
    agent: ArchiveHandle,
    host: H,
    requests: Q,
    responses: R,
    config: ServerConfig,
    request: Vec<u8>,
    /// The request whose agent answer has not come.
    waiting: Option<Waiting>,
    /// Answers and signals not sent yet, in order.
    pending: VecDeque<Vec<u8>>,
    dropped_signals: u64,
    unencoded: u64,
    unattended: u64,
    /// The retention engine, once attached (ADR-0088).
    retention: Option<Box<dyn RetentionControl>>,
    /// Each replication this Archive serves: its request's correlation id
    /// and recording, and the agent's messages for it (karyos#1113).
    replications: Vec<(u64, u64, Receiver<Outgoing>)>,
    /// A retention state answer being sent on the stream its query named
    /// (ADR-0101): that stream and the messages not sent yet. It never
    /// holds the shared stream back.
    answering: Option<(Box<dyn ResponseSink + Send>, VecDeque<Vec<u8>>)>,
}

impl<H, Q, R> core::fmt::Debug for ControlServer<H, Q, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControlServer")
            .field("pending", &self.pending.len())
            .field("waiting", &self.waiting.is_some())
            .finish_non_exhaustive()
    }
}

impl<H: ArchiveHost, Q: RequestSource, R: ResponseSink> ControlServer<H, Q, R> {
    /// A server of `agent`'s archive, with `host`'s streams.
    pub fn new(agent: ArchiveHandle, host: H, requests: Q, responses: R) -> Self {
        Self {
            agent,
            host,
            requests,
            responses,
            config: ServerConfig::default(),
            request: vec![0; MAX_REQUEST],
            waiting: None,
            pending: VecDeque::new(),
            dropped_signals: 0,
            unencoded: 0,
            unattended: 0,
            retention: None,
            replications: Vec::new(),
            answering: None,
        }
    }

    /// The server with `retention` serving the retention requests
    /// (ADR-0088).
    #[must_use]
    pub fn with_retention(mut self, retention: Box<dyn RetentionControl>) -> Self {
        self.retention = Some(retention);
        self
    }

    /// The server with `config`.
    #[must_use]
    pub const fn with_config(mut self, config: ServerConfig) -> Self {
        self.config = config;
        self
    }

    /// The agent.
    pub const fn agent(&self) -> &ArchiveHandle {
        &self.agent
    }

    /// The host.
    pub const fn host(&self) -> &H {
        &self.host
    }

    /// The host, mutably.
    pub const fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Answers and signals waiting for room on the response stream.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Whether a request waits for the agent's answer.
    #[must_use]
    pub const fn is_waiting(&self) -> bool {
        self.waiting.is_some()
    }

    /// Signals dropped because [`ServerConfig::max_pending_signals`] were
    /// waiting.
    #[must_use]
    pub const fn dropped_signals(&self) -> u64 {
        self.dropped_signals
    }

    /// The agent's recording events dropped before the server read them:
    /// signals no reader got.
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.agent.dropped_events()
    }

    /// Replays that ended with no reader on their target by the agent's
    /// attach deadline ([`ReplayOutcome::NoSubscriber`]), having written
    /// nothing (`quantstratum-docs: karyos/design/archive-host.md`, H2b).
    #[must_use]
    pub const fn unattended(&self) -> u64 {
        self.unattended
    }

    /// Messages that did not encode, which a correct server never builds;
    /// they are dropped rather than sent malformed.
    #[must_use]
    pub const fn unencoded(&self) -> u64 {
        self.unencoded
    }

    /// One duty, which never blocks: the agent's answer to the request
    /// waiting, the agent's events as signals, the waiting answers sent,
    /// and, once none waits, the next request served or posted. Returns
    /// whether anything moved.
    pub fn duty(&mut self) -> bool {
        let mut worked = self.collect();
        while let Some(event) = self.agent.try_event() {
            worked = true;
            // An event follows the answers the agent sent before it: take
            // the answer first, so the request's signals come first.
            self.collect();
            self.signal(&event);
        }
        // No version 1 signal: a replay's target's seal says it ended. One
        // whose target had no reader by the attach deadline is counted:
        // its requester sees only that the target retired unjoined.
        while let Some(ended) = self.agent.try_replay_ended() {
            worked = true;
            if ended.outcome == ReplayOutcome::NoSubscriber {
                count(&mut self.unattended);
            }
        }
        worked |= self.forward_replications();
        worked |= self.flush();
        if self.waiting.is_none()
            && self.pending.is_empty()
            && let Some(length) = self.requests.next(&mut self.request)
        {
            worked = true;
            self.serve(length);
            self.flush();
        }
        worked
    }

    /// Stops the agent: what records is stopped, what replays finished.
    /// Answers not sent yet, and one the agent still owes, are dropped.
    ///
    /// # Errors
    ///
    /// The agent's shutdown errors.
    pub fn shutdown(self) -> Result<(), AgentError> {
        self.agent.shutdown()
    }

    /// Stops the agent as [`ControlServer::shutdown`] does, then hands the
    /// host back with the agent's result: a host that owns a driver keeps
    /// it, finishes the replays the stop ended, and shuts it down itself
    /// (`quantstratum-docs: karyos/design/archive-host.md`, H2).
    pub fn shutdown_into_host(self) -> (H, Result<(), AgentError>) {
        let stopped = self.agent.shutdown();
        (self.host, stopped)
    }

    fn flush(&mut self) -> bool {
        let mut sent = self.flush_answering();
        while let Some(message) = self.pending.front() {
            if !self.responses.send(message) {
                break;
            }
            sent = true;
            self.pending.pop_front();
        }
        sent
    }

    /// Sends what waits on a retention state answer's own stream; the
    /// stream is let go once all is sent.
    fn flush_answering(&mut self) -> bool {
        let Some((sink, queued)) = self.answering.as_mut() else {
            return false;
        };
        let mut sent = false;
        while let Some(message) = queued.front() {
            if !sink.send(message) {
                break;
            }
            sent = true;
            queued.pop_front();
        }
        if queued.is_empty() {
            self.answering = None;
        }
        sent
    }

    /// Encodes `message` for a retention state answer's own stream;
    /// `None` (counted) when it did not encode.
    fn encode_answer(&mut self, message: &ControlMessage<'_>) -> Option<Vec<u8>> {
        let mut out = vec![0u8; MAX_ANSWER];
        let Ok(length) = message.encode(&mut out) else {
            count(&mut self.unencoded);
            return None;
        };
        out.truncate(length);
        Some(out)
    }

    /// Queues `message`; `false` when it did not encode.
    fn queue(&mut self, message: &ControlMessage<'_>) -> bool {
        self.queue_encoded(|out| message.encode(out))
    }

    /// Queues the message `encode` writes, of any schema.
    fn queue_encoded(
        &mut self,
        encode: impl FnOnce(&mut [u8]) -> Result<usize, CodecError>,
    ) -> bool {
        let mut out = vec![0u8; MAX_ANSWER];
        // Every message the server builds is valid and fits: a failure is
        // a bug, and the message is counted and dropped rather than sent
        // malformed.
        let Ok(length) = encode(&mut out) else {
            count(&mut self.unencoded);
            return false;
        };
        out.truncate(length);
        self.pending.push_back(out);
        true
    }

    fn respond(&mut self, correlation_id: u64, id: u64, code: ResponseCode, message: &str) {
        let (id, message) = if code == ResponseCode::Ok {
            (id, "")
        } else {
            (0, cut(message))
        };
        self.queue(&ControlMessage::ControlResponse(ControlResponse {
            correlation_id,
            id,
            code,
            message,
        }));
    }

    /// A recording's end or failure, signalled for every reader; dropped
    /// and counted when too many signals wait.
    fn signal(&mut self, event: &Event) {
        let (recording_id, position, signal) = match *event {
            Event::Ended { id, ended } => (
                id,
                ended.position,
                Signal::Stopped {
                    reason: ended.reason,
                    incomplete: ended.incomplete,
                },
            ),
            Event::Failed { id, position, .. } => (id, position, Signal::Failed),
            // No control signal carries it: the control codec has none, and
            // a new one is a wire change. It is counted by
            // `ArchiveHandle::shortened_indexes` and reported by the
            // verifier as `inconsistent` (karyos#671).
            Event::IndexShortened(_) => return,
        };
        if self.pending.len() >= self.config.max_pending_signals {
            count(&mut self.dropped_signals);
            return;
        }
        self.queue(&ControlMessage::RecordingSignal(RecordingSignal {
            correlation_id: 0,
            recording_id,
            position,
            signal,
        }));
    }

    /// Serves the request of `length` bytes in the buffer: answered now, or
    /// posted to the agent.
    fn serve(&mut self, length: usize) {
        let request = std::mem::take(&mut self.request);
        if let Some(bytes) = request.get(..length) {
            self.waiting = self.serve_bytes(bytes, length);
        }
        self.request = request;
    }

    fn serve_bytes(&mut self, bytes: &[u8], length: usize) -> Option<Waiting> {
        if bytes.get(..2) == Some(&durable::SCHEMA_ID.to_le_bytes()[..]) {
            return self.serve_durable(bytes);
        }
        if bytes.get(..2) == Some(&replication::SCHEMA_ID.to_le_bytes()[..]) {
            return self.serve_replication(bytes);
        }
        let message = match ControlMessage::decode(bytes) {
            Ok(message) => message,
            Err(error) => {
                self.undecodable(bytes, &error);
                return None;
            }
        };
        match message {
            ControlMessage::StartRecording(request) => self.start_recording(&request),
            ControlMessage::StopRecording(request) => {
                let correlation_id = request.correlation_id;
                let posted = self.agent.post_stop(request.recording_id);
                self.posted(correlation_id, posted, |answer| Waiting::Stop {
                    correlation_id,
                    recording_id: request.recording_id,
                    answer,
                })
            }
            ControlMessage::ListRecordings(request) => {
                let correlation_id = request.correlation_id;
                // The codec caps `max_count` at `MAX_LIST_COUNT`.
                let max = usize::try_from(request.max_count).unwrap_or(usize::MAX);
                let posted = self.agent.post_list(request.from_id, max);
                self.posted(correlation_id, posted, |answer| Waiting::List {
                    correlation_id,
                    answer,
                })
            }
            ControlMessage::Replay(request) => self.replay(&request, length),
            ControlMessage::StopReplay(request) => {
                let correlation_id = request.correlation_id;
                let posted = self.agent.post_stop_replay(request.replay_id);
                self.posted(correlation_id, posted, |answer| Waiting::StopReplay {
                    correlation_id,
                    replay_id: request.replay_id,
                    answer,
                })
            }
            ControlMessage::HoldRecording(request) => self.retain(
                request.correlation_id,
                request.recording_id,
                |engine| engine.hold(request.recording_id),
                |agent| agent.post_hold(request.recording_id),
            ),
            ControlMessage::ReleaseHold(request) => self.retain(
                request.correlation_id,
                request.recording_id,
                |engine| engine.release(request.recording_id),
                |agent| agent.post_release(request.recording_id),
            ),
            ControlMessage::PurgeRecording(request) => self.retain(
                request.correlation_id,
                request.recording_id,
                |engine| {
                    engine.purge(
                        request.recording_id,
                        request.before,
                        request.request_id,
                        request.operator,
                    )
                },
                |agent| {
                    agent.post_purge(
                        request.recording_id,
                        request.before,
                        request.request_id,
                        request.operator,
                    )
                },
            ),
            ControlMessage::VerifyRecording(request) => {
                self.verify(request.correlation_id, request.recording_id)
            }
            ControlMessage::RetentionState(request) => self.retention_state(&request),
            ControlMessage::ControlResponse(ControlResponse { correlation_id, .. })
            | ControlMessage::RetentionDescriptor(control::RetentionDescriptor {
                correlation_id,
                ..
            })
            | ControlMessage::RetentionSummary(control::RetentionSummary {
                correlation_id, ..
            })
            | ControlMessage::RecordingDescriptor(RecordingDescriptor { correlation_id, .. })
            | ControlMessage::RangeOutcome(control::RangeOutcome { correlation_id, .. })
            | ControlMessage::RecordingSignal(RecordingSignal { correlation_id, .. }) => {
                self.respond(
                    correlation_id,
                    0,
                    ResponseCode::InvalidRequest,
                    "not a request",
                );
                None
            }
        }
    }

    /// Serves a retention state query (ADR-0101): opens the stream it
    /// names and posts the snapshot to the agent. A refusal (code 1: no
    /// such stream, or the last answer still being sent) goes to the
    /// shared stream, one frame.
    fn retention_state(&mut self, request: &control::RetentionState<'_>) -> Option<Waiting> {
        let correlation_id = request.correlation_id;
        if self.answering.is_some() {
            self.respond(
                correlation_id,
                0,
                ResponseCode::Error,
                RETENTION_ANSWER_BUSY,
            );
            return None;
        }
        let sink = match self
            .host
            .open_response(request.response_stream_id, request.response_channel)
        {
            Ok(sink) => sink,
            Err(HostRefusal(why)) => {
                self.respond(correlation_id, 0, ResponseCode::Error, &why);
                return None;
            }
        };
        // The codec caps `max_count` at `MAX_LIST_COUNT`.
        let max = usize::try_from(request.max_count).unwrap_or(usize::MAX);
        let posted = self.agent.post_retention_state(request.from_id, max);
        self.posted(correlation_id, posted, |answer| Waiting::RetentionState {
            correlation_id,
            sink,
            answer,
        })
    }

    /// Queues a retention state answer on its own stream: a descriptor
    /// per recording, then the summary with their count and the free
    /// space.
    fn answer_retention_state(
        &mut self,
        correlation_id: u64,
        sink: Box<dyn ResponseSink + Send>,
        descriptors: Vec<control::RetentionDescriptor>,
    ) {
        let mut queued = VecDeque::with_capacity(descriptors.len().saturating_add(1));
        let mut sent = 0u64;
        for descriptor in descriptors {
            let descriptor = control::RetentionDescriptor {
                correlation_id,
                ..descriptor
            };
            if let Some(bytes) =
                self.encode_answer(&ControlMessage::RetentionDescriptor(descriptor))
            {
                queued.push_back(bytes);
                count(&mut sent);
            }
        }
        let (min_free_bytes, free_bytes) = self.host.free_space();
        if let Some(bytes) = self.encode_answer(&ControlMessage::RetentionSummary(
            control::RetentionSummary {
                correlation_id,
                count: sent,
                min_free_bytes,
                free_bytes,
            },
        )) {
            queued.push_back(bytes);
        }
        self.answering = Some((sink, queued));
        self.flush_answering();
    }

    /// Answers a hold, a release or a purge with what the attached
    /// [`RetentionControl`] said, now; without one, posts it to the
    /// agent's retention engine and answers when it does.
    fn retain(
        &mut self,
        correlation_id: u64,
        recording_id: u64,
        call: impl FnOnce(&mut dyn RetentionControl) -> RetentionAnswer,
        post: impl FnOnce(&ArchiveHandle) -> Result<Posted<RetentionAnswer>, AgentError>,
    ) -> Option<Waiting> {
        if let Some(engine) = self.retention.as_deref_mut() {
            let answer = call(engine);
            self.answer_retention(correlation_id, recording_id, &answer);
            return None;
        }
        let posted = post(&self.agent);
        self.posted(correlation_id, posted, |answer| Waiting::Retain {
            correlation_id,
            recording_id,
            answer,
        })
    }

    fn answer_retention(
        &mut self,
        correlation_id: u64,
        recording_id: u64,
        answer: &RetentionAnswer,
    ) {
        let (code, message) = match answer {
            RetentionAnswer::Done => (ResponseCode::Ok, ""),
            RetentionAnswer::HeldWithoutEvidence => (ResponseCode::HeldWithoutEvidence, ""),
            RetentionAnswer::HeldInMemoryOnly => (ResponseCode::HeldInMemoryOnly, ""),
            RetentionAnswer::UnknownRecording => {
                (ResponseCode::UnknownRecording, "no such recording")
            }
            RetentionAnswer::Refused(reason) => (ResponseCode::Refused, reason.as_str()),
            RetentionAnswer::Error(why) => (ResponseCode::Error, why.as_str()),
        };
        self.respond(correlation_id, recording_id, code, message);
    }

    /// Verifies through the attached [`RetentionControl`] now, or posts
    /// the verification to the agent.
    fn verify(&mut self, correlation_id: u64, recording_id: u64) -> Option<Waiting> {
        if let Some(engine) = self.retention.as_deref_mut() {
            let verified = engine.verify(recording_id);
            self.answer_verified(correlation_id, recording_id, verified);
            return None;
        }
        let posted = self.agent.post_verify(recording_id);
        self.posted(correlation_id, posted, |answer| Waiting::Verify {
            correlation_id,
            recording_id,
            answer,
        })
    }

    /// One `RangeOutcome` per range, then the count of those sent.
    fn answer_verified(
        &mut self,
        correlation_id: u64,
        recording_id: u64,
        verified: agent::Verified,
    ) {
        match verified {
            Ok(ranges) => {
                let mut sent = 0u64;
                for range in ranges {
                    let range = control::RangeOutcome {
                        correlation_id,
                        ..range
                    };
                    if self.queue(&ControlMessage::RangeOutcome(range)) {
                        count(&mut sent);
                    }
                }
                self.respond(correlation_id, sent, ResponseCode::Ok, "");
            }
            Err(RetentionAnswer::Done) => self.respond(correlation_id, 0, ResponseCode::Ok, ""),
            Err(answer) => self.answer_retention(correlation_id, recording_id, &answer),
        }
    }

    /// Serves a schema 6 message (ADR-0091; karyos#1113): a replica's
    /// request or stop is posted to the agent; a source's message is not a
    /// request, and a request that does not decode is refused with code 4.
    fn serve_replication(&mut self, bytes: &[u8]) -> Option<Waiting> {
        match ReplicationMessage::decode(bytes) {
            Ok(ReplicationMessage::ReplicateRecording(request)) => {
                let correlation_id = request.correlation_id;
                let recording_id = request.recording_id;
                let chunk = self
                    .responses
                    .max_message()
                    .saturating_sub(RECORDING_BYTES_OVERHEAD);
                if chunk == 0 {
                    self.respond(
                        correlation_id,
                        0,
                        ResponseCode::InvalidRequest,
                        "response stream too short for replication",
                    );
                    return None;
                }
                let posted = self.agent.post_replicate(request, chunk);
                self.posted(correlation_id, posted, |answer| Waiting::Replicate {
                    correlation_id,
                    recording_id,
                    answer,
                })
            }
            Ok(ReplicationMessage::StopReplication(stop)) => {
                let correlation_id = stop.correlation_id;
                let posted = self.agent.post_stop_replication(stop);
                self.posted(correlation_id, posted, |answer| Waiting::StopReplication {
                    answer,
                })
            }
            Ok(_) => {
                let correlation_id = bytes
                    .get(12..20)
                    .and_then(|id| <[u8; 8]>::try_from(id).ok())
                    .map_or(0, u64::from_le_bytes);
                self.respond(
                    correlation_id,
                    0,
                    ResponseCode::InvalidRequest,
                    "not a request",
                );
                None
            }
            Err(error) => {
                self.undecodable(bytes, &error);
                None
            }
        }
    }

    /// Hands over what the agent sent for each replication, in order, as
    /// schema 6 messages; a replication whose agent side ended is dropped.
    fn forward_replications(&mut self) -> bool {
        let mut worked = false;
        let mut taken = 0;
        let mut index = 0;
        while let Some((correlation_id, recording_id, messages)) = self.replications.get(index) {
            let (correlation_id, recording_id) = (*correlation_id, *recording_id);
            let mut ended = false;
            let mut batch = Vec::new();
            while taken < REPLICATION_FORWARD
                && self.pending.len().saturating_add(batch.len()) < REPLICATION_FORWARD
            {
                match messages.try_recv() {
                    Ok(message) => {
                        batch.push(message);
                        taken += 1;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        ended = true;
                        break;
                    }
                }
            }
            for message in batch {
                worked = true;
                self.queue_replication(correlation_id, recording_id, &message);
            }
            if ended {
                self.replications.swap_remove(index);
            } else {
                index += 1;
            }
        }
        worked
    }

    /// Queues one of a replication's messages, encoded in schema 6.
    fn queue_replication(&mut self, correlation_id: u64, recording_id: u64, message: &Outgoing) {
        let mut out = vec![0u8; replication::RECORDING_BYTES.max_length as usize];
        let encoded = match message {
            Outgoing::Bytes { start, bytes } => {
                ReplicationMessage::RecordingBytes(RecordingBytes {
                    correlation_id,
                    recording_id,
                    start: *start,
                    bytes,
                })
            }
            Outgoing::Seal(seal) => ReplicationMessage::SourceSeal(SourceSeal {
                correlation_id,
                seal: *seal,
            }),
            Outgoing::Status(status) => ReplicationMessage::ReplicationStatus(*status),
        };
        match encoded.encode(&mut out) {
            Ok(length) => {
                out.truncate(length);
                self.pending.push_back(out);
            }
            Err(_) => count(&mut self.unencoded),
        }
    }

    /// Serves a schema 4 message: a durability query is posted to the
    /// agent; anything else is refused.
    fn serve_durable(&mut self, bytes: &[u8]) -> Option<Waiting> {
        match DurabilityMessage::decode(bytes) {
            Ok(DurabilityMessage::QueryDurable(query)) => {
                let correlation_id = query.correlation_id;
                let posted = self.agent.post_describe(query.recording_id);
                self.posted(correlation_id, posted, |answer| Waiting::Durable {
                    correlation_id,
                    answer,
                })
            }
            Ok(DurabilityMessage::DurablePosition(DurableAnswer { correlation_id, .. })) => {
                self.respond(
                    correlation_id,
                    0,
                    ResponseCode::InvalidRequest,
                    "not a request",
                );
                None
            }
            Err(error) => {
                self.undecodable(bytes, &error);
                None
            }
        }
    }

    /// Answers a request that does not decode: unsupported for an unknown
    /// tuple, invalid otherwise, under the correlation id at bytes 12 to 19
    /// (every request's first field).
    fn undecodable(&mut self, bytes: &[u8], error: &CodecError) {
        let correlation_id = bytes
            .get(12..20)
            .and_then(|id| <[u8; 8]>::try_from(id).ok())
            .map_or(0, u64::from_le_bytes);
        let code = if matches!(error, CodecError::UnsupportedSchema { .. }) {
            ResponseCode::UnsupportedSchema
        } else {
            ResponseCode::InvalidRequest
        };
        self.respond(correlation_id, 0, code, &error.to_string());
    }

    /// The request waiting for `posted`'s answer, or refused now when it
    /// could not be posted.
    fn posted<T>(
        &mut self,
        correlation_id: u64,
        posted: Result<Posted<T>, AgentError>,
        waiting: impl FnOnce(Posted<T>) -> Waiting,
    ) -> Option<Waiting> {
        match posted {
            Ok(answer) => Some(waiting(answer)),
            Err(error) => {
                self.refuse(correlation_id, &error);
                None
            }
        }
    }

    /// Answers an agent error.
    fn refuse(&mut self, correlation_id: u64, error: &AgentError) {
        let code = match error {
            AgentError::NotRecording { .. } | AgentError::Unknown { .. } => {
                ResponseCode::UnknownRecording
            }
            // Code 2 for an unknown recording, 4 off a seal boundary.
            AgentError::ReplicationRefused(refusal) => refusal.code(),
            // What the request asked for, not a fault of the archive.
            AgentError::Replay(
                ReplayError::NotAFrameBoundary { .. }
                | ReplayError::OutOfRange { .. }
                | ReplayError::RecordTimeUnknown { .. },
            ) => ResponseCode::InvalidRequest,
            _ => ResponseCode::Error,
        };
        self.respond(correlation_id, 0, code, &error.to_string());
    }

    /// Opens the lane and posts the recording's start.
    fn start_recording(&mut self, request: &control::StartRecording<'_>) -> Option<Waiting> {
        let correlation_id = request.correlation_id;
        let opened = match self.host.open_recording(request) {
            Ok(opened) => opened,
            Err(HostRefusal(why)) => {
                self.respond(correlation_id, 0, ResponseCode::Error, &why);
                return None;
            }
        };
        let geometry = if request.segment_length == 0 {
            Geometry::with_default_length(opened.term_length)
        } else {
            Geometry::new(opened.term_length, request.segment_length)
        };
        let Ok(geometry) = geometry else {
            self.respond(
                correlation_id,
                0,
                ResponseCode::InvalidRequest,
                "segment_length is not a multiple of the term length",
            );
            return None;
        };
        let start = opened.source.position();
        let posted = self.agent.post_start(agent::StartRecording {
            stream_id: request.stream_id,
            session_id: request.session_id,
            channel: request.channel.as_bytes().to_vec(),
            geometry,
            policy: request.sync_policy,
            mode: request.mode,
            format: opened.format,
            source: opened.source,
            origin: opened.origin,
        });
        match posted {
            Ok(answer) => Some(Waiting::Start {
                correlation_id,
                start,
                answer,
            }),
            Err(error) => {
                self.respond(correlation_id, 0, ResponseCode::Error, &error.to_string());
                None
            }
        }
    }

    /// Posts a replay's preparation; the host opens its target once the
    /// agent found its range readable.
    fn replay(&mut self, request: &control::Replay<'_>, length: usize) -> Option<Waiting> {
        let correlation_id = request.correlation_id;
        // The codec refuses a scale of 0.
        let rate = match request.rate {
            ReplayRate::Full => Rate::Full,
            ReplayRate::AsRecorded => Rate::AsRecorded,
            ReplayRate::Scaled { ppm } => match core::num::NonZeroU32::new(ppm) {
                Some(ppm) => Rate::Scaled { ppm },
                None => {
                    self.respond(correlation_id, 0, ResponseCode::InvalidRequest, "scale_ppm");
                    return None;
                }
            },
        };
        let posted = self.agent.post_prepare_replay(PrepareReplay {
            recording_id: request.recording_id,
            position: request.position,
            length: request.length,
            rate,
        });
        self.posted(correlation_id, posted, |answer| Waiting::Prepare {
            correlation_id,
            length,
            answer,
        })
    }

    /// Takes the agent's answer to the request waiting, if it came, and
    /// queues what it answers. Returns whether it came.
    fn collect(&mut self) -> bool {
        let Some(waiting) = self.waiting.take() else {
            return false;
        };
        match waiting {
            Waiting::Start {
                correlation_id,
                start,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::Start {
                    correlation_id,
                    start,
                    answer,
                }),
                Some(Ok(id)) => {
                    self.respond(correlation_id, id, ResponseCode::Ok, "");
                    // The request's own signal: never dropped.
                    self.queue(&ControlMessage::RecordingSignal(RecordingSignal {
                        correlation_id,
                        recording_id: id,
                        position: start,
                        signal: Signal::Started,
                    }));
                    true
                }
                Some(Err(error)) => {
                    self.respond(correlation_id, 0, ResponseCode::Error, &error.to_string());
                    true
                }
            },
            Waiting::Stop {
                correlation_id,
                recording_id,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::Stop {
                    correlation_id,
                    recording_id,
                    answer,
                }),
                Some(Ok(ended)) => {
                    self.respond(correlation_id, recording_id, ResponseCode::Ok, "");
                    // The request's own signal: never dropped.
                    self.queue(&ControlMessage::RecordingSignal(RecordingSignal {
                        correlation_id: 0,
                        recording_id,
                        position: ended.position,
                        signal: Signal::Stopped {
                            reason: ended.reason,
                            incomplete: ended.incomplete,
                        },
                    }));
                    true
                }
                Some(Err(error)) => {
                    self.refuse(correlation_id, &error);
                    true
                }
            },
            Waiting::List {
                correlation_id,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::List {
                    correlation_id,
                    answer,
                }),
                Some(Ok(listed)) => {
                    self.list(correlation_id, &listed);
                    true
                }
                Some(Err(error)) => {
                    self.refuse(correlation_id, &error);
                    true
                }
            },
            Waiting::Prepare {
                correlation_id,
                length,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::Prepare {
                    correlation_id,
                    length,
                    answer,
                }),
                Some(Ok(prepared)) => {
                    self.open_replay(correlation_id, length, &prepared);
                    true
                }
                Some(Err(error)) => {
                    self.refuse(correlation_id, &error);
                    true
                }
            },
            Waiting::Attach {
                correlation_id,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::Attach {
                    correlation_id,
                    answer,
                }),
                Some(Ok(id)) => {
                    self.respond(correlation_id, id, ResponseCode::Ok, "");
                    true
                }
                Some(Err(error)) => {
                    self.respond(correlation_id, 0, ResponseCode::Error, &error.to_string());
                    true
                }
            },
            Waiting::Retain {
                correlation_id,
                recording_id,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::Retain {
                    correlation_id,
                    recording_id,
                    answer,
                }),
                Some(Ok(answer)) => {
                    self.answer_retention(correlation_id, recording_id, &answer);
                    true
                }
                Some(Err(error)) => {
                    self.refuse(correlation_id, &error);
                    true
                }
            },
            Waiting::RetentionState {
                correlation_id,
                sink,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::RetentionState {
                    correlation_id,
                    sink,
                    answer,
                }),
                Some(Ok(descriptors)) => {
                    self.answer_retention_state(correlation_id, sink, descriptors);
                    true
                }
                Some(Err(error)) => {
                    self.refuse(correlation_id, &error);
                    true
                }
            },
            Waiting::Verify {
                correlation_id,
                recording_id,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::Verify {
                    correlation_id,
                    recording_id,
                    answer,
                }),
                Some(Ok(verified)) => {
                    self.answer_verified(correlation_id, recording_id, verified);
                    true
                }
                Some(Err(error)) => {
                    self.refuse(correlation_id, &error);
                    true
                }
            },
            Waiting::Replicate {
                correlation_id,
                recording_id,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::Replicate {
                    correlation_id,
                    recording_id,
                    answer,
                }),
                Some(Ok(messages)) => {
                    self.replications
                        .push((correlation_id, recording_id, messages));
                    true
                }
                Some(Err(error)) => {
                    self.refuse(correlation_id, &error);
                    true
                }
            },
            // The stop's own status follows on the replication's stream.
            Waiting::StopReplication { answer } => match answer.try_answer() {
                None => self.wait(Waiting::StopReplication { answer }),
                Some(_) => true,
            },
            Waiting::Durable {
                correlation_id,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::Durable {
                    correlation_id,
                    answer,
                }),
                Some(Ok(described)) => {
                    let answer = DurableAnswer {
                        correlation_id,
                        position: DurablePosition::of(&described),
                    };
                    // A position the codec refuses is a bug: answered as
                    // an error, so the querier is never left waiting.
                    if !self.queue_encoded(|out| answer.encode(out)) {
                        self.respond(
                            correlation_id,
                            0,
                            ResponseCode::Error,
                            "the durable position does not encode",
                        );
                    }
                    true
                }
                Some(Err(error)) => {
                    self.refuse(correlation_id, &error);
                    true
                }
            },
            Waiting::StopReplay {
                correlation_id,
                replay_id,
                answer,
            } => match answer.try_answer() {
                None => self.wait(Waiting::StopReplay {
                    correlation_id,
                    replay_id,
                    answer,
                }),
                Some(Ok(_)) => {
                    self.respond(correlation_id, replay_id, ResponseCode::Ok, "");
                    true
                }
                Some(Err(AgentError::Unknown { .. })) => {
                    self.respond(
                        correlation_id,
                        0,
                        ResponseCode::UnknownReplay,
                        "no such replay",
                    );
                    true
                }
                Some(Err(error)) => {
                    self.refuse(correlation_id, &error);
                    true
                }
            },
        }
    }

    /// Keeps waiting: nothing came.
    fn wait(&mut self, waiting: Waiting) -> bool {
        self.waiting = Some(waiting);
        false
    }

    /// One descriptor per recording listed, then the count of those sent.
    fn list(&mut self, correlation_id: u64, listed: &[Described]) {
        let mut count = 0u64;
        for described in listed {
            let recording = &described.recording;
            let state = match recording.stop {
                Some(stop) => RecordingState::Stopped(stop),
                None => RecordingState::Recording {
                    written: described.end,
                    incomplete: described.incomplete,
                },
            };
            let Ok(channel) = core::str::from_utf8(&recording.channel) else {
                continue;
            };
            let queued = self.queue(&ControlMessage::RecordingDescriptor(RecordingDescriptor {
                correlation_id,
                recording_id: recording.id,
                start: recording.start,
                start_time_ns: recording.start_time_ns,
                state,
                geometry: recording.geometry,
                source: recording.format.source,
                stream_id: recording.stream_id,
                session_id: recording.session_id,
                channel,
            }));
            if queued {
                count += 1;
            }
        }
        self.respond(correlation_id, count, ResponseCode::Ok, "");
    }

    /// The prepared replay's target, opened by the host, then attached.
    fn open_replay(&mut self, correlation_id: u64, length: usize, prepared: &Prepared) {
        let decoded = self.request.get(..length).map(ControlMessage::decode);
        let opened = match decoded {
            Some(Ok(ControlMessage::Replay(request))) => self.host.open_replay(
                &request,
                &prepared.recording,
                prepared.replay_id,
                prepared.from,
                prepared.to,
            ),
            // It decoded when it was served, and stays in the buffer while
            // it waits.
            _ => Err(HostRefusal("the request is gone".to_owned())),
        };
        let posted = match opened {
            Ok(sink) => self
                .agent
                .post_attach_replay(prepared.replay_id, prepared.from, sink),
            Err(HostRefusal(why)) => {
                // The prepared replay is dropped; its answer is not needed.
                let _ = self.agent.post_stop_replay(prepared.replay_id);
                self.respond(correlation_id, 0, ResponseCode::Error, &why);
                return;
            }
        };
        self.waiting = self.posted(correlation_id, posted, |answer| Waiting::Attach {
            correlation_id,
            answer,
        });
    }
}

/// The session id of replay `replay_id`'s target: the id's low 32 bits,
/// as Aeron does (archive-control-codec.md section 4.1).
#[must_use]
pub fn replay_session_id(replay_id: u64) -> i32 {
    let low = u32::try_from(replay_id & u64::from(u32::MAX)).unwrap_or_default();
    low.cast_signed()
}

/// Adds one to `counter`; once at `u64::MAX` it stays there, never
/// wrapping.
fn count(counter: &mut u64) {
    if let Some(next) = counter.checked_add(1) {
        *counter = next;
    }
}

/// `message` cut to [`MAX_RESPONSE_MESSAGE`] bytes at a character boundary.
fn cut(message: &str) -> &str {
    let longest = message.len().min(MAX_RESPONSE_MESSAGE);
    let end = (0..=longest)
        .rev()
        .find(|end| message.is_char_boundary(*end))
        .unwrap_or(0);
    message.get(..end).unwrap_or("")
}
