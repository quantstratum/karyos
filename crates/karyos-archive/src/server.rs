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
//! This is the control path: it allocates (the queued answers, the boxed
//! host objects); the replayed frames do not pass through it.

use std::collections::VecDeque;

use karyos_codec::CodecError;

use crate::agent::{
    self, AgentError, ArchiveHandle, Described, Event, Posted, PrepareReplay, Prepared, ReplaySink,
};
use crate::catalog::{Recording, StreamFormat};
use crate::control::{
    self, ControlMessage, ControlResponse, MAX_CHANNEL, MAX_RESPONSE_MESSAGE, RecordingDescriptor,
    RecordingSignal, RecordingState, ReplayRate, ResponseCode, Signal,
};
use crate::recorder::{Ended, FrameSource};
use crate::replay::{Rate, ReplayError};
use crate::segment::Geometry;

#[cfg(test)]
mod tests;

/// The longest request: a `Replay` with the longest channel.
pub const MAX_REQUEST: usize = 1079;

/// The longest message the server sends: a `RecordingDescriptor` with the
/// longest channel (the envelope, its block, and the channel's length and
/// bytes).
pub const MAX_ANSWER: usize = 12 + 110 + 2 + MAX_CHANNEL;

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
}

/// A recorded lane the host opened.
pub struct HostRecording {
    /// Its reader, positioned at the recording's start.
    pub source: Box<dyn FrameSource + Send>,
    /// Its term length.
    pub term_length: u32,
    /// The recorded stream's format, kept in the catalog for its replays.
    pub format: StreamFormat,
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
}

/// The server's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        }
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
        // No version 1 signal: a replay's target's seal says it ended.
        while self.agent.try_replay_ended().is_some() {
            worked = true;
        }
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

    fn flush(&mut self) -> bool {
        let mut sent = false;
        while let Some(message) = self.pending.front() {
            if !self.responses.send(message) {
                break;
            }
            sent = true;
            self.pending.pop_front();
        }
        sent
    }

    /// Queues `message`; `false` when it did not encode.
    fn queue(&mut self, message: &ControlMessage<'_>) -> bool {
        let mut out = vec![0u8; MAX_ANSWER];
        // Every message the server builds is valid and fits: a failure is
        // a bug, and the message is counted and dropped rather than sent
        // malformed.
        let Ok(length) = message.encode(&mut out) else {
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
        let message = match ControlMessage::decode(bytes) {
            Ok(message) => message,
            Err(error) => {
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
            ControlMessage::ControlResponse(ControlResponse { correlation_id, .. })
            | ControlMessage::RecordingDescriptor(RecordingDescriptor { correlation_id, .. })
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
