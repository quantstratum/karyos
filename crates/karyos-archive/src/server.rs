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
//! - **Signals.** A recording's start is signalled with its start
//!   request's correlation id; its stop or failure with 0, for every
//!   reader. A replay's end has no signal in version 1: its target stream's
//!   seal says it.
//!
//! This is the control path: it allocates (the queued answers, the boxed
//! host objects); the replayed frames do not pass through it.

use std::collections::VecDeque;

use karyos_codec::CodecError;

use crate::agent::{self, AgentError, ArchiveHandle, Event, ReplaySink, StartReplay};
use crate::catalog::{Recording, StreamFormat};
use crate::control::{
    self, ControlMessage, ControlResponse, MAX_RESPONSE_MESSAGE, RecordingDescriptor,
    RecordingSignal, RecordingState, ReplayRate, ResponseCode, Signal,
};
use crate::recorder::FrameSource;
use crate::replay::Rate;
use crate::segment::Geometry;

#[cfg(test)]
mod tests;

/// The longest request: a `Replay` with the longest channel.
pub const MAX_REQUEST: usize = 1079;

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

    /// Opens the target stream of a replay of `recording` over
    /// `[from, to)`: an image that keeps the recorded positions. The sink's
    /// `finish` names where the replay ended; it reached its end only at
    /// `to`.
    ///
    /// # Errors
    ///
    /// A [`HostRefusal`] the requester is told.
    fn open_replay(
        &mut self,
        request: &control::Replay<'_>,
        recording: &Recording,
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

/// The control server: requests in, the agent's work, answers out.
pub struct ControlServer<H, Q, R> {
    agent: ArchiveHandle,
    host: H,
    requests: Q,
    responses: R,
    request: Vec<u8>,
    /// Answers and signals not sent yet, in order.
    pending: VecDeque<Vec<u8>>,
}

impl<H, Q, R> core::fmt::Debug for ControlServer<H, Q, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControlServer")
            .field("pending", &self.pending.len())
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
            request: vec![0; MAX_REQUEST],
            pending: VecDeque::new(),
        }
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

    /// One duty: the agent's events become signals, waiting answers are
    /// sent, and, once none waits, one request is served. Returns whether
    /// anything moved.
    pub fn duty(&mut self) -> bool {
        let mut worked = false;
        while let Some(event) = self.agent.try_event() {
            worked = true;
            self.signal(&event);
        }
        worked |= self.flush();
        if self.pending.is_empty()
            && let Some(length) = self.requests.next(&mut self.request)
        {
            worked = true;
            let request = std::mem::take(&mut self.request);
            if let Some(bytes) = request.get(..length) {
                self.serve(bytes);
            }
            self.request = request;
            self.flush();
        }
        worked
    }

    /// Stops the agent: what records is stopped, what replays finished.
    /// Answers not sent yet are dropped.
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

    fn queue(&mut self, message: &ControlMessage<'_>) {
        let mut out = vec![0u8; 1200];
        // Every message the server builds is valid and fits: a failure is
        // a bug, and the answer is dropped rather than sent malformed.
        if let Ok(length) = message.encode(&mut out) {
            out.truncate(length);
            self.pending.push_back(out);
        }
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
            // Where its segments end now; the next start settles it there.
            Event::Failed { id, .. } => (
                id,
                self.agent.describe(id).map_or(0, |described| described.end),
                Signal::Failed,
            ),
            // No version 1 signal: the target's seal says it.
            Event::ReplayEnded { .. } => return,
        };
        self.queue(&ControlMessage::RecordingSignal(RecordingSignal {
            correlation_id: 0,
            recording_id,
            position,
            signal,
        }));
    }

    fn serve(&mut self, bytes: &[u8]) {
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
                return;
            }
        };
        match message {
            ControlMessage::StartRecording(request) => self.start_recording(&request),
            ControlMessage::StopRecording(request) => {
                let correlation_id = request.correlation_id;
                match self.agent.stop(request.recording_id) {
                    Ok(ended) => {
                        self.respond(correlation_id, request.recording_id, ResponseCode::Ok, "");
                        self.signal(&Event::Ended {
                            id: request.recording_id,
                            ended,
                        });
                    }
                    Err(error) => self.refuse(correlation_id, &error),
                }
            }
            ControlMessage::ListRecordings(request) => self.list(&request),
            ControlMessage::Replay(request) => self.replay(&request),
            ControlMessage::StopReplay(request) => {
                match self.agent.stop_replay(request.replay_id) {
                    Ok(_) => self.respond(
                        request.correlation_id,
                        request.replay_id,
                        ResponseCode::Ok,
                        "",
                    ),
                    Err(AgentError::Unknown { .. }) => self.respond(
                        request.correlation_id,
                        0,
                        ResponseCode::UnknownReplay,
                        "no such replay",
                    ),
                    Err(error) => self.refuse(request.correlation_id, &error),
                }
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
            }
        }
    }

    /// Answers an agent error.
    fn refuse(&mut self, correlation_id: u64, error: &AgentError) {
        let code = match error {
            AgentError::NotRecording { .. } | AgentError::Unknown { .. } => {
                ResponseCode::UnknownRecording
            }
            AgentError::Replay(_) => ResponseCode::InvalidRequest,
            _ => ResponseCode::Error,
        };
        self.respond(correlation_id, 0, code, &error.to_string());
    }

    fn start_recording(&mut self, request: &control::StartRecording<'_>) {
        let correlation_id = request.correlation_id;
        let opened = match self.host.open_recording(request) {
            Ok(opened) => opened,
            Err(HostRefusal(why)) => {
                self.respond(correlation_id, 0, ResponseCode::Error, &why);
                return;
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
            return;
        };
        let start = opened.source.position();
        let started = self.agent.start(agent::StartRecording {
            stream_id: request.stream_id,
            session_id: request.session_id,
            channel: request.channel.as_bytes().to_vec(),
            geometry,
            policy: request.sync_policy,
            mode: request.mode,
            format: opened.format,
            source: opened.source,
        });
        match started {
            Ok(id) => {
                self.respond(correlation_id, id, ResponseCode::Ok, "");
                self.queue(&ControlMessage::RecordingSignal(RecordingSignal {
                    correlation_id,
                    recording_id: id,
                    position: start,
                    signal: Signal::Started,
                }));
            }
            Err(error) => self.respond(correlation_id, 0, ResponseCode::Error, &error.to_string()),
        }
    }

    fn list(&mut self, request: &control::ListRecordings) {
        let correlation_id = request.correlation_id;
        let recordings = match self.agent.recordings() {
            Ok(recordings) => recordings,
            Err(error) => return self.refuse(correlation_id, &error),
        };
        let mut count = 0u64;
        let listed = recordings
            .iter()
            .filter(|recording| recording.id >= request.from_id)
            .take(usize::try_from(request.max_count).unwrap_or(usize::MAX));
        for recording in listed {
            let state = match recording.stop {
                Some(stop) => RecordingState::Stopped(stop),
                None => RecordingState::Recording {
                    incomplete: self
                        .agent
                        .describe(recording.id)
                        .is_ok_and(|described| described.incomplete),
                },
            };
            let Ok(channel) = core::str::from_utf8(&recording.channel) else {
                continue;
            };
            self.queue(&ControlMessage::RecordingDescriptor(RecordingDescriptor {
                correlation_id,
                recording_id: recording.id,
                start: recording.start,
                start_time_ns: recording.start_time_ns,
                state,
                geometry: recording.geometry,
                stream_id: recording.stream_id,
                session_id: recording.session_id,
                channel,
            }));
            count += 1;
        }
        self.respond(correlation_id, count, ResponseCode::Ok, "");
    }

    fn replay(&mut self, request: &control::Replay<'_>) {
        let correlation_id = request.correlation_id;
        let described = match self.agent.describe(request.recording_id) {
            Ok(described) => described,
            Err(error) => return self.refuse(correlation_id, &error),
        };
        let from = request.position;
        let to = if request.length == u64::MAX {
            Some(described.end)
        } else {
            from.checked_add(request.length)
        };
        let Some(to) = to.filter(|to| from < *to && *to <= described.end) else {
            self.respond(
                correlation_id,
                0,
                ResponseCode::InvalidRequest,
                "the range is not within the recording",
            );
            return;
        };
        // The codec refuses a scale of 0.
        let rate = match request.rate {
            ReplayRate::Full => Rate::Full,
            ReplayRate::AsRecorded => Rate::AsRecorded,
            ReplayRate::Scaled { ppm } => match core::num::NonZeroU32::new(ppm) {
                Some(ppm) => Rate::Scaled { ppm },
                None => {
                    self.respond(correlation_id, 0, ResponseCode::InvalidRequest, "scale_ppm");
                    return;
                }
            },
        };
        let sink = match self
            .host
            .open_replay(request, &described.recording, from, to)
        {
            Ok(sink) => sink,
            Err(HostRefusal(why)) => {
                self.respond(correlation_id, 0, ResponseCode::Error, &why);
                return;
            }
        };
        let started = self.agent.replay(StartReplay {
            recording_id: request.recording_id,
            from,
            to,
            rate,
            sink,
        });
        match started {
            Ok(id) => self.respond(correlation_id, id, ResponseCode::Ok, ""),
            Err(error) => self.refuse(correlation_id, &error),
        }
    }
}

/// `message` cut to [`MAX_RESPONSE_MESSAGE`] bytes at a character boundary.
fn cut(message: &str) -> &str {
    let mut end = message.len().min(MAX_RESPONSE_MESSAGE);
    while !message.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    message.get(..end).unwrap_or("")
}
