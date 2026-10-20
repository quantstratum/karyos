// SPDX-License-Identifier: Apache-2.0

//! A replayer over the Archive's control streams (quantstratum-docs:
//! karyos/design/archive-replay-control.md, B6): it starts and stops
//! replays for a requester such as a binding, and never reads them.
//!
//! [`Replayer::start`] and [`Replayer::stop`] queue a request and return
//! its [`RequestId`]; each [`Replayer::poll`] sends what it can, reads the
//! answers there are, and reports one answered or expired request as a
//! [`ReplayerEvent`]. It never blocks. At most [`MAX_PENDING`] requests
//! wait at once, and nothing grows after [`Replayer::new`].
//!
//! A started replay's target is a replay target (stream
//! [`ReplaySpec::target_stream_id`], session
//! [`replay_session_id`] of the replay id), exclusive to its first
//! reader. A reader takes it through the host's `replay_targets`, and
//! learns the replay's end from the target's seal: `EndOfStream` when the
//! replay reached its requested end, `ImageRetired` when it was stopped,
//! failed, or found no reader in time. No answer on the control streams
//! tells the requester (version 1 has no replay-ended signal).
//!
//! A request that gets no answer within [`ReplayerConfig::deadline`]
//! expires and is forgotten. A replay its late answer started is stopped,
//! as [`ArchiveClient`](super::ArchiveClient) stops a withdrawn one, so a
//! request that timed out never leaves a replay running; at most
//! [`MAX_ORPHANS`] such requests are remembered.
//!
//! Correlation ids carry [`ReplayerConfig::client_id`] in their high 32
//! bits; answers to other requesters, and signals, are skipped. The low 32
//! bits start at 1 and skip 0 when they wrap.

use std::time::{Duration, Instant};

use super::{ControlRequests, ControlResponses};
use crate::control::{
    self, ControlMessage, ControlResponse, MAX_CHANNEL, ReplayRate, ResponseCode,
};
use crate::server::{MAX_ANSWER, MAX_REQUEST, replay_session_id};

/// Requests waiting for their answers at most.
pub const MAX_PENDING: usize = 16;

/// Answers read at most per poll.
pub const ANSWERS_PER_CALL: usize = 64;

/// Expired replay requests remembered at most, so a late start is
/// stopped; past it the oldest is forgotten.
pub const MAX_ORPHANS: usize = 64;

/// The replayer's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReplayerConfig {
    /// This requester's id, the high 32 bits of its correlation ids, unique
    /// among the Archive's requesters (archive-control-codec.md §7a).
    pub client_id: u32,
    /// How long a request waits for its answer.
    pub deadline: Duration,
}

impl ReplayerConfig {
    /// A replayer `client_id` whose requests wait up to a second.
    #[must_use]
    pub fn new(client_id: u32) -> Self {
        Self {
            client_id,
            deadline: Duration::from_secs(1),
        }
    }
}

/// What to replay, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReplaySpec {
    /// The recording, never 0.
    pub recording_id: u64,
    /// The first position replayed.
    pub position: u64,
    /// Bytes; `u64::MAX` to the recording's end.
    pub length: u64,
    /// The pace.
    pub rate: ReplayRate,
    /// The target stream.
    pub target_stream_id: i32,
    /// The target channel, 1 to [`MAX_CHANNEL`] bytes.
    pub target_channel: String,
}

impl ReplaySpec {
    /// The whole recording from `position`, at full rate, onto
    /// `target_stream_id` over `karyos:ipc`.
    #[must_use]
    pub fn new(recording_id: u64, position: u64, target_stream_id: i32) -> Self {
        Self {
            recording_id,
            position,
            length: u64::MAX,
            rate: ReplayRate::Full,
            target_stream_id,
            target_channel: "karyos:ipc".to_owned(),
        }
    }
}

/// A request's id: the low 32 bits of its correlation id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(u32);

impl RequestId {
    /// The id's value, never 0.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// What a poll reports: one request answered or expired.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplayerEvent {
    /// The Archive started the replay. Its target is the replay target at
    /// the spec's stream and `session_id`, which is
    /// [`replay_session_id`] of `replay_id`.
    Started {
        /// The request.
        request: RequestId,
        /// The replay.
        replay_id: u64,
        /// Its target's session.
        session_id: i32,
    },
    /// The Archive stopped the replay.
    Stopped {
        /// The request.
        request: RequestId,
        /// The replay.
        replay_id: u64,
    },
    /// The Archive refused the request.
    Refused {
        /// The request.
        request: RequestId,
        /// Why.
        code: ResponseCode,
        /// The Archive's message.
        message: String,
    },
    /// No answer came within [`ReplayerConfig::deadline`]. The request is
    /// forgotten; a replay its late answer starts is stopped.
    Expired {
        /// The request.
        request: RequestId,
    },
}

/// Why a request was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayerError {
    /// [`MAX_PENDING`] requests wait already, or the next correlation id
    /// is still in use: poll, then try again.
    #[error("too many requests are waiting")]
    Busy,
    /// A recording or replay id of 0, a target channel that is empty or
    /// longer than [`MAX_CHANNEL`] bytes, or a scale out of its bounds.
    #[error("the request is invalid")]
    InvalidSpec,
}

/// What a waiting request asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Replay,
    Stop { replay_id: u64 },
}

/// A request waiting for its answer, encoded once at queueing.
#[derive(Debug)]
struct Pending {
    low: u32,
    kind: Kind,
    since: Instant,
    sent: bool,
    length: usize,
    bytes: Vec<u8>,
}

/// A stop the replayer sends by itself, for a late start: its answer is
/// read and dropped.
#[derive(Debug, Clone, Copy)]
struct Orphan {
    /// The expired replay request's correlation id.
    correlation_id: u64,
}

/// The replayer (see the module).
#[derive(Debug)]
pub struct Replayer<Q, R> {
    config: ReplayerConfig,
    requests: Q,
    responses: R,
    next: u32,
    pending: Vec<Pending>,
    /// Encoding buffers of answered requests, reused.
    spare: Vec<Vec<u8>>,
    orphans: Vec<Orphan>,
    /// Stops of late starts not sent yet, each with its own correlation id.
    stops: Vec<(u64, u64)>,
    /// The correlation ids of the stops sent, whose answers are dropped.
    stopping: Vec<u64>,
    events: Vec<ReplayerEvent>,
    stop_buffer: Vec<u8>,
    answer: Vec<u8>,
}

impl<Q: ControlRequests, R: ControlResponses> Replayer<Q, R> {
    /// A replayer sending on `requests` and reading `responses`.
    #[must_use]
    pub fn new(config: ReplayerConfig, requests: Q, responses: R) -> Self {
        Self {
            config,
            requests,
            responses,
            next: 1,
            pending: Vec::with_capacity(MAX_PENDING),
            spare: (0..MAX_PENDING).map(|_| vec![0; MAX_REQUEST]).collect(),
            orphans: Vec::with_capacity(MAX_ORPHANS),
            stops: Vec::with_capacity(MAX_ORPHANS),
            stopping: Vec::with_capacity(MAX_ORPHANS),
            events: Vec::with_capacity(MAX_PENDING),
            stop_buffer: vec![0; MAX_REQUEST],
            answer: vec![0; MAX_ANSWER],
        }
    }

    /// The transports back, dropping the requests that wait: to close them
    /// (`connection::Requests::close`).
    #[must_use]
    pub fn into_transports(self) -> (Q, R) {
        (self.requests, self.responses)
    }

    /// The requests waiting for their answers.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Queues a replay request for `spec`; it is sent by this call when
    /// there is room, else by a later [`Replayer::poll`].
    ///
    /// # Errors
    ///
    /// [`ReplayerError::Busy`] and [`ReplayerError::InvalidSpec`].
    pub fn start(&mut self, spec: &ReplaySpec, now: Instant) -> Result<RequestId, ReplayerError> {
        let channel = spec.target_channel.len();
        if spec.recording_id == 0 || channel == 0 || channel > MAX_CHANNEL {
            return Err(ReplayerError::InvalidSpec);
        }
        self.queue(Kind::Replay, now, |correlation_id| {
            ControlMessage::Replay(control::Replay {
                correlation_id,
                recording_id: spec.recording_id,
                position: spec.position,
                length: spec.length,
                rate: spec.rate,
                target_stream_id: spec.target_stream_id,
                target_channel: &spec.target_channel,
            })
        })
    }

    /// Queues a stop of replay `replay_id`; it is sent by this call when
    /// there is room, else by a later [`Replayer::poll`].
    ///
    /// # Errors
    ///
    /// [`ReplayerError::Busy`] (also while [`MAX_PENDING`] answers wait to
    /// be polled), and [`ReplayerError::InvalidSpec`] for a replay id of 0.
    pub fn stop(&mut self, replay_id: u64, now: Instant) -> Result<RequestId, ReplayerError> {
        if replay_id == 0 {
            return Err(ReplayerError::InvalidSpec);
        }
        self.queue(Kind::Stop { replay_id }, now, |correlation_id| {
            ControlMessage::StopReplay(control::StopReplay {
                correlation_id,
                replay_id,
            })
        })
    }

    fn correlation(&self, low: u32) -> u64 {
        (u64::from(self.config.client_id) << 32) | u64::from(low)
    }

    /// Whether a correlation id with low bits `low` is still awaited.
    fn in_use(&self, low: u32) -> bool {
        let correlation_id = self.correlation(low);
        self.pending.iter().any(|pending| pending.low == low)
            || self
                .orphans
                .iter()
                .any(|orphan| orphan.correlation_id == correlation_id)
            || self.stopping.contains(&correlation_id)
            || self.stops.iter().any(|(_, stop)| *stop == correlation_id)
    }

    /// The next low 32 bits, which skip 0 on a wrap; `None` while that id
    /// is still in use.
    fn take_low(&mut self) -> Option<u32> {
        let low = self.next;
        if self.in_use(low) {
            return None;
        }
        self.next = low.checked_add(1).unwrap_or(1);
        Some(low)
    }

    fn queue<'a>(
        &mut self,
        kind: Kind,
        now: Instant,
        message: impl FnOnce(u64) -> ControlMessage<'a>,
    ) -> Result<RequestId, ReplayerError> {
        // Events not polled yet count too, so what waits stays bounded.
        if self
            .pending
            .len()
            .checked_add(self.events.len())
            .is_none_or(|waiting| waiting >= MAX_PENDING)
        {
            return Err(ReplayerError::Busy);
        }
        let Some(mut bytes) = self.spare.pop() else {
            return Err(ReplayerError::Busy);
        };
        // The id is taken only once the request encodes, so a refused
        // spec uses none.
        let low = self.next;
        if self.in_use(low) {
            self.spare.push(bytes);
            return Err(ReplayerError::Busy);
        }
        let length = match message(self.correlation(low)).encode(&mut bytes) {
            Ok(length) => length,
            Err(_) => {
                self.spare.push(bytes);
                return Err(ReplayerError::InvalidSpec);
            }
        };
        self.next = low.checked_add(1).unwrap_or(1);
        self.pending.push(Pending {
            low,
            kind,
            since: now,
            sent: false,
            length,
            bytes,
        });
        self.send();
        Ok(RequestId(low))
    }

    /// Sends the stops of late starts, then the requests not sent yet, in
    /// order, while there is room.
    fn send(&mut self) {
        while let Some(&(replay_id, correlation_id)) = self.stops.first() {
            let message = ControlMessage::StopReplay(control::StopReplay {
                correlation_id,
                replay_id,
            });
            let sent = match message.encode(&mut self.stop_buffer) {
                Ok(length) => self
                    .stop_buffer
                    .get(..length)
                    .is_some_and(|bytes| self.requests.send(bytes)),
                // A replay id the Archive gave encodes; drop one that does
                // not rather than send it malformed.
                Err(_) => true,
            };
            if !sent {
                return;
            }
            self.stops.remove(0);
            if self.stopping.len() >= MAX_ORPHANS {
                self.stopping.remove(0);
            }
            self.stopping.push(correlation_id);
        }
        for pending in self.pending.iter_mut().filter(|pending| !pending.sent) {
            let Some(bytes) = pending.bytes.get(..pending.length) else {
                continue;
            };
            if !self.requests.send(bytes) {
                return;
            }
            pending.sent = true;
        }
    }

    /// Sends what it can, reads at most [`ANSWERS_PER_CALL`] answers, and
    /// reports one answered or expired request, oldest first.
    pub fn poll(&mut self, now: Instant) -> Option<ReplayerEvent> {
        self.send();
        let mut answer = std::mem::take(&mut self.answer);
        for _ in 0..ANSWERS_PER_CALL {
            let Some(length) = self.responses.next(&mut answer) else {
                break;
            };
            if let Some(Ok(ControlMessage::ControlResponse(response))) =
                answer.get(..length).map(ControlMessage::decode)
            {
                self.answered(&response);
            }
            // Signals, other messages and what does not decode are
            // skipped.
        }
        self.answer = answer;
        self.expire(now);
        // A late start found by this poll is stopped now if there is room.
        self.send();
        (!self.events.is_empty()).then(|| self.events.remove(0))
    }

    /// One response: a waiting request's answer, a late start to stop, or
    /// the answer to such a stop; another requester's is skipped.
    fn answered(&mut self, response: &ControlResponse<'_>) {
        let correlation_id = response.correlation_id;
        if correlation_id >> 32 != u64::from(self.config.client_id) {
            return;
        }
        if let Some(index) = self.stopping.iter().position(|id| *id == correlation_id) {
            self.stopping.swap_remove(index);
            return;
        }
        if let Some(index) = self
            .orphans
            .iter()
            .position(|orphan| orphan.correlation_id == correlation_id)
        {
            self.orphans.swap_remove(index);
            if response.code == ResponseCode::Ok {
                self.stop_late(response.id);
            }
            return;
        }
        let Some(index) = self
            .pending
            .iter()
            .position(|pending| self.correlation(pending.low) == correlation_id && pending.sent)
        else {
            return;
        };
        let pending = self.pending.remove(index);
        let request = RequestId(pending.low);
        let event = match (response.code, pending.kind) {
            (ResponseCode::Ok, Kind::Replay) => ReplayerEvent::Started {
                request,
                replay_id: response.id,
                session_id: replay_session_id(response.id),
            },
            (ResponseCode::Ok, Kind::Stop { replay_id }) => {
                ReplayerEvent::Stopped { request, replay_id }
            }
            (code, _) => ReplayerEvent::Refused {
                request,
                code,
                message: response.message.to_owned(),
            },
        };
        self.spare.push(pending.bytes);
        self.events.push(event);
    }

    /// Queues the stop of `replay_id`, which a request that expired
    /// started. With no correlation id free it is not sent, and the replay
    /// runs to its end.
    fn stop_late(&mut self, replay_id: u64) {
        let Some(low) = self.take_low() else {
            return;
        };
        if self.stops.len() >= MAX_ORPHANS {
            self.stops.remove(0);
        }
        let correlation_id = self.correlation(low);
        self.stops.push((replay_id, correlation_id));
    }

    /// Expires the requests waiting past the deadline. A sent replay
    /// request is remembered, so a late start is stopped.
    fn expire(&mut self, now: Instant) {
        let deadline = self.config.deadline;
        while let Some(index) = self.pending.iter().position(|pending| {
            now.checked_duration_since(pending.since)
                .is_some_and(|waited| waited >= deadline)
        }) {
            let pending = self.pending.remove(index);
            if pending.sent && pending.kind == Kind::Replay {
                if self.orphans.len() >= MAX_ORPHANS {
                    self.orphans.remove(0);
                }
                self.orphans.push(Orphan {
                    correlation_id: self.correlation(pending.low),
                });
            }
            self.spare.push(pending.bytes);
            self.events.push(ReplayerEvent::Expired {
                request: RequestId(pending.low),
            });
        }
    }
}

#[cfg(test)]
mod tests;
