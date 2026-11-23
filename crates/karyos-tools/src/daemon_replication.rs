// SPDX-License-Identifier: Apache-2.0

//! `karyosd`'s source side of recording replication (quantstratum-docs:
//! karyos/adr/0102-replication-pushed-from-the-source.md; design
//! archive-replication.md §1 and §4; karyos#1113).
//!
//! Each `--replicate` is one replication the source's operator authorized:
//! a recording, a mode, the replica's endpoint and a stream id. For each,
//! the daemon runs three parts in its duty cycle:
//!
//! - **The pair's server.** A request stream and a response stream of the
//!   replication alone (decision 1), served against the Archive agent like
//!   the H3 pair but never shared, so a stalled replica holds back only its
//!   own pair. It reads the request stream every duty whatever output is
//!   pending, posts `ReplicateRecording` and `StopReplication` to the
//!   agent, and writes the agent's messages in schema 6 on the response
//!   stream, holding one message while that stream refuses it.
//! - **The requester.** The daemon's own admitted local client of the
//!   pair: it asks with `from` the recording's current start and `until`
//!   `u64::MAX`, a fresh `correlation_id` per request.
//! - **The forwarder.** It republishes, byte for byte and in order, each
//!   message of the current request from the response stream on a
//!   reliable UDP publication to the replica, on the configured stream
//!   id, a fresh incarnation (session id) per request (decision 3, the
//!   epoch fence). While the publication refuses a message it keeps that
//!   one and stops reading, so the stall reaches the agent through the
//!   pair's bounded streams; output of an older request is discarded
//!   unread.
//!
//! Recovery is the source's (decision 7): an `interrupted` status is
//! forwarded and the request asked again from the current start after a
//! backoff of 1 s doubling to 60 s; a connection to the replica that comes
//! back after a loss and stays up 1 s restarts the request under the same
//! backoff; a daemon start asks from the current start. An interrupted
//! status whose start did not move is an interior gap: the replication
//! ends, alarmed, and is not retried. A stop forwards nothing more at
//! once, sends `StopReplication` on the pair, and waits until the agent
//! itself says the request is gone before a replacement starts.
//!
//! Trust fails closed (decision 10): a replication starts only with the
//! operator's `--replication-trusted-network`, on the trusted profile.

use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use karyos_archive::agent::{AgentError, ArchiveHandle, Posted};
use karyos_archive::control::{ControlMessage, ControlResponse, ResponseCode};
use karyos_archive::replication::transport::Outgoing;
use karyos_archive::replication::{
    self, RecordingBytes, ReplicateRecording, ReplicationMessage, ReplicationStatus, SourceSeal,
    State, StopReplication,
};
use karyos_client::{ClientPublication, ClientSubscription, MessageLimit, OfferOutcome};
use karyos_driver::embedded::{AggregateHandle, EmbeddedDriver, StreamHandle};
use karyos_driver::{AggregateConfig, DriverError};
use karyos_protocol::channel::{Destination, Security, UdpConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::Role;
use karyos_sys::term_bytes::SharedTerms;

use crate::args::{ReplicateOption, StreamOption, TermOptions};

/// The first backoff between two requests of a replication.
pub const BACKOFF_FIRST: Duration = Duration::from_secs(1);
/// The longest backoff.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// How long a connection to the replica stays up after a loss before the
/// request starts again.
pub const RECONNECT_SETTLE: Duration = Duration::from_secs(1);

/// The high 32 bits of the correlation ids of the daemon's replication
/// requests: distinct from its boot recordings'.
pub const REPLICATION_REQUESTER: u64 = 0xFFFF_FFFE << 32;

/// The longest message of the pair's streams: a full `RecordingBytes`.
const MAX_MESSAGE: usize = replication::RECORDING_BYTES.max_length as usize;

/// A `RecordingBytes` message's length beyond its bytes.
const RECORDING_BYTES_OVERHEAD: usize = MAX_MESSAGE - replication::MAX_CHUNK;

/// Agent messages the pair's server forwards per duty at most.
const FORWARD_PER_DUTY: usize = 8;

/// Why the replications did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicationStartError {
    /// A replication on a network the operator did not declare trusted
    /// (ADR-0102 decision 10).
    Untrusted,
    /// A stream of a replication was refused.
    Stream(DriverError),
}

impl std::fmt::Display for ReplicationStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Untrusted => write!(
                f,
                "replication refused: no --replication-trusted-network, and no authenticated \
                 profile is selected"
            ),
            Self::Stream(error) => write!(f, "replication stream refused: {error}"),
        }
    }
}

impl std::error::Error for ReplicationStartError {}

/// The replications' counters, for the operator.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplicationCounters {
    /// Requests asked, restarts included.
    pub requests: u64,
    /// Messages forwarded to replicas.
    pub forwarded: u64,
    /// Messages of an older request discarded unread.
    pub discarded: u64,
    /// Requests interrupted.
    pub interrupted: u64,
    /// Replications ended by an interior gap, alarmed and not retried.
    pub interior_gaps: u64,
    /// Requests the Archive refused.
    pub refused: u64,
}

/// Where a replication's request is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// No request: the next one is asked at `at`.
    Idle { at: Instant },
    /// A request is asked and forwarded.
    Streaming,
    /// A stop was decided: nothing more is forwarded; the next request
    /// waits for the agent to drop this one, then for `at`.
    Stopping { at: Instant },
    /// Done for good: caught up on demand, ended, or an interior gap.
    Ended,
}

/// The pair's server: the agent's side of the replication's own streams.
struct PairServer {
    requests: ClientSubscription<SharedTerms>,
    responses: ClientPublication<SharedTerms>,
    /// The request posted and not answered yet: its correlation id and
    /// recording.
    posted: Option<(u64, u64, Posted<Receiver<Outgoing>>)>,
    /// Stops posted, kept until answered.
    stops: Vec<Posted<()>>,
    /// The replication the agent serves: its correlation id, recording and
    /// messages.
    serving: Option<(u64, u64, Receiver<Outgoing>)>,
    /// One encoded message the response stream refused.
    held: Option<Vec<u8>>,
    request: Vec<u8>,
}

/// One authorized replication.
struct Replication {
    option: ReplicateOption,
    terms: TermOptions,
    server: PairServer,
    /// The requester's request stream.
    ask: ClientPublication<SharedTerms>,
    /// The requester's view of the response stream.
    answers: ClientSubscription<SharedTerms>,
    /// The forwarding publication's incarnation and handle.
    forward: Option<(AggregateHandle, ClientPublication<SharedTerms>)>,
    /// The next incarnation's session id.
    session: i32,
    /// The current request's correlation id; 0 for none.
    correlation_id: u64,
    next: u64,
    phase: Phase,
    backoff: Duration,
    /// The last start the source announced for this replication.
    start: Option<u64>,
    /// One message of the current request the publication refused.
    held: Option<Vec<u8>>,
    /// A request encoded and not offered yet on the pair.
    pending: Option<Vec<u8>>,
    /// The connection to the replica: whether it was lost, and since when
    /// it is back.
    lost: bool,
    back_since: Option<Instant>,
    /// The agent's answer to "is the stopped request still active".
    confirming: Option<Posted<bool>>,
    buf: Vec<u8>,
}

/// Every replication of a source daemon.
pub struct Replications {
    replications: Vec<Replication>,
    counters: ReplicationCounters,
    /// The streams the daemon adds, removed at shutdown.
    streams: Vec<StreamHandle>,
}

impl std::fmt::Debug for Replications {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replications")
            .field("replications", &self.replications.len())
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

/// The forwarding channel to `endpoint`: reliable unicast UDP on the
/// trusted profile.
#[must_use]
pub fn forward_channel(endpoint: SocketAddr) -> UdpConfig {
    UdpConfig {
        retransmit_window: None,
        nak_control: Vec::new(),
        linger: None,
        path_skew: None,
        destination: Destination::Unicast(endpoint),
        interface: None,
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    }
}

/// The correlation id of a schema 1 or schema 6 message, at the start of
/// its block; 0 when too short.
fn correlation_of(bytes: &[u8]) -> u64 {
    bytes
        .get(12..20)
        .and_then(|id| <[u8; 8]>::try_from(id).ok())
        .map_or(0, u64::from_le_bytes)
}

impl Replications {
    /// Adds each replication's pair to `driver` and readies it; the first
    /// requests are asked on the first duty.
    ///
    /// # Errors
    ///
    /// [`ReplicationStartError::Untrusted`] for any replication without
    /// `trusted_network`, and a refused stream.
    pub fn start(
        driver: &mut EmbeddedDriver<SharedTerms>,
        terms: &TermOptions,
        options: &[ReplicateOption],
        trusted_network: bool,
    ) -> Result<Self, ReplicationStartError> {
        if !options.is_empty() && !trusted_network {
            return Err(ReplicationStartError::Untrusted);
        }
        let mut replications = Self {
            replications: Vec::with_capacity(options.len()),
            counters: ReplicationCounters::default(),
            streams: Vec::new(),
        };
        let now = Instant::now();
        for option in options {
            let stream = |stream_id| {
                crate::daemon::stream_config(
                    terms,
                    StreamOption {
                        stream_id,
                        session_id: 0,
                        allow_unconnected: false,
                    },
                )
                .map_err(|_| ReplicationStartError::Stream(DriverError::InvalidConfig))
            };
            let mut responses_config = stream(option.responses)?;
            // An answer nobody reads is not held.
            responses_config.allow_unconnected = true;
            let requests = driver
                .add_stream(stream(option.requests)?)
                .map_err(ReplicationStartError::Stream)?;
            replications.streams.push(requests);
            let responses = driver
                .add_stream(responses_config)
                .map_err(ReplicationStartError::Stream)?;
            replications.streams.push(responses);
            let handle = ReplicationStartError::Stream;
            let server = PairServer {
                requests: driver.subscribe(requests, Role::Required).map_err(handle)?,
                responses: driver.publication(responses).map_err(handle)?,
                posted: None,
                stops: Vec::new(),
                serving: None,
                held: None,
                request: vec![0; MAX_MESSAGE],
            };
            replications.replications.push(Replication {
                option: *option,
                terms: *terms,
                server,
                ask: driver.publication(requests).map_err(handle)?,
                answers: driver
                    .subscribe(responses, Role::Required)
                    .map_err(handle)?,
                forward: None,
                session: 1,
                correlation_id: 0,
                next: 1,
                phase: Phase::Idle { at: now },
                backoff: BACKOFF_FIRST,
                start: None,
                held: None,
                pending: None,
                lost: false,
                back_since: None,
                confirming: None,
                buf: vec![0; MAX_MESSAGE],
            });
        }
        Ok(replications)
    }

    /// The counters.
    #[must_use]
    pub const fn counters(&self) -> ReplicationCounters {
        self.counters
    }

    /// The streams the daemon added, for their removal at shutdown.
    #[must_use]
    pub fn streams(&self) -> &[StreamHandle] {
        &self.streams
    }

    /// One duty of every replication; returns whether anything moved.
    pub fn duty(
        &mut self,
        agent: &ArchiveHandle,
        driver: &mut EmbeddedDriver<SharedTerms>,
    ) -> bool {
        let now = Instant::now();
        let mut worked = false;
        for replication in &mut self.replications {
            worked |= replication.server.duty(agent);
            worked |= replication.duty(agent, driver, now, &mut self.counters);
        }
        worked
    }

    /// Removes every forwarding publication; the pair's streams are the
    /// caller's to remove ([`Self::streams`]).
    pub fn shutdown(self, driver: &mut EmbeddedDriver<SharedTerms>) {
        for replication in self.replications {
            if let Some((aggregate, publication)) = replication.forward {
                drop(publication);
                let _ = driver.remove_aggregate(&aggregate);
            }
        }
    }
}

impl PairServer {
    /// Reads one request whatever output is pending, takes the agent's
    /// answer, and writes the agent's messages.
    fn duty(&mut self, agent: &ArchiveHandle) -> bool {
        let mut worked = false;
        let mut length = None;
        let request = &mut self.request;
        let _ = self.requests.poll(
            |bytes, _| {
                if let Some(into) = request.get_mut(..bytes.len()) {
                    into.copy_from_slice(bytes);
                    length = Some(bytes.len());
                }
            },
            MessageLimit::new(1),
        );
        if let Some(length) = length {
            worked = true;
            self.serve(agent, length);
        }
        self.stops.retain(|stop| stop.try_answer().is_none());
        if let Some((correlation_id, recording_id, posted)) = self.posted.take() {
            match posted.try_answer() {
                None => self.posted = Some((correlation_id, recording_id, posted)),
                Some(Ok(messages)) => {
                    worked = true;
                    self.serving = Some((correlation_id, recording_id, messages));
                }
                Some(Err(error)) => {
                    worked = true;
                    self.refuse(correlation_id, &error);
                }
            }
        }
        worked | self.forward()
    }

    fn serve(&mut self, agent: &ArchiveHandle, length: usize) {
        let bytes = self.request.get(..length).unwrap_or_default();
        match ReplicationMessage::decode(bytes) {
            Ok(ReplicationMessage::ReplicateRecording(request)) => {
                let chunk = usize::try_from(self.responses.max_message_length())
                    .unwrap_or(usize::MAX)
                    .min(MAX_MESSAGE)
                    .saturating_sub(RECORDING_BYTES_OVERHEAD);
                match agent.post_replicate(request, chunk) {
                    Ok(posted) => {
                        // A new request replaces what was served: its
                        // output is no longer read.
                        self.serving = None;
                        self.held = None;
                        self.posted = Some((request.correlation_id, request.recording_id, posted));
                    }
                    Err(error) => self.refuse(request.correlation_id, &error),
                }
            }
            Ok(ReplicationMessage::StopReplication(stop)) => {
                if let Ok(posted) = agent.post_stop_replication(stop) {
                    self.stops.push(posted);
                }
            }
            // Only the daemon's own requester writes this stream.
            _ => tracing::warn!(
                recording = ?bytes.len(),
                "replication pair request dropped: not a request"
            ),
        }
    }

    fn refuse(&mut self, correlation_id: u64, error: &AgentError) {
        let code = match error {
            AgentError::ReplicationRefused(refusal) => refusal.code(),
            _ => ResponseCode::Error,
        };
        let message = error.to_string();
        let response = ControlMessage::ControlResponse(ControlResponse {
            correlation_id,
            id: 0,
            code,
            message: message
                .get(
                    ..message
                        .len()
                        .min(karyos_archive::control::MAX_RESPONSE_MESSAGE),
                )
                .unwrap_or_default(),
        });
        let mut out = vec![0u8; MAX_MESSAGE];
        if let Ok(length) = response.encode(&mut out) {
            out.truncate(length);
            if self.held.is_none() {
                self.held = Some(out);
            }
        }
    }

    /// Writes the held message, then the agent's next messages, while the
    /// response stream takes them.
    fn forward(&mut self) -> bool {
        let mut worked = false;
        if let Some(held) = &self.held {
            if !matches!(
                self.responses.offer(held),
                Ok(OfferOutcome::Accepted { .. })
            ) {
                return worked;
            }
            self.held = None;
            worked = true;
        }
        let Some((correlation_id, recording_id, messages)) = &self.serving else {
            return worked;
        };
        let (correlation_id, recording_id) = (*correlation_id, *recording_id);
        for _ in 0..FORWARD_PER_DUTY {
            let message = match messages.try_recv() {
                Ok(message) => message,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.serving = None;
                    break;
                }
            };
            worked = true;
            let mut out = vec![0u8; MAX_MESSAGE];
            let Ok(length) = encode(correlation_id, recording_id, &message, &mut out) else {
                continue;
            };
            out.truncate(length);
            if !matches!(
                self.responses.offer(&out),
                Ok(OfferOutcome::Accepted { .. })
            ) {
                self.held = Some(out);
                break;
            }
        }
        worked
    }
}

/// `message` of the request `correlation_id`, encoded in schema 6.
fn encode(
    correlation_id: u64,
    recording_id: u64,
    message: &Outgoing,
    out: &mut [u8],
) -> Result<usize, karyos_codec::CodecError> {
    match message {
        Outgoing::Bytes { start, bytes } => ReplicationMessage::RecordingBytes(RecordingBytes {
            correlation_id,
            recording_id,
            start: *start,
            bytes,
        })
        .encode(out),
        Outgoing::Seal(seal) => ReplicationMessage::SourceSeal(SourceSeal {
            correlation_id,
            seal: *seal,
        })
        .encode(out),
        Outgoing::Status(status) => ReplicationMessage::ReplicationStatus(*status).encode(out),
        _ => Err(karyos_codec::CodecError::ValueOutOfRange { field: "message" }),
    }
}

impl Replication {
    fn duty(
        &mut self,
        agent: &ArchiveHandle,
        driver: &mut EmbeddedDriver<SharedTerms>,
        now: Instant,
        counters: &mut ReplicationCounters,
    ) -> bool {
        let mut worked = false;
        if let Some(pending) = &self.pending
            && matches!(self.ask.offer(pending), Ok(OfferOutcome::Accepted { .. }))
        {
            self.pending = None;
            worked = true;
        }
        match self.phase {
            Phase::Ended => {}
            Phase::Idle { at } => {
                if now >= at && self.pending.is_none() {
                    worked = true;
                    self.ask(agent, driver, counters);
                }
            }
            Phase::Stopping { at } => worked |= self.confirm(agent, driver, now, at),
            Phase::Streaming => worked |= self.relay(now, counters),
        }
        worked
    }

    /// Asks from the recording's current start, on a fresh incarnation.
    fn ask(
        &mut self,
        agent: &ArchiveHandle,
        driver: &mut EmbeddedDriver<SharedTerms>,
        counters: &mut ReplicationCounters,
    ) {
        let recording_id = self.option.recording_id;
        let from = match agent.describe(recording_id) {
            Ok(described) => described.recording.start,
            Err(error) => {
                tracing::warn!(recording_id, %error, "replication waits: recording not described");
                self.retry(Instant::now());
                return;
            }
        };
        // The previous incarnation is closed before the next one exists.
        if let Some((aggregate, publication)) = self.forward.take() {
            drop(publication);
            let _ = driver.remove_aggregate(&aggregate);
        }
        let session = self.session;
        self.session = self.session.wrapping_add(1).max(1);
        match self.open_forward(driver, session) {
            Ok(forward) => self.forward = Some(forward),
            Err(error) => {
                tracing::warn!(recording_id, %error, "replication publication refused");
                self.retry(Instant::now());
                return;
            }
        }
        let Some(next) = self
            .next
            .checked_add(1)
            .filter(|_| self.next <= u64::from(u32::MAX))
        else {
            tracing::error!(recording_id, "replication request ids exhausted");
            self.phase = Phase::Ended;
            return;
        };
        // A fresh correlation id per request: old output never passes
        // for the new request's.
        let correlation_id = REPLICATION_REQUESTER | self.next;
        self.next = next;
        self.correlation_id = correlation_id;
        self.held = None;
        self.start = None;
        self.lost = false;
        self.back_since = None;
        let request = ReplicateRecording {
            correlation_id,
            recording_id,
            from,
            until: u64::MAX,
            mode: self.option.mode,
        };
        let mut out = vec![0u8; MAX_MESSAGE];
        match request.encode(&mut out) {
            Ok(length) => {
                out.truncate(length);
                self.pending = Some(out);
                self.phase = Phase::Streaming;
                counters.requests = counters.requests.saturating_add(1);
                tracing::info!(
                    recording_id,
                    correlation_id,
                    from,
                    session,
                    stream_id = self.option.stream_id,
                    endpoint = %self.option.endpoint,
                    "replication requested"
                );
            }
            Err(error) => {
                tracing::error!(recording_id, %error, "replication request not encoded");
                self.phase = Phase::Ended;
            }
        }
    }

    fn open_forward(
        &self,
        driver: &mut EmbeddedDriver<SharedTerms>,
        session: i32,
    ) -> Result<(AggregateHandle, ClientPublication<SharedTerms>), DriverError> {
        let mut stream = crate::daemon::stream_config(
            &self.terms,
            StreamOption {
                stream_id: self.option.stream_id,
                session_id: session,
                allow_unconnected: false,
            },
        )
        .map_err(|_| DriverError::InvalidConfig)?;
        stream.allow_unconnected = false;
        let mtu = u64::from(stream.buffer.mtu);
        let config = AggregateConfig {
            stream,
            quanta: vec![mtu.saturating_add(31) / 32 * 32 * 4],
        };
        let aggregate =
            driver.add_network_publication(config, &forward_channel(self.option.endpoint))?;
        let lane = aggregate
            .lane(Lane::ZERO)
            .ok_or(DriverError::InvalidConfig)?;
        Ok((aggregate, driver.publication(lane)?))
    }

    /// The next request after the backoff, which doubles up to its cap.
    fn retry(&mut self, now: Instant) {
        self.phase = Phase::Idle {
            at: now.checked_add(self.backoff).unwrap_or(now),
        };
        self.backoff = self.backoff.saturating_mul(2).min(BACKOFF_MAX);
    }

    /// Decides a stop: nothing more is forwarded, the stop is sent on the
    /// pair, and the next request waits for the agent to drop this one.
    fn stop(&mut self, now: Instant) {
        self.held = None;
        let stop = StopReplication {
            correlation_id: self.correlation_id,
            recording_id: self.option.recording_id,
        };
        let mut out = vec![0u8; MAX_MESSAGE];
        if let Ok(length) = stop.encode(&mut out) {
            out.truncate(length);
            self.pending = Some(out);
        }
        let at = now.checked_add(self.backoff).unwrap_or(now);
        self.backoff = self.backoff.saturating_mul(2).min(BACKOFF_MAX);
        self.phase = Phase::Stopping { at };
    }

    /// Waits until the agent says the stopped request is gone, discarding
    /// what is left of it on the response stream, then for `at`.
    fn confirm(
        &mut self,
        agent: &ArchiveHandle,
        _driver: &mut EmbeddedDriver<SharedTerms>,
        now: Instant,
        at: Instant,
    ) -> bool {
        let mut discarded = 0u64;
        let _ = self
            .answers
            .poll(|_, _| discarded += 1, MessageLimit::new(64));
        if self.pending.is_some() {
            return discarded > 0;
        }
        match self.confirming.take() {
            None => {
                if let Ok(posted) = agent.post_replication_active(self.correlation_id) {
                    self.confirming = Some(posted);
                }
            }
            Some(posted) => match posted.try_answer() {
                None => self.confirming = Some(posted),
                Some(Ok(true)) => {}
                Some(Ok(false)) => {
                    self.phase = Phase::Idle { at: at.max(now) };
                    return true;
                }
                Some(Err(_)) => {}
            },
        }
        discarded > 0
    }

    /// Forwards the current request's messages while the publication
    /// takes them, and acts on its statuses and refusals.
    fn relay(&mut self, now: Instant, counters: &mut ReplicationCounters) -> bool {
        let mut worked = false;
        let Some((_, publication)) = self.forward.as_mut() else {
            return false;
        };
        if let Some(held) = &self.held {
            match publication.offer(held) {
                Ok(OfferOutcome::Accepted { .. }) => {
                    self.held = None;
                    counters.forwarded = counters.forwarded.saturating_add(1);
                    worked = true;
                    self.connected(now);
                }
                Ok(OfferOutcome::NotConnected) => {
                    self.lost = true;
                    self.back_since = None;
                    return worked;
                }
                _ => return worked,
            }
        }
        if self.lost
            && let Some(since) = self.back_since
            && now.saturating_duration_since(since) >= RECONNECT_SETTLE
        {
            tracing::info!(
                recording_id = self.option.recording_id,
                "replica connection back: replication asked again from the start"
            );
            self.stop(now);
            return true;
        }
        for _ in 0..FORWARD_PER_DUTY {
            let mut length = None;
            let buf = &mut self.buf;
            let _ = self.answers.poll(
                |bytes, _| {
                    if let Some(into) = buf.get_mut(..bytes.len()) {
                        into.copy_from_slice(bytes);
                        length = Some(bytes.len());
                    }
                },
                MessageLimit::new(1),
            );
            let Some(length) = length else {
                break;
            };
            worked = true;
            let buf = std::mem::take(&mut self.buf);
            let message = buf.get(..length).unwrap_or_default();
            let done = self.forward_one(message, now, counters);
            self.buf = buf;
            if done {
                break;
            }
        }
        worked
    }

    /// Forwards one message of the response stream; true when the relay
    /// stops for this duty (a held message, or a phase change).
    fn forward_one(
        &mut self,
        message: &[u8],
        now: Instant,
        counters: &mut ReplicationCounters,
    ) -> bool {
        if correlation_of(message) != self.correlation_id {
            counters.discarded = counters.discarded.saturating_add(1);
            return false;
        }
        let outcome = self.observe(message, now, counters);
        let Some((_, publication)) = self.forward.as_mut() else {
            return true;
        };
        match publication.offer(message) {
            Ok(OfferOutcome::Accepted { .. }) => {
                counters.forwarded = counters.forwarded.saturating_add(1);
                self.connected(now);
            }
            Ok(OfferOutcome::NotConnected) => {
                self.lost = true;
                self.back_since = None;
                self.held = Some(message.to_vec());
            }
            _ => self.held = Some(message.to_vec()),
        }
        if let Some(next) = outcome {
            self.phase = next;
            return true;
        }
        self.held.is_some()
    }

    fn connected(&mut self, now: Instant) {
        if self.lost && self.back_since.is_none() {
            self.back_since = Some(now);
        }
    }

    /// What a forwarded message of the current request changes: an end, a
    /// restart after an interruption, or a refusal.
    fn observe(
        &mut self,
        message: &[u8],
        now: Instant,
        counters: &mut ReplicationCounters,
    ) -> Option<Phase> {
        let recording_id = self.option.recording_id;
        if let Ok(ControlMessage::ControlResponse(response)) = ControlMessage::decode(message) {
            counters.refused = counters.refused.saturating_add(1);
            tracing::warn!(
                recording_id,
                code = ?response.code,
                message = response.message,
                "replication refused by the Archive: asked again after the backoff"
            );
            let at = now.checked_add(self.backoff).unwrap_or(now);
            self.backoff = self.backoff.saturating_mul(2).min(BACKOFF_MAX);
            return Some(Phase::Idle { at });
        }
        let Ok(ReplicationMessage::ReplicationStatus(status)) = ReplicationMessage::decode(message)
        else {
            return None;
        };
        self.status(&status, now, counters)
    }

    fn status(
        &mut self,
        status: &ReplicationStatus,
        now: Instant,
        counters: &mut ReplicationCounters,
    ) -> Option<Phase> {
        let recording_id = self.option.recording_id;
        let previous = self.start;
        match status.state {
            State::Streaming => {
                self.start = Some(status.source_start);
                // A request that streams resets the backoff only once its
                // connection held.
                if !self.lost {
                    self.backoff = BACKOFF_FIRST;
                }
                None
            }
            State::Interrupted => {
                counters.interrupted = counters.interrupted.saturating_add(1);
                if previous.is_some_and(|start| status.source_start <= start) {
                    // The store's start did not move: a gap inside the
                    // store, not a purge. It ends the replication.
                    counters.interior_gaps = counters.interior_gaps.saturating_add(1);
                    tracing::warn!(
                        recording_id,
                        sealed_end = status.sealed_end,
                        "replication interrupted by an interior gap at the source: ended, \
                         not retried"
                    );
                    return Some(Phase::Ended);
                }
                tracing::warn!(
                    recording_id,
                    source_start = status.source_start,
                    "replication interrupted: asked again from the current start after the \
                     backoff"
                );
                let at = now.checked_add(self.backoff).unwrap_or(now);
                self.backoff = self.backoff.saturating_mul(2).min(BACKOFF_MAX);
                Some(Phase::Stopping { at })
            }
            State::CaughtUp | State::Ended => {
                tracing::info!(recording_id, state = ?status.state, "replication done");
                Some(Phase::Ended)
            }
            State::Stopped => Some(Phase::Idle { at: now }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;
    use karyos_archive::replication::Mode;

    #[test]
    fn a_correlation_id_is_read_from_either_schema() {
        let mut out = [0u8; 64];
        let length = StopReplication {
            correlation_id: 0x1234,
            recording_id: 9,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(correlation_of(&out[..length]), 0x1234);
        assert_eq!(correlation_of(&[0u8; 4]), 0);
    }

    #[test]
    fn the_forwarding_channel_is_reliable_and_trusted() {
        let channel = forward_channel("127.0.0.1:4000".parse().unwrap());
        assert!(channel.reliable);
        assert_eq!(channel.security, Security::Trusted);
    }

    #[test]
    fn the_mode_round_trips_in_the_request() {
        let mut out = [0u8; 64];
        let request = ReplicateRecording {
            correlation_id: 1,
            recording_id: 1,
            from: 0,
            until: u64::MAX,
            mode: Mode::Continuous,
        };
        let length = request.encode(&mut out).unwrap();
        assert!(matches!(
            ReplicationMessage::decode(&out[..length]).unwrap(),
            ReplicationMessage::ReplicateRecording(decoded) if decoded == request
        ));
    }
}
