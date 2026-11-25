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
    /// The recording's current start is asked of the agent, posted: the
    /// duty never blocks on it.
    Describing,
    /// A request is asked and forwarded.
    Streaming,
    /// A stop was decided: nothing more is forwarded; the next request
    /// waits for the agent to drop this one, then for `at`.
    Stopping { at: Instant },
    /// Done for good: caught up on demand, ended, or an interior gap.
    Ended,
}

/// A stream that takes a message or refuses it for now.
trait Offer {
    /// Offers `message`; an error is a refusal.
    fn offer_message(&mut self, message: &[u8]) -> OfferOutcome;
}

impl Offer for ClientPublication<SharedTerms> {
    fn offer_message(&mut self, message: &[u8]) -> OfferOutcome {
        self.offer(message).unwrap_or(OfferOutcome::Closed)
    }
}

/// What offering a held message did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Offered {
    /// Nothing was held.
    Empty,
    /// Taken: the phase change it deferred, if any, applies now.
    Accepted(Option<Phase>),
    /// No receiver: still held.
    NotConnected,
    /// Refused for now: still held.
    Refused,
}

/// One message a stream refused, kept in a buffer allocated once for the
/// pair's life (global_rules.md, no allocation on a steady path), with the
/// phase change it defers: a phase moves only once the message that moved
/// it was taken.
struct Held {
    buf: Vec<u8>,
    length: Option<usize>,
    then: Option<Phase>,
}

impl Held {
    fn new() -> Self {
        Self {
            buf: vec![0; MAX_MESSAGE],
            length: None,
            then: None,
        }
    }

    const fn is_held(&self) -> bool {
        self.length.is_some()
    }

    /// Holds `message` and the phase change it defers; false when it does
    /// not fit, which no schema 1 or 6 message does.
    fn hold(&mut self, message: &[u8], then: Option<Phase>) -> bool {
        match self.buf.get_mut(..message.len()) {
            Some(into) => {
                into.copy_from_slice(message);
                self.length = Some(message.len());
                self.then = then;
                true
            }
            None => false,
        }
    }

    fn clear(&mut self) {
        self.length = None;
        self.then = None;
    }

    /// Offers the held message to `to`.
    fn offer(&mut self, to: &mut impl Offer) -> Offered {
        let Some(message) = self.length.and_then(|length| self.buf.get(..length)) else {
            return Offered::Empty;
        };
        match to.offer_message(message) {
            OfferOutcome::Accepted { .. } => {
                let then = self.then;
                self.clear();
                Offered::Accepted(then)
            }
            OfferOutcome::NotConnected => Offered::NotConnected,
            _ => Offered::Refused,
        }
    }
}

/// Retries a stop the agent refused as busy, until it is posted or the
/// agent is gone: a stop is never dropped (ADR-0102 decision 3).
fn retry_stop<P>(
    wanted: &mut Option<StopReplication>,
    posted: &mut Vec<P>,
    post: impl FnOnce(StopReplication) -> Result<P, AgentError>,
) {
    let Some(stop) = *wanted else {
        return;
    };
    match post(stop) {
        Ok(answer) => {
            posted.push(answer);
            *wanted = None;
        }
        Err(AgentError::Busy) => {}
        Err(error) => {
            tracing::warn!(%error, "replication stop not posted: the agent is gone");
            *wanted = None;
        }
    }
}

/// Whether an `interrupted` status starting at `source_start` is an
/// interior gap: the store's start did not move above `baseline`, the
/// request's `from` or the last streaming start. A purge moves it up.
const fn is_interior_gap(baseline: u64, source_start: u64) -> bool {
    source_start <= baseline
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
    /// A stop the agent refused as busy, retried each duty.
    stop_wanted: Option<StopReplication>,
    /// The replication the agent serves: its correlation id, recording and
    /// messages.
    serving: Option<(u64, u64, Receiver<Outgoing>)>,
    /// One encoded message the response stream refused.
    held: Held,
    request: Vec<u8>,
    /// The encoding buffer, reused for every message.
    out: Vec<u8>,
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
    phase: Phase,
    backoff: Duration,
    /// Where the store started for the current request: its `from`, then
    /// each streaming status's start.
    start: u64,
    /// One message of the current request the publication refused.
    held: Held,
    /// The agent's answer to the recording's description.
    describing: Option<Posted<karyos_archive::agent::Described>>,
    /// A request encoded and not offered yet on the pair.
    pending: Option<Vec<u8>>,
    /// The connection to the replica: whether it was lost, and since when
    /// it is back.
    lost: bool,
    back_since: Option<Instant>,
    /// The current incarnation reached the replica once: a refusal for no
    /// receiver before that is the join, not a loss.
    joined: bool,
    /// The current request's first `streaming` status was forwarded.
    streamed: bool,
    /// The agent's answer to "is the stopped request still active".
    confirming: Option<Posted<bool>>,
    buf: Vec<u8>,
}

/// Every replication of a source daemon.
pub struct Replications {
    replications: Vec<Replication>,
    /// The next request number, daemon wide: no two requests share a
    /// correlation id, which the agent's active query matches alone.
    next: u64,
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
        etf: None,
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
            next: 1,
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
                stop_wanted: None,
                serving: None,
                held: Held::new(),
                request: vec![0; MAX_MESSAGE],
                out: vec![0; MAX_MESSAGE],
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
                phase: Phase::Idle { at: now },
                backoff: BACKOFF_FIRST,
                start: 0,
                held: Held::new(),
                describing: None,
                pending: None,
                lost: false,
                back_since: None,
                joined: false,
                streamed: false,
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
            worked |= replication.duty(agent, driver, now, &mut self.next, &mut self.counters);
        }
        worked
    }

    /// Removes every forwarding publication; the pair's streams are the
    /// caller's to remove ([`Self::streams`]).
    pub fn shutdown(self, driver: &mut EmbeddedDriver<SharedTerms>) {
        if !self.replications.is_empty() {
            tracing::info!(counters = ?self.counters, "replications stopped");
        }
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
        retry_stop(&mut self.stop_wanted, &mut self.stops, |stop| {
            agent.post_stop_replication(stop)
        });
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
                        self.held.clear();
                        self.posted = Some((request.correlation_id, request.recording_id, posted));
                    }
                    Err(error) => self.refuse(request.correlation_id, &error),
                }
            }
            Ok(ReplicationMessage::StopReplication(stop)) => {
                self.stop_wanted = Some(stop);
                retry_stop(&mut self.stop_wanted, &mut self.stops, |stop| {
                    agent.post_stop_replication(stop)
                });
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
        if let Ok(length) = response.encode(&mut self.out)
            && !self.held.is_held()
        {
            let _ = self
                .held
                .hold(self.out.get(..length).unwrap_or_default(), None);
        }
    }

    /// Writes the held message, then the agent's next messages, while the
    /// response stream takes them.
    fn forward(&mut self) -> bool {
        let mut worked = false;
        match self.held.offer(&mut self.responses) {
            Offered::Empty => {}
            Offered::Accepted(_) => worked = true,
            Offered::NotConnected | Offered::Refused => return worked,
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
            let Ok(length) = encode(correlation_id, recording_id, &message, &mut self.out) else {
                continue;
            };
            let encoded = self.out.get(..length).unwrap_or_default();
            if !matches!(
                self.responses.offer_message(encoded),
                OfferOutcome::Accepted { .. }
            ) {
                let _ = self.held.hold(encoded, None);
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
        next: &mut u64,
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
                    self.describe(agent, now);
                }
            }
            Phase::Describing => worked |= self.described(driver, now, next, counters),
            Phase::Stopping { at } => worked |= self.confirm(agent, driver, now, at),
            Phase::Streaming => worked |= self.relay(now, counters),
        }
        worked
    }

    /// Posts the recording's description: its current start.
    fn describe(&mut self, agent: &ArchiveHandle, now: Instant) {
        match agent.post_describe(self.option.recording_id) {
            Ok(posted) => {
                self.describing = Some(posted);
                self.phase = Phase::Describing;
            }
            // Busy: asked again on the next duty.
            Err(AgentError::Busy) => {}
            Err(error) => {
                tracing::warn!(
                    recording_id = self.option.recording_id,
                    %error,
                    "replication waits: recording not described"
                );
                self.retry(now);
            }
        }
    }

    /// Takes the description once the agent answered, then asks.
    fn described(
        &mut self,
        driver: &mut EmbeddedDriver<SharedTerms>,
        now: Instant,
        next: &mut u64,
        counters: &mut ReplicationCounters,
    ) -> bool {
        let Some(posted) = self.describing.take() else {
            self.retry(now);
            return true;
        };
        match posted.try_answer() {
            None => {
                self.describing = Some(posted);
                false
            }
            Some(Ok(described)) => {
                self.ask(driver, described.recording.start, next, counters);
                true
            }
            Some(Err(error)) => {
                tracing::warn!(
                    recording_id = self.option.recording_id,
                    %error,
                    "replication waits: recording not described"
                );
                self.retry(now);
                true
            }
        }
    }

    /// Asks from the recording's current start, `from`, on a fresh
    /// incarnation.
    fn ask(
        &mut self,
        driver: &mut EmbeddedDriver<SharedTerms>,
        from: u64,
        next: &mut u64,
        counters: &mut ReplicationCounters,
    ) {
        let recording_id = self.option.recording_id;
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
        let Some(following) = next.checked_add(1).filter(|_| *next <= u64::from(u32::MAX)) else {
            tracing::error!(recording_id, "replication request ids exhausted");
            self.phase = Phase::Ended;
            return;
        };
        // A fresh correlation id per request: old output never passes
        // for the new request's.
        let correlation_id = REPLICATION_REQUESTER | *next;
        *next = following;
        self.correlation_id = correlation_id;
        self.held.clear();
        // The baseline an interior gap is told by: the request's start.
        self.start = from;
        self.lost = false;
        self.back_since = None;
        self.joined = false;
        self.streamed = false;
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
        self.held.clear();
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
        match self.held.offer(publication) {
            Offered::Empty => {}
            Offered::Accepted(then) => {
                counters.forwarded = counters.forwarded.saturating_add(1);
                worked = true;
                self.connected(now);
                // The change the held message deferred applies now.
                if let Some(then) = then {
                    self.phase = then;
                    return true;
                }
            }
            Offered::NotConnected => {
                self.lose();
                self.back_since = None;
                return worked;
            }
            Offered::Refused => return worked,
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
        match publication.offer_message(message) {
            OfferOutcome::Accepted { .. } => {
                counters.forwarded = counters.forwarded.saturating_add(1);
                self.connected(now);
            }
            refused => {
                if refused == OfferOutcome::NotConnected {
                    self.lose();
                    self.back_since = None;
                }
                // Held with the phase change it moves: an end or a restart
                // waits until the replica has the message.
                let _ = self.held.hold(message, outcome);
                return true;
            }
        }
        if let Some(next) = outcome {
            self.phase = next;
            return true;
        }
        false
    }

    /// The publication found no receiver: a loss once the incarnation
    /// had reached the replica, before that only its join.
    fn lose(&mut self) {
        if self.joined && !self.lost {
            tracing::info!(
                recording_id = self.option.recording_id,
                endpoint = %self.option.endpoint,
                "replica connection lost"
            );
        }
        self.lost |= self.joined;
    }

    fn connected(&mut self, now: Instant) {
        self.joined = true;
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
        match status.state {
            State::Streaming => {
                if !self.streamed {
                    self.streamed = true;
                    tracing::info!(
                        recording_id,
                        source_start = status.source_start,
                        sealed_end = status.sealed_end,
                        "replication streaming"
                    );
                }
                self.start = status.source_start;
                // A request that streams resets the backoff only once its
                // connection held.
                if !self.lost {
                    self.backoff = BACKOFF_FIRST;
                }
                None
            }
            State::Interrupted => {
                counters.interrupted = counters.interrupted.saturating_add(1);
                if is_interior_gap(self.start, status.source_start) {
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

    /// A stream refusing until told otherwise.
    struct Sink {
        take: bool,
        taken: Vec<Vec<u8>>,
    }

    impl Offer for Sink {
        fn offer_message(&mut self, message: &[u8]) -> OfferOutcome {
            if self.take {
                self.taken.push(message.to_vec());
                OfferOutcome::Accepted {
                    lane: Lane::ZERO,
                    position: 0,
                }
            } else {
                OfferOutcome::BackPressured
            }
        }
    }

    /// Codex P1 1: a held `caught_up`, `ended` or `interrupted` is offered
    /// again until taken, and only then moves the phase.
    #[test]
    fn a_held_end_moves_the_phase_only_once_taken() {
        let mut held = Held::new();
        let mut sink = Sink {
            take: false,
            taken: Vec::new(),
        };
        assert_eq!(held.offer(&mut sink), Offered::Empty);
        assert!(held.hold(b"ended", Some(Phase::Ended)));
        assert_eq!(held.offer(&mut sink), Offered::Refused);
        assert_eq!(held.offer(&mut sink), Offered::Refused);
        assert!(held.is_held());
        sink.take = true;
        assert_eq!(held.offer(&mut sink), Offered::Accepted(Some(Phase::Ended)));
        assert_eq!(sink.taken, vec![b"ended".to_vec()]);
        assert_eq!(held.offer(&mut sink), Offered::Empty);
        // The buffer is the pair's own: holding never grows it.
        let capacity = held.buf.capacity();
        assert!(held.hold(&[7; MAX_MESSAGE], None));
        assert_eq!(held.buf.capacity(), capacity);
        assert!(!held.hold(&vec![7; MAX_MESSAGE + 1], None));
    }

    /// Codex P1 2: a stop the agent refuses as busy is kept and posted on
    /// a later duty; one for an agent that is gone is dropped.
    #[test]
    fn a_busy_stop_is_retried_until_posted() {
        let stop = StopReplication {
            correlation_id: 3,
            recording_id: 9,
        };
        let mut wanted = Some(stop);
        let mut posted: Vec<StopReplication> = Vec::new();
        retry_stop(&mut wanted, &mut posted, |_| Err(AgentError::Busy));
        assert_eq!(wanted, Some(stop));
        assert!(posted.is_empty());
        retry_stop(&mut wanted, &mut posted, Ok);
        assert_eq!(wanted, None);
        assert_eq!(posted, vec![stop]);
        let mut wanted = Some(stop);
        retry_stop(&mut wanted, &mut posted, |_| Err(AgentError::Gone));
        assert_eq!(wanted, None);
    }

    /// Codex P2 5: an interruption on the first status, with the store's
    /// start still the request's `from`, is an interior gap; a purge moves
    /// the start up.
    #[test]
    fn an_interior_gap_is_told_from_the_requests_start() {
        assert!(is_interior_gap(100, 100));
        assert!(is_interior_gap(100, 40));
        assert!(!is_interior_gap(100, 101));
    }

    /// Codex P1 3: the recording's start is posted, never waited for in
    /// the duty: the first answer may not be there yet.
    #[test]
    fn the_recording_is_described_without_blocking() {
        let dir =
            std::env::temp_dir().join(format!("karyosd-repl-describe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let agent = ArchiveHandle::spawn(
            karyos_archive::disk::StdDisk,
            &dir,
            karyos_archive::agent::AgentConfig::default(),
        )
        .unwrap();
        let posted = agent.post_describe(42).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let answer = loop {
            if let Some(answer) = posted.try_answer() {
                break answer;
            }
            assert!(Instant::now() < deadline, "no answer");
            std::thread::yield_now();
        };
        assert!(answer.is_err(), "an unknown recording is not described");
        agent.shutdown().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
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
