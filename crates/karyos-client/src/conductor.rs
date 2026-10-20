// SPDX-License-Identifier: Apache-2.0

//! The client conductor (SPEC.md §3; quantstratum-docs: karyos/design/client-commands.md):
//! writes commands to the client's command ring, reads driver responses
//! from the broadcast buffer, and turns ready capabilities into handles.
//!
//! Requests are identified by a checked, never reused sequence. A request
//! whose response may have been lost (the receiver was lapped, the
//! broadcast closed or the driver dropped) completes as
//! [`Outcome::Unknown`], terminally: it is never retried automatically, and
//! a late response for it is ignored.
//!
//! Client counters (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Client counters") are
//! requested with [`ClientConductor::allocate_counter`] and complete as
//! [`Outcome::Counter`]. A released or dropped counter queues its release,
//! which the next [`ClientConductor::poll`] sends as `ReleaseCounter`; that
//! request is the conductor's own and never reported.
//!
//! Loss reports (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Loss reports from clients"):
//! each poll sends the reports its subscriptions queued ([`crate::loss`]) as
//! `ReportLoss`, in order, while the ring and the pending bound take them;
//! the rest wait for a later poll. These requests are the conductor's own
//! and never reported. Reports dropped because the queue was full are
//! counted locally ([`ClientConductor::loss_reports_dropped`]) and mirrored
//! into the client counter `loss reports dropped` (kind client), which the
//! conductor allocates for itself with one `AllocateCounter` at the first
//! drop, so a client that never drops a report holds no cell of its
//! `max_counters_per_client`. If that allocation is refused or its outcome
//! is unknown, the conductor keeps counting locally and does not ask again;
//! nothing ever waits for it.
//!
//! Trace journals (`quantstratum-docs: karyos/design/trace-journal-region.md`;
//! [`crate::journal`]) are requested with [`ClientConductor::trace_journal`]
//! and complete as [`Outcome::Journal`], or as [`Outcome::FetchableJournal`]
//! for a remote client; [`ClientConductor::close_journal`] gives a journal's
//! final delivery boundary and completes as [`Outcome::Succeeded`].

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use karyos_protocol::cnc::{
    ChannelUri, Command, CounterLabel, Event, MAX_COMMAND_LENGTH, Response, StreamKey,
    SubscriberRole,
};
use karyos_protocol::cnc::{CutoverState, ErrorCode};
use karyos_sys::broadcast::{BroadcastReceiver, Received};
use karyos_sys::command_ring::{RingError, RingProducer};
use karyos_sys::counters::ClientCells;
use karyos_sys::frame::Lane;
use karyos_sys::record_journal::JournalLayout;
use karyos_sys::term_bytes::{HeapTerms, TermBytes};
use thiserror::Error;

use crate::concurrent::ClientConcurrentPublication;
use crate::counter::{ClientCounterHandle, Release};
use crate::generation::GenerationLink;
use crate::journal::{ClientJournal, FetchableJournal};
use crate::link::{Capability, ClientLink, Origin, Owner};
use crate::loss::LossReporter;
use crate::publication::ClientPublication;
use crate::subscription::ClientSubscription;

/// Errors submitting a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConductorError {
    /// The command ring has no room; retry after the driver drains it.
    #[error("command ring full")]
    Full,
    /// The client or the driver is closed.
    #[error("client or driver closed")]
    Closed,
    /// The pending request limit is reached.
    #[error("too many pending requests")]
    TooManyPending,
    /// Request sequences are exhausted.
    #[error("request sequences exhausted")]
    SequencesExhausted,
    /// The handle was not issued through this conductor.
    #[error("the handle belongs to another client")]
    ForeignHandle,
    /// A counter label is longer than 64 bytes.
    #[error("counter label longer than 64 bytes")]
    LabelTooLong,
    /// Journal sizes the driver would refuse to decode (a capacity that is
    /// not a nonzero power of two, no payload word or no drop range), or
    /// journal number 0.
    #[error("invalid trace journal request")]
    InvalidJournal,
    /// A channel URI is longer than the 512 bytes a command carries
    /// (`karyos_protocol::cnc::MAX_COMMAND_URI`, SPEC §18).
    #[error("channel URI longer than 512 bytes")]
    UriTooLong,
    /// A channel URI is empty.
    #[error("empty channel URI")]
    EmptyUri,
    /// A channel URI does not parse; `code` is the parse error's code
    /// (`karyos_protocol::channel::ChannelError::code`).
    #[error("invalid channel URI (code {code})")]
    InvalidChannel {
        /// The parse error's code.
        code: u64,
    },
    /// The command ring cannot carry the command: it is smaller than the
    /// driver's minimum (`DriverConfig::ring_capacity`).
    #[error("command larger than the command ring carries")]
    CommandTooLarge,
    /// A guard reopen names an epoch that cannot be closed: 0, an even
    /// (open) epoch, or one above `karyos_sys::guard::MAX_EPOCH`.
    #[error("not a closed guard epoch")]
    InvalidGuardEpoch,
}

/// The channel URI `uri` for a command: it parses (SPEC §5) and fits.
/// Also whether it names an IPC channel.
fn channel_uri(uri: &str) -> Result<(ChannelUri, bool), ConductorError> {
    if uri.is_empty() {
        return Err(ConductorError::EmptyUri);
    }
    if uri.len() > karyos_protocol::cnc::MAX_COMMAND_URI {
        return Err(ConductorError::UriTooLong);
    }
    let channel = karyos_protocol::channel::ChannelConfig::parse(uri)
        .map_err(|error| ConductorError::InvalidChannel { code: error.code() })?;
    let ipc = matches!(channel.media, karyos_protocol::channel::Media::Ipc);
    Ok((ChannelUri::new(uri).ok_or(ConductorError::UriTooLong)?, ipc))
}

/// How a request ended.
#[derive(Debug)]
#[non_exhaustive]
pub enum Outcome<T: TermBytes = HeapTerms> {
    /// The publication, ready to offer.
    Publication(ClientPublication<T>),
    /// A concurrent publication handle, ready to offer.
    ConcurrentPublication(ClientConcurrentPublication<T>),
    /// The subscription, ready to poll.
    Subscription(ClientSubscription<T>),
    /// A remote client's grant, answered with its hand-over key: the
    /// client takes it with `RemoteClient::take_publication`,
    /// `take_concurrent_publication` or `take_subscription`
    /// (`quantstratum-docs: karyos/design/ipc-data-path.md`, The client).
    Fetchable(Fetchable),
    /// A client counter, ready to update.
    Counter(ClientCounterHandle),
    /// A trace journal, ready to append.
    Journal(ClientJournal),
    /// A remote client's trace journal, answered with its hand-over key:
    /// the client takes it with `RemoteClient::take_journal`.
    FetchableJournal(FetchableJournal),
    /// A remote client's view of a conflated stream's table, answered with
    /// its hand-over key and the table's configuration
    /// (`quantstratum-docs: karyos/design/conflation-end-to-end.md`,
    /// Cross-process views).
    FetchableConflated(FetchableConflated),
    /// A network subscription (W5): the driver announces each of its
    /// images with `ImageAvailable` naming `registration`, the image's
    /// aggregate registration and its source. A subscriber attaches to an
    /// image by its registration with `AddImageSubscription`, as the
    /// client facade does, or with [`ClientConductor::add_subscription`]
    /// naming the alias, which reaches the oldest live image of it
    /// (`quantstratum-docs: karyos/design/per-source-images.md`, D2-2).
    NetworkSubscription {
        /// The network subscription's registration.
        registration: u64,
    },
    /// A guard's word after a guard close or reopen (M10).
    GuardState {
        /// The guard id.
        guard: u64,
        /// Its state after the transition.
        state: karyos_sys::guard::GuardState,
    },
    /// The command succeeded.
    Succeeded,
    /// The driver refused the command; it had no effect.
    Refused {
        /// Why.
        code: ErrorCode,
        /// A bounded detail value.
        detail: u64,
    },
    /// The response may have been lost; the command may or may not have
    /// taken effect. Terminal.
    Unknown,
}

impl<T: TermBytes> Outcome<T> {
    /// Attaches a generation link to a delivered handle. A base the handle
    /// refuses would be a driver defect: the handle is dropped and the
    /// outcome is not known.
    fn with_generation(self, link: Arc<GenerationLink<T>>, base: u64) -> Self {
        let attached = match self {
            Self::Publication(handle) => handle.with_generation(link, base).map(Self::Publication),
            Self::ConcurrentPublication(handle) => handle
                .with_generation(link, base)
                .map(Self::ConcurrentPublication),
            Self::Subscription(handle) => {
                handle.with_generation(link, base).map(Self::Subscription)
            }
            other => Ok(other),
        };
        attached.unwrap_or(Self::Unknown)
    }
}

/// What a request asked for, kept per request sequence: the handle needs
/// it and neither the response nor the wire record carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Request {
    /// The stream's exclusive publication.
    Publication {
        /// The stream.
        stream: StreamKey,
        /// The lane of the stream's aggregate.
        lane: Lane,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
    },
    /// A concurrent publication handle.
    ConcurrentPublication {
        /// The stream.
        stream: StreamKey,
        /// The lane of the stream's aggregate.
        lane: Lane,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
    },
    /// A subscription.
    Subscription {
        /// The stream.
        stream: StreamKey,
        /// The lane of the stream's aggregate.
        lane: Lane,
        /// Its role.
        role: SubscriberRole,
    },
    /// A remote client's view of a conflated stream's table.
    ConflatedSubscription {
        /// The stream.
        stream: StreamKey,
    },
}

impl Request {
    /// The stream requested.
    #[must_use]
    pub fn stream(&self) -> StreamKey {
        match *self {
            Self::Publication { stream, .. }
            | Self::ConcurrentPublication { stream, .. }
            | Self::Subscription { stream, .. }
            | Self::ConflatedSubscription { stream } => stream,
        }
    }

    /// The request with `session_id` in its stream: a request by channel
    /// URI names none, so a grant's carries it.
    #[must_use]
    pub fn with_session(mut self, session_id: i32) -> Self {
        match &mut self {
            Self::Publication { stream, .. }
            | Self::ConcurrentPublication { stream, .. }
            | Self::Subscription { stream, .. }
            | Self::ConflatedSubscription { stream } => stream.session_id = session_id,
        }
        self
    }

    /// The lane requested; a conflated view names none.
    #[must_use]
    pub fn lane(&self) -> Option<Lane> {
        match *self {
            Self::Publication { lane, .. }
            | Self::ConcurrentPublication { lane, .. }
            | Self::Subscription { lane, .. } => Some(lane),
            Self::ConflatedSubscription { .. } => None,
        }
    }
}

/// A remote client's grant, ready to fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Fetchable {
    /// The hand-over key of the response, which the fetch names.
    pub key: u64,
    /// The registration the response answered.
    pub registration: u64,
    /// What was requested.
    pub request: Request,
    /// The request named its stream by channel URI (W7): the driver chose
    /// the stream, so the request's session id is not known and the
    /// grant's is taken.
    pub by_uri: bool,
}

/// A remote client's view of a conflated stream's table, ready to fetch.
/// The configuration is the driver's answer: a view checks it against its
/// own limits before it maps anything, then requires it of the region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FetchableConflated {
    /// The hand-over key of the response, which the fetch names.
    pub key: u64,
    /// The registration the response answered.
    pub registration: u64,
    /// The stream requested.
    pub stream: StreamKey,
    /// The table's key count.
    pub keys: u32,
    /// The table's value capacity in bytes.
    pub value_capacity: u64,
    /// The table's journal capacity in bytes.
    pub journal_capacity: u64,
}

/// A completed request.
#[derive(Debug)]
#[non_exhaustive]
pub struct Completion<T: TermBytes = HeapTerms> {
    /// The request sequence returned when it was submitted.
    pub sequence: u64,
    /// How it ended.
    pub outcome: Outcome<T>,
}

/// What one [`ClientConductor::poll`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ConductorPoll {
    /// Broadcast records read, including other clients' responses and lap
    /// reports.
    pub records: usize,
    /// Whether the poll observed `Pending`: a complete drain.
    pub drained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    AddPublication,
    AddConcurrentPublication,
    AddSubscription,
    AddNetworkSubscription,
    /// A remote client's view of a conflated stream's table.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    AddConflatedSubscription,
    Remove,
    AllocateCounter,
    /// The conductor's own `ReleaseCounter`: never reported.
    ReleaseCounter,
    /// The conductor's own `ReportLoss`: never reported.
    ReportLoss,
    /// The conductor's own `AllocateCounter` of `loss reports dropped`:
    /// never reported.
    DroppedCounter,
    TraceJournal,
    CloseJournal,
    /// A remote client's `QueryCutover` after a lap: never reported.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    QueryCutover,
    /// A guard close or reopen (M10).
    Guard,
}

impl Kind {
    /// Whether the request is the conductor's own, never reported.
    fn internal(self) -> bool {
        matches!(
            self,
            Self::ReleaseCounter | Self::ReportLoss | Self::DroppedCounter | Self::QueryCutover
        )
    }
}

/// Label of the client counter of loss reports dropped.
pub const LOSS_REPORTS_DROPPED: &str = "loss reports dropped";

/// The client counter `loss reports dropped`, allocated at the first drop.
#[derive(Debug)]
enum DroppedCounter {
    /// No report was dropped yet, or the request is still to be sent.
    NotRequested,
    /// `AllocateCounter` was sent.
    Requested,
    /// The cell, and the drops already added to it.
    Allocated(ClientCounterHandle, u64),
    /// The allocation was refused or its outcome is unknown: the count
    /// stays local.
    Unavailable,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    sequence: u64,
    kind: Kind,
    /// What an `Add*` asked for; `None` for a remove.
    request: Option<Request>,
    /// The sizes a `TraceJournal` asked for.
    journal: Option<JournalLayout>,
    /// The request named its stream by channel URI.
    by_uri: bool,
}

/// A client's conductor (not `Clone`). Dropping it closes the client: the
/// command ring producer is dropped first, then the close flag is set.
#[derive(Debug)]
pub struct ClientConductor<T: TermBytes = HeapTerms> {
    owner: Owner,
    producer: Option<RingProducer>,
    receiver: BroadcastReceiver,
    link: Arc<ClientLink<T>>,
    next_sequence: u64,
    pending: Vec<Pending>,
    /// Requests already terminalized as `Unknown` whose notification has
    /// not been delivered yet. A notification leaves this queue only after
    /// its callback returns, so a panicking callback loses none.
    unknown: VecDeque<u64>,
    max_pending: usize,
    /// Liveness (quantstratum-docs:
    /// `karyos/design/required-participant-loss.md`), on this client's own
    /// monotonic clock: how often it advances its heartbeat, and how long
    /// the driver's may stay unchanged before the driver is presumed lost.
    heartbeat_interval: Duration,
    driver_timeout: Duration,
    last_beat: Option<Instant>,
    /// The driver heartbeat last seen and when it was first seen.
    driver_seen: Option<(u64, Instant)>,
    driver_lost: bool,
    /// Driver events received and not yet taken, at most [`EVENT_QUEUE`].
    events: VecDeque<Event>,
    /// Events dropped because the queue was full.
    events_dropped: u64,
    /// Event records that did not decode (see `events_undecoded`).
    events_undecoded: u64,
    /// A client of a driver in another process: its grants complete as
    /// [`Outcome::Fetchable`], never through the in-process hand-over.
    remote: bool,
    /// A remote client's cutover events (`SuccessorReady`, `Fenced`,
    /// `PublicationClosed`), kept for its control path whatever the
    /// application does with its own queue.
    cutover_events: Vec<Event>,
    /// A remote client fell a lap behind the broadcast buffer since its
    /// control path last asked: cutover events may be lost.
    lapped: bool,
    /// Laps of the broadcast receiver, for every client: what was
    /// broadcast meanwhile, events included, is lost.
    laps: u64,
    /// The writer view of the driver's client counters region; `None`
    /// when the driver gave none, and allocated counters then complete as
    /// `Unknown`.
    cells: Option<ClientCells>,
    /// The client counter `loss reports dropped`.
    dropped_counter: DroppedCounter,
    /// A remote client's admission session, which each counter handle
    /// keeps; dropped after `cells`.
    session: Option<Arc<dyn core::any::Any + Send + Sync>>,
}

/// Driver events a client keeps until the application takes them.
pub const EVENT_QUEUE: usize = 64;

/// Default heartbeat interval of a client.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(100);
/// Default time a client waits for the driver's heartbeat to change.
pub const DEFAULT_DRIVER_TIMEOUT: Duration = Duration::from_secs(10);

impl<T: TermBytes> ClientConductor<T> {
    /// Creates the conductor for an admitted client (called by the driver,
    /// control path: allocates the pending list).
    #[must_use]
    pub fn new(
        owner: Owner,
        producer: RingProducer,
        receiver: BroadcastReceiver,
        link: Arc<ClientLink<T>>,
        max_pending: usize,
    ) -> Self {
        Self {
            owner,
            producer: Some(producer),
            receiver,
            link,
            next_sequence: 1,
            pending: Vec::with_capacity(max_pending),
            unknown: VecDeque::with_capacity(max_pending),
            max_pending,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            driver_timeout: DEFAULT_DRIVER_TIMEOUT,
            last_beat: None,
            driver_seen: None,
            driver_lost: false,
            events: VecDeque::with_capacity(EVENT_QUEUE),
            events_dropped: 0,
            events_undecoded: 0,
            remote: false,
            cutover_events: Vec::new(),
            lapped: false,
            laps: 0,
            cells: None,
            dropped_counter: DroppedCounter::NotRequested,
            session: None,
        }
    }

    /// The same conductor with the writer view of the driver's client
    /// counters region, from which it builds the counters it is allocated.
    #[must_use]
    pub fn with_counters(mut self, cells: ClientCells) -> Self {
        self.cells = Some(cells);
        self
    }

    /// Keeps a remote client's admission session in every counter handle,
    /// so that `Leave` is not sent while one lives.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn set_session(&mut self, session: Arc<dyn core::any::Any + Send + Sync>) {
        self.session = Some(session);
    }

    /// Marks this conductor as a remote client's.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn set_remote(&mut self) {
        self.remote = true;
    }

    /// A remote client's cutover events received since the last call,
    /// oldest first (control path).
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn take_cutover_events(&mut self) -> Vec<Event> {
        core::mem::take(&mut self.cutover_events)
    }

    /// Laps of the broadcast receiver so far: each lost what was broadcast
    /// meanwhile, events included. At its end the count keeps its value.
    #[must_use]
    pub fn laps(&self) -> u64 {
        self.laps
    }

    /// Whether a lap happened since the last call (a remote client's
    /// control path then asks about each live registration).
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn take_lapped(&mut self) -> bool {
        core::mem::take(&mut self.lapped)
    }

    /// Asks again at the next lap check, when a query could not be sent.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn mark_lapped(&mut self) {
        self.lapped = true;
    }

    /// Asks the driver for the cutover state of `registration`
    /// (`quantstratum-docs: karyos/design/ipc-data-path.md`, "Resync after
    /// a lap"). The answer is the conductor's own: a fenced or closed
    /// registration becomes a `Fenced` cutover event for the control path,
    /// and a reserved successor arrives as the `SuccessorReady` the driver
    /// emits again before it.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn query_cutover(&mut self, registration: u64) -> Result<u64, ConductorError> {
        self.submit(Kind::QueryCutover, None, |sequence| Command::QueryCutover {
            sequence,
            registration,
        })
    }

    /// Sets the heartbeat interval and the driver timeout, both on this
    /// client's own monotonic clock. A timeout shorter than ten intervals
    /// is raised to ten intervals.
    pub fn set_liveness(&mut self, heartbeat_interval: Duration, driver_timeout: Duration) {
        self.heartbeat_interval = heartbeat_interval;
        self.driver_timeout = driver_timeout.max(heartbeat_interval.saturating_mul(10));
    }

    /// Takes the driver events received by earlier polls, oldest first
    /// (quantstratum-docs: `karyos/design/required-participant-loss.md`,
    /// Reporting): every client sees every event, and filters by stream.
    pub fn take_events(&mut self) -> impl Iterator<Item = Event> + '_ {
        self.events.drain(..)
    }

    /// Events dropped because the application did not take them before
    /// [`EVENT_QUEUE`] more arrived.
    #[must_use]
    pub fn events_dropped(&self) -> u64 {
        self.events_dropped
    }

    /// Driver event records that did not decode, skipped: an older client
    /// counts here the events whose type or reason it does not know (a
    /// newer driver's), instead of hiding them. Sticky at `u64::MAX`.
    #[must_use]
    pub fn events_undecoded(&self) -> u64 {
        self.events_undecoded
    }

    /// Whether the driver's heartbeat stopped for the driver timeout: the
    /// client then refuses new requests and fails those pending, and keeps
    /// what it already holds until it is dropped.
    #[must_use]
    pub fn driver_lost(&self) -> bool {
        self.driver_lost
    }

    /// Advances this client's heartbeat once per interval and samples the
    /// driver's; called by every poll, the client's duty.
    fn serve_liveness(&mut self) {
        let now = Instant::now();
        let due = self
            .last_beat
            .is_none_or(|last| now.saturating_duration_since(last) >= self.heartbeat_interval);
        if due && let Some(producer) = self.producer.as_mut() {
            // An exhausted heartbeat closes the ring, which `closed` sees.
            let _ = producer.beat();
            self.last_beat = Some(now);
        }
        let beat = self.receiver.heartbeat();
        match self.driver_seen {
            Some((seen, since)) if seen == beat => {
                if now.saturating_duration_since(since) >= self.driver_timeout {
                    self.driver_lost = true;
                }
            }
            _ => self.driver_seen = Some((beat, now)),
        }
    }

    /// The client's owner identity.
    #[must_use]
    pub fn owner(&self) -> Owner {
        self.owner
    }

    /// Requests that are submitted and not yet reported.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len() + self.unknown.len()
    }

    /// Requests the stream's exclusive publication on lane 0; returns the
    /// request sequence.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub fn add_publication(
        &mut self,
        stream: StreamKey,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        self.add_publication_on_lane(stream, Lane::ZERO, allow_unconnected)
    }

    /// Requests the exclusive publication of one lane of the stream's
    /// aggregate; returns the request sequence. The driver refuses a lane
    /// the aggregate does not configure with `UnknownStream`.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub fn add_publication_on_lane(
        &mut self,
        stream: StreamKey,
        lane: Lane,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        let request = Request::Publication {
            stream,
            lane,
            allow_unconnected,
        };
        self.submit(Kind::AddPublication, Some(request), |sequence| {
            Command::AddPublication {
                sequence,
                stream,
                lane,
                allow_unconnected,
            }
        })
    }

    /// Requests an exclusive publication of `stream_id` on the channel
    /// `uri` (W5; SPEC §5 channel URIs); returns the request sequence. The
    /// driver parses the URI: `karyos:ipc` resolves the stream as
    /// [`add_publication`](Self::add_publication) does, `karyos:udp`
    /// creates a network publication whose session id the driver draws. It
    /// completes as [`Outcome::Publication`], on lane 0 of the URI's lanes.
    /// A URI that does not parse is refused with `InvalidChannel`, one the
    /// driver cannot serve with `UnsupportedChannel`.
    ///
    /// # Errors
    ///
    /// [`ConductorError::EmptyUri`], [`ConductorError::UriTooLong`] over 512
    /// bytes, [`ConductorError::InvalidChannel`] for a URI that does not
    /// parse, and see [`ConductorError`]; nothing is submitted on error.
    pub fn add_network_publication(
        &mut self,
        uri: &str,
        stream_id: i32,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        let (uri, _) = channel_uri(uri)?;
        let request = Request::Publication {
            stream: StreamKey {
                stream_id,
                session_id: 0,
            },
            lane: Lane::ZERO,
            allow_unconnected,
        };
        self.submit_uri(Kind::AddPublication, request, |sequence| {
            Command::AddNetworkPublication {
                sequence,
                stream_id,
                allow_unconnected,
                uri,
            }
        })
    }

    /// Subscribes `stream_id` on the channel `uri` (W5); returns the
    /// request sequence. A `karyos:udp` subscription completes as
    /// [`Outcome::NetworkSubscription`]; its images are then announced with
    /// `ImageAvailable`, and each is attached as a stream with
    /// [`add_subscription`](Self::add_subscription) and `role`. A
    /// `karyos:ipc` one subscribes the only stream of `stream_id` on lane 0
    /// and completes as [`add_subscription`](Self::add_subscription) does
    /// (W7); the driver refuses it with `UnknownStream` when there is none
    /// or more than one.
    ///
    /// # Errors
    ///
    /// As [`add_network_publication`](Self::add_network_publication).
    pub fn add_network_subscription(
        &mut self,
        uri: &str,
        stream_id: i32,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        let (uri, ipc) = channel_uri(uri)?;
        let command = |sequence| Command::AddNetworkSubscription {
            sequence,
            stream_id,
            role,
            uri,
        };
        if ipc {
            let request = Request::Subscription {
                stream: StreamKey {
                    stream_id,
                    session_id: 0,
                },
                lane: Lane::ZERO,
                role,
            };
            self.submit_uri(Kind::AddSubscription, request, command)
        } else {
            self.submit(Kind::AddNetworkSubscription, None, command)
        }
    }

    /// Removes the network subscription `registration`; its images retire.
    /// Returns the request sequence; it completes as [`Outcome::Succeeded`].
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub fn remove_network_subscription(
        &mut self,
        registration: u64,
    ) -> Result<u64, ConductorError> {
        self.submit(Kind::Remove, None, |sequence| Command::RemoveSubscription {
            sequence,
            registration,
        })
    }

    /// Requests a concurrent publication handle on the stream; returns the
    /// request sequence. The driver refuses it with
    /// `InvalidPublicationMode` for an exclusive stream and with
    /// `PublicationTaken` while all its publisher slots are held.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub fn add_concurrent_publication(
        &mut self,
        stream: StreamKey,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        self.add_concurrent_publication_on_lane(stream, Lane::ZERO, allow_unconnected)
    }

    /// Requests a concurrent publication handle on one lane of the
    /// stream's aggregate, as
    /// [`add_concurrent_publication`](Self::add_concurrent_publication)
    /// does on lane 0.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub fn add_concurrent_publication_on_lane(
        &mut self,
        stream: StreamKey,
        lane: Lane,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        let request = Request::ConcurrentPublication {
            stream,
            lane,
            allow_unconnected,
        };
        self.submit(Kind::AddConcurrentPublication, Some(request), |sequence| {
            Command::AddConcurrentPublication {
                sequence,
                stream,
                lane,
                allow_unconnected,
            }
        })
    }

    /// Requests a subscription to the stream on lane 0; returns the
    /// request sequence.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub fn add_subscription(
        &mut self,
        stream: StreamKey,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        self.add_subscription_on_lane(stream, Lane::ZERO, role)
    }

    /// Requests a subscription to one lane of the stream's aggregate;
    /// returns the request sequence.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub fn add_subscription_on_lane(
        &mut self,
        stream: StreamKey,
        lane: Lane,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        let request = Request::Subscription { stream, lane, role };
        self.submit(Kind::AddSubscription, Some(request), |sequence| {
            Command::AddSubscription {
                sequence,
                stream,
                lane,
                role,
            }
        })
    }

    /// Requests a subscription to lane `lane` of the network image whose
    /// aggregate registration is `image`, of the alias `stream`
    /// (`quantstratum-docs: karyos/design/per-source-images.md`, D2-5):
    /// `AddImageSubscription`, recorded as a [`Request::Subscription`] of
    /// the alias, so the grant is checked against it as any other.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub(crate) fn add_image_subscription(
        &mut self,
        stream: StreamKey,
        image: u64,
        lane: Lane,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        let request = Request::Subscription { stream, lane, role };
        self.submit(Kind::AddSubscription, Some(request), |sequence| {
            Command::AddImageSubscription {
                sequence,
                image,
                lane,
                role,
            }
        })
    }

    /// Requests a view of a conflated stream's table (a remote client;
    /// `quantstratum-docs: karyos/design/conflation-end-to-end.md`,
    /// Cross-process views); returns the request sequence. It completes as
    /// [`Outcome::FetchableConflated`]; an in-process client's view comes
    /// from the driver's `subscribe_conflated` instead, and the driver
    /// refuses the command.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn add_conflated_subscription(
        &mut self,
        stream: StreamKey,
    ) -> Result<u64, ConductorError> {
        let request = Request::ConflatedSubscription { stream };
        self.submit(Kind::AddConflatedSubscription, Some(request), |sequence| {
            Command::AddConflatedSubscription { sequence, stream }
        })
    }

    /// Removes a publication this conductor handed out. The handle is
    /// dropped only after the command is written.
    ///
    /// # Errors
    ///
    /// Returns the handle intact with the error, so the caller can retry.
    #[allow(
        clippy::result_large_err,
        reason = "the handle is returned intact so the caller can retry; boxing it would allocate on every Full"
    )]
    pub fn remove_publication(
        &mut self,
        publication: ClientPublication<T>,
    ) -> Result<u64, (ClientPublication<T>, ConductorError)> {
        let Some(registration) = self.owned(publication.origin()) else {
            return Err((publication, ConductorError::ForeignHandle));
        };
        match self.submit(Kind::Remove, None, |sequence| Command::RemovePublication {
            sequence,
            registration,
        }) {
            Ok(sequence) => {
                // The Remove is queued: the driver keeps the registration
                // until it serves it.
                if let Some(origin) = publication.origin() {
                    origin.lease.mark_removing();
                }
                drop(publication);
                Ok(sequence)
            }
            Err(error) => Err((publication, error)),
        }
    }

    /// Submits the removal of the publication `registration`, whose handle
    /// a remote client took from its grant and drops once this is written.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn remove_publication_registration(
        &mut self,
        registration: u64,
    ) -> Result<u64, ConductorError> {
        self.submit(Kind::Remove, None, |sequence| Command::RemovePublication {
            sequence,
            registration,
        })
    }

    /// Submits `RemoveSubscription` for `registration`: the subscription a
    /// remote client took from its grant and drops once this is written.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn remove_subscription_registration(
        &mut self,
        registration: u64,
    ) -> Result<u64, ConductorError> {
        self.submit(Kind::Remove, None, |sequence| Command::RemoveSubscription {
            sequence,
            registration,
        })
    }

    /// Removes a concurrent publication handle this conductor handed out,
    /// as [`ClientConductor::remove_publication`]; dropping the handle frees
    /// its publisher slot.
    ///
    /// # Errors
    ///
    /// Returns the handle intact with the error, so the caller can retry.
    #[allow(
        clippy::result_large_err,
        reason = "the handle is returned intact so the caller can retry; boxing it would allocate on every Full"
    )]
    pub fn remove_concurrent_publication(
        &mut self,
        publication: ClientConcurrentPublication<T>,
    ) -> Result<u64, (ClientConcurrentPublication<T>, ConductorError)> {
        let Some(registration) = self.owned(publication.origin()) else {
            return Err((publication, ConductorError::ForeignHandle));
        };
        match self.submit(Kind::Remove, None, |sequence| Command::RemovePublication {
            sequence,
            registration,
        }) {
            Ok(sequence) => {
                // The Remove is queued: the driver keeps the registration
                // until it serves it.
                if let Some(origin) = publication.origin() {
                    origin.lease.mark_removing();
                }
                drop(publication);
                Ok(sequence)
            }
            Err(error) => Err((publication, error)),
        }
    }

    /// Removes a subscription this conductor handed out. The handle is
    /// dropped (detaching its registry cell) only after the command is
    /// written.
    ///
    /// # Errors
    ///
    /// Returns the handle intact with the error, so the caller can retry.
    #[allow(
        clippy::result_large_err,
        reason = "the handle is returned intact so the caller can retry; boxing it would allocate on every Full"
    )]
    pub fn remove_subscription(
        &mut self,
        subscription: ClientSubscription<T>,
    ) -> Result<u64, (ClientSubscription<T>, ConductorError)> {
        let Some(registration) = self.owned(subscription.origin()) else {
            return Err((subscription, ConductorError::ForeignHandle));
        };
        match self.submit(Kind::Remove, None, |sequence| Command::RemoveSubscription {
            sequence,
            registration,
        }) {
            Ok(sequence) => {
                // The Remove is queued: the driver keeps the registration
                // until it serves it.
                if let Some(origin) = subscription.origin() {
                    origin.lease.mark_removing();
                }
                drop(subscription);
                Ok(sequence)
            }
            Err(error) => Err((subscription, error)),
        }
    }

    /// Requests a client counter cell (`quantstratum-docs:
    /// karyos/design/observability-and-tools.md`, "Client counters") of
    /// `type_id` with `label`, keyed to the stream registration `stream`
    /// and to this client's participant registration `participant`, each
    /// 0 for none; returns the request sequence. It completes as
    /// [`Outcome::Counter`].
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError::LabelTooLong`] for a label of more than 64
    /// bytes, and the other [`ConductorError`]s; nothing is submitted on
    /// error.
    pub fn allocate_counter(
        &mut self,
        type_id: u64,
        label: &str,
        stream: u64,
        participant: u64,
    ) -> Result<u64, ConductorError> {
        let label = CounterLabel::new(label).ok_or(ConductorError::LabelTooLong)?;
        self.submit(Kind::AllocateCounter, None, |sequence| {
            Command::AllocateCounter {
                sequence,
                type_id,
                label,
                stream,
                participant,
            }
        })
    }

    /// Requests a trace journal of `layout` (`quantstratum-docs:
    /// karyos/design/trace-journal-region.md`) observing `registration`:
    /// one of this client's live subscriptions (a subscriber journal) or
    /// live publications (a publisher journal). `provenance` is the clock
    /// provenance word of the journal's observer, which the driver records
    /// in the journal's table entry without interpreting it: the word of
    /// the agent clock's `karyos_trace::ClockProvenance` (0 opaque, 1 the
    /// standard library's monotonic clock, 2 the host's `CLOCK_MONOTONIC`,
    /// the only one a tool can calibrate across processes). Returns the
    /// request sequence. It completes as [`Outcome::Journal`] (in process)
    /// or [`Outcome::FetchableJournal`] (remote), or is refused with
    /// `UnknownRegistration` (a registration that is not a live one of this
    /// client), `TraceJournalsExhausted` or `ResourcesUnavailable`. The
    /// driver takes a subscription's join position from its own record.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError::InvalidJournal`] for sizes the driver
    /// would refuse to decode or registration 0, and the other
    /// [`ConductorError`]s; nothing is submitted on error.
    pub fn trace_journal(
        &mut self,
        layout: JournalLayout,
        registration: u64,
        provenance: u64,
    ) -> Result<u64, ConductorError> {
        if layout.validate().is_err() || registration == 0 {
            return Err(ConductorError::InvalidJournal);
        }
        let words = |value: usize| u64::try_from(value).map_err(|_| ConductorError::InvalidJournal);
        let (capacity, payload_words, drop_ranges) = (
            words(layout.capacity)?,
            words(layout.payload_words)?,
            words(layout.drop_ranges)?,
        );
        self.submit_journal(Kind::TraceJournal, Some(layout), |sequence| {
            Command::TraceJournal {
                sequence,
                capacity,
                payload_words,
                drop_ranges,
                registration,
                provenance,
            }
        })
    }

    /// Gives the driver the final delivery boundary of trace journal
    /// `journal`, before the client closes it; returns the request
    /// sequence. It completes as [`Outcome::Succeeded`], or is refused with
    /// `UnknownRegistration` for a journal that is not an open journal of
    /// this client without a boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError::InvalidJournal`] for journal 0, and the
    /// other [`ConductorError`]s; nothing is submitted on error.
    pub fn close_journal(&mut self, journal: u64, boundary: u64) -> Result<u64, ConductorError> {
        if journal == 0 {
            return Err(ConductorError::InvalidJournal);
        }
        self.submit_journal(Kind::CloseJournal, None, |sequence| Command::CloseJournal {
            sequence,
            journal,
            boundary,
        })
    }

    /// Closes guard `guard` (`quantstratum-docs:
    /// karyos/design/guards-and-abort.md`, local guards; M10), on behalf of
    /// operator `operator` (a uid; 0 when the client acts for itself) with
    /// the operator's `reason`. The driver audits it with `operation`, the
    /// client (and the operator) and the request's parameters digest,
    /// `karyos_protocol::cnc::guard_parameters` over the guard, epoch 0,
    /// the operation, the operator and the reason. Returns the request
    /// sequence. It completes as [`Outcome::GuardState`] with the guard's
    /// state after the close (already closed included), or is refused with
    /// `UnknownGuard`, `GuardExhausted` or `NotAuthorized`.
    ///
    /// # Errors
    ///
    /// The [`ConductorError`]s of a submission; nothing is submitted on
    /// error.
    pub fn guard_close(
        &mut self,
        guard: u64,
        operation: u64,
        operator: u64,
        reason: &[u8],
    ) -> Result<u64, ConductorError> {
        let parameters =
            karyos_protocol::cnc::guard_parameters(guard, 0, operation, operator, reason);
        self.submit(Kind::Guard, None, |sequence| Command::GuardClose {
            sequence,
            guard,
            operation,
            operator,
            parameters,
        })
    }

    /// Reopens guard `guard`, closed at `expected`, as
    /// [`ClientConductor::guard_close`] closes one: audited alike, its
    /// digest over `expected`. It completes as [`Outcome::GuardState`], or
    /// is refused with `UnknownGuard`, `GuardNotClosedAt` (detail: the
    /// current guard word), `GuardExhausted` or `NotAuthorized`.
    ///
    /// # Errors
    ///
    /// Returns [`ConductorError::InvalidGuardEpoch`] when `expected` is not
    /// a closed epoch, and the other [`ConductorError`]s; nothing is
    /// submitted on error.
    pub fn guard_reopen(
        &mut self,
        guard: u64,
        expected: u64,
        operation: u64,
        operator: u64,
        reason: &[u8],
    ) -> Result<u64, ConductorError> {
        let closed = karyos_sys::guard::GuardState {
            epoch: expected,
            open: false,
        };
        if karyos_sys::guard::encode(closed).is_none() {
            return Err(ConductorError::InvalidGuardEpoch);
        }
        let parameters =
            karyos_protocol::cnc::guard_parameters(guard, expected, operation, operator, reason);
        self.submit(Kind::Guard, None, |sequence| Command::GuardReopen {
            sequence,
            guard,
            expected,
            operation,
            operator,
            parameters,
        })
    }

    /// Loss reports of this client's subscriptions dropped because the
    /// queue was full: the local count, complete whether or not the client
    /// counter `loss reports dropped` could be allocated.
    #[must_use]
    pub fn loss_reports_dropped(&self) -> u64 {
        self.link.loss_reports().dropped()
    }

    /// The loss report queue of this client's subscriptions, for the
    /// subscriptions a remote client takes by fetch.
    #[cfg(target_os = "linux")]
    pub(crate) fn loss_report_queue(&self) -> Arc<crate::loss::LossReports> {
        Arc::clone(self.link.loss_reports())
    }

    /// Loss reports queued and not yet sent.
    #[must_use]
    pub fn loss_reports_queued(&self) -> usize {
        self.link.loss_reports().queued()
    }

    /// The client counter `loss reports dropped`, once allocated; `None`
    /// before the first drop and when the allocation was refused.
    #[must_use]
    pub fn loss_reports_dropped_counter(&self) -> Option<&ClientCounterHandle> {
        match &self.dropped_counter {
            DroppedCounter::Allocated(handle, _) => Some(handle),
            _ => None,
        }
    }

    /// Sends the loss reports the client's subscriptions queued, in order,
    /// while the ring and the pending bound take them; the rest wait for a
    /// later poll.
    fn send_loss_reports(&mut self) {
        let reports = Arc::clone(self.link.loss_reports());
        while let Some(loss) = reports.pop() {
            let sent = self.submit(Kind::ReportLoss, None, |sequence| Command::ReportLoss {
                sequence,
                loss,
            });
            if sent.is_err() {
                reports.unpop(loss);
                break;
            }
        }
    }

    /// Brings the client counter `loss reports dropped` up to the local
    /// count, requesting the cell at the first drop.
    fn sync_dropped_counter(&mut self) {
        let dropped = self.link.loss_reports().dropped();
        match &mut self.dropped_counter {
            DroppedCounter::NotRequested if dropped > 0 => {
                let Some(label) = CounterLabel::new(LOSS_REPORTS_DROPPED) else {
                    return;
                };
                // An event counter, of the driver's event type id; a full
                // ring or pending bound retries on the next poll.
                let sent = self.submit(Kind::DroppedCounter, None, |sequence| {
                    Command::AllocateCounter {
                        sequence,
                        type_id: 1,
                        label,
                        stream: 0,
                        participant: 0,
                    }
                });
                if sent.is_ok() {
                    self.dropped_counter = DroppedCounter::Requested;
                }
            }
            // An overflow leaves the cell unchanged; the local count stays
            // exact.
            DroppedCounter::Allocated(handle, counted)
                if dropped > *counted && handle.increment(dropped - *counted).is_ok() =>
            {
                *counted = dropped;
            }
            _ => {}
        }
    }

    /// Completes the request for `loss reports dropped`.
    fn dropped_counter_answered(&mut self, response: Option<Response>) {
        let counter = match response {
            Some(Response::CounterAllocated {
                cell, registration, ..
            }) => usize::try_from(cell).ok().and_then(|cell| {
                self.cells
                    .as_ref()
                    .and_then(|cells| cells.counter(cell, registration))
            }),
            _ => None,
        };
        self.dropped_counter = match counter {
            Some(counter) => DroppedCounter::Allocated(
                ClientCounterHandle::new(
                    counter,
                    Arc::clone(self.link.counter_releases()),
                    self.session.clone(),
                ),
                0,
            ),
            None => DroppedCounter::Unavailable,
        };
    }

    /// Sends the releases the client's counter handles queued, in order,
    /// while the ring and the pending bound take them; the rest wait for a
    /// later poll.
    fn send_releases(&mut self) {
        let releases = Arc::clone(self.link.counter_releases());
        while let Some(release) = releases.pop() {
            let Release { cell, registration } = release;
            let sent = self.submit(Kind::ReleaseCounter, None, |sequence| {
                Command::ReleaseCounter {
                    sequence,
                    cell,
                    registration,
                }
            });
            if sent.is_err() {
                releases.unpop(release);
                break;
            }
        }
    }

    fn owned(&self, origin: Option<&Origin>) -> Option<u64> {
        origin
            .filter(|origin| origin.owner == self.owner)
            .map(|origin| origin.registration)
    }

    /// Whether this client can no longer be served: its ring was closed (by
    /// itself or by the driver, which retires a faulty client), the
    /// broadcast buffer closed, or the driver was dropped.
    fn closed(&self) -> bool {
        self.producer
            .as_ref()
            .is_none_or(karyos_sys::command_ring::RingProducer::is_closed)
            || self.receiver.is_closed()
            || self.link.driver_gone()
            || self.driver_lost
    }

    fn submit(
        &mut self,
        kind: Kind,
        request: Option<Request>,
        command: impl FnOnce(u64) -> Command,
    ) -> Result<u64, ConductorError> {
        self.submit_with(kind, request, None, command)
    }

    fn submit_journal(
        &mut self,
        kind: Kind,
        journal: Option<JournalLayout>,
        command: impl FnOnce(u64) -> Command,
    ) -> Result<u64, ConductorError> {
        self.submit_with(kind, None, journal, command)
    }

    fn submit_with(
        &mut self,
        kind: Kind,
        request: Option<Request>,
        journal: Option<JournalLayout>,
        command: impl FnOnce(u64) -> Command,
    ) -> Result<u64, ConductorError> {
        self.submit_full(kind, request, journal, false, command)
    }

    /// Submits a request that names its stream by channel URI: a remote
    /// client's grant takes its session id from the driver's.
    fn submit_uri(
        &mut self,
        kind: Kind,
        request: Request,
        command: impl FnOnce(u64) -> Command,
    ) -> Result<u64, ConductorError> {
        self.submit_full(kind, Some(request), None, true, command)
    }

    fn submit_full(
        &mut self,
        kind: Kind,
        request: Option<Request>,
        journal: Option<JournalLayout>,
        by_uri: bool,
        command: impl FnOnce(u64) -> Command,
    ) -> Result<u64, ConductorError> {
        if self.closed() {
            return Err(ConductorError::Closed);
        }
        if self.pending() >= self.max_pending {
            return Err(ConductorError::TooManyPending);
        }
        let sequence = self.next_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or(ConductorError::SequencesExhausted)?;
        let command = command(sequence);
        let mut bytes = [0u8; MAX_COMMAND_LENGTH];
        // Every command fits MAX_COMMAND_LENGTH by construction.
        let length = command
            .encode(&mut bytes)
            .map_err(|_| ConductorError::Closed)?;
        let producer = self.producer.as_mut().ok_or(ConductorError::Closed)?;
        match producer.write(command.type_id(), bytes.get(..length).unwrap_or(&[])) {
            Ok(_) => {
                self.next_sequence = next;
                self.pending.push(Pending {
                    sequence,
                    kind,
                    request,
                    journal,
                    by_uri,
                });
                Ok(sequence)
            }
            Err(RingError::Full) => Err(ConductorError::Full),
            // Only a ring smaller than the driver's validated minimum
            // refuses a command for its size.
            Err(RingError::MessageTooLarge { .. }) => Err(ConductorError::CommandTooLarge),
            Err(_) => Err(ConductorError::Closed),
        }
    }

    /// Makes at most `limit` broadcast receive attempts and reports
    /// completed requests to `on`. Each attempt reads one record of any
    /// client or a lap report, plus at most one padding record before it.
    /// Returns early when nothing more is published.
    pub fn poll<F>(&mut self, limit: usize, mut on: F) -> ConductorPoll
    where
        F: FnMut(Completion<T>),
    {
        let mut report = ConductorPoll::default();
        self.serve_liveness();
        // A closed client resolves its pending requests now, however small
        // the budget and however busy the broadcast buffer.
        if self.closed() {
            self.fail_pending(&mut on);
        } else {
            self.deliver_unknown(&mut on);
            self.send_releases();
            self.send_loss_reports();
            self.sync_dropped_counter();
        }
        while report.records < limit {
            // Copy what is needed out of the receiver before acting on it.
            let step = match self.receiver.receive() {
                Received::Pending => None,
                Received::Lapped { .. } => {
                    self.lapped |= self.remote;
                    if let Some(laps) = self.laps.checked_add(1) {
                        self.laps = laps;
                    }
                    Some(None)
                }
                Received::Message {
                    type_id, payload, ..
                } if Event::is_event_type(type_id) => {
                    // Driver events answer no request: queue them for the
                    // application, dropping the oldest when full.
                    if let Ok(event) = Event::decode(type_id, payload) {
                        if self.remote
                            && matches!(
                                event,
                                Event::SuccessorReady { .. }
                                    | Event::Fenced { .. }
                                    | Event::PublicationClosed { .. }
                            )
                        {
                            self.cutover_events.push(event);
                        }
                        if self.events.len() == EVENT_QUEUE {
                            self.events.pop_front();
                            self.events_dropped = self.events_dropped.saturating_add(1);
                        }
                        self.events.push_back(event);
                    } else if let Some(count) = self.events_undecoded.checked_add(1) {
                        self.events_undecoded = count;
                    }
                    Some(Some(None))
                }
                Received::Message {
                    type_id, payload, ..
                } => Some(Some(Response::decode(type_id, payload).ok())),
            };
            let response = match step {
                None => {
                    report.drained = true;
                    if self.closed() {
                        self.fail_pending(&mut on);
                    }
                    break;
                }
                Some(None) => {
                    report.records += 1;
                    self.fail_pending(&mut on);
                    continue;
                }
                Some(Some(response)) => {
                    report.records += 1;
                    response
                }
            };
            let Some(response) = response else {
                continue;
            };
            let request = response.request();
            if request.client != self.owner.client {
                continue;
            }
            let Some(index) = self
                .pending
                .iter()
                .position(|pending| pending.sequence == request.sequence)
            else {
                // Late response for a request already completed: ignored.
                continue;
            };
            let pending = self.pending.swap_remove(index);
            // The conductor's own requests: nothing to report.
            if pending.kind == Kind::DroppedCounter {
                self.dropped_counter_answered(Some(response));
                self.sync_dropped_counter();
                continue;
            }
            if let (
                Kind::QueryCutover,
                Response::CutoverState {
                    registration,
                    state: CutoverState::Fenced | CutoverState::Closed,
                    ..
                },
            ) = (pending.kind, response)
            {
                // Only the registration matters to the control path.
                self.cutover_events.push(Event::Fenced {
                    stream: StreamKey {
                        stream_id: 0,
                        session_id: 0,
                    },
                    registration,
                });
            }
            if pending.kind.internal() {
                continue;
            }
            let outcome = self.outcome(pending, response);
            on(Completion {
                sequence: pending.sequence,
                outcome,
            });
        }
        report
    }

    fn outcome(&self, pending: Pending, response: Response) -> Outcome<T> {
        let kind = pending.kind;
        // A remote client's grant is fetched, never taken from the
        // in-process hand-over table.
        if self.remote {
            match (pending.request, response) {
                (
                    Some(request),
                    Response::PublicationReady {
                        registration, key, ..
                    }
                    | Response::SubscriptionReady {
                        registration, key, ..
                    },
                ) if matches!(
                    (kind, response),
                    (
                        Kind::AddPublication | Kind::AddConcurrentPublication,
                        Response::PublicationReady { .. }
                    ) | (Kind::AddSubscription, Response::SubscriptionReady { .. })
                ) =>
                {
                    return Outcome::Fetchable(Fetchable {
                        key,
                        registration,
                        request,
                        by_uri: pending.by_uri,
                    });
                }
                _ => {}
            }
            if let (
                Kind::AddConflatedSubscription,
                Some(Request::ConflatedSubscription { stream }),
                Response::ConflatedReady {
                    registration,
                    key,
                    keys,
                    value_capacity,
                    journal_capacity,
                    ..
                },
            ) = (kind, pending.request, response)
            {
                return Outcome::FetchableConflated(FetchableConflated {
                    key,
                    registration,
                    stream,
                    keys,
                    value_capacity,
                    journal_capacity,
                });
            }
            if let (Kind::TraceJournal, Some(layout), Response::JournalReady { journal, key, .. }) =
                (kind, pending.journal, response)
            {
                return Outcome::FetchableJournal(FetchableJournal {
                    journal,
                    key,
                    layout,
                });
            }
        }
        match (kind, response) {
            (
                Kind::AddPublication,
                Response::PublicationReady {
                    registration, key, ..
                },
            )
            | (
                Kind::AddConcurrentPublication,
                Response::PublicationReady {
                    registration, key, ..
                },
            )
            | (
                Kind::AddSubscription,
                Response::SubscriptionReady {
                    registration, key, ..
                },
            ) => match self.link.take(key) {
                Ok(entry) => {
                    let origin = Origin {
                        owner: self.owner,
                        registration,
                        lease: entry.lease,
                    };
                    let generation = entry.generation;
                    let outcome = match (kind, entry.capability) {
                        (
                            Kind::AddPublication,
                            Capability::Publication {
                                inner,
                                allow_unconnected,
                            },
                        ) => Outcome::Publication(ClientPublication::from_hand_over(
                            inner,
                            allow_unconnected,
                            origin,
                        )),
                        (
                            Kind::AddConcurrentPublication,
                            Capability::ConcurrentPublication {
                                inner,
                                allow_unconnected,
                            },
                        ) => Outcome::ConcurrentPublication(
                            ClientConcurrentPublication::from_hand_over(
                                inner,
                                allow_unconnected,
                                origin,
                            ),
                        ),
                        (Kind::AddSubscription, Capability::Subscription(inner)) => {
                            let subscription = ClientSubscription::from_hand_over(inner, origin);
                            Outcome::Subscription(match entry.publication {
                                Some(publication) => subscription.with_loss_reports(LossReporter {
                                    publication,
                                    registration,
                                    reports: Arc::clone(self.link.loss_reports()),
                                }),
                                None => subscription,
                            })
                        }
                        // A capability of another kind than requested would
                        // be a driver defect: it is dropped (ending its
                        // lease and freeing what it holds), never converted.
                        _ => Outcome::Unknown,
                    };
                    match generation {
                        Some((link, base)) => outcome.with_generation(link, base),
                        None => outcome,
                    }
                }
                Err(_) => Outcome::Unknown,
            },
            (Kind::Remove | Kind::CloseJournal, Response::OperationSucceeded { .. }) => {
                Outcome::Succeeded
            }
            (Kind::Guard, Response::GuardState { guard, state, .. }) => {
                Outcome::GuardState { guard, state }
            }
            (
                Kind::AddNetworkSubscription,
                Response::NetworkSubscriptionReady { registration, .. },
            ) => Outcome::NetworkSubscription { registration },
            // The writer waits in the hand-over table under its key.
            (Kind::TraceJournal, Response::JournalReady { journal, key, .. }) => {
                match self.link.take_journal(key) {
                    Ok(writer) => Outcome::Journal(ClientJournal::new(journal, writer)),
                    Err(_) => Outcome::Unknown,
                }
            }
            (
                Kind::AllocateCounter,
                Response::CounterAllocated {
                    cell, registration, ..
                },
            ) => {
                // A cell the region does not hold for this allocation would
                // be a driver defect: the outcome is not known, and the cell
                // stays charged until the client's exit proof.
                let counter = usize::try_from(cell).ok().and_then(|cell| {
                    self.cells
                        .as_ref()
                        .and_then(|cells| cells.counter(cell, registration))
                });
                match counter {
                    Some(counter) => Outcome::Counter(ClientCounterHandle::new(
                        counter,
                        Arc::clone(self.link.counter_releases()),
                        self.session.clone(),
                    )),
                    None => Outcome::Unknown,
                }
            }
            (_, Response::Error { code, detail, .. }) => Outcome::Refused { code, detail },
            // A response of the wrong kind would be a driver defect; the
            // outcome is not known.
            _ => Outcome::Unknown,
        }
    }

    /// Terminalizes every pending request as `Unknown` before any callback
    /// runs (a late response can no longer match it), then delivers the
    /// notifications.
    fn fail_pending<F: FnMut(Completion<T>)>(&mut self, on: &mut F) {
        // The conductor's own requests are not reported.
        if self
            .pending
            .iter()
            .any(|pending| pending.kind == Kind::DroppedCounter)
        {
            self.dropped_counter_answered(None);
        }
        self.unknown.extend(
            self.pending
                .drain(..)
                .filter(|pending| !pending.kind.internal())
                .map(|pending| pending.sequence),
        );
        self.deliver_unknown(on);
    }

    fn deliver_unknown<F: FnMut(Completion<T>)>(&mut self, on: &mut F) {
        while let Some(&sequence) = self.unknown.front() {
            on(Completion {
                sequence,
                outcome: Outcome::Unknown,
            });
            self.unknown.pop_front();
        }
    }

    /// Closes the client: drops the command ring producer, then sets the
    /// close flag. Same as dropping the conductor.
    pub fn close(self) {
        drop(self);
    }
}

impl<T: TermBytes> Drop for ClientConductor<T> {
    fn drop(&mut self) {
        // The conductor's own counter makes its last access first.
        self.dropped_counter = DroppedCounter::Unavailable;
        drop(self.producer.take());
        self.link.mark_closed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{HandOverEntry, Lease, LeaseEnd, StreamLeases};
    use karyos_protocol::cnc::RequestId;
    use karyos_sys::broadcast::broadcast;
    use karyos_sys::command_ring::command_ring;
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBuffer, LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    // A capability of another kind than the request is never converted: a
    // driver defect the real driver cannot produce, injected by hand.
    #[test]
    fn a_capability_of_another_kind_is_dropped_as_unknown() {
        let mut transmitter = broadcast(4096).unwrap();
        let (producer, _consumer) = command_ring(1024).unwrap();
        let link = Arc::new(ClientLink::new());
        let owner = Owner {
            driver: 1,
            client: 1,
        };
        let mut client = ClientConductor::new(
            owner,
            producer,
            transmitter.receiver(),
            Arc::clone(&link),
            4,
        );
        let sequence = client.add_concurrent_publication(
            StreamKey {
                stream_id: 2,
                session_id: 1,
            },
            true,
        );
        let sequence = sequence.unwrap();
        let buffer = Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 2,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            })
            .unwrap(),
        );
        let leases = Arc::new(StreamLeases::default());
        link.hold(HandOverEntry {
            key: 9,
            capability: Capability::Publication {
                inner: buffer.publication_owned().unwrap().unwrap(),
                allow_unconnected: true,
            },
            lease: Lease::acquire(&leases, &Arc::new(LeaseEnd::default())),
            generation: None,
            publication: None,
        });
        let response = Response::PublicationReady {
            request: RequestId {
                client: 1,
                sequence,
            },
            registration: 9,
            key: 9,
        };
        let mut payload = [0u8; karyos_protocol::cnc::MAX_RESPONSE_LENGTH];
        let length = response.encode(&mut payload).unwrap();
        let _ = transmitter
            .transmit(response.type_id(), &payload[..length])
            .unwrap();
        let mut done = Vec::new();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        assert_eq!(done.len(), 1);
        assert!(matches!(done[0].outcome, Outcome::Unknown));
        // Taken and dropped: its lease ended.
        assert_eq!(leases.live(), 0);
    }

    /// A driver event the client cannot decode, here a `PublicationClosed`
    /// whose close reason this build does not know, is skipped: the poll
    /// goes on, later events are queued, the conductor stays open, and the
    /// skip is counted (`events_undecoded`).
    /// This is what a build from before `EndOfStream` (code 8) does with an
    /// image's clean end; its handles still close on the final seal,
    /// which needs no event (ADR-0061).
    #[test]
    fn an_event_with_an_unknown_close_reason_is_skipped() {
        let mut transmitter = broadcast(4096).unwrap();
        let (producer, _consumer) = command_ring(1024).unwrap();
        let link = Arc::new(ClientLink::<karyos_sys::term_bytes::HeapTerms>::new());
        let owner = Owner {
            driver: 1,
            client: 1,
        };
        let mut client = ClientConductor::new(owner, producer, transmitter.receiver(), link, 4);
        let closed = |reason| Event::PublicationClosed {
            stream: StreamKey {
                stream_id: 2,
                session_id: 1,
            },
            lane: Lane::ZERO,
            reason,
            image: 0,
        };
        let known = closed(karyos_protocol::cnc::CloseReason::StreamRemoved);
        let mut payload = [0u8; karyos_protocol::cnc::MAX_EVENT_LENGTH];
        let length = known.encode(&mut payload).unwrap();
        let mut unknown = payload;
        unknown[8..16].copy_from_slice(&200u64.to_le_bytes());
        let _ = transmitter
            .transmit(known.type_id(), &unknown[..length])
            .unwrap();
        let poll = client.poll(usize::MAX, |_| {});
        assert_eq!((poll.records, client.events_undecoded()), (1, 1));
        let _ = transmitter
            .transmit(known.type_id(), &payload[..length])
            .unwrap();
        let poll = client.poll(usize::MAX, |_| {});
        assert_eq!(poll.records, 1, "{poll:?}");
        assert_eq!(client.events_undecoded(), 1, "a valid event is not counted");
        let events: Vec<Event> = client.take_events().collect();
        assert_eq!(events, [known]);
        assert!(!client.closed());
        let _ = client.poll(usize::MAX, |_| {});
        assert_eq!(client.take_events().count(), 0);
    }
}
