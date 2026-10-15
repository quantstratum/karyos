// SPDX-License-Identifier: Apache-2.0

//! The embedded driver: log buffers and their conductors in the
//! application's process, with conductor duty run by the application.
//!
//! The driver never calls application code. Its data path holds no locks;
//! the only lock is each client's hand-over table, on the control path
//! (quantstratum-docs: karyos/design/client-commands.md). Dropping the driver stops conductor
//! duty and closes the broadcast buffer: publications and subscriptions
//! already handed out keep their buffers alive and keep working until the
//! buffers need rotation, cleaning or new limits, which then report back
//! pressure or admin actions: without the driver, progress is bounded by
//! what is already prepared and admitted. Requests clients had submitted
//! become unknown; new requests and hand-over takes fail.
//!
//! Streams are configured on the driver ([`EmbeddedDriver::add_stream`]).
//! Clients admitted with [`EmbeddedDriver::connect`] request publications
//! and subscriptions through their command rings; the direct
//! [`EmbeddedDriver::publication`] and [`EmbeddedDriver::subscribe`] calls
//! remain for single-component use; their handles hold stream leases too.
//!
//! [`EmbeddedDriver::remove_stream`] retires a stream at once; a later duty
//! cycle frees it when no capability lease and no registration of it
//! remains (quantstratum-docs: karyos/design/stream-lifecycle.md).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::link::{Lease, LeaseEnd, StreamLeases};
use karyos_client::{
    ClientConcurrentPublication, ClientPublication, ClientSubscription, GenerationLink,
};
use karyos_protocol::cnc::MAX_RESPONSE_LENGTH;
use karyos_sys::broadcast::{BroadcastTransmitter, HEADER_LENGTH, broadcast};
use karyos_sys::log_buffer::{
    Conductor, DeadlineError, DeadlineReport, LogBuffer, LogBufferConfig, LossPolicy, Publication,
    Role, SealState,
};
use karyos_sys::term::Generation;

use crate::clock::{MonotonicClock, SystemClock};
use crate::commands::ClientSlot;
use crate::counters::{DriverCounters, Event};
use crate::error::DriverError;
use crate::generations::{Cutover, Member, MemberKind, Retained};

/// Limits and sizes of the control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverConfig {
    /// Clients admitted at once, including retired clients whose command
    /// ring producer has not yet detached.
    pub max_clients: usize,
    /// Pending requests and held hand-over entries per client.
    pub max_pending_per_client: usize,
    /// Held hand-over entries over all clients.
    pub max_hand_over: usize,
    /// Commands served per duty cycle (`B`).
    pub command_budget: usize,
    /// Duty cycles whose responses may fall between the ends of two
    /// consecutive drains by a client (`m`); the application's promise.
    pub cycles_between_drains: usize,
    /// Bytes of each client's command ring.
    pub ring_capacity: usize,
    /// Bytes of the broadcast buffer; at least `2 * B * R * m`, `R` being
    /// the largest response record.
    pub broadcast_capacity: usize,
    /// Streams configured at once, active or retiring.
    pub max_streams: usize,
    /// Predecessor mappings each stream retains at once after cutovers
    /// (SPEC.md §4 `max_retained_generations`).
    pub max_retained_generations: usize,
    /// How long a handle has to move to a successor mapping, in the unit of
    /// the driver's clock: from the cutover's opening for publishers, from
    /// the last observed progress for subscribers
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`).
    pub cutover_deadline: u64,
    /// How often the driver advances its heartbeat, in the clock's unit
    /// (quantstratum-docs: `karyos/design/required-participant-loss.md`).
    pub heartbeat_interval: u64,
    /// How long a client's heartbeat may stay unchanged, in the clock's
    /// unit, before the client is timed out: its command ring is closed and
    /// it is no longer served. At least ten heartbeat intervals.
    pub client_liveness_timeout: u64,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            max_clients: 16,
            max_pending_per_client: 16,
            max_hand_over: 64,
            command_budget: 64,
            cycles_between_drains: 2,
            ring_capacity: 1024,
            broadcast_capacity: 16 * 1024,
            max_streams: 64,
            max_retained_generations: 2,
            cutover_deadline: 1_000_000_000,
            heartbeat_interval: 100_000_000,
            client_liveness_timeout: 10_000_000_000,
        }
    }
}

/// Bytes of the largest response record: header plus payload.
const RESPONSE_EXTENT: usize = HEADER_LENGTH as usize + MAX_RESPONSE_LENGTH;

/// Configuration of one stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    /// The log buffer's configuration.
    pub buffer: LogBufferConfig,
    /// Allow offers while no subscriber is attached (SPEC.md §4).
    pub allow_unconnected: bool,
    /// What happens to a required subscriber whose client is lost
    /// (SPEC.md §4 `on_required_loss`; quantstratum-docs:
    /// `karyos/design/required-participant-loss.md`). Under `Continue`
    /// required subscribers are admitted with a spare-slot credit.
    pub on_required_loss: LossPolicy,
}

/// Names a stream of one [`EmbeddedDriver`]. It is distinct from the wire
/// `stream_id`: it carries the issuing driver's identity and a stream id
/// that is never reused, so a handle from another driver, or to a removed
/// stream, never names another stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamHandle {
    driver: u64,
    stream: u64,
}

/// The lifecycle state of a stream (quantstratum-docs: karyos/design/stream-lifecycle.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamState {
    /// Accepts publications and subscriptions.
    Active,
    /// Removed: accepts nothing new and is freed once no capability or
    /// registration remains.
    Retiring,
    /// Freed: its buffer is gone.
    Freed,
}

/// Source of driver identities within the process.
static NEXT_DRIVER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct Stream {
    pub(crate) id: u64,
    pub(crate) retiring: bool,
    pub(crate) buffer: Arc<LogBuffer>,
    pub(crate) conductor: Conductor<Arc<LogBuffer>>,
    pub(crate) leases: Arc<StreamLeases>,
    allow_unconnected: bool,
    /// The stream's `on_required_loss` policy.
    pub(crate) policy: LossPolicy,
    pub(crate) stream_id: i32,
    pub(crate) session_id: i32,
    /// Whether the latest deadline call returned `Waiting`.
    claim_waiting: bool,
    /// The current mapping's configuration and generation, and the stream
    /// position where it starts (`quantstratum-docs: karyos/design/mapping-generations.md`).
    pub(crate) config: LogBufferConfig,
    pub(crate) generation: Generation,
    pub(crate) base: u64,
    /// The generation links of the handles on the current mapping.
    pub(crate) members: Vec<Member>,
    /// The cutover in progress, if any.
    pub(crate) cutover: Option<Cutover>,
    /// Predecessor mappings still referenced, oldest first.
    pub(crate) retained: Vec<Retained>,
    /// The current mapping's exclusive publication, returned by a fence,
    /// for the next issuance.
    pub(crate) spare: Option<Publication<Arc<LogBuffer>>>,
}

impl Stream {
    /// A new generation link for a handle on the current mapping.
    pub(crate) fn join(&mut self, kind: MemberKind) -> (Arc<GenerationLink>, u64) {
        let link = GenerationLink::new();
        self.members.push(Member {
            link: Arc::downgrade(&link),
            kind,
        });
        (link, self.base)
    }

    /// Refuses issuance while a cutover is pending.
    pub(crate) fn issuing(&self) -> Result<(), DriverError> {
        match &self.cutover {
            Some(cutover) if cutover.is_pending() => {
                Err(DriverError::CutoverPending { stream: self.id })
            }
            _ => Ok(()),
        }
    }
}

/// Owns streams and clients and runs conductor duty on demand.
#[derive(Debug)]
pub struct EmbeddedDriver {
    pub(crate) id: u64,
    pub(crate) config: DriverConfig,
    pub(crate) streams: Vec<Stream>,
    pub(crate) broadcast: BroadcastTransmitter,
    pub(crate) clients: Vec<ClientSlot>,
    pub(crate) registrations: Vec<crate::commands::Registration>,
    pub(crate) next_client: u64,
    pub(crate) next_stream: u64,
    pub(crate) next_registration: u64,
    pub(crate) scan_cursor: usize,
    pub(crate) terminal: bool,
    pub(crate) counters: DriverCounters,
    /// The clock of claim deadlines and of the admission timeout.
    pub(crate) clock: Box<dyn MonotonicClock>,
    /// The next export id: one checked namespace, never reused, for the
    /// exports of remote clients and the occupant ids of every subscriber
    /// cell this driver registers (quantstratum-docs:
    /// `karyos/design/required-participant-loss.md`, Occupants).
    pub(crate) next_export: u64,
    /// Lost `hold` participants whose bound is still in force.
    pub(crate) holding: Vec<crate::commands::Holding>,
    /// When the driver last advanced its heartbeat, in clock units.
    pub(crate) last_beat: Option<u64>,
    /// The admission socket and its connections (IPC mode).
    #[cfg(target_os = "linux")]
    pub(crate) admission: Option<crate::admission::Admission>,
}

impl EmbeddedDriver {
    /// An empty driver.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::DriverIdsExhausted`] once the process has
    /// created `u64::MAX - 1` drivers; identities are never reused, so a
    /// stale handle can never name another driver's stream.
    pub fn new() -> Result<Self, DriverError> {
        Self::with_config(DriverConfig::default())
    }

    /// An empty driver with explicit control-channel limits.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::InvalidConfig`] for a zero limit, a ring or
    /// broadcast size the primitives reject, or a broadcast smaller than
    /// `2 * B * R * m`; and [`DriverError::DriverIdsExhausted`].
    pub fn with_config(config: DriverConfig) -> Result<Self, DriverError> {
        Self::with_clock(config, Box::new(SystemClock::new()))
    }

    /// An empty driver with explicit limits and the clock of claim
    /// deadlines (`quantstratum-docs: karyos/design/client-claims.md`), in the unit of each
    /// stream's `claim_deadline`.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::with_config`].
    pub fn with_clock(
        config: DriverConfig,
        clock: Box<dyn MonotonicClock>,
    ) -> Result<Self, DriverError> {
        Self::build(config, clock, None)
    }

    /// A driver that also admits clients of other processes through its
    /// admission socket (`quantstratum-docs: karyos/design/ipc-admission-server.md`, Linux).
    /// Its broadcast buffer and counters live in shared regions.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::with_config`], [`DriverError::InvalidConfig`]
    /// for a zero admission limit, and [`DriverError::Sys`] when the
    /// socket or a region cannot be created.
    #[cfg(target_os = "linux")]
    pub fn with_ipc(
        config: DriverConfig,
        ipc: crate::admission::IpcConfig,
        clock: Box<dyn MonotonicClock>,
    ) -> Result<Self, DriverError> {
        Self::build(config, clock, Some(ipc))
    }

    fn build(
        config: DriverConfig,
        clock: Box<dyn MonotonicClock>,
        #[cfg(target_os = "linux")] ipc: Option<crate::admission::IpcConfig>,
        #[cfg(not(target_os = "linux"))] ipc: Option<core::convert::Infallible>,
    ) -> Result<Self, DriverError> {
        let needed = RESPONSE_EXTENT
            .checked_mul(2)
            .and_then(|n| n.checked_mul(config.command_budget))
            .and_then(|n| n.checked_mul(config.cycles_between_drains))
            .ok_or(DriverError::InvalidConfig)?;
        let valid = config.max_clients > 0
            && config.max_streams > 0
            && config.max_retained_generations > 0
            && config.cutover_deadline > 0
            && config.heartbeat_interval > 0
            && config
                .heartbeat_interval
                .checked_mul(10)
                .is_some_and(|minimum| config.client_liveness_timeout >= minimum)
            && config.max_pending_per_client > 0
            && config.max_hand_over > 0
            && config.command_budget > 0
            && config.cycles_between_drains > 0
            && config.ring_capacity >= karyos_sys::command_ring::MIN_CAPACITY
            && config.ring_capacity.is_power_of_two()
            && config.broadcast_capacity >= needed;
        if !valid {
            return Err(DriverError::InvalidConfig);
        }
        #[cfg(target_os = "linux")]
        let (broadcast, counters, admission) = match ipc {
            Some(ipc) => {
                let (admission, instance) = crate::admission::Admission::new(ipc)?;
                let broadcast = BroadcastTransmitter::create_in(
                    instance,
                    crate::admission::BROADCAST_REGION,
                    config.broadcast_capacity,
                )
                .map_err(|_| DriverError::InvalidConfig)?;
                let counters = DriverCounters::new_in(instance, crate::admission::COUNTERS_REGION)?;
                (broadcast, counters, Some(admission))
            }
            None => (
                broadcast(config.broadcast_capacity).map_err(|_| DriverError::InvalidConfig)?,
                DriverCounters::new()?,
                None,
            ),
        };
        #[cfg(not(target_os = "linux"))]
        let (broadcast, counters) = {
            let _ = ipc;
            (
                broadcast(config.broadcast_capacity).map_err(|_| DriverError::InvalidConfig)?,
                DriverCounters::new()?,
            )
        };
        if !broadcast.has_room(MAX_RESPONSE_LENGTH) {
            return Err(DriverError::InvalidConfig);
        }
        let id = NEXT_DRIVER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| DriverError::DriverIdsExhausted)?;
        Ok(Self {
            counters,
            id,
            config,
            streams: Vec::new(),
            broadcast,
            clients: Vec::new(),
            registrations: Vec::new(),
            next_client: 1,
            next_stream: 1,
            next_registration: 1,
            scan_cursor: 0,
            terminal: false,
            clock,
            next_export: 1,
            holding: Vec::new(),
            last_beat: None,
            #[cfg(target_os = "linux")]
            admission,
        })
    }

    /// Live capability leases of a stream: capabilities held for hand-over
    /// and handles of either API (client conductor or direct calls).
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::UnknownStream`] for a foreign handle or a
    /// freed stream.
    pub fn live_leases(&mut self, stream: StreamHandle) -> Result<u64, DriverError> {
        Ok(self.stream(stream)?.leases.live())
    }

    /// The stream's lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::UnknownStream`] for a handle of another
    /// driver.
    pub fn stream_state(&self, stream: StreamHandle) -> Result<StreamState, DriverError> {
        if stream.driver != self.id || stream.stream >= self.next_stream {
            return Err(DriverError::UnknownStream {
                stream: stream.stream,
            });
        }
        // Derived: an issued id that is no longer present was freed.
        Ok(match self.streams.iter().find(|s| s.id == stream.stream) {
            Some(s) if s.retiring => StreamState::Retiring,
            Some(_) => StreamState::Active,
            None => StreamState::Freed,
        })
    }

    /// The seal state of a stream's buffer (`quantstratum-docs: karyos/design/publication-seal.md`):
    /// `Active` until it is removed, then `Sealed` until every issued
    /// publication has released, `Positioned` at the end of its last
    /// granted reservation, and `Retired` once every attached subscriber
    /// has read up to that position.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::UnknownStream`] for a foreign handle or a
    /// freed stream.
    pub fn seal_state(&self, stream: StreamHandle) -> Result<SealState, DriverError> {
        self.streams
            .iter()
            .find(|s| stream.driver == self.id && s.id == stream.stream)
            .map(|s| s.conductor.seal_state())
            .ok_or(DriverError::UnknownStream {
                stream: stream.stream,
            })
    }

    /// A read-only view of the driver's counters (SPEC.md §11), for tools.
    #[must_use]
    pub fn counters(&self) -> karyos_sys::counters::CountersReader {
        self.counters.reader()
    }

    /// Refreshes every gauge from the current state.
    pub(crate) fn update_stream_gauges(&self) {
        let gauge = |count: usize| u64::try_from(count).unwrap_or(u64::MAX);
        let retiring = self.streams.iter().filter(|s| s.retiring).count();
        let active = self.streams.len() - retiring;
        self.counters.set(Event::StreamsActive, gauge(active));
        self.counters.set(Event::StreamsRetiring, gauge(retiring));
        let waiting = self.streams.iter().filter(|s| s.claim_waiting).count();
        self.counters.set(Event::ClaimsWaiting, gauge(waiting));
        self.counters
            .set(Event::ClientsConnected, gauge(self.clients.len()));
        self.counters
            .set(Event::HandOverHeld, gauge(self.held_total()));
        match self
            .streams
            .iter()
            .try_fold(0u64, |sum, s| sum.checked_add(s.leases.live()))
        {
            Some(leases) => self.counters.set(Event::LeasesLive, leases),
            None => self.counters.add(Event::CounterOverflows, 1),
        }
    }

    /// Removes a stream: it stops accepting publications and subscriptions
    /// at once, its buffer is sealed (`quantstratum-docs: karyos/design/publication-seal.md`),
    /// and it is freed by a later duty cycle once no capability or
    /// registration of it remains. Never waits and never revokes a live
    /// capability: a live publication returns `Closed` on its next attempt
    /// and releases, and subscribers read the backlog up to the seal
    /// position, then report it. Removing a retiring stream again succeeds
    /// with no effect.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::UnknownStream`] for a foreign or freed
    /// stream, and [`DriverError::Sys`] from the descriptor protocol, which
    /// indicates a broken invariant.
    pub fn remove_stream(&mut self, stream: StreamHandle) -> Result<(), DriverError> {
        let target = self.stream(stream)?;
        if !target.retiring {
            target.conductor.seal()?;
            // A cutover ends with the stream: its handles are fenced and its
            // successor, if not current yet, is dropped.
            if let Some(cutover) = target.cutover.take() {
                cutover.abandon();
            }
            target.retiring = true;
            self.counters.add(Event::StreamsRemoved, 1);
        }
        self.update_stream_gauges();
        Ok(())
    }

    /// Frees retiring streams with no live lease and no registration.
    pub(crate) fn free_retired_streams(&mut self) {
        let before = self.streams.len();
        let registrations = &self.registrations;
        self.streams.retain(|stream| {
            !(stream.retiring
                && stream.leases.live() == 0
                && !registrations
                    .iter()
                    .any(|registration| registration.stream() == stream.id))
        });
        let freed = before - self.streams.len();
        if freed > 0 {
            self.counters.add(
                Event::StreamsFreed,
                u64::try_from(freed).unwrap_or(u64::MAX),
            );
            self.update_stream_gauges();
        }
    }

    /// Whether the driver is in its terminal state: the broadcast buffer is
    /// closed and no command is served.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Creates a stream (control path: allocates its log buffer).
    ///
    /// # Errors
    ///
    /// Returns configuration and allocation errors; no stream is added on
    /// error.
    pub fn add_stream(&mut self, config: StreamConfig) -> Result<StreamHandle, DriverError> {
        // A key in use (active or retiring) is reported before the quota.
        let key = (config.buffer.stream_id, config.buffer.session_id);
        if self
            .streams
            .iter()
            .any(|s| (s.stream_id, s.session_id) == key)
        {
            return Err(DriverError::DuplicateStream {
                stream_id: key.0,
                session_id: key.1,
            });
        }
        if self.streams.len() >= self.config.max_streams {
            return Err(DriverError::TooManyStreams);
        }
        let id = self.next_stream;
        let next = id.checked_add(1).ok_or(DriverError::StreamIdsExhausted)?;
        let buffer = Arc::new(LogBuffer::new(config.buffer)?);
        let conductor = buffer
            .conductor_owned()
            .ok_or(karyos_sys::error::SysError::ResourcesUnavailable)?;
        self.next_stream = next;
        self.streams.push(Stream {
            id,
            retiring: false,
            buffer,
            conductor,
            leases: Arc::new(StreamLeases::default()),
            allow_unconnected: config.allow_unconnected,
            policy: config.on_required_loss,
            stream_id: key.0,
            session_id: key.1,
            claim_waiting: false,
            config: config.buffer,
            generation: Generation::default(),
            base: 0,
            members: Vec::new(),
            cutover: None,
            retained: Vec::new(),
            spare: None,
        });
        self.update_stream_gauges();
        Ok(StreamHandle {
            driver: self.id,
            stream: id,
        })
    }

    /// Takes the stream's only publication. The handle holds a stream lease
    /// until dropped.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::PublicationTaken`] after the first call,
    /// [`DriverError::InvalidPublicationMode`] for a concurrent stream,
    /// [`DriverError::StreamRetiring`] for a removed stream, and
    /// [`DriverError::UnknownStream`] for a foreign handle or a freed stream.
    pub fn publication(&mut self, stream: StreamHandle) -> Result<ClientPublication, DriverError> {
        let stream = self.active_stream(stream)?;
        stream.issuing()?;
        let inner = match stream.spare.take() {
            Some(inner) => inner,
            None => stream
                .buffer
                .publication_owned()
                .map_err(mode_error)?
                .ok_or(DriverError::PublicationTaken)?,
        };
        let lease = Lease::acquire(&stream.leases, &Arc::new(LeaseEnd::default()));
        let (link, base) = stream.join(MemberKind::Exclusive);
        let publication = ClientPublication::with_lease(inner, stream.allow_unconnected, lease)
            .with_generation(link, base)?;
        self.update_stream_gauges();
        Ok(publication)
    }

    /// Issues a concurrent publication handle on one of the stream's `P`
    /// publisher slots (`quantstratum-docs: karyos/design/client-concurrent-publication.md`).
    /// The handle holds a stream lease until dropped; dropping it frees its
    /// slot for a later handle.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::InvalidPublicationMode`] for an exclusive
    /// stream, [`DriverError::PublicationTaken`] while all `P` slots are
    /// held, `ResourcesUnavailable` when the claim staging of a shared
    /// buffer cannot be allocated, [`DriverError::StreamRetiring`] for a
    /// removed stream, and [`DriverError::UnknownStream`] for a foreign
    /// handle or a freed stream. Nothing is held after an error.
    pub fn concurrent_publication(
        &mut self,
        stream: StreamHandle,
    ) -> Result<ClientConcurrentPublication, DriverError> {
        let stream = self.active_stream(stream)?;
        stream.issuing()?;
        let inner = stream
            .conductor
            .concurrent_publication()
            .map_err(mode_error)?
            .ok_or(DriverError::PublicationTaken)?;
        let lease = Lease::acquire(&stream.leases, &Arc::new(LeaseEnd::default()));
        let (link, base) = stream.join(MemberKind::Concurrent);
        let publication =
            ClientConcurrentPublication::with_lease(inner, stream.allow_unconnected, lease)
                .with_generation(link, base)?;
        self.update_stream_gauges();
        Ok(publication)
    }

    /// Admits a subscriber to the stream (control path: allocates its copy
    /// buffer). The handle holds a stream lease until dropped.
    ///
    /// # Errors
    ///
    /// Returns `ResourcesUnavailable` when the stream's registry or loan
    /// credits are exhausted, [`DriverError::StreamRetiring`] for a removed
    /// stream, and [`DriverError::UnknownStream`] for a foreign handle or a
    /// freed stream.
    pub fn subscribe(
        &mut self,
        stream: StreamHandle,
        role: Role,
    ) -> Result<ClientSubscription, DriverError> {
        let stream = self.active_stream(stream)?;
        stream.issuing()?;
        let inner = stream.conductor.subscribe(role)?;
        let lease = Lease::acquire(&stream.leases, &Arc::new(LeaseEnd::default()));
        let (link, base) = stream.join(MemberKind::Subscriber {
            role,
            cell: inner.cell(),
        });
        let subscription =
            ClientSubscription::with_lease(inner, lease).with_generation(link, base)?;
        self.update_stream_gauges();
        Ok(subscription)
    }

    /// Runs one duty cycle: retires closed clients, serves client commands,
    /// then, on every stream, active or retiring, the commit deadline of its
    /// claim and one conductor duty cycle. Returns commands served plus
    /// claims aborted at their deadline plus slots cleaned plus terms
    /// prepared, a rough measure of work done.
    ///
    /// The clock is read for a stream only once its claim is observed
    /// admitted (`quantstratum-docs: karyos/design/client-claims.md`).
    ///
    /// # Errors
    ///
    /// Returns the first error, after every other stream has still run its
    /// deadline and duty cycle and the gauges were refreshed: a stream
    /// error (a corrupt claim record or a broken conductor invariant), or
    /// [`DriverError::WorkCountOverflow`] when the work count does not fit
    /// `u32`.
    pub fn do_work(&mut self) -> Result<u32, DriverError> {
        #[cfg(target_os = "linux")]
        let admitted = self.serve_admission();
        #[cfg(not(target_os = "linux"))]
        let admitted = 0;
        // Retire before sampling liveness: an orderly close at the
        // deadline is a retirement, not a time-out.
        self.retire_closed_clients();
        let alive = self.serve_liveness();
        self.sweep_ended_registrations();
        self.free_retired_streams();
        let mut work = self
            .serve_commands()
            .saturating_add(admitted)
            .saturating_add(alive);
        let mut first_error = None;
        let clock = &mut self.clock;
        let counters = &self.counters;
        let deadline = self.config.cutover_deadline;
        for stream in &mut self.streams {
            stream.claim_waiting = account_deadlines(
                counters,
                &mut work,
                &mut first_error,
                stream.conductor.service_deadlines(&mut || clock.now()),
            );
            duty(counters, &mut work, &mut first_error, &mut stream.conductor);
            // Predecessors keep their duty until freed: deadlines and
            // retirement while readers drain them.
            for retained in &mut stream.retained {
                let _ = account_deadlines(
                    counters,
                    &mut work,
                    &mut first_error,
                    retained.conductor.service_deadlines(&mut || clock.now()),
                );
                duty(
                    counters,
                    &mut work,
                    &mut first_error,
                    &mut retained.conductor,
                );
            }
            // The clock is read only while a cutover is in progress.
            if stream.cutover.is_some()
                && let Err(error) = stream.advance_cutover(clock.now(), deadline)
            {
                first_error.get_or_insert(error);
            }
            stream.forget_unused();
        }
        if !self.holding.is_empty() {
            self.report_withdrawn_bounds();
        }
        self.update_stream_gauges();
        match first_error {
            Some(error) => Err(error),
            None => Ok(work),
        }
    }

    fn stream(&mut self, stream: StreamHandle) -> Result<&mut Stream, DriverError> {
        let unknown = DriverError::UnknownStream {
            stream: stream.stream,
        };
        if stream.driver != self.id {
            return Err(unknown);
        }
        self.streams
            .iter_mut()
            .find(|s| s.id == stream.stream)
            .ok_or(unknown)
    }

    fn active_stream(&mut self, stream: StreamHandle) -> Result<&mut Stream, DriverError> {
        let found = self.stream(stream)?;
        if found.retiring {
            return Err(DriverError::StreamRetiring { stream: found.id });
        }
        Ok(found)
    }

    pub(crate) fn active_stream_mut(
        &mut self,
        stream: StreamHandle,
    ) -> Result<&mut Stream, DriverError> {
        self.active_stream(stream)
    }

    pub(crate) fn stream_ref(&self, stream: StreamHandle) -> Result<&Stream, DriverError> {
        let unknown = DriverError::UnknownStream {
            stream: stream.stream,
        };
        if stream.driver != self.id {
            return Err(unknown);
        }
        self.streams
            .iter()
            .find(|s| s.id == stream.stream)
            .ok_or(unknown)
    }

    pub(crate) fn clock_now(&mut self) -> u64 {
        self.clock.now()
    }
}

/// One conductor duty cycle, its work added.
fn duty(
    counters: &DriverCounters,
    work: &mut u32,
    first_error: &mut Option<DriverError>,
    conductor: &mut Conductor<Arc<LogBuffer>>,
) {
    match conductor.duty_cycle() {
        Ok(report) => {
            add_work(counters, work, first_error, report.cleaned);
            add_work(counters, work, first_error, u32::from(report.prepared));
            if report.bounds_withdrawn > 0 {
                counters.add(
                    Event::RequiredBoundsWithdrawn,
                    u64::from(report.bounds_withdrawn),
                );
            }
        }
        Err(error) => {
            first_error.get_or_insert(DriverError::from(error));
        }
    }
}

/// Accounts a stream's deadline service call: counts every field of its
/// report, also the one an error carries, adds the aborts to `work`, then
/// records the error (`quantstratum-docs: karyos/design/concurrent-deadline.md`, Results).
/// Returns whether the stream is waiting on a deadline.
/// A publication kind that does not match the stream's mode is the
/// driver's typed refusal; other errors pass through.
fn mode_error(error: karyos_sys::error::SysError) -> DriverError {
    match error {
        karyos_sys::error::SysError::InvalidPublicationMode { .. } => {
            DriverError::InvalidPublicationMode
        }
        other => DriverError::Sys(other),
    }
}

fn account_deadlines(
    counters: &DriverCounters,
    work: &mut u32,
    first_error: &mut Option<DriverError>,
    result: Result<DeadlineReport, DeadlineError>,
) -> bool {
    let (report, error) = match result {
        Ok(report) => (report, None),
        Err(DeadlineError { report, error }) => (report, Some(error)),
    };
    counters.add(Event::ClaimsAborted, u64::from(report.aborted));
    counters.add(Event::ClaimDeadlinesResolved, u64::from(report.resolved));
    counters.add(
        Event::ClaimClockStepsBack,
        u64::from(report.clock_went_back),
    );
    counters.add(
        Event::ClaimDeadlinesUnrepresentable,
        u64::from(report.unrepresentable),
    );
    add_work(counters, work, first_error, report.aborted);
    if let Some(error) = error {
        first_error.get_or_insert(DriverError::from(error));
    }
    report.waiting
}

/// Adds `delta` to a duty cycle's work count with a checked sum
/// (ADR-0007). An overflow leaves the count unchanged, is recorded in
/// `counter overflows` and becomes [`DriverError::WorkCountOverflow`]
/// unless an earlier error is already recorded; the rest of the cycle
/// still runs.
fn add_work(
    counters: &DriverCounters,
    work: &mut u32,
    first_error: &mut Option<DriverError>,
    delta: u32,
) {
    match work.checked_add(delta) {
        Some(sum) => *work = sum,
        None => {
            counters.add(Event::CounterOverflows, 1);
            first_error.get_or_insert(DriverError::WorkCountOverflow {
                count: *work,
                delta,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MonotonicClock;
    use karyos_client::{ClaimOutcome, ClientConductor, CommitOutcome};
    use karyos_protocol::cnc::StreamKey;
    use karyos_sys::error::SysError;
    use karyos_sys::frame::Lane;
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;
    use std::time::Duration;

    #[derive(Debug, Clone, Default)]
    struct ManualClock(Arc<AtomicU64>);

    impl MonotonicClock for ManualClock {
        fn now(&mut self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    fn config(stream_id: i32) -> StreamConfig {
        StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id,
                claim_deadline: 100,
                publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            },
            allow_unconnected: false,
            on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        }
    }

    /// A beat from `observer`, a driver cycle, then the events it took.
    fn observed_work(
        driver: &mut EmbeddedDriver,
        observer: &mut ClientConductor,
    ) -> Vec<karyos_protocol::cnc::Event> {
        let _ = observer.poll(usize::MAX, |_| {});
        let _ = driver.do_work().unwrap();
        let _ = observer.poll(usize::MAX, |_| {});
        observer.take_events().collect()
    }

    #[test]
    fn a_lost_hold_reader_with_a_loan_reports_the_withdrawal_when_the_loan_ends() {
        use karyos_protocol::cnc::{Event as DriverEvent, LossPolicyCode, SubscriberRole};
        let clock = ManualClock::default();
        let driver_config = DriverConfig {
            heartbeat_interval: 10,
            client_liveness_timeout: 100,
            ..DriverConfig::default()
        };
        let mut driver =
            EmbeddedDriver::with_clock(driver_config, Box::new(clock.clone())).unwrap();
        let stream = driver.add_stream(config(2)).unwrap();
        let mut observer = driver.connect().unwrap();
        observer.set_liveness(Duration::ZERO, Duration::from_secs(3600));
        let mut client = driver.connect().unwrap();
        let key = StreamKey {
            stream_id: 2,
            session_id: 1,
        };
        let _ = client
            .add_subscription(key, SubscriberRole::Required)
            .unwrap();
        // The completion owns the subscription: keep it alive.
        let mut done = Vec::new();
        while done.is_empty() {
            assert!(observed_work(&mut driver, &mut observer).is_empty());
            let _ = client.poll(usize::MAX, |completion| done.push(completion));
        }
        let cell = driver
            .registrations
            .iter()
            .find_map(|registration| registration.subscriber)
            .unwrap()
            .0;
        let buffer = Arc::clone(&driver.stream(stream).unwrap().buffer);
        assert!(buffer.hold_read_loan(cell));
        assert!(observed_work(&mut driver, &mut observer).is_empty());
        clock.0.store(100, Ordering::Relaxed);
        let lost = observed_work(&mut driver, &mut observer);
        assert!(
            matches!(
                lost.as_slice(),
                [DriverEvent::ParticipantLost {
                    policy: LossPolicyCode::Hold,
                    ..
                }]
            ),
            "{lost:?}"
        );
        // The bound holds while the loan does.
        assert!(observed_work(&mut driver, &mut observer).is_empty());
        assert_eq!(driver.holding.len(), 1);
        buffer.release_read_loan(cell);
        let withdrawn = observed_work(&mut driver, &mut observer);
        assert!(
            matches!(
                withdrawn.as_slice(),
                [DriverEvent::RequiredBoundWithdrawn { stream, .. }] if *stream == key
            ),
            "{withdrawn:?}"
        );
        assert!(driver.holding.is_empty());
        assert!(observed_work(&mut driver, &mut observer).is_empty());
    }

    #[test]
    fn a_client_keeps_the_newest_events_and_counts_the_dropped_ones() {
        use karyos_client::EVENT_QUEUE;
        use karyos_protocol::cnc::{CloseReason, Event as DriverEvent};
        let mut driver = EmbeddedDriver::new().unwrap();
        let mut observer = driver.connect().unwrap();
        let extra = 6;
        for stream_id in 0..i32::try_from(EVENT_QUEUE + extra).unwrap() {
            driver.emit(&DriverEvent::PublicationClosed {
                stream: StreamKey {
                    stream_id,
                    session_id: 1,
                },
                reason: CloseReason::RequiredParticipantLost,
            });
        }
        let _ = observer.poll(usize::MAX, |_| {});
        assert_eq!(observer.events_dropped(), u64::try_from(extra).unwrap());
        let events: Vec<_> = observer.take_events().collect();
        assert_eq!(events.len(), EVENT_QUEUE);
        // The oldest were dropped: the first kept is the seventh sent.
        assert!(matches!(
            events[0],
            DriverEvent::PublicationClosed { stream, .. } if stream.stream_id == 6
        ));
        assert_eq!(observer.take_events().count(), 0);
    }

    #[test]
    fn a_failing_stream_does_not_stop_the_next_one() {
        let clock = ManualClock::default();
        let mut driver =
            EmbeddedDriver::with_clock(DriverConfig::default(), Box::new(clock.clone())).unwrap();
        let broken = driver.add_stream(config(2)).unwrap();
        let healthy = driver.add_stream(config(3)).unwrap();
        let _subscription = driver.subscribe(healthy, Role::Optional).unwrap();
        let mut publication = driver.publication(healthy).unwrap();
        let ClaimOutcome::Claimed(claim) = publication.try_claim(8).unwrap() else {
            panic!("not claimed");
        };
        let _ = driver.do_work().unwrap();
        driver
            .stream(broken)
            .unwrap()
            .buffer
            .inject_deadline_fault();
        clock.0.store(100, Ordering::Relaxed);
        // The broken stream, first in order, reports its error only after
        // the healthy one still ran its deadline and duty cycle.
        assert!(matches!(driver.do_work(), Err(DriverError::Sys(_))));
        assert!(matches!(claim.commit(), CommitOutcome::Aborted { .. }));
    }

    #[test]
    fn an_overflowing_work_count_is_a_typed_error() {
        let counters = DriverCounters::new().unwrap();
        let mut work = u32::MAX - 1;
        let mut error = None;
        add_work(&counters, &mut work, &mut error, 1);
        assert_eq!((work, error.is_none()), (u32::MAX, true));
        add_work(&counters, &mut work, &mut error, 0);
        assert_eq!((work, error.is_none()), (u32::MAX, true));
        add_work(&counters, &mut work, &mut error, 2);
        assert_eq!(work, u32::MAX);
        assert!(matches!(
            error,
            Some(DriverError::WorkCountOverflow {
                count: u32::MAX,
                delta: 2,
            })
        ));
        assert_eq!(counters.value(Event::CounterOverflows), 1);
        // A later overflow is counted; the first error is kept.
        add_work(&counters, &mut work, &mut error, 3);
        assert!(matches!(
            error,
            Some(DriverError::WorkCountOverflow { delta: 2, .. })
        ));
        assert_eq!(counters.value(Event::CounterOverflows), 2);
    }

    #[test]
    fn a_deadline_error_counts_its_report_and_leaves_the_gauge() {
        let clock = ManualClock::default();
        let mut driver =
            EmbeddedDriver::with_clock(DriverConfig::default(), Box::new(clock.clone())).unwrap();
        let stream = driver.add_stream(config(2)).unwrap();
        let _subscription = driver.subscribe(stream, Role::Optional).unwrap();
        let mut publication = driver.publication(stream).unwrap();
        let ClaimOutcome::Claimed(claim) = publication.try_claim(8).unwrap() else {
            panic!("not claimed");
        };
        assert_eq!(driver.do_work().unwrap(), 0);
        assert_eq!(driver.counters.value(Event::ClaimsWaiting), 1);
        driver
            .stream(stream)
            .unwrap()
            .buffer
            .inject_deadline_fault();
        clock.0.store(100, Ordering::Relaxed);
        assert!(matches!(
            driver.do_work(),
            Err(DriverError::Sys(SysError::ResourcesUnavailable))
        ));
        // The error carries an empty report: nothing counted, not waiting.
        assert_eq!(driver.counters.value(Event::ClaimsWaiting), 0);
        assert_eq!(driver.counters.value(Event::ClaimsAborted), 0);
        assert!(matches!(claim.commit(), CommitOutcome::Accepted { .. }));
    }

    #[test]
    fn every_report_field_is_counted_also_from_an_error() {
        let counters = DriverCounters::new().unwrap();
        let report = DeadlineReport {
            aborted: 3,
            aborted_bytes: 96,
            resolved: 2,
            clock_went_back: 4,
            unrepresentable: 5,
            waiting: true,
        };
        let counted = |counters: &DriverCounters| {
            [
                Event::ClaimsAborted,
                Event::ClaimDeadlinesResolved,
                Event::ClaimClockStepsBack,
                Event::ClaimDeadlinesUnrepresentable,
            ]
            .map(|event| counters.value(event))
        };
        let mut work = 10;
        let mut error = None;
        assert!(account_deadlines(
            &counters,
            &mut work,
            &mut error,
            Ok(report)
        ));
        assert_eq!((work, error.is_none()), (13, true));
        assert_eq!(counted(&counters), [3, 2, 4, 5]);
        let mut work = u32::MAX - 1;
        assert!(account_deadlines(
            &counters,
            &mut work,
            &mut error,
            Err(DeadlineError {
                report,
                error: SysError::ResourcesUnavailable,
            }),
        ));
        // The report is counted first; the work overflow is the first error.
        assert_eq!(counted(&counters), [6, 4, 8, 10]);
        assert_eq!(work, u32::MAX - 1);
        assert!(matches!(
            error,
            Some(DriverError::WorkCountOverflow { delta: 3, .. })
        ));
        let mut work = 0;
        let mut error = None;
        assert!(account_deadlines(
            &counters,
            &mut work,
            &mut error,
            Err(DeadlineError {
                report,
                error: SysError::ResourcesUnavailable,
            }),
        ));
        assert_eq!(counted(&counters), [9, 6, 12, 15]);
        assert_eq!(work, 3);
        assert!(matches!(
            error,
            Some(DriverError::Sys(SysError::ResourcesUnavailable))
        ));
        assert_eq!(counters.value(Event::CounterOverflows), 1);
    }
}
