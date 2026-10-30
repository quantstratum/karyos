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

use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::link::{Lease, LeaseEnd, StreamLeases};
use karyos_client::{
    ClientConcurrentPublication, ClientPublication, ClientSubscription, ConflatedSubscription,
    GenerationLink, MessageLimit,
};
use karyos_protocol::cnc::{CloseReason, Event as DriverEvent, MAX_RESPONSE_LENGTH, StreamKey};
use karyos_protocol::lanes::drr::{DrrConfig, MAX_LANES};
use karyos_protocol::trace_hook::PublicationIdentity;
use karyos_sys::broadcast::{BroadcastTransmitter, HEADER_LENGTH, broadcast};
use karyos_sys::conflation::{
    Budget as ConflationBudget, ConflationConfig, ConflationError, ConflationWriter, conflation,
};
use karyos_sys::counters::{Counter, CounterKeys, KIND_NONE};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    Conductor, DeadlineError, DeadlineReport, LogBuffer, LogBufferConfig, LossPolicy, Publication,
    Role, SealReason, SealState,
};
use karyos_sys::term::{Generation, TermId};
#[cfg(target_os = "linux")]
use karyos_sys::term_bytes::SharedTerms;
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use crate::client_counters::ClientCounters;
use crate::clock::{MonotonicClock, SystemClock};
use crate::commands::ClientSlot;
use crate::counters::{DriverCounters, Event, TYPE_EVENTS};
use crate::error::{DriverError, WalkerUnavailable};
use crate::generations::{Cutover, Member, MemberKind, Retained};
use crate::guards::GuardHandle;

/// The term backing of a driver's streams (`quantstratum-docs:
/// karyos/design/ipc-data-path.md`, Terms in the types): heap words for an
/// embedded driver, shared regions for a driver in IPC mode, whose
/// in-process clients use the same shared terms, so one stream never has
/// two backings. Sealed: only the driver creates streams.
pub trait StreamTerms: TermBytes + sealed::Create {}

impl StreamTerms for HeapTerms {}
#[cfg(target_os = "linux")]
impl StreamTerms for SharedTerms {}

pub(crate) mod sealed {
    use karyos_sys::log_buffer::{ConflationShape, LogBuffer, LogBufferConfig};
    use karyos_sys::term::Generation;
    use karyos_sys::term_bytes::TermBytes;

    use crate::embedded::{EmbeddedDriver, StreamTerms};
    use crate::error::DriverError;

    /// `buffer` with the shape of its stream's conflation table written in
    /// its configuration block, before it is shared (F7b-2c-2).
    fn shaped<T: TermBytes>(
        buffer: LogBuffer<T>,
        conflation: Option<ConflationShape>,
    ) -> Result<LogBuffer<T>, DriverError> {
        Ok(match conflation {
            Some(shape) => buffer.with_conflation(shape)?,
            None => buffer,
        })
    }

    /// Creates a stream's log buffer on the driver's backing.
    pub trait Create: Sized {
        /// A log buffer of `generation` for `config`, carrying the shape of
        /// the stream's conflation table, if it has one.
        fn create(
            driver: &mut EmbeddedDriver<Self>,
            config: LogBufferConfig,
            generation: Generation,
            conflation: Option<ConflationShape>,
        ) -> Result<LogBuffer<Self>, DriverError>
        where
            Self: StreamTerms;

        /// The shared region of `buffer`, which a fetch exports; `None` on
        /// the heap.
        #[cfg(target_os = "linux")]
        fn region(buffer: &LogBuffer<Self>) -> Option<&karyos_sys::ipc::Region>
        where
            Self: StreamTerms;

        /// An image lane for `config` at generation 0 from `source`
        /// (network-shared-terms N-2): on the heap, or in a new region of
        /// the driver's admission.
        fn image_lane(
            source: &mut crate::agents::images::LaneSource<'_>,
            config: LogBufferConfig,
        ) -> Result<LogBuffer<Self>, DriverError>
        where
            Self: StreamTerms;
    }

    impl Create for karyos_sys::term_bytes::HeapTerms {
        fn create(
            _driver: &mut EmbeddedDriver<Self>,
            config: LogBufferConfig,
            generation: Generation,
            conflation: Option<ConflationShape>,
        ) -> Result<LogBuffer<Self>, DriverError> {
            shaped(
                LogBuffer::new_with_generation(config, generation)?,
                conflation,
            )
        }

        #[cfg(target_os = "linux")]
        fn region(_buffer: &LogBuffer<Self>) -> Option<&karyos_sys::ipc::Region> {
            None
        }

        fn image_lane(
            _source: &mut crate::agents::images::LaneSource<'_>,
            config: LogBufferConfig,
        ) -> Result<LogBuffer<Self>, DriverError> {
            Ok(LogBuffer::new(config)?)
        }
    }

    #[cfg(target_os = "linux")]
    impl Create for karyos_sys::term_bytes::SharedTerms {
        fn create(
            driver: &mut EmbeddedDriver<Self>,
            config: LogBufferConfig,
            generation: Generation,
            conflation: Option<ConflationShape>,
        ) -> Result<LogBuffer<Self>, DriverError> {
            let admission = driver
                .admission
                .as_mut()
                .ok_or(DriverError::InvalidConfig)?;
            let (instance, region) = admission.next_region()?;
            shaped(
                LogBuffer::create_in(instance, region, config, generation)?,
                conflation,
            )
        }

        fn region(buffer: &LogBuffer<Self>) -> Option<&karyos_sys::ipc::Region> {
            buffer.region()
        }

        fn image_lane(
            source: &mut crate::agents::images::LaneSource<'_>,
            config: LogBufferConfig,
        ) -> Result<LogBuffer<Self>, DriverError> {
            // An IPC driver always lends its admission's region ids.
            let (instance, region) = source.next_region().ok_or(DriverError::InvalidConfig)??;
            Ok(LogBuffer::create_in(
                instance,
                region,
                config,
                Generation::default(),
            )?)
        }
    }
}

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
    /// Bytes of each client's command ring, a power of two whose largest
    /// record (an eighth of it) carries the largest command with its
    /// header: at least 8192 bytes (a URI command, W5a).
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
    /// Maximum log messages copied into the keyed conflation table per
    /// conductor duty cycle.
    pub conflation_feeder_budget: NonZeroU32,
    /// Key reads and retries per [`ConflatedSubscription`] poll.
    pub conflated_subscription_budget: ConflationBudget,
    /// Cells of the counters region: the fixed driver counters plus the
    /// per-stream and per-subscriber position cells. At least the number of
    /// fixed counters; positions that find no free cell are shown as
    /// unavailable and counted in `counters unavailable`.
    pub counters_capacity: usize,
    /// How often the driver samples stream positions into the counters
    /// region, in host `CLOCK_MONOTONIC` nanoseconds, the clock of
    /// `positions sampled at`
    /// (`quantstratum-docs: karyos/design/observability-and-tools.md`).
    /// The driver's injectable clock is not read for it, so it is read only
    /// for deadlines.
    pub position_sample_interval: u64,
    /// Records of the error log
    /// (`quantstratum-docs: karyos/design/observability-and-tools.md`).
    pub error_log_records: usize,
    /// Records of the loss report.
    pub loss_report_records: usize,
    /// How long after its last occurrence a repeated error updates its
    /// record instead of writing a new one, in host `CLOCK_MONOTONIC`
    /// nanoseconds.
    pub error_dedup_window: u64,
    /// Cells of the client counters region, which clients allocate with
    /// `AllocateCounter` (`quantstratum-docs:
    /// karyos/design/observability-and-tools.md`, "Client counters").
    pub client_counters_capacity: usize,
    /// Client counter cells one client holds at once; an allocation beyond
    /// it is refused with `ResourcesUnavailable`.
    pub max_counters_per_client: usize,
    /// Application trace points one client holds at once (R-CORE-1,
    /// `quantstratum-docs: karyos/design/trace-records.md`, "Point names");
    /// a registration beyond it is refused with `ResourcesUnavailable`.
    /// Its cells also count against `max_counters_per_client`.
    pub max_trace_points_per_client: usize,
    /// Application trace points one client registers over its life, live
    /// or dropped: since ids are never reused, it keeps one client from
    /// using up the instance's ids. Beyond it, `ResourcesUnavailable`.
    pub max_trace_point_registrations_per_client: usize,
    /// Entries of the trace mirror's journal table (`quantstratum-docs:
    /// karyos/design/trace-journal-region.md`): the open client trace
    /// journals plus the ended ones whose records the mirror's ring still
    /// retains, or that are still needed and cannot be logged (see
    /// `trace_recycle_log_entries`). A `TraceJournal` that finds no free
    /// entry is refused with `TraceJournalsExhausted`.
    pub max_trace_journals: usize,
    /// Entries of the trace mirror's recycle log (`quantstratum-docs:
    /// karyos/design/trace-tool.md`, T5): one per recycled subscriber
    /// journal that a pending or retained `Publish` record may still need.
    /// With the log full, such an entry is not reused until no record
    /// needs it, so a `TraceJournal` may be refused with
    /// `TraceJournalsExhausted`.
    pub trace_recycle_log_entries: usize,
    /// Bytes of every client trace journal the driver holds at once, each
    /// counted as its whole region (header included); a `TraceJournal`
    /// beyond it is refused with `ResourcesUnavailable`.
    pub max_trace_journal_bytes: u64,
    /// Bytes of every network trace journal the driver holds at once
    /// (`quantstratum-docs: karyos/design/trace-network.md`, NT-3), each
    /// counted as its whole region; a network journal beyond it is refused
    /// and counted, never created.
    pub max_network_journal_bytes: u64,
    /// Records of each network trace journal, a power of two; each record
    /// is `karyos_protocol::trace_hook::TRACE_RECORD_WORDS` wide.
    pub network_journal_records: usize,
    /// Journal records the driver copies into the trace mirror per duty
    /// cycle, over all journals.
    pub trace_drain_budget: usize,
    /// Records of the trace mirror's ring.
    pub trace_mirror_records: usize,
    /// Guards configured at once (`quantstratum-docs:
    /// karyos/design/guards-and-abort.md`).
    pub max_guards: usize,
    /// Blocks each guard walker reads per duty cycle.
    pub guard_walker_budget: u32,
    /// Records of the guard audit ring (G9 interim); a full ring overwrites
    /// its oldest record and counts it. Zero keeps only the count.
    pub guard_audit_records: usize,
    /// Sender gates registered with their guards' owner at once
    /// (`EmbeddedDriver::register_guard_sender`).
    pub max_guard_senders: usize,
    /// How long, in the driver clock's unit, a sender may take to apply a
    /// close before the effective-close acknowledgement reports it overdue;
    /// it is still pending, never closed (guards-and-abort.md). Nonzero.
    pub guard_ack_timeout: u64,
    /// How long, in the driver clock's unit, the host has to declare its
    /// startup complete ([`EmbeddedDriver::startup_complete`]) before the
    /// driver's readiness is failed with
    /// [`FailedReason::StartupDeadline`] (R-CORE-35). Nonzero; 30 s by
    /// default.
    pub startup_timeout: u64,
    /// The most bytes one stream lane may take (R-CORE-34): its log buffer
    /// region, header included, plus its conflation table's region if it
    /// has one, by the functions that size them. Every lane the driver
    /// creates is checked against it: `add_stream`, `add_aggregate`,
    /// network publications, replay targets, a reincarnation and a
    /// reconfiguration's successor. A larger one is refused with
    /// [`DriverError::StreamTooLarge`] and nothing is created. `None`, the
    /// default, bounds nothing; `Some(0)` is refused. Network image lanes
    /// have their own budget, `ImageTemplate::storage_budget`.
    pub max_stream_bytes: Option<u64>,
    /// The network agents (`quantstratum-docs:
    /// karyos/design/driver-network-agents.md`); `None`, the default, for
    /// a driver without network channels. In
    /// [`crate::agents::ThreadingMode::Shared`] the duty cycle drives them
    /// with the driver clock, which must then count nanoseconds. An IPC
    /// driver creates each image lane in a shared region that holds a
    /// descriptor, so its start checks `RLIMIT_NOFILE` against its bounds
    /// (`max_images` times four lanes, plus `max_streams` times one more
    /// than `max_retained_generations`, plus three per client) and fails
    /// with [`DriverError::DescriptorLimit`] below them, naming the soft and
    /// the hard limit.
    pub network: Option<crate::net::NetworkConfig>,
    /// Tests only: the `initial_term_id` of every local publication, in
    /// place of the draw. `None`, the default, draws a random one on the
    /// control path for each publication (SPEC §4, initial state); network
    /// publications take theirs from
    /// [`crate::net::NetworkStreamDefaults::initial_term_id`].
    #[doc(hidden)]
    pub initial_term_id: Option<u32>,
}

impl DriverConfig {
    /// Checks the configuration as a driver does when it is created: every
    /// limit nonzero, the rings and the broadcast buffer large enough, the
    /// network configuration valid. The sizing report checks it the same
    /// way, so it never sizes a configuration a driver refuses.
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidConfig`].
    pub fn validate(&self) -> Result<(), DriverError> {
        let needed = RESPONSE_EXTENT
            .checked_mul(2)
            .and_then(|n| n.checked_mul(self.command_budget))
            .and_then(|n| n.checked_mul(self.cycles_between_drains))
            .ok_or(DriverError::InvalidConfig)?;
        let valid = self.max_clients > 0
            && self.max_streams > 0
            && self.max_retained_generations > 0
            && self.counters_capacity >= crate::counters::FIXED_COUNTERS
            && self.position_sample_interval > 0
            && self.error_log_records > 0
            && self.loss_report_records > 0
            && self.client_counters_capacity > 0
            && self.max_counters_per_client > 0
            && self.max_trace_points_per_client > 0
            && self.max_trace_point_registrations_per_client > 0
            && self.max_trace_journals > 0
            && self.trace_recycle_log_entries > 0
            && self.max_trace_journal_bytes > 0
            && self.max_network_journal_bytes > 0
            && self.network_journal_records.is_power_of_two()
            && self.trace_drain_budget > 0
            && self.trace_mirror_records > 0
            && self.cutover_deadline > 0
            && self.startup_timeout > 0
            && self.max_stream_bytes != Some(0)
            && self.heartbeat_interval > 0
            && self
                .heartbeat_interval
                .checked_mul(10)
                .is_some_and(|minimum| self.client_liveness_timeout >= minimum)
            && self.max_pending_per_client > 0
            && self.max_hand_over > 0
            && self.command_budget > 0
            && self.cycles_between_drains > 0
            && self.ring_capacity >= karyos_sys::command_ring::MIN_CAPACITY
            && self.ring_capacity.is_power_of_two()
            && karyos_protocol::cnc::MAX_COMMAND_LENGTH
                .checked_add(HEADER_LENGTH as usize)
                .is_some_and(|record| self.ring_capacity / 8 >= record)
            && self.broadcast_capacity >= needed
            && self.guard_ack_timeout > 0
            && self.network.is_none_or(|network| {
                crate::net::client::valid_network(&network, self.max_clients)
            });
        if valid {
            Ok(())
        } else {
            Err(DriverError::InvalidConfig)
        }
    }
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            max_clients: 16,
            max_pending_per_client: 16,
            max_hand_over: 64,
            command_budget: 64,
            cycles_between_drains: 2,
            // The smallest power of two whose largest record carries a
            // command with a 512-byte channel URI (W5a, SPEC §18).
            ring_capacity: 8192,
            // Room for two cycles of `command_budget` responses of the
            // largest extent (`ConflatedReady`), with headroom.
            broadcast_capacity: 32 * 1024,
            max_streams: 64,
            max_retained_generations: 2,
            cutover_deadline: 1_000_000_000,
            heartbeat_interval: 100_000_000,
            client_liveness_timeout: 10_000_000_000,
            conflation_feeder_budget: match NonZeroU32::new(1024) {
                Some(value) => value,
                None => NonZeroU32::MIN,
            },
            conflated_subscription_budget: ConflationBudget::new(1024, 3),
            counters_capacity: 1024,
            position_sample_interval: 10_000_000,
            error_log_records: karyos_sys::diag::DEFAULT_ERROR_RECORDS,
            loss_report_records: karyos_sys::diag::DEFAULT_LOSS_RECORDS,
            error_dedup_window: 1_000_000_000,
            client_counters_capacity: 1024,
            max_counters_per_client: 64,
            max_trace_points_per_client: 16,
            max_trace_point_registrations_per_client: 256,
            max_trace_journals: 64,
            trace_recycle_log_entries: 64,
            // Provisional until the trace overhead numbers of P11.
            max_trace_journal_bytes: 64 * 1024 * 1024,
            max_network_journal_bytes: 64 * 1024 * 1024,
            network_journal_records: 4096,
            trace_drain_budget: 1024,
            trace_mirror_records: 4096,
            max_guards: 16,
            guard_walker_budget: 1024,
            guard_audit_records: 1024,
            max_guard_senders: 64,
            guard_ack_timeout: 1_000_000_000,
            startup_timeout: 30_000_000_000,
            max_stream_bytes: None,
            network: None,
            initial_term_id: None,
        }
    }
}

/// Bytes of the largest response record: header plus payload.
const RESPONSE_EXTENT: usize = HEADER_LENGTH as usize + MAX_RESPONSE_LENGTH;

/// Where the host's startup stands (R-CORE-35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Startup {
    /// Not yet declared complete, within the deadline.
    Pending,
    /// Declared complete in time.
    Complete,
    /// Not declared complete in time; it does not end.
    Failed,
}

/// A driver's readiness for a probe (R-CORE-35;
/// [`EmbeddedDriver::readiness`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Readiness {
    /// The host has not declared its startup complete, within the deadline.
    Starting,
    /// A client would be admitted now, into no cutover.
    Ready,
    /// Admitting, but a stream still retains a predecessor mapping after a
    /// cutover: traffic routed now would meet the cutover.
    Recovering,
    /// Not admitting a client now.
    NotReady(NotReadyReason),
    /// Startup failed; it does not end.
    Failed(FailedReason),
}

/// Why a driver is not ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotReadyReason {
    /// [`EmbeddedDriver::stop_admitting`]: an orderly shutdown.
    NotAdmitting,
    /// The driver holds `max_clients` clients.
    Full,
    /// The driver is terminal.
    Terminal,
}

impl Readiness {
    /// The state and reason codes of `karyos_protocol::admission::probe`,
    /// the one mapping a probe's answer and the C ABI share.
    #[must_use]
    pub fn wire(self) -> (u64, u64) {
        use karyos_protocol::admission::probe;
        match self {
            Self::Starting => (probe::STARTING, probe::NONE),
            Self::Ready => (probe::READY, probe::NONE),
            Self::Recovering => (probe::RECOVERING, probe::NONE),
            Self::NotReady(why) => (
                probe::NOT_READY,
                match why {
                    NotReadyReason::NotAdmitting => probe::NOT_ADMITTING,
                    NotReadyReason::Full => probe::FULL,
                    NotReadyReason::Terminal => probe::TERMINAL,
                },
            ),
            Self::Failed(FailedReason::StartupDeadline) => (probe::FAILED, probe::STARTUP_DEADLINE),
        }
    }
}

/// Why a driver's startup failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailedReason {
    /// [`EmbeddedDriver::startup_complete`] was not called within
    /// [`DriverConfig::startup_timeout`].
    StartupDeadline,
}

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
    /// Optional keyed conflation table, fed by a required subscriber.
    pub conflation: Option<ConflationConfig>,
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

/// The configuration of an aggregate publication of one to four lanes
/// (SPEC.md §7.4; `quantstratum-docs: karyos/design/aggregate-ownership.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateConfig {
    /// The configuration every lane shares; lane `l` is lane `l`, whatever
    /// `stream.buffer.lane` says.
    pub stream: StreamConfig,
    /// One deficit round robin quantum per lane, lane 0 first: their count,
    /// 1 to 4, is the number of lanes. Each must be at least the largest
    /// charged frame (the MTU aligned to 32 bytes).
    pub quanta: Vec<u64>,
}

/// Names an aggregate publication and its lanes. Each lane is a stream with
/// its own [`StreamHandle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AggregateHandle {
    driver: u64,
    /// Lane 0's stream id, the aggregate's registration.
    registration: u64,
    /// The stream id of each configured lane, by lane number.
    lanes: [Option<u64>; MAX_LANES],
}

impl AggregateHandle {
    /// The number of lanes.
    #[must_use]
    pub fn lanes(&self) -> u8 {
        self.lanes
            .iter()
            .filter(|lane| lane.is_some())
            .count()
            .try_into()
            .unwrap_or(0)
    }

    /// The stream of `lane`; `None` for a lane this aggregate does not have.
    #[must_use]
    pub fn lane(&self, lane: Lane) -> Option<StreamHandle> {
        let stream = (*self.lanes.get(usize::from(lane.get()))?)?;
        Some(StreamHandle {
            driver: self.driver,
            stream,
        })
    }

    /// The aggregate's registration: lane 0's stream id.
    pub(crate) fn registration(&self) -> u64 {
        self.registration
    }

    /// The streams of every lane, lane 0 first.
    pub(crate) fn streams(&self) -> impl Iterator<Item = StreamHandle> + '_ {
        self.lanes.iter().flatten().map(|stream| StreamHandle {
            driver: self.driver,
            stream: *stream,
        })
    }
}

/// What the lanes of one aggregate share, kept by each lane stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Aggregate {
    /// The aggregate's registration: lane 0's stream id, or the only lane's
    /// for a stream added with [`EmbeddedDriver::add_stream`]. Every field
    /// that names the publication carries it with the lane.
    pub(crate) registration: u64,
    /// The number of lanes.
    pub(crate) lanes: u8,
    /// The validated scheduling profile.
    pub(crate) profile: DrrConfig,
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

/// A local stream (`add_stream`, `add_aggregate`) refuses a schedule ring:
/// it has no sender to release one, so a timed lane there would take
/// `schedule_capacity` offers and then back pressure for good (owner item
/// 65). Timed lanes are network publications'
/// (`add_timed_network_publication`, or a timed network stream of
/// `NetworkStreamDefaults::timed`).
fn local_schedule(config: &StreamConfig) -> Result<(), DriverError> {
    if config.buffer.schedule_capacity > 0 {
        return Err(DriverError::InvalidConfig);
    }
    Ok(())
}

/// The largest charged frame of a lane of `config` (aggregate-lanes.md,
/// charged bytes): a frame never exceeds the MTU, aligned to 32 bytes.
fn largest_charge(config: &StreamConfig) -> Result<u64, DriverError> {
    charge_of(config.buffer.mtu).ok_or(DriverError::InvalidConfig)
}

/// The bound a sender gate validates a rate policy against for a stream of
/// `mtu` (R-CORE-21): [`charge_of`]. An MTU no frame aligns never reaches
/// a gate (its add was refused), so the MTU itself stands in for it.
fn gate_bound(mtu: u32) -> u64 {
    charge_of(mtu).unwrap_or(u64::from(mtu))
}

/// The largest charge of a frame on a stream of `mtu`, the MTU aligned to
/// 32 bytes: [`largest_charge`]'s, and the bound a sender gate validates a
/// rate policy against (R-CORE-21); `None` for an MTU no frame aligns.
fn charge_of(mtu: u32) -> Option<u64> {
    karyos_sys::sizing::align_frame(mtu).ok().map(u64::from)
}

/// Source of driver identities within the process.
static NEXT_DRIVER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct Stream<T: StreamTerms> {
    pub(crate) id: u64,
    /// Where a network image's lane comes from; `None` for a local stream,
    /// a network publication's lane and a replay target
    /// (`quantstratum-docs: karyos/design/per-source-images.md`, D2-1).
    pub(crate) source: Option<crate::net::ImageSource>,
    /// A replay target's lane: no source, and its key is its own while it
    /// lives, retiring included (#283 P3; karyos#490).
    pub(crate) replay: bool,
    /// The aggregate this lane belongs to.
    pub(crate) aggregate: Aggregate,
    pub(crate) retiring: bool,
    pub(crate) buffer: Arc<LogBuffer<T>>,
    pub(crate) conductor: Conductor<Arc<LogBuffer<T>>>,
    pub(crate) leases: Arc<StreamLeases>,
    /// Its configuration's `allow_unconnected`: every exclusive or
    /// concurrent publication of the stream offers with no subscriber, an
    /// in-process client's included (SPEC.md §4).
    pub(crate) allow_unconnected: bool,
    /// The stream's `on_required_loss` policy.
    pub(crate) policy: LossPolicy,
    pub(crate) stream_id: i32,
    pub(crate) session_id: i32,
    /// Whether the latest deadline call returned `Waiting`.
    claim_waiting: bool,
    /// The current mapping's configuration and generation, and the stream
    /// position where it starts (`quantstratum-docs: karyos/design/mapping-generations.md`).
    pub(crate) config: LogBufferConfig,
    /// The optional keyed conflation configuration shared by publishers.
    pub(crate) conflation: Option<ConflationConfig>,
    pub(crate) generation: Generation,
    pub(crate) base: u64,
    /// The generation links of the handles on the current mapping.
    pub(crate) members: Vec<Member<T>>,
    /// The cutover in progress, if any.
    pub(crate) cutover: Option<Cutover<T>>,
    /// Predecessor mappings still referenced, oldest first.
    pub(crate) retained: Vec<Retained<T>>,
    /// The current mapping's exclusive publication, returned by a fence,
    /// for the next issuance.
    pub(crate) spare: Option<Publication<Arc<LogBuffer<T>>>>,
    /// The required subscriber and keyed table writer, when conflation is
    /// configured. The table itself survives mapping generations.
    pub(crate) feeder: Option<ConflationFeeder<T>>,
    /// A network image lane's view its terminal cell closed: the closed
    /// table and the terminal, kept to seed the view's recreation
    /// (karyos#658) and released when it is recreated, the image retires or
    /// the driver closes. Its feeder's subscription is gone, so it holds no
    /// position of the lane.
    pub(crate) closed_view: Option<ClosedView>,
    /// Terminal table failure that sealed this stream. Kept for internal
    /// lifecycle state until the public seal reason is designed.
    pub(crate) conflation_terminal: Option<karyos_sys::conflation::ConflationError>,
    /// The feeder's counters, when conflation is configured. They outlive
    /// the feeder and are freed with the stream.
    pub(crate) feeder_counters: Option<FeederCounters>,
    /// The guard binding and walker of a guarded stream
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`).
    pub(crate) guarded: Option<crate::guard_streams::GuardedStream<T>>,
    /// The current incarnation of the stream's publication: from
    /// [`FIRST_INCARNATION`], the next one after each guard close and
    /// reopen (`quantstratum-docs: karyos/design/guards-and-abort.md`,
    /// The fresh incarnation), never reused within the registration.
    pub(crate) incarnation: u64,
    /// When the current incarnation began, past the first: host monotonic
    /// nanoseconds, written in each of its handles' rings
    /// (`outcome_ring::REINCARNATED_AT`), so a handle's rate copy starts
    /// where the reincarnation's gate did (R-CORE-21); 0 for the first.
    pub(crate) reincarnated_at: u64,
    /// Tests: how much earlier than now the next reincarnation is stamped
    /// ([`EmbeddedDriver::backdate_next_reincarnation`]); 0 otherwise.
    pub(crate) reincarnation_backdate: u64,
    /// Incarnations a guard close sealed and a fresh incarnation replaced,
    /// retiring: served until their walker ended and their readers passed
    /// the seal.
    pub(crate) replaced: Vec<Replaced<T>>,
    /// Whether it is a lane of a network publication, and whether its
    /// sender serves the current incarnation: such a lane reincarnates
    /// only through the network, never locally.
    pub(crate) network: NetworkLane,
    /// A timed lane's settings (`quantstratum-docs:
    /// karyos/design/timed-tx.md`); the defaults when not set.
    pub(crate) schedule: Option<karyos_client::schedule::ScheduleOptions>,
    /// A handle of this incarnation's timed lane was issued: its settings
    /// are fixed from then on, even after the handle is dropped, since its
    /// entries stay in the ring (#234 P3).
    pub(crate) schedule_issued: bool,
    /// A timed lane's clock, when not the host's clock of its domain
    /// ([`EmbeddedDriver::schedule_stream_with_clock`]).
    pub(crate) schedule_clock: Option<karyos_client::schedule::ScheduleClock>,
    /// A timed lane's counters, allocated when its first handle is
    /// prepared, once its settings are final: the offer counters its
    /// handles share and the sender's.
    pub(crate) timed_counters: Option<TimedCounters>,
}

/// A timed lane's counter cells (`quantstratum-docs:
/// karyos/design/timed-tx.md`, section 6).
#[derive(Debug, Clone)]
pub(crate) struct TimedCounters {
    offers: Arc<karyos_client::schedule::ScheduleCounters>,
    sender: Arc<crate::timed_gate::TimedLaneCounters>,
}

impl TimedCounters {
    /// The cells of `stream`'s `lane`, labelled with its clock `domain`;
    /// a cell the region has no room for is `None`, counted in `counters
    /// unavailable`.
    fn allocate(
        counters: &mut DriverCounters,
        stream: u64,
        lane: u8,
        domain: karyos_client::schedule::ClockDomain,
    ) -> Self {
        let keys = CounterKeys {
            stream,
            lane,
            kind: KIND_NONE,
            participant: 0,
        };
        let mut allocate = |label: &str| {
            let label = format!("{label} ({})", domain.label());
            counters.allocate_keyed(TYPE_EVENTS, &label, keys)
        };
        let offers = karyos_client::schedule::ScheduleCounters {
            scheduled_offers: allocate("timed scheduled offers"),
            rejected_invalid: allocate("timed rejections invalid"),
            rejected_too_far: allocate("timed rejections too far"),
            rejected_overflow: allocate("timed rejections overflow"),
            rejected_ring_full: allocate("timed rejections ring full"),
        };
        let sender = crate::timed_gate::TimedLaneCounters {
            late_sends: allocate("timed late sends"),
            deadline_aborts: allocate("timed deadline aborts"),
            lateness: crate::timed_gate::LATENESS_LABELS.map(&mut allocate),
        };
        Self {
            offers: Arc::new(offers),
            sender: Arc::new(sender),
        }
    }
}

/// Whether a stream is a lane of a network publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkLane {
    /// Not a network publication's lane.
    Local,
    /// Its network sender serves the current incarnation.
    Sending,
    /// Swapped to its next incarnation, whose sender is not posted yet:
    /// nothing is issued on it until it is.
    AwaitingSender,
}

/// The next incarnation of a guarded stream, checked
/// (`EmbeddedDriver::reincarnation_plan`).
#[derive(Debug)]
struct Incarnation {
    incarnation: u64,
    base: u64,
    config: LogBufferConfig,
    generation: Generation,
    guard: crate::guards::GuardHandle,
    messages: u64,
    rate: Option<karyos_sys::rate_limit::RatePolicy>,
    /// The rate policy's version and control reserve, kept across the
    /// incarnation (R-CORE-21).
    rate_version: u64,
    reserve: Option<karyos_sys::rate_limit::Rate>,
    gate_slot: Option<Arc<crate::shared_words::Words>>,
}

/// A prepared incarnation's log, not installed yet.
struct Fresh<T: StreamTerms> {
    buffer: Arc<LogBuffer<T>>,
    conductor: Conductor<Arc<LogBuffer<T>>>,
    walker: karyos_sys::log_buffer::Subscription<Arc<LogBuffer<T>>>,
    scratch: usize,
}

/// A sealed incarnation a fresh one replaced, retiring like a removed
/// stream (`quantstratum-docs: karyos/design/guards-and-abort.md`, The
/// fresh incarnation).
#[derive(Debug)]
pub(crate) struct Replaced<T: StreamTerms> {
    pub(crate) incarnation: u64,
    pub(crate) base: u64,
    /// The sealed buffer, which remote grants of this incarnation fetch.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) buffer: Arc<LogBuffer<T>>,
    pub(crate) conductor: Conductor<Arc<LogBuffer<T>>>,
    /// The old walker and the old handles' rings: its last pass, up to
    /// the seal, writes there.
    pub(crate) guarded: crate::guard_streams::GuardedStream<T>,
}

/// The conflation feeder's event counters of one stream
/// (`quantstratum-docs: karyos/design/conflation-end-to-end.md`,
/// Counters), keyed by the stream and its lane. A counter is `None` when
/// no cell was free, which `counters unavailable` counted.
#[derive(Debug)]
pub(crate) struct FeederCounters {
    written: Option<Counter>,
    keys_rejected: Option<Counter>,
    values_too_large: Option<Counter>,
}

/// What one feeder poll did with its messages.
#[derive(Debug, Default, Clone, Copy)]
struct Fed {
    written: u64,
    keys_rejected: u64,
    values_too_large: u64,
}

impl FeederCounters {
    fn allocate(counters: &mut DriverCounters, stream: u64, lane: u8) -> Self {
        let keys = CounterKeys {
            stream,
            lane,
            kind: KIND_NONE,
            participant: 0,
        };
        let mut allocate = |label| counters.allocate_keyed(TYPE_EVENTS, label, keys);
        Self {
            written: allocate("conflation updates written"),
            keys_rejected: allocate("conflation keys rejected"),
            values_too_large: allocate("conflation values too large"),
        }
    }

    fn add(&self, counters: &DriverCounters, fed: Fed) {
        for (counter, delta) in [
            (&self.written, fed.written),
            (&self.keys_rejected, fed.keys_rejected),
            (&self.values_too_large, fed.values_too_large),
        ] {
            if let Some(counter) = counter
                && delta > 0
            {
                counters.add_to(counter, delta);
            }
        }
    }

    fn free(self, counters: &mut DriverCounters) {
        for counter in [self.written, self.keys_rejected, self.values_too_large]
            .into_iter()
            .flatten()
        {
            counters.free(counter);
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConflationFeeder<T: StreamTerms> {
    pub(crate) subscription: ClientSubscription<T>,
    pub(crate) writer: ConflationWriter,
    /// The freshness state of a network image's view; `None` for an IPC
    /// stream's (which has no loss).
    pub(crate) fresh: Option<FreshFeed>,
}

/// A network image lane's view closed by its terminal cell, kept until its
/// recreation (karyos#658).
#[derive(Debug)]
pub(crate) struct ClosedView {
    /// The closed table: its last values seed the recreated view.
    pub(crate) writer: ConflationWriter,
    /// The terminal that closed it.
    pub(crate) terminal: karyos_sys::freshness::Terminal,
}

/// The feeder side of a network image lane's view
/// (conflated-network-images.md (b)): the link its table shares with the
/// receiver's seal gate, and a gap met in the log that the barrier could
/// not take yet. While one waits, nothing past it is polled, so no value
/// past a gap is published before the gap is recorded.
#[derive(Debug)]
pub(crate) struct FreshFeed {
    pub(crate) link: karyos_sys::freshness::FreshnessLink,
    pub(crate) gap: Option<(u64, u64)>,
    /// Every poll of the feeder fails (tests).
    #[cfg(test)]
    pub(crate) fail_polls: bool,
}

/// What a network image view's feeder did in one duty, beyond its writes.
#[derive(Debug, Clone, Copy, Default)]
struct FreshFed {
    /// Seal requests acknowledged after the loss was recorded.
    acked: u64,
    /// Seal requests whose acknowledgement was withheld: the barrier was
    /// full.
    withheld: u64,
    /// Gaps met in the log and recorded (not through the mailbox).
    caught_up: u64,
    /// Refresh cycle markers whose payload did not decode (ADR-0080).
    markers_malformed: u64,
}

impl<T: StreamTerms> Stream<T> {
    /// The stream's wire key.
    pub(crate) fn key(&self) -> StreamKey {
        StreamKey {
            stream_id: self.stream_id,
            session_id: self.session_id,
        }
    }

    /// The image registration a close of this lane names
    /// (`quantstratum-docs: karyos/design/per-source-images.md`, D2-3):
    /// its aggregate's for an image's lane, 0 for any other stream.
    pub(crate) const fn image_registration(&self) -> u64 {
        match self.source {
            Some(_) => self.aggregate.registration,
            None => 0,
        }
    }

    /// A new generation link for a handle on the current mapping.
    pub(crate) fn join(&mut self, kind: MemberKind) -> (Arc<GenerationLink<T>>, u64) {
        self.join_member(kind, false)
    }

    /// As [`join`](Self::join), for a handle the embedding program holds
    /// through the driver's own API (karyos#885).
    pub(crate) fn join_host(&mut self, kind: MemberKind) -> (Arc<GenerationLink<T>>, u64) {
        self.join_member(kind, true)
    }

    fn join_member(&mut self, kind: MemberKind, host: bool) -> (Arc<GenerationLink<T>>, u64) {
        let link = GenerationLink::new();
        self.members.push(Member {
            link: Arc::downgrade(&link),
            kind,
            host,
        });
        (link, self.base)
    }

    /// The embedding program's live publication handles on this lane,
    /// exclusive and concurrent, a pending cutover's included: the value of
    /// its `embedded publications` gauge (karyos#885).
    pub(crate) fn host_publications(&self) -> u64 {
        let pending = self
            .cutover
            .as_ref()
            .map_or(&[][..], crate::generations::Cutover::pending_members);
        let live = self
            .members
            .iter()
            .chain(pending)
            .filter(|member| member.is_live_host_publication())
            .count();
        u64::try_from(live).unwrap_or(u64::MAX)
    }

    /// The conductor of incarnation `incarnation`: the current one, or a
    /// replaced incarnation still retiring; `None` once it is gone.
    pub(crate) fn conductor_of(
        &mut self,
        incarnation: u64,
    ) -> Option<&mut Conductor<Arc<LogBuffer<T>>>> {
        if incarnation == self.incarnation {
            return Some(&mut self.conductor);
        }
        self.replaced
            .iter_mut()
            .find(|replaced| replaced.incarnation == incarnation)
            .map(|replaced| &mut replaced.conductor)
    }

    /// The stream position where incarnation `incarnation`'s current
    /// mapping starts, as [`Self::conductor_of`] finds its conductor.
    pub(crate) fn base_of(&self, incarnation: u64) -> Option<u64> {
        if incarnation == self.incarnation {
            return Some(self.base);
        }
        self.replaced
            .iter()
            .find(|replaced| replaced.incarnation == incarnation)
            .map(|replaced| replaced.base)
    }

    /// The conductor of the mapping a grant names, by incarnation and
    /// generation: the current mapping or a retained predecessor of the
    /// current incarnation, or a replaced incarnation (one mapping, as a
    /// guarded stream takes no cutover).
    pub(crate) fn grant_conductor(
        &mut self,
        incarnation: u64,
        generation: u32,
    ) -> Option<&mut Conductor<Arc<LogBuffer<T>>>> {
        if incarnation != self.incarnation {
            return self.conductor_of(incarnation);
        }
        if self.generation.get() == generation {
            return Some(&mut self.conductor);
        }
        self.retained
            .iter_mut()
            .find(|retained| retained.generation.get() == generation)
            .map(|retained| &mut retained.conductor)
    }

    /// The buffer of the mapping a grant names, as [`Self::grant_conductor`],
    /// and the stream position where that mapping starts: the base a remote
    /// client maps it at (G-d2c).
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn grant_buffer(
        &self,
        incarnation: u64,
        generation: u32,
    ) -> Option<(&Arc<LogBuffer<T>>, u64)> {
        if incarnation != self.incarnation {
            return self
                .replaced
                .iter()
                .find(|replaced| replaced.incarnation == incarnation)
                .map(|replaced| (&replaced.buffer, replaced.base));
        }
        if self.generation.get() == generation {
            return Some((&self.buffer, self.base));
        }
        self.retained
            .iter()
            .find(|retained| retained.generation.get() == generation)
            .map(|retained| (&retained.buffer, retained.base))
    }

    /// Fixes a timed lane's settings as a handle of it is issued, or as its
    /// sender is added: they are written once into the ring's binding
    /// words, which a publisher in another process reads (`quantstratum-docs:
    /// karyos/design/timed-tx.md`, section 11, TT-6b), and do not change
    /// for the incarnation. A lane that is not timed, or whose settings are
    /// already fixed, is unchanged.
    ///
    /// # Errors
    ///
    /// [`DriverError::Sys`] for a ring that is not one (a broken
    /// invariant).
    pub(crate) fn fix_schedule(&mut self) -> Result<(), DriverError> {
        if self.schedule_issued {
            return Ok(());
        }
        let Some(ring) = self.buffer.schedule_ring() else {
            return Ok(());
        };
        let binding = self.schedule.unwrap_or_default().binding();
        karyos_sys::schedule_ring::write_binding(ring, binding)
            .map_err(|error| DriverError::Sys(error.into()))?;
        self.schedule_issued = true;
        Ok(())
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
pub struct EmbeddedDriver<T: StreamTerms = HeapTerms> {
    pub(crate) id: u64,
    /// The random 128-bit `driver_id` of SPEC.md §4, drawn once at start.
    pub(crate) driver_id: [u64; 2],
    /// The next trace number: journal numbers and traced subscriber
    /// registrations, never reused within this driver instance.
    pub(crate) next_trace_number: u64,
    pub(crate) config: DriverConfig,
    pub(crate) streams: Vec<Stream<T>>,
    pub(crate) broadcast: BroadcastTransmitter,
    pub(crate) clients: Vec<ClientSlot<T>>,
    pub(crate) registrations: Vec<crate::commands::Registration>,
    /// The audited streams and their grants not drained yet (H3).
    pub(crate) grant_audits: crate::grant_audit::GrantAudits,
    pub(crate) next_client: u64,
    pub(crate) next_stream: u64,
    /// The replay targets this driver made (A5b).
    pub(crate) replays: crate::replay::ReplayTargets,
    /// Tests: the stream id at which staging a lane fails, and the cutover
    /// preparation of that stream.
    #[cfg(test)]
    pub(crate) fail_at: Option<u64>,
    pub(crate) next_registration: u64,
    pub(crate) scan_cursor: usize,
    /// The private copy of the command being decoded: the largest record
    /// a command ring carries (`ring_capacity / 8`), allocated once, so a
    /// command with receiver roles (karyos#637) is bounded by the ring and
    /// a client never changes what is being decoded.
    pub(crate) command_bytes: Vec<u8>,
    pub(crate) terminal: bool,
    /// Whether new clients are admitted; cleared once by
    /// [`EmbeddedDriver::stop_admitting`].
    pub(crate) admitting: bool,
    /// When the driver was created, on its clock (R-CORE-35).
    pub(crate) started_at: u64,
    /// Where the host's startup stands (R-CORE-35).
    pub(crate) startup: Startup,
    pub(crate) counters: DriverCounters,
    /// The client counters region and the owner of each allocated cell.
    pub(crate) client_counters: ClientCounters,
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
    /// The per-stream positions sampling state.
    pub(crate) positions: crate::positions::Positions,
    /// The admission socket and its connections (IPC mode).
    #[cfg(target_os = "linux")]
    pub(crate) admission: Option<crate::admission::Admission<T>>,
    /// Remote clients the conductor found faulty outside admission (a
    /// timed lane's schedule violation), for admission to retire with its
    /// socket and pidfd at its next step.
    #[cfg(target_os = "linux")]
    pub(crate) faulty_pending: Vec<u64>,
    /// The error log and the loss report.
    pub(crate) diagnostics: crate::diagnostics::Diagnostics,
    /// The client trace journals and the trace mirror.
    pub(crate) trace_journals: crate::trace_journals::TraceJournals,
    /// The network trace hooks and their journals.
    pub(crate) network: crate::network_journals::NetworkTracing,
    /// The guard registry and its audit ring.
    pub(crate) guards: crate::guards::Guards,
    /// Each guarded publication's rate policy and its version, by its
    /// aggregate's registration (a stream's own for a single lane): one
    /// policy and one version per aggregate, which its guarded lanes copy
    /// (R-CORE-21). Bounded by construction: an entry is made only by
    /// guarding a lane in the table and goes with its publication's last
    /// lane, so `rate_policies.len() <= streams.len() <= max_streams`
    /// always, and no entry is ever refused for room.
    pub(crate) rate_policies:
        std::collections::BTreeMap<u64, (karyos_sys::rate_limit::RatePolicy, u64)>,
    /// The sender gates registered with their guards (G-e4).
    pub(crate) guard_senders: crate::guard_ack::GuardSenders,
    /// Test only: guarding a network publication's lane of this index
    /// fails, as a walker short of a spare slot does.
    #[cfg(test)]
    pub(crate) guard_lane_fault: Option<usize>,
    /// The outcome ring or consumed cell of each binding grant not ended
    /// yet, by export: what its fetch grants. The walker's bound holds
    /// the same words until its last outcome record is written.
    pub(crate) binding_exports: Vec<(u64, Arc<crate::shared_words::Words>)>,
    /// The network agents and their tables, when configured.
    pub(crate) net: Option<crate::net::Network<T>>,
    /// Each guard's word gauge (M4).
    guard_cells: crate::guards::GuardCells,
    /// Each guard's close acknowledgement gauges (M4b).
    guard_ack_cells: crate::guard_ack::GuardAckCells,
    /// The word the conductor loop's spin meter stores into (M5), copied
    /// into the fixed `conductor spin time` cell at each duty cycle, and
    /// whether the meter was handed out.
    spin_word: Arc<std::sync::atomic::AtomicU64>,
    spin_taken: bool,
    /// Each network endpoint's capability gauges (M3).
    capabilities: crate::capabilities::CapabilityCells,
    /// What clients created by channel URI, owned by their registrations
    /// (W5b): at most `NetworkConfig::max_owned_per_client` per client,
    /// preallocated for every client.
    pub(crate) net_owned: Vec<crate::net::client::OwnedNetwork>,
    /// Network resources refused because their client owned its most.
    pub(crate) owned_refusals: u64,
    /// `owned_refusals` reached its end and kept its value (SPEC §14).
    pub(crate) owned_refusals_overflowed: bool,
}

/// The incarnation of a stream's publication in the embedded driver: one per
/// stream registration, kept across mapping cutovers.
pub const FIRST_INCARNATION: u64 = 1;

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Exposes the lanes of an installed image as the lane streams of one
    /// aggregate, named by its registration (`quantstratum-docs:
    /// karyos/design/per-source-images.md`, D2-1; wiring note W-e, W3).
    /// Each lane's conductor is issued here, so the duty cycle prepares
    /// the image's terms as for a local stream.
    ///
    /// A network image comes with its `source`: images of one alias from
    /// different sources are each exposed, and an image is exposed beside
    /// a local stream of its key too, such as this driver's own network
    /// publication whose loopback image it receives (karyos#490). Key
    /// lookups prefer the local stream; an image is reached by its
    /// registration, or by its alias from a network subscription
    /// (`quantstratum-docs: karyos/design/per-source-images.md`, D2-4). A
    /// replay target has no source and is refused for any stream of its
    /// key, and an image is refused over a replay target's key. Returns
    /// `None`, with nothing added, for a refused key, a full stream table or
    /// an aggregate that cannot be built (its quanta, its profile, its
    /// registrations or a conductor already issued). A retiring replay
    /// target keeps its key until it frees, so an image of that alias
    /// installed meanwhile stays unexposed for its whole life (#283 P3).
    pub(crate) fn add_image_aggregate(
        &mut self,
        lanes: &[Arc<LogBuffer<T>>],
        source: Option<crate::net::ImageSource>,
    ) -> Option<AggregateHandle> {
        let first = lanes.first()?.config();
        let key = (first.stream_id, first.session_id);
        let count = u8::try_from(lanes.len()).ok()?;
        // A replay target (no source) is refused over any stream of its key;
        // an image only over a replay target's.
        let taken = self.streams.iter().any(|stream| {
            (stream.stream_id, stream.session_id) == key && (source.is_none() || stream.replay)
        });
        if taken
            || self
                .streams
                .len()
                .checked_add(lanes.len())
                .is_none_or(|total| total > self.config.max_streams)
        {
            return None;
        }
        // Each lane's quantum is four of its largest frames, as for a
        // sender's lanes.
        let quanta = lanes
            .iter()
            .map(|lane| u64::from(lane.config().mtu).checked_mul(4))
            .collect::<Option<Vec<u64>>>()?;
        let charge = largest_charge(&StreamConfig {
            buffer: *first,
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        })
        .ok()?;
        let profile = DrrConfig::new(&quanta, charge).ok()?;
        let registration = self.next_stream;
        let next = registration.checked_add(u64::from(count))?;
        let aggregate = Aggregate {
            registration,
            lanes: count,
            profile,
        };
        let mut staged = Vec::with_capacity(lanes.len());
        let mut handle = AggregateHandle {
            driver: self.id,
            registration,
            lanes: [None; MAX_LANES],
        };
        for (id, buffer) in (registration..next).zip(lanes) {
            let config = *buffer.config();
            let conductor = buffer.conductor_owned()?;
            if let Some(slot) = handle.lanes.get_mut(usize::from(config.lane.get())) {
                *slot = Some(id);
            }
            staged.push(Stream {
                id,
                source,
                replay: source.is_none(),
                aggregate,
                retiring: false,
                buffer: Arc::clone(buffer),
                conductor,
                leases: Arc::new(StreamLeases::default()),
                allow_unconnected: true,
                policy: LossPolicy::Hold,
                stream_id: key.0,
                session_id: key.1,
                claim_waiting: false,
                config,
                conflation: None,
                generation: Generation::default(),
                base: 0,
                members: Vec::new(),
                cutover: None,
                retained: Vec::new(),
                spare: None,
                feeder: None,
                closed_view: None,
                conflation_terminal: None,
                feeder_counters: None,
                guarded: None,
                incarnation: FIRST_INCARNATION,
                reincarnated_at: 0,
                reincarnation_backdate: 0,
                replaced: Vec::new(),
                network: NetworkLane::Local,
                schedule: None,
                schedule_issued: false,
                schedule_clock: None,
                timed_counters: None,
            });
        }
        self.next_stream = next;
        self.streams.extend(staged);
        self.update_stream_gauges();
        Some(handle)
    }
}

impl EmbeddedDriver<HeapTerms> {
    /// An empty driver.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::DriverIdsExhausted`] once the process has
    /// created `u64::MAX - 1` drivers; identities are never reused, so a
    /// stale handle can never name another driver's stream. Returns
    /// [`DriverError::Sys`] when the random source of the `driver_id`
    /// fails.
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
}

#[cfg(target_os = "linux")]
impl EmbeddedDriver<SharedTerms> {
    /// A driver that also admits clients of other processes through its
    /// admission socket (`quantstratum-docs: karyos/design/ipc-admission-server.md`, Linux).
    /// Its broadcast buffer, counters and every stream live in shared
    /// regions; its in-process clients use the same shared terms.
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
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    fn build(
        config: DriverConfig,
        clock: Box<dyn MonotonicClock>,
        #[cfg(target_os = "linux")] ipc: Option<crate::admission::IpcConfig>,
        #[cfg(not(target_os = "linux"))] ipc: Option<core::convert::Infallible>,
    ) -> Result<Self, DriverError>
    where
        T: 'static,
    {
        config.validate()?;
        // The one per-instance id: trace and loss identities carry it, and
        // in IPC mode it is the admission instance id too (ACS 13555).
        let mut driver_id = [0u64; 2];
        karyos_sys::random::fill_u64s(&mut driver_id)?;
        #[cfg(target_os = "linux")]
        let (broadcast, mut counters, client_counters, mut admission, diagnostics, mirror) =
            match ipc {
                Some(ipc) => {
                    // Fail fast: the image lanes of a network are regions too.
                    if let Some(network) = &config.network {
                        crate::admission::check_descriptors(
                            crate::admission::descriptors_needed(&config, network),
                            karyos_sys::ipc::descriptor_limits(),
                        )?;
                    }
                    let instance = crate::admission::instance_of(driver_id);
                    let mut admission = crate::admission::Admission::new(ipc, instance)?;
                    let broadcast = BroadcastTransmitter::create_in(
                        instance,
                        crate::admission::BROADCAST_REGION,
                        config.broadcast_capacity,
                    )
                    .map_err(|_| DriverError::InvalidConfig)?;
                    let counters = DriverCounters::new_in(
                        instance,
                        crate::admission::COUNTERS_REGION,
                        config.counters_capacity,
                    )?;
                    let diagnostics =
                        crate::diagnostics::Diagnostics::new_in(&mut admission, &config)?;
                    let (_, region) = admission.next_region()?;
                    let client_counters = ClientCounters::new_in(
                        instance,
                        region,
                        config.client_counters_capacity,
                        config.max_counters_per_client,
                    )?
                    .with_trace_points(
                        config.max_trace_points_per_client,
                        config.max_trace_point_registrations_per_client,
                    );
                    let (_, region) = admission.next_region()?;
                    let mirror = karyos_sys::trace_mirror::trace_mirror_in(
                        instance,
                        region,
                        config.max_trace_journals,
                        config.trace_recycle_log_entries,
                        config.trace_mirror_records,
                    )
                    .map_err(|_| DriverError::InvalidConfig)?;
                    (
                        broadcast,
                        counters,
                        client_counters,
                        Some(admission),
                        diagnostics,
                        mirror,
                    )
                }
                None => (
                    broadcast(config.broadcast_capacity).map_err(|_| DriverError::InvalidConfig)?,
                    DriverCounters::with_capacity(config.counters_capacity)?,
                    ClientCounters::new(
                        config.client_counters_capacity,
                        config.max_counters_per_client,
                    )?
                    .with_trace_points(
                        config.max_trace_points_per_client,
                        config.max_trace_point_registrations_per_client,
                    ),
                    None,
                    crate::diagnostics::Diagnostics::new(&config)?,
                    heap_mirror(&config)?,
                ),
            };
        #[cfg(not(target_os = "linux"))]
        let (broadcast, mut counters, client_counters, diagnostics, mirror) = {
            let _ = ipc;
            (
                broadcast(config.broadcast_capacity).map_err(|_| DriverError::InvalidConfig)?,
                DriverCounters::with_capacity(config.counters_capacity)?,
                ClientCounters::new(
                    config.client_counters_capacity,
                    config.max_counters_per_client,
                )?
                .with_trace_points(
                    config.max_trace_points_per_client,
                    config.max_trace_point_registrations_per_client,
                ),
                crate::diagnostics::Diagnostics::new(&config)?,
                heap_mirror(&config)?,
            )
        };
        if !broadcast.has_room(MAX_RESPONSE_LENGTH) {
            return Err(DriverError::InvalidConfig);
        }
        // The tools' guard audit ring (M4): a driver-only region in IPC
        // mode. It holds at least one record, so a driver that keeps no
        // audit of its own still shows its latest transition.
        let audit_records = config.guard_audit_records.max(1);
        #[cfg(target_os = "linux")]
        let guard_ring = match admission.as_mut() {
            Some(admission) => {
                let (_, region) = admission.next_region()?;
                karyos_sys::diag::guard_audit_in(
                    crate::admission::instance_of(driver_id),
                    region,
                    audit_records,
                )
            }
            None => karyos_sys::diag::guard_audit(audit_records),
        }
        .map_err(|_| DriverError::InvalidConfig)?;
        #[cfg(not(target_os = "linux"))]
        let guard_ring =
            karyos_sys::diag::guard_audit(audit_records).map_err(|_| DriverError::InvalidConfig)?;
        // The guard words, one per guard: a driver-only region in IPC mode,
        // which every guarded grant carries read-only (`quantstratum-docs:
        // karyos/design/guards-and-abort.md`, "The binding across
        // processes").
        #[cfg(target_os = "linux")]
        let guard_words = match admission.as_mut() {
            Some(admission) => {
                let (_, region) = admission.next_region()?;
                crate::shared_words::Words::region(
                    crate::admission::instance_of(driver_id),
                    region,
                    karyos_sys::ipc::RegionKind::GuardRegion,
                    karyos_sys::guard::GUARD_REGION_LAYOUT_VERSION,
                    config.max_guards,
                    true,
                )
                .map_err(|_| DriverError::InvalidConfig)?
            }
            None => crate::shared_words::Words::heap(config.max_guards),
        };
        #[cfg(not(target_os = "linux"))]
        let guard_words = crate::shared_words::Words::heap(config.max_guards);
        // The network agents' cells, allocated before any agent starts.
        let network_cells = config
            .network
            .as_ref()
            .map(|network| network_cells(&mut counters, network.threading));
        // The conductor loop's spin meter (M5), for whoever drives
        // `do_work`.
        let spin_word = Arc::new(std::sync::atomic::AtomicU64::new(0));
        counters.set(Event::DriverPid, u64::from(std::process::id()));
        counters.set(
            Event::DriverStartedAt,
            karyos_sys::host_clock::host_monotonic_ns(),
        );
        // R-CORE-35: the startup deadline counts from here.
        let mut clock = clock;
        let started_at = clock.now();
        let id = NEXT_DRIVER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| DriverError::DriverIdsExhausted)?;
        Ok(Self {
            counters,
            client_counters,
            id,
            driver_id,
            next_trace_number: 1,
            config,
            streams: Vec::new(),
            broadcast,
            clients: Vec::new(),
            registrations: Vec::new(),
            grant_audits: crate::grant_audit::GrantAudits::default(),
            next_client: 1,
            next_stream: 1,
            replays: crate::replay::ReplayTargets::default(),
            #[cfg(test)]
            fail_at: None,
            next_registration: 1,
            scan_cursor: 0,
            command_bytes: vec![0; config.ring_capacity / 8],
            terminal: false,
            admitting: true,
            started_at,
            startup: Startup::Pending,
            clock,
            next_export: 1,
            holding: Vec::new(),
            last_beat: None,
            positions: crate::positions::Positions::default(),
            #[cfg(target_os = "linux")]
            admission,
            #[cfg(target_os = "linux")]
            faulty_pending: Vec::new(),
            diagnostics,
            trace_journals: crate::trace_journals::TraceJournals::new(
                mirror,
                config.max_trace_journal_bytes,
                config.max_network_journal_bytes,
                config.trace_drain_budget,
            ),
            network: crate::network_journals::NetworkTracing::new(config.max_trace_journals),
            guards: crate::guards::Guards::new(
                id,
                config.max_guards,
                guard_words,
                config.guard_audit_records,
                guard_ring,
            ),
            rate_policies: std::collections::BTreeMap::new(),
            guard_cells: crate::guards::GuardCells::default(),
            guard_ack_cells: crate::guard_ack::GuardAckCells::default(),
            spin_word,
            spin_taken: false,
            guard_senders: crate::guard_ack::GuardSenders::new(config.max_guard_senders),
            #[cfg(test)]
            guard_lane_fault: None,
            binding_exports: Vec::new(),
            // Validated above: the product fits.
            net_owned: Vec::with_capacity(config.network.map_or(0, |network| {
                crate::net::client::owned_capacity(&network, config.max_clients).unwrap_or(0)
            })),
            owned_refusals: 0,
            owned_refusals_overflowed: false,
            capabilities: crate::capabilities::CapabilityCells::default(),
            // Last: a driver that fails to build starts no agent.
            net: config
                .network
                .as_ref()
                .zip(network_cells)
                .map(|(network, cells)| crate::net::Network::start(network, cells))
                .transpose()?,
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

    /// Why a stream's buffer was sealed (`quantstratum-docs: karyos/design/publication-seal.md`):
    /// `None` while it is active or sealed only for a cutover.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::UnknownStream`] for a foreign handle or a
    /// freed stream.
    pub fn seal_reason(&self, stream: StreamHandle) -> Result<Option<SealReason>, DriverError> {
        self.streams
            .iter()
            .find(|s| stream.driver == self.id && s.id == stream.stream)
            .map(|s| s.conductor.seal_reason())
            .ok_or(DriverError::UnknownStream {
                stream: stream.stream,
            })
    }

    /// The seal state of a stream's buffer (`quantstratum-docs: karyos/design/publication-seal.md`):
    /// `Active` until it is removed, then `Sealed` until every issued
    /// publication has released, `Positioned` at the end of its last
    /// granted reservation, and `Retired` once every attached subscriber
    /// has read up to that position. The position is an absolute stream
    /// position, as offers report: the current mapping's base plus the
    /// buffer's own seal position.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::UnknownStream`] for a foreign handle or a
    /// freed stream, and [`DriverError::PositionsExhausted`] for a position
    /// past the stream position range.
    pub fn seal_state(&self, stream: StreamHandle) -> Result<SealState, DriverError> {
        let found = self
            .streams
            .iter()
            .find(|s| stream.driver == self.id && s.id == stream.stream)
            .ok_or(DriverError::UnknownStream {
                stream: stream.stream,
            })?;
        let absolute = |position: u64| {
            found
                .base
                .checked_add(position)
                .ok_or(DriverError::PositionsExhausted)
        };
        Ok(match found.conductor.seal_state() {
            SealState::Positioned { position } => SealState::Positioned {
                position: absolute(position)?,
            },
            SealState::Retired { position } => SealState::Retired {
                position: absolute(position)?,
            },
            state @ (SealState::Active | SealState::Sealed) => state,
        })
    }

    /// A read-only view of the driver's counters (SPEC.md §11), for tools.
    #[must_use]
    pub fn counters(&self) -> karyos_sys::counters::CountersReader {
        self.counters.reader()
    }

    /// A read-only view of the client counters region, for tools: the cells
    /// clients allocated with `AllocateCounter` (`quantstratum-docs:
    /// karyos/design/observability-and-tools.md`, "Client counters").
    #[must_use]
    pub fn client_counters(&self) -> karyos_sys::counters::CountersReader {
        self.client_counters.reader()
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
        match self.held_total() {
            Some(held) => self.counters.set(Event::HandOverHeld, gauge(held)),
            None => self.counters.add(Event::CounterOverflows, 1),
        }
        match self
            .streams
            .iter()
            .try_fold(0u64, |sum, s| sum.checked_add(s.leases.live()))
        {
            Some(leases) => self.counters.set(Event::LeasesLive, leases),
            None => self.counters.add(Event::CounterOverflows, 1),
        }
        match self
            .streams
            .iter()
            .try_fold(0usize, |sum, s| sum.checked_add(s.retained.len()))
        {
            Some(retained) => self
                .counters
                .set(Event::GenerationsRetired, gauge(retained)),
            None => self.counters.add(Event::CounterOverflows, 1),
        }
        // Over every live mapping: the current one and the retained
        // predecessors, which still hold slots, credits and loans.
        // Checked sums, as `LeasesLive` above: a sum that does not fit
        // leaves its gauge at its last value and counts one `counter
        // overflows` (SPEC.md §14, ADR-0007).
        let conductors = || {
            self.streams.iter().flat_map(|stream| {
                core::iter::once(&stream.conductor)
                    .chain(stream.retained.iter().map(|retained| &retained.conductor))
            })
        };
        for (event, sum) in [
            (
                Event::SlotsQuarantined,
                conductors().try_fold(0usize, |sum, c| sum.checked_add(c.quarantined_slots())),
            ),
            (
                Event::SpareReservationsInUse,
                conductors().try_fold(0usize, |sum, c| sum.checked_add(c.spare_credits())),
            ),
            (
                Event::LoansOutstanding,
                conductors().try_fold(0usize, |sum, c| sum.checked_add(c.loans_outstanding())),
            ),
        ] {
            match sum {
                Some(sum) => self.counters.set(event, gauge(sum)),
                None => self.counters.add(Event::CounterOverflows, 1),
            }
        }
        self.counters
            .set(Event::TraceJournalsOpen, gauge(self.trace_journals.open()));
        self.counters.set(
            Event::NetworkTraceJournalsOpen,
            gauge(self.trace_journals.network_open()),
        );
    }

    /// Runs a positions sampling pass when `position_sample_interval` has
    /// elapsed (`quantstratum-docs: karyos/design/observability-and-tools.md`),
    /// then records `now` as the end of this duty cycle.
    fn sample_positions(&mut self) {
        let now = karyos_sys::host_clock::host_monotonic_ns();
        self.counters.set(Event::ConductorDutyAt, now);
        if self
            .positions
            .due(now, self.config.position_sample_interval)
        {
            self.positions
                .sample(now, &mut self.counters, &self.streams, &self.registrations);
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
        if target.aggregate.lanes > 1 {
            return Err(DriverError::LaneOfAggregate { stream: target.id });
        }
        let registration = target.aggregate.registration;
        self.retire_lane(stream)?;
        let closes = self.publication_journal_closes(registration);
        if let Some(net) = &mut self.net {
            let _ = net.remove_publication(registration, closes);
        }
        self.update_stream_gauges();
        Ok(())
    }

    /// Subscribes to every configured lane of `aggregate` with `role`, in
    /// one control call, all or nothing (`quantstratum-docs:
    /// karyos/design/aggregate-subscriber.md`, l3): one frame-level reader
    /// per lane and the aggregate's DRR profile. A failure at any lane
    /// drops the lanes already subscribed, which detaches their cells.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::subscribe`] for any lane.
    pub fn subscribe_aggregate(
        &mut self,
        aggregate: &AggregateHandle,
        role: Role,
    ) -> Result<karyos_client::aggregate::AggregateSubscription<T>, DriverError> {
        let first = aggregate
            .streams()
            .next()
            .ok_or(DriverError::UnknownStream { stream: 0 })?;
        let profile = self.stream(first)?.aggregate.profile;
        let mut lanes = Vec::with_capacity(usize::from(aggregate.lanes()));
        for stream in aggregate.streams() {
            let lane = self.stream(stream)?.config.lane;
            // On error, `lanes` drops here: every cell already taken
            // detaches.
            lanes.push((lane, self.subscribe(stream, role)?));
        }
        karyos_client::aggregate::AggregateSubscription::new(profile, lanes)
            .map_err(|_| DriverError::InvalidConfig)
    }

    /// Removes an aggregate: every lane is sealed as
    /// [`EmbeddedDriver::remove_stream`] seals a stream, in one control
    /// step. The seals are separate stores, one per lane, each with its own
    /// seal position; no order across lanes is promised (SPEC.md §7.4).
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::remove_stream`].
    pub fn remove_aggregate(&mut self, aggregate: &AggregateHandle) -> Result<(), DriverError> {
        // Every lane is found before any is sealed.
        for stream in aggregate.streams() {
            self.stream(stream)?;
        }
        for stream in aggregate.streams() {
            self.retire_lane(stream)?;
        }
        // A network publication's data path comes back to drop its lane
        // readers (wiring note W-d).
        let closes = self.publication_journal_closes(aggregate.registration());
        if let Some(net) = &mut self.net {
            let _ = net.remove_publication(aggregate.registration(), closes);
        }
        self.update_stream_gauges();
        Ok(())
    }

    /// Seals one lane stream and marks it retiring, once.
    fn retire_lane(&mut self, stream: StreamHandle) -> Result<(), DriverError> {
        self.retire_lane_with(
            stream,
            SealReason::StreamRemoved,
            CloseReason::StreamRemoved,
        )
    }

    /// Seals one lane stream with `seal` and marks it retiring, once,
    /// reporting `close` to clients.
    pub(crate) fn retire_lane_with(
        &mut self,
        stream: StreamHandle,
        seal: SealReason,
        close: CloseReason,
    ) -> Result<(), DriverError> {
        let target = self.stream(stream)?;
        if !target.retiring {
            // A stream an earlier seal closed keeps that reason and was
            // reported then.
            let was_active = target.conductor.seal_state() == SealState::Active;
            target.conductor.seal_with_reason(seal)?;
            let key = target.key();
            let lane = target.config.lane;
            let image = target.image_registration();
            if let Some(mut feeder) = target.feeder.take() {
                feeder.writer.close();
            }
            // A cutover ends with the stream: its handles are fenced and its
            // successor, if not current yet, is dropped.
            if let Some(cutover) = target.cutover.take() {
                cutover.abandon();
            }
            target.retiring = true;
            self.counters.add(Event::StreamsRemoved, 1);
            if was_active {
                self.emit(&DriverEvent::PublicationClosed {
                    stream: key,
                    lane,
                    reason: close,
                    image,
                });
            }
        }
        Ok(())
    }

    /// Frees retiring streams with no live lease and no remote grant. A
    /// registration does not keep its stream: once the stream is freed it
    /// stays, naming a stream id that is never reused, until its client
    /// removes it, a remote one's last grant ends (it is then reclaimed,
    /// `sweep_ended_registrations`) or the client ends. A remote client's
    /// grants (its ledger) keep the stream until they end, at their
    /// `Detach` or the client's exit proof. A network publication's lanes
    /// stay while its removal lingers: its
    /// sender still reads them to their seals and serves repair from them,
    /// with no lease (driver-network-agents.md §7). A stopped or failed
    /// network holds nothing, so they free with no linger.
    pub(crate) fn free_retired_streams(&mut self) {
        let clients = &self.clients;
        let net = self.net.as_ref();
        // A remote grant keeps its stream until it ends, even after its
        // registration was removed.
        let freed: Vec<Stream<T>> = self
            .streams
            .extract_if(.., |stream| {
                stream.retiring
                    && stream.leases.live() == 0
                    && !net.is_some_and(|net| net.holds_publication(stream.aggregate.registration))
                    && !clients.iter().any(|client| {
                        client
                            .ledger
                            .as_ref()
                            .is_some_and(|ledger| ledger.names_stream(stream.id))
                    })
            })
            .collect();
        if !freed.is_empty() {
            let count = u64::try_from(freed.len()).unwrap_or(u64::MAX);
            // The feeder counters go with their stream, and a publication's
            // rate policy with its last lane (registrations are never
            // reused, so a kept one would only grow the map): one pass over
            // the lanes left, each looked up among the freed registrations.
            let mut gone: Vec<_> = Vec::with_capacity(freed.len());
            for stream in freed {
                gone.push(stream.aggregate.registration);
                if let Some(counters) = stream.feeder_counters {
                    counters.free(&mut self.counters);
                }
            }
            gone.sort_unstable();
            gone.dedup();
            let mut kept = vec![false; gone.len()];
            for lane in &self.streams {
                if let Ok(index) = gone.binary_search(&lane.aggregate.registration)
                    && let Some(kept) = kept.get_mut(index)
                {
                    *kept = true;
                }
            }
            for (registration, kept) in gone.iter().zip(kept) {
                if !kept {
                    let _ = self.rate_policies.remove(registration);
                }
            }
            self.counters.add(Event::StreamsFreed, count);
            self.update_stream_gauges();
        }
    }

    /// Whether the driver is in its terminal state: the broadcast buffer is
    /// closed and no command is served.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Stops admitting clients, for an orderly shutdown
    /// (`quantstratum-docs: karyos/design/observability-and-tools.md`,
    /// Binaries): [`EmbeddedDriver::connect`] then returns
    /// [`DriverError::NotAdmitting`], and in IPC mode a client `Hello` is
    /// refused with `SHUTTING_DOWN`, so that a client does not retry as it
    /// would after `LIMIT`. Clients already admitted are served as
    /// before, and tools are still admitted, so that diagnostics stay
    /// readable. It cannot be undone; calling it again has no effect.
    pub fn stop_admitting(&mut self) {
        self.admitting = false;
    }

    /// Whether new clients are admitted: true until
    /// [`EmbeddedDriver::stop_admitting`].
    #[must_use]
    pub fn is_admitting(&self) -> bool {
        self.admitting
    }

    /// Declares the host's startup complete (R-CORE-35): the streams,
    /// guards and services it configures before taking traffic exist, so
    /// [`EmbeddedDriver::readiness`] may report ready. Before it, readiness
    /// is starting, and past [`DriverConfig::startup_timeout`] it is
    /// failed: **a host that never calls this reports failed once the
    /// deadline passes**, and a probe then stops the pod. Returns whether
    /// startup is complete: false when the deadline had already passed,
    /// which this call does not undo. Calling it again has no effect.
    pub fn startup_complete(&mut self) -> bool {
        let now = self.clock.now();
        self.startup_at(now);
        if self.startup == Startup::Pending {
            self.startup = Startup::Complete;
        }
        self.startup == Startup::Complete
    }

    /// Fails a pending startup whose deadline passed at `now`.
    fn startup_at(&mut self, now: u64) {
        if self.startup == Startup::Pending
            && karyos_sys::host_clock::age_ns(now, self.started_at) > self.config.startup_timeout
        {
            self.startup = Startup::Failed;
        }
    }

    /// The driver's readiness (R-CORE-35), from the conditions a client
    /// `Hello` is admitted under, never from a counter. In order:
    ///
    /// - terminal, or not admitting: [`Readiness::NotReady`];
    /// - startup not declared complete: [`Readiness::Starting`] until
    ///   [`DriverConfig::startup_timeout`], then [`Readiness::Failed`] for
    ///   good;
    /// - `max_clients` clients: [`Readiness::NotReady`] (full);
    /// - a stream still retaining a predecessor mapping after a cutover:
    ///   [`Readiness::Recovering`];
    /// - otherwise [`Readiness::Ready`]: a client would be admitted now,
    ///   into no cutover.
    ///
    /// It reads plain fields of the driver and its clock: no region, no
    /// counter, nothing a publisher or subscriber touches.
    pub fn readiness(&mut self) -> Readiness {
        let now = self.clock.now();
        self.startup_at(now);
        if self.terminal {
            return Readiness::NotReady(NotReadyReason::Terminal);
        }
        if !self.admitting {
            return Readiness::NotReady(NotReadyReason::NotAdmitting);
        }
        match self.startup {
            Startup::Pending => return Readiness::Starting,
            Startup::Failed => return Readiness::Failed(FailedReason::StartupDeadline),
            Startup::Complete => {}
        }
        if self.clients.len() >= self.config.max_clients {
            return Readiness::NotReady(NotReadyReason::Full);
        }
        if self
            .streams
            .iter()
            .any(|stream| !stream.retained.is_empty())
        {
            return Readiness::Recovering;
        }
        Readiness::Ready
    }

    /// Nanoseconds since the driver was created, on its clock: the uptime a
    /// readiness probe answers with (R-CORE-35).
    pub fn uptime(&mut self) -> u64 {
        let now = self.clock.now();
        karyos_sys::host_clock::age_ns(now, self.started_at)
    }

    /// Adds a guard named `name`, created closed at epoch 1, on the control
    /// path (`quantstratum-docs: karyos/design/guards-and-abort.md`).
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidConfig`] for an empty name, one longer than
    /// [`crate::guards::MAX_GUARD_NAME`] bytes, or one of the labels of a
    /// guard's close acknowledgement gauges (`guard ack pass`, `guard ack
    /// epoch`, `guard senders applied`, `in flight`, `pending` and
    /// `overdue`, each `guard senders ...`); [`DriverError::DuplicateGuard`],
    /// [`DriverError::TooManyGuards`] and [`DriverError::GuardIdsExhausted`].
    pub fn add_guard(&mut self, name: &str) -> Result<GuardHandle, DriverError> {
        self.guards.add(name)
    }

    /// The guard named `name`.
    #[must_use]
    pub fn guard(&self, name: &str) -> Option<GuardHandle> {
        self.guards.find(name)
    }

    /// A guard's state.
    ///
    /// # Errors
    ///
    /// [`DriverError::UnknownGuard`] for a foreign handle;
    /// [`DriverError::Guard`] for a corrupt word (a broken invariant).
    pub fn guard_state(
        &self,
        guard: GuardHandle,
    ) -> Result<karyos_sys::guard::GuardState, DriverError> {
        self.guards.state(guard)
    }

    /// Closes a guard for the in-process caller (G1), with the caller's
    /// `operation` id for the audit record. Idempotent at the current
    /// epoch.
    ///
    /// # Errors
    ///
    /// [`DriverError::UnknownGuard`] and [`DriverError::Guard`]; every
    /// call, refused or not, is audited.
    pub fn close_guard(
        &mut self,
        guard: GuardHandle,
        operation: u64,
    ) -> Result<karyos_sys::guard::Closed, DriverError> {
        let now = self.clock.now();
        let closed = self.guards.close(
            guard,
            operation,
            crate::guards::Requester::InProcess,
            0,
            now,
        );
        match &closed {
            // The close took effect: a failed seal is reported, never
            // returned as a failed close.
            Ok(_) => self.seal_guarded_reporting(guard),
            Err(error) => self.report_guard_error(guard.id(), error),
        }
        closed
    }

    /// Seals every stream guarded by `guard` with `GuardClosed` and aborts
    /// its outstanding claim (guards-and-abort.md, Local streams); the
    /// walker's last pass writes the final records. A stream already
    /// sealed is not sealed again.
    ///
    /// # Errors
    ///
    /// [`DriverError::Sys`] from a seal (a broken invariant); every stream
    /// is still tried.
    pub(crate) fn seal_guarded(&mut self, guard: GuardHandle) -> Result<(), DriverError> {
        let mut first_error = None;
        for stream in &mut self.streams {
            let bound = stream
                .guarded
                .as_ref()
                .is_some_and(|guarded| guarded.guard == guard);
            if !bound {
                continue;
            }
            if stream.conductor.seal_state() == SealState::Active
                && let Err(error) = stream.conductor.seal_with_reason(SealReason::GuardClosed)
            {
                first_error.get_or_insert(DriverError::from(error));
            }
            if let Err(error) = abort_guarded_claim(stream) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// [`Self::seal_guarded`] after a close that took effect: a failure is
    /// recorded in the error log (`GuardSealFailed`, keyed by the guard),
    /// never reported as a failed close. The walker's duty repeats only
    /// the claim abort, and only on a stream whose seal reason is
    /// `GuardClosed`; a seal that failed to set is not retried.
    pub(crate) fn seal_guarded_reporting(&mut self, guard: GuardHandle) {
        if let Err(error) = self.seal_guarded(guard) {
            self.diagnostics.error(
                &mut self.counters,
                crate::diagnostics::ErrorCode::GuardSealFailed,
                [guard.id(), 0],
                &error.to_string(),
            );
        }
    }

    /// Guards a stream with `guard` on the control path, before any
    /// publication handle is issued (`quantstratum-docs:
    /// karyos/design/guards-and-abort.md`, Admission, Local streams and
    /// Rate limits). Each handle issued later is bound to the guard's open
    /// epoch, with an outcome ring of `messages` (`C_m`) message records
    /// and, with `rate`, the publication's rate limit: the handle's copy of
    /// the message bucket returns `RateLimited` early, and the sender
    /// gate's bucket is authoritative.
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidPublicationMode`] for a concurrent stream
    /// (GC-7); [`DriverError::InvalidConfig`] for a stream already guarded,
    /// one with an issued handle, `messages` of 0, or `messages` reserved
    /// messages that do not fit half a term (the publication window, so
    /// the walker's retained span never needs more than the rotation and
    /// spare slots can hold); [`DriverError::UnknownGuard`]; and
    /// [`DriverError::GuardWalkerUnavailable`] when the walker, which holds
    /// one spare-slot credit for the stream's life, finds no credit
    /// ([`WalkerUnavailable::NoSpareCredit`]) or no reader cell
    /// ([`WalkerUnavailable::NoReaderCell`]);
    /// [`DriverError::RateScopeUnsupported`] for a rate scope other than
    /// the publication (GC-5) and [`DriverError::InvalidRatePolicy`] for a
    /// policy whose byte burst cannot hold the stream's largest frame, or
    /// with a zero rate or burst.
    pub fn guard_stream(
        &mut self,
        stream: StreamHandle,
        guard: GuardHandle,
        messages: u64,
        rate: Option<crate::guards::GuardRate>,
    ) -> Result<(), DriverError> {
        if let Err(error) = self.guards.state(guard) {
            self.report_guard_error(guard.id(), &error);
            return Err(error);
        }
        // The aggregate's policy and version, if it has one: one policy and
        // one version per aggregate (R-CORE-21, ACS 33546).
        let registration = self.stream_ref(stream)?.aggregate.registration;
        let held = self.rate_policies.get(&registration).copied();
        let found = self.active_stream(stream)?;
        if !matches!(
            found.config.publication,
            karyos_sys::log_buffer::PublicationMode::Exclusive
        ) {
            return Err(DriverError::InvalidPublicationMode);
        }
        let window = u64::from(found.config.term_length.get() / 2);
        let fits = messages
            .checked_mul(u64::from(found.config.max_reserved))
            .is_some_and(|span| span <= window);
        // An exclusive handle already issued, not a subscriber, rules it out.
        let issued = found
            .members
            .iter()
            .any(|member| matches!(member.kind, MemberKind::Exclusive));
        if found.guarded.is_some() || issued || messages == 0 || !fits {
            return Err(DriverError::InvalidConfig);
        }
        let joins_rateless = rate.is_none() && held.is_some();
        let rate = match rate {
            // A lane guarded without a rate takes its aggregate's policy,
            // if it has one.
            None => held.map(|(policy, _)| (policy, None)),
            Some(crate::guards::GuardRate {
                scope: crate::guards::RateScope::Publication,
                policy,
                reserve,
            }) => {
                // A policy other than the publication's would change it
                // without a version: refused, typed with both, and audited.
                // Only a change changes it.
                if let Some((held, version)) = held
                    && held != policy
                {
                    let error = DriverError::RatePolicyConflict {
                        requested: policy,
                        held,
                    };
                    let now = self.clock.now();
                    self.guards.audit_rate(
                        guard,
                        (version, version),
                        (
                            0,
                            crate::guards::Requester::InProcess,
                            crate::guards::RateAuthority::Administrator,
                        ),
                        Err(&error),
                        now,
                    );
                    return Err(error);
                }
                // The largest charge a route's sender gate validates against:
                // the MTU aligned as a frame, so a policy accepted here is
                // never one the gate refuses (#841 review, A1).
                let frame = gate_bound(found.config.mtu);
                policy
                    .validate(frame)
                    .map_err(DriverError::InvalidRatePolicy)?;
                if reserve.is_some_and(|reserve| !policy.keeps(&reserve, frame)) {
                    return Err(DriverError::RateChange(
                        crate::guards::RateChangeError::ReserveCrossed,
                    ));
                }
                Some((policy, reserve))
            }
            Some(crate::guards::GuardRate { scope, .. }) => {
                return Err(DriverError::RateScopeUnsupported { scope });
            }
        };
        // The credit is checked first, as admission counts it, so its
        // refusal is told apart from a full cell table.
        let id = found.id;
        let unavailable = |reason| DriverError::GuardWalkerUnavailable { stream: id, reason };
        // A stream whose spare slots are all cleaning headroom can host no
        // walker.
        let allowed = found
            .config
            .spare_slots
            .checked_sub(karyos_sys::log_buffer::CLEANING_HEADROOM)
            .map(usize::from);
        let credits = found.conductor.spare_credits().checked_add(1);
        if allowed
            .zip(credits)
            .is_none_or(|(allowed, credits)| credits > allowed)
        {
            return Err(unavailable(WalkerUnavailable::NoSpareCredit));
        }
        let walker = found
            .conductor
            .subscribe(karyos_sys::log_buffer::Role::Walker)
            .map_err(|error| match error {
                karyos_sys::error::SysError::ResourcesUnavailable => {
                    unavailable(WalkerUnavailable::NoReaderCell)
                }
                other => DriverError::Sys(other),
            })?;
        let scratch = usize::try_from(found.buffer.max_message_length())
            .map_err(|_| DriverError::InvalidConfig)?;
        let mut guarded = crate::guard_streams::GuardedStream::new(
            guard,
            messages,
            (
                rate.map(|(policy, _)| policy),
                rate.and_then(|(_, reserve)| reserve),
            ),
            walker,
            scratch,
        );
        // It joins at the aggregate's version, never at 1 on its own, so
        // one `expected` names every lane (R-CORE-21); one guarded without
        // a rate is audited moving from no rate to it.
        if let Some((policy, version)) = held {
            guarded.set_rate(policy, version);
            if joins_rateless {
                let now = self.clock.now();
                self.guards.audit_rate(
                    guard,
                    (0, version),
                    (
                        0,
                        crate::guards::Requester::InProcess,
                        crate::guards::RateAuthority::Administrator,
                    ),
                    Ok(()),
                    now,
                );
            }
        }
        let found = self.active_stream(stream)?;
        found.guarded = Some(guarded);
        // The aggregate's first policy: its other guarded lanes, guarded
        // without a rate before, take it too, at version 1, in the same
        // operation, each audited from no rate (version 0).
        if let (None, Some((policy, _))) = (held, rate) {
            let _ = self.rate_policies.insert(registration, (policy, 1));
            // Bounded by the streams: an entry is a publication with a lane
            // in the table, removed with its last lane, and the table holds
            // at most `max_streams` lanes, so no entry needs refusing.
            debug_assert!(self.rate_policies.len() <= self.streams.len());
            let mut moved = Vec::new();
            let mut published: Vec<Arc<crate::shared_words::Words>> = Vec::new();
            for lane in self
                .streams
                .iter_mut()
                .filter(|lane| lane.aggregate.registration == registration)
            {
                if let Some(guarded) = lane.guarded.as_mut()
                    && guarded.rate.is_none()
                {
                    // Into its handles' rings and its sender gate's slot,
                    // so the lane is limited, not only audited.
                    guarded.set_rate(policy, 1);
                    if let Some(slot) = guarded.gate_slot().cloned()
                        && !published.iter().any(|seen| Arc::ptr_eq(seen, &slot))
                    {
                        published.push(slot);
                        guarded.publish_gate();
                    }
                    if !moved.contains(&guarded.guard) {
                        moved.push(guarded.guard);
                    }
                }
            }
            let now = self.clock.now();
            for moved in moved {
                self.guards.audit_rate(
                    moved,
                    (0, 1),
                    (
                        0,
                        crate::guards::Requester::InProcess,
                        crate::guards::RateAuthority::Administrator,
                    ),
                    Ok(()),
                    now,
                );
            }
        }
        Ok(())
    }

    /// Changes the rate policy of `stream`, guarded with a rate, from
    /// version `expected` to `policy` under `authority`, with the caller's
    /// `operation` id for the audit (R-CORE-21; `quantstratum-docs:
    /// karyos/design/guards-and-abort.md`, Rate limits). Returns the new
    /// version, or the current one when `policy` is unchanged.
    ///
    /// The safety path takes only a provable tightening
    /// ([`karyos_sys::rate_limit::Transition::Tightening`]); an
    /// administrator takes any valid policy. No policy goes below the
    /// stream's control reserve. The change binds at once: every bound
    /// handle's outcome ring publishes it, read on the handle's next call,
    /// and a guarded network publication's sender gate reads it at its next
    /// serve. Each bucket keeps its level, clamped to the new burst: a
    /// change never grants tokens.
    ///
    /// A lane of an aggregate of several lanes stands for its aggregate,
    /// as [`Self::change_aggregate_rate_policy`]: its guarded lanes change
    /// together or not at all, so their versions never part.
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidRatePolicy`] for a policy its stream refuses;
    /// [`DriverError::RateChange`] with `NoRate` (no guarded lane with a
    /// rate policy), `VersionMismatch`, `NotATightening` and
    /// `ReserveCrossed`; the stream lookup's errors. Every call that names
    /// a guarded stream, refused or not, is audited, once per guard; an
    /// unchanged policy as unchanged.
    pub fn change_rate_policy(
        &mut self,
        stream: StreamHandle,
        expected: u64,
        policy: karyos_sys::rate_limit::RatePolicy,
        by: (crate::guards::RateAuthority, u64),
    ) -> Result<u64, DriverError> {
        let aggregate = self.stream_ref(stream)?.aggregate;
        if aggregate.lanes > 1 {
            match self.aggregate_of(aggregate.registration) {
                Ok(handle) => {
                    return self.change_aggregate_rate_policy(&handle, expected, policy, by);
                }
                Err(error) => {
                    // A lane of it could not be found: refused, audited for
                    // every guard of the lanes still there.
                    let version = self
                        .rate_policies
                        .get(&aggregate.registration)
                        .map_or(0, |(_, version)| *version);
                    let mut guards: Vec<GuardHandle> = Vec::new();
                    for lane in &self.streams {
                        if lane.aggregate.registration == aggregate.registration
                            && let Some(guarded) = lane.guarded.as_ref()
                            && !guards.contains(&guarded.guard)
                        {
                            guards.push(guarded.guard);
                        }
                    }
                    let now = self.clock.now();
                    for guard in guards {
                        self.guards.audit_rate(
                            guard,
                            (version, version),
                            (by.1, crate::guards::Requester::InProcess, by.0),
                            Err(&error),
                            now,
                        );
                    }
                    return Err(error);
                }
            }
        }
        self.change_rate_in(&[stream], expected, policy, by)
    }

    /// [`Self::change_rate_policy`] for a guarded aggregate, a network
    /// publication's lanes among them: its guarded lanes change together,
    /// each weighed on its own, and its sender gate reads the change at its
    /// next serve. Unguarded lanes are left as they are.
    ///
    /// # Errors
    ///
    /// As [`Self::change_rate_policy`]. The version, the transition and the
    /// policy's validity are the publication's: their refusals name no
    /// lane. A guarded lane whose control reserve the policy would cross is
    /// [`DriverError::RateChangeOnLane`] with `ReserveCrossed`, naming the
    /// lane, and refuses the change on every lane.
    pub fn change_aggregate_rate_policy(
        &mut self,
        aggregate: &AggregateHandle,
        expected: u64,
        policy: karyos_sys::rate_limit::RatePolicy,
        by: (crate::guards::RateAuthority, u64),
    ) -> Result<u64, DriverError> {
        let streams: Vec<StreamHandle> = aggregate.streams().collect();
        self.change_rate_in(&streams, expected, policy, by)
    }

    /// Changes the rate policy of the publication `streams` are the lanes
    /// of: its one policy and version (R-CORE-21, ACS 33546), weighed for
    /// each guarded lane against that lane's reserve and the largest frame,
    /// taken by every guarded lane or by none, and audited once for each
    /// guard among them, refusals included.
    fn change_rate_in(
        &mut self,
        streams: &[StreamHandle],
        expected: u64,
        policy: karyos_sys::rate_limit::RatePolicy,
        (authority, operation): (crate::guards::RateAuthority, u64),
    ) -> Result<u64, DriverError> {
        use crate::guards::{RateChangeError, Requester};

        let now = self.clock.now();
        // Every lane looked up first, whatever their order, a retiring one
        // included so that its guard is audited: each guarded lane, each
        // guard once, and the largest frame, a byte burst holding the
        // largest datagram.
        let mut lanes = Vec::with_capacity(streams.len());
        let mut guards: Vec<GuardHandle> = Vec::new();
        let mut lookup = None;
        let mut registration = None;
        let mut frame = 0;
        for stream in streams {
            match self.stream_ref(*stream) {
                Err(error) => {
                    lookup.get_or_insert(error);
                }
                Ok(found) => {
                    frame = frame.max(gate_bound(found.config.mtu));
                    registration.get_or_insert(found.aggregate.registration);
                    if found.retiring {
                        lookup.get_or_insert(DriverError::StreamRetiring { stream: found.id });
                    }
                    if let Some(guarded) = found.guarded.as_ref() {
                        if !guards.contains(&guarded.guard) {
                            guards.push(guarded.guard);
                        }
                        lanes.push((*stream, guarded.reserve, found.config.lane.get()));
                    }
                }
            }
        }
        let held =
            registration.and_then(|registration| self.rate_policies.get(&registration).copied());
        let current = held.map_or(0, |(_, version)| version);
        let decided = (|| {
            if let Some(error) = lookup {
                return Err(error);
            }
            let Some((old, current)) = held else {
                return Err(DriverError::RateChange(RateChangeError::NoRate));
            };
            if lanes.is_empty() {
                return Err(DriverError::RateChange(RateChangeError::NoRate));
            }
            // The policy, its version and its transition are the
            // publication's: decided once, naming no lane.
            let next = decide_rate_change(
                Some(old),
                &policy,
                (expected, current),
                None,
                frame,
                authority,
            )?;
            // Each lane's own reserve: a refusal names the lane, on an
            // aggregate of several lanes.
            if next != current {
                let named = streams.len() > 1;
                for &(_, reserve, lane) in &lanes {
                    if reserve.is_some_and(|reserve| !policy.keeps(&reserve, frame)) {
                        let refusal =
                            crate::guards::LaneRefusal::Change(RateChangeError::ReserveCrossed);
                        return Err(if named {
                            DriverError::RateChangeOnLane { lane, refusal }
                        } else {
                            refusal.error()
                        });
                    }
                }
            }
            Ok(next)
        })();
        if let (Ok(next), Some(registration)) = (decided, registration)
            && next != current
        {
            let _ = self.rate_policies.insert(registration, (policy, next));
            // Every guarded lane takes the policy at the new version; each
            // shared gate slot is published once.
            let mut published: Vec<Arc<crate::shared_words::Words>> = Vec::new();
            for &(stream, ..) in &lanes {
                if let Some(guarded) = self.active_stream(stream)?.guarded.as_mut() {
                    guarded.set_rate(policy, next);
                    if let Some(slot) = guarded.gate_slot().cloned()
                        && !published.iter().any(|seen| Arc::ptr_eq(seen, &slot))
                    {
                        published.push(slot);
                        guarded.publish_gate();
                    }
                }
            }
        }
        let after = decided.as_ref().map_or(current, |next| *next);
        for guard in guards {
            self.guards.audit_rate(
                guard,
                (current, after),
                (operation, Requester::InProcess, authority),
                decided.as_ref().map(|_| ()),
                now,
            );
        }
        decided
    }

    /// Reports a corrupt guard word in the error log (G2); other guard
    /// errors are the caller's to handle.
    pub(crate) fn report_guard_error(&mut self, guard: u64, error: &DriverError) {
        if let DriverError::Guard(karyos_sys::guard::GuardError::Corrupt { word }) = error {
            self.diagnostics.error(
                &mut self.counters,
                crate::diagnostics::ErrorCode::GuardWordCorrupt,
                [guard, *word],
                &error.to_string(),
            );
        }
    }

    /// Reopens a guard closed at `expected` for the in-process caller (G1),
    /// returning the new open epoch.
    ///
    /// A guarded stream the close sealed takes its fresh incarnation at its
    /// next [`EmbeddedDriver::publication`]. A guarded network publication
    /// takes it as a new publication identity on the wire, under the same
    /// alias: its old session is removed first, and the alias is then
    /// quarantined for `alias_quarantine` (default 10 s) from that removal,
    /// so `publication()` refuses with [`DriverError::QuarantinedAlias`]
    /// until then.
    ///
    /// # Errors
    ///
    /// [`DriverError::UnknownGuard`] and [`DriverError::Guard`]
    /// (`NotClosedAt`, `Exhausted`); every call is audited.
    pub fn reopen_guard(
        &mut self,
        guard: GuardHandle,
        expected: u64,
        operation: u64,
    ) -> Result<u64, DriverError> {
        let now = self.clock.now();
        let reopened = self.guards.reopen(
            guard,
            expected,
            operation,
            crate::guards::Requester::InProcess,
            0,
            now,
        );
        if let Err(error) = &reopened {
            self.report_guard_error(guard.id(), error);
        }
        reopened
    }

    /// A snapshot of the guard audit ring (G9 interim).
    #[must_use]
    pub fn guard_audit(&self) -> crate::guards::Audit {
        self.guards.audit()
    }

    /// The spin meter of the loop that drives [`EmbeddedDriver::do_work`]
    /// (`conductor spin time`, M5), once: that loop's idle strategy is its
    /// only writer (`crate::spin`). `None` once taken.
    pub fn take_spin_meter(&mut self) -> Option<crate::spin::SpinMeter> {
        if self.spin_taken {
            return None;
        }
        self.spin_taken = true;
        Some(crate::spin::SpinMeter::shared(Arc::clone(&self.spin_word)))
    }

    /// The tools' guard audit ring (M4), as a tool reads it: every
    /// transition with host and driver times.
    #[must_use]
    pub fn guard_audit_ring(&self) -> karyos_sys::diag::GuardAuditReader {
        self.guards.ring_reader()
    }

    /// Creates a stream (control path: allocates its log buffer). Its
    /// `initial_term_id` is drawn at random in place of the configured one
    /// (SPEC §4, initial state).
    ///
    /// # Errors
    ///
    /// Returns configuration and allocation errors; no stream is added on
    /// error, and the refusal is recorded in the error log. That includes
    /// [`DriverError::InvalidConfig`] for a schedule ring
    /// (`schedule_capacity` above 0): a local stream has no sender to
    /// release it (owner item 65), so timed lanes are network
    /// publications'. [`DriverError::Sys`] when the random source fails,
    /// before anything else is validated; it is logged too.
    pub fn add_stream(&mut self, config: StreamConfig) -> Result<StreamHandle, DriverError> {
        self.add_local_stream(config, false)
    }

    /// Tests: sets the next application trace point id the instance
    /// assigns, so a test reaches its last id (R-CORE-1) without 65 535
    /// registrations; past 65 535 every registration is refused.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn set_next_trace_point(&mut self, next: u32) {
        self.client_counters.set_next_trace_point(next);
    }

    /// Tests: stamps `stream`'s next reincarnation `by_ns` nanoseconds
    /// earlier than it happens, as if it had begun then, for its handles'
    /// rate copies (R-CORE-21).
    ///
    /// # Errors
    ///
    /// The stream lookup's errors.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn backdate_next_reincarnation(
        &mut self,
        stream: StreamHandle,
        by_ns: u64,
    ) -> Result<(), DriverError> {
        self.stream(stream)?.reincarnation_backdate = by_ns;
        Ok(())
    }

    /// [`EmbeddedDriver::add_stream`] whose schedule ring, if any, is
    /// taken: the caller consumes and releases the stream's schedule ring
    /// itself (a simulator's `ScheduleConsumer`); without that, the lane
    /// takes `schedule_capacity` offers and then back pressures for good.
    /// Not for applications: `add_stream`, the client facade, karyosd and
    /// the C ABI keep refusing a ring (owner item 65).
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_stream`], but for the schedule ring.
    #[doc(hidden)]
    pub fn add_stream_with_external_schedule(
        &mut self,
        config: StreamConfig,
    ) -> Result<StreamHandle, DriverError> {
        self.add_local_stream(config, true)
    }

    fn add_local_stream(
        &mut self,
        config: StreamConfig,
        external_schedule: bool,
    ) -> Result<StreamHandle, DriverError> {
        // The first term id, drawn on the control path before the stream
        // exists (SPEC §4, initial state); a failed draw refuses the add.
        let mut config = config;
        let key = [
            u64::from(config.buffer.stream_id.cast_unsigned()),
            u64::from(config.buffer.session_id.cast_unsigned()),
        ];
        // One lane, the configured one, with a quantum of the largest frame:
        // exactly today's stream.
        let lane = config.buffer.lane;
        let schedule = if external_schedule {
            Ok(())
        } else {
            local_schedule(&config)
        };
        let added = schedule
            .and_then(|()| self.draw_initial_term_id(self.config.initial_term_id))
            .and_then(|drawn| {
                config.buffer.initial_term_id = drawn;
                largest_charge(&config)
            })
            .and_then(|charge| self.add_aggregate_checked(config, &[lane], &[charge]))
            .and_then(|aggregate| aggregate.lane(lane).ok_or(DriverError::InvalidConfig));
        if let Err(error) = &added {
            self.diagnostics.error(
                &mut self.counters,
                crate::diagnostics::ErrorCode::StreamConfigRejected,
                key,
                &error.to_string(),
            );
        }
        added
    }

    /// Creates an aggregate publication of one to four lanes, `0` to
    /// `count - 1` (SPEC.md §7.4; `quantstratum-docs:
    /// karyos/design/aggregate-ownership.md`), on the control path: every
    /// lane is validated, sized and built first, privately, and only then
    /// are they all added in one step that cannot fail. Each lane is a
    /// stream; every lane reports the aggregate's registration. Every lane
    /// shares one `initial_term_id`, drawn as for a stream.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::add_stream`], and [`DriverError::InvalidConfig`]
    /// for no lane, more than four, or a quantum below the largest charged
    /// frame. No lane is added on error.
    pub fn add_aggregate(
        &mut self,
        config: AggregateConfig,
    ) -> Result<AggregateHandle, DriverError> {
        // As for a stream, one draw shared by every lane; a failed draw is
        // logged as any other refusal, as is a schedule ring.
        let mut config = config;
        match local_schedule(&config.stream)
            .and_then(|()| self.draw_initial_term_id(self.config.initial_term_id))
        {
            Ok(drawn) => {
                config.stream.buffer.initial_term_id = drawn;
                self.add_aggregate_drawn(config)
            }
            Err(error) => {
                let key = [
                    u64::from(config.stream.buffer.stream_id.cast_unsigned()),
                    u64::from(config.stream.buffer.session_id.cast_unsigned()),
                ];
                self.diagnostics.error(
                    &mut self.counters,
                    crate::diagnostics::ErrorCode::StreamConfigRejected,
                    key,
                    &error.to_string(),
                );
                Err(error)
            }
        }
    }

    /// [`EmbeddedDriver::add_aggregate`] with the `initial_term_id` already
    /// in `config`.
    pub(crate) fn add_aggregate_drawn(
        &mut self,
        config: AggregateConfig,
    ) -> Result<AggregateHandle, DriverError> {
        let key = [
            u64::from(config.stream.buffer.stream_id.cast_unsigned()),
            u64::from(config.stream.buffer.session_id.cast_unsigned()),
        ];
        let lanes: Vec<Lane> = (0..config.quanta.len())
            .map_while(|lane| {
                u8::try_from(lane)
                    .ok()
                    .and_then(|lane| Lane::try_new(lane).ok())
            })
            .collect();
        let added = if lanes.len() == config.quanta.len() {
            self.add_aggregate_checked(config.stream, &lanes, &config.quanta)
        } else {
            Err(DriverError::InvalidConfig)
        };
        if let Err(error) = &added {
            self.diagnostics.error(
                &mut self.counters,
                crate::diagnostics::ErrorCode::StreamConfigRejected,
                key,
                &error.to_string(),
            );
        }
        added
    }

    /// A publication's `initial_term_id`: `forced`, a test override, or a
    /// random draw.
    ///
    /// # Errors
    ///
    /// [`DriverError::Sys`] when the random source fails.
    pub(crate) fn draw_initial_term_id(&self, forced: Option<u32>) -> Result<TermId, DriverError> {
        if let Some(forced) = forced {
            return Ok(TermId::new(forced));
        }
        let mut word = [0u64; 1];
        karyos_sys::random::fill_u64s(&mut word)?;
        let [value] = word;
        // The high half.
        let [a, b, c, d, ..] = value.to_be_bytes();
        Ok(TermId::new(u32::from_be_bytes([a, b, c, d])))
    }

    /// Validates, stages and publishes the lanes `lanes` of an aggregate
    /// with `quanta`, all or nothing.
    fn add_aggregate_checked(
        &mut self,
        config: StreamConfig,
        lanes: &[Lane],
        quanta: &[u64],
    ) -> Result<AggregateHandle, DriverError> {
        // 1. Validate: the lane count and the profile, the key, the quota.
        let count = u8::try_from(lanes.len()).map_err(|_| DriverError::InvalidConfig)?;
        let profile = DrrConfig::new(quanta, largest_charge(&config)?)
            .map_err(|_| DriverError::InvalidConfig)?;
        // A key in use (active or retiring) is reported before the quota. A
        // network image of the key is not in the way: the two coexist, key
        // lookups preferring the local stream (karyos#490).
        let key = (config.buffer.stream_id, config.buffer.session_id);
        if self
            .streams
            .iter()
            .any(|s| (s.stream_id, s.session_id) == key && s.source.is_none())
        {
            return Err(DriverError::DuplicateStream {
                stream_id: key.0,
                session_id: key.1,
            });
        }
        if self
            .streams
            .len()
            .checked_add(lanes.len())
            .is_none_or(|total| total > self.config.max_streams)
        {
            return Err(DriverError::TooManyStreams);
        }
        let registration = self.next_stream;
        let next = registration
            .checked_add(u64::from(count))
            .ok_or(DriverError::StreamIdsExhausted)?;
        let aggregate = Aggregate {
            registration,
            lanes: count,
            profile,
        };
        // 2 and 3. Reserve the table, then build every lane privately. A
        // failure drops the staged lanes; nothing outside this call can
        // name them, and spare capacity is not state.
        self.streams.reserve(lanes.len());
        let mut staged: Vec<Stream<T>> = Vec::with_capacity(lanes.len());
        let mut handle = AggregateHandle {
            driver: self.id,
            registration,
            lanes: [None; MAX_LANES],
        };
        for (id, lane) in (registration..next).zip(lanes) {
            let buffer = LogBufferConfig {
                lane: *lane,
                ..config.buffer
            };
            match self.stage_lane(config, buffer, id, aggregate) {
                Ok(stream) => staged.push(stream),
                Err(error) => {
                    for stream in staged {
                        if let Some(counters) = stream.feeder_counters {
                            counters.free(&mut self.counters);
                        }
                    }
                    return Err(error);
                }
            }
            if let Some(slot) = handle.lanes.get_mut(usize::from(lane.get())) {
                *slot = Some(id);
            }
        }
        // 4. Publish in one step that cannot fail.
        self.next_stream = next;
        self.streams.extend(staged);
        self.update_stream_gauges();
        Ok(handle)
    }

    /// The table of a conflated stream: in a driver-only region when this
    /// driver admits remote clients, so views in other processes map it
    /// read-only (`quantstratum-docs: karyos/design/conflation-end-to-end.md`,
    /// Cross-process views); on the heap otherwise.
    fn conflation_table(
        &mut self,
        config: ConflationConfig,
    ) -> Result<ConflationWriter, DriverError> {
        #[cfg(target_os = "linux")]
        if let Some(admission) = self.admission.as_mut() {
            let (instance, region) = admission.next_region()?;
            return Ok(karyos_sys::conflation::conflation_in(
                instance,
                region,
                config.keys,
                config.value_capacity,
                config.journal_capacity,
            )?);
        }
        Ok(conflation(
            config.keys,
            config.value_capacity,
            config.journal_capacity,
        )?)
    }

    /// Refuses a lane above `max_stream_bytes` (R-CORE-34) before
    /// anything is created: every stream the driver makes passes here.
    pub(crate) fn check_stream_bytes(
        &self,
        buffer: &LogBufferConfig,
        conflation: Option<&ConflationConfig>,
    ) -> Result<(), DriverError> {
        check_lane_bytes(self.config.max_stream_bytes, buffer, conflation)
    }

    /// Builds one lane stream of an aggregate, not yet added: its buffer,
    /// conductor, conflation feeder and counters.
    fn stage_lane(
        &mut self,
        config: StreamConfig,
        buffer_config: LogBufferConfig,
        id: u64,
        aggregate: Aggregate,
    ) -> Result<Stream<T>, DriverError> {
        #[cfg(test)]
        if self.fail_at == Some(id) {
            return Err(DriverError::Sys(
                karyos_sys::error::SysError::ResourcesUnavailable,
            ));
        }
        let key = (config.buffer.stream_id, config.buffer.session_id);
        // The table's shape, before the lane is sized for the cap. Since
        // `table_region_bytes` refuses what `conflation_shape` refuses,
        // the order no longer decides the error (karyos#824).
        let shape = config.conflation.map(conflation_shape).transpose()?;
        self.check_stream_bytes(&buffer_config, config.conflation.as_ref())?;
        let buffer = Arc::new(<T as sealed::Create>::create(
            self,
            buffer_config,
            Generation::default(),
            shape,
        )?);
        let mut conductor = buffer
            .conductor_owned()
            .ok_or(karyos_sys::error::SysError::ResourcesUnavailable)?;
        let (feeder, members) = match config.conflation {
            Some(conflation_config) => {
                let writer = self.conflation_table(conflation_config)?;
                let inner = conductor.subscribe(Role::Required)?;
                let link = GenerationLink::new();
                let subscription =
                    ClientSubscription::new(inner).with_generation(Arc::clone(&link), 0)?;
                let feeder = ConflationFeeder {
                    subscription,
                    writer,
                    fresh: None,
                };
                let member = Member {
                    link: Arc::downgrade(&link),
                    kind: MemberKind::Feeder,
                    host: false,
                };
                (Some(feeder), vec![member])
            }
            None => (None, Vec::new()),
        };
        let feeder_counters = feeder.is_some().then(|| {
            FeederCounters::allocate(
                &mut self.counters,
                aggregate.registration,
                buffer_config.lane.get(),
            )
        });
        Ok(Stream {
            id,
            source: None,
            replay: false,
            aggregate,
            retiring: false,
            buffer,
            conductor,
            leases: Arc::new(StreamLeases::default()),
            allow_unconnected: config.allow_unconnected,
            policy: config.on_required_loss,
            stream_id: key.0,
            session_id: key.1,
            claim_waiting: false,
            config: buffer_config,
            conflation: config.conflation,
            generation: Generation::default(),
            base: 0,
            members,
            cutover: None,
            retained: Vec::new(),
            spare: None,
            feeder,
            closed_view: None,
            conflation_terminal: None,
            feeder_counters,
            guarded: None,
            incarnation: FIRST_INCARNATION,
            reincarnated_at: 0,
            reincarnation_backdate: 0,
            replaced: Vec::new(),
            network: NetworkLane::Local,
            schedule: None,
            schedule_issued: false,
            schedule_clock: None,
            timed_counters: None,
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
    /// On a guarded stream also [`DriverError::GuardNotOpen`],
    /// [`DriverError::GuardSealed`], [`DriverError::IncarnationsExhausted`],
    /// [`DriverError::PositionsExhausted`] and, for a lane of a network
    /// publication between incarnations after a guard reopen,
    /// [`DriverError::QuarantinedAlias`]: retryable, at its `until_ns`. The
    /// first call after the reopen removes the old incarnation's session;
    /// the call past the alias's quarantine adds the next one, every lane
    /// at once (see [`EmbeddedDriver::reopen_guard`]). Nothing is taken on
    /// error.
    pub fn publication(
        &mut self,
        stream: StreamHandle,
    ) -> Result<ClientPublication<T>, DriverError> {
        // A foreign, freed or removed stream is refused before anything
        // else, so nothing is created for it.
        let _ = self.active_stream(stream)?;
        // After a guard close and reopen, the fresh incarnation first.
        self.reincarnate_if_reopened(stream)?;
        // A guarded handle's binding is prepared first, so a refusal takes
        // nothing.
        let binding = match self.prepare_guard_binding(stream, crate::guard_streams::Place::Heap) {
            Ok(binding) => binding,
            Err(error) => {
                let guard = self
                    .stream_ref(stream)
                    .ok()
                    .and_then(|found| found.guarded.as_ref().map(|guarded| guarded.guard.id()));
                if let Some(guard) = guard {
                    self.report_guard_error(guard, &error);
                }
                return Err(error);
            }
        };
        // A timed lane's handle gets its schedule binding, prepared before
        // the publication is taken, so a refusal takes nothing.
        // The binding first, so a refused one allocates no counters; then
        // the lane's counters, which its handles share.
        let schedule = self.prepare_schedule_binding(stream)?;
        let schedule = match schedule {
            Some(binding) => {
                self.ensure_timed_counters(stream)?;
                let counters = self
                    .stream_ref(stream)?
                    .timed_counters
                    .as_ref()
                    .map(|counters| Arc::clone(&counters.offers));
                Some(match counters {
                    Some(counters) => binding.with_counters(counters),
                    None => binding,
                })
            }
            None => None,
        };
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
        let (link, base) = stream.join_host(MemberKind::Exclusive);
        // Its stream's conflation table comes with the buffer (F7b-2c-2).
        let publication = ClientPublication::with_lease(inner, stream.allow_unconnected, lease);
        let mut publication = publication.with_generation(link, base)?;
        if let (Some((client, bound)), Some(guarded)) = (binding, stream.guarded.as_mut()) {
            publication = publication.with_guard(client);
            guarded.bind(bound);
        }
        if let Some(schedule) = schedule {
            stream.fix_schedule()?;
            publication = publication.with_schedule(schedule);
        }
        self.update_stream_gauges();
        Ok(publication)
    }

    /// The schedule binding of a timed lane's next handle; `None` for a
    /// lane that is not timed.
    fn prepare_schedule_binding(
        &self,
        stream: StreamHandle,
    ) -> Result<Option<karyos_client::schedule::ScheduleBinding>, DriverError> {
        let found = self.stream_ref(stream)?;
        if found.buffer.schedule_ring().is_none() {
            return Ok(None);
        }
        let options = found.schedule.unwrap_or_default();
        let clock = match &found.schedule_clock {
            Some(clock) => clock.clone(),
            None => karyos_client::schedule::ScheduleClock::host(options.domain)?,
        };
        Ok(Some(karyos_client::schedule::ScheduleBinding::new(
            options, clock,
        )))
    }

    /// Allocates a timed lane's counters once, when its first handle is
    /// prepared; nothing for a lane that is not timed.
    pub(crate) fn ensure_timed_counters(
        &mut self,
        stream: StreamHandle,
    ) -> Result<(), DriverError> {
        let found = self.stream_ref(stream)?;
        if found.buffer.schedule_ring().is_none() || found.timed_counters.is_some() {
            return Ok(());
        }
        let (id, lane) = (found.id, found.buffer.lane().get());
        let domain = found.schedule.unwrap_or_default().domain;
        let counters = TimedCounters::allocate(&mut self.counters, id, lane, domain);
        self.stream(stream)?.timed_counters = Some(counters);
        Ok(())
    }

    /// The sender's counter cells of a timed lane, for its
    /// [`crate::timed_gate::TimedGate`]
    /// ([`crate::timed_gate::TimedGate::attach_counters`]); `None` until
    /// the lane's first handle is issued, and for a lane that is not
    /// timed.
    ///
    /// # Errors
    ///
    /// The stream lookup errors.
    pub fn timed_counters(
        &self,
        stream: StreamHandle,
    ) -> Result<Option<Arc<crate::timed_gate::TimedLaneCounters>>, DriverError> {
        Ok(self
            .stream_ref(stream)?
            .timed_counters
            .as_ref()
            .map(|counters| Arc::clone(&counters.sender)))
    }

    /// The words of a timed lane's schedule ring, for its sender's
    /// [`crate::schedule::ScheduleConsumer`]; `None` for a lane that is
    /// not timed.
    ///
    /// # Errors
    ///
    /// The stream lookup errors.
    pub fn schedule_ring(
        &self,
        stream: StreamHandle,
    ) -> Result<Option<&[karyos_sys::sync::AtomicU64]>, DriverError> {
        Ok(self.stream_ref(stream)?.buffer.schedule_ring())
    }

    /// Audits the grants of the stream `stream` from now on (`quantstratum-docs:
    /// karyos/design/archive-host.md`, H3): each handle the control path
    /// grants on it is recorded for [`Self::drain_grant_audits`]. A handle
    /// the host takes in process ([`Self::publication`], [`Self::subscribe`])
    /// is the host's own and is not recorded. Control path.
    ///
    /// # Errors
    ///
    /// The stream lookup errors.
    pub fn audit_grants(&mut self, stream: StreamHandle) -> Result<(), DriverError> {
        let id = self.stream_ref(stream)?.id;
        self.grant_audits.watch(id);
        Ok(())
    }

    /// Hands every grant recorded on an audited stream since the last
    /// drain to `each`, oldest first.
    pub fn drain_grant_audits(&mut self, each: impl FnMut(crate::grant_audit::GrantAudit)) {
        self.grant_audits.drain(each);
    }

    /// Grants on audited streams dropped because more than 64 waited for a
    /// drain.
    #[must_use]
    pub fn grant_audits_dropped(&self) -> u64 {
        self.grant_audits.dropped()
    }

    /// Seals a timed lane whose sender's [`crate::timed_gate::TimedGate`]
    /// found a missed deadline under cancel-on-deadline (G7), with
    /// `SealReason::DeadlineMissed`: the step between gates
    /// ([`crate::timed_gate::TimedGate::between_gates`]). A stream already
    /// sealed keeps its first reason.
    ///
    /// # Errors
    ///
    /// [`DriverError::Sys`] from the seal (a broken invariant); the stream
    /// lookup errors.
    pub fn seal_deadline_missed(&mut self, stream: StreamHandle) -> Result<(), DriverError> {
        let found = self.active_stream(stream)?;
        crate::timed_gate::seal_deadline_missed(&mut found.conductor)?;
        Ok(())
    }

    /// [`Self::schedule_stream`] with the lane's offers checked against
    /// `clock` instead of the host's clock of `options.domain`: a
    /// simulator's virtual time, or a driver's own clock. `clock` runs on
    /// the offer path; see [`karyos_client::schedule::ScheduleClock`].
    ///
    /// # Errors
    ///
    /// As [`Self::schedule_stream`].
    pub fn schedule_stream_with_clock(
        &mut self,
        stream: StreamHandle,
        options: karyos_client::schedule::ScheduleOptions,
        clock: karyos_client::schedule::ScheduleClock,
    ) -> Result<(), DriverError> {
        self.schedule_stream(stream, options)?;
        self.active_stream(stream)?.schedule_clock = Some(clock);
        Ok(())
    }

    /// Sets a timed lane's settings (`quantstratum-docs:
    /// karyos/design/timed-tx.md`, TT-2 and TT-3) on the control path,
    /// before any publication handle is issued: its clock domain, horizon,
    /// lateness tolerance and cancel-on-deadline. Without it a timed lane
    /// uses [`karyos_client::schedule::ScheduleOptions::default`].
    ///
    /// Timed lanes are meant for network publications
    /// ([`EmbeddedDriver::add_timed_network_publication`]), whose sender
    /// releases each schedule entry once its message is sent. On a stream
    /// of [`EmbeddedDriver::add_stream`] nothing sends, so nothing releases
    /// the ring: the lane takes `schedule_capacity` timed offers, then back
    /// pressures for good.
    ///
    /// # Errors
    ///
    /// [`DriverError::NotTimed`] for a stream whose buffer has no schedule
    /// ring (`schedule_capacity` 0); [`DriverError::InvalidConfig`] once a
    /// handle of the incarnation was issued, also if it was dropped since;
    /// [`DriverError::Client`] with `InvalidSchedule` for a zero horizon and
    /// for the `Tai` domain off Linux; the stream lookup errors.
    pub fn schedule_stream(
        &mut self,
        stream: StreamHandle,
        options: karyos_client::schedule::ScheduleOptions,
    ) -> Result<(), DriverError> {
        let _ = options.domain.clock()?;
        if options.max_horizon == 0 {
            return Err(DriverError::Client(
                karyos_client::ClientError::InvalidSchedule {
                    reason: "a zero horizon",
                },
            ));
        }
        let found = self.active_stream(stream)?;
        if found.buffer.schedule_ring().is_none() {
            return Err(DriverError::NotTimed { stream: found.id });
        }
        // Once a handle of this incarnation was issued, its entries are in
        // the ring under the old settings, also after the handle is gone.
        if found.schedule_issued {
            return Err(DriverError::InvalidConfig);
        }
        found.schedule = Some(options);
        // Settings that change before any handle relabel the counters: the
        // next handle allocates them again.
        found.schedule_clock = None;
        found.timed_counters = None;
        Ok(())
    }

    /// Creates the fresh incarnation of a guarded stream a guard close
    /// sealed, once its guard is open again (`quantstratum-docs:
    /// karyos/design/guards-and-abort.md`, The fresh incarnation): a new
    /// log buffer from the stream's configuration starting at the sealed
    /// one's seal position, the next incarnation number, and a new walker.
    /// The sealed incarnation retires with its walker and the old handles'
    /// rings. Every check comes first; nothing changes on refusal. A stream
    /// that is not guarded, not sealed by a guard close, or whose guard is
    /// still closed is left as it is.
    ///
    /// A lane of a network publication reincarnates with its whole
    /// aggregate, as a new publication identity on the wire
    /// (`reincarnate_network`).
    ///
    /// # Errors
    ///
    /// [`DriverError::GuardSealed`] while the sealed incarnation's
    /// publication has not released (no seal position yet), and for a
    /// conflated stream or one with a cutover or retained mappings (remote
    /// holders stay on the replaced incarnation, which they pin);
    /// [`DriverError::IncarnationsExhausted`]; [`DriverError::PositionsExhausted`];
    /// [`DriverError::QuarantinedAlias`] for a lane of a network
    /// publication between incarnations; and the buffer's allocation
    /// errors.
    fn reincarnate_if_reopened(&mut self, handle: StreamHandle) -> Result<(), DriverError> {
        let found = self.stream_ref(handle)?;
        let (registration, id) = (found.aggregate.registration, found.id);
        let network = found.network != NetworkLane::Local;
        if network
            || self.net.as_ref().is_some_and(|net| {
                net.is_network_aggregate(registration)
                    || net
                        .reincarnation(registration)
                        .is_ok_and(|phase| phase.is_some())
            })
        {
            return self.reincarnate_network(registration, id);
        }
        let Some(plan) = self.reincarnation_plan(handle)? else {
            return Ok(());
        };
        let fresh = self.prepare_incarnation(&plan)?;
        self.swap_incarnation(handle, plan, fresh)
    }

    /// The next incarnation of a guarded stream a guard close sealed, once
    /// its guard is open again, with every check of
    /// `reincarnate_if_reopened` done; `None` for a stream left as it is.
    fn reincarnation_plan(&self, handle: StreamHandle) -> Result<Option<Incarnation>, DriverError> {
        let found = self.stream_ref(handle)?;
        let Some(guarded) = &found.guarded else {
            return Ok(None);
        };
        // A removed stream is refused by `publication()` itself; nothing is
        // created for it.
        if found.retiring
            || found.conductor.seal_reason() != Some(SealReason::GuardClosed)
            || !self.guards.state(guarded.guard)?.open
        {
            return Ok(None);
        }
        let sealed = DriverError::GuardSealed { stream: found.id };
        let position = match found.conductor.seal_state() {
            SealState::Positioned { position } | SealState::Retired { position } => position,
            SealState::Active | SealState::Sealed => return Err(sealed),
        };
        // Remote registrations, grants and held bounds stay on the replaced
        // incarnation, which retires only once none names it (G-d2b).
        if found.conflation.is_some() || found.cutover.is_some() || !found.retained.is_empty() {
            return Err(sealed);
        }
        let incarnation = found
            .incarnation
            .checked_add(1)
            .ok_or(DriverError::IncarnationsExhausted { stream: found.id })?;
        let base = found
            .base
            .checked_add(position)
            .ok_or(DriverError::PositionsExhausted)?;
        Ok(Some(Incarnation {
            incarnation,
            base,
            config: found.config,
            generation: found.generation,
            guard: guarded.guard,
            messages: guarded.messages,
            rate: guarded.rate,
            rate_version: guarded.rate_version,
            reserve: guarded.reserve,
            gate_slot: guarded.gate_slot().cloned(),
        }))
    }

    /// The buffer, conductor and walker of the incarnation `plan`, not
    /// installed yet.
    fn prepare_incarnation(&mut self, plan: &Incarnation) -> Result<Fresh<T>, DriverError> {
        // A conflated stream has no fresh incarnation
        // (`reincarnation_plan` refuses it), so its buffer has no table.
        // Its configuration is the stream's current one, already within
        // `max_stream_bytes`, so it needs no cap check; kept checked in
        // debug builds.
        debug_assert!(
            check_lane_bytes(self.config.max_stream_bytes, &plan.config, None).is_ok(),
            "a reincarnation above max_stream_bytes"
        );
        let buffer = Arc::new(<T as sealed::Create>::create(
            self,
            plan.config,
            plan.generation,
            None,
        )?);
        let mut conductor = buffer
            .conductor_owned()
            .ok_or(karyos_sys::error::SysError::ResourcesUnavailable)?;
        let walker = conductor.subscribe(Role::Walker)?;
        let scratch =
            usize::try_from(buffer.max_message_length()).map_err(|_| DriverError::InvalidConfig)?;
        Ok(Fresh {
            buffer,
            conductor,
            walker,
            scratch,
        })
    }

    /// Installs the prepared incarnation `plan` of `handle`; the sealed
    /// one is kept until it retires.
    fn swap_incarnation(
        &mut self,
        handle: StreamHandle,
        plan: Incarnation,
        fresh: Fresh<T>,
    ) -> Result<(), DriverError> {
        let found = self.stream(handle)?;
        let mut guarded = crate::guard_streams::GuardedStream::new(
            plan.guard,
            plan.messages,
            (plan.rate, plan.reserve),
            fresh.walker,
            fresh.scratch,
        );
        // The policy at its version, then the publication's slot, which
        // already holds it: a reincarnation publishes nothing to its gate.
        if let Some(policy) = plan.rate {
            guarded.set_rate(policy, plan.rate_version);
        }
        if let Some(slot) = plan.gate_slot {
            guarded.keep_gate_slot(slot);
        }
        if let Some(old) = found.guarded.replace(guarded) {
            found.replaced.push(Replaced {
                incarnation: found.incarnation,
                base: found.base,
                buffer: Arc::clone(&found.buffer),
                conductor: std::mem::replace(&mut found.conductor, fresh.conductor),
                guarded: old,
            });
        }
        found.buffer = fresh.buffer;
        // The buffer's configuration, which a network sender announces.
        found.config = plan.config;
        found.incarnation = plan.incarnation;
        found.reincarnated_at = karyos_sys::host_clock::host_monotonic_ns()
            .saturating_sub(std::mem::take(&mut found.reincarnation_backdate))
            .max(1);
        // A fresh incarnation has a fresh ring. A local lane takes new
        // settings before its next handle; a network lane's are its
        // sender's, fixed from the add: kept, with its counters, on every
        // lane, so a reopen bypasses no refusal of the add.
        if found.network == NetworkLane::Local {
            found.schedule_issued = false;
        }
        found.base = plan.base;
        found.members.clear();
        found.spare = None;
        found.claim_waiting = false;
        Ok(())
    }

    /// Reincarnates the network publication `registration`, every lane at
    /// once, as a new publication identity on the wire (`quantstratum-docs:
    /// karyos/design/guards-and-abort.md`, On the network). The first call
    /// after the reopen removes the old incarnation's session, with no
    /// linger (its closed guard sends no EOS); its alias then stays
    /// quarantined for `alias_quarantine` from that removal, as remote
    /// receivers quarantine it, and the next incarnation is added under the
    /// same alias only after that. No incarnation overlaps the other on
    /// the sender. Until then each call refuses with
    /// [`DriverError::QuarantinedAlias`]; the call past the quarantine
    /// swaps in every lane's next incarnation and posts its sender.
    fn reincarnate_network(&mut self, registration: u64, stream: u64) -> Result<(), DriverError> {
        let handle = self.aggregate_of(registration)?;
        // A network that closed or whose agent failed adds no sender: a
        // lane swapped without one, or a reopened one, is refused and
        // stays as it is (sealed), so no offer is accepted that no sender
        // reads.
        let unusable = match self.net.as_ref() {
            None => Some(DriverError::NetworkUnavailable),
            Some(net) => net.unusable(),
        };
        if let Some(error) = unusable {
            for lane in handle.streams() {
                let found = self.stream_ref(lane)?;
                if found.network == NetworkLane::AwaitingSender
                    || self.reincarnation_plan(lane)?.is_some()
                {
                    return Err(error);
                }
            }
            return Ok(());
        }
        let net = self.net.as_ref().ok_or(DriverError::NetworkUnavailable)?;
        let swapped = match net.reincarnation(registration)? {
            Some(crate::net::ReincarnationPhase::Waiting { until_ns }) => {
                // A guard closed again while waiting is reported as such.
                let found = self.stream_ref(StreamHandle {
                    driver: self.id,
                    stream,
                })?;
                if let Some(guarded) = &found.guarded
                    && !self.guards.state(guarded.guard)?.open
                {
                    return Err(DriverError::GuardNotOpen {
                        guard: guarded.guard.id(),
                    });
                }
                return Err(DriverError::QuarantinedAlias { stream, until_ns });
            }
            Some(crate::net::ReincarnationPhase::Ready { swapped }) => Some(swapped),
            None => None,
        };
        if swapped != Some(true) {
            // Every lane's checks first: all lanes reincarnate, or none.
            let mut plans = Vec::with_capacity(usize::from(handle.lanes()));
            for lane in handle.streams() {
                plans.push((lane, self.reincarnation_plan(lane)?));
            }
            let reopened = plans.iter().filter(|(_, plan)| plan.is_some()).count();
            if reopened == 0 {
                return Ok(());
            }
            if reopened != plans.len() {
                return Err(DriverError::GuardSealed { stream });
            }
            if swapped.is_none() {
                // Its open sender journals close before the removal, as
                // on `remove_aggregate`.
                let closes = self.publication_journal_closes(registration);
                let net = self.net.as_mut().ok_or(DriverError::NetworkUnavailable)?;
                let until_ns = net.start_reincarnation(registration, stream, closes)?;
                return Err(DriverError::QuarantinedAlias { stream, until_ns });
            }
            // The new incarnation is announced anew: its first term id is
            // drawn before it, as for any publication (SPEC §4, initial
            // state), shared by every lane; a test pin still wins. A
            // failed draw refuses with nothing swapped.
            let forced = self
                .config
                .network
                .and_then(|network| network.stream_defaults.initial_term_id);
            let drawn = self.draw_initial_term_id(forced)?;
            let mut fresh = Vec::with_capacity(plans.len());
            for (lane, plan) in plans {
                if let Some(mut plan) = plan {
                    plan.config.initial_term_id = drawn;
                    let prepared = self.prepare_incarnation(&plan)?;
                    fresh.push((lane, plan, prepared));
                }
            }
            // Every lane is prepared: the swaps cannot fail. Nothing is
            // issued on them until their sender is posted.
            for (lane, plan, prepared) in fresh {
                self.swap_incarnation(lane, plan, prepared)?;
                self.stream(lane)?.network = NetworkLane::AwaitingSender;
            }
        }
        let net = self.net.as_mut().ok_or(DriverError::NetworkUnavailable)?;
        let channel = net
            .reincarnation_swapped(registration)
            .ok_or(DriverError::UnknownStream { stream })?;
        let incarnation = self.stream_ref(StreamHandle {
            driver: self.id,
            stream: registration,
        })?;
        let incarnation = incarnation.incarnation;
        // A refused add leaves the lanes swapped: a later call posts the
        // sender again, and nothing is issued meanwhile.
        self.attach_sender(&handle, channel, incarnation, true)?;
        if let Some(net) = self.net.as_mut() {
            let _ = net.end_reincarnation(registration);
        }
        Ok(())
    }

    /// The handle of the aggregate `registration`, from its lanes.
    fn aggregate_of(&self, registration: u64) -> Result<AggregateHandle, DriverError> {
        let first = self.stream_ref(StreamHandle {
            driver: self.id,
            stream: registration,
        })?;
        let mut handle = AggregateHandle {
            driver: self.id,
            registration,
            lanes: [None; MAX_LANES],
        };
        for offset in 0..u64::from(first.aggregate.lanes) {
            let id = registration
                .checked_add(offset)
                .ok_or(DriverError::UnknownStream {
                    stream: registration,
                })?;
            let lane = self.stream_ref(StreamHandle {
                driver: self.id,
                stream: id,
            })?;
            if let Some(slot) = handle.lanes.get_mut(usize::from(lane.config.lane.get())) {
                *slot = Some(id);
            }
        }
        Ok(handle)
    }

    /// The bound of a guarded publication about to be granted to a remote
    /// client (G-x2), after the steps `publication()` takes first: the
    /// fresh incarnation after a guard reopen, then the binding, its ring
    /// and consumed cell in the regions `ring` and `cell` of `instance`.
    /// `None` for a stream that is not guarded. Nothing is registered on
    /// error.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_remote_guard(
        &mut self,
        stream: u64,
        instance: u128,
        ring: u64,
        cell: u64,
    ) -> Result<Option<crate::guard_streams::Bound>, DriverError> {
        let handle = StreamHandle {
            driver: self.id,
            stream,
        };
        self.reincarnate_if_reopened(handle)?;
        let place = crate::guard_streams::Place::Regions {
            instance,
            ring,
            cell,
        };
        // The client binds its own handle from the granted regions (G-x3).
        Ok(self
            .prepare_guard_binding(handle, place)?
            .map(|(_, bound)| bound))
    }

    /// Hands `bound` to the walker of guarded stream `stream`, once its
    /// grant is recorded.
    pub(crate) fn bind_remote_guard(&mut self, stream: u64, bound: crate::guard_streams::Bound) {
        if let Some(guarded) = self
            .streams
            .iter_mut()
            .find(|found| found.id == stream)
            .and_then(|found| found.guarded.as_mut())
        {
            guarded.bind(bound);
        }
    }

    /// The guard binding of a handle about to be issued on a guarded
    /// stream: refused on a stream a guard close sealed (its incarnation is
    /// final, G-d2 brings the fresh one) and while the guard is not open.
    fn prepare_guard_binding(
        &self,
        stream: StreamHandle,
        place: crate::guard_streams::Place,
    ) -> Result<Option<(karyos_client::GuardBinding, crate::guard_streams::Bound)>, DriverError>
    {
        let found = self.stream_ref(stream)?;
        let Some(guarded) = &found.guarded else {
            return Ok(None);
        };
        // A closed guard first: nothing is issued or created while it is.
        let state = self.guards.state(guarded.guard)?;
        if !state.open {
            return Err(DriverError::GuardNotOpen {
                guard: guarded.guard.id(),
            });
        }
        // Open, yet still the sealed incarnation: it could not be replaced.
        if found.conductor.seal_reason() == Some(SealReason::GuardClosed) {
            return Err(DriverError::GuardSealed { stream: found.id });
        }
        // The handle, the gate and the ring's header all name the guard by
        // its index in the guard words.
        let (words, index) = self.guards.view(guarded.guard)?;
        let (ring, consumed, writer) =
            crate::guard_streams::new_ring(guarded.messages, state.epoch, index, place)?;
        // A reincarnation's start, for the handle's rate copy, local or
        // remote.
        if found.incarnation > FIRST_INCARNATION {
            karyos_sys::outcome_ring::set_reincarnated_at(ring.words(), found.reincarnated_at);
        }
        let client = karyos_client::GuardBinding::new(
            words,
            index,
            state.epoch,
            Arc::clone(&ring) as Arc<dyn karyos_client::SharedWords>,
            Arc::clone(&consumed) as Arc<dyn karyos_client::ConsumedCell>,
            found.config.lane.get() + 1,
            guarded.messages,
        )?;
        // The handle's early copy of the rate limit, read against the host
        // clock; the sender gate's bucket is authoritative. A reincarnation's
        // copy starts empty, as its gate does (R-CORE-21).
        let client = if found.incarnation > FIRST_INCARNATION {
            client.reincarnated_at(found.reincarnated_at)
        } else {
            client
        };
        let client = match guarded.rate {
            Some(policy) => client.with_rate(policy, karyos_sys::host_clock::host_monotonic_ns),
            // No policy yet: the handle watches its ring for one.
            None => client.with_published_rate(karyos_sys::host_clock::host_monotonic_ns),
        };
        let bound = crate::guard_streams::Bound {
            from: found.conductor.head()?,
            epoch: state.epoch,
            ring,
            consumed,
            writer,
        };
        Ok(Some((client, bound)))
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
    ) -> Result<ClientConcurrentPublication<T>, DriverError> {
        let stream = self.active_stream(stream)?;
        stream.issuing()?;
        let inner = stream
            .conductor
            .concurrent_publication()
            .map_err(mode_error)?
            .ok_or(DriverError::PublicationTaken)?;
        let lease = Lease::acquire(&stream.leases, &Arc::new(LeaseEnd::default()));
        let (link, base) = stream.join_host(MemberKind::Concurrent);
        // Its stream's conflation table comes with the buffer (F7b-2c-2).
        let publication =
            ClientConcurrentPublication::with_lease(inner, stream.allow_unconnected, lease);
        let publication = publication.with_generation(link, base)?;
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
    ) -> Result<ClientSubscription<T>, DriverError> {
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

    /// Subscribes to the latest values in a stream's keyed conflation table.
    /// This reader is independent of log mapping generations and may skip
    /// intermediate versions.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::NotConflated`] when the stream was created
    /// without conflation, [`DriverError::StreamRetiring`] for a removed
    /// stream, and [`DriverError::UnknownStream`] for a foreign or freed
    /// stream.
    pub fn subscribe_conflated(
        &mut self,
        stream: StreamHandle,
    ) -> Result<ConflatedSubscription, DriverError> {
        let budget = self.config.conflated_subscription_budget;
        let stream = self.active_stream(stream)?;
        let feeder = stream.feeder.as_ref().ok_or(DriverError::NotConflated)?;
        Ok(ConflatedSubscription::new(feeder.writer.reader(), budget))
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
        // Replay targets whose feed was dropped unfinished retire.
        self.reap_replays();
        #[cfg(target_os = "linux")]
        let admitted = self.serve_admission();
        #[cfg(not(target_os = "linux"))]
        let admitted: (u32, Option<DriverError>) = (0, None);
        // Retire before sampling liveness: an orderly close at the
        // deadline is a retirement, not a time-out.
        self.retire_closed_clients();
        let alive = self.serve_liveness();
        self.sweep_ended_registrations();
        // What ended registrations owned goes with them (W5b).
        self.reconcile_network_owned();
        // Their publications' admission states, when they changed
        // (karyos#637).
        self.send_network_admissions();
        self.free_retired_streams();
        let mut work = self.serve_commands();
        let mut first_error = None;
        add_step(&self.counters, &mut work, &mut first_error, admitted);
        // An agent failure is an error, not a counter overflow.
        let (network, failure) = self.serve_network();
        add_work(&self.counters, &mut work, &mut first_error, network);
        if let Some(error) = failure {
            first_error.get_or_insert(error);
        }
        add_work(&self.counters, &mut work, &mut first_error, alive);
        let charged = self.charged_generations();
        let mut opened = Vec::new();
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
            if stream.cutover.is_some() {
                let before = stream.generation.get();
                let now = clock.now();
                if let Err(error) = stream.advance_cutover(now, deadline) {
                    first_error.get_or_insert(error);
                }
                if stream.generation.get() != before {
                    opened.push((stream.id, before, now));
                }
            }
            stream.forget_unused(&charged);
        }
        // Remote participants of the cutovers that opened, then the fences
        // whose deadline passed; the clock is read only while one waits.
        for (stream, before, now) in opened {
            self.open_remote_successors(stream, before, now);
        }
        if self.fences_pending() {
            let now = self.clock.now();
            self.fence_late_successors(now);
        }
        if !self.holding.is_empty() {
            self.report_withdrawn_bounds();
        }
        match self.walk_guarded() {
            Ok(walked) => add_work(&self.counters, &mut work, &mut first_error, walked),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
        match self.feed_conflation() {
            Ok(feeder_work) => add_work(&self.counters, &mut work, &mut first_error, feeder_work),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
        let mirrored = self
            .trace_journals
            .drain(&mut self.diagnostics, &mut self.counters);
        add_work(&self.counters, &mut work, &mut first_error, mirrored);
        self.update_stream_gauges();
        self.guard_cells.sync(&self.guards, &mut self.counters);
        // The close acknowledgements of closed guards (M4b).
        let clock = &mut self.clock;
        self.guard_ack_cells.sync(
            &self.guards,
            &self.guard_senders,
            &mut self.counters,
            &mut || clock.now(),
            self.config.guard_ack_timeout,
        );
        // The conductor loop's spin time, stored by its meter on this thread.
        self.counters
            .set_conductor_spin(self.spin_word.load(std::sync::atomic::Ordering::Relaxed));
        self.sample_positions();
        match first_error {
            Some(error) => Err(error),
            None => Ok(work),
        }
    }

    /// One walk per guarded stream (guards-and-abort.md, Local streams):
    /// final outcome records for the blocks committed or aborted since the
    /// last walk, under the walker budget. A lapped walker, a broken
    /// invariant, abandons the bound rings and is reported.
    fn walk_guarded(&mut self) -> Result<u32, DriverError> {
        let budget = self.config.guard_walker_budget;
        let mut work = 0u32;
        let mut first_error = None;
        let mut lapped = Vec::new();
        // The (stream, incarnation) pairs an in-process registration, a
        // remote grant or a held bound still names: a replaced incarnation
        // they name is kept, so a reader can read it to its seal. A remote
        // registration pins through its grants, not by itself: one with no
        // grant left reads nothing and is reclaimed. A dead remote client
        // releases them through its liveness timeout or exit proof.
        let clients = &self.clients;
        let mut pinned: Vec<(u64, u64)> = self
            .registrations
            .iter()
            .filter(|registration| {
                clients
                    .iter()
                    .find(|slot| slot.id() == registration.client())
                    .is_none_or(|slot| slot.ledger.is_none())
            })
            .map(|registration| (registration.stream(), registration.incarnation()))
            .chain(
                self.holding
                    .iter()
                    .map(|entry| (entry.stream(), entry.incarnation())),
            )
            .collect();
        for client in &self.clients {
            if let Some(ledger) = &client.ledger {
                pinned.extend(
                    ledger
                        .grants()
                        .iter()
                        .map(|grant| (grant.stream, grant.incarnation)),
                );
            }
        }
        for stream in &mut self.streams {
            let lane = stream.config.lane.get();
            // Replaced incarnations first: their last pass, then their
            // retirement once the walker ended and the readers passed the
            // seal.
            for replaced in &mut stream.replaced {
                duty(
                    &self.counters,
                    &mut work,
                    &mut first_error,
                    &mut replaced.conductor,
                );
                match replaced
                    .guarded
                    .walk(budget, replaced.base, lane, replaced.incarnation)
                {
                    Ok(walked) => {
                        self.counters
                            .add(Event::GuardOutcomesWritten, u64::from(walked.written));
                        self.counters
                            .add(Event::GuardOutcomesLost, u64::from(walked.lost));
                        if walked.budget_exhausted {
                            self.counters.add(Event::GuardWalkerBudgetExhausted, 1);
                        }
                        // A lapped walker abandoned its rings: nothing more
                        // will be recorded, so the entry is done.
                        if walked.overrun {
                            lapped.push(stream.id);
                            replaced.guarded.finish();
                        }
                        add_work(&self.counters, &mut work, &mut first_error, walked.written);
                        add_work(&self.counters, &mut work, &mut first_error, walked.lost);
                    }
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            let id = stream.id;
            stream.replaced.retain(|replaced| {
                !(replaced.guarded.ended()
                    && matches!(replaced.conductor.seal_state(), SealState::Retired { .. })
                    && !pinned.contains(&(id, replaced.incarnation)))
            });
            // Until the publication releases at the guard's seal, a claim
            // admitted after the close's abort ran (its record written,
            // its head not yet) is aborted here, every duty cycle.
            if stream.guarded.is_some()
                && stream.conductor.seal_reason() == Some(SealReason::GuardClosed)
                && stream.conductor.seal_state() == SealState::Sealed
                && let Err(error) = abort_guarded_claim(stream)
            {
                first_error.get_or_insert(error);
            }
            let (base, id, incarnation) = (stream.base, stream.id, stream.incarnation);
            let Some(guarded) = &mut stream.guarded else {
                continue;
            };
            match guarded.walk(budget, base, lane, incarnation) {
                Ok(walked) => {
                    self.counters
                        .add(Event::GuardOutcomesWritten, u64::from(walked.written));
                    self.counters
                        .add(Event::GuardOutcomesLost, u64::from(walked.lost));
                    if walked.budget_exhausted {
                        self.counters.add(Event::GuardWalkerBudgetExhausted, 1);
                    }
                    if walked.overrun {
                        lapped.push(id);
                    }
                    add_work(&self.counters, &mut work, &mut first_error, walked.written);
                    add_work(&self.counters, &mut work, &mut first_error, walked.lost);
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        for id in lapped {
            self.diagnostics.error(
                &mut self.counters,
                crate::diagnostics::ErrorCode::GuardWalkerLapped,
                [id, 0],
                "a guard walker was lapped: outcome streams abandoned",
            );
        }
        first_error.map_or(Ok(work), Err)
    }

    /// Copies a bounded number of messages into each configured keyed table.
    fn feed_conflation(&mut self) -> Result<u32, DriverError> {
        let budget = self.config.conflation_feeder_budget.get();
        let mut work = 0u32;
        let mut first_error: Option<DriverError> = None;
        let mut closed = Vec::new();
        let mut lost = Vec::new();
        for stream in &mut self.streams {
            if stream.conflation_terminal.is_some() {
                if let Some(cutover) = stream.cutover.take() {
                    cutover.abandon();
                }
                // A retry after a failed seal.
                let was_active = stream.conductor.seal_state() == SealState::Active;
                if let Err(error) =
                    seal_conflation_terminal(&mut stream.conflation_terminal, None, || {
                        stream
                            .conductor
                            .seal_with_reason(SealReason::ConflationVersionsExhausted)
                    })
                {
                    first_error.get_or_insert(DriverError::from(error));
                }
                if was_active && stream.conductor.seal_state() != SealState::Active {
                    closed.push((
                        stream.key(),
                        stream.config.lane,
                        stream.image_registration(),
                    ));
                }
            }
            let Some(config) = stream.conflation else {
                continue;
            };
            // A network image's view whose terminal cell is published is
            // done: its readers deliver nothing more, and the feeder stops
            // (conflated-network-images.md (c)).
            let published = stream
                .feeder
                .as_ref()
                .and_then(|feeder| feeder.fresh.as_ref())
                .is_some_and(|fresh| {
                    karyos_sys::freshness::TerminalCell::read(&fresh.link.terminal_words())
                        .is_some()
                });
            if published {
                if let Some(mut feeder) = stream.feeder.take() {
                    feeder.writer.close();
                    // Kept to seed a recreation (karyos#658), unless the
                    // image is going: a retired image's view is never
                    // recreated.
                    let terminal = feeder.fresh.as_ref().and_then(|fresh| {
                        karyos_sys::freshness::TerminalCell::read(&fresh.link.terminal_words())
                    });
                    if let Some(terminal) = terminal
                        && !stream.retiring
                        && terminal.reason != karyos_sys::freshness::TERMINAL_IMAGE_RETIRED
                    {
                        stream.closed_view = Some(ClosedView {
                            writer: feeder.writer,
                            terminal,
                        });
                    }
                }
                stream
                    .members
                    .retain(|member| member.kind != MemberKind::Feeder);
                if let Some(net) = &mut self.net {
                    net.count_views(|views| views.add(|c| &mut c.closed_terminal, 1));
                }
                continue;
            }
            let Some(feeder) = &mut stream.feeder else {
                continue;
            };
            let ConflationFeeder {
                subscription,
                writer,
                fresh,
            } = feeder;
            // The mailbox and a gap met in the log come first, so a loss is
            // recorded before any value past it is written.
            let mut fresh_fed = FreshFed::default();
            let blocked = match fresh.as_mut() {
                Some(fresh) => !serve_fresh(writer, fresh, &mut fresh_fed),
                None => false,
            };
            let with_positions = fresh.is_some();
            #[cfg(test)]
            let fail_poll = fresh.as_ref().is_some_and(|fresh| fresh.fail_polls);
            let mut terminal = None;
            let mut fed = Fed::default();
            let cycles_before = writer.fresh_counters().unwrap_or_default();
            let mut fed_markers_malformed = 0u64;
            let polled = if blocked {
                Ok(karyos_client::subscription::PollSummary::default())
            } else {
                subscription.poll(
                    |value, info| {
                        use karyos_sys::conflation::cycle::{Marker, Reserved};
                        // Cycle traffic only when the view opts in
                        // (ADR-0080); otherwise every reserved value
                        // outside the keys is a rejected key, as before.
                        let reserved = if config.refresh {
                            Reserved::read(info.reserved_value)
                        } else {
                            Reserved::Invalid
                        };
                        let written = match reserved {
                            // A refresh value: its errors may abort its
                            // cycle, so it goes to the writer even when the
                            // shape refuses it.
                            Reserved::Value { cycle, key } => Some(if with_positions {
                                writer.passed(info.position);
                                writer.cycle_value(cycle, key, value, info.position)
                            } else {
                                writer.cycle_value(cycle, key, value, 0)
                            }),
                            Reserved::Marker { cycle } => {
                                // A table without a barrier has nothing to
                                // restore: its markers are ignored.
                                if with_positions {
                                    writer.passed(info.position);
                                    match Marker::decode(value) {
                                        Some(Marker::Begin { scope }) => {
                                            writer.cycle_begin(cycle, scope, info.position);
                                            None
                                        }
                                        Some(end) => writer
                                            .cycle_end(cycle, end, info.position)
                                            .err()
                                            .map(Err),
                                        None => {
                                            fed_markers_malformed += 1;
                                            writer.cycle_abort();
                                            None
                                        }
                                    }
                                } else {
                                    None
                                }
                            }
                            Reserved::Live { .. } | Reserved::Invalid => {
                                match config.validate_publication(info.reserved_value, value.len())
                                {
                                    Err(error) => Some(Err(error)),
                                    Ok(()) => u32::try_from(info.reserved_value).ok().map(|key| {
                                        if with_positions {
                                            // Everything below the message is
                                            // consumed.
                                            writer.passed(info.position);
                                            writer.write_at(key, value, info.position)
                                        } else {
                                            writer.write(key, value)
                                        }
                                    }),
                                }
                            }
                        };
                        match written {
                            Some(Ok(_)) => fed.written += 1,
                            Some(Err(ConflationError::KeyOutOfRange { .. })) => {
                                fed.keys_rejected += 1;
                            }
                            Some(Err(ConflationError::ValueTooLarge { .. })) => {
                                fed.values_too_large += 1;
                            }
                            Some(Err(error @ ConflationError::VersionsExhausted)) => {
                                terminal = Some(error);
                            }
                            Some(Err(_)) | None => {}
                        }
                    },
                    MessageLimit::new(budget),
                )
            };
            fresh_fed.markers_malformed = fed_markers_malformed;
            // A poll failure injected by a test (a feeder that cannot read
            // on).
            #[cfg(test)]
            let polled = if fail_poll {
                Err(karyos_client::subscription::PollError::new(
                    karyos_client::subscription::PollSummary::default(),
                    karyos_client::ClientError::ClosedByOverrun,
                ))
            } else {
                polled
            };
            // A failed poll still reports what it handled before the failure.
            if let Some(counters) = &stream.feeder_counters {
                counters.add(&self.counters, fed);
            }
            // A network image's view closes on its own, never sealing the
            // image lane its other subscribers read (#324 review): exhausted
            // versions or a feeder that cannot read on publish the view's
            // terminal cell, every value stale, and the next duty closes
            // the feeder.
            if with_positions {
                let reason = match (&terminal, &polled) {
                    (Some(_), _) => Some(karyos_sys::freshness::TERMINAL_FRESHNESS_EXHAUSTED),
                    (None, Err(_)) => Some(karyos_sys::freshness::TERMINAL_FEEDER_LOST),
                    (None, Ok(_)) => None,
                };
                if let Some(reason) = reason {
                    let _ = writer.publish_terminal(0, u64::MAX, reason);
                    if let Some(net) = &mut self.net {
                        net.count_views(|views| {
                            // What the mailbox did this duty still counts.
                            views.add(|c| &mut c.acked, fresh_fed.acked);
                            views.add(|c| &mut c.withheld, fresh_fed.withheld);
                            views.add(|c| &mut c.caught_up, fresh_fed.caught_up);
                            count_cycles(views, &cycles_before, writer, &fresh_fed);
                            if reason == karyos_sys::freshness::TERMINAL_FEEDER_LOST {
                                views.add(|c| &mut c.feeders_lost, 1);
                            }
                        });
                    }
                    continue;
                }
            }
            // A gap the poll stopped at: recorded now, or held (nothing
            // past it is polled) until the barrier takes it.
            if let (Some(fresh), Ok(summary)) = (fresh.as_mut(), &polled) {
                if let Some(skipped) = summary.skipped
                    && let Some(end) = skipped.position.checked_add(u64::from(skipped.extent))
                {
                    fresh.gap = Some((skipped.position, end));
                    let _ = serve_gap(writer, fresh, &mut fresh_fed);
                }
                // Bounded reconciliation of the recorded losses.
                let _ = writer.reconcile(budget);
            }
            if let Some(net) = &mut self.net {
                net.count_views(|views| {
                    views.add(|c| &mut c.acked, fresh_fed.acked);
                    views.add(|c| &mut c.withheld, fresh_fed.withheld);
                    views.add(|c| &mut c.caught_up, fresh_fed.caught_up);
                    count_cycles(views, &cycles_before, writer, &fresh_fed);
                });
            }
            let summary = match polled {
                Ok(summary) => summary,
                // The feeder cannot read on: the stream ends explicitly.
                Err(error) => {
                    // A stream already closed for good was reported then.
                    let open = stream.conductor.seal_reason().is_none();
                    lost.push((
                        [
                            stream.aggregate.registration,
                            u64::from(stream.config.lane.get()),
                        ],
                        (
                            stream.key(),
                            stream.config.lane,
                            stream.image_registration(),
                        ),
                        error.cause.to_string(),
                        open,
                    ));
                    if let Err(error) = lose_feeder(stream) {
                        first_error.get_or_insert(DriverError::from(error));
                    }
                    continue;
                }
            };
            add_work(
                &self.counters,
                &mut work,
                &mut first_error,
                summary.delivered,
            );
            if (terminal.is_some() || stream.conflation_terminal.is_some())
                && let Some(cutover) = stream.cutover.take()
            {
                cutover.abandon();
            }
            // Only a new exhaustion can move the stream out of `Active`
            // here: the branch above sealed an earlier one.
            let was_active =
                terminal.is_some() && stream.conductor.seal_state() == SealState::Active;
            if let Err(error) =
                seal_conflation_terminal(&mut stream.conflation_terminal, terminal, || {
                    stream
                        .conductor
                        .seal_with_reason(SealReason::ConflationVersionsExhausted)
                })
            {
                first_error.get_or_insert(DriverError::from(error));
            }
            // Only the seal that moved the stream out of `Active` reports it.
            if was_active && stream.conductor.seal_state() != SealState::Active {
                closed.push((
                    stream.key(),
                    stream.config.lane,
                    stream.image_registration(),
                ));
            }
            // An end the stream did not reach (no terminal seal: the feeder
            // could not follow a cutover) is a lost feeder, never a silent
            // end of the view.
            if summary.closed.is_some() && stream.conductor.seal_reason().is_none() {
                lost.push((
                    [
                        stream.aggregate.registration,
                        u64::from(stream.config.lane.get()),
                    ],
                    (
                        stream.key(),
                        stream.config.lane,
                        stream.image_registration(),
                    ),
                    "the feeder ended before its stream".to_owned(),
                    true,
                ));
                if let Err(error) = lose_feeder(stream) {
                    first_error.get_or_insert(DriverError::from(error));
                }
            } else if summary.closed.is_some() {
                if let Some(mut feeder) = stream.feeder.take() {
                    feeder.writer.close();
                }
                stream
                    .members
                    .retain(|member| member.kind != MemberKind::Feeder);
                if let Some(cutover) = stream.cutover.take() {
                    cutover.abandon();
                }
            }
        }
        for (stream, lane, image) in closed {
            self.emit(&DriverEvent::PublicationClosed {
                stream,
                lane,
                reason: CloseReason::ConflationVersionsExhausted,
                image,
            });
        }
        // The loss is always logged; only a stream it closes is reported,
        // so a stream closed for good earlier gets no second closing.
        // The record names the aggregate's registration and the lane.
        for (key, (stream, lane, image), cause, open) in lost {
            self.diagnostics.error(
                &mut self.counters,
                crate::diagnostics::ErrorCode::ConflationFeederLost,
                key,
                &format!("conflation feeder lost: {cause}"),
            );
            if open {
                self.emit(&DriverEvent::PublicationClosed {
                    stream,
                    lane,
                    reason: CloseReason::ConflationFeederLost,
                    image,
                });
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(work),
        }
    }

    pub(crate) fn stream(&mut self, stream: StreamHandle) -> Result<&mut Stream<T>, DriverError> {
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

    /// A reader of the driver's error log
    /// (`quantstratum-docs: karyos/design/observability-and-tools.md`).
    #[must_use]
    pub fn error_log(&self) -> karyos_sys::diag::ErrorLogReader {
        self.diagnostics.error_reader()
    }

    /// A reader of the driver's loss report.
    #[must_use]
    pub fn loss_report(&self) -> karyos_sys::diag::LossReportReader {
        self.diagnostics.loss_reader()
    }

    /// A reader of the driver's trace mirror (`quantstratum-docs:
    /// karyos/design/trace-journal-region.md`): the journal table and the
    /// records drained from the client trace journals.
    #[must_use]
    pub fn trace_mirror(&self) -> karyos_sys::trace_mirror::TraceMirrorReader {
        self.trace_journals.reader()
    }

    /// The driver instance's random 128-bit `driver_id` (SPEC.md §4), as
    /// two words `[high, low]`. Trace records, observers and loss records
    /// carry it, and in IPC mode it is the admission instance id too
    /// (`instance()`, `u128::from(high) << 64 | u128::from(low)`; ACS
    /// 13555).
    #[must_use]
    pub fn driver_id(&self) -> [u64; 2] {
        self.driver_id
    }

    /// The handle of the active local stream of `key`: one this driver
    /// added or a replay target, never a network image of the key (key
    /// lookups prefer the local stream, karyos#490) nor a removed stream
    /// still retiring. `None` when there is none. A host finds a stream by
    /// the key its requesters name, as the Archive's `StartRecording` does
    /// (`quantstratum-docs: karyos/design/archive-host.md`, H2).
    #[must_use]
    pub fn stream_handle(&self, key: StreamKey) -> Option<StreamHandle> {
        self.streams
            .iter()
            .find(|s| s.key() == key && s.source.is_none() && !s.retiring)
            .map(|s| StreamHandle {
                driver: self.id,
                stream: s.id,
            })
    }

    /// The publication identity trace records of `stream` carry
    /// (`quantstratum-docs: karyos/design/trace-data-path.md`; SPEC.md §5,
    /// `(driver_id, registration_id, incarnation)`): this driver's
    /// `driver_id`, the stream's registration, its wire stream and session
    /// ids, and the incarnation. The embedded driver opens one incarnation
    /// per stream registration, and registrations are never reused, so the
    /// incarnation is [`FIRST_INCARNATION`]; a mapping cutover keeps it
    /// (a successor mapping is not a new incarnation). Publisher and
    /// subscriber hooks of the stream use the same identity before and
    /// after a cutover, so their records pair.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::UnknownStream`] for a handle of another driver
    /// or a removed stream.
    pub fn trace_identity(
        &mut self,
        stream: StreamHandle,
    ) -> Result<PublicationIdentity, DriverError> {
        let driver = self.driver_id;
        let found = self.stream(stream)?;
        Ok(PublicationIdentity {
            driver,
            registration: found.aggregate.registration,
            stream_id: found.stream_id,
            session_id: found.session_id,
            incarnation: found.incarnation,
        })
    }

    /// The publication identity of incarnation `incarnation` of `stream`:
    /// the current one, or a replaced one still retiring
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`, The fresh
    /// incarnation). Records of an old handle or reader name it.
    ///
    /// # Errors
    ///
    /// As [`EmbeddedDriver::trace_identity`], and
    /// [`DriverError::UnknownStream`] for an incarnation the stream does
    /// not hold.
    pub fn trace_identity_at(
        &mut self,
        stream: StreamHandle,
        incarnation: u64,
    ) -> Result<PublicationIdentity, DriverError> {
        let current = self.trace_identity(stream)?;
        let found = self.stream(stream)?;
        let held = incarnation == found.incarnation
            || found
                .replaced
                .iter()
                .any(|replaced| replaced.incarnation == incarnation);
        if !held {
            return Err(DriverError::UnknownStream { stream: found.id });
        }
        Ok(PublicationIdentity {
            incarnation,
            ..current
        })
    }

    /// A new trace number, never reused within this driver instance: for an
    /// agent's journal number and a traced subscriber's registration.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::TraceNumbersExhausted`] once `u64::MAX` numbers
    /// were handed out.
    pub fn next_trace_number(&mut self) -> Result<u64, DriverError> {
        let number = self.next_trace_number;
        self.next_trace_number = number
            .checked_add(1)
            .ok_or(DriverError::TraceNumbersExhausted)?;
        Ok(number)
    }

    fn active_stream(&mut self, stream: StreamHandle) -> Result<&mut Stream<T>, DriverError> {
        let found = self.stream(stream)?;
        if found.retiring {
            return Err(DriverError::StreamRetiring { stream: found.id });
        }
        Ok(found)
    }

    pub(crate) fn active_stream_mut(
        &mut self,
        stream: StreamHandle,
    ) -> Result<&mut Stream<T>, DriverError> {
        self.active_stream(stream)
    }

    pub(crate) fn stream_ref(&self, stream: StreamHandle) -> Result<&Stream<T>, DriverError> {
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

    /// One cycle of the network agents and their events (wiring note
    /// W-c): their work, and the error of a failed agent.
    pub(crate) fn serve_network(&mut self) -> (u32, Option<DriverError>) {
        let Some(net) = &mut self.net else {
            return (0, None);
        };
        // The image table builds lanes from the admission's region ids, a
        // sibling field lent for this duty (network-shared-terms N-2).
        #[cfg(target_os = "linux")]
        let mut lanes = lane_source(self.admission.as_mut());
        #[cfg(not(target_os = "linux"))]
        let mut lanes = crate::agents::images::LaneSource::heap();
        let served = match net.duty(&mut lanes) {
            Ok(work) => (work, None),
            Err(error) => (0, Some(error)),
        };
        // The endpoints' capabilities after their opens and resets (M3).
        let (snapshots, missing) = net.endpoint_capabilities();
        self.capabilities
            .sync(&mut self.counters, snapshots, missing);
        // Subscriptions created since the last cycle learn of the images
        // already there first; the cycle's image events then go to every
        // announced subscription, so none is told twice.
        self.announce_existing_images();
        self.serve_images();
        // The network journals' answers, after the images they name.
        self.serve_network_trace();
        // The guarded publications the sender refused or returned: their
        // gates are gone, so their senders leave the close acknowledgement.
        self.deregister_released_guards();
        self.apply_schedule_violations();
        served
    }

    /// Builds the conflated view of the installed image `slot`, when its
    /// key asked for one (conflated-network-images.md (a)): a heap table
    /// over the link the receiver's seal gate shares, fed from a required
    /// subscription of the exposed lane, then attached to the mailbox. An
    /// unexposed image, or a table that cannot be built, gets no view and is
    /// counted; the gate then seals as without a feeder.
    fn build_network_view(
        &mut self,
        slot: crate::sessions::receive::SlotRef,
        endpoint: crate::agents::EndpointId,
        exposed: Option<&AggregateHandle>,
    ) {
        let Some((lane, link)) = self.net.as_ref().and_then(|net| net.image_freshness(slot)) else {
            return;
        };
        use crate::net::ViewBuildFailure;
        // `Err(None)`: the image is not exposed.
        let built: Result<(), Option<ViewBuildFailure>> = (|| {
            let handle = exposed.ok_or(None)?;
            let id = handle
                .lanes
                .get(usize::from(lane.get()))
                .copied()
                .flatten()
                .ok_or(Some(ViewBuildFailure::NoLane))?;
            let index = self
                .streams
                .iter()
                .position(|stream| stream.id == id)
                .ok_or(Some(ViewBuildFailure::NoLane))?;
            let stream_id = self
                .streams
                .get(index)
                .ok_or(Some(ViewBuildFailure::NoLane))?
                .stream_id;
            let (_, config) = self
                .net
                .as_ref()
                .and_then(|net| net.conflation_of(endpoint, stream_id))
                .ok_or(Some(ViewBuildFailure::NoConfiguration))?;
            let mut writer = karyos_sys::conflation::conflation_fresh(
                config.keys,
                config.value_capacity,
                config.journal_capacity,
                link.clone(),
            )
            .map_err(|error| Some(ViewBuildFailure::Table(error)))?;
            // The cycles' bitset, allocated with the view (ADR-0080).
            if config.refresh {
                let _ = writer.enable_cycles();
            }
            let stream = self
                .streams
                .get_mut(index)
                .ok_or(Some(ViewBuildFailure::NoLane))?;
            let inner = stream
                .conductor
                .subscribe(Role::Required)
                .map_err(|_| Some(ViewBuildFailure::Subscription))?;
            let generation = GenerationLink::new();
            let subscription = ClientSubscription::new(inner)
                .with_generation(Arc::clone(&generation), 0)
                .map_err(|_| Some(ViewBuildFailure::Subscription))?;
            stream.members.push(Member {
                link: Arc::downgrade(&generation),
                kind: MemberKind::Feeder,
                host: false,
            });
            stream.conflation = Some(config);
            stream.feeder = Some(ConflationFeeder {
                subscription,
                writer,
                fresh: Some(FreshFeed {
                    link: link.clone(),
                    gap: None,
                    #[cfg(test)]
                    fail_polls: false,
                }),
            });
            let registration = stream.aggregate.registration;
            let counters = FeederCounters::allocate(&mut self.counters, registration, lane.get());
            if let Some(stream) = self.streams.get_mut(index) {
                stream.feeder_counters = Some(counters);
            }
            Ok(())
        })();
        let deferred = self
            .net
            .as_ref()
            .is_some_and(crate::net::Network::defers_view_attach);
        if built.is_ok()
            && !deferred
            && let Ok(mailbox) = link.mailbox()
        {
            // Attached once its feeder exists: the receiver's gate posts
            // its seals from now on.
            mailbox.attach();
        }
        if let Some(net) = &mut self.net {
            net.count_views(|views| match built {
                Ok(()) => views.add(|c| &mut c.built, 1),
                Err(None) => views.add(|c| &mut c.unbuilt_unexposed, 1),
                Err(Some(failure)) => {
                    views.add(|c| &mut c.unbuilt_failed, 1);
                    views.last_build_failure = Some(failure);
                }
            });
        }
    }

    /// Recreates the conflated view of `handle`'s `lane`, a network
    /// image's whose view its terminal cell closed (SPEC.md §7.1, "Lane
    /// seal and terminal closure": "recovery recreates the view, and every
    /// key of the new view starts `Stale` until its own update";
    /// `quantstratum-docs: karyos/design/conflated-network-images.md`,
    /// "Recovery"; karyos#658), the view of
    /// [`EmbeddedDriver::add_network_subscription_conflated`] (karyos#637).
    ///
    /// The new table, over a new link, is seeded with the closed view's
    /// last value of every written key at the terminal's start, then the
    /// loss from there to the new feeder's join position is recorded, so
    /// every seeded key reads `Stale { since: terminal.start }` before any
    /// reader can see the view; a key turns `Fresh` only with its own
    /// update past the join. The receiver's seal gate moves to the new link,
    /// and the closed table is released.
    ///
    /// # Errors
    ///
    /// [`DriverError::UnknownStream`] for a lane `handle` does not have;
    /// [`DriverError::StreamRetiring`] for a retiring or retired image;
    /// [`DriverError::NotConflated`] without a network view;
    /// [`DriverError::ViewNotClosed`] for a view that is open or was never
    /// closed by its terminal cell; [`DriverError::NetworkBusy`] when the
    /// receiver cannot take the relink now (retry); a table or subscription
    /// failure as [`DriverError::Conflation`], [`DriverError::Client`] or
    /// [`DriverError::Sys`].
    /// Nothing changes on error: the closed view stays to retry.
    pub fn recreate_network_view(
        &mut self,
        handle: &AggregateHandle,
        lane: karyos_sys::frame::Lane,
    ) -> Result<(), DriverError> {
        let id = handle
            .lanes
            .get(usize::from(lane.get()))
            .copied()
            .flatten()
            .ok_or(DriverError::UnknownStream {
                stream: handle.registration,
            })?;
        let index = self
            .streams
            .iter()
            .position(|stream| stream.id == id)
            .ok_or(DriverError::UnknownStream { stream: id })?;
        // An image no longer installed is a retired one.
        let slot = self.net.as_ref().and_then(|net| net.image_slot(handle));
        let stream = self
            .streams
            .get_mut(index)
            .ok_or(DriverError::UnknownStream { stream: id })?;
        let slot = match slot {
            Some(slot) if !stream.retiring => slot,
            _ => return Err(DriverError::StreamRetiring { stream: id }),
        };
        let config = stream.conflation.ok_or(DriverError::NotConflated)?;
        if stream.feeder.is_some() {
            return Err(DriverError::ViewNotClosed);
        }
        let terminal = stream
            .closed_view
            .as_ref()
            .map(|closed| closed.terminal)
            .ok_or(DriverError::ViewNotClosed)?;
        let link = karyos_sys::freshness::FreshnessLink::new();
        let mut writer = karyos_sys::conflation::conflation_fresh(
            config.keys,
            config.value_capacity,
            config.journal_capacity,
            link.clone(),
        )?;
        // A recreated view starts with no open cycle (ADR-0080).
        if config.refresh {
            let _ = writer.enable_cycles();
        }
        let inner = stream
            .conductor
            .subscribe(Role::Required)
            .map_err(DriverError::Sys)?;
        let generation = GenerationLink::new();
        let subscription =
            ClientSubscription::new(inner).with_generation(Arc::clone(&generation), 0)?;
        // Seeds at the terminal's start, the loss from there to the join:
        // the join is the lane's reserved head, past every position the
        // closed view held, so the interval is never empty unless nothing
        // was ever published, and then nothing is seeded either.
        let join = subscription.position();
        if terminal.start < join {
            let mut out = vec![0u8; config.value_capacity];
            let mut seeded = Ok(());
            let mut unstable = 0;
            if let Some(closed) = &stream.closed_view {
                unstable = closed.writer.for_each_value(&mut out, |key, value| {
                    if seeded.is_ok() {
                        seeded = writer.write_at(key, value, terminal.start).map(|_| ());
                    }
                });
            }
            seeded?;
            // The closed table has one writer, closed: every written slot
            // reads coherent. A slot that did not would come back absent
            // instead of Stale, so it is counted (#757 review).
            debug_assert_eq!(unstable, 0, "a closed table's slot read unstable");
            if unstable > 0
                && let Some(net) = &mut self.net
            {
                net.count_views(|views| {
                    views.add(|c| &mut c.recreate_unstable, u64::from(unstable))
                });
            }
            // A new table: its ring is empty and its frontier 0, and the
            // interval is not empty, so no refusal is expected here.
            writer
                .record_loss(terminal.start, join)
                .map_err(|_| DriverError::Conflation(ConflationError::InvalidConfig))?;
            // One pass reconciles every slot; the bound only guards the
            // loop.
            for _ in 0..=config.keys {
                if !writer.reconciling() {
                    break;
                }
                writer.reconcile(u32::MAX)?;
            }
            writer.passed(join);
        }
        if let Some(net) = &mut self.net {
            net.relink_view(slot, lane, &link)?;
        }
        let stream = self
            .streams
            .get_mut(index)
            .ok_or(DriverError::UnknownStream { stream: id })?;
        stream.members.push(Member {
            link: Arc::downgrade(&generation),
            kind: MemberKind::Feeder,
            host: false,
        });
        stream.feeder = Some(ConflationFeeder {
            subscription,
            writer,
            fresh: Some(FreshFeed {
                link: link.clone(),
                gap: None,
                #[cfg(test)]
                fail_polls: false,
            }),
        });
        stream.closed_view = None;
        let deferred = self
            .net
            .as_ref()
            .is_some_and(crate::net::Network::defers_view_attach);
        if !deferred && let Ok(mailbox) = link.mailbox() {
            mailbox.attach();
        }
        if let Some(net) = &mut self.net {
            net.count_views(|views| views.add(|c| &mut c.recreated, 1));
        }
        Ok(())
    }

    /// Whether `handle`'s `lane` keeps a closed view's table for a
    /// recreation (tests).
    #[cfg(test)]
    pub(crate) fn holds_closed_network_view(
        &self,
        handle: &AggregateHandle,
        lane: karyos_sys::frame::Lane,
    ) -> bool {
        let id = handle.lanes.get(usize::from(lane.get())).copied().flatten();
        self.streams
            .iter()
            .any(|stream| Some(stream.id) == id && stream.closed_view.is_some())
    }

    /// Attaches every built conflated view of a network image that
    /// `Network::defer_view_attach` held back (tests).
    #[cfg(test)]
    pub(crate) fn attach_network_views(&self) {
        for stream in &self.streams {
            if let Some(fresh) = stream
                .feeder
                .as_ref()
                .and_then(|feeder| feeder.fresh.as_ref())
                && let Ok(mailbox) = fresh.link.mailbox()
            {
                mailbox.attach();
            }
        }
    }

    /// The reader of the conflated view of `handle`'s `lane`, a network
    /// image's (tests).
    #[cfg(test)]
    pub(crate) fn network_view_reader(
        &self,
        handle: &AggregateHandle,
        lane: karyos_sys::frame::Lane,
    ) -> Option<karyos_sys::conflation::ConflationReader> {
        let id = handle
            .lanes
            .get(usize::from(lane.get()))
            .copied()
            .flatten()?;
        let stream = self.streams.iter().find(|stream| stream.id == id)?;
        Some(stream.feeder.as_ref()?.writer.reader())
    }

    /// The link the conflated view of `handle`'s `lane` shares with the
    /// receiver's seal gate (tests).
    #[cfg(test)]
    pub(crate) fn network_view_link(
        &self,
        handle: &AggregateHandle,
        lane: karyos_sys::frame::Lane,
    ) -> Option<karyos_sys::freshness::FreshnessLink> {
        let id = handle
            .lanes
            .get(usize::from(lane.get()))
            .copied()
            .flatten()?;
        let stream = self.streams.iter().find(|stream| stream.id == id)?;
        Some(stream.feeder.as_ref()?.fresh.as_ref()?.link.clone())
    }

    /// Seeds `key`'s version in the conflated view of `handle`'s `lane`,
    /// so that its next write exhausts it (tests).
    #[cfg(test)]
    pub(crate) fn seed_network_view_version(
        &self,
        handle: &AggregateHandle,
        lane: karyos_sys::frame::Lane,
        key: u32,
        version: u64,
    ) {
        let id = handle.lanes.get(usize::from(lane.get())).copied().flatten();
        if let Some(feeder) = self
            .streams
            .iter()
            .find(|stream| Some(stream.id) == id)
            .and_then(|stream| stream.feeder.as_ref())
        {
            feeder.writer.seed_version(key, version);
        }
    }

    /// Makes every poll of the feeder of `handle`'s `lane` fail (tests).
    #[cfg(test)]
    pub(crate) fn fail_network_view_polls(
        &mut self,
        handle: &AggregateHandle,
        lane: karyos_sys::frame::Lane,
    ) {
        let id = handle.lanes.get(usize::from(lane.get())).copied().flatten();
        if let Some(fresh) = self
            .streams
            .iter_mut()
            .find(|stream| Some(stream.id) == id)
            .and_then(|stream| stream.feeder.as_mut())
            .and_then(|feeder| feeder.fresh.as_mut())
        {
            fresh.fail_polls = true;
        }
    }

    /// What the conflated views of network images did.
    #[must_use]
    pub fn network_view_counters(&self) -> crate::net::NetworkViewCounters {
        self.net
            .as_ref()
            .map(crate::net::Network::view_counters)
            .unwrap_or_default()
    }

    /// Applies the image table's events (W3): an installed image becomes
    /// the lane streams of one aggregate, or is driven unexposed; a
    /// retiring one has its streams sealed and retired, so they free once
    /// no lease holds them and the image table can reclaim the image.
    fn serve_images(&mut self) {
        let Some(events) = self
            .net
            .as_mut()
            .map(crate::net::Network::take_image_events)
        else {
            return;
        };
        for event in &events {
            match *event {
                crate::agents::images::ImageEvent::Installed {
                    slot,
                    endpoint,
                    source,
                    identity,
                    alias,
                } => {
                    let Some(lanes) = self.net.as_ref().and_then(|net| net.image_lanes(slot))
                    else {
                        continue;
                    };
                    let source = crate::net::ImageSource {
                        endpoint,
                        source,
                        identity,
                    };
                    let exposed = self.add_image_aggregate(&lanes, Some(source));
                    if let Some(net) = &mut self.net {
                        let traced = crate::net::trace::identity(&identity, alias);
                        net.record_image(slot, source, traced, exposed, &lanes);
                    }
                    self.build_network_view(slot, endpoint, exposed.as_ref());
                    // Its receiver journals, while the receiver has a hook.
                    self.open_image_journals(slot);
                    // Its loss counts' cells (M2b), keyed by its stream: an
                    // unexposed image has no stream a tool could show.
                    if let Some(handle) = &exposed
                        && let Some(cells) = stream_network_cells(
                            &mut self.counters,
                            handle.registration(),
                            &crate::agents::IMAGE_CELLS,
                        )
                        && let Some(net) = &self.net
                    {
                        let _ = net.post_image_cells(slot, cells);
                    }
                    if let Some(handle) = exposed {
                        self.announce_image(endpoint, &handle, true);
                    }
                }
                crate::agents::images::ImageEvent::Retiring { slot, complete } => {
                    // An image that reached its EOS bounds ends cleanly;
                    // any other retirement may leave its prefix unresolved.
                    let (seal, close) = if complete {
                        (SealReason::EndOfStream, CloseReason::EndOfStream)
                    } else {
                        (SealReason::ImageRetired, CloseReason::ImageRetired)
                    };
                    self.close_image_journals(slot);
                    let handle = self.net.as_ref().and_then(|net| net.image_aggregate(slot));
                    let endpoint = self.net.as_ref().and_then(|net| net.image_endpoint(slot));
                    if let (Some(handle), Some(endpoint)) = (handle, endpoint) {
                        // Announced while its streams still name the alias.
                        self.announce_image(endpoint, &handle, false);
                    }
                    if let Some(handle) = handle {
                        for stream in handle.streams() {
                            // A conflated view of the image closes with a
                            // typed reason, marking no value stale (design
                            // (a)); the retire below closes the feeder.
                            if let Some(feeder) = self
                                .stream(stream)
                                .ok()
                                .and_then(|lane| lane.feeder.as_ref())
                                .filter(|feeder| feeder.fresh.is_some())
                            {
                                // The cell is one-shot: an earlier reason
                                // (exhausted versions) keeps it, and the
                                // close is counted as that terminal.
                                let won = feeder.writer.publish_terminal(
                                    0,
                                    0,
                                    karyos_sys::freshness::TERMINAL_IMAGE_RETIRED,
                                );
                                if let Some(net) = &mut self.net {
                                    net.count_views(|views| {
                                        if won {
                                            views.add(|c| &mut c.closed_retired, 1);
                                        } else {
                                            views.add(|c| &mut c.closed_terminal, 1);
                                        }
                                    });
                                }
                            }
                            // A closed view is never recreated on a
                            // retired image: its table goes now.
                            if let Ok(lane) = self.stream(stream) {
                                lane.closed_view = None;
                            }
                            let _ = self.retire_lane_with(stream, seal, close);
                        }
                    }
                    if let Some(net) = &mut self.net {
                        net.retire_unexposed(slot);
                    }
                }
                crate::agents::images::ImageEvent::Reclaimed { slot } => {
                    if let Some(net) = &mut self.net {
                        net.forget_image(slot);
                    }
                }
                _ => {}
            }
        }
        if let Some(net) = &mut self.net {
            net.return_image_events(events);
            // The cells of removed publications and retired images (M2b),
            // freed at once so no tool shows a stale count.
            for cell in net.take_cells() {
                self.counters.free(cell);
            }
        }
    }

    /// Stops the network agents and reclaims their endpoints and images
    /// (wiring note W-g); `None` without a network or once closed. An image
    /// whose `CreateImage` is still queued is refused, on either backing,
    /// before any lane is built (no region, memfd or heap). Dropping
    /// the driver does the same, then joins any agent thread that did not
    /// stop in time (blocking: such a thread exits once its rings are
    /// gone), so none is ever detached.
    pub fn close_network(&mut self) -> Option<crate::net::NetworkShutdown<T>> {
        let net = self.net.as_mut()?;
        // An image still asked for at the close is refused: no region or
        // memory is spent on a network that stops.
        let mut lanes = crate::agents::images::LaneSource::closing();
        let mut shutdown = net.close(&mut lanes);
        for cell in net.take_cells() {
            self.counters.free(cell);
        }
        self.capabilities.close(&mut self.counters);
        // The closed network released every tracked guard sender: none of
        // them stays in a close acknowledgement.
        shutdown.guard_senders_released = self.deregister_released_guards();
        self.net = None;
        // The agents stopped with their hooks: no network journal stays open.
        self.close_network_tracing();
        Some(shutdown)
    }

    /// Applies the schedule violations the senders reported
    /// (`quantstratum-docs: karyos/design/timed-tx.md`, section 11, TT-6):
    /// each lane still in the incarnation its sender served is sealed with
    /// `SealReason::ScheduleViolation` (a lane already sealed keeps its
    /// first reason), counted, and logged with its holder; a remote holder
    /// is retired as faulty, an in-process one gets only the seal. A report
    /// for a lane gone or reincarnated since is dropped, and every dropped
    /// report counts in `schedule violations dropped`. Returns how many
    /// lanes it sealed.
    fn apply_schedule_violations(&mut self) -> usize {
        let mut sealed = 0usize;
        while let Some(violation) = self
            .net
            .as_mut()
            .and_then(crate::net::Network::pop_schedule_violation)
        {
            let lane = karyos_sys::frame::Lane::try_new(violation.lane).ok();
            let stream = self
                .aggregate_of(violation.registration)
                .ok()
                .zip(lane)
                .and_then(|(aggregate, lane)| aggregate.lane(lane));
            let found = stream.and_then(|stream| self.active_stream(stream).ok());
            let Some(found) = found.filter(|found| found.incarnation == violation.incarnation)
            else {
                if let Some(net) = &mut self.net {
                    net.count_stale_schedule_violation();
                }
                continue;
            };
            let id = found.id;
            if found.conductor.seal_state() == karyos_sys::log_buffer::SealState::Active
                && found
                    .conductor
                    .seal_with_reason(karyos_sys::log_buffer::SealReason::ScheduleViolation)
                    .is_err()
            {
                continue;
            }
            self.counters
                .add(crate::counters::Event::ScheduleViolations, 1);
            if let Some(count) = sealed.checked_add(1) {
                sealed = count;
            }
            let holder = self.publication_holder(id);
            self.diagnostics.error(
                &mut self.counters,
                crate::diagnostics::ErrorCode::ClientProtocolViolation,
                [holder.map_or(0, |(client, _)| client), id],
                "a timed lane's publisher breached its schedule ring; the lane is sealed",
            );
            #[cfg(target_os = "linux")]
            if let Some((client, true)) = holder
                && !self.faulty_pending.contains(&client)
            {
                self.faulty_pending.push(client);
            }
        }
        let dropped = self
            .net
            .as_mut()
            .map_or(0, crate::net::Network::take_schedule_violations_dropped);
        if dropped > 0 {
            self.counters
                .add(crate::counters::Event::ScheduleViolationsDropped, dropped);
        }
        sealed
    }

    /// Deregisters the guard senders the network released (their
    /// publication was refused, returned or stopped with the agents);
    /// a failure is counted. Returns how many it deregistered.
    fn deregister_released_guards(&mut self) -> usize {
        let mut deregistered = 0usize;
        while let Some(id) = self
            .net
            .as_mut()
            .and_then(crate::net::Network::pop_released_guard)
        {
            if self.deregister_guard_sender(id).is_ok() {
                if let Some(count) = deregistered.checked_add(1) {
                    deregistered = count;
                }
            } else if let Some(net) = &mut self.net {
                net.count_guard_deregister_failure();
            }
        }
        deregistered
    }

    pub(crate) fn clock_now(&mut self) -> u64 {
        self.clock.now()
    }
}

/// Where the image table builds lanes: new regions of an IPC driver's
/// admission, or the heap without one.
#[cfg(target_os = "linux")]
pub(crate) fn lane_source<T: StreamTerms>(
    admission: Option<&mut crate::admission::Admission<T>>,
) -> crate::agents::images::LaneSource<'_> {
    admission.map_or_else(crate::agents::images::LaneSource::heap, |admission| {
        crate::agents::images::LaneSource::regions(admission.region_ids())
    })
}

/// The trace mirror of a driver without IPC, on the heap.
fn heap_mirror(
    config: &DriverConfig,
) -> Result<karyos_sys::trace_mirror::TraceMirror, DriverError> {
    karyos_sys::trace_mirror::trace_mirror(
        config.max_trace_journals,
        config.trace_recycle_log_entries,
        config.trace_mirror_records,
    )
    .map_err(|_| DriverError::InvalidConfig)
}

/// Ends a stream whose conflation feeder failed: its cutover is abandoned,
/// its table closed (views end with `closed`) and its publication sealed
/// with `ConflationFeederLost`, so its readers get `Closed`. A current
/// mapping already sealed (a cutover that had not opened yet) keeps its
/// seal word, as any later seal does; the event and the error log record
/// still name the loss.
fn lose_feeder<T: StreamTerms>(stream: &mut Stream<T>) -> Result<(), karyos_sys::error::SysError> {
    if let Some(cutover) = stream.cutover.take() {
        cutover.abandon();
    }
    if let Some(mut feeder) = stream.feeder.take() {
        feeder.writer.close();
    }
    stream
        .members
        .retain(|member| member.kind != MemberKind::Feeder);
    stream
        .conductor
        .seal_with_reason(SealReason::ConflationFeederLost)
}

/// Records the gap a network image view's feeder met in its log, unless the
/// mailbox already did; returns whether it is resolved (recorded, or the
/// view closed). While the barrier is full it stays held.
fn serve_gap(writer: &mut ConflationWriter, fresh: &mut FreshFeed, fed: &mut FreshFed) -> bool {
    let Some((start, end)) = fresh.gap else {
        return true;
    };
    let resolved = writer.recorded(start, end)
        || match writer.record_loss(start, end) {
            Ok(_) => {
                fed.caught_up = fed.caught_up.checked_add(1).unwrap_or(fed.caught_up);
                true
            }
            Err(karyos_sys::conflation::LossError::Full) => false,
            // Below the frontier or exhausted: the writer published the
            // terminal cell, and the view closes on the next duty.
            Err(_) => true,
        };
    if resolved {
        writer.passed(end);
        fresh.gap = None;
    }
    resolved
}

#[cfg(test)]
#[path = "embedded/fresh_feed_tests.rs"]
mod fresh_feed_tests;

/// A network image view's feeder duty before its poll
/// (conflated-network-images.md (b)): first a held gap from the log, then
/// the seal mailbox, whose request is acknowledged only once the barrier
/// recorded the loss. Returns whether the poll may run (no gap is held).
/// Adds a view's refresh cycle work of one duty (ADR-0080): the change of
/// its writer's counters since `before`, and the malformed markers met.
fn count_cycles(
    views: &mut crate::net::NetworkViewCounters,
    before: &karyos_sys::conflation::FreshCounters,
    writer: &ConflationWriter,
    fed: &FreshFed,
) {
    let after = writer.fresh_counters().unwrap_or_default();
    views.add(
        |c| &mut c.cycles_completed,
        after
            .cycles_completed
            .saturating_sub(before.cycles_completed),
    );
    views.add(
        |c| &mut c.snapshots_completed,
        after
            .snapshots_completed
            .saturating_sub(before.snapshots_completed),
    );
    views.add(
        |c| &mut c.cycles_aborted,
        after.cycles_aborted.saturating_sub(before.cycles_aborted),
    );
    views.add(
        |c| &mut c.keys_restored,
        after.keys_restored.saturating_sub(before.keys_restored),
    );
    views.add(|c| &mut c.markers_malformed, fed.markers_malformed);
}

fn serve_fresh(writer: &mut ConflationWriter, fresh: &mut FreshFeed, fed: &mut FreshFed) -> bool {
    if !serve_gap(writer, fresh, fed) {
        return false;
    }
    let Ok(mailbox) = fresh.link.mailbox() else {
        return true;
    };
    if let Some(request) = mailbox.pending() {
        match writer.record_loss(request.start, request.end) {
            Ok(_) => {
                if mailbox.acknowledge(request.request).is_ok() {
                    fed.acked = fed.acked.checked_add(1).unwrap_or(fed.acked);
                }
            }
            Err(karyos_sys::conflation::LossError::Full) => {
                fed.withheld = fed.withheld.checked_add(1).unwrap_or(fed.withheld);
            }
            // Below the frontier or exhausted: the terminal cell is
            // published; without an ack the receiver's bound closes the
            // view and seals.
            Err(_) => {}
        }
    }
    true
}

fn seal_conflation_terminal<E>(
    terminal: &mut Option<karyos_sys::conflation::ConflationError>,
    error: Option<karyos_sys::conflation::ConflationError>,
    mut seal: impl FnMut() -> Result<(), E>,
) -> Result<(), E> {
    if let Some(error) = error {
        *terminal = Some(error);
    }
    if terminal.is_some() {
        seal()?;
    }
    Ok(())
}

/// Aborts a guarded stream's admitted claim for its guard close and
/// records the block, so the walker labels it `GUARD_CLOSED`.
fn abort_guarded_claim<T: StreamTerms>(stream: &mut Stream<T>) -> Result<(), DriverError> {
    // The outstanding claim: its commit and this abort race on the block's
    // decision word, and exactly one wins.
    if let karyos_sys::log_buffer::ClaimDeadline::Aborted { position, .. } =
        stream.conductor.abort_admitted_claim()?
        && let Some(guarded) = &mut stream.guarded
    {
        guarded.note_guard_abort(position);
    }
    Ok(())
}

/// The CnC cells of one network publication or image (M2b), keyed by
/// its stream's `registration`, all or none: when the region has no room
/// for one of them, those already allocated are freed, `counters
/// unavailable` is counted once, and the stream runs without cells (its
/// counts stay in process). It is not tried again later.
pub(crate) fn stream_network_cells(
    counters: &mut DriverCounters,
    registration: u64,
    labels: &[&str],
) -> Option<crate::agents::AgentCells> {
    let keys = CounterKeys {
        stream: registration,
        ..CounterKeys::DRIVER
    };
    let mut cells = Vec::with_capacity(labels.len());
    for label in labels {
        // The first refusal is counted; nothing more is asked.
        let Some(cell) = counters.allocate_keyed(TYPE_EVENTS, label, keys) else {
            for cell in cells {
                counters.free(cell);
            }
            return None;
        };
        cells.push(cell);
    }
    Some(crate::agents::AgentCells::new(
        cells.into_iter().map(Some).collect(),
    ))
}

/// The network agents' driver-wide CnC cells (`quantstratum-docs:
/// karyos/design/management-agent-gap-analysis.md`, M2), in
/// [`crate::agents::SENDER_CELLS`] and [`crate::agents::RECEIVER_CELLS`]
/// order; a cell the region has no room for is `None`, counted in
/// `counters unavailable`.
/// With the spin meters of the agents' idle loops (M5) for `threading`:
/// none in Shared mode, whose loop is the conductor's; one per agent in
/// Dedicated mode; the one loop's, on the sender, in SharedNetwork mode.
fn network_cells(
    counters: &mut DriverCounters,
    threading: crate::agents::ThreadingMode,
) -> (crate::agents::AgentCells, crate::agents::AgentCells) {
    use crate::agents::ThreadingMode;
    let mut allocate = |labels: &[&str]| {
        crate::agents::AgentCells::new(
            labels
                .iter()
                .map(|label| counters.allocate_keyed(TYPE_EVENTS, label, CounterKeys::DRIVER))
                .collect(),
        )
    };
    let sender = allocate(&crate::agents::SENDER_CELLS);
    let receiver = allocate(&crate::agents::RECEIVER_CELLS);
    let (sender_spin, receiver_spin) = match threading {
        ThreadingMode::Shared => (None, None),
        ThreadingMode::Dedicated => (Some("sender spin time"), Some("receiver spin time")),
        ThreadingMode::SharedNetwork => (Some("network spin time"), None),
    };
    let mut meter = |label: Option<&str>| {
        label.map(|label| {
            crate::spin::SpinMeter::new(counters.allocate_keyed(
                crate::counters::TYPE_SPIN_TIME,
                label,
                CounterKeys::DRIVER,
            ))
        })
    };
    let sender = sender.with_spin(meter(sender_spin));
    let receiver = receiver.with_spin(meter(receiver_spin));
    (sender, receiver)
}

/// One conductor duty cycle, its work added.
fn duty<T: TermBytes>(
    counters: &DriverCounters,
    work: &mut u32,
    first_error: &mut Option<DriverError>,
    conductor: &mut Conductor<Arc<LogBuffer<T>>>,
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

/// Adds a step's own checked count to a duty cycle's work count, as
/// [`add_work`]: the work that fit is added, and an overflow inside the
/// step counts one `counter overflows` and becomes the cycle's error
/// unless an earlier one is recorded.
fn add_step(
    counters: &DriverCounters,
    work: &mut u32,
    first_error: &mut Option<DriverError>,
    (count, overflow): (u32, Option<DriverError>),
) {
    add_work(counters, work, first_error, count);
    if let Some(error) = overflow {
        counters.add(Event::CounterOverflows, 1);
        first_error.get_or_insert(error);
    }
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

    /// R-CORE-35: starting until the host declares its startup complete,
    /// then ready; a full driver is not ready, and an orderly shutdown
    /// is not ready for good.
    #[test]
    fn readiness_goes_from_starting_to_ready_and_to_not_ready() {
        let clock = ManualClock::default();
        let mut driver = EmbeddedDriver::with_clock(
            DriverConfig {
                max_clients: 1,
                ..DriverConfig::default()
            },
            Box::new(clock.clone()),
        )
        .unwrap();
        assert_eq!(driver.readiness(), Readiness::Starting);
        clock.0.store(29_000_000_000, Ordering::Relaxed);
        assert_eq!(driver.readiness(), Readiness::Starting);
        assert!(driver.startup_complete());
        assert_eq!(driver.readiness(), Readiness::Ready);
        // Past the deadline once complete: still ready.
        clock.0.store(60_000_000_000, Ordering::Relaxed);
        assert_eq!(driver.readiness(), Readiness::Ready);
        let conductor = driver.connect().unwrap();
        assert_eq!(
            driver.readiness(),
            Readiness::NotReady(NotReadyReason::Full)
        );
        drop(conductor);
        driver.stop_admitting();
        assert_eq!(
            driver.readiness(),
            Readiness::NotReady(NotReadyReason::NotAdmitting)
        );
    }

    /// R-CORE-35: a host that does not declare its startup complete within
    /// `startup_timeout` reports failed, for good: a late declaration does
    /// not undo it.
    #[test]
    fn a_startup_past_its_deadline_fails_for_good() {
        let clock = ManualClock::default();
        let mut driver = EmbeddedDriver::with_clock(
            DriverConfig {
                startup_timeout: 1_000,
                ..DriverConfig::default()
            },
            Box::new(clock.clone()),
        )
        .unwrap();
        clock.0.store(1_000, Ordering::Relaxed);
        assert_eq!(driver.readiness(), Readiness::Starting);
        clock.0.store(1_001, Ordering::Relaxed);
        assert_eq!(
            driver.readiness(),
            Readiness::Failed(FailedReason::StartupDeadline)
        );
        assert!(!driver.startup_complete());
        assert_eq!(
            driver.readiness(),
            Readiness::Failed(FailedReason::StartupDeadline)
        );
        assert!(matches!(
            EmbeddedDriver::with_config(DriverConfig {
                startup_timeout: 0,
                ..DriverConfig::default()
            }),
            Err(DriverError::InvalidConfig)
        ));
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
                schedule_capacity: 0,
            },
            allow_unconnected: false,
            on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
            conflation: None,
        }
    }

    /// The default broadcast capacity keeps a margin over the largest
    /// response extent, which `ConflatedReady` raised to 64 bytes: the
    /// default needs half of it, and every command budget that built with
    /// 40-byte extents at 16 KiB (up to 102) still builds.
    #[test]
    fn the_default_broadcast_capacity_keeps_a_margin() {
        assert_eq!(RESPONSE_EXTENT, 64);
        let config = DriverConfig::default();
        let needed = RESPONSE_EXTENT * 2 * config.command_budget * config.cycles_between_drains;
        assert!(2 * needed <= config.broadcast_capacity);
        for command_budget in [64, 102, 128] {
            assert!(
                EmbeddedDriver::with_config(DriverConfig {
                    command_budget,
                    ..DriverConfig::default()
                })
                .is_ok(),
                "{command_budget}"
            );
        }
        assert!(matches!(
            EmbeddedDriver::with_config(DriverConfig {
                command_budget: 129,
                ..DriverConfig::default()
            }),
            Err(DriverError::InvalidConfig)
        ));
    }

    /// conflation-end-to-end.md, Counters: the feeder counts the messages
    /// it writes and those it rejects, by cause. Every client publication
    /// refuses bad keys and oversized values before reserving, from the
    /// table its buffer carries (F7b-2c-2), so the rejected ones are
    /// appended through the buffer's raw publication, as a misbehaving
    /// process could write them. A table without `refresh` treats refresh
    /// cycle traffic as rejected keys, exactly as before ADR-0080.
    #[test]
    fn the_feeder_counts_writes_and_rejections_by_cause() {
        use karyos_sys::counters::CellRead;
        use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};

        let mut driver = EmbeddedDriver::new().unwrap();
        let mut stream_config = config(42);
        stream_config.conflation = Some(ConflationConfig {
            keys: 4,
            value_capacity: 8,
            journal_capacity: 1024,
            refresh: false,
        });
        let handle = driver.add_stream(stream_config).unwrap();
        let inner = driver
            .stream(handle)
            .unwrap()
            .buffer
            .publication_owned()
            .unwrap()
            .unwrap();
        let mut publication = inner;
        let cycle = karyos_sys::conflation::cycle::CycleId::default();
        let begin = karyos_sys::conflation::cycle::Marker::Begin {
            scope: karyos_sys::conflation::cycle::Scope::Refresh,
        }
        .encode();
        for (key, value) in [
            (1, b"ok".as_slice()),
            (99, b"bad-key"),
            (-1, b"negative"),
            (2, b"too-long-value"),
            (3, b"fine"),
            (
                karyos_sys::conflation::cycle::marker(cycle),
                begin.as_slice(),
            ),
            (
                karyos_sys::conflation::cycle::value(cycle, 1).unwrap(),
                b"refresh",
            ),
        ] {
            let options = AppendOptions {
                reserved_value: key,
                ..AppendOptions::default()
            };
            assert!(matches!(
                publication.append(value, options).unwrap(),
                AppendOutcome::Appended { .. }
            ));
        }
        let _ = driver.do_work().unwrap();
        let reader = driver.counters();
        let value = |counter: &Option<Counter>| match reader.read(counter.as_ref().unwrap().index())
        {
            CellRead::Allocated { value, .. } => value,
            other => panic!("unexpected {other:?}"),
        };
        let counters = driver.streams[0].feeder_counters.as_ref().unwrap();
        assert_eq!(value(&counters.written), 2);
        assert_eq!(value(&counters.keys_rejected), 4);
        assert_eq!(value(&counters.values_too_large), 1);
    }

    /// ADR-0080: an IPC table with `refresh` has no loss, so nothing to
    /// restore: a refresh value is written as a value, and a marker is
    /// ignored, neither written nor rejected.
    #[test]
    fn an_ipc_table_with_refresh_writes_refresh_values_as_values() {
        use karyos_sys::counters::CellRead;
        use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};

        let mut driver = EmbeddedDriver::new().unwrap();
        let mut stream_config = config(42);
        stream_config.conflation = Some(ConflationConfig::new(4, 8, 1024).with_refresh());
        let handle = driver.add_stream(stream_config).unwrap();
        let mut publication = driver
            .stream(handle)
            .unwrap()
            .buffer
            .publication_owned()
            .unwrap()
            .unwrap();
        let cycle = karyos_sys::conflation::cycle::CycleId::default();
        let begin = karyos_sys::conflation::cycle::Marker::Begin {
            scope: karyos_sys::conflation::cycle::Scope::Refresh,
        }
        .encode();
        for (key, value) in [
            (
                karyos_sys::conflation::cycle::marker(cycle),
                begin.as_slice(),
            ),
            (
                karyos_sys::conflation::cycle::value(cycle, 1).unwrap(),
                b"refresh",
            ),
            (-1, b"negative"),
        ] {
            let options = AppendOptions {
                reserved_value: key,
                ..AppendOptions::default()
            };
            assert!(matches!(
                publication.append(value, options).unwrap(),
                AppendOutcome::Appended { .. }
            ));
        }
        let _ = driver.do_work().unwrap();
        let reader = driver.counters();
        let value = |counter: &Option<Counter>| match reader.read(counter.as_ref().unwrap().index())
        {
            CellRead::Allocated { value, .. } => value,
            other => panic!("unexpected {other:?}"),
        };
        let counters = driver.streams[0].feeder_counters.as_ref().unwrap();
        assert_eq!(value(&counters.written), 1);
        assert_eq!(value(&counters.keys_rejected), 0);
    }

    /// A conflation table that exhausted its versions seals the stream
    /// with that reason and reports the closing once.
    #[test]
    fn conflation_exhaustion_seals_with_its_reason_and_reports_it_once() {
        use karyos_protocol::cnc::{CloseReason, Event as DriverEvent};
        let mut driver = EmbeddedDriver::new().unwrap();
        let mut stream_config = config(42);
        stream_config.conflation = Some(ConflationConfig {
            keys: 4,
            value_capacity: 8,
            journal_capacity: 1024,
            refresh: false,
        });
        let handle = driver.add_stream(stream_config).unwrap();
        let mut observer = driver.connect().unwrap();
        observer.set_liveness(Duration::ZERO, Duration::from_secs(3600));
        assert!(observed_work(&mut driver, &mut observer).is_empty());
        driver.streams[0].conflation_terminal =
            Some(karyos_sys::conflation::ConflationError::VersionsExhausted);
        assert_eq!(
            observed_work(&mut driver, &mut observer),
            [DriverEvent::PublicationClosed {
                stream: StreamKey {
                    stream_id: 42,
                    session_id: 1,
                },
                lane: karyos_sys::frame::Lane::ZERO,
                reason: CloseReason::ConflationVersionsExhausted,
                image: 0,
            }]
        );
        assert_eq!(
            driver.seal_reason(handle).unwrap(),
            Some(SealReason::ConflationVersionsExhausted)
        );
        assert!(observed_work(&mut driver, &mut observer).is_empty());
    }

    /// conflation-end-to-end.md, Mapping generations: a feeder that cannot
    /// follow a cutover (its generation link closed: a defect, here forced)
    /// ends the stream explicitly, sealed with `ConflationFeederLost`,
    /// reported once and logged, and its views end; never a silent loss.
    #[test]
    fn a_feeder_that_cannot_follow_a_cutover_ends_the_stream() {
        use karyos_client::{ConflatedSubscription, OfferOutcome};
        use karyos_protocol::cnc::{CloseReason, Event as DriverEvent};
        use karyos_sys::log_buffer::AppendOptions;
        let mut driver = EmbeddedDriver::new().unwrap();
        let mut stream_config = config(42);
        stream_config.conflation = Some(ConflationConfig {
            keys: 4,
            value_capacity: 8,
            journal_capacity: 1024,
            refresh: false,
        });
        let handle = driver.add_stream(stream_config).unwrap();
        let mut observer = driver.connect().unwrap();
        observer.set_liveness(Duration::ZERO, Duration::from_secs(3600));
        let mut publication = driver.publication(handle).unwrap();
        let mut conflated: ConflatedSubscription = driver.subscribe_conflated(handle).unwrap();
        let options = AppendOptions {
            reserved_value: 1,
            ..AppendOptions::default()
        };
        assert!(matches!(
            publication.offer_with(b"before", options).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
        assert!(observed_work(&mut driver, &mut observer).is_empty());
        let _ = driver
            .reconfigure_stream(
                handle,
                crate::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                    spare_slots: 3,
                },
            )
            .unwrap();
        // The defect: the feeder's link closes before it moves.
        let link = driver.streams[0]
            .feeder
            .as_ref()
            .unwrap()
            .subscription
            .generation_link()
            .cloned()
            .unwrap();
        let _ = link.close();
        let mut events = Vec::new();
        for _ in 0..20 {
            let _ = publication.offer_with(b"after", options).unwrap();
            events.extend(observed_work(&mut driver, &mut observer));
        }
        assert_eq!(
            events,
            [DriverEvent::PublicationClosed {
                stream: StreamKey {
                    stream_id: 42,
                    session_id: 1,
                },
                lane: karyos_sys::frame::Lane::ZERO,
                reason: CloseReason::ConflationFeederLost,
                image: 0,
            }]
        );
        assert!(driver.streams[0].feeder.is_none());
        assert_eq!(
            driver.seal_reason(handle).unwrap(),
            Some(SealReason::ConflationFeederLost)
        );
        let mut records = Vec::new();
        let _ = driver
            .error_log()
            .scan(&mut 0, |record| records.push(record));
        assert!(
            records.iter().any(|record| record.code
                == crate::diagnostics::ErrorCode::ConflationFeederLost as u32
                && record.key
                    == [
                        driver.streams[0].aggregate.registration,
                        u64::from(driver.streams[0].config.lane.get())
                    ]),
            "{records:?}"
        );
        // The views end.
        let mut report = conflated.poll_changed(|_, _| {}).unwrap();
        for _ in 0..8 {
            if report.closed {
                break;
            }
            report = conflated.poll_changed(|_, _| {}).unwrap();
        }
        assert!(report.closed, "{report:?}");
    }

    #[test]
    fn conflation_version_exhaustion_stores_cause_and_retries_a_failed_seal() {
        let mut driver = EmbeddedDriver::new().unwrap();
        let _stream = driver.add_stream(config(42)).unwrap();
        let stream = driver.streams.first_mut().unwrap();
        let Stream {
            conflation_terminal,
            conductor,
            ..
        } = stream;
        let mut fail_first_seal = true;
        let error = karyos_sys::conflation::ConflationError::VersionsExhausted;

        let first = seal_conflation_terminal(conflation_terminal, Some(error), || {
            if fail_first_seal {
                fail_first_seal = false;
                Err("injected seal failure")
            } else {
                conductor.seal().map_err(|_| "conductor seal failed")
            }
        });
        assert_eq!(first, Err("injected seal failure"));
        assert_eq!(*conflation_terminal, Some(error));
        assert_eq!(conductor.seal_state(), SealState::Active);

        let retry = seal_conflation_terminal(conflation_terminal, None, || {
            conductor.seal().map_err(|_| "conductor seal failed")
        });
        assert_eq!(retry, Ok(()));
        assert_eq!(conductor.seal_state(), SealState::Sealed);
    }

    #[test]
    fn each_driver_draws_its_own_driver_id() {
        let first = EmbeddedDriver::new().unwrap();
        let second = EmbeddedDriver::new().unwrap();
        assert_ne!(first.driver_id(), [0, 0]);
        assert_ne!(first.driver_id(), second.driver_id());
    }

    /// A host finds an active local stream by its key; another key, and a
    /// removed stream still retiring, are not found (archive-host.md, H2).
    #[test]
    fn a_local_stream_is_found_by_its_key_until_it_is_removed() {
        let mut driver = EmbeddedDriver::new().unwrap();
        let stream = driver.add_stream(config(42)).unwrap();
        let key = |stream_id| StreamKey {
            stream_id,
            session_id: 1,
        };
        assert_eq!(driver.stream_handle(key(42)), Some(stream));
        assert_eq!(driver.stream_handle(key(43)), None);
        assert_eq!(
            driver.stream_handle(StreamKey {
                stream_id: 42,
                session_id: 2
            }),
            None
        );
        // A subscriber keeps the removed stream retiring: it is no longer
        // found.
        let held = driver.subscribe(stream, Role::Required).unwrap();
        driver.remove_stream(stream).unwrap();
        assert_eq!(driver.stream_handle(key(42)), None);
        drop(held);
        driver.do_work().unwrap();
        assert_eq!(driver.stream_handle(key(42)), None);
    }

    #[test]
    fn the_trace_identity_names_the_driver_and_the_stream() {
        let mut driver = EmbeddedDriver::new().unwrap();
        let stream = driver.add_stream(config(42)).unwrap();
        let identity = driver.trace_identity(stream).unwrap();
        assert_eq!(identity.driver, driver.driver_id());
        assert_eq!(identity.stream_id, 42);
        assert_eq!(identity.session_id, 1);
        assert_eq!(identity.registration, stream.stream);
        // Stable for the same mapping.
        assert_eq!(driver.trace_identity(stream).unwrap(), identity);
        assert_eq!(identity.incarnation, FIRST_INCARNATION);
        // A cutover to a successor mapping is not a new incarnation: a
        // writer bound before it and a subscriber bound after it share the
        // identity (review finding on #93).
        let generation = driver
            .reconfigure_stream(
                stream,
                crate::generations::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 6,
                },
            )
            .unwrap();
        assert!(generation.get() > 0);
        assert_eq!(driver.trace_identity(stream).unwrap(), identity);
        let mut other = EmbeddedDriver::new().unwrap();
        assert!(matches!(
            other.trace_identity(stream),
            Err(DriverError::UnknownStream { .. })
        ));
    }

    #[test]
    fn trace_numbers_are_never_reused_and_end_with_a_typed_error() {
        let mut driver = EmbeddedDriver::new().unwrap();
        assert_eq!(driver.next_trace_number().unwrap(), 1);
        assert_eq!(driver.next_trace_number().unwrap(), 2);
        driver.next_trace_number = u64::MAX - 1;
        assert_eq!(driver.next_trace_number().unwrap(), u64::MAX - 1);
        assert!(matches!(
            driver.next_trace_number(),
            Err(DriverError::TraceNumbersExhausted)
        ));
        // Exhaustion is sticky: the last number is never handed out twice.
        assert!(matches!(
            driver.next_trace_number(),
            Err(DriverError::TraceNumbersExhausted)
        ));
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

    /// G-d2b, coordinator ACS 15247 (ii): a client that never leaves does
    /// not pin a replaced incarnation forever. Its liveness timeout
    /// releases its registration, and the replaced incarnation retires.
    #[test]
    fn a_dead_client_lets_the_replaced_incarnation_retire() {
        use karyos_protocol::cnc::SubscriberRole;
        let clock = ManualClock::default();
        let driver_config = DriverConfig {
            heartbeat_interval: 10,
            client_liveness_timeout: 100,
            ..DriverConfig::default()
        };
        let mut driver =
            EmbeddedDriver::with_clock(driver_config, Box::new(clock.clone())).unwrap();
        let stream = driver.add_stream(config(2)).unwrap();
        let guard = driver.add_guard("orders").unwrap();
        driver.guard_stream(stream, guard, 4, None).unwrap();
        assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
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
        let mut done = Vec::new();
        while done.is_empty() {
            let _ = observed_work(&mut driver, &mut observer);
            let _ = client.poll(usize::MAX, |completion| done.push(completion));
        }
        let publication = driver.publication(stream).unwrap();
        let _ = driver.close_guard(guard, 2).unwrap();
        drop(publication);
        let _ = observed_work(&mut driver, &mut observer);
        assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
        let _fresh = driver.publication(stream).unwrap();
        for _ in 0..3 {
            let _ = observed_work(&mut driver, &mut observer);
        }
        // Pinned by the client's registration on incarnation 1.
        assert_eq!(driver.stream(stream).unwrap().replaced.len(), 1);
        // The client stops beating: its liveness timeout passes.
        clock.0.store(100, Ordering::Relaxed);
        for _ in 0..4 {
            let _ = observed_work(&mut driver, &mut observer);
        }
        drop(done);
        for _ in 0..4 {
            let _ = observed_work(&mut driver, &mut observer);
        }
        assert!(
            driver.stream(stream).unwrap().replaced.is_empty(),
            "the dead client still pins the replaced incarnation"
        );
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
                lane: karyos_sys::frame::Lane::ZERO,
                reason: CloseReason::RequiredParticipantLost,
                image: 0,
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

    /// A step that overflowed inside adds the work that fit, counts one
    /// overflow and sets the cycle's error; an earlier error is kept.
    #[test]
    fn a_step_overflow_adds_what_fit_and_is_a_typed_error() {
        let counters = DriverCounters::new().unwrap();
        let mut work = 3;
        let mut error = None;
        add_step(&counters, &mut work, &mut error, (4, None));
        assert_eq!((work, error.is_none()), (7, true));
        let overflow = DriverError::WorkCountOverflow { count: 5, delta: 9 };
        add_step(&counters, &mut work, &mut error, (5, Some(overflow)));
        assert_eq!(work, 12);
        assert!(matches!(
            error,
            Some(DriverError::WorkCountOverflow { count: 5, delta: 9 })
        ));
        assert_eq!(counters.value(Event::CounterOverflows), 1);
        let later = DriverError::WorkCountOverflow { count: 1, delta: 1 };
        add_step(&counters, &mut work, &mut error, (0, Some(later)));
        assert!(matches!(
            error,
            Some(DriverError::WorkCountOverflow { count: 5, .. })
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

#[cfg(test)]
mod aggregate_subscriber_tests;
#[cfg(test)]
mod aggregate_tests;
#[cfg(test)]
mod initial_term_id_tests;
#[cfg(test)]
mod stream_cap_tests;

/// M2b: a stream's cells are allocated all or none.
#[cfg(test)]
mod stream_cells_tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use karyos_sys::counters::CellRead;

    use super::*;
    use crate::counters::{Event, FIXED_COUNTERS};

    fn allocated(counters: &DriverCounters) -> usize {
        let reader = counters.reader();
        (0..reader.capacity())
            .filter(|&index| matches!(reader.read(index), CellRead::Allocated { .. }))
            .count()
    }

    /// With room for five cells, a publication's six are refused whole:
    /// the five taken are freed, `counters unavailable` counts one, and
    /// the region holds what it held. With room, all six are keyed by the
    /// stream's registration.
    #[test]
    fn a_full_region_refuses_the_whole_group_once() {
        let labels = &crate::agents::PUBLICATION_CELLS;
        assert_eq!(labels.len(), 6);
        let mut counters = DriverCounters::with_capacity(FIXED_COUNTERS + 5).unwrap();
        let before = allocated(&counters);
        assert!(stream_network_cells(&mut counters, 7, labels).is_none());
        assert_eq!(allocated(&counters), before);
        assert_eq!(counters.value(Event::CountersUnavailable), 1);
        let mut counters = DriverCounters::with_capacity(FIXED_COUNTERS + 6).unwrap();
        let mut cells = stream_network_cells(&mut counters, 7, labels).unwrap();
        assert_eq!(counters.value(Event::CountersUnavailable), 0);
        let reader = counters.reader();
        let keyed: Vec<_> = (0..reader.capacity())
            .filter_map(|index| match reader.read(index) {
                CellRead::Allocated { metadata, .. } if metadata.keys.stream == 7 => {
                    Some(String::from_utf8(metadata.label().to_vec()).unwrap())
                }
                _ => None,
            })
            .collect();
        assert_eq!(keyed, labels);
        for cell in cells.take() {
            counters.free(cell);
        }
        assert_eq!(allocated(&counters), before);
    }
}

/// The bytes of a log buffer region of `buffer` (R-CORE-34), header
/// included, by the function that sizes it when it is created; `None` for
/// a configuration a buffer refuses. One definition for the stream cap
/// and the sizing report.
pub(crate) fn log_region_bytes(buffer: &LogBufferConfig) -> Option<u64> {
    region_bytes(LogBuffer::<karyos_sys::term_bytes::SharedTerms>::structure_length(buffer))
}

/// The bytes of a conflation table region of `table`, as
/// [`log_region_bytes`] for a log buffer: `None` also for a table that
/// [`conflation_shape`] refuses (a value capacity past `u32`), so the cap
/// and the sizing report refuse what `add_stream` refuses (karyos#824).
pub(crate) fn table_region_bytes(table: &ConflationConfig) -> Option<u64> {
    conflation_shape(*table).ok()?;
    region_bytes(table.structure_length())
}

/// The bytes of one stream lane's regions (R-CORE-34): its log buffer's,
/// and its conflation table's when it has one. The one definition behind
/// [`stream_lane_bytes`] and the sizing report. `None` for a configuration
/// a buffer or a table refuses.
pub(crate) fn lane_regions(
    buffer: &LogBufferConfig,
    conflation: Option<&ConflationConfig>,
) -> Option<(u64, Option<u64>)> {
    let log = log_region_bytes(buffer)?;
    let table = match conflation {
        Some(table) => Some(table_region_bytes(table)?),
        None => None,
    };
    Some((log, table))
}

pub(crate) fn region_bytes(structure: Option<usize>) -> Option<u64> {
    structure
        .and_then(karyos_sys::sizing::region_length)
        .and_then(|bytes| u64::try_from(bytes).ok())
}

/// The bytes one stream lane takes (R-CORE-34): its log buffer region,
/// header included, plus its conflation table's region if it has one, by
/// the functions that size them when they are created. It is what
/// `DriverConfig::max_stream_bytes` bounds. `None` for a configuration a
/// buffer or a table refuses, or a sum past 64 bits.
#[must_use]
pub fn stream_lane_bytes(
    buffer: &LogBufferConfig,
    conflation: Option<&ConflationConfig>,
) -> Option<u64> {
    let (log, table) = lane_regions(buffer, conflation)?;
    log.checked_add(table.unwrap_or(0))
}

/// `max` against [`stream_lane_bytes`]: [`DriverError::StreamTooLarge`]
/// above it, nothing checked without it. A configuration a buffer or a
/// table refuses passes here, so that its creation refuses it with its own
/// error, whether a cap is set or not.
pub(crate) fn check_lane_bytes(
    max: Option<u64>,
    buffer: &LogBufferConfig,
    conflation: Option<&ConflationConfig>,
) -> Result<(), DriverError> {
    let (Some(max), Some(bytes)) = (max, stream_lane_bytes(buffer, conflation)) else {
        return Ok(());
    };
    if bytes > max {
        return Err(DriverError::StreamTooLarge { bytes, max });
    }
    Ok(())
}

/// The shape of `config`'s table that its publications check, written in
/// every log buffer of the stream (F7b-2c-2).
///
/// # Errors
///
/// [`DriverError::InvalidConfig`] for a value capacity past `u32`, which
/// no message carries.
pub(crate) fn conflation_shape(
    config: ConflationConfig,
) -> Result<karyos_sys::log_buffer::ConflationShape, DriverError> {
    let value_capacity =
        u32::try_from(config.value_capacity).map_err(|_| DriverError::InvalidConfig)?;
    Ok(karyos_sys::log_buffer::ConflationShape::new(
        config.keys,
        value_capacity,
    ))
}

/// Whether `policy` replaces `rate` at version `current`, as the caller
/// `expected`, for `authority` (R-CORE-21): the new version, the current
/// one when unchanged, or the refusal.
fn decide_rate_change(
    rate: Option<karyos_sys::rate_limit::RatePolicy>,
    policy: &karyos_sys::rate_limit::RatePolicy,
    (expected, current): (u64, u64),
    reserve: Option<karyos_sys::rate_limit::Rate>,
    frame: u64,
    authority: crate::guards::RateAuthority,
) -> Result<u64, DriverError> {
    use crate::guards::{RateAuthority, RateChangeError};
    use karyos_sys::rate_limit::Transition;

    let old = rate.ok_or(DriverError::RateChange(RateChangeError::NoRate))?;
    policy
        .validate(frame)
        .map_err(DriverError::InvalidRatePolicy)?;
    if expected != current {
        return Err(DriverError::RateChange(RateChangeError::VersionMismatch {
            expected,
            current,
        }));
    }
    let transition = old.transition(policy);
    if transition == Transition::Unchanged {
        return Ok(current);
    }
    if authority == RateAuthority::Safety && transition != Transition::Tightening {
        return Err(DriverError::RateChange(RateChangeError::NotATightening));
    }
    if reserve.is_some_and(|reserve| !policy.keeps(&reserve, frame)) {
        return Err(DriverError::RateChange(RateChangeError::ReserveCrossed));
    }
    // Versions count accepted changes; 2^64 of them never happen.
    current
        .checked_add(1)
        .ok_or(DriverError::RateChange(RateChangeError::VersionMismatch {
            expected,
            current,
        }))
}
