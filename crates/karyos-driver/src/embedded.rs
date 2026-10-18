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
    use karyos_sys::log_buffer::{LogBuffer, LogBufferConfig};
    use karyos_sys::term::Generation;

    use crate::embedded::{EmbeddedDriver, StreamTerms};
    use crate::error::DriverError;

    /// Creates a stream's log buffer on the driver's backing.
    pub trait Create: Sized {
        /// A log buffer of `generation` for `config`.
        fn create(
            driver: &mut EmbeddedDriver<Self>,
            config: LogBufferConfig,
            generation: Generation,
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
        ) -> Result<LogBuffer<Self>, DriverError> {
            Ok(LogBuffer::new_with_generation(config, generation)?)
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
        ) -> Result<LogBuffer<Self>, DriverError> {
            let admission = driver
                .admission
                .as_mut()
                .ok_or(DriverError::InvalidConfig)?;
            let (instance, region) = admission.next_region()?;
            Ok(LogBuffer::create_in(instance, region, config, generation)?)
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
            conflated_subscription_budget: ConflationBudget {
                keys: 1024,
                retries: 3,
            },
            counters_capacity: 1024,
            position_sample_interval: 10_000_000,
            error_log_records: karyos_sys::diag::DEFAULT_ERROR_RECORDS,
            loss_report_records: karyos_sys::diag::DEFAULT_LOSS_RECORDS,
            error_dedup_window: 1_000_000_000,
            client_counters_capacity: 1024,
            max_counters_per_client: 64,
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
            network: None,
            initial_term_id: None,
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

/// The largest charged frame of a lane of `config` (aggregate-lanes.md,
/// charged bytes): a frame never exceeds the MTU, aligned to 32 bytes.
fn largest_charge(config: &StreamConfig) -> Result<u64, DriverError> {
    karyos_sys::sizing::align_frame(config.buffer.mtu)
        .map(u64::from)
        .map_err(|_| DriverError::InvalidConfig)
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
    /// The aggregate this lane belongs to.
    pub(crate) aggregate: Aggregate,
    pub(crate) retiring: bool,
    pub(crate) buffer: Arc<LogBuffer<T>>,
    pub(crate) conductor: Conductor<Arc<LogBuffer<T>>>,
    pub(crate) leases: Arc<StreamLeases>,
    /// Recording readers holding the stream (`recording_reader`): a
    /// cutover waits until there are none.
    pub(crate) recordings: Arc<std::sync::atomic::AtomicU64>,
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
        let link = GenerationLink::new();
        self.members.push(Member {
            link: Arc::downgrade(&link),
            kind,
        });
        (link, self.base)
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
    pub(crate) terminal: bool,
    /// Whether new clients are admitted; cleared once by
    /// [`EmbeddedDriver::stop_admitting`].
    pub(crate) admitting: bool,
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
    /// The error log and the loss report.
    pub(crate) diagnostics: crate::diagnostics::Diagnostics,
    /// The client trace journals and the trace mirror.
    pub(crate) trace_journals: crate::trace_journals::TraceJournals,
    /// The network trace hooks and their journals.
    pub(crate) network: crate::network_journals::NetworkTracing,
    /// The guard registry and its audit ring.
    pub(crate) guards: crate::guards::Guards,
    /// The sender gates registered with their guards (G-e4).
    pub(crate) guard_senders: crate::guard_ack::GuardSenders,
    /// Test only: guarding a network publication's lane of this index
    /// fails, as a walker short of a spare slot does.
    #[cfg(test)]
    pub(crate) guard_lane_fault: Option<usize>,
    /// The network agents and their tables, when configured.
    pub(crate) net: Option<crate::net::Network<T>>,
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
    /// different sources are each exposed, and the alias is refused only
    /// when it is the key of a stream that is not a network image (as a
    /// local stream over an image's key is refused). A replay target has
    /// no source and is refused for any stream of its key. Returns `None`,
    /// with nothing added, for a refused key, a full stream table or an
    /// aggregate that cannot be built (its quanta, its profile, its
    /// registrations or a conductor already issued). A retiring stream
    /// keeps its key until it frees, so an image of that alias installed
    /// meanwhile stays unexposed for its whole life (#283 P3).
    pub(crate) fn add_image_aggregate(
        &mut self,
        lanes: &[Arc<LogBuffer<T>>],
        source: Option<crate::net::ImageSource>,
    ) -> Option<AggregateHandle> {
        let first = lanes.first()?.config();
        let key = (first.stream_id, first.session_id);
        let count = u8::try_from(lanes.len()).ok()?;
        if self.streams.iter().any(|stream| {
            (stream.stream_id, stream.session_id) == key
                && (source.is_none() || stream.source.is_none())
        }) || self
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
                aggregate,
                retiring: false,
                buffer: Arc::clone(buffer),
                conductor,
                leases: Arc::new(StreamLeases::default()),
                recordings: Arc::default(),
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
                conflation_terminal: None,
                feeder_counters: None,
                guarded: None,
                incarnation: FIRST_INCARNATION,
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
        let needed = RESPONSE_EXTENT
            .checked_mul(2)
            .and_then(|n| n.checked_mul(config.command_budget))
            .and_then(|n| n.checked_mul(config.cycles_between_drains))
            .ok_or(DriverError::InvalidConfig)?;
        let valid = config.max_clients > 0
            && config.max_streams > 0
            && config.max_retained_generations > 0
            && config.counters_capacity >= crate::counters::FIXED_COUNTERS
            && config.position_sample_interval > 0
            && config.error_log_records > 0
            && config.loss_report_records > 0
            && config.client_counters_capacity > 0
            && config.max_counters_per_client > 0
            && config.max_trace_journals > 0
            && config.trace_recycle_log_entries > 0
            && config.max_trace_journal_bytes > 0
            && config.max_network_journal_bytes > 0
            && config.network_journal_records.is_power_of_two()
            && config.trace_drain_budget > 0
            && config.trace_mirror_records > 0
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
            && karyos_protocol::cnc::MAX_COMMAND_LENGTH
                .checked_add(HEADER_LENGTH as usize)
                .is_some_and(|record| config.ring_capacity / 8 >= record)
            && config.broadcast_capacity >= needed
            && config.guard_ack_timeout > 0
            && config.network.is_none_or(|network| {
                crate::net::client::valid_network(&network, config.max_clients)
            });
        if !valid {
            return Err(DriverError::InvalidConfig);
        }
        // The one per-instance id: trace and loss identities carry it, and
        // in IPC mode it is the admission instance id too (ACS 13555).
        let mut driver_id = [0u64; 2];
        karyos_sys::random::fill_u64s(&mut driver_id)?;
        #[cfg(target_os = "linux")]
        let (broadcast, counters, client_counters, admission, diagnostics, mirror) = match ipc {
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
                let diagnostics = crate::diagnostics::Diagnostics::new_in(&mut admission, &config)?;
                let (_, region) = admission.next_region()?;
                let client_counters = ClientCounters::new_in(
                    instance,
                    region,
                    config.client_counters_capacity,
                    config.max_counters_per_client,
                )?;
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
                )?,
                None,
                crate::diagnostics::Diagnostics::new(&config)?,
                heap_mirror(&config)?,
            ),
        };
        #[cfg(not(target_os = "linux"))]
        let (broadcast, counters, client_counters, diagnostics, mirror) = {
            let _ = ipc;
            (
                broadcast(config.broadcast_capacity).map_err(|_| DriverError::InvalidConfig)?,
                DriverCounters::with_capacity(config.counters_capacity)?,
                ClientCounters::new(
                    config.client_counters_capacity,
                    config.max_counters_per_client,
                )?,
                crate::diagnostics::Diagnostics::new(&config)?,
                heap_mirror(&config)?,
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
            client_counters,
            id,
            driver_id,
            next_trace_number: 1,
            config,
            streams: Vec::new(),
            broadcast,
            clients: Vec::new(),
            registrations: Vec::new(),
            next_client: 1,
            next_stream: 1,
            replays: crate::replay::ReplayTargets::default(),
            #[cfg(test)]
            fail_at: None,
            next_registration: 1,
            scan_cursor: 0,
            terminal: false,
            admitting: true,
            clock,
            next_export: 1,
            holding: Vec::new(),
            last_beat: None,
            positions: crate::positions::Positions::default(),
            #[cfg(target_os = "linux")]
            admission,
            diagnostics,
            trace_journals: crate::trace_journals::TraceJournals::new(
                mirror,
                config.max_trace_journal_bytes,
                config.max_network_journal_bytes,
                config.trace_drain_budget,
            ),
            network: crate::network_journals::NetworkTracing::new(config.max_trace_journals),
            guards: crate::guards::Guards::new(id, config.max_guards, config.guard_audit_records),
            guard_senders: crate::guard_ack::GuardSenders::new(config.max_guard_senders),
            #[cfg(test)]
            guard_lane_fault: None,
            // Validated above: the product fits.
            net_owned: Vec::with_capacity(config.network.map_or(0, |network| {
                crate::net::client::owned_capacity(&network, config.max_clients).unwrap_or(0)
            })),
            owned_refusals: 0,
            owned_refusals_overflowed: false,
            // Last: a driver that fails to build starts no agent.
            net: config
                .network
                .as_ref()
                .map(crate::net::Network::start)
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
    /// elapsed (`quantstratum-docs: karyos/design/observability-and-tools.md`).
    fn sample_positions(&mut self) {
        let now = karyos_sys::host_clock::host_monotonic_ns();
        if self
            .positions
            .due(now, self.config.position_sample_interval)
        {
            self.positions
                .sample(now, &mut self.counters, &self.streams);
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
    /// stays as a tombstone, naming a stream id that is never reused, until
    /// its client removes it or ends. A remote client's grants (its ledger)
    /// keep the stream until they end, at their `Detach` or the client's
    /// exit proof. A network publication's lanes stay while its removal lingers: its
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
            // The feeder counters go with their stream.
            for stream in freed {
                if let Some(counters) = stream.feeder_counters {
                    counters.free(&mut self.counters);
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

    /// Adds a guard named `name`, created closed at epoch 1, on the control
    /// path (`quantstratum-docs: karyos/design/guards-and-abort.md`).
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidConfig`] for an empty name or one longer than
    /// [`crate::guards::MAX_GUARD_NAME`] bytes, [`DriverError::DuplicateGuard`],
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
        let closed = self
            .guards
            .close(guard, operation, crate::guards::Requester::InProcess, now);
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
        let rate = match rate {
            None => None,
            Some(crate::guards::GuardRate {
                scope: crate::guards::RateScope::Publication,
                policy,
            }) => {
                // Every datagram fits the MTU (aggregate-lanes.md), so a byte
                // burst that holds the MTU holds whatever a route's sender
                // gate is validated against.
                let frame = u64::from(found.config.mtu);
                policy
                    .validate(frame)
                    .map_err(DriverError::InvalidRatePolicy)?;
                Some(policy)
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
        found.guarded = Some(crate::guard_streams::GuardedStream::new(
            guard, messages, rate, walker, scratch,
        ));
        Ok(())
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

    /// Creates a stream (control path: allocates its log buffer). Its
    /// `initial_term_id` is drawn at random in place of the configured one
    /// (SPEC §4, initial state).
    ///
    /// # Errors
    ///
    /// Returns configuration and allocation errors; no stream is added on
    /// error, and the refusal is recorded in the error log.
    /// [`DriverError::Sys`] when the random source fails, before anything
    /// is validated; it is logged too.
    pub fn add_stream(&mut self, config: StreamConfig) -> Result<StreamHandle, DriverError> {
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
        let added = self
            .draw_initial_term_id(self.config.initial_term_id)
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
        // logged as any other refusal.
        let mut config = config;
        match self.draw_initial_term_id(self.config.initial_term_id) {
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
        let buffer = Arc::new(<T as sealed::Create>::create(
            self,
            buffer_config,
            Generation::default(),
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
            aggregate,
            retiring: false,
            buffer,
            conductor,
            leases: Arc::new(StreamLeases::default()),
            recordings: Arc::default(),
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
            conflation_terminal: None,
            feeder_counters,
            guarded: None,
            incarnation: FIRST_INCARNATION,
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
        let binding = match self.prepare_guard_binding(stream) {
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
        let (link, base) = stream.join(MemberKind::Exclusive);
        let conflation = stream.conflation;
        let mut publication = ClientPublication::with_lease(inner, stream.allow_unconnected, lease);
        if let Some(config) = conflation {
            publication = publication.with_conflation(config);
        }
        let mut publication = publication.with_generation(link, base)?;
        if let (Some((client, bound)), Some(guarded)) = (binding, stream.guarded.as_mut()) {
            publication = publication.with_guard(client);
            guarded.bind(bound);
        }
        if let Some(schedule) = schedule {
            publication = publication.with_schedule(schedule);
            stream.schedule_issued = true;
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
        }))
    }

    /// The buffer, conductor and walker of the incarnation `plan`, not
    /// installed yet.
    fn prepare_incarnation(&mut self, plan: &Incarnation) -> Result<Fresh<T>, DriverError> {
        let buffer = Arc::new(<T as sealed::Create>::create(
            self,
            plan.config,
            plan.generation,
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
        let guarded = crate::guard_streams::GuardedStream::new(
            plan.guard,
            plan.messages,
            plan.rate,
            fresh.walker,
            fresh.scratch,
        );
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

    /// The guard binding of a handle about to be issued on a guarded
    /// stream: refused on a stream a guard close sealed (its incarnation is
    /// final, G-d2 brings the fresh one) and while the guard is not open.
    fn prepare_guard_binding(
        &self,
        stream: StreamHandle,
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
        let (ring, writer) =
            crate::guard_streams::new_ring(guarded.messages).map_err(DriverError::Outcomes)?;
        let consumed = Arc::new(karyos_sys::sync::AtomicU64::new(0));
        let client = karyos_client::GuardBinding::new(
            self.guards.view(guarded.guard)?,
            0,
            state.epoch,
            Arc::clone(&ring) as Arc<dyn karyos_client::SharedWords>,
            Arc::clone(&consumed) as Arc<dyn karyos_client::ConsumedCell>,
            found.config.lane.get() + 1,
            guarded.messages,
        )?;
        // The handle's early copy of the rate limit, read against the host
        // clock; the sender gate's bucket is authoritative.
        let client = match guarded.rate {
            Some(policy) => client.with_rate(policy, karyos_sys::host_clock::host_monotonic_ns),
            None => client,
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
        let (link, base) = stream.join(MemberKind::Concurrent);
        let conflation = stream.conflation;
        let mut publication =
            ClientConcurrentPublication::with_lease(inner, stream.allow_unconnected, lease);
        if let Some(config) = conflation {
            publication = publication.with_conflation(config);
        }
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
        // The (stream, incarnation) pairs a registration, a remote grant or
        // a held bound still names: a replaced incarnation they name is
        // kept, so a remote reader can read it to its seal. A dead remote
        // client releases them through its liveness timeout or exit proof.
        let mut pinned: Vec<(u64, u64)> = self
            .registrations
            .iter()
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
            let polled = if blocked {
                Ok(karyos_client::subscription::PollSummary::default())
            } else {
                subscription.poll(
                    |value, info| match config
                        .validate_publication(info.reserved_value, value.len())
                    {
                        Err(ConflationError::KeyOutOfRange { .. }) => fed.keys_rejected += 1,
                        Err(ConflationError::ValueTooLarge { .. }) => fed.values_too_large += 1,
                        Err(_) => {}
                        Ok(()) => {
                            if let Ok(key) = u32::try_from(info.reserved_value) {
                                let written = if with_positions {
                                    // Everything below the message is consumed.
                                    writer.passed(info.position);
                                    writer.write_at(key, value, info.position)
                                } else {
                                    writer.write(key, value)
                                };
                                match written {
                                    Ok(_) => fed.written += 1,
                                    Err(error @ ConflationError::VersionsExhausted) => {
                                        terminal = Some(error);
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    },
                    MessageLimit::new(budget),
                )
            };
            // A poll failure injected by a test (a feeder that cannot read
            // on).
            #[cfg(test)]
            let polled = if fail_poll {
                Err(karyos_client::subscription::PollError {
                    summary: karyos_client::subscription::PollSummary::default(),
                    cause: karyos_client::ClientError::ClosedByOverrun,
                })
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
            let writer = karyos_sys::conflation::conflation_fresh(
                config.keys,
                config.value_capacity,
                config.journal_capacity,
                link.clone(),
            )
            .map_err(|error| Some(ViewBuildFailure::Table(error)))?;
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
        // The closed network released every tracked guard sender: none of
        // them stays in a close acknowledgement.
        shutdown.guard_senders_released = self.deregister_released_guards();
        self.net = None;
        // The agents stopped with their hooks: no network journal stays open.
        self.close_network_tracing();
        Some(shutdown)
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
    /// it writes and those it rejects, by cause. A driver-issued
    /// publication refuses bad keys and oversized values before reserving,
    /// so the rejected ones come through a raw publication without those
    /// checks, as a misbehaving process could write them.
    #[test]
    fn the_feeder_counts_writes_and_rejections_by_cause() {
        use karyos_client::{ClientPublication, OfferOutcome};
        use karyos_sys::counters::CellRead;
        use karyos_sys::log_buffer::AppendOptions;

        let mut driver = EmbeddedDriver::new().unwrap();
        let mut stream_config = config(42);
        stream_config.conflation = Some(ConflationConfig {
            keys: 4,
            value_capacity: 8,
            journal_capacity: 1024,
        });
        let handle = driver.add_stream(stream_config).unwrap();
        let inner = driver
            .stream(handle)
            .unwrap()
            .buffer
            .publication_owned()
            .unwrap()
            .unwrap();
        let mut publication = ClientPublication::new(inner, false);
        for (key, value) in [
            (1, b"ok".as_slice()),
            (99, b"bad-key"),
            (-1, b"negative"),
            (2, b"too-long-value"),
            (3, b"fine"),
        ] {
            let options = AppendOptions {
                reserved_value: key,
                ..AppendOptions::default()
            };
            assert!(matches!(
                publication.offer_with(value, options).unwrap(),
                OfferOutcome::Accepted { .. }
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
        assert_eq!(value(&counters.keys_rejected), 2);
        assert_eq!(value(&counters.values_too_large), 1);
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
