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
use karyos_sys::term::Generation;
#[cfg(target_os = "linux")]
use karyos_sys::term_bytes::SharedTerms;
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use crate::client_counters::ClientCounters;
use crate::clock::{MonotonicClock, SystemClock};
use crate::commands::ClientSlot;
use crate::counters::{DriverCounters, Event, TYPE_EVENTS};
use crate::error::DriverError;
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
            trace_drain_budget: 1024,
            trace_mirror_records: 4096,
            max_guards: 16,
            guard_walker_budget: 1024,
            guard_audit_records: 1024,
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
    /// The aggregate this lane belongs to.
    pub(crate) aggregate: Aggregate,
    pub(crate) retiring: bool,
    pub(crate) buffer: Arc<LogBuffer<T>>,
    pub(crate) conductor: Conductor<Arc<LogBuffer<T>>>,
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
}

/// A sealed incarnation a fresh one replaced, retiring like a removed
/// stream (`quantstratum-docs: karyos/design/guards-and-abort.md`, The
/// fresh incarnation).
#[derive(Debug)]
pub(crate) struct Replaced<T: StreamTerms> {
    pub(crate) incarnation: u64,
    pub(crate) base: u64,
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
}

impl<T: StreamTerms> Stream<T> {
    /// The stream's wire key.
    pub(crate) fn key(&self) -> StreamKey {
        StreamKey {
            stream_id: self.stream_id,
            session_id: self.session_id,
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
    /// The guard registry and its audit ring.
    pub(crate) guards: crate::guards::Guards,
}

/// The incarnation of a stream's publication in the embedded driver: one per
/// stream registration, kept across mapping cutovers.
pub const FIRST_INCARNATION: u64 = 1;

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
    ) -> Result<Self, DriverError> {
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
            && config.broadcast_capacity >= needed;
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
                config.trace_drain_budget,
            ),
            guards: crate::guards::Guards::new(id, config.max_guards, config.guard_audit_records),
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
        self.retire_lane(stream)?;
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
        self.update_stream_gauges();
        Ok(())
    }

    /// Seals one lane stream and marks it retiring, once.
    fn retire_lane(&mut self, stream: StreamHandle) -> Result<(), DriverError> {
        let target = self.stream(stream)?;
        if !target.retiring {
            // A stream an earlier seal closed keeps that reason and was
            // reported then.
            let was_active = target.conductor.seal_state() == SealState::Active;
            target
                .conductor
                .seal_with_reason(SealReason::StreamRemoved)?;
            let key = target.key();
            let lane = target.config.lane;
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
                    reason: CloseReason::StreamRemoved,
                });
            }
        }
        Ok(())
    }

    /// Frees retiring streams with no live lease and no registration.
    pub(crate) fn free_retired_streams(&mut self) {
        let registrations = &self.registrations;
        let clients = &self.clients;
        // A remote grant keeps its stream until it ends, even after its
        // registration was removed.
        let freed: Vec<Stream<T>> = self
            .streams
            .extract_if(.., |stream| {
                stream.retiring
                    && stream.leases.live() == 0
                    && !registrations
                        .iter()
                        .any(|registration| registration.stream() == stream.id)
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
    /// recorded in the error log (`GuardSealFailed`, keyed by the guard)
    /// and retried by the walker's duty, never reported as a failed close.
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
    /// karyos/design/guards-and-abort.md`, Admission and Local streams).
    /// Each handle issued later is bound to the guard's open epoch, with an
    /// outcome ring of `messages` (`C_m`) message records.
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidPublicationMode`] for a concurrent stream
    /// (GC-7); [`DriverError::InvalidConfig`] for a stream already guarded,
    /// one with an issued handle, `messages` of 0, or `messages` reserved
    /// messages that do not fit half a term (the publication window, so
    /// the walker's retained span never needs more than the rotation and
    /// spare slots can hold); [`DriverError::UnknownGuard`]; and the
    /// walker's admission errors (it takes a spare-slot credit).
    pub fn guard_stream(
        &mut self,
        stream: StreamHandle,
        guard: GuardHandle,
        messages: u64,
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
        let walker = found
            .conductor
            .subscribe(karyos_sys::log_buffer::Role::Walker)?;
        let scratch = usize::try_from(found.buffer.max_message_length())
            .map_err(|_| DriverError::InvalidConfig)?;
        found.guarded = Some(crate::guard_streams::GuardedStream::new(
            guard, messages, walker, scratch,
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

    /// Creates a stream (control path: allocates its log buffer).
    ///
    /// # Errors
    ///
    /// Returns configuration and allocation errors; no stream is added on
    /// error, and the refusal is recorded in the error log.
    pub fn add_stream(&mut self, config: StreamConfig) -> Result<StreamHandle, DriverError> {
        let key = [
            u64::from(config.buffer.stream_id.cast_unsigned()),
            u64::from(config.buffer.session_id.cast_unsigned()),
        ];
        // One lane, the configured one, with a quantum of the largest frame:
        // exactly today's stream.
        let lane = config.buffer.lane;
        let added = largest_charge(&config)
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
    /// stream; every lane reports the aggregate's registration.
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
            conflation_terminal: None,
            feeder_counters,
            guarded: None,
            incarnation: FIRST_INCARNATION,
            replaced: Vec::new(),
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
    pub fn publication(
        &mut self,
        stream: StreamHandle,
    ) -> Result<ClientPublication<T>, DriverError> {
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
        self.update_stream_gauges();
        Ok(publication)
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
    /// # Errors
    ///
    /// [`DriverError::GuardSealed`] while the sealed incarnation's
    /// publication has not released (no seal position yet), for a
    /// conflated stream, and while a remote client holds a registration or
    /// export of the stream (remote incarnations are G-d2b);
    /// [`DriverError::IncarnationsExhausted`]; [`DriverError::PositionsExhausted`];
    /// and the buffer's allocation errors.
    fn reincarnate_if_reopened(&mut self, handle: StreamHandle) -> Result<(), DriverError> {
        let found = self.stream_ref(handle)?;
        let Some(guarded) = &found.guarded else {
            return Ok(());
        };
        if found.conductor.seal_reason() != Some(SealReason::GuardClosed)
            || !self.guards.state(guarded.guard)?.open
        {
            return Ok(());
        }
        let sealed = DriverError::GuardSealed { stream: found.id };
        let position = match found.conductor.seal_state() {
            SealState::Positioned { position } | SealState::Retired { position } => position,
            SealState::Active | SealState::Sealed => return Err(sealed),
        };
        let remote = self
            .registrations
            .iter()
            .any(|registration| registration.stream() == found.id);
        if found.conflation.is_some()
            || found.cutover.is_some()
            || !found.retained.is_empty()
            || remote
        {
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
        let (config, generation, guard, messages) = (
            found.config,
            found.generation,
            guarded.guard,
            guarded.messages,
        );
        let buffer = Arc::new(<T as sealed::Create>::create(self, config, generation)?);
        let mut conductor = buffer
            .conductor_owned()
            .ok_or(karyos_sys::error::SysError::ResourcesUnavailable)?;
        let walker = conductor.subscribe(Role::Walker)?;
        let scratch =
            usize::try_from(buffer.max_message_length()).map_err(|_| DriverError::InvalidConfig)?;
        // Every check passed: the swap cannot fail.
        let found = self.stream(handle)?;
        let fresh = crate::guard_streams::GuardedStream::new(guard, messages, walker, scratch);
        if let Some(old) = found.guarded.replace(fresh) {
            found.replaced.push(Replaced {
                incarnation: found.incarnation,
                base: found.base,
                conductor: std::mem::replace(&mut found.conductor, conductor),
                guarded: old,
            });
        }
        found.buffer = buffer;
        found.incarnation = incarnation;
        found.base = base;
        found.members.clear();
        found.spare = None;
        found.claim_waiting = false;
        Ok(())
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
        #[cfg(target_os = "linux")]
        let admitted = self.serve_admission();
        #[cfg(not(target_os = "linux"))]
        let admitted: (u32, Option<DriverError>) = (0, None);
        // Retire before sampling liveness: an orderly close at the
        // deadline is a retirement, not a time-out.
        self.retire_closed_clients();
        let alive = self.serve_liveness();
        self.sweep_ended_registrations();
        self.free_retired_streams();
        let mut work = self.serve_commands();
        let mut first_error = None;
        add_step(&self.counters, &mut work, &mut first_error, admitted);
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
                        add_work(&self.counters, &mut work, &mut first_error, walked.written);
                        add_work(&self.counters, &mut work, &mut first_error, walked.lost);
                    }
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            stream.replaced.retain(|replaced| {
                !(replaced.guarded.ended()
                    && matches!(replaced.conductor.seal_state(), SealState::Retired { .. }))
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
                    closed.push((stream.key(), stream.config.lane));
                }
            }
            let Some(config) = stream.conflation else {
                continue;
            };
            let Some(feeder) = &mut stream.feeder else {
                continue;
            };
            let ConflationFeeder {
                subscription,
                writer,
            } = feeder;
            let mut terminal = None;
            let mut fed = Fed::default();
            let polled = subscription.poll(
                |value, info| match config.validate_publication(info.reserved_value, value.len()) {
                    Err(ConflationError::KeyOutOfRange { .. }) => fed.keys_rejected += 1,
                    Err(ConflationError::ValueTooLarge { .. }) => fed.values_too_large += 1,
                    Err(_) => {}
                    Ok(()) => {
                        if let Ok(key) = u32::try_from(info.reserved_value) {
                            match writer.write(key, value) {
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
            );
            // A failed poll still reports what it handled before the failure.
            if let Some(counters) = &stream.feeder_counters {
                counters.add(&self.counters, fed);
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
                        (stream.key(), stream.config.lane),
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
                closed.push((stream.key(), stream.config.lane));
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
                    (stream.key(), stream.config.lane),
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
        for (stream, lane) in closed {
            self.emit(&DriverEvent::PublicationClosed {
                stream,
                lane,
                reason: CloseReason::ConflationVersionsExhausted,
            });
        }
        // The loss is always logged; only a stream it closes is reported,
        // so a stream closed for good earlier gets no second closing.
        // The record names the aggregate's registration and the lane.
        for (key, (stream, lane), cause, open) in lost {
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
                });
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(work),
        }
    }

    fn stream(&mut self, stream: StreamHandle) -> Result<&mut Stream<T>, DriverError> {
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

    pub(crate) fn clock_now(&mut self) -> u64 {
        self.clock.now()
    }
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
        let mut report = conflated.poll_changed(|_, _| {});
        for _ in 0..8 {
            if report.closed {
                break;
            }
            report = conflated.poll_changed(|_, _| {});
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
