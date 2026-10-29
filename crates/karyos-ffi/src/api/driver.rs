// SPDX-License-Identifier: Apache-2.0

//! Embedded drivers (F5): create, drive, connect clients, close
//! (quantstratum-docs: karyos/design/ffi-gap-analysis.md §3, §4.2).
//!
//! - **Two modes.** A new driver is driven by its caller ([`do_work`], the
//!   invoker mode). [`start`] moves it to a thread of its own that runs
//!   its duty cycle under an idle strategy until [`stop`] or the close;
//!   meanwhile [`do_work`] answers [`Status::Busy`]. [`stop`] gives it
//!   back to its caller.
//! - **Poisoning.** A panic in a duty cycle the caller runs poisons the
//!   driver's slot; one on its thread poisons the driver the thread
//!   shares, and the thread ends. Either way the driver answers
//!   [`Status::Internal`] until it is closed, and so do the clients it
//!   connected ([`usable`]; SPEC.md §10.2).
//! - **Protocol.** An embedded client and its driver come from one build
//!   and speak the protocol version this library was built with,
//!   [`PROTOCOL_VERSION`], asserted at compile time (ADR-0053).

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use std::collections::BTreeMap;

use karyos_client::ClientConductor;
use karyos_driver::agents::{IdleStrategy as _, YieldThenSleep};
use karyos_driver::{
    DriverConfig, DriverError, EmbeddedDriver, Readiness, StreamConfig, StreamHandle,
};
use karyos_sys::conflation::ConflationConfig;
use karyos_sys::error::SysError;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    DEFAULT_CLAIM_DEADLINE, LogBufferConfig, LossPolicy, PublicationMode,
};
use karyos_sys::schedule_ring::{MAX_CAPACITY, ScheduleError};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use crate::api::client::{IDLE_BUSY_SPIN, IDLE_SLEEP, IDLE_YIELD, IDLE_YIELD_THEN_SLEEP};
use crate::boundary::drop_payload;
use crate::handles::{Handle, Kind, Table};
use crate::status::{Failure, Status};

/// The protocol version of the embedded client and driver
/// (`KARYOS_PROTOCOL_VERSION`).
pub(crate) const PROTOCOL_VERSION: u64 = 3;

// The client and the driver of one build share karyos-protocol's version,
// and the header documents it: a change of it is a change of this library.
const _: () = assert!(PROTOCOL_VERSION == karyos_protocol::admission::VERSION);

/// The most drivers open at once (`KARYOS_MAX_DRIVERS`).
pub(crate) const MAX_DRIVERS: u32 = 8;

/// A driver's options, as `karyos_driver_options` carries them; every
/// other setting is the driver's default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Options {
    /// Clients admitted at once.
    pub(crate) max_clients: u32,
    /// Streams configured at once.
    pub(crate) max_streams: u32,
    /// Pending requests per client.
    pub(crate) max_pending_per_client: u32,
    /// Bytes of each client's command ring, a power of two.
    pub(crate) ring_capacity: u32,
    /// Bytes of the broadcast buffer.
    pub(crate) broadcast_capacity: u32,
    /// Cells of the counters region.
    pub(crate) counters_capacity: u32,
    /// How often the driver advances its heartbeat, in nanoseconds.
    pub(crate) heartbeat_interval_ns: u64,
    /// How long a client's heartbeat may stay unchanged, in nanoseconds.
    pub(crate) client_liveness_timeout_ns: u64,
    /// How long a handle has to move to a successor mapping, in
    /// nanoseconds.
    pub(crate) cutover_deadline_ns: u64,
    /// How long the host has to declare its startup complete, in
    /// nanoseconds (R-CORE-35).
    pub(crate) startup_timeout_ns: u64,
    /// Whether the driver runs its network agents, with
    /// `NetworkConfig::default()`.
    pub(crate) network: bool,
    /// The most bytes one stream lane may take
    /// (`DriverConfig::max_stream_bytes`, R-CORE-34); 0 for no cap.
    pub(crate) max_stream_bytes: u64,
}

/// `KARYOS_NETWORK_OFF`: no network agents; `karyos:ipc` only.
pub(crate) const NETWORK_OFF: u32 = 0;
/// `KARYOS_NETWORK_ON`: the network agents with their default
/// configuration, on their own threads.
pub(crate) const NETWORK_ON: u32 = 1;

impl Options {
    /// The driver's defaults.
    pub(crate) fn defaults() -> Self {
        let config = DriverConfig::default();
        let narrow = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
        Self {
            max_clients: narrow(config.max_clients),
            max_streams: narrow(config.max_streams),
            max_pending_per_client: narrow(config.max_pending_per_client),
            ring_capacity: narrow(config.ring_capacity),
            broadcast_capacity: narrow(config.broadcast_capacity),
            counters_capacity: narrow(config.counters_capacity),
            heartbeat_interval_ns: config.heartbeat_interval,
            client_liveness_timeout_ns: config.client_liveness_timeout,
            cutover_deadline_ns: config.cutover_deadline,
            startup_timeout_ns: config.startup_timeout,
            network: config.network.is_some(),
            max_stream_bytes: config.max_stream_bytes.unwrap_or(0),
        }
    }

    /// The driver's configuration; the driver checks it.
    fn config(&self) -> Result<DriverConfig, Failure> {
        let widen = |value: u32| usize::try_from(value).map_err(|_| Status::InvalidArgument);
        Ok(DriverConfig {
            max_clients: widen(self.max_clients)?,
            max_streams: widen(self.max_streams)?,
            max_pending_per_client: widen(self.max_pending_per_client)?,
            ring_capacity: widen(self.ring_capacity)?,
            broadcast_capacity: widen(self.broadcast_capacity)?,
            counters_capacity: widen(self.counters_capacity)?,
            heartbeat_interval: self.heartbeat_interval_ns,
            client_liveness_timeout: self.client_liveness_timeout_ns,
            cutover_deadline: self.cutover_deadline_ns,
            startup_timeout: self.startup_timeout_ns,
            network: self
                .network
                .then(karyos_driver::net::NetworkConfig::default),
            // 0 is no cap: `Some(0)`, which the driver refuses, is never
            // asked for (karyos#818).
            max_stream_bytes: (self.max_stream_bytes != 0).then_some(self.max_stream_bytes),
            ..DriverConfig::default()
        })
    }
}

/// `KARYOS_PUBLICATION_EXCLUSIVE`: one publication.
pub(crate) const PUBLICATION_EXCLUSIVE: u32 = 0;
/// `KARYOS_PUBLICATION_CONCURRENT`: up to `publishers` concurrent handles
/// on lane 0 (F7a-1).
pub(crate) const PUBLICATION_CONCURRENT: u32 = 1;
/// `KARYOS_LOSS_HOLD`.
pub(crate) const LOSS_HOLD: u32 = 0;
/// `KARYOS_LOSS_CONTINUE`.
pub(crate) const LOSS_CONTINUE: u32 = 1;
/// `KARYOS_LOSS_ABORT`.
pub(crate) const LOSS_ABORT: u32 = 2;

/// A stream's options, as `karyos_stream_options` carries them: the
/// fields of the Rust `StreamConfig`, its `LogBufferConfig` and its
/// conflation table (SPEC.md §4, §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamOptions {
    /// The wire stream id.
    pub(crate) stream_id: i32,
    /// Bytes of each term, a power of two.
    pub(crate) term_length: u32,
    /// The largest frame, header included.
    pub(crate) mtu: u32,
    /// The most bytes one claim reserves.
    pub(crate) max_reserved: u32,
    /// Term slots beyond the three in use.
    pub(crate) spare_slots: u32,
    /// Subscribers at once.
    pub(crate) max_subscribers: u32,
    /// The session alias.
    pub(crate) session_id: i32,
    /// The first term's id.
    pub(crate) initial_term_id: u32,
    /// The lane; 0 in this version.
    pub(crate) lane: u32,
    /// `KARYOS_PUBLICATION_*`.
    pub(crate) publication_mode: u32,
    /// Offers allowed with no subscriber attached: 0 or 1.
    pub(crate) allow_unconnected: u32,
    /// Entries of the stream's schedule ring: 0 for none, or a power of
    /// two up to [`MAX_CAPACITY`] on an exclusive stream.
    pub(crate) schedule_capacity: u32,
    /// `KARYOS_LOSS_*`: what a lost required subscriber does.
    pub(crate) on_required_loss: u32,
    /// How long a claim may stay open, in nanoseconds.
    pub(crate) claim_deadline_ns: u64,
    /// Keys of the conflation table; 0, with the two below, for none.
    pub(crate) conflation_keys: u32,
    /// The table's largest value, in bytes.
    pub(crate) conflation_value_capacity: u32,
    /// Bytes of the table's update journal.
    pub(crate) conflation_journal_capacity: u64,
    /// Concurrent handles at once: at least 1 for a concurrent stream, 0
    /// for an exclusive one.
    pub(crate) publishers: u32,
}

impl StreamOptions {
    /// A heap stream of the smallest term, as the driver's tests use.
    pub(crate) fn defaults() -> Self {
        Self {
            stream_id: 0,
            term_length: MIN_TERM_LENGTH,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            spare_slots: 3,
            max_subscribers: 4,
            session_id: 1,
            initial_term_id: 0,
            lane: 0,
            publication_mode: PUBLICATION_EXCLUSIVE,
            allow_unconnected: 0,
            schedule_capacity: 0,
            on_required_loss: LOSS_HOLD,
            claim_deadline_ns: DEFAULT_CLAIM_DEADLINE,
            conflation_keys: 0,
            conflation_value_capacity: 0,
            conflation_journal_capacity: 0,
            publishers: 0,
        }
    }

    /// The conflation table: none when all three fields are 0; a partial
    /// set, or sizes this target cannot hold, is refused. The driver
    /// checks the rest when it adds the stream.
    fn conflation(&self) -> Result<Option<ConflationConfig>, Failure> {
        let invalid = |code: u64| Failure::with(Status::InvalidArgument, code, 0);
        match (
            self.conflation_keys,
            self.conflation_value_capacity,
            self.conflation_journal_capacity,
        ) {
            (0, 0, 0) => Ok(None),
            (0, _, _) | (_, 0, _) | (_, _, 0) => Err(invalid(0)),
            (keys, value, journal) => Ok(Some(ConflationConfig {
                keys,
                value_capacity: usize::try_from(value).map_err(|_| invalid(u64::from(value)))?,
                journal_capacity: usize::try_from(journal).map_err(|_| invalid(journal))?,
                refresh: false,
            })),
        }
    }

    /// The driver's stream configuration; the driver checks the rest.
    fn config(&self) -> Result<StreamConfig, Failure> {
        let invalid = |code: u64| Failure::with(Status::InvalidArgument, code, 0);
        let term_length = TermLength::try_new(self.term_length)
            .map_err(|_| invalid(u64::from(self.term_length)))?;
        let lane = u8::try_from(self.lane)
            .ok()
            .filter(|lane| *lane == 0)
            .and_then(|lane| Lane::try_new(lane).ok())
            .ok_or_else(|| Failure::with(Status::InvalidLane, u64::from(self.lane), 0))?;
        // A concurrent stream's handles reserve with one `fetch_add`; on a
        // CPU where that is not a single instruction (aarch64 without LSE,
        // detected at run time by karyos-sys) the driver refuses the
        // stream, as its default is (ADR-0012).
        let publication = match (self.publication_mode, self.publishers) {
            (PUBLICATION_EXCLUSIVE, 0) => PublicationMode::Exclusive,
            (PUBLICATION_CONCURRENT, publishers) if publishers > 0 => PublicationMode::Concurrent {
                publishers: u8::try_from(publishers).map_err(|_| invalid(u64::from(publishers)))?,
                allow_non_lse: false,
            },
            (PUBLICATION_EXCLUSIVE | PUBLICATION_CONCURRENT, publishers) => {
                return Err(invalid(u64::from(publishers)));
            }
            (mode, _) => return Err(invalid(u64::from(mode))),
        };
        // A timed lane's schedule (TT-1, GC-7): the driver refuses any
        // other as a system failure, so it is refused here first.
        let schedule_capacity = match self.schedule_capacity {
            0 => 0,
            capacity if !capacity.is_power_of_two() || capacity > MAX_CAPACITY => {
                return Err(invalid(u64::from(capacity)));
            }
            _ if publication != PublicationMode::Exclusive => {
                return Err(invalid(u64::from(self.publication_mode)));
            }
            capacity => capacity,
        };
        let allow_unconnected = match self.allow_unconnected {
            0 => false,
            1 => true,
            other => return Err(invalid(u64::from(other))),
        };
        let on_required_loss = match self.on_required_loss {
            LOSS_HOLD => LossPolicy::Hold,
            LOSS_CONTINUE => LossPolicy::Continue,
            LOSS_ABORT => LossPolicy::Abort,
            other => return Err(invalid(u64::from(other))),
        };
        let narrow = |value: u32| u8::try_from(value).map_err(|_| invalid(u64::from(value)));
        Ok(StreamConfig {
            buffer: LogBufferConfig {
                term_length,
                spare_slots: narrow(self.spare_slots)?,
                max_subscribers: narrow(self.max_subscribers)?,
                mtu: self.mtu,
                max_reserved: self.max_reserved,
                initial_term_id: TermId::new(self.initial_term_id),
                lane,
                session_id: self.session_id,
                stream_id: self.stream_id,
                claim_deadline: self.claim_deadline_ns,
                publication,
                schedule_capacity,
            },
            allow_unconnected,
            on_required_loss,
            conflation: self.conflation()?,
        })
    }
}

/// An idle strategy, as `karyos_driver_start` takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Idle {
    /// `KARYOS_IDLE_*`.
    pub(crate) strategy: u32,
    /// The sleep of `KARYOS_IDLE_SLEEP`, in nanoseconds.
    pub(crate) sleep_ns: u64,
}

impl Idle {
    /// Waits after a duty cycle that did `work`; `backoff` is the thread's
    /// `KARYOS_IDLE_YIELD_THEN_SLEEP` state, the driver agents' own
    /// strategy (ADR-0066).
    fn idle(self, work: u32, backoff: &mut YieldThenSleep) {
        if self.strategy == IDLE_YIELD_THEN_SLEEP {
            backoff.idle(work);
            return;
        }
        if work > 0 {
            return;
        }
        match self.strategy {
            IDLE_BUSY_SPIN => std::hint::spin_loop(),
            // Parked, not slept: a stop or a close unparks the thread, so
            // neither waits out a long idle sleep (`karyos.h`, Threads). A
            // park may also return early (a spurious wake), so an idle
            // sleep is at most `sleep_ns`, not exactly it: harmless for an
            // idle strategy, which only runs the next cycle sooner.
            IDLE_SLEEP => std::thread::park_timeout(Duration::from_nanos(self.sleep_ns)),
            _ => std::thread::yield_now(),
        }
    }
}

/// The driver a thread of its own drives.
struct Threaded {
    /// The driver, shared with the thread.
    shared: Arc<Mutex<EmbeddedDriver>>,
    /// The callers waiting for `shared`: the thread yields to them between
    /// cycles, so a caller waits for one cycle, not for as long as the
    /// thread keeps winning an unfair lock (`karyos.h`, "Threads").
    waiting: Arc<AtomicU32>,
    /// The thread's duty cycles, and the most a caller waited through:
    /// the test of the bound (`tests::a_call_on_a_busy_spinning_driver_waits_for_one_cycle`).
    #[cfg(test)]
    cycles: Arc<Waited>,
    /// Asks the thread to stop.
    stop: Arc<AtomicBool>,
    /// The thread, until it is joined.
    thread: Option<JoinHandle<()>>,
}

/// A started driver's duty cycles and the most a caller waited through
/// (tests only).
#[cfg(test)]
#[derive(Debug, Default)]
struct Waited {
    done: std::sync::atomic::AtomicU64,
    most: std::sync::atomic::AtomicU64,
}

impl Threaded {
    /// Stops the thread and waits for it; a panic it ended with is
    /// dropped (its poison stays on the driver).
    fn join(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            // Wakes an idle sleep, which parks: the thread then sees the
            // stop before its next cycle.
            thread.thread().unpark();
            if let Err(payload) = thread.join() {
                drop_payload(payload);
            }
        }
    }
}

/// What a driver's dependants (its clients and their publications) see
/// of it, without taking its slot: one Acquire load per call.
#[derive(Debug, Clone)]
pub(crate) struct DriverState(Arc<AtomicU8>);

/// The driver runs.
const LIVE: u8 = 0;
/// A panic poisoned it, or it was lost between modes.
const LOST: u8 = 1;
/// It is closed.
const CLOSED: u8 = 2;

impl DriverState {
    fn new() -> Self {
        Self(Arc::new(AtomicU8::new(LIVE)))
    }

    /// Marks it lost, unless it is closed.
    fn lose(&self) {
        let _ = self
            .0
            .compare_exchange(LIVE, LOST, Ordering::AcqRel, Ordering::Acquire);
    }

    fn close(&self) {
        self.0.store(CLOSED, Ordering::Release);
    }

    /// Whether a dependant may act.
    ///
    /// # Errors
    ///
    /// [`Status::Internal`] once the driver is poisoned or lost,
    /// [`Status::Closed`] once it is closed.
    pub(crate) fn usable(&self) -> Result<(), Status> {
        match self.0.load(Ordering::Acquire) {
            LIVE => Ok(()),
            LOST => Err(Status::Internal),
            _ => Err(Status::Closed),
        }
    }
}

/// Marks a driver lost when a panic unwinds past it: in a call that holds
/// its slot, or on its thread.
struct Watch(DriverState);

impl Drop for Watch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.lose();
        }
    }
}

/// How a driver runs.
enum Mode {
    /// Its caller drives it (boxed: the other modes are small).
    Invoker(Box<EmbeddedDriver>),
    /// A thread of its own drives it.
    Threaded(Threaded),
    /// Between two modes, or lost: a panic during a mode change, or a
    /// driver its thread poisoned. It answers [`Status::Internal`].
    Lost,
}

/// A driver handle's object.
pub(crate) struct Driver {
    mode: Mode,
    /// Its streams, by wire stream id, with their session ids: the C ABI
    /// keys a driver's streams by stream id alone.
    streams: BTreeMap<i32, (StreamHandle, i32)>,
    /// What its dependants see of it.
    state: DriverState,
}

impl Drop for Driver {
    fn drop(&mut self) {
        // A closed driver's thread ends before the driver goes.
        if let Mode::Threaded(threaded) = &mut self.mode {
            threaded.join();
        }
    }
}

impl Driver {
    /// Runs `f` on the driver, in either mode.
    fn with_driver<R>(&mut self, f: impl FnOnce(&mut EmbeddedDriver) -> R) -> Result<R, Status> {
        match &mut self.mode {
            Mode::Invoker(driver) => Ok(f(driver)),
            // The thread holds it only for one duty cycle at a time.
            Mode::Threaded(threaded) => {
                threaded.waiting.fetch_add(1, Ordering::AcqRel);
                // Counted from the announcement: cycles the thread ran
                // before it could see a caller waiting are not the wait.
                #[cfg(test)]
                let before = threaded.cycles.done.load(Ordering::Acquire);
                let locked = threaded.shared.lock();
                threaded.waiting.fetch_sub(1, Ordering::AcqRel);
                #[cfg(test)]
                threaded.cycles.most.fetch_max(
                    threaded.cycles.done.load(Ordering::Acquire) - before,
                    Ordering::AcqRel,
                );
                locked
                    .map(|mut driver| f(&mut driver))
                    .map_err(|_| Status::Internal)
            }
            Mode::Lost => Err(Status::Internal),
        }
    }
}

/// The table of drivers, allocated on first use.
fn drivers() -> &'static Table<Driver> {
    static DRIVERS: OnceLock<Table<Driver>> = OnceLock::new();
    DRIVERS.get_or_init(|| Table::new(Kind::Driver, MAX_DRIVERS))
}

/// Runs `f` on `driver`'s slot; a panic in it poisons the slot (the
/// table) and marks the driver lost for its dependants.
fn with_slot<R>(driver: Handle, f: impl FnOnce(&mut Driver) -> R) -> Result<R, Status> {
    drivers().with(driver, |slot| {
        let _watch = Watch(slot.state.clone());
        f(slot)
    })
}

impl From<&DriverError> for Failure {
    fn from(error: &DriverError) -> Self {
        match error {
            DriverError::InvalidConfig => Status::InvalidArgument.into(),
            DriverError::TooManyClients | DriverError::ClientIdsExhausted => {
                Status::ResourcesUnavailable.into()
            }
            DriverError::Terminal => Status::Closed.into(),
            DriverError::NotAdmitting => Status::Refused.into(),
            // The descriptors needed in the code, the soft limit in the
            // value.
            DriverError::DescriptorLimit { needed, limit, .. } => {
                Self::with(Status::System, *needed, *limit)
            }
            // A stream configuration the buffer refuses is the caller's
            // argument, whichever check found it first.
            DriverError::Sys(SysError::Schedule(ScheduleError::Capacity { capacity })) => {
                Self::with(Status::InvalidArgument, u64::from(*capacity), 0)
            }
            DriverError::Sys(SysError::InvalidPublicationMode { .. }) => {
                Status::InvalidArgument.into()
            }
            DriverError::Sys(error) => error.into(),
            DriverError::DuplicateStream {
                stream_id,
                session_id,
            } => Self::with(
                Status::InvalidArgument,
                u64::from(stream_id.unsigned_abs()),
                u64::from(session_id.unsigned_abs()),
            ),
            DriverError::TooManyStreams | DriverError::StreamIdsExhausted => {
                Status::ResourcesUnavailable.into()
            }
            // A lane above `max_stream_bytes` is refused for the driver's
            // life: the caller's argument, its bytes and the cap in the
            // detail.
            DriverError::StreamTooLarge { bytes, max } => {
                Self::with(Status::InvalidArgument, *bytes, *max)
            }
            // An endpoint that cannot hold the publication (karyos#859):
            // retryable once a removal ends; the limit, the endpoint's
            // capacity and what it would take in the value.
            DriverError::EndpointCapacity {
                limit,
                capacity,
                needed,
            } => Self::with(
                Status::ResourcesUnavailable,
                0,
                limit.detail(*capacity, *needed),
            ),
            _ => Status::Unknown.into(),
        }
    }
}

/// Creates a driver in the invoker mode.
///
/// # Errors
///
/// The configuration's refusal, the driver's start's failure, and
/// [`Status::HandlesExhausted`].
pub(crate) fn create(options: &Options) -> Result<Handle, Failure> {
    let driver =
        EmbeddedDriver::with_config(options.config()?).map_err(|error| Failure::from(&error))?;
    Ok(drivers().insert(Driver {
        mode: Mode::Invoker(Box::new(driver)),
        streams: BTreeMap::new(),
        state: DriverState::new(),
    })?)
}

/// Runs one duty cycle of an invoker-mode driver; its work count.
///
/// # Errors
///
/// [`Status::Busy`] while the driver runs on its thread,
/// [`Status::Internal`] for a lost one, the table's errors, and the duty
/// cycle's.
pub(crate) fn do_work(driver: Handle) -> Result<u32, Failure> {
    with_slot(driver, |slot| {
        #[cfg(feature = "test-hooks")]
        if PANIC_NEXT_DUTY_CYCLE
            .compare_exchange(driver.raw(), 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            std::panic::resume_unwind(Box::new("the fault hook's panic"));
        }
        match &mut slot.mode {
            Mode::Invoker(driver) => driver.do_work().map_err(|error| Failure::from(&error)),
            Mode::Threaded(threaded) if threaded.shared.is_poisoned() => {
                Err(Status::Internal.into())
            }
            Mode::Threaded(_) => Err(Status::Busy.into()),
            Mode::Lost => Err(Status::Internal.into()),
        }
    })?
}

/// The driver whose next duty cycle panics while it holds the driver, its
/// caller's or its thread's, or 0 for none
/// (`karyos_test_panic_next_duty_cycle`, the test kit's fault hook): the
/// panic poisons the driver and its clients as any panic there does. One
/// handle, so that no other driver's cycle takes it.
#[cfg(feature = "test-hooks")]
pub(crate) static PANIC_NEXT_DUTY_CYCLE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// How long the fault hook waits for a driver's thread to take its panic.
#[cfg(feature = "test-hooks")]
const FAULT_WAIT: Duration = Duration::from_secs(10);

/// Arms the fault hook for `driver`'s next duty cycle. For a driver on its
/// own thread, it returns once that thread's cycle has panicked and the
/// driver is lost, so the caller's next call sees the poison.
///
/// # Errors
///
/// The table's errors for a handle that names no open driver, and
/// [`Status::Timeout`] when the thread took no cycle within
/// [`FAULT_WAIT`] (the hook is disarmed).
#[cfg(feature = "test-hooks")]
pub(crate) fn panic_next_duty_cycle(driver: Handle) -> Result<(), Status> {
    let threaded = drivers().with(driver, |slot| {
        matches!(slot.mode, Mode::Threaded(_)).then(|| slot.state.clone())
    })?;
    PANIC_NEXT_DUTY_CYCLE.store(driver.raw(), Ordering::Release);
    let Some(state) = threaded else {
        return Ok(());
    };
    let start = std::time::Instant::now();
    while state.usable().is_ok() {
        if start.elapsed() > FAULT_WAIT {
            let _ = PANIC_NEXT_DUTY_CYCLE.compare_exchange(
                driver.raw(),
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Err(Status::Timeout);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

/// Moves an invoker-mode driver to a thread of its own.
///
/// # Errors
///
/// [`Status::InvalidArgument`] for an unknown idle strategy,
/// [`Status::Busy`] when it already runs on its thread,
/// [`Status::Internal`] for a lost one, the table's errors, and the
/// thread's spawn as [`Status::System`] (the driver stays its caller's).
pub(crate) fn start(driver: Handle, idle: Idle) -> Result<(), Failure> {
    if ![
        IDLE_BUSY_SPIN,
        IDLE_YIELD,
        IDLE_SLEEP,
        IDLE_YIELD_THEN_SLEEP,
    ]
    .contains(&idle.strategy)
    {
        return Err(Status::InvalidArgument.into());
    }
    with_slot(driver, |slot| {
        match &slot.mode {
            Mode::Invoker(_) => {}
            Mode::Threaded(_) => return Err(Status::Busy.into()),
            Mode::Lost => return Err(Status::Internal.into()),
        }
        let Mode::Invoker(owned) = std::mem::replace(&mut slot.mode, Mode::Lost) else {
            return Err(Status::Internal.into());
        };
        let shared = Arc::new(Mutex::new(*owned));
        let stop = Arc::new(AtomicBool::new(false));
        let waiting = Arc::new(AtomicU32::new(0));
        #[cfg(test)]
        let cycles = Arc::new(Waited::default());
        let spawned = {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            let waiting = Arc::clone(&waiting);
            #[cfg(test)]
            let cycles = Arc::clone(&cycles);
            let state = slot.state.clone();
            #[cfg(feature = "test-hooks")]
            let raw = driver.raw();
            std::thread::Builder::new()
                .name("karyos-driver".to_owned())
                .spawn(move || {
                    run(
                        &shared,
                        &stop,
                        &waiting,
                        idle,
                        state,
                        #[cfg(test)]
                        &cycles,
                        #[cfg(feature = "test-hooks")]
                        raw,
                    );
                })
        };
        match spawned {
            Ok(thread) => {
                slot.mode = Mode::Threaded(Threaded {
                    shared,
                    waiting,
                    #[cfg(test)]
                    cycles,
                    stop,
                    thread: Some(thread),
                });
                Ok(())
            }
            Err(error) => {
                // No thread holds the driver: it goes back to its caller.
                match Arc::try_unwrap(shared) {
                    Ok(mutex) => {
                        slot.mode = Mode::Invoker(Box::new(
                            mutex.into_inner().unwrap_or_else(PoisonError::into_inner),
                        ));
                    }
                    Err(_) => slot.state.lose(),
                }
                let errno = error.raw_os_error().map_or(0, i32::unsigned_abs);
                Err(Failure::with(Status::System, 0, u64::from(errno)))
            }
        }
    })?
}

/// The driver's thread: duty cycles until asked to stop. A panic in one
/// poisons the shared driver and ends the thread.
fn run(
    shared: &Mutex<EmbeddedDriver>,
    stop: &AtomicBool,
    waiting: &AtomicU32,
    idle: Idle,
    state: DriverState,
    #[cfg(test)] cycles: &Waited,
    #[cfg(feature = "test-hooks")] handle: u64,
) {
    let watch = Watch(state);
    let mut backoff = YieldThenSleep::default();
    while !stop.load(Ordering::Acquire) {
        let work = {
            let Ok(mut driver) = shared.lock() else {
                // Poisoned by a panic in another holder.
                watch.0.lose();
                return;
            };
            #[cfg(feature = "test-hooks")]
            if PANIC_NEXT_DUTY_CYCLE
                .compare_exchange(handle, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                std::panic::resume_unwind(Box::new("the fault hook's panic"));
            }
            // A duty cycle's error is not fatal: the next one runs.
            driver.do_work().unwrap_or(0)
        };
        #[cfg(test)]
        cycles.done.fetch_add(1, Ordering::AcqRel);
        // A caller waiting for the driver takes it before the next cycle:
        // the lock is not fair, and this thread would otherwise take it
        // back at once (a busy-spin or busy driver).
        while waiting.load(Ordering::Acquire) > 0 && !stop.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        idle.idle(work, &mut backoff);
    }
}

/// Stops a driver's thread and gives the driver back to its caller.
///
/// # Errors
///
/// [`Status::Busy`] when it does not run on a thread,
/// [`Status::Internal`] when a panic on its thread poisoned it (it stays
/// lost until closed), and the table's errors.
pub(crate) fn stop(driver: Handle) -> Result<(), Status> {
    with_slot(driver, |slot| {
        let Mode::Threaded(threaded) = &mut slot.mode else {
            return Err(match slot.mode {
                Mode::Lost => Status::Internal,
                _ => Status::Busy,
            });
        };
        threaded.join();
        let Mode::Threaded(Threaded { shared, .. }) = std::mem::replace(&mut slot.mode, Mode::Lost)
        else {
            return Err(Status::Internal);
        };
        // The thread has ended, so this is the last reference; a poisoned
        // driver stays lost.
        let driver = Arc::try_unwrap(shared)
            .ok()
            .and_then(|mutex| mutex.into_inner().ok());
        match driver {
            Some(driver) => {
                slot.mode = Mode::Invoker(Box::new(driver));
                Ok(())
            }
            None => {
                slot.state.lose();
                Err(Status::Internal)
            }
        }
    })?
}

/// Adds a stream to `driver`; it lives until removed or the driver's
/// close.
///
/// # Errors
///
/// The options' and the driver's refusals: a stream id the driver already
/// has, in any session, is [`Status::InvalidArgument`] with the stream id
/// and the session id it has (the C ABI keys a driver's streams by stream
/// id alone, while the driver keys them by stream and session); a
/// partial conflation table, or one the driver cannot build, is
/// [`Status::InvalidArgument`]; [`Status::Internal`] for a lost driver,
/// and the table's errors.
pub(crate) fn add_stream(driver: Handle, options: &StreamOptions) -> Result<(), Failure> {
    let config = options.config()?;
    with_slot(driver, |slot| {
        if let Some((_, session)) = slot.streams.get(&options.stream_id) {
            return Err(Failure::with(
                Status::InvalidArgument,
                u64::from(options.stream_id.unsigned_abs()),
                u64::from(session.unsigned_abs()),
            ));
        }
        let added = slot.with_driver(|driver| driver.add_stream(config))?;
        let stream = added.map_err(|error| match error {
            // A conflation table the driver cannot build from the options.
            DriverError::Conflation(_) => Failure::from(Status::InvalidArgument),
            error => Failure::from(&error),
        })?;
        let _ = slot
            .streams
            .insert(options.stream_id, (stream, options.session_id));
        Ok(())
    })
    .map_err(Failure::from)?
}

/// Removes the stream `stream_id` of `driver`: its publication closes,
/// and its subscribers read up to its seal.
///
/// # Errors
///
/// [`Status::InvalidArgument`] for a stream id the driver does not have,
/// [`Status::Internal`] for a lost driver, and the table's errors.
pub(crate) fn remove_stream(driver: Handle, stream_id: i32) -> Result<(), Failure> {
    with_slot(driver, |slot| {
        let (stream, _) = slot.streams.get(&stream_id).copied().ok_or_else(|| {
            Failure::with(
                Status::InvalidArgument,
                u64::from(stream_id.unsigned_abs()),
                0,
            )
        })?;
        let removed = slot.with_driver(|driver| driver.remove_stream(stream))?;
        removed.map_err(|error| Failure::from(&error))?;
        let _ = slot.streams.remove(&stream_id);
        Ok(())
    })
    .map_err(Failure::from)?
}

/// Runs `f` on `driver`'s embedded driver and its stream `stream_id`, and
/// returns its result with the state the driver's dependants follow.
///
/// # Errors
///
/// [`Status::InvalidArgument`] for a stream id the driver does not have,
/// the driver's state ([`DriverState::usable`]), [`Status::Internal`] for
/// a lost driver, and the table's errors.
pub(crate) fn with_stream<R>(
    driver: Handle,
    stream_id: i32,
    f: impl FnOnce(&mut EmbeddedDriver, StreamHandle) -> R,
) -> Result<(R, DriverState), Failure> {
    with_slot(driver, |slot| {
        slot.state.usable()?;
        let (stream, _) = slot.streams.get(&stream_id).copied().ok_or_else(|| {
            Failure::with(
                Status::InvalidArgument,
                u64::from(stream_id.unsigned_abs()),
                0,
            )
        })?;
        let result = slot.with_driver(|driver| f(driver, stream))?;
        Ok((result, slot.state.clone()))
    })?
}

/// A conductor of `driver` for a new client, and the state the client
/// follows.
///
/// # Errors
///
/// The driver's refusal, [`Status::Internal`] for a lost driver, and the
/// table's errors.
pub(crate) fn conductor(driver: Handle) -> Result<(ClientConductor, DriverState), Failure> {
    with_slot(driver, |slot| {
        slot.state.usable()?;
        let conductor =
            slot.with_driver(|driver| driver.connect().map_err(|error| Failure::from(&error)))??;
        Ok((conductor, slot.state.clone()))
    })?
}

/// Declares `driver`'s startup complete (R-CORE-35), on its caller's
/// thread or its own: whether startup is complete, `false` when its
/// deadline had already passed.
///
/// # Errors
///
/// [`Status::Internal`] for a lost driver, and the table's errors.
pub(crate) fn startup_complete(driver: Handle) -> Result<bool, Status> {
    with_slot(driver, |slot| {
        slot.with_driver(EmbeddedDriver::startup_complete)
    })?
}

/// `driver`'s readiness (R-CORE-35) and its uptime in nanoseconds, on
/// its caller's thread or its own.
///
/// # Errors
///
/// [`Status::Internal`] for a lost driver, and the table's errors.
pub(crate) fn readiness(driver: Handle) -> Result<(Readiness, u64), Status> {
    with_slot(driver, |slot| {
        slot.with_driver(|driver| (driver.readiness(), driver.uptime()))
    })?
}

/// Closes `driver`, stopping its thread first; its clients stay to be
/// closed and answer [`Status::Closed`] meanwhile.
///
/// # Errors
///
/// As [`Table::remove`].
pub(crate) fn close(driver: Handle) -> Result<(), Status> {
    let closed = drivers().remove(driver)?;
    closed.state.close();
    // Dropping it joins its thread.
    drop(closed);
    Ok(())
}

#[cfg(test)]
mod tests;
