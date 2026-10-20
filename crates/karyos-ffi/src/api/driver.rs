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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use karyos_client::ClientConductor;
use karyos_driver::{DriverConfig, DriverError, EmbeddedDriver};

use crate::api::client::{IDLE_BUSY_SPIN, IDLE_SLEEP, IDLE_YIELD};
use crate::boundary::drop_payload;
use crate::handles::{Handle, Kind, Table};
use crate::status::{Failure, Status};

/// The protocol version of the embedded client and driver
/// (`KARYOS_PROTOCOL_VERSION`).
pub(crate) const PROTOCOL_VERSION: u64 = 2;

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
}

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
            ..DriverConfig::default()
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
    /// Waits after a duty cycle that did `work`.
    fn idle(self, work: u32) {
        if work > 0 {
            return;
        }
        match self.strategy {
            IDLE_BUSY_SPIN => std::hint::spin_loop(),
            IDLE_SLEEP => std::thread::sleep(Duration::from_nanos(self.sleep_ns)),
            _ => std::thread::yield_now(),
        }
    }
}

/// The driver a thread of its own drives.
struct Threaded {
    /// The driver, shared with the thread.
    shared: Arc<Mutex<EmbeddedDriver>>,
    /// Asks the thread to stop.
    stop: Arc<AtomicBool>,
    /// The thread, until it is joined.
    thread: Option<JoinHandle<()>>,
}

impl Threaded {
    /// Stops the thread and waits for it; a panic it ended with is
    /// dropped (its poison stays on the driver).
    fn join(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take()
            && let Err(payload) = thread.join()
        {
            drop_payload(payload);
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
            Mode::Threaded(threaded) => threaded
                .shared
                .lock()
                .map(|mut driver| f(&mut driver))
                .map_err(|_| Status::Internal),
            Mode::Lost => Err(Status::Internal),
        }
    }

    /// Whether it can no longer be used.
    fn failed(&self) -> bool {
        match &self.mode {
            Mode::Invoker(_) => false,
            Mode::Threaded(threaded) => threaded.shared.is_poisoned(),
            Mode::Lost => true,
        }
    }
}

/// The table of drivers, allocated on first use.
fn drivers() -> &'static Table<Driver> {
    static DRIVERS: OnceLock<Table<Driver>> = OnceLock::new();
    DRIVERS.get_or_init(|| Table::new(Kind::Driver, MAX_DRIVERS))
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
            DriverError::Sys(error) => error.into(),
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
    drivers().with(driver, |slot| match &mut slot.mode {
        Mode::Invoker(driver) => driver.do_work().map_err(|error| Failure::from(&error)),
        Mode::Threaded(threaded) if threaded.shared.is_poisoned() => Err(Status::Internal.into()),
        Mode::Threaded(_) => Err(Status::Busy.into()),
        Mode::Lost => Err(Status::Internal.into()),
    })?
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
    if ![IDLE_BUSY_SPIN, IDLE_YIELD, IDLE_SLEEP].contains(&idle.strategy) {
        return Err(Status::InvalidArgument.into());
    }
    drivers().with(driver, |slot| {
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
        let spawned = {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("karyos-driver".to_owned())
                .spawn(move || run(&shared, &stop, idle))
        };
        match spawned {
            Ok(thread) => {
                slot.mode = Mode::Threaded(Threaded {
                    shared,
                    stop,
                    thread: Some(thread),
                });
                Ok(())
            }
            Err(error) => {
                // No thread holds the driver: it goes back to its caller.
                if let Ok(mutex) = Arc::try_unwrap(shared) {
                    slot.mode = Mode::Invoker(Box::new(
                        mutex.into_inner().unwrap_or_else(PoisonError::into_inner),
                    ));
                }
                let errno = error.raw_os_error().map_or(0, i32::unsigned_abs);
                Err(Failure::with(Status::System, 0, u64::from(errno)))
            }
        }
    })?
}

/// The driver's thread: duty cycles until asked to stop. A panic in one
/// poisons the shared driver and ends the thread.
fn run(shared: &Mutex<EmbeddedDriver>, stop: &AtomicBool, idle: Idle) {
    while !stop.load(Ordering::Acquire) {
        let work = {
            let Ok(mut driver) = shared.lock() else {
                return;
            };
            // A duty cycle's error is not fatal: the next one runs.
            driver.do_work().unwrap_or(0)
        };
        idle.idle(work);
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
    drivers().with(driver, |slot| {
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
            None => Err(Status::Internal),
        }
    })?
}

/// A conductor of `driver` for a new client.
///
/// # Errors
///
/// The driver's refusal, [`Status::Internal`] for a lost driver, and the
/// table's errors.
pub(crate) fn conductor(driver: Handle) -> Result<ClientConductor, Failure> {
    drivers()
        .with(driver, |slot| {
            slot.with_driver(|driver| driver.connect().map_err(|error| Failure::from(&error)))
        })?
        .map_err(Failure::from)?
}

/// Whether a client of `driver` may act: [`Status::Internal`] once the
/// driver is poisoned or lost, [`Status::Closed`] once it is closed. A
/// driver another thread holds, or this thread's callback, is not
/// failed.
///
/// # Errors
///
/// As described.
pub(crate) fn usable(driver: Handle) -> Result<(), Status> {
    match drivers().with(driver, |slot| slot.failed()) {
        Ok(false) | Err(Status::Busy | Status::Reentrant) => Ok(()),
        Ok(true) => Err(Status::Internal),
        Err(status) => Err(status),
    }
}

/// Closes `driver`, stopping its thread first; its clients stay to be
/// closed and answer [`Status::Closed`] meanwhile.
///
/// # Errors
///
/// As [`Table::remove`].
pub(crate) fn close(driver: Handle) -> Result<(), Status> {
    drivers().remove(driver).map(drop)
}

#[cfg(test)]
mod tests;
