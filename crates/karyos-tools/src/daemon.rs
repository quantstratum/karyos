// SPDX-License-Identifier: Apache-2.0

//! The `karyosd` daemon: one dedicated driver in IPC mode (SPEC.md §3;
//! `quantstratum-docs: karyos/design/observability-and-tools.md`,
//! Binaries).
//!
//! [`Daemon::start`] builds an `EmbeddedDriver::with_ipc` from the parsed
//! [`Options`] and configures the streams they name. [`Daemon::run`] loops
//! on `do_work` with a [`crate::idle::BackoffIdle`] strategy until the stop flag is set
//! (by `SIGTERM` or `SIGINT` in the binary). It then stops admitting
//! clients, removes every stream (which seals it and marks it retiring,
//! `quantstratum-docs: karyos/design/stream-lifecycle.md`), and keeps
//! running duty cycles for up to the shutdown linger while clients leave
//! and retired streams are freed. The result is [`Shutdown::Clean`] once
//! every client has left and every stream is freed, and
//! [`Shutdown::Lingering`] when the linger ends first. A second signal
//! during the linger changes nothing. A driver that enters its terminal
//! state (`quantstratum-docs: karyos/design/client-commands.md`) serves
//! nothing more, so the daemon then stops at once with
//! [`Shutdown::Terminal`], logged as an error, whether or not a stop was
//! requested, so that a supervisor sees the failure.
//!
//! The daemon only emits `tracing` events; installing a subscriber is the
//! binary's job.

use std::fmt;
use std::sync::atomic::AtomicBool;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
#[cfg(target_os = "linux")]
use std::time::Instant;

use karyos_driver::{DriverError, LossPolicy, StreamConfig};
#[cfg(target_os = "linux")]
use karyos_driver::{EmbeddedDriver, IpcConfig, StreamHandle, StreamState, SystemClock};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::sizing::TermLength;
use karyos_sys::term::TermId;
#[cfg(target_os = "linux")]
use karyos_sys::term_bytes::SharedTerms;

#[cfg(target_os = "linux")]
use crate::args::AdmissionOptions;
use crate::args::{Options, StreamOption, TermOptions};
#[cfg(target_os = "linux")]
use crate::idle::BackoffIdle;

/// Exit status after an orderly shutdown with every client gone.
pub const EXIT_CLEAN: u8 = 0;
/// Exit status of a configuration or startup error.
pub const EXIT_STARTUP: u8 = 2;
/// Exit status when the shutdown linger ended first: clients were still
/// attached or a stream was not yet freed.
pub const EXIT_LINGERED: u8 = 3;
/// Exit status when the driver entered its terminal state.
pub const EXIT_TERMINAL: u8 = 4;

/// A startup failure; its display is the single line `karyosd` prints
/// before exiting with [`EXIT_STARTUP`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// IPC mode, and so the daemon, exists only on Linux.
    Unsupported,
    /// The term settings are invalid.
    InvalidTerms,
    /// The driver refused its configuration or could not create its
    /// socket or regions.
    Driver(DriverError),
    /// A configured stream was refused.
    Stream {
        /// The stream as given.
        stream: StreamOption,
        /// Why it was refused.
        error: DriverError,
    },
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "IPC mode needs Linux"),
            Self::InvalidTerms => write!(f, "invalid term settings"),
            Self::Driver(error) => write!(f, "driver start failed: {error}"),
            Self::Stream { stream, error } => write!(
                f,
                "stream {}:{} refused: {error}",
                stream.stream_id, stream.session_id
            ),
        }
    }
}

impl std::error::Error for StartError {}

/// How the daemon ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shutdown {
    /// Every client left and every stream was freed within the linger.
    Clean,
    /// The linger ended first.
    Lingering {
        /// Clients still admitted.
        clients: usize,
        /// Streams not yet freed.
        streams: usize,
    },
    /// The driver entered its terminal state.
    Terminal,
}

impl Shutdown {
    /// The process exit status: [`EXIT_CLEAN`], [`EXIT_LINGERED`] or
    /// [`EXIT_TERMINAL`].
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Clean => EXIT_CLEAN,
            Self::Lingering { .. } => EXIT_LINGERED,
            Self::Terminal => EXIT_TERMINAL,
        }
    }
}

/// The configuration of a stream started from `terms`: exclusive
/// publication, lane 0, initial term id 0, publications refused while no
/// subscriber is attached, and the `Hold` loss policy.
///
/// # Errors
///
/// Returns [`StartError::InvalidTerms`] for a term length that is not a
/// power of two from 64 KiB to 1 GiB. The driver checks the rest when the
/// stream is added.
pub fn stream_config(
    terms: &TermOptions,
    stream: StreamOption,
) -> Result<StreamConfig, StartError> {
    let term_length =
        TermLength::try_new(terms.term_length).map_err(|_| StartError::InvalidTerms)?;
    Ok(StreamConfig {
        buffer: LogBufferConfig {
            term_length,
            spare_slots: terms.spare_slots,
            max_subscribers: terms.max_subscribers,
            mtu: terms.mtu,
            max_reserved: terms
                .max_reserved
                .unwrap_or_else(|| term_length.max_reserved_limit()),
            initial_term_id: TermId::new(0),
            lane: Lane::ZERO,
            session_id: stream.session_id,
            stream_id: stream.stream_id,
            publication: PublicationMode::Exclusive,
            claim_deadline: terms.claim_deadline,
            schedule_capacity: 0,
        },
        allow_unconnected: false,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    })
}

/// The driver's admission settings from the command line.
#[cfg(target_os = "linux")]
#[must_use]
pub fn ipc_config(admission: &AdmissionOptions) -> IpcConfig {
    IpcConfig {
        dir: admission.dir.clone(),
        max_pending_hellos: admission.max_pending_hellos,
        hello_timeout: admission.hello_timeout,
        max_outbound_per_client: admission.max_outbound_per_client,
        fetch_deadline: admission.fetch_deadline,
        max_exports_per_client: admission.max_exports_per_client,
        max_fetches_per_client: admission.max_fetches_per_client,
        max_regions_per_fetch: admission.max_regions_per_fetch,
        max_fetch_bytes: admission.max_fetch_bytes,
        max_tools: admission.max_tools,
    }
}

/// A started daemon: its driver and the streams it configured.
#[derive(Debug)]
pub struct Daemon {
    #[cfg(target_os = "linux")]
    driver: EmbeddedDriver<SharedTerms>,
    #[cfg(target_os = "linux")]
    streams: Vec<StreamHandle>,
    #[cfg(target_os = "linux")]
    linger: std::time::Duration,
    /// The last duty cycle error logged, so a repeated one is logged once.
    #[cfg(target_os = "linux")]
    last_error: Option<DriverError>,
    #[cfg(not(target_os = "linux"))]
    never: core::convert::Infallible,
}

impl Daemon {
    /// Builds the driver from `options`, opening its admission socket, and
    /// adds the configured streams.
    ///
    /// # Errors
    ///
    /// Returns [`StartError`]; nothing is left running.
    pub fn start(options: &Options) -> Result<Self, StartError> {
        #[cfg(target_os = "linux")]
        {
            let configs = options
                .streams
                .iter()
                .map(|stream| {
                    stream_config(&options.terms, *stream).map(|config| (*stream, config))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut driver = EmbeddedDriver::with_ipc(
                options.driver,
                ipc_config(&options.admission),
                Box::new(SystemClock::new()),
            )
            .map_err(StartError::Driver)?;
            let mut streams = Vec::with_capacity(configs.len());
            for (stream, config) in configs {
                let handle = driver
                    .add_stream(config)
                    .map_err(|error| StartError::Stream { stream, error })?;
                streams.push(handle);
            }
            Ok(Self {
                driver,
                streams,
                linger: options.shutdown_linger,
                last_error: None,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = options;
            Err(StartError::Unsupported)
        }
    }

    /// Logs the start with the daemon's settings, once a subscriber is
    /// installed.
    pub fn log_started(&self, options: &Options) {
        #[cfg(target_os = "linux")]
        tracing::info!(
            dir = %options.admission.dir.display(),
            instance = ?self.driver.instance().map(|instance| format!("{instance:032x}")),
            streams = self.streams.len(),
            max_clients = options.driver.max_clients,
            network = options.driver.network.is_some(),
            shutdown_linger_ms = u64::try_from(options.shutdown_linger.as_millis()).unwrap_or(u64::MAX),
            "karyosd started"
        );
        #[cfg(not(target_os = "linux"))]
        {
            let _ = options;
            match self.never {}
        }
    }

    /// Runs duty cycles until `stop` is set, then shuts down as the module
    /// documentation describes.
    pub fn run(self, stop: &AtomicBool) -> Shutdown {
        #[cfg(target_os = "linux")]
        {
            let mut daemon = self;
            daemon.serve(stop)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stop;
            match self.never {}
        }
    }
}

#[cfg(target_os = "linux")]
impl Daemon {
    fn serve(&mut self, stop: &AtomicBool) -> Shutdown {
        // This loop drives the conductor: its spin time is the driver's
        // `conductor spin time` (M5).
        let mut idle = BackoffIdle::default().with_spin_meter(self.driver.take_spin_meter());
        let mut clients = self.driver.clients();
        while !stop.load(Ordering::Acquire) {
            let work = self.cycle();
            clients = self.log_clients(clients);
            if let Some(terminal) = self.terminal(clients) {
                return terminal;
            }
            idle.idle(work);
        }
        tracing::info!(
            clients,
            streams = self.streams.len(),
            linger_ms = u64::try_from(self.linger.as_millis()).unwrap_or(u64::MAX),
            "shutdown requested"
        );
        self.driver.stop_admitting();
        for &stream in &self.streams {
            if let Err(error) = self.driver.remove_stream(stream) {
                tracing::warn!(%error, "stream removal failed");
            }
        }
        let deadline = Instant::now().checked_add(self.linger);
        idle.reset();
        loop {
            let work = self.cycle();
            clients = self.log_clients(clients);
            if let Some(terminal) = self.terminal(clients) {
                return terminal;
            }
            let left = self.unfreed();
            if clients == 0 && left == 0 {
                tracing::info!("shutdown complete");
                return Shutdown::Clean;
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                tracing::warn!(
                    clients,
                    streams = left,
                    "shutdown linger ended with clients attached or streams not freed"
                );
                return Shutdown::Lingering {
                    clients,
                    streams: left,
                };
            }
            idle.idle(work);
        }
    }

    /// [`Shutdown::Terminal`], logged as an error, once the driver is in
    /// its terminal state.
    fn terminal(&self, clients: usize) -> Option<Shutdown> {
        if !self.driver.is_terminal() {
            return None;
        }
        tracing::error!(
            clients,
            streams = self.unfreed(),
            "driver entered its terminal state; stopping"
        );
        Some(Shutdown::Terminal)
    }

    /// One duty cycle; its work, 0 on error. A duty cycle error is logged
    /// when it differs from the last one logged.
    fn cycle(&mut self) -> u32 {
        match self.driver.do_work() {
            Ok(work) => work,
            Err(error) => {
                if self.last_error != Some(error) {
                    tracing::warn!(%error, "duty cycle error");
                    self.last_error = Some(error);
                }
                0
            }
        }
    }

    /// Logs a change of the admitted client count; returns the new count.
    fn log_clients(&self, before: usize) -> usize {
        let clients = self.driver.clients();
        if clients != before {
            tracing::info!(clients, before, "clients changed");
        }
        clients
    }

    /// Configured streams not yet freed.
    fn unfreed(&self) -> usize {
        self.streams
            .iter()
            .filter(|&&stream| !matches!(self.driver.stream_state(stream), Ok(StreamState::Freed)))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const STREAM: StreamOption = StreamOption {
        stream_id: 10,
        session_id: 1,
    };

    #[test]
    fn stream_config_takes_the_term_settings() {
        let options = Options::new(PathBuf::from("/d"));
        let config = stream_config(&options.terms, STREAM).unwrap();
        assert_eq!(
            config.buffer.term_length.get(),
            crate::args::DEFAULT_TERM_LENGTH
        );
        assert_eq!(
            config.buffer.max_reserved,
            crate::args::DEFAULT_TERM_LENGTH / 8
        );
        assert_eq!(config.buffer.stream_id, 10);
        assert_eq!(config.buffer.session_id, 1);
        let mut terms = options.terms;
        terms.max_reserved = Some(512);
        assert_eq!(
            stream_config(&terms, STREAM).unwrap().buffer.max_reserved,
            512
        );
        terms.term_length = 1000;
        assert_eq!(stream_config(&terms, STREAM), Err(StartError::InvalidTerms));
    }

    #[test]
    fn shutdown_codes() {
        assert_eq!(Shutdown::Clean.code(), 0);
        assert_eq!(
            Shutdown::Lingering {
                clients: 1,
                streams: 0
            }
            .code(),
            3
        );
        assert_eq!(Shutdown::Terminal.code(), 4);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_daemon_needs_linux() {
        let options = Options::new(PathBuf::from("/d"));
        assert!(matches!(
            Daemon::start(&options),
            Err(StartError::Unsupported)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_daemon_without_clients_shuts_down_cleanly() {
        let dir = std::env::temp_dir().join(format!("karyosd-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut options = Options::new(dir.clone());
        options.terms.term_length = karyos_sys::sizing::MIN_TERM_LENGTH;
        options.streams.push(STREAM);
        let daemon = Daemon::start(&options).unwrap();
        assert_eq!(daemon.streams.len(), 1);
        let stop = AtomicBool::new(true);
        assert_eq!(daemon.run(&stop), Shutdown::Clean);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_duplicate_stream_fails_the_start() {
        let dir = std::env::temp_dir().join(format!("karyosd-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut options = Options::new(dir.clone());
        options.terms.term_length = karyos_sys::sizing::MIN_TERM_LENGTH;
        options.streams.extend([STREAM, STREAM]);
        assert!(matches!(
            Daemon::start(&options),
            Err(StartError::Stream {
                stream: STREAM,
                error: DriverError::DuplicateStream { .. }
            })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
