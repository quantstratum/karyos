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
//! With the network on, it logs each network endpoint's capabilities when
//! the endpoint first appears and at each new capability epoch (M3b;
//! [`crate::capability_log`]), from its own CnC, checked at most every
//! [`CAPABILITY_CHECK`].
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

/// How often, at most, the daemon looks for endpoints to log.
pub const CAPABILITY_CHECK: std::time::Duration = std::time::Duration::from_millis(250);

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
    /// The Archive did not start (`--archive`).
    #[cfg(target_os = "linux")]
    Archive(crate::daemon_archive::ArchiveStartError),
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
            #[cfg(target_os = "linux")]
            Self::Archive(error) => write!(f, "{error}"),
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
/// subscriber is attached unless `stream` allows them, and the `Hold`
/// loss policy.
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
        allow_unconnected: stream.allow_unconnected,
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

/// The daemon's driver, alone or behind its Archive (`--archive`).
#[cfg(target_os = "linux")]
#[derive(Debug)]
enum Serving {
    /// The driver alone (boxed, as the Archive is).
    Plain(Box<EmbeddedDriver<SharedTerms>>),
    /// The driver behind the Archive's control server.
    Archive(Box<crate::daemon_archive::DaemonArchive>),
}

/// A started daemon: its driver and the streams it configured.
#[derive(Debug)]
pub struct Daemon {
    #[cfg(target_os = "linux")]
    serving: Serving,
    #[cfg(target_os = "linux")]
    streams: Vec<StreamHandle>,
    #[cfg(target_os = "linux")]
    linger: std::time::Duration,
    /// The last duty cycle error logged, so a repeated one is logged once.
    #[cfg(target_os = "linux")]
    last_error: Option<DriverError>,
    /// The endpoints whose capabilities are logged, with their epoch.
    #[cfg(target_os = "linux")]
    logged: Vec<(u64, u64)>,
    /// When to look for endpoints next.
    #[cfg(target_os = "linux")]
    next_check: Instant,
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
            let mut streams = Vec::with_capacity(configs.len().checked_add(2).unwrap_or(0));
            for (stream, config) in configs {
                let handle = driver
                    .add_stream(config)
                    .map_err(|error| StartError::Stream { stream, error })?;
                streams.push(handle);
            }
            let serving = match &options.archive {
                Some(archive) => {
                    let (archive, control) = crate::daemon_archive::DaemonArchive::start(
                        driver,
                        &options.terms,
                        archive,
                    )
                    .map_err(StartError::Archive)?;
                    streams.extend(control);
                    Serving::Archive(Box::new(archive))
                }
                None => Serving::Plain(Box::new(driver)),
            };
            Ok(Self {
                serving,
                streams,
                linger: options.shutdown_linger,
                last_error: None,
                logged: Vec::new(),
                next_check: Instant::now(),
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
            instance = ?self.driver().instance().map(|instance| format!("{instance:032x}")),
            streams = self.streams.len(),
            max_clients = options.driver.max_clients,
            network = options.driver.network.is_some(),
            archive = ?options.archive.as_ref().map(|archive| archive.dir.display().to_string()),
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
            self.serve(stop)
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
    /// The driver.
    fn driver(&self) -> &EmbeddedDriver<SharedTerms> {
        match &self.serving {
            Serving::Plain(driver) => driver,
            Serving::Archive(archive) => archive.driver(),
        }
    }

    /// The driver, mutably.
    fn driver_mut(&mut self) -> &mut EmbeddedDriver<SharedTerms> {
        match &mut self.serving {
            Serving::Plain(driver) => driver,
            Serving::Archive(archive) => archive.driver_mut(),
        }
    }

    /// Ends the Archive, if there is one: stops the boot recordings
    /// through the control path while duty cycles run, for at most
    /// `within`, then stops the agent and keeps the driver alone.
    fn end_archive(mut self, within: std::time::Duration) -> Self {
        let Serving::Archive(archive) = &mut self.serving else {
            return self;
        };
        archive.stop_recordings();
        let deadline = Instant::now().checked_add(within);
        while archive.stopping() && deadline.is_none_or(|deadline| Instant::now() < deadline) {
            let _ = archive.cycle();
            std::thread::yield_now();
        }
        if archive.stopping() {
            tracing::warn!("boot recordings not confirmed stopped; the agent stops them");
        }
        let Self {
            serving,
            streams,
            linger,
            last_error,
            logged,
            next_check,
        } = self;
        let driver = match serving {
            Serving::Archive(archive) => Box::new(archive.shutdown()),
            Serving::Plain(driver) => driver,
        };
        tracing::info!("archive stopped");
        Self {
            serving: Serving::Plain(driver),
            streams,
            linger,
            last_error,
            logged,
            next_check,
        }
    }

    fn serve(mut self, stop: &AtomicBool) -> Shutdown {
        // This loop drives the conductor: its spin time is the driver's
        // `conductor spin time` (M5).
        let mut idle = BackoffIdle::default().with_spin_meter(self.driver_mut().take_spin_meter());
        let mut clients = self.driver().clients();
        while !stop.load(Ordering::Acquire) {
            let work = self.cycle();
            self.log_capabilities();
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
        // The Archive first, within the linger: its recordings, then its
        // agent; the driver serves on alone.
        let deadline = Instant::now().checked_add(self.linger);
        let linger = self.linger;
        self = self.end_archive(linger);
        self.driver_mut().stop_admitting();
        for stream in self.streams.clone() {
            if let Err(error) = self.driver_mut().remove_stream(stream) {
                tracing::warn!(%error, "stream removal failed");
            }
        }
        idle.reset();
        loop {
            let work = self.cycle();
            self.log_capabilities();
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
        if !self.driver().is_terminal() {
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
        let done = match &mut self.serving {
            Serving::Plain(driver) => driver.do_work(),
            Serving::Archive(archive) => archive.cycle(),
        };
        match done {
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

    /// Logs each endpoint's capabilities (M3b) the first time a
    /// consistent read shows it at an epoch; forgets endpoints that left.
    /// Reads the CnC at most every [`CAPABILITY_CHECK`].
    fn log_capabilities(&mut self) {
        let now = Instant::now();
        if now < self.next_check {
            return;
        }
        self.next_check = now.checked_add(CAPABILITY_CHECK).unwrap_or(now);
        let endpoints =
            karyos_client::capabilities::endpoint_capabilities(&self.driver().counters());
        self.logged
            .retain(|(endpoint, _)| endpoints.iter().any(|found| found.endpoint == *endpoint));
        for found in endpoints.iter().filter(|found| found.consistent) {
            let epoch = found
                .gauges
                .iter()
                .find(|(label, _)| label == crate::capability_log::EPOCH)
                .map_or(0, |(_, epoch)| *epoch);
            if self.logged.contains(&(found.endpoint, epoch)) {
                continue;
            }
            self.logged
                .retain(|(endpoint, _)| *endpoint != found.endpoint);
            self.logged.push((found.endpoint, epoch));
            tracing::info!(
                endpoint = found.endpoint,
                epoch,
                capabilities = %crate::capability_log::line(&found.gauges),
                "endpoint capabilities"
            );
        }
    }

    /// Logs a change of the admitted client count; returns the new count.
    fn log_clients(&self, before: usize) -> usize {
        let clients = self.driver().clients();
        if clients != before {
            tracing::info!(clients, before, "clients changed");
        }
        clients
    }

    /// Configured streams not yet freed.
    fn unfreed(&self) -> usize {
        self.streams
            .iter()
            .filter(|&&stream| {
                !matches!(self.driver().stream_state(stream), Ok(StreamState::Freed))
            })
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
        allow_unconnected: false,
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
    fn a_daemon_with_an_archive_starts_and_shuts_down_cleanly() {
        let dir = std::env::temp_dir().join(format!("karyosd-unit-archive-{}", std::process::id()));
        let archive =
            std::env::temp_dir().join(format!("karyosd-unit-catalog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&archive);
        std::fs::create_dir_all(&archive).unwrap();
        let mut options = Options::new(dir.clone());
        options.terms.term_length = karyos_sys::sizing::MIN_TERM_LENGTH;
        options.streams.push(STREAM);
        options.archive = Some(crate::args::ArchiveOptions {
            dir: archive.clone(),
            requests: 100,
            responses: 101,
            records: vec![crate::args::RecordOption {
                stream_id: STREAM.stream_id,
                session_id: STREAM.session_id,
                sync: karyos_archive::segment::SyncPolicy::PerSegment,
            }],
            min_free: 0,
        });
        let daemon = Daemon::start(&options).unwrap();
        // The configured stream and the two control streams.
        assert_eq!(daemon.streams.len(), 3);
        let stop = AtomicBool::new(true);
        assert_eq!(daemon.run(&stop), Shutdown::Clean);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&archive);
    }

    /// Control streams that collide with a configured stream fail the
    /// start.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_archive_control_stream_that_collides_fails_the_start() {
        let dir = std::env::temp_dir().join(format!("karyosd-unit-collide-{}", std::process::id()));
        let archive = std::env::temp_dir().join(format!(
            "karyosd-unit-collide-catalog-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&archive).unwrap();
        let mut options = Options::new(dir.clone());
        options.terms.term_length = karyos_sys::sizing::MIN_TERM_LENGTH;
        options.streams.push(StreamOption {
            stream_id: 100,
            session_id: 0,
            allow_unconnected: false,
        });
        options.archive = Some(crate::args::ArchiveOptions {
            dir: archive.clone(),
            requests: 100,
            responses: 101,
            records: Vec::new(),
            min_free: 0,
        });
        assert!(matches!(
            Daemon::start(&options),
            Err(StartError::Archive(
                crate::daemon_archive::ArchiveStartError::Stream(_)
            ))
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&archive);
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
