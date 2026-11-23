// SPDX-License-Identifier: Apache-2.0

//! The command line of `karyosd`, parsed by hand over `std::env::args_os`
//! (`quantstratum-docs: karyos/design/observability-and-tools.md`,
//! Binaries).
//!
//! Every option takes one value, as `--name value` or `--name=value`,
//! except `--help` and `--sizing-report`.
//! Counts and sizes are decimal integers; a size may end in `k`, `m` or `g`
//! (powers of 1024). Durations are an integer followed by `ns`, `us`, `ms`
//! or `s`. Values are checked here only for their syntax and range; the
//! driver validates the configuration as a whole when it starts.
//!
//! `--network on` gives the driver `NetworkConfig::default()`: the network
//! agents on their own threads, so clients create `karyos:udp`
//! publications and subscriptions by URI, whose `term-length`, `mtu` and
//! `lanes` keys override the stream defaults. The rest of the network
//! configuration is not on the command line yet: the agents' rings and
//! session limits, the threading mode, the image template, the stream
//! defaults, the NAK control groups and the per-client limit. The one
//! exception is `--idle-image-timeout` (owner item 1, karyos#638).

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use karyos_driver::DriverConfig;

use crate::config::{ConfigError, IoBackend, IoConfig, IoSchema, SocketsBackend};
use karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE;
use karyos_sys::sizing::DEFAULT_MTU;

/// The usage text of `karyosd --help`.
pub const HELP: &str = "\
karyosd: runs one dedicated Karyos driver (IPC mode, Linux).

Usage: karyosd --dir <path> [options]
       karyosd --sizing-report [options]

Configuration:
  --config <path>                   a configuration file: the [io] table and its backend
                                    tables (TOML); the options below override it
  --io-backend <name>               the I/O backend, overriding [io] backend; this driver
                                    has sockets [sockets]
  --io-require <capability>         a capability every endpoint must have active; one
                                    that lacks it fails to open, at startup or at the
                                    first add; any use replaces [io] require; repeatable
                                    The io configuration needs --network on.

Admission:
  --dir <path>                      private directory of the admission socket (required)
  --max-pending-hellos <n>          connections not yet past Hello [4]
  --hello-timeout <duration>        time a connection has to send Hello [5s]
  --max-outbound-per-client <n>     messages queued for one client [16]
  --fetch-deadline <duration>       time a client has to take a fetch [5s]
  --max-exports-per-client <n>      grants one client holds at once [16]
  --max-fetches-per-client <n>      open fetches of one client [4]
  --max-regions-per-fetch <n>       records in one manifest [4]
  --max-fetch-bytes <size>          bytes of the regions of one fetch [1g]
  --max-tools <n>                   tool connections at once [4]

Driver limits:
  --max-clients <n>                 clients admitted at once [16]
  --max-streams <n>                 streams configured at once [64]
  --max-pending-per-client <n>      pending requests per client [16]
  --max-hand-over <n>               hand-over entries over all clients [64]
  --command-budget <n>              commands served per duty cycle [64]
  --cycles-between-drains <n>       duty cycles between two client drains [2]
  --ring-capacity <size>            bytes of each command ring, at least 8k [8k]
  --broadcast-capacity <size>       bytes of the broadcast buffer [32k]
  --max-retained-generations <n>    predecessor mappings per stream [2]
  --max-stream-bytes <size>         the most bytes one stream lane may take, its log
                                    buffer and table; a larger stream, replay target or
                                    reconfiguration is refused, and the sizing report
                                    gains its bounded figures [unset: no bound]
  --cutover-deadline <duration>     time a handle has to move to a successor [1s]
  --heartbeat-interval <duration>   driver heartbeat period [100ms]
  --client-liveness-timeout <duration>  silence before a client times out [10s]
  --counters-capacity <n>           cells of the counters region [1024]
  --client-counters-capacity <n>    cells of the client counters region [1024]
  --max-counters-per-client <n>     client counter cells per client [64]
  --max-trace-points-per-client <n> live application trace points per client [16]
  --max-trace-point-registrations-per-client <n>
                                    trace points a client registers over its life [256]
  --max-trace-point-copies <n>      driver-written trace point copies, own cells [256]
  --max-trace-journals <n>          entries of the trace journal table [64]
  --max-trace-journal-bytes <size>  bytes of every client trace journal [64m]
  --trace-drain-budget <n>          journal records mirrored per duty cycle [1024]
  --trace-mirror-records <n>        records of the trace mirror [4096]

Diagnostics:
  --sample-interval <duration>      positions sampling period [10ms]
  --error-log-records <n>           records of the error log [1024]
  --loss-report-records <n>         records of the loss report [256]
  --error-dedup-window <duration>   window that merges a repeated error [1s]
  --log-level <level>               error, warn, info, debug or trace [info]

Network:
  --network <on|off>                run the network agents, so clients create karyos:udp
                                    publications and subscriptions by URI, with the
                                    driver's default network configuration [off]
  --timed-network <stream_id>:<capacity>
                                    the network publications clients create by URI on
                                    this stream are timed, a schedule ring of capacity
                                    entries (a power of two) on each lane; needs
                                    --network on; not a --stream; at most 8 streams,
                                    each once; repeatable
  --idle-image-timeout <duration>   how long stationary heartbeats keep an image alive
                                    after its last fresh evidence, in ns, us, ms or s;
                                    at least the image liveness timeout (10s); needs
                                    --network on [60s]

Streams:
  --stream <stream_id>:<session_id>[:allow-unconnected]
                                    configure a stream at start; allow-unconnected lets
                                    its publications, a remote client's included, offer
                                    with no subscriber attached; repeatable
  --conflation <stream_id>:<session_id>:<keys>:<value_capacity>:<journal_capacity>
                                    a conflation table on a configured stream: an
                                    offer's reserved value is its key, below keys;
                                    the capacities are sizes; repeatable
  --guard <name>:<stream_id>:<session_id>:<messages>
                                    guard a configured stream with guard name (one
                                    guard however many streams name it), its outcome
                                    records holding messages; the guard is opened once
                                    at start (audited); closing it remains an operator
                                    action (owner item 59); repeatable
  --term-length <size>              term length of every stream [1m]
  --mtu <n>                         frame bytes per fragment [1408]
  --max-reserved <size>             bytes one message may reserve [term length / 8]
  --spare-slots <n>                 spare slots beyond the three rotation slots [3]
  --max-subscribers <n>             subscriber registry capacity [4]
  --claim-deadline <duration>       commit deadline of claims [1s]

Archive:
  --archive <path>                  run the Archive agent, its catalog in this directory
  --archive-control <req>,<resp>    the Archive's request and response stream ids, which the
                                    daemon adds (the request stream concurrent); required
                                    with --archive
  --record <stream_id>:<session_id>[:<sync>]
                                    start recording a configured stream at boot, through the
                                    control path; sync is none, segment or a duration
                                    [segment]; repeatable; needs --archive
                                    Under same-uid admission every admitted client may
                                    control the Archive: the trust boundary is the daemon's
                                    uid. Per-client authorization comes with owner item 43.
  --archive-min-free <size>         refuse a recording while the archive's file system has
                                    less free space [1g]
  --archive-seal-interval <duration>
                                    seal each recorded byte in the integrity journal within
                                    this time [1s]
  --archive-anchor-interval <duration>
                                    the anchor interval (SPEC 8.4, X14): required with
                                    --archive, no default; the signing's coverage-lag
                                    threshold: the daemon logs a warning when signed
                                    coverage falls behind it, and when it recovers
  --archive-signer <program>        the operator's head signer, run as `<program> sign`:
                                    the head's signed bytes in hex on stdin, the Ed25519
                                    signature in hex on stdout; needs --archive-signer-key
                                    and --archive-trust
  --archive-signer-key <hex>        the signer's 32-byte public key, in hex
  --archive-trust <file>            the trust file the key registry is replayed under (the
                                    format of karyos-catalog verify --trust)
  --archive-copy-location <hex>     this Archive's 32-byte location id in its copy catalog:
                                    each recording closed sealed is recorded as a local copy
  --archive-retain-for <duration>   retention policy: how long a range is kept once it closed
  --archive-purge <mode>            retention policy: manual or after-expiry
  --archive-min-copies <n>          retention policy: verified copies elsewhere before a
                                    purge (the three together, with --archive-copy-location)
  --archive-time-evidence           keep time evidence entries: makes <archive>/time-evidence
                                    (with a signer, the trust file needs a time-journal line)

Shutdown:
  --shutdown-linger <duration>      time clients have to leave after SIGTERM or SIGINT [5s]

  --sizing-report                   print the bytes of every shared region these options
                                    map (configured, bounded and restart peak) and exit
                                    without starting; --dir is not needed
  -h, --help                        print this text

Exit status: 0 after an orderly shutdown with every client gone and every
stream freed; 2 on a configuration or startup error; 3 when the shutdown
linger ended first (clients still attached or a stream not yet freed); 4
when the driver entered its terminal state.
";

/// The default term length of configured streams: 1 MiB.
pub const DEFAULT_TERM_LENGTH: u32 = 1024 * 1024;
/// The default shutdown linger.
pub const DEFAULT_SHUTDOWN_LINGER: Duration = Duration::from_secs(5);

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print [`HELP`] and exit.
    Help,
    /// Run the daemon.
    Run(Box<Options>),
    /// Print the sizing report of these options (R-CORE-34) and exit.
    SizingReport(Box<Options>),
}

/// The admission socket settings, mirroring the driver's `IpcConfig`
/// (which exists only on Linux).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionOptions {
    /// The private directory of the admission socket.
    pub dir: PathBuf,
    /// Connections accepted but not yet past `Hello`.
    pub max_pending_hellos: usize,
    /// How long a connection has to send `Hello`, in nanoseconds.
    pub hello_timeout: u64,
    /// Messages queued for one client.
    pub max_outbound_per_client: usize,
    /// How long a client has to take a fetch, in nanoseconds.
    pub fetch_deadline: u64,
    /// Grants one client holds at once.
    pub max_exports_per_client: usize,
    /// Fetches of one client whose messages are still queued.
    pub max_fetches_per_client: usize,
    /// Records in one manifest.
    pub max_regions_per_fetch: usize,
    /// Bytes of the regions of one fetch.
    pub max_fetch_bytes: u64,
    /// Tool connections admitted at once.
    pub max_tools: usize,
}

/// The term settings shared by every stream configured at start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TermOptions {
    /// Length of every term, in bytes.
    pub term_length: u32,
    /// Maximum frame bytes per fragment.
    pub mtu: u32,
    /// Maximum bytes one message may reserve; `None` for
    /// `term_length / 8`.
    pub max_reserved: Option<u32>,
    /// Spare slots beyond the three rotation slots.
    pub spare_slots: u8,
    /// Subscriber registry capacity.
    pub max_subscribers: u8,
    /// Commit deadline of claims, in nanoseconds.
    pub claim_deadline: u64,
}

/// A stream to configure at start: its wire stream id and session, and
/// whether its publications may offer with no subscriber attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamOption {
    /// Wire stream id.
    pub stream_id: i32,
    /// Session alias.
    pub session_id: i32,
    /// `:allow-unconnected` was given: every publication of the stream,
    /// a remote client's included, offers with no subscriber attached
    /// (SPEC.md §4 `allow_unconnected`).
    pub allow_unconnected: bool,
}

/// A configured stream's conflation table (`--conflation`), fed by its
/// publication: an offer's reserved value is its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConflationOption {
    /// The stream's wire stream id.
    pub stream_id: i32,
    /// Its session alias.
    pub session_id: i32,
    /// Dense keys, `0..keys`.
    pub keys: u32,
    /// The largest value, in bytes.
    pub value_capacity: u64,
    /// The update journal's capacity, in bytes.
    pub journal_capacity: u64,
}

/// A configured stream guarded at start (`--guard`): its publication's
/// messages go through guard `name`'s gate and outcome records. The guard
/// opens at start; closing it is an operator action outside the daemon
/// (owner item 59).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardOption {
    /// The guard's name, created once however many streams name it.
    pub name: String,
    /// The stream's wire stream id.
    pub stream_id: i32,
    /// Its session alias.
    pub session_id: i32,
    /// Messages the guard's outcome records hold open at once.
    pub messages: u64,
}

/// A recording the daemon starts at boot (`--record`), through the
/// Archive's control path like any requester's `StartRecording`
/// (`quantstratum-docs: karyos/design/archive-host.md`, H3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordOption {
    /// The recorded stream's wire stream id.
    pub stream_id: i32,
    /// Its session alias.
    pub session_id: i32,
    /// The store's sync policy.
    pub sync: karyos_archive::segment::SyncPolicy,
}

/// The Archive agent's settings (`--archive`, `--archive-control`,
/// `--record`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveOptions {
    /// The directory of the Archive's catalog and segments.
    pub dir: PathBuf,
    /// The control request stream's id; the daemon adds it concurrent.
    pub requests: i32,
    /// The control response stream's id.
    pub responses: i32,
    /// The recordings started at boot, in command-line order.
    pub records: Vec<RecordOption>,
    /// The free bytes of the archive's file system below which a
    /// recording is refused.
    pub min_free: u64,
    /// The `seal_interval`: each recorded byte is sealed within it (A10).
    pub seal_interval: Duration,
    /// The `anchor_interval`, required with no default (SPEC.md §8.4,
    /// X14): the signing configuration's coverage-lag threshold, past
    /// which the daemon logs the signing alarm (karyos#1031).
    pub anchor_interval: Duration,
    /// The head signer, when one is configured (karyos#966).
    pub signer: Option<SignerOption>,
    /// This Archive's location id in its copy catalog
    /// (`--archive-copy-location`, karyos#1024): each recording closed
    /// sealed is recorded as a local copy.
    pub copy_location: Option<[u8; 32]>,
    /// The retention policy purges are checked against
    /// (`--archive-retain-for`, `--archive-purge`, `--archive-min-copies`;
    /// karyos#1093). Needs `copy_location`.
    pub retention: Option<karyos_archive::integrity::retention::RetentionPolicy>,
    /// Whether the Archive keeps time evidence entries
    /// (`--archive-time-evidence`, ADR-0095 and ADR-0098): the daemon
    /// makes `<archive>/time-evidence/` before the agent starts. With a
    /// signer, the trust file needs its `time-journal` line.
    pub time_evidence: bool,
}

/// The head signer of an Archive (`--archive-signer`,
/// `--archive-signer-key`, `--archive-trust`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerOption {
    /// The signing program.
    pub program: PathBuf,
    /// The signer's public key.
    pub public: [u8; 32],
    /// The trust file.
    pub trust: PathBuf,
}

/// The default `--archive-seal-interval`: 1 s.
pub const DEFAULT_ARCHIVE_SEAL_INTERVAL: Duration = Duration::from_secs(1);

/// The default `--archive-min-free`: 1 GiB. A free-space floor that
/// protects the host; it complements retention (karyos#667) and never
/// proves it.
pub const DEFAULT_ARCHIVE_MIN_FREE: u64 = 1 << 30;

/// The verbosity of the control-path log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Informational records and above.
    Info,
    /// Debug records and above.
    Debug,
    /// Everything.
    Trace,
}

/// The parsed options of `karyosd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The driver's limits and sizes.
    pub driver: DriverConfig,
    /// The admission socket settings.
    pub admission: AdmissionOptions,
    /// The term settings of the configured streams.
    pub terms: TermOptions,
    /// The streams configured at start, in command-line order.
    pub streams: Vec<StreamOption>,
    /// The conflation tables of configured streams (`--conflation`).
    pub conflations: Vec<ConflationOption>,
    /// The guarded configured streams (`--guard`).
    pub guards: Vec<GuardOption>,
    /// The timed network streams (`--timed-network`): stream id and
    /// schedule capacity, in command-line order.
    pub timed_networks: Vec<(i32, u32)>,
    /// The network agents' `idle_image_timeout` (`--idle-image-timeout`),
    /// set on the network configuration once the arguments are parsed.
    pub idle_image_timeout: Option<Duration>,
    /// How long the shutdown waits for clients to leave.
    pub shutdown_linger: Duration,
    /// The control-path log verbosity.
    pub log_level: LogLevel,
    /// The Archive agent, when `--archive` is given.
    pub archive: Option<ArchiveOptions>,
    /// The I/O configuration: the file of `--config` with `--io-backend`
    /// and `--io-require` over it, checked against the schema the binary
    /// registered ([`parse_with`]). A backend's table is read from it with
    /// [`IoConfig::table`].
    pub io: IoConfig,
}

impl Options {
    /// The defaults, with the admission socket in `dir`.
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            driver: DriverConfig::default(),
            admission: AdmissionOptions {
                dir,
                max_pending_hellos: 4,
                hello_timeout: 5_000_000_000,
                max_outbound_per_client: 16,
                fetch_deadline: 5_000_000_000,
                max_exports_per_client: 16,
                max_fetches_per_client: 4,
                max_regions_per_fetch: 4,
                max_fetch_bytes: 1 << 30,
                max_tools: 4,
            },
            terms: TermOptions {
                term_length: DEFAULT_TERM_LENGTH,
                mtu: DEFAULT_MTU,
                max_reserved: None,
                spare_slots: 3,
                max_subscribers: 4,
                claim_deadline: DEFAULT_CLAIM_DEADLINE,
            },
            streams: Vec::new(),
            conflations: Vec::new(),
            guards: Vec::new(),
            timed_networks: Vec::new(),
            idle_image_timeout: None,
            shutdown_linger: DEFAULT_SHUTDOWN_LINGER,
            log_level: LogLevel::Info,
            archive: None,
            io: IoConfig::default(),
        }
    }
}

/// A command-line error. Its display is the single line `karyosd` prints
/// before exiting with status 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgsError {
    /// An argument that is not a known option.
    UnknownOption(String),
    /// An option given without its value.
    MissingValue(&'static str),
    /// A value that does not parse or is out of range.
    InvalidValue {
        /// The option.
        option: &'static str,
        /// The value as given.
        value: String,
    },
    /// A required option is absent.
    Missing(&'static str),
    /// An option that needs another, which is absent.
    Needs {
        /// The option given.
        option: &'static str,
        /// The option it needs.
        needs: &'static str,
    },
    /// A duration that does not parse in the channel URI grammar
    /// ([`karyos_protocol::channel::parse_duration`]).
    InvalidDuration {
        /// The option.
        option: &'static str,
        /// The value as given.
        value: String,
        /// Why it does not parse.
        error: karyos_protocol::channel::DurationError,
    },
    /// The configuration file, or the io options over it, were refused.
    Config(ConfigError),
}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOption(option) => write!(f, "unknown option {option:?}; see --help"),
            Self::MissingValue(option) => write!(f, "option {option} needs a value"),
            Self::InvalidValue { option, value } => {
                write!(f, "invalid value {value:?} for {option}")
            }
            Self::Missing(option) => write!(f, "option {option} is required"),
            Self::Needs { option, needs } => write!(f, "option {option} needs {needs}"),
            Self::InvalidDuration {
                option,
                value,
                error,
            } => write!(f, "invalid duration {value:?} for {option}: {error}"),
            Self::Config(error) => write!(f, "configuration: {error}"),
        }
    }
}

impl std::error::Error for ArgsError {}

/// Parses the arguments after the program name.
///
/// # Errors
///
/// Returns [`ArgsError`] for an unknown option, a missing or invalid
/// value, or an absent `--dir`. `--help` wins over any error that follows
/// it, not over one before it.
pub fn parse<I>(args: I) -> Result<Command, ArgsError>
where
    I: IntoIterator<Item = OsString>,
{
    parse_with(args, &IoSchema::core())
}

/// [`parse`] with the I/O backends of `schema`: a driver binary built with
/// other backends (`karyosd-native`) passes the schema it registered them
/// in, and reads their tables from [`Options::io`] (R-CORE-43).
///
/// # Errors
///
/// As [`parse`].
pub fn parse_with<I>(args: I, schema: &IoSchema) -> Result<Command, ArgsError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut options = Options::new(PathBuf::new());
    let mut io = IoOptions::default();
    let mut dir = None;
    let mut archive = Archive::default();
    let mut sizing = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| ArgsError::UnknownOption(arg.to_string_lossy().into_owned()))?;
        if text == "-h" || text == "--help" {
            return Ok(Command::Help);
        }
        if text == "--sizing-report" {
            sizing = true;
            continue;
        }
        if text == "--archive-time-evidence" {
            archive.time_evidence = true;
            continue;
        }
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(OsString::from(value))),
            _ => (text, None),
        };
        let option = known(name).ok_or_else(|| ArgsError::UnknownOption(text.to_owned()))?;
        let value = inline
            .or_else(|| args.next())
            .ok_or(ArgsError::MissingValue(option))?;
        if option == "--dir" {
            dir = Some(PathBuf::from(value));
            continue;
        }
        if option == "--archive" {
            archive.dir = Some(PathBuf::from(value));
            continue;
        }
        if option == "--config" {
            io.file = Some(PathBuf::from(value));
            continue;
        }
        let value = value
            .into_string()
            .map_err(|value| ArgsError::InvalidValue {
                option,
                value: value.to_string_lossy().into_owned(),
            })?;
        if matches!(
            option,
            "--archive-seal-interval" | "--archive-anchor-interval" | "--archive-retain-for"
        ) {
            let parsed = karyos_protocol::channel::parse_duration(&value).map_err(|error| {
                ArgsError::InvalidDuration {
                    option,
                    value: value.clone(),
                    error,
                }
            })?;
            if parsed.is_zero() {
                return Err(ArgsError::InvalidValue { option, value });
            }
            if option == "--archive-seal-interval" {
                archive.seal_interval = Some(parsed);
            } else if option == "--archive-retain-for" {
                archive.retain_for = Some(parsed);
            } else {
                archive.anchor_interval = Some(parsed);
            }
            continue;
        }
        if option == "--idle-image-timeout" {
            let parsed = karyos_protocol::channel::parse_duration(&value).map_err(|error| {
                ArgsError::InvalidDuration {
                    option,
                    value: value.clone(),
                    error,
                }
            })?;
            options.idle_image_timeout = Some(parsed);
            continue;
        }
        let applied = match option {
            "--io-backend" => {
                io.backend = Some(value.clone());
                Some(())
            }
            "--io-require" => {
                io.require.get_or_insert_with(Vec::new).push(value.clone());
                Some(())
            }
            "--archive-control" => control(&value).map(|control| archive.control = Some(control)),
            "--record" => record(&value).map(|record| archive.records.push(record)),
            "--archive-min-free" => size(&value).map(|size| archive.min_free = Some(size)),
            "--archive-signer" => {
                archive.signer = Some(PathBuf::from(&value));
                Some(())
            }
            "--archive-signer-key" => crate::catalog_verify::hex32(&value)
                .ok()
                .map(|key| archive.signer_key = Some(key)),
            "--archive-trust" => {
                archive.trust = Some(PathBuf::from(&value));
                Some(())
            }
            "--archive-copy-location" => crate::catalog_verify::hex32(&value)
                .ok()
                .map(|location| archive.copy_location = Some(location)),
            "--archive-purge" => match value.as_str() {
                "manual" => Some(karyos_archive::integrity::retention::PurgeMode::Manual),
                "after-expiry" => {
                    Some(karyos_archive::integrity::retention::PurgeMode::AfterExpiry)
                }
                _ => None,
            }
            .map(|purge| archive.purge = Some(purge)),
            "--archive-min-copies" => value
                .parse::<std::num::NonZeroU32>()
                .ok()
                .map(|copies| archive.min_copies = Some(copies)),
            _ => apply(&mut options, option, &value),
        };
        applied.ok_or_else(|| ArgsError::InvalidValue {
            option,
            value: value.clone(),
        })?;
    }
    options.admission.dir = match dir {
        Some(dir) => dir,
        None if sizing => PathBuf::new(),
        None => return Err(ArgsError::Missing("--dir")),
    };
    configured(&options)?;
    timed_networks(&mut options)?;
    idle_image_timeout(&mut options)?;
    io_config(&mut options, schema, io).map_err(ArgsError::Config)?;
    options.archive = archive.finish()?;
    if sizing {
        return Ok(Command::SizingReport(Box::new(options)));
    }
    Ok(Command::Run(Box::new(options)))
}

/// The io options as given, applied once the arguments are parsed.
#[derive(Default)]
struct IoOptions {
    /// `--config`.
    file: Option<PathBuf>,
    /// `--io-backend`.
    backend: Option<String>,
    /// Every `--io-require`, in order.
    require: Option<Vec<String>>,
}

/// Reads `--config`, applies `--io-backend` and `--io-require` over it and
/// checks the result against `schema`. A configuration beyond the defaults
/// needs `--network on`. With the sockets backend selected, its table sets
/// the endpoint tables and `require` the capabilities every endpoint needs.
fn io_config(options: &mut Options, schema: &IoSchema, io: IoOptions) -> Result<(), ConfigError> {
    let mut config = match &io.file {
        Some(path) => schema.read(path)?,
        None => IoConfig::default(),
    };
    if let Some(backend) = io.backend {
        config.set_backend(backend);
    }
    if let Some(require) = io.require {
        config.set_require(require);
    }
    schema.check(&config)?;
    if config.is_configured() {
        let network = options
            .driver
            .network
            .as_mut()
            .ok_or(ConfigError::NetworkOff)?;
        if config.backend() == <SocketsBackend as IoBackend>::NAME {
            sockets(network, &config);
        }
    }
    options.io = config;
    Ok(())
}

/// Applies the sockets backend's table and `require` to `network`.
fn sockets(network: &mut karyos_driver::net::NetworkConfig, config: &IoConfig) {
    use std::num::NonZeroU16;

    if let Some(table) = config.table::<SocketsBackend>() {
        let tables = &mut network.endpoint_tables;
        for (value, field) in [
            (table.tx_slots, &mut tables.tx_slots),
            (table.max_queues, &mut tables.max_queues),
            (table.max_routes, &mut tables.max_routes),
        ] {
            if let Some(value) = value.and_then(NonZeroU16::new) {
                *field = value;
            }
        }
    }
    network.require = config
        .require()
        .iter()
        .filter_map(|name| crate::config::sockets_capability(name))
        .fold(
            karyos_io::sockets::endpoint::CapabilitySet::EMPTY,
            |set, capability| set.with(capability),
        );
}

/// Every option that takes a value.
const OPTIONS: &[&str] = &[
    "--config",
    "--io-backend",
    "--io-require",
    "--dir",
    "--max-pending-hellos",
    "--hello-timeout",
    "--max-outbound-per-client",
    "--fetch-deadline",
    "--max-exports-per-client",
    "--max-fetches-per-client",
    "--max-regions-per-fetch",
    "--max-fetch-bytes",
    "--max-tools",
    "--max-clients",
    "--max-streams",
    "--max-pending-per-client",
    "--max-hand-over",
    "--command-budget",
    "--cycles-between-drains",
    "--ring-capacity",
    "--broadcast-capacity",
    "--max-retained-generations",
    "--cutover-deadline",
    "--heartbeat-interval",
    "--client-liveness-timeout",
    "--counters-capacity",
    "--client-counters-capacity",
    "--max-counters-per-client",
    "--max-trace-points-per-client",
    "--max-trace-point-registrations-per-client",
    "--max-trace-point-copies",
    "--max-trace-journals",
    "--max-trace-journal-bytes",
    "--max-stream-bytes",
    "--trace-drain-budget",
    "--trace-mirror-records",
    "--sample-interval",
    "--error-log-records",
    "--loss-report-records",
    "--error-dedup-window",
    "--log-level",
    "--network",
    "--stream",
    "--conflation",
    "--guard",
    "--timed-network",
    "--idle-image-timeout",
    "--term-length",
    "--mtu",
    "--max-reserved",
    "--spare-slots",
    "--max-subscribers",
    "--claim-deadline",
    "--shutdown-linger",
    "--archive",
    "--archive-control",
    "--record",
    "--archive-min-free",
    "--archive-seal-interval",
    "--archive-anchor-interval",
    "--archive-signer",
    "--archive-signer-key",
    "--archive-trust",
    "--archive-copy-location",
    "--archive-retain-for",
    "--archive-purge",
    "--archive-min-copies",
];

/// The static name of a known option.
fn known(name: &str) -> Option<&'static str> {
    OPTIONS.iter().copied().find(|option| *option == name)
}

/// Sets `option` from `value`; `None` when the value is invalid.
fn apply(options: &mut Options, option: &str, value: &str) -> Option<()> {
    let driver = &mut options.driver;
    let admission = &mut options.admission;
    let terms = &mut options.terms;
    match option {
        "--max-pending-hellos" => admission.max_pending_hellos = count(value)?,
        "--hello-timeout" => admission.hello_timeout = nanos(value)?,
        "--max-outbound-per-client" => admission.max_outbound_per_client = count(value)?,
        "--fetch-deadline" => admission.fetch_deadline = nanos(value)?,
        "--max-exports-per-client" => admission.max_exports_per_client = count(value)?,
        "--max-fetches-per-client" => admission.max_fetches_per_client = count(value)?,
        "--max-regions-per-fetch" => admission.max_regions_per_fetch = count(value)?,
        "--max-fetch-bytes" => admission.max_fetch_bytes = size(value)?,
        "--max-tools" => admission.max_tools = count(value)?,
        "--max-clients" => driver.max_clients = count(value)?,
        "--max-streams" => driver.max_streams = count(value)?,
        "--max-pending-per-client" => driver.max_pending_per_client = count(value)?,
        "--max-hand-over" => driver.max_hand_over = count(value)?,
        "--command-budget" => driver.command_budget = count(value)?,
        "--cycles-between-drains" => driver.cycles_between_drains = count(value)?,
        "--ring-capacity" => driver.ring_capacity = usize::try_from(size(value)?).ok()?,
        "--broadcast-capacity" => {
            driver.broadcast_capacity = usize::try_from(size(value)?).ok()?;
        }
        "--max-retained-generations" => driver.max_retained_generations = count(value)?,
        "--cutover-deadline" => driver.cutover_deadline = nanos(value)?,
        "--heartbeat-interval" => driver.heartbeat_interval = nanos(value)?,
        "--client-liveness-timeout" => driver.client_liveness_timeout = nanos(value)?,
        "--counters-capacity" => driver.counters_capacity = count(value)?,
        "--client-counters-capacity" => driver.client_counters_capacity = count(value)?,
        "--max-counters-per-client" => driver.max_counters_per_client = count(value)?,
        "--max-trace-points-per-client" => driver.max_trace_points_per_client = count(value)?,
        "--max-trace-point-registrations-per-client" => {
            driver.max_trace_point_registrations_per_client = count(value)?;
        }
        "--max-trace-point-copies" => driver.max_trace_point_copies = count(value)?,
        "--max-trace-journals" => driver.max_trace_journals = count(value)?,
        "--max-trace-journal-bytes" => driver.max_trace_journal_bytes = size(value)?,
        "--max-stream-bytes" => {
            driver.max_stream_bytes = Some(size(value).filter(|bytes| *bytes > 0)?);
        }
        "--trace-drain-budget" => driver.trace_drain_budget = count(value)?,
        "--trace-mirror-records" => driver.trace_mirror_records = count(value)?,
        "--sample-interval" => driver.position_sample_interval = nanos(value)?,
        "--error-log-records" => driver.error_log_records = count(value)?,
        "--loss-report-records" => driver.loss_report_records = count(value)?,
        "--error-dedup-window" => driver.error_dedup_window = nanos(value)?,
        "--log-level" => options.log_level = level(value)?,
        "--network" => {
            driver.network = match value {
                "on" => Some(karyos_driver::net::NetworkConfig::default()),
                "off" => None,
                _ => return None,
            };
        }
        "--stream" => options.streams.push(stream(value)?),
        "--conflation" => options.conflations.push(conflation(value)?),
        "--guard" => options.guards.push(guard(value)?),
        "--timed-network" => options.timed_networks.push(timed_network(value)?),
        "--term-length" => terms.term_length = u32::try_from(size(value)?).ok()?,
        "--mtu" => terms.mtu = value.parse().ok()?,
        "--max-reserved" => terms.max_reserved = Some(u32::try_from(size(value)?).ok()?),
        "--spare-slots" => terms.spare_slots = value.parse().ok()?,
        "--max-subscribers" => terms.max_subscribers = value.parse().ok()?,
        "--claim-deadline" => terms.claim_deadline = nanos(value)?,
        "--shutdown-linger" => options.shutdown_linger = Duration::from_nanos(nanos(value)?),
        _ => return None,
    }
    Some(())
}

/// A live Archive, as `--live DIR=REQ,RESP` names it: the driver's
/// directory and the Archive's request and response streams there
/// (`quantstratum-docs: karyos/design/archive-host.md`, H4b and H6; the
/// shape of karyos-agent's `--archive`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveArchive {
    /// The driver's directory.
    pub dir: PathBuf,
    /// The Archive's request stream.
    pub requests: i32,
    /// The Archive's response stream.
    pub responses: i32,
}

/// Parses `value`, the value of `--live`, as `DIR=REQ,RESP`.
///
/// # Errors
///
/// [`ArgsError::InvalidValue`] for a value without `=` or `,`, an empty
/// directory, or a stream id that is not an `i32`.
pub fn parse_live(value: &str) -> Result<LiveArchive, ArgsError> {
    let invalid = || ArgsError::InvalidValue {
        option: "--live",
        value: value.to_owned(),
    };
    let (dir, streams) = value.rsplit_once('=').ok_or_else(invalid)?;
    let (requests, responses) = streams.split_once(',').ok_or_else(invalid)?;
    if dir.is_empty() {
        return Err(invalid());
    }
    Ok(LiveArchive {
        dir: PathBuf::from(dir),
        requests: requests.trim().parse().map_err(|_| invalid())?,
        responses: responses.trim().parse().map_err(|_| invalid())?,
    })
}

/// The command line of a diagnostic tool (`karyos-stat`,
/// `karyos-errors`): `--dir <path>` (required), `--interval <duration>`
/// (default 1 s, at least 1 ms) and one flag without a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolArgs {
    /// The driver's admission socket directory.
    pub dir: PathBuf,
    /// The period of repeated output.
    pub interval: Duration,
    /// Whether the tool's flag was given.
    pub flag: bool,
}

/// Parses a diagnostic tool's arguments after the program name, with
/// `flag` its one option without a value. `None` asks for the help text.
///
/// # Errors
///
/// As [`parse`]: an unknown option, a missing or invalid value, or an
/// absent `--dir`. `--help` wins over any error that follows it.
pub fn parse_tool<I>(args: I, flag: &'static str) -> Result<Option<ToolArgs>, ArgsError>
where
    I: IntoIterator<Item = OsString>,
{
    let (mut dir, mut interval, mut flagged) = (None, Duration::from_secs(1), false);
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| ArgsError::UnknownOption(arg.to_string_lossy().into_owned()))?;
        if text == "-h" || text == "--help" {
            return Ok(None);
        }
        if text == flag {
            flagged = true;
            continue;
        }
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(OsString::from(value))),
            _ => (text, None),
        };
        let option = ["--dir", "--interval"]
            .into_iter()
            .find(|option| *option == name)
            .ok_or_else(|| ArgsError::UnknownOption(text.to_owned()))?;
        let value = inline
            .or_else(|| args.next())
            .ok_or(ArgsError::MissingValue(option))?;
        if option == "--dir" {
            dir = Some(PathBuf::from(value));
            continue;
        }
        let invalid = |value: &OsString| ArgsError::InvalidValue {
            option,
            value: value.to_string_lossy().into_owned(),
        };
        interval = value
            .to_str()
            .and_then(nanos)
            .filter(|nanos| *nanos >= 1_000_000)
            .map(Duration::from_nanos)
            .ok_or_else(|| invalid(&value))?;
    }
    Ok(Some(ToolArgs {
        dir: dir.ok_or(ArgsError::Missing("--dir"))?,
        interval,
        flag: flagged,
    }))
}

/// `<stream_id>:<session_id>:<keys>:<value_capacity>:<journal_capacity>`,
/// the capacities sizes; none of the three is 0.
fn conflation(value: &str) -> Option<ConflationOption> {
    let mut parts = value.split(':');
    let option = ConflationOption {
        stream_id: parts.next()?.parse().ok()?,
        session_id: parts.next()?.parse().ok()?,
        keys: parts.next()?.parse().ok().filter(|keys| *keys > 0)?,
        value_capacity: size(parts.next()?).filter(|size| *size > 0)?,
        journal_capacity: size(parts.next()?).filter(|size| *size > 0)?,
    };
    parts.next().is_none().then_some(option)
}

/// `<name>:<stream_id>:<session_id>:<messages>`, a nonempty name and a
/// nonzero count.
fn guard(value: &str) -> Option<GuardOption> {
    let mut parts = value.split(':');
    let option = GuardOption {
        name: parts.next().filter(|name| !name.is_empty())?.to_owned(),
        stream_id: parts.next()?.parse().ok()?,
        session_id: parts.next()?.parse().ok()?,
        messages: parts
            .next()?
            .parse()
            .ok()
            .filter(|messages| *messages > 0)?,
    };
    parts.next().is_none().then_some(option)
}

/// Each `--conflation` and `--guard` names a stream a `--stream`
/// configures, and names it once.
fn configured(options: &Options) -> Result<(), ArgsError> {
    let streams: Vec<(i32, i32)> = options
        .streams
        .iter()
        .map(|stream| (stream.stream_id, stream.session_id))
        .collect();
    let named = options
        .conflations
        .iter()
        .map(|table| ("--conflation", (table.stream_id, table.session_id)))
        .chain(
            options
                .guards
                .iter()
                .map(|guard| ("--guard", (guard.stream_id, guard.session_id))),
        );
    let mut seen: Vec<(&'static str, (i32, i32))> = Vec::new();
    for (option, key) in named {
        if !streams.contains(&key) {
            return Err(ArgsError::Needs {
                option,
                needs: "a --stream of that stream and session",
            });
        }
        if seen.contains(&(option, key)) {
            return Err(ArgsError::InvalidValue {
                option,
                value: format!("{}:{} named twice", key.0, key.1),
            });
        }
        seen.push((option, key));
    }
    Ok(())
}

/// `--timed-network`'s `<stream_id>:<capacity>`: a capacity of at least 1
/// (the log checks it is a power of two).
fn timed_network(value: &str) -> Option<(i32, u32)> {
    let (stream_id, capacity) = value.split_once(':')?;
    let capacity: u32 = capacity.parse().ok()?;
    (capacity > 0).then_some((stream_id.parse().ok()?, capacity))
}

/// Sets `--idle-image-timeout` on the network configuration, whichever
/// order the options came in. The driver checks it against the image
/// liveness timeout when it starts.
fn idle_image_timeout(options: &mut Options) -> Result<(), ArgsError> {
    let Some(timeout) = options.idle_image_timeout else {
        return Ok(());
    };
    let Some(network) = options.driver.network.as_mut() else {
        return Err(ArgsError::Needs {
            option: "--idle-image-timeout",
            needs: "--network on",
        });
    };
    network.agents.idle_image_timeout =
        u64::try_from(timeout.as_nanos()).map_err(|_| ArgsError::InvalidValue {
            option: "--idle-image-timeout",
            value: format!("{timeout:?}"),
        })?;
    Ok(())
}

/// Applies `--timed-network` to the network's stream defaults: it needs
/// `--network on`, names no `--stream` (a configured stream is local, and
/// refuses a schedule ring), names each stream once and at most
/// `MAX_TIMED_NETWORK_STREAMS` streams.
fn timed_networks(options: &mut Options) -> Result<(), ArgsError> {
    use karyos_driver::net::{MAX_TIMED_NETWORK_STREAMS, TimedNetworkStream};

    if options.timed_networks.is_empty() {
        return Ok(());
    }
    let invalid = |value: String| ArgsError::InvalidValue {
        option: "--timed-network",
        value,
    };
    let Some(network) = options.driver.network.as_mut() else {
        return Err(ArgsError::Needs {
            option: "--timed-network",
            needs: "--network on",
        });
    };
    if options.timed_networks.len() > MAX_TIMED_NETWORK_STREAMS {
        return Err(invalid(format!(
            "{} streams, at most {MAX_TIMED_NETWORK_STREAMS}",
            options.timed_networks.len()
        )));
    }
    for (index, &(stream_id, schedule_capacity)) in options.timed_networks.iter().enumerate() {
        if options
            .streams
            .iter()
            .any(|stream| stream.stream_id == stream_id)
        {
            return Err(invalid(format!("{stream_id}: also a --stream")));
        }
        if options
            .timed_networks
            .iter()
            .take(index)
            .any(|(other, _)| *other == stream_id)
        {
            return Err(invalid(format!("{stream_id}: named twice")));
        }
        if let Some(slot) = network.stream_defaults.timed.get_mut(index) {
            *slot = Some(TimedNetworkStream {
                stream_id,
                schedule_capacity,
            });
        }
    }
    Ok(())
}

/// A decimal count.
fn count(value: &str) -> Option<usize> {
    value.parse().ok()
}

/// A size in bytes: a decimal integer, optionally followed by `k`, `m` or
/// `g` (powers of 1024).
fn size(value: &str) -> Option<u64> {
    let (digits, shift) = match value.as_bytes().last()? {
        b'k' | b'K' => (value.get(..value.len() - 1)?, 10),
        b'm' | b'M' => (value.get(..value.len() - 1)?, 20),
        b'g' | b'G' => (value.get(..value.len() - 1)?, 30),
        _ => (value, 0),
    };
    let base: u64 = digits.parse().ok()?;
    base.checked_mul(1u64 << shift)
}

/// A duration in nanoseconds: a decimal integer followed by `ns`, `us`,
/// `ms` or `s`.
pub(crate) fn nanos(value: &str) -> Option<u64> {
    let (digits, scale) = if let Some(digits) = value.strip_suffix("ns") {
        (digits, 1)
    } else if let Some(digits) = value.strip_suffix("us") {
        (digits, 1_000)
    } else if let Some(digits) = value.strip_suffix("ms") {
        (digits, 1_000_000)
    } else {
        (value.strip_suffix('s')?, 1_000_000_000)
    };
    let base: u64 = digits.parse().ok()?;
    base.checked_mul(scale)
}

/// A log level name.
fn level(value: &str) -> Option<LogLevel> {
    Some(match value {
        "error" => LogLevel::Error,
        "warn" => LogLevel::Warn,
        "info" => LogLevel::Info,
        "debug" => LogLevel::Debug,
        "trace" => LogLevel::Trace,
        _ => return None,
    })
}

/// `<stream_id>:<session_id>[:allow-unconnected]`.
fn stream(value: &str) -> Option<StreamOption> {
    let mut parts = value.splitn(3, ':');
    let stream_id = parts.next()?.parse().ok()?;
    let session_id = parts.next()?.parse().ok()?;
    let allow_unconnected = match parts.next() {
        None => false,
        Some("allow-unconnected") => true,
        Some(_) => return None,
    };
    Some(StreamOption {
        stream_id,
        session_id,
        allow_unconnected,
    })
}

/// The Archive options as the command line gives them, in any order.
#[derive(Debug, Default)]
struct Archive {
    dir: Option<PathBuf>,
    control: Option<(i32, i32)>,
    records: Vec<RecordOption>,
    min_free: Option<u64>,
    seal_interval: Option<Duration>,
    anchor_interval: Option<Duration>,
    signer: Option<PathBuf>,
    signer_key: Option<[u8; 32]>,
    trust: Option<PathBuf>,
    copy_location: Option<[u8; 32]>,
    retain_for: Option<Duration>,
    purge: Option<karyos_archive::integrity::retention::PurgeMode>,
    min_copies: Option<std::num::NonZeroU32>,
    time_evidence: bool,
}

impl Archive {
    /// The Archive's settings: `--archive` with its `--archive-control`,
    /// or nothing when neither the agent nor a recording is asked for.
    fn finish(self) -> Result<Option<ArchiveOptions>, ArgsError> {
        let Some(dir) = self.dir else {
            if self.control.is_some() {
                return Err(ArgsError::Needs {
                    option: "--archive-control",
                    needs: "--archive",
                });
            }
            for (given, option) in [
                (!self.records.is_empty(), "--record"),
                (self.min_free.is_some(), "--archive-min-free"),
                (self.seal_interval.is_some(), "--archive-seal-interval"),
                (self.anchor_interval.is_some(), "--archive-anchor-interval"),
                (self.signer.is_some(), "--archive-signer"),
                (self.signer_key.is_some(), "--archive-signer-key"),
                (self.trust.is_some(), "--archive-trust"),
                (self.copy_location.is_some(), "--archive-copy-location"),
                (self.retain_for.is_some(), "--archive-retain-for"),
                (self.purge.is_some(), "--archive-purge"),
                (self.min_copies.is_some(), "--archive-min-copies"),
                (self.time_evidence, "--archive-time-evidence"),
            ] {
                if given {
                    return Err(ArgsError::Needs {
                        option,
                        needs: "--archive",
                    });
                }
            }
            return Ok(None);
        };
        let (requests, responses) = self.control.ok_or(ArgsError::Needs {
            option: "--archive",
            needs: "--archive-control",
        })?;
        // No default: an Archive whose heads are never anchored is refused
        // rather than started with an interval nobody chose.
        let anchor_interval = self.anchor_interval.ok_or(ArgsError::Needs {
            option: "--archive",
            needs: "--archive-anchor-interval",
        })?;
        let retention = retention(
            self.retain_for,
            self.purge,
            self.min_copies,
            self.copy_location.is_some(),
        )?;
        // The signer, its key and the trust file come together or not at
        // all.
        let signer = match (self.signer, self.signer_key, self.trust) {
            (None, None, None) => None,
            (Some(program), Some(public), Some(trust)) => Some(SignerOption {
                program,
                public,
                trust,
            }),
            (signer, key, _) => {
                return Err(ArgsError::Needs {
                    option: if signer.is_some() {
                        "--archive-signer"
                    } else if key.is_some() {
                        "--archive-signer-key"
                    } else {
                        "--archive-trust"
                    },
                    needs: if signer.is_none() {
                        "--archive-signer"
                    } else if key.is_none() {
                        "--archive-signer-key"
                    } else {
                        "--archive-trust"
                    },
                });
            }
        };
        Ok(Some(ArchiveOptions {
            dir,
            requests,
            responses,
            records: self.records,
            min_free: self.min_free.unwrap_or(DEFAULT_ARCHIVE_MIN_FREE),
            seal_interval: self.seal_interval.unwrap_or(DEFAULT_ARCHIVE_SEAL_INTERVAL),
            anchor_interval,
            signer,
            copy_location: self.copy_location,
            retention,
            time_evidence: self.time_evidence,
        }))
    }
}

/// The retention policy: `--archive-retain-for`, `--archive-purge` and
/// `--archive-min-copies` together or not at all, with
/// `--archive-copy-location` (`located`; karyos#1093). Policy 1, version 1,
/// tier 0: the one policy this Archive applies to every recording.
fn retention(
    retain_for: Option<Duration>,
    purge: Option<karyos_archive::integrity::retention::PurgeMode>,
    min_copies: Option<std::num::NonZeroU32>,
    located: bool,
) -> Result<Option<karyos_archive::integrity::retention::RetentionPolicy>, ArgsError> {
    {
        let (retain_for, purge, min_copies) = match (retain_for, purge, min_copies) {
            (None, None, None) => return Ok(None),
            (Some(retain_for), Some(purge), Some(min_copies)) => (retain_for, purge, min_copies),
            (retain_for, purge, _) => {
                let given = |is: bool, option| is.then_some(option);
                let option = given(retain_for.is_some(), "--archive-retain-for")
                    .or(given(purge.is_some(), "--archive-purge"))
                    .unwrap_or("--archive-min-copies");
                let needs = given(retain_for.is_none(), "--archive-retain-for")
                    .or(given(purge.is_none(), "--archive-purge"))
                    .unwrap_or("--archive-min-copies");
                return Err(ArgsError::Needs { option, needs });
            }
        };
        if !located {
            return Err(ArgsError::Needs {
                option: "--archive-retain-for",
                needs: "--archive-copy-location",
            });
        }
        let retain_for_ns =
            u64::try_from(retain_for.as_nanos()).map_err(|_| ArgsError::InvalidValue {
                option: "--archive-retain-for",
                value: format!("{retain_for:?}"),
            })?;
        Ok(Some(
            karyos_archive::integrity::retention::RetentionPolicy {
                policy: 1,
                version: 1,
                retain_for_ns,
                min_copies,
                storage_tier: 0,
                purge,
            },
        ))
    }
}

/// `<req>,<resp>`: two distinct stream ids.
fn control(value: &str) -> Option<(i32, i32)> {
    let (requests, responses) = value.split_once(',')?;
    let (requests, responses) = (requests.parse().ok()?, responses.parse().ok()?);
    (requests != responses).then_some((requests, responses))
}

/// `<stream_id>:<session_id>[:<sync>]`, the sync `none`, `segment` or a
/// duration (`Every`), `segment` by default.
fn record(value: &str) -> Option<RecordOption> {
    use karyos_archive::segment::SyncPolicy;

    let mut parts = value.splitn(3, ':');
    let stream_id = parts.next()?.parse().ok()?;
    let session_id = parts.next()?.parse().ok()?;
    let sync = match parts.next() {
        None | Some("segment") => SyncPolicy::PerSegment,
        Some("none") => SyncPolicy::None,
        Some(interval) => SyncPolicy::Every {
            interval_ns: nanos(interval).filter(|nanos| *nanos > 0)?,
        },
    };
    Some(RecordOption {
        stream_id,
        session_id,
        sync,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Command, ArgsError> {
        parse(args.iter().map(OsString::from))
    }

    fn options(args: &[&str]) -> Options {
        match run(args).unwrap() {
            Command::Run(options) => *options,
            Command::Help | Command::SizingReport(_) => panic!("expected options"),
        }
    }

    #[test]
    fn the_sizing_report_needs_no_directory_and_keeps_the_options() {
        match run(&["--sizing-report", "--max-clients", "3"]).unwrap() {
            Command::SizingReport(options) => {
                assert_eq!(options.driver.max_clients, 3);
                assert_eq!(options.admission.dir, PathBuf::new());
            }
            other => panic!("expected a sizing report, got {other:?}"),
        }
        assert!(matches!(
            run(&["--dir", "/run/karyos", "--sizing-report"]).unwrap(),
            Command::SizingReport(_)
        ));
        assert_eq!(
            run(&["--max-clients", "3"]),
            Err(ArgsError::Missing("--dir"))
        );
    }

    #[test]
    fn the_directory_alone_gives_the_defaults() {
        let parsed = options(&["--dir", "/run/karyos"]);
        assert_eq!(parsed, Options::new(PathBuf::from("/run/karyos")));
        assert_eq!(parsed.driver, DriverConfig::default());
        assert_eq!(parsed.shutdown_linger, DEFAULT_SHUTDOWN_LINGER);
    }

    #[test]
    fn the_stream_cap_takes_a_size_and_refuses_zero() {
        assert_eq!(
            options(&["--dir", "/run/karyos"]).driver.max_stream_bytes,
            None
        );
        assert_eq!(
            options(&["--dir", "/run/karyos", "--max-stream-bytes", "4m"])
                .driver
                .max_stream_bytes,
            Some(4 << 20)
        );
        assert_eq!(
            options(&["--dir", "/run/karyos", "--max-stream-bytes=397568"])
                .driver
                .max_stream_bytes,
            Some(397_568)
        );
        assert!(matches!(
            run(&["--dir", "/run/karyos", "--max-stream-bytes", "0"]),
            Err(ArgsError::InvalidValue {
                option: "--max-stream-bytes",
                ..
            })
        ));
    }

    #[test]
    fn every_option_sets_its_field() {
        let parsed = options(&[
            "--dir=/tmp/k",
            "--max-clients",
            "3",
            "--max-streams=5",
            "--ring-capacity",
            "4k",
            "--broadcast-capacity",
            "1m",
            "--heartbeat-interval",
            "50ms",
            "--client-liveness-timeout",
            "2s",
            "--sample-interval",
            "250us",
            "--error-log-records",
            "8",
            "--loss-report-records",
            "9",
            "--error-dedup-window",
            "10ns",
            "--max-trace-journal-bytes",
            "2g",
            "--hello-timeout",
            "1s",
            "--max-tools",
            "2",
            "--max-fetch-bytes",
            "64k",
            "--stream",
            "10:1",
            "--stream=-2:7:allow-unconnected",
            "--term-length",
            "128k",
            "--mtu",
            "1024",
            "--max-reserved",
            "8k",
            "--spare-slots",
            "1",
            "--max-subscribers",
            "8",
            "--claim-deadline",
            "3ms",
            "--shutdown-linger",
            "200ms",
            "--log-level",
            "debug",
        ]);
        assert_eq!(parsed.admission.dir, PathBuf::from("/tmp/k"));
        assert_eq!(parsed.driver.max_clients, 3);
        assert_eq!(parsed.driver.max_streams, 5);
        assert_eq!(parsed.driver.ring_capacity, 4096);
        assert_eq!(parsed.driver.broadcast_capacity, 1 << 20);
        assert_eq!(parsed.driver.heartbeat_interval, 50_000_000);
        assert_eq!(parsed.driver.client_liveness_timeout, 2_000_000_000);
        assert_eq!(parsed.driver.position_sample_interval, 250_000);
        assert_eq!(parsed.driver.error_log_records, 8);
        assert_eq!(parsed.driver.loss_report_records, 9);
        assert_eq!(parsed.driver.error_dedup_window, 10);
        assert_eq!(parsed.driver.max_trace_journal_bytes, 2 << 30);
        assert_eq!(parsed.admission.hello_timeout, 1_000_000_000);
        assert_eq!(parsed.admission.max_tools, 2);
        assert_eq!(parsed.admission.max_fetch_bytes, 65_536);
        assert_eq!(
            parsed.streams,
            [
                StreamOption {
                    stream_id: 10,
                    session_id: 1,
                    allow_unconnected: false,
                },
                StreamOption {
                    stream_id: -2,
                    session_id: 7,
                    allow_unconnected: true,
                },
            ]
        );
        assert_eq!(
            parsed.terms,
            TermOptions {
                term_length: 128 * 1024,
                mtu: 1024,
                max_reserved: Some(8192),
                spare_slots: 1,
                max_subscribers: 8,
                claim_deadline: 3_000_000,
            }
        );
        assert_eq!(parsed.shutdown_linger, Duration::from_millis(200));
        assert_eq!(parsed.log_level, LogLevel::Debug);
    }

    /// Owner item 1 (karyos#638): `idle_image_timeout` from the command
    /// line, in the channel URI's duration grammar, before or after
    /// `--network on`, and refused without the network.
    #[test]
    fn the_idle_image_timeout_is_set_from_the_command_line() {
        use karyos_protocol::channel::DurationError;

        let timeout = |args: &[&str]| {
            options(args)
                .driver
                .network
                .map(|network| network.agents.idle_image_timeout)
        };
        assert_eq!(
            timeout(&["--dir", "/d", "--network", "on"]),
            Some(60_000_000_000)
        );
        assert_eq!(
            timeout(&[
                "--dir",
                "/d",
                "--idle-image-timeout",
                "90s",
                "--network",
                "on"
            ]),
            Some(90_000_000_000)
        );
        assert_eq!(
            timeout(&[
                "--dir",
                "/d",
                "--network=on",
                "--idle-image-timeout=15000ms"
            ]),
            Some(15_000_000_000)
        );
        assert_eq!(
            run(&[
                "--dir",
                "d",
                "--network",
                "on",
                "--idle-image-timeout",
                "90"
            ]),
            Err(ArgsError::InvalidDuration {
                option: "--idle-image-timeout",
                value: "90".to_owned(),
                error: DurationError::MissingUnit,
            })
        );
        assert_eq!(
            run(&["--dir", "d", "--idle-image-timeout", "90s"]),
            Err(ArgsError::Needs {
                option: "--idle-image-timeout",
                needs: "--network on"
            })
        );
        assert_eq!(
            run(&[
                "--dir",
                "d",
                "--idle-image-timeout",
                "90s",
                "--network",
                "off"
            ]),
            Err(ArgsError::Needs {
                option: "--idle-image-timeout",
                needs: "--network on"
            })
        );
    }

    /// `--network on` runs the network agents with the driver's default
    /// network configuration; `off`, the default, runs none.
    #[test]
    fn the_network_is_off_unless_turned_on() {
        let base = ["--dir", "/d"];
        assert_eq!(options(&base).driver.network, None);
        let on = options(&[base[0], base[1], "--network", "on"]);
        assert_eq!(
            on.driver.network,
            Some(karyos_driver::net::NetworkConfig::default())
        );
        let off = options(&[base[0], base[1], "--network=on", "--network", "off"]);
        assert_eq!(off.driver.network, None);
    }

    #[test]
    fn help_is_recognised_in_both_spellings() {
        assert_eq!(run(&["--help"]), Ok(Command::Help));
        assert_eq!(run(&["-h"]), Ok(Command::Help));
        assert_eq!(
            run(&["--dir", "/d", "--help", "--bogus"]),
            Ok(Command::Help)
        );
        assert!(HELP.contains("--shutdown-linger"));
        for option in OPTIONS {
            assert!(HELP.contains(option), "{option} is not in the help");
        }
    }

    #[test]
    fn invalid_arguments_are_errors() {
        assert_eq!(run(&[]), Err(ArgsError::Missing("--dir")));
        assert_eq!(
            run(&["--dir", "/d", "--bogus"]),
            Err(ArgsError::UnknownOption("--bogus".to_owned()))
        );
        assert_eq!(
            run(&["positional"]),
            Err(ArgsError::UnknownOption("positional".to_owned()))
        );
        assert_eq!(
            run(&["--dir", "/d", "--max-clients"]),
            Err(ArgsError::MissingValue("--max-clients"))
        );
        for (option, value) in [
            ("--max-clients", "-1"),
            ("--max-clients", "many"),
            ("--hello-timeout", "5"),
            ("--hello-timeout", "5h"),
            ("--shutdown-linger", "s"),
            ("--ring-capacity", "4x"),
            ("--max-fetch-bytes", "99999999999999g"),
            ("--term-length", "8g"),
            ("--spare-slots", "300"),
            ("--stream", "10"),
            ("--stream", "10:x"),
            ("--stream", "10:1:allow"),
            ("--stream", "10:1:allow-unconnected:x"),
            ("--log-level", "loud"),
            ("--network", "yes"),
        ] {
            assert_eq!(
                run(&["--dir", "/d", option, value]),
                Err(ArgsError::InvalidValue {
                    option: known(option).unwrap(),
                    value: value.to_owned()
                }),
                "{option} {value}"
            );
        }
    }

    #[test]
    fn errors_display_as_one_line() {
        for error in [
            ArgsError::UnknownOption("--x".to_owned()),
            ArgsError::MissingValue("--dir"),
            ArgsError::InvalidValue {
                option: "--mtu",
                value: "x".to_owned(),
            },
            ArgsError::Missing("--dir"),
        ] {
            assert!(!error.to_string().contains('\n'));
        }
    }

    /// H3 (archive-host.md): `--archive` with its control streams and
    /// boot recordings, each sync form, in any order.
    #[test]
    fn the_archive_options_parse() {
        use karyos_archive::segment::SyncPolicy;

        let parsed = options(&[
            "--record",
            "7:1",
            "--dir",
            "/run/k",
            "--archive=/var/archive",
            "--archive-control",
            "100,101",
            "--archive-anchor-interval",
            "3600s",
            "--record=8:2:none",
            "--record",
            "9:3:250ms",
            "--record",
            "10:4:segment",
        ]);
        let record = |stream_id, session_id, sync| RecordOption {
            stream_id,
            session_id,
            sync,
        };
        assert_eq!(
            parsed.archive,
            Some(ArchiveOptions {
                dir: PathBuf::from("/var/archive"),
                requests: 100,
                responses: 101,
                records: vec![
                    record(7, 1, SyncPolicy::PerSegment),
                    record(8, 2, SyncPolicy::None),
                    record(
                        9,
                        3,
                        SyncPolicy::Every {
                            interval_ns: 250_000_000
                        }
                    ),
                    record(10, 4, SyncPolicy::PerSegment),
                ],
                min_free: DEFAULT_ARCHIVE_MIN_FREE,
                seal_interval: DEFAULT_ARCHIVE_SEAL_INTERVAL,
                anchor_interval: Duration::from_secs(3600),
                signer: None,
                copy_location: None,
                retention: None,
                time_evidence: false,
            })
        );
        let guarded = options(&[
            "--dir",
            "d",
            "--archive",
            "a",
            "--archive-control",
            "1,2",
            "--archive-min-free=64m",
            "--archive-anchor-interval=600s",
            "--archive-seal-interval=250ms",
        ])
        .archive
        .unwrap();
        assert_eq!(guarded.min_free, 64 << 20);
        assert_eq!(guarded.anchor_interval, Duration::from_secs(600));
        assert_eq!(guarded.seal_interval, Duration::from_millis(250));
        assert_eq!(options(&["--dir", "/run/k"]).archive, None);
    }

    /// The head signer's three options come together (karyos#966).
    #[test]
    fn the_archive_signer_options_come_together() {
        let base = [
            "--dir",
            "d",
            "--archive",
            "a",
            "--archive-control",
            "1,2",
            "--archive-anchor-interval",
            "3600s",
        ];
        let key = "03".repeat(32);
        let with = |extra: &[&str]| {
            let mut all: Vec<&str> = base.to_vec();
            all.extend_from_slice(extra);
            run(&all)
        };
        let parsed = options(
            &[
                &base[..],
                &[
                    "--archive-signer",
                    "/usr/local/bin/sign-head",
                    "--archive-signer-key",
                    &key,
                    "--archive-trust",
                    "/etc/karyos/trust",
                ],
            ]
            .concat(),
        )
        .archive
        .unwrap();
        assert_eq!(
            parsed.signer,
            Some(SignerOption {
                program: PathBuf::from("/usr/local/bin/sign-head"),
                public: [3; 32],
                trust: PathBuf::from("/etc/karyos/trust"),
            })
        );
        assert!(matches!(
            with(&["--archive-signer", "/bin/s"]),
            Err(ArgsError::Needs {
                option: "--archive-signer",
                needs: "--archive-signer-key"
            })
        ));
        assert!(matches!(
            with(&["--archive-signer-key", &key, "--archive-trust", "t"]),
            Err(ArgsError::Needs {
                needs: "--archive-signer",
                ..
            })
        ));
        assert!(matches!(
            with(&["--archive-signer-key", "zz"]),
            Err(ArgsError::InvalidValue { .. })
        ));
    }

    /// The retention policy's three options come together, with the copy
    /// location (karyos#1093).
    #[test]
    fn the_archive_retention_options_come_together() {
        use karyos_archive::integrity::retention::{PurgeMode, RetentionPolicy};
        let base = [
            "--dir",
            "d",
            "--archive",
            "a",
            "--archive-control",
            "1,2",
            "--archive-anchor-interval",
            "3600s",
        ];
        let location = "05".repeat(32);
        let with = |extra: &[&str]| {
            let mut all: Vec<&str> = base.to_vec();
            all.extend_from_slice(extra);
            run(&all)
        };
        let policy = [
            "--archive-retain-for",
            "3600s",
            "--archive-purge",
            "after-expiry",
            "--archive-min-copies",
            "2",
        ];
        let parsed = options(
            &[
                &base[..],
                &policy[..],
                &["--archive-copy-location", &location],
            ]
            .concat(),
        )
        .archive
        .unwrap();
        assert_eq!(parsed.copy_location, Some([5; 32]));
        assert!(!parsed.time_evidence);
        // karyos#1137 review: never accepted without --archive.
        assert_eq!(
            run(&["--dir", "d", "--archive-time-evidence"]),
            Err(ArgsError::Needs {
                option: "--archive-time-evidence",
                needs: "--archive",
            })
        );
        // karyos#1137: a flag, no value.
        let kept = options(&[&base[..], &["--archive-time-evidence"]].concat())
            .archive
            .unwrap();
        assert!(kept.time_evidence);
        assert_eq!(
            parsed.retention,
            Some(RetentionPolicy {
                policy: 1,
                version: 1,
                retain_for_ns: 3_600_000_000_000,
                min_copies: std::num::NonZeroU32::new(2).unwrap(),
                storage_tier: 0,
                purge: PurgeMode::AfterExpiry,
            })
        );
        assert!(matches!(
            with(&policy),
            Err(ArgsError::Needs {
                needs: "--archive-copy-location",
                ..
            })
        ));
        assert!(matches!(
            with(&["--archive-retain-for", "3600s"]),
            Err(ArgsError::Needs {
                option: "--archive-retain-for",
                needs: "--archive-purge"
            })
        ));
        assert!(matches!(
            with(&["--archive-purge", "sometimes"]),
            Err(ArgsError::InvalidValue { .. })
        ));
        assert!(matches!(
            with(&["--archive-min-copies", "0"]),
            Err(ArgsError::InvalidValue { .. })
        ));
    }

    /// The Archive's options need each other, and their values are checked.
    #[test]
    fn the_archive_options_are_checked() {
        let needs = |option, needs| Err(ArgsError::Needs { option, needs });
        assert_eq!(
            run(&["--dir", "d", "--archive", "a"]),
            needs("--archive", "--archive-control")
        );
        // An unconfigured anchor_interval refuses to start the Archive.
        assert_eq!(
            run(&["--dir", "d", "--archive", "a", "--archive-control", "1,2"]),
            needs("--archive", "--archive-anchor-interval")
        );
        assert_eq!(
            run(&["--dir", "d", "--archive-anchor-interval", "3600s"]),
            needs("--archive-anchor-interval", "--archive")
        );
        assert_eq!(
            run(&["--dir", "d", "--archive-control", "1,2"]),
            needs("--archive-control", "--archive")
        );
        assert_eq!(
            run(&["--dir", "d", "--record", "1:2"]),
            needs("--record", "--archive")
        );
        assert_eq!(
            run(&["--dir", "d", "--archive-min-free", "1g"]),
            needs("--archive-min-free", "--archive")
        );
        for (option, value) in [
            ("--archive-control", "1"),
            ("--archive-control", "1,1"),
            ("--archive-control", "1,x"),
            ("--record", "1"),
            ("--record", "1:x"),
            ("--record", "1:2:sometimes"),
            ("--record", "1:2:0ms"),
            ("--archive-min-free", "lots"),
            ("--archive-anchor-interval", "0s"),
            ("--archive-seal-interval", "0ms"),
        ] {
            assert_eq!(
                run(&["--dir", "d", "--archive", "a", option, value]),
                Err(ArgsError::InvalidValue {
                    option,
                    value: value.to_owned()
                }),
                "{option} {value}"
            );
        }
        assert_eq!(
            ArgsError::Needs {
                option: "--record",
                needs: "--archive"
            }
            .to_string(),
            "option --record needs --archive"
        );
    }

    /// `--timed-network` (owner item 65) fills the network's timed streams,
    /// and is refused without `--network on`, for a malformed or zero
    /// capacity, a stream `--stream` configures, a stream named twice, or
    /// more than `MAX_TIMED_NETWORK_STREAMS`.
    #[test]
    fn the_timed_network_option_parses_and_is_checked() {
        use karyos_driver::net::{MAX_TIMED_NETWORK_STREAMS, TimedNetworkStream};

        let parsed = options(&[
            "--dir",
            "d",
            "--timed-network",
            "25:4",
            "--network",
            "on",
            "--timed-network=26:8",
        ]);
        assert_eq!(parsed.timed_networks, [(25, 4), (26, 8)]);
        let timed = parsed.driver.network.unwrap().stream_defaults.timed;
        assert_eq!(
            timed[..3],
            [
                Some(TimedNetworkStream {
                    stream_id: 25,
                    schedule_capacity: 4
                }),
                Some(TimedNetworkStream {
                    stream_id: 26,
                    schedule_capacity: 8
                }),
                None
            ]
        );
        let base = ["--dir", "d", "--network", "on", "--stream", "10:1"];
        let with = |extra: &[&str]| run(&[&base[..], extra].concat());
        for value in ["25", "25:0", "25:x", "x:4", "25:4:1"] {
            assert_eq!(
                with(&["--timed-network", value]),
                Err(ArgsError::InvalidValue {
                    option: "--timed-network",
                    value: value.to_owned()
                }),
                "{value}"
            );
        }
        assert_eq!(
            with(&["--timed-network", "10:4"]),
            Err(ArgsError::InvalidValue {
                option: "--timed-network",
                value: "10: also a --stream".to_owned()
            })
        );
        assert_eq!(
            with(&["--timed-network", "25:4", "--timed-network", "25:8"]),
            Err(ArgsError::InvalidValue {
                option: "--timed-network",
                value: "25: named twice".to_owned()
            })
        );
        let many: Vec<String> = (0..=MAX_TIMED_NETWORK_STREAMS)
            .flat_map(|stream| ["--timed-network".to_owned(), format!("{}:4", 30 + stream)])
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(matches!(
            with(&many),
            Err(ArgsError::InvalidValue {
                option: "--timed-network",
                ..
            })
        ));
        assert_eq!(
            run(&["--dir", "d", "--timed-network", "25:4"]),
            Err(ArgsError::Needs {
                option: "--timed-network",
                needs: "--network on"
            })
        );
    }

    /// `--conflation` and `--guard` parse into their configured stream's
    /// table and guard, and are refused for a malformed value, a stream no
    /// `--stream` configures, or a stream named twice.
    #[test]
    fn the_conflation_and_guard_options_parse_and_are_checked() {
        let base = ["--dir", "d", "--stream", "10:1", "--stream", "11:1"];
        let with = |extra: &[&str]| run(&[&base[..], extra].concat());
        let parsed = options(
            &[
                &base[..],
                &[
                    "--conflation",
                    "10:1:4:16:4k",
                    "--guard=orders:10:1:4",
                    "--guard",
                    "orders:11:1:8",
                ],
            ]
            .concat(),
        );
        assert_eq!(
            parsed.conflations,
            [ConflationOption {
                stream_id: 10,
                session_id: 1,
                keys: 4,
                value_capacity: 16,
                journal_capacity: 4096,
            }]
        );
        assert_eq!(
            parsed
                .guards
                .iter()
                .map(|guard| (guard.name.as_str(), guard.stream_id, guard.messages))
                .collect::<Vec<_>>(),
            [("orders", 10, 4), ("orders", 11, 8)]
        );
        for (option, value) in [
            ("--conflation", "10:1"),
            ("--conflation", "10:1:0:16:4k"),
            ("--conflation", "10:1:4:0:4k"),
            ("--conflation", "10:1:4:16:0"),
            ("--conflation", "10:1:4:16:4k:x"),
            ("--guard", ":10:1:4"),
            ("--guard", "orders:10:1:0"),
            ("--guard", "orders:10:1"),
            ("--guard", "orders:10:1:4:x"),
        ] {
            assert_eq!(
                with(&[option, value]),
                Err(ArgsError::InvalidValue {
                    option,
                    value: value.to_owned()
                }),
                "{option} {value}"
            );
        }
        let unconfigured = Err(ArgsError::Needs {
            option: "--guard",
            needs: "a --stream of that stream and session",
        });
        assert_eq!(with(&["--guard", "orders:12:1:4"]), unconfigured);
        assert_eq!(
            with(&["--conflation", "10:2:4:16:4k"]),
            Err(ArgsError::Needs {
                option: "--conflation",
                needs: "a --stream of that stream and session",
            })
        );
        assert_eq!(
            with(&["--guard", "a:10:1:4", "--guard", "b:10:1:4"]),
            Err(ArgsError::InvalidValue {
                option: "--guard",
                value: "10:1 named twice".to_owned()
            })
        );
        // A table and a guard may name the same stream.
        assert!(with(&["--conflation", "10:1:4:16:4k", "--guard", "a:10:1:4"]).is_ok());
    }

    /// A configuration file named for `test` in the temporary directory.
    fn config_file(test: &str, text: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("karyosd-{test}-{}.toml", std::process::id()));
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn the_config_file_sizes_the_endpoints_and_requires_their_capabilities() {
        use karyos_io::backend::Capability;
        use karyos_io::sockets::endpoint::CapabilitySet;

        let path = config_file(
            "sizes",
            "[io]\nrequire = [\"gso\"]\n[io.sockets]\ntx_slots = 512\nmax_routes = 32\n",
        );
        let file = path.to_str().unwrap();
        let parsed = options(&["--dir", "d", "--network", "on", "--config", file]);
        let network = parsed.driver.network.unwrap();
        assert_eq!(network.endpoint_tables.tx_slots.get(), 512);
        assert_eq!(
            network.endpoint_tables.max_queues,
            karyos_driver::net::EndpointTables::default().max_queues
        );
        assert_eq!(network.endpoint_tables.max_routes.get(), 32);
        assert_eq!(network.require, CapabilitySet::EMPTY.with(Capability::Gso));
        assert_eq!(parsed.io.require(), ["gso"]);
        // The command line overrides the file: any --io-require replaces
        // its list.
        let parsed = options(&[
            "--dir",
            "d",
            "--network",
            "on",
            "--config",
            file,
            "--io-require",
            "path-mtu",
            "--io-require",
            "dont-fragment",
        ]);
        assert_eq!(
            parsed.driver.network.unwrap().require,
            CapabilitySet::EMPTY
                .with(Capability::PathMtu)
                .with(Capability::DontFragment)
        );
        assert_eq!(
            run(&[
                "--dir",
                "d",
                "--network",
                "on",
                "--config",
                file,
                "--io-backend",
                "dpdk"
            ]),
            Err(ArgsError::Config(ConfigError::UnsupportedBackend {
                name: "dpdk".to_owned(),
                reason: crate::config::Unsupported::NativeOnly,
                available: vec!["sockets"],
            }))
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn the_io_configuration_needs_the_network() {
        let path = config_file("network", "[io.sockets]\ntx_slots = 64\n");
        let file = path.to_str().unwrap();
        assert_eq!(
            run(&["--dir", "d", "--config", file]),
            Err(ArgsError::Config(ConfigError::NetworkOff))
        );
        assert_eq!(
            run(&["--dir", "d", "--io-require", "gso"]),
            Err(ArgsError::Config(ConfigError::NetworkOff))
        );
        // A file that configures nothing beyond the defaults is accepted.
        let empty = config_file("empty", "");
        let parsed = options(&["--dir", "d", "--config", empty.to_str().unwrap()]);
        assert_eq!(parsed, Options::new(PathBuf::from("d")));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(empty).unwrap();
    }

    #[test]
    fn an_unreadable_or_invalid_config_file_is_refused() {
        assert!(matches!(
            run(&[
                "--dir",
                "d",
                "--network",
                "on",
                "--config",
                "/nonexistent/karyosd.toml"
            ]),
            Err(ArgsError::Config(ConfigError::Read { .. }))
        ));
        let path = config_file("invalid", "[net]\n");
        assert_eq!(
            run(&[
                "--dir",
                "d",
                "--network",
                "on",
                "--config",
                path.to_str().unwrap()
            ]),
            Err(ArgsError::Config(ConfigError::UnknownKey {
                key: "net".to_owned()
            }))
        );
        assert!(
            ArgsError::Config(ConfigError::NetworkOff)
                .to_string()
                .contains("--network on")
        );
        std::fs::remove_file(path).unwrap();
    }

    /// A binary built with other backends passes its schema, and reads its
    /// tables from the parsed options.
    #[test]
    fn a_registered_backend_is_selected_through_parse_with() {
        use crate::config::{IoBackend, TableError};

        struct Nic;
        #[derive(Debug, PartialEq, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NicTable {
            queues: u16,
        }
        impl IoBackend for Nic {
            const NAME: &'static str = "nic";
            type Table = NicTable;
            fn validate(_: &NicTable) -> Result<(), TableError> {
                Ok(())
            }
            fn capabilities() -> &'static [&'static str] {
                &[]
            }
        }

        let mut schema = IoSchema::core();
        schema.register::<Nic>().unwrap();
        let path = config_file("nic", "[io]\nbackend = \"nic\"\n[io.nic]\nqueues = 4\n");
        let args = [
            "--dir",
            "d",
            "--network",
            "on",
            "--config",
            path.to_str().unwrap(),
        ];
        let Command::Run(parsed) = parse_with(args.iter().map(OsString::from), &schema).unwrap()
        else {
            panic!("expected options");
        };
        assert_eq!(parsed.io.backend(), "nic");
        assert_eq!(parsed.io.table::<Nic>(), Some(&NicTable { queues: 4 }));
        // Not the sockets backend: its defaults stay.
        assert_eq!(
            parsed.driver.network.unwrap().endpoint_tables,
            karyos_driver::net::EndpointTables::default()
        );
        // The core schema refuses the same file, at the table it does not
        // know.
        assert_eq!(
            run(&args),
            Err(ArgsError::Config(ConfigError::UnknownKey {
                key: "io.nic".to_owned()
            }))
        );
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod tool_tests {
    use super::*;

    fn tool(args: &[&str]) -> Result<Option<ToolArgs>, ArgsError> {
        parse_tool(args.iter().map(OsString::from), "--once")
    }

    #[test]
    fn a_tool_command_line_parses_its_dir_interval_and_flag() {
        assert_eq!(
            tool(&["--dir", "/d"]),
            Ok(Some(ToolArgs {
                dir: PathBuf::from("/d"),
                interval: Duration::from_secs(1),
                flag: false,
            }))
        );
        assert_eq!(
            tool(&["--once", "--interval=250ms", "--dir=/d"]),
            Ok(Some(ToolArgs {
                dir: PathBuf::from("/d"),
                interval: Duration::from_millis(250),
                flag: true,
            }))
        );
        assert_eq!(tool(&["--dir", "/d", "--help", "--bogus"]), Ok(None));
        assert_eq!(tool(&[]), Err(ArgsError::Missing("--dir")));
        assert_eq!(
            tool(&["--follow"]),
            Err(ArgsError::UnknownOption("--follow".into()))
        );
        assert_eq!(tool(&["--dir"]), Err(ArgsError::MissingValue("--dir")));
        // Below 1 ms, or not a duration.
        for value in ["999us", "5", "fast"] {
            assert_eq!(
                tool(&["--dir", "/d", "--interval", value]),
                Err(ArgsError::InvalidValue {
                    option: "--interval",
                    value: value.into(),
                })
            );
        }
    }
}
