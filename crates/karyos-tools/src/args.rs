// SPDX-License-Identifier: Apache-2.0

//! The command line of `karyosd`, parsed by hand over `std::env::args_os`
//! (`quantstratum-docs: karyos/design/observability-and-tools.md`,
//! Binaries).
//!
//! Every option takes one value, as `--name value` or `--name=value`.
//! Counts and sizes are decimal integers; a size may end in `k`, `m` or `g`
//! (powers of 1024). Durations are an integer followed by `ns`, `us`, `ms`
//! or `s`. Values are checked here only for their syntax and range; the
//! driver validates the configuration as a whole when it starts.

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use karyos_driver::DriverConfig;
use karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE;
use karyos_sys::sizing::DEFAULT_MTU;

/// The usage text of `karyosd --help`.
pub const HELP: &str = "\
karyosd: runs one dedicated Karyos driver (IPC mode, Linux).

Usage: karyosd --dir <path> [options]

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
  --ring-capacity <size>            bytes of each command ring [1k]
  --broadcast-capacity <size>       bytes of the broadcast buffer [16k]
  --max-retained-generations <n>    predecessor mappings per stream [2]
  --cutover-deadline <duration>     time a handle has to move to a successor [1s]
  --heartbeat-interval <duration>   driver heartbeat period [100ms]
  --client-liveness-timeout <duration>  silence before a client times out [10s]
  --counters-capacity <n>           cells of the counters region [1024]
  --client-counters-capacity <n>    cells of the client counters region [1024]
  --max-counters-per-client <n>     client counter cells per client [64]
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

Streams:
  --stream <stream_id>:<session_id> configure a stream at start; repeatable
  --term-length <size>              term length of every stream [1m]
  --mtu <n>                         frame bytes per fragment [1408]
  --max-reserved <size>             bytes one message may reserve [term length / 8]
  --spare-slots <n>                 spare slots beyond the three rotation slots [3]
  --max-subscribers <n>             subscriber registry capacity [4]
  --claim-deadline <duration>       commit deadline of claims [1s]

Shutdown:
  --shutdown-linger <duration>      time clients have to leave after SIGTERM or SIGINT [5s]

  -h, --help                        print this text

Exit status: 0 after an orderly shutdown with every client gone; 2 on a
configuration or startup error; 3 when clients were still attached at the
end of the shutdown linger.
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

/// A stream to configure at start: its wire stream id and session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamOption {
    /// Wire stream id.
    pub stream_id: i32,
    /// Session alias.
    pub session_id: i32,
}

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
    /// How long the shutdown waits for clients to leave.
    pub shutdown_linger: Duration,
    /// The control-path log verbosity.
    pub log_level: LogLevel,
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
            shutdown_linger: DEFAULT_SHUTDOWN_LINGER,
            log_level: LogLevel::Info,
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
    let mut options = Options::new(PathBuf::new());
    let mut dir = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| ArgsError::UnknownOption(arg.to_string_lossy().into_owned()))?;
        if text == "-h" || text == "--help" {
            return Ok(Command::Help);
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
        let value = value
            .into_string()
            .map_err(|value| ArgsError::InvalidValue {
                option,
                value: value.to_string_lossy().into_owned(),
            })?;
        apply(&mut options, option, &value).ok_or_else(|| ArgsError::InvalidValue {
            option,
            value: value.clone(),
        })?;
    }
    options.admission.dir = dir.ok_or(ArgsError::Missing("--dir"))?;
    Ok(Command::Run(Box::new(options)))
}

/// Every option that takes a value.
const OPTIONS: &[&str] = &[
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
    "--max-trace-journals",
    "--max-trace-journal-bytes",
    "--trace-drain-budget",
    "--trace-mirror-records",
    "--sample-interval",
    "--error-log-records",
    "--loss-report-records",
    "--error-dedup-window",
    "--log-level",
    "--stream",
    "--term-length",
    "--mtu",
    "--max-reserved",
    "--spare-slots",
    "--max-subscribers",
    "--claim-deadline",
    "--shutdown-linger",
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
        "--max-trace-journals" => driver.max_trace_journals = count(value)?,
        "--max-trace-journal-bytes" => driver.max_trace_journal_bytes = size(value)?,
        "--trace-drain-budget" => driver.trace_drain_budget = count(value)?,
        "--trace-mirror-records" => driver.trace_mirror_records = count(value)?,
        "--sample-interval" => driver.position_sample_interval = nanos(value)?,
        "--error-log-records" => driver.error_log_records = count(value)?,
        "--loss-report-records" => driver.loss_report_records = count(value)?,
        "--error-dedup-window" => driver.error_dedup_window = nanos(value)?,
        "--log-level" => options.log_level = level(value)?,
        "--stream" => options.streams.push(stream(value)?),
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
fn nanos(value: &str) -> Option<u64> {
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

/// A `<stream_id>:<session_id>` pair.
fn stream(value: &str) -> Option<StreamOption> {
    let (stream_id, session_id) = value.split_once(':')?;
    Some(StreamOption {
        stream_id: stream_id.parse().ok()?,
        session_id: session_id.parse().ok()?,
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
            Command::Help => panic!("expected options"),
        }
    }

    #[test]
    fn the_directory_alone_gives_the_defaults() {
        let parsed = options(&["--dir", "/run/karyos"]);
        assert_eq!(parsed, Options::new(PathBuf::from("/run/karyos")));
        assert_eq!(parsed.driver, DriverConfig::default());
        assert_eq!(parsed.shutdown_linger, DEFAULT_SHUTDOWN_LINGER);
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
            "--stream=-2:7",
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
                    session_id: 1
                },
                StreamOption {
                    stream_id: -2,
                    session_id: 7
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
            ("--log-level", "loud"),
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
}
