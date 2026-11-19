// SPDX-License-Identifier: Apache-2.0

//! `karyos-catalog list` (SPEC §11; `quantstratum-docs:
//! karyos/design/archive-host.md`, H4): an Archive's recordings.
//!
//! - `list DIR` reads the catalog in DIR offline by
//!   [`karyos_archive::catalog::list`] through a read-only disk, so it
//!   needs no running Archive and may run beside one. A torn last record
//!   (one an Archive is appending, or a crash left) is listed up to and
//!   reported as "maybe behind", never as an error.
//! - `list --live DIR=REQ,RESP` (H4b) asks a running Archive over its
//!   control streams on the driver in DIR, with a [`RecordingLister`]
//!   ([`list_live`]); the connection is opened for the listing and closed
//!   after it, so it holds none of the Archive's requester slots.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use karyos_archive::catalog::{FailKind, Listing, Recording, Stop, StopReason, list};
use karyos_archive::client::connection::{ArchiveConnection, ControlStreams, Requests, Responses};
use karyos_archive::client::list::{
    ListPoll, ListedRecording, ListerConfig, Listing as LiveListing, RecordingLister,
};
use karyos_archive::client::{ControlRequests, ControlResponses};
use karyos_archive::control::RecordingState;
use karyos_archive::disk::{ReadOnly, StdDisk};
use karyos_client::{Client, Connection};

use crate::args::{LiveArchive, parse_live};
use crate::replay::quoted;
use crate::replay_live::{DEFAULT_TIMEOUT, LiveError};

/// The usage text of `karyos-catalog --help`.
pub const HELP: &str = "\
karyos-catalog: an Archive's recordings (SPEC.md section 11).

Usage: karyos-catalog list <dir> [--json]
       karyos-catalog list --live DIR=REQ,RESP [--timeout-ms N] [--json]
       karyos-catalog verify <dir> [--trust FILE] [--anchors HEX=DIR]... [--json]

  list <dir>     the recordings of the catalog in <dir>, read only: no
                 running Archive is needed, and none is disturbed. A
                 record still being written is left out and the listing
                 says it may be behind
  --live DIR=REQ,RESP
                 the recordings of the running Archive whose control
                 streams are REQ and RESP on the driver in DIR (Linux)
  --timeout-ms N how long to wait for the driver, and then for the
                 listing (default 5000)
  --json         one JSON object instead of text
  -h, --help     print this text
  verify <dir>   the integrity outcome of every range (SPEC.md section
                 8.4); karyos-catalog verify --help for its options

Exit status: 0 listed (a directory with no catalog lists nothing); 2 an
error (arguments, I/O, a damaged catalog or another format version, an
Archive that cannot be reached or refuses).
";

/// Exit status of an error.
pub const EXIT_ERROR: u8 = 2;

/// Where `list` reads the recordings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// The catalog in an archive directory, read offline.
    Offline(PathBuf),
    /// A running Archive (`--live`).
    Live(LiveArchive),
}

/// A parsed `list` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListArgs {
    /// Where the recordings are read.
    pub source: Source,
    /// JSON output.
    pub json: bool,
    /// How long `--live` waits for the driver, and then for the listing.
    pub timeout: Duration,
}

/// Parses the arguments after `list`: `Ok(None)` for `--help`.
///
/// # Errors
///
/// The usage error, as text.
pub fn parse_list(args: impl IntoIterator<Item = OsString>) -> Result<Option<ListArgs>, String> {
    let (mut dir, mut live, mut json, mut timeout) = (None, None, false, None);
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let Some(text) = arg.to_str() else {
            if dir.is_some() {
                return Err("one directory, at most".to_owned());
            }
            dir = Some(PathBuf::from(arg));
            continue;
        };
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_owned())),
            _ => (text, None),
        };
        let mut value = |option: &str| {
            inline
                .clone()
                .or_else(|| args.next().and_then(|value| value.into_string().ok()))
                .ok_or(format!("{option} needs a value"))
        };
        match name {
            "-h" | "--help" => return Ok(None),
            "--json" if inline.is_none() => json = true,
            "--live" => {
                live = Some(parse_live(&value("--live")?).map_err(|error| error.to_string())?);
            }
            "--timeout-ms" => {
                let given = value("--timeout-ms")?;
                let ms = given
                    .parse()
                    .map_err(|_| format!("invalid --timeout-ms {given}"))?;
                timeout = Some(Duration::from_millis(ms));
            }
            option if option.starts_with("--") => {
                return Err(format!("unknown option {text}"));
            }
            _ if dir.is_none() => dir = Some(PathBuf::from(text)),
            _ => return Err("one directory, at most".to_owned()),
        }
    }
    let source = match (dir, live) {
        (Some(dir), None) => Source::Offline(dir),
        (None, Some(live)) => Source::Live(live),
        (Some(_), Some(_)) => return Err("a directory or --live, not both".to_owned()),
        (None, None) => return Err("no directory given".to_owned()),
    };
    if timeout.is_some() && matches!(source, Source::Offline(_)) {
        return Err("--timeout-ms is for --live".to_owned());
    }
    Ok(Some(ListArgs {
        source,
        json,
        timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
    }))
}

/// A stop reason's name.
fn reason(reason: StopReason) -> &'static str {
    match reason {
        StopReason::Normal => "sealed",
        StopReason::Recovered => "recovered",
        StopReason::Empty => "empty",
        StopReason::Lapped => "lapped",
        StopReason::Stopped => "stopped",
        StopReason::Shutdown => "shutdown",
        StopReason::Failed(FailKind::Source) => "failed: source",
        StopReason::Failed(FailKind::RequiredLapped) => "failed: required lapped",
        StopReason::Failed(FailKind::Invalid) => "failed: invalid",
        // A reason a later Archive version decodes.
        _ => "unknown",
    }
}

fn channel(recording: &Recording) -> String {
    String::from_utf8_lossy(&recording.channel).into_owned()
}

/// A channel on one line of text: a control character or a backslash in
/// it is escaped as in a Rust string.
fn channel_line(channel: &str) -> String {
    let mut out = String::new();
    for c in channel.chars() {
        if c == '\\' || c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// The listing as text, one line per recording.
#[must_use]
pub fn text(dir: &std::path::Path, listing: &Listing) -> String {
    let mut out = String::new();
    if listing.missing {
        let _ = writeln!(out, "no catalog in {}: nothing recorded", dir.display());
        return out;
    }
    let _ = writeln!(
        out,
        "{} recording(s) in {}",
        listing.recordings.len(),
        dir.display()
    );
    for recording in &listing.recordings {
        let _ = write!(
            out,
            "{}  stream {}  session {}  channel {}  start {}  {}  ",
            recording.id,
            recording.stream_id,
            recording.session_id,
            channel_line(&channel(recording)),
            recording.start,
            if recording.required {
                "required"
            } else {
                "async"
            },
        );
        let _ = match &recording.stop {
            None => writeln!(out, "recording"),
            Some(stop) => writeln!(out, "{}", stopped_text(stop)),
        };
    }
    if let Some(offset) = listing.behind {
        let _ = writeln!(
            out,
            "maybe behind: the record at offset {offset} is incomplete (an Archive writing it, or a crash its next open cuts)"
        );
    }
    out
}

/// The listing as one JSON object.
#[must_use]
pub fn json(dir: &std::path::Path, listing: &Listing) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "{{\"dir\":{},\"missing\":{},\"behind\":{},\"recordings\":[",
        quoted(&dir.display().to_string()),
        listing.missing,
        listing
            .behind
            .map_or_else(|| "null".to_owned(), |offset| offset.to_string()),
    );
    for (index, recording) in listing.recordings.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"id\":{},\"stream_id\":{},\"session_id\":{},\"channel\":{},\"start\":{},\"start_time_ns\":{},\"required\":{},\"stop\":",
            recording.id,
            recording.stream_id,
            recording.session_id,
            quoted(&channel(recording)),
            recording.start,
            recording.start_time_ns,
            recording.required,
        );
        let _ = match &recording.stop {
            None => write!(out, "null}}"),
            Some(stop) => write!(out, "{}}}", stopped_json(stop)),
        };
    }
    out.push_str("]}\n");
    out
}

/// How a stopped recording is shown in text.
fn stopped_text(stop: &Stop) -> String {
    format!(
        "stopped at {} ({}{})",
        stop.position,
        reason(stop.reason),
        if stop.incomplete { ", incomplete" } else { "" }
    )
}

/// How a stopped recording is shown in JSON.
fn stopped_json(stop: &Stop) -> String {
    format!(
        "{{\"position\":{},\"time_ns\":{},\"reason\":{},\"incomplete\":{}}}",
        stop.position,
        stop.time_ns,
        quoted(reason(stop.reason)),
        stop.incomplete
    )
}

/// The recordings of the running Archive `live` names, listed through
/// `client` with a [`RecordingLister`]. The connection is opened for the
/// listing and closed after it, whatever the outcome. The whole listing is
/// waited for up to `timeout`.
///
/// The lister's requester id is this process's id, as `karyos-replay`'s
/// correlation ids are: run one listing at a time per process. Two at
/// once, or a retry while a timed-out listing's answers are still in
/// flight, share that id and its correlation ids, and could read each
/// other's answers.
///
/// # Errors
///
/// [`LiveError::Connect`] when the control streams cannot be reached,
/// [`LiveError::NoAnswer`] when the listing does not end within `timeout`,
/// and [`LiveError::Refused`] when the Archive refuses a page.
pub fn list_live<C: Connection>(
    client: &mut Client<C>,
    live: &LiveArchive,
    timeout: Duration,
) -> Result<LiveListing, LiveError>
where
    Requests<C::Terms>: ControlRequests,
    Responses<C::Terms>: ControlResponses,
{
    let (requests, responses) =
        ArchiveConnection::open(client, ControlStreams::new(live.requests, live.responses))
            .map_err(|error| LiveError::Connect(error.to_string()))?
            .into_transports();
    // This process's id tells its answers apart, as the replay client's
    // correlation ids do.
    let mut lister =
        RecordingLister::new(ListerConfig::new(std::process::id()), requests, responses);
    lister.start();
    let start = Instant::now();
    let listed = loop {
        let _ = client.poll();
        match lister.poll() {
            ListPoll::Done(listing) => break Ok(listing),
            ListPoll::Refused { code, message } => break Err(LiveError::Refused { code, message }),
            // Started above, so never idle; nothing more will come.
            ListPoll::Idle => break Err(LiveError::NoAnswer),
            _ => {}
        }
        if start.elapsed() >= timeout {
            break Err(LiveError::NoAnswer);
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let (requests, responses) = lister.into_transports();
    requests.close(client);
    responses.close(client);
    listed
}

/// A live recording's state in text.
fn state_text(recording: &ListedRecording) -> String {
    match &recording.state {
        RecordingState::Recording {
            written,
            incomplete,
        } => format!(
            "recording, written to {written}{}",
            if *incomplete { ", incomplete" } else { "" }
        ),
        RecordingState::Stopped(stop) => stopped_text(stop),
        // A state a later Archive version decodes.
        _ => "unknown".to_owned(),
    }
}

/// A live listing as text, one line per recording.
#[must_use]
pub fn live_text(live: &LiveArchive, listing: &LiveListing) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} recording(s) of the Archive on {} (control streams {}, {})",
        listing.recordings.len(),
        live.dir.display(),
        live.requests,
        live.responses
    );
    for recording in &listing.recordings {
        let _ = writeln!(
            out,
            "{}  stream {}  session {}  channel {}  start {}  {}",
            recording.recording_id,
            recording.stream_id,
            recording.session_id,
            channel_line(&recording.channel),
            recording.start,
            state_text(recording),
        );
    }
    if listing.left_out > 0 {
        let _ = writeln!(
            out,
            "{} more recording(s) left out (past the listing's bound)",
            listing.left_out
        );
    }
    out
}

/// A live listing as one JSON object.
#[must_use]
pub fn live_json(live: &LiveArchive, listing: &LiveListing) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "{{\"live\":{{\"dir\":{},\"requests\":{},\"responses\":{}}},\"left_out\":{},\"recordings\":[",
        quoted(&live.dir.display().to_string()),
        live.requests,
        live.responses,
        listing.left_out,
    );
    for (index, recording) in listing.recordings.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let state = match &recording.state {
            RecordingState::Recording {
                written,
                incomplete,
            } => format!("{{\"written\":{written},\"incomplete\":{incomplete}}}"),
            RecordingState::Stopped(stop) => stopped_json(stop),
            // A state a later Archive version decodes.
            _ => "\"unknown\"".to_owned(),
        };
        let (recording_state, stop) = match recording.state {
            RecordingState::Recording { .. } => (state, "null".to_owned()),
            RecordingState::Stopped(_) => ("null".to_owned(), state),
            _ => (state, "null".to_owned()),
        };
        let _ = write!(
            out,
            "{{\"id\":{},\"stream_id\":{},\"session_id\":{},\"channel\":{},\"start\":{},\"start_time_ns\":{},\"recording\":{recording_state},\"stop\":{stop}}}",
            recording.recording_id,
            recording.stream_id,
            recording.session_id,
            quoted(&recording.channel),
            recording.start,
            recording.start_time_ns,
        );
    }
    out.push_str("]}\n");
    out
}

/// Runs `list` on `args` (the arguments after `list`): prints the help,
/// the listing (to `stdout`) or the error (to `stderr`), and returns the
/// exit status.
pub fn run_list(
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> u8 {
    let parsed = match parse_list(args) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => {
            let _ = stdout.write_all(HELP.as_bytes());
            return 0;
        }
        Err(error) => {
            let _ = writeln!(
                stderr,
                "karyos-catalog: {error} (karyos-catalog --help for the usage)"
            );
            return EXIT_ERROR;
        }
    };
    let listed = match &parsed.source {
        Source::Offline(dir) => list(ReadOnly(StdDisk), dir)
            .map(|listing| {
                if parsed.json {
                    json(dir, &listing)
                } else {
                    text(dir, &listing)
                }
            })
            .map_err(|error| format!("{}: {error}", dir.display())),
        Source::Live(live) => crate::replay_live::connect(live, parsed.timeout)
            .and_then(|mut client| list_live(&mut client, live, parsed.timeout))
            .map(|listing| {
                if parsed.json {
                    live_json(live, &listing)
                } else {
                    live_text(live, &listing)
                }
            })
            .map_err(|error| error.to_string()),
    };
    match listed {
        Ok(output) => {
            let _ = stdout.write_all(output.as_bytes());
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "karyos-catalog: {error}");
            EXIT_ERROR
        }
    }
}

#[cfg(test)]
mod tests;
