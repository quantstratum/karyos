// SPDX-License-Identifier: Apache-2.0

//! `karyos-catalog list` (SPEC §11; `quantstratum-docs:
//! karyos/design/archive-host.md`, H4): an archive directory's recordings,
//! read offline from its catalog by [`karyos_archive::catalog::list`]
//! through a read-only disk, so it needs no running Archive and may run
//! beside one. A torn last record (one an Archive is appending, or a crash
//! left) is listed up to and reported as "maybe behind", never as an
//! error. Listing a running Archive over its control streams (`--live`)
//! is H4b.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::PathBuf;

use karyos_archive::catalog::{FailKind, Listing, Recording, StopReason, list};
use karyos_archive::disk::{ReadOnly, StdDisk};

use crate::replay::quoted;

/// The usage text of `karyos-catalog --help`.
pub const HELP: &str = "\\
karyos-catalog: an archive directory's recordings (SPEC.md section 11).

Usage: karyos-catalog list <dir> [--json]

  list <dir>    the recordings of the catalog in <dir>, read only: no
                running Archive is needed, and none is disturbed. A
                record still being written is left out and the listing
                says it may be behind
  --json        one JSON object instead of text
  -h, --help    print this text

Exit status: 0 listed (a directory with no catalog lists nothing); 2 an
error (arguments, I/O, a damaged catalog or another format version).
";

/// Exit status of an error.
pub const EXIT_ERROR: u8 = 2;

/// A parsed `list` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListArgs {
    /// The archive directory.
    pub dir: PathBuf,
    /// JSON output.
    pub json: bool,
}

/// Parses the arguments after `list`: `Ok(None)` for `--help`.
///
/// # Errors
///
/// The usage error, as text.
pub fn parse_list(args: impl IntoIterator<Item = OsString>) -> Result<Option<ListArgs>, String> {
    let (mut dir, mut json) = (None, false);
    for arg in args {
        match arg.to_str() {
            Some("-h" | "--help") => return Ok(None),
            Some("--json") => json = true,
            Some(option) if option.starts_with("--") => {
                return Err(format!("unknown option {option}"));
            }
            _ if dir.is_none() => dir = Some(PathBuf::from(arg)),
            _ => return Err("one directory, at most".to_owned()),
        }
    }
    let dir = dir.ok_or("no directory given")?;
    Ok(Some(ListArgs { dir, json }))
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
    }
}

fn channel(recording: &Recording) -> String {
    String::from_utf8_lossy(&recording.channel).into_owned()
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
            channel(recording),
            recording.start,
            if recording.required {
                "required"
            } else {
                "async"
            },
        );
        let _ = match recording.stop {
            None => writeln!(out, "recording"),
            Some(stop) => writeln!(
                out,
                "stopped at {} ({}{})",
                stop.position,
                reason(stop.reason),
                if stop.incomplete { ", incomplete" } else { "" }
            ),
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
        let _ = match recording.stop {
            None => write!(out, "null}}"),
            Some(stop) => write!(
                out,
                "{{\"position\":{},\"time_ns\":{},\"reason\":{},\"incomplete\":{}}}}}",
                stop.position,
                stop.time_ns,
                quoted(reason(stop.reason)),
                stop.incomplete
            ),
        };
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
    match list(ReadOnly(StdDisk), &parsed.dir) {
        Ok(listing) => {
            let output = if parsed.json {
                json(&parsed.dir, &listing)
            } else {
                text(&parsed.dir, &listing)
            };
            let _ = stdout.write_all(output.as_bytes());
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "karyos-catalog: {}: {error}", parsed.dir.display());
            EXIT_ERROR
        }
    }
}

#[cfg(test)]
mod tests;
