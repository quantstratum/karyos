// SPDX-License-Identifier: Apache-2.0

//! `karyos-replay diff`, and its alias `karyos-tools replay diff`: the
//! command line over [`karyos_archive::group::diff`], the public
//! comparison, which this module only parses for and prints
//! (R-CORE-49, karyos#919).
//! (`quantstratum-docs: karyos/design/recording-group-replay.md` section
//! 10; `karyos/design/archive-host.md`, H5): the first difference between
//! two recording group journals.
//!
//! It recovers both journals, compares their headers, then their events
//! in order over the range, record by record: the input event, each
//! observation, and the event's end. It reads only. Both journals are
//! recovered through [`ReadOnly`](karyos_archive::disk::ReadOnly), so one that recovery would repair (a
//! torn tail) is an error, never repaired; it opens no driver.
//!
//! The comparison is of records, never of payload bytes: a payload by
//! reference is compared as its reference, so the complete prefix is
//! bounded only by incomplete events and gap markers. A payload not
//! captured, or a reference unavailable, in the range is not comparable.
//!
//! Recorded checkpoints (template 30, A8-2) are compared as records,
//! matched by `group_seq`: their length, crc32c and format; a difference,
//! or a checkpoint on one side only, is the `state checkpoint` kind.
//! `--from-checkpoint <id>` opens the left journal at its checkpoint
//! `<id>` and the right one at its checkpoint with the same `group_seq`,
//! each through its store opened read only: what the store's recovery
//! would cut or mark lost reads as lost, so a damaged checkpoint is not
//! comparable.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::PathBuf;

use karyos_archive::disk::Disk;
// The comparison is the archive's public one (R-CORE-49, karyos#919):
// one implementation, which this command prints.
use karyos_archive::group::diff::DiffRequest;
pub use karyos_archive::group::diff::{CHECKPOINTS, Journal, Kind, Report};

#[cfg(test)]
mod tests;

/// The usage text of `<command> --help`, where `command` is how the diff
/// was named: `karyos-replay diff`, or its alias `karyos-tools replay
/// diff`.
#[must_use]
pub fn help(command: &str) -> String {
    let indent = " ".repeat("Usage: ".len() + command.len() + 1);
    format!(
        "\
{command}: the first difference between two recording group
journals (recording-group-replay.md section 10). It reads only.

Usage: {command} <left-dir> <left-group> <right-dir> <right-group>
{indent}[--from <seq>] [--to <seq>] [--json] [--accept-manifest]
{indent}[--from-checkpoint <id>]

  --from <seq>          the first group_seq compared [the first event]
  --to <seq>            the last group_seq compared [the end of the longer
                        complete prefix: an event on one side only is a
                        divergence; give --to for the shared prefix only]
  --json                one JSON object instead of text
  --accept-manifest     compare journals whose manifests differ
  --from-checkpoint <id>  compare from the event after the left journal's
                        checkpoint <id> and the right one's at its group_seq
                        (stores in <dir>/checkpoints; a replay capture has
                        none, so it is not comparable). The prefix is
                        recovered with the reopen hold the journal's header
                        records, as the run kept it
  -h, --help            print this text

Exit status: 0 identical over the range; 1 diverged, the first difference
reported; 2 not comparable; 3 error (arguments, I/O, or a journal that does
not recover read only).
"
    )
}

/// Exit status of a command-line error.
pub const EXIT_ERROR: u8 = 3;

/// Runs the diff command named `command` on `args` (the arguments after
/// `diff`): prints the help, the report (to `stdout`; an error report as
/// text to `stderr`) or the argument error (to `stderr`), and returns the
/// exit status.
pub fn run_diff(
    command: &str,
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> u8 {
    let parsed = match parse_diff(args) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => {
            let _ = stdout.write_all(help(command).as_bytes());
            return 0;
        }
        Err(error) => {
            let program = command.split(' ').next().unwrap_or(command);
            let _ = writeln!(
                stderr,
                "{program}: {error} ({command} --help for the usage)"
            );
            return EXIT_ERROR;
        }
    };
    let report = diff(&parsed);
    let output = if parsed.json {
        report.json()
    } else {
        report.text()
    };
    let _ = if matches!(report, Report::Error { .. }) && !parsed.json {
        stderr.write_all(output.as_bytes())
    } else {
        stdout.write_all(output.as_bytes())
    };
    report.exit_code()
}

/// A `replay diff` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffArgs {
    /// The expected journal.
    pub left: Journal,
    /// The journal compared with it.
    pub right: Journal,
    /// The first `group_seq` compared.
    pub from: Option<u64>,
    /// The last `group_seq` compared.
    pub to: Option<u64>,
    /// JSON output.
    pub json: bool,
    /// Compare journals whose manifests differ.
    pub accept_manifest: bool,
    /// Compare from the event after this checkpoint (A9 section 7), in
    /// the range it opens.
    pub from_checkpoint: Option<u64>,
}

impl DiffArgs {
    /// What the archive's [`diff`](karyos_archive::group::diff::diff)
    /// compares.
    #[must_use]
    pub fn request(&self) -> DiffRequest {
        DiffRequest {
            left: self.left.clone(),
            right: self.right.clone(),
            from: self.from,
            to: self.to,
            accept_manifest: self.accept_manifest,
            from_checkpoint: self.from_checkpoint,
        }
    }
}

/// Parses `replay diff`'s arguments, those after `replay diff`: `None`
/// for `--help`.
///
/// # Errors
///
/// What is wrong with them.
pub fn parse_diff(args: impl IntoIterator<Item = OsString>) -> Result<Option<DiffArgs>, String> {
    let mut positional = Vec::new();
    let (mut from, mut to, mut json, mut accept_manifest) = (None, None, false, false);
    let mut from_checkpoint = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| format!("not UTF-8: {}", arg.to_string_lossy()))?;
        match text {
            "-h" | "--help" => return Ok(None),
            "--json" => json = true,
            "--accept-manifest" => accept_manifest = true,
            "--from" | "--to" | "--from-checkpoint" => {
                let what = if text == "--from-checkpoint" {
                    "a checkpoint id"
                } else {
                    "a group_seq"
                };
                let value = args
                    .next()
                    .and_then(|value| value.to_str().map(str::to_owned))
                    .ok_or_else(|| format!("{text} needs {what}"))?;
                let seq = value
                    .parse::<u64>()
                    .map_err(|_| format!("{text}: not {what}: {value}"))?;
                match text {
                    "--from" => from = Some(seq),
                    "--to" => to = Some(seq),
                    _ => from_checkpoint = Some(seq),
                }
            }
            // Any dash but a lone one is an option; none other is known.
            option if option.starts_with('-') && option.len() > 1 => {
                return Err(format!("unknown option {option}"));
            }
            _ => positional.push(text.to_owned()),
        }
    }
    let [left_dir, left_group, right_dir, right_group] = <[String; 4]>::try_from(positional)
        .map_err(|found| {
            format!(
                "four arguments needed (two directories and their groups), found {}",
                found.len()
            )
        })?;
    let group = |text: &str| {
        text.parse::<u64>()
            .map_err(|_| format!("not a group id: {text}"))
    };
    if let (Some(from), Some(to)) = (from, to)
        && from > to
    {
        return Err(format!("--from {from} is past --to {to}"));
    }
    Ok(Some(DiffArgs {
        left: Journal {
            dir: PathBuf::from(left_dir),
            group: group(&left_group)?,
        },
        right: Journal {
            dir: PathBuf::from(right_dir),
            group: group(&right_group)?,
        },
        from,
        to,
        json,
        accept_manifest,
        from_checkpoint,
    }))
}

/// The command's output of a [`Report`]: its exit status, its text and
/// its JSON object.
pub trait ReportOutput {
    /// The exit status: 0, 1, 2 or 3.
    fn exit_code(&self) -> u8;
    /// The text output.
    fn text(&self) -> String;
    /// The `--json` output: one object.
    fn json(&self) -> String;
}

impl ReportOutput for Report {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Identical { .. } => 0,
            Self::Diverged { .. } => 1,
            Self::NotComparable { .. } => 2,
            // An error, or an outcome this tool does not know yet.
            _ => 3,
        }
    }

    fn text(&self) -> String {
        match self {
            Self::Identical {
                from,
                to: Some(to),
                events,
            } => format!("identical: group_seq {from} to {to}, {events} events\n"),
            Self::Identical { from, to: None, .. } => {
                format!("identical: no events from group_seq {from}\n")
            }
            Self::Diverged {
                group_seq,
                index,
                kind,
                expected,
                found,
            } => {
                let mut out = format!("diverged at group_seq {group_seq}");
                if let Some(index) = index {
                    let _ = write!(out, ", observation {index}");
                }
                let _ = write!(
                    out,
                    ": {}\n  expected: {expected}\n  found:    {found}\n",
                    kind.name()
                );
                out
            }
            Self::NotComparable { reason } => format!("not comparable: {reason}\n"),
            Self::Error { reason } => format!("error: {reason}\n"),
            _ => "error: an outcome this version does not know\n".to_owned(),
        }
    }

    fn json(&self) -> String {
        let null = || "null".to_owned();
        let (result, group_seq, index, kind, expected, found, reason) = match self {
            Self::Identical { .. } => ("identical", null(), null(), null(), null(), null(), null()),
            Self::Diverged {
                group_seq,
                index,
                kind,
                expected,
                found,
            } => (
                "diverged",
                group_seq.to_string(),
                index.map_or_else(null, |index| index.to_string()),
                quoted(kind.name()),
                quoted(expected),
                quoted(found),
                null(),
            ),
            Self::NotComparable { reason } => (
                "not_comparable",
                null(),
                null(),
                null(),
                null(),
                null(),
                quoted(reason),
            ),
            Self::Error { reason } => (
                "error",
                null(),
                null(),
                null(),
                null(),
                null(),
                quoted(reason),
            ),
            _ => (
                "error",
                null(),
                null(),
                null(),
                null(),
                null(),
                quoted("an outcome this version does not know"),
            ),
        };
        let mut out = format!(
            "{{\"result\":\"{result}\",\"group_seq\":{group_seq},\"index\":{index},\
             \"kind\":{kind},\"expected\":{expected},\"found\":{found},\"reason\":{reason}"
        );
        if let Self::Identical { from, to, events } = self {
            let to = to.map_or_else(null, |to| to.to_string());
            let _ = write!(out, ",\"from\":{from},\"to\":{to},\"events\":{events}");
        }
        out.push_str("}\n");
        out
    }
}

/// `text` as a JSON string.
pub(crate) fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Compares the journals `args` names on the operating system's files:
/// the archive's [`diff`](karyos_archive::group::diff::diff).
#[must_use]
pub fn diff(args: &DiffArgs) -> Report {
    karyos_archive::group::diff::diff(&args.request())
}

/// Compares the journals `args` names on `disk`.
#[must_use]
pub fn diff_on<D: Disk + Clone>(disk: D, args: &DiffArgs) -> Report {
    karyos_archive::group::diff::diff_on(disk, &args.request())
}
