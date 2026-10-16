// SPDX-License-Identifier: Apache-2.0

//! The command line of `karyos-trace`, parsed by hand over
//! `std::env::args_os` as `karyosd`'s (`quantstratum-docs:
//! karyos/design/trace-tool.md`, "The command", T3):
//! `karyos-trace --dir <admission directory> [--follow] [--interval <ms>]`.
//! An option with a value takes it as `--name value` or `--name=value`.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use crate::args::ArgsError;

/// The usage text of `karyos-trace --help`.
pub const HELP: &str = "\
karyos-trace: the trace report of a running Karyos driver (Linux).

Usage: karyos-trace --dir <path> [--follow] [--interval <ms>]

  --dir <path>        admission directory of the driver (required)
  --follow            rescan and print what changed until the driver exits
                      or the process is interrupted
  --interval <ms>     milliseconds between two rescans with --follow [1000]
  -h, --help          print this text

The report has one section per publication: its messages, the latency
from Publish to each SubscriberPoll (count, min, p50, p99, p99.9 and max,
each as an interval that holds its uncertainty, or unavailable) and the
traces that are complete, incomplete, provisional (a journal is still
open) or out of scope. A trace is complete only if its root Publish was
seen. Two final lines give the missed journals (journals created and
recycled between two rescans, which put the messages held then out of
scope) and the mirror loss with the journals excluded as malformed.

Exit status: 0 after a report; 1 on a usage error; 2 when the driver
cannot be attached.
";

/// The default interval between two rescans with `--follow`.
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(1000);

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print [`HELP`] and exit.
    Help,
    /// Report.
    Run(Options),
}

/// The parsed options of `karyos-trace`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The driver's admission directory.
    pub dir: PathBuf,
    /// Rescan until the driver exits or the process is interrupted.
    pub follow: bool,
    /// The interval between two rescans.
    pub interval: Duration,
}

/// Parses the arguments after the program name.
///
/// # Errors
///
/// Returns [`ArgsError`] for an unknown option, a missing or invalid
/// value (an interval must be a positive number of milliseconds), or an
/// absent `--dir`. `--help` wins over any error that follows it, not over
/// one before it.
pub fn parse<I>(args: I) -> Result<Command, ArgsError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut dir = None;
    let mut follow = false;
    let mut interval = DEFAULT_INTERVAL;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| ArgsError::UnknownOption(arg.to_string_lossy().into_owned()))?;
        match text {
            "-h" | "--help" => return Ok(Command::Help),
            "--follow" => {
                follow = true;
                continue;
            }
            _ => {}
        }
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(OsString::from(value))),
            _ => (text, None),
        };
        let option = match name {
            "--dir" => "--dir",
            "--interval" => "--interval",
            _ => return Err(ArgsError::UnknownOption(text.to_owned())),
        };
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
        let millis = value
            .to_str()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .ok_or_else(|| invalid(&value))?;
        interval = Duration::from_millis(millis);
    }
    Ok(Command::Run(Options {
        dir: dir.ok_or(ArgsError::Missing("--dir"))?,
        follow,
        interval,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Command, ArgsError> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn the_directory_alone_reports_once() {
        assert_eq!(
            run(&["--dir", "/run/karyos"]),
            Ok(Command::Run(Options {
                dir: PathBuf::from("/run/karyos"),
                follow: false,
                interval: DEFAULT_INTERVAL,
            }))
        );
    }

    #[test]
    fn follow_and_interval_are_set() {
        assert_eq!(
            run(&["--follow", "--dir=/d", "--interval", "250"]),
            Ok(Command::Run(Options {
                dir: PathBuf::from("/d"),
                follow: true,
                interval: Duration::from_millis(250),
            }))
        );
        assert_eq!(
            run(&["--dir", "/d", "--interval=5"]),
            Ok(Command::Run(Options {
                dir: PathBuf::from("/d"),
                follow: false,
                interval: Duration::from_millis(5),
            }))
        );
    }

    #[test]
    fn help_wins_over_what_follows() {
        assert_eq!(run(&["-h"]), Ok(Command::Help));
        assert_eq!(
            run(&["--dir", "/d", "--help", "--bogus"]),
            Ok(Command::Help)
        );
        for option in ["--dir", "--follow", "--interval"] {
            assert!(HELP.contains(option), "{option} is not in the help");
        }
    }

    #[test]
    fn invalid_arguments_are_errors() {
        assert_eq!(run(&[]), Err(ArgsError::Missing("--dir")));
        assert_eq!(run(&["--follow"]), Err(ArgsError::Missing("--dir")));
        assert_eq!(
            run(&["--dir", "/d", "--bogus"]),
            Err(ArgsError::UnknownOption("--bogus".to_owned()))
        );
        assert_eq!(run(&["/d"]), Err(ArgsError::UnknownOption("/d".to_owned())));
        assert_eq!(run(&["--dir"]), Err(ArgsError::MissingValue("--dir")));
        assert_eq!(
            run(&["--dir", "/d", "--interval"]),
            Err(ArgsError::MissingValue("--interval"))
        );
        for value in ["0", "-1", "1s", "x", ""] {
            assert_eq!(
                run(&["--dir", "/d", "--interval", value]),
                Err(ArgsError::InvalidValue {
                    option: "--interval",
                    value: value.to_owned()
                }),
                "{value}"
            );
        }
    }
}
