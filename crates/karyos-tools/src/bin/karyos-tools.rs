// SPDX-License-Identifier: Apache-2.0

//! `karyos-tools`: subcommands that read Karyos's files offline. The one
//! so far is `replay diff` (`quantstratum-docs:
//! karyos/design/recording-group-replay.md` section 10), whose logic is in
//! [`karyos_tools::replay`]. See `karyos-tools replay diff --help`.

use std::io::Write;
use std::process::ExitCode;

use karyos_tools::replay;

/// The usage text of `karyos-tools --help`.
const HELP: &str = "\
karyos-tools: subcommands that read Karyos's files offline.

Usage: karyos-tools replay diff ...   (see karyos-tools replay diff --help)
";

/// Exit status of a command-line error, as `replay diff` gives one.
const EXIT_ERROR: u8 = 3;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (command, sub) = (args.next(), args.next());
    match (text(command.as_ref()), text(sub.as_ref())) {
        // A command that is not UTF-8 is no command: an error, not help.
        (Some(None), _) | (_, Some(None)) => fail(&"an argument is not UTF-8"),
        (Some(Some("replay")), Some(Some("diff"))) => diff(args),
        (Some(Some("replay")), None | Some(Some("-h" | "--help"))) => {
            let _ = std::io::stdout().write_all(replay::HELP.as_bytes());
            ExitCode::SUCCESS
        }
        (None | Some(Some("-h" | "--help")), _) => {
            let _ = std::io::stdout().write_all(HELP.as_bytes());
            ExitCode::SUCCESS
        }
        _ => fail(&"unknown subcommand (karyos-tools --help lists them)"),
    }
}

/// An argument as text: `Some(None)` when it is not UTF-8.
fn text(arg: Option<&std::ffi::OsString>) -> Option<Option<&str>> {
    arg.map(|arg| arg.to_str())
}

fn diff(args: impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    let parsed = match replay::parse_diff(args) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => {
            let _ = std::io::stdout().write_all(replay::HELP.as_bytes());
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            return fail(&format_args!(
                "{error} (karyos-tools replay diff --help for the usage)"
            ));
        }
    };
    let report = replay::diff(&parsed);
    let output = if parsed.json {
        report.json()
    } else {
        report.text()
    };
    let _ = if matches!(report, replay::Report::Error { .. }) && !parsed.json {
        std::io::stderr().write_all(output.as_bytes())
    } else {
        std::io::stdout().write_all(output.as_bytes())
    };
    ExitCode::from(report.exit_code())
}

/// Prints one error line and returns status 3.
fn fail(error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(std::io::stderr(), "karyos-tools: {error}");
    ExitCode::from(EXIT_ERROR)
}
