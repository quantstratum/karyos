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
    let command = args.next();
    let sub = args.next();
    match (
        command.as_deref().and_then(|c| c.to_str()),
        sub.as_deref().and_then(|s| s.to_str()),
    ) {
        (Some("replay"), Some("diff")) => diff(args),
        (None | Some("-h" | "--help"), _) => {
            let _ = std::io::stdout().write_all(HELP.as_bytes());
            ExitCode::SUCCESS
        }
        _ => fail(&"unknown subcommand (karyos-tools --help lists them)"),
    }
}

fn diff(args: impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    let parsed = match replay::parse_diff(args) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => {
            let _ = std::io::stdout().write_all(replay::HELP.as_bytes());
            return ExitCode::SUCCESS;
        }
        Err(error) => return fail(&error),
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
