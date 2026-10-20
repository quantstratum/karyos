// SPDX-License-Identifier: Apache-2.0

//! `karyos-replay` (SPEC §11; `quantstratum-docs:
//! karyos/design/archive-host.md`, H5): replay and output diff. Its one
//! subcommand so far is `diff`, the first difference between two
//! recording group journals, whose logic is [`karyos_tools::replay`];
//! `karyos-tools replay diff` stays as its alias. See
//! `karyos-replay diff --help`.

use std::io::Write;
use std::process::ExitCode;

use karyos_tools::replay;

/// The usage text of `karyos-replay --help`.
const HELP: &str = "\
karyos-replay: replay and output diff (SPEC.md section 11).

Usage: karyos-replay diff ...   (see karyos-replay diff --help)

`karyos-tools replay diff` is the same command.
";

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let command = args.next();
    match command.as_ref().map(|command| command.to_str()) {
        // A command that is not UTF-8 is no command: an error, not help.
        Some(None) => fail(&"an argument is not UTF-8"),
        Some(Some("diff")) => ExitCode::from(replay::run_diff(
            "karyos-replay diff",
            args,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        )),
        None | Some(Some("-h" | "--help")) => {
            let _ = std::io::stdout().write_all(HELP.as_bytes());
            ExitCode::SUCCESS
        }
        Some(Some(_)) => fail(&"unknown subcommand (karyos-replay --help lists them)"),
    }
}

/// Prints one error line and returns the error status.
fn fail(error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(std::io::stderr(), "karyos-replay: {error}");
    ExitCode::from(replay::EXIT_ERROR)
}
