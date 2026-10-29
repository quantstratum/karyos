// SPDX-License-Identifier: Apache-2.0

//! `karyos-catalog` (SPEC §11; `quantstratum-docs:
//! karyos/design/archive-host.md`, H4 and H4b): an Archive's recordings.
//! `list DIR` reads the catalog offline and read only; `list --live` asks a
//! running Archive over its control streams. The logic is
//! [`karyos_tools::catalog`]. See `karyos-catalog --help`.

use std::io::Write;
use std::process::ExitCode;

use karyos_tools::catalog;

fn main() -> ExitCode {
    // R-CORE-33: `--versions` before anything else, touching no driver.
    if let Some(code) = karyos_tools::versions::intercept(std::env::args_os().skip(1)) {
        return code;
    }
    let mut args = std::env::args_os().skip(1);
    let command = args.next();
    match command.as_ref().map(|command| command.to_str()) {
        // A command that is not UTF-8 is no command: an error, not help.
        Some(None) => fail(&"an argument is not UTF-8"),
        Some(Some("list")) => ExitCode::from(catalog::run_list(
            args,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        )),
        None | Some(Some("-h" | "--help")) => {
            let _ = std::io::stdout().write_all(catalog::HELP.as_bytes());
            ExitCode::SUCCESS
        }
        Some(Some(_)) => fail(&"unknown subcommand (karyos-catalog --help lists them)"),
    }
}

/// Prints one error line and returns the error status.
fn fail(error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(std::io::stderr(), "karyos-catalog: {error}");
    ExitCode::from(catalog::EXIT_ERROR)
}
