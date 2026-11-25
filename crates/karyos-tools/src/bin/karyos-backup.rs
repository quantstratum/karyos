// SPDX-License-Identifier: Apache-2.0

//! `karyos-backup`: a Cluster node's backup to remote storage, its check,
//! and a rebuild from it (karyos#717). See [`karyos_tools::backup::HELP`].

use std::io::Write;
use std::process::ExitCode;

/// Exit status of a usage or a command error.
const EXIT_ERROR: u8 = 2;

fn main() -> ExitCode {
    // R-CORE-33: `--versions` before anything else.
    if let Some(code) = karyos_tools::versions::intercept(std::env::args_os().skip(1)) {
        return code;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        let _ = std::io::stdout().write_all(karyos_tools::backup::HELP.as_bytes());
        return ExitCode::SUCCESS;
    }
    match karyos_tools::backup::run(&args) {
        Ok(out) => {
            if std::io::stdout().write_all(out.as_bytes()).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "karyos-backup: {error}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}
