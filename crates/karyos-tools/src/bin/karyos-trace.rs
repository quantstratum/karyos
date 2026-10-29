// SPDX-License-Identifier: Apache-2.0

//! `karyos-trace`: the trace report of a running Karyos driver
//! (`quantstratum-docs: karyos/design/trace-tool.md`). See `--help`.
//!
//! `SIGTERM` and `SIGINT` only set a flag (`signal_hook::flag`), which the
//! `--follow` loop polls. A usage error prints one line on standard error
//! and exits with status 1; a driver that cannot be attached exits with 2.

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use karyos_tools::trace::args::{self, Command};
use karyos_tools::trace::{EXIT_ATTACH, EXIT_USAGE, run};
use signal_hook::consts::signal::{SIGINT, SIGTERM};

fn main() -> ExitCode {
    // R-CORE-33: `--versions` before anything else, touching no driver.
    if let Some(code) = karyos_tools::versions::intercept(std::env::args_os().skip(1)) {
        return code;
    }
    let options = match args::parse(std::env::args_os().skip(1)) {
        Ok(Command::Run(options)) => options,
        Ok(Command::Help) => {
            let _ = std::io::stdout().write_all(args::HELP.as_bytes());
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "karyos-trace: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [SIGTERM, SIGINT] {
        if let Err(error) = signal_hook::flag::register(signal, Arc::clone(&stop)) {
            let _ = writeln!(
                std::io::stderr(),
                "karyos-trace: signal handler registration failed: {error}"
            );
            return ExitCode::from(EXIT_ATTACH);
        }
    }
    let status = run(
        &options,
        &stop,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(status)
}
