// SPDX-License-Identifier: Apache-2.0

//! `karyosd`: one dedicated Karyos driver (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, Binaries). See `--help`.
//!
//! `SIGTERM` and `SIGINT` only set a flag (`signal_hook::flag`), which the
//! duty cycle loop polls. A configuration or startup error prints one line
//! on standard error, before the log subscriber exists, and exits with
//! status 2.

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use karyos_tools::args::{self, Command, LogLevel};
use karyos_tools::daemon::{self, Daemon, EXIT_STARTUP};
use signal_hook::consts::signal::{SIGINT, SIGTERM};

fn main() -> ExitCode {
    let options = match args::parse(std::env::args_os().skip(1)) {
        Ok(Command::Run(options)) => options,
        Ok(Command::Help) => {
            let _ = std::io::stdout().write_all(args::HELP.as_bytes());
            return ExitCode::SUCCESS;
        }
        Ok(Command::SizingReport(options)) => {
            return match daemon::sizing_report(&options) {
                Ok(report) => {
                    let _ = std::io::stdout().write_all(report.as_bytes());
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error),
            };
        }
        Err(error) => return fail(&error),
    };
    // Registered before the driver exists, so a signal during startup
    // starts the shutdown at once.
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [SIGTERM, SIGINT] {
        if let Err(error) = signal_hook::flag::register(signal, Arc::clone(&stop)) {
            return fail(&format_args!("signal handler registration failed: {error}"));
        }
    }
    let daemon = match Daemon::start(&options) {
        Ok(daemon) => daemon,
        Err(error) => return fail(&error),
    };
    let level = match options.log_level {
        LogLevel::Error => tracing::Level::ERROR,
        LogLevel::Warn => tracing::Level::WARN,
        LogLevel::Info => tracing::Level::INFO,
        LogLevel::Debug => tracing::Level::DEBUG,
        LogLevel::Trace => tracing::Level::TRACE,
    };
    let installed = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .try_init();
    if let Err(error) = installed {
        return fail(&format_args!("log subscriber installation failed: {error}"));
    }
    daemon.log_started(&options);
    ExitCode::from(daemon.run(&stop).code())
}

/// Prints the single startup error line and returns status 2.
fn fail(error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(std::io::stderr(), "karyosd: {error}");
    ExitCode::from(EXIT_STARTUP)
}
