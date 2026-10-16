// SPDX-License-Identifier: Apache-2.0

//! `karyos-stat`: a running driver's counters and stream positions
//! (`quantstratum-docs: karyos/design/observability-and-tools.md`,
//! Binaries). See `--help`.
//!
//! It attaches as a tool (read-only views of the diagnostic regions) and
//! prints a report every `--interval`, or once with `--once`, until the
//! driver's socket closes. The report is built by
//! [`karyos_tools::stat::report`].

use std::io::Write;
use std::process::ExitCode;

use karyos_tools::args::{self, ToolArgs};
use karyos_tools::stat;

/// Exit status of a command-line or attach error.
const EXIT_ERROR: u8 = 2;

fn main() -> ExitCode {
    match args::parse_tool(std::env::args_os().skip(1), stat::ONCE) {
        Ok(Some(options)) => run(&options),
        Ok(None) => {
            let _ = std::io::stdout().write_all(stat::HELP.as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error),
    }
}

#[cfg(target_os = "linux")]
fn run(options: &ToolArgs) -> ExitCode {
    use karyos_sys::host_clock::host_monotonic_ns;

    let mut tool = match karyos_client::tool::attach_tool(&options.dir, ATTACH_TIMEOUT) {
        Ok(tool) => tool,
        Err(error) => return fail(&format_args!("attach failed: {error}")),
    };
    let mut stdout = std::io::stdout();
    loop {
        let text = stat::report(tool.counters(), tool.client_counters(), host_monotonic_ns());
        // A closed standard output (a pipe whose reader left) ends the tool.
        if stdout.write_all(text.as_bytes()).is_err() || stdout.flush().is_err() {
            return ExitCode::SUCCESS;
        }
        if options.flag {
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(options.interval);
        match tool.driver_closed() {
            Ok(false) => {
                let _ = writeln!(stdout);
            }
            Ok(true) => return ExitCode::SUCCESS,
            Err(error) => return fail(&format_args!("driver connection failed: {error}")),
        }
    }
}

/// How long the attach waits for the driver.
#[cfg(target_os = "linux")]
const ATTACH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(not(target_os = "linux"))]
fn run(_options: &ToolArgs) -> ExitCode {
    fail(&"a tool attaches through the driver's admission socket, which exists on Linux only")
}

/// Prints one error line and returns status 2.
fn fail(error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(std::io::stderr(), "karyos-stat: {error}");
    ExitCode::from(EXIT_ERROR)
}
