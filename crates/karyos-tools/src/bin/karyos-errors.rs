// SPDX-License-Identifier: Apache-2.0

//! `karyos-errors`: a running driver's error log and loss report
//! (`quantstratum-docs: karyos/design/observability-and-tools.md`,
//! Binaries). See `--help`.
//!
//! It attaches as a tool and prints every retained record once; with
//! `--follow` it keeps printing new records and changed occurrence counts
//! every `--interval` until the driver's socket closes, after one last
//! poll. The records are formatted by [`karyos_tools::errors::Follower`].

use std::io::Write;
use std::process::ExitCode;

use karyos_tools::args::{self, ToolArgs};
use karyos_tools::errors;

/// Exit status of a command-line or attach error.
const EXIT_ERROR: u8 = 2;

fn main() -> ExitCode {
    match args::parse_tool(std::env::args_os().skip(1), errors::FOLLOW) {
        Ok(Some(options)) => run(&options),
        Ok(None) => {
            let _ = std::io::stdout().write_all(errors::HELP.as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error),
    }
}

#[cfg(target_os = "linux")]
fn run(options: &ToolArgs) -> ExitCode {
    let mut tool = match karyos_client::tool::attach_tool(&options.dir, ATTACH_TIMEOUT) {
        Ok(tool) => tool,
        Err(error) => return fail(&format_args!("attach failed: {error}")),
    };
    let mut stdout = std::io::stdout();
    let mut follower = errors::Follower::new();
    let mut first = true;
    loop {
        let closed = match tool.driver_closed() {
            Ok(closed) => closed,
            Err(error) => return fail(&format_args!("driver connection failed: {error}")),
        };
        let mut text = String::new();
        follower.poll(tool.error_log(), tool.loss_report(), &mut text);
        if first && text.is_empty() {
            text.push_str("no error or loss records\n");
        }
        first = false;
        // A closed standard output (a pipe whose reader left) ends the tool.
        if stdout.write_all(text.as_bytes()).is_err() || stdout.flush().is_err() {
            return ExitCode::SUCCESS;
        }
        // The mappings outlive the driver: the poll above read its last
        // state.
        if !options.flag || closed {
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(options.interval);
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
    let _ = writeln!(std::io::stderr(), "karyos-errors: {error}");
    ExitCode::from(EXIT_ERROR)
}
