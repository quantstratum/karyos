// SPDX-License-Identifier: Apache-2.0

//! `karyos-tools probe` (Linux; R-CORE-35): a driver's readiness for an
//! orchestrator's exec probe, read from its admission socket with
//! `karyos_client::probe::probe`. It maps no shared memory. It prints one
//! line, the state and its reason, and exits with a status the probe acts
//! on:
//!
//! | Exit | Meaning | Readiness probe | Liveness probe |
//! | --- | --- | --- | --- |
//! | 0 | ready | pass | pass |
//! | 1 | starting or recovering | fail | pass |
//! | 2 | not ready or failed | fail | fail on failed or terminal |
//! | 3 | unreachable, or no answer in time | fail | fail after several |
//! | 4 | incompatible driver | fail | fail |
//! | 5 | a refusal (too many probes at once) or a usage error | fail | pass |
//!
//! Expected use: every 5 s with `--timeout 1000`.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use karyos_client::probe::{ProbeError, ProbeReason, ProbeState, probe};

/// Ready.
pub const EXIT_READY: u8 = 0;
/// Starting or recovering.
pub const EXIT_WAIT: u8 = 1;
/// Not ready or failed.
pub const EXIT_NOT_READY: u8 = 2;
/// Unreachable, or no answer in time.
pub const EXIT_UNREACHABLE: u8 = 3;
/// A driver that does not serve this probe.
pub const EXIT_INCOMPATIBLE: u8 = 4;
/// A refusal or a usage error.
pub const EXIT_ERROR: u8 = 5;

/// The usage text of `karyos-tools probe --help`.
pub const HELP: &str = "\
karyos-tools probe: a driver's readiness, for an orchestrator's probe.

Usage: karyos-tools probe --dir <driver directory> [--timeout <ms>]

Prints the state and exits 0 ready, 1 starting or recovering, 2 not ready
or failed, 3 unreachable, 4 incompatible driver, 5 refused or usage error.
The default timeout is 1000 ms. It maps no shared memory.
";

/// Runs `karyos-tools probe` with `args`, writing its line to `out` and
/// errors to `err`; returns the exit status.
pub fn run(
    args: impl Iterator<Item = std::ffi::OsString>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let mut dir = None;
    let mut timeout = Duration::from_millis(1000);
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-h" | "--help") => {
                let _ = out.write_all(HELP.as_bytes());
                return EXIT_READY;
            }
            Some("--dir") => dir = args.next().map(PathBuf::from),
            Some("--timeout") => {
                match args
                    .next()
                    .and_then(|value| value.to_str()?.parse::<u64>().ok())
                    .filter(|ms| *ms > 0)
                {
                    Some(ms) => timeout = Duration::from_millis(ms),
                    None => return usage(err, "--timeout needs a positive number of ms"),
                }
            }
            _ => return usage(err, "unknown argument (karyos-tools probe --help)"),
        }
    }
    let Some(dir) = dir else {
        return usage(err, "--dir is required");
    };
    let (line, status) = match probe(&dir, timeout) {
        Ok(answer) => match answer.state {
            ProbeState::Ready => ("ready".to_owned(), EXIT_READY),
            ProbeState::Starting => ("starting".to_owned(), EXIT_WAIT),
            ProbeState::Recovering => ("recovering".to_owned(), EXIT_WAIT),
            ProbeState::NotReady(reason) => {
                (format!("not_ready {}", reason_name(reason)), EXIT_NOT_READY)
            }
            ProbeState::Failed(reason) => {
                (format!("failed {}", reason_name(reason)), EXIT_NOT_READY)
            }
            _ => ("incompatible driver".to_owned(), EXIT_INCOMPATIBLE),
        },
        Err(ProbeError::Unreachable(error)) => (format!("unreachable {error}"), EXIT_UNREACHABLE),
        Err(ProbeError::Timeout) => ("unreachable no answer in time".to_owned(), EXIT_UNREACHABLE),
        Err(ProbeError::Incompatible) => ("incompatible driver".to_owned(), EXIT_INCOMPATIBLE),
        Err(ProbeError::Refused { code }) => (format!("refused code {code}"), EXIT_ERROR),
        Err(_) => ("incompatible driver".to_owned(), EXIT_INCOMPATIBLE),
    };
    let _ = writeln!(out, "{line}");
    status
}

/// The name of `reason` in the printed line.
fn reason_name(reason: ProbeReason) -> &'static str {
    match reason {
        ProbeReason::NotAdmitting => "not_admitting",
        ProbeReason::Full => "full",
        ProbeReason::Terminal => "terminal",
        ProbeReason::StartupDeadline => "startup_deadline",
        _ => "unknown",
    }
}

/// Prints a usage error and returns [`EXIT_ERROR`].
fn usage(err: &mut dyn Write, why: &str) -> u8 {
    let _ = writeln!(err, "karyos-tools probe: {why}");
    EXIT_ERROR
}
