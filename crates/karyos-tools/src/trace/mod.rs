// SPDX-License-Identifier: Apache-2.0

//! `karyos-trace` (`quantstratum-docs: karyos/design/trace-tool.md`, issue
//! #97): attaches to a running driver as a tool (P7's tool attach, Linux),
//! reads its trace mirror and prints the trace report of
//! `trace-data-path.md` ("Journals and the report") and
//! `trace-attribution.md`.
//!
//! Its logic lives here so that it can be tested: the command line
//! ([`args`]), the mirror reader that feeds `karyos-trace`'s report
//! ([`mirror`]), the plain text output ([`output`]) and the run loop
//! ([`run`]). While any journal is open, expected sets are not frozen, so
//! the traces touching it are counted as provisional, in the one-shot
//! report as with `--follow`. `--follow` builds the report again from
//! everything the tool has read at each rescan and prints it whenever it
//! changed.

pub mod args;
pub mod mirror;
pub mod output;

use std::io::Write;
use std::sync::atomic::AtomicBool;

pub use args::Options;

/// Exit status after a report.
pub const EXIT_REPORT: u8 = 0;
/// Exit status on a usage error.
pub const EXIT_USAGE: u8 = 1;
/// Exit status when the driver cannot be attached.
pub const EXIT_ATTACH: u8 = 2;

/// Runs `karyos-trace` with `options`, printing the report on `out` and
/// errors on `err`, until the report is printed or, with `--follow`, until
/// the driver exits or `stop` is set (by `SIGINT` or `SIGTERM`). Returns
/// the exit status.
#[cfg(target_os = "linux")]
pub fn run(options: &Options, stop: &AtomicBool, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let mut tool = match karyos_client::tool::attach_tool(&options.dir, Duration::from_secs(5)) {
        Ok(tool) => tool,
        Err(error) => {
            let _ = writeln!(err, "karyos-trace: cannot attach to the driver: {error:?}");
            return EXIT_ATTACH;
        }
    };
    let mut mirror = mirror::MirrorTool::new(tool.instance());
    let mut last: Option<String> = None;
    let mut scan = 0u64;
    loop {
        // Whether the driver had exited before this scan: the scan then
        // shows its last state, and nothing follows.
        let ended = !options.follow || tool.driver_closed().unwrap_or(true);
        let _ = mirror.scan(tool.trace_mirror());
        scan += 1;
        let text = mirror
            .report()
            .map_err(|error| error.to_string())
            .and_then(|report| output::render(&mirror, &report).map_err(|e| e.to_string()));
        let text = match text {
            Ok(text) => text,
            Err(error) => {
                let _ = writeln!(err, "karyos-trace: cannot build the report: {error}");
                return EXIT_ATTACH;
            }
        };
        if last.as_ref() != Some(&text) {
            if options.follow {
                let _ = writeln!(out, "--- scan {scan}");
            }
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
            last = Some(text);
        }
        if ended || stop.load(Ordering::Relaxed) {
            return EXIT_REPORT;
        }
        // Waits for the interval, noticing an interrupt or the driver's
        // exit within a few milliseconds.
        let start = Instant::now();
        while start.elapsed() < options.interval {
            if stop.load(Ordering::Relaxed) || tool.driver_closed().unwrap_or(true) {
                break;
            }
            let left = options.interval.saturating_sub(start.elapsed());
            std::thread::sleep(left.min(Duration::from_millis(20)));
        }
    }
}

/// Tool attach needs Linux (`quantstratum-docs:
/// karyos/design/observability-and-tools.md`, "Tool attach"): off Linux the
/// driver cannot be attached.
#[cfg(not(target_os = "linux"))]
pub fn run(options: &Options, stop: &AtomicBool, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let _ = (options, stop, out);
    let _ = writeln!(
        err,
        "karyos-trace: cannot attach to the driver: tool attach needs Linux"
    );
    EXIT_ATTACH
}
