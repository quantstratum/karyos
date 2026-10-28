// SPDX-License-Identifier: Apache-2.0

//! `karyosd --sizing-report` (Linux; R-CORE-34): it prints the report and
//! exits 0 without starting, and a running `karyosd` with the same options
//! stays within it.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use karyos_client::ipc::attach;

/// The options both the report and the running daemon get.
const OPTIONS: [&str; 6] = [
    "--stream",
    "2:1",
    "--term-length",
    "64k",
    "--log-level",
    "warn",
];

/// The resident set a running `karyosd` may hold beyond the report's
/// configured figure: 10 % of it plus this many bytes. The report covers
/// the shared regions only; the rest of the process (code, heap, thread
/// stacks, kernel socket buffers, all listed as excluded) is not in it, so
/// the margin bounds that remainder, which is a few MiB for a debug build.
const RSS_MARGIN_BYTES: u64 = 4 * 1024 * 1024;
/// The relative part of the margin, in percent of the configured figure.
const RSS_MARGIN_PERCENT: u64 = 10;

/// A `karyosd` process, killed when the test ends however it ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn report() -> String {
    let output = sizing(&[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// `karyosd --sizing-report` with [`OPTIONS`] and `extra`.
fn sizing(extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_karyosd"))
        .arg("--sizing-report")
        .args(OPTIONS)
        .args(extra)
        .output()
        .unwrap()
}

/// The number of bytes on the report line that starts with `label`.
fn figure(report: &str, label: &str) -> u64 {
    let line = report
        .lines()
        .find(|line| line.starts_with(label))
        .unwrap_or_else(|| panic!("no {label:?} line in {report}"));
    line[label.len()..]
        .trim()
        .trim_end_matches("bytes")
        .trim()
        .parse()
        .unwrap()
}

/// The `kB` value of `field` in `/proc/<pid>/<file>`, in bytes, summed over
/// the lines whose mapping matches `mapping` when it is given (smaps).
fn kilobytes(pid: u32, file: &str, field: &str, mapping: Option<&str>) -> u64 {
    let text = std::fs::read_to_string(format!("/proc/{pid}/{file}")).unwrap();
    let mut inside = mapping.is_none();
    let mut total = 0;
    for line in text.lines() {
        // A mapping's header in smaps starts with its address range.
        let header = line
            .split_whitespace()
            .next()
            .and_then(|range| range.split_once('-'))
            .is_some_and(|(low, _)| u64::from_str_radix(low, 16).is_ok());
        if header {
            inside = mapping.is_some_and(|mapping| line.contains(mapping));
            continue;
        }
        if inside && let Some(value) = line.strip_prefix(field).and_then(|v| v.strip_prefix(':')) {
            let kb: u64 = value.trim().trim_end_matches("kB").trim().parse().unwrap();
            total += kb * 1024;
        }
    }
    total
}

#[test]
fn the_sizing_report_prints_two_figures_and_exits_without_starting() {
    let report = report();
    let configured = figure(&report, "configured steady state:");
    let peak = figure(&report, "restart peak:");
    assert!(configured > 0 && configured < peak, "{report}");
    assert!(
        report.contains("bounded:                 none, max_stream_bytes is unset"),
        "no bounded figure without the cap: {report}"
    );
    assert!(
        report.contains("stream 2:1 (declared 0): log buffer"),
        "{report}"
    );
    assert!(
        report.contains("the restart peak assumes no reconfigure_stream"),
        "{report}"
    );
    assert!(report.contains("excluded:"), "{report}");
}

/// With `--max-stream-bytes` the report adds its bounded figures, which
/// need no assumption, and no longer excludes added streams (karyos#809);
/// a declared stream above the cap is refused as a start refuses it.
#[test]
fn with_the_stream_cap_the_report_is_bounded() {
    let output = sizing(&["--max-stream-bytes", "1m"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = String::from_utf8(output.stdout).unwrap();
    let configured = figure(&report, "configured steady state:");
    let bounded = figure(&report, "bounded steady state:");
    let peak = figure(&report, "bounded restart peak:");
    assert!(configured < bounded && bounded < peak, "{report}");
    assert!(
        !report.contains("streams added after start and Archive replay targets"),
        "{report}"
    );
    let refused = sizing(&["--max-stream-bytes", "4k"]);
    assert_eq!(refused.status.code(), Some(2), "{refused:?}");
}

/// With `--archive` the report counts the Archive's two control streams
/// and excludes replay targets, whose geometry no option bounds.
#[test]
fn with_the_archive_the_report_counts_its_control_streams() {
    let archive =
        std::env::temp_dir().join(format!("karyosd-sizing-archive-{}", std::process::id()));
    let output = sizing(&[
        "--archive",
        archive.to_str().unwrap(),
        "--archive-control",
        "10,11",
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        report.matches(": log buffer").count(),
        3,
        "the declared stream and the two control streams: {report}"
    );
    assert!(
        report.contains("- streams added after start and Archive replay targets"),
        "{report}"
    );
    assert!(!archive.exists(), "the report creates nothing");
}

/// A configuration the driver refuses is refused by the report too, with
/// the startup error's exit status.
#[test]
fn the_report_refuses_what_the_driver_refuses() {
    for extra in [
        &["--max-retained-generations", "0"][..],
        &["--max-streams", "0"],
        &["--stream", "2:1"],
    ] {
        let output = sizing(extra);
        assert_eq!(output.status.code(), Some(2), "{extra:?}: {output:?}");
        assert_eq!(String::from_utf8(output.stderr).unwrap().lines().count(), 1);
    }
}

#[test]
fn a_running_karyosd_stays_within_its_sizing_report() {
    let configured = figure(&report(), "configured steady state:");
    let dir: PathBuf = std::env::temp_dir().join(format!("karyosd-sizing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_karyosd"))
            .arg("--dir")
            .arg(&dir)
            .args(OPTIONS)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    let client = loop {
        match attach(&dir, Duration::from_secs(5), 16) {
            Ok(client) => break client,
            Err(error) => {
                assert!(start.elapsed() < Duration::from_secs(10), "{error:?}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    let pid = daemon.0.id();
    let regions = kilobytes(pid, "smaps", "Rss", Some("karyos-region"));
    let resident = kilobytes(pid, "status", "VmRSS", None);
    let ceiling = configured + configured * RSS_MARGIN_PERCENT / 100 + RSS_MARGIN_BYTES;
    assert!(
        regions <= configured,
        "regions resident {regions} B above the configured {configured} B"
    );
    assert!(
        resident <= ceiling,
        "karyosd resident {resident} B above {ceiling} B (configured {configured} B)"
    );
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}
