// SPDX-License-Identifier: Apache-2.0

// `karyos-catalog list` (archive-host.md, H4): a catalog written with the
// operating system's files is listed as text and as JSON; a torn last
// record is listed up to and reported as maybe behind, never cut; a
// directory with no catalog lists nothing; a missing directory, a damaged
// catalog and bad arguments exit 2.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_archive::catalog::{
    CATALOG, Catalog, NewRecording, SourceIncarnation, StopReason, StreamFormat,
};
use karyos_archive::segment::{Geometry, SyncPolicy};

use super::*;

/// A fresh directory under the system's temporary one, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "karyos-catalog-list-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn new_recording(stream_id: i32, required: bool) -> NewRecording<'static> {
    NewRecording {
        stream_id,
        session_id: 7,
        channel: b"karyos:ipc",
        start: 64,
        start_time_ns: 5,
        geometry: Geometry::new(64 * 1024, 1024 * 1024).unwrap(),
        policy: SyncPolicy::PerSegment,
        format: StreamFormat {
            lane: karyos_sys::frame::Lane::ZERO,
            initial_term_id: 1,
            mtu: core::num::NonZeroU32::new(1408).unwrap(),
            source: SourceIncarnation {
                driver: [1, 2],
                registration: 3,
                incarnation: 1,
            },
        },
        required,
    }
}

/// A catalog in `dir` with recording 1 stopped and recording 2 recording.
fn two_recordings(dir: &Path) {
    let mut catalog = Catalog::open(StdDisk, dir).unwrap().catalog;
    let first = catalog.start(new_recording(1001, false)).unwrap();
    let _ = catalog.start(new_recording(1002, true)).unwrap();
    catalog
        .stop(first, 4096, 9, StopReason::Stopped, false)
        .unwrap();
}

fn run(args: &[&std::ffi::OsStr]) -> (u8, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run_list(
        args.iter().map(|arg| arg.to_os_string()),
        &mut out,
        &mut err,
    );
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn a_catalog_is_listed_as_text_and_as_json() {
    let scratch = Scratch::new();
    two_recordings(&scratch.0);
    let (status, out, err) = run(&[scratch.0.as_os_str()]);
    assert_eq!((status, err.as_str()), (0, ""));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(lines[0].starts_with("2 recording(s) in "), "{out}");
    assert_eq!(
        lines[1],
        "1  stream 1001  session 7  channel karyos:ipc  start 64  async  stopped at 4096 (stopped)"
    );
    assert_eq!(
        lines[2],
        "2  stream 1002  session 7  channel karyos:ipc  start 64  required  recording"
    );
    let (status, out, _) = run(&[scratch.0.as_os_str(), "--json".as_ref()]);
    assert_eq!(status, 0);
    assert!(out.contains("\"missing\":false,\"behind\":null"), "{out}");
    assert!(
        out.contains(
            "{\"id\":1,\"stream_id\":1001,\"session_id\":7,\"channel\":\"karyos:ipc\",\"start\":64,\"start_time_ns\":5,\"required\":false,\"stop\":{\"position\":4096,\"time_ns\":9,\"reason\":\"stopped\",\"incomplete\":false}}"
        ),
        "{out}"
    );
    assert!(out.contains("\"required\":true,\"stop\":null}]}"), "{out}");
}

/// A channel's control characters and backslashes are escaped in the
/// text, which keeps one line per recording; the JSON quotes it.
#[test]
fn a_channel_stays_on_its_line() {
    let scratch = Scratch::new();
    let mut catalog = Catalog::open(StdDisk, &scratch.0).unwrap().catalog;
    let _ = catalog
        .start(NewRecording {
            channel: b"a\nb\\c\td",
            ..new_recording(1001, false)
        })
        .unwrap();
    drop(catalog);
    let (status, out, _) = run(&[scratch.0.as_os_str()]);
    assert_eq!(status, 0);
    assert_eq!(out.lines().count(), 2, "{out}");
    assert!(out.contains("  channel a\\nb\\\\c\\td  "), "{out}");
    let (status, out, _) = run(&[scratch.0.as_os_str(), "--json".as_ref()]);
    assert_eq!(status, 0);
    assert!(out.contains("\"channel\":\"a\\nb\\\\c\\u0009d\""), "{out}");
}

/// A record an Archive is still writing: listed up to it, reported, and
/// the file left as it was.
#[test]
fn a_torn_last_record_is_listed_up_to_and_reported() {
    let scratch = Scratch::new();
    two_recordings(&scratch.0);
    let path = scratch.0.join(CATALOG);
    let end = std::fs::metadata(&path).unwrap().len();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&[1, 0, 200, 0, 9])
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    let (status, out, _) = run(&[scratch.0.as_os_str()]);
    assert_eq!(status, 0);
    assert!(out.starts_with("2 recording(s)"), "{out}");
    assert!(
        out.ends_with(&format!(
            "maybe behind: the record at offset {end} is incomplete (an Archive writing it, or a crash its next open cuts)\n"
        )),
        "{out}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing cut");
    let (_, out, _) = run(&[scratch.0.as_os_str(), "--json".as_ref()]);
    assert!(out.contains(&format!("\"behind\":{end}")), "{out}");
}

#[test]
fn a_directory_without_a_catalog_lists_nothing() {
    let scratch = Scratch::new();
    let (status, out, _) = run(&[scratch.0.as_os_str()]);
    assert_eq!(status, 0);
    assert!(out.starts_with("no catalog in "), "{out}");
    assert!(!scratch.0.join(CATALOG).exists(), "no catalog created");
    let (_, out, _) = run(&[scratch.0.as_os_str(), "--json".as_ref()]);
    assert!(
        out.contains("\"missing\":true,\"behind\":null,\"recordings\":[]"),
        "{out}"
    );
}

#[test]
fn errors_exit_2() {
    let scratch = Scratch::new();
    let missing = scratch.0.join("absent");
    let (status, out, err) = run(&[missing.as_os_str()]);
    assert_eq!((status, out.as_str()), (EXIT_ERROR, ""));
    assert!(err.starts_with("karyos-catalog: "), "{err}");
    // A damaged record with more of the log behind it.
    two_recordings(&scratch.0);
    let path = scratch.0.join(CATALOG);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[16 + 6] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    let (status, _, err) = run(&[scratch.0.as_os_str()]);
    assert_eq!(status, EXIT_ERROR);
    assert!(err.contains("corrupt at offset 16"), "{err}");
    for args in [
        &[][..],
        &["--bogus".as_ref()][..],
        &["a".as_ref(), "b".as_ref()][..],
    ] {
        let (status, _, err) = run(args);
        assert_eq!(status, EXIT_ERROR, "{args:?}");
        assert!(err.contains("karyos-catalog --help"), "{err}");
    }
    let (status, out, _) = run(&["--help".as_ref()]);
    assert_eq!(status, 0);
    assert!(out.contains("Usage: karyos-catalog list <dir> [--json]"));
}
