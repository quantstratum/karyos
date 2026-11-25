// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use karyos_archive::integrity::calibration_journal::read;
use karyos_trace::clocks::{Calibration, ClockKey};
use karyos_trace::journal::ObserverId;

use super::*;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-calibrate-append-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn calibration(valid_from: u64, valid_to: u64) -> [u64; CALIBRATION_WORDS] {
    let key = |driver| ClockKey {
        observer: ObserverId {
            driver: [driver, 0],
            journal: 1,
        },
        domain: 1,
        epoch: 1,
    };
    Calibration {
        from: key(1),
        to: key(2),
        reference: valid_from,
        offset: -5,
        offset_uncertainty: 3,
        drift: 0,
        drift_uncertainty: 0,
        valid_from,
        valid_to,
    }
    .encode()
    .unwrap()
}

/// The words as `calibrate phc` prints them.
fn printed(words: &[u64; CALIBRATION_WORDS]) -> Vec<String> {
    words.iter().map(|word| format!("{word:#018x}")).collect()
}

fn append(journal: &Path, words: &[String], input: &str) -> (u8, String, String) {
    let mut args: Vec<OsString> = vec!["--journal".into(), journal.into()];
    args.extend(words.iter().map(OsString::from));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run(
        args.into_iter(),
        &mut std::io::Cursor::new(input.as_bytes()),
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
fn records_given_as_words_or_on_standard_input_are_journalled() {
    let dir = temp_dir("append");
    let first = calibration(0, 100);
    let (status, out, err) = append(&dir, &printed(&first), "");
    assert_eq!((status, err.as_str()), (0, ""));
    assert_eq!(out, "appended at 0\n");
    // `calibrate phc`'s output: its evidence lines, then the record.
    let second = calibration(100, 200);
    let text = format!(
        "host x\nclock source tsc\nrecord {}\n",
        printed(&second).join(" ")
    );
    let (status, out, err) = append(&dir, &[], &text);
    assert_eq!((status, err.as_str()), (0, ""));
    assert_eq!(out, "appended at 144\n");
    // Decimal words too, and an unknown type, kept for a newer reader.
    let mut unknown: Vec<String> = vec!["9".into()];
    unknown.extend(std::iter::repeat_n("0".to_owned(), 17));
    assert_eq!(append(&dir, &unknown, "").0, 0);
    let records = read(StdDisk, &dir).unwrap();
    assert!(records.lossless);
    assert_eq!(records.records.len(), 3);
    assert_eq!(records.records[..2], [first, second]);
    assert_eq!(records.records[2][0], 9);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_bad_record_or_usage_appends_nothing() {
    let dir = temp_dir("refused");
    let mut bad = calibration(0, 100);
    // A calibration from a clock to itself.
    let from = bad;
    bad[6..11].copy_from_slice(&from[1..6]);
    let good = printed(&calibration(0, 100));
    let both: Vec<String> = good.iter().cloned().chain(printed(&bad)).collect();
    let (status, _, err) = append(&dir, &both, "");
    assert_eq!(status, EXIT_ERROR);
    assert!(err.contains("record 1"), "{err}");
    let (status, _, err) = append(&dir, &good[..17], "");
    assert_eq!(status, EXIT_ERROR);
    assert!(err.contains("17 words"), "{err}");
    let (status, _, err) = append(&dir, &[], "nothing here\n");
    assert_eq!(status, EXIT_ERROR);
    assert!(err.contains("0 words"), "{err}");
    let (status, _, err) = append(&dir, &["0xzz".into()], "");
    assert_eq!(status, EXIT_ERROR);
    assert!(
        err.contains("not a record word") || err.contains("words"),
        "{err}"
    );
    // Nothing was made.
    assert!(!dir.exists());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run(
        std::iter::empty(),
        &mut std::io::Cursor::new(&b""[..]),
        &mut out,
        &mut err,
    );
    assert_eq!(status, EXIT_ERROR);
    assert!(String::from_utf8(err).unwrap().contains("--journal"));
}
