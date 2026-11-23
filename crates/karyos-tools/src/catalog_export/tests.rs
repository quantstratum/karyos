// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::ffi::OsString;

use super::{run_export, run_verify_export};
use crate::catalog_verify::tests::{OPERATOR, RECORDING, archive, hex};

fn run(
    f: fn(Vec<OsString>, &mut dyn std::io::Write, &mut dyn std::io::Write) -> u8,
    argv: &[String],
) -> (u8, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = f(
        argv.iter().map(OsString::from).collect(),
        &mut out,
        &mut err,
    );
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn export(argv: Vec<OsString>, out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> u8 {
    run_export(argv, out, err)
}

fn verify(argv: Vec<OsString>, out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> u8 {
    run_verify_export(argv, out, err)
}

/// karyos#668: an export of an Archive's recording, written by `export`
/// from its files, verifies offline with `verify-export` under the trust
/// file and the operator's anchor store only, with the online verifier's
/// outcomes: the anchored ranges `verified`, the later ones
/// `beyond_anchor`, so the status is 1.
#[test]
fn an_exported_recording_verifies_offline_as_online() {
    let archive = archive("export-offline");
    let file = archive.dir().with_extension("kxe");
    let anchors = format!("{}={}", hex(&OPERATOR), archive.anchors().display());
    let (status, out, err) = run(
        export,
        &[
            archive.dir().display().to_string(),
            "--trust".into(),
            archive.trust().display().to_string(),
            "--recording".into(),
            RECORDING.to_string(),
            "--anchors".into(),
            anchors.clone(),
            "--out".into(),
            file.display().to_string(),
        ],
    );
    assert_eq!((status, err.as_str()), (0, ""), "{out}");
    // The Archive's files are gone: only the export, the trust and the
    // anchor store are read.
    std::fs::remove_dir_all(archive.dir()).unwrap();
    let (status, out, err) = run(
        verify,
        &[
            file.display().to_string(),
            "--trust".into(),
            archive.trust().display().to_string(),
            "--anchors".into(),
            anchors,
        ],
    );
    assert_eq!((status, err.as_str()), (1, ""), "{out}");
    assert!(out.contains("recording 3 [0, 8) verified"), "{out}");
    assert!(out.contains("recording 3 [24, 32) verified"), "{out}");
    assert!(out.contains("recording 3 [32, 40) beyond_anchor"), "{out}");
    let _ = std::fs::remove_file(&file);
}

/// A damaged export is refused, the error status.
#[test]
fn a_damaged_export_is_refused() {
    let archive = archive("export-damaged");
    let file = archive.dir().with_extension("kxe");
    std::fs::write(&file, b"not an export").unwrap();
    let (status, _, err) = run(
        verify,
        &[
            file.display().to_string(),
            "--trust".into(),
            archive.trust().display().to_string(),
        ],
    );
    assert_eq!(status, crate::catalog::EXIT_ERROR, "{err}");
    let _ = std::fs::remove_file(&file);
}
