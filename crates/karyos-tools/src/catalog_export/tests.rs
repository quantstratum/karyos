// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::ffi::OsString;

use super::{run_export, run_verify_export};
use crate::catalog_verify::tests::{OPERATOR, RECORDING, archive, hex, open_journal};

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
    // #1196 review: the unsealed tail travels and verifies as online.
    assert!(out.contains("recording 3 [48, 52) unsealed"), "{out}");
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

fn export_args(
    archive: &crate::catalog_verify::tests::Archive,
    file: &std::path::Path,
) -> Vec<String> {
    vec![
        archive.dir().display().to_string(),
        "--trust".into(),
        archive.trust().display().to_string(),
        "--recording".into(),
        RECORDING.to_string(),
        "--anchors".into(),
        format!("{}={}", hex(&OPERATOR), archive.anchors().display()),
        "--out".into(),
        file.display().to_string(),
    ]
}

/// #1196 review P1: an `--out` that exists, such as one of the inputs, is
/// never overwritten: the export fails and the file is unchanged.
#[test]
fn an_existing_out_is_never_overwritten() {
    let archive = archive("export-exists");
    let file = archive.trust();
    let before = std::fs::read(&file).unwrap();
    let (status, _, err) = run(export, &export_args(&archive, &file));
    assert_eq!(status, crate::catalog::EXIT_ERROR, "{err}");
    assert_eq!(std::fs::read(&file).unwrap(), before);
}

/// #1196 review P2: after a purge below the first range, only the
/// retained span is exported; the purge record classifies the range
/// below the floor, and the export never fails reading deleted bytes.
///
/// The purge is signed as an Archive signs its heads, and the export is
/// verified with the operator's anchor store, as any export is: without
/// it the export's anchors cannot be confirmed, which is malformed
/// evidence for the whole journal and leaves every range inconsistent,
/// which the retained-span checks below catch (#1268 review). The
/// fixture anchors its fourth range, so the last two sealed ranges are
/// beyond the anchor.
#[test]
fn a_purged_prefix_exports_only_the_retained_span() {
    use karyos_archive::disk::StdDisk;
    use karyos_archive::integrity::ledger::Ledger;
    use karyos_archive::integrity::signing::HeadSigner as _;
    use karyos_archive::integrity::test_key::TestKey;
    use karyos_archive::integrity::trust::{
        ChainHead, Custody, HEADS_FILE, SIGNED_HEAD_LENGTH, SignedHead,
    };
    use karyos_archive::segment::{SegmentStore, SyncPolicy, recorded_geometry};

    use crate::catalog_verify::tests::{ARCHIVE, SIGNER_SEED};

    let archive = archive("export-purged");
    let dir = archive.dir();
    let geometry = recorded_geometry(&mut StdDisk, &dir, RECORDING)
        .unwrap()
        .unwrap();
    let mut store = SegmentStore::recover(StdDisk, &dir, RECORDING, geometry, SyncPolicy::None)
        .unwrap()
        .store;
    let floor = store.purge_before(8).unwrap();
    drop(store);
    let mut journal = open_journal(&dir);
    journal.record_purge(RECORDING, 0, floor, [0; 32]).unwrap();
    let purge = journal.records().unwrap().last().copied().unwrap();
    drop(journal);
    // The Archive's signer signs a head over the purge record.
    let mut signer = TestKey::from_seed(SIGNER_SEED);
    let head = ChainHead {
        archive_id: ARCHIVE,
        journal_id: 0,
        counter: purge.counter,
        digest: purge.digest(),
    };
    let signed = SignedHead {
        head,
        key_id: signer.key_id(),
        custody: Custody::NoSeparation,
        signature: signer.sign(&head).unwrap(),
    };
    Ledger::<_, SIGNED_HEAD_LENGTH>::open(StdDisk, &dir, HEADS_FILE)
        .unwrap()
        .append(signed.encode())
        .unwrap();
    let file = archive.dir().with_extension("kxe");
    let (status, out, err) = run(export, &export_args(&archive, &file));
    assert_eq!((status, err.as_str()), (0, ""), "{out}");
    let (_, out, err) = run(
        verify,
        &[
            file.display().to_string(),
            "--trust".into(),
            archive.trust().display().to_string(),
            "--anchors".into(),
            format!("{}={}", hex(&OPERATOR), archive.anchors().display()),
        ],
    );
    assert!(err.is_empty(), "{err}");
    // Below the floor: purged, never verified.
    assert!(out.contains("recording 3 [0, 8) purged"), "{out}");
    // The retained span is exported and verified, from the floor to the
    // anchor; past it beyond the anchor; the unsealed tail as online.
    for range in ["[8, 16)", "[16, 24)", "[24, 32)"] {
        assert!(
            out.contains(&format!("recording 3 {range} verified")),
            "{out}"
        );
    }
    for range in ["[32, 40)", "[40, 48)"] {
        assert!(
            out.contains(&format!("recording 3 {range} beyond_anchor")),
            "{out}"
        );
    }
    assert!(out.contains("recording 3 [48, 52) unsealed"), "{out}");
    let _ = std::fs::remove_file(&file);
}

/// #1196 review P1: a recording the carried chain seals but the export
/// does not select is chain evidence only, never reported: the blind
/// vector X-8 seals recording 9 without exporting it.
#[test]
fn an_unselected_recording_is_not_reported() {
    use karyos_archive::integrity::anchor::{ANCHOR_FILE, ANCHOR_LENGTH};
    use karyos_archive::integrity::export::{SectionKind, decode};
    use karyos_archive::integrity::ledger::Ledger;
    use karyos_archive::integrity::test_key::TestKey;
    let vectors = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../karyos-archive/src/integrity/export/vectors.txt"
    ));
    let hex8 = vectors
        .lines()
        .find_map(|line| line.strip_prefix("X-8 "))
        .unwrap();
    let bytes: Vec<u8> = (0..hex8.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex8[at..at + 2], 16).unwrap())
        .collect();
    let root = std::env::temp_dir().join(format!("karyos-export-x8-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = root.join("store");
    std::fs::create_dir_all(&store).unwrap();
    let export = decode(&bytes).unwrap();
    let mut ledger =
        Ledger::<_, ANCHOR_LENGTH>::open(karyos_archive::disk::StdDisk, &store, ANCHOR_FILE)
            .unwrap();
    for section in export
        .sections
        .iter()
        .filter(|section| section.kind == SectionKind::Anchors)
    {
        for anchor in section.body.as_chunks::<ANCHOR_LENGTH>().0 {
            ledger.append(*anchor).unwrap();
        }
    }
    drop(ledger);
    let file = root.join("x8.kxe");
    std::fs::write(&file, &bytes).unwrap();
    let trust = root.join("trust");
    std::fs::write(
        &trust,
        format!(
            "archive {}\nauthority {}\njournal 1\n",
            hex(&[7; 32]),
            hex(&TestKey::from_seed([1; 32]).public())
        ),
    )
    .unwrap();
    let (status, out, err) = run(
        verify,
        &[
            file.display().to_string(),
            "--trust".into(),
            trust.display().to_string(),
            "--anchors".into(),
            format!("{}={}", hex(&[0x0A; 32]), store.display()),
        ],
    );
    // Recording 7's ranges are reported; recording 9, sealed in the
    // carried chain but not exported, is not. (The vector's anchor
    // receipt is synthetic, so this store does not confirm it: the
    // outcomes themselves are the offline verifier's tests' subject.)
    assert_eq!(status, 1, "{err}{out}");
    assert!(err.is_empty(), "{err}");
    assert!(!out.contains("recording 9 "), "{out}");
    assert!(out.contains("recording 7 [0, 64) "), "{out}");
    assert!(out.contains("recording 7 [64, 128) "), "{out}");
    let _ = std::fs::remove_dir_all(&root);
}
