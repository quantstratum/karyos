// SPDX-License-Identifier: Apache-2.0

//! `karyos-catalog verify` over a real archive directory: a recording,
//! its seals, a registry endorsed by a test authority, a signed head and
//! an operator anchor store (karyos#665).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::anchor::{AnchorKind, LedgerAnchorStore, publish_due};
use karyos_archive::integrity::journal::IntegrityJournal;
use karyos_archive::integrity::ledger::Ledger;
use karyos_archive::integrity::signing::HeadSigner as _;
use karyos_archive::integrity::test_key::TestKey;
use karyos_archive::integrity::trust::*;
use karyos_archive::segment::{Geometry, SegmentStore, SyncPolicy};

use super::*;

const ARCHIVE: [u8; 32] = [7; 32];
const OPERATOR: [u8; 32] = [21; 32];
const RECORDING: u64 = 3;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Archive {
    root: PathBuf,
}

impl Drop for Archive {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Archive {
    fn dir(&self) -> PathBuf {
        self.root.join("archive")
    }
    fn anchors(&self) -> PathBuf {
        self.root.join("operator")
    }
    fn trust(&self) -> PathBuf {
        self.root.join("trust")
    }
}

fn range(index: u64) -> Vec<u8> {
    (index * 1_000).to_le_bytes().to_vec()
}

/// An archive of six sealed eight-byte ranges and four unsealed bytes,
/// the head signed at the last seal and anchored at the fourth range.
fn archive(name: &str) -> Archive {
    let root = std::env::temp_dir().join(format!("karyos-verify-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let archive = Archive { root };
    let dir = archive.dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(archive.anchors()).unwrap();
    let mut store = SegmentStore::create(
        StdDisk,
        &dir,
        RECORDING,
        Geometry::new(64, 128).unwrap(),
        SyncPolicy::None,
        0,
    )
    .unwrap();
    let mut journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
    let authority = TestKey::from_seed([1; 32]);
    let mut signer = TestKey::from_seed([9; 32]);
    let mut entry = RegistryEntry {
        action: RegistryAction::Register,
        algorithm: Algorithm::Ed25519,
        custody: Custody::NoSeparation,
        sequence: 0,
        key_id: signer.key_id(),
        public: signer.public(),
        effective: 0,
        evidence: [0; 32],
        endorsement: [0; 64],
    };
    entry.endorsement = authority.sign_bytes(&entry.endorsement_bytes(&ARCHIVE));
    let trust = TrustRoot {
        archive_id: ARCHIVE,
        authorities: vec![authority.public()],
    };
    let mut keys = Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(StdDisk, &dir, KEYS_FILE).unwrap();
    KeyRegistry::new(trust)
        .append(&entry, &mut journal, &mut keys)
        .unwrap();
    for index in 0..6 {
        store.append(index * 8, &range(index)).unwrap();
        journal
            .seal_segment(RECORDING, index * 8, &range(index), false)
            .unwrap();
    }
    store.append(48, b"tail").unwrap();
    store.sync().unwrap();
    let records = journal.records().unwrap();
    let mut head = |counter: usize| {
        let head = ChainHead {
            archive_id: ARCHIVE,
            journal_id: 0,
            counter: records[counter].counter,
            digest: records[counter].digest(),
        };
        SignedHead {
            head,
            key_id: signer.key_id(),
            custody: Custody::NoSeparation,
            signature: signer.sign(&head).unwrap(),
        }
    };
    let mut heads = Ledger::<_, SIGNED_HEAD_LENGTH>::open(StdDisk, &dir, HEADS_FILE).unwrap();
    heads.append(head(6).encode()).unwrap();
    let mut anchors = LedgerAnchorStore::open(
        StdDisk,
        &archive.anchors(),
        AnchorKind::OperatorExport,
        OPERATOR,
    )
    .unwrap();
    publish_due(
        &mut anchors,
        None,
        Some(&head(4)),
        std::num::NonZeroU64::new(1).unwrap(),
    )
    .unwrap()
    .unwrap();
    std::fs::write(
        archive.trust(),
        format!(
            "# test trust\narchive {}\nauthority {}\njournal 0\n",
            hex(&ARCHIVE),
            hex(&authority.public())
        ),
    )
    .unwrap();
    archive
}

fn run(args: &[&Path], flags: &[&str]) -> (u8, String, String) {
    let mut argv: Vec<OsString> = args.iter().map(|path| path.as_os_str().into()).collect();
    argv.extend(flags.iter().map(OsString::from));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run_verify(argv, &mut out, &mut err);
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn full(archive: &Archive, json: bool) -> (u8, String, String) {
    let dir = archive.dir();
    let trust = archive.trust();
    let anchors = archive.anchors();
    let mut argv: Vec<OsString> = vec![
        dir.into(),
        "--trust".into(),
        trust.into(),
        "--anchors".into(),
        anchors.into(),
    ];
    if json {
        argv.push("--json".into());
    }
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run_verify(argv, &mut out, &mut err);
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn verify_reports_verified_beyond_anchor_and_unsealed_ranges() {
    let archive = archive("outcomes");
    let (status, out, err) = full(&archive, false);
    assert_eq!((status, err.as_str()), (0, ""), "{out}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines[0].starts_with("recording 3 [0, 8) verified seal=1: tamper evident"),
        "{out}"
    );
    assert!(
        lines[3].starts_with("recording 3 [24, 32) verified"),
        "{out}"
    );
    assert_eq!(
        lines[4],
        "recording 3 [32, 40) beyond_anchor seal=5 reasons=no_anchor unverifiable"
    );
    assert_eq!(lines[6], "recording 3 [48, 52) unsealed unverifiable");
    assert_eq!(
        lines[7],
        "coverage: 7 records, signed through 6, anchored through 4"
    );
    assert_eq!(
        lines[8],
        "time evidence: not evaluated by the integrity verifier"
    );
    // Only verified lines carry the tamper-evidence statement.
    for line in &lines {
        assert_eq!(line.contains("tamper evident"), line.contains(" verified "));
    }
}

#[test]
fn verify_without_trust_reports_untrusted_evidence_not_corruption() {
    let archive = archive("untrusted");
    let (status, out, _) = run(&[&archive.dir()], &[]);
    assert_eq!(status, EXIT_INCONSISTENT);
    for line in out.lines().take(6) {
        assert!(
            line.contains("inconsistent") && line.contains("untrusted_evidence"),
            "{line}"
        );
        assert!(!line.contains("corruption"), "{line}");
    }
}

#[test]
fn verify_finds_an_altered_byte_on_disk() {
    let archive = archive("altered");
    let segment = std::fs::read_dir(archive.dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "seg"))
        .unwrap();
    let mut bytes = std::fs::read(&segment).unwrap();
    // The data of range 2 ([16, 24)): find it and flip one byte.
    let needle = range(2);
    let at = bytes
        .windows(needle.len())
        .position(|window| window == needle.as_slice())
        .unwrap();
    bytes[at] ^= 1;
    std::fs::write(&segment, bytes).unwrap();
    let (status, out, _) = full(&archive, false);
    assert_eq!(status, EXIT_INCONSISTENT);
    // The store's CRC-32C detects the damaged entry and its recovery cuts
    // the index there, so the bytes below the seals are gone: an index
    // shortened below a seal, which the verifier reports as inconsistent
    // from that range on, while the ranges before it still verify.
    assert!(out.contains("recording 3 [8, 16) verified seal=2"), "{out}");
    assert!(
        out.contains(
            "recording 3 [16, 24) inconsistent seal=3 reasons=shortened_index first_inconsistent=3 unverifiable"
        ),
        "{out}"
    );
}

#[test]
fn verify_writes_integrity_and_time_in_separate_json_fields() {
    let archive = archive("json");
    let (status, out, _) = full(&archive, true);
    assert_eq!(status, 0);
    assert!(
        out.starts_with("{\"integrity\":[{\"recording\":3,"),
        "{out}"
    );
    assert!(out.contains("\"outcome\":\"verified\""), "{out}");
    assert!(out.contains("\"unverifiable\":false"), "{out}");
    assert!(out.ends_with(",\"time\":\"not_evaluated\"}\n"), "{out}");
    assert!(!out.contains("\"met\"") && !out.contains("no_evidence"));
}

#[test]
fn verify_refuses_bad_arguments_and_a_bad_trust_file() {
    let (status, out, _) = run(&[], &["--help"]);
    assert_eq!(
        (status, out.starts_with("karyos-catalog verify")),
        (0, true)
    );
    let (status, _, err) = run(&[], &[]);
    assert_eq!(status, EXIT_ERROR);
    assert!(err.contains("verify needs a directory"), "{err}");
    let (status, _, err) = run(&[], &["--frob"]);
    assert_eq!(status, EXIT_ERROR);
    assert!(err.contains("unknown option --frob"), "{err}");
    assert!(parse_trust("archive 00\n").is_err());
    assert!(parse_trust(&format!("archive {}\n", hex(&ARCHIVE))).is_err());
    assert!(parse_trust("colour blue\n").is_err());
}

#[test]
fn verify_reports_a_seal_larger_than_its_recording_without_reading_it() {
    let archive = archive("oversized");
    let mut journal = IntegrityJournal::open(StdDisk, &archive.dir())
        .unwrap()
        .journal;
    // A corrupt seal declaring far more than the recording holds.
    journal
        .append(
            karyos_archive::integrity::SealKind::OpenSegment,
            RECORDING,
            48,
            u64::MAX / 2,
            [0; 32],
        )
        .unwrap();
    let (status, out, _) = full(&archive, false);
    assert_eq!(status, EXIT_INCONSISTENT);
    assert!(
        out.contains(&format!(
            "recording 3 [48, {}) inconsistent seal=7 reasons=shortened_index",
            u64::MAX / 2
        )),
        "{out}"
    );
}

#[test]
fn verify_reports_a_journal_record_that_does_not_decode() {
    let archive = archive("malformed");
    let path = IntegrityJournal::<StdDisk>::path(&archive.dir());
    let mut bytes = std::fs::read(&path).unwrap();
    let record = karyos_archive::integrity::SEAL_RECORD_LENGTH;
    bytes.extend(std::iter::repeat_n(0xFF, record));
    std::fs::write(&path, bytes).unwrap();
    let (status, out, _) = full(&archive, false);
    assert_eq!(status, EXIT_INCONSISTENT);
    assert!(
        out.contains("journal inconsistent first_inconsistent=7"),
        "{out}"
    );
    let (_, json_out, _) = full(&archive, true);
    assert!(
        json_out.contains("\"journal_first_inconsistent\":7"),
        "{json_out}"
    );
}

#[test]
fn verify_of_a_directory_that_does_not_exist_is_an_error() {
    let missing = std::env::temp_dir().join(format!("karyos-verify-absent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&missing);
    let (status, out, err) = run(&[&missing], &[]);
    assert_eq!(status, EXIT_ERROR, "{out}");
    assert!(err.contains("karyos-verify-absent"), "{err}");
}
