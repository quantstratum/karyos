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
use karyos_archive::integrity::anchor::{LedgerAnchorStore, publish_due};
use karyos_archive::integrity::journal::IntegrityJournal;
use karyos_archive::integrity::ledger::Ledger;
use karyos_archive::integrity::signing::HeadSigner as _;
use karyos_archive::integrity::test_key::TestKey;
use karyos_archive::integrity::trust::*;
use karyos_archive::segment::{Geometry, SegmentStore, SyncPolicy};

use super::*;

pub(crate) const ARCHIVE: [u8; 32] = [7; 32];
/// The seed of the fixture's Archive signer.
pub(crate) const SIGNER_SEED: [u8; 32] = [9; 32];
pub(crate) const OPERATOR: [u8; 32] = [21; 32];
pub(crate) const RECORDING: u64 = 3;

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) struct Archive {
    root: PathBuf,
}

impl Drop for Archive {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Archive {
    pub(crate) fn dir(&self) -> PathBuf {
        self.root.join("archive")
    }
    pub(crate) fn anchors(&self) -> PathBuf {
        self.root.join("operator")
    }
    pub(crate) fn trust(&self) -> PathBuf {
        self.root.join("trust")
    }
}

fn range(index: u64) -> Vec<u8> {
    (index * 1_000).to_le_bytes().to_vec()
}

/// An archive of six sealed eight-byte ranges and four unsealed bytes,
/// the head signed at the last seal and anchored at the fourth range.
pub(crate) fn archive(name: &str) -> Archive {
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
    let mut journal = open_journal(&dir);
    let authority = TestKey::from_seed([1; 32]);
    let mut signer = TestKey::from_seed(SIGNER_SEED);
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
    let mut anchors = LedgerAnchorStore::open(StdDisk, &archive.anchors(), OPERATOR).unwrap();
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
        format!("{}={}", hex(&OPERATOR), anchors.display()).into(),
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
        "coverage: 7 records, signed through 6 (no custody separation), anchored through 4"
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
    let mut journal = open_journal(&archive.dir());
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

#[test]
fn verify_counts_anchors_only_from_the_store_location_the_operator_names() {
    let archive = archive("location");
    let dir = archive.dir();
    let elsewhere = [22u8; 32];
    let argv: Vec<OsString> = vec![
        dir.into(),
        "--trust".into(),
        archive.trust().into(),
        "--anchors".into(),
        format!("{}={}", hex(&elsewhere), archive.anchors().display()).into(),
    ];
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run_verify(argv, &mut out, &mut err);
    let out = String::from_utf8(out).unwrap();
    // The store's entries claim another location than the operator stated:
    // nothing is anchored, and the mismatch is reported as evidence.
    assert_eq!(status, EXIT_INCONSISTENT, "{out}");
    assert!(out.contains("anchored through none"), "{out}");
    assert!(!out.contains(" verified seal="), "{out}");
    assert!(
        out.contains("evidence inconsistent reasons=malformed_evidence"),
        "{out}"
    );
    let (status, _, err) = run(&[&archive.dir()], &["--anchors", "not-a-location"]);
    assert_eq!(status, EXIT_ERROR);
    assert!(err.contains("--anchors needs HEX=DIR"), "{err}");
}

/// A writer that always fails.
struct Broken;

impl std::io::Write for Broken {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("closed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("closed"))
    }
}

#[test]
fn a_report_that_cannot_be_written_is_an_error() {
    let archive = archive("broken-out");
    let argv: Vec<OsString> = vec![archive.dir().into()];
    let mut err = Vec::new();
    assert_eq!(run_verify(argv, &mut Broken, &mut err), EXIT_ERROR);
    assert!(
        String::from_utf8(err)
            .unwrap()
            .contains("writing the report"),
        "the error is reported"
    );
}

#[test]
fn a_store_that_cannot_be_opened_is_an_error_not_a_shortened_index() {
    use std::os::unix::fs::PermissionsExt as _;
    let archive = archive("unreadable");
    let segment = std::fs::read_dir(archive.dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "seg"))
        .unwrap();
    std::fs::set_permissions(&segment, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&segment).is_ok() {
        // Running as a user permissions do not bind (root in a container):
        // the store cannot be made unreadable this way.
        std::fs::set_permissions(&segment, std::fs::Permissions::from_mode(0o644)).unwrap();
        return;
    }
    let (status, out, err) = full(&archive, false);
    std::fs::set_permissions(&segment, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(status, EXIT_ERROR, "{out}");
    assert!(err.contains("recording 3"), "{err}");
    assert!(!out.contains("shortened_index"), "{out}");
}

#[test]
fn verify_reports_the_custody_of_the_signed_coverage() {
    let archive = archive("custody");
    let (status, out, _) = full(&archive, false);
    assert_eq!(status, 0, "{out}");
    assert!(
        out.contains("signed through 6 (no custody separation)"),
        "{out}"
    );
    let (_, json_out, _) = full(&archive, true);
    assert!(
        json_out.contains("\"custody\":\"no custody separation\""),
        "{json_out}"
    );
}

#[test]
fn verify_fails_on_a_malformed_anchor_entry_even_with_no_sealed_range() {
    let root = std::env::temp_dir().join(format!("karyos-verify-empty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("archive");
    let store = root.join("anchors");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
        store.join(karyos_archive::integrity::anchor::ANCHOR_FILE),
        vec![0xFF; karyos_archive::integrity::anchor::ANCHOR_LENGTH],
    )
    .unwrap();
    let anchors = format!("{}={}", hex(&OPERATOR), store.display());
    let (status, out, _) = run(&[&dir], &["--anchors", &anchors]);
    assert_eq!(status, EXIT_INCONSISTENT, "{out}");
    assert!(out.contains("evidence inconsistent"), "{out}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_store_whose_geometry_cannot_be_recovered_is_an_error_not_an_absent_store() {
    let archive = archive("geometry");
    let index = std::fs::read_dir(archive.dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "idx"))
        .unwrap();
    std::fs::write(&index, b"").unwrap();
    let (status, out, err) = full(&archive, false);
    assert_eq!(status, EXIT_ERROR, "{out}");
    assert!(err.contains("geometry cannot be recovered"), "{err}");
}

#[test]
fn an_anchor_store_named_but_missing_is_an_error() {
    let archive = archive("missing-store");
    let absent = archive.dir().join("no-such-store");
    let anchors = format!("{}={}", hex(&OPERATOR), absent.display());
    let (status, out, err) = run(&[&archive.dir()], &["--anchors", &anchors]);
    assert_eq!(status, EXIT_ERROR, "{out}");
    assert!(err.contains("no-such-store"), "{err}");
}

fn usage(args: &[&str]) -> UsageError {
    parse_verify(args.iter().map(OsString::from)).unwrap_err()
}

#[test]
fn each_usage_error_is_typed_and_keeps_its_message() {
    let location = hex(&OPERATOR);
    let cases: [(&[&str], UsageError, &str); 9] = [
        (
            &["--trust"],
            UsageError::TrustNeedsFile,
            "--trust needs a file",
        ),
        (
            &["--trust", "a", "--trust", "b"],
            UsageError::TrustTwice,
            "--trust given twice",
        ),
        (
            &["--anchors"],
            UsageError::AnchorsNeedsValue,
            "--anchors needs HEX=DIR",
        ),
        (
            &["--anchors", "nodir"],
            UsageError::AnchorsNoSeparator,
            "--anchors needs HEX=DIR: the store's location, then its directory",
        ),
        (
            &["--anchors", "00=d"],
            UsageError::AnchorsLocation(HexError::Length("00".into())),
            "\"00\" is not 64 hex digits",
        ),
        (
            &["--frob"],
            UsageError::UnknownOption("--frob".into()),
            "unknown option --frob",
        ),
        (
            &["a", "b"],
            UsageError::OneDirectoryOnly,
            "one directory only",
        ),
        (&[], UsageError::NoDirectory, "verify needs a directory"),
        (
            &["--trust", "t", &format!("--anchors={location}")],
            UsageError::UnknownOption(format!("--anchors={location}")),
            "unknown option --anchors=",
        ),
    ];
    for (args, expected, message) in cases {
        let error = usage(args);
        assert_eq!(error, expected, "{args:?}");
        assert!(error.to_string().starts_with(message), "{error}");
    }
    let zz = "z".repeat(64);
    assert_eq!(
        usage(&["--anchors", &format!("{zz}=d")]),
        UsageError::AnchorsLocation(HexError::NotHex(zz.clone()))
    );
    {
        use std::os::unix::ffi::OsStringExt as _;
        let error = parse_verify([OsString::from("--anchors"), OsString::from_vec(vec![0xff])])
            .unwrap_err();
        assert_eq!(error, UsageError::AnchorsNotText);
    }
}

#[test]
fn each_trust_file_error_is_typed_with_its_line() {
    let key = hex(&ARCHIVE);
    let line = |line, error| TrustError::Line { line, error };
    let cases = [
        ("archive\n", line(1, LineError::NoValue("archive".into()))),
        (
            "# c\narchive 00\n",
            line(2, LineError::Hex(HexError::Length("00".into()))),
        ),
        (
            &*format!("archive {key}\njournal x\n"),
            line(2, LineError::JournalId("x".into())),
        ),
        (
            "colour blue\n",
            line(1, LineError::UnknownKey("colour".into())),
        ),
        (&*format!("authority {key}\n"), TrustError::NoArchive),
        (&*format!("archive {key}\n"), TrustError::NoAuthority),
    ];
    for (text, expected) in cases {
        assert_eq!(parse_trust(text).unwrap_err(), expected, "{text:?}");
    }
    assert_eq!(
        line(2, LineError::JournalId("x".into())).to_string(),
        "line 2: \"x\" is not a journal id"
    );
}

#[test]
fn run_checks_errors_keep_their_path_and_source() {
    let archive = archive("typed-errors");
    let args = |trust: Option<PathBuf>, anchors: Vec<([u8; 32], PathBuf)>| VerifyArgs {
        recording: None,
        dir: archive.dir(),
        trust,
        anchors,
        json: false,
        time_requirement: None,
        time_anchors: Vec::new(),
    };
    let missing = archive.root.join("no-such-trust");
    match run_checks(&args(Some(missing.clone()), Vec::new())) {
        Err(VerifyError::TrustRead { path, source }) => {
            assert_eq!(path, missing);
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("{other:?}"),
    }
    let bad = archive.root.join("bad-trust");
    std::fs::write(&bad, "colour blue\n").unwrap();
    match run_checks(&args(Some(bad.clone()), Vec::new())) {
        Err(VerifyError::Trust { path, source }) => {
            assert_eq!(path, bad);
            assert_eq!(
                source,
                TrustError::Line {
                    line: 1,
                    error: LineError::UnknownKey("colour".into())
                }
            );
        }
        other => panic!("{other:?}"),
    }
    let store = archive.root.join("no-such-store");
    match run_checks(&args(None, vec![(OPERATOR, store.clone())])) {
        Err(VerifyError::Io { path, source }) => {
            assert_eq!(path, store.join(ANCHOR_FILE));
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("{other:?}"),
    }
}

/// A groups directory the running Archive sealed (karyos#1088): one
/// group whose journal holds timer events, made durable and sealed by the
/// agent, then signed and anchored at its last seal by the operator.
/// Returns the directory and the group journal's segment file.
fn sealed_groups(name: &str) -> (Archive, PathBuf) {
    use karyos_archive::agent::{AgentConfig, ArchiveHandle, NewGroup, StartGroup};
    use karyos_archive::group::capture::CaptureConfig;
    use karyos_archive::group::journal::JournalConfig;
    use karyos_archive::group::record::{
        Capture, EndOutcome, EventEnd, GroupRecord, MAX_RECORD, TimerEvent,
    };

    const GROUP: u64 = 5;
    let root = std::env::temp_dir().join(format!("karyos-verify-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let archive = Archive { root };
    let groups = archive.dir();
    std::fs::create_dir_all(&groups).unwrap();
    std::fs::create_dir_all(archive.anchors()).unwrap();
    let host = archive.root.join("host");
    std::fs::create_dir_all(&host).unwrap();
    let config =
        AgentConfig::default().with_seal_interval(Some(std::time::Duration::from_millis(1)));
    let agent = ArchiveHandle::spawn(StdDisk, &host, config).unwrap();
    let start = StartGroup::new(
        GROUP,
        groups.clone(),
        JournalConfig::new(
            karyos_archive::group::journal::MIN_SEGMENT_LENGTH,
            SyncPolicy::Every { interval_ns: 0 },
        ),
        CaptureConfig::new(1 << 16, 4096, 64),
    )
    .with_new(NewGroup::new(1, 4096, Capture::Strict, b"m".to_vec()));
    let mut sender = agent.start_group(start).unwrap();
    let mut out = vec![0u8; MAX_RECORD];
    for seq in 1..=3u64 {
        let mut bytes = Vec::new();
        for record in [
            GroupRecord::Timer(TimerEvent {
                group_seq: seq,
                logical_time: seq,
                timer_id: 1,
            }),
            GroupRecord::End(EventEnd {
                group_seq: seq,
                observations: 0,
                outcome: EndOutcome::Complete,
            }),
        ] {
            let length = record.encode(&mut out).unwrap();
            bytes.extend_from_slice(&out[..length]);
        }
        sender.admit().unwrap();
        sender.send(&bytes, seq).unwrap();
    }
    assert_eq!(
        sender
            .waiter()
            .wait_durable(3, std::time::Duration::from_secs(5)),
        Ok(3)
    );
    // A duty after the durability seals it.
    std::thread::sleep(std::time::Duration::from_millis(100));
    agent.shutdown().unwrap();

    // The operator's key, signed head and anchor, as for an archive.
    let mut journal = open_journal(&groups);
    let authority = TestKey::from_seed([1; 32]);
    let mut signer = TestKey::from_seed([9; 32]);
    let mut entry = RegistryEntry {
        action: RegistryAction::Register,
        algorithm: Algorithm::Ed25519,
        custody: Custody::NoSeparation,
        sequence: 0,
        key_id: signer.key_id(),
        public: signer.public(),
        // Effective from the next record: the journal holds the group's
        // seals already.
        effective: u64::try_from(journal.records().unwrap().len()).unwrap(),
        evidence: [0; 32],
        endorsement: [0; 64],
    };
    entry.endorsement = authority.sign_bytes(&entry.endorsement_bytes(&ARCHIVE));
    let trust = TrustRoot {
        archive_id: ARCHIVE,
        authorities: vec![authority.public()],
    };
    let mut keys = Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(StdDisk, &groups, KEYS_FILE).unwrap();
    KeyRegistry::new(trust)
        .append(&entry, &mut journal, &mut keys)
        .unwrap();
    let records = journal.records().unwrap();
    assert!(
        records
            .iter()
            .any(|record| record.subject == GROUP && record.kind.is_range()),
        "the agent sealed the group journal"
    );
    let last = records.last().unwrap();
    let head = ChainHead {
        archive_id: ARCHIVE,
        journal_id: 0,
        counter: last.counter,
        digest: last.digest(),
    };
    let signed = SignedHead {
        head,
        key_id: signer.key_id(),
        custody: Custody::NoSeparation,
        signature: signer.sign(&head).unwrap(),
    };
    let mut heads = Ledger::<_, SIGNED_HEAD_LENGTH>::open(StdDisk, &groups, HEADS_FILE).unwrap();
    heads.append(signed.encode()).unwrap();
    let mut anchors = LedgerAnchorStore::open(StdDisk, &archive.anchors(), OPERATOR).unwrap();
    publish_due(
        &mut anchors,
        None,
        Some(&signed),
        std::num::NonZeroU64::new(1).unwrap(),
    )
    .unwrap()
    .unwrap();
    std::fs::write(
        archive.trust(),
        format!(
            "archive {}\nauthority {}\njournal 0\n",
            hex(&ARCHIVE),
            hex(&authority.public())
        ),
    )
    .unwrap();
    let segment = std::fs::read_dir(&groups)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "seg"))
        .unwrap();
    (archive, segment)
}

/// karyos#1088: `karyos-catalog verify` of a groups directory the Archive
/// sealed reports the group journal's ranges verified, and a tampered
/// byte in it inconsistent.
#[test]
fn verify_reports_a_sealed_group_journal_and_its_tampering() {
    let (archive, segment) = sealed_groups("groups");
    let (status, out, err) = full(&archive, false);
    assert_eq!((status, err.as_str()), (0, ""), "{out}");
    let ranges: Vec<&str> = out
        .lines()
        .filter(|line| line.starts_with("recording 5 "))
        .collect();
    assert!(!ranges.is_empty(), "{out}");
    assert!(
        ranges.iter().all(|line| line.contains(" verified ")),
        "{out}"
    );

    let mut bytes = std::fs::read(&segment).unwrap();
    // A byte inside the first sealed range (the data file holds the
    // journal's bytes from position 0): a digest mismatch.
    bytes[20] ^= 0xff;
    std::fs::write(&segment, &bytes).unwrap();
    let (status, out, _) = full(&archive, false);
    assert_eq!(status, EXIT_INCONSISTENT, "{out}");
    assert!(out.contains(" inconsistent "), "{out}");
}

/// An archive directory whose only content is two time evidence entries,
/// sealed in `time-evidence/`, the head there signed and anchored by the
/// operator (karyos#1065) as journal `journal_id`, the trust file's
/// `time-journal 1`. The first entry meets a 1000 ns requirement, the
/// second has no evidence.
fn time_archive(name: &str, journal_id: u64) -> Archive {
    use karyos_archive::integrity::time::{Source, SyncState};
    use karyos_archive::integrity::time_evidence::{Entry, EntryStore, NO_BOUND, entries_dir};

    let root = std::env::temp_dir().join(format!("karyos-verify-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let archive = Archive { root };
    let dir = archive.dir();
    let entries = entries_dir(&dir);
    std::fs::create_dir_all(&entries).unwrap();
    std::fs::create_dir_all(archive.anchors()).unwrap();
    let met = Entry {
        source: Source::Gnss,
        sync_state: SyncState::Synchronised,
        clock: [1, 0, 2, 3, 4],
        recording: 7,
        start: 0,
        end: 4096,
        min_time: 1000,
        max_time: 2000,
        granularity: 1,
        bound_min_ns: 150,
        bound_max_ns: 160,
        calibration: [0xAA; 32],
        utc_reference: [0xBB; 32],
        tick_fs: 1_000_000,
    };
    let missing = Entry {
        start: 4096,
        end: 8192,
        bound_min_ns: NO_BOUND,
        bound_max_ns: NO_BOUND,
        utc_reference: [0; 32],
        ..met
    };
    // The Archive seals recording 7's [0, 8192), which the entries cite
    // (karyos#1137: an entry naming unsealed positions is invalid).
    let mut recording = SegmentStore::create(
        StdDisk,
        &dir,
        7,
        Geometry::new(4096, 8192).unwrap(),
        SyncPolicy::None,
        0,
    )
    .unwrap();
    let bytes = vec![7u8; 8192];
    recording.append(0, &bytes).unwrap();
    recording.sync().unwrap();
    drop(recording);
    let mut sealed = open_journal(&dir);
    sealed.seal_segment(7, 0, &bytes[..4096], false).unwrap();
    sealed.seal_segment(7, 4096, &bytes[4096..], false).unwrap();
    drop(sealed);
    let mut store = EntryStore::open(StdDisk, &dir).unwrap();
    store.append(&met).unwrap();
    store.append(&missing).unwrap();
    drop(store);
    sign_time_evidence(&archive, &entries, journal_id);
    archive
}

/// Signs and anchors the head of the time evidence journal in `entries` as
/// journal `journal_id`, the operator's, and writes the trust file naming
/// it `time-journal 1`.
fn sign_time_evidence(archive: &Archive, entries: &Path, journal_id: u64) {
    let mut journal = open_journal(entries);
    let authority = TestKey::from_seed([1; 32]);
    let mut signer = TestKey::from_seed([9; 32]);
    let mut entry = RegistryEntry {
        action: RegistryAction::Register,
        algorithm: Algorithm::Ed25519,
        custody: Custody::NoSeparation,
        sequence: 0,
        key_id: signer.key_id(),
        public: signer.public(),
        effective: u64::try_from(journal.records().unwrap().len()).unwrap(),
        evidence: [0; 32],
        endorsement: [0; 64],
    };
    entry.endorsement = authority.sign_bytes(&entry.endorsement_bytes(&ARCHIVE));
    let trust = TrustRoot {
        archive_id: ARCHIVE,
        authorities: vec![authority.public()],
    };
    let mut keys = Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(StdDisk, entries, KEYS_FILE).unwrap();
    KeyRegistry::new(trust)
        .append(&entry, &mut journal, &mut keys)
        .unwrap();
    let records = journal.records().unwrap();
    let last = records.last().unwrap();
    let head = ChainHead {
        archive_id: ARCHIVE,
        journal_id,
        counter: last.counter,
        digest: last.digest(),
    };
    let signed = SignedHead {
        head,
        key_id: signer.key_id(),
        custody: Custody::NoSeparation,
        signature: signer.sign(&head).unwrap(),
    };
    let mut heads = Ledger::<_, SIGNED_HEAD_LENGTH>::open(StdDisk, entries, HEADS_FILE).unwrap();
    heads.append(signed.encode()).unwrap();
    let mut anchors = LedgerAnchorStore::open(StdDisk, &archive.anchors(), OPERATOR).unwrap();
    publish_due(
        &mut anchors,
        None,
        Some(&signed),
        std::num::NonZeroU64::new(1).unwrap(),
    )
    .unwrap()
    .unwrap();
    std::fs::write(
        archive.trust(),
        format!(
            "archive {}\nauthority {}\njournal 0\ntime-journal 1\n",
            hex(&ARCHIVE),
            hex(&authority.public())
        ),
    )
    .unwrap();
}

/// A whole data frame of trace stream `message`, aligned.
fn trace_frame(message: &karyos_trace::stream::StreamMessage) -> Vec<u8> {
    use karyos_sys::frame::{FRAME_ALIGNMENT, Flags, FrameType, HEADER_LENGTH, Lane, Word0};
    let mut payload = [0u8; karyos_trace::stream::MAX_MESSAGE_BYTES];
    let length = message.encode(&mut payload).unwrap();
    let frame = HEADER_LENGTH as usize + length;
    let word0 = Word0::new(
        i32::try_from(frame).unwrap(),
        Flags::new(true, true, false, false, Lane::ZERO),
        FrameType::Data,
    );
    let mut bytes = vec![0u8; HEADER_LENGTH as usize];
    bytes[..8].copy_from_slice(&word0.pack().to_le_bytes());
    bytes.extend_from_slice(&payload[..length]);
    bytes.resize(frame.next_multiple_of(FRAME_ALIGNMENT as usize), 0);
    bytes
}

/// ADR-0117 point 5 and 10: a trace recording (recording 7, its first
/// message the self message) holding a loss message reports the loss
/// beside its verdict, which is never `met`; `--recording` reports one
/// recording alone and needs a requirement.
#[test]
fn verify_reports_a_trace_recordings_losses_and_one_recording_alone() {
    use karyos_archive::integrity::time::{Source, SyncState};
    use karyos_archive::integrity::time_evidence::{Entry, EntryStore, NO_BOUND, entries_dir};
    use karyos_trace::stream::{DriverSelf, StreamLoss, StreamMessage};

    let root = std::env::temp_dir().join(format!("karyos-verify-trace-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let archive = Archive { root };
    let dir = archive.dir();
    std::fs::create_dir_all(entries_dir(&dir)).unwrap();
    std::fs::create_dir_all(archive.anchors()).unwrap();
    let mut bytes = trace_frame(&StreamMessage::DriverSelf(DriverSelf {
        namespace: 1,
        namespace_inode: 9,
        clock: [0, 0, 0, 5, 77],
        granularity: 1000,
    }));
    bytes.extend(trace_frame(&StreamMessage::Loss(StreamLoss {
        journal: 7,
        first: 3,
        last: 4,
    })));
    let length = bytes.len() as u64;
    let mut recording = SegmentStore::create(
        StdDisk,
        &dir,
        7,
        Geometry::new(4096, 8192).unwrap(),
        SyncPolicy::None,
        0,
    )
    .unwrap();
    recording.append(0, &bytes).unwrap();
    recording.sync().unwrap();
    drop(recording);
    let mut sealed = open_journal(&dir);
    sealed.seal_segment(7, 0, &bytes, false).unwrap();
    drop(sealed);
    // One entry of the met kind covers the whole range: only the loss
    // keeps the verdict from `met`.
    let met = Entry {
        source: Source::Gnss,
        sync_state: SyncState::Synchronised,
        clock: [0, 0, 0, 5, 77],
        recording: 7,
        start: 0,
        end: length,
        min_time: 1000,
        max_time: 2000,
        granularity: 1,
        bound_min_ns: 150,
        bound_max_ns: 160,
        calibration: [0xAA; 32],
        utc_reference: [0xBB; 32],
        tick_fs: 1_000_000,
    };
    assert_ne!(met.bound_max_ns, NO_BOUND);
    let mut store = EntryStore::open(StdDisk, &dir).unwrap();
    store.append(&met).unwrap();
    drop(store);
    sign_time_evidence(&archive, &entries_dir(&dir), 1);
    let (_, out, err) = time_run(&archive, &["--time-requirement", "1000:1"]);
    assert_eq!(err, "", "{out}");
    assert!(
        out.contains(&format!("time recording 7 [0, {length}) clock 5:77 met")),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "time recording 7 [0, {length}) loss journal 7 sequences [3, 4] no_evidence"
        )),
        "{out}"
    );
    assert!(
        out.ends_with("time verdict: no_evidence (capture incomplete: 1 losses)\n"),
        "{out}"
    );
    let (_, out, _) = time_run(&archive, &["--time-requirement", "1000:1", "--json"]);
    assert!(
        out.contains(&format!(
            "\"losses\":[{{\"recording\":7,\"start\":0,\"end\":{length},\"journal\":7,\"first\":3,\"last\":4}}]"
        )),
        "{out}"
    );
    // Another recording alone: nothing of 7's, so no evidence and no loss.
    let (_, out, _) = time_run(
        &archive,
        &["--time-requirement", "1000:1", "--recording", "8"],
    );
    assert!(!out.contains("time recording 7"), "{out}");
    assert!(out.ends_with("time verdict: no_evidence\n"), "{out}");
    let (_, out, _) = time_run(
        &archive,
        &["--time-requirement", "1000:1", "--recording", "7"],
    );
    assert!(out.contains("loss journal 7"), "{out}");
    assert_eq!(
        usage(&["d", "--recording", "7"]),
        UsageError::RecordingNeedsRequirement
    );
    for bad in ["0", "x"] {
        assert_eq!(
            usage(&["d", "--recording", bad, "--time-requirement", "1:1"]),
            UsageError::Recording
        );
    }
}

/// karyos#1128: the requirement a trace recording carries (karyosd
/// --archive-time-requirement) judges its entries when verify is given no
/// --time-requirement: recording 7 carries 1000:1 (met), recording 8
/// 100:1 (not_met). A --time-requirement is the verifier's own and
/// overrides what the recordings carry, reported as such.
#[test]
fn verify_judges_entries_against_the_requirement_their_recording_carries() {
    use karyos_archive::integrity::time::{Source, SyncState};
    use karyos_archive::integrity::time_evidence::{Entry, EntryStore, entries_dir};
    use karyos_trace::stream::{DriverSelf, StreamMessage, TimeRequirement};

    let root = std::env::temp_dir().join(format!("karyos-verify-carried-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let archive = Archive { root };
    let dir = archive.dir();
    std::fs::create_dir_all(entries_dir(&dir)).unwrap();
    std::fs::create_dir_all(archive.anchors()).unwrap();
    let mut journal = open_journal(&dir);
    let mut store_entries = Vec::new();
    for (recording, divergence) in [(7u64, 1000u64), (8, 100)] {
        let mut bytes = trace_frame(&StreamMessage::DriverSelf(DriverSelf {
            namespace: 1,
            namespace_inode: 9,
            clock: [0, 0, 0, 5, 77],
            granularity: 1000,
        }));
        bytes.extend(trace_frame(&StreamMessage::Requirement(TimeRequirement {
            domain: 5,
            max_divergence_ns: divergence,
            max_granularity_ns: 1,
        })));
        let length = bytes.len() as u64;
        let mut store = SegmentStore::create(
            StdDisk,
            &dir,
            recording,
            Geometry::new(4096, 8192).unwrap(),
            SyncPolicy::None,
            0,
        )
        .unwrap();
        store.append(0, &bytes).unwrap();
        store.sync().unwrap();
        drop(store);
        journal.seal_segment(recording, 0, &bytes, false).unwrap();
        store_entries.push(Entry {
            source: Source::Gnss,
            sync_state: SyncState::Synchronised,
            clock: [0, 0, 0, 5, 77],
            recording,
            start: 0,
            end: length,
            min_time: 1000,
            max_time: 2000,
            granularity: 1,
            bound_min_ns: 150,
            bound_max_ns: 160,
            calibration: [0xAA; 32],
            utc_reference: [0xBB; 32],
            tick_fs: 1_000_000,
        });
    }
    drop(journal);
    let mut store = EntryStore::open(StdDisk, &dir).unwrap();
    for entry in &store_entries {
        store.append(entry).unwrap();
    }
    drop(store);
    sign_time_evidence(&archive, &entries_dir(&dir), 1);
    let (_, out, err) = time_run(&archive, &[]);
    assert_eq!(err, "", "{out}");
    assert!(out.contains("time recording 7 [0, "), "{out}");
    assert!(out.contains("clock 5:77 met\n"), "{out}");
    assert!(out.contains("clock 5:77 not_met\n"), "{out}");
    assert!(
        out.contains(
            "time requirement of recording 7 clock domain 5: declared 1000:1, applied 1000:1 (recorded)"
        ),
        "{out}"
    );
    assert!(out.ends_with("time verdict: not_met\n"), "{out}");
    // Recording 7 alone: its own requirement, met.
    let (_, out, _) = time_run(&archive, &["--recording", "7"]);
    assert!(out.ends_with("time verdict: met\n"), "{out}");
    // A flag that agrees with recording 7, alone.
    // The flag is the verifier's own requirement: it overrides both, and
    // says so.
    let (status, out, _) = time_run(&archive, &["--time-requirement", "1000:1"]);
    assert_eq!(status, 1, "{out}");
    // Both shown, always; looser than declared is flagged: 1000 ns
    // against recording 8's 100, but not against recording 7's 1000.
    assert!(
        out.contains("time requirement of recording 8 clock domain 5: declared 100:1, applied 1000:1 (--time-requirement, looser than declared)"),
        "{out}"
    );
    assert!(
        out.contains("time requirement of recording 7 clock domain 5: declared 1000:1, applied 1000:1 (--time-requirement)"),
        "{out}"
    );
    assert!(!out.contains("not_met"), "{out}");
    // Coarser granularity alone is looser too; stricter on both is not.
    let (_, out, _) = time_run(&archive, &["--time-requirement", "100:2"]);
    assert!(
        out.contains("declared 100:1, applied 100:2 (--time-requirement, looser than declared)"),
        "{out}"
    );
    let (_, out, _) = time_run(&archive, &["--time-requirement", "10:1"]);
    assert!(!out.contains("looser"), "{out}");
    assert!(
        out.contains("declared 1000:1, applied 10:1 (--time-requirement)"),
        "{out}"
    );
}

fn time_run(archive: &Archive, extra: &[&str]) -> (u8, String, String) {
    let mut argv: Vec<OsString> = vec![
        archive.dir().into(),
        "--trust".into(),
        archive.trust().into(),
        // The entries' own journal is anchored in its own store.
        "--time-anchors".into(),
        format!("{}={}", hex(&OPERATOR), archive.anchors().display()).into(),
    ];
    argv.extend(extra.iter().map(OsString::from));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run_verify(argv, &mut out, &mut err);
    (
        status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// karyos#1065: the time verdict of verified entries, per entry and
/// combined, apart from integrity; none without a requirement.
#[test]
fn verify_reports_the_time_verdict_of_verified_entries() {
    let archive = time_archive("time", 1);
    // The Archive's own chain seals recording 7 unsigned in this fixture,
    // so integrity is unverifiable (1); the time verdict stays apart.
    let (status, out, err) = time_run(&archive, &[]);
    assert_eq!((status, err.as_str()), (1, ""), "{out}");
    assert!(
        out.contains("time evidence: not evaluated by the integrity verifier"),
        "{out}"
    );
    let (status, out, err) = time_run(&archive, &["--time-requirement", "1000:1"]);
    assert_eq!((status, err.as_str()), (1, ""), "{out}");
    assert!(
        out.contains("time recording 7 [0, 4096) clock 3:4 met"),
        "{out}"
    );
    assert!(
        out.contains("time recording 7 [4096, 8192) clock 3:4 no_evidence"),
        "{out}"
    );
    assert!(out.ends_with("time verdict: no_evidence\n"), "{out}");
    let (_, out, _) = time_run(&archive, &["--time-requirement", "155:1"]);
    assert!(out.contains("[0, 4096) clock 3:4 not_met"), "{out}");
    assert!(out.ends_with("time verdict: not_met\n"), "{out}");
    let (_, out, _) = time_run(&archive, &["--time-requirement", "1000:1", "--json"]);
    assert!(
        out.contains("\"time\":{\"verdict\":\"no_evidence\",\"entries\":[{\"recording\":7,\"start\":0,\"end\":4096,\"domain\":3,\"epoch\":4,\"verdict\":\"met\"}"),
        "{out}"
    );
    // Both sealed ranges are covered: no gap.
    assert!(out.contains("\"gaps\":[]"), "{out}");
    // The entries' journal has its own anchor store: a requirement
    // without it is a usage error, never an unverified `no_evidence`.
    assert_eq!(
        usage(&["d", "--time-requirement", "1000:1"]),
        UsageError::TimeAnchorsRequired
    );
    assert_eq!(
        usage(&["d", "--time-requirement", "x"]),
        UsageError::TimeRequirement
    );
}

/// karyos#1138 review P2: the entries' journal is verified as the trust
/// file's `time-journal`, never as the integrity journal: a head and
/// anchor naming the integrity journal's identity is `WrongJournal`, so
/// its entries have no evidence.
#[test]
fn time_evidence_anchored_as_another_journal_has_no_evidence() {
    let archive = time_archive("time-wrong-journal", 0);
    let (_, out, _) = time_run(&archive, &["--time-requirement", "1000:1"]);
    assert!(
        out.contains("time recording 7 [0, 4096) clock 3:4 no_evidence"),
        "{out}"
    );
    assert!(out.ends_with("time verdict: no_evidence\n"), "{out}");
}

/// karyos#1128: the time evidence journal's identity is the trust
/// file's `time-journal`, never guessed and never the journal's own;
/// without that line, time evidence is refused with a clear error.
#[test]
fn the_time_journal_is_another_than_the_journal() {
    use super::parse_trust_journals;
    let base = format!("archive {}\nauthority {}\n", hex(&ARCHIVE), hex(&[3; 32]));
    assert_eq!(parse_trust_journals(&base).unwrap().3, None);
    let explicit = format!("{base}journal 4\ntime-journal 9\n");
    let parsed = parse_trust_journals(&explicit).unwrap();
    assert_eq!((parsed.2, parsed.3), (4, Some(9)));
    assert_eq!(
        parse_trust_journals(&format!("{base}journal 4\ntime-journal 4\n")).unwrap_err(),
        TrustError::TimeJournal
    );
    // A time verdict asked of a trust file with no `time-journal` line.
    let archive = time_archive("time-no-journal-line", 1);
    std::fs::write(
        archive.trust(),
        format!(
            "archive {}\nauthority {}\njournal 0\n",
            hex(&ARCHIVE),
            hex(&[3; 32])
        ),
    )
    .unwrap();
    let (status, _, err) = time_run(&archive, &["--time-requirement", "1000:1"]);
    assert_eq!(status, 2, "{err}");
    assert!(err.contains("no time-journal line"), "{err}");
}

/// karyos#1087: each copy the chain commits is reported with its state
/// and enforcement, in text and JSON.
#[test]
fn verify_reports_each_copy_and_its_enforcement() {
    use karyos_archive::integrity::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
    let archive = archive("copies");
    let dir = archive.dir();
    {
        let mut journal = open_journal(&dir);
        let mut copies = CopyCatalog::open(StdDisk, &dir, &mut journal).unwrap();
        for (location, enforcement) in [
            ([0x11u8; 32], Enforcement::ImmutableAttribute),
            ([0x22u8; 32], Enforcement::Unsupported),
        ] {
            copies
                .record(
                    CopyRecord {
                        sequence: 0,
                        recording: RECORDING,
                        start: 0,
                        end: 48,
                        location,
                        digest: [0; 32],
                        retain_until_ns: 0,
                        state: CopyState::Verified,
                        enforcement,
                        profile: karyos_archive::integrity::copies::ArrivalProfile::Local,
                    },
                    &mut journal,
                )
                .unwrap();
        }
    }
    let (_, out, err) = full(&archive, false);
    assert_eq!(err, "", "{out}");
    assert!(
        out.contains(&format!(
            "copy recording 3 [0, 48) location {} verified enforcement immutable_attribute observed not_checked\n",
            hex(&[0x11; 32])
        )),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "copy recording 3 [0, 48) location {} verified enforcement none observed not_checked\n",
            hex(&[0x22; 32])
        )),
        "{out}"
    );
    let (_, out, _) = full(&archive, true);
    assert!(
        out.contains("\"copies\":[{\"recording\":3,\"start\":0,\"end\":48,"),
        "{out}"
    );
    assert!(
        out.contains("\"enforcement\":\"immutable_attribute\""),
        "{out}"
    );
}

/// Records one copy of `[0, 48)` of the test recording per entry of
/// `changes`, each a location, a state and an enforcement, in order.
fn record_copies(
    dir: &Path,
    changes: &[(
        [u8; 32],
        karyos_archive::integrity::copies::CopyState,
        karyos_archive::integrity::copies::Enforcement,
    )],
) {
    use karyos_archive::integrity::copies::{CopyCatalog, CopyRecord};
    let mut journal = open_journal(dir);
    let mut copies = CopyCatalog::open(StdDisk, dir, &mut journal).unwrap();
    for &(location, state, enforcement) in changes {
        copies
            .record(
                CopyRecord {
                    sequence: 0,
                    recording: RECORDING,
                    start: 0,
                    end: 48,
                    location,
                    digest: [0; 32],
                    retain_until_ns: 0,
                    state,
                    enforcement,
                    profile: karyos_archive::integrity::copies::ArrivalProfile::Local,
                },
                &mut journal,
            )
            .unwrap();
    }
}

/// karyos#1087 review: the copies are replayed from the journal snapshot
/// the verification checked, limited to its accepted prefix. A matching
/// copy update chained after the journal's first inconsistent record
/// never changes the reported copy state.
#[test]
fn a_copy_update_after_a_chain_break_does_not_change_the_copy_state() {
    use karyos_archive::integrity::copies::{CopyState, Enforcement};
    let archive = archive("copies-break");
    let dir = archive.dir();
    record_copies(
        &dir,
        &[
            ([0x11; 32], CopyState::Verified, Enforcement::Unsupported),
            ([0x11; 32], CopyState::Removed, Enforcement::Unsupported),
        ],
    );
    // The first copy change, still decodable, no longer chains to the
    // second: the journal breaks at the second, position 8.
    let path = IntegrityJournal::<StdDisk>::path(&dir);
    let mut bytes = std::fs::read(&path).unwrap();
    let length = karyos_archive::integrity::SEAL_RECORD_LENGTH;
    let at = 7 * length;
    let mut record =
        karyos_archive::integrity::SealRecord::decode(&bytes[at..at + length]).unwrap();
    record.end ^= 1;
    bytes[at..at + length].copy_from_slice(&record.encode());
    std::fs::write(&path, bytes).unwrap();
    let (status, out, err) = full(&archive, false);
    assert_eq!(err, "", "{out}");
    assert_eq!(status, EXIT_INCONSISTENT, "{out}");
    assert!(
        out.contains("journal inconsistent first_inconsistent=8"),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "copy recording 3 [0, 48) location {} verified enforcement none",
            hex(&[0x11; 32])
        )),
        "{out}"
    );
    assert!(!out.contains("removed"), "{out}");
}

/// karyos#1087 review: a copy change the chain commits whose record the
/// copy catalog no longer holds is an inconsistency of the report (exit
/// 1, the report written, JSON included), never an error that discards
/// it.
#[test]
fn a_truncated_copy_catalog_is_reported_inconsistent_not_an_error() {
    use karyos_archive::integrity::copies::{COPIES_FILE, CopyState, Enforcement};
    let archive = archive("copies-truncated");
    let dir = archive.dir();
    record_copies(
        &dir,
        &[([0x11; 32], CopyState::Verified, Enforcement::Unsupported)],
    );
    std::fs::write(dir.join(COPIES_FILE), b"").unwrap();
    let (status, out, err) = full(&archive, false);
    assert_eq!(err, "", "{out}");
    assert_eq!(status, EXIT_INCONSISTENT, "{out}");
    assert!(
        out.contains("copies inconsistent first_inconsistent=7"),
        "{out}"
    );
    let (status, out, err) = full(&archive, true);
    assert_eq!(err, "", "{out}");
    assert_eq!(status, EXIT_INCONSISTENT, "{out}");
    assert!(
        out.contains("\"copies\":[],\"copies_first_inconsistent\":7"),
        "{out}"
    );
}

/// karyos#1087 review: the immutable attribute of a copy in this
/// directory is read from its segment files, never assumed from the
/// record. A copy recorded immutable whose files do not carry the
/// attribute is reported with what they carry and, where they plainly do
/// not, as an enforcement mismatch (exit 1).
#[test]
fn verify_reads_the_attribute_of_a_local_copy_from_its_files() {
    use karyos_archive::integrity::copies::{CopyState, Enforcement};
    let archive = archive("copies-observed");
    let dir = archive.dir();
    record_copies(
        &dir,
        &[(
            ARCHIVE,
            CopyState::Verified,
            Enforcement::ImmutableAttribute,
        )],
    );
    let (status, out, err) = full(&archive, false);
    assert_eq!(err, "", "{out}");
    let prefix = format!(
        "copy recording 3 [0, 48) location {} verified enforcement immutable_attribute observed ",
        hex(&ARCHIVE)
    );
    let line = out
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("{out}"));
    assert!(!line.contains("observed immutable_attribute"), "{out}");
    if line.contains("observed none") {
        assert!(line.ends_with(" enforcement_mismatch"), "{out}");
        assert_eq!(status, EXIT_INCONSISTENT, "{out}");
        let (_, json_out, _) = full(&archive, true);
        assert!(
            json_out.contains("\"observed\":\"none\",\"mismatch\":true"),
            "{json_out}"
        );
    } else {
        // A file system with no attribute to read.
        assert!(line.ends_with("observed unknown"), "{out}");
    }
    if cfg!(target_os = "macos") {
        assert!(line.contains("observed none"), "{out}");
    }
}

/// karyos#1087 review: on macOS the owner may set the user immutable flag
/// (`chflags uchg`), and a copy whose every segment file carries it is
/// reported as carrying the attribute, with no mismatch.
#[cfg(target_os = "macos")]
#[test]
fn verify_reports_the_immutable_flag_its_files_carry() {
    use karyos_archive::integrity::copies::{CopyState, Enforcement};
    struct Flagged(Vec<PathBuf>);
    impl Drop for Flagged {
        fn drop(&mut self) {
            for file in &self.0 {
                let _ = std::process::Command::new("chflags")
                    .arg("nouchg")
                    .arg(file)
                    .status();
            }
        }
    }
    let archive = archive("copies-flagged");
    let dir = archive.dir();
    record_copies(
        &dir,
        &[(
            ARCHIVE,
            CopyState::Verified,
            Enforcement::ImmutableAttribute,
        )],
    );
    let prefix = format!("{RECORDING:016x}-");
    let files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".seg"))
        })
        .collect();
    assert!(!files.is_empty());
    let flagged = Flagged(files);
    for file in &flagged.0 {
        let status = std::process::Command::new("chflags")
            .arg("uchg")
            .arg(file)
            .status()
            .unwrap();
        assert!(status.success());
    }
    let (_, out, err) = full(&archive, false);
    assert_eq!(err, "", "{out}");
    assert!(
        out.contains(&format!(
            "copy recording 3 [0, 48) location {} verified enforcement immutable_attribute observed immutable_attribute\n",
            hex(&ARCHIVE)
        )),
        "{out}"
    );
    drop(flagged);
}

/// Opens the integrity journal of `dir`. An agent's shutdown releases the
/// journal's lock, but `flock` belongs to the open file description: a
/// child another test of this binary forks while the agent's file was open
/// shares it until the child execs, so `Locked` can be seen for that
/// instant (karyos#1148). Retried, bounded.
/// Opens the journal in `dir`, retrying while it is `Locked` for about 30 s
/// (the last try may follow a late sleep): a handle the test dropped can
/// still hold the lock for a moment (karyos#1067). A time window, not a
/// count of tries, which a loaded host stretched.
pub(crate) fn open_journal(dir: &std::path::Path) -> IntegrityJournal<StdDisk> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match IntegrityJournal::open(StdDisk, dir) {
            Ok(opened) => break opened.journal,
            Err(karyos_archive::integrity::journal::IntegrityError::Locked)
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => panic!("{error:?}"),
        }
    }
}

/// karyos#1137 (ADR-0098 item 2; docs#975): entries are checked against
/// what their directory's chain seals. A sealed range no entry covers is
/// reported `no_evidence`; an entry naming positions the chain does not
/// seal, or a zero identity entry other than the sentinel, is an
/// integrity failure (exit 2), never a verdict.
#[test]
fn time_evidence_is_checked_against_its_directorys_seals() {
    use karyos_archive::integrity::time_evidence::{Entry, EntryStore, NO_BOUND, entries_dir};
    let archive = time_archive("time-coverage", 1);
    let dir = archive.dir();
    // A third range, sealed, with no entry.
    let mut recording = SegmentStore::recover(
        StdDisk,
        &dir,
        7,
        Geometry::new(4096, 8192).unwrap(),
        SyncPolicy::None,
    )
    .unwrap()
    .store;
    let bytes = vec![7u8; 4096];
    recording.append(8192, &bytes).unwrap();
    recording.sync().unwrap();
    drop(recording);
    let mut sealed = open_journal(&dir);
    sealed.seal_segment(7, 8192, &bytes, false).unwrap();
    drop(sealed);
    let (_, out, _) = time_run(&archive, &["--time-requirement", "1000:1"]);
    assert!(
        out.contains("time recording 7 [8192, 12288) uncovered no_evidence"),
        "{out}"
    );
    assert!(out.ends_with("time verdict: no_evidence\n"), "{out}");
    let base = time_evidence_first(&dir);
    // An entry naming positions the chain does not seal, appended to a
    // fresh copy's store: exit 2.
    let copy = time_archive("time-invalid-unsealed", 1);
    let mut store = EntryStore::open(StdDisk, &copy.dir()).unwrap();
    store
        .append(&Entry {
            start: 12_288,
            end: 16_384,
            ..base
        })
        .unwrap();
    drop(store);
    let (status, _, err) = time_run(&copy, &["--time-requirement", "1000:1"]);
    assert_eq!(status, 2, "{err}");
    assert!(err.contains("invalid time evidence entry"), "{err}");
    // A zero identity entry with a bound, as a store written by another
    // build could hold (this build's store refuses it): invalid.
    let bad = Entry {
        clock: [0; 5],
        ..base
    };
    assert!(matches!(
        super::coverage(&dir, &entries_dir(&dir), &[bad]),
        Err(super::VerifyError::InvalidTimeEvidence { .. })
    ));
    // Two entries over the same positions: invalid.
    assert!(matches!(
        super::coverage(&dir, &entries_dir(&dir), &[base, base]),
        Err(super::VerifyError::InvalidTimeEvidence { .. })
    ));
    let _ = NO_BOUND;
}

/// The first entry of `dir`'s store.
fn time_evidence_first(dir: &std::path::Path) -> karyos_archive::integrity::time_evidence::Entry {
    karyos_archive::integrity::time_evidence::read_sealed(StdDisk, dir).unwrap()[0]
}

/// karyos#1137's last acceptance point: a group recorded by a running
/// Archive agent, whose calibration source is the one `karyosd
/// --archive-calibration-journal` gives it, gets time evidence entries
/// from the records `karyos-tools calibrate append` writes to the journal
/// on disk, including records appended after the group's events, while
/// the agent waits for them; `verify --time-requirement` then reports a
/// verdict. The UTC reference records are synthetic: no hardware here is
/// UTC traceable, and nothing here claims UTC.
#[cfg(target_os = "linux")]
#[test]
fn a_group_gets_time_evidence_from_the_calibration_journal_on_disk() {
    use karyos_archive::agent::{
        AgentConfig, ArchiveHandle, GroupTimeEvidence, NewGroup, StartGroup,
    };
    use karyos_archive::group::capture::CaptureConfig;
    use karyos_archive::group::journal::JournalConfig;
    use karyos_archive::group::record::{
        Capture, EndOutcome, EventEnd, ExternalEvent, GroupRecord, MAX_RECORD,
    };
    use karyos_archive::integrity::time_evidence::{NO_BOUND, entries_dir, read_sealed};
    use karyos_archive::integrity::time_producer::EventClock;
    use karyos_trace::clocks::utc::{
        Scale, Source as UtcSource, SyncState as UtcSync, UtcReference,
    };
    use karyos_trace::clocks::{Calibration, ClockKey};
    use karyos_trace::journal::ObserverId;

    const GROUP: u64 = 5;
    let key = |[low, high, journal, domain, epoch]: [u64; 5]| ClockKey {
        observer: ObserverId {
            driver: [low, high],
            journal,
        },
        domain,
        epoch,
    };
    let calibration = |valid_from: u64, valid_to: u64| {
        Calibration {
            from: key([1, 0, 2, 3, 4]),
            to: key([9, 0, 9, 9, 9]),
            reference: valid_from,
            offset: 10,
            offset_uncertainty: 2,
            drift: 0,
            drift_uncertainty: 0,
            valid_from,
            valid_to,
        }
        .encode()
        .unwrap()
    };
    let reference = |valid_from: u64, valid_to: u64| {
        UtcReference {
            clock: key([9, 0, 9, 9, 9]),
            source: UtcSource::Gnss,
            sync_state: UtcSync::Synchronised,
            bound: 100,
            valid_from,
            valid_to,
            tick_fs: 1_000_000,
            scale: Scale::Tai,
            origin: 0,
            origin_scale_ns: 2_000_000_000_000_000_000,
            leap_table: 69,
            transform_uncertainty_ns: 0,
        }
        .encode()
        .unwrap()
    };
    let root = std::env::temp_dir().join(format!(
        "karyos-verify-calibration-journal-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let archive = Archive { root };
    let groups = archive.dir();
    std::fs::create_dir_all(entries_dir(&groups)).unwrap();
    std::fs::create_dir_all(archive.anchors()).unwrap();
    let host = archive.root.join("host");
    std::fs::create_dir_all(&host).unwrap();
    let calibrations = archive.root.join("calibrations");
    // The producer's CLI, as an operator pipes `calibrate phc` into it.
    let append = |records: &[[u64; 18]]| {
        let text: String = records
            .iter()
            .map(|words| {
                let words: Vec<String> = words.iter().map(|word| format!("{word:#018x}")).collect();
                format!("record {}\n", words.join(" "))
            })
            .collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = crate::calibrate::journal::run(
            [OsString::from("--journal"), calibrations.clone().into()].into_iter(),
            &mut std::io::Cursor::new(text.into_bytes()),
            &mut out,
            &mut err,
        );
        assert_eq!(status, 0, "{}", String::from_utf8_lossy(&err));
    };
    append(&[calibration(0, 100), reference(0, 1999)]);

    // karyosd's own path: its arguments parsed, then the source its start
    // sets on the agent from them.
    let parsed = match crate::args::parse(
        [
            "--dir",
            "/run/k",
            "--archive",
            host.to_str().unwrap(),
            "--archive-control",
            "100,101",
            "--archive-anchor-interval",
            "3600s",
            "--archive-calibration-journal",
            calibrations.to_str().unwrap(),
        ]
        .iter()
        .map(OsString::from),
    )
    .unwrap()
    {
        crate::args::Command::Run(options) => options.archive.unwrap(),
        _ => panic!("expected options"),
    };
    assert_eq!(
        parsed.calibration_journal.as_deref(),
        Some(calibrations.as_path())
    );
    let daemon_source = crate::daemon_archive::configured_calibration_source(&parsed).unwrap();
    let config =
        AgentConfig::default().with_seal_interval(Some(std::time::Duration::from_millis(1)));
    let agent = ArchiveHandle::spawn(StdDisk, &host, config).unwrap();
    agent.set_calibration_source(daemon_source).unwrap();
    let clock = EventClock {
        clock: [1, 0, 2, 3, 4],
        granularity: 1,
    };
    let start = StartGroup::new(
        GROUP,
        groups.clone(),
        JournalConfig::new(
            karyos_archive::group::journal::MIN_SEGMENT_LENGTH,
            SyncPolicy::Every { interval_ns: 0 },
        ),
        CaptureConfig::new(1 << 16, 4096, 64),
    )
    .with_new(NewGroup::new(1, 4096, Capture::Strict, b"m".to_vec()))
    .with_time_evidence(GroupTimeEvidence::new(
        clock,
        std::time::Duration::from_secs(30),
    ));
    let mut sender = agent.start_group(start).unwrap();
    let mut out = vec![0u8; MAX_RECORD];
    for seq in 1..=3u64 {
        let mut bytes = Vec::new();
        for record in [
            GroupRecord::External(ExternalEvent {
                group_seq: seq,
                logical_time: seq,
                kind: 1,
                value: b"x",
            }),
            GroupRecord::End(EventEnd {
                group_seq: seq,
                observations: 0,
                outcome: EndOutcome::Complete,
            }),
        ] {
            let length = record.encode(&mut out).unwrap();
            bytes.extend_from_slice(&out[..length]);
        }
        sender.admit().unwrap();
        sender.send(&bytes, seq).unwrap();
    }
    assert_eq!(
        sender
            .waiter()
            // Each write is synced (`SyncPolicy::Every`): on a loaded host
            // running the whole suite in parallel, 5 s was not always
            // enough for three syncs. The wait only bounds a stall.
            .wait_durable(3, std::time::Duration::from_secs(60)),
        Ok(3)
    );
    // The range is sealed and waits: the journal holds no completeness
    // boundary past it yet.
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(read_sealed(StdDisk, &groups).unwrap().is_empty());
    // The producer publishes past it, while the agent runs.
    append(&[calibration(1000, 2000), reference(2000, 3000)]);
    let mut entries = Vec::new();
    for _ in 0..10_000 {
        entries = read_sealed(StdDisk, &groups).unwrap();
        if !entries.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    agent.shutdown().unwrap();
    assert!(!entries.is_empty(), "no entry produced");
    for entry in &entries {
        assert_eq!(entry.recording, GROUP);
        assert_eq!(entry.clock, [1, 0, 2, 3, 4]);
        assert_ne!(entry.bound_min_ns, NO_BOUND);
        assert_ne!(entry.utc_reference, [0; 32]);
    }

    sign_time_evidence(&archive, &entries_dir(&groups), 1);
    let (_, out, err) = time_run(&archive, &["--time-requirement", "1000:1"]);
    assert_eq!(err, "", "{out}");
    // Every event range is met through the journal's records. The group
    // journal's header, before the session's first event, carries no
    // timestamp and has no entry, as for any group (karyos#1137): it is
    // the one uncovered range, so the combined verdict stays no_evidence.
    let first = entries.iter().map(|entry| entry.start).min().unwrap();
    let ranges: Vec<&str> = out
        .lines()
        .filter(|line| line.starts_with(&format!("time recording {GROUP} [")))
        .collect();
    assert!(!ranges.is_empty(), "{out}");
    for line in &ranges {
        if line.contains("uncovered") {
            assert_eq!(
                *line,
                format!("time recording {GROUP} [0, {first}) uncovered no_evidence"),
                "{out}"
            );
        } else {
            assert!(line.ends_with("clock 3:4 met"), "{out}");
        }
    }
    assert_eq!(
        ranges.iter().filter(|line| line.ends_with(" met")).count(),
        entries.len(),
        "{out}"
    );
    let (_, out, _) = time_run(&archive, &["--time-requirement", "50:1"]);
    assert!(out.contains("clock 3:4 not_met"), "{out}");
    assert!(out.ends_with("time verdict: not_met\n"), "{out}");
    std::fs::remove_dir_all(&archive.root).unwrap();
}
