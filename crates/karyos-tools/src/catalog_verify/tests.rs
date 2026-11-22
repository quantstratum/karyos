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
    let mut journal = IntegrityJournal::open(StdDisk, &groups).unwrap().journal;
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
    let mut store = EntryStore::open(StdDisk, &dir).unwrap();
    store.append(&met).unwrap();
    store.append(&missing).unwrap();
    drop(store);

    let mut journal = IntegrityJournal::open(StdDisk, &entries).unwrap().journal;
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
    let mut keys = Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(StdDisk, &entries, KEYS_FILE).unwrap();
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
    let mut heads = Ledger::<_, SIGNED_HEAD_LENGTH>::open(StdDisk, &entries, HEADS_FILE).unwrap();
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
    archive
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
    let (status, out, err) = time_run(&archive, &[]);
    assert_eq!((status, err.as_str()), (0, ""), "{out}");
    assert!(
        out.contains("time evidence: not evaluated by the integrity verifier"),
        "{out}"
    );
    let (status, out, err) = time_run(&archive, &["--time-requirement", "1000:1"]);
    assert_eq!((status, err.as_str()), (0, ""), "{out}");
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
/// file's `time-journal`, by default the journal's plus one, and never
/// the journal's own.
#[test]
fn the_time_journal_is_another_than_the_journal() {
    use super::parse_trust_journals;
    let base = format!("archive {}\nauthority {}\n", hex(&ARCHIVE), hex(&[3; 32]));
    assert_eq!(parse_trust_journals(&base).unwrap().3, 1);
    let explicit = format!("{base}journal 4\ntime-journal 9\n");
    let parsed = parse_trust_journals(&explicit).unwrap();
    assert_eq!((parsed.2, parsed.3), (4, 9));
    for refused in [
        format!("{base}journal 4\ntime-journal 4\n"),
        format!("{base}journal {}\n", u64::MAX),
    ] {
        assert_eq!(
            parse_trust_journals(&refused).unwrap_err(),
            TrustError::TimeJournal,
            "{refused:?}"
        );
    }
}
