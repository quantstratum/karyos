// SPDX-License-Identifier: Apache-2.0

//! ADR-0113's Validation, one test per bullet or refusal.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::{Path, PathBuf};

use karyos_archive::integrity::journal::IntegrityJournal;
use karyos_archive::integrity::retention::Operation;
use karyos_archive::integrity::signing::HeadSigner as _;
use karyos_archive::integrity::test_key::TestKey;
use karyos_archive::integrity::trust::{
    Algorithm, ChainHead, Custody, KeyRegistry, RegistryAction, RegistryEntry, SignedHead, key_id,
};

use super::super::TERM_LENGTH;
use super::*;
use crate::retention::{Command, Operation as Op, RetentionAnswer, journal_command};

/// One segment: the tests' journals have segments of one term.
const SEG: u64 = TERM_LENGTH as u64;

/// A fresh directory for test `name`.
fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-journal-retention-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A policy that has expired as soon as a segment closed.
fn expired() -> JournalPolicy {
    JournalPolicy {
        retain_for_ns: 1,
        purge: PurgeMode::Manual,
        min_copies: NonZeroU32::MIN,
    }
}

/// Settings with `policy` and, when given, the copy in `copy`.
fn settings(policy: Option<JournalPolicy>, copy: Option<&Path>) -> JournalRetention {
    let settings = JournalRetention::default().with_policy(policy);
    match copy {
        Some(copy) => settings.with_copy("vault".to_owned(), copy.to_path_buf()),
        None => settings,
    }
}

fn authorised() -> Authorisation {
    Authorisation {
        operator: 1000,
        authorised: true,
    }
}

/// Appends records until the journal has written `until` bytes, the last
/// one durable, so everything is sealed.
fn fill(journal: &mut Journal, until: u64) {
    let mut time = 10;
    while journal.recorder.as_ref().unwrap().store().written() < until {
        let mut record = JournalRecord::new(Kind::CloseRequest, time);
        record.guard = 1;
        record.reason = b"drill".to_vec();
        let _ = journal.append(&record, time).unwrap();
        time += 1;
    }
    let _ = journal
        .append_durable(&JournalRecord::new(Kind::CloseOutcome, time), time)
        .unwrap();
}

/// Copies directory `from` to `to`, as an operator's copy of the journal.
fn copy_dir(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            let _ = std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A journal of three and a half segments, and a copy of it.
fn filled(name: &str, policy: Option<JournalPolicy>) -> (Journal, PathBuf, PathBuf) {
    let dir = dir(name);
    let copy = dir.with_extension("copy");
    let mut journal = Journal::open_small(&dir, 1, settings(policy, Some(&copy))).unwrap();
    fill(&mut journal, 3 * SEG + SEG / 2);
    copy_dir(&dir, &copy);
    (journal, dir, copy)
}

fn reason(reply: &RetentionReply) -> &str {
    match reply {
        RetentionReply::Refused { reason, .. } => reason,
        other => panic!("not refused: {other:?}"),
    }
}

fn start(journal: &Journal) -> u64 {
    journal.recorder.as_ref().unwrap().store().start()
}

fn cleanup(dirs: &[&Path]) {
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A hold makes a purge of an expired range refused; a release with
/// evidence allows it again, and only whole sealed segments go.
#[test]
fn a_hold_refuses_a_purge_until_it_is_released() {
    let (mut journal, dir, copy) = filled("hold", Some(expired()));
    assert_eq!(journal.hold(), "none");
    assert_eq!(
        journal.hold_journal(),
        RetentionReply::Done { evidenced: true }
    );
    assert_eq!(journal.hold(), "held");
    let refused = journal.purge_journal(1, SEG, authorised(), 2);
    assert_eq!(reason(&refused), "legal_hold");
    assert_eq!(start(&journal), 0);
    assert_eq!(
        journal.release_journal(),
        RetentionReply::Done { evidenced: true }
    );
    assert_eq!(journal.hold(), "none");
    assert_eq!(
        journal.purge_journal(2, SEG, authorised(), 3),
        RetentionReply::Done { evidenced: true }
    );
    assert_eq!(start(&journal), SEG);
    let purged = &journal.integrity().unwrap().purged;
    assert_eq!((purged[0].start, purged[0].end), (0, SEG));
    cleanup(&[&dir, &copy]);
}

/// Each refusal, with its reason.
#[test]
fn each_refusal_names_its_reason() {
    let (mut journal, dir, copy) = filled("refusals", Some(expired()));
    let refusal = |journal: &mut Journal, before: u64, authorisation| {
        let reply = journal.purge_journal(7, before, authorisation, 2);
        reason(&reply).to_owned()
    };
    assert_eq!(
        refusal(&mut journal, SEG + 128, authorised()),
        INSIDE_SEGMENT
    );
    assert_eq!(
        refusal(&mut journal, 4 * SEG, authorised()),
        CURRENT_SEGMENT
    );
    let unauthorised = Authorisation {
        operator: 1000,
        authorised: false,
    };
    assert_eq!(refusal(&mut journal, SEG, unauthorised), "not_authorised");
    assert_eq!(start(&journal), 0, "nothing was purged");
    let recording = journal.recording();
    drop(journal);

    // No policy, then one not expired.
    for (policy, name) in [
        (None, "no_policy"),
        (
            Some(JournalPolicy {
                retain_for_ns: 3_600_000_000_000,
                ..expired()
            }),
            "not_expired",
        ),
    ] {
        let mut journal = Journal::open_small(&dir, 3, settings(policy, Some(&copy))).unwrap();
        assert_eq!(refusal(&mut journal, SEG, authorised()), name);
    }

    // No copy, then a copy that does not verify.
    let mut journal = Journal::open_small(&dir, 4, settings(Some(expired()), None)).unwrap();
    assert_eq!(refusal(&mut journal, SEG, authorised()), "below_min_copies");
    drop(journal);
    let segment = copy.join(format!("{recording:016x}-{:016x}.seg", 0));
    let mut bytes = std::fs::read(&segment).unwrap();
    bytes[200] ^= 0xff;
    std::fs::write(&segment, bytes).unwrap();
    let mut journal = Journal::open_small(&dir, 5, settings(Some(expired()), Some(&copy))).unwrap();
    assert_eq!(refusal(&mut journal, SEG, authorised()), "below_min_copies");
    assert_eq!(start(&journal), 0, "nothing was purged");
    cleanup(&[&dir, &copy]);
}

/// A hold neither its marker nor its ledger could record answers `hold
/// not durable`, and every purge is refused for it.
#[test]
fn a_hold_not_durable_refuses_every_purge() {
    let (mut journal, dir, copy) = filled("not-durable", Some(expired()));
    fault::fail(true);
    assert_eq!(journal.hold_journal(), RetentionReply::HoldNotDurable);
    assert_eq!(journal.hold(), "not_durable");
    let refused = journal.purge_journal(1, SEG, authorised(), 2);
    fault::fail(false);
    assert_eq!(reason(&refused), HOLD_NOT_DURABLE);
    // A later poll makes it durable once it can; it still holds.
    journal.retry_hold();
    let refused = journal.purge_journal(2, SEG, authorised(), 3);
    assert!(
        [HOLD_NOT_DURABLE, "legal_hold"].contains(&reason(&refused)),
        "{refused:?}"
    );
    assert_eq!(start(&journal), 0);
    cleanup(&[&dir, &copy]);
}

/// A release or a purge whose request cannot be made durable is refused
/// `journal unavailable`, and nothing changes; a refusal is journalled
/// with its reason's code.
#[test]
fn a_purge_without_a_durable_request_is_refused_journal_unavailable() {
    let (mut journal, dir, copy) = filled("unavailable", None);
    let command = |operation| Command {
        operation,
        recording: JOURNAL_SUBJECT,
        id: 9,
        operator: 1000,
        relay: 0,
        reason: b"expired",
    };
    let answer = journal_command(
        Some(&mut journal),
        &command(Op::Purge { before: SEG }),
        (true, &|_| false),
        || 5,
    );
    assert!(
        matches!(&answer, RetentionAnswer::Refused { reason, .. } if reason == "no_policy"),
        "{answer:?}"
    );
    journal.break_recorder();
    for operation in [Op::Purge { before: SEG }, Op::Release] {
        assert_eq!(
            journal_command(
                Some(&mut journal),
                &command(operation),
                (true, &|_| false),
                || 6
            ),
            RetentionAnswer::JournalUnavailable
        );
    }
    drop(journal);
    let journal = Journal::open_small(&dir, 7, settings(None, None)).unwrap();
    let outcome = journal
        .scanned
        .iter()
        .find(|record| record.kind == Kind::PurgeOutcome)
        .unwrap();
    assert_eq!(outcome.guard, JOURNAL_SUBJECT);
    assert_eq!(
        (outcome.code, outcome.word),
        (REFUSED, refusal_word("no_policy"))
    );
    assert_eq!(start(&journal), 0);
    cleanup(&[&dir, &copy]);
}

/// A purge runs through the writer's own store while appends go on, and
/// the verification then shows the prefix purged, with its evidence.
#[test]
fn a_purge_while_appending_is_reported_purged() {
    let (mut journal, dir, copy) = filled("appending", Some(expired()));
    assert_eq!(
        journal.purge_journal(1, 2 * SEG, authorised(), 2),
        RetentionReply::Done { evidenced: true }
    );
    fill(&mut journal, 4 * SEG + SEG / 2);
    journal.verify(3);
    let integrity = journal.integrity().unwrap();
    assert_eq!(integrity.purged.len(), 1);
    assert_eq!(
        (integrity.purged[0].start, integrity.purged[0].end),
        (0, 2 * SEG)
    );
    // Untrusted: the purge's evidence is there, not authenticated.
    let first = &integrity.ranges[0];
    assert_eq!((first.start, first.end), (0, 2 * SEG));
    assert!(
        first.reasons.contains(&"unauthenticated_purge".to_owned()),
        "{first:?}"
    );
    assert!(
        integrity
            .ranges
            .iter()
            .all(|range| !range.reasons.contains(&"corruption".to_owned())
                && !range.reasons.contains(&"shortened_index".to_owned())),
        "{integrity:?}"
    );
    assert!(!journal.purge_pending());
    cleanup(&[&dir, &copy]);
}

/// A crash after the floor advanced but before the purge's seal is
/// reported inconsistent, never clean.
#[test]
fn a_floor_without_its_purge_seal_is_inconsistent() {
    let (mut journal, dir, copy) = filled("floor", Some(expired()));
    let _ = journal.store_mut().purge_before(SEG).unwrap();
    journal.verify(2);
    let integrity = journal.integrity().unwrap();
    assert!(integrity.purged.is_empty());
    let first = &integrity.ranges[0];
    assert_eq!(first.outcome, "inconsistent");
    assert!(
        first.reasons.contains(&"shortened_index".to_owned()),
        "{first:?}"
    );
    cleanup(&[&dir, &copy]);
}

/// Appends `operation` to the operations ledger of the closed journal in
/// `dir`.
fn write_operation(dir: &Path, operation: &Operation) {
    let mut ledger =
        Ledger::<StdDisk, OPERATION_LENGTH>::open(StdDisk, dir, OPERATIONS_FILE).unwrap();
    ledger.append(operation.encode()).unwrap();
}

fn intent(id: u64, recording: u64, before: u64) -> Operation {
    Operation::PurgeIntent {
        id,
        recording,
        before,
        operator: 1000,
        closed_ns: 0,
        source: PurgeSource::Operator,
        from: 0,
    }
}

/// An intent recovery cannot reconcile is `purge_pending` and refuses
/// every further purge.
#[test]
fn an_unreconciled_intent_is_pending_and_blocks_purges() {
    let (journal, dir, copy) = filled("pending", Some(expired()));
    let recording = journal.recording();
    drop(journal);
    write_operation(&dir, &intent(5, recording.wrapping_add(1000), SEG));
    let mut journal = Journal::open_small(&dir, 2, settings(Some(expired()), Some(&copy))).unwrap();
    assert!(journal.purge_pending());
    let refused = journal.purge_journal(6, SEG, authorised(), 3);
    assert_eq!(reason(&refused), PURGE_PENDING);
    assert_eq!(start(&journal), 0);
    cleanup(&[&dir, &copy]);
}

/// A crash between the intent and the deletion is recovered at the next
/// start; a hold applied before that start inhibits the recovered purge.
#[test]
fn a_crash_after_the_intent_is_recovered_unless_a_hold_came_first() {
    for held in [false, true] {
        let name = if held { "recover-held" } else { "recover" };
        let (mut journal, dir, copy) = filled(name, Some(expired()));
        if held {
            assert_eq!(
                journal.hold_journal(),
                RetentionReply::Done { evidenced: true }
            );
        }
        let recording = journal.recording();
        drop(journal);
        write_operation(&dir, &intent(5, recording, SEG));
        let journal = Journal::open_small(&dir, 2, settings(Some(expired()), Some(&copy))).unwrap();
        assert!(!journal.purge_pending(), "reconciled");
        let purged = &journal.integrity().unwrap().purged;
        if held {
            assert_eq!(start(&journal), 0, "the hold inhibits it");
            assert!(purged.is_empty());
        } else {
            assert_eq!(start(&journal), SEG);
            assert_eq!((purged[0].start, purged[0].end), (0, SEG));
        }
        // The recovery's request was made durable first.
        drop(journal);
        let journal = Journal::open_small(&dir, 3, settings(None, None)).unwrap();
        assert!(
            journal
                .scanned
                .iter()
                .any(|record| record.kind == Kind::PurgeRequest
                    && record.guard == JOURNAL_SUBJECT
                    && record.operation == 5
                    && record.reason == b"recovery"),
            "no durable recovery request"
        );
        cleanup(&[&dir, &copy]);
    }
}

/// A pending hold survives a restart, and unreadable hold state inhibits
/// every purge.
#[test]
fn a_pending_hold_survives_and_unreadable_holds_inhibit() {
    let (journal, dir, copy) = filled("pending-hold", Some(expired()));
    let recording = journal.recording();
    drop(journal);
    let mut marker = [0u8; MARKER_LENGTH];
    marker[..8].copy_from_slice(&recording.to_le_bytes());
    marker[8] = 1;
    Ledger::<StdDisk, MARKER_LENGTH>::open(StdDisk, &dir, PENDING_HOLDS_FILE)
        .unwrap()
        .append(marker)
        .unwrap();
    let mut journal = Journal::open_small(&dir, 2, settings(Some(expired()), Some(&copy))).unwrap();
    assert_eq!(journal.hold(), "pending");
    assert_eq!(
        reason(&journal.purge_journal(1, SEG, authorised(), 3)),
        "legal_hold"
    );
    drop(journal);
    let mut ledger =
        Ledger::<StdDisk, OPERATION_LENGTH>::open(StdDisk, &dir, OPERATIONS_FILE).unwrap();
    ledger.append([0xff; OPERATION_LENGTH]).unwrap();
    drop(ledger);
    let mut journal = Journal::open_small(&dir, 4, settings(Some(expired()), Some(&copy))).unwrap();
    assert_eq!(journal.hold(), "unknown");
    assert_eq!(
        reason(&journal.purge_journal(2, SEG, authorised(), 5)),
        "holds_unknown"
    );
    assert_eq!(start(&journal), 0);
    cleanup(&[&dir, &copy]);
}

/// Signs the chain's last record into the heads ledger of `dir`.
fn sign_head(dir: &Path, key: &mut TestKey, archive: Digest) -> SignedHead {
    let (records, _) = read_records(&mut StdDisk, dir).unwrap();
    let last = records.last().unwrap();
    let head = ChainHead {
        archive_id: archive,
        journal_id: 0,
        counter: last.counter,
        digest: last.digest(),
    };
    let signed = SignedHead {
        head,
        key_id: key.key_id(),
        custody: key.custody(),
        signature: key.sign(&head).unwrap(),
    };
    Ledger::<StdDisk, SIGNED_HEAD_LENGTH>::open(StdDisk, dir, HEADS_FILE)
        .unwrap()
        .append(signed.encode())
        .unwrap();
    signed
}

/// `--journal-trust`: an intact journal whose heads a registered key
/// signed is no longer `untrusted_evidence`, and a purged prefix is
/// `purged`. Without an external anchor (the journal keeps none) a sealed
/// range is `beyond_anchor`, as `karyos-catalog verify --trust` reports it.
#[test]
fn a_trusted_journal_is_no_longer_untrusted() {
    let dir = dir("trust");
    let copy = dir.with_extension("copy");
    let (archive, mut archival, trust) = register(&dir);
    let settings = settings(Some(expired()), Some(&copy)).with_trust(Some(trust));
    let mut journal = Journal::open_small(&dir, 1, settings).unwrap();
    fill(&mut journal, 2 * SEG + SEG / 2);
    copy_dir(&dir, &copy);
    let _ = sign_head(&dir, &mut archival, archive);
    journal.verify(2);
    let ranges = &journal.integrity().unwrap().ranges;
    assert!(
        ranges
            .iter()
            .all(|range| range.outcome == "beyond_anchor"
                && range.reasons == ["no_anchor".to_owned()]),
        "{ranges:?}"
    );
    assert_eq!(
        journal.purge_journal(1, SEG, authorised(), 3),
        RetentionReply::Done { evidenced: true }
    );
    let _ = sign_head(&dir, &mut archival, archive);
    journal.verify(4);
    let ranges = &journal.integrity().unwrap().ranges;
    assert_eq!(ranges[0].outcome, "purged", "{ranges:?}");
    assert_eq!((ranges[0].start, ranges[0].end), (0, SEG));
    assert!(
        ranges[1..]
            .iter()
            .all(|range| range.outcome == "beyond_anchor"),
        "{ranges:?}"
    );
    cleanup(&[&dir, &copy]);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The policy option's grammar, and the trust file's.
#[test]
fn the_policy_and_the_trust_parse() {
    assert_eq!(
        JournalPolicy::parse("retain_for=10s,min_copies=3"),
        Some(JournalPolicy {
            retain_for_ns: 10_000_000_000,
            purge: PurgeMode::Manual,
            min_copies: NonZeroU32::new(3).unwrap(),
        })
    );
    assert_eq!(JournalPolicy::parse("min_copies=3"), None);
    assert!(JournalTrust::parse("archive 00").is_err());
    assert!(JournalTrust::parse(&format!("archive {}\n", "00".repeat(32))).is_err());
    assert_eq!(refusal_word("legal_hold"), 2);
    assert_eq!(refusal_word(PURGE_PENDING), 102);
}

/// Registers an archival key in `dir` before the journal opens; the
/// archive identity, the key, and the trust that names them.
fn register(dir: &Path) -> (Digest, TestKey, JournalTrust) {
    let archive = [7u8; 32];
    let authority = TestKey::from_seed([1; 32]);
    let archival = TestKey::from_seed([9; 32]);
    let root = TrustRoot {
        archive_id: archive,
        authorities: vec![authority.public()],
    };
    let mut integrity = IntegrityJournal::open(StdDisk, dir).unwrap().journal;
    let mut keys = Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(StdDisk, dir, KEYS_FILE).unwrap();
    let mut entry = RegistryEntry {
        action: RegistryAction::Register,
        algorithm: Algorithm::Ed25519,
        custody: Custody::Declared,
        sequence: 0,
        key_id: key_id(&archival.public()),
        public: archival.public(),
        effective: 0,
        evidence: [0; 32],
        endorsement: [0; 64],
    };
    entry.endorsement = authority.sign_bytes(&entry.endorsement_bytes(&archive));
    KeyRegistry::new(root)
        .append(&entry, &mut integrity, &mut keys)
        .unwrap();
    let trust = JournalTrust::parse(&format!(
        "# the journal's trust\narchive {}\nauthority {}\njournal 0\n",
        hex(&archive),
        hex(&authority.public())
    ))
    .unwrap();
    (archive, archival, trust)
}

/// `--journal-anchors`: an anchored, trusted, intact journal is
/// `verified`, as `karyos-catalog verify --trust --anchors` reports it.
#[test]
fn an_anchored_trusted_journal_is_verified() {
    use karyos_archive::integrity::anchor::{ANCHOR_FILE, ANCHOR_LENGTH, Anchor, AnchorKind};
    let dir = dir("anchored");
    let store = dir.with_extension("anchors");
    let _ = std::fs::remove_dir_all(&store);
    std::fs::create_dir_all(&store).unwrap();
    let (archive, mut archival, trust) = register(&dir);
    let location = [0x5a; 32];
    let settings = JournalRetention::default()
        .with_trust(Some(trust))
        .with_anchors(location, store.clone());
    let mut journal = Journal::open_small(&dir, 1, settings).unwrap();
    fill(&mut journal, SEG + SEG / 2);
    let signed = sign_head(&dir, &mut archival, archive);
    let anchor = Anchor {
        kind: AnchorKind::OperatorExport,
        location,
        external_counter: 0,
        receipt: [0; 32],
        signed,
    };
    Ledger::<StdDisk, ANCHOR_LENGTH>::open(StdDisk, &store, ANCHOR_FILE)
        .unwrap()
        .append(anchor.encode())
        .unwrap();
    journal.verify(2);
    let ranges = &journal.integrity().unwrap().ranges;
    assert!(!ranges.is_empty());
    assert!(
        ranges
            .iter()
            .all(|range| range.outcome == "verified" && range.reasons.is_empty()),
        "{ranges:?}"
    );
    // An anchor store that is not there is a fault, never an empty store.
    std::fs::remove_dir_all(&store).unwrap();
    journal.verify(3);
    let ranges = &journal.integrity().unwrap().ranges;
    assert!(
        ranges.iter().all(|range| range.outcome != "verified"),
        "{ranges:?}"
    );
    cleanup(&[&dir]);
}

/// The wall clock moved by `seconds` on this thread, until dropped.
struct Clock;

impl Clock {
    fn step(seconds: i64) -> Self {
        fault::step_clock(seconds.saturating_mul(1_000_000_000));
        Self
    }
}

impl Drop for Clock {
    fn drop(&mut self) {
        fault::step_clock(0);
        fault::crash(fault::Crash::None);
        fault::fail_seal(false);
        fault::fail_clock(false);
        fault::fail(false);
    }
}

/// An hour's retention.
fn hour() -> JournalPolicy {
    JournalPolicy {
        retain_for_ns: 3_600_000_000_000,
        ..expired()
    }
}

fn skip_closes(journal: &mut Journal, skip: bool) {
    journal.retention.as_mut().unwrap().skip_closes = skip;
}

fn closes(journal: &Journal) -> std::collections::BTreeMap<u64, u64> {
    journal.retention.as_ref().unwrap().closes.clone()
}

/// ADR-0115: a closed segment's recorded time drives expiry, not expired
/// before `close + retain_for`, expired after.
#[test]
fn a_recorded_close_time_drives_expiry() {
    let (mut journal, dir, copy) = filled("close-expiry", Some(hour()));
    assert!(closes(&journal).contains_key(&0));
    assert_eq!(
        reason(&journal.purge_journal(1, SEG, authorised(), 2)),
        "not_expired"
    );
    let clock = Clock::step(3_601);
    assert_eq!(
        journal.purge_journal(2, SEG, authorised(), 3),
        RetentionReply::Done { evidenced: true }
    );
    drop(clock);
    cleanup(&[&dir, &copy]);
}

/// ADR-0115: a clock stepped back between two closes does not expire the
/// older segment early.
#[test]
fn a_clock_stepped_back_expires_nothing_early() {
    let dir = dir("step-back");
    let copy = dir.with_extension("copy");
    let mut journal = Journal::open_small(&dir, 1, settings(Some(hour()), Some(&copy))).unwrap();
    fill(&mut journal, SEG + SEG / 2);
    let back = Clock::step(-7_200);
    fill(&mut journal, 2 * SEG + SEG / 2);
    drop(back);
    fill(&mut journal, 3 * SEG + SEG / 2);
    copy_dir(&dir, &copy);
    let times = closes(&journal);
    assert!(times[&SEG] < times[&0], "{times:?}");
    // The newer segment's time has passed, the older one's has not.
    let clock = Clock::step(100);
    assert_eq!(
        reason(&journal.purge_journal(1, 2 * SEG, authorised(), 2)),
        "not_expired"
    );
    drop(clock);
    let clock = Clock::step(3_700);
    assert_eq!(
        journal.purge_journal(2, 2 * SEG, authorised(), 3),
        RetentionReply::Done { evidenced: true }
    );
    drop(clock);
    cleanup(&[&dir, &copy]);
}

/// Appends until an append fails, as the crash `at` stops it.
fn crash_at_rollover(journal: &mut Journal, at: fault::Crash) {
    let _clock = Clock::step(0);
    fault::crash(at);
    let mut time = 10;
    loop {
        let mut record = JournalRecord::new(Kind::CloseRequest, time);
        record.reason = b"drill".to_vec();
        if journal.append(&record, time).is_err() {
            break;
        }
        time += 1;
        assert!(time < 100_000, "no rollover");
    }
}

/// ADR-0115: a crash after the close entry and before the successor's
/// first record leaves the predecessor closed, its time kept; one before
/// the entry leaves it without a close time.
#[test]
fn a_crash_at_the_rollover_keeps_or_lacks_the_close() {
    let dir = dir("crash-after");
    let mut journal = Journal::open_small(&dir, 1, settings(Some(expired()), None)).unwrap();
    crash_at_rollover(&mut journal, fault::Crash::AfterClose);
    let closed = closes(&journal)[&0];
    assert!(journal.recorder.is_none(), "the crash stops the journal");
    drop(journal);
    let mut journal = Journal::open_small(&dir, 2, settings(Some(expired()), None)).unwrap();
    assert_eq!(closes(&journal).get(&0), Some(&closed));
    fill(&mut journal, 2 * SEG + SEG / 2);
    assert_eq!(
        closes(&journal).get(&0),
        Some(&closed),
        "never closed again"
    );
    drop(journal);
    cleanup(&[&dir]);

    let dir = self::dir("crash-before");
    let mut journal = Journal::open_small(&dir, 1, settings(Some(expired()), None)).unwrap();
    crash_at_rollover(&mut journal, fault::Crash::BeforeClose);
    assert!(closes(&journal).is_empty(), "no close time was recorded");
    drop(journal);
    // The next start's first record does not fit the segment either: that
    // rollover is its close, recorded then (karyos#702 review).
    let journal = Journal::open_small(&dir, 2, settings(Some(expired()), None)).unwrap();
    assert!(closes(&journal).contains_key(&0), "closed at the start");
    assert_eq!(journal.gap.unwrap().position, SEG);
    cleanup(&[&dir]);
}

fn written(journal: &Journal) -> u64 {
    journal.recorder.as_ref().unwrap().store().written()
}

/// The room left in the current segment.
fn room(journal: &Journal) -> u64 {
    SEG - written(journal) % SEG
}

/// ADR-0115 point 1 (karyos#702 review): the close times are loaded
/// before a start's first record. After a crash between a close entry and
/// the successor's first record, the start's first record goes to the
/// successor even where it would fit the closed segment; and a start
/// whose first record rolls over records that close (above).
#[test]
fn test_journal_the_first_resumed_write_never_lands_in_a_closed_segment() {
    let dir = dir("resume-closed");
    let mut journal = Journal::open_small(&dir, 1, settings(Some(expired()), None)).unwrap();
    let small = frame_length(&JournalRecord::new(Kind::UnknownInterval, 0));
    let mut big = JournalRecord::new(Kind::CloseRequest, 10);
    big.reason = vec![b'x'; super::super::MAX_REASON];
    let filler = JournalRecord::new(Kind::CloseRequest, 10);
    assert_eq!(frame_length(&filler), small);
    assert!(frame_length(&big) >= 2 * small);
    while room(&journal) >= frame_length(&big) {
        let _ = journal.append(&filler, 10).unwrap();
    }
    assert!(room(&journal) >= small, "a start's record would fit");
    let clock = Clock::step(0);
    fault::crash(fault::Crash::AfterClose);
    assert!(journal.append(&big, 11).is_err());
    drop(clock);
    let closed = closes(&journal)[&0];
    drop(journal);
    let journal = Journal::open_small(&dir, 2, settings(Some(expired()), None)).unwrap();
    // The unknown interval is the start's first record: in the successor.
    let gap = journal.gap.unwrap();
    assert_eq!(gap.position, SEG, "{gap:?}");
    assert_eq!(
        closes(&journal).get(&0),
        Some(&closed),
        "never closed again"
    );
    assert!(written(&journal) > SEG);
    cleanup(&[&dir]);
}

/// ADR-0115 point 1 (karyos#702 review): a rollover whose seal fails,
/// whose wall clock cannot be read, or whose close entry cannot be synced
/// writes no successor record: that append fails as a journal write does,
/// writing nothing, and the next append closes the segment and goes on.
#[test]
fn test_journal_a_rollover_that_cannot_close_writes_no_successor_record() {
    for failure in ["seal", "clock", "entry"] {
        let dir = dir(&format!("close-fails-{failure}"));
        let mut journal = Journal::open_small(&dir, 1, settings(Some(expired()), None)).unwrap();
        let clock = Clock::step(0);
        let mut record = JournalRecord::new(Kind::CloseRequest, 10);
        record.reason = b"drill".to_vec();
        // Frames tile a segment exactly: a larger record is the one that
        // cannot fit, so the filling always ends.
        let mut big = record.clone();
        big.reason = vec![b'x'; super::super::MAX_REASON];
        while room(&journal) >= frame_length(&big) {
            let _ = journal.append(&record, 10).unwrap();
        }
        let record = big;
        let before = written(&journal);
        let failed = journal.failed_appends();
        match failure {
            "seal" => fault::fail_seal(true),
            "clock" => fault::fail_clock(true),
            _ => fault::fail(true),
        }
        let refused = journal.append(&record, 11);
        assert!(
            matches!(refused, Err(crate::journal::JournalError::NotClosed)),
            "{failure}: {refused:?}"
        );
        assert_eq!(written(&journal), before, "{failure}: nothing written");
        // No close entry reached the ledger either (ADR-0115, point 1).
        let entries =
            read_entries::<_, OPERATION_LENGTH>(&mut StdDisk, &dir, OPERATIONS_FILE).unwrap();
        assert!(
            !entries.iter().any(|bytes| matches!(
                Operation::decode(bytes),
                Some(Operation::SegmentClosed { .. })
            )),
            "{failure}: no SegmentClosed"
        );
        assert!(closes(&journal).is_empty(), "{failure}");
        assert_eq!(journal.failed_appends(), failed + 1, "{failure}");
        drop(clock);
        // Retried at the next append, the refusal recorded first as an
        // unknown interval (karyos#773 review).
        let position = journal.append(&record, 12).unwrap();
        let gap = journal.gap().unwrap();
        assert_eq!(
            (gap.reason, gap.from),
            (crate::journal::GapReason::AppendRefused, 11),
            "{failure}: the refusal is an unknown interval"
        );
        // The interval's small record still fits before the boundary; the
        // refused record is the successor's first.
        assert!(gap.position < SEG, "{failure}");
        assert_eq!(position, SEG, "{failure}: the successor's first record");
        assert!(closes(&journal).contains_key(&0), "{failure}: closed");
        drop(journal);
        cleanup(&[&dir]);
    }
}

/// A purge never removes the record an operation id still retained is
/// rebuilt from at start, its `ApprovalRequested`, `Submitted` or
/// `ClusterRequest`: refused `operation_state_retained`, before and after
/// a restart, so the id is never reused (karyos#738, karyos#739 review).
#[test]
fn test_journal_a_purge_keeps_the_record_of_a_retained_operation_id() {
    for kind in [
        Kind::ApprovalRequested,
        Kind::Submitted,
        Kind::ClusterRequest,
    ] {
        let dir = dir(&format!("retained-{}", kind.code()));
        let copy = dir.with_extension("copy");
        let mut journal =
            Journal::open_small(&dir, 1, settings(Some(expired()), Some(&copy))).unwrap();
        let mut record = JournalRecord::new(kind, 5);
        record.operation = 51;
        let _ = journal.append_durable(&record, 5).unwrap();
        fill(&mut journal, 3 * SEG + SEG / 2);
        copy_dir(&dir, &copy);
        let retained = |operation: u64| operation == 51;
        let refused = journal.purge_journal_retaining(1, SEG, authorised(), 2, &retained);
        assert_eq!(reason(&refused), OPERATION_STATE_RETAINED, "{kind:?}");
        assert_eq!(start(&journal), 0);
        drop(journal);
        let mut journal =
            Journal::open_small(&dir, 3, settings(Some(expired()), Some(&copy))).unwrap();
        let refused = journal.purge_journal_retaining(2, SEG, authorised(), 4, &retained);
        assert_eq!(
            reason(&refused),
            OPERATION_STATE_RETAINED,
            "{kind:?} restarted"
        );
        assert_eq!(start(&journal), 0);
        // An id no longer retained holds nothing.
        assert_eq!(
            journal.purge_journal_retaining(3, SEG, authorised(), 5, &|_| false),
            RetentionReply::Done { evidenced: true },
            "{kind:?}"
        );
        assert_eq!(start(&journal), SEG);
        cleanup(&[&dir, &copy]);
    }
}

/// Another recording's purge intent with the same id never narrows this
/// journal's `from` (karyos#702 review).
#[test]
fn test_journal_another_recordings_intent_does_not_narrow_from() {
    let (journal, dir, copy) = filled("froms", Some(expired()));
    let recording = journal.recording();
    drop(journal);
    let other = Operation::PurgeIntent {
        id: 5,
        recording: recording.wrapping_add(1000),
        before: 3 * SEG,
        operator: 1000,
        closed_ns: 0,
        source: PurgeSource::Operator,
        from: 2 * SEG,
    };
    write_operation(&dir, &other);
    write_operation(&dir, &intent(5, recording, SEG));
    let journal = Journal::open_small(&dir, 2, settings(Some(expired()), Some(&copy))).unwrap();
    assert_eq!(
        journal.retention.as_ref().unwrap().froms.get(&5),
        Some(&0),
        "this journal's own intent's from"
    );
    drop(journal);
    cleanup(&[&dir, &copy]);
}

/// A copy is a directory other than the live journal's, by canonical
/// path, and two locations of one directory count once (karyos#702
/// review).
#[test]
fn test_journal_a_copy_is_another_directory_counted_once() {
    let (journal, dir, copy) = filled("self-copy", Some(expired()));
    drop(journal);
    // The live directory as its own copy, spelled otherwise.
    let own = JournalRetention::default()
        .with_policy(Some(expired()))
        .with_copy("self".to_owned(), dir.join("."));
    let mut journal = Journal::open_small(&dir, 2, own).unwrap();
    let refused = journal.purge_journal(1, SEG, authorised(), 3);
    assert_eq!(reason(&refused), "below_min_copies");
    assert_eq!(start(&journal), 0);
    drop(journal);
    // One copy under two names where two are needed.
    let two = JournalPolicy {
        min_copies: NonZeroU32::new(2).unwrap(),
        ..expired()
    };
    let link = dir.with_extension("link");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&copy, &link).unwrap();
    let twice = JournalRetention::default()
        .with_policy(Some(two))
        .with_copy("vault".to_owned(), copy.clone())
        .with_copy("mirror".to_owned(), link.clone());
    let mut journal = Journal::open_small(&dir, 4, twice).unwrap();
    let refused = journal.purge_journal(2, SEG, authorised(), 5);
    assert_eq!(reason(&refused), "below_min_copies");
    assert_eq!(start(&journal), 0);
    drop(journal);
    // Two directories do.
    let other = dir.with_extension("other");
    copy_dir(&copy, &other);
    let distinct = JournalRetention::default()
        .with_policy(Some(two))
        .with_copy("vault".to_owned(), copy.clone())
        .with_copy("mirror".to_owned(), link.clone())
        .with_copy("other".to_owned(), other.clone());
    let mut journal = Journal::open_small(&dir, 6, distinct).unwrap();
    assert_eq!(
        journal.purge_journal(3, SEG, authorised(), 7),
        RetentionReply::Done { evidenced: true }
    );
    drop(journal);
    let _ = std::fs::remove_file(&link);
    cleanup(&[&dir, &copy, &other]);
}

/// ADR-0113 point 8 (karyos#702 review): an intent whose floor already
/// reached its `BEFORE` is rechecked before it completes. Under a hold,
/// or with no copy that verifies, it is not completed (no purge record)
/// and stays pending; with the checks passing it completes. That the
/// files left below the floor stay is the library's test,
/// `recovery_rechecks_an_intent_whose_floor_already_reached_its_cutoff`:
/// the journal's store drops them when it reopens.
#[test]
fn test_journal_recovery_rechecks_an_intent_whose_floor_reached_its_cutoff() {
    for case in ["hold", "copies", "passes"] {
        let (mut journal, dir, copy) = filled(&format!("floor-{case}"), Some(expired()));
        if case == "hold" {
            assert_eq!(
                journal.hold_journal(),
                RetentionReply::Done { evidenced: true }
            );
        }
        let recording = journal.recording();
        // A crash after the floor moved, before the purge was recorded.
        let _ = journal.store_mut().purge_before(SEG).unwrap();
        drop(journal);
        write_operation(&dir, &intent(5, recording, SEG));
        let copies = (case != "copies").then_some(copy.as_path());
        let journal = Journal::open_small(&dir, 2, settings(Some(expired()), copies)).unwrap();
        assert_eq!(start(&journal), SEG);
        let purged = !journal.integrity().unwrap().purged.is_empty();
        if case == "passes" {
            assert!(!journal.purge_pending(), "completed");
            assert!(purged, "its purge is recorded");
        } else {
            assert!(journal.purge_pending(), "{case}: stays pending");
            assert!(!purged, "{case}: not completed");
        }
        drop(journal);
        cleanup(&[&dir, &copy]);
    }
}

/// ADR-0115: recovery rechecks expiry over the intent's original range;
/// a clock step back or a missing close entry leaves it `purge_pending`.
#[test]
fn recovery_rechecks_expiry_over_the_original_range() {
    // A clock stepped back since the intent.
    let (journal, dir, copy) = filled("recheck-clock", Some(hour()));
    let recording = journal.recording();
    drop(journal);
    write_operation(&dir, &intent(5, recording, SEG));
    let journal = Journal::open_small(&dir, 2, settings(Some(hour()), Some(&copy))).unwrap();
    assert!(journal.purge_pending(), "not expired at the recovery");
    assert_eq!(start(&journal), 0);
    drop(journal);
    let clock = Clock::step(3_700);
    let journal = Journal::open_small(&dir, 3, settings(Some(hour()), Some(&copy))).unwrap();
    assert!(!journal.purge_pending(), "expired now: completed");
    assert_eq!(start(&journal), SEG);
    drop((journal, clock));
    cleanup(&[&dir, &copy]);

    // A missing close entry, even with the floor already advanced.
    let dir = self::dir("recheck-missing");
    let copy = dir.with_extension("copy");
    let mut journal = Journal::open_small(&dir, 1, settings(Some(expired()), Some(&copy))).unwrap();
    skip_closes(&mut journal, true);
    fill(&mut journal, 2 * SEG + SEG / 2);
    let _ = journal.store_mut().purge_before(SEG).unwrap();
    let recording = journal.recording();
    drop(journal);
    write_operation(&dir, &intent(5, recording, SEG));
    let journal = Journal::open_small(&dir, 2, settings(Some(expired()), Some(&copy))).unwrap();
    assert!(journal.purge_pending());
    assert!(
        journal.integrity().unwrap().purged.is_empty(),
        "never completed"
    );
    cleanup(&[&dir, &copy]);
}

/// ADR-0115: a segment without a recorded close time is never expired,
/// nor a prefix that contains one.
#[test]
fn a_segment_without_a_close_time_never_expires() {
    let dir = dir("no-close");
    let copy = dir.with_extension("copy");
    let mut journal = Journal::open_small(&dir, 1, settings(Some(expired()), Some(&copy))).unwrap();
    fill(&mut journal, SEG + SEG / 2);
    skip_closes(&mut journal, true);
    fill(&mut journal, 2 * SEG + SEG / 2);
    skip_closes(&mut journal, false);
    fill(&mut journal, 3 * SEG + SEG / 2);
    copy_dir(&dir, &copy);
    assert!(!closes(&journal).contains_key(&SEG));
    for before in [2 * SEG, 3 * SEG] {
        assert_eq!(
            reason(&journal.purge_journal(before, before, authorised(), 2)),
            "not_expired"
        );
    }
    assert_eq!(
        journal.purge_journal(1, SEG, authorised(), 3),
        RetentionReply::Done { evidenced: true }
    );
    cleanup(&[&dir, &copy]);
}

/// ADR-0115: a segment file's modification time changes no decision.
#[test]
fn a_segment_files_modification_time_changes_nothing() {
    let set = |journal: &Journal, dir: &Path, time: std::time::SystemTime| {
        let path = dir.join(format!("{:016x}-{:016x}.seg", journal.recording(), 0));
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(time)
            .unwrap();
    };
    let (mut journal, dir, copy) = filled("mtime-old", Some(hour()));
    set(
        &journal,
        &dir,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1),
    );
    assert_eq!(
        reason(&journal.purge_journal(1, SEG, authorised(), 2)),
        "not_expired"
    );
    cleanup(&[&dir, &copy]);
    let (mut journal, dir, copy) = filled("mtime-new", Some(expired()));
    let future = std::time::SystemTime::now() + std::time::Duration::from_secs(86_400);
    set(&journal, &dir, future);
    assert_eq!(
        journal.purge_journal(2, SEG, authorised(), 3),
        RetentionReply::Done { evidenced: true }
    );
    cleanup(&[&dir, &copy]);
}

/// ADR-0115: a close time later than the clock is not expired.
#[test]
fn a_close_time_later_than_the_clock_is_not_expired() {
    let dir = dir("future-close");
    let copy = dir.with_extension("copy");
    let mut journal = Journal::open_small(&dir, 1, settings(Some(expired()), Some(&copy))).unwrap();
    let ahead = Clock::step(7_200);
    fill(&mut journal, SEG + SEG / 2);
    drop(ahead);
    fill(&mut journal, 2 * SEG + SEG / 2);
    copy_dir(&dir, &copy);
    assert_eq!(
        reason(&journal.purge_journal(1, SEG, authorised(), 2)),
        "not_expired"
    );
    cleanup(&[&dir, &copy]);
}

/// R-CORE-14 (karyos#725): after a purge, a history cursor below the new
/// retention floor is refused with the floor, never answered with an
/// empty page, and a read without a cursor starts at the floor.
#[test]
fn a_history_cursor_below_the_floor_is_refused_with_it() {
    use crate::journal::{HistoryCursor, HistoryRefusal};

    let (mut journal, dir, copy) = filled("history-floor", Some(expired()));
    let first = journal.history(None, 1).unwrap();
    assert_eq!(first.floor, 0);
    let old = HistoryCursor::new(first.recording, first.records[0].next);
    assert_eq!(
        journal.purge_journal(1, SEG, authorised(), 2),
        RetentionReply::Done { evidenced: true }
    );
    assert_eq!(
        journal.history(Some(old), 1),
        Err(HistoryRefusal::BelowFloor {
            recording: first.recording,
            floor: SEG
        })
    );
    let page = journal.history(None, 1).unwrap();
    assert_eq!((page.floor, page.records[0].position), (SEG, SEG));
    cleanup(&[&dir, &copy]);
}
