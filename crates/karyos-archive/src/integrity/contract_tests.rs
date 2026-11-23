// SPDX-License-Identifier: Apache-2.0

//! The contract test group "Retention integrity" (quantstratum-docs:
//! karyos/SPEC.md §13, the group of SPEC.md line 946; karyos#670). Each
//! test exercises one case end to end through the integrity APIs: the
//! hash chain, signed heads, the key registry, external anchors, the
//! verifier, time evidence and the crash-safe purge.
//!
//! The integrity outcomes (`verify::Outcome`, `verify::Reason`) and the
//! time verdicts (`time::Verdict`) are kept in separate tests.
//!
//! Skipped: "an export is verified offline", since the offline export
//! verifier is not on main yet (tracked by karyos#668).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::collections::BTreeSet;
use std::io;
use std::num::NonZeroU32;
use std::path::Path;

use ed25519_dalek::Signer as _;
use karyos_trace::clocks::{Calibration, ClockKey};
use karyos_trace::journal::ObserverId;

use super::anchor::{
    Absence, Anchor, AnchorEvidence, AnchorFinding, AnchorKind, AnchorReport, Externality,
    check_anchors,
};
use super::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
use super::journal::{IntegrityError, IntegrityJournal};
use super::ledger::{Ledger, read_entries};
use super::retention::{
    Authorisation, HoldReport, MARKER_LENGTH, OPERATION_LENGTH, OPERATIONS_FILE, Operation,
    OperationsJournal, PENDING_HOLDS_FILE, PurgeContext, PurgeError, PurgeMode, PurgeRefusal,
    PurgeRequest, PurgeSource, ReleaseError, Retention, RetentionPolicy,
};
use super::signing::{
    BacklogPolicy, HeadSigner, HeadSigning, HeadStore, SignerUnavailable, SigningConfig,
};
use super::test_support::{
    ARCHIVE, DIR, JOURNAL, archival_key, authority, chain, registry, sign, trust,
};
use super::time::{
    CalibrationEvidence, ClockEvidence, Coordinate, Gap, Requirement, Sample, Source, SyncState,
    TargetKind, UtcReference, Verdict, clock_verdict, combined_bound, derived_bound, reduce, split,
};
use super::trust::{
    Algorithm, ChainHead, Custody, HeadReason, HeadVerdict, KEYS_FILE, KeyRegistry,
    REGISTRY_ENTRY_LENGTH, RegistryAction, RegistryEntry, SIGNATURE_LENGTH, SIGNED_HEAD_LENGTH,
    SignedHead, TrustRoot, key_id,
};
use super::verify::{Evidence, Outcome, RangeBytes, Reason, Verification, verify};
use super::{Digest, Inconsistency, SealRecord, digest, verify_chain};
use crate::fault::{FaultDisk, Survives};
use crate::segment::{Geometry, SegmentStore, SyncPolicy};

const OPERATOR: Digest = [21; 32];
const REPLICA: Digest = [22; 32];

// ---------------------------------------------------------------------
// Integrity fixtures: a chain whose record 0 registers the archival key
// and whose records 1 to 6 seal six eight-byte ranges of recording 3.
// ---------------------------------------------------------------------

/// Stores that hold exactly the anchors listed.
#[derive(Debug)]
struct Held<'a>(&'a [Anchor]);

impl AnchorEvidence for Held<'_> {
    fn confirms(&self, anchor: &Anchor) -> bool {
        self.0.contains(anchor)
    }
}

/// The bytes of range `index` of recording 3.
fn range(index: u64) -> Vec<u8> {
    (index * 1_000).to_le_bytes().to_vec()
}

fn registration() -> RegistryEntry {
    let key = archival_key();
    let mut entry = RegistryEntry {
        action: RegistryAction::Register,
        algorithm: Algorithm::Ed25519,
        custody: Custody::Declared,
        sequence: 0,
        key_id: key_id(&key.verifying_key().to_bytes()),
        public: key.verifying_key().to_bytes(),
        effective: 0,
        evidence: [0; 32],
        endorsement: [0; 64],
    };
    entry.endorsement = authority()
        .sign(&entry.endorsement_bytes(&ARCHIVE))
        .to_bytes();
    entry
}

/// A revocation of the archival key effective at `effective`.
fn revocation(effective: u64) -> RegistryEntry {
    let mut entry = RegistryEntry {
        action: RegistryAction::Revoke,
        sequence: 1,
        effective,
        evidence: digest(b"anchor before the compromise"),
        ..registration()
    };
    entry.endorsement = authority()
        .sign(&entry.endorsement_bytes(&ARCHIVE))
        .to_bytes();
    entry
}

struct Scenario {
    journal: IntegrityJournal<FaultDisk>,
    keys: Vec<[u8; REGISTRY_ENTRY_LENGTH]>,
    heads: Vec<[u8; SIGNED_HEAD_LENGTH]>,
    anchors: Vec<Anchor>,
    trust: Option<TrustRoot>,
    written: Vec<(u64, u64)>,
}

impl Scenario {
    /// The chain, its head signed at record 6 and anchored at record 4.
    fn new() -> Self {
        let disk = FaultDisk::default();
        let mut journal = IntegrityJournal::open(disk.clone(), Path::new(DIR))
            .unwrap()
            .journal;
        let mut ledger =
            Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(disk, Path::new(DIR), KEYS_FILE).unwrap();
        KeyRegistry::new(trust())
            .append(&registration(), &mut journal, &mut ledger)
            .unwrap();
        for index in 0..6 {
            journal
                .seal_segment(3, index * 8, &range(index), false)
                .unwrap();
        }
        let mut scenario = Self {
            journal,
            keys: ledger.entries().to_vec(),
            heads: Vec::new(),
            anchors: Vec::new(),
            trust: Some(trust()),
            written: vec![(3, 48)],
        };
        scenario.sign_head();
        scenario.anchor(4);
        scenario
    }

    fn records(&mut self) -> Vec<SealRecord> {
        self.journal.records().unwrap()
    }

    fn sign_head(&mut self) {
        let records = self.records();
        self.heads.push(sign(records.last().unwrap()).encode());
    }

    fn anchor(&mut self, counter: usize) {
        let records = self.records();
        let external = u64::try_from(self.anchors.len()).unwrap();
        self.anchors.push(Anchor {
            kind: AnchorKind::OperatorExport,
            location: OPERATOR,
            external_counter: external,
            receipt: [0; 32],
            signed: sign(&records[counter]),
        });
    }

    /// Verifies `records` in place of the journal's, reading with `read`.
    fn verify_records(
        &self,
        records: &[SealRecord],
        read: impl FnMut(u64, u64, u64) -> RangeBytes,
    ) -> Verification {
        let externality = Externality {
            local_archive: ARCHIVE,
            ..Externality::default()
        };
        let evidence = Evidence {
            records,
            journal_fault: None,
            journal_id: JOURNAL,
            trust: self.trust.as_ref(),
            registry: &self.keys,
            heads: &self.heads,
            anchors: &self.anchors,
            anchor_faults: 0,
            stores: &Held(&self.anchors),
            externality: &externality,
            written: &self.written,
        };
        verify(&evidence, read)
    }

    fn verify_with(&mut self, read: impl FnMut(u64, u64, u64) -> RangeBytes) -> Verification {
        let records = self.records();
        self.verify_records(&records, read)
    }

    fn verify(&mut self) -> Verification {
        self.verify_with(intact)
    }
}

fn intact(_: u64, start: u64, _: u64) -> RangeBytes {
    RangeBytes::Bytes(range(start / 8))
}

fn never_verified(verification: &Verification) {
    assert!(
        verification
            .ranges
            .iter()
            .all(|range| range.outcome != Outcome::Verified),
        "{verification:?}"
    );
}

/// Stores that confirm every anchor whose receipt is the digest of its
/// external counter.
#[derive(Debug)]
struct Receipts;

impl AnchorEvidence for Receipts {
    fn confirms(&self, anchor: &Anchor) -> bool {
        anchor.receipt == digest(&anchor.external_counter.to_le_bytes())
    }
}

fn receipted(kind: AnchorKind, location: Digest, external: u64, record: &SealRecord) -> Anchor {
    Anchor {
        kind,
        location,
        external_counter: external,
        receipt: digest(&external.to_le_bytes()),
        signed: sign(record),
    }
}

fn check(records: &[SealRecord], anchors: &[Anchor]) -> AnchorReport {
    let externality = Externality {
        local_archive: ARCHIVE,
        ..Externality::default()
    };
    check_anchors(
        records,
        JOURNAL,
        anchors,
        &registry(),
        &externality,
        &Receipts,
    )
}

// ---------------------------------------------------------------------
// Integrity cases.
// ---------------------------------------------------------------------

#[test]
fn test_retention_integrity_altered_sealed_segment_inconsistent_naming_record() {
    let mut scenario = Scenario::new();
    let verification = scenario.verify_with(|_, start, _| {
        let mut bytes = range(start / 8);
        if start == 16 {
            bytes[0] ^= 1;
        }
        RangeBytes::Bytes(bytes)
    });
    let altered = &verification.ranges[2];
    assert_eq!(altered.outcome, Outcome::Inconsistent);
    assert_eq!(altered.reasons, [Reason::Corruption]);
    // Record 3 seals the range at 16.
    assert_eq!(altered.first_inconsistent, Some(3));
    assert_eq!(verification.ranges[1].outcome, Outcome::Verified);
}

#[test]
fn test_retention_integrity_removed_seal_record_inconsistent_chain_break() {
    let mut scenario = Scenario::new();
    let mut records = scenario.records();
    records.remove(3);
    assert!(matches!(
        verify_chain(&records),
        Err(Inconsistency::CounterGap {
            expected: 3,
            found: 4
        })
    ));
    let verification = scenario.verify_records(&records, intact);
    assert_eq!(verification.journal_break, Some(3));
    let broken: Vec<_> = verification
        .ranges
        .iter()
        .filter(|range| range.first_inconsistent == Some(3))
        .map(|range| (range.counter, range.outcome))
        .collect();
    assert_eq!(
        broken,
        [
            (Some(4), Outcome::Inconsistent),
            (Some(5), Outcome::Inconsistent),
            (Some(6), Outcome::Inconsistent)
        ]
    );
}

#[test]
fn test_retention_integrity_truncated_after_last_anchor_detected() {
    let mut scenario = Scenario::new();
    let records = scenario.records();
    // Anchored at 4, signed at 6: records 5 and 6 are cut off.
    let truncated = &records[..5];
    let verification = scenario.verify_records(truncated, intact);
    assert_eq!(verification.coverage.anchored_through, Some(4));
    // The signed head names a record the chain no longer holds.
    assert_eq!(verification.coverage.signed_through, None);
    assert!(
        verification
            .ranges
            .iter()
            .filter(|range| range.counter.is_some())
            .all(|range| range.outcome == Outcome::Inconsistent
                && range.reasons.contains(&Reason::Corruption)),
        "{verification:?}"
    );
    // The bytes whose seals were cut off. The SPEC does not classify them
    // after a truncation: ADR-0051 item 8 lists `unsealed` by name only.
    // It does guarantee that "None of these is silently classified as
    // `beyond_anchor`, which requires a valid chain", that "Only `verified`
    // supports a tamper-evidence statement", and that "A supplied old anchor
    // proves only the prefix it covers, never freshness or completeness
    // beyond it" (SPEC.md §8.4). So the test asserts that and no more: the
    // tail is never `verified` nor `beyond_anchor`. quantstratum-docs#934
    // asks the SPEC to state the tail's outcome; this test pins it then.
    assert!(
        verification
            .ranges
            .iter()
            .filter(|range| range.counter.is_none())
            .all(|range| range.outcome != Outcome::Verified
                && range.outcome != Outcome::BeyondAnchor),
        "{verification:?}"
    );
    assert!(
        verification
            .ranges
            .iter()
            .all(|range| range.outcome != Outcome::Verified)
    );
}

#[test]
fn test_retention_integrity_rollback_to_earlier_head_detected_against_anchor() {
    let (_, records) = chain(10);
    let anchored = receipted(AnchorKind::ClusterLog, REPLICA, 0, &records[6]);
    // The host rolls the journal back to record 4 and writes other records.
    let (mut rewritten, _) = chain(5);
    for start in [40, 48, 56] {
        rewritten
            .seal_segment(3, start, b"forged!!", false)
            .unwrap();
    }
    let forged = rewritten.records().unwrap();
    let report = check(&forged, &[anchored]);
    assert_eq!(report.findings, [AnchorFinding::Rollback { counter: 6 }]);
    assert_eq!(report.anchored_through, None);
    assert!(report.is_conflicting());
    // Rolled back to the earlier head without rewriting: truncation.
    let report = check(&records[..5], &[anchored]);
    assert_eq!(
        report.findings,
        [AnchorFinding::Truncated {
            anchored: 6,
            records: 5
        }]
    );
}

/// Opens a journal on a disk that crashes after `budget` units and seals
/// four ranges; returns the crashed disk, or `None` when it did not crash.
fn crashed_seal(budget: u64) -> Option<FaultDisk> {
    let disk = FaultDisk::with_budget(budget);
    if let Ok(opened) = IntegrityJournal::open(disk.clone(), Path::new(DIR)) {
        let mut journal = opened.journal;
        for index in 0..4u64 {
            if journal
                .seal_segment(3, index * 8, &index.to_le_bytes(), false)
                .is_err()
            {
                break;
            }
        }
    }
    disk.has_crashed().then_some(disk)
}

#[test]
fn test_retention_integrity_crash_while_sealing_recoverable_chain() {
    let (_, full) = chain(4);
    let full: Vec<Digest> = full.iter().map(SealRecord::digest).collect();
    let mut crashes = 0u32;
    for budget in 0..10_000 {
        let Some(disk) = crashed_seal(budget) else {
            break;
        };
        crashes += 1;
        for survives in [Survives::Synced, Survives::Everything] {
            let mut journal = IntegrityJournal::open(disk.after_crash(survives), Path::new(DIR))
                .unwrap()
                .journal;
            let records = journal.records().unwrap();
            verify_chain(&records).unwrap();
            // What survives is a prefix of the chain the run would write.
            let digests: Vec<Digest> = records.iter().map(SealRecord::digest).collect();
            assert_eq!(
                digests,
                full[..digests.len()],
                "budget {budget} {survives:?}"
            );
            // Sealing resumes from the recovered head.
            let start = journal.sealed_end(3).unwrap_or(0);
            journal.seal_segment(3, start, b"resumed!", false).unwrap();
            verify_chain(&journal.records().unwrap()).unwrap();
        }
    }
    assert!(crashes > 4, "{crashes}");
}

/// A signer that is down.
struct Unavailable;

impl HeadSigner for Unavailable {
    fn key_id(&self) -> Digest {
        key_id(&archival_key().verifying_key().to_bytes())
    }
    fn custody(&self) -> Custody {
        Custody::NoSeparation
    }
    fn sign(&mut self, _: &ChainHead) -> Result<[u8; SIGNATURE_LENGTH], SignerUnavailable> {
        Err(SignerUnavailable)
    }
}

/// A store of signed heads in memory.
#[derive(Default)]
struct Heads(Vec<SignedHead>);

impl HeadStore for Heads {
    fn record(&mut self, signed: &SignedHead) -> Result<(), IntegrityError> {
        self.0.push(*signed);
        Ok(())
    }
}

#[test]
fn test_retention_integrity_signer_unavailable_sealing_continues_lag_reported() {
    let mut journal = IntegrityJournal::open(FaultDisk::default(), Path::new(DIR))
        .unwrap()
        .journal;
    let config = SigningConfig::new(Some(1_000), BacklogPolicy::Coalesce).unwrap();
    let mut signing = HeadSigning::new(config, ARCHIVE, JOURNAL, 0);
    let mut signer = Unavailable;
    let mut store = Heads::default();
    let registry = registry();
    for round in 1..=20u64 {
        let now = round * 100;
        // The data path: sealing completes with the signer down.
        journal
            .seal_segment(3, (round - 1) * 8, &round.to_le_bytes(), false)
            .unwrap();
        let _ = signing.offer(
            ChainHead {
                archive_id: ARCHIVE,
                journal_id: JOURNAL,
                counter: journal.next_counter() - 1,
                digest: journal.head(),
            },
            now,
        );
        let signed = signing
            .poll(
                &mut signer,
                &mut store,
                &registry,
                &journal.records().unwrap(),
                now,
            )
            .unwrap();
        assert_eq!(signed, 0);
        let status = signing.status(now, journal.next_counter(), &registry);
        // The backlog stays bounded.
        assert!(status.pending <= 1, "round {round}");
        // The lag is reported before the first signed head.
        assert_eq!(status.last_signed, None);
        assert_eq!(status.coverage_lag_records, round);
        assert_eq!(status.coverage_lag_ns, now - 100);
    }
    let status = signing.status(2_000, journal.next_counter(), &registry);
    assert!(status.alarm);
    assert_eq!(status.coalesced, 19);
    assert!(store.0.is_empty());
    assert_eq!(journal.records().unwrap().len(), 20);
}

#[test]
fn test_retention_integrity_head_signed_after_revocation_invalid() {
    let (_, records) = chain(25);
    let mut registry = registry();
    registry.apply(&revocation(20)).unwrap();
    assert_eq!(
        registry.verify(&sign(&records[20]), Some(30)),
        HeadVerdict::Invalid(HeadReason::SignedAfterRevocation)
    );
    assert_eq!(
        registry.verify(&sign(&records[24]), None),
        HeadVerdict::Invalid(HeadReason::SignedAfterRevocation)
    );
}

#[test]
fn test_retention_integrity_head_without_pre_revocation_anchor_not_trusted() {
    let (_, records) = chain(25);
    let mut registry = registry();
    registry.apply(&revocation(20)).unwrap();
    let before = sign(&records[12]);
    assert_eq!(
        registry.verify(&before, None),
        HeadVerdict::NotTrustedEvidence(HeadReason::NoPreRevocationAnchor)
    );
    // An anchor below the head proves nothing about it.
    assert_eq!(
        registry.verify(&before, Some(11)),
        HeadVerdict::NotTrustedEvidence(HeadReason::NoPreRevocationAnchor)
    );
    assert!(matches!(
        registry.verify(&before, Some(12)),
        HeadVerdict::Trusted { .. }
    ));
}

#[test]
fn test_retention_integrity_untrusted_missing_or_conflicting_anchors_never_verified() {
    // Untrusted: the only anchor's signature is broken.
    let mut untrusted = Scenario::new();
    untrusted.anchors[0].signed.signature[0] ^= 1;
    let verification = untrusted.verify();
    assert!(verification.evidence.contains(&Reason::MalformedEvidence));
    never_verified(&verification);
    // Missing: a stated absence, beyond the anchor, never verified.
    let mut missing = Scenario::new();
    missing.anchors.clear();
    let verification = missing.verify();
    assert_eq!(verification.anchors.absent, Some(Absence::NoAnchor));
    for range in &verification.ranges {
        assert_eq!(range.outcome, Outcome::BeyondAnchor);
        assert_eq!(range.reasons, [Reason::NoAnchor]);
    }
    // Conflicting: another head at the anchored position.
    let mut conflicting = Scenario::new();
    let records = conflicting.records();
    let mut other = sign(&records[5]);
    other.head.digest = digest(b"another head");
    other.signature = archival_key()
        .sign(&other.head.signed_bytes(other.custody))
        .to_bytes();
    conflicting.anchors.push(Anchor {
        kind: AnchorKind::ReplicaJournal,
        location: REPLICA,
        external_counter: 0,
        receipt: [0; 32],
        signed: other,
    });
    let verification = conflicting.verify();
    for range in &verification.ranges {
        assert_eq!(range.outcome, Outcome::Inconsistent);
        assert!(range.reasons.contains(&Reason::ConflictingAnchors));
    }
}

#[test]
fn test_retention_integrity_anchor_equivocation_or_rollback_flagged() {
    let (_, records) = chain(10);
    let (mut fork, _) = chain(5);
    fork.seal_segment(3, 40, b"another", false).unwrap();
    let other = fork.records().unwrap();
    let one = receipted(AnchorKind::OperatorExport, OPERATOR, 0, &records[5]);
    let two = receipted(AnchorKind::ReplicaJournal, REPLICA, 0, &other[5]);
    let report = check(&records, &[one, two]);
    assert_eq!(
        report.findings,
        [AnchorFinding::Equivocation { counter: 5 }]
    );
    assert_eq!(report.anchored_through, None);
    assert!(report.is_conflicting());
    // A store whose counter rises while its anchored head goes back.
    let later = receipted(AnchorKind::OperatorExport, OPERATOR, 1, &records[3]);
    let earlier = receipted(AnchorKind::OperatorExport, OPERATOR, 2, &records[2]);
    let report = check(&records, &[later, earlier]);
    assert_eq!(
        report.findings,
        [AnchorFinding::CounterRollback {
            kind: AnchorKind::OperatorExport,
            location: OPERATOR
        }]
    );
    assert!(report.is_conflicting());
}

#[test]
fn test_retention_integrity_index_shortened_below_seal_inconsistent() {
    let mut scenario = Scenario::new();
    let verification = scenario.verify_with(|_, start, _| {
        if start >= 32 {
            RangeBytes::Missing
        } else {
            RangeBytes::Bytes(range(start / 8))
        }
    });
    assert_eq!(verification.ranges[3].outcome, Outcome::Verified);
    let shortened = &verification.ranges[4];
    assert_eq!(shortened.outcome, Outcome::Inconsistent);
    assert_eq!(shortened.reasons, [Reason::ShortenedIndex]);
    assert_eq!(shortened.first_inconsistent, Some(5));
}

#[test]
fn test_retention_integrity_each_outcome_reachable() {
    let mut scenario = Scenario::new();
    let records = scenario.records();
    // Range 0 purged under a signed head; bytes written past the seals.
    scenario
        .journal
        .record_purge(3, 0, 8, records[1].content)
        .unwrap();
    scenario.sign_head();
    scenario.written = vec![(3, 60)];
    let verification = scenario.verify_with(|_, start, _| {
        let mut bytes = range(start / 8);
        if start == 16 {
            bytes[0] ^= 1;
        }
        RangeBytes::Bytes(bytes)
    });
    let reached: BTreeSet<&str> = verification
        .ranges
        .iter()
        .map(|range| range.outcome.name())
        .collect();
    let all: BTreeSet<&str> = [
        Outcome::Verified,
        Outcome::BeyondAnchor,
        Outcome::Unsealed,
        Outcome::Purged,
        Outcome::Inconsistent,
    ]
    .into_iter()
    .map(Outcome::name)
    .collect();
    assert_eq!(reached, all, "{verification:?}");
}

/// SPEC.md §13, Retention integrity: "an export is verified offline" (ADR-0103;
/// karyos#668, #670). The contract scenario's own evidence (its chain, a
/// head signed at record 6 and anchored at record 4, the registry, the
/// recording's bytes, an unsealed tail) is exported, then verified with
/// the external trust only, no Archive present: every range's outcome is
/// the online verifier's, the anchored ranges `verified`, the later ones
/// `beyond_anchor`, the tail `unsealed`.
#[test]
fn test_retention_integrity_export_verified_offline() {
    use super::export::assemble::{ExportContents, JournalExport, RecordingExport, assemble};
    use super::export::offline::{OfflineTrust, Role, verify_export};

    let mut scenario = Scenario::new();
    scenario.written = vec![(3, 52)];
    let online = scenario.verify_with(|_, start, end| {
        if start >= 48 {
            RangeBytes::Bytes(vec![0xEE; usize::try_from(end - start).unwrap()])
        } else {
            RangeBytes::Bytes(range(start / 8))
        }
    });
    let mut bytes: Vec<u8> = (0..6).flat_map(range).collect();
    bytes.extend_from_slice(&[0xEE; 4]);
    let contents = ExportContents {
        archive_id: ARCHIVE,
        journals: vec![JournalExport {
            id: JOURNAL,
            role: 1,
            records: scenario.records(),
            heads: scenario
                .heads
                .iter()
                .map(|head| SignedHead::decode(head).unwrap())
                .collect(),
            anchors: scenario.anchors.clone(),
            registry: scenario
                .keys
                .iter()
                .map(|entry| RegistryEntry::decode(entry).unwrap())
                .collect(),
        }],
        recordings: vec![RecordingExport {
            recording: 3,
            start: 0,
            segment_length: 64,
            bytes,
            ..RecordingExport::default()
        }],
        ..ExportContents::default()
    };
    let export = assemble(&contents).unwrap();
    // No Archive: only the bytes, the trust and the anchor stores.
    drop(scenario.journal);
    let externality = Externality {
        local_archive: ARCHIVE,
        ..Externality::default()
    };
    let report = verify_export(
        &export,
        &OfflineTrust {
            trust: &trust(),
            journals: &[(JOURNAL, Role::Archive)],
            stores: &Held(&scenario.anchors),
            externality: &externality,
            requirement: None,
        },
    )
    .unwrap();
    let outcomes = |verification: &Verification| -> Vec<(u64, u64, u64, Outcome)> {
        verification
            .ranges
            .iter()
            .map(|range| (range.recording, range.start, range.end, range.outcome))
            .collect()
    };
    let offline = outcomes(&report.journals[0].2);
    assert_eq!(offline, outcomes(&online));
    assert!(
        offline.contains(&(3, 0, 8, Outcome::Verified)),
        "{offline:?}"
    );
    assert!(
        offline.contains(&(3, 40, 48, Outcome::BeyondAnchor)),
        "{offline:?}"
    );
    assert!(
        offline.contains(&(3, 48, 52, Outcome::Unsealed)),
        "{offline:?}"
    );
}

// ---------------------------------------------------------------------
// Time evidence cases: the verdict vocabulary only.
// ---------------------------------------------------------------------

const VALID_TO: u64 = 1_000_000_000_000;

fn coordinate() -> Coordinate {
    Coordinate::new(7).unwrap()
}

fn clock(domain: u64) -> ClockKey {
    ClockKey {
        observer: ObserverId {
            driver: [1, 2],
            journal: 3,
        },
        domain,
        epoch: 1,
    }
}

fn calibration() -> CalibrationEvidence {
    CalibrationEvidence {
        calibration: Calibration {
            from: clock(1),
            to: clock(2),
            reference: 0,
            offset: 1_000,
            offset_uncertainty: 10,
            drift: 0,
            drift_uncertainty: 0,
            valid_from: 0,
            valid_to: VALID_TO,
        },
        target_kind: TargetKind::Traceable,
        authoritative: true,
    }
}

fn reference() -> UtcReference {
    UtcReference {
        clock: clock(2),
        bound_ns: 50,
        valid_from: 0,
        valid_to: VALID_TO,
        source: Source::Ptp,
        sync_state: SyncState::Synchronised,
        scale_stated: true,
        coordinate: Some(coordinate()),
    }
}

fn evidence() -> ClockEvidence {
    ClockEvidence {
        sync_state: SyncState::Synchronised,
        source: Source::Ptp,
        granularity_ns: Some(1),
        coordinate: Some(coordinate()),
        calibration: Some(calibration()),
        reference: Some(reference()),
        min: 1_000,
        max: 2_000,
    }
}

fn requirement(max_divergence_ns: u64) -> Requirement {
    Requirement {
        max_divergence_ns,
        max_granularity_ns: 1_000,
    }
}

fn sample(position: u64, timestamp: u64, parameters: u64) -> Sample {
    Sample {
        position,
        timestamp,
        parameters,
        leap_boundary: false,
    }
}

#[test]
fn test_retention_integrity_missing_utc_reference_or_calibration_no_evidence() {
    assert_eq!(
        clock_verdict(&evidence(), &requirement(5_000)),
        Verdict::Met
    );
    for missing in [
        ClockEvidence {
            reference: None,
            ..evidence()
        },
        ClockEvidence {
            calibration: None,
            ..evidence()
        },
    ] {
        // However generous the requirement, never met.
        for divergence in [5_000, u64::MAX] {
            assert_eq!(
                clock_verdict(&missing, &requirement(divergence)),
                Verdict::NoEvidence,
                "{missing:?}"
            );
        }
    }
}

#[test]
fn test_retention_integrity_bound_change_mid_range_splits_entries() {
    let entries = split(&[sample(0, 10, 1), sample(8, 20, 1), sample(16, 30, 2)]);
    assert_eq!(entries.len(), 2);
    assert_eq!((entries[0].min, entries[0].max), (10, 20));
    assert_eq!(entries[0].last_position, 8);
    assert_eq!(entries[1].first_position, 16);
    assert_eq!(entries[1].parameters, 2);
}

#[test]
fn test_retention_integrity_non_monotone_samples_split_entries() {
    let entries = split(&[sample(0, 10, 1), sample(8, 30, 1), sample(16, 20, 1)]);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].last_position, 8);
    assert_eq!(entries[1].first_position, 16);
}

#[test]
fn test_retention_integrity_leap_boundary_splits_entries() {
    let mut leap = sample(16, 30, 1);
    leap.leap_boundary = true;
    let entries = split(&[sample(0, 10, 1), sample(8, 20, 1), leap]);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].last_position, 8);
    assert_eq!(entries[1].first_position, 16);
}

#[test]
fn test_retention_integrity_clamp_behind_leader_own_bound_or_no_evidence() {
    let cal = calibration().calibration;
    // The leader's clock is behind: the clamp keeps the raw value, and its
    // bound is computed for it, not assumed.
    let raw = 4_000;
    let leader_last = 3_000;
    let clamped = raw.max(leader_last);
    assert_eq!(
        derived_bound(clamped, raw, coordinate(), &cal, &reference()),
        combined_bound(raw, coordinate(), &cal, &reference())
    );
    // A clamp that moves the value gets a bound of its own, never the raw.
    let moved = derived_bound(9_000, raw, coordinate(), &cal, &reference()).unwrap();
    assert_ne!(
        moved,
        combined_bound(raw, coordinate(), &cal, &reference()).unwrap()
    );
    // Without the raw value's UTC interval it is no evidence.
    let mut unscaled = reference();
    unscaled.scale_stated = false;
    assert_eq!(
        derived_bound(9_000, raw, coordinate(), &cal, &unscaled),
        Err(Gap::ScaleNotStated)
    );
}

#[test]
fn test_retention_integrity_verdict_precedence_not_met_over_no_evidence() {
    let unsynchronised = ClockEvidence {
        sync_state: SyncState::Unsynchronised,
        calibration: None,
        reference: None,
        granularity_ns: None,
        ..evidence()
    };
    assert_eq!(
        clock_verdict(&unsynchronised, &requirement(5_000)),
        Verdict::NotMet
    );
    // C-COMP: not_met over no_evidence over met, the gaps kept.
    let combined = reduce(
        &[Verdict::NotMet, Verdict::NoEvidence, Verdict::Met],
        Some(&requirement(1)),
    )
    .unwrap();
    assert_eq!(combined.verdict, Verdict::NotMet);
    assert_eq!(combined.gaps, vec![1]);
    assert_eq!(
        reduce(&[Verdict::Met, Verdict::NoEvidence], Some(&requirement(1)))
            .unwrap()
            .verdict,
        Verdict::NoEvidence
    );
}

// ---------------------------------------------------------------------
// Retention cases: an archive of three sealed segments with two copies.
// ---------------------------------------------------------------------

const RECORDING: u64 = 3;
const BEFORE: u64 = 256;
const REPLICA_A: Digest = [30; 32];
const REPLICA_B: Digest = [31; 32];

type Ops = Ledger<FaultDisk, OPERATION_LENGTH>;
type Markers = Ledger<FaultDisk, MARKER_LENGTH>;

/// An operations journal that is down.
struct Down;

impl OperationsJournal for Down {
    fn append(&mut self, _: &Operation) -> io::Result<Digest> {
        Err(io::Error::other("operations journal unavailable"))
    }
}

fn geometry() -> Geometry {
    Geometry::new(64, 128).unwrap()
}

fn chunk(index: u64) -> Vec<u8> {
    vec![u8::try_from(index).unwrap(); 64]
}

fn policy(retain_for_ns: u64) -> RetentionPolicy {
    RetentionPolicy {
        policy: 1,
        version: 1,
        retain_for_ns,
        min_copies: NonZeroU32::new(2).unwrap(),
        storage_tier: 0,
        purge: PurgeMode::AfterExpiry,
    }
}

fn request() -> PurgeRequest {
    PurgeRequest {
        id: 1,
        recording: RECORDING,
        before: BEFORE,
        authorisation: Authorisation {
            operator: 42,
            authorised: true,
        },
        closed_ns: 0,
        source: PurgeSource::Operator,
    }
}

fn setup(disk: &FaultDisk) {
    let dir = Path::new(DIR);
    let mut journal = IntegrityJournal::open(disk.clone(), dir).unwrap().journal;
    let mut keys = Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(disk.clone(), dir, KEYS_FILE).unwrap();
    KeyRegistry::new(trust())
        .append(&registration(), &mut journal, &mut keys)
        .unwrap();
    let mut store = SegmentStore::create(
        disk.clone(),
        dir,
        RECORDING,
        geometry(),
        SyncPolicy::None,
        0,
    )
    .unwrap();
    for index in 0..6 {
        store.append(index * 64, &chunk(index)).unwrap();
    }
    store.close_synced().unwrap();
    for segment in 0..3u64 {
        let mut bytes = chunk(segment * 2);
        bytes.extend(chunk(segment * 2 + 1));
        journal
            .seal_segment(RECORDING, segment * 128, &bytes, true)
            .unwrap();
    }
    let mut copies = CopyCatalog::open(disk.clone(), dir, &mut journal).unwrap();
    for location in [REPLICA_A, REPLICA_B] {
        copies
            .record(
                CopyRecord {
                    sequence: 0,
                    recording: RECORDING,
                    start: 0,
                    end: 384,
                    location,
                    digest: digest(b"copy"),
                    retain_until_ns: 0,
                    state: CopyState::Verified,
                    enforcement: Enforcement::ObjectLock,
                },
                &mut journal,
            )
            .unwrap();
    }
}

struct Archive {
    disk: FaultDisk,
    journal: IntegrityJournal<FaultDisk>,
    store: SegmentStore<FaultDisk>,
    copies: CopyCatalog<FaultDisk>,
    retention: Retention<Ops, FaultDisk>,
}

/// Opens the archive on `disk` as a restart does.
fn open(disk: FaultDisk) -> Archive {
    let dir = Path::new(DIR);
    let mut journal = IntegrityJournal::open(disk.clone(), dir).unwrap().journal;
    let store = SegmentStore::recover(disk.clone(), dir, RECORDING, geometry(), SyncPolicy::None)
        .unwrap()
        .store;
    let copies = CopyCatalog::open(disk.clone(), dir, &mut journal).unwrap();
    let ops = Ops::open(disk.clone(), dir, OPERATIONS_FILE).unwrap();
    let records = ops.entries().to_vec();
    let markers = Markers::open(disk.clone(), dir, PENDING_HOLDS_FILE).unwrap();
    let retention = Retention::recover(ops, Some(&records), markers);
    Archive {
        disk,
        journal,
        store,
        copies,
        retention,
    }
}

fn context<'a>(
    policy: &'a RetentionPolicy,
    copies: &'a CopyCatalog<FaultDisk>,
    now_ns: u64,
) -> PurgeContext<'a, FaultDisk> {
    PurgeContext {
        policy: Some(policy),
        copies,
        local: ARCHIVE,
        now_ns,
    }
}

fn operations(disk: &FaultDisk) -> Vec<Operation> {
    let mut disk = disk.clone();
    read_entries::<_, OPERATION_LENGTH>(&mut disk, Path::new(DIR), OPERATIONS_FILE)
        .unwrap()
        .iter()
        .filter_map(Operation::decode)
        .collect()
}

impl Archive {
    fn purge(&mut self, policy: &RetentionPolicy, now_ns: u64) -> Result<SealRecord, PurgeError> {
        let context = context(policy, &self.copies, now_ns);
        self.retention
            .purge(&request(), &context, &mut self.store, &mut self.journal)
    }
}

#[test]
fn test_retention_integrity_purge_under_hold_or_before_expiry_rejected_and_journalled() {
    let disk = FaultDisk::default();
    setup(&disk);
    let mut archive = open(disk);
    let policy = policy(1_000);
    assert!(matches!(
        archive.purge(&policy, 999),
        Err(PurgeError::Refused {
            refusal: PurgeRefusal::NotExpired { expires_ns: 1_000 },
            journalled: true
        })
    ));
    assert!(matches!(
        archive.retention.apply_hold(RECORDING),
        HoldReport::Applied { .. }
    ));
    assert!(matches!(
        archive.purge(&policy, 5_000),
        Err(PurgeError::Refused {
            refusal: PurgeRefusal::LegalHold,
            journalled: true
        })
    ));
    assert_eq!(archive.store.start(), 0);
    let rejected: Vec<u8> = operations(&archive.disk)
        .into_iter()
        .filter_map(|operation| match operation {
            Operation::PurgeRejected { reason, .. } => Some(reason),
            _ => None,
        })
        .collect();
    assert_eq!(
        rejected,
        [
            PurgeRefusal::NotExpired { expires_ns: 0 }.code(),
            PurgeRefusal::LegalHold.code()
        ]
    );
}

/// Runs the purge on a disk that crashes after `budget` units past the
/// setup and the restart; returns the crashed disk, or `None`.
fn crashed_purge(budget: u64) -> Option<FaultDisk> {
    let setup_disk = FaultDisk::default();
    setup(&setup_disk);
    let _ = open(setup_disk.clone());
    let used = setup_disk.used();
    let disk = FaultDisk::with_budget(used + budget);
    setup(&disk);
    let mut archive = open(disk.clone());
    let _ = archive.purge(&policy(1_000), 5_000);
    disk.has_crashed().then_some(disk)
}

#[test]
fn test_retention_integrity_crash_between_intent_and_deletion_hold_inhibits_deletion() {
    let mut crashes = 0u32;
    let mut held_back = 0u32;
    for budget in 0..400 {
        let Some(disk) = crashed_purge(budget) else {
            break;
        };
        crashes += 1;
        for survives in [Survives::Synced, Survives::Everything] {
            let mut archive = open(disk.after_crash(survives));
            let deleted = archive.store.start();
            assert!(matches!(
                archive.retention.apply_hold(RECORDING),
                HoldReport::Applied { .. }
            ));
            let policy = policy(1_000);
            let context = context(&policy, &archive.copies, 5_000);
            let outcomes = archive
                .retention
                .recover_purges(&context, |_| true, &mut archive.store, &mut archive.journal)
                .unwrap();
            assert_eq!(
                archive.store.start(),
                deleted,
                "budget {budget} {survives:?}"
            );
            if deleted < BEFORE && !outcomes.is_empty() {
                assert_eq!(outcomes, [Err(PurgeRefusal::LegalHold)]);
                held_back += 1;
            }
            verify_chain(&archive.journal.records().unwrap()).unwrap();
        }
    }
    assert!(crashes > 10, "{crashes}");
    assert!(held_back > 0, "{held_back}");
}

#[test]
fn test_retention_integrity_hold_unknown_at_restart_purge_inhibited() {
    let disk = FaultDisk::default();
    setup(&disk);
    let markers = Markers::open(disk.clone(), Path::new(DIR), PENDING_HOLDS_FILE).unwrap();
    // The hold state could not be read at restart.
    let mut retention = Retention::recover(Down, None, markers);
    let mut journal = IntegrityJournal::open(disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let copies = CopyCatalog::open(disk, Path::new(DIR), &mut journal).unwrap();
    let policy = policy(1_000);
    assert_eq!(
        retention.check(&request(), &context(&policy, &copies, 5_000), 0),
        Err(PurgeRefusal::HoldsUnknown)
    );
    assert_eq!(
        retention.release_hold(RECORDING),
        Err(ReleaseError::Unknown)
    );
}
