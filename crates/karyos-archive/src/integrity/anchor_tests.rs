// SPDX-License-Identifier: Apache-2.0

//! Tests of external anchors and the copy catalog (karyos#664).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::path::Path;

use super::anchor::*;
use super::copies::*;
use super::test_support::*;
use super::trust::{HeadReason, RegistryAction, RegistryEntry};
use super::{SealRecord, digest};
use crate::fault::FaultDisk;

const REPLICA: [u8; 32] = [20; 32];
const OPERATOR: [u8; 32] = [21; 32];

fn anchor(kind: AnchorKind, location: [u8; 32], external: u64, record: &SealRecord) -> Anchor {
    Anchor {
        kind,
        location,
        external_counter: external,
        receipt: digest(&external.to_le_bytes()),
        signed: sign(record),
    }
}

/// The stores of these tests: each confirms an anchor whose receipt is
/// the digest of its external counter, as [`anchor`] builds it.
struct Receipts;

impl AnchorEvidence for Receipts {
    fn confirms(&self, anchor: &Anchor) -> bool {
        anchor.receipt == digest(&anchor.external_counter.to_le_bytes())
    }
}

fn externality() -> Externality {
    Externality {
        local_archive: ARCHIVE,
        ..Externality::default()
    }
}

fn check(records: &[SealRecord], anchors: &[Anchor]) -> AnchorReport {
    check_anchors(
        records,
        JOURNAL,
        anchors,
        &registry(),
        &externality(),
        &Receipts,
    )
}

#[test]
fn an_anchor_covers_its_prefix_and_no_more() {
    let (_, records) = chain(10);
    let old = anchor(AnchorKind::OperatorExport, OPERATOR, 0, &records[3]);
    let report = check(&records, &[old]);
    assert_eq!(report.anchored_through, Some(3));
    assert!(report.findings.is_empty());
    assert_eq!(report.absent, None);
    // A later anchor raises it; the old one alone never does.
    let new = anchor(AnchorKind::OperatorExport, OPERATOR, 1, &records[8]);
    assert_eq!(check(&records, &[old, new]).anchored_through, Some(8));
}

#[test]
fn truncation_after_the_last_anchored_head_is_detected() {
    let (_, records) = chain(10);
    let anchored = anchor(AnchorKind::ReplicaJournal, REPLICA, 0, &records[7]);
    let report = check(&records[..5], &[anchored]);
    assert_eq!(
        report.findings,
        vec![AnchorFinding::Truncated {
            anchored: 7,
            records: 5
        }]
    );
    assert_eq!(report.anchored_through, None);
    assert!(report.is_conflicting());
}

#[test]
fn a_rollback_below_an_anchor_is_detected() {
    let (_, records) = chain(10);
    let anchored = anchor(AnchorKind::ClusterLog, REPLICA, 0, &records[6]);
    // The host rolls back to record 4 and writes different records after.
    let (mut rewritten, _) = chain(5);
    rewritten.seal_segment(3, 40, b"forged!!", false).unwrap();
    rewritten.seal_segment(3, 48, b"forged!!", false).unwrap();
    rewritten.seal_segment(3, 56, b"forged!!", false).unwrap();
    let forged = rewritten.records().unwrap();
    let report = check(&forged, &[anchored]);
    assert_eq!(
        report.findings,
        vec![AnchorFinding::Rollback { counter: 6 }]
    );
}

#[test]
fn two_conflicting_anchors_are_flagged_as_equivocation() {
    let (_, records) = chain(10);
    let (_, other) = {
        let (mut journal, _) = chain(5);
        journal.seal_segment(3, 40, b"another", false).unwrap();
        let records = journal.records().unwrap();
        (journal, records)
    };
    let one = anchor(AnchorKind::OperatorExport, OPERATOR, 0, &records[5]);
    let two = anchor(AnchorKind::ReplicaJournal, REPLICA, 0, &other[5]);
    let report = check(&records, &[one, two]);
    assert_eq!(
        report.findings,
        vec![AnchorFinding::Equivocation { counter: 5 }]
    );
    // Neither side is picked.
    assert_eq!(report.anchored_through, None);
    assert_eq!(report.absent, Some(Absence::NoTrustedAnchor));
}

#[test]
fn a_store_counter_that_goes_back_is_a_counter_rollback() {
    let (_, records) = chain(10);
    let later = anchor(AnchorKind::OperatorExport, OPERATOR, 1, &records[3]);
    let earlier = anchor(AnchorKind::OperatorExport, OPERATOR, 2, &records[2]);
    let report = check(&records, &[later, earlier]);
    assert_eq!(
        report.findings,
        vec![AnchorFinding::CounterRollback {
            kind: AnchorKind::OperatorExport,
            location: OPERATOR
        }]
    );
}

#[test]
fn a_local_replica_and_a_circular_pair_are_refused_as_external() {
    let (_, records) = chain(4);
    let mut externality = externality();
    externality.local_locations.insert(REPLICA);
    let local = anchor(AnchorKind::ReplicaJournal, REPLICA, 0, &records[2]);
    let report = check_anchors(
        &records,
        JOURNAL,
        &[local],
        &registry(),
        &externality,
        &Receipts,
    );
    assert_eq!(
        report.findings,
        vec![AnchorFinding::Untrusted {
            index: 0,
            reason: AnchorReason::LocalReplica
        }]
    );
    assert_eq!(report.absent, Some(Absence::NoTrustedAnchor));
    // Two Archives anchoring each other anchor nothing.
    let mut pair = Externality {
        local_archive: ARCHIVE,
        ..Externality::default()
    };
    pair.anchored_by_this.insert(OPERATOR);
    let circular = anchor(AnchorKind::ReplicaJournal, OPERATOR, 0, &records[2]);
    let report = check_anchors(
        &records,
        JOURNAL,
        &[circular],
        &registry(),
        &pair,
        &Receipts,
    );
    assert_eq!(
        report.findings,
        vec![AnchorFinding::Untrusted {
            index: 0,
            reason: AnchorReason::Circular
        }]
    );
    // An anchor kept in this very Archive is not external either.
    let own = anchor(AnchorKind::ReplicaJournal, ARCHIVE, 0, &records[2]);
    assert_eq!(
        check(&records, &[own]).findings,
        vec![AnchorFinding::Untrusted {
            index: 0,
            reason: AnchorReason::NotExternal
        }]
    );
}

#[test]
fn a_missing_anchor_is_a_stated_absence_neither_pass_nor_failure() {
    let (_, records) = chain(4);
    let report = check(&records, &[]);
    assert_eq!(report.absent, Some(Absence::NoAnchor));
    assert_eq!(report.anchored_through, None);
    assert!(report.findings.is_empty());
    assert!(!report.is_conflicting());
}

#[test]
fn an_untrusted_or_deferred_anchor_carries_its_reason() {
    let (_, records) = chain(4);
    let deferred = anchor(AnchorKind::Rfc3161, OPERATOR, 0, &records[1]);
    let mut forged = anchor(AnchorKind::OperatorExport, OPERATOR, 0, &records[2]);
    forged.signed.signature[0] ^= 1;
    let mut other_journal = anchor(AnchorKind::OperatorExport, OPERATOR, 1, &records[3]);
    other_journal.signed.head.journal_id = 2;
    let report = check(&records, &[deferred, forged, other_journal]);
    assert_eq!(
        report.findings,
        vec![
            AnchorFinding::Untrusted {
                index: 0,
                reason: AnchorReason::KindDeferred
            },
            AnchorFinding::Untrusted {
                index: 1,
                reason: AnchorReason::Head(HeadReason::BadSignature)
            },
            AnchorFinding::Untrusted {
                index: 2,
                reason: AnchorReason::WrongJournal
            },
        ]
    );
    assert_eq!(report.anchored_through, None);
    assert!(!report.is_conflicting());
}

#[test]
fn an_ancestry_proof_shows_a_later_anchor_extends_an_earlier_one() {
    let (_, records) = chain(8);
    let earlier = sign(&records[2]).head;
    let later = sign(&records[6]).head;
    assert!(proves_ancestry(&earlier, &later, &records[3..=6]));
    assert!(!proves_ancestry(&earlier, &later, &records[3..=5]));
    let mut swapped = records[3..=6].to_vec();
    swapped.swap(0, 1);
    assert!(!proves_ancestry(&earlier, &later, &swapped));
}

#[test]
fn the_policy_requires_kinds_and_a_maximum_interval() {
    let (_, records) = chain(10);
    let report = check(
        &records,
        &[anchor(AnchorKind::OperatorExport, OPERATOR, 0, &records[2])],
    );
    let policy = AnchorPolicy {
        required_kinds: BTreeSet::from([AnchorKind::OperatorExport, AnchorKind::ReplicaJournal]),
        max_unanchored_records: NonZeroU64::new(5).unwrap(),
    };
    assert_eq!(
        policy.check(&report, 10),
        vec![
            PolicyFinding::MissingKind(AnchorKind::ReplicaJournal),
            PolicyFinding::IntervalExceeded { unanchored: 7 },
        ]
    );
    assert_eq!(policy.check(&report, 8).len(), 1);
}

#[test]
fn anchors_are_published_on_schedule_with_what_a_third_party_needs() {
    let (_, records) = chain(10);
    let disk = FaultDisk::default();
    let operator_dir = Path::new("/operator");
    let mut store = LedgerAnchorStore::open(
        disk.clone(),
        operator_dir,
        AnchorKind::OperatorExport,
        OPERATOR,
    )
    .unwrap();
    let every = NonZeroU64::new(4).unwrap();
    let first = publish_due(&mut store, None, Some(&sign(&records[1])), every)
        .unwrap()
        .unwrap();
    assert_eq!(first.external_counter, 0);
    assert_eq!(
        publish_due(&mut store, Some(1), Some(&sign(&records[4])), every).unwrap(),
        None
    );
    let second = publish_due(&mut store, Some(1), Some(&sign(&records[5])), every)
        .unwrap()
        .unwrap();
    assert_eq!(second.external_counter, 1);
    // A third party reopens the store and checks the chain against it.
    let reopened =
        LedgerAnchorStore::open(disk, operator_dir, AnchorKind::OperatorExport, OPERATOR).unwrap();
    let anchors = reopened.anchors();
    assert_eq!(anchors.len(), 2);
    let report = check_anchors(
        &records,
        JOURNAL,
        &anchors,
        &registry(),
        &externality(),
        &reopened,
    );
    assert_eq!(report.anchored_through, Some(5));
    assert!(report.findings.is_empty());
    assert_eq!(anchors[0], first);
    // The store confirms only what it holds, where it holds it.
    let mut moved = first;
    moved.external_counter = 1;
    assert!(!reopened.confirms(&moved));
    let mut rewritten = first;
    rewritten.receipt = [0; 32];
    assert!(!reopened.confirms(&rewritten));
    assert_eq!(
        Anchor::decode(&first.encode()).unwrap().signed,
        first.signed
    );
}

fn copy(location: [u8; 32], state: CopyState, enforcement: Enforcement) -> CopyRecord {
    CopyRecord {
        sequence: 0,
        recording: 3,
        start: 0,
        end: 80,
        location,
        digest: digest(b"range"),
        retain_until_ns: 1_000,
        state,
        enforcement,
    }
}

#[test]
fn the_catalog_states_the_immutability_enforcement_per_copy() {
    let disk = FaultDisk::default();
    let (mut journal, _) = chain(2);
    let mut copies = CopyCatalog::open(disk.clone(), Path::new(DIR), &mut journal).unwrap();
    let local = copy(ARCHIVE, CopyState::Verified, Enforcement::Unsupported);
    let remote = copy(REPLICA, CopyState::Verified, Enforcement::ObjectLock);
    let record = copies.record(local, &mut journal).unwrap();
    copies.record(remote, &mut journal).unwrap();
    // Each copy record is chained as a copy change.
    assert_eq!(record.kind, super::SealKind::Copy);
    assert_eq!(record.content, digest(&copies.records()[0].encode()));
    let reopened = CopyCatalog::open(disk, Path::new(DIR), &mut journal).unwrap();
    let current = reopened.current();
    assert_eq!(current[0].enforcement, Enforcement::Unsupported);
    assert_eq!(current[1].enforcement, Enforcement::ObjectLock);
    assert_eq!(reopened.verified_copies(3, 0, 80), 2);
    // Storage without support says so rather than proceeding silently.
    let mut backend = NoImmutability;
    use super::copies::ImmutabilityBackend as _;
    assert_eq!(
        backend.enforce(Path::new("/archive/x.seg"), 1_000).unwrap(),
        Enforcement::Unsupported
    );
}

#[test]
fn an_unverified_or_removed_copy_counts_towards_nothing() {
    let (mut journal, _) = chain(1);
    let mut copies = CopyCatalog::open(FaultDisk::default(), Path::new(DIR), &mut journal).unwrap();
    copies
        .record(
            copy(REPLICA, CopyState::Unverified, Enforcement::Unsupported),
            &mut journal,
        )
        .unwrap();
    assert_eq!(copies.verified_copies(3, 0, 80), 0);
    copies
        .record(
            copy(REPLICA, CopyState::Verified, Enforcement::Unsupported),
            &mut journal,
        )
        .unwrap();
    assert_eq!(copies.verified_copies(3, 0, 80), 1);
    assert_eq!(copies.verified_copies(3, 0, 81), 0);
    copies
        .record(
            copy(REPLICA, CopyState::Removed, Enforcement::Unsupported),
            &mut journal,
        )
        .unwrap();
    assert_eq!(copies.verified_copies(3, 0, 80), 0);
    assert_eq!(copies.current().len(), 1);
}

#[test]
fn an_anchor_its_store_does_not_confirm_does_not_count() {
    let (_, records) = chain(4);
    // A valid signed head wrapped in invented store metadata.
    let invented = Anchor {
        kind: AnchorKind::ObjectLock,
        location: [9; 32],
        external_counter: 999,
        receipt: [0; 32],
        signed: sign(&records[0]),
    };
    let report = check(&records, &[invented]);
    assert_eq!(
        report.findings,
        vec![AnchorFinding::Untrusted {
            index: 0,
            reason: AnchorReason::Unconfirmed
        }]
    );
    assert_eq!(report.anchored_through, None);
    assert!(report.kinds.is_empty());
}

#[test]
fn an_ancestry_proof_requires_the_same_archive_and_journal() {
    let (_, records) = chain(8);
    let earlier = sign(&records[2]).head;
    let mut later = sign(&records[6]).head;
    later.journal_id = JOURNAL + 1;
    assert!(!proves_ancestry(&earlier, &later, &records[3..=6]));
    let mut later = sign(&records[6]).head;
    later.archive_id = [1; 32];
    assert!(!proves_ancestry(&earlier, &later, &records[3..=6]));
}

#[test]
fn a_repeated_anchor_counts_once_and_a_different_one_at_its_counter_conflicts() {
    let (_, records) = chain(6);
    let one = anchor(AnchorKind::OperatorExport, OPERATOR, 0, &records[3]);
    let report = check(&records, &[one, one]);
    assert!(report.findings.is_empty());
    assert_eq!(report.anchored_through, Some(3));
    assert!(!report.is_conflicting());
    let other = anchor(AnchorKind::OperatorExport, OPERATOR, 0, &records[4]);
    let report = check(&records, &[one, other]);
    assert_eq!(
        report.findings,
        vec![AnchorFinding::CounterRollback {
            kind: AnchorKind::OperatorExport,
            location: OPERATOR
        }]
    );
}

#[test]
fn a_copy_whose_journal_append_failed_never_counts() {
    use super::journal::IntegrityJournal;
    let probe = FaultDisk::default();
    IntegrityJournal::open(probe.clone(), Path::new(DIR)).unwrap();
    // A journal disk that crashes on the first append after opening.
    let journal_disk = FaultDisk::with_budget(probe.used());
    let mut journal = IntegrityJournal::open(journal_disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let copies_disk = FaultDisk::default();
    let mut copies = CopyCatalog::open(copies_disk.clone(), Path::new(DIR), &mut journal).unwrap();
    let remote = copy(REPLICA, CopyState::Verified, Enforcement::ObjectLock);
    assert!(copies.record(remote, &mut journal).is_err());
    assert!(journal_disk.has_crashed());
    assert_eq!(copies.verified_copies(3, 0, 80), 0);
    assert!(copies.records().is_empty());
    // The ledger entry survived, but the reopened catalog filters it out.
    let mut recovered = IntegrityJournal::open(
        journal_disk.after_crash(crate::fault::Survives::Synced),
        Path::new(DIR),
    )
    .unwrap()
    .journal;
    assert_eq!(recovered.next_counter(), 0);
    let reopened = CopyCatalog::open(copies_disk, Path::new(DIR), &mut recovered).unwrap();
    assert_eq!(reopened.verified_copies(3, 0, 80), 0);
    assert!(reopened.records().is_empty());
}

#[test]
fn an_anchor_covers_nothing_past_a_record_that_does_not_chain() {
    let (_, mut records) = chain(10);
    let low = anchor(AnchorKind::OperatorExport, OPERATOR, 0, &records[1]);
    let high = anchor(AnchorKind::OperatorExport, OPERATOR, 1, &records[6]);
    // Record 2 is rewritten; record 6 is byte for byte the anchored one.
    records[2].content = digest(b"rewritten");
    let report = check(&records, &[low, high]);
    assert_eq!(
        report.findings,
        vec![AnchorFinding::BrokenChain { counter: 3 }]
    );
    assert_eq!(report.anchored_through, Some(1));
    assert!(report.is_conflicting());
}

/// Receipts whose store also proves, for every anchor, that it held the
/// anchored head before `through`'s revocation.
struct Timestamped;

impl AnchorEvidence for Timestamped {
    fn confirms(&self, anchor: &Anchor) -> bool {
        Receipts.confirms(anchor)
    }

    fn anchored_before_revocation(&self, anchor: &Anchor) -> Option<u64> {
        Some(anchor.signed.head.counter)
    }
}

#[test]
fn an_anchor_proved_to_predate_its_keys_revocation_still_counts() {
    use ed25519_dalek::Signer as _;
    let (_, records) = chain(10);
    let key = archival_key();
    let mut revoke = RegistryEntry {
        action: RegistryAction::Revoke,
        algorithm: super::trust::Algorithm::Ed25519,
        custody: super::trust::Custody::Declared,
        sequence: 1,
        key_id: super::trust::key_id(&key.verifying_key().to_bytes()),
        public: key.verifying_key().to_bytes(),
        effective: 6,
        evidence: digest(b"compromised at 6"),
        endorsement: [0; 64],
    };
    revoke.endorsement = authority()
        .sign(&revoke.endorsement_bytes(&ARCHIVE))
        .to_bytes();
    let mut revoked = registry();
    revoked.apply(&revoke).unwrap();
    let old = anchor(AnchorKind::OperatorExport, OPERATOR, 0, &records[3]);
    // Present-day storage proves no ordering.
    let report = check_anchors(
        &records,
        JOURNAL,
        &[old],
        &revoked,
        &externality(),
        &Receipts,
    );
    assert_eq!(report.anchored_through, None);
    // Evidence that the store held it before the revocation does.
    let report = check_anchors(
        &records,
        JOURNAL,
        &[old],
        &revoked,
        &externality(),
        &Timestamped,
    );
    assert_eq!(report.anchored_through, Some(3));
    assert!(report.findings.is_empty());
}

#[test]
fn stores_of_different_kinds_at_one_location_keep_separate_counters() {
    let (_, records) = chain(6);
    let export = anchor(AnchorKind::OperatorExport, OPERATOR, 0, &records[2]);
    let replica = anchor(AnchorKind::ReplicaJournal, OPERATOR, 0, &records[4]);
    let report = check(&records, &[export, replica]);
    assert!(report.findings.is_empty());
    assert_eq!(report.anchored_through, Some(4));
}

#[test]
fn copy_state_is_replayed_in_journal_order_once_per_committed_change() {
    use super::journal::IntegrityJournal;
    let disk = FaultDisk::default();
    let (mut journal, _) = chain(1);
    let mut copies = CopyCatalog::open(disk.clone(), Path::new(DIR), &mut journal).unwrap();
    copies
        .record(
            copy(REPLICA, CopyState::Verified, Enforcement::ObjectLock),
            &mut journal,
        )
        .unwrap();
    // The removal reaches the ledger, then the journal append fails.
    let removed = CopyRecord {
        sequence: 1,
        ..copy(REPLICA, CopyState::Removed, Enforcement::ObjectLock)
    };
    let mut ledger = super::ledger::Ledger::<_, COPY_RECORD_LENGTH>::open(
        disk.clone(),
        Path::new(DIR),
        COPIES_FILE,
    )
    .unwrap();
    ledger.append(removed.encode()).unwrap();
    let mut reopened = CopyCatalog::open(disk.clone(), Path::new(DIR), &mut journal).unwrap();
    assert_eq!(reopened.verified_copies(3, 0, 80), 1);
    // The retry stores the same bytes again and commits.
    reopened
        .record(
            copy(REPLICA, CopyState::Removed, Enforcement::ObjectLock),
            &mut journal,
        )
        .unwrap();
    let again = CopyCatalog::open(disk.clone(), Path::new(DIR), &mut journal).unwrap();
    assert_eq!(again.records().len(), 2);
    assert_eq!(again.next_sequence(), 2);
    assert_eq!(again.verified_copies(3, 0, 80), 0);
    // A committed change missing from the ledger is reported, never
    // replaced by stale state.
    let mut empty_journal_disk = IntegrityJournal::open(FaultDisk::default(), Path::new(DIR))
        .unwrap()
        .journal;
    let lost = FaultDisk::default();
    let mut lost_copies =
        CopyCatalog::open(lost.clone(), Path::new(DIR), &mut empty_journal_disk).unwrap();
    lost_copies
        .record(
            copy(REPLICA, CopyState::Verified, Enforcement::ObjectLock),
            &mut empty_journal_disk,
        )
        .unwrap();
    assert!(matches!(
        CopyCatalog::open(
            FaultDisk::default(),
            Path::new(DIR),
            &mut empty_journal_disk
        ),
        Err(super::journal::IntegrityError::Unrecorded { counter: 0 })
    ));
}
