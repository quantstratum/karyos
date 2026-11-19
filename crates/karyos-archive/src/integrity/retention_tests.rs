// SPDX-License-Identifier: Apache-2.0

//! Tests of retention, legal hold and the crash-safe purge (karyos#667).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::io;
use std::num::NonZeroU32;
use std::path::Path;

use super::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
use super::journal::IntegrityJournal;
use super::ledger::{Ledger, read_entries};
use super::retention::*;
use super::test_support::{ARCHIVE, DIR, JOURNAL, archival_key, authority, sign, trust};
use super::trust::*;
use super::verify::{Evidence, Outcome, RangeBytes, verify};
use super::{Digest, SealKind, digest};
use crate::fault::{FaultDisk, Survives};
use crate::segment::{Geometry, SegmentStore, SyncPolicy};

use ed25519_dalek::Signer as _;

const RECORDING: u64 = 3;
const BEFORE: u64 = 256;
const REPLICA_A: Digest = [30; 32];
const REPLICA_B: Digest = [31; 32];

type Ops = Ledger<FaultDisk, OPERATION_LENGTH>;
type Markers = Ledger<FaultDisk, MARKER_LENGTH>;

/// No anchor store reaches anything.
#[derive(Debug)]
struct NoStores;

impl super::anchor::AnchorEvidence for NoStores {
    fn confirms(&self, _: &super::anchor::Anchor) -> bool {
        false
    }
}

/// The copy catalog of `disk`, as committed by its journal.
fn open_copies(disk: &FaultDisk) -> CopyCatalog<FaultDisk> {
    let mut journal = IntegrityJournal::open(disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    CopyCatalog::open(disk.clone(), Path::new(DIR), &mut journal).unwrap()
}

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

fn policy(retain_for_ns: u64, min_copies: u32) -> RetentionPolicy {
    RetentionPolicy {
        policy: 1,
        version: 1,
        retain_for_ns,
        min_copies: NonZeroU32::new(min_copies).unwrap(),
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
    }
}

/// An archive on `disk`: the archival key registered, a recording of six
/// 64-byte writes over three segments, each segment sealed, and two
/// verified copies elsewhere.
fn setup(disk: &FaultDisk) {
    let dir = Path::new(DIR);
    let mut journal = IntegrityJournal::open(disk.clone(), dir).unwrap().journal;
    let mut keys = Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(disk.clone(), dir, KEYS_FILE).unwrap();
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
    KeyRegistry::new(trust())
        .append(&entry, &mut journal, &mut keys)
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

fn fresh() -> Archive {
    let disk = FaultDisk::default();
    setup(&disk);
    open(disk)
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
        start: 0,
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
    fn purge(
        &mut self,
        policy: &RetentionPolicy,
        now_ns: u64,
    ) -> Result<super::SealRecord, PurgeError> {
        let context = context(policy, &self.copies, now_ns);
        self.retention
            .purge(&request(), &context, &mut self.store, &mut self.journal)
    }
}

#[test]
fn a_purge_before_expiry_and_one_under_hold_are_rejected_and_journalled() {
    let mut archive = fresh();
    let policy = policy(1_000, 2);
    let refused = archive.purge(&policy, 999).unwrap_err();
    assert!(matches!(
        refused,
        PurgeError::Refused {
            refusal: PurgeRefusal::NotExpired { expires_ns: 1_000 },
            journalled: true
        }
    ));
    assert!(matches!(
        archive.retention.apply_hold(RECORDING),
        HoldReport::Applied { .. }
    ));
    let refused = archive.purge(&policy, 5_000).unwrap_err();
    assert!(matches!(
        refused,
        PurgeError::Refused {
            refusal: PurgeRefusal::LegalHold,
            journalled: true
        }
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

#[test]
fn a_purge_below_min_copies_is_rejected() {
    let mut archive = fresh();
    let refused = archive.purge(&policy(1_000, 3), 5_000).unwrap_err();
    assert!(matches!(
        refused,
        PurgeError::Refused {
            refusal: PurgeRefusal::BelowMinCopies {
                verified: 2,
                required: 3
            },
            ..
        }
    ));
    let mut unauthorised = request();
    unauthorised.authorisation.authorised = false;
    let policy = policy(1_000, 2);
    let context = context(&policy, &archive.copies, 5_000);
    assert_eq!(
        archive.retention.check(&unauthorised, &context),
        Err(PurgeRefusal::NotAuthorised)
    );
}

#[test]
fn an_executed_purge_is_in_the_chain_and_the_verifier_reports_it_purged() {
    let mut archive = fresh();
    let record = archive.purge(&policy(1_000, 2), 5_000).unwrap();
    assert_eq!(archive.store.start(), BEFORE);
    assert_eq!(
        (record.kind, record.start, record.end),
        (SealKind::Purge, 0, BEFORE)
    );
    let records = archive.journal.records().unwrap();
    assert_eq!(record.content, seals_digest(&records, RECORDING, 0, BEFORE));
    assert!(matches!(
        operations(&archive.disk).last(),
        Some(Operation::PurgeDone { id: 1 })
    ));
    // Signed past the purge, the verifier reports the purged ranges.
    let heads = [sign(records.last().unwrap()).encode()];
    let mut disk = archive.disk.clone();
    let keys: Vec<[u8; REGISTRY_ENTRY_LENGTH]> =
        read_entries(&mut disk, Path::new(DIR), KEYS_FILE).unwrap();
    let trust = trust();
    let externality = super::anchor::Externality::default();
    let verification = verify(
        &Evidence {
            records: &records,
            journal_fault: None,
            journal_id: JOURNAL,
            trust: Some(&trust),
            registry: &keys,
            heads: &heads,
            anchors: &[],
            anchor_faults: 0,
            stores: &NoStores,
            externality: &externality,
            written: &[],
        },
        |_, _, _| RangeBytes::Missing,
    );
    let outcomes: Vec<Outcome> = verification.ranges.iter().map(|r| r.outcome).collect();
    assert_eq!(outcomes[..2], [Outcome::Purged, Outcome::Purged]);
    // The key registry is untouched: its key is still there and still
    // needed by the retained signed head.
    assert_eq!(keys.len(), 1);
    let mut registry = KeyRegistry::new(trust.clone());
    registry
        .apply(&RegistryEntry::decode(&keys[0]).unwrap())
        .unwrap();
    let head = SignedHead::decode(&heads[0]).unwrap();
    assert!(!registry.may_drop(&head.key_id, &[head]));
}

#[test]
fn a_hold_applies_without_the_operations_journal_but_is_not_reported_applied() {
    let disk = FaultDisk::default();
    setup(&disk);
    let markers = Markers::open(disk.clone(), Path::new(DIR), PENDING_HOLDS_FILE).unwrap();
    let mut retention = Retention::recover(Down, Some(&[]), markers);
    assert_eq!(
        retention.apply_hold(RECORDING),
        HoldReport::PendingNoEvidence
    );
    assert_eq!(retention.hold(RECORDING), Some(Hold::Pending));
    let copies = open_copies(&disk);
    let policy = policy(1_000, 2);
    assert_eq!(
        retention.check(&request(), &context(&policy, &copies, 5_000)),
        Err(PurgeRefusal::LegalHold)
    );
    // The pending hold survives a restart.
    let markers = Markers::open(disk, Path::new(DIR), PENDING_HOLDS_FILE).unwrap();
    let restarted = Retention::recover(Down, Some(&[]), markers);
    assert_eq!(restarted.hold(RECORDING), Some(Hold::Pending));
}

#[test]
fn a_release_without_evidence_fails_closed() {
    let disk = FaultDisk::default();
    let markers = Markers::open(disk.clone(), Path::new(DIR), PENDING_HOLDS_FILE).unwrap();
    let mut retention = Retention::recover(Down, Some(&[]), markers);
    let _ = retention.apply_hold(RECORDING);
    assert_eq!(
        retention.release_hold(RECORDING),
        Err(ReleaseError::NoEvidence {
            recording: RECORDING
        })
    );
    assert_eq!(retention.hold(RECORDING), Some(Hold::Pending));
}

#[test]
fn a_release_the_journal_cannot_record_fails_closed() {
    let mut archive = fresh();
    let evidence = match archive.retention.apply_hold(RECORDING) {
        HoldReport::Applied { evidence } => evidence,
        other => panic!("the journal is up: {other:?}"),
    };
    assert_eq!(
        archive.retention.hold(RECORDING),
        Some(Hold::Applied { evidence })
    );
    // The same state over a journal that is down.
    let ops = operations(&archive.disk);
    let records: Vec<[u8; OPERATION_LENGTH]> = ops.iter().map(Operation::encode).collect();
    let markers = Markers::open(archive.disk.clone(), Path::new(DIR), PENDING_HOLDS_FILE).unwrap();
    let mut down = Retention::recover(Down, Some(&records), markers);
    assert_eq!(
        down.release_hold(RECORDING),
        Err(ReleaseError::JournalUnavailable)
    );
    assert!(down.hold(RECORDING).is_some());
    // With the journal, the evidenced hold releases.
    archive.retention.release_hold(RECORDING).unwrap();
    assert_eq!(archive.retention.hold(RECORDING), None);
    let restarted = open(archive.disk.clone());
    assert_eq!(restarted.retention.hold(RECORDING), None);
}

#[test]
fn an_unknown_hold_at_restart_inhibits_the_purge() {
    let disk = FaultDisk::default();
    setup(&disk);
    let markers = Markers::open(disk.clone(), Path::new(DIR), PENDING_HOLDS_FILE).unwrap();
    let mut retention = Retention::recover(Down, None, markers);
    let copies = open_copies(&disk);
    let policy = policy(1_000, 2);
    assert_eq!(
        retention.check(&request(), &context(&policy, &copies, 5_000)),
        Err(PurgeRefusal::HoldsUnknown)
    );
    assert_eq!(
        retention.release_hold(RECORDING),
        Err(ReleaseError::Unknown)
    );
    assert!(retention.holds_readable(&[]));
    assert_eq!(
        retention.check(&request(), &context(&policy, &copies, 5_000)),
        Ok(())
    );
}

#[test]
fn recovery_rechecks_the_policy_that_changed_across_the_crash() {
    let archive = fresh();
    // The intent is durable, then the Archive crashes before deleting.
    let intent = Operation::PurgeIntent {
        id: 1,
        recording: RECORDING,
        before: BEFORE,
        operator: 42,
        closed_ns: 0,
    };
    OperationsJournal::append(
        &mut Ops::open(archive.disk.clone(), Path::new(DIR), OPERATIONS_FILE).unwrap(),
        &intent,
    )
    .unwrap();
    let mut restarted = open(archive.disk.after_crash(Survives::Synced));
    assert_eq!(restarted.retention.outstanding().len(), 1);
    // The policy now keeps the range for longer.
    let longer = policy(10_000, 2);
    let context = context(&longer, &restarted.copies, 5_000);
    let outcomes = restarted
        .retention
        .recover_purges(
            &context,
            |_| true,
            &mut restarted.store,
            &mut restarted.journal,
        )
        .unwrap();
    assert_eq!(
        outcomes,
        [Err(PurgeRefusal::NotExpired { expires_ns: 10_000 })]
    );
    assert_eq!(restarted.store.start(), 0);
    assert!(restarted.retention.outstanding().is_empty());
    assert!(matches!(
        operations(&restarted.disk).last(),
        Some(Operation::PurgeCancelled { id: 1, .. })
    ));
}

/// Runs the purge on a disk that crashes after `budget` units, and
/// returns the crashed disk, or `None` when it did not crash.
fn crashed_purge(budget: u64) -> Option<FaultDisk> {
    // The work before the purge: the setup, then the restart's opening.
    let setup_disk = FaultDisk::default();
    setup(&setup_disk);
    let _ = open(setup_disk.clone());
    let used = setup_disk.used();
    let disk = FaultDisk::with_budget(used + budget);
    setup(&disk);
    let mut archive = open(disk.clone());
    let _ = archive.purge(&policy(1_000, 2), 5_000);
    disk.has_crashed().then_some(disk)
}

#[test]
fn a_hold_applied_before_recovery_stops_the_deletion_at_every_crash_point() {
    let mut crashes = 0u32;
    let mut held_back = 0u32;
    for budget in 0..400 {
        let Some(disk) = crashed_purge(budget) else {
            break;
        };
        crashes += 1;
        for survives in [Survives::Synced, Survives::Everything] {
            let restarted_disk = disk.after_crash(survives);
            let mut archive = open(restarted_disk);
            let deleted = archive.store.start();
            // The hold is applied before recovery runs.
            assert!(matches!(
                archive.retention.apply_hold(RECORDING),
                HoldReport::Applied { .. }
            ));
            let policy = policy(1_000, 2);
            let context = context(&policy, &archive.copies, 5_000);
            let outcomes = archive
                .retention
                .recover_purges(&context, |_| true, &mut archive.store, &mut archive.journal)
                .unwrap();
            // Nothing more is deleted than the crash had already deleted.
            assert_eq!(
                archive.store.start(),
                deleted,
                "budget {budget} {survives:?}"
            );
            if deleted < BEFORE && !outcomes.is_empty() {
                assert_eq!(outcomes, [Err(PurgeRefusal::LegalHold)]);
                held_back += 1;
            }
            // The chain stays sound.
            super::verify_chain(&archive.journal.records().unwrap()).unwrap();
        }
    }
    assert!(crashes > 10, "{crashes}");
    assert!(held_back > 0, "{held_back}");
}

#[test]
fn without_a_hold_recovery_completes_the_purge_at_every_crash_point() {
    for budget in 0..400 {
        let Some(disk) = crashed_purge(budget) else {
            break;
        };
        let mut archive = open(disk.after_crash(Survives::Synced));
        let had_intent = !archive.retention.outstanding().is_empty();
        let policy = policy(1_000, 2);
        let context = context(&policy, &archive.copies, 5_000);
        archive
            .retention
            .recover_purges(&context, |_| true, &mut archive.store, &mut archive.journal)
            .unwrap();
        let records = archive.journal.records().unwrap();
        let purged = records.iter().any(|record| record.kind == SealKind::Purge);
        if had_intent {
            assert_eq!(archive.store.start(), BEFORE, "budget {budget}");
            assert!(purged, "budget {budget}");
        } else {
            // Never journalled as intended, so never deleted.
            assert_eq!(archive.store.start(), 0, "budget {budget}");
        }
        super::verify_chain(&records).unwrap();
    }
}

#[test]
fn policies_are_versioned_chained_and_bound_by_recording_or_class() {
    let mut archive = fresh();
    let dir = Path::new(DIR);
    let mut book = PolicyBook::open(archive.disk.clone(), dir, &mut archive.journal).unwrap();
    let first = book.record(policy(1_000, 2), &mut archive.journal).unwrap();
    assert_eq!(first.kind, SealKind::Policy);
    assert_eq!(first.content, digest(&policy(1_000, 2).canonical()));
    assert!(book.record(policy(5, 1), &mut archive.journal).is_err());
    let mut second = policy(2_000, 2);
    second.version = 2;
    book.record(second, &mut archive.journal).unwrap();
    let mut other = policy(9, 1);
    other.policy = 2;
    book.record(other, &mut archive.journal).unwrap();
    let class = Selector::Class {
        channel: b"karyos:ipc".to_vec(),
        stream_id: 10,
    };
    book.bind(&class, 1, &mut archive.journal).unwrap();
    book.bind(&Selector::Recording(4), 2, &mut archive.journal)
        .unwrap();
    assert!(matches!(
        book.bind(&Selector::Recording(5), 9, &mut archive.journal),
        Err(super::journal::IntegrityError::Policy(
            PolicyError::Unknown { policy: 9 }
        ))
    ));
    assert_eq!(book.resolve(3, b"karyos:ipc", 10).unwrap().version, 2);
    assert_eq!(book.resolve(4, b"karyos:ipc", 10).unwrap().policy, 2);
    assert!(book.resolve(5, b"karyos:udp", 10).is_none());

    // A restart restores the effective versions and bindings, and an older
    // version is still refused against them.
    let mut journal = IntegrityJournal::open(archive.disk.clone(), dir)
        .unwrap()
        .journal;
    let mut restored = PolicyBook::open(archive.disk.clone(), dir, &mut journal).unwrap();
    assert_eq!(restored.resolve(3, b"karyos:ipc", 10).unwrap().version, 2);
    assert_eq!(restored.resolve(4, b"karyos:ipc", 10).unwrap().policy, 2);
    assert!(restored.record(policy(1, 1), &mut journal).is_err());
}

/// A policy entry stored without its journal record is not committed: a
/// restart does not restore it.
#[test]
fn an_unchained_policy_entry_is_not_restored() {
    let archive = fresh();
    let dir = Path::new(DIR);
    let mut entries =
        Ledger::<_, POLICY_ENTRY_LENGTH>::open(archive.disk.clone(), dir, POLICIES_FILE).unwrap();
    let mut entry = [0u8; POLICY_ENTRY_LENGTH];
    entry[0] = 1;
    entry[1..31].copy_from_slice(&policy(1, 1).canonical());
    entries.append(entry).unwrap();
    let mut journal = IntegrityJournal::open(archive.disk.clone(), dir)
        .unwrap()
        .journal;
    let mut book = PolicyBook::open(archive.disk.clone(), dir, &mut journal).unwrap();
    assert!(matches!(
        book.bind(&Selector::Recording(3), 1, &mut journal),
        Err(super::journal::IntegrityError::Policy(
            PolicyError::Unknown { .. }
        ))
    ));
}

#[test]
fn operations_round_trip_through_their_bytes() {
    for operation in [
        Operation::HoldApplied { recording: 3 },
        Operation::HoldReleased { recording: 3 },
        Operation::PurgeIntent {
            id: 1,
            recording: 3,
            before: 256,
            operator: 42,
            closed_ns: 7,
        },
        Operation::PurgeRejected {
            id: 1,
            recording: 3,
            reason: 2,
        },
        Operation::PurgeDone { id: 1 },
        Operation::PurgeCancelled { id: 1, reason: 5 },
    ] {
        assert_eq!(Operation::decode(&operation.encode()), Some(operation));
    }
    assert_eq!(Operation::decode(&[0; OPERATION_LENGTH]), None);
}

/// A purge whose request names another recording than the store is
/// refused before its intent, and deletes nothing.
#[test]
fn a_purge_for_another_recording_than_the_store_is_refused() {
    let mut archive = fresh();
    let policy = policy(1_000, 2);
    let context = context(&policy, &archive.copies, 5_000);
    let mut other = request();
    other.recording = RECORDING + 1;
    let refused = archive
        .retention
        .purge(&other, &context, &mut archive.store, &mut archive.journal)
        .unwrap_err();
    assert!(matches!(
        refused,
        PurgeError::Refused {
            refusal: PurgeRefusal::WrongStore { .. },
            journalled: true
        }
    ));
    assert_eq!(archive.store.start(), 0);
    assert!(archive.retention.outstanding().is_empty());
}

/// A cutoff inside a sealed range is refused: the purge would split it.
#[test]
fn a_cutoff_inside_a_sealed_range_is_refused() {
    let mut archive = fresh();
    let policy = policy(1_000, 2);
    let context = context(&policy, &archive.copies, 5_000);
    let mut split = request();
    split.before = 192;
    let refused = archive
        .retention
        .purge(&split, &context, &mut archive.store, &mut archive.journal)
        .unwrap_err();
    assert!(matches!(
        refused,
        PurgeError::Refused {
            refusal: PurgeRefusal::SplitsSeal { before: 192, .. },
            ..
        }
    ));
    assert_eq!(archive.store.start(), 0);
}

/// Copies need cover only the store's current start onwards: once the
/// copies of the whole recording are gone and copies of what remains
/// stay, a purge from the store's start counts them.
#[test]
fn copies_are_counted_from_the_stores_start() {
    let mut archive = fresh();
    let policy = policy(1_000, 2);
    for location in [REPLICA_A, REPLICA_B] {
        archive
            .copies
            .record(
                CopyRecord {
                    sequence: 0,
                    recording: RECORDING,
                    start: 0,
                    end: 384,
                    location,
                    digest: digest(b"copy"),
                    retain_until_ns: 0,
                    state: CopyState::Removed,
                    enforcement: Enforcement::ObjectLock,
                },
                &mut archive.journal,
            )
            .unwrap();
        archive
            .copies
            .record(
                CopyRecord {
                    sequence: 0,
                    recording: RECORDING,
                    start: 128,
                    end: 384,
                    location,
                    digest: digest(b"copy"),
                    retain_until_ns: 0,
                    state: CopyState::Verified,
                    enforcement: Enforcement::ObjectLock,
                },
                &mut archive.journal,
            )
            .unwrap();
    }
    let mut context = context(&policy, &archive.copies, 5_000);
    let mut later = request();
    later.id = 2;
    assert!(matches!(
        archive.retention.check(&later, &context),
        Err(PurgeRefusal::BelowMinCopies { verified: 0, .. })
    ));
    context.start = 128;
    assert_eq!(archive.retention.check(&later, &context), Ok(()));
}

/// An intent whose range the floor already passed completes with its
/// record and no second deletion.
#[test]
fn recovery_records_an_intent_the_floor_already_passed() {
    let mut archive = fresh();
    let intent = Operation::PurgeIntent {
        id: 1,
        recording: RECORDING,
        before: 128,
        operator: 42,
        closed_ns: 0,
    };
    let mut ops = Ops::open(archive.disk.clone(), Path::new(DIR), OPERATIONS_FILE).unwrap();
    ops.append(intent.encode()).unwrap();
    archive.store.sync().unwrap();
    archive.store.purge_before(BEFORE).unwrap();
    let mut archive = open(archive.disk);
    assert_eq!(archive.retention.outstanding().len(), 1);
    let policy = policy(1_000, 2);
    let context = context(&policy, &archive.copies, 5_000);
    let outcomes = archive
        .retention
        .recover_purges(&context, |_| true, &mut archive.store, &mut archive.journal)
        .unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].unwrap().kind, SealKind::Purge);
    assert!(archive.retention.outstanding().is_empty());
}

/// A hold neither journal records is in force here but says it does not
/// survive a restart.
#[test]
fn a_hold_no_journal_records_says_it_is_in_memory_only() {
    let opened = FaultDisk::default();
    let _ = Markers::open(opened.clone(), Path::new(DIR), PENDING_HOLDS_FILE).unwrap();
    let disk = FaultDisk::with_budget(opened.used());
    let markers = Markers::open(disk.clone(), Path::new(DIR), PENDING_HOLDS_FILE).unwrap();
    let mut retention = Retention::recover(Down, Some(&[]), markers);
    assert_eq!(retention.apply_hold(RECORDING), HoldReport::InMemoryOnly);
    assert_eq!(retention.hold(RECORDING), Some(Hold::Pending));
}

/// Hold state read again replays the journal's holds before purges are
/// allowed, and an undecodable record keeps them inhibited.
#[test]
fn readable_hold_state_replays_the_restored_holds() {
    let disk = FaultDisk::default();
    setup(&disk);
    let markers = Markers::open(disk.clone(), Path::new(DIR), PENDING_HOLDS_FILE).unwrap();
    let mut retention = Retention::recover(Down, None, markers);
    let copies = open_copies(&disk);
    let policy = policy(1_000, 2);
    assert!(!retention.holds_readable(&[[0xff; OPERATION_LENGTH]]));
    assert_eq!(
        retention.check(&request(), &context(&policy, &copies, 5_000)),
        Err(PurgeRefusal::HoldsUnknown)
    );
    let held = Operation::HoldApplied {
        recording: RECORDING,
    }
    .encode();
    assert!(retention.holds_readable(&[held]));
    assert!(matches!(
        retention.hold(RECORDING),
        Some(Hold::Applied { .. })
    ));
    assert_eq!(
        retention.check(&request(), &context(&policy, &copies, 5_000)),
        Err(PurgeRefusal::LegalHold)
    );
}
