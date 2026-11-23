// SPDX-License-Identifier: Apache-2.0

//! Tests of offline tiering (ADR-0104, decisions 2 and 9; karyos#1113):
//! the preconditions, the location check, the downgrade acceptance, the
//! object-lock readback and the remote verification.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::collections::HashMap;
use std::io;
use std::num::NonZeroU32;
use std::path::Path;

use super::Digest;
use super::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement, NoImmutability};
use super::journal::IntegrityJournal;
use super::ledger::Ledger;
use super::retention::{
    MARKER_LENGTH, OPERATION_LENGTH, OPERATIONS_FILE, Operation, OperationsJournal,
    PENDING_HOLDS_FILE, PurgeSource, Retention,
};
use super::test_support::DIR;
use super::tiering::{LockMode, ObjectKey, ObjectRetention, ObjectStore, Tiering};
use super::tiering_offline::{ObjectState, Offline, OfflineError, OffloadOptions, Stopped};
use crate::catalog::{Catalog, NewRecording, SourceIncarnation, StopReason, StreamFormat};
use crate::fault::FaultDisk;
use crate::segment::{Geometry, SegmentStore, SyncPolicy};

const LOCAL: Digest = [10; 32];
const BUCKET: Digest = [40; 32];
const REPLICA: Digest = [30; 32];

/// Object storage in memory, with the retention each put asked for.
#[derive(Default)]
struct Bucket {
    objects: HashMap<ObjectKey, Vec<u8>>,
    retained: HashMap<ObjectKey, u64>,
    /// Object lock applies.
    lock: bool,
}

impl ObjectStore for Bucket {
    fn put(&mut self, key: &ObjectKey, bytes: &[u8], until: u64) -> io::Result<Enforcement> {
        self.objects.insert(*key, bytes.to_vec());
        self.retained.insert(*key, until);
        Ok(Enforcement::ObjectLock)
    }

    fn get(&mut self, key: &ObjectKey) -> io::Result<Vec<u8>> {
        self.objects
            .get(key)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn retention(&mut self, key: &ObjectKey) -> io::Result<Option<ObjectRetention>> {
        Ok(self
            .lock
            .then(|| self.retained.get(key).copied())
            .flatten()
            .map(|retain_until_ns| ObjectRetention {
                mode: LockMode::Compliance,
                retain_until_ns,
            }))
    }
}

const fn tiering() -> Tiering {
    Tiering {
        local: LOCAL,
        remote: BUCKET,
    }
}

fn format() -> StreamFormat {
    StreamFormat {
        lane: karyos_sys::frame::Lane::ZERO,
        initial_term_id: -3,
        mtu: NonZeroU32::new(1408).unwrap(),
        source: SourceIncarnation {
            driver: [1, 2],
            registration: 3,
            incarnation: 1,
        },
    }
}

/// An archive with one stopped recording of six 64-byte writes over
/// three 128-byte segments, each sealed, its local copy at [`LOCAL`] and
/// one replica: the recording's id.
fn archive(disk: &FaultDisk) -> u64 {
    let dir = Path::new(DIR);
    let geometry = Geometry::new(64, 128).unwrap();
    let mut catalog = Catalog::open(disk.clone(), dir).unwrap().catalog;
    let id = catalog
        .start(NewRecording {
            stream_id: 1,
            session_id: 7,
            channel: b"tiering",
            start: 0,
            start_time_ns: 5,
            geometry,
            policy: SyncPolicy::PerSegment,
            format: format(),
            required: false,
        })
        .unwrap();
    let mut store =
        SegmentStore::create(disk.clone(), dir, id, geometry, SyncPolicy::None, 0).unwrap();
    for index in 0..6u8 {
        store.append(u64::from(index) * 64, &[index; 64]).unwrap();
    }
    store.close_synced().unwrap();
    catalog.stop(id, 384, 9, StopReason::Normal, false).unwrap();
    let mut journal = IntegrityJournal::open(disk.clone(), dir).unwrap().journal;
    for segment in 0..3u8 {
        let mut bytes = vec![segment * 2; 64];
        bytes.extend([segment * 2 + 1; 64]);
        journal
            .seal_segment(id, u64::from(segment) * 128, &bytes, true)
            .unwrap();
    }
    let mut copies = CopyCatalog::open(disk.clone(), dir, &mut journal).unwrap();
    for location in [LOCAL, REPLICA] {
        copies
            .record(
                CopyRecord {
                    sequence: 0,
                    recording: id,
                    start: 0,
                    end: 384,
                    location,
                    digest: [1; 32],
                    retain_until_ns: if location == LOCAL { 0 } else { 1 },
                    state: CopyState::Verified,
                    enforcement: Enforcement::Unsupported,
                },
                &mut journal,
            )
            .unwrap();
    }
    id
}

fn open(disk: &FaultDisk) -> Offline<FaultDisk> {
    Offline::open(disk.clone(), Path::new(DIR), Box::new(NoImmutability)).unwrap()
}

fn options(accept: bool) -> OffloadOptions {
    OffloadOptions {
        min_copies: NonZeroU32::new(2),
        accept_downgrade_break: accept,
        limit: None,
    }
}

#[test]
fn an_offline_offload_moves_every_finished_segment_and_restores_them() {
    let disk = FaultDisk::default();
    let id = archive(&disk);
    let mut offline = open(&disk);
    offline.check_location(&LOCAL).unwrap();
    let mut bucket = Bucket::default();
    let report = offline
        .offload(&tiering(), id, &mut bucket, &options(true))
        .unwrap();
    assert_eq!(report.offloaded.len(), 2, "{report:?}");
    assert_eq!(report.stopped, Stopped::NoneLeft);
    assert!(offline.journal().tiered());
    let verified = offline.verify(&tiering(), id, &mut bucket).unwrap();
    assert_eq!(verified.len(), 4);
    assert!(
        verified
            .iter()
            .all(|object| object.state == ObjectState::Verified)
    );
    drop(offline);
    let mut offline = open(&disk);
    let restored = offline.restore(&tiering(), id, &mut bucket, None).unwrap();
    assert_eq!(restored.len(), 2);
}

#[test]
fn the_first_tiering_needs_the_downgrade_break_accepted() {
    let disk = FaultDisk::default();
    let id = archive(&disk);
    let mut offline = open(&disk);
    let counter = offline.journal().next_counter();
    assert!(matches!(
        offline.offload(&tiering(), id, &mut Bucket::default(), &options(false)),
        Err(OfflineError::DowngradeBreak)
    ));
    assert_eq!(offline.journal().next_counter(), counter);
}

#[test]
fn a_location_other_than_the_archives_own_is_refused() {
    let disk = FaultDisk::default();
    let _ = archive(&disk);
    let offline = open(&disk);
    assert!(matches!(
        offline.check_location(&[11; 32]),
        Err(OfflineError::LocationMismatch { .. })
    ));
    assert!(offline.check_location(&LOCAL).is_ok());
}

#[test]
fn an_unresolved_purge_intent_or_a_hold_refuses_tiering() {
    let disk = FaultDisk::default();
    let id = archive(&disk);
    let dir = Path::new(DIR);
    {
        let mut operations =
            Ledger::<_, OPERATION_LENGTH>::open(disk.clone(), dir, OPERATIONS_FILE).unwrap();
        OperationsJournal::append(
            &mut operations,
            &Operation::PurgeIntent {
                id: 9,
                recording: id,
                before: 128,
                operator: 1,
                closed_ns: 0,
                source: PurgeSource::Operator,
                from: 0,
            },
        )
        .unwrap();
    }
    let mut offline = open(&disk);
    assert!(matches!(
        offline.offload(&tiering(), id, &mut Bucket::default(), &options(true)),
        Err(OfflineError::PurgeIntent { id: 9, .. })
    ));
    drop(offline);

    let disk = FaultDisk::default();
    let id = archive(&disk);
    {
        let operations =
            Ledger::<_, OPERATION_LENGTH>::open(disk.clone(), dir, OPERATIONS_FILE).unwrap();
        let markers =
            Ledger::<_, MARKER_LENGTH>::open(disk.clone(), dir, PENDING_HOLDS_FILE).unwrap();
        let records = operations.entries().to_vec();
        let mut retention: Retention<_, FaultDisk> =
            Retention::recover(operations, Some(&records), markers);
        let _ = retention.apply_hold(id);
    }
    let mut offline = open(&disk);
    let mut bucket = Bucket::default();
    assert!(matches!(
        offline.offload(&tiering(), id, &mut bucket, &options(true)),
        Err(OfflineError::LegalHold { .. })
    ));
    assert!(bucket.objects.is_empty());
}

#[test]
fn a_missing_or_corrupt_object_is_reported_and_its_copy_downgraded() {
    let disk = FaultDisk::default();
    let id = archive(&disk);
    let mut offline = open(&disk);
    let mut bucket = Bucket::default();
    let _ = offline
        .offload(&tiering(), id, &mut bucket, &options(true))
        .unwrap();
    let mut keys: Vec<ObjectKey> = bucket.objects.keys().copied().collect();
    keys.sort_by_key(|key| {
        (
            key.start,
            key.end,
            key.kind == super::tiering::ObjectKind::Index,
        )
    });
    let ranges: Vec<ObjectKey> = keys
        .iter()
        .copied()
        .filter(|key| key.kind == super::tiering::ObjectKind::Range)
        .collect();
    let _ = bucket.objects.remove(&ranges[0]);
    bucket.objects.get_mut(&ranges[1]).unwrap()[0] ^= 1;
    let reports = offline.verify(&tiering(), id, &mut bucket).unwrap();
    let states: Vec<ObjectState> = reports
        .iter()
        .filter(|report| report.start != report.end)
        .map(|report| report.state)
        .collect();
    assert_eq!(states, vec![ObjectState::Missing, ObjectState::Corrupt]);
    let remote: Vec<CopyState> = offline
        .copies()
        .current()
        .unwrap()
        .into_iter()
        .filter(|copy| copy.location == BUCKET)
        .map(|copy| copy.state)
        .collect();
    assert!(
        remote.iter().all(|state| *state != CopyState::Verified),
        "{remote:?}"
    );
}

#[test]
fn under_a_retention_deadline_an_object_without_an_enforcing_lock_skips_the_segment() {
    let disk = FaultDisk::default();
    let id = archive(&disk);
    // A policy bound to the recording: retained for a year from its close.
    {
        let dir = Path::new(DIR);
        let mut journal = IntegrityJournal::open(disk.clone(), dir).unwrap().journal;
        let mut book = super::retention::PolicyBook::open(disk.clone(), dir, &mut journal).unwrap();
        let policy = super::retention::RetentionPolicy {
            policy: 1,
            version: 1,
            retain_for_ns: 365 * 86_400 * 1_000_000_000,
            min_copies: NonZeroU32::new(2).unwrap(),
            storage_tier: 0,
            purge: super::retention::PurgeMode::Manual,
        };
        let _ = book.record(policy, &mut journal).unwrap();
        let _ = book
            .bind(&super::retention::Selector::Recording(id), 1, &mut journal)
            .unwrap();
    }
    let mut offline = open(&disk);
    let counter = offline.journal().next_counter();
    let mut bucket = Bucket::default();
    let report = offline
        .offload(&tiering(), id, &mut bucket, &options(true))
        .unwrap();
    assert!(
        matches!(report.stopped, Stopped::LockNotEnforced { base: 0, .. }),
        "{report:?}"
    );
    assert!(report.offloaded.is_empty());
    assert_eq!(offline.journal().next_counter(), counter);
    // With object lock retained past the deadline, it commits.
    bucket.lock = true;
    let report = offline
        .offload(&tiering(), id, &mut bucket, &options(true))
        .unwrap();
    assert_eq!(report.offloaded.len(), 2, "{report:?}");
}

#[test]
fn a_missing_index_downgrades_its_segments_range_copies() {
    let disk = FaultDisk::default();
    let id = archive(&disk);
    let mut offline = open(&disk);
    let mut bucket = Bucket::default();
    let _ = offline
        .offload(&tiering(), id, &mut bucket, &options(true))
        .unwrap();
    let index = bucket
        .objects
        .keys()
        .copied()
        .find(|key| key.kind == super::tiering::ObjectKind::Index && key.start == 0)
        .unwrap();
    let _ = bucket.objects.remove(&index);
    let reports = offline.verify(&tiering(), id, &mut bucket).unwrap();
    assert!(
        reports
            .iter()
            .any(|report| report.start == report.end && report.state == ObjectState::Missing)
    );
    // The range object is there and sound, but cannot be restored.
    let first: Vec<CopyState> = offline
        .copies()
        .current()
        .unwrap()
        .into_iter()
        .filter(|copy| copy.location == BUCKET && copy.start == 0)
        .map(|copy| copy.state)
        .collect();
    assert!(!first.is_empty());
    assert!(
        first.iter().all(|state| *state != CopyState::Verified),
        "{first:?}"
    );
}

#[test]
fn a_store_the_copies_were_not_recorded_at_changes_nothing() {
    let disk = FaultDisk::default();
    let id = archive(&disk);
    let mut offline = open(&disk);
    let mut bucket = Bucket::default();
    let _ = offline
        .offload(&tiering(), id, &mut bucket, &options(true))
        .unwrap();
    let elsewhere = Tiering {
        local: LOCAL,
        remote: [41; 32],
    };
    let counter = offline.journal().next_counter();
    assert!(matches!(
        offline.verify(&elsewhere, id, &mut Bucket::default()),
        Err(OfflineError::DestinationMismatch)
    ));
    assert_eq!(offline.journal().next_counter(), counter);
}

#[test]
fn the_location_check_holds_after_the_local_copy_is_offloaded() {
    let disk = FaultDisk::default();
    let id = archive(&disk);
    let mut offline = open(&disk);
    let _ = offline
        .offload(&tiering(), id, &mut Bucket::default(), &options(true))
        .unwrap();
    drop(offline);
    let offline = open(&disk);
    offline.check_location(&LOCAL).unwrap();
}
