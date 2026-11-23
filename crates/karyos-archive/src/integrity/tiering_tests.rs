// SPDX-License-Identifier: Apache-2.0

//! Tests of tiering by whole segments (ADR-0104; karyos#1113): the upload
//! and its read back with no custody change, the per-segment commit, the
//! refusal of a purge over offloaded segments and the reconciliation of an
//! offload a crash cut short.

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

use super::copies::{CopyState, Enforcement};
use super::retention::{PurgeError, PurgeRefusal};
use super::retention_tests::{Archive, RECORDING, fresh, open, policy};
use super::test_support::{ARCHIVE, DIR};
use super::tiering::{
    LocalSegment, NoRelease, ObjectKey, ObjectStore, Tiering, TieringError, Uploaded, index_digest,
    offloaded, reconcile_floors,
};
use super::{Digest, SealKind, SealRecord};
use crate::disk::Disk as _;
use crate::fault::FaultDisk;

const BUCKET: Digest = [40; 32];

/// Object storage in memory, counting its calls.
#[derive(Default)]
struct Bucket {
    objects: HashMap<ObjectKey, Vec<u8>>,
    calls: u64,
    corrupt_on_read: bool,
}

impl ObjectStore for Bucket {
    fn put(&mut self, key: &ObjectKey, bytes: &[u8], _: u64) -> io::Result<Enforcement> {
        self.calls += 1;
        self.objects.insert(*key, bytes.to_vec());
        Ok(Enforcement::ObjectLock)
    }

    fn get(&mut self, key: &ObjectKey) -> io::Result<Vec<u8>> {
        self.calls += 1;
        let mut bytes = self
            .objects
            .get(key)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if self.corrupt_on_read {
            bytes[0] ^= 1;
        }
        Ok(bytes)
    }
}

const fn tiering() -> Tiering {
    Tiering {
        local: ARCHIVE,
        remote: BUCKET,
    }
}

fn copies(min: u32) -> NonZeroU32 {
    NonZeroU32::new(min).unwrap()
}

fn read_all(disk: &FaultDisk, path: &Path) -> Vec<u8> {
    let mut disk = disk.clone();
    let file = disk.open_read(path).unwrap();
    let mut bytes = vec![0u8; usize::try_from(disk.len(&file).unwrap()).unwrap()];
    disk.read_at(&file, 0, &mut bytes).unwrap();
    bytes
}

fn names(disk: &FaultDisk) -> Vec<String> {
    let mut disk = disk.clone();
    let mut names = disk.list(Path::new(DIR)).unwrap();
    names.sort();
    names
}

fn segment_names(disk: &FaultDisk, base: u64) -> usize {
    let prefix = format!("{RECORDING:016x}-{base:016x}.");
    names(disk)
        .iter()
        .filter(|name| name.starts_with(&prefix))
        .count()
}

/// Uploads the lowest local segment; nothing is recorded.
fn upload(archive: &mut Archive, bucket: &mut Bucket, min: u32) -> Result<Uploaded, TieringError> {
    let (start, end) = archive.store.lowest_finished_segment().unwrap();
    let base = archive.store.geometry().base_of(start);
    let seals: Vec<SealRecord> = archive
        .journal
        .records()
        .unwrap()
        .into_iter()
        .filter(|record| {
            record.kind.is_range()
                && record.subject == RECORDING
                && record.start < end
                && record.end > start
        })
        .collect();
    let (data, index) = archive.store.segment_paths(base);
    let (data, index) = (
        read_all(&archive.disk, &data),
        read_all(&archive.disk, &index),
    );
    let segment = LocalSegment {
        recording: RECORDING,
        base,
        start,
        end,
        seals: &seals,
        data: &data,
        index: &index,
    };
    tiering().upload_segment(&segment, copies(min), 0, &archive.copies, bucket)
}

fn commit(
    archive: &mut Archive,
    uploaded: &Uploaded,
    min: u32,
) -> Result<SealRecord, TieringError> {
    tiering().commit_segment(
        uploaded,
        copies(min),
        0,
        &mut archive.copies,
        &mut archive.journal,
        &mut archive.store,
        &mut NoRelease,
    )
}

fn offload(archive: &mut Archive, bucket: &mut Bucket, min: u32) -> SealRecord {
    let uploaded = upload(archive, bucket, min).unwrap();
    commit(archive, &uploaded, min).unwrap()
}

#[test]
fn an_offload_raises_the_start_past_the_whole_segment_and_removes_its_files() {
    let mut archive = fresh();
    let index = read_all(&archive.disk, &archive.store.segment_paths(0).1);
    let mut bucket = Bucket::default();
    let record = offload(&mut archive, &mut bucket, 3);
    assert_eq!(record.kind, SealKind::Offload);
    assert_eq!(
        (record.subject, record.start, record.end),
        (RECORDING, 0, 128)
    );
    assert_eq!(record.content, index_digest(&index));
    assert_eq!(archive.store.start(), 128);
    assert_eq!(archive.store.offload_floor(), Some(0));
    assert_eq!(archive.store.lowest_retained(), 0);
    assert_eq!(
        segment_names(&archive.disk, 0),
        0,
        "{:?}",
        names(&archive.disk)
    );
    // One object for the range seal, one for the index, verbatim.
    assert_eq!(bucket.objects.len(), 2);
    assert_eq!(
        bucket.objects.get(&ObjectKey::index(ARCHIVE, RECORDING, 0)),
        Some(&index)
    );
    // The remote copy counts; the local one never did here.
    let current = archive.copies.current().unwrap();
    assert!(current.iter().any(|copy| copy.location == BUCKET
        && copy.state == CopyState::Verified
        && (copy.start, copy.end) == (0, 128)));

    // A restart reads the offload floor back from the floor record.
    let disk = archive.disk.clone();
    drop(archive);
    let mut archive = open(disk);
    assert_eq!(archive.store.start(), 128);
    assert_eq!(archive.store.offload_floor(), Some(0));

    // The next segment is the next one offloaded; the one being written
    // never is.
    let _ = offload(&mut archive, &mut bucket, 3);
    assert_eq!(archive.store.start(), 256);
    assert_eq!(archive.store.offload_floor(), Some(0));
    assert_eq!(archive.store.lowest_finished_segment(), None);
    let held = offloaded(&archive.journal.records().unwrap());
    assert_eq!(held.get(&RECORDING).map(Vec::len), Some(2));
}

#[test]
fn a_failure_between_upload_and_commit_leaves_the_archive_unchanged() {
    let mut archive = fresh();
    let counter = archive.journal.next_counter();
    let before = names(&archive.disk);
    let mut bucket = Bucket {
        corrupt_on_read: true,
        ..Bucket::default()
    };
    assert!(matches!(
        upload(&mut archive, &mut bucket, 3),
        Err(TieringError::RemoteMismatch(_))
    ));
    // An upload that verified, never committed: also nothing changes.
    let uploaded = upload(&mut archive, &mut Bucket::default(), 3).unwrap();
    assert_eq!(archive.journal.next_counter(), counter);
    assert_eq!(names(&archive.disk), before);
    assert_eq!(archive.store.start(), 0);
    drop(uploaded);
    let disk = archive.disk.clone();
    drop(archive);
    let mut journal = super::journal::IntegrityJournal::open(disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let records = journal.records().unwrap();
    drop(journal);
    assert!(
        reconcile_floors(&mut disk.clone(), Path::new(DIR), &records)
            .unwrap()
            .is_empty()
    );
    archive = open(disk);
    assert_eq!(archive.store.start(), 0);
    assert_eq!(archive.store.offload_floor(), None);
}

#[test]
fn a_segment_below_min_copies_is_not_offloaded_and_nothing_is_removed() {
    let mut archive = fresh();
    let counter = archive.journal.next_counter();
    let mut bucket = Bucket::default();
    // Two copies elsewhere plus the bucket's: three, not four.
    assert!(matches!(
        upload(&mut archive, &mut bucket, 4),
        Err(TieringError::BelowMinCopies {
            verified: 3,
            required: 4
        })
    ));
    assert_eq!(bucket.calls, 0);
    // An upload under a laxer policy then committed under a stricter one
    // is refused by the commit's recheck.
    let uploaded = upload(&mut archive, &mut bucket, 3).unwrap();
    assert!(matches!(
        commit(&mut archive, &uploaded, 4),
        Err(TieringError::BelowMinCopies { .. })
    ));
    assert_eq!(archive.journal.next_counter(), counter);
    assert_eq!(archive.store.start(), 0);
    assert_eq!(segment_names(&archive.disk, 0), 2);
}

#[test]
fn a_purge_of_a_recording_with_offloaded_segments_is_refused_at_any_cutoff() {
    let mut archive = fresh();
    let _ = offload(&mut archive, &mut Bucket::default(), 3);
    let counter = archive.journal.next_counter();
    let policy = policy(1, 1);
    for before in [64, 128, 256] {
        let mut request = super::retention_tests::request();
        request.before = before;
        let context = super::retention::PurgeContext {
            policy: Some(&policy),
            copies: &archive.copies,
            local: ARCHIVE,
            now_ns: 5_000,
        };
        let refused = archive
            .retention
            .purge(&request, &context, &mut archive.store, &mut archive.journal)
            .unwrap_err();
        assert!(
            matches!(
                refused,
                PurgeError::Refused {
                    refusal: PurgeRefusal::Offloaded {
                        lowest: 0,
                        start: 128
                    },
                    ..
                }
            ),
            "{refused:?}"
        );
    }
    assert_eq!(archive.store.start(), 128);
    assert_eq!(archive.journal.next_counter(), counter);
    assert!(archive.retention.outstanding().is_empty());
}

#[test]
fn a_crash_after_the_offload_record_is_finished_on_the_next_open() {
    let mut archive = fresh();
    let uploaded = upload(&mut archive, &mut Bucket::default(), 3).unwrap();
    // The crash: the offload record is chained, the start not raised.
    let _ = archive
        .journal
        .record_offload(RECORDING, 0, 128, uploaded.index_digest)
        .unwrap();
    let disk = archive.disk.clone();
    drop(archive);
    assert_eq!(segment_names(&disk, 0), 2);
    // Before any scan, the start is raised.
    let mut journal = super::journal::IntegrityJournal::open(disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    assert!(journal.tiered());
    let records = journal.records().unwrap();
    drop(journal);
    assert_eq!(
        reconcile_floors(&mut disk.clone(), Path::new(DIR), &records).unwrap(),
        vec![RECORDING]
    );
    let mut archive = open(disk);
    assert_eq!(archive.store.start(), 128);
    assert_eq!(archive.store.offload_floor(), Some(0));
    tiering()
        .reconcile(
            &mut archive.copies,
            &mut archive.journal,
            &mut archive.store,
            &mut NoRelease,
        )
        .unwrap();
    assert_eq!(segment_names(&archive.disk, 0), 0);
    // Reconciling again changes nothing.
    let counter = archive.journal.next_counter();
    tiering()
        .reconcile(
            &mut archive.copies,
            &mut archive.journal,
            &mut archive.store,
            &mut NoRelease,
        )
        .unwrap();
    assert_eq!(archive.journal.next_counter(), counter);
}

#[test]
fn a_commit_run_again_after_it_completed_only_finishes() {
    let mut archive = fresh();
    let mut bucket = Bucket::default();
    let uploaded = upload(&mut archive, &mut bucket, 3).unwrap();
    let first = commit(&mut archive, &uploaded, 3).unwrap();
    let counter = archive.journal.next_counter();
    let again = commit(&mut archive, &uploaded, 3).unwrap();
    assert_eq!(again, first);
    assert_eq!(archive.journal.next_counter(), counter);
    assert_eq!(archive.store.start(), 128);
}

#[test]
fn a_segment_whose_seals_cross_its_boundary_is_not_eligible() {
    let mut archive = fresh();
    let records = archive.journal.records().unwrap();
    let seal = records
        .iter()
        .find(|record| record.kind.is_range() && record.start == 0)
        .copied()
        .unwrap();
    let crossing = SealRecord { end: 192, ..seal };
    let segment = LocalSegment {
        recording: RECORDING,
        base: 0,
        start: 0,
        end: 128,
        seals: &[crossing],
        data: &[0; 192],
        index: &[],
    };
    assert!(matches!(
        tiering().upload_segment(
            &segment,
            copies(1),
            0,
            &archive.copies,
            &mut Bucket::default()
        ),
        Err(TieringError::NotEligible { base: 0, .. })
    ));
}
