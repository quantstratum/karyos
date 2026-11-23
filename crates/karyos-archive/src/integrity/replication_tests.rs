// SPDX-License-Identifier: Apache-2.0

//! Tests of replica verification, copy counting and tiered storage
//! (karyos#669).

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

use super::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
use super::journal::IntegrityJournal;
use super::replication::{Replica, ReplicationError, Verdict};
use super::test_support::DIR;
use super::tiering::{LocalRanges, ObjectKey, ObjectStore, Tiering, TieringError};
use super::{Digest, SealRecord};
use crate::fault::FaultDisk;

const RECORDING: u64 = 3;
const LOCAL: Digest = [10; 32];
const REPLICA: Digest = [20; 32];
const BUCKET: Digest = [40; 32];

/// A journal with two sealed ranges of [`RECORDING`], their bytes and seals.
struct Fixture {
    disk: FaultDisk,
    journal: IntegrityJournal<FaultDisk>,
    copies: CopyCatalog<FaultDisk>,
    ranges: Vec<(SealRecord, Vec<u8>)>,
}

fn fixture() -> Fixture {
    let disk = FaultDisk::default();
    let mut journal = IntegrityJournal::open(disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let mut ranges = Vec::new();
    for index in 0u8..2 {
        let bytes = vec![index; 16];
        let seal = journal
            .seal_segment(RECORDING, u64::from(index) * 16, &bytes, false)
            .unwrap();
        ranges.push((seal, bytes));
    }
    let copies = CopyCatalog::open(disk.clone(), Path::new(DIR), &mut journal).unwrap();
    Fixture {
        disk,
        journal,
        copies,
        ranges,
    }
}

fn replica() -> Replica {
    Replica::new(REPLICA, 0, Enforcement::Unsupported)
}

#[test]
fn a_replica_counts_only_after_verifying_and_never_a_corrupt_range() {
    let mut f = fixture();
    let (seal, bytes) = f.ranges[0].clone();
    assert_eq!(
        f.copies
            .verified_copies(RECORDING, seal.start, seal.end)
            .unwrap(),
        0
    );

    let mut corrupt = bytes.clone();
    corrupt[3] ^= 1;
    let verdict = replica()
        .verify(&mut f.copies, &mut f.journal, &seal, &corrupt)
        .unwrap();
    assert!(matches!(verdict, Verdict::Corrupt(_)));
    assert_eq!(
        f.copies
            .verified_copies(RECORDING, seal.start, seal.end)
            .unwrap(),
        0
    );

    let verdict = replica()
        .verify(&mut f.copies, &mut f.journal, &seal, &bytes)
        .unwrap();
    assert!(matches!(verdict, Verdict::Counted(_)));
    assert_eq!(
        f.copies
            .verified_copies(RECORDING, seal.start, seal.end)
            .unwrap(),
        1
    );

    // The count survives a reopen: it is chained, not held in memory.
    let reopened = CopyCatalog::open(f.disk.clone(), Path::new(DIR), &mut f.journal).unwrap();
    assert_eq!(
        reopened
            .verified_copies(RECORDING, seal.start, seal.end)
            .unwrap(),
        1
    );
}

#[test]
fn a_seal_of_no_range_or_an_inverted_invalidation_is_refused() {
    let mut f = fixture();
    let (seal, bytes) = f.ranges[0].clone();
    let Verdict::Counted(catalog) = replica()
        .verify(&mut f.copies, &mut f.journal, &seal, &bytes)
        .unwrap()
    else {
        panic!("a matching seal counts");
    };
    assert!(matches!(
        replica().verify(&mut f.copies, &mut f.journal, &catalog, &bytes),
        Err(ReplicationError::NotARange { .. })
    ));
    assert!(matches!(
        replica().invalidate(&mut f.copies, &mut f.journal, RECORDING, 9, 8),
        Err(ReplicationError::InvertedRange { .. })
    ));
}

#[test]
fn the_replication_lag_is_observable() {
    let mut f = fixture();
    let source_end = f.ranges[1].0.end;
    assert_eq!(
        replica()
            .lag(&f.copies, RECORDING, 0, source_end)
            .unwrap()
            .behind,
        32
    );
    for (seal, bytes) in f.ranges.clone() {
        let _ = replica()
            .verify(&mut f.copies, &mut f.journal, &seal, &bytes)
            .unwrap();
        let lag = replica().lag(&f.copies, RECORDING, 0, source_end).unwrap();
        assert_eq!(lag.verified_end, seal.end);
        assert_eq!(lag.behind, source_end - seal.end);
    }
}

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

/// Local ranges, recording what was removed.
#[derive(Default)]
struct Local {
    removed: Vec<ObjectKey>,
}

impl LocalRanges for Local {
    fn remove(&mut self, key: &ObjectKey) -> io::Result<()> {
        self.removed.push(*key);
        Ok(())
    }
}

fn tiering() -> Tiering {
    Tiering {
        local: LOCAL,
        remote: BUCKET,
    }
}

fn copies_of(min: u32) -> NonZeroU32 {
    NonZeroU32::new(min).unwrap()
}

fn verified_local(f: &mut Fixture, seal: &SealRecord) {
    let record = CopyRecord {
        sequence: 0,
        recording: RECORDING,
        start: seal.start,
        end: seal.end,
        location: LOCAL,
        digest: seal.content,
        retain_until_ns: 0,
        state: CopyState::Verified,
        enforcement: Enforcement::Unsupported,
    };
    f.copies.record(record, &mut f.journal).unwrap();
}

#[test]
fn an_offloaded_range_is_restored_byte_for_byte_and_removed_only_after_it_verified() {
    let mut f = fixture();
    let (seal, bytes) = f.ranges[0].clone();
    verified_local(&mut f, &seal);
    let mut bucket = Bucket::default();
    let mut local = Local::default();
    let offloaded = tiering()
        .offload(
            &seal,
            &bytes,
            copies_of(1),
            0,
            &mut f.copies,
            &mut f.journal,
            &mut bucket,
            &mut local,
        )
        .unwrap();
    assert_eq!(offloaded.enforcement, Enforcement::ObjectLock);
    assert_eq!(local.removed, vec![ObjectKey::of(LOCAL, &seal)]);
    assert_eq!(tiering().copies_elsewhere(&f.copies, &seal).unwrap(), 1);
    assert_eq!(
        f.copies
            .verified_copies(RECORDING, seal.start, seal.end)
            .unwrap(),
        1
    );

    let restored = tiering().restore(&seal, &mut bucket).unwrap();
    assert_eq!(restored, bytes);
    assert!(super::verify_range(&seal, &restored).is_ok());
}

#[test]
fn a_remote_copy_that_does_not_verify_is_not_counted_and_nothing_is_removed() {
    let mut f = fixture();
    let (seal, bytes) = f.ranges[0].clone();
    let mut bucket = Bucket {
        corrupt_on_read: true,
        ..Bucket::default()
    };
    let mut local = Local::default();
    let error = tiering()
        .offload(
            &seal,
            &bytes,
            copies_of(1),
            0,
            &mut f.copies,
            &mut f.journal,
            &mut bucket,
            &mut local,
        )
        .unwrap_err();
    assert!(matches!(error, TieringError::RemoteMismatch(_)));
    assert!(local.removed.is_empty());
    assert_eq!(tiering().copies_elsewhere(&f.copies, &seal).unwrap(), 0);
    assert!(matches!(
        tiering().restore(&seal, &mut bucket),
        Err(TieringError::RemoteMismatch(_))
    ));
}

#[test]
fn an_offload_below_min_copies_is_refused_before_it_acts() {
    let mut f = fixture();
    let (seal, bytes) = f.ranges[0].clone();
    let mut bucket = Bucket::default();
    let mut local = Local::default();
    let error = tiering()
        .offload(
            &seal,
            &bytes,
            copies_of(2),
            0,
            &mut f.copies,
            &mut f.journal,
            &mut bucket,
            &mut local,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        TieringError::BelowMinCopies {
            verified: 1,
            required: 2
        }
    ));
    assert_eq!(bucket.calls, 0);
    assert!(local.removed.is_empty());
    assert!(f.copies.records().is_empty());

    // With a verified replica elsewhere, the same offload satisfies it.
    let _ = replica()
        .verify(&mut f.copies, &mut f.journal, &seal, &bytes)
        .unwrap();
    let _ = tiering()
        .offload(
            &seal,
            &bytes,
            copies_of(2),
            0,
            &mut f.copies,
            &mut f.journal,
            &mut bucket,
            &mut local,
        )
        .unwrap();
    assert_eq!(tiering().copies_elsewhere(&f.copies, &seal).unwrap(), 2);
}

#[test]
fn a_corrupt_local_range_is_never_offloaded() {
    let mut f = fixture();
    let (seal, mut bytes) = f.ranges[0].clone();
    bytes[0] ^= 1;
    let mut bucket = Bucket::default();
    let mut local = Local::default();
    let error = tiering()
        .offload(
            &seal,
            &bytes,
            copies_of(1),
            0,
            &mut f.copies,
            &mut f.journal,
            &mut bucket,
            &mut local,
        )
        .unwrap_err();
    assert!(matches!(error, TieringError::LocalMismatch(_)));
    assert_eq!(bucket.calls, 0);
}

#[test]
fn a_missing_prefix_shows_in_the_lag() {
    let mut f = fixture();
    let (seal, bytes) = f.ranges[1].clone();
    let _ = replica()
        .verify(&mut f.copies, &mut f.journal, &seal, &bytes)
        .unwrap();
    let lag = replica().lag(&f.copies, RECORDING, 0, seal.end).unwrap();
    assert_eq!((lag.verified_end, lag.behind), (0, 32));
}

#[test]
fn a_failed_or_replayed_seal_never_downgrades_a_verified_copy() {
    let mut f = fixture();
    let (seal, bytes) = f.ranges[0].clone();
    let _ = replica()
        .verify(&mut f.copies, &mut f.journal, &seal, &bytes)
        .unwrap();
    let records = f.copies.records().len();
    // Replayed: accepted with no catalog change.
    assert_eq!(
        replica()
            .verify(&mut f.copies, &mut f.journal, &seal, &bytes)
            .unwrap(),
        Verdict::AlreadyCounted
    );
    // Not matching: reported, nothing recorded, the copy still counts.
    let mut corrupt = bytes.clone();
    corrupt[0] ^= 1;
    let verdict = replica()
        .verify(&mut f.copies, &mut f.journal, &seal, &corrupt)
        .unwrap();
    assert!(matches!(verdict, Verdict::Corrupt(_)));
    assert_eq!(f.copies.records().len(), records);
    assert_eq!(
        f.copies
            .verified_copies(RECORDING, seal.start, seal.end)
            .unwrap(),
        1
    );
}

#[test]
fn only_the_replicas_own_check_invalidates_a_verified_copy() {
    let mut f = fixture();
    for (seal, bytes) in f.ranges.clone() {
        let _ = replica()
            .verify(&mut f.copies, &mut f.journal, &seal, &bytes)
            .unwrap();
    }
    let (first, _) = f.ranges[0].clone();
    // An empty range inside a verified copy checks nothing and changes
    // nothing.
    let records = f.copies.records().len();
    assert_eq!(
        replica()
            .invalidate(&mut f.copies, &mut f.journal, RECORDING, 4, 4)
            .unwrap(),
        0
    );
    assert_eq!(f.copies.records().len(), records);
    assert_eq!(
        replica()
            .invalidate(
                &mut f.copies,
                &mut f.journal,
                RECORDING,
                first.start,
                first.end
            )
            .unwrap(),
        1
    );
    assert_eq!(
        f.copies
            .verified_copies(RECORDING, first.start, first.end)
            .unwrap(),
        0
    );
    let (second, _) = f.ranges[1].clone();
    assert_eq!(
        f.copies
            .verified_copies(RECORDING, second.start, second.end)
            .unwrap(),
        1
    );
    // A verifying seal counts the invalidated range again.
    let (seal, bytes) = f.ranges[0].clone();
    assert!(matches!(
        replica()
            .verify(&mut f.copies, &mut f.journal, &seal, &bytes)
            .unwrap(),
        Verdict::Counted(_)
    ));
}

#[test]
fn offloading_part_of_a_wider_local_copy_splits_it() {
    let mut f = fixture();
    let (seal, bytes) = f.ranges[0].clone();
    let wide = CopyRecord {
        sequence: 0,
        recording: RECORDING,
        start: 0,
        end: 32,
        location: LOCAL,
        digest: seal.content,
        retain_until_ns: 0,
        state: CopyState::Verified,
        enforcement: Enforcement::Unsupported,
    };
    f.copies.record(wide, &mut f.journal).unwrap();
    let _ = tiering()
        .offload(
            &seal,
            &bytes,
            copies_of(1),
            0,
            &mut f.copies,
            &mut f.journal,
            &mut Bucket::default(),
            &mut Local::default(),
        )
        .unwrap();
    // [0, 16) counts only in the bucket; [16, 32) still counts locally.
    assert_eq!(f.copies.verified_copies(RECORDING, 0, 16).unwrap(), 1);
    assert_eq!(tiering().copies_elsewhere(&f.copies, &seal).unwrap(), 1);
    let local: Vec<_> = f
        .copies
        .current()
        .unwrap()
        .into_iter()
        .filter(|copy| copy.location == LOCAL && copy.state == CopyState::Verified)
        .map(|copy| (copy.start, copy.end))
        .collect();
    assert_eq!(local, vec![(16, 32)]);
}

#[test]
fn an_offload_to_a_location_already_counted_adds_no_copy() {
    let mut f = fixture();
    let (seal, bytes) = f.ranges[0].clone();
    let mut bucket = Bucket::default();
    let mut local = Local::default();
    let _ = tiering()
        .offload(
            &seal,
            &bytes,
            copies_of(1),
            0,
            &mut f.copies,
            &mut f.journal,
            &mut bucket,
            &mut local,
        )
        .unwrap();
    let calls = bucket.calls;
    let error = tiering()
        .offload(
            &seal,
            &bytes,
            copies_of(2),
            0,
            &mut f.copies,
            &mut f.journal,
            &mut bucket,
            &mut local,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        TieringError::BelowMinCopies {
            verified: 1,
            required: 2
        }
    ));
    assert_eq!(bucket.calls, calls, "refused before it acts");
}

#[test]
fn object_keys_are_scoped_to_their_archive() {
    let (seal, _) = fixture().ranges[0].clone();
    let ours = ObjectKey::of(LOCAL, &seal);
    let theirs = ObjectKey::of(REPLICA, &seal);
    assert_ne!(ours, theirs);
    assert_ne!(ours.name(), theirs.name());
    assert!(ours.name().starts_with(&"0a".repeat(32)));
}
