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
use super::tiering::{ObjectKey, ObjectKind};
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
fn a_replayed_seal_is_never_counted_from_a_stale_catalog() {
    use super::journal::IntegrityError;
    let mut f = fixture();
    let (seal, bytes) = f.ranges[0].clone();
    let _ = replica()
        .verify(&mut f.copies, &mut f.journal, &seal, &bytes)
        .unwrap();
    // Another handle invalidates the copy: this one's snapshot still says
    // verified.
    let mut other = CopyCatalog::open(f.disk.clone(), Path::new(DIR), &mut f.journal).unwrap();
    assert_eq!(
        replica()
            .invalidate(&mut other, &mut f.journal, RECORDING, seal.start, seal.end)
            .unwrap(),
        1
    );
    assert!(matches!(
        replica().verify(&mut f.copies, &mut f.journal, &seal, &bytes),
        Err(ReplicationError::Integrity(IntegrityError::StaleCatalog))
    ));
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
fn object_keys_are_scoped_to_their_archive() {
    let (seal, _) = fixture().ranges[0].clone();
    let ours = ObjectKey::of(LOCAL, &seal);
    let theirs = ObjectKey::of(REPLICA, &seal);
    assert_ne!(ours, theirs);
    assert_ne!(ours.name(), theirs.name());
    assert!(ours.name().starts_with(&"0a".repeat(32)));
    let index = ObjectKey::index(LOCAL, RECORDING, 256);
    assert_eq!(index.kind, ObjectKind::Index);
    assert!(
        index
            .name()
            .ends_with("/0000000000000003/0000000000000100.idx")
    );
    assert_ne!(index, ObjectKey::index(REPLICA, RECORDING, 256));
}
