// SPDX-License-Identifier: Apache-2.0

//! Backups to remote storage and a rebuild from them (karyos#717): an
//! export of a node's snapshot and committed log, read back and checked;
//! a rebuild whose log and snapshot match the source's up to the reported
//! top; a damaged object refused, naming its range, before anything is
//! written; a rebuild through an Archive hold refused, changing nothing.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::copies::Enforcement;
use karyos_archive::integrity::tiering::{ObjectKey, ObjectStore};
use karyos_archive::segment::Geometry;
use karyos_cluster::backup::{
    self, BackupError, LOG_OBJECTS, MANIFEST_OBJECT, NOT_INCLUDED, Retention, Target,
};
use karyos_cluster::cluster_identity::{ClusterId, IdentityRecord, rebuild_identity};
use karyos_cluster::snapshot::{Section, SectionKind, SnapshotConfig, SnapshotStore};
use karyos_cluster::{Entry, HardState, RaftLog};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("karyos-backup-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Remote storage in memory; `corrupt_puts` stores every object with its
/// first byte flipped.
#[derive(Default)]
struct Bucket {
    objects: BTreeMap<String, Vec<u8>>,
    corrupt_puts: bool,
    /// What its puts enforce: `Unsupported` unless set.
    enforces: Option<Enforcement>,
    /// Every get fails, other than for a missing key.
    unreadable: bool,
}

impl ObjectStore for Bucket {
    fn put(&mut self, key: &ObjectKey, bytes: &[u8], _: u64) -> io::Result<Enforcement> {
        let mut stored = bytes.to_vec();
        if self.corrupt_puts
            && let Some(first) = stored.first_mut()
        {
            *first ^= 0xFF;
        }
        self.objects.insert(key.name(), stored);
        Ok(self.enforces.unwrap_or(Enforcement::Unsupported))
    }

    fn get(&mut self, key: &ObjectKey) -> io::Result<Vec<u8>> {
        if self.unreadable {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, key.name()));
        }
        self.objects
            .get(&key.name())
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, key.name()))
    }
}

const CLUSTER: [u8; 32] = [7; 32];

fn geometry() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

fn entry(index: u64) -> Entry {
    Entry {
        index,
        term: 1 + index / 100,
        event_time: index,
        payload: vec![
            u8::try_from(index % 251).unwrap();
            100 + usize::try_from(index % 37).unwrap()
        ],
    }
}

/// A node with entries 1 to 300, committed to 290, and a snapshot at 100.
fn source(dir: &Path) -> (RaftLog<StdDisk>, SnapshotStore<StdDisk>) {
    std::fs::create_dir_all(dir.join("log")).unwrap();
    std::fs::create_dir_all(dir.join("snap")).unwrap();
    let mut log = RaftLog::create(StdDisk, &dir.join("log"), geometry(), 1).unwrap();
    let entries: Vec<Entry> = (1..=300).map(entry).collect();
    let _ = log.append(&entries).unwrap();
    let _ = log.sync().unwrap();
    log.save_hard_state(HardState {
        current_term: 4,
        voted_for: Some(1),
        commit: Some(290),
    })
    .unwrap();
    let mut snapshots = SnapshotStore::open(
        StdDisk,
        &dir.join("snap"),
        geometry(),
        SnapshotConfig::default(),
    )
    .unwrap()
    .store;
    let state = vec![3u8; 70_000];
    let _ = snapshots
        .write(
            100,
            entry(100).term,
            &[
                Section::new(SectionKind::Service, 2, &state),
                Section::new(SectionKind::Sessions, 1, b"sessions"),
            ],
        )
        .unwrap();
    (log, snapshots)
}

/// A rebuild's target: its two directories, made.
fn target(dir: &Path) -> (PathBuf, PathBuf) {
    let (log, snap) = (dir.join("log"), dir.join("snap"));
    std::fs::create_dir_all(&log).unwrap();
    std::fs::create_dir_all(&snap).unwrap();
    (log, snap)
}

fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for sub in ["log", "snap"] {
        let path = dir.join(sub);
        let Ok(read) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in read {
            let entry = entry.unwrap();
            out.push((
                format!("{sub}/{}", entry.file_name().to_string_lossy()),
                std::fs::read(entry.path()).unwrap(),
            ));
        }
    }
    out.sort();
    out
}

#[test]
fn a_rebuild_matches_its_source_up_to_the_reported_top() {
    let source_dir = TempDir::new("source");
    let (mut log, snapshots) = source(&source_dir.0);
    let mut bucket = Bucket::default();
    let exported = backup::export(
        &snapshots,
        &mut log,
        &mut bucket,
        CLUSTER,
        Retention::until(u64::MAX),
    )
    .unwrap();
    assert_eq!(exported.base, (100, entry(100).term));
    assert_eq!(
        exported.top,
        (290, entry(290).term),
        "the commit, not the last entry"
    );
    assert_eq!(exported.entries, 190);
    assert_eq!(exported.not_included, NOT_INCLUDED);
    let manifest = backup::verify(&mut bucket, CLUSTER).unwrap();
    assert_eq!(manifest.objects.len(), 2, "one snapshot, one log range");
    let rebuilt_dir = TempDir::new("rebuilt");
    let (log_dir, snap_dir) = target(&rebuilt_dir.0);
    let report = backup::rebuild(
        &mut bucket,
        CLUSTER,
        &Target {
            disk: &StdDisk,
            log: &log_dir,
            snapshots: &snap_dir,
            geometry: geometry(),
            nonce: [7; 32],
        },
    )
    .unwrap();
    assert_eq!(
        (report.base, report.top, report.entries),
        (exported.base, exported.top, 190)
    );
    // ADR-0123 decision 2: the rebuild took its own identity, derived from
    // the export's, isolated from it, and stored it next to its log.
    let identity = IdentityRecord {
        identity: rebuild_identity(ClusterId(CLUSTER), report.top.0, report.top.1, [7; 32]),
        isolated_from: Some(ClusterId(CLUSTER)),
    };
    assert_ne!(identity.identity, ClusterId(CLUSTER));
    assert_eq!(report.identity, Some(identity));
    assert_eq!(exported.identity, None);
    assert_eq!((report.nonce, exported.nonce), (Some([7; 32]), None));
    assert_eq!(
        IdentityRecord::load(&mut StdDisk, &log_dir).unwrap(),
        Some(identity)
    );
    // The rebuilt node: its snapshot's sections and its log's entries are
    // the source's, up to the top.
    let rebuilt_snaps =
        SnapshotStore::open(StdDisk, &snap_dir, geometry(), SnapshotConfig::default())
            .unwrap()
            .store;
    let latest = rebuilt_snaps.latest().unwrap();
    assert_eq!((latest.index, latest.term), exported.base);
    assert_eq!(
        rebuilt_snaps.read(&latest).unwrap(),
        snapshots.read(&snapshots.latest().unwrap()).unwrap()
    );
    let mut rebuilt = RaftLog::open_with(StdDisk, &log_dir, geometry(), Some(&rebuilt_snaps))
        .unwrap()
        .log;
    assert_eq!(
        (rebuilt.first_index(), rebuilt.last_index()),
        (101, Some(290))
    );
    assert_eq!(
        rebuilt.hard_state().and_then(|state| state.commit),
        Some(290)
    );
    assert_eq!(
        rebuilt.entries(101..291, u64::MAX).unwrap(),
        (101..=290).map(entry).collect::<Vec<_>>()
    );
}

#[test]
fn a_damaged_object_is_refused_naming_its_range_before_anything_is_written() {
    let source_dir = TempDir::new("damaged-source");
    let (mut log, snapshots) = source(&source_dir.0);
    let mut bucket = Bucket::default();
    let _ = backup::export(
        &snapshots,
        &mut log,
        &mut bucket,
        CLUSTER,
        Retention::until(u64::MAX),
    )
    .unwrap();
    // One byte of the log range flipped in storage.
    let name = bucket
        .objects
        .keys()
        .find(|name| name.contains(&format!("/{LOG_OBJECTS:016x}/")))
        .cloned()
        .unwrap();
    bucket.objects.get_mut(&name).unwrap()[17] ^= 1;
    let expected = (LOG_OBJECTS, 101, 291);
    for result in [backup::verify(&mut bucket, CLUSTER).map(|_| ()), {
        let dir = TempDir::new("damaged-target");
        let (log_dir, snap_dir) = target(&dir.0);
        let result = backup::rebuild(
            &mut bucket,
            CLUSTER,
            &Target {
                disk: &StdDisk,
                log: &log_dir,
                snapshots: &snap_dir,
                geometry: geometry(),
                nonce: [7; 32],
            },
        )
        .map(|_| ());
        assert!(files(&dir.0).is_empty(), "a refused rebuild wrote");
        result
    }] {
        match result {
            Err(BackupError::Damaged {
                recording,
                start,
                end,
            }) => assert_eq!((recording, start, end), expected),
            other => panic!("{other:?}"),
        }
    }
    // A missing manifest: no export to rebuild.
    bucket
        .objects
        .retain(|name, _| !name.contains(&format!("/{MANIFEST_OBJECT:016x}/")));
    assert!(matches!(
        backup::verify(&mut bucket, CLUSTER),
        Err(BackupError::Manifest(_))
    ));
}

#[test]
fn an_export_whose_copy_does_not_read_back_counts_nothing() {
    let source_dir = TempDir::new("unread-source");
    let (mut log, snapshots) = source(&source_dir.0);
    let mut bucket = Bucket {
        corrupt_puts: true,
        ..Bucket::default()
    };
    assert!(matches!(
        backup::export(
            &snapshots,
            &mut log,
            &mut bucket,
            CLUSTER,
            Retention::until(u64::MAX)
        ),
        Err(BackupError::Damaged { .. })
    ));
    assert!(matches!(
        backup::manifest(&mut bucket, CLUSTER),
        Err(BackupError::Manifest(_))
    ));
}

/// A rebuild writes only into empty directories: over a node's state it
/// is refused, changing nothing, so it never installs over a log, and never
/// purges what an Archive hold keeps.
#[test]
fn a_rebuild_into_a_node_s_directories_is_refused_and_changes_nothing() {
    let source_dir = TempDir::new("occupied-source");
    let (mut log, snapshots) = source(&source_dir.0);
    let mut bucket = Bucket::default();
    let _ = backup::export(
        &snapshots,
        &mut log,
        &mut bucket,
        CLUSTER,
        Retention::until(u64::MAX),
    )
    .unwrap();
    let occupied = TempDir::new("occupied-target");
    drop(source(&occupied.0));
    let before = files(&occupied.0);
    let (log_dir, snap_dir) = target(&occupied.0);
    let refused = backup::rebuild(
        &mut bucket,
        CLUSTER,
        &Target {
            disk: &StdDisk,
            log: &log_dir,
            snapshots: &snap_dir,
            geometry: geometry(),
            nonce: [7; 32],
        },
    );
    assert!(
        matches!(refused, Err(BackupError::NotEmpty(_))),
        "{refused:?}"
    );
    assert_eq!(files(&occupied.0), before);
}

/// A manifest that is whole and checksummed but leaves a gap in the log,
/// or does not reach its top, is refused by `verify` and `rebuild`.
#[test]
fn a_manifest_that_does_not_cover_the_log_is_refused() {
    let source_dir = TempDir::new("gap-source");
    let (mut log, snapshots) = source(&source_dir.0);
    let mut bucket = Bucket::default();
    let _ = backup::export(
        &snapshots,
        &mut log,
        &mut bucket,
        CLUSTER,
        Retention::until(u64::MAX),
    )
    .unwrap();
    let manifest = backup::manifest(&mut bucket, CLUSTER).unwrap();
    let key = ObjectKey {
        archive: CLUSTER,
        recording: MANIFEST_OBJECT,
        start: 0,
        end: 0,
        kind: karyos_archive::integrity::tiering::ObjectKind::Index,
    };
    // Its top raised past the last entry: the ranges no longer end there.
    let mut raised = manifest.clone();
    raised.top.0 += 1;
    bucket.objects.insert(key.name(), raised.encode());
    assert!(matches!(
        backup::verify(&mut bucket, CLUSTER),
        Err(BackupError::Manifest(_))
    ));
    // Its log range dropped: a gap.
    let mut gap = manifest.clone();
    let _ = gap.objects.pop();
    bucket.objects.insert(key.name(), gap.encode());
    assert!(matches!(
        backup::verify(&mut bucket, CLUSTER),
        Err(BackupError::Manifest(_))
    ));
    let dir = TempDir::new("gap-target");
    let (log_dir, snap_dir) = target(&dir.0);
    assert!(matches!(
        backup::rebuild(
            &mut bucket,
            CLUSTER,
            &Target {
                disk: &StdDisk,
                log: &log_dir,
                snapshots: &snap_dir,
                geometry: geometry(),
                nonce: [7; 32],
            },
        ),
        Err(BackupError::Manifest(_))
    ));
    assert!(files(&dir.0).is_empty());
}

/// An export checks its snapshot is the log's and its commit reaches the
/// snapshot, and never overwrites another export.
#[test]
fn an_export_refuses_a_foreign_snapshot_a_low_commit_and_a_used_remote() {
    let source_dir = TempDir::new("checks-source");
    let (mut log, mut snapshots) = source(&source_dir.0);
    let mut bucket = Bucket::default();
    let _ = backup::export(
        &snapshots,
        &mut log,
        &mut bucket,
        CLUSTER,
        Retention::until(u64::MAX),
    )
    .unwrap();
    assert!(matches!(
        backup::export(
            &snapshots,
            &mut log,
            &mut bucket,
            CLUSTER,
            Retention::until(u64::MAX)
        ),
        Err(BackupError::Exists)
    ));
    // A snapshot at 200 with another term than the log's there.
    let _ = snapshots
        .write(
            200,
            entry(200).term + 5,
            &[Section::new(SectionKind::Service, 2, b"x")],
        )
        .unwrap();
    assert!(matches!(
        backup::export(
            &snapshots,
            &mut log,
            &mut Bucket::default(),
            CLUSTER,
            Retention::until(u64::MAX)
        ),
        Err(BackupError::SnapshotTerm { index: 200, .. })
    ));
    // A snapshot past the commit.
    let _ = snapshots
        .write(
            295,
            entry(295).term,
            &[Section::new(SectionKind::Service, 2, b"y")],
        )
        .unwrap();
    assert!(matches!(
        backup::export(
            &snapshots,
            &mut log,
            &mut Bucket::default(),
            CLUSTER,
            Retention::until(u64::MAX)
        ),
        Err(BackupError::CommitBelowBase {
            base: 295,
            commit: Some(290)
        })
    ));
}

/// The report states the weakest retention the store enforced; an export
/// that requires it fails on the first object the store does not enforce
/// it for, leaving no manifest.
#[test]
fn an_export_reports_retention_and_fails_when_it_is_required_and_not_enforced() {
    let source_dir = TempDir::new("retention");
    let (mut log, snapshots) = source(&source_dir.0);
    let mut locked = Bucket {
        enforces: Some(Enforcement::ObjectLock),
        ..Bucket::default()
    };
    let required = Retention::until(u64::MAX).required();
    let report = backup::export(&snapshots, &mut log, &mut locked, CLUSTER, required).unwrap();
    assert_eq!(report.retention, Enforcement::ObjectLock);
    let mut plain = Bucket::default();
    let report = backup::export(
        &snapshots,
        &mut log,
        &mut plain,
        CLUSTER,
        Retention::until(1),
    )
    .unwrap();
    assert_eq!(report.retention, Enforcement::Unsupported);
    let mut plain = Bucket::default();
    assert!(matches!(
        backup::export(&snapshots, &mut log, &mut plain, CLUSTER, required),
        Err(BackupError::RetentionNotEnforced(Enforcement::Unsupported))
    ));
    assert_eq!(plain.objects.len(), 1, "stopped at the first object");
    assert!(matches!(
        backup::verify(&mut plain, CLUSTER),
        Err(BackupError::Manifest("missing"))
    ));
}

/// A manifest lookup that fails other than for a missing key is the
/// store's error: an export puts nothing, and a check does not call the
/// manifest missing.
#[test]
fn a_failed_manifest_lookup_is_not_taken_for_a_missing_one() {
    let source_dir = TempDir::new("lookup");
    let (mut log, snapshots) = source(&source_dir.0);
    let mut bucket = Bucket {
        unreadable: true,
        ..Bucket::default()
    };
    assert!(matches!(
        backup::export(&snapshots, &mut log, &mut bucket, CLUSTER, Retention::until(u64::MAX)),
        Err(BackupError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
    ));
    assert!(
        bucket.objects.is_empty(),
        "an export put with its lookup failed"
    );
    assert!(matches!(
        backup::verify(&mut bucket, CLUSTER),
        Err(BackupError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
    ));
}

/// A section the service's check refuses fails the check and the rebuild,
/// naming its kind, before anything is written.
#[test]
fn a_section_the_service_check_refuses_is_refused_before_anything_is_written() {
    let source_dir = TempDir::new("sections-source");
    let (mut log, snapshots) = source(&source_dir.0);
    let mut bucket = Bucket::default();
    let _ = backup::export(
        &snapshots,
        &mut log,
        &mut bucket,
        CLUSTER,
        Retention::until(u64::MAX),
    )
    .unwrap();
    let mut seen = Vec::new();
    let mut check = |kind: SectionKind, version: u64, bytes: &[u8]| {
        seen.push((kind, version, bytes.len()));
        if kind == SectionKind::Sessions && bytes != b"a session table" {
            return Err("not a session table".to_owned());
        }
        Ok(())
    };
    assert!(matches!(
        backup::verify_with(&mut bucket, CLUSTER, &mut check),
        Err(BackupError::Section { kind: SectionKind::Sessions, reason })
            if reason == "not a session table"
    ));
    assert_eq!(
        seen,
        vec![
            (SectionKind::Service, 2, 70_000),
            (SectionKind::Sessions, 1, 8)
        ]
    );
    let rebuilt_dir = TempDir::new("sections-rebuilt");
    let (log_dir, snap_dir) = target(&rebuilt_dir.0);
    assert!(matches!(
        backup::rebuild_with(
            &mut bucket,
            CLUSTER,
            &Target {
                disk: &StdDisk,
                log: &log_dir,
                snapshots: &snap_dir,
                geometry: geometry(),
                nonce: [7; 32],
            },
            &mut |kind, _, _| if kind == SectionKind::Service {
                Err("the service cannot open it".to_owned())
            } else {
                Ok(())
            },
        ),
        Err(BackupError::Section {
            kind: SectionKind::Service,
            ..
        })
    ));
    for dir in [&log_dir, &snap_dir] {
        assert_eq!(
            std::fs::read_dir(dir).unwrap().count(),
            0,
            "a refused rebuild wrote"
        );
    }
    // A check that takes every section rebuilds.
    assert!(
        backup::rebuild_with(
            &mut bucket,
            CLUSTER,
            &Target {
                disk: &StdDisk,
                log: &log_dir,
                snapshots: &snap_dir,
                geometry: geometry(),
                nonce: [7; 32],
            },
            &mut |_, _, _| Ok(()),
        )
        .is_ok()
    );
}

/// Codex review of karyos#1283: an export under the all-zero identity,
/// which no identity record can name as a source, is refused before the
/// rebuild writes anything.
#[test]
fn a_rebuild_of_the_zero_identity_is_refused_unwritten() {
    let source_dir = TempDir::new("zero-source");
    let (mut log, snapshots) = source(&source_dir.0);
    let mut bucket = Bucket::default();
    let _ = backup::export(
        &snapshots,
        &mut log,
        &mut bucket,
        [0; 32],
        Retention::until(u64::MAX),
    )
    .unwrap();
    let dir = TempDir::new("zero-rebuilt");
    let (log_dir, snap_dir) = target(&dir.0);
    let refused = backup::rebuild(
        &mut bucket,
        [0; 32],
        &Target {
            disk: &StdDisk,
            log: &log_dir,
            snapshots: &snap_dir,
            geometry: geometry(),
            nonce: [7; 32],
        },
    );
    assert!(matches!(refused, Err(BackupError::ZeroIdentity)), "{refused:?}");
    assert!(files(&dir.0).is_empty(), "a refused rebuild wrote");
}
