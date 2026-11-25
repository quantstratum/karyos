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

use karyos_archive::control::HoldState;
use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::copies::Enforcement;
use karyos_archive::integrity::tiering::{ObjectKey, ObjectStore};
use karyos_archive::segment::Geometry;
use karyos_cluster::backup::{
    self, BackupError, LOG_OBJECTS, MANIFEST_OBJECT, NOT_INCLUDED, Target,
};
use karyos_cluster::snapshot::{Section, SectionKind, SnapshotConfig, SnapshotStore};
use karyos_cluster::{Entry, HardState, LogError, RaftLog};

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
        Ok(Enforcement::Unsupported)
    }

    fn get(&mut self, key: &ObjectKey) -> io::Result<Vec<u8>> {
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
    let exported = backup::export(&snapshots, &mut log, &mut bucket, CLUSTER, u64::MAX).unwrap();
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
        },
        &HoldState::None,
    )
    .unwrap();
    assert_eq!(
        (report.base, report.top, report.entries),
        (exported.base, exported.top, 190)
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
    let _ = backup::export(&snapshots, &mut log, &mut bucket, CLUSTER, u64::MAX).unwrap();
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
            },
            &HoldState::None,
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
        Err(BackupError::Manifest)
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
        backup::export(&snapshots, &mut log, &mut bucket, CLUSTER, u64::MAX),
        Err(BackupError::Damaged { .. })
    ));
    assert!(matches!(
        backup::manifest(&mut bucket, CLUSTER),
        Err(BackupError::Manifest)
    ));
}

#[test]
fn a_rebuild_through_a_hold_is_refused_and_changes_nothing() {
    let source_dir = TempDir::new("held-source");
    let (mut log, snapshots) = source(&source_dir.0);
    let mut bucket = Bucket::default();
    let _ = backup::export(&snapshots, &mut log, &mut bucket, CLUSTER, u64::MAX).unwrap();
    // A target that already holds a node's log, under a hold.
    let held_dir = TempDir::new("held-target");
    drop(source(&held_dir.0));
    let before = files(&held_dir.0);
    let (log_dir, snap_dir) = target(&held_dir.0);
    for state in [HoldState::Held, HoldState::Pending, HoldState::Unknown] {
        let refused = backup::rebuild(
            &mut bucket,
            CLUSTER,
            &Target {
                disk: &StdDisk,
                log: &log_dir,
                snapshots: &snap_dir,
                geometry: geometry(),
            },
            &state,
        );
        assert!(
            matches!(refused, Err(BackupError::Log(LogError::ArchiveHeld { state: got })) if got == state),
            "{state:?}: {refused:?}"
        );
        assert_eq!(
            files(&held_dir.0),
            before,
            "{state:?}: a refused rebuild changed a file"
        );
    }
}
