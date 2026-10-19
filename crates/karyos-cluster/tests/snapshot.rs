// SPDX-License-Identifier: Apache-2.0

//! C8a's snapshot store on the operating system's disk (quantstratum-docs:
//! karyos/design/cluster-dedup-and-snapshots.md §3). The crash cases run on
//! C2's simulated disk in karyos-sim's `tests/snapshot_crash.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::{Path, PathBuf};

use karyos_archive::disk::{Disk, StdDisk};
use karyos_archive::segment::Geometry;
use karyos_cluster::snapshot::{
    MANIFEST_FILE, Section, SectionKind, SnapshotConfig, SnapshotError, SnapshotStore,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("karyos-c8-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 4 KiB segments, so a snapshot of a few KiB spans them.
fn geometry() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

fn open(dir: &Path) -> SnapshotStore<StdDisk> {
    SnapshotStore::open(StdDisk, dir, geometry(), SnapshotConfig::default())
        .unwrap()
        .store
}

fn bytes(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|at| u8::try_from(at % 251).unwrap() ^ seed)
        .collect()
}

#[test]
fn sections_round_trip_in_order() {
    let dir = TempDir::new("round-trip");
    let mut store = open(dir.path());
    let (consensus, sessions, service) = (bytes(1, 40), bytes(2, 9000), bytes(3, 0));
    let info = store
        .write(
            100,
            3,
            &[
                Section::new(SectionKind::Consensus, 1, &consensus),
                Section::new(SectionKind::Sessions, 1, &sessions),
                Section::new(SectionKind::Service, 0x0002_0001, &service),
            ],
        )
        .unwrap();
    assert_eq!((info.index, info.term), (100, 3));
    let reopened = open(dir.path());
    assert_eq!(reopened.latest(), Some(info));
    let sections = reopened.read(&info).unwrap();
    let read: Vec<_> = sections
        .iter()
        .map(|section| (section.kind, section.version, section.bytes.clone()))
        .collect();
    assert_eq!(
        read,
        vec![
            (SectionKind::Consensus, 1, consensus),
            (SectionKind::Sessions, 1, sessions),
            (SectionKind::Service, 0x0002_0001, service),
        ]
    );
}

#[test]
fn the_two_newest_are_kept_and_the_others_purged() {
    let dir = TempDir::new("purge");
    let mut store = open(dir.path());
    let payload = bytes(7, 5000);
    let infos: Vec<_> = (1..=4)
        .map(|n| {
            store
                .write(
                    n * 10,
                    1,
                    &[Section::new(SectionKind::Service, 1, &payload)],
                )
                .unwrap()
        })
        .collect();
    assert_eq!(store.snapshots(), &infos[2..]);
    // Only the kept snapshots' files and the manifest remain.
    let mut names = StdDisk.list(dir.path()).unwrap();
    names.retain(|name| name != MANIFEST_FILE);
    let ids: Vec<u64> = names
        .iter()
        .map(|name| u64::from_str_radix(name.split_once('-').unwrap().0, 16).unwrap())
        .collect();
    assert!(
        ids.iter()
            .all(|id| *id == infos[2].id || *id == infos[3].id),
        "{names:?}"
    );
    assert_eq!(open(dir.path()).snapshots(), &infos[2..]);
}

#[test]
fn a_snapshot_must_be_newer_and_not_empty() {
    let dir = TempDir::new("refusals");
    let mut store = open(dir.path());
    let payload = bytes(1, 10);
    store
        .write(10, 1, &[Section::new(SectionKind::Service, 1, &payload)])
        .unwrap();
    assert!(matches!(
        store.write(10, 2, &[Section::new(SectionKind::Service, 1, &payload)]),
        Err(SnapshotError::NotNewer {
            index: 10,
            newest: 10
        })
    ));
    assert!(matches!(store.write(11, 1, &[]), Err(SnapshotError::Empty)));
    // A refusal does not poison the store.
    store
        .write(11, 1, &[Section::new(SectionKind::Service, 1, &payload)])
        .unwrap();
}

#[test]
fn an_unpublished_store_is_removed_at_open() {
    let dir = TempDir::new("unpublished");
    let mut store = open(dir.path());
    let payload = bytes(1, 100);
    let info = store
        .write(10, 1, &[Section::new(SectionKind::Service, 1, &payload)])
        .unwrap();
    // A store a crash left before its manifest: a copy under another id.
    for name in StdDisk.list(dir.path()).unwrap() {
        if let Some(rest) = name.strip_prefix(&format!("{:016x}-", info.id)) {
            std::fs::copy(
                dir.path().join(&name),
                dir.path().join(format!("{:016x}-{rest}", info.id + 5)),
            )
            .unwrap();
        }
    }
    let opened =
        SnapshotStore::open(StdDisk, dir.path(), geometry(), SnapshotConfig::default()).unwrap();
    assert_eq!(opened.removed, vec![info.id + 5]);
    assert_eq!(opened.store.snapshots(), &[info]);
    // Ids are never reused.
    let mut store = opened.store;
    let next = store
        .write(20, 1, &[Section::new(SectionKind::Service, 1, &payload)])
        .unwrap();
    assert!(next.id > info.id + 5);
}

#[test]
fn a_damaged_snapshot_is_reported_and_not_used() {
    let dir = TempDir::new("damaged");
    let mut store = open(dir.path());
    let payload = bytes(1, 100);
    let older = store
        .write(10, 1, &[Section::new(SectionKind::Service, 1, &payload)])
        .unwrap();
    let newer = store
        .write(20, 1, &[Section::new(SectionKind::Service, 1, &payload)])
        .unwrap();
    let data = dir.path().join(format!("{:016x}-{:016x}.seg", newer.id, 0));
    let mut contents = std::fs::read(&data).unwrap();
    // A byte of the payload, past the segment's header.
    let at = contents.len() - 10;
    contents[at] ^= 0xFF;
    std::fs::write(&data, contents).unwrap();
    let opened =
        SnapshotStore::open(StdDisk, dir.path(), geometry(), SnapshotConfig::default()).unwrap();
    assert_eq!(opened.damaged, vec![newer]);
    assert_eq!(opened.store.latest(), Some(older));
}

#[test]
fn a_damaged_manifest_is_refused() {
    let dir = TempDir::new("manifest");
    let mut store = open(dir.path());
    let payload = bytes(1, 100);
    store
        .write(10, 1, &[Section::new(SectionKind::Service, 1, &payload)])
        .unwrap();
    let manifest = dir.path().join(MANIFEST_FILE);
    let mut contents = std::fs::read(&manifest).unwrap();
    contents[20] ^= 1;
    std::fs::write(&manifest, contents).unwrap();
    assert!(matches!(
        SnapshotStore::open(StdDisk, dir.path(), geometry(), SnapshotConfig::default()),
        Err(SnapshotError::Manifest)
    ));
}
