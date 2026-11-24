// SPDX-License-Identifier: Apache-2.0

//! Streamed snapshot writes (karyos#682): a snapshot whose sections arrive
//! in pieces, as a leader's install sends them, is the same snapshot
//! `SnapshotStore::write` would publish, byte for byte; one not whole is
//! never published, and an abandoned one leaves nothing.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::{Path, PathBuf};

use karyos_archive::disk::StdDisk;
use karyos_archive::segment::Geometry;
use karyos_cluster::snapshot::{
    Section, SectionKind, SnapshotConfig, SnapshotError, SnapshotStore, WRITE_CHUNK,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("karyos-c8s-{}-{name}", std::process::id()));
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

fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// The same sections, written whole in one store and streamed in odd
/// pieces in another: the same length, digest and sections.
#[test]
fn a_streamed_snapshot_is_the_written_one() {
    let service = bytes(3, 3 * WRITE_CHUNK + 777);
    let sessions = bytes(9, 1000);
    let whole_dir = TempDir::new("whole");
    let mut whole = open(&whole_dir.0);
    let written = whole
        .write(
            40,
            2,
            &[
                Section::new(SectionKind::Service, 7, &service),
                Section::new(SectionKind::Sessions, 1, &sessions),
            ],
        )
        .unwrap();
    let stream_dir = TempDir::new("stream");
    let mut streamed = open(&stream_dir.0);
    let mut pending = streamed.begin(40, 2).unwrap();
    pending
        .section(
            SectionKind::Service,
            7,
            u64::try_from(service.len()).unwrap(),
        )
        .unwrap();
    for piece in service.chunks(5_003) {
        pending.write(piece).unwrap();
    }
    assert_eq!(pending.left(), 0);
    pending
        .section(
            SectionKind::Sessions,
            1,
            u64::try_from(sessions.len()).unwrap(),
        )
        .unwrap();
    pending.write(&sessions).unwrap();
    let info = streamed.publish(pending).unwrap();
    assert_eq!(
        (info.index, info.term, info.length, info.digest),
        (written.index, written.term, written.length, written.digest)
    );
    assert_eq!(streamed.read(&info).unwrap(), whole.read(&written).unwrap());
    // Reopened, it is published and verifies.
    drop(streamed);
    let reopened = open(&stream_dir.0);
    assert_eq!(reopened.latest(), Some(info));
    reopened.verify(&info).unwrap();
}

/// A snapshot not whole, or written past a section, is never published,
/// and leaves no file; an abandoned one neither; a newer one published
/// meanwhile wins.
#[test]
fn an_incomplete_or_abandoned_snapshot_is_never_published() {
    let dir = TempDir::new("incomplete");
    let mut store = open(&dir.0);
    let before = files(&dir.0);
    // A section short of its length.
    let mut short = store.begin(10, 1).unwrap();
    short.section(SectionKind::Service, 1, 100).unwrap();
    short.write(&[1; 60]).unwrap();
    assert!(matches!(
        store.publish(short),
        Err(SnapshotError::Incomplete)
    ));
    // Past its length: the write is refused and the snapshot broken.
    let mut long = store.begin(10, 1).unwrap();
    long.section(SectionKind::Service, 1, 10).unwrap();
    assert!(matches!(
        long.write(&[1; 11]),
        Err(SnapshotError::Incomplete)
    ));
    long.write(&[1; 10]).unwrap_err();
    assert!(matches!(
        store.publish(long),
        Err(SnapshotError::Incomplete)
    ));
    // No section at all; a section opened before the last is whole.
    let empty = store.begin(10, 1).unwrap();
    assert!(matches!(
        store.publish(empty),
        Err(SnapshotError::Incomplete)
    ));
    let mut early = store.begin(10, 1).unwrap();
    early.section(SectionKind::Service, 1, 5).unwrap();
    assert!(matches!(
        early.section(SectionKind::Sessions, 1, 5),
        Err(SnapshotError::Incomplete)
    ));
    store.abandon(early).unwrap();
    // Abandoned whole.
    let mut dropped = store.begin(10, 1).unwrap();
    dropped.section(SectionKind::Service, 1, 3).unwrap();
    dropped.write(b"abc").unwrap();
    store.abandon(dropped).unwrap();
    assert_eq!(store.latest(), None);
    assert_eq!(
        files(&dir.0),
        before,
        "a refused or abandoned snapshot left files"
    );
    // A newer snapshot published while one streams: the older is refused.
    let mut older = store.begin(10, 1).unwrap();
    older.section(SectionKind::Service, 1, 3).unwrap();
    older.write(b"old").unwrap();
    let _ = store
        .write(20, 1, &[Section::new(SectionKind::Service, 1, b"new")])
        .unwrap();
    assert!(matches!(
        store.publish(older),
        Err(SnapshotError::NotNewer {
            index: 10,
            newest: 20
        })
    ));
    assert_eq!(store.latest().map(|info| info.index), Some(20));
    // And a stream not past the newest is refused at its start.
    assert!(matches!(
        store.begin(20, 1),
        Err(SnapshotError::NotNewer { .. })
    ));
}
