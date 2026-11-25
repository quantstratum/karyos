// SPDX-License-Identifier: Apache-2.0

//! `karyos-backup` end to end (karyos#717): a node's directories exported
//! to a remote directory, the export verified, a node rebuilt from it into
//! fresh directories that open with the same log up to the reported top;
//! then one damaged object refused by `verify` and `rebuild`, naming its
//! range. Each step's output is printed (`--nocapture`): the run the
//! documented procedure quotes.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use karyos_archive::disk::StdDisk;
use karyos_archive::segment::Geometry;
use karyos_cluster::snapshot::{Section, SectionKind, SnapshotConfig, SnapshotStore};
use karyos_cluster::{Entry, HardState, RaftLog};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("karyos-backup-tool-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn sub(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::create_dir_all(&path).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const GEOMETRY: &str = "4096,65536";

fn geometry() -> Geometry {
    Geometry::new(4096, 65_536).unwrap()
}

fn entry(index: u64) -> Entry {
    Entry {
        index,
        term: 2,
        event_time: index,
        payload: format!("entry {index}").into_bytes(),
    }
}

/// A stopped node: entries 1 to 2,500, committed to 2,400, a snapshot at
/// 1,000.
fn node(log: &Path, snapshots: &Path) {
    let mut raft = RaftLog::create(StdDisk, log, geometry(), 1).unwrap();
    let entries: Vec<Entry> = (1..=2_500).map(entry).collect();
    let _ = raft.append(&entries).unwrap();
    let _ = raft.sync().unwrap();
    raft.save_hard_state(HardState {
        current_term: 2,
        voted_for: Some(1),
        commit: Some(2_400),
    })
    .unwrap();
    let mut store = SnapshotStore::open(StdDisk, snapshots, geometry(), SnapshotConfig::default())
        .unwrap()
        .store;
    let _ = store
        .write(
            1_000,
            2,
            &[Section::new(
                SectionKind::Service,
                1,
                b"the service state at 1,000",
            )],
        )
        .unwrap();
}

fn backup(args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_karyos-backup"))
        .args(args)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("$ karyos-backup {}\n{text}", args.join(" "));
    (output.status.success(), text)
}

#[test]
fn a_node_is_exported_verified_and_rebuilt_end_to_end() {
    let dir = TempDir::new("e2e");
    let (log, snapshots, remote) = (dir.sub("log"), dir.sub("snap"), dir.sub("remote"));
    node(&log, &snapshots);
    let cluster = "c1".repeat(32);
    let path = |path: &Path| path.to_str().unwrap().to_owned();
    let (ok, out) = backup(&[
        "export",
        "--log",
        &path(&log),
        "--snapshots",
        &path(&snapshots),
        "--geometry",
        GEOMETRY,
        "--cluster",
        &cluster,
        "--remote",
        &path(&remote),
    ]);
    assert!(ok, "{out}");
    assert!(
        out.starts_with("export base=1000:2 top=2400:2 entries=1400 objects=4\n"),
        "{out}"
    );
    assert!(
        out.contains("not included: entries past the commit index"),
        "{out}"
    );
    let (ok, out) = backup(&["verify", "--cluster", &cluster, "--remote", &path(&remote)]);
    assert!(ok, "{out}");
    assert_eq!(out, "verify base=1000:2 top=2400:2 objects=4 ok\n");
    let (rebuilt_log, rebuilt_snaps) = (dir.sub("rebuilt-log"), dir.sub("rebuilt-snap"));
    let (ok, out) = backup(&[
        "rebuild",
        "--log",
        &path(&rebuilt_log),
        "--snapshots",
        &path(&rebuilt_snaps),
        "--geometry",
        GEOMETRY,
        "--cluster",
        &cluster,
        "--remote",
        &path(&remote),
    ]);
    assert!(ok, "{out}");
    assert!(
        out.starts_with("rebuild base=1000:2 top=2400:2 entries=1400 objects=4\n"),
        "{out}"
    );
    // The rebuilt node opens with the source's committed log after the
    // snapshot, and the snapshot itself.
    let store = SnapshotStore::open(
        StdDisk,
        &rebuilt_snaps,
        geometry(),
        SnapshotConfig::default(),
    )
    .unwrap()
    .store;
    let latest = store.latest().unwrap();
    assert_eq!((latest.index, latest.term), (1_000, 2));
    let mut rebuilt = RaftLog::open_with(StdDisk, &rebuilt_log, geometry(), Some(&store))
        .unwrap()
        .log;
    assert_eq!(
        (rebuilt.first_index(), rebuilt.last_index()),
        (1_001, Some(2_400))
    );
    assert_eq!(
        rebuilt.entries(1_001..2_401, u64::MAX).unwrap(),
        (1_001..=2_400).map(entry).collect::<Vec<_>>()
    );
    // One byte of the second log range damaged: both commands refuse,
    // naming its range.
    let damaged = std::fs::read_dir(&remote)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("_0000000000000001_00000000000007e9-"))
        })
        .unwrap();
    let mut bytes = std::fs::read(&damaged).unwrap();
    bytes[40] ^= 1;
    std::fs::write(&damaged, bytes).unwrap();
    let (ok, out) = backup(&["verify", "--cluster", &cluster, "--remote", &path(&remote)]);
    assert!(!ok);
    assert!(out.contains("object 1 2025..2401 is damaged"), "{out}");
    let (fresh_log, fresh_snaps) = (dir.sub("fresh-log"), dir.sub("fresh-snap"));
    let (ok, out) = backup(&[
        "rebuild",
        "--log",
        &path(&fresh_log),
        "--snapshots",
        &path(&fresh_snaps),
        "--geometry",
        GEOMETRY,
        "--cluster",
        &cluster,
        "--remote",
        &path(&remote),
    ]);
    assert!(!ok);
    assert!(out.contains("object 1 2025..2401 is damaged"), "{out}");
    assert_eq!(
        std::fs::read_dir(&fresh_log).unwrap().count(),
        0,
        "a refused rebuild wrote"
    );
}
