// SPDX-License-Identifier: Apache-2.0

//! C4's install (karyos-cluster `RaftLog::install`; karyos#687, decided
//! 2026-10-30 by QS-COORDINATOR) over C2's crashing disk: a follower's log
//! holds entries 1 to 6, commit 3; a snapshot at index 20 of term 2 is
//! published in the node's snapshot store; the log installs it and appends
//! entry 21. The run crashes at every disk operation from the install on,
//! and each is reopened under every survival mode.
//!
//! The invariant, at every crash point:
//!
//! 1. with its snapshot store, the log opens, either as it was (first
//!    index 1, commit 3, entries 1 to 6) or installed (first index 21,
//!    term 20 of 2, commit 20, nothing or entry 21 after it);
//! 2. installed, it does not open without the snapshot store
//!    (`InstallUnverified`);
//! 3. some crash point leaves the install's record durable with the old
//!    commit and frames: the cut the coordinator named, finished by the
//!    open.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_archive::disk::Disk;
use karyos_archive::segment::Geometry;
use karyos_cluster::hard_state::{HARD_STATE_FILE, HardState};
use karyos_cluster::snapshot::{Section, SectionKind, SnapshotConfig, SnapshotStore};
use karyos_cluster::{Entry, LogError, RaftLog};
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::rng::Rng;
use karyos_sim::scenarios;

const LOG: &str = "/raft";
const SNAPSHOTS: &str = "/snap";
const BASE: u64 = 20;
const BASE_TERM: u64 = 2;

/// 4 KiB segments: the entries span a few.
fn geometry() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

fn entry(index: u64, term: u64) -> Entry {
    Entry {
        index,
        term,
        event_time: index,
        payload: vec![u8::try_from(index % 251).unwrap(); 900],
    }
}

fn snapshots(disk: SimDisk) -> Result<SnapshotStore<SimDisk>, String> {
    SnapshotStore::open(
        disk,
        Path::new(SNAPSHOTS),
        geometry(),
        SnapshotConfig::default(),
    )
    .map(|opened| opened.store)
    .map_err(|error| format!("snapshots: {error}"))
}

/// The follower before the install, on a clean disk; the operations it
/// took.
fn prepare(disk: &SimDisk) -> u64 {
    let mut log = RaftLog::create(disk.clone(), Path::new(LOG), geometry(), 1).unwrap();
    let _ = log
        .append(&(1..=6).map(|index| entry(index, 1)).collect::<Vec<_>>())
        .unwrap();
    let _ = log.sync().unwrap();
    log.save_hard_state(HardState {
        current_term: 1,
        voted_for: Some(0),
        commit: Some(3),
    })
    .unwrap();
    let mut store = snapshots(disk.clone()).unwrap();
    let _ = store
        .write(
            BASE,
            BASE_TERM,
            &[Section::new(SectionKind::Service, 1, b"the state up to 20")],
        )
        .unwrap();
    disk.used()
}

/// How far the install got before the crash.
#[derive(Debug, Default, Clone, Copy)]
struct Model {
    installed: bool,
    appended: bool,
}

/// The install and one append, on a disk prepared by [`prepare`].
fn install(disk: &SimDisk) -> Model {
    let mut model = Model::default();
    let Ok(store) = snapshots(disk.clone()) else {
        return model;
    };
    let Ok(opened) = RaftLog::open_with(disk.clone(), Path::new(LOG), geometry(), Some(&store))
    else {
        return model;
    };
    let mut log = opened.log;
    if log.install(BASE, BASE_TERM, &store).is_err() {
        return model;
    }
    model.installed = true;
    if log.append(&[entry(BASE + 1, BASE_TERM)]).is_err() || log.sync().is_err() {
        return model;
    }
    model.appended = true;
    model
}

/// The stored hard state's commit, read raw.
fn stored_commit(disk: &mut SimDisk) -> Option<u64> {
    let file = disk.open_read(&Path::new(LOG).join(HARD_STATE_FILE)).ok()?;
    let mut bytes = vec![0u8; karyos_cluster::hard_state::HARD_STATE_LEN];
    disk.read_at(&file, 0, &mut bytes).ok()?;
    HardState::decode(&bytes).ok()?.commit
}

/// Checks the invariant after `disk` crashed; whether the install's record
/// was durable with the old commit (point 3).
fn check(disk: &SimDisk, survives: Survives, model: Model) -> Result<bool, String> {
    let mut restarted = disk
        .after_crash(survives)
        .map_err(|error| error.to_string())?;
    let raw_commit = stored_commit(&mut restarted);
    let store = snapshots(restarted.clone())?;
    let plain = RaftLog::open(restarted.clone(), Path::new(LOG), geometry());
    let again_disk = restarted.clone();
    let opened = RaftLog::open_with(restarted, Path::new(LOG), geometry(), Some(&store))
        .map_err(|error| format!("open: {error}"))?;
    let log = opened.log;
    let commit = log.hard_state().and_then(|state| state.commit);
    match log.base() {
        Some((BASE, BASE_TERM)) => {
            if log.first_index() != BASE + 1 || log.term(BASE) != Some(BASE_TERM) {
                return Err(format!(
                    "installed at {} {:?}",
                    log.first_index(),
                    log.base()
                ));
            }
            if commit != Some(BASE) {
                return Err(format!("installed with commit {commit:?}"));
            }
            if !matches!(log.last_index(), None | Some(21)) {
                return Err(format!("installed holding up to {:?}", log.last_index()));
            }
            if model.appended && survives == Survives::Synced && log.last_index() != Some(21) {
                return Err("the synced append is lost".into());
            }
            if !matches!(
                plain,
                Err(LogError::InstallUnverified {
                    index: BASE,
                    term: BASE_TERM
                })
            ) {
                return Err(format!("opened installed without its snapshot: {plain:?}"));
            }
            // The recovered log goes on: it appends what follows, and
            // opens again over it.
            let mut log = log;
            if log.last_index().is_none() {
                let _ = log
                    .append(&[entry(BASE + 1, BASE_TERM)])
                    .map_err(|error| format!("append after recovery: {error}"))?;
            }
            let _ = log
                .append(&[entry(BASE + 2, BASE_TERM)])
                .map_err(|error| format!("append after recovery: {error}"))?;
            let _ = log.sync().map_err(|error| format!("sync: {error}"))?;
            drop(log);
            let again = RaftLog::open_with(again_disk, Path::new(LOG), geometry(), Some(&store))
                .map_err(|error| format!("second open: {error}"))?
                .log;
            if again.last_index() != Some(BASE + 2) || again.first_index() != BASE + 1 {
                return Err(format!(
                    "second open: first {} last {:?}",
                    again.first_index(),
                    again.last_index()
                ));
            }
            Ok(raw_commit == Some(3))
        }
        None => {
            if model.installed {
                return Err("an install that returned is lost".into());
            }
            if log.first_index() != 1 || commit != Some(3) || log.last_index() != Some(6) {
                return Err(format!(
                    "as it was? first {} commit {commit:?} last {:?}",
                    log.first_index(),
                    log.last_index()
                ));
            }
            Ok(false)
        }
        other => Err(format!("another base {other:?}")),
    }
}

#[test]
fn every_crash_point_of_an_install_recovers_over_its_snapshot() {
    let whole = SimDisk::new();
    let prepared = prepare(&whole);
    let model = install(&whole);
    assert!(model.appended, "the run without a crash stopped early");
    let operations = whole.used() - prepared;
    let mut failures = Vec::new();
    let mut cut_after_record = 0;
    for point in 0..=operations {
        let disk = SimDisk::with_budget(prepared + point);
        assert_eq!(prepare(&disk), prepared);
        let model = install(&disk);
        let mut modes = vec![Survives::Synced, Survives::Everything];
        for seed in scenarios::seeds() {
            let mixed = Rng::new(seed ^ point.rotate_left(32)).next_u64();
            modes.push(Survives::Subset { seed: mixed });
            modes.push(Survives::Torn { seed: mixed });
        }
        for survives in modes {
            match check(&disk, survives, model) {
                Ok(true) => cut_after_record += 1,
                Ok(false) => {}
                Err(broken) => failures.push(format!(
                    "crash at install operation {} under {survives:?}: {broken}",
                    point + 1
                )),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures of {} points:\n{}",
        failures.len(),
        operations + 1,
        failures.join("\n")
    );
    assert!(
        cut_after_record > 0,
        "no crash point left the record durable with the old commit"
    );
}

/// An install refuses, changing nothing, without its snapshot, at another
/// base, or not past the commit.
#[test]
fn an_install_without_its_snapshot_or_not_past_the_commit_is_refused() {
    let disk = SimDisk::new();
    let _ = prepare(&disk);
    let store = snapshots(disk.clone()).unwrap();
    let mut log = RaftLog::open_with(disk.clone(), Path::new(LOG), geometry(), Some(&store))
        .unwrap()
        .log;
    assert!(matches!(
        log.install(BASE + 1, BASE_TERM, &store),
        Err(LogError::InstallUnverified { .. })
    ));
    assert!(matches!(
        log.install(BASE, BASE_TERM + 1, &store),
        Err(LogError::InstallUnverified { .. })
    ));
    let empty = snapshots(SimDisk::new()).unwrap();
    assert!(matches!(
        log.install(BASE, BASE_TERM, &empty),
        Err(LogError::InstallUnverified { .. })
    ));
    assert_eq!((log.first_index(), log.last_index()), (1, Some(6)));
    // A later snapshot is no install's base: the latest must be the base
    // itself, index and term (karyos#903 review, QS-REVIEWER).
    let mut later = snapshots(disk.clone()).unwrap();
    let _ = later
        .write(
            BASE + 10,
            BASE_TERM,
            &[Section::new(SectionKind::Service, 1, b"the state up to 30")],
        )
        .unwrap();
    assert!(matches!(
        log.install(BASE, BASE_TERM + 1, &later),
        Err(LogError::InstallUnverified { .. })
    ));
    assert!(matches!(
        log.install(BASE, BASE_TERM, &later),
        Err(LogError::InstallUnverified { .. })
    ));
    assert_eq!((log.first_index(), log.last_index()), (1, Some(6)));
    // Past the commit only: a commit at the base refuses it.
    let _ = log
        .append(&(7..=20).map(|index| entry(index, 1)).collect::<Vec<_>>())
        .unwrap();
    let _ = log.sync().unwrap();
    log.save_hard_state(HardState {
        current_term: 1,
        voted_for: Some(0),
        commit: Some(BASE),
    })
    .unwrap();
    assert!(matches!(
        log.install(BASE, BASE_TERM, &store),
        Err(LogError::InstallStale { index: BASE, .. })
    ));
}

/// An installed log reopens after a later compaction: a newer snapshot
/// holds the base's state too (karyos#903 review, codex: latest 30 against
/// an install at 20 was InstallUnverified). The install's vote, of an older
/// term than the base's, does not carry into the base's term.
#[test]
fn an_install_survives_a_later_snapshot_and_drops_an_old_vote() {
    let disk = SimDisk::new();
    let _ = prepare(&disk);
    let mut store = snapshots(disk.clone()).unwrap();
    let mut log = RaftLog::open_with(disk.clone(), Path::new(LOG), geometry(), Some(&store))
        .unwrap()
        .log;
    log.install(BASE, BASE_TERM, &store).unwrap();
    let state = log.hard_state().unwrap();
    assert_eq!(
        (state.current_term, state.voted_for, state.commit),
        (BASE_TERM, None, Some(BASE)),
        "the term-1 vote does not carry into term 2"
    );
    let _ = log
        .append(
            &(BASE + 1..=BASE + 10)
                .map(|index| entry(index, BASE_TERM))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let _ = log.sync().unwrap();
    log.save_hard_state(HardState {
        current_term: BASE_TERM,
        voted_for: None,
        commit: Some(BASE + 10),
    })
    .unwrap();
    // A compaction at 30: the newer snapshot, then a purge that keeps the
    // last entries and so leaves the install's record.
    let _ = store
        .write(
            BASE + 10,
            BASE_TERM,
            &[Section::new(SectionKind::Service, 1, b"the state up to 30")],
        )
        .unwrap();
    let _ = log.purge_prefix(BASE + 1).unwrap();
    drop(log);
    let reopened = RaftLog::open_with(disk, Path::new(LOG), geometry(), Some(&store))
        .unwrap()
        .log;
    assert_eq!(
        (reopened.first_index(), reopened.last_index()),
        (BASE + 1, Some(BASE + 10))
    );
}
