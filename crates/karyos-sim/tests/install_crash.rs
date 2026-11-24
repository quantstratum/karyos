// SPDX-License-Identifier: Apache-2.0

//! Snapshot install and compaction through the custom Raft core
//! (karyos-cluster `consensus::Core`, ADR-0105) over C2's crashing disk,
//! at every manifest and truncation boundary (karyos#682): every disk
//! operation of the whole sequence, each reopened under every survival
//! mode.
//!
//! - **Install** (a follower behind compaction): the follower's log holds
//!   entries 1 to 6, commit 3. It writes the leader's snapshot at 20 of
//!   term 2 to its store (sections, then the manifest that publishes it),
//!   checks the core's admission, installs it in its log (the first-index
//!   record, the watermark, the cut, the hard state's commit), tells the
//!   core, and appends entry 21.
//! - **Compaction** (a node at its commit): the log holds entries 1 to 40,
//!   commit 40. It writes a snapshot at 30 (manifest last), purges the log
//!   below 31 (A2's floor, then the first-index file) and tells the core.
//!
//! The invariant, at every crash point, for the replica rebuilt from its
//! store and log, its core recovered over the store's latest snapshot:
//!
//! 1. the log opens with its store, and every entry it no longer holds is
//!    covered by a verified snapshot: its first index minus one is at most
//!    the store's latest base;
//! 2. the rebuilt state (the latest snapshot's service section, then the
//!    log's committed entries after it) is the one the run built, up to
//!    the recovered commit, never another;
//! 3. the core recovers committed at least to the base, and an install it
//!    has not finished is still admitted, so a retry completes it: the
//!    replica is recoverable, not only consistent;
//! 4. some crash points fall between the manifest and the log's record
//!    (published, not installed or not purged): the boundaries are hit, not
//!    stepped over.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_archive::segment::Geometry;
use karyos_cluster::consensus::{Config, Core, Effects, InstallError, Message, TermVote};
use karyos_cluster::hard_state::HardState;
use karyos_cluster::snapshot::{Section, SectionKind, SnapshotConfig, SnapshotStore};
use karyos_cluster::{Entry, RaftLog};
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::rng::Rng;
use karyos_sim::scenarios;

const LOG: &str = "/raft";
const SNAPSHOTS: &str = "/snap";

/// 4 KiB segments: the entries span several.
fn geometry() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

/// Entry `index`'s payload: its identity in the state.
fn payload(index: u64) -> Vec<u8> {
    vec![u8::try_from(index % 251).unwrap(); 600]
}

fn entry(index: u64, term: u64) -> Entry {
    Entry {
        index,
        term,
        event_time: index,
        payload: payload(index),
    }
}

/// The service state up to `index`: the entries' identities, in order.
fn state(index: u64) -> Vec<u8> {
    (1..=index)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
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

/// What the core asks for, kept only to count it.
#[derive(Default)]
struct Sink(usize);

impl Effects for Sink {
    fn persist(&mut self, _: TermVote) {
        self.0 += 1;
    }
    fn write(&mut self, _: u64, _: u64) {
        self.0 += 1;
    }
    fn append(&mut self, _: u64, _: u64) {
        self.0 += 1;
    }
    fn send(&mut self, _: u64, _: Message) {
        self.0 += 1;
    }
    fn send_after_persist(&mut self, _: u64, _: Message) {
        self.0 += 1;
    }
    fn commit(&mut self, _: u64) {
        self.0 += 1;
    }
    fn send_snapshot(&mut self, _: u64) {
        self.0 += 1;
    }
}

/// The snapshot a replica recovers over: the store's latest, when the
/// log's commit reaches it (compacted below it, or installed at it). A
/// snapshot published past the commit is staged, not installed: the log
/// does not stand on it, and its install is retried.
fn recovered_over(
    log: &RaftLog<SimDisk>,
    store: &SnapshotStore<SimDisk>,
) -> Option<karyos_cluster::snapshot::SnapshotInfo> {
    let commit = log.hard_state().and_then(|state| state.commit).unwrap_or(0);
    store.latest().filter(|info| info.index <= commit)
}

/// Node 2 of three, its core recovered from what its log and store hold.
fn core(log: &RaftLog<SimDisk>, store: &SnapshotStore<SimDisk>) -> Core {
    let config = Config::new(2, &[1, 2, 3], 10, 20, 3, 4, 7).unwrap();
    let stored = log.hard_state();
    let term_vote = stored.map_or_else(TermVote::default, TermVote::from);
    let commit = stored.and_then(|state| state.commit).unwrap_or(0);
    let core = Core::new(config, term_vote, commit);
    match recovered_over(log, store) {
        Some(info) => core.with_snapshot(info.index, info.term),
        None => core,
    }
}

/// The state rebuilt from the store's latest snapshot and the log's
/// committed entries after it, up to `commit`.
fn rebuilt(
    log: &mut RaftLog<SimDisk>,
    store: &SnapshotStore<SimDisk>,
    commit: u64,
) -> Result<Vec<u8>, String> {
    let (mut state, from) = match recovered_over(log, store) {
        Some(info) => {
            store
                .verify(&info)
                .map_err(|error| format!("verify {}: {error}", info.index))?;
            let sections = store
                .read(&info)
                .map_err(|error| format!("read {}: {error}", info.index))?;
            let service = sections
                .into_iter()
                .find(|section| section.kind == SectionKind::Service)
                .ok_or("no service section")?;
            (service.bytes, info.index + 1)
        }
        None => (Vec::new(), 1),
    };
    if from <= commit {
        let entries = log
            .entries(from..commit + 1, u64::MAX)
            .map_err(|error| format!("entries {from}..={commit}: {error}"))?;
        if u64::try_from(entries.len()).unwrap() != commit + 1 - from {
            return Err(format!("entries {from}..={commit} not all held"));
        }
        for entry in entries {
            if entry.payload != payload(entry.index) {
                return Err(format!("entry {} is not the run's", entry.index));
            }
            state.push(entry.payload.first().copied().unwrap_or(0));
        }
    }
    Ok(state)
}

/// How far a run got before the crash.
#[derive(Debug, Default, Clone, Copy)]
struct Model {
    published: bool,
    logged: bool,
    told: bool,
}

/// One of the two sequences.
#[derive(Debug, Clone, Copy)]
enum Run {
    Install,
    Compaction,
}

impl Run {
    const BASE_INSTALL: u64 = 20;
    const BASE_COMPACT: u64 = 30;

    fn base(self) -> (u64, u64) {
        match self {
            Self::Install => (Self::BASE_INSTALL, 2),
            Self::Compaction => (Self::BASE_COMPACT, 1),
        }
    }

    /// The node before the sequence, on a clean disk: the operations it
    /// took.
    fn prepare(self, disk: &SimDisk) -> u64 {
        let mut log = RaftLog::create(disk.clone(), Path::new(LOG), geometry(), 1).unwrap();
        let (last, commit) = match self {
            Self::Install => (6, 3),
            Self::Compaction => (40, 40),
        };
        let _ = log
            .append(&(1..=last).map(|index| entry(index, 1)).collect::<Vec<_>>())
            .unwrap();
        let _ = log.sync().unwrap();
        log.save_hard_state(HardState {
            current_term: 1,
            voted_for: Some(1),
            commit: Some(commit),
        })
        .unwrap();
        drop(snapshots(disk.clone()).unwrap());
        disk.used()
    }

    /// The sequence, on a prepared disk.
    fn run(self, disk: &SimDisk) -> Model {
        let mut model = Model::default();
        let (base, term) = self.base();
        let Ok(mut store) = snapshots(disk.clone()) else {
            return model;
        };
        let Ok(opened) = RaftLog::open_with(disk.clone(), Path::new(LOG), geometry(), Some(&store))
        else {
            return model;
        };
        let mut log = opened.log;
        let mut core = core(&log, &store);
        if matches!(self, Self::Install) && core.can_install(base).is_err() {
            return model;
        }
        let service = state(base);
        if store
            .write(
                base,
                term,
                &[Section::new(SectionKind::Service, 1, &service)],
            )
            .is_err()
        {
            return model;
        }
        model.published = true;
        let logged = match self {
            Self::Install => log.install(base, term, &store),
            Self::Compaction => log.purge_prefix(base + 1).map(|_| ()),
        };
        if logged.is_err() {
            return model;
        }
        model.logged = true;
        let told = match self {
            Self::Install => core.install(base, term, &mut Sink::default()).is_ok(),
            Self::Compaction => core.compacted(base, term).is_ok(),
        };
        assert!(told, "the core refused its own sequence");
        model.told = true;
        if matches!(self, Self::Install)
            && (log.append(&[entry(base + 1, term)]).is_err() || log.sync().is_err())
        {
            return model;
        }
        model
    }

    /// Checks the invariant after `disk` crashed; whether the crash fell
    /// between the manifest and the log's record (point 4).
    fn check(self, disk: &SimDisk, survives: Survives, model: Model) -> Result<bool, String> {
        let (base, term) = self.base();
        let restarted = disk
            .after_crash(survives)
            .map_err(|error| error.to_string())?;
        let store = snapshots(restarted.clone())?;
        let opened = RaftLog::open_with(restarted, Path::new(LOG), geometry(), Some(&store))
            .map_err(|error| format!("open: {error}"))?;
        let mut log = opened.log;
        let latest = store.latest().map(|info| (info.index, info.term));
        // 1. What the log no longer holds, a verified snapshot covers.
        let floor = log.first_index().saturating_sub(1);
        if floor > latest.map_or(0, |(index, _)| index) {
            return Err(format!(
                "first index {} with the latest snapshot {latest:?}",
                log.first_index()
            ));
        }
        if latest.is_some_and(|latest| latest != (base, term)) {
            return Err(format!("another snapshot {latest:?}"));
        }
        if model.published && survives == Survives::Synced && latest.is_none() {
            return Err("a published snapshot is lost".into());
        }
        // 2. The state rebuilt is the run's, up to the recovered commit.
        let commit = log.hard_state().and_then(|state| state.commit).unwrap_or(0);
        let rebuilt = rebuilt(&mut log, &store, commit)?;
        if rebuilt != state(commit) {
            return Err(format!("the state up to {commit} is not the run's"));
        }
        // 3. The core recovers over it, and an unfinished install retries.
        let mut core = core(&log, &store);
        let installed = log.base() == Some((base, term));
        let over = recovered_over(&log, &store).map(|info| info.index);
        if core.commit() < commit || over.is_some_and(|index| core.commit() < index) {
            return Err(format!("the core recovered at commit {}", core.commit()));
        }
        let between = match self {
            Self::Install => {
                if model.logged && !installed && log.first_index() != 1 {
                    return Err("an install that returned is lost".into());
                }
                if installed {
                    if commit != base {
                        return Err(format!("installed with commit {commit}"));
                    }
                    if core.can_install(base) != Err(InstallError::Stale) {
                        return Err("an installed base admitted again".into());
                    }
                } else {
                    // Not installed: the store may hold the snapshot (the
                    // manifest was published), and the core's recovery
                    // over it already commits the base; the log, not yet.
                    if log.first_index() != 1 || log.last_index() != Some(6) {
                        return Err(format!(
                            "half installed: first {} last {:?}",
                            log.first_index(),
                            log.last_index()
                        ));
                    }
                    if core.can_install(base).is_err() {
                        return Err("an unfinished install is no longer admitted".into());
                    }
                    let mut store = store;
                    if latest.is_none() {
                        let _ = store
                            .write(
                                base,
                                term,
                                &[Section::new(SectionKind::Service, 1, &state(base))],
                            )
                            .map_err(|error| format!("retry write: {error}"))?;
                    }
                    log.install(base, term, &store)
                        .map_err(|error| format!("retry install: {error}"))?;
                    core.install(base, term, &mut Sink::default())
                        .map_err(|error| format!("retry core install: {error:?}"))?;
                }
                latest.is_some() && !installed
            }
            Self::Compaction => {
                if model.logged && survives == Survives::Synced && log.first_index() != base + 1 {
                    return Err(format!(
                        "a purge that returned is lost: {}",
                        log.first_index()
                    ));
                }
                if log.last_index() != Some(40) {
                    return Err(format!("compaction lost entries: {:?}", log.last_index()));
                }
                if latest.is_some() && core.snapshot_base() != (base, term) {
                    return Err(format!("the core's base {:?}", core.snapshot_base()));
                }
                latest.is_some() && log.first_index() == 1
            }
        };
        Ok(between)
    }
}

fn every_crash_point(run: Run) {
    let whole = SimDisk::new();
    let prepared = run.prepare(&whole);
    let model = run.run(&whole);
    assert!(model.told, "{run:?}: the run without a crash stopped early");
    let operations = whole.used() - prepared;
    let mut failures = Vec::new();
    let mut between = 0;
    for point in 0..=operations {
        let disk = SimDisk::with_budget(prepared + point);
        assert_eq!(run.prepare(&disk), prepared);
        let model = run.run(&disk);
        let mut modes = vec![Survives::Synced, Survives::Everything];
        for seed in scenarios::seeds() {
            let mixed = Rng::new(seed ^ point.rotate_left(32)).next_u64();
            modes.push(Survives::Subset { seed: mixed });
            modes.push(Survives::Torn { seed: mixed });
        }
        for survives in modes {
            match run.check(&disk, survives, model) {
                Ok(true) => between += 1,
                Ok(false) => {}
                Err(broken) => failures.push(format!(
                    "{run:?}: crash at operation {} under {survives:?}: {broken}",
                    point + 1
                )),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures over {} points:\n{}",
        failures.len(),
        operations + 1,
        failures.join("\n")
    );
    assert!(
        between > 0,
        "{run:?}: no crash point fell between the manifest and the log's record"
    );
}

#[test]
fn every_crash_point_of_an_install_through_the_core_recovers() {
    every_crash_point(Run::Install);
}

#[test]
fn every_crash_point_of_a_compaction_through_the_core_recovers() {
    every_crash_point(Run::Compaction);
}
