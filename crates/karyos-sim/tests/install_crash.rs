// SPDX-License-Identifier: Apache-2.0

//! Snapshot install and compaction through the custom Raft core
//! (karyos-cluster `consensus::Core`, ADR-0105) over C2's crashing disk,
//! at every manifest and truncation boundary (karyos#682): every disk
//! operation of the whole sequence, each reopened under every survival
//! mode.
//!
//! - **Install** (a follower of leader 1 in term 2, behind compaction):
//!   its log holds entries 1 to 6 of term 1, commit 3. It checks the
//!   core's admission, writes the leader's snapshot at 20 of term 2 to its
//!   store (sections, then the manifest that publishes it), installs it in
//!   its log (the first-index record, the watermark, the cut, the hard
//!   state's commit), tells the core, and releases the core's
//!   acknowledgement of 20. Then the leader's append of entry 21 is
//!   stepped through the core, written and synced, and its
//!   acknowledgement released.
//! - **Compaction** (a node at its commit): its log holds entries 1 to 40,
//!   commit 40. It writes a snapshot at 30 (manifest last), purges the log
//!   below 31 (A2's floor, then the first-index file) and tells the core.
//!
//! The invariant, at every crash point, for the replica rebuilt from its
//! store and log, its core recovered over the snapshot it stands on (the
//! newest its log's commit reaches; one past it is staged, not installed):
//!
//! 1. the log opens with its store, and every entry it no longer holds is
//!    covered by a verified snapshot;
//! 2. its commit, term and vote are the run's own (3 before the install,
//!    20 after it; 40 throughout the compaction), never fewer, and every
//!    entry it holds is the run's, uncommitted ones included;
//! 3. what was acknowledged survives: after a synced crash, a released
//!    acknowledgement of 20 means the log is installed, and one of 21
//!    means it holds entry 21;
//! 4. an install not finished is still admitted, and a retry over the
//!    staged snapshot completes it;
//! 5. under an Archive hold applied before the reopen, an open that would
//!    finish removing committed bytes (the install's frames, the purge's
//!    segments) refuses, typed, and changes no file;
//! 6. the boundaries are hit, on synced images read before any reopen
//!    repairs them: the manifest durable with the log's old record; the
//!    install's record durable with its frames still present; A2's floor
//!    durable with the old first-index file.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_archive::control::HoldState;
use karyos_archive::disk::Disk;
use karyos_archive::segment::{DropReason, Geometry, SegmentStore};
use karyos_cluster::consensus::{
    AppendOutcome, Config, Core, Effects, InstallError, LogTerms, Message, TermVote,
};
use karyos_cluster::hard_state::HardState;
use karyos_cluster::log::{FIRST_INDEX_FILE, LOG_RECORDING};
use karyos_cluster::snapshot::{Section, SectionKind, SnapshotConfig, SnapshotInfo, SnapshotStore};
use karyos_cluster::{Entry, LogError, RaftLog};
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::rng::Rng;
use karyos_sim::scenarios;

const LOG: &str = "/raft";
const SNAPSHOTS: &str = "/snap";
const LEADER: u64 = 1;
const TERM: u64 = 2;

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

/// What the core asked for.
#[derive(Default)]
struct Sink {
    persisted: bool,
    writes: Vec<(u64, u64)>,
    after: Vec<(u64, Message)>,
}

impl Effects for Sink {
    fn persist(&mut self, _: TermVote) {
        self.persisted = true;
    }
    fn write(&mut self, index: u64, skip: u64) {
        self.writes.push((index, skip));
    }
    fn append(&mut self, _: u64, _: u64) {}
    fn send(&mut self, _: u64, _: Message) {}
    fn send_after_persist(&mut self, to: u64, message: Message) {
        self.after.push((to, message));
    }
    fn commit(&mut self, _: u64) {}
    fn send_snapshot(&mut self, _: u64) {}
}

impl Sink {
    /// The index an acknowledgement to the leader names, if one waits.
    fn acknowledged(&self) -> Option<u64> {
        self.after.iter().find_map(|(to, message)| match message {
            Message::AppendReply {
                outcome: AppendOutcome::Accepted { index },
                ..
            } if *to == LEADER => Some(*index),
            _ => None,
        })
    }
}

/// The core's view of the log, with the base the log keeps.
struct Terms<'a>(&'a RaftLog<SimDisk>);

impl LogTerms for Terms<'_> {
    fn last_index(&self) -> u64 {
        self.0
            .last_index()
            .or_else(|| self.0.base().map(|(index, _)| index))
            .unwrap_or(0)
    }

    fn term(&self, index: u64) -> Option<u64> {
        if index == 0 {
            return Some(0);
        }
        self.0.term(index)
    }

    fn size(&self, index: u64) -> Option<u64> {
        self.0.term(index).map(|_| 600)
    }
}

/// The snapshot a replica stands on: the newest its log's commit reaches.
fn active(log: &RaftLog<SimDisk>, store: &SnapshotStore<SimDisk>) -> Option<SnapshotInfo> {
    let commit = log.hard_state().and_then(|state| state.commit).unwrap_or(0);
    store
        .snapshots()
        .iter()
        .rev()
        .find(|info| info.index <= commit)
        .copied()
}

/// Node 2 of three, its core recovered from what its log and store hold.
fn core(log: &RaftLog<SimDisk>, store: &SnapshotStore<SimDisk>) -> Core {
    let config = Config::new(2, &[1, 2, 3], 10, 20, 3, 4, 7).unwrap();
    let stored = log.hard_state();
    let term_vote = stored.map_or_else(TermVote::default, TermVote::from);
    let commit = stored.and_then(|state| state.commit).unwrap_or(0);
    let core = Core::new(config, term_vote, commit);
    match active(log, store) {
        Some(info) => core.with_snapshot(info.index, info.term),
        None => core,
    }
}

/// A heartbeat of the leader at `prev`, which the follower then follows.
fn follow(core: &mut Core, log: &RaftLog<SimDisk>, prev: (u64, u64), commit: u64) -> Sink {
    let mut sink = Sink::default();
    let heartbeat = Message::Append {
        term: TERM,
        prev_index: prev.0,
        prev_term: prev.1,
        entries: 0,
        commit,
        epoch: 1,
    };
    core.step(LEADER, heartbeat, &[], &Terms(log), &mut sink)
        .unwrap();
    sink
}

/// The bytes of every file under `dir`, by name, read raw: an image to
/// compare, changing nothing.
fn image(disk: &SimDisk, dir: &str) -> Vec<(String, Vec<u8>)> {
    let mut disk = disk.clone();
    let mut names = disk.list(Path::new(dir)).unwrap_or_default();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let path = Path::new(dir).join(&name);
            let bytes = disk
                .open_read(&path)
                .and_then(|file| {
                    let len = disk.len(&file)?;
                    let mut bytes = vec![0; usize::try_from(len).unwrap()];
                    disk.read_at(&file, 0, &mut bytes)?;
                    Ok(bytes)
                })
                .unwrap_or_default();
            (name, bytes)
        })
        .collect()
}

/// A file's raw bytes.
fn raw(disk: &SimDisk, dir: &str, name: &str) -> Vec<u8> {
    image(disk, dir)
        .into_iter()
        .find(|(file, _)| file == name)
        .map(|(_, bytes)| bytes)
        .unwrap_or_default()
}

/// How far a run got before the crash.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Model {
    published: bool,
    logged: bool,
    told: bool,
    /// The core's acknowledgement of the base was released.
    acked_base: bool,
    /// Entry 21 was appended and synced, and its acknowledgement released.
    acked_next: bool,
}

/// What a synced image showed before any reopen repaired it.
#[derive(Debug, Default)]
struct Boundaries {
    manifest_before_record: u64,
    record_before_cut: u64,
    floor_before_first_index: u64,
    held_refusals: u64,
}

/// One of the two sequences.
#[derive(Debug, Clone, Copy)]
enum Run {
    Install,
    Compaction,
}

/// The prepared node's first-index file and log bytes, raw.
struct Prepared {
    used: u64,
    first_index: Vec<u8>,
    written: u64,
}

impl Run {
    fn base(self) -> (u64, u64) {
        match self {
            Self::Install => (20, TERM),
            Self::Compaction => (30, 1),
        }
    }

    /// The commit the run's log holds: before and after its record.
    const fn commits(self) -> (u64, u64) {
        match self {
            Self::Install => (3, 20),
            Self::Compaction => (40, 40),
        }
    }

    /// The node before the sequence, on a clean disk.
    fn prepare(self, disk: &SimDisk) -> Prepared {
        let mut log = RaftLog::create(disk.clone(), Path::new(LOG), geometry(), 1).unwrap();
        let last = match self {
            Self::Install => 6,
            Self::Compaction => 40,
        };
        let _ = log
            .append(&(1..=last).map(|index| entry(index, 1)).collect::<Vec<_>>())
            .unwrap();
        let _ = log.sync().unwrap();
        log.save_hard_state(HardState {
            current_term: TERM,
            voted_for: Some(LEADER),
            commit: Some(self.commits().0),
        })
        .unwrap();
        drop(log);
        drop(snapshots(disk.clone()).unwrap());
        let written = SegmentStore::<SimDisk>::verify(
            disk.clone(),
            Path::new(LOG),
            LOG_RECORDING,
            geometry(),
        )
        .unwrap()
        .kept
        .unwrap()
        .written;
        Prepared {
            used: disk.used(),
            first_index: raw(disk, LOG, FIRST_INDEX_FILE),
            written,
        }
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
        if matches!(self, Self::Install) {
            let _ = follow(&mut core, &log, (0, 0), 0);
            if core.can_install(base).is_err() {
                return model;
            }
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
            Self::Install => log.install_under(base, term, &store, &HoldState::None),
            Self::Compaction => log
                .purge_prefix_under(base + 1, &HoldState::None)
                .map(|_| ()),
        };
        if logged.is_err() {
            return model;
        }
        model.logged = true;
        let mut sink = Sink::default();
        let told = match self {
            Self::Install => core.install(base, term, &mut sink).is_ok(),
            Self::Compaction => core.compacted(base, term).is_ok(),
        };
        assert!(told, "the core refused its own sequence");
        model.told = true;
        if matches!(self, Self::Compaction) {
            return model;
        }
        // The install is durable: its acknowledgement is released.
        assert_eq!(
            sink.acknowledged(),
            Some(base),
            "no acknowledgement of the base"
        );
        model.acked_base = true;
        // The leader's next entry, through the core.
        let mut sink = Sink::default();
        let append = Message::Append {
            term: TERM,
            prev_index: base,
            prev_term: term,
            entries: 1,
            commit: base,
            epoch: 1,
        };
        core.step(LEADER, append, &[TERM], &Terms(&log), &mut sink)
            .unwrap();
        assert_eq!(sink.writes, vec![(base + 1, 0)], "the core asks for 21");
        if log.append(&[entry(base + 1, TERM)]).is_err() || log.sync().is_err() {
            return model;
        }
        assert_eq!(sink.acknowledged(), Some(base + 1));
        model.acked_next = true;
        model
    }

    /// Checks the invariant after `disk` crashed.
    fn check(
        self,
        disk: &SimDisk,
        prepared: &Prepared,
        survives: Survives,
        model: Model,
        seen: &mut Boundaries,
    ) -> Result<(), String> {
        let (base, term) = self.base();
        let restarted = disk
            .after_crash(survives)
            .map_err(|error| error.to_string())?;
        // 6. The synced image, before any reopen repairs it.
        let store = snapshots(restarted.clone())?;
        let first_raw = raw(&restarted, LOG, FIRST_INDEX_FILE);
        let plan = SegmentStore::<SimDisk>::verify(
            restarted.clone(),
            Path::new(LOG),
            LOG_RECORDING,
            geometry(),
        )
        .map_err(|error| format!("verify: {error}"))?;
        let old_record = first_raw == prepared.first_index;
        let frames_kept = plan
            .kept
            .is_some_and(|kept| kept.written == prepared.written);
        let purging = plan
            .dropped
            .iter()
            .any(|dropped| dropped.reason == DropReason::Purged);
        let floor_moved = plan.kept.is_some_and(|kept| kept.start > 0);
        if survives == Survives::Synced {
            match self {
                Self::Install => {
                    if store.latest().is_some() && old_record {
                        seen.manifest_before_record += 1;
                    }
                    if !old_record && frames_kept {
                        seen.record_before_cut += 1;
                    }
                }
                Self::Compaction => {
                    if store.latest().is_some() && old_record && !floor_moved {
                        seen.manifest_before_record += 1;
                    }
                    if floor_moved && old_record {
                        seen.floor_before_first_index += 1;
                    }
                }
            }
        }
        // 5. A hold applied before the reopen: an open that would finish
        // removing committed bytes refuses and changes no file.
        let removing = match self {
            Self::Install => !old_record && frames_kept && prepared.written > 0,
            Self::Compaction => purging,
        };
        if removing {
            let before = (image(&restarted, LOG), image(&restarted, SNAPSHOTS));
            let held = RaftLog::open_with_under(
                restarted.clone(),
                Path::new(LOG),
                geometry(),
                Some(&store),
                &HoldState::Held,
            );
            if !matches!(
                held,
                Err(LogError::ArchiveHeld {
                    state: HoldState::Held
                })
            ) {
                return Err(format!("opened through a hold: {:?}", held.map(|_| ())));
            }
            if (image(&restarted, LOG), image(&restarted, SNAPSHOTS)) != before {
                return Err("a refused open changed a file".into());
            }
            seen.held_refusals += 1;
        }
        let opened = RaftLog::open_with(restarted, Path::new(LOG), geometry(), Some(&store))
            .map_err(|error| format!("open: {error}"))?;
        let mut log = opened.log;
        let latest = store.latest().map(|info| (info.index, info.term));
        if latest.is_some_and(|latest| latest != (base, term)) {
            return Err(format!("another snapshot {latest:?}"));
        }
        if model.published && survives == Survives::Synced && latest.is_none() {
            return Err("a published snapshot is lost".into());
        }
        // 1. What the log no longer holds, a verified snapshot covers.
        let floor = log.first_index().saturating_sub(1);
        if floor > active(&log, &store).map_or(0, |info| info.index) {
            return Err(format!(
                "first index {} over the active snapshot {:?}",
                log.first_index(),
                active(&log, &store)
            ));
        }
        // 2. The run's own commit, term and vote, and its entries.
        let stored = log.hard_state().ok_or("no hard state")?;
        let installed = log.base() == Some((base, term));
        let (before, after) = self.commits();
        let expected = match self {
            Self::Install if installed => after,
            Self::Install => before,
            Self::Compaction => before,
        };
        if stored.commit != Some(expected) {
            return Err(format!("commit {:?}, not {expected}", stored.commit));
        }
        if (stored.current_term, stored.voted_for) != (TERM, Some(LEADER)) {
            return Err(format!("term and vote {stored:?}"));
        }
        // An installed log with no entry after its base ends at the base.
        let last = log
            .last_index()
            .unwrap_or_else(|| log.first_index().saturating_sub(1));
        for index in log.first_index()..=last {
            let held = log
                .entries(index..index + 1, u64::MAX)
                .map_err(|error| format!("entry {index}: {error}"))?;
            let want_term = if matches!(self, Self::Install) && index > base {
                TERM
            } else {
                1
            };
            if held != vec![entry(index, want_term)] {
                return Err(format!("entry {index} is not the run's"));
            }
        }
        let rebuilt = {
            let mut state = match active(&log, &store) {
                Some(info) => {
                    store
                        .verify(&info)
                        .map_err(|error| format!("verify: {error}"))?;
                    store
                        .read(&info)
                        .map_err(|error| format!("read: {error}"))?
                        .into_iter()
                        .find(|section| section.kind == SectionKind::Service)
                        .ok_or("no service section")?
                        .bytes
                }
                None => Vec::new(),
            };
            let from = active(&log, &store).map_or(1, |info| info.index + 1);
            for index in from..=expected {
                state.push(payload(index)[0]);
            }
            state
        };
        if rebuilt != state(expected) {
            return Err(format!("the state up to {expected} is not the run's"));
        }
        let mut core = core(&log, &store);
        if core.commit() != expected {
            return Err(format!("the core recovered at {}", core.commit()));
        }
        // 3. What was acknowledged survives a synced crash.
        if survives == Survives::Synced {
            if model.acked_base && !installed {
                return Err("an acknowledged install is lost".into());
            }
            if model.logged && matches!(self, Self::Install) && !installed {
                return Err("an install that returned is lost".into());
            }
            if model.acked_next && last != base + 1 {
                return Err("an acknowledged entry 21 is lost".into());
            }
            if model.logged && matches!(self, Self::Compaction) && log.first_index() != base + 1 {
                return Err(format!(
                    "a purge that returned is lost: {}",
                    log.first_index()
                ));
            }
        }
        match self {
            Self::Install if installed => {
                if core.can_install(base) != Err(InstallError::Stale) {
                    return Err("an installed base admitted again".into());
                }
                if !matches!(last, 20 | 21) {
                    return Err(format!("installed holding up to {last}"));
                }
            }
            Self::Install => {
                // 4. Not installed: its old log whole, and a retry over the
                // staged snapshot completes the install.
                if (log.first_index(), last) != (1, 6) {
                    return Err(format!("half installed: {} to {last}", log.first_index()));
                }
                let _ = follow(&mut core, &log, (6, 1), 3);
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
                log.install_under(base, term, &store, &HoldState::None)
                    .map_err(|error| format!("retry install: {error}"))?;
                let mut sink = Sink::default();
                core.install(base, term, &mut sink)
                    .map_err(|error| format!("retry core install: {error:?}"))?;
                if sink.acknowledged() != Some(base) {
                    return Err("the retried install is not acknowledged".into());
                }
            }
            Self::Compaction => {
                if last != 40 {
                    return Err(format!("compaction lost entries: {last}"));
                }
                if latest.is_some() && core.snapshot_base() != (base, term) {
                    return Err(format!("the core's base {:?}", core.snapshot_base()));
                }
            }
        }
        Ok(())
    }
}

fn every_crash_point(run: Run) {
    let whole = SimDisk::new();
    let prepared = run.prepare(&whole);
    let model = run.run(&whole);
    let complete = match run {
        Run::Install => model.acked_next,
        Run::Compaction => model.told,
    };
    assert!(
        complete,
        "{run:?}: the run without a crash stopped early: {model:?}"
    );
    let operations = whole.used() - prepared.used;
    assert!(operations > 0);
    let mut failures = Vec::new();
    let mut seen = Boundaries::default();
    for point in 0..=operations {
        let disk = SimDisk::with_budget(prepared.used + point);
        let again = run.prepare(&disk);
        assert_eq!(again.used, prepared.used);
        let model = run.run(&disk);
        // Each budgeted run hits its fault; the last one completes.
        if point < operations {
            assert!(disk.has_crashed(), "{run:?}: point {point} never faulted");
        }
        let mut modes = vec![Survives::Synced, Survives::Everything];
        for seed in scenarios::seeds() {
            let mixed = Rng::new(seed ^ point.rotate_left(32)).next_u64();
            modes.push(Survives::Subset { seed: mixed });
            modes.push(Survives::Torn { seed: mixed });
        }
        for survives in modes {
            if let Err(broken) = run.check(&disk, &prepared, survives, model, &mut seen) {
                failures.push(format!(
                    "{run:?}: crash at operation {} under {survives:?}: {broken}",
                    point + 1
                ));
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
    assert!(seen.manifest_before_record > 0, "{run:?}: {seen:?}");
    match run {
        Run::Install => assert!(seen.record_before_cut > 0, "{run:?}: {seen:?}"),
        Run::Compaction => assert!(seen.floor_before_first_index > 0, "{run:?}: {seen:?}"),
    }
    assert!(seen.held_refusals > 0, "{run:?}: {seen:?}");
}

#[test]
fn every_crash_point_of_an_install_through_the_core_recovers() {
    every_crash_point(Run::Install);
}

#[test]
fn every_crash_point_of_a_compaction_through_the_core_recovers() {
    every_crash_point(Run::Compaction);
}
