// SPDX-License-Identifier: Apache-2.0

//! The Raft log of C4 (karyos-cluster) over C2's crashing disk
//! (quantstratum-docs: karyos/design/cluster-gap-analysis.md §6, C4): the
//! eight crash cases of the `log` module and three more truncations, each
//! run once per disk operation with the disk crashing at that operation
//! (and once after the last step), then reopened under every survival mode
//! of [`Survives`]: `Synced` and `Everything` once, `Subset` and `Torn` once
//! per seed of [`scenarios::seeds`]. The run without a crash must complete
//! every step, so no case is cut short by a refusal of its own.
//!
//! The invariant, checked by [`check`] at every crash point:
//!
//! 1. every entry the log reported durable before the crash is present,
//!    byte for byte, unless a truncation that removes it was in flight;
//! 2. nothing is claimed that was not written: every entry present is one
//!    the workload appended at that index and no truncation removed, and
//!    the reopened log claims no durable index past its last;
//! 3. the term and vote are the last saved record or the one in flight,
//!    never torn, so no vote is cast twice in a term;
//! 4. the stored commit is durable: every committed entry is present, as
//!    the log reported it durable;
//! 5. open never refuses a legitimate crash: it is `Ok`, a torn tail or a
//!    crash's loss above the watermark cut at most. Crash points whose
//!    recovery removes a segment its creation left without a data file
//!    (A2's `CreationGap`) are counted, and must open too.
//!
//! A failed flush ends a workload: the log is poisoned, the workload never
//! retries the flush or counts its data durable, and only a reopen goes
//! on.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    reason = "test helpers and per-case counts, as ADR-0007 allows in tests"
)]

use std::collections::BTreeMap;
use std::path::Path;

use karyos_archive::segment::{DropReason, Geometry, SegmentStore};
use karyos_cluster::{Corruption, Entry, HardState, LogError, RaftLog};
use karyos_sim::disk::{Decision, SimDisk, Survives};
use karyos_sim::rng::Rng;
use karyos_sim::scenarios;

const DIR: &str = "/raft";

/// 4 KiB segments, so entries of a few KiB span them.
fn geometry() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

fn entry(index: u64, term: u64, size: usize) -> Entry {
    let payload = (0..size)
        .map(|at| u8::try_from((at as u64 * 31 + index * 7 + term) % 251).unwrap())
        .collect();
    Entry {
        index,
        term,
        event_time: index * 1_000,
        payload,
    }
}

/// One step of a workload.
#[derive(Debug, Clone)]
enum Step {
    Append(Vec<Entry>),
    Sync,
    Truncate(u64),
    Save(HardState),
}

/// What the workload knew when the disk crashed or a call failed.
#[derive(Debug, Default, Clone)]
struct Model {
    /// The log was created: its first-index file and store exist.
    created: bool,
    /// Entries reported durable, by index.
    durable: BTreeMap<u64, Entry>,
    /// Every entry appended at each index, in any version.
    versions: BTreeMap<u64, Vec<Entry>>,
    /// The entries written now, by index.
    written: BTreeMap<u64, Entry>,
    /// A truncation in flight from this index: what it removes may be gone.
    truncating: Option<u64>,
    /// The last hard state saved.
    saved: Option<HardState>,
    /// The one being saved when the run stopped.
    saving: Option<HardState>,
    /// Every step ran and returned `Ok`.
    completed: bool,
}

/// Runs `steps` on a log created on `disk`, until the end, a crash or a
/// failed call; returns what it knew.
fn run(disk: SimDisk, steps: &[Step]) -> Model {
    let mut model = Model::default();
    let Ok(mut log) = RaftLog::create(disk, Path::new(DIR), geometry(), 1) else {
        return model;
    };
    model.created = true;
    for step in steps {
        match step {
            Step::Append(entries) => {
                for entry in entries {
                    model
                        .versions
                        .entry(entry.index)
                        .or_default()
                        .push(entry.clone());
                }
                let appended = log.append(entries);
                // Written in part or whole: the versions are known.
                if appended.is_err() {
                    return model;
                }
                for entry in entries {
                    let _ = model.written.insert(entry.index, entry.clone());
                }
            }
            Step::Sync => {
                let Ok(durable) = log.sync() else {
                    return model;
                };
                let durable = durable.unwrap_or(0);
                model.durable = model
                    .written
                    .range(..=durable)
                    .map(|(index, entry)| (*index, entry.clone()))
                    .collect();
            }
            Step::Truncate(from) => {
                model.truncating = Some(*from);
                if log.truncate_suffix(*from).is_err() {
                    return model;
                }
                model.truncating = None;
                let _ = model.written.split_off(from);
                let _ = model.durable.split_off(from);
                // What it removed must not come back.
                let _ = model.versions.split_off(from);
                // What is kept is durable on return.
                model.durable = model.written.clone();
            }
            Step::Save(state) => {
                model.saving = Some(*state);
                if log.save_hard_state(*state).is_err() {
                    return model;
                }
                model.saving = None;
                model.saved = Some(*state);
            }
        }
    }
    model.completed = true;
    model
}

/// How a case is swept.
#[derive(Debug, Clone, Copy)]
struct Sweep {
    /// The disk's tear unit; `None` for its default sector.
    sector: Option<u64>,
    /// Seeds swept besides [`scenarios::seeds`], whatever it selects.
    extra_seeds: &'static [u64],
}

impl Sweep {
    const DEFAULT: Self = Self {
        sector: None,
        extra_seeds: &[],
    };

    /// `disk` with this sweep's tear unit.
    fn disk(&self, disk: SimDisk) -> SimDisk {
        match self.sector {
            Some(sector) => disk.with_sector(sector),
            None => disk,
        }
    }

    /// The seeds swept, without repeats.
    fn seeds(&self) -> Vec<u64> {
        let mut seeds = scenarios::seeds();
        seeds.extend(self.extra_seeds);
        seeds.sort_unstable();
        seeds.dedup();
        seeds
    }
}

thread_local! {
    /// Crash points whose recovery removes a segment its creation left
    /// with no data file (A2's `CreationGap`), per test: they must open.
    static GAPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The invariant: `Ok` when the reopened log keeps it, else what broke.
fn check(disk: &SimDisk, survives: Survives, model: &Model) -> Result<(), String> {
    let restarted = disk
        .after_crash(survives)
        .map_err(|error| error.to_string())?;
    if let Ok(plan) = SegmentStore::verify(restarted.clone(), Path::new(DIR), 1, geometry())
        && plan
            .dropped
            .iter()
            .any(|dropped| dropped.reason == DropReason::CreationGap)
    {
        GAPS.with(|gaps| gaps.set(gaps.get() + 1));
    }
    let mut log = match RaftLog::open(restarted, Path::new(DIR), geometry()) {
        Ok(opened) => opened.log,
        Err(LogError::FirstIndex) if !model.created => {
            return Ok(());
        }
        Err(error) => return Err(format!("open refused: {error}")),
    };
    // 1. Durable entries are kept.
    for (index, entry) in &model.durable {
        if model.truncating.is_some_and(|from| *index >= from) {
            continue;
        }
        let found = log
            .entries(*index..index + 1, u64::MAX)
            .map_err(|e| e.to_string())?;
        if found.first() != Some(entry) {
            return Err(format!("durable entry {index} lost or changed"));
        }
    }
    // 2. Nothing is claimed that was not written.
    let last = log.last_index();
    if log.durable_index() != last {
        return Err(format!(
            "reopened durable {:?} differs from last {last:?}",
            log.durable_index()
        ));
    }
    if let Some(last) = last {
        for found in log
            .entries(1..last + 1, u64::MAX)
            .map_err(|e| e.to_string())?
        {
            let known = model
                .versions
                .get(&found.index)
                .is_some_and(|versions| versions.contains(&found));
            if !known {
                return Err(format!("entry {} was never appended", found.index));
            }
        }
    }
    // 3. The term and vote: the saved record or the one in flight.
    let state = log.hard_state();
    if state != model.saved && (model.saving.is_none() || state != model.saving) {
        return Err(format!(
            "hard state {state:?}, saved {:?}, saving {:?}",
            model.saved, model.saving
        ));
    }
    // 4. The commit is durable: every committed entry is present, as the
    // log reported it durable.
    if let Some(commit) = state.and_then(|state| state.commit) {
        let committed = log
            .entries(1..commit + 1, u64::MAX)
            .map_err(|e| e.to_string())?;
        if committed.len() as u64 != commit {
            return Err(format!("committed {commit}, but {} held", committed.len()));
        }
        for found in committed {
            if model
                .durable
                .get(&found.index)
                .is_some_and(|durable| *durable != found)
            {
                return Err(format!("committed entry {} changed", found.index));
            }
        }
    }
    Ok(())
}

/// Checks `disk` under every survival mode: the deterministic ones once,
/// the seeded ones once per seed (mixed with `point`, the crash point).
fn check_all(
    disk: &SimDisk,
    model: &Model,
    seeds: &[u64],
    point: u64,
    label: &dyn Fn(Survives) -> String,
    failures: &mut Vec<String>,
) {
    let mut modes = vec![Survives::Synced, Survives::Everything];
    for seed in seeds {
        let mixed = Rng::new(seed ^ point.rotate_left(32)).next_u64();
        modes.push(Survives::Subset { seed: mixed });
        modes.push(Survives::Torn { seed: mixed });
    }
    for survives in modes {
        if let Err(broken) = check(disk, survives, model) {
            failures.push(format!("{}: {broken}", label(survives)));
        }
    }
}

/// Runs `steps` with a crash at every disk operation in turn (and after
/// the last), then with every flush failing in turn; checks the invariant
/// under every survival mode. Returns the crash points and the failed
/// flushes run.
fn sweep(name: &str, steps: &[Step], how: Sweep) -> (u64, u64) {
    let (points, flushes, failures) = sweep_all(name, steps, how);
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    (points, flushes)
}

/// The call the disk crashed at.
fn crashed_at(disk: &SimDisk) -> &'static str {
    disk.trace()
        .iter()
        .find_map(|decision| match decision {
            Decision::Crash { call, .. } => Some(*call),
            _ => None,
        })
        .unwrap_or("after the last step")
}

/// [`sweep`], returning every broken check instead of the first.
fn sweep_all(name: &str, steps: &[Step], how: Sweep) -> (u64, u64, Vec<String>) {
    let mut failures = Vec::new();
    let seeds = how.seeds();
    // The full run must complete: a step that fails for a logic reason
    // would shorten every sweep below.
    let whole = how.disk(SimDisk::new());
    let model = run(whole.clone(), steps);
    assert!(
        model.completed,
        "{name}: the run without a crash stopped early"
    );
    let operations = whole.used();
    for budget in 0..=operations {
        let disk = how.disk(SimDisk::with_budget(budget));
        let model = run(disk.clone(), steps);
        if budget < operations {
            assert!(disk.has_crashed(), "{name}: budget {budget} did not crash");
        } else {
            assert!(
                model.completed,
                "{name}: the last crash point stopped early"
            );
        }
        let label = |survives| {
            format!(
                "{name}: crash at operation {} ({}) under {survives:?}",
                budget + 1,
                crashed_at(&disk)
            )
        };
        check_all(&disk, &model, &seeds, budget, &label, &mut failures);
    }
    // Each flush failing in turn, then a crash with what survives.
    let mut syncs = 0;
    loop {
        let next = syncs + 1;
        let disk = how.disk(SimDisk::new().with_failed_syncs([next]));
        let model = run(disk.clone(), steps);
        let failed = disk
            .trace()
            .iter()
            .any(|decision| matches!(decision, Decision::FailedSync { .. }));
        if !failed {
            break;
        }
        syncs = next;
        let label = |survives| format!("{name}: flush {next} failed, under {survives:?}");
        check_all(
            &disk,
            &model,
            &seeds,
            next.rotate_left(16),
            &label,
            &mut failures,
        );
    }
    (operations, syncs, failures)
}

fn appends(range: std::ops::Range<u64>, term: u64, size: usize) -> Step {
    Step::Append(range.map(|index| entry(index, term, size)).collect())
}

fn state(term: u64, vote: Option<u64>, commit: Option<u64>) -> Step {
    Step::Save(HardState {
        current_term: term,
        voted_for: vote,
        commit,
    })
}

/// Case 1: entries of 3 KiB over 4 KiB segments, each but the first
/// spanning two.
#[test]
fn case_1_an_append_spanning_segments() {
    let steps = [
        appends(1..2, 1, 3000),
        appends(2..4, 1, 3000),
        Step::Sync,
        appends(4..5, 1, 3000),
        Step::Sync,
    ];
    let (points, flushes) = sweep("case 1", &steps, Sweep::DEFAULT);
    println!(
        "case 1: {points} crash points, {flushes} failed flushes, {} creation gaps opened",
        GAPS.with(std::cell::Cell::get)
    );
}

/// Case 2: appends left unsynced between syncs.
#[test]
fn case_2_a_crash_between_append_and_sync() {
    let steps = [
        appends(1..4, 1, 200),
        Step::Sync,
        appends(4..7, 1, 200),
        appends(7..8, 2, 200),
    ];
    let (points, flushes) = sweep("case 2", &steps, Sweep::DEFAULT);
    println!(
        "case 2: {points} crash points, {flushes} failed flushes, {} creation gaps opened",
        GAPS.with(std::cell::Cell::get)
    );
}

/// Case 3: a truncation of synced entries, then the suffix again in a new
/// term.
#[test]
fn case_3_every_step_of_truncate() {
    let steps = [
        appends(1..6, 1, 900),
        Step::Sync,
        Step::Truncate(3),
        appends(3..5, 2, 900),
        Step::Sync,
    ];
    let (points, flushes) = sweep("case 3", &steps, Sweep::DEFAULT);
    println!(
        "case 3: {points} crash points, {flushes} failed flushes, {} creation gaps opened",
        GAPS.with(std::cell::Cell::get)
    );
}

/// Case 4: hard-state saves, a vote then a commit, each replacing the
/// record.
#[test]
fn case_4_every_step_of_a_hard_state_save() {
    let steps = [
        appends(1..3, 1, 100),
        Step::Sync,
        state(1, Some(2), None),
        state(2, Some(3), Some(1)),
        state(2, Some(3), Some(2)),
    ];
    let (points, flushes) = sweep("case 4", &steps, Sweep::DEFAULT);
    println!(
        "case 4: {points} crash points, {flushes} failed flushes, {} creation gaps opened",
        GAPS.with(std::cell::Cell::get)
    );
}

/// Case 5: a torn record. The hard state (44 bytes) and a watermark slot
/// (32) fit in one 512-byte sector, so this case tears at 8-byte sectors:
/// the torn survival mode keeps an 8-byte-aligned prefix of any write, the
/// record's and the slot's included, and a reordered writeback keeps a
/// rename without its data.
#[test]
fn case_5_a_torn_record() {
    let steps = [
        appends(1..3, 1, 100),
        Step::Sync,
        state(5, Some(1), None),
        appends(3..4, 1, 100),
        Step::Sync,
        state(6, None, None),
        state(6, Some(2), Some(2)),
    ];
    let (points, flushes) = sweep("case 5", &steps, TORN_SMALL);
    println!(
        "case 5: {points} crash points, {flushes} failed flushes, {} creation gaps opened",
        GAPS.with(std::cell::Cell::get)
    );
}

/// Case 6: every flush of a mixed workload fails in turn (the sweep's
/// second half), then the disk crashes with what was durable.
#[test]
fn case_6_a_failed_flush_of_the_log_or_the_hard_state() {
    let steps = [
        appends(1..3, 1, 2500),
        Step::Sync,
        state(1, Some(1), Some(1)),
        appends(3..5, 1, 2500),
        Step::Sync,
        state(1, Some(1), Some(4)),
    ];
    let (points, flushes) = sweep("case 6", &steps, Sweep::DEFAULT);
    assert!(flushes > 0);
    println!(
        "case 6: {points} crash points, {flushes} failed flushes, {} creation gaps opened",
        GAPS.with(std::cell::Cell::get)
    );
}

/// Case 7: commits saved after their entries are durable; the reopened
/// commit is never above the recovered log.
#[test]
fn case_7_a_reopened_commit_against_the_recovered_log() {
    let steps = [
        appends(1..4, 1, 700),
        Step::Sync,
        state(1, None, Some(3)),
        appends(4..8, 1, 700),
        Step::Sync,
        state(1, None, Some(7)),
        appends(8..9, 2, 700),
    ];
    let (points, flushes) = sweep("case 7", &steps, Sweep::DEFAULT);
    println!(
        "case 7: {points} crash points, {flushes} failed flushes, {} creation gaps opened",
        GAPS.with(std::cell::Cell::get)
    );
}

/// Seeds whose survival draws hit a creation gap in case 8, swept whatever
/// `KARYOS_SIM_SEED` selects, so its assertion does not depend on it.
const CASE_8: Sweep = Sweep {
    sector: None,
    extra_seeds: &[1, 3],
};

/// Tears at 8-byte sectors, so a 44-byte record and a 32-byte slot tear.
const TORN_SMALL: Sweep = Sweep {
    sector: Some(8),
    extra_seeds: &[],
};

/// Case 8: a crash inside `create`: the directory opens empty, or is
/// refused for its missing first index while the creation never ended.
#[test]
fn case_8_a_crash_inside_create() {
    let (points, flushes) = sweep("case 8", &[], CASE_8);
    assert!(
        GAPS.with(std::cell::Cell::get) > 0,
        "no crash point left a creation gap"
    );
    println!(
        "case 8: {points} crash points, {flushes} failed flushes, {} creation gaps opened",
        GAPS.with(std::cell::Cell::get)
    );
}

/// The other side of the invariant: a bit flip in an entry a sync
/// reported durable is refused at open, below the watermark, on the same
/// disk and workload that recover cleanly from every crash.
#[test]
fn a_flip_below_the_watermark_is_refused() {
    use karyos_archive::disk::Disk;

    let steps = [
        appends(1..4, 1, 900),
        Step::Sync,
        appends(4..6, 1, 900),
        Step::Sync,
    ];
    let disk = SimDisk::new();
    let model = run(disk.clone(), &steps);
    assert_eq!(model.durable.len(), 5);
    let mut restarted = disk.after_crash(Survives::Synced).unwrap();
    // A byte of entry 2's payload, in the first segment.
    let segment = Path::new(DIR).join(format!("{:016x}-{:016x}.seg", 1, 0));
    let file = restarted.open(&segment).unwrap();
    let mut byte = [0u8; 1];
    restarted.read_at(&file, 1000, &mut byte).unwrap();
    restarted.write_at(&file, 1000, &[byte[0] ^ 1]).unwrap();
    restarted.sync(&file).unwrap();
    match RaftLog::open(restarted, Path::new(DIR), geometry()) {
        Err(LogError::Corruption(Corruption::BelowMark { last, mark })) => {
            assert_eq!((last, mark), (Some(1), 5));
        }
        other => panic!("{other:?}"),
    }
}

/// Case 3 again at 8-byte sectors: the watermark's slots tear too, so a
/// torn newer slot must fall back to the older one.
#[test]
fn case_3_at_small_sectors() {
    let steps = [
        appends(1..6, 1, 900),
        Step::Sync,
        Step::Truncate(3),
        appends(3..5, 2, 900),
        Step::Sync,
    ];
    let (points, flushes) = sweep("case 3 small", &steps, TORN_SMALL);
    println!("case 3 at 8-byte sectors: {points} crash points, {flushes} failed flushes");
}

/// Case 9: truncating entries never synced, then appending again.
#[test]
fn case_9_truncating_unsynced_entries() {
    let steps = [
        appends(1..3, 1, 600),
        Step::Sync,
        appends(3..7, 1, 600),
        Step::Truncate(4),
        appends(4..6, 2, 600),
        Step::Sync,
    ];
    let (points, flushes) = sweep("case 9", &steps, Sweep::DEFAULT);
    println!("case 9: {points} crash points, {flushes} failed flushes");
}

/// Case 10: truncating to the first index, emptying the log, then filling
/// it again.
#[test]
fn case_10_truncating_to_the_first_index() {
    let steps = [
        appends(1..4, 1, 1500),
        Step::Sync,
        Step::Truncate(1),
        appends(1..3, 2, 1500),
        Step::Sync,
    ];
    let (points, flushes) = sweep("case 10", &steps, Sweep::DEFAULT);
    println!("case 10: {points} crash points, {flushes} failed flushes");
}

/// Case 11: saves mixed with truncation: a commit, a truncation above it,
/// a new vote carrying the commit, and a later commit.
#[test]
fn case_11_saves_mixed_with_truncation() {
    let steps = [
        appends(1..6, 1, 500),
        Step::Sync,
        state(1, Some(1), Some(2)),
        Step::Truncate(4),
        state(2, Some(2), Some(2)),
        appends(4..6, 2, 500),
        Step::Sync,
        state(2, Some(2), Some(5)),
    ];
    let (points, flushes) = sweep("case 11", &steps, Sweep::DEFAULT);
    println!("case 11: {points} crash points, {flushes} failed flushes");
}
