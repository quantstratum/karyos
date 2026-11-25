// SPDX-License-Identifier: Apache-2.0

//! The C5 comparison's corpus runner (karyos#691; quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v1.md, Corpora): every case of
//! the given workloads, of one [`ConsensusCore`], over a range of seeds,
//! each run written as one JSON line of raw results, with a [`Summary`].
//!
//! - **Evidence.** Every line names what it is evidence of: [`Evidence`].
//!   A run of the `Reference` fixture, or of anything not named in the
//!   frozen manifest's run record, is [`Evidence::HarnessValidation`], and
//!   the field says so in the data, not only in documents. The runner
//!   writes where its caller tells it, never into the evaluation record.
//! - **A line** holds the evidence, the core, the workload, the case, the
//!   seed, the repetitions of the determinism mode, the client window
//!   ([`Case::window`]), the declared limits ([`Case::limits`]), the verdict ([`Verdict`]), whether the run ended
//!   at its step bound with clients still waiting, the case's fault
//!   schedule as `step:action`, what the case does not cover
//!   ([`Case::notes`]), the trace digest, and the error of a run that
//!   could not be set up or stepped.
//! - **Per-fault coverage** (manifest, Seed corpora): each line lists
//!   the faults its run applied, each with its step and whether it fell
//!   before the run's first leader commit, during replication, or after
//!   its last ([`Phase`]); the [`Summary`] counts the seeds of each fault
//!   kind per workload in each phase.
//! - **Named seeds** ([`NAMED_SEEDS`], 1 to 10 of the CI corpus) carry
//!   their run's full trace in their line, so the same schedules can be
//!   compared across variants and rerun by anyone.
//! - **Minimised traces.** A failing run's line carries its case shrunk
//!   ([`minimise`]): the schedule's faults removed one at a time, and then
//!   its steps halved, while the run still fails the same check under the
//!   same seed, with the shrunk run's schedule, steps and trace. The
//!   seed is kept: a schedule is only a function of its seed.

use std::io::Write;
use std::ops::RangeInclusive;

use std::collections::BTreeMap;

use super::core::ConsensusCore;
use super::workloads::{Case, Failed, Outcome, Phase, RunError, pass, run};

/// The named seeds of every fault (manifest, Failure schedules: seeds 1 to
/// 10 of the CI corpus): their lines carry their full trace.
pub const NAMED_SEEDS: RangeInclusive<u64> = 1..=10;

/// The most runs [`minimise`] spends on one failing run.
pub const MINIMISE_RUNS: u32 = 64;

/// What a run is evidence of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// A check of the harness and of the runner itself, never of a
    /// candidate: the `Reference` fixture, or a core not named in the
    /// manifest's run record.
    HarnessValidation,
    /// A run of a core version 2 of the C5 comparison names (`raft`,
    /// `openraft` and the custom core of ADR-0105; karyos#691): evidence
    /// once that version's run record names the commit it ran at.
    C5Version2,
}

impl Evidence {
    /// Its text in every line.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::HarnessValidation => "harness validation, not C5 evidence",
            Self::C5Version2 => "C5 version 2",
        }
    }
}

/// How one run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// It passed, every client finishing.
    Pass,
    /// It passed its safety and state checks, and progress stopped where
    /// the case allows it to.
    LivenessGap,
    /// It failed a check: [`Failed`]'s kind.
    Failed(&'static str),
    /// It could not be set up or stepped.
    Error,
    /// The case needs a capability the core does not have (a W2 case's
    /// limits): nothing was shown, so it neither passes nor fails.
    NotDemonstrated,
}

impl Verdict {
    /// Its name in a line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::LivenessGap => "liveness_gap",
            Self::Failed(kind) => kind,
            Self::Error => "error",
            Self::NotDemonstrated => "not_demonstrated",
        }
    }
}

/// The kind of a failed check, as a line names it.
const fn failed_kind(failed: &Failed) -> &'static str {
    match failed {
        Failed::Safety(_) => "failed_safety",
        Failed::Liveness(_) => "failed_liveness",
        Failed::Diverged(_) => "failed_diverged",
        Failed::NotReplayed => "failed_not_replayed",
        Failed::WrongState { .. } => "failed_wrong_state",
        Failed::NotBehind { .. } => "failed_not_behind",
        Failed::NotShown(_) => "failed_not_shown",
    }
}

/// What a corpus gave, per verdict, plus the failing runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// Runs.
    pub runs: u64,
    /// Runs that passed.
    pub passed: u64,
    /// Runs that passed with progress stopped where allowed.
    pub liveness_gaps: u64,
    /// Runs that ended at their step bound with clients waiting.
    pub step_bound: u64,
    /// Runs that failed a check, and their workload, case and seed.
    pub failed: Vec<(String, String, u64)>,
    /// Runs that could not be set up or stepped.
    pub errors: u64,
    /// Runs whose case needs a capability the core does not have.
    pub not_demonstrated: u64,
    /// Per workload and fault kind: the runs in which it fell before the
    /// first leader commit, during replication and after the last.
    pub coverage: BTreeMap<(String, String), [u64; 3]>,
}

/// A failing run's shrunk case: its schedule and steps, and its trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Minimised {
    /// The shrunk case.
    pub case: Case,
    /// Its run's trace.
    pub trace: Vec<String>,
}

/// The kind of check `case` fails under `seed`, if it fails one.
fn failing<C: ConsensusCore>(case: &Case, seed: u64) -> Option<(&'static str, Outcome)> {
    let outcome = run::<C>(case, seed).ok()?;
    match pass(case, &outcome) {
        Err(failed) => Some((failed_kind(&failed), outcome)),
        Ok(_) => None,
    }
}

/// Shrinks a case that fails check `kind` under `seed`: removes each
/// scheduled fault in turn, keeping a removal while the run still fails
/// `kind`, then halves the steps (never below the last fault's step) while
/// it still does; at most [`MINIMISE_RUNS`] runs. `None` when the case no
/// longer fails `kind` at all, which a deterministic run never does.
#[must_use]
pub fn minimise<C: ConsensusCore>(case: &Case, seed: u64, kind: &str) -> Option<Minimised> {
    let (_, mut outcome) = failing::<C>(case, seed).filter(|(got, _)| *got == kind)?;
    let mut shrunk = case.clone();
    let mut runs = 1u32;
    let mut at = 0;
    while at < shrunk.schedule.len() && runs < MINIMISE_RUNS {
        let mut candidate = shrunk.clone();
        let _ = candidate.schedule.remove(at);
        runs += 1;
        match failing::<C>(&candidate, seed) {
            Some((got, again)) if got == kind => {
                shrunk = candidate;
                outcome = again;
            }
            _ => at += 1,
        }
    }
    let floor = shrunk
        .schedule
        .iter()
        .map(|(step, _)| *step)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    while runs < MINIMISE_RUNS {
        let steps = shrunk.steps / 2;
        if steps < floor || steps == 0 {
            break;
        }
        let mut candidate = shrunk.clone();
        candidate.steps = steps;
        runs += 1;
        match failing::<C>(&candidate, seed) {
            Some((got, again)) if got == kind => {
                shrunk = candidate;
                outcome = again;
            }
            _ => break,
        }
    }
    Some(Minimised {
        case: shrunk,
        trace: outcome.trace,
    })
}

/// One workload: its name and its cases under a seed (W4's survival modes
/// are seeded).
pub type Workload<'a> = (&'a str, &'a dyn Fn(u64) -> Vec<Case>);

/// Runs every case of `workloads` of core `C`, named `core`, under each
/// seed of `seeds`, writing one JSON line per run to `out` as `evidence`.
/// With `repetitions` above 1, the determinism gate's mode (manifest,
/// Hard gates): each seed's run is repeated, and a repetition whose
/// outcome differs from the first's (trace, digest, history, states, any
/// of them) fails it as `failed_not_replayed`.
///
/// # Errors
///
/// The writer's error; a run's own error is a line, not an error.
pub fn run_corpus<C: ConsensusCore>(
    core: &str,
    evidence: Evidence,
    workloads: &[Workload<'_>],
    (seeds, repetitions): (RangeInclusive<u64>, u32),
    out: &mut impl Write,
) -> std::io::Result<Summary> {
    let mut summary = Summary::default();
    for seed in seeds {
        for (workload, cases) in workloads {
            for case in &cases(seed) {
                let mut faults = Vec::new();
                let mut trace = None;
                let (verdict, bound, digest, error) = match run::<C>(case, seed) {
                    Ok(outcome) => {
                        faults.clone_from(&outcome.faults);
                        if NAMED_SEEDS.contains(&seed) {
                            trace = Some(outcome.trace.clone());
                        }
                        let replayed = (1..repetitions)
                            .all(|_| run::<C>(case, seed).is_ok_and(|again| again == outcome));
                        let verdict = match pass(case, &outcome) {
                            _ if !replayed => Verdict::Failed(failed_kind(&Failed::NotReplayed)),
                            Ok(None) => Verdict::Pass,
                            Ok(Some(_)) => Verdict::LivenessGap,
                            Err(failed) => Verdict::Failed(failed_kind(&failed)),
                        };
                        (
                            verdict,
                            outcome.liveness.is_err(),
                            Some(outcome.digest),
                            None,
                        )
                    }
                    Err(RunError::Unsupported(_)) => (Verdict::NotDemonstrated, false, None, None),
                    Err(error) => (Verdict::Error, false, None, Some(format!("{error:?}"))),
                };
                summary.runs = summary.runs.saturating_add(1);
                match verdict {
                    Verdict::Pass => summary.passed = summary.passed.saturating_add(1),
                    Verdict::LivenessGap => {
                        summary.liveness_gaps = summary.liveness_gaps.saturating_add(1);
                    }
                    Verdict::Failed(_) => {
                        summary
                            .failed
                            .push(((*workload).to_owned(), case.name.clone(), seed));
                    }
                    Verdict::Error => summary.errors = summary.errors.saturating_add(1),
                    Verdict::NotDemonstrated => {
                        summary.not_demonstrated = summary
                            .not_demonstrated
                            .checked_add(1)
                            .ok_or_else(|| std::io::Error::other("run count overflow"))?;
                    }
                }
                if bound {
                    summary.step_bound = summary.step_bound.saturating_add(1);
                }
                for fault in &faults {
                    let slot = summary
                        .coverage
                        .entry(((*workload).to_owned(), fault.kind().to_owned()))
                        .or_default();
                    let at = match fault.phase {
                        Phase::BeforeFirstCommit => 0,
                        Phase::DuringReplication => 1,
                        Phase::AfterLastCommit => 2,
                    };
                    if let Some(count) = slot.get_mut(at) {
                        *count = count.saturating_add(1);
                    }
                }
                // A replay failure is the determinism gate's, not one a
                // shrunk schedule reproduces.
                let minimised = match verdict {
                    Verdict::Failed(kind) if kind != "failed_not_replayed" => {
                        minimise::<C>(case, seed, kind)
                    }
                    _ => None,
                };
                let line = Line {
                    evidence,
                    core,
                    workload,
                    case,
                    seed,
                    repetitions,
                    verdict,
                    bound,
                    digest,
                    error: error.as_deref(),
                    faults: &faults,
                    trace: trace.as_deref(),
                    minimised: minimised.as_ref(),
                };
                writeln!(out, "{}", line.json())?;
            }
        }
    }
    Ok(summary)
}

/// One run's raw result.
struct Line<'a> {
    evidence: Evidence,
    core: &'a str,
    workload: &'a str,
    case: &'a Case,
    seed: u64,
    repetitions: u32,
    verdict: Verdict,
    bound: bool,
    digest: Option<u64>,
    error: Option<&'a str>,
    faults: &'a [super::workloads::FaultPhase],
    trace: Option<&'a [String]>,
    minimised: Option<&'a Minimised>,
}

/// A schedule as JSON strings, `step:action`.
fn schedule_json(case: &Case) -> String {
    case.schedule
        .iter()
        .map(|(step, action)| string(&format!("{step}:{action:?}")))
        .collect::<Vec<_>>()
        .join(",")
}

/// A trace as a JSON array of strings.
fn trace(lines: &[String]) -> String {
    format!(
        "[{}]",
        lines
            .iter()
            .map(|line| string(line))
            .collect::<Vec<_>>()
            .join(",")
    )
}

impl Line<'_> {
    /// The line as one JSON object.
    fn json(&self) -> String {
        let schedule = schedule_json(self.case);
        let coverage: Vec<String> = self
            .faults
            .iter()
            .map(|fault| {
                format!(
                    "{{\"step\":{},\"fault\":{},\"phase\":{}}}",
                    fault.step,
                    string(&fault.fault),
                    string(fault.phase.name())
                )
            })
            .collect();
        let minimised = self.minimised.map_or_else(
            || "null".to_owned(),
            |shrunk| {
                format!(
                    "{{\"steps\":{},\"schedule\":[{}],\"trace\":{}}}",
                    shrunk.case.steps,
                    schedule_json(&shrunk.case),
                    trace(&shrunk.trace)
                )
            },
        );
        let notes: Vec<String> = self.case.notes.iter().map(|note| string(note)).collect();
        format!(
            "{{\"evidence\":{},\"core\":{},\"workload\":{},\"case\":{},\"seed\":{},\"repetitions\":{},\"window\":{},\"limits\":{},\"verdict\":{},\"step_bound\":{},\"steps\":{},\"schedule\":[{}],\"notes\":[{}],\"digest\":{},\"error\":{},\"coverage\":[{}],\"trace\":{},\"minimised\":{}}}",
            string(self.evidence.text()),
            string(self.core),
            string(self.workload),
            string(&self.case.name),
            self.seed,
            self.repetitions.max(1),
            self.case.window.max(1),
            self.case.limits.map_or_else(
                || "null".to_owned(),
                |limits| format!(
                    "{{\"in_flight_entries\":{},\"in_flight_bytes\":{},\"queue\":{},\"log_read_bytes\":{}}}",
                    limits.in_flight_entries,
                    limits.in_flight_bytes,
                    limits.queue,
                    limits.log_read_bytes
                ),
            ),
            string(self.verdict.name()),
            self.bound,
            self.case.steps,
            schedule,
            notes.join(","),
            self.digest
                .map_or_else(|| "null".to_owned(), |digest| digest.to_string()),
            self.error.map_or_else(|| "null".to_owned(), string),
            coverage.join(","),
            self.trace.map_or_else(|| "null".to_owned(), trace),
            minimised,
        )
    }
}

/// `text` as a JSON string.
fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests;
