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
//!   seed, the verdict ([`Verdict`]), whether the run ended at its step
//!   bound with clients still waiting, the case's fault schedule as
//!   `step:action`, the trace digest, and the error of a run that could
//!   not be set up or stepped.
//! - **Not yet.** Per-fault coverage (before the first commit, during
//!   replication, after the last commit) and the minimised traces of
//!   failing seeds (manifest, Corpora) need commit times in steps, which
//!   the observations do not carry; a later step adds them. Until then a
//!   failing seed is listed with its case, and its full trace is the
//!   run's to rebuild from the seed.

use std::io::Write;
use std::ops::RangeInclusive;

use super::core::ConsensusCore;
use super::workloads::{Case, Failed, pass, run};

/// What a run is evidence of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// A check of the harness and of the runner itself, never of a
    /// candidate: the `Reference` fixture, or a core not named in the
    /// manifest's run record.
    HarnessValidation,
}

impl Evidence {
    /// Its text in every line.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::HarnessValidation => "harness validation, not C5 evidence",
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
}

/// One workload: its name and its cases under a seed (W4's survival modes
/// are seeded).
pub type Workload<'a> = (&'a str, &'a dyn Fn(u64) -> Vec<Case>);

/// Runs every case of `workloads` of core `C`, named `core`, under each
/// seed of `seeds`, writing one JSON line per run to `out` as `evidence`.
///
/// # Errors
///
/// The writer's error; a run's own error is a line, not an error.
pub fn run_corpus<C: ConsensusCore>(
    core: &str,
    evidence: Evidence,
    workloads: &[Workload<'_>],
    seeds: RangeInclusive<u64>,
    out: &mut impl Write,
) -> std::io::Result<Summary> {
    let mut summary = Summary::default();
    for seed in seeds {
        for (workload, cases) in workloads {
            for case in &cases(seed) {
                let (verdict, bound, digest, error) = match run::<C>(case, seed) {
                    Ok(outcome) => {
                        let verdict = match pass(case, &outcome) {
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
                }
                if bound {
                    summary.step_bound = summary.step_bound.saturating_add(1);
                }
                let line = Line {
                    evidence,
                    core,
                    workload,
                    case,
                    seed,
                    verdict,
                    bound,
                    digest,
                    error: error.as_deref(),
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
    verdict: Verdict,
    bound: bool,
    digest: Option<u64>,
    error: Option<&'a str>,
}

impl Line<'_> {
    /// The line as one JSON object.
    fn json(&self) -> String {
        let schedule: Vec<String> = self
            .case
            .schedule
            .iter()
            .map(|(step, action)| string(&format!("{step}:{action:?}")))
            .collect();
        format!(
            "{{\"evidence\":{},\"core\":{},\"workload\":{},\"case\":{},\"seed\":{},\"verdict\":{},\"step_bound\":{},\"steps\":{},\"schedule\":[{}],\"digest\":{},\"error\":{}}}",
            string(self.evidence.text()),
            string(self.core),
            string(self.workload),
            string(&self.case.name),
            self.seed,
            string(self.verdict.name()),
            self.bound,
            self.case.steps,
            schedule.join(","),
            self.digest
                .map_or_else(|| "null".to_owned(), |digest| digest.to_string()),
            self.error.map_or_else(|| "null".to_owned(), string),
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
