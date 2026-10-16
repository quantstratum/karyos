// SPDX-License-Identifier: Apache-2.0

//! The measurement plan (`quantstratum-docs:
//! karyos/design/measurement-harness.md` 5.4 and section 3): a point set
//! expanded into rounds of fresh process pairs, fixed before any run.
//!
//! - **Samples (8.1):** every run keeps exactly `N` measured messages
//!   after its warmup; `N` is fixed in the plan, at least 10^6 for a
//!   decision. A drop stays in the count as a +∞ sample (M-11).
//! - **Runs (8.2):** at least [`MIN_RUNS`] rounds per point.
//! - **Interleaving (6.2, H-2):** in round `r` every configuration runs
//!   once, in the configuration list rotated by `r`; `trusted` is in
//!   every round.
//! - **W5 and N (M-5b; coordinator decision, ACS 15286):** one W5
//!   sequence carries `k` messages (21 at `E_max` = 64), so a run sends
//!   `ceil(N / k)` sequences and [`keep_n`] expands their samples and
//!   drops the surplus, fewer than `k` samples, from the last sequence
//!   only. `N` is the manifest's `N` for every shape, so points stay
//!   comparable; [`PlannedRun::surplus`] records what was dropped.
//!
//! F2 waits for batch B3d and R5 for the key epochs of a profile; both
//! are listed as skipped with their cause, never left out.

use std::fmt::Write as _;
use std::time::Duration;

use crate::manifest::{Fanout, Load, MtuRule, Point, Shape};
use crate::wire::stage::{StageLoad, StageRun};
use crate::workloads::BenchError;

/// The fewest runs per point and configuration (manifest 8.2).
pub const MIN_RUNS: u32 = 5;

/// Measured messages per run for a decision (manifest 8.1).
pub const MESSAGES: u64 = 1_000_000;

/// Warmup messages per run (manifest 8.1).
pub const WARMUP: u64 = 100_000;

/// Measured messages per run of a smoke plan: never decision grade.
pub const SMOKE_MESSAGES: u64 = 2_000;

/// Warmup messages per run of a smoke plan.
pub const SMOKE_WARMUP: u64 = 200;

/// The label of a plan whose `N` is below [`MESSAGES`].
pub const INSUFFICIENT: &str = "insufficient samples";

/// The configurations of the A/A plan, all of the `trusted` profile:
/// the baseline and the two sides it compares (coordinator, ACS 15349).
/// Names follow the sample files' profile rule (no `/`).
pub const AA: [&str; 3] = ["trusted", "trusted-a", "trusted-b"];

/// The assumed cost of one R1 message, for the runtime estimate only.
const R1_ESTIMATE: Duration = Duration::from_micros(20);

/// The assumed cost of starting and draining one process pair.
const RUN_OVERHEAD: Duration = Duration::from_secs(1);

/// What a plan holds fixed for every run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOptions {
    /// Rounds per point.
    pub runs: u32,
    /// `N`, measured messages kept per run.
    pub messages: u64,
    /// Warmup messages per run.
    pub warmup: u64,
    /// `E_max`.
    pub e_max: u32,
    /// The MTU rule.
    pub rule: MtuRule,
    /// The configurations, in round 0 order.
    pub configurations: Vec<String>,
}

impl PlanOptions {
    /// The decision plan: [`MIN_RUNS`] rounds of `N` = [`MESSAGES`].
    #[must_use]
    pub fn decision(e_max: u32, rule: MtuRule) -> Self {
        Self {
            runs: MIN_RUNS,
            messages: MESSAGES,
            warmup: WARMUP,
            e_max,
            rule,
            configurations: AA.iter().map(ToString::to_string).collect(),
        }
    }

    /// The smoke plan (`KARYOS_MEASURE_SMOKE=1`): small `N`, labelled
    /// [`INSUFFICIENT`].
    #[must_use]
    pub fn smoke(e_max: u32, rule: MtuRule) -> Self {
        Self {
            messages: SMOKE_MESSAGES,
            warmup: SMOKE_WARMUP,
            ..Self::decision(e_max, rule)
        }
    }

    /// Whether runs of this plan can reach a decision at all.
    #[must_use]
    pub fn sufficient(&self) -> bool {
        self.messages >= MESSAGES && self.runs >= MIN_RUNS
    }
}

/// One run of the plan: one configuration of one point in one round, in
/// a fresh pair of processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRun {
    /// The point.
    pub point: Point,
    /// The round, from 0.
    pub round: u32,
    /// The configuration.
    pub configuration: String,
    /// What the processes run: `run.messages` is the sequence count.
    pub run: StageRun,
    /// Messages each sequence stands for (M-5b).
    pub messages_per_sample: u64,
    /// Expanded samples dropped from the last sequence to keep `N`.
    pub surplus: u64,
}

impl PlannedRun {
    /// A directory name for the run: point, configuration and round.
    #[must_use]
    pub fn slug(&self) -> String {
        let clean = |text: String| {
            text.chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect::<String>()
        };
        format!(
            "{}_{}_r{}",
            clean(self.point.to_string()),
            clean(self.configuration.clone()),
            self.round
        )
    }
}

/// An expanded plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The fixed options.
    pub options: PlanOptions,
    /// Every run, in execution order.
    pub runs: Vec<PlannedRun>,
    /// Points of the set that this harness cannot run yet, with why.
    pub skipped: Vec<(Point, String)>,
}

/// Why `point` cannot run yet; `None` when it can.
fn skip_reason(point: &Point) -> Option<&'static str> {
    if matches!(point.fanout, Fanout::F2 { .. }) {
        return Some("F2 pending batch B3d");
    }
    match point.load {
        Load::R1 | Load::R2 { .. } => None,
        Load::R5 { .. } => Some("R5 deferred: key epochs of a profile (5.4)"),
        Load::R3 | Load::R4 { .. } => Some("not a decision load"),
    }
}

/// Messages one sequence of `shape` stands for: the frames of a W5
/// datagram, one otherwise.
fn messages_per_sample(shape: Shape, e_max: u32, rule: MtuRule) -> Result<u64, BenchError> {
    if shape != Shape::W5 {
        return Ok(1);
    }
    let size = shape
        .size(e_max, rule)
        .map_err(|error| BenchError(format!("{shape}: {error}")))?;
    Ok(u64::from(size.frames_per_datagram))
}

/// Expands `points` under `options`.
///
/// # Errors
///
/// Fewer than [`MIN_RUNS`] rounds, no configuration, no `trusted`
/// configuration, `N` or `E_max` of zero, or a size error.
pub fn expand(points: &[Point], options: &PlanOptions) -> Result<Plan, BenchError> {
    if options.runs < MIN_RUNS {
        return Err(BenchError(format!(
            "{} rounds, at least {MIN_RUNS}",
            options.runs
        )));
    }
    if options.messages == 0 {
        return Err(BenchError("N of zero".into()));
    }
    if options.e_max == 0 {
        return Err(BenchError("E_max of zero".into()));
    }
    let count = options.configurations.len();
    if !options
        .configurations
        .iter()
        .any(|name| name.starts_with("trusted"))
    {
        return Err(BenchError("no trusted configuration in the round".into()));
    }
    let mut runs = Vec::new();
    let mut skipped = Vec::new();
    for point in points {
        if let Some(reason) = skip_reason(point) {
            skipped.push((*point, reason.to_string()));
            continue;
        }
        let load = match point.load {
            Load::R2 { rate } => StageLoad::Open {
                rate: u64::from(rate),
            },
            _ => StageLoad::Closed,
        };
        let per = messages_per_sample(point.shape, options.e_max, options.rule)?;
        let sequences = options.messages.div_ceil(per);
        // The warmup counts messages too (manifest 8.1): W5 warms up with
        // ceil(warmup / k) sequences.
        let warmup = options.warmup.div_ceil(per);
        let surplus = sequences
            .checked_mul(per)
            .and_then(|expanded| expanded.checked_sub(options.messages))
            .ok_or_else(|| BenchError("sequence count overflow".into()))?;
        for round in 0..options.runs {
            let shift = usize::try_from(round)
                .map_err(|_| BenchError("round".into()))?
                .checked_rem(count)
                .ok_or_else(|| BenchError("no configuration".into()))?;
            let mut order = options.configurations.clone();
            order.rotate_left(shift);
            for configuration in order {
                runs.push(PlannedRun {
                    point: *point,
                    round,
                    configuration,
                    run: StageRun {
                        shape: point.shape,
                        e_max: options.e_max,
                        rule: options.rule,
                        load,
                        messages: sequences,
                        warmup,
                    },
                    messages_per_sample: per,
                    surplus,
                });
            }
        }
    }
    Ok(Plan {
        options: options.clone(),
        runs,
        skipped,
    })
}

/// The estimated runtime of `plan`: R2 runs at their rate, R1 runs at an
/// assumed 20 µs per message, plus about a second per process pair;
/// `None` past what a `Duration` of nanoseconds holds.
#[must_use]
pub fn estimate(plan: &Plan) -> Option<Duration> {
    let mut nanos: u128 = 0;
    for planned in &plan.runs {
        let messages =
            u128::from(planned.run.messages).checked_add(u128::from(planned.run.warmup))?;
        let traffic = match planned.run.load {
            StageLoad::Open { rate } => messages
                .checked_mul(1_000_000_000)?
                .checked_div(u128::from(rate))?,
            StageLoad::Closed => messages.checked_mul(R1_ESTIMATE.as_nanos())?,
        };
        nanos = nanos
            .checked_add(traffic)?
            .checked_add(RUN_OVERHEAD.as_nanos())?;
    }
    u64::try_from(nanos).ok().map(Duration::from_nanos)
}

/// `plan` as text: options, runs per point, skipped points and the
/// estimated runtime.
#[must_use]
pub fn render(plan: &Plan) -> String {
    let options = &plan.options;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "plan: N {} warmup {} rounds {} E_max {} rule {:?} configurations {}",
        options.messages,
        options.warmup,
        options.runs,
        options.e_max,
        options.rule,
        options.configurations.join(" ")
    );
    if !options.sufficient() {
        let _ = writeln!(out, "label: {INSUFFICIENT}");
    }
    let mut points: Vec<Point> = plan.runs.iter().map(|run| run.point).collect();
    points.dedup();
    for point in &points {
        let runs: Vec<&PlannedRun> = plan.runs.iter().filter(|r| r.point == *point).collect();
        let first = runs.first();
        let _ = writeln!(
            out,
            "  {point}: {} runs, {} sequences each{}",
            runs.len(),
            first.map_or(0, |run| run.run.messages),
            first
                .filter(|run| run.messages_per_sample > 1)
                .map(|run| format!(
                    " of {} messages, surplus {}",
                    run.messages_per_sample, run.surplus
                ))
                .unwrap_or_default()
        );
    }
    for (point, reason) in &plan.skipped {
        let _ = writeln!(out, "  {point}: skipped, {reason}");
    }
    let _ = writeln!(
        out,
        "{} runs, estimated {} s",
        plan.runs.len(),
        estimate(plan).map_or_else(
            || "too long to state".to_string(),
            |d| d.as_secs().to_string()
        )
    );
    out
}

/// Exactly `n` per-message samples from per-sequence `samples`: each
/// repeated `per` times in order, the surplus cut from the last
/// sequence only (ACS 15286).
///
/// # Errors
///
/// Fewer expanded samples than `n`, or a surplus of `per` or more,
/// which would cut more than the last sequence.
pub fn keep_n(samples: &[u32], per: u64, n: u64) -> Result<Vec<u32>, BenchError> {
    let per = usize::try_from(per).map_err(|_| BenchError("messages per sample".into()))?;
    let n = usize::try_from(n).map_err(|_| BenchError("N".into()))?;
    let expanded = samples
        .len()
        .checked_mul(per)
        .ok_or_else(|| BenchError("expanded length".into()))?;
    let surplus = expanded
        .checked_sub(n)
        .ok_or_else(|| BenchError(format!("{expanded} samples, {n} needed")))?;
    if surplus >= per.max(1) {
        return Err(BenchError(format!(
            "surplus {surplus} spans more than the last sequence of {per}"
        )));
    }
    let mut kept = Vec::with_capacity(n);
    for sample in samples {
        for _ in 0..per {
            if kept.len() == n {
                return Ok(kept);
            }
            kept.push(*sample);
        }
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ILLUSTRATIVE_E_MAX, primary};

    fn decision() -> Plan {
        expand(
            &primary(),
            &PlanOptions::decision(ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope),
        )
        .unwrap()
    }

    #[test]
    fn the_primary_plan_runs_f1_and_lists_the_rest() {
        let plan = decision();
        // 8 F1 points of R1 and R2, 5 rounds, 3 configurations.
        assert_eq!(plan.runs.len(), 8 * 5 * 3);
        assert_eq!(plan.skipped.len(), 9);
        assert_eq!(
            plan.skipped
                .iter()
                .filter(|(_, reason)| reason.contains("B3d"))
                .count(),
            8
        );
        assert!(plan.skipped.iter().any(|(point, reason)| {
            matches!(point.load, Load::R5 { .. }) && reason.contains("deferred")
        }));
        assert!(plan.options.sufficient());
        assert!(!render(&plan).contains(INSUFFICIENT));
    }

    #[test]
    fn rounds_rotate_the_configurations() {
        let plan = decision();
        let first: Vec<(u32, &str)> = plan
            .runs
            .iter()
            .take(4)
            .map(|run| (run.round, run.configuration.as_str()))
            .collect();
        assert_eq!(
            first,
            [
                (0, "trusted"),
                (0, "trusted-a"),
                (0, "trusted-b"),
                (1, "trusted-a")
            ]
        );
        let mut three = PlanOptions::decision(ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope);
        three.configurations = vec!["trusted".into(), "x".into(), "y".into()];
        let plan = expand(&primary()[..1], &three).unwrap();
        let round2: Vec<&str> = plan
            .runs
            .iter()
            .filter(|run| run.round == 2)
            .map(|run| run.configuration.as_str())
            .collect();
        assert_eq!(round2, ["y", "trusted", "x"]);
    }

    #[test]
    fn w5_runs_ceil_n_over_k_sequences_and_records_the_surplus() {
        let plan = decision();
        let w5 = plan
            .runs
            .iter()
            .find(|run| run.point.shape == Shape::W5)
            .unwrap();
        assert_eq!(w5.messages_per_sample, 21);
        assert_eq!(w5.run.messages, 47_620);
        assert_eq!(w5.surplus, 20);
        // The warmup counts messages too: ceil(10^5 / 21) sequences.
        assert_eq!(w5.run.warmup, 4_762);
        let w1 = plan.runs.first().unwrap();
        assert_eq!((w1.run.messages, w1.surplus), (MESSAGES, 0));
    }

    #[test]
    fn keep_n_cuts_only_the_last_sequence() {
        assert_eq!(keep_n(&[1, 2, 3], 3, 7).unwrap(), [1, 1, 1, 2, 2, 2, 3]);
        assert_eq!(keep_n(&[1, 2], 1, 2).unwrap(), [1, 2]);
        // A missing message stays in the kept range as MISSING.
        let missing = crate::samples::MISSING;
        assert_eq!(keep_n(&[missing, 2], 2, 3).unwrap(), [missing, missing, 2]);
        assert!(keep_n(&[1, 2], 3, 7).is_err());
        assert!(keep_n(&[1, 2, 3], 3, 6).is_err());
    }

    #[test]
    fn a_plan_needs_five_rounds_and_trusted() {
        let mut options = PlanOptions::smoke(ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope);
        assert!(!options.sufficient());
        let plan = expand(&primary(), &options).unwrap();
        assert!(render(&plan).contains(INSUFFICIENT));
        options.runs = 4;
        assert!(expand(&primary(), &options).is_err());
        options.runs = 5;
        options.configurations = vec!["a".into(), "b".into()];
        assert!(expand(&primary(), &options).is_err());
    }
}
