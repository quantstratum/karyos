// SPDX-License-Identifier: Apache-2.0

//! Decision rules of manifest sections 7 and 8
//! (`quantstratum-docs: karyos/design/wire-threat-model-manifest.md`;
//! `karyos/design/measurement-harness.md` 3 and 5.4).
//!
//! - Per point: drops (M-11), saturation, the CV gate (8.4, per
//!   configuration) and the environment (8.8) can make a point Not
//!   demonstrated; otherwise the point is a win, a loss or a tie (8.5).
//! - Overall (8.6): over the primary points of the decision set, never
//!   averaged, labelled `incomplete` while any of them is not demonstrated
//!   (H-4, ACS 14817). F2 points stay reported only until P2.7 (M-6).
//! - Tie breakers (8.7) as data, the gate table (7) defaulting to Not
//!   demonstrated, and the decision grade, which refuses a decision label
//!   for a provisional `E_max` (M-7) among other conditions.
//!
//! Side `A` and side `B` are the two candidate profiles of a comparison.
//! The lower added latency wins.

use std::fmt;

use crate::manifest::{
    EMax, Fanout, MtuRule, Point, Shape, max_message_length_64k, primary, section8,
};
use crate::samples;
use crate::stats::{self, BootstrapSpec, Estimate, PointBootstrap, Resampling, StatsError, Value};

/// The environments of manifest 6.3. Full classification is batch B2; this
/// is the hook of 8.8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Environment {
    /// Physical Linux host, x86_64: the decision metric.
    E1,
    /// Two physical Linux hosts on one switch: round trip and fan-out.
    E2,
    /// aarch64: reported as Not demonstrated in this version (Q-5).
    E3,
    /// macOS workspace and Linux VMs: functional only, never decides.
    E4,
}

impl Environment {
    /// Whether a result from this environment may decide (6.3, 8.8).
    #[must_use]
    pub const fn decides(self) -> bool {
        matches!(self, Self::E1 | Self::E2)
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::E1 => "E1",
            Self::E2 => "E2",
            Self::E3 => "E3",
            Self::E4 => "E4",
        })
    }
}

/// One side of a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    /// Profile `a`.
    A,
    /// Profile `b`.
    B,
}

/// Why a point is not demonstrated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// More than 0.1% of one run's messages were dropped, so its p99.9 is
    /// infinite (coordinator M-11, ACS 14828). The gate applies to each
    /// run, not to the pooled configuration (review of #186, P3).
    Drops {
        /// The configuration.
        profile: String,
        /// The run index.
        run: usize,
        /// Missing messages in the run.
        missing: u64,
        /// All messages of the run.
        total: u64,
    },
    /// A run of the configuration has a saturated sample
    /// (`measurement-harness.md` 2.3).
    Saturated {
        /// The configuration.
        profile: String,
    },
    /// The CV of p99.9 still exceeds 10% after a re-run (8.4).
    Variation {
        /// The configurations over the limit.
        profiles: Vec<String>,
    },
    /// The CV exceeds 10% and the point awaits a re-run with a recorded
    /// cause (8.4).
    RerunPending {
        /// The configurations over the limit.
        profiles: Vec<String>,
    },
    /// The environment cannot decide (6.3, 8.8).
    Environment(Environment),
    /// There is no interval (no resample).
    NoInterval,
    /// More than 2.5% of the resamples of the difference are undefined
    /// (`∞ - ∞`), so the sign of the difference is unknown (review of
    /// #186, P3).
    UndefinedResamples {
        /// Undefined resamples.
        undefined: u32,
        /// All resamples.
        resamples: u32,
    },
    /// The interval excludes zero on one side while the point estimate is
    /// on the other side or at zero (review of #186, P3).
    Inconsistent,
    /// The point is not part of the results.
    NotMeasured,
    /// Another cause, such as `F2 before P2.7` or `profile not
    /// implemented`.
    Other(String),
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Drops {
                profile,
                run,
                missing,
                total,
            } => write!(
                f,
                "drops: {profile} run {run} lost {missing} of {total} messages"
            ),
            Self::Saturated { profile } => write!(f, "saturated samples in {profile}"),
            Self::Variation { profiles } => {
                write!(
                    f,
                    "CV of p99.9 above 10% after re-run: {}",
                    profiles.join(", ")
                )
            }
            Self::RerunPending { profiles } => {
                write!(
                    f,
                    "CV of p99.9 above 10%, re-run pending: {}",
                    profiles.join(", ")
                )
            }
            Self::Environment(environment) => {
                write!(f, "environment {environment} does not decide")
            }
            Self::NoInterval => f.write_str("no bootstrap resample"),
            Self::UndefinedResamples {
                undefined,
                resamples,
            } => write!(
                f,
                "{undefined} of {resamples} resamples undefined (both p99.9 infinite)"
            ),
            Self::Inconsistent => {
                f.write_str("point estimate on the other side of zero from the interval")
            }
            Self::NotMeasured => f.write_str("not measured"),
            Self::Other(cause) => f.write_str(cause),
        }
    }
}

/// The result at one point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The side with the lower added latency wins (8.5).
    Win(Side),
    /// A tie (8.5).
    Tie,
    /// Not demonstrated for both profiles.
    NotDemonstrated(Cause),
}

/// Classifies one point from its bootstrap (manifest 8.5): a tie when the
/// interval of the difference contains zero, or when the magnitude of the
/// difference is below 2% of the larger magnitude of the two added
/// latencies, `|diff| < 0.02 × max(|added_a|, |added_b|)` (ACS 14828;
/// never the total p99.9). Otherwise the side with the lower added latency
/// wins: `a` when the whole interval is below zero.
///
/// - An infinite end counts like any other: the interval is a tie only if
///   it contains zero (ACS 14838). The 2% rule applies only when the
///   difference and both added latencies are finite.
/// - More than 2.5% undefined resamples make the point Not demonstrated
///   (review of #186, P3): their sign is unknown.
/// - A percentile interval need not contain its point estimate. When the
///   interval excludes zero but the point estimate is zero or on the
///   other side, the evidence contradicts itself and the point is Not
///   demonstrated (review of #186, P3).
#[must_use]
pub fn classify(difference: &Estimate, added_a: Value, added_b: Value) -> Outcome {
    let interval = &difference.interval;
    let Some((low, _)) = interval.ends else {
        return Outcome::NotDemonstrated(Cause::NoInterval);
    };
    if interval.too_many_undefined() {
        return Outcome::NotDemonstrated(Cause::UndefinedResamples {
            undefined: interval.undefined,
            resamples: interval.resamples,
        });
    }
    if interval.contains_zero() {
        return Outcome::Tie;
    }
    if let (Value::Finite(diff), Value::Finite(a), Value::Finite(b)) =
        (difference.point, added_a, added_b)
    {
        let larger = i128::from(a).abs().max(i128::from(b).abs());
        let magnitude = i128::from(diff).abs();
        // |diff| < 2% of larger  <=>  100 |diff| < 2 larger.
        if magnitude * 100 < i128::from(section8::TIE_PERCENT) * larger {
            return Outcome::Tie;
        }
    }
    // The interval excludes zero: it lies wholly on one side, and the
    // point estimate must lie on the same side.
    let above = low > Value::Finite(0);
    let consistent = if above {
        difference.point > Value::Finite(0) && difference.point != Value::Undefined
    } else {
        difference.point < Value::Finite(0)
    };
    match (consistent, above) {
        (false, _) => Outcome::NotDemonstrated(Cause::Inconsistent),
        (true, true) => Outcome::Win(Side::B),
        (true, false) => Outcome::Win(Side::A),
    }
}

/// Whether a run set needs its point re-run (8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// The first run set.
    First,
    /// A re-run, with the cause recorded before it (8.4).
    Rerun {
        /// The recorded cause; never empty.
        cause: String,
    },
}

impl Attempt {
    /// A re-run with its recorded cause.
    ///
    /// # Errors
    ///
    /// Returns the empty cause back when it is blank: 8.4 requires the
    /// cause to be recorded.
    pub fn rerun(cause: &str) -> Result<Self, String> {
        if cause.trim().is_empty() {
            Err(cause.to_string())
        } else {
            Ok(Self::Rerun {
                cause: cause.trim().to_string(),
            })
        }
    }
}

/// The outcome of the CV gate of 8.4 at one point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CvGate {
    /// Every configuration is within 10%.
    Valid,
    /// A configuration exceeds 10% on the first run set: re-run after
    /// recording the cause.
    Rerun {
        /// The configurations over the limit.
        profiles: Vec<String>,
    },
    /// A configuration still exceeds 10% after the re-run: Not
    /// demonstrated for both profiles.
    NotDemonstrated {
        /// The configurations over the limit.
        profiles: Vec<String>,
    },
}

/// The CV gate of 8.4, applied to each configuration separately (ACS
/// 14828): `per_run` holds each configuration's per-run p99.9 values. A
/// CV strictly above 10% fails, at or below passes; an undefined CV (an
/// infinite per-run p99.9, fewer than 2 runs) fails.
#[must_use]
pub fn cv_gate(per_run: &[(&str, &[u32])], attempt: &Attempt) -> CvGate {
    let profiles: Vec<String> = per_run
        .iter()
        .filter(|(_, values)| stats::cv_exceeds(values, section8::CV_LIMIT_PERCENT).unwrap_or(true))
        .map(|(profile, _)| (*profile).to_string())
        .collect();
    match (profiles.is_empty(), attempt) {
        (true, _) => CvGate::Valid,
        (false, Attempt::First) => CvGate::Rerun { profiles },
        (false, Attempt::Rerun { .. }) => CvGate::NotDemonstrated { profiles },
    }
}

/// Whether more than 0.1% of the messages are missing (M-11): then the
/// p99.9 is infinite and the point is Not demonstrated with the cause
/// "drops".
#[must_use]
pub fn drops_exceed(missing: u64, total: u64) -> bool {
    u128::from(missing) * 1000 > u128::from(total)
}

/// The runs of one configuration at a point: per-message decision samples
/// (send plus receive, the slowest receiver under F2, see
/// [`samples::combine`]).
#[derive(Debug, Clone)]
pub struct Config<'a> {
    /// The profile name.
    pub profile: &'a str,
    /// Each run's samples, all of equal length (H-1).
    pub runs: Vec<&'a [u32]>,
    /// Saturated samples over all runs.
    pub saturated: u64,
}

/// The drops of one run (M-11), reported for every run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDrops {
    /// The configuration.
    pub profile: String,
    /// The run index.
    pub run: usize,
    /// Missing messages.
    pub missing: u64,
    /// All messages.
    pub total: u64,
}

impl RunDrops {
    /// The drop rate.
    #[must_use]
    pub fn rate(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let rate = self.missing as f64 / (self.total.max(1)) as f64;
        rate
    }
}

/// The evidence of one point.
#[derive(Debug, Clone)]
pub struct PointInput<'a> {
    /// The point.
    pub point: Point,
    /// Where it was measured.
    pub environment: Environment,
    /// Profile `a`.
    pub a: Config<'a>,
    /// Profile `b`.
    pub b: Config<'a>,
    /// The `trusted` baseline.
    pub trusted: Config<'a>,
    /// First run set or re-run.
    pub attempt: Attempt,
    /// The bootstrap parameters.
    pub spec: BootstrapSpec,
}

/// The evaluated point.
#[derive(Debug, Clone, PartialEq)]
pub struct PointResult {
    /// The point.
    pub point: Point,
    /// The outcome.
    pub outcome: Outcome,
    /// Per configuration: name, per-run p99.9, CV (reported, H-1).
    pub spread: Vec<(String, Vec<u32>, Option<f64>)>,
    /// Per run of every configuration: missing and total messages
    /// (M-11).
    pub drops: Vec<RunDrops>,
    /// The bootstrap, when it ran.
    pub bootstrap: Option<PointBootstrap>,
}

/// Evaluates one point: the environment (8.8), drops per run (M-11),
/// saturation,
/// the CV gate per configuration (8.4), then the bootstrap (8.3) and the
/// classification (8.5).
///
/// # Errors
///
/// [`StatsError`] for malformed runs.
pub fn evaluate_point(input: &PointInput<'_>) -> Result<PointResult, StatsError> {
    let configs = [&input.a, &input.b, &input.trusted];
    let mut spread = Vec::with_capacity(3);
    let mut drops = Vec::with_capacity(3);
    for config in configs {
        let per_run: Vec<u32> = stats::per_run_p999(&config.runs)
            .into_iter()
            .map(|value| value.unwrap_or(samples::MISSING))
            .collect();
        let cv = stats::cv(&per_run);
        spread.push((config.profile.to_string(), per_run, cv));
        for (run, samples) in config.runs.iter().enumerate() {
            drops.push(RunDrops {
                profile: config.profile.to_string(),
                run,
                missing: samples::missing(samples),
                total: u64::try_from(samples.len()).unwrap_or(u64::MAX),
            });
        }
    }
    let done = |outcome: Outcome, spread, drops| {
        Ok(PointResult {
            point: input.point,
            outcome,
            spread,
            drops,
            bootstrap: None,
        })
    };
    if !input.environment.decides() {
        return done(
            Outcome::NotDemonstrated(Cause::Environment(input.environment)),
            spread,
            drops,
        );
    }
    if let Some(run) = drops
        .iter()
        .find(|run| drops_exceed(run.missing, run.total))
    {
        let cause = Cause::Drops {
            profile: run.profile.clone(),
            run: run.run,
            missing: run.missing,
            total: run.total,
        };
        return done(Outcome::NotDemonstrated(cause), spread, drops);
    }
    if let Some(config) = configs.iter().find(|config| config.saturated > 0) {
        let cause = Cause::Saturated {
            profile: config.profile.to_string(),
        };
        return done(Outcome::NotDemonstrated(cause), spread, drops);
    }
    let per_run: Vec<(&str, &[u32])> = spread
        .iter()
        .map(|(profile, values, _)| (profile.as_str(), values.as_slice()))
        .collect();
    match cv_gate(&per_run, &input.attempt) {
        CvGate::Valid => {}
        CvGate::Rerun { profiles } => {
            return done(
                Outcome::NotDemonstrated(Cause::RerunPending { profiles }),
                spread,
                drops,
            );
        }
        CvGate::NotDemonstrated { profiles } => {
            return done(
                Outcome::NotDemonstrated(Cause::Variation { profiles }),
                spread,
                drops,
            );
        }
    }
    let bootstrap = stats::bootstrap_point(
        &input.a.runs,
        &input.b.runs,
        &input.trusted.runs,
        &input.spec,
    )?;
    let outcome = classify(
        &bootstrap.difference,
        bootstrap.added_a.point,
        bootstrap.added_b.point,
    );
    Ok(PointResult {
        point: input.point,
        outcome,
        spread,
        drops,
        bootstrap: Some(bootstrap),
    })
}

/// Which primary points decide (H-4, ACS 14817).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionSet {
    /// F2 points are reported only until P2.7 lands (M-6). Default `true`.
    pub f2_reported_only: bool,
}

impl Default for DecisionSet {
    fn default() -> Self {
        Self {
            f2_reported_only: true,
        }
    }
}

impl DecisionSet {
    /// The primary points that decide: the 17 of manifest 6.1, without
    /// the 8 F2 points while they are reported only.
    #[must_use]
    pub fn points(self) -> Vec<Point> {
        primary()
            .into_iter()
            .filter(|point| !(self.f2_reported_only && matches!(point.fanout, Fanout::F2 { .. })))
            .collect()
    }
}

/// The overall verdict of 8.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The side won at least one point of the decision set and lost none.
    Wins(Side),
    /// Any other pattern, including mixed wins and losses and all ties.
    Tie,
}

/// The overall result (8.6; H-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overall {
    /// The verdict over the demonstrated points of the decision set.
    pub verdict: Verdict,
    /// Points of the decision set won by `a`.
    pub wins_a: Vec<Point>,
    /// Points of the decision set won by `b`.
    pub wins_b: Vec<Point>,
    /// Tied points of the decision set.
    pub ties: Vec<Point>,
    /// Points of the decision set not demonstrated, with their causes.
    pub missing: Vec<(Point, Cause)>,
    /// Primary points reported but excluded from the decision set (F2
    /// before P2.7).
    pub reported_only: Vec<Point>,
}

impl Overall {
    /// Whether every point of the decision set is demonstrated. A
    /// selection may not rest on an incomplete result (H-4).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// `complete` or `incomplete`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        if self.is_complete() {
            "complete"
        } else {
            "incomplete"
        }
    }
}

/// The overall rule of 8.6 over the points of `set`. Per-point outcomes
/// are counted, never averaged (ADR-0044 step 3). A point of the set that
/// is absent from `results` or not demonstrated is neither a win nor a
/// loss and is listed in [`Overall::missing`].
#[must_use]
pub fn overall(results: &[(Point, Outcome)], set: DecisionSet) -> Overall {
    let decide = set.points();
    let mut wins_a = Vec::new();
    let mut wins_b = Vec::new();
    let mut ties = Vec::new();
    let mut missing = Vec::new();
    for point in &decide {
        match results.iter().find(|(p, _)| p == point).map(|(_, o)| o) {
            Some(Outcome::Win(Side::A)) => wins_a.push(*point),
            Some(Outcome::Win(Side::B)) => wins_b.push(*point),
            Some(Outcome::Tie) => ties.push(*point),
            Some(Outcome::NotDemonstrated(cause)) => missing.push((*point, cause.clone())),
            None => missing.push((*point, Cause::NotMeasured)),
        }
    }
    let reported_only = primary()
        .into_iter()
        .filter(|point| !decide.contains(point))
        .collect();
    let verdict = match (wins_a.is_empty(), wins_b.is_empty()) {
        (false, true) => Verdict::Wins(Side::A),
        (true, false) => Verdict::Wins(Side::B),
        _ => Verdict::Tie,
    };
    Overall {
        verdict,
        wins_a,
        wins_b,
        ties,
        missing,
        reported_only,
    }
}

/// Implementation simplicity of a profile, the first tie breaker (8.7 a),
/// declared per profile from its ADR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Simplicity {
    /// New dependency families.
    pub dependency_families: u32,
    /// New crates.
    pub crates: u32,
    /// Distinct primitive families in the whole profile.
    pub primitive_families: u32,
}

/// What the tie breakers need of a profile (8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TieBreakInput {
    /// 8.7 (a).
    pub simplicity: Simplicity,
    /// The DATA envelope bytes, for 8.7 (b).
    pub envelope: u32,
}

/// The MTU overhead of a profile at the default MTU (8.7 b; reported by
/// 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuOverhead {
    /// Envelope bytes per datagram.
    pub envelope: u32,
    /// `max_message_length` at 64 KiB terms under the rule.
    pub max_message_length: Option<u32>,
}

/// The MTU overhead of an envelope of `envelope` bytes under `rule`.
#[must_use]
pub fn mtu_overhead(envelope: u32, rule: MtuRule) -> MtuOverhead {
    MtuOverhead {
        envelope,
        max_message_length: max_message_length_64k(envelope, rule).ok(),
    }
}

/// Which tie breaker decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TieBreak {
    /// (a) The simpler profile: fewer dependency families, then fewer
    /// crates, then fewer primitive families (design 3, compared in that
    /// order).
    Simplicity(Side),
    /// (b) The smaller MTU overhead at MTU 1408: the shorter envelope.
    MtuOverhead(Side),
    /// (c) The owner decides, with the reason recorded.
    OwnerDecides,
}

/// The tie breakers of 8.7, in order.
#[must_use]
pub fn break_tie(a: &TieBreakInput, b: &TieBreakInput) -> TieBreak {
    match a.simplicity.cmp(&b.simplicity) {
        std::cmp::Ordering::Less => return TieBreak::Simplicity(Side::A),
        std::cmp::Ordering::Greater => return TieBreak::Simplicity(Side::B),
        std::cmp::Ordering::Equal => {}
    }
    match a.envelope.cmp(&b.envelope) {
        std::cmp::Ordering::Less => TieBreak::MtuOverhead(Side::A),
        std::cmp::Ordering::Greater => TieBreak::MtuOverhead(Side::B),
        std::cmp::Ordering::Equal => TieBreak::OwnerDecides,
    }
}

/// The hard gates of manifest 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gate {
    /// H1 Coverage.
    H1,
    /// H2 Verify first.
    H2,
    /// H3 Authority model.
    H3,
    /// H4 Replay, restart and freshness.
    H4,
    /// H5 Vectors.
    H5,
    /// H6 Pure Rust.
    H6,
    /// H7 Constant time.
    H7,
    /// H8 Specialist review.
    H8,
    /// H9 Limits enforced.
    H9,
    /// H10 Bounded unverified work.
    H10,
    /// H11 MTU accounting.
    H11,
    /// H12 Dependency review.
    H12,
}

impl Gate {
    /// Every gate, in order.
    pub const ALL: [Self; 12] = [
        Self::H1,
        Self::H2,
        Self::H3,
        Self::H4,
        Self::H5,
        Self::H6,
        Self::H7,
        Self::H8,
        Self::H9,
        Self::H10,
        Self::H11,
        Self::H12,
    ];

    /// The gate's name in manifest 7.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::H1 => "H1 Coverage",
            Self::H2 => "H2 Verify first",
            Self::H3 => "H3 Authority model",
            Self::H4 => "H4 Replay, restart and freshness",
            Self::H5 => "H5 Vectors",
            Self::H6 => "H6 Pure Rust",
            Self::H7 => "H7 Constant time",
            Self::H8 => "H8 Specialist review",
            Self::H9 => "H9 Limits enforced",
            Self::H10 => "H10 Bounded unverified work",
            Self::H11 => "H11 MTU accounting",
            Self::H12 => "H12 Dependency review",
        }
    }
}

/// A gate's status (manifest 7). Missing evidence is Not demonstrated,
/// never Pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum GateStatus {
    /// Passed, with the link to the evidence.
    Pass {
        /// The evidence link.
        evidence: String,
    },
    /// Failed, with the link to the evidence.
    Fail {
        /// The evidence link.
        evidence: String,
    },
    /// No evidence.
    #[default]
    NotDemonstrated,
}

/// The gate table of one profile; every row starts Not demonstrated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateTable {
    rows: Vec<(Gate, GateStatus)>,
}

impl Default for GateTable {
    fn default() -> Self {
        Self {
            rows: Gate::ALL
                .iter()
                .map(|gate| (*gate, GateStatus::NotDemonstrated))
                .collect(),
        }
    }
}

impl GateTable {
    /// The rows in manifest order.
    #[must_use]
    pub fn rows(&self) -> &[(Gate, GateStatus)] {
        &self.rows
    }

    /// Sets a gate's status.
    ///
    /// # Errors
    ///
    /// Returns the gate when a Pass or Fail has an empty evidence link.
    pub fn set(&mut self, gate: Gate, status: GateStatus) -> Result<(), Gate> {
        let blank = match &status {
            GateStatus::Pass { evidence } | GateStatus::Fail { evidence } => {
                evidence.trim().is_empty()
            }
            GateStatus::NotDemonstrated => false,
        };
        if blank {
            return Err(gate);
        }
        if let Some(row) = self.rows.iter_mut().find(|(g, _)| *g == gate) {
            row.1 = status;
        }
        Ok(())
    }

    /// Whether every gate passes: no performance result offsets a Fail or
    /// a Not demonstrated (manifest 7).
    #[must_use]
    pub fn admits(&self) -> bool {
        self.rows
            .iter()
            .all(|(_, status)| matches!(status, GateStatus::Pass { .. }))
    }
}

/// The aarch64 row: Not demonstrated for every point and gate in this
/// version, and it does not count against either profile (6.3, 8.8, Q-5).
pub const AARCH64_ROW: &str =
    "aarch64 (E3): Not demonstrated (manifest 6.3 and 8.8, owner decision Q-5)";

/// Why a result is not decision grade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GradeReason {
    /// `E_max` is not fixed by decision 5 (M-7).
    ProvisionalEMax,
    /// A run comes from an environment that does not decide.
    Environment(Environment),
    /// Fewer measured messages per run than 8.1 requires.
    Samples(u64),
    /// Fewer warmup messages per run than 8.1 requires.
    Warmup(u64),
    /// Fewer runs than 8.2 requires.
    Runs(u32),
    /// Fewer resamples than 8.3 requires.
    Resamples(u32),
    /// The resampling is not stratified by run in whole blocks (8.3,
    /// M-10): message-level [`Resampling::Iid`] never is, and the two
    /// stage and run jackknife variants await the owner (manifest 1.1).
    Resampling(Resampling),
    /// Stratified blocks of the wrong length for the shape: M-10 resamples
    /// whole units, a datagram for W5 and [`stats::DEFAULT_BLOCK_LEN`]
    /// otherwise (see [`stats::block_len`]).
    BlockLength {
        /// The shape.
        shape: Shape,
        /// The block length used.
        used: usize,
        /// The block length required; `None` when the shape has none at
        /// this `E_max`.
        required: Option<usize>,
    },
    /// The overall result is incomplete (H-4).
    Incomplete,
}

/// Whether a comparison is decision grade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grade {
    /// Every condition holds.
    Decision,
    /// The listed conditions fail; the report must not carry a decision
    /// label.
    NotDecisionGrade(Vec<GradeReason>),
}

/// The facts a decision grade depends on.
#[derive(Debug, Clone)]
pub struct GradeInputs<'a> {
    /// The envelope budget.
    pub e_max: EMax,
    /// The environment of every run.
    pub environments: &'a [Environment],
    /// The smallest measured count of any run.
    pub min_samples: u64,
    /// The smallest warmup of any run.
    pub min_warmup: u64,
    /// The smallest run count of any configuration at any point.
    pub min_runs: u32,
    /// The bootstrap resamples used (the smallest at any point).
    pub resamples: u32,
    /// The shape and resampling of every point of the comparison.
    pub points: &'a [(Shape, Resampling)],
    /// The overall result.
    pub overall: &'a Overall,
}

/// The decision grade: refused for a provisional `E_max` (M-7), an
/// environment that does not decide (6.3), too few samples, warmup, runs
/// or resamples (8.1 to 8.3), a resampling other than stratified whole
/// blocks of the shape's length (M-10; review of #186), or an incomplete
/// overall result (H-4).
#[must_use]
pub fn grade(inputs: &GradeInputs<'_>) -> Grade {
    let mut reasons = Vec::new();
    if !inputs.e_max.is_decided() {
        reasons.push(GradeReason::ProvisionalEMax);
    }
    let mut seen: Vec<Environment> = Vec::new();
    for environment in inputs.environments {
        if !environment.decides() && !seen.contains(environment) {
            seen.push(*environment);
            reasons.push(GradeReason::Environment(*environment));
        }
    }
    if inputs.min_samples < section8::MIN_SAMPLES_PER_RUN {
        reasons.push(GradeReason::Samples(inputs.min_samples));
    }
    if inputs.min_warmup < section8::WARMUP_PER_RUN {
        reasons.push(GradeReason::Warmup(inputs.min_warmup));
    }
    if inputs.min_runs < section8::MIN_RUNS {
        reasons.push(GradeReason::Runs(inputs.min_runs));
    }
    if inputs.resamples < section8::BOOTSTRAP_RESAMPLES {
        reasons.push(GradeReason::Resamples(inputs.resamples));
    }
    for &(shape, resampling) in inputs.points {
        let reason = match resampling {
            Resampling::StratifiedBlocks { block_len } => {
                let required = stats::block_len(shape, inputs.e_max.bytes()).ok();
                (required != Some(block_len)).then_some(GradeReason::BlockLength {
                    shape,
                    used: block_len,
                    required,
                })
            }
            other => Some(GradeReason::Resampling(other)),
        };
        if let Some(reason) = reason.filter(|reason| !reasons.contains(reason)) {
            reasons.push(reason);
        }
    }
    if !inputs.overall.is_complete() {
        reasons.push(GradeReason::Incomplete);
    }
    if reasons.is_empty() {
        Grade::Decision
    } else {
        Grade::NotDecisionGrade(reasons)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Load, RATE_100K, Shape};
    use crate::stats::Interval;
    use karyos_sim::Rng;

    fn estimate(point: i64, low: i64, high: i64) -> Estimate {
        Estimate {
            point: Value::Finite(point),
            interval: Interval {
                ends: Some((Value::Finite(low), Value::Finite(high))),
                infinite: 0,
                undefined: 0,
                resamples: 10_000,
            },
        }
    }

    #[test]
    fn interval_containing_zero_is_a_tie() {
        let diff = estimate(-30, -60, 5);
        assert_eq!(
            classify(&diff, Value::Finite(500), Value::Finite(530)),
            Outcome::Tie
        );
    }

    #[test]
    fn two_percent_uses_the_larger_added_latency_not_the_total() {
        // Added 1000 and 1100, totals near 12 000: a difference of 100 is
        // 9% of the larger added latency (a win), but under 2% of the
        // total p99.9 (which would have been a tie).
        let diff = estimate(-100, -120, -80);
        assert_eq!(
            classify(&diff, Value::Finite(1000), Value::Finite(1100)),
            Outcome::Win(Side::A)
        );
        // 15 of 1015 is under 2%: a tie although the interval excludes 0.
        let diff = estimate(-15, -20, -10);
        assert_eq!(
            classify(&diff, Value::Finite(1000), Value::Finite(1015)),
            Outcome::Tie
        );
        // Exactly 2% is not below 2%.
        let diff = estimate(20, 18, 22);
        assert_eq!(
            classify(&diff, Value::Finite(1000), Value::Finite(980)),
            Outcome::Win(Side::B)
        );
        // Magnitudes: added latencies of -1000 and -960 (both faster than
        // trusted) compare by magnitude.
        let diff = estimate(-40, -50, -30);
        assert_eq!(
            classify(&diff, Value::Finite(-1000), Value::Finite(-960)),
            Outcome::Win(Side::A)
        );
        let diff = estimate(-10, -15, -5);
        assert_eq!(
            classify(&diff, Value::Finite(-1000), Value::Finite(-990)),
            Outcome::Tie
        );
    }

    #[test]
    fn infinite_ends_tie_only_when_they_contain_zero() {
        let open = |point: Value, low: Value, high: Value| Estimate {
            point,
            interval: Interval {
                ends: Some((low, high)),
                infinite: 3,
                undefined: 1,
                resamples: 1000,
            },
        };
        assert_eq!(
            classify(
                &open(Value::PosInf, Value::Finite(5), Value::PosInf),
                Value::PosInf,
                Value::Finite(10)
            ),
            Outcome::Win(Side::B)
        );
        assert_eq!(
            classify(
                &open(Value::PosInf, Value::Finite(-5), Value::PosInf),
                Value::PosInf,
                Value::Finite(10)
            ),
            Outcome::Tie
        );
        assert_eq!(
            classify(
                &open(Value::NegInf, Value::NegInf, Value::Finite(-1)),
                Value::Finite(1),
                Value::PosInf
            ),
            Outcome::Win(Side::A)
        );
        let none = Estimate {
            point: Value::Undefined,
            interval: Interval {
                ends: None,
                infinite: 0,
                undefined: 0,
                resamples: 0,
            },
        };
        assert_eq!(
            classify(&none, Value::Undefined, Value::Undefined),
            Outcome::NotDemonstrated(Cause::NoInterval)
        );
    }

    #[test]
    fn too_many_undefined_resamples_are_not_demonstrated() {
        // 30 of 1000 resamples undefined (3% > 2.5%): the interval built
        // by stats::interval is (-inf, +inf), and the point is Not
        // demonstrated rather than a tie.
        let mut values: Vec<Value> = (1..=970).map(Value::Finite).collect();
        values.extend(std::iter::repeat_n(Value::Undefined, 30));
        let difference = Estimate {
            point: Value::Finite(500),
            interval: stats::interval(&values),
        };
        assert_eq!(
            classify(&difference, Value::Finite(900), Value::Finite(400)),
            Outcome::NotDemonstrated(Cause::UndefinedResamples {
                undefined: 30,
                resamples: 1000
            })
        );
        // 10 of 1000 (1%): classified, the undefined counted at both ends.
        let mut values: Vec<Value> = (1..=990).map(Value::Finite).collect();
        values.extend(std::iter::repeat_n(Value::Undefined, 10));
        let difference = Estimate {
            point: Value::Finite(500),
            interval: stats::interval(&values),
        };
        assert_eq!(
            classify(&difference, Value::Finite(900), Value::Finite(400)),
            Outcome::Win(Side::B)
        );
    }

    #[test]
    fn the_point_estimate_must_agree_with_the_interval() {
        // The interval is above zero but the point estimate is below it:
        // contradictory evidence. Added latencies of 100 and 50 put the 2%
        // band at 2 ns, so a point of -5 is outside it.
        let difference = estimate(-5, 10, 60);
        assert_eq!(
            classify(&difference, Value::Finite(100), Value::Finite(50)),
            Outcome::NotDemonstrated(Cause::Inconsistent)
        );
        let difference = estimate(5, -60, -10);
        assert_eq!(
            classify(&difference, Value::Finite(50), Value::Finite(100)),
            Outcome::NotDemonstrated(Cause::Inconsistent)
        );
        // A point estimate of zero is always inside the 2% band: a tie.
        let difference = estimate(0, 10, 60);
        assert_eq!(
            classify(&difference, Value::Finite(100), Value::Finite(50)),
            Outcome::Tie
        );
        // Agreement wins as before.
        let difference = estimate(-35, -60, -10);
        assert_eq!(
            classify(&difference, Value::Finite(50), Value::Finite(100)),
            Outcome::Win(Side::A)
        );
    }

    #[test]
    fn the_cv_gate_applies_per_configuration() {
        let calm = [1000u32, 1000, 1000, 1000, 1000];
        let at_limit = [90u32, 110, 90, 110, 100]; // exactly 10%
        let just_above = [899u32, 1101, 899, 1101, 1000]; // 10.1%
        let just_below = [901u32, 1099, 901, 1099, 1000]; // 9.9%
        assert_eq!(
            cv_gate(&[("a", &calm), ("trusted", &at_limit)], &Attempt::First),
            CvGate::Valid
        );
        assert_eq!(
            cv_gate(&[("a", &just_below)], &Attempt::First),
            CvGate::Valid
        );
        assert_eq!(
            cv_gate(&[("a", &calm), ("trusted", &just_above)], &Attempt::First),
            CvGate::Rerun {
                profiles: vec!["trusted".into()]
            }
        );
        let rerun = Attempt::rerun("governor reset during run 3").unwrap();
        assert_eq!(
            cv_gate(&[("a", &just_above), ("trusted", &calm)], &rerun),
            CvGate::NotDemonstrated {
                profiles: vec!["a".into()]
            }
        );
        assert!(Attempt::rerun("  ").is_err());
    }

    #[test]
    fn drop_threshold() {
        assert!(!drops_exceed(1000, 1_000_000));
        assert!(drops_exceed(1001, 1_000_000));
        assert!(!drops_exceed(0, 0));
    }

    fn point(shape: Shape, fanout: Fanout) -> Point {
        Point {
            shape,
            load: Load::R1,
            fanout,
        }
    }

    fn all(outcome: &Outcome) -> Vec<(Point, Outcome)> {
        primary()
            .into_iter()
            .map(|p| (p, outcome.clone()))
            .collect()
    }

    fn set(results: &mut [(Point, Outcome)], target: Point, outcome: Outcome) {
        for (p, o) in results.iter_mut() {
            if *p == target {
                *o = outcome.clone();
            }
        }
    }

    #[test]
    fn overall_rule() {
        let decision = DecisionSet::default();
        assert_eq!(decision.points().len(), 9);
        let w1 = point(Shape::W1, Fanout::F1);
        let w3 = point(Shape::W3, Fanout::F1);
        // One win and no loss wins.
        let mut results = all(&Outcome::Tie);
        set(&mut results, w1, Outcome::Win(Side::A));
        let found = overall(&results, decision);
        assert_eq!(found.verdict, Verdict::Wins(Side::A));
        assert!(found.is_complete());
        assert_eq!(found.reported_only.len(), 8);
        // A win and a loss: an overall tie.
        set(&mut results, w3, Outcome::Win(Side::B));
        assert_eq!(overall(&results, decision).verdict, Verdict::Tie);
        // All ties: a tie, broken by 8.7.
        let ties = all(&Outcome::Tie);
        let found = overall(&ties, decision);
        assert_eq!(found.verdict, Verdict::Tie);
        assert_eq!(found.ties.len(), 9);
    }

    #[test]
    fn f2_points_are_reported_only_by_default() {
        let f2 = point(Shape::W1, Fanout::F2 { receivers: 4 });
        let mut results = all(&Outcome::Tie);
        set(
            &mut results,
            f2,
            Outcome::NotDemonstrated(Cause::Other("F2 before P2.7".into())),
        );
        // With F2 reported only, the F2 gap does not make it incomplete.
        let found = overall(&results, DecisionSet::default());
        assert!(found.is_complete(), "{found:?}");
        assert!(found.reported_only.contains(&f2));
        // An F2 loss does not count either.
        set(&mut results, f2, Outcome::Win(Side::B));
        set(
            &mut results,
            point(Shape::W4, Fanout::F1),
            Outcome::Win(Side::A),
        );
        assert_eq!(
            overall(&results, DecisionSet::default()).verdict,
            Verdict::Wins(Side::A)
        );
        // Once P2.7 lands, F2 decides: the F2 loss makes it a tie.
        let with_f2 = DecisionSet {
            f2_reported_only: false,
        };
        assert_eq!(with_f2.points().len(), 17);
        assert_eq!(overall(&results, with_f2).verdict, Verdict::Tie);
    }

    #[test]
    fn a_missing_primary_point_makes_the_result_incomplete() {
        let r5 = Point {
            shape: Shape::W1,
            load: Load::R5 {
                rate: crate::manifest::RATE_1M,
            },
            fanout: Fanout::F1,
        };
        let mut results = all(&Outcome::Tie);
        results.retain(|(p, _)| *p != r5);
        let w5 = Point {
            shape: Shape::W5,
            load: Load::R2 { rate: RATE_100K },
            fanout: Fanout::F1,
        };
        set(
            &mut results,
            w5,
            Outcome::NotDemonstrated(Cause::Variation {
                profiles: vec!["a".into()],
            }),
        );
        set(
            &mut results,
            point(Shape::W1, Fanout::F1),
            Outcome::Win(Side::B),
        );
        let found = overall(&results, DecisionSet::default());
        // Computed over the demonstrated points, labelled incomplete.
        assert_eq!(found.verdict, Verdict::Wins(Side::B));
        assert_eq!(found.label(), "incomplete");
        assert_eq!(found.missing.len(), 2);
        assert!(found.missing.contains(&(r5, Cause::NotMeasured)));
        let grade = grade(&GradeInputs {
            e_max: EMax::Decided(64),
            environments: &[Environment::E1],
            min_samples: 1_000_000,
            min_warmup: 100_000,
            min_runs: 5,
            resamples: 10_000,
            points: &[(Shape::W1, Resampling::default_with(64))],
            overall: &found,
        });
        assert_eq!(
            grade,
            Grade::NotDecisionGrade(vec![GradeReason::Incomplete])
        );
    }

    #[test]
    fn decision_grade_conditions() {
        let complete = overall(&all(&Outcome::Tie), DecisionSet::default());
        let good = [
            (Shape::W1, Resampling::default_with(64)),
            (Shape::W5, Resampling::default_with(21)),
        ];
        let mut inputs = GradeInputs {
            e_max: EMax::Decided(64),
            environments: &[Environment::E1, Environment::E1],
            min_samples: 1_000_020,
            min_warmup: 100_002,
            min_runs: 5,
            resamples: 10_000,
            points: &good,
            overall: &complete,
        };
        assert_eq!(grade(&inputs), Grade::Decision);
        inputs.e_max = EMax::Provisional(64);
        inputs.environments = &[Environment::E4, Environment::E3, Environment::E4];
        inputs.min_samples = 999_999;
        inputs.resamples = 1000;
        let two_stage = [(Shape::W1, Resampling::TwoStage { block_len: 64 })];
        inputs.points = &two_stage;
        assert_eq!(
            grade(&inputs),
            Grade::NotDecisionGrade(vec![
                GradeReason::ProvisionalEMax,
                GradeReason::Environment(Environment::E4),
                GradeReason::Environment(Environment::E3),
                GradeReason::Samples(999_999),
                GradeReason::Resamples(1000),
                GradeReason::Resampling(Resampling::TwoStage { block_len: 64 }),
            ])
        );
    }

    #[test]
    fn decision_grade_needs_whole_units() {
        // M-10: whole units, never single messages (review of #186, P2).
        let complete = overall(&all(&Outcome::Tie), DecisionSet::default());
        let check = |points: &[(Shape, Resampling)]| {
            grade(&GradeInputs {
                e_max: EMax::Decided(64),
                environments: &[Environment::E1],
                min_samples: 1_000_020,
                min_warmup: 100_002,
                min_runs: 5,
                resamples: 10_000,
                points,
                overall: &complete,
            })
        };
        let refused = |reason: GradeReason| Grade::NotDecisionGrade(vec![reason]);
        assert_eq!(
            check(&[(Shape::W1, Resampling::Iid)]),
            refused(GradeReason::Resampling(Resampling::Iid))
        );
        assert_eq!(
            check(&[(Shape::W1, Resampling::default_with(1))]),
            refused(GradeReason::BlockLength {
                shape: Shape::W1,
                used: 1,
                required: Some(64)
            })
        );
        // W5 blocks must be its datagrams (21 at E_max 64), not 64.
        assert_eq!(
            check(&[(Shape::W5, Resampling::default_with(64))]),
            refused(GradeReason::BlockLength {
                shape: Shape::W5,
                used: 64,
                required: Some(21)
            })
        );
        assert_eq!(
            check(&[(Shape::W3, Resampling::RunWelchT)]),
            refused(GradeReason::Resampling(Resampling::RunWelchT))
        );
        assert_eq!(
            check(&[(Shape::W5, Resampling::default_with(21))]),
            Grade::Decision
        );
    }

    #[test]
    fn tie_breakers_in_order() {
        let hmac = TieBreakInput {
            simplicity: Simplicity {
                dependency_families: 1,
                crates: 2,
                primitive_families: 1,
            },
            envelope: 48,
        };
        let cmac = TieBreakInput {
            simplicity: Simplicity {
                dependency_families: 2,
                crates: 3,
                primitive_families: 2,
            },
            envelope: 32,
        };
        assert_eq!(break_tie(&hmac, &cmac), TieBreak::Simplicity(Side::A));
        let same = TieBreakInput {
            envelope: 32,
            ..hmac
        };
        assert_eq!(break_tie(&hmac, &same), TieBreak::MtuOverhead(Side::B));
        assert_eq!(break_tie(&hmac, &hmac), TieBreak::OwnerDecides);
        let overhead = mtu_overhead(64, MtuRule::CountsEnvelope);
        assert_eq!(overhead.max_message_length, Some(7968));
        assert_eq!(
            mtu_overhead(64, MtuRule::ExcludesEnvelope).max_message_length,
            mtu_overhead(0, MtuRule::CountsEnvelope).max_message_length
        );
    }

    #[test]
    fn gates_default_to_not_demonstrated() {
        let mut table = GateTable::default();
        assert_eq!(table.rows().len(), 12);
        assert!(
            table
                .rows()
                .iter()
                .all(|(_, status)| *status == GateStatus::NotDemonstrated)
        );
        assert!(!table.admits());
        assert_eq!(
            table.set(
                Gate::H5,
                GateStatus::Pass {
                    evidence: " ".into()
                }
            ),
            Err(Gate::H5)
        );
        for gate in Gate::ALL {
            table
                .set(
                    gate,
                    GateStatus::Pass {
                        evidence: format!("https://example.invalid/{}", gate.name()),
                    },
                )
                .unwrap();
        }
        assert!(table.admits());
        table
            .set(
                Gate::H7,
                GateStatus::Fail {
                    evidence: "review".into(),
                },
            )
            .unwrap();
        assert!(!table.admits());
        assert!(AARCH64_ROW.contains("Not demonstrated"));
    }

    fn runs(rng: &mut Rng, base: u32, count: usize, n: usize) -> Vec<Vec<u32>> {
        (0..count)
            .map(|_| {
                (0..n)
                    .map(|_| base + u32::try_from(rng.below(1000)).unwrap())
                    .collect()
            })
            .collect()
    }

    fn config<'a>(profile: &'a str, runs: &'a [Vec<u32>]) -> Config<'a> {
        Config {
            profile,
            runs: runs.iter().map(Vec::as_slice).collect(),
            saturated: 0,
        }
    }

    fn input<'a>(a: Config<'a>, b: Config<'a>, t: Config<'a>) -> PointInput<'a> {
        PointInput {
            point: point(Shape::W1, Fanout::F1),
            environment: Environment::E1,
            a,
            b,
            trusted: t,
            attempt: Attempt::First,
            spec: BootstrapSpec {
                resampling: Resampling::default_with(16),
                resamples: 1000,
                seed: 7,
                threads: None,
            },
        }
    }

    #[test]
    fn a_a_is_a_tie_and_a_five_percent_shift_wins() {
        // Base 10 000 + U(0, 1000): p99.9 ≈ 10 999. Trusted at offset 0,
        // profiles at +1000 added latency.
        let mut rng = Rng::new(1);
        let t = runs(&mut rng, 10_000, 5, 32_000);
        let a = runs(&mut rng, 11_000, 5, 32_000);
        let b = runs(&mut rng, 11_000, 5, 32_000);
        let result = evaluate_point(&input(
            config("a", &a),
            config("b", &b),
            config("trusted", &t),
        ))
        .unwrap();
        assert_eq!(result.outcome, Outcome::Tie, "{result:?}");
        // b adds 5% more: 1050 instead of 1000.
        let b = runs(&mut rng, 11_050, 5, 32_000);
        let result = evaluate_point(&input(
            config("a", &a),
            config("b", &b),
            config("trusted", &t),
        ))
        .unwrap();
        assert_eq!(result.outcome, Outcome::Win(Side::A), "{result:?}");
        let swapped = evaluate_point(&input(
            config("b", &b),
            config("a", &a),
            config("trusted", &t),
        ))
        .unwrap();
        assert_eq!(swapped.outcome, Outcome::Win(Side::B));
    }

    #[test]
    fn point_gates_before_the_bootstrap() {
        let mut rng = Rng::new(2);
        let t = runs(&mut rng, 10_000, 5, 4_000);
        let a = runs(&mut rng, 11_000, 5, 4_000);
        let mut b = runs(&mut rng, 11_000, 5, 4_000);
        // Environment.
        let mut e4 = input(config("a", &a), config("b", &b), config("trusted", &t));
        e4.environment = Environment::E4;
        assert_eq!(
            evaluate_point(&e4).unwrap().outcome,
            Outcome::NotDemonstrated(Cause::Environment(Environment::E4))
        );
        // Saturation.
        let mut saturated = input(config("a", &a), config("b", &b), config("trusted", &t));
        saturated.a.saturated = 1;
        assert!(matches!(
            evaluate_point(&saturated).unwrap().outcome,
            Outcome::NotDemonstrated(Cause::Saturated { .. })
        ));
        // CV: one run of b far slower.
        for value in &mut b[0] {
            *value += 5000;
        }
        let result = evaluate_point(&input(
            config("a", &a),
            config("b", &b),
            config("trusted", &t),
        ))
        .unwrap();
        assert_eq!(
            result.outcome,
            Outcome::NotDemonstrated(Cause::RerunPending {
                profiles: vec!["b".into()]
            })
        );
        assert!(result.bootstrap.is_none());
        // Drops: 5 in run 1, over 0.1% of its 4000 messages, while the
        // pooled configuration (5 of 20 000) is under 0.1%. The gate is per
        // run (review of #186, P3).
        let mut dropped = a.clone();
        for value in dropped[1].iter_mut().take(5) {
            *value = samples::MISSING;
        }
        let result = evaluate_point(&input(
            config("a", &dropped),
            config("trusted", &t),
            config("trusted", &t),
        ))
        .unwrap();
        assert_eq!(
            result.outcome,
            Outcome::NotDemonstrated(Cause::Drops {
                profile: "a".into(),
                run: 1,
                missing: 5,
                total: 4000
            })
        );
        // Every run is reported, with its rate.
        assert_eq!(result.drops.len(), 15);
        let run = result
            .drops
            .iter()
            .find(|run| run.profile == "a" && run.run == 1)
            .unwrap();
        assert!((run.rate() - 0.00125).abs() < 1e-12);
        // 4 drops in a run of 4000 is exactly 0.1%: not over the limit.
        let mut edge = a.clone();
        for value in edge[1].iter_mut().take(4) {
            *value = samples::MISSING;
        }
        let result = evaluate_point(&input(
            config("a", &edge),
            config("trusted", &t),
            config("trusted", &t),
        ))
        .unwrap();
        assert!(!matches!(
            result.outcome,
            Outcome::NotDemonstrated(Cause::Drops { .. })
        ));
    }
}
