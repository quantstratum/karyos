// SPDX-License-Identifier: Apache-2.0

//! Quantiles, run-to-run variation and the bootstrap interval of manifest
//! section 8 (`quantstratum-docs: karyos/design/wire-threat-model-manifest.md`;
//! `karyos/design/measurement-harness.md` section 3).
//!
//! # Quantile
//!
//! The quantile `q = num / den` of `n` samples is the **nearest rank**: the
//! value at 1-based rank `k = max(1, ceil(num * n / den))` of the samples
//! sorted ascending, computed in integers. p99.9 is `k = ceil(999 n /
//! 1000)`: rank 999 of 1000 samples, rank 1000 of 1001, rank 1 of 1.
//! A [`MISSING`] sample (a dropped message) ranks above every measured
//! value, as +∞ (coordinator, ACS 14828); a quantile that lands on it is
//! [`MISSING`].
//!
//! # Point estimate
//!
//! The p99.9 of a configuration at a point is taken over the pooled
//! samples of its runs, every run contributing the same count (H-1, ACS
//! 14817). The added latency of a profile is its p99.9 minus the p99.9 of
//! `trusted` (manifest 6.2), never a quantile of per-message differences.
//!
//! # Bootstrap (manifest 8.3)
//!
//! One resample redraws every configuration of the point, `trusted`
//! included, and computes each pooled p99.9, the added latencies and their
//! difference. The interval is the percentile interval of the resampled
//! statistics: the values at nearest ranks 2.5% and 97.5% of the sorted
//! resamples (ranks 250 and 9750 of 10 000). The stage that redraws a
//! configuration is a [`Resampling`]:
//!
//! - [`Resampling::StratifiedBlocks`], the default (coordinator, ACS 14828
//!   and 14831): the runs are fixed strata, as manifest 8.3 says, and each
//!   run is redrawn as whole non-overlapping blocks of `block_len`
//!   consecutive messages, with replacement, so that messages of one
//!   datagram (W5) or a burst stay together.
//! - [`Resampling::TwoStage`]: the runs are first drawn with replacement,
//!   then each drawn run is redrawn by blocks. It carries the between-run
//!   variance; it is pending the owner as a manifest 1.1 change and is
//!   never the default.
//! - [`Resampling::Iid`]: single messages within fixed runs, the
//!   stratified scheme with a block of one. Never decision grade (M-10:
//!   whole units, never single messages).
//! - [`Resampling::RunWelchT`]: no resampling. The interval is Welch's
//!   t interval on the per-run p99.9 values (see
//!   [`Resampling::RunWelchT`]). It is the remedy measured for the
//!   undercoverage of [`Resampling::TwoStage`] with 5 runs (review of
//!   #186, ACS 14914) and, like it, awaits the owner (manifest 1.1).
//!
//! # Undefined resamples
//!
//! A resample in which both p99.9 values are infinite (drops) has an
//! undefined contrast. Its sign is unknown, so [`interval`] counts it as
//! −∞ for the lower end and as +∞ for the upper end: it can only widen the
//! interval, never turn a tie into a win. When more than 2.5% of the
//! resamples are undefined both ends are infinite, and
//! `decision::classify` reports the point as Not demonstrated.
//!
//! # Reproducibility
//!
//! A seed reproduces an interval exactly on one platform, whatever the
//! thread count. The binomial draws use `f64::ln` and `f64::ln_1p` from
//! the platform's math library, which may differ in the last bit between
//! platforms; across platforms an interval can therefore differ in rare
//! draws, not in distribution.
//!
//! # Cost
//!
//! Redrawing `N` = 5 × 10^6 messages naively for each of 10^4 resamples
//! and 3 configurations is 1.5 × 10^11 draws. Only the top of a resample
//! matters for p99.9, so the bootstrap draws only the blocks that reach
//! into the pooled upper tail, exactly:
//!
//! 1. Once per configuration, every message gets its global rank in the
//!    pooled samples (0 = largest; ties broken by position), in `O(N log
//!    N)`. Nested tail regions `T_0 < T_1 < … = N` are fixed, with `T_0 =
//!    max(4 m, 256)` where `m = N - k + 1` is the rank of p99.9 from the
//!    top, and `T_{l+1} = 4 T_l`. A block belongs to band `l` when its
//!    best rank is in `[T_{l-1}, T_l)`.
//! 2. A resample redraws a run's `B` blocks as `B` independent uniform
//!    draws. The draws that land in band 0 are `Binomial(B, k_0 / B)`
//!    (geometric waiting times, `O(hits)`), each a uniform block of the
//!    band; the others land below and hold only messages of rank `>= T_0`.
//! 3. If the drawn blocks hold at least `m` messages of rank `< T_0`, the
//!    `m`-th largest of the resample is the `m`-th largest of those, read
//!    by a counting scan over `T_0` ranks. Otherwise the same resample is
//!    extended to band 1: of the draws not yet placed, those landing in
//!    band 1 are `Binomial(remaining, k_1 / blocks outside bands < 1)`.
//!    The extension keeps the earlier draws, so the resample is the one a
//!    naive draw would give in distribution, not a redraw conditioned on
//!    failure.
//!
//! A resample costs `O(T_0 + hits)` ≈ `O(m)` per configuration while band
//! 0 suffices, which is nearly always under stratified resampling; two
//! stage resampling extends more often when runs differ. Resamples run on
//! scoped threads. Resample `i` uses its own generator, derived from the
//! seed and `i`, so the interval does not depend on the thread count. The
//! generator is `karyos_sim::Rng` (SplitMix64); no new dependency.

use std::fmt;
use std::num::NonZeroUsize;
use std::thread;

use karyos_sim::Rng;

use crate::manifest::{ManifestError, Shape, section8, w5_frames};
pub use crate::samples::MISSING;

/// Errors of the statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsError {
    /// A configuration has no run, or a run has no sample.
    Empty,
    /// The runs of a configuration differ in sample count (H-1 requires
    /// equal counts).
    UnequalRuns,
    /// A run's sample count is not a multiple of the block length, or the
    /// block length is zero.
    BlockLength {
        /// Samples per run.
        samples: usize,
        /// The block length.
        block_len: usize,
    },
    /// More pooled samples than the ranking supports (`u32::MAX`).
    TooLarge,
    /// Zero resamples.
    NoResamples,
    /// The configurations of a comparison differ in run count or in
    /// samples per run.
    UnequalConfigs,
    /// The run-level t interval needs at least 2 runs per configuration.
    TooFewRuns,
}

impl fmt::Display for StatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("no runs or no samples"),
            Self::UnequalRuns => f.write_str("runs differ in sample count"),
            Self::BlockLength { samples, block_len } => write!(
                f,
                "{samples} samples per run are not a multiple of block length {block_len}"
            ),
            Self::TooLarge => f.write_str("too many pooled samples"),
            Self::NoResamples => f.write_str("zero resamples"),
            Self::UnequalConfigs => {
                f.write_str("configurations differ in run count or samples per run")
            }
            Self::TooFewRuns => f.write_str("the run-level t interval needs at least 2 runs"),
        }
    }
}

impl std::error::Error for StatsError {}

/// The 1-based nearest rank of quantile `num / den` among `n` samples:
/// `max(1, ceil(num * n / den))`, at most `n`. `None` when `n` is 0 or the
/// quantile is not in `(0, 1]`.
#[must_use]
pub fn nearest_rank(n: u64, num: u64, den: u64) -> Option<u64> {
    if n == 0 || den == 0 || num == 0 || num > den {
        return None;
    }
    let product = u128::from(num).checked_mul(u128::from(n))?;
    let rank = product.div_ceil(u128::from(den));
    u64::try_from(rank).ok().map(|rank| rank.clamp(1, n))
}

/// The nearest-rank quantile of samples already sorted ascending.
#[must_use]
pub fn quantile_sorted(sorted: &[u32], num: u64, den: u64) -> Option<u32> {
    let n = u64::try_from(sorted.len()).ok()?;
    let rank = nearest_rank(n, num, den)?;
    let index = usize::try_from(rank.checked_sub(1)?).ok()?;
    sorted.get(index).copied()
}

/// The nearest-rank quantile of unsorted samples, by selection.
#[must_use]
pub fn quantile(samples: &[u32], num: u64, den: u64) -> Option<u32> {
    let n = u64::try_from(samples.len()).ok()?;
    let rank = nearest_rank(n, num, den)?;
    let index = usize::try_from(rank.checked_sub(1)?).ok()?;
    let mut copy = samples.to_vec();
    let (_, value, _) = copy.select_nth_unstable(index);
    Some(*value)
}

/// The nearest-rank p99.9 (manifest 6.2).
#[must_use]
pub fn p999(samples: &[u32]) -> Option<u32> {
    let (num, den) = section8::DECISION_QUANTILE;
    quantile(samples, num, den)
}

fn check_runs(runs: &[&[u32]]) -> Result<usize, StatsError> {
    let first = runs.first().ok_or(StatsError::Empty)?.len();
    if first == 0 {
        return Err(StatsError::Empty);
    }
    if runs.iter().any(|run| run.len() != first) {
        return Err(StatsError::UnequalRuns);
    }
    Ok(first)
}

/// The p99.9 over the pooled samples of equal-length runs (H-1).
///
/// # Errors
///
/// [`StatsError::Empty`] or [`StatsError::UnequalRuns`].
pub fn pooled_p999(runs: &[&[u32]]) -> Result<u32, StatsError> {
    check_runs(runs)?;
    let pooled: Vec<u32> = runs.iter().flat_map(|run| run.iter().copied()).collect();
    p999(&pooled).ok_or(StatsError::Empty)
}

/// The p99.9 of each run, for the spread and the CV (H-1; manifest 8.4).
#[must_use]
pub fn per_run_p999(runs: &[&[u32]]) -> Vec<Option<u32>> {
    runs.iter().map(|run| p999(run)).collect()
}

/// The run-to-run coefficient of variation: the sample standard deviation
/// (divisor `n - 1`) over the mean. `None` for fewer than 2 values, a zero
/// mean or a [`MISSING`] value. For reporting; the gate uses
/// [`cv_exceeds`], which is exact.
#[must_use]
pub fn cv(values: &[u32]) -> Option<f64> {
    if values.len() < 2 || values.contains(&MISSING) {
        return None;
    }
    let n = f64::from(u32::try_from(values.len()).ok()?);
    let mean = values.iter().map(|&v| f64::from(v)).sum::<f64>() / n;
    if mean <= 0.0 {
        return None;
    }
    let squares = values
        .iter()
        .map(|&v| (f64::from(v) - mean).powi(2))
        .sum::<f64>();
    Some((squares / (n - 1.0)).sqrt() / mean)
}

/// Whether the coefficient of variation of [`cv`] is strictly above
/// `percent` %, in exact integer arithmetic: `cv > p / 100` exactly when
/// `10^4 n (n S2 - S1^2) > p^2 (n - 1) S1^2`, with `S1` the sum and `S2`
/// the sum of squares. `None` where [`cv`] is undefined.
#[must_use]
pub fn cv_exceeds(values: &[u32], percent: u32) -> Option<bool> {
    if values.len() < 2 || values.contains(&MISSING) {
        return None;
    }
    let n = u128::try_from(values.len()).ok()?;
    let s1 = values
        .iter()
        .try_fold(0u128, |sum, &v| sum.checked_add(u128::from(v)))?;
    let s2 = values.iter().try_fold(0u128, |sum, &v| {
        sum.checked_add(u128::from(v).checked_mul(u128::from(v))?)
    })?;
    if s1 == 0 {
        return None;
    }
    let spread = n.checked_mul(s2)?.checked_sub(s1.checked_mul(s1)?)?;
    let left = 10_000u128.checked_mul(n)?.checked_mul(spread)?;
    let p = u128::from(percent);
    let right = p
        .checked_mul(p)?
        .checked_mul(n - 1)?
        .checked_mul(s1.checked_mul(s1)?)?;
    Some(left > right)
}

/// The recorded block length of every shape other than W5 (coordinator
/// rule, ACS 14838): 64 consecutive messages. It is long enough to keep a
/// short burst of interference (an interrupt or a scheduler preemption,
/// tens of microseconds at 10^6 messages per second) inside one block, and
/// short enough that a run of 10^6 messages still has 15 625 blocks to
/// resample. It divides the 10^6 samples of manifest 8.1. The block length
/// used is recorded with every result.
pub const DEFAULT_BLOCK_LEN: usize = 64;

/// The block length of a shape (coordinator rule, ACS 14838): W5 blocks
/// are its datagrams, `floor((1408 - E_max) / 64)` messages (21 at
/// `E_max` = 64, manifest 6.1), so a block never splits the messages one
/// datagram carries (coordinator M-5b samples W5 per message). Every
/// other shape uses [`DEFAULT_BLOCK_LEN`]; a W6 sample already spans its
/// 5 datagrams.
///
/// # Errors
///
/// [`ManifestError`] when W5 has no frame at `e_max`.
pub fn block_len(shape: Shape, e_max: u32) -> Result<usize, ManifestError> {
    match shape {
        Shape::W5 => {
            let frames = w5_frames(e_max)?;
            usize::try_from(frames).map_err(|_| ManifestError::EnvelopeTooLarge {
                e_max,
                mtu: crate::manifest::MTU,
            })
        }
        _ => Ok(DEFAULT_BLOCK_LEN),
    }
}

/// The measured samples per run for a block length: the manifest minimum
/// of 10^6 (8.1) rounded up to whole blocks, so that W5 runs end on a
/// datagram boundary (21 × 47 620 = 1 000 020 at `E_max` = 64).
#[must_use]
pub fn samples_per_run(block_len: usize) -> u64 {
    let block = u64::try_from(block_len.max(1)).unwrap_or(u64::MAX);
    section8::MIN_SAMPLES_PER_RUN
        .div_ceil(block)
        .saturating_mul(block)
}

/// The warmup messages discarded per run for a block length: the
/// manifest's 10^5 (8.1) rounded up to whole blocks, so that the measured
/// messages start on a block boundary. For W5 at `E_max` = 64 the warmup
/// is 21 × 4762 = 100 002 messages, so every block of 21 measured messages
/// is one datagram (review of #186, P3).
#[must_use]
pub fn warmup_per_run(block_len: usize) -> u64 {
    let block = u64::try_from(block_len.max(1)).unwrap_or(u64::MAX);
    section8::WARMUP_PER_RUN
        .div_ceil(block)
        .saturating_mul(block)
}

/// How one configuration is redrawn in a bootstrap resample (see the
/// module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resampling {
    /// Single messages within fixed runs.
    Iid,
    /// Fixed runs (manifest 8.3), whole blocks of `block_len` messages
    /// within each: the default (ACS 14831). A datagram group is a block
    /// of the messages per datagram (21 for W5 at `E_max` = 64).
    StratifiedBlocks {
        /// Messages per block; divides the samples per run.
        block_len: usize,
    },
    /// Runs drawn with replacement, then blocks within each drawn run.
    /// Pending the owner (manifest 1.1); never the default.
    TwoStage {
        /// Messages per block; divides the samples per run.
        block_len: usize,
    },
    /// No resampling: Welch's t interval on run-level estimates. Each run
    /// gives one p99.9; for configurations `X` and `Y` of `k` runs each,
    /// with means `m` and sample variances `s²` of those values, the
    /// interval of `p99.9(X) - p99.9(Y)` is
    /// `(m_X - m_Y) ± t(0.975, ν) × sqrt(s²_X / k + s²_Y / k)`, with the
    /// Welch-Satterthwaite `ν` rounded down (between `k - 1` and `2k - 2`)
    /// and the ends rounded outwards to whole nanoseconds.
    ///
    /// The run is the unit of independence, so the interval carries the
    /// between-run variance, and the t quantile corrects for the few runs:
    /// estimate the parameter once per independent group and apply a t
    /// test to the group estimates (Ibragimov and Müller, "t-statistic
    /// based correlation and heterogeneity robust inference", Journal of
    /// Business and Economic Statistics 28 (2010) 453-468), with unequal
    /// variances (Welch, "The generalization of 'Student's' problem when
    /// several different population variances are involved", Biometrika
    /// 34 (1947) 28-35; Satterthwaite, Biometrics Bulletin 2 (1946)
    /// 110-114).
    ///
    /// The interval is centred on the difference of the run means, while
    /// the point estimate stays the pooled p99.9 (H-1); a point estimate
    /// on the other side of an interval that excludes zero is Not
    /// demonstrated (`decision::classify`). At the design CV of about 8%
    /// the A/A rate of an interval excluding zero is 4.8% ± 0.9% with 5
    /// runs of 10^6 messages (2000 replications), where two stage
    /// resampling gives 14.7% and a delete-a-group jackknife of the pooled
    /// p99.9 gives 8.3% (see the test `calibration_at_design_cv`).
    RunWelchT,
}

impl Resampling {
    /// The default: [`Resampling::StratifiedBlocks`] with `block_len`.
    #[must_use]
    pub const fn default_with(block_len: usize) -> Self {
        Self::StratifiedBlocks { block_len }
    }

    /// The block length of a resampling scheme; `None` for the run-level
    /// t interval, whose unit is the whole run.
    #[must_use]
    pub const fn block_len(self) -> Option<usize> {
        match self {
            Self::Iid => Some(1),
            Self::StratifiedBlocks { block_len } | Self::TwoStage { block_len } => Some(block_len),
            Self::RunWelchT => None,
        }
    }
}

impl fmt::Display for Resampling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Iid => f.write_str("iid within runs"),
            Self::StratifiedBlocks { block_len } => {
                write!(f, "stratified by run, blocks of {block_len}")
            }
            Self::TwoStage { block_len } => {
                write!(f, "two stage (runs, then blocks of {block_len})")
            }
            Self::RunWelchT => f.write_str("run-level Welch t on per-run p99.9"),
        }
    }
}

/// The parameters of one bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapSpec {
    /// The resampling stage.
    pub resampling: Resampling,
    /// Resamples: 10 000 for a decision (manifest 8.3).
    pub resamples: u32,
    /// The seed, recorded with the result.
    pub seed: u64,
    /// Worker threads; `None` uses the available parallelism. The result
    /// does not depend on it.
    pub threads: Option<NonZeroUsize>,
}

impl BootstrapSpec {
    /// The manifest values: 10 000 resamples, the given seed and stage.
    #[must_use]
    pub const fn manifest(resampling: Resampling, seed: u64) -> Self {
        Self {
            resampling,
            resamples: section8::BOOTSTRAP_RESAMPLES,
            seed,
            threads: None,
        }
    }
}

/// A contrast of two p99.9 values, such as an added latency, with the
/// infinite values a drop produces (coordinator rule, ACS 14838):
/// `+∞ - finite = +∞`, `finite - +∞ = -∞` and `∞ - ∞` is
/// [`Value::Undefined`]. The order is `NegInf < Finite < PosInf`;
/// `Undefined` is not ordered (see [`Interval`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Value {
    /// −∞.
    NegInf,
    /// A finite difference in nanoseconds.
    Finite(i64),
    /// +∞.
    PosInf,
    /// `∞ - ∞`.
    Undefined,
}

impl Value {
    /// `x - y` of two p99.9 values, [`MISSING`] being +∞.
    #[must_use]
    pub fn contrast(x: u32, y: u32) -> Self {
        match (x == MISSING, y == MISSING) {
            (false, false) => Self::Finite(i64::from(x) - i64::from(y)),
            (true, false) => Self::PosInf,
            (false, true) => Self::NegInf,
            (true, true) => Self::Undefined,
        }
    }

    /// The finite value, if any.
    #[must_use]
    pub const fn finite(self) -> Option<i64> {
        match self {
            Self::Finite(value) => Some(value),
            _ => None,
        }
    }

    /// Whether the value is at most 0 (−∞ is; +∞ and undefined are not).
    const fn at_most_zero(self) -> bool {
        match self {
            Self::NegInf => true,
            Self::Finite(value) => value <= 0,
            Self::PosInf | Self::Undefined => false,
        }
    }

    /// Whether the value is at least 0.
    const fn at_least_zero(self) -> bool {
        match self {
            Self::PosInf => true,
            Self::Finite(value) => value >= 0,
            Self::NegInf | Self::Undefined => false,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegInf => f.write_str("-inf"),
            Self::Finite(value) => write!(f, "{value}"),
            Self::PosInf => f.write_str("+inf"),
            Self::Undefined => f.write_str("undefined"),
        }
    }
}

/// A 95% interval of a contrast.
///
/// For a bootstrap it is the percentile interval: the nearest ranks 2.5%
/// and 97.5% of the resamples, ordered `-∞ < finite < +∞`. An end may be
/// infinite. **Undefined resamples** (`∞ - ∞`) have an unknown sign, so
/// they count as −∞ for the lower end and as +∞ for the upper end (review
/// of #186, P3): they widen the interval and are counted. With more than
/// 2.5% undefined, both ends are infinite. [`Interval::ends`] is `None`
/// only when there is no resample at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    /// The 2.5% and 97.5% ends, `None` without any resample.
    pub ends: Option<(Value, Value)>,
    /// Resamples with an infinite contrast (`±∞`), reported.
    pub infinite: u32,
    /// Resamples with an undefined contrast (`∞ - ∞`), reported.
    pub undefined: u32,
    /// All resamples (0 for the run-level t interval).
    pub resamples: u32,
}

impl Interval {
    /// Whether the interval contains zero. An interval with an infinite
    /// end contains zero only if its other end is on the other side of
    /// zero, like any other (ACS 14838). No interval contains nothing.
    #[must_use]
    pub const fn contains_zero(&self) -> bool {
        match self.ends {
            Some((low, high)) => low.at_most_zero() && high.at_least_zero(),
            None => false,
        }
    }

    /// Whether both ends are finite.
    #[must_use]
    pub const fn is_bounded(&self) -> bool {
        matches!(self.ends, Some((Value::Finite(_), Value::Finite(_))))
    }

    /// Whether more than 2.5% of the resamples are undefined; such a
    /// point is Not demonstrated (review of #186, P3).
    #[must_use]
    pub fn too_many_undefined(&self) -> bool {
        let tail = u64::from((1000 - section8::CONFIDENCE_PER_MILLE) / 2);
        u64::from(self.undefined) * 1000 > tail * u64::from(self.resamples)
    }
}

/// A point estimate with its interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimate {
    /// The point estimate from the pooled p99.9 values.
    pub point: Value,
    /// The bootstrap interval.
    pub interval: Interval,
}

/// The bootstrap of one point comparing profiles `a` and `b` against
/// `trusted`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointBootstrap {
    /// Pooled p99.9 of `a`, `b` and `trusted` (`MISSING` when infinite).
    pub p999: [u32; 3],
    /// Added latency of `a`: p99.9(a) - p99.9(trusted).
    pub added_a: Estimate,
    /// Added latency of `b`.
    pub added_b: Estimate,
    /// The difference of added latencies, `added_a - added_b` (manifest
    /// 8.3). It is computed as `p99.9(a) - p99.9(b)` of the resample, in
    /// which the shared `trusted` term cancels; this also keeps a resample
    /// with an infinite `trusted` p99.9 defined.
    pub difference: Estimate,
}

/// The percentile interval at the manifest's 95% level.
#[must_use]
pub fn interval(values: &[Value]) -> Interval {
    let count = |predicate: fn(&Value) -> bool| {
        u32::try_from(values.iter().filter(|v| predicate(v)).count()).unwrap_or(u32::MAX)
    };
    let infinite = count(|v| matches!(v, Value::NegInf | Value::PosInf));
    let undefined = count(|v| matches!(v, Value::Undefined));
    let unknown = usize::try_from(undefined).unwrap_or(usize::MAX);
    let mut sorted: Vec<Value> = values
        .iter()
        .copied()
        .filter(|v| *v != Value::Undefined)
        .collect();
    sorted.sort_unstable();
    let tail = u64::from((1000 - section8::CONFIDENCE_PER_MILLE) / 2);
    let n = u64::try_from(values.len()).unwrap_or(u64::MAX);
    let index =
        |num: u64| nearest_rank(n, num, 1000).and_then(|rank| usize::try_from(rank - 1).ok());
    // Lower end: the undefined resamples first, as -inf.
    let low = index(tail).map(|i| match i.checked_sub(unknown) {
        Some(i) => sorted.get(i).copied().unwrap_or(Value::PosInf),
        None => Value::NegInf,
    });
    // Upper end: the undefined resamples last, as +inf.
    let high = index(1000 - tail).map(|i| sorted.get(i).copied().unwrap_or(Value::PosInf));
    Interval {
        ends: low.zip(high),
        infinite,
        undefined,
        resamples: u32::try_from(values.len()).unwrap_or(u32::MAX),
    }
}

/// The ranked tail model of one configuration (module documentation,
/// "Cost").
#[derive(Debug)]
struct Model {
    runs: usize,
    per_run: usize,
    block_len: usize,
    blocks: usize,
    total: usize,
    /// Rank from the top of the quantile, 1-based.
    from_top: usize,
    levels: Vec<usize>,
    /// Values by global rank.
    value_at: Vec<u32>,
    /// Global ranks of each run's blocks, ascending within a block.
    block_ranks: Vec<u32>,
    /// `[run][level]`: blocks whose best rank is in the band.
    bands: Vec<Vec<Vec<u32>>>,
    /// `[run][level]`: blocks in bands below `level`.
    below: Vec<Vec<usize>>,
}

impl Model {
    fn new(
        runs: &[&[u32]],
        block_len: usize,
        num: u64,
        den: u64,
        first_level: Option<usize>,
    ) -> Result<Self, StatsError> {
        let per_run = check_runs(runs)?;
        if block_len == 0 || per_run % block_len != 0 {
            return Err(StatsError::BlockLength {
                samples: per_run,
                block_len,
            });
        }
        let total = per_run
            .checked_mul(runs.len())
            .ok_or(StatsError::TooLarge)?;
        let total_u32 = u32::try_from(total).map_err(|_| StatsError::TooLarge)?;
        let rank = nearest_rank(u64::from(total_u32), num, den).ok_or(StatsError::Empty)?;
        let rank = usize::try_from(rank).map_err(|_| StatsError::TooLarge)?;
        let from_top = total - rank + 1;

        // Keys sort descending by value, then ascending by position.
        let mut keys: Vec<u64> = Vec::with_capacity(total);
        let mut position: u32 = 0;
        for run in runs {
            for &value in *run {
                keys.push((u64::from(value) << 32) | u64::from(u32::MAX - position));
                position = position.saturating_add(1);
            }
        }
        keys.sort_unstable_by(|a, b| b.cmp(a));
        let mut rank_of = vec![0u32; total];
        let mut value_at = Vec::with_capacity(total);
        for (rank, key) in (0u32..).zip(&keys) {
            let index = u32::MAX - u32::try_from(key & u64::from(u32::MAX)).unwrap_or(0);
            if let Some(slot) = usize::try_from(index).ok().and_then(|i| rank_of.get_mut(i)) {
                *slot = rank;
            }
            value_at.push(u32::try_from(key >> 32).unwrap_or(MISSING));
        }
        drop(keys);

        let mut levels = Vec::new();
        let mut level = first_level
            .unwrap_or_else(|| from_top.saturating_mul(4).max(256))
            .clamp(from_top, total);
        loop {
            levels.push(level);
            if level >= total {
                break;
            }
            level = level.saturating_mul(4).min(total);
        }

        let blocks = per_run / block_len;
        let mut block_ranks = rank_of;
        for block in block_ranks.chunks_mut(block_len) {
            block.sort_unstable();
        }
        let mut bands = vec![vec![Vec::new(); levels.len()]; runs.len()];
        for (run, run_bands) in bands.iter_mut().enumerate() {
            for block in 0..blocks {
                let start = run
                    .checked_mul(per_run)
                    .and_then(|s| s.checked_add(block.checked_mul(block_len)?))
                    .ok_or(StatsError::TooLarge)?;
                let best = block_ranks.get(start).copied().unwrap_or(u32::MAX);
                let best = usize::try_from(best).unwrap_or(usize::MAX);
                let band = levels.iter().position(|&level| best < level);
                if let Some(list) = band.and_then(|band| run_bands.get_mut(band)) {
                    list.push(u32::try_from(block).map_err(|_| StatsError::TooLarge)?);
                }
            }
        }
        let below = bands
            .iter()
            .map(|run_bands| {
                let mut sum = 0usize;
                run_bands
                    .iter()
                    .map(|band| {
                        let before = sum;
                        sum = sum.saturating_add(band.len());
                        before
                    })
                    .collect()
            })
            .collect();
        Ok(Self {
            runs: runs.len(),
            per_run,
            block_len,
            blocks,
            total,
            from_top,
            levels,
            value_at,
            block_ranks,
            bands,
            below,
        })
    }

    fn ranks(&self, run: usize, block: u32) -> &[u32] {
        let block = usize::try_from(block).unwrap_or(usize::MAX);
        let start = run
            .saturating_mul(self.per_run)
            .saturating_add(block.saturating_mul(self.block_len));
        self.block_ranks
            .get(start..start.saturating_add(self.block_len))
            .unwrap_or_default()
    }
}

/// Scratch space of one worker.
#[derive(Debug, Default)]
struct Scratch {
    counts: Vec<u32>,
    slots: Vec<usize>,
    drawn: Vec<Vec<u32>>,
    hits: Vec<usize>,
}

/// A uniform value in `(0, 1]`.
fn unit_open(rng: &mut Rng) -> f64 {
    // 53 random bits, exactly representable.
    #[allow(clippy::cast_precision_loss)]
    let bits = ((rng.next_u64() >> 11) + 1) as f64;
    bits * (1.0 / 9_007_199_254_740_992.0)
}

/// `Binomial(trials, p)` by geometric waiting times, in `O(successes)`.
fn binomial(rng: &mut Rng, trials: usize, p: f64) -> usize {
    if trials == 0 || p <= 0.0 {
        return 0;
    }
    if p >= 1.0 {
        return trials;
    }
    let log_q = (-p).ln_1p();
    let mut successes = 0usize;
    let mut used = 0usize;
    loop {
        let gap = (unit_open(rng).ln() / log_q).floor();
        let remaining = trials - used;
        #[allow(clippy::cast_precision_loss)]
        if gap.is_nan() || gap >= remaining as f64 {
            return successes;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let gap = gap as usize;
        used = used.saturating_add(gap).saturating_add(1);
        successes += 1;
        if used >= trials {
            return successes;
        }
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let value = numerator as f64 / denominator as f64;
    value
}

/// One resampled quantile of `model`.
fn resample(model: &Model, two_stage: bool, rng: &mut Rng, scratch: &mut Scratch) -> u32 {
    scratch.slots.clear();
    if two_stage {
        let runs = u64::try_from(model.runs).unwrap_or(u64::MAX);
        for _ in 0..model.runs {
            let run = usize::try_from(rng.below(runs)).unwrap_or(0);
            scratch.slots.push(run);
        }
    } else {
        scratch.slots.extend(0..model.runs);
    }
    scratch.drawn.resize_with(model.runs, Vec::new);
    scratch.hits.clear();
    scratch.hits.resize(model.runs, 0);
    for drawn in &mut scratch.drawn {
        drawn.clear();
    }
    for (level, &limit) in model.levels.iter().enumerate() {
        for (slot, &run) in scratch.slots.iter().enumerate() {
            let (Some(band), Some(&below)) = (
                model.bands.get(run).and_then(|bands| bands.get(level)),
                model.below.get(run).and_then(|below| below.get(level)),
            ) else {
                continue;
            };
            let (Some(hits), Some(drawn)) =
                (scratch.hits.get_mut(slot), scratch.drawn.get_mut(slot))
            else {
                continue;
            };
            let trials = model.blocks.saturating_sub(*hits);
            let outside = model.blocks.saturating_sub(below);
            let new = binomial(rng, trials, ratio(band.len(), outside));
            let width = u64::try_from(band.len()).unwrap_or(u64::MAX);
            for _ in 0..new {
                let pick = usize::try_from(rng.below(width)).unwrap_or(0);
                if let Some(&block) = band.get(pick) {
                    drawn.push(block);
                }
            }
            *hits = hits.saturating_add(new);
        }
        if scratch.counts.len() < limit {
            scratch.counts.resize(limit, 0);
        }
        let counts = scratch.counts.get_mut(..limit).unwrap_or_default();
        counts.fill(0);
        let mut found = 0usize;
        for (slot, &run) in scratch.slots.iter().enumerate() {
            for &block in scratch
                .drawn
                .get(slot)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                for &rank in model.ranks(run, block) {
                    let rank = usize::try_from(rank).unwrap_or(usize::MAX);
                    match counts.get_mut(rank) {
                        Some(count) => {
                            *count = count.saturating_add(1);
                            found = found.saturating_add(1);
                        }
                        None => break,
                    }
                }
            }
        }
        if found >= model.from_top || limit >= model.total {
            let mut seen = 0usize;
            for (rank, &count) in counts.iter().enumerate() {
                seen = seen.saturating_add(usize::try_from(count).unwrap_or(usize::MAX));
                if seen >= model.from_top {
                    return model.value_at.get(rank).copied().unwrap_or(MISSING);
                }
            }
            return MISSING;
        }
    }
    MISSING
}

/// The generator of resample `index`.
fn resample_rng(seed: u64, index: u32) -> Rng {
    let mut root = Rng::new(seed ^ u64::from(index).wrapping_mul(0xD6E8_FEB8_6659_FD93));
    Rng::new(root.next_u64())
}

/// Resampled quantiles of every model, `resamples × models`, row-major.
fn run_bootstrap(models: &[Model], spec: &BootstrapSpec) -> Result<Vec<u32>, StatsError> {
    if spec.resamples == 0 {
        return Err(StatsError::NoResamples);
    }
    let width = models.len();
    let resamples = usize::try_from(spec.resamples).map_err(|_| StatsError::TooLarge)?;
    let mut out = vec![0u32; resamples.checked_mul(width).ok_or(StatsError::TooLarge)?];
    let threads = spec
        .threads
        .or_else(|| thread::available_parallelism().ok())
        .map_or(1, NonZeroUsize::get)
        .min(resamples)
        .max(1);
    let per_thread = resamples.div_ceil(threads);
    let two_stage = matches!(spec.resampling, Resampling::TwoStage { .. });
    thread::scope(|scope| {
        for (chunk_index, chunk) in out.chunks_mut(per_thread.saturating_mul(width)).enumerate() {
            let first = chunk_index.saturating_mul(per_thread);
            scope.spawn(move || {
                let mut scratch = Scratch::default();
                for (offset, row) in chunk.chunks_mut(width).enumerate() {
                    let index = u32::try_from(first.saturating_add(offset)).unwrap_or(u32::MAX);
                    let mut rng = resample_rng(spec.seed, index);
                    for (cell, model) in row.iter_mut().zip(models) {
                        *cell = resample(model, two_stage, &mut rng, &mut scratch);
                    }
                }
            });
        }
    });
    Ok(out)
}

/// Checks that every configuration has the same run count and the same
/// samples per run (review of #186, P3), and returns that shape.
fn check_configs(configs: &[&[&[u32]]]) -> Result<(usize, usize), StatsError> {
    let mut shape = None;
    for runs in configs {
        let per_run = check_runs(runs)?;
        match shape {
            None => shape = Some((runs.len(), per_run)),
            Some(seen) if seen == (runs.len(), per_run) => {}
            Some(_) => return Err(StatsError::UnequalConfigs),
        }
    }
    shape.ok_or(StatsError::Empty)
}

fn models(
    configs: &[&[&[u32]]],
    block_len: usize,
    first_level: Option<usize>,
) -> Result<Vec<Model>, StatsError> {
    let (num, den) = section8::DECISION_QUANTILE;
    configs
        .iter()
        .map(|runs| Model::new(runs, block_len, num, den, first_level))
        .collect()
}

/// Two-sided 97.5% quantiles of Student's t for 1 to 30 degrees of
/// freedom (standard tables, four decimals). Beyond 30 the value at 30 is
/// used, which is conservative.
const T_975: [f64; 30] = [
    12.7062, 4.3027, 3.1824, 2.7764, 2.5706, 2.4469, 2.3646, 2.3060, 2.2622, 2.2281, 2.2010,
    2.1788, 2.1604, 2.1448, 2.1314, 2.1199, 2.1098, 2.1009, 2.0930, 2.0860, 2.0796, 2.0739, 2.0687,
    2.0639, 2.0595, 2.0555, 2.0518, 2.0484, 2.0452, 2.0423,
];

/// `t(0.975, df)` from [`T_975`]; `df` of 0 gives +∞.
fn t_975(df: usize) -> f64 {
    match df {
        0 => f64::INFINITY,
        df => T_975
            .get(df.min(T_975.len()) - 1)
            .copied()
            .unwrap_or(f64::INFINITY),
    }
}

/// Welch's t interval of `p99.9(X) - p99.9(Y)` on the per-run p99.9
/// values (see [`Resampling::RunWelchT`]). An infinite per-run p99.9
/// makes the sign unknown: the interval is `(-∞, +∞)`.
fn run_welch_interval(x: &[&[u32]], y: &[&[u32]]) -> Result<Interval, StatsError> {
    let unknown = Interval {
        ends: Some((Value::NegInf, Value::PosInf)),
        infinite: 0,
        undefined: 0,
        resamples: 0,
    };
    let k = x.len();
    if k < 2 || y.len() != k {
        return Err(StatsError::TooFewRuns);
    }
    let moments = |runs: &[&[u32]]| -> Option<(f64, f64)> {
        let values = per_run_p999(runs)
            .into_iter()
            .map(|value| value.filter(|&v| v != MISSING).map(f64::from))
            .collect::<Option<Vec<f64>>>()?;
        let n = f64::from(u32::try_from(values.len()).ok()?);
        let mean = values.iter().sum::<f64>() / n;
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
        Some((mean, variance / n))
    };
    let (Some((mx, ex)), Some((my, ey))) = (moments(x), moments(y)) else {
        return Ok(unknown);
    };
    let each = f64::from(u32::try_from(k - 1).map_err(|_| StatsError::TooLarge)?);
    let nu = (ex + ey).powi(2) / (ex * ex / each + ey * ey / each);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let df = if nu.is_finite() {
        (nu.floor() as usize).clamp(k - 1, 2 * k - 2)
    } else {
        k - 1
    };
    let half = t_975(df) * (ex + ey).sqrt();
    let centre = mx - my;
    let (low, high) = ((centre - half).floor(), (centre + half).ceil());
    if !(low.is_finite() && high.is_finite()) {
        return Ok(unknown);
    }
    #[allow(clippy::cast_possible_truncation)]
    let ends = (Value::Finite(low as i64), Value::Finite(high as i64));
    Ok(Interval {
        ends: Some(ends),
        ..unknown
    })
}

/// The bootstrap of one point: profiles `a` and `b` against `trusted`
/// (manifest 6.2 and 8.3).
///
/// # Errors
///
/// [`StatsError`] for empty or unequal runs, a block length that does not
/// divide the run length, or zero resamples.
pub fn bootstrap_point(
    a: &[&[u32]],
    b: &[&[u32]],
    trusted: &[&[u32]],
    spec: &BootstrapSpec,
) -> Result<PointBootstrap, StatsError> {
    check_configs(&[a, b, trusted])?;
    let p999 = [pooled_p999(a)?, pooled_p999(b)?, pooled_p999(trusted)?];
    let Some(block_len) = spec.resampling.block_len() else {
        let [pa, pb, pt] = p999;
        return Ok(PointBootstrap {
            p999,
            added_a: Estimate {
                point: Value::contrast(pa, pt),
                interval: run_welch_interval(a, trusted)?,
            },
            added_b: Estimate {
                point: Value::contrast(pb, pt),
                interval: run_welch_interval(b, trusted)?,
            },
            difference: Estimate {
                point: Value::contrast(pa, pb),
                interval: run_welch_interval(a, b)?,
            },
        });
    };
    let models = models(&[a, b, trusted], block_len, None)?;
    let table = run_bootstrap(&models, spec)?;
    let mut added_a = Vec::with_capacity(table.len() / 3);
    let mut added_b = Vec::with_capacity(table.len() / 3);
    let mut difference = Vec::with_capacity(table.len() / 3);
    for &[qa, qb, qt] in table.as_chunks::<3>().0 {
        added_a.push(Value::contrast(qa, qt));
        added_b.push(Value::contrast(qb, qt));
        difference.push(Value::contrast(qa, qb));
    }
    let [pa, pb, pt] = p999;
    Ok(PointBootstrap {
        p999,
        added_a: Estimate {
            point: Value::contrast(pa, pt),
            interval: interval(&added_a),
        },
        added_b: Estimate {
            point: Value::contrast(pb, pt),
            interval: interval(&added_b),
        },
        difference: Estimate {
            point: Value::contrast(pa, pb),
            interval: interval(&difference),
        },
    })
}

/// The bootstrap of `p999(x) - p999(y)`, such as one profile's added
/// latency over `trusted`.
///
/// # Errors
///
/// As [`bootstrap_point`].
pub fn bootstrap_difference(
    x: &[&[u32]],
    y: &[&[u32]],
    spec: &BootstrapSpec,
) -> Result<Estimate, StatsError> {
    check_configs(&[x, y])?;
    let point = Value::contrast(pooled_p999(x)?, pooled_p999(y)?);
    let Some(block_len) = spec.resampling.block_len() else {
        return Ok(Estimate {
            point,
            interval: run_welch_interval(x, y)?,
        });
    };
    let models = models(&[x, y], block_len, None)?;
    let table = run_bootstrap(&models, spec)?;
    let values: Vec<Value> = table
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[qx, qy]| Value::contrast(qx, qy))
        .collect();
    Ok(Estimate {
        point,
        interval: interval(&values),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Calibration evidence only, not a production method: the
    /// delete-a-group jackknife (Kott, Journal of Official Statistics 17
    /// (2001) 521-526; Shao and Wu, Annals of Statistics 17 (1989)
    /// 1176-1197), which undercovers here (8.3% at the design CV).
    ///
    /// The leave-one-run-out pooled p99.9 values and their jackknife variance
    /// `(k - 1) / k × Σ (θ(-i) - θ̄)²`; `None` when a value is infinite.
    pub(super) fn jackknife_variance(runs: &[&[u32]]) -> Result<Option<f64>, StatsError> {
        let k = runs.len();
        if k < 2 {
            return Err(StatsError::TooFewRuns);
        }
        let mut values = Vec::with_capacity(k);
        for left_out in 0..k {
            let pooled: Vec<u32> = runs
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != left_out)
                .flat_map(|(_, run)| run.iter().copied())
                .collect();
            match p999(&pooled) {
                Some(value) if value != MISSING => values.push(f64::from(value)),
                _ => return Ok(None),
            }
        }
        let kf = f64::from(u32::try_from(k).map_err(|_| StatsError::TooLarge)?);
        let mean = values.iter().sum::<f64>() / kf;
        let squares = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>();
        Ok(Some((kf - 1.0) / kf * squares))
    }

    /// The run-jackknife t interval of `point` with the variances of its two
    /// configurations and `df` degrees of freedom (see
    /// the calibration's `k - 1` or Welch-Satterthwaite).
    pub(super) fn jackknife_interval(
        point: Value,
        variances: [Option<f64>; 2],
        df: usize,
    ) -> Interval {
        let unknown = Interval {
            ends: Some((Value::NegInf, Value::PosInf)),
            infinite: 0,
            undefined: 0,
            resamples: 0,
        };
        let (Value::Finite(point), [Some(vx), Some(vy)]) = (point, variances) else {
            return unknown;
        };
        let half = t_975(df) * (vx + vy).sqrt();
        #[allow(clippy::cast_precision_loss)]
        let centre = point as f64;
        let (low, high) = ((centre - half).floor(), (centre + half).ceil());
        if !(low.is_finite() && high.is_finite()) {
            return unknown;
        }
        #[allow(clippy::cast_possible_truncation)]
        let ends = (Value::Finite(low as i64), Value::Finite(high as i64));
        Interval {
            ends: Some(ends),
            ..unknown
        }
    }

    fn spec(resampling: Resampling, resamples: u32, seed: u64) -> BootstrapSpec {
        BootstrapSpec {
            resampling,
            resamples,
            seed,
            threads: None,
        }
    }

    /// Runs of `n` samples: a base of `base + U(0, spread)`.
    fn uniform_runs(seed: u64, runs: usize, n: usize, base: u32, spread: u64) -> Vec<Vec<u32>> {
        let mut rng = Rng::new(seed);
        (0..runs)
            .map(|_| {
                (0..n)
                    .map(|_| base + u32::try_from(rng.below(spread)).unwrap())
                    .collect()
            })
            .collect()
    }

    fn refs(runs: &[Vec<u32>]) -> Vec<&[u32]> {
        runs.iter().map(Vec::as_slice).collect()
    }

    #[test]
    fn nearest_rank_on_known_arrays() {
        let sorted: Vec<u32> = (1..=10).collect();
        assert_eq!(quantile_sorted(&sorted, 1, 2), Some(5));
        assert_eq!(quantile_sorted(&sorted, 9, 10), Some(9));
        assert_eq!(quantile_sorted(&sorted, 91, 100), Some(10));
        assert_eq!(quantile_sorted(&sorted, 1, 1), Some(10));
        assert_eq!(quantile_sorted(&sorted, 1, 100), Some(1));
        assert_eq!(quantile(&[3, 1, 2], 1, 2), Some(2));
        assert_eq!(quantile(&[], 1, 2), None);
        assert_eq!(quantile(&[7], 0, 2), None);
    }

    #[test]
    fn p999_rank_edge_cases() {
        assert_eq!(nearest_rank(1, 999, 1000), Some(1));
        assert_eq!(nearest_rank(999, 999, 1000), Some(999));
        assert_eq!(nearest_rank(1000, 999, 1000), Some(999));
        assert_eq!(nearest_rank(1001, 999, 1000), Some(1000));
        assert_eq!(nearest_rank(2000, 999, 1000), Some(1998));
        assert_eq!(nearest_rank(1_000_000, 999, 1000), Some(999_000));
        assert_eq!(nearest_rank(5_000_001, 999, 1000), Some(4_995_001));
        assert_eq!(nearest_rank(0, 999, 1000), None);
        let thousand: Vec<u32> = (1..=1000).rev().collect();
        assert_eq!(p999(&thousand), Some(999));
        let million: Vec<u32> = (1..=1_000_000).collect();
        assert_eq!(p999(&million), Some(999_000));
        // A drop ranks above every measured value.
        let mut dropped = thousand.clone();
        dropped[0] = MISSING;
        assert_eq!(p999(&dropped), Some(999));
        dropped[1] = MISSING;
        assert_eq!(p999(&dropped), Some(MISSING));
    }

    #[test]
    fn pooled_requires_equal_runs() {
        let a = [1u32, 2, 3];
        let b = [4u32, 5];
        assert_eq!(pooled_p999(&[&a, &b]), Err(StatsError::UnequalRuns));
        assert_eq!(pooled_p999(&[]), Err(StatsError::Empty));
        assert_eq!(pooled_p999(&[&a, &[7, 8, 9]]), Ok(9));
    }

    #[test]
    fn cv_and_its_exact_gate() {
        // Mean 100, squared deviations 400 over n - 1 = 4: variance 100,
        // sample sd 10, so the CV is exactly 10%, which does not exceed 10%.
        let ten = [90u32, 110, 90, 110, 100];
        assert!((cv(&ten).unwrap() - 0.1).abs() < 1e-12);
        assert_eq!(cv_exceeds(&ten, 10), Some(false));
        // Squared deviations 200: variance 50, CV 7.07%.
        let lower = [90u32, 100, 110, 100, 100];
        assert!((cv(&lower).unwrap() - 0.0707).abs() < 1e-4);
        assert_eq!(cv_exceeds(&lower, 10), Some(false));
        // 10.1%: deviations of 101 on a mean of 1000.
        let above = [899u32, 1101, 899, 1101, 1000];
        assert!((cv(&above).unwrap() - 0.101).abs() < 1e-9);
        assert_eq!(cv_exceeds(&above, 10), Some(true));
        // 9.9%.
        let below = [901u32, 1099, 901, 1099, 1000];
        assert_eq!(cv_exceeds(&below, 10), Some(false));
        assert_eq!(cv_exceeds(&[5], 10), None);
        assert_eq!(cv_exceeds(&[5, MISSING], 10), None);
    }

    #[test]
    fn binomial_mean_is_right() {
        let mut rng = Rng::new(9);
        let draws = 2000;
        let total: usize = (0..draws).map(|_| binomial(&mut rng, 10_000, 0.01)).sum();
        let mean = ratio(total, draws);
        assert!((mean - 100.0).abs() < 1.5, "{mean}");
        assert_eq!(binomial(&mut rng, 10, 1.0), 10);
        assert_eq!(binomial(&mut rng, 10, 0.0), 0);
    }

    #[test]
    fn the_same_seed_gives_the_same_interval() {
        let a = uniform_runs(1, 5, 4000, 1000, 1_000_000);
        let b = uniform_runs(2, 5, 4000, 1000, 1_000_000);
        let t = uniform_runs(3, 5, 4000, 900, 1_000_000);
        for resampling in [
            Resampling::Iid,
            Resampling::StratifiedBlocks { block_len: 8 },
            Resampling::TwoStage { block_len: 8 },
        ] {
            let mut one = spec(resampling, 400, 77);
            let first = bootstrap_point(&refs(&a), &refs(&b), &refs(&t), &one).unwrap();
            one.threads = NonZeroUsize::new(1);
            let second = bootstrap_point(&refs(&a), &refs(&b), &refs(&t), &one).unwrap();
            assert_eq!(first, second, "{resampling}");
            one.seed = 78;
            let third = bootstrap_point(&refs(&a), &refs(&b), &refs(&t), &one).unwrap();
            assert_ne!(first.difference.interval, third.difference.interval);
        }
    }

    #[test]
    fn errors() {
        let a = uniform_runs(1, 2, 10, 1, 5);
        let s = spec(Resampling::StratifiedBlocks { block_len: 3 }, 10, 0);
        assert!(matches!(
            bootstrap_difference(&refs(&a), &refs(&a), &s),
            Err(StatsError::BlockLength { .. })
        ));
        let s = spec(Resampling::Iid, 0, 0);
        assert_eq!(
            bootstrap_difference(&refs(&a), &refs(&a), &s),
            Err(StatsError::NoResamples)
        );
        // Configurations must match in run count and samples per run.
        let s = spec(Resampling::Iid, 10, 0);
        let three = uniform_runs(2, 3, 10, 1, 5);
        let longer = uniform_runs(3, 2, 20, 1, 5);
        assert_eq!(
            bootstrap_difference(&refs(&a), &refs(&three), &s),
            Err(StatsError::UnequalConfigs)
        );
        assert_eq!(
            bootstrap_point(&refs(&a), &refs(&a), &refs(&longer), &s),
            Err(StatsError::UnequalConfigs)
        );
        let one = uniform_runs(4, 1, 10, 1, 5);
        assert_eq!(
            bootstrap_difference(&refs(&one), &refs(&one), &spec(Resampling::RunWelchT, 1, 0)),
            Err(StatsError::TooFewRuns)
        );
    }

    #[test]
    fn run_welch_t_interval() {
        // Constant runs: each run's p99.9 is its value. x: 100..=140 by
        // 10, mean 120, s² 250, s²/k 50; y: all 100, s² 0. Welch df
        // 50² / (50² / 4) = 4, t(0.975, 4) = 2.7764, se sqrt(50): the
        // interval is 20 ± 19.63, rounded outwards to (0, 40).
        let x: Vec<Vec<u32>> = [100u32, 110, 120, 130, 140]
            .iter()
            .map(|&v| vec![v; 1000])
            .collect();
        let y: Vec<Vec<u32>> = vec![vec![100u32; 1000]; 5];
        let welch = spec(Resampling::RunWelchT, 1, 0);
        let estimate = bootstrap_difference(&refs(&x), &refs(&y), &welch).unwrap();
        // The point estimate stays the pooled p99.9 (H-1): 140 - 100.
        assert_eq!(estimate.point, Value::Finite(40));
        assert_eq!(
            estimate.interval.ends,
            Some((Value::Finite(0), Value::Finite(40)))
        );
        assert_eq!(estimate.interval.resamples, 0);
        // Equal variances: df = 100² / (2 × 50² / 4) = 8, t = 2.3060,
        // se 10: 10 ± 23.06, rounded outwards to (-14, 34).
        let z: Vec<Vec<u32>> = [90u32, 100, 110, 120, 130]
            .iter()
            .map(|&v| vec![v; 1000])
            .collect();
        let estimate = bootstrap_difference(&refs(&x), &refs(&z), &welch).unwrap();
        assert_eq!(
            estimate.interval.ends,
            Some((Value::Finite(-14), Value::Finite(34)))
        );
        // An infinite per-run p99.9 makes the sign unknown.
        let mut dropped = y.clone();
        for run in &mut dropped {
            run[..2].fill(MISSING);
        }
        let estimate = bootstrap_difference(&refs(&x), &refs(&dropped), &welch).unwrap();
        assert_eq!(estimate.interval.ends, Some((Value::NegInf, Value::PosInf)));
        // The three intervals of a point.
        let point = bootstrap_point(&refs(&x), &refs(&z), &refs(&y), &welch).unwrap();
        assert_eq!(
            point.difference.interval.ends.unwrap().0,
            Value::Finite(-14)
        );
        assert_eq!(point.added_a.interval.ends.unwrap().1, Value::Finite(40));
        assert_eq!(t_975(4), 2.7764);
        assert_eq!(t_975(100), 2.0423);
        assert!(t_975(0).is_infinite());
    }

    #[test]
    fn calibration_jackknife_helper() {
        // Pooled p99.9 of 4 runs of 1000 is rank 3996 of 4000: the 4th
        // largest. With constant runs the leave-one-out p99.9 is the
        // largest remaining run value: 140, 140, 140, 140, 130; mean 138,
        // Σ squares 80, V = 4/5 × 80 = 64, sd 8; t(0.975, 4) = 2.7764.
        let x: Vec<Vec<u32>> = [100u32, 110, 120, 130, 140]
            .iter()
            .map(|&v| vec![v; 1000])
            .collect();
        let variance = jackknife_variance(&refs(&x)).unwrap();
        assert_eq!(variance, Some(64.0));
        let found = jackknife_interval(Value::Finite(40), [variance, Some(0.0)], 4);
        assert_eq!(found.ends, Some((Value::Finite(17), Value::Finite(63))));
    }

    #[test]
    fn warmup_ends_on_a_block_boundary() {
        assert_eq!(warmup_per_run(21), 100_002);
        assert_eq!(warmup_per_run(21) % 21, 0);
        assert_eq!(warmup_per_run(64), 100_032);
        assert_eq!(warmup_per_run(1), 100_000);
    }

    /// The naive resampler: every block drawn explicitly.
    fn naive(
        runs: &[&[u32]],
        block_len: usize,
        two_stage: bool,
        rng: &mut Rng,
        num: u64,
        den: u64,
    ) -> u32 {
        let r = runs.len();
        let mut pooled = Vec::new();
        for slot in 0..r {
            let run = if two_stage {
                runs[usize::try_from(rng.below(r as u64)).unwrap()]
            } else {
                runs[slot]
            };
            let blocks = run.len() / block_len;
            for _ in 0..blocks {
                let block = usize::try_from(rng.below(blocks as u64)).unwrap();
                pooled.extend_from_slice(&run[block * block_len..(block + 1) * block_len]);
            }
        }
        quantile(&pooled, num, den).unwrap()
    }

    fn ecdf_distance(mut x: Vec<u32>, mut y: Vec<u32>) -> f64 {
        x.sort_unstable();
        y.sort_unstable();
        let mut values: Vec<u32> = x.iter().chain(&y).copied().collect();
        values.sort_unstable();
        values.dedup();
        let n = x.len() as f64;
        let m = y.len() as f64;
        values
            .iter()
            .map(|&v| {
                let fx = x.partition_point(|&s| s <= v) as f64 / n;
                let fy = y.partition_point(|&s| s <= v) as f64 / m;
                (fx - fy).abs()
            })
            .fold(0.0, f64::max)
    }

    #[test]
    fn tail_resampling_agrees_with_naive_resampling() {
        // Three runs with a between-run shift, ties and clustered highs.
        let mut rng = Rng::new(5);
        let runs: Vec<Vec<u32>> = (0..3u32)
            .map(|run| {
                (0..600)
                    .map(|i| {
                        let burst = (i / 30) % 7 == run;
                        let base = 100 + run * 15 + u32::try_from(rng.below(40)).unwrap();
                        if burst { base + 200 } else { base }
                    })
                    .collect()
            })
            .collect();
        let runs = refs(&runs);
        // Two-sample Kolmogorov-Smirnov bound at about alpha = 0.001 for
        // 8000 draws each: 1.95 * sqrt(2 / 8000) = 0.031.
        let draws = 8_000;
        for (num, den) in [(999, 1000), (9, 10)] {
            for (block_len, two_stage) in [(1, false), (5, false), (5, true), (30, true)] {
                // A first level of exactly the quantile's rank from the top
                // forces frequent band extensions.
                let model = Model::new(&runs, block_len, num, den, Some(1)).unwrap();
                let mut scratch = Scratch::default();
                let fast: Vec<u32> = (0..draws)
                    .map(|i| resample(&model, two_stage, &mut resample_rng(11, i), &mut scratch))
                    .collect();
                let mut naive_rng = Rng::new(12);
                let slow: Vec<u32> = (0..draws)
                    .map(|_| naive(&runs, block_len, two_stage, &mut naive_rng, num, den))
                    .collect();
                let distance = ecdf_distance(fast, slow);
                assert!(
                    distance < 0.031,
                    "q {num}/{den}, block {block_len}, two stage {two_stage}: {distance}"
                );
            }
        }
    }

    #[test]
    fn a_full_first_level_is_the_quantile_of_the_resample() {
        // With one run, block length n and stratified resampling, every
        // resample is the run itself.
        let run: Vec<u32> = (0..1000).collect();
        let model = Model::new(&[&run], 1000, 999, 1000, None).unwrap();
        let mut scratch = Scratch::default();
        for i in 0..20 {
            assert_eq!(
                resample(&model, false, &mut resample_rng(1, i), &mut scratch),
                998
            );
        }
    }

    #[test]
    fn drops_make_the_interval_unbounded() {
        let mut a = uniform_runs(1, 5, 2000, 1000, 100);
        let t = uniform_runs(2, 5, 2000, 1000, 100);
        // Three drops per run: above 0.1%, p99.9 is infinite.
        for run in &mut a {
            run[0] = MISSING;
            run[1] = MISSING;
            run[2] = MISSING;
        }
        let estimate =
            bootstrap_difference(&refs(&a), &refs(&t), &spec(Resampling::Iid, 200, 1)).unwrap();
        assert_eq!(estimate.point, Value::PosInf);
        assert!(estimate.interval.infinite > 0);
        assert_eq!(
            estimate.interval.ends.map(|(_, high)| high),
            Some(Value::PosInf)
        );
    }

    #[test]
    fn infinite_contrasts() {
        assert_eq!(Value::contrast(MISSING, 5), Value::PosInf);
        assert_eq!(Value::contrast(5, MISSING), Value::NegInf);
        assert_eq!(Value::contrast(MISSING, MISSING), Value::Undefined);
        assert_eq!(Value::contrast(7, 5), Value::Finite(2));
        assert!(Value::NegInf < Value::Finite(i64::MIN));
        assert!(Value::Finite(i64::MAX) < Value::PosInf);
    }

    #[test]
    fn undefined_resamples_have_an_unknown_sign() {
        // 1000 resamples: 990 finite in 1..=990 and 10 undefined (1%).
        let mut values: Vec<Value> = (1..=990).map(Value::Finite).collect();
        values.extend(std::iter::repeat_n(Value::Undefined, 10));
        let found = interval(&values);
        assert_eq!(
            (found.infinite, found.undefined, found.resamples),
            (0, 10, 1000)
        );
        // Ranks 25 and 975 of 1000. Low: the 10 undefined count as -inf
        // first, so it is the 15th finite value; high: they count as +inf
        // last, so it is the 975th finite value.
        assert_eq!(found.ends, Some((Value::Finite(15), Value::Finite(975))));
        assert!(!found.contains_zero());
        assert!(!found.too_many_undefined());
        // The order of the input does not matter.
        values.reverse();
        assert_eq!(interval(&values), found);
        // 30 undefined (3%): excluding them would leave a lower end of 25,
        // a win; with an unknown sign the lower end is -inf, the interval
        // contains 0, and the point is too undefined to classify.
        let mut edge: Vec<Value> = (1..=970).map(Value::Finite).collect();
        edge.extend(std::iter::repeat_n(Value::Undefined, 30));
        let found = interval(&edge);
        assert_eq!(found.ends, Some((Value::NegInf, Value::PosInf)));
        assert!(found.contains_zero());
        assert!(found.too_many_undefined());
        // Exactly 2.5% is not more than 2.5%.
        let mut limit: Vec<Value> = (1..=975).map(Value::Finite).collect();
        limit.extend(std::iter::repeat_n(Value::Undefined, 25));
        assert!(!interval(&limit).too_many_undefined());
        // An infinite end is a tie only if the interval contains 0.
        let positive: Vec<Value> = (1..=40)
            .map(Value::Finite)
            .chain([Value::PosInf; 5])
            .collect();
        let found = interval(&positive);
        assert_eq!(found.ends, Some((Value::Finite(2), Value::PosInf)));
        assert!(!found.contains_zero());
        assert_eq!(found.infinite, 5);
        let negative: Vec<Value> = std::iter::repeat_n(Value::NegInf, 39)
            .chain([Value::Finite(-1)])
            .collect();
        assert!(!interval(&negative).contains_zero());
        // All undefined: both ends infinite. No resample: no interval.
        let all = interval(&[Value::Undefined; 4]);
        assert_eq!(all.ends, Some((Value::NegInf, Value::PosInf)));
        assert!(all.too_many_undefined());
        let none = interval(&[]);
        assert_eq!(none.ends, None);
        assert!(!none.contains_zero());
    }

    #[test]
    fn block_lengths() {
        assert_eq!(block_len(Shape::W5, 64), Ok(21));
        assert_eq!(block_len(Shape::W1, 64), Ok(DEFAULT_BLOCK_LEN));
        assert_eq!(samples_per_run(21), 1_000_020);
        assert_eq!(samples_per_run(64), 1_000_000);
        assert_eq!(samples_per_run(1), 1_000_000);
    }

    /// Messages per burst in the calibration data, and the block length of
    /// the block methods.
    const BURST: usize = 50;

    /// Synthetic runs with a between-run shift and clustered tails. Each
    /// run is shifted by `U(0, shift)` ns; a message is `1000 + U(0, 200)`
    /// ns, and with probability 1/2000 a burst of [`BURST`] consecutive
    /// messages at a common level `3000 + U(0, 1500)` (+ `U(0, 100)` each)
    /// starts instead.
    fn clustered_runs(rng: &mut Rng, runs: usize, n: usize, shift: u64) -> Vec<Vec<u32>> {
        (0..runs)
            .map(|_| {
                let shift = u32::try_from(rng.below(shift)).unwrap();
                let mut run = Vec::with_capacity(n + BURST);
                while run.len() < n {
                    if rng.below(2000) == 0 {
                        let level = 3000 + u32::try_from(rng.below(1500)).unwrap();
                        for _ in 0..BURST {
                            run.push(level + shift + u32::try_from(rng.below(100)).unwrap());
                        }
                    } else {
                        run.push(1000 + shift + u32::try_from(rng.below(200)).unwrap());
                    }
                }
                run.truncate(n);
                run
            })
            .collect()
    }

    /// One calibration case.
    #[derive(Debug, Clone, Copy)]
    struct Case {
        runs: usize,
        samples: usize,
        shift: u64,
        replications: u32,
        resamples: u32,
    }

    /// The methods compared, in the order of a result row.
    const METHODS: [&str; 7] = [
        "iid",
        "stratified blocks of 50 (default)",
        "two stage, blocks of 50",
        "run jackknife of pooled p99.9, t(k - 1)",
        "run jackknife of pooled p99.9, t(Welch df)",
        "run-level t, Student, t(2k - 2)",
        "run-level t, Welch df (RunWelchT)",
    ];

    /// Mean and sample variance of the per-run p99.9 values.
    fn run_moments(runs: &[&[u32]]) -> (f64, f64) {
        let values: Vec<f64> = per_run_p999(runs)
            .into_iter()
            .map(|v| f64::from(v.unwrap()))
            .collect();
        let k = values.len() as f64;
        let mean = values.iter().sum::<f64>() / k;
        let var = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (k - 1.0);
        (mean, var)
    }

    /// Whether `centre ± t(df) × se` excludes zero.
    fn t_excludes(centre: f64, se: f64, df: usize) -> bool {
        let half = t_975(df) * se;
        centre - half > 0.0 || centre + half < 0.0
    }

    /// One A/A replication: whether each method's interval excludes zero,
    /// and the per-run p99.9 CV of each configuration.
    fn replicate(case: Case, replication: u32) -> ([bool; 7], [f64; 2]) {
        let mut rng = resample_rng(0x00CA_11B8_A7E0, replication);
        let a = clustered_runs(&mut rng, case.runs, case.samples, case.shift);
        let b = clustered_runs(&mut rng, case.runs, case.samples, case.shift);
        let (ra, rb) = (refs(&a), refs(&b));
        let run_cv = |runs: &[&[u32]]| {
            let values: Vec<u32> = per_run_p999(runs).into_iter().map(Option::unwrap).collect();
            cv(&values).unwrap()
        };
        let cvs = [run_cv(&ra), run_cv(&rb)];
        let mut excluded = [false; 7];
        let methods = [
            Resampling::Iid,
            Resampling::StratifiedBlocks { block_len: BURST },
            Resampling::TwoStage { block_len: BURST },
        ];
        let mut built: Option<(usize, Vec<Model>)> = None;
        for (slot, resampling) in excluded.iter_mut().zip(methods) {
            let block_len = resampling.block_len().unwrap();
            if built.as_ref().map(|(len, _)| *len) != Some(block_len) {
                drop(built.take());
                built = Some((block_len, models(&[&ra, &rb], block_len, None).unwrap()));
            }
            let spec = BootstrapSpec {
                resampling,
                resamples: case.resamples,
                seed: u64::from(replication),
                threads: NonZeroUsize::new(1),
            };
            let table = run_bootstrap(&built.as_ref().unwrap().1, &spec).unwrap();
            let values: Vec<Value> = table
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&[x, y]| Value::contrast(x, y))
                .collect();
            *slot = !interval(&values).contains_zero();
        }
        drop(built);
        let point = Value::contrast(pooled_p999(&ra).unwrap(), pooled_p999(&rb).unwrap());
        let (va, vb) = (
            jackknife_variance(&ra).unwrap().unwrap(),
            jackknife_variance(&rb).unwrap().unwrap(),
        );
        excluded[3] =
            !jackknife_interval(point, [Some(va), Some(vb)], case.runs - 1).contains_zero();
        // Welch-Satterthwaite with k - 1 degrees of freedom per variance,
        // rounded down (Welch, Biometrika 34 (1947) 28-35).
        let each = (case.runs - 1) as f64;
        let nu = (va + vb).powi(2) / (va * va / each + vb * vb / each);
        let df = if nu.is_finite() {
            nu.floor() as usize
        } else {
            case.runs - 1
        };
        excluded[4] = !jackknife_interval(point, [Some(va), Some(vb)], df).contains_zero();
        // Run-level t intervals on the per-run p99.9 values: Student's
        // two-sample t with pooled variance and 2k - 2 degrees of freedom,
        // and Welch's with the Welch-Satterthwaite df rounded down.
        let ((ma, sa), (mb, sb)) = (run_moments(&ra), run_moments(&rb));
        let k = case.runs as f64;
        let pooled = (sa + sb) / 2.0;
        excluded[5] = t_excludes(ma - mb, (pooled * 2.0 / k).sqrt(), 2 * case.runs - 2);
        let (ea, eb) = (sa / k, sb / k);
        let nu = (ea + eb).powi(2) / (ea * ea / each + eb * eb / each);
        let df = if nu.is_finite() {
            nu.floor() as usize
        } else {
            case.runs - 1
        };
        excluded[6] = t_excludes(ma - mb, (ea + eb).sqrt(), df);
        (excluded, cvs)
    }

    /// Runs a case on parallel workers; every replication is seeded by
    /// its index, so the result does not depend on the worker count.
    /// Returns the exclusion counts and the mean per-run p99.9 CV.
    #[allow(clippy::print_stderr)]
    fn calibrate(case: Case) -> ([u32; 7], f64) {
        // About 32 bytes per sample are live in one replication.
        let per_replication = case.runs * case.samples * 2 * 32;
        let workers = thread::available_parallelism()
            .map_or(1, NonZeroUsize::get)
            .min((4usize << 30) / per_replication)
            .max(1);
        let started = std::time::Instant::now();
        let results: Vec<([bool; 7], [f64; 2])> = thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|worker| {
                    scope.spawn(move || {
                        (0..case.replications)
                            .filter(|r| usize::try_from(*r).unwrap() % workers == worker)
                            .map(|r| replicate(case, r))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect()
        });
        let mut counts = [0u32; 7];
        let mut cv_sum = 0.0;
        for (excluded, cvs) in &results {
            for (count, &hit) in counts.iter_mut().zip(excluded) {
                *count += u32::from(hit);
            }
            cv_sum += cvs[0] + cvs[1];
        }
        let mean_cv = cv_sum / (2.0 * f64::from(case.replications));
        let reps = f64::from(case.replications);
        eprintln!(
            "calibration k = {} runs x {} samples, shift U(0, {}) ns, {} replications, {} \
             resamples: mean per-run p99.9 CV {:.2}% ({:.0?}, {workers} workers)",
            case.runs,
            case.samples,
            case.shift,
            case.replications,
            case.resamples,
            100.0 * mean_cv,
            started.elapsed(),
        );
        for (name, &count) in METHODS.iter().zip(&counts) {
            let rate = f64::from(count) / reps;
            let half = 1.96 * (rate * (1.0 - rate) / reps).sqrt();
            eprintln!(
                "  {name}: A/A non-tie rate {:.1}% +/- {:.1}% ({count}/{})",
                100.0 * rate,
                100.0 * half,
                case.replications
            );
        }
        (counts, mean_cv)
    }

    /// The run shift that gives the design's per-run p99.9 CV of about 8%
    /// with this generator (measured by [`calibrate`] and printed).
    const DESIGN_SHIFT: u64 = 1500;

    /// Calibration at the design CV (review of #186, ACS 14914): the A/A
    /// rate at which a method's 95% interval of the difference excludes
    /// zero, with a between-run shift and clustered tails, at the
    /// decision's 5 runs × 10^6 messages and, for sensitivity, at 5 × 10^4
    /// messages per run. Only the chosen method's rate is asserted.
    ///
    /// Measured on 2026-10-16 (Apple M5 Max, release, 2000 replications,
    /// 1000 resamples; mean per-run p99.9 CV 7.98% at 10^6 and 8.21% at
    /// 5 × 10^4 messages per run), A/A rate of an interval excluding zero
    /// at 10^6 (and 5 × 10^4) messages per run, ± 95% binomial half-width
    /// of about 1%:
    ///
    /// | Method | 10^6 | 5 × 10^4 |
    /// | --- | --- | --- |
    /// | iid | 97.2% | 90.1% |
    /// | stratified blocks of 50 (default) | 86.0% | 52.6% |
    /// | two stage, blocks of 50 | 14.7% | 11.7% |
    /// | run jackknife of pooled p99.9, t(k - 1) | 8.3% | 7.8% |
    /// | run jackknife of pooled p99.9, t(Welch df) | 10.2% | 9.1% |
    /// | run-level Student t, t(2k - 2) | 5.9% | 5.9% |
    /// | run-level Welch t (`RunWelchT`) | 4.8% | 4.9% |
    ///
    /// Fewer messages per run add within-run noise that hides part of the
    /// between-run variance, so 5 × 10^4 understates the undercoverage of
    /// the resampling methods. Heavy (about 4 minutes): run with
    /// `cargo test --release -p karyos-bench -- --ignored calibration_at --nocapture`.
    #[test]
    #[ignore = "heavy calibration, run in release"]
    fn calibration_at_design_cv() {
        let design = Case {
            runs: 5,
            samples: 1_000_000,
            shift: DESIGN_SHIFT,
            replications: 2000,
            resamples: 1000,
        };
        let (counts, mean_cv) = calibrate(design);
        assert!((0.075..=0.085).contains(&mean_cv), "CV {mean_cv}");
        let small = Case {
            samples: 50_000,
            ..design
        };
        calibrate(small);
        // Only the chosen method is asserted: RunWelchT near 5%.
        let rate = f64::from(counts[6]) / f64::from(design.replications);
        assert!(rate <= 0.07, "run-level Welch t rate {rate}");
    }

    /// The run count each method needs at the design CV (review of #186):
    /// k = 5, 10 and 20 runs of 10^6 messages, 500 replications each
    /// (± about 2%).
    ///
    /// Measured on 2026-10-16 (mean per-run p99.9 CV 7.98%, 8.13%, 8.23%):
    ///
    /// | Method | k = 5 | k = 10 | k = 20 |
    /// | --- | --- | --- | --- |
    /// | iid | 97.0% | 98.2% | 97.4% |
    /// | stratified blocks of 50 (default) | 84.8% | 89.6% | 86.4% |
    /// | two stage, blocks of 50 | 12.4% | 9.0% | 6.2% |
    /// | run jackknife of pooled p99.9, t(k - 1) | 8.2% | 6.6% | 4.0% |
    /// | run jackknife of pooled p99.9, t(Welch df) | 9.4% | 7.0% | 4.8% |
    /// | run-level Student t, t(2k - 2) | 5.8% | 6.0% | 4.2% |
    /// | run-level Welch t (`RunWelchT`) | 4.6% | 5.4% | 4.2% |
    ///
    /// Two stage resampling needs about 20 runs to approach 5%; fixed run
    /// strata never do, whatever the run count. Heavy (about 25 minutes):
    /// run with
    /// `cargo test --release -p karyos-bench -- --ignored calibration_runs --nocapture`.
    #[test]
    #[ignore = "heavy calibration, run in release"]
    fn calibration_runs_sweep() {
        for runs in [5, 10, 20] {
            calibrate(Case {
                runs,
                samples: 1_000_000,
                shift: DESIGN_SHIFT,
                replications: 500,
                resamples: 1000,
            });
        }
    }

    /// The decision-size bootstrap: 3 configurations of 5 runs × 10^6
    /// samples, 10 000 resamples. Run with
    /// `cargo test --release -p karyos-bench -- --ignored decision_size --nocapture`.
    #[test]
    #[ignore = "timing, run in release"]
    #[allow(clippy::print_stderr)]
    fn decision_size_bootstrap_completes() {
        let mut rng = Rng::new(3);
        let mut make = |offset: u32| -> Vec<Vec<u32>> {
            (0..5)
                .map(|_| {
                    (0..1_000_000)
                        .map(|_| {
                            let tail = if rng.below(1000) == 0 { 2000 } else { 0 };
                            offset + tail + u32::try_from(rng.below(800)).unwrap()
                        })
                        .collect()
                })
                .collect()
        };
        let a = make(1100);
        let b = make(1150);
        let t = make(1000);
        for resampling in [
            Resampling::StratifiedBlocks { block_len: 1 },
            Resampling::StratifiedBlocks { block_len: 20 },
            Resampling::TwoStage { block_len: 20 },
        ] {
            let start = std::time::Instant::now();
            let result = bootstrap_point(
                &refs(&a),
                &refs(&b),
                &refs(&t),
                &BootstrapSpec::manifest(resampling, 1),
            )
            .unwrap();
            eprintln!(
                "decision size, {resampling}: {:?} on {} threads; {result:?}",
                start.elapsed(),
                thread::available_parallelism().map_or(1, NonZeroUsize::get)
            );
            assert!(result.difference.interval.is_bounded());
        }
    }
}
