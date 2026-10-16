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
//!   stratified scheme with a block of one.
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
}

impl Resampling {
    /// The default: [`Resampling::StratifiedBlocks`] with `block_len`.
    #[must_use]
    pub const fn default_with(block_len: usize) -> Self {
        Self::StratifiedBlocks { block_len }
    }

    const fn block_len(self) -> usize {
        match self {
            Self::Iid => 1,
            Self::StratifiedBlocks { block_len } | Self::TwoStage { block_len } => block_len,
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

/// A percentile interval of a resampled contrast.
///
/// **Undefined resamples** (`∞ - ∞`) are excluded and counted: the ends
/// are the nearest ranks 2.5% and 97.5% of the remaining resamples,
/// ordered `-∞ < finite < +∞`. An end may be infinite. When every resample
/// is undefined there is no interval ([`Interval::ends`] is `None`), and
/// the point cannot be classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    /// The 2.5% and 97.5% ends, `None` when every resample is undefined.
    pub ends: Option<(Value, Value)>,
    /// Resamples with an infinite contrast (`±∞`), reported.
    pub infinite: u32,
    /// Resamples with an undefined contrast (`∞ - ∞`), excluded, reported.
    pub undefined: u32,
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
    let mut sorted: Vec<Value> = values
        .iter()
        .copied()
        .filter(|v| *v != Value::Undefined)
        .collect();
    sorted.sort_unstable();
    let tail = u64::from((1000 - section8::CONFIDENCE_PER_MILLE) / 2);
    let n = u64::try_from(sorted.len()).unwrap_or(u64::MAX);
    let at = |num: u64| {
        nearest_rank(n, num, 1000)
            .and_then(|rank| usize::try_from(rank - 1).ok())
            .and_then(|index| sorted.get(index).copied())
    };
    let ends = at(tail).zip(at(1000 - tail));
    Interval {
        ends,
        infinite,
        undefined,
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

fn models(
    configs: &[&[&[u32]]],
    resampling: Resampling,
    first_level: Option<usize>,
) -> Result<Vec<Model>, StatsError> {
    let (num, den) = section8::DECISION_QUANTILE;
    configs
        .iter()
        .map(|runs| Model::new(runs, resampling.block_len(), num, den, first_level))
        .collect()
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
    let models = models(&[a, b, trusted], spec.resampling, None)?;
    let table = run_bootstrap(&models, spec)?;
    let p999 = [pooled_p999(a)?, pooled_p999(b)?, pooled_p999(trusted)?];
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
    let models = models(&[x, y], spec.resampling, None)?;
    let table = run_bootstrap(&models, spec)?;
    let values: Vec<Value> = table
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[qx, qy]| Value::contrast(qx, qy))
        .collect();
    Ok(Estimate {
        point: Value::contrast(pooled_p999(x)?, pooled_p999(y)?),
        interval: interval(&values),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // mean 100, sample sd 10: cv exactly 10%.
        let exact = [90u32, 100, 110, 100, 100];
        // Sum of squared deviations 200, n - 1 = 4: variance 50. Use a set
        // whose variance is exactly 100: deviations -10, +10, -10, +10, 0
        // give 400 / 4 = 100.
        let ten = [90u32, 110, 90, 110, 100];
        assert!((cv(&ten).unwrap() - 0.1).abs() < 1e-12);
        assert_eq!(cv_exceeds(&ten, 10), Some(false));
        assert_eq!(cv_exceeds(&exact, 10), Some(false));
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
    fn undefined_resamples_are_excluded_and_counted() {
        // 40 resamples: 10 undefined, 2 at +inf, the rest finite -14..=13.
        let mut values: Vec<Value> = (-14..14).map(Value::Finite).collect();
        values.extend([Value::PosInf, Value::PosInf]);
        values.extend(std::iter::repeat_n(Value::Undefined, 10));
        let found = interval(&values);
        assert_eq!((found.infinite, found.undefined), (2, 10));
        // 30 ordered values: ranks ceil(0.75) = 1 and ceil(29.25) = 30.
        assert_eq!(found.ends, Some((Value::Finite(-14), Value::PosInf)));
        assert!(found.contains_zero());
        assert!(!found.is_bounded());
        // The order of the input does not matter.
        values.reverse();
        assert_eq!(interval(&values), found);
        // An infinite end is a tie only if the interval contains 0.
        let positive: Vec<Value> = (1..=40)
            .map(Value::Finite)
            .chain([Value::PosInf; 5])
            .collect();
        let found = interval(&positive);
        assert_eq!(found.ends, Some((Value::Finite(2), Value::PosInf)));
        assert!(!found.contains_zero());
        let negative: Vec<Value> = std::iter::repeat_n(Value::NegInf, 39)
            .chain([Value::Finite(-1)])
            .collect();
        assert!(!interval(&negative).contains_zero());
        // All undefined: no interval.
        let none = interval(&[Value::Undefined; 4]);
        assert_eq!((none.ends, none.undefined), (None, 4));
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

    /// Synthetic runs with a between-run shift and clustered tails: bursts
    /// of `burst` consecutive slow messages.
    fn clustered_runs(rng: &mut Rng, runs: usize, n: usize, burst: usize) -> Vec<Vec<u32>> {
        (0..runs)
            .map(|_| {
                let shift = u32::try_from(rng.below(300)).unwrap();
                let mut run = Vec::with_capacity(n);
                while run.len() < n {
                    if rng.below(2000) == 0 {
                        let level = 3000 + u32::try_from(rng.below(1500)).unwrap();
                        for _ in 0..burst {
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

    /// Calibration (coordinator, ACS 14831): the A/A rate at which the
    /// interval of the difference excludes zero, for each resampling, on
    /// data with a between-run shift and clustered tails. Only the two
    /// stage rate is asserted; the other rates are printed and recorded
    /// here. The data: 5 runs of 50 000 messages per configuration, each
    /// run shifted by U(0, 300) ns, a base of 1000 + U(0, 200) ns, and
    /// bursts of 50 consecutive messages at 3000 + U(0, 1500) ns starting
    /// with probability 1/2000 per message; 1000 resamples per interval.
    ///
    /// Measured on 2026-10-16 (1000 replications, Apple M5 Max, release):
    /// iid 84.6%, stratified blocks of 50 (the default) 28.0%, two stage
    /// 5.3%. Fixed run strata do not carry the between-run variance, so
    /// with run-to-run shifts the default's interval is too narrow; this
    /// is the evidence for the pending manifest 1.1 question (ACS 14831).
    /// Heavy: run with
    /// `cargo test --release -p karyos-bench -- --ignored calibration --nocapture`.
    #[test]
    #[ignore = "heavy calibration, run in release"]
    #[allow(clippy::print_stderr)]
    fn calibration_a_a_non_tie_rate() {
        let replications = 1000u32;
        let burst = 50;
        let variants = [
            Resampling::Iid,
            Resampling::StratifiedBlocks { block_len: burst },
            Resampling::TwoStage { block_len: burst },
        ];
        let mut rates = Vec::new();
        for resampling in variants {
            let mut rng = Rng::new(2026);
            let mut excluded = 0u32;
            for replication in 0..replications {
                let a = clustered_runs(&mut rng, 5, 50_000, burst);
                let b = clustered_runs(&mut rng, 5, 50_000, burst);
                let estimate = bootstrap_difference(
                    &refs(&a),
                    &refs(&b),
                    &spec(resampling, 1000, u64::from(replication)),
                )
                .unwrap();
                if !estimate.interval.contains_zero() {
                    excluded += 1;
                }
            }
            let rate = f64::from(excluded) / f64::from(replications);
            eprintln!(
                "calibration: {resampling}: A/A non-tie rate {rate:.3} ({excluded}/{replications})"
            );
            rates.push(rate);
        }
        assert!(rates[2] <= 0.075, "two stage rate {}", rates[2]);
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
