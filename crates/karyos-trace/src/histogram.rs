// SPDX-License-Identifier: Apache-2.0

//! Latency histograms (design in `quantstratum-docs: karyos/design/trace-histograms.md`): the
//! aggregation primitive for latency intervals, used on the collector side,
//! never inside the publication operation.
//!
//! A latency is an interval `[min, max]`; the histogram keeps one
//! distribution of the `min` bounds and one of the `max` bounds over the
//! same population. The `k`-th smallest true latency lies between the
//! `k`-th smallest `min` and the `k`-th smallest `max`, so a quantile is
//! reported as an interval: the lowest value of the bucket holding the
//! `k`-th `min` and the highest value of the bucket holding the `k`-th
//! `max`. Buckets are HDR-style (log-linear, declared precision, fixed
//! memory) with their own guarantee and no format interoperability.

use crate::clocks::{Latency, Unavailable};

/// Bounds of the significant decimal digits.
const MIN_DIGITS: u8 = 1;
const MAX_DIGITS: u8 = 5;

/// Errors of histograms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HistogramError {
    /// The digits or the highest magnitude are out of range, or the table
    /// does not fit or cannot be allocated.
    #[error("invalid histogram configuration")]
    InvalidConfig,
    /// A latency interval with `min > max`.
    #[error("latency interval with min above max")]
    InvalidInterval,
    /// A quantile with a zero denominator or above 1.
    #[error("invalid quantile")]
    InvalidQuantile,
    /// A count would overflow. No count was changed; `record` also marks
    /// the histogram incomplete, `merge` leaves the destination entirely
    /// unchanged.
    #[error("histogram count overflow")]
    Overflow,
    /// Merging histograms of different layouts or units.
    #[error("histograms differ in layout or unit")]
    Mismatch,
    /// Exported counts name a bucket outside the layout, name one twice,
    /// or do not add up to their population (R-CORE-23).
    #[error("histogram counts out of range or inconsistent")]
    InvalidCounts,
}

/// The bucket layout: `d` significant digits up to a highest magnitude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    digits: u8,
    highest: u64,
    /// `S`: the smallest power of two at least `2 * 10^d`.
    sub_count: u64,
    /// `log2 S`.
    sub_bits: u32,
    /// Buckets in `0 ..= highest`.
    len: usize,
}

impl Layout {
    fn new(digits: u8, highest: u64) -> Option<Self> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) || !(1..=1u64 << 63).contains(&highest) {
            return None;
        }
        let target = 2u64.checked_mul(10u64.checked_pow(u32::from(digits))?)?;
        let sub_count = target.checked_next_power_of_two()?;
        let mut layout = Self {
            digits,
            highest,
            sub_count,
            sub_bits: sub_count.trailing_zeros(),
            len: 0,
        };
        layout.len = layout.index(highest)?.checked_add(1)?;
        Some(layout)
    }

    fn half(&self) -> u64 {
        self.sub_count / 2
    }

    /// The bucket index of magnitude `value` (which may exceed `highest`;
    /// the caller checks the range).
    fn index(&self, value: u64) -> Option<usize> {
        if value < self.sub_count {
            return usize::try_from(value).ok();
        }
        let log2 = 63 - value.leading_zeros();
        let level = u64::from(log2 - self.sub_bits + 1);
        let sub = value >> level;
        let index = self
            .sub_count
            .checked_add((level - 1).checked_mul(self.half())?)?
            .checked_add(sub - self.half())?;
        usize::try_from(index).ok()
    }

    /// The inclusive magnitude range of bucket `index`, cut at `highest`.
    fn bucket(&self, index: usize) -> (u64, u64) {
        let index = index as u64;
        let (low, high) = if index < self.sub_count {
            (index, index)
        } else {
            let relative = index - self.sub_count;
            let level = relative / self.half() + 1;
            let sub = relative % self.half() + self.half();
            let low = sub << level;
            (low, low + ((1u64 << level) - 1))
        };
        (low, high.min(self.highest))
    }
}

/// One side (all `min` bounds, or all `max` bounds): counts by magnitude
/// bucket for each sign, and the out-of-range tails.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Side {
    non_negative: Box<[u64]>,
    negative: Box<[u64]>,
    above: u64,
    below: u64,
}

/// Where one value of a side is counted.
#[derive(Debug, Clone, Copy)]
enum Slot {
    NonNegative(usize),
    Negative(usize),
    Above,
    Below,
}

impl Side {
    fn new(len: usize) -> Option<Self> {
        Some(Self {
            non_negative: zeroed(len)?,
            negative: zeroed(len)?,
            above: 0,
            below: 0,
        })
    }

    fn counter(&mut self, slot: Slot) -> Option<&mut u64> {
        match slot {
            Slot::NonNegative(index) => self.non_negative.get_mut(index),
            Slot::Negative(index) => self.negative.get_mut(index),
            Slot::Above => Some(&mut self.above),
            Slot::Below => Some(&mut self.below),
        }
    }

    fn value(&self, slot: Slot) -> u64 {
        match slot {
            Slot::NonNegative(index) => self.non_negative.get(index).copied().unwrap_or(0),
            Slot::Negative(index) => self.negative.get(index).copied().unwrap_or(0),
            Slot::Above => self.above,
            Slot::Below => self.below,
        }
    }

    /// Walks the slots in ascending order of value and returns the slot of
    /// the `rank`-th value (1-based).
    fn find(&self, rank: u128) -> Option<Slot> {
        let mut seen: u128 = 0;
        let mut visit = |slot: Slot, count: u64| {
            seen += u128::from(count);
            (seen >= rank).then_some(slot)
        };
        if let Some(slot) = visit(Slot::Below, self.below) {
            return Some(slot);
        }
        for (index, count) in self.negative.iter().enumerate().rev() {
            if let Some(slot) = visit(Slot::Negative(index), *count) {
                return Some(slot);
            }
        }
        for (index, count) in self.non_negative.iter().enumerate() {
            if let Some(slot) = visit(Slot::NonNegative(index), *count) {
                return Some(slot);
            }
        }
        visit(Slot::Above, self.above)
    }
}

fn zeroed(len: usize) -> Option<Box<[u64]>> {
    let mut counts = Vec::new();
    counts.try_reserve_exact(len).ok()?;
    counts.resize(len, 0);
    Some(counts.into_boxed_slice())
}

/// The counts of one side, sparse: the nonzero buckets as `(index, count)`
/// in ascending index, and the out-of-range tails.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SideCounts {
    /// Nonzero buckets of the non-negative values.
    pub non_negative: Vec<(u32, u64)>,
    /// Nonzero buckets of the negative values (by magnitude).
    pub negative: Vec<(u32, u64)>,
    /// Values above `highest`.
    pub above: u64,
    /// Values below `-highest`.
    pub below: u64,
}

impl SideCounts {
    fn of(side: &Side) -> Self {
        let nonzero = |counts: &[u64]| {
            counts
                .iter()
                .enumerate()
                .filter(|(_, count)| **count > 0)
                .filter_map(|(index, count)| Some((u32::try_from(index).ok()?, *count)))
                .collect()
        };
        Self {
            non_negative: nonzero(&side.non_negative),
            negative: nonzero(&side.negative),
            above: side.above,
            below: side.below,
        }
    }

    /// The side these counts describe in a layout of `len` buckets, and
    /// their total; `None` for an index out of range or out of order (so
    /// named twice), or a total that overflows.
    fn side(&self, len: usize) -> Option<(Side, u64)> {
        let mut side = Side::new(len)?;
        let mut total = self.above.checked_add(self.below)?;
        let mut fill = |into: &mut [u64], counts: &[(u32, u64)]| -> Option<()> {
            let mut last = None;
            for &(index, count) in counts {
                if last.is_some_and(|previous| previous >= index) {
                    return None;
                }
                last = Some(index);
                *into.get_mut(usize::try_from(index).ok()?)? = count;
                total = total.checked_add(count)?;
            }
            Some(())
        };
        fill(&mut side.non_negative, &self.non_negative)?;
        fill(&mut side.negative, &self.negative)?;
        side.above = self.above;
        side.below = self.below;
        Some((side, total))
    }

    /// The bytes these counts hold: 12 per nonzero bucket and 16 for the
    /// tails (R-CORE-23's retained-bucket budget).
    #[must_use]
    pub fn bytes(&self) -> usize {
        (self.non_negative.len() + self.negative.len()) * 12 + 16
    }
}

/// A histogram's counts in a form another process can rebuild and merge
/// (R-CORE-23): its layout, both sides sparse, and its accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistogramCounts {
    /// Significant digits.
    pub digits: u8,
    /// Highest magnitude.
    pub highest: u64,
    /// The caller-declared unit.
    pub unit: u64,
    /// The `min` bounds.
    pub min: SideCounts,
    /// The `max` bounds.
    pub max: SideCounts,
    /// Available latencies (`N`).
    pub available: u64,
    /// Unavailable latencies, by reason: no calibration, not valid,
    /// ambiguous, overflow.
    pub unavailable: [u64; 4],
    /// A count overflowed.
    pub incomplete: bool,
}

impl HistogramCounts {
    /// The bytes these counts hold, for a retention budget.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.min.bytes() + self.max.bytes() + 64
    }
}

/// A quantile of recorded latencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantile {
    /// The quantile lies in `[low, high]`; `None` is an unbounded side
    /// (out of range).
    Interval {
        /// Lower bound, or unbounded.
        low: Option<i64>,
        /// Upper bound, or unbounded.
        high: Option<i64>,
    },
    /// No available latency was recorded.
    Empty,
    /// A count overflowed: the histogram is incomplete and answers nothing.
    Incomplete,
}

/// A histogram of latency intervals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Histogram {
    layout: Layout,
    unit: u64,
    min: Side,
    max: Side,
    available: u64,
    unavailable: [u64; 4],
    incomplete: bool,
}

fn unavailable_index(reason: Unavailable) -> usize {
    match reason {
        Unavailable::NoCalibration => 0,
        Unavailable::NotValid => 1,
        Unavailable::Ambiguous => 2,
        Unavailable::Overflow => 3,
    }
}

impl Histogram {
    /// A histogram with `digits` significant digits (1 to 5) for magnitudes
    /// up to `highest` (in `1 ..= 2^63`, the magnitudes of `i64`), measuring
    /// values in the caller-declared `unit` (control path: allocates its
    /// tables).
    ///
    /// # Errors
    ///
    /// Returns [`HistogramError::InvalidConfig`] for out-of-range
    /// parameters or a table that does not fit or cannot be allocated.
    pub fn new(digits: u8, highest: u64, unit: u64) -> Result<Self, HistogramError> {
        let layout = Layout::new(digits, highest).ok_or(HistogramError::InvalidConfig)?;
        Ok(Self {
            min: Side::new(layout.len).ok_or(HistogramError::InvalidConfig)?,
            max: Side::new(layout.len).ok_or(HistogramError::InvalidConfig)?,
            layout,
            unit,
            available: 0,
            unavailable: [0; 4],
            incomplete: false,
        })
    }

    fn slot(&self, value: i64) -> Slot {
        let magnitude = value.unsigned_abs();
        if magnitude > self.layout.highest {
            return if value < 0 { Slot::Below } else { Slot::Above };
        }
        match self.layout.index(magnitude) {
            Some(index) if value < 0 => Slot::Negative(index),
            Some(index) => Slot::NonNegative(index),
            // Unreachable for a magnitude within `highest`; treat as out of
            // range, which only widens answers.
            None if value < 0 => Slot::Below,
            None => Slot::Above,
        }
    }

    /// Records one latency. Transactional: on refusal no count changes (an
    /// overflow still marks the histogram incomplete).
    ///
    /// # Errors
    ///
    /// Returns [`HistogramError::InvalidInterval`] for `min > max`, and
    /// [`HistogramError::Overflow`] (the histogram becomes incomplete) when
    /// a count would overflow.
    pub fn record(&mut self, latency: Latency) -> Result<(), HistogramError> {
        match latency {
            Latency::Available { min, max } => {
                if min > max {
                    return Err(HistogramError::InvalidInterval);
                }
                let (low, high) = (self.slot(min), self.slot(max));
                let fits = self.min.value(low).checked_add(1).is_some()
                    && self.max.value(high).checked_add(1).is_some()
                    && self.available.checked_add(1).is_some();
                if !fits {
                    self.incomplete = true;
                    return Err(HistogramError::Overflow);
                }
                if let Some(count) = self.min.counter(low) {
                    *count += 1;
                }
                if let Some(count) = self.max.counter(high) {
                    *count += 1;
                }
                self.available += 1;
                Ok(())
            }
            Latency::Unavailable(reason) => {
                let index = unavailable_index(reason);
                match self.unavailable.get_mut(index) {
                    Some(count) => match count.checked_add(1) {
                        Some(next) => {
                            *count = next;
                            Ok(())
                        }
                        None => {
                            self.incomplete = true;
                            Err(HistogramError::Overflow)
                        }
                    },
                    None => Err(HistogramError::Overflow),
                }
            }
        }
    }

    /// Available latencies recorded (`N`).
    #[must_use]
    pub fn available(&self) -> u64 {
        self.available
    }

    /// Unavailable latencies recorded with `reason`.
    #[must_use]
    pub fn unavailable(&self, reason: Unavailable) -> u64 {
        self.unavailable
            .get(unavailable_index(reason))
            .copied()
            .unwrap_or(0)
    }

    /// Whether a count overflowed (directly or through a merge).
    #[must_use]
    pub fn is_incomplete(&self) -> bool {
        self.incomplete
    }

    /// The quantile `numerator / denominator` as an interval, by nearest
    /// rank: `k = max(1, ceil(q * N))`, so `q = 0` is the minimum and
    /// `q = 1` the maximum. `Incomplete` takes precedence over `Empty`. It
    /// describes only the available latencies recorded, not trace
    /// completeness or unsampled traffic.
    ///
    /// # Errors
    ///
    /// Returns [`HistogramError::InvalidQuantile`] unless
    /// `0 < denominator` and `numerator <= denominator`.
    pub fn quantile(&self, numerator: u64, denominator: u64) -> Result<Quantile, HistogramError> {
        if denominator == 0 || numerator > denominator {
            return Err(HistogramError::InvalidQuantile);
        }
        if self.incomplete {
            return Ok(Quantile::Incomplete);
        }
        if self.available == 0 {
            return Ok(Quantile::Empty);
        }
        let product = u128::from(numerator) * u128::from(self.available);
        let rank = product.div_ceil(u128::from(denominator)).max(1);
        let low = self.min.find(rank).and_then(|slot| self.lowest(slot));
        let high = self.max.find(rank).and_then(|slot| self.highest(slot));
        Ok(Quantile::Interval { low, high })
    }

    /// The lowest value a slot stands for; `None` if unbounded.
    fn lowest(&self, slot: Slot) -> Option<i64> {
        match slot {
            Slot::NonNegative(index) => Some(positive(self.layout.bucket(index).0)),
            Slot::Negative(index) => negate(self.layout.bucket(index).1),
            // Values above `highest` are still at least `highest + 1`.
            Slot::Above => self
                .layout
                .highest
                .checked_add(1)
                .and_then(|value| i64::try_from(value).ok()),
            Slot::Below => None,
        }
    }

    /// The highest value a slot stands for; `None` if unbounded.
    fn highest(&self, slot: Slot) -> Option<i64> {
        match slot {
            Slot::NonNegative(index) => Some(positive(self.layout.bucket(index).1)),
            Slot::Negative(index) => negate(self.layout.bucket(index).0),
            Slot::Above => None,
            // Values below `-highest` are still at most `-(highest + 1)`.
            Slot::Below => self.layout.highest.checked_add(1).and_then(negate),
        }
    }

    /// The histogram's counts, sparse (R-CORE-23; allocates).
    #[must_use]
    pub fn counts(&self) -> HistogramCounts {
        HistogramCounts {
            digits: self.layout.digits,
            highest: self.layout.highest,
            unit: self.unit,
            min: SideCounts::of(&self.min),
            max: SideCounts::of(&self.max),
            available: self.available,
            unavailable: self.unavailable,
            incomplete: self.incomplete,
        }
    }

    /// Rebuilds a histogram from `counts`, which must have the layout and
    /// unit of `like` (the histogram it will merge with): a different
    /// layout is never converted (R-CORE-23; allocates).
    ///
    /// # Errors
    ///
    /// [`HistogramError::Mismatch`] for other digits, highest magnitude or
    /// unit; [`HistogramError::InvalidCounts`] for a bucket index outside
    /// the layout, an index named twice, or sides whose totals differ from
    /// the available count; [`HistogramError::Overflow`] for a total that
    /// overflows.
    pub fn from_counts(counts: &HistogramCounts, like: &Self) -> Result<Self, HistogramError> {
        if counts.digits != like.layout.digits
            || counts.highest != like.layout.highest
            || counts.unit != like.unit
        {
            return Err(HistogramError::Mismatch);
        }
        let len = like.layout.len;
        let total_fits = |side: &SideCounts| {
            side.above
                .checked_add(side.below)
                .and_then(|tails| {
                    side.non_negative
                        .iter()
                        .chain(&side.negative)
                        .try_fold(tails, |sum, (_, count)| sum.checked_add(*count))
                })
                .is_some()
        };
        if !total_fits(&counts.min) || !total_fits(&counts.max) {
            return Err(HistogramError::Overflow);
        }
        let (min, min_total) = counts.min.side(len).ok_or(HistogramError::InvalidCounts)?;
        let (max, max_total) = counts.max.side(len).ok_or(HistogramError::InvalidCounts)?;
        if min_total != counts.available || max_total != counts.available {
            return Err(HistogramError::InvalidCounts);
        }
        Ok(Self {
            layout: like.layout,
            unit: like.unit,
            min,
            max,
            available: counts.available,
            unavailable: counts.unavailable,
            incomplete: counts.incomplete,
        })
    }

    /// Adds `other` into `self`. All or nothing: every sum is checked before
    /// any is applied, so on refusal `self` is unchanged; nothing is
    /// allocated. An incomplete source makes `self` incomplete. That both
    /// histograms measure the same quantity over a compatible selection is
    /// the caller's contract; only the layout and the unit tag are checked.
    ///
    /// # Errors
    ///
    /// Returns [`HistogramError::Mismatch`] for another layout or unit and
    /// [`HistogramError::Overflow`] when a sum would overflow.
    pub fn merge(&mut self, other: &Self) -> Result<(), HistogramError> {
        if self.layout != other.layout || self.unit != other.unit {
            return Err(HistogramError::Mismatch);
        }
        let fits = self.available.checked_add(other.available).is_some()
            && self
                .unavailable
                .iter()
                .zip(other.unavailable)
                .all(|(a, b)| a.checked_add(b).is_some())
            && side_fits(&self.min, &other.min)
            && side_fits(&self.max, &other.max);
        if !fits {
            return Err(HistogramError::Overflow);
        }
        self.available += other.available;
        for (into, from) in self.unavailable.iter_mut().zip(other.unavailable) {
            *into += from;
        }
        add_side(&mut self.min, &other.min);
        add_side(&mut self.max, &other.max);
        self.incomplete |= other.incomplete;
        Ok(())
    }
}

/// Whether every element-wise sum of two sides fits.
fn side_fits(into: &Side, from: &Side) -> bool {
    let fits = |a: &[u64], b: &[u64]| a.iter().zip(b).all(|(x, y)| x.checked_add(*y).is_some());
    fits(&into.non_negative, &from.non_negative)
        && fits(&into.negative, &from.negative)
        && into.above.checked_add(from.above).is_some()
        && into.below.checked_add(from.below).is_some()
}

/// Adds `from` into `into`; [`side_fits`] has checked every sum.
fn add_side(into: &mut Side, from: &Side) {
    for (a, b) in into.non_negative.iter_mut().zip(from.non_negative.iter()) {
        *a += *b;
    }
    for (a, b) in into.negative.iter_mut().zip(from.negative.iter()) {
        *a += *b;
    }
    into.above += from.above;
    into.below += from.below;
}

/// `-magnitude` as `i64`. Recorded values are `i64`, so a magnitude beyond
/// `2^63` bounds nothing lower than `i64::MIN`.
fn negate(magnitude: u64) -> Option<i64> {
    if magnitude >= 1u64 << 63 {
        return Some(i64::MIN);
    }
    i64::try_from(magnitude).ok().map(|value| -value)
}

/// `magnitude` as `i64`. Recorded values are `i64`, so a magnitude beyond
/// `i64::MAX` bounds nothing higher than `i64::MAX`.
fn positive(magnitude: u64) -> i64 {
    i64::try_from(magnitude).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests;
