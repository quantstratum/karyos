// SPDX-License-Identifier: Apache-2.0

//! A calibration fitted from bracketed reads of two clocks on one host
//! (karyos#749, the single-host half): the producer of the
//! [`Calibration`] records that [`crate::clocks::latency`] consumes.
//!
//! **Method.** Each [`PairedRead`] reads the source clock, then the
//! target clock, then the source clock again. The target was read at some
//! source time in `[before, after]`, so the pair bounds the offset
//! `target - source` to `[target - after, target - before]`, with no
//! assumption about where in the window the read fell. [`fit`] keeps the
//! reads with the narrowest windows (a preempted read has a wide one),
//! fits the offset as a line in the source time by least squares (the
//! drift is its slope), and then measures, rather than assumes, both
//! uncertainties:
//!
//! - the **offset uncertainty** is the largest distance, over the kept
//!   reads, from the fitted line to the far end of the read's own offset
//!   interval, so every kept read's interval lies inside the line plus or
//!   minus it;
//! - the **drift uncertainty** is the larger difference between the whole
//!   fit's slope and the slope of either half of the reads alone, plus
//!   the slope the offset uncertainty allows across the span.
//!
//! The calibration is valid from the first read to the last plus a
//! caller-chosen extension, and [`crate::clocks::Calibration::convert`]
//! widens a converted time by the drift uncertainty times its distance
//! from the reference, so nothing past the measured span is claimed
//! without that growth. Nothing here reads a clock: the caller does, off
//! the data path.

use crate::clocks::{Calibration, CalibrationError, ClockKey};

/// Parts per billion, as the calibration's drift.
const BILLION: i128 = 1_000_000_000;

/// The fewest reads a fit accepts after the narrowest are kept: enough
/// for each half to fit a slope of its own.
pub const MIN_KEPT_READS: usize = 8;

/// One bracketed read: the source clock, the target clock, the source
/// clock again, all in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairedRead {
    /// The source clock before the target was read.
    pub before: u64,
    /// The target clock.
    pub target: u64,
    /// The source clock after the target was read.
    pub after: u64,
}

/// What a fit produces besides its source and target clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FitConfig {
    /// The source clock.
    pub from: ClockKey,
    /// The target clock.
    pub to: ClockKey,
    /// The percentage of reads kept, the narrowest windows first
    /// (1 to 100).
    pub keep_percent: u8,
    /// How long past the last read the calibration stays valid, in
    /// nanoseconds of the source clock.
    pub extension: u64,
}

/// A fitted calibration and the evidence behind its uncertainties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fit {
    /// The calibration.
    pub calibration: Calibration,
    /// Reads given.
    pub reads: usize,
    /// Reads kept.
    pub kept: usize,
    /// The narrowest window of any read, in nanoseconds.
    pub narrowest_window: u64,
    /// The widest window among the kept reads, in nanoseconds.
    pub widest_kept_window: u64,
    /// The largest distance from a kept read's offset midpoint to the
    /// fitted line, in nanoseconds.
    pub largest_residual: u64,
    /// The slopes of the first and second halves of the kept reads, in
    /// parts per billion.
    pub half_drifts: (i64, i64),
    /// The source time the kept reads span, in nanoseconds.
    pub span: u64,
}

/// Why a fit is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FitError {
    /// Fewer than [`MIN_KEPT_READS`] reads are left to fit.
    #[error("too few reads to fit: {kept} kept, at least {MIN_KEPT_READS} needed")]
    TooFewReads {
        /// Reads kept.
        kept: usize,
    },
    /// A read whose source time went backwards, or reads out of order.
    #[error("the source clock went backwards in read {index}")]
    Backwards {
        /// The read at fault.
        index: usize,
    },
    /// A keep percentage outside 1 to 100.
    #[error("keep percentage {percent} is outside 1 to 100")]
    Keep {
        /// The percentage given.
        percent: u8,
    },
    /// The kept reads span no source time, so no slope exists.
    #[error("the kept reads span no source time")]
    NoSpan,
    /// A value does not fit the calibration's integers.
    #[error("a value does not fit the calibration's integers")]
    Overflow,
    /// The calibration record itself is refused.
    #[error(transparent)]
    Calibration(#[from] CalibrationError),
}

/// A kept read: the window's midpoint `x` from the reference, the offset
/// at it, and the half-width of the offset interval around it.
#[derive(Debug, Clone, Copy)]
struct Point {
    x: i128,
    offset: i128,
    half: i128,
}

/// The least-squares line through `points`: an intercept at `x = 0` and a
/// slope in parts per billion, both rounded to integers.
fn line(points: &[Point]) -> Option<(i128, i128)> {
    let count = i128::try_from(points.len()).ok()?;
    let (mut sx, mut sy) = (0_i128, 0_i128);
    for point in points {
        sx = sx.checked_add(point.x)?;
        sy = sy.checked_add(point.offset)?;
    }
    // Centred sums, so the products stay small: x spans seconds (1e10 ns)
    // and the offsets vary by microseconds.
    let (mut sxx, mut sxy) = (0_i128, 0_i128);
    for point in points {
        let dx = point.x.checked_mul(count)?.checked_sub(sx)?;
        let dy = point.offset.checked_mul(count)?.checked_sub(sy)?;
        sxx = sxx.checked_add(dx.checked_mul(dx)?)?;
        sxy = sxy.checked_add(dx.checked_mul(dy)?)?;
    }
    if sxx == 0 {
        return None;
    }
    let slope = sxy.checked_mul(BILLION)?.checked_div(sxx)?;
    // intercept = mean(y) - slope * mean(x) / 1e9
    let intercept = sy
        .checked_mul(BILLION)?
        .checked_sub(slope.checked_mul(sx)?)?
        .checked_div(count.checked_mul(BILLION)?)?;
    Some((intercept, slope))
}

/// Fits a calibration from `config.from` to `config.to` from `reads`, in
/// the order they were taken.
///
/// # Errors
///
/// [`FitError`] for reads that cannot support a calibration: a source
/// clock that went backwards, too few reads kept, kept reads spanning no
/// time, or values beyond the record's integers.
pub fn fit(reads: &[PairedRead], config: &FitConfig) -> Result<Fit, FitError> {
    if !(1..=100).contains(&config.keep_percent) {
        return Err(FitError::Keep {
            percent: config.keep_percent,
        });
    }
    let mut previous = 0_u64;
    for (index, read) in reads.iter().enumerate() {
        if read.after < read.before || read.before < previous {
            return Err(FitError::Backwards { index });
        }
        previous = read.after;
    }
    let (Some(first), Some(last)) = (reads.first(), reads.last()) else {
        return Err(FitError::TooFewReads { kept: 0 });
    };
    // The narrowest windows, then back in time order.
    let mut order: Vec<usize> = (0..reads.len()).collect();
    order.sort_by_key(|&index| {
        reads
            .get(index)
            .map_or(u64::MAX, |read| read.after - read.before)
    });
    let keep = reads
        .len()
        .saturating_mul(usize::from(config.keep_percent))
        .div_ceil(100);
    order.truncate(keep);
    order.sort_unstable();
    let kept: Vec<PairedRead> = order
        .iter()
        .filter_map(|&index| reads.get(index).copied())
        .collect();
    if kept.len() < MIN_KEPT_READS {
        return Err(FitError::TooFewReads { kept: kept.len() });
    }
    let narrowest_window = reads
        .iter()
        .map(|read| read.after - read.before)
        .min()
        .unwrap_or(0);
    let widest_kept_window = kept
        .iter()
        .map(|read| read.after - read.before)
        .max()
        .unwrap_or(0);
    // The reference is the middle kept read's midpoint.
    let middle = kept.get(kept.len() / 2).ok_or(FitError::Overflow)?;
    let reference = middle.before + (middle.after - middle.before) / 2;
    let points: Vec<Point> = kept
        .iter()
        .map(|read| {
            let midpoint = read.before + (read.after - read.before) / 2;
            Point {
                x: i128::from(midpoint) - i128::from(reference),
                offset: i128::from(read.target) - i128::from(midpoint),
                // The target was read at a source time in [before, after]:
                // the far end from the midpoint bounds the offset's error.
                half: i128::from(read.after - midpoint),
            }
        })
        .collect();
    let (Some(start), Some(end)) = (points.first(), points.last()) else {
        return Err(FitError::TooFewReads { kept: 0 });
    };
    let span = end.x - start.x;
    if span <= 0 {
        return Err(FitError::NoSpan);
    }
    let (intercept, slope) = line(&points).ok_or(FitError::NoSpan)?;
    let at = |x: i128| intercept + slope * x / BILLION;
    let mut largest_residual = 0_i128;
    let mut offset_uncertainty = 0_i128;
    for point in &points {
        let residual = (point.offset - at(point.x)).abs();
        largest_residual = largest_residual.max(residual);
        // +1 for the line's integer rounding.
        offset_uncertainty = offset_uncertainty.max(residual + point.half + 1);
    }
    let (early, late) = points.split_at(points.len() / 2);
    let (_, early_slope) = line(early).ok_or(FitError::NoSpan)?;
    let (_, late_slope) = line(late).ok_or(FitError::NoSpan)?;
    let spread = (early_slope - slope).abs().max((late_slope - slope).abs());
    // The slope the offset uncertainty itself allows across the span,
    // rounded up.
    let allowed = (2 * offset_uncertainty * BILLION + span - 1) / span;
    let drift_uncertainty = spread + allowed;
    let small = |value: i128| u64::try_from(value).map_err(|_| FitError::Overflow);
    let signed = |value: i128| i64::try_from(value).map_err(|_| FitError::Overflow);
    let calibration = Calibration {
        from: config.from,
        to: config.to,
        reference,
        offset: signed(intercept)?,
        offset_uncertainty: small(offset_uncertainty)?,
        drift: signed(slope)?,
        drift_uncertainty: small(drift_uncertainty)?,
        valid_from: first.before,
        valid_to: last
            .after
            .checked_add(config.extension)
            .ok_or(FitError::Overflow)?,
    };
    calibration.validate()?;
    Ok(Fit {
        calibration,
        reads: reads.len(),
        kept: kept.len(),
        narrowest_window,
        widest_kept_window,
        largest_residual: small(largest_residual)?,
        half_drifts: (signed(early_slope)?, signed(late_slope)?),
        span: small(span)?,
    })
}

#[cfg(test)]
mod tests;
