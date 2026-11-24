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
//! narrowest read of each stretch of the run (a preempted read has a wide
//! window), so the kept reads cover the whole run,
//! fits the offset as a line in the source time by least squares (the
//! drift is its slope), and then measures, rather than assumes, both
//! uncertainties:
//!
//! - the **offset uncertainty** is the largest distance, over the kept
//!   reads and both ends of each read's window, from the fitted line to
//!   the offset the read implies there, so the true offset at the instant
//!   of every kept read, wherever in its window it fell, lies within it of
//!   the line, and so does the truth between reads while both clocks are
//!   affine;
//! - the **drift uncertainty** is the larger difference between the whole
//!   fit's slope and the slope of either half of the reads alone, plus
//!   the slope the offset uncertainty allows across the span.
//!
//! **Assumption.** Both clocks are affine over the run: neither steps nor
//! slews. A step or slew that shows as a residual larger than the read
//! windows refuses the fit ([`FitError::NotAffine`]); one too small to show
//! there is inside the bound by construction, and one between reads that
//! leaves no trace in them cannot be seen by any sampling. The PHC must not
//! be steered during the run (no `phc2sys` or `ptp4l` adjusting it).
//!
//! The calibration is valid from the first kept read to the last plus a
//! caller-chosen extension, and [`crate::clocks::Calibration::convert`]
//! widens a converted time by the drift uncertainty times its distance
//! from the reference, so nothing past the measured span is claimed
//! without that growth. Nothing here reads a clock: the caller does, off
//! the data path.

use crate::clocks::{Calibration, CalibrationError, ClockKey};

pub mod chain;

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
    /// The kept reads are not explained by one line within their windows:
    /// a clock stepped or slewed during the run.
    #[error(
        "a residual of {residual} ns exceeds the widest kept window, {window} ns: a clock stepped or slewed"
    )]
    NotAffine {
        /// The largest residual.
        residual: u64,
        /// The widest kept window.
        window: u64,
    },
    /// A value does not fit the calibration's integers.
    #[error("a value does not fit the calibration's integers")]
    Overflow,
    /// The calibration record itself is refused.
    #[error(transparent)]
    Calibration(#[from] CalibrationError),
}

/// A kept read: the window's midpoint `x` from the reference, and the
/// offset at it.
#[derive(Debug, Clone, Copy)]
struct Point {
    x: i128,
    offset: i128,
}

/// The least-squares line through `points`: an intercept at `x = 0` and a
/// slope in parts per billion, both rounded to integers.
fn line(points: &[Point]) -> Result<(i128, i128), FitError> {
    line_checked(points)
        .ok_or(FitError::Overflow)
        .and_then(|fitted| fitted.ok_or(FitError::NoSpan))
}

/// [`line`]: `None` on overflow, `Some(None)` for points spanning no `x`.
fn line_checked(points: &[Point]) -> Option<Option<(i128, i128)>> {
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
        return Some(None);
    }
    let slope = sxy.checked_mul(BILLION)?.checked_div(sxx)?;
    // intercept = mean(y) - slope * mean(x) / 1e9
    let intercept = sy
        .checked_mul(BILLION)?
        .checked_sub(slope.checked_mul(sx)?)?
        .checked_div(count.checked_mul(BILLION)?)?;
    Some(Some((intercept, slope)))
}

/// Fits a calibration from `config.from` to `config.to` from `reads`, in
/// the order they were taken.
///
/// # Errors
///
/// [`FitError`] for reads that cannot support a calibration: a source
/// clock that went backwards, too few reads kept, kept reads spanning no
/// time, reads that no line explains within their own windows (a step or
/// slew of either clock), or values beyond the record's integers.
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
    // The narrowest read of each run of `bucket` consecutive reads, so the
    // kept reads cover the whole run, not only its quietest stretch.
    let bucket = 100_usize.div_ceil(usize::from(config.keep_percent));
    let kept: Vec<PairedRead> = reads
        .chunks(bucket)
        .filter_map(|chunk| {
            chunk
                .iter()
                .min_by_key(|read| read.after - read.before)
                .copied()
        })
        .collect();
    if kept.len() < MIN_KEPT_READS {
        return Err(FitError::TooFewReads { kept: kept.len() });
    }
    let (Some(first), Some(last)) = (kept.first(), kept.last()) else {
        return Err(FitError::TooFewReads { kept: 0 });
    };
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
    let relative = |time: u64| i128::from(time) - i128::from(reference);
    let points: Vec<Point> = kept
        .iter()
        .map(|read| {
            let midpoint = read.before + (read.after - read.before) / 2;
            Point {
                x: relative(midpoint),
                offset: i128::from(read.target) - i128::from(midpoint),
            }
        })
        .collect();
    let span = relative(last.after) - relative(first.before);
    if span <= 0 {
        return Err(FitError::NoSpan);
    }
    let (intercept, slope) = line(&points)?;
    let at = |x: i128| intercept + slope * x / BILLION;
    // The target was read at some source time t in [before, after], where
    // the true offset is `target - t`. Its distance from the line,
    // `target - t - at(t)`, is affine in t, so its largest size over the
    // window is at one of the window's ends: that is the read's bound, and
    // the true offset at its read time lies within it of the line, wherever
    // in the window the read fell.
    let mut largest_residual = 0_i128;
    let mut offset_uncertainty = 0_i128;
    for read in &kept {
        let target = i128::from(read.target);
        for end in [read.before, read.after] {
            let x = relative(end);
            let distance = (target - i128::from(end) - at(x)).abs();
            // +1 for the line's integer rounding.
            offset_uncertainty = offset_uncertainty.max(distance + 1);
        }
    }
    for point in &points {
        largest_residual = largest_residual.max((point.offset - at(point.x)).abs());
    }
    // Two affine clocks leave residuals within the read windows. A larger
    // one means a clock stepped or slewed during the run, which no single
    // line describes: the reads cannot support a calibration.
    let widest = i128::from(widest_kept_window);
    if largest_residual > widest {
        return Err(FitError::NotAffine {
            residual: u64::try_from(largest_residual).unwrap_or(u64::MAX),
            window: widest_kept_window,
        });
    }
    let (early, late) = points.split_at(points.len() / 2);
    let (_, early_slope) = line(early)?;
    let (_, late_slope) = line(late)?;
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
        // The kept reads' span: the fit says nothing measured outside it.
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
