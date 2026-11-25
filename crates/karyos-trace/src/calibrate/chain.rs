// SPDX-License-Identifier: Apache-2.0

//! Calibrations between hosts (karyos#749, the cross-host half): a
//! calibration of a PTP link from its client's samples ([`link`]), and the
//! composition of calibrations into the single direct one that
//! [`crate::clocks::latency`] requires ([`compose`]).
//!
//! **Link.** A PTP client reports its PHC's offset from the server's,
//! `offsetFromMaster = client - server`, and the mean path delay, once per
//! sample. The servo keeps the offset small, but E2E PTP assumes the two
//! directions of the path take equal time: an asymmetry shifts the true
//! offset by up to half of it, and nothing on the hosts can measure it. So
//! [`link`] bounds the offset by the largest observed offset plus the
//! largest mean path delay (the whole delay, an asymmetry of every
//! nanosecond of it in one direction, which no real path exceeds), and
//! claims no drift: while the servo holds the lock the offset stays inside
//! that bound, which is why the calibration holds only over the sampled
//! span. It is valid for that server, that client and that path only.
//!
//! **Composition.** `A to B` then `B to C` is `A to C`. At the reference
//! of the first, the composed offset interval is the second's conversion
//! of the first's; away from it, every slope the two models allow is a
//! product of one slope of each, so the composed drift is the midpoint of
//! the four products and its uncertainty half their range. The composed
//! interval therefore contains every value the two models allow together,
//! never fewer. It is valid where the first holds and its converted
//! interval lies wholly inside the second's validity.

use crate::clocks::{Calibration, CalibrationError, ClockKey};

/// Parts per billion.
const BILLION: i128 = 1_000_000_000;

/// One sample of a PTP client: the time it applied (its PHC, ns), the
/// offset from the server, and the mean path delay, both ns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkSample {
    /// The client PHC's time of the sample.
    pub time: u64,
    /// `client - server`, ns.
    pub offset: i64,
    /// The mean path delay, ns.
    pub path_delay: u64,
}

/// Why a link or a composition is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// No samples, or samples out of time order.
    #[error("the link samples are empty or out of time order")]
    Samples,
    /// The link's bound is past the allowed one: the lock did not hold.
    #[error("the link bound of {bound} ns is past the allowed {max_bound} ns")]
    TooWide {
        /// The bound the samples give.
        bound: u64,
        /// The allowed bound.
        max_bound: u64,
    },
    /// Two link samples further apart than allowed.
    #[error("two link samples are {gap} ns apart, more than allowed")]
    Gap {
        /// The gap.
        gap: u64,
    },
    /// The second calibration does not start where the first ends.
    #[error("the second calibration's source is not the first's target")]
    Disjoint,
    /// No time of the first calibration converts wholly inside the
    /// second's validity.
    #[error("the calibrations share no valid time")]
    NoOverlap,
    /// A value does not fit the record's integers.
    #[error("a value does not fit the calibration's integers")]
    Overflow,
    /// The composed record itself is refused.
    #[error(transparent)]
    Calibration(#[from] CalibrationError),
}

/// A calibration from the server's PHC `server` to the client's `client`,
/// from the client's `samples` (in time order, no two more than `max_gap`
/// ns apart), valid over their span.
///
/// **Assumptions** (stated, not measured, and recorded with every result):
/// between two samples the offset moves no further than the largest change
/// observed between consecutive samples, which `max_gap` keeps short; and
/// the path asymmetry is no larger than the reported mean path delay
/// (`ptp4l` reports a filtered delay, so a raw exchange can exceed it; the
/// largest change term covers that too while the lock holds). A run whose
/// samples break the lock shows it in that largest change, and widens the
/// bound accordingly.
///
/// # Errors
///
/// [`ChainError::Samples`] for no samples or samples out of order;
/// [`ChainError::Gap`] for two samples further apart than `max_gap`;
/// [`ChainError::TooWide`] for a bound past `max_bound` ns, so no
/// calibration (and so no latency) is ever made from a link that did not
/// hold its lock; [`ChainError::Overflow`].
pub fn link(
    server: ClockKey,
    client: ClockKey,
    samples: &[LinkSample],
    max_gap: u64,
    max_bound: u64,
) -> Result<Calibration, ChainError> {
    let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
        return Err(ChainError::Samples);
    };
    if samples
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if b.time < a.time))
    {
        return Err(ChainError::Samples);
    }
    let mut change = 0_i128;
    for pair in samples.windows(2) {
        if let [a, b] = pair {
            if b.time - a.time > max_gap {
                return Err(ChainError::Gap {
                    gap: b.time - a.time,
                });
            }
            change = change.max((i128::from(b.offset) - i128::from(a.offset)).abs());
        }
    }
    let largest_offset = samples
        .iter()
        .map(|sample| i128::from(sample.offset).abs())
        .max()
        .unwrap_or(0);
    let largest_delay = samples
        .iter()
        .map(|sample| i128::from(sample.path_delay))
        .max()
        .unwrap_or(0);
    // +1 for the samples' whole-nanosecond rounding (rounded outwards).
    let bound = largest_offset + change + largest_delay + 1;
    if bound > i128::from(max_bound) {
        return Err(ChainError::TooWide {
            bound: u64::try_from(bound).unwrap_or(u64::MAX),
            max_bound,
        });
    }
    // In the server's time: the client's sample times less their offset,
    // widened by the bound so the span is the server's for certain.
    let server_time = |sample: &LinkSample, widen: i128| {
        u64::try_from(i128::from(sample.time) - i128::from(sample.offset) + widen)
            .map_err(|_| ChainError::Overflow)
    };
    let valid_from = server_time(first, bound)?;
    let valid_to = server_time(last, -bound)?;
    if valid_from > valid_to {
        return Err(ChainError::Samples);
    }
    let calibration = Calibration {
        from: server,
        to: client,
        reference: valid_from + (valid_to - valid_from) / 2,
        offset: 0,
        offset_uncertainty: u64::try_from(bound).map_err(|_| ChainError::Overflow)?,
        drift: 0,
        drift_uncertainty: 0,
        valid_from,
        valid_to,
    };
    calibration.validate()?;
    Ok(calibration)
}

/// Ceiling of `numerator / denominator` for a positive denominator.
fn ceil_div(numerator: i128, denominator: i128) -> i128 {
    let floor = numerator.div_euclid(denominator);
    if numerator.rem_euclid(denominator) == 0 {
        floor
    } else {
        floor + 1
    }
}

/// `first` then `second`: a calibration from `first.from` to
/// `second.to`.
///
/// # Errors
///
/// [`ChainError::Disjoint`] unless `second.from == first.to`;
/// [`ChainError::NoOverlap`] when no time of `first` converts inside
/// `second`'s validity; [`ChainError::Overflow`].
pub fn compose(first: &Calibration, second: &Calibration) -> Result<Calibration, ChainError> {
    if second.from != first.to {
        return Err(ChainError::Disjoint);
    }
    // Where `first` converts wholly inside `second`: a time range of
    // `first`, found by bisection (the converted bounds grow with time).
    let inside = |time: i128| {
        first
            .convert(time, time)
            .is_some_and(|(low, high)| second.covers(low, high))
    };
    let (from, to) = (i128::from(first.valid_from), i128::from(first.valid_to));
    // One time inside. The overlap is one interval (the conversion's
    // bounds grow with time): seeds where it most likely is, first the
    // time `first` maps onto the middle of `second`'s validity (one
    // correction step from its offset), then its reference, its ends and a
    // scan; none inside means none of these is in an overlap, which is
    // then refused.
    let middle = (i128::from(second.valid_from) + i128::from(second.valid_to)) / 2;
    let guess = (middle - i128::from(first.offset)).clamp(from, to);
    let corrected = first
        .convert(guess, guess)
        .map(|(low, high)| (guess - ((low + high) / 2 - middle)).clamp(from, to));
    let step = (to - from) / 1024 + 1;
    let found = corrected
        .into_iter()
        .chain([guess, i128::from(first.reference).clamp(from, to), from, to])
        .chain((0..=1024).map(|index| (from + index * step).min(to)))
        .find(|&time| inside(time))
        .ok_or(ChainError::NoOverlap)?;
    // Below `found` only the lower bound can leave `second`'s validity,
    // and above it only the upper one, so each side is a bisection.
    let start = {
        let (mut low, mut high) = (from, found);
        while low < high {
            let mid = low + (high - low) / 2;
            if inside(mid) {
                high = mid
            } else {
                low = mid + 1
            }
        }
        low
    };
    let end = {
        let (mut low, mut high) = (found, to);
        while low < high {
            let mid = low + (high - low + 1) / 2;
            if inside(mid) {
                low = mid
            } else {
                high = mid - 1
            }
        }
        low
    };
    if !inside(start) || !inside(end) {
        return Err(ChainError::NoOverlap);
    }
    // The reference: `first`'s, kept inside the overlap.
    let reference = i128::from(first.reference).clamp(start, end);
    let (b_low, b_high) = first
        .convert(reference, reference)
        .ok_or(ChainError::Overflow)?;
    let (c_low, c_high) = second.convert(b_low, b_high).ok_or(ChainError::Overflow)?;
    let centre = c_low + (c_high - c_low) / 2;
    let offset = centre - reference;
    // `first`'s conversion rounds by up to 1 ns at any time, and `second`
    // multiplies that by its slope: its largest slope, rounded up, more.
    let steepest = ceil_div(
        BILLION + i128::from(second.drift).abs() + i128::from(second.drift_uncertainty),
        BILLION,
    );
    let offset_uncertainty = (c_high - centre).max(centre - c_low) + 1 + steepest;
    // Every slope `1 + rate / 1e9` of each, multiplied: in ppb,
    // (1e9 + r1)(1e9 + r2) / 1e9 - 1e9.
    let rates = |calibration: &Calibration| {
        let drift = i128::from(calibration.drift);
        let spread = i128::from(calibration.drift_uncertainty);
        [drift - spread, drift + spread]
    };
    let mut products = Vec::with_capacity(4);
    for r1 in rates(first) {
        for r2 in rates(second) {
            let product = (BILLION + r1)
                .checked_mul(BILLION + r2)
                .ok_or(ChainError::Overflow)?;
            products.push((
                product.div_euclid(BILLION) - BILLION,
                ceil_div(product, BILLION) - BILLION,
            ));
        }
    }
    let lowest = products
        .iter()
        .map(|(floor, _)| *floor)
        .min()
        .ok_or(ChainError::Overflow)?;
    let highest = products
        .iter()
        .map(|(_, ceil)| *ceil)
        .max()
        .ok_or(ChainError::Overflow)?;
    let drift = lowest + (highest - lowest) / 2;
    let drift_uncertainty = (highest - drift).max(drift - lowest) + 1;
    let small = |value: i128| u64::try_from(value).map_err(|_| ChainError::Overflow);
    let signed = |value: i128| i64::try_from(value).map_err(|_| ChainError::Overflow);
    let composed = Calibration {
        from: first.from,
        to: second.to,
        reference: small(reference)?,
        offset: signed(offset)?,
        offset_uncertainty: small(offset_uncertainty)?,
        drift: signed(drift)?,
        drift_uncertainty: small(drift_uncertainty)?,
        valid_from: small(start)?,
        valid_to: small(end)?,
    };
    composed.validate()?;
    Ok(composed)
}

#[cfg(test)]
mod tests;
