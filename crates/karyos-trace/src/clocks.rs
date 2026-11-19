// SPDX-License-Identifier: Apache-2.0

//! Clock calibration and latency (SPEC.md §7.3, ADR-0040; design in
//! `quantstratum-docs: karyos/design/trace-clocks.md`).
//!
//! A clock is identified by `(ObserverId, domain, epoch)`. Times of one
//! clock compare directly; times of different clocks compare only through a
//! single, direct calibration valid over the whole observation interval.
//! Latency is an interval that contains every value the observations and the
//! calibration allow, or it is unavailable with a reason; never an
//! apparently precise difference. Nothing here claims physical accuracy.

use crate::journal::ObserverId;

/// Parts per billion.
const BILLION: i128 = 1_000_000_000;
/// Layout version of an encoded calibration.
pub const CALIBRATION_VERSION: u64 = 1;
/// Words of an encoded calibration.
pub const CALIBRATION_WORDS: usize = 18;

/// A clock: an observer's clock domain in one calibration epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClockKey {
    /// The observer that owns the clock numbers.
    pub observer: ObserverId,
    /// Clock domain.
    pub domain: u64,
    /// Calibration epoch.
    pub epoch: u64,
}

/// An observation as an interval `[time - uncertainty, time + uncertainty]`
/// of its clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// Its clock.
    pub clock: ClockKey,
    /// Time in the clock's unit.
    pub time: u64,
    /// Half-width of the interval, same unit.
    pub uncertainty: u64,
}

impl Observation {
    fn interval(&self) -> (i128, i128) {
        let time = i128::from(self.time);
        let uncertainty = i128::from(self.uncertainty);
        (time - uncertainty, time + uncertainty)
    }
}

/// A calibration from clock `from` to clock `to`:
/// `t_to = t + offset + drift * (t - reference) / 10^9`, valid for times of
/// `from` in `[valid_from, valid_to]`. Both clocks share one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Calibration {
    /// Source clock.
    pub from: ClockKey,
    /// Target clock.
    pub to: ClockKey,
    /// The time of `from` at which `offset` was measured.
    pub reference: u64,
    /// Offset in the shared unit.
    pub offset: i64,
    /// Half-width of the offset's uncertainty.
    pub offset_uncertainty: u64,
    /// Rate error in parts per billion of `t - reference`.
    pub drift: i64,
    /// Half-width of the drift's uncertainty, parts per billion.
    pub drift_uncertainty: u64,
    /// First time of `from` the calibration holds for.
    pub valid_from: u64,
    /// Last time of `from` the calibration holds for.
    pub valid_to: u64,
}

/// Why a latency or conversion is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// No calibration from the first observation's clock to the second's.
    NoCalibration,
    /// No calibration valid over the observation's whole interval.
    NotValid,
    /// More than one calibration could apply.
    Ambiguous,
    /// A bound does not fit the arithmetic.
    Overflow,
}

/// A latency `b - a` as an interval, or why it is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Latency {
    /// Every value the observations and calibration allow lies in
    /// `[min, max]`.
    Available {
        /// Lower bound.
        min: i64,
        /// Upper bound.
        max: i64,
    },
    /// Not computable from the evidence.
    Unavailable(Unavailable),
}

/// Floor of `numerator / BILLION`.
fn floor_billionths(numerator: i128) -> i128 {
    numerator.div_euclid(BILLION)
}

/// Ceiling of `numerator / BILLION`, from the floor and the remainder, so it
/// never negates `i128::MIN` (the quotient is far from the type's bounds, so
/// adding one cannot overflow).
fn ceil_billionths(numerator: i128) -> i128 {
    let floor = numerator.div_euclid(BILLION);
    if numerator.rem_euclid(BILLION) == 0 {
        floor
    } else {
        floor + 1
    }
}

impl Calibration {
    /// Checks the record: `valid_from <= valid_to` and distinct clocks.
    ///
    /// # Errors
    ///
    /// Returns [`CalibrationError::Invalid`].
    pub fn validate(&self) -> Result<(), CalibrationError> {
        if self.valid_from > self.valid_to || self.from == self.to {
            return Err(CalibrationError::Invalid);
        }
        Ok(())
    }

    /// Whether `[low, high]` of `from` lies wholly inside the validity.
    #[must_use]
    pub fn covers(&self, low: i128, high: i128) -> bool {
        low >= i128::from(self.valid_from) && high <= i128::from(self.valid_to)
    }

    /// Converts the interval `[low, high]` of `from` into an interval of
    /// `to` containing every value the model allows: the minimum and
    /// maximum over the corners of the time, offset and drift intervals,
    /// with the drift term rounded outwards.
    /// Returns `None` when a product does not fit `i128`.
    #[must_use]
    pub fn convert(&self, low: i128, high: i128) -> Option<(i128, i128)> {
        let reference = i128::from(self.reference);
        let offset = i128::from(self.offset);
        let offset_uncertainty = i128::from(self.offset_uncertainty);
        let drift = i128::from(self.drift);
        let drift_uncertainty = i128::from(self.drift_uncertainty);
        let mut lower = i128::MAX;
        let mut upper = i128::MIN;
        for time in [low, high] {
            let delta = time - reference;
            for rate in [drift - drift_uncertainty, drift + drift_uncertainty] {
                let term = delta.checked_mul(rate)?;
                let base_low = time.checked_add(offset)?.checked_sub(offset_uncertainty)?;
                let base_high = time.checked_add(offset)?.checked_add(offset_uncertainty)?;
                lower = lower.min(base_low.checked_add(floor_billionths(term))?);
                upper = upper.max(base_high.checked_add(ceil_billionths(term))?);
            }
        }
        Some((lower, upper))
    }

    /// Encodes the record.
    ///
    /// # Errors
    ///
    /// As [`Calibration::validate`].
    pub fn encode(&self) -> Result<[u64; CALIBRATION_WORDS], CalibrationError> {
        self.validate()?;
        let clock = |key: ClockKey| {
            [
                key.observer.driver[0],
                key.observer.driver[1],
                key.observer.journal,
                key.domain,
                key.epoch,
            ]
        };
        let [f0, f1, f2, f3, f4] = clock(self.from);
        let [t0, t1, t2, t3, t4] = clock(self.to);
        Ok([
            CALIBRATION_VERSION,
            f0,
            f1,
            f2,
            f3,
            f4,
            t0,
            t1,
            t2,
            t3,
            t4,
            self.reference,
            self.offset as u64,
            self.offset_uncertainty,
            self.drift as u64,
            self.drift_uncertainty,
            self.valid_from,
            self.valid_to,
        ])
    }

    /// Decodes and checks a record.
    ///
    /// # Errors
    ///
    /// Returns [`CalibrationError::Version`] and the errors of
    /// [`Calibration::validate`].
    pub fn decode(words: &[u64; CALIBRATION_WORDS]) -> Result<Self, CalibrationError> {
        let [
            version,
            f0,
            f1,
            f2,
            f3,
            f4,
            t0,
            t1,
            t2,
            t3,
            t4,
            reference,
            offset,
            offset_uncertainty,
            drift,
            drift_uncertainty,
            valid_from,
            valid_to,
        ] = *words;
        if version != CALIBRATION_VERSION {
            return Err(CalibrationError::Version { version });
        }
        let clock = |driver0, driver1, journal, domain, epoch| ClockKey {
            observer: ObserverId {
                driver: [driver0, driver1],
                journal,
            },
            domain,
            epoch,
        };
        let calibration = Self {
            from: clock(f0, f1, f2, f3, f4),
            to: clock(t0, t1, t2, t3, t4),
            reference,
            offset: offset as i64,
            offset_uncertainty,
            drift: drift as i64,
            drift_uncertainty,
            valid_from,
            valid_to,
        };
        calibration.validate()?;
        Ok(calibration)
    }
}

/// Errors of calibration records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CalibrationError {
    /// The layout version is not supported.
    #[error("unsupported calibration version {version}")]
    Version {
        /// The version found.
        version: u64,
    },
    /// The validity interval is reversed, or the record maps a clock to
    /// itself.
    #[error("invalid calibration record")]
    Invalid,
}

fn bounded(min: i128, max: i128) -> Latency {
    match (i64::try_from(min), i64::try_from(max)) {
        (Ok(min), Ok(max)) => Latency::Available { min, max },
        _ => Latency::Unavailable(Unavailable::Overflow),
    }
}

/// The latency `b - a` as an interval. Same clock: direct. Different
/// clocks: exactly one direct calibration from `a`'s clock to `b`'s, valid
/// over `a`'s whole interval, converts `a` first. Anything else is
/// unavailable with its reason.
///
/// Precondition: `calibrations` is the complete, authoritative set for the
/// queried times. This function cannot detect a record missing from the
/// slice: an integrator that cannot establish the set (a competing or
/// replacing calibration may be lost) must report the latency unavailable
/// itself, and replay passes the exact historical set it used.
#[must_use]
pub fn latency(a: &Observation, b: &Observation, calibrations: &[Calibration]) -> Latency {
    let (b_low, b_high) = b.interval();
    let (a_low, a_high) = if a.clock == b.clock {
        a.interval()
    } else {
        let (low, high) = a.interval();
        let mut any = false;
        let mut chosen = None;
        for calibration in calibrations
            .iter()
            .filter(|calibration| calibration.from == a.clock && calibration.to == b.clock)
        {
            any = true;
            if calibration.validate().is_ok() && calibration.covers(low, high) {
                if chosen.is_some() {
                    return Latency::Unavailable(Unavailable::Ambiguous);
                }
                chosen = Some(calibration);
            }
        }
        match chosen {
            Some(calibration) => match calibration.convert(low, high) {
                Some(converted) => converted,
                None => return Latency::Unavailable(Unavailable::Overflow),
            },
            None if any => return Latency::Unavailable(Unavailable::NotValid),
            None => return Latency::Unavailable(Unavailable::NoCalibration),
        }
    };
    bounded(b_low - a_high, b_high - a_low)
}

#[cfg(test)]
mod tests;
