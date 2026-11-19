// SPDX-License-Identifier: Apache-2.0

//! Time evidence and its per-clock verdicts (quantstratum-docs:
//! karyos/SPEC.md §8.4, "Time evidence"; karyos#666).
//!
//! This module is the evidence model and its rules. The calibrations come
//! from the trace clocks of `karyos-trace` (design/trace-clocks.md); the UTC
//! reference record is the deployment clock producer's, never derived here.
//!
//! - [`Source`] and [`SyncState`] are the reserved word 0 codes; an unknown
//!   code is refused, never defaulted.
//! - [`combined_bound`] is SPEC.md's combined bound: the conversion of
//!   `[t, t]` gives `[lo, hi]` in the UTC-traceable clock, UTC lies in
//!   `[lo - e_B, hi + e_B]`, and the divergence is the larger distance from
//!   `t` to the ends. The converted interval must lie in the reference's
//!   validity, conversions are never chained, and bounds add in the worst
//!   case. Arithmetic is in nanoseconds and checked: an overflow is
//!   `no_evidence`, never a clamp.
//! - [`entry_bound`] applies it at a range's minimum and maximum
//!   timestamps (the bound is convex in `t`), not at its first and last
//!   positions.
//! - [`derived_bound`] gives a derived timestamp, such as a clamped
//!   `event_time = max(raw, last)`, its own distance to the raw value's
//!   UTC interval: it never inherits the raw clock's bound.
//! - [`split`] ends an entry at every parameter change, non-monotone
//!   sample and leap boundary.
//! - [`clock_verdict`] is the precedence of SPEC.md's Verdict, and
//!   [`reduce`] is the C-COMP reduction: `not_met` over `no_evidence` over
//!   `met`, every gap kept beside a failure.
//!
//! No regulatory value is built in: the [`Requirement`] is the operator's,
//! and a report with none is refused ([`TimeError::NoRequirement`]).
//! Integrity outcomes are reported apart, by `integrity::verify`.

use std::num::NonZeroU64;

use karyos_trace::clocks::{Calibration, ClockKey};

/// A declared time coordinate: the identity of an epoch and scale (and its
/// leap, TAI or smear transformation) that timestamps and UTC intervals are
/// normalized to before they are compared (SPEC.md §8.4). Two values are
/// compared only when they carry the same coordinate; 0 is "not stated" and
/// has no `Coordinate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Coordinate(NonZeroU64);

impl Coordinate {
    /// The coordinate of `id`, or `None` for 0 ("not stated").
    #[must_use]
    pub const fn new(id: u64) -> Option<Self> {
        match NonZeroU64::new(id) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    /// Its identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Where a UTC-traceable clock gets its time. The values are the reserved
/// word 0 codes of design/trace-clocks.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Source {
    /// Not stated: missing evidence.
    NotStated = 0,
    /// A GNSS receiver.
    Gnss = 1,
    /// PTP (IEEE 1588) from a grandmaster.
    Ptp = 2,
    /// NTP.
    Ntp = 3,
    /// Another UTC-traceable source the operator declares.
    OperatorDeclared = 4,
}

/// A clock's synchronisation state. The values are the reserved word 0
/// codes of design/trace-clocks.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyncState {
    /// Not stated: missing evidence.
    NotStated = 0,
    /// Synchronised.
    Synchronised = 1,
    /// In holdover.
    Holdover = 2,
    /// Unsynchronised.
    Unsynchronised = 3,
}

/// Why time evidence could not be read or a report not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TimeError {
    /// A `source` code this version does not know.
    #[error("unknown source code {0}")]
    UnknownSource(u8),
    /// A `sync_state` code this version does not know.
    #[error("unknown sync_state code {0}")]
    UnknownSyncState(u8),
    /// A report was asked for with no declared requirement.
    #[error("no requirement is declared; a time verdict needs one")]
    NoRequirement,
}

impl Source {
    /// The source of `code`.
    ///
    /// # Errors
    ///
    /// [`TimeError::UnknownSource`] for an unknown code.
    pub const fn from_code(code: u8) -> Result<Self, TimeError> {
        Ok(match code {
            0 => Self::NotStated,
            1 => Self::Gnss,
            2 => Self::Ptp,
            3 => Self::Ntp,
            4 => Self::OperatorDeclared,
            other => return Err(TimeError::UnknownSource(other)),
        })
    }
}

impl SyncState {
    /// The state of `code`.
    ///
    /// # Errors
    ///
    /// [`TimeError::UnknownSyncState`] for an unknown code.
    pub const fn from_code(code: u8) -> Result<Self, TimeError> {
        Ok(match code {
            0 => Self::NotStated,
            1 => Self::Synchronised,
            2 => Self::Holdover,
            3 => Self::Unsynchronised,
            other => return Err(TimeError::UnknownSyncState(other)),
        })
    }
}

/// A UTC reference record: the deployment clock producer's statement of a
/// UTC-traceable clock's bound to UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcReference {
    /// The UTC-traceable clock `B`.
    pub clock: ClockKey,
    /// `e_B`, its bound to UTC, in `B`'s unit (ns).
    pub bound_ns: u64,
    /// First time of `B` the record holds for.
    pub valid_from: u64,
    /// Last time of `B` the record holds for.
    pub valid_to: u64,
    /// Its source.
    pub source: Source,
    /// Its sync state.
    pub sync_state: SyncState,
    /// Whether the epoch, scale and leap, TAI or smear transformation are
    /// stated with their uncertainty. Without them the record is
    /// insufficient evidence.
    pub scale_stated: bool,
    /// The declared coordinate its UTC interval is expressed in; `None`
    /// when not stated, which is missing evidence.
    pub coordinate: Option<Coordinate>,
}

/// What a calibration's target is (`target_kind`, design/trace-clocks.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TargetKind {
    /// Not stated.
    NotStated = 0,
    /// A clock not traceable to UTC.
    NotTraceable = 1,
    /// A clock traceable to UTC.
    Traceable = 2,
}

/// A calibration as time evidence: the record and whether it belongs to an
/// authoritative calibration set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibrationEvidence {
    /// The calibration, `from` the recorded clock `to` clock `B`.
    pub calibration: Calibration,
    /// Its target's kind.
    pub target_kind: TargetKind,
    /// Whether it belongs to an authoritative calibration set.
    pub authoritative: bool,
}

/// Why a bound is `no_evidence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Gap {
    /// The UTC reference is not for the calibration's target clock.
    WrongReference,
    /// The calibration is not valid over the timestamp.
    CalibrationNotValid,
    /// The converted interval leaves the UTC reference's validity.
    ReferenceNotValid,
    /// The UTC reference does not state its scale transformation.
    ScaleNotStated,
    /// The arithmetic does not fit: never clamped.
    Overflow,
    /// An input is missing or "not stated".
    Missing,
    /// The timestamps and the UTC reference are not normalized to the same
    /// declared coordinate.
    CoordinateMismatch,
    /// The evidence is malformed: a calibration its own validation refuses
    /// (such as one from a clock to itself), or an interval whose minimum
    /// is above its maximum.
    Invalid,
}

/// The UTC interval a timestamp `t` of the calibration's source clock lies
/// in, in ns: `[lo - e_B, hi + e_B]`. `coordinate` is the declared
/// coordinate `t` is normalized to; it must be the reference's, so the
/// timestamp and the interval are compared in one coordinate.
///
/// # Errors
///
/// The [`Gap`] that makes it `no_evidence`.
pub fn utc_interval(
    t: u64,
    coordinate: Coordinate,
    calibration: &Calibration,
    reference: &UtcReference,
) -> Result<(i128, i128), Gap> {
    if calibration.validate().is_err() {
        return Err(Gap::Invalid);
    }
    if reference.clock != calibration.to {
        return Err(Gap::WrongReference);
    }
    if !reference.scale_stated {
        return Err(Gap::ScaleNotStated);
    }
    match reference.coordinate {
        None => return Err(Gap::Missing),
        Some(declared) if declared != coordinate => return Err(Gap::CoordinateMismatch),
        Some(_) => {}
    }
    let time = i128::from(t);
    if !calibration.covers(time, time) {
        return Err(Gap::CalibrationNotValid);
    }
    let (lo, hi) = calibration.convert(time, time).ok_or(Gap::Overflow)?;
    if lo < i128::from(reference.valid_from) || hi > i128::from(reference.valid_to) {
        return Err(Gap::ReferenceNotValid);
    }
    let bound = i128::from(reference.bound_ns);
    Ok((
        lo.checked_sub(bound).ok_or(Gap::Overflow)?,
        hi.checked_add(bound).ok_or(Gap::Overflow)?,
    ))
}

/// The larger distance from `value` to the ends of `interval`, in ns.
fn distance(value: i128, (lo, hi): (i128, i128)) -> Result<u64, Gap> {
    let below = value.checked_sub(lo).ok_or(Gap::Overflow)?.unsigned_abs();
    let above = hi.checked_sub(value).ok_or(Gap::Overflow)?.unsigned_abs();
    u64::try_from(below.max(above)).map_err(|_| Gap::Overflow)
}

/// The combined bound of a raw timestamp `t`, normalized to
/// `coordinate`: its larger distance to the UTC interval it lies in, in ns.
///
/// # Errors
///
/// The [`Gap`] that makes it `no_evidence`.
pub fn combined_bound(
    t: u64,
    coordinate: Coordinate,
    calibration: &Calibration,
    reference: &UtcReference,
) -> Result<u64, Gap> {
    distance(
        i128::from(t),
        utc_interval(t, coordinate, calibration, reference)?,
    )
}

/// The bound of an entry whose timestamps range over `[min, max]`: the
/// larger of the bounds at the minimum and the maximum timestamp (the bound
/// is convex in `t`), never at the first and last positions.
///
/// # Errors
///
/// [`Gap::Invalid`] when `min > max`, otherwise the [`Gap`] of either end.
pub fn entry_bound(
    min: u64,
    max: u64,
    coordinate: Coordinate,
    calibration: &Calibration,
    reference: &UtcReference,
) -> Result<u64, Gap> {
    if min > max {
        return Err(Gap::Invalid);
    }
    Ok(
        combined_bound(min, coordinate, calibration, reference)?.max(combined_bound(
            max,
            coordinate,
            calibration,
            reference,
        )?),
    )
}

/// The bound of a derived timestamp `derived` made from the raw timestamp
/// `raw`, such as a clamped `event_time = max(raw, last)`: its own distance
/// to the UTC interval the raw value lies in, the clamp included. It never
/// inherits the raw clock's bound. Both values are normalized to
/// `coordinate`.
///
/// # Errors
///
/// The [`Gap`] that makes it `no_evidence`.
pub fn derived_bound(
    derived: u64,
    raw: u64,
    coordinate: Coordinate,
    calibration: &Calibration,
    reference: &UtcReference,
) -> Result<u64, Gap> {
    distance(
        i128::from(derived),
        utc_interval(raw, coordinate, calibration, reference)?,
    )
}

/// One timestamped sample of a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Its position in the recording.
    pub position: u64,
    /// Its timestamp.
    pub timestamp: u64,
    /// The identity of the evidence parameters in force: calibration, UTC
    /// reference, epoch, source, sync state, granularity, UTC offset and
    /// leader. A change starts a new entry.
    pub parameters: u64,
    /// Whether a leap or smear boundary falls just before it.
    pub leap_boundary: bool,
}

/// An entry: samples under one set of parameters, monotone, with no leap
/// boundary inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The first sample's position.
    pub first_position: u64,
    /// The last sample's position.
    pub last_position: u64,
    /// The minimum timestamp.
    pub min: u64,
    /// The maximum timestamp.
    pub max: u64,
    /// The parameters' identity.
    pub parameters: u64,
}

/// Splits `samples`, in position order, into entries: a new entry starts
/// at a parameter change, a non-monotone sample and a leap boundary.
#[must_use]
pub fn split(samples: &[Sample]) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut last: Option<Sample> = None;
    for sample in samples {
        let continues = last.is_some_and(|last| {
            last.parameters == sample.parameters
                && sample.timestamp >= last.timestamp
                && !sample.leap_boundary
        });
        match entries.last_mut().filter(|_| continues) {
            Some(entry) => {
                entry.last_position = sample.position;
                entry.min = entry.min.min(sample.timestamp);
                entry.max = entry.max.max(sample.timestamp);
            }
            None => entries.push(Entry {
                first_position: sample.position,
                last_position: sample.position,
                min: sample.timestamp,
                max: sample.timestamp,
                parameters: sample.parameters,
            }),
        }
        last = Some(*sample);
    }
    entries
}

/// The operator's requirement for a clock or recording class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirement {
    /// The maximum divergence from UTC, in ns.
    pub max_divergence_ns: u64,
    /// The coarsest granularity allowed, in ns.
    pub max_granularity_ns: u64,
}

/// A time verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// The evidence proves the requirement met.
    Met,
    /// Evidence is missing: neither met nor not met is proved.
    NoEvidence,
    /// The requirement is proved not met.
    NotMet,
}

/// One clock's evidence over a sub-interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockEvidence {
    /// The clock's sync state.
    pub sync_state: SyncState,
    /// Its source.
    pub source: Source,
    /// Its stated granularity, in ns; `None` or 0 when not stated
    /// (design/trace-clocks.md reserves 0 for "not stated").
    pub granularity_ns: Option<u64>,
    /// The declared coordinate its timestamps are normalized to; `None`
    /// when not stated.
    pub coordinate: Option<Coordinate>,
    /// The calibration used, if any.
    pub calibration: Option<CalibrationEvidence>,
    /// The UTC reference used, if any.
    pub reference: Option<UtcReference>,
    /// The sub-interval's timestamp range.
    pub min: u64,
    /// See `min`.
    pub max: u64,
}

/// The verdict of one clock over one sub-interval, in SPEC.md's precedence:
/// `not_met` when unsynchronised, even with evidence missing; otherwise
/// `no_evidence` for any missing input or rule yielding it; otherwise
/// `not_met` when the bound or granularity exceeds the requirement;
/// otherwise `met`, which needs an authoritative direct calibration to a
/// UTC-traceable clock and a UTC reference, both valid over the whole
/// sub-interval. Holdover meets nothing without such a bound.
#[must_use]
pub fn clock_verdict(evidence: &ClockEvidence, requirement: &Requirement) -> Verdict {
    if evidence.sync_state == SyncState::Unsynchronised {
        return Verdict::NotMet;
    }
    let (Some(calibration), Some(reference), Some(granularity), Some(coordinate)) = (
        evidence.calibration,
        evidence.reference,
        evidence.granularity_ns,
        evidence.coordinate,
    ) else {
        return Verdict::NoEvidence;
    };
    if granularity == 0
        || evidence.sync_state == SyncState::NotStated
        || evidence.source == Source::NotStated
        || reference.sync_state == SyncState::NotStated
        || reference.source == Source::NotStated
        || reference.sync_state == SyncState::Unsynchronised
        || calibration.target_kind != TargetKind::Traceable
        || !calibration.authoritative
    {
        return Verdict::NoEvidence;
    }
    let Ok(bound) = entry_bound(
        evidence.min,
        evidence.max,
        coordinate,
        &calibration.calibration,
        &reference,
    ) else {
        return Verdict::NoEvidence;
    };
    if bound > requirement.max_divergence_ns || granularity > requirement.max_granularity_ns {
        return Verdict::NotMet;
    }
    Verdict::Met
}

/// The combined verdict of several clocks or sub-intervals (C-COMP):
/// `not_met` over `no_evidence` over `met`, with every `no_evidence` gap
/// kept beside a `not_met`, by its index in `verdicts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combined {
    /// The reduced verdict.
    pub verdict: Verdict,
    /// The inputs that lacked evidence.
    pub gaps: Vec<usize>,
}

/// Reduces `verdicts` against a declared requirement.
///
/// # Errors
///
/// [`TimeError::NoRequirement`] when none is declared: no verdict is made.
pub fn reduce(
    verdicts: &[Verdict],
    requirement: Option<&Requirement>,
) -> Result<Combined, TimeError> {
    requirement.ok_or(TimeError::NoRequirement)?;
    let verdict = verdicts
        .iter()
        .copied()
        .max()
        .unwrap_or(Verdict::NoEvidence);
    let gaps = verdicts
        .iter()
        .enumerate()
        .filter(|(_, verdict)| **verdict == Verdict::NoEvidence)
        .map(|(index, _)| index)
        .collect();
    Ok(Combined { verdict, gaps })
}

#[cfg(test)]
mod tests;
