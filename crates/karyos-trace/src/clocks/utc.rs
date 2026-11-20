// SPDX-License-Identifier: Apache-2.0

//! The UTC reference record of the calibration journal (SPEC.md §8.4,
//! "Time evidence"; ADR-0090; quantstratum-docs:
//! karyos/design/trace-clocks.md, "UTC reference records";
//! quantstratum/karyos#991).
//!
//! A record states, for a UTC-traceable clock, its bound to UTC, its
//! validity, `source` and `sync_state`, and its time scale with the exact
//! leap table (an IERS Bulletin C number) and smear. It is 18 words, type 2
//! in word 0's low byte; a calibration is type 1. [`UtcReference::utc`]
//! maps a time of the clock to the UTC coordinate `U` (nanoseconds since
//! 1958-01-01 UTC, counted without leap seconds), or to nothing where the
//! evidence cannot say (`no_evidence`).

use super::ClockKey;
use crate::journal::ObserverId;

#[cfg(test)]
mod tests;

/// Words of an encoded UTC reference record, a calibration's width.
pub const UTC_REFERENCE_WORDS: usize = 18;
/// The record type in word 0's low byte.
pub const UTC_REFERENCE_TYPE: u64 = 2;

/// One second, in nanoseconds.
const SECOND: i128 = 1_000_000_000;
/// Femtoseconds per nanosecond.
const FS_PER_NS: i128 = 1_000_000;
/// The newest Bulletin C this build knows (July 2025).
const NEWEST_BULLETIN: u64 = 70;
/// TAI minus UTC, in seconds, from 1972-01-01.
const FIRST_OFFSET: i64 = 10;
/// Each leap: its date (year, month; the first UTC day after it) and TAI
/// minus UTC from then, in seconds.
const LEAPS: [(i64, i64, i64); 27] = [
    (1972, 7, 11),
    (1973, 1, 12),
    (1974, 1, 13),
    (1975, 1, 14),
    (1976, 1, 15),
    (1977, 1, 16),
    (1978, 1, 17),
    (1979, 1, 18),
    (1980, 1, 19),
    (1981, 7, 20),
    (1982, 7, 21),
    (1983, 7, 22),
    (1985, 7, 23),
    (1988, 1, 24),
    (1990, 1, 25),
    (1991, 1, 26),
    (1992, 7, 27),
    (1993, 7, 28),
    (1994, 7, 29),
    (1996, 1, 30),
    (1997, 7, 31),
    (1999, 1, 32),
    (2006, 1, 33),
    (2009, 1, 34),
    (2012, 7, 35),
    (2015, 7, 36),
    (2017, 1, 37),
];

/// How the clock is synchronised to UTC (SPEC.md §8.4 codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Source {
    /// Not stated: the evidence is `no_evidence`.
    NotStated = 0,
    /// A GNSS receiver.
    Gnss = 1,
    /// PTP (IEEE 1588) from a grandmaster.
    Ptp = 2,
    /// NTP.
    Ntp = 3,
    /// Another UTC-traceable source the operator declares.
    Declared = 4,
}

/// The synchronisation state (SPEC.md §8.4 codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SyncState {
    /// Not stated: the evidence is `no_evidence`.
    NotStated = 0,
    /// Synchronised.
    Synchronised = 1,
    /// In holdover.
    Holdover = 2,
    /// Unsynchronised.
    Unsynchronised = 3,
}

/// How the clock counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scale {
    /// TAI.
    Tai,
    /// UTC, stepping at each leap second.
    UtcStepped,
    /// UTC, smearing each leap second over `smear_ns`, of which
    /// `after_ns` fall after the leap (0: ending at it; half: centred).
    UtcSmeared {
        /// The smear's length, never 0.
        smear_ns: u64,
        /// The part after the leap, at most `smear_ns`.
        after_ns: u64,
    },
    /// GPS time (TAI's rate; its origin is given as the TAI instant).
    Gps,
}

impl Scale {
    const fn code(self) -> u64 {
        match self {
            Self::Tai => 1,
            Self::UtcStepped => 2,
            Self::UtcSmeared { .. } => 3,
            Self::Gps => 4,
        }
    }
}

/// A UTC reference record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcReference {
    /// The clock it is about.
    pub clock: ClockKey,
    /// Its synchronisation source.
    pub source: Source,
    /// Its synchronisation state.
    pub sync_state: SyncState,
    /// Its bound to UTC, in the clock's unit.
    pub bound: u64,
    /// The first time of the clock the record holds for.
    pub valid_from: u64,
    /// The last time of the clock the record holds for.
    pub valid_to: u64,
    /// The clock's unit, in femtoseconds; never 0.
    pub tick_fs: u64,
    /// The time scale.
    pub scale: Scale,
    /// A reading of the clock.
    pub origin: u64,
    /// The scale's coordinate at `origin`: TAI nanoseconds since
    /// 1958-01-01 TAI for TAI and GPS, the UTC coordinate for UTC.
    pub origin_scale_ns: u64,
    /// The IERS Bulletin C number whose leap seconds apply; never 0.
    pub leap_table: u64,
    /// The half-width of the error the transformation adds, in ns.
    pub transform_uncertainty_ns: u64,
}

/// Why a UTC reference record is refused, in the order of the checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UtcReferenceError {
    /// Word 0's low byte is not 2.
    #[error("record type {value} is not a UTC reference record")]
    RecordType {
        /// The type found.
        value: u64,
    },
    /// A reserved bit or word is not zero.
    #[error("a reserved field of a UTC reference record is not zero")]
    Reserved,
    /// An unknown `source`, `sync_state` or `scale`.
    #[error("unknown {field} code {value}")]
    Code {
        /// The field.
        field: &'static str,
        /// The value.
        value: u64,
    },
    /// `valid_from > valid_to`.
    #[error("the validity is reversed")]
    Validity,
    /// `tick_fs` is 0.
    #[error("the clock's unit is 0")]
    Tick,
    /// `leap_table` is 0.
    #[error("no leap table is named")]
    LeapTable,
    /// The smear fields do not match the scale.
    #[error("the smear does not match the scale")]
    Smear,
}

impl UtcReference {
    /// Encodes the record.
    ///
    /// # Errors
    ///
    /// The refusals of [`UtcReference::decode`] that a value can hold.
    pub fn encode(&self) -> Result<[u64; UTC_REFERENCE_WORDS], UtcReferenceError> {
        self.validate()?;
        let (smear, after) = match self.scale {
            Scale::UtcSmeared { smear_ns, after_ns } => (smear_ns, after_ns),
            _ => (0, 0),
        };
        let key = self.clock;
        Ok([
            UTC_REFERENCE_TYPE | ((self.source as u64) << 16) | ((self.sync_state as u64) << 24),
            key.observer.driver[0],
            key.observer.driver[1],
            key.observer.journal,
            key.domain,
            key.epoch,
            self.bound,
            self.valid_from,
            self.valid_to,
            self.tick_fs,
            self.scale.code(),
            self.origin,
            self.origin_scale_ns,
            self.leap_table,
            smear,
            self.transform_uncertainty_ns,
            after,
            0,
        ])
    }

    /// Decodes and checks a record.
    ///
    /// # Errors
    ///
    /// The first [`UtcReferenceError`], in its declared order.
    pub fn decode(words: &[u64; UTC_REFERENCE_WORDS]) -> Result<Self, UtcReferenceError> {
        let [
            w0,
            d0,
            d1,
            journal,
            domain,
            epoch,
            bound,
            valid_from,
            valid_to,
            tick_fs,
            scale,
            origin,
            origin_scale_ns,
            leap_table,
            smear_ns,
            transform_uncertainty_ns,
            after_ns,
            reserved,
        ] = *words;
        let kind = w0 & 0xff;
        if kind != UTC_REFERENCE_TYPE {
            return Err(UtcReferenceError::RecordType { value: kind });
        }
        if w0 & 0xffff_ffff_0000_ff00 != 0 || scale & !0xff != 0 || reserved != 0 {
            return Err(UtcReferenceError::Reserved);
        }
        let source = match (w0 >> 16) & 0xff {
            0 => Source::NotStated,
            1 => Source::Gnss,
            2 => Source::Ptp,
            3 => Source::Ntp,
            4 => Source::Declared,
            value => {
                return Err(UtcReferenceError::Code {
                    field: "source",
                    value,
                });
            }
        };
        let sync_state = match (w0 >> 24) & 0xff {
            0 => SyncState::NotStated,
            1 => SyncState::Synchronised,
            2 => SyncState::Holdover,
            3 => SyncState::Unsynchronised,
            value => {
                return Err(UtcReferenceError::Code {
                    field: "sync_state",
                    value,
                });
            }
        };
        let scale = match scale {
            1 => Scale::Tai,
            2 => Scale::UtcStepped,
            3 => Scale::UtcSmeared { smear_ns, after_ns },
            4 => Scale::Gps,
            value => {
                return Err(UtcReferenceError::Code {
                    field: "scale",
                    value,
                });
            }
        };
        let record = Self {
            clock: ClockKey {
                observer: ObserverId {
                    driver: [d0, d1],
                    journal,
                },
                domain,
                epoch,
            },
            source,
            sync_state,
            bound,
            valid_from,
            valid_to,
            tick_fs,
            scale,
            origin,
            origin_scale_ns,
            leap_table,
            transform_uncertainty_ns,
        };
        record.validate()?;
        // A non-smeared scale carries no smear words.
        if !matches!(scale, Scale::UtcSmeared { .. }) && (smear_ns != 0 || after_ns != 0) {
            return Err(UtcReferenceError::Smear);
        }
        Ok(record)
    }

    fn validate(&self) -> Result<(), UtcReferenceError> {
        if self.valid_from > self.valid_to {
            return Err(UtcReferenceError::Validity);
        }
        if self.tick_fs == 0 {
            return Err(UtcReferenceError::Tick);
        }
        if self.leap_table == 0 {
            return Err(UtcReferenceError::LeapTable);
        }
        if let Scale::UtcSmeared { smear_ns, after_ns } = self.scale
            && (smear_ns == 0 || after_ns > smear_ns)
        {
            return Err(UtcReferenceError::Smear);
        }
        Ok(())
    }

    /// The bound to UTC of every time in the validity, in nanoseconds:
    /// `ceil(bound * tick_fs / 10^6) + transform_uncertainty_ns`; `None`
    /// when it overflows (`no_evidence`).
    #[must_use]
    pub fn bound_ns(&self) -> Option<u64> {
        let product = u128::from(self.bound).checked_mul(u128::from(self.tick_fs))?;
        let ns = product.div_ceil(1_000_000);
        u64::try_from(ns)
            .ok()?
            .checked_add(self.transform_uncertainty_ns)
    }

    /// The UTC coordinate `U` of time `t` of the clock, or `None`
    /// (`no_evidence`): outside the validity, on overflow, before 1972,
    /// past the leap table's half-year, inside an inserted second, at an
    /// ambiguous stepped reading, or with a Bulletin C this build does not
    /// know.
    #[must_use]
    pub fn utc(&self, t: u64) -> Option<i128> {
        if t < self.valid_from || t > self.valid_to {
            return None;
        }
        let table = Table::new(self.leap_table)?;
        let elapsed = i128::from(t)
            .checked_sub(i128::from(self.origin))?
            .checked_mul(i128::from(self.tick_fs))?
            .div_euclid(FS_PER_NS);
        let reading = i128::from(self.origin_scale_ns).checked_add(elapsed)?;
        let u = match self.scale {
            Scale::Tai | Scale::Gps => table.tai_to_utc(reading)?,
            Scale::UtcStepped => table.stepped(reading)?,
            Scale::UtcSmeared { smear_ns, after_ns } => {
                table.smeared(reading, i128::from(smear_ns), i128::from(after_ns))?
            }
        };
        (u >= table.first && u < table.end).then_some(u)
    }
}

/// The days from 1958-01-01 to the first of `month` of `year`.
const fn days_since_1958(year: i64, month: i64) -> i64 {
    // Days from civil (Howard Hinnant's algorithm), relative to 1958.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 715_085
}

/// The UTC coordinate of the first of `month` of `year`.
fn u_of(year: i64, month: i64) -> i128 {
    i128::from(days_since_1958(year, month)) * 86_400 * SECOND
}

/// The leaps a Bulletin C names, with its coverage.
struct Table {
    /// 1972-01-01 in `U`.
    first: i128,
    /// The end of the half-year the bulletin announces, in `U`.
    end: i128,
    /// How many of [`LEAPS`] fall before `end`.
    count: usize,
}

impl Table {
    fn new(bulletin: u64) -> Option<Self> {
        if bulletin == 0 || bulletin > NEWEST_BULLETIN {
            return None;
        }
        // Bulletin C 69 is January 2025; one every half-year. It covers to
        // the end of the half-year it is issued in.
        let half = 4050_i64
            .checked_add(i64::try_from(bulletin).ok()?)?
            .checked_sub(69)?;
        let next = half.checked_add(1)?;
        let end = u_of(
            next.div_euclid(2),
            if next.rem_euclid(2) == 0 { 1 } else { 7 },
        );
        let count = LEAPS
            .iter()
            .take_while(|&&(year, month, _)| u_of(year, month) < end)
            .count();
        Some(Self {
            first: u_of(1972, 1),
            end,
            count,
        })
    }

    /// Each leap: its first UTC instant after it, TAI minus UTC before and
    /// after, in nanoseconds.
    fn leaps(&self) -> impl Iterator<Item = (i128, i128, i128)> + '_ {
        let mut before = i128::from(FIRST_OFFSET) * SECOND;
        LEAPS
            .iter()
            .take(self.count)
            .map(move |&(year, month, after)| {
                let after = i128::from(after) * SECOND;
                let leap = (u_of(year, month), before, after);
                before = after;
                leap
            })
    }

    /// `U = T - L(T)`, `None` inside an inserted second.
    fn tai_to_utc(&self, tai: i128) -> Option<i128> {
        let mut offset = i128::from(FIRST_OFFSET) * SECOND;
        for (at, before, after) in self.leaps() {
            if tai < at + before {
                break;
            }
            if tai < at + after {
                return None;
            }
            offset = after;
        }
        tai.checked_sub(offset)
    }

    /// A stepped reading is `U`, except in the second before a positive
    /// leap, which the clock repeats.
    fn stepped(&self, reading: i128) -> Option<i128> {
        let ambiguous = self
            .leaps()
            .any(|(at, before, after)| after > before && reading >= at - SECOND && reading < at);
        (!ambiguous).then_some(reading)
    }

    /// A smeared reading mapped back to `U` over the smear that holds it.
    fn smeared(&self, reading: i128, width: i128, after: i128) -> Option<i128> {
        for (at, before, leap_after) in self.leaps() {
            let sign: i128 = if leap_after > before { 1 } else { -1 };
            let start = at.checked_sub(width.checked_sub(after)?)?;
            if reading < start || reading >= start.checked_add(width)? {
                continue;
            }
            let into = reading.checked_sub(start)?;
            let tau = into
                .checked_mul(width.checked_add(sign * SECOND)?)?
                .div_euclid(width);
            let leap = width.checked_sub(after)?;
            if tau < leap {
                return start.checked_add(tau);
            }
            if sign > 0 && tau < leap.checked_add(SECOND)? {
                return None;
            }
            return start.checked_add(tau)?.checked_sub(sign * SECOND);
        }
        Some(reading)
    }
}
