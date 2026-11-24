// SPDX-License-Identifier: Apache-2.0

//! The read resources for clocks, calibrations and rate limits
//! (R-CORE-40, karyos#741; quantstratum-docs:
//! karyos/design/product-requirements-on-core.md, R-CORE-40), as the parts
//! that touch no mapping, so every platform tests them.
//!
//! - **Clocks.** A clock's calibration state is decided as
//!   `karyos_trace::latency` decides a calibration's use (SPEC.md §7.3,
//!   ADR-0040): one calibration from the clock to a target, valid at the
//!   clock's last observed time, holds; none, only expired ones, only ones
//!   not started yet, or two for one target, is unavailable with that
//!   reason. Nothing here derives a latency or an offset to show: a clock
//!   reads as a calibration's state, never as a number it does not
//!   justify. The agent reads no calibration source until karyos#118
//!   produces calibrations, so every clock reads `no_calibration` and a
//!   clocks view legitimately shows no cross-host calibration until then.
//! - **Rate limits.** A network publication's sender gate writes its
//!   limiters into its counter cells (`network rate limiters` and the
//!   cells after it, karyos-driver's counters table): which buckets exist,
//!   the policy version applied, each bucket's policy and refusals. A
//!   bucket whose bit is clear is [`Limiter::None`], and a driver with no
//!   such cells is [`Limiter::Unknown`]: neither is ever read as a bucket
//!   that refused nothing.
//! - **Off the data path.** Both reads use what the agent already holds:
//!   the trace window's journals and the last sampling pass's counters,
//!   so a request touches no mapping and costs O(journals) or O(cells),
//!   both bounded by configuration.

use std::collections::BTreeMap;

use karyos_sys::rate_limit::{Rate, RatePolicy};
use karyos_trace::{Calibration, ClockKey};

use crate::api::{
    CalibrationState, CalibrationUnavailable, CalibrationView, Counter, Limiter, PublicationRates,
};

/// Whether a calibration from `clock` holds at `at`, the clock's last
/// observed time, among `calibrations`.
pub(crate) fn calibration_state(
    clock: ClockKey,
    at: Option<u64>,
    calibrations: &[Calibration],
) -> CalibrationState {
    let unavailable = |reason| CalibrationState::Unavailable { reason };
    let mut from = calibrations
        .iter()
        .filter(|calibration| calibration.from == clock && calibration.validate().is_ok())
        .peekable();
    if from.peek().is_none() {
        return unavailable(CalibrationUnavailable::NoCalibration);
    }
    let Some(at) = at else {
        return unavailable(CalibrationUnavailable::NotObserved);
    };
    let time = i128::from(at);
    let mut valid: Vec<&Calibration> = Vec::new();
    let mut expired = false;
    for calibration in from {
        if calibration.covers(time, time) {
            // Two for one target: `latency` would refuse both.
            if valid.iter().any(|held| held.to == calibration.to) {
                return unavailable(CalibrationUnavailable::Ambiguous);
            }
            valid.push(calibration);
        } else if calibration.valid_to < at {
            expired = true;
        }
    }
    match (valid.len(), expired) {
        (0, true) => unavailable(CalibrationUnavailable::Expired),
        (0, false) => unavailable(CalibrationUnavailable::NotYetValid),
        (count, _) => CalibrationState::Valid { count },
    }
}

/// `calibration` as the agent shows it, its state at `at`, its source
/// clock's last observed time.
pub(crate) fn calibration_view(calibration: Calibration, at: Option<u64>) -> CalibrationView {
    let state = match at {
        None => "not_observed",
        Some(at) if at > calibration.valid_to => "expired",
        Some(at) if at < calibration.valid_from => "not_yet_valid",
        Some(_) => "valid",
    };
    CalibrationView { calibration, state }
}

/// The first cell of a network publication: every one with cells has it.
const PUBLICATION: &str = "network frames sent";
/// The rate cells, in `PUBLICATION_CELLS` order (karyos-driver).
const RATE_LABELS: [&str; 12] = [
    "network rate limiters",
    "network rate policy version",
    "network rate messages per second",
    "network rate message burst",
    "network rate bytes per second",
    "network rate byte burst",
    "network rate refusals",
    "network control rate messages per second",
    "network control rate message burst",
    "network control rate bytes per second",
    "network control rate byte burst",
    "network control rate refusals",
];
/// Bits of `network rate limiters`: the publication's bucket and its byte
/// limit, the control bucket and its byte limit.
const PUBLICATION_BUCKET: u64 = 1;
const PUBLICATION_BYTES: u64 = 2;
const CONTROL_BUCKET: u64 = 4;
const CONTROL_BYTES: u64 = 8;

/// The rate limiters of the network publications whose cells `counters`
/// (one sampling pass) holds, by stream registration.
pub(crate) fn rate_limits(counters: &[Counter]) -> Vec<PublicationRates> {
    let mut publications: BTreeMap<u64, [Option<u64>; RATE_LABELS.len()]> = BTreeMap::new();
    for counter in counters {
        // A publication's cells are keyed by its registration alone.
        if counter.stream == 0 || counter.lane != 0 || counter.kind != 0 {
            continue;
        }
        if counter.label == PUBLICATION {
            let _ = publications
                .entry(counter.stream)
                .or_insert([None; RATE_LABELS.len()]);
        } else if let Some(at) = RATE_LABELS.iter().position(|label| *label == counter.label) {
            let cells = publications
                .entry(counter.stream)
                .or_insert([None; RATE_LABELS.len()]);
            if let Some(cell) = cells.get_mut(at) {
                *cell = Some(counter.value);
            }
        }
    }
    publications
        .into_iter()
        .map(|(registration, cells)| publication(registration, &cells))
        .collect()
}

/// One publication's limiters from its rate cells, `None` for a cell the
/// pass did not hold.
fn publication(registration: u64, cells: &[Option<u64>; RATE_LABELS.len()]) -> PublicationRates {
    let [
        bits,
        version,
        p_rate,
        p_burst,
        p_byte_rate,
        p_byte_burst,
        p_refusals,
        c_rate,
        c_burst,
        c_byte_rate,
        c_byte_burst,
        c_refusals,
    ] = *cells;
    let limiter = |bucket: u64, bytes: u64, values: [Option<u64>; 5]| {
        let [rate, burst, byte_rate, byte_burst, refusals] = values;
        let Some(bits) = bits else {
            return Limiter::Unknown;
        };
        if bits & bucket == 0 {
            return Limiter::None;
        }
        let (Some(per_second), Some(burst), Some(refusals)) = (rate, burst, refusals) else {
            return Limiter::Unknown;
        };
        let bytes = if bits & bytes == 0 {
            None
        } else {
            match (byte_rate, byte_burst) {
                (Some(per_second), Some(burst)) => Some(Rate { per_second, burst }),
                _ => return Limiter::Unknown,
            }
        };
        Limiter::Limited {
            policy: RatePolicy {
                messages: Rate { per_second, burst },
                bytes,
            },
            refusals,
        }
    };
    PublicationRates {
        registration,
        publication: limiter(
            PUBLICATION_BUCKET,
            PUBLICATION_BYTES,
            [p_rate, p_burst, p_byte_rate, p_byte_burst, p_refusals],
        ),
        control: limiter(
            CONTROL_BUCKET,
            CONTROL_BYTES,
            [c_rate, c_burst, c_byte_rate, c_byte_burst, c_refusals],
        ),
        version,
    }
}

#[cfg(test)]
mod tests;
