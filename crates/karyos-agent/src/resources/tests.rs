// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_trace::ObserverId;

use super::*;

fn clock(journal: u64) -> ClockKey {
    ClockKey {
        observer: ObserverId {
            driver: [1, 2],
            journal,
        },
        domain: 1,
        epoch: 3,
    }
}

fn calibration(to: u64, valid_from: u64, valid_to: u64) -> Calibration {
    Calibration {
        from: clock(1),
        to: clock(to),
        reference: valid_from,
        offset: 0,
        offset_uncertainty: 1,
        drift: 0,
        drift_uncertainty: 0,
        valid_from,
        valid_to,
    }
}

fn unavailable(reason: CalibrationUnavailable) -> CalibrationState {
    CalibrationState::Unavailable { reason }
}

/// R-CORE-40: a clock with no valid calibration reads as unavailable with
/// its reason, never as a value: none at all, none to check against, only
/// expired ones, only ones not started, two for one target; one valid per
/// target holds.
#[test]
fn a_clock_without_a_valid_calibration_reads_unavailable_with_its_reason() {
    let at = Some(100);
    assert_eq!(
        calibration_state(clock(1), at, &[]),
        unavailable(CalibrationUnavailable::NoCalibration)
    );
    // Another clock's calibration is not this one's.
    let mut other = calibration(2, 0, 200);
    other.from = clock(3);
    assert_eq!(
        calibration_state(clock(1), at, &[other]),
        unavailable(CalibrationUnavailable::NoCalibration)
    );
    // A malformed record (a reversed range) is no calibration.
    assert_eq!(
        calibration_state(clock(1), at, &[calibration(2, 200, 0)]),
        unavailable(CalibrationUnavailable::NoCalibration)
    );
    assert_eq!(
        calibration_state(clock(1), None, &[calibration(2, 0, 200)]),
        unavailable(CalibrationUnavailable::NotObserved)
    );
    assert_eq!(
        calibration_state(clock(1), at, &[calibration(2, 0, 99)]),
        unavailable(CalibrationUnavailable::Expired)
    );
    assert_eq!(
        calibration_state(clock(1), at, &[calibration(2, 101, 200)]),
        unavailable(CalibrationUnavailable::NotYetValid)
    );
    assert_eq!(
        calibration_state(
            clock(1),
            at,
            &[calibration(2, 0, 200), calibration(2, 50, 150)]
        ),
        unavailable(CalibrationUnavailable::Ambiguous)
    );
    assert_eq!(
        calibration_state(
            clock(1),
            at,
            &[
                calibration(2, 0, 200),
                calibration(4, 0, 200),
                calibration(2, 0, 99)
            ]
        ),
        CalibrationState::Valid { count: 2 }
    );
    // Its range's ends hold.
    assert_eq!(
        calibration_state(clock(1), Some(200), &[calibration(2, 100, 200)]),
        CalibrationState::Valid { count: 1 }
    );
}

#[test]
fn a_calibration_shows_its_range_and_its_state() {
    let held = calibration(2, 10, 20);
    for (at, state) in [
        (None, "not_observed"),
        (Some(9), "not_yet_valid"),
        (Some(10), "valid"),
        (Some(20), "valid"),
        (Some(21), "expired"),
    ] {
        let view = calibration_view(held, at);
        assert_eq!((view.calibration, view.state), (held, state), "{at:?}");
    }
}

fn cell(stream: u64, label: &str, value: u64) -> Counter {
    Counter {
        label: label.to_owned(),
        type_id: 1,
        stream,
        lane: 0,
        kind: 0,
        participant: 0,
        cell_registration: 0,
        value,
        read_ns: 0,
        changed_ns: None,
    }
}

/// The cells a sender writes for a publication: `limiters` bits, then
/// `values` in `RATE_LABELS` order from the version on.
fn publication_cells(stream: u64, limiters: u64, values: [u64; 11]) -> Vec<Counter> {
    let mut cells = vec![
        cell(stream, PUBLICATION, 9),
        cell(stream, RATE_LABELS[0], limiters),
    ];
    for (label, value) in RATE_LABELS[1..].iter().zip(values) {
        cells.push(cell(stream, label, value));
    }
    cells
}

fn policy(per_second: u64, burst: u64, bytes: Option<(u64, u64)>) -> RatePolicy {
    RatePolicy {
        messages: Rate { per_second, burst },
        bytes: bytes.map(|(per_second, burst)| Rate { per_second, burst }),
    }
}

/// R-CORE-40: the rate limits read reports each publication's policy in
/// force with its version and each limiter's refusals; a limiter that
/// refused nothing (counted, 0) differs from one the gate does not have
/// (`None`) and from one the driver does not count (`Unknown`, a driver
/// with no rate cells).
#[test]
fn the_rate_limits_read_tells_zero_refusals_from_not_counted() {
    let mut counters = Vec::new();
    // Stream 5: a publication bucket with a byte limit that refused
    // nothing, at version 3, and a control bucket that refused twice.
    counters.extend(publication_cells(
        5,
        PUBLICATION_BUCKET | PUBLICATION_BYTES | CONTROL_BUCKET | CONTROL_BYTES,
        [3, 100, 10, 6400, 640, 0, 2, 2, 128, 128, 2],
    ));
    // Stream 6: no guard, so no bucket: all 0.
    counters.extend(publication_cells(6, 0, [0; 11]));
    // Stream 7: a driver older than karyos#741, with no rate cell.
    counters.push(cell(7, PUBLICATION, 1));
    // A driver-wide cell and an image's are no publication.
    counters.push(cell(0, RATE_LABELS[6], 4));
    counters.push(cell(8, "network losses", 1));
    let read = rate_limits(&counters);
    assert_eq!(
        read,
        [
            PublicationRates {
                registration: 5,
                publication: Limiter::Limited {
                    policy: policy(100, 10, Some((6400, 640))),
                    refusals: 0,
                },
                control: Limiter::Limited {
                    policy: policy(2, 2, Some((128, 128))),
                    refusals: 2,
                },
                version: Some(3),
            },
            PublicationRates {
                registration: 6,
                publication: Limiter::None,
                control: Limiter::None,
                version: Some(0),
            },
            PublicationRates {
                registration: 7,
                publication: Limiter::Unknown,
                control: Limiter::Unknown,
                version: None,
            },
        ]
    );
}

/// A pass that missed one of a bucket's cells (one freed and allocated
/// again between passes) reads that bucket as not counted, never as 0.
#[test]
fn a_bucket_with_a_cell_missing_is_not_counted() {
    let mut counters =
        publication_cells(5, PUBLICATION_BUCKET, [1, 10, 10, 0, 0, 4, 0, 0, 0, 0, 0]);
    counters.retain(|counter| counter.label != "network rate refusals");
    let read = rate_limits(&counters);
    assert_eq!(read[0].publication, Limiter::Unknown);
    assert_eq!(read[0].control, Limiter::None);
}
