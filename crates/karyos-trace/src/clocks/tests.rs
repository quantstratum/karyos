// SPDX-License-Identifier: Apache-2.0

use super::*;

const OBSERVER_A: ObserverId = ObserverId {
    driver: [1, 1],
    journal: 1,
};
const OBSERVER_B: ObserverId = ObserverId {
    driver: [2, 2],
    journal: 1,
};

fn clock(observer: ObserverId, epoch: u64) -> ClockKey {
    ClockKey {
        observer,
        domain: 7,
        epoch,
    }
}

fn at(clock: ClockKey, time: u64, uncertainty: u64) -> Observation {
    Observation {
        clock,
        time,
        uncertainty,
    }
}

fn calibration(drift: i64, drift_uncertainty: u64) -> Calibration {
    Calibration {
        from: clock(OBSERVER_A, 0),
        to: clock(OBSERVER_B, 0),
        reference: 0,
        offset: 0,
        offset_uncertainty: 0,
        drift,
        drift_uncertainty,
        valid_from: 0,
        valid_to: u64::MAX,
    }
}

fn available(min: i64, max: i64) -> Latency {
    Latency::Available { min, max }
}

#[test]
fn same_clock_latency_includes_both_uncertainties() {
    let a = at(clock(OBSERVER_A, 0), 100, 2);
    let b = at(clock(OBSERVER_A, 0), 150, 3);
    assert_eq!(latency(&a, &b, &[]), available(45, 55));
    // Clock error can make it negative.
    assert_eq!(latency(&b, &a, &[]), available(-55, -45));
}

#[test]
fn large_timestamps_with_a_small_difference_are_available() {
    let a = at(clock(OBSERVER_A, 0), u64::MAX - 10, 1);
    let b = at(clock(OBSERVER_A, 0), u64::MAX, 1);
    assert_eq!(latency(&a, &b, &[]), available(8, 12));
}

#[test]
fn different_clocks_need_one_valid_calibration() {
    let a = at(clock(OBSERVER_A, 0), 1_000, 0);
    let b = at(clock(OBSERVER_B, 0), 1_500, 0);
    assert_eq!(
        latency(&a, &b, &[]),
        Latency::Unavailable(Unavailable::NoCalibration)
    );
    let mut shifted = calibration(0, 0);
    shifted.offset = 100;
    shifted.offset_uncertainty = 5;
    // a maps to [1095, 1105] of B.
    assert_eq!(latency(&a, &b, &[shifted]), available(395, 405));
    // Equal numbers on another observer, or another epoch, are not the
    // calibrated clock.
    let other_epoch = at(clock(OBSERVER_A, 1), 1_000, 0);
    assert_eq!(
        latency(&other_epoch, &b, &[shifted]),
        Latency::Unavailable(Unavailable::NoCalibration)
    );
    // Two candidates: ambiguous.
    assert_eq!(
        latency(&a, &b, &[shifted, shifted]),
        Latency::Unavailable(Unavailable::Ambiguous)
    );
}

#[test]
fn validity_covers_the_whole_interval() {
    let mut window = calibration(0, 0);
    window.valid_from = 100;
    window.valid_to = 200;
    let b = at(clock(OBSERVER_B, 0), 500, 0);
    // Touching both bounds converts.
    assert!(matches!(
        latency(&at(clock(OBSERVER_A, 0), 150, 50), &b, &[window]),
        Latency::Available { .. }
    ));
    // Crossing a bound, even partly, does not.
    assert_eq!(
        latency(&at(clock(OBSERVER_A, 0), 150, 51), &b, &[window]),
        Latency::Unavailable(Unavailable::NotValid)
    );
}

/// Review witness: drift -2e9 ppb maps t to -t; global extrema over all
/// corners give [-20, -10] for [10, 20].
#[test]
fn a_negative_slope_uses_global_extrema() {
    let mirror = calibration(-2_000_000_000, 0);
    assert_eq!(mirror.convert(10, 20), Some((-20, -10)));
    // A drift interval crossing zero slope: [0.5e9 .. -2.5e9] around -1e9.
    let wide = calibration(-1_000_000_000, 1_500_000_000);
    let (low, high) = wide.convert(10, 20).unwrap();
    // Corner values: t + t*r/1e9 for r in {-2.5e9, 0.5e9}, t in {10, 20}.
    assert_eq!((low, high), (-30, 30));
}

#[test]
fn drift_terms_round_outwards() {
    // drift 1 ppb at delta -1: the exact term is -1e-9.
    let mut tiny = calibration(1, 0);
    tiny.reference = 11;
    // t = 10: exact value 10 - 1e-9; floor 9, ceil 10.
    assert_eq!(tiny.convert(10, 10), Some((9, 10)));
    // t = 12: exact 12 + 1e-9; floor 12, ceil 13.
    assert_eq!(tiny.convert(12, 12), Some((12, 13)));
}

/// The converted interval contains every exact model value (checked on a
/// grid against rational arithmetic).
#[test]
fn conversion_contains_the_exact_model() {
    for drift in [-3_000_000_000i64, -7, 0, 13, 999_999_999] {
        for drift_uncertainty in [0u64, 5, 1_000_000_000] {
            let mut cal = calibration(drift, drift_uncertainty);
            cal.reference = 1_000;
            cal.offset = -40;
            cal.offset_uncertainty = 3;
            let (low, high) = cal.convert(900, 1_300).unwrap();
            for time in [900i128, 1_000, 1_150, 1_300] {
                for rate in [
                    i128::from(drift) - i128::from(drift_uncertainty),
                    i128::from(drift),
                    i128::from(drift) + i128::from(drift_uncertainty),
                ] {
                    for offset in [-43i128, -40, -37] {
                        // value * 1e9, exactly.
                        let scaled = (time + offset) * BILLION + (time - 1_000) * rate;
                        assert!(low * BILLION <= scaled && scaled <= high * BILLION);
                    }
                }
            }
        }
    }
}

#[test]
fn overflowing_products_are_unavailable() {
    let extreme = Calibration {
        drift: i64::MAX,
        drift_uncertainty: u64::MAX,
        reference: u64::MAX,
        ..calibration(0, 0)
    };
    let a = at(clock(OBSERVER_A, 0), 0, 0);
    let b = at(clock(OBSERVER_B, 0), 0, 0);
    assert_eq!(
        latency(&a, &b, &[extreme]),
        Latency::Unavailable(Unavailable::Overflow)
    );
}

#[test]
fn encoding_round_trips_and_refuses_invalid_records() {
    let record = Calibration {
        from: ClockKey {
            observer: ObserverId {
                driver: [0x11, 0x12],
                journal: 0x13,
            },
            domain: 0x14,
            epoch: 0x15,
        },
        to: ClockKey {
            observer: ObserverId {
                driver: [0x21, 0x22],
                journal: 0x23,
            },
            domain: 0x24,
            epoch: 0x25,
        },
        reference: 0x30,
        offset: -2,
        offset_uncertainty: 0x31,
        drift: -3,
        drift_uncertainty: 0x32,
        valid_from: 0x33,
        valid_to: 0x34,
    };
    let golden: [u64; CALIBRATION_WORDS] = [
        1,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x21,
        0x22,
        0x23,
        0x24,
        0x25,
        0x30,
        u64::MAX - 1,
        0x31,
        u64::MAX - 2,
        0x32,
        0x33,
        0x34,
    ];
    assert_eq!(record.encode(), Ok(golden));
    assert_eq!(Calibration::decode(&golden), Ok(record));

    let mut reversed = record;
    reversed.valid_from = 0x35;
    assert_eq!(reversed.encode(), Err(CalibrationError::Invalid));
    let mut same = record;
    same.to = same.from;
    assert_eq!(same.encode(), Err(CalibrationError::Invalid));
    let mut version = golden;
    version[0] = 2;
    assert_eq!(
        Calibration::decode(&version),
        Err(CalibrationError::Version { version: 2 })
    );
    let mut bad = golden;
    bad[16] = 0x40;
    assert_eq!(Calibration::decode(&bad), Err(CalibrationError::Invalid));
}

/// Exact acceptance vectors from the review.
#[test]
fn review_acceptance_vectors() {
    let mut window = calibration(0, 0);
    window.valid_from = 0;
    window.valid_to = 100;
    assert_eq!(
        latency(
            &at(clock(OBSERVER_A, 0), 100, 1),
            &at(clock(OBSERVER_B, 0), 0, 0),
            &[window]
        ),
        Latency::Unavailable(Unavailable::NotValid)
    );
    assert_eq!(
        latency(
            &at(clock(OBSERVER_A, 0), 100, 4),
            &at(clock(OBSERVER_A, 0), 102, 4),
            &[]
        ),
        available(-6, 10)
    );
    let mut tiny = calibration(1, 0);
    tiny.reference = 100;
    // Truncation toward zero would give [99, 99].
    assert_eq!(tiny.convert(99, 99), Some((98, 99)));
    assert_eq!(tiny.convert(101, 101), Some((101, 102)));
    let high = 1u64 << 63;
    assert_eq!(
        latency(
            &at(clock(OBSERVER_A, 0), high + 10, 0),
            &at(clock(OBSERVER_A, 0), high + 13, 0),
            &[]
        ),
        available(3, 3)
    );
}

/// Review regression: a drift product equal to `i128::MIN` is computed
/// without negating it, and the latency is unavailable or bounded, never a
/// panic.
#[test]
fn a_product_equal_to_i128_min_does_not_panic() {
    let extreme = Calibration {
        drift: i64::MIN,
        drift_uncertainty: 1 << 63,
        ..calibration(0, 0)
    };
    let a = at(clock(OBSERVER_A, 0), 1 << 63, 0);
    let b = at(clock(OBSERVER_B, 0), 0, 0);
    assert_eq!(
        latency(&a, &b, &[extreme]),
        Latency::Unavailable(Unavailable::Overflow)
    );
    assert_eq!(
        ceil_billionths(i128::MIN),
        i128::MIN.div_euclid(BILLION) + 1
    );
    assert_eq!(ceil_billionths(-1), 0);
    assert_eq!(ceil_billionths(1), 1);
    assert_eq!(ceil_billionths(-BILLION), -1);
}

/// The public conversion never panics or wraps: a time whose difference
/// from the reference does not fit `i128` gives `None` (karyos#666 review).
#[test]
fn a_conversion_whose_difference_overflows_is_none() {
    let mut record = calibration(0, 0);
    record.reference = 1;
    assert_eq!(record.convert(i128::MIN, i128::MIN), None);
    record.reference = 0;
    assert!(record.convert(0, 0).is_some());
}
