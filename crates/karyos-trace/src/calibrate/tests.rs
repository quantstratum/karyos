// SPDX-License-Identifier: Apache-2.0

use super::{FitConfig, FitError, MIN_KEPT_READS, PairedRead, fit};
use crate::clocks::{ClockKey, Latency, Observation, Unavailable, latency};
use crate::journal::ObserverId;

fn key(domain: u64) -> ClockKey {
    ClockKey {
        observer: ObserverId {
            driver: [1, 2],
            journal: 3,
        },
        domain,
        epoch: 1,
    }
}

fn config(keep_percent: u8, extension: u64) -> FitConfig {
    FitConfig {
        from: key(10),
        to: key(20),
        keep_percent,
        extension,
    }
}

/// A target clock `offset` ahead of the source and running `drift` ppb
/// fast, read every `step` ns from `start`: read `i` takes `window(i)` ns
/// of source time and the target is read at `place(i)` ns into it.
fn reads(
    count: u64,
    start: u64,
    step: u64,
    offset: i128,
    drift: i128,
    window: impl Fn(u64) -> u64,
    place: impl Fn(u64, u64) -> u64,
) -> Vec<PairedRead> {
    (0..count)
        .map(|i| {
            let before = start + i * step;
            let width = window(i);
            let at = before + place(i, width);
            let target = i128::from(at)
                + offset
                + (i128::from(at) - i128::from(start)) * drift / 1_000_000_000;
            PairedRead {
                before,
                target: u64::try_from(target).unwrap(),
                after: before + width,
            }
        })
        .collect()
}

/// The true target time at source time `at`.
fn truth(at: u64, start: u64, offset: i128, drift: i128) -> i128 {
    i128::from(at) + offset + (i128::from(at) - i128::from(start)) * drift / 1_000_000_000
}

#[test]
fn every_read_lies_within_the_fit_and_the_truth_within_its_bounds() {
    // A PHC 1.7e18 ns ahead (TAI since 1970 against a boot clock), 12 ppm
    // fast, read every 1 ms for 2 s, windows of 40 to 79 ns and reads
    // placed anywhere in them.
    let (start, offset, drift) = (5_000_000_000_u64, 1_700_000_000_000_000_000_i128, 12_000);
    let reads = reads(
        2_000,
        start,
        1_000_000,
        offset,
        drift,
        |i| 40 + (i * 7919) % 40,
        |i, width| (i * 104_729) % (width + 1),
    );
    let fitted = fit(&reads, &config(100, 0)).unwrap();
    let calibration = fitted.calibration;
    assert_eq!(fitted.kept, 2_000);
    assert!(calibration.offset_uncertainty <= 80, "{fitted:?}");
    assert!(
        (i128::from(calibration.drift) - drift).abs() <= i128::from(calibration.drift_uncertainty)
    );
    // Every instant of the measured span converts to an interval holding
    // the true target time.
    for at in (start..start + 2_000_000_000).step_by(1_000_003) {
        let (low, high) = calibration.convert(i128::from(at), i128::from(at)).unwrap();
        let real = truth(at, start, offset, drift);
        assert!(low <= real && real <= high, "{at}: {low} {real} {high}");
    }
}

#[test]
fn preempted_reads_are_dropped_by_their_windows() {
    // One read in ten is preempted: a 50 us window with the target read at
    // its end. Keeping the narrowest half leaves only the clean ones.
    let (start, offset, drift) = (1_000, 1_000_000_i128, -3_000);
    let reads = reads(
        1_000,
        start,
        100_000,
        offset,
        drift,
        |i| if i % 10 == 0 { 50_000 } else { 60 },
        |i, width| if i % 10 == 0 { width } else { width / 2 },
    );
    let all = fit(&reads, &config(100, 0)).unwrap();
    let clean = fit(&reads, &config(50, 0)).unwrap();
    assert_eq!(clean.kept, 500);
    assert_eq!(clean.widest_kept_window, 60);
    assert!(clean.calibration.offset_uncertainty <= 61, "{clean:?}");
    assert!(all.calibration.offset_uncertainty >= 25_000, "{all:?}");
}

#[test]
fn the_validity_ends_at_the_last_read_plus_the_extension() {
    let reads = reads(64, 1_000, 1_000, 0, 0, |_| 10, |_, _| 5);
    let fitted = fit(&reads, &config(100, 7)).unwrap();
    assert_eq!(fitted.calibration.valid_from, 1_000);
    assert_eq!(fitted.calibration.valid_to, 1_000 + 63 * 1_000 + 10 + 7);
}

#[test]
fn an_expired_or_absent_calibration_is_unavailable_with_a_reason() {
    let reads = reads(64, 1_000, 1_000, 500, 0, |_| 10, |_, _| 5);
    let calibration = fit(&reads, &config(100, 1_000)).unwrap().calibration;
    let at = |time: u64| Observation {
        clock: calibration.from,
        time,
        uncertainty: 0,
    };
    let target = Observation {
        clock: calibration.to,
        time: 100_000,
        uncertainty: 0,
    };
    // Inside the validity: a value.
    assert!(matches!(
        latency(&at(2_000), &target, &[calibration]),
        Latency::Available { .. }
    ));
    // Past its end (the epoch's validity is over): unavailable, not a number.
    assert_eq!(
        latency(&at(calibration.valid_to + 1), &target, &[calibration]),
        Latency::Unavailable(Unavailable::NotValid)
    );
    // No calibration at all.
    assert_eq!(
        latency(&at(2_000), &target, &[]),
        Latency::Unavailable(Unavailable::NoCalibration)
    );
}

#[test]
fn reads_that_cannot_support_a_calibration_are_refused() {
    let good = reads(64, 1_000, 1_000, 0, 0, |_| 10, |_, _| 5);
    assert_eq!(
        fit(&good[..MIN_KEPT_READS - 1], &config(100, 0)),
        Err(FitError::TooFewReads {
            kept: MIN_KEPT_READS - 1
        })
    );
    assert_eq!(
        fit(&[], &config(100, 0)),
        Err(FitError::TooFewReads { kept: 0 })
    );
    // 10 % of 64 keeps 7.
    assert_eq!(
        fit(&good, &config(10, 0)),
        Err(FitError::TooFewReads { kept: 7 })
    );
    assert_eq!(
        fit(&good, &config(0, 0)),
        Err(FitError::Keep { percent: 0 })
    );
    assert_eq!(
        fit(&good, &config(101, 0)),
        Err(FitError::Keep { percent: 101 })
    );
    let mut backwards = good.clone();
    backwards[5].after = backwards[5].before - 1;
    assert_eq!(
        fit(&backwards, &config(100, 0)),
        Err(FitError::Backwards { index: 5 })
    );
    let mut reordered = good.clone();
    reordered.swap(3, 4);
    assert_eq!(
        fit(&reordered, &config(100, 0)),
        Err(FitError::Backwards { index: 4 })
    );
    let still = vec![
        PairedRead {
            before: 10,
            target: 20,
            after: 10,
        };
        16
    ];
    assert_eq!(fit(&still, &config(100, 0)), Err(FitError::NoSpan));
    assert_eq!(fit(&good, &config(100, u64::MAX)), Err(FitError::Overflow));
}

#[test]
fn the_truth_is_always_inside_the_converted_interval() {
    // A deterministic sweep in place of a property test (no new
    // dependency): offsets, drifts, read periods and window widths.
    let start = 2_000_000_000_000_u64;
    let mut seed = 0x9e37_79b9_u64;
    let mut next = |bound: u64| {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (seed >> 33) % bound
    };
    for _ in 0..200 {
        let offset = i128::from(next(2_000_000_000_000)) - 1_000_000_000_000;
        let drift = i128::from(next(200_000)) - 100_000;
        let step = 1_000 + next(10_000_000);
        let width = 1 + next(10_000);
        let salt = next(1_000_000);
        let reads = reads(
            256,
            start,
            step,
            offset,
            drift,
            |i| 1 + (i * 31 + salt) % width,
            |i, w| (i * 17 + salt) % (w + 1),
        );
        let calibration = fit(&reads, &config(100, 0)).unwrap().calibration;
        let end = reads.last().unwrap().after;
        for at in [start, start + (end - start) / 3, end] {
            let (low, high) = calibration.convert(i128::from(at), i128::from(at)).unwrap();
            let real = truth(at, start, offset, drift);
            assert!(
                low <= real && real <= high,
                "{offset} {drift} {step} {width}: {low} {real} {high}"
            );
        }
    }
}
