// SPDX-License-Identifier: Apache-2.0

use super::{ChainError, LinkSample, compose, link};
use crate::calibrate::{FitConfig, PairedRead, fit};
use crate::clocks::{Calibration, ClockKey, Latency, Observation, Unavailable, latency};
use crate::journal::ObserverId;

fn key(domain: u64) -> ClockKey {
    ClockKey {
        observer: ObserverId {
            driver: [0, 0],
            journal: 0,
        },
        domain,
        epoch: 1,
    }
}

/// A clock `offset` ahead of `t` and `drift` ppb fast from `start`.
fn affine(t: u64, start: u64, offset: i128, drift: i128) -> i128 {
    i128::from(t) + offset + (i128::from(t) - i128::from(start)) * drift / 1_000_000_000
}

/// A fitted calibration `from` to `to` of a clock `offset` ahead and
/// `drift` fast, read every 1 ms for 0.5 s with 50 ns windows.
fn fitted(from: u64, to: u64, start: u64, offset: i128, drift: i128) -> Calibration {
    let reads: Vec<PairedRead> = (0..500_u64)
        .map(|i| {
            let before = start + i * 1_000_000;
            let at = before + (i * 37) % 51;
            PairedRead {
                before,
                target: u64::try_from(affine(at, start, offset, drift)).unwrap(),
                after: before + 50,
            }
        })
        .collect();
    fit(
        &reads,
        &FitConfig {
            from: key(from),
            to: key(to),
            keep_percent: 100,
            extension: 0,
        },
    )
    .unwrap()
    .calibration
}

#[test]
fn a_composition_contains_the_truth_of_the_chain() {
    let start = 10_000_000_000_u64;
    // A to B: 1.7e18 ahead, 70 ppm fast; B to C: 5 us behind, -30 ppm.
    let ab = fitted(1, 2, start, 1_700_000_000_000_000_000, 70_000);
    let b_start = u64::try_from(affine(start, start, 1_700_000_000_000_000_000, 70_000)).unwrap();
    let bc = fitted(2, 3, b_start, -5_000, -30_000);
    let ac = compose(&ab, &bc).unwrap();
    assert_eq!((ac.from, ac.to), (key(1), key(3)));
    for t in (ac.valid_from..=ac.valid_to).step_by(7_000_003) {
        let b = affine(t, start, 1_700_000_000_000_000_000, 70_000);
        let c = affine(u64::try_from(b).unwrap(), b_start, -5_000, -30_000);
        let (low, high) = ac.convert(i128::from(t), i128::from(t)).unwrap();
        assert!(low <= c && c <= high, "{t}: {low} {c} {high}");
    }
    // The composed bounds are near the sum of the parts, not inflated.
    assert!(
        ac.offset_uncertainty <= ab.offset_uncertainty + bc.offset_uncertainty + 4,
        "{ac:?}"
    );
}

#[test]
fn a_composition_holds_only_where_both_hold() {
    let ab = Calibration {
        from: key(1),
        to: key(2),
        reference: 1_000,
        offset: 100,
        offset_uncertainty: 5,
        drift: 0,
        drift_uncertainty: 0,
        valid_from: 0,
        valid_to: 10_000,
    };
    let bc = Calibration {
        from: key(2),
        to: key(3),
        reference: 3_000,
        offset: 0,
        offset_uncertainty: 1,
        drift: 0,
        drift_uncertainty: 0,
        valid_from: 2_000,
        valid_to: 5_000,
    };
    let ac = compose(&ab, &bc).unwrap();
    // t + 100 +/- 5 inside [2000, 5000]: t in [1905, 4895].
    assert_eq!((ac.valid_from, ac.valid_to), (1_905, 4_895));
    let disjoint = Calibration { from: key(9), ..bc };
    assert_eq!(compose(&ab, &disjoint), Err(ChainError::Disjoint));
    let later = Calibration {
        valid_from: 50_000,
        valid_to: 60_000,
        ..bc
    };
    assert_eq!(compose(&ab, &later), Err(ChainError::NoOverlap));
}

#[test]
fn a_link_bounds_the_offset_by_the_samples_and_the_whole_path_delay() {
    let samples: Vec<LinkSample> = (0..100_u64)
        .map(|i| LinkSample {
            time: 1_000_000_000 + i * 1_000_000_000,
            offset: if i == 40 { -46 } else { 12 },
            path_delay: 3_218,
        })
        .collect();
    let calibration = link(key(2), key(3), &samples).unwrap();
    assert_eq!(calibration.offset_uncertainty, 46 + 3_218 + 1);
    assert_eq!(
        (
            calibration.offset,
            calibration.drift,
            calibration.drift_uncertainty
        ),
        (0, 0, 0)
    );
    // Valid over the samples' span only, in the server's time.
    assert!(calibration.valid_from > 1_000_000_000 && calibration.valid_to < 100_000_000_000);
    assert_eq!(link(key(2), key(3), &[]), Err(ChainError::Samples));
    let mut reversed = samples.clone();
    reversed.swap(0, 1);
    assert_eq!(link(key(2), key(3), &reversed), Err(ChainError::Samples));
}

#[test]
fn a_cross_host_latency_becomes_a_value_through_the_chain() {
    // Host A's raw clock to its PHC (fitted), the PTP link from A's PHC
    // to B's, B's PHC to its raw clock (fitted the other way): three
    // calibrations, composed into the one direct one latency needs.
    let start = 5_000_000_000_u64;
    let a_phc = 1_700_000_000_000_000_000_i128;
    let raw_to_phc = fitted(1, 2, start, a_phc, 77_000);
    let phc_start = u64::try_from(affine(start, start, a_phc, 77_000)).unwrap();
    let samples: Vec<LinkSample> = (0..600_u64)
        .map(|i| LinkSample {
            time: phc_start - 1_000_000_000 + i * 5_000_000,
            offset: 10,
            path_delay: 3_200,
        })
        .collect();
    let ptp = link(key(2), key(3), &samples).unwrap();
    let b_raw = -1_699_999_000_000_000_000_i128;
    let phc_to_raw = fitted(3, 4, phc_start, b_raw, -68_000);
    let a_to_b = compose(&compose(&raw_to_phc, &ptp).unwrap(), &phc_to_raw).unwrap();
    let sent = Observation {
        clock: key(1),
        time: start + 200_000_000,
        uncertainty: 0,
    };
    // Without a calibration: unavailable with its reason.
    let received_time = affine(
        u64::try_from(affine(sent.time, start, a_phc, 77_000) + 10 + 30_000).unwrap(),
        phc_start,
        b_raw,
        -68_000,
    );
    let received = Observation {
        clock: key(4),
        time: u64::try_from(received_time).unwrap(),
        uncertainty: 0,
    };
    assert_eq!(
        latency(&sent, &received, &[]),
        Latency::Unavailable(Unavailable::NoCalibration)
    );
    let Latency::Available { min, max } = latency(&sent, &received, &[a_to_b]) else {
        panic!("a value through the chain");
    };
    // The true one-way time is 30 us; the interval holds it, within the
    // link's 3.2 us bound and the fits' own.
    assert!(min <= 30_000 && 30_000 <= max, "{min} {max}");
    assert!(max - min < 10_000, "{min} {max}");
}
