// SPDX-License-Identifier: Apache-2.0

use super::*;

fn interval(min: i64, max: i64) -> Latency {
    Latency::Available { min, max }
}

/// Every magnitude maps to a bucket that contains it, buckets partition the
/// range in order, and widths respect the precision.
#[test]
fn buckets_partition_and_respect_precision() {
    for digits in 1..=3u8 {
        let layout = Layout::new(digits, 5_000_000).unwrap();
        let mut expected_low = 0u64;
        for index in 0..layout.len {
            let (low, high) = layout.bucket(index);
            assert_eq!(low, expected_low, "digits {digits} index {index}");
            assert!(low <= high);
            let width = high - low + 1;
            if low >= layout.sub_count {
                // width / low < 10^-d, exactly.
                assert!(
                    u128::from(width) * u128::from(10u64.pow(u32::from(digits))) < u128::from(low)
                );
            } else {
                assert_eq!(width, 1);
            }
            for value in [low, high, low + (high - low) / 2] {
                assert_eq!(layout.index(value), Some(index), "value {value}");
            }
            expected_low = high + 1;
        }
        assert_eq!(expected_low, 5_000_001);
    }
}

#[test]
fn configuration_is_checked() {
    assert_eq!(
        Histogram::new(0, 10, 1).err(),
        Some(HistogramError::InvalidConfig)
    );
    assert_eq!(
        Histogram::new(6, 10, 1).err(),
        Some(HistogramError::InvalidConfig)
    );
    assert_eq!(
        Histogram::new(2, 0, 1).err(),
        Some(HistogramError::InvalidConfig)
    );
    // Highest is bounded by the magnitudes of i64.
    assert!(Layout::new(5, 1 << 63).is_some());
    assert_eq!(
        Histogram::new(2, (1 << 63) + 1, 1).err(),
        Some(HistogramError::InvalidConfig)
    );
}

#[test]
fn quantiles_are_conservative_intervals() {
    let mut histogram = Histogram::new(2, 1_000_000, 1).unwrap();
    assert_eq!(histogram.quantile(1, 2), Ok(Quantile::Empty));
    for (min, max) in [(10, 12), (20, 25), (30, 31), (-5, 2)] {
        histogram.record(interval(min, max)).unwrap();
    }
    // Sorted mins: -5, 10, 20, 30; sorted maxes: 2, 12, 25, 31.
    assert_eq!(
        histogram.quantile(0, 1),
        Ok(Quantile::Interval {
            low: Some(-5),
            high: Some(2)
        })
    );
    assert_eq!(
        histogram.quantile(1, 2),
        Ok(Quantile::Interval {
            low: Some(10),
            high: Some(12)
        })
    );
    assert_eq!(
        histogram.quantile(1, 1),
        Ok(Quantile::Interval {
            low: Some(30),
            high: Some(31)
        })
    );
    assert_eq!(histogram.available(), 4);
}

#[test]
fn out_of_range_values_give_unbounded_sides() {
    let mut histogram = Histogram::new(1, 100, 1).unwrap();
    histogram.record(interval(50, 1_000)).unwrap();
    assert_eq!(
        histogram.quantile(1, 1),
        Ok(Quantile::Interval {
            low: Some(50),
            high: None
        })
    );
    let mut negative = Histogram::new(1, 100, 1).unwrap();
    negative.record(interval(i64::MIN, -1_000)).unwrap();
    assert_eq!(
        negative.quantile(1, 1),
        Ok(Quantile::Interval {
            low: None,
            high: Some(-101)
        })
    );
}

#[test]
fn negative_magnitudes_and_zero() {
    let mut histogram = Histogram::new(1, 1 << 63, 1).unwrap();
    histogram.record(interval(i64::MIN, i64::MIN)).unwrap();
    histogram.record(interval(0, 0)).unwrap();
    let Ok(Quantile::Interval { low, high }) = histogram.quantile(0, 1) else {
        panic!("no interval");
    };
    assert_eq!(low, Some(i64::MIN));
    assert!(high.is_some_and(|high| high < 0));
    assert_eq!(
        histogram.quantile(1, 1),
        Ok(Quantile::Interval {
            low: Some(0),
            high: Some(0)
        })
    );
}

#[test]
fn inputs_are_validated() {
    let mut histogram = Histogram::new(2, 1_000, 1).unwrap();
    assert_eq!(
        histogram.record(interval(5, 4)),
        Err(HistogramError::InvalidInterval)
    );
    assert_eq!(histogram.available(), 0);
    assert_eq!(
        histogram.quantile(1, 0),
        Err(HistogramError::InvalidQuantile)
    );
    assert_eq!(
        histogram.quantile(2, 1),
        Err(HistogramError::InvalidQuantile)
    );
}

#[test]
fn unavailable_latencies_are_counted_apart() {
    let mut histogram = Histogram::new(2, 1_000, 1).unwrap();
    histogram
        .record(Latency::Unavailable(Unavailable::Ambiguous))
        .unwrap();
    assert_eq!(histogram.unavailable(Unavailable::Ambiguous), 1);
    assert_eq!(histogram.quantile(1, 2), Ok(Quantile::Empty));
}

#[test]
fn overflow_refuses_the_record_and_marks_incomplete() {
    let mut histogram = Histogram::new(2, 1_000, 1).unwrap();
    histogram.record(interval(1, 2)).unwrap();
    histogram.available = u64::MAX;
    let before = histogram.clone();
    assert_eq!(
        histogram.record(interval(3, 4)),
        Err(HistogramError::Overflow)
    );
    assert!(histogram.is_incomplete());
    assert_eq!(histogram.min, before.min);
    assert_eq!(histogram.max, before.max);
    assert_eq!(histogram.quantile(1, 2), Ok(Quantile::Incomplete));

    // Incomplete takes precedence over Empty.
    let mut empty = Histogram::new(2, 1_000, 1).unwrap();
    empty.unavailable[0] = u64::MAX;
    assert_eq!(
        empty.record(Latency::Unavailable(Unavailable::NoCalibration)),
        Err(HistogramError::Overflow)
    );
    assert_eq!(empty.quantile(1, 2), Ok(Quantile::Incomplete));
}

#[test]
fn merge_is_all_or_nothing_and_propagates_incompleteness() {
    let mut a = Histogram::new(2, 1_000, 1).unwrap();
    let mut b = Histogram::new(2, 1_000, 1).unwrap();
    a.record(interval(1, 2)).unwrap();
    b.record(interval(10, 20)).unwrap();
    assert_eq!(
        a.merge(&Histogram::new(2, 1_000, 2).unwrap()),
        Err(HistogramError::Mismatch)
    );
    assert_eq!(
        a.merge(&Histogram::new(3, 1_000, 1).unwrap()),
        Err(HistogramError::Mismatch)
    );
    a.merge(&b).unwrap();
    assert_eq!(a.available(), 2);
    let mut full = b.clone();
    full.available = u64::MAX;
    let before = a.clone();
    assert_eq!(a.merge(&full), Err(HistogramError::Overflow));
    assert_eq!(a, before);
    let mut broken = Histogram::new(2, 1_000, 1).unwrap();
    broken.incomplete = true;
    a.merge(&broken).unwrap();
    assert!(a.is_incomplete());
}

/// Property: for random interval sets with known true values, every
/// quantile interval contains the exact quantile of the true values.
#[test]
fn quantile_intervals_contain_the_true_quantile() {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move |bound: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % bound
    };
    for _ in 0..300 {
        let mut histogram = Histogram::new(2, 50_000, 1).unwrap();
        let count = 1 + next(40);
        let mut truths = Vec::new();
        for _ in 0..count {
            // Some true values fall outside the +-50_000 range.
            let truth = next(120_000) as i64 - 60_000;
            let below = next(500) as i64;
            let above = next(500) as i64;
            histogram
                .record(interval(truth - below, truth + above))
                .unwrap();
            truths.push(truth);
        }
        truths.sort_unstable();
        for (numerator, denominator) in [(0u64, 1u64), (1, 4), (1, 2), (9, 10), (99, 100), (1, 1)] {
            let rank = (u128::from(numerator) * u128::from(count))
                .div_ceil(u128::from(denominator))
                .max(1) as usize;
            let truth = truths[rank - 1];
            let Ok(Quantile::Interval { low, high }) = histogram.quantile(numerator, denominator)
            else {
                panic!("no interval");
            };
            assert!(low.is_none_or(|low| low <= truth), "low {low:?} > {truth}");
            assert!(
                high.is_none_or(|high| truth <= high),
                "high {high:?} < {truth}"
            );
        }
    }
}
