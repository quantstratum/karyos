// SPDX-License-Identifier: Apache-2.0

//! Tests of time evidence and its verdicts (karyos#666).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use karyos_trace::journal::ObserverId;

use super::*;

const VALID_TO: u64 = 1_000_000_000_000;

/// The declared coordinate the fixtures' timestamps and UTC reference share.
fn coordinate() -> Coordinate {
    Coordinate::new(7).unwrap()
}

fn clock(domain: u64) -> ClockKey {
    ClockKey {
        observer: ObserverId {
            driver: [1, 2],
            journal: 3,
        },
        domain,
        epoch: 1,
    }
}

/// Clock A (domain 1) to the UTC-traceable clock B (domain 2): offset
/// 1000 ns, uncertainty 10 ns, no drift.
fn calibration() -> CalibrationEvidence {
    CalibrationEvidence {
        calibration: Calibration {
            from: clock(1),
            to: clock(2),
            reference: 0,
            offset: 1_000,
            offset_uncertainty: 10,
            drift: 0,
            drift_uncertainty: 0,
            valid_from: 0,
            valid_to: VALID_TO,
        },
        target_kind: TargetKind::Traceable,
        authoritative: true,
    }
}

/// B is within 50 ns of UTC.
fn reference() -> UtcReference {
    UtcReference {
        clock: clock(2),
        bound_ns: 50,
        valid_from: 0,
        valid_to: VALID_TO,
        source: Source::Ptp,
        sync_state: SyncState::Synchronised,
        scale_stated: true,
        coordinate: Some(coordinate()),
    }
}

fn evidence() -> ClockEvidence {
    ClockEvidence {
        sync_state: SyncState::Synchronised,
        source: Source::Ptp,
        granularity_ns: Some(1),
        coordinate: Some(coordinate()),
        calibration: Some(calibration()),
        reference: Some(reference()),
        min: 1_000,
        max: 2_000,
    }
}

/// 1060 ns is the bound of every timestamp under the fixtures: UTC lies in
/// `[t + 940, t + 1060]`.
fn requirement(max_divergence_ns: u64) -> Requirement {
    Requirement {
        max_divergence_ns,
        max_granularity_ns: 1_000,
    }
}

#[test]
fn unknown_source_and_sync_state_codes_are_refused() {
    assert_eq!(Source::from_code(2), Ok(Source::Ptp));
    assert_eq!(Source::from_code(5), Err(TimeError::UnknownSource(5)));
    assert_eq!(SyncState::from_code(3), Ok(SyncState::Unsynchronised));
    assert_eq!(SyncState::from_code(9), Err(TimeError::UnknownSyncState(9)));
}

#[test]
fn the_combined_bound_is_the_larger_distance_to_the_utc_interval() {
    let cal = calibration().calibration;
    assert_eq!(
        utc_interval(1_000, coordinate(), &cal, &reference()),
        Ok((1_940, 2_060))
    );
    assert_eq!(
        combined_bound(1_000, coordinate(), &cal, &reference()),
        Ok(1_060)
    );
}

#[test]
fn the_bound_is_taken_at_the_minimum_and_maximum_timestamps() {
    // A drifting calibration: the bound grows away from the reference, so
    // the entry's bound is the one at its extreme timestamp, wherever in
    // the range its position is.
    let mut cal = calibration().calibration;
    cal.drift_uncertainty = 1_000_000;
    let at_min = combined_bound(1_000, coordinate(), &cal, &reference()).unwrap();
    let at_max = combined_bound(500_000, coordinate(), &cal, &reference()).unwrap();
    assert!(at_max > at_min);
    assert_eq!(
        entry_bound(1_000, 500_000, coordinate(), &cal, &reference()),
        Ok(at_max)
    );
}

#[test]
fn missing_or_invalid_evidence_is_no_evidence_never_a_bound() {
    let cal = calibration().calibration;
    let mut other = reference();
    other.clock = clock(9);
    assert_eq!(
        combined_bound(1_000, coordinate(), &cal, &other),
        Err(Gap::WrongReference)
    );
    let mut unscaled = reference();
    unscaled.scale_stated = false;
    assert_eq!(
        combined_bound(1_000, coordinate(), &cal, &unscaled),
        Err(Gap::ScaleNotStated)
    );
    let mut short = reference();
    short.valid_to = 1_500;
    assert_eq!(
        combined_bound(1_000, coordinate(), &cal, &short),
        Err(Gap::ReferenceNotValid)
    );
    assert_eq!(
        combined_bound(VALID_TO + 1, coordinate(), &cal, &reference()),
        Err(Gap::CalibrationNotValid)
    );
}

#[test]
fn an_unsynchronised_clock_is_not_met_even_with_evidence_missing() {
    let unsynchronised = ClockEvidence {
        sync_state: SyncState::Unsynchronised,
        calibration: None,
        reference: None,
        granularity_ns: None,
        ..evidence()
    };
    assert_eq!(
        clock_verdict(&unsynchronised, &requirement(5_000)),
        Verdict::NotMet
    );
}

#[test]
fn a_missing_record_or_a_field_not_stated_is_no_evidence() {
    let missing = [
        ClockEvidence {
            reference: None,
            ..evidence()
        },
        ClockEvidence {
            calibration: None,
            ..evidence()
        },
        ClockEvidence {
            granularity_ns: None,
            ..evidence()
        },
        ClockEvidence {
            source: Source::NotStated,
            ..evidence()
        },
        ClockEvidence {
            sync_state: SyncState::NotStated,
            ..evidence()
        },
    ];
    for evidence in missing {
        assert_eq!(
            clock_verdict(&evidence, &requirement(5_000)),
            Verdict::NoEvidence,
            "{evidence:?}"
        );
    }
}

#[test]
fn met_needs_an_authoritative_direct_calibration_to_utc() {
    assert_eq!(
        clock_verdict(&evidence(), &requirement(5_000)),
        Verdict::Met
    );
    let mut indirect = calibration();
    indirect.target_kind = TargetKind::NotTraceable;
    let mut unauthoritative = calibration();
    unauthoritative.authoritative = false;
    for calibration in [indirect, unauthoritative] {
        let evidence = ClockEvidence {
            calibration: Some(calibration),
            ..evidence()
        };
        assert_eq!(
            clock_verdict(&evidence, &requirement(5_000)),
            Verdict::NoEvidence
        );
    }
}

#[test]
fn a_bound_or_granularity_over_the_requirement_is_not_met() {
    assert_eq!(
        clock_verdict(&evidence(), &requirement(1_000)),
        Verdict::NotMet
    );
    let coarse = ClockEvidence {
        granularity_ns: Some(2_000),
        ..evidence()
    };
    assert_eq!(clock_verdict(&coarse, &requirement(5_000)), Verdict::NotMet);
}

#[test]
fn holdover_meets_only_with_an_authoritative_bound_over_the_full_range() {
    let holdover = ClockEvidence {
        sync_state: SyncState::Holdover,
        ..evidence()
    };
    assert_eq!(clock_verdict(&holdover, &requirement(5_000)), Verdict::Met);
    let mut short = reference();
    short.valid_to = 2_500;
    let uncovered = ClockEvidence {
        reference: Some(short),
        ..holdover
    };
    assert_eq!(
        clock_verdict(&uncovered, &requirement(5_000)),
        Verdict::NoEvidence
    );
}

#[test]
fn verdicts_reduce_not_met_over_no_evidence_with_the_gaps_kept() {
    // C-COMP: clock A exceeds the requirement while clock B lacks evidence.
    let combined = reduce(
        &[Verdict::NotMet, Verdict::NoEvidence, Verdict::Met],
        Some(&requirement(1)),
    )
    .unwrap();
    assert_eq!(combined.verdict, Verdict::NotMet);
    assert_eq!(combined.gaps, vec![1]);
    assert_eq!(
        reduce(&[Verdict::Met, Verdict::NoEvidence], Some(&requirement(1)))
            .unwrap()
            .verdict,
        Verdict::NoEvidence
    );
}

#[test]
fn no_verdict_is_made_without_a_requirement() {
    assert_eq!(reduce(&[Verdict::Met], None), Err(TimeError::NoRequirement));
}

fn sample(position: u64, timestamp: u64, parameters: u64) -> Sample {
    Sample {
        position,
        timestamp,
        parameters,
        leap_boundary: false,
    }
}

#[test]
fn a_bound_change_splits_the_entry() {
    let entries = split(&[sample(0, 10, 1), sample(8, 20, 1), sample(16, 30, 2)]);
    assert_eq!(entries.len(), 2);
    assert_eq!((entries[0].min, entries[0].max), (10, 20));
    assert_eq!(entries[1].parameters, 2);
}

#[test]
fn a_non_monotone_sample_splits_the_entry() {
    let entries = split(&[sample(0, 10, 1), sample(8, 30, 1), sample(16, 20, 1)]);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].first_position, 16);
}

#[test]
fn a_leap_boundary_splits_the_entry() {
    let mut leap = sample(16, 30, 1);
    leap.leap_boundary = true;
    let entries = split(&[sample(0, 10, 1), sample(8, 20, 1), leap]);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].last_position, 8);
}

#[test]
fn a_clamped_timestamp_never_carries_the_raw_bound() {
    let cal = calibration().calibration;
    // event_time = max(raw, last): raw 1000 is clamped up to 5000.
    let raw = combined_bound(1_000, coordinate(), &cal, &reference()).unwrap();
    let derived = derived_bound(5_000, 1_000, coordinate(), &cal, &reference()).unwrap();
    assert_ne!(derived, raw);
    assert_eq!(derived, 3_060);
    // Without the raw value's UTC interval it is no_evidence, never the
    // raw bound.
    let mut unscaled = reference();
    unscaled.scale_stated = false;
    assert_eq!(
        derived_bound(5_000, 1_000, coordinate(), &cal, &unscaled),
        Err(Gap::ScaleNotStated)
    );
}

#[test]
fn a_clamp_following_a_leader_whose_clock_is_behind_gets_its_own_bound() {
    // The leader's clock is behind: its last value is below the raw one,
    // so the clamp leaves the raw value; the derived bound is the raw
    // value's distance, computed, not assumed.
    let cal = calibration().calibration;
    let raw = 4_000;
    let leader_last = 3_000;
    let derived = raw.max(leader_last);
    assert_eq!(
        derived_bound(derived, raw, coordinate(), &cal, &reference()),
        combined_bound(raw, coordinate(), &cal, &reference())
    );
    // And when the leader is ahead the clamp moves it, and its own bound
    // grows with the clamp.
    let ahead = derived_bound(raw.max(9_000), raw, coordinate(), &cal, &reference()).unwrap();
    assert!(ahead > combined_bound(raw, coordinate(), &cal, &reference()).unwrap());
}

/// A calibration its own validation refuses, from a clock to itself, is
/// never evidence, even marked authoritative (karyos#666 review).
#[test]
fn an_invalid_calibration_is_no_evidence() {
    let mut own = calibration();
    own.calibration.to = own.calibration.from;
    let mut reference = reference();
    reference.clock = own.calibration.from;
    assert_eq!(
        utc_interval(1_000, coordinate(), &own.calibration, &reference),
        Err(Gap::Invalid)
    );
    let evidence = ClockEvidence {
        calibration: Some(own),
        reference: Some(reference),
        ..evidence()
    };
    assert_eq!(
        clock_verdict(&evidence, &requirement(5_000)),
        Verdict::NoEvidence
    );
}

/// A timestamp and a UTC reference in different declared coordinates are
/// never compared, and a coordinate not stated is missing evidence.
#[test]
fn timestamps_and_utc_are_compared_only_in_one_coordinate() {
    let cal = calibration().calibration;
    let other = Coordinate::new(8).unwrap();
    assert_eq!(
        combined_bound(1_000, other, &cal, &reference()),
        Err(Gap::CoordinateMismatch)
    );
    assert_eq!(
        derived_bound(5_000, 1_000, other, &cal, &reference()),
        Err(Gap::CoordinateMismatch)
    );
    let mut unstated = reference();
    unstated.coordinate = None;
    assert_eq!(
        combined_bound(1_000, coordinate(), &cal, &unstated),
        Err(Gap::Missing)
    );
    assert_eq!(Coordinate::new(0), None);
    for evidence in [
        ClockEvidence {
            coordinate: Some(other),
            ..evidence()
        },
        ClockEvidence {
            coordinate: None,
            ..evidence()
        },
    ] {
        assert_eq!(
            clock_verdict(&evidence, &requirement(5_000)),
            Verdict::NoEvidence,
            "{evidence:?}"
        );
    }
}

/// Granularity 0 is "not stated" (design/trace-clocks.md): missing
/// evidence, never a granularity that passes every requirement.
#[test]
fn zero_granularity_is_no_evidence() {
    let zero = ClockEvidence {
        granularity_ns: Some(0),
        ..evidence()
    };
    assert_eq!(
        clock_verdict(&zero, &requirement(5_000)),
        Verdict::NoEvidence
    );
}

/// A reversed interval is malformed: never covered, never met.
#[test]
fn a_reversed_interval_is_refused() {
    let cal = calibration().calibration;
    assert!(!cal.covers(2_000, 1_000));
    assert_eq!(
        entry_bound(2_000, 1_000, coordinate(), &cal, &reference()),
        Err(Gap::Invalid)
    );
    let reversed = ClockEvidence {
        min: 2_000,
        max: 1_000,
        ..evidence()
    };
    assert_eq!(
        clock_verdict(&reversed, &requirement(5_000)),
        Verdict::NoEvidence
    );
}
