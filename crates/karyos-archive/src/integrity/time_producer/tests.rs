// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use karyos_trace::clocks::utc::{Scale, Source as UtcSource, SyncState as UtcSync};

use super::*;

const A: [u64; 5] = [1, 0, 2, 3, 4];

fn key(clock: [u64; 5]) -> ClockKey {
    EventClock {
        clock,
        granularity: 0,
    }
    .key()
}

fn b() -> ClockKey {
    key([9, 0, 9, 9, 9])
}

fn calibration(valid_from: u64, valid_to: u64, offset: i64) -> [u64; CALIBRATION_WORDS] {
    Calibration {
        from: key(A),
        to: b(),
        reference: valid_from,
        offset,
        offset_uncertainty: 2,
        drift: 0,
        drift_uncertainty: 0,
        valid_from,
        valid_to,
    }
    .encode()
    .unwrap()
}

fn reference(valid_from: u64, valid_to: u64) -> [u64; CALIBRATION_WORDS] {
    UtcReference {
        clock: b(),
        source: UtcSource::Gnss,
        sync_state: UtcSync::Synchronised,
        bound: 100,
        valid_from,
        valid_to,
        tick_fs: 1_000_000,
        scale: Scale::Tai,
        origin: 0,
        origin_scale_ns: 2_000_000_000_000_000_000,
        leap_table: 69,
        transform_uncertainty_ns: 0,
    }
    .encode()
    .unwrap()
}

/// A calibration of A valid up to 100, another from 101, both into B; a
/// UTC reference of B over them; and the producer's later records, past
/// any range below 1000: the completeness boundary.
fn records() -> Vec<[u64; CALIBRATION_WORDS]> {
    vec![
        calibration(0, 100, 10),
        calibration(101, 999, 20),
        reference(0, 1999),
        calibration(1000, 2000, 20),
        reference(2000, 3000),
    ]
}

fn clock() -> EventClock {
    EventClock {
        clock: A,
        granularity: 1,
    }
}

fn events(times: &[(u64, bool)]) -> Vec<Event> {
    times
        .iter()
        .zip(0u64..)
        .map(|(&(time, in_session), index)| Event {
            start: index * 10,
            end: index * 10 + 10,
            time,
            in_session,
        })
        .collect()
}

fn digest_of(words: &[u64; CALIBRATION_WORDS]) -> Digest {
    record_digest(words)
}

/// ADR-0098 item 3: out of order timestamps across a calibration boundary
/// (90, 110, 95 with the boundary at 100) give three entries, one per run
/// of uniform provenance, each citing one calibration; they tile the range
/// and encode.
#[test]
fn a_boundary_crossed_out_of_order_partitions_before_the_extrema() {
    let records = records();
    let snapshot = Snapshot::new(&records, true);
    let entries = produce(
        7,
        &events(&[(90, true), (110, true), (95, true)]),
        Some(&clock()),
        &snapshot,
    );
    assert_eq!(entries.len(), 3);
    let cites: Vec<Digest> = entries.iter().map(|entry| entry.calibration).collect();
    assert_eq!(
        cites,
        [
            digest_of(&records[0]),
            digest_of(&records[1]),
            digest_of(&records[0])
        ]
    );
    assert_eq!(
        entries
            .iter()
            .map(|entry| (entry.start, entry.end))
            .collect::<Vec<_>>(),
        [(0, 10), (10, 20), (20, 30)]
    );
    for entry in &entries {
        assert_eq!(entry.recording, 7);
        assert_eq!(entry.clock, A);
        assert_eq!(entry.tick_fs, HOST_MONOTONIC_TICK_FS);
        assert_eq!(entry.utc_reference, digest_of(&records[2]));
        assert_ne!(entry.bound_min_ns, NO_BOUND);
        assert_eq!(entry.source, Source::Gnss);
        entry.encode().unwrap();
    }
}

/// Consecutive events under one provenance make one entry with their
/// extrema.
#[test]
fn a_uniform_run_is_one_entry_with_its_extrema() {
    let snapshot = Snapshot::new(&records(), true);
    let entries = produce(
        7,
        &events(&[(40, true), (20, true), (60, true)]),
        Some(&clock()),
        &snapshot,
    );
    assert_eq!(entries.len(), 1);
    let [entry] = entries.as_slice() else {
        panic!()
    };
    assert_eq!(
        (entry.start, entry.end, entry.min_time, entry.max_time),
        (0, 30, 20, 60)
    );
    // The offset's uncertainty (2) and the reference's bound (100).
    assert_eq!(entry.bound_min_ns, 102);
    assert_eq!(entry.bound_max_ns, 102);
}

/// No declaration: one entry, identity all zero, `no_evidence`.
#[test]
fn without_a_declared_clock_the_identity_is_zero() {
    let snapshot = Snapshot::new(&records(), true);
    let entries = produce(7, &events(&[(40, true), (60, true)]), None, &snapshot);
    let [entry] = entries.as_slice() else {
        panic!()
    };
    assert_eq!(entry.clock, [0; 5]);
    assert_eq!(
        (entry.bound_min_ns, entry.bound_max_ns),
        (NO_BOUND, NO_BOUND)
    );
    assert_eq!(entry.calibration, [0; 32]);
    entry.encode().unwrap();
}

/// A loss, a missing completeness boundary, or two calibrations valid at
/// once: the declared identity, `no_evidence` bounds, no record cited.
#[test]
fn incomplete_or_ambiguous_coverage_is_no_evidence() {
    let mut competing = records();
    competing.push(calibration(0, 100, 11));
    let cases = [
        Snapshot::new(&records(), false),
        Snapshot::new(&records()[..3], true),
        Snapshot::new(&competing, true),
    ];
    for snapshot in &cases {
        let entries = produce(7, &events(&[(40, true)]), Some(&clock()), snapshot);
        let [entry] = entries.as_slice() else {
            panic!()
        };
        assert_eq!(entry.clock, A);
        assert_eq!(entry.bound_min_ns, NO_BOUND);
        assert_eq!((entry.calibration, entry.utc_reference), ([0; 32], [0; 32]));
        entry.encode().unwrap();
    }
}

/// A timer scheduled in an earlier session gets its own entry with an
/// all zero identity, between the proven ones.
#[test]
fn a_timer_from_an_earlier_session_is_not_proven() {
    let snapshot = Snapshot::new(&records(), true);
    let entries = produce(
        7,
        &events(&[(40, true), (50, false), (60, true)]),
        Some(&clock()),
        &snapshot,
    );
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1].clock, [0; 5]);
    assert_eq!(entries[1].bound_min_ns, NO_BOUND);
    assert_ne!(entries[0].bound_min_ns, NO_BOUND);
    assert_ne!(entries[2].bound_min_ns, NO_BOUND);
}

/// Nothing sealed, nothing produced.
#[test]
fn no_events_no_entries() {
    assert!(produce(7, &[], Some(&clock()), &Snapshot::new(&records(), true)).is_empty());
}

/// docs#975: records naming the zero tuple are never matched, and a
/// declaration of it declares nothing.
#[test]
fn the_zero_tuple_is_never_a_clock() {
    let zero_target = Calibration {
        from: key(A),
        to: key([0; 5]),
        reference: 0,
        offset: 0,
        offset_uncertainty: 0,
        drift: 0,
        drift_uncertainty: 0,
        valid_from: 0,
        valid_to: 100,
    }
    .encode()
    .unwrap();
    // The ordinary calibration over [0, 100] competes with one into the
    // zero tuple: skipped, so coverage stays unique.
    let mut with_zero = records();
    with_zero.push(zero_target);
    let entries = produce(
        7,
        &events(&[(40, true)]),
        Some(&clock()),
        &Snapshot::new(&with_zero, true),
    );
    assert_ne!(entries[0].bound_min_ns, NO_BOUND);
    let zero = EventClock {
        clock: [0; 5],
        granularity: 1,
    };
    let entries = produce(
        7,
        &events(&[(40, true)]),
        Some(&zero),
        &Snapshot::new(&records(), true),
    );
    assert_eq!(entries[0].clock, [0; 5]);
    assert_eq!(entries[0].granularity, 0);
    assert_eq!(entries[0].bound_min_ns, NO_BOUND);
}

/// #1168 review P2: a known record that does not decode makes the
/// snapshot incomplete, so the rest can never look unique.
#[test]
fn a_known_record_that_does_not_decode_makes_coverage_incomplete() {
    let mut broken = calibration(0, 100, 11);
    // Type 1, but word 0 not exactly 1: refused by the calibration codec.
    broken[0] |= 1 << 8;
    let mut records = records();
    records.push(broken);
    let entries = produce(
        7,
        &events(&[(40, true)]),
        Some(&clock()),
        &Snapshot::new(&records, true),
    );
    assert_eq!(entries[0].bound_min_ns, NO_BOUND);
}

/// #1168 review P1: completeness is checked for the target the entry
/// cites. A calibration retargets A to C; the producer's later records
/// cover only B, so the entry citing C is `no_evidence`, even with a
/// valid reference of C.
#[test]
fn completeness_is_of_the_cited_target() {
    let c = key([8, 0, 8, 8, 8]);
    let into_c = Calibration {
        from: key(A),
        to: c,
        reference: 0,
        offset: 10,
        offset_uncertainty: 2,
        drift: 0,
        drift_uncertainty: 0,
        valid_from: 0,
        valid_to: 100,
    }
    .encode()
    .unwrap();
    let mut reference_c = reference(0, 1999);
    let utc_c = UtcReference::decode(&reference_c).unwrap();
    reference_c = UtcReference { clock: c, ..utc_c }.encode().unwrap();
    // Without B's calibration over [0, 100]: only C applies there.
    let records = vec![
        into_c,
        reference_c,
        reference(0, 1999),
        calibration(1000, 2000, 20),
        reference(2000, 3000),
    ];
    let entries = produce(
        7,
        &events(&[(40, true)]),
        Some(&clock()),
        &Snapshot::new(&records, true),
    );
    assert_eq!(entries[0].bound_min_ns, NO_BOUND);
    assert_eq!(entries[0].calibration, [0; 32]);
}

/// #1168 review P1: runs split where the offset to UTC changes (a leap
/// second), and a timestamp inside the inserted second, where the UTC
/// conversion is undefined, gets a `no_evidence` entry of its own.
#[test]
fn a_leap_second_splits_and_an_inserted_second_is_no_evidence() {
    let second = 1_000_000_000u64;
    // TAI at the leap of 2017-01-01, 1958 based: 21550 days, then the 36 s
    // TAI was ahead of UTC before it; start 5 s before.
    let leap_tai = (21_550 * 86_400 + 36) * second;
    let start_tai = leap_tai - 5 * second;
    let utc = |valid_from: u64, valid_to: u64| {
        let base = UtcReference::decode(&reference(valid_from, valid_to)).unwrap();
        UtcReference {
            origin: 0,
            origin_scale_ns: start_tai,
            ..base
        }
        .encode()
        .unwrap()
    };
    let span = 20 * second;
    let records = vec![
        calibration(0, span, 0),
        utc(0, 2 * span),
        calibration(span + 1, 2 * span, 0),
        utc(3 * span, 4 * span),
    ];
    let snapshot = Snapshot::new(&records, true);
    let times: Vec<(u64, bool)> = (0..=20).map(|half| (half * second / 2, true)).collect();
    let entries = produce(7, &events(&times), Some(&clock()), &snapshot);
    let proven: Vec<_> = entries
        .iter()
        .filter(|entry| entry.bound_min_ns != NO_BOUND)
        .collect();
    assert!(proven.len() >= 2, "{entries:#?}");
    assert!(
        entries.iter().any(|entry| entry.bound_min_ns == NO_BOUND),
        "the inserted second: {entries:#?}"
    );
    // The proven runs never straddle the leap: each lies wholly before or
    // after it (5 s into the range).
    for entry in proven {
        assert!(
            entry.max_time < 5 * second || entry.min_time >= 6 * second,
            "{entry:?}"
        );
    }
}

/// #1171 review: the agent waits on the target-specific completeness
/// boundary: a later calibration published before its target's UTC
/// reference does not end the wait.
#[test]
fn reaching_needs_the_cited_targets_reference_too() {
    let mut records = records();
    // Without the later UTC reference of B.
    records.pop();
    let events = events(&[(40, true)]);
    assert!(!Snapshot::new(&records, true).reaches(&clock(), &events));
    assert!(Snapshot::new(&self::records(), true).reaches(&clock(), &events));
    // Events of no session prove nothing and wait for nothing.
    assert!(Snapshot::default().reaches(&clock(), &self::events(&[(40, false)])));
}
