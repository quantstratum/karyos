// SPDX-License-Identifier: Apache-2.0

//! A clamp that follows a leader whose clock is behind, at the time
//! evidence layer (SPEC.md §8.4; contract C-TIME, ADR-0111 decision 5;
//! quantstratum/karyos#666): the Cluster entries' event times are stamped
//! with [`stamp`] across a leader change to a node whose clock is behind,
//! and the time evidence producer, given a calibration and a UTC
//! reference record, reports every possibly clamped entry (at or below
//! the watermark before it) as `no_evidence`, every later one with the raw
//! clock's own bound, and splits the entries where the clamp ends.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use karyos_archive::integrity::time::{
    ClusterTime, Requirement, Source, Verdict, classify_cluster_time,
};
use karyos_archive::integrity::time_evidence::{Entry, NO_BOUND};
use karyos_archive::integrity::time_producer::{
    Event, EventClock, HOST_MONOTONIC_TICK_FS, Snapshot, produce, produce_cluster,
};
use karyos_cluster::stamp;
use karyos_trace::clocks::utc::{Scale, Source as UtcSource, SyncState as UtcSync, UtcReference};
use karyos_trace::clocks::{CALIBRATION_WORDS, Calibration, ClockKey};
use karyos_trace::journal::ObserverId;

/// The leaders' event clock, A.
const A: [u64; 5] = [1, 0, 2, 3, 4];
/// The recording the entries are for.
const RECORDING: u64 = 7;

fn key([low, high, journal, domain, epoch]: [u64; 5]) -> ClockKey {
    ClockKey {
        observer: ObserverId {
            driver: [low, high],
            journal,
        },
        domain,
        epoch,
    }
}

/// B, the UTC-traceable clock A is calibrated to.
fn b() -> ClockKey {
    key([9, 0, 9, 9, 9])
}

fn calibration(valid_from: u64, valid_to: u64) -> [u64; CALIBRATION_WORDS] {
    Calibration {
        from: key(A),
        to: b(),
        reference: valid_from,
        offset: 10,
        offset_uncertainty: 2,
        drift: 0,
        drift_uncertainty: 0,
        valid_from,
        valid_to,
    }
    .encode()
    .unwrap()
}

/// A synthetic UTC reference record of B.
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

/// One calibration and one UTC reference over every time below 1000,
/// and the producer's later records past them: the completeness boundary.
fn snapshot() -> Snapshot {
    Snapshot::new(
        &[
            calibration(0, 999),
            reference(0, 1999),
            calibration(1000, 2000),
            reference(2000, 3000),
        ],
        true,
    )
}

fn clock() -> EventClock {
    EventClock {
        clock: A,
        granularity: 1,
    }
}

/// The old leader's raw readings, then a leader change to a node whose
/// clock is 300 behind, which catches up past the watermark.
const OLD_LEADER: [u64; 5] = [100, 200, 300, 400, 500];
const NEW_LEADER: [u64; 6] = [200, 300, 400, 500, 510, 600];

/// The Cluster entries' event times, each stamped by its leader with
/// `max(raw, watermark)` against the log before it, as Cluster events of
/// the recording, one per 10 positions.
fn history(watermark: u64, raws: &[u64]) -> Vec<Event> {
    let mut watermark = watermark;
    raws.iter()
        .zip(0u64..)
        .map(|(&raw, index)| {
            let time = stamp(raw, watermark);
            watermark = time;
            Event {
                start: index * 10,
                end: index * 10 + 10,
                time,
                in_session: true,
            }
        })
        .collect()
}

fn requirement() -> Requirement {
    Requirement {
        max_divergence_ns: 1_000,
        max_granularity_ns: 1_000,
    }
}

/// The raw clock's own bound at `time`, as the producer gives an
/// unclamped event of the same clock.
fn raw_bound(time: u64) -> u64 {
    let event = Event {
        start: 0,
        end: 1,
        time,
        in_session: true,
    };
    let entries = produce(RECORDING, &[event], Some(&clock()), &snapshot());
    assert_eq!(entries.len(), 1);
    assert_ne!(entries[0].bound_min_ns, NO_BOUND);
    entries[0].bound_min_ns
}

/// The clamped entry: the declared clock, but no bound, record or code.
fn assert_no_evidence(entry: &Entry) {
    assert_eq!(entry.clock, A);
    assert_eq!(entry.tick_fs, HOST_MONOTONIC_TICK_FS);
    assert_eq!(entry.bound_min_ns, NO_BOUND);
    assert_eq!(entry.bound_max_ns, NO_BOUND);
    assert_eq!(entry.utc_reference, [0; 32]);
    assert_eq!(entry.calibration, [0; 32]);
    assert_eq!(entry.verdict(&requirement()), Verdict::NoEvidence);
    entry.encode().unwrap();
}

/// A raw entry: the raw clock's own bound at each end.
fn assert_raw(entry: &Entry) {
    assert_eq!(entry.clock, A);
    assert_eq!(entry.source, Source::Gnss);
    assert_eq!(entry.bound_min_ns, raw_bound(entry.min_time));
    assert_eq!(entry.bound_max_ns, raw_bound(entry.max_time));
    assert_ne!(entry.utc_reference, [0; 32]);
    assert_eq!(entry.verdict(&requirement()), Verdict::Met);
    entry.encode().unwrap();
}

/// SPEC.md §8.4's contract case "a clamp follows a leader whose clock is
/// behind": the clamped values are `no_evidence`, never the raw clock's
/// bound; the later values are raw and bounded; the entries split at the
/// boundary on each side of the clamp.
#[test]
fn a_clamp_after_a_leader_whose_clock_is_behind_is_no_evidence() {
    let raws: Vec<u64> = OLD_LEADER.iter().chain(&NEW_LEADER).copied().collect();
    let events = history(0, &raws);
    let times: Vec<u64> = events.iter().map(|event| event.time).collect();
    // The new leader's first four readings are behind the watermark 500:
    // stamped at it, then 510 and 600 are its own clock again.
    assert_eq!(
        times,
        [100, 200, 300, 400, 500, 500, 500, 500, 500, 510, 600]
    );
    // Against the watermark before each: the old leader's and the caught
    // up readings are raw, the four at the watermark possibly clamped.
    let mut watermark = Some(0);
    let classes: Vec<ClusterTime> = times
        .iter()
        .map(|&time| {
            let class = classify_cluster_time(time, watermark);
            watermark = watermark.map(|mark| mark.max(time));
            class
        })
        .collect();
    let clamped = |index: usize| (5..9).contains(&index);
    for (index, class) in classes.iter().enumerate() {
        let expected = if clamped(index) {
            ClusterTime::PossiblyClamped
        } else {
            ClusterTime::Raw
        };
        assert_eq!(*class, expected, "event {index}");
    }

    let entries = produce_cluster(RECORDING, &events, Some(0), Some(&clock()), &snapshot());
    // Split at the boundary on each side of the clamp, tiling the range.
    assert_eq!(
        entries
            .iter()
            .map(|entry| (entry.start, entry.end, entry.min_time, entry.max_time))
            .collect::<Vec<_>>(),
        [(0, 50, 100, 500), (50, 90, 500, 500), (90, 110, 510, 600)]
    );
    assert!(entries.iter().all(|entry| entry.recording == RECORDING));
    assert_raw(&entries[0]);
    assert_no_evidence(&entries[1]);
    assert_raw(&entries[2]);
    // The clamped value would have a finite bound if it were taken as a
    // raw reading of 500: it never inherits it.
    let unclassified = produce(RECORDING, &events[5..9], Some(&clock()), &snapshot());
    assert_eq!(unclassified.len(), 1);
    assert_ne!(unclassified[0].bound_min_ns, NO_BOUND);
}

/// The history starts after a snapshot whose log time is the old leader's
/// largest event time: the watermark is that log time, so the new
/// leader's first entries are possibly clamped from the history's start.
#[test]
fn a_clamp_against_a_snapshot_log_time_is_no_evidence_from_the_start() {
    let events = history(500, &NEW_LEADER);
    let entries = produce_cluster(RECORDING, &events, Some(500), Some(&clock()), &snapshot());
    assert_eq!(
        entries
            .iter()
            .map(|entry| (entry.start, entry.end))
            .collect::<Vec<_>>(),
        [(0, 40), (40, 60)]
    );
    assert_no_evidence(&entries[0]);
    assert_raw(&entries[1]);
}

/// A producer that cannot establish the watermark reports every entry
/// `no_evidence` rather than guessing from the entries it sees, even the
/// ones that are raw.
#[test]
fn an_unknown_watermark_is_no_evidence_for_every_entry() {
    let events = history(500, &NEW_LEADER);
    let entries = produce_cluster(RECORDING, &events, None, Some(&clock()), &snapshot());
    assert_eq!(entries.len(), 1);
    assert_eq!((entries[0].start, entries[0].end), (0, 60));
    assert_no_evidence(&entries[0]);
}
