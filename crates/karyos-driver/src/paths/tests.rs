// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use super::queues::{PathQueues, Push};
use super::skew::{SkewDeadline, SkewError};
use super::stats::{ARRIVAL_BUCKETS, Arrival, Delivered, PathStats, arrival_bucket};
use super::{MAX_PATHS, MAX_SKEW_WINDOW, PathConfig, PathConfigError};

const MS: u64 = 1_000_000;

#[test]
fn the_configuration_is_validated() {
    assert_eq!(PathConfig::default().validate(), Ok(()));
    for max_paths in [0, MAX_PATHS + 1] {
        assert_eq!(
            PathConfig {
                max_paths,
                ..PathConfig::default()
            }
            .validate(),
            Err(PathConfigError::MaxPaths { value: max_paths })
        );
    }
    assert_eq!(
        PathConfig {
            path_queue_datagrams: 0,
            ..PathConfig::default()
        }
        .validate(),
        Err(PathConfigError::ZeroCapacity)
    );
    // RP-4: 0 to 1 s, both ends included.
    for window in [0, MAX_SKEW_WINDOW] {
        let config = PathConfig {
            path_skew_window: window,
            ..PathConfig::default()
        };
        assert_eq!(config.validate(), Ok(()));
    }
    assert_eq!(
        PathConfig {
            path_skew_window: MAX_SKEW_WINDOW + 1,
            ..PathConfig::default()
        }
        .validate(),
        Err(PathConfigError::SkewWindow {
            value: MAX_SKEW_WINDOW + 1
        })
    );
}

/// RP-4 and RP-5: the deadline is detection plus the window with two or
/// more live paths, detection alone with fewer; it is a value, so nothing
/// after detection moves it.
#[test]
fn the_skew_deadline_is_fixed_at_detection() {
    let deadline = SkewDeadline::reliable(100, MS, 2).unwrap();
    assert_eq!(deadline.at(), 100 + MS);
    assert!(!deadline.passed(100 + MS - 1));
    assert!(deadline.passed(100 + MS));
    // One live path: no other path can still deliver the gap.
    assert_eq!(SkewDeadline::reliable(100, MS, 1).unwrap().at(), 100);
    assert_eq!(SkewDeadline::reliable(100, MS, 0).unwrap().at(), 100);
    assert_eq!(
        SkewDeadline::reliable(u64::MAX, 1, 2),
        Err(SkewError::Overflow)
    );
    // A window of 0 is allowed and waits nothing.
    assert_eq!(SkewDeadline::reliable(100, 0, 3).unwrap().at(), 100);
}

/// GU-4: on unreliable channels the one deadline is the larger of the
/// reorder timeout and the skew window, never their sum.
#[test]
fn the_unreliable_deadline_is_the_larger_wait() {
    assert_eq!(
        SkewDeadline::unreliable(0, MS, 2, 3 * MS).unwrap().at(),
        3 * MS
    );
    assert_eq!(
        SkewDeadline::unreliable(0, 5 * MS, 2, MS).unwrap().at(),
        5 * MS
    );
    // One live path: the skew window is 0, the reorder timeout remains.
    assert_eq!(SkewDeadline::unreliable(0, 5 * MS, 1, MS).unwrap().at(), MS);
    assert_eq!(
        SkewDeadline::unreliable(u64::MAX, 0, 1, 1),
        Err(SkewError::Overflow)
    );
}

fn config(paths: u8, queue: u16, ring: u16) -> PathConfig {
    PathConfig {
        max_paths: paths,
        path_queue_datagrams: queue,
        skew_sample_frames: ring,
        ..PathConfig::default()
    }
}

/// A full queue drops only its own path's datagram, counted.
#[test]
fn a_full_queue_drops_only_its_path() {
    let mut queues = PathQueues::new(&config(2, 2, 8));
    assert_eq!(queues.push(0, 1), Push::Queued);
    assert_eq!(queues.push(0, 2), Push::Queued);
    assert_eq!(queues.push(0, 3), Push::Full(3));
    assert_eq!(queues.push(1, 10), Push::Queued);
    assert_eq!(queues.push(2, 20), Push::UnknownPath(20));
    assert_eq!((queues.drops(0), queues.drops(1)), (1, 0));
    assert_eq!((queues.len(0), queues.len(1)), (2, 1));
}

/// Round robin: one datagram per path per turn, so a slow path is served
/// between a fast path's datagrams.
#[test]
fn round_robin_serves_a_slow_path() {
    let mut queues = PathQueues::new(&config(3, 8, 8));
    for datagram in 0..5 {
        assert_eq!(queues.push(0, datagram), Push::Queued);
    }
    assert_eq!(queues.push(2, 100), Push::Queued);
    let order: Vec<(usize, i32)> = core::iter::from_fn(|| queues.pop()).collect();
    assert_eq!(
        order,
        vec![(0, 0), (2, 100), (0, 1), (0, 2), (0, 3), (0, 4)]
    );
    assert!(queues.is_empty());
    // A turn starts after the path served last (path 0): path 1 first.
    assert_eq!(queues.push(1, 7), Push::Queued);
    assert_eq!(queues.push(0, 8), Push::Queued);
    assert_eq!(queues.pop(), Some((1, 7)));
    assert_eq!(queues.pop(), Some((0, 8)));
    queues.push(1, 9);
    queues.clear(1);
    assert_eq!(queues.pop(), None);
}

fn frame(path: usize, position: u64, now: u64) -> Delivered {
    Delivered {
        path,
        lane: 0,
        term: 0,
        position,
        length: 64,
        now,
    }
}

#[test]
fn arrival_buckets_are_log2() {
    assert_eq!(arrival_bucket(0), 0);
    assert_eq!(arrival_bucket(1), 1);
    assert_eq!(arrival_bucket(2), 2);
    assert_eq!(arrival_bucket(3), 2);
    assert_eq!(arrival_bucket(1_000_000), 20);
    assert_eq!(arrival_bucket(u64::MAX), ARRIVAL_BUCKETS - 1);
}

/// RP-2: a cross-path duplicate is fresh on the path that carried it; a
/// replay or a late copy at or below that path's own mark is not.
#[test]
fn freshness_is_judged_per_path() {
    let mut stats = PathStats::new(&config(2, 8, 8), 1, 4);
    assert!(stats.arrived(frame(0, 0, 10), Arrival::First));
    // The same frame from path 1: a duplicate, fresh on path 1.
    assert!(stats.arrived(frame(1, 0, 12), Arrival::Duplicate));
    // A replay on path 0, and on path 1: not fresh.
    assert!(!stats.arrived(frame(0, 0, 14), Arrival::Duplicate));
    assert!(!stats.arrived(frame(1, 0, 14), Arrival::Duplicate));
    // A new frame refreshes again; an older one does not.
    assert!(stats.arrived(frame(1, 128, 20), Arrival::First));
    assert!(!stats.arrived(frame(1, 64, 21), Arrival::First));
    // A lost path starts afresh.
    stats.path_lost(1);
    assert!(stats.arrived(frame(1, 64, 22), Arrival::Duplicate));
    // Unknown paths and lanes record nothing.
    assert!(!stats.arrived(frame(2, 0, 30), Arrival::First));
    assert!(!stats.arrived(
        Delivered {
            lane: 1,
            ..frame(0, 256, 30)
        },
        Arrival::First
    ));
}

/// Duplicates yield arrival differences on the receiver's clock; one whose
/// first arrival left the ring is unmatched.
#[test]
fn duplicates_measure_the_arrival_difference() {
    let mut stats = PathStats::new(&config(2, 8, 2), 1, 4);
    stats.arrived(frame(0, 0, 1_000), Arrival::First);
    stats.arrived(frame(0, 64, 2_000), Arrival::First);
    stats.arrived(frame(1, 64, 2_000 + 3), Arrival::Duplicate);
    stats.arrived(frame(1, 0, 1_000 + MS), Arrival::Duplicate);
    // Two more first arrivals push positions 0 and 64 out of the ring of
    // 2: a late copy of 64 is unmatched.
    stats.arrived(frame(0, 128, 3_000), Arrival::First);
    stats.arrived(frame(0, 192, 4_000), Arrival::First);
    stats.arrived(frame(1, 64, 4_010), Arrival::Duplicate);
    let mut late_zero = PathStats::new(&config(2, 8, 2), 1, 4);
    late_zero.arrived(frame(0, 0, 10), Arrival::First);
    late_zero.arrived(frame(1, 0, 10), Arrival::Duplicate);
    assert_eq!(late_zero.counts(1).unwrap().arrival[0], 1);
    // A copy timed before its first arrival is an accounting fault.
    late_zero.arrived(frame(1, 0, 9), Arrival::Duplicate);
    assert_eq!(late_zero.inconsistent(), 1);
    assert_eq!(late_zero.counts(1).unwrap().arrival.iter().sum::<u64>(), 1);
    let counts = stats.counts(1).unwrap();
    assert_eq!(counts.duplicates, 3);
    assert_eq!(counts.arrival[arrival_bucket(3)], 1);
    assert_eq!(counts.arrival[arrival_bucket(MS)], 1);
    assert_eq!(counts.unmatched, 1);
    assert_eq!(stats.counts(0).unwrap().wins, 4);
}

/// RP-1: frames below the image's join count as Late on their path and
/// never as delivered bytes.
#[test]
fn late_frames_are_counted_per_path() {
    let mut stats = PathStats::new(&config(2, 8, 8), 1, 4);
    stats.arrived(frame(1, 0, 1), Arrival::Late);
    stats.arrived(frame(1, 64, 2), Arrival::Late);
    stats.arrived(frame(0, 128, 3), Arrival::First);
    stats.term_cleaned(0, 0, 64);
    assert_eq!(stats.counts(1).unwrap().late, 2);
    assert_eq!(stats.counts(0).unwrap().late, 0);
    assert_eq!(stats.counts(1).unwrap().missing_bytes, 64);
    assert_eq!(stats.counts(0).unwrap().missing_bytes, 0);
}

/// Missing bytes per term at its cleaning, with no bitmap: a replay on
/// one path does not hide its losses; conflicts are counted.
#[test]
fn missing_bytes_follow_fresh_deliveries() {
    let mut stats = PathStats::new(&config(2, 8, 8), 1, 4);
    for position in [0, 64, 128] {
        stats.arrived(frame(0, position, position), Arrival::First);
    }
    // Path 1 carries only the first frame, then replays it twice.
    stats.arrived(frame(1, 0, 5), Arrival::Duplicate);
    stats.arrived(frame(1, 0, 6), Arrival::Duplicate);
    stats.arrived(frame(1, 0, 7), Arrival::Conflict);
    stats.term_cleaned(0, 0, 192);
    assert_eq!(stats.counts(0).unwrap().missing_bytes, 0);
    assert_eq!(stats.counts(1).unwrap().missing_bytes, 128);
    assert_eq!(stats.counts(1).unwrap().conflicts, 1);
    assert_eq!(stats.inconsistent(), 0);
    // A term cleaned with more fresh bytes than committed is a fault, not
    // a negative missing count.
    stats.arrived(
        Delivered {
            term: 1,
            ..frame(0, 192, 9)
        },
        Arrival::First,
    );
    stats.term_cleaned(0, 1, 32);
    assert_eq!(stats.inconsistent(), 1);
}

/// A seeded model of two paths over one lane: path 0 loses frames with
/// one probability and path 1 with another, and copies arrive in a random
/// order within the skew. The statistics match the model's own count of
/// wins, duplicates and missing bytes.
#[test]
fn the_statistics_match_a_seeded_two_path_model() {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let frames = 4_000u64;
    let term_frames = 500u64;
    let mut stats = PathStats::new(&config(2, 8, 64), 1, 4);
    let mut wins = [0u64; 2];
    let mut duplicates = [0u64; 2];
    let mut missing = [0u64; 2];
    let mut delivered = [0u64; 2];
    let mut committed = 0u64;
    let mut now = 0u64;
    for index in 0..frames {
        let position = index * 64;
        let term = index / term_frames;
        let carried = [next() % 10 != 0, next() % 4 != 0];
        let first = if next() % 2 == 0 { 0 } else { 1 };
        let order = [first, 1 - first];
        let mut committed_by = None;
        for path in order {
            if !carried[path] {
                continue;
            }
            now += 1 + next() % 1_000;
            let arrival = if committed_by.is_none() {
                committed_by = Some(path);
                wins[path] += 1;
                Arrival::First
            } else {
                duplicates[path] += 1;
                Arrival::Duplicate
            };
            delivered[path] += 64;
            assert!(stats.arrived(
                Delivered {
                    path,
                    lane: 0,
                    term,
                    position,
                    length: 64,
                    now,
                },
                arrival
            ));
        }
        if committed_by.is_some() {
            committed += 64;
        }
        if (index + 1) % term_frames == 0 {
            stats.term_cleaned(0, term, committed);
            for path in 0..2 {
                missing[path] += committed - delivered[path];
                delivered[path] = 0;
            }
            committed = 0;
        }
    }
    for path in 0..2 {
        let counts = stats.counts(path).unwrap();
        assert_eq!(counts.wins, wins[path], "path {path}");
        assert_eq!(counts.duplicates, duplicates[path], "path {path}");
        assert_eq!(counts.missing_bytes, missing[path], "path {path}");
        assert_eq!(
            counts.arrival.iter().sum::<u64>() + counts.unmatched,
            duplicates[path]
        );
    }
    assert!(wins[0] > 0 && wins[1] > 0 && missing[1] > missing[0]);
    assert_eq!(stats.inconsistent(), 0);
}
