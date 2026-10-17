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

/// Stats with `paths` paths of one lane, each bound at position 0 in term
/// 0 (charged from term 1).
fn bound(paths: u8, ring: u16) -> PathStats {
    let mut stats = PathStats::new(&config(paths, 8, ring), 1, 4);
    for path in 0..usize::from(paths) {
        stats.path_bound(path, &[(0, 0)]);
    }
    stats
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
/// replay or a late copy at or below that path's own mark is not, and is
/// counted stale, out of the duplicates and the histogram.
#[test]
fn freshness_is_judged_per_path() {
    let mut stats = bound(2, 8);
    assert!(stats.arrived(frame(0, 0, 10), Arrival::First));
    // The same frame from path 1: a duplicate, fresh on path 1.
    assert!(stats.arrived(frame(1, 0, 12), Arrival::Duplicate));
    // A replay on each path: not fresh, stale.
    assert!(!stats.arrived(frame(0, 0, 14), Arrival::Duplicate));
    assert!(!stats.arrived(frame(1, 0, 14), Arrival::Duplicate));
    // A new frame refreshes again; an older one does not.
    assert!(stats.arrived(frame(1, 128, 20), Arrival::First));
    assert!(!stats.arrived(frame(1, 64, 21), Arrival::First));
    let counts = stats.counts(1).unwrap();
    assert_eq!((counts.duplicates, counts.stale), (1, 1));
    assert_eq!(counts.arrival.iter().sum::<u64>(), 1);
    assert_eq!(stats.counts(0).unwrap().stale, 1);
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

/// #243 review P2-1: a path's mark starts at its join, and stays across a
/// loss, so replays of old history on a rebound path are never fresh; an
/// unbound path records nothing.
#[test]
fn the_mark_starts_at_the_join_and_survives_a_loss() {
    let mut stats = PathStats::new(&config(2, 8, 8), 1, 4);
    assert!(!stats.arrived(frame(1, 0, 1), Arrival::Duplicate));
    stats.path_bound(0, &[(0, 0)]);
    stats.path_bound(1, &[(128, 0)]);
    for position in [0, 64, 128] {
        assert!(stats.arrived(frame(0, position, 2), Arrival::First));
    }
    // Path 1 joined at 128: frames ending at or below it are history.
    assert!(!stats.arrived(frame(1, 0, 3), Arrival::Duplicate));
    assert!(!stats.arrived(frame(1, 64, 3), Arrival::Duplicate));
    assert!(stats.arrived(frame(1, 128, 3), Arrival::Duplicate));
    stats.path_lost(1, &[0]);
    assert!(!stats.arrived(frame(1, 192, 4), Arrival::Duplicate));
    // Rebound at a lower join: the higher mark stays; replays are stale.
    stats.path_bound(1, &[(64, 0)]);
    for position in [0, 64, 128] {
        assert!(!stats.arrived(frame(1, position, 5), Arrival::Duplicate));
    }
    assert!(stats.arrived(frame(1, 192, 6), Arrival::Duplicate));
}

/// Duplicates yield arrival differences on the receiver's clock; one whose
/// first arrival left the ring is unmatched; a negative difference is 0
/// (#243 review P2-3).
#[test]
fn duplicates_measure_the_arrival_difference() {
    let mut stats = bound(2, 2);
    stats.arrived(frame(0, 0, 1_000), Arrival::First);
    stats.arrived(frame(0, 64, 2_000), Arrival::First);
    stats.arrived(frame(1, 0, 1_000 + MS), Arrival::Duplicate);
    stats.arrived(frame(1, 64, 2_000 + 3), Arrival::Duplicate);
    // Two more first arrivals push positions 0 and 64 out of the ring of
    // 2: a copy of 128 read before its first arrival is a 0 difference.
    stats.arrived(frame(0, 128, 3_000), Arrival::First);
    stats.arrived(frame(0, 192, 4_000), Arrival::First);
    stats.arrived(frame(1, 128, 2_990), Arrival::Duplicate);
    let counts = stats.counts(1).unwrap();
    assert_eq!(counts.duplicates, 3);
    assert_eq!(counts.arrival[arrival_bucket(MS)], 1);
    assert_eq!(counts.arrival[arrival_bucket(3)], 1);
    assert_eq!(counts.arrival[0], 1);
    assert_eq!(stats.inconsistent(), 0);
    let mut ring = bound(2, 2);
    for position in [0, 64, 128] {
        ring.arrived(frame(0, position, position), Arrival::First);
    }
    // Position 0 left the ring of 2.
    ring.arrived(frame(1, 0, 500), Arrival::Duplicate);
    assert_eq!(ring.counts(1).unwrap().unmatched, 1);
    assert_eq!(stats.counts(0).unwrap().wins, 4);
}

/// RP-1: frames below the image's join count as Late on their path and
/// never as delivered bytes.
#[test]
fn late_frames_are_counted_per_path() {
    let mut stats = bound(2, 8);
    stats.arrived(frame(1, 0, 1), Arrival::Late);
    stats.arrived(frame(1, 64, 2), Arrival::Late);
    stats.arrived(frame(0, 128, 3), Arrival::First);
    assert_eq!(stats.counts(1).unwrap().late, 2);
    assert_eq!(stats.counts(0).unwrap().late, 0);
}

fn in_term(term: u64, delivered: Delivered) -> Delivered {
    Delivered { term, ..delivered }
}

/// Missing bytes per whole term of a binding: a replay or a conflicting
/// copy does not count as delivered; a never-bound path and the join's own
/// term are not charged; bytes delivered before a loss stay; the term of
/// the loss and later are not charged (#243 review P2-2).
#[test]
fn missing_bytes_follow_the_binding() {
    let mut stats = PathStats::new(&config(3, 8, 8), 1, 4);
    stats.path_bound(0, &[(0, 0)]);
    stats.path_bound(1, &[(0, 0)]);
    // Term 0 is the join's: cleaned, charged to nobody.
    stats.arrived(in_term(0, frame(0, 0, 1)), Arrival::First);
    stats.term_cleaned(0, 0, 64);
    // Term 1: path 0 carries 3 frames; path 1 one, then replays it and
    // sends a conflicting copy of another.
    for position in [64, 128, 192] {
        stats.arrived(in_term(1, frame(0, position, position)), Arrival::First);
    }
    stats.arrived(in_term(1, frame(1, 64, 5)), Arrival::Duplicate);
    stats.arrived(in_term(1, frame(1, 64, 6)), Arrival::Duplicate);
    stats.arrived(in_term(1, frame(1, 128, 7)), Arrival::Conflict);
    stats.term_cleaned(0, 1, 192);
    assert_eq!(stats.counts(0).unwrap().missing_bytes, 0);
    assert_eq!(stats.counts(1).unwrap().missing_bytes, 128);
    assert_eq!(stats.counts(2).unwrap().missing_bytes, 0, "never bound");
    // Term 2: path 1 delivers one frame of 4, then is lost in term 3.
    for position in [256, 320, 384, 448] {
        stats.arrived(in_term(2, frame(0, position, position)), Arrival::First);
    }
    stats.arrived(in_term(2, frame(1, 256, 9)), Arrival::Duplicate);
    stats.path_lost(1, &[3]);
    stats.term_cleaned(0, 2, 256);
    assert_eq!(stats.counts(1).unwrap().missing_bytes, 128 + 192);
    // Term 3, the loss's: not charged to path 1.
    stats.term_cleaned(0, 3, 64);
    assert_eq!(stats.counts(1).unwrap().missing_bytes, 128 + 192);
    assert_eq!(stats.counts(0).unwrap().missing_bytes, 64);
    assert_eq!(stats.inconsistent(), 0);
}

/// Each term is cleaned once, in order; a second cleaning charges nothing
/// and is an accounting fault.
#[test]
fn a_term_is_cleaned_once() {
    let mut stats = bound(1, 8);
    stats.term_cleaned(0, 1, 64);
    stats.term_cleaned(0, 1, 64);
    stats.term_cleaned(0, 0, 64);
    assert_eq!(stats.counts(0).unwrap().missing_bytes, 64);
    assert_eq!(stats.inconsistent(), 2);
}

/// Reordering on one path: a frame that arrives after a later one is not
/// fresh, so it counts as missing; missing bytes are an upper bound.
#[test]
fn reordering_on_a_path_counts_as_missing() {
    let mut stats = bound(2, 8);
    for position in [0, 64] {
        stats.arrived(in_term(1, frame(0, position, position)), Arrival::First);
    }
    stats.arrived(in_term(1, frame(1, 64, 5)), Arrival::Duplicate);
    stats.arrived(in_term(1, frame(1, 0, 6)), Arrival::Duplicate);
    stats.term_cleaned(0, 1, 128);
    assert_eq!(stats.counts(1).unwrap().missing_bytes, 64);
    assert_eq!(stats.counts(1).unwrap().stale, 1);
}

/// A seeded model of two paths over one lane: path 0 loses frames with
/// one probability and path 1 with another, and copies arrive in a random
/// order within the skew. The statistics match the model's own count of
/// wins, duplicates and missing bytes.
#[test]
fn the_statistics_match_a_seeded_two_path_model() {
    let seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut state = seed;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let frames = 4_000u64;
    let term_frames = 500u64;
    let mut stats = PathStats::new(&config(2, 8, 64), 1, 4);
    // Bound at position 0 in term 0: charged from term 1 on.
    stats.path_bound(0, &[(0, 0)]);
    stats.path_bound(1, &[(0, 0)]);
    let mut wins = [0u64; 2];
    let mut duplicates = [0u64; 2];
    let mut conflicts = [0u64; 2];
    let mut arrival = [[0u64; ARRIVAL_BUCKETS]; 2];
    let mut missing = [0u64; 2];
    let mut delivered = [0u64; 2];
    let mut committed = 0u64;
    let mut now = 0u64;
    for index in 0..frames {
        let position = index * 64;
        let term = index / term_frames;
        let carried = [next() % 10 != 0, next() % 4 != 0];
        let first = usize::from(next() % 2 != 0);
        let order = [first, 1 - first];
        // One second copy in 16 carries other bytes: a conflict.
        let conflicting = next() % 16 == 0;
        let mut committed_by: Option<(usize, u64)> = None;
        for path in order {
            if !carried[path] {
                continue;
            }
            now += 1 + next() % 1_000;
            let kind = match committed_by {
                None => {
                    committed_by = Some((path, now));
                    wins[path] += 1;
                    Arrival::First
                }
                Some(_) if conflicting => {
                    conflicts[path] += 1;
                    Arrival::Conflict
                }
                Some((_, first)) => {
                    duplicates[path] += 1;
                    // The first arrival is always in the ring here: it came
                    // just before.
                    arrival[path][arrival_bucket(now - first)] += 1;
                    Arrival::Duplicate
                }
            };
            let delivery = Delivered {
                path,
                lane: 0,
                term,
                position,
                length: 64,
                now,
            };
            if kind == Arrival::Conflict {
                // A conflict delivers nothing.
                let _ = stats.arrived(delivery, kind);
            } else {
                delivered[path] += 64;
                assert!(stats.arrived(delivery, kind), "seed {seed:#x}");
            }
        }
        if committed_by.is_some() {
            committed += 64;
        }
        if (index + 1) % term_frames == 0 {
            stats.term_cleaned(0, term, committed);
            for path in 0..2 {
                if term > 0 {
                    missing[path] += committed - delivered[path];
                }
                delivered[path] = 0;
            }
            committed = 0;
        }
    }
    for path in 0..2 {
        let counts = stats.counts(path).unwrap();
        let at = format!("seed {seed:#x}, path {path}");
        assert_eq!(counts.wins, wins[path], "{at}");
        assert_eq!(counts.duplicates, duplicates[path], "{at}");
        assert_eq!(counts.conflicts, conflicts[path], "{at}");
        assert_eq!(counts.missing_bytes, missing[path], "{at}");
        // rp-w7b: the arrival differences match the model, bucket by
        // bucket; none is unmatched.
        assert_eq!(counts.arrival, arrival[path], "{at}");
        assert_eq!(counts.unmatched, 0, "{at}");
    }
    assert!(wins[0] > 0 && wins[1] > 0 && missing[1] > missing[0]);
    assert!(conflicts[0] + conflicts[1] > 0, "the model makes conflicts");
    assert_eq!(stats.inconsistent(), 0);
}
