// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_sys::counters::{CounterKeys, KIND_PUBLICATION, TYPE_EVENT, TYPE_TIMESTAMP};

use super::*;

fn cell(label: &str, type_id: u64, keys: CounterKeys, value: u64) -> Cell {
    let mut metadata = CounterMetadata::new(1, type_id, label).unwrap();
    metadata.keys = keys;
    (metadata, value)
}

fn lane(stream: u64, lane: u8, kind: u8, participant: u64) -> CounterKeys {
    CounterKeys {
        stream,
        lane,
        kind,
        participant,
    }
}

#[test]
fn a_pass_groups_counters_and_computes_headroom_and_lag() {
    let cells = vec![
        cell("positions epoch", TYPE_EVENT, CounterKeys::DRIVER, 4),
        cell(
            "positions sampled at",
            TYPE_TIMESTAMP,
            CounterKeys::DRIVER,
            900,
        ),
        cell("commands", TYPE_EVENT, CounterKeys::DRIVER, 7),
        cell(
            "stream limit",
            TYPE_POSITION,
            lane(5, 0, KIND_PUBLICATION, 0),
            2000,
        ),
        cell(
            "stream head",
            TYPE_POSITION,
            lane(5, 0, KIND_PUBLICATION, 0),
            1500,
        ),
        cell(
            "stream floor",
            TYPE_POSITION,
            lane(5, 0, KIND_PUBLICATION, 0),
            1000,
        ),
        cell(
            "sub position",
            TYPE_POSITION,
            lane(5, 0, KIND_SUBSCRIBER, 12),
            1400,
        ),
        cell(
            "sub position",
            TYPE_POSITION,
            lane(5, 0, KIND_SUBSCRIBER, 11),
            1500,
        ),
    ];
    let sample = sample(&cells, true, 1000);
    assert!(sample.consistent && sample.sampled);
    assert_eq!(sample.age_ns, Some(100));
    let labels: Vec<&str> = sample.counters.iter().map(|c| c.label.as_str()).collect();
    assert_eq!(
        labels,
        ["commands", "positions epoch", "positions sampled at"]
    );
    assert_eq!(sample.lanes.len(), 1);
    let lane = &sample.lanes[0];
    assert_eq!(
        (lane.limit, lane.head, lane.floor, lane.headroom),
        (Some(2000), Some(1500), Some(1000), Some(500))
    );
    let lags: Vec<(u64, Option<i64>)> = lane
        .subscribers
        .iter()
        .map(|s| (s.registration, s.lag))
        .collect();
    assert_eq!(lags, [(11, Some(0)), (12, Some(100))]);
}

#[test]
fn a_mixed_pass_keeps_signed_differences_and_never_underflows() {
    // A subscriber ahead of a head from another pass: a negative lag.
    let cells = vec![
        cell(
            "stream head",
            TYPE_POSITION,
            lane(5, 1, KIND_PUBLICATION, 0),
            100,
        ),
        cell(
            "sub position",
            TYPE_POSITION,
            lane(5, 1, KIND_SUBSCRIBER, 3),
            150,
        ),
    ];
    let sample = sample(&cells, false, 0);
    assert!(!sample.consistent && !sample.sampled);
    assert_eq!(sample.age_ns, None);
    let lane = &sample.lanes[0];
    assert_eq!(lane.headroom, None);
    assert_eq!(lane.subscribers[0].lag, Some(-50));
}

#[test]
fn a_follower_keeps_the_newest_records_and_counts_every_one() {
    let mut follower = Follower::new(2);
    for record in 1..=5 {
        follower.push(record);
    }
    follower.count(5, 3);
    follower.count(1, 0);
    let feed = follower.feed();
    assert_eq!(feed.records, [4, 5]);
    assert_eq!((feed.delivered, feed.overwritten), (6, 3));
    // A history of zero keeps nothing, still counting.
    let mut none = Follower::new(0);
    none.push(1);
    none.count(1, 0);
    assert_eq!((none.feed().records.len(), none.feed().delivered), (0, 1));
}
