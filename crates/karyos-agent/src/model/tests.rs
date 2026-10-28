// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_sys::counters::{CounterKeys, KIND_PUBLICATION, TYPE_EVENT, TYPE_TIMESTAMP};

use super::*;

/// A cell whose registration is a function of its identity, as one
/// allocation keeps across passes.
fn cell(label: &str, type_id: u64, keys: CounterKeys, value: u64) -> Cell {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for word in [
        type_id,
        keys.stream,
        u64::from(keys.lane),
        u64::from(keys.kind),
        keys.participant,
    ]
    .into_iter()
    .chain(label.bytes().map(u64::from))
    {
        hash = (hash ^ word).wrapping_mul(0x0100_0000_01b3);
    }
    allocated(hash, label, type_id, keys, value)
}

/// A cell of registration `registration`.
fn allocated(registration: u64, label: &str, type_id: u64, keys: CounterKeys, value: u64) -> Cell {
    let mut metadata = CounterMetadata::new(registration, type_id, label).unwrap();
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
    let sample = sample(&cells, true, 1000, &mut Changes::default());
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
    let sample = sample(&cells, false, 0, &mut Changes::default());
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

#[test]
fn a_restart_drops_the_old_instances_records_and_counts() {
    let mut follower = Follower::new(4);
    follower.push(1);
    follower.count(1, 2);
    follower.cursor = 9;
    follower.restart();
    let feed = follower.feed();
    assert!(feed.records.is_empty());
    assert_eq!(
        (feed.delivered, feed.overwritten, follower.cursor),
        (0, 0, 0)
    );
}

// R-CORE-17 (karyos#737): per-datum identity and sample time.

use karyos_sys::counters::{TYPE_APPLICATION_EVENT, TYPE_APPLICATION_GAUGE};

/// The counter of `sample` labelled `label` with type `type_id`.
fn find<'s>(sample: &'s Sample, label: &str, type_id: u64) -> &'s Counter {
    sample
        .counters
        .iter()
        .find(|counter| counter.label == label && counter.type_id == type_id)
        .unwrap()
}

fn pass(commands: u64, sub: u64, sampled_at: u64) -> Vec<Cell> {
    vec![
        cell("positions epoch", TYPE_EVENT, CounterKeys::DRIVER, 1),
        cell(
            "positions sampled at",
            TYPE_TIMESTAMP,
            CounterKeys::DRIVER,
            sampled_at,
        ),
        cell("commands", TYPE_EVENT, CounterKeys::DRIVER, commands),
        cell(
            "sub position",
            TYPE_POSITION,
            lane(5, 0, KIND_SUBSCRIBER, 12),
            sub,
        ),
    ]
}

#[test]
fn test_agent_datum_two_passes_join_by_identity_and_report_their_times() {
    let mut changes = Changes::default();
    let first = sample(&pass(7, 100, 90), true, 1000, &mut changes);
    let commands = find(&first, "commands", TYPE_EVENT);
    assert_eq!((commands.read_ns, commands.changed_ns), (1000, None));
    assert_eq!(first.lanes[0].sampled_ns, Some(90));
    assert_eq!(first.lanes[0].subscribers[0].changed_ns, None);
    // The second pass joins the first: `commands` moved, the position did
    // not.
    let second = sample(&pass(9, 100, 190), true, 2000, &mut changes);
    let commands = find(&second, "commands", TYPE_EVENT);
    assert_eq!((commands.read_ns, commands.changed_ns), (2000, Some(2000)));
    assert_eq!(second.lanes[0].subscribers[0].changed_ns, None);
    // The pass-level fields mean what they meant.
    assert_eq!(
        (second.consistent, second.sampled, second.age_ns),
        (true, true, Some(1810))
    );
}

#[test]
fn test_agent_datum_untouched_for_several_passes_keeps_its_last_change() {
    let mut changes = Changes::default();
    let _ = sample(&pass(1, 100, 90), true, 1000, &mut changes);
    let _ = sample(&pass(2, 150, 190), true, 2000, &mut changes);
    for now in [3000, 4000, 5000] {
        let unchanged = sample(&pass(2, 150, now - 10), true, now, &mut changes);
        let commands = find(&unchanged, "commands", TYPE_EVENT);
        // Read now; last seen changing at 2000, never the pass time.
        assert_eq!((commands.read_ns, commands.changed_ns), (now, Some(2000)));
        // A position's change is at the driver's sampling time.
        assert_eq!(unchanged.lanes[0].subscribers[0].changed_ns, Some(190));
    }
}

#[test]
fn test_agent_datum_a_new_instance_breaks_the_join() {
    let mut changes = Changes::default();
    let _ = sample(&pass(1, 100, 90), true, 1000, &mut changes);
    let _ = sample(&pass(2, 100, 190), true, 2000, &mut changes);
    changes.restart();
    // The same keys under a new instance are a new series: nothing
    // carries over, though the value differs from the old one.
    let after = sample(&pass(3, 100, 290), true, 3000, &mut changes);
    assert_eq!(find(&after, "commands", TYPE_EVENT).changed_ns, None);
}

#[test]
fn test_agent_datum_a_freed_counter_leaves_no_entry_and_returns_as_new() {
    let mut changes = Changes::default();
    let _ = sample(&pass(1, 100, 90), true, 1000, &mut changes);
    let _ = sample(&pass(2, 100, 190), true, 2000, &mut changes);
    assert_eq!(changes.len(), 4);
    // `commands` freed: its entry goes with it.
    let mut freed = pass(2, 100, 290);
    freed.remove(2);
    let _ = sample(&freed, true, 3000, &mut changes);
    assert_eq!(changes.len(), 3, "never more entries than live cells");
    // Allocated again, under a new registration as a region always gives:
    // a new datum, with no change seen yet.
    let mut again = pass(2, 100, 390);
    again[2] = allocated(77, "commands", TYPE_EVENT, CounterKeys::DRIVER, 2);
    let back = sample(&again, true, 4000, &mut changes);
    assert_eq!(find(&back, "commands", TYPE_EVENT).changed_ns, None);
    assert_eq!(changes.len(), 4);
}

/// Two application counters may share a label in two classes (karyos#786):
/// type is part of the identity, so they are two data.
#[test]
fn test_agent_datum_identity_tells_apart_a_label_in_two_classes() {
    let cells = |event, gauge| {
        vec![
            cell("orders", TYPE_APPLICATION_EVENT, CounterKeys::DRIVER, event),
            cell("orders", TYPE_APPLICATION_GAUGE, CounterKeys::DRIVER, gauge),
        ]
    };
    let mut changes = Changes::default();
    let _ = sample(&cells(1, 5), true, 1000, &mut changes);
    assert_eq!(changes.len(), 2, "two identities");
    let second = sample(&cells(2, 5), true, 2000, &mut changes);
    assert_eq!(
        find(&second, "orders", TYPE_APPLICATION_EVENT).changed_ns,
        Some(2000)
    );
    assert_eq!(
        find(&second, "orders", TYPE_APPLICATION_GAUGE).changed_ns,
        None
    );
    // Within one pass every identity is unique.
    let identities: std::collections::BTreeSet<_> = cells(1, 1)
        .iter()
        .map(|(metadata, _)| identity(metadata))
        .collect();
    assert_eq!(identities.len(), 2);
}

/// The cost of a pass with per-datum times (karyos#737, recorded in the
/// pull request, not a gate): 4000 counters and 1000 positions,
/// `cargo test --release -p karyos-agent pass_cost -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, run by hand"]
#[allow(clippy::print_stdout, reason = "prints the measurement")]
fn pass_cost() {
    let mut cells = vec![cell(
        "positions sampled at",
        TYPE_TIMESTAMP,
        CounterKeys::DRIVER,
        1,
    )];
    for i in 0..4000u64 {
        cells.push(cell(
            "commands",
            TYPE_EVENT,
            lane(i, 0, KIND_PUBLICATION, i),
            i,
        ));
    }
    for i in 0..1000u64 {
        cells.push(cell(
            "sub position",
            TYPE_POSITION,
            lane(i, 0, KIND_SUBSCRIBER, i),
            i,
        ));
    }
    let mut changes = Changes::default();
    let passes = 200u32;
    let start = std::time::Instant::now();
    for now in 0..passes {
        let pass = sample(&cells, true, u64::from(now), &mut changes);
        assert_eq!(pass.counters.len(), 4001);
    }
    println!(
        "pass_cost: {:?} per pass of {} cells",
        start.elapsed() / passes,
        cells.len()
    );
}
