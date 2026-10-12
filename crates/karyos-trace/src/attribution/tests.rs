// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::*;
use crate::record::{ObservedTime, Point, PublicationId, TraceIds, TraceRecord};

fn config(span: u64) -> AttributionConfig {
    AttributionConfig {
        span,
        max_traces: 64,
        max_intervals: 16,
    }
}

fn record(trace: u64) -> TraceRecord {
    TraceRecord {
        point: Point::Publish,
        publication: PublicationId::default(),
        lane: 0,
        position: 0,
        ids: TraceIds {
            trace_id: [trace, 0],
            ..TraceIds::default()
        },
        observed: ObservedTime::default(),
        subscriber: None,
        packet: None,
    }
}

/// Feeds records given as `(sequence, trace, epoch, time)`, deriving gaps
/// from missing sequences like the journal does.
struct Feed {
    attributor: Attributor,
    expected: u64,
}

impl Feed {
    fn new(config: AttributionConfig) -> Self {
        Self {
            attributor: Attributor::new(config).unwrap(),
            expected: 0,
        }
    }

    fn record(&mut self, sequence: u64, trace: u64, epoch: u64, time: u64) -> Observed {
        let gap = (sequence != self.expected).then_some((self.expected, sequence));
        self.expected = sequence + 1;
        self.attributor.observe(&Collected::Record {
            sequence,
            gap,
            record: record(trace),
            collected: Stamp {
                time,
                clock: 1,
                epoch,
            },
        })
    }

    fn corrupt(&mut self, sequence: u64) -> Observed {
        let gap = (sequence != self.expected).then_some((self.expected, sequence));
        self.expected = sequence + 1;
        self.attributor.observe(&Collected::Corrupt {
            sequence,
            gap,
            error: TraceError::ReservedBits,
        })
    }

    fn close(&mut self, attempted: u64) -> HashMap<u64, Verdict> {
        assert_eq!(
            self.attributor.observe(&Collected::Closed),
            Observed::Nothing
        );
        self.attributor
            .close(attempted)
            .unwrap()
            .map(|(id, verdict)| (id[0], verdict))
            .collect()
    }
}

use Verdict::{Complete, Incomplete};

#[test]
fn a_single_loss_marks_only_overlapping_windows() {
    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    feed.record(1, 2, 0, 100);
    // Sequence 2 lost between 100 and 200.
    feed.record(3, 3, 0, 200);
    let verdicts = feed.close(4);
    assert_eq!(verdicts[&1], Complete);
    assert_eq!(verdicts[&2], Incomplete);
    assert_eq!(verdicts[&3], Incomplete);
}

/// SPEC.md §13: the journal overflows while every record is borrowed and no
/// later event arrives.
#[test]
fn a_tail_loss_marks_the_cohort() {
    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    feed.attributor.observe_snapshot(3, 1);
    assert_eq!(feed.attributor.provisional([1, 0]), Some(Incomplete));
    let verdicts = feed.close(3);
    assert_eq!(verdicts[&1], Incomplete);
}

#[test]
fn a_tail_loss_is_also_caught_at_the_close() {
    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    let verdicts = feed.close(2);
    assert_eq!(verdicts[&1], Incomplete);
}

/// A late hardware stamp collected long after the frame keeps the trace's
/// window open on the collection axis.
#[test]
fn a_late_stamp_keeps_the_window_open() {
    let mut feed = Feed::new(config(60));
    feed.record(0, 7, 0, 0);
    feed.record(1, 8, 0, 20);
    // Sequence 2 lost between 20 and 40.
    feed.record(3, 8, 0, 40);
    feed.record(4, 7, 0, 50);
    let verdicts = feed.close(5);
    assert_eq!(verdicts[&7], Incomplete);
}

#[test]
fn a_loss_across_an_epoch_change_marks_the_cohort() {
    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    feed.record(2, 2, 1, 0);
    let verdicts = feed.close(3);
    assert_eq!(verdicts[&1], Incomplete);
    assert_eq!(verdicts[&2], Incomplete);
}

/// Review counterexample: a loss in e0 whose interval expired still marks a
/// trace first retained in e1.
#[test]
fn an_expired_loss_still_marks_traces_first_seen_in_later_epochs() {
    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    // Sequence 1 (trace 9) lost.
    feed.record(2, 1, 0, 10);
    feed.record(3, 2, 0, 30);
    feed.record(4, 9, 1, 0);
    let verdicts = feed.close(5);
    assert_eq!(verdicts[&9], Incomplete);
    assert_eq!(verdicts[&2], Complete);
}

/// Review counterexample: a trace seen in e0 is marked by a loss bounded
/// inside e1, and by one bounded across e1 and e2.
#[test]
fn a_trace_seen_earlier_is_marked_by_later_epoch_losses() {
    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    feed.record(1, 2, 1, 0);
    feed.record(3, 2, 1, 10);
    let verdicts = feed.close(4);
    assert_eq!(verdicts[&1], Incomplete);

    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    feed.record(1, 2, 1, 0);
    feed.record(3, 3, 2, 0);
    let verdicts = feed.close(4);
    assert_eq!(verdicts[&1], Incomplete);
}

#[test]
fn a_loss_before_the_first_record_marks_the_cohort() {
    let mut feed = Feed::new(config(10));
    feed.record(1, 1, 0, 5);
    feed.record(2, 2, 3, 0);
    let verdicts = feed.close(3);
    assert_eq!(verdicts[&1], Incomplete);
    assert_eq!(verdicts[&2], Incomplete);
}

#[test]
fn a_span_beyond_d_is_a_window_violation() {
    let mut feed = Feed::new(config(10));
    assert_eq!(feed.record(0, 5, 0, 0), Observed::Tracked);
    assert_eq!(feed.record(1, 5, 0, 9), Observed::Tracked);
    assert_eq!(
        feed.record(2, 5, 0, 18),
        Observed::WindowViolation { trace_id: [5, 0] }
    );
    assert_eq!(feed.close(3)[&5], Incomplete);
}

#[test]
fn a_corrupt_record_is_a_loss_bounded_by_its_neighbours() {
    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    assert_eq!(feed.corrupt(1), Observed::Loss);
    feed.record(2, 2, 0, 100);
    feed.record(3, 3, 0, 500);
    let verdicts = feed.close(4);
    assert_eq!(verdicts[&1], Incomplete);
    assert_eq!(verdicts[&2], Incomplete);
    assert_eq!(verdicts[&3], Complete);
}

#[test]
fn a_trailing_corrupt_record_marks_the_cohort_at_close() {
    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    feed.corrupt(1);
    assert_eq!(feed.close(2)[&1], Incomplete);
}

#[test]
fn overflowing_tables_only_mark_more_traces() {
    let mut feed = Feed::new(AttributionConfig {
        span: 10,
        max_traces: 1,
        max_intervals: 1,
    });
    assert_eq!(feed.record(0, 1, 0, 0), Observed::Tracked);
    assert_eq!(
        feed.record(1, 2, 0, 1),
        Observed::Untracked { trace_id: [2, 0] }
    );
    let verdicts = feed.close(2);
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[&1], Complete);

    let mut feed = Feed::new(AttributionConfig {
        span: 10,
        max_traces: 8,
        max_intervals: 1,
    });
    feed.record(0, 1, 0, 0);
    feed.record(2, 2, 0, 5);
    // A second interval does not fit: incarnation cohort.
    feed.record(4, 3, 0, 6);
    feed.record(5, 4, 0, 1_000);
    let verdicts = feed.close(6);
    assert!(verdicts.values().all(|verdict| *verdict == Incomplete));
}

/// Final verdicts wait for the observed close; a provisional view is never
/// final, and a record appended after a snapshot is still counted.
#[test]
fn verdicts_need_the_terminal_close() {
    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    assert!(matches!(
        feed.attributor.close(1),
        Err(TraceError::NotClosed)
    ));
    assert_eq!(feed.attributor.provisional([1, 0]), Some(Complete));
    // A paused producer appends after the snapshot horizon: still counted.
    feed.attributor.observe_snapshot(1, 1);
    feed.record(2, 1, 0, 5);
    assert_eq!(feed.close(3)[&1], Incomplete);
}

#[test]
fn a_zero_trace_id_is_unattributed() {
    let mut feed = Feed::new(config(10));
    assert_eq!(feed.record(0, 0, 0, 0), Observed::Unattributed);
    assert!(feed.close(1).is_empty());
}

#[test]
fn combining_expected_journals() {
    assert_eq!(combine([Some(Complete), Some(Complete)]), Complete);
    assert_eq!(combine([Some(Complete), None]), Incomplete);
    assert_eq!(combine([Some(Incomplete), Some(Complete)]), Incomplete);
    assert_eq!(combine(std::iter::empty()), Incomplete);
}

#[test]
fn table_sizes_are_checked() {
    assert!(
        Attributor::new(AttributionConfig {
            span: 1,
            max_traces: 0,
            max_intervals: 1,
        })
        .is_err()
    );
}

/// Reference model: random journals with traces that respect `D`, random
/// lost and corrupt observations, and epoch changes. Every trace that truly
/// lost an observation must be reported `Incomplete`.
#[test]
fn every_trace_that_lost_an_observation_is_incomplete() {
    const SPAN: u64 = 20;
    let mut completes = 0usize;
    for seed in 1..=600u64 {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = move |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };
        let mut feed = Feed::new(AttributionConfig {
            span: SPAN,
            max_traces: 256,
            max_intervals: 8,
        });
        let (mut epoch, mut time) = (0u64, 0u64);
        // Open traces in the current epoch: trace id -> first time.
        let mut open: BTreeMap<u64, u64> = BTreeMap::new();
        let mut lost: BTreeSet<u64> = BTreeSet::new();
        let mut retained: BTreeSet<u64> = BTreeSet::new();
        let mut next_trace = 1u64;
        let steps = 10 + next(40);
        for sequence in 0..steps {
            if next(20) == 0 {
                epoch += 1;
                time = next(5);
                // A trace may continue into the new epoch with a new window.
                open = open.keys().map(|&trace| (trace, time)).collect();
            } else {
                time += next(6);
            }
            open.retain(|_, first| time - *first <= SPAN);
            let trace = if open.is_empty() || next(3) == 0 {
                let trace = next_trace;
                next_trace += 1;
                open.insert(trace, time);
                trace
            } else {
                let keys: Vec<u64> = open.keys().copied().collect();
                keys[next(keys.len() as u64) as usize]
            };
            match next(40) {
                0 => {
                    lost.insert(trace);
                }
                1 => {
                    lost.insert(trace);
                    feed.corrupt(sequence);
                }
                _ => {
                    retained.insert(trace);
                    feed.record(sequence, trace, epoch, time);
                }
            }
        }
        let verdicts = feed.close(steps);
        // Every retained trace gets exactly one verdict (the table holds
        // them all), and every one that lost an observation is incomplete.
        let keys: BTreeSet<u64> = verdicts.keys().copied().collect();
        assert_eq!(keys, retained, "seed {seed}: verdict set");
        for trace in lost.intersection(&retained) {
            assert_eq!(
                verdicts[trace], Incomplete,
                "seed {seed}: trace {trace} lost one"
            );
        }
        completes += verdicts
            .values()
            .filter(|verdict| **verdict == Complete)
            .count();
        // Traces entirely lost here have no verdict: `combine` makes them
        // incomplete wherever they are expected.
    }
    // The model is not trivially marking everything.
    assert!(completes > 100, "only {completes} complete verdicts");
}

/// A loss bounded by records in two epochs cannot be placed: the cohort
/// mark also covers a trace first retained much later in the new epoch,
/// whose lost observation may have been in the old one.
#[test]
fn an_epoch_spanning_loss_reaches_traces_first_seen_much_later() {
    let mut feed = Feed::new(config(10));
    feed.record(0, 1, 0, 0);
    // Sequence 1 (trace 9, epoch 0) lost.
    feed.record(2, 2, 1, 0);
    feed.record(3, 3, 1, 100);
    feed.record(4, 9, 1, 200);
    assert_eq!(feed.close(5)[&9], Incomplete);
}

#[test]
fn unallocatable_tables_are_refused() {
    assert!(matches!(
        Attributor::new(AttributionConfig {
            span: 1,
            max_traces: usize::MAX,
            max_intervals: 1,
        }),
        Err(TraceError::Attribution)
    ));
}
