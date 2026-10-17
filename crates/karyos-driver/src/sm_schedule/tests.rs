// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use super::*;

const MS: u64 = 1_000_000;
const INTERVAL: u64 = 10 * MS;

fn schedule(windows: &[u32]) -> SmSchedule {
    SmSchedule::new(INTERVAL, windows).unwrap()
}

/// Asks at `now` and, if due, sends: returns the reason.
fn tick(schedule: &mut SmSchedule, now: u64, consumption: &[u64]) -> Option<SmReason> {
    let due = schedule.due(now, consumption)?;
    schedule.sent(&due, now);
    Some(due.reason)
}

#[test]
fn the_schedule_is_validated() {
    assert_eq!(
        SmSchedule::new(0, &[100]).err(),
        Some(SmScheduleError::Interval)
    );
    for windows in [&[][..], &[1, 2, 3, 4, 5][..], &[100, 0][..]] {
        assert_eq!(
            SmSchedule::new(INTERVAL, windows).err(),
            Some(SmScheduleError::Windows)
        );
    }
}

/// The first SM is due at once, then one per interval, exactly at it.
#[test]
fn the_join_then_one_per_interval() {
    let mut schedule = schedule(&[4096]);
    assert_eq!(tick(&mut schedule, 5 * MS, &[0]), Some(SmReason::Join));
    assert_eq!(tick(&mut schedule, 5 * MS + INTERVAL - 1, &[0]), None);
    assert_eq!(
        tick(&mut schedule, 5 * MS + INTERVAL, &[0]),
        Some(SmReason::Interval)
    );
    // A backward clock read sends nothing early.
    assert_eq!(tick(&mut schedule, MS, &[0]), None);
    let counts = schedule.counts();
    assert_eq!((counts.joins, counts.interval, counts.progress), (1, 1, 0));
}

/// A quarter-window advance on any lane is due at once; less is not.
#[test]
fn a_quarter_window_advance_is_due_at_once() {
    let mut schedule = schedule(&[4096, 400]);
    tick(&mut schedule, 0, &[0, 0]);
    assert_eq!(tick(&mut schedule, MS, &[1023, 99]), None);
    assert_eq!(
        tick(&mut schedule, MS, &[1024, 99]),
        Some(SmReason::Progress),
        "lane 0 by a quarter"
    );
    assert_eq!(
        tick(&mut schedule, 2 * MS, &[1024, 199]),
        Some(SmReason::Progress),
        "lane 1 by 100 = 400 / 4"
    );
    // The progress SM restarts the interval.
    assert_eq!(
        tick(&mut schedule, 2 * MS + INTERVAL - 1, &[1100, 200]),
        None
    );
    assert_eq!(schedule.counts().progress, 2);
}

/// A window below 4 has a quarter of 1.
#[test]
fn a_tiny_window_advances_by_one() {
    let mut schedule = schedule(&[3]);
    tick(&mut schedule, 0, &[0]);
    assert_eq!(tick(&mut schedule, 1, &[1]), Some(SmReason::Progress));
}

/// A lower consumption is never reported: the SM carries the last value
/// and the regression is counted once per SM.
#[test]
fn the_reported_consumption_never_goes_back() {
    let mut schedule = schedule(&[4096, 4096]);
    tick(&mut schedule, 0, &[500, 70]);
    assert!(schedule.due(MS, &[400, 70]).is_none(), "not due yet");
    assert_eq!(schedule.counts().regressions, 0);
    let due = schedule.due(INTERVAL, &[400, 80]).unwrap();
    assert_eq!(due.reason, SmReason::Interval);
    assert_eq!(due.consumption, [500, 80, 0, 0]);
    assert_eq!(schedule.counts().regressions, 1);
    // A stale due sent late cannot move the reference back either.
    let stale = SmDue {
        reason: SmReason::Interval,
        consumption: [10, 10, 0, 0],
    };
    schedule.sent(&stale, INTERVAL);
    let next = schedule.due(2 * INTERVAL, &[500, 80]).unwrap();
    assert_eq!(next.consumption, [500, 80, 0, 0]);
}

/// An SM not sent stays due; extra and missing lanes are handled.
#[test]
fn an_unsent_sm_stays_due() {
    let mut schedule = schedule(&[4096]);
    assert!(schedule.due(0, &[]).is_some());
    let due = schedule.due(MS, &[7, 99]).unwrap();
    assert_eq!(due.reason, SmReason::Join);
    assert_eq!(due.consumption, [7, 0, 0, 0], "lane 1 is not the image's");
    schedule.sent(&due, MS);
    assert!(schedule.due(MS, &[7]).is_none());
}
