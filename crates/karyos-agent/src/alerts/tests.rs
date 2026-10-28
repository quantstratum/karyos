// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use super::*;
use crate::api::{Lane, Subscriber};

/// A sample of one lane whose subscribers have `lags`, consistent or not.
fn sample(consistent: bool, lags: &[(u64, Option<i64>)]) -> Sample {
    Sample {
        consistent,
        sampled: true,
        age_ns: Some(0),
        counters: Vec::new(),
        lanes: vec![Lane {
            sampled_ns: None,
            stream: 3,
            lane: 0,
            limit: Some(1 << 30),
            head: Some(1 << 29),
            floor: Some(0),
            headroom: None,
            subscribers: lags
                .iter()
                .map(|&(registration, lag)| Subscriber {
                    cell_registration: 0,
                    changed_ns: None,
                    registration,
                    label: String::new(),
                    position: 0,
                    lag,
                })
                .collect(),
        }],
    }
}

fn rules() -> AlertRules {
    AlertRules::default()
        .with_lag_bytes(100)
        .with_lag_refreshes(2)
        .with_loss_quiet(2)
}

#[test]
fn a_lag_fires_after_its_samples_and_clears_below_the_bound() {
    let rules = rules();
    let mut alerts = Alerts::default();
    let lagging = sample(true, &[(5, Some(150)), (6, Some(10))]);
    alerts.update(&rules, Some(&lagging), 0, 1000);
    assert!(alerts.firing().is_empty(), "one sample is not enough");
    alerts.update(&rules, Some(&lagging), 0, 2000);
    let firing = alerts.firing();
    assert_eq!(firing.len(), 1);
    assert_eq!(
        (firing[0].kind, firing[0].stream, firing[0].participant),
        (AlertKind::Lag, 3, 5)
    );
    // It began firing at its second sample (IMPLEMENT's F2 on #477).
    assert_eq!((firing[0].value, firing[0].since), (150, 2000));
    // A sample that may mix passes changes nothing.
    alerts.update(&rules, Some(&sample(false, &[(5, Some(0))])), 0, 3000);
    assert_eq!(alerts.firing().len(), 1);
    // No sample at all (the driver went away) changes nothing either.
    alerts.update(&rules, None, 0, 4000);
    assert_eq!(alerts.firing().len(), 1);
    // One consistent sample below the bound clears it.
    alerts.update(&rules, Some(&sample(true, &[(5, Some(99))])), 0, 5000);
    assert!(alerts.firing().is_empty());
    // A gone subscriber clears it too, and a run starts over.
    alerts.update(&rules, Some(&lagging), 0, 6000);
    alerts.update(&rules, Some(&sample(true, &[])), 0, 7000);
    alerts.update(&rules, Some(&lagging), 0, 8000);
    assert!(alerts.firing().is_empty());
}

#[test]
fn an_unknown_or_negative_lag_never_fires() {
    let rules = rules().with_lag_refreshes(1);
    let mut alerts = Alerts::default();
    alerts.update(
        &rules,
        Some(&sample(true, &[(5, None), (6, Some(-500))])),
        0,
        1,
    );
    assert!(alerts.firing().is_empty());
}

#[test]
fn losses_fire_count_and_clear_after_quiet_refreshes() {
    let rules = rules();
    let mut alerts = Alerts::default();
    alerts.update(&rules, None, 0, 10);
    assert!(alerts.firing().is_empty());
    alerts.update(&rules, None, 2, 20);
    let firing = alerts.firing();
    assert_eq!(
        (firing[0].kind, firing[0].value, firing[0].since),
        (AlertKind::Loss, 2, 20)
    );
    // More losses add to the count; the start stays.
    alerts.update(&rules, None, 5, 30);
    assert_eq!(
        (alerts.firing()[0].value, alerts.firing()[0].since),
        (5, 20)
    );
    // Two quiet refreshes clear it.
    alerts.update(&rules, None, 5, 40);
    assert_eq!(alerts.firing().len(), 1);
    alerts.update(&rules, None, 5, 50);
    assert!(alerts.firing().is_empty());
    // A new instance starts the count over: its first loss is one loss.
    alerts.restart();
    alerts.update(&rules, None, 1, 60);
    assert_eq!(alerts.firing()[0].value, 1);
}

/// IMPLEMENT's F1 on #477: a refresh that reads nothing (the driver closed
/// or cannot be attached) clears every lag alert and is a quiet refresh
/// for the loss alert, which then clears after its quiet refreshes.
#[test]
fn a_detached_driver_clears_lags_and_quiets_losses() {
    let rules = rules().with_lag_refreshes(1);
    let mut alerts = Alerts::default();
    alerts.update(&rules, Some(&sample(true, &[(5, Some(150))])), 3, 10);
    assert_eq!(alerts.firing().len(), 2);
    alerts.detached(&rules);
    let firing = alerts.firing();
    assert_eq!(firing.len(), 1);
    assert_eq!(firing[0].kind, AlertKind::Loss);
    alerts.detached(&rules);
    assert!(alerts.firing().is_empty());
}

fn ack(guard: u64, consistent: bool, epoch: u64, overdue: u64) -> AckRead {
    AckRead {
        guard,
        consistent,
        epoch,
        overdue,
    }
}

fn guard_alerts(alerts: &Alerts) -> Vec<(u64, u64, u64)> {
    alerts
        .firing()
        .iter()
        .filter(|alert| alert.kind == AlertKind::GuardAck)
        .map(|alert| (alert.participant, alert.value, alert.since))
        .collect()
}

/// A close with senders overdue fires per guard, keeps its start while
/// the same close stays overdue, starts over at a new close, and clears
/// when none is overdue or the guard is gone. A read that may mix passes
/// changes nothing.
#[test]
fn a_guard_with_senders_overdue_fires_and_clears() {
    let mut alerts = Alerts::default();
    // Pending within the timeout, or open: nothing fires.
    alerts.update_guard_acks(&[ack(1, true, 3, 0), ack(2, true, 0, 0)], 10);
    assert!(guard_alerts(&alerts).is_empty());
    alerts.update_guard_acks(&[ack(1, true, 3, 2), ack(2, true, 0, 0)], 20);
    assert_eq!(guard_alerts(&alerts), [(1, 2, 20)]);
    // One applied: the count follows, the start stays.
    alerts.update_guard_acks(&[ack(1, true, 3, 1)], 30);
    assert_eq!(guard_alerts(&alerts), [(1, 1, 20)]);
    // An inconsistent read keeps the last state, whatever it holds.
    alerts.update_guard_acks(&[ack(1, false, 0, 0)], 40);
    assert_eq!(guard_alerts(&alerts), [(1, 1, 20)]);
    // A new close of the same guard starts over.
    alerts.update_guard_acks(&[ack(1, true, 5, 1)], 50);
    assert_eq!(guard_alerts(&alerts), [(1, 1, 50)]);
    // None overdue clears; so does the guard gone.
    alerts.update_guard_acks(&[ack(1, true, 5, 0)], 60);
    assert!(guard_alerts(&alerts).is_empty());
    alerts.update_guard_acks(&[ack(1, true, 5, 3)], 70);
    alerts.update_guard_acks(&[], 80);
    assert!(guard_alerts(&alerts).is_empty());
    // An inconsistent read of a guard not firing does not fire it.
    alerts.update_guard_acks(&[ack(1, false, 5, 3)], 90);
    assert!(guard_alerts(&alerts).is_empty());
}

/// A refresh that reads nothing clears the guard alerts, as it does lags.
#[test]
fn a_detached_driver_clears_guard_alerts() {
    let rules = rules();
    let mut alerts = Alerts::default();
    alerts.update_guard_acks(&[ack(4, true, 3, 1)], 10);
    assert_eq!(guard_alerts(&alerts), [(4, 1, 10)]);
    alerts.detached(&rules);
    assert!(guard_alerts(&alerts).is_empty());
}
