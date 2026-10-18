// SPDX-License-Identifier: Apache-2.0

// The order rules: valid journals of each shape, and one mutation per
// rule, each refused at the record that breaks it with the checker left
// as it was.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;
use crate::group::record::{EventEnd, GapMarker, GapReason};

fn header(capture: Capture, first: u64) -> Role {
    Role::Header {
        capture,
        first_group_seq: first,
    }
}

fn end(seq: u64, observations: u32, outcome: EndOutcome) -> Role {
    Role::End(EventEnd {
        group_seq: seq,
        observations,
        outcome,
    })
}

fn complete(seq: u64, observations: u32) -> Role {
    end(seq, observations, EndOutcome::Complete)
}

fn gap(from: u64, to: u64) -> Role {
    Role::Gap(GapMarker {
        from_seq: from,
        to_seq: to,
        reason: GapReason::BudgetExceeded,
    })
}

/// Checks `roles` in order; returns the checker, or the first error.
fn check(roles: &[Role]) -> Result<OrderCheck, OrderError> {
    let mut check = OrderCheck::new();
    for role in roles {
        check.push(*role)?;
    }
    Ok(check)
}

#[test]
fn valid_journals_pass() {
    // A strict journal: events with and without observations.
    let strict = check(&[
        header(Capture::Strict, 5),
        Role::Event(5),
        Role::Observation(5, 0),
        Role::Observation(5, 1),
        complete(5, 2),
        Role::Event(6),
        complete(6, 0),
    ])
    .unwrap();
    assert!(strict.at_boundary());
    assert_eq!((strict.next_seq(), strict.records()), (7, 7));
    // Inside an event the journal is not at a boundary.
    let open = check(&[header(Capture::Strict, 1), Role::Event(1)]).unwrap();
    assert!(!open.at_boundary());
    // A strict journal ends at an incomplete event.
    let ended = check(&[
        header(Capture::Strict, 1),
        Role::Event(1),
        Role::Observation(1, 0),
        end(1, 1, EndOutcome::Incomplete),
    ])
    .unwrap();
    assert!(ended.at_boundary());
    // A best-effort journal goes on after an incomplete event, with gaps.
    let best_effort = check(&[
        header(Capture::BestEffort, 1),
        Role::Event(1),
        end(1, 0, EndOutcome::Incomplete),
        gap(2, 4),
        Role::Event(5),
        complete(5, 0),
        gap(6, 6),
    ])
    .unwrap();
    assert_eq!(best_effort.next_seq(), 7);
    // A header alone is a valid, empty journal.
    assert!(check(&[header(Capture::Strict, 1)]).unwrap().at_boundary());
}

/// Each journal breaks one rule at its last record.
#[test]
fn each_rule_is_enforced() {
    let cases: Vec<(Vec<Role>, OrderRule)> = vec![
        (vec![Role::Event(1)], OrderRule::Header),
        (
            vec![header(Capture::Strict, 1), header(Capture::Strict, 1)],
            OrderRule::Header,
        ),
        (
            vec![header(Capture::Strict, 1), Role::Event(2)],
            OrderRule::Sequence,
        ),
        (
            vec![
                header(Capture::Strict, 1),
                Role::Event(1),
                complete(1, 0),
                Role::Event(1),
            ],
            OrderRule::Sequence,
        ),
        (
            vec![header(Capture::BestEffort, 1), gap(2, 3)],
            OrderRule::Sequence,
        ),
        (
            vec![header(Capture::Strict, 1), Role::Event(1), Role::Event(2)],
            OrderRule::Nested,
        ),
        (
            vec![header(Capture::BestEffort, 1), Role::Event(1), gap(2, 2)],
            OrderRule::Nested,
        ),
        (
            vec![header(Capture::Strict, 1), Role::Observation(1, 0)],
            OrderRule::OutsideEvent,
        ),
        (
            vec![header(Capture::Strict, 1), complete(1, 0)],
            OrderRule::OutsideEvent,
        ),
        (
            vec![
                header(Capture::Strict, 1),
                Role::Event(1),
                Role::Observation(2, 0),
            ],
            OrderRule::OutsideEvent,
        ),
        (
            vec![header(Capture::Strict, 1), Role::Event(1), complete(2, 0)],
            OrderRule::OutsideEvent,
        ),
        (
            vec![
                header(Capture::Strict, 1),
                Role::Event(1),
                Role::Observation(1, 1),
            ],
            OrderRule::Index,
        ),
        (
            vec![
                header(Capture::Strict, 1),
                Role::Event(1),
                Role::Observation(1, 0),
                complete(1, 2),
            ],
            OrderRule::Count,
        ),
        (
            vec![
                header(Capture::Strict, 1),
                Role::Event(1),
                end(1, 0, EndOutcome::Incomplete),
                Role::Event(2),
            ],
            OrderRule::AfterIncomplete,
        ),
        (
            vec![header(Capture::Strict, 1), gap(1, 1)],
            OrderRule::StrictGap,
        ),
        (
            vec![
                header(Capture::Strict, u64::MAX),
                Role::Event(u64::MAX),
                complete(u64::MAX, 0),
            ],
            OrderRule::Exhausted,
        ),
        (
            vec![header(Capture::BestEffort, 1), gap(1, u64::MAX)],
            OrderRule::Exhausted,
        ),
        // Roles no decoded record has, refused by the checker itself.
        (vec![header(Capture::Strict, 0)], OrderRule::Invalid),
        (
            vec![header(Capture::BestEffort, 5), gap(5, 2)],
            OrderRule::Invalid,
        ),
    ];
    for (roles, rule) in cases {
        let (last, before) = roles.split_last().unwrap();
        let mut checker = check(before).unwrap();
        let kept = checker;
        assert_eq!(
            checker.push(*last),
            Err(OrderError {
                ordinal: u64::try_from(before.len()).unwrap(),
                rule
            }),
            "{roles:?}"
        );
        assert_eq!(checker, kept, "a refused record changed the checker");
    }
}

/// An index past `u32::MAX` is refused, not wrapped.
#[test]
fn an_observation_index_does_not_wrap() {
    let mut checker = check(&[header(Capture::Strict, 1), Role::Event(1)]).unwrap();
    checker.state = State::InEvent {
        seq: 1,
        index: u32::MAX,
    };
    assert_eq!(
        checker.push(Role::Observation(1, u32::MAX)),
        Err(OrderError {
            ordinal: 2,
            rule: OrderRule::Exhausted
        })
    );
}

/// A reference unavailable record (A7d): between events of a best-effort
/// journal, naming an event that ended; refused in a strict journal, for
/// an event not ended, inside an event, with a `group_seq` of 0, and after
/// a strict journal's end.
#[test]
fn a_reference_unavailable_names_an_ended_event_of_a_best_effort_journal() {
    let valid = check(&[
        header(Capture::BestEffort, 1),
        Role::Event(1),
        complete(1, 0),
        Role::Event(2),
        complete(2, 0),
        Role::Unavailable(1),
        Role::Unavailable(2),
        Role::Event(3),
        complete(3, 0),
    ])
    .unwrap();
    assert!(valid.at_boundary());
    assert_eq!((valid.next_seq(), valid.records()), (4, 9));
    let ended = [
        header(Capture::BestEffort, 1),
        Role::Event(1),
        complete(1, 0),
    ];
    let cases: Vec<(Vec<Role>, Role, OrderRule)> = vec![
        (
            vec![header(Capture::Strict, 1), Role::Event(1), complete(1, 0)],
            Role::Unavailable(1),
            OrderRule::Unavailable,
        ),
        (ended.to_vec(), Role::Unavailable(2), OrderRule::Unavailable),
        (ended.to_vec(), Role::Unavailable(0), OrderRule::Invalid),
        (
            vec![header(Capture::BestEffort, 1), Role::Event(1)],
            Role::Unavailable(1),
            OrderRule::Nested,
        ),
        (
            vec![
                header(Capture::Strict, 1),
                Role::Event(1),
                end(1, 0, EndOutcome::Incomplete),
            ],
            Role::Unavailable(1),
            OrderRule::AfterIncomplete,
        ),
        (vec![], Role::Unavailable(1), OrderRule::Header),
        // #405 review P3: below the first event.
        (
            vec![
                header(Capture::BestEffort, 5),
                Role::Event(5),
                complete(5, 0),
            ],
            Role::Unavailable(4),
            OrderRule::Unavailable,
        ),
        // An uncaptured payload in a strict journal, and nested.
        (
            vec![header(Capture::Strict, 1)],
            Role::Uncaptured(1),
            OrderRule::Unavailable,
        ),
        (
            vec![header(Capture::BestEffort, 1), Role::Event(1)],
            Role::Uncaptured(2),
            OrderRule::Nested,
        ),
        (
            vec![header(Capture::BestEffort, 1)],
            Role::Uncaptured(2),
            OrderRule::Sequence,
        ),
    ];
    for (before, role, rule) in cases {
        let mut checker = check(&before).unwrap();
        let kept = checker;
        assert_eq!(
            checker.push(role),
            Err(OrderError {
                ordinal: u64::try_from(before.len()).unwrap(),
                rule
            }),
            "{before:?} then {role:?}"
        );
        assert_eq!(checker, kept, "the checker stays as it was");
    }
}

/// A best-effort journal holds an uncaptured payload as an event.
#[test]
fn a_best_effort_journal_holds_an_uncaptured_payload() {
    let checker = check(&[
        header(Capture::BestEffort, 1),
        Role::Uncaptured(1),
        Role::Observation(1, 0),
        complete(1, 1),
        Role::Event(2),
        complete(2, 0),
    ])
    .unwrap();
    assert_eq!(checker.next_seq(), 3);
}

fn checkpoint(group_seq: u64, checkpoint_id: u64) -> Role {
    Role::Checkpoint {
        group_seq,
        checkpoint_id,
    }
}

/// A9-1: a checkpoint sits between events and names one already ended,
/// at or after the first; recorded checkpoints rise in `group_seq` and in
/// id. Events after its `group_seq` may come before it (its record lags
/// the write). A strict journal holds them too, but nothing after its
/// incomplete end.
#[test]
fn checkpoints_name_ended_events_in_rising_order() {
    let checker = check(&[
        header(Capture::Strict, 5),
        Role::Event(5),
        complete(5, 0),
        Role::Event(6),
        complete(6, 0),
        checkpoint(5, 1),
        checkpoint(6, 4),
    ])
    .unwrap();
    assert_eq!(checker.last_checkpoint(), Some((6, 4)));
    let cases = [
        (
            vec![header(Capture::Strict, 5)],
            checkpoint(0, 1),
            OrderRule::Invalid,
        ),
        (
            vec![header(Capture::Strict, 5)],
            checkpoint(1, 0),
            OrderRule::Invalid,
        ),
        (
            vec![header(Capture::Strict, 5)],
            checkpoint(5, 1),
            OrderRule::Checkpoint,
        ),
        (
            vec![header(Capture::Strict, 5), Role::Event(5), complete(5, 0)],
            checkpoint(4, 1),
            OrderRule::Checkpoint,
        ),
        (
            vec![
                header(Capture::Strict, 5),
                Role::Event(5),
                complete(5, 0),
                checkpoint(5, 2),
            ],
            checkpoint(5, 3),
            OrderRule::Checkpoint,
        ),
        (
            vec![
                header(Capture::Strict, 5),
                Role::Event(5),
                complete(5, 0),
                Role::Event(6),
                complete(6, 0),
                checkpoint(5, 2),
            ],
            checkpoint(6, 2),
            OrderRule::Checkpoint,
        ),
        (
            vec![header(Capture::Strict, 5), Role::Event(5)],
            checkpoint(5, 1),
            OrderRule::Nested,
        ),
        (
            vec![
                header(Capture::Strict, 5),
                Role::Event(5),
                end(5, 0, EndOutcome::Incomplete),
            ],
            checkpoint(5, 1),
            OrderRule::AfterIncomplete,
        ),
    ];
    for (before, role, rule) in cases {
        let mut checker = check(&before).unwrap();
        let kept = checker;
        assert_eq!(
            checker.push(role),
            Err(OrderError {
                ordinal: u64::try_from(before.len()).unwrap(),
                rule
            }),
            "{before:?} then {role:?}"
        );
        assert_eq!(checker, kept, "the checker stays as it was");
    }
    // In best effort, after a gap: the gap's events count as ended.
    let checker = check(&[header(Capture::BestEffort, 1), gap(1, 3), checkpoint(3, 1)]).unwrap();
    assert_eq!(checker.next_seq(), 4);
}
