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
