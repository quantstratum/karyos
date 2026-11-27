// SPDX-License-Identifier: Apache-2.0

//! Phase 5 membership (P5-S1) against the shipped core (karyos#711): the
//! custom core's single-server changes behind the harness, under the same
//! scenarios and checks as the reference fixture
//! (`tests/reconfiguration.rs`), with elections, so the leader is whichever
//! server won:
//!
//! - M1: a spare joins as a learner and is promoted; every server ends
//!   under four voters;
//! - M5: a learner cut off is refused promotion as lagging, and promoted
//!   once it caught up;
//! - M8: every voter restarts under the latest configuration its log
//!   holds;
//! - a learner added before a compaction purged its configuration entry
//!   learns its membership from the snapshot it installs, and keeps it
//!   across a restart over that snapshot;
//! - the core refuses an invalid, an overlapping and a non-leader change.

#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_sim::harness::core::{Change, ChangeRefused, Configuration};
use karyos_sim::harness::custom::{Custom, PROMOTION_LAG};
use karyos_sim::harness::membership::{self, M5_EARLY, M5_LATE, SPARE};
use karyos_sim::harness::node::{Compaction, Observation};
use karyos_sim::harness::workloads::{self, Action, Outcome};
use karyos_sim::net::NodeId;
use karyos_sim::scenarios;

/// Seeds every scenario runs besides `scenarios::seeds()`.
const CORPUS: [u64; 4] = [0x05, 0x0054, 0xDEAD_BEEF, u64::MAX];

fn corpus() -> Vec<u64> {
    let mut seeds = CORPUS.to_vec();
    seeds.extend(scenarios::seeds());
    seeds
}

/// The configurations `node` reported, in order.
fn reported(outcome: &Outcome, node: NodeId) -> Vec<Configuration> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Configuration {
                node: at,
                configuration,
                ..
            } if *at == node => Some(configuration.clone()),
            _ => None,
        })
        .collect()
}

/// The answers to `change` other than a non-leader's refusal, in order.
fn answers(outcome: &Outcome, change: Change) -> Vec<Result<(), ChangeRefused>> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Change {
                change: asked,
                result,
                ..
            } if *asked == change && !matches!(result, Err(ChangeRefused::NotLeader(_))) => {
                Some(*result)
            }
            _ => None,
        })
        .collect()
}

/// Steps a scenario waits before its schedule: the reference's leader is
/// fixed, this core's is elected first.
const WARM_UP: u64 = 100;

/// `case` with its schedule after [`WARM_UP`].
fn warmed(mut case: workloads::Case) -> workloads::Case {
    for (step, _) in &mut case.schedule {
        *step += WARM_UP;
    }
    case.steps += WARM_UP;
    case
}

fn passing(case: &workloads::Case, seed: u64) -> Outcome {
    let outcome = workloads::run::<Custom>(case, seed).unwrap();
    assert_eq!(
        workloads::pass(case, &outcome),
        Ok(None),
        "{} seed {seed:#x}",
        case.name
    );
    outcome
}

#[test]
fn m1_adds_and_promotes_a_learner() {
    let case = warmed(membership::m1());
    for seed in corpus() {
        let outcome = passing(&case, seed);
        assert_eq!(
            answers(&outcome, Change::AddLearner(SPARE)),
            vec![Ok(())],
            "seed {seed:#x}"
        );
        assert_eq!(
            answers(&outcome, Change::Promote(SPARE)),
            vec![Ok(())],
            "seed {seed:#x}"
        );
        for node in 0..=SPARE {
            let last = reported(&outcome, node).pop().unwrap();
            assert_eq!(
                last.voters,
                vec![0, 1, 2, SPARE],
                "node {node} seed {seed:#x}"
            );
            assert!(last.learners.is_empty());
        }
    }
}

#[test]
fn m5_refuses_a_lagging_learner_then_promotes_it() {
    let case = warmed(membership::m5());
    const { assert!(M5_EARLY < M5_LATE) };
    for seed in corpus() {
        let outcome = passing(&case, seed);
        let promotions = answers(&outcome, Change::Promote(SPARE));
        assert_eq!(promotions.len(), 2, "seed {seed:#x}: {promotions:?}");
        match promotions[0] {
            Err(ChangeRefused::Lagging { behind }) => assert!(behind > PROMOTION_LAG),
            other => panic!("seed {seed:#x}: the early promotion gave {other:?}"),
        }
        assert_eq!(promotions[1], Ok(()), "seed {seed:#x}");
        let last = reported(&outcome, SPARE).pop().unwrap();
        assert_eq!(last.voters, vec![0, 1, 2, SPARE], "seed {seed:#x}");
    }
}

#[test]
fn m8_restarts_under_the_latest_configuration_in_the_log() {
    let case = warmed(membership::m8());
    for seed in corpus() {
        // The harness checks each restart's configuration against the log
        // the server reopened (`check::configuration_from_log`). Unlike
        // the reference's fixed leader, an elected one cut off when it
        // appended the change may lose it to the next leader: the voters
        // end agreeing, either way.
        let outcome = passing(&case, seed);
        let last: Vec<Configuration> = (0..3)
            .map(|node| reported(&outcome, node).pop().unwrap())
            .collect();
        assert!(
            last.iter()
                .all(|configuration| configuration.voters == vec![0, 1, 2]
                    && configuration.learners == last[0].learners),
            "seed {seed:#x}: {last:?}"
        );
    }
}

/// The learner is added while it is down, the leader's compactions purge
/// the configuration entry, and only then does the learner start: it
/// installs a snapshot, which must carry its membership.
#[test]
fn a_learner_added_before_a_purge_learns_its_membership_from_the_snapshot() {
    let mut case = membership::m1();
    case.name = "learner after a purge".to_owned();
    case.schedule = vec![
        (2, Action::Change(Change::AddLearner(SPARE))),
        (400, Action::Join(SPARE)),
        (700, Action::Crash(SPARE)),
        (710, Action::Restart(SPARE)),
    ];
    case.compaction = Some(Compaction {
        every: 20,
        keep: 0,
        frame: 1,
        every_bytes: None,
    });
    case.steps = 1_000;
    let case = warmed(case);
    for seed in CORPUS {
        let outcome = passing(&case, seed);
        assert_eq!(answers(&outcome, Change::AddLearner(SPARE)), vec![Ok(())]);
        assert!(
            outcome.observations.iter().any(|observation| matches!(
                observation,
                Observation::Installed { node, .. } if *node == SPARE
            )),
            "seed {seed:#x}: the learner installed no snapshot"
        );
        let configurations = reported(&outcome, SPARE);
        let last = configurations.last().unwrap();
        assert_eq!(
            (last.voters.clone(), last.learners.clone()),
            (vec![0, 1, 2], vec![SPARE]),
            "seed {seed:#x}: {configurations:?}"
        );
    }
}

#[test]
fn the_core_refuses_invalid_overlapping_and_follower_changes() {
    let mut case = membership::m1();
    case.schedule = vec![
        (5, Action::Join(SPARE)),
        (60, Action::Change(Change::Promote(SPARE))),
        (61, Action::Change(Change::Remove(9))),
        (62, Action::Change(Change::AddLearner(SPARE))),
        (62, Action::Change(Change::Remove(1))),
        (300, Action::Change(Change::AddLearner(SPARE))),
    ];
    let case = warmed(case);
    let outcome = passing(&case, 0x05);
    assert_eq!(
        answers(&outcome, Change::Promote(SPARE)),
        vec![Err(ChangeRefused::Invalid)]
    );
    assert_eq!(
        answers(&outcome, Change::Remove(9)),
        vec![Err(ChangeRefused::Invalid)]
    );
    assert_eq!(
        answers(&outcome, Change::AddLearner(SPARE)),
        vec![Ok(()), Err(ChangeRefused::Invalid)]
    );
    assert_eq!(
        answers(&outcome, Change::Remove(1)),
        vec![Err(ChangeRefused::InProgress)]
    );
    assert!(outcome.observations.iter().any(|observation| matches!(
        observation,
        Observation::Change {
            result: Err(ChangeRefused::NotLeader(_)),
            ..
        }
    )));
}
