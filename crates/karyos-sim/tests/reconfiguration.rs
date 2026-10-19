// SPDX-License-Identifier: Apache-2.0

//! Phase 5 membership over the harness (quantstratum-docs:
//! karyos/design/phase-5-cluster-scenarios.md, P5-S1), with the reference
//! core's fixed-leader configuration changes, over a fixed corpus of seeds
//! plus `scenarios::seeds()`:
//!
//! - M1: a spare joins as a learner and is promoted; while the leader and
//!   the learner are split from the other voters nothing commits, and
//!   after the promotion quorums are of four;
//! - M5: a learner cut off from the cluster is refused promotion as
//!   lagging, and promoted once it caught up;
//! - M8: every voter restarts under the latest configuration its log
//!   holds, the leader under an uncommitted one;
//! - the reference refuses what it cannot do;
//! - each membership check catches its violation in a hand-built record.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_sim::harness::check::{self, Violation};
use karyos_sim::harness::core::{Applying, Change, ChangeRefused, Configuration, Persisted, Step};
use karyos_sim::harness::membership::{self, M5_EARLY, M5_LATE, SPARE};
use karyos_sim::harness::node::{Observation, Positions};
use karyos_sim::harness::reference::{
    PROMOTION_LAG, Reference, decode_configuration, encode_configuration,
};
use karyos_sim::harness::workloads::{self, Outcome};
use karyos_sim::net::NodeId;
use karyos_sim::scenarios;

/// Seeds every scenario runs besides `scenarios::seeds()`.
const CORPUS: [u64; 4] = [0x05, 0x0054, 0xDEAD_BEEF, u64::MAX];

fn corpus() -> Vec<u64> {
    let mut seeds = CORPUS.to_vec();
    seeds.extend(scenarios::seeds());
    seeds
}

fn configuration(index: Option<u64>, voters: &[NodeId], learners: &[NodeId]) -> Configuration {
    Configuration {
        index,
        voters: voters.to_vec(),
        outgoing: Vec::new(),
        learners: learners.to_vec(),
    }
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

/// The answers the leader gave to `change`, in order.
fn answers(outcome: &Outcome, change: Change) -> Vec<Result<(), ChangeRefused>> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Change {
                node: 0,
                change: asked,
                result,
            } if *asked == change => Some(*result),
            _ => None,
        })
        .collect()
}

fn passing(case: &workloads::Case, seed: u64) -> Outcome {
    let outcome = workloads::run::<Reference>(case, seed).unwrap();
    assert_eq!(
        workloads::pass(case, &outcome),
        Ok(None),
        "{} seed {seed:#x}",
        case.name
    );
    outcome
}

#[test]
fn configuration_entries_round_trip() {
    let bytes = encode_configuration(&[0, 1, 2], &[3]);
    assert_eq!(decode_configuration(&bytes), Some((vec![0, 1, 2], vec![3])));
    assert_eq!(decode_configuration(&bytes[..bytes.len() - 1]), None);
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(decode_configuration(&longer), None);
    assert_eq!(decode_configuration(b"KC5\x01"), None);
}

#[test]
fn m1_adds_and_promotes_a_learner() {
    let case = membership::m1();
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
        // Every server, the new voter included, ends under four voters.
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
    let case = membership::m5();
    const { assert!(M5_EARLY < M5_LATE) };
    for seed in corpus() {
        let outcome = passing(&case, seed);
        let promotions = answers(&outcome, Change::Promote(SPARE));
        assert_eq!(promotions.len(), 2, "seed {seed:#x}");
        match promotions[0] {
            Err(ChangeRefused::Lagging { behind }) => assert!(behind > PROMOTION_LAG),
            other => panic!("seed {seed:#x}: the early promotion gave {other:?}"),
        }
        assert_eq!(promotions[1], Ok(()), "seed {seed:#x}");
        let last = reported(&outcome, 0).pop().unwrap();
        assert_eq!(last.voters, vec![0, 1, 2, SPARE]);
    }
}

#[test]
fn m8_restarts_under_the_latest_configuration_in_the_log() {
    let case = membership::m8();
    for seed in corpus() {
        let outcome = passing(&case, seed);
        // The leader's first configuration after its restart is the
        // uncommitted one its log holds; the followers' the bootstrap one.
        let after_restart = |node: NodeId| {
            outcome
                .observations
                .iter()
                .skip_while(|observation| {
                    !matches!(observation, Observation::Recovered { node: at, .. } if *at == node)
                })
                .find_map(|observation| match observation {
                    Observation::Configuration {
                        node: at,
                        configuration,
                        ..
                    } if *at == node => Some(configuration.clone()),
                    _ => None,
                })
                .unwrap()
        };
        let leader = after_restart(0);
        assert_eq!(leader.learners, vec![SPARE], "seed {seed:#x}");
        assert!(leader.index.is_some());
        for follower in [1, 2] {
            assert_eq!(
                after_restart(follower),
                configuration(None, &[0, 1, 2], &[]),
                "seed {seed:#x}"
            );
        }
        // After the heal the entry commits and reaches the followers.
        let last = reported(&outcome, 1).pop().unwrap();
        assert_eq!(last.learners, vec![SPARE], "seed {seed:#x}");
    }
}

#[test]
fn the_reference_refuses_what_it_cannot_do() {
    let mut case = membership::m1();
    case.schedule = vec![
        (5, workloads::Action::Join(SPARE)),
        // A promotion of a stranger, a removal of the fixed leader, and a
        // second change before the first commits.
        (6, workloads::Action::Change(Change::Promote(SPARE))),
        (6, workloads::Action::Change(Change::Remove(0))),
        (6, workloads::Action::Change(Change::AddLearner(SPARE))),
        (6, workloads::Action::Change(Change::Remove(1))),
        // Adding a member twice, once the first change committed.
        (200, workloads::Action::Change(Change::AddLearner(SPARE))),
    ];
    let outcome = passing(&case, 0x05);
    assert_eq!(
        answers(&outcome, Change::Promote(SPARE)),
        vec![Err(ChangeRefused::Invalid)]
    );
    assert_eq!(
        answers(&outcome, Change::Remove(0)),
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
    // Followers refuse every change: they do not lead.
    assert!(outcome.observations.iter().any(|observation| matches!(
        observation,
        Observation::Change {
            node: 1,
            result: Err(ChangeRefused::NotLeader(_)),
            ..
        }
    )));
}

// Hand-built records: each membership check catches its violation.

fn persisted(node: NodeId, appended: Vec<(u64, u64)>) -> Observation {
    Observation::Drive {
        node,
        step: Step::Persisted {
            persisted: Persisted {
                durable: appended.last().map(|(index, _)| *index),
                hard_state: None,
            },
            truncated_from: None,
            appended,
        },
    }
}

fn reports(node: NodeId, configuration: Configuration, entry_term: Option<u64>) -> Observation {
    Observation::Configuration {
        node,
        configuration,
        entry_term,
    }
}

fn commit(node: NodeId, index: u64) -> Observation {
    Observation::Commit {
        node,
        term: 1,
        leader: true,
        index,
        entry_term: 1,
    }
}

#[test]
fn a_commit_counting_a_learner_is_caught() {
    let learner = configuration(Some(1), &[0, 1, 2], &[3]);
    // The leader and its learner hold entry 2; neither other voter does.
    let mut record = vec![
        reports(0, learner.clone(), Some(1)),
        persisted(0, vec![(1, 1), (2, 1)]),
        persisted(3, vec![(1, 1), (2, 1)]),
        commit(0, 2),
    ];
    assert_eq!(
        check::quorum_of_voters(&record),
        Err(Violation::QuorumOfVoters {
            node: 0,
            index: 2,
            term: 1,
            holding: 1,
            configuration: Box::new(learner.clone()),
        })
    );
    // The reply check counts voters too.
    let reply = Observation::Reply {
        node: 0,
        client: 9,
        index: 2,
        term: 1,
        generation: 1,
    };
    record.insert(3, reply);
    assert!(matches!(
        check::durable_majority_before_reply(&record, 4),
        Err(Violation::ReplyBeforeDurableMajority {
            durable: 1,
            servers: 3,
            ..
        })
    ));
    // One more voter holding it makes both a majority.
    record.insert(3, persisted(1, vec![(1, 1), (2, 1)]));
    assert_eq!(check::quorum_of_voters(&record), Ok(()));
    assert_eq!(check::durable_majority_before_reply(&record, 4), Ok(()));
}

#[test]
fn a_joint_commit_needs_both_majorities() {
    let mut joint = configuration(Some(3), &[0, 3, 4], &[]);
    joint.outgoing = vec![0, 1, 2];
    let record = vec![
        reports(0, joint, Some(1)),
        persisted(0, vec![(1, 1)]),
        persisted(3, vec![(1, 1)]),
        commit(0, 1),
    ];
    // A majority of the new voters, but one of three of the outgoing.
    assert!(matches!(
        check::quorum_of_voters(&record),
        Err(Violation::QuorumOfVoters { holding: 2, .. })
    ));
    // A reply then is short of the outgoing majority too: one of three.
    let mut replied = record.clone();
    replied.push(Observation::Reply {
        node: 0,
        client: 9,
        index: 1,
        term: 1,
        generation: 1,
    });
    assert!(matches!(
        check::durable_majority_before_reply(&replied, 5),
        Err(Violation::ReplyBeforeDurableMajority {
            durable: 1,
            servers: 3,
            ..
        })
    ));
    // One more outgoing voter holding it makes both majorities.
    replied.insert(3, persisted(1, vec![(1, 1)]));
    assert_eq!(check::durable_majority_before_reply(&replied, 5), Ok(()));
    assert_eq!(check::quorum_of_voters(&replied), Ok(()));
}

#[test]
fn a_restart_under_another_configuration_is_caught() {
    let added = configuration(Some(2), &[0, 1, 2], &[3]);
    let recovered = |entries: Vec<(u64, u64)>| Observation::Recovered {
        node: 1,
        entries,
        durable: Some(2),
    };
    // Its log holds the configuration entry: it must come back under it.
    let record = vec![
        reports(0, added.clone(), Some(1)),
        Observation::Crashed { node: 1 },
        recovered(vec![(1, 1), (2, 1)]),
        reports(1, configuration(None, &[0, 1, 2], &[]), None),
    ];
    assert_eq!(
        check::configuration_from_log(&record),
        Err(Violation::ConfigurationNotFromLog {
            node: 1,
            expected: Some(Box::new(added.clone())),
            found: Box::new(configuration(None, &[0, 1, 2], &[])),
        })
    );
    // A log without it comes back under the bootstrap one.
    let mut fine = record.clone();
    fine[2] = recovered(vec![(1, 1)]);
    assert_eq!(check::configuration_from_log(&fine), Ok(()));
    // An entry of the same index but another term is not that entry.
    fine[2] = recovered(vec![(1, 1), (2, 2)]);
    assert_eq!(check::configuration_from_log(&fine), Ok(()));
    // Coming back under it passes; a later change is not the restart's.
    let mut back = record.clone();
    back[3] = reports(1, added.clone(), Some(1));
    back.push(reports(
        1,
        configuration(Some(5), &[0, 1, 2, 3], &[]),
        Some(1),
    ));
    assert_eq!(check::configuration_from_log(&back), Ok(()));
    // Of two configuration entries in the log, the latest one counts.
    let promoted = configuration(Some(4), &[0, 1, 2, 3], &[]);
    let two = |found: Configuration| {
        vec![
            reports(0, added.clone(), Some(1)),
            reports(0, promoted.clone(), Some(1)),
            Observation::Crashed { node: 1 },
            recovered(vec![(1, 1), (2, 1), (3, 1), (4, 1)]),
            reports(1, found, Some(1)),
        ]
    };
    assert_eq!(
        check::configuration_from_log(&two(promoted.clone())),
        Ok(())
    );
    assert_eq!(
        check::configuration_from_log(&two(added.clone())),
        Err(Violation::ConfigurationNotFromLog {
            node: 1,
            expected: Some(Box::new(promoted)),
            found: Box::new(added.clone()),
        })
    );
    // One entry reported as two configurations.
    let conflict = vec![
        reports(0, added, Some(1)),
        reports(1, configuration(Some(2), &[0, 1], &[]), Some(1)),
    ];
    assert_eq!(
        check::configuration_from_log(&conflict),
        Err(Violation::ConfigurationConflict { index: 2, term: 1 })
    );
}

#[test]
fn a_promotion_of_a_lagging_learner_is_caught() {
    let at = |durable: Option<u64>, committed: Option<u64>| Positions {
        received: durable.max(committed),
        written: durable.max(committed),
        durable: durable.max(committed),
        committed,
        applied: committed,
    };
    let learner = |durable: Option<u64>| Observation::Positions {
        node: 3,
        positions: Positions {
            committed: None,
            applied: None,
            ..at(durable, None)
        },
    };
    let promoted = Observation::Change {
        node: 0,
        change: Change::Promote(3),
        result: Ok(()),
    };
    let leader = Observation::Positions {
        node: 0,
        positions: at(Some(20), Some(20)),
    };
    let record = vec![leader.clone(), learner(Some(10)), promoted.clone()];
    assert_eq!(
        check::learner_caught_up(&record, 4),
        Err(Violation::LearnerBehind {
            node: 0,
            learner: 3,
            behind: 10,
            lag: 4,
        })
    );
    // A learner that never reported is behind by the whole commit.
    assert!(matches!(
        check::learner_caught_up(&[leader.clone(), promoted.clone()], 4),
        Err(Violation::LearnerBehind { behind: 20, .. })
    ));
    // Within the lag, and a refused promotion, pass.
    assert_eq!(
        check::learner_caught_up(&[leader.clone(), learner(Some(16)), promoted], 4),
        Ok(())
    );
    let refused = Observation::Change {
        node: 0,
        change: Change::Promote(3),
        result: Err(ChangeRefused::Lagging { behind: 10 }),
    };
    assert_eq!(
        check::learner_caught_up(&[leader, learner(Some(10)), refused], 4),
        Ok(())
    );
}

#[test]
fn a_core_with_static_membership_reports_nothing_and_passes() {
    // No configuration observed: the reply check keeps counting servers,
    // and the membership checks pass at once.
    let record = vec![
        persisted(0, vec![(1, 1)]),
        persisted(1, vec![(1, 1)]),
        commit(0, 1),
        Observation::Applied {
            node: 0,
            entry: karyos_cluster::Entry {
                index: 1,
                term: 1,
                event_time: 0,
                payload: Vec::new(),
            },
            applying: Applying {
                durable: Some(1),
                logged_term: Some(1),
            },
            response: None,
        },
    ];
    assert_eq!(check::membership(&record, 0), Ok(()));
}
