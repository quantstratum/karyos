// SPDX-License-Identifier: Apache-2.0

//! Phase 5 standby (P5-S2) against the shipped core (karyos#713): the
//! custom Raft core (ADR-0105) in both groups, under the same scenarios
//! and checks as the reference fixture (`tests/standby.rs`, kept as the
//! control), with elections, so each group's leader is whichever server
//! won. Each scenario runs over the feed and over the Cluster log
//! replication (ADR-0120, karyos#714):
//!
//! - S1: the standby follows, effects disabled, and verifies the
//!   primary's commit;
//! - S2: after an operator stop, the standby is promoted; the verified
//!   prefix survives, the rest is reported, clients continue on it;
//! - S3: after the lease expired, the old primary alive and partitioned,
//!   the standby is promoted and no old-generation reply follows;
//! - S4: promotions before fencing are refused;
//! - S6: damaged sends are refused before they apply;
//! - S7: a restarted standby resumes from its verified position.
//!
//! S5, a client's generations, is a test of the client node with no core
//! underneath (`tests/standby.rs`).
//!
//! **Following across primary leader changes.** The fixture hands the
//! primary's leadership to chosen servers twice (`s1_source_change`).
//! The custom core has no leadership transfer API, so on the core the
//! same two changes are forced by failure: the primary's leader is
//! crashed, a new one elected, and that one crashed in turn. The test
//! requires exactly two distinct leader changes and a standby that
//! followed both with no gap and no duplicate.
//!
//! **Mutants with the core underneath.** Each standby check catches its
//! violation planted in a record the custom core produced: the same
//! mutations as the hand-built records of `tests/standby.rs`, applied to
//! a real run that passed.
//!
//! **Results.** [`p5_s2_results_on_the_core_and_on_the_fixture`] runs
//! every case on the fixture and on the core, each judged apart over the
//! same seeds, and requires the same verdict of both; the fixture's
//! leadership handover case is the fixture's alone.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use karyos_sim::harness::check::{self, Violation};
use karyos_sim::harness::core::ConsensusCore;
use karyos_sim::harness::custom::{Custom, ELECTION_MAX};
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::standby::{self, Fencing, PRIMARY, PromotionReport, STANDBY};
use karyos_sim::harness::workloads::{
    self, Action, Case, LeaderAction, Liveness, Outcome, RunError,
};
use karyos_sim::net::NodeId;
use karyos_sim::scenarios;

/// Seeds every scenario runs besides `scenarios::seeds()`: those of
/// `tests/standby.rs`.
const CORPUS: [u64; 4] = [0x55, 0x0054, 0xDEAD_BEEF, u64::MAX];

fn corpus() -> Vec<u64> {
    let mut seeds = CORPUS.to_vec();
    seeds.extend(scenarios::seeds());
    seeds
}

/// Steps a scenario waits before its schedule: the reference's leaders
/// are fixed, this core's are elected first. The longest election
/// timeout: long enough for both groups to elect, short enough that the
/// clients, which start at step 0, still have commands in flight when
/// the schedule acts (S2's operator stop).
const WARM_UP: u64 = ELECTION_MAX as u64;

/// `case` with its schedule after [`WARM_UP`].
fn warmed(mut case: Case) -> Case {
    for (step, _) in &mut case.schedule {
        *step += WARM_UP;
    }
    case.steps += WARM_UP;
    case
}

/// `case` over the feed and over the replication, warmed.
fn both(case: Case) -> [Case; 2] {
    [
        warmed(case.clone()),
        warmed(standby::over_replication(case)),
    ]
}

fn passing(case: &Case, seed: u64) -> Outcome {
    let outcome = workloads::run::<Custom>(case, seed).unwrap();
    assert_eq!(
        workloads::pass(case, &outcome),
        Ok(None),
        "{} seed {seed:#x}",
        case.name
    );
    outcome
}

/// The highest primary index `node` applied.
fn verified(outcome: &Outcome, node: NodeId) -> Option<u64> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::FeedApplied {
                node: at, index, ..
            } if *at == node => Some(*index),
            _ => None,
        })
        .max()
}

/// The highest commit a primary server reached.
fn primary_commit(outcome: &Outcome) -> Option<u64> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Commit { node, index, .. } if PRIMARY.contains(node) => Some(*index),
            _ => None,
        })
        .max()
}

fn promoted(outcome: &Outcome) -> Option<(NodeId, PromotionReport)> {
    outcome
        .observations
        .iter()
        .find_map(|observation| match observation {
            Observation::Promoted { node, report } => Some((*node, report.clone())),
            _ => None,
        })
}

fn succeeded_in(outcome: &Outcome, generation: u64) -> bool {
    outcome.observations.iter().any(|observation| {
        matches!(observation, Observation::Success { generation: g, .. } if *g == generation)
    })
}

#[test]
fn s1_the_standby_follows_with_effects_disabled_on_the_core() {
    for case in both(standby::s1()) {
        for seed in corpus() {
            let outcome = passing(&case, seed);
            let commit = primary_commit(&outcome);
            assert!(commit.is_some(), "{} seed {seed:#x}", case.name);
            for node in STANDBY {
                assert_eq!(
                    verified(&outcome, node),
                    commit,
                    "{} node {node} seed {seed:#x}",
                    case.name
                );
            }
            assert!(promoted(&outcome).is_none());
        }
    }
}

#[test]
fn s2_an_operator_stop_then_a_promotion_on_the_core() {
    for case in both(standby::s2()) {
        for seed in corpus() {
            let outcome = passing(&case, seed);
            let (node, report) = promoted(&outcome).unwrap();
            assert!(STANDBY.contains(&node), "{} seed {seed:#x}", case.name);
            assert_eq!(report.generation, 2);
            assert!(report.verified <= report.learnt_commit);
            // The stop came with commands in flight, each reported.
            assert!(!report.unknown.is_empty(), "{} seed {seed:#x}", case.name);
            assert_eq!(report.replication.is_some(), case.replication);
            assert!(outcome.observations.iter().any(|observation| matches!(
                observation,
                Observation::Fenced {
                    fencing: Fencing::OperatorStop,
                    lease_end: None
                }
            )));
            assert!(succeeded_in(&outcome, 2), "{} seed {seed:#x}", case.name);
        }
    }
}

#[test]
fn s3_a_lease_expiry_then_a_promotion_with_the_old_primary_alive_on_the_core() {
    for case in both(standby::s3()) {
        for seed in corpus() {
            let outcome = workloads::run::<Custom>(&case, seed).unwrap();
            // Client 1 stays on the old primary, which never answers it
            // again.
            assert_eq!(
                workloads::pass(&case, &outcome),
                Ok(Some(Liveness::Stalled { waiting: 1 })),
                "{} seed {seed:#x}",
                case.name
            );
            let (_, report) = promoted(&outcome).unwrap();
            assert_eq!(report.generation, 2, "{} seed {seed:#x}", case.name);
            assert!(outcome.observations.iter().any(|observation| matches!(
                observation,
                Observation::Fenced {
                    fencing: Fencing::Lease,
                    lease_end: Some(_)
                }
            )));
        }
    }
}

#[test]
fn s4_a_promotion_before_fencing_is_refused_on_the_core() {
    for case in both(standby::s4()) {
        for seed in corpus() {
            let outcome = passing(&case, seed);
            for fencing in [Fencing::Lease, Fencing::OperatorStop] {
                assert!(
                    outcome
                        .observations
                        .contains(&Observation::PromotionRefused { fencing }),
                    "{} seed {seed:#x}",
                    case.name
                );
            }
            assert!(promoted(&outcome).is_none());
            assert!(!succeeded_in(&outcome, 2));
        }
    }
}

/// The seeds on which S6's damaged feed sends reach no standby leader: the
/// standby group has not elected yet when the primary feeds indices 3, 5
/// and 7, so the damaged sends are dropped unread and the resends arrive
/// intact. Their safety is still checked; that nothing is refused is
/// asserted, so the list stays exact. 0x1e: since karyos 4014992f the
/// election timeouts are drawn from the run seed, and on it the standby
/// elects after the primary fed index 7, over the feed (over the
/// replication it is refused).
const S6_UNREACHED: [(u64, bool); 1] = [(0x1e, false)];

#[test]
fn s6_damaged_sends_are_refused_before_they_apply_on_the_core() {
    for (replicated, case) in both(standby::s6()).into_iter().enumerate() {
        for seed in corpus() {
            let outcome = passing(&case, seed);
            let refused = outcome.observations.iter().any(|observation| {
                matches!(
                    observation,
                    Observation::FeedRefused { .. } | Observation::ReplicationRefused { .. }
                )
            });
            let reached = !S6_UNREACHED.contains(&(seed, replicated == 1));
            assert_eq!(
                refused, reached,
                "{} seed {seed:#x}: refused {refused}, the scenario reached {reached}",
                case.name
            );
            // Nothing damaged applied (the standby checks compare every
            // applied entry with the primary's), and the resends got
            // through.
            for node in STANDBY {
                assert_eq!(
                    verified(&outcome, node),
                    primary_commit(&outcome),
                    "{} node {node} seed {seed:#x}",
                    case.name
                );
            }
        }
    }
}

#[test]
fn s7_a_restarted_standby_resumes_from_its_verified_position_on_the_core() {
    for case in both(standby::s7()) {
        for seed in corpus() {
            let outcome = passing(&case, seed);
            for node in STANDBY {
                assert_eq!(
                    verified(&outcome, node),
                    primary_commit(&outcome),
                    "{} node {node} seed {seed:#x}",
                    case.name
                );
            }
        }
    }
}

// Following across two primary leader changes, forced by failure: the
// core has no leadership transfer (karyos#713).

/// The fixture's `s1_source_change` with each targeted handover replaced
/// by a crash of whichever primary server leads, the first crashed
/// server restarted before the second crash so that the primary keeps
/// its quorum.
fn forced_source_change() -> Case {
    let mut case = standby::s1_source_change();
    case.name = "S1 follow across primary leader changes forced by crashes".to_owned();
    case.schedule = vec![
        (60, Action::Leader(LeaderAction::Crash)),
        (110, Action::Leader(LeaderAction::RestartCrashed)),
        (160, Action::Leader(LeaderAction::Crash)),
        (210, Action::Leader(LeaderAction::RestartCrashed)),
    ];
    case
}

/// The primary servers that led, in order, one per term.
fn primary_leaders(observations: &[Observation]) -> Vec<(NodeId, u64)> {
    observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Leading { node, term } if PRIMARY.contains(node) => Some((*node, *term)),
            _ => None,
        })
        .collect()
}

/// Whether the record shows exactly two primary leader changes, each to
/// another server, each forced by a crash of the leader then, and every
/// standby server applying the primary's entries with no gap and no
/// duplicate up to the primary's commit.
fn followed_two_changes(observations: &[Observation]) -> Result<(), String> {
    let leaders = primary_leaders(observations);
    if leaders.len() != 3 {
        return Err(format!(
            "{} primary leaders, not 3: {leaders:?}",
            leaders.len()
        ));
    }
    for pair in leaders.windows(2) {
        let [(from, before), (to, after)] = pair else {
            unreachable!()
        };
        if from == to || after <= before {
            return Err(format!(
                "no change from {from} at {before} to {to} at {after}"
            ));
        }
    }
    let crashed: Vec<NodeId> = observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Triggered {
                what: "leader crash",
                node,
                ..
            } => Some(*node),
            _ => None,
        })
        .collect();
    let replaced: Vec<NodeId> = leaders[..2].iter().map(|(node, _)| *node).collect();
    if crashed != replaced {
        return Err(format!(
            "crashed {crashed:?}, leaders replaced {replaced:?}"
        ));
    }
    let commit = observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Commit { node, index, .. } if PRIMARY.contains(node) => Some(*index),
            _ => None,
        })
        .max()
        .ok_or("no primary commit")?;
    for standby in STANDBY {
        let applied: Vec<u64> = observations
            .iter()
            .filter_map(|observation| match observation {
                Observation::FeedApplied { node, index, .. } if *node == standby => Some(*index),
                _ => None,
            })
            .collect();
        let Some(&first) = applied.first() else {
            return Err(format!("standby {standby} applied nothing"));
        };
        for pair in applied.windows(2) {
            if pair[1] != pair[0] + 1 {
                return Err(format!("standby {standby}: {} after {}", pair[1], pair[0]));
            }
        }
        let last = applied[applied.len() - 1];
        if first != 1 || last != commit {
            return Err(format!(
                "standby {standby} applied {first} to {last}, the primary committed {commit}"
            ));
        }
    }
    Ok(())
}

#[test]
fn s1_the_standby_follows_two_forced_primary_leader_changes_on_the_core() {
    for case in both(forced_source_change()) {
        for seed in corpus() {
            let outcome = passing(&case, seed);
            assert_eq!(
                followed_two_changes(&outcome.observations),
                Ok(()),
                "{} seed {seed:#x}",
                case.name
            );
            assert!(promoted(&outcome).is_none());
        }
    }
}

/// A passing record of the forced source change on the core.
fn forced_record() -> Vec<Observation> {
    let observations = record(forced_source_change());
    assert_eq!(followed_two_changes(&observations), Ok(()));
    observations
}

fn standby_applied(observation: &Observation) -> bool {
    matches!(observation, Observation::FeedApplied { node, index, .. } if *node == STANDBY[0] && *index > 1)
}

#[test]
fn a_gap_in_what_the_standby_followed_is_caught_on_the_core() {
    let mut observations = forced_record();
    let at = position(&observations, standby_applied);
    observations.remove(at);
    assert!(followed_two_changes(&observations).is_err());
}

#[test]
fn a_duplicate_in_what_the_standby_followed_is_caught_on_the_core() {
    let mut observations = forced_record();
    let at = position(&observations, standby_applied);
    let again = observations[at].clone();
    observations.insert(at + 1, again);
    assert!(followed_two_changes(&observations).is_err());
}

#[test]
fn a_missing_leader_change_is_caught_on_the_core() {
    let mut observations = forced_record();
    let last = observations
        .iter()
        .rposition(|o| matches!(o, Observation::Leading { node, .. } if PRIMARY.contains(node)))
        .unwrap();
    observations.remove(last);
    assert!(followed_two_changes(&observations).is_err());
}

#[test]
fn a_change_to_the_same_leader_is_caught_on_the_core() {
    let mut observations = forced_record();
    let leaders = primary_leaders(&observations);
    let last = observations
        .iter()
        .rposition(|o| matches!(o, Observation::Leading { node, .. } if PRIMARY.contains(node)))
        .unwrap();
    let Observation::Leading { node, .. } = &mut observations[last] else {
        unreachable!()
    };
    *node = leaders[1].0;
    assert!(followed_two_changes(&observations).is_err());
}

// Each standby check catches its violation planted in a record of the
// custom core.

/// A passing record of `case` on the custom core.
fn record(case: Case) -> Vec<Observation> {
    let case = warmed(case);
    let outcome = passing(&case, CORPUS[0]);
    assert_eq!(check::standby(&outcome.observations, &STANDBY), Ok(()));
    outcome.observations
}

fn position(observations: &[Observation], what: impl Fn(&Observation) -> bool) -> usize {
    observations.iter().position(what).unwrap()
}

#[test]
fn a_standby_reply_before_a_promotion_is_caught_on_the_core() {
    let mut observations = record(standby::s1());
    let at = position(&observations, |o| matches!(o, Observation::Reply { .. }));
    let Observation::Reply { node, .. } = &mut observations[at] else {
        unreachable!()
    };
    *node = STANDBY[1];
    assert_eq!(
        check::standby(&observations, &STANDBY),
        Err(Violation::StandbyEffect { node: STANDBY[1] })
    );
}

#[test]
fn an_old_generation_reply_after_a_promotion_is_caught_on_the_core() {
    let mut observations = record(standby::s2());
    let from = position(&observations, |o| matches!(o, Observation::Promoted { .. }));
    let at = from
        + position(&observations[from..], |o| {
            matches!(o, Observation::Reply { generation: 2, .. })
        });
    let Observation::Reply {
        node, generation, ..
    } = &mut observations[at]
    else {
        unreachable!()
    };
    *generation = 1;
    let node = *node;
    assert_eq!(
        check::standby(&observations, &STANDBY),
        Err(Violation::OldGenerationReply {
            node,
            generation: 1
        })
    );
}

#[test]
fn a_primary_reply_after_the_fencing_point_is_caught_on_the_core() {
    let mut observations = record(standby::s2());
    let fenced = position(&observations, |o| matches!(o, Observation::Fenced { .. }));
    let reply = position(
        &observations,
        |o| matches!(o, Observation::Reply { node, .. } if PRIMARY.contains(node)),
    );
    let late = observations[reply].clone();
    observations.insert(fenced + 1, late);
    assert!(matches!(
        check::standby(&observations, &STANDBY),
        Err(Violation::ReplyAfterFencing { .. })
    ));
}

#[test]
fn a_standby_entry_other_than_the_primarys_is_caught_on_the_core() {
    let mut observations = record(standby::s1());
    let at = position(
        &observations,
        |o| matches!(o, Observation::FeedApplied { payload, .. } if !payload.is_empty()),
    );
    let Observation::FeedApplied {
        node,
        index,
        payload,
        ..
    } = &mut observations[at]
    else {
        unreachable!()
    };
    payload[0] ^= 0xFF;
    let (node, index) = (*node, *index);
    assert_eq!(
        check::standby(&observations, &STANDBY),
        Err(Violation::FeedMismatch { node, index })
    );
}

#[test]
fn a_verified_position_the_standby_did_not_apply_is_caught_on_the_core() {
    let mut observations = record(standby::s2());
    let (node, report) = observations
        .iter()
        .find_map(|o| match o {
            Observation::Promoted { node, report } => Some((*node, report.clone())),
            _ => None,
        })
        .unwrap();
    let verified = report.verified.unwrap();
    observations.retain(|o| {
        !matches!(o, Observation::FeedApplied { node: at, index, .. }
            if *at == node && *index == verified)
    });
    assert_eq!(
        check::standby(&observations, &STANDBY),
        Err(Violation::VerifiedLost {
            node,
            index: verified
        })
    );
}

#[test]
fn an_overstated_gap_report_is_caught_on_the_core() {
    let mut observations = record(standby::s2());
    let at = position(&observations, |o| matches!(o, Observation::Promoted { .. }));
    let commit = observations
        .iter()
        .filter_map(|o| match o {
            Observation::Commit { node, index, .. } if PRIMARY.contains(node) => Some(*index),
            _ => None,
        })
        .max();
    let Observation::Promoted { report, .. } = &mut observations[at] else {
        unreachable!()
    };
    report.learnt_commit = commit.map(|index| index + 1);
    assert!(matches!(
        check::standby(&observations, &STANDBY),
        Err(Violation::GapMisreported { .. })
    ));
}

#[test]
fn a_client_accepting_a_lower_generation_is_caught_on_the_core() {
    let mut observations = record(standby::s2());
    let first = position(&observations, |o| {
        matches!(o, Observation::Success { generation: 2, .. })
    });
    let Observation::Success { client, .. } = observations[first] else {
        unreachable!()
    };
    let later = first
        + 1
        + position(
            &observations[first + 1..],
            |o| matches!(o, Observation::Success { client: c, .. } if *c == client),
        );
    let Observation::Success { generation, .. } = &mut observations[later] else {
        unreachable!()
    };
    *generation = 1;
    assert_eq!(
        check::standby(&observations, &STANDBY),
        Err(Violation::GenerationBack {
            client,
            generation: 1,
            seen: 2
        })
    );
}

// The results, per scenario, on the core and on the fixture, apart.

/// What `case` gave on core `C` over the corpus: `Ok` with the liveness
/// it ended with when every seed passed, the first failure otherwise.
fn result<C: ConsensusCore>(case: &Case) -> Result<Option<Liveness>, String> {
    let mut last = None;
    for seed in corpus() {
        let outcome = match workloads::run::<C>(case, seed) {
            Ok(outcome) => outcome,
            Err(RunError::Unsupported(_)) => return Err("unsupported".to_owned()),
            Err(error) => return Err(format!("seed {seed:#x}: {error:?}")),
        };
        last = workloads::pass(case, &outcome)
            .map_err(|failed| format!("seed {seed:#x}: {failed:?}"))?;
    }
    Ok(last)
}

#[test]
fn p5_s2_results_on_the_core_and_on_the_fixture() {
    let mut cases = standby::cases();
    cases.extend(standby::replicated_cases());
    for case in cases {
        let fixture = result::<Reference>(&case);
        let core = result::<Custom>(&warmed(case.clone()));
        assert!(fixture.is_ok(), "{}: fixture {fixture:?}", case.name);
        assert_eq!(core, fixture, "{}", case.name);
    }
    // The targeted leadership handover the fixture drives is not one the
    // custom core offers (it has no transfer API): on the core the same
    // two leader changes are forced by crashes instead.
    let handover = standby::over_replication(standby::s1_source_change());
    assert!(result::<Reference>(&handover).is_ok());
    assert_eq!(
        result::<Custom>(&warmed(handover)),
        Err("unsupported".to_owned())
    );
    for forced in both(forced_source_change()) {
        let core = result::<Custom>(&forced);
        assert!(core.is_ok(), "{}: core {core:?}", forced.name);
    }
}
