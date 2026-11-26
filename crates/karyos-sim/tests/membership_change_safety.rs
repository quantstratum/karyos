// SPDX-License-Identifier: Apache-2.0

//! The SPEC §13 "Membership change safety" contract row (ADR-0054;
//! karyos#718), phase 5: its named test is
//! [`test_cluster_membership_change_safety`], on the custom Raft core
//! (ADR-0105) with elections, over a fixed corpus of seeds plus
//! `scenarios::seeds()`.
//!
//! The row's scenarios, each its own case:
//!
//! - members added and removed during partitions and leader crashes: M2
//!   (a follower, then the leader removed), M3 (an addition and a removal
//!   under a partition), M4 (a leader crash at each reach of a change,
//!   under each crash mode) and M6 (every voter replaced under load and
//!   crashes);
//! - a learner promoted while lagging: M5;
//! - a standby promoted while a partitioned old primary keeps its quorum
//!   and clients still reach it: S3 over the Cluster log replication
//!   (ADR-0120), the primary cut from the standby and the arbiter, its
//!   three servers together, client 1 staying on it.
//!
//! The pass conditions, in the row's order:
//!
//! - every safety check of the harness holds (no two leaders commit in
//!   one term, across every configuration; within a generation no
//!   committed entry is lost; a linearizable history), and the scenario
//!   ends as it expects;
//! - the lagging learner is not promoted: `ChangeRefused::Lagging`, then
//!   promoted once caught up;
//! - for the promotion, in order: verified fencing first (the arbiter saw
//!   the lease expired before the promotion); every entry up to the
//!   standby's verified position kept; the unknown interval (with its
//!   lower bound) and every request in flight reported; the old
//!   generation refused (no client success from it after the fencing
//!   point, no old-primary reply at or past the lease's end, and no client
//!   that saw the new generation accepting the old one).
//!
//! Each condition has a mutant it catches, planted in a record of the
//! core that passed. The test needs no authenticated profile (owner items
//! 5 and 36): `karyos-sim`'s default features, no credentials.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::BTreeMap;

use karyos_cluster::standby::TailBound;
use karyos_sim::harness::check::{self, Violation};
use karyos_sim::harness::core::{Change, ChangeRefused};
use karyos_sim::harness::custom::{Custom, PROMOTION_LAG};
use karyos_sim::harness::membership::{self, SPARE};
use karyos_sim::harness::node::{Observation, SEAL_TICKS};
use karyos_sim::harness::standby::{self, Fencing, PRIMARY, STANDBY};
use karyos_sim::harness::workloads::{self, Case, Liveness, Outcome};
use karyos_sim::net::NodeId;
use karyos_sim::scenarios;

/// Seeds every scenario runs besides `scenarios::seeds()`.
const CORPUS: [u64; 4] = [0x05, 0x0054, 0xDEAD_BEEF, u64::MAX];

fn corpus() -> Vec<u64> {
    let mut seeds = CORPUS.to_vec();
    seeds.extend(scenarios::seeds());
    seeds
}

/// `case`'s schedule after the warm-up in which this core elects its
/// leaders (P5-S1's and P5-S2's fixed-leader schedules).
fn warmed(mut case: Case) -> Case {
    for (step, _) in &mut case.schedule {
        *step += membership::SETTLED;
    }
    case.steps += membership::SETTLED;
    case
}

/// A pass condition the row names, broken.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Breach {
    /// A safety check of the harness: two leaders in a term, a committed
    /// entry lost, a history that does not linearize.
    Safety(Box<Violation>),
    /// The scenario did not end as it expects.
    Ended(String),
    /// The lagging learner was promoted, or not refused as lagging.
    LaggingPromoted,
    /// The promotion came before verified fencing, or without it.
    NotFencedFirst,
    /// An entry at or below the verified position is missing on the
    /// promoted standby, or is not the primary's.
    VerifiedEntryLost(u64),
    /// The unknown interval or a request in flight is not reported.
    UnknownNotReported,
    /// An old-generation answer was taken after the fencing point.
    OldGenerationServed,
    /// The old primary did not keep its quorum, or its client never
    /// reached it after the cut.
    OldPrimaryNotServing,
}

/// The harness's safety checks, recomputed from the record (not the
/// run's own verdict), so a planted mutant is judged.
fn safety(case: &Case, outcome: &Outcome) -> Result<(), Breach> {
    check::all(&outcome.observations, &outcome.history, case.servers)
        .map_err(|violation| Breach::Safety(Box::new(violation)))?;
    check::membership(&outcome.observations, case.promotion_lag)
        .map_err(|violation| Breach::Safety(Box::new(violation)))
}

/// Adds and removes under partitions and leader crashes.
fn membership_conditions(case: &Case, outcome: &Outcome) -> Result<(), Breach> {
    safety(case, outcome)?;
    match workloads::pass(case, outcome) {
        Ok(None) => Ok(()),
        other => Err(Breach::Ended(format!("{other:?}"))),
    }
}

/// The answers to promoting the spare, a non-leader's refusals aside.
fn promotions(outcome: &Outcome) -> Vec<Result<(), ChangeRefused>> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Change {
                change: Change::Promote(SPARE),
                result,
                ..
            } if !matches!(result, Err(ChangeRefused::NotLeader(_))) => Some(*result),
            _ => None,
        })
        .collect()
}

/// A learner promoted while lagging.
fn lagging_conditions(case: &Case, outcome: &Outcome) -> Result<(), Breach> {
    membership_conditions(case, outcome)?;
    match promotions(outcome).as_slice() {
        [Err(ChangeRefused::Lagging { behind }), Ok(())] if *behind > PROMOTION_LAG => Ok(()),
        _ => Err(Breach::LaggingPromoted),
    }
}

/// The client S3 keeps on the old primary: clients are numbered after
/// the primary's and the standby's servers.
const ON_OLD_PRIMARY: NodeId = 7;

/// A standby promoted while a partitioned old primary keeps its quorum:
/// the four conditions, in order.
fn promotion_conditions(case: &Case, outcome: &Outcome) -> Result<(), Breach> {
    let observations = &outcome.observations;
    check::group(&check::of_servers(observations, &PRIMARY), case.servers)
        .map_err(|violation| Breach::Safety(Box::new(violation)))?;
    check::group(&check::of_servers(observations, &STANDBY), case.standby)
        .map_err(|violation| Breach::Safety(Box::new(violation)))?;
    check::linearizable(&check::across_promotion(&outcome.history, observations))
        .map_err(|violation| Breach::Safety(Box::new(violation)))?;
    // Client 1 stays on the old primary, which never answers it again.
    if workloads::pass(case, outcome) != Ok(Some(Liveness::Stalled { waiting: 1 })) {
        return Err(Breach::Ended(format!(
            "{:?}",
            workloads::pass(case, outcome)
        )));
    }
    // The old primary keeps its quorum after the cut: its three servers
    // on one side of the partition, a leader of it commits past what it
    // had committed at the cut, and its client still reaches it with an
    // answer to such an entry.
    let split = observations
        .iter()
        .position(|observation| {
            matches!(observation, Observation::Split { left, .. }
                if PRIMARY.iter().all(|node| left.contains(node)))
        })
        .ok_or(Breach::OldPrimaryNotServing)?;
    let committed_at_split = observations[..split]
        .iter()
        .filter_map(|observation| match observation {
            Observation::Commit { node, index, .. } if PRIMARY.contains(node) => Some(*index),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    let after = &observations[split..];
    let primary_commits = after.iter().any(|observation| {
        matches!(observation, Observation::Commit { node, leader: true, index, .. }
            if PRIMARY.contains(node) && *index > committed_at_split)
    });
    let reached = after.iter().any(|observation| {
        matches!(observation, Observation::Reply { node, client, index, .. }
            if PRIMARY.contains(node) && *client == ON_OLD_PRIMARY && *index > committed_at_split)
    });
    if !primary_commits || !reached {
        return Err(Breach::OldPrimaryNotServing);
    }
    let cut = observations
        .iter()
        .position(|observation| matches!(observation, Observation::Fenced { .. }))
        .ok_or(Breach::NotFencedFirst)?;

    // 1. Verified fencing first.
    let promoted_at = observations
        .iter()
        .position(|observation| matches!(observation, Observation::Promoted { .. }))
        .ok_or(Breach::NotFencedFirst)?;
    let lease_end = match &observations[cut] {
        Observation::Fenced {
            fencing: Fencing::Lease,
            lease_end: Some(end),
        } => *end,
        _ => return Err(Breach::NotFencedFirst),
    };
    if cut > promoted_at {
        return Err(Breach::NotFencedFirst);
    }
    let Observation::Promoted { node, report } = &observations[promoted_at] else {
        unreachable!()
    };

    // 2. Every entry up to the verified position kept: the promoted
    //    standby applied each, the primary's own.
    let primary_applied: BTreeMap<u64, &[u8]> = observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Applied { node, entry, .. } if PRIMARY.contains(node) => {
                Some((entry.index, entry.payload.as_slice()))
            }
            _ => None,
        })
        .collect();
    let fed: BTreeMap<u64, &[u8]> = observations[..promoted_at]
        .iter()
        .filter_map(|observation| match observation {
            Observation::FeedApplied {
                node: at,
                index,
                payload,
                ..
            } if at == node => Some((*index, payload.as_slice())),
            _ => None,
        })
        .collect();
    let verified = report.verified.ok_or(Breach::VerifiedEntryLost(0))?;
    for index in standby::PRIMARY_FIRST_INDEX..=verified {
        if !fed.contains_key(&index) || fed.get(&index) != primary_applied.get(&index) {
            return Err(Breach::VerifiedEntryLost(index));
        }
    }

    // 3. The unknown interval, with its lower bound, and every request in
    //    flight reported.
    let follower = report
        .replication
        .as_ref()
        .ok_or(Breach::UnknownNotReported)?;
    let in_flight = report
        .unknown
        .iter()
        .any(|&(client, _)| client == ON_OLD_PRIMARY);
    let listed: Vec<(u64, u64)> = follower
        .unknown
        .iter()
        .map(|flight| (flight.client, flight.sequence))
        .collect();
    let mut unknown: Vec<(u64, u64)> = report
        .unknown
        .iter()
        .map(|&(client, sequence)| (u64::from(client), sequence))
        .collect();
    unknown.sort_unstable();
    if report.learnt_commit.is_none_or(|learnt| learnt < verified)
        || !in_flight
        || listed != unknown
        || follower.verified.map(|position| position.index) != Some(verified)
    {
        return Err(Breach::UnknownNotReported);
    }
    // The follower's gap: the sealed bytes it has not verified, known once
    // its verified position is mapped into the copy, and exactly those (a
    // lower bound is never above the true gap), plus the unsealed tail
    // within the configured seal interval.
    let copy = follower.copy.as_ref().ok_or(Breach::UnknownNotReported)?;
    let sealed_gap = match (copy.verified, follower.gap.sealed_unverified) {
        (Some(at), Some(gap)) => gap == copy.sealed.unwrap_or(copy.checked).saturating_sub(at),
        (None, None) => true,
        _ => false,
    };
    if !sealed_gap || follower.gap.unsealed_tail != TailBound::Interval(SEAL_TICKS) {
        return Err(Breach::UnknownNotReported);
    }

    // 4. The old generation refused after the fencing point.
    let old_reply = observations.iter().any(|observation| {
        matches!(observation, Observation::Reply { node, at, .. }
            if PRIMARY.contains(node) && *at >= lease_end)
    });
    let old_success = observations[cut..]
        .iter()
        .any(|observation| matches!(observation, Observation::Success { generation, .. } if *generation < report.generation));
    if old_reply || old_success {
        return Err(Breach::OldGenerationServed);
    }
    check::standby(observations, &STANDBY).map_err(|violation| Breach::Safety(Box::new(violation)))
}

/// The row's scenarios of adds and removes, with the seed each runs.
fn adds_and_removes() -> Vec<(Case, u64)> {
    let mut cases = Vec::new();
    for seed in corpus() {
        cases.push((membership::m2(), seed));
        cases.push((membership::m3(false), seed));
        cases.push((membership::m3(true), seed));
        cases.push((membership::m6(seed), seed));
        cases.extend(
            membership::m4_cases(seed)
                .into_iter()
                .map(|case| (case, seed)),
        );
    }
    cases
}

fn lagging() -> Case {
    warmed(membership::m5())
}

fn partitioned_old_primary() -> Case {
    warmed(standby::over_replication(standby::s3()))
}

fn run(case: &Case, seed: u64) -> Outcome {
    workloads::run::<Custom>(case, seed).unwrap()
}

/// The row's named test (SPEC.md §13, "Membership change safety").
#[test]
fn test_cluster_membership_change_safety() {
    for (case, seed) in adds_and_removes() {
        let outcome = run(&case, seed);
        assert_eq!(
            membership_conditions(&case, &outcome),
            Ok(()),
            "{} seed {seed:#x}",
            case.name
        );
    }
    let case = lagging();
    for seed in corpus() {
        let outcome = run(&case, seed);
        assert_eq!(
            lagging_conditions(&case, &outcome),
            Ok(()),
            "{} seed {seed:#x}",
            case.name
        );
    }
    let case = partitioned_old_primary();
    for seed in corpus() {
        let outcome = run(&case, seed);
        assert_eq!(
            promotion_conditions(&case, &outcome),
            Ok(()),
            "{} seed {seed:#x}",
            case.name
        );
    }
}

// Each condition catches its mutant, planted in a record of the core.

/// A passing record of the partitioned-old-primary case.
fn promotion_record() -> (Case, Outcome) {
    let case = partitioned_old_primary();
    let outcome = run(&case, CORPUS[0]);
    assert_eq!(promotion_conditions(&case, &outcome), Ok(()));
    (case, outcome)
}

fn at(outcome: &Outcome, what: impl Fn(&Observation) -> bool) -> usize {
    outcome.observations.iter().position(what).unwrap()
}

#[test]
fn test_cluster_membership_change_safety_catches_two_leaders_in_a_term() {
    let case = membership::m3(false);
    let mut outcome = run(&case, CORPUS[0]);
    assert_eq!(membership_conditions(&case, &outcome), Ok(()));
    let (leader, term) = outcome
        .observations
        .iter()
        .find_map(|observation| match observation {
            Observation::Leading { node, term } => Some((*node, *term)),
            _ => None,
        })
        .unwrap();
    let other = (leader + 1) % 5;
    outcome
        .observations
        .push(Observation::Leading { node: other, term });
    assert!(matches!(
        membership_conditions(&case, &outcome),
        Err(Breach::Safety(violation)) if matches!(*violation, Violation::TwoLeaders { .. })
    ));
}

/// The early promotion's refusal in `outcome`.
fn early_refusal(outcome: &Outcome) -> usize {
    at(outcome, |observation| {
        matches!(
            observation,
            Observation::Change {
                change: Change::Promote(SPARE),
                result: Err(ChangeRefused::Lagging { .. }),
                ..
            }
        )
    })
}

#[test]
fn test_cluster_membership_change_safety_catches_a_lagging_promotion() {
    let case = lagging();
    let mut outcome = run(&case, CORPUS[0]);
    assert_eq!(lagging_conditions(&case, &outcome), Ok(()));
    let early = early_refusal(&outcome);
    let Observation::Change { result, .. } = &mut outcome.observations[early] else {
        unreachable!()
    };
    *result = Ok(());
    // The harness's own check names it first.
    assert!(matches!(
        lagging_conditions(&case, &outcome),
        Err(Breach::Safety(violation)) if matches!(*violation, Violation::LearnerBehind { .. })
    ));
}

#[test]
fn test_cluster_membership_change_safety_catches_a_missing_lagging_refusal() {
    let case = lagging();
    let mut outcome = run(&case, CORPUS[0]);
    let early = early_refusal(&outcome);
    let _ = outcome.observations.remove(early);
    assert_eq!(
        lagging_conditions(&case, &outcome),
        Err(Breach::LaggingPromoted)
    );
}

#[test]
fn test_cluster_membership_change_safety_catches_a_promotion_before_fencing() {
    let (case, mut outcome) = promotion_record();
    let fenced = at(&outcome, |o| matches!(o, Observation::Fenced { .. }));
    let promoted = at(&outcome, |o| matches!(o, Observation::Promoted { .. }));
    let promotion = outcome.observations.remove(promoted);
    outcome.observations.insert(fenced, promotion);
    assert_eq!(
        promotion_conditions(&case, &outcome),
        Err(Breach::NotFencedFirst)
    );
}

#[test]
fn test_cluster_membership_change_safety_catches_a_lost_verified_entry() {
    let (case, mut outcome) = promotion_record();
    let promoted = at(&outcome, |o| matches!(o, Observation::Promoted { .. }));
    let Observation::Promoted { node, report } = outcome.observations[promoted].clone() else {
        unreachable!()
    };
    let verified = report.verified.unwrap();
    outcome.observations.retain(|o| {
        !matches!(o, Observation::FeedApplied { node: n, index, .. } if *n == node && *index == verified)
    });
    assert_eq!(
        promotion_conditions(&case, &outcome),
        Err(Breach::VerifiedEntryLost(verified))
    );
}

#[test]
fn test_cluster_membership_change_safety_catches_an_unreported_request_in_flight() {
    let (case, mut outcome) = promotion_record();
    let promoted = at(&outcome, |o| matches!(o, Observation::Promoted { .. }));
    let Observation::Promoted { report, .. } = &mut outcome.observations[promoted] else {
        unreachable!()
    };
    report
        .unknown
        .retain(|&(client, _)| client != ON_OLD_PRIMARY);
    assert_eq!(
        promotion_conditions(&case, &outcome),
        Err(Breach::UnknownNotReported)
    );
}

#[test]
fn test_cluster_membership_change_safety_catches_an_unreported_interval() {
    let (case, mut outcome) = promotion_record();
    let promoted = at(&outcome, |o| matches!(o, Observation::Promoted { .. }));
    let Observation::Promoted { report, .. } = &mut outcome.observations[promoted] else {
        unreachable!()
    };
    report.learnt_commit = None;
    assert_eq!(
        promotion_conditions(&case, &outcome),
        Err(Breach::UnknownNotReported)
    );
}

#[test]
fn test_cluster_membership_change_safety_catches_an_old_generation_success() {
    let (case, mut outcome) = promotion_record();
    let fenced = at(&outcome, |o| matches!(o, Observation::Fenced { .. }));
    outcome.observations.insert(
        fenced + 1,
        Observation::Success {
            client: ON_OLD_PRIMARY,
            index: 1,
            generation: 1,
        },
    );
    assert_eq!(
        promotion_conditions(&case, &outcome),
        Err(Breach::OldGenerationServed)
    );
}

#[test]
fn test_cluster_membership_change_safety_catches_an_old_primary_reply_past_the_lease() {
    let (case, mut outcome) = promotion_record();
    let reply = at(
        &outcome,
        |o| matches!(o, Observation::Reply { node, .. } if PRIMARY.contains(node)),
    );
    let lease_end = outcome
        .observations
        .iter()
        .find_map(|o| match o {
            Observation::Fenced { lease_end, .. } => *lease_end,
            _ => None,
        })
        .unwrap();
    let mut late = outcome.observations[reply].clone();
    let Observation::Reply { at: when, .. } = &mut late else {
        unreachable!()
    };
    *when = lease_end;
    outcome.observations.push(late);
    assert_eq!(
        promotion_conditions(&case, &outcome),
        Err(Breach::OldGenerationServed)
    );
}

#[test]
fn test_cluster_membership_change_safety_catches_an_old_primary_cut_off_from_its_client() {
    let (case, mut outcome) = promotion_record();
    outcome.observations.retain(|o| {
        !matches!(o, Observation::Reply { node, client, .. }
            if PRIMARY.contains(node) && *client == ON_OLD_PRIMARY)
    });
    assert_eq!(
        promotion_conditions(&case, &outcome),
        Err(Breach::OldPrimaryNotServing)
    );
}

#[test]
fn test_cluster_membership_change_safety_catches_an_old_primary_that_stops_committing_at_the_cut() {
    let (case, mut outcome) = promotion_record();
    let split = at(&outcome, |o| matches!(o, Observation::Split { .. }));
    let mut index = 0;
    outcome.observations.retain(|o| {
        index += 1;
        index <= split + 1
            || !matches!(o, Observation::Commit { node, leader: true, .. } if PRIMARY.contains(node))
    });
    assert_eq!(
        promotion_conditions(&case, &outcome),
        Err(Breach::OldPrimaryNotServing)
    );
}

#[test]
fn test_cluster_membership_change_safety_catches_an_overstated_replication_gap() {
    let (case, mut outcome) = promotion_record();
    let promoted = at(&outcome, |o| matches!(o, Observation::Promoted { .. }));
    let Observation::Promoted { report, .. } = &mut outcome.observations[promoted] else {
        unreachable!()
    };
    report.replication.as_mut().unwrap().gap.sealed_unverified = Some(u64::MAX);
    assert_eq!(
        promotion_conditions(&case, &outcome),
        Err(Breach::UnknownNotReported)
    );
}

#[test]
fn test_cluster_membership_change_safety_catches_a_wrong_unsealed_tail_bound() {
    let (case, mut outcome) = promotion_record();
    let promoted = at(&outcome, |o| matches!(o, Observation::Promoted { .. }));
    let Observation::Promoted { report, .. } = &mut outcome.observations[promoted] else {
        unreachable!()
    };
    report.replication.as_mut().unwrap().gap.unsealed_tail = TailBound::Interval(SEAL_TICKS - 1);
    assert_eq!(
        promotion_conditions(&case, &outcome),
        Err(Breach::UnknownNotReported)
    );
}
