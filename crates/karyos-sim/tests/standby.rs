// SPDX-License-Identifier: Apache-2.0

//! A standby cluster over the harness (quantstratum-docs:
//! karyos/design/phase-5-cluster-scenarios.md, P5-S2), with the reference
//! core in both groups, over a fixed corpus of seeds plus
//! `scenarios::seeds()`:
//!
//! - S1: the standby follows, effects disabled, and verifies the
//!   primary's commit;
//! - S2: after an operator stop, the standby is promoted; the verified
//!   prefix survives, the rest is reported, clients continue on it;
//! - S3: after the lease expired, the old primary alive and partitioned,
//!   the standby is promoted and no old-generation reply follows;
//! - S4: promotions before fencing are refused;
//! - S5: a client rejects a lower generation once it has seen a higher;
//! - S6: damaged feed sends are refused before they apply;
//! - S7: a restarted standby resumes from its verified position;
//! - each standby check catches its violation in a hand-built record, and
//!   the history across a promotion leaves an unknown outcome pending;
//! - S1 to S4, S6 and S7 again over the Cluster log replication (ADR-0120,
//!   karyos#714), the feed's runs their control: S6's damage applied to
//!   the bytes in transit, S7's restarted standby leader rebuilding its
//!   verified position from its own log, and a primary leader change
//!   starting a new copy;
//! - S2 and S5 again with the Cluster client's failover (karyos#720): a
//!   client reaching the old primary and the promoted standby, no command
//!   applied twice, an unknown request retried only by its caller, and
//!   generation 1 refused once generation 2 is seen.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use karyos_cluster::client::Event;
use karyos_cluster::standby::{RecoveryPoint, Refusal};
use karyos_sim::cluster::Node;
use karyos_sim::harness::check::{self, Violation};
use karyos_sim::harness::node::{
    ClientNode, Command, Observation, Op, Recorder, Ret, Shared, Wire,
};
use karyos_sim::harness::reference::{Message, Reference};
use karyos_sim::harness::standby::{
    self, ExternalLease, FeedRefusal, Fencing, PRIMARY, PromotionReport, STANDBY,
};
use karyos_sim::harness::workloads::{self, Case, Liveness, Outcome};
use karyos_sim::lin::History;
use karyos_sim::net::NodeId;
use karyos_sim::scenarios;

/// Seeds every scenario runs besides `scenarios::seeds()`.
const CORPUS: [u64; 4] = [0x55, 0x0054, 0xDEAD_BEEF, u64::MAX];

fn corpus() -> Vec<u64> {
    let mut seeds = CORPUS.to_vec();
    seeds.extend(scenarios::seeds());
    seeds
}

fn passing(case: &Case, seed: u64) -> Outcome {
    let outcome = workloads::run::<Reference>(case, seed).unwrap();
    assert_eq!(
        workloads::pass(case, &outcome),
        Ok(None),
        "{} seed {seed:#x}",
        case.name
    );
    outcome
}

/// The highest primary index `node` applied from the feed.
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

#[test]
fn wrapped_entries_and_checksums_round_trip() {
    let wrapped = standby::wrap(7, 2, b"payload");
    assert_eq!(standby::unwrap(&wrapped), Some((7, 2, &b"payload"[..])));
    assert_eq!(standby::unwrap(b"KC5\x01"), None);
    let sum = standby::checksum(7, 2, b"payload");
    assert_ne!(sum, standby::checksum(8, 2, b"payload"));
    assert_ne!(sum, standby::checksum(7, 3, b"payload"));
    assert_ne!(sum, standby::checksum(7, 2, b"paylaod"));
}

#[test]
fn a_lease_is_held_until_its_end_and_expired_past_the_margin() {
    let mut lease = ExternalLease::new(10);
    assert!(!lease.held_at(0));
    lease.renewed_at = Some(5);
    assert!(lease.held_at(14));
    assert!(!lease.held_at(15));
    // Renewing: never expired for the arbiter.
    assert!(!lease.expired_at(1000, 2));
    lease.renewing = false;
    assert!(!lease.expired_at(17, 2));
    assert!(lease.expired_at(18, 2));
}

#[test]
fn s1_the_standby_follows_with_effects_disabled() {
    let case = standby::s1();
    for seed in corpus() {
        let outcome = passing(&case, seed);
        assert_eq!(
            verified(&outcome, STANDBY[0]),
            primary_commit(&outcome),
            "seed {seed:#x}"
        );
        // Its followers apply the same entries.
        assert_eq!(
            verified(&outcome, STANDBY[1]),
            verified(&outcome, STANDBY[0])
        );
        assert!(promoted(&outcome).is_none());
    }
}

#[test]
fn s2_an_operator_stop_then_a_promotion() {
    let case = standby::s2();
    for seed in corpus() {
        let outcome = passing(&case, seed);
        let (node, report) = promoted(&outcome).unwrap();
        assert_eq!(node, STANDBY[0]);
        assert_eq!(report.generation, 2);
        assert!(report.verified <= report.learnt_commit);
        assert!(outcome.observations.iter().any(|observation| matches!(
            observation,
            Observation::Fenced {
                fencing: Fencing::OperatorStop,
                lease_end: None
            }
        )));
        // The clients finished on the standby, in generation 2.
        assert!(
            outcome.observations.iter().any(|observation| matches!(
                observation,
                Observation::Success { generation: 2, .. }
            ))
        );
    }
}

#[test]
fn s3_a_lease_expiry_then_a_promotion_with_the_old_primary_alive() {
    let case = standby::s3();
    for seed in corpus() {
        let outcome = workloads::run::<Reference>(&case, seed).unwrap();
        // Client 1 stays on the old primary, which never answers it again.
        assert_eq!(
            workloads::pass(&case, &outcome),
            Ok(Some(Liveness::Stalled { waiting: 1 })),
            "seed {seed:#x}"
        );
        let (_, report) = promoted(&outcome).unwrap();
        assert_eq!(report.generation, 2, "seed {seed:#x}");
        assert!(outcome.observations.iter().any(|observation| matches!(
            observation,
            Observation::Fenced {
                fencing: Fencing::Lease,
                lease_end: Some(_)
            }
        )));
    }
}

#[test]
fn s4_a_promotion_before_fencing_is_refused() {
    let case = standby::s4();
    for seed in corpus() {
        let outcome = passing(&case, seed);
        for fencing in [Fencing::Lease, Fencing::OperatorStop] {
            assert!(
                outcome
                    .observations
                    .contains(&Observation::PromotionRefused { fencing }),
                "seed {seed:#x}"
            );
        }
        assert!(promoted(&outcome).is_none());
        assert!(
            !outcome.observations.iter().any(|observation| matches!(
                observation,
                Observation::Success { generation: 2, .. }
            ))
        );
    }
}

#[test]
fn s5_a_client_rejects_a_lower_generation_once_it_saw_a_higher() {
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    let script = vec![Op::Append(vec![1]), Op::Append(vec![2])];
    let mut client = ClientNode::new(10, 0, script, Rc::clone(&recorder));
    let mut out: Vec<(NodeId, Wire<Message>)> = Vec::new();
    let answer = |sequence: u64, generation: u64| Wire::<Message>::Response {
        sequence,
        bytes: Ret::Appended(sequence).canonical(),
        index: sequence,
        generation,
    };
    client.tick(0, &mut out);
    client.deliver(3, answer(1, 2), 1, &mut out);
    client.tick(2, &mut out);
    assert_eq!(client.open(), Some(2));
    // The old generation's answer to the open request is rejected.
    client.deliver(0, answer(2, 1), 3, &mut out);
    assert_eq!(client.open(), Some(2));
    client.deliver(3, answer(2, 2), 4, &mut out);
    assert!(client.done());
    let observations = &recorder.borrow().observations;
    assert!(observations.contains(&Observation::StaleGeneration {
        client: 10,
        generation: 1
    }));
    assert_eq!(check::standby(observations, &STANDBY), Ok(()));
}

#[test]
fn s6_damaged_feed_sends_are_refused_before_they_apply() {
    let case = standby::s6();
    for seed in corpus() {
        let outcome = passing(&case, seed);
        let refusals: Vec<(u64, FeedRefusal)> = outcome
            .observations
            .iter()
            .filter_map(|observation| match observation {
                Observation::FeedRefused { index, reason, .. } => Some((*index, *reason)),
                _ => None,
            })
            .collect();
        for (index, reason) in [
            (3, FeedRefusal::Checksum),
            (5, FeedRefusal::Checksum),
            (8, FeedRefusal::Gap),
        ] {
            assert!(
                refusals.contains(&(index, reason)),
                "seed {seed:#x}: {refusals:?}"
            );
        }
        // The resends got through.
        assert_eq!(verified(&outcome, STANDBY[0]), primary_commit(&outcome));
    }
}

#[test]
fn s7_a_restarted_standby_resumes_from_its_verified_position() {
    let case = standby::s7();
    for seed in corpus() {
        let outcome = passing(&case, seed);
        assert_eq!(
            verified(&outcome, STANDBY[0]),
            primary_commit(&outcome),
            "seed {seed:#x}"
        );
    }
}

// Hand-built records: each standby check catches its violation.

fn reply(node: NodeId, generation: u64) -> Observation {
    reply_at(node, generation, 0)
}

fn reply_at(node: NodeId, generation: u64, at: u64) -> Observation {
    Observation::Reply {
        node,
        client: 9,
        index: 1,
        term: 1,
        generation,
        at,
    }
}

fn promotion(verified: Option<u64>, learnt_commit: Option<u64>) -> Observation {
    Observation::Promoted {
        node: STANDBY[0],
        report: PromotionReport {
            generation: 2,
            verified,
            learnt_commit,
            unknown: Vec::new(),
            replication: None,
        },
    }
}

fn applied(node: NodeId, index: u64, payload: &[u8]) -> Observation {
    Observation::Applied {
        node,
        entry: karyos_cluster::Entry {
            index,
            term: 1,
            event_time: 0,
            payload: payload.to_vec(),
        },
        applying: karyos_sim::harness::core::Applying {
            durable: Some(index),
            logged_term: Some(1),
        },
        response: None,
    }
}

fn fed(index: u64, payload: &[u8]) -> Observation {
    Observation::FeedApplied {
        node: STANDBY[0],
        index,
        term: 1,
        payload: payload.to_vec(),
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
fn a_standby_reply_before_a_promotion_is_caught() {
    assert_eq!(
        check::standby(&[reply(STANDBY[0], 1)], &STANDBY),
        Err(Violation::StandbyEffect { node: STANDBY[0] })
    );
    assert_eq!(
        check::standby(
            &[commit(0, 1), promotion(None, Some(1)), reply(STANDBY[0], 2)],
            &STANDBY
        ),
        Ok(())
    );
}

#[test]
fn an_old_generation_reply_after_a_promotion_is_caught() {
    let record = [
        commit(0, 1),
        reply(0, 1),
        promotion(None, Some(1)),
        reply(0, 1),
    ];
    assert_eq!(
        check::standby(&record, &STANDBY),
        Err(Violation::OldGenerationReply {
            node: 0,
            generation: 1
        })
    );
    assert_eq!(check::standby(&record[..3], &STANDBY), Ok(()));
}

#[test]
fn a_reply_at_or_after_the_fencing_point_is_caught() {
    // The lease ended at 52 on the holder's clock; the promotion came
    // later. A reply at 52 broke the lease, one at 51 did not.
    let fenced = Observation::Fenced {
        fencing: Fencing::Lease,
        lease_end: Some(52),
    };
    let record = [
        commit(0, 1),
        reply_at(0, 1, 52),
        fenced.clone(),
        promotion(None, Some(1)),
    ];
    assert_eq!(
        check::standby(&record, &STANDBY),
        Err(Violation::ReplyAfterFencing {
            node: 0,
            at: 52,
            lease_end: Some(52)
        })
    );
    let before = [
        commit(0, 1),
        reply_at(0, 1, 51),
        fenced,
        promotion(None, Some(1)),
    ];
    assert_eq!(check::standby(&before, &STANDBY), Ok(()));
    // After an operator stop, no primary reply at all.
    let stopped = [
        commit(0, 1),
        Observation::Fenced {
            fencing: Fencing::OperatorStop,
            lease_end: None,
        },
        reply_at(0, 1, 0),
    ];
    assert!(matches!(
        check::standby(&stopped, &STANDBY),
        Err(Violation::ReplyAfterFencing { node: 0, .. })
    ));
}

#[test]
fn a_standby_entry_other_than_the_primarys_is_caught() {
    let record = [applied(0, 1, b"a"), fed(1, b"b")];
    assert_eq!(
        check::standby(&record, &STANDBY),
        Err(Violation::FeedMismatch {
            node: STANDBY[0],
            index: 1
        })
    );
    assert_eq!(
        check::standby(&[applied(0, 1, b"a"), fed(1, b"a")], &STANDBY),
        Ok(())
    );
}

#[test]
fn a_verified_position_the_standby_did_not_apply_is_caught() {
    let record = [
        applied(0, 1, b"a"),
        applied(0, 2, b"b"),
        commit(0, 2),
        fed(1, b"a"),
        promotion(Some(2), Some(2)),
    ];
    assert_eq!(
        check::standby(&record, &STANDBY),
        Err(Violation::VerifiedLost {
            node: STANDBY[0],
            index: 2
        })
    );
    let mut whole = record.to_vec();
    whole.insert(4, fed(2, b"b"));
    assert_eq!(check::standby(&whole, &STANDBY), Ok(()));
}

#[test]
fn an_overstated_gap_report_is_caught() {
    // A learnt commit beyond the primary's.
    assert!(matches!(
        check::standby(&[commit(0, 2), promotion(None, Some(3))], &STANDBY),
        Err(Violation::GapMisreported { .. })
    ));
    // A verified position beyond the learnt commit.
    assert!(matches!(
        check::standby(
            &[
                applied(0, 1, b"a"),
                commit(0, 2),
                fed(1, b"a"),
                promotion(Some(1), None)
            ],
            &STANDBY
        ),
        Err(Violation::GapMisreported { .. })
    ));
}

#[test]
fn a_client_accepting_a_lower_generation_is_caught() {
    let success = |generation| Observation::Success {
        client: 9,
        index: 1,
        generation,
    };
    assert_eq!(
        check::standby(&[success(2), success(1)], &STANDBY),
        Err(Violation::GenerationBack {
            client: 9,
            generation: 1,
            seen: 2
        })
    );
}

#[test]
fn an_old_answer_beyond_the_verified_position_is_left_pending() {
    // Client 9 appended at primary index 2 (generation 1), beyond the
    // standby's verified position 1, then read on the standby, which never
    // saw the append.
    let mut history: History<Op, Ret> = History::new();
    let _ = history
        .invoke(9, Op::Append(vec![1]))
        .ret(9, Ret::Appended(1))
        .invoke(9, Op::Append(vec![2]))
        .ret(9, Ret::Appended(2))
        .invoke(9, Op::Read)
        .ret(9, Ret::Values(vec![vec![1]]));
    let observations = [
        Observation::Success {
            client: 9,
            index: 1,
            generation: 1,
        },
        Observation::Success {
            client: 9,
            index: 2,
            generation: 1,
        },
        promotion(Some(1), Some(2)),
        Observation::Success {
            client: 9,
            index: 1,
            generation: 2,
        },
    ];
    assert!(matches!(
        check::linearizable(&history),
        Err(Violation::NotLinearizable(_))
    ));
    let across = check::across_promotion(&history, &observations);
    assert_eq!(check::linearizable(&across), Ok(()));
    // The append beyond the verified position is pending; the read went to
    // a fresh client id.
    assert_eq!(across.events().len(), 5);
}

// The same scenarios over the Cluster log replication (ADR-0120,
// karyos#714); the runs above, over the feed, are their control.

fn recovery_points(outcome: &Outcome) -> Vec<RecoveryPoint> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::RecoveryPoint { point, .. } => Some(*point),
            _ => None,
        })
        .collect()
}

fn replication_refusals(outcome: &Outcome) -> Vec<Refusal> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::ReplicationRefused { refusal, .. } => Some(refusal.clone()),
            _ => None,
        })
        .collect()
}

fn copy_sources(outcome: &Outcome) -> Vec<NodeId> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::CopyStarted { source, .. } => Some(*source),
            _ => None,
        })
        .collect()
}

#[test]
fn s1_over_replication_the_standby_follows_with_effects_disabled() {
    let case = standby::over_replication(standby::s1());
    for seed in corpus() {
        // `passing` runs the standby checks: no standby reply before a
        // promotion, every applied primary entry the primary's.
        let outcome = passing(&case, seed);
        assert_eq!(
            verified(&outcome, STANDBY[0]),
            primary_commit(&outcome),
            "seed {seed:#x}"
        );
        assert_eq!(
            verified(&outcome, STANDBY[1]),
            verified(&outcome, STANDBY[0])
        );
        assert!(promoted(&outcome).is_none());
        // No feed ran: the entries came over the replication.
        assert!(
            !outcome
                .observations
                .iter()
                .any(|observation| matches!(observation, Observation::FeedRefused { .. }))
        );
        assert!(!copy_sources(&outcome).is_empty(), "seed {seed:#x}");
        // The recovery point is reported continuously and is never zero:
        // behind while it lags (a non-zero count by its type), then at the
        // sealed end with the tail unknown.
        let points = recovery_points(&outcome);
        assert!(
            points
                .iter()
                .any(|point| matches!(point, RecoveryPoint::Behind { .. })),
            "seed {seed:#x}: {points:?}"
        );
        assert!(matches!(
            points.last(),
            Some(RecoveryPoint::AtSealedEnd { .. })
        ));
        assert!(replication_refusals(&outcome).is_empty(), "seed {seed:#x}");
    }
}

#[test]
fn s1_over_replication_a_new_primary_leader_is_a_new_copy() {
    let case = standby::over_replication(standby::s1_source_change());
    for seed in corpus() {
        let outcome = passing(&case, seed);
        let sources = copy_sources(&outcome);
        let mut distinct = sources.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert!(distinct.len() >= 2, "seed {seed:#x}: {sources:?}");
        assert!(distinct.iter().all(|source| PRIMARY.contains(source)));
        assert_eq!(
            verified(&outcome, STANDBY[0]),
            primary_commit(&outcome),
            "seed {seed:#x}"
        );
    }
}

#[test]
fn s2_over_replication_an_operator_stop_then_a_promotion() {
    let case = standby::over_replication(standby::s2());
    for seed in corpus() {
        let outcome = passing(&case, seed);
        let (node, report) = promoted(&outcome).unwrap();
        assert_eq!(node, STANDBY[0]);
        assert_eq!(report.generation, 2);
        assert!(report.verified <= report.learnt_commit);
        let follower = report.replication.clone().unwrap();
        assert_eq!(follower.generation, 2);
        assert_eq!(
            follower.verified.map(|position| position.index),
            report.verified
        );
        // Every request in flight is reported unknown, with its client and
        // sequence.
        let mut unknown: Vec<(u64, u64)> = report
            .unknown
            .iter()
            .map(|&(client, sequence)| (u64::from(client), sequence))
            .collect();
        unknown.sort_unstable();
        let listed: Vec<(u64, u64)> = follower
            .unknown
            .iter()
            .map(|flight| (flight.client, flight.sequence))
            .collect();
        assert_eq!(listed, unknown, "seed {seed:#x}");
        // The gap is a lower bound: the sealed bytes not verified, and an
        // unsealed tail that is unknown.
        // Unknown (None) while V is not mapped into the copy.
        if let Some(copy) = follower.copy
            && let (Some(gap), Some(verified)) = (follower.gap.sealed_unverified, copy.verified)
        {
            assert!(gap >= copy.sealed.unwrap_or(copy.checked).saturating_sub(verified));
        }
        assert_eq!(
            follower.gap.unsealed_tail,
            karyos_cluster::standby::TailBound::Interval(karyos_sim::harness::node::SEAL_TICKS)
        );
        // The clients finished on the standby, in generation 2, and no
        // old-generation success followed (the standby checks).
        assert!(
            outcome.observations.iter().any(|observation| matches!(
                observation,
                Observation::Success { generation: 2, .. }
            ))
        );
    }
}

#[test]
fn s3_over_replication_a_lease_expiry_then_a_promotion_with_the_old_primary_alive() {
    let case = standby::over_replication(standby::s3());
    for seed in corpus() {
        let outcome = workloads::run::<Reference>(&case, seed).unwrap();
        assert_eq!(
            workloads::pass(&case, &outcome),
            Ok(Some(Liveness::Stalled { waiting: 1 })),
            "seed {seed:#x}"
        );
        let (_, report) = promoted(&outcome).unwrap();
        assert_eq!(report.generation, 2, "seed {seed:#x}");
        assert!(report.replication.is_some());
        assert!(outcome.observations.iter().any(|observation| matches!(
            observation,
            Observation::Fenced {
                fencing: Fencing::Lease,
                lease_end: Some(_)
            }
        )));
    }
}

#[test]
fn s4_over_replication_a_promotion_before_fencing_is_refused() {
    let case = standby::over_replication(standby::s4());
    for seed in corpus() {
        let outcome = passing(&case, seed);
        for fencing in [Fencing::Lease, Fencing::OperatorStop] {
            assert!(
                outcome
                    .observations
                    .contains(&Observation::PromotionRefused { fencing }),
                "seed {seed:#x}"
            );
        }
        assert!(promoted(&outcome).is_none());
        assert!(
            !outcome.observations.iter().any(|observation| matches!(
                observation,
                Observation::Success { generation: 2, .. }
            ))
        );
        assert_eq!(verified(&outcome, STANDBY[0]), primary_commit(&outcome));
    }
}

#[test]
fn s6_over_replication_damage_in_transit_is_refused_before_it_applies() {
    let case = standby::over_replication(standby::s6());
    for seed in corpus() {
        let outcome = passing(&case, seed);
        let refusals = replication_refusals(&outcome);
        // The flipped byte (index 3) and the changed term (index 5) fail
        // their seals; the skipped chunk (index 7) only leaves the seal
        // waiting, so it is no refusal, and the resend fills it.
        let seals = refusals
            .iter()
            .filter(|refusal| matches!(refusal, Refusal::Seal(_)))
            .count();
        assert!(seals >= 2, "seed {seed:#x}: {refusals:?}");
        assert!(
            refusals
                .iter()
                .all(|refusal| matches!(refusal, Refusal::Seal(_) | Refusal::Busy { .. })),
            "seed {seed:#x}: {refusals:?}"
        );
        // Nothing damaged applied (the standby checks compare every
        // applied entry with the primary's), and the resends got through.
        assert_eq!(
            verified(&outcome, STANDBY[0]),
            primary_commit(&outcome),
            "seed {seed:#x}"
        );
    }
}

#[test]
fn s7_over_replication_a_restarted_standby_leader_rebuilds_v_from_its_log() {
    let case = standby::over_replication(standby::s7());
    for seed in corpus() {
        let outcome = passing(&case, seed);
        assert_eq!(
            verified(&outcome, STANDBY[0]),
            primary_commit(&outcome),
            "seed {seed:#x}"
        );
        // Each primary entry applied once per standby server and run of
        // it: the restart re-applies from its own log, the new copy skips
        // up to V.
        let mut applied: Vec<(NodeId, u64)> = outcome
            .observations
            .iter()
            .filter_map(|observation| match observation {
                Observation::FeedApplied { node, index, .. } => Some((*node, *index)),
                _ => None,
            })
            .collect();
        let total = applied.len();
        applied.sort_unstable();
        applied.dedup();
        assert!(total <= 2 * applied.len(), "seed {seed:#x}");
    }
}

#[test]
fn every_replicated_scenario_runs_with_its_feed_control() {
    let feed = standby::cases();
    let replicated = standby::replicated_cases();
    assert_eq!(feed.len(), replicated.len());
    for (control, case) in feed.iter().zip(&replicated) {
        assert!(!control.replication);
        assert!(case.replication);
        assert_eq!(case.schedule, control.schedule);
        assert_eq!(case.feed_faults, control.feed_faults);
    }
}

#[test]
fn s7_over_replication_a_standby_leader_restart_after_acknowledgement_makes_progress() {
    let case = standby::over_replication(standby::s7_after_acknowledgement());
    for seed in corpus() {
        let outcome = passing(&case, seed);
        // The replication was acknowledged before the crash.
        assert!(!copy_sources(&outcome).is_empty(), "seed {seed:#x}");
        assert_eq!(
            verified(&outcome, STANDBY[0]),
            primary_commit(&outcome),
            "seed {seed:#x}"
        );
        assert_eq!(
            verified(&outcome, STANDBY[1]),
            primary_commit(&outcome),
            "seed {seed:#x}"
        );
    }
}

/// Each server's application of each command, by client and sequence, is
/// one: a command its service applied twice would answer two different
/// appends (the deduplication check of karyos#720).
fn applied_once(outcome: &Outcome) {
    let mut answered: BTreeMap<(NodeId, NodeId, u64), Vec<u8>> = BTreeMap::new();
    for observation in &outcome.observations {
        let Observation::Applied {
            node,
            entry,
            response: Some(response),
            ..
        } = observation
        else {
            continue;
        };
        let payload = standby::unwrap(&entry.payload)
            .map_or(entry.payload.as_slice(), |(_, _, payload)| payload);
        let Some(command) = Command::decode(payload) else {
            continue;
        };
        if let Some(earlier) =
            answered.insert((*node, command.client, command.sequence), response.clone())
        {
            assert_eq!(&earlier, response, "{command:?} applied twice on {node}");
        }
    }
}

/// The Cluster client's events and its caller's retries, of `client`, in
/// order.
fn client_events(outcome: &Outcome, client: NodeId) -> Vec<&Observation> {
    outcome
        .observations
        .iter()
        .filter(|observation| {
            matches!(
                observation,
                Observation::ClientEvent { client: c, .. }
                    | Observation::ClientRetry { client: c, .. }
                    if *c == client
            )
        })
        .collect()
}

/// S2 with every client's failover the Cluster client's
/// (`karyos_cluster::client::ClusterClient`; karyos#720), over the feed
/// and over the replication: each client reaches the old primary and the
/// promoted standby; the harness's checks hold (generations monotone, no
/// old-generation reply or success after the promotion, the history
/// linearizable across it); no command is applied twice; each request in
/// flight at the change is reported unknown and sent again only by its
/// caller's retry, which, with slow answers, the standby answers from its
/// deduplication.
#[test]
fn s2_cluster_clients_fail_over_to_the_promoted_standby() {
    // With slow answers, the stop lands while answers are in flight for
    // requests the feed already carried: each one's retry is answered
    // by the promoted standby from its deduplication. In the others, every
    // request in flight at the stop is past what the standby holds (over
    // the replication, in the unsealed tail): its retry applies there, once.
    let mut slow = standby::with_cluster_clients(standby::s2());
    slow.reply_delay = 12;
    slow.name.push_str(" and slow answers");
    for (case, deduplicates) in [
        (standby::with_cluster_clients(standby::s2()), false),
        (
            standby::with_cluster_clients(standby::over_replication(standby::s2())),
            false,
        ),
        (slow, true),
    ] {
        let mut unknown_at_change = 0;
        let mut retries_deduplicated = 0;
        for seed in corpus() {
            let outcome = passing(&case, seed);
            let observations = &outcome.observations;
            let (_, report) = promoted(&outcome).unwrap();
            assert_eq!(report.generation, 2, "{} seed {seed:#x}", case.name);
            applied_once(&outcome);
            let clients: Vec<NodeId> = (0..case.clients)
                .map(|index| u32::try_from(PRIMARY.len() + STANDBY.len() + index).unwrap())
                .collect();
            for &client in &clients {
                // It reached the old primary, then the promoted standby.
                for (group, generation) in [(&PRIMARY, 1), (&STANDBY, 2)] {
                    assert!(
                        observations.iter().any(|observation| matches!(
                            observation,
                            Observation::Reply { node, client: c, generation: g, .. }
                                if group.contains(node) && *c == client && *g == generation
                        )),
                        "{} seed {seed:#x}: client {client} not answered in generation {generation}",
                        case.name
                    );
                }
                // An unknown request is sent again only by its caller's
                // retry, never by the Cluster client on its own, and has
                // its outcome in the end.
                let mut unknown = BTreeSet::new();
                for observation in client_events(&outcome, client) {
                    match observation {
                        Observation::ClientEvent {
                            event: Event::Unknown { sequence, .. },
                            ..
                        } => {
                            let _ = unknown.insert(*sequence);
                        }
                        Observation::ClientRetry { sequence, .. }
                        | Observation::ClientEvent {
                            event: Event::Completed { sequence, .. },
                            ..
                        } => {
                            let _ = unknown.remove(sequence);
                        }
                        Observation::ClientEvent {
                            event: Event::Resend(send),
                            ..
                        } => assert!(
                            !unknown.contains(&send.key.sequence),
                            "{} seed {seed:#x}: unknown {} resent",
                            case.name,
                            send.key.sequence
                        ),
                        _ => {}
                    }
                }
                assert!(unknown.is_empty(), "{} seed {seed:#x}", case.name);
            }
            // Each request in flight at the promotion was reported unknown.
            for &(client, sequence) in &report.unknown {
                assert!(
                    observations.iter().any(|observation| matches!(
                        observation,
                        Observation::ClientEvent {
                            client: c,
                            event: Event::Unknown { client: id, sequence: s },
                        } if *c == client && *id == u64::from(client) && *s + 1 == sequence
                    )),
                    "{} seed {seed:#x}: ({client}, {sequence}) not unknown",
                    case.name
                );
                unknown_at_change += 1;
            }
            // A caller's retry after the change, answered by the promoted
            // standby from its deduplication: applied once, as
            // `applied_once` shows.
            let fenced = observations
                .iter()
                .position(|observation| matches!(observation, Observation::Fenced { .. }))
                .unwrap();
            for (at, observation) in observations.iter().enumerate().skip(fenced) {
                if let Observation::ClientRetry { client, sequence } = observation
                    && observations.iter().skip(at).any(|later| {
                        matches!(
                            later,
                            Observation::Deduplicated { node, client: c, sequence: s }
                                if STANDBY.contains(node) && c == client && *s == sequence + 1
                        )
                    })
                {
                    retries_deduplicated += 1;
                }
            }
        }
        assert!(unknown_at_change > 0, "{}", case.name);
        if deduplicates {
            assert!(retries_deduplicated > 0, "{}", case.name);
        }
    }
}

/// S5 with the Cluster client: answered by the old primary in generation
/// 1, sent to the promoted standby by the operator, the client reports
/// its open request unknown and sends nothing until its caller's retry;
/// once it has seen generation 2, every generation 1 answer is refused,
/// to an open request or to one already settled (karyos#720).
#[test]
fn s5_a_cluster_client_rejects_generation_1_once_it_saw_generation_2() {
    const OLD: NodeId = PRIMARY[0];
    const NEW: NodeId = STANDBY[0];
    const OPERATOR: NodeId = 99;
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    let script = vec![
        Op::Append(vec![1]),
        Op::Append(vec![2]),
        Op::Append(vec![3]),
    ];
    let mut client = ClientNode::new(10, OLD, script, Rc::clone(&recorder)).with_cluster_client();
    let mut out: Vec<(NodeId, Wire<Message>)> = Vec::new();
    let answer = |sequence: u64, generation: u64| Wire::<Message>::Response {
        sequence,
        bytes: Ret::Appended(sequence).canonical(),
        index: sequence,
        generation,
    };
    let sent = |out: &[(NodeId, Wire<Message>)]| match out.last() {
        Some((to, Wire::Request(command))) => (*to, command.sequence),
        other => panic!("{other:?}"),
    };
    client.tick(0, &mut out);
    assert_eq!(sent(&out), (OLD, 1));
    client.deliver(OLD, answer(1, 1), 1, &mut out);
    client.tick(2, &mut out);
    assert_eq!(sent(&out), (OLD, 2));
    // The promotion: the operator sends the client to the standby. The
    // open request is unknown, and nothing is sent on its own.
    let before = out.len();
    client.deliver(OPERATOR, Wire::Redirect { server: NEW }, 3, &mut out);
    assert_eq!(out.len(), before);
    assert_eq!(client.open(), Some(2));
    // The caller's retry: the same request, to the standby.
    client.tick(4, &mut out);
    assert_eq!(sent(&out), (NEW, 2));
    client.deliver(NEW, answer(2, 2), 5, &mut out);
    client.tick(6, &mut out);
    assert_eq!(sent(&out), (NEW, 3));
    // The old primary's generation 1 answers: to the open request,
    // refused; to the settled one, nothing.
    client.deliver(OLD, answer(3, 1), 7, &mut out);
    client.deliver(OLD, answer(2, 1), 8, &mut out);
    assert_eq!(client.open(), Some(3));
    client.deliver(NEW, answer(3, 2), 9, &mut out);
    assert!(client.done());
    let observations = &recorder.borrow().observations;
    let events: Vec<Event> = observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::ClientEvent { client: 10, event } => Some(*event),
            _ => None,
        })
        .collect();
    let unknown: Vec<&Event> = events
        .iter()
        .filter(|event| matches!(event, Event::Unknown { .. }))
        .collect();
    assert_eq!(
        unknown,
        [&Event::Unknown {
            client: 10,
            sequence: 1
        }]
    );
    assert!(!events.iter().any(|event| matches!(event, Event::Resend(_))));
    assert!(observations.contains(&Observation::ClientRetry {
        client: 10,
        sequence: 1
    }));
    assert!(events.contains(&Event::StaleGeneration {
        generation: 1,
        highest: 2
    }));
    assert!(observations.contains(&Observation::StaleGeneration {
        client: 10,
        generation: 1
    }));
    let successes: Vec<u64> = observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Success { generation, .. } => Some(*generation),
            _ => None,
        })
        .collect();
    assert_eq!(successes, [1, 2, 2]);
    assert_eq!(check::standby(observations, &STANDBY), Ok(()));
}
