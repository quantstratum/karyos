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
//!   the history across a promotion leaves an unknown outcome pending.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::cell::RefCell;
use std::rc::Rc;

use karyos_sim::cluster::Node;
use karyos_sim::harness::check::{self, Violation};
use karyos_sim::harness::node::{ClientNode, Observation, Op, Recorder, Ret, Shared, Wire};
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
