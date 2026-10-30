// SPDX-License-Identifier: Apache-2.0

//! ADR-0043's workloads over the reference core (cluster-gap-analysis.md
//! §6, C5), over a fixed corpus of seeds plus `scenarios::seeds()`
//! (`KARYOS_SIM_SEEDS` widens it):
//!
//! - the reference passes W1, W4 and W6, and W3's safety predicates;
//! - W3's leader crash, and W4's lost durable majority, show a liveness
//!   gap, not a violation;
//! - a retried command is applied twice and answered once, by the
//!   service's deduplication, and the state digest is the linearized
//!   history's;
//! - W2 and W5 are typed as not yet runnable.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_sim::harness::core::Limit;
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::workloads::{
    self, ADR_0043, Action, Failed, Liveness, Progress, W1, W2, W3, W3Fault, W4, W4Cut, W5, W6,
};
use karyos_sim::scenarios;

/// Seeds every sweep runs besides `scenarios::seeds()`.
const CORPUS: [u64; 4] = [0xC5, 0x0043, 0xDEAD_BEEF, u64::MAX];

fn corpus() -> Vec<u64> {
    let mut seeds = CORPUS.to_vec();
    seeds.extend(scenarios::seeds());
    seeds
}

#[test]
fn the_module_records_its_adr_revision() {
    assert!(ADR_0043.contains("03ffb394"));
    assert!(ADR_0043.contains("Proposed"));
}

/// W5's snapshot half at the manifest's values (harness validation):
/// compaction every 1,000 entries, keeping 100.
#[test]
#[ignore = "the manifest's W5 takes long; run on request"]
fn w5_snapshots_manifest_passes() {
    for case in W5::manifest().cases().unwrap() {
        let outcome = workloads::run::<Reference>(&case, 1).unwrap();
        assert_eq!(workloads::pass(&case, &outcome), Ok(None), "{}", case.name);
    }
}

/// W5's snapshot half, the skeleton (harness validation): every case
/// compacts and converges; the follower behind the compaction point
/// catches up by an installed snapshot, also when its install or another
/// server's snapshot build is cut by a crash; and a retry after a lost
/// reply and a leader change is answered from deduplication.
#[test]
fn w5_passes() {
    let cases = W5::skeleton().cases().unwrap();
    assert_eq!(cases.len(), 5);
    for case in &cases {
        let outcome = workloads::run::<Reference>(case, 1).unwrap();
        assert_eq!(workloads::pass(case, &outcome), Ok(None), "{}", case.name);
        let count = |wanted: &dyn Fn(&Observation) -> bool| {
            outcome.observations.iter().filter(|o| wanted(o)).count()
        };
        if case.compaction.is_some() {
            assert!(
                count(&|o| matches!(o, Observation::Compacted { .. })) > 0,
                "{}: nothing compacted",
                case.name
            );
        } else {
            // The retry: the handover took, the new leader committed in its
            // term, and a retry was answered from deduplication.
            assert!(
                count(&|o| matches!(
                    o,
                    Observation::Transfer {
                        node: 0,
                        to: 1,
                        result: Ok(())
                    }
                )) == 1,
                "{}: no handover",
                case.name
            );
            assert!(
                count(&|o| matches!(
                    o,
                    Observation::Commit {
                        node: 1,
                        leader: true,
                        term: 2,
                        ..
                    }
                )) > 0,
                "{}: the new leader committed nothing",
                case.name
            );
            assert!(
                outcome.deduplicated > 0,
                "{}: no retry deduplicated",
                case.name
            );
        }
        if case.behind.is_some() {
            assert!(
                count(&|o| matches!(o, Observation::Installed { node: 2, .. })) > 0,
                "{}: the follower installed nothing",
                case.name
            );
        }
        assert_eq!(
            count(&|o| matches!(o, Observation::SnapshotRefused { .. })),
            0,
            "{}",
            case.name
        );
    }
}

/// W2's skeleton under the declared limits (harness validation): the
/// clients complete, and the follower cut off while the leader commits
/// its entries catches up to the same state.
#[test]
fn w2_passes() {
    let w2 = W2::skeleton();
    let cases = w2.cases().unwrap();
    assert_eq!(cases.len(), 5);
    for case in &cases {
        assert_eq!(case.limits, Some(w2.limits));
        let outcome = workloads::run::<Reference>(case, 1).unwrap();
        // The queue's burst is pushed back, typed; nothing else is.
        let pushed = outcome
            .observations
            .iter()
            .filter(|observation| {
                matches!(
                    observation,
                    Observation::Backpressure {
                        limit: Limit::Queue,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            pushed > 0,
            case.name.contains("burst 4x queue"),
            "{}: {pushed}",
            case.name
        );
        assert_eq!(workloads::pass(case, &outcome), Ok(None), "{}", case.name);
        let applied: Vec<_> = outcome
            .states
            .iter()
            .map(|(_, applied, _)| *applied)
            .collect();
        assert!(
            applied.windows(2).all(|pair| pair[0] == pair[1]),
            "{}: {applied:?}",
            case.name
        );
    }
    // The same run stopped as the pause ends: the follower is the case's
    // `behind` entries back, or more.
    let slow = &cases[3];
    assert!(slow.name.contains("slow follower"), "{}", slow.name);
    let mut paused = slow.clone();
    paused.steps = w2.pause + 10;
    paused
        .schedule
        .retain(|(_, action)| !matches!(action, Action::Heal));
    paused.quiet = 0;
    paused.progress = Progress::MayStop;
    let outcome = workloads::run::<Reference>(&paused, 1).unwrap();
    let applied = |node| {
        outcome
            .states
            .iter()
            .find(|(id, ..)| *id == node)
            .and_then(|(_, applied, _)| *applied)
            .unwrap_or(0)
    };
    let gap = applied(0).checked_sub(applied(W2::SLOW)).unwrap();
    assert!(gap >= w2.behind, "{gap} behind at the heal");
    let manifest = W2::manifest();
    assert_eq!(manifest.limits, karyos_sim::harness::core::Limits::W2);
    assert_eq!(
        (manifest.processes, manifest.clients, manifest.payload_bytes),
        (3, 32, 256)
    );
    assert_eq!((manifest.pause, manifest.behind), (2_000, 10_000));
    // The manifest's bursts: 4,096 requests open for the queue, 256 for
    // the in-flight entries, a follower 16,384 entries (4 MiB) behind.
    let full = manifest.cases().unwrap();
    assert_eq!(
        (full[1].sessions(), full[2].sessions()),
        (Some(4_096), Some(256))
    );
    assert!(full[4].name.contains("16384 behind"), "{}", full[4].name);
    assert!(W2::IN_FLIGHT_BYTES.contains("not reached"));
}

#[test]
fn w1_passes() {
    let cases = W1::skeleton().cases();
    assert_eq!(cases.len(), 16);
    // The full sweep for a few seeds; the widest case for the rest.
    for seed in corpus() {
        let chosen: Vec<_> = if CORPUS.contains(&seed) {
            cases.iter().collect()
        } else {
            cases
                .iter()
                .filter(|case| case.servers == 5)
                .take(2)
                .collect()
        };
        for case in chosen {
            let outcome = workloads::run::<Reference>(case, seed).unwrap();
            assert_eq!(
                workloads::pass(case, &outcome),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

/// W2 at the manifest's values (harness validation): 32 clients, the
/// bursts (4,096 requests open, 256 in flight, a follower 4 MiB behind),
/// and the follower catching up from 10,000 entries behind. About 10 s in
/// a release build.
#[test]
#[ignore = "the manifest's W2 takes long; run on request"]
fn w2_manifest_passes() {
    for case in W2::manifest().cases().unwrap() {
        let outcome = workloads::run::<Reference>(&case, 1).unwrap();
        assert_eq!(workloads::pass(&case, &outcome), Ok(None), "{}", case.name);
    }
}

/// The up servers agree with one another, but not with the register the
/// linearized history builds: `pass` reports the wrong state, not
/// success. The run is real and passes untouched; only the servers'
/// digests are changed, all to the same value, so the divergence check
/// cannot catch it first.
#[test]
fn a_state_the_history_does_not_build_is_wrong() {
    let case = &W1::skeleton().cases()[0];
    let mut outcome = workloads::run::<Reference>(case, CORPUS[0]).unwrap();
    assert_eq!(workloads::pass(case, &outcome), Ok(None));
    assert!(!outcome.states.is_empty());
    let right = outcome.states[0].2;
    let wrong = right ^ 1;
    for state in &mut outcome.states {
        state.2 = wrong;
    }
    assert_eq!(
        workloads::pass(case, &outcome),
        Err(Failed::WrongState {
            expected: right,
            states: outcome.states.clone(),
        })
    );
}

#[test]
fn w3_safety_holds_and_a_leader_crash_is_a_gap() {
    let w3 = W3::skeleton();
    for seed in corpus() {
        for (fault, case) in w3.faults.iter().zip(w3.cases()) {
            let outcome = workloads::run::<Reference>(&case, seed).unwrap();
            let expected = if *fault == W3Fault::LeaderCrash {
                Some(Liveness::NoLeader)
            } else {
                None
            };
            assert_eq!(
                workloads::pass(&case, &outcome),
                Ok(expected),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

#[test]
fn w4_passes_and_a_lost_majority_is_a_gap() {
    for seed in corpus() {
        let w4 = W4::skeleton(seed);
        let cases = w4.cases();
        let modes = w4.survives.len();
        for (index, case) in cases.iter().enumerate() {
            let cut = w4.cuts[index / modes];
            let outcome = workloads::run::<Reference>(case, seed).unwrap();
            let verdict = workloads::pass(case, &outcome);
            match cut {
                W4Cut::FailedFlushes { .. } => assert!(
                    matches!(verdict, Ok(Some(Liveness::Stalled { .. }))),
                    "{} seed {seed}: {verdict:?}",
                    case.name
                ),
                W4Cut::LeaderCrash { .. } => {
                    assert_eq!(case.progress, Progress::MayStop);
                    assert!(verdict.is_ok(), "{} seed {seed}: {verdict:?}", case.name);
                }
                W4Cut::FollowerCrash { .. } | W4Cut::FailedFlush { .. } => {
                    assert_eq!(verdict, Ok(None), "{} seed {seed}", case.name);
                }
            }
        }
    }
}

#[test]
fn slow_replies_are_retried_and_deduplicated() {
    let case = W6::skeleton()
        .cases()
        .into_iter()
        .find(|case| case.name == "W6 slow replies")
        .unwrap();
    for seed in corpus() {
        let outcome = workloads::run::<Reference>(&case, seed).unwrap();
        assert_eq!(workloads::pass(&case, &outcome), Ok(None), "seed {seed}");
        assert!(outcome.deduplicated > 0, "seed {seed}: nothing retried");
    }
}

#[test]
fn w6_replays_every_seed() {
    let w6 = W6::skeleton();
    for seed in corpus() {
        for case in w6.cases() {
            assert_eq!(
                w6.pass::<Reference>(&case, seed).unwrap(),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

/// The reference's handover refuses itself and a stranger as targets, and
/// one behind its log; a handover to a caught-up voter takes, and the run
/// stays safe and complete (harness validation).
#[test]
fn a_handover_refuses_what_it_cannot_hand_over_to() {
    use karyos_sim::harness::core::TransferRefused;
    let mut case = workloads::Case::healthy("handover", 3, 2, 8);
    case.schedule = vec![
        (3, Action::TransferLeadership(1)),
        (4, Action::TransferLeadership(0)),
        (5, Action::TransferLeadership(9)),
        (60, Action::TransferLeadership(2)),
    ];
    case.steps = 1_200;
    let outcome = workloads::run::<Reference>(&case, 1).unwrap();
    assert_eq!(workloads::pass(&case, &outcome), Ok(None));
    let leader_answers: Vec<_> = outcome
        .observations
        .iter()
        .filter_map(|o| match o {
            Observation::Transfer {
                node: 0,
                to,
                result,
            } => Some((*to, *result)),
            _ => None,
        })
        .collect();
    assert!(
        matches!(
            leader_answers[..],
            [
                (1, Err(TransferRefused::Lagging { .. }) | Ok(())),
                (
                    0,
                    Err(TransferRefused::Invalid) | Err(TransferRefused::NotLeader(_))
                ),
                (
                    9,
                    Err(TransferRefused::Invalid) | Err(TransferRefused::NotLeader(_))
                ),
                ..
            ]
        ),
        "{leader_answers:?}"
    );
    // Some server led the last handover's term.
    assert!(outcome.observations.iter().any(|o| matches!(
        o,
        Observation::Commit {
            leader: true,
            term: 2..,
            ..
        }
    )));
}
