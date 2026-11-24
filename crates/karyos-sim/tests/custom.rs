// SPDX-License-Identifier: Apache-2.0

//! The custom Raft core (ADR-0105) through the harness's `ConsensusCore`
//! adapter (quantstratum/karyos#681, part (d)): W1 to W4 and W6 over the
//! same seeds as the candidates' suite, each verdict asserted.

#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_sim::harness::core::Limit;
use karyos_sim::harness::custom::Custom;
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::workloads::{self, Liveness, W1, W2, W3, W3Fault, W4, W6};

/// Seeds every sweep runs: the candidates' suite's.
const SEEDS: [u64; 4] = [1, 0xC5, 0x0043, 0xDEAD_BEEF];

#[test]
fn w1_passes() {
    for seed in SEEDS {
        for case in W1::skeleton().cases() {
            let outcome = workloads::run::<Custom>(&case, seed).unwrap();
            assert_eq!(
                workloads::pass(&case, &outcome),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

#[test]
fn w3_safety_holds_and_only_the_unrestarted_crash_is_a_gap() {
    for seed in SEEDS {
        for (fault, case) in W3::skeleton().faults.iter().zip(W3::skeleton().cases()) {
            let outcome = workloads::run::<Custom>(&case, seed).unwrap();
            let result = workloads::pass(&case, &outcome);
            match fault {
                W3Fault::LeaderCrash => assert!(
                    matches!(result, Ok(None | Some(Liveness::Stalled { .. }))),
                    "{} seed {seed}: {result:?}",
                    case.name
                ),
                _ => assert_eq!(result, Ok(None), "{} seed {seed}", case.name),
            }
        }
    }
}

#[test]
fn w4_passes_and_a_lost_majority_is_a_gap() {
    for seed in SEEDS {
        for case in W4::skeleton(seed).cases() {
            let outcome = workloads::run::<Custom>(&case, seed).unwrap();
            let result = workloads::pass(&case, &outcome);
            if case.name.contains("FailedFlushes") {
                assert_eq!(
                    result,
                    Ok(Some(Liveness::NoLeader)),
                    "{} seed {seed}",
                    case.name
                );
            } else {
                assert_eq!(result, Ok(None), "{} seed {seed}", case.name);
            }
        }
    }
}

#[test]
fn w6_replays_every_seed() {
    let w6 = W6::skeleton();
    for case in w6.cases() {
        for seed in SEEDS {
            assert_eq!(
                w6.pass::<Custom>(&case, seed).unwrap(),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

#[test]
fn a_seed_reproduces_its_run() {
    let mut cases = W1::skeleton().cases();
    cases.extend(W3::skeleton().cases());
    let mut cases: Vec<_> = cases.into_iter().step_by(3).collect();
    cases.extend(W2::skeleton().cases().unwrap());
    for case in &cases {
        for seed in SEEDS {
            let first = workloads::run::<Custom>(case, seed).unwrap();
            let second = workloads::run::<Custom>(case, seed).unwrap();
            assert_eq!(first, second, "{} seed {seed}", case.name);
        }
    }
}

/// W2 under the declared limits: every case keeps safety and passes, and
/// the queue's burst is refused with a typed `Backpressure(Queue)` only.
#[test]
fn w2_passes_and_its_burst_is_refused_by_the_queue() {
    for case in &W2::skeleton().cases().unwrap() {
        let outcome = workloads::run::<Custom>(case, 1).unwrap();
        assert!(outcome.safety.is_ok(), "{}", case.name);
        let pushed: Vec<_> = outcome
            .observations
            .iter()
            .filter_map(|observation| match observation {
                Observation::Backpressure { limit, .. } => Some(*limit),
                _ => None,
            })
            .collect();
        if case.name.contains("burst 4x queue") {
            assert!(!pushed.is_empty(), "{}", case.name);
            assert!(
                pushed.iter().all(|limit| *limit == Limit::Queue),
                "{}",
                case.name
            );
        }
        assert_eq!(workloads::pass(case, &outcome), Ok(None), "{}", case.name);
    }
}

/// The step and the request of a trigger, from a run.
type Trigger = (u64, karyos_sim::net::NodeId, Option<(u64, u64, u64)>);

fn trigger(observations: &[Observation], name: &str) -> Option<Trigger> {
    observations
        .iter()
        .find_map(|observation| match observation {
            Observation::Triggered {
                what,
                node,
                at,
                request,
                ..
            } if *what == name => Some((*at, *node, *request)),
            _ => None,
        })
}

/// C5 version 2's W5 retry, relative to whoever leads: the custom core
/// passes it on every seed, its triggers in the frozen order (cut, lost,
/// crash before the next step, restart 40 steps after the crash) on one
/// leader; the witness is the lost request's own retry, from a later
/// term; and a trigger not reached by the deadline fails, inclusively.
#[test]
fn the_lost_reply_whoever_leads_passes_on_its_own_witness() {
    use karyos_sim::harness::workloads::{Failed, W5};
    let case = W5::manifest().lost_reply_whoever_leads();
    let mut first = None;
    for seed in SEEDS {
        let outcome = workloads::run::<Custom>(&case, seed).unwrap();
        assert_eq!(
            workloads::pass(&case, &outcome),
            Ok(None),
            "{} seed {seed}",
            case.name
        );
        let observations = &outcome.observations;
        let (cut, leader, _) = trigger(observations, "cut").unwrap();
        let (lost, lost_on, request) = trigger(observations, "lost").unwrap();
        let (crash, crashed, _) = trigger(observations, "crash").unwrap();
        let (restart, restarted, _) = trigger(observations, "restart").unwrap();
        assert!(cut >= 12 && cut <= lost, "seed {seed}");
        assert_eq!(crash, lost + 1, "seed {seed}");
        assert_eq!(restart, crash + 40, "seed {seed}");
        assert!(
            [lost_on, crashed, restarted]
                .iter()
                .all(|node| *node == leader)
        );
        assert!(request.is_some(), "seed {seed}");
        first.get_or_insert((outcome, cut));
    }
    let (outcome, cut) = first.unwrap();
    let mutated = |change: &dyn Fn(&mut Observation)| {
        let mut outcome = outcome.clone();
        for observation in &mut outcome.observations {
            change(observation);
        }
        workloads::pass(&case, &outcome)
    };
    // Another request's deduplication is no witness.
    assert_eq!(
        mutated(&|observation| {
            if let Observation::Deduplicated { sequence, .. } = observation {
                *sequence += 1_000;
            }
        }),
        Err(Failed::NotShown("retry"))
    );
    // Nor is an answer from a term not above the lost reply's.
    assert_eq!(
        mutated(&|observation| {
            if let Observation::Triggered {
                request: Some((_, term, _)),
                ..
            } = observation
            {
                *term = u64::MAX;
            }
        }),
        Err(Failed::NotShown("retry"))
    );
    // The deadline is inclusive: at the cut's step the cut counts, one
    // before it does not.
    let at = |deadline| {
        let mut late = case.clone();
        if let Some(lost) = late.lost_reply.as_mut() {
            lost.deadline = deadline;
        }
        let outcome = workloads::run::<Custom>(&late, SEEDS[0]).unwrap();
        workloads::pass(&late, &outcome)
    };
    assert_eq!(at(cut - 1), Err(Failed::NotShown("cut")));
    assert_ne!(at(cut), Err(Failed::NotShown("cut")));
}

/// W5\x27s snapshot cases through the core\x27s snapshot install (#682):
/// compaction under load, a follower behind the compaction point, a
/// follower crashing around its install and one crashing between builds
/// all pass on every seed. Version 1\x27s retry case needs a handover, which
/// the core does not take: not demonstrated, never passed.
#[test]
fn w5_snapshots_pass_and_the_handover_retry_is_not_demonstrated() {
    use karyos_sim::harness::workloads::{RunError, W5};
    let cases = W5::skeleton().cases().unwrap();
    assert_eq!(cases.len(), 5);
    for case in &cases {
        for seed in SEEDS {
            let run = workloads::run::<Custom>(case, seed);
            if case.handover.is_some() {
                assert!(
                    matches!(run, Err(RunError::Unsupported(_))),
                    "{} seed {seed}: {run:?}",
                    case.name
                );
                continue;
            }
            let outcome = run.unwrap();
            assert_eq!(
                workloads::pass(case, &outcome),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
            assert!(
                outcome
                    .observations
                    .iter()
                    .any(|observation| matches!(observation, Observation::Compacted { .. })),
                "{} seed {seed}: no compaction",
                case.name
            );
        }
    }
}

/// The replication path's buffers hold to the bounds derived from the
/// limits ([`Bounds`]): over W1 to W6, no pooled entry is made past the
/// prefill, the entries out of the pool at once stay within the bound,
/// and every Ready within its reserved sizes. W1, run without limits,
/// takes [`DEFAULT_LIMITS`] and never reaches any of them: no refusal,
/// and every follower's window below both caps.
#[test]
fn the_buffers_hold_to_the_bounds_the_limits_give() {
    use karyos_sim::harness::custom::{
        Bounds, DEFAULT_LIMITS, READY_MESSAGES, pool_stats, reset_pool_peaks,
    };
    use karyos_sim::harness::workloads::{Case, W5};
    let mut cases: Vec<Case> = W1::skeleton().cases();
    cases.extend(W2::skeleton().cases().unwrap());
    cases.extend(W3::skeleton().cases());
    cases.extend(W4::skeleton(1).cases());
    cases.extend(
        W5::skeleton()
            .cases()
            .unwrap()
            .into_iter()
            .filter(|case| case.handover.is_none()),
    );
    cases.push(W5::manifest().lost_reply_whoever_leads());
    cases.extend(W6::skeleton().cases());
    for case in &cases {
        let limits = case.limits.unwrap_or(DEFAULT_LIMITS);
        let bounds = Bounds::of(&limits, case.servers).unwrap();
        reset_pool_peaks();
        let outcome = workloads::run::<Custom>(case, 1).unwrap();
        let stats = pool_stats();
        assert_eq!(stats.created, stats.prefilled, "{}: {stats:?}", case.name);
        assert_eq!(stats.vector_misses, 0, "{}: {stats:?}", case.name);
        assert_eq!(stats.payload_misses, 0, "{}: {stats:?}", case.name);
        assert!(
            stats.peak_out <= bounds.pool_entries,
            "{}: {stats:?} {bounds:?}",
            case.name
        );
        let [messages, after, entries, committed] = stats.peak_ready;
        assert!(
            messages <= READY_MESSAGES && after <= READY_MESSAGES,
            "{}: {stats:?}",
            case.name
        );
        assert!(
            entries <= bounds.ready_entries,
            "{}: {stats:?} {bounds:?}",
            case.name
        );
        assert!(
            committed <= bounds.committed,
            "{}: {stats:?} {bounds:?}",
            case.name
        );
        if case.name.starts_with("W1") {
            assert!(
                !outcome
                    .observations
                    .iter()
                    .any(|observation| matches!(observation, Observation::Backpressure { .. })),
                "{}: W1 reached a limit",
                case.name
            );
            let (window, bytes) = stats.peak_window;
            assert!(
                window < DEFAULT_LIMITS.in_flight_entries && bytes < DEFAULT_LIMITS.in_flight_bytes,
                "{}: W1 reached the in-flight caps: {stats:?}",
                case.name
            );
        }
    }
}

/// The custom core's model invariants (`crates/karyos-cluster/tests/
/// consensus_model.rs`), checked on a harness history: what the run's
/// observations show of terms, leaders and commits (C5 version 2, the
/// custom core's trace checking; ADR-0105, decision 4).
///
/// - Election safety: at most one server commits as leader in a term.
/// - State machine safety: every server that commits an index commits the
///   same entry term there.
/// - Commit monotone: a server's commit index never moves back while it
///   is up.
/// - Leader completeness: a server's first commit as the leader of a term
///   is at or past every index committed before it in the run.
fn model_violation(observations: &[Observation]) -> Option<String> {
    use std::collections::BTreeMap;
    let mut leaders: BTreeMap<u64, u32> = BTreeMap::new();
    let mut entries: BTreeMap<u64, u64> = BTreeMap::new();
    let mut commits: BTreeMap<u32, u64> = BTreeMap::new();
    let mut led: BTreeMap<(u32, u64), ()> = BTreeMap::new();
    let mut highest = 0u64;
    for observation in observations {
        match observation {
            Observation::Crashed { node } => {
                let _ = commits.remove(node);
            }
            Observation::Commit {
                node,
                term,
                leader,
                index,
                entry_term,
            } => {
                if *leader {
                    let first = leaders.entry(*term).or_insert(*node);
                    if first != node {
                        return Some(format!("two leaders in term {term}: {first} and {node}"));
                    }
                    if led.insert((*node, *term), ()).is_none() && *index < highest {
                        return Some(format!(
                            "leader {node} of term {term} first commits {index}, below {highest}"
                        ));
                    }
                }
                if let Some(previous) = commits.insert(*node, *index)
                    && *index < previous
                {
                    return Some(format!(
                        "{node}'s commit moved back from {previous} to {index}"
                    ));
                }
                if let Some(term) = entries.insert(*index, *entry_term)
                    && term != *entry_term
                {
                    return Some(format!(
                        "index {index} committed with terms {term} and {entry_term}"
                    ));
                }
                highest = highest.max(*index);
            }
            _ => {}
        }
    }
    None
}

/// Every W1, W3, W4, W5 and W6 history of the custom core keeps the
/// model's invariants on every seed; and each invariant is shown to
/// catch its violation on a history mutated to break it.
#[test]
fn the_harness_histories_keep_the_model_invariants() {
    use karyos_sim::harness::workloads::W5;
    let mut cases = W1::skeleton().cases();
    cases.extend(W3::skeleton().cases());
    cases.extend(
        W5::skeleton()
            .cases()
            .unwrap()
            .into_iter()
            .filter(|case| case.handover.is_none()),
    );
    cases.push(W5::manifest().lost_reply_whoever_leads());
    cases.extend(W6::skeleton().cases());
    let mut sample = None;
    for seed in SEEDS {
        let mut all = cases.clone();
        all.extend(W4::skeleton(seed).cases());
        for case in &all {
            let outcome = workloads::run::<Custom>(case, seed).unwrap();
            assert_eq!(
                model_violation(&outcome.observations),
                None,
                "{} seed {seed}",
                case.name
            );
            sample.get_or_insert(outcome);
        }
    }
    let sample = sample.unwrap();
    let commits: Vec<usize> = sample
        .observations
        .iter()
        .enumerate()
        .filter_map(|(at, observation)| {
            matches!(observation, Observation::Commit { leader: true, .. }).then_some(at)
        })
        .collect();
    assert!(commits.len() >= 2, "too few leader commits to mutate");
    let broken = |change: &dyn Fn(&mut Vec<Observation>)| {
        let mut observations = sample.observations.clone();
        change(&mut observations);
        model_violation(&observations)
    };
    // A second leader in the same term.
    assert!(
        broken(&|o| {
            if let Some(Observation::Commit { node, .. }) = o.get_mut(commits[1]) {
                *node += 1;
            }
        })
        .is_some_and(|v| v.contains("two leaders"))
    );
    // The same index committed with another term.
    assert!(
        broken(&|o| {
            let copy = o[commits[0]].clone();
            if let Observation::Commit {
                node,
                leader,
                entry_term,
                ..
            } = copy
            {
                o.push(Observation::Commit {
                    node: node.wrapping_add(99), // committed nothing before: only the term differs
                    term: 0,
                    leader: false,
                    index: match o[commits[0]] {
                        Observation::Commit { index, .. } => index,
                        _ => 0,
                    },
                    entry_term: entry_term + 1,
                });
                let _ = leader;
            }
        })
        .is_some_and(|v| v.contains("committed with terms"))
    );
    // A commit moving back on a server that stayed up.
    assert!(
        broken(&|o| {
            if let Observation::Commit {
                node,
                term,
                index,
                entry_term,
                ..
            } = o[commits[commits.len() - 1]].clone()
                && index > 0
            {
                o.push(Observation::Commit {
                    node,
                    term,
                    leader: false,
                    index: index - 1,
                    entry_term,
                });
            }
        })
        .is_some_and(|v| v.contains("moved back"))
    );
    // A new leader whose first commit is below what was committed.
    assert!(
        broken(&|o| {
            o.push(Observation::Commit {
                node: 9,
                term: u64::MAX,
                leader: true,
                index: 0,
                entry_term: 0,
            });
        })
        .is_some_and(|v| v.contains("first commits"))
    );
}
