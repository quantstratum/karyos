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

/// What [`model_violation`] tracks of one server.
#[derive(Default, Clone)]
struct Server {
    /// Its log as written: index to term.
    log: std::collections::BTreeMap<u64, u64>,
    /// Its latest snapshot base, (index, term): below it the snapshot
    /// holds the state.
    base: (u64, u64),
    /// Its commit index since it last started.
    committed: Option<u64>,
}

/// The custom core's model invariants (`crates/karyos-cluster/tests/
/// consensus_model.rs`), checked on a harness history, event by event
/// (C5 version 2, the custom core's trace checking; ADR-0105, decision 4):
///
/// - **Election safety**: at most one server leads a term
///   ([`Observation::Leading`], recorded when a server first leads one).
/// - **Log matching**: when a server writes an entry another server holds
///   with the same term, both logs agree on every entry before it, above
///   both snapshot bases.
/// - **Leader completeness**: a server that starts to lead holds every
///   entry applied anywhere before, above its snapshot base, with its term.
/// - **State machine safety**: every server applies the same entry
///   (index, term and command) at an index.
/// - **Commit monotone**: a server's commit index never moves back while
///   it is up.
/// - **Persist then send**: a message that waited for persistence leaves
///   only once what its Ready appended is durable and its hard state is
///   the stored one.
fn model_violation(observations: &[Observation]) -> Option<String> {
    use karyos_sim::harness::core::Step;
    use std::collections::BTreeMap;
    let mut servers: BTreeMap<u32, Server> = BTreeMap::new();
    let mut leaders: BTreeMap<u64, u32> = BTreeMap::new();
    let mut applied: BTreeMap<u64, (u64, Vec<u8>)> = BTreeMap::new();
    for observation in observations {
        match observation {
            Observation::Leading { node, term } => {
                let first = *leaders.entry(*term).or_insert(*node);
                if first != *node {
                    return Some(format!("two leaders in term {term}: {first} and {node}"));
                }
                let server = servers.entry(*node).or_default();
                for (index, (term_applied, _)) in &applied {
                    if *index > server.base.0 && server.log.get(index) != Some(term_applied) {
                        return Some(format!(
                            "leader {node} of term {term} lacks applied entry {index} of term {term_applied}"
                        ));
                    }
                }
            }
            Observation::Drive {
                node,
                step:
                    Step::Persisted {
                        truncated_from,
                        appended,
                        ..
                    },
            } => {
                let mine = servers.entry(*node).or_default();
                if let Some(from) = truncated_from {
                    let _ = mine.log.split_off(from);
                }
                for &(index, term) in appended {
                    let _ = mine.log.insert(index, term);
                }
                let mine = mine.clone();
                for &(index, term) in appended {
                    for (other, theirs) in &servers {
                        if other == node || theirs.log.get(&index) != Some(&term) {
                            continue;
                        }
                        let floor = mine.base.0.max(theirs.base.0);
                        let differs = (floor + 1..index).find(|at| {
                            matches!((mine.log.get(at), theirs.log.get(at)), (Some(a), Some(b)) if a != b)
                        });
                        if let Some(at) = differs {
                            return Some(format!(
                                "log matching broken between {node} and {other}: equal at {index}, not at {at}"
                            ));
                        }
                    }
                }
            }
            Observation::Recovered { node, entries, .. } => {
                let server = servers.entry(*node).or_default();
                server.log = entries.iter().copied().collect();
                server.committed = None;
            }
            Observation::Crashed { node } => {
                servers.entry(*node).or_default().committed = None;
            }
            Observation::Installed { node, base, .. }
            | Observation::Compacted { node, base, .. } => {
                let server = servers.entry(*node).or_default();
                if matches!(observation, Observation::Installed { .. })
                    && server.log.get(&base.index) != Some(&base.term)
                {
                    server.log.clear();
                }
                server.log = std::mem::take(&mut server.log)
                    .into_iter()
                    .filter(|(index, _)| *index > base.index)
                    .collect();
                server.base = server.base.max((base.index, base.term));
            }
            Observation::Positions { node, positions } => {
                let server = servers.entry(*node).or_default();
                if let (Some(before), Some(now)) = (server.committed, positions.committed)
                    && now < before
                {
                    return Some(format!("{node}'s commit moved back from {before} to {now}"));
                }
                if positions.committed.is_some() {
                    server.committed = positions.committed;
                }
            }
            Observation::Applied { node, entry, .. } => {
                let seen = applied
                    .entry(entry.index)
                    .or_insert((entry.term, entry.payload.clone()));
                if *seen != (entry.term, entry.payload.clone()) {
                    return Some(format!("{node} applied another entry at {}", entry.index));
                }
            }
            Observation::Released { node, release, .. } => {
                if release.needs.is_some() && release.durable < release.needs {
                    return Some(format!(
                        "{node} sent before {:?} was durable",
                        release.needs
                    ));
                }
                if release.needs_state.is_some() && release.stored_state != release.needs_state {
                    return Some(format!("{node} sent before its hard state was stored"));
                }
            }
            _ => {}
        }
    }
    None
}

/// The custom core's W1 to W6 histories keep the model's invariants on
/// every seed, W5's through snapshots (each compacts or installs); and each
/// invariant catches its violation, injected into a valid history.
#[test]
fn the_harness_histories_keep_the_model_invariants() {
    use karyos_sim::harness::workloads::W5;
    let mut cases = W1::skeleton().cases();
    cases.extend(W2::skeleton().cases().unwrap());
    cases.extend(W3::skeleton().cases());
    let snapshots: Vec<_> = W5::skeleton()
        .cases()
        .unwrap()
        .into_iter()
        .filter(|case| case.handover.is_none())
        .collect();
    cases.extend(snapshots.iter().cloned());
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
            if snapshots.iter().any(|snapshot| snapshot.name == case.name) {
                assert!(
                    outcome.observations.iter().any(|observation| matches!(
                        observation,
                        Observation::Compacted { .. } | Observation::Installed { .. }
                    )),
                    "{} seed {seed}: no snapshot",
                    case.name
                );
            }
            if case.name.starts_with("W1") {
                sample.get_or_insert(outcome);
            }
        }
    }
    let valid = sample.unwrap().observations;
    let broken = |change: &dyn Fn(&mut Vec<Observation>)| {
        let mut observations = valid.clone();
        change(&mut observations);
        model_violation(&observations).unwrap_or_default()
    };
    let first = |pick: &dyn Fn(&Observation) -> bool| valid.iter().position(pick).unwrap();
    // A second leader of a term already led.
    let led = first(&|o| matches!(o, Observation::Leading { .. }));
    assert!(
        broken(&|o| {
            if let Observation::Leading { node, term } = o[led].clone() {
                o.insert(
                    led + 1,
                    Observation::Leading {
                        node: node + 1,
                        term,
                    },
                );
            }
        })
        .contains("two leaders")
    );
    // A server writing an entry another holds, over a different prefix.
    let written = first(&|o| {
        matches!(o, Observation::Drive { step: karyos_sim::harness::core::Step::Persisted { appended, .. }, .. }
            if appended.iter().any(|(index, _)| *index >= 2))
    });
    assert!(
        broken(&|o| {
            if let Observation::Drive {
                step:
                    karyos_sim::harness::core::Step::Persisted {
                        appended,
                        persisted,
                        ..
                    },
                ..
            } = o[written].clone()
                && let Some(&(index, term)) = appended.iter().find(|(index, _)| *index >= 2)
            {
                o.insert(
                    written + 1,
                    Observation::Drive {
                        node: 99,
                        step: karyos_sim::harness::core::Step::Persisted {
                            persisted,
                            truncated_from: None,
                            appended: vec![(index - 1, term + 1_000), (index, term)],
                        },
                    },
                );
            }
        })
        .contains("log matching")
    );
    // A leader missing an entry applied before it leads.
    let applied = first(&|o| matches!(o, Observation::Applied { .. }));
    assert!(
        broken(&|o| o.insert(
            applied + 1,
            Observation::Leading {
                node: 99,
                term: u64::MAX
            }
        ))
        .contains("lacks applied entry")
    );
    // Another command applied at an index.
    assert!(
        broken(&|o| {
            if let Observation::Applied {
                node,
                entry,
                applying,
                response,
            } = o[applied].clone()
            {
                let mut other = entry;
                other.payload.push(0xFF);
                o.insert(
                    applied + 1,
                    Observation::Applied {
                        node: node + 1,
                        entry: other,
                        applying,
                        response,
                    },
                );
            }
        })
        .contains("applied another entry")
    );
    // A commit moving back on a server that stayed up.
    let position = first(
        &|o| matches!(o, Observation::Positions { positions, .. } if positions.committed.is_some_and(|c| c > 0)),
    );
    assert!(
        broken(&|o| {
            if let Observation::Positions { node, positions } = o[position].clone() {
                let mut back = positions;
                back.committed = back.committed.map(|c| c - 1);
                o.insert(
                    position + 1,
                    Observation::Positions {
                        node,
                        positions: back,
                    },
                );
            }
        })
        .contains("moved back")
    );
    // A message released before what it waited for was durable.
    let released = first(
        &|o| matches!(o, Observation::Released { release, .. } if release.needs.is_some_and(|n| n > 0)),
    );
    assert!(
        broken(&|o| {
            if let Observation::Released { release, .. } = &mut o[released] {
                release.durable = release.needs.map(|n| n - 1);
            }
        })
        .contains("sent before")
    );
}
