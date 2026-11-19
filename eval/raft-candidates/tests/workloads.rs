// SPDX-License-Identifier: Apache-2.0

//! ADR-0043's workloads W1 to W6 over both candidates' adapters, `raft`
//! 0.7.0 (plan issue 060, karyos#678) and `openraft` 0.10.0-alpha.37 on
//! the manually pumped executor (plan issue 076, karyos#690), with the
//! same cases, seeds and parameters for both: what passes, which gaps are
//! allowed, and what is not demonstrated yet, each asserted rather than
//! assumed.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_raft_eval::openraft_core::OpenRaft;
use karyos_raft_eval::raft_rs::{MAX_IN_FLIGHT_ENTRIES, RaftRs};
use karyos_sim::harness::core::{ConsensusCore, Limit, Limits, Unsupported};
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::workloads::{
    self, Failed, Liveness, RunError, W1, W2, W3, W3Fault, W4, W5, W6,
};

/// Seeds every sweep runs.
const SEEDS: [u64; 4] = [1, 0xC5, 0x0043, 0xDEAD_BEEF];

fn w1_passes<C: ConsensusCore>() {
    for seed in SEEDS {
        for case in W1::skeleton().cases() {
            let outcome = workloads::run::<C>(&case, seed).unwrap();
            assert_eq!(
                workloads::pass(&case, &outcome),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

/// W3: every fault keeps safety, and every case but the leader crash
/// completes. The leader crash is a liveness gap of the harness's client,
/// not of the core: server 0 crashes at step 2 and never restarts, the
/// clients start on it and re-target only when a server redirects them,
/// so they never reach the leader servers 1 and 2 elect.
fn w3_safety_holds_and_only_the_unrestarted_crash_is_a_gap<C: ConsensusCore>() {
    for seed in SEEDS {
        for (fault, case) in W3::skeleton().faults.iter().zip(W3::skeleton().cases()) {
            let outcome = workloads::run::<C>(&case, seed).unwrap();
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

/// W4: every cut keeps safety; a single failed flush recovers, and the
/// repeated failed flushes (a lost durable majority) are a gap with no
/// leader, as with the reference.
fn w4_passes_and_a_lost_majority_is_a_gap<C: ConsensusCore>() {
    for seed in SEEDS {
        for case in W4::skeleton(seed).cases() {
            let outcome = workloads::run::<C>(&case, seed).unwrap();
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

fn w6_replays_every_seed<C: ConsensusCore>() {
    let w6 = W6::skeleton();
    for case in w6.cases() {
        for seed in SEEDS {
            assert_eq!(
                w6.pass::<C>(&case, seed).unwrap(),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
    }
}

/// The same seed reproduces the same run, observations included: raft-rs's
/// election timeout draw has one value (see the adapter).
fn a_seed_reproduces_its_run<C: ConsensusCore>() {
    let mut cases = W1::skeleton().cases();
    cases.extend(W3::skeleton().cases());
    let mut cases: Vec<_> = cases.into_iter().step_by(3).collect();
    cases.extend(W2::skeleton().cases().unwrap());
    for case in &cases {
        for seed in SEEDS {
            let first = workloads::run::<C>(case, seed).unwrap();
            let second = workloads::run::<C>(case, seed).unwrap();
            assert_eq!(first, second, "{} seed {seed}", case.name);
        }
    }
}

/// W2's skeleton under the declared limits (karyos#679), the same cases
/// and limits for both cores: the queue's burst is refused with a typed
/// `Backpressure(Queue)` and nothing else is; every case keeps safety; and
/// each case passes, or fails with the typed reason this function is told
/// to expect for that core (`short`: the slow-follower cases whose leader
/// did not commit the required entries while the follower was cut off).
fn w2<C: ConsensusCore>(short: &[&str]) {
    let w2 = W2::skeleton();
    let cases = w2.cases().unwrap();
    assert_eq!(cases.len(), 5);
    for case in &cases {
        let outcome = workloads::run::<C>(case, 1).unwrap();
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
        } else {
            assert!(pushed.is_empty(), "{}: {pushed:?}", case.name);
        }
        // Not demonstrated, whatever its result (karyos#963 review): a
        // lagging follower catches up from the adapter's own mirror of the
        // log, never through the harness's metered `LogView`, so a read
        // past `log_read_bytes` would go unseen. Its safety is asserted
        // above; it is never counted a pass.
        if case.name.contains("log-read burst") {
            continue;
        }
        let result = workloads::pass(case, &outcome);
        if short.iter().any(|name| case.name.contains(name)) {
            assert!(
                matches!(result, Err(Failed::NotBehind { .. })),
                "{}: {result:?}",
                case.name
            );
        } else {
            assert_eq!(result, Ok(None), "{}", case.name);
        }
    }
}

fn w2_raft<C: ConsensusCore>() {
    w2::<C>(&[]);
}

/// OpenRaft commits fewer entries than W2 requires while the follower is
/// cut off (787 of 1,000 and 842 of 1,024 at seed 1): the case cannot
/// establish its slow follower, a typed failure, not a pass.
fn w2_openraft<C: ConsensusCore>() {
    w2::<C>(&["slow follower"]);
}

/// The byte cap reached before the entry cap (karyos#963 review): 256 B
/// values against 8 entries and 1 KiB in flight, a share of 128 B per
/// entry. Neither adapter meters a follower's bytes in flight, so each
/// refuses every command over its share, typed `Backpressure(InFlightBytes)`,
/// rather than let a full window of entries pass the byte cap. Safety
/// holds and no other limit is named.
fn w2_byte_cap_binds_before_the_entry_cap<C: ConsensusCore>() {
    let w2 = W2 {
        payload_bytes: 256,
        limits: Limits {
            in_flight_entries: 8,
            in_flight_bytes: 1024,
            ..W2::skeleton().limits
        },
        ..W2::skeleton()
    };
    let case = w2.cases().unwrap().into_iter().next().unwrap();
    let outcome = workloads::run::<C>(&case, 1).unwrap();
    assert!(outcome.safety.is_ok(), "{}", case.name);
    let pushed: Vec<_> = outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Backpressure { limit, .. } => Some(*limit),
            _ => None,
        })
        .collect();
    assert!(!pushed.is_empty(), "{}", case.name);
    assert!(
        pushed.iter().all(|limit| *limit == Limit::InFlightBytes),
        "{}: {pushed:?}",
        case.name
    );
}

/// An entry cap the adapters cannot take is refused before startup as
/// unsupported limits, never a core that cannot elect nor a panic on
/// allocation: none, one past `MAX_IN_FLIGHT_ENTRIES`, and `u64::MAX`
/// (karyos#963 review). The cap's edge is taken.
fn an_entry_cap_the_adapters_cannot_take_is_unsupported<C: ConsensusCore>() {
    let base = W2::skeleton().cases().unwrap().into_iter().next().unwrap();
    let with = |cap| {
        let mut case = base.clone();
        case.limits = Some(Limits {
            in_flight_entries: cap,
            ..W2::skeleton().limits
        });
        case
    };
    for cap in [0, MAX_IN_FLIGHT_ENTRIES + 1, u64::MAX] {
        assert!(
            matches!(
                workloads::run::<C>(&with(cap), 1),
                Err(RunError::Unsupported(Unsupported))
            ),
            "cap {cap}"
        );
    }
    assert!(workloads::run::<C>(&with(MAX_IN_FLIGHT_ENTRIES), 1).is_ok());
}

/// W5 (karyos#679). Its snapshot cases need compaction and a snapshot
/// installed through the core, which neither adapter takes: they are
/// refused as not demonstrated (`Unsupported`), never passed, and wait
/// for plan issue 065 (snapshot install through the core). Its retry after
/// a lost reply and a leader change runs and keeps safety; its retry is
/// not shown for either candidate, because the frozen schedule (reply cut
/// at step 12, handover from server 0 to 1 at step 22) assumes the
/// reference's leader, server 0 from step 0, while the candidates elect
/// their first leader later (raft-rs) or elsewhere (OpenRaft): moved 30
/// steps later, the same case shows the retry for raft-rs. The schedule is
/// the comparison's to freeze (plan issue 062), not tuned here.
fn w5_is_not_demonstrated_yet<C: ConsensusCore>() {
    for case in W5::skeleton().cases().unwrap() {
        let run = workloads::run::<C>(&case, 1);
        if case.compaction.is_some() {
            assert!(
                matches!(run, Err(RunError::Unsupported(Unsupported))),
                "{}",
                case.name
            );
        } else {
            let outcome = run.unwrap();
            assert!(outcome.safety.is_ok(), "{}", case.name);
            assert!(
                matches!(
                    workloads::pass(&case, &outcome),
                    Ok(None) | Err(Failed::NotShown(_))
                ),
                "{}",
                case.name
            );
        }
    }
}

/// One test per workload and core: the same functions, the same cases.
macro_rules! suite {
    ($module:ident, $core:ty) => {
        mod $module {
            use super::*;

            #[test]
            fn w1_passes() {
                super::w1_passes::<$core>();
            }

            #[test]
            fn w3_safety_holds_and_only_the_unrestarted_crash_is_a_gap() {
                super::w3_safety_holds_and_only_the_unrestarted_crash_is_a_gap::<$core>();
            }

            #[test]
            fn w4_passes_and_a_lost_majority_is_a_gap() {
                super::w4_passes_and_a_lost_majority_is_a_gap::<$core>();
            }

            #[test]
            fn w6_replays_every_seed() {
                super::w6_replays_every_seed::<$core>();
            }

            #[test]
            fn a_seed_reproduces_its_run() {
                super::a_seed_reproduces_its_run::<$core>();
            }

            #[test]
            fn w2_byte_cap_binds_before_the_entry_cap() {
                super::w2_byte_cap_binds_before_the_entry_cap::<$core>();
            }

            #[test]
            fn an_entry_cap_the_adapters_cannot_take_is_unsupported() {
                super::an_entry_cap_the_adapters_cannot_take_is_unsupported::<$core>();
            }

            #[test]
            fn w5_is_not_demonstrated_yet() {
                super::w5_is_not_demonstrated_yet::<$core>();
            }
        }
    };
}

suite!(raft, RaftRs);
suite!(openraft, OpenRaft);

#[test]
fn raft_w2_honours_its_limits() {
    w2_raft::<RaftRs>();
}

#[test]
fn openraft_w2_honours_its_limits_and_reports_a_short_gap() {
    w2_openraft::<OpenRaft>();
}
