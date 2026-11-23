// SPDX-License-Identifier: Apache-2.0

//! The harness's safety checks still catch their violations with a real
//! core behind them (plan issue 060, karyos#678), not only with the
//! fixture: each mutant wraps the `raft` adapter and breaks one rule the
//! way a faulty core or adapter would, and the run's checks name it. The
//! unmutated adapter passes the same cases.
//!
//! **Candidate-backed here**, each by one mutant: `DivergentPrefix`
//! (divergent application), `ReplyBeforeDurableMajority`, `Contract` (a
//! gapped append), `OldTermCommit`, `Contract` with
//! `TruncateBelowCommit` (applied entries truncated: C4's log refuses
//! it), and `PositionsOutOfOrder` (a core that reports no last index over
//! a written log; karyos#976). **Fault-injected** around the unmutated
//! adapter (karyos#1038), the core real and its surroundings faulty:
//! `AppliedNotDurable` (a driver that applies a Ready's fresh entries),
//! `ReleasedBeforePersisted` (a driver that releases before the sync),
//! `DivergentResponse` (a service that alters one server's answers) and
//! `NotLinearizable` (a client that records a value no one wrote). The
//! other checks of
//! `karyos_sim::harness::check::Violation` keep their fixture negative
//! cases (`crates/karyos-sim/tests/harness.rs`); why each has no mutant
//! here is recorded in `eval/raft-candidates/README.md` (karyos#976).

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_raft_eval::raft_rs::RaftRs;
use karyos_sim::harness::check::Violation;
use karyos_sim::harness::core::{ConsensusCore, DriveFault, LogView, Persisted, Ready, Refused};
use karyos_sim::harness::node::Breach;
use karyos_sim::harness::workloads::{self, Case, W1};
use karyos_sim::net::NodeId;

/// Server 1 applies a different command than the others at each index.
const DIVERGE: u8 = 0;
/// A leader applies, and so answers, what it has only appended.
const EARLY: u8 = 1;
/// Server 0 hands its log entries one index too far.
const GAP: u8 = 2;
/// A leader acts under a term one ahead of the term its entries carry:
/// every commit it reports lands on an entry of an older term than its own.
const OLD: u8 = 3;
/// Server 2 truncates its whole log once the cluster has applied some.
const TRUNCATE: u8 = 4;
/// Each server reports no last index while its log holds entries
/// (karyos#976).
const UNREPORTED: u8 = 5;
/// Server 2's core panics at its tenth Ready (karyos#976): any core's
/// panic, not a particular library's.
const PANICS: u8 = 6;
/// Server 2 never stores a commit, then truncates its whole log once the
/// cluster has applied some (karyos#976): C4's log has no stored commit
/// to refuse the truncation below.
const FORGETS: u8 = 7;

#[derive(Debug)]
struct Mutant<const KIND: u8> {
    id: NodeId,
    core: RaftRs,
    /// The last index handed out to apply.
    handed: u64,
    /// Entries this node has applied (`TRUNCATE`).
    applied: u64,
    /// Whether it truncated already (`TRUNCATE`).
    truncated: bool,
    /// Readys taken (`PANICS`).
    readies: u32,
}

impl<const KIND: u8> Mutant<KIND> {
    fn mutate(
        &mut self,
        mut ready: Ready<<RaftRs as ConsensusCore>::Message>,
    ) -> Ready<<RaftRs as ConsensusCore>::Message> {
        match KIND {
            DIVERGE if self.id == 1 => {
                for entry in &mut ready.committed {
                    if let Some(last) = entry.payload.last_mut() {
                        *last ^= 0xFF;
                    }
                }
            }
            EARLY => {
                let handed = self.handed;
                let mut committed: Vec<_> = ready
                    .committed
                    .drain(..)
                    .filter(|entry| entry.index > handed)
                    .collect();
                if self.core.leads() {
                    let from = committed.last().map_or(handed, |entry| entry.index);
                    committed.extend(
                        ready
                            .entries
                            .iter()
                            .filter(|entry| entry.index > from)
                            .cloned(),
                    );
                }
                if let Some(last) = committed.last() {
                    self.handed = last.index;
                }
                ready.committed = committed;
            }
            GAP if self.id == 0 => {
                for entry in &mut ready.entries {
                    entry.index += 1;
                }
            }
            FORGETS if self.id == 2 => {
                if let Some(state) = ready.hard_state.as_mut() {
                    state.commit = None;
                }
                if !self.truncated && self.applied >= 4 {
                    ready.truncate_from = Some(1);
                    ready.entries.clear();
                    self.truncated = true;
                }
                self.applied += u64::try_from(ready.committed.len()).unwrap();
            }
            TRUNCATE if self.id == 2 => {
                if !self.truncated && self.applied >= 4 {
                    // Drops the entries it applied, and appends nothing:
                    // a core that forgot its log.
                    ready.truncate_from = Some(1);
                    ready.entries.clear();
                    self.truncated = true;
                }
                self.applied += u64::try_from(ready.committed.len()).unwrap();
            }
            _ => {}
        }
        ready
    }
}

impl<const KIND: u8> ConsensusCore for Mutant<KIND> {
    type Message = <RaftRs as ConsensusCore>::Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self {
            id,
            core: RaftRs::recover(id, peers, log),
            handed: 0,
            applied: 0,
            truncated: false,
            readies: 0,
        }
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.core.propose(command, log)
    }

    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>) {
        self.core.step(from, message, log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.core.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        if KIND == PANICS && self.id == 2 {
            self.readies += 1;
            assert!(self.readies < 10, "a core that panics (karyos#976)");
        }
        let ready = self.core.ready(log)?;
        Some(self.mutate(ready))
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.core.advance(persisted, log);
    }

    fn term(&self) -> u64 {
        match KIND {
            OLD if self.core.leads() => self.core.term() + 1,
            _ => self.core.term(),
        }
    }

    fn leads(&self) -> bool {
        self.core.leads()
    }

    fn received(&self) -> Option<u64> {
        match KIND {
            UNREPORTED => None,
            _ => self.core.received(),
        }
    }

    fn committed(&self) -> Option<u64> {
        self.core.committed()
    }
}

fn case() -> Case {
    W1::skeleton().cases().into_iter().nth(1).unwrap()
}

fn violation<C: ConsensusCore>() -> Violation {
    let case = case();
    let outcome = workloads::run::<C>(&case, 1).unwrap();
    outcome.safety.unwrap_err()
}

#[test]
fn the_unmutated_adapter_passes_the_case() {
    let case = case();
    let outcome = workloads::run::<RaftRs>(&case, 1).unwrap();
    assert_eq!(workloads::pass(&case, &outcome), Ok(None));
}

#[test]
fn a_server_that_applies_other_commands_is_caught() {
    let violation = violation::<Mutant<DIVERGE>>();
    assert!(
        matches!(violation, Violation::DivergentPrefix { .. }),
        "{violation:?}"
    );
}

#[test]
fn a_leader_that_answers_before_a_durable_majority_is_caught() {
    let violation = violation::<Mutant<EARLY>>();
    assert!(
        matches!(violation, Violation::ReplyBeforeDurableMajority { .. }),
        "{violation:?}"
    );
}

#[test]
fn a_core_that_breaks_the_log_contract_is_caught() {
    let violation = violation::<Mutant<GAP>>();
    assert!(
        matches!(violation, Violation::Contract { .. }),
        "{violation:?}"
    );
}

#[test]
fn a_leader_that_commits_an_older_term_entry_directly_is_caught() {
    let violation = violation::<Mutant<OLD>>();
    assert!(
        matches!(violation, Violation::OldTermCommit { .. }),
        "{violation:?}"
    );
}

#[test]
fn a_server_that_truncates_applied_entries_is_caught() {
    let violation = violation::<Mutant<TRUNCATE>>();
    assert!(
        matches!(
            violation,
            Violation::Contract {
                node: 2,
                breach: Breach::TruncateBelowCommit,
                ..
            }
        ),
        "{violation:?}"
    );
}

#[test]
fn a_core_that_reports_no_last_index_over_a_written_log_is_caught() {
    let violation = violation::<Mutant<UNREPORTED>>();
    assert!(
        matches!(violation, Violation::PositionsOutOfOrder { .. }),
        "{violation:?}"
    );
}

/// The case with `faults` injected around the unmutated adapter
/// (karyos#1038): the core is real, the driver, disk, service or client
/// is faulty.
fn faulty(faults: workloads::Faults, schedule: Vec<(u64, workloads::Action)>) -> Violation {
    let mut case = case();
    case.faults = faults;
    case.schedule.extend(schedule);
    case.schedule.sort_by_key(|(at, _)| *at);
    let outcome = workloads::run::<RaftRs>(&case, 1).unwrap();
    outcome.safety.unwrap_err()
}

fn drive(node: NodeId, fault: DriveFault) -> workloads::Faults {
    workloads::Faults {
        drive: vec![(node, fault)],
        ..workloads::Faults::default()
    }
}

#[test]
fn a_driver_that_applies_fresh_entries_is_caught() {
    let violation = faulty(drive(1, DriveFault::ApplyFresh), Vec::new());
    assert!(
        matches!(violation, Violation::AppliedNotDurable { .. }),
        "{violation:?}"
    );
}

#[test]
fn a_driver_that_releases_before_persistence_is_caught() {
    let violation = faulty(drive(1, DriveFault::ReleaseEarly), Vec::new());
    assert!(
        matches!(violation, Violation::ReleasedBeforePersisted { .. }),
        "{violation:?}"
    );
}

#[test]
fn a_service_that_answers_differently_is_caught() {
    let faults = workloads::Faults {
        altered_responses: vec![1],
        ..workloads::Faults::default()
    };
    let violation = faulty(faults, Vec::new());
    assert!(
        matches!(violation, Violation::DivergentResponse { .. }),
        "{violation:?}"
    );
}

#[test]
fn a_client_that_reads_a_value_never_written_is_caught() {
    let faults = workloads::Faults {
        corrupt_reads: vec![0],
        ..workloads::Faults::default()
    };
    let violation = faulty(faults, Vec::new());
    assert!(
        matches!(violation, Violation::NotLinearizable(_)),
        "{violation:?}"
    );
}

/// The faulty service's answer is the one sent, not only the one
/// recorded: when every server answers the same altered way, no two
/// responses diverge, and the clients' history is what refuses it.
#[test]
fn an_altered_answer_reaches_the_client() {
    let faults = workloads::Faults {
        altered_responses: vec![0, 1, 2],
        ..workloads::Faults::default()
    };
    let violation = faulty(faults, Vec::new());
    assert!(
        matches!(violation, Violation::NotLinearizable(_)),
        "{violation:?}"
    );
}

/// A core that panics is caught at the harness's core boundary, whatever
/// the core: the run completes, and the panic is its verdict when nothing
/// else names a cause (karyos#976).
#[test]
fn a_core_that_panics_is_caught_and_reported() {
    let case = case();
    let outcome = workloads::run::<Mutant<PANICS>>(&case, 1).unwrap();
    assert!(
        matches!(outcome.safety, Err(Violation::CorePanicked { node: 2 })),
        "{:?}",
        outcome.safety
    );
}

/// A disk that acknowledges file syncs without making them durable loses
/// them at a crash: the restarted server's log no longer holds what it
/// reported durable, and `DurableLost` names it even though the real core
/// may panic over the loss afterwards (karyos#976).
#[test]
fn a_disk_that_lies_about_syncs_loses_durable_entries_at_a_crash() {
    let faults = workloads::Faults {
        lying_disks: vec![1],
        ..workloads::Faults::default()
    };
    let violation = faulty(
        faults,
        vec![
            (300, workloads::Action::Crash(1)),
            (340, workloads::Action::Restart(1)),
        ],
    );
    assert!(
        matches!(violation, Violation::DurableLost { node: 1, .. }),
        "{violation:?}"
    );
}

/// A server that stores no commit lets C4's log truncate entries the
/// cluster applied (karyos#976). The run's first verdict is the contract
/// breach that follows (its next append is no longer the next index), so
/// the check is asked directly over the same run's observations:
/// `CommittedTruncated` names the truncation itself.
#[test]
fn a_server_that_forgets_its_commit_and_truncates_applied_entries_is_caught() {
    let outcome = workloads::run::<Mutant<FORGETS>>(&case(), 1).unwrap();
    assert!(
        matches!(outcome.safety, Err(Violation::Contract { node: 2, .. })),
        "{:?}",
        outcome.safety
    );
    let truncated = karyos_sim::harness::check::durable_kept(&outcome.observations);
    assert!(
        matches!(
            truncated,
            Err(Violation::CommittedTruncated { node: 2, .. })
        ),
        "{truncated:?}"
    );
}
