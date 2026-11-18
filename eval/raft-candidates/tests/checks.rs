// SPDX-License-Identifier: Apache-2.0

//! The harness's safety checks still catch their violations with a real
//! core behind them (plan issue 060, karyos#678), not only with the
//! fixture: each mutant wraps the `raft` adapter and breaks one rule the
//! way a faulty core or adapter would, and the run's checks name it. The
//! unmutated adapter passes the same case.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_raft_eval::raft_rs::RaftRs;
use karyos_sim::harness::check::Violation;
use karyos_sim::harness::core::{ConsensusCore, LogView, Persisted, Ready, Refused};
use karyos_sim::harness::workloads::{self, Case, W1};
use karyos_sim::net::NodeId;

/// Server 1 applies a different command than the others at each index.
const DIVERGE: u8 = 0;
/// A leader applies, and so answers, what it has only appended.
const EARLY: u8 = 1;
/// Server 0 hands its log entries one index too far.
const GAP: u8 = 2;

#[derive(Debug)]
struct Mutant<const KIND: u8> {
    id: NodeId,
    core: RaftRs,
    /// The last index handed out to apply.
    handed: u64,
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
        let ready = self.core.ready(log)?;
        Some(self.mutate(ready))
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.core.advance(persisted, log);
    }

    fn term(&self) -> u64 {
        self.core.term()
    }

    fn leads(&self) -> bool {
        self.core.leads()
    }

    fn received(&self) -> Option<u64> {
        self.core.received()
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
        matches!(
            violation,
            Violation::DivergentPrefix { .. } | Violation::NotLinearizable(_)
        ),
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
