// SPDX-License-Identifier: Apache-2.0

//! The membership checks catch their violations with the custom core
//! behind them (karyos#976, karyos#1038), not only in the hand-built
//! records of `tests/reconfiguration.rs`: each mutant wraps the custom
//! core's harness adapter ([`Custom`], which takes configuration changes
//! since ADR-0121) and breaks one membership rule the way a faulty core or
//! adapter would, and the run's checks name it. The unmutated adapter
//! passes the same cases. The consensus code itself is not changed: every
//! mutant alters only what the adapter reports or answers.
//!
//! The cases are `harness::membership`'s M1, M5 and M8 with their changes
//! issued once the custom core elected a leader: those scenarios ask at
//! steps the reference core's fixed leader already leads, where an
//! elected core still refuses them as not leading, so the checks would
//! see no change at all. Each case here asserts its changes land.
//!
//! - `QuorumOfVoters`: a leader that acts under voters it never counted
//!   (four strangers added to the bootstrap configuration it leads under,
//!   which no entry carries, so no other check sees them), so its commits
//!   are no majority of them.
//! - `ConfigurationNotFromLog`: a restarted server that comes back under
//!   the bootstrap configuration although its log holds a later one.
//! - `ConfigurationConflict`: a server that reports one configuration
//!   entry as another configuration than the rest of the cluster.
//! - `LearnerBehind`: a leader that answers a refused promotion of a
//!   lagging learner as accepted.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use karyos_sim::harness::check::{self, Violation};
use karyos_sim::harness::core::{
    Change, ChangeRefused, Configuration, ConsensusCore, InstallRefused, Limits, LogView,
    Persisted, Ready, ReadyBuf, Refused, SnapshotBase, TransferRefused, Unsupported,
};
use karyos_sim::harness::custom::Custom;
use karyos_sim::harness::membership::SPARE;
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::workloads::{self, Action, Case, Progress};
use karyos_sim::net::NodeId;

/// The step by which the custom core elected a leader under every case's
/// seed: changes are asked from then on.
const ELECTED: u64 = 100;

/// The leader reports four voters that are not in the cluster in its
/// bootstrap configuration.
const STRANGERS: u8 = 0;
/// A server restarted over a non-empty log reports the bootstrap
/// configuration.
const BOOTSTRAP: u8 = 1;
/// Server 1 reports every configuration entry with one more learner.
const CONFLICT: u8 = 2;
/// The leader answers a promotion it refused as lagging as accepted.
const LAGGING: u8 = 3;

/// Ids no server of the cases has.
const STRANGER_IDS: [NodeId; 2] = [7, 8];
/// Four strangers: with them the three servers are no majority of seven
/// voters.
const UNCOUNTED: [NodeId; 4] = [7, 8, 9, 10];

#[derive(Debug)]
struct Mutant<const KIND: u8> {
    id: NodeId,
    peers: Vec<NodeId>,
    core: Custom,
    /// Whether the core recovered over a log that held entries.
    restarted: bool,
    /// Configurations reported since the recovery.
    reported: std::cell::Cell<u32>,
}

impl<const KIND: u8> Mutant<KIND> {
    fn wrap(id: NodeId, peers: &[NodeId], core: Custom) -> Self {
        let restarted = core.received().is_some();
        Self {
            id,
            peers: peers.to_vec(),
            core,
            restarted,
            reported: std::cell::Cell::new(0),
        }
    }
}

impl<const KIND: u8> ConsensusCore for Mutant<KIND> {
    type Message = <Custom as ConsensusCore>::Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self::wrap(id, peers, Custom::recover(id, peers, log))
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        Custom::recover_with(id, peers, limits, log).map(|core| Self::wrap(id, peers, core))
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.core.propose(command, log)
    }

    fn propose_slice(&mut self, command: &[u8], log: &mut LogView<'_>) -> Result<(), Refused> {
        self.core.propose_slice(command, log)
    }

    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>) {
        self.core.step(from, message, log);
    }

    fn step_lent(&mut self, from: NodeId, message: &mut Self::Message, log: &mut LogView<'_>) {
        self.core.step_lent(from, message, log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.core.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        self.core.ready(log)
    }

    fn ready_into(&mut self, out: &mut ReadyBuf<Self::Message>, log: &mut LogView<'_>) -> bool {
        self.core.ready_into(out, log)
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

    fn configuration_stamp(&self) -> Option<u64> {
        // The node asks every time: what a mutant reports may change
        // without the core's stamp moving (leadership, the first report).
        None
    }

    fn configuration(&self) -> Option<Configuration> {
        let mut configuration = self.core.configuration()?;
        self.reported.set(self.reported.get().saturating_add(1));
        match KIND {
            STRANGERS if self.core.leads() && configuration.index.is_none() => {
                configuration.voters.extend(UNCOUNTED);
            }
            BOOTSTRAP if self.restarted && self.reported.get() == 1 => {
                configuration = Configuration {
                    index: None,
                    voters: self.peers.clone(),
                    outgoing: Vec::new(),
                    learners: Vec::new(),
                };
            }
            CONFLICT if self.id == 1 && configuration.index.is_some() => {
                configuration.learners.extend(STRANGER_IDS);
            }
            _ => {}
        }
        Some(configuration)
    }

    fn compacted(&mut self, base: SnapshotBase, log: &mut LogView<'_>) -> Result<(), Unsupported> {
        self.core.compacted(base, log)
    }

    fn install(&mut self, base: SnapshotBase, log: &mut LogView<'_>) -> Result<(), InstallRefused> {
        self.core.install(base, log)
    }

    fn transfer_leadership(
        &mut self,
        to: NodeId,
        log: &mut LogView<'_>,
    ) -> Result<(), TransferRefused> {
        self.core.transfer_leadership(to, log)
    }

    fn is_configuration_entry(payload: &[u8]) -> bool {
        Custom::is_configuration_entry(payload)
    }

    fn propose_change(
        &mut self,
        change: Change,
        log: &mut LogView<'_>,
    ) -> Result<(), ChangeRefused> {
        match (KIND, change, self.core.propose_change(change, log)) {
            (LAGGING, Change::Promote(_), Err(ChangeRefused::Lagging { .. })) => Ok(()),
            (_, _, result) => result,
        }
    }
}

/// A membership case under the custom core: three voters and the spare,
/// the spare joining at step 1, then `schedule`.
fn case(name: &str, operations: usize, mut schedule: Vec<(u64, Action)>) -> Case {
    let mut case = Case::healthy(name, 3, 2, operations);
    case.spares = 1;
    case.retry_after = 60;
    case.steps = 900;
    case.progress = Progress::Expected;
    schedule.insert(0, (1, Action::Join(SPARE)));
    case.schedule = schedule;
    case
}

/// M1 after the election: the spare added as a learner, then promoted.
fn add_and_promote() -> Case {
    case(
        "custom M1 add and promote",
        12,
        vec![
            (ELECTED, Action::Change(Change::AddLearner(SPARE))),
            (ELECTED + 140, Action::Change(Change::Promote(SPARE))),
        ],
    )
}

/// M5 after the election: the learner cut off is refused promotion as
/// lagging, and promoted once healed and caught up.
fn lagging_learner() -> Case {
    case(
        "custom M5 lagging learner",
        24,
        vec![
            (2, Action::Isolate(SPARE)),
            (ELECTED, Action::Change(Change::AddLearner(SPARE))),
            (ELECTED + 200, Action::Change(Change::Promote(SPARE))),
            (ELECTED + 300, Action::Heal),
            (ELECTED + 500, Action::Change(Change::Promote(SPARE))),
        ],
    )
}

/// M8 after the election: every voter crashes and restarts over a log
/// that holds the learner's configuration entry.
fn restart() -> Case {
    case(
        "custom M8 restart rebuilds the configuration",
        12,
        vec![
            (ELECTED, Action::Change(Change::AddLearner(SPARE))),
            (ELECTED + 100, Action::Crash(0)),
            (ELECTED + 100, Action::Crash(1)),
            (ELECTED + 100, Action::Crash(2)),
            (ELECTED + 110, Action::Restart(0)),
            (ELECTED + 110, Action::Restart(1)),
            (ELECTED + 110, Action::Restart(2)),
        ],
    )
}

/// The changes some server accepted in `outcome`, in order.
fn accepted(outcome: &workloads::Outcome) -> Vec<Change> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Change {
                change,
                result: Ok(()),
                ..
            } => Some(*change),
            _ => None,
        })
        .collect()
}

/// Whether some server refused `change` as lagging in `outcome`.
fn refused_lagging(outcome: &workloads::Outcome, change: Change) -> bool {
    outcome.observations.iter().any(|observation| {
        matches!(
            observation,
            Observation::Change {
                change: asked,
                result: Err(ChangeRefused::Lagging { .. }),
                ..
            } if *asked == change
        )
    })
}

/// The violation the run of `case` under `C` ends with.
fn violation<C: ConsensusCore>(case: &Case) -> Violation {
    let outcome = workloads::run::<C>(case, 1).unwrap();
    outcome.safety.unwrap_err()
}

fn passing<C: ConsensusCore>(case: &Case) -> workloads::Outcome {
    let outcome = workloads::run::<C>(case, 1).unwrap();
    assert_eq!(workloads::pass(case, &outcome), Ok(None), "{}", case.name);
    outcome
}

#[test]
fn the_unmutated_custom_core_passes_the_membership_cases() {
    let promoted = vec![Change::AddLearner(SPARE), Change::Promote(SPARE)];
    let added = vec![Change::AddLearner(SPARE)];
    let outcome = passing::<Custom>(&add_and_promote());
    assert_eq!(accepted(&outcome), promoted);
    let outcome = passing::<Custom>(&lagging_learner());
    assert_eq!(accepted(&outcome), promoted);
    assert!(refused_lagging(&outcome, Change::Promote(SPARE)));
    let outcome = passing::<Custom>(&restart());
    assert_eq!(accepted(&outcome), added);
    // The wrapper alone, with no mutation, passes too.
    for case in [add_and_promote(), lagging_learner(), restart()] {
        let _ = passing::<Mutant<{ u8::MAX }>>(&case);
    }
}

#[test]
fn a_leader_that_commits_without_a_majority_of_its_voters_is_caught() {
    let outcome = workloads::run::<Mutant<STRANGERS>>(&add_and_promote(), 1).unwrap();
    // The run's first verdict is the reply check, which counts the same
    // voters: the leader's first reply is no durable majority of seven.
    assert!(
        matches!(
            outcome.safety,
            Err(Violation::ReplyBeforeDurableMajority { servers: 7, .. })
        ),
        "{:?}",
        outcome.safety
    );
    // The commit check names the commit itself over the same run.
    let violation = check::quorum_of_voters(&outcome.observations).unwrap_err();
    let Violation::QuorumOfVoters {
        holding,
        configuration,
        ..
    } = violation
    else {
        panic!("expected QuorumOfVoters, got {violation:?}");
    };
    assert!(holding < 4, "{holding}");
    assert!(
        configuration.voters.ends_with(&UNCOUNTED),
        "{configuration:?}"
    );
}

#[test]
fn a_server_restarted_under_the_bootstrap_configuration_is_caught() {
    let violation = violation::<Mutant<BOOTSTRAP>>(&restart());
    let Violation::ConfigurationNotFromLog {
        expected, found, ..
    } = violation
    else {
        panic!("expected ConfigurationNotFromLog, got {violation:?}");
    };
    assert!(expected.is_some_and(|expected| expected.learners.contains(&SPARE)));
    assert_eq!(found.index, None);
}

#[test]
fn a_server_that_reports_another_configuration_for_one_entry_is_caught() {
    let violation = violation::<Mutant<CONFLICT>>(&add_and_promote());
    assert!(
        matches!(violation, Violation::ConfigurationConflict { .. }),
        "{violation:?}"
    );
}

#[test]
fn a_leader_that_promotes_a_lagging_learner_is_caught() {
    let case = lagging_learner();
    let violation = violation::<Mutant<LAGGING>>(&case);
    let Violation::LearnerBehind {
        learner,
        behind,
        lag,
        ..
    } = violation
    else {
        panic!("expected LearnerBehind, got {violation:?}");
    };
    assert_eq!(learner, SPARE);
    assert_eq!(lag, case.promotion_lag);
    assert!(behind > lag);
}
