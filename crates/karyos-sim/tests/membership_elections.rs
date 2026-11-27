// SPDX-License-Identifier: Apache-2.0

//! The membership scenarios that need elections (karyos#712;
//! quantstratum-docs: karyos/design/phase-5-cluster-scenarios.md §4),
//! against the custom core's single-server changes (ADR-0121), with every
//! check of the harness enabled:
//!
//! - M2: a follower is removed, then the leader, which steps down once
//!   its removal commits; the rest elect a leader of their own;
//! - M3: a change taken by a leader split into a minority is truncated
//!   everywhere after the heal;
//! - M4: the leader crashes once a change is durable on it alone, on a
//!   majority, or committed, under each crash mode; every server ends
//!   under the same configuration;
//! - M6: every voter is replaced one at a time under load and crashes;
//! - M7: the single-server errata refuse a second change before the new
//!   leader committed an entry of its term (`InProgress`). The custom core
//!   uses single-server changes, so M7 runs rather than being skipped.
//!
//! Each new assertion has a mutant it catches: a core that keeps
//! claiming leadership (two leaders in a term), a core that takes a
//! change the errata refuse, and a core that reports a stale
//! configuration; and the two new checks catch their violations in
//! hand-built records.
//!
//! P5-S1's own checks catch their mutants with the custom core underneath
//! too (karyos#713): `quorum_of_voters` a core that reports its learners
//! as voters, `configuration_from_log` a core that restarts under its
//! bootstrap configuration (M8), and `learner_caught_up` a core that
//! promotes a lagging learner (M5).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::cell::Cell;

use karyos_sim::harness::check::{self, Violation};
use karyos_sim::harness::core::{
    Change, ChangeRefused, Configuration, ConsensusCore, InstallRefused, Limits, LogView,
    Persisted, Ready, Refused, SnapshotBase, TransferRefused, Unsupported,
};
use karyos_sim::harness::custom::Custom;
use karyos_sim::harness::membership::{self, M6_SPARES};
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::workloads::{self, Case, Failed, Outcome};
use karyos_sim::net::NodeId;

/// The seeds every scenario runs.
const CORPUS: [u64; 4] = [0x05, 0x0054, 0xDEAD_BEEF, u64::MAX];

fn passing<C: ConsensusCore>(case: &Case, seed: u64) -> Outcome {
    let outcome = workloads::run::<C>(case, seed).unwrap();
    assert_eq!(
        workloads::pass(case, &outcome),
        Ok(None),
        "{} seed {seed:#x}",
        case.name
    );
    outcome
}

/// The configurations `node` reported, in order.
fn reported(outcome: &Outcome, node: NodeId) -> Vec<Configuration> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Configuration {
                node: at,
                configuration,
                ..
            } if *at == node => Some(configuration.clone()),
            _ => None,
        })
        .collect()
}

/// The answers to `change` other than a non-leader's refusal, in order.
fn answers(outcome: &Outcome, change: Change) -> Vec<Result<(), ChangeRefused>> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Change {
                change: asked,
                result,
                ..
            } if *asked == change && !matches!(result, Err(ChangeRefused::NotLeader(_))) => {
                Some(*result)
            }
            _ => None,
        })
        .collect()
}

/// The server a leader-relative action named `what` acted on.
fn acted_on(outcome: &Outcome, what: &str) -> NodeId {
    outcome
        .observations
        .iter()
        .find_map(|observation| match observation {
            Observation::Triggered { what: w, node, .. } if *w == what => Some(*node),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {what}"))
}

/// The follower M2 removed: the voter missing from the first four-voter
/// configuration reported after the removal.
fn acted_follower(outcome: &Outcome) -> NodeId {
    let at = outcome
        .observations
        .iter()
        .position(|observation| {
            matches!(
                observation,
                Observation::Triggered {
                    what: "follower remove",
                    ..
                }
            )
        })
        .unwrap();
    outcome.observations[at..]
        .iter()
        .find_map(|observation| match observation {
            Observation::Configuration { configuration, .. }
                if configuration.index.is_some() && configuration.voters.len() == 4 =>
            {
                (0..5).find(|id| !configuration.voters.contains(id))
            }
            _ => None,
        })
        .unwrap()
}

/// The last configuration each of `nodes` reported.
fn last_of(outcome: &Outcome, nodes: impl IntoIterator<Item = NodeId>) -> Vec<Configuration> {
    nodes
        .into_iter()
        .map(|node| reported(outcome, node).pop().unwrap())
        .collect()
}

/// Every one of `configurations` has the same voters and learners.
fn agree(configurations: &[Configuration]) -> bool {
    configurations
        .windows(2)
        .all(|pair| (&pair[0].voters, &pair[0].learners) == (&pair[1].voters, &pair[1].learners))
}

#[test]
fn m2_removes_a_follower_then_the_leader_which_steps_down() {
    let case = membership::m2();
    for seed in CORPUS {
        let outcome = passing::<Custom>(&case, seed);
        let follower_leader = acted_on(&outcome, "follower remove");
        let leader = acted_on(&outcome, "leader remove");
        assert_eq!(
            follower_leader, leader,
            "seed {seed:#x}: one leader removed both"
        );
        assert_eq!(
            answers(&outcome, Change::Remove(leader)),
            vec![Ok(())],
            "seed {seed:#x}"
        );
        // A new leader among the three left, after the removal.
        let at = outcome
            .observations
            .iter()
            .position(|observation| {
                matches!(
                    observation,
                    Observation::Triggered {
                        what: "leader remove",
                        ..
                    }
                )
            })
            .unwrap();
        let next = outcome.observations[at..]
            .iter()
            .filter_map(|observation| match observation {
                Observation::Leading { node, .. } => Some(*node),
                _ => None,
            })
            .next_back();
        assert!(
            next.is_some_and(|node| node != leader),
            "seed {seed:#x}: {next:?}"
        );
        // The three voters left, and the two removed servers apart.
        let follower = acted_follower(&outcome);
        let rest: Vec<NodeId> = (0..5)
            .filter(|&id| id != leader && id != follower)
            .collect();
        let last = last_of(&outcome, rest.iter().copied());
        assert!(agree(&last), "seed {seed:#x}: {last:?}");
        assert_eq!(last[0].voters.len(), 3, "seed {seed:#x}");
        assert!(!last[0].voters.contains(&leader), "seed {seed:#x}");
    }
}

#[test]
fn m3_truncates_a_minority_change_everywhere() {
    for remove in [false, true] {
        let case = membership::m3(remove);
        for seed in CORPUS {
            let outcome = passing::<Custom>(&case, seed);
            // The minority's leader took the change.
            let taken = outcome.observations.iter().any(|observation| {
                matches!(observation, Observation::Change { result: Ok(()), .. })
            });
            assert!(
                taken,
                "{} seed {seed:#x}: no leader took the change",
                case.name
            );
            let last = last_of(&outcome, 0..5);
            assert!(agree(&last), "{} seed {seed:#x}: {last:?}", case.name);
            assert_eq!(
                last[0].voters,
                vec![0, 1, 2, 3, 4],
                "{} seed {seed:#x}",
                case.name
            );
            assert!(last[0].learners.is_empty(), "{} seed {seed:#x}", case.name);
        }
    }
}

#[test]
fn m4_keeps_or_truncates_a_change_everywhere_across_a_leader_crash() {
    for seed in CORPUS {
        for case in membership::m4_cases(seed) {
            let outcome = passing::<Custom>(&case, seed);
            assert_eq!(
                answers(&outcome, Change::AddLearner(5)).first(),
                Some(&Ok(())),
                "{:?} seed {seed:#x}",
                case.survives
            );
            let last = last_of(&outcome, 0..5);
            assert!(
                agree(&last),
                "{} {:?} seed {seed:#x}: {last:?}",
                case.name,
                case.survives
            );
        }
    }
    // A change durable on the crashed leader alone is truncated.
    let outcome = passing::<Custom>(
        &membership::m4(
            membership::Reach::Leader,
            karyos_sim::disk::Survives::Synced,
        ),
        0x05,
    );
    assert!(last_of(&outcome, 0..5)[0].learners.is_empty());
    // A committed change is kept.
    let outcome = passing::<Custom>(
        &membership::m4(
            membership::Reach::Committed,
            karyos_sim::disk::Survives::Synced,
        ),
        0x05,
    );
    assert_eq!(last_of(&outcome, 0..5)[0].learners, vec![5]);
}

#[test]
fn m6_replaces_every_voter_one_at_a_time() {
    for seed in CORPUS {
        let case = membership::m6(seed);
        let outcome = passing::<Custom>(&case, seed);
        let ensured = outcome
            .observations
            .iter()
            .filter(|observation| {
                matches!(
                    observation,
                    Observation::Triggered {
                        what: "ensured",
                        ..
                    }
                )
            })
            .count();
        assert_eq!(ensured, 9, "seed {seed:#x}");
        let last = last_of(&outcome, M6_SPARES);
        assert!(agree(&last), "seed {seed:#x}: {last:?}");
        assert_eq!(last[0].voters, M6_SPARES.to_vec(), "seed {seed:#x}");
    }
}

/// M7's answers to the second change, by core.
fn m7_second<C: ConsensusCore>(seed: u64) -> Vec<Result<(), ChangeRefused>> {
    answers(
        &passing::<C>(&membership::m7(), seed),
        Change::AddLearner(6),
    )
}

#[test]
fn m7_the_errata_refuse_a_change_before_the_new_leader_commits() {
    for seed in CORPUS {
        let second = m7_second::<Custom>(seed);
        assert_eq!(
            second.first(),
            Some(&Err(ChangeRefused::InProgress)),
            "seed {seed:#x}: {second:?}"
        );
        assert_eq!(second.last(), Some(&Ok(())), "seed {seed:#x}: {second:?}");
    }
}

// Mutants: the custom core with one rule broken, each caught.

/// What a [`Mutant`] breaks.
const STICKY: u8 = 1;
const NO_ERRATA: u8 = 2;
const FROZEN: u8 = 3;
const AS_VOTERS: u8 = 4;
const NO_LAG: u8 = 5;
const BOOTSTRAP: u8 = 6;

/// The custom core with rule `KIND` broken:
///
/// - [`STICKY`]: it keeps claiming leadership once it led;
/// - [`NO_ERRATA`]: it answers a change the errata refuse as taken;
/// - [`FROZEN`]: it reports the first configuration it had, forever;
/// - [`AS_VOTERS`]: it reports its learners as voters;
/// - [`NO_LAG`]: it answers a promotion refused as lagging as taken;
/// - [`BOOTSTRAP`]: restarted over a log that holds a configuration
///   entry, it reports the bootstrap voters instead.
#[derive(Debug)]
struct Mutant<const KIND: u8> {
    inner: Custom,
    led: Cell<bool>,
    first: Option<Configuration>,
    bootstrap: Configuration,
}

impl<const KIND: u8> Mutant<KIND> {
    fn of(inner: Custom, peers: &[NodeId]) -> Self {
        let first = inner.configuration();
        let mut voters = peers.to_vec();
        voters.sort_unstable();
        Self {
            inner,
            led: Cell::new(false),
            first,
            bootstrap: Configuration {
                index: None,
                voters,
                outgoing: Vec::new(),
                learners: Vec::new(),
            },
        }
    }
}

impl<const KIND: u8> ConsensusCore for Mutant<KIND> {
    type Message = <Custom as ConsensusCore>::Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self::of(Custom::recover(id, peers, log), peers)
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        Custom::recover_with(id, peers, limits, log).map(|inner| Self::of(inner, peers))
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.inner.propose(command, log)
    }

    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>) {
        self.inner.step(from, message, log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.inner.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        self.inner.ready(log)
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.inner.advance(persisted, log);
    }

    fn term(&self) -> u64 {
        self.inner.term()
    }

    fn leads(&self) -> bool {
        let leads = self.inner.leads();
        if KIND == STICKY {
            self.led.set(self.led.get() || leads);
            return self.led.get();
        }
        leads
    }

    fn received(&self) -> Option<u64> {
        self.inner.received()
    }

    fn committed(&self) -> Option<u64> {
        self.inner.committed()
    }

    fn configuration(&self) -> Option<Configuration> {
        if KIND == FROZEN {
            return self.first.clone();
        }
        // Recovered under an entry of its log: it claims the bootstrap.
        if KIND == BOOTSTRAP
            && self
                .first
                .as_ref()
                .is_some_and(|first| first.index.is_some())
        {
            return Some(self.bootstrap.clone());
        }
        let mut configuration = self.inner.configuration();
        if KIND == AS_VOTERS
            && let Some(configuration) = configuration.as_mut()
        {
            let learners = std::mem::take(&mut configuration.learners);
            configuration.voters.extend(learners);
            configuration.voters.sort_unstable();
        }
        configuration
    }

    fn configuration_stamp(&self) -> Option<u64> {
        if KIND == FROZEN || KIND == AS_VOTERS || KIND == BOOTSTRAP {
            return None;
        }
        self.inner.configuration_stamp()
    }

    fn is_configuration_entry(payload: &[u8]) -> bool {
        Custom::is_configuration_entry(payload)
    }

    fn compacted(&mut self, base: SnapshotBase, log: &mut LogView<'_>) -> Result<(), Unsupported> {
        self.inner.compacted(base, log)
    }

    fn install(&mut self, base: SnapshotBase, log: &mut LogView<'_>) -> Result<(), InstallRefused> {
        self.inner.install(base, log)
    }

    fn transfer_leadership(
        &mut self,
        to: NodeId,
        log: &mut LogView<'_>,
    ) -> Result<(), TransferRefused> {
        self.inner.transfer_leadership(to, log)
    }

    fn propose_change(
        &mut self,
        change: Change,
        log: &mut LogView<'_>,
    ) -> Result<(), ChangeRefused> {
        let answer = self.inner.propose_change(change, log);
        if KIND == NO_ERRATA && answer == Err(ChangeRefused::InProgress) {
            return Ok(());
        }
        if KIND == NO_LAG && matches!(answer, Err(ChangeRefused::Lagging { .. })) {
            return Ok(());
        }
        answer
    }
}

#[test]
fn a_core_that_keeps_claiming_leadership_is_caught_as_two_leaders() {
    // The minoritys leader of M3 hears the majoritys term after the
    // heal, and goes on claiming the leadership in it.
    let case = membership::m3(false);
    let caught = CORPUS.iter().any(|&seed| {
        let outcome = workloads::run::<Mutant<STICKY>>(&case, seed).unwrap();
        matches!(
            workloads::pass(&case, &outcome),
            Err(Failed::Safety(violation)) if matches!(*violation, Violation::TwoLeaders { .. })
        )
    });
    assert!(caught, "the sticky leader passed M3");
}

#[test]
fn a_core_ignoring_the_errata_fails_m7() {
    let caught = CORPUS.iter().any(|&seed| {
        let outcome = workloads::run::<Mutant<NO_ERRATA>>(&membership::m7(), seed).unwrap();
        answers(&outcome, Change::AddLearner(6)).first() != Some(&Err(ChangeRefused::InProgress))
    });
    assert!(caught, "M7 did not tell the errata apart");
}

/// A core that reports only its first configuration never shows the
/// removals M2 makes: the assertion that the three left act under three
/// voters fails.
#[test]
fn a_core_reporting_a_stale_configuration_fails_m2() {
    let case = membership::m2();
    for seed in CORPUS {
        let outcome = workloads::run::<Mutant<FROZEN>>(&case, seed).unwrap();
        let last = last_of(&outcome, 0..5);
        assert!(
            last.iter()
                .all(|configuration| configuration.voters.len() == 5),
            "seed {seed:#x}: {last:?}"
        );
    }
}

/// P5-S1's cases on the custom core: its schedule after the warm-up in
/// which a leader is elected (the reference's leader is fixed).
fn warmed(mut case: Case) -> Case {
    for (step, _) in &mut case.schedule {
        *step += membership::SETTLED;
    }
    case.steps += membership::SETTLED;
    case
}

/// Whether some seed of `case`, run on core `C`, fails with a violation
/// `caught` names.
fn caught<C: ConsensusCore>(case: &Case, caught: impl Fn(&Violation) -> bool) -> bool {
    CORPUS.iter().any(|&seed| {
        let outcome = workloads::run::<C>(case, seed).unwrap();
        matches!(
            workloads::pass(case, &outcome),
            Err(Failed::Safety(violation)) if caught(&violation)
        )
    })
}

/// The seed of the learners-as-voters check: its scenario needs node 0,
/// which M1's split puts with the learner, to lead, and the check is
/// caught exactly on the seeds where it does. Was any of [`CORPUS`]: since
/// karyos 4014992f the election timeouts are drawn from the run seed, and
/// none of the corpus seeds elects node 0 any more; 0x04, the first seed
/// from 1 that does.
const AS_VOTERS_SEED: u64 = 0x04;

#[test]
fn quorum_of_voters_catches_learners_reported_as_voters() {
    let case = warmed(membership::m1());
    let outcome = workloads::run::<Mutant<AS_VOTERS>>(&case, AS_VOTERS_SEED).unwrap();
    // The scenario is reached: node 0 leads, on the learner's side.
    let leader = outcome
        .observations
        .iter()
        .find_map(|observation| match observation {
            Observation::Leading { node, .. } => Some(*node),
            _ => None,
        });
    assert_eq!(
        leader,
        Some(0),
        "seed {AS_VOTERS_SEED:#x}: node 0 did not lead"
    );
    assert!(
        matches!(
            workloads::pass(&case, &outcome),
            Err(Failed::Safety(violation)) if matches!(*violation, Violation::QuorumOfVoters { .. })
        ),
        "seed {AS_VOTERS_SEED:#x}: the learners counted as voters were not caught"
    );
}

#[test]
fn configuration_from_log_catches_a_restart_under_the_bootstrap() {
    assert!(caught::<Mutant<BOOTSTRAP>>(
        &warmed(membership::m8()),
        |violation| { matches!(violation, Violation::ConfigurationNotFromLog { .. }) }
    ));
}

#[test]
fn learner_caught_up_catches_a_lagging_promotion() {
    assert!(caught::<Mutant<NO_LAG>>(
        &warmed(membership::m5()),
        |violation| { matches!(violation, Violation::LearnerBehind { .. }) }
    ));
}

// Hand-built records: each new check catches its violation.

fn leading(node: NodeId, term: u64) -> Observation {
    Observation::Leading { node, term }
}

#[test]
fn two_leaders_of_one_term_are_caught() {
    assert_eq!(
        check::one_leader_per_term(&[leading(0, 3), leading(1, 2), leading(1, 3)]),
        Err(Violation::TwoLeaders {
            term: 3,
            first: 0,
            second: 1
        })
    );
    assert_eq!(
        check::one_leader_per_term(&[leading(0, 3), leading(0, 3), leading(1, 4)]),
        Ok(())
    );
}

fn reports(node: NodeId, index: u64, voters: &[NodeId]) -> Observation {
    Observation::Configuration {
        node,
        configuration: Configuration {
            index: Some(index),
            voters: voters.to_vec(),
            outgoing: Vec::new(),
            learners: Vec::new(),
        },
        entry_term: Some(1),
    }
}

fn commit(node: NodeId, leader: bool, index: u64) -> Observation {
    Observation::Commit {
        node,
        term: 1,
        leader,
        index,
        entry_term: 1,
    }
}

#[test]
fn a_removed_leader_that_goes_on_leading_is_caught() {
    // 0 removes itself at 10, commits it, and steps down: fine.
    let steps_down = [reports(0, 10, &[1, 2, 3]), commit(0, true, 10)];
    assert_eq!(check::removed_leader_steps_down(&steps_down), Ok(()));
    // It commits past its removal as leader.
    let commits_on = [
        reports(0, 10, &[1, 2, 3]),
        commit(0, true, 10),
        commit(0, true, 12),
    ];
    assert_eq!(
        check::removed_leader_steps_down(&commits_on),
        Err(Violation::RemovedLeaderLed {
            node: 0,
            removed_at: 10
        })
    );
    // It leads again.
    let leads_again = [
        reports(0, 10, &[1, 2, 3]),
        commit(0, true, 10),
        leading(0, 5),
    ];
    assert!(check::removed_leader_steps_down(&leads_again).is_err());
    // Added back as a voter, it may lead.
    let back = [
        reports(0, 10, &[1, 2, 3]),
        commit(0, true, 10),
        reports(0, 20, &[0, 1, 2, 3]),
        leading(0, 6),
    ];
    assert_eq!(check::removed_leader_steps_down(&back), Ok(()));
}
