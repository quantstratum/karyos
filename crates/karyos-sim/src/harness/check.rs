// SPDX-License-Identifier: Apache-2.0

//! The checks of a recorded run (ADR-0043, Harness): the clients' history
//! through C3's checker, and the safety properties over the
//! [`Observation`]s. Each returns the first [`Violation`] it finds.
//!
//! **Membership** (phase 5; quantstratum-docs:
//! karyos/design/phase-5-cluster-scenarios.md §5). Where a core reports
//! its configuration, a majority is one of the voters the reporting
//! server acts under, never of every server, and [`membership`] adds
//! three checks: [`quorum_of_voters`], [`configuration_from_log`] and
//! [`learner_caught_up`]. A core with static membership reports none, and
//! they pass at once.

use std::collections::{BTreeMap, BTreeSet};

use karyos_cluster::Entry;

use super::core::{Applying, Change, Configuration, Release, Step};
use super::node::{Breach, Observation, Op, Positions, Ret, ServiceModel};
use crate::lin::{self, History, HistoryError, Limit, Verdict};
use crate::net::NodeId;

/// A property a run broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// The clients' history is not linearizable.
    NotLinearizable(lin::Counterexample<Op, Ret>),
    /// C3 gave up before deciding.
    Undecided {
        /// The configurations it explored.
        explored: u64,
    },
    /// The history is not well formed.
    MalformedHistory(HistoryError),
    /// Two servers applied different entries at one index.
    DivergentPrefix {
        /// The index.
        index: u64,
        /// One server and its entry.
        first: (NodeId, Entry),
        /// The other and its entry.
        second: (NodeId, Entry),
    },
    /// A leader's commit index moved directly to an entry of an older
    /// term.
    OldTermCommit {
        /// The leader.
        node: NodeId,
        /// Its term.
        term: u64,
        /// The commit index.
        index: u64,
        /// The entry's term.
        entry_term: u64,
    },
    /// A server released its reply for the entry at `index` while fewer
    /// than a majority of the servers held that entry (its index and
    /// term) durably.
    ReplyBeforeDurableMajority {
        /// The server.
        node: NodeId,
        /// The client.
        client: NodeId,
        /// The entry's index.
        index: u64,
        /// The entry's term.
        term: u64,
        /// The servers that held it durably.
        durable: usize,
        /// The servers.
        servers: usize,
    },
    /// A server's positions out of their order.
    PositionsOutOfOrder {
        /// The server.
        node: NodeId,
        /// Its positions.
        positions: Positions,
    },
    /// A server sent a message that waits for persistence before the
    /// log held what it waits for.
    ReleasedBeforePersisted {
        /// The server.
        node: NodeId,
        /// The receiver.
        to: NodeId,
        /// What it waited for, and what the log held.
        release: Release,
    },
    /// A server's core broke C4's contract.
    Contract {
        /// The server.
        node: NodeId,
        /// What it broke.
        breach: Breach,
        /// The log's error.
        error: String,
    },
    /// A restarted server's log lacks an entry it held durably before.
    DurableLost {
        /// The server.
        node: NodeId,
        /// The entry's index.
        index: u64,
        /// The entry's term.
        term: u64,
    },
    /// A server crashed holding durable entries and was not restarted, so
    /// whether it kept them is unknown.
    Unverified {
        /// The server.
        node: NodeId,
    },
    /// A server applied an entry its log did not hold durably.
    AppliedNotDurable {
        /// The server.
        node: NodeId,
        /// The entry's index.
        index: u64,
        /// What the log held then.
        applying: Applying,
    },
    /// Two servers answered the entry at one index differently.
    DivergentResponse {
        /// The index.
        index: u64,
        /// One server.
        first: NodeId,
        /// The other.
        second: NodeId,
    },
    /// A server truncated an entry the cluster had applied.
    CommittedTruncated {
        /// The server.
        node: NodeId,
        /// The entry's index.
        index: u64,
    },
    /// A leader committed an entry fewer than a majority of its voters
    /// held durably: learners or strangers were counted.
    QuorumOfVoters {
        /// The leader.
        node: NodeId,
        /// The commit index.
        index: u64,
        /// The entry's term.
        term: u64,
        /// The voters that held it durably.
        holding: usize,
        /// The configuration it acted under.
        configuration: Box<Configuration>,
    },
    /// A restarted server's configuration is not the latest one its log
    /// holds.
    ConfigurationNotFromLog {
        /// The server.
        node: NodeId,
        /// The latest configuration in its reopened log, `None` for the
        /// bootstrap one.
        expected: Option<Box<Configuration>>,
        /// What its core reported.
        found: Box<Configuration>,
    },
    /// One configuration entry (its index and term) reported as two
    /// configurations.
    ConfigurationConflict {
        /// The entry's index.
        index: u64,
        /// The entry's term.
        term: u64,
    },
    /// A leader promoted a learner further behind its commit than the lag.
    LearnerBehind {
        /// The leader.
        node: NodeId,
        /// The learner.
        learner: NodeId,
        /// Entries the learner held durably behind the leader's commit.
        behind: u64,
        /// The promotion lag.
        lag: u64,
    },
}

/// The configurations C3 may explore per check.
pub const LIMIT: Limit = Limit {
    max_configurations: 1_000_000,
};

/// The clients' `history` against the test service's model.
///
/// # Errors
///
/// [`Violation::NotLinearizable`], [`Violation::Undecided`] or
/// [`Violation::MalformedHistory`].
pub fn linearizable(history: &History<Op, Ret>) -> Result<(), Violation> {
    match lin::check(&ServiceModel, history, LIMIT) {
        Ok(Verdict::Linearizable(_)) => Ok(()),
        Ok(Verdict::NotLinearizable(counterexample)) => {
            Err(Violation::NotLinearizable(counterexample))
        }
        Ok(Verdict::Undecided { explored }) => Err(Violation::Undecided { explored }),
        Err(error) => Err(Violation::MalformedHistory(error)),
    }
}

/// Every two servers applied the same entry at every index both applied.
///
/// # Errors
///
/// [`Violation::DivergentPrefix`].
pub fn committed_prefixes_agree(observations: &[Observation]) -> Result<(), Violation> {
    let mut applied: BTreeMap<u64, (NodeId, Entry)> = BTreeMap::new();
    for observation in observations {
        let Observation::Applied { node, entry, .. } = observation else {
            continue;
        };
        match applied.get(&entry.index) {
            Some((first, seen)) if seen != entry => {
                return Err(Violation::DivergentPrefix {
                    index: entry.index,
                    first: (*first, seen.clone()),
                    second: (*node, entry.clone()),
                });
            }
            Some(_) => {}
            None => {
                let _ = applied.insert(entry.index, (*node, entry.clone()));
            }
        }
    }
    Ok(())
}

/// A leader's commit index moves only to an entry of its own term; older
/// entries commit with it, indirectly (Raft §5.4.2).
///
/// # Errors
///
/// [`Violation::OldTermCommit`].
pub fn no_old_term_direct_commit(observations: &[Observation]) -> Result<(), Violation> {
    for observation in observations {
        if let Observation::Commit {
            node,
            term,
            leader: true,
            index,
            entry_term,
        } = observation
            && entry_term != term
        {
            return Err(Violation::OldTermCommit {
                node: *node,
                term: *term,
                index: *index,
                entry_term: *entry_term,
            });
        }
    }
    Ok(())
}

/// What each server holds durably: index to term, from its persisted
/// Readys and its reopened log. A crashed server's durable entries still
/// count: they are on its disk, and its restart shows them
/// ([`durable_kept`]).
#[derive(Debug, Default)]
struct DurableLogs {
    logs: BTreeMap<NodeId, BTreeMap<u64, u64>>,
}

impl DurableLogs {
    /// Takes `observation` in; returns the entries a truncation removed.
    fn observe(&mut self, observation: &Observation) -> Vec<(NodeId, u64, u64)> {
        match observation {
            Observation::Drive {
                node,
                step:
                    Step::Persisted {
                        truncated_from,
                        appended,
                        ..
                    },
            } => {
                let log = self.logs.entry(*node).or_default();
                let removed = truncated_from
                    .map(|from| log.split_off(&from))
                    .unwrap_or_default();
                log.extend(appended.iter().copied());
                removed
                    .into_iter()
                    .map(|(index, term)| (*node, index, term))
                    .collect()
            }
            Observation::Recovered {
                node,
                entries,
                durable,
            } => {
                let log = entries
                    .iter()
                    .copied()
                    .filter(|(index, _)| Some(*index) <= *durable)
                    .collect();
                let _ = self.logs.insert(*node, log);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// The servers holding entry `index` of `term` durably.
    fn holding(&self, index: u64, term: u64) -> usize {
        self.logs
            .values()
            .filter(|log| log.get(&index) == Some(&term))
            .count()
    }

    /// The servers of `members` holding entry `index` of `term` durably.
    fn holding_among(&self, members: &[NodeId], index: u64, term: u64) -> usize {
        members
            .iter()
            .filter(|member| {
                self.logs
                    .get(member)
                    .is_some_and(|log| log.get(&index) == Some(&term))
            })
            .count()
    }
}

/// The set of `configuration` that lacks a durable majority holding entry
/// `index` of `term`: its voters (also when there are none), else its
/// outgoing voters under joint consensus; `None` when both hold it.
fn short_of_majority<'a>(
    logs: &DurableLogs,
    configuration: &'a Configuration,
    index: u64,
    term: u64,
) -> Option<&'a [NodeId]> {
    let majority =
        |members: &[NodeId]| logs.holding_among(members, index, term) > members.len() / 2;
    if configuration.voters.is_empty() || !majority(&configuration.voters) {
        return Some(&configuration.voters);
    }
    (!configuration.outgoing.is_empty() && !majority(&configuration.outgoing))
        .then_some(configuration.outgoing.as_slice())
}

/// Whether a durable majority of `configuration`'s voters, and of its
/// outgoing voters under joint consensus, holds entry `index` of `term`.
fn voters_hold(logs: &DurableLogs, configuration: &Configuration, index: u64, term: u64) -> bool {
    short_of_majority(logs, configuration, index, term).is_none()
}

/// Each server's configuration, from its last [`Observation::Configuration`].
#[derive(Debug, Default)]
struct Configurations {
    current: BTreeMap<NodeId, Configuration>,
}

impl Configurations {
    fn observe(&mut self, observation: &Observation) {
        if let Observation::Configuration {
            node,
            configuration,
            ..
        } = observation
        {
            let _ = self.current.insert(*node, configuration.clone());
        }
    }

    fn of(&self, node: NodeId) -> Option<&Configuration> {
        self.current.get(&node)
    }
}

/// Every reply a server releases is for an entry (its index and term) a
/// majority of the `servers` held durably at that moment; where the server
/// reports its configuration, a majority of its voters (see the module).
///
/// # Errors
///
/// [`Violation::ReplyBeforeDurableMajority`].
pub fn durable_majority_before_reply(
    observations: &[Observation],
    servers: usize,
) -> Result<(), Violation> {
    let mut logs = DurableLogs::default();
    let mut configurations = Configurations::default();
    for observation in observations {
        let _ = logs.observe(observation);
        configurations.observe(observation);
        if let Observation::Reply {
            node,
            client,
            index,
            term,
        } = observation
        {
            // Under a configuration, the set short of its majority: the
            // voters, or the outgoing voters under joint consensus.
            let (durable, servers) = match configurations.of(*node) {
                Some(configuration) => {
                    match short_of_majority(&logs, configuration, *index, *term) {
                        Some(short) => (logs.holding_among(short, *index, *term), short.len()),
                        None => continue,
                    }
                }
                None => (logs.holding(*index, *term), servers),
            };
            if durable <= servers / 2 {
                return Err(Violation::ReplyBeforeDurableMajority {
                    node: *node,
                    client: *client,
                    index: *index,
                    term: *term,
                    durable,
                    servers,
                });
            }
        }
    }
    Ok(())
}

/// A restarted server's reopened log holds every entry it held durably
/// before the crash, and no server truncates an entry the cluster applied.
/// A server is down from its crash, or from a drive error that stopped it
/// while up, to its next reopened log. A down server whose log then fails
/// to open lost what it held; one still down at the end leaves what it
/// held unverified, so a run should restart every crashed or stopped
/// server before its checks.
///
/// # Errors
///
/// [`Violation::DurableLost`], [`Violation::Unverified`] and
/// [`Violation::CommittedTruncated`].
pub fn durable_kept(observations: &[Observation]) -> Result<(), Violation> {
    let mut logs = DurableLogs::default();
    let mut applied: BTreeMap<u64, u64> = BTreeMap::new();
    let mut down: BTreeSet<NodeId> = BTreeSet::new();
    for observation in observations {
        match observation {
            Observation::Crashed { node } => {
                let _ = down.insert(*node);
            }
            Observation::OpenFailed { node, .. } if down.contains(node) => {
                if let Some((index, term)) = logs.logs.get(node).and_then(|log| log.iter().next()) {
                    return Err(Violation::DurableLost {
                        node: *node,
                        index: *index,
                        term: *term,
                    });
                }
            }
            // A drive error stops a server that is up: what it held waits
            // for its restart, as after a crash.
            Observation::OpenFailed { node, .. } | Observation::Contract { node, .. } => {
                let _ = down.insert(*node);
            }
            Observation::Applied { entry, .. } => {
                let _ = applied.insert(entry.index, entry.term);
            }
            Observation::Recovered { node, entries, .. } => {
                let _ = down.remove(node);
                if let Some(before) = logs.logs.get(node) {
                    let reopened: BTreeMap<u64, u64> = entries.iter().copied().collect();
                    if let Some((index, term)) = before
                        .iter()
                        .find(|(index, term)| reopened.get(index) != Some(term))
                    {
                        return Err(Violation::DurableLost {
                            node: *node,
                            index: *index,
                            term: *term,
                        });
                    }
                }
            }
            _ => {}
        }
        for (node, index, term) in logs.observe(observation) {
            if applied.get(&index) == Some(&term) {
                return Err(Violation::CommittedTruncated { node, index });
            }
        }
    }
    for node in down {
        if logs.logs.get(&node).is_some_and(|log| !log.is_empty()) {
            return Err(Violation::Unverified { node });
        }
    }
    Ok(())
}

/// Every server applies only an entry its own log holds durably, the same
/// term at its index.
///
/// # Errors
///
/// [`Violation::AppliedNotDurable`].
pub fn applied_durable(observations: &[Observation]) -> Result<(), Violation> {
    for observation in observations {
        if let Observation::Applied {
            node,
            entry,
            applying,
            ..
        } = observation
            && !(applying.durable >= Some(entry.index) && applying.logged_term == Some(entry.term))
        {
            return Err(Violation::AppliedNotDurable {
                node: *node,
                index: entry.index,
                applying: *applying,
            });
        }
    }
    Ok(())
}

/// Every server that applied the entry at an index answered it in the
/// same canonical response bytes.
///
/// # Errors
///
/// [`Violation::DivergentResponse`].
pub fn responses_agree(observations: &[Observation]) -> Result<(), Violation> {
    let mut responses: BTreeMap<u64, (NodeId, &Option<Vec<u8>>)> = BTreeMap::new();
    for observation in observations {
        let Observation::Applied {
            node,
            entry,
            response,
            ..
        } = observation
        else {
            continue;
        };
        match responses.get(&entry.index) {
            Some((first, seen)) if *seen != response => {
                return Err(Violation::DivergentResponse {
                    index: entry.index,
                    first: *first,
                    second: *node,
                });
            }
            Some(_) => {}
            None => {
                let _ = responses.insert(entry.index, (*node, response));
            }
        }
    }
    Ok(())
}

/// No server's core broke C4's contract.
///
/// # Errors
///
/// [`Violation::Contract`].
pub fn no_contract_breach(observations: &[Observation]) -> Result<(), Violation> {
    for observation in observations {
        if let Observation::Contract {
            node,
            breach,
            error,
        } = observation
        {
            return Err(Violation::Contract {
                node: *node,
                breach: *breach,
                error: error.clone(),
            });
        }
    }
    Ok(())
}

/// The five positions keep their order at every server: durable at most
/// written at most received, and applied at most committed at most
/// written.
///
/// # Errors
///
/// [`Violation::PositionsOutOfOrder`].
pub fn positions_ordered(observations: &[Observation]) -> Result<(), Violation> {
    for observation in observations {
        let Observation::Positions { node, positions } = observation else {
            continue;
        };
        let Positions {
            received,
            written,
            durable,
            committed,
            applied,
        } = *positions;
        // `None` is below every index.
        if !(durable <= written
            && written <= received
            && applied <= committed
            && committed <= written)
        {
            return Err(Violation::PositionsOutOfOrder {
                node: *node,
                positions: *positions,
            });
        }
    }
    Ok(())
}

/// Every message that waits for persistence left when the log held what
/// it waits for: its Ready's last entry durable, its hard state stored.
///
/// # Errors
///
/// [`Violation::ReleasedBeforePersisted`].
pub fn released_after_persistence(observations: &[Observation]) -> Result<(), Violation> {
    for observation in observations {
        if let Observation::Released { node, to, release } = observation {
            let durable = release.durable >= release.needs;
            let stored =
                release.needs_state.is_none() || release.stored_state == release.needs_state;
            if !(durable && stored) {
                return Err(Violation::ReleasedBeforePersisted {
                    node: *node,
                    to: *to,
                    release: *release,
                });
            }
        }
    }
    Ok(())
}

/// A leader's commit index moves only to an entry a durable majority of
/// the voters it acts under holds, of both sets under joint consensus: a
/// learner never counts (ADR-0054). A server with no configuration is not
/// checked.
///
/// # Errors
///
/// [`Violation::QuorumOfVoters`].
pub fn quorum_of_voters(observations: &[Observation]) -> Result<(), Violation> {
    let mut logs = DurableLogs::default();
    let mut configurations = Configurations::default();
    for observation in observations {
        let _ = logs.observe(observation);
        configurations.observe(observation);
        if let Observation::Commit {
            node,
            leader: true,
            index,
            entry_term,
            ..
        } = observation
            && let Some(configuration) = configurations.of(*node)
            && !voters_hold(&logs, configuration, *index, *entry_term)
        {
            return Err(Violation::QuorumOfVoters {
                node: *node,
                index: *index,
                term: *entry_term,
                holding: logs.holding_among(&configuration.voters, *index, *entry_term),
                configuration: Box::new(configuration.clone()),
            });
        }
    }
    Ok(())
}

/// A restarted server's core acts under the latest configuration its
/// reopened log holds, committed or not, or the bootstrap one when it
/// holds none (Raft's rule; ADR-0054). The configuration entries are
/// known by the [`Observation::Configuration`]s every server reported
/// with their entry's term, and one entry is one configuration.
///
/// # Errors
///
/// [`Violation::ConfigurationNotFromLog`] and
/// [`Violation::ConfigurationConflict`].
pub fn configuration_from_log(observations: &[Observation]) -> Result<(), Violation> {
    let mut known: BTreeMap<(u64, u64), Configuration> = BTreeMap::new();
    let mut reopened: BTreeMap<NodeId, Vec<(u64, u64)>> = BTreeMap::new();
    for observation in observations {
        match observation {
            Observation::Recovered { node, entries, .. } => {
                let _ = reopened.insert(*node, entries.clone());
            }
            Observation::Crashed { node } => {
                let _ = reopened.remove(node);
            }
            Observation::Configuration {
                node,
                configuration,
                entry_term,
            } => {
                if let (Some(index), Some(term)) = (configuration.index, *entry_term) {
                    match known.get(&(index, term)) {
                        Some(seen) if seen != configuration => {
                            return Err(Violation::ConfigurationConflict { index, term });
                        }
                        Some(_) => {}
                        None => {
                            let _ = known.insert((index, term), configuration.clone());
                        }
                    }
                }
                // The first configuration after a restart is the one the
                // core recovered.
                if let Some(entries) = reopened.remove(node) {
                    let expected = entries.iter().rev().find_map(|key| known.get(key)).cloned();
                    let matches = match &expected {
                        Some(expected) => expected == configuration,
                        None => configuration.index.is_none(),
                    };
                    if !matches {
                        return Err(Violation::ConfigurationNotFromLog {
                            node: *node,
                            expected: expected.map(Box::new),
                            found: Box::new(configuration.clone()),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// A leader accepts the promotion of a learner only when the learner held
/// durably every entry up to `lag` entries below the leader's commit, by
/// their last reported positions (a leader that knows less refuses more).
///
/// # Errors
///
/// [`Violation::LearnerBehind`].
pub fn learner_caught_up(observations: &[Observation], lag: u64) -> Result<(), Violation> {
    let mut positions: BTreeMap<NodeId, Positions> = BTreeMap::new();
    for observation in observations {
        match observation {
            Observation::Positions {
                node,
                positions: at,
            } => {
                let _ = positions.insert(*node, *at);
            }
            Observation::Change {
                node,
                change: Change::Promote(learner),
                result: Ok(()),
            } => {
                let commit = positions.get(node).and_then(|at| at.committed).unwrap_or(0);
                let durable = positions
                    .get(learner)
                    .and_then(|at| at.durable)
                    .unwrap_or(0);
                let behind = commit.saturating_sub(durable);
                if behind > lag {
                    return Err(Violation::LearnerBehind {
                        node: *node,
                        learner: *learner,
                        behind,
                        lag,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The membership checks (see the module), with promotion lag `lag`.
///
/// # Errors
///
/// The first [`Violation`].
pub fn membership(observations: &[Observation], lag: u64) -> Result<(), Violation> {
    quorum_of_voters(observations)?;
    configuration_from_log(observations)?;
    learner_caught_up(observations, lag)
}

/// Every check of a run with `servers` servers.
///
/// # Errors
///
/// The first [`Violation`].
pub fn all(
    observations: &[Observation],
    history: &History<Op, Ret>,
    servers: usize,
) -> Result<(), Violation> {
    no_contract_breach(observations)?;
    released_after_persistence(observations)?;
    durable_majority_before_reply(observations, servers)?;
    durable_kept(observations)?;
    applied_durable(observations)?;
    committed_prefixes_agree(observations)?;
    responses_agree(observations)?;
    no_old_term_direct_commit(observations)?;
    positions_ordered(observations)?;
    linearizable(history)
}
