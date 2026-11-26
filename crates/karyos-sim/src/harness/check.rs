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
//!
//! **A standby** (phase 5, P5-S2): [`group`] checks each group of servers
//! on its own observations ([`of_servers`]), [`standby`] adds the checks
//! of the feed, the fencing and the promotion, and [`across_promotion`]
//! gives the history C3 checks: an answer of the old generation above the
//! promoted standby's verified position is an unknown outcome.

use std::collections::{BTreeMap, BTreeSet};

use karyos_cluster::Entry;

use super::core::{Applying, Change, Configuration, Release, Step};
use super::node::{Breach, Observation, Op, Positions, Ret, ServiceModel};
use super::standby::{Fencing, PromotionReport};
use crate::lin::{self, Event, History, HistoryError, Limit, Verdict};
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
    /// A server's core panicked (karyos#976). Reported after every other
    /// check, linearizability included, so only when none names what led
    /// to it: a panic that follows a lost durable entry is reported as
    /// [`Violation::DurableLost`].
    CorePanicked {
        /// The server.
        node: NodeId,
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
    /// Two servers led the same term (karyos#712).
    TwoLeaders {
        /// The term.
        term: u64,
        /// The first server seen leading it.
        first: NodeId,
        /// The second.
        second: NodeId,
    },
    /// A server led, or committed as leader, after its own removal had
    /// committed (karyos#712).
    RemovedLeaderLed {
        /// The server.
        node: NodeId,
        /// The index of the committed configuration entry that removed it.
        removed_at: u64,
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
    /// A standby server replied before any promotion: its effects were
    /// not disabled.
    StandbyEffect {
        /// The server.
        node: NodeId,
    },
    /// A primary server released a reply at or after the fencing point:
    /// its lease's end on its own clock, or after the operator's stop.
    ReplyAfterFencing {
        /// The server.
        node: NodeId,
        /// Its clock at the release.
        at: u64,
        /// The lease's end, for a lease.
        lease_end: Option<u64>,
    },
    /// A server of an older generation replied after a promotion, past
    /// the fencing point.
    OldGenerationReply {
        /// The server.
        node: NodeId,
        /// Its generation.
        generation: u64,
    },
    /// A standby applied a primary entry other than the one the primary
    /// applied at that index.
    FeedMismatch {
        /// The standby server.
        node: NodeId,
        /// The primary's index.
        index: u64,
    },
    /// A promoted standby reported a verified position whose entries it
    /// did not all apply.
    VerifiedLost {
        /// The server.
        node: NodeId,
        /// The first primary index missing.
        index: u64,
    },
    /// A promoted standby's report overstates what it learnt: a commit
    /// beyond the primary's, or a verified position beyond it.
    GapMisreported {
        /// The server.
        node: NodeId,
        /// What it reported.
        report: Box<PromotionReport>,
        /// The highest commit the primary's servers reached.
        primary_commit: Option<u64>,
    },
    /// A client accepted an answer of a generation below one it had
    /// accepted.
    GenerationBack {
        /// The client.
        client: NodeId,
        /// The answer's generation.
        generation: u64,
        /// The highest it had accepted.
        seen: u64,
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
    match lin::check(&ServiceModel::default(), history, LIMIT) {
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
            // A compaction drops entries its snapshot holds: no loss.
            Observation::Compacted { node, first, .. } => {
                if let Some(log) = self.logs.get_mut(node) {
                    *log = log.split_off(first);
                }
                Vec::new()
            }
            // An install drops the whole log: entries up to the base its
            // snapshot holds; any after it are removed, as a truncation.
            Observation::Installed { node, base, .. } => {
                let log = self.logs.remove(node).unwrap_or_default();
                log.into_iter()
                    .filter(|(index, _)| *index > base.index)
                    .map(|(index, term)| (*node, index, term))
                    .collect()
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
            ..
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
    // Servers down since their core panicked: their verdict is the panic
    // (`no_core_panic`), not an unverified log (karyos#976).
    let mut panicked: BTreeSet<NodeId> = BTreeSet::new();
    for observation in observations {
        match observation {
            Observation::Crashed { node } => {
                let _ = down.insert(*node);
                let _ = panicked.remove(node);
            }
            Observation::CorePanicked { node } => {
                let _ = down.insert(*node);
                let _ = panicked.insert(*node);
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
            // A drive error, or a core's panic, stops a server that is up:
            // what it held waits for its restart, as after a crash.
            Observation::OpenFailed { node, .. } | Observation::Contract { node, .. } => {
                let _ = down.insert(*node);
            }
            Observation::Applied { entry, .. } => {
                let _ = applied.insert(entry.index, entry.term);
            }
            Observation::Recovered { node, entries, .. } => {
                let _ = down.remove(node);
                let _ = panicked.remove(node);
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
    for node in down.difference(&panicked).copied() {
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

/// No server's core panicked (karyos#976).
///
/// # Errors
///
/// [`Violation::CorePanicked`] with the first server that did.
pub fn no_core_panic(observations: &[Observation]) -> Result<(), Violation> {
    match observations
        .iter()
        .find_map(|observation| match observation {
            Observation::CorePanicked { node } => Some(*node),
            _ => None,
        }) {
        Some(node) => Err(Violation::CorePanicked { node }),
        None => Ok(()),
    }
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
    removed_leader_steps_down(observations)?;
    learner_caught_up(observations, lag)
}

/// The server an observation is of, if it is one of a server.
fn server_of(observation: &Observation) -> Option<NodeId> {
    match observation {
        Observation::Drive { node, .. }
        | Observation::Released { node, .. }
        | Observation::Reply { node, .. }
        | Observation::Crashed { node }
        | Observation::CorePanicked { node }
        | Observation::Recovered { node, .. }
        | Observation::Contract { node, .. }
        | Observation::Commit { node, .. }
        | Observation::Applied { node, .. }
        | Observation::Positions { node, .. }
        | Observation::OpenFailed { node, .. }
        | Observation::Configuration { node, .. }
        | Observation::Change { node, .. }
        | Observation::FeedRefused { node, .. }
        | Observation::Backpressure { node, .. }
        | Observation::Compacted { node, .. }
        | Observation::Installed { node, .. }
        | Observation::SnapshotRefused { node, .. }
        | Observation::SnapshotPiece { node, .. }
        | Observation::SnapshotPieceLost { node, .. }
        | Observation::SnapshotAbandoned { node, .. }
        | Observation::SnapshotSent { node, .. }
        | Observation::Unsupported { node, .. }
        | Observation::Transfer { node, .. }
        | Observation::Deduplicated { node, .. }
        | Observation::Redirected { node, .. }
        | Observation::FeedApplied { node, .. }
        | Observation::Promoted { node, .. }
        | Observation::Leading { node, .. } => Some(*node),
        Observation::Success { .. }
        | Observation::StaleGeneration { .. }
        | Observation::Fenced { .. }
        | Observation::PromotionRefused { .. }
        | Observation::Expired { .. }
        | Observation::Healed
        | Observation::Triggered { .. } => None,
    }
}

/// The observations of the servers `nodes`, in order: one group's.
#[must_use]
pub fn of_servers(observations: &[Observation], nodes: &[NodeId]) -> Vec<Observation> {
    observations
        .iter()
        .filter(|observation| server_of(observation).is_some_and(|node| nodes.contains(&node)))
        .cloned()
        .collect()
}

/// A standby's checks (P5-S2), its servers `standby`, every other server
/// a primary one:
///
/// - no primary server replies at or after the fencing point: its
///   lease's end on its own clock, or the operator's stop;
/// - no standby server replies before a promotion;
/// - after a promotion, no server of an older generation replies;
/// - every primary entry a standby applied is the one a primary server
///   applied at that index;
/// - a promoted standby applied every primary entry up to the verified
///   position it reports, and reports a learnt commit no higher than the
///   primary's servers reached, and a verified position no higher than
///   it;
/// - no client accepts an answer of a lower generation than one it
///   accepted.
///
/// # Errors
///
/// The first [`Violation`].
pub fn standby(observations: &[Observation], standby: &[NodeId]) -> Result<(), Violation> {
    let mut primary_applied: BTreeMap<u64, (u64, &[u8])> = BTreeMap::new();
    let mut primary_commit: Option<u64> = None;
    for observation in observations {
        match observation {
            Observation::Applied { node, entry, .. } if !standby.contains(node) => {
                let _ = primary_applied.insert(entry.index, (entry.term, &entry.payload));
            }
            Observation::Commit { node, index, .. } if !standby.contains(node) => {
                primary_commit = primary_commit.max(Some(*index));
            }
            _ => {}
        }
    }
    // A lease's fencing point is known only at the promotion, after the
    // replies it bounds: take it first.
    let lease_end = observations
        .iter()
        .find_map(|observation| match observation {
            Observation::Fenced {
                lease_end: Some(end),
                ..
            } => Some(*end),
            _ => None,
        });
    let mut stopped = false;
    let mut promoted: Option<u64> = None;
    let mut fed: BTreeMap<NodeId, BTreeSet<u64>> = BTreeMap::new();
    let mut accepted: BTreeMap<NodeId, u64> = BTreeMap::new();
    for observation in observations {
        match observation {
            Observation::Fenced {
                fencing: Fencing::OperatorStop,
                ..
            } => stopped = true,
            Observation::Reply {
                node,
                generation,
                at,
                ..
            } => {
                if !standby.contains(node) && (stopped || lease_end.is_some_and(|end| *at >= end)) {
                    return Err(Violation::ReplyAfterFencing {
                        node: *node,
                        at: *at,
                        lease_end,
                    });
                }
                if promoted.is_none() && standby.contains(node) {
                    return Err(Violation::StandbyEffect { node: *node });
                }
                if promoted.is_some_and(|newest| *generation < newest) {
                    return Err(Violation::OldGenerationReply {
                        node: *node,
                        generation: *generation,
                    });
                }
            }
            Observation::FeedApplied {
                node,
                index,
                term,
                payload,
            } => {
                if primary_applied
                    .get(index)
                    .is_some_and(|(at, bytes)| (at, *bytes) != (term, payload.as_slice()))
                {
                    return Err(Violation::FeedMismatch {
                        node: *node,
                        index: *index,
                    });
                }
                let _ = fed.entry(*node).or_default().insert(*index);
            }
            Observation::Promoted { node, report } => {
                // From the primary's first index: once snapshots purge a
                // prefix (C8), the floor becomes the snapshot's index.
                if let Some(verified) = report.verified {
                    let applied = fed.get(node);
                    if let Some(index) = (super::standby::PRIMARY_FIRST_INDEX..=verified)
                        .find(|index| !applied.is_some_and(|set| set.contains(index)))
                    {
                        return Err(Violation::VerifiedLost { node: *node, index });
                    }
                }
                // Every feed send carries a commit at least as high as its
                // entries, so the learnt commit bounds the verified position.
                if report.learnt_commit > primary_commit || report.verified > report.learnt_commit {
                    return Err(Violation::GapMisreported {
                        node: *node,
                        report: Box::new(report.clone()),
                        primary_commit,
                    });
                }
                promoted = promoted.max(Some(report.generation));
            }
            Observation::Success {
                client, generation, ..
            } => {
                let seen = accepted.entry(*client).or_insert(0);
                if *generation < *seen {
                    return Err(Violation::GenerationBack {
                        client: *client,
                        generation: *generation,
                        seen: *seen,
                    });
                }
                *seen = *generation;
            }
            _ => {}
        }
    }
    Ok(())
}

/// The clients' `history` across a promotion (SPEC.md §9): an answer of a
/// generation below the first promoted standby's, for a primary index
/// above its verified position, is an unknown outcome. Its return is left
/// out, so the operation is pending, and the client's later operations
/// carry a fresh client id. Without a promotion, `history` as it is.
#[must_use]
pub fn across_promotion(
    history: &History<Op, Ret>,
    observations: &[Observation],
) -> History<Op, Ret> {
    let Some(report) = observations
        .iter()
        .find_map(|observation| match observation {
            Observation::Promoted { report, .. } => Some(report),
            _ => None,
        })
    else {
        return history.clone();
    };
    // Per client, whether each of its successes, in order, is unknown.
    let mut unknown: BTreeMap<NodeId, Vec<bool>> = BTreeMap::new();
    for observation in observations {
        if let Observation::Success {
            client,
            index,
            generation,
        } = observation
        {
            let lost = *generation < report.generation && Some(*index) > report.verified;
            unknown.entry(*client).or_default().push(lost);
        }
    }
    let mut fresh = history
        .events()
        .iter()
        .map(|event| match event {
            Event::Invoke { client, .. } | Event::Return { client, .. } => *client,
        })
        .max()
        .map_or(0, |last| last.saturating_add(1));
    let mut alias: BTreeMap<NodeId, NodeId> = BTreeMap::new();
    let mut returned: BTreeMap<NodeId, usize> = BTreeMap::new();
    let mut rewritten = History::new();
    for event in history.events() {
        match event {
            Event::Invoke { client, op } => {
                let id = alias.get(client).copied().unwrap_or(*client);
                let _ = rewritten.invoke(id, op.clone());
            }
            Event::Return { client, ret } => {
                let count = returned.entry(*client).or_insert(0);
                let lost = unknown
                    .get(client)
                    .and_then(|flags| flags.get(*count))
                    .copied()
                    .unwrap_or(false);
                *count = count.saturating_add(1);
                if lost {
                    let _ = alias.insert(*client, fresh);
                    // Fresh ids start above every client's and grow by
                    // one per unknown outcome, far below u32::MAX.
                    fresh = fresh.saturating_add(1);
                } else {
                    let id = alias.get(client).copied().unwrap_or(*client);
                    let _ = rewritten.ret(id, ret.clone());
                }
            }
        }
    }
    rewritten
}

/// Every check of one group of `servers` servers but linearizability.
///
/// # Errors
///
/// The first [`Violation`].
pub fn group(observations: &[Observation], servers: usize) -> Result<(), Violation> {
    no_contract_breach(observations)?;
    released_after_persistence(observations)?;
    durable_majority_before_reply(observations, servers)?;
    durable_kept(observations)?;
    applied_durable(observations)?;
    committed_prefixes_agree(observations)?;
    responses_agree(observations)?;
    no_old_term_direct_commit(observations)?;
    one_leader_per_term(observations)?;
    positions_ordered(observations)
}

/// No two servers lead the same term, across every configuration
/// (karyos#712; Raft's election safety). Reads [`Observation::Leading`].
///
/// # Errors
///
/// [`Violation::TwoLeaders`].
pub fn one_leader_per_term(observations: &[Observation]) -> Result<(), Violation> {
    let mut leaders: BTreeMap<u64, NodeId> = BTreeMap::new();
    for observation in observations {
        if let Observation::Leading { node, term } = observation {
            match leaders.get(term) {
                Some(first) if first != node => {
                    return Err(Violation::TwoLeaders {
                        term: *term,
                        first: *first,
                        second: *node,
                    });
                }
                Some(_) => {}
                None => {
                    let _ = leaders.insert(*term, *node);
                }
            }
        }
    }
    Ok(())
}

/// A server whose own removal it knows committed never leads again, nor
/// commits as leader past the removal, unless a later configuration makes
/// it a voter again (karyos#712, M2). The removal is known by its own
/// [`Observation::Configuration`], whose voters exclude it, and its own
/// commit reaching that entry.
///
/// # Errors
///
/// [`Violation::RemovedLeaderLed`].
pub fn removed_leader_steps_down(observations: &[Observation]) -> Result<(), Violation> {
    // Per server: the removing entry's index, and whether its commit has
    // reached it.
    let mut removal: BTreeMap<NodeId, (u64, bool)> = BTreeMap::new();
    let mut commits: BTreeMap<NodeId, u64> = BTreeMap::new();
    for observation in observations {
        match observation {
            Observation::Configuration {
                node,
                configuration,
                ..
            } => match configuration.index {
                Some(index) if !configuration.voters.contains(node) => {
                    let reached = commits.get(node).is_some_and(|commit| *commit >= index);
                    let _ = removal.insert(*node, (index, reached));
                }
                _ => {
                    let _ = removal.remove(node);
                }
            },
            Observation::Commit {
                node,
                leader,
                index,
                ..
            } => {
                let _ = commits.insert(*node, *index);
                if let Some((at, reached)) = removal.get_mut(node) {
                    if *reached && *leader && *index > *at {
                        return Err(Violation::RemovedLeaderLed {
                            node: *node,
                            removed_at: *at,
                        });
                    }
                    if *index >= *at {
                        *reached = true;
                    }
                }
            }
            Observation::Leading { node, .. } => {
                if let Some(&(at, true)) = removal.get(node) {
                    return Err(Violation::RemovedLeaderLed {
                        node: *node,
                        removed_at: at,
                    });
                }
            }
            Observation::Crashed { node } => {
                let _ = commits.remove(node);
            }
            _ => {}
        }
    }
    Ok(())
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
    group(observations, servers)?;
    linearizable(history)?;
    // Last: a core's panic is reported only when no other check, client
    // history included, names its cause (karyos#976).
    no_core_panic(observations)
}
