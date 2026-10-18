// SPDX-License-Identifier: Apache-2.0

//! The checks of a recorded run (ADR-0043, Harness): the clients' history
//! through C3's checker, and the safety properties over the
//! [`Observation`]s. Each returns the first [`Violation`] it finds.

use std::collections::BTreeMap;

use karyos_cluster::Entry;

use super::core::{Release, Step};
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
    /// A server truncated an entry the cluster had applied.
    CommittedTruncated {
        /// The server.
        node: NodeId,
        /// The entry's index.
        index: u64,
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
        let Observation::Applied { node, entry } = observation else {
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
}

/// Every reply a server releases is for an entry (its index and term) a
/// majority of the `servers` held durably at that moment.
///
/// # Errors
///
/// [`Violation::ReplyBeforeDurableMajority`].
pub fn durable_majority_before_reply(
    observations: &[Observation],
    servers: usize,
) -> Result<(), Violation> {
    let mut logs = DurableLogs::default();
    for observation in observations {
        let _ = logs.observe(observation);
        if let Observation::Reply {
            node,
            client,
            index,
            term,
        } = observation
        {
            let durable = logs.holding(*index, *term);
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
///
/// # Errors
///
/// [`Violation::DurableLost`] and [`Violation::CommittedTruncated`].
pub fn durable_kept(observations: &[Observation]) -> Result<(), Violation> {
    let mut logs = DurableLogs::default();
    let mut applied: BTreeMap<u64, u64> = BTreeMap::new();
    for observation in observations {
        match observation {
            Observation::Applied { entry, .. } => {
                let _ = applied.insert(entry.index, entry.term);
            }
            Observation::Recovered { node, entries, .. } => {
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
    committed_prefixes_agree(observations)?;
    no_old_term_direct_commit(observations)?;
    positions_ordered(observations)?;
    linearizable(history)
}
