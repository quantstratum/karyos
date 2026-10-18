// SPDX-License-Identifier: Apache-2.0

//! The checks of a recorded run (ADR-0043, Harness): the clients' history
//! through C3's checker, and the safety properties over the
//! [`Observation`]s. Each returns the first [`Violation`] it finds.

use std::collections::BTreeMap;

use karyos_cluster::Entry;

use super::core::Step;
use super::node::{Observation, Op, Positions, Ret, ServiceModel};
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
    /// A client got a success for an index fewer than a majority of the
    /// servers held durably.
    SuccessBeforeDurableMajority {
        /// The client.
        client: NodeId,
        /// The index.
        index: u64,
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
    /// A server released messages that depend on persistence before that
    /// persistence was reported.
    ReleasedBeforePersisted {
        /// The server.
        node: NodeId,
        /// How many messages.
        count: usize,
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

/// Every success names an index that a majority of the `servers` held
/// durably when it arrived, by their last positions recorded before it.
///
/// # Errors
///
/// [`Violation::SuccessBeforeDurableMajority`].
pub fn durable_majority_before_success(
    observations: &[Observation],
    servers: usize,
) -> Result<(), Violation> {
    let mut durable: BTreeMap<NodeId, Option<u64>> = BTreeMap::new();
    for observation in observations {
        match observation {
            Observation::Positions { node, positions } => {
                let _ = durable.insert(*node, positions.durable);
            }
            Observation::Success { client, index } => {
                let holding = durable
                    .values()
                    .filter(|last| last.is_some_and(|last| last >= *index))
                    .count();
                if holding <= servers / 2 {
                    return Err(Violation::SuccessBeforeDurableMajority {
                        client: *client,
                        index: *index,
                        durable: holding,
                        servers,
                    });
                }
            }
            _ => {}
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

/// At every server, each release of messages that depend on persistence
/// follows that server's report of the persistence they depend on.
///
/// # Errors
///
/// [`Violation::ReleasedBeforePersisted`].
pub fn released_after_persistence(observations: &[Observation]) -> Result<(), Violation> {
    let mut persisted: BTreeMap<NodeId, bool> = BTreeMap::new();
    for observation in observations {
        let Observation::Drive { node, step } = observation else {
            continue;
        };
        match step {
            Step::Persisted(_) => {
                let _ = persisted.insert(*node, true);
            }
            Step::Released { count } => {
                if !persisted.insert(*node, false).unwrap_or(false) && *count > 0 {
                    return Err(Violation::ReleasedBeforePersisted {
                        node: *node,
                        count: *count,
                    });
                }
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
    released_after_persistence(observations)?;
    durable_majority_before_success(observations, servers)?;
    committed_prefixes_agree(observations)?;
    no_old_term_direct_commit(observations)?;
    positions_ordered(observations)?;
    linearizable(history)
}
