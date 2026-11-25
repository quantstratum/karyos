// SPDX-License-Identifier: Apache-2.0

//! What the processes of a real-process run report, as text lines, and
//! their merge into one [`Recorder`] (C5 v2, "Processes"; karyos#691).
//!
//! Each server process ([`crate::process::run_server`]) and each client
//! process (`raft-eval-client`) writes every observation the harness's
//! own nodes would record (`harness::node::Observation`), and each client
//! its history events, one per line, each stamped with the nanoseconds of
//! the host's `CLOCK_MONOTONIC` when it was recorded
//! (`karyos_sys::host_clock::host_monotonic_ns`). [`merge`] orders every
//! process's lines by that stamp into one [`Recorder`], which
//! `harness::workloads::outcome` checks as it checks a simulated run.
//!
//! **The clock is the precondition of every check across processes.**
//! The order of two events of different processes is the order of their
//! stamps, so every process must read one monotonic clock: the same
//! `CLOCK_MONOTONIC` on the same host, which `host_monotonic_ns` reads on
//! Linux ([`CLOCK`]). An event is stamped where its order is safe: an
//! invocation before its request leaves the client, a return after its
//! answer arrived, a server's durability before the message that
//! acknowledges it leaves, and a reply before it leaves; so a stamp order
//! never contradicts what one process could have seen of another.
//!
//! A line is `<stamp> <tag> <fields>...`, its fields separated by single
//! spaces: numbers in decimal, an absent number `-`, bytes in hex after an
//! `x`, a list of ids comma-separated (`.` when empty).

use karyos_cluster::{Entry, HardState};
use karyos_sim::harness::core::{Applying, Configuration, Limit, Persisted, Release, Step};
use karyos_sim::harness::node::{Breach, Observation, Op, Positions, Recorder, Ret};
use karyos_sim::net::NodeId;

/// The clock every stamp is read from, as the run record names it: the
/// precondition of the linearizability and the other checks across
/// processes.
pub const CLOCK: &str = "CLOCK_MONOTONIC of one host (karyos_sys::host_clock::host_monotonic_ns), read by every node and client process";

/// One stamped record of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// An observation, as `harness::node` records it.
    Observation(Observation),
    /// A client invoked `op` (its history).
    Invoke {
        /// The client.
        client: NodeId,
        /// The operation.
        op: Op,
    },
    /// A client's open operation returned `ret` (its history).
    Return {
        /// The client.
        client: NodeId,
        /// The return.
        ret: Ret,
    },
    /// A server sent an append (W2: the byte oracle's trace, read from
    /// the message itself).
    Sent {
        /// The sender.
        leader: NodeId,
        /// The receiver.
        to: NodeId,
        /// The append's leader term.
        term: u64,
        /// Its entries: index and payload bytes.
        entries: Vec<(u64, u64)>,
    },
    /// A server stepped an accepted append reply (W2: the byte oracle's
    /// trace).
    Acked {
        /// The server that stepped it.
        leader: NodeId,
        /// The follower that sent it.
        from: NodeId,
        /// Its term.
        term: u64,
        /// The index it acknowledges.
        index: u64,
    },
}

/// The stamp of now: nanoseconds of the host's monotonic clock ([`CLOCK`]).
#[must_use]
pub fn now() -> u64 {
    karyos_sys::host_clock::host_monotonic_ns()
}

/// Writes fields into one line.
struct Line(String);

impl Line {
    fn new(stamp: u64, tag: &str) -> Self {
        Self(format!("{stamp} {tag}"))
    }

    fn field(mut self, field: impl std::fmt::Display) -> Self {
        self.0.push(' ');
        self.0.push_str(&field.to_string());
        self
    }

    fn number(self, value: u64) -> Self {
        self.field(value)
    }

    fn optional(self, value: Option<u64>) -> Self {
        match value {
            Some(value) => self.field(value),
            None => self.field('-'),
        }
    }

    fn flag(self, value: bool) -> Self {
        self.field(u8::from(value))
    }

    fn bytes(self, bytes: &[u8]) -> Self {
        let mut hex = String::with_capacity(bytes.len().saturating_mul(2).saturating_add(1));
        hex.push('x');
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        self.field(hex)
    }

    fn ids(self, ids: &[NodeId]) -> Self {
        if ids.is_empty() {
            return self.field('.');
        }
        let ids: Vec<String> = ids.iter().map(ToString::to_string).collect();
        self.field(ids.join(","))
    }

    fn hard_state(self, state: Option<HardState>) -> Self {
        match state {
            None => self.field('-'),
            Some(state) => {
                let part =
                    |value: Option<u64>| value.map_or_else(|| "-".to_owned(), |v| v.to_string());
                self.field(format!(
                    "{},{},{}",
                    state.current_term,
                    part(state.voted_for),
                    part(state.commit)
                ))
            }
        }
    }

    fn pairs(self, pairs: &[(u64, u64)]) -> Self {
        if pairs.is_empty() {
            return self.field('.');
        }
        let pairs: Vec<String> = pairs.iter().map(|(a, b)| format!("{a}:{b}")).collect();
        self.field(pairs.join(","))
    }
}

/// A breach's name in a line.
const BREACHES: [(Breach, &str); 10] = [
    (Breach::NotNext, "not_next"),
    (Breach::TermBack, "term_back"),
    (Breach::TooLarge, "too_large"),
    (Breach::OutOfRange, "out_of_range"),
    (Breach::PurgeBeyondCommit, "purge_beyond_commit"),
    (Breach::TruncateBelowCommit, "truncate_below_commit"),
    (Breach::HardState, "hard_state"),
    (Breach::CommitBeyondDurable, "commit_beyond_durable"),
    (Breach::CommitBack, "commit_back"),
    (Breach::WorkBudget, "work_budget"),
];

/// A limit's name in a line.
const LIMITS: [(Limit, &str); 4] = [
    (Limit::InFlightEntries, "in_flight_entries"),
    (Limit::InFlightBytes, "in_flight_bytes"),
    (Limit::Queue, "queue"),
    (Limit::LogRead, "log_read"),
];

/// `item`, stamped `stamp`, as one line; `None` for an observation no
/// process of a run records (a standby's, a snapshot's, a membership
/// change's, a crash's: none of them happens in a run of W1).
#[must_use]
pub fn encode(stamp: u64, item: &Item) -> Option<String> {
    let line = match item {
        Item::Invoke { client, op } => {
            let line = Line::new(stamp, "invoke").number(u64::from(*client));
            match op {
                Op::Append(value) => line.field('a').bytes(value),
                Op::Read => line.field('r'),
            }
        }
        Item::Return { client, ret } => Line::new(stamp, "return")
            .number(u64::from(*client))
            .bytes(&ret.canonical()),
        Item::Observation(observation) => observation_line(stamp, observation)?,
        Item::Sent {
            leader,
            to,
            term,
            entries,
        } => Line::new(stamp, "sent")
            .number(u64::from(*leader))
            .number(u64::from(*to))
            .number(*term)
            .pairs(entries),
        Item::Acked {
            leader,
            from,
            term,
            index,
        } => Line::new(stamp, "acked")
            .number(u64::from(*leader))
            .number(u64::from(*from))
            .number(*term)
            .number(*index),
    };
    Some(line.0)
}

fn observation_line(stamp: u64, observation: &Observation) -> Option<Line> {
    let id = |node: &NodeId| u64::from(*node);
    Some(match observation {
        Observation::CorePanicked { node } => Line::new(stamp, "panicked").number(id(node)),
        Observation::Drive {
            node,
            step: Step::SnapshotTo(to),
        } => Line::new(stamp, "snapshot_to")
            .number(id(node))
            .number(id(to)),
        Observation::Drive {
            node,
            step:
                Step::Persisted {
                    persisted,
                    truncated_from,
                    appended,
                },
        } => Line::new(stamp, "persisted")
            .number(id(node))
            .optional(persisted.durable)
            .hard_state(persisted.hard_state)
            .optional(*truncated_from)
            .pairs(appended),
        Observation::Released { node, to, release } => Line::new(stamp, "released")
            .number(id(node))
            .number(id(to))
            .optional(release.needs)
            .hard_state(release.needs_state)
            .optional(release.durable)
            .hard_state(release.stored_state),
        Observation::Reply {
            node,
            client,
            index,
            term,
            generation,
            at,
        } => Line::new(stamp, "reply")
            .number(id(node))
            .number(id(client))
            .number(*index)
            .number(*term)
            .number(*generation)
            .number(*at),
        Observation::Commit {
            node,
            term,
            leader,
            index,
            entry_term,
        } => Line::new(stamp, "commit")
            .number(id(node))
            .number(*term)
            .flag(*leader)
            .number(*index)
            .number(*entry_term),
        Observation::Applied {
            node,
            entry,
            applying,
            response,
        } => {
            let line = Line::new(stamp, "applied")
                .number(id(node))
                .number(entry.index)
                .number(entry.term)
                .number(entry.event_time)
                .bytes(&entry.payload)
                .optional(applying.durable)
                .optional(applying.logged_term);
            match response {
                Some(response) => line.bytes(response),
                None => line.field('-'),
            }
        }
        Observation::Success {
            client,
            index,
            generation,
        } => Line::new(stamp, "success")
            .number(id(client))
            .number(*index)
            .number(*generation),
        Observation::StaleGeneration { client, generation } => Line::new(stamp, "stale")
            .number(id(client))
            .number(*generation),
        Observation::Backpressure {
            node,
            client,
            sequence,
            limit,
        } => {
            let (_, name) = LIMITS.iter().find(|(known, _)| known == limit)?;
            Line::new(stamp, "backpressure")
                .number(id(node))
                .number(id(client))
                .number(*sequence)
                .field(name)
        }
        Observation::Positions { node, positions } => Line::new(stamp, "positions")
            .number(id(node))
            .optional(positions.received)
            .optional(positions.written)
            .optional(positions.durable)
            .optional(positions.committed)
            .optional(positions.applied),
        Observation::OpenFailed { node, error } => Line::new(stamp, "open_failed")
            .number(id(node))
            .bytes(error.as_bytes()),
        Observation::Contract {
            node,
            breach,
            error,
        } => {
            let (_, name) = BREACHES.iter().find(|(known, _)| known == breach)?;
            Line::new(stamp, "contract")
                .number(id(node))
                .field(name)
                .bytes(error.as_bytes())
        }
        Observation::Configuration {
            node,
            configuration,
            entry_term,
        } => Line::new(stamp, "configuration")
            .number(id(node))
            .optional(configuration.index)
            .ids(&configuration.voters)
            .ids(&configuration.outgoing)
            .ids(&configuration.learners)
            .optional(*entry_term),
        Observation::Deduplicated {
            node,
            client,
            sequence,
        } => Line::new(stamp, "deduplicated")
            .number(id(node))
            .number(id(client))
            .number(*sequence),
        Observation::Redirected {
            node,
            client,
            sequence,
            to,
        } => Line::new(stamp, "redirected")
            .number(id(node))
            .number(id(client))
            .number(*sequence)
            .number(id(to)),
        Observation::Expired { client, sequence } => Line::new(stamp, "expired")
            .number(id(client))
            .number(*sequence),
        Observation::Healed => Line::new(stamp, "healed"),
        Observation::Unsupported { node, what } => Line::new(stamp, "unsupported")
            .number(id(node))
            .bytes(what.as_bytes()),
        _ => return None,
    })
}

/// Reads the fields of one line.
struct Fields<'a>(std::str::Split<'a, char>);

impl<'a> Fields<'a> {
    fn text(&mut self) -> Option<&'a str> {
        self.0.next()
    }

    fn number(&mut self) -> Option<u64> {
        self.text()?.parse().ok()
    }

    fn node(&mut self) -> Option<NodeId> {
        NodeId::try_from(self.number()?).ok()
    }

    fn optional(&mut self) -> Option<Option<u64>> {
        optional(self.text()?)
    }

    fn flag(&mut self) -> Option<bool> {
        match self.text()? {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }
    }

    fn bytes(&mut self) -> Option<Vec<u8>> {
        bytes(self.text()?)
    }

    fn string(&mut self) -> Option<String> {
        String::from_utf8(self.bytes()?).ok()
    }

    fn ids(&mut self) -> Option<Vec<NodeId>> {
        let text = self.text()?;
        if text == "." {
            return Some(Vec::new());
        }
        text.split(',').map(|id| id.parse().ok()).collect()
    }

    fn hard_state(&mut self) -> Option<Option<HardState>> {
        let text = self.text()?;
        if text == "-" {
            return Some(None);
        }
        let mut parts = text.split(',');
        let current_term = parts.next()?.parse().ok()?;
        let voted_for = optional(parts.next()?)?;
        let commit = optional(parts.next()?)?;
        parts.next().is_none().then_some(Some(HardState {
            current_term,
            voted_for,
            commit,
        }))
    }

    fn pairs(&mut self) -> Option<Vec<(u64, u64)>> {
        let text = self.text()?;
        if text == "." {
            return Some(Vec::new());
        }
        text.split(',')
            .map(|pair| {
                let (a, b) = pair.split_once(':')?;
                Some((a.parse().ok()?, b.parse().ok()?))
            })
            .collect()
    }

    /// The line has no field left.
    fn end(mut self) -> Option<()> {
        self.0.next().is_none().then_some(())
    }
}

fn optional(text: &str) -> Option<Option<u64>> {
    if text == "-" {
        Some(None)
    } else {
        text.parse().ok().map(Some)
    }
}

fn bytes(text: &str) -> Option<Vec<u8>> {
    let hex = text.strip_prefix('x')?.as_bytes();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    hex.chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

/// One line of [`encode`]: its stamp and item; `None` for a line that is
/// not one.
#[must_use]
pub fn decode(line: &str) -> Option<(u64, Item)> {
    let mut fields = Fields(line.split(' '));
    let stamp = fields.number()?;
    let tag = fields.text()?;
    let item = match tag {
        "invoke" => {
            let client = fields.node()?;
            let op = match fields.text()? {
                "a" => Op::Append(fields.bytes()?),
                "r" => Op::Read,
                _ => return None,
            };
            Item::Invoke { client, op }
        }
        "return" => Item::Return {
            client: fields.node()?,
            ret: Ret::decode(&fields.bytes()?)?,
        },
        "sent" => Item::Sent {
            leader: fields.node()?,
            to: fields.node()?,
            term: fields.number()?,
            entries: fields.pairs()?,
        },
        "acked" => Item::Acked {
            leader: fields.node()?,
            from: fields.node()?,
            term: fields.number()?,
            index: fields.number()?,
        },
        _ => Item::Observation(observation(tag, &mut fields)?),
    };
    fields.end()?;
    Some((stamp, item))
}

fn observation(tag: &str, fields: &mut Fields<'_>) -> Option<Observation> {
    Some(match tag {
        "healed" => Observation::Healed,
        "panicked" => Observation::CorePanicked {
            node: fields.node()?,
        },
        "snapshot_to" => Observation::Drive {
            node: fields.node()?,
            step: Step::SnapshotTo(fields.node()?),
        },
        "persisted" => {
            let node = fields.node()?;
            let durable = fields.optional()?;
            let hard_state = fields.hard_state()?;
            Observation::Drive {
                node,
                step: Step::Persisted {
                    persisted: Persisted {
                        durable,
                        hard_state,
                    },
                    truncated_from: fields.optional()?,
                    appended: fields.pairs()?,
                },
            }
        }
        "released" => Observation::Released {
            node: fields.node()?,
            to: fields.node()?,
            release: Release {
                needs: fields.optional()?,
                needs_state: fields.hard_state()?,
                durable: fields.optional()?,
                stored_state: fields.hard_state()?,
            },
        },
        "reply" => Observation::Reply {
            node: fields.node()?,
            client: fields.node()?,
            index: fields.number()?,
            term: fields.number()?,
            generation: fields.number()?,
            at: fields.number()?,
        },
        "commit" => Observation::Commit {
            node: fields.node()?,
            term: fields.number()?,
            leader: fields.flag()?,
            index: fields.number()?,
            entry_term: fields.number()?,
        },
        "applied" => {
            let node = fields.node()?;
            let entry = Entry {
                index: fields.number()?,
                term: fields.number()?,
                event_time: fields.number()?,
                payload: fields.bytes()?,
            };
            let applying = Applying {
                durable: fields.optional()?,
                logged_term: fields.optional()?,
            };
            let response = match fields.text()? {
                "-" => None,
                text => Some(bytes(text)?),
            };
            Observation::Applied {
                node,
                entry,
                applying,
                response,
            }
        }
        "success" => Observation::Success {
            client: fields.node()?,
            index: fields.number()?,
            generation: fields.number()?,
        },
        "stale" => Observation::StaleGeneration {
            client: fields.node()?,
            generation: fields.number()?,
        },
        "backpressure" => {
            let node = fields.node()?;
            let client = fields.node()?;
            let sequence = fields.number()?;
            let name = fields.text()?;
            let (limit, _) = LIMITS.iter().find(|(_, known)| *known == name)?;
            Observation::Backpressure {
                node,
                client,
                sequence,
                limit: *limit,
            }
        }
        "positions" => Observation::Positions {
            node: fields.node()?,
            positions: Positions {
                received: fields.optional()?,
                written: fields.optional()?,
                durable: fields.optional()?,
                committed: fields.optional()?,
                applied: fields.optional()?,
            },
        },
        "open_failed" => Observation::OpenFailed {
            node: fields.node()?,
            error: fields.string()?,
        },
        "contract" => {
            let node = fields.node()?;
            let name = fields.text()?;
            let (breach, _) = BREACHES.iter().find(|(_, known)| *known == name)?;
            Observation::Contract {
                node,
                breach: *breach,
                error: fields.string()?,
            }
        }
        "configuration" => Observation::Configuration {
            node: fields.node()?,
            configuration: Configuration {
                index: fields.optional()?,
                voters: fields.ids()?,
                outgoing: fields.ids()?,
                learners: fields.ids()?,
            },
            entry_term: fields.optional()?,
        },
        "deduplicated" => Observation::Deduplicated {
            node: fields.node()?,
            client: fields.node()?,
            sequence: fields.number()?,
        },
        "redirected" => Observation::Redirected {
            node: fields.node()?,
            client: fields.node()?,
            sequence: fields.number()?,
            to: fields.node()?,
        },
        "expired" => Observation::Expired {
            client: fields.node()?,
            sequence: fields.number()?,
        },
        "unsupported" => {
            let node = fields.node()?;
            let _ = fields.string()?;
            // The capability's name is static in the harness; any
            // unsupported report makes the case not demonstrated.
            Observation::Unsupported {
                node,
                what: "reported by a process",
            }
        }
        _ => return None,
    })
}

/// Every process's stamped items, merged into one [`Recorder`] in the
/// order of their stamps ([`CLOCK`]). Items of one process keep their
/// order: each process records in order, its stamps never going back, and
/// the sort is stable.
#[must_use]
pub fn merge(processes: Vec<Vec<(u64, Item)>>) -> Recorder {
    let mut items: Vec<(u64, Item)> = processes.into_iter().flatten().collect();
    items.sort_by_key(|(stamp, _)| *stamp);
    let mut recorder = Recorder::default();
    for (_, item) in items {
        match item {
            Item::Observation(observation) => recorder.observations.push(observation),
            Item::Invoke { client, op } => {
                let _ = recorder.history.invoke(client, op);
            }
            Item::Return { client, ret } => {
                let _ = recorder.history.ret(client, ret);
            }
            // The byte oracle's trace: not the harness's to record.
            Item::Sent { .. } | Item::Acked { .. } => {}
        }
    }
    recorder
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(item: Item) {
        let line = encode(7, &item).unwrap_or_default();
        assert_eq!(decode(&line), Some((7, item)), "{line}");
    }

    #[test]
    fn every_recorded_item_round_trips() {
        let state = Some(HardState {
            current_term: 3,
            voted_for: Some(1),
            commit: None,
        });
        round_trip(Item::Invoke {
            client: 3,
            op: Op::Append(vec![0, 1, 0xFF]),
        });
        round_trip(Item::Invoke {
            client: 3,
            op: Op::Read,
        });
        round_trip(Item::Return {
            client: 4,
            ret: Ret::Values(vec![vec![1, 2], Vec::new()]),
        });
        round_trip(Item::Return {
            client: 4,
            ret: Ret::Appended(9),
        });
        round_trip(Item::Sent {
            leader: 0,
            to: 2,
            term: 3,
            entries: vec![(7, 8209), (8, 0)],
        });
        round_trip(Item::Sent {
            leader: 0,
            to: 2,
            term: 3,
            entries: Vec::new(),
        });
        round_trip(Item::Acked {
            leader: 0,
            from: 2,
            term: 3,
            index: 8,
        });
        for observation in [
            Observation::Drive {
                node: 1,
                step: Step::Persisted {
                    persisted: Persisted {
                        durable: Some(4),
                        hard_state: state,
                    },
                    truncated_from: None,
                    appended: vec![(3, 1), (4, 2)],
                },
            },
            Observation::Drive {
                node: 1,
                step: Step::SnapshotTo(2),
            },
            Observation::Released {
                node: 0,
                to: 2,
                release: Release {
                    needs: Some(4),
                    needs_state: None,
                    durable: Some(4),
                    stored_state: state,
                },
            },
            Observation::Reply {
                node: 0,
                client: 3,
                index: 5,
                term: 2,
                generation: 1,
                at: 77,
            },
            Observation::Commit {
                node: 0,
                term: 2,
                leader: true,
                index: 5,
                entry_term: 2,
            },
            Observation::Applied {
                node: 2,
                entry: Entry {
                    index: 5,
                    term: 2,
                    event_time: 0,
                    payload: b"KC5".to_vec(),
                },
                applying: Applying {
                    durable: Some(5),
                    logged_term: Some(2),
                },
                response: Some(Ret::Appended(1).canonical()),
            },
            Observation::Applied {
                node: 2,
                entry: Entry {
                    index: 1,
                    term: 1,
                    event_time: 3,
                    payload: Vec::new(),
                },
                applying: Applying {
                    durable: None,
                    logged_term: None,
                },
                response: None,
            },
            Observation::Positions {
                node: 1,
                positions: Positions {
                    received: Some(3),
                    written: Some(3),
                    durable: None,
                    committed: Some(1),
                    applied: None,
                },
            },
            Observation::Configuration {
                node: 1,
                configuration: Configuration {
                    index: None,
                    voters: vec![0, 1, 2],
                    outgoing: Vec::new(),
                    learners: Vec::new(),
                },
                entry_term: None,
            },
            Observation::Contract {
                node: 1,
                breach: Breach::CommitBack,
                error: "a commit going back".to_owned(),
            },
            Observation::OpenFailed {
                node: 1,
                error: "disk".to_owned(),
            },
            Observation::Deduplicated {
                node: 0,
                client: 3,
                sequence: 2,
            },
            Observation::Redirected {
                node: 1,
                client: 3,
                sequence: 2,
                to: 0,
            },
            Observation::Backpressure {
                node: 0,
                client: 3,
                sequence: 2,
                limit: Limit::Queue,
            },
            Observation::Success {
                client: 3,
                index: 5,
                generation: 1,
            },
            Observation::Expired {
                client: 3,
                sequence: 2,
            },
            Observation::StaleGeneration {
                client: 3,
                generation: 1,
            },
            Observation::CorePanicked { node: 1 },
            Observation::Healed,
        ] {
            round_trip(Item::Observation(observation));
        }
    }

    #[test]
    fn a_malformed_line_is_refused() {
        assert_eq!(decode(""), None);
        assert_eq!(decode("7 reply 0 3"), None);
        assert_eq!(decode("7 reply 0 3 5 2 1 77 extra"), None);
        assert_eq!(decode("7 return 4 x0"), None);
        assert_eq!(decode("7 unknown 1"), None);
    }

    #[test]
    fn the_merge_orders_by_stamp_and_keeps_each_process_order() {
        let invoke = |client| Item::Invoke {
            client,
            op: Op::Read,
        };
        let ret = |client| Item::Return {
            client,
            ret: Ret::Values(Vec::new()),
        };
        let recorder = merge(vec![
            vec![(1, invoke(1)), (5, ret(1))],
            vec![(3, invoke(2)), (3, ret(2))],
        ]);
        let mut expected = karyos_sim::lin::History::new();
        let _ = expected
            .invoke(1, Op::Read)
            .invoke(2, Op::Read)
            .ret(2, Ret::Values(Vec::new()))
            .ret(1, Ret::Values(Vec::new()));
        assert_eq!(recorder.history, expected);
    }
}
