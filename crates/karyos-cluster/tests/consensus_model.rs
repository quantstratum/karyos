// SPDX-License-Identifier: Apache-2.0

//! The custom Raft core (ADR-0105, part (b) of karyos#681) against
//! Raft's safety properties: a seeded simulation of 3 and 5 nodes over a
//! lossy, reordering, duplicating network with restarts, checking
//! election safety, log matching, leader completeness and state machine
//! safety after every event; and the core's rules one by one.

use std::collections::BTreeMap;

use karyos_cluster::consensus::{
    AppendOutcome, Backpressure, Config, ConfigError, Core, Effects, Limits, LogTerms, Message,
    ProposeError, Role, StepError, TermVote,
};

/// A log of entry terms: index `i` is `terms[i - 1]`, and `ids[i - 1]`
/// is that entry's identity, so the safety checks compare entries, not
/// only terms.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TestLog {
    terms: Vec<u64>,
    ids: Vec<u64>,
}

impl TestLog {
    fn of(terms: Vec<u64>) -> Self {
        let ids = vec![0; terms.len()];
        Self { terms, ids }
    }

    fn entries(&self) -> Vec<(u64, u64)> {
        self.terms
            .iter()
            .copied()
            .zip(self.ids.iter().copied())
            .collect()
    }

    fn push(&mut self, term: u64, id: u64) {
        self.terms.push(term);
        self.ids.push(id);
    }
}

impl LogTerms for TestLog {
    fn last_index(&self) -> u64 {
        u64::try_from(self.terms.len()).unwrap_or(u64::MAX)
    }

    fn term(&self, index: u64) -> Option<u64> {
        if index == 0 {
            return Some(0);
        }
        let at = usize::try_from(index - 1).ok()?;
        self.terms.get(at).copied()
    }

    fn size(&self, index: u64) -> Option<u64> {
        let at = usize::try_from(index.checked_sub(1)?).ok()?;
        self.ids.get(at).map(|&id| size_of(id))
    }
}

/// An entry's size in bytes, from its identity: 100 to 500.
const fn size_of(id: u64) -> u64 {
    (id % 5 + 1) * 100
}

/// The model's flow limits: a batch of 4, 8 entries or 1,000 bytes in
/// flight per follower (two to ten entries, so both bounds are reached),
/// 16 uncommitted entries, 6 size lookups and 1,500 bytes read per
/// duty.
const LIMITS: Limits = Limits {
    in_flight_entries: 8,
    in_flight_bytes: 1_000,
    queue: 16,
    reads: 6,
    read_bytes: 1_500,
};

/// What one core call asked for.
#[derive(Debug, Default, PartialEq, Eq)]
struct Recorded {
    /// Every effect, in order, for the persist-then-send checks.
    trace: Vec<Effect>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Persist(TermVote),
    Write(u64, u64),
    Append(u64, u64),
    Send(u64, Message),
    SendAfter(u64, Message),
    Commit(u64),
    Snapshot(u64),
}

impl Effects for Recorded {
    fn persist(&mut self, term_vote: TermVote) {
        self.trace.push(Effect::Persist(term_vote));
    }
    fn write(&mut self, index: u64, skip: u64) {
        self.trace.push(Effect::Write(index, skip));
    }
    fn append(&mut self, index: u64, term: u64) {
        self.trace.push(Effect::Append(index, term));
    }
    fn send(&mut self, to: u64, message: Message) {
        self.trace.push(Effect::Send(to, message));
    }
    fn send_after_persist(&mut self, to: u64, message: Message) {
        self.trace.push(Effect::SendAfter(to, message));
    }
    fn commit(&mut self, index: u64) {
        self.trace.push(Effect::Commit(index));
    }
    fn send_snapshot(&mut self, to: u64) {
        // This model never compacts: no snapshot is ever needed.
        self.trace.push(Effect::Snapshot(to));
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

struct InFlight {
    from: u64,
    to: u64,
    message: Message,
    terms: Vec<u64>,
    ids: Vec<u64>,
}

struct Node {
    core: Core,
    log: TestLog,
    stored: TermVote,
}

struct Cluster {
    ids: Vec<u64>,
    nodes: BTreeMap<u64, Node>,
    net: Vec<InFlight>,
    rng: Rng,
    seed: u64,
    /// The leader of each term.
    leaders: BTreeMap<u64, u64>,
    /// The longest committed prefix seen on any node, as (term, id).
    committed: Vec<(u64, u64)>,
    /// The next entry identity.
    next_id: u64,
    /// Every event, for the determinism check.
    history: Vec<String>,
    /// Proposals refused by backpressure.
    refused: usize,
}

fn config(id: u64, ids: &[u64], seed: u64) -> Result<Config, ConfigError> {
    Config::new(id, ids, 10, 20, 3, 4, seed)?.with_limits(LIMITS)
}

impl Cluster {
    fn new(size: u64, seed: u64) -> Self {
        let ids: Vec<u64> = (1..=size).collect();
        let mut nodes = BTreeMap::new();
        for &id in &ids {
            let config = config(id, &ids, seed);
            assert!(config.is_ok(), "{config:?}");
            if let Ok(config) = config {
                nodes.insert(
                    id,
                    Node {
                        core: Core::new(config, TermVote::default(), 0),
                        log: TestLog::default(),
                        stored: TermVote::default(),
                    },
                );
            }
        }
        Self {
            ids,
            nodes,
            net: Vec::new(),
            rng: Rng(seed),
            seed,
            leaders: BTreeMap::new(),
            committed: Vec::new(),
            next_id: 1,
            history: Vec::new(),
            refused: 0,
        }
    }

    /// Applies a call's effects as a driver does: persists and writes
    /// first, then the messages; checks persist then send.
    fn apply(&mut self, id: u64, recorded: Recorded, incoming: (&[u64], &[u64])) {
        let mut durable = true;
        for effect in &recorded.trace {
            // What waits for durability never goes out at once.
            if let Effect::Send(_, message) = effect {
                let waits = matches!(
                    message,
                    Message::Vote { .. }
                        | Message::VoteReply { .. }
                        | Message::AppendReply {
                            outcome: AppendOutcome::Accepted { .. },
                            ..
                        }
                );
                assert!(!waits, "sent before persisting: {message:?}");
            }
            if let Effect::Persist(_) | Effect::Write(..) = effect {
                assert!(
                    durable,
                    "a persist after a send-after-persist: {recorded:?}"
                );
            }
            if let Effect::SendAfter(..) = effect {
                durable = false;
            }
        }
        let Some(node) = self.nodes.get_mut(&id) else {
            return;
        };
        let mut appended = false;
        for effect in &recorded.trace {
            match *effect {
                Effect::Persist(term_vote) => node.stored = term_vote,
                Effect::Write(index, skip) => {
                    let keep = usize::try_from(index - 1).unwrap_or(usize::MAX);
                    node.log.terms.truncate(keep);
                    node.log.ids.truncate(keep);
                    let skip = usize::try_from(skip).unwrap_or(usize::MAX);
                    node.log.terms.extend(incoming.0.iter().skip(skip));
                    node.log.ids.extend(incoming.1.iter().skip(skip));
                }
                Effect::Append(index, term) => {
                    assert_eq!(index, node.log.last_index() + 1);
                    node.log.push(term, self.next_id);
                    self.next_id += 1;
                    appended = true;
                }
                Effect::Commit(_) | Effect::Send(..) | Effect::SendAfter(..) => {}
                Effect::Snapshot(to) => assert_eq!(to, 0, "a snapshot asked without compaction"),
            }
        }
        assert_eq!(
            node.stored,
            node.core.term_vote(),
            "the stored term and vote"
        );
        for effect in &recorded.trace {
            if let Effect::Send(to, message) | Effect::SendAfter(to, message) = *effect {
                let (from, count) = match message {
                    Message::Append {
                        prev_index,
                        entries,
                        ..
                    } => (
                        usize::try_from(prev_index).unwrap_or(usize::MAX),
                        usize::try_from(entries).unwrap_or(usize::MAX),
                    ),
                    _ => (0, 0),
                };
                if let Message::Append { entries, .. } = message {
                    // From the entries themselves, not the core's counters.
                    let bytes: u64 = node
                        .log
                        .ids
                        .iter()
                        .skip(from)
                        .take(count)
                        .map(|&id| size_of(id))
                        .sum();
                    assert!(entries <= 4, "{entries} entries in one append");
                    assert!(
                        entries <= 1 || bytes <= LIMITS.in_flight_bytes,
                        "{bytes} bytes in one append"
                    );
                }
                let terms = node
                    .log
                    .terms
                    .iter()
                    .skip(from)
                    .take(count)
                    .copied()
                    .collect();
                let ids = node
                    .log
                    .ids
                    .iter()
                    .skip(from)
                    .take(count)
                    .copied()
                    .collect();
                self.net.push(InFlight {
                    from: id,
                    to,
                    message,
                    terms,
                    ids,
                });
            }
        }
        if appended {
            self.persisted(id);
        }
        self.check(id);
    }

    fn persisted(&mut self, id: u64) {
        let Some(node) = self.nodes.get_mut(&id) else {
            return;
        };
        let mut recorded = Recorded::default();
        node.core
            .persisted(node.log.last_index(), &node.log, &mut recorded);
        node.core.replicate(&node.log, &mut recorded);
        self.apply(id, recorded, (&[], &[]));
    }

    fn event(&mut self) {
        let size = u64::try_from(self.ids.len()).unwrap_or(0);
        let pick = self
            .ids
            .get(usize::try_from(self.rng.below(size)).unwrap_or(0));
        let id = pick.copied().unwrap_or(1);
        match self.rng.below(100) {
            0..=29 => {
                self.history.push(format!("tick {id}"));
                let Some(node) = self.nodes.get_mut(&id) else {
                    return;
                };
                let mut recorded = Recorded::default();
                node.core.tick(&node.log, &mut recorded);
                self.apply(id, recorded, (&[], &[]));
            }
            30..=39 => {
                let Some(node) = self.nodes.get_mut(&id) else {
                    return;
                };
                match node.core.propose(size_of(self.next_id), &node.log) {
                    Ok((index, term)) => {
                        self.history.push(format!("propose {id} {index} {term}"));
                        assert_eq!(index, node.log.last_index() + 1);
                        node.log.push(term, self.next_id);
                        self.next_id += 1;
                        self.persisted(id);
                    }
                    Err(ProposeError::Backpressure(why)) => {
                        self.history.push(format!("refused {id} {why:?}"));
                        self.refused += 1;
                    }
                    Err(ProposeError::NotLeader(_)) => {}
                }
            }
            40 => {
                // A restart: the volatile state is lost, the log and the
                // term and vote are durable.
                self.history.push(format!("restart {id}"));
                let ids = self.ids.clone();
                let seed = self.seed.wrapping_add(self.rng.next());
                if let (Some(node), Ok(config)) = (self.nodes.get_mut(&id), config(id, &ids, seed))
                {
                    node.core = Core::new(config, node.stored, 0);
                }
            }
            _ => {
                if self.net.is_empty() {
                    return;
                }
                let len = u64::try_from(self.net.len()).unwrap_or(1);
                let at = usize::try_from(self.rng.below(len)).unwrap_or(0);
                let roll = self.rng.below(100);
                let flight = if roll < 5 {
                    // Duplicated: delivered and kept.
                    let Some(kept) = self.net.get(at) else { return };
                    InFlight {
                        from: kept.from,
                        to: kept.to,
                        message: kept.message,
                        terms: kept.terms.clone(),
                        ids: kept.ids.clone(),
                    }
                } else {
                    self.net.swap_remove(at)
                };
                if (5..15).contains(&roll) {
                    self.history.push("drop".to_owned());
                    return;
                }
                self.history.push(format!(
                    "deliver {} -> {} {:?}",
                    flight.from, flight.to, flight.message
                ));
                let Some(node) = self.nodes.get_mut(&flight.to) else {
                    return;
                };
                let mut recorded = Recorded::default();
                let stepped = node.core.step(
                    flight.from,
                    flight.message,
                    &flight.terms,
                    &node.log,
                    &mut recorded,
                );
                assert_eq!(stepped, Ok(()), "{:?}", flight.message);
                self.apply(flight.to, recorded, (&flight.terms, &flight.ids));
            }
        }
    }

    fn check(&mut self, id: u64) {
        let Some(node) = self.nodes.get(&id) else {
            return;
        };
        let term = node.core.term_vote().term;
        if node.core.role() == Role::Leader {
            let leader = *self.leaders.entry(term).or_insert(id);
            assert_eq!(leader, id, "two leaders in term {term}");
            // Leader completeness, for the newest leader: a deposed one
            // that has not heard yet may lack later terms' entries.
            let newest = self.leaders.keys().next_back().copied().unwrap_or(0);
            assert!(
                term < newest || node.log.entries().starts_with(&self.committed),
                "leader {id} of term {term} lacks committed entries"
            );
            // The flow limits hold strictly, whatever the network lost.
            for &other in &self.ids {
                if let Some((entries, bytes)) = node.core.in_flight(other) {
                    assert!(
                        entries <= LIMITS.in_flight_entries,
                        "{entries} entries in flight to {other}"
                    );
                    assert!(
                        bytes <= LIMITS.in_flight_bytes,
                        "{bytes} bytes in flight to {other}"
                    );
                }
            }
        }
        // State machine safety: committed prefixes agree.
        let commit = usize::try_from(node.core.commit()).unwrap_or(usize::MAX);
        assert!(
            commit <= node.log.terms.len(),
            "commit past the log on {id}"
        );
        let entries = node.log.entries();
        let mine = entries.get(..commit).unwrap_or(&[]);
        let shorter = mine.len().min(self.committed.len());
        assert_eq!(
            mine.get(..shorter),
            self.committed.get(..shorter),
            "committed prefixes differ on {id}"
        );
        if mine.len() > self.committed.len() {
            self.committed = mine.to_vec();
        }
        // Log matching against every other node.
        for other in self.nodes.values() {
            let theirs = other.log.entries();
            let common = theirs.len().min(entries.len());
            for at in (0..common).rev() {
                if theirs.get(at).map(|e| e.0) == entries.get(at).map(|e| e.0) {
                    assert_eq!(
                        theirs.get(..=at),
                        entries.get(..=at),
                        "log matching broken at {}",
                        at + 1
                    );
                    break;
                }
            }
        }
    }
}

fn run(size: u64, seed: u64, events: usize) -> Cluster {
    let mut cluster = Cluster::new(size, seed);
    for _ in 0..events {
        cluster.event();
    }
    cluster
}

#[test]
fn three_and_five_nodes_keep_raft_safety_and_commit() {
    for size in [3, 5] {
        let mut committed = 0;
        let mut refused = 0;
        for seed in 0..100 {
            let cluster = run(size, seed, 4_000);
            committed += cluster.committed.len();
            refused += cluster.refused;
        }
        assert!(committed > 1_000, "{size} nodes committed {committed}");
        assert!(refused > 0, "{size} nodes never reached a flow limit");
    }
}

#[test]
fn the_same_seed_reproduces_the_same_history() {
    let first = run(5, 7, 3_000);
    let second = run(5, 7, 3_000);
    assert_eq!(first.history, second.history);
    assert_eq!(first.committed, second.committed);
    let other = run(5, 8, 3_000);
    assert_ne!(first.history, other.history);
}

fn core(id: u64, term: u64) -> Core {
    core_with(id, term, None)
}

/// A core with the default limits, or `limits`.
fn core_with(id: u64, term: u64, limits: Option<Limits>) -> Core {
    let config = Config::new(id, &[1, 2, 3], 10, 20, 3, 4, 1)
        .and_then(|config| limits.map_or(Ok(config), |limits| config.with_limits(limits)));
    assert!(config.is_ok());
    let config = config.unwrap_or_else(|_| unreachable!());
    Core::new(
        config,
        TermVote {
            term,
            voted_for: None,
        },
        0,
    )
}

fn tick_until_pre_vote(core: &mut Core, log: &TestLog) -> Recorded {
    for _ in 0..100 {
        let mut recorded = Recorded::default();
        core.tick(log, &mut recorded);
        if !recorded.trace.is_empty() {
            return recorded;
        }
    }
    Recorded::default()
}

/// The round of the pre-votes a call sent.
fn round_of(recorded: &Recorded) -> u64 {
    recorded
        .trace
        .iter()
        .find_map(|effect| match effect {
            Effect::Send(_, Message::PreVote { round, .. }) => Some(*round),
            _ => None,
        })
        .unwrap_or(0)
}

/// Node 1 elected in term `term + 1` over `log`.
fn leader(term: u64, log: &TestLog) -> Core {
    leader_with(term, log, None)
}

/// Node 1 elected in term `term + 1` over `log`, with `limits`.
fn leader_with(term: u64, log: &TestLog, limits: Option<Limits>) -> Core {
    let mut node = core_with(1, term, limits);
    let pre = tick_until_pre_vote(&mut node, log);
    let round = round_of(&pre);
    assert_eq!(node.role(), Role::PreCandidate);
    assert_eq!(node.term_vote().term, term, "a pre-vote keeps the term");
    assert!(
        pre.trace
            .iter()
            .all(|e| matches!(e, Effect::Send(_, Message::PreVote { .. })))
    );
    let mut recorded = Recorded::default();
    let reply = Message::PreVoteReply {
        term: term + 1,
        granted: true,
        round,
    };
    assert_eq!(node.step(2, reply, &[], log, &mut recorded), Ok(()));
    assert_eq!(node.role(), Role::Candidate);
    let vote = Message::VoteReply {
        term: term + 1,
        granted: true,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(3, vote, &[], log, &mut recorded), Ok(()));
    assert_eq!(node.role(), Role::Leader);
    assert_eq!(
        recorded.trace,
        vec![Effect::Append(log.last_index() + 1, term + 1)]
    );
    node
}

#[test]
fn a_candidate_persists_its_vote_before_asking_for_votes() {
    let log = TestLog::default();
    let mut node = core(1, 4);
    let round = round_of(&tick_until_pre_vote(&mut node, &log));
    let mut recorded = Recorded::default();
    let reply = Message::PreVoteReply {
        term: 5,
        granted: true,
        round,
    };
    assert_eq!(node.step(3, reply, &[], &log, &mut recorded), Ok(()));
    let vote = Message::Vote {
        term: 5,
        last_index: 0,
        last_term: 0,
    };
    assert_eq!(
        recorded.trace,
        vec![
            Effect::Persist(TermVote {
                term: 5,
                voted_for: Some(1)
            }),
            Effect::SendAfter(2, vote),
            Effect::SendAfter(3, vote),
        ]
    );
}

#[test]
fn a_vote_is_persisted_before_its_reply_and_given_once_per_term() {
    let log = TestLog::of(vec![1, 2]);
    let mut node = core(1, 2);
    let mut recorded = Recorded::default();
    let ask = |last_term| Message::Vote {
        term: 3,
        last_index: 2,
        last_term,
    };
    // A shorter log is refused, but the term is followed.
    assert_eq!(node.step(2, ask(1), &[], &log, &mut recorded), Ok(()));
    let refused = Message::VoteReply {
        term: 3,
        granted: false,
    };
    assert_eq!(
        recorded.trace,
        vec![
            Effect::Persist(TermVote {
                term: 3,
                voted_for: None
            }),
            Effect::SendAfter(2, refused),
        ]
    );
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, ask(2), &[], &log, &mut recorded), Ok(()));
    let granted = Message::VoteReply {
        term: 3,
        granted: true,
    };
    assert_eq!(
        recorded.trace,
        vec![
            Effect::Persist(TermVote {
                term: 3,
                voted_for: Some(2)
            }),
            Effect::SendAfter(2, granted),
        ]
    );
    // Another candidate of the same term is refused.
    let mut recorded = Recorded::default();
    assert_eq!(node.step(3, ask(2), &[], &log, &mut recorded), Ok(()));
    assert_eq!(recorded.trace, vec![Effect::SendAfter(3, refused)]);
}

#[test]
fn a_partitioned_node_does_not_raise_the_term() {
    let log = TestLog::default();
    let mut node = core(1, 7);
    for _ in 0..1_000 {
        let mut recorded = Recorded::default();
        node.tick(&log, &mut recorded);
    }
    assert_eq!(node.role(), Role::PreCandidate);
    assert_eq!(node.term_vote().term, 7);
}

#[test]
fn a_follower_of_a_live_leader_refuses_a_pre_vote() {
    let log = TestLog::of(vec![3]);
    let mut node = core(2, 3);
    let heartbeat = Message::Append {
        term: 3,
        prev_index: 1,
        prev_term: 3,
        entries: 0,
        commit: 0,
        epoch: 0,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(1, heartbeat, &[], &log, &mut recorded), Ok(()));
    let pre = Message::PreVote {
        term: 4,
        last_index: 1,
        last_term: 3,
        round: 9,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(3, pre, &[], &log, &mut recorded), Ok(()));
    let refused = Message::PreVoteReply {
        term: 3,
        granted: false,
        round: 9,
    };
    assert_eq!(recorded.trace, vec![Effect::Send(3, refused)]);
    assert_eq!(node.term_vote().term, 3, "a pre-vote changes no term");
}

#[test]
fn an_earlier_term_entry_commits_only_with_one_of_the_leaders_term() {
    // Raft's figure 8: index 2 of term 2 on a majority is not committed
    // by a leader of term 3 until an entry of term 3 is.
    let mut log = TestLog::of(vec![1, 2]);
    let mut node = leader(2, &log);
    let mut recorded = Recorded::default();
    node.persisted(2, &log, &mut recorded);
    let e2 = epoch_of(&node, 2);
    let accepted = |index| Message::AppendReply {
        term: 3,
        outcome: AppendOutcome::Accepted { index },
        epoch: e2,
    };
    assert_eq!(node.step(2, accepted(2), &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.commit(), 0);
    assert!(
        !recorded
            .trace
            .iter()
            .any(|e| matches!(e, Effect::Commit(_)))
    );
    log.terms.push(3);
    let mut recorded = Recorded::default();
    node.persisted(3, &log, &mut recorded);
    assert_eq!(node.commit(), 0, "the leader alone is no majority");
    assert_eq!(node.step(3, accepted(3), &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.commit(), 3);
    assert_eq!(recorded.trace, vec![Effect::Commit(3)]);
}

#[test]
fn a_follower_acknowledges_only_after_its_write() {
    let log = TestLog::of(vec![1, 1]);
    let mut node = core(2, 1);
    let append = Message::Append {
        term: 2,
        prev_index: 1,
        prev_term: 1,
        entries: 2,
        commit: 3,
        epoch: 0,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(1, append, &[2, 2], &log, &mut recorded), Ok(()));
    assert_eq!(
        recorded.trace,
        vec![
            Effect::Persist(TermVote {
                term: 2,
                voted_for: None
            }),
            Effect::Write(2, 0),
            Effect::Commit(3),
            Effect::SendAfter(
                1,
                Message::AppendReply {
                    term: 2,
                    outcome: AppendOutcome::Accepted { index: 3 },
                    epoch: 0,
                }
            ),
        ]
    );
    assert_eq!(node.role(), Role::Follower { leader: Some(1) });
}

#[test]
fn a_mismatched_previous_entry_is_rejected_with_a_hint() {
    let log = TestLog::of(vec![1]);
    let mut node = core(2, 1);
    let append = |prev_index, prev_term| Message::Append {
        term: 2,
        prev_index,
        prev_term,
        entries: 0,
        commit: 0,
        epoch: 0,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(1, append(5, 2), &[], &log, &mut recorded), Ok(()));
    assert_eq!(
        recorded.trace.last(),
        Some(&Effect::SendAfter(
            1,
            Message::AppendReply {
                term: 2,
                outcome: AppendOutcome::Rejected { probe: 5, hint: 1 },
                epoch: 0,
            }
        ))
    );
    let mut recorded = Recorded::default();
    assert_eq!(node.step(1, append(1, 2), &[], &log, &mut recorded), Ok(()));
    assert_eq!(
        recorded.trace,
        vec![Effect::SendAfter(
            1,
            Message::AppendReply {
                term: 2,
                outcome: AppendOutcome::Rejected { probe: 1, hint: 0 },
                epoch: 0,
            }
        )]
    );
}

#[test]
fn an_append_truncating_a_committed_entry_is_refused() {
    let log = TestLog::of(vec![1, 1]);
    let mut node = core(2, 1);
    let commit = Message::Append {
        term: 1,
        prev_index: 2,
        prev_term: 1,
        entries: 0,
        commit: 2,
        epoch: 0,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(1, commit, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.commit(), 2);
    let rewrite = Message::Append {
        term: 2,
        prev_index: 1,
        prev_term: 1,
        entries: 1,
        commit: 2,
        epoch: 0,
    };
    let mut recorded = Recorded::default();
    let before = node.term_vote();
    assert_eq!(
        node.step(3, rewrite, &[2], &log, &mut recorded),
        Err(StepError::CommittedConflict)
    );
    assert!(recorded.trace.is_empty());
    assert_eq!(node.term_vote(), before);
}

#[test]
fn malformed_messages_and_strangers_are_refused() {
    let log = TestLog::default();
    let mut node = core(2, 1);
    let append = Message::Append {
        term: 1,
        prev_index: 0,
        prev_term: 0,
        entries: 2,
        commit: 0,
        epoch: 0,
    };
    let mut recorded = Recorded::default();
    assert_eq!(
        node.step(1, append, &[1], &log, &mut recorded),
        Err(StepError::Malformed)
    );
    assert_eq!(
        node.step(1, append, &[1, 2], &log, &mut recorded),
        Err(StepError::Malformed),
        "an entry above the leader's term"
    );
    assert_eq!(
        node.step(9, append, &[1, 1], &log, &mut recorded),
        Err(StepError::UnknownSender)
    );
    assert_eq!(
        node.step(2, append, &[1, 1], &log, &mut recorded),
        Err(StepError::UnknownSender)
    );
    assert!(recorded.trace.is_empty());
}

#[test]
fn a_rejected_append_is_retried_from_the_hint() {
    let log = TestLog::of(vec![1, 1, 1, 1]);
    let mut node = leader(1, &log);
    let mut recorded = Recorded::default();
    let rejected = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 4, hint: 1 },
        epoch: epoch_of(&node, 2),
    };
    assert_eq!(node.step(2, rejected, &[], &log, &mut recorded), Ok(()));
    assert_eq!(
        recorded.trace,
        vec![Effect::Send(
            2,
            Message::Append {
                term: 2,
                prev_index: 1,
                prev_term: 1,
                entries: 3,
                commit: 0,
                epoch: epoch_of(&node, 2),
            }
        )]
    );
}

#[test]
fn configurations_are_checked() {
    assert_eq!(
        Config::new(1, &[1, 2], 10, 20, 3, 4, 0).err(),
        Some(ConfigError::VoterCount(2))
    );
    assert_eq!(
        Config::new(1, &[1, 2, 3, 4], 10, 20, 3, 4, 0).err(),
        Some(ConfigError::VoterCount(4))
    );
    assert_eq!(
        Config::new(9, &[1, 2, 3], 10, 20, 3, 4, 0).err(),
        Some(ConfigError::NotAVoter)
    );
    assert_eq!(
        Config::new(1, &[1, 2, 2], 10, 20, 3, 4, 0).err(),
        Some(ConfigError::BadVoter)
    );
    assert_eq!(
        Config::new(1, &[1, 2, 3], 10, 10, 3, 4, 0).err(),
        Some(ConfigError::Timeouts)
    );
    assert_eq!(
        Config::new(1, &[1, 2, 3], 10, 11, 3, 4, 0).err(),
        Some(ConfigError::Timeouts),
        "one timeout value"
    );
    assert!(Config::new(1, &[1, 2, 3], 10, 12, 3, 4, 0).is_ok());
    assert_eq!(
        Config::new(1, &[1, 2, 3], 10, 20, 10, 4, 0).err(),
        Some(ConfigError::Timeouts)
    );
    assert_eq!(
        Config::new(1, &[1, 2, 3], 10, 20, 3, 0, 0).err(),
        Some(ConfigError::Batch)
    );
    assert!(Config::new(1, &[1, 2, 3, 4, 5], 10, 20, 3, 4, 0).is_ok());
}

#[test]
fn election_timeouts_are_seeded_and_in_range() {
    let draw = |seed| {
        let config = Config::new(1, &[1, 2, 3], 10, 20, 3, 4, seed);
        config.map(|config| Core::new(config, TermVote::default(), 0).election_timeout())
    };
    assert_eq!(draw(5), draw(5));
    let timeouts: Vec<_> = (0..50).filter_map(|seed| draw(seed).ok()).collect();
    assert!(timeouts.iter().all(|t| (10..20).contains(t)));
    assert!(
        timeouts
            .iter()
            .any(|&t| t != timeouts.first().copied().unwrap_or(0))
    );
}

#[test]
fn a_leader_without_a_quorum_steps_down() {
    // A one-way partition: the leader's heartbeats reach a follower but
    // no answer comes back. The leader steps down within an election
    // timeout, so the follower stops refusing other pre-votes.
    let log = TestLog::of(vec![1]);
    let mut node = leader(1, &log);
    for _ in 0..9 {
        let mut recorded = Recorded::default();
        node.tick(&log, &mut recorded);
    }
    assert_eq!(node.role(), Role::Leader);
    let mut recorded = Recorded::default();
    node.tick(&log, &mut recorded);
    assert_eq!(node.role(), Role::Follower { leader: None });
    assert_eq!(node.term_vote().term, 2, "stepping down keeps the term");
}

#[test]
fn a_leader_answered_by_a_quorum_stays() {
    let log = TestLog::of(vec![1]);
    let mut node = leader(1, &log);
    for tick in 0..100 {
        let mut recorded = Recorded::default();
        node.tick(&log, &mut recorded);
        if tick % 5 == 0 {
            let reply = Message::AppendReply {
                term: 2,
                outcome: AppendOutcome::Accepted { index: 1 },
                epoch: epoch_of(&node, 2),
            };
            assert_eq!(node.step(2, reply, &[], &log, &mut recorded), Ok(()));
        }
    }
    assert_eq!(node.role(), Role::Leader);
}

#[test]
fn a_pre_vote_grant_of_an_earlier_round_is_not_counted() {
    let log = TestLog::default();
    let mut node = core(1, 4);
    let first = round_of(&tick_until_pre_vote(&mut node, &log));
    let second = round_of(&tick_until_pre_vote(&mut node, &log));
    assert_ne!(first, second);
    let mut recorded = Recorded::default();
    let stale = Message::PreVoteReply {
        term: 5,
        granted: true,
        round: first,
    };
    assert_eq!(node.step(2, stale, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.role(), Role::PreCandidate);
    assert!(recorded.trace.is_empty());
    let fresh = Message::PreVoteReply {
        term: 5,
        granted: true,
        round: second,
    };
    assert_eq!(node.step(2, fresh, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.role(), Role::Candidate);
}

#[test]
fn a_late_rejection_of_an_acknowledged_prefix_is_ignored() {
    let log = TestLog::of(vec![1, 1, 1, 1]);
    let mut node = leader(1, &log);
    let mut recorded = Recorded::default();
    let accepted = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 4 },
        epoch: epoch_of(&node, 2),
    };
    assert_eq!(node.step(2, accepted, &[], &log, &mut recorded), Ok(()));
    let late = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 3, hint: 1 },
        epoch: epoch_of(&node, 2),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, late, &[], &log, &mut recorded), Ok(()));
    assert!(recorded.trace.is_empty(), "no rewind: {recorded:?}");
}

/// The appends a call sent to `to`, as (prev index, entries).
fn appends_to(recorded: &Recorded, to: u64) -> Vec<(u64, u64)> {
    recorded
        .trace
        .iter()
        .filter_map(|effect| match *effect {
            Effect::Send(
                peer,
                Message::Append {
                    prev_index,
                    entries,
                    ..
                },
            ) if peer == to => Some((prev_index, entries)),
            _ => None,
        })
        .collect()
}

/// A log of `count` entries of term 1 and 100 bytes each.
fn hundreds(count: usize) -> TestLog {
    let mut log = TestLog::default();
    for _ in 0..count {
        log.push(1, 5);
    }
    log
}

const TIGHT: Limits = Limits {
    in_flight_entries: 8,
    in_flight_bytes: 500,
    queue: 64,
    reads: 64,
    read_bytes: u64::MAX,
};

#[test]
fn the_in_flight_window_holds_across_lost_acknowledgements() {
    let mut log = hundreds(20);
    let mut node = leader_with(1, &log, Some(TIGHT));
    log.push(2, 5);
    let mut recorded = Recorded::default();
    node.replicate(&log, &mut recorded);
    assert_eq!(appends_to(&recorded, 2), vec![(20, 1)]);
    assert_eq!(node.in_flight(2), Some((1, 100)));
    // The follower is at the start: rewind to it, releasing the probe.
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 20, hint: 0 },
        epoch: epoch_of(&node, 2),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, reject, &[], &log, &mut recorded), Ok(()));
    // A batch of 4 (400 bytes), then 1 more reaches the 500-byte cap.
    assert_eq!(appends_to(&recorded, 2), vec![(0, 4)]);
    assert_eq!(node.in_flight(2), Some((4, 400)));
    let mut recorded = Recorded::default();
    node.replicate(&log, &mut recorded);
    assert_eq!(appends_to(&recorded, 2), vec![(4, 1)]);
    assert_eq!(node.in_flight(2), Some((5, 500)));
    // Every acknowledgement is lost: heartbeats only, nothing more sent.
    for _ in 0..3 {
        let mut recorded = Recorded::default();
        node.replicate(&log, &mut recorded);
        assert_eq!(appends_to(&recorded, 2), vec![(5, 0)]);
        assert_eq!(node.in_flight(2), Some((5, 500)));
    }
    // An acknowledgement covering a send in part frees nothing of it.
    let partial = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 3 },
        epoch: epoch_of(&node, 2),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, partial, &[], &log, &mut recorded), Ok(()));
    assert_eq!(appends_to(&recorded, 2), vec![]);
    assert_eq!(node.in_flight(2), Some((5, 500)));
    // A heartbeat's answer frees the window, and the leader refills it.
    let accepted = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 5 },
        epoch: epoch_of(&node, 2),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, accepted, &[], &log, &mut recorded), Ok(()));
    assert_eq!(appends_to(&recorded, 2), vec![(5, 4)]);
    assert_eq!(node.in_flight(2), Some((4, 400)));
    // A duplicate of it frees nothing more.
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, accepted, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.in_flight(2), Some((4, 400)));
}

#[test]
fn a_rejection_releases_what_is_past_the_retry_point() {
    let log = hundreds(8);
    let mut node = leader_with(1, &log, Some(TIGHT));
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 8, hint: 0 },
        epoch: epoch_of(&node, 2),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, reject, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.in_flight(2), Some((4, 400)));
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 2, hint: 1 },
        epoch: epoch_of(&node, 2),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, reject, &[], &log, &mut recorded), Ok(()));
    // The send of 1..=4 straddles the retry point: entry 1 stays in
    // flight and the send keeps its whole 400 bytes, so one more fits.
    assert_eq!(appends_to(&recorded, 2), vec![(1, 1)]);
    assert_eq!(node.in_flight(2), Some((2, 500)));
}

#[test]
fn the_entries_in_flight_are_bounded_without_a_byte_cap() {
    let log = hundreds(30);
    let limits = Limits {
        in_flight_entries: 8,
        in_flight_bytes: u64::MAX,
        queue: 64,
        reads: 64,
        read_bytes: u64::MAX,
    };
    let mut node = leader_with(1, &log, Some(limits));
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 30, hint: 0 },
        epoch: epoch_of(&node, 3),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(3, reject, &[], &log, &mut recorded), Ok(()));
    for _ in 0..4 {
        let mut recorded = Recorded::default();
        node.replicate(&log, &mut recorded);
    }
    assert_eq!(node.in_flight(3), Some((8, 800)));
}

#[test]
fn a_duty_reads_at_most_its_budget() {
    let log = hundreds(8);
    let limits = Limits {
        in_flight_entries: 8,
        in_flight_bytes: u64::MAX,
        queue: 64,
        reads: 6,
        read_bytes: u64::MAX,
    };
    let mut node = leader_with(1, &log, Some(limits));
    for peer in [2, 3] {
        let reject = Message::AppendReply {
            term: 2,
            outcome: AppendOutcome::Rejected { probe: 8, hint: 0 },
            epoch: epoch_of(&node, peer),
        };
        let mut recorded = Recorded::default();
        assert_eq!(node.step(peer, reject, &[], &log, &mut recorded), Ok(()));
    }
    // Both at 4 in flight; one duty may read 6 more entries in all.
    let mut recorded = Recorded::default();
    node.replicate(&log, &mut recorded);
    let sent: u64 = [2, 3]
        .iter()
        .flat_map(|&peer| appends_to(&recorded, peer))
        .map(|(_, entries)| entries)
        .sum();
    assert_eq!(sent, 6);
}

#[test]
fn proposals_beyond_a_limit_are_refused_with_backpressure() {
    let log = hundreds(3);
    let limits = Limits {
        in_flight_entries: 8,
        in_flight_bytes: 500,
        queue: 4,
        reads: 64,
        read_bytes: u64::MAX,
    };
    let node = leader_with(1, &log, Some(limits));
    assert_eq!(
        node.propose(501, &log),
        Err(ProposeError::Backpressure(Backpressure::InFlightBytes))
    );
    assert_eq!(node.propose(500, &log), Ok((4, 2)));
    let full = hundreds(4);
    assert_eq!(
        node.propose(1, &full),
        Err(ProposeError::Backpressure(Backpressure::Queue))
    );
    let follower = core(2, 1);
    assert!(matches!(
        follower.propose(1, &log),
        Err(ProposeError::NotLeader(_))
    ));
}

#[test]
fn flow_limits_are_checked() {
    let base = Config::new(1, &[1, 2, 3], 10, 20, 3, 4, 0);
    assert!(base.is_ok());
    let base = base.unwrap_or_else(|_| unreachable!());
    let good = Limits {
        in_flight_entries: 4,
        in_flight_bytes: 1,
        queue: 1,
        reads: 1,
        read_bytes: u64::MAX,
    };
    assert_eq!(base.with_limits(good).map(|c| c.limits()), Ok(good));
    for bad in [
        Limits {
            in_flight_entries: 3,
            ..good
        },
        Limits {
            in_flight_bytes: 0,
            ..good
        },
        Limits { queue: 0, ..good },
        Limits { reads: 0, ..good },
        Limits {
            read_bytes: 0,
            ..good
        },
    ] {
        assert_eq!(base.with_limits(bad).err(), Some(ConfigError::Limits));
    }
}

/// A leader's pipeline epoch for `peer`.
fn epoch_of(node: &Core, peer: u64) -> u64 {
    node.pipeline_epoch(peer).unwrap_or(0)
}

#[test]
fn a_duplicate_or_earlier_rejection_refunds_nothing() {
    let log = hundreds(8);
    let mut node = leader_with(1, &log, Some(TIGHT));
    let first = epoch_of(&node, 2);
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 8, hint: 0 },
        epoch: first,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, reject, &[], &log, &mut recorded), Ok(()));
    assert_eq!(appends_to(&recorded, 2), vec![(0, 4)]);
    assert_eq!(node.in_flight(2), Some((4, 400)));
    assert_ne!(epoch_of(&node, 2), first, "a rewind starts an epoch");
    // The same rejection again (a duplicate of the reply, or a second
    // heartbeat's): no rewind, no refund, no resend.
    for _ in 0..3 {
        let mut recorded = Recorded::default();
        assert_eq!(node.step(2, reject, &[], &log, &mut recorded), Ok(()));
        assert!(recorded.trace.is_empty(), "{recorded:?}");
        assert_eq!(node.in_flight(2), Some((4, 400)));
    }
    // A rejection of a different probe, still from the earlier epoch.
    let earlier = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 3, hint: 0 },
        epoch: first,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, earlier, &[], &log, &mut recorded), Ok(()));
    assert!(recorded.trace.is_empty());
    assert_eq!(node.in_flight(2), Some((4, 400)));
}

#[test]
fn a_new_term_starts_from_an_empty_window() {
    let log = hundreds(8);
    let mut node = leader_with(1, &log, Some(TIGHT));
    let old = epoch_of(&node, 2);
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 8, hint: 0 },
        epoch: old,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, reject, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.in_flight(2), Some((4, 400)));
    // Deposed by a higher term, then elected again in term 4.
    let higher = Message::AppendReply {
        term: 3,
        outcome: AppendOutcome::Accepted { index: 0 },
        epoch: 0,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(3, higher, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.in_flight(2), None);
    let round = round_of(&tick_until_pre_vote(&mut node, &log));
    for message in [
        Message::PreVoteReply {
            term: 4,
            granted: true,
            round,
        },
        Message::VoteReply {
            term: 4,
            granted: true,
        },
    ] {
        let mut recorded = Recorded::default();
        assert_eq!(node.step(2, message, &[], &log, &mut recorded), Ok(()));
    }
    assert_eq!(node.role(), Role::Leader);
    assert_eq!(node.in_flight(2), Some((0, 0)));
    assert_ne!(epoch_of(&node, 2), old);
}

#[test]
fn an_entry_larger_than_the_window_is_sent_alone() {
    // Written under a larger limit: 500 bytes against a 300-byte window.
    let mut log = hundreds(1);
    log.push(1, 4);
    log.push(1, 5);
    let limits = Limits {
        in_flight_bytes: 300,
        ..TIGHT
    };
    let mut node = leader_with(1, &log, Some(limits));
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 3, hint: 1 },
        epoch: epoch_of(&node, 2),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, reject, &[], &log, &mut recorded), Ok(()));
    assert_eq!(appends_to(&recorded, 2), vec![(1, 1)]);
    assert_eq!(node.in_flight(2), Some((1, 500)));
    // Nothing joins it until it is acknowledged.
    let mut recorded = Recorded::default();
    node.replicate(&log, &mut recorded);
    assert_eq!(appends_to(&recorded, 2), vec![(2, 0)]);
    let accepted = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 2 },
        epoch: epoch_of(&node, 2),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, accepted, &[], &log, &mut recorded), Ok(()));
    assert_eq!(appends_to(&recorded, 2), vec![(2, 1)]);
    assert_eq!(node.in_flight(2), Some((1, 100)));
}

#[test]
fn a_new_leaders_no_op_is_written_past_a_full_queue() {
    let limits = Limits { queue: 2, ..TIGHT };
    let mut log = hundreds(2);
    let node = leader_with(1, &log, Some(limits));
    // `leader_with` checked the no-op's append at index 3.
    log.push(2, 5);
    assert_eq!(
        node.propose(100, &log),
        Err(ProposeError::Backpressure(Backpressure::Queue))
    );
}

/// A log that counts the entry sizes read through it.
struct Counting<'a> {
    log: &'a TestLog,
    reads: std::cell::Cell<u64>,
}

impl LogTerms for Counting<'_> {
    fn last_index(&self) -> u64 {
        self.log.last_index()
    }

    fn term(&self, index: u64) -> Option<u64> {
        self.log.term(index)
    }

    fn size(&self, index: u64) -> Option<u64> {
        self.reads.set(self.reads.get() + 1);
        self.log.size(index)
    }
}

#[test]
fn every_size_read_counts_against_the_duty_budget() {
    let limits = Limits {
        in_flight_entries: 8,
        in_flight_bytes: 350,
        queue: 64,
        reads: 6,
        read_bytes: u64::MAX,
    };
    let mut node = leader_with(1, &hundreds(4), Some(limits));
    // Entries proposed since: both windows are empty, 26 entries to send.
    let log = hundreds(30);
    let counting = Counting {
        log: &log,
        reads: std::cell::Cell::new(0),
    };
    let mut recorded = Recorded::default();
    node.replicate(&counting, &mut recorded);
    // The first follower takes 3 entries (300 bytes) and the read of a
    // fourth that does not fit: 4 reads. Two reads are left for the other.
    assert_eq!(counting.reads.get(), 6);
    assert_eq!(appends_to(&recorded, 2), vec![(4, 3)]);
    assert_eq!(appends_to(&recorded, 3), vec![(4, 2)]);
    // A reply's refill has its own budget, and keeps to it.
    let accepted = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 7 },
        epoch: epoch_of(&node, 2),
    };
    counting.reads.set(0);
    let mut recorded = Recorded::default();
    assert_eq!(
        node.step(2, accepted, &[], &counting, &mut recorded),
        Ok(())
    );
    assert_eq!(counting.reads.get(), 4);
    assert_eq!(appends_to(&recorded, 2), vec![(7, 3)]);
}

#[test]
fn a_duty_sends_at_most_its_log_read_bytes() {
    let limits = Limits {
        in_flight_entries: 8,
        in_flight_bytes: u64::MAX,
        queue: 64,
        reads: 64,
        read_bytes: 600,
    };
    let mut node = leader_with(1, &hundreds(4), Some(limits));
    let log = hundreds(30);
    // 4 entries (400 bytes) to the first, 2 (200 bytes) to the second.
    let mut recorded = Recorded::default();
    node.replicate(&log, &mut recorded);
    assert_eq!(appends_to(&recorded, 2), vec![(4, 4)]);
    assert_eq!(appends_to(&recorded, 3), vec![(4, 2)]);
    // A reply's refill has its own 600 bytes.
    let accepted = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 8 },
        epoch: epoch_of(&node, 2),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, accepted, &[], &log, &mut recorded), Ok(()));
    assert_eq!(appends_to(&recorded, 2), vec![(8, 4)]);
    // An entry larger than a duty's read is refused, not stalled on.
    assert_eq!(
        node.propose(601, &log),
        Err(ProposeError::Backpressure(Backpressure::LogRead))
    );
    assert!(node.propose(600, &log).is_ok());
}
