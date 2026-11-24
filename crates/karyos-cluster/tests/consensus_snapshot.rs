// SPDX-License-Identifier: Apache-2.0

//! Snapshot install through the custom Raft core (quantstratum/karyos#682,
//! over ADR-0105's core): a leader asks for a snapshot when a follower
//! needs entries its log no longer holds, the follower installs it and
//! acknowledges its base, and the cluster keeps Raft's safety with
//! compactions, a partitioned follower left behind compaction, lost and
//! duplicated snapshots and restarts over a snapshot; and the rules one by
//! one.

use std::collections::BTreeMap;

use karyos_cluster::consensus::{
    AppendOutcome, CompactError, Config, ConfigError, Core, Effects, InstallError, LogTerms,
    Message, Role, TermVote,
};

/// A log that may start after a snapshot: index `base + 1 + i` is
/// `terms[i]`, with identity `ids[i]`; entries up to `base` are gone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TestLog {
    base: u64,
    terms: Vec<u64>,
    ids: Vec<u64>,
}

impl TestLog {
    fn at(&self, index: u64) -> Option<usize> {
        let offset = index.checked_sub(self.base)?.checked_sub(1)?;
        usize::try_from(offset).ok()
    }

    fn id(&self, index: u64) -> Option<u64> {
        self.ids.get(self.at(index)?).copied()
    }

    fn push(&mut self, term: u64, id: u64) {
        self.terms.push(term);
        self.ids.push(id);
    }

    /// Drops everything up to `index`.
    fn compact(&mut self, index: u64) {
        let drop = usize::try_from(index.saturating_sub(self.base))
            .unwrap_or(usize::MAX)
            .min(self.terms.len());
        self.terms.drain(..drop);
        self.ids.drain(..drop);
        self.base = self.base.max(index);
    }

    /// Truncates from `index` on.
    fn truncate(&mut self, index: u64) {
        let keep = usize::try_from(index.saturating_sub(self.base).saturating_sub(1))
            .unwrap_or(usize::MAX);
        self.terms.truncate(keep);
        self.ids.truncate(keep);
    }
}

impl LogTerms for TestLog {
    fn last_index(&self) -> u64 {
        self.base + u64::try_from(self.terms.len()).unwrap_or(u64::MAX)
    }

    fn term(&self, index: u64) -> Option<u64> {
        if index == 0 {
            return Some(0);
        }
        self.terms.get(self.at(index)?).copied()
    }

    fn size(&self, index: u64) -> Option<u64> {
        self.id(index).map(|_| 100)
    }
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

#[derive(Debug, Default)]
struct Recorded {
    trace: Vec<Effect>,
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

/// A snapshot: its base and the committed identities up to it (the
/// service state it holds).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Snapshot {
    index: u64,
    term: u64,
    state: Vec<u64>,
}

#[derive(Debug, Clone)]
enum Payload {
    Core {
        message: Message,
        terms: Vec<u64>,
        ids: Vec<u64>,
    },
    Snapshot(Snapshot),
}

struct InFlight {
    from: u64,
    to: u64,
    payload: Payload,
}

struct Node {
    core: Core,
    log: TestLog,
    stored: TermVote,
    snapshot: Snapshot,
    installs: usize,
}

impl Node {
    /// The committed identities: the snapshot's, then the log's up to
    /// the commit index.
    fn committed(&self) -> Vec<u64> {
        let mut state = self.snapshot.state.clone();
        for index in self.snapshot.index + 1..=self.core.commit() {
            state.push(self.log.id(index).unwrap_or(u64::MAX));
        }
        state
    }
}

struct Cluster {
    ids: Vec<u64>,
    nodes: BTreeMap<u64, Node>,
    net: Vec<InFlight>,
    rng: Rng,
    seed: u64,
    leaders: BTreeMap<u64, u64>,
    committed: Vec<u64>,
    next_id: u64,
    /// The node cut off from every other, if any.
    cut: Option<u64>,
    snapshots_asked: usize,
}

fn config(id: u64, ids: &[u64], seed: u64) -> Result<Config, ConfigError> {
    Config::new(id, ids, 10, 20, 3, 4, seed)
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
                        snapshot: Snapshot::default(),
                        installs: 0,
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
            cut: None,
            snapshots_asked: 0,
        }
    }

    /// Applies a call's effects: persists and writes first, then the
    /// messages and snapshots, each carrying what it names.
    fn apply(&mut self, id: u64, recorded: Recorded, incoming: (&[u64], &[u64])) {
        let mut durable = true;
        for effect in &recorded.trace {
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
                assert!(durable, "a persist after a send-after-persist");
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
                    assert!(index > node.snapshot.index, "a write into the snapshot");
                    node.log.truncate(index);
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
                Effect::Snapshot(_) => self.snapshots_asked += 1,
            }
        }
        assert_eq!(node.stored, node.core.term_vote());
        for effect in &recorded.trace {
            let (to, payload) = match *effect {
                Effect::Send(to, message) | Effect::SendAfter(to, message) => {
                    let (mut terms, mut ids) = (Vec::new(), Vec::new());
                    if let Message::Append {
                        prev_index,
                        entries,
                        ..
                    } = message
                    {
                        for index in prev_index + 1..=prev_index + entries {
                            let term = node.log.term(index);
                            let entry = node.log.id(index);
                            assert!(term.is_some() && entry.is_some(), "a gone entry sent");
                            terms.push(term.unwrap_or(0));
                            ids.push(entry.unwrap_or(0));
                        }
                    }
                    (
                        to,
                        Payload::Core {
                            message,
                            terms,
                            ids,
                        },
                    )
                }
                Effect::Snapshot(to) => (to, Payload::Snapshot(node.snapshot.clone())),
                _ => continue,
            };
            self.net.push(InFlight {
                from: id,
                to,
                payload,
            });
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

    /// A node snapshots its committed state and drops its log up to it.
    fn compact(&mut self, id: u64) {
        let Some(node) = self.nodes.get_mut(&id) else {
            return;
        };
        let index = node.core.commit();
        if index <= node.snapshot.index {
            return;
        }
        let Some(term) = node.log.term(index) else {
            return;
        };
        let state = node.committed();
        node.snapshot = Snapshot { index, term, state };
        node.log.compact(index);
        assert_eq!(node.core.compacted(index, term), Ok(()));
        assert_eq!(node.core.snapshot_base(), (index, term));
    }

    /// A follower installs a leader's snapshot as its driver does: the
    /// store first, then the log restarts after the base, then the core.
    fn install(&mut self, from: u64, id: u64, snapshot: Snapshot) {
        let Some(node) = self.nodes.get_mut(&id) else {
            return;
        };
        let leads = node.core.role() == Role::Leader;
        if snapshot.index <= node.core.commit() || leads {
            let mut recorded = Recorded::default();
            let refused = node
                .core
                .install(snapshot.index, snapshot.term, &mut recorded);
            let want = if leads {
                InstallError::Leader
            } else {
                InstallError::Stale
            };
            assert_eq!(refused, Err(want));
            assert!(recorded.trace.is_empty());
            return;
        }
        let _ = from;
        if node.log.term(snapshot.index) == Some(snapshot.term) {
            // It holds the base's entry: the entries after it stay, as
            // the leader may count them (Raft's figure 13, step 6).
            node.log.compact(snapshot.index);
        } else {
            node.log = TestLog {
                base: snapshot.index,
                terms: Vec::new(),
                ids: Vec::new(),
            };
        }
        node.snapshot = snapshot;
        node.installs += 1;
        let mut recorded = Recorded::default();
        let (index, term) = (node.snapshot.index, node.snapshot.term);
        assert_eq!(node.core.install(index, term, &mut recorded), Ok(()));
        assert_eq!(node.core.commit(), index);
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
                if let Ok((index, term)) = node.core.propose(100, &node.log) {
                    assert_eq!(index, node.log.last_index() + 1);
                    node.log.push(term, self.next_id);
                    self.next_id += 1;
                    self.persisted(id);
                }
            }
            40..=42 => self.compact(id),
            43 => {
                // A restart over the stored snapshot, log, term and vote.
                let ids = self.ids.clone();
                let seed = self.seed.wrapping_add(self.rng.next());
                if let (Some(node), Ok(config)) = (self.nodes.get_mut(&id), config(id, &ids, seed))
                {
                    node.core = Core::new(config, node.stored, 0)
                        .with_snapshot(node.snapshot.index, node.snapshot.term);
                    assert_eq!(node.core.commit(), node.snapshot.index);
                }
            }
            _ => self.deliver(),
        }
    }

    fn deliver(&mut self) {
        if self.net.is_empty() {
            return;
        }
        let len = u64::try_from(self.net.len()).unwrap_or(1);
        let at = usize::try_from(self.rng.below(len)).unwrap_or(0);
        let roll = self.rng.below(100);
        let flight = if roll < 5 {
            let Some(kept) = self.net.get(at) else { return };
            InFlight {
                from: kept.from,
                to: kept.to,
                payload: kept.payload.clone(),
            }
        } else {
            self.net.swap_remove(at)
        };
        let cut = self
            .cut
            .is_some_and(|cut| flight.from == cut || flight.to == cut);
        if (5..15).contains(&roll) || cut {
            return;
        }
        match flight.payload {
            Payload::Snapshot(snapshot) => self.install(flight.from, flight.to, snapshot),
            Payload::Core {
                message,
                terms,
                ids,
            } => {
                let Some(node) = self.nodes.get_mut(&flight.to) else {
                    return;
                };
                let mut recorded = Recorded::default();
                let stepped =
                    node.core
                        .step(flight.from, message, &terms, &node.log, &mut recorded);
                assert_eq!(stepped, Ok(()), "{message:?}");
                self.apply(flight.to, recorded, (&terms, &ids));
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
        }
        assert!(
            node.core.commit() <= node.log.last_index(),
            "commit past the log on {id}"
        );
        assert!(node.snapshot.index <= node.core.commit());
        // State machine safety: committed states agree, through
        // snapshots.
        let mine = node.committed();
        let shorter = mine.len().min(self.committed.len());
        assert_eq!(
            mine.get(..shorter),
            self.committed.get(..shorter),
            "committed states differ on {id}"
        );
        if mine.len() > self.committed.len() {
            self.committed = mine;
        }
    }

    /// Delivers, ticks and proposes until every node holds the same
    /// committed state as the longest.
    fn settle(&mut self) -> bool {
        self.cut = None;
        for _ in 0..200_000 {
            let roll = self.rng.below(100);
            if roll < 20 {
                let size = u64::try_from(self.ids.len()).unwrap_or(1);
                let at = usize::try_from(self.rng.below(size)).unwrap_or(0);
                let id = self.ids.get(at).copied().unwrap_or(1);
                if let Some(node) = self.nodes.get_mut(&id) {
                    let mut recorded = Recorded::default();
                    node.core.tick(&node.log, &mut recorded);
                    self.apply(id, recorded, (&[], &[]));
                }
            } else {
                self.deliver();
            }
            let target = self.committed.clone();
            if self.nodes.values().all(|node| node.committed() == target) {
                return true;
            }
        }
        false
    }
}

/// A cluster that runs with one follower cut off while the others
/// compact, then heals.
fn run(size: u64, seed: u64) -> Cluster {
    let mut cluster = Cluster::new(size, seed);
    for step in 0..6_000 {
        if step == 1_000 {
            cluster.cut = Some(size);
        }
        if step == 4_000 {
            cluster.cut = None;
        }
        cluster.event();
    }
    cluster
}

#[test]
fn a_follower_behind_compaction_is_caught_up_by_an_install_and_answers_alike() {
    for size in [3, 5] {
        let mut installs = 0;
        let mut asked = 0;
        for seed in 0..60 {
            let mut cluster = run(size, seed);
            assert!(cluster.settle(), "seed {seed}: the cluster never settled");
            installs += cluster
                .nodes
                .values()
                .map(|node| node.installs)
                .sum::<usize>();
            asked += cluster.snapshots_asked;
            let states: Vec<_> = cluster.nodes.values().map(Node::committed).collect();
            assert!(states.windows(2).all(|pair| pair.first() == pair.get(1)));
        }
        assert!(installs > 20, "{size} nodes installed {installs} snapshots");
        assert!(asked >= installs);
    }
}

fn core(id: u64, term: u64) -> Core {
    let config = Config::new(id, &[1, 2, 3], 10, 20, 3, 4, 1);
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

/// Node 1 elected in term `term + 1` over `log`.
fn leader(term: u64, log: &TestLog) -> Core {
    let mut node = core(1, term);
    let mut round = None;
    for _ in 0..100 {
        let mut recorded = Recorded::default();
        node.tick(log, &mut recorded);
        round = recorded.trace.iter().find_map(|effect| match effect {
            Effect::Send(_, Message::PreVote { round, .. }) => Some(*round),
            _ => None,
        });
        if round.is_some() {
            break;
        }
    }
    let mut recorded = Recorded::default();
    let reply = Message::PreVoteReply {
        term: term + 1,
        granted: true,
        round: round.unwrap_or(0),
    };
    assert_eq!(node.step(2, reply, &[], log, &mut recorded), Ok(()));
    let vote = Message::VoteReply {
        term: term + 1,
        granted: true,
    };
    assert_eq!(node.step(3, vote, &[], log, &mut recorded), Ok(()));
    assert_eq!(node.role(), Role::Leader);
    node
}

/// A leader of term 2 whose log holds entries 6 to 8 after a snapshot at
/// 5 of term 1, with its own no-op at 8 committed.
fn compacted_leader() -> (Core, TestLog) {
    let mut log = TestLog {
        base: 5,
        terms: vec![1, 1],
        ids: vec![6, 7],
    };
    let mut node = leader(1, &log).with_snapshot(5, 1);
    log.push(2, 8);
    let mut recorded = Recorded::default();
    node.persisted(8, &log, &mut recorded);
    let ack = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 8 },
        epoch: node.pipeline_epoch(3).unwrap_or(0),
    };
    assert_eq!(node.step(3, ack, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.commit(), 8);
    assert_eq!(node.compacted(5, 1), Ok(()));
    (node, log)
}

/// Rewinds follower 2 to a point below the log: it answers that it
/// holds only `hint` entries.
fn rewind(node: &mut Core, log: &TestLog, hint: u64) -> Recorded {
    let mut recorded = Recorded::default();
    node.replicate(log, &mut recorded);
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 8, hint },
        epoch: node.pipeline_epoch(2).unwrap_or(0),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, reject, &[], log, &mut recorded), Ok(()));
    recorded
}

/// The leader asked for a snapshot for follower 2, then sent it only a
/// heartbeat at the base.
fn asks_for_a_snapshot(recorded: &Recorded) {
    assert_eq!(recorded.trace.first(), Some(&Effect::Snapshot(2)));
    for effect in recorded.trace.iter().skip(1) {
        assert!(
            matches!(
                effect,
                Effect::Send(
                    2,
                    Message::Append {
                        prev_index: 5,
                        prev_term: 1,
                        entries: 0,
                        ..
                    }
                )
            ),
            "{effect:?}"
        );
    }
}

#[test]
fn a_leader_asks_for_a_snapshot_instead_of_a_gone_entry() {
    let (mut node, log) = compacted_leader();
    asks_for_a_snapshot(&rewind(&mut node, &log, 2));
    // Until acknowledged it sends no entries, only heartbeats at the
    // base, and does not ask again within the election timeout.
    for _ in 0..9 {
        let mut recorded = Recorded::default();
        node.tick(&log, &mut recorded);
        for effect in &recorded.trace {
            match effect {
                Effect::Send(2, message) => assert!(
                    matches!(
                        message,
                        Message::Append {
                            prev_index: 5,
                            prev_term: 1,
                            entries: 0,
                            ..
                        }
                    ),
                    "{message:?}"
                ),
                Effect::Snapshot(to) => assert_eq!(*to, 0, "asked again too early"),
                _ => {}
            }
        }
    }
    // A rejection of the base changes nothing while it waits.
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 5, hint: 2 },
        epoch: node.pipeline_epoch(2).unwrap_or(0),
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, reject, &[], &log, &mut recorded), Ok(()));
    assert!(recorded.trace.is_empty(), "{:?}", recorded.trace);
}

#[test]
fn a_lost_snapshot_is_asked_for_again_after_the_election_timeout() {
    let (mut node, log) = compacted_leader();
    asks_for_a_snapshot(&rewind(&mut node, &log, 2));
    let mut asked = 0;
    for _ in 0..30 {
        let mut recorded = Recorded::default();
        node.tick(&log, &mut recorded);
        // Keep the quorum heard, so it keeps leading.
        let ack = Message::AppendReply {
            term: 2,
            outcome: AppendOutcome::Accepted { index: 8 },
            epoch: node.pipeline_epoch(3).unwrap_or(0),
        };
        let mut ignored = Recorded::default();
        assert_eq!(node.step(3, ack, &[], &log, &mut ignored), Ok(()));
        asked += recorded
            .trace
            .iter()
            .filter(|effect| **effect == Effect::Snapshot(2))
            .count();
    }
    assert!((1..=3).contains(&asked), "asked {asked} times in 30 ticks");
    assert_eq!(node.role(), Role::Leader);
}

#[test]
fn an_acknowledged_base_resumes_appends_after_it() {
    let (mut node, log) = compacted_leader();
    asks_for_a_snapshot(&rewind(&mut node, &log, 2));
    let ack = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 5 },
        epoch: 0,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, ack, &[], &log, &mut recorded), Ok(()));
    let sent = recorded.trace.iter().find_map(|effect| match effect {
        Effect::Send(
            2,
            Message::Append {
                prev_index,
                prev_term,
                entries,
                ..
            },
        ) => Some((*prev_index, *prev_term, *entries)),
        _ => None,
    });
    assert_eq!(sent, Some((5, 1, 3)));
}

#[test]
fn a_follower_installs_commits_the_base_and_acknowledges_it_after_persisting() {
    let mut node = core(2, 2);
    let log = TestLog::default();
    // It follows leader 1 of term 2.
    let heartbeat = Message::Append {
        term: 2,
        prev_index: 0,
        prev_term: 0,
        entries: 0,
        commit: 0,
        epoch: 9,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(1, heartbeat, &[], &log, &mut recorded), Ok(()));
    let log = TestLog {
        base: 5,
        ..TestLog::default()
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.install(5, 1, &mut recorded), Ok(()));
    assert_eq!(node.commit(), 5);
    assert_eq!(node.snapshot_base(), (5, 1));
    assert_eq!(
        recorded.trace,
        vec![Effect::SendAfter(
            1,
            Message::AppendReply {
                term: 2,
                outcome: AppendOutcome::Accepted { index: 5 },
                epoch: 0,
            }
        )]
    );
    // Again, or older: stale, nothing changes.
    let mut recorded = Recorded::default();
    assert_eq!(node.install(5, 1, &mut recorded), Err(InstallError::Stale));
    assert_eq!(node.install(3, 1, &mut recorded), Err(InstallError::Stale));
    assert!(recorded.trace.is_empty());
    // A heartbeat at the base matches through the core's base term.
    let heartbeat = Message::Append {
        term: 2,
        prev_index: 5,
        prev_term: 1,
        entries: 0,
        commit: 5,
        epoch: 9,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(1, heartbeat, &[], &log, &mut recorded), Ok(()));
    assert!(recorded.trace.contains(&Effect::SendAfter(
        1,
        Message::AppendReply {
            term: 2,
            outcome: AppendOutcome::Accepted { index: 5 },
            epoch: 9,
        }
    )));
    // An append below the base is acknowledged up to the base only.
    let below = Message::Append {
        term: 2,
        prev_index: 3,
        prev_term: 1,
        entries: 1,
        commit: 5,
        epoch: 9,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(1, below, &[1], &log, &mut recorded), Ok(()));
    assert_eq!(
        recorded.trace,
        vec![Effect::SendAfter(
            1,
            Message::AppendReply {
                term: 2,
                outcome: AppendOutcome::Accepted { index: 5 },
                epoch: 9,
            }
        )]
    );
}

#[test]
fn a_leader_refuses_an_install_and_compaction_stops_at_the_commit() {
    let (mut node, _) = compacted_leader();
    let mut recorded = Recorded::default();
    assert_eq!(
        node.install(20, 2, &mut recorded),
        Err(InstallError::Leader)
    );
    assert!(recorded.trace.is_empty());
    assert_eq!(node.compacted(9, 2), Err(CompactError::Uncommitted));
    assert_eq!(node.snapshot_base(), (5, 1));
    // An older base is no step back.
    assert_eq!(node.compacted(4, 1), Ok(()));
    assert_eq!(node.snapshot_base(), (5, 1));
}

#[test]
fn a_restart_over_a_snapshot_resumes_from_its_base() {
    let node = core(2, 3).with_snapshot(7, 2);
    assert_eq!(node.commit(), 7);
    assert_eq!(node.snapshot_base(), (7, 2));
}

/// Follower 2 of term `term` following leader `leader`.
fn follower_of(leader: u64, term: u64) -> Core {
    let mut node = core(2, term);
    let heartbeat = Message::Append {
        term,
        prev_index: 0,
        prev_term: 0,
        entries: 0,
        commit: 0,
        epoch: 1,
    };
    let mut recorded = Recorded::default();
    let log = TestLog::default();
    assert_eq!(
        node.step(leader, heartbeat, &[], &log, &mut recorded),
        Ok(())
    );
    assert_eq!(
        node.role(),
        Role::Follower {
            leader: Some(leader)
        }
    );
    node
}

#[test]
fn a_snapshot_of_an_earlier_term_is_installed_and_acknowledged_to_the_current_leader() {
    // Leader 1 of term 4 sent it; the follower now follows leader 3 of
    // term 5. The snapshot holds committed entries only, which leader 3
    // holds too: it is installed, and acknowledged to leader 3 in term 5.
    let mut node = follower_of(3, 5);
    assert_eq!(node.can_install(6), Ok(()));
    let mut recorded = Recorded::default();
    assert_eq!(node.install(6, 4, &mut recorded), Ok(()));
    assert_eq!(
        recorded.trace,
        vec![Effect::SendAfter(
            3,
            Message::AppendReply {
                term: 5,
                outcome: AppendOutcome::Accepted { index: 6 },
                epoch: 0,
            }
        )]
    );
    assert_eq!(node.term_vote().term, 5, "the term is unchanged");
}

#[test]
fn a_deposed_leader_refuses_a_later_terms_snapshot_and_follows_on_the_next_heartbeat() {
    let (mut node, log) = compacted_leader();
    assert_eq!(node.can_install(20), Err(InstallError::Leader));
    let mut recorded = Recorded::default();
    assert_eq!(
        node.install(20, 3, &mut recorded),
        Err(InstallError::Leader)
    );
    assert!(recorded.trace.is_empty());
    // The new leader's heartbeat deposes it; then it takes the snapshot.
    let heartbeat = Message::Append {
        term: 3,
        prev_index: 20,
        prev_term: 3,
        entries: 0,
        commit: 20,
        epoch: 1,
    };
    assert_eq!(node.step(2, heartbeat, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.role(), Role::Follower { leader: Some(2) });
    assert_eq!(node.can_install(20), Ok(()));
    let mut recorded = Recorded::default();
    assert_eq!(node.install(20, 3, &mut recorded), Ok(()));
    assert_eq!(node.commit(), 20);
}

#[test]
fn admission_matches_install_while_a_snapshot_is_staged() {
    // Admitted, then the commit passes the base while it is staged: the
    // driver checks again before publishing, and both refuse alike.
    let mut node = follower_of(1, 2);
    assert_eq!(node.can_install(3), Ok(()));
    let held = TestLog {
        base: 0,
        terms: vec![1, 1, 1, 1],
        ids: vec![1, 2, 3, 4],
    };
    let probe = Message::Append {
        term: 2,
        prev_index: 4,
        prev_term: 1,
        entries: 0,
        commit: 4,
        epoch: 1,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(1, probe, &[], &held, &mut recorded), Ok(()));
    assert_eq!(node.commit(), 4);
    assert_eq!(node.can_install(3), Err(InstallError::Stale));
    let mut recorded = Recorded::default();
    assert_eq!(node.install(3, 1, &mut recorded), Err(InstallError::Stale));
    assert!(recorded.trace.is_empty());
}

#[test]
fn an_acknowledgement_of_the_first_base_counts_after_compaction_moved_on() {
    // The install takes longer than the retry interval while the leader
    // compacts again: the acknowledgement of the first base asked still
    // ends the transfer, and a new one starts for what is gone since.
    let (mut node, mut log) = compacted_leader();
    asks_for_a_snapshot(&rewind(&mut node, &log, 2));
    for _ in 0..10 {
        let mut recorded = Recorded::default();
        node.tick(&log, &mut recorded);
    }
    log.compact(7);
    assert_eq!(node.compacted(7, 1), Ok(()));
    let ack = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 5 },
        epoch: 0,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, ack, &[], &log, &mut recorded), Ok(()));
    assert_eq!(recorded.trace.first(), Some(&Effect::Snapshot(2)));
    // Its heartbeats are at the current base, whose term the core keeps.
    let mut beat = None;
    for _ in 0..3 {
        let mut recorded = Recorded::default();
        node.tick(&log, &mut recorded);
        beat = beat.or(recorded.trace.iter().find_map(|effect| match effect {
            Effect::Send(2, Message::Append { prev_index, .. }) => Some(*prev_index),
            _ => None,
        }));
    }
    assert_eq!(beat, Some(7));
}

/// A log that keeps terms below its entries, and counts size reads.
struct TermsOnly<'a> {
    log: &'a TestLog,
    terms_from: u64,
    reads: std::cell::Cell<u64>,
}

impl LogTerms for TermsOnly<'_> {
    fn last_index(&self) -> u64 {
        self.log.last_index()
    }

    fn term(&self, index: u64) -> Option<u64> {
        if index >= self.terms_from && index <= self.log.base {
            return Some(1);
        }
        self.log.term(index)
    }

    fn size(&self, index: u64) -> Option<u64> {
        self.reads.set(self.reads.get() + 1);
        self.log.size(index)
    }
}

#[test]
fn a_kept_term_without_its_entry_still_asks_for_a_snapshot() {
    let (mut node, log) = compacted_leader();
    let terms = TermsOnly {
        log: &log,
        terms_from: 1,
        reads: std::cell::Cell::new(0),
    };
    let mut recorded = Recorded::default();
    node.replicate(&terms, &mut recorded);
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 8, hint: 2 },
        epoch: node.pipeline_epoch(2).unwrap_or(0),
    };
    let before = terms.reads.get();
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, reject, &[], &terms, &mut recorded), Ok(()));
    asks_for_a_snapshot(&recorded);
    assert_eq!(terms.reads.get() - before, 1, "the one size read decides");
}

#[test]
fn a_blocked_transfer_is_asked_for_once_per_timeout_per_follower() {
    let (mut node, log) = compacted_leader();
    asks_for_a_snapshot(&rewind(&mut node, &log, 2));
    let mut asked = 0;
    for tick in 1..=100 {
        let mut recorded = Recorded::default();
        node.tick(&log, &mut recorded);
        let ack = Message::AppendReply {
            term: 2,
            outcome: AppendOutcome::Accepted { index: 8 },
            epoch: node.pipeline_epoch(3).unwrap_or(0),
        };
        let mut ignored = Recorded::default();
        assert_eq!(node.step(3, ack, &[], &log, &mut ignored), Ok(()));
        asked += recorded
            .trace
            .iter()
            .filter(|effect| matches!(effect, Effect::Snapshot(_)))
            .count();
        assert!(asked <= tick / 10, "{asked} requests by tick {tick}");
        assert!(
            !recorded.trace.contains(&Effect::Snapshot(3)),
            "a follower that holds the log is never sent one"
        );
    }
    assert_eq!(asked, 10);
}

#[test]
fn old_pipeline_replies_around_a_snapshot_neither_rewind_nor_refund() {
    // A leader with a full window to follower 2 at index 9..: the log is
    // compacted past it and the follower rejects, so a snapshot is asked.
    let mut log = TestLog {
        base: 5,
        terms: vec![1, 1],
        ids: vec![6, 7],
    };
    let mut node = leader(1, &log).with_snapshot(5, 1);
    for id in 8..=20 {
        log.push(2, id);
    }
    let mut recorded = Recorded::default();
    node.persisted(20, &log, &mut recorded);
    node.replicate(&log, &mut recorded);
    let old_epoch = node.pipeline_epoch(2).unwrap_or(0);
    let ack3 = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 20 },
        epoch: node.pipeline_epoch(3).unwrap_or(0),
    };
    assert_eq!(node.step(3, ack3, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.commit(), 20);
    log.compact(15);
    assert_eq!(node.compacted(15, 2), Ok(()));
    let reject = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Rejected { probe: 7, hint: 3 },
        epoch: old_epoch,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, reject, &[], &log, &mut recorded), Ok(()));
    asks_snapshot_of(&recorded, 15);
    assert_eq!(node.in_flight(2), Some((0, 0)));
    // Old replies before the acknowledgement change nothing.
    for outcome in [
        AppendOutcome::Accepted { index: 9 },
        AppendOutcome::Rejected { probe: 9, hint: 1 },
    ] {
        let old = Message::AppendReply {
            term: 2,
            outcome,
            epoch: old_epoch,
        };
        let mut recorded = Recorded::default();
        assert_eq!(node.step(2, old, &[], &log, &mut recorded), Ok(()));
        assert!(recorded.trace.is_empty(), "{:?}", recorded.trace);
        assert_eq!(node.in_flight(2), Some((0, 0)));
    }
    // The acknowledgement resumes appends after the base, charged once.
    let ack = Message::AppendReply {
        term: 2,
        outcome: AppendOutcome::Accepted { index: 15 },
        epoch: 0,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(2, ack, &[], &log, &mut recorded), Ok(()));
    assert_eq!(node.in_flight(2), Some((4, 400)));
    // A duplicate of it, and old replies after it, change nothing.
    for (outcome, epoch) in [
        (AppendOutcome::Accepted { index: 15 }, 0),
        (AppendOutcome::Accepted { index: 9 }, old_epoch),
        (AppendOutcome::Rejected { probe: 9, hint: 1 }, old_epoch),
    ] {
        let old = Message::AppendReply {
            term: 2,
            outcome,
            epoch,
        };
        let mut recorded = Recorded::default();
        assert_eq!(node.step(2, old, &[], &log, &mut recorded), Ok(()));
        assert_eq!(node.in_flight(2), Some((4, 400)), "{outcome:?}");
    }
}

/// The call asked for a snapshot for follower 2, then sent it only a
/// heartbeat at `base`.
fn asks_snapshot_of(recorded: &Recorded, base: u64) {
    assert_eq!(recorded.trace.first(), Some(&Effect::Snapshot(2)));
    for effect in recorded.trace.iter().skip(1) {
        assert!(
            matches!(
                effect,
                Effect::Send(
                    2,
                    Message::Append {
                        prev_index,
                        entries: 0,
                        ..
                    }
                ) if *prev_index == base
            ),
            "{effect:?}"
        );
    }
}

#[test]
fn a_node_recovered_over_only_a_snapshot_campaigns_and_leads_from_its_base() {
    let log = TestLog {
        base: 7,
        ..TestLog::default()
    };
    let config = Config::new(1, &[1, 2, 3], 10, 20, 3, 4, 1);
    assert!(config.is_ok());
    let config = config.unwrap_or_else(|_| unreachable!());
    let mut node = Core::new(
        config,
        TermVote {
            term: 3,
            voted_for: None,
        },
        0,
    )
    .with_snapshot(7, 2);
    let mut pre = None;
    for _ in 0..100 {
        let mut recorded = Recorded::default();
        node.tick(&log, &mut recorded);
        pre = pre.or(recorded.trace.iter().find_map(|effect| match effect {
            Effect::Send(_, message @ Message::PreVote { .. }) => Some(*message),
            _ => None,
        }));
        if pre.is_some() {
            break;
        }
    }
    let Some(Message::PreVote {
        last_index,
        last_term,
        round,
        ..
    }) = pre
    else {
        unreachable!("no pre-vote")
    };
    assert_eq!((last_index, last_term), (7, 2));
    let mut recorded = Recorded::default();
    let reply = Message::PreVoteReply {
        term: 4,
        granted: true,
        round,
    };
    assert_eq!(node.step(2, reply, &[], &log, &mut recorded), Ok(()));
    assert!(recorded.trace.iter().any(|effect| matches!(
        effect,
        Effect::SendAfter(
            _,
            Message::Vote {
                last_index: 7,
                last_term: 2,
                ..
            }
        )
    )));
    let vote = Message::VoteReply {
        term: 4,
        granted: true,
    };
    let mut recorded = Recorded::default();
    assert_eq!(node.step(3, vote, &[], &log, &mut recorded), Ok(()));
    assert_eq!(recorded.trace, vec![Effect::Append(8, 4)]);
    // With a kept suffix, the suffix gives the last index and term.
    let kept = TestLog {
        base: 7,
        terms: vec![3],
        ids: vec![8],
    };
    assert_eq!(node.propose(100, &kept), Ok((9, 4)));
}
