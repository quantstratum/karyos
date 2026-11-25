// SPDX-License-Identifier: Apache-2.0

//! The custom Raft core's membership changes (karyos#711): single-server
//! changes with the errata, learners that count toward no quorum, the
//! latest configuration in the log in effect, a truncation restoring the
//! one before, a removed leader stepping down once its removal commits,
//! and a seeded model of changes under loss, reordering and restarts
//! checking Raft's safety and that every commit is held by a majority of
//! the voters the leader acted under.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::{BTreeMap, BTreeSet};

use karyos_cluster::consensus::{
    ChangeError, Config, Core, Effects, LogTerms, Message, Role, StepError, TermVote,
};
use karyos_cluster::membership::{Membership, MembershipChange};

/// A node's log: each entry's term and, for a configuration entry, its
/// membership.
#[derive(Debug, Clone, Default)]
struct Log {
    entries: Vec<(u64, Option<Membership>)>,
}

impl LogTerms for Log {
    fn last_index(&self) -> u64 {
        self.entries.len() as u64
    }

    fn term(&self, index: u64) -> Option<u64> {
        if index == 0 {
            return Some(0);
        }
        self.entries
            .get(usize::try_from(index - 1).ok()?)
            .map(|(term, _)| *term)
    }

    fn size(&self, index: u64) -> Option<u64> {
        self.term(index).filter(|_| index > 0).map(|_| 10)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Persist(TermVote),
    Write(u64, u64),
    Append(u64, u64),
    Send(u64, Message),
    Commit(u64),
}

#[derive(Debug, Default)]
struct Recorded(Vec<Effect>);

impl Effects for Recorded {
    fn persist(&mut self, term_vote: TermVote) {
        self.0.push(Effect::Persist(term_vote));
    }
    fn write(&mut self, index: u64, skip: u64) {
        self.0.push(Effect::Write(index, skip));
    }
    fn append(&mut self, index: u64, term: u64) {
        self.0.push(Effect::Append(index, term));
    }
    fn send(&mut self, to: u64, message: Message) {
        self.0.push(Effect::Send(to, message));
    }
    fn send_after_persist(&mut self, to: u64, message: Message) {
        self.0.push(Effect::Send(to, message));
    }
    fn commit(&mut self, index: u64) {
        self.0.push(Effect::Commit(index));
    }
    fn send_snapshot(&mut self, _: u64) {
        panic!("a snapshot asked without compaction");
    }
}

/// A message in flight with the entries an append carries.
#[derive(Debug, Clone)]
struct Flight {
    from: u64,
    to: u64,
    message: Message,
    entries: Vec<(u64, Option<Membership>)>,
}

struct Node {
    core: Core,
    log: Log,
    stored: TermVote,
}

/// The promotion lag every test uses.
const LAG: u64 = 2;

fn config(id: u64, seed: u64) -> Config {
    Config::joining(id, &[1, 2, 3], 10, 20, 3, 4, seed).unwrap()
}

struct Cluster {
    nodes: BTreeMap<u64, Node>,
    net: Vec<Flight>,
    /// Links that drop everything, both ways.
    cut: BTreeSet<(u64, u64)>,
    seed: u64,
}

impl Cluster {
    /// Voters 1 to 3, and spares from 4 to `last`, joining.
    fn new(last: u64, seed: u64) -> Self {
        let nodes = (1..=last)
            .map(|id| {
                let node = Node {
                    core: Core::new(config(id, seed), TermVote::default(), 0),
                    log: Log::default(),
                    stored: TermVote::default(),
                };
                (id, node)
            })
            .collect();
        Self {
            nodes,
            net: Vec::new(),
            cut: BTreeSet::new(),
            seed,
        }
    }

    fn node(&mut self, id: u64) -> &mut Node {
        self.nodes.get_mut(&id).unwrap()
    }

    /// A driver applying `recorded` for `id`; `incoming` are a stepped
    /// append's entries.
    fn apply(&mut self, id: u64, recorded: Recorded, incoming: &[(u64, Option<Membership>)]) {
        let mut appended = false;
        let mut sends = Vec::new();
        {
            let node = self.nodes.get_mut(&id).unwrap();
            for effect in recorded.0 {
                match effect {
                    Effect::Persist(term_vote) => node.stored = term_vote,
                    Effect::Write(index, skip) => {
                        node.log
                            .entries
                            .truncate(usize::try_from(index - 1).unwrap());
                        let first = node.log.entries.len() as u64 + 1;
                        for (at, entry) in incoming
                            .iter()
                            .skip(usize::try_from(skip).unwrap())
                            .enumerate()
                        {
                            node.log.entries.push(*entry);
                            if let Some(membership) = entry.1 {
                                let index = first + at as u64;
                                node.core.configured(index, membership, &node.log);
                            }
                        }
                    }
                    Effect::Append(index, term) => {
                        assert_eq!(index, node.log.last_index() + 1);
                        node.log.entries.push((term, None));
                        appended = true;
                    }
                    Effect::Send(to, message) => sends.push((to, message)),
                    Effect::Commit(_) => {}
                }
            }
            for (to, message) in sends {
                let entries = match message {
                    Message::Append {
                        prev_index,
                        entries,
                        ..
                    } => node
                        .log
                        .entries
                        .iter()
                        .skip(usize::try_from(prev_index).unwrap())
                        .take(usize::try_from(entries).unwrap())
                        .copied()
                        .collect(),
                    _ => Vec::new(),
                };
                self.net.push(Flight {
                    from: id,
                    to,
                    message,
                    entries,
                });
            }
        }
        if appended {
            self.persisted(id);
        }
    }

    fn persisted(&mut self, id: u64) {
        let node = self.node(id);
        let mut recorded = Recorded::default();
        node.core
            .persisted(node.log.last_index(), &node.log, &mut recorded);
        node.core.replicate(&node.log, &mut recorded);
        self.apply(id, recorded, &[]);
    }

    fn tick(&mut self, id: u64) {
        let node = self.node(id);
        let mut recorded = Recorded::default();
        node.core.tick(&node.log, &mut recorded);
        self.apply(id, recorded, &[]);
    }

    fn deliver(&mut self, flight: Flight) -> Result<(), StepError> {
        if self.cut.contains(&(flight.from, flight.to)) || !self.nodes.contains_key(&flight.to) {
            return Ok(());
        }
        let terms: Vec<u64> = flight.entries.iter().map(|(term, _)| *term).collect();
        let node = self.node(flight.to);
        let mut recorded = Recorded::default();
        node.core.step(
            flight.from,
            flight.message,
            &terms,
            &node.log,
            &mut recorded,
        )?;
        self.apply(flight.to, recorded, &flight.entries);
        Ok(())
    }

    /// Delivers everything in flight, in order, until nothing is.
    fn settle(&mut self) {
        for _ in 0..10_000 {
            if self.net.is_empty() {
                return;
            }
            let flight = self.net.remove(0);
            // A member removed, or not yet known, refuses a stranger.
            let _ = self.deliver(flight);
        }
        panic!("the network never settles");
    }

    /// Ticks every node and settles, `rounds` times.
    fn run(&mut self, rounds: u32) {
        let ids: Vec<u64> = self.nodes.keys().copied().collect();
        for _ in 0..rounds {
            for &id in &ids {
                self.tick(id);
            }
            self.settle();
        }
    }

    fn leader(&self) -> Option<u64> {
        self.nodes
            .iter()
            .filter(|(_, node)| node.core.role() == Role::Leader)
            .map(|(id, node)| (node.core.term_vote().term, *id))
            .max()
            .map(|(_, id)| id)
    }

    fn propose(&mut self, id: u64) {
        let node = self.node(id);
        let (index, term) = node.core.propose(10, &node.log).unwrap();
        assert_eq!(index, node.log.last_index() + 1);
        node.log.entries.push((term, None));
        self.persisted(id);
    }

    fn change(&mut self, id: u64, change: MembershipChange) -> Result<Membership, ChangeError> {
        let node = self.node(id);
        let mut recorded = Recorded::default();
        let (index, term, membership) =
            node.core
                .propose_change(change, 10, LAG, &node.log, &mut recorded)?;
        assert_eq!(index, node.log.last_index() + 1);
        node.log.entries.push((term, Some(membership)));
        self.apply(id, recorded, &[]);
        self.persisted(id);
        Ok(membership)
    }

    /// A restart of `id`: its log and term and vote are durable; its
    /// configuration comes back from the log's entries, replayed.
    fn restart(&mut self, id: u64) {
        let seed = self.seed ^ id;
        let node = self.node(id);
        node.core = Core::new(config(id, seed), node.stored, 0);
        for (at, (_, membership)) in node.log.entries.clone().iter().enumerate() {
            if let Some(membership) = membership {
                node.core.configured(at as u64 + 1, *membership, &node.log);
            }
        }
    }
}

fn three_and(spare: u64) -> Membership {
    Membership::new(&[1, 2, 3], &[spare]).unwrap()
}

/// A cluster of voters 1 to 3 and spares to `last`, with a leader that has
/// committed an entry of its term.
fn led(last: u64, seed: u64) -> (Cluster, u64) {
    let mut cluster = Cluster::new(last, seed);
    // The spares stay quiet until added: they are no member of anyone.
    for _ in 0..200 {
        cluster.run(1);
        if let Some(leader) = cluster.leader() {
            cluster.run(2);
            return (cluster, leader);
        }
    }
    panic!("no leader");
}

#[test]
fn a_learner_never_counts_toward_a_commit() {
    let (mut cluster, leader) = led(4, 1);
    cluster
        .change(leader, MembershipChange::AddLearner(4))
        .unwrap();
    cluster.run(3);
    assert_eq!(cluster.node(4).core.membership(), three_and(4));
    assert_eq!(
        cluster.node(4).core.role(),
        Role::Follower {
            leader: Some(leader)
        }
    );
    // The leader and the learner cut off from the other two voters: an
    // entry both hold does not commit.
    let others: Vec<u64> = [1, 2, 3].into_iter().filter(|&id| id != leader).collect();
    for &other in &others {
        for end in [leader, 4] {
            cluster.cut.insert((end, other));
            cluster.cut.insert((other, end));
        }
    }
    let before = cluster.node(leader).core.commit();
    cluster.propose(leader);
    for _ in 0..3 {
        cluster.tick(leader);
        cluster.settle();
    }
    let last = cluster.node(leader).log.last_index();
    assert_eq!(
        cluster.node(4).log.last_index(),
        last,
        "the learner holds it"
    );
    assert_eq!(
        cluster.node(leader).core.commit(),
        before,
        "a learner counted"
    );
    // Healed, the voters commit it.
    cluster.cut.clear();
    cluster.run(3);
    assert!(cluster.node(leader).core.commit() >= last);
}

#[test]
fn a_promotion_waits_for_the_learner_to_catch_up() {
    let (mut cluster, leader) = led(4, 2);
    cluster
        .change(leader, MembershipChange::AddLearner(4))
        .unwrap();
    cluster.run(3);
    // Cut off, the learner falls behind the commit.
    cluster.cut.insert((leader, 4));
    for _ in 0..LAG + 3 {
        cluster.propose(leader);
        cluster.run(1);
    }
    match cluster.change(leader, MembershipChange::Promote(4)) {
        Err(ChangeError::Lagging { behind }) => assert!(behind > LAG, "{behind}"),
        other => panic!("{other:?}"),
    }
    cluster.cut.clear();
    cluster.run(4);
    let four = Membership::new(&[1, 2, 3, 4], &[]).unwrap();
    assert_eq!(
        cluster.change(leader, MembershipChange::Promote(4)),
        Ok(four)
    );
    cluster.run(4);
    for id in 1..=4 {
        assert_eq!(cluster.node(id).core.membership(), four, "node {id}");
    }
    // A majority of four is three: the leader and one voter no longer
    // commit.
    let lone = [1, 2, 3, 4].into_iter().find(|&id| id != leader).unwrap();
    for id in [1, 2, 3, 4] {
        if id != leader && id != lone {
            cluster.cut.insert((leader, id));
            cluster.cut.insert((id, leader));
        }
    }
    let before = cluster.node(leader).core.commit();
    cluster.propose(leader);
    cluster.tick(leader);
    cluster.settle();
    assert_eq!(cluster.node(leader).core.commit(), before);
}

#[test]
fn early_overlapping_and_invalid_changes_are_refused() {
    let mut cluster = Cluster::new(5, 3);
    let leader = loop {
        cluster.run(1);
        if let Some(leader) = cluster.leader() {
            break leader;
        }
    };
    // Its no-op is not committed yet: the errata refuse a change.
    let node = cluster.node(leader);
    if node.core.commit() < node.log.last_index() {
        assert_eq!(
            cluster.change(leader, MembershipChange::AddLearner(4)),
            Err(ChangeError::InProgress)
        );
    }
    cluster.run(2);
    // One change at a time: the first uncommitted refuses the second.
    let others: Vec<u64> = [1, 2, 3].into_iter().filter(|&id| id != leader).collect();
    for &other in &others {
        cluster.cut.insert((leader, other));
    }
    cluster
        .change(leader, MembershipChange::AddLearner(4))
        .unwrap();
    assert_eq!(
        cluster.change(leader, MembershipChange::AddLearner(5)),
        Err(ChangeError::InProgress)
    );
    cluster.cut.clear();
    cluster.run(3);
    assert_eq!(
        cluster.change(leader, MembershipChange::AddLearner(4)),
        Err(ChangeError::Invalid)
    );
    assert_eq!(
        cluster.change(leader, MembershipChange::Promote(others[0])),
        Err(ChangeError::Invalid)
    );
    assert_eq!(
        cluster.change(leader, MembershipChange::Remove(9)),
        Err(ChangeError::Invalid)
    );
    let follower = others[0];
    let node = cluster.node(follower);
    let mut recorded = Recorded::default();
    assert!(matches!(
        node.core.propose_change(
            MembershipChange::AddLearner(5),
            10,
            LAG,
            &node.log,
            &mut recorded
        ),
        Err(ChangeError::NotLeader(_))
    ));
}

#[test]
fn a_learner_never_stands_for_election() {
    let (mut cluster, leader) = led(4, 4);
    cluster
        .change(leader, MembershipChange::AddLearner(4))
        .unwrap();
    cluster.run(3);
    // Everyone else gone: the learner's timeout passes, and it asks for
    // nothing.
    for id in [1, 2, 3] {
        cluster.cut.insert((4, id));
        cluster.cut.insert((id, 4));
    }
    for _ in 0..100 {
        cluster.tick(4);
        assert!(
            cluster.net.iter().all(|flight| flight.from != 4),
            "it campaigned"
        );
        cluster.net.clear();
    }
    assert_eq!(
        cluster.node(4).core.term_vote().term,
        cluster.node(leader).core.term_vote().term
    );
}

#[test]
fn a_truncated_configuration_entry_gives_way_to_the_one_before() {
    let (mut cluster, leader) = led(4, 5);
    let others: Vec<u64> = [1, 2, 3].into_iter().filter(|&id| id != leader).collect();
    // The leader appends a change no other voter receives.
    for &other in &others {
        cluster.cut.insert((leader, other));
        cluster.cut.insert((other, leader));
    }
    cluster
        .change(leader, MembershipChange::AddLearner(4))
        .unwrap();
    assert_eq!(cluster.node(leader).core.membership(), three_and(4));
    let index = cluster.node(leader).log.last_index();
    assert_eq!(cluster.node(leader).core.configuration_index(), Some(index));
    // The others elect a leader and overwrite it.
    let mut new = None;
    for _ in 0..200 {
        for &other in &others {
            cluster.tick(other);
        }
        cluster.settle();
        new = others
            .iter()
            .copied()
            .find(|&id| cluster.node(id).core.role() == Role::Leader);
        if new.is_some() {
            break;
        }
    }
    let new = new.unwrap();
    cluster.run(1);
    cluster.propose(new);
    cluster.run(1);
    cluster.cut.clear();
    cluster.run(4);
    let three = Membership::new(&[1, 2, 3], &[]).unwrap();
    assert_eq!(cluster.node(leader).core.membership(), three);
    assert_eq!(cluster.node(leader).core.configuration_index(), None);
    assert_eq!(
        cluster.node(leader).core.role(),
        Role::Follower { leader: Some(new) }
    );
}

/// Voters 1 to 4: spare 4 added and promoted under `leader`.
fn four_voters(cluster: &mut Cluster, leader: u64) {
    cluster
        .change(leader, MembershipChange::AddLearner(4))
        .unwrap();
    cluster.run(4);
    cluster
        .change(leader, MembershipChange::Promote(4))
        .unwrap();
    cluster.run(4);
}

#[test]
fn a_removed_leader_steps_down_once_its_removal_commits() {
    let (mut cluster, leader) = led(4, 6);
    four_voters(&mut cluster, leader);
    let three: Vec<u64> = [1, 2, 3, 4]
        .into_iter()
        .filter(|&id| id != leader)
        .collect();
    let after = Membership::new(&three, &[]).unwrap();
    assert_eq!(
        cluster.change(leader, MembershipChange::Remove(leader)),
        Ok(after)
    );
    // Until it commits, it still leads, and replicates.
    assert_eq!(cluster.node(leader).core.role(), Role::Leader);
    cluster.settle();
    cluster.tick(leader);
    cluster.settle();
    let index = cluster.node(leader).core.configuration_index().unwrap();
    assert!(cluster.node(leader).core.commit() >= index);
    assert_ne!(cluster.node(leader).core.role(), Role::Leader);
    // The other three elect a leader of their own and go on.
    cluster.run(200);
    let new = cluster.leader().unwrap();
    assert!(three.contains(&new));
    cluster.propose(new);
    cluster.run(3);
    assert_eq!(
        cluster.node(new).core.commit(),
        cluster.node(new).log.last_index()
    );
    // The removed node never stands again.
    assert_ne!(cluster.node(leader).core.role(), Role::Leader);
}

/// The cluster moves entirely off its bootstrap voters 1 to 3, onto 4 to 6,
/// one server at a time; then spare 7 joins. It was started with the
/// bootstrap voters, none of which leads or is a member any more, and still
/// follows the leader and catches up.
#[test]
fn a_joiner_follows_a_leader_outside_its_bootstrap_voters() {
    let (mut cluster, leader) = led(7, 10);
    let step = |cluster: &mut Cluster, leader: u64, change| {
        cluster.change(leader, change).unwrap();
        cluster.run(6);
    };
    for spare in [4, 5] {
        step(&mut cluster, leader, MembershipChange::AddLearner(spare));
        step(&mut cluster, leader, MembershipChange::Promote(spare));
    }
    for gone in [1, 2, 3].into_iter().filter(|&id| id != leader) {
        step(&mut cluster, leader, MembershipChange::Remove(gone));
    }
    step(&mut cluster, leader, MembershipChange::AddLearner(6));
    step(&mut cluster, leader, MembershipChange::Promote(6));
    step(&mut cluster, leader, MembershipChange::Remove(leader));
    cluster.run(300);
    let new = cluster.leader().unwrap();
    assert!([4, 5, 6].contains(&new), "{new}");
    let four_to_six = Membership::new(&[4, 5, 6], &[]).unwrap();
    assert_eq!(cluster.node(new).core.membership(), four_to_six);
    step(&mut cluster, new, MembershipChange::AddLearner(7));
    cluster.propose(new);
    cluster.run(6);
    assert_eq!(
        cluster.node(7).core.membership(),
        Membership::new(&[4, 5, 6], &[7]).unwrap()
    );
    assert_eq!(
        cluster.node(7).log.last_index(),
        cluster.node(new).log.last_index(),
        "the joiner caught up"
    );
}

#[test]
fn a_restart_acts_under_the_latest_configuration_its_log_holds() {
    let (mut cluster, leader) = led(4, 7);
    cluster
        .change(leader, MembershipChange::AddLearner(4))
        .unwrap();
    cluster.run(3);
    for id in 1..=4 {
        cluster.restart(id);
        assert_eq!(
            cluster.node(id).core.membership(),
            three_and(4),
            "node {id}"
        );
    }
    cluster.run(200);
    let leader = cluster.leader().unwrap();
    assert_eq!(
        cluster.change(leader, MembershipChange::Promote(4)),
        Ok(Membership::new(&[1, 2, 3, 4], &[]).unwrap())
    );
}

#[test]
fn a_snapshot_restores_the_membership_at_its_base() {
    let (mut cluster, leader) = led(4, 8);
    let start = cluster.node(leader).log.last_index();
    cluster
        .change(leader, MembershipChange::AddLearner(4))
        .unwrap();
    let at = cluster.node(leader).log.last_index();
    let core = &cluster.node(leader).core;
    assert_eq!(
        core.membership_at(start),
        Some(Membership::new(&[1, 2, 3], &[]).unwrap())
    );
    assert_eq!(core.membership_at(at), Some(three_and(4)));
    // A node that knows none of it, restored over a snapshot at `at`.
    let mut fresh = Core::new(config(4, 9), TermVote::default(), 0).with_snapshot(at, 1);
    fresh.restore_membership(at, three_and(4));
    assert_eq!(fresh.membership(), three_and(4));
    assert_eq!(fresh.configuration_index(), None);
    // Below the snapshot it cannot say.
    assert_eq!(fresh.membership_at(at - 1), None);
    assert_eq!(fresh.membership_at(at), Some(three_and(4)));
}

/// Raft's safety under membership changes, losses, reordering and
/// restarts, over many seeds: one leader per term, committed prefixes
/// agree, and every entry a leader commits is held by a majority of the
/// voters it acts under.
#[test]
fn membership_changes_keep_raft_safety() {
    let mut made = [0u32; 3];
    for seed in 0..40u64 {
        let mut cluster = Cluster::new(5, seed);
        let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut draw = |n: u64| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % n
        };
        let mut leaders: BTreeMap<u64, u64> = BTreeMap::new();
        let mut committed: Vec<(u64, Option<Membership>)> = Vec::new();
        let mut seen: BTreeMap<u64, u64> = BTreeMap::new();
        for _ in 0..3_000 {
            let id = 1 + draw(5);
            match draw(100) {
                0..=29 => cluster.tick(id),
                30..=37 => {
                    if cluster.node(id).core.role() == Role::Leader {
                        let node = cluster.node(id);
                        if node.core.propose(10, &node.log).is_ok() {
                            cluster.propose(id);
                        }
                    }
                }
                38..=41 => {
                    if cluster.node(id).core.role() == Role::Leader {
                        let target = 1 + draw(5);
                        let change = match draw(3) {
                            0 => MembershipChange::AddLearner(target),
                            1 => MembershipChange::Promote(target),
                            _ => MembershipChange::Remove(target),
                        };
                        if cluster.change(id, change).is_ok() {
                            made[match change {
                                MembershipChange::AddLearner(_) => 0,
                                MembershipChange::Promote(_) => 1,
                                MembershipChange::Remove(_) => 2,
                            }] += 1;
                        }
                    }
                }
                42 => cluster.restart(id),
                _ => {
                    if !cluster.net.is_empty() {
                        let at = usize::try_from(draw(cluster.net.len() as u64)).unwrap();
                        let flight = cluster.net.swap_remove(at);
                        if draw(10) > 0 {
                            let _ = cluster.deliver(flight);
                        }
                    }
                }
            }
            for (&id, node) in &cluster.nodes {
                let term = node.core.term_vote().term;
                let commit = node.core.commit();
                let moved = seen.insert(id, commit).is_none_or(|before| commit > before);
                if node.core.role() == Role::Leader {
                    assert_eq!(*leaders.entry(term).or_insert(id), id, "seed {seed}");
                }
                if node.core.role() == Role::Leader && moved {
                    // A commit it just made is held by a majority of the
                    // voters it acts under.
                    let members = node.core.membership();
                    let holding = members
                        .voters()
                        .filter(|voter| {
                            cluster.nodes.get(voter).is_some_and(|other| {
                                other.log.term(commit) == node.log.term(commit)
                            })
                        })
                        .count();
                    assert!(
                        commit == 0 || holding >= members.quorum(),
                        "seed {seed}: {commit} held by {holding} of {members:?}"
                    );
                }
                let commit = usize::try_from(commit).unwrap();
                let mine = node.log.entries.get(..commit).unwrap_or(&[]);
                let shorter = mine.len().min(committed.len());
                assert_eq!(mine.get(..shorter), committed.get(..shorter), "seed {seed}");
                if mine.len() > committed.len() {
                    committed = mine.to_vec();
                }
            }
        }
    }
    // Every kind of change was made, many times over.
    assert!(made.iter().all(|&count| count >= 10), "{made:?}");
}
