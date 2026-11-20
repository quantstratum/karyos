// SPDX-License-Identifier: Apache-2.0

//! The `ClusteredService` delivery path (C10, karyos#686) on the
//! harness's reference core, on 3 and 5 servers:
//!
//! - a client registers, and its requests reach the log through the
//!   service container and their outcomes return to it;
//! - every replica applies the same entries to the same state, sessions
//!   and outcomes;
//! - a request sent twice is applied once, the second copy answered from
//!   the session table;
//! - a restarted server rebuilds its container from the log.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use karyos_archive::segment::Geometry;
use karyos_cluster::DedupConfig;
use karyos_cluster::service::ContainerConfig;
use karyos_sim::cluster::ClusterSim;
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::harness::delivery::{
    Answer, AppendService, Delivery, DeliveryClient, DeliveryMember, DeliveryServer,
};
use karyos_sim::harness::reference::{LEADER, Message, Reference};
use karyos_sim::net::{LinkConfig, NodeId};
use karyos_sim::scenarios;

type Member = DeliveryMember<Reference, AppendService>;
type Sim = ClusterSim<Member, Delivery<Message>>;

fn config() -> ContainerConfig {
    ContainerConfig::default().with_dedup(
        DedupConfig::default()
            .with_sessions(8)
            .with_window(8)
            .with_response_bytes(16),
    )
}

/// `servers` servers, then `clients`, each sending to the leader.
fn cluster(seed: u64, servers: u32, clients: Vec<Vec<Vec<u8>>>, twice: bool) -> (Sim, Vec<NodeId>) {
    let mut sim = Sim::new("delivery", seed, LinkConfig::default()).unwrap();
    for id in 0..servers {
        let server = DeliveryServer::new(
            id,
            (0..servers).collect(),
            SimDisk::new(),
            Survives::Synced,
            Geometry::new(4096, 4096).unwrap(),
            AppendService::default(),
            config(),
        )
        .unwrap();
        assert_eq!(
            sim.add_node(Member::Server(Box::new(server)), 0, 0)
                .unwrap(),
            id
        );
    }
    let ids = clients
        .into_iter()
        .zip(servers..)
        .map(|(commands, id)| {
            let client = DeliveryClient::new(id, LEADER, commands);
            let client = if twice { client.twice() } else { client };
            assert_eq!(sim.add_node(Member::Client(client), 0, 0).unwrap(), id);
            id
        })
        .collect();
    (sim, ids)
}

fn values(values: &[u64]) -> Vec<Vec<u8>> {
    values
        .iter()
        .map(|value| value.to_le_bytes().to_vec())
        .collect()
}

fn count(count: u64) -> Answer {
    Answer::Applied(count.to_le_bytes().to_vec())
}

fn server(sim: &Sim, id: NodeId) -> &DeliveryServer<Reference, AppendService> {
    sim.node(id).and_then(Member::server).unwrap()
}

fn client(sim: &Sim, id: NodeId) -> &DeliveryClient {
    sim.node(id).and_then(Member::client).unwrap()
}

/// Every server applied the same entries to the same state and sessions,
/// with the same outcomes.
fn replicas_agree(sim: &Sim, servers: u32) {
    let first = server(sim, 0);
    for id in 1..servers {
        let other = server(sim, id);
        assert_eq!(
            other.container().applied(),
            first.container().applied(),
            "{id}"
        );
        assert_eq!(
            other.container().service(),
            first.container().service(),
            "{id}"
        );
        assert_eq!(
            other.container().sessions().encode(),
            first.container().sessions().encode(),
            "{id}"
        );
        assert_eq!(other.outcomes(), first.outcomes(), "{id}");
    }
}

#[test]
fn test_delivery_a_request_reaches_the_log_and_its_outcome_returns_on_3_and_5_servers() {
    for servers in [3, 5] {
        for seed in scenarios::seeds() {
            let (mut sim, clients) = cluster(
                seed,
                servers,
                vec![values(&[10, 20, 30]), values(&[40])],
                false,
            );
            sim.run_for(600).unwrap();
            for &id in &clients {
                assert!(client(&sim, id).done(), "{servers} servers, seed {seed}");
                assert!(client(&sim, id).epoch().is_some());
            }
            // Each answer is the count after its command, in the order
            // the log applied them.
            let answers: Vec<_> = clients
                .iter()
                .flat_map(|&id| client(&sim, id).answers().to_vec())
                .collect();
            assert_eq!(answers.len(), 4);
            for (_, answer) in &answers {
                assert!(matches!(answer, Answer::Applied(_)), "{answer:?}");
            }
            let mut counts: Vec<_> = answers.into_iter().map(|(_, answer)| answer).collect();
            counts.sort_by_key(|answer| format!("{answer:?}"));
            let mut wanted: Vec<_> = (1..=4).map(count).collect();
            wanted.sort_by_key(|answer| format!("{answer:?}"));
            assert_eq!(counts, wanted, "{servers} servers, seed {seed}");
            let mut applied = server(&sim, LEADER).container().service().values.clone();
            applied.sort_unstable();
            assert_eq!(applied, [10, 20, 30, 40]);
            replicas_agree(&sim, servers);
        }
    }
}

/// karyos#686, condition 1, through the harness: the same seed gives the
/// same run, and every replica of it the same state and outcomes.
#[test]
fn test_delivery_every_replica_gives_the_same_state_and_outcomes() {
    for servers in [3, 5] {
        let run = || {
            let (mut sim, _) = cluster(3, servers, vec![values(&[1, 2]), values(&[3, 4])], false);
            sim.run_for(600).unwrap();
            replicas_agree(&sim, servers);
            let leader = server(&sim, LEADER);
            (
                leader.container().service().clone(),
                leader.container().sessions().encode(),
                leader.outcomes().to_vec(),
            )
        };
        assert_eq!(run(), run(), "{servers} servers");
    }
}

/// karyos#927: the leader writes the session bounds into the log, and
/// every replica applies them as an entry, so a restarted one reads them
/// from the log.
#[test]
fn test_delivery_the_session_bounds_are_a_log_entry_on_every_replica() {
    for servers in [3, 5] {
        for seed in scenarios::seeds() {
            let (mut sim, _) = cluster(seed, servers, vec![values(&[10])], false);
            sim.run_for(600).unwrap();
            for id in 0..servers {
                let server = server(&sim, id);
                assert!(
                    server.container().bounds_logged(),
                    "server {id}, seed {seed}"
                );
                assert!(
                    server.kinds().iter().any(|(_, kind)| *kind == "bounds"),
                    "server {id}, seed {seed}: {:?}",
                    server.kinds()
                );
                assert_eq!(server.container().sessions().config(), config().dedup);
            }
            replicas_agree(&sim, servers);
        }
    }
}

#[test]
fn test_delivery_a_request_sent_twice_is_applied_once() {
    for servers in [3, 5] {
        let (mut sim, clients) = cluster(5, servers, vec![values(&[7, 8, 9])], true);
        sim.run_for(800).unwrap();
        let id = clients[0];
        assert!(client(&sim, id).done());
        assert_eq!(
            client(&sim, id).answers(),
            [(0, count(1)), (1, count(2)), (2, count(3))]
        );
        let leader = server(&sim, LEADER);
        assert_eq!(leader.container().service().values, [7, 8, 9]);
        // Each second copy was logged and answered from the session
        // table, the command not run again.
        let retained = leader
            .outcomes()
            .iter()
            .filter(|(_, outcome)| matches!(outcome, Some(Answer::Retained(_))))
            .count();
        assert_eq!(retained, 3, "{servers} servers");
        replicas_agree(&sim, servers);
    }
}

#[test]
fn test_delivery_a_restarted_server_rebuilds_its_container_from_the_log() {
    let (mut sim, clients) = cluster(9, 3, vec![values(&[5, 6, 7])], false);
    sim.run_for(600).unwrap();
    assert!(client(&sim, clients[0]).done());
    let before = server(&sim, 2).container().service().clone();
    sim.crash(2).unwrap();
    sim.run_for(40).unwrap();
    sim.restart(2).unwrap();
    sim.run_for(400).unwrap();
    assert!(server(&sim, 2).is_up());
    assert_eq!(server(&sim, 2).container().service(), &before);
    replicas_agree(&sim, 3);
}

// Forwarding and unknown outcomes (karyos#686, part 3). The reference core
// never changes leader, so a loss of leadership is played by `Deposable`:
// the reference core, whose node can be told it no longer leads, in a
// later term, while the core underneath goes on replicating. A request it
// took may then still commit, which is the case an unknown outcome is for.

mod deposable {
    use std::cell::Cell;

    use karyos_sim::harness::core::{ConsensusCore, LogView, NotLeader, Persisted, Ready, Refused};
    use karyos_sim::harness::reference::{Message, Reference};
    use karyos_sim::net::NodeId;

    thread_local! {
        static DEPOSED: Cell<Option<NodeId>> = const { Cell::new(None) };
        static TERMS: Cell<u64> = const { Cell::new(0) };
    }

    /// `node` stops leading, until [`restore`].
    pub fn depose(node: NodeId) {
        DEPOSED.with(|deposed| deposed.set(Some(node)));
        TERMS.with(|terms| terms.set(terms.get() + 1));
    }

    /// The deposed node leads again, in a later term.
    pub fn restore() {
        DEPOSED.with(|deposed| deposed.set(None));
        TERMS.with(|terms| terms.set(terms.get() + 1));
    }

    fn deposed(node: NodeId) -> bool {
        DEPOSED.with(Cell::get) == Some(node)
    }

    /// The reference core, deposable.
    pub struct Deposable {
        id: NodeId,
        inner: Reference,
    }

    impl ConsensusCore for Deposable {
        type Message = Message;

        fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
            Self {
                id,
                inner: Reference::recover(id, peers, log),
            }
        }

        fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
            if deposed(self.id) {
                // A deposed leader knows of no leader.
                return Err(NotLeader { leader: None }.into());
            }
            self.inner.propose(command, log)
        }

        fn step(&mut self, from: NodeId, message: Message, log: &mut LogView<'_>) {
            self.inner.step(from, message, log);
        }

        fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
            self.inner.tick(now, log);
        }

        fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
            self.inner.ready(log)
        }

        fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
            self.inner.advance(persisted, log);
        }

        fn term(&self) -> u64 {
            self.inner.term() + TERMS.with(Cell::get)
        }

        fn leads(&self) -> bool {
            self.inner.leads() && !deposed(self.id)
        }

        fn received(&self) -> Option<u64> {
            self.inner.received()
        }

        fn committed(&self) -> Option<u64> {
            self.inner.committed()
        }
    }
}

use deposable::{Deposable, depose, restore};

type Movable = DeliveryMember<Deposable, AppendService>;
type MovableSim = ClusterSim<Movable, Delivery<Message>>;

/// `servers` deposable servers and one client sending `commands` to
/// `to`.
fn movable(
    seed: u64,
    servers: u32,
    to: NodeId,
    commands: Vec<Vec<u8>>,
    deadline: u64,
) -> (MovableSim, NodeId) {
    let mut sim = MovableSim::new("delivery", seed, LinkConfig::default()).unwrap();
    for id in 0..servers {
        let server = DeliveryServer::new(
            id,
            (0..servers).collect(),
            SimDisk::new(),
            Survives::Synced,
            Geometry::new(4096, 4096).unwrap(),
            AppendService::default(),
            config(),
        )
        .unwrap();
        assert_eq!(
            sim.add_node(Movable::Server(Box::new(server)), 0, 0)
                .unwrap(),
            id
        );
    }
    let client = DeliveryClient::new(servers, to, commands).with_deadline(deadline);
    assert_eq!(
        sim.add_node(Movable::Client(client), 0, 0).unwrap(),
        servers
    );
    (sim, servers)
}

fn movable_server(sim: &MovableSim, id: NodeId) -> &DeliveryServer<Deposable, AppendService> {
    sim.node(id).and_then(Movable::server).unwrap()
}

fn movable_client(sim: &MovableSim, id: NodeId) -> &DeliveryClient {
    sim.node(id).and_then(Movable::client).unwrap()
}

/// Steps until `until` holds, at most `steps` times.
fn run_until(sim: &mut MovableSim, steps: u64, until: impl Fn(&MovableSim) -> bool) {
    for _ in 0..steps {
        if until(sim) {
            return;
        }
        sim.step().unwrap();
    }
    panic!("not reached in {steps} steps");
}

#[test]
fn test_delivery_a_request_to_a_follower_is_forwarded_and_answered() {
    for servers in [3, 5] {
        for seed in scenarios::seeds() {
            let follower = servers - 1;
            let (mut sim, client) = movable(seed, servers, follower, values(&[4, 5]), DEADLINE_OFF);
            sim.run_for(800).unwrap();
            let client = movable_client(&sim, client);
            assert!(client.done(), "{servers} servers, seed {seed}");
            assert_eq!(client.answers(), [(0, count(1)), (1, count(2))]);
            // Forwarded, not redirected: the client never left the follower.
            assert_eq!(client.server(), follower);
            assert_eq!(client.retries(), 0);
            assert_eq!(
                movable_server(&sim, LEADER).container().service().values,
                [4, 5]
            );
        }
    }
}

/// A deadline no test reaches.
const DEADLINE_OFF: u64 = u64::MAX;

/// The number of times `value` was applied on `server`.
fn applied_times(sim: &MovableSim, server: NodeId, value: u64) -> usize {
    movable_server(sim, server)
        .container()
        .service()
        .values
        .iter()
        .filter(|applied| **applied == value)
        .count()
}

/// A leader that stops leading with a request pending answers it
/// `Unknown`, not a failure; the client retries the same epoch and
/// sequence, and once a leader takes it again the session table answers
/// it. The command runs once.
fn deposed_with_a_request_pending(servers: u32, to: NodeId) {
    for seed in scenarios::seeds() {
        let (mut sim, client) = movable(seed, servers, to, values(&[42]), DEADLINE_OFF);
        // Until the leader holds the request, uncommitted.
        run_until(&mut sim, 2000, |sim| {
            movable_server(sim, LEADER).pending_requests() > 0
        });
        depose(LEADER);
        run_until(&mut sim, 2000, |sim| {
            movable_client(sim, client).unknowns() > 0
        });
        assert!(
            movable_client(&sim, client).answers().is_empty(),
            "no guess"
        );
        sim.run_for(200).unwrap();
        restore();
        sim.run_for(1500).unwrap();
        let answered = movable_client(&sim, client);
        assert!(answered.done(), "{servers} servers, seed {seed}");
        let [(0, answer)] = answered.answers() else {
            panic!("{:?}", answered.answers());
        };
        assert!(
            matches!(answer, Answer::Applied(_) | Answer::Retained(_)),
            "{answer:?}"
        );
        assert_eq!(
            *answer.reply(),
            1u64.to_le_bytes(),
            "{servers} servers, seed {seed}"
        );
        for server in 0..servers {
            assert_eq!(
                applied_times(&sim, server, 42),
                1,
                "server {server}, seed {seed}"
            );
        }
    }
}

#[test]
fn test_delivery_a_deposed_leader_answers_unknown_and_the_retry_is_deduplicated() {
    for servers in [3, 5] {
        deposed_with_a_request_pending(servers, LEADER);
    }
}

/// karyos#686, condition 3: the leader changes while a forward is in
/// flight; the follower relays `Unknown`, the client retries through it,
/// and the command never runs twice.
#[test]
fn test_delivery_a_leader_change_with_a_forward_in_flight_never_applies_twice() {
    for servers in [3, 5] {
        deposed_with_a_request_pending(servers, servers - 1);
    }
}

#[test]
fn test_delivery_a_request_unresolved_at_its_deadline_is_unknown() {
    let (mut sim, client) = movable(1, 3, LEADER, values(&[9, 10]), 1000);
    run_until(&mut sim, 2000, |sim| {
        movable_server(sim, LEADER).pending_requests() > 0
    });
    // Deposed for good: nothing resolves the request.
    depose(LEADER);
    sim.run_for(3000).unwrap();
    let client = movable_client(&sim, client);
    assert!(client.done());
    assert_eq!(
        client.answers(),
        [(0, Answer::Unknown), (1, Answer::Unknown)]
    );
    // The first may have applied, never twice; the second never reached a
    // leader.
    assert!(applied_times(&sim, LEADER, 9) <= 1);
    assert_eq!(applied_times(&sim, LEADER, 10), 0);
    restore();
}

// Timers and configuration changes through the log (karyos#686, part 4).

use karyos_sim::harness::core::{Change, ConsensusCore};
use karyos_sim::harness::delivery::schedule;
use karyos_sim::harness::reference::decode_configuration;

/// The index of every entry of `kind` `server` applied.
fn indexes_of<C: ConsensusCore>(server: &DeliveryServer<C, AppendService>, kind: &str) -> Vec<u64> {
    server
        .kinds()
        .iter()
        .filter(|(_, applied)| *applied == kind)
        .map(|(index, _)| *index)
        .collect()
}

/// The index of every `event` the service of `server` recorded.
fn events_of<C: ConsensusCore>(server: &DeliveryServer<C, AppendService>, event: &str) -> Vec<u64> {
    server
        .container()
        .service()
        .events
        .iter()
        .filter(|(_, recorded)| recorded == event)
        .map(|(index, _)| *index)
        .collect()
}

#[test]
fn test_delivery_a_timer_fires_through_its_log_entry_on_every_replica() {
    for servers in [3, 5] {
        for seed in scenarios::seeds() {
            let mut commands = vec![schedule(1, 200)];
            commands.extend(values(&[3]));
            let (mut sim, clients) = cluster(seed, servers, vec![commands], false);
            sim.run_for(1200).unwrap();
            assert!(client(&sim, clients[0]).done());
            let leader = server(&sim, LEADER);
            let timers = indexes_of(leader, "timer");
            assert_eq!(
                timers.len(),
                1,
                "{servers} servers, seed {seed}: {timers:?}"
            );
            // Delivered at its own entry, after the request that set it.
            assert_eq!(events_of(leader, "timer 1"), timers);
            assert!(indexes_of(leader, "request")[0] < timers[0]);
            for id in 0..servers {
                assert_eq!(
                    events_of(server(&sim, id), "timer 1"),
                    timers,
                    "server {id}"
                );
            }
            replicas_agree(&sim, servers);
        }
    }
}

#[test]
fn test_delivery_a_configuration_change_is_delivered_at_its_entry_before_what_follows() {
    for servers in [3, 5] {
        let (mut sim, clients) = {
            let mut sim = Sim::new("delivery", 11, LinkConfig::default()).unwrap();
            for id in 0..servers {
                let server = DeliveryServer::new(
                    id,
                    (0..servers).collect(),
                    SimDisk::new(),
                    Survives::Synced,
                    Geometry::new(4096, 4096).unwrap(),
                    AppendService::default(),
                    config(),
                )
                .unwrap()
                .with_configurations(|payload| decode_configuration(payload).is_some());
                sim.add_node(Member::Server(Box::new(server)), 0, 0)
                    .unwrap();
            }
            let client = DeliveryClient::new(servers, LEADER, values(&[1, 2]));
            let id = sim.add_node(Member::Client(client), 0, 0).unwrap();
            (sim, vec![id])
        };
        sim.run_for(200).unwrap();
        // The operator adds a learner that is never started: the change is
        // an entry, and the service sees it when it applies.
        let _ = sim.send(
            clients[0],
            LEADER,
            Delivery::Change(Change::AddLearner(servers + 1)),
        );
        sim.run_for(800).unwrap();
        assert!(client(&sim, clients[0]).done());
        for id in 0..servers {
            let server = server(&sim, id);
            assert_eq!(server.halted(), None, "server {id}");
            let changes = indexes_of(server, "configuration");
            assert_eq!(changes.len(), 1, "server {id}: {:?}", server.kinds());
            assert_eq!(
                events_of(
                    server,
                    &format!("configuration of {} bytes", configuration_bytes(servers))
                ),
                changes,
                "server {id}"
            );
        }
        replicas_agree(&sim, servers);
    }
}

/// The reference core's configuration entry for `servers` voters and one
/// learner.
fn configuration_bytes(servers: u32) -> usize {
    karyos_sim::harness::reference::encode_configuration(
        &(0..servers).collect::<Vec<_>>(),
        &[servers + 1],
    )
    .len()
}

/// karyos#686, condition 4: a leader that comes back after losing its
/// leadership proposes the due timers again, those it proposed before
/// included; the second firing of a timer is a no-op, so the timer runs
/// once on every replica. A timer that fell due while no one led is
/// proposed by the next leader.
#[test]
fn test_delivery_a_new_leader_proposes_due_timers_again_and_a_duplicate_firing_is_a_no_op() {
    for servers in [3, 5] {
        for seed in scenarios::seeds() {
            let mut commands = vec![schedule(1, 300), schedule(2, 900)];
            commands.extend(values(&[8]));
            let (mut sim, client) = movable(seed, servers, LEADER, commands, DEADLINE_OFF);
            // Timer 1's firing proposed, then the leader is deposed and
            // restored: it proposes the firing again.
            run_until(&mut sim, 4000, |sim| {
                movable_server(sim, LEADER)
                    .kinds()
                    .iter()
                    .any(|(_, kind)| *kind == "timer")
                    || movable_server(sim, LEADER).proposed_firings() > 0
            });
            depose(LEADER);
            sim.run_for(5).unwrap();
            restore();
            // Timer 2 falls due while no one leads.
            run_until(&mut sim, 4000, |sim| movable_client(sim, client).done());
            depose(LEADER);
            sim.run_for(1200).unwrap();
            assert!(events_of(movable_server(&sim, LEADER), "timer 2").is_empty());
            restore();
            sim.run_for(800).unwrap();
            for id in 0..servers {
                let server = movable_server(&sim, id);
                assert_eq!(
                    events_of(server, "timer 1").len(),
                    1,
                    "server {id}, seed {seed}"
                );
                assert_eq!(
                    events_of(server, "timer 2").len(),
                    1,
                    "server {id}, seed {seed}"
                );
            }
            let firings = indexes_of(movable_server(&sim, LEADER), "timer").len();
            assert!(
                firings >= 3,
                "timer 1 proposed twice: {firings} firings logged"
            );
        }
    }
}

/// karyos#927 review P1: no registration applies before the session
/// bounds. With clients registering from the start, on every replica of
/// every seed the log holds the bounds entry before any registration (a
/// Register a leader takes before the bounds apply is held and proposed
/// after them), every client still registers, and the sessions run under
/// the logged bounds.
#[test]
fn test_delivery_no_registration_applies_before_the_session_bounds() {
    for servers in [3, 5] {
        for seed in scenarios::seeds() {
            let (mut sim, clients) = cluster(
                seed,
                servers,
                vec![values(&[1]), values(&[2]), values(&[3])],
                false,
            );
            sim.run_for(1200).unwrap();
            for id in 0..servers {
                let server = server(&sim, id);
                let kinds = server.kinds();
                let bounds = kinds.iter().position(|(_, kind)| *kind == "bounds");
                let first_register = kinds.iter().position(|(_, kind)| *kind == "register");
                if let Some(register) = first_register {
                    assert!(
                        bounds.is_some_and(|bounds| bounds < register),
                        "server {id}, seed {seed}: a registration before the bounds: {kinds:?}"
                    );
                }
                assert_eq!(server.container().sessions().config(), config().dedup);
            }
            for &id in &clients {
                assert!(
                    client(&sim, id).epoch().is_some(),
                    "client {id}, seed {seed} never registered"
                );
            }
            replicas_agree(&sim, servers);
        }
    }
}

/// `servers` deposable servers that never propose the session bounds, so a
/// leader holds every registration, each holding at most `held`; and
/// `clients` clients registering with the leader.
fn holding(seed: u64, servers: u32, held: usize, clients: u32) -> (MovableSim, Vec<NodeId>) {
    let mut sim = MovableSim::new("delivery", seed, LinkConfig::default()).unwrap();
    for id in 0..servers {
        let server = DeliveryServer::new(
            id,
            (0..servers).collect(),
            SimDisk::new(),
            Survives::Synced,
            Geometry::new(4096, 4096).unwrap(),
            AppendService::default(),
            config(),
        )
        .unwrap()
        .with_held_registrations(held)
        .without_bounds_proposal();
        assert_eq!(
            sim.add_node(Movable::Server(Box::new(server)), 0, 0)
                .unwrap(),
            id
        );
    }
    let ids = (servers..servers + clients)
        .map(|id| {
            let client = DeliveryClient::new(id, LEADER, values(&[1]));
            assert_eq!(sim.add_node(Movable::Client(client), 0, 0).unwrap(), id);
            id
        })
        .collect();
    (sim, ids)
}

/// karyos#927 review: a leader holds at most its configured number of
/// registrations before the bounds apply; one more is answered NotLeader
/// naming the leader, so its client retries, and none is held past the
/// bound.
#[test]
fn test_delivery_held_registrations_are_bounded() {
    for seed in scenarios::seeds() {
        let (mut sim, clients) = holding(seed, 3, 1, 3);
        run_until(&mut sim, 2000, |sim| {
            movable_server(sim, LEADER).held_registrations() == 1
        });
        sim.run_for(300).unwrap();
        assert_eq!(movable_server(&sim, LEADER).held_registrations(), 1);
        let refused = clients
            .iter()
            .filter(|&&id| movable_client(&sim, id).retries() > 0)
            .count();
        assert!(
            refused >= 2,
            "seed {seed}: the clients past the bound retry"
        );
        assert!(
            clients
                .iter()
                .all(|&id| movable_client(&sim, id).epoch().is_none()),
            "seed {seed}: no registration before the bounds"
        );
    }
}

/// karyos#927 review: a leader that loses its leadership answers every
/// registration it held, never dropping one silently.
#[test]
fn test_delivery_held_registrations_are_answered_on_leadership_loss() {
    for seed in scenarios::seeds() {
        restore();
        let (mut sim, clients) = holding(seed, 3, 4, 1);
        let client = clients[0];
        run_until(&mut sim, 2000, |sim| {
            movable_server(sim, LEADER).held_registrations() == 1
        });
        let before = movable_client(&sim, client).retries();
        depose(LEADER);
        run_until(&mut sim, 200, |sim| {
            movable_server(sim, LEADER).held_registrations() == 0
                && movable_client(sim, client).retries() > before
        });
        restore();
    }
}
