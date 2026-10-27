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
