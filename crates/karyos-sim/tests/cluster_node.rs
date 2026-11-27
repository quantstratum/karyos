// SPDX-License-Identifier: Apache-2.0

//! The shipped Cluster node ([`karyos_cluster::node::ClusterNode`], C6,
//! quantstratum/karyos#681) with the custom Raft core (ADR-0105) behind it,
//! on 3 and 5 servers in the simulator:
//!
//! - a client's requests reach the log through the elected leader and
//!   their outcomes return, every replica applying the same entries;
//! - the same seed gives the same run: trace, digest and outcomes;
//! - pre-vote is active: a partitioned follower that rejoins disrupts no
//!   leader and moves no term;
//! - a driver that releases messages before they are durable is caught:
//!   the node refuses every such message;
//! - the log compacts through the snapshot store, a restart stands on the
//!   latest snapshot, a follower behind the purge installs the leader's,
//!   and no prefix purge crosses the Archive's hold (A2's purge floor).

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use karyos_archive::control::HoldState;
use karyos_archive::segment::Geometry;
use karyos_cluster::DedupConfig;
use karyos_cluster::custom::Custom;
use karyos_cluster::driver::ConsensusCore;
use karyos_cluster::service::{ContainerConfig, ServiceSnapshot};
use karyos_cluster::snapshot::SnapshotConfig;
use karyos_sim::cluster::ClusterSim;
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::harness::delivery::{
    Answer, AppendService, Delivery, DeliveryClient, DeliveryMember, DeliveryServer,
};
use karyos_sim::net::{LinkConfig, NodeId};
use karyos_sim::scenarios;

type Member = DeliveryMember<Custom, AppendService>;
type Sim = ClusterSim<Member, Delivery<<Custom as ConsensusCore>::Message>>;

/// The most steps a run waits for what it expects.
const PATIENCE: u64 = 40_000;

fn config() -> ContainerConfig {
    ContainerConfig::default().with_dedup(
        DedupConfig::default()
            .with_sessions(8)
            .with_window(8)
            .with_response_bytes(16),
    )
}

fn values(values: &[u64]) -> Vec<Vec<u8>> {
    values
        .iter()
        .map(|value| value.to_le_bytes().to_vec())
        .collect()
}

/// `servers` custom-core servers, each made by `make`, then one client
/// per command list, each sending to server 0, which forwards to the
/// leader its core names.
fn cluster(
    seed: u64,
    servers: u32,
    clients: Vec<Vec<Vec<u8>>>,
    make: impl Fn(DeliveryServer<Custom, AppendService>) -> DeliveryServer<Custom, AppendService>,
) -> (Sim, Vec<NodeId>) {
    let mut sim = Sim::new("cluster-node", seed, LinkConfig::default()).unwrap();
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
        let member = Member::Server(Box::new(make(server)));
        assert_eq!(sim.add_node(member, 0, 0).unwrap(), id);
    }
    let ids = clients
        .into_iter()
        .zip(servers..)
        .map(|(commands, id)| {
            let client = DeliveryClient::new(id, 0, commands);
            assert_eq!(sim.add_node(Member::Client(client), 0, 0).unwrap(), id);
            id
        })
        .collect();
    (sim, ids)
}

fn server(sim: &Sim, id: NodeId) -> &DeliveryServer<Custom, AppendService> {
    sim.node(id).and_then(Member::server).unwrap()
}

fn client(sim: &Sim, id: NodeId) -> &DeliveryClient {
    sim.node(id).and_then(Member::client).unwrap()
}

/// The server whose core leads, if exactly one does at the highest term.
fn leader(sim: &Sim, servers: u32) -> Option<(NodeId, u64)> {
    let leading: Vec<_> = (0..servers)
        .filter_map(|id| {
            let core = server(sim, id).core()?;
            core.leads().then(|| (id, core.term()))
        })
        .collect();
    let top = leading.iter().map(|&(_, term)| term).max()?;
    let mut at_top = leading.into_iter().filter(|&(_, term)| term == top);
    let first = at_top.next()?;
    at_top.next().is_none().then_some(first)
}

/// Steps until `until` holds, failing after [`PATIENCE`] steps.
fn run_until(sim: &mut Sim, what: &str, until: impl Fn(&Sim) -> bool) {
    for _ in 0..PATIENCE / 100 {
        if until(sim) {
            return;
        }
        sim.run_for(100).unwrap();
    }
    assert!(until(sim), "{what} within {PATIENCE} steps");
}

fn all_done(sim: &Sim, clients: &[NodeId]) -> bool {
    clients.iter().all(|&id| client(sim, id).done())
}

/// Every server applied the same entries to the same state and sessions.
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
    }
}

#[test]
fn test_cluster_node_requests_are_applied_and_answered_on_3_and_5_servers() {
    for servers in [3, 5] {
        for seed in scenarios::seeds() {
            let (mut sim, clients) = cluster(
                seed,
                servers,
                vec![values(&[10, 20, 30]), values(&[40])],
                |server| server,
            );
            run_until(&mut sim, "every client answered", |sim| {
                all_done(sim, &clients)
            });
            let answers: Vec<_> = clients
                .iter()
                .flat_map(|&id| client(&sim, id).answers().to_vec())
                .collect();
            assert_eq!(answers.len(), 4, "{servers} servers, seed {seed}");
            for (_, answer) in &answers {
                assert!(matches!(answer, Answer::Applied(_)), "{answer:?}");
            }
            // Every replica catches up to the same applied state.
            run_until(&mut sim, "every replica applied", |sim| {
                (0..servers).all(|id| server(sim, id).container().service().values.len() == 4)
            });
            let mut applied = server(&sim, 0).container().service().values.clone();
            applied.sort_unstable();
            assert_eq!(applied, [10, 20, 30, 40], "{servers} servers, seed {seed}");
            replicas_agree(&sim, servers);
            for id in 0..servers {
                assert_eq!(server(&sim, id).early_sends(), 0, "{id}");
            }
        }
    }
}

#[test]
fn test_cluster_node_the_same_seed_gives_the_same_run() {
    for servers in [3, 5] {
        let run = || {
            let (mut sim, clients) = cluster(
                0xC6,
                servers,
                vec![values(&[1, 2, 3]), values(&[4, 5])],
                |server| server,
            );
            run_until(&mut sim, "every client answered", |sim| {
                all_done(sim, &clients)
            });
            sim.run_for(2_000).unwrap();
            let answers: Vec<_> = clients
                .iter()
                .map(|&id| client(&sim, id).answers().to_vec())
                .collect();
            let applied: Vec<_> = (0..servers)
                .map(|id| server(&sim, id).container().applied())
                .collect();
            (sim.trace().to_vec(), sim.digest(), answers, applied)
        };
        assert_eq!(run(), run(), "{servers} servers");
    }
}

#[test]
fn test_cluster_node_a_rejoining_follower_disrupts_no_leader() {
    for servers in [3, 5] {
        for seed in scenarios::seeds() {
            let (mut sim, clients) = cluster(seed, servers, vec![values(&[7])], |server| server);
            run_until(&mut sim, "every client answered", |sim| {
                all_done(sim, &clients)
            });
            let (leader_id, term) = leader(&sim, servers).unwrap();
            let follower = (leader_id + 1) % servers;
            let everyone: Vec<_> = sim.ids();
            // Many election timeouts apart: without pre-vote the follower
            // would raise its term again and again, and depose the leader
            // when it rejoins.
            sim.net_mut().isolate(follower, &everyone);
            sim.run_for(8_000).unwrap();
            assert_eq!(
                server(&sim, follower).core().unwrap().term(),
                term,
                "seed {seed}"
            );
            sim.net_mut().heal();
            sim.run_for(8_000).unwrap();
            assert_eq!(
                leader(&sim, servers),
                Some((leader_id, term)),
                "{servers} servers, seed {seed}"
            );
            assert_eq!(server(&sim, follower).core().unwrap().term(), term);
        }
    }
}

#[cfg(feature = "test-hooks")]
#[test]
fn test_cluster_node_refuses_what_a_driver_releases_before_it_is_durable() {
    use karyos_cluster::driver::DriveFault;

    for servers in [3, 5] {
        let (mut sim, _clients) = cluster(0xC6, servers, vec![values(&[1, 2])], |server| {
            server.with_drive_fault(DriveFault::ReleaseEarly)
        });
        run_until(&mut sim, "an early release refused", |sim| {
            (0..servers).any(|id| server(sim, id).early_sends() > 0)
        });
    }
}

/// Compacts after every 4 applied entries, keeping no log bytes below the
/// oldest kept snapshot.
fn compacting(
    server: DeliveryServer<Custom, AppendService>,
) -> DeliveryServer<Custom, AppendService> {
    server
        .with_snapshots(
            SnapshotConfig::default()
                .with_every_entries(4)
                .with_allowance(0),
            ServiceSnapshot::new(4096, 4),
        )
        .unwrap()
}

/// `count` values, from 1.
fn many(count: u64) -> Vec<Vec<u8>> {
    values(&(1..=count).collect::<Vec<_>>())
}

fn applied_all(sim: &Sim, servers: u32, count: usize) -> bool {
    (0..servers).all(|id| server(sim, id).container().service().values.len() == count)
}

#[test]
fn test_cluster_node_compacts_through_the_snapshot_store_and_restarts_from_it() {
    for servers in [3, 5] {
        for seed in scenarios::seeds() {
            let (mut sim, clients) = cluster(seed, servers, vec![many(24)], compacting);
            run_until(&mut sim, "every client answered", |sim| {
                all_done(sim, &clients)
            });
            run_until(&mut sim, "every replica applied", |sim| {
                applied_all(sim, servers, 24)
            });
            for id in 0..servers {
                let node = server(&sim, id);
                assert!(!node.snapshots().is_empty(), "{id}, seed {seed}");
                let base = node.base().unwrap();
                assert_eq!(node.snapshots().last().unwrap().index, base.index);
                // Purged below the oldest kept snapshot: the allowance is 0.
                let oldest = node.snapshots().first().unwrap().index;
                assert_eq!(node.first_index(), Some(oldest + 1), "{id}, seed {seed}");
                assert_eq!(node.held_purges(), 0);
            }
            replicas_agree(&sim, servers);
            // A restarted server stands on its latest snapshot and the log
            // after it.
            let restarted = servers - 1;
            sim.crash(restarted).unwrap();
            sim.restart(restarted).unwrap();
            sim.run_for(2_000).unwrap();
            let node = server(&sim, restarted);
            assert!(node.base().is_some(), "seed {seed}");
            assert_eq!(
                node.container().service().values,
                (1..=24).collect::<Vec<_>>()
            );
            replicas_agree(&sim, servers);
        }
    }
}

#[test]
fn test_cluster_node_never_purges_across_the_archive_hold() {
    for hold in [HoldState::Held, HoldState::Pending, HoldState::Unknown] {
        let (mut sim, clients) = cluster(0xC6, 3, vec![many(16)], |server| {
            compacting(server).with_hold(Box::new(hold))
        });
        run_until(&mut sim, "every client answered", |sim| {
            all_done(sim, &clients)
        });
        run_until(&mut sim, "every replica applied", |sim| {
            applied_all(sim, 3, 16)
        });
        for id in 0..3 {
            let node = server(&sim, id);
            // Snapshots are taken, and the log keeps everything.
            assert!(!node.snapshots().is_empty(), "{hold:?} {id}");
            assert_eq!(node.first_index(), Some(1), "{hold:?} {id}");
            assert!(node.held_purges() > 0, "{hold:?} {id}");
        }
        replicas_agree(&sim, 3);
    }
}

#[test]
fn test_cluster_node_a_follower_behind_the_purge_installs_the_leaders_snapshot() {
    for servers in [3, 5] {
        for seed in scenarios::seeds() {
            let (mut sim, clients) = cluster(seed, servers, vec![values(&[1])], compacting);
            run_until(&mut sim, "the first answer", |sim| all_done(sim, &clients));
            let (leader_id, _) = leader(&sim, servers).unwrap();
            let lagging = (leader_id + 1) % servers;
            sim.crash(lagging).unwrap();
            // The rest commit, compact and purge what the lagging server
            // needs next.
            let client = sim
                .add_node(
                    Member::Client(DeliveryClient::new(servers + 1, leader_id, many(20))),
                    0,
                    0,
                )
                .unwrap();
            run_until(&mut sim, "the second client answered", |sim| {
                all_done(sim, &[client])
            });
            let first = server(&sim, leader_id).first_index().unwrap();
            assert!(first > 2, "seed {seed}: the leader purged to {first}");
            sim.restart(lagging).unwrap();
            run_until(&mut sim, "the lagging server installed", |sim| {
                server(sim, lagging).base().is_some()
                    && server(sim, lagging).container().service().values.len() == 21
            });
            replicas_agree(&sim, servers);
        }
    }
}
