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
//!   and no prefix purge crosses the Archive's hold (A2's purge floor);
//! - an install keeps the snapshot the node stands on until it is durable,
//!   waits out the Archive's hold without publishing, and a node without a
//!   snapshot store refuses a snapshot and keeps running; a node an
//!   earlier process left reopens from its log and snapshots.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use karyos_archive::control::HoldState;
use karyos_archive::segment::Geometry;
use karyos_cluster::DedupConfig;
use karyos_cluster::custom::Custom;
use karyos_cluster::driver::ConsensusCore;
use karyos_cluster::node::Storage;
use karyos_cluster::service::{ContainerConfig, ServiceSnapshot};
use karyos_cluster::snapshot::SnapshotConfig;
use karyos_sim::cluster::ClusterSim;
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::harness::delivery::{
    Answer, AppendService, Delivery, DeliveryClient, DeliveryMember, DeliveryServer,
};
use karyos_sim::harness::node::{LOG_DIR, SNAPSHOT_DIR};
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
    make: impl Fn(
        NodeId,
        DeliveryServer<Custom, AppendService>,
    ) -> DeliveryServer<Custom, AppendService>,
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
        let member = Member::Server(Box::new(make(id, server)));
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
                |_, server| server,
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
                |_, server| server,
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
            let (mut sim, clients) = cluster(seed, servers, vec![values(&[7])], |_, server| server);
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
        let (mut sim, _clients) = cluster(0xC6, servers, vec![values(&[1, 2])], |_, server| {
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
            let (mut sim, clients) = cluster(seed, servers, vec![many(24)], |_, server| {
                compacting(server)
            });
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
        let (mut sim, clients) = cluster(0xC6, 3, vec![many(16)], |_, server| {
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
            let (mut sim, clients) = cluster(seed, servers, vec![values(&[1])], |_, server| {
                compacting(server)
            });
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

/// `server` compacting at `config`, with the parts of each snapshot.
fn compacting_at(
    server: DeliveryServer<Custom, AppendService>,
    config: SnapshotConfig,
) -> DeliveryServer<Custom, AppendService> {
    server
        .with_snapshots(config, ServiceSnapshot::new(4096, 4))
        .unwrap()
}

/// Crashes the follower after the leader, lets the others apply `more`
/// values and purge what it needs next, and returns it with the leader.
fn lag_behind_the_purge(sim: &mut Sim, servers: u32, more: u64) -> (NodeId, NodeId) {
    let (leader_id, _) = leader(sim, servers).unwrap();
    let lagging = (leader_id + 1) % servers;
    sim.crash(lagging).unwrap();
    let client = sim
        .add_node(
            Member::Client(DeliveryClient::new(next_id(sim), leader_id, many(more))),
            0,
            0,
        )
        .unwrap();
    run_until(sim, "the second client answered", |sim| {
        all_done(sim, &[client])
    });
    assert!(server(sim, leader_id).first_index().unwrap() > 2);
    (leader_id, lagging)
}

/// The id the next node added gets.
fn next_id(sim: &Sim) -> NodeId {
    NodeId::try_from(sim.ids().len()).unwrap()
}

/// The values its container holds.
fn held(sim: &Sim, id: NodeId) -> usize {
    server(sim, id).container().service().values.len()
}

#[cfg(feature = "test-hooks")]
#[test]
fn test_cluster_node_a_crash_after_publishing_an_install_restarts_on_the_snapshot_it_stood_on() {
    // One snapshot kept: without the pin, publishing the leader's would
    // remove the one the lagging server's log stands on.
    let config = SnapshotConfig::default()
        .with_every_entries(4)
        .with_allowance(0)
        .with_keep(1);
    let (mut sim, clients) = cluster(0xC6, 3, vec![many(10)], |_, server| {
        compacting_at(server, config).with_stop_after_publish()
    });
    run_until(&mut sim, "the first answers", |sim| all_done(sim, &clients));
    run_until(&mut sim, "every replica applied", |sim| {
        applied_all(sim, 3, 10)
    });
    let (_, lagging) = lag_behind_the_purge(&mut sim, 3, 20);
    let stood_on = server(&sim, lagging).snapshots().to_vec();
    assert_eq!(stood_on.len(), 1);
    sim.restart(lagging).unwrap();
    run_until(&mut sim, "the install published and stopped", |sim| {
        !server(sim, lagging).is_up()
    });
    // The crash the stop stands for, then the restart: the node stands on
    // the snapshot it had, with its state, not on an empty container.
    sim.crash(lagging).unwrap();
    sim.restart(lagging).unwrap();
    let node = server(&sim, lagging);
    assert!(node.is_up());
    assert_eq!(node.base().map(|base| base.index), Some(stood_on[0].index));
    assert!(held(&sim, lagging) >= 1, "the state it stood on");
}

/// The Archive's hold one node reads, switched by the test.
#[derive(Clone)]
struct Switch(std::rc::Rc<std::cell::Cell<HoldState>>);

impl karyos_cluster::log::HoldSource for Switch {
    fn hold_state(&self) -> HoldState {
        self.0.get()
    }
}

#[test]
fn test_cluster_node_an_install_under_the_archive_hold_is_taken_once_the_hold_clears() {
    let switches: Vec<Switch> = (0..3)
        .map(|_| Switch(std::rc::Rc::new(std::cell::Cell::new(HoldState::None))))
        .collect();
    let (mut sim, clients) = cluster(0xC6, 3, vec![values(&[1])], |id, server| {
        compacting(server).with_hold(Box::new(switches[id as usize].clone()))
    });
    run_until(&mut sim, "the first answer", |sim| all_done(sim, &clients));
    let (_, lagging) = lag_behind_the_purge(&mut sim, 3, 20);
    let before = server(&sim, lagging).snapshots().to_vec();
    switches[lagging as usize].0.set(HoldState::Held);
    sim.restart(lagging).unwrap();
    sim.run_for(3_000).unwrap();
    // Held: nothing published, nothing installed, still up.
    let node = server(&sim, lagging);
    assert!(node.is_up());
    assert_eq!(node.snapshots(), &before[..]);
    assert_eq!(held(&sim, lagging), 1);
    switches[lagging as usize].0.set(HoldState::None);
    run_until(&mut sim, "the install once the hold cleared", |sim| {
        held(sim, lagging) == 21
    });
    replicas_agree(&sim, 3);
}

#[test]
fn test_cluster_node_without_a_snapshot_store_refuses_a_snapshot_and_keeps_running() {
    // A snapshot from a compacting run, past everything the other run
    // applies.
    let (mut source, clients) = cluster(0xC6, 3, vec![many(30)], |_, server| compacting(server));
    run_until(&mut source, "every client answered", |sim| {
        all_done(sim, &clients)
    });
    let (base, sections) = server(&source, 0).latest_snapshot().unwrap();
    let (mut sim, clients) = cluster(0xC6, 3, vec![values(&[1])], |_, server| server);
    run_until(&mut sim, "the first answer", |sim| all_done(sim, &clients));
    let (leader_id, _) = leader(&sim, 3).unwrap();
    let follower = (leader_id + 1) % 3;
    sim.send(leader_id, follower, Delivery::Snapshot { base, sections })
        .unwrap();
    sim.run_for(200).unwrap();
    assert!(server(&sim, follower).is_up());
    let client = sim
        .add_node(
            Member::Client(DeliveryClient::new(next_id(&sim), leader_id, values(&[2]))),
            0,
            0,
        )
        .unwrap();
    run_until(&mut sim, "the next request", |sim| all_done(sim, &[client]));
    run_until(&mut sim, "the follower applied it", |sim| {
        held(sim, follower) == 2
    });
}

#[test]
fn test_cluster_node_opens_the_log_and_snapshots_an_earlier_process_left() {
    let policy = SnapshotConfig::default()
        .with_every_entries(4)
        .with_allowance(0);
    let (mut sim, clients) = cluster(0xC6, 3, vec![many(24)], |_, server| {
        compacting_at(server, policy)
    });
    run_until(&mut sim, "every client answered", |sim| {
        all_done(sim, &clients)
    });
    run_until(&mut sim, "every replica applied", |sim| {
        applied_all(sim, 3, 24)
    });
    sim.crash(2).unwrap();
    let disk = server(&sim, 2).disk().clone();
    let at = (disk.clone(), std::path::Path::new(LOG_DIR));
    // A new log over it is refused: the directory holds one.
    assert!(
        karyos_cluster::node::ClusterNode::<Custom, AppendService, SimDisk>::new(
            2,
            vec![0, 1, 2],
            at.clone(),
            Geometry::new(4096, 4096).unwrap(),
            AppendService::default(),
            config(),
        )
        .is_err()
    );
    let mut opened = karyos_cluster::node::ClusterNode::<Custom, AppendService, SimDisk>::open(
        2,
        vec![0, 1, 2],
        at,
        Geometry::new(4096, 4096).unwrap(),
        AppendService::default(),
        config(),
        Storage {
            snapshots: Some((
                std::path::Path::new(SNAPSHOT_DIR),
                policy,
                ServiceSnapshot::new(4096, 4),
            )),
            hold: None,
        },
    )
    .unwrap();
    assert!(opened.is_up());
    assert!(opened.base().is_some(), "it stands on its latest snapshot");
    let mut out = Vec::new();
    for now in 1..=50 {
        opened.tick(now, &mut out);
    }
    assert_eq!(
        opened.container().service().values,
        (1..=24).collect::<Vec<_>>()
    );
}

#[test]
fn test_cluster_node_a_follower_holding_the_snapshot_base_keeps_its_log_after_it() {
    // A snapshot after every entry, and no purge.
    let policy = SnapshotConfig::default()
        .with_every_entries(1)
        .with_allowance(u64::MAX);
    let (mut sim, clients) = cluster(0xC6, 3, vec![values(&[1])], |_, server| {
        compacting_at(server, policy)
    });
    run_until(&mut sim, "the first answer", |sim| all_done(sim, &clients));
    run_until(&mut sim, "every replica applied", |sim| {
        applied_all(sim, 3, 1)
    });
    let (leader_id, _) = leader(&sim, 3).unwrap();
    let follower = (leader_id + 1) % 3;
    let other = (leader_id + 2) % 3;
    let client = sim
        .add_node(
            Member::Client(DeliveryClient::new(next_id(&sim), leader_id, values(&[2]))),
            0,
            0,
        )
        .unwrap();
    // The follower holds the request's entry, and has not learned it
    // committed: then the leader's messages to it stop.
    let core = |sim: &Sim, id| {
        let core = server(sim, id).core().unwrap();
        (core.received(), core.committed())
    };
    for _ in 0..PATIENCE {
        let (received, committed) = core(&sim, follower);
        // The leader took the request: its entry is the last there is.
        if server(&sim, leader_id).pending_requests() > 0
            && received.is_some()
            && received == core(&sim, leader_id).0
            && committed < received
        {
            break;
        }
        sim.step().unwrap();
    }
    let (received, committed) = core(&sim, follower);
    assert!(committed < received, "{committed:?} {received:?}");
    sim.net_mut().cut(leader_id, follower);
    run_until(&mut sim, "the leader answered", |sim| {
        all_done(sim, &[client])
    });
    let (base, sections) = server(&sim, leader_id).latest_snapshot().unwrap();
    assert_eq!(
        Some(base.index),
        received,
        "the snapshot's base is the follower's last entry"
    );
    let before = (
        server(&sim, follower).base(),
        server(&sim, follower).snapshots().to_vec(),
    );
    // A delayed snapshot at the base its log holds: no install, which
    // would cut the entries after the base the leader may count.
    sim.send(other, follower, Delivery::Snapshot { base, sections })
        .unwrap();
    sim.run_for(50).unwrap();
    let node = server(&sim, follower);
    assert!(node.is_up());
    assert_eq!(node.first_index(), Some(1));
    assert_eq!((node.base(), node.snapshots().to_vec()), before);
    sim.net_mut().heal();
    run_until(&mut sim, "every replica applied", |sim| {
        applied_all(sim, 3, 2)
    });
    replicas_agree(&sim, 3);
}

#[test]
fn test_cluster_node_a_leader_refuses_a_snapshot_past_its_commit_unchanged() {
    // A snapshot from a run that applied more than this one ever does.
    let (mut source, clients) = cluster(0xC6, 3, vec![many(30)], |_, server| compacting(server));
    run_until(&mut source, "every client answered", |sim| {
        all_done(sim, &clients)
    });
    let (base, sections) = server(&source, 0).latest_snapshot().unwrap();
    let (mut sim, clients) = cluster(0xC6, 3, vec![values(&[1])], |_, server| compacting(server));
    run_until(&mut sim, "the first answer", |sim| all_done(sim, &clients));
    let (leader_id, term) = leader(&sim, 3).unwrap();
    let before = (
        server(&sim, leader_id).first_index(),
        server(&sim, leader_id).base(),
        held(&sim, leader_id),
    );
    let follower = (leader_id + 1) % 3;
    sim.send(follower, leader_id, Delivery::Snapshot { base, sections })
        .unwrap();
    sim.run_for(50).unwrap();
    let node = server(&sim, leader_id);
    assert!(node.is_up());
    assert_eq!(leader(&sim, 3), Some((leader_id, term)));
    assert_eq!(
        (node.first_index(), node.base(), held(&sim, leader_id)),
        before
    );
}
