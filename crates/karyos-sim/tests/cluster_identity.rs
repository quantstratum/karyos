// SPDX-License-Identifier: Apache-2.0

//! The isolation of a rebuilt cluster (quantstratum-docs:
//! karyos/adr/0123-cluster-identity.md; karyos#717), over the harness with
//! the reference core (a fixed leader, server 0):
//!
//! - a rebuilt server among the live cluster's peers drops every frame of
//!   the live cluster before its core sees it, and the live servers drop
//!   its frames: the live cluster commits without it, and its log stays
//!   empty (decision 3);
//! - a live client refuses a rebuilt server's answer, and a rebuilt server
//!   drops a live client's request unjournalled (decision 4);
//! - an isolated rebuild applies nothing it answers, replies to nobody and
//!   refuses its promotion (decision 5).

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::cell::RefCell;
use std::rc::Rc;

use karyos_archive::segment::Geometry;
use karyos_cluster::client::Accepted;
use karyos_cluster::cluster_identity::{ClusterId, IdentityRecord};
use karyos_sim::cluster::{ClusterSim, Node, Outbox};
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::harness::node::{
    ClientNode, HARNESS_CLUSTER, Member, Observation, Op, Recorder, Ret, ServerNode, Shared, Wire,
};
use karyos_sim::harness::reference::{LEADER, Message as Msg, Reference as Fixed};
use karyos_sim::harness::standby::Fencing;
use karyos_sim::net::{LinkConfig, NodeId};

type Sim = ClusterSim<Member<Fixed>, Wire<Msg>>;

/// A rebuild of the harness's cluster, isolated from it.
const REBUILT: IdentityRecord = IdentityRecord {
    identity: ClusterId([0x72; 32]),
    isolated_from: Some(HARNESS_CLUSTER),
};

fn server(id: NodeId, servers: u32, recorder: &Shared) -> ServerNode<Fixed> {
    ServerNode::new(
        id,
        (0..servers).collect(),
        SimDisk::new(),
        Survives::Synced,
        Geometry::new(4096, 4096).unwrap(),
        Rc::clone(recorder),
    )
    .unwrap()
}

fn run(servers: Vec<ServerNode<Fixed>>, client: Option<ClientNode>) -> Sim {
    let mut sim = Sim::new("cluster-identity", 7, LinkConfig::default()).unwrap();
    for server in servers {
        let _ = sim
            .add_node(Member::Server(Box::new(server)), 0, 0)
            .unwrap();
    }
    if let Some(client) = client {
        let _ = sim.add_node(Member::Client(client), 0, 0).unwrap();
    }
    sim
}

fn appends(count: u8) -> Vec<Op> {
    (0..count).map(|value| Op::Append(vec![value])).collect()
}

fn observed(recorder: &Shared, wanted: impl Fn(&Observation) -> bool) -> usize {
    recorder
        .borrow()
        .observations
        .iter()
        .filter(|o| wanted(o))
        .count()
}

/// Server 2 of three under `odd`, the others under `even`, a client
/// sending four appends to the fixed leader: whether the client finished,
/// how many frames server 2 dropped, and whether server 2 applied anything.
fn mixed(even: IdentityRecord, odd: IdentityRecord) -> (bool, u64, usize, Shared) {
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    let servers = vec![
        server(0, 3, &recorder).with_identity(even),
        server(1, 3, &recorder).with_identity(even),
        server(2, 3, &recorder).with_identity(odd),
    ];
    let client = ClientNode::new(3, LEADER, appends(4), Rc::clone(&recorder))
        .accepting(Accepted::only(even.identity));
    let mut sim = run(servers, Some(client));
    sim.run_for(400).unwrap();
    let done = sim.node(3).and_then(Member::client).unwrap().done();
    let dropped = sim
        .node(2)
        .and_then(Member::server)
        .unwrap()
        .foreign_dropped();
    let applied = observed(&recorder, |o| {
        matches!(o, Observation::Applied { node: 2, .. })
    });
    (done, dropped, applied, recorder)
}

#[test]
fn a_rebuilt_peer_and_the_live_cluster_drop_each_other_s_frames() {
    let live = IdentityRecord {
        identity: HARNESS_CLUSTER,
        isolated_from: None,
    };
    // A rebuilt server among the live cluster: it drops the live leader's
    // frames, and the live majority commits without it.
    let (done, dropped, applied, recorder) = mixed(live, REBUILT);
    assert!(done, "the live cluster commits on its own majority");
    assert!(dropped > 0, "the live leader's frames");
    assert_eq!(applied, 0, "the rebuilt core never saw a live entry");
    assert!(
        observed(&recorder, |o| matches!(
            o,
            Observation::ForeignDropped {
                node: 2,
                from: 0,
                ..
            }
        )) > 0
    );
    // The reverse: a live server among the peers of another cluster that
    // takes requests drops that cluster's frames. (An isolated rebuild
    // takes none, so it sends nothing to drop.)
    let other = IdentityRecord {
        identity: ClusterId([0x6f; 32]),
        isolated_from: None,
    };
    let (done, dropped, applied, _) = mixed(other, live);
    assert!(done, "the other cluster commits on its own majority");
    assert!(dropped > 0, "the other leader's frames");
    assert_eq!(applied, 0, "the live core never saw the other's entry");
}

#[test]
fn a_live_client_and_a_rebuilt_server_refuse_each_other() {
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    // The client's request names the live cluster: the rebuilt server
    // drops it before its core, so nothing is journalled.
    let servers = (0..3)
        .map(|id| server(id, 3, &recorder).with_identity(REBUILT))
        .collect();
    let client = ClientNode::new(3, LEADER, appends(1), Rc::clone(&recorder));
    let mut sim = run(servers, Some(client));
    sim.run_for(200).unwrap();
    assert!(!sim.node(3).and_then(Member::client).unwrap().done());
    assert!(
        observed(&recorder, |o| matches!(
            o,
            Observation::ForeignDropped { from: 3, .. }
        )) > 0
    );
    assert_eq!(
        observed(&recorder, |o| matches!(o, Observation::Applied { .. })),
        0
    );

    // A rebuilt server's answer, even to the open request, is refused.
    let mut client = ClientNode::new(9, 0, appends(1), Rc::clone(&recorder));
    let mut out: Outbox<Wire<Msg>> = Outbox::new();
    client.tick(0, &mut out);
    let answer = Wire::<Msg>::Response {
        cluster: REBUILT.identity,
        sequence: 1,
        bytes: Ret::Appended(1).canonical(),
        index: 1,
        generation: 9,
    };
    client.deliver(0, answer, 1, &mut out);
    assert_eq!(client.open(), Some(1));
    assert!(
        recorder
            .borrow()
            .observations
            .contains(&Observation::ForeignCluster {
                client: 9,
                cluster: REBUILT.identity,
            })
    );
}

#[test]
fn an_isolated_rebuild_replies_to_nobody_and_refuses_promotion() {
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    let servers = (0..3)
        .map(|id| server(id, 3, &recorder).with_identity(REBUILT))
        .collect();
    // A client given the rebuild's identity: its requests reach the core's
    // node, which, isolated, takes none.
    let client = ClientNode::new(3, LEADER, appends(2), Rc::clone(&recorder))
        .accepting(Accepted::only(REBUILT.identity));
    let mut sim = run(servers, Some(client));
    sim.run_for(200).unwrap();
    assert_eq!(
        observed(&recorder, |o| matches!(o, Observation::Reply { .. })),
        0
    );
    assert!(!sim.node(3).and_then(Member::client).unwrap().done());
    let _ = sim
        .send(
            3,
            LEADER,
            Wire::Promote {
                fencing: Fencing::OperatorStop,
                unknown: Vec::new(),
            },
        )
        .unwrap();
    sim.run_for(50).unwrap();
    assert!(
        observed(&recorder, |o| matches!(
            o,
            Observation::IsolatedPromotion { node: LEADER }
        )) > 0
    );
    assert_eq!(
        observed(&recorder, |o| matches!(o, Observation::Promoted { .. })),
        0
    );
}
