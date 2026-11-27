// SPDX-License-Identifier: Apache-2.0

//! The shipped Cluster node's steady cycle allocates nothing once warm
//! (C6, quantstratum/karyos#681), in the style of `log_alloc.rs`: three
//! [`ClusterNode`]s with the custom core on `StdDisk`, in one thread, a
//! client's request to the leader proposed, replicated, persisted,
//! committed, applied on every node and answered make no allocation,
//! reallocation or free. The host's part is the transport's: it decodes
//! each client request into a buffer of the leader's pool
//! ([`ClusterNode::buffer`]), carries each message to its node, and gives
//! every answer back to the node that sent it once delivered
//! ([`ClusterNode::recycle`]), as a transport does once it has encoded it
//! for the wire.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::VecDeque;
use std::path::PathBuf;

use karyos_archive::disk::StdDisk;
use karyos_archive::segment::Geometry;
use karyos_cluster::DedupConfig;
use karyos_cluster::custom::Custom;
use karyos_cluster::dedup::Request;
use karyos_cluster::driver::{ConsensusCore, NodeId};
use karyos_cluster::node::{Answer, ClusterNode, Delivery, Outbox};
use karyos_cluster::service::{ClusteredService, ContainerConfig, Context};
use karyos_sys::alloc_count::{CountingAllocator, count};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const CLIENT: NodeId = 100;
const SERVERS: u32 = 3;

type Message = Delivery<<Custom as ConsensusCore>::Message>;
type Node = ClusterNode<Custom, Counter, StdDisk>;

/// Counts its commands and replies with the count.
#[derive(Debug, Clone, Default)]
struct Counter {
    count: u64,
}

impl ClusteredService for Counter {
    fn on_command(
        &mut self,
        _context: &mut Context<'_>,
        _client: u64,
        _command: &[u8],
        reply: &mut [u8],
    ) -> Option<usize> {
        self.count += 1;
        reply
            .get_mut(..8)?
            .copy_from_slice(&self.count.to_le_bytes());
        Some(8)
    }

    fn on_timer(&mut self, _context: &mut Context<'_>, _timer: u64) {}

    fn on_configuration(&mut self, _context: &mut Context<'_>, _configuration: &[u8]) {}
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("karyos-node-alloc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The host: the nodes, the messages in flight, and the clock.
struct Host {
    nodes: Vec<Node>,
    queue: VecDeque<(NodeId, NodeId, Message)>,
    out: Outbox<Message>,
    now: u64,
    /// What reached the client: its sender and the message.
    client: Vec<(NodeId, Message)>,
}

impl Host {
    fn route(&mut self, from: NodeId) {
        for (to, message) in self.out.drain(..) {
            if to == CLIENT {
                self.client.push((from, message));
            } else {
                self.queue.push_back((from, to, message));
            }
        }
    }

    /// One tick of every node, then every message in flight delivered.
    fn step(&mut self) {
        self.now += 1;
        for id in 0..SERVERS {
            self.nodes[id as usize].tick(self.now, &mut self.out);
            self.route(id);
        }
        while let Some((from, to, message)) = self.queue.pop_front() {
            self.nodes[to as usize].deliver(from, message, &mut self.out);
            self.route(to);
        }
    }

    fn leader(&self) -> Option<NodeId> {
        (0..SERVERS).find(|&id| self.nodes[id as usize].core().is_some_and(Custom::leads))
    }

    /// Sends `message` from the client to `to`, and steps until an answer
    /// reaches the client: it is given back to its sender.
    fn call(&mut self, to: NodeId, message: Message) -> (NodeId, Message) {
        self.nodes[to as usize].deliver(CLIENT, message, &mut self.out);
        self.route(to);
        for _ in 0..10_000 {
            if let Some(answer) = self.client.pop() {
                return answer;
            }
            self.step();
        }
        panic!("no answer");
    }
}

#[test]
fn a_steady_request_cycle_allocates_nothing_once_warm() {
    const WARM: u64 = 256;
    const MEASURED: u64 = 1024;
    let dirs: Vec<TempDir> = (0..SERVERS)
        .map(|id| TempDir::new(&id.to_string()))
        .collect();
    let config = ContainerConfig::default().with_dedup(
        DedupConfig::default()
            .with_sessions(8)
            .with_window(8)
            .with_response_bytes(16),
    );
    let nodes = (0..SERVERS)
        .map(|id| {
            ClusterNode::new(
                id,
                (0..SERVERS).collect(),
                (StdDisk, dirs[id as usize].0.as_path()),
                Geometry::with_default_length(1 << 24).unwrap(),
                Counter::default(),
                config,
            )
            .unwrap()
        })
        .collect();
    let mut host = Host {
        nodes,
        queue: VecDeque::with_capacity(1024),
        out: Vec::with_capacity(1024),
        now: 0,
        client: Vec::with_capacity(16),
    };
    while host.leader().is_none() {
        assert!(host.now < 100_000, "no leader");
        host.step();
    }
    let leader = host.leader().unwrap();
    // The session bounds apply before a registration is taken.
    let epoch = loop {
        match host.call(leader, Delivery::Register) {
            (_, Delivery::Registered { epoch }) => break epoch,
            _ => host.step(),
        }
    };
    // The client's requests, as the transport decodes them: into a
    // buffer of the leader's pool.
    let requests = (1..=WARM + MEASURED).map(|sequence| {
        (
            Request::new(u64::from(CLIENT), epoch, sequence, sequence),
            sequence.to_le_bytes(),
        )
    });
    let mut answers = Vec::with_capacity(usize::try_from(WARM + MEASURED).unwrap());
    let mut cycle = |host: &mut Host, (request, bytes): (Request, [u8; 8])| {
        let mut command = host.nodes[leader as usize].buffer();
        command.extend_from_slice(&bytes);
        let (from, answer) = host.call(leader, Delivery::Request { request, command });
        let Delivery::Answer { request, answer } = answer else {
            panic!("{answer:?}");
        };
        answers.push((request.sequence, matches!(answer, Answer::Applied(_))));
        host.nodes[from as usize].recycle(Delivery::Answer { request, answer });
    };
    let mut requests = requests;
    // The run's entries fit the log's index, as `log_alloc.rs` reserves.
    for node in &mut host.nodes {
        node.reserve(usize::try_from(2 * (WARM + MEASURED)).unwrap())
            .unwrap();
    }
    for request in requests.by_ref().take(usize::try_from(WARM).unwrap()) {
        cycle(&mut host, request);
    }
    let ((), seen) = count(|| {
        for request in requests {
            cycle(&mut host, request);
        }
    });
    assert_eq!(host.leader(), Some(leader), "a steady leader");
    assert_eq!(answers.len(), usize::try_from(WARM + MEASURED).unwrap());
    assert!(answers.iter().all(|&(_, applied)| applied), "{answers:?}");
    // Every node applied every request.
    for _ in 0..200 {
        host.step();
    }
    for node in &host.nodes {
        assert_eq!(node.container().service().count, WARM + MEASURED);
    }
    assert_eq!(
        seen, 0,
        "allocations, reallocations and frees in the steady cycle"
    );
}
