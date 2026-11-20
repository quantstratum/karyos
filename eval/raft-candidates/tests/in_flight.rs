// SPDX-License-Identifier: Apache-2.0

//! OpenRaft's in-flight cap across an RPC timeout (karyos#975 point 1,
//! karyos#1040): pinned as a finding of the comparison, not enforced by
//! the adapter. With one entry in flight per follower declared, the
//! leader's appends to a follower whose answers never arrive are timed
//! out after [`RPC_TIMEOUT`], and OpenRaft then sends the next append
//! while the first may still be in flight: more than one unacknowledged
//! append carrying entries leaves for that follower. raft-rs's
//! counterpart, a heartbeat answer freeing a full window's slot, is
//! pinned by `raft_rs::window`.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::path::Path;

use karyos_cluster::RaftLog;
use karyos_raft_eval::openraft_core::{Message, OpenRaft, RPC_TIMEOUT, Request};
use karyos_sim::disk::SimDisk;
use karyos_sim::harness::core::{ConsensusCore, Limits, LogView, drive};
use karyos_sim::harness::workloads;
use karyos_sim::net::NodeId;

const SERVERS: NodeId = 3;

/// Whether `message` is an append request carrying entries.
fn carries_entries(message: &Message) -> bool {
    matches!(
        message,
        Message::Request { request: Request::Append(rpc), .. } if !rpc.entries.is_empty()
    )
}

#[test]
fn openraft_sends_a_second_append_across_an_rpc_timeout() {
    let limits = Limits {
        in_flight_entries: 1,
        in_flight_bytes: 64 * 1024,
        queue: 64,
        log_read_bytes: 64 * 1024,
    };
    let peers: Vec<NodeId> = (0..SERVERS).collect();
    let mut logs: Vec<RaftLog<SimDisk>> = peers
        .iter()
        .map(|_| {
            RaftLog::create(
                SimDisk::new(),
                Path::new("log"),
                workloads::geometry().unwrap(),
                1,
            )
            .unwrap()
        })
        .collect();
    let mut cores: Vec<OpenRaft> = peers
        .iter()
        .zip(&mut logs)
        .map(|(id, log)| {
            OpenRaft::recover_with(*id, &peers, &limits, &mut LogView::new(log)).unwrap()
        })
        .collect();
    let mut queue: Vec<(NodeId, NodeId, Message)> = Vec::new();
    // `held`: the follower whose entry-carrying appends are withheld, never
    // delivered and so never answered; the count of those sent to it.
    let mut held: Option<NodeId> = None;
    let mut withheld = 0usize;
    let mut now = 0u64;
    let mut step = |cores: &mut Vec<OpenRaft>,
                    logs: &mut Vec<RaftLog<SimDisk>>,
                    queue: &mut Vec<(NodeId, NodeId, Message)>,
                    held: Option<NodeId>,
                    withheld: &mut usize| {
        now += 1;
        let mut sent = Vec::new();
        for id in 0..SERVERS {
            let index = usize::try_from(id).unwrap();
            cores[index].tick(now, &mut LogView::new(&mut logs[index]));
            drive(
                &mut cores[index],
                &mut logs[index],
                &mut |to, message, _| sent.push((id, to, message)),
                &mut |_, _| {},
                &mut |_| {},
            )
            .unwrap();
        }
        queue.extend(sent);
        for (from, to, message) in std::mem::take(queue) {
            if Some(to) == held && carries_entries(&message) {
                *withheld += 1;
                continue;
            }
            let index = usize::try_from(to).unwrap();
            cores[index].step(from, message, &mut LogView::new(&mut logs[index]));
            let mut sent = Vec::new();
            drive(
                &mut cores[index],
                &mut logs[index],
                &mut |next, message, _| sent.push((to, next, message)),
                &mut |_, _| {},
                &mut |_| {},
            )
            .unwrap();
            queue.extend(sent);
        }
    };
    for _ in 0..200 {
        step(&mut cores, &mut logs, &mut queue, held, &mut withheld);
    }
    let leader = (0..SERVERS)
        .find(|id| cores[usize::try_from(*id).unwrap()].leads())
        .unwrap();
    let follower = (0..SERVERS).find(|id| *id != leader).unwrap();
    held = Some(follower);
    let index = usize::try_from(leader).unwrap();
    cores[index]
        .propose(vec![1, 2, 3], &mut LogView::new(&mut logs[index]))
        .unwrap();
    let timeout = u64::try_from(RPC_TIMEOUT.as_millis()).unwrap();
    for _ in 0..timeout * 4 {
        step(&mut cores, &mut logs, &mut queue, held, &mut withheld);
    }
    // One entry in flight was declared; none of these was answered.
    assert!(withheld >= 2, "{withheld} appends with entries withheld");
}
