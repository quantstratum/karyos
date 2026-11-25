// SPDX-License-Identifier: Apache-2.0

//! The W2 in-flight byte case's oracle (C5 v2, "W2: an in-flight byte
//! case that reaches its bound"), from a run's own messages: every append
//! a leader sends with its term and its entries' indices and payload
//! bytes, and every acknowledgement it steps. Shared by the simulated
//! runs (`tests/w2_bytes.rs`) and the real-process runs
//! (`tests/real_processes.rs`), so both judge the bound the same way.

// Each test crate that includes it uses a part of it.
#![allow(dead_code)]

use std::collections::BTreeMap;

use karyos_sim::net::NodeId;

/// One leader's view of one follower within a term.
#[derive(Debug, Default)]
pub struct Window {
    pub term: u64,
    /// The highest index the follower acknowledged in `term`.
    pub acked: u64,
    /// The indices sent above `acked`, with their payload bytes.
    pub unacked: BTreeMap<u64, u64>,
}

/// What the oracle saw of one run.
#[derive(Debug, Default)]
pub struct Trace {
    pub windows: BTreeMap<(NodeId, NodeId), Window>,
    /// The most payload bytes ever unacknowledged to one follower.
    pub most: u64,
    /// The largest entry payload seen in any append.
    pub largest: u64,
    /// Entries with a payload seen in appends.
    pub commands: u64,
}

impl Trace {
    pub fn sent(&mut self, leader: NodeId, to: NodeId, term: u64, entries: &[(u64, u64)]) {
        let window = self.windows.entry((leader, to)).or_default();
        if term < window.term {
            return;
        }
        if term > window.term {
            *window = Window {
                term,
                ..Window::default()
            };
        }
        for &(index, bytes) in entries {
            self.largest = self.largest.max(bytes);
            if bytes > 0 {
                self.commands += 1;
            }
            if index > window.acked {
                window.unacked.insert(index, bytes);
            }
        }
        let total: u64 = window.unacked.values().sum();
        self.most = self.most.max(total);
    }

    pub fn acked(&mut self, leader: NodeId, from: NodeId, term: u64, index: u64) {
        if let Some(window) = self.windows.get_mut(&(leader, from))
            && window.term == term
            && index > window.acked
        {
            window.acked = index;
            window.unacked.retain(|&at, _| at > index);
        }
    }

    pub fn unacked(&self, leader: NodeId, to: NodeId) -> u64 {
        self.windows
            .get(&(leader, to))
            .map_or(0, |window| window.unacked.values().sum())
    }
}
