// SPDX-License-Identifier: Apache-2.0

//! C5 version 2's W2 in-flight byte case (quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v2.md, "W2: an in-flight byte
//! case that reaches its bound"; ADR-0105, decision 4; karyos#691): 3
//! servers, 32 clients each keeping 4 requests open, 8,192-byte payloads,
//! 256 KiB (262,144 bytes) in flight per follower and version 1's 64
//! entries, queue of 1,024 and log read of 1 MiB per duty, 128 operations
//! per client.
//!
//! **Oracle**, from the run's own trace, never from an adapter's
//! counters: every append a leader sends is observed with its entries'
//! indices and payload bytes, and every acknowledgement it steps with the
//! index it acknowledges; for each leader and follower, the payload bytes
//! sent and not yet acknowledged (each index counted once, however often
//! it is resent) must never exceed 262,144, and must reach 229,376 (28
//! entries) at least once per seed. Every refusal is a typed backpressure,
//! and W1's pass condition holds once the load stops.
//!
//! The candidates' adapters keep the byte cap by entry size: every
//! 8,192-byte command is over their 4 KiB share and refused with a typed
//! `Backpressure(InFlightBytes)`. The case shows that refusal for them, as
//! its result to report separately; their metered window is not
//! demonstrated, and no per-entry count is made from a case with no
//! replicated entries.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use karyos_raft_eval::openraft_core::{self, OpenRaft};
use karyos_raft_eval::raft_rs::{self, RaftRs};
use karyos_sim::harness::core::{
    ConsensusCore, Limit, Limits, LogView, Persisted, Ready, ReadyBuf, Refused, Unsupported,
};
use karyos_sim::harness::custom::{self, Custom};
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::workloads::{self, Case, Outcome, W2};
use karyos_sim::net::NodeId;

const SEEDS: [u64; 4] = [1, 0xC5, 0x0043, 0xDEAD_BEEF];

/// The frozen byte cap per follower.
const CAP: u64 = 256 * 1024;

/// The bytes in flight the case must reach once per seed: 28 entries.
const REACHED: u64 = 28 * 8192;

/// The frozen case.
fn case() -> Case {
    let w2 = W2 {
        payload_bytes: 8192,
        limits: Limits {
            in_flight_bytes: CAP,
            ..W2::manifest().limits
        },
        ..W2::manifest()
    };
    assert_eq!(w2.limits.in_flight_entries, 64);
    assert_eq!(w2.limits.queue, 1024);
    assert_eq!(w2.limits.log_read_bytes, 1024 * 1024);
    assert_eq!(w2.clients, 32);
    let mut case = w2.cases().unwrap().into_iter().next().unwrap();
    case.name = "W2 v2 n=3 clients=32 window=4 payload=8192 in-flight 256 KiB".to_owned();
    case.window = 4;
    // 128 operations per client, over its 4 sessions.
    case.operations = 128 / case.window;
    case
}

/// What the oracle saw of one run.
#[derive(Debug, Default)]
struct Trace {
    /// Per leader and follower: the term, and the unacknowledged indices'
    /// payload bytes.
    unacked: BTreeMap<(NodeId, NodeId), (u64, BTreeMap<u64, u64>)>,
    /// The most payload bytes ever unacknowledged to one follower.
    most: u64,
    /// Entries seen in appends.
    appended: u64,
}

impl Trace {
    fn sent(&mut self, leader: NodeId, term: u64, to: NodeId, entries: &[(u64, u64)]) {
        let (seen, unacked) = self.unacked.entry((leader, to)).or_default();
        if term != *seen {
            *seen = term;
            unacked.clear();
        }
        for &(index, bytes) in entries {
            unacked.insert(index, bytes);
            self.appended += 1;
        }
        let total: u64 = unacked.values().sum();
        self.most = self.most.max(total);
    }

    fn acked(&mut self, leader: NodeId, from: NodeId, index: u64) {
        if let Some((_, unacked)) = self.unacked.get_mut(&(leader, from)) {
            unacked.retain(|&at, _| at > index);
        }
    }
}

thread_local! {
    static TRACE: RefCell<Trace> = RefCell::new(Trace::default());
}

/// How a core's messages are read: an append's entries as (index,
/// payload bytes), and an acknowledgement's index.
trait Read: ConsensusCore {
    fn entries(message: &Self::Message) -> Option<Vec<(u64, u64)>>;
    fn ack(message: &Self::Message) -> Option<u64>;
}

impl Read for RaftRs {
    fn entries(message: &Self::Message) -> Option<Vec<(u64, u64)>> {
        raft_rs::append_entries(message)
    }

    fn ack(message: &Self::Message) -> Option<u64> {
        raft_rs::append_ack(message)
    }
}

impl Read for OpenRaft {
    fn entries(message: &Self::Message) -> Option<Vec<(u64, u64)>> {
        openraft_core::append_entries(message)
    }

    fn ack(message: &Self::Message) -> Option<u64> {
        openraft_core::append_ack(message)
    }
}

impl Read for Custom {
    fn entries(message: &Self::Message) -> Option<Vec<(u64, u64)>> {
        matches!(
            message.core,
            karyos_cluster::consensus::Message::Append { .. }
        )
        .then(|| {
            message
                .entries
                .iter()
                .map(|entry| (entry.index, u64::try_from(entry.payload.len()).unwrap()))
                .collect()
        })
    }

    fn ack(message: &Self::Message) -> Option<u64> {
        match message.core {
            karyos_cluster::consensus::Message::AppendReply {
                outcome: karyos_cluster::consensus::AppendOutcome::Accepted { index },
                ..
            } => Some(index),
            _ => None,
        }
    }
}

/// A core whose appends and acknowledgements are observed.
#[derive(Debug)]
struct Observed<C> {
    id: NodeId,
    core: C,
}

impl<C: Read> Observed<C> {
    fn observe(&self, messages: &[(NodeId, C::Message)]) {
        if !self.core.leads() {
            return;
        }
        let term = self.core.term();
        TRACE.with(|trace| {
            let mut trace = trace.borrow_mut();
            for (to, message) in messages {
                if let Some(entries) = C::entries(message) {
                    trace.sent(self.id, term, *to, &entries);
                }
            }
        });
    }
}

impl<C: Read> ConsensusCore for Observed<C> {
    type Message = C::Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self {
            id,
            core: C::recover(id, peers, log),
        }
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        Ok(Self {
            id,
            core: C::recover_with(id, peers, limits, log)?,
        })
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.core.propose(command, log)
    }

    fn propose_slice(&mut self, command: &[u8], log: &mut LogView<'_>) -> Result<(), Refused> {
        self.core.propose_slice(command, log)
    }

    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>) {
        if let Some(index) = C::ack(&message) {
            TRACE.with(|trace| trace.borrow_mut().acked(self.id, from, index));
        }
        self.core.step(from, message, log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.core.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        let ready = self.core.ready(log)?;
        self.observe(&ready.messages);
        self.observe(&ready.after_persist);
        Some(ready)
    }

    fn ready_into(&mut self, out: &mut ReadyBuf<Self::Message>, log: &mut LogView<'_>) -> bool {
        let ready = self.core.ready_into(out, log);
        self.observe(&out.ready.messages);
        self.observe(&out.ready.after_persist);
        ready
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.core.advance(persisted, log);
    }

    fn term(&self) -> u64 {
        self.core.term()
    }

    fn leads(&self) -> bool {
        self.core.leads()
    }

    fn received(&self) -> Option<u64> {
        self.core.received()
    }

    fn committed(&self) -> Option<u64> {
        self.core.committed()
    }
}

/// Runs the case of `C` under `seed`: its outcome, the oracle's trace and
/// the refusals it observed.
fn run<C: Read>(seed: u64) -> (Outcome, Trace, Vec<Limit>) {
    TRACE.with(|trace| *trace.borrow_mut() = Trace::default());
    let outcome = workloads::run::<Observed<C>>(&case(), seed).unwrap();
    let trace = TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()));
    let refused = outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Backpressure { limit, .. } => Some(*limit),
            _ => None,
        })
        .collect();
    (outcome, trace, refused)
}

/// The custom core passes the case on every seed: the bound held, reached
/// with at least 28 entries in flight, typed refusals only, and W1's pass
/// condition after the load.
#[test]
fn the_custom_core_holds_and_reaches_the_byte_cap() {
    assert_eq!(custom::BATCH, 16, "the adapter's batch, for the record");
    for seed in SEEDS {
        let (outcome, trace, refused) = run::<Custom>(seed);
        assert!(outcome.safety.is_ok(), "seed {seed}");
        assert!(
            trace.most <= CAP,
            "seed {seed}: {} bytes unacked",
            trace.most
        );
        assert!(
            trace.most >= REACHED,
            "seed {seed}: at most {} bytes in flight",
            trace.most
        );
        assert!(
            refused
                .iter()
                .all(|limit| matches!(limit, Limit::InFlightBytes | Limit::Queue)),
            "seed {seed}: {refused:?}"
        );
        assert_eq!(workloads::pass(&case(), &outcome), Ok(None), "seed {seed}");
    }
}

/// The candidates refuse every 8,192-byte command with
/// `Backpressure(InFlightBytes)`: their result, reported separately. No
/// command entry is replicated, so nothing over the cap is ever in
/// flight, and safety holds.
#[test]
fn the_candidates_refuse_every_command_over_their_share() {
    fn check<C: Read>(name: &str) {
        for seed in SEEDS {
            let (outcome, trace, refused) = run::<C>(seed);
            assert!(outcome.safety.is_ok(), "{name} seed {seed}");
            assert!(!refused.is_empty(), "{name} seed {seed}");
            assert!(
                refused.iter().all(|limit| *limit == Limit::InFlightBytes),
                "{name} seed {seed}: {refused:?}"
            );
            assert!(trace.most < 8192, "{name} seed {seed}: {}", trace.most);
        }
    }
    check::<RaftRs>("raft");
    check::<OpenRaft>("openraft");
}

/// The oracle itself: a resend counts once, an acknowledgement frees what
/// it covers, and a new term starts afresh.
#[test]
fn the_oracle_counts_each_unacknowledged_index_once() {
    let mut trace = Trace::default();
    trace.sent(0, 1, 1, &[(1, 100), (2, 100)]);
    trace.sent(0, 1, 1, &[(2, 100), (3, 100)]);
    assert_eq!(trace.most, 300);
    trace.acked(0, 1, 2);
    trace.sent(0, 1, 1, &[(4, 100)]);
    assert_eq!(
        trace
            .unacked
            .get(&(0, 1))
            .map(|(_, u)| u.values().sum::<u64>()),
        Some(200)
    );
    trace.sent(0, 2, 1, &[(5, 50)]);
    assert_eq!(
        trace
            .unacked
            .get(&(0, 1))
            .map(|(_, u)| u.values().sum::<u64>()),
        Some(50)
    );
    assert_eq!(trace.most, 300);
}
