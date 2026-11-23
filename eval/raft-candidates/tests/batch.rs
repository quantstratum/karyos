// SPDX-License-Identifier: Apache-2.0

//! The batch entry cap of the allocation case (W1's frozen batch limit of
//! 16 entries, quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v1.md, W1; karyos#691): every
//! append each capped adapter sends is observed, catch-up of a returning
//! follower included, and none carries more than 16 entries or more than
//! W1's 16 KiB per-append byte cap; the cap binds (an append of exactly 16
//! is seen), and the run passes its checks.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::cell::Cell;

use karyos_raft_eval::openraft_core::{self, OpenRaftBatch16};
use karyos_raft_eval::raft_rs::{self, RaftRsBatch16};
use karyos_sim::harness::core::{
    ConsensusCore, Limits, LogView, Persisted, Ready, ReadyBuf, Refused, Unsupported,
};
use karyos_sim::harness::reference::BATCH_BYTES;
use karyos_sim::harness::workloads::{self, Case, W1, W3, W3Fault};
use karyos_sim::net::NodeId;

const SEEDS: [u64; 4] = [1, 0xC5, 0x0043, 0xDEAD_BEEF];

thread_local! {
    /// The most entries, and payload bytes, one observed append carried.
    static LARGEST: Cell<(usize, u64)> = const { Cell::new((0, 0)) };
}

/// How a core's messages are read as appends.
trait Shape: ConsensusCore {
    fn shape(message: &Self::Message) -> Option<(usize, u64)>;
}

impl Shape for RaftRsBatch16 {
    fn shape(message: &Self::Message) -> Option<(usize, u64)> {
        raft_rs::append_shape(message)
    }
}

impl Shape for OpenRaftBatch16 {
    fn shape(message: &Self::Message) -> Option<(usize, u64)> {
        openraft_core::append_shape(message)
    }
}

/// A core whose every outgoing append is observed.
#[derive(Debug)]
struct Observed<C>(C);

fn observe<C: Shape>(messages: &[(NodeId, C::Message)]) {
    for (_, message) in messages {
        if let Some((entries, bytes)) = C::shape(message) {
            LARGEST.with(|largest| {
                let (most, heaviest) = largest.get();
                largest.set((most.max(entries), heaviest.max(bytes)));
            });
        }
    }
}

impl<C: Shape> ConsensusCore for Observed<C> {
    type Message = C::Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self(C::recover(id, peers, log))
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        Ok(Self(C::recover_with(id, peers, limits, log)?))
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.0.propose(command, log)
    }

    fn propose_slice(&mut self, command: &[u8], log: &mut LogView<'_>) -> Result<(), Refused> {
        self.0.propose_slice(command, log)
    }

    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>) {
        self.0.step(from, message, log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.0.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        let ready = self.0.ready(log)?;
        observe::<C>(&ready.messages);
        observe::<C>(&ready.after_persist);
        Some(ready)
    }

    fn ready_into(&mut self, out: &mut ReadyBuf<Self::Message>, log: &mut LogView<'_>) -> bool {
        let ready = self.0.ready_into(out, log);
        observe::<C>(&out.ready.messages);
        observe::<C>(&out.ready.after_persist);
        ready
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.0.advance(persisted, log);
    }

    fn term(&self) -> u64 {
        self.0.term()
    }

    fn leads(&self) -> bool {
        self.0.leads()
    }

    fn received(&self) -> Option<u64> {
        self.0.received()
    }

    fn committed(&self) -> Option<u64> {
        self.0.committed()
    }
}

/// W1's allocation case, and W3's returning follower with W1's 32 clients,
/// so that the follower comes back more than 16 entries behind.
fn cases() -> Vec<Case> {
    let w1 = W1::skeleton().cases().into_iter().nth(1).unwrap();
    let w3 = W3::skeleton();
    let mut returning = w3
        .faults
        .iter()
        .zip(w3.cases())
        .find(|(fault, case)| **fault == W3Fault::IsolatedFollowerReturning && case.servers == 3)
        .map(|(_, case)| case)
        .unwrap();
    returning.clients = w1.clients;
    returning.payload = w1.payload;
    vec![w1, returning]
}

fn the_cap_holds<C: Shape>() {
    for (returning, case) in cases()
        .into_iter()
        .enumerate()
        .map(|(at, case)| (at == 1, case))
    {
        LARGEST.with(|largest| largest.set((0, 0)));
        for seed in SEEDS {
            let outcome = workloads::run::<Observed<C>>(&case, seed).unwrap();
            assert_eq!(
                workloads::pass(&case, &outcome),
                Ok(None),
                "{} seed {seed}",
                case.name
            );
        }
        let (most, heaviest) = LARGEST.with(Cell::get);
        assert!(most <= 16, "{}: an append of {most} entries", case.name);
        assert!(
            heaviest <= BATCH_BYTES,
            "{}: an append of {heaviest} payload bytes",
            case.name
        );
        if returning {
            assert_eq!(most, 16, "{}: the cap never bound", case.name);
        }
    }
}

#[test]
fn raft_appends_hold_the_batch_cap() {
    the_cap_holds::<RaftRsBatch16>();
}

#[test]
fn openraft_appends_hold_the_batch_cap() {
    the_cap_holds::<OpenRaftBatch16>();
}
