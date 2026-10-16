// SPDX-License-Identifier: Apache-2.0

//! Tests of the sockets endpoint against the scripted socket: the rows of
//! `quantstratum-docs: karyos/design/sockets-backend.md` section 12 that
//! need no kernel. Each test is named after its row. On Linux, `loopback`
//! runs the rows that need only a real socket on loopback. Rows that need
//! more are listed, with their batch, in `DEFERRED_ROWS`.

mod lifecycle;
#[cfg(target_os = "linux")]
mod loopback;
mod model;
mod rx;
mod tx;

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::ops::ControlFlow;

use super::*;
use crate::backend::{
    Authority, Commit, Exposure, FlushOutcome, GateDecision, RxDatagram, RxDrop, SenderToken,
    Spent, SubmissionId, TxEntry, TxFrame, TxOptions,
};
use crate::sockets::scripted::ScriptedSocket;

/// Rows of section 12 that need a real socket, kernel or driver beyond
/// Linux loopback, and the batch that covers them. Kept as data so the
/// coverage claim is reviewed with the code. On Linux, `loopback` covers RX
/// oversize, split halves, the round trip, the buffer read back, the
/// unverified path MTU, the unanswered port and multicast loop within one
/// namespace.
const DEFERRED_ROWS: &[(&str, &str)] = &[
    (
        "RX oversize, split halves and loopback round trip on macOS",
        "the macOS std::net batch (portable.rs)",
    ),
    (
        "Multicast between interfaces or namespaces",
        "S4: network namespaces",
    ),
    (
        "Probes (seccomp ENOSYS and EPERM)",
        "S4: container with a seccomp profile",
    ),
    (
        "Path MTU (1280 byte namespace link, MTU shrink)",
        "S4: network namespace",
    ),
    (
        "Repair authority: partly covered here by \
         tx::repair_authority_exposure_carries_the_queue_authority (every \
         exposure carries its queue's authority to the gate); the control \
         class misuse and the incarnation's gate are deferred",
        "driver: the endpoint only carries the queue authority",
    ),
    (
        "Lane order (with aggregate lanes): the backend half is covered \
         here for one queue and for two interleaved queues sharing the pool \
         (model::state_machine_model_and_lane_order, \
         model::two_queue_model_and_lane_order); the aggregate lanes half \
         is deferred",
        "driver: aggregate lanes over several queues",
    ),
];

// "Identity: generation overflow retires the slot" is covered, not
// deferred: tx::identity_generation_overflow_retires_the_slot at the
// endpoint, and the S1 pool and ledger tests
// (backend::pool::identity_generation_overflow_retires_the_slot,
// backend::ledger::claim_error_order_identity_exhausted_only_after_retirement).

/// The deferred rows are named, each with its batch.
#[test]
fn deferred_rows_name_their_batch() {
    assert_eq!(DEFERRED_ROWS.len(), 6);
    assert!(
        DEFERRED_ROWS
            .iter()
            .all(|(row, batch)| !row.is_empty() && !batch.is_empty())
    );
}

pub(super) fn nz(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap()
}

pub(super) fn local() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 7000))
}

pub(super) fn peer() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 7001))
}

/// Small pools: 256 byte datagrams, 8 slots, 4 queues and routes, batches
/// of 8.
pub(super) fn config() -> SocketsConfig {
    let mut config = SocketsConfig::new(local());
    config.max_datagram = nz(256);
    config.tx_slots = nz(8);
    config.max_queues = nz(4);
    config.max_routes = nz(4);
    config.max_batch = nz(8);
    config
}

/// A payload of `len` bytes, each `value`.
pub(super) fn payload(value: u8, len: usize) -> Vec<u8> {
    vec![value; len]
}

/// A gate that records its calls and answers `decision`, or permits every
/// candidate when it is `None`.
#[derive(Debug, Default)]
pub(super) struct Gate {
    pub(super) calls: u32,
    pub(super) decision: Option<GateDecision>,
    /// Authority and tokens of each call.
    pub(super) seen: Vec<(Authority, Vec<u64>)>,
}

impl Gate {
    pub(super) fn deny() -> Self {
        Self {
            decision: Some(GateDecision::Deny),
            ..Self::default()
        }
    }

    pub(super) fn permit(count: u16) -> Self {
        Self {
            decision: Some(GateDecision::Permit { count: nz(count) }),
            ..Self::default()
        }
    }
}

impl SenderGate for Gate {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        self.calls += 1;
        self.seen.push((
            candidate.authority,
            candidate.tokens.iter().map(|token| token.get()).collect(),
        ));
        self.decision.unwrap_or(GateDecision::Permit {
            count: nz(u16::try_from(candidate.tokens.len()).unwrap()),
        })
    }
}

/// An RX handler that records what it is lent.
#[derive(Debug, Default)]
pub(super) struct Recorder {
    pub(super) datagrams: Vec<(Vec<u8>, SocketAddr)>,
    pub(super) drops: Vec<RxDrop>,
    /// `Break` after this many datagrams.
    pub(super) stop_after: Option<usize>,
}

impl RxHandler for Recorder {
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
        self.datagrams
            .push((datagram.bytes().to_vec(), datagram.source()));
        match self.stop_after {
            Some(limit) if self.datagrams.len() >= limit => ControlFlow::Break(()),
            _ => ControlFlow::Continue(()),
        }
    }

    fn dropped(&mut self, drop: RxDrop) {
        self.drops.push(drop);
    }
}

/// Every entry of `report`, oldest first.
pub(super) fn drain(report: &mut TxReport) -> Vec<TxEntry> {
    std::iter::from_fn(|| report.pop_front()).collect()
}

/// An open endpoint split into halves, with one route to [`peer`] and one
/// queue, and an observer of its scripted socket.
pub(super) struct Harness {
    pub(super) tx: SocketsTx<ScriptedSocket>,
    pub(super) rx: SocketsRx<ScriptedSocket>,
    pub(super) socket: ScriptedSocket,
    pub(super) route: RouteId,
    pub(super) queue: TxQueueId,
}

impl Harness {
    pub(super) fn open(config: SocketsConfig, max_pending: u16) -> Self {
        let socket = ScriptedSocket::new();
        let observer = socket.observer();
        let endpoint = SocketsEndpoint::open(&config, InstanceId::FIRST, socket).unwrap();
        let (mut tx, rx) = endpoint.split().unwrap();
        let route = tx.add_route(peer()).unwrap();
        let queue = tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: nz(max_pending),
            })
            .unwrap();
        Self {
            tx,
            rx,
            socket: observer,
            route,
            queue,
        }
    }

    /// The default harness: [`config`], one queue of 8.
    pub(super) fn new() -> Self {
        Self::open(config(), 8)
    }

    /// Claims, fills and commits `bytes` to `queue` with `token`.
    pub(super) fn commit_to(&mut self, queue: TxQueueId, bytes: &[u8], token: u64) -> TxTicket {
        let mut frame = self.tx.claim_tx(queue, bytes.len()).unwrap();
        frame.bytes_mut().copy_from_slice(bytes);
        frame
            .commit(Commit {
                len: bytes.len(),
                token: SenderToken::new(token),
                options: TxOptions::none(),
            })
            .unwrap()
    }

    /// Commits `count` items of 10 bytes, valued and tokened by index from
    /// `first`.
    pub(super) fn commit_n(&mut self, first: u8, count: u8) -> Vec<TxTicket> {
        (first..first + count)
            .map(|index| self.commit_to(self.queue, &payload(index, 10), u64::from(index)))
            .collect()
    }

    /// Flushes `queue` with no datagram or byte limit below the batch.
    pub(super) fn flush_queue<G: SenderGate>(
        &mut self,
        queue: TxQueueId,
        gate: &mut G,
    ) -> (FlushOutcome, Vec<TxEntry>) {
        let mut report = TxReport::new();
        let outcome = self.tx.flush(
            FlushRequest {
                queue,
                max_datagrams: nz(64),
                max_bytes: u32::MAX,
            },
            gate,
            &mut report,
        );
        (outcome, drain(&mut report))
    }

    pub(super) fn flush<G: SenderGate>(&mut self, gate: &mut G) -> (FlushOutcome, Vec<TxEntry>) {
        self.flush_queue(self.queue, gate)
    }

    /// Joins the halves.
    pub(super) fn join(self) -> (SocketsEndpoint<ScriptedSocket>, ScriptedSocket) {
        (
            SocketsEndpoint::join(self.tx, self.rx).unwrap(),
            self.socket,
        )
    }

    /// Joins and retires, returning every pending item.
    pub(super) fn shutdown(self) -> Vec<TxEntry> {
        let (mut endpoint, _socket) = self.join();
        retire_all(&mut endpoint)
    }
}

/// Retires `endpoint`, emptying the report after each call.
pub(super) fn retire_all<O: SocketOps>(endpoint: &mut SocketsEndpoint<O>) -> Vec<TxEntry> {
    let mut report = TxReport::new();
    let mut entries = Vec::new();
    loop {
        let retired = endpoint.retire(&mut report);
        entries.extend(drain(&mut report));
        match retired {
            Retired::More { .. } => {}
            Retired::Complete { .. } => return entries,
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Resets `endpoint` to completion, emptying the report after each call.
pub(super) fn reset_all(endpoint: &mut SocketsEndpoint<ScriptedSocket>) -> Vec<TxEntry> {
    let mut report = TxReport::new();
    let mut entries = Vec::new();
    loop {
        let outcome = endpoint.reset(&mut report);
        assert!(!outcome.report_not_empty);
        entries.extend(drain(&mut report));
        if !outcome.more {
            return entries;
        }
    }
}
