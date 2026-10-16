// SPDX-License-Identifier: Apache-2.0

//! The lane sender over a sockets endpoint and the scripted `SocketOps`
//! (`quantstratum-docs: karyos/design/lane-sender.md`, "What l2 builds").

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;

use karyos_protocol::lanes::drr::Stop;

use super::*;
use crate::backend::{
    Authority, Commit, Exposure, GateDecision, InstanceId, SenderToken, TxFrame, TxOptions,
    TxQueueConfig,
};
use crate::sockets::endpoint::{SocketsConfig, SocketsEndpoint, SocketsTx};
use crate::sockets::ops::SendResult;
use crate::sockets::scripted::ScriptedSocket;

/// Datagrams each lane queue may hold.
const BOUND: u16 = 4;

/// A gate that permits every candidate, except a lane closed to the probe
/// or denied at exposure.
#[derive(Debug, Default)]
struct Gate {
    closed: [bool; 4],
    deny_exposure: bool,
}

impl SenderGate for Gate {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        if self.deny_exposure {
            GateDecision::Deny
        } else {
            GateDecision::Permit {
                count: NonZeroU16::new(u16::try_from(candidate.tokens.len()).unwrap()).unwrap(),
            }
        }
    }
}

impl LaneGate for Gate {
    fn admits(&mut self, lane: usize) -> bool {
        !self.closed[lane]
    }
}

struct Fixture {
    tx: SocketsTx<ScriptedSocket>,
    socket: ScriptedSocket,
    queues: Vec<TxQueueId>,
    route: crate::backend::RouteId,
    sender: LaneSender,
    next_token: u64,
}

impl Fixture {
    /// A sender of `quanta.len()` lanes, each charge at most `max_charge`.
    fn new(quanta: &[u64], max_charge: u64) -> Self {
        let mut config = SocketsConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 7000)));
        config.max_datagram = NonZeroU16::new(256).unwrap();
        config.tx_slots = NonZeroU16::new(16).unwrap();
        config.max_queues = NonZeroU16::new(4).unwrap();
        config.max_routes = NonZeroU16::new(4).unwrap();
        config.max_batch = NonZeroU16::new(8).unwrap();
        let socket = ScriptedSocket::new();
        let observer = socket.observer();
        let endpoint = SocketsEndpoint::open(&config, InstanceId::FIRST, socket).unwrap();
        let (mut tx, _rx) = endpoint.split().unwrap();
        let route = tx
            .add_route(SocketAddr::from((Ipv4Addr::LOCALHOST, 7001)))
            .unwrap();
        let queues: Vec<TxQueueId> = quanta
            .iter()
            .map(|_| {
                tx.open_queue(TxQueueConfig {
                    authority: Authority::FIRST,
                    route,
                    max_pending: NonZeroU16::new(BOUND).unwrap(),
                })
                .unwrap()
            })
            .collect();
        let sender = LaneSender::new(
            DrrConfig::new(quanta, max_charge).unwrap(),
            &queues,
            usize::from(BOUND),
        )
        .unwrap();
        Self {
            tx,
            socket: observer,
            queues,
            route,
            sender,
            next_token: 1,
        }
    }

    /// Commits a datagram of `len` bytes charged `charge` to `lane`.
    fn stage(&mut self, lane: usize, len: u16, charge: u64) -> TxTicket {
        let mut frame = self
            .tx
            .claim_tx(self.queues[lane], usize::from(len))
            .unwrap();
        frame.bytes_mut().fill(u8::try_from(lane).unwrap());
        let ticket = frame
            .commit(Commit {
                len: usize::from(len),
                token: SenderToken::new(self.next_token),
                options: TxOptions::none(),
            })
            .unwrap();
        self.next_token += 1;
        self.sender
            .staged(
                lane,
                Staged {
                    ticket,
                    charge,
                    len,
                },
            )
            .unwrap();
        ticket
    }

    /// The kernel accepts the next `count` single-datagram sends.
    fn accept(&self, count: usize) {
        for _ in 0..count {
            self.socket.push_send(SendResult::Sent {
                sent: 1,
                error: None,
            });
        }
    }

    fn serve(&mut self, gate: &mut Gate, bytes: u64) -> SenderReport {
        self.sender
            .serve(&mut self.tx, gate, Budget { work: 64, bytes })
    }
}

impl Drop for Fixture {
    /// Returns every item still pending: a TX half refuses to be dropped
    /// with pending items.
    fn drop(&mut self) {
        let mut report = TxReport::new();
        for queue in self.queues.clone() {
            while let Ok(outcome) = self.tx.cancel_pending(queue, &mut report) {
                while report.pop_front().is_some() {}
                if !outcome.more {
                    break;
                }
            }
        }
    }
}

fn served(report: &SenderReport) -> [u64; 2] {
    [
        report.drr.lanes[0].served_bytes,
        report.drr.lanes[1].served_bytes,
    ]
}

#[test]
fn backlogged_lanes_are_served_by_their_quanta() {
    let mut f = Fixture::new(&[200, 100], 100);
    for _ in 0..4 {
        f.stage(0, 100, 100);
    }
    for _ in 0..2 {
        f.stage(1, 80, 100);
    }
    f.accept(6);
    let report = f.serve(&mut Gate::default(), 600);
    // Two rounds: lane 0 twice its quantum's worth per round, lane 1 once.
    assert_eq!(served(&report), [400, 200]);
    assert_eq!(report.failure, None);
    assert_eq!(f.socket.send_calls(), 6, "one datagram per flush");
    assert_eq!(
        (f.sender.pending(0), f.sender.pending(1)),
        (Some(0), Some(0))
    );
}

#[test]
fn a_full_or_closed_lane_never_blocks_another() {
    let mut f = Fixture::new(&[100, 100], 100);
    for _ in 0..BOUND {
        f.stage(0, 50, 64);
    }
    // Lane 0's queue and record are full; lane 1 still stages and sends.
    let ticket = f.stage(1, 50, 64);
    assert_eq!(
        f.sender.staged(
            0,
            Staged {
                ticket,
                charge: 64,
                len: 50
            }
        ),
        Err(StageError::Full { lane: 0 })
    );
    f.accept(1);
    let mut gate = Gate::default();
    gate.closed[0] = true;
    let report = f.serve(&mut gate, 1000);
    assert_eq!(served(&report), [0, 64]);
    assert_eq!(f.sender.pending(0), Some(usize::from(BOUND)));
}

/// LS-4: a socket without room stops the call on the next lane: the
/// blocked lane forfeits and no round is counted, so a socket that never
/// has room for one lane's quantum still lets the other lane send.
#[test]
fn persistent_backpressure_still_rotates_the_lanes() {
    let mut f = Fixture::new(&[200, 200], 100);
    for _ in 0..2 {
        f.stage(0, 50, 64);
        f.stage(1, 50, 64);
    }
    // Unscripted sends answer EAGAIN.
    let first = f.serve(&mut Gate::default(), 1000);
    assert_eq!(first.drr.stop, Stop::Backpressure { lane: 0 });
    assert_eq!(first.drr.rounds, 0);
    assert_eq!(first.drr.lanes[0].forfeited, 200);
    assert_eq!(f.socket.send_calls(), 1, "no other lane is tried");
    // The next call starts on lane 1; one send has room.
    f.accept(1);
    let second = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&second), [0, 64]);
    assert_eq!(second.drr.stop, Stop::Backpressure { lane: 1 });
    assert_eq!(
        (f.sender.pending(0), f.sender.pending(1)),
        (Some(2), Some(1))
    );
}

#[test]
fn an_exposure_denied_by_the_gate_is_not_served() {
    let mut f = Fixture::new(&[100, 100], 100);
    f.stage(0, 50, 64);
    let mut gate = Gate {
        deny_exposure: true,
        ..Gate::default()
    };
    let report = f.serve(&mut gate, 1000);
    assert_eq!(served(&report), [0, 0]);
    assert_eq!(report.drr.lanes[0].failed, 1);
    assert_eq!(f.socket.send_calls(), 0);
    assert_eq!(f.sender.pending(0), Some(1));
}

#[test]
fn an_unproven_exposure_suspends_its_lane_and_spends_budget() {
    let mut f = Fixture::new(&[100, 100], 100);
    f.stage(0, 50, 64);
    f.stage(0, 50, 64);
    f.stage(1, 50, 64);
    f.socket.push_send(SendResult::OutOfAbi { proven: 0 });
    f.accept(1);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(report.drr.lanes[0].uncertain_bytes, 64);
    assert_eq!(served(&report), [0, 64]);
    assert_eq!(f.sender.suspended(0), Some(true));
    assert_eq!(report.failure, None, "the other lane goes on");
    // Its next item waits: the lane is never served past the uncertain one
    // (sockets also faulted its queue, which only an endpoint reset
    // clears), while the other lane goes on.
    assert_eq!(f.sender.pending(0), Some(1));
    f.stage(1, 50, 64);
    f.accept(1);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report), [0, 64]);
    assert_eq!(f.sender.pending(0), Some(1));
    assert_eq!(f.socket.send_calls(), 3, "lane 0 was never flushed again");
}

#[test]
fn an_uncertain_charge_counts_against_the_byte_budget() {
    let mut f = Fixture::new(&[100, 100], 100);
    f.stage(0, 50, 64);
    f.stage(1, 50, 64);
    f.socket.push_send(SendResult::OutOfAbi { proven: 0 });
    f.accept(1);
    // 64 uncertain leave 36 bytes, below lane 1's head.
    let report = f.serve(&mut Gate::default(), 100);
    assert_eq!(report.drr.lanes[0].uncertain_bytes, 64);
    assert_eq!(
        report.drr.stop,
        Stop::BytesLimited {
            lane: 1,
            charge: 64
        }
    );
    assert_eq!(served(&report), [0, 0]);
}

#[test]
fn serving_allocates_nothing() {
    let mut f = Fixture::new(&[200, 100], 100);
    for _ in 0..4 {
        f.stage(0, 100, 100);
    }
    f.stage(1, 80, 100);
    f.accept(5);
    let mut gate = Gate::default();
    let (report, allocations) = karyos_sys::alloc_count::count(|| f.serve(&mut gate, 1000));
    assert_eq!(served(&report), [400, 100]);
    assert_eq!(allocations, 0);
}

#[test]
fn a_length_above_its_charge_is_refused() {
    let mut f = Fixture::new(&[100, 100], 100);
    let ticket = f.stage(0, 50, 64);
    assert_eq!(
        f.sender.staged(
            1,
            Staged {
                ticket,
                charge: 40,
                len: 50
            }
        ),
        Err(StageError::LengthAboveCharge {
            len: 50,
            charge: 40
        })
    );
}

/// A lane whose queue the control path closed waits for `reopen`; the
/// other lane goes on, and the reopened lane is served again.
#[test]
fn a_closed_queue_holds_its_lane_until_reopened() {
    let mut f = Fixture::new(&[100, 100], 100);
    f.stage(0, 50, 64);
    f.stage(1, 50, 64);
    let mut report = TxReport::new();
    let closed = f.tx.close_queue(f.queues[0], &mut report);
    assert!(closed.is_ok(), "{closed:?}");
    while report.pop_front().is_some() {}
    f.accept(1);
    let first = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&first), [0, 64]);
    assert_eq!(f.sender.needs_control(0), Some(true));
    let queue =
        f.tx.open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route: f.route,
            max_pending: NonZeroU16::new(BOUND).unwrap(),
        })
        .unwrap();
    f.queues[0] = queue;
    f.sender.reopen(0, queue);
    f.stage(0, 50, 64);
    f.accept(1);
    let second = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&second), [64, 0]);
}

/// Refills every lane's record to its bound with datagrams of `charge`.
fn refill(f: &mut Fixture, lanes: usize, charge: u64) {
    for lane in 0..lanes {
        while f.sender.pending(lane).unwrap() < usize::from(BOUND) {
            f.stage(lane, u16::try_from(charge).unwrap(), charge);
        }
    }
}

/// The lane-sender bound (lane-sender.md): a lane that stays eligible and
/// is credited `k` times is served at least `k * Q - D_max` charged bytes,
/// `D_max` being the largest datagram charge, with the other lanes
/// backlogged.
#[test]
fn a_continuously_eligible_lane_gets_k_quanta_less_d_max() {
    const D_MAX: u64 = 96;
    let quanta = [150, 100];
    let mut f = Fixture::new(&quanta, D_MAX);
    let (mut served_bytes, mut credits) = (0u64, 0u64);
    for call in 0..12u64 {
        refill(&mut f, 2, if call % 2 == 0 { D_MAX } else { 64 });
        f.accept(8);
        // A budget that ends visits at varying points.
        let report = f.serve(&mut Gate::default(), 97 + call * 13);
        served_bytes += report.drr.lanes[0].served_bytes;
        credits += report.drr.lanes[0].credits;
        assert_eq!(report.failure, None);
    }
    assert!(credits >= 4, "lane 0 was visited");
    assert!(
        served_bytes + D_MAX >= credits * quanta[0],
        "{served_bytes} served over {credits} credits"
    );
}

/// The order of the datagrams sent is the DRR's, whatever the split of the
/// work into calls.
#[test]
fn the_send_order_is_the_same_under_any_split_into_calls() {
    let order = |work: u32| -> Vec<u8> {
        let mut f = Fixture::new(&[200, 100, 150], 100);
        for lane in 0..3 {
            for charge in [100, 60, 40, 80] {
                f.stage(lane, u16::try_from(charge).unwrap(), charge);
            }
        }
        f.accept(12);
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = std::sync::Arc::clone(&sent);
        f.socket.set_send_hook(Box::new(move |_, datagrams| {
            record
                .lock()
                .unwrap()
                .extend(datagrams.iter().map(|datagram| datagram[0]));
        }));
        for _ in 0..200 {
            let _ = f.sender.serve(
                &mut f.tx,
                &mut Gate::default(),
                Budget {
                    work,
                    bytes: u64::MAX,
                },
            );
        }
        std::mem::take(&mut *sent.lock().unwrap())
    };
    let whole = order(u32::MAX);
    assert_eq!(whole.len(), 12);
    for work in [1, 2, 3, 5] {
        assert_eq!(order(work), whole, "work {work} per call");
    }
}
