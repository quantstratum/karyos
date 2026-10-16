// SPDX-License-Identifier: Apache-2.0

//! The timed gate over the guard gate, a lane sender and the sockets
//! endpoint with the scripted `SocketOps` (P2.11 T1 step 4).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use karyos_client::{HeapWords, SharedWords};
use karyos_io::backend::{
    Authority, BackendEpoch, Commit, InstanceId, RouteId, TxBackend, TxFrame, TxOptions,
    TxQueueConfig, TxQueueId, TxReport,
};
use karyos_io::lanes::{LaneSender, SenderReport};
use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint, SocketsTx};
use karyos_io::sockets::ops::SendResult;
use karyos_io::sockets::scripted::ScriptedSocket;
use karyos_protocol::lanes::drr::{Budget, DrrConfig};
use karyos_sys::applied_epoch::AppliedEpoch;
use karyos_sys::frame::Lane;
use karyos_sys::guard;
use karyos_sys::rate_limit::{Rate, RatePolicy};
use karyos_sys::sync::Ordering;

use super::*;
use crate::guard_gate::{GateHead, GateLane, GuardGate};

/// Datagrams each lane queue may hold.
const BOUND: u16 = 4;
const FRAME: u16 = 64;
const MAX_FRAME: u16 = 256;
const PAST: u64 = 50;
const NOW: u64 = 100;
const FUTURE: u64 = 200;

/// A guard word, open at epoch 2.
fn open_guard() -> Arc<HeapWords> {
    let word = Arc::new(HeapWords::zeroed(1));
    let cell = word.words().first().unwrap();
    cell.store(guard::created(), Ordering::Release);
    assert_eq!(guard::reopen(cell, 1), Ok(2));
    word
}

struct Fixture {
    tx: SocketsTx<ScriptedSocket>,
    socket: ScriptedSocket,
    queues: Vec<TxQueueId>,
    sender: LaneSender,
    gate: TimedGate<GuardGate>,
    word: Arc<HeapWords>,
    next_token: u64,
    next_position: Vec<u64>,
}

impl Fixture {
    /// `lanes` lanes of quantum 256 over a guard gate open at epoch 2,
    /// with the publication's `rate`; both clocks at [`NOW`].
    fn new(lanes: usize, rate: Option<RatePolicy>) -> Self {
        let mut config = SocketsConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 7000)));
        config.max_datagram = NonZeroU16::new(MAX_FRAME).unwrap();
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
        let queues: Vec<TxQueueId> = (0..lanes)
            .map(|_| {
                tx.open_queue(TxQueueConfig {
                    authority: Authority::FIRST,
                    route,
                    max_pending: NonZeroU16::new(BOUND).unwrap(),
                })
                .unwrap()
            })
            .collect();
        let quanta = vec![u64::from(MAX_FRAME); lanes];
        let sender = LaneSender::new(
            DrrConfig::new(&quanta, u64::from(MAX_FRAME)).unwrap(),
            &queues,
            usize::from(BOUND),
        )
        .unwrap();
        let word = open_guard();
        let gate_lanes: Vec<GateLane> = (0..lanes)
            .map(|index| GateLane {
                lane: Lane::try_new(u8::try_from(index).unwrap()).unwrap(),
                epoch: 2,
                bound: usize::from(BOUND),
            })
            .collect();
        let mut guard = GuardGate::new(
            Arc::clone(&word) as Arc<dyn SharedWords>,
            Arc::new(AppliedEpoch::new()),
            &gate_lanes,
            &sender,
            rate,
            u64::from(MAX_FRAME),
            0,
        )
        .unwrap();
        guard.set_now(NOW);
        Self {
            tx,
            socket: observer,
            queues,
            sender,
            gate: TimedGate::new(guard, lanes, usize::from(BOUND), NOW),
            word,
            next_token: 1,
            next_position: vec![0; lanes],
        }
    }

    /// Commits one datagram starting one message requested at `time` to
    /// `lane`, through both gates.
    fn stage(&mut self, lane: usize, time: Option<u64>) -> SenderToken {
        let token = SenderToken::new(self.next_token);
        self.next_token += 1;
        let mut frame = self
            .tx
            .claim_tx(self.queues[lane], usize::from(FRAME))
            .unwrap();
        frame.bytes_mut().fill(u8::try_from(lane).unwrap());
        let ticket = frame
            .commit(Commit {
                len: usize::from(FRAME),
                token,
                options: TxOptions::none(),
            })
            .unwrap();
        let staged = Staged {
            ticket,
            charge: u64::from(FRAME),
            len: FRAME,
        };
        let end = self.next_position[lane] + u64::from(FRAME);
        self.next_position[lane] = end;
        let sender = &mut self.sender;
        self.gate
            .stage(lane, token, time, |guard| {
                guard.stage(
                    sender,
                    lane,
                    staged,
                    GateHead {
                        token,
                        length: u64::from(FRAME),
                        messages: 1,
                        end,
                    },
                )
            })
            .unwrap();
        token
    }

    fn accept(&self, count: usize) {
        for _ in 0..count {
            self.socket.push_send(SendResult::Sent {
                sent: 1,
                error: None,
            });
        }
    }

    fn serve(&mut self, now: u64) -> SenderReport {
        self.gate.set_now(now);
        self.gate.inner_mut().set_now(now);
        self.sender.serve(
            &mut self.tx,
            &mut self.gate,
            Budget {
                work: 64,
                bytes: 10_000,
            },
        )
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

fn served(report: &SenderReport, lane: usize) -> u64 {
    report.drr.lanes[lane].served_bytes
}

fn check<G: LaneGate>(gate: &mut G, lane: usize, tokens: &[SenderToken]) -> GateDecision {
    let lengths = vec![FRAME; tokens.len()];
    gate.flushing(lane);
    gate.check(&Exposure {
        authority: Authority::FIRST,
        route: RouteId::new(BackendEpoch::FIRST, 0, core::num::NonZeroU32::MIN),
        epoch: BackendEpoch::FIRST,
        tokens,
        lengths: &lengths,
    })
}

fn permit(count: u16) -> GateDecision {
    GateDecision::Permit {
        count: NonZeroU16::new(count).unwrap(),
    }
}

/// ACS 15436: a batch of times `[past, past, future]` permits 2; the
/// future one is held, and permitted once its time comes.
#[test]
fn only_the_due_prefix_is_permitted() {
    let mut f = Fixture::new(1, None);
    let tokens = [
        f.stage(0, Some(PAST)),
        f.stage(0, Some(NOW)),
        f.stage(0, Some(FUTURE)),
    ];
    assert_eq!(check(&mut f.gate, 0, &tokens), permit(2));
    assert_eq!(f.gate.counts().held, 1);
    f.gate.set_now(FUTURE);
    assert_eq!(check(&mut f.gate, 0, &tokens), permit(3));
}

/// Through the sender: the due heads go, the future one waits with its
/// lane ineligible, and goes when the clock reaches it; the lateness is
/// measured against the requested time.
#[test]
fn a_future_head_waits_for_its_time() {
    let mut f = Fixture::new(1, None);
    f.stage(0, Some(PAST));
    f.stage(0, Some(PAST));
    f.stage(0, Some(FUTURE));
    f.accept(3);
    let report = f.serve(NOW);
    assert_eq!(served(&report, 0), 128);
    assert_eq!(f.gate.earliest(), Some(FUTURE));
    assert_eq!(f.gate.counts().sent, 2);
    assert_eq!(f.gate.counts().max_lateness, Some(50));
    // Still early: nothing goes.
    let report = f.serve(FUTURE - 1);
    assert_eq!(served(&report, 0), 0);
    let report = f.serve(FUTURE + 7);
    assert_eq!(served(&report, 0), 64);
    assert_eq!(f.gate.earliest(), None);
    assert_eq!(f.gate.counts().sent, 3);
    assert_eq!(f.gate.counts().max_lateness, Some(50));
}

/// A lane waiting for its time does not hold another lane back, and heads
/// that carry no time pass at once.
#[test]
fn a_waiting_lane_does_not_hold_another() {
    let mut f = Fixture::new(2, None);
    f.stage(0, Some(FUTURE));
    f.stage(1, None);
    f.stage(1, Some(PAST));
    f.accept(3);
    let report = f.serve(NOW);
    assert_eq!((served(&report, 0), served(&report, 1)), (0, 128));
    let report = f.serve(FUTURE);
    assert_eq!((served(&report, 0), served(&report, 1)), (64, 0));
    assert_eq!(f.gate.counts().max_lateness, Some(50));
}

/// The inner gate is charged only for the due prefix, and its own permit
/// bounds the timed one: with one message token, `[past, past]` permits 1,
/// and a future head costs no token while it waits.
#[test]
fn the_inner_gate_sees_only_the_due_prefix() {
    let rate = RatePolicy {
        messages: Rate {
            per_second: 1,
            burst: 1,
        },
        bytes: None,
    };
    let mut f = Fixture::new(1, Some(rate));
    let future = [f.stage(0, Some(FUTURE))];
    assert_eq!(check(&mut f.gate, 0, &future), GateDecision::Deny);
    assert_eq!(f.gate.inner().message_tokens(), Some(1), "nothing charged");
    let mut g = Fixture::new(1, Some(rate));
    let tokens = [g.stage(0, Some(PAST)), g.stage(0, Some(PAST))];
    assert_eq!(check(&mut g.gate, 0, &tokens), permit(1));
    assert_eq!(g.gate.inner().message_tokens(), Some(0));
}

/// A guard that closes while a head waits for its time is seen at the
/// next probe: the inner gate is always asked.
#[test]
fn a_close_is_seen_while_a_head_waits() {
    let mut f = Fixture::new(1, None);
    f.stage(0, Some(FUTURE));
    assert!(!f.gate.admits(0));
    let _ = guard::close(f.word.words().first().unwrap()).unwrap();
    assert!(!f.gate.admits(0));
    assert_eq!(f.gate.inner().counts().guard_denied, 1);
    assert!(f.gate.inner().abort_cause(0).is_some());
    f.gate.set_now(FUTURE);
    assert!(!f.gate.admits(0));
}

/// An exposure that is not the lane's next heads, or with no lane
/// flushed, is a fault, denied.
#[test]
fn a_misplaced_exposure_is_a_fault() {
    let mut f = Fixture::new(
        1,
        Some(RatePolicy {
            messages: Rate {
                per_second: 1,
                burst: 1,
            },
            bytes: None,
        }),
    );
    let token = f.stage(0, Some(PAST));
    let other = SenderToken::new(99);
    assert_eq!(check(&mut f.gate, 0, &[other]), GateDecision::Deny);
    assert_eq!(check(&mut f.gate, 0, &[token, token]), GateDecision::Deny);
    assert_eq!(f.gate.counts().faults, 2);
    // No lane flushed.
    let lengths = [FRAME];
    let decision = f.gate.check(&Exposure {
        authority: Authority::FIRST,
        route: RouteId::new(BackendEpoch::FIRST, 0, core::num::NonZeroU32::MIN),
        epoch: BackendEpoch::FIRST,
        tokens: &[token],
        lengths: &lengths,
    });
    assert_eq!(decision, GateDecision::Deny);
    assert_eq!(f.gate.counts().faults, 3);
    // Nothing of a misplaced exposure was charged.
    assert_eq!(f.gate.inner().message_tokens(), Some(1));
}

/// A refused stage records nothing and runs no inner stage.
#[test]
fn a_refused_stage_records_nothing() {
    let mut f = Fixture::new(1, None);
    for _ in 0..BOUND {
        f.stage(0, None);
    }
    let mut ran = false;
    assert_eq!(
        f.gate.stage(0, SenderToken::new(7), None, |_| {
            ran = true;
            Ok::<(), ()>(())
        }),
        Err(TimedStageError::Full { lane: 0 })
    );
    assert_eq!(
        f.gate
            .stage(5, SenderToken::new(7), None, |_| Ok::<(), ()>(())),
        Err(TimedStageError::UnknownLane { lane: 5 })
    );
    assert!(!ran);
    assert_eq!(
        f.gate.stage(0, SenderToken::new(7), None, |_| Err(())),
        Err(TimedStageError::Full { lane: 0 })
    );
}

/// The inner gate's refusal leaves the timed record unchanged.
#[test]
fn an_inner_refusal_records_nothing() {
    let mut f = Fixture::new(1, None);
    assert_eq!(
        f.gate.stage(0, SenderToken::new(7), Some(PAST), |_| Err(3)),
        Err(TimedStageError::Inner(3))
    );
    assert_eq!(f.gate.earliest(), None);
    let token = f.stage(0, Some(FUTURE));
    assert_eq!(f.gate.earliest(), Some(FUTURE));
    f.gate.set_now(FUTURE);
    assert_eq!(check(&mut f.gate, 0, &[token]), permit(1));
}

/// Lateness is signed and checked.
#[test]
fn lateness_is_signed_and_checked() {
    assert_eq!(lateness(10, 3), Some(7));
    assert_eq!(lateness(3, 10), Some(-7));
    assert_eq!(lateness(u64::MAX, 0), None);
    assert_eq!(lateness(0, u64::MAX), None);
}
