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
    /// The ticket of the datagram staged last.
    last_ticket: Option<TxTicket>,
}

impl Fixture {
    /// `lanes` lanes of quantum 256 over a guard gate open at epoch 2,
    /// with the publication's `rate` and the default late policy; both
    /// clocks at [`NOW`].
    fn new(lanes: usize, rate: Option<RatePolicy>) -> Self {
        Self::with_policy(lanes, rate, LatePolicy::default())
    }

    /// [`Self::new`] with `policy` on every lane.
    fn with_policy(lanes: usize, rate: Option<RatePolicy>, policy: LatePolicy) -> Self {
        let policies = vec![policy; lanes];
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
                    etf: None,
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
            gate: TimedGate::new(guard, &policies, usize::from(BOUND), NOW),
            word,
            next_token: 1,
            next_position: vec![0; lanes],
            last_ticket: None,
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
            .stage(lane, token, ticket, time, |guard| {
                guard.stage(
                    sender,
                    lane,
                    staged,
                    GateHead {
                        token,
                        length: u64::from(FRAME),
                        messages: 1,
                        start: end - u64::from(FRAME),
                        end,
                    },
                )
            })
            .unwrap();
        self.last_ticket = Some(ticket);
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
    let ticket = f.last_ticket.unwrap();
    let mut ran = false;
    assert_eq!(
        f.gate.stage(0, SenderToken::new(7), ticket, None, |_| {
            ran = true;
            Ok::<(), ()>(())
        }),
        Err(TimedStageError::Full { lane: 0 })
    );
    assert_eq!(
        f.gate
            .stage(5, SenderToken::new(7), ticket, None, |_| Ok::<(), ()>(())),
        Err(TimedStageError::UnknownLane { lane: 5 })
    );
    assert!(!ran);
    assert_eq!(
        f.gate
            .stage(0, SenderToken::new(7), ticket, None, |_| Err(())),
        Err(TimedStageError::Full { lane: 0 })
    );
}

/// The inner gate's refusal leaves the timed record unchanged.
#[test]
fn an_inner_refusal_records_nothing() {
    // A ticket from another endpoint: the refusal never records it.
    let mut other = Fixture::new(1, None);
    other.stage(0, None);
    let ticket = other.last_ticket.unwrap();
    let mut f = Fixture::new(1, None);
    assert_eq!(
        f.gate
            .stage(0, SenderToken::new(7), ticket, Some(PAST), |_| Err(3)),
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

const TOLERANCE: u64 = 10;

fn cancel() -> LatePolicy {
    LatePolicy {
        tolerance: TOLERANCE,
        cancel_on_deadline: true,
        max_horizon: u64::MAX,
    }
}

/// G7: under cancel-on-deadline, a head not exposed by its time plus the
/// tolerance aborts the lane for good, counted once; nothing behind it is
/// exposed, and the one already sent stays sent.
#[test]
fn a_missed_deadline_aborts_the_lane_for_good() {
    let mut f = Fixture::with_policy(1, None, cancel());
    f.stage(0, Some(NOW));
    f.accept(1);
    let report = f.serve(NOW);
    assert_eq!(served(&report, 0), 64);
    let late = f.stage(0, Some(FUTURE));
    let behind = f.stage(0, Some(FUTURE + 1));
    f.accept(2);
    // Past FUTURE + TOLERANCE without exposure: the lane aborts.
    let report = f.serve(FUTURE + TOLERANCE + 1);
    assert_eq!(served(&report, 0), 0);
    assert!(f.gate.deadline_missed(0));
    assert_eq!(f.gate.counts().deadline_aborts, 1);
    assert_eq!(f.gate.counts().sent, 1);
    // For good: probes and exposures stay denied and are not recounted.
    assert!(!f.gate.admits(0));
    assert_eq!(check(&mut f.gate, 0, &[late, behind]), GateDecision::Deny);
    let report = f.serve(FUTURE + 1_000);
    assert_eq!(served(&report, 0), 0);
    assert_eq!(f.gate.counts().deadline_aborts, 1);
    assert_eq!(f.gate.earliest(), None);
}

/// At the boundary, time plus tolerance, a head is neither missed nor
/// late; one nanosecond later it is missed (under cancel) or late (sent).
#[test]
fn the_deadline_boundary_is_not_late() {
    let mut f = Fixture::with_policy(1, None, cancel());
    f.stage(0, Some(NOW));
    f.accept(1);
    let report = f.serve(NOW + TOLERANCE);
    assert_eq!(served(&report, 0), 64);
    assert!(!f.gate.deadline_missed(0));
    assert_eq!(f.gate.counts().late_sends, 0);
    let mut g = Fixture::with_policy(1, None, cancel());
    g.stage(0, Some(NOW));
    g.accept(1);
    let report = g.serve(NOW + TOLERANCE + 1);
    assert_eq!(served(&report, 0), 0);
    assert!(g.gate.deadline_missed(0));
}

/// Without cancel-on-deadline nothing aborts: a head past its tolerance
/// is sent and counted late; one at the boundary is not.
#[test]
fn without_cancel_late_heads_are_sent_and_counted() {
    let policy = LatePolicy {
        tolerance: TOLERANCE,
        cancel_on_deadline: false,
        max_horizon: u64::MAX,
    };
    let mut f = Fixture::with_policy(1, None, policy);
    f.stage(0, Some(NOW));
    f.stage(0, Some(NOW - TOLERANCE));
    f.stage(0, Some(NOW - TOLERANCE - 1));
    f.accept(3);
    let report = f.serve(NOW);
    assert_eq!(served(&report, 0), 192);
    assert!(!f.gate.deadline_missed(0));
    assert_eq!(f.gate.counts().deadline_aborts, 0);
    assert_eq!(f.gate.counts().late_sends, 1);
    assert_eq!(f.gate.counts().sent, 3);
}

/// A head already exposed (the backend keeps it pending) never misses its
/// deadline: it may have been sent.
#[test]
fn an_exposed_head_never_misses() {
    let mut f = Fixture::with_policy(1, None, cancel());
    let token = f.stage(0, Some(NOW));
    assert_eq!(check(&mut f.gate, 0, &[token]), permit(1));
    f.gate.set_now(NOW + TOLERANCE + 100);
    assert_eq!(check(&mut f.gate, 0, &[token]), permit(1));
    assert!(!f.gate.deadline_missed(0));
}

/// ACS 15455: the inner guard gate is not told of a deadline abort; its
/// work in flight, which the close acknowledgement reads, is unchanged.
#[test]
fn a_deadline_abort_leaves_the_inner_work_in_flight() {
    let mut f = Fixture::with_policy(1, None, cancel());
    let sent = f.stage(0, Some(NOW));
    assert_eq!(check(&mut f.gate, 0, &[sent]), permit(1));
    f.stage(0, Some(NOW + 1));
    let before = f.gate.inner().in_flight();
    assert_eq!(before, Some(1));
    f.gate.set_now(NOW + 1 + TOLERANCE + 1);
    assert!(!f.gate.admits(0));
    assert!(f.gate.deadline_missed(0));
    assert_eq!(f.gate.inner().in_flight(), before);
    assert_eq!(f.gate.inner().counts().aborted, 0);
}

/// The step between gates seals a missed lane once, with
/// `DeadlineMissed`; a second step neither reseals nor recounts, and a
/// failed seal is tried again.
#[test]
fn between_gates_seals_a_missed_lane_once() {
    use karyos_sys::log_buffer::{LogBuffer, LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    let buffer = LogBuffer::new(LogBufferConfig {
        term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        spare_slots: 3,
        max_subscribers: 4,
        mtu: DEFAULT_MTU,
        max_reserved: MIN_TERM_LENGTH / 8,
        initial_term_id: TermId::new(7),
        lane: Lane::ZERO,
        session_id: 1,
        stream_id: 2,
        claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
        publication: PublicationMode::Exclusive,
        schedule_capacity: 4,
    })
    .unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut f = Fixture::with_policy(2, None, cancel());
    f.stage(1, Some(NOW));
    let mut calls = Vec::new();
    // Nothing missed yet: nothing sealed.
    f.gate
        .between_gates(|lane| {
            calls.push(lane);
            Ok::<(), SysError>(())
        })
        .unwrap();
    assert!(calls.is_empty());
    f.gate.set_now(NOW + TOLERANCE + 1);
    assert!(!f.gate.admits(1));
    // A failed seal is retried at the next step.
    assert_eq!(f.gate.between_gates(|_| Err(7)), Err(7));
    for _ in 0..2 {
        f.gate
            .between_gates(|lane| {
                calls.push(lane);
                seal_deadline_missed(&mut conductor)
            })
            .unwrap();
    }
    assert_eq!(calls, vec![1]);
    assert_eq!(conductor.seal_reason(), Some(SealReason::DeadlineMissed));
    assert_eq!(f.gate.counts().deadline_aborts, 1);
    // A buffer already sealed keeps its first reason.
    seal_deadline_missed(&mut conductor).unwrap();
    assert_eq!(conductor.seal_reason(), Some(SealReason::DeadlineMissed));
}

/// A buffer sealed for another reason keeps it.
#[test]
fn a_seal_keeps_its_first_reason() {
    use karyos_sys::log_buffer::{LogBuffer, LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    let buffer = LogBuffer::new(LogBufferConfig {
        term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        spare_slots: 3,
        max_subscribers: 4,
        mtu: DEFAULT_MTU,
        max_reserved: MIN_TERM_LENGTH / 8,
        initial_term_id: TermId::new(7),
        lane: Lane::ZERO,
        session_id: 1,
        stream_id: 2,
        claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
        publication: PublicationMode::Exclusive,
        schedule_capacity: 4,
    })
    .unwrap();
    let mut conductor = buffer.conductor().unwrap();
    conductor.seal_with_reason(SealReason::GuardClosed).unwrap();
    seal_deadline_missed(&mut conductor).unwrap();
    assert_eq!(conductor.seal_reason(), Some(SealReason::GuardClosed));
}

fn close_guard(f: &Fixture) {
    let _ = guard::close(f.word.words().first().unwrap()).unwrap();
}

/// G7, close first: the guard closes, then the clock passes the deadline;
/// the lane ends by its guard, and no miss is declared, counted or sealed
/// (#240 review, P2).
#[test]
fn a_deadline_after_a_close_changes_nothing() {
    let mut f = Fixture::with_policy(1, None, cancel());
    let token = f.stage(0, Some(NOW));
    close_guard(&f);
    assert!(!f.gate.admits(0));
    assert!(f.gate.inner().aborting(0));
    f.gate.set_now(NOW + TOLERANCE + 1);
    assert!(!f.gate.admits(0));
    assert_eq!(check(&mut f.gate, 0, &[token]), GateDecision::Deny);
    assert!(!f.gate.deadline_missed(0));
    assert_eq!(f.gate.counts().deadline_aborts, 0);
    let mut sealed = Vec::new();
    f.gate
        .between_gates(|lane| {
            sealed.push(lane);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert!(sealed.is_empty());
    // The lane is aborting either way.
    assert!(f.gate.aborting(0));
}

/// G7, deadline first: the miss is declared, then the guard closes; the
/// miss stays the lane's end, counted once.
#[test]
fn a_close_after_a_miss_keeps_the_miss() {
    let mut f = Fixture::with_policy(1, None, cancel());
    f.stage(0, Some(NOW));
    f.gate.set_now(NOW + TOLERANCE + 1);
    assert!(!f.gate.admits(0));
    assert!(f.gate.deadline_missed(0));
    close_guard(&f);
    assert!(!f.gate.admits(0));
    assert!(f.gate.inner().aborting(0));
    assert!(f.gate.deadline_missed(0));
    assert_eq!(f.gate.counts().deadline_aborts, 1);
    assert!(f.gate.aborting(0));
}

/// The idle wait wakes for a deadline under cancel: a due head not yet
/// exposed waits on its time plus the tolerance; a lane its inner gate
/// aborts waits on nothing (#240 review, P3).
#[test]
fn earliest_includes_the_deadline_under_cancel() {
    let mut f = Fixture::with_policy(1, None, cancel());
    f.stage(0, Some(NOW - 5));
    assert_eq!(f.gate.earliest(), Some(NOW - 5 + TOLERANCE));
    // A future head: its own time comes first.
    let mut g = Fixture::with_policy(1, None, cancel());
    g.stage(0, Some(FUTURE));
    assert_eq!(g.gate.earliest(), Some(FUTURE));
    // Without cancel, a due head waits on nothing.
    let mut h = Fixture::new(1, None);
    h.stage(0, Some(NOW - 5));
    assert_eq!(h.gate.earliest(), None);
    // A closed guard: nothing to wake for.
    close_guard(&f);
    assert!(!f.gate.admits(0));
    assert_eq!(f.gate.earliest(), None);
}

/// A head that leaves with another ticket than the one staged is a fault,
/// counted, and its lateness is not measured (#239 review).
#[test]
fn a_report_with_another_ticket_is_a_fault() {
    let mut f = Fixture::new(1, None);
    f.stage(0, Some(PAST));
    // The second head's ticket, reported for the first.
    f.stage(0, Some(PAST));
    let staged = Staged {
        ticket: f.last_ticket.unwrap(),
        charge: u64::from(FRAME),
        len: FRAME,
    };
    f.gate.left(0, staged, Left::Submitted);
    assert_eq!(f.gate.counts().faults, 1);
    assert_eq!(f.gate.counts().sent, 0);
    assert_eq!(f.gate.counts().max_lateness, None);
}

/// The lateness histogram's buckets: negative, each bound inclusive, and
/// beyond the last bound or beyond `i64`.
#[test]
fn lateness_buckets_are_inclusive() {
    assert_eq!(lateness_bucket(Some(-1)), 0);
    assert_eq!(lateness_bucket(Some(0)), 1);
    assert_eq!(lateness_bucket(Some(1_000)), 1);
    assert_eq!(lateness_bucket(Some(1_001)), 2);
    assert_eq!(lateness_bucket(Some(1_000_000)), 4);
    assert_eq!(lateness_bucket(Some(100_000_000)), 6);
    assert_eq!(lateness_bucket(Some(100_000_001)), 7);
    assert_eq!(lateness_bucket(None), 7);
}

/// A lane's attached cells count its late sends, its deadline abort and
/// the lateness of each submitted timed head (timed-tx.md section 6).
#[test]
fn the_lane_cells_count_lateness_and_aborts() {
    use karyos_sys::counters::{CellRead, CounterKeys, counters};

    let (mut manager, reader) = counters(32).unwrap();
    let mut allocate = |label: &str| manager.allocate_keyed(1, label, CounterKeys::DRIVER).ok();
    let cells = Arc::new(TimedLaneCounters {
        late_sends: allocate("late"),
        deadline_aborts: allocate("aborts"),
        lateness: LATENESS_LABELS.map(&mut allocate),
    });
    let read = |label: &str| {
        (0..reader.capacity())
            .find_map(|index| match reader.read(index) {
                CellRead::Allocated {
                    metadata, value, ..
                } if metadata.label() == label.as_bytes() => Some(value),
                _ => None,
            })
            .unwrap()
    };
    let mut f = Fixture::with_policy(1, None, cancel());
    f.gate.attach_counters(0, Arc::clone(&cells));
    f.stage(0, Some(NOW));
    f.stage(0, Some(NOW + 1));
    f.accept(2);
    // Both sent at NOW + TOLERANCE: lateness 10 and 9, neither late.
    let report = f.serve(NOW + TOLERANCE);
    assert_eq!(served(&report, 0), 128);
    assert_eq!(read(LATENESS_LABELS[1]), 2);
    assert_eq!(read("late"), 0);
    // Without cancel, one sent 2 ms late.
    let mut g = Fixture::new(1, None);
    g.gate.attach_counters(0, Arc::clone(&cells));
    g.stage(0, Some(NOW));
    g.accept(1);
    let report = g.serve(NOW + 2_000_000);
    assert_eq!(served(&report, 0), 64);
    assert_eq!(read("late"), 1);
    assert_eq!(read(LATENESS_LABELS[5]), 1);
    // A miss under cancel counts one abort, once.
    f.stage(0, Some(FUTURE));
    f.gate.set_now(FUTURE + TOLERANCE + 1);
    assert!(!f.gate.admits(0));
    assert!(!f.gate.admits(0));
    assert_eq!(read("aborts"), 1);
}
