// SPDX-License-Identifier: Apache-2.0

//! The guard gate over a lane sender and the sockets endpoint with the
//! scripted `SocketOps` (G-e2b).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{Ipv4Addr, SocketAddr};

use karyos_io::backend::{
    Authority, BackendEpoch, Commit, InstanceId, RouteId, TxBackend, TxFrame, TxOptions,
    TxQueueConfig, TxQueueId, TxReport,
};
use karyos_io::lanes::{LaneSender, SenderReport};
use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint, SocketsTx};
use karyos_io::sockets::ops::SendResult;
use karyos_io::sockets::scripted::ScriptedSocket;
use karyos_protocol::lanes::drr::{Budget, DrrConfig};
use karyos_sys::rate_limit::Rate;

use super::*;

const SECOND: u64 = 1_000_000_000;
/// Datagrams each lane queue may hold.
const BOUND: u16 = 4;
/// Every frame here: 64 bytes, charged 64.
const FRAME: u16 = 64;

fn rate(per_second: u64, burst: u64) -> RatePolicy {
    RatePolicy {
        messages: Rate { per_second, burst },
        bytes: None,
    }
}

/// A guard word, open at epoch 2.
fn open_guard() -> Arc<HeapWords> {
    let word = Arc::new(HeapWords::zeroed(1));
    let cell = word.words().first().unwrap();
    cell.store(guard::created(), karyos_sys::sync::Ordering::Release);
    assert_eq!(guard::reopen(cell, 1), Ok(2));
    word
}

fn close(word: &HeapWords) {
    let _ = guard::close(word.words().first().unwrap()).unwrap();
}

struct Fixture {
    tx: SocketsTx<ScriptedSocket>,
    socket: ScriptedSocket,
    queues: Vec<TxQueueId>,
    sender: LaneSender,
    gate: GuardGate,
    word: Arc<HeapWords>,
    cell: Arc<AppliedEpoch>,
    next_token: u64,
    /// The next stream position per DRR lane.
    next_position: Vec<u64>,
    /// The sender's record of the last staged frame.
    last: Option<Staged>,
}

impl Fixture {
    /// Lanes of quantum 128, publication lanes 0, 1, ..., bound to epoch 2,
    /// with `rates[i]` for DRR lane `i`.
    fn new(rates: &[Option<RatePolicy>]) -> Self {
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
        let queues: Vec<TxQueueId> = rates
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
        let quanta = vec![128; rates.len()];
        let sender = LaneSender::new(
            DrrConfig::new(&quanta, u64::from(FRAME)).unwrap(),
            &queues,
            usize::from(BOUND),
        )
        .unwrap();
        let word = open_guard();
        let cell = Arc::new(AppliedEpoch::new());
        let lanes: Vec<GateLane> = rates
            .iter()
            .enumerate()
            .map(|(index, rate)| GateLane {
                lane: Lane::try_new(u8::try_from(index).unwrap()).unwrap(),
                epoch: 2,
                rate: *rate,
                bound: usize::from(BOUND),
            })
            .collect();
        let gate = GuardGate::new(Arc::clone(&word), Arc::clone(&cell), &lanes, 0);
        Self {
            tx,
            socket: observer,
            queues,
            sender,
            gate,
            word,
            cell,
            next_token: 1,
            next_position: vec![0; rates.len()],
            last: None,
        }
    }

    /// Commits one first-of-message frame to `lane`, recorded by both the
    /// sender and the gate; returns its token and end position.
    fn stage(&mut self, lane: usize) -> (SenderToken, u64) {
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
        self.sender.staged(lane, staged).unwrap();
        self.last = Some(staged);
        let end = self.next_position[lane] + u64::from(FRAME);
        self.next_position[lane] = end;
        self.gate
            .staged(
                lane,
                GateHead {
                    token,
                    length: u64::from(FRAME),
                    first_of_message: true,
                    end,
                },
            )
            .unwrap();
        (token, end)
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

    fn serve(&mut self, now: u64) -> SenderReport {
        self.gate.set_now(now);
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

/// An exposure of `tokens` on the fixture's route, for direct checks.
fn exposure(tokens: &[SenderToken]) -> (Vec<SenderToken>, Vec<u16>) {
    (tokens.to_vec(), vec![FRAME; tokens.len()])
}

fn check(gate: &mut GuardGate, tokens: &[SenderToken]) -> GateDecision {
    let (tokens, lengths) = exposure(tokens);
    gate.check(&Exposure {
        authority: Authority::FIRST,
        route: RouteId::new(BackendEpoch::FIRST, 0, core::num::NonZeroU32::MIN),
        epoch: BackendEpoch::FIRST,
        tokens: &tokens,
        lengths: &lengths,
    })
}

fn permit(count: u16) -> GateDecision {
    GateDecision::Permit {
        count: NonZeroU16::new(count).unwrap(),
    }
}

#[test]
fn an_open_guard_sends_every_head_and_records_the_positions() {
    let mut f = Fixture::new(&[None, None]);
    f.stage(0);
    let (_, end0) = f.stage(0);
    let (_, end1) = f.stage(1);
    f.accept(3);
    let report = f.serve(0);
    assert_eq!((served(&report, 0), served(&report, 1)), (128, 64));
    assert_eq!(f.gate.last_submitted(Lane::try_new(0).unwrap()), end0);
    assert_eq!(f.gate.last_submitted(Lane::try_new(1).unwrap()), end1);
    assert_eq!(f.gate.counts(), GateCounts::default());
    assert_eq!(f.cell.try_read().unwrap().epoch, 0, "nothing applied");
}

/// Design step 3: a close between two gates stops the exposure, the
/// incarnation aborts for good and the applied epoch is published once,
/// with the last positions submitted under the old epoch.
#[test]
fn a_close_aborts_the_incarnation_and_publishes_the_applied_epoch_once() {
    let mut f = Fixture::new(&[None, None]);
    let (_, sent) = f.stage(0);
    f.accept(1);
    let _ = f.serve(0);
    f.stage(0);
    f.stage(1);
    close(&f.word);
    let report = f.serve(0);
    assert_eq!((served(&report, 0), served(&report, 1)), (0, 0));
    assert_eq!(f.socket.send_calls(), 1, "nothing exposed after the close");
    assert_eq!(
        (f.gate.aborting(0), f.gate.aborting(1)),
        (Some(true), Some(true))
    );
    let applied = f.cell.try_read().unwrap();
    assert_eq!(applied.epoch, 3);
    assert_eq!(applied.positions[0], sent);
    assert_eq!(applied.positions[1], 0);
    // More denials under the same closed epoch publish nothing more.
    let counts = f.gate.counts();
    let _ = f.serve(0);
    assert_eq!(f.gate.counts().applied, 1);
    assert_eq!(f.gate.counts().aborted, 2, "once per incarnation");
    assert!(f.gate.counts().guard_denied > counts.guard_denied);
}

/// The between gates step makes a close effective with nothing pending:
/// the incarnation aborts and the applied epoch is published once, with
/// nothing exposed and no denial counted.
#[test]
fn the_between_gates_step_applies_a_close_without_traffic() {
    let mut f = Fixture::new(&[None]);
    let (_, sent) = f.stage(0);
    f.accept(1);
    let _ = f.serve(0);
    f.gate.between_gates();
    assert_eq!(
        f.gate.aborting(0),
        Some(false),
        "an open guard changes nothing"
    );
    assert_eq!(f.cell.try_read().unwrap().epoch, 0);
    close(&f.word);
    f.gate.between_gates();
    f.gate.between_gates();
    assert_eq!(f.gate.aborting(0), Some(true));
    let applied = f.cell.try_read().unwrap();
    assert_eq!((applied.epoch, applied.positions[0]), (3, sent));
    let counts = f.gate.counts();
    assert_eq!(
        (counts.applied, counts.aborted, counts.guard_denied),
        (1, 1, 0)
    );
}

/// A reopen between two gates does not resume the incarnation: its epoch
/// 2 can never be current again.
#[test]
fn a_reopen_to_a_later_epoch_does_not_resume() {
    let mut f = Fixture::new(&[None]);
    f.stage(0);
    let cell = f.word.words().first().unwrap();
    close(&f.word);
    assert_eq!(guard::reopen(cell, 3), Ok(4));
    f.accept(1);
    let report = f.serve(0);
    assert_eq!(served(&report, 0), 0);
    assert_eq!(f.socket.send_calls(), 0);
    assert_eq!(f.gate.aborting(0), Some(true));
    assert_eq!(f.cell.try_read().unwrap().epoch, 4);
}

/// Rate limits: an empty bucket holds its lane's head in order, the lane
/// forfeits its deficit, the other lane is served, and after a refill the
/// held head goes first.
#[test]
fn a_rate_held_lane_neither_starves_the_others_nor_skips_its_head() {
    let mut f = Fixture::new(&[Some(rate(1, 1)), None]);
    let (_, first) = f.stage(0);
    let (_, held) = f.stage(0);
    f.stage(0);
    for _ in 0..3 {
        f.stage(1);
    }
    f.accept(4);
    let report = f.serve(0);
    assert_eq!(served(&report, 0), 64, "one token: one message");
    assert_eq!(served(&report, 1), 192, "the other lane is served");
    assert!(report.drr.lanes[0].forfeited > 0, "{report:?}");
    assert!(f.gate.counts().rate_held > 0);
    assert_eq!(f.gate.counts().faults, 0, "a held head is not a fault");
    assert_eq!(f.gate.last_submitted(Lane::try_new(0).unwrap()), first);
    // A second earns one token: the held head, not the one after it.
    f.accept(1);
    let report = f.serve(SECOND);
    assert_eq!(served(&report, 0), 64);
    assert_eq!(f.gate.last_submitted(Lane::try_new(0).unwrap()), held);
    assert_eq!(f.sender.pending(0), Some(1));
}

/// Several frames exposed in one batch against a small bucket: only the
/// prefix the bucket pays for is permitted, and a re-exposure of a pending
/// head is not charged again.
#[test]
fn a_batch_is_permitted_only_as_far_as_its_tokens() {
    let mut f = Fixture::new(&[Some(rate(1, 2))]);
    let tokens: Vec<SenderToken> = (0..3).map(|_| f.stage(0).0).collect();
    assert_eq!(check(&mut f.gate, &tokens), permit(2));
    assert_eq!(f.gate.message_tokens(0), Some(0));
    assert_eq!(f.gate.counts().rate_held, 1);
    // The backend kept both pending: exposed again, they are not charged
    // twice, and the third still waits.
    assert_eq!(check(&mut f.gate, &tokens), permit(2));
    assert_eq!(f.gate.message_tokens(0), Some(0));
    assert_eq!(check(&mut f.gate, &tokens[..1]), permit(1));
}

/// A head that left without exposure gets its tokens back; a submitted or
/// unknown one keeps its charge.
#[test]
fn a_returned_head_is_refunded_and_regated_without_a_second_charge() {
    let mut f = Fixture::new(&[Some(rate(1, 2))]);
    let (token, _) = f.stage(0);
    let (second, _) = f.stage(0);
    let staged = f.last.unwrap();
    assert_eq!(check(&mut f.gate, &[token]), permit(1));
    assert_eq!(f.gate.message_tokens(0), Some(1));
    f.gate.left(0, staged, Left::Returned);
    assert_eq!(f.gate.message_tokens(0), Some(2), "refunded");
    // The packetizer stages it again: one charge for its one send.
    f.gate
        .staged(
            0,
            GateHead {
                token,
                length: u64::from(FRAME),
                first_of_message: true,
                end: 192,
            },
        )
        .unwrap();
    assert_eq!(check(&mut f.gate, &[second]), permit(1));
    f.gate.left(0, staged, Left::Unknown);
    assert_eq!(
        f.gate.message_tokens(0),
        Some(1),
        "unknown keeps its charge"
    );
    assert_eq!(check(&mut f.gate, &[token]), permit(1));
    f.gate.left(0, staged, Left::Submitted);
    assert_eq!(f.gate.message_tokens(0), Some(0));
    assert_eq!(f.gate.last_submitted(Lane::try_new(0).unwrap()), 192);
}

/// An exposure that does not start with a lane's head is a sender fault,
/// denied; an abort and a reopen give reserved tokens back.
#[test]
fn faults_are_denied_and_dropped_heads_are_refunded() {
    let mut f = Fixture::new(&[Some(rate(1, 2))]);
    let (token, _) = f.stage(0);
    let (second, _) = f.stage(0);
    assert_eq!(check(&mut f.gate, &[second]), GateDecision::Deny);
    assert_eq!(
        check(&mut f.gate, &[SenderToken::new(99)]),
        GateDecision::Deny
    );
    assert_eq!(
        check(&mut f.gate, &[token, SenderToken::new(99)]),
        permit(1)
    );
    assert_eq!(f.gate.counts().faults, 3);
    assert_eq!(f.gate.message_tokens(0), Some(1));
    f.gate.reopen(0);
    assert_eq!(f.gate.message_tokens(0), Some(2), "a reopen refunds");
    let (token, _) = f.stage(0);
    assert_eq!(check(&mut f.gate, &[token]), permit(1));
    close(&f.word);
    assert_eq!(check(&mut f.gate, &[token]), GateDecision::Deny);
    assert_eq!(f.gate.message_tokens(0), Some(2), "an abort refunds");
}
