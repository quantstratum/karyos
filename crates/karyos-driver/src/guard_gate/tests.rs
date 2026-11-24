// SPDX-License-Identifier: Apache-2.0

//! The guard gate over a lane sender and the sockets endpoint with the
//! scripted `SocketOps` (G-e2b).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{Ipv4Addr, SocketAddr};

use karyos_client::HeapWords;
use karyos_io::backend::{
    Authority, BackendEpoch, Commit, InstanceId, RouteId, TxBackend, TxFrame, TxOptions,
    TxQueueConfig, TxReport,
};
use karyos_io::lanes::SenderReport;
use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint, SocketsTx};
use karyos_io::sockets::ops::SendResult;
use karyos_io::sockets::scripted::ScriptedSocket;
use karyos_protocol::lanes::drr::{Budget, DrrConfig};
use karyos_sys::load_words::LoadWords;
use karyos_sys::rate_limit::Rate;
use karyos_sys::sync::{AtomicU64, Ordering};

use super::*;

const SECOND: u64 = 1_000_000_000;
/// Datagrams each lane queue may hold.
const BOUND: u16 = 4;
/// A datagram here: 64 bytes, charged 64, unless a test stages another.
const FRAME: u16 = 64;
/// The largest datagram and DRR charge here: the route's `max_datagram`.
const MAX_FRAME: u16 = 256;

fn rate(per_second: u64, burst: u64) -> RatePolicy {
    RatePolicy {
        messages: Rate { per_second, burst },
        bytes: None,
    }
}

/// A guard word that counts its Acquire loads.
#[derive(Debug)]
struct CountingWords {
    words: HeapWords,
    acquires: AtomicU64,
}

impl CountingWords {
    fn cell(&self) -> &AtomicU64 {
        self.words.words().first().unwrap()
    }

    fn acquires(&self) -> u64 {
        self.acquires.load(Ordering::Relaxed)
    }
}

impl LoadWords for CountingWords {
    fn len(&self) -> usize {
        self.words.len()
    }

    fn load(&self, index: usize) -> Option<u64> {
        self.words.load(index)
    }

    fn load_acquire(&self, index: usize) -> Option<u64> {
        self.acquires.fetch_add(1, Ordering::Relaxed);
        self.words.load_acquire(index)
    }
}

/// A guard word, open at epoch 2.
fn open_guard() -> Arc<CountingWords> {
    let word = Arc::new(CountingWords {
        words: HeapWords::zeroed(1),
        acquires: AtomicU64::new(0),
    });
    word.cell().store(guard::created(), Ordering::Release);
    assert_eq!(guard::reopen(word.cell(), 1), Ok(2));
    word
}

fn close(word: &CountingWords) {
    let _ = guard::close(word.cell()).unwrap();
}

struct Fixture {
    tx: SocketsTx<ScriptedSocket>,
    socket: ScriptedSocket,
    queues: Vec<TxQueueId>,
    sender: LaneSender,
    gate: GuardGate,
    word: Arc<CountingWords>,
    cell: Arc<AppliedEpoch>,
    next_token: u64,
    /// The next stream position per DRR lane.
    next_position: Vec<u64>,
}

fn gate_lanes(lanes: usize) -> Vec<GateLane> {
    (0..lanes)
        .map(|index| GateLane {
            lane: Lane::try_new(u8::try_from(index).unwrap()).unwrap(),
            epoch: 2,
            bound: usize::from(BOUND),
        })
        .collect()
}

impl Fixture {
    /// `lanes` lanes of quantum 256, publication lanes 0, 1, ..., bound to
    /// epoch 2, sharing the publication's `rate`.
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
        let cell = Arc::new(AppliedEpoch::new());
        let gate = GuardGate::new(
            Arc::clone(&word) as Arc<dyn SharedWords>,
            Arc::clone(&cell),
            &gate_lanes(lanes),
            &sender,
            rate,
            u64::from(MAX_FRAME),
            0,
        )
        .unwrap();
        Self {
            tx,
            socket: observer,
            queues,
            sender,
            gate,
            word,
            cell,
            next_token: 1,
            next_position: vec![0; lanes],
        }
    }

    /// Commits one datagram starting one message to `lane`, through the
    /// gate; returns its token, end position and the sender's record.
    fn stage(&mut self, lane: usize) -> (SenderToken, u64, Staged) {
        self.stage_with(lane, FRAME, 1, None)
    }

    /// [`Self::stage`] with `len` bytes, `messages` messages started and
    /// an optional token of the test's choosing.
    fn stage_with(
        &mut self,
        lane: usize,
        len: u16,
        messages: u64,
        token: Option<u64>,
    ) -> (SenderToken, u64, Staged) {
        let token = SenderToken::new(token.unwrap_or(self.next_token));
        self.next_token += 1;
        let mut frame = self
            .tx
            .claim_tx(self.queues[lane], usize::from(len))
            .unwrap();
        frame.bytes_mut().fill(u8::try_from(lane).unwrap());
        let ticket = frame
            .commit(Commit {
                len: usize::from(len),
                token,
                options: TxOptions::none(),
            })
            .unwrap();
        let staged = Staged {
            ticket,
            charge: u64::from(len),
            len,
        };
        let end = self.next_position[lane] + u64::from(len);
        self.next_position[lane] = end;
        self.gate
            .stage(
                &mut self.sender,
                lane,
                staged,
                GateHead {
                    token,
                    length: u64::from(len),
                    messages,
                    start: end - u64::from(len),
                    end,
                },
            )
            .unwrap();
        (token, end, staged)
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

fn lane(index: u8) -> Lane {
    Lane::try_new(index).unwrap()
}

/// `lane`'s exposure of `tokens`, checked directly.
fn check(gate: &mut GuardGate, lane: usize, tokens: &[SenderToken]) -> GateDecision {
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

#[test]
fn an_open_guard_sends_every_head_and_records_the_positions() {
    let mut f = Fixture::new(2, None);
    f.stage(0);
    let (_, end0, _) = f.stage(0);
    let (_, end1, _) = f.stage(1);
    f.accept(3);
    let report = f.serve(0);
    assert_eq!((served(&report, 0), served(&report, 1)), (128, 64));
    assert_eq!(f.gate.last_submitted(lane(0)), end0);
    assert_eq!(f.gate.last_submitted(lane(1)), end1);
    assert_eq!(
        f.gate.counts(),
        GateCounts {
            checks: 3,
            ..GateCounts::default()
        }
    );
    assert_eq!(f.cell.try_read().unwrap().epoch, 0, "nothing applied");
}

/// Design step 3: a close between two gates stops the exposure, the
/// incarnation aborts for good and the applied epoch is published once,
/// with the last positions submitted under the old epoch; the denial is
/// counted once per incarnation, however often the lane is probed.
#[test]
fn a_close_aborts_the_incarnation_and_publishes_the_applied_epoch_once() {
    let mut f = Fixture::new(2, None);
    let (_, sent, _) = f.stage(0);
    f.accept(1);
    let _ = f.serve(0);
    f.stage(0);
    f.stage(1);
    close(&f.word);
    let report = f.serve(0);
    assert_eq!((served(&report, 0), served(&report, 1)), (0, 0));
    assert_eq!(f.socket.send_calls(), 1, "nothing exposed after the close");
    assert_eq!(f.gate.abort_cause(0), Some(AbortCause::Guard));
    assert_eq!(f.gate.abort_cause(1), Some(AbortCause::Guard));
    let applied = f.cell.try_read().unwrap();
    assert_eq!(applied.epoch, 3);
    assert_eq!(applied.positions[0], sent);
    assert_eq!(applied.positions[1], 0);
    for _ in 0..3 {
        let _ = f.serve(0);
    }
    let counts = f.gate.counts();
    assert_eq!(
        (counts.applied, counts.aborted, counts.guard_denied),
        (1, 2, 2)
    );
}

/// The between gates step makes a close effective with nothing pending:
/// the incarnation aborts and the applied epoch is published once, with
/// nothing exposed and no denial counted.
#[test]
fn the_between_gates_step_applies_a_close_without_traffic() {
    let mut f = Fixture::new(1, None);
    let (_, sent, _) = f.stage(0);
    f.accept(1);
    let _ = f.serve(0);
    f.gate.between_gates();
    assert_eq!(f.gate.abort_cause(0), None, "an open guard changes nothing");
    assert_eq!(f.cell.try_read().unwrap().epoch, 0);
    close(&f.word);
    f.gate.between_gates();
    f.gate.between_gates();
    assert_eq!(f.gate.abort_cause(0), Some(AbortCause::Guard));
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
    let mut f = Fixture::new(1, None);
    f.stage(0);
    close(&f.word);
    assert_eq!(guard::reopen(f.word.cell(), 3), Ok(4));
    f.accept(1);
    let report = f.serve(0);
    assert_eq!(served(&report, 0), 0);
    assert_eq!(f.socket.send_calls(), 0);
    assert_eq!(f.gate.abort_cause(0), Some(AbortCause::Guard));
    assert_eq!(f.cell.try_read().unwrap().epoch, 4);
}

/// The single Acquire load per probe and per check, pinned.
#[test]
fn each_probe_and_check_loads_the_guard_once() {
    let mut f = Fixture::new(1, None);
    let (token, _, _) = f.stage(0);
    let before = f.word.acquires();
    assert!(f.gate.admits(0));
    assert_eq!(f.word.acquires(), before + 1);
    assert_eq!(check(&mut f.gate, 0, &[token]), permit(1));
    assert_eq!(f.word.acquires(), before + 2);
    // An aborting lane is refused without a load.
    close(&f.word);
    assert!(!f.gate.admits(0));
    assert!(!f.gate.admits(0));
    assert_eq!(f.word.acquires(), before + 3);
}

/// The bucket is the publication's, shared by its lanes (ACS 15344): with
/// it empty every lane is held in order, each refill lets one message
/// through, and no lane ever skips its own head.
#[test]
fn an_empty_bucket_holds_every_lane_in_order() {
    let mut f = Fixture::new(2, Some(rate(1, 1)));
    let mut ends = [Vec::new(), Vec::new()];
    for lane in [0, 1, 0, 1] {
        ends[lane].push(f.stage(lane).1);
    }
    f.accept(4);
    let mut sent = [0usize; 2];
    for second in 0..4 {
        let report = f.serve(second * SECOND);
        assert_eq!(
            served(&report, 0) + served(&report, 1),
            64,
            "one token, one message, at second {second}"
        );
        for index in 0..2u8 {
            let last = f.gate.last_submitted(lane(index));
            let at = usize::from(index);
            // Each lane's submissions are its heads in order.
            let count = ends[at]
                .iter()
                .position(|&end| end == last)
                .map_or(0, |found| found + 1);
            assert!(
                count == sent[at] || count == sent[at] + 1,
                "lane {index} skipped"
            );
            sent[at] = count;
        }
    }
    assert_eq!(sent, [2, 2]);
    assert!(f.gate.counts().rate_held > 0);
    assert_eq!(f.gate.counts().faults, 0, "a held head is not a fault");
}

/// A head the bucket cannot pay for holds its lane, which forfeits its
/// deficit, while another lane whose head fits is served; after a refill
/// the held head goes first.
#[test]
fn a_held_lane_does_not_starve_another() {
    let policy = RatePolicy {
        messages: Rate {
            per_second: 1000,
            burst: 1000,
        },
        bytes: Some(Rate {
            per_second: u64::from(MAX_FRAME),
            burst: u64::from(MAX_FRAME),
        }),
    };
    let mut f = Fixture::new(2, Some(policy));
    // Lane 0 sends a small datagram, which leaves it deficit, then holds a
    // full-size one the 192 bytes left cannot pay for.
    let (_, small, _) = f.stage(0);
    let (_, held, _) = f.stage_with(0, MAX_FRAME, 1, None);
    f.stage(1);
    let (_, other, _) = f.stage(1);
    f.accept(4);
    let report = f.serve(0);
    assert_eq!((served(&report, 0), served(&report, 1)), (64, 128));
    assert!(report.drr.lanes[0].forfeited > 0, "{report:?}");
    assert_eq!(f.gate.last_submitted(lane(0)), small);
    assert_eq!(f.gate.last_submitted(lane(1)), other);
    assert!(f.gate.counts().rate_held > 0);
    // A second refills the bytes: the held head goes.
    let report = f.serve(SECOND);
    assert_eq!(served(&report, 0), u64::from(MAX_FRAME));
    assert_eq!(f.gate.last_submitted(lane(0)), held);
}

/// A rate-held lane is ineligible at the probe: it is never flushed.
#[test]
fn a_rate_held_lane_is_never_flushed() {
    let mut f = Fixture::new(1, Some(rate(1, 1)));
    f.stage(0);
    f.stage(0);
    f.accept(2);
    let _ = f.serve(0);
    let (checks, sends) = (f.gate.counts().checks, f.socket.send_calls());
    assert_eq!((checks, sends), (1, 1));
    for _ in 0..3 {
        let report = f.serve(0);
        assert_eq!(served(&report, 0), 0);
    }
    assert_eq!(f.gate.counts().checks, checks, "no flush, so no exposure");
    assert_eq!(f.socket.send_calls(), sends);
}

/// Review of #221 (P2-1): tokens need not be unique across lanes. With the
/// same token at two lanes' heads and one message token, one datagram goes,
/// charged to the lane flushed, and no fault.
#[test]
fn the_flushed_lane_places_an_exposure_whatever_its_tokens() {
    let mut f = Fixture::new(2, Some(rate(1, 1)));
    f.stage_with(0, FRAME, 1, Some(7));
    f.stage_with(1, FRAME, 1, Some(7));
    f.stage_with(1, FRAME, 1, Some(8));
    f.accept(3);
    let report = f.serve(0);
    assert_eq!(served(&report, 0) + served(&report, 1), 64, "{report:?}");
    assert_eq!(f.socket.send_calls(), 1);
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(f.gate.counts().faults, 0);
}

/// Review of #221 (P2-2): a datagram that starts several messages costs a
/// message token each; it waits until the bucket holds them all.
#[test]
fn a_datagram_pays_for_every_message_it_starts() {
    let mut f = Fixture::new(1, Some(rate(1, 2)));
    let (token, _, _) = f.stage_with(0, FRAME, 2, None);
    let (later, _, _) = f.stage_with(0, FRAME, 2, None);
    assert_eq!(check(&mut f.gate, 0, &[token, later]), permit(1));
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert!(f.gate.admits(0), "a charged pending head may go again");
    // A second earns one token: not enough for a datagram of two.
    f.gate.set_now(SECOND);
    assert_eq!(check(&mut f.gate, 0, &[token, later]), permit(1));
    assert_eq!(f.gate.message_tokens(), Some(1));
    f.gate.set_now(2 * SECOND);
    assert_eq!(check(&mut f.gate, 0, &[token, later]), permit(2));
    assert_eq!(f.gate.message_tokens(), Some(0));
}

/// Several datagrams exposed in one batch against a small bucket: only the
/// prefix the bucket pays for is permitted, and a re-exposure of a pending
/// head is not charged again.
#[test]
fn a_batch_is_permitted_only_as_far_as_its_tokens() {
    let mut f = Fixture::new(1, Some(rate(1, 2)));
    let tokens: Vec<SenderToken> = (0..3).map(|_| f.stage(0).0).collect();
    assert_eq!(check(&mut f.gate, 0, &tokens), permit(2));
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(f.gate.counts().rate_held, 1);
    // The backend kept both pending: exposed again, they are not charged
    // twice, and the third still waits.
    assert_eq!(check(&mut f.gate, 0, &tokens), permit(2));
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(check(&mut f.gate, 0, &tokens[..1]), permit(1));
}

/// A head that left without exposure gets its tokens back; a submitted or
/// unknown one keeps its charge.
#[test]
fn a_returned_head_is_refunded_and_a_submitted_one_kept() {
    let mut f = Fixture::new(1, Some(rate(1, 2)));
    let (token, _, staged) = f.stage(0);
    let (second, _, second_staged) = f.stage(0);
    let (third, end, third_staged) = f.stage(0);
    assert_eq!(check(&mut f.gate, 0, &[token]), permit(1));
    assert_eq!(f.gate.message_tokens(), Some(1));
    f.gate.left(0, staged, Left::Returned);
    assert_eq!(f.gate.message_tokens(), Some(2), "refunded");
    assert_eq!(check(&mut f.gate, 0, &[second]), permit(1));
    f.gate.left(0, second_staged, Left::Unknown);
    assert_eq!(f.gate.message_tokens(), Some(1), "unknown keeps its charge");
    assert_eq!(check(&mut f.gate, 0, &[third]), permit(1));
    f.gate.left(0, third_staged, Left::Submitted);
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(f.gate.last_submitted(lane(0)), end);
    assert_eq!(f.gate.counts().faults, 0);
}

/// Sender faults: an exposure the gate cannot place, or that contradicts
/// the lane's heads, is denied; a contradiction is terminal for the lane,
/// counted once, and gives its reserved tokens back.
#[test]
fn a_contradicted_exposure_is_terminal_for_its_lane() {
    let mut f = Fixture::new(2, Some(rate(1, 2)));
    let (token, _, _) = f.stage(0);
    let (other, _, _) = f.stage(1);
    // No flushing lane: unplaced, but no lane to blame.
    let lengths = [FRAME];
    let exposure = Exposure {
        authority: Authority::FIRST,
        route: RouteId::new(BackendEpoch::FIRST, 0, core::num::NonZeroU32::MIN),
        epoch: BackendEpoch::FIRST,
        tokens: &[token],
        lengths: &lengths,
    };
    assert_eq!(f.gate.check(&exposure), GateDecision::Deny);
    assert_eq!(f.gate.counts().faults, 1);
    assert_eq!(f.gate.abort_cause(0), None);
    // Lane 0's head charged, then a candidate that is not its next head.
    assert_eq!(
        check(&mut f.gate, 0, &[token, SenderToken::new(99)]),
        GateDecision::Deny
    );
    assert_eq!(f.gate.abort_cause(0), Some(AbortCause::Fault));
    assert_eq!(f.gate.message_tokens(), Some(2), "nothing stays reserved");
    assert_eq!(f.gate.counts().faults, 2);
    assert!(!f.gate.admits(0));
    assert_eq!(check(&mut f.gate, 0, &[token]), GateDecision::Deny);
    assert_eq!(f.gate.counts().faults, 2, "terminal, not one per cycle");
    // The other lane goes on.
    assert_eq!(check(&mut f.gate, 1, &[other]), permit(1));
}

/// A report that does not match the gate's head is a fault, terminal for
/// the lane; a report on an empty record is counted.
#[test]
fn a_report_out_of_step_is_a_fault() {
    let mut f = Fixture::new(2, None);
    let (_, _, staged) = f.stage(0);
    let (_, _, other) = f.stage(1);
    f.gate.left(0, other, Left::Submitted);
    assert_eq!(f.gate.abort_cause(0), Some(AbortCause::Fault));
    assert_eq!(f.gate.counts().faults, 1);
    f.gate.left(0, staged, Left::Submitted);
    assert_eq!(f.gate.counts().faults, 2, "nothing recorded any more");
    assert_eq!(f.gate.last_submitted(lane(0)), 0);
}

/// The gate and the sender stay paired: lane counts at construction,
/// records at each stage, and a reopen of both that refunds.
#[test]
fn the_gate_and_its_sender_stay_paired() {
    let mut f = Fixture::new(2, Some(rate(1, 2)));
    let other = GuardGate::new(
        Arc::clone(&f.word) as Arc<dyn SharedWords>,
        Arc::new(AppliedEpoch::new()),
        &gate_lanes(3),
        &f.sender,
        None,
        u64::from(MAX_FRAME),
        0,
    );
    assert_eq!(other.err(), Some(GateError::LaneCount { gate: 3 }));
    // A record the gate did not make puts the lane out of step.
    let mut frame = f.tx.claim_tx(f.queues[0], usize::from(FRAME)).unwrap();
    frame.bytes_mut().fill(0);
    let ticket = frame
        .commit(Commit {
            len: usize::from(FRAME),
            token: SenderToken::new(50),
            options: TxOptions::none(),
        })
        .unwrap();
    let staged = Staged {
        ticket,
        charge: u64::from(FRAME),
        len: FRAME,
    };
    f.sender.staged(0, staged).unwrap();
    let head = GateHead {
        token: SenderToken::new(51),
        length: u64::from(FRAME),
        messages: 1,
        start: 0,
        end: 64,
    };
    assert_eq!(
        f.gate.stage(&mut f.sender, 0, staged, head),
        Err(GateStageError::OutOfStep { lane: 0 })
    );
    // A reopen of both clears both and refunds what was reserved.
    let (token, _, _) = f.stage(1);
    assert_eq!(check(&mut f.gate, 1, &[token]), permit(1));
    assert_eq!(f.gate.message_tokens(), Some(1));
    let mut report = TxReport::new();
    while let Ok(outcome) = f.tx.cancel_pending(f.queues[1], &mut report) {
        while report.pop_front().is_some() {}
        if !outcome.more {
            break;
        }
    }
    let queue = f.queues[1];
    f.gate.reopen(&mut f.sender, 1, queue, false);
    assert_eq!(f.gate.message_tokens(), Some(2), "a reopen refunds");
    assert_eq!(f.sender.pending(1), Some(0));
    f.stage(1);
}

/// The byte burst must hold the route's largest datagram (P2-2).
#[test]
fn a_policy_is_validated_against_the_largest_datagram() {
    let f = Fixture::new(1, None);
    let policy = RatePolicy {
        messages: Rate {
            per_second: 10,
            burst: 1,
        },
        bytes: Some(Rate {
            per_second: 1000,
            burst: u64::from(MAX_FRAME) - 1,
        }),
    };
    let refused = GuardGate::new(
        Arc::clone(&f.word) as Arc<dyn SharedWords>,
        Arc::new(AppliedEpoch::new()),
        &gate_lanes(1),
        &f.sender,
        Some(policy),
        u64::from(MAX_FRAME),
        0,
    );
    assert_eq!(
        refused.err(),
        Some(GateError::InvalidRatePolicy(
            RatePolicyError::BurstBelowFrame {
                burst: u64::from(MAX_FRAME) - 1,
                frame: u64::from(MAX_FRAME),
            }
        ))
    );
}

/// G-e4 (DN-7): the gate counts its work in flight, exposed heads not yet
/// left and unproven ones until a reopen, publishes it with the applied
/// epoch, and again from the between gates step as it drains.
#[test]
fn the_work_in_flight_is_published_as_it_drains() {
    let mut f = Fixture::new(1, None);
    let (token, _, staged) = f.stage(0);
    let (second, _, second_staged) = f.stage(0);
    assert_eq!(f.gate.in_flight(), Some(0), "staged is not exposed");
    assert_eq!(check(&mut f.gate, 0, &[token, second]), permit(2));
    assert_eq!(f.gate.in_flight(), Some(2));
    close(&f.word);
    f.gate.between_gates();
    let applied = f.cell.try_read().unwrap();
    assert_eq!((applied.epoch, applied.in_flight), (3, 2));
    f.gate.left(0, staged, Left::Submitted);
    f.gate.left(0, second_staged, Left::Unknown);
    assert_eq!(f.gate.in_flight(), Some(1), "unknown stays in flight");
    f.gate.between_gates();
    assert_eq!(f.cell.try_read().unwrap().in_flight, 1);
    let queue = f.queues[0];
    let mut report = TxReport::new();
    while let Ok(outcome) = f.tx.cancel_pending(queue, &mut report) {
        while report.pop_front().is_some() {}
        if !outcome.more {
            break;
        }
    }
    f.gate.reopen(&mut f.sender, 0, queue, false);
    f.gate.between_gates();
    let drained = f.cell.try_read().unwrap();
    assert_eq!((drained.epoch, drained.in_flight), (3, 0));
    assert_eq!(f.gate.counts().applied, 1, "one epoch applied, republished");
}

/// Review of #227 (P2-2): a report that contradicts the gate's head leaves
/// that item's fate unknown, so it stays in flight until a reopen.
#[test]
fn a_contradicted_report_stays_in_flight_until_a_reopen() {
    let mut f = Fixture::new(2, None);
    let (token, _, _) = f.stage(0);
    let (_, _, other) = f.stage(1);
    assert_eq!(check(&mut f.gate, 0, &[token]), permit(1));
    assert_eq!(f.gate.in_flight(), Some(1));
    f.gate.left(0, other, Left::Submitted);
    assert_eq!(f.gate.abort_cause(0), Some(AbortCause::Fault));
    assert_eq!(f.gate.in_flight(), Some(1), "not counted as settled");
    let queue = f.queues[0];
    let mut report = TxReport::new();
    while let Ok(outcome) = f.tx.cancel_pending(queue, &mut report) {
        while report.pop_front().is_some() {}
        if !outcome.more {
            break;
        }
    }
    f.gate.reopen(&mut f.sender, 0, queue, false);
    assert_eq!(f.gate.in_flight(), Some(0));
}

impl Fixture {
    /// The walker's submission frontier, published by the gate from now on.
    fn frontier(&mut self) -> Arc<SubmissionFrontier> {
        let frontier = Arc::new(SubmissionFrontier::new());
        self.gate.set_frontier(Arc::clone(&frontier));
        frontier
    }

    /// An endpoint reset of `lane`'s queue: the backend returns what it
    /// held, and the gate reopens it, `rewound` or not.
    fn reset(&mut self, lane: usize, rewound: bool) {
        let queue = self.queues[lane];
        let mut report = TxReport::new();
        while let Ok(outcome) = self.tx.cancel_pending(queue, &mut report) {
            while report.pop_front().is_some() {}
            if !outcome.more {
                break;
            }
        }
        self.gate.reopen(&mut self.sender, lane, queue, rewound);
    }
}

use karyos_sys::submission_frontier::{Final, Frontier, SubmissionFrontier};

fn at(resolved: u64, unknown_hi: u64, sent_hi: u64, staged_hi: u64) -> Frontier {
    Frontier {
        resolved,
        unknown_hi,
        sent_hi,
        staged_hi,
    }
}

/// Records plan v2 (s-88's review): the frontier is prefix-closed. A head
/// whose exposure is unknown stays a hole below a later submitted one:
/// `resolved` passes both, `unknown_hi` covers the first.
#[test]
fn an_unknown_head_below_a_later_submission_stays_unknown() {
    let mut f = Fixture::new(1, None);
    let frontier = f.frontier();
    let (first, first_end, first_staged) = f.stage(0);
    let (second, second_end, second_staged) = f.stage(0);
    assert_eq!(check(&mut f.gate, 0, &[first, second]), permit(2));
    f.gate.between_gates();
    assert_eq!(
        frontier.read(lane(0)),
        (Final::Open, at(0, 0, 0, second_end))
    );
    f.gate.left(0, first_staged, Left::Unknown);
    f.gate.left(0, second_staged, Left::Submitted);
    f.gate.between_gates();
    assert_eq!(
        frontier.read(lane(0)),
        (
            Final::Open,
            at(second_end, first_end, second_end, second_end)
        )
    );
    // `submitted` is the max the acknowledgement used to carry.
    assert_eq!(f.gate.last_submitted(lane(0)), second_end);
}

/// A reset keeps an unknown head unknown: the reopen settles the in-flight
/// count, never the frontier. An exposure the reset cut short may have
/// left too, even when the lane rewinds.
#[test]
fn a_reset_never_unsends_what_may_have_left() {
    let mut f = Fixture::new(1, None);
    let frontier = f.frontier();
    let (first, first_end, first_staged) = f.stage(0);
    let (second, second_end, _) = f.stage(0);
    assert_eq!(check(&mut f.gate, 0, &[first, second]), permit(2));
    f.gate.left(0, first_staged, Left::Unknown);
    f.reset(0, true);
    f.gate.between_gates();
    assert_eq!(f.gate.in_flight(), Some(0));
    let (_, read) = frontier.read(lane(0));
    assert_eq!(read.unknown_hi, second_end, "the cut exposure");
    assert!(read.unknown_hi > first_end);
    assert_eq!(read.resolved, second_end);
}

/// A rewound reset: what it returned unexposed is staged again, so it holds
/// the frontier until a copy of it is submitted; without the rewind it is a
/// hole no first send fills, `Unknown` (decision 1 of the records plan).
#[test]
fn a_rewound_reset_holds_its_returned_heads_until_they_go_again() {
    for rewound in [true, false] {
        let mut f = Fixture::new(1, None);
        let frontier = f.frontier();
        let (first, first_end, first_staged) = f.stage(0);
        let _ = f.stage(0);
        let (_, third_end, _) = f.stage(0);
        assert_eq!(check(&mut f.gate, 0, &[first]), permit(1));
        f.gate.left(0, first_staged, Left::Submitted);
        f.reset(0, rewound);
        f.gate.between_gates();
        if !rewound {
            assert_eq!(
                frontier.read(lane(0)).1,
                at(third_end, third_end, third_end, third_end)
            );
            continue;
        }
        assert_eq!(
            frontier.read(lane(0)).1,
            at(first_end, 0, first_end, third_end)
        );
        // Read again from the first returned head, and sent.
        f.next_position[0] = first_end;
        let (second, _, second_staged) = f.stage(0);
        let (third, _, third_staged) = f.stage(0);
        f.gate.between_gates();
        assert_eq!(frontier.read(lane(0)).1.resolved, first_end);
        assert_eq!(check(&mut f.gate, 0, &[second, third]), permit(2));
        f.gate.left(0, second_staged, Left::Submitted);
        f.gate.left(0, third_staged, Left::Submitted);
        f.gate.between_gates();
        assert_eq!(
            frontier.read(lane(0)).1,
            at(third_end, 0, third_end, third_end)
        );
    }
}

/// A close finishes the lane once no exposure is unreported: what was
/// staged and never exposed stays above `resolved`, and the walker aborts
/// it. The acknowledgement's position is `resolved` (decision D).
#[test]
fn a_close_finishes_the_lane_once_its_exposures_are_reported() {
    let mut f = Fixture::new(1, None);
    let frontier = f.frontier();
    let (first, first_end, first_staged) = f.stage(0);
    let (second, second_end, second_staged) = f.stage(0);
    let (_, third_end, _) = f.stage(0);
    assert_eq!(check(&mut f.gate, 0, &[first]), permit(1));
    f.gate.left(0, first_staged, Left::Submitted);
    assert_eq!(check(&mut f.gate, 0, &[second]), permit(1));
    close(&f.word);
    f.gate.between_gates();
    assert_eq!(frontier.read(lane(0)).0, Final::Open, "one unreported");
    f.gate.left(0, second_staged, Left::Submitted);
    f.gate.between_gates();
    assert_eq!(
        frontier.read(lane(0)),
        (
            Final::Finished {
                reason: REASON_GUARD_CLOSED
            },
            at(second_end, 0, second_end, third_end)
        )
    );
    assert_eq!(f.cell.try_read().unwrap().positions[0], second_end);
    assert!(first_end < second_end);
}

/// A removal is final at once: an exposure not reported yet may have left,
/// so it is `Unknown`; what was never exposed is aborted.
#[test]
fn a_removal_makes_an_unreported_exposure_unknown() {
    let mut f = Fixture::new(1, None);
    let frontier = f.frontier();
    let (first, first_end, first_staged) = f.stage(0);
    let (second, second_end, _) = f.stage(0);
    let (_, third_end, _) = f.stage(0);
    assert_eq!(check(&mut f.gate, 0, &[first, second]), permit(2));
    f.gate.left(0, first_staged, Left::Submitted);
    f.gate.finish_removed();
    assert_eq!(
        frontier.read(lane(0)),
        (
            Final::Finished {
                reason: REASON_DRIVER_SHUTDOWN
            },
            at(first_end, second_end, second_end, third_end)
        )
    );
}

/// Positions read and never staged (a failed commit) are a gap no first
/// send covers: `Unknown`, never `Submitted`.
#[test]
fn a_gap_in_the_staged_positions_is_unknown() {
    let mut f = Fixture::new(1, None);
    let frontier = f.frontier();
    let (first, first_end, first_staged) = f.stage(0);
    f.next_position[0] += u64::from(FRAME);
    let (second, second_end, second_staged) = f.stage(0);
    assert_eq!(check(&mut f.gate, 0, &[first, second]), permit(2));
    f.gate.left(0, first_staged, Left::Submitted);
    f.gate.left(0, second_staged, Left::Submitted);
    f.gate.between_gates();
    assert_eq!(
        frontier.read(lane(0)).1,
        at(
            second_end,
            second_end - u64::from(FRAME),
            second_end,
            second_end
        )
    );
    assert!(first_end < second_end - u64::from(FRAME));
}

/// A contradicted report leaves nothing the lane staged trusted as unsent:
/// `unknown_hi` reaches its highest staged end, and the faulted lane, whose
/// contradicted head left its ring, is finished; a reset changes neither.
#[test]
fn a_contradiction_makes_the_lane_unknown_and_finishes_it() {
    let mut f = Fixture::new(2, None);
    let frontier = f.frontier();
    let (token, _, _) = f.stage(0);
    let (_, end, _) = f.stage(0);
    let (_, _, other) = f.stage(1);
    assert_eq!(check(&mut f.gate, 0, &[token]), permit(1));
    f.gate.left(0, other, Left::Submitted);
    f.gate.between_gates();
    let faulted = (
        Final::Finished {
            reason: REASON_PUBLICATION_FAULT,
        },
        at(end - u64::from(FRAME), end, end, end),
    );
    assert_eq!(frontier.read(lane(0)), faulted);
    f.reset(0, false);
    f.gate.between_gates();
    assert_eq!(frontier.read(lane(0)), faulted);
    assert_eq!(frontier.read(lane(1)).0, Final::Open);
}

/// R-CORE-21: the gate applies a newer policy the driver published at its
/// next `set_now`, earning the old rate up to then and clamping its level
/// to the new burst; an older or equal version, or a publication in
/// progress, changes nothing.
#[test]
fn the_gate_applies_a_newer_published_policy_at_its_next_serve() {
    use karyos_sys::rate_policy_slot::{SLOT_WORDS, publish};

    let mut f = Fixture::new(1, Some(rate(10, 8)));
    let slot = Arc::new(HeapWords::zeroed(SLOT_WORDS));
    f.gate
        .set_policy_slot(Arc::clone(&slot) as Arc<dyn SharedWords>);
    f.gate.set_now(0);
    assert_eq!(
        (f.gate.policy_version(), f.gate.message_tokens()),
        (0, Some(8))
    );
    publish(slot.words(), 0, 2, &rate(5, 3));
    f.gate.set_now(1);
    assert_eq!(
        (f.gate.policy_version(), f.gate.message_tokens()),
        (2, Some(3))
    );
    // Not newer: ignored.
    publish(slot.words(), 0, 2, &rate(1, 1));
    f.gate.set_now(2);
    assert_eq!(
        (f.gate.policy_version(), f.gate.message_tokens()),
        (2, Some(3))
    );
    // A publication in progress (an odd sequence) waits for the next call.
    publish(slot.words(), 0, 3, &rate(1, 1));
    slot.words()[0].fetch_add(1, Ordering::Relaxed);
    f.gate.set_now(3);
    assert_eq!(f.gate.policy_version(), 2);
    slot.words()[0].fetch_add(1, Ordering::Relaxed);
    f.gate.set_now(4);
    assert_eq!(
        (f.gate.policy_version(), f.gate.message_tokens()),
        (3, Some(1))
    );
}

/// R-CORE-21, follow-up 1 of the #814 review: a gate built with no rate
/// (a rateless lane's) creates its bucket from the first policy published
/// to its slot, empty (a policy taken at run time never grants tokens,
/// decided 2026-10-28 by QS-COORDINATOR), and takes later changes as any
/// other gate.
#[test]
fn a_rateless_gate_adopts_a_published_policy() {
    use karyos_sys::rate_policy_slot::{SLOT_WORDS, publish};

    let mut f = Fixture::new(1, None);
    let slot = Arc::new(HeapWords::zeroed(SLOT_WORDS));
    f.gate
        .set_policy_slot(Arc::clone(&slot) as Arc<dyn SharedWords>);
    f.gate.set_now(0);
    assert_eq!(
        (f.gate.policy_version(), f.gate.message_tokens()),
        (0, None)
    );
    publish(slot.words(), 0, 1, &rate(5, 3));
    f.gate.set_now(1);
    assert_eq!(
        (f.gate.policy_version(), f.gate.message_tokens()),
        (1, Some(0))
    );
    // It earns from the adoption on.
    f.gate.set_now(1 + 1_000_000_000);
    assert_eq!(f.gate.message_tokens(), Some(3));
    publish(slot.words(), 0, 2, &rate(1, 1));
    f.gate.set_now(2 + 1_000_000_000);
    assert_eq!(
        (f.gate.policy_version(), f.gate.message_tokens()),
        (2, Some(1))
    );
}

/// Z1 of the #841 review: positions a gate with no rate let through took
/// no tokens: once it adopts a policy they are exempt, exposed again on
/// any route without a charge, and returning them gives nothing back.
#[test]
fn a_rateless_gates_positions_are_never_refunded_after_adoption() {
    use karyos_sys::rate_policy_slot::{SLOT_WORDS, publish};

    let mut f = Fixture::new(1, None);
    let slot = Arc::new(HeapWords::zeroed(SLOT_WORDS));
    f.gate
        .set_policy_slot(Arc::clone(&slot) as Arc<dyn SharedWords>);
    f.gate.set_now(0);
    let early: Vec<_> = (0..2).map(|_| f.stage(0)).collect();
    let mut tokens: Vec<_> = early.iter().map(|(token, _, _)| *token).collect();
    assert_eq!(check(&mut f.gate, 0, &tokens), permit(2));
    publish(slot.words(), 0, 1, &rate(1, 2));
    f.gate.set_now(0);
    assert_eq!(f.gate.message_tokens(), Some(0), "adopted empty");
    // Two seconds fill the burst of 2.
    f.gate.set_now(2_000_000_000);
    assert_eq!(f.gate.message_tokens(), Some(2));
    // Exposed again with two new ones: the early two are exempt, the new
    // two take the burst.
    tokens.extend((0..2).map(|_| f.stage(0).0));
    assert_eq!(check(&mut f.gate, 0, &tokens), permit(4));
    assert_eq!(f.gate.message_tokens(), Some(0));
    // The early two come back unsent: nothing is refunded, as nothing was
    // taken for them.
    for (_, _, staged) in early {
        f.gate.left(0, staged, Left::Returned);
    }
    assert_eq!(f.gate.message_tokens(), Some(0), "nothing refunded");
    assert_eq!(f.gate.counts().faults, 0);
}

/// Z2 and A1 of the #841 review: a published policy the gate refuses (a
/// byte burst below its largest datagram, which the driver never
/// publishes) is counted, and the gate fails closed: it limits with the
/// stricter of it and the policy in force, here a byte bucket no frame
/// fits, so the lane is held until a valid version.
#[test]
fn a_policy_the_gate_refuses_is_applied_as_the_stricter() {
    use karyos_sys::rate_limit::Rate;
    use karyos_sys::rate_policy_slot::{SLOT_WORDS, publish};

    let mut f = Fixture::new(1, Some(rate(10, 8)));
    let slot = Arc::new(HeapWords::zeroed(SLOT_WORDS));
    f.gate
        .set_policy_slot(Arc::clone(&slot) as Arc<dyn SharedWords>);
    let small = RatePolicy {
        messages: Rate {
            per_second: 20,
            burst: 20,
        },
        bytes: Some(Rate {
            per_second: 1000,
            burst: u64::from(MAX_FRAME) - 1,
        }),
    };
    publish(slot.words(), 0, 1, &small);
    f.gate.set_now(1);
    assert_eq!(f.gate.policy_version(), 1);
    assert_eq!(f.gate.counts().policies_refused, 1);
    // The stricter of each: 10 messages a second, a burst of 8 (the level
    // kept), and the refused byte bucket, which no frame fits.
    assert_eq!(f.gate.message_tokens(), Some(8));
    // The largest datagram: more bytes than the refused burst holds.
    let (token, _, _) = f.stage_with(0, MAX_FRAME, 1, None);
    f.gate.set_now(10_000_000_000);
    assert!(!f.gate.admits(0), "held");
    assert_eq!(check(&mut f.gate, 0, &[token]), GateDecision::Deny);
    // Read once: the next serve does not count it again.
    assert_eq!(f.gate.counts().policies_refused, 1);
    // A valid version releases it.
    publish(slot.words(), 0, 2, &rate(1, 1));
    f.gate.set_now(10_000_000_001);
    assert_eq!(f.gate.policy_version(), 2);
    assert_eq!(check(&mut f.gate, 0, &[token]), permit(1));
}

/// The coordinator's decision on the #841 review: a reincarnation's gate
/// starts its bucket empty when the reincarnation began, so reincarnating
/// never buys a new burst; it has earned since (#852's review).
#[test]
fn a_reincarnations_gate_starts_empty() {
    let mut f = Fixture::new(1, Some(rate(1, 4)));
    assert_eq!(f.gate.message_tokens(), Some(4));
    f.gate.empty_bucket_since(0, 0);
    assert_eq!(f.gate.message_tokens(), Some(0));
    f.gate.set_now(2_000_000_000);
    assert_eq!(f.gate.message_tokens(), Some(2), "it earns from then on");
}

/// Words that complete a publication of version 3 right after the first
/// plain load of the sequence word once `armed` returns: the load that
/// validates a read, so the read is whole and the publication lands
/// between it and anything the reader does next.
#[derive(Debug)]
struct RacingSlot {
    words: HeapWords,
    loads: AtomicU64,
    armed: core::sync::atomic::AtomicBool,
}

impl LoadWords for RacingSlot {
    fn load(&self, index: usize) -> Option<u64> {
        let value = self.words.load(index);
        if index == 0
            && self.armed.load(Ordering::Relaxed)
            && self.loads.fetch_add(1, Ordering::Relaxed) == 0
        {
            self.armed.store(false, Ordering::Relaxed);
            karyos_sys::rate_policy_slot::publish(self.words.words(), 0, 3, &rate(1, 1));
        }
        value
    }

    fn load_acquire(&self, index: usize) -> Option<u64> {
        self.words.load_acquire(index)
    }

    fn len(&self) -> usize {
        self.words.len()
    }
}

/// R-CORE-21, review B2 of #814: a publication that completes right after
/// the gate read the slot is applied at the next serve, never recorded as
/// seen and lost.
#[test]
fn a_publication_completed_during_a_read_is_not_lost() {
    use karyos_sys::rate_policy_slot::{SLOT_WORDS, publish};

    let mut f = Fixture::new(1, Some(rate(10, 8)));
    let slot = Arc::new(RacingSlot {
        words: HeapWords::zeroed(SLOT_WORDS),
        loads: AtomicU64::new(0),
        armed: core::sync::atomic::AtomicBool::new(false),
    });
    f.gate
        .set_policy_slot(Arc::clone(&slot) as Arc<dyn SharedWords>);
    f.gate.set_now(0);
    publish(slot.words.words(), 0, 2, &rate(5, 3));
    slot.armed.store(true, Ordering::Relaxed);
    f.gate.set_now(1);
    assert_eq!(f.gate.policy_version(), 2);
    // Version 3 completed right after that read: a gate that loaded the
    // sequence again there would take it as seen and keep version 2 for
    // good. This one applies it at the next serve.
    f.gate.set_now(2);
    assert_eq!(
        (f.gate.policy_version(), f.gate.message_tokens()),
        (3, Some(1))
    );
}

/// The control reserve of karyos#840 (R-CORE-21): `per_second` and `burst`
/// messages.
fn reserve(per_second: u64, burst: u64) -> Rate {
    Rate { per_second, burst }
}

/// R-CORE-21, karyos#840, acceptance 1: under a policy equal to the
/// reserve, ordinary traffic spends every token of the publication's
/// bucket, and a cancel (a `SESSION_ABORT`) and a resolution (an `ABORTED`
/// record) still go through at once, from the control bucket.
#[test]
fn ordinary_traffic_spends_its_bucket_and_a_cancel_still_goes_through() {
    let mut f = Fixture::new(1, Some(rate(2, 2)));
    f.gate.set_control_reserve(reserve(2, 2), 0).unwrap();
    for _ in 0..3 {
        f.stage(0);
    }
    f.accept(2);
    let report = f.serve(0);
    // Two sent, the third held for its rate: the publication's bucket is
    // empty.
    assert_eq!(served(&report, 0), 2 * u64::from(FRAME));
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(f.gate.control_message_tokens(), Some(2));
    assert_eq!(
        f.gate
            .admit_control(FrameType::SessionAbort, u64::from(FRAME)),
        ControlAdmission::Admitted
    );
    assert_eq!(
        f.gate
            .admit_control(FrameType::Aborted, u64::from(MAX_FRAME)),
        ControlAdmission::Admitted
    );
    // Control traffic spent the control bucket alone.
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(f.gate.control_message_tokens(), Some(0));
    assert_eq!(f.gate.counts().control_held, 0);
}

/// R-CORE-21, karyos#840, acceptance 2: control traffic past the reserve
/// is held until its own bucket refills, never paid from the publication's
/// bucket however full (no borrowing), so it never goes past the reserve.
#[test]
fn control_traffic_beyond_the_reserve_is_held() {
    let mut f = Fixture::new(1, Some(rate(100, 100)));
    f.gate.set_control_reserve(reserve(1, 2), 0).unwrap();
    f.gate.set_now(0);
    let abort = |gate: &mut GuardGate| gate.admit_control(FrameType::SessionAbort, 32);
    assert_eq!(abort(&mut f.gate), ControlAdmission::Admitted);
    assert_eq!(abort(&mut f.gate), ControlAdmission::Admitted);
    assert_eq!(abort(&mut f.gate), ControlAdmission::Held);
    assert_eq!(
        f.gate.admit_control(FrameType::SessionAbortAck, 32),
        ControlAdmission::Held
    );
    // The publication's tokens were not borrowed.
    assert_eq!(f.gate.message_tokens(), Some(100));
    // Half a second earns half a token: still held.
    f.gate.set_now(SECOND / 2);
    assert_eq!(abort(&mut f.gate), ControlAdmission::Held);
    // A second earns one: one more, then held again.
    f.gate.set_now(SECOND);
    assert_eq!(abort(&mut f.gate), ControlAdmission::Admitted);
    assert_eq!(abort(&mut f.gate), ControlAdmission::Held);
    assert_eq!(f.gate.counts().control_held, 4);
    // Over ten seconds, at most the burst plus the earned tokens leave.
    let mut sent = 0;
    for tenth in 11..=110 {
        f.gate.set_now(tenth * SECOND / 10);
        while abort(&mut f.gate) == ControlAdmission::Admitted {
            sent += 1;
        }
    }
    assert_eq!(sent, 10);
    assert_eq!(f.gate.message_tokens(), Some(100));
}

/// The control bucket's byte side holds the reserve's messages at the
/// largest datagram: a full frame per reserved message, no more.
#[test]
fn the_control_bucket_charges_bytes_at_the_largest_datagram() {
    let mut f = Fixture::new(1, None);
    f.gate.set_control_reserve(reserve(1, 2), 0).unwrap();
    assert_eq!(
        f.gate.control_policy(),
        Some(RatePolicy::of_reserve(&reserve(1, 2), u64::from(MAX_FRAME)))
    );
    assert_eq!(f.gate.control_byte_tokens(), Some(2 * u64::from(MAX_FRAME)));
    // A frame longer than the largest datagram is never paid in one go:
    // two of them would take more bytes than the burst.
    let long = u64::from(MAX_FRAME) + 1;
    assert_eq!(
        f.gate.admit_control(FrameType::SessionAbort, long),
        ControlAdmission::Admitted
    );
    assert_eq!(
        f.gate.admit_control(FrameType::SessionAbort, long),
        ControlAdmission::Held
    );
}

/// R-CORE-21, karyos#840, acceptance 3: a policy change, tightening or
/// loosening, leaves the control bucket's level and its rates as the
/// reserve sets them.
#[test]
fn a_policy_change_leaves_the_control_bucket_as_the_reserve_sets_it() {
    use karyos_sys::rate_policy_slot::{SLOT_WORDS, publish};

    let mut f = Fixture::new(1, Some(rate(10, 8)));
    let slot = Arc::new(HeapWords::zeroed(SLOT_WORDS));
    f.gate
        .set_policy_slot(Arc::clone(&slot) as Arc<dyn SharedWords>);
    f.gate.set_control_reserve(reserve(2, 4), 0).unwrap();
    let control = RatePolicy::of_reserve(&reserve(2, 4), u64::from(MAX_FRAME));
    f.gate.set_now(0);
    assert_eq!(
        f.gate
            .admit_control(FrameType::SessionAbort, u64::from(FRAME)),
        ControlAdmission::Admitted
    );
    let level = (
        f.gate.control_message_tokens(),
        f.gate.control_byte_tokens(),
    );
    assert_eq!(
        level,
        (Some(3), Some(4 * u64::from(MAX_FRAME) - u64::from(FRAME)))
    );
    // A tightening to the reserve, then a loosening, then a byte limit: the
    // publication's bucket follows each, the control bucket none.
    let tight = rate(2, 4);
    let loose = rate(50, 40);
    let bytes = RatePolicy {
        messages: Rate {
            per_second: 50,
            burst: 40,
        },
        bytes: Some(Rate {
            per_second: 4 * u64::from(MAX_FRAME),
            burst: 4 * u64::from(MAX_FRAME),
        }),
    };
    for (version, policy, tokens) in [(2, tight, 4), (3, loose, 4), (4, bytes, 4)] {
        publish(slot.words(), 0, version, &policy);
        f.gate.set_now(0);
        assert_eq!(f.gate.policy_version(), version);
        assert_eq!(f.gate.message_tokens(), Some(tokens));
        assert_eq!(f.gate.control_policy(), Some(control));
        assert_eq!(
            (
                f.gate.control_message_tokens(),
                f.gate.control_byte_tokens()
            ),
            level
        );
    }
    // And it refills at the reserve's rate, not the policy's: one second
    // earns two messages, capped at the reserve's burst.
    f.gate.set_now(SECOND);
    assert_eq!(f.gate.control_message_tokens(), Some(4));
}

/// Without a reserve, control traffic shares the publication's bucket, and
/// without a rate either it is not limited; ordinary and unmetered frames
/// are never charged by `admit_control`.
#[test]
fn without_a_reserve_control_traffic_shares_the_publications_bucket() {
    let mut f = Fixture::new(1, Some(rate(1, 1)));
    assert_eq!(f.gate.control_policy(), None);
    assert_eq!(
        f.gate.admit_control(FrameType::SessionAbort, 32),
        ControlAdmission::Admitted
    );
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(
        f.gate.admit_control(FrameType::Aborted, 32),
        ControlAdmission::Held
    );
    for frame_type in [
        FrameType::Data,
        FrameType::Pad,
        FrameType::Setup,
        FrameType::Nak,
    ] {
        assert_eq!(
            f.gate.admit_control(frame_type, 32),
            ControlAdmission::NotControl
        );
    }
    let mut rateless = Fixture::new(1, None);
    for _ in 0..1000 {
        assert_eq!(
            rateless.gate.admit_control(FrameType::SessionAbort, 32),
            ControlAdmission::Admitted
        );
    }
}

/// A reserve with a zero rate or burst is refused, and the gate keeps what
/// it had.
#[test]
fn a_zero_reserve_is_refused() {
    let mut f = Fixture::new(1, None);
    f.gate.set_control_reserve(reserve(1, 1), 0).unwrap();
    for zero in [reserve(0, 1), reserve(1, 0)] {
        assert_eq!(
            f.gate.set_control_reserve(zero, 0),
            Err(GateError::InvalidRatePolicy(RatePolicyError::Zero))
        );
    }
    assert_eq!(f.gate.control_message_tokens(), Some(1));
}
