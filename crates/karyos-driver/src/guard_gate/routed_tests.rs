// SPDX-License-Identifier: Apache-2.0

//! The guard gate over a routed lane sender on two scripted sockets
//! endpoints (redundant-paths.md RP-10; rp-w4b2a, ACS 16510).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{Ipv4Addr, SocketAddr};

use karyos_client::HeapWords;
use karyos_io::backend::{
    Authority, Commit, InstanceId, TxBackend, TxFrame, TxOptions, TxQueueConfig, TxReport,
};
use karyos_io::lanes::SenderReport;
use karyos_io::lanes::routes::Routes;
use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint, SocketsTx};
use karyos_io::sockets::ops::SendResult;
use karyos_io::sockets::scripted::ScriptedSocket;
use karyos_protocol::lanes::drr::{Budget, DrrConfig};
use karyos_sys::rate_limit::Rate;
use karyos_sys::sync::Ordering;

use super::*;

/// Datagrams each lane queue may hold.
const BOUND: u16 = 4;
/// A datagram here: 64 bytes, charged 64.
const FRAME: u16 = 64;
/// The largest datagram and DRR charge here.
const MAX_FRAME: u16 = 256;

struct Route {
    tx: SocketsTx<ScriptedSocket>,
    socket: ScriptedSocket,
    queue: TxQueueId,
}

impl Route {
    fn new(port: u16) -> Self {
        let mut config = SocketsConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
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
            .add_route(SocketAddr::from((Ipv4Addr::LOCALHOST, port + 1)))
            .unwrap();
        let queue = tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: NonZeroU16::new(BOUND).unwrap(),
            })
            .unwrap();
        Self {
            tx,
            socket: observer,
            queue,
        }
    }

    fn accept(&self, count: usize) {
        for _ in 0..count {
            self.socket.push_send(SendResult::Sent {
                sent: 1,
                error: None,
            });
        }
    }
}

impl Drop for Route {
    /// Returns every pending item: a TX half refuses to drop with some.
    fn drop(&mut self) {
        let mut report = TxReport::new();
        while let Ok(outcome) = self.tx.cancel_pending(self.queue, &mut report) {
            while report.pop_front().is_some() {}
            if !outcome.more {
                break;
            }
        }
    }
}

struct Lent<'a>(&'a mut [Route]);

impl Routes for Lent<'_> {
    type Backend = SocketsTx<ScriptedSocket>;

    fn route(&mut self, route: usize) -> Option<&mut Self::Backend> {
        self.0.get_mut(route).map(|route| &mut route.tx)
    }
}

/// One lane over two routes, guarded by an open epoch 2.
struct Fixture {
    routes: Vec<Route>,
    sender: RoutedLaneSender,
    gate: GuardGate,
    word: Arc<HeapWords>,
    cell: Arc<AppliedEpoch>,
    next_token: u64,
    next_position: u64,
}

fn rate(burst: u64) -> RatePolicy {
    RatePolicy {
        messages: Rate {
            per_second: 1,
            burst,
        },
        bytes: None,
    }
}

impl Fixture {
    fn new(rate: Option<RatePolicy>) -> Self {
        let routes = vec![Route::new(7600), Route::new(7610)];
        let queues: Vec<[TxQueueId; 1]> = routes.iter().map(|route| [route.queue]).collect();
        let queues: Vec<&[TxQueueId]> = queues.iter().map(<[TxQueueId; 1]>::as_slice).collect();
        let sender = RoutedLaneSender::new(
            DrrConfig::new(&[u64::from(MAX_FRAME)], u64::from(MAX_FRAME)).unwrap(),
            &queues,
            usize::from(BOUND),
        )
        .unwrap();
        let word = Arc::new(HeapWords::zeroed(1));
        word.words()[0].store(guard::created(), Ordering::Release);
        assert_eq!(guard::reopen(&word.words()[0], 1), Ok(2));
        let cell = Arc::new(AppliedEpoch::new());
        let lanes = [GateLane {
            lane: Lane::ZERO,
            epoch: 2,
            bound: usize::from(BOUND),
        }];
        let gate = GuardGate::new_routed(
            Arc::clone(&word) as Arc<dyn SharedWords>,
            Arc::clone(&cell),
            &lanes,
            &sender,
            rate,
            u64::from(MAX_FRAME),
            0,
        )
        .unwrap();
        Self {
            routes,
            sender,
            gate,
            word,
            cell,
            next_token: 1,
            next_position: 0,
        }
    }

    /// Stages the next position, one message, on each route in `on`;
    /// returns its end.
    fn stage(&mut self, on: &[usize]) -> u64 {
        let position = self.next_position;
        let end = position + u64::from(FRAME);
        self.next_position = end;
        for &route in on {
            let token = SenderToken::new(self.next_token);
            self.next_token += 1;
            let queue = self.routes[route].queue;
            let mut frame = self.routes[route]
                .tx
                .claim_tx(queue, usize::from(FRAME))
                .unwrap();
            frame.bytes_mut().fill(7);
            let ticket = frame
                .commit(Commit {
                    len: usize::from(FRAME),
                    token,
                    options: TxOptions::none(),
                })
                .unwrap();
            let copy = RoutedStaged {
                staged: Staged {
                    ticket,
                    charge: u64::from(FRAME),
                    len: FRAME,
                },
                position,
            };
            self.gate
                .stage_copy(
                    &mut self.sender,
                    0,
                    route,
                    copy,
                    GateHead {
                        token,
                        length: u64::from(FRAME),
                        messages: 1,
                        start: position,
                        end,
                    },
                )
                .unwrap();
        }
        end
    }

    fn serve(&mut self) -> SenderReport {
        let Self {
            routes,
            sender,
            gate,
            ..
        } = self;
        sender.serve(
            &mut Lent(routes),
            gate,
            Budget {
                work: 64,
                bytes: 10_000,
            },
        )
    }

    fn catch_up(&mut self) -> u32 {
        let Self {
            routes,
            sender,
            gate,
            ..
        } = self;
        sender.catch_up(&mut Lent(routes), gate).submitted
    }

    fn cancel(&mut self) {
        let Self {
            routes,
            sender,
            gate,
            ..
        } = self;
        sender.cancel(&mut Lent(routes), 0, gate).unwrap();
    }

    fn close(&self) {
        let _ = guard::close(&self.word.words()[0]).unwrap();
    }
}

/// ACS 16510 (1): a close that lands between route 0's exposure and route
/// 1's denies route 1 and aborts the lane. The position route 0 submitted
/// before the close is the applied epoch's position; once route 1's copy is
/// cancelled, nothing is in flight.
#[test]
fn a_close_between_routes_denies_the_later_route() {
    let mut f = Fixture::new(None);
    let end = f.stage(&[0, 1]);
    f.routes[0].accept(1);
    f.routes[1].accept(1);
    let word = Arc::clone(&f.word);
    f.routes[0].socket.set_send_hook(Box::new(move |_, _| {
        let _ = guard::close(&word.words()[0]);
    }));
    let _ = f.serve();
    assert_eq!(f.routes[0].socket.send_calls(), 1);
    assert_eq!(f.routes[1].socket.send_calls(), 0);
    assert_eq!(f.gate.abort_cause(0), Some(AbortCause::Guard));
    let applied = f.cell.try_read().unwrap();
    assert_eq!(applied.epoch, 3);
    assert_eq!(applied.positions[0], end);
    assert_eq!(f.sender.pending(0, 1), Some(1));
    f.cancel();
    f.gate.between_gates();
    assert_eq!(f.gate.in_flight(), Some(0));
    assert_eq!(f.cell.try_read().unwrap().in_flight, 0);
    assert_eq!(f.sender.pending(0, 1), Some(0));
}

/// A close before any exposure stops both routes: nothing is sent.
#[test]
fn a_close_before_the_exposures_stops_both_routes() {
    let mut f = Fixture::new(None);
    let _ = f.stage(&[0, 1]);
    f.routes[0].accept(1);
    f.routes[1].accept(1);
    f.close();
    let _ = f.serve();
    assert_eq!(f.routes[0].socket.send_calls(), 0);
    assert_eq!(f.routes[1].socket.send_calls(), 0);
    assert_eq!(f.cell.try_read().unwrap().positions[0], 0);
}

/// A position is charged once, at its first permitted copy: with a burst
/// of two messages, two positions go out on both routes.
#[test]
fn a_position_is_charged_once_for_every_route() {
    let mut f = Fixture::new(Some(rate(2)));
    let _ = f.stage(&[0, 1]);
    let end = f.stage(&[0, 1]);
    f.routes[0].accept(2);
    f.routes[1].accept(2);
    let _ = f.serve();
    assert_eq!(f.routes[0].socket.send_calls(), 2);
    assert_eq!(f.routes[1].socket.send_calls(), 2);
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(f.gate.last_submitted(Lane::ZERO), end);
}

/// #841 review, point 9: a position a gate with no rate let through is
/// exempt on every route: while its copy on route 1 is still held, the
/// gate, having adopted a policy with an empty bucket, admits the lane
/// for it, charges nothing, and holds nothing.
#[test]
fn another_routes_copy_of_an_exempt_position_is_not_charged() {
    use karyos_sys::rate_policy_slot::{SLOT_WORDS, publish};

    let mut f = Fixture::new(None);
    let slot = Arc::new(HeapWords::zeroed(SLOT_WORDS));
    f.gate
        .set_policy_slot(Arc::clone(&slot) as Arc<dyn SharedWords>);
    f.gate.set_now(0);
    let _ = f.stage(&[0, 1]);
    f.routes[0].accept(1);
    // Route 1 would block: its copy stays, exposed, uncharged.
    let _ = f.serve();
    assert_eq!(f.routes[0].socket.send_calls(), 1);
    publish(slot.words(), 0, 1, &rate(1));
    f.gate.set_now(0);
    assert_eq!(f.gate.message_tokens(), Some(0), "adopted empty");
    assert_eq!(f.sender.pending(0, 1), Some(1), "route 1 holds its copy");
    assert!(f.gate.admits(0), "exempt, not held for the empty bucket");
    assert_eq!(f.gate.counts().rate_held, 0);
    f.routes[1].accept(1);
    assert_eq!(f.catch_up(), 1, "route 1's copy went out");
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(f.gate.counts().rate_held, 0);
}

/// A copy returned on one route refunds nothing while the position was
/// submitted on another; a position whose every copy returns unsent is
/// refunded.
#[test]
fn a_refund_waits_for_every_route() {
    let mut f = Fixture::new(Some(rate(1)));
    let _ = f.stage(&[0, 1]);
    f.routes[0].accept(1);
    // Route 1 would block: its copy stays, exposed.
    let _ = f.serve();
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(f.sender.pending(0, 1), Some(1));
    f.cancel();
    assert_eq!(f.gate.message_tokens(), Some(0), "route 0 sent it");

    let mut f = Fixture::new(Some(rate(1)));
    let _ = f.stage(&[0, 1]);
    // Both routes would block: the first exposure charged it.
    let _ = f.serve();
    assert_eq!(f.gate.message_tokens(), Some(0));
    f.cancel();
    assert_eq!(f.gate.message_tokens(), Some(1), "no copy was sent");
}

/// ACS 16510 (2): a position skipped on every route (RP-8) is never
/// staged, so never charged: only the staged positions spend tokens.
#[test]
fn a_position_skipped_on_every_route_is_never_charged() {
    let mut f = Fixture::new(Some(rate(3)));
    let _ = f.stage(&[0, 1]);
    f.sender.skipped(0);
    f.sender.skipped(1);
    f.next_position += u64::from(FRAME);
    let _ = f.stage(&[0, 1]);
    f.routes[0].accept(2);
    f.routes[1].accept(2);
    let _ = f.serve();
    assert_eq!(f.routes[0].socket.send_calls(), 2);
    assert_eq!(f.gate.message_tokens(), Some(1));
}

/// The work in flight counts every route: a copy exposed on route 1 keeps
/// it above zero after route 0's left, until route 1 catches up.
#[test]
fn in_flight_drains_only_when_every_route_does() {
    let mut f = Fixture::new(None);
    let end = f.stage(&[0, 1]);
    f.routes[0].accept(1);
    let _ = f.serve();
    assert_eq!(f.gate.in_flight(), Some(1));
    f.routes[1].accept(1);
    assert_eq!(f.catch_up(), 1);
    assert_eq!(f.gate.in_flight(), Some(0));
    assert_eq!(f.gate.last_submitted(Lane::ZERO), end);
}

/// Each route keeps its own order: route 1's copy is no fault although its
/// token is not route 0's next.
#[test]
fn copies_on_two_routes_are_no_fault() {
    let mut f = Fixture::new(None);
    let _ = f.stage(&[0, 1]);
    let _ = f.stage(&[0, 1]);
    f.routes[0].accept(2);
    f.routes[1].accept(2);
    let _ = f.serve();
    assert_eq!(f.gate.counts().faults, 0);
    assert_eq!(f.routes[1].socket.send_calls(), 2);
}

/// A reopen of one route drops only its records: the position route 0
/// still holds keeps its charge.
#[test]
fn a_route_reopen_keeps_the_other_routes_charge() {
    let mut f = Fixture::new(Some(rate(1)));
    let _ = f.stage(&[0, 1]);
    // Both block: charged once, both copies held.
    let _ = f.serve();
    assert_eq!(f.gate.message_tokens(), Some(0));
    let queue = f.routes[1].queue;
    let mut report = TxReport::new();
    while let Ok(outcome) = f.routes[1].tx.cancel_pending(queue, &mut report) {
        while report.pop_front().is_some() {}
        if !outcome.more {
            break;
        }
    }
    f.gate.reopen_route(&mut f.sender, 0, 1, queue, false);
    assert_eq!(f.gate.message_tokens(), Some(0));
    assert_eq!(f.sender.pending(0, 1), Some(0));
    assert_eq!(f.sender.pending(0, 0), Some(1));
    // Route 0's copy is still its next head: it goes, with no fault.
    f.routes[0].accept(1);
    let _ = f.serve();
    assert_eq!(f.gate.counts().faults, 0);
    assert_eq!(f.sender.pending(0, 0), Some(0));
}

/// #333 review P3: a close before a lagging route catches up stops that
/// route's copy: the applied position is the one the other route
/// submitted, and once the copy is cancelled nothing is in flight.
#[test]
fn a_close_before_a_lagging_route_catches_up_stops_it() {
    let mut f = Fixture::new(None);
    let end = f.stage(&[0, 1]);
    f.routes[0].accept(1);
    // Route 1 would block: its copy lags, exposed.
    let _ = f.serve();
    assert_eq!(f.sender.pending(0, 1), Some(1));
    f.close();
    f.routes[1].accept(1);
    assert_eq!(f.catch_up(), 0);
    assert_eq!(f.routes[1].socket.send_calls(), 1, "only the blocked try");
    f.gate.between_gates();
    assert_eq!(f.cell.try_read().unwrap().positions[0], end);
    f.cancel();
    f.gate.between_gates();
    assert_eq!(f.gate.in_flight(), Some(0));
}

/// #333 review P3: over several routes, a report that is no route's next
/// head faults the lane and counts in flight until a reopen, as a ticket
/// mismatch on one route does.
#[test]
fn a_report_of_no_routes_head_faults_the_lane() {
    let mut f = Fixture::new(None);
    let _ = f.stage(&[0, 1]);
    // A frame committed on route 0 but never staged through the gate.
    let queue = f.routes[0].queue;
    let mut frame = f.routes[0].tx.claim_tx(queue, usize::from(FRAME)).unwrap();
    frame.bytes_mut().fill(1);
    let ticket = frame
        .commit(Commit {
            len: usize::from(FRAME),
            token: SenderToken::new(999),
            options: TxOptions::none(),
        })
        .unwrap();
    let stray = Staged {
        ticket,
        charge: u64::from(FRAME),
        len: FRAME,
    };
    f.gate.left(0, stray, Left::Submitted);
    assert_eq!(f.gate.abort_cause(0), Some(AbortCause::Fault));
    assert_eq!(f.gate.in_flight(), Some(1));
    f.cancel();
}

/// Records plan v2 (s-88's review): a position skipped on route 0 and
/// returned by route 1's reset leaves no copy. Without a rewind no first
/// send takes it again: a hole, `Unknown` below the later position route 0
/// submits. With one (no other route held the lane's copies), it holds the
/// frontier until it is staged again.
#[test]
fn a_position_no_route_sent_is_a_hole_unless_rewound() {
    use karyos_sys::submission_frontier::{Frontier, SubmissionFrontier};

    for rewound in [false, true] {
        let mut f = Fixture::new(None);
        let frontier = Arc::new(SubmissionFrontier::new());
        f.gate.set_frontier(Arc::clone(&frontier));
        let first = f.stage(&[1]);
        f.sender.skipped(0);
        let second = f.stage(&[0, 1]);
        let queue = f.routes[1].queue;
        let mut report = TxReport::new();
        while let Ok(outcome) = f.routes[1].tx.cancel_pending(queue, &mut report) {
            while report.pop_front().is_some() {}
            if !outcome.more {
                break;
            }
        }
        f.gate.reopen_route(&mut f.sender, 0, 1, queue, rewound);
        f.routes[0].accept(1);
        let _ = f.serve();
        f.gate.between_gates();
        let expected = if rewound {
            Frontier {
                resolved: 0,
                unknown_hi: 0,
                sent_hi: second,
                staged_hi: second,
            }
        } else {
            Frontier {
                resolved: second,
                unknown_hi: first,
                sent_hi: second,
                staged_hi: second,
            }
        };
        assert_eq!(frontier.read(Lane::ZERO).1, expected, "rewound {rewound}");
    }
}

/// #381 review: a position route 0 submits above a hole that never leaves
/// (held on route 1, out of the live set, then cancelled by the close) is
/// above `resolved`, yet it may have left whole: `sent_hi` covers it, so
/// the walker records it `Unknown`, never `Aborted`.
#[test]
fn a_later_routes_submission_above_a_hole_is_covered_by_sent_hi() {
    use karyos_sys::submission_frontier::{Final, Frontier, SubmissionFrontier};

    let mut f = Fixture::new(None);
    let frontier = Arc::new(SubmissionFrontier::new());
    f.gate.set_frontier(Arc::clone(&frontier));
    let _ = f.stage(&[1]);
    f.sender.skipped(0);
    let second = f.stage(&[0, 1]);
    // Route 1 leaves the live set: it holds no head back, and route 0
    // submits the second position alone.
    f.sender.set_live(1, false);
    f.routes[0].accept(1);
    let _ = f.serve();
    assert_eq!(f.gate.last_submitted(Lane::ZERO), second);
    f.close();
    f.gate.between_gates();
    f.cancel();
    f.gate.between_gates();
    assert_eq!(
        frontier.read(Lane::ZERO),
        (
            Final::Finished {
                reason: crate::guard_streams::REASON_GUARD_CLOSED
            },
            Frontier {
                resolved: 0,
                unknown_hi: 0,
                sent_hi: second,
                staged_hi: second,
            }
        )
    );
}
