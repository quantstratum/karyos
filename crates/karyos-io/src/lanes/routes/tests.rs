// SPDX-License-Identifier: Apache-2.0

//! The routed lane sender over sockets endpoints and the scripted
//! `SocketOps` (`quantstratum-docs: karyos/design/redundant-paths.md`
//! section 7, RP-10).

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;

use karyos_protocol::lanes::drr::Stop;

use super::*;
use crate::backend::{
    Authority, Commit, Exposure, GateDecision, InstanceId, SenderGate, SenderToken, TxFrame,
    TxOptions, TxQueueConfig, TxTicket,
};
use crate::lanes::LaneSender;
use crate::sockets::endpoint::{SocketsConfig, SocketsEndpoint, SocketsTx};
use crate::sockets::ops::SendResult;
use crate::sockets::scripted::ScriptedSocket;

/// Copies each lane queue may hold.
const BOUND: u16 = 4;

/// A gate that permits every candidate unless it denies exposures: all of
/// them, the first `deny_first`, or every one from `deny_from` on.
#[derive(Debug, Default)]
struct Gate {
    deny_exposure: bool,
    deny_first: u32,
    deny_from: Option<u32>,
    exposures: u32,
    /// Copies reported gone, by kind (submitted, returned, unknown).
    left: [u32; 3],
}

impl SenderGate for Gate {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        let seen = self.exposures;
        self.exposures += 1;
        if self.deny_exposure
            || seen < self.deny_first
            || self.deny_from.is_some_and(|from| seen >= from)
        {
            GateDecision::Deny
        } else {
            GateDecision::Permit {
                count: NonZeroU16::new(u16::try_from(candidate.tokens.len()).unwrap()).unwrap(),
            }
        }
    }
}

impl LaneGate for Gate {
    fn admits(&mut self, _lane: usize) -> bool {
        true
    }

    fn left(&mut self, _lane: usize, _staged: Staged, how: Left) {
        let kind = match how {
            Left::Submitted => 0,
            Left::Returned => 1,
            Left::Unknown => 2,
        };
        self.left[kind] += 1;
    }
}

/// One route: a sockets endpoint over a scripted socket, a queue per lane.
struct Route {
    tx: SocketsTx<ScriptedSocket>,
    socket: ScriptedSocket,
    queues: Vec<TxQueueId>,
}

impl Route {
    fn new(lanes: usize, port: u16) -> Self {
        let mut config = SocketsConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
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
            .add_route(SocketAddr::from((Ipv4Addr::LOCALHOST, port + 1)))
            .unwrap();
        let queues = (0..lanes)
            .map(|_| {
                tx.open_queue(TxQueueConfig {
                    authority: Authority::FIRST,
                    route,
                    max_pending: NonZeroU16::new(BOUND).unwrap(),
                })
                .unwrap()
            })
            .collect();
        Self {
            tx,
            socket: observer,
            queues,
        }
    }

    /// Commits a datagram of `len` bytes to `lane`'s queue.
    fn commit(&mut self, lane: usize, len: u16, token: u64) -> TxTicket {
        let mut frame = self
            .tx
            .claim_tx(self.queues[lane], usize::from(len))
            .unwrap();
        frame.bytes_mut().fill(u8::try_from(lane).unwrap());
        frame
            .commit(Commit {
                len: usize::from(len),
                token: SenderToken::new(token),
                options: TxOptions::none(),
            })
            .unwrap()
    }

    /// The kernel accepts the next `count` single sends.
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

/// The routes a test lends the sender.
struct Lent<'a>(&'a mut [Route]);

impl Routes for Lent<'_> {
    type Backend = SocketsTx<ScriptedSocket>;

    fn route(&mut self, route: usize) -> Option<&mut Self::Backend> {
        self.0.get_mut(route).map(|route| &mut route.tx)
    }
}

struct Fixture {
    routes: Vec<Route>,
    sender: RoutedLaneSender,
    next_token: u64,
}

impl Fixture {
    fn new(quanta: &[u64], max_charge: u64, routes: usize) -> Self {
        let routes: Vec<Route> = (0..routes)
            .map(|route| Route::new(quanta.len(), 7100 + 10 * u16::try_from(route).unwrap()))
            .collect();
        let queues: Vec<&[TxQueueId]> =
            routes.iter().map(|route| route.queues.as_slice()).collect();
        let sender = RoutedLaneSender::new(
            DrrConfig::new(quanta, max_charge).unwrap(),
            &queues,
            usize::from(BOUND),
        )
        .unwrap();
        Self {
            routes,
            sender,
            next_token: 1,
        }
    }

    /// Stages datagram `position` of `lane` (`len` bytes, charged
    /// `charge`) on each route in `on`.
    fn stage(&mut self, lane: usize, position: u64, len: u16, charge: u64, on: &[usize]) {
        for &route in on {
            let token = self.next_token;
            self.next_token += 1;
            let ticket = self.routes[route].commit(lane, len, token);
            self.sender
                .staged(
                    lane,
                    route,
                    RoutedStaged {
                        staged: Staged {
                            ticket,
                            charge,
                            len,
                        },
                        position,
                    },
                )
                .unwrap();
        }
    }

    fn serve(&mut self, gate: &mut Gate, bytes: u64) -> SenderReport {
        let Self { routes, sender, .. } = self;
        sender.serve(&mut Lent(routes), gate, Budget { work: 64, bytes })
    }
}

fn served(report: &SenderReport, lanes: usize) -> Vec<u64> {
    (0..lanes)
        .map(|lane| report.drr.lanes[lane].served_bytes)
        .collect()
}

/// Negative control (single route): the routed sender takes the same DRR
/// steps as `LaneSender` over the same staging and the same kernel: the
/// same served bytes per lane, the same stop and the same sends.
#[test]
fn one_route_matches_the_lane_sender() {
    let quanta = [200, 100];
    let mut routed = Fixture::new(&quanta, 100, 1);
    let mut plain = Route::new(2, 7300);
    let mut lane_sender = LaneSender::new(
        DrrConfig::new(&quanta, 100).unwrap(),
        &plain.queues,
        usize::from(BOUND),
    )
    .unwrap();
    let plan = [
        (0, 100, 100),
        (0, 100, 100),
        (0, 100, 100),
        (1, 80, 100),
        (1, 80, 100),
    ];
    let mut positions = [0u64; 2];
    for (index, &(lane, len, charge)) in plan.iter().enumerate() {
        routed.stage(lane, positions[lane], len, charge, &[0]);
        positions[lane] += 128;
        let ticket = plain.commit(lane, len, 1000 + u64::try_from(index).unwrap());
        lane_sender
            .staged(
                lane,
                Staged {
                    ticket,
                    charge,
                    len,
                },
            )
            .unwrap();
    }
    // Four sends accepted, then the socket blocks: both stop alike.
    routed.routes[0].accept(4);
    plain.accept(4);
    let a = routed.serve(&mut Gate::default(), 1000);
    let b = lane_sender.serve(
        &mut plain.tx,
        &mut Gate::default(),
        Budget {
            work: 64,
            bytes: 1000,
        },
    );
    assert_eq!(served(&a, 2), served(&b, 2));
    assert_eq!(a.drr.stop, b.drr.stop);
    assert_eq!(a.drr.rounds, b.drr.rounds);
    assert_eq!(
        routed.routes[0].socket.send_calls(),
        plain.socket.send_calls()
    );
    for lane in 0..2 {
        assert_eq!(
            routed.sender.drr().deficit(lane),
            lane_sender.drr().deficit(lane)
        );
        assert_eq!(routed.sender.pending(lane, 0), lane_sender.pending(lane));
    }
}

/// RP-10: a head selected once is submitted on every route that holds it
/// and debited once, at the first route that submits it.
#[test]
fn a_head_on_two_routes_debits_once() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.routes[0].accept(1);
    f.routes[1].accept(1);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 1), [100]);
    assert_eq!(f.routes[0].socket.send_calls(), 1);
    assert_eq!(f.routes[1].socket.send_calls(), 1);
    assert_eq!(f.sender.debited(0), Some(0));
    assert_eq!(f.sender.counters(1).unwrap().late, 1);
    assert_eq!(
        (f.sender.pending(0, 0), f.sender.pending(0, 1)),
        (Some(0), Some(0))
    );
}

/// RP-10 Service: a head no route can take (would block everywhere)
/// debits nothing: the call stops as backpressure and both copies stay.
#[test]
fn would_block_on_every_route_debits_nothing() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 1), [0]);
    assert!(
        matches!(report.drr.stop, Stop::Backpressure { .. }),
        "{:?}",
        report.drr.stop
    );
    assert_eq!(f.sender.debited(0), None);
    assert_eq!(
        (f.sender.pending(0, 0), f.sender.pending(0, 1)),
        (Some(1), Some(1))
    );
}

/// A route without room does not hold the lane back: the other route
/// submits and debits; the blocked route's copy stays pending and is sent
/// later by `catch_up`, which debits nothing more.
#[test]
fn a_blocked_route_catches_up_without_a_second_debit() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.routes[1].accept(1);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 1), [100]);
    assert_eq!(f.sender.pending(0, 0), Some(1));
    let deficit = f.sender.drr().deficit(0);
    f.routes[0].accept(1);
    let mut gate = Gate::default();
    let Fixture { routes, sender, .. } = &mut f;
    assert_eq!(sender.catch_up(&mut Lent(routes), &mut gate).submitted, 1);
    assert_eq!(f.sender.pending(0, 0), Some(0));
    assert_eq!(f.sender.drr().deficit(0), deficit);
    assert_eq!(f.sender.counters(0).unwrap().late, 1);
    // Nothing is left to debit: a later call serves nothing.
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 1), [0]);
}

/// #301 guard at every route's exposure: a close that lands between the
/// selection and the first route's exposure stops every route; nothing is
/// submitted and the deficit is untouched.
#[test]
fn a_close_before_the_first_exposure_stops_every_route() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.routes[0].accept(1);
    f.routes[1].accept(1);
    let deficit = f.sender.drr().deficit(0);
    let mut gate = Gate {
        deny_exposure: true,
        ..Gate::default()
    };
    let report = f.serve(&mut gate, 1000);
    assert_eq!(served(&report, 1), [0]);
    assert_eq!(f.routes[0].socket.send_calls(), 0);
    assert_eq!(f.routes[1].socket.send_calls(), 0);
    assert_eq!(f.sender.drr().deficit(0), deficit);
    assert_eq!(gate.left, [0, 0, 0]);
}

/// A route that skipped a datagram (no room to stage it) holds a later
/// copy; the head is still sent on the route that has it, and the skip is
/// counted per route.
#[test]
fn a_skipped_copy_is_counted_and_the_head_still_goes() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0]);
    f.sender.skipped(1);
    f.stage(0, 128, 100, 100, &[0, 1]);
    f.routes[0].accept(2);
    f.routes[1].accept(1);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 1), [200]);
    assert_eq!(f.sender.counters(1).unwrap().skipped, 1);
    assert_eq!(f.sender.counters(0).unwrap().skipped, 0);
    assert_eq!(f.routes[1].socket.send_calls(), 1);
}

/// #301: a cancel at close returns the never-exposed copies of every
/// route.
#[test]
fn a_cancel_returns_every_routes_copies() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.stage(0, 128, 100, 100, &[0, 1]);
    let mut gate = Gate::default();
    let Fixture { routes, sender, .. } = &mut f;
    sender.cancel(&mut Lent(routes), 0, &mut gate).unwrap();
    assert_eq!(gate.left, [0, 4, 0]);
    assert_eq!(
        (f.sender.pending(0, 0), f.sender.pending(0, 1)),
        (Some(0), Some(0))
    );
}

/// Construction checks the routes.
#[test]
fn routes_are_checked() {
    let config = DrrConfig::new(&[100], 100).unwrap();
    assert!(RoutedLaneSender::new(config, &[], 4).is_err());
    let route = Route::new(2, 7400);
    assert!(RoutedLaneSender::new(config, &[route.queues.as_slice()], 4).is_err());
}

/// A route holds copies in position order; serving one head never flushes
/// another position's copy on a route that skipped the head.
#[test]
fn a_head_is_never_sent_out_of_order_on_a_route() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0]);
    f.sender.skipped(1);
    f.stage(0, 128, 100, 100, &[0, 1]);
    f.routes[0].accept(2);
    f.routes[1].accept(1);
    // The budget covers one head: position 0, on route 0 only.
    let report = f.serve(&mut Gate::default(), 100);
    assert_eq!(served(&report, 1), [100]);
    assert_eq!(f.routes[1].socket.send_calls(), 0);
    assert_eq!(f.sender.pending(0, 1), Some(1));
}

/// A copy behind the debited position is never the lane's head: serving
/// again before `catch_up` debits nothing a second time.
#[test]
fn a_lagging_copy_is_never_debited_twice() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.routes[1].accept(1);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 1), [100]);
    f.routes[0].accept(1);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 1), [0]);
    assert_eq!(f.sender.pending(0, 0), Some(1));
}

/// #317 review P1: a head at no route's front is not a head. Route 0 holds
/// `[0 (debited), 128]` behind a blocked socket and route 1 skipped 128:
/// lane 0 is ineligible, so lane 1's ready copy on route 1 is served and
/// no work is burnt on lane 0.
#[test]
fn a_head_at_no_routes_front_leaves_the_lane_ineligible() {
    let mut f = Fixture::new(&[100, 100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.routes[1].accept(1);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 2), [100, 0]);
    assert_eq!(f.sender.pending(0, 0), Some(1));
    f.stage(0, 128, 100, 100, &[0]);
    f.sender.skipped(1);
    f.stage(1, 0, 100, 100, &[1]);
    f.sender.skipped(0);
    f.routes[1].accept(1);
    let calls = f.routes[0].socket.send_calls();
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 2), [0, 100]);
    assert_eq!(report.drr.lanes[0].failed, 0);
    assert_eq!(f.routes[0].socket.send_calls(), calls);
    // Route 0 catches up 0, then sends 128 as the head, debited.
    f.routes[0].accept(2);
    let mut gate = Gate::default();
    let Fixture { routes, sender, .. } = &mut f;
    assert_eq!(sender.catch_up(&mut Lent(routes), &mut gate).submitted, 1);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 2), [100, 0]);
    assert_eq!(f.sender.debited(0), Some(128));
}

/// #317 review P2: the head never moves past a position no route
/// submitted. Route 0 alone holds 0 and the gate denies it: 128 on route 1
/// waits, and 0 is debited when route 0 sends it.
#[test]
fn a_denied_lowest_copy_holds_the_lane() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0]);
    f.sender.skipped(1);
    f.stage(0, 128, 100, 100, &[0, 1]);
    f.routes[0].accept(2);
    f.routes[1].accept(1);
    let mut gate = Gate {
        deny_first: 1,
        ..Gate::default()
    };
    let report = f.serve(&mut gate, 1000);
    assert_eq!(served(&report, 1), [0]);
    assert_eq!(f.routes[1].socket.send_calls(), 0);
    assert_eq!(f.sender.debited(0), None);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 1), [200]);
    assert_eq!(f.sender.debited(0), Some(128));
    assert_eq!(f.routes[1].socket.send_calls(), 1);
}

/// #317 re-review P2: with several routes a failure stops only its route
/// (a failure stops only that half): the head another route submitted is
/// debited, the failed route is out for the call with its failure kept,
/// and the other route serves every lane, on every call.
#[test]
fn a_failed_route_stops_alone() {
    let mut f = Fixture::new(&[100, 100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.stage(1, 0, 100, 100, &[0, 1]);
    f.routes[0].accept(2);
    f.routes[1]
        .socket
        .push_send(SendResult::Error(crate::sockets::ops::Errno::BADF));
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 2), [100, 100]);
    assert_eq!(report.failure, None);
    assert_eq!(f.sender.debited(0), Some(0));
    assert_eq!(f.routes[0].socket.send_calls(), 2);
    assert_eq!(f.routes[1].socket.send_calls(), 1, "out for the call");
    let failures = f.sender.take_failures();
    assert!(
        matches!(
            failures[1],
            Some(SenderFailure::Backend {
                lane: 0,
                stop: FlushStop::Failed(_)
            })
        ),
        "{failures:?}"
    );
    assert_eq!(failures[0], None);
    assert_eq!(f.sender.take_failures(), [None; MAX_ROUTES]);
    // The next call: route 1's half stays stopped until its reset (its
    // queues read as needing one), and route 0 still serves.
    f.stage(0, 128, 100, 100, &[0, 1]);
    f.routes[0].accept(1);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 2), [100, 0]);
    assert_eq!(report.failure, None);
    assert_eq!(f.routes[1].socket.send_calls(), 1);
}

/// #317 re-review P1: a detached route (no TX half lent) is out for the
/// call: lane 0's position held only there leaves lane 0 ineligible, and
/// lane 1 is served on route 1 with no work burnt.
#[test]
fn a_detached_route_is_out_for_the_call() {
    let mut f = Fixture::new(&[100, 100], 100, 2);
    f.stage(0, 0, 100, 100, &[0]);
    f.sender.skipped(1);
    f.stage(1, 0, 100, 100, &[1]);
    f.sender.skipped(0);
    f.routes[1].accept(1);
    let Fixture { routes, sender, .. } = &mut f;
    let mut lent = Detach(routes, 0);
    let report = sender.serve(
        &mut lent,
        &mut Gate::default(),
        Budget {
            work: 64,
            bytes: 1000,
        },
    );
    assert_eq!(served(&report, 2), [0, 100]);
    assert_eq!(report.drr.lanes[0].failed, 0);
    assert!(
        matches!(report.drr.stop, Stop::Idle),
        "{:?}",
        report.drr.stop
    );
}

/// #317 re-review P3: a socket that would block in `catch_up` takes no
/// more flushes in the call, on any lane.
#[test]
fn a_blocked_route_is_out_for_the_catch_up() {
    let mut f = Fixture::new(&[100, 100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.stage(1, 0, 100, 100, &[0, 1]);
    f.routes[1].accept(2);
    let _ = f.serve(&mut Gate::default(), 1000);
    assert_eq!(
        (f.sender.pending(0, 0), f.sender.pending(1, 0)),
        (Some(1), Some(1))
    );
    let calls = f.routes[0].socket.send_calls();
    let mut gate = Gate::default();
    let Fixture { routes, sender, .. } = &mut f;
    assert_eq!(sender.catch_up(&mut Lent(routes), &mut gate).submitted, 0);
    assert_eq!(f.routes[0].socket.send_calls(), calls + 1);
}

/// #317 review P2: a cancel goes on past a route's error and returns the
/// first error; a detached route keeps its copies, counted.
#[test]
fn a_cancel_covers_every_route() {
    let mut f = Fixture::new(&[100], 100, 3);
    f.stage(0, 0, 100, 100, &[0, 1, 2]);
    let mut report = TxReport::new();
    let queue = f.routes[0].queues[0];
    f.routes[0].tx.close_queue(queue, &mut report).unwrap();
    let mut gate = Gate::default();
    let Fixture { routes, sender, .. } = &mut f;
    let result = sender.cancel(&mut Lent(&mut routes[..2]), 0, &mut gate);
    assert_eq!(result, Err(QueueError::UnknownQueue));
    assert_eq!(f.sender.pending(0, 1), Some(0));
    assert_eq!(gate.left, [0, 1, 0]);
    assert_eq!(f.sender.pending(0, 2), Some(1));
    assert_eq!(f.sender.counters(2).unwrap().uncancelled, 1);
    assert_eq!(f.sender.counters(1).unwrap().uncancelled, 0);
}

/// #317 review (M2): a close that lands between route 0's exposure and
/// route 1's stops route 1 only: the head is debited once, and route 1's
/// copy stays for the close's cancel.
#[test]
fn a_close_between_routes_stops_the_later_route() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.routes[0].accept(1);
    f.routes[1].accept(1);
    let mut gate = Gate {
        deny_from: Some(1),
        ..Gate::default()
    };
    let report = f.serve(&mut gate, 1000);
    assert_eq!(served(&report, 1), [100]);
    assert_eq!(f.routes[1].socket.send_calls(), 0);
    assert_eq!(f.sender.pending(0, 1), Some(1));
    assert_eq!(gate.left, [1, 0, 0]);
    let Fixture { routes, sender, .. } = &mut f;
    assert_eq!(sender.catch_up(&mut Lent(routes), &mut gate).submitted, 0);
    assert_eq!(f.sender.pending(0, 1), Some(1));
}

/// #317 review (M3): `catch_up` sends only copies at or below the debited
/// position.
#[test]
fn catch_up_never_sends_above_the_debited_position() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.stage(0, 128, 100, 100, &[0, 1]);
    f.routes[0].accept(2);
    f.routes[1].accept(2);
    // The budget covers one head: 0, on both routes.
    let report = f.serve(&mut Gate::default(), 100);
    assert_eq!(served(&report, 1), [100]);
    let mut gate = Gate::default();
    let Fixture { routes, sender, .. } = &mut f;
    assert_eq!(sender.catch_up(&mut Lent(routes), &mut gate).submitted, 0);
    assert_eq!(
        (f.sender.pending(0, 0), f.sender.pending(0, 1)),
        (Some(1), Some(1))
    );
}

/// A blocked socket takes no more flushes in the call, on any lane: the
/// other route serves both lanes.
#[test]
fn a_blocked_route_is_out_for_the_call() {
    let mut f = Fixture::new(&[100, 100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.stage(1, 0, 100, 100, &[0, 1]);
    f.routes[1].accept(2);
    let report = f.serve(&mut Gate::default(), 1000);
    assert_eq!(served(&report, 2), [100, 100]);
    assert_eq!(f.routes[0].socket.send_calls(), 1);
}

/// #317 review P3: a failure in `catch_up` is reported.
#[test]
fn a_catch_up_failure_is_reported() {
    let mut f = Fixture::new(&[100], 100, 2);
    f.stage(0, 0, 100, 100, &[0, 1]);
    f.routes[1].accept(1);
    let _ = f.serve(&mut Gate::default(), 1000);
    f.routes[0]
        .socket
        .push_send(SendResult::Error(crate::sockets::ops::Errno::BADF));
    let mut gate = Gate::default();
    let Fixture { routes, sender, .. } = &mut f;
    let done = sender.catch_up(&mut Lent(routes), &mut gate);
    assert_eq!(done.submitted, 0);
    // One route of two: kept for its control path, not a stop.
    assert_eq!(done.failure, None);
    let failures = f.sender.take_failures();
    assert!(
        matches!(failures[0], Some(SenderFailure::Backend { lane: 0, .. })),
        "{failures:?}"
    );
}

/// #317 review P3: copies are staged in position order per route.
#[test]
fn a_copy_out_of_order_is_refused() {
    let mut f = Fixture::new(&[100], 100, 1);
    f.stage(0, 128, 100, 100, &[0]);
    let ticket = f.routes[0].commit(0, 100, 99);
    let copy = RoutedStaged {
        staged: Staged {
            ticket,
            charge: 100,
            len: 100,
        },
        position: 128,
    };
    assert_eq!(
        f.sender.staged(0, 0, copy),
        Err(StageError::OutOfOrder { lane: 0 })
    );
    assert_eq!(f.sender.pending(0, 0), Some(1));
    let mut report = TxReport::new();
    let queue = f.routes[0].queues[0];
    while let Ok(outcome) = f.routes[0].tx.cancel_pending(queue, &mut report) {
        while report.pop_front().is_some() {}
        if !outcome.more {
            break;
        }
    }
}

/// The routes with one of them detached.
struct Detach<'a>(&'a mut [Route], usize);

impl Routes for Detach<'_> {
    type Backend = SocketsTx<ScriptedSocket>;

    fn route(&mut self, route: usize) -> Option<&mut Self::Backend> {
        if route == self.1 {
            return None;
        }
        self.0.get_mut(route).map(|route| &mut route.tx)
    }
}

/// Fake routes: one scripted backend per route.
struct Faked(Vec<crate::lanes::tests::fake::Fake>);

impl Routes for Faked {
    type Backend = crate::lanes::tests::fake::Fake;

    fn route(&mut self, route: usize) -> Option<&mut Self::Backend> {
        self.0.get_mut(route)
    }
}

/// #317 review P2, single-route parity: for every flush outcome of the
/// outcome table, one route reports what `LaneSender` reports: the same
/// failure, stop, inactivity, flushes, service and pending records.
#[test]
fn one_route_reports_every_outcome_as_the_lane_sender() {
    use crate::backend::Release;
    use crate::lanes::tests::fake::{self, Fake, Reply};

    let pending = |cause| Some((TxItemOutcome::Pending { cause }, fake::ticket(0)));
    let os = BackendFailure::Os {
        operation: "sendmmsg",
        errno: 9,
    };
    let invariant = BackendFailure::Invariant {
        operation: "sendmmsg",
    };
    let rows: Vec<Reply> = vec![
        (None, FlushStop::Queue(QueueError::NotActive)),
        (None, FlushStop::Queue(QueueError::UnknownQueue)),
        (None, FlushStop::Queue(QueueError::NeedsReset)),
        (None, FlushStop::Failed(os)),
        (None, FlushStop::Failed(invariant)),
        (None, FlushStop::QueueEmpty),
        (None, FlushStop::HeadExceedsBudget { head_len: 50 }),
        (None, FlushStop::ReportNotEmpty),
        (
            None,
            FlushStop::GateError {
                permitted: 2,
                offered: 1,
            },
        ),
        (
            Some((
                TxItemOutcome::Submitted {
                    release: Release::AtSubmission,
                },
                fake::ticket(9),
            )),
            FlushStop::Exposed,
        ),
        (Some((fake::RETURNED, fake::ticket(0))), FlushStop::Exposed),
        (
            Some((TxItemOutcome::Unknown, fake::ticket(0))),
            FlushStop::Exposed,
        ),
        (pending(PendingCause::GateDenied), FlushStop::Exposed),
        (pending(PendingCause::WouldBlock), FlushStop::Exposed),
        (pending(PendingCause::NoBuffers), FlushStop::Exposed),
        (pending(PendingCause::Interrupted), FlushStop::Exposed),
        (pending(PendingCause::PeerError), FlushStop::Exposed),
        (pending(PendingCause::ErrorLost), FlushStop::Exposed),
        (pending(PendingCause::NotAttempted), FlushStop::Exposed),
        (pending(PendingCause::Failed(os)), FlushStop::Exposed),
        (pending(PendingCause::Failed(invariant)), FlushStop::Exposed),
    ];
    let budget = Budget {
        work: 16,
        bytes: 1000,
    };
    for reply in rows {
        // As `faked`: two lanes, tickets 0 and 2 on lane 0, 1 on lane 1.
        let config = DrrConfig::new(&[100, 100], 100).unwrap();
        let queues = [fake::queue(0), fake::queue(1)];
        let mut plain = LaneSender::new(config, &queues, 4).unwrap();
        let mut routed = RoutedLaneSender::new(config, &[&queues], 4).unwrap();
        for (position, (lane, slot)) in [(0, 0), (0, 2), (1, 1)].into_iter().enumerate() {
            let staged = Staged {
                ticket: fake::ticket(slot),
                charge: 64,
                len: 50,
            };
            plain.staged(lane, staged).unwrap();
            let position = u64::try_from(position).unwrap() * 64;
            routed
                .staged(lane, 0, RoutedStaged { staged, position })
                .unwrap();
        }
        let mut backend = Fake {
            replies: vec![reply].into(),
            flushes: 0,
        };
        let mut gate_a = Gate::default();
        let a = plain.serve(&mut backend, &mut gate_a, budget);
        let mut routes = Faked(vec![Fake {
            replies: vec![reply].into(),
            flushes: 0,
        }]);
        let mut gate_b = Gate::default();
        let b = routed.serve(&mut routes, &mut gate_b, budget);
        assert_eq!(gate_a.left, gate_b.left, "{reply:?}");
        assert_eq!(routed.take_failures(), [None; MAX_ROUTES], "{reply:?}");
        assert_eq!(a.failure, b.failure, "{reply:?}");
        assert_eq!(a.drr.stop, b.drr.stop, "{reply:?}");
        assert_eq!(a.inactive, b.inactive, "{reply:?}");
        assert_eq!(backend.flushes, routes.0[0].flushes, "{reply:?}");
        for lane in 0..2 {
            assert_eq!(
                a.drr.lanes[lane], b.drr.lanes[lane],
                "{reply:?} lane {lane}"
            );
            assert_eq!(plain.pending(lane), routed.pending(lane, 0), "{reply:?}");
            assert_eq!(
                plain.needs_control(lane),
                routed.needs_control(lane, 0),
                "{reply:?}"
            );
        }
    }
}

/// One route's endpoint inactive does not make the call inactive while
/// another route serves.
#[test]
fn one_inactive_route_does_not_stop_the_others() {
    use crate::backend::Release;
    use crate::lanes::tests::fake::{self, Fake};

    let config = DrrConfig::new(&[100], 100).unwrap();
    let queues = [fake::queue(0)];
    let mut routed = RoutedLaneSender::new(config, &[&queues, &queues], 4).unwrap();
    for route in 0..2 {
        let staged = Staged {
            ticket: fake::ticket(u32::try_from(route).unwrap()),
            charge: 64,
            len: 50,
        };
        routed
            .staged(
                0,
                route,
                RoutedStaged {
                    staged,
                    position: 0,
                },
            )
            .unwrap();
    }
    let mut routes = Faked(vec![
        Fake {
            replies: vec![(None, FlushStop::Queue(QueueError::NotActive))].into(),
            flushes: 0,
        },
        Fake {
            replies: vec![(
                Some((
                    TxItemOutcome::Submitted {
                        release: Release::AtSubmission,
                    },
                    fake::ticket(1),
                )),
                FlushStop::Exposed,
            )]
            .into(),
            flushes: 0,
        },
    ]);
    let report = routed.serve(
        &mut routes,
        &mut Gate::default(),
        Budget {
            work: 16,
            bytes: 1000,
        },
    );
    assert!(!report.inactive);
    assert_eq!(report.drr.lanes[0].served_bytes, 64);
    assert_eq!(routed.debited(0), Some(0));
}

/// #317 merge review P3: a failed route takes no more flushes in the call,
/// in `serve` and in `catch_up`, and the first failure of a route is the
/// one kept until the control path takes it.
#[test]
fn a_failed_route_is_flushed_once_per_call_and_keeps_its_first_failure() {
    use crate::backend::Release;
    use crate::lanes::tests::fake::{self, Fake};

    let config = DrrConfig::new(&[100, 100], 100).unwrap();
    let queues = [fake::queue(0), fake::queue(1)];
    let mut routed = RoutedLaneSender::new(config, &[&queues, &queues], 4).unwrap();
    // Route 0: tickets 0 and 1; route 1: tickets 2 and 3; lanes 0 and 1.
    for (route, lane, slot) in [(0, 0, 0), (0, 1, 1), (1, 0, 2), (1, 1, 3)] {
        let staged = Staged {
            ticket: fake::ticket(slot),
            charge: 64,
            len: 50,
        };
        routed
            .staged(
                lane,
                route,
                RoutedStaged {
                    staged,
                    position: 0,
                },
            )
            .unwrap();
    }
    let os = |errno| {
        (
            None,
            FlushStop::Failed(BackendFailure::Os {
                operation: "sendmmsg",
                errno,
            }),
        )
    };
    let submitted = |slot| {
        (
            Some((
                TxItemOutcome::Submitted {
                    release: Release::AtSubmission,
                },
                fake::ticket(slot),
            )),
            FlushStop::Exposed,
        )
    };
    let mut routes = Faked(vec![
        Fake {
            replies: vec![os(9), os(5)].into(),
            flushes: 0,
        },
        Fake {
            replies: vec![submitted(2), submitted(3)].into(),
            flushes: 0,
        },
    ]);
    let budget = Budget {
        work: 16,
        bytes: 1000,
    };
    let report = routed.serve(&mut routes, &mut Gate::default(), budget);
    assert_eq!(report.failure, None);
    assert_eq!(served(&report, 2), [64, 64]);
    assert_eq!(routes.0[0].flushes, 1, "out after its failure in serve");
    // Route 0 lags at the debited position on both lanes; it fails again on
    // lane 0 and takes no flush for lane 1.
    let done = routed.catch_up(&mut routes, &mut Gate::default());
    assert_eq!(done, CatchUp::default());
    assert_eq!(routes.0[0].flushes, 2, "out after its failure in catch_up");
    let failures = routed.take_failures();
    assert!(
        matches!(
            failures[0],
            Some(SenderFailure::Backend {
                lane: 0,
                stop: FlushStop::Failed(BackendFailure::Os { errno: 9, .. })
            })
        ),
        "the first failure is kept: {failures:?}"
    );
    assert_eq!(failures[1], None);
}
