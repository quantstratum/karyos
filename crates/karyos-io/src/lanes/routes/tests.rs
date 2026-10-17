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

/// A gate that permits every candidate unless it denies exposures.
#[derive(Debug, Default)]
struct Gate {
    deny_exposure: bool,
    /// Copies reported gone, by kind (submitted, returned, unknown).
    left: [u32; 3],
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
    assert_eq!(sender.catch_up(&mut Lent(routes), &mut gate), 1);
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
