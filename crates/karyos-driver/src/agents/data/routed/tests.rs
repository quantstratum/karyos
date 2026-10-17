// SPDX-License-Identifier: Apache-2.0

//! A routed publication over scripted endpoints (rp-w4b1).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};

use karyos_io::backend::InstanceId;
use karyos_io::backend::TxReport;
use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint, SocketsRx};
use karyos_io::sockets::ops::{Errno, SendResult};
use karyos_io::sockets::scripted::ScriptedSocket;
use karyos_protocol::lanes::drr::Budget;
use karyos_protocol::network::{Alias, Datagram, TermParams, classify};
use karyos_sys::log_buffer::AppendOptions;

use super::super::super::{EndpointId, Half};
use super::super::testing::{TestLog, outbound_routed};
use super::super::{GuardSpec, Outbound};
use crate::guard_gate::GateError;

const ALIAS: Alias = Alias {
    session_id: 5,
    stream_id: 6,
};

const TERM: TermParams = TermParams {
    term_length: 65_536,
    initial_term_id: 9,
    mtu: 1408,
};

/// The DATA datagrams one socket sent.
type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

/// One scripted path: its TX half, observer and what it sent. The first
/// `blocked` send calls would block: they are not recorded.
fn path(id: u32, blocked: usize) -> ((EndpointId, Half<ScriptedSocket>), ScriptedSocket, Seen) {
    let (half, observer, seen, _rx) = path_rx(id, blocked);
    (half, observer, seen)
}

/// [`path`], keeping its RX half for a reset ([`reset`]).
fn path_rx(
    id: u32,
    blocked: usize,
) -> (
    (EndpointId, Half<ScriptedSocket>),
    ScriptedSocket,
    Seen,
    SocketsRx<ScriptedSocket>,
) {
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let mut blocked = blocked;
    for _ in 0..blocked {
        observer.push_send(SendResult::Error(Errno::AGAIN));
    }
    observer.set_send_hook(Box::new(move |_, datagrams| {
        if let Some(left) = blocked.checked_sub(1) {
            blocked = left;
            return;
        }
        for datagram in datagrams {
            let Ok(Datagram::DataBatch(data)) = classify(datagram) else {
                panic!("not a DATA datagram");
            };
            assert_eq!(data.alias(), ALIAS);
            record.lock().unwrap().push(data.bytes().to_vec());
        }
    }));
    let local = local();
    // Each path its own instance, so tickets never collide across routes.
    let instance = InstanceId::new(std::num::NonZeroU32::new(id).unwrap());
    let endpoint = SocketsEndpoint::open(&local, instance, socket).unwrap();
    let (tx, rx) = endpoint.split().unwrap();
    ((EndpointId(id), Half::Tx(Box::new(tx))), observer, seen, rx)
}

/// Resets the endpoint of `halves[at]` and reopens it at its next epoch,
/// as the endpoint table does; returns its new RX half.
fn reset(
    halves: &mut [(EndpointId, Half<ScriptedSocket>)],
    at: usize,
    rx: SocketsRx<ScriptedSocket>,
) -> SocketsRx<ScriptedSocket> {
    let placeholder = Half::Rx(Box::new(rx));
    let Half::Tx(tx) = std::mem::replace(&mut halves[at].1, placeholder) else {
        panic!("not a TX half");
    };
    let Half::Rx(rx) = std::mem::replace(&mut halves[at].1, Half::Rx(Box::new(dummy_rx()))) else {
        panic!("not an RX half");
    };
    let mut endpoint = SocketsEndpoint::join(*tx, *rx).ok().unwrap();
    let mut report = TxReport::new();
    while endpoint.reset(&mut report).more {
        while report.pop_front().is_some() {}
    }
    while report.pop_front().is_some() {}
    let local = local();
    let _ = endpoint.reopen(&local).unwrap();
    let (tx, rx) = endpoint.split().unwrap();
    halves[at].1 = Half::Tx(Box::new(tx));
    rx
}

/// Each path's endpoint: two routes, and two queues (one lane and the
/// repair queue), so a second open of the lane queues would fail.
fn local() -> SocketsConfig {
    let mut local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    local.max_routes = NonZeroU16::new(2).unwrap();
    local.max_queues = NonZeroU16::new(2).unwrap();
    local
}

/// An RX half of a throwaway endpoint, a placeholder while one is reset.
fn dummy_rx() -> SocketsRx<ScriptedSocket> {
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, ScriptedSocket::new()).unwrap();
    endpoint.split().unwrap().1
}

fn sent(observer: &ScriptedSocket, times: usize) {
    for _ in 0..times {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
}

/// Two paths, A (endpoint 1) and A2 (endpoint 2), each toward its own
/// destination, with `messages` of 1000 bytes (one per datagram) committed on one lane.
fn routed(messages: u8) -> (Box<Outbound>, TestLog) {
    let routes = [
        (EndpointId(1), SocketAddr::from(([127, 0, 0, 1], 41_000))),
        (EndpointId(2), SocketAddr::from(([127, 0, 0, 2], 41_000))),
    ];
    let (outbound, mut log) = outbound_routed(&routes, ALIAS, TERM, 1, false);
    for i in 0..messages {
        let _ = log.publications[0]
            .append(&[i; 1000], AppendOptions::default())
            .unwrap();
    }
    (outbound, log)
}

/// One message's aligned frame: its 32 byte header and 1000 bytes.
const FRAME: u64 = 1056;

const BUDGET: Budget = Budget {
    work: 64,
    bytes: 1 << 20,
};

/// A routed publication refuses a guard until rp-w4b2 gates every
/// route's exposure (ACS 16423): no path can bypass a close.
#[test]
fn a_guard_on_a_routed_publication_is_refused() {
    use karyos_sys::applied_epoch::AppliedEpoch;
    use karyos_sys::sync::Ordering;

    let (mut outbound, _log) = routed(0);
    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(&word.words()[0], 1), Ok(2));
    let spec = GuardSpec {
        word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
        cell: Arc::new(AppliedEpoch::new()),
        epoch: 2,
        rate: None,
    };
    assert_eq!(outbound.guard(spec, 0), Err(GateError::Routed));
    assert!(outbound.guard_gate().is_none());
}

/// Each committed datagram goes out once on each path, in order; the
/// lane is debited once per datagram and the sent frontier is the
/// highest position submitted.
#[test]
fn every_datagram_goes_on_both_paths_once() {
    let (a, observer_a, seen_a) = path(1, 0);
    let (b, observer_b, seen_b) = path(2, 0);
    sent(&observer_a, 16);
    sent(&observer_b, 16);
    let mut halves = vec![a, b];
    let (mut outbound, _log) = routed(3);
    assert!(outbound.is_routed());
    assert_eq!(
        outbound.route_endpoints().collect::<Vec<_>>(),
        [EndpointId(1), EndpointId(2)]
    );
    for _ in 0..4 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    let seen_a = seen_a.lock().unwrap().clone();
    let seen_b = seen_b.lock().unwrap().clone();
    assert_eq!(seen_a.len(), 3);
    assert_eq!(seen_a, seen_b);
    // In order: message `i` is filled with `i`, after its 32 byte header.
    for (i, bytes) in seen_a.iter().enumerate() {
        assert_eq!(usize::from(bytes[32]), i);
    }
    let sender = outbound.routed_sender().unwrap();
    assert_eq!(sender.debited(0), Some(2 * FRAME));
    assert_eq!(sender.counters(0).unwrap().skipped, 0);
    assert_eq!(sender.counters(1).unwrap().skipped, 0);
    let frontier = outbound.readers()[0].sent_position();
    assert_eq!(frontier, 3 * FRAME);
}

/// A path that would block falls behind and catches up: it sends every
/// datagram afterwards, counted late, while the frontier never moves
/// back and nothing is debited twice.
#[test]
fn a_blocked_path_catches_up_without_a_second_debit() {
    let (a, observer_a, seen_a) = path(1, 0);
    let (b, observer_b, seen_b) = path(2, 8);
    sent(&observer_a, 16);
    let mut halves = vec![a, b];
    let (mut outbound, _log) = routed(3);
    let mut frontier = 0;
    for _ in 0..4 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
        let now = outbound.sent_high(0).unwrap();
        assert!(now >= frontier);
        frontier = now;
    }
    assert_eq!(seen_a.lock().unwrap().len(), 3);
    assert!(seen_b.lock().unwrap().is_empty());
    let debited = outbound.routed_sender().unwrap().debited(0);
    assert!(debited.is_some());
    sent(&observer_b, 16);
    // Each call catches up at most one copy per route and lane, after the
    // blocked calls left in its script.
    for _ in 0..16 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
        let now = outbound.sent_high(0).unwrap();
        assert!(now >= frontier);
        frontier = now;
    }
    assert_eq!(*seen_b.lock().unwrap(), *seen_a.lock().unwrap());
    let sender = outbound.routed_sender().unwrap();
    assert_eq!(sender.debited(0), debited);
    assert_eq!(sender.counters(1).unwrap().late, 3);
    assert_eq!(sender.counters(0).unwrap().late, 0);
    assert_eq!(frontier, 3 * FRAME);
    assert_eq!(outbound.readers()[0].sent_position(), 3 * FRAME);
}

/// A path without a TX half this cycle (its endpoint is resetting) does
/// not stop the other: the publication goes on the path it has.
#[test]
fn a_missing_path_does_not_stop_the_other() {
    let (a, observer_a, seen_a) = path(1, 0);
    sent(&observer_a, 16);
    let mut halves = vec![a];
    let (mut outbound, _log) = routed(2);
    for _ in 0..4 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    assert_eq!(seen_a.lock().unwrap().len(), 2);
    let sender = outbound.routed_sender().unwrap();
    assert_eq!(sender.counters(1).unwrap().skipped, 2);
    assert_eq!(outbound.readers()[0].sent_position(), 2 * FRAME);
}

/// #321 review P1: with path B absent and path A blocked, no frame is read
/// that no path can take. Once A unblocks, every message goes out on it, in
/// order: none is lost.
#[test]
fn no_frame_is_lost_while_no_path_can_take_it() {
    let (a, observer_a, seen_a) = path(1, 8);
    let mut halves = vec![a];
    let (mut outbound, _log) = routed(20);
    // Every send would block: A's queue fills, B has no half.
    for _ in 0..8 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    assert_eq!(observer_a.send_calls(), 8);
    sent(&observer_a, 64);
    for _ in 0..40 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    let seen = seen_a.lock().unwrap().clone();
    assert_eq!(seen.len(), 20);
    for (i, bytes) in seen.iter().enumerate() {
        assert_eq!(usize::from(bytes[32]), i);
    }
    assert_eq!(outbound.counters().queue_failures, 0);
}

/// #321 review P3 (M7): copies leave out of order across routes within one
/// call: route A submits two positions, then route B catches up the first.
/// The sent frontier is the highest, and no copy reads as mismatched.
#[test]
fn copies_leaving_out_of_order_across_routes_keep_the_frontier() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, seen_b) = path(2, 1);
    sent(&observer_a, 16);
    sent(&observer_b, 16);
    let mut halves = vec![a, b];
    let (mut outbound, _log) = routed(2);
    // One call: B blocks in serve, A sends both, B catches up the first.
    let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    assert_eq!(seen_b.lock().unwrap().len(), 1);
    assert_eq!(outbound.sent_high(0), Some(2 * FRAME));
    for _ in 0..4 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    assert_eq!(seen_b.lock().unwrap().len(), 2);
    assert_eq!(outbound.sent_high(0), Some(2 * FRAME));
    assert_eq!(outbound.counters().mismatched, 0);
}

/// #321 review P2: a failed route resets only its own endpoint. Path B's
/// half fails; only B's endpoint is asked for a reset, once per request
/// cycle, while A keeps sending. B's new epoch clears it, and B takes the
/// frames from the current selection point on.
#[test]
fn a_failed_route_resets_only_its_endpoint() {
    let (a, observer_a, seen_a) = path(1, 0);
    let (b, observer_b, seen_b, rx_b) = path_rx(2, 0);
    observer_b.push_send(SendResult::Error(Errno::BADF));
    sent(&observer_a, 32);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(2);
    for _ in 0..4 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    assert_eq!(seen_a.lock().unwrap().len(), 2);
    // One attempt on B, which failed; its half stays stopped.
    assert_eq!(observer_b.send_calls(), 1);
    assert!(outbound.needs_reset());
    let mut posted = Vec::new();
    let done = outbound.post_reset_requests(0, |endpoint| {
        posted.push(endpoint);
        true
    });
    assert_eq!(done, (1, 0));
    assert_eq!(posted, [EndpointId(2)]);
    // Not due again within the request cycles.
    assert_eq!(outbound.post_reset_requests(1, |_| true), (0, 0));
    let _rx_b = reset(&mut halves, 1, rx_b);
    sent(&observer_b, 32);
    let _ = log.publications[0]
        .append(&[9; 1000], AppendOptions::default())
        .unwrap();
    for _ in 0..4 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    assert!(!outbound.needs_reset());
    assert_eq!(seen_a.lock().unwrap().len(), 3);
    let seen_b = seen_b.lock().unwrap();
    // The failed attempt, then only the new message: B rejoins at the
    // selection point.
    assert_eq!(seen_b.len(), 2, "B rejoins at the selection point");
    assert_eq!(seen_b[1][32], 9);
}

/// #321 review P2: after a routed reset that leaves no route holding a
/// reliable lane's copies, the lane reads again from its registered
/// position, as on one path: nothing is lost. Unreliable, the gap stays for
/// the receivers' gap policy.
#[test]
fn a_reset_with_no_copy_left_rewinds_a_reliable_lane() {
    for reliable in [true, false] {
        let (a, observer_a, seen_a, rx_a) = path_rx(1, 2);
        let mut halves = vec![a];
        let routes = [(EndpointId(1), SocketAddr::from(([127, 0, 0, 1], 41_000)))];
        let (mut outbound, mut log) = outbound_routed(&routes, ALIAS, TERM, 1, reliable);
        for i in 0..2u8 {
            let _ = log.publications[0]
                .append(&[i; 1000], AppendOptions::default())
                .unwrap();
        }
        // Both datagrams staged; the socket blocks.
        for _ in 0..2 {
            let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
        }
        assert!(seen_a.lock().unwrap().is_empty());
        let _rx_a = reset(&mut halves, 0, rx_a);
        sent(&observer_a, 32);
        for _ in 0..4 {
            let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
        }
        let seen = seen_a.lock().unwrap().len();
        assert_eq!(seen, if reliable { 2 } else { 0 }, "reliable {reliable}");
    }
}

/// #321 review P2: repair on a routed publication uses the founding route
/// opened by `open_routes`, never a second route: staging stays in step.
#[test]
fn repair_on_a_routed_publication_opens_no_second_route() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 32);
    sent(&observer_b, 32);
    let mut halves = vec![a, b];
    let routes = [
        (EndpointId(1), SocketAddr::from(([127, 0, 0, 1], 41_000))),
        (EndpointId(2), SocketAddr::from(([127, 0, 0, 2], 41_000))),
    ];
    let (mut outbound, mut log) = outbound_routed(&routes, ALIAS, TERM, 1, true);
    let identity = karyos_protocol::network::Identity {
        driver_id: [1, 2],
        registration_id: 1,
        incarnation: 1,
    };
    outbound
        .enable_repair(
            &crate::agents::repair::RepairConfig::default(),
            TERM.term_length,
            identity,
        )
        .unwrap();
    let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    let Half::Tx(tx) = &mut halves[0].1 else {
        panic!("not a TX half");
    };
    let mut budget = crate::repair::scheduler::RepairBudget::default();
    let _ = outbound.serve_repair(tx, &mut budget, 0);
    assert_eq!(outbound.counters().queue_failures, 0);
    let _ = log.publications[0]
        .append(&[5; 1000], AppendOptions::default())
        .unwrap();
    for _ in 0..4 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    assert_eq!(outbound.counters().staged_refused, 0);
    assert!(!outbound.needs_reset());
}

/// A reset of one route while another still holds a reliable lane's
/// copies does not rewind: the other route sends them, and the reset
/// route rejoins at the selection point (RP-9).
#[test]
fn a_reset_while_another_route_holds_the_copies_does_not_rewind() {
    let (a, observer_a, seen_a) = path(1, 2);
    let (b, observer_b, seen_b, rx_b) = path_rx(2, 2);
    let mut halves = vec![a, b];
    let routes = [
        (EndpointId(1), SocketAddr::from(([127, 0, 0, 1], 41_000))),
        (EndpointId(2), SocketAddr::from(([127, 0, 0, 2], 41_000))),
    ];
    let (mut outbound, mut log) = outbound_routed(&routes, ALIAS, TERM, 1, true);
    let _ = log.publications[0]
        .append(&[0; 1000], AppendOptions::default())
        .unwrap();
    // Staged on both; both sockets block.
    for _ in 0..2 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    let _rx_b = reset(&mut halves, 1, rx_b);
    sent(&observer_a, 32);
    sent(&observer_b, 32);
    for _ in 0..4 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    assert_eq!(seen_a.lock().unwrap().len(), 1);
    assert!(seen_b.lock().unwrap().is_empty(), "no rewind onto B");
}

/// #321 merge review: two paths on one endpoint are refused, since each
/// route's TX half is found by its endpoint; so are no path and more than
/// four.
#[test]
fn routes_need_their_own_endpoints() {
    use super::super::OutboundError;

    let at = |id: u32, host: u8| {
        (
            EndpointId(id),
            SocketAddr::from(([127, 0, 0, host], 41_000)),
        )
    };
    assert_eq!(super::check_routes(&[at(1, 1), at(2, 2)]), Ok(()));
    assert_eq!(
        super::check_routes(&[at(1, 1), at(1, 2)]),
        Err(OutboundError::Routes)
    );
    assert_eq!(
        super::check_routes(&[at(1, 1), at(2, 2), at(1, 3)]),
        Err(OutboundError::Routes)
    );
    assert_eq!(super::check_routes(&[]), Err(OutboundError::Routes));
    let five: Vec<_> = (1..=5).map(|id| at(id, 1)).collect();
    assert_eq!(super::check_routes(&five), Err(OutboundError::Routes));
}
