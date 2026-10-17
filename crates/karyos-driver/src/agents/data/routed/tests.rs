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

const ALIAS: Alias = Alias {
    session_id: 5,
    stream_id: 6,
};

/// A second publication on the same endpoints (rp-w7a).
const OTHER_ALIAS: Alias = Alias {
    session_id: 7,
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
            assert!(data.alias() == ALIAS || data.alias() == OTHER_ALIAS);
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

/// rp-w4b2a: a guard on a routed publication gates every path. A close
/// that lands while path A sends stops path B's copy, and the aborted
/// copies come back on every path, so nothing stays in flight.
#[test]
fn a_guard_close_stops_every_path() {
    use karyos_sys::applied_epoch::AppliedEpoch;
    use karyos_sys::sync::Ordering;

    let (a, observer_a, seen_a) = path(1, 0);
    let (b, observer_b, seen_b) = path(2, 0);
    sent(&observer_a, 16);
    sent(&observer_b, 16);
    let mut halves = vec![a, b];
    let (mut outbound, _log) = routed(1);
    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(&word.words()[0], 1), Ok(2));
    let cell = Arc::new(AppliedEpoch::new());
    let spec = GuardSpec {
        word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
        cell: Arc::clone(&cell),
        epoch: 2,
        rate: None,
    };
    outbound.guard(spec, 0).unwrap();
    // The close lands as path A's socket sends.
    let closing = Arc::clone(&word);
    observer_a.set_send_hook(Box::new(move |_, _| {
        let _ = karyos_sys::guard::close(&closing.words()[0]);
    }));
    for _ in 0..4 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    assert!(
        seen_a.lock().unwrap().is_empty(),
        "the hook replaced the recorder"
    );
    assert_eq!(observer_a.send_calls(), 1);
    assert!(seen_b.lock().unwrap().is_empty());
    let applied = cell.try_read().unwrap();
    assert_eq!(applied.positions[0], FRAME);
    assert_eq!(applied.in_flight, 0);
    let sender = outbound.routed_sender().unwrap();
    assert_eq!(
        (sender.pending(0, 0), sender.pending(0, 1)),
        (Some(0), Some(0))
    );
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
    // B left on its fault (RP-8); after its backoff (10 ms) it returns on
    // its new epoch (RP-9).
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(false));
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 20_000_000)
        .unwrap();
    let _ = log.publications[0]
        .append(&[9; 1000], AppendOptions::default())
        .unwrap();
    for _ in 0..4 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, 20_000_000)
            .unwrap();
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

/// #331 review (M4): a route waiting for its reset takes no new copies;
/// the datagram is skipped there and goes on the other route.
#[test]
fn a_route_waiting_for_its_reset_takes_no_copy() {
    let (a, observer_a, seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 16);
    sent(&observer_b, 16);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(1);
    // Opened on both, then route B waits for its reset.
    let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    assert_eq!(seen_a.lock().unwrap().len(), 1);
    outbound.routed.as_deref_mut().unwrap().routes[1].needs_reset = true;
    let skipped = outbound
        .routed_sender()
        .unwrap()
        .counters(1)
        .unwrap()
        .skipped;
    let _ = log.publications[0]
        .append(&[1; 1000], AppendOptions::default())
        .unwrap();
    let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    let sender = outbound.routed_sender().unwrap();
    assert_eq!(sender.pending(0, 1), Some(0));
    assert_eq!(sender.counters(1).unwrap().skipped, skipped + 1);
    assert_eq!(seen_a.lock().unwrap().len(), 2);
}

/// #331 review (M6): a copy committed but refused by the sender's record
/// (here a datagram read again below the route's last copy) marks its route
/// for a reset, which then takes nothing more.
#[test]
fn a_refused_copy_marks_its_route_for_a_reset() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, _observer_b, _seen_b, rx_b) = path_rx(2, 4);
    sent(&observer_a, 16);
    let mut halves = vec![a, b];
    let routes = [
        (EndpointId(1), SocketAddr::from(([127, 0, 0, 1], 41_000))),
        (EndpointId(2), SocketAddr::from(([127, 0, 0, 2], 41_000))),
    ];
    let (mut outbound, mut log) = outbound_routed(&routes, ALIAS, TERM, 1, true);
    let _ = log.publications[0]
        .append(&[0; 1000], AppendOptions::default())
        .unwrap();
    // A sends it; B blocks and keeps its copy at position 0.
    let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    assert_eq!(outbound.routed_sender().unwrap().pending(0, 1), Some(1));
    assert!(!outbound.needs_reset());
    // The lane reads position 0 again: B's copy of it is out of order.
    outbound.readers_mut()[0].rewind().unwrap();
    let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    assert_eq!(outbound.counters().staged_refused, 1);
    assert!(outbound.routed.as_deref().unwrap().routes[1].needs_reset);
    assert!(outbound.needs_reset());
    // The reset returns the unrecorded item.
    let _rx_b = reset(&mut halves, 1, rx_b);
}

/// #331 review P3-3: a route waiting for its reset holds no copies that
/// count against a rewind: they will be dropped. A reset of the other route
/// then rewinds the reliable lane, as if it were alone.
#[test]
fn a_resetting_routes_copies_do_not_block_a_rewind() {
    let (a, observer_a, seen_a, rx_a) = path_rx(1, 2);
    let (b, _observer_b, _seen_b, rx_b) = path_rx(2, 8);
    let mut halves = vec![a, b];
    let routes = [
        (EndpointId(1), SocketAddr::from(([127, 0, 0, 1], 41_000))),
        (EndpointId(2), SocketAddr::from(([127, 0, 0, 2], 41_000))),
    ];
    let (mut outbound, mut log) = outbound_routed(&routes, ALIAS, TERM, 1, true);
    let _ = log.publications[0]
        .append(&[0; 1000], AppendOptions::default())
        .unwrap();
    // Staged on both; both block. Then B waits for its reset.
    for _ in 0..2 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    outbound.routed.as_deref_mut().unwrap().routes[1].needs_reset = true;
    let _rx_a = reset(&mut halves, 0, rx_a);
    sent(&observer_a, 32);
    for _ in 0..4 {
        let _ = outbound.serve_routes(&mut halves, BUDGET, None, 0).unwrap();
    }
    assert_eq!(seen_a.lock().unwrap().len(), 1, "A sends it again");
    let _rx_b = reset(&mut halves, 1, rx_b);
}

/// rp-w5a test policy: a 1 ms window, the default 50%, and a minimum of
/// eight datagrams' bytes, so one early skip decides nothing.
fn policy() -> super::super::PathPolicy {
    super::super::PathPolicy {
        lag_limit: 1_000_000,
        skip_percent: 50,
        skip_min_bytes: 8 * FRAME,
        ..super::super::PathPolicy::default()
    }
}

/// Commits `count` more messages of 1000 bytes on lane 0, from `first`.
fn commit(log: &mut TestLog, first: u8, count: u8) {
    for i in first..first + count {
        let _ = log.publications[0]
            .append(&[i; 1000], AppendOptions::default())
            .unwrap();
    }
}

/// RP-8: a path that skips a minority of the window's datagrams is
/// `Degraded` and stays in the live set; one that skips most leaves it,
/// counted, and takes nothing more.
#[test]
fn a_lagging_path_leaves_and_a_microburst_does_not() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, seen_b) = path(2, 0);
    sent(&observer_a, 64);
    sent(&observer_b, 2);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    // Both take every datagram: neither degraded.
    commit(&mut log, 0, 2);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 10)
        .unwrap();
    assert_eq!(outbound.path_state(1), Some((true, false)));
    // B blocks: its queue fills, and later datagrams skip it.
    for _ in 0..16 {
        observer_b.push_send(SendResult::Error(Errno::AGAIN));
    }
    let before = observer_b.send_calls();
    commit(&mut log, 2, 20);
    for now in 20..30 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(outbound.path_state(1), Some((false, false)), "B left");
    assert_eq!(outbound.routed_sender().unwrap().is_live(1), Some(false));
    let counters = outbound.path_counters(1).unwrap();
    assert_eq!(counters.exits, 1);
    assert_eq!(counters.degraded, 1);
    assert_eq!(outbound.path_state(0), Some((true, false)), "A stays");
    // Out of the live set, B takes no copy and no flush.
    let calls = observer_b.send_calls();
    assert!(calls > before);
    commit(&mut log, 22, 2);
    for now in 30..34 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(observer_b.send_calls(), calls);
    assert_eq!(outbound.routed_sender().unwrap().pending(0, 1), Some(0));
    let _ = seen_b;
}

/// RP-8: the last live path never leaves, whatever it skips; and a window
/// with nothing selected (0/0) decides nothing.
#[test]
fn the_last_live_path_never_leaves() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    // A 0/0 window: nothing selected, nothing decided.
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 10)
        .unwrap();
    assert_eq!(outbound.path_state(0), Some((true, false)));
    assert_eq!(outbound.path_state(1), Some((true, false)));
    // B lags and leaves; then A lags too and stays: the live set is never
    // empty.
    for _ in 0..32 {
        observer_b.push_send(SendResult::Error(Errno::AGAIN));
    }
    sent(&observer_a, 64);
    commit(&mut log, 0, 20);
    for now in 20..30 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(false));
    for _ in 0..64 {
        observer_a.push_send(SendResult::Error(Errno::AGAIN));
    }
    commit(&mut log, 20, 20);
    for now in 30..60 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(outbound.path_state(0).map(|state| state.0), Some(true));
    assert_eq!(outbound.path_counters(0).unwrap().exits, 0);
}

/// RP-8: a microburst costs a few skipped datagrams and no exit. B misses
/// one datagram of four (its half absent for a cycle): it is `Degraded`
/// and stays in the live set.
#[test]
fn a_microburst_degrades_without_an_exit() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 16);
    sent(&observer_b, 16);
    let mut halves = vec![a];
    let (mut outbound, mut log) = routed(0);
    // A minimum of four datagrams' bytes: the window below is past it.
    outbound.set_path_policy(super::super::PathPolicy {
        skip_min_bytes: 4 * FRAME,
        ..policy()
    });
    commit(&mut log, 0, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 10)
        .unwrap();
    halves.push(b);
    commit(&mut log, 1, 3);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 20)
        .unwrap();
    assert_eq!(outbound.path_state(1), Some((true, true)), "degraded, live");
    assert_eq!(outbound.path_counters(1).unwrap().exits, 0);
}

/// #16835: the copies a leaving path held alone, above the debited
/// position, are counted: no live path sends them, and the receivers get
/// them by NAK or close the gap by their gap policy.
#[test]
fn a_leaving_paths_lone_copies_are_counted() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    for _ in 0..32 {
        observer_b.push_send(SendResult::Error(Errno::AGAIN));
    }
    sent(&observer_a, 64);
    let mut halves = vec![b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    // Only B is there for the first datagram: A skips it, B holds it.
    commit(&mut log, 0, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 10)
        .unwrap();
    halves.insert(0, a);
    // B stays blocked: the lane waits on B alone, A cannot send. Under
    // `path_lag_limit` (1 ms here) B stays; past it, B leaves (ACS 16856).
    commit(&mut log, 1, 20);
    // Many cycles inside `path_lag_limit`: time decides, not cycles.
    for now in (20..990_000).step_by(20_000) {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(true));
    assert_eq!(observer_a.send_calls(), 0, "the lane waits on B");
    // The next cycle spans the limit from the stall's start.
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1_000_100)
        .unwrap();
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(false));
    assert_eq!(outbound.path_counters(1).unwrap().copies_abandoned, 1);
    // The head moves on: A resumes.
    for now in 1_000_200..1_000_210 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert!(observer_a.send_calls() > 0, "A resumes");
    assert_eq!(outbound.routed_sender().unwrap().pending(0, 1), Some(0));
}

/// #16782 (2): a path's leave settles the guard gate's ring for it, so a
/// close acknowledgement afterwards does not wait on the left path.
#[test]
fn a_close_after_a_leave_does_not_wait_on_the_left_path() {
    use karyos_sys::applied_epoch::AppliedEpoch;
    use karyos_sys::sync::Ordering;

    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    for _ in 0..32 {
        observer_b.push_send(SendResult::Error(Errno::AGAIN));
    }
    sent(&observer_a, 64);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(&word.words()[0], 1), Ok(2));
    let cell = Arc::new(AppliedEpoch::new());
    outbound
        .guard(
            GuardSpec {
                word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
                cell: Arc::clone(&cell),
                epoch: 2,
                rate: None,
            },
            0,
        )
        .unwrap();
    commit(&mut log, 0, 20);
    for now in 10..20 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(false));
    let _ = karyos_sys::guard::close(&word.words()[0]).unwrap();
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 30)
        .unwrap();
    let applied = cell.try_read().unwrap();
    assert_eq!(applied.epoch, 3);
    assert_eq!(applied.in_flight, 0, "nothing waits on the left path");
}

/// RP-9 test policy: backoffs of 10 ns doubling to 40 ns, reset after
/// 100 ns live; leaving by the hook only.
fn return_policy() -> super::super::PathPolicy {
    super::super::PathPolicy {
        backoff_initial: 10,
        backoff_max: 40,
        backoff_reset: 100,
        ..policy()
    }
}

/// RP-9: a flapping path backs off 10, 20, 40 and then 40 again (the
/// maximum), counting every exit and entry.
#[test]
fn a_flapping_path_backs_off_doubling_to_the_maximum() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 64);
    sent(&observer_b, 64);
    let mut halves = vec![a, b];
    let (mut outbound, _log) = routed(0);
    outbound.set_path_policy(return_policy());
    let mut now = 1000;
    for wait in [10u64, 20, 40, 40] {
        outbound.leave_before_serve(1);
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
        assert_eq!(outbound.path_state(1).map(|state| state.0), Some(false));
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now + wait - 1)
            .unwrap();
        assert_eq!(
            outbound.path_state(1).map(|state| state.0),
            Some(false),
            "still waiting at {wait} - 1"
        );
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now + wait)
            .unwrap();
        assert_eq!(
            outbound.path_state(1).map(|state| state.0),
            Some(true),
            "back after {wait}"
        );
        now += wait + 1;
    }
    let counters = outbound.path_counters(1).unwrap();
    assert_eq!((counters.exits, counters.entries), (4, 4));
}

/// RP-9: a returning path bounds `sent_low` only from its first submit;
/// live for `path_backoff_reset`, its wait starts over.
#[test]
fn a_returning_path_counts_from_its_first_submit() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 64);
    sent(&observer_b, 64);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(return_policy());
    // B leaves before serve and holds out while A sends two datagrams.
    outbound.leave_before_serve(1);
    commit(&mut log, 0, 2);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1000)
        .unwrap();
    let a_front = outbound.sent_low(0).unwrap();
    assert_eq!(a_front, 2 * FRAME, "A alone bounds it");
    // Back after 10 ns, but nothing submitted yet: still A's frontier.
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1010)
        .unwrap();
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(true));
    assert_eq!(outbound.sent_low(0), Some(a_front));
    assert!(outbound.routed.as_deref().unwrap().routes[1].returning);
    // B submits from the selection point on: it is live, and bounds it.
    commit(&mut log, 2, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1020)
        .unwrap();
    assert!(!outbound.routed.as_deref().unwrap().routes[1].returning);
    assert_eq!(outbound.sent_low(0), Some(3 * FRAME));
    // Live past the reset, after a submit: its wait starts over.
    assert_eq!(outbound.routed.as_deref().unwrap().routes[1].backoff, 10);
    commit(&mut log, 3, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1200)
        .unwrap();
    assert_eq!(outbound.routed.as_deref().unwrap().routes[1].backoff, 0);
}

/// RP-8: a frame a path skipped counts as passed for its frontier, so
/// `sent_low` is not held at a skipped position.
#[test]
fn a_skipped_frame_passes_the_paths_frontier() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 16);
    sent(&observer_b, 16);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(return_policy());
    outbound.withhold_route(1, 1);
    commit(&mut log, 0, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1000)
        .unwrap();
    assert_eq!(outbound.routed_sender().unwrap().pending(0, 1), Some(0));
    assert_eq!(outbound.sent_low(0), Some(FRAME));
}

/// RP-8 and RP-9: a faulted route leaves while another is live; its queue
/// is not retried until it returns after its backoff, through
/// `retry_queue`, and then it sends again.
#[test]
fn a_faulted_route_leaves_and_returns_by_retry() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, seen_b) = path(2, 0);
    sent(&observer_a, 64);
    observer_b.push_send(SendResult::Error(Errno::NETUNREACH));
    sent(&observer_b, 64);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(return_policy());
    commit(&mut log, 0, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1000)
        .unwrap();
    assert_eq!(
        outbound.path_state(1).map(|state| state.0),
        Some(false),
        "B left"
    );
    let calls = observer_b.send_calls();
    // During its backoff: no retry, no flush.
    commit(&mut log, 1, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1005)
        .unwrap();
    assert_eq!(observer_b.send_calls(), calls);
    assert_eq!(
        outbound.routed_sender().unwrap().needs_control(0, 1),
        Some(true),
        "not retried while it is out"
    );
    // Back after 10 ns: retried, and its next copies go.
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1010)
        .unwrap();
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(true));
    commit(&mut log, 2, 1);
    for now in 1011..1015 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert!(observer_b.send_calls() > calls);
    assert!(!seen_b.lock().unwrap().is_empty());
    assert!(!outbound.needs_reset());
}

/// #350 review P2: a returning path that has not submitted is not live for
/// the leave guard. B leaves and returns while its socket blocks, then A
/// faults: A stays, the last path that can send, and `sent_low` keeps a
/// frontier.
#[test]
fn a_returning_path_does_not_let_the_last_live_one_leave() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(return_policy());
    outbound.leave_before_serve(1);
    commit(&mut log, 0, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1000)
        .unwrap();
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(false));
    // Back after 10 ns; its socket blocks, so it submits nothing.
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1010)
        .unwrap();
    assert!(outbound.routed.as_deref().unwrap().routes[1].returning);
    observer_a.push_send(SendResult::Error(Errno::NETUNREACH));
    commit(&mut log, 1, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1011)
        .unwrap();
    assert_eq!(
        outbound.path_state(0).map(|state| state.0),
        Some(true),
        "A is the last path that can send"
    );
    assert!(outbound.sent_low(0).is_some());
    sent(&observer_a, 64);
    sent(&observer_b, 64);
    for now in 1012..1100 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
}

/// RP-8: room is judged after the cycle's flushes, so a path whose socket
/// takes everything never looks full, however the backend orders its
/// queues: across many cycles it skips nothing and never leaves.
#[test]
fn a_healthy_path_never_looks_full() {
    let (a, observer_a, seen_a) = path(1, 0);
    let (b, observer_b, seen_b) = path(2, 0);
    sent(&observer_a, 256);
    sent(&observer_b, 256);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    // Within one term of the test log (no conductor rotates it here).
    for round in 0..4u8 {
        commit(&mut log, round * 6, 6);
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, 1000 + u64::from(round))
            .unwrap();
    }
    for _ in 0..8 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, 2000)
            .unwrap();
    }
    let sender = outbound.routed_sender().unwrap();
    assert_eq!(sender.counters(0).unwrap().skipped, 0);
    assert_eq!(sender.counters(1).unwrap().skipped, 0);
    assert_eq!(outbound.path_state(1), Some((true, false)));
    assert_eq!(seen_a.lock().unwrap().len(), 24);
    assert_eq!(seen_b.lock().unwrap().len(), 24);
}

/// ACS 17049: a path that leaves while its TX half is detached, and never
/// comes back, does not keep a close from becoming effective: on the close
/// its copies are forgotten through the guard gate. When it does come
/// back, it comes back through a reset, and no forgotten copy is sent.
#[test]
fn a_close_does_not_wait_on_a_detached_left_path() {
    use karyos_sys::applied_epoch::AppliedEpoch;
    use karyos_sys::sync::Ordering;

    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b, rx_b) = path_rx(2, 0);
    for _ in 0..32 {
        observer_b.push_send(SendResult::Error(Errno::AGAIN));
    }
    sent(&observer_a, 64);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(&word.words()[0], 1), Ok(2));
    let cell = Arc::new(AppliedEpoch::new());
    outbound
        .guard(
            GuardSpec {
                word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
                cell: Arc::clone(&cell),
                epoch: 2,
                rate: None,
            },
            0,
        )
        .unwrap();
    // B blocks on its copies; then its half goes and it leaves detached.
    commit(&mut log, 0, 4);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 10)
        .unwrap();
    assert!(outbound.routed_sender().unwrap().pending(0, 1).unwrap() > 0);
    let b_half = halves.pop().unwrap();
    outbound.leave_before_serve(1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 20)
        .unwrap();
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(false));
    let _ = karyos_sys::guard::close(&word.words()[0]).unwrap();
    for now in 30..40 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    let applied = cell.try_read().unwrap();
    assert_eq!(applied.epoch, 3);
    assert_eq!(applied.in_flight, 0, "nothing waits on the detached path");
    assert_eq!(outbound.routed_sender().unwrap().pending(0, 1), Some(0));
    // The leave's cancel found B detached once; the close forgot its
    // copies and attempted no more cancels on it (#350 review).
    let counters = outbound.routed_sender().unwrap().counters(1).unwrap();
    assert_eq!(counters.uncancelled, 1, "{counters:?}");
    assert!(counters.forgotten > 0, "{counters:?}");
    // B's half comes back: the route asks for a reset first.
    let calls = observer_b.send_calls();
    halves.push(b_half);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 40)
        .unwrap();
    assert!(outbound.needs_reset());
    let _rx_b = reset(&mut halves, 1, rx_b);
    for now in 50..60 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert!(!outbound.needs_reset());
    assert_eq!(observer_b.send_calls(), calls, "no forgotten copy is sent");
}

/// #346 review P2-3: several paths can leave in one pass, and the last live
/// one never does. Three paths each take one datagram of three (the others'
/// halves are away): each skipped two thirds, so A and B leave and C stays.
#[test]
fn several_paths_leave_in_one_pass_but_not_the_last() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    let (c, observer_c, _seen_c) = path(3, 0);
    for observer in [&observer_a, &observer_b, &observer_c] {
        sent(observer, 16);
    }
    let routes = [
        (EndpointId(1), SocketAddr::from(([127, 0, 0, 1], 41_000))),
        (EndpointId(2), SocketAddr::from(([127, 0, 0, 2], 41_000))),
        (EndpointId(3), SocketAddr::from(([127, 0, 0, 3], 41_000))),
    ];
    let (mut outbound, mut log) = outbound_routed(&routes, ALIAS, TERM, 1, false);
    outbound.set_path_policy(super::super::PathPolicy {
        skip_min_bytes: 3 * FRAME,
        ..policy()
    });
    let mut halves = [Some(a), Some(b), Some(c)];
    for (i, now) in [(0usize, 10u64), (1, 11), (2, 12)] {
        let mut present = vec![halves[i].take().unwrap()];
        commit(&mut log, u8::try_from(i).unwrap(), 1);
        let _ = outbound
            .serve_routes(&mut present, BUDGET, None, now)
            .unwrap();
        halves[i] = present.pop();
    }
    let live: Vec<bool> = (0..3)
        .map(|route| outbound.path_state(route).unwrap().0)
        .collect();
    assert_eq!(live, [false, false, true], "A and B leave, C stays");
    let mut halves: Vec<_> = halves.into_iter().flatten().collect();
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 13)
        .unwrap();
}

/// #346 review P2-4: a submit resets the stall clock. B holds the lane's
/// two first datagrams alone and is blocked for 60% of `path_lag_limit`.
/// It submits the first and, in the same cycle, still holds the next head
/// alone; blocked for 60% again, it never leaves.
#[test]
fn a_submit_resets_the_stall_clock() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 64);
    let mut halves = vec![b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    // B alone takes p0 and p1, and its socket would block (nothing
    // scripted).
    commit(&mut log, 0, 2);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1_000)
        .unwrap();
    halves.insert(0, a);
    commit(&mut log, 2, 2);
    for now in [2_000, 300_000, 601_000] {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(true));
    // B submits p0: the clock resets, though B still holds p1 alone.
    observer_b.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 602_000)
        .unwrap();
    for now in [604_000, 900_000, 1_204_000] {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(
        outbound.path_state(1).map(|state| state.0),
        Some(true),
        "each stall stayed under the limit"
    );
    sent(&observer_b, 64);
    for now in 1_205_000..1_205_010 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
}

/// #346 delta review (ACS 17096): a route reopened after a reset is ready
/// again. A and B block on p0, A submits it, B resets and is reopened (its
/// copies, and the one that blocked it, dropped). A alone holds p128 and
/// blocks; B, drained, holds p256: the lane waits on A, which leaves after
/// `path_lag_limit`.
#[test]
fn a_reopened_path_is_waited_on_and_the_lone_holder_leaves() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b, rx_b) = path_rx(2, 0);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    commit(&mut log, 0, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 1_000)
        .unwrap();
    observer_a.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 2_000)
        .unwrap();
    assert_eq!(outbound.routed_sender().unwrap().pending(0, 0), Some(0));
    let _rx_b = reset(&mut halves, 1, rx_b);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 3_000)
        .unwrap();
    let b_half = halves.remove(1);
    commit(&mut log, 1, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 4_000)
        .unwrap();
    halves.push(b_half);
    commit(&mut log, 2, 1);
    sent(&observer_b, 64);
    for now in (5_000..1_000_000).step_by(100_000) {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(outbound.path_state(0).map(|state| state.0), Some(true));
    for now in (1_100_000..1_500_000).step_by(100_000) {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(
        outbound.path_state(0).map(|state| state.0),
        Some(false),
        "A held the lane alone past the limit"
    );
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(true));
    assert!(observer_b.send_calls() > 0, "B resumes");
}

/// #346 review P2-2: a shared bottleneck evicts no path. B submits p0 and
/// A blocks on it; B alone takes p1 and blocks too. B holds the lane's head
/// alone, but A, which holds later copies, is blocked as well: neither
/// leaves, however long both sockets would block.
#[test]
fn a_shared_bottleneck_evicts_no_path() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    observer_b.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    commit(&mut log, 0, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 500)
        .unwrap();
    let a_half = halves.remove(0);
    commit(&mut log, 1, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 700)
        .unwrap();
    halves.insert(0, a_half);
    commit(&mut log, 2, 2);
    for now in (1_000..3_000_000).step_by(100_000) {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert_eq!(outbound.path_state(0).map(|state| state.0), Some(true));
    assert_eq!(outbound.path_state(1).map(|state| state.0), Some(true));
    sent(&observer_a, 64);
    sent(&observer_b, 64);
    for now in 3_000_000..3_000_010 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
}

mod validation;
