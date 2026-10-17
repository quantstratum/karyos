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
use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint};
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
    let mut local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    local.max_routes = NonZeroU16::new(2).unwrap();
    // Each path its own instance, so tickets never collide across routes.
    let instance = InstanceId::new(std::num::NonZeroU32::new(id).unwrap());
    let endpoint = SocketsEndpoint::open(&local, instance, socket).unwrap();
    let (tx, _rx) = endpoint.split().unwrap();
    ((EndpointId(id), Half::Tx(Box::new(tx))), observer, seen)
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
