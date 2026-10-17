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
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
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
