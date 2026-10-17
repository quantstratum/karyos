// SPDX-License-Identifier: Apache-2.0

//! The data path over the scripted `SocketOps`: what it emits.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use karyos_io::backend::InstanceId;
use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint};
use karyos_io::sockets::ops::SendResult;
use karyos_io::sockets::scripted::ScriptedSocket;
use karyos_protocol::lanes::drr::Budget;
use karyos_protocol::network::{Alias, Datagram, TermParams, classify};
use karyos_sys::log_buffer::{AppendOptions, ClaimOutcome};

use super::EndpointId;
use super::testing::outbound;

/// Everything the data path flushes is a DATA datagram of its alias and
/// lane (a batch of DATA, PAD or ABORTED records): no control can take the
/// data gate, whose only caller reads the log. An aborted claim goes out
/// as its canonical record, never as payload.
#[test]
fn the_data_path_emits_only_data() {
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    observer.set_send_hook(Box::new(move |_, datagrams| {
        for datagram in datagrams {
            record.lock().unwrap().push(datagram.to_vec());
        }
    }));
    for _ in 0..64 {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (mut tx, _rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (mut path, mut log) = outbound(EndpointId(1), alias, destination, term, 1, false);
    let publication = &mut log.publications[0];
    let _ = publication
        .append(&[1u8; 3000], AppendOptions::default())
        .unwrap();
    let ClaimOutcome::Claimed(claim) = publication
        .try_claim(100, AppendOptions::default())
        .unwrap()
    else {
        panic!("not claimed");
    };
    claim.abort();
    let _ = publication
        .append(&[2u8; 200], AppendOptions::default())
        .unwrap();
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for _ in 0..4 {
        let _ = path.serve(&mut tx, budget, None).unwrap();
    }
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 4, "{} datagrams", seen.len());
    for bytes in seen.iter() {
        let Ok(Datagram::DataBatch(data)) = classify(bytes) else {
            panic!("not a DATA datagram: {:?}", classify(bytes));
        };
        assert_eq!(data.alias(), alias);
    }
    assert_eq!(path.counters().records, 1);
    assert!(path.readers()[0].sent_position() > 0);
}

/// A scripted endpoint with `max_queues` queues and two routes, the
/// observer, and a one-lane outbound path with three messages committed.
fn scripted(
    max_queues: u16,
    lanes: u8,
) -> (
    karyos_io::sockets::endpoint::SocketsTx<ScriptedSocket>,
    ScriptedSocket,
    Box<super::Outbound>,
    super::testing::TestLog,
) {
    use std::num::NonZeroU16;

    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let mut local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    local.max_queues = NonZeroU16::new(max_queues).unwrap();
    local.max_routes = NonZeroU16::new(2).unwrap();
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (tx, _rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (path, mut log) = outbound(EndpointId(1), alias, destination, term, lanes, false);
    for i in 0..3u8 {
        let _ = log.publications[0]
            .append(&[i; 300], AppendOptions::default())
            .unwrap();
    }
    (tx, observer, path, log)
}

/// P2-4: a send fault is retried on its queue, which keeps its items; the
/// lane is not wedged and nothing needs a reset.
#[test]
fn a_send_fault_is_retried() {
    use karyos_io::sockets::ops::Errno;

    let (mut tx, observer, mut path, _log) = scripted(4, 1);
    observer.push_send(SendResult::Error(Errno::NETUNREACH));
    for _ in 0..16 {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for _ in 0..6 {
        let _ = path.serve(&mut tx, budget, None).unwrap();
    }
    let counters = path.counters();
    assert_eq!(counters.send_faults, 1);
    assert!(counters.submitted >= 1, "{counters:?}");
    assert!(!path.needs_reset());
    let reader = &path.readers()[0];
    assert_eq!(reader.sent_position(), reader.position());
}

/// P2-5: an open that fails part way closes what it opened, so retrying
/// every cycle never exhausts the endpoint's routes.
#[test]
fn a_failed_open_leaks_nothing() {
    // Two lanes, one queue allowed: the second queue always fails.
    let (mut tx, _observer, mut path, _log) = scripted(1, 2);
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for _ in 0..5 {
        assert_eq!(path.serve(&mut tx, budget, None).unwrap(), 0);
    }
    let counters = path.counters();
    assert_eq!((counters.queue_failures, counters.route_failures), (5, 0));
}
