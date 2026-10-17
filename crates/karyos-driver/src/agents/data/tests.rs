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
