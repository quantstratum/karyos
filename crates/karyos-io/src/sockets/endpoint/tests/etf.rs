// SPDX-License-Identifier: Apache-2.0

//! The etf queue of ADR-0109 over the scripted socket: who may open one,
//! the send time a commit carries, the flush split into runs by route in
//! submission order, a partial run, late reports and the error queue
//! drain.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use super::*;
use crate::backend::{
    CommitError, EtfQueue, FlushStop, PendingCause, QueueError, Reason, Release, TxItemOutcome,
};
use crate::sockets::errqueue::{ErrEntry, TxtimeCode};
use crate::sockets::ops::{Errno, SendResult};

const ETF: EtfQueue = EtfQueue {
    interface: 2,
    priority: 3,
    delta_ns: 300_000,
};

/// The time the scripted `CLOCK_TAI` reads.
const NOW: u64 = 1_000_000;

fn etf_config() -> SocketsConfig {
    SocketsConfig {
        etf_route: true,
        ..config()
    }
}

/// An etf harness: [`etf_config`], one etf queue of 6 to [`peer`] and the
/// scripted clock at [`NOW`].
fn etf_harness() -> Harness {
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let endpoint = SocketsEndpoint::open(&etf_config(), InstanceId::FIRST, socket).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let route = tx.add_route(peer()).unwrap();
    let queue = tx
        .open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route,
            max_pending: nz(6),
            etf: Some(ETF),
        })
        .unwrap();
    observer.set_tai_now_ns(Some(NOW));
    Harness {
        tx,
        rx,
        socket: observer,
        route,
        queue,
    }
}

/// Commits one 10 byte datagram valued and tokened `token`, with `options`.
fn commit(h: &mut Harness, token: u8, options: TxOptions) -> Result<TxTicket, CommitError> {
    let mut frame = h.tx.claim_tx(h.queue, 10).unwrap();
    frame.bytes_mut().copy_from_slice(&payload(token, 10));
    frame
        .commit(Commit {
            len: 10,
            token: SenderToken::new(u64::from(token)),
            options,
        })
        .map_err(|rejected| rejected.error)
}

/// Every send call in order: the socket, the first byte of each datagram
/// and the send time of an `etf` send.
type Log = Arc<Mutex<Vec<(&'static str, Vec<u8>, Option<u64>)>>>;

/// Records every send call in [`Log`].
fn record(h: &Harness) -> Log {
    let log = Arc::new(Mutex::new(Vec::new()));
    let sends = Arc::clone(&log);
    h.socket.set_send_hook(Box::new(move |_, datagrams| {
        let firsts = datagrams.iter().map(|datagram| datagram[0]).collect();
        sends.lock().unwrap().push(("endpoint", firsts, None));
    }));
    let etf = Arc::clone(&log);
    h.socket
        .set_etf_send_hook(Box::new(move |_, datagram, txtime| {
            etf.lock()
                .unwrap()
                .push(("etf", vec![datagram[0]], Some(txtime)));
        }));
    log
}

const fn sent(sent: usize) -> SendResult {
    SendResult::Sent { sent, error: None }
}

const SUBMITTED: TxItemOutcome = TxItemOutcome::Submitted {
    release: Release::AtSubmission,
};

#[test]
fn an_etf_queue_needs_an_etf_route_endpoint_unicast_and_its_socket() {
    // An endpoint not opened for the route refuses it.
    let mut h = Harness::new();
    let etf_queue = TxQueueConfig {
        authority: Authority::FIRST,
        route: h.route,
        max_pending: nz(1),
        etf: Some(ETF),
    };
    assert_eq!(h.tx.open_queue(etf_queue), Err(QueueError::EtfRefused));
    // A send time on an immediate queue stays an unsupported option.
    assert_eq!(
        commit(&mut h, 1, TxOptions::txtime(NOW)),
        Err(CommitError::UnsupportedOption)
    );
    h.shutdown();

    let mut h = etf_harness();
    assert_eq!(h.socket.etf_live(), 1, "the queue owns its etf socket");
    // A multicast destination is refused (ADR-0109 point 5).
    let group =
        h.tx.add_route(SocketAddr::from((Ipv4Addr::new(239, 1, 2, 3), 7002)))
            .unwrap();
    let to_group = TxQueueConfig {
        authority: Authority::FIRST,
        route: group,
        max_pending: nz(1),
        etf: Some(ETF),
    };
    assert_eq!(h.tx.open_queue(to_group), Err(QueueError::EtfRefused));
    // A refused socket option refuses the queue and leaves no queue open.
    let denied = Reason::Denied {
        errno: Errno::PERM.raw(),
    };
    h.socket.push_etf_open(Err(denied));
    let again = TxQueueConfig {
        route: h.route,
        ..to_group
    };
    assert_eq!(
        h.tx.open_queue(again),
        Err(QueueError::EtfUnavailable { reason: denied })
    );
    assert_eq!(h.tx.commitment().queues, 1);
    let second = h.tx.open_queue(again).unwrap();
    assert_eq!(h.socket.etf_live(), 2);
    // Closing an etf queue closes its socket.
    let mut report = TxReport::new();
    let closed = h.tx.close_queue(second, &mut report).unwrap();
    assert!(!closed.more);
    assert_eq!(h.socket.etf_live(), 1);
    // The configuration refuses the route with a multicast group.
    let mut multicast = etf_config();
    multicast.multicast = Some(MulticastConfig::new(
        std::net::IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
        InterfaceSel::Index(1),
    ));
    assert_eq!(
        multicast.validate(),
        Err(OpenError::InvalidConfig {
            field: "etf_route",
            value: 1
        })
    );
    let socket = h.socket.observer();
    h.shutdown();
    assert_eq!(socket.etf_live(), 0, "retiring closes every etf socket");
}

#[test]
fn a_mixed_flush_keeps_submission_order_across_runs() {
    let mut h = etf_harness();
    let log = record(&h);
    // Immediate, two times ahead, one already past, immediate.
    let options = [
        TxOptions::none(),
        TxOptions::txtime(NOW + 2_000),
        TxOptions::txtime(NOW + 1_000),
        TxOptions::txtime(NOW - 1),
        TxOptions::none(),
    ];
    for (token, options) in (1..).zip(options) {
        commit(&mut h, token, options).unwrap();
    }
    h.socket
        .push_send(sent(1))
        .push_etf_send(sent(1))
        .push_etf_send(sent(1))
        .push_send(sent(2));
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcome.stop, FlushStop::Exposed);
    assert_eq!((outcome.submitted, outcome.bytes), (5, 50));
    assert_eq!(outcome.spent.ops, 4, "two batches and two etf sends");
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            ("endpoint", vec![1], None),
            ("etf", vec![2], Some(NOW + 2_000)),
            ("etf", vec![3], Some(NOW + 1_000)),
            ("endpoint", vec![4, 5], None),
        ],
        "runs in submission order; a time already past goes immediately"
    );
    assert!(entries.iter().all(|entry| entry.outcome == SUBMITTED));
    assert_eq!(
        entries.iter().map(|entry| entry.late).collect::<Vec<_>>(),
        [false, false, false, true, false],
        "only the past time is late"
    );
    h.shutdown();
}

#[test]
fn a_partial_run_ends_the_flush_and_the_rest_stays_queued() {
    let mut h = etf_harness();
    let log = record(&h);
    let options = [
        TxOptions::none(),
        TxOptions::txtime(NOW + 1),
        TxOptions::txtime(NOW + 2),
        TxOptions::none(),
    ];
    for (token, options) in (1..).zip(options) {
        commit(&mut h, token, options).unwrap();
    }
    h.socket
        .push_send(sent(1))
        .push_etf_send(sent(1))
        .push_etf_send(SendResult::Error(Errno::AGAIN));
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcome.stop, FlushStop::WouldBlock);
    assert_eq!(outcome.submitted, 2);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>(),
        [
            SUBMITTED,
            SUBMITTED,
            TxItemOutcome::Pending {
                cause: PendingCause::WouldBlock
            },
            TxItemOutcome::Pending {
                cause: PendingCause::NotAttempted
            },
        ]
    );
    assert_eq!(log.lock().unwrap().len(), 3, "the last run was not sent");
    // The next flush takes up the rest in order; the clock is read again,
    // so the third time is now past and goes immediately, late.
    h.socket.set_tai_now_ns(Some(NOW + 5)).push_send(sent(2));
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcome.stop, FlushStop::Exposed);
    assert_eq!(
        entries
            .iter()
            .map(|entry| (entry.token.get(), entry.late))
            .collect::<Vec<_>>(),
        [(3, true), (4, false)]
    );
    assert_eq!(
        log.lock().unwrap().last(),
        Some(&("endpoint", vec![3, 4], None))
    );

    // A partial batch on the endpoint socket ends the flush the same way.
    commit(&mut h, 5, TxOptions::none()).unwrap();
    commit(&mut h, 6, TxOptions::none()).unwrap();
    commit(&mut h, 7, TxOptions::txtime(NOW + 100)).unwrap();
    h.socket.push_send(sent(1));
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcome.stop, FlushStop::ErrorLost);
    assert_eq!(outcome.submitted, 1);
    assert_eq!(
        entries[1].outcome,
        TxItemOutcome::Pending {
            cause: PendingCause::ErrorLost
        }
    );
    assert_eq!(h.socket.etf_send_calls(), 2, "the etf run was not reached");
    let _ = h.shutdown();
}

#[test]
fn without_a_clock_every_timed_datagram_goes_immediately_late() {
    let mut h = etf_harness();
    h.socket.set_tai_now_ns(None);
    commit(&mut h, 1, TxOptions::txtime(u64::MAX)).unwrap();
    h.socket.push_send(sent(1));
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcome.stop, FlushStop::Exposed);
    assert!(entries[0].late);
    assert_eq!(h.socket.etf_send_calls(), 0);
    h.shutdown();
}

#[test]
fn the_error_queue_drains_into_decoded_drops() {
    let mut h = etf_harness();
    let drop = ErrEntry::Txtime {
        txtime_ns: NOW + 7,
        code: TxtimeCode::Missed,
        errno: 62,
    };
    h.socket.push_etf_error(drop);
    let mut out = [ErrEntry::Truncated; 4];
    assert_eq!(h.tx.drain_etf(h.queue, &mut out), Ok(1));
    assert_eq!(out[0], drop);
    assert_eq!(h.tx.drain_etf(h.queue, &mut out), Ok(0));
    // An immediate queue has no error queue to drain.
    let immediate =
        h.tx.open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route: h.route,
            max_pending: nz(1),
            etf: None,
        })
        .unwrap();
    assert_eq!(
        h.tx.drain_etf(immediate, &mut out),
        Err(EtfDrainError::Queue(QueueError::EtfRefused))
    );
    h.shutdown();
}
