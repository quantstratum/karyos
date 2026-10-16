// SPDX-License-Identifier: Apache-2.0

//! RX rows of section 12: budget admission, truncation drops, storms,
//! transient errors and the handler borrow.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use crate::backend::{
    BackendFailure, ClockDomain, ClockEpoch, ObservationPoint, RxDropReason, RxStop,
};
use crate::sockets::ops::{Errno, RecvResult, SendResult};

/// A budget that admits `datagrams` datagrams of 256 bytes.
fn budget(datagrams: u32) -> Budget {
    Budget::new(datagrams, u64::from(datagrams) * 256, datagrams)
}

#[test]
fn rx_byte_budget() {
    let mut h = Harness::new();
    h.socket.push_recv_datagram(b"one", Some(peer()));
    let mut handler = Recorder::default();
    // Below max_datagram: no receive call.
    let outcome = h.rx.poll_rx(Budget::new(10, 255, 10), &mut handler);
    assert_eq!(outcome.stop, RxStop::Budget);
    assert_eq!(outcome.spent, Spent::default());
    assert_eq!(h.socket.recv_calls(), 0);
    // A zero budget changes nothing either.
    let outcome = h.rx.poll_rx(Budget::new(0, 0, 0), &mut handler);
    assert_eq!((outcome.stop, h.socket.recv_calls()), (RxStop::Budget, 0));
    // Exactly one datagram's room: one receive, then Budget.
    let outcome = h.rx.poll_rx(Budget::new(10, 256, 10), &mut handler);
    assert_eq!(outcome.stop, RxStop::Budget);
    assert_eq!(outcome.delivered, 1);
    assert_eq!(outcome.spent.bytes, 3);
    assert_eq!(handler.datagrams, vec![(b"one".to_vec(), peer())]);
    assert_eq!(h.socket.recv_calls(), 1);
}

#[test]
fn rx_oversize_scripted() {
    let mut h = Harness::new();
    // Linux: MSG_TRUNC reports the true length.
    h.socket.push_recv_datagram(&payload(1, 9000), Some(peer()));
    // macOS: a read that fills the max_datagram + 1 buffer, no length.
    h.socket.push_recv(
        RecvResult::Datagram {
            len: 257,
            truncated: None,
            source: Some(peer()),
        },
        &payload(2, 257),
    );
    // Exactly max_datagram is delivered whole.
    h.socket.push_recv_datagram(&payload(3, 256), Some(peer()));
    let mut handler = Recorder::default();
    let outcome = h.rx.poll_rx(budget(8), &mut handler);
    assert_eq!(outcome.stop, RxStop::WouldBlock);
    assert_eq!((outcome.delivered, outcome.dropped), (1, 2));
    assert_eq!(outcome.spent.datagrams, 3);
    assert_eq!(outcome.spent.ops, 4, "three datagrams and the EAGAIN");
    assert_eq!(outcome.spent.bytes, 256, "drops spend no bytes");
    assert_eq!(
        handler
            .drops
            .iter()
            .map(|drop| drop.reason)
            .collect::<Vec<_>>(),
        vec![
            RxDropReason::Oversize {
                limit: 256,
                received: Some(9000)
            },
            RxDropReason::Oversize {
                limit: 256,
                received: None
            }
        ]
    );
    assert_eq!(handler.datagrams.len(), 1, "never delivered short");
    assert_eq!(handler.datagrams[0].0, payload(3, 256));
}

#[test]
fn rx_unsupported_source_and_invariant() {
    let mut h = Harness::new();
    h.socket.push_recv_datagram(b"x", None);
    h.socket.push_recv(
        RecvResult::Datagram {
            len: 9000,
            truncated: None,
            source: Some(peer()),
        },
        &[],
    );
    let mut handler = Recorder::default();
    let outcome = h.rx.poll_rx(budget(8), &mut handler);
    assert_eq!(handler.drops[0].reason, RxDropReason::UnsupportedSource);
    assert_eq!(
        outcome.stop,
        RxStop::Failed(BackendFailure::Invariant { operation: "recv" }),
        "a length above the buffer is outside the ABI"
    );
}

#[test]
fn rx_storm() {
    let mut h = Harness::new();
    for _ in 0..100 {
        h.socket.push_recv_datagram(&payload(0, 300), Some(peer()));
    }
    let mut handler = Recorder::default();
    let outcome = h.rx.poll_rx(Budget::new(1000, 1_000_000, 16), &mut handler);
    assert_eq!(outcome.stop, RxStop::Budget);
    assert_eq!(outcome.spent.ops, 16);
    assert_eq!(outcome.dropped, 16);
    assert_eq!(h.socket.recv_calls(), 16, "stops at the op budget");
    // The datagram budget bounds drops too.
    let outcome = h.rx.poll_rx(Budget::new(5, 1_000_000, 1000), &mut handler);
    assert_eq!((outcome.stop, outcome.dropped), (RxStop::Budget, 5));
}

#[test]
fn rx_transient_errors() {
    let mut h = Harness::new();
    h.commit_n(0, 1);
    let mut handler = Recorder::default();
    for (errno, stop) in [
        (Errno::NOBUFS, RxStop::NoBuffers),
        (Errno::NOMEM, RxStop::NoBuffers),
        (Errno::AGAIN, RxStop::WouldBlock),
        (Errno::INTR, RxStop::Interrupted),
    ] {
        h.socket.push_recv(RecvResult::Error(errno), &[]);
        let outcome = h.rx.poll_rx(budget(8), &mut handler);
        assert_eq!(outcome.stop, stop, "{errno:?}");
        assert_eq!(outcome.spent.ops, 1, "one op: {errno:?}");
    }
    // The TX half is untouched and nothing was reset.
    assert_eq!(h.tx.pending(), 1);
    h.socket.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    assert_eq!(h.flush(&mut Gate::default()).0.submitted, 1);
    // ECONNREFUSED is counted and the poll continues.
    h.socket
        .push_recv(RecvResult::Error(Errno::CONNREFUSED), &[]);
    h.socket.push_recv_datagram(b"after", Some(peer()));
    let outcome = h.rx.poll_rx(budget(8), &mut handler);
    assert_eq!(outcome.delivered, 1);
    assert_eq!(outcome.spent.ops, 3);
    assert_eq!(h.rx.peer_errors(), 1);
    // EBADF, EPERM and the rest fail the half: rx_failed_stops_the_half.
    h.shutdown();
}

/// Review P3-2: a `Failed` result stops the RX half (3.10). Later polls
/// return the same failure with no system call until reset and reopen;
/// the TX half keeps working.
#[test]
fn rx_failed_stops_the_half() {
    for errno in [Errno::BADF, Errno::PERM, Errno::ACCES, Errno::INVAL] {
        let mut h = Harness::new();
        let failed = RxStop::Failed(BackendFailure::Os {
            operation: "recv",
            errno: errno.raw(),
        });
        let mut handler = Recorder::default();
        h.socket.push_recv(RecvResult::Error(errno), &[]);
        h.socket.push_recv_datagram(b"later", Some(peer()));
        let outcome = h.rx.poll_rx(budget(8), &mut handler);
        assert_eq!(outcome.stop, failed, "{errno:?}");
        assert_eq!(outcome.spent.ops, 1);
        let outcome = h.rx.poll_rx(budget(8), &mut handler);
        assert_eq!(outcome.stop, failed, "stopped: {errno:?}");
        assert_eq!(outcome.spent, Spent::default());
        assert_eq!(h.socket.recv_calls(), 1, "no system call after Failed");
        assert!(handler.datagrams.is_empty());
        // The TX half is not stopped.
        h.commit_n(0, 1);
        h.socket.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
        assert_eq!(h.flush(&mut Gate::default()).0.submitted, 1);
        // Reset and reopen clear the failure.
        let (mut endpoint, socket) = h.join();
        reset_all(&mut endpoint);
        endpoint.reopen(&config()).unwrap();
        let (tx, mut rx) = endpoint.split().unwrap();
        let outcome = rx.poll_rx(budget(8), &mut handler);
        assert_eq!(outcome.delivered, 1, "{errno:?}");
        assert_eq!(socket.recv_calls(), 3, "the datagram, then EAGAIN");
        let mut endpoint = SocketsEndpoint::join(tx, rx).unwrap();
        retire_all(&mut endpoint);
    }
    // An invariant fault stops the half as well.
    let mut h = Harness::new();
    h.socket.push_recv(
        RecvResult::Datagram {
            len: 9000,
            truncated: None,
            source: Some(peer()),
        },
        &[],
    );
    let invariant = RxStop::Failed(BackendFailure::Invariant { operation: "recv" });
    let mut handler = Recorder::default();
    assert_eq!(h.rx.poll_rx(budget(8), &mut handler).stop, invariant);
    assert_eq!(h.rx.poll_rx(budget(8), &mut handler).stop, invariant);
    assert_eq!(h.socket.recv_calls(), 1);
}

#[test]
fn rx_borrow_and_unwind() {
    struct Panicking;
    impl RxHandler for Panicking {
        fn datagram(&mut self, _: RxDatagram<'_>) -> ControlFlow<()> {
            panic!("handler failure");
        }
        fn dropped(&mut self, _: RxDrop) {}
    }
    let mut h = Harness::new();
    h.socket.push_recv_datagram(b"first", Some(peer()));
    h.socket.push_recv_datagram(b"second", Some(peer()));
    let result = catch_unwind(AssertUnwindSafe(|| h.rx.poll_rx(budget(8), &mut Panicking)));
    assert!(result.is_err());
    // The half is usable; the next poll receives the next datagram.
    let mut handler = Recorder {
        stop_after: Some(1),
        ..Recorder::default()
    };
    let outcome = h.rx.poll_rx(budget(8), &mut handler);
    assert_eq!(outcome.stop, RxStop::HandlerStopped);
    assert_eq!(handler.datagrams, vec![(b"second".to_vec(), peer())]);
}

#[test]
fn rx_datagram_metadata_and_observation() {
    let mut cfg = config();
    cfg.rx_observation = true;
    cfg.clock_epoch = ClockEpoch::new(7);
    cfg.path = crate::backend::PathId::new(3);
    let mut h = Harness::open(cfg, 1);
    h.socket.push_recv_datagram(b"x", Some(peer()));
    struct Check;
    impl RxHandler for Check {
        fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
            assert_eq!(datagram.path().get(), 3);
            assert_eq!(datagram.epoch(), BackendEpoch::FIRST);
            let observation = datagram.observation().unwrap();
            assert_eq!(observation.point, ObservationPoint::RecvReturn);
            assert_eq!(observation.domain, ClockDomain::HostMonotonic);
            assert_eq!(observation.epoch, ClockEpoch::new(7));
            assert_eq!(observation.uncertainty_ns, 1);
            ControlFlow::Continue(())
        }
        fn dropped(&mut self, _: RxDrop) {}
    }
    assert_eq!(h.rx.poll_rx(budget(2), &mut Check).delivered, 1);
}
