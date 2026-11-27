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
    assert_eq!(h.tx.pending(), Some(1));
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
    // The batched receive read ahead once (EAGAIN); the stopped half makes
    // no further call.
    assert_eq!(h.socket.recv_calls(), 2);
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

/// The counter pattern of the driver: an increment that would overflow
/// leaves the counter unchanged and is counted in `counter overflows`;
/// only an overflow of that count itself is lost.
#[test]
fn a_counter_overflow_is_counted_not_wrapped() {
    use super::super::rx::count_up;
    let (mut counter, mut overflows) = (u64::MAX - 1, 0);
    count_up(&mut counter, &mut overflows);
    assert_eq!((counter, overflows), (u64::MAX, 0));
    count_up(&mut counter, &mut overflows);
    assert_eq!((counter, overflows), (u64::MAX, 1));
    overflows = u64::MAX;
    count_up(&mut counter, &mut overflows);
    assert_eq!((counter, overflows), (u64::MAX, u64::MAX));
    let h = Harness::new();
    assert_eq!((h.tx.counter_overflows(), h.rx.counter_overflows()), (0, 0));
    assert!(h.shutdown().is_empty());
}

use crate::sockets::ops::SocketOps as _;

/// The batched receive of the scripted backend: single receives in order,
/// each result exactly what `recv` returns, stopping after the first error.
#[test]
fn scripted_recv_batch_is_single_receives_in_order() {
    let mut socket = ScriptedSocket::new();
    let observer = socket.observer();
    socket.open(&config()).unwrap();
    let other = SocketAddr::from((Ipv4Addr::LOCALHOST, 7002));
    observer
        .push_recv_datagram(b"one", Some(peer()))
        .push_recv_datagram(&payload(2, 300), Some(other))
        .push_recv_datagram(b"three", None)
        .push_recv_datagram(b"four", Some(peer()));
    let stride = 257;
    let mut slab = vec![0_u8; stride * 8];
    let mut results = [RecvResult::Error(Errno::INVAL); 8];
    // A partial batch: three slots, three datagrams, no error.
    assert_eq!(socket.recv_batch(&mut slab, stride, &mut results[..3]), 3);
    assert_eq!(
        results[..3],
        [
            RecvResult::Datagram {
                len: 3,
                truncated: None,
                source: Some(peer()),
            },
            RecvResult::Datagram {
                len: 257,
                truncated: Some(300),
                source: Some(other),
            },
            RecvResult::Datagram {
                len: 5,
                truncated: None,
                source: None,
            },
        ]
    );
    assert_eq!(&slab[..3], b"one");
    assert_eq!(&slab[stride..2 * stride], &payload(2, 257)[..]);
    assert_eq!(&slab[2 * stride..2 * stride + 5], b"three");
    // The rest, then the error that ends the batch.
    assert_eq!(socket.recv_batch(&mut slab, stride, &mut results), 2);
    assert_eq!(
        results[..2],
        [
            RecvResult::Datagram {
                len: 4,
                truncated: None,
                source: Some(peer()),
            },
            RecvResult::Error(Errno::AGAIN),
        ]
    );
    assert_eq!(observer.recv_calls(), 5);
    // Nothing to fill: no call.
    assert_eq!(socket.recv_batch(&mut slab, stride, &mut []), 0);
    assert_eq!(socket.recv_batch(&mut slab, 0, &mut results), 0);
    assert_eq!(observer.recv_calls(), 5);
    socket.close();
}

/// A handler that stops in the middle of a batch leaves the rest pending:
/// the next poll delivers it, in order, before any new receive call, and
/// the budget still counts one op and one datagram per result.
#[test]
fn rx_results_of_a_batch_stay_pending_across_polls() {
    let mut h = Harness::new();
    let other = SocketAddr::from((Ipv4Addr::LOCALHOST, 7002));
    for at in 0..5_u8 {
        let source = if at % 2 == 0 { peer() } else { other };
        h.socket.push_recv_datagram(&[at; 10], Some(source));
    }
    h.socket.push_recv_datagram(&payload(9, 400), Some(peer()));
    let mut handler = Recorder {
        stop_after: Some(2),
        ..Recorder::default()
    };
    let outcome = h.rx.poll_rx(budget(8), &mut handler);
    assert_eq!(outcome.stop, RxStop::HandlerStopped);
    assert_eq!(
        (
            outcome.delivered,
            outcome.spent.ops,
            outcome.spent.datagrams
        ),
        (2, 2, 2)
    );
    // One batch read all six and the EAGAIN after them.
    assert_eq!(h.socket.recv_calls(), 7);
    handler.stop_after = None;
    // A budget of two takes two pending results and makes no call.
    let outcome = h.rx.poll_rx(budget(2), &mut handler);
    assert_eq!((outcome.stop, outcome.delivered), (RxStop::Budget, 2));
    assert_eq!(h.socket.recv_calls(), 7);
    let outcome = h.rx.poll_rx(budget(8), &mut handler);
    assert_eq!(outcome.stop, RxStop::WouldBlock);
    assert_eq!((outcome.delivered, outcome.dropped), (1, 1));
    assert_eq!(outcome.spent.ops, 3, "two datagrams and the EAGAIN");
    let got: Vec<_> = handler
        .datagrams
        .iter()
        .map(|(bytes, source)| (bytes[0], *source))
        .collect();
    assert_eq!(
        got,
        vec![
            (0, peer()),
            (1, other),
            (2, peer()),
            (3, other),
            (4, peer())
        ]
    );
    assert_eq!(handler.drops.len(), 1);
    // The EAGAIN that stopped it was pending too: still no new call.
    assert_eq!(h.socket.recv_calls(), 7);
}

/// Steady state of the scripted batched receive: once a warm-up batch has
/// run, repeated batches, full and then on an empty script, allocate
/// nothing.
#[test]
fn scripted_recv_batch_does_not_allocate_in_steady_state() {
    let mut socket = ScriptedSocket::new();
    let observer = socket.observer();
    socket.open(&config()).unwrap();
    for at in 0..40_u8 {
        observer.push_recv_datagram(&[at; 10], Some(peer()));
    }
    let stride = 257;
    let mut slab = vec![0_u8; stride * 8];
    let mut results = [RecvResult::Error(Errno::INVAL); 8];
    assert_eq!(socket.recv_batch(&mut slab, stride, &mut results), 8);
    let (filled, allocations) = karyos_sys::alloc_count::count(|| {
        let mut filled = 0;
        for _ in 0..4 {
            filled += socket.recv_batch(&mut slab, stride, &mut results);
        }
        for _ in 0..4 {
            assert_eq!(socket.recv_batch(&mut slab, stride, &mut results), 1);
            assert_eq!(results[0], RecvResult::Error(Errno::AGAIN));
        }
        filled
    });
    assert_eq!((filled, allocations), (32, 0));
    assert_eq!(
        &slab[..10],
        &[32_u8; 10],
        "the last full batch starts at 32"
    );
    socket.close();
}

/// Steady state of the RX path: once a warm-up poll has run, polls that
/// drive `recv_batch`, through full batches, pending results and the empty
/// queue, allocate nothing.
#[test]
fn rx_batched_polls_do_not_allocate_in_steady_state() {
    struct Count(u32);
    impl RxHandler for Count {
        fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
            assert_eq!(datagram.bytes().len(), 10);
            self.0 += 1;
            ControlFlow::Continue(())
        }
        fn dropped(&mut self, _: RxDrop) {}
    }
    let mut h = Harness::new();
    for at in 0..48_u8 {
        h.socket.push_recv_datagram(&[at; 10], Some(peer()));
    }
    // Warm the clock and the scripted lock on the control path.
    let _ = karyos_sys::host_clock::host_monotonic_ns();
    let _ = h.socket.recv_calls();
    let mut handler = Count(0);
    let outcome = h.rx.poll_rx(budget(8), &mut handler);
    assert_eq!(outcome.delivered, 8);
    let (delivered, allocations) = karyos_sys::alloc_count::count(|| {
        let mut delivered = 0;
        // Budgets of 3 split batches, so results stay pending across polls.
        for _ in 0..10 {
            delivered += h.rx.poll_rx(budget(3), &mut handler).delivered;
        }
        for _ in 0..2 {
            delivered += h.rx.poll_rx(budget(8), &mut handler).delivered;
        }
        for _ in 0..4 {
            let outcome = h.rx.poll_rx(budget(8), &mut handler);
            assert_eq!((outcome.stop, outcome.delivered), (RxStop::WouldBlock, 0));
        }
        delivered
    });
    assert_eq!((delivered, allocations, handler.0), (40, 0, 48));
}
