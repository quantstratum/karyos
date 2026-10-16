// SPDX-License-Identifier: Apache-2.0

//! TX rows of section 12: claim and commit, queues, the gate, flush
//! results, the errno table and invariant faults.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::backend::{
    BackendFailure, Capability, CapabilityState, ClaimError, CommitError, CommitRejected,
    FlushStop, PendingCause, QueueError, Reason, Release, ReturnReason, RouteError, SendError,
    TxItemOutcome,
};
use crate::sockets::ops::{Errno, SendResult};

const SUBMITTED: TxItemOutcome = TxItemOutcome::Submitted {
    release: Release::AtSubmission,
};

fn pending(cause: PendingCause) -> TxItemOutcome {
    TxItemOutcome::Pending { cause }
}

fn outcomes(entries: &[TxEntry]) -> Vec<TxItemOutcome> {
    entries.iter().map(|entry| entry.outcome).collect()
}

fn tokens(entries: &[TxEntry]) -> Vec<u64> {
    entries.iter().map(|entry| entry.token.get()).collect()
}

#[test]
fn claim_commit_drop_scripted() {
    let mut h = Harness::open(config(), 1);
    // A rejected commit returns the same frame with its bytes.
    {
        let mut frame = h.tx.claim_tx(h.queue, 4).unwrap();
        assert_eq!(frame.capacity(), 4);
        frame.bytes_mut().copy_from_slice(b"abcd");
        let CommitRejected { mut frame, error } = frame
            .commit(Commit {
                len: 5,
                token: SenderToken::new(1),
                options: TxOptions::none(),
            })
            .unwrap_err();
        assert_eq!(
            error,
            CommitError::LengthExceedsClaim {
                len: 5,
                capacity: 4
            }
        );
        assert_eq!(frame.bytes_mut(), b"abcd");
        let CommitRejected { frame, error } = frame
            .commit(Commit {
                len: 0,
                token: SenderToken::new(1),
                options: TxOptions::none(),
            })
            .unwrap_err();
        assert_eq!(error, CommitError::Empty);
        // Dropping the returned frame frees the claim.
        drop(frame);
    }
    // A dropped frame frees its slot and queue charge.
    let frame = h.tx.claim_tx(h.queue, 4).unwrap();
    drop(frame);
    assert_eq!(h.tx.pending(), 0);
    // Committing a prefix of the claim sends exactly that prefix.
    let mut frame = h.tx.claim_tx(h.queue, 8).unwrap();
    frame.bytes_mut().copy_from_slice(b"01234567");
    let ticket = frame
        .commit(Commit {
            len: 3,
            token: SenderToken::new(9),
            options: TxOptions::none(),
        })
        .unwrap();
    assert!(h.tx.is_pending(ticket));
    assert_eq!(h.socket.send_calls(), 0, "nothing is submitted by a commit");
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    h.socket.set_send_hook(Box::new(move |_, datagrams| {
        record
            .lock()
            .unwrap()
            .extend(datagrams.iter().map(|datagram| datagram.to_vec()));
    }));
    h.socket.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcome.stop, FlushStop::Exposed);
    assert_eq!((outcome.submitted, outcome.bytes), (1, 3));
    assert_eq!(entries[0].ticket, ticket);
    assert_eq!(entries[0].len, 3);
    assert_eq!(*seen.lock().unwrap(), vec![b"012".to_vec()]);
    assert!(!h.tx.is_pending(ticket));
}

#[test]
fn claim_error_order() {
    let mut h = Harness::open(config(), 1);
    let stale = TxQueueId::new(BackendEpoch::FIRST, 3, h.queue.generation());
    assert_eq!(
        h.tx.claim_tx(stale, 0).err(),
        Some(ClaimError::UnknownQueue)
    );
    assert_eq!(h.tx.claim_tx(h.queue, 0).err(), Some(ClaimError::Empty));
    assert_eq!(
        h.tx.claim_tx(h.queue, 257).err(),
        Some(ClaimError::TooLarge { len: 257, max: 256 })
    );
    h.commit_n(0, 1);
    assert_eq!(
        h.tx.claim_tx(h.queue, 257).err(),
        Some(ClaimError::TooLarge { len: 257, max: 256 }),
        "TooLarge before QueueFull"
    );
    assert_eq!(
        h.tx.claim_tx(h.queue, 1).err(),
        Some(ClaimError::QueueFull { max_pending: 1 })
    );
    // NotActive comes first: see lifecycle::reset_in_progress_stops_both_halves.
    // IdentityExhausted only after slot retirement: the pool and ledger
    // tests of S1 (backend::ledger) set generations the endpoint does not
    // expose.
    h.shutdown();
}

#[test]
fn queue_capacity_and_overcommit() {
    let mut h = Harness::open(config(), 6);
    assert_eq!(
        h.tx.open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route: h.route,
            max_pending: nz(3),
        }),
        Err(QueueError::OverCommitted {
            requested: 3,
            free: 2
        })
    );
    let control =
        h.tx.open_queue(TxQueueConfig {
            authority: Authority::FIRST.next().unwrap(),
            route: h.route,
            max_pending: nz(2),
        })
        .unwrap();
    h.commit_n(0, 6);
    assert_eq!(
        h.tx.claim_tx(h.queue, 10).err(),
        Some(ClaimError::QueueFull { max_pending: 6 })
    );
    // A full lane never blocks a control queue's claim.
    h.commit_to(control, b"control", 100);
    assert_eq!(h.tx.pending(), 7);
    h.shutdown();
}

#[test]
fn repair_authority_exposure_carries_the_queue_authority() {
    let mut h = Harness::open(config(), 4);
    let incarnation = Authority::FIRST;
    let repair =
        h.tx.open_queue(TxQueueConfig {
            authority: incarnation,
            route: h.route,
            max_pending: nz(1),
        })
        .unwrap();
    let control_class = Authority::FIRST.next().unwrap();
    let control =
        h.tx.open_queue(TxQueueConfig {
            authority: control_class,
            route: h.route,
            max_pending: nz(1),
        })
        .unwrap();
    h.commit_to(repair, b"repair", 1);
    h.commit_to(control, b"nak", 2);
    let mut gate = Gate::default();
    h.socket
        .push_send(SendResult::Sent {
            sent: 1,
            error: None,
        })
        .push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    h.flush_queue(repair, &mut gate);
    h.flush_queue(control, &mut gate);
    assert_eq!(
        gate.seen,
        vec![(incarnation, vec![1]), (control_class, vec![2])]
    );
}

#[test]
fn gate_denial() {
    let mut h = Harness::new();
    h.commit_n(0, 3);
    let mut deny = Gate::deny();
    let (outcome, entries) = h.flush(&mut deny);
    assert_eq!(outcome.stop, FlushStop::GateDenied);
    assert_eq!(outcome.spent.ops, 0);
    assert_eq!(h.socket.send_calls(), 0, "a denial makes no system call");
    assert_eq!(tokens(&entries), vec![0, 1, 2], "pending in order");
    assert!(
        outcomes(&entries)
            .iter()
            .all(|outcome| *outcome == pending(PendingCause::GateDenied))
    );
    // The next flush calls the gate again: nothing was cached.
    let (outcome, _) = h.flush(&mut deny);
    assert_eq!(outcome.stop, FlushStop::GateDenied);
    assert_eq!(deny.calls, 2);
    h.socket.push_send(SendResult::Sent {
        sent: 3,
        error: None,
    });
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcome.submitted, 3);
    assert_eq!(tokens(&entries), vec![0, 1, 2]);
}

#[test]
fn gate_trim_and_gate_error() {
    let mut h = Harness::new();
    h.commit_n(0, 4);
    // A count above the candidates exposes nothing.
    let (outcome, entries) = h.flush(&mut Gate::permit(5));
    assert_eq!(
        outcome.stop,
        FlushStop::GateError {
            permitted: 5,
            offered: 4
        }
    );
    assert_eq!(h.socket.send_calls(), 0);
    assert_eq!(entries.len(), 4);
    assert_eq!(h.tx.pending(), 4);
    // Permit { count } exposes exactly `count` head items.
    h.socket.push_send(SendResult::Sent {
        sent: 2,
        error: None,
    });
    let (outcome, entries) = h.flush(&mut Gate::permit(2));
    assert_eq!(outcome.stop, FlushStop::Exposed);
    assert_eq!(outcome.submitted, 2);
    assert_eq!(h.socket.datagrams_offered(), 2);
    assert_eq!(
        outcomes(&entries),
        vec![
            SUBMITTED,
            SUBMITTED,
            pending(PendingCause::GateDenied),
            pending(PendingCause::GateDenied)
        ]
    );
    assert_eq!(tokens(&entries), vec![0, 1, 2, 3]);
    h.shutdown();
}

#[test]
fn report_not_empty_flush_and_cancel_and_close() {
    let mut h = Harness::new();
    h.commit_n(0, 2);
    let mut full = TxReport::new();
    let request = FlushRequest {
        queue: h.queue,
        max_datagrams: nz(1),
        max_bytes: u32::MAX,
    };
    // Fill the report with one denied entry and leave it unread.
    h.tx.flush(request, &mut Gate::deny(), &mut full);
    assert!(!full.is_empty());
    let mut gate = Gate::default();
    let outcome = h.tx.flush(request, &mut gate, &mut full);
    assert_eq!(outcome.stop, FlushStop::ReportNotEmpty);
    assert_eq!(
        h.tx.cancel_pending(h.queue, &mut full),
        Err(QueueError::ReportNotEmpty)
    );
    assert_eq!(
        h.tx.close_queue(h.queue, &mut full),
        Err(QueueError::ReportNotEmpty)
    );
    assert_eq!(gate.calls, 0);
    assert_eq!(h.socket.send_calls(), 0);
    assert_eq!(h.tx.pending(), 2, "no state changed");
    assert_eq!(drain(&mut full).len(), 1, "the unread entry is intact");
    // reset and retire: lifecycle::report_not_empty_reset_and_retire.
    h.shutdown();
}

#[test]
fn partial_sendmmsg() {
    let mut h = Harness::new();
    h.commit_n(0, 4);
    // The hook checks the bytes it is handed: a premature release would
    // let a claim overwrite them.
    let expected = Arc::new(AtomicU64::new(0));
    let next = Arc::clone(&expected);
    h.socket.set_send_hook(Box::new(move |_, datagrams| {
        let first = next.load(Ordering::Relaxed);
        for (offset, datagram) in datagrams.iter().enumerate() {
            let value = u8::try_from(first).unwrap() + u8::try_from(offset).unwrap();
            assert_eq!(*datagram, payload(value, 10).as_slice());
        }
    }));
    h.socket.push_send(SendResult::Sent {
        sent: 2,
        error: None,
    });
    let mut gate = Gate::default();
    let (outcome, entries) = h.flush(&mut gate);
    assert_eq!(outcome.submitted, 2);
    assert_eq!(outcome.spent.ops, 1);
    assert_eq!(
        outcomes(&entries),
        vec![
            SUBMITTED,
            SUBMITTED,
            pending(PendingCause::ErrorLost),
            pending(PendingCause::NotAttempted)
        ]
    );
    // The retry starts at item 2 after a new gate check.
    expected.store(2, Ordering::Relaxed);
    h.socket.push_send(SendResult::Sent {
        sent: 2,
        error: None,
    });
    let (outcome, entries) = h.flush(&mut gate);
    assert_eq!(gate.calls, 2);
    assert_eq!(gate.seen[1].1, vec![2, 3]);
    assert_eq!(outcome.submitted, 2);
    assert_eq!(tokens(&entries), vec![2, 3]);
}

#[test]
fn head_error() {
    let mut h = Harness::new();
    h.commit_n(0, 3);
    h.socket.push_send(SendResult::Sent {
        sent: 1,
        error: Some(Errno::MSGSIZE),
    });
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcome.stop, FlushStop::Faulted(SendError::MessageTooLarge));
    assert_eq!(
        outcomes(&entries),
        vec![
            SUBMITTED,
            pending(PendingCause::Faulted(SendError::MessageTooLarge)),
            pending(PendingCause::NotAttempted)
        ]
    );
    // No later item is exposed until retry_queue or close_queue.
    let mut gate = Gate::default();
    let (outcome, entries) = h.flush(&mut gate);
    assert_eq!(outcome.stop, FlushStop::Faulted(SendError::MessageTooLarge));
    assert!(entries.is_empty());
    assert_eq!((gate.calls, h.socket.send_calls()), (0, 1));
    h.tx.retry_queue(h.queue).unwrap();
    h.socket.push_send(SendResult::Sent {
        sent: 2,
        error: None,
    });
    let (outcome, entries) = h.flush(&mut gate);
    assert_eq!(outcome.submitted, 2);
    assert_eq!(tokens(&entries), vec![1, 2], "the head is attempted again");
    // close_queue is the other exit.
    h.commit_n(3, 1);
    h.socket.push_send(SendResult::Error(Errno::HOSTUNREACH));
    h.flush(&mut gate);
    let mut report = TxReport::new();
    let closed = h.tx.close_queue(h.queue, &mut report).unwrap();
    assert_eq!((closed.returned, closed.more), (1, false));
    assert_eq!(
        drain(&mut report)[0].outcome,
        TxItemOutcome::Returned {
            reason: ReturnReason::QueueClosed
        }
    );
}

#[test]
fn transient_errors() {
    let cases = [
        (
            Errno::AGAIN,
            PendingCause::WouldBlock,
            FlushStop::WouldBlock,
        ),
        (
            Errno::INTR,
            PendingCause::Interrupted,
            FlushStop::Interrupted,
        ),
        (Errno::NOBUFS, PendingCause::NoBuffers, FlushStop::NoBuffers),
        (Errno::NOMEM, PendingCause::NoBuffers, FlushStop::NoBuffers),
    ];
    let mut h = Harness::new();
    h.commit_n(0, 2);
    for (index, (errno, cause, stop)) in cases.into_iter().enumerate() {
        h.socket.push_send(SendResult::Error(errno));
        let (outcome, entries) = h.flush(&mut Gate::default());
        assert_eq!(outcome.stop, stop);
        assert_eq!(outcome.spent.ops, 1, "one op each");
        assert_eq!(
            h.socket.send_calls(),
            u64::try_from(index).unwrap() + 1,
            "no loop"
        );
        assert_eq!(
            outcomes(&entries),
            vec![pending(cause), pending(PendingCause::NotAttempted)]
        );
        assert_eq!(h.tx.pending(), 2);
    }
    // Not faulted: the next flush sends.
    h.socket.push_send(SendResult::Sent {
        sent: 2,
        error: None,
    });
    assert_eq!(h.flush(&mut Gate::default()).0.submitted, 2);
}

#[test]
fn econnrefused_on_send() {
    let mut h = Harness::new();
    h.commit_n(0, 2);
    h.socket.push_send(SendResult::Error(Errno::CONNREFUSED));
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcome.stop, FlushStop::PeerError);
    assert_eq!(outcome.submitted, 0);
    assert_eq!(entries[0].outcome, pending(PendingCause::PeerError));
    assert_eq!(h.tx.peer_errors(), 1);
    // Not faulted: retried by the next flush after a new gate check.
    let mut gate = Gate::default();
    h.socket.push_send(SendResult::Sent {
        sent: 2,
        error: None,
    });
    let (outcome, entries) = h.flush(&mut gate);
    assert_eq!(gate.calls, 1);
    assert_eq!(outcome.submitted, 2);
    assert_eq!(tokens(&entries), vec![0, 1]);
}

/// The send column of the 4.7 errno table.
#[test]
fn errno_classification_send() {
    let os = |errno: Errno| BackendFailure::Os {
        operation: "send",
        errno: errno.raw(),
    };
    let faulted = |error: SendError| (PendingCause::Faulted(error), FlushStop::Faulted(error));
    let other = Errno::from_raw(10_000);
    let cases = [
        (Errno::MSGSIZE, faulted(SendError::MessageTooLarge)),
        (
            Errno::NETUNREACH,
            faulted(SendError::Unreachable {
                errno: Errno::NETUNREACH.raw(),
            }),
        ),
        (
            Errno::HOSTUNREACH,
            faulted(SendError::Unreachable {
                errno: Errno::HOSTUNREACH.raw(),
            }),
        ),
        (
            Errno::NETDOWN,
            faulted(SendError::Unreachable {
                errno: Errno::NETDOWN.raw(),
            }),
        ),
        (Errno::ADDRNOTAVAIL, faulted(SendError::AddressUnavailable)),
        (
            Errno::PERM,
            faulted(SendError::Denied {
                errno: Errno::PERM.raw(),
            }),
        ),
        (
            Errno::ACCES,
            faulted(SendError::Denied {
                errno: Errno::ACCES.raw(),
            }),
        ),
        (other, faulted(SendError::Other { errno: other.raw() })),
        (
            Errno::BADF,
            (
                PendingCause::Failed(os(Errno::BADF)),
                FlushStop::Failed(os(Errno::BADF)),
            ),
        ),
        (
            Errno::NOTSOCK,
            (
                PendingCause::Failed(os(Errno::NOTSOCK)),
                FlushStop::Failed(os(Errno::NOTSOCK)),
            ),
        ),
        (
            Errno::FAULT,
            (
                PendingCause::Failed(os(Errno::FAULT)),
                FlushStop::Failed(os(Errno::FAULT)),
            ),
        ),
        (
            Errno::INVAL,
            (
                PendingCause::Failed(os(Errno::INVAL)),
                FlushStop::Failed(os(Errno::INVAL)),
            ),
        ),
    ];
    for (errno, (cause, stop)) in cases {
        let mut h = Harness::new();
        h.commit_n(0, 1);
        h.socket.push_send(SendResult::Error(errno));
        let (outcome, entries) = h.flush(&mut Gate::default());
        assert_eq!(outcome.stop, stop, "{errno:?}");
        assert_eq!(entries[0].outcome, pending(cause), "{errno:?}");
        let faults = matches!(stop, FlushStop::Faulted(_));
        let (again, _) = h.flush(&mut Gate::default());
        assert_eq!(
            matches!(again.stop, FlushStop::Faulted(_)),
            faults,
            "only a SendError faults the queue: {errno:?}"
        );
        h.shutdown();
    }
}

#[test]
fn invariant_checks_short_msg_len() {
    let mut h = Harness::open(config(), 4);
    let tickets = h.commit_n(0, 4);
    h.socket.push_send(SendResult::OutOfAbi { proven: 1 });
    let (outcome, entries) = h.flush(&mut Gate::permit(3));
    assert_eq!(
        outcome.stop,
        FlushStop::Failed(BackendFailure::Invariant { operation: "send" })
    );
    assert_eq!(outcome.submitted, 1);
    assert_eq!(
        outcomes(&entries),
        vec![
            SUBMITTED,
            TxItemOutcome::Unknown,
            TxItemOutcome::Unknown,
            pending(PendingCause::GateDenied)
        ]
    );
    // Unknown items leave the queue and are never retried.
    assert!(!h.tx.is_pending(tickets[1]));
    assert_eq!(h.tx.pending(), 1);
    let mut gate = Gate::default();
    let (outcome, entries) = h.flush(&mut gate);
    assert_eq!(outcome.stop, FlushStop::Queue(QueueError::NeedsReset));
    assert!(entries.is_empty());
    assert_eq!((gate.calls, h.socket.send_calls()), (0, 1));
    assert_eq!(h.tx.retry_queue(h.queue), Err(QueueError::NeedsReset));
    // Quarantined until reset: the item behind them is returned by the
    // reset, and after reopen every slot is claimable again.
    let (mut endpoint, _socket) = h.join();
    let entries = reset_all(&mut endpoint);
    assert_eq!(tokens(&entries), vec![3]);
    let config = config();
    endpoint.reopen(&config).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let route = tx.add_route(peer()).unwrap();
    let queue = tx
        .open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route,
            max_pending: nz(8),
        })
        .unwrap();
    for _ in 0..8 {
        let mut frame = tx.claim_tx(queue, 1).unwrap();
        frame.bytes_mut()[0] = 1;
        frame
            .commit(Commit {
                len: 1,
                token: SenderToken::new(0),
                options: TxOptions::none(),
            })
            .unwrap();
    }
    let mut endpoint = SocketsEndpoint::join(tx, rx).unwrap();
    assert_eq!(retire_all(&mut endpoint).len(), 8);
}

#[test]
fn invariant_checks_count_above_request() {
    for result in [
        SendResult::Sent {
            sent: 3,
            error: None,
        },
        SendResult::Sent {
            sent: 0,
            error: None,
        },
        SendResult::OutOfAbi { proven: 9 },
    ] {
        let mut h = Harness::new();
        h.commit_n(0, 2);
        h.socket.push_send(result);
        let (outcome, entries) = h.flush(&mut Gate::default());
        assert_eq!(
            outcome.stop,
            FlushStop::Failed(BackendFailure::Invariant { operation: "send" }),
            "{result:?}"
        );
        if let SendResult::OutOfAbi { .. } = result {
            assert_eq!(outcomes(&entries), vec![SUBMITTED, SUBMITTED]);
        } else {
            assert_eq!(
                outcomes(&entries),
                vec![TxItemOutcome::Unknown, TxItemOutcome::Unknown],
                "{result:?}"
            );
        }
        h.shutdown();
    }
    // An error after a complete batch: every item is proven, the queue
    // still needs a reset.
    let mut h = Harness::new();
    h.commit_n(0, 2);
    h.socket.push_send(SendResult::Sent {
        sent: 2,
        error: Some(Errno::AGAIN),
    });
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcomes(&entries), vec![SUBMITTED, SUBMITTED]);
    assert!(matches!(outcome.stop, FlushStop::Failed(_)));
    assert_eq!(h.tx.retry_queue(h.queue), Err(QueueError::NeedsReset));
}

#[test]
fn identity_old_generation_resolves_to_nothing() {
    let mut h = Harness::open(config(), 1);
    let first = h.commit_n(0, 1)[0];
    h.socket.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    h.flush(&mut Gate::default());
    let second = h.commit_n(1, 1)[0];
    assert_eq!(first.id().slot(), second.id().slot(), "the slot is reused");
    assert!(second.id().generation() > first.id().generation());
    assert!(!h.tx.is_pending(first));
    assert!(h.tx.is_pending(second));
    let other_instance = TxTicket::new(SubmissionId::new(
        InstanceId::FIRST.next().unwrap(),
        second.id().epoch(),
        second.id().slot(),
        second.id().generation(),
    ));
    assert!(!h.tx.is_pending(other_instance));
    // An old epoch: lifecycle::reset_returns_items_and_invalidates_handles.
    // Generation overflow retires the slot: backend::pool and ledger tests.
    h.shutdown();
}

#[test]
fn gate_panic() {
    struct Panicking;
    impl SenderGate for Panicking {
        fn check(&mut self, _: &Exposure<'_>) -> GateDecision {
            panic!("gate failure");
        }
    }
    let mut h = Harness::new();
    let tickets = h.commit_n(0, 2);
    let mut report = TxReport::new();
    let request = FlushRequest {
        queue: h.queue,
        max_datagrams: nz(8),
        max_bytes: u32::MAX,
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        h.tx.flush(request, &mut Panicking, &mut report)
    }));
    assert!(result.is_err());
    assert_eq!(h.socket.send_calls(), 0, "nothing sent");
    assert!(report.is_empty());
    assert_eq!(h.tx.pending(), 2);
    assert!(tickets.iter().all(|ticket| h.tx.is_pending(*ticket)));
    // The next flush reports normally.
    h.socket.push_send(SendResult::Sent {
        sent: 2,
        error: None,
    });
    let (outcome, entries) = h.flush(&mut Gate::default());
    assert_eq!(outcome.submitted, 2);
    assert_eq!(tokens(&entries), vec![0, 1]);
}

#[test]
fn budget() {
    let mut h = Harness::new();
    h.commit_n(0, 3);
    let mut gate = Gate::default();
    let mut report = TxReport::new();
    // A zero byte budget changes nothing: HeadExceedsBudget without an op.
    let outcome = h.tx.flush(
        FlushRequest {
            queue: h.queue,
            max_datagrams: nz(8),
            max_bytes: 0,
        },
        &mut gate,
        &mut report,
    );
    assert_eq!(outcome.stop, FlushStop::HeadExceedsBudget { head_len: 10 });
    assert_eq!(outcome.spent, Spent::default());
    assert!(report.is_empty());
    assert_eq!((gate.calls, h.socket.send_calls()), (0, 0));
    // A byte budget of 25 selects two items of 10; spent stays within it.
    h.socket.push_send(SendResult::Sent {
        sent: 2,
        error: None,
    });
    let outcome = h.tx.flush(
        FlushRequest {
            queue: h.queue,
            max_datagrams: nz(8),
            max_bytes: 25,
        },
        &mut gate,
        &mut report,
    );
    assert_eq!(outcome.submitted, 2);
    assert_eq!(gate.seen[0].1, vec![0, 1]);
    assert!(outcome.spent.bytes <= 25 && outcome.spent.ops == 1 && outcome.spent.datagrams == 2);
    drain(&mut report);
    // max_datagrams and max_batch clamp the prefix.
    h.commit_n(3, 7);
    h.socket.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    let outcome = h.tx.flush(
        FlushRequest {
            queue: h.queue,
            max_datagrams: nz(1),
            max_bytes: u32::MAX,
        },
        &mut gate,
        &mut report,
    );
    assert_eq!((outcome.submitted, drain(&mut report).len()), (1, 1));
    h.socket.push_send(SendResult::Sent {
        sent: 7,
        error: None,
    });
    let outcome = h.tx.flush(
        FlushRequest {
            queue: h.queue,
            max_datagrams: nz(64),
            max_bytes: u32::MAX,
        },
        &mut gate,
        &mut report,
    );
    assert_eq!(outcome.submitted, 7, "max_batch of 8 holds the 7 left");
    drain(&mut report);
    // An empty queue: QueueEmpty without a gate call.
    let calls = gate.calls;
    let outcome = h.tx.flush(
        FlushRequest {
            queue: h.queue,
            max_datagrams: nz(1),
            max_bytes: u32::MAX,
        },
        &mut gate,
        &mut report,
    );
    assert_eq!(outcome.stop, FlushStop::QueueEmpty);
    assert_eq!(gate.calls, calls);
}

#[test]
fn cancel_pending_returns_in_order_across_calls() {
    let mut cfg = config();
    cfg.tx_slots = nz(70);
    let mut h = Harness::open(cfg, 70);
    for index in 0..66_u8 {
        h.commit_to(h.queue, &[index], u64::from(index));
    }
    let mut report = TxReport::new();
    let first = h.tx.cancel_pending(h.queue, &mut report).unwrap();
    assert_eq!((first.returned, first.more), (64, true));
    let entries = drain(&mut report);
    assert_eq!(tokens(&entries), (0..64).collect::<Vec<u64>>());
    assert!(entries.iter().all(|entry| entry.outcome
        == TxItemOutcome::Returned {
            reason: ReturnReason::Cancelled
        }));
    let second = h.tx.cancel_pending(h.queue, &mut report).unwrap();
    assert_eq!((second.returned, second.more), (2, false));
    drain(&mut report);
    // The queue stays open after a cancellation.
    h.commit_to(h.queue, b"x", 99);
    // close_queue across calls: the queue takes no claim until it closes.
    for index in 0..65_u8 {
        h.commit_to(h.queue, &[index], u64::from(index));
    }
    let closing = h.tx.close_queue(h.queue, &mut report).unwrap();
    assert_eq!((closing.returned, closing.more), (64, true));
    drain(&mut report);
    assert_eq!(
        h.tx.claim_tx(h.queue, 1).err(),
        Some(ClaimError::UnknownQueue)
    );
    assert_eq!(
        h.tx.cancel_pending(h.queue, &mut report),
        Err(QueueError::UnknownQueue)
    );
    let (outcome, _) = h.flush(&mut Gate::default());
    assert_eq!(outcome.stop, FlushStop::Queue(QueueError::UnknownQueue));
    let closed = h.tx.close_queue(h.queue, &mut report).unwrap();
    assert_eq!((closed.returned, closed.more), (2, false));
    drain(&mut report);
    assert_eq!(
        h.tx.close_queue(h.queue, &mut report),
        Err(QueueError::UnknownQueue)
    );
    // Its capacity is free again.
    h.tx.open_queue(TxQueueConfig {
        authority: Authority::FIRST,
        route: h.route,
        max_pending: nz(70),
    })
    .unwrap();
}

#[test]
fn path_mtu_scripted_routes() {
    let mut h = Harness::new();
    // Unmeasured: the declared fallback.
    let info = h.tx.route_info(h.route).unwrap();
    assert_eq!(info.route_mtu, None);
    assert_eq!(info.path_mtu, CapabilityState::Fallback(Reason::Unverified));
    // Measured and too small: 256 + 8 + 20 = 284.
    h.socket.set_route_mtu(Some(283));
    let other = SocketAddr::from((Ipv4Addr::LOCALHOST, 7002));
    assert_eq!(
        h.tx.add_route(other),
        Err(RouteError::PathTooSmall {
            datagram: 256,
            overhead: 28,
            route_mtu: 283
        })
    );
    h.socket.set_route_mtu(Some(284));
    let measured = h.tx.add_route(other).unwrap();
    assert_eq!(
        h.tx.route_info(measured).unwrap(),
        RouteInfo {
            route_mtu: Some(284),
            path_mtu: CapabilityState::Active
        }
    );
    // Destination checks, then the route limit.
    assert_eq!(
        h.tx.add_route(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1))),
        Err(RouteError::Unsupported)
    );
    assert_eq!(
        h.tx.add_route(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        Err(RouteError::Unsupported)
    );
    assert_eq!(
        h.tx.add_route(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 1))),
        Err(RouteError::FamilyMismatch)
    );
    h.tx.add_route(other).unwrap();
    h.tx.add_route(other).unwrap();
    assert_eq!(h.tx.add_route(other), Err(RouteError::RouteLimit));
    // Removal: in use while a queue names it; stale afterwards.
    assert_eq!(h.tx.remove_route(h.route), Err(RouteError::InUse));
    h.tx.remove_route(measured).unwrap();
    assert_eq!(h.tx.remove_route(measured), Err(RouteError::Unknown));
    assert_eq!(h.tx.route_info(measured), Err(RouteError::Unknown));
    assert_eq!(
        h.tx.open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route: measured,
            max_pending: nz(1),
        }),
        Err(QueueError::RouteUnknown)
    );
    // Required and unmeasured: PathUnverified.
    let mut cfg = config();
    cfg.require = CapabilitySet::EMPTY.with(Capability::PathMtu);
    let socket = ScriptedSocket::new();
    let endpoint = SocketsEndpoint::open(&cfg, InstanceId::FIRST, socket).unwrap();
    let (mut tx, _rx) = endpoint.split().unwrap();
    assert_eq!(tx.add_route(peer()), Err(RouteError::PathUnverified));
}

#[test]
fn ipv6_route_overhead_is_48_bytes() {
    let v6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 7000));
    let mut cfg = SocketsConfig::new(v6);
    cfg.max_datagram = nz(1408);
    let socket = ScriptedSocket::new();
    socket.set_route_mtu(Some(1280));
    let endpoint = SocketsEndpoint::open(&cfg, InstanceId::FIRST, socket).unwrap();
    let (mut tx, _rx) = endpoint.split().unwrap();
    let destination = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 7001));
    assert_eq!(
        tx.add_route(destination),
        Err(RouteError::PathTooSmall {
            datagram: 1408,
            overhead: 48,
            route_mtu: 1280
        })
    );
}
