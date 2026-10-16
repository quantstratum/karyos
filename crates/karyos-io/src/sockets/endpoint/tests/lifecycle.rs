// SPDX-License-Identifier: Apache-2.0

//! Lifecycle rows of section 12: open, reset, reopen, retire, drop, split
//! and join, required capabilities, allocation freedom, the guard race and
//! the idle close.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::*;
use crate::backend::{
    BackendFailure, Capability, CapabilityState, ClaimError, CompletionHandler, FlushStop,
    PendingCause, QueueError, Reason, Release, ReturnReason, RouteError, RxStop, TxEvent,
    TxItemOutcome,
};
use crate::sockets::ops::{Errno, RecvResult, SendResult};
use crate::sockets::scripted::default_probes;

const RESET: TxItemOutcome = TxItemOutcome::Returned {
    reason: ReturnReason::Reset,
};

/// A harness with room for 70 pending items, so a reset needs two calls.
fn large() -> Harness {
    let mut cfg = config();
    cfg.tx_slots = nz(70);
    Harness::open(cfg, 70)
}

#[test]
fn open_rejects_invalid_configuration_and_protection() {
    let check = |edit: fn(&mut SocketsConfig), expected: OpenError| {
        let mut cfg = config();
        edit(&mut cfg);
        let socket = ScriptedSocket::new();
        let observer = socket.observer();
        let error = SocketsEndpoint::open(&cfg, InstanceId::FIRST, socket).unwrap_err();
        assert_eq!(error, expected);
        assert_eq!(
            observer.open_calls(),
            0,
            "no socket for a bad configuration"
        );
    };
    check(
        |cfg| cfg.max_datagram = nz(255),
        OpenError::InvalidConfig {
            field: "max_datagram",
            value: 255,
        },
    );
    check(
        |cfg| cfg.max_datagram = nz(8193),
        OpenError::InvalidConfig {
            field: "max_datagram",
            value: 8193,
        },
    );
    check(
        |cfg| cfg.tx_slots = nz(4097),
        OpenError::InvalidConfig {
            field: "tx_slots",
            value: 4097,
        },
    );
    check(
        |cfg| cfg.max_queues = nz(1025),
        OpenError::InvalidConfig {
            field: "max_queues",
            value: 1025,
        },
    );
    check(
        |cfg| cfg.max_routes = nz(1025),
        OpenError::InvalidConfig {
            field: "max_routes",
            value: 1025,
        },
    );
    check(
        |cfg| cfg.max_batch = nz(65),
        OpenError::InvalidConfig {
            field: "max_batch",
            value: 65,
        },
    );
    check(
        |cfg| {
            cfg.multicast = Some(MulticastConfig::new(
                Ipv4Addr::LOCALHOST.into(),
                InterfaceSel::Index(1),
            ));
        },
        OpenError::InvalidConfig {
            field: "multicast.group",
            value: 0,
        },
    );
    check(
        |cfg| cfg.protection = Protection::Authenticated,
        OpenError::ProtectionUnavailable,
    );
}

#[test]
fn defaults_are_the_provisional_values() {
    let cfg = SocketsConfig::new(local());
    assert_eq!(cfg.max_datagram.get(), 1408);
    assert_eq!(cfg.tx_slots.get(), 256);
    assert_eq!((cfg.max_queues.get(), cfg.max_routes.get()), (64, 64));
    assert_eq!(cfg.max_batch.get(), 32);
    assert_eq!(cfg.send_buffer, Some(DEFAULT_SEND_BUFFER));
    assert_eq!(cfg.recv_buffer.unwrap().get(), 4 << 20);
    assert_eq!(cfg.rx_budget(), Budget::new(64, 64 * 1408, 64));
    assert_eq!(cfg.protection, Protection::Trusted);
    assert_eq!(
        MulticastConfig::new(Ipv4Addr::new(239, 1, 1, 1).into(), InterfaceSel::Index(1)).ttl,
        1
    );
    assert_eq!(cfg.validate(), Ok(()));
}

#[test]
fn snapshot_records_the_baseline() {
    let socket = ScriptedSocket::new();
    let endpoint = SocketsEndpoint::open(&config(), InstanceId::FIRST, socket).unwrap();
    let snapshot = *endpoint.capabilities();
    assert_eq!(snapshot.epoch, BackendEpoch::FIRST);
    assert_eq!(snapshot.platform, Platform::current());
    assert_eq!(snapshot.copy_mode, CopyMode::Staged);
    assert_eq!(snapshot.queue_assignment, QueueAssignment::KernelSelected);
    assert_eq!(snapshot.max_datagram, 256);
    let library = CapabilityState::Unavailable(Reason::LibraryApi);
    for capability in [
        Capability::RxBatch,
        Capability::Gso,
        Capability::Gro,
        Capability::KernelStamps,
        Capability::HardwareStamps,
        Capability::BusyPoll,
    ] {
        assert_eq!(snapshot.state(capability), library, "{capability:?}");
    }
    assert_eq!(snapshot.user_observations, CapabilityState::Active);
    assert!(!snapshot.enobufs_reported);
    assert_eq!(snapshot.clock.granularity_ns, 1);
    let (tx, rx) = endpoint.split().unwrap();
    assert_eq!(*tx.capabilities(), snapshot);
    assert_eq!(*rx.capabilities(), snapshot);
}

#[test]
fn required_capability_loss() {
    // A LibraryApi capability required: open fails and closes the socket.
    let mut cfg = config();
    cfg.require = CapabilitySet::EMPTY.with(Capability::Gso);
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    assert_eq!(
        SocketsEndpoint::open(&cfg, InstanceId::FIRST, socket).unwrap_err(),
        OpenError::RequiredCapability {
            capability: Capability::Gso,
            state: CapabilityState::Unavailable(Reason::LibraryApi),
        }
    );
    assert_eq!(observer.live_descriptors(), 0);
    // TX batching required and present at open, lost at reopen.
    let mut cfg = config();
    cfg.require = CapabilitySet::EMPTY.with(Capability::TxBatch);
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let mut endpoint = SocketsEndpoint::open(&cfg, InstanceId::FIRST, socket).unwrap();
    reset_all(&mut endpoint);
    let lost = CapabilityState::Unavailable(Reason::Unsupported {
        errno: Errno::NOSYS.raw(),
    });
    let mut probes = default_probes(&cfg);
    probes.tx_batch = lost;
    observer.push_open(Ok(probes));
    assert_eq!(
        endpoint.reopen(&cfg).unwrap_err(),
        OpenError::RequiredCapability {
            capability: Capability::TxBatch,
            state: lost,
        }
    );
    assert_eq!(observer.live_descriptors(), 0, "no partial socket kept");
    // The endpoint stays closed in its old epoch; a later reopen succeeds.
    assert_eq!(endpoint.capabilities().epoch, BackendEpoch::FIRST);
    let snapshot = *endpoint.reopen(&cfg).unwrap();
    assert_eq!(snapshot.epoch.get().get(), 2);
    assert_eq!(snapshot.tx_batch, CapabilityState::Active);
    retire_all(&mut endpoint);
}

#[test]
fn reset_returns_items_and_invalidates_handles() {
    let mut h = large();
    let tickets: Vec<TxTicket> = (0..66_u8)
        .map(|index| h.commit_to(h.queue, &[index], u64::from(index)))
        .collect();
    let (old_route, old_queue) = (h.route, h.queue);
    let (mut endpoint, socket) = h.join();
    assert_eq!(socket.live_descriptors(), 1, "join closed the duplicate");
    let mut report = TxReport::new();
    let first = endpoint.reset(&mut report);
    assert_eq!((first.returned, first.more), (64, true));
    // While more is true: reopen and retire fail and nothing is discarded.
    let cfg = config();
    let mut cfg_large = cfg;
    cfg_large.tx_slots = nz(70);
    let entries = drain(&mut report);
    assert_eq!(endpoint.reopen(&cfg_large), Err(OpenError::ResetIncomplete));
    assert_eq!(endpoint.retire(&mut report), Retired::ResetIncomplete);
    assert_eq!(endpoint.pending(), 2);
    assert_eq!(socket.live_descriptors(), 1, "the socket stays open");
    let second = endpoint.reset(&mut report);
    assert_eq!((second.returned, second.more), (2, false));
    let entries: Vec<TxEntry> = entries.into_iter().chain(drain(&mut report)).collect();
    assert_eq!(
        entries.iter().map(|entry| entry.ticket).collect::<Vec<_>>(),
        tickets
    );
    assert!(entries.iter().all(|entry| entry.outcome == RESET));
    assert_eq!(socket.live_descriptors(), 0, "reset closes the socket");
    // A finished reset is idempotent.
    assert!(!endpoint.reset(&mut report).more);
    // reopen probes again and advances the epoch.
    assert_eq!(socket.open_calls(), 1);
    let snapshot = *endpoint.reopen(&cfg_large).unwrap();
    assert_eq!(socket.open_calls(), 2);
    assert_eq!(snapshot.epoch.get().get(), 2);
    let (mut tx, rx) = endpoint.split().unwrap();
    // Handles from before the reset: UnknownQueue and Unknown, also when
    // a new handle reuses the same index.
    let route = tx.add_route(peer()).unwrap();
    let queue = tx
        .open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route,
            max_pending: nz(70),
        })
        .unwrap();
    assert_eq!(
        (route.index(), queue.index()),
        (old_route.index(), old_queue.index())
    );
    assert_eq!(tx.route_info(old_route), Err(RouteError::Unknown));
    assert_eq!(tx.remove_route(old_route), Err(RouteError::Unknown));
    assert_eq!(
        tx.claim_tx(old_queue, 1).err(),
        Some(ClaimError::UnknownQueue)
    );
    let mut report = TxReport::new();
    let outcome = tx.flush(
        FlushRequest {
            queue: old_queue,
            max_datagrams: nz(1),
            max_bytes: u32::MAX,
        },
        &mut Gate::default(),
        &mut report,
    );
    assert_eq!(outcome.stop, FlushStop::Queue(QueueError::UnknownQueue));
    assert_eq!(
        tx.open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route: old_route,
            max_pending: nz(1),
        }),
        Err(QueueError::RouteUnknown)
    );
    // Old tickets are inert, even for a slot claimed again.
    let mut frame = tx.claim_tx(queue, 1).unwrap();
    frame.bytes_mut()[0] = 0;
    let new = frame
        .commit(Commit {
            len: 1,
            token: SenderToken::new(0),
            options: TxOptions::none(),
        })
        .unwrap();
    let old = tickets
        .iter()
        .find(|ticket| ticket.id().slot() == new.id().slot())
        .unwrap();
    assert!(!tx.is_pending(*old));
    assert!(tickets.iter().all(|ticket| !tx.is_pending(*ticket)));
    assert!(tx.is_pending(new));
    let mut endpoint = SocketsEndpoint::join(tx, rx).unwrap();
    retire_all(&mut endpoint);
}

#[test]
fn reset_in_progress_stops_both_halves() {
    let mut h = large();
    for index in 0..65_u8 {
        h.commit_to(h.queue, &[index], u64::from(index));
    }
    let queue = h.queue;
    let (mut endpoint, socket) = h.join();
    let mut report = TxReport::new();
    assert!(endpoint.reset(&mut report).more);
    drain(&mut report);
    // Halves of a resetting endpoint: claims, commits and flushes return
    // NotActive; poll_rx returns Failed with no system call.
    let (mut tx, mut rx) = endpoint.split().unwrap();
    assert_eq!(tx.claim_tx(queue, 1).err(), Some(ClaimError::NotActive));
    let outcome = tx.flush(
        FlushRequest {
            queue,
            max_datagrams: nz(1),
            max_bytes: u32::MAX,
        },
        &mut Gate::default(),
        &mut report,
    );
    assert_eq!(outcome.stop, FlushStop::Queue(QueueError::NotActive));
    assert_eq!(
        tx.cancel_pending(queue, &mut report),
        Err(QueueError::NotActive)
    );
    assert_eq!(tx.retry_queue(queue), Err(QueueError::NotActive));
    assert_eq!(tx.add_route(peer()), Err(RouteError::NotActive));
    socket.push_recv_datagram(b"x", Some(peer()));
    let outcome = rx.poll_rx(Budget::new(8, 8 * 256, 8), &mut Recorder::default());
    assert_eq!(outcome.stop, RxStop::Failed(BackendFailure::NotActive));
    assert_eq!((socket.recv_calls(), socket.send_calls()), (0, 0));
    let mut endpoint = SocketsEndpoint::join(tx, rx).unwrap();
    assert!(!endpoint.reset(&mut report).more);
    assert_eq!(drain(&mut report).len(), 1);
}

#[test]
fn report_not_empty_reset_and_retire() {
    let mut h = Harness::new();
    h.commit_n(0, 2);
    let mut full = TxReport::new();
    h.tx.flush(
        FlushRequest {
            queue: h.queue,
            max_datagrams: nz(1),
            max_bytes: u32::MAX,
        },
        &mut Gate::deny(),
        &mut full,
    );
    let (mut endpoint, socket) = h.join();
    let outcome = endpoint.reset(&mut full);
    assert!(outcome.report_not_empty && outcome.more);
    assert_eq!(outcome.returned, 0);
    assert_eq!(endpoint.retire(&mut full), Retired::ReportNotEmpty);
    assert_eq!(endpoint.pending(), 2, "no state changed");
    assert_eq!(socket.live_descriptors(), 1);
    // The endpoint is still active: it splits and flushes.
    let (tx, rx) = endpoint.split().unwrap();
    let mut endpoint = SocketsEndpoint::join(tx, rx).unwrap();
    assert_eq!(drain(&mut full).len(), 1);
    assert_eq!(retire_all(&mut endpoint).len(), 2);
}

#[test]
fn retire_and_drop() {
    let mut h = large();
    for index in 0..65_u8 {
        h.commit_to(h.queue, &[index], u64::from(index));
    }
    let (mut endpoint, socket) = h.join();
    let mut report = TxReport::new();
    assert_eq!(endpoint.retire(&mut report), Retired::More { returned: 64 });
    drain(&mut report);
    // A reset during retirement keeps the retirement's final state.
    let outcome = endpoint.reset(&mut report);
    assert_eq!((outcome.returned, outcome.more), (1, false));
    drain(&mut report);
    assert_eq!(
        endpoint.retire(&mut report),
        Retired::Complete { returned: 0 }
    );
    assert_eq!(socket.live_descriptors(), 0);
    assert_eq!(endpoint.reopen(&config()), Err(OpenError::Retired));
    // A retirement after a finished reset completes at once.
    let socket = ScriptedSocket::new();
    let mut endpoint = SocketsEndpoint::open(&config(), InstanceId::FIRST, socket).unwrap();
    reset_all(&mut endpoint);
    assert_eq!(
        endpoint.retire(&mut TxReport::new()),
        Retired::Complete { returned: 0 }
    );
    // A drop with nothing pending is quiet.
    let before = tx_discarded_on_drop();
    drop(Harness::new());
    assert_eq!(tx_discarded_on_drop(), before);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "dropped with 1 pending items")]
fn retire_and_drop_non_unwinding_drop_with_pending_items_asserts() {
    let mut h = Harness::new();
    h.commit_n(0, 1);
    drop(h);
}

#[test]
fn retire_and_drop_during_unwinding_is_quiet() {
    let result = std::panic::catch_unwind(|| {
        let mut h = Harness::new();
        h.commit_n(0, 1);
        panic!("driver failure with a pending item");
    });
    assert!(result.is_err(), "only the driver's panic unwound");
}

#[test]
fn reopen_requires_a_finished_reset_and_fixed_pool_sizes() {
    let socket = ScriptedSocket::new();
    let mut endpoint = SocketsEndpoint::open(&config(), InstanceId::FIRST, socket).unwrap();
    assert_eq!(endpoint.reopen(&config()), Err(OpenError::ResetIncomplete));
    reset_all(&mut endpoint);
    let mut changed = config();
    changed.tx_slots = nz(9);
    assert_eq!(
        endpoint.reopen(&changed),
        Err(OpenError::InvalidConfig {
            field: "tx_slots",
            value: 9
        })
    );
    // The other fields may change.
    let mut changed = config();
    changed.max_batch = nz(2);
    changed.rx_observation = true;
    endpoint.reopen(&changed).unwrap();
    retire_all(&mut endpoint);
}

#[test]
fn reopen_fails_when_the_epoch_cannot_advance() {
    // The endpoint does not expose its epoch counter; BackendEpoch::next
    // is the checked step reopen takes (backend tests cover its overflow).
    assert_eq!(
        BackendEpoch::new(std::num::NonZeroU32::MAX).next(),
        Err(OpenError::EpochExhausted)
    );
}

#[test]
fn split_halves_scripted_threads() {
    let mut h = Harness::new();
    let tickets = h.commit_n(0, 3);
    for index in 0..3_u8 {
        h.socket.push_recv_datagram(&[index], Some(peer()));
    }
    h.socket.push_send(SendResult::Sent {
        sent: 3,
        error: None,
    });
    let Harness {
        mut tx,
        mut rx,
        socket,
        queue,
        ..
    } = h;
    assert_eq!(
        socket.live_descriptors(),
        2,
        "split duplicated the descriptor"
    );
    let sender = std::thread::spawn(move || {
        let mut report = TxReport::new();
        let outcome = tx.flush(
            FlushRequest {
                queue,
                max_datagrams: nz(8),
                max_bytes: u32::MAX,
            },
            &mut Gate::default(),
            &mut report,
        );
        assert_eq!(outcome.submitted, 3);
        let entries = drain(&mut report);
        (tx, entries)
    });
    let receiver = std::thread::spawn(move || {
        let mut handler = Recorder::default();
        let outcome = rx.poll_rx(Budget::new(8, 8 * 256, 8), &mut handler);
        assert_eq!(outcome.delivered, 3);
        rx
    });
    let (tx, entries) = sender.join().unwrap();
    let rx = receiver.join().unwrap();
    assert_eq!(
        entries.iter().map(|entry| entry.ticket).collect::<Vec<_>>(),
        tickets
    );
    // Dropping one half closes only its duplicate; the other keeps working.
    drop(rx);
    assert_eq!(socket.live_descriptors(), 1);
    let mut tx = tx;
    let mut frame = tx.claim_tx(queue, 1).unwrap();
    frame.bytes_mut()[0] = 9;
    frame
        .commit(Commit {
            len: 1,
            token: SenderToken::new(9),
            options: TxOptions::none(),
        })
        .unwrap();
    socket.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    let mut report = TxReport::new();
    let outcome = tx.flush(
        FlushRequest {
            queue,
            max_datagrams: nz(8),
            max_bytes: u32::MAX,
        },
        &mut Gate::default(),
        &mut report,
    );
    assert_eq!(outcome.submitted, 1);
}

#[test]
fn split_halves_join_refuses_mismatched_halves() {
    let one = Harness::new();
    let socket = ScriptedSocket::new();
    let other =
        SocketsEndpoint::open(&config(), InstanceId::FIRST.next().unwrap(), socket).unwrap();
    let (other_tx, other_rx) = other.split().unwrap();
    let error = SocketsEndpoint::join(one.tx, other_rx).unwrap_err();
    assert!(error.to_string().contains("different"));
    assert!(format!("{error:?}").contains("JoinError"));
    // Both halves come back unchanged and join with their own partners.
    let JoinError { tx, rx } = error;
    SocketsEndpoint::join(tx, one.rx).unwrap();
    SocketsEndpoint::join(other_tx, rx).unwrap();
    // Halves of different epochs of one instance are refused too.
    let (_, stale_rx) = SocketsEndpoint::open(&config(), InstanceId::FIRST, ScriptedSocket::new())
        .unwrap()
        .split()
        .unwrap();
    let mut endpoint =
        SocketsEndpoint::open(&config(), InstanceId::FIRST, ScriptedSocket::new()).unwrap();
    reset_all(&mut endpoint);
    endpoint.reopen(&config()).unwrap();
    let (new_tx, new_rx) = endpoint.split().unwrap();
    let JoinError { tx, rx } = SocketsEndpoint::join(new_tx, stale_rx).unwrap_err();
    assert_eq!(tx.capabilities().epoch.get().get(), 2);
    assert_eq!(rx.capabilities().epoch, BackendEpoch::FIRST);
    SocketsEndpoint::join(tx, new_rx).unwrap();
}

#[test]
fn split_fails_when_the_descriptor_cannot_be_duplicated() {
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let endpoint = SocketsEndpoint::open(&config(), InstanceId::FIRST, socket).unwrap();
    observer.fail_next_clone(Errno::NOMEM);
    assert_eq!(
        endpoint.split().unwrap_err(),
        OpenError::Os {
            operation: "dup",
            errno: Errno::NOMEM.raw()
        }
    );
    assert_eq!(observer.live_descriptors(), 0, "the endpoint was dropped");
}

#[test]
fn no_allocation() {
    struct Permit;
    impl SenderGate for Permit {
        fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
            GateDecision::Permit {
                count: NonZeroU16::new(u16::try_from(candidate.tokens.len()).unwrap_or(1))
                    .unwrap_or(NonZeroU16::MIN),
            }
        }
    }
    struct Count(u32);
    impl RxHandler for Count {
        fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
            self.0 += u32::try_from(datagram.bytes().len()).unwrap_or(0);
            ControlFlow::Continue(())
        }
        fn dropped(&mut self, _: RxDrop) {}
    }
    struct NoEvents;
    impl CompletionHandler for NoEvents {
        fn event(&mut self, _: TxEvent) {}
    }
    let mut cfg = config();
    cfg.rx_observation = true;
    let mut h = Harness::open(cfg, 8);
    h.socket
        .push_send(SendResult::Sent {
            sent: 2,
            error: None,
        })
        .push_send(SendResult::Error(Errno::AGAIN));
    h.socket.push_recv_datagram(b"abc", Some(peer()));
    h.socket.push_recv_datagram(&payload(0, 400), Some(peer()));
    h.socket.push_recv(RecvResult::Error(Errno::NOBUFS), &[]);
    // Warm the clock and the scripted lock on the control path.
    let _ = karyos_sys::host_clock::host_monotonic_ns();
    let _ = h.socket.send_calls();
    let queue = h.queue;
    let mut report = TxReport::new();
    let request = FlushRequest {
        queue,
        max_datagrams: nz(8),
        max_bytes: u32::MAX,
    };
    let ((), allocations) = karyos_sys::alloc_count::count(|| {
        for token in 0..3_u64 {
            let mut frame = h.tx.claim_tx(queue, 10).unwrap_or_else(|_| unreachable!());
            frame.bytes_mut().fill(1);
            let committed = frame.commit(Commit {
                len: 10,
                token: SenderToken::new(token),
                options: TxOptions::none(),
            });
            assert!(committed.is_ok());
        }
        // A dropped frame and a rejected commit.
        drop(h.tx.claim_tx(queue, 10));
        let frame = h.tx.claim_tx(queue, 10).unwrap_or_else(|_| unreachable!());
        let rejected = frame.commit(Commit {
            len: 11,
            token: SenderToken::new(0),
            options: TxOptions::none(),
        });
        assert!(rejected.is_err());
        drop(rejected);
        let outcome = h.tx.flush(request, &mut Permit, &mut report);
        assert_eq!(outcome.submitted, 2);
        while report.pop_front().is_some() {}
        let outcome = h.tx.flush(request, &mut Permit, &mut report);
        assert_eq!(outcome.stop, FlushStop::WouldBlock);
        while report.pop_front().is_some() {}
        let mut handler = Count(0);
        let outcome = h.rx.poll_rx(Budget::new(8, 8 * 256, 8), &mut handler);
        assert_eq!((outcome.delivered, outcome.dropped), (1, 1));
        let outcome = h.tx.poll_completions(Budget::new(8, 0, 8), &mut NoEvents);
        assert_eq!(outcome.events, 0);
    });
    assert_eq!(allocations, 0, "the data calls allocate and free nothing");
    h.shutdown();
}

/// A model of the driver's gate of guards-and-abort.md, keyed by one
/// authority: an Acquire load of the guard word, a permit while open, and
/// the between gates step that publishes `applied_epoch` with the
/// submitted positions (section 6.2, step 4).
struct GuardGate {
    /// The guard epoch; odd while open, even once closed.
    guard: Arc<AtomicU64>,
    applied_epoch: u64,
    /// Tokens submitted since the last publication: old epoch in flight
    /// when the next publication applies a close.
    in_flight: Vec<u64>,
    /// Each publication: the epoch applied and the in flight list it
    /// carried.
    published: Vec<(u64, Vec<u64>)>,
}

impl GuardGate {
    fn new(guard: Arc<AtomicU64>) -> Self {
        let applied_epoch = guard.load(Ordering::Acquire);
        Self {
            guard,
            applied_epoch,
            in_flight: Vec::new(),
            published: Vec::new(),
        }
    }

    /// The sender records its submitted entries before the next exposure.
    fn record(&mut self, entries: &[TxEntry]) {
        self.in_flight.extend(
            entries
                .iter()
                .filter(|entry| matches!(entry.outcome, TxItemOutcome::Submitted { .. }))
                .map(|entry| entry.token.get()),
        );
    }

    /// The between gates step: run once per duty cycle, outside flush.
    fn between_gates(&mut self) {
        let observed = self.guard.load(Ordering::Acquire);
        if observed > self.applied_epoch {
            self.applied_epoch = observed;
            self.published
                .push((observed, std::mem::take(&mut self.in_flight)));
        }
    }

    fn closed(&self) -> bool {
        self.guard.load(Ordering::Acquire).is_multiple_of(2)
    }
}

impl SenderGate for GuardGate {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        self.between_gates();
        if self.closed() {
            GateDecision::Deny
        } else {
            GateDecision::Permit {
                count: nz(u16::try_from(candidate.tokens.len()).unwrap()),
            }
        }
    }
}

#[test]
fn guard_race_close_between_permit_and_system_call() {
    let guard = Arc::new(AtomicU64::new(1));
    let mut gate = GuardGate::new(Arc::clone(&guard));
    let mut h = Harness::new();
    h.commit_n(0, 2);
    // The send hook closes the guard after the permit, before the call.
    let closer = Arc::clone(&guard);
    let armed = Arc::new(AtomicBool::new(true));
    let once = Arc::clone(&armed);
    h.socket.set_send_hook(Box::new(move |_, _| {
        if once.swap(false, Ordering::Relaxed) {
            closer.store(2, Ordering::Release);
        }
    }));
    h.socket.push_send(SendResult::Sent {
        sent: 2,
        error: None,
    });
    let (outcome, entries) = h.flush(&mut gate);
    assert_eq!(outcome.submitted, 2, "the permitted exposure completes");
    gate.record(&entries);
    gate.between_gates();
    // The datagrams appear as old epoch in flight in the applied close.
    assert_eq!(gate.published, vec![(2, vec![0, 1])]);
    // No submission follows the applied close.
    h.commit_n(2, 1);
    let (outcome, entries) = h.flush(&mut gate);
    assert_eq!(outcome.stop, FlushStop::GateDenied);
    assert_eq!(h.socket.send_calls(), 1);
    assert_eq!(
        entries[0].outcome,
        TxItemOutcome::Pending {
            cause: PendingCause::GateDenied
        }
    );
    h.shutdown();
}

#[test]
fn guard_race_failed_admission_after_permit() {
    let guard = Arc::new(AtomicU64::new(1));
    let mut gate = GuardGate::new(Arc::clone(&guard));
    let mut h = Harness::new();
    h.commit_n(0, 2);
    let closer = Arc::clone(&guard);
    h.socket.set_send_hook(Box::new(move |_, _| {
        closer.store(2, Ordering::Release);
    }));
    // Admission fails after the permit: the items stay pending.
    h.socket.push_send(SendResult::Error(Errno::AGAIN));
    let (outcome, entries) = h.flush(&mut gate);
    assert_eq!(outcome.stop, FlushStop::WouldBlock);
    gate.record(&entries);
    // The next flush calls the gate, sees the close and submits nothing.
    let (outcome, _) = h.flush(&mut gate);
    assert_eq!(outcome.stop, FlushStop::GateDenied);
    assert_eq!(h.socket.send_calls(), 1);
    assert_eq!(gate.published, vec![(2, vec![])]);
    assert_eq!(h.tx.pending(), 2);
    h.shutdown();
}

#[test]
fn idle_close() {
    let guard = Arc::new(AtomicU64::new(1));
    let mut gate = GuardGate::new(Arc::clone(&guard));
    let mut h = Harness::open(config(), 4);
    // A second queue, faulted by a head error.
    let faulted =
        h.tx.open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route: h.route,
            max_pending: nz(2),
        })
        .unwrap();
    h.commit_to(faulted, b"head", 1);
    h.socket.push_send(SendResult::Error(Errno::MSGSIZE));
    h.flush_queue(faulted, &mut gate);
    assert_eq!(gate.published, vec![]);
    // The guard closes while every queue is empty or faulted.
    guard.store(2, Ordering::Release);
    // One duty cycle (5.3): poll_completions, poll_rx, one flush per
    // queue, then the between gates step.
    h.tx.poll_completions(Budget::new(1, 0, 1), &mut NoopCompletions);
    h.rx.poll_rx(Budget::new(1, 256, 1), &mut Recorder::default());
    let calls = h.socket.send_calls();
    let (empty, _) = h.flush(&mut gate);
    let (fault, _) = h.flush_queue(faulted, &mut gate);
    assert_eq!(empty.stop, FlushStop::QueueEmpty);
    assert!(matches!(fault.stop, FlushStop::Faulted(_)));
    assert_eq!(gate.published, vec![], "no flush reached the gate");
    gate.between_gates();
    assert_eq!(
        gate.published,
        vec![(2, vec![])],
        "applied within one cycle"
    );
    assert_eq!(h.socket.send_calls(), calls);
    h.shutdown();
}

struct NoopCompletions;
impl CompletionHandler for NoopCompletions {
    fn event(&mut self, _: TxEvent) {}
}

#[test]
fn release_is_at_submission() {
    let mut h = Harness::new();
    h.commit_n(0, 1);
    h.socket.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    let (_, entries) = h.flush(&mut Gate::default());
    assert_eq!(
        entries[0].outcome,
        TxItemOutcome::Submitted {
            release: Release::AtSubmission
        }
    );
}
