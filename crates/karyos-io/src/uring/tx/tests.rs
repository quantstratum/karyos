// SPDX-License-Identifier: Apache-2.0

//! The TX state machine over [`ScriptedRing`], and over the real ring on
//! Linux with the `uring` feature.

use std::net::{Ipv4Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use super::*;
use crate::backend::{Authority, Budget, InstanceId, TxEntry};
use crate::uring::ops::{CancelTarget, Cqe, PushError, RingOps, UserData};
use crate::uring::scripted::{Pushed, ScriptedRing};

const SLOTS: u16 = 4;
const LEN: u16 = 64;

fn nz(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap_or(NonZeroU16::MIN)
}

fn config() -> UringTxConfig {
    UringTxConfig {
        max_datagram: nz(LEN),
        tx_slots: nz(SLOTS),
        max_queues: nz(2),
        max_routes: nz(2),
        max_batch: nz(8),
        sqpoll: None,
    }
}

fn destination() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 9000))
}

fn instance() -> InstanceId {
    InstanceId::new(NonZeroU32::MIN)
}

struct Fixture {
    tx: UringTx<ScriptedRing>,
    queue: TxQueueId,
    route: crate::backend::RouteId,
}

fn fixture_with(sq: usize) -> Fixture {
    let ring = ScriptedRing::new(SLOTS, LEN, sq);
    let tx = UringTx::open(config(), instance(), ring, CapabilityState::NotRequested);
    let Ok(mut tx) = tx else {
        panic!("open: {tx:?}");
    };
    let route = tx.add_route(destination());
    let Ok(route) = route else {
        panic!("route: {route:?}");
    };
    let queue = tx.open_queue(TxQueueConfig {
        authority: Authority::new(NonZeroU64::MIN),
        route,
        max_pending: nz(SLOTS),
        etf: None,
    });
    let Ok(queue) = queue else {
        panic!("queue: {queue:?}");
    };
    Fixture { tx, queue, route }
}

fn fixture() -> Fixture {
    fixture_with(16)
}

struct Permit;

impl SenderGate for Permit {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        let count = u16::try_from(candidate.tokens.len()).unwrap_or(0);
        match NonZeroU16::new(count) {
            Some(count) => GateDecision::Permit { count },
            None => GateDecision::Deny,
        }
    }
}

struct Deny;

impl SenderGate for Deny {
    fn check(&mut self, _: &Exposure<'_>) -> GateDecision {
        GateDecision::Deny
    }
}

#[derive(Default)]
struct Events(Vec<TxEvent>);

impl CompletionHandler for Events {
    fn event(&mut self, event: TxEvent) {
        self.0.push(event);
    }
}

fn commit(fixture: &mut Fixture, byte: u8, len: u16) -> TxTicket {
    let frame = fixture.tx.claim_tx(fixture.queue, usize::from(len));
    let Ok(mut frame) = frame else {
        panic!("claim: {frame:?}");
    };
    frame.bytes_mut().fill(byte);
    let ticket = frame.commit(Commit {
        len: usize::from(len),
        token: SenderToken::new(u64::from(byte)),
        options: crate::backend::TxOptions::none(),
    });
    match ticket {
        Ok(ticket) => ticket,
        Err(rejected) => panic!("commit: {:?}", rejected.error),
    }
}

fn request(queue: TxQueueId) -> FlushRequest {
    FlushRequest {
        queue,
        max_datagrams: nz(64),
        max_bytes: u32::MAX,
    }
}

fn drain(report: &mut TxReport) -> Vec<TxEntry> {
    std::iter::from_fn(|| report.pop_front()).collect()
}

fn budget() -> Budget {
    Budget::new(64, u64::MAX, 8)
}

fn slot_of(ticket: TxTicket) -> u16 {
    u16::try_from(ticket.id().slot()).unwrap_or(u16::MAX)
}

#[test]
fn a_flush_publishes_one_copied_sendmsg_per_item_released_by_its_completion() {
    let mut f = fixture();
    let first = commit(&mut f, 1, 10);
    let second = commit(&mut f, 2, 20);
    let mut report = TxReport::new();
    let outcome = f.tx.flush(request(f.queue), &mut Permit, &mut report);
    assert_eq!(outcome.stop, FlushStop::Exposed);
    assert_eq!(outcome.submitted, 2);
    assert_eq!(outcome.bytes, 30);
    let entries = drain(&mut report);
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert_eq!(
            entry.outcome,
            TxItemOutcome::Submitted {
                release: Release::Deferred
            }
        );
    }
    assert_eq!(f.tx.ring().enters(), 1, "one enter per flush");
    let sends: Vec<_> =
        f.tx.ring()
            .pushed()
            .iter()
            .filter_map(|pushed| match pushed {
                Pushed::Send {
                    slot,
                    len,
                    destination: to,
                    ..
                } => Some((*slot, *len, *to)),
                Pushed::Cancel { .. } => None,
            })
            .collect();
    assert_eq!(
        sends,
        vec![
            (slot_of(first), 10, destination()),
            (slot_of(second), 20, destination())
        ]
    );
    assert_eq!(f.tx.submitted(), 2);

    // Kernel owned: the bytes are not reachable and nothing is released.
    assert!(f.tx.ring_mut().bytes_mut(slot_of(first)).is_none());
    let mut events = Events::default();
    let none = f.tx.poll_completions(budget(), &mut events);
    assert_eq!(none.events, 0);
    assert!(events.0.is_empty());

    assert!(f.tx.ring_mut().complete_slot(slot_of(first), 10));
    let done = f.tx.poll_completions(budget(), &mut events);
    assert_eq!(done.events, 2);
    assert_eq!(
        events.0,
        vec![
            TxEvent::SendResult {
                id: first.id(),
                token: SenderToken::new(1),
                result: Ok(())
            },
            TxEvent::Released {
                id: first.id(),
                token: SenderToken::new(1)
            },
        ]
    );
    assert_eq!(f.tx.submitted(), 1);
    assert!(f.tx.ring_mut().bytes_mut(slot_of(first)).is_some());
    assert_eq!(
        f.tx.ring()
            .slot_bytes(slot_of(second))
            .map(|bytes| bytes[..20].to_vec()),
        Some(vec![2; 20]),
        "the kernel reads the committed bytes"
    );
}

#[test]
fn a_submitted_slot_is_never_claimed_again_before_its_completion() {
    let mut f = fixture();
    let sent = commit(&mut f, 7, 8);
    let mut report = TxReport::new();
    f.tx.flush(request(f.queue), &mut Permit, &mut report);
    drain(&mut report);
    // Every other slot can be claimed; the kernel owned one cannot.
    let mut others = Vec::new();
    for byte in 0..SLOTS - 1 {
        let ticket = commit(&mut f, u8::try_from(byte).unwrap_or(0), 4);
        assert_ne!(ticket.id().slot(), sent.id().slot());
        others.push(ticket);
    }
    assert!(matches!(
        f.tx.claim_tx(f.queue, 4),
        Err(ClaimError::QueueFull { .. })
    ));
    assert!(f.tx.ring().owner(slot_of(sent)).is_some());
}

#[test]
fn sqpoll_is_off_by_default() {
    assert_eq!(UringTxConfig::default().sqpoll, None);
    let f = fixture();
    assert_eq!(f.tx.sqpoll(), CapabilityState::NotRequested);
}

#[test]
fn the_completion_table_of_design_3_5() {
    let rows: [(i32, Option<Result<(), SendError>>); 12] = [
        (16, Some(Ok(()))),
        (-90, Some(Err(SendError::MessageTooLarge))),
        (-101, Some(Err(SendError::Unreachable { errno: 101 }))),
        (-99, Some(Err(SendError::AddressUnavailable))),
        (-1, Some(Err(SendError::Denied { errno: 1 }))),
        (-11, Some(Err(SendError::WouldBlock))),
        (-105, Some(Err(SendError::NoBuffers))),
        (-111, Some(Err(SendError::PeerRefused))),
        (-125, Some(Err(SendError::Cancelled))),
        (-4, Some(Err(SendError::Other { errno: 4 }))),
        (-9, None),
        (3, None),
    ];
    for (result, expected) in rows {
        let mut f = fixture();
        let ticket = commit(&mut f, 1, 16);
        let mut report = TxReport::new();
        f.tx.flush(request(f.queue), &mut Permit, &mut report);
        drain(&mut report);
        f.tx.ring_mut().complete_slot(slot_of(ticket), result);
        let mut events = Events::default();
        f.tx.poll_completions(budget(), &mut events);
        match expected {
            Some(expected) => {
                assert_eq!(
                    events.0,
                    vec![
                        TxEvent::SendResult {
                            id: ticket.id(),
                            token: SenderToken::new(1),
                            result: expected
                        },
                        TxEvent::Released {
                            id: ticket.id(),
                            token: SenderToken::new(1)
                        },
                    ],
                    "result {result}"
                );
            }
            None => {
                assert!(events.0.is_empty(), "result {result}");
                assert_eq!(f.tx.counters().invariants, 1);
                let outcome = f.tx.flush(request(f.queue), &mut Permit, &mut report);
                assert_eq!(outcome.stop, FlushStop::Queue(QueueError::NeedsReset));
            }
        }
    }
    let mut f = fixture();
    let ticket = commit(&mut f, 1, 16);
    let mut report = TxReport::new();
    f.tx.flush(request(f.queue), &mut Permit, &mut report);
    f.tx.ring_mut().complete_slot(slot_of(ticket), -11);
    f.tx.poll_completions(budget(), &mut Events::default());
    let counters = f.tx.counters();
    assert_eq!(counters.send_wouldblock, 1);
    assert_eq!(counters.known_not_transmitted, 1);
}

#[test]
fn a_stale_or_duplicated_completion_never_releases_the_current_occupant() {
    let mut f = fixture();
    let ticket = commit(&mut f, 1, 16);
    let mut report = TxReport::new();
    f.tx.flush(request(f.queue), &mut Permit, &mut report);
    drain(&mut report);
    let slot = slot_of(ticket);
    let stale = UserData::new(slot, ticket.id().generation().get().wrapping_add(1));
    f.tx.ring_mut().complete(stale, 16, 0);
    let mut events = Events::default();
    f.tx.poll_completions(budget(), &mut events);
    assert!(events.0.is_empty());
    assert_eq!(f.tx.counters().stale_completions, 1);
    assert!(f.tx.ring().owner(slot).is_some(), "still kernel owned");
    assert_eq!(f.tx.submitted(), 1);
    let outcome = f.tx.flush(request(f.queue), &mut Permit, &mut report);
    assert_eq!(outcome.stop, FlushStop::Queue(QueueError::NeedsReset));

    // The real completion releases it once; a duplicate does nothing.
    f.tx.ring_mut().complete_slot(slot, 16);
    let real = UserData::new(slot, ticket.id().generation().get());
    f.tx.ring_mut().complete(real, 16, 0);
    f.tx.poll_completions(budget(), &mut events);
    let released = events
        .0
        .iter()
        .filter(|event| matches!(event, TxEvent::Released { .. }))
        .count();
    assert_eq!(released, 1);
    assert_eq!(f.tx.counters().stale_completions, 2);
}

#[test]
fn a_denied_gate_publishes_nothing() {
    let mut f = fixture();
    commit(&mut f, 1, 16);
    let mut report = TxReport::new();
    let outcome = f.tx.flush(request(f.queue), &mut Deny, &mut report);
    assert_eq!(outcome.stop, FlushStop::GateDenied);
    assert!(f.tx.ring().pushed().is_empty());
    assert_eq!(f.tx.ring().enters(), 0);
    let entries = drain(&mut report);
    assert_eq!(
        entries.first().map(|entry| entry.outcome),
        Some(TxItemOutcome::Pending {
            cause: PendingCause::GateDenied
        })
    );
}

#[test]
fn a_full_sq_stops_before_the_gate_and_clamps_the_prefix() {
    let mut f = fixture_with(1);
    commit(&mut f, 1, 16);
    commit(&mut f, 2, 16);
    let mut report = TxReport::new();
    f.tx.ring_mut().fail_next_enter(EINTR);
    let first = f.tx.flush(request(f.queue), &mut Permit, &mut report);
    assert_eq!(first.submitted, 1, "clamped to the free SQ entries");
    assert_eq!(first.stop, FlushStop::Interrupted);
    let entries = drain(&mut report);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>(),
        vec![TxItemOutcome::Submitted {
            release: Release::Deferred
        },],
        "only the free SQ entries are offered, and a failed enter after the publication changes no entry"
    );
    assert_eq!(f.tx.ring().unconsumed(), 1);
    // The next flush enters to drain the SQ, then publishes the next item.
    let second = f.tx.flush(request(f.queue), &mut Permit, &mut report);
    assert_eq!(second.submitted, 1);
    assert_eq!(second.stop, FlushStop::Exposed);
    assert_eq!(f.tx.counters().enter_retries, 1);
}

#[test]
fn cancel_submitted_releases_only_through_the_target_completion() {
    let mut f = fixture();
    let ticket = commit(&mut f, 1, 16);
    let mut report = TxReport::new();
    f.tx.flush(request(f.queue), &mut Permit, &mut report);
    drain(&mut report);
    let cancel = f.tx.cancel_submitted(f.queue);
    assert_eq!(
        cancel,
        Ok(CancelSubmitted {
            issued: 1,
            more: false
        })
    );
    let target = UserData::new(slot_of(ticket), ticket.id().generation().get());
    let control = f.tx.ring().pushed().iter().find_map(|pushed| match pushed {
        Pushed::Cancel {
            target: CancelTarget::One(named),
            user_data,
        } if *named == target => Some(*user_data),
        _ => None,
    });
    let Some(control) = control else {
        panic!("no cancel of the target was published");
    };
    // The cancel's own completion releases nothing.
    f.tx.ring_mut().complete(control, 0, 0);
    let mut events = Events::default();
    f.tx.poll_completions(budget(), &mut events);
    assert!(events.0.is_empty());
    assert_eq!(f.tx.submitted(), 1);
    f.tx.ring_mut().complete_slot(slot_of(ticket), -125);
    f.tx.poll_completions(budget(), &mut events);
    assert_eq!(
        events.0.first(),
        Some(&TxEvent::SendResult {
            id: ticket.id(),
            token: SenderToken::new(1),
            result: Err(SendError::Cancelled)
        })
    );
    assert_eq!(f.tx.counters().cancelled, 1);
    assert_eq!(f.tx.submitted(), 0);
}

#[test]
fn a_bounded_reset_retains_kernel_owned_storage_and_reports_its_cost() {
    let mut f = fixture();
    let ticket = commit(&mut f, 1, 16);
    commit(&mut f, 2, 16);
    let mut report = TxReport::new();
    let request = FlushRequest {
        queue: f.queue,
        max_datagrams: nz(1),
        max_bytes: u32::MAX,
    };
    f.tx.flush(request, &mut Permit, &mut report);
    drain(&mut report);
    let mut events = Events::default();
    let first = f.tx.reset(&mut report, budget(), &mut events);
    assert_eq!(first.returned, 1, "the pending item returns");
    assert!(first.more, "the kernel still owns the submitted one");
    assert_eq!(
        first.retained,
        Retained {
            slots: 1,
            bytes: u64::from(LEN)
        }
    );
    assert!(drain(&mut report).iter().all(|entry| entry.outcome
        == TxItemOutcome::Returned {
            reason: ReturnReason::Reset
        }));
    assert!(matches!(
        f.tx.claim_tx(f.queue, 4),
        Err(ClaimError::NotActive)
    ));
    // The ring cancel was published once; its count is 1, but the target
    // completes normally: the reset still completes on terminal CQEs.
    let cancel = f.tx.ring().pushed().iter().find_map(|pushed| match pushed {
        Pushed::Cancel {
            target: CancelTarget::All,
            user_data,
        } => Some(*user_data),
        _ => None,
    });
    let Some(cancel) = cancel else {
        panic!("no ring cancel");
    };
    let again = f.tx.reset(&mut report, budget(), &mut events);
    assert!(again.more);
    assert_eq!(again.retained.slots, 1, "nothing freed under the kernel");
    f.tx.ring_mut().complete(cancel, 1, 0);
    f.tx.ring_mut().complete_slot(slot_of(ticket), 16);
    let last = f.tx.reset(&mut report, budget(), &mut events);
    assert!(!last.more);
    assert_eq!(last.retained, Retained::default());
    assert_eq!(f.tx.counters().cancel_count_diff, 1);
    let cancels =
        f.tx.ring()
            .pushed()
            .iter()
            .filter(|pushed| matches!(pushed, Pushed::Cancel { .. }))
            .count();
    assert_eq!(cancels, 1);
}

#[test]
fn a_cq_overflow_quarantines_every_submitted_slot() {
    let mut f = fixture();
    let ticket = commit(&mut f, 1, 16);
    let mut report = TxReport::new();
    f.tx.flush(request(f.queue), &mut Permit, &mut report);
    drain(&mut report);
    f.tx.ring_mut().set_overflowed();
    let mut events = Events::default();
    f.tx.poll_completions(budget(), &mut events);
    assert_eq!(f.tx.counters().cq_overflow, 1);
    assert_eq!(f.tx.submitted(), 0);
    let outcome = f.tx.flush(request(f.queue), &mut Permit, &mut report);
    assert_eq!(
        outcome.stop,
        FlushStop::Failed(BackendFailure::Invariant {
            operation: "uring_cq_overflow"
        })
    );
    // A late completion releases kernel ownership but infers no release.
    f.tx.ring_mut().complete_slot(slot_of(ticket), 16);
    f.tx.poll_completions(budget(), &mut events);
    assert!(events.0.is_empty());
    assert_eq!(f.tx.retained(), Retained::default());
}

#[test]
fn flush_and_completions_do_not_allocate() {
    let mut f = fixture();
    let ticket = commit(&mut f, 1, 16);
    let mut report = TxReport::new();
    let mut gate = Permit;
    let (outcome, allocations) = karyos_sys::alloc_count::count_allocations(|| {
        f.tx.flush(request(f.queue), &mut gate, &mut report)
    });
    assert_eq!(outcome.submitted, 1);
    assert_eq!(allocations, 0);
    drain(&mut report);
    f.tx.ring_mut().complete_slot(slot_of(ticket), 16);
    let mut events = Events(Vec::with_capacity(8));
    let (_, allocations) =
        karyos_sys::alloc_count::count_allocations(|| f.tx.poll_completions(budget(), &mut events));
    assert_eq!(allocations, 0);
}

#[test]
fn the_configuration_bounds_user_data_and_the_batch() {
    let mut wide = config();
    wide.tx_slots = nz(u16::MAX);
    assert!(matches!(
        wide.validate(),
        Err(OpenError::InvalidConfig {
            field: "tx_slots",
            ..
        })
    ));
    let mut batch = config();
    batch.max_batch = nz(URING_MAX_BATCH + 1);
    assert!(batch.validate().is_err());
    assert_eq!(config().sq_entries(), 16);
    assert_eq!(UringTxConfig::default().sq_entries(), 64);
    assert_eq!(UringTxConfig::default().cq_entries(), 512);
}

#[test]
fn send_and_control_identities_are_disjoint() {
    let mut ring = ScriptedRing::new(SLOTS, LEN, 16);
    let dest = destination();
    // A send must carry its own slot's identity.
    assert_eq!(
        ring.push_send(1, 8, dest, UserData::new(2, 1)),
        Err(PushError::OutOfRange)
    );
    // A cancel may not carry a send slot's identity.
    assert_eq!(
        ring.push_cancel(CancelTarget::All, UserData::new(1, 1)),
        Err(PushError::OutOfRange)
    );
    assert_eq!(ring.push_send(1, 8, dest, UserData::new(1, 1)), Ok(()));
    assert_eq!(
        ring.push_cancel(CancelTarget::All, UserData::new(SLOTS, 1)),
        Ok(())
    );
    // The cancel's completion never ends the send's kernel ownership.
    ring.complete(UserData::new(SLOTS, 1), 1, 0);
    let mut cqes = [Cqe::EMPTY; 4];
    ring.reap(&mut cqes);
    assert!(ring.owner(1).is_some());
}

#[test]
fn closing_a_queue_waits_for_its_submitted_items_and_strands_no_slot() {
    let mut f = fixture();
    let mut report = TxReport::new();
    for round in 0..(u32::from(SLOTS) * 4) {
        let ticket = commit(&mut f, 1, 8);
        f.tx.flush(request(f.queue), &mut Permit, &mut report);
        drain(&mut report);
        let first = f.tx.close_queue(f.queue, &mut report).unwrap();
        assert!(
            first.more,
            "round {round}: a submitted item keeps the queue open"
        );
        assert!(matches!(
            f.tx.claim_tx(f.queue, 4),
            Err(ClaimError::UnknownQueue)
        ));
        f.tx.ring_mut().complete_slot(slot_of(ticket), 8);
        f.tx.poll_completions(budget(), &mut Events::default());
        let last = f.tx.close_queue(f.queue, &mut report).unwrap();
        assert!(!last.more);
        f.queue =
            f.tx.open_queue(TxQueueConfig {
                authority: Authority::new(NonZeroU64::MIN),
                route: f.route,
                max_pending: nz(SLOTS),
                etf: None,
            })
            .unwrap();
    }
}

#[test]
fn the_cq_is_never_smaller_than_the_sq() {
    let mut small = config();
    small.tx_slots = nz(8);
    small.max_batch = nz(32);
    assert!(small.cq_entries() >= small.sq_entries());
}

/// The real ring on this kernel. Where the environment denies
/// `io_uring` (a default Docker seccomp profile, `io_uring_disabled`),
/// each test says so and returns, unless `KARYOS_URING_REQUIRED` is set,
/// which the Linux gate run sets.
#[cfg(all(feature = "uring", target_os = "linux"))]
#[expect(
    clippy::print_stderr,
    reason = "a skipped kernel test says why on the test output"
)]
mod kernel {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::backend::Reason;
    use crate::uring::ring::{OsRing, probe_send_parking};

    fn required() -> bool {
        std::env::var_os("KARYOS_URING_REQUIRED").is_some()
    }

    fn open_ring(config: &UringTxConfig) -> Option<(OsRing, crate::uring::ring::OsRingProbes)> {
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        match OsRing::open(local, config) {
            Ok(opened) => Some(opened),
            Err(OpenError::Os {
                operation: "io_uring_setup",
                errno,
            }) if !required() => {
                eprintln!("io_uring unavailable here (io_uring_setup errno {errno}); skipped");
                None
            }
            Err(error) => panic!("open: {error}"),
        }
    }

    #[test]
    fn a_datagram_goes_out_through_the_ring_and_is_released_by_its_completion() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0));
        let Ok(receiver) = receiver else {
            panic!("bind: {receiver:?}");
        };
        let Ok(to) = receiver.local_addr() else {
            panic!("local_addr");
        };
        let _ = receiver.set_read_timeout(Some(Duration::from_secs(5)));
        let config = config();
        let Some((ring, probes)) = open_ring(&config) else {
            return;
        };
        assert_eq!(probes.sqpoll, CapabilityState::NotRequested);
        let tx = UringTx::open(config, instance(), ring, probes.sqpoll);
        let Ok(mut tx) = tx else {
            panic!("open: {tx:?}");
        };
        let Ok(route) = tx.add_route(to) else {
            panic!("route");
        };
        let Ok(queue) = tx.open_queue(TxQueueConfig {
            authority: Authority::new(NonZeroU64::MIN),
            route,
            max_pending: nz(SLOTS),
            etf: None,
        }) else {
            panic!("queue");
        };
        let Ok(mut frame) = tx.claim_tx(queue, 5) else {
            panic!("claim");
        };
        frame.bytes_mut().copy_from_slice(b"karyo");
        let Ok(ticket) = frame.commit(Commit {
            len: 5,
            token: SenderToken::new(9),
            options: crate::backend::TxOptions::none(),
        }) else {
            panic!("commit");
        };
        let mut report = TxReport::new();
        let outcome = tx.flush(request(queue), &mut Permit, &mut report);
        assert_eq!(outcome.stop, FlushStop::Exposed);
        assert_eq!(outcome.submitted, 1);
        let mut events = Events::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        while events.0.len() < 2 && Instant::now() < deadline {
            tx.poll_completions(budget(), &mut events);
            std::thread::yield_now();
        }
        assert_eq!(
            events.0,
            vec![
                TxEvent::SendResult {
                    id: ticket.id(),
                    token: SenderToken::new(9),
                    result: Ok(())
                },
                TxEvent::Released {
                    id: ticket.id(),
                    token: SenderToken::new(9)
                },
            ]
        );
        let mut buffer = [0_u8; 16];
        let received = receiver.recv_from(&mut buffer);
        let Ok((len, from)) = received else {
            panic!("recv: {received:?}");
        };
        assert_eq!(buffer.get(..len), Some(&b"karyo"[..]));
        assert_eq!(Ok(from), tx.ring().local_addr());
        assert_eq!(tx.retained(), Retained::default());
    }

    #[test]
    fn a_send_on_a_full_buffer_parks_and_is_cancelled() {
        let state = probe_send_parking();
        if !required()
            && matches!(
                state,
                CapabilityState::Fallback(Reason::ProbeFailed { errno: 1 | 38 })
            )
        {
            eprintln!("io_uring unavailable here; skipped");
            return;
        }
        assert_eq!(
            state,
            CapabilityState::Active,
            "the kernel parks a send on a full buffer, and a cancel ends it with -ECANCELED"
        );
    }

    /// The default Docker profile job of IU-10: with
    /// `KARYOS_URING_EXPECT_DENIED` set, the setup must be denied with
    /// `EPERM`, distinct from `ENOSYS` (design section 9).
    #[test]
    fn a_denying_seccomp_profile_is_reported_as_denied() {
        if std::env::var_os("KARYOS_URING_EXPECT_DENIED").is_none() {
            return;
        }
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let opened = OsRing::open(local, &config());
        assert!(
            matches!(
                opened,
                Err(OpenError::Os {
                    operation: "io_uring_setup",
                    errno: 1
                })
            ),
            "{:?}",
            opened.map(|_| ())
        );
    }

    #[test]
    fn a_configured_sqpoll_is_set_up_without_the_taskrun_flags() {
        let mut polled = config();
        polled.sqpoll = Some(SqPoll {
            cpu: 0,
            idle_ms: 10,
        });
        let Some((_ring, probes)) = open_ring(&polled) else {
            return;
        };
        // EINVAL would mean the SQPOLL setup still carried COOP_TASKRUN or
        // TASKRUN_FLAG; a denial or another kernel refusal stays possible.
        assert_ne!(
            probes.sqpoll,
            CapabilityState::Fallback(Reason::ProbeFailed { errno: 22 })
        );
    }

    #[test]
    fn the_real_ring_refuses_a_cancel_with_a_send_identity() {
        let Some((mut ring, _)) = open_ring(&config()) else {
            return;
        };
        assert_eq!(
            ring.push_cancel(CancelTarget::All, UserData::new(0, 1)),
            Err(PushError::OutOfRange)
        );
        assert_eq!(
            ring.push_send(0, 4, destination(), UserData::new(1, 1)),
            Err(PushError::OutOfRange)
        );
    }

    #[test]
    fn sqpoll_stays_off_unless_configured() {
        let Some((ring, probes)) = open_ring(&config()) else {
            return;
        };
        assert_eq!(probes.sqpoll, CapabilityState::NotRequested);
        drop(ring);
    }
}

#[test]
fn an_etf_queue_is_an_unavailable_capability() {
    let mut f = fixture();
    let etf = crate::backend::EtfQueue {
        interface: 1,
        priority: 3,
        delta_ns: 300_000,
    };
    assert_eq!(
        f.tx.open_queue(TxQueueConfig {
            authority: Authority::new(NonZeroU64::MIN),
            route: f.route,
            max_pending: nz(1),
            etf: Some(etf),
        }),
        Err(QueueError::EtfUnavailable {
            reason: crate::backend::Reason::Platform
        })
    );
}
