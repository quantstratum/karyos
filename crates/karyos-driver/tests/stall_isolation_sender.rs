// SPDX-License-Identifier: Apache-2.0

//! SPEC.md §13 "Stall isolation and capacity" with the real network sender
//! as the participant that keeps up (karyos#627): two optional readers and
//! an observer stalled inside their copies with their loans held, on the
//! lane of a reliable network publication whose sender keeps up with a
//! receiver in another driver, while an in-process publisher runs ten
//! terms; then one more admission arrives.
//!
//! A paused claim, the row's other holder, has its own test here: the
//! sender reads the lane in order and cannot pass the claim's uncommitted
//! block, so the publisher is held at its window until the claim's
//! deadline aborts the claim (SPEC.md §13, clarified 2026-10-27;
//! quantstratum-docs: karyos/design/claim-deadline.md). On a lane with no
//! in-order reader a paused claim never holds the publisher (`karyos-sys`,
//! `test_stall_isolation_optional_observer_claim`).
//!
//! The readers pause through `PausePoint::ReadLoanHeld`, a hook armed for
//! the whole process, so these tests have their own binary and run one at
//! a time: no other poll can reach the armed point.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    reason = "tests, as ADR-0007 allows; the log records what the run did"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use karyos_client::concurrent::{ConcurrentClaimOutcome, ConcurrentOfferOutcome};
use karyos_client::{ClientSubscription, CommitOutcome, MessageLimit};
use karyos_driver::agents::ThreadingMode;
use karyos_driver::net::NetworkConfig;
use karyos_driver::{AggregateConfig, DriverConfig, DriverError, EmbeddedDriver, StreamConfig};
use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::counters::CellRead;
use karyos_sys::error::SysError;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::test_pause::{self, PausePoint};

/// Spare slots `S`. Credits: two concurrent publishers, the sender's
/// reader, two optional readers and the observer make six, which is
/// `S - 1` (one slot of cleaning headroom): the lane is full, and one more
/// admission is refused.
const SPARES: u8 = 7;
const TERM: u64 = MIN_TERM_LENGTH as u64;
const PAYLOAD: usize = 1000;
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// One test at a time: the pause point is armed for the whole process.
static SERIAL: Mutex<()> = Mutex::new(());

/// Readers paused inside their copies.
static HOLDING: AtomicUsize = AtomicUsize::new(0);
/// Set once the run is over: the paused readers go on.
static GO: AtomicBool = AtomicBool::new(false);

/// The `ReadLoanHeld` hook: counts the pause and waits for [`GO`], the
/// reader's loan held.
fn hold_here(_: PausePoint) {
    HOLDING.fetch_add(1, Ordering::SeqCst);
    while !GO.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn driver() -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading: ThreadingMode::Shared,
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap()
}

/// One concurrent lane of two publishers, `S` = 7, room for the sender,
/// its retention hold and three local readers, and a claim deadline of
/// `claim_deadline` nanoseconds.
fn aggregate(claim_deadline: u64) -> AggregateConfig {
    AggregateConfig {
        stream: StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: SPARES,
                max_subscribers: 6,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 3,
                stream_id: 10,
                claim_deadline,
                publication: PublicationMode::Concurrent {
                    publishers: 2,
                    allow_non_lse: true,
                },
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        },
        quanta: vec![u64::from(DEFAULT_MTU) * 4],
    }
}

fn channel(address: SocketAddr) -> UdpConfig {
    UdpConfig {
        retransmit_window: None,
        nak_control: Vec::new(),
        linger: None,
        path_skew: None,
        destination: Destination::Unicast(address),
        interface: Some(Interface::Address(LOOPBACK)),
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
        etf: None,
    }
}

/// The "slots quarantined" gauge: slots held out of rotation by a loan.
fn quarantined(driver: &EmbeddedDriver) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == b"slots quarantined" => Some(value),
            _ => None,
        })
        .unwrap()
}

/// A stalled reader: pauses inside its first copy with its loan held,
/// then, once released, keeps polling until it is lapped. Returns the
/// first message it read and whether it was lapped.
fn stalled(mut reader: ClientSubscription) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut first = None;
        for _ in 0..100_000 {
            let summary = reader
                .poll(
                    |bytes, _| {
                        if first.is_none() {
                            first = Some(bytes.to_vec());
                        }
                    },
                    MessageLimit::new(1),
                )
                .unwrap();
            if summary.overrun.is_some() {
                return (first.unwrap_or_default(), true);
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        (first.unwrap_or_default(), false)
    })
}

/// SPEC.md §13 "Stall isolation and capacity", the kept-up participant
/// being the network sender itself: the stalled holders never cause
/// `BackPressured` or `ResourcesUnavailable` for the in-process publisher;
/// slots held out of rotation never exceed `S`; the extra admission is
/// `ResourcesUnavailable`; the stalled readers read the bytes committed
/// before the run unchanged, and then are lapped (`Overrun`). The sender
/// keeps up: the receiver gets every message exactly once and in order.
#[test]
fn test_stall_isolation_a_kept_up_network_sender_never_holds_the_publisher() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (mut a, mut b, lane, mut receiver) = connected(u64::MAX / 2);
    let mut running = a.concurrent_publication(lane).unwrap();

    // The readers join at the head, then the message every one of them
    // copies first is committed.
    let subscribed: Vec<_> = [Role::Optional, Role::Optional, Role::Observer]
        .into_iter()
        .map(|role| (role, a.subscribe(lane, role).unwrap()))
        .collect();
    let first = [0x5au8; PAYLOAD];
    assert!(matches!(
        running.offer(&first).unwrap(),
        ConcurrentOfferOutcome::Accepted { .. }
    ));
    // Each reader pauses in its copy of it, its loan held; the point is
    // armed again for the next once the last one paused. Nothing else
    // polls meanwhile, so only these readers reach it.
    let mut readers = Vec::new();
    for (index, (role, reader)) in subscribed.into_iter().enumerate() {
        test_pause::arm(PausePoint::ReadLoanHeld, hold_here);
        readers.push(stalled(reader));
        for _ in 0..5000 {
            if HOLDING.load(Ordering::SeqCst) > index {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(HOLDING.load(Ordering::SeqCst), index + 1, "{role:?} paused");
    }

    // Ten terms from the in-process publisher, at the rate the sender
    // keeps up with, while the receiver reads every message in order.
    let messages = u32::try_from(10 * TERM / 1056).unwrap();
    let (mut sent, mut received) = (0u32, 0u32);
    let mut most_quarantined = 0;
    for _ in 0..400_000 {
        if sent < messages {
            let mut payload = [0u8; PAYLOAD];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match running.offer(&payload) {
                Ok(ConcurrentOfferOutcome::Accepted { .. }) => sent += 1,
                Ok(ConcurrentOfferOutcome::AdminAction) => {}
                Ok(other) => panic!("message {sent}: {other:?} with stalled holders"),
                Err(error) => panic!("message {sent}: {error:?} with stalled holders"),
            }
        }
        let _ = receiver.poll(
            |bytes, _, _| {
                // The first message, committed before the run, and then
                // every one of the run, in order, once each.
                if bytes[..] != first[..] {
                    let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                    assert_eq!(index, received, "exactly once, in order");
                    received += 1;
                }
            },
            Budget {
                work: 256,
                bytes: 1 << 22,
            },
        );
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        let held = quarantined(&a);
        assert!(
            held <= u64::from(SPARES),
            "{held} slots held out of rotation"
        );
        most_quarantined = most_quarantined.max(held);
        if sent == messages && received == messages {
            break;
        }
        std::thread::sleep(Duration::from_micros(50));
    }
    assert_eq!((sent, received), (messages, messages), "the sender kept up");
    assert!(most_quarantined >= 1, "the held loans quarantined no slot");

    // One more admission: the lane's credits are spent.
    assert!(
        matches!(
            a.subscribe(lane, Role::Optional),
            Err(DriverError::Sys(SysError::ResourcesUnavailable))
        ),
        "the extra admission is refused"
    );
    println!(
        "{messages} messages over ten terms, sent and received in order; \
         at most {most_quarantined} slots quarantined of {SPARES}"
    );

    // The stalled readers go on: each read the first message unchanged,
    // and is then lapped.
    GO.store(true, Ordering::SeqCst);
    for (index, reader) in readers.into_iter().enumerate() {
        let (bytes, lapped) = reader.join().unwrap();
        assert_eq!(bytes, first, "reader {index} read the bytes it held");
        assert!(lapped, "reader {index} was not lapped");
    }
}

/// Two drivers: A publishes the lane over a reliable channel with
/// `claim_deadline`, B receives it; B's image reader is returned.
fn connected(
    claim_deadline: u64,
) -> (
    EmbeddedDriver,
    EmbeddedDriver,
    karyos_driver::StreamHandle,
    karyos_client::aggregate::AggregateSubscription,
) {
    let (mut a, mut b) = (driver(), driver());
    let _ = b
        .add_network_subscription(10, &channel(SocketAddr::new(LOOPBACK, 0)))
        .unwrap();
    let address = b.network_subscription_address(10).unwrap();
    let publication = a
        .add_network_publication(aggregate(claim_deadline), &channel(address))
        .unwrap();
    let lane = publication.lane(Lane::ZERO).unwrap();
    let mut image = None;
    for _ in 0..40_000 {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        image = b.network_image(10, 3);
        if image.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    let receiver = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    (a, b, lane, receiver)
}

/// The claim deadline of the paused-claim test: 50 ms.
const DEADLINE: Duration = Duration::from_millis(50);

/// How late after its deadline the claim's abort may free the publisher:
/// a duty cycle finds the expired claim and aborts it, then the sender
/// sends past the aborted block and the receiver's status message moves
/// the limit. Two seconds bounds that on a loaded test host; on a quiet
/// one it takes a few cycles.
const ABORT_MARGIN: Duration = Duration::from_secs(2);

/// SPEC.md §13 "Stall isolation and capacity", a paused claim on a lane
/// with an in-order reader (clarified 2026-10-27): the network sender reads
/// the lane in order and cannot pass the claim's uncommitted block, so the
/// publisher is `BackPressured` once it fills its window, a concurrent
/// lane's `term_length / 2 - (P - 1) × max_reserved`. That back pressure
/// ends when the claim's deadline aborts the claim
/// (quantstratum-docs: karyos/design/claim-deadline.md): no earlier than
/// the deadline, and within [`ABORT_MARGIN`] after it. The publisher then
/// goes on, and the receiver gets every message once and in order, the
/// aborted block skipped.
#[test]
fn test_stall_isolation_a_paused_claim_holds_the_in_order_sender_until_its_deadline() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let deadline = u64::try_from(DEADLINE.as_nanos()).unwrap();
    let (mut a, mut b, lane, mut receiver) = connected(deadline);
    let mut running = a.concurrent_publication(lane).unwrap();
    let mut paused = a.concurrent_publication(lane).unwrap();
    let ConcurrentClaimOutcome::Claimed(claim) = paused.try_claim(64).unwrap() else {
        panic!("the claim was not granted");
    };
    let claimed = Instant::now();
    let window = TERM / 2 - u64::from(MIN_TERM_LENGTH / 8);
    let messages = 200u32;
    let (mut sent, mut received) = (0u32, 0u32);
    let payload_of = |index: u32| {
        let mut payload = [0u8; PAYLOAD];
        payload[..4].copy_from_slice(&index.to_le_bytes());
        payload
    };
    // The window is filled before any duty cycle runs (karyos#832; SPEC
    // §13, "Stall isolation and capacity"). The claim's deadline counts
    // from the conductor's first sight of the claim, in `a.do_work()`, so
    // it cannot pass while the window fills, however loaded the host. No
    // duty cycle may run inside this burst.
    let mut held = None;
    while sent < messages {
        match running.offer(&payload_of(sent)).unwrap() {
            ConcurrentOfferOutcome::Accepted { .. } => sent += 1,
            ConcurrentOfferOutcome::BackPressured => {
                held = Some((sent, Instant::now()));
                break;
            }
            ConcurrentOfferOutcome::AdminAction => {
                panic!("AdminAction before the window filled, after {sent} offers")
            }
            other => panic!("message {sent}: {other:?}"),
        }
    }
    let Some((at, since)) = held else {
        panic!("the window was not filled before the claim's deadline: {sent} offers accepted");
    };
    // Until the first duty cycle the limit is the stored `join + window`,
    // so that refusal holds with or without a claim. After it, the
    // conductor has seen the claim, and the publisher must still be held:
    // the sender cannot pass the claim's block. The claim's deadline counts
    // from this cycle, so the publisher must stay held until it passes.
    let seen = Instant::now();
    let _ = a.do_work().unwrap();
    let _ = b.do_work().unwrap();
    assert!(
        matches!(
            running.offer(&payload_of(sent)).unwrap(),
            ConcurrentOfferOutcome::BackPressured
        ),
        "the claim did not hold the publisher after the first duty cycle"
    );
    let mut freed = None;
    for _ in 0..400_000 {
        if sent < messages {
            match running.offer(&payload_of(sent)).unwrap() {
                ConcurrentOfferOutcome::Accepted { .. } => {
                    if freed.is_none() {
                        freed = Some(Instant::now());
                    }
                    sent += 1;
                }
                ConcurrentOfferOutcome::BackPressured | ConcurrentOfferOutcome::AdminAction => {}
                other => panic!("message {sent}: {other:?}"),
            }
        }
        let _ = receiver.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, received, "once each, in order");
                received += 1;
            },
            Budget {
                work: 256,
                bytes: 1 << 22,
            },
        );
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        if sent == messages && received == messages {
            break;
        }
        std::thread::sleep(Duration::from_micros(50));
    }
    let freed = freed.expect("the publisher was never freed");
    // Held at its window: the claim's block (64 bytes and a 32-byte
    // header), then the messages behind it, 1056 bytes each.
    let filled = 96 + u64::from(at) * 1056;
    assert!(
        filled <= window && window < filled + 1056,
        "held after {at} messages, {filled} bytes, for a window of {window}"
    );
    // Held until the deadline, which counts from the conductor's first
    // sight of the claim (`seen`), and freed within the margin after it.
    assert!(
        freed >= seen + DEADLINE,
        "freed {:?} after the claim was seen, before its {DEADLINE:?} deadline",
        freed - seen
    );
    assert!(
        freed <= claimed + DEADLINE + ABORT_MARGIN,
        "freed {:?} after the deadline",
        freed - (claimed + DEADLINE)
    );
    assert!(
        matches!(claim.commit(), CommitOutcome::Aborted { .. }),
        "the deadline aborted the claim"
    );
    assert_eq!((sent, received), (messages, messages));
    println!(
        "held after {at} messages ({filled} of {window} bytes) for {:?}; \
         freed {:?} after the claim, whose deadline is {DEADLINE:?}",
        freed - since,
        freed - claimed
    );
}
