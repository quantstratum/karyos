// SPDX-License-Identifier: Apache-2.0

//! Mapping generations and the cutover in the embedded driver
//! (`quantstratum-docs: karyos/design/mapping-generations.md`, g3), with a manual clock.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::{
    ClaimOutcome, ClientSubscription, CommitOutcome, ConcurrentClaimOutcome,
    ConcurrentOfferOutcome, MessageLimit, OfferOutcome, PollSummary,
};
use karyos_driver::{
    DriverConfig, DriverError, EmbeddedDriver, MonotonicClock, Reconfiguration, SealState,
    StreamConfig, StreamHandle, StreamState,
};
use karyos_sys::error::SysError;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::{Generation, TermId};

const DEADLINE: u64 = 100;
const CLAIM_DEADLINE: u64 = 50;

#[derive(Debug, Clone, Default)]
struct ManualClock {
    now: Arc<AtomicU64>,
}

impl ManualClock {
    fn set(&self, now: u64) {
        self.now.store(now, Ordering::Relaxed);
    }
}

impl MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

fn driver(max_retained_generations: usize) -> (EmbeddedDriver, ManualClock) {
    let clock = ManualClock::default();
    let config = DriverConfig {
        cutover_deadline: DEADLINE,
        max_retained_generations,
        ..DriverConfig::default()
    };
    let driver = EmbeddedDriver::with_clock(config, Box::new(clock.clone())).unwrap();
    (driver, clock)
}

fn stream(
    driver: &mut EmbeddedDriver,
    stream_id: i32,
    publication: PublicationMode,
) -> StreamHandle {
    driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 6,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id,
                claim_deadline: CLAIM_DEADLINE,
                publication,
            },
            allow_unconnected: true,
            on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
            conflation: None,
        })
        .unwrap()
}

fn concurrent(publishers: u8) -> PublicationMode {
    PublicationMode::Concurrent {
        publishers,
        allow_non_lse: true,
    }
}

fn larger() -> Reconfiguration {
    Reconfiguration {
        term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
        spare_slots: 5,
    }
}

/// Polls until a poll delivers nothing, returning the messages with their
/// positions and the last summary.
fn read(subscription: &mut ClientSubscription) -> (Vec<(u64, Vec<u8>)>, PollSummary) {
    let mut seen = Vec::new();
    loop {
        let summary = subscription
            .poll(
                |bytes, info| seen.push((info.position, bytes.to_vec())),
                MessageLimit::new(8),
            )
            .unwrap();
        if summary.delivered == 0 && summary.aborted.is_none() {
            return (seen, summary);
        }
    }
}

/// The value of the driver counter labelled `label`.
fn counter(driver: &EmbeddedDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            karyos_sys::counters::CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

fn accepted(outcome: OfferOutcome) -> u64 {
    match outcome {
        OfferOutcome::Accepted { position, .. } => position,
        other => panic!("not accepted: {other:?}"),
    }
}

fn concurrent_accepted(outcome: ConcurrentOfferOutcome) -> u64 {
    match outcome {
        ConcurrentOfferOutcome::Accepted { position, .. } => position,
        other => panic!("not accepted: {other:?}"),
    }
}

#[test]
fn an_exclusive_stream_moves_to_a_larger_term_with_continuous_positions() {
    let (mut driver, _) = driver(2);
    let stream = stream(&mut driver, 2, PublicationMode::Exclusive);
    let mut reader = driver.subscribe(stream, Role::Required).unwrap();
    let mut writer = driver.publication(stream).unwrap();
    assert_eq!(accepted(writer.offer(b"one").unwrap()), 0);
    let generation = driver.reconfigure_stream(stream, larger()).unwrap();
    assert_eq!(generation, Generation::try_new(1).unwrap());
    // Exclusive: the cutover waits for the writer's next call.
    assert_eq!(driver.seal_state(stream).unwrap(), SealState::Sealed);
    assert!(matches!(
        driver.publication(stream),
        Err(DriverError::CutoverPending { .. })
    ));
    assert!(matches!(
        driver.reconfigure_stream(stream, larger()),
        Err(DriverError::CutoverPending { .. })
    ));
    assert_eq!(writer.offer(b"two").unwrap(), OfferOutcome::AdminAction);
    let _ = driver.do_work().unwrap();
    let table = driver.generations(stream).unwrap();
    assert_eq!(table.len(), 2);
    let end = table[0].seal.unwrap();
    assert_eq!((table[1].generation.get(), table[1].base), (1, end));
    // The writer moves, then publishes at the seal position.
    assert_eq!(writer.offer(b"two").unwrap(), OfferOutcome::AdminAction);
    assert_eq!(accepted(writer.offer(b"two").unwrap()), end);
    let ClaimOutcome::Claimed(mut claim) = writer.try_claim(5).unwrap() else {
        panic!("not claimed");
    };
    let at = claim.position();
    claim.payload().copy_from_slice(b"three");
    assert!(matches!(claim.commit(), CommitOutcome::Accepted { position, .. } if position == at));
    let (seen, summary) = read(&mut reader);
    assert_eq!(
        seen,
        vec![
            (0, b"one".to_vec()),
            (end, b"two".to_vec()),
            (at, b"three".to_vec())
        ]
    );
    assert_eq!(summary.closed, None);
    // The predecessor is freed once nothing references it.
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.generations(stream).unwrap().len(), 1);
}

#[test]
fn a_concurrent_cutover_opens_at_once_and_fences_an_idle_handle() {
    let (mut driver, clock) = driver(2);
    let stream = stream(&mut driver, 3, concurrent(2));
    let mut reader = driver.subscribe(stream, Role::Optional).unwrap();
    let mut active = driver.concurrent_publication(stream).unwrap();
    let mut idle = driver.concurrent_publication(stream).unwrap();
    let first = concurrent_accepted(active.offer(b"one").unwrap());
    let _ = driver.reconfigure_stream(stream, larger()).unwrap();
    // Positioned by the fence: the cutover is open already.
    let end = driver.generations(stream).unwrap()[0].seal.unwrap();
    assert_eq!(
        active.offer(b"two").unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(concurrent_accepted(active.offer(b"two").unwrap()), end);
    // The reader drains and moves before the deadline.
    let (seen, _) = read(&mut reader);
    assert_eq!(seen, vec![(first, b"one".to_vec()), (end, b"two".to_vec())]);
    // The idle handle never calls: fenced at the deadline, its successor
    // slot freed for a new handle.
    clock.set(DEADLINE);
    let _ = driver.do_work().unwrap();
    assert_eq!(idle.offer(b"late").unwrap(), ConcurrentOfferOutcome::Closed);
    assert!(matches!(
        idle.try_claim(4).unwrap(),
        ConcurrentClaimOutcome::Closed
    ));
    let mut fresh = driver.concurrent_publication(stream).unwrap();
    let third = concurrent_accepted(fresh.offer(b"three").unwrap());
    assert!(third > end);
    let (seen, _) = read(&mut reader);
    assert_eq!(seen, vec![(third, b"three".to_vec())]);
}

#[test]
fn claims_drain_by_commit_or_deadline_and_a_paused_handle_never_delays_the_cutover() {
    // SPEC.md §13 "Cutover with backlog", in process.
    let (mut driver, clock) = driver(2);
    let stream = stream(&mut driver, 4, concurrent(3));
    let mut lagging = driver.subscribe(stream, Role::Optional).unwrap();
    let mut on_time = driver.concurrent_publication(stream).unwrap();
    let mut late = driver.concurrent_publication(stream).unwrap();
    let mut paused = driver.concurrent_publication(stream).unwrap();
    for _ in 0..3 {
        let _ = concurrent_accepted(paused.offer(b"backlog").unwrap());
    }
    let ConcurrentClaimOutcome::Claimed(mut committed) = on_time.try_claim(4).unwrap() else {
        panic!("not claimed");
    };
    let ConcurrentClaimOutcome::Claimed(mut expired) = late.try_claim(4).unwrap() else {
        panic!("not claimed");
    };
    let expired_at = expired.position();
    let _ = driver.do_work().unwrap();
    let _ = driver.reconfigure_stream(stream, larger()).unwrap();
    let end = driver.generations(stream).unwrap()[0].seal.unwrap();
    committed.payload().copy_from_slice(b"kept");
    assert!(matches!(committed.commit(), CommitOutcome::Accepted { .. }));
    clock.set(CLAIM_DEADLINE);
    let _ = driver.do_work().unwrap();
    expired.payload().copy_from_slice(b"lost");
    assert!(
        matches!(expired.commit(), CommitOutcome::Aborted { position, .. } if position == expired_at)
    );
    // The responsive handles move; the lagging reader makes some progress
    // (renewing its lease); the paused handle is fenced at the deadline.
    for handle in [&mut on_time, &mut late] {
        assert_eq!(
            handle.offer(b"x").unwrap(),
            ConcurrentOfferOutcome::AdminAction
        );
    }
    let mut seen = Vec::new();
    let first = lagging
        .poll(
            |bytes, info| seen.push((info.position, bytes.to_vec())),
            MessageLimit::new(1),
        )
        .unwrap();
    assert_eq!(first.delivered, 1);
    let _ = driver.do_work().unwrap();
    clock.set(CLAIM_DEADLINE + DEADLINE - 30);
    let _ = driver.do_work().unwrap();
    assert_eq!(paused.offer(b"x").unwrap(), ConcurrentOfferOutcome::Closed);
    assert_eq!(concurrent_accepted(on_time.offer(b"new").unwrap()), end);
    // The lagging reader drains the backlog, the commit, the abort, then
    // continues on the successor.
    let mut aborted = None;
    loop {
        let summary = lagging
            .poll(
                |bytes, info| seen.push((info.position, bytes.to_vec())),
                MessageLimit::new(8),
            )
            .unwrap();
        if let Some(abort) = summary.aborted {
            aborted = Some(abort.position);
            continue;
        }
        if summary.delivered == 0 {
            break;
        }
    }
    assert_eq!(aborted, Some(expired_at));
    assert_eq!(seen.len(), 5);
    assert!(seen.iter().any(|(_, bytes)| bytes == b"kept"));
    assert_eq!(seen.last().unwrap(), &(end, b"new".to_vec()));
}

#[test]
fn a_paused_required_subscriber_is_fenced_and_a_draining_one_is_admitted() {
    let (mut driver, clock) = driver(2);
    let stream = stream(&mut driver, 5, concurrent(1));
    let mut paused = driver.subscribe(stream, Role::Required).unwrap();
    let mut draining = driver.subscribe(stream, Role::Required).unwrap();
    let mut writer = driver.concurrent_publication(stream).unwrap();
    for _ in 0..6 {
        let _ = concurrent_accepted(writer.offer(b"backlog").unwrap());
    }
    let _ = driver.reconfigure_stream(stream, larger()).unwrap();
    let end = driver.generations(stream).unwrap()[0].seal.unwrap();
    assert_eq!(
        writer.offer(b"x").unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    // The draining subscriber reads one message per cycle; each read
    // renews its lease, across several deadlines.
    for step in 1..=6 {
        let summary = draining.poll(|_, _| {}, MessageLimit::new(1)).unwrap();
        assert_eq!(summary.delivered, 1);
        clock.set(step * (DEADLINE - 1));
        let _ = driver.do_work().unwrap();
    }
    // The paused one made no progress for a deadline: fenced. Its
    // successor cell no longer bounds the writer.
    let (seen, summary) = read(&mut paused);
    assert_eq!(seen.len(), 6);
    assert_eq!(summary.closed, Some(end));
    assert_eq!(concurrent_accepted(writer.offer(b"new").unwrap()), end);
    let (seen, summary) = read(&mut draining);
    assert_eq!(seen, vec![(end, b"new".to_vec())]);
    assert_eq!(summary.closed, None);
}

#[test]
fn retained_generations_are_bounded_and_released() {
    let (mut driver, clock) = driver(1);
    let stream = stream(&mut driver, 6, concurrent(1));
    let mut holder = driver.subscribe(stream, Role::Optional).unwrap();
    let mut writer = driver.concurrent_publication(stream).unwrap();
    let _ = concurrent_accepted(writer.offer(b"one").unwrap());
    let _ = driver.reconfigure_stream(stream, larger()).unwrap();
    // The writer moves; the reader never polls and is fenced, holding the
    // predecessor.
    assert_eq!(
        writer.offer(b"x").unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    clock.set(DEADLINE);
    let _ = driver.do_work().unwrap();
    assert!(matches!(
        driver.reconfigure_stream(stream, larger()),
        Err(DriverError::Sys(SysError::ResourcesUnavailable))
    ));
    assert_eq!(counter(&driver, "retirement pool exhausted"), 1);
    // Released once the holder reads to the end and drops.
    let (_, summary) = read(&mut holder);
    assert!(summary.closed.is_some());
    drop(holder);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.generations(stream).unwrap().len(), 1);
    assert_eq!(
        driver.reconfigure_stream(stream, larger()).unwrap(),
        Generation::try_new(2).unwrap()
    );
}

#[test]
fn removal_during_a_pending_cutover_closes_every_handle() {
    let (mut driver, _) = driver(2);
    let stream = stream(&mut driver, 7, PublicationMode::Exclusive);
    let mut reader = driver.subscribe(stream, Role::Optional).unwrap();
    let mut writer = driver.publication(stream).unwrap();
    let _ = accepted(writer.offer(b"one").unwrap());
    let _ = driver.reconfigure_stream(stream, larger()).unwrap();
    driver.remove_stream(stream).unwrap();
    assert_eq!(writer.offer(b"x").unwrap(), OfferOutcome::Closed);
    let _ = driver.do_work().unwrap();
    let (seen, summary) = read(&mut reader);
    assert_eq!(seen.len(), 1);
    let end = driver.generations(stream).unwrap()[0].seal.unwrap();
    assert_eq!(summary.closed, Some(end));
    drop((reader, writer));
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.stream_state(stream).unwrap(), StreamState::Freed);
}

#[test]
fn handles_from_the_command_path_move_and_commands_wait_for_a_pending_cutover() {
    use karyos_client::{ClientConductor, Outcome};
    use karyos_protocol::cnc::{ErrorCode, StreamKey, SubscriberRole};

    fn served(driver: &mut EmbeddedDriver, client: &mut ClientConductor) -> Outcome {
        let _ = driver.do_work().unwrap();
        let mut done = Vec::new();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        assert_eq!(done.len(), 1);
        done.pop().unwrap().outcome
    }

    let (mut driver, _) = driver(2);
    let concurrent_stream = stream(&mut driver, 8, concurrent(2));
    let exclusive_stream = stream(&mut driver, 9, PublicationMode::Exclusive);
    let mut client = driver.connect().unwrap();
    let key = |stream_id| StreamKey {
        stream_id,
        session_id: 1,
    };
    let _ = client
        .add_subscription(key(8), SubscriberRole::Required)
        .unwrap();
    let Outcome::Subscription(mut reader) = served(&mut driver, &mut client) else {
        panic!("no subscription");
    };
    let _ = client.add_concurrent_publication(key(8), true).unwrap();
    let Outcome::ConcurrentPublication(mut writer) = served(&mut driver, &mut client) else {
        panic!("no publication");
    };
    let first = concurrent_accepted(writer.offer(b"one").unwrap());
    let _ = driver
        .reconfigure_stream(concurrent_stream, larger())
        .unwrap();
    let end = driver.generations(concurrent_stream).unwrap()[0]
        .seal
        .unwrap();
    assert_eq!(
        writer.offer(b"two").unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(concurrent_accepted(writer.offer(b"two").unwrap()), end);
    let (seen, _) = read(&mut reader);
    assert_eq!(seen, vec![(first, b"one".to_vec()), (end, b"two".to_vec())]);
    // An exclusive stream's cutover stays pending until its writer calls;
    // meanwhile commands for it are refused, with no effect.
    let _ = client.add_publication(key(9), true).unwrap();
    let Outcome::Publication(mut exclusive) = served(&mut driver, &mut client) else {
        panic!("no publication");
    };
    let _ = driver
        .reconfigure_stream(exclusive_stream, larger())
        .unwrap();
    let _ = client
        .add_subscription(key(9), SubscriberRole::Optional)
        .unwrap();
    assert!(matches!(
        served(&mut driver, &mut client),
        Outcome::Refused {
            code: ErrorCode::ResourcesUnavailable,
            ..
        }
    ));
    assert_eq!(exclusive.offer(b"x").unwrap(), OfferOutcome::AdminAction);
    let _ = driver.do_work().unwrap();
    assert_eq!(exclusive.offer(b"x").unwrap(), OfferOutcome::AdminAction);
    let end = driver.generations(exclusive_stream).unwrap()[0]
        .seal
        .unwrap();
    assert_eq!(accepted(exclusive.offer(b"x").unwrap()), end);
    let _ = client
        .add_subscription(key(9), SubscriberRole::Optional)
        .unwrap();
    assert!(matches!(
        served(&mut driver, &mut client),
        Outcome::Subscription(_)
    ));
}
