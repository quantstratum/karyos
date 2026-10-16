// SPDX-License-Identifier: Apache-2.0

//! Sealing through stream removal in the embedded driver
//! (`quantstratum-docs: karyos/design/publication-seal.md`, e2), with a manual clock.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::{
    Aborted, ClientConcurrentClaim, ClientSubscription, CommitOutcome, ConcurrentClaimOutcome,
    ConcurrentOfferOutcome, MessageLimit, OfferOutcome, PollSummary,
};
use karyos_driver::{
    DriverConfig, DriverError, EmbeddedDriver, MonotonicClock, SealState, StreamConfig,
    StreamHandle, StreamState,
};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

const DEADLINE: u64 = 100;

#[derive(Debug, Clone, Default)]
struct ManualClock {
    now: Arc<AtomicU64>,
}

impl MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

fn driver() -> (EmbeddedDriver, ManualClock) {
    let clock = ManualClock::default();
    let driver =
        EmbeddedDriver::with_clock(DriverConfig::default(), Box::new(clock.clone())).unwrap();
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
                claim_deadline: DEADLINE,
                publication,
                schedule_capacity: 0,
            },
            allow_unconnected: false,
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

/// Polls until a poll delivers nothing, returning the messages and the
/// last summary.
fn read(subscription: &mut ClientSubscription) -> (Vec<Vec<u8>>, PollSummary) {
    let mut seen = Vec::new();
    loop {
        let summary = subscription
            .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
            .unwrap();
        if summary.delivered == 0 && summary.aborted.is_none() {
            return (seen, summary);
        }
    }
}

fn claimed(outcome: ConcurrentClaimOutcome<'_>) -> ClientConcurrentClaim<'_> {
    match outcome {
        ConcurrentClaimOutcome::Claimed(claim) => claim,
        other => panic!("not claimed: {other:?}"),
    }
}

#[test]
fn removal_closes_an_exclusive_publication_and_readers_reach_the_end() {
    let (mut driver, _) = driver();
    let stream = stream(&mut driver, 2, PublicationMode::Exclusive);
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    for payload in [&b"one"[..], b"two"] {
        assert!(matches!(
            publication.offer(payload).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    assert_eq!(driver.seal_state(stream).unwrap(), SealState::Active);
    driver.remove_stream(stream).unwrap();
    assert_eq!(driver.seal_state(stream).unwrap(), SealState::Sealed);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.seal_state(stream).unwrap(), SealState::Sealed);
    assert_eq!(publication.offer(b"late").unwrap(), OfferOutcome::Closed);
    let _ = driver.do_work().unwrap();
    let SealState::Positioned { position } = driver.seal_state(stream).unwrap() else {
        panic!("not positioned");
    };
    let (seen, summary) = read(&mut subscription);
    assert_eq!(seen, vec![b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(summary.closed, Some(position));
    assert_eq!(
        driver.seal_state(stream).unwrap(),
        SealState::Retired { position }
    );
    // Freed once every handle is gone; the seal state goes with it.
    drop(publication);
    drop(subscription);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.stream_state(stream).unwrap(), StreamState::Freed);
    assert!(matches!(
        driver.seal_state(stream),
        Err(DriverError::UnknownStream { .. })
    ));
}

#[test]
fn a_backlog_of_claims_drains_by_commit_or_deadline_before_the_end() {
    let (mut driver, clock) = driver();
    let stream = stream(&mut driver, 3, concurrent(3));
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut on_time = driver.concurrent_publication(stream).unwrap();
    let mut late = driver.concurrent_publication(stream).unwrap();
    let mut idle = driver.concurrent_publication(stream).unwrap();
    let mut committed = claimed(on_time.try_claim(4).unwrap());
    let mut expired = claimed(late.try_claim(4).unwrap());
    let expired_at = expired.position();
    let _ = driver.do_work().unwrap();
    driver.remove_stream(stream).unwrap();
    committed.payload().copy_from_slice(b"kept");
    assert!(matches!(committed.commit(), CommitOutcome::Accepted { .. }));
    clock.now.store(DEADLINE, Ordering::Relaxed);
    let _ = driver.do_work().unwrap();
    expired.payload().copy_from_slice(b"lost");
    assert!(matches!(expired.commit(), CommitOutcome::Aborted { .. }));
    // The fence positioned the seal at removal: the idle holder does not
    // delay it (quantstratum-docs: karyos/design/mapping-generations.md).
    let SealState::Positioned { position } = driver.seal_state(stream).unwrap() else {
        panic!("not positioned");
    };
    assert_eq!(position, expired_at + 64);
    for handle in [&mut on_time, &mut late] {
        assert_eq!(handle.offer(b"x").unwrap(), ConcurrentOfferOutcome::Closed);
    }
    assert!(matches!(
        idle.try_claim(4).unwrap(),
        ConcurrentClaimOutcome::Closed
    ));
    let _ = driver.do_work().unwrap();
    let first = subscription
        .poll(|bytes, _| assert_eq!(bytes, b"kept"), MessageLimit::new(8))
        .unwrap();
    assert_eq!(first.delivered, 1);
    assert_eq!(
        first.aborted,
        Some(Aborted {
            position: expired_at,
            extent: 64,
        })
    );
    let (seen, end) = read(&mut subscription);
    assert!(seen.is_empty());
    assert_eq!(end.closed, Some(position));
}

#[test]
fn a_stream_without_subscribers_still_positions_its_seal() {
    let (mut driver, _) = driver();
    let stream = stream(&mut driver, 4, concurrent(2));
    let mut handle = driver.concurrent_publication(stream).unwrap();
    driver.remove_stream(stream).unwrap();
    // Not connected, but sealed: Closed, and the slot is released.
    assert_eq!(handle.offer(b"x").unwrap(), ConcurrentOfferOutcome::Closed);
    let _ = driver.do_work().unwrap();
    assert_eq!(
        driver.seal_state(stream).unwrap(),
        SealState::Retired { position: 0 }
    );
    drop(handle);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.stream_state(stream).unwrap(), StreamState::Freed);
}

#[test]
fn seal_state_of_a_foreign_handle_is_unknown() {
    let (mut driver, _) = driver();
    let (mut other, _) = self::driver();
    let foreign = stream(&mut other, 5, PublicationMode::Exclusive);
    let _ = stream(&mut driver, 5, PublicationMode::Exclusive);
    assert!(matches!(
        driver.seal_state(foreign),
        Err(DriverError::UnknownStream { .. })
    ));
}

#[test]
fn a_held_hand_over_entry_delays_the_position_until_its_client_closes() {
    let (mut driver, _) = driver();
    let stream = stream(&mut driver, 6, PublicationMode::Exclusive);
    let mut client = driver.connect().unwrap();
    let _ = client
        .add_publication(
            karyos_protocol::cnc::StreamKey {
                stream_id: 6,
                session_id: 1,
            },
            false,
        )
        .unwrap();
    // Served, never taken: the entry holds the publication.
    let _ = driver.do_work().unwrap();
    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.seal_state(stream).unwrap(), SealState::Sealed);
    // Closing the client drops the entry, which releases; with no lease
    // left the stream is freed in the same duty cycle.
    client.close();
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.stream_state(stream).unwrap(), StreamState::Freed);
}
