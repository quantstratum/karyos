// SPDX-License-Identifier: Apache-2.0

//! Concurrent publication through the client wrapper and the direct
//! driver API (`quantstratum-docs: karyos/design/client-concurrent-publication.md`, d1).

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::{
    Aborted, ClientConcurrentClaim, ClientError, ClientSubscription, CommitOutcome,
    ConcurrentClaimOutcome, ConcurrentOfferOutcome, MessageLimit,
};
use karyos_driver::{
    DriverConfig, DriverError, EmbeddedDriver, MonotonicClock, StreamConfig, StreamHandle,
    StreamState,
};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

const PUBLISHERS: u8 = 3;
const DEADLINE: u64 = 100;

#[derive(Debug, Clone, Default)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::Relaxed);
    }
}

impl MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

fn config(stream_id: i32, publication: PublicationMode, allow_unconnected: bool) -> StreamConfig {
    StreamConfig {
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
        },
        allow_unconnected,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
    }
}

fn concurrent() -> PublicationMode {
    PublicationMode::Concurrent {
        publishers: PUBLISHERS,
        allow_non_lse: true,
    }
}

fn driver() -> (EmbeddedDriver, ManualClock) {
    let clock = ManualClock::default();
    let driver =
        EmbeddedDriver::with_clock(DriverConfig::default(), Box::new(clock.clone())).unwrap();
    (driver, clock)
}

fn stream(driver: &mut EmbeddedDriver, allow_unconnected: bool) -> StreamHandle {
    driver
        .add_stream(config(2, concurrent(), allow_unconnected))
        .unwrap()
}

fn claimed(outcome: ConcurrentClaimOutcome<'_>) -> ClientConcurrentClaim<'_> {
    match outcome {
        ConcurrentClaimOutcome::Claimed(claim) => claim,
        other => panic!("not claimed: {other:?}"),
    }
}

fn read_all(subscription: &mut ClientSubscription) -> Vec<Vec<u8>> {
    let mut seen = Vec::new();
    let _ = subscription
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(64))
        .unwrap();
    seen
}

/// The `claims aborted at deadline` counter.
fn deadline_aborts(driver: &EmbeddedDriver) -> u64 {
    use karyos_sys::counters::CellRead;
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == b"claims aborted at deadline" => Some(value),
            _ => None,
        })
        .unwrap()
}

#[test]
fn offers_and_claims_are_committed_and_delivered() {
    let (mut driver, _clock) = driver();
    let stream = stream(&mut driver, false);
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut first = driver.concurrent_publication(stream).unwrap();
    let mut second = driver.concurrent_publication(stream).unwrap();
    assert!(matches!(
        first.offer(b"one").unwrap(),
        ConcurrentOfferOutcome::Accepted {
            lane: Lane::ZERO,
            position: 0
        }
    ));
    let mut claim = claimed(second.try_claim(3).unwrap());
    claim.payload().copy_from_slice(b"two");
    let position = claim.position();
    assert_eq!(
        claim.commit(),
        CommitOutcome::Accepted {
            lane: Lane::ZERO,
            position,
        }
    );
    assert_eq!(
        read_all(&mut subscription),
        vec![b"one".to_vec(), b"two".to_vec()]
    );
}

#[test]
fn a_claim_held_past_its_deadline_is_aborted_and_readers_move_on() {
    let (mut driver, clock) = driver();
    let stream = stream(&mut driver, false);
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut stuck = driver.concurrent_publication(stream).unwrap();
    let mut other = driver.concurrent_publication(stream).unwrap();
    let mut claim = claimed(stuck.try_claim(8).unwrap());
    let position = claim.position();
    assert!(matches!(
        other.offer(b"after").unwrap(),
        ConcurrentOfferOutcome::Accepted { .. }
    ));
    // The reader waits at the uncommitted block.
    assert!(read_all(&mut subscription).is_empty());
    let _ = driver.do_work().unwrap();
    clock.set(DEADLINE - 1);
    let _ = driver.do_work().unwrap();
    assert_eq!(deadline_aborts(&driver), 0, "not before the deadline");
    clock.set(DEADLINE);
    let _ = driver.do_work().unwrap();
    assert_eq!(deadline_aborts(&driver), 1);
    claim.payload()[0] = 1;
    assert_eq!(
        claim.commit(),
        CommitOutcome::Aborted {
            lane: Lane::ZERO,
            position,
        }
    );
    let summary = subscription
        .poll(
            |_, _| panic!("the aborted block is skipped"),
            MessageLimit::new(1),
        )
        .unwrap();
    assert_eq!(
        summary.aborted,
        Some(Aborted {
            position,
            extent: 64
        })
    );
    assert_eq!(read_all(&mut subscription), vec![b"after".to_vec()]);
}

#[test]
fn not_connected_still_resolves_a_forgotten_claim() {
    for offer in [false, true] {
        let (mut driver, clock) = driver();
        let stream = stream(&mut driver, false);
        let subscription = driver.subscribe(stream, Role::Optional).unwrap();
        let mut publication = driver.concurrent_publication(stream).unwrap();
        core::mem::forget(claimed(publication.try_claim(8).unwrap()));
        // The last subscriber leaves.
        drop(subscription);
        if offer {
            assert_eq!(
                publication.offer(b"x").unwrap(),
                ConcurrentOfferOutcome::NotConnected
            );
        } else {
            assert!(matches!(
                publication.try_claim(8).unwrap(),
                ConcurrentClaimOutcome::NotConnected
            ));
        }
        // Resolved before the early return: no deadline abort is left to
        // win, and nothing new was reserved.
        let _ = driver.do_work().unwrap();
        clock.set(u64::MAX / 2);
        let _ = driver.do_work().unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(deadline_aborts(&driver), 0);
        let probe = driver.subscribe(stream, Role::Required).unwrap();
        assert_eq!(
            probe.position(),
            64,
            "the head moved past the forgotten claim only"
        );
    }
}

#[test]
fn a_claim_admitted_while_connected_commits_after_a_detach() {
    let (mut driver, _clock) = driver();
    let stream = stream(&mut driver, false);
    let subscription = driver.subscribe(stream, Role::Optional).unwrap();
    let mut publication = driver.concurrent_publication(stream).unwrap();
    let mut claim = claimed(publication.try_claim(3).unwrap());
    drop(subscription);
    claim.payload().copy_from_slice(b"abc");
    assert!(matches!(claim.commit(), CommitOutcome::Accepted { .. }));
    assert_eq!(
        publication.offer(b"x").unwrap(),
        ConcurrentOfferOutcome::NotConnected
    );
}

#[test]
fn a_subscriber_of_either_role_connects_and_unconnected_use_can_be_allowed() {
    for role in [Role::Required, Role::Optional] {
        let (mut driver, _clock) = driver();
        let stream = stream(&mut driver, false);
        let mut publication = driver.concurrent_publication(stream).unwrap();
        assert_eq!(
            publication.offer(b"x").unwrap(),
            ConcurrentOfferOutcome::NotConnected
        );
        let _subscription = driver.subscribe(stream, role).unwrap();
        assert!(matches!(
            publication.offer(b"x").unwrap(),
            ConcurrentOfferOutcome::Accepted { .. }
        ));
    }
    let (mut driver, _clock) = driver();
    let stream = stream(&mut driver, true);
    let mut publication = driver.concurrent_publication(stream).unwrap();
    assert!(matches!(
        publication.offer(b"x").unwrap(),
        ConcurrentOfferOutcome::Accepted { .. }
    ));
    let claim = claimed(publication.try_claim(8).unwrap());
    assert!(matches!(claim.commit(), CommitOutcome::Accepted { .. }));
}

#[test]
fn sizes_are_checked_and_claims_stay_within_one_fragment() {
    let (mut driver, _clock) = driver();
    let stream = stream(&mut driver, true);
    let mut publication = driver.concurrent_publication(stream).unwrap();
    assert!(matches!(
        publication.offer(b""),
        Err(ClientError::EmptyMessage)
    ));
    assert!(matches!(
        publication.try_claim(0),
        Err(ClientError::EmptyMessage)
    ));
    let max = publication.max_message_length();
    assert!(matches!(
        publication.offer(&vec![0; max as usize + 1]),
        Err(ClientError::MessageTooLarge { .. })
    ));
    // Two fragments: an offer, never a claim.
    let two_fragments = vec![7; DEFAULT_MTU as usize];
    assert!(matches!(
        publication.offer(&two_fragments).unwrap(),
        ConcurrentOfferOutcome::Accepted { .. }
    ));
    assert!(matches!(
        publication.try_claim(DEFAULT_MTU),
        Err(ClientError::MessageTooLarge { .. })
    ));
}

#[test]
fn p_handles_are_issued_and_the_next_is_refused_until_one_drops() {
    let (mut driver, _clock) = driver();
    let stream = stream(&mut driver, true);
    let mut handles: Vec<_> = (0..PUBLISHERS)
        .map(|_| driver.concurrent_publication(stream).unwrap())
        .collect();
    let leases = driver.live_leases(stream).unwrap();
    assert!(matches!(
        driver.concurrent_publication(stream),
        Err(DriverError::PublicationTaken)
    ));
    assert_eq!(driver.live_leases(stream).unwrap(), leases, "nothing held");
    drop(handles.pop());
    let mut reissued = driver.concurrent_publication(stream).unwrap();
    assert!(matches!(
        reissued.offer(b"x").unwrap(),
        ConcurrentOfferOutcome::Accepted { .. }
    ));
}

#[test]
fn a_kind_that_does_not_match_the_mode_is_refused() {
    let (mut driver, _clock) = driver();
    let exclusive = driver
        .add_stream(config(3, PublicationMode::Exclusive, true))
        .unwrap();
    let concurrent = stream(&mut driver, true);
    assert!(matches!(
        driver.concurrent_publication(exclusive),
        Err(DriverError::InvalidPublicationMode)
    ));
    assert!(matches!(
        driver.publication(concurrent),
        Err(DriverError::InvalidPublicationMode)
    ));
    assert_eq!(driver.live_leases(exclusive).unwrap(), 0);
    assert_eq!(driver.live_leases(concurrent).unwrap(), 0);
    // Neither refusal consumed the stream's publications.
    let _ = driver.publication(exclusive).unwrap();
    let _ = driver.concurrent_publication(concurrent).unwrap();
}

#[test]
fn a_crossing_pads_its_remainder_and_publication_continues_in_the_next_term() {
    let (mut driver, _clock) = driver();
    let stream = stream(&mut driver, false);
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.concurrent_publication(stream).unwrap();
    let message = vec![5; 1000];
    let (mut accepted, mut admin, mut last) = (0u32, 0u32, 0u64);
    for _ in 0..1000 {
        match publication.offer(&message).unwrap() {
            ConcurrentOfferOutcome::Accepted { position, .. } => {
                accepted += 1;
                last = position;
            }
            ConcurrentOfferOutcome::AdminAction => admin += 1,
            ConcurrentOfferOutcome::BackPressured => {}
            other => panic!("unexpected {other:?}"),
        }
        let _ = driver.do_work().unwrap();
        for bytes in read_all(&mut subscription) {
            assert_eq!(bytes, message);
        }
        if last > u64::from(MIN_TERM_LENGTH) {
            break;
        }
    }
    assert!(admin >= 1, "the crossing returned AdminAction");
    assert!(
        last > u64::from(MIN_TERM_LENGTH),
        "publication continued in the next term"
    );
    // 1056 reserved bytes each: 62 fill the first term, one more follows.
    assert!(accepted >= 63);
}

#[test]
fn handles_publish_from_their_own_threads() {
    const MESSAGES: u32 = 2000;
    let (mut driver, _clock) = driver();
    let stream = stream(&mut driver, false);
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let writers: Vec<_> = (0..PUBLISHERS)
        .map(|writer| {
            let mut publication = driver.concurrent_publication(stream).unwrap();
            std::thread::spawn(move || {
                let mut sequence = 0u32;
                while sequence < MESSAGES {
                    let mut payload = [0u8; 8];
                    payload[..4].copy_from_slice(&u32::from(writer).to_le_bytes());
                    payload[4..].copy_from_slice(&sequence.to_le_bytes());
                    match publication.offer(&payload).unwrap() {
                        ConcurrentOfferOutcome::Accepted { .. } => sequence += 1,
                        ConcurrentOfferOutcome::BackPressured
                        | ConcurrentOfferOutcome::AdminAction => std::thread::yield_now(),
                        other => panic!("unexpected {other:?}"),
                    }
                }
            })
        })
        .collect();
    let mut next = [0u32; PUBLISHERS as usize];
    let total = MESSAGES * u32::from(PUBLISHERS);
    let mut received = 0u32;
    while received < total {
        let _ = driver.do_work().unwrap();
        for bytes in read_all(&mut subscription) {
            let writer = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
            let sequence = u32::from_le_bytes(bytes[4..].try_into().unwrap());
            assert_eq!(
                sequence, next[writer],
                "each writer's messages once, in order"
            );
            next[writer] += 1;
            received += 1;
        }
    }
    for writer in writers {
        writer.join().unwrap();
    }
    assert_eq!(next, [MESSAGES; PUBLISHERS as usize]);
}

#[test]
fn a_retiring_stream_issues_nothing_and_is_freed_after_its_last_handle() {
    let (mut driver, _clock) = driver();
    let stream = stream(&mut driver, true);
    let mut publication = driver.concurrent_publication(stream).unwrap();
    driver.remove_stream(stream).unwrap();
    assert!(matches!(
        driver.concurrent_publication(stream),
        Err(DriverError::StreamRetiring { .. })
    ));
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.stream_state(stream).unwrap(), StreamState::Retiring);
    // A live handle is not revoked; the seal closes it on its next
    // attempt (`quantstratum-docs: karyos/design/publication-seal.md`).
    assert_eq!(
        publication.offer(b"x").unwrap(),
        ConcurrentOfferOutcome::Closed
    );
    drop(publication);
    let _ = driver.do_work().unwrap();
    assert!(matches!(
        driver.stream_state(stream),
        Ok(StreamState::Freed) | Err(DriverError::UnknownStream { .. })
    ));
}
