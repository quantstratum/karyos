// SPDX-License-Identifier: Apache-2.0

//! The commit deadline of claims in the embedded driver's duty cycle
//! (`quantstratum-docs: karyos/design/client-claims.md`, part 2), with a manual clock.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::{Aborted, ClaimOutcome, ClientClaim, CommitOutcome, MessageLimit};
use karyos_driver::{DriverConfig, EmbeddedDriver, MonotonicClock, StreamConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

/// A clock the test sets; it counts its reads.
#[derive(Debug, Clone, Default)]
struct ManualClock {
    now: Arc<AtomicU64>,
    reads: Arc<AtomicU64>,
}

impl ManualClock {
    fn set(&self, now: u64) {
        self.now.store(now, Ordering::Relaxed);
    }

    fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }
}

impl MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.now.load(Ordering::Relaxed)
    }
}

fn config(stream_id: i32, claim_deadline: u64) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline,
        },
        allow_unconnected: false,
    }
}

fn driver() -> (EmbeddedDriver, ManualClock) {
    let clock = ManualClock::default();
    let driver =
        EmbeddedDriver::with_clock(DriverConfig::default(), Box::new(clock.clone())).unwrap();
    (driver, clock)
}

fn claimed(outcome: ClaimOutcome<'_>) -> ClientClaim<'_> {
    match outcome {
        ClaimOutcome::Claimed(claim) => claim,
        other => panic!("not claimed: {other:?}"),
    }
}

#[test]
fn a_held_claim_is_aborted_at_exactly_its_deadline() {
    let (mut driver, clock) = driver();
    let stream = driver.add_stream(config(2, 100)).unwrap();
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    // No claim: the clock is never read.
    clock.set(10);
    let _ = driver.do_work().unwrap();
    assert_eq!(clock.reads(), 0);
    let mut claim = claimed(publication.try_claim(8).unwrap());
    let position = claim.position();
    // First observation at 10: the deadline counts from there.
    let _ = driver.do_work().unwrap();
    assert_eq!(clock.reads(), 1);
    clock.set(109);
    let work = driver.do_work().unwrap();
    assert_eq!(work, 0, "waiting adds no work");
    claim.payload().fill(1);
    clock.set(110);
    assert_eq!(driver.do_work().unwrap(), 1, "the won abort counts as work");
    // The writer may keep writing; its commit loses.
    claim.payload().fill(2);
    assert_eq!(
        claim.commit(),
        CommitOutcome::Aborted {
            lane: Lane::ZERO,
            position,
        }
    );
    let summary = subscription
        .poll(|_, _| panic!("nothing to deliver"), MessageLimit::new(4))
        .unwrap();
    assert_eq!(
        summary.aborted,
        Some(Aborted {
            position,
            extent: 64
        })
    );
}

#[test]
fn a_claim_committed_before_its_deadline_is_delivered() {
    let (mut driver, clock) = driver();
    let stream = driver.add_stream(config(2, 100)).unwrap();
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let mut claim = claimed(publication.try_claim(4).unwrap());
    let _ = driver.do_work().unwrap();
    clock.set(99);
    let _ = driver.do_work().unwrap();
    claim.payload().copy_from_slice(b"late");
    assert!(matches!(claim.commit(), CommitOutcome::Accepted { .. }));
    clock.set(1000);
    let _ = driver.do_work().unwrap();
    let mut seen = Vec::new();
    let _ = subscription
        .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(4))
        .unwrap();
    assert_eq!(seen, vec![b"late".to_vec()]);
}

#[test]
fn streams_keep_their_own_deadlines() {
    let (mut driver, clock) = driver();
    let short = driver.add_stream(config(2, 10)).unwrap();
    let long = driver.add_stream(config(3, 1000)).unwrap();
    let _short_subscription = driver.subscribe(short, Role::Optional).unwrap();
    let _long_subscription = driver.subscribe(long, Role::Optional).unwrap();
    let mut short_publication = driver.publication(short).unwrap();
    let mut long_publication = driver.publication(long).unwrap();
    let short_claim = claimed(short_publication.try_claim(8).unwrap());
    let long_claim = claimed(long_publication.try_claim(8).unwrap());
    let _ = driver.do_work().unwrap();
    clock.set(10);
    assert_eq!(driver.do_work().unwrap(), 1);
    assert!(matches!(
        short_claim.commit(),
        CommitOutcome::Aborted { .. }
    ));
    assert!(matches!(
        long_claim.commit(),
        CommitOutcome::Accepted { .. }
    ));
}

#[test]
fn a_clock_step_back_delays_and_never_advances_the_abort() {
    let (mut driver, clock) = driver();
    let stream = driver.add_stream(config(2, 100)).unwrap();
    let _subscription = driver.subscribe(stream, Role::Optional).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let claim = claimed(publication.try_claim(8).unwrap());
    clock.set(500);
    let _ = driver.do_work().unwrap();
    clock.set(200);
    let _ = driver.do_work().unwrap();
    clock.set(299);
    assert_eq!(driver.do_work().unwrap(), 0);
    clock.set(300);
    assert_eq!(driver.do_work().unwrap(), 1);
    assert!(matches!(claim.commit(), CommitOutcome::Aborted { .. }));
}

#[test]
fn a_retiring_stream_still_runs_its_deadline() {
    let (mut driver, clock) = driver();
    let stream = driver.add_stream(config(2, 100)).unwrap();
    let _subscription = driver.subscribe(stream, Role::Optional).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    let claim = claimed(publication.try_claim(8).unwrap());
    let _ = driver.do_work().unwrap();
    driver.remove_stream(stream).unwrap();
    clock.set(100);
    assert_eq!(driver.do_work().unwrap(), 1);
    assert!(matches!(claim.commit(), CommitOutcome::Aborted { .. }));
}
