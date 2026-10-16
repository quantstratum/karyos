// SPDX-License-Identifier: Apache-2.0

//! Timed transmission through the embedded driver (`quantstratum-docs:
//! karyos/design/timed-tx.md`; P2.11 T1, step 3b): a timed lane's handle
//! takes `offer_at` only, checked before anything is reserved, and every
//! accepted message leaves its entry in the lane's schedule ring.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use karyos_client::schedule::{ClockDomain, ScheduleOptions, now};
use karyos_client::{ClientError, OfferOutcome};
use karyos_driver::{DriverError, EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

const SECOND: u64 = 1_000_000_000;

fn stream(driver: &mut EmbeddedDriver, schedule_capacity: u32) -> StreamHandle {
    driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        })
        .unwrap()
}

fn invalid(result: Result<OfferOutcome, ClientError>) -> bool {
    matches!(result, Err(ClientError::InvalidSchedule { .. }))
}

#[test]
fn a_lane_that_is_not_timed_refuses_offer_at() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 0);
    assert!(matches!(
        driver.schedule_stream(handle, ScheduleOptions::default()),
        Err(DriverError::NotTimed { .. })
    ));
    let mut publication = driver.publication(handle).unwrap();
    assert!(publication.schedule().is_none());
    assert!(invalid(publication.offer_at(b"a", 0)));
}

/// A timed lane takes `offer_at` only, and its times never go backwards
/// (the entries are checked against the ring in the driver's unit tests).
#[test]
fn a_timed_lane_takes_timed_offers_in_order() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 4);
    driver
        .schedule_stream(
            handle,
            ScheduleOptions {
                max_horizon: SECOND,
                ..ScheduleOptions::default()
            },
        )
        .unwrap();
    let mut publication = driver.publication(handle).unwrap();
    assert_eq!(
        publication.schedule().unwrap().options().max_horizon,
        SECOND
    );
    assert!(invalid(publication.offer(b"a")));
    assert!(matches!(
        publication.try_claim(8),
        Err(ClientError::InvalidSchedule { .. })
    ));
    let now = now(ClockDomain::Monotonic).unwrap();
    let mut positions = Vec::new();
    // A time already past, then later ones.
    for time in [1, now, now + 10] {
        let OfferOutcome::Accepted { position, .. } = publication.offer_at(b"m", time).unwrap()
        else {
            panic!("not accepted");
        };
        positions.push((position, time));
    }
    assert_eq!(publication.schedule().unwrap().last_time(), Some(now + 10));
    assert!(invalid(publication.offer_at(b"m", now)), "below the last");
    assert!(matches!(
        publication.offer_at(b"m", now + 10 * SECOND),
        Err(ClientError::ScheduleTooFar { .. })
    ));
    let _ = positions;
}

/// The schedule ring's room is checked before reservation: a full ring is
/// back pressure, nothing reserved, and the next offer goes once a slot is
/// released.
#[test]
fn a_full_schedule_backpressures_the_offer() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2);
    let mut publication = driver.publication(handle).unwrap();
    for time in [1, 2] {
        assert!(matches!(
            publication.offer_at(b"m", time).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    assert_eq!(
        publication.offer_at(b"m", 3).unwrap(),
        OfferOutcome::BackPressured
    );
    // Still refused while no sender frees a slot: nothing was reserved.
    assert_eq!(
        publication.offer_at(b"m", 3).unwrap(),
        OfferOutcome::BackPressured
    );
}

#[test]
fn the_schedule_is_set_before_any_handle() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 4);
    let _publication = driver.publication(handle).unwrap();
    assert_eq!(
        driver.schedule_stream(handle, ScheduleOptions::default()),
        Err(DriverError::InvalidConfig)
    );
    if !cfg!(target_os = "linux") {
        let other = {
            let mut driver = EmbeddedDriver::new().unwrap();
            let handle = stream(&mut driver, 4);
            driver.schedule_stream(
                handle,
                ScheduleOptions {
                    domain: ClockDomain::Tai,
                    ..ScheduleOptions::default()
                },
            )
        };
        assert!(matches!(
            other,
            Err(DriverError::Client(ClientError::InvalidSchedule { .. }))
        ));
    }
}
