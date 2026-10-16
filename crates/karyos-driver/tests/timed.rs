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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::schedule::{ClockDomain, ScheduleClock, ScheduleOptions, now};
use karyos_client::{ClientError, OfferOutcome};
use karyos_driver::{DriverError, EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

const SECOND: u64 = 1_000_000_000;

fn stream(driver: &mut EmbeddedDriver, schedule_capacity: u32) -> StreamHandle {
    try_stream(driver, schedule_capacity).unwrap()
}

fn try_stream(
    driver: &mut EmbeddedDriver,
    schedule_capacity: u32,
) -> Result<StreamHandle, DriverError> {
    driver.add_stream(StreamConfig {
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
}

/// The driver refuses a schedule capacity that is not a power of two up
/// to the bound with the schedule's own error, not a publication mode one.
#[test]
fn a_schedule_capacity_is_bounded() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let max = karyos_sys::schedule_ring::MAX_CAPACITY;
    for capacity in [3, max * 2] {
        assert_eq!(
            try_stream(&mut driver, capacity).err(),
            Some(DriverError::Sys(karyos_sys::error::SysError::Schedule(
                karyos_sys::schedule_ring::ScheduleError::Capacity { capacity }
            ))),
        );
    }
    assert!(try_stream(&mut driver, max).is_ok());
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

/// A timed lane takes no cutover: its ring belongs to one buffer, and the
/// handle's publisher would not follow a successor (#234 P1). Nothing
/// changes on the refusal: the lane keeps its mapping and its offers.
#[test]
fn a_timed_lane_refuses_a_cutover() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 4);
    let mut publication = driver.publication(handle).unwrap();
    assert!(matches!(
        publication.offer_at(b"m", 1).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert!(matches!(
        driver.reconfigure_stream(
            handle,
            karyos_driver::Reconfiguration {
                term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                spare_slots: 3,
            },
        ),
        Err(DriverError::TimedCutover { .. })
    ));
    assert_eq!(driver.generations(handle).unwrap().len(), 1);
    assert!(matches!(
        publication.offer_at(b"m", 2).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    // A lane that is not timed still takes one.
    let mut other = EmbeddedDriver::new().unwrap();
    let plain = stream(&mut other, 0);
    assert!(
        other
            .reconfigure_stream(
                plain,
                karyos_driver::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                    spare_slots: 3,
                },
            )
            .is_ok()
    );
}

/// A zero horizon is refused: every offer would be checked against the
/// clock alone (#234 P3).
#[test]
fn a_zero_horizon_is_refused() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 4);
    assert!(matches!(
        driver.schedule_stream(
            handle,
            ScheduleOptions {
                max_horizon: 0,
                ..ScheduleOptions::default()
            },
        ),
        Err(DriverError::Client(ClientError::InvalidSchedule { .. }))
    ));
}

/// The settings are fixed once a handle of the incarnation was issued,
/// also after it is dropped: its entries stay in the ring (#234 P3).
#[test]
fn the_schedule_stays_fixed_after_a_handle_is_dropped() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 4);
    let mut publication = driver.publication(handle).unwrap();
    assert!(matches!(
        publication.offer_at(b"m", 1).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    drop(publication);
    let _ = driver.do_work();
    assert_eq!(
        driver.schedule_stream(handle, ScheduleOptions::default()),
        Err(DriverError::InvalidConfig)
    );
}

/// A sealed handle reports its seal before a refused time, as every other
/// refusal does and as sys does (#234 P3).
#[test]
fn a_sealed_handle_reports_the_seal_before_a_refused_time() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 4);
    let mut publication = driver.publication(handle).unwrap();
    assert!(matches!(
        publication.offer_at(b"m", 10).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert!(invalid(publication.offer_at(b"m", 5)));
    driver.remove_stream(handle).unwrap();
    assert_eq!(publication.offer_at(b"m", 5).unwrap(), OfferOutcome::Closed);
    assert_eq!(publication.offer_at(b"m", 5).unwrap(), OfferOutcome::Closed);
}

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

/// A timed lane's offers are counted by outcome, in cells labelled with
/// its clock domain and checked against the injected clock (timed-tx.md
/// section 6; ACS 15462).
#[test]
fn timed_offers_are_counted_against_the_injected_clock() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2);
    let virtual_now = Arc::new(AtomicU64::new(1_000));
    let clock = {
        let virtual_now = Arc::clone(&virtual_now);
        ScheduleClock::new(move || virtual_now.load(Ordering::Relaxed))
    };
    driver
        .schedule_stream_with_clock(
            handle,
            ScheduleOptions {
                max_horizon: 100,
                ..ScheduleOptions::default()
            },
            clock,
        )
        .unwrap();
    assert!(driver.timed_counters(handle).unwrap().is_none());
    let mut publication = driver.publication(handle).unwrap();
    assert!(driver.timed_counters(handle).unwrap().is_some());
    // The horizon is read from the injected clock: 1_100 is the limit.
    assert!(matches!(
        publication.offer_at(b"m", 1_101),
        Err(ClientError::ScheduleTooFar { limit: 1_100, .. })
    ));
    assert!(matches!(
        publication.offer_at(b"m", 1_100).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert!(invalid(publication.offer_at(b"m", 1_000)));
    assert!(matches!(
        publication.offer_at(b"m", u64::MAX),
        Err(ClientError::ScheduleOverflow)
    ));
    virtual_now.store(2_000, Ordering::Relaxed);
    assert!(matches!(
        publication.offer_at(b"m", 2_000).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert_eq!(
        publication.offer_at(b"m", 2_001).unwrap(),
        OfferOutcome::BackPressured
    );
    let read = |label: &str| counter(&driver, &format!("{label} (monotonic)"));
    assert_eq!(read("timed scheduled offers"), 2);
    assert_eq!(read("timed rejections invalid"), 1);
    assert_eq!(read("timed rejections too far"), 1);
    assert_eq!(read("timed rejections overflow"), 1);
    assert_eq!(read("timed rejections ring full"), 1);
    assert_eq!(read("timed late sends"), 0);
    assert_eq!(read("timed deadline aborts"), 0);
    assert_eq!(read("timed lateness <= 1us"), 0);
}
