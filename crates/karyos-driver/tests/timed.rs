// SPDX-License-Identifier: Apache-2.0

//! Timed transmission through the embedded driver (`quantstratum-docs:
//! karyos/design/timed-tx.md`; P2.11 T1, step 3b): a timed lane's handle
//! takes `offer_at` only, checked before anything is reserved, and every
//! accepted message leaves its entry in the lane's schedule ring. A timed
//! lane is a network publication's (owner item 65): each test's lane is
//! one, reliable, towards a loopback port nothing reads, and its driver
//! runs no cycle unless the test does, so the sender releases nothing; a
//! local stream refuses a ring.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::schedule::{
    CLOCK_UNAVAILABLE, ClockDomain, ScheduleClock, ScheduleOptions, now,
};
use karyos_client::{ClientError, OfferOutcome};
use karyos_driver::agents::ThreadingMode;
use karyos_driver::net::NetworkConfig;
use karyos_driver::{
    AggregateConfig, AggregateHandle, DriverConfig, DriverError, EmbeddedDriver, StreamConfig,
    StreamHandle,
};
use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

const SECOND: u64 = 1_000_000_000;

/// A network-enabled driver whose agents run only in the test's cycles.
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

fn config(schedule_capacity: u32) -> StreamConfig {
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
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// A reliable channel towards a loopback port nothing reads; the socket
/// holding the port is leaked for the test's life.
fn channel() -> UdpConfig {
    let unread = Box::leak(Box::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap()));
    UdpConfig {
        retransmit_window: None,
        nak_control: Vec::new(),
        linger: None,
        path_skew: None,
        destination: Destination::Unicast(unread.local_addr().unwrap()),
        interface: Some(Interface::Address(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        ))),
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    }
}

/// A network publication of one lane with `schedule_capacity` entries,
/// timed with `options` (and `clock`) when that is above 0, and its lane.
fn try_publication(
    driver: &mut EmbeddedDriver,
    schedule_capacity: u32,
    options: ScheduleOptions,
    clock: Option<ScheduleClock>,
) -> Result<(AggregateHandle, StreamHandle), DriverError> {
    let aggregate = AggregateConfig {
        stream: config(schedule_capacity),
        quanta: vec![u64::from(DEFAULT_MTU) * 4],
    };
    let channel = channel();
    let publication = match (schedule_capacity, clock) {
        (0, _) => driver.add_network_publication(aggregate, &channel),
        (_, None) => driver.add_timed_network_publication(aggregate, &channel, None, options),
        (_, Some(clock)) => driver
            .add_timed_network_publication_with_clock(aggregate, &channel, None, options, clock),
    }?;
    let lane = publication.lane(Lane::ZERO).unwrap();
    Ok((publication, lane))
}

fn stream(driver: &mut EmbeddedDriver, schedule_capacity: u32) -> StreamHandle {
    stream_with(driver, schedule_capacity, ScheduleOptions::default())
}

fn stream_with(
    driver: &mut EmbeddedDriver,
    schedule_capacity: u32,
    options: ScheduleOptions,
) -> StreamHandle {
    try_publication(driver, schedule_capacity, options, None)
        .unwrap()
        .1
}

/// Owner item 65: a local stream has no sender to release a schedule
/// ring, so the driver refuses one there, for a stream and for an
/// aggregate, with `InvalidConfig`; nothing is added. A ring of 0 is a
/// plain stream.
#[test]
fn a_local_stream_refuses_a_schedule_ring() {
    let mut driver = EmbeddedDriver::new().unwrap();
    assert_eq!(
        driver.add_stream(config(4)).err(),
        Some(DriverError::InvalidConfig)
    );
    assert_eq!(
        driver
            .add_aggregate(AggregateConfig {
                stream: config(4),
                quanta: vec![u64::from(DEFAULT_MTU) * 4],
            })
            .err(),
        Some(DriverError::InvalidConfig)
    );
    // Nothing was added: the key is free.
    assert!(driver.add_stream(config(0)).is_ok());
}

/// The driver refuses a schedule capacity that is not a power of two up
/// to the bound with the schedule's own error, not a publication mode one.
#[test]
fn a_schedule_capacity_is_bounded() {
    let mut driver = driver();
    let max = karyos_sys::schedule_ring::MAX_CAPACITY;
    for capacity in [3, max * 2] {
        assert_eq!(
            try_publication(&mut driver, capacity, ScheduleOptions::default(), None).err(),
            Some(DriverError::Sys(karyos_sys::error::SysError::Schedule(
                karyos_sys::schedule_ring::ScheduleError::Capacity { capacity }
            ))),
        );
    }
    assert!(try_publication(&mut driver, max, ScheduleOptions::default(), None).is_ok());
}

fn invalid(result: Result<OfferOutcome, ClientError>) -> bool {
    matches!(result, Err(ClientError::InvalidSchedule { .. }))
}

#[test]
fn a_lane_that_is_not_timed_refuses_offer_at() {
    let mut driver = driver();
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
    let mut driver = driver();
    let handle = stream_with(
        &mut driver,
        4,
        ScheduleOptions::default().with_max_horizon(SECOND),
    );
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
    let mut driver = driver();
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

/// A network lane's settings are fixed at its creation: `schedule_stream`
/// is refused at once, before any handle, and after one. The software
/// route refuses the `Tai` domain, so no timed lane is `Tai` (the IPC
/// lanes that were are refused since owner item 65).
#[test]
fn the_schedule_is_fixed_at_creation() {
    let mut driver = driver();
    let handle = stream(&mut driver, 4);
    assert_eq!(
        driver.schedule_stream(handle, ScheduleOptions::default()),
        Err(DriverError::InvalidConfig)
    );
    let _publication = driver.publication(handle).unwrap();
    assert_eq!(
        driver.schedule_stream(handle, ScheduleOptions::default()),
        Err(DriverError::InvalidConfig)
    );
    let mut other = self::driver();
    assert!(matches!(
        try_publication(
            &mut other,
            4,
            ScheduleOptions::default().with_domain(ClockDomain::Tai),
            None,
        ),
        Err(DriverError::TimedNetworkUnsupported { .. })
    ));
}

/// A timed lane takes no cutover: its ring belongs to one buffer, and the
/// handle's publisher would not follow a successor (#234 P1). A timed lane
/// is a network publication's, whose cutover is refused first until its
/// sender follows successors (W2, `NetworkCutover`); `TimedCutover` then
/// still refuses it. Nothing changes on the refusal: the lane keeps its
/// mapping and its offers.
#[test]
fn a_timed_lane_refuses_a_cutover() {
    let mut driver = driver();
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
        Err(DriverError::NetworkCutover { .. })
    ));
    assert_eq!(driver.generations(handle).unwrap().len(), 1);
    assert!(matches!(
        publication.offer_at(b"m", 2).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    // A local stream, not timed, still takes one.
    let mut other = EmbeddedDriver::new().unwrap();
    let plain = other.add_stream(config(0)).unwrap();
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
    let mut driver = driver();
    assert!(matches!(
        try_publication(
            &mut driver,
            4,
            ScheduleOptions::default().with_max_horizon(0),
            None,
        ),
        Err(DriverError::Client(ClientError::InvalidSchedule { .. }))
    ));
}

/// The settings are fixed once a handle of the incarnation was issued,
/// also after it is dropped: its entries stay in the ring (#234 P3).
#[test]
fn the_schedule_stays_fixed_after_a_handle_is_dropped() {
    let mut driver = driver();
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
    let mut driver = driver();
    let (aggregate, handle) =
        try_publication(&mut driver, 4, ScheduleOptions::default(), None).unwrap();
    let mut publication = driver.publication(handle).unwrap();
    assert!(matches!(
        publication.offer_at(b"m", 10).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert!(invalid(publication.offer_at(b"m", 5)));
    driver.remove_aggregate(&aggregate).unwrap();
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
    let mut driver = driver();
    let virtual_now = Arc::new(AtomicU64::new(1_000));
    let clock = {
        let virtual_now = Arc::clone(&virtual_now);
        ScheduleClock::new(move || virtual_now.load(Ordering::Relaxed))
    };
    let (_aggregate, handle) = try_publication(
        &mut driver,
        2,
        ScheduleOptions::default().with_max_horizon(100),
        Some(clock),
    )
    .unwrap();
    // A network lane's counters exist from its creation.
    assert!(driver.timed_counters(handle).unwrap().is_some());
    let mut publication = driver.publication(handle).unwrap();
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

/// A clock that cannot read the time refuses every offer with
/// `ScheduleOverflow`, counted, whatever the horizon (ACS 15475; a zero
/// horizon is refused at creation).
#[test]
fn an_unavailable_clock_refuses_the_offer() {
    for max_horizon in [1, SECOND] {
        let mut driver = driver();
        let (_aggregate, handle) = try_publication(
            &mut driver,
            2,
            ScheduleOptions::default().with_max_horizon(max_horizon),
            Some(ScheduleClock::new(|| CLOCK_UNAVAILABLE)),
        )
        .unwrap();
        let mut publication = driver.publication(handle).unwrap();
        for time in [0, 1_000, u64::MAX - SECOND] {
            assert!(matches!(
                publication.offer_at(b"m", time),
                Err(ClientError::ScheduleOverflow)
            ));
        }
        assert_eq!(counter(&driver, "timed rejections overflow (monotonic)"), 3);
        assert_eq!(counter(&driver, "timed scheduled offers (monotonic)"), 0);
    }
}

/// The timed network streams a driver configures
/// (`NetworkStreamDefaults::timed`) are checked at start: a capacity of 0
/// or a stream given twice refuses the driver with `InvalidConfig`.
#[test]
fn invalid_timed_network_streams_refuse_the_driver() {
    use karyos_driver::net::TimedNetworkStream;

    let with = |timed: [Option<TimedNetworkStream>; 2]| {
        let mut network = NetworkConfig {
            threading: ThreadingMode::Shared,
            ..NetworkConfig::default()
        };
        network.stream_defaults.timed[..2].copy_from_slice(&timed);
        EmbeddedDriver::with_config(DriverConfig {
            network: Some(network),
            ..DriverConfig::default()
        })
        .err()
    };
    let one = |stream_id, schedule_capacity| {
        Some(TimedNetworkStream {
            stream_id,
            schedule_capacity,
        })
    };
    assert_eq!(with([one(3, 0), None]), Some(DriverError::InvalidConfig));
    assert_eq!(
        with([one(3, 4), one(3, 8)]),
        Some(DriverError::InvalidConfig)
    );
    assert_eq!(with([one(3, 4), one(4, 8)]), None);
}
