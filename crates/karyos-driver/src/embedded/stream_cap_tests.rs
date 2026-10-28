// SPDX-License-Identifier: Apache-2.0

//! `DriverConfig::max_stream_bytes` (R-CORE-34, karyos#809): every path
//! that creates a stream lane refuses one above the cap with
//! `StreamTooLarge`, and creates nothing.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;
use crate::generations::Reconfiguration;

fn stream(stream_id: i32, term_length: u32) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(term_length).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: term_length / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation: None,
    }
}

/// The bytes of a lane of `term_length`: the cap a test sets at it.
fn lane_bytes(term_length: u32) -> u64 {
    stream_lane_bytes(&stream(1, term_length).buffer, None).unwrap()
}

/// A driver whose cap admits a lane of the smallest term and no larger.
fn capped() -> (EmbeddedDriver, u64) {
    let max = lane_bytes(MIN_TERM_LENGTH);
    let driver = EmbeddedDriver::with_config(DriverConfig {
        max_stream_bytes: Some(max),
        ..DriverConfig::default()
    })
    .unwrap();
    (driver, max)
}

fn too_large(max: u64, term_length: u32) -> DriverError {
    DriverError::StreamTooLarge {
        bytes: lane_bytes(term_length),
        max,
    }
}

#[test]
fn a_zero_cap_is_refused_and_none_bounds_nothing() {
    let zero = DriverConfig {
        max_stream_bytes: Some(0),
        ..DriverConfig::default()
    };
    assert_eq!(zero.validate(), Err(DriverError::InvalidConfig));
    let mut driver = EmbeddedDriver::new().unwrap();
    assert!(driver.add_stream(stream(2, 1 << 20)).is_ok());
}

#[test]
fn add_stream_and_add_aggregate_refuse_a_lane_above_the_cap() {
    let (mut driver, max) = capped();
    assert!(driver.add_stream(stream(2, MIN_TERM_LENGTH)).is_ok());
    let larger = MIN_TERM_LENGTH * 2;
    assert_eq!(
        driver.add_stream(stream(3, larger)).map(|_| ()),
        Err(too_large(max, larger))
    );
    let frame = u64::from(karyos_sys::sizing::align_frame(DEFAULT_MTU).unwrap()) * 4;
    assert_eq!(
        driver
            .add_aggregate(AggregateConfig {
                stream: stream(4, larger),
                quanta: vec![frame; 2],
            })
            .map(|_| ()),
        Err(too_large(max, larger))
    );
    assert_eq!(driver.streams.len(), 1, "nothing created");
}

#[test]
fn a_reconfiguration_successor_above_the_cap_is_refused() {
    let (mut driver, max) = capped();
    let handle = driver.add_stream(stream(2, MIN_TERM_LENGTH)).unwrap();
    let larger = MIN_TERM_LENGTH * 2;
    let refused = driver.reconfigure_stream(
        handle,
        Reconfiguration {
            term_length: TermLength::try_new(larger).unwrap(),
            spare_slots: 3,
        },
    );
    assert_eq!(refused, Err(too_large(max, larger)));
    assert!(
        driver.streams[0].retained.is_empty(),
        "no successor, nothing retained"
    );
}

#[test]
fn a_reincarnation_above_the_cap_is_refused() {
    // The cap is fixed for a driver's life, so a reincarnation, which keeps
    // its stream's geometry, never exceeds it; lowering it here reaches
    // the check on that path.
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_stream(stream(2, MIN_TERM_LENGTH)).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(handle, guard, 4, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let mut publication = driver.publication(handle).unwrap();
    assert!(publication.offer(b"one").is_ok());
    assert!(driver.close_guard(guard, 2).is_ok());
    // As the guards tests do: a gated offer, the duty cycles, and the
    // outcomes read, so the sealed incarnation has released.
    let _ = publication.offer(b"two").unwrap();
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    let _ = publication.poll_outcomes(64, |_, _| {}).unwrap();
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    let max = lane_bytes(MIN_TERM_LENGTH) - 1;
    driver.config.max_stream_bytes = Some(max);
    assert_eq!(
        driver.publication(handle).map(|_| ()),
        Err(DriverError::StreamTooLarge {
            bytes: max + 1,
            max
        })
    );
    assert_eq!(driver.trace_identity(handle).unwrap().incarnation, 1);
}

#[test]
fn a_replay_target_above_the_cap_is_refused() {
    let (mut driver, max) = capped();
    let larger = MIN_TERM_LENGTH * 2;
    let refused = driver.replay_target(crate::replay::ReplayTargetConfig {
        stream_id: 9,
        session_id: 9,
        term_length: larger,
        initial_term_id: 0,
        mtu: DEFAULT_MTU,
        join: 0,
        lane: Lane::ZERO,
        source_stream_id: 2,
        source_session_id: 1,
    });
    let Err(DriverError::StreamTooLarge { bytes, max: seen }) = refused.map(|_| ()) else {
        panic!("not refused by the cap");
    };
    assert_eq!(seen, max);
    assert!(bytes > max);
    assert!(driver.streams.is_empty(), "nothing created");
}
