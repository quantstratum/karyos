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
fn the_cap_does_not_hide_a_buffers_own_refusal() {
    // A buffer that refuses its configuration refuses it with its own
    // error, whether a cap is set or not.
    let mut invalid = stream(2, MIN_TERM_LENGTH);
    invalid.buffer.max_reserved = MIN_TERM_LENGTH * 2;
    let uncapped = EmbeddedDriver::new()
        .unwrap()
        .add_stream(invalid)
        .map(|_| ());
    assert!(uncapped.is_err());
    assert!(
        !matches!(uncapped, Err(DriverError::InvalidConfig)),
        "{uncapped:?}"
    );
    let (mut driver, _) = capped();
    assert_eq!(driver.add_stream(invalid).map(|_| ()), uncapped);
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

/// On an IPC driver, a refused lane takes no region id (R-CORE-34, plan
/// 153): `add_stream`, `add_aggregate` and `replay_target` refuse before
/// any region is created. `tests/sizing_bounded.rs` checks the mappings.
#[cfg(target_os = "linux")]
#[test]
fn a_refused_lane_takes_no_region_id() {
    let dir = std::env::temp_dir().join(format!(
        "karyos-stream-cap-{}-region-ids",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let timeout = 5_000_000_000;
    let max = lane_bytes(MIN_TERM_LENGTH);
    let mut driver: EmbeddedDriver<karyos_sys::term_bytes::SharedTerms> = EmbeddedDriver::with_ipc(
        DriverConfig {
            max_stream_bytes: Some(max),
            ..DriverConfig::default()
        },
        crate::admission::IpcConfig {
            dir: dir.clone(),
            max_pending_hellos: 2,
            hello_timeout: timeout,
            max_outbound_per_client: 8,
            fetch_deadline: timeout,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: crate::admission::DEFAULT_MAX_TOOLS,
        },
        Box::new(crate::clock::SystemClock::new()),
    )
    .unwrap();
    let next = |driver: &EmbeddedDriver<karyos_sys::term_bytes::SharedTerms>| {
        driver.admission.as_ref().unwrap().peek_next_region()
    };
    let before = next(&driver);
    let larger = MIN_TERM_LENGTH * 2;
    assert!(matches!(
        driver.add_stream(stream(3, larger)),
        Err(DriverError::StreamTooLarge { .. })
    ));
    let frame = u64::from(karyos_sys::sizing::align_frame(DEFAULT_MTU).unwrap()) * 4;
    assert!(matches!(
        driver.add_aggregate(AggregateConfig {
            stream: stream(4, larger),
            quanta: vec![frame; 2],
        }),
        Err(DriverError::StreamTooLarge { .. })
    ));
    assert!(matches!(
        driver.replay_target(crate::replay::ReplayTargetConfig {
            stream_id: 9,
            session_id: 9,
            term_length: larger,
            initial_term_id: 0,
            mtu: DEFAULT_MTU,
            join: 0,
            lane: Lane::ZERO,
            source_stream_id: 2,
            source_session_id: 1,
        }),
        Err(DriverError::StreamTooLarge { .. })
    ));
    assert_eq!(next(&driver), before, "a refusal took a region id");
    assert!(driver.streams.is_empty());
    // A lane at the cap takes one.
    assert!(driver.add_stream(stream(2, MIN_TERM_LENGTH)).is_ok());
    assert!(next(&driver) > before);
    drop(driver);
    let _ = std::fs::remove_dir_all(&dir);
}
