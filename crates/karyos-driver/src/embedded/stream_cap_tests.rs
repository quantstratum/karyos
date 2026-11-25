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

use karyos_sys::conflation::ConflationConfig;
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

/// A table that `conflation_shape` refuses (a value capacity past `u32`)
/// keeps its own error with the cap set, on `add_stream` and
/// `add_aggregate` (karyos#824): the cap must not turn it into
/// `StreamTooLarge`. A reconfiguration keeps its stream's table, which its
/// creation already checked.
#[test]
fn the_cap_does_not_hide_a_tables_own_refusal() {
    let mut table = stream(2, MIN_TERM_LENGTH);
    table.conflation = Some(ConflationConfig::new(1, 1 << 32, 4096));
    let uncapped = EmbeddedDriver::new().unwrap().add_stream(table).map(|_| ());
    assert_eq!(uncapped, Err(DriverError::InvalidConfig));
    let (mut driver, _) = capped();
    assert_eq!(driver.add_stream(table).map(|_| ()), uncapped, "add_stream");
    let frame = u64::from(karyos_sys::sizing::align_frame(DEFAULT_MTU).unwrap()) * 4;
    let mut aggregate = stream(4, MIN_TERM_LENGTH);
    aggregate.conflation = table.conflation;
    assert_eq!(
        driver
            .add_aggregate(AggregateConfig {
                stream: aggregate,
                quanta: vec![frame; 2],
            })
            .map(|_| ()),
        uncapped,
        "add_aggregate"
    );
    assert!(driver.streams.is_empty(), "nothing created");
}

/// The invariant behind every path (karyos#824): `table_region_bytes`, and
/// so `lane_regions` and `stream_lane_bytes`, refuse a table that
/// `conflation_shape` refuses, so no caller can size it, cap it or report
/// it. A reconfiguration reuses the live stream's table, already
/// validated by `conflation_shape`, and is unreachable with such a table
/// from the public API; this covers it and any later path.
#[test]
fn table_region_bytes_refuses_what_conflation_shape_refuses() {
    let refused = ConflationConfig::new(1, 1 << 32, 4096);
    assert!(conflation_shape(refused).is_err());
    assert_eq!(table_region_bytes(&refused), None);
    let buffer = stream(2, MIN_TERM_LENGTH).buffer;
    assert_eq!(lane_regions(&buffer, Some(&refused)), None);
    assert_eq!(stream_lane_bytes(&buffer, Some(&refused)), None);
    let accepted = ConflationConfig::new(1, usize::try_from(u32::MAX).unwrap(), 4096);
    assert!(conflation_shape(accepted).is_ok());
    // Accepted: sized exactly as its region is, and the lane is the log
    // buffer plus the table (the #837 review, point 1).
    let bytes = region_bytes(accepted.structure_length());
    assert!(bytes.is_some(), "an accepted table has a size");
    assert_eq!(table_region_bytes(&accepted), bytes);
    let log = log_region_bytes(&buffer).unwrap();
    assert_eq!(
        stream_lane_bytes(&buffer, Some(&accepted)),
        Some(log + bytes.unwrap())
    );
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
            client_send_buffer: None,
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

/// The report without a cap is byte for byte the one of `d01c477a`, before
/// karyos#824 (plan 160, criterion 4): two declared streams, one
/// conflated, at the defaults and 4 KiB pages.
///
/// `sizing_uncapped_d01c477a.txt` is that commit's
/// `crate::sizing::report(..).to_string()` for exactly these inputs,
/// captured on Linux (`rust:1.99`) with this test's body run at
/// `d01c477a`. A change to the uncapped report must be deliberate: it
/// regenerates the file the same way, and says so.
///
/// Regenerated for karyos#869: the driver counters region holds
/// `max_trace_point_copies` (256) more cells, the trace point copies'.
#[cfg(target_os = "linux")]
#[test]
fn the_uncapped_report_is_unchanged() {
    let mut conflated = stream(3, MIN_TERM_LENGTH);
    conflated.conflation = Some(ConflationConfig::new(4, 64, 4096));
    let report = crate::sizing::report(
        &DriverConfig::default(),
        &[stream(2, MIN_TERM_LENGTH), conflated],
        4096,
    )
    .unwrap();
    assert_eq!(
        report.to_string(),
        include_str!("sizing_uncapped_d01c477a.txt")
    );
}

/// The sizing report refuses a table that `add_stream` refuses (a value
/// capacity past `u32`), with or without a cap, as the same invalid
/// conflation configuration (karyos#824).
#[cfg(target_os = "linux")]
#[test]
fn the_report_refuses_a_table_that_add_stream_refuses() {
    let mut table = stream(2, MIN_TERM_LENGTH);
    table.conflation = Some(ConflationConfig::new(1, 1 << 32, 4096));
    let refused = Err(crate::sizing::SizingError::Invalid(
        "a stream's conflation configuration",
    ));
    for max_stream_bytes in [None, Some(lane_bytes(MIN_TERM_LENGTH))] {
        let config = DriverConfig {
            max_stream_bytes,
            ..DriverConfig::default()
        };
        assert_eq!(
            crate::sizing::report(&config, &[table], 4096).map(|_| ()),
            refused,
            "cap {max_stream_bytes:?}"
        );
    }
}
