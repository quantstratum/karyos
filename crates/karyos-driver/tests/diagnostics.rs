// SPDX-License-Identifier: Apache-2.0

//! The driver's error log and loss report (roadmap P7, o3b;
//! quantstratum-docs: `karyos/design/observability-and-tools.md`, "Error
//! log" and "Loss report"): refusals become deduplicated error records and
//! overwrites are counted.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use karyos_driver::diagnostics::ErrorCode;
use karyos_driver::{DriverConfig, DriverError, EmbeddedDriver, LossPolicy, StreamConfig};
use karyos_sys::counters::CellRead;
use karyos_sys::diag::ErrorRecord;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

fn stream_config(stream_id: i32) -> StreamConfig {
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
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

fn counter(driver: &EmbeddedDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

fn errors(driver: &EmbeddedDriver) -> Vec<ErrorRecord> {
    let mut records = Vec::new();
    let _ = driver
        .error_log()
        .scan(&mut 0, |record| records.push(record));
    records
}

#[test]
fn test_error_log_a_repeated_refusal_updates_one_record() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let _ = driver.add_stream(stream_config(2)).unwrap();
    for _ in 0..3 {
        assert!(matches!(
            driver.add_stream(stream_config(2)),
            Err(DriverError::DuplicateStream { .. })
        ));
    }
    let records = errors(&driver);
    assert_eq!(records.len(), 1, "{records:?}");
    let record = &records[0];
    assert_eq!(record.code, ErrorCode::StreamConfigRejected as u32);
    assert_eq!(record.key, [2, 1]);
    assert_eq!(record.occurrences, 3);
    assert!(record.first > 0 && record.last >= record.first);
    assert!(!record.message.is_empty());
}

#[test]
fn test_error_log_overwrites_are_counted() {
    let config = DriverConfig {
        error_log_records: 1,
        ..DriverConfig::default()
    };
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    for stream_id in [2, 3] {
        let _ = driver.add_stream(stream_config(stream_id)).unwrap();
        let _ = driver.add_stream(stream_config(stream_id)).unwrap_err();
    }
    // Two keys in a ring of one record: the first was overwritten.
    let mut cursor = 0;
    let mut records = Vec::new();
    let scan = driver
        .error_log()
        .scan(&mut cursor, |record| records.push(record));
    assert_eq!((scan.overwritten, records.len()), (1, 1));
    assert_eq!(records[0].key, [3, 1]);
    assert_eq!(counter(&driver, "error records overwritten"), 1);
    assert_eq!(counter(&driver, "loss records overwritten"), 0);
    assert_eq!(counter(&driver, "error events dropped"), 0);
}

#[test]
fn test_error_log_and_loss_report_sizes_are_validated() {
    for config in [
        DriverConfig {
            error_log_records: 0,
            ..DriverConfig::default()
        },
        DriverConfig {
            loss_report_records: 0,
            ..DriverConfig::default()
        },
    ] {
        assert!(matches!(
            EmbeddedDriver::with_config(config),
            Err(DriverError::InvalidConfig)
        ));
    }
    let driver = EmbeddedDriver::new().unwrap();
    let mut records = 0;
    let _ = driver.loss_report().scan(&mut 0, |_, _| records += 1);
    assert_eq!(records, 0);
}
