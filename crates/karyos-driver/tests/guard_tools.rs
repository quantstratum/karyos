// SPDX-License-Identifier: Apache-2.0

//! Guards for tools (`quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md`, M4): every transition,
//! refusals included, reaches the guard audit ring a tool reads, with host
//! and driver times; each guard's word is a gauge labelled with its name.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use karyos_driver::EmbeddedDriver;
use karyos_sys::counters::{CellRead, KIND_GUARD};
use karyos_sys::diag::GuardAuditRecord;

/// The gauges of kind guard: (guard id, label, value).
/// The labels of a guard's acknowledgement cells (M4b), beside its word.
const ACK_CELLS: [&str; 6] = [
    "guard ack pass",
    "guard ack epoch",
    "guard senders applied",
    "guard senders in flight",
    "guard senders pending",
    "guard senders overdue",
];

/// Each guard's word gauge: (guard id, label, value).
fn guard_gauges(driver: &EmbeddedDriver) -> Vec<(u64, String, u64)> {
    let reader = driver.counters();
    (0..reader.capacity())
        .filter_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.keys.kind == KIND_GUARD => Some((
                metadata.keys.participant,
                String::from_utf8(metadata.label().to_vec()).unwrap(),
                value,
            )),
            _ => None,
        })
        .filter(|(_, label, _)| !ACK_CELLS.contains(&label.as_str()))
        .collect()
}

fn ring(driver: &EmbeddedDriver, cursor: &mut u64) -> Vec<GuardAuditRecord> {
    let mut records = Vec::new();
    let _ = driver
        .guard_audit_ring()
        .scan(cursor, |_, record| records.push(record));
    records
}

#[test]
fn transitions_reach_the_ring_and_words_their_gauges() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let kill = driver.add_guard("kill switch").unwrap();
    let other = driver.add_guard("desk 7").unwrap();
    let _ = driver.do_work().unwrap();
    let word = |driver: &EmbeddedDriver, id: u64| {
        guard_gauges(driver)
            .into_iter()
            .find(|(guard, _, _)| *guard == id)
            .map(|(_, label, value)| (label, value))
            .unwrap()
    };
    let created = word(&driver, kill.id());
    assert_eq!(created.0, "kill switch");
    assert_ne!(created.1, 0);
    assert_eq!(word(&driver, other.id()).0, "desk 7");

    let before = karyos_sys::host_clock::host_monotonic_ns();
    let _ = driver.reopen_guard(kill, 1, 41).unwrap();
    let _ = driver.close_guard(kill, 42).unwrap();
    let _ = driver.close_guard(kill, 43).unwrap();
    // A reopen at a stale epoch is refused, and recorded.
    assert!(driver.reopen_guard(kill, 1, 44).is_err());
    let mut cursor = 0;
    let records = ring(&driver, &mut cursor);
    let outcomes: Vec<(u64, u8, u8)> = records
        .iter()
        .map(|record| (record.operation, record.outcome, record.requester_kind))
        .collect();
    assert_eq!(outcomes, [(41, 3, 0), (42, 1, 0), (43, 2, 0), (44, 4, 0)]);
    assert!(records.iter().all(|record| record.time >= before));
    assert!(records.iter().all(|record| record.guard == kill.id()));
    assert_ne!(records[3].refusal, 0);
    assert_eq!(records[1].before, records[0].after);
    // The ring holds what the driver's own audit holds, field by field.
    let audit = driver.guard_audit();
    for (own, tool) in audit.records.iter().zip(&records) {
        assert_eq!(
            (own.time, own.guard, own.before, own.after, own.operation),
            (
                tool.driver_time,
                tool.guard,
                tool.before,
                tool.after,
                tool.operation
            )
        );
    }
    // The gauge follows the word at the next duty cycle.
    let _ = driver.do_work().unwrap();
    assert_eq!(word(&driver, kill.id()).1, records[1].after);
    assert_ne!(word(&driver, kill.id()).1, created.1);
    // Nothing new: a later scan delivers nothing.
    assert!(ring(&driver, &mut cursor).is_empty());
}

/// DESIGN's repro on #470: the conductor loop's spin meter taken and
/// dropped leaves the fixed `conductor spin time` cell in place, so a
/// later keyed allocation (a guard's gauge) never takes a fixed index.
#[test]
fn a_dropped_spin_meter_keeps_the_fixed_cells_in_place() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let fixed = |driver: &EmbeddedDriver| {
        let reader = driver.counters();
        (0..reader.capacity())
            .filter_map(|index| match reader.read(index) {
                CellRead::Allocated { metadata, .. } if metadata.keys.kind == 0 => {
                    Some((index, String::from_utf8(metadata.label().to_vec()).unwrap()))
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let before = fixed(&driver);
    assert!(
        before
            .iter()
            .any(|(_, label)| label == "conductor spin time")
    );
    drop(driver.take_spin_meter().unwrap());
    let _ = driver.add_guard("kill switch").unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(fixed(&driver), before, "a fixed cell moved or was released");
    let gauges = guard_gauges(&driver);
    assert_eq!(gauges.len(), 1);
    // The guard's gauge took a cell past every fixed one.
    let reader = driver.counters();
    let guard_index = (0..reader.capacity())
        .find(|&index| {
            matches!(
                reader.read(index),
                CellRead::Allocated { metadata, .. } if metadata.keys.kind == KIND_GUARD
            )
        })
        .unwrap();
    assert!(before.iter().all(|(index, _)| *index < guard_index));
}

/// A full guard audit ring counts each record it overwrites in `guard
/// audit records overwritten`; nothing is dropped while sequences last
/// (exhausting 2^64 sequences is out of a test's reach, as for the error
/// log's `error events dropped`).
#[test]
fn a_full_guard_ring_counts_what_it_overwrites() {
    let config = karyos_driver::DriverConfig {
        guard_audit_records: 2,
        ..karyos_driver::DriverConfig::default()
    };
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let guard = driver.add_guard("kill switch").unwrap();
    let _ = driver.reopen_guard(guard, 1, 1).unwrap();
    let _ = driver.close_guard(guard, 2).unwrap();
    let _ = driver.reopen_guard(guard, 3, 3).unwrap();
    let _ = driver.close_guard(guard, 4).unwrap();
    let _ = driver.do_work().unwrap();
    let value = |driver: &EmbeddedDriver, label: &str| {
        let reader = driver.counters();
        (0..reader.capacity())
            .find_map(|index| match reader.read(index) {
                CellRead::Allocated {
                    metadata, value, ..
                } if metadata.label() == label.as_bytes() => Some(value),
                _ => None,
            })
            .unwrap()
    };
    assert_eq!(value(&driver, "guard audit records overwritten"), 2);
    assert_eq!(value(&driver, "guard audit records dropped"), 0);
    // A sync with nothing new adds nothing.
    let _ = driver.do_work().unwrap();
    assert_eq!(value(&driver, "guard audit records overwritten"), 2);
}
