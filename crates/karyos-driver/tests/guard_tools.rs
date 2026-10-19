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
