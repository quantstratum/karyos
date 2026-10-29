// SPDX-License-Identifier: Apache-2.0

//! Application trace point names (R-CORE-1, karyos#722;
//! `quantstratum-docs: karyos/design/trace-records.md`, "Point names")
//! against an in-process driver: the id the driver assigns and publishes
//! with the cell, the label checks on both sides, the bounds per client,
//! and the instance's ids running out.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::time::Duration;

use karyos_client::{Client, ClientError, Context, IdleStrategy};
use karyos_driver::{DriverConfig, EmbeddedDriver};
use karyos_protocol::cnc::ErrorCode;
use karyos_sys::counters::{CellRead, KIND_CLIENT, TYPE_TRACE_POINT};

fn context() -> Context {
    Context::builder()
        .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn serve<R: Send>(driver: &mut EmbeddedDriver, work: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(work);
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(50));
        }
        handle.join().unwrap()
    })
}

/// The driver counter labelled `label`.
fn driver_counter(driver: &EmbeddedDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|cell| match reader.read(cell) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no driver counter {label}"))
}

fn refused_with(result: Result<karyos_client::TracePointHandle, ClientError>) -> ErrorCode {
    match result {
        Err(ClientError::Refused { code, .. }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A point's cell is keyed to its client, of type id 8, its label the
/// name and its value the id; ids count up from 1 and a released point's
/// id is never given again.
#[test]
fn the_driver_assigns_ids_and_publishes_them_with_the_cell() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    let (first, second, third) = serve(&mut driver, || {
        let first = client.add_trace_point("order received").unwrap();
        let second = client.add_trace_point("risk checked").unwrap();
        drop(first);
        // The label is free again, under a new id.
        let third = client.add_trace_point("order received").unwrap();
        let second_id = (second.id(), second.client(), second.cell());
        (1u16, second_id, (third.id(), third.cell()))
    });
    assert_eq!(first, 1);
    assert_eq!(second.0, 2);
    assert_eq!(third.0, 3);
    let reader = driver.client_counters();
    let CellRead::Allocated {
        metadata, value, ..
    } = reader.read(second.2)
    else {
        panic!("not allocated");
    };
    assert_eq!(metadata.type_id, TYPE_TRACE_POINT);
    assert_eq!(metadata.label(), b"risk checked");
    assert_eq!(metadata.keys.kind, KIND_CLIENT);
    assert_eq!(metadata.keys.participant, second.1);
    assert_eq!(value, 2);
}

/// Hostile labels are refused by the client before anything is
/// requested; a duplicate of a live label is refused too.
#[test]
fn hostile_and_duplicate_labels_are_refused() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    serve(&mut driver, || {
        for label in [
            "",
            "line\nbreak",
            "nul\0byte",
            "escape\u{1b}[31m",
            "c1\u{85}control",
            "del\u{7f}",
            &"x".repeat(65),
        ] {
            assert_eq!(
                client.add_trace_point(label).err(),
                Some(ClientError::InvalidLabel),
                "{label:?}"
            );
        }
        // Quotes, backslashes and non-ASCII letters are printable: the
        // export escapes them.
        let quoted = client.add_trace_point("say \"hi\" \\ café").unwrap();
        let longest = client.add_trace_point(&"é".repeat(32)).unwrap();
        assert_eq!(
            client.add_trace_point("say \"hi\" \\ café").err(),
            Some(ClientError::DuplicateTracePoint)
        );
        drop((quoted, longest));
    });
}

/// The bounds per client: live points, then registrations over its life,
/// both refused with `ResourcesUnavailable`; another client is unaffected.
#[test]
fn the_bounds_per_client_are_refused() {
    let config = DriverConfig {
        max_trace_points_per_client: 2,
        max_trace_point_registrations_per_client: 3,
        ..DriverConfig::default()
    };
    let mut driver = EmbeddedDriver::with_config(config).unwrap();
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    let mut other = Client::with_conductor(driver.connect().unwrap(), context());
    serve(&mut driver, || {
        let a = client.add_trace_point("a").unwrap();
        let b = client.add_trace_point("b").unwrap();
        assert_eq!(
            refused_with(client.add_trace_point("c")),
            ErrorCode::ResourcesUnavailable
        );
        drop(a);
        // The release reaches the driver with the client's next poll; a
        // refused attempt registers nothing.
        let start = std::time::Instant::now();
        let c = loop {
            let _ = client.poll();
            match client.add_trace_point("c") {
                Ok(c) => break c,
                Err(ClientError::Refused {
                    code: ErrorCode::ResourcesUnavailable,
                    ..
                }) if start.elapsed() < Duration::from_secs(10) => {}
                Err(error) => panic!("{error:?}"),
            }
        };
        drop(b);
        // Three registered over its life: the fourth is refused, live or
        // not.
        assert_eq!(
            refused_with(client.add_trace_point("d")),
            ErrorCode::ResourcesUnavailable
        );
        let theirs = other.add_trace_point("d").unwrap();
        drop((c, theirs));
    });
}

/// The instance's last id is 65 535: past it every registration is
/// refused with `TracePointIdsExhausted` and counted, and nothing is
/// allocated for it.
#[test]
fn the_instances_ids_run_out_with_a_typed_refusal() {
    let mut driver = EmbeddedDriver::new().unwrap();
    driver.set_next_trace_point(u32::from(u16::MAX));
    let mut client = Client::with_conductor(driver.connect().unwrap(), context());
    let (last, refused, again) = serve(&mut driver, || {
        let last = client.add_trace_point("last").unwrap();
        let id = last.id();
        drop(last);
        (
            id,
            refused_with(client.add_trace_point("one too many")),
            refused_with(client.add_trace_point("last")),
        )
    });
    assert_eq!(last, u16::MAX);
    assert_eq!(refused, ErrorCode::TracePointIdsExhausted);
    assert_eq!(again, ErrorCode::TracePointIdsExhausted);
    assert_eq!(driver_counter(&driver, "trace point ids exhausted"), 2);
    let reader = driver.client_counters();
    let points = (0..reader.capacity())
        .filter(|cell| {
            matches!(reader.read(*cell), CellRead::Allocated { metadata, .. }
                if metadata.type_id == TYPE_TRACE_POINT)
        })
        .count();
    assert_eq!(points, 0, "only the released point was ever allocated");
}
