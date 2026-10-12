// SPDX-License-Identifier: Apache-2.0

//! The embedded driver's system counters (SPEC.md §11).

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::HashMap;

use karyos_driver::counters::{TYPE_EVENTS, TYPE_GAUGE};
use karyos_driver::{EmbeddedDriver, StreamConfig};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::counters::CellRead;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::LogBufferConfig;
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
        },
        allow_unconnected: true,
    }
}

/// Label -> (type, value) of every allocated counter.
fn snapshot(driver: &EmbeddedDriver) -> HashMap<String, (u64, u64)> {
    let reader = driver.counters();
    (0..reader.capacity())
        .filter_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } => Some((
                String::from_utf8(metadata.label().to_vec()).unwrap(),
                (metadata.type_id, value),
            )),
            _ => None,
        })
        .collect()
}

fn value(driver: &EmbeddedDriver, label: &str) -> u64 {
    snapshot(driver)[label].1
}

#[test]
fn counters_track_clients_commands_and_streams() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let all = snapshot(&driver);
    assert_eq!(all["commands served"].0, TYPE_EVENTS);
    assert_eq!(all["streams active"].0, TYPE_GAUGE);
    assert!(all.values().all(|&(_, value)| value == 0));

    let stream = driver.add_stream(stream_config(2)).unwrap();
    assert_eq!(value(&driver, "streams active"), 1);
    let mut client = driver.connect().unwrap();
    let _other = driver.connect().unwrap();
    assert_eq!(value(&driver, "clients admitted"), 2);

    let key = StreamKey {
        stream_id: 2,
        session_id: 1,
    };
    let _ = client.add_publication(key, false).unwrap();
    let _ = driver.do_work().unwrap();
    let _ = client
        .add_subscription(
            StreamKey {
                stream_id: 99,
                session_id: 1,
            },
            SubscriberRole::Optional,
        )
        .unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(value(&driver, "commands served"), 2);
    assert_eq!(value(&driver, "commands refused"), 1);
    assert_eq!(value(&driver, "responses sent"), 2);

    driver.remove_stream(stream).unwrap();
    assert_eq!(value(&driver, "streams active"), 0);
    assert_eq!(value(&driver, "streams retiring"), 1);
    // The held publication keeps the stream until the client closes.
    client.close();
    let _ = driver.do_work().unwrap();
    assert_eq!(value(&driver, "clients retired"), 1);
    assert_eq!(value(&driver, "streams retiring"), 0);
    assert_eq!(value(&driver, "streams freed"), 1);
    assert_eq!(value(&driver, "terminal"), 0);
    assert_eq!(value(&driver, "counter overflows"), 0);
}
