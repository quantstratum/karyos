// SPDX-License-Identifier: Apache-2.0

//! Heartbeats and liveness (roadmap P4, batch p4b; quantstratum-docs:
//! `karyos/design/required-participant-loss.md`): the driver times out a
//! client whose heartbeat stopped, on the driver's clock, and a client
//! presumes the driver lost when the driver's heartbeat stops, on the
//! client's clock.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use karyos_client::{ClientConductor, ConductorError};
use karyos_driver::{DriverConfig, EmbeddedDriver, MonotonicClock};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::counters::CellRead;

#[derive(Debug, Clone, Default)]
struct ManualClock {
    now: Arc<AtomicU64>,
    reads: Arc<AtomicU64>,
}

impl ManualClock {
    fn set(&self, now: u64) {
        self.now.store(now, Ordering::Relaxed);
    }

    fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }
}

impl MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.now.load(Ordering::Relaxed)
    }
}

const INTERVAL: u64 = 10;
const TIMEOUT: u64 = 100;

fn driver() -> (EmbeddedDriver, ManualClock) {
    let clock = ManualClock::default();
    let config = DriverConfig {
        heartbeat_interval: INTERVAL,
        client_liveness_timeout: TIMEOUT,
        ..DriverConfig::default()
    };
    let driver = EmbeddedDriver::with_clock(config, Box::new(clock.clone())).unwrap();
    (driver, clock)
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

fn subscribe(client: &mut ClientConductor) -> Result<u64, ConductorError> {
    client.add_subscription(
        StreamKey {
            stream_id: 99,
            session_id: 1,
        },
        SubscriberRole::Optional,
    )
}

/// A client beats on every poll, so the driver's manual clock alone
/// decides when it is late.
fn beating(driver: &mut EmbeddedDriver) -> ClientConductor {
    let mut client = driver.connect().unwrap();
    client.set_liveness(Duration::ZERO, Duration::from_secs(3600));
    client
}

#[test]
fn test_driver_liveness_a_silent_client_times_out_at_exactly_the_timeout() {
    let (mut driver, clock) = driver();
    let mut client = driver.connect().unwrap();
    // First sample at 0: the client's heartbeat never changes after it.
    let _ = driver.do_work().unwrap();
    clock.set(TIMEOUT - 1);
    assert_eq!(driver.do_work().unwrap(), 0);
    assert_eq!(counter(&driver, "clients timed out"), 0);
    assert!(subscribe(&mut client).is_ok());
    clock.set(TIMEOUT);
    // The served command above and the time-out are this cycle's work.
    let _ = driver.do_work().unwrap();
    assert_eq!(counter(&driver, "clients timed out"), 1);
    assert_eq!(counter(&driver, "clients faulty"), 0);
    // Its ring is closed: it learns it was disconnected and must connect
    // again. Timing out is not a detach proof: the slot stays charged until
    // the client closes.
    assert_eq!(subscribe(&mut client), Err(ConductorError::Closed));
    assert_eq!(driver.clients(), 1);
    drop(client);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.clients(), 0);
}

#[test]
fn test_driver_liveness_a_close_at_the_deadline_is_a_retirement_not_a_time_out() {
    let (mut driver, clock) = driver();
    let client = driver.connect().unwrap();
    let _ = driver.do_work().unwrap();
    clock.set(TIMEOUT);
    client.close();
    let _ = driver.do_work().unwrap();
    assert_eq!(counter(&driver, "clients timed out"), 0);
    assert_eq!(counter(&driver, "clients retired"), 1);
    assert_eq!(driver.clients(), 0);
}

#[test]
fn test_driver_liveness_a_beating_client_never_times_out() {
    let (mut driver, clock) = driver();
    let mut client = beating(&mut driver);
    for step in 0..50 {
        clock.set(step * (TIMEOUT / 2));
        let _ = client.poll(usize::MAX, |_| {});
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(counter(&driver, "clients timed out"), 0);
    assert!(subscribe(&mut client).is_ok());
}

#[test]
fn test_driver_liveness_a_paused_driver_does_not_time_out_a_client_that_kept_beating() {
    let (mut driver, clock) = driver();
    let mut client = beating(&mut driver);
    let _ = client.poll(usize::MAX, |_| {});
    let _ = driver.do_work().unwrap();
    // The driver pauses far past the timeout while the client keeps beating.
    let _ = client.poll(usize::MAX, |_| {});
    clock.set(10 * TIMEOUT);
    let _ = driver.do_work().unwrap();
    assert_eq!(counter(&driver, "clients timed out"), 0);
    assert!(subscribe(&mut client).is_ok());
}

#[test]
fn test_driver_liveness_the_clock_is_read_only_while_a_client_is_admitted() {
    let (mut driver, clock) = driver();
    let _ = driver.do_work().unwrap();
    assert_eq!(clock.reads(), 0);
    let client = driver.connect().unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(clock.reads(), 1);
    drop(client);
    let _ = driver.do_work().unwrap();
    let reads = clock.reads();
    let _ = driver.do_work().unwrap();
    assert_eq!(clock.reads(), reads);
}

#[test]
fn test_client_liveness_a_silent_driver_is_presumed_lost() {
    let (mut driver, _clock) = driver();
    let mut client = driver.connect().unwrap();
    client.set_liveness(Duration::from_millis(1), Duration::from_millis(10));
    // The driver's heartbeat never moves: it runs no duty.
    let _ = client.poll(usize::MAX, |_| {});
    assert!(!client.driver_lost());
    std::thread::sleep(Duration::from_millis(20));
    let _ = client.poll(usize::MAX, |_| {});
    assert!(client.driver_lost());
    assert_eq!(subscribe(&mut client), Err(ConductorError::Closed));
}

#[test]
fn test_client_liveness_a_beating_driver_is_never_lost() {
    let (mut driver, clock) = driver();
    let mut client = driver.connect().unwrap();
    client.set_liveness(Duration::from_millis(1), Duration::from_millis(10));
    for step in 0..20 {
        // Each driver cycle is one heartbeat interval later.
        clock.set(step * INTERVAL);
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |_| {});
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(!client.driver_lost());
}
