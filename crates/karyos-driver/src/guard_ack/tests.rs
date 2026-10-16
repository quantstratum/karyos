// SPDX-License-Identifier: Apache-2.0

//! The effective-close acknowledgement (G-e4), with the gates' cells
//! written directly: the gate's own publication is tested with the gate.

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use std::sync::atomic::{AtomicU64 as StdAtomicU64, Ordering};

use karyos_sys::guard::Closed;

use super::*;
use crate::clock::MonotonicClock;
use crate::embedded::DriverConfig;

const SECOND: u64 = 1_000_000_000;

#[derive(Debug, Clone, Default)]
struct ManualClock {
    now: Arc<StdAtomicU64>,
}

impl MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

/// A driver on a manual clock, with a guard open at epoch 2.
fn driver(config: DriverConfig) -> (EmbeddedDriver, GuardHandle, Arc<StdAtomicU64>) {
    let clock = ManualClock::default();
    let now = Arc::clone(&clock.now);
    let mut driver = EmbeddedDriver::with_clock(config, Box::new(clock)).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    (driver, guard, now)
}

fn applied(epoch: u64, in_flight: u64) -> Applied {
    Applied {
        epoch,
        positions: [64, 0, 0, 0],
        in_flight,
    }
}

#[test]
fn no_sender_says_nothing_about_effectiveness() {
    let (mut driver, guard, _) = driver(DriverConfig::default());
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert!(ack.senders.is_empty());
    assert_eq!(ack.effective(), None, "no sender is not an applied close");
    assert_eq!(ack.unreachable, Unreachable::NotTracked);
}

/// Applied with work in flight is not effective; drained, it is.
#[test]
fn applied_and_effective_are_told_apart() {
    let (mut driver, guard, _) = driver(DriverConfig::default());
    let (id, cell) = driver.register_guard_sender(guard).unwrap();
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    cell.publish(applied(3, 2));
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert_eq!(
        ack.senders,
        vec![(
            id,
            SenderAck::Applied {
                positions: [64, 0, 0, 0],
                in_flight: 2
            }
        )]
    );
    assert_eq!(ack.effective(), Some(false));
    cell.publish(applied(3, 0));
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert!(ack.senders[0].1.effective());
    assert_eq!(ack.effective(), Some(true));
}

/// A sender that has not applied the close is pending, and overdue past
/// the timeout, by the driver clock from the close; never closed.
#[test]
fn a_pending_sender_becomes_overdue_never_closed() {
    let config = DriverConfig {
        guard_ack_timeout: SECOND,
        ..DriverConfig::default()
    };
    let (mut driver, guard, now) = driver(config);
    let (id, cell) = driver.register_guard_sender(guard).unwrap();
    now.store(10 * SECOND, Ordering::Relaxed);
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    // The sender only applied the earlier open epoch.
    cell.publish(applied(2, 0));
    now.store(11 * SECOND - 1, Ordering::Relaxed);
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert_eq!(
        ack.senders,
        vec![(id, SenderAck::Pending { overdue: false })]
    );
    now.store(11 * SECOND, Ordering::Relaxed);
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert_eq!(
        ack.senders,
        vec![(id, SenderAck::Pending { overdue: true })]
    );
    assert_eq!(ack.effective(), Some(false));
}

/// A writer stopped in the middle of a publication is read at most
/// `ACK_READ_ATTEMPTS` times, then reported pending.
#[test]
fn a_stalled_writer_is_reported_pending() {
    let (mut driver, guard, _) = driver(DriverConfig::default());
    let (id, cell) = driver.register_guard_sender(guard).unwrap();
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    cell.publish(applied(3, 0));
    cell.stall_writer();
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert_eq!(
        ack.senders,
        vec![(id, SenderAck::Pending { overdue: false })]
    );
    assert_eq!(ACK_READ_ATTEMPTS, 8);
}

/// A later reopen, or a later close the sender applied, does not undo an
/// acknowledgement of the earlier close.
#[test]
fn a_later_epoch_keeps_an_earlier_close_applied() {
    let (mut driver, guard, _) = driver(DriverConfig::default());
    let (_, cell) = driver.register_guard_sender(guard).unwrap();
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    cell.publish(applied(3, 0));
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    assert_eq!(
        driver.close_guard_ack(guard, 3).unwrap().effective(),
        Some(true)
    );
    assert_eq!(driver.close_guard(guard, 4), Ok(Closed::Now { epoch: 5 }));
    cell.publish(applied(5, 0));
    assert_eq!(
        driver.close_guard_ack(guard, 3).unwrap().effective(),
        Some(true)
    );
    assert_eq!(
        driver.close_guard_ack(guard, 5).unwrap().effective(),
        Some(true)
    );
}

/// Only closes are acknowledged: an epoch the guard never closed at, or an
/// open epoch, is refused.
#[test]
fn only_a_close_is_acknowledged() {
    let (mut driver, guard, _) = driver(DriverConfig::default());
    assert!(matches!(
        driver.close_guard_ack(guard, 3),
        Err(DriverError::Guard(GuardError::NotClosedAt {
            expected: 3,
            ..
        }))
    ));
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    assert!(matches!(
        driver.close_guard_ack(guard, 2),
        Err(DriverError::Guard(GuardError::NotClosedAt {
            expected: 2,
            ..
        }))
    ));
    assert!(matches!(
        driver.close_guard_ack(guard, 5),
        Err(DriverError::Guard(GuardError::NotClosedAt {
            expected: 5,
            ..
        }))
    ));
}

/// The registry is bounded, a retired sender leaves later acks, and a
/// sender serves one guard only.
#[test]
fn the_registry_is_bounded_and_senders_retire() {
    let config = DriverConfig {
        max_guard_senders: 2,
        ..DriverConfig::default()
    };
    let (mut driver, guard, _) = driver(config);
    let other = driver.add_guard("quotes").unwrap();
    let (first, _) = driver.register_guard_sender(guard).unwrap();
    let (second, _) = driver.register_guard_sender(other).unwrap();
    assert_eq!(
        driver.register_guard_sender(guard).err(),
        Some(DriverError::TooManyGuardSenders)
    );
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert_eq!(
        ack.senders.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        vec![first],
        "the other guard's sender is not listed"
    );
    driver.deregister_guard_sender(first).unwrap();
    assert!(driver.close_guard_ack(guard, 3).unwrap().senders.is_empty());
    assert_eq!(
        driver.deregister_guard_sender(first),
        Err(DriverError::UnknownGuardSender {
            sender: first.get()
        })
    );
    let (third, _) = driver.register_guard_sender(guard).unwrap();
    assert!(third.get() > second.get(), "ids are never reused");
}

#[test]
fn a_zero_ack_timeout_is_refused() {
    let config = DriverConfig {
        guard_ack_timeout: 0,
        ..DriverConfig::default()
    };
    assert_eq!(
        EmbeddedDriver::with_config(config).err(),
        Some(DriverError::InvalidConfig)
    );
}
