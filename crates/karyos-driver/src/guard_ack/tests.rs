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

/// Review of #227 (P2-1): a sender registered after a close is not
/// concerned by it; it is by later closes.
#[test]
fn a_sender_registered_after_a_close_is_not_listed_for_it() {
    let (mut driver, guard, _) = driver(DriverConfig::default());
    let (old, cell) = driver.register_guard_sender(guard).unwrap();
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    cell.publish(applied(3, 0));
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    let (new, _) = driver.register_guard_sender(guard).unwrap();
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert_eq!(
        ack.senders.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        vec![old]
    );
    assert_eq!(ack.effective(), Some(true));
    assert_eq!(driver.close_guard(guard, 4), Ok(Closed::Now { epoch: 5 }));
    let ack = driver.close_guard_ack(guard, 5).unwrap();
    assert_eq!(
        ack.senders.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        vec![old, new]
    );
}

/// Overdue for an older close is measured from that close's own time,
/// while it is in the kept history.
#[test]
fn overdue_is_measured_from_the_close_acknowledged() {
    let config = DriverConfig {
        guard_ack_timeout: SECOND,
        ..DriverConfig::default()
    };
    let (mut driver, guard, now) = driver(config);
    let _ = driver.register_guard_sender(guard).unwrap();
    now.store(10 * SECOND, Ordering::Relaxed);
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    now.store(20 * SECOND, Ordering::Relaxed);
    assert_eq!(driver.close_guard(guard, 4), Ok(Closed::Now { epoch: 5 }));
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert_eq!(ack.senders[0].1, SenderAck::Pending { overdue: true });
    let ack = driver.close_guard_ack(guard, 5).unwrap();
    assert_eq!(ack.senders[0].1, SenderAck::Pending { overdue: false });
    // A clock read behind the close is never overdue.
    now.store(5 * SECOND, Ordering::Relaxed);
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert_eq!(ack.senders[0].1, SenderAck::Pending { overdue: false });
}

/// Epoch 1 is the guard's creation, not a close.
#[test]
fn the_initial_epoch_is_not_a_close() {
    let (mut driver, guard, _) = driver(DriverConfig::default());
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    assert!(matches!(
        driver.close_guard_ack(guard, 1),
        Err(DriverError::Guard(GuardError::NotClosedAt {
            expected: 1,
            ..
        }))
    ));
}

/// A sender id names its driver: another driver does not know it.
#[test]
fn a_sender_id_belongs_to_its_driver() {
    let (mut driver, guard, _) = driver(DriverConfig::default());
    let (mut other, other_guard, _) = self::driver(DriverConfig::default());
    let (id, _) = other.register_guard_sender(other_guard).unwrap();
    let (mine, _) = driver.register_guard_sender(guard).unwrap();
    assert_eq!(id.get(), mine.get(), "the same number, two drivers");
    assert_eq!(
        driver.deregister_guard_sender(id),
        Err(DriverError::UnknownGuardSender { sender: id.get() })
    );
    driver.deregister_guard_sender(mine).unwrap();
    other.deregister_guard_sender(id).unwrap();
}

/// The guard's acknowledgement gauges (M4b), as a tool reads them: label
/// to value, and the pass cell's value.
fn ack_gauges(driver: &EmbeddedDriver, guard: GuardHandle) -> (Vec<(String, u64)>, u64) {
    use karyos_sys::counters::{CellRead, KIND_GUARD};
    let reader = driver.counters();
    let mut gauges = Vec::new();
    let mut pass = None;
    for index in 0..reader.capacity() {
        if let CellRead::Allocated {
            metadata, value, ..
        } = reader.read(index)
            && metadata.keys.kind == KIND_GUARD
            && metadata.keys.participant == guard.id()
        {
            let label = String::from_utf8(metadata.label().to_vec()).unwrap();
            if label == ACK_PASS_LABEL {
                pass = Some(value);
            } else if ACK_LABELS.contains(&label.as_str()) {
                gauges.push((label, value));
            }
        }
    }
    (gauges, pass.unwrap())
}

fn values(gauges: &[(String, u64)]) -> [u64; 5] {
    let mut out = [0; 5];
    for (slot, label) in out.iter_mut().zip(ACK_LABELS) {
        *slot = gauges
            .iter()
            .find(|(name, _)| name == label)
            .map(|(_, value)| *value)
            .unwrap();
    }
    out
}

/// M4b: a close's senders reach the CnC by state, recomputed at each duty
/// cycle: pending, then overdue as the clock passes the timeout, then
/// applied with work in flight and applied; a reopen clears the gauges.
/// Each change is one pass; an unchanged cycle writes nothing.
#[test]
fn a_close_acknowledgement_reaches_the_cnc() {
    let (mut driver, guard, now) = driver(DriverConfig::default());
    let (_first, cell) = driver.register_guard_sender(guard).unwrap();
    let (_second, _never) = driver.register_guard_sender(guard).unwrap();
    let _ = driver.do_work().unwrap();
    // Open: no close in effect, written once so a reader trusts it.
    let (gauges, pass) = ack_gauges(&driver, guard);
    assert_eq!((values(&gauges), pass), ([0; 5], 2));
    now.store(10, Ordering::Relaxed);
    assert_eq!(driver.close_guard(guard, 1), Ok(Closed::Now { epoch: 3 }));
    let _ = driver.do_work().unwrap();
    let (gauges, pass) = ack_gauges(&driver, guard);
    assert_eq!((values(&gauges), pass), ([3, 0, 0, 2, 0], 4));
    // Nothing changed: no pass.
    let _ = driver.do_work().unwrap();
    assert_eq!(ack_gauges(&driver, guard).1, 4);
    // Past the timeout, both are overdue; one then applies with work in
    // flight, then drains.
    now.store(10 + SECOND, Ordering::Relaxed);
    let _ = driver.do_work().unwrap();
    assert_eq!(values(&ack_gauges(&driver, guard).0), [3, 0, 0, 0, 2]);
    cell.publish(applied(3, 4));
    let _ = driver.do_work().unwrap();
    assert_eq!(values(&ack_gauges(&driver, guard).0), [3, 0, 1, 0, 1]);
    cell.publish(applied(3, 0));
    let _ = driver.do_work().unwrap();
    let (gauges, pass) = ack_gauges(&driver, guard);
    assert_eq!((values(&gauges), pass), ([3, 1, 0, 0, 1], 10));
    // The counts agree with close_guard_ack's report.
    let ack = driver.close_guard_ack(guard, 3).unwrap();
    assert_eq!(ack.senders.len(), 2);
    // A reopen ends the close: the gauges clear.
    assert_eq!(driver.reopen_guard(guard, 3, 2), Ok(4));
    let _ = driver.do_work().unwrap();
    assert_eq!(values(&ack_gauges(&driver, guard).0), [0; 5]);
}

/// DESIGN's P2 on #479: a guard's word gauge carries its name beside its
/// acknowledgement group, so a name equal to a group label is refused,
/// whatever readers would make of it; other names are not.
#[test]
fn a_guard_may_not_take_an_acknowledgement_label_as_its_name() {
    let (mut driver, _, _) = driver(DriverConfig::default());
    for name in ACK_LABELS.iter().chain([&ACK_PASS_LABEL]) {
        assert_eq!(
            driver.add_guard(name),
            Err(DriverError::InvalidConfig),
            "{name}"
        );
    }
    assert!(driver.add_guard("guard ack").is_ok());
}
