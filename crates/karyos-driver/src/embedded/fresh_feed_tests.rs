// SPDX-License-Identifier: Apache-2.0

//! A network image view's feeder steps (conflated-network-images.md (b)):
//! the seal mailbox and the gaps met in the log, over a real table and
//! link.

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use karyos_sys::conflation::conflation_fresh;
use karyos_sys::freshness::{DEFAULT_RING, FreshnessLink, TERMINAL_BELOW_FRONTIER, TerminalCell};

use super::{FreshFed, FreshFeed, serve_fresh, serve_gap};

fn view() -> (karyos_sys::conflation::ConflationWriter, FreshFeed) {
    let link = FreshnessLink::new();
    let writer = conflation_fresh(4, 8, 1024, link.clone()).unwrap();
    (writer, FreshFeed { link, gap: None })
}

/// A posted interval is acknowledged only after the barrier recorded it;
/// with the barrier full the ack is withheld, counted, and given once a
/// reconciliation made room.
#[test]
fn a_seal_request_is_acknowledged_after_its_record() {
    let (mut writer, mut fresh) = view();
    let mut fed = FreshFed::default();
    let owner_link = fresh.link.clone();
    let owner = owner_link.mailbox().unwrap();
    let request = owner.post(64, 128).unwrap();
    assert!(serve_fresh(&mut writer, &mut fresh, &mut fed));
    assert!(owner.is_acknowledged(request));
    assert!(writer.recorded(64, 128));
    assert_eq!(fed.acked, 1);
    // Fill the barrier, then post one more: withheld until room.
    for i in 1..DEFAULT_RING as u64 {
        writer.record_loss(128 * i + 64, 128 * i + 96).unwrap();
    }
    let request = owner.post(4096, 4160).unwrap();
    assert!(serve_fresh(&mut writer, &mut fresh, &mut fed));
    assert!(!owner.is_acknowledged(request));
    assert_eq!(fed.withheld, 1);
    let _ = writer.reconcile(16).unwrap();
    writer.passed(4096);
    assert!(serve_fresh(&mut writer, &mut fresh, &mut fed));
    assert!(owner.is_acknowledged(request));
    assert_eq!(fed.acked, 2);
}

/// A gap met in the log (sealed before the attach) is recorded there and
/// passed; one the mailbox already recorded is only passed; a gap the full
/// barrier cannot take is held, and the poll does not run past it.
#[test]
fn a_gap_met_in_the_log_is_recorded_before_anything_past_it() {
    let (mut writer, mut fresh) = view();
    let mut fed = FreshFed::default();
    fresh.gap = Some((64, 128));
    assert!(serve_gap(&mut writer, &mut fresh, &mut fed));
    assert_eq!((fresh.gap, fed.caught_up), (None, 1));
    assert!(!writer.recorded(64, 128), "passed: behind the frontier");
    // Recorded through the mailbox first: passed without a second record.
    writer.record_loss(192, 256).unwrap();
    fresh.gap = Some((192, 256));
    assert!(serve_gap(&mut writer, &mut fresh, &mut fed));
    assert_eq!(fed.caught_up, 1);
    assert_eq!(writer.fresh_counters().unwrap().losses, 2);
    // Full: held, and serve_fresh says the poll waits.
    for i in 0..DEFAULT_RING as u64 - 2 {
        writer.record_loss(512 + 64 * i, 512 + 64 * i + 32).unwrap();
    }
    fresh.gap = Some((8192, 8256));
    assert!(!serve_gap(&mut writer, &mut fresh, &mut fed));
    assert!(!serve_fresh(&mut writer, &mut fresh, &mut fed));
    assert_eq!(fresh.gap, Some((8192, 8256)));
}

/// A request below the frontier breaks the readers' invariant: the writer
/// publishes the terminal cell and the request is not acknowledged.
#[test]
fn a_request_below_the_frontier_closes_the_view() {
    let (mut writer, mut fresh) = view();
    let mut fed = FreshFed::default();
    writer.passed(1024);
    let owner_link = fresh.link.clone();
    let owner = owner_link.mailbox().unwrap();
    let request = owner.post(64, 128).unwrap();
    assert!(serve_fresh(&mut writer, &mut fresh, &mut fed));
    assert!(!owner.is_acknowledged(request));
    assert_eq!(
        TerminalCell::read(&fresh.link.terminal_words()).map(|terminal| terminal.reason),
        Some(TERMINAL_BELOW_FRONTIER)
    );
}
