// SPDX-License-Identifier: Apache-2.0

//! The conflated lane's seal gate against a feeder played by the test over
//! the shared link.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

const MS: u64 = 1_000_000;
const TIMEOUT: u64 = DEFAULT_BARRIER_ACK_TIMEOUT_NS;

fn gate() -> (ConflatedGate, FreshnessLink) {
    let link = FreshnessLink::new();
    (ConflatedGate::new(Lane::ZERO, link.clone(), TIMEOUT), link)
}

/// Without an attached feeder, and on another lane, the seal is permitted
/// at once and nothing is posted.
#[test]
fn an_unattached_view_and_another_lane_seal_at_once() {
    let (mut gate, link) = gate();
    assert_eq!(gate.before_seal(Lane::ZERO, 64, 64, 0), GateAnswer::Permit);
    link.mailbox().unwrap().attach();
    let other = Lane::try_new(1).unwrap();
    assert_eq!(gate.before_seal(other, 64, 64, 0), GateAnswer::Permit);
    assert_eq!(link.mailbox().unwrap().pending(), None);
    assert_eq!(
        gate.take_counts(),
        GateCounts {
            unattached: 1,
            ..GateCounts::default()
        }
    );
}

/// Attached: the interval is posted and held until the feeder's
/// acknowledgement, then permitted; the next hole is posted anew.
#[test]
fn an_attached_view_holds_the_seal_until_the_ack() {
    let (mut gate, link) = gate();
    let feeder = link.mailbox().unwrap();
    feeder.attach();
    assert_eq!(gate.before_seal(Lane::ZERO, 64, 64, 0), GateAnswer::Pending);
    let request = feeder.pending().unwrap();
    assert_eq!((request.start, request.end), (64, 128));
    assert_eq!(
        gate.before_seal(Lane::ZERO, 64, 64, MS),
        GateAnswer::Pending
    );
    feeder.acknowledge(request.request).unwrap();
    assert_eq!(
        gate.before_seal(Lane::ZERO, 64, 64, 2 * MS),
        GateAnswer::Permit
    );
    assert_eq!(
        gate.before_seal(Lane::ZERO, 192, 32, 3 * MS),
        GateAnswer::Pending
    );
    assert_eq!(feeder.pending().map(|r| (r.start, r.end)), Some((192, 224)));
    assert_eq!(
        gate.take_counts(),
        GateCounts {
            posted: 2,
            acknowledged: 1,
            ..GateCounts::default()
        }
    );
    assert!(
        link.terminal_words()
            .iter()
            .all(|w| w.load(std::sync::atomic::Ordering::Relaxed) == 0)
    );
}

/// A stalled feeder: past the bound the gate publishes the terminal cell
/// with the posted interval, permits the seal and every later one.
#[test]
fn a_stalled_feeder_closes_the_view_at_the_bound() {
    let (mut gate, link) = gate();
    link.mailbox().unwrap().attach();
    assert_eq!(gate.before_seal(Lane::ZERO, 64, 64, 0), GateAnswer::Pending);
    assert_eq!(
        gate.before_seal(Lane::ZERO, 64, 64, TIMEOUT - 1),
        GateAnswer::Pending
    );
    assert_eq!(
        gate.before_seal(Lane::ZERO, 64, 64, TIMEOUT),
        GateAnswer::Permit
    );
    assert_eq!(
        TerminalCell::read(&link.terminal_words()),
        Some(Terminal {
            start: 64,
            end: 128,
            reason: TERMINAL_BARRIER_TIMEOUT
        })
    );
    assert!(gate.closed());
    assert_eq!(
        gate.before_seal(Lane::ZERO, 192, 32, TIMEOUT),
        GateAnswer::Permit
    );
    assert_eq!(
        gate.take_counts(),
        GateCounts {
            posted: 1,
            timeouts: 1,
            ..GateCounts::default()
        }
    );
}

/// The feeder claimed the cell first and has not published it: the gate
/// waits (Pending, counted) and permits only once the cell reads
/// published (docs#120).
#[test]
fn a_claimed_cell_holds_the_seal_until_published() {
    let (mut gate, link) = gate();
    link.mailbox().unwrap().attach();
    assert_eq!(gate.before_seal(Lane::ZERO, 64, 64, 0), GateAnswer::Pending);
    // The feeder's claim, its body not yet published.
    link.terminal_words()[0].store(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        gate.before_seal(Lane::ZERO, 64, 64, TIMEOUT),
        GateAnswer::Pending
    );
    assert_eq!(
        gate.before_seal(Lane::ZERO, 64, 64, TIMEOUT + MS),
        GateAnswer::Pending
    );
    assert!(!gate.closed());
    // The feeder publishes.
    for (word, value) in link.terminal_words()[1..].iter().zip([64, 128, 2]) {
        word.store(value, std::sync::atomic::Ordering::Relaxed);
    }
    link.terminal_words()[0].store(2, std::sync::atomic::Ordering::Release);
    assert_eq!(
        gate.before_seal(Lane::ZERO, 64, 64, TIMEOUT + 2 * MS),
        GateAnswer::Permit
    );
    assert!(gate.closed());
    assert_eq!(
        gate.take_counts(),
        GateCounts {
            posted: 1,
            timeouts: 1,
            claim_waits: 2,
            ..GateCounts::default()
        }
    );
}

/// #320 review: the bound counts from each request's own post. A posted at
/// 50 ms and acknowledged; B posted at 200 ms is still Pending at
/// 299.999 ms and goes to the fail-safe at 300 ms.
#[test]
fn the_bound_counts_from_each_requests_post() {
    let (mut gate, link) = gate();
    let feeder = link.mailbox().unwrap();
    feeder.attach();
    assert_eq!(
        gate.before_seal(Lane::ZERO, 64, 64, 50 * MS),
        GateAnswer::Pending
    );
    feeder
        .acknowledge(feeder.pending().unwrap().request)
        .unwrap();
    assert_eq!(
        gate.before_seal(Lane::ZERO, 64, 64, 60 * MS),
        GateAnswer::Permit
    );
    assert_eq!(
        gate.before_seal(Lane::ZERO, 192, 64, 200 * MS),
        GateAnswer::Pending
    );
    assert_eq!(
        gate.before_seal(Lane::ZERO, 192, 64, 200 * MS + TIMEOUT - 1),
        GateAnswer::Pending
    );
    assert_eq!(
        gate.before_seal(Lane::ZERO, 192, 64, 200 * MS + TIMEOUT),
        GateAnswer::Permit
    );
    assert!(gate.closed());
    let counts = gate.take_counts();
    assert_eq!(
        (counts.posted, counts.acknowledged, counts.timeouts),
        (2, 1, 1)
    );
}

/// An acknowledged interval whose seal waited (its term not ready) is
/// permitted again without a second post, so the feeder records it once.
#[test]
fn an_acknowledged_interval_is_never_posted_twice() {
    let (mut gate, link) = gate();
    let feeder = link.mailbox().unwrap();
    feeder.attach();
    assert_eq!(gate.before_seal(Lane::ZERO, 64, 64, 0), GateAnswer::Pending);
    feeder
        .acknowledge(feeder.pending().unwrap().request)
        .unwrap();
    assert_eq!(gate.before_seal(Lane::ZERO, 64, 64, MS), GateAnswer::Permit);
    // The seal returned NotReady: the policy asks again.
    assert_eq!(
        gate.before_seal(Lane::ZERO, 64, 64, 2 * MS),
        GateAnswer::Permit
    );
    assert_eq!(feeder.pending(), None);
    assert_eq!(gate.take_counts().posted, 1);
}

/// A terminal cell the feeder published (its own exhaustion) closes the
/// view before any post, and while a request is Pending.
#[test]
fn a_published_terminal_cell_permits_without_a_post() {
    let terminal = Terminal {
        start: 0,
        end: 64,
        reason: karyos_sys::freshness::TERMINAL_FRESHNESS_EXHAUSTED,
    };
    let (mut gate, link) = gate();
    link.mailbox().unwrap().attach();
    assert!(link.terminal().unwrap().publish(terminal));
    assert_eq!(gate.before_seal(Lane::ZERO, 64, 64, 0), GateAnswer::Permit);
    assert!(gate.closed());
    assert_eq!(link.mailbox().unwrap().pending(), None, "nothing posted");
    // While Pending.
    let (mut gate, link) = gate_pair();
    link.mailbox().unwrap().attach();
    assert_eq!(gate.before_seal(Lane::ZERO, 64, 64, 0), GateAnswer::Pending);
    assert!(link.terminal().unwrap().publish(terminal));
    assert_eq!(gate.before_seal(Lane::ZERO, 64, 64, MS), GateAnswer::Permit);
    assert_eq!(gate.take_counts().timeouts, 0, "not a timeout");
}

fn gate_pair() -> (ConflatedGate, FreshnessLink) {
    gate()
}
