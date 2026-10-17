// SPDX-License-Identifier: Apache-2.0

//! rp-w7a: redundant-paths.md section 8 validation on the routed
//! `Outbound`: a degraded path, leaving, service and the frontier. Time is
//! the network clock in ns; every timing bound is in time, not cycles.
//!
//! The test log has no receiver, so no SM opens its publication window:
//! half a 64 KiB term, 31 frames of 1056 bytes, is all a test can send.
//! Each test commits at most [`FRAMES`] (30); one that needs more must
//! send SMs first.

use super::*;

/// 100 µs between cycles.
const STEP: u64 = 100_000;

/// Frames a test commits at most: the test log's publication window (half
/// a 64 KiB term) takes 31 frames of 1056 bytes with no receiver SM.
const FRAMES: u8 = 30;

/// Serves 20 cycles with both sockets taking everything, so nothing is
/// left pending when the halves drop.
fn drain(
    outbound: &mut Outbound,
    halves: &mut [(EndpointId, Half<ScriptedSocket>)],
    observers: &[&ScriptedSocket],
    from: u64,
) {
    for observer in observers {
        sent(observer, 64);
    }
    for now in (from..).step_by(usize::try_from(STEP).unwrap()).take(20) {
        let _ = outbound.serve_routes(halves, BUDGET, None, now).unwrap();
    }
}

/// §8 Degraded path: B returns `EAGAIN` continuously. Its frames are
/// skipped and it leaves within `path_lag_limit` of the first skip, and A
/// submits every frame in the cycle it is committed, as on one path.
#[test]
fn a_blocked_path_leaves_and_costs_the_other_path_nothing() {
    let (a, observer_a, seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 256);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    let mut left_at = None;
    for k in 0..FRAMES {
        commit(&mut log, k, 1);
        let now = u64::from(k) * STEP;
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
        assert_eq!(
            seen_a.lock().unwrap().len(),
            usize::from(k) + 1,
            "A sends each frame in its own cycle at {now} ns"
        );
        if left_at.is_none() && outbound.path_state(1).map(|state| state.0) == Some(false) {
            left_at = Some(now);
        }
    }
    let left_at = left_at.expect("B left");
    assert!(
        left_at <= 2 * policy().lag_limit,
        "B left at {left_at} ns, past two windows"
    );
    assert_eq!(outbound.path_counters(1).unwrap().exits, 1);
    drain(
        &mut outbound,
        &mut halves,
        &[&observer_a, &observer_b],
        u64::from(FRAMES) * STEP,
    );
}

/// §8 Degraded path: B drains two datagrams of every three. It skips what
/// does not fit its queue (counted, `Degraded`), stays live, and A is not
/// slowed.
#[test]
fn a_path_draining_now_and_then_stays_live() {
    let (a, observer_a, seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 256);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    for k in 0..FRAMES {
        if k % 3 != 0 {
            sent(&observer_b, 1);
        }
        commit(&mut log, k, 1);
        let now = u64::from(k) * STEP;
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
        assert_eq!(seen_a.lock().unwrap().len(), usize::from(k) + 1);
        assert_eq!(
            outbound.path_state(1).map(|state| state.0),
            Some(true),
            "B stays live at {now} ns"
        );
    }
    let skipped = outbound
        .routed_sender()
        .unwrap()
        .counters(1)
        .unwrap()
        .skipped;
    assert!(skipped > 0, "B skipped what it could not take");
    let counters = outbound.path_counters(1).unwrap();
    assert!(counters.degraded >= 1, "{counters:?}");
    assert_eq!(counters.exits, 0, "{counters:?}");
    drain(
        &mut outbound,
        &mut halves,
        &[&observer_a, &observer_b],
        u64::from(FRAMES) * STEP,
    );
}

/// §8 Leaving: under steady traffic (a datagram every 5 ms), a path that
/// sends one datagram every 99 ms leaves within one `path_lag_limit`
/// window (100 ms).
#[test]
fn a_path_sending_every_99_ms_leaves_within_one_window() {
    const MS: u64 = 1_000_000;
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 256);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    let policy = super::super::PathPolicy {
        skip_min_bytes: 8 * FRAME,
        ..super::super::PathPolicy::default()
    };
    outbound.set_path_policy(policy);
    let mut left_at = None;
    let mut next_b = 0;
    for k in 0..FRAMES {
        let now = u64::from(k) * 5 * MS;
        if now >= next_b {
            sent(&observer_b, 1);
            next_b += 99 * MS;
        }
        commit(&mut log, k, 1);
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
        if left_at.is_none() && outbound.path_state(1).map(|state| state.0) == Some(false) {
            left_at = Some(now);
        }
    }
    let left_at = left_at.expect("B left");
    assert!(
        left_at <= policy.lag_limit,
        "B left at {left_at} ns, past one window"
    );
    drain(
        &mut outbound,
        &mut halves,
        &[&observer_a, &observer_b],
        200 * MS,
    );
}

/// §8 Leaving: only that publication's items on that path go. Another
/// publication on the same endpoints keeps sending on the path the first
/// one left.
#[test]
fn another_publication_on_the_same_endpoint_keeps_sending() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 256);
    sent(&observer_b, 256);
    let mut halves = vec![a, b];
    let routes = [
        (EndpointId(1), SocketAddr::from(([127, 0, 0, 1], 41_000))),
        (EndpointId(2), SocketAddr::from(([127, 0, 0, 2], 41_000))),
    ];
    let (mut first, mut first_log) = routed(0);
    let (mut second, mut second_log) = outbound_routed(&routes, OTHER_ALIAS, TERM, 1, false);
    first.set_path_policy(policy());
    second.set_path_policy(policy());
    commit(&mut first_log, 0, 1);
    commit(&mut second_log, 0, 1);
    for now in 0..4 {
        let _ = first.serve_routes(&mut halves, BUDGET, None, now).unwrap();
        let _ = second.serve_routes(&mut halves, BUDGET, None, now).unwrap();
    }
    first.leave_before_serve(1);
    let _ = first.serve_routes(&mut halves, BUDGET, None, 10).unwrap();
    assert_eq!(first.path_state(1).map(|state| state.0), Some(false));
    let calls = observer_b.send_calls();
    commit(&mut first_log, 1, 2);
    commit(&mut second_log, 1, 2);
    for now in 11..20 {
        let _ = first.serve_routes(&mut halves, BUDGET, None, now).unwrap();
        let _ = second.serve_routes(&mut halves, BUDGET, None, now).unwrap();
    }
    assert_eq!(
        first.routed_sender().unwrap().pending(0, 1),
        Some(0),
        "the first publication takes nothing on B"
    );
    assert_eq!(second.path_state(1).map(|state| state.0), Some(true));
    assert_eq!(
        observer_b.send_calls() - calls,
        2,
        "the second publication's two datagrams go on B"
    );
}

/// §8 Service: a frame selected while every path returns `WouldBlock`
/// debits nothing; once one path submits it, it is debited once.
#[test]
fn a_frame_no_path_can_take_debits_nothing() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(policy());
    commit(&mut log, 0, 1);
    for now in 0..4 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    assert!(outbound.routed_sender().unwrap().pending(0, 0).unwrap() > 0);
    assert_eq!(outbound.routed_sender().unwrap().debited(0), None);
    sent(&observer_a, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 10)
        .unwrap();
    assert_eq!(outbound.routed_sender().unwrap().debited(0), Some(0));
    drain(&mut outbound, &mut halves, &[&observer_a, &observer_b], 20);
}

/// A small seeded generator (xorshift64*), so a failing run names its
/// seed and replays.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// §8 Monotonic frontier: across random sends, blocks, leaves and returns
/// on two paths, `sent_high` never decreases. Seeded; the seed is in every
/// failure.
#[test]
fn sent_high_never_decreases_across_paths() {
    for seed in [1u64, 7, 0x5eed, 0xdead_beef, 42] {
        let mut random = Seeded(seed);
        let (a, observer_a, _seen_a) = path(1, 0);
        let (b, observer_b, _seen_b) = path(2, 0);
        let mut halves = vec![a, b];
        let (mut outbound, mut log) = routed(0);
        outbound.set_path_policy(return_policy());
        let mut high = 0;
        let mut committed = 0u8;
        for k in 0..60u64 {
            let roll = random.next();
            if roll.is_multiple_of(3) && committed < FRAMES {
                commit(&mut log, committed, 1);
                committed += 1;
            }
            if (roll >> 8).is_multiple_of(2) {
                sent(&observer_a, 1);
            }
            if !(roll >> 16).is_multiple_of(3) {
                sent(&observer_b, 1);
            }
            if (roll >> 24).is_multiple_of(17) {
                outbound.leave_before_serve(usize::try_from((roll >> 32) % 2).unwrap());
            }
            let now = 1_000 + k * 10;
            let _ = outbound
                .serve_routes(&mut halves, BUDGET, None, now)
                .unwrap();
            let now_high = outbound.sent_high(0).unwrap();
            assert!(
                now_high >= high,
                "seed {seed:#x}: sent_high went from {high} to {now_high} at cycle {k}"
            );
            high = now_high;
        }
        drain(
            &mut outbound,
            &mut halves,
            &[&observer_a, &observer_b],
            10_000,
        );
    }
}
