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

/// §8 Degraded path: B's socket refuses every send with `errno` (`EAGAIN`
/// or `ENOBUFS`, which karyos-io reports apart: `WouldBlock` and
/// `NoBuffers`). Its frames are skipped and it leaves, and A submits every
/// frame in the cycle it is committed, as on one path. The bound is two
/// `path_lag_limit` windows, not one: the sliding window must first hold
/// `path_skip_min_bytes` selected before the skipped share can decide.
fn a_refusing_path_leaves_and_costs_the_other_path_nothing(errno: Errno) {
    let (a, observer_a, seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 256);
    for _ in 0..256 {
        observer_b.push_send(SendResult::Error(errno));
    }
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
            "{errno:?}: A sends each frame in its own cycle at {now} ns"
        );
        if left_at.is_none() && outbound.path_state(1).map(|state| state.0) == Some(false) {
            left_at = Some(now);
        }
        // A full socket is a lag, never a fault: B's queue is never held
        // for its control path (a retry or a reset).
        assert_ne!(
            outbound.routed_sender().unwrap().needs_control(0, 1),
            Some(true),
            "{errno:?}: B held for control at {now} ns"
        );
    }
    let skipped = outbound
        .routed_sender()
        .unwrap()
        .counters(1)
        .unwrap()
        .skipped;
    assert!(skipped > 0, "{errno:?}: B skipped what it could not take");
    let left_at = left_at.unwrap_or_else(|| panic!("{errno:?}: B left"));
    assert!(
        left_at <= 2 * policy().lag_limit,
        "{errno:?}: B left at {left_at} ns, past two windows"
    );
    let counters = outbound.path_counters(1).unwrap();
    assert_eq!(counters.exits, 1, "{errno:?}: {counters:?}");
    assert!(
        !outbound.needs_reset(),
        "{errno:?}: no reset for a full socket"
    );
    // B left: its copies are gone and it takes no more, so the drain
    // flushes A only.
    drain(
        &mut outbound,
        &mut halves,
        &[&observer_a, &observer_b],
        u64::from(FRAMES) * STEP,
    );
}

/// §8 Degraded path, `EAGAIN` (`WouldBlock`).
#[test]
fn a_blocked_path_leaves_and_costs_the_other_path_nothing() {
    a_refusing_path_leaves_and_costs_the_other_path_nothing(Errno::AGAIN);
}

/// §8 Degraded path, `ENOBUFS` (`NoBuffers`).
#[test]
fn a_path_out_of_buffers_leaves_and_costs_the_other_path_nothing() {
    a_refusing_path_leaves_and_costs_the_other_path_nothing(Errno::NOBUFS);
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

/// §8 Leaving: only that incarnation's items on that path are cancelled.
/// Two publications on the same endpoints both stage copies on B while B
/// blocks; the first leaves B. Once B drains, only the second's copies go
/// out on it: the first's were cancelled.
#[test]
fn another_publication_on_the_same_endpoint_keeps_sending() {
    static BOTH: [Alias; 2] = [ALIAS, OTHER_ALIAS];
    let (a, observer_a, _seen_a, _rx_a) = path_carrying(1, 0, &BOTH);
    let (b, observer_b, _seen_b, _rx_b) = path_carrying(2, 0, &BOTH);
    sent(&observer_a, 256);
    let mut halves = vec![a, b];
    let routes = [
        (EndpointId(1), SocketAddr::from(([127, 0, 0, 1], 41_000))),
        (EndpointId(2), SocketAddr::from(([127, 0, 0, 2], 41_000))),
    ];
    let (mut first, mut first_log) = routed(0);
    let (mut second, mut second_log) = outbound_routed(&routes, OTHER_ALIAS, TERM, 1, false);
    first.set_path_policy(policy());
    second.set_path_policy(policy());
    // B blocks: both publications stage their copies there.
    commit(&mut first_log, 0, 2);
    commit(&mut second_log, 0, 2);
    for now in 0..4 {
        let _ = first.serve_routes(&mut halves, BUDGET, None, now).unwrap();
        let _ = second.serve_routes(&mut halves, BUDGET, None, now).unwrap();
    }
    assert_eq!(first.routed_sender().unwrap().pending(0, 1), Some(2));
    assert_eq!(second.routed_sender().unwrap().pending(0, 1), Some(2));
    first.leave_before_serve(1);
    let _ = first.serve_routes(&mut halves, BUDGET, None, 10).unwrap();
    assert_eq!(first.path_state(1).map(|state| state.0), Some(false));
    assert_eq!(
        first.routed_sender().unwrap().pending(0, 1),
        Some(0),
        "the first publication's copies on B were cancelled"
    );
    assert_eq!(second.routed_sender().unwrap().pending(0, 1), Some(2));
    // B drains: only the second publication's two copies go out on it.
    sent(&observer_b, 64);
    let calls = observer_b.send_calls();
    for now in 11..20 {
        let _ = first.serve_routes(&mut halves, BUDGET, None, now).unwrap();
        let _ = second.serve_routes(&mut halves, BUDGET, None, now).unwrap();
    }
    assert_eq!(
        observer_b.send_calls() - calls,
        2,
        "the second publication's two copies, none of the first's"
    );
    assert_eq!(second.routed_sender().unwrap().pending(0, 1), Some(0));
    assert_eq!(second.path_state(1).map(|state| state.0), Some(true));
}

/// §8 Service: a frame selected while every path returns `WouldBlock`
/// debits nothing, and with both paths full nothing is skipped: selection
/// waits. Submitted on two paths, it debits once: A's submit debits it,
/// B's later copy is a catch-up copy (`late`) that debits nothing.
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
    let sender = outbound.routed_sender().unwrap();
    assert!(sender.pending(0, 0).unwrap() > 0);
    assert_eq!(sender.debited(0), None);
    for route in 0..2 {
        assert_eq!(
            sender.counters(route).unwrap().skipped,
            0,
            "route {route}: both full, nothing skipped"
        );
    }
    sent(&observer_a, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 10)
        .unwrap();
    assert_eq!(outbound.routed_sender().unwrap().debited(0), Some(0));
    sent(&observer_b, 1);
    let _ = outbound
        .serve_routes(&mut halves, BUDGET, None, 11)
        .unwrap();
    let sender = outbound.routed_sender().unwrap();
    assert_eq!(
        sender.counters(1).unwrap().late,
        1,
        "B's copy debits nothing"
    );
    assert_eq!(sender.debited(0), Some(0), "debited once");
    assert_eq!(sender.pending(0, 1), Some(0));
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
        // No seed passes trivially: something was sent, a path left and
        // one came back.
        assert!(high > 0, "seed {seed:#x}: nothing sent");
        let (exits, entries) = (0..2).fold((0, 0), |(exits, entries), route| {
            let counters = outbound.path_counters(route).unwrap();
            (
                u64::checked_add(exits, counters.exits).unwrap(),
                u64::checked_add(entries, counters.entries).unwrap(),
            )
        });
        assert!(
            exits >= 1 && entries >= 1,
            "seed {seed:#x}: {exits} exits, {entries} entries"
        );
        drain(
            &mut outbound,
            &mut halves,
            &[&observer_a, &observer_b],
            10_000,
        );
    }
}

/// rp-w7c, §8 Leaving: a path that flaps, leaving by lag and returning on
/// its open queue each time, never asks for an endpoint reset, and sends
/// again after each return.
#[test]
fn a_flapping_path_returns_with_no_reset() {
    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 64);
    sent(&observer_b, 64);
    let mut halves = vec![a, b];
    let (mut outbound, mut log) = routed(0);
    outbound.set_path_policy(return_policy());
    let mut now = 1000;
    for (flap, wait) in [10u64, 20, 40, 40].into_iter().enumerate() {
        outbound.leave_before_serve(1);
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
        assert_eq!(outbound.path_state(1).map(|state| state.0), Some(false));
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now + wait)
            .unwrap();
        assert_eq!(outbound.path_state(1).map(|state| state.0), Some(true));
        let calls = observer_b.send_calls();
        commit(&mut log, u8::try_from(flap).unwrap(), 1);
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now + wait + 1)
            .unwrap();
        assert!(
            observer_b.send_calls() > calls,
            "flap {flap}: B sends again"
        );
        assert!(!outbound.needs_reset(), "flap {flap}: no endpoint reset");
        now += wait + 2;
    }
    let counters = outbound.path_counters(1).unwrap();
    assert_eq!((counters.exits, counters.entries), (4, 4));
}

/// rp-w7c, §8 Leaving: a lagging path never fills `repair_jobs`. With room
/// for 4 jobs and B blocked for good, 12 NAKs in turn each make a job that
/// completes on A while B skips it: the table never fills.
#[test]
fn a_lagging_path_never_fills_repair_jobs() {
    use crate::agents::repair::{NakOutcome, RepairConfig};
    use crate::repair::jobs::JobsConfig;
    use crate::repair::scheduler::RepairBudget;

    let (a, observer_a, _seen_a) = path(1, 0);
    let (b, observer_b, _seen_b) = path(2, 0);
    sent(&observer_a, 64);
    sent(&observer_b, 1);
    let mut halves = vec![a, b];
    let routes = [
        (EndpointId(1), SocketAddr::from(([127, 0, 0, 1], 41_000))),
        (EndpointId(2), SocketAddr::from(([127, 0, 0, 2], 41_000))),
    ];
    let (mut outbound, mut log) = outbound_routed(&routes, ALIAS, TERM, 1, true);
    let config = RepairConfig {
        jobs: JobsConfig {
            repair_jobs: 4,
            ..JobsConfig::default()
        },
        ..RepairConfig::default()
    };
    outbound
        .enable_repair(&config, TERM.term_length, repair_identity())
        .unwrap();
    outbound.set_path_policy(super::super::PathPolicy::default());
    commit(&mut log, 0, 1);
    for now in 0..4 {
        let _ = outbound
            .serve_routes(&mut halves, BUDGET, None, now)
            .unwrap();
    }
    // Each NAK past the last job's linger: a new job each time.
    let linger = JobsConfig::default().repair_linger;
    for round in 0..12u64 {
        let now = 10 + round * 2 * linger;
        assert_eq!(
            outbound.nak_on(&first_nak(), MEMBER, (0, true), now),
            NakOutcome::Queued,
            "round {round}"
        );
        let mut budget = RepairBudget::default();
        assert_eq!(
            outbound.serve_repair_routes(&mut halves, &mut budget, now),
            1,
            "round {round}"
        );
    }
    let (_, jobs, _) = outbound.repair().unwrap().parts();
    let counts = jobs.counts();
    assert_eq!((counts.done, counts.full), (12, 0), "{counts:?}");
    assert_eq!(outbound.repair_route_counts(1).unwrap().skipped, 12);
    drain(
        &mut outbound,
        &mut halves,
        &[&observer_a, &observer_b],
        1_000_000_000,
    );
}

/// rp-w7c, §8 Absorption table: with the table full, a NAK's copy on the
/// other path is served as an ordinary NAK (it joins its job), not
/// absorbed and not dropped.
#[test]
fn a_full_absorption_table_serves_copies_as_naks() {
    use crate::agents::repair::NakOutcome;

    let (mut outbound, _log, _halves, _seen, _observer_b) = repair_rig();
    outbound.set_path_policy(super::super::PathPolicy {
        copy_entries: 1,
        ..super::super::PathPolicy::default()
    });
    let mut second = first_nak();
    second.receiver.receiver_id = 2;
    assert_eq!(
        outbound.nak_on(&first_nak(), MEMBER, (0, true), 10),
        NakOutcome::Queued
    );
    // The table's one entry holds the first NAK: the second is not
    // recorded.
    assert_eq!(
        outbound.nak_on(&second, MEMBER, (0, true), 11),
        NakOutcome::Queued
    );
    assert_eq!(outbound.repair().unwrap().absorb_counts().full, 1);
    assert!(outbound.absorbs(&first_nak(), 1, 12), "the recorded one is");
    assert!(
        !outbound.absorbs(&second, 1, 12),
        "the unrecorded one is not"
    );
    // Served as an ordinary NAK: it joins the pending job.
    assert_eq!(
        outbound.nak_on(&second, MEMBER, (1, true), 12),
        NakOutcome::Queued
    );
}
