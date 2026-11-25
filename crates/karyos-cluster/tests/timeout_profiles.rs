// SPDX-License-Identifier: Apache-2.0

//! The custom core's election-timeout defaults per deployment profile
//! (ADR-0039; ADR-0105, decision 5): chosen from simulated faults driven by
//! measured process pauses and network tails, documenting false elections
//! against recovery time.
//!
//! **The simulation.** Three cores (`karyos_cluster::consensus::Core`) over
//! a simulated network, in microseconds, with no client load and an empty
//! log but the leaders' no-ops. Each node's timer fires every tick plus a
//! pause drawn from the profile's measured pause tail: the pause delays the
//! node's heartbeats and election checks only; its message handling and
//! persistence are immediate. Each message arrives after half a round trip
//! drawn from the round-trip tail, independently per message and alike on
//! every link and in both directions (a symmetric, independent
//! approximation: a slow leg is not told from a slow return, and no
//! message is lost). A draw is piecewise linear over the measured median,
//! p99, p99.9 and maximum, the maximum its last bucket's endpoint.
//!
//! Each run waits for its first leader, then observes a fixed window of
//! [`WINDOW_US`] with no fault: a **leader change** is any node becoming
//! leader, or a leader stepping down, after the first; leaderless time is
//! summed. Then the leader crashes (messages it had in flight are dropped),
//! and the **recovery** is the time until a surviving node leads: an
//! election, not a committed operation.
//!
//! **The inputs** are the `karyos-bench timeouts` reports the profile's
//! record cites (quantstratum-docs: karyos/environments/election-timeouts.md),
//! each taken with its host's load: [`PROFILES`] carries, at each point
//! (median, p99, p99.9, maximum), the worst over the profile's hosts,
//! directions and payload sizes.
//!
//! **The rule.** A profile's default election timeout is twice the smallest
//! swept value whose runs show no leader change; every smaller swept value
//! must show some, so the floor is not an accident of a non-monotone sweep,
//! and the default is checked again on seeds the choice did not use. The
//! doubling is a heuristic margin for what a finite measurement cannot have
//! seen, not a bound. The heartbeat is a quarter of the default and the
//! timeout's range is `[min, 2 * min)`. [`the_defaults_follow_the_rule`]
//! checks the shipped defaults; `sweep` (ignored, on request) prints the
//! table the record publishes.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

use karyos_cluster::consensus::{
    Config, Core, Effects, LAN_DEDICATED, LAN_SHARED, LogTerms, Message, Role, SAME_HOST, TermVote,
    TimeoutProfile,
};

/// A measured tail, in microseconds.
#[derive(Debug, Clone, Copy)]
struct Tail {
    p50: u64,
    p99: u64,
    p999: u64,
    max: u64,
}

impl Tail {
    /// A draw from the tail: piecewise linear over the measured points.
    fn draw(&self, rng: &mut Rng) -> u64 {
        let u = rng.below(1_000_000);
        let (low, high, from, span) = match u {
            0..500_000 => (0, self.p50, 0, 500_000),
            500_000..990_000 => (self.p50, self.p99, 500_000, 490_000),
            990_000..999_000 => (self.p99, self.p999, 990_000, 9_000),
            _ => (self.p999, self.max, 999_000, 1_000),
        };
        // `span - 1`: the last draw of a bucket is its upper point, so the
        // measured maximum itself is drawn.
        low + (high.saturating_sub(low)) * (u - from) / (span - 1)
    }
}

/// The measured tails per profile, in microseconds: the record's tables
/// (karyos-bench timeouts, 2026-11-25), the worse host at each point.
const PROFILES: [(&TimeoutProfile, Tail, Tail); 3] = [
    // One host under build load (xaskar, load 10 to 94): its timer pauses,
    // and the round trip over loopback.
    (
        &SAME_HOST,
        Tail {
            p50: 59,
            p99: 132,
            p999: 805,
            max: 5_046,
        },
        Tail {
            p50: 35,
            p99: 142,
            p999: 496,
            max: 12_095,
        },
    ),
    // Dedicated, idle hosts on a direct bond (swarmer01 and swarmer02, load
    // under 1): pauses over both hosts, the round trip over both payload
    // sizes.
    (
        &LAN_DEDICATED,
        Tail {
            p50: 51,
            p99: 53,
            p999: 69,
            max: 1_343,
        },
        Tail {
            p50: 50,
            p99: 67,
            p999: 87,
            max: 2_234,
        },
    ),
    // Hosts shared with heavy build load on a switched LAN: pauses over
    // xaskar and flumix (load 9 to 100), the xaskar to flumix round trip
    // over both payload sizes.
    (
        &LAN_SHARED,
        Tail {
            p50: 59,
            p99: 428,
            p999: 2_885,
            max: 26_662,
        },
        Tail {
            p50: 204,
            p99: 2_749,
            p999: 4_878,
            max: 16_162,
        },
    ),
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A node's log: entry terms.
#[derive(Default)]
struct Log(Vec<u64>);

impl LogTerms for Log {
    fn last_index(&self) -> u64 {
        self.0.len() as u64
    }
    fn term(&self, index: u64) -> Option<u64> {
        if index == 0 {
            return Some(0);
        }
        self.0.get(usize::try_from(index - 1).ok()?).copied()
    }
    fn size(&self, index: u64) -> Option<u64> {
        self.term(index).filter(|_| index > 0).map(|_| 64)
    }
}

#[derive(Default)]
struct Sink {
    sends: Vec<(u64, Message)>,
    writes: Vec<(u64, u64)>,
    appends: Vec<(u64, u64)>,
}

impl Effects for Sink {
    fn persist(&mut self, _: TermVote) {}
    fn write(&mut self, index: u64, skip: u64) {
        self.writes.push((index, skip));
    }
    fn append(&mut self, index: u64, term: u64) {
        self.appends.push((index, term));
    }
    fn send(&mut self, to: u64, message: Message) {
        self.sends.push((to, message));
    }
    fn send_after_persist(&mut self, to: u64, message: Message) {
        self.sends.push((to, message));
    }
    fn commit(&mut self, _: u64) {}
    fn send_snapshot(&mut self, _: u64) {}
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Event {
    Tick(u64),
    Deliver { from: u64, to: u64, at: u64 },
}

/// What one run gave.
#[derive(Debug, Default)]
struct Run {
    /// Leader changes in the window: a node becoming leader, or a leader
    /// stepping down, after the first leader.
    changes: u64,
    /// Time in the window with no leader.
    leaderless_us: u64,
    /// Whether the window ended with a leader to crash.
    crashed: bool,
    /// The time from the crash until a surviving node led.
    recovery_us: Option<u64>,
}

/// The window observed after the first leader, with no fault.
const WINDOW_US: u64 = 60_000_000;

/// One run of `profile`'s timeouts at `pause` and `rtt` tails: its first
/// leader, [`WINDOW_US`] with no fault, then the leader's crash.
fn run(profile: &TimeoutProfile, (pause, rtt): (Tail, Tail), seed: u64) -> Run {
    let ids = [1u64, 2, 3];
    let mut rng = Rng(seed);
    let mut cores: BTreeMap<u64, Core> = BTreeMap::new();
    let mut logs: BTreeMap<u64, Log> = BTreeMap::new();
    for &id in &ids {
        let config = Config::new(
            id,
            &ids,
            profile.election_min,
            profile.election_max,
            profile.heartbeat,
            16,
            seed,
        )
        .unwrap();
        cores.insert(id, Core::new(config, TermVote::default(), 0));
        logs.insert(id, Log::default());
    }
    let mut queue: BinaryHeap<Reverse<(u64, u64, Event)>> = BinaryHeap::new();
    let mut messages: BTreeMap<u64, (Message, Vec<u64>)> = BTreeMap::new();
    let mut serial = 0u64;
    for &id in &ids {
        queue.push(Reverse((
            rng.below(profile.tick_us),
            serial,
            Event::Tick(id),
        )));
        serial += 1;
    }
    let mut result = Run::default();
    // The first leader's time, once there is one: the window starts there.
    let mut first: Option<u64> = None;
    let mut leaderless_since: Option<u64> = None;
    let mut crashed: Option<(u64, u64)> = None;
    let bootstrap_end = 60_000_000;
    while let Some(Reverse((now, _, event))) = queue.pop() {
        if result.recovery_us.is_some() {
            break;
        }
        if first.is_none() && now > bootstrap_end {
            // No first leader at all: nothing to observe.
            break;
        }
        if let Some(start) = first
            && crashed.is_none()
            && now >= start + WINDOW_US
        {
            if let Some(since) = leaderless_since.take() {
                result.leaderless_us += start + WINDOW_US - since;
            }
            // The window ends: the leader crashes, if there is one.
            match cores.iter().find(|(_, core)| core.role() == Role::Leader) {
                Some((&leader, _)) => {
                    crashed = Some((leader, now));
                    result.crashed = true;
                }
                None => break,
            }
        }
        if crashed.is_some_and(|(_, at)| now > at + 60_000_000) {
            break;
        }
        let down = crashed.map(|(id, _)| id);
        let (id, before, sink, incoming) = match event {
            Event::Tick(id) => {
                let next = now + profile.tick_us + pause.draw(&mut rng);
                queue.push(Reverse((next, serial, Event::Tick(id))));
                serial += 1;
                if Some(id) == down {
                    continue;
                }
                let before = cores[&id].role();
                let mut sink = Sink::default();
                cores.get_mut(&id).unwrap().tick(&logs[&id], &mut sink);
                (id, before, sink, Vec::new())
            }
            Event::Deliver { from, to, at } => {
                let (message, terms) = messages.remove(&at).unwrap();
                if Some(to) == down || Some(from) == down {
                    continue;
                }
                let before = cores[&to].role();
                let mut sink = Sink::default();
                let _ = cores
                    .get_mut(&to)
                    .unwrap()
                    .step(from, message, &terms, &logs[&to], &mut sink);
                (to, before, sink, terms)
            }
        };
        let log = logs.get_mut(&id).unwrap();
        for (index, skip) in &sink.writes {
            log.0.truncate(usize::try_from(index - 1).unwrap());
            log.0
                .extend(incoming.iter().skip(usize::try_from(*skip).unwrap()));
        }
        for (_, term) in &sink.appends {
            log.0.push(*term);
        }
        if !sink.appends.is_empty() {
            let mut more = Sink::default();
            let last = log.last_index();
            let core = cores.get_mut(&id).unwrap();
            core.persisted(last, &logs[&id], &mut more);
            core.replicate(&logs[&id], &mut more);
            for send in more.sends {
                schedule(
                    send,
                    id,
                    now,
                    &logs,
                    (&rtt, &mut rng),
                    (&mut queue, &mut messages, &mut serial),
                );
            }
        }
        for send in sink.sends {
            schedule(
                send,
                id,
                now,
                &logs,
                (&rtt, &mut rng),
                (&mut queue, &mut messages, &mut serial),
            );
        }
        let after = cores[&id].role();
        let became = after == Role::Leader && before != Role::Leader;
        let left = before == Role::Leader && after != Role::Leader;
        if let Some((_, at)) = crashed {
            if became {
                result.recovery_us = Some(now - at);
            }
        } else if first.is_none() {
            if became {
                first = Some(now);
            }
        } else if became || left {
            result.changes += 1;
            let leading = cores.values().any(|core| core.role() == Role::Leader);
            match (leading, leaderless_since) {
                (false, None) => leaderless_since = Some(now),
                (true, Some(since)) => {
                    result.leaderless_us += now - since;
                    leaderless_since = None;
                }
                _ => {}
            }
        }
    }
    result
}

type Queue = BinaryHeap<Reverse<(u64, u64, Event)>>;

/// Messages in flight, by their serial.
type InFlight = BTreeMap<u64, (Message, Vec<u64>)>;

fn schedule(
    (to, message): (u64, Message),
    from: u64,
    now: u64,
    logs: &BTreeMap<u64, Log>,
    (rtt, rng): (&Tail, &mut Rng),
    (queue, messages, serial): (&mut Queue, &mut InFlight, &mut u64),
) {
    let terms = match message {
        Message::Append {
            prev_index,
            entries,
            ..
        } => (prev_index + 1..=prev_index + entries)
            .map(|index| logs[&from].term(index).unwrap_or(0))
            .collect(),
        _ => Vec::new(),
    };
    let at = now + 1 + rtt.draw(rng) / 2;
    let key = *serial;
    *serial += 1;
    messages.insert(key, (message, terms));
    queue.push(Reverse((at, key, Event::Deliver { from, to, at: key })));
}

/// The sweep's runs per candidate.
const RUNS: u64 = 40;

/// The seeds a choice is made on, and the hold-out ones it is checked on.
const CHOICE: std::ops::RangeInclusive<u64> = 1..=RUNS;
const HOLD_OUT: std::ops::RangeInclusive<u64> = 1_001..=1_000 + RUNS;

/// What a candidate gave over its runs.
#[derive(Debug, Default)]
struct Summary {
    changes: u64,
    leaderless_us: u64,
    crashes: u64,
    recoveries: u64,
    recovery_median_us: u64,
    recovery_worst_us: u64,
}

/// A candidate over `seeds`.
fn evaluate(
    profile: &TimeoutProfile,
    tails: (Tail, Tail),
    seeds: std::ops::RangeInclusive<u64>,
) -> Summary {
    let mut summary = Summary::default();
    let mut recoveries = Vec::new();
    for seed in seeds {
        let run = run(profile, tails, seed);
        summary.changes += run.changes;
        summary.leaderless_us += run.leaderless_us;
        summary.crashes += u64::from(run.crashed);
        recoveries.extend(run.recovery_us);
    }
    recoveries.sort_unstable();
    summary.recoveries = recoveries.len() as u64;
    summary.recovery_median_us = recoveries.get(recoveries.len() / 2).copied().unwrap_or(0);
    summary.recovery_worst_us = recoveries.last().copied().unwrap_or(0);
    summary
}

/// A candidate of `profile`'s tick: `[min, 2 * min)` and a quarter of it
/// as heartbeat.
fn candidate(profile: &TimeoutProfile, min: u32) -> TimeoutProfile {
    TimeoutProfile {
        election_min: min,
        election_max: min * 2,
        heartbeat: (min / 4).max(1),
        ..*profile
    }
}

/// The swept values, in ticks.
const SWEEP: [u32; 9] = [4, 6, 8, 12, 16, 24, 32, 48, 64];

/// The smallest swept value with no leader change on the choice seeds,
/// doubled.
///
/// # Panics
///
/// When no swept value qualifies: the profile has no measured default.
fn rule(profile: &TimeoutProfile, tails: (Tail, Tail)) -> u32 {
    let floor = SWEEP
        .iter()
        .copied()
        .find(|&min| evaluate(&candidate(profile, min), tails, CHOICE).changes == 0)
        .unwrap_or_else(|| panic!("{}: no swept value is free of leader changes", profile.name));
    floor * 2
}

/// The shipped defaults follow the rule: each is twice a swept floor with
/// no leader change, every smaller swept value has some, and the default
/// itself has none on the choice seeds and on the hold-out ones, with a
/// crash and a recovery in every run.
#[test]
fn the_defaults_follow_the_rule() {
    for (profile, pause, rtt) in PROFILES {
        let floor = profile.election_min / 2;
        assert_eq!(
            (
                profile.election_min,
                profile.election_max,
                profile.heartbeat
            ),
            (floor * 2, floor * 4, (floor / 2).max(1)),
            "{}: not the rule's shape",
            profile.name
        );
        let at = SWEEP
            .iter()
            .position(|&min| min == floor)
            .unwrap_or_else(|| panic!("{}: floor {floor} is not swept", profile.name));
        assert_eq!(
            evaluate(&candidate(profile, floor), (pause, rtt), CHOICE).changes,
            0,
            "{}: leader changes at the floor",
            profile.name
        );
        for &below in SWEEP.get(..at).unwrap_or(&[]) {
            assert!(
                evaluate(&candidate(profile, below), (pause, rtt), CHOICE).changes > 0,
                "{}: no leader change below the floor, at {below}",
                profile.name
            );
        }
        for seeds in [CHOICE, HOLD_OUT] {
            let summary = evaluate(profile, (pause, rtt), seeds.clone());
            assert_eq!(summary.changes, 0, "{} {seeds:?}", profile.name);
            assert_eq!(
                (summary.crashes, summary.recoveries),
                (RUNS, RUNS),
                "{} {seeds:?}: a run without its crash or its recovery",
                profile.name
            );
        }
    }
}

#[test]
#[ignore = "the sweep's table, for the record; run on request"]
fn sweep() {
    for (profile, pause, rtt) in PROFILES {
        println!("{} (tick {} us):", profile.name, profile.tick_us);
        println!(
            "  min ticks | leader changes / leaderless ms over {RUNS} runs | crashes / recoveries | recovery median / worst ms"
        );
        for min in SWEEP {
            let summary = evaluate(&candidate(profile, min), (pause, rtt), CHOICE);
            println!(
                "  {min:>9} | {:>14} / {:>13.1} | {:>7} / {:>10} | {:>6.1} / {:>6.1}",
                summary.changes,
                summary.leaderless_us as f64 / 1000.0,
                summary.crashes,
                summary.recoveries,
                summary.recovery_median_us as f64 / 1000.0,
                summary.recovery_worst_us as f64 / 1000.0
            );
        }
        println!("  rule: {}", rule(profile, (pause, rtt)));
        let held = evaluate(profile, (pause, rtt), HOLD_OUT);
        println!(
            "  default {}: hold-out leader changes {}, recovery median / worst {:.1} / {:.1} ms",
            profile.election_min,
            held.changes,
            held.recovery_median_us as f64 / 1000.0,
            held.recovery_worst_us as f64 / 1000.0
        );
    }
}
