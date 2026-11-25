// SPDX-License-Identifier: Apache-2.0

//! The custom core's election-timeout defaults per deployment profile
//! (ADR-0039; ADR-0105, decision 5): chosen from simulated faults driven by
//! measured process pauses and network tails, documenting false elections
//! against recovery time.
//!
//! **The simulation.** Three cores (`karyos_cluster::consensus::Core`) over
//! a simulated network, in microseconds. Each node's timer fires every
//! tick plus a pause drawn from the profile's measured pause tail; each
//! message arrives after half a round trip drawn from its measured
//! round-trip tail. A draw is piecewise over the measured median, p99,
//! p99.9 and maximum, so the worst observed sample is in the model. With no
//! fault, any election after the first is a **false election**: a leader
//! lost to timing alone. Then the leader crashes, and the time until a
//! surviving node leads is the **recovery**.
//!
//! **The inputs** are the `karyos-bench timeouts` reports the profile's
//! record cites (quantstratum-docs: karyos/environments/election-timeouts.md),
//! each taken with its host's load: [`PROFILES`] carries them.
//!
//! **The rule.** A profile's default election timeout is the smallest swept
//! value with no false election over the sweep's runs at its measured
//! tails, doubled for what a finite measurement cannot have seen; the
//! heartbeat is a quarter of it, and the timeout's range is
//! `[min, 2 * min)`. [`the_defaults_follow_the_rule`] checks the shipped
//! defaults against the rule; `sweep` (ignored, on request) prints the
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
        low + (high.saturating_sub(low)) * (u - from) / span
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
    // under 1): the worse host's pauses, the round trip at 1,200 bytes.
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
    // Hosts shared with heavy build load on a switched LAN (flumix's pauses
    // at load 18 to 100, the xaskar to flumix round trip at 1,200 bytes).
    (
        &LAN_SHARED,
        Tail {
            p50: 56,
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

/// What one run gave: elections after the first with no fault, and the
/// recovery after the leader's crash, in microseconds.
struct Run {
    false_elections: u64,
    recovery_us: Option<u64>,
}

/// One run of `profile`'s timeouts at `pause` and `rtt` tails: `steady_us`
/// of no fault, then the leader crashes.
fn run(profile: &TimeoutProfile, (pause, rtt): (Tail, Tail), seed: u64, steady_us: u64) -> Run {
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
    let mut leaders_seen = 0u64;
    let mut crashed: Option<(u64, u64)> = None;
    let mut recovery_us = None;
    let end = steady_us + 60_000_000;
    while let Some(Reverse((now, _, event))) = queue.pop() {
        if now > end || recovery_us.is_some() {
            break;
        }
        if crashed.is_none() && now >= steady_us {
            // The leader crashes: the run measures how long until another
            // node leads.
            if let Some((&leader, _)) = cores.iter().find(|(_, core)| core.role() == Role::Leader) {
                crashed = Some((leader, now));
            }
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
        if after == Role::Leader && before != Role::Leader {
            leaders_seen += 1;
            if let Some((_, at)) = crashed {
                recovery_us = Some(now - at);
            }
        }
    }
    Run {
        false_elections: leaders_seen
            .saturating_sub(1)
            .saturating_sub(u64::from(recovery_us.is_some())),
        recovery_us,
    }
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

/// The sweep's runs per candidate, and the steady time of each.
const RUNS: u64 = 40;
const STEADY_US: u64 = 60_000_000;

/// False elections and the recovery's p99 over the sweep's runs.
fn evaluate(profile: &TimeoutProfile, tails: (Tail, Tail), runs: u64) -> (u64, u64) {
    let mut false_elections = 0;
    let mut recoveries = Vec::new();
    for seed in 1..=runs {
        let run = run(profile, tails, seed, STEADY_US);
        false_elections += run.false_elections;
        recoveries.extend(run.recovery_us);
    }
    recoveries.sort_unstable();
    let p99 = recoveries
        .get(recoveries.len().saturating_mul(99) / 100)
        .copied()
        .unwrap_or(u64::MAX);
    (false_elections, p99)
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

/// The smallest swept value with no false election, doubled.
fn rule(profile: &TimeoutProfile, tails: (Tail, Tail)) -> u32 {
    let floor = SWEEP
        .iter()
        .copied()
        .find(|&min| evaluate(&candidate(profile, min), tails, RUNS).0 == 0)
        .unwrap_or(*SWEEP.last().unwrap());
    floor * 2
}

/// The shipped defaults follow the rule, checked without the whole sweep:
/// each default is twice a swept floor with no false election, the swept
/// value below the floor has some (unless the floor is the sweep's
/// smallest), and the default itself has none and recovers.
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
        let at = SWEEP.iter().position(|&min| min == floor);
        let at = at.unwrap_or_else(|| panic!("{}: floor {floor} is not swept", profile.name));
        assert_eq!(
            evaluate(&candidate(profile, floor), (pause, rtt), RUNS).0,
            0,
            "{}: false elections at the floor",
            profile.name
        );
        if let Some(&below) = at.checked_sub(1).and_then(|at| SWEEP.get(at)) {
            assert!(
                evaluate(&candidate(profile, below), (pause, rtt), RUNS).0 > 0,
                "{}: no false election below the floor, at {below}",
                profile.name
            );
        }
        let (false_elections, p99) = evaluate(profile, (pause, rtt), RUNS);
        assert_eq!(false_elections, 0, "{}", profile.name);
        assert!(p99 < u64::MAX, "{}: no recovery", profile.name);
    }
}

#[test]
#[ignore = "the sweep's table, for the record; run on request"]
fn sweep() {
    for (profile, pause, rtt) in PROFILES {
        println!("{} (tick {} us):", profile.name, profile.tick_us);
        println!("  min ticks | false elections over {RUNS} runs | recovery p99 ms");
        for min in SWEEP {
            let (false_elections, p99) = evaluate(&candidate(profile, min), (pause, rtt), RUNS);
            println!(
                "  {min:>9} | {false_elections:>31} | {:>15.1}",
                p99 as f64 / 1000.0
            );
        }
        println!("  rule: {}", rule(profile, (pause, rtt)));
    }
}
