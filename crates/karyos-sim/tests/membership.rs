// SPDX-License-Identifier: Apache-2.0

//! Multicast receiver membership on virtual time (`quantstratum-docs:
//! karyos/design/multicast-flow-control.md`; P2.7 C preparation, ACS
//! 15661).
//!
//! The scenarios drive [`Membership`] directly, standing in for the sender
//! agent: each step the sender raises each lane's `sent_high` within the
//! table's limit, the scripted receivers consume and send their SMs (some
//! lost, some copied over a second path), and the table's timers run. The
//! harness is the one phase 6's wiring will reuse; until then the SM path
//! is the table's own API.
//!
//! - `membership-required-loss`: a required receiver stops at a random
//!   step. Admission must stay open until exactly `receiver_timeout` after
//!   its last delivered SM, then stop for good with every lane held, its
//!   last consumption kept as the retention bound, and nothing sent after.
//! - `membership-optional-pause`: an optional receiver pauses past
//!   `pause_timeout` while still sending SMs, then resumes. It must not
//!   rejoin on its stationary SMs (the tombstone, ACS 15647), the sender
//!   must move past its edge, and it must rejoin once it advances.
//! - `membership-two-paths`: receivers send SM copies over a second path
//!   in either order, and that path's binding comes and goes. A shadow
//!   table fed only the first path must agree on the limit of every lane,
//!   admission, connection and retention at every step (MC-9).
//!
//! On every step, for every required member, `sent_high` stays within its
//! last delivered consumption plus its window. A failure prints its seed
//! and trace.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints); the lane
// arrays are indexed by lane below LANES.
#![allow(clippy::panic, clippy::indexing_slicing)]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use karyos_driver::agents::EndpointId;
use karyos_driver::membership::{
    Admission, Limit, MemberEvent, Membership, MembershipConfig, Roles, SmKey, StatusOutcome,
};
use karyos_protocol::network::{Alias, Identity, LaneStatus, Lanes, Receiver, StatusMessage};
use karyos_sys::frame::Lane;

use karyos_sim::{Failure, Rng, scenarios};

/// Lanes of the publication.
const LANES: usize = 2;
/// One step of virtual time: the SM interval.
const STEP: u64 = 10_000_000;
/// The table's timeouts, short so a run covers several of them.
const RECEIVER_TIMEOUT: u64 = 20 * STEP;
const PAUSE_TIMEOUT: u64 = 100 * STEP;
/// The receivers' window.
const WINDOW: u32 = 8192;
/// Steps kept in a failure's trace.
const TRACE: usize = 32;

/// A membership scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    RequiredLoss,
    OptionalPause,
    TwoPaths,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MembershipScenario {
    name: &'static str,
    kind: Kind,
    steps: u64,
}

fn membership_scenarios() -> Vec<MembershipScenario> {
    vec![
        MembershipScenario {
            name: "membership-required-loss",
            kind: Kind::RequiredLoss,
            steps: 1500,
        },
        MembershipScenario {
            name: "membership-optional-pause",
            kind: Kind::OptionalPause,
            steps: 1500,
        },
        MembershipScenario {
            name: "membership-two-paths",
            kind: Kind::TwoPaths,
            steps: 1500,
        },
    ]
}

/// What a run did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct MembershipReport {
    /// Bytes sent over the lanes.
    sent: u64,
    /// SMs accepted by the table.
    accepted: u64,
    /// Whether a required loss stopped admission.
    lost: bool,
    /// Rejoins of the paused receiver after its tombstone.
    rejoined: u64,
    /// Second-path bindings removed.
    unbound: u64,
    /// A digest of every step: equal for equal seeds.
    digest: u64,
}

/// A receiver's script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Running,
    Paused,
    Dead,
}

#[derive(Debug, Clone, Copy)]
struct Scripted {
    id: u64,
    required: bool,
    two_paths: bool,
    script: Script,
    consumption: [u64; LANES],
    /// The consumption of its last SM the table accepted.
    delivered: Option<[u64; LANES]>,
    /// When the table last accepted an SM of it.
    last_delivered: u64,
    /// When the table last accepted a fresh SM of it: one that advanced a
    /// lane, or was caught up on every lane.
    last_fresh: u64,
}

struct Run {
    scenario: &'static str,
    seed: u64,
    step: u64,
    trace: VecDeque<String>,
    digest: u64,
}

impl Run {
    fn fail(&self, reason: impl Into<String>) -> Failure {
        Failure {
            scenario: self.scenario,
            seed: self.seed,
            step: self.step,
            reason: reason.into(),
            trace: self.trace.iter().cloned().collect(),
        }
    }

    fn note(&mut self, event: String) {
        if self.trace.len() == TRACE {
            self.trace.pop_front();
        }
        self.trace.push_back(format!("{}: {event}", self.step));
    }

    fn mix(&mut self, value: u64) {
        self.digest = (self.digest ^ value)
            .wrapping_mul(0x0100_0000_01b3)
            .rotate_left(7);
    }
}

fn identity() -> Identity {
    Identity {
        driver_id: [3, 4],
        registration_id: 1,
        incarnation: 1,
    }
}

fn alias() -> Alias {
    Alias {
        session_id: 9,
        stream_id: 10,
    }
}

fn receiver(id: u64) -> Receiver {
    Receiver {
        receiver_boot_id: [id, 77],
        receiver_id: id,
    }
}

/// The binding of receiver `id` over `path` (1 or 2).
fn key(id: u64, path: u32) -> SmKey {
    let host = u8::try_from(id).unwrap_or(u8::MAX);
    let net = u8::try_from(path).unwrap_or(u8::MAX);
    SmKey {
        endpoint: EndpointId(path),
        alias: alias(),
        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, net, host)), 4000),
        identity: identity(),
        receiver: receiver(id),
    }
}

fn lane(at: usize) -> Lane {
    Lane::try_new(u8::try_from(at).unwrap_or(0)).unwrap_or(Lane::ZERO)
}

fn sm(id: u64, consumption: [u64; LANES]) -> Result<StatusMessage, String> {
    let lanes: Vec<LaneStatus> = consumption
        .iter()
        .map(|&consumption| LaneStatus {
            consumption,
            window: WINDOW,
        })
        .collect();
    Ok(StatusMessage {
        alias: alias(),
        identity: identity(),
        receiver: receiver(id),
        group_tag: 0,
        lanes: Lanes::new(&lanes).map_err(|error| format!("lanes: {error:?}"))?,
    })
}

fn new_table(required: &[u64]) -> Result<Membership, String> {
    let config = MembershipConfig {
        max_receivers: 8,
        max_pending: 4,
        max_paths: 2,
        sm_interval: STEP,
        receiver_timeout: RECEIVER_TIMEOUT,
        pause_timeout: PAUSE_TIMEOUT,
        join_timeout: RECEIVER_TIMEOUT,
        ..MembershipConfig::new(2, 1024, 1 << 20)
    };
    Membership::new(
        config,
        identity(),
        alias(),
        &Roles {
            required,
            tags: &[],
        },
        0,
    )
    .map_err(|error| format!("membership: {error:?}"))
}

fn receivers(kind: Kind) -> Vec<Scripted> {
    let scripted = |id, required, two_paths| Scripted {
        id,
        required,
        two_paths,
        script: Script::Running,
        consumption: [0; LANES],
        delivered: None,
        last_delivered: 0,
        last_fresh: 0,
    };
    match kind {
        Kind::RequiredLoss => vec![
            scripted(1, true, false),
            scripted(2, true, false),
            scripted(3, false, false),
        ],
        Kind::OptionalPause => vec![
            scripted(1, true, false),
            scripted(2, false, false),
            scripted(3, false, false),
        ],
        Kind::TwoPaths => vec![
            scripted(1, true, true),
            scripted(2, false, true),
            scripted(3, false, false),
        ],
    }
}

/// The whole observable state of a table at `now`, for the shadow check
/// and the digest.
fn observe(table: &Membership, now: u64) -> (Vec<Limit>, Admission, bool, Vec<Option<u64>>) {
    (
        (0..LANES).map(|at| table.limit(lane(at), now)).collect(),
        table.admission(now),
        table.connected(now),
        (0..LANES).map(|at| table.retention(lane(at))).collect(),
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "one scenario loop, its steps in order, as in tests/timed.rs"
)]
fn run_membership(scenario: &MembershipScenario, seed: u64) -> Result<MembershipReport, Failure> {
    let mut run = Run {
        scenario: scenario.name,
        seed,
        step: 0,
        trace: VecDeque::new(),
        digest: 0xcbf2_9ce4_8422_2325,
    };
    let mut rng = Rng::new(seed);
    let mut scripted = receivers(scenario.kind);
    let required: Vec<u64> = scripted
        .iter()
        .filter(|r| r.required)
        .map(|r| r.id)
        .collect();
    let mut table = new_table(&required).map_err(|reason| run.fail(reason))?;
    let mut shadow = new_table(&required).map_err(|reason| run.fail(reason))?;
    let mut sent = [0u64; LANES];
    let mut report = MembershipReport::default();

    // The scripted events.
    let death = rng.between(200, 800);
    let pause_start = rng.between(100, 300);
    let pause_end = pause_start + rng.between(150, 300);
    let mut lost_at: Option<u64> = None;
    let mut paused_expired = false;
    let mut pause_joins = 0u64;

    for step in 0..scenario.steps {
        run.step = step;
        let now = step * STEP;
        // 1. Scripts.
        for r in &mut scripted {
            match scenario.kind {
                Kind::RequiredLoss if r.id == 2 && step == death => {
                    r.script = Script::Dead;
                    run.note(format!("receiver 2 dies; last SM at {}", r.last_delivered));
                }
                Kind::OptionalPause if r.id == 2 && step == pause_start => {
                    r.script = Script::Paused;
                    run.note("receiver 2 pauses".into());
                }
                Kind::OptionalPause if r.id == 2 && step == pause_end => {
                    r.script = Script::Running;
                    run.note("receiver 2 resumes".into());
                }
                _ => {}
            }
        }
        // 2. The sender, within the limit while admission is open.
        let admission = table.admission(now);
        for (at, high) in sent.iter_mut().enumerate() {
            let limit = table.limit(lane(at), now);
            let Limit::Edge(edge) = limit else {
                continue;
            };
            if admission != Admission::Open || edge <= *high {
                continue;
            }
            let next = edge.min(*high + rng.between(0, 3000));
            report.sent += next - *high;
            *high = next;
            if !table.advance_sent(lane(at), next) || !shadow.advance_sent(lane(at), next) {
                return Err(run.fail("sent_high refused"));
            }
        }
        // 3. Receivers consume and send their SMs.
        for r in &mut scripted {
            if r.script == Script::Running {
                for (at, consumption) in r.consumption.iter_mut().enumerate() {
                    let budget = rng.between(0, 4000);
                    *consumption = sent[at].min(*consumption + budget);
                }
            }
            if r.script == Script::Dead {
                continue;
            }
            let message = sm(r.id, r.consumption).map_err(|reason| run.fail(reason))?;
            // The first path loses one SM in ten, except where the shadow
            // must see every first-path SM.
            let first = scenario.kind == Kind::TwoPaths || rng.chance(9, 10);
            let second = r.two_paths && rng.chance(1, 2);
            let second_first = second && rng.chance(1, 2);
            let mut deliveries = Vec::new();
            if second_first {
                deliveries.push(2);
            }
            if first {
                deliveries.push(1);
            }
            if second && !second_first {
                deliveries.push(2);
            }
            for path in deliveries {
                let outcome = table.status(&key(r.id, path), &message, now);
                if let StatusOutcome::Accepted { joined, fresh, .. } = outcome {
                    report.accepted += 1;
                    let advanced = r
                        .delivered
                        .is_none_or(|last| last.iter().zip(r.consumption).any(|(a, b)| b > *a));
                    let caught_up = r.consumption == sent;
                    if fresh != (joined || advanced || caught_up) {
                        return Err(run.fail(format!("receiver {} fresh {fresh}", r.id)));
                    }
                    if fresh {
                        r.last_fresh = now;
                    }
                    r.delivered = Some(r.consumption);
                    r.last_delivered = now;
                    if joined
                        && scenario.kind == Kind::OptionalPause
                        && r.id == 2
                        && step > pause_start
                    {
                        pause_joins += 1;
                    }
                }
                if path == 1 {
                    let _ = shadow.status(&key(r.id, 1), &message, now);
                }
                run.mix(r.id ^ (u64::from(path) << 8));
            }
        }
        // 4. The second path's binding goes now and then.
        if scenario.kind == Kind::TwoPaths && rng.chance(1, 50) {
            let id = if rng.chance(1, 2) { 1 } else { 2 };
            let _ = table.binding_gone(&key(id, 2), now);
            report.unbound += 1;
            run.note(format!("path 2 of receiver {id} gone"));
        }
        // 5. Timers.
        table.timers(now, 16);
        shadow.timers(now, 16);
        table.drain_events(|event| {
            if let MemberEvent::LostRequired { .. } = event {
                report.lost = true;
            }
        });
        shadow.drain_events(|_| {});

        // Oracles.
        let observed = observe(&table, now);
        for value in observed.0.iter().map(|limit| match limit {
            Limit::Edge(edge) => *edge,
            Limit::NoReceiverWindow => u64::MAX,
            Limit::Held => u64::MAX - 1,
        }) {
            run.mix(value);
        }
        // Every required member bounds what was sent.
        for r in scripted.iter().filter(|r| r.required) {
            let Some(delivered) = r.delivered else {
                continue;
            };
            for at in 0..LANES {
                if sent[at] > delivered[at] + u64::from(WINDOW) {
                    return Err(run.fail(format!(
                        "lane {at}: sent {} beyond required {}'s edge {}",
                        sent[at],
                        r.id,
                        delivered[at] + u64::from(WINDOW)
                    )));
                }
            }
        }
        match scenario.kind {
            Kind::RequiredLoss => {
                let dead = scripted
                    .iter()
                    .find(|r| r.id == 2 && r.script == Script::Dead);
                let deadline = dead.map(|r| r.last_delivered + RECEIVER_TIMEOUT);
                let expired = deadline.is_some_and(|deadline| now >= deadline);
                if expired {
                    lost_at.get_or_insert(step);
                    if observed.1 != Admission::LostRequired {
                        return Err(run.fail(format!("admission {:?} after the loss", observed.1)));
                    }
                    if observed.0.iter().any(|limit| *limit != Limit::Held) {
                        return Err(run.fail("a lane not held after the loss"));
                    }
                    let kept = dead.and_then(|r| r.delivered);
                    for at in 0..LANES {
                        let least = scripted
                            .iter()
                            .filter(|r| r.required)
                            .filter_map(|r| r.delivered.map(|d| d[at]))
                            .min();
                        if observed.3[at] != least || kept.is_none() {
                            return Err(run.fail(format!(
                                "lane {at}: retention {:?}, the required minimum {least:?}",
                                observed.3[at]
                            )));
                        }
                    }
                } else if observed.1 == Admission::LostRequired {
                    return Err(run.fail("admission stopped before the deadline"));
                }
            }
            Kind::OptionalPause => {
                let paused = scripted
                    .iter()
                    .find(|r| r.id == 2)
                    .filter(|r| r.script == Script::Paused);
                if let Some(r) = paused {
                    // One step after pause_timeout from its last fresh SM.
                    if now >= r.last_fresh + PAUSE_TIMEOUT + STEP {
                        paused_expired = true;
                        if pause_joins > 0 {
                            return Err(run.fail("the paused receiver rejoined on stationary SMs"));
                        }
                        let edge = r.consumption[0] + u64::from(WINDOW);
                        if now >= pause_end * STEP - STEP && sent[0] <= edge {
                            return Err(run.fail(format!(
                                "the sender stayed at {} behind the paused edge {edge}",
                                sent[0]
                            )));
                        }
                    }
                }
            }
            Kind::TwoPaths => {
                let expected = observe(&shadow, now);
                if observed != expected {
                    return Err(run.fail(format!("two paths {observed:?}, one path {expected:?}")));
                }
            }
        }
    }
    if scenario.kind == Kind::OptionalPause {
        if !paused_expired {
            return Err(run.fail("the pause never outlived pause_timeout"));
        }
        if pause_joins == 0 {
            return Err(run.fail("the resumed receiver never rejoined"));
        }
        report.rejoined = pause_joins;
    }
    if scenario.kind == Kind::RequiredLoss && lost_at.is_some() != report.lost {
        return Err(run.fail("the loss event disagrees with the oracle"));
    }
    report.digest = run.digest;
    Ok(report)
}

fn sweep(name: &str) -> Vec<MembershipReport> {
    let scenario = membership_scenarios()
        .into_iter()
        .find(|scenario| scenario.name == name)
        .unwrap_or_else(|| panic!("no scenario {name}"));
    scenarios::seeds()
        .into_iter()
        .map(|seed| run_membership(&scenario, seed).unwrap_or_else(|failure| panic!("{failure}")))
        .collect()
}

#[test]
fn membership_required_loss() {
    let reports = sweep("membership-required-loss");
    if reports.len() == 1 {
        return;
    }
    assert!(reports.iter().all(|report| report.lost));
    assert!(reports.iter().map(|report| report.sent).sum::<u64>() > 0);
}

#[test]
fn membership_optional_pause() {
    let reports = sweep("membership-optional-pause");
    assert!(reports.iter().all(|report| report.rejoined > 0));
}

#[test]
fn membership_two_paths() {
    let reports = sweep("membership-two-paths");
    if reports.len() == 1 {
        return;
    }
    assert!(reports.iter().map(|report| report.unbound).sum::<u64>() > 0);
    assert!(reports.iter().map(|report| report.accepted).sum::<u64>() > 0);
}

#[test]
fn a_membership_seed_reproduces_its_run() {
    for scenario in membership_scenarios() {
        let first = run_membership(&scenario, 7).unwrap_or_else(|failure| panic!("{failure}"));
        let second = run_membership(&scenario, 7).unwrap_or_else(|failure| panic!("{failure}"));
        assert_eq!(first, second, "scenario {}", scenario.name);
        let other = run_membership(&scenario, 8).unwrap_or_else(|failure| panic!("{failure}"));
        assert_ne!(first.digest, other.digest, "scenario {}", scenario.name);
    }
}
