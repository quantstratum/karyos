// SPDX-License-Identifier: Apache-2.0

//! The sender's repair path on virtual time (`quantstratum-docs:
//! karyos/design/reliable-transport.md`; phase 6 R4, R5 and R7; ACS
//! 15767).
//!
//! NAK admission ([`Admission`]), the job table ([`Jobs`]) and the repair
//! scheduler ([`Scheduler`]) run together against a scripted log of two
//! lanes and a scripted backend. Each step the log grows, receivers NAK
//! overlapping, identical and sometimes invalid ranges (duplicates and
//! reorder included), the floor may move, and the scheduler runs on a
//! random repair budget; the backend answers each submission submitted,
//! not submitted, uncertain or with no room. Step 8 ERRs go through
//! admission's ERR linger, as the wiring will send them.
//!
//! Oracles:
//!
//! - every job created ends exactly once (done, failed or unresolved),
//!   and none is served after it ended; a final drain ends them all and
//!   the table's counts agree;
//! - an exact duplicate within `repair_linger` of a job's last submission
//!   never creates a second job;
//! - no ERR for the same receiver, lane and range repeats within
//!   `nak_reply_linger`;
//! - `RANGE_UNAVAILABLE` only names the floor read at that moment, above
//!   the request's start;
//! - `repair-fair`: two lanes kept backlogged and always submitted get
//!   service within `Q + 2 F` of each other over any window in which both
//!   stay backlogged (`Q` the quantum, `F` the largest charge): each
//!   lane's service in the window is its credits plus or minus a deficit
//!   below `F` at each end, and the credits differ by at most one visit;
//! - a seed reproduces its run.
//!
//! A failure prints its seed and trace.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints); the lane
// arrays are indexed by lane below LANES.
#![allow(clippy::panic, clippy::indexing_slicing)]

use std::collections::{BTreeMap, VecDeque};

use karyos_driver::repair::admission::{Admission, Admitted, NakContext, Requester};
use karyos_driver::repair::jobs::{Domain, JobKey, JobRef, Jobs, JobsConfig, Joined};
use karyos_driver::repair::scheduler::{
    Head, RepairBudget, RepairRead, RepairReadError, RepairSubmit, Scheduler, Submit,
};
use karyos_protocol::lanes::drr::DrrConfig;
use karyos_protocol::network::{Alias, Identity, Nak, NakRange, NakReplyReason, Receiver};
use karyos_sys::frame::Lane;

use karyos_sim::{Failure, Rng, scenarios};

const LANES: usize = 2;
/// A short term, so ranges and PADs meet term ends often.
const TERM: u64 = 16 * 1024;
/// One step of virtual time.
const STEP: u64 = 100_000;
/// `repair_linger` and `nak_reply_linger`: ten steps.
const LINGER: u64 = 1_000_000;
const QUANTUM: u64 = 1024;
const MAX_CHARGE: u64 = 512;
const RECEIVERS: u64 = 6;
const TRACE: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Mixed,
    Fair,
}

#[derive(Debug, Clone, Copy)]
struct RepairScenario {
    name: &'static str,
    kind: Kind,
    steps: u64,
}

fn repair_scenarios() -> Vec<RepairScenario> {
    vec![
        RepairScenario {
            name: "repair-mixed",
            kind: Kind::Mixed,
            steps: 2000,
        },
        RepairScenario {
            name: "repair-fair",
            kind: Kind::Fair,
            steps: 600,
        },
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct RepairReport {
    created: u64,
    done: u64,
    failed: u64,
    unresolved: u64,
    errs: u64,
    digest: u64,
}

/// One lane of the scripted log: frame boundaries from 0, each with the
/// head that starts there.
#[derive(Debug, Default)]
struct LogLane {
    heads: BTreeMap<u64, Head>,
    /// The end of the last frame: the log's head.
    end: u64,
    /// What was sent: NAKs are valid below it.
    sent: u64,
    floor: u64,
}

impl LogLane {
    /// Appends a frame of `aligned` bytes, or a PAD to the term end when
    /// it does not fit the term.
    fn append(&mut self, aligned: u64) {
        let term_end = (self.end / TERM + 1) * TERM;
        let head = if self.end + aligned > term_end {
            Head::Record { next: term_end }
        } else {
            Head::Data {
                aligned,
                next: self.end + aligned,
            }
        };
        let next = match head {
            Head::Data { next, .. } | Head::Record { next } => next,
        };
        self.heads.insert(self.end, head);
        self.end = next;
    }
}

#[derive(Debug, Default)]
struct Log {
    lanes: [LogLane; LANES],
}

impl RepairRead for Log {
    fn head(&mut self, lane: u8, from: u64, _end: Option<u64>) -> Result<Head, RepairReadError> {
        let log = &self.lanes[usize::from(lane)];
        if from < log.floor {
            return Err(RepairReadError::Unavailable { lowest: log.floor });
        }
        if from >= log.sent {
            return Err(RepairReadError::BadRequest);
        }
        log.heads
            .get(&from)
            .copied()
            .ok_or(RepairReadError::BadRequest)
    }

    fn floor(&self, lane: u8) -> u64 {
        self.lanes[usize::from(lane)].floor
    }
}

/// What the harness knows of a job.
#[derive(Debug, Clone, Copy)]
struct Tracked {
    key: JobKey,
    ended: Option<&'static str>,
}

/// The scripted backend and the harness's bookkeeping.
struct Wire<'a> {
    rng: &'a mut Rng,
    always_submit: bool,
    now: u64,
    tracked: &'a mut BTreeMap<(u16, u64), Tracked>,
    done_at: &'a mut BTreeMap<(u8, u64, u32), u64>,
    /// Step 8 ERRs, to send through admission's linger.
    replies: Vec<(JobKey, Vec<Receiver>, NakReplyReason)>,
    floors: [u64; LANES],
    violation: Option<String>,
    submitted: [u64; LANES],
}

impl RepairSubmit for Wire<'_> {
    fn submit(&mut self, lane: u8, job: JobRef, from: u64, head: Head) -> Submit {
        let Some(tracked) = self.tracked.get_mut(&(job.slot, job.generation)) else {
            self.violation = Some(format!("submit for an unknown job {job:?}"));
            return Submit::Broken;
        };
        if let Some(how) = tracked.ended {
            self.violation = Some(format!("job {job:?} served after it ended ({how})"));
            return Submit::Broken;
        }
        let outcome = if self.always_submit {
            Submit::Submitted
        } else {
            match self.rng.below(20) {
                0 => Submit::NotSubmitted,
                1 => Submit::Uncertain,
                2 => Submit::NoRoom,
                _ => Submit::Submitted,
            }
        };
        let (next, charge) = match head {
            Head::Data { aligned, next } => (next, aligned),
            Head::Record { next } => (next, 32),
        };
        let key = tracked.key;
        let end = key.start + u64::from(key.length);
        match outcome {
            Submit::Submitted => {
                self.submitted[usize::from(lane)] += charge;
                if next == end {
                    tracked.ended = Some("done");
                    self.done_at
                        .insert((key.lane, key.start, key.length), self.now);
                }
            }
            Submit::Uncertain => tracked.ended = Some("unresolved"),
            _ => {}
        }
        let _ = from;
        outcome
    }

    fn reply(
        &mut self,
        key: &JobKey,
        requesters: &[Receiver],
        _routes: &[usize],
        reason: NakReplyReason,
    ) {
        if let NakReplyReason::RangeUnavailable { lowest_retained } = reason {
            let floor = self.floors[usize::from(key.lane)];
            if lowest_retained != floor || key.start >= lowest_retained {
                self.violation = Some(format!(
                    "RANGE_UNAVAILABLE {lowest_retained} for {key:?} with the floor at {floor}"
                ));
            }
        }
        let pending = self
            .tracked
            .values_mut()
            .find(|t| t.key == *key && t.ended.is_none());
        match pending {
            Some(tracked) => tracked.ended = Some("failed"),
            None => self.violation = Some(format!("an ERR for no pending job {key:?}")),
        }
        self.replies.push((*key, requesters.to_vec(), reason));
    }
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
            .rotate_left(9);
    }
}

fn receiver(id: u64) -> Receiver {
    Receiver {
        receiver_boot_id: [id, 3],
        receiver_id: id,
    }
}

fn nak(id: u64, lane: u8, start: u64, length: u32) -> Nak {
    Nak {
        alias: Alias {
            session_id: 1,
            stream_id: 1,
        },
        identity: Identity {
            driver_id: [5, 6],
            registration_id: 1,
            incarnation: 1,
        },
        receiver: receiver(id),
        range: NakRange {
            lane: Lane::try_new(lane).unwrap_or(Lane::ZERO),
            length,
            start,
        },
    }
}

/// A NAK range of `frames` whole frames from a boundary of `lane`, within
/// one term; sometimes deliberately malformed.
fn draw_range(rng: &mut Rng, log: &LogLane, frames: u64, malformed: bool) -> Option<(u64, u32)> {
    let boundaries: Vec<u64> = log.heads.range(..log.sent).map(|(at, _)| *at).collect();
    if boundaries.is_empty() {
        return None;
    }
    let first = usize::try_from(rng.below(u64::try_from(boundaries.len()).ok()?)).ok()?;
    let start = boundaries[first];
    let mut end = start;
    for at in &boundaries[first..] {
        let next = match log.heads.get(at)? {
            Head::Data { next, .. } | Head::Record { next } => *next,
        };
        if next / TERM != start / TERM && next % TERM != 0 {
            break;
        }
        end = next;
        if (end - start) / 32 >= frames * 4 || next % TERM == 0 {
            break;
        }
    }
    let (start, end) = match if malformed { rng.below(20) } else { 2 } {
        // Not on a boundary.
        0 => (start + 32, end),
        // Past what was sent.
        1 => (log.sent, log.sent + 64),
        _ => (start, end),
    };
    let length = u32::try_from(end.checked_sub(start)?).ok()?;
    (length >= 32).then_some((start, length))
}

#[expect(
    clippy::too_many_lines,
    reason = "one scenario loop, its steps in order, as in tests/timed.rs"
)]
fn run_repair(scenario: &RepairScenario, seed: u64) -> Result<RepairReport, Failure> {
    let mut run = Run {
        scenario: scenario.name,
        seed,
        step: 0,
        trace: VecDeque::new(),
        digest: 0xcbf2_9ce4_8422_2325,
    };
    let mut rng = Rng::new(seed);
    let mut log = Log::default();
    let mut admission = Admission::new(LINGER, 256).map_err(|e| run.fail(format!("{e:?}")))?;
    let mut jobs = Jobs::new(JobsConfig {
        repair_linger: LINGER,
        ..JobsConfig::default()
    })
    .map_err(|e| run.fail(format!("{e:?}")))?;
    let config =
        DrrConfig::new(&[QUANTUM; LANES], MAX_CHARGE).map_err(|e| run.fail(format!("{e:?}")))?;
    let mut scheduler = Scheduler::new(config);
    let mut tracked: BTreeMap<(u16, u64), Tracked> = BTreeMap::new();
    let mut done_at: BTreeMap<(u8, u64, u32), u64> = BTreeMap::new();
    let mut errs_at: BTreeMap<(u64, u8, u64, u32), u64> = BTreeMap::new();
    let mut report = RepairReport::default();
    let mut fair_served = [0u64; LANES];
    let fair = scenario.kind == Kind::Fair;
    let sizes = [64, 128, 256, 512];

    let steps = scenario.steps + 400;
    for step in 0..steps {
        run.step = step;
        let now = step * STEP;
        let draining = step >= scenario.steps;
        // 1. The log grows and is sent; the floor moves now and then.
        if !draining {
            for lane in &mut log.lanes {
                for _ in 0..rng.below(4) {
                    lane.append(sizes[usize::try_from(rng.below(4)).unwrap_or(0)]);
                }
                lane.sent = lane.end;
                if !fair && rng.chance(1, 40) && lane.sent > lane.floor + 4096 {
                    let raised = lane.floor + rng.below(2048) / 32 * 32;
                    run.note(format!("floor {} -> {raised}", lane.floor));
                    lane.floor = raised;
                }
            }
        }
        // 2. NAKs, duplicated across receivers and repeated.
        let naks = if draining {
            0
        } else if fair {
            4
        } else {
            rng.below(6)
        };
        let mut batch: Vec<Nak> = Vec::new();
        for _ in 0..naks {
            let lane = u8::try_from(rng.below(2)).unwrap_or(0);
            let frames = if fair { 8 } else { 1 + rng.below(3) };
            let Some((start, length)) =
                draw_range(&mut rng, &log.lanes[usize::from(lane)], frames, !fair)
            else {
                continue;
            };
            let copies = 1 + rng.below(3);
            for _ in 0..copies {
                batch.push(nak(1 + rng.below(RECEIVERS), lane, start, length));
            }
        }
        // Reorder.
        for at in (1..batch.len()).rev() {
            let other = usize::try_from(rng.below(u64::try_from(at + 1).unwrap_or(1))).unwrap_or(0);
            batch.swap(at, other);
        }
        for request in &batch {
            let lane = usize::from(request.range.lane.get());
            let ctx = NakContext {
                reliable: true,
                lane_count: 2,
                requester: Requester::Member {
                    join: 0,
                    consumption: 0,
                    window: u32::MAX,
                },
                floor: log.lanes[lane].floor,
                nak_bound: log.lanes[lane].sent,
                term_length: u32::try_from(TERM).unwrap_or(u32::MAX),
            };
            match admission.admit(request, &ctx, now) {
                Admitted::Pass(passed) => {
                    let key = (passed.lane, passed.start, passed.length);
                    match jobs.join_or_create(&passed, Domain::Group, now) {
                        Joined::Created(job) => {
                            if done_at.get(&key).is_some_and(|at| now - at < LINGER) {
                                return Err(run.fail(format!(
                                    "a duplicate of {key:?} within the linger created a job"
                                )));
                            }
                            tracked.insert(
                                (job.slot, job.generation),
                                Tracked {
                                    key: JobKey {
                                        lane: passed.lane,
                                        start: passed.start,
                                        length: passed.length,
                                        domain: Domain::Group,
                                    },
                                    ended: None,
                                },
                            );
                            report.created += 1;
                            run.mix(passed.start ^ u64::from(passed.length));
                        }
                        Joined::Joined(_) | Joined::Lingering | Joined::Full => {}
                    }
                }
                Admitted::Reply(reply) => {
                    let key = (
                        reply.receiver.receiver_id,
                        reply.range.lane.get(),
                        reply.range.start,
                        reply.range.length,
                    );
                    if errs_at.get(&key).is_some_and(|at| now - at < LINGER) {
                        return Err(run.fail(format!("an ERR repeated within the linger: {key:?}")));
                    }
                    errs_at.insert(key, now);
                    report.errs += 1;
                }
                Admitted::Dropped(_) => {}
            }
        }
        // 3. The scheduler, on a random budget (ample when draining or
        // fair).
        let budget = if draining || fair {
            RepairBudget {
                bytes: 4 * QUANTUM,
                loads: 256,
            }
        } else {
            RepairBudget {
                bytes: rng.below(4096),
                loads: 64,
            }
        };
        let before = [
            jobs.next_for_lane(0).is_some(),
            jobs.next_for_lane(1).is_some(),
        ];
        let mut wire = Wire {
            rng: &mut rng,
            always_submit: draining || fair,
            now,
            tracked: &mut tracked,
            done_at: &mut done_at,
            replies: Vec::new(),
            floors: [log.lanes[0].floor, log.lanes[1].floor],
            violation: None,
            submitted: [0; LANES],
        };
        let served = scheduler.serve(&mut jobs, budget, &mut log, &mut wire, now);
        if let Some(violation) = wire.violation.take() {
            return Err(run.fail(violation));
        }
        let replies = std::mem::take(&mut wire.replies);
        let submitted = wire.submitted;
        for (key, requesters, reason) in replies {
            for requester in requesters {
                let request = nak(requester.receiver_id, key.lane, key.start, key.length);
                if let Admitted::Reply(_) = admission.reply_to(&request, reason, now) {
                    let err = (requester.receiver_id, key.lane, key.start, key.length);
                    if errs_at.get(&err).is_some_and(|at| now - at < LINGER) {
                        return Err(run.fail(format!("a step 8 ERR repeated: {err:?}")));
                    }
                    errs_at.insert(err, now);
                    report.errs += 1;
                }
            }
        }
        for lane in 0..LANES {
            run.mix(served.lanes[lane].served_bytes);
        }
        // 4. Fairness while both lanes stay backlogged.
        if fair && !draining {
            let after = [
                jobs.next_for_lane(0).is_some(),
                jobs.next_for_lane(1).is_some(),
            ];
            if before == [true, true] && after == [true, true] {
                for lane in 0..LANES {
                    fair_served[lane] += submitted[lane];
                }
                let gap = fair_served[0].abs_diff(fair_served[1]);
                if gap > QUANTUM + 2 * MAX_CHARGE {
                    return Err(run.fail(format!(
                        "lanes served {fair_served:?} while both backlogged"
                    )));
                }
            } else {
                fair_served = [0; LANES];
            }
        }
    }
    // Every job ended exactly once, and the table agrees.
    for (job, tracked) in &tracked {
        match tracked.ended {
            Some("done") => report.done += 1,
            Some("failed") => report.failed += 1,
            Some("unresolved") => report.unresolved += 1,
            _ => return Err(run.fail(format!("job {job:?} never ended"))),
        }
    }
    let counts = jobs.counts();
    if (
        counts.created,
        counts.done,
        counts.failed,
        counts.unresolved,
    ) != (
        report.created,
        report.done,
        report.failed,
        report.unresolved,
    ) {
        return Err(run.fail(format!(
            "the table counted {counts:?}, the harness {report:?}"
        )));
    }
    if jobs.next_for_lane(0).is_some() || jobs.next_for_lane(1).is_some() {
        return Err(run.fail("jobs pending after the drain"));
    }
    report.digest = run.digest;
    Ok(report)
}

fn sweep(name: &str) -> Vec<RepairReport> {
    let scenario = repair_scenarios()
        .into_iter()
        .find(|scenario| scenario.name == name)
        .unwrap_or_else(|| panic!("no scenario {name}"));
    scenarios::seeds()
        .into_iter()
        .map(|seed| run_repair(&scenario, seed).unwrap_or_else(|failure| panic!("{failure}")))
        .collect()
}

#[test]
fn repair_mixed() {
    let reports = sweep("repair-mixed");
    if reports.len() == 1 {
        return;
    }
    let total = |f: fn(&RepairReport) -> u64| reports.iter().map(f).sum::<u64>();
    assert!(total(|r| r.done) > 0);
    assert!(total(|r| r.failed) > 0);
    assert!(total(|r| r.unresolved) > 0);
    assert!(total(|r| r.errs) > 0);
}

#[test]
fn repair_fair() {
    let reports = sweep("repair-fair");
    assert!(reports.iter().all(|r| r.done > 0));
}

#[test]
fn a_repair_seed_reproduces_its_run() {
    for scenario in repair_scenarios() {
        let first = run_repair(&scenario, 7).unwrap_or_else(|failure| panic!("{failure}"));
        let second = run_repair(&scenario, 7).unwrap_or_else(|failure| panic!("{failure}"));
        assert_eq!(first, second, "scenario {}", scenario.name);
        let other = run_repair(&scenario, 8).unwrap_or_else(|failure| panic!("{failure}"));
        assert_ne!(first.digest, other.digest, "scenario {}", scenario.name);
    }
}
