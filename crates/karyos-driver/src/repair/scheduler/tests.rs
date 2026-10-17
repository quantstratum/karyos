// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use std::collections::BTreeMap;

use karyos_protocol::lanes::drr::Stop;

use super::super::admission::Request;
use super::super::jobs::{Domain, JobsConfig, Joined};
use super::*;

const MS: u64 = 1_000_000;

fn receiver(id: u64) -> Receiver {
    Receiver {
        receiver_boot_id: [id, 1],
        receiver_id: id,
    }
}

/// Lanes of frames by position, a floor and scripted read errors.
#[derive(Default)]
struct Log {
    heads: BTreeMap<(u8, u64), Head>,
    errors: BTreeMap<(u8, u64), RepairReadError>,
    floor: u64,
    reads: u64,
}

impl Log {
    /// DATA frames of `aligned` bytes on `lane` from `start`, `count` of
    /// them.
    fn data(mut self, lane: u8, start: u64, aligned: u64, count: u64) -> Self {
        for at in 0..count {
            let from = start + at * aligned;
            self.heads.insert(
                (lane, from),
                Head::Data {
                    aligned,
                    next: from + aligned,
                },
            );
        }
        self
    }
}

impl RepairRead for Log {
    fn head(&mut self, lane: u8, from: u64) -> Result<Head, RepairReadError> {
        self.reads += 1;
        if let Some(error) = self.errors.get(&(lane, from)) {
            return Err(*error);
        }
        self.heads
            .get(&(lane, from))
            .copied()
            .ok_or(RepairReadError::BadRequest)
    }

    fn floor(&self, _lane: u8) -> u64 {
        self.floor
    }
}

/// Records submissions and ERRs; answers each submission with the next
/// scripted outcome, then `Submitted`.
#[derive(Default)]
struct Wire {
    submitted: Vec<(u8, u64)>,
    replies: Vec<(JobKey, Vec<Receiver>, NakReplyReason)>,
    script: Vec<Submit>,
    /// A lane whose every submission fails.
    failing: Option<u8>,
    attempts: u64,
}

impl RepairSubmit for Wire {
    fn submit(&mut self, lane: u8, _job: JobRef, from: u64, _head: Head) -> Submit {
        self.attempts += 1;
        let outcome = if self.failing == Some(lane) {
            Submit::NotSubmitted
        } else if self.script.is_empty() {
            Submit::Submitted
        } else {
            self.script.remove(0)
        };
        if outcome == Submit::Submitted {
            self.submitted.push((lane, from));
        }
        outcome
    }

    fn reply(
        &mut self,
        key: &JobKey,
        requesters: &[Receiver],
        _routes: &[usize],
        reason: NakReplyReason,
    ) {
        self.replies.push((*key, requesters.to_vec(), reason));
    }
}

fn new_scheduler(lanes: usize) -> Scheduler {
    let quanta = vec![1024; lanes];
    Scheduler::new(DrrConfig::new(&quanta, 1024).unwrap())
}

fn new_jobs() -> Jobs {
    Jobs::new(JobsConfig::default()).unwrap()
}

fn job(jobs: &mut Jobs, id: u64, lane: u8, start: u64, length: u32) -> JobRef {
    let request = Request {
        receiver: receiver(id),
        lane,
        start,
        length,
    };
    match jobs.join_or_create(&request, Domain::Group, 0) {
        Joined::Created(job) | Joined::Joined(job) => job,
        other => panic!("{other:?}"),
    }
}

/// A job's whole frames go out in order; its last one ends it and starts
/// its linger.
#[test]
fn a_job_is_served_frame_by_frame() {
    let mut log = Log::default().data(0, 1024, 256, 4);
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(1);
    let request = job(&mut jobs, 1, 0, 1024, 3 * 256);
    scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, MS);
    assert_eq!(wire.submitted, [(0, 1024), (0, 1280), (0, 1536)]);
    assert!(!jobs.current(request));
    assert_eq!(scheduler.counts().done, 1);
    assert_eq!(
        jobs.join_or_create(
            &Request {
                receiver: receiver(2),
                lane: 0,
                start: 1024,
                length: 3 * 256,
            },
            Domain::Group,
            MS + 1
        ),
        Joined::Lingering
    );
}

/// A budget too small for the next head suspends the call; the job keeps
/// its cursor and the lane its deficit, and the next call resumes.
#[test]
fn the_budget_suspends_and_keeps_the_deficit() {
    let mut log = Log::default().data(0, 0, 512, 4);
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(1);
    let request = job(&mut jobs, 1, 0, 0, 4 * 512);
    let report = scheduler.serve(
        &mut jobs,
        RepairBudget {
            bytes: 700,
            loads: 100,
        },
        &mut log,
        &mut wire,
        0,
    );
    assert!(matches!(report.stop, Stop::BytesLimited { lane: 0, .. }));
    assert_eq!(wire.submitted, [(0, 0)]);
    assert_eq!(scheduler.deficit(0), Some(512), "1024 credited, 512 served");
    assert_eq!(jobs.next_for_lane(0).unwrap().cursor, 512);
    scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert_eq!(wire.submitted.len(), 4);
    assert!(!jobs.current(request));
}

/// A head read out of word 0 loads ends the call: its job and every lane's
/// deficit are kept, nothing is refused, and the next call resumes where
/// the read stopped.
#[test]
fn a_read_out_of_loads_suspends_the_call() {
    let mut log = Log::default().data(0, 0, 256, 4).data(1, 0, 256, 2);
    log.errors.insert((0, 256), RepairReadError::Budget);
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(2);
    let first = job(&mut jobs, 1, 0, 0, 3 * 256);
    let second = job(&mut jobs, 1, 1, 0, 2 * 256);
    let report = scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert!(
        matches!(report.stop, Stop::Halted { lane: 0 }),
        "{report:?}"
    );
    assert_eq!(wire.submitted, [(0, 0)]);
    assert!(wire.replies.is_empty());
    assert!(jobs.current(first) && jobs.current(second));
    assert_eq!(jobs.next_for_lane(0).unwrap().cursor, 256);
    assert_eq!(scheduler.deficit(0), Some(768), "1024 credited, 256 served");
    assert_eq!(scheduler.counts().budget_suspended, 1);
    assert_eq!(report.lanes[1].forfeited, 0);
    // Loads again: the visit resumes uncredited and both jobs finish.
    log.errors.clear();
    scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert_eq!(
        wire.submitted,
        [(0, 0), (0, 256), (0, 512), (1, 0), (1, 256)]
    );
    assert!(!jobs.current(first) && !jobs.current(second));
}

/// Once a read runs out of loads, no other lane reads a head in that call,
/// even when the suspended lane's deficit is too small to halt it at once.
#[test]
fn a_suspended_call_reads_no_other_lane() {
    let mut log = Log::default().data(0, 0, 1000, 2).data(1, 0, 256, 2);
    log.errors.insert((0, 1000), RepairReadError::Budget);
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(2);
    job(&mut jobs, 1, 0, 0, 2000);
    let other = job(&mut jobs, 1, 1, 0, 512);
    scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert_eq!(wire.submitted, [(0, 0)]);
    assert_eq!(log.reads, 2, "lane 1 read nothing");
    assert_eq!(scheduler.deficit(0), Some(24), "1024 credited, 1000 served");
    assert!(jobs.current(other));
    assert_eq!(jobs.next_for_lane(1).unwrap().cursor, 0);
}

/// PAD and ABORTED records are charged their canonical 32 bytes, whatever
/// their logical extent.
#[test]
fn records_are_charged_32_bytes() {
    let mut log = Log::default();
    log.heads.insert((0, 0), Head::Record { next: 4096 });
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(1);
    job(&mut jobs, 1, 0, 0, 4096);
    let report = scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert_eq!(report.lanes[0].served_bytes, 32);
    assert_eq!(scheduler.counts().done, 1);
}

/// Step 8: BadRequest and an extent crossing the end answer RANGE_INVALID
/// to every requester; Unavailable and Revoked RANGE_UNAVAILABLE with the
/// floor read after; CorruptTerm, Retry and TooSmall drop with no ERR.
#[test]
fn heads_that_fail_end_their_job() {
    let mut log = Log::default().data(0, 0, 256, 2);
    log.heads.insert(
        (1, 0),
        Head::Data {
            aligned: 512,
            next: 512,
        },
    );
    log.errors
        .insert((2, 0), RepairReadError::Unavailable { lowest: 64 });
    log.errors.insert((3, 0), RepairReadError::Revoked);
    log.floor = 128;
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(4);
    // Lane 0: the second frame is missing (not a boundary).
    let bad = job(&mut jobs, 1, 0, 0, 768);
    job(&mut jobs, 2, 0, 0, 768);
    // Lane 1: the frame crosses the job's end.
    job(&mut jobs, 1, 1, 0, 256);
    job(&mut jobs, 1, 2, 0, 256);
    job(&mut jobs, 1, 3, 0, 256);
    scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert!(!jobs.current(bad));
    assert_eq!(
        wire.submitted,
        [(0, 0), (0, 256)],
        "whole frames before stay"
    );
    let reasons: Vec<_> = wire.replies.iter().map(|r| (r.0.lane, r.2)).collect();
    assert_eq!(
        reasons,
        [
            (0, NakReplyReason::RangeInvalid),
            (1, NakReplyReason::RangeInvalid),
            (
                2,
                NakReplyReason::RangeUnavailable {
                    lowest_retained: 128
                }
            ),
            (
                3,
                NakReplyReason::RangeUnavailable {
                    lowest_retained: 128
                }
            ),
        ]
    );
    assert_eq!(
        wire.replies[0].1,
        [receiver(1), receiver(2)],
        "every requester"
    );
    let counts = scheduler.counts();
    assert_eq!((counts.range_invalid, counts.range_unavailable), (2, 2));

    let mut log = Log::default();
    for (lane, error) in [
        RepairReadError::CorruptTerm,
        RepairReadError::Retry,
        RepairReadError::TooSmall,
    ]
    .into_iter()
    .enumerate()
    {
        log.errors.insert((u8::try_from(lane).unwrap(), 0), error);
    }
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(3);
    for lane in 0..3 {
        job(&mut jobs, 1, lane, 0, 256);
    }
    scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert!(wire.replies.is_empty());
    assert_eq!(scheduler.counts().dropped, 3);
}

/// Lanes share the repair budget by DRR: each is served within a call.
#[test]
fn lanes_are_served_round_robin() {
    let mut log = Log::default().data(0, 0, 512, 8).data(1, 0, 512, 8);
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(2);
    job(&mut jobs, 1, 0, 0, 8 * 512);
    job(&mut jobs, 1, 1, 0, 8 * 512);
    scheduler.serve(
        &mut jobs,
        RepairBudget {
            bytes: 4096,
            loads: 100,
        },
        &mut log,
        &mut wire,
        0,
    );
    let lane0 = wire.submitted.iter().filter(|(lane, _)| *lane == 0).count();
    let lane1 = wire.submitted.iter().filter(|(lane, _)| *lane == 1).count();
    assert_eq!((lane0, lane1), (4, 4));
}

/// A known failure keeps the job and holds the lane for the call; an
/// uncertain one ends it unresolved with no linger; no room ends the call
/// as backpressure, the job kept.
#[test]
fn submission_outcomes() {
    let mut log = Log::default().data(0, 0, 256, 2);
    let mut wire = Wire {
        script: vec![Submit::NotSubmitted, Submit::NoRoom],
        ..Wire::default()
    };
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(1);
    let kept = job(&mut jobs, 1, 0, 0, 512);
    let report = scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert_eq!(report.stop, Stop::Idle, "the lane is held for the call");
    assert_eq!(
        report.lanes[0].failed, 1,
        "the known failure is not debited"
    );
    assert_eq!(report.lanes[0].served_bytes, 0);
    assert_eq!(wire.attempts, 1);
    let report = scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert!(matches!(report.stop, Stop::Backpressure { lane: 0 }));
    assert!(jobs.current(kept));
    assert_eq!(jobs.next_for_lane(0).unwrap().cursor, 0);
    let mut wire = Wire {
        script: vec![Submit::Uncertain],
        ..Wire::default()
    };
    scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert!(!jobs.current(kept));
    assert_eq!(scheduler.counts().unresolved, 1);
    assert!(matches!(
        jobs.join_or_create(
            &Request {
                receiver: receiver(1),
                lane: 0,
                start: 0,
                length: 512,
            },
            Domain::Group,
            0
        ),
        Joined::Created(_)
    ));
}

/// A probe reads one head: a refused job makes it ineligible, and the
/// lane's next job goes at the lane's next probe.
#[test]
fn a_refused_job_gives_way_at_the_next_probe() {
    let mut log = Log::default().data(0, 1024, 256, 1);
    log.errors.insert((0, 0), RepairReadError::BadRequest);
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(1);
    let bad = job(&mut jobs, 1, 0, 0, 256);
    let good = job(&mut jobs, 1, 0, 1024, 256);
    let budget = RepairBudget {
        bytes: 4096,
        loads: 1,
    };
    scheduler.serve(&mut jobs, budget, &mut log, &mut wire, 0);
    assert!(!jobs.current(bad) && jobs.current(good));
    assert_eq!(log.reads, 1, "one load, one read");
    assert_eq!(wire.replies.len(), 1);
    scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert!(!jobs.current(good));
    assert_eq!(wire.submitted, [(0, 1024)]);
}

/// Fifty refusable jobs cost at most one read and one ERR per load.
#[test]
fn refusals_stay_within_the_loads() {
    let mut log = Log::default();
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(1);
    for at in 0..50 {
        job(&mut jobs, 1, 0, at * 64, 64);
    }
    scheduler.serve(
        &mut jobs,
        RepairBudget {
            bytes: 4096,
            loads: 8,
        },
        &mut log,
        &mut wire,
        0,
    );
    assert!(log.reads <= 8, "{} reads", log.reads);
    assert!(wire.replies.len() <= 8);
}

/// A lane whose submissions keep failing is held for the call; the other
/// lane is served and the reads stay bounded.
#[test]
fn a_failing_lane_does_not_starve_another() {
    let mut log = Log::default().data(0, 0, 256, 64).data(1, 0, 256, 64);
    let mut wire = Wire {
        failing: Some(0),
        ..Wire::default()
    };
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(2);
    job(&mut jobs, 1, 0, 0, 64 * 256);
    job(&mut jobs, 1, 1, 0, 64 * 256);
    for _ in 0..5 {
        scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    }
    let lane1 = wire.submitted.iter().filter(|(lane, _)| *lane == 1).count();
    assert!(lane1 >= 5 * 4, "lane 1 sent {lane1}");
    assert!(log.reads < 5 * 64, "{} reads", log.reads);
}

/// A head the DRR would refuse is dropped and counted; the lane's next
/// job is served on a later call.
#[test]
fn an_invalid_head_is_dropped() {
    for head in [
        Head::Data {
            aligned: 0,
            next: 64,
        },
        Head::Data {
            aligned: 2048,
            next: 2048,
        },
        Head::Data {
            aligned: 64,
            next: 0,
        },
    ] {
        let mut log = Log::default().data(0, 4096, 64, 1);
        log.heads.insert((0, 0), head);
        let mut wire = Wire::default();
        let mut jobs = new_jobs();
        let mut scheduler = new_scheduler(1);
        let bad = job(&mut jobs, 1, 0, 0, 4096);
        let good = job(&mut jobs, 1, 0, 4096, 64);
        scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
        assert!(!jobs.current(bad), "{head:?}");
        assert_eq!(scheduler.counts().invalid_heads, 1);
        scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
        assert!(!jobs.current(good), "{head:?}");
    }
}

/// RANGE_UNAVAILABLE names the higher of the read's floor and the floor
/// read after it.
#[test]
fn the_lowest_retained_is_the_higher_floor() {
    let mut log = Log::default();
    log.errors
        .insert((0, 0), RepairReadError::Unavailable { lowest: 300 });
    log.floor = 128;
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(1);
    job(&mut jobs, 1, 0, 0, 256);
    scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert_eq!(
        wire.replies[0].2,
        NakReplyReason::RangeUnavailable {
            lowest_retained: 300
        }
    );
}

/// A head charged exactly the largest charge is valid and served.
#[test]
fn a_head_of_the_largest_charge_is_served() {
    let mut log = Log::default().data(0, 0, 1024, 1);
    let mut wire = Wire::default();
    let mut jobs = new_jobs();
    let mut scheduler = new_scheduler(1);
    let request = job(&mut jobs, 1, 0, 0, 1024);
    scheduler.serve(&mut jobs, RepairBudget::default(), &mut log, &mut wire, 0);
    assert!(!jobs.current(request));
    assert_eq!(scheduler.counts().invalid_heads, 0);
    assert_eq!(wire.submitted, [(0, 0)]);
}
