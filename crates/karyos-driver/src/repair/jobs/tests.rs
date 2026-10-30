// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use super::*;

const MS: u64 = 1_000_000;

fn receiver(id: u64) -> Receiver {
    Receiver {
        receiver_boot_id: [id, 1],
        receiver_id: id,
    }
}

fn request(id: u64, lane: u8, start: u64, length: u32) -> Request {
    Request {
        receiver: receiver(id),
        lane,
        start,
        length,
    }
}

fn jobs(config: JobsConfig) -> Jobs {
    Jobs::new(config).unwrap()
}

fn created(joined: Joined) -> JobRef {
    match joined {
        Joined::Created(job) => job,
        other => panic!("not created: {other:?}"),
    }
}

#[test]
fn the_table_is_validated() {
    for config in [
        JobsConfig {
            repair_jobs: 0,
            ..JobsConfig::default()
        },
        JobsConfig {
            repair_linger_entries: 0,
            ..JobsConfig::default()
        },
        JobsConfig {
            requesters_per_job: 0,
            ..JobsConfig::default()
        },
        JobsConfig {
            repair_jobs: 1 << 17,
            ..JobsConfig::default()
        },
    ] {
        assert_eq!(Jobs::new(config).err(), Some(JobsError::Capacity));
    }
}

/// An exact duplicate in the group domain joins the pending job and adds
/// its requester; any other interval is another job.
#[test]
fn only_an_exact_duplicate_joins() {
    let mut jobs = jobs(JobsConfig::default());
    let job = created(jobs.join_or_create(&request(1, 0, 1024, 64), Domain::Group, 0));
    assert_eq!(
        jobs.join_or_create(&request(2, 0, 1024, 64), Domain::Group, 0),
        Joined::Joined(job)
    );
    assert_eq!(
        jobs.join_or_create(&request(2, 0, 1024, 64), Domain::Group, 0),
        Joined::Joined(job),
        "a repeat requester is recorded once"
    );
    assert_eq!(jobs.requesters(job), &[receiver(1), receiver(2)]);
    for other in [
        request(3, 0, 1024, 32),
        request(3, 0, 1056, 64),
        request(3, 1, 1024, 64),
    ] {
        assert!(matches!(
            jobs.join_or_create(&other, Domain::Group, 0),
            Joined::Created(_)
        ));
    }
    let counts = jobs.counts();
    assert_eq!((counts.created, counts.joined), (4, 2));
}

/// With the requester domain, another receiver or membership generation
/// is another job.
#[test]
fn the_requester_domain_keys_the_receiver() {
    let mut jobs = jobs(JobsConfig::default());
    let one = Domain::Requester {
        receiver: receiver(1),
        generation: 1,
    };
    let job = created(jobs.join_or_create(&request(1, 0, 0, 64), one, 0));
    assert_eq!(
        jobs.join_or_create(&request(1, 0, 0, 64), one, 0),
        Joined::Joined(job)
    );
    for (id, domain) in [
        (
            2,
            Domain::Requester {
                receiver: receiver(2),
                generation: 1,
            },
        ),
        (
            1,
            Domain::Requester {
                receiver: receiver(1),
                generation: 2,
            },
        ),
        (1, Domain::Group),
    ] {
        assert!(matches!(
            jobs.join_or_create(&request(id, 0, 0, 64), domain, 0),
            Joined::Created(_)
        ));
    }
}

/// The linger starts at the last submission and drops duplicates within
/// it, never extended by them; failure and uncertainty start none.
#[test]
fn the_linger_follows_the_last_submission() {
    let mut jobs = jobs(JobsConfig::default());
    let range = request(1, 0, 0, 64);
    let job = created(jobs.join_or_create(&range, Domain::Group, 0));
    jobs.progress(job, 32);
    assert_eq!(
        jobs.join_or_create(&range, Domain::Group, MS),
        Joined::Joined(job),
        "a partly sent job is still pending"
    );
    jobs.done(job, 5 * MS);
    assert!(!jobs.current(job));
    assert_eq!(
        jobs.join_or_create(&range, Domain::Group, 6 * MS - 1),
        Joined::Lingering
    );
    assert_eq!(
        jobs.join_or_create(&range, Domain::Group, 6 * MS - 1),
        Joined::Lingering
    );
    assert!(matches!(
        jobs.join_or_create(&range, Domain::Group, 6 * MS),
        Joined::Created(_)
    ));
    let failed = created(jobs.join_or_create(&request(1, 1, 0, 64), Domain::Group, 0));
    jobs.failed(failed);
    assert!(matches!(
        jobs.join_or_create(&request(1, 1, 0, 64), Domain::Group, 0),
        Joined::Created(_)
    ));
    let uncertain = created(jobs.join_or_create(&request(1, 2, 0, 64), Domain::Group, 0));
    jobs.unresolved(uncertain);
    assert!(matches!(
        jobs.join_or_create(&request(1, 2, 0, 64), Domain::Group, 0),
        Joined::Created(_)
    ));
    let counts = jobs.counts();
    assert_eq!(
        (
            counts.lingering,
            counts.done,
            counts.failed,
            counts.unresolved
        ),
        (2, 1, 1, 1)
    );
}

/// Full job and linger tables drop and count; a stale reference changes
/// nothing; requesters beyond the limit are counted.
#[test]
fn capacity_is_bounded() {
    let mut jobs = jobs(JobsConfig {
        repair_jobs: 2,
        repair_linger_entries: 1,
        requesters_per_job: 1,
        ..JobsConfig::default()
    });
    let first = created(jobs.join_or_create(&request(1, 0, 0, 64), Domain::Group, 0));
    created(jobs.join_or_create(&request(1, 0, 64, 64), Domain::Group, 0));
    assert_eq!(
        jobs.join_or_create(&request(1, 0, 128, 64), Domain::Group, 0),
        Joined::Full
    );
    jobs.join_or_create(&request(2, 0, 0, 64), Domain::Group, 0);
    assert_eq!(jobs.requesters(first), &[receiver(1)]);
    assert_eq!(jobs.counts().requesters_full, 1);
    jobs.done(first, 0);
    // The freed slot is reused at a new generation; the old reference is
    // stale.
    let reused = created(jobs.join_or_create(&request(1, 1, 128, 64), Domain::Group, 0));
    assert_eq!(reused.slot, first.slot);
    assert_ne!(reused.generation, first.generation);
    jobs.done(first, 0);
    assert!(jobs.current(reused));
    assert!(!jobs.current(first));
    assert_eq!(jobs.requesters(first), &[] as &[Receiver]);
    // A stale reference moves nothing.
    jobs.progress(first, 160);
    assert_eq!(jobs.next_for_lane(1).unwrap().cursor, 128);
    assert_eq!(jobs.requesters(reused), &[receiver(1)], "cleared at reuse");
    // One linger entry, live: the next done job has none.
    jobs.done(reused, 0);
    assert_eq!(jobs.counts().linger_full, 1);
    assert_eq!(jobs.counts().full, 1);
}

/// The scheduler sees each lane's oldest job and its cursor; progress
/// moves the cursor forward only, within the job.
#[test]
fn each_lane_serves_its_oldest_job() {
    let mut jobs = jobs(JobsConfig::default());
    let later = created(jobs.join_or_create(&request(1, 0, 4096, 64), Domain::Group, 0));
    let other = created(jobs.join_or_create(&request(1, 1, 0, 64), Domain::Group, 0));
    let oldest = jobs.next_for_lane(0).unwrap();
    assert_eq!(oldest.job, later);
    assert_eq!(oldest.cursor, 4096);
    jobs.progress(later, 4128);
    jobs.progress(later, 4096);
    assert_eq!(jobs.next_for_lane(0).unwrap().cursor, 4128);
    jobs.progress(later, 1 << 20);
    assert_eq!(
        jobs.next_for_lane(0).unwrap().cursor,
        4160,
        "not past its end"
    );
    assert_eq!(jobs.next_for_lane(1).unwrap().job, other);
    assert_eq!(jobs.next_for_lane(2), None);
    jobs.done(later, 0);
    assert_eq!(jobs.next_for_lane(0), None);
}

/// The oldest of two jobs on a lane goes first, then the newer.
#[test]
fn the_oldest_job_of_a_lane_goes_first() {
    let mut jobs = jobs(JobsConfig::default());
    let older = created(jobs.join_or_create(&request(1, 0, 4096, 64), Domain::Group, 0));
    let newer = created(jobs.join_or_create(&request(1, 0, 0, 64), Domain::Group, 0));
    assert_eq!(jobs.next_for_lane(0).unwrap().job, older);
    jobs.done(older, 0);
    assert_eq!(jobs.next_for_lane(0).unwrap().job, newer);
}

/// An expired linger entry is reused: a later done job gets one.
#[test]
fn an_expired_linger_entry_is_reused() {
    let mut jobs = jobs(JobsConfig {
        repair_linger_entries: 1,
        ..JobsConfig::default()
    });
    let a = created(jobs.join_or_create(&request(1, 0, 0, 64), Domain::Group, 0));
    let b = created(jobs.join_or_create(&request(1, 0, 64, 64), Domain::Group, 0));
    jobs.done(a, 0);
    jobs.done(b, MS);
    assert_eq!(jobs.counts().linger_full, 0);
    assert_eq!(
        jobs.join_or_create(&request(2, 0, 64, 64), Domain::Group, MS),
        Joined::Lingering
    );
}

/// A reused slot starts with only its new requester, and a done job has
/// none.
#[test]
fn requesters_belong_to_their_job() {
    let mut jobs = jobs(JobsConfig {
        repair_jobs: 1,
        ..JobsConfig::default()
    });
    let first = created(jobs.join_or_create(&request(1, 0, 0, 64), Domain::Group, 0));
    jobs.join_or_create(&request(2, 0, 0, 64), Domain::Group, 0);
    jobs.done(first, 0);
    assert!(jobs.requesters(first).is_empty());
    let next = created(jobs.join_or_create(&request(3, 0, 64, 64), Domain::Group, 0));
    assert_eq!(next.slot, first.slot);
    assert_eq!(jobs.requesters(next), &[receiver(3)]);
}

/// karyos#890 review: only a submission moves a lane's catch-up
/// position. A job that progressed one frame and was then refused (its
/// end inside a frame) leaves it at that frame's end, never at the job's
/// end; one refused before submitting anything leaves it where it was.
#[test]
fn a_refused_catch_up_moves_nothing_it_did_not_submit() {
    let mut jobs = jobs(JobsConfig::default());
    let job = created(jobs.create_catch_up(0, 4_224, 1_088));
    jobs.progress(job, 5_280);
    jobs.failed(job);
    assert!(!jobs.current(job));
    assert_eq!(jobs.catch_up_through(0), 5_280);
    let job = created(jobs.create_catch_up(0, 5_280, 32));
    jobs.failed(job);
    assert_eq!(
        jobs.catch_up_through(0),
        5_280,
        "a refused job adds nothing"
    );
    let job = created(jobs.create_catch_up(0, 5_280, 1_056));
    jobs.done(job, 0);
    assert_eq!(
        jobs.catch_up_through(0),
        6_336,
        "a done job submitted all of it"
    );
}
