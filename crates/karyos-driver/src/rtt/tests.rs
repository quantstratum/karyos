// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use std::net::{IpAddr, Ipv4Addr};

use super::*;

const MS: u64 = 1_000_000;
const SECOND: u64 = 1_000_000_000;

/// Ids 1, 2, 3 and so on, or a failure while `fail` is set.
#[derive(Debug, Default)]
struct Ids {
    next: u64,
    fail: bool,
}

impl ProbeIds for Ids {
    fn probe_id(&mut self) -> Option<u64> {
        if self.fail {
            return None;
        }
        self.next += 1;
        Some(self.next)
    }
}

/// A source that only draws zero.
struct Zero;

impl ProbeIds for Zero {
    fn probe_id(&mut self) -> Option<u64> {
        Some(0)
    }
}

fn probes(paths: usize) -> RttProbes<Ids> {
    RttProbes::with_ids(RttConfig::default(), paths, Ids::default()).unwrap()
}

fn source(host: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, host)), 40_000)
}

/// Sends `path`'s due probe at `now`, submitted, and returns it.
fn send(probes: &mut RttProbes<Ids>, path: usize, now: u64) -> Probe {
    let probe = probes.due(path, now).unwrap();
    probes.submitted(probe, now);
    probe
}

#[test]
fn the_configuration_is_validated() {
    assert_eq!(RttConfig::default().validate(), Ok(()));
    let base = RttConfig::default();
    for config in [
        RttConfig {
            rtt_floor: 0,
            ..base
        },
        RttConfig {
            rtt_floor: 2 * MS,
            ..base
        },
        RttConfig {
            rtt_initial: 2 * SECOND,
            ..base
        },
    ] {
        assert_eq!(config.validate(), Err(RttConfigError::Order));
    }
    for config in [
        RttConfig {
            rtt_probe_interval: 0,
            ..base
        },
        RttConfig {
            rtt_sample_window: 0,
            ..base
        },
        RttConfig {
            rttm_reply_rate: 0,
            ..base
        },
        RttConfig {
            rttm_reply_sources: 0,
            ..base
        },
    ] {
        assert_eq!(config.validate(), Err(RttConfigError::Zero));
        assert_eq!(RttReplies::new(&config).err(), Some(RttConfigError::Zero));
    }
}

/// The operating system's ids come from a pool drawn on the control path:
/// nonzero, not repeating in practice; taking one makes no draw, an empty
/// pool gives none, and a refill restocks it.
#[test]
fn os_probe_ids_come_from_a_pool() {
    let mut ids = OsProbeIds::new();
    assert_eq!(ids.len(), ID_POOL);
    let drawn: Vec<u64> = (0..ID_POOL).map(|_| ids.probe_id().unwrap()).collect();
    assert!(ids.is_empty());
    assert_eq!(ids.probe_id(), None);
    assert!(drawn.iter().all(|id| *id != 0));
    for (at, id) in drawn.iter().enumerate() {
        assert!(!drawn[at + 1..].contains(id));
    }
    ids.refill();
    assert_eq!(ids.len(), ID_POOL);
    // Above the low-water mark a refill draws nothing.
    let held = ids.pool;
    for _ in 0..ID_POOL - ID_LOW_WATER - 1 {
        ids.probe_id();
    }
    assert_eq!(ids.len(), ID_LOW_WATER + 1);
    ids.refill();
    assert_eq!(ids.len(), ID_LOW_WATER + 1, "no draw above the mark");
    assert_eq!(ids.pool, held);
    // At the mark it restocks, keeping the ids at hand.
    ids.probe_id();
    ids.refill();
    assert_eq!(ids.len(), ID_POOL);
    assert_eq!(ids.pool[..ID_LOW_WATER], held[..ID_LOW_WATER]);
}

/// An image's probes drain the pool and fail, counted, until the control
/// path refills it.
#[test]
fn probes_wait_for_a_refill() {
    let mut probes = RttProbes::new(
        RttConfig {
            rtt_probe_timeout: 1,
            rtt_initial: 1,
            rtt_floor: 1,
            rtt_probe_interval: 1,
            ..RttConfig::default()
        },
        1,
    )
    .unwrap();
    let mut now = 0;
    for _ in 0..ID_POOL {
        let probe = probes.due(0, now).unwrap();
        assert_ne!(probe.probe_id, 0);
        probes.not_submitted(probe);
        now += 1;
    }
    assert_eq!(probes.due(0, now), None);
    assert_eq!(probes.counts().id_failures, 1);
    probes.refill_ids();
    assert!(probes.due(0, now + 1).is_some());
}

/// One outstanding probe per path, one per interval, with ids from the
/// image's source.
#[test]
fn probes_follow_the_interval_one_at_a_time() {
    let mut probes = probes(2);
    let first = probes.due(0, 0).unwrap();
    assert_eq!(first.probe_id, 1);
    assert_eq!(probes.due(0, 10 * MS), None, "one outstanding");
    let other = probes.due(1, 10 * MS).unwrap();
    assert_eq!(other.probe_id, 2);
    probes.submitted(first, 0);
    assert_eq!(probes.reply(0, 0, 1, 5 * MS), ReplyOutcome::Sample(5 * MS));
    // Answered, but the interval has not passed.
    assert_eq!(probes.due(0, 500 * MS), None);
    assert_eq!(probes.due(0, SECOND).unwrap().probe_id, 3);
    assert_eq!(probes.counts().probes, 3);
}

/// The estimate is the largest of the last window of samples, the initial
/// value before any; a sample below the floor counts as the floor; a zero
/// sample is invalid.
#[test]
fn the_estimate_is_the_largest_recent_sample() {
    let mut probes = probes(1);
    assert_eq!(probes.estimate(0), MS, "rtt_initial");
    let mut now = 0;
    for sample in [9 * MS, 2 * MS, 3 * MS, 4 * MS] {
        let probe = send(&mut probes, 0, now);
        assert_eq!(
            probes.reply(0, probe.generation, probe.probe_id, now + sample),
            ReplyOutcome::Sample(sample)
        );
        now += SECOND;
    }
    assert_eq!(probes.estimate(0), 9 * MS);
    // A fifth sample pushes the 9 ms one out of the window of 4.
    let probe = send(&mut probes, 0, now);
    probes.reply(0, 0, probe.probe_id, now + 1_000);
    assert_eq!(probes.estimate(0), 4 * MS);
    assert_eq!(
        probes.counts().floored,
        1,
        "1 us raised to the 0.1 ms floor"
    );
    now += SECOND;
    // A zero sample (the clock went back): invalid, no estimate change.
    let probe = send(&mut probes, 0, now);
    assert_eq!(
        probes.reply(0, 0, probe.probe_id, now),
        ReplyOutcome::Ignored
    );
    assert_eq!(probes.counts().invalid, 1);
    assert_eq!(probes.estimate(0), 4 * MS);
}

/// Duplicates, unmatched ids, wrong paths, old generations, late replies
/// and replies to unsubmitted probes change no estimate and are counted.
#[test]
fn invalid_replies_change_nothing() {
    let mut probes = probes(2);
    let probe = send(&mut probes, 0, 0);
    // Wrong path and wrong id.
    assert_eq!(
        probes.reply(1, 0, probe.probe_id, MS),
        ReplyOutcome::Ignored
    );
    assert_eq!(probes.reply(0, 0, 99, MS), ReplyOutcome::Ignored);
    assert_eq!(
        probes.reply(5, 0, probe.probe_id, MS),
        ReplyOutcome::Ignored
    );
    // The real one, then its duplicate.
    assert_eq!(
        probes.reply(0, 0, probe.probe_id, 2 * MS),
        ReplyOutcome::Sample(2 * MS)
    );
    assert_eq!(
        probes.reply(0, 0, probe.probe_id, 3 * MS),
        ReplyOutcome::Ignored
    );
    // An unsubmitted probe yields no sample, even if answered.
    let unsent = probes.due(1, 0).unwrap();
    assert_eq!(
        probes.reply(1, 0, unsent.probe_id, MS),
        ReplyOutcome::Ignored
    );
    probes.not_submitted(unsent);
    // A late reply, past the timeout.
    let late = send(&mut probes, 0, SECOND);
    assert_eq!(
        probes.reply(0, 0, late.probe_id, 2 * SECOND),
        ReplyOutcome::Ignored
    );
    let counts = probes.counts();
    assert_eq!(counts.samples, 1);
    assert_eq!(counts.duplicates, 1);
    assert_eq!(counts.unmatched, 4);
    assert_eq!(counts.unsubmitted, 1);
    assert_eq!(counts.late, 1);
    assert_eq!(probes.estimate(0), 2 * MS);
    assert_eq!(probes.estimate(1), MS);
}

/// An outstanding probe expires at the timeout, counted, and the next is
/// due at once if the interval has passed.
#[test]
fn an_unanswered_probe_expires() {
    let mut probes = probes(1);
    let probe = send(&mut probes, 0, 0);
    assert_eq!(probes.due(0, SECOND - 1), None);
    let next = probes.due(0, SECOND).unwrap();
    assert_eq!(next.probe_id, probe.probe_id + 1);
    assert_eq!(probes.counts().expired, 1);
    assert_eq!(
        probes.reply(0, 0, probe.probe_id, SECOND + 1),
        ReplyOutcome::Ignored
    );
}

/// A rebinding moves the generation, drops the samples (the estimate is
/// rtt_initial again) and makes the old probe's reply unmatched.
#[test]
fn a_rebinding_starts_afresh() {
    let mut probes = probes(1);
    let probe = send(&mut probes, 0, 0);
    probes.reply(0, 0, probe.probe_id, 7 * MS);
    let old = send(&mut probes, 0, SECOND);
    probes.rebind(0);
    assert_eq!(probes.estimate(0), MS);
    assert_eq!(
        probes.reply(0, 0, old.probe_id, SECOND + MS),
        ReplyOutcome::Ignored
    );
    let fresh = probes.due(0, SECOND + 2 * MS).unwrap();
    assert_eq!(fresh.generation, 1);
    probes.submitted(fresh, SECOND + 2 * MS);
    assert_eq!(
        probes.reply(0, 1, fresh.probe_id, SECOND + 5 * MS),
        ReplyOutcome::Sample(3 * MS)
    );
}

/// The image's snapshot is the largest estimate over its live paths.
#[test]
fn the_snapshot_is_the_largest_live_estimate() {
    let mut probes = probes(3);
    for (path, sample) in [(0, 2 * MS), (1, 6 * MS)] {
        let probe = send(&mut probes, path, 0);
        probes.reply(path, 0, probe.probe_id, sample);
    }
    assert_eq!(probes.snapshot([0, 1]), 6 * MS);
    assert_eq!(probes.snapshot([0]), 2 * MS);
    // Path 2 has no sample: rtt_initial counts.
    assert_eq!(probes.snapshot([0, 2]), 2 * MS);
    assert_eq!(probes.snapshot([]), MS);
}

/// A failed id draw sends nothing, is counted, and the next try waits an
/// interval; a zero id counts as a failure.
#[test]
fn a_failed_id_draw_sends_nothing() {
    let mut probes = probes(1);
    probes.ids.fail = true;
    assert_eq!(probes.due(0, 0), None);
    probes.ids.fail = false;
    assert_eq!(probes.due(0, SECOND - 1), None, "waits an interval");
    assert!(probes.due(0, SECOND).is_some());
    let mut zeros = RttProbes::with_ids(RttConfig::default(), 1, Zero).unwrap();
    assert_eq!(zeros.due(0, 0), None);
    assert_eq!(zeros.counts().id_failures, 1);
    assert_eq!(probes.counts().id_failures, 1);
    assert_eq!(probes.counts().probes, 1);
}

/// The binding generation never wraps: at its end the path is retired and
/// never probes again, counted once.
#[test]
fn an_exhausted_generation_retires_the_path() {
    let mut probes = probes(2);
    probes.paths[0].generation = u64::MAX;
    let old = send(&mut probes, 0, 0);
    probes.rebind(0);
    probes.rebind(0);
    assert_eq!(probes.counts().generations_exhausted, 1);
    assert_eq!(probes.due(0, 10 * SECOND), None);
    assert_eq!(
        probes.reply(0, u64::MAX, old.probe_id, MS),
        ReplyOutcome::Ignored
    );
    assert_eq!(probes.estimate(0), MS);
    assert!(probes.due(1, 10 * SECOND).is_some(), "other paths go on");
}

/// The sender answers at most rttm_reply_rate requests per second per
/// source; the rest are dropped and counted, and one source cannot starve
/// another.
#[test]
fn replies_are_rate_limited_per_source() {
    let mut replies = RttReplies::new(&RttConfig::default()).unwrap();
    let answered = (0..20).filter(|_| replies.admit(source(1), 0)).count();
    assert_eq!(answered, 16);
    assert_eq!(replies.dropped(), 4);
    assert!(
        replies.admit(source(2), 0),
        "another source keeps its budget"
    );
    // 1/16 s later one more token.
    assert!(replies.admit(source(1), SECOND / 16));
    assert!(!replies.admit(source(1), SECOND / 16));
    assert_eq!(RttReplies::service_delay(10, 25), 15);
    assert_eq!(RttReplies::service_delay(25, 10), 0);
}

/// The source table is bounded: a new source beyond it is dropped and
/// counted until an entry has been idle for a second.
#[test]
fn the_reply_sources_are_bounded() {
    let mut replies = RttReplies::new(&RttConfig {
        rttm_reply_sources: 2,
        ..RttConfig::default()
    })
    .unwrap();
    assert!(replies.admit(source(1), 0));
    assert!(replies.admit(source(2), 0));
    assert!(!replies.admit(source(3), 0));
    assert_eq!(replies.sources_full(), 1);
    assert!(replies.admit(source(3), SECOND));
}
