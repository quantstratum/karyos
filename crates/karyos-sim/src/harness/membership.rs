// SPDX-License-Identifier: Apache-2.0

//! Phase 5 membership scenarios (quantstratum-docs:
//! karyos/design/phase-5-cluster-scenarios.md §4, ADR-0054, SPEC.md §13
//! "Membership change safety"), as [`Case`]s for [`super::workloads::run`]
//! and [`super::workloads::pass`], whose safety includes
//! [`super::check::membership`].
//!
//! Batch P5-S1 is the scenarios a fixed leader can run (M1, M5 and M8),
//! so the reference fixture exercises the harness and its checks. The
//! others (M2, M3, M4, M6 and M7) need elections, and run against the
//! custom core (ADR-0121, karyos#712). Their schedules act on whichever
//! server leads ([`Action::Leader`]) and queue changes until they hold
//! ([`Action::Ensure`]), since the leader is elected, not fixed.

use super::core::Change;
use super::workloads::{Action, Case, LeaderAction, Progress};
use crate::disk::Survives;

/// The spare that joins in every scenario: the first id after three
/// bootstrap voters.
pub const SPARE: u32 = 3;

/// The step at which M1 splits the leader and the learner from the other
/// voters, while clients still have requests to send.
pub const M1_SPLIT: u64 = 8;

/// M1, add and promote: a spare joins as a learner under load and is
/// promoted once caught up. Before the promotion the leader and the
/// learner are split from the two other voters: they are no majority of
/// the voters, so nothing commits until the split heals; a core that
/// counted the learner would commit.
#[must_use]
pub fn m1() -> Case {
    let mut case = Case::healthy("M1 add and promote", 3, 2, 12);
    case.spares = 1;
    case.retry_after = 60;
    case.schedule = vec![
        (1, Action::Join(SPARE)),
        (2, Action::Change(Change::AddLearner(SPARE))),
        (
            M1_SPLIT,
            Action::Split {
                left: vec![0, SPARE],
                right: vec![1, 2],
            },
        ),
        (120, Action::Heal),
        (240, Action::Change(Change::Promote(SPARE))),
    ];
    case.steps = 900;
    case
}

/// The step of M5's early promotion, which the leader must refuse.
pub const M5_EARLY: u64 = 150;
/// The step of M5's promotion after the learner caught up.
pub const M5_LATE: u64 = 420;

/// M5, lagging learner: a spare joins and becomes a learner while cut off
/// from the cluster; the commit moves on under load; a promotion then is
/// refused as lagging, and accepted after the link heals and the learner
/// catches up.
#[must_use]
pub fn m5() -> Case {
    let mut case = Case::healthy("M5 lagging learner", 3, 2, 8);
    case.spares = 1;
    case.schedule = vec![
        (5, Action::Join(SPARE)),
        (6, Action::Isolate(SPARE)),
        (7, Action::Change(Change::AddLearner(SPARE))),
        (M5_EARLY, Action::Change(Change::Promote(SPARE))),
        (300, Action::Heal),
        (M5_LATE, Action::Change(Change::Promote(SPARE))),
    ];
    case.steps = 900;
    case
}

/// M8, restart rebuilds the configuration: the leader, cut off from the
/// other voters, appends a configuration entry that holds durably on it
/// alone; every voter crashes and restarts before it commits. Each must
/// come back under the latest configuration its log holds, the leader
/// under the uncommitted one; after the heal it commits.
#[must_use]
pub fn m8() -> Case {
    let mut case = Case::healthy("M8 restart rebuilds the configuration", 3, 2, 4);
    case.spares = 1;
    case.retry_after = 60;
    case.schedule = vec![
        (10, Action::Isolate(0)),
        (12, Action::Change(Change::AddLearner(SPARE))),
        (30, Action::Crash(0)),
        (30, Action::Crash(1)),
        (30, Action::Crash(2)),
        (40, Action::Restart(0)),
        (40, Action::Restart(1)),
        (40, Action::Restart(2)),
        (45, Action::Heal),
    ];
    case.steps = 900;
    // Requests the crashed leader held are retried; progress is expected
    // once it is back and healed.
    case.progress = Progress::Expected;
    case
}

/// M1, M5 and M8.
#[must_use]
pub fn cases() -> Vec<Case> {
    vec![m1(), m5(), m8()]
}

/// The step from which the election-driven scenarios act: a leader has
/// been elected and has committed an entry of its term.
pub const SETTLED: u64 = 100;

/// M2, remove a follower, then the leader: five voters; the leader removes
/// a follower, then itself. It steps down once its removal commits, and
/// the three left elect a leader of their own.
#[must_use]
pub fn m2() -> Case {
    let mut case = Case::healthy("M2 remove a follower, then the leader", 5, 2, 16);
    case.retry_after = 60;
    case.schedule = vec![
        (SETTLED, Action::Leader(LeaderAction::RemoveFollower)),
        (SETTLED + 150, Action::Leader(LeaderAction::Remove)),
    ];
    case.steps = 900;
    case
}

/// M3, a change under a partition: five voters and a spare. The leader
/// and one other server are split from the other three, a majority, and
/// the leader takes a change (`remove` a voter if set, else add the spare
/// as a learner) it can never commit. The majority elects a leader of its
/// own; after the heal the minority's change is truncated everywhere.
#[must_use]
pub fn m3(remove: bool) -> Case {
    let name = if remove {
        "M3 removal under a partition"
    } else {
        "M3 addition under a partition"
    };
    let mut case = Case::healthy(name, 5, 2, 16);
    case.spares = 1;
    case.retry_after = 60;
    let spare = 5;
    let change = if remove {
        Action::Leader(LeaderAction::RemoveFollower)
    } else {
        Action::Change(Change::AddLearner(spare))
    };
    case.schedule = vec![
        (1, Action::Join(spare)),
        (SETTLED, Action::Leader(LeaderAction::Split { with: 1 })),
        (SETTLED + 1, change),
        (SETTLED + 200, Action::Heal),
    ];
    case.steps = 900;
    case
}

/// How far a configuration entry got when M4 crashes the leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Durable on the leader alone: it was cut from every other server.
    Leader,
    /// Durable on a majority, which the leader never heard of: every
    /// acknowledgement to it was cut.
    Majority,
    /// Committed.
    Committed,
}

/// M4, a leader crash in the middle of a change: five voters and a spare;
/// the leader takes a change, which reaches `reach` before the leader
/// crashes, every disk keeping what `survives` says. Later leaders keep
/// the change everywhere or truncate it everywhere; nothing committed is
/// lost. The crashed leader restarts after the heal.
#[must_use]
pub fn m4(reach: Reach, survives: Survives) -> Case {
    let mut case = Case::healthy("M4 leader crash mid-change", 5, 2, 16);
    case.spares = 1;
    case.retry_after = 60;
    case.survives = survives;
    let spare = 5;
    let mut schedule = vec![(1, Action::Join(spare))];
    match reach {
        Reach::Leader => schedule.push((SETTLED, Action::Leader(LeaderAction::Isolate))),
        Reach::Majority => schedule.push((SETTLED, Action::Leader(LeaderAction::MuteAcks))),
        Reach::Committed => {}
    }
    schedule.extend([
        (SETTLED + 1, Action::Change(Change::AddLearner(spare))),
        (SETTLED + 40, Action::Leader(LeaderAction::Crash)),
        (SETTLED + 240, Action::Heal),
        (SETTLED + 250, Action::Leader(LeaderAction::RestartCrashed)),
    ]);
    case.schedule = schedule;
    case.steps = 1_000;
    case
}

/// M4 at every reach under every crash mode.
#[must_use]
pub fn m4_cases(seed: u64) -> Vec<Case> {
    let mut cases = Vec::new();
    for reach in [Reach::Leader, Reach::Majority, Reach::Committed] {
        for survives in [
            Survives::Synced,
            Survives::Everything,
            Survives::Subset { seed },
        ] {
            cases.push(m4(reach, survives));
        }
    }
    cases
}

/// The spares of M6, which replace voters 0, 1 and 2 in order.
pub const M6_SPARES: [u32; 3] = [3, 4, 5];

/// M6, a rolling replacement: three voters and three spares; each voter in
/// turn is replaced (its spare added, promoted, then the voter removed)
/// under load, while servers crash and restart at times `seed` draws.
/// Every change is queued until it holds ([`Action::Ensure`]).
#[must_use]
pub fn m6(seed: u64) -> Case {
    let mut case = Case::healthy("M6 rolling replacement", 3, 2, 40);
    case.spares = M6_SPARES.len();
    case.retry_after = 60;
    let mut schedule: Vec<(u64, Action)> = M6_SPARES
        .iter()
        .map(|&spare| (1, Action::Join(spare)))
        .collect();
    for (old, &spare) in M6_SPARES.iter().enumerate() {
        let old = u32::try_from(old).unwrap_or(u32::MAX);
        schedule.extend([
            (SETTLED, Action::Ensure(Change::AddLearner(spare))),
            (SETTLED, Action::Ensure(Change::Promote(spare))),
            (SETTLED, Action::Ensure(Change::Remove(old))),
        ]);
    }
    // A crash every 150 to 300 steps, of a server the seed picks, each
    // restarted 60 steps later.
    let mut state = seed | 1;
    let mut draw = |bound: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % bound
    };
    let mut at = SETTLED + 50;
    while at < 2_000 {
        let server = u32::try_from(draw(6)).unwrap_or(0);
        schedule.push((at, Action::Crash(server)));
        schedule.push((at + 60, Action::Restart(server)));
        at += 150 + draw(150);
    }
    case.schedule = schedule;
    case.steps = 3_000;
    case
}

/// M7, the single-server errata: five voters and two spares. The leader,
/// hearing no acknowledgement, takes a change and crashes. The next
/// leader is muted the step it is seen leading, so it commits nothing of
/// its term, and is asked for a second change at once, which the errata
/// refuse (`InProgress`). Once healed, the second change is taken.
#[must_use]
pub fn m7() -> Case {
    let mut case = Case::healthy("M7 single-server errata", 5, 2, 16);
    case.spares = 2;
    case.retry_after = 60;
    case.progress = Progress::Expected;
    case.schedule = vec![
        (1, Action::Join(5)),
        (1, Action::Join(6)),
        (SETTLED, Action::Leader(LeaderAction::MuteAcks)),
        (SETTLED + 1, Action::Change(Change::AddLearner(5))),
        (SETTLED + 10, Action::Leader(LeaderAction::Crash)),
        (
            SETTLED + 11,
            Action::Leader(LeaderAction::MuteNextLeaderAcks),
        ),
        (SETTLED + 12, Action::Change(Change::AddLearner(6))),
        (SETTLED + 300, Action::Heal),
        (SETTLED + 310, Action::Leader(LeaderAction::RestartCrashed)),
        (SETTLED + 320, Action::Ensure(Change::AddLearner(6))),
    ];
    case.steps = 1_200;
    case
}
