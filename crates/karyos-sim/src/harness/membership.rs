// SPDX-License-Identifier: Apache-2.0

//! Phase 5 membership scenarios (quantstratum-docs:
//! karyos/design/phase-5-cluster-scenarios.md §4, ADR-0054, SPEC.md §13
//! "Membership change safety"), as [`Case`]s for [`super::workloads::run`]
//! and [`super::workloads::pass`], whose safety includes
//! [`super::check::membership`].
//!
//! This is batch P5-S1: the scenarios a fixed leader can run (M1, M5 and
//! M8), so the reference fixture exercises the harness and its checks
//! before a core with elections exists. The others (M2 to M4, M6, M7)
//! need elections and come with the chosen core (C6).

use super::core::Change;
use super::workloads::{Action, Case, Progress};

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
