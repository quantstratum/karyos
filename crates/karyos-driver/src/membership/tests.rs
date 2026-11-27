// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use std::net::{IpAddr, Ipv4Addr};

use karyos_protocol::network::{LaneStatus, Lanes};

use super::*;

const MS: u64 = 1_000_000;
const SECOND: u64 = 1_000_000_000;
const TIMEOUT: u64 = 5 * SECOND;
const PAUSE: u64 = 60 * SECOND;

fn identity(incarnation: u64) -> Identity {
    Identity {
        driver_id: [1, 2],
        registration_id: 3,
        incarnation,
    }
}

fn receiver(id: u64, boot: u64) -> Receiver {
    Receiver {
        receiver_boot_id: [boot, 9],
        receiver_id: id,
    }
}

fn alias() -> Alias {
    Alias {
        session_id: 5,
        stream_id: 6,
    }
}

/// `receiver`'s binding through endpoint `path` from its own address.
fn path(receiver: Receiver, path: u32) -> SmKey {
    SmKey {
        endpoint: EndpointId(path),
        alias: alias(),
        source: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                10,
                0,
                0,
                u8::try_from(receiver.receiver_id).unwrap(),
            )),
            40_000,
        ),
        identity: identity(1),
        receiver,
    }
}

/// Takes `sm` through its receiver's first path.
fn status(table: &mut Membership, sm: &StatusMessage, now: u64) -> StatusOutcome {
    table.status(&path(sm.receiver, 1), sm, now)
}

fn lane(lane: u8) -> Lane {
    Lane::try_new(lane).unwrap()
}

/// An SM of receiver `id` (boot 1) with `(consumption, window)` per lane.
fn sm(id: u64, lanes: &[(u64, u32)]) -> StatusMessage {
    sm_from(receiver(id, 1), 0, lanes)
}

fn sm_from(receiver: Receiver, group_tag: u64, lanes: &[(u64, u32)]) -> StatusMessage {
    let status: Vec<LaneStatus> = lanes
        .iter()
        .map(|&(consumption, window)| LaneStatus {
            consumption,
            window,
        })
        .collect();
    StatusMessage {
        alias: alias(),
        identity: identity(1),
        receiver,
        group_tag,
        lanes: Lanes::new(&status).unwrap(),
    }
}

fn config(lanes: u8) -> MembershipConfig {
    MembershipConfig::new(lanes, 10, 1 << 20)
}

fn table(config: MembershipConfig, roles: &Roles<'_>) -> Membership {
    let mut table = Membership::new(config, identity(1), alias(), roles, 0).unwrap();
    for at in 0..config.lane_count {
        assert!(table.advance_sent(lane(at), 1 << 30));
    }
    table
}

fn accepted(outcome: StatusOutcome) -> (MemberRef, bool, bool) {
    match outcome {
        StatusOutcome::Accepted {
            member,
            joined,
            fresh,
        } => (member, joined, fresh),
        StatusOutcome::Rejected(reason) => panic!("rejected: {reason:?}"),
    }
}

fn rejected(outcome: StatusOutcome) -> StatusRejected {
    match outcome {
        StatusOutcome::Rejected(reason) => reason,
        StatusOutcome::Accepted { .. } => panic!("accepted"),
    }
}

fn events(table: &mut Membership) -> Vec<MemberEvent> {
    let mut out = Vec::new();
    table.drain_events(|event| out.push(event));
    out
}

#[test]
fn the_configuration_is_validated() {
    let base = config(2);
    assert_eq!(base.validate(), Ok(()));
    for (bad, error) in [
        (
            MembershipConfig {
                max_receivers: 0,
                ..base
            },
            MembershipConfigError::Capacity,
        ),
        (
            MembershipConfig {
                max_pending: 65,
                ..base
            },
            MembershipConfigError::Capacity,
        ),
        (
            MembershipConfig {
                max_paths: 0,
                ..base
            },
            MembershipConfigError::Paths,
        ),
        (
            MembershipConfig {
                max_paths: MAX_PATHS + 1,
                ..base
            },
            MembershipConfigError::Paths,
        ),
        (
            MembershipConfig {
                lane_count: 5,
                ..base
            },
            MembershipConfigError::Lanes,
        ),
        (
            MembershipConfig {
                min_window: 0,
                ..base
            },
            MembershipConfigError::Window,
        ),
        (
            MembershipConfig {
                min_window: 2 << 20,
                ..base
            },
            MembershipConfigError::Window,
        ),
        (
            MembershipConfig {
                receiver_timeout: 10 * base.sm_interval - 1,
                ..base
            },
            MembershipConfigError::Timeouts,
        ),
        (
            MembershipConfig {
                pause_timeout: base.receiver_timeout - 1,
                ..base
            },
            MembershipConfigError::Timeouts,
        ),
        (
            MembershipConfig {
                sm_interval: u64::MAX,
                ..base
            },
            MembershipConfigError::Timeouts,
        ),
        (
            MembershipConfig {
                strategy: Strategy::Tagged(0),
                ..base
            },
            MembershipConfigError::Tag,
        ),
    ] {
        assert_eq!(bad.validate(), Err(error), "{bad:?}");
    }
    for roles in [
        Roles {
            required: &[1, 1],
            tags: &[],
        },
        Roles {
            required: &[0],
            tags: &[],
        },
        Roles {
            required: &[],
            tags: &[(1, 0)],
        },
        Roles {
            required: &[],
            tags: &[(1, 7), (1, 8)],
        },
    ] {
        assert_eq!(
            Membership::new(base, identity(1), alias(), &roles, 0).err(),
            Some(MembershipConfigError::Roles)
        );
    }
}

/// karyos#637 review: the counts are checked before either list is read,
/// and repeats by sorting a copy, so a long list costs no quadratic walk.
/// One receiver more than the table is refused although every id is
/// distinct and nonzero, which only the count refuses; a full table of
/// each, one receiver both required and tagged, is accepted; a repeat at
/// both ends of a full list is refused, also past the stack buffer.
#[test]
fn roles_are_bounded_before_they_are_read() {
    let max = DEFAULT_MAX_RECEIVERS;
    let full = usize::from(max);
    let ids: Vec<u64> = (1..=u64::from(max) + 1).collect();
    let pairs: Vec<(u64, u64)> = ids.iter().map(|&id| (id, 9)).collect();
    let check = |required: &[u64], tags: &[(u64, u64)], max: u16| {
        check_roles(&Roles { required, tags }, max)
    };
    let refused = Err(MembershipConfigError::Roles);
    assert_eq!(check(&ids, &[], max), refused);
    assert_eq!(check(&[], &pairs, max), refused);
    let (ids_full, pairs_full) = (ids.get(..full).unwrap(), pairs.get(..full).unwrap());
    assert_eq!(check(ids_full, pairs_full, max), Ok(()));
    let mut repeated = ids_full.to_vec();
    *repeated.last_mut().unwrap() = 1;
    assert_eq!(check(&repeated, &[], max), refused);
    let mut repeated = pairs_full.to_vec();
    *repeated.last_mut().unwrap() = (1, 9);
    assert_eq!(check(&[], &repeated, max), refused);
    // A configured table past the stack buffer.
    let wide = 4 * max;
    let ids: Vec<u64> = (1..=u64::from(wide)).collect();
    assert_eq!(check(&ids, &[], wide), Ok(()));
    let mut repeated = ids;
    *repeated.last_mut().unwrap() = 1;
    assert_eq!(check(&repeated, &[], wide), refused);
}

/// The design's example: A at 100 with window 100 (edge 200), B at 150
/// with window 10 (edge 160). The extrema are of the edges, and a required
/// B bounds every strategy.
#[test]
fn edges_are_checked_sums_and_required_members_bound_every_strategy() {
    for (strategy, required, expected) in [
        (Strategy::Min, &[][..], 160),
        (Strategy::Max, &[][..], 200),
        (Strategy::Max, &[2][..], 160),
        (Strategy::Min, &[1][..], 160),
    ] {
        let mut table = table(
            MembershipConfig {
                strategy,
                ..config(1)
            },
            &Roles {
                required,
                tags: &[],
            },
        );
        accepted(status(&mut table, &sm(1, &[(100, 100)]), 0));
        accepted(status(&mut table, &sm(2, &[(150, 10)]), 0));
        assert_eq!(
            table.limit(lane(0), 0),
            Limit::Edge(expected),
            "{strategy:?}"
        );
    }
}

/// Positions are per lane: no lane's edge uses another lane's values.
#[test]
fn every_lane_has_its_own_edge() {
    let mut table = table(config(2), &Roles::default());
    accepted(status(&mut table, &sm(1, &[(100, 10), (5, 1000)]), 0));
    accepted(status(&mut table, &sm(2, &[(50, 20), (7, 10)]), 0));
    assert_eq!(table.limit(lane(0), 0), Limit::Edge(70));
    assert_eq!(table.limit(lane(1), 0), Limit::Edge(17));
    assert_eq!(table.limit(lane(2), 0), Limit::NoReceiverWindow);
}

/// A tagged strategy uses only configured members of its tag; a required
/// member outside the tag still bounds it; a tagged group with no live
/// member gives no window even while an untagged required member is live.
#[test]
fn a_tagged_group_never_falls_back() {
    let mut table = table(
        MembershipConfig {
            strategy: Strategy::Tagged(7),
            ..config(1)
        },
        &Roles {
            required: &[3],
            tags: &[(1, 7), (2, 7)],
        },
    );
    accepted(status(&mut table, &sm(3, &[(0, 100)]), 0));
    assert_eq!(table.limit(lane(0), 0), Limit::NoReceiverWindow);
    accepted(status(
        &mut table,
        &sm_from(receiver(1, 1), 7, &[(100, 100)]),
        0,
    ));
    accepted(status(
        &mut table,
        &sm_from(receiver(2, 1), 7, &[(100, 50)]),
        0,
    ));
    assert_eq!(
        table.limit(lane(0), 0),
        Limit::Edge(100),
        "required 3 bounds"
    );
    accepted(status(&mut table, &sm(3, &[(80, 100)]), 20 * MS));
    assert_eq!(
        table.limit(lane(0), 20 * MS),
        Limit::Edge(150),
        "tag minimum"
    );
    // The tagged members expire; the required one stays live.
    accepted(status(&mut table, &sm(3, &[(90, 100)]), TIMEOUT));
    assert_eq!(table.limit(lane(0), TIMEOUT), Limit::NoReceiverWindow);
    assert!(table.connected(TIMEOUT));
}

/// MC-2: a declared tag other than the configured one rejects the SM whole,
/// and a receiver cannot join a group by declaring its tag.
#[test]
fn a_declared_tag_cannot_choose_a_group() {
    let mut table = table(
        MembershipConfig {
            strategy: Strategy::Tagged(7),
            ..config(1)
        },
        &Roles {
            required: &[],
            tags: &[(1, 7)],
        },
    );
    assert_eq!(
        rejected(status(
            &mut table,
            &sm_from(receiver(2, 1), 7, &[(0, 100)]),
            0
        )),
        StatusRejected::Tag
    );
    assert_eq!(
        rejected(status(
            &mut table,
            &sm_from(receiver(1, 1), 0, &[(0, 100)]),
            0
        )),
        StatusRejected::Tag
    );
    assert_eq!(table.limit(lane(0), 0), Limit::NoReceiverWindow);
    assert_eq!(table.counters().tag, 2);
}

/// MC-3 and MC-4: no member means no window and no connection.
#[test]
fn an_empty_table_grants_nothing() {
    let table = table(config(4), &Roles::default());
    for at in 0..4 {
        assert_eq!(table.limit(lane(at), 0), Limit::NoReceiverWindow);
    }
    assert!(!table.connected(0));
    assert_eq!(table.admission(0), Admission::Open);
    assert_eq!(table.retention(lane(0)), None);
}

/// MC-5: the join fixes the window within bounds; a changed window, a
/// lower consumption, a consumption above `sent_high` or an overflowing
/// edge rejects the whole SM and refreshes nothing.
#[test]
fn credit_violations_reject_the_whole_sm() {
    let mut table = Membership::new(config(2), identity(1), alias(), &Roles::default(), 0).unwrap();
    assert!(table.advance_sent(lane(0), 1000));
    assert!(table.advance_sent(lane(1), u64::MAX));
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(0, 9), (0, 100)]), 0)),
        StatusRejected::Window
    );
    assert_eq!(
        rejected(status(
            &mut table,
            &sm(1, &[(0, 100), (0, (1 << 20) + 1)]),
            0
        )),
        StatusRejected::Window
    );
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(1001, 100), (0, 100)]), 0)),
        StatusRejected::Beyond
    );
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(0, 100), (u64::MAX, 100)]), 0)),
        StatusRejected::Overflow
    );
    let (member, joined, fresh) = accepted(status(&mut table, &sm(1, &[(500, 100), (5, 100)]), 0));
    assert!(joined && fresh);
    for (bad, reason) in [
        (
            sm(1, &[(600, 101), (5, 100)]),
            StatusRejected::WindowChanged,
        ),
        (sm(1, &[(600, 99), (5, 100)]), StatusRejected::WindowChanged),
        (sm(1, &[(499, 100), (6, 100)]), StatusRejected::Stale),
        (sm(1, &[(1001, 100), (6, 100)]), StatusRejected::Beyond),
        (sm(1, &[(600, 100)]), StatusRejected::Lanes),
    ] {
        assert_eq!(rejected(status(&mut table, &bad, TIMEOUT - 1)), reason);
    }
    let mut other = sm(1, &[(600, 100), (5, 100)]);
    other.identity = identity(2);
    let mut key = path(other.receiver, 1);
    key.identity = other.identity;
    assert_eq!(
        rejected(table.status(&key, &other, TIMEOUT - 1)),
        StatusRejected::Identity
    );
    // Nothing refreshed: the member expires at its join's timeout.
    assert_eq!(table.limit(lane(0), TIMEOUT - 1), Limit::Edge(600));
    assert_eq!(table.limit(lane(0), TIMEOUT), Limit::NoReceiverWindow);
    assert!(table.current(member));
    let counts = table.counters();
    assert_eq!(
        (
            counts.window,
            counts.window_changed,
            counts.stale,
            counts.beyond,
            counts.overflow,
            counts.lanes,
            counts.identity
        ),
        (2, 2, 1, 2, 1, 1, 1)
    );
}

/// ACS 15604 and 15610: an advance or a caught-up report is fresh; an
/// unchanged state behind `sent_high` is stationary and keeps the member
/// only until `pause_timeout` after its last fresh SM.
#[test]
fn stationary_sms_keep_a_member_only_until_pause_timeout() {
    let mut table = Membership::new(config(1), identity(1), alias(), &Roles::default(), 0).unwrap();
    assert!(table.advance_sent(lane(0), 100));
    accepted(status(&mut table, &sm(1, &[(50, 100)]), 0));
    let (_, _, fresh) = accepted(status(&mut table, &sm(1, &[(60, 100)]), SECOND));
    assert!(fresh, "advanced");
    let (_, _, fresh) = accepted(status(&mut table, &sm(1, &[(60, 100)]), 2 * SECOND));
    assert!(!fresh, "stationary");
    // Stationary SMs keep it past receiver_timeout from the last fresh one.
    let mut now = 2 * SECOND;
    while now < SECOND + PAUSE - SECOND {
        now += SECOND;
        let (_, _, fresh) = accepted(status(&mut table, &sm(1, &[(60, 100)]), now));
        assert!(!fresh);
        assert_eq!(table.limit(lane(0), now), Limit::Edge(160));
    }
    assert!(table.connected(SECOND + PAUSE - 1));
    assert!(!table.connected(SECOND + PAUSE), "pause_timeout reached");
    let counts = *table.counters();
    assert_eq!(counts.fresh, 2);
    assert!(counts.stationary > counts.paused && counts.paused > 0);
}

/// A caught-up member stays live on unchanged SMs, so an idle group is not
/// lost. By rule (ii) of ACS 15604 and 15610 this also lets a replay of a
/// dead member's caught-up SM keep it live while the sender is idle: the
/// documented residual risk of the trusted profile, harmless because a
/// caught-up member holds nothing back.
#[test]
fn a_caught_up_member_stays_live_even_on_replays() {
    let mut table = Membership::new(config(2), identity(1), alias(), &Roles::default(), 0).unwrap();
    assert!(table.advance_sent(lane(0), 100));
    assert!(table.advance_sent(lane(1), 7));
    accepted(status(&mut table, &sm(1, &[(100, 100), (7, 100)]), 0));
    for step in 1..=100 {
        let (_, joined, fresh) = accepted(status(
            &mut table,
            &sm(1, &[(100, 100), (7, 100)]),
            step * SECOND,
        ));
        assert!(fresh && !joined);
    }
    assert!(
        table.connected(100 * SECOND + TIMEOUT - 1),
        "past pause_timeout"
    );
    // Once the sender moves on, the same SM is stationary.
    assert!(table.advance_sent(lane(1), 8));
    let (_, _, fresh) = accepted(status(
        &mut table,
        &sm(1, &[(100, 100), (7, 100)]),
        101 * SECOND,
    ));
    assert!(!fresh);
    assert!(!table.advance_sent(lane(1), 7), "sent_high never decreases");
    assert!(!table.advance_sent(lane(2), 7), "outside the publication");
    assert_eq!(table.counters().sent_regressed, 2);
}

/// Expiry is exact at `receiver_timeout` and judged when asked, before the
/// timers reach the entry; a clock read behind the last SM expires nothing.
#[test]
fn expiry_is_exact_and_needs_no_sweep() {
    let mut table = table(config(1), &Roles::default());
    accepted(status(&mut table, &sm(1, &[(0, 100)]), 10 * SECOND));
    assert!(table.connected(10 * SECOND + TIMEOUT - 1));
    assert!(!table.connected(10 * SECOND + TIMEOUT));
    assert_eq!(
        table.limit(lane(0), 10 * SECOND + TIMEOUT),
        Limit::NoReceiverWindow
    );
    assert!(table.connected(SECOND), "a backward clock expires nothing");
    assert_eq!(table.counters().expired, 0, "not swept yet");
}

/// An optional member expires with an event and leaves; its return is a new
/// membership with a new generation and join point, and old work naming
/// the old generation is no longer current.
#[test]
fn an_expired_optional_member_rejoins_as_a_new_membership() {
    let mut table = table(config(1), &Roles::default());
    let (first, _, _) = accepted(status(&mut table, &sm(1, &[(500, 100)]), 0));
    assert_eq!(table.timers(TIMEOUT, 64), 64);
    assert_eq!(table.counters().expired, 1);
    assert!(!table.current(first));
    let all = events(&mut table);
    assert!(matches!(all[0], MemberEvent::Joined { joins, .. } if joins[0] == 500));
    assert_eq!(
        all[1],
        MemberEvent::Expired {
            member: first,
            receiver: receiver(1, 1),
            consumption: [500, 0, 0, 0],
        }
    );
    // A delayed older SM cannot rejoin below the tombstone (ACS 15647).
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(400, 100)]), TIMEOUT + 1)),
        StatusRejected::Expired
    );
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(500, 100)]), TIMEOUT + 2)),
        StatusRejected::Expired,
        "stationary"
    );
    // An advance is fresh against the tombstone: a new join point.
    let (second, joined, _) = accepted(status(&mut table, &sm(1, &[(600, 100)]), TIMEOUT + 3));
    assert!(joined);
    assert_eq!(second.slot, first.slot);
    assert_eq!(second.generation, first.generation + 1);
    assert!(!table.current(first) && table.current(second));
}

/// A late SM of an expired member that the timers have not reached yet
/// still finds it expired: an optional one rejoins, a required one is lost.
#[test]
fn an_sm_after_the_deadline_cannot_revive_a_member() {
    let mut table = table(
        config(1),
        &Roles {
            required: &[1],
            tags: &[],
        },
    );
    accepted(status(&mut table, &sm(1, &[(0, 100)]), 0));
    accepted(status(&mut table, &sm(2, &[(0, 100)]), 0));
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(10, 100)]), TIMEOUT)),
        StatusRejected::Lost
    );
    let (_, joined, _) = accepted(status(&mut table, &sm(2, &[(10, 100)]), TIMEOUT));
    assert!(joined);
    assert_eq!(table.counters().lost_required, 1);
    assert_eq!(table.counters().expired, 1);
}

/// Owner decisions M4 and M5: admission opens once the required set has
/// joined; a required loss holds every lane and stops admission for the
/// incarnation, keeping the member's last consumption for retention; a new
/// boot id of a required receiver is refused.
#[test]
fn a_required_loss_holds_the_incarnation() {
    let mut table = table(
        config(2),
        &Roles {
            required: &[1, 2],
            tags: &[],
        },
    );
    assert_eq!(table.admission(0), Admission::NotJoined);
    accepted(status(&mut table, &sm(1, &[(40, 100), (4, 100)]), 0));
    assert_eq!(table.admission(0), Admission::NotJoined);
    accepted(status(&mut table, &sm(2, &[(30, 100), (9, 100)]), 0));
    accepted(status(&mut table, &sm(3, &[(10, 100), (1, 100)]), 0));
    assert_eq!(table.admission(0), Admission::Open);
    assert_eq!(table.retention(lane(0)), Some(30));
    assert_eq!(table.retention(lane(1)), Some(4));
    assert_eq!(table.limit(lane(0), 0), Limit::Edge(110));

    assert_eq!(
        rejected(status(
            &mut table,
            &sm_from(receiver(1, 2), 0, &[(0, 100), (0, 100)]),
            SECOND
        )),
        StatusRejected::BootChanged
    );
    accepted(status(&mut table, &sm(1, &[(90, 100), (9, 100)]), SECOND));
    accepted(status(&mut table, &sm(3, &[(90, 100), (9, 100)]), SECOND));
    // Receiver 2 stops: lost at its deadline, even before the sweep.
    assert_eq!(table.admission(TIMEOUT), Admission::LostRequired);
    assert_eq!(table.limit(lane(0), TIMEOUT), Limit::Held);
    assert_eq!(table.limit(lane(1), TIMEOUT), Limit::Held);
    table.timers(TIMEOUT, 64);
    assert_eq!(table.retention(lane(0)), Some(30), "kept for retention");
    assert_eq!(table.admission(TIMEOUT + SECOND), Admission::LostRequired);
    assert!(events(&mut table).contains(&MemberEvent::LostRequired {
        member: MemberRef {
            slot: 1,
            generation: 1
        },
        receiver: receiver(2, 1),
        consumption: [30, 9, 0, 0],
    }));
    // No return within the incarnation, nor through a new boot.
    assert_eq!(
        rejected(status(
            &mut table,
            &sm(2, &[(30, 100), (9, 100)]),
            TIMEOUT + SECOND
        )),
        StatusRejected::Lost
    );
    assert_eq!(
        table.expect(&path(receiver(2, 1), 1), &[0], TIMEOUT + SECOND),
        Err(StatusRejected::Lost)
    );
    assert_eq!(
        rejected(status(
            &mut table,
            &sm_from(receiver(2, 3), 0, &[(0, 100), (0, 100)]),
            TIMEOUT + SECOND
        )),
        StatusRejected::BootChanged
    );
}

/// A required receiver that never joins keeps admission closed and is
/// reported once after `join_timeout`; an expected entry without an SM is
/// removed then.
#[test]
fn a_required_member_that_never_joins_is_reported_once() {
    let mut table = table(
        config(1),
        &Roles {
            required: &[1, 2],
            tags: &[],
        },
    );
    let pending = table.expect(&path(receiver(2, 1), 1), &[0], 0).unwrap();
    assert_eq!(
        table.expect(&path(receiver(2, 1), 1), &[0], SECOND),
        Ok(pending),
        "no extension"
    );
    assert_eq!(table.timers(TIMEOUT - 1, 64), 64);
    assert!(events(&mut table).is_empty());
    table.timers(TIMEOUT, 64);
    table.timers(2 * TIMEOUT, 64);
    assert_eq!(
        events(&mut table),
        [
            MemberEvent::NotJoined { receiver_id: 1 },
            MemberEvent::NotJoined { receiver_id: 2 }
        ]
    );
    assert_eq!(table.counters().join_expired, 1);
    assert!(!table.current(pending));
    assert_eq!(table.admission(2 * TIMEOUT), Admission::NotJoined);
}

/// The pending limit, the table size and the room reserved for required
/// receivers refuse newcomers; nothing is evicted.
#[test]
fn a_full_table_refuses_without_evicting() {
    let mut table = table(
        MembershipConfig {
            max_receivers: 3,
            max_pending: 1,
            ..config(1)
        },
        &Roles {
            required: &[9],
            tags: &[],
        },
    );
    table.expect(&path(receiver(1, 1), 1), &[0], 0).unwrap();
    assert_eq!(
        table.expect(&path(receiver(2, 1), 1), &[0], 0),
        Err(StatusRejected::PendingFull)
    );
    accepted(status(&mut table, &sm(2, &[(0, 100)]), 0));
    assert_eq!(
        rejected(status(&mut table, &sm(3, &[(0, 100)]), 0)),
        StatusRejected::TableFull,
        "the last slot is reserved for receiver 9"
    );
    accepted(status(&mut table, &sm(9, &[(0, 100)]), 0));
    accepted(status(&mut table, &sm(1, &[(0, 100)]), 0));
    assert_eq!(table.counters().table_full, 1);
    assert_eq!(table.counters().pending_full, 1);
}

/// A slot whose generation is exhausted is retired, never wrapped.
#[test]
fn an_exhausted_generation_retires_its_slot() {
    let mut table = table(
        MembershipConfig {
            max_receivers: 2,
            max_pending: 2,
            ..config(1)
        },
        &Roles::default(),
    );
    table.entries[0].generation = u64::MAX;
    let (member, _, _) = accepted(status(&mut table, &sm(1, &[(0, 100)]), 0));
    assert_eq!(
        member,
        MemberRef {
            slot: 1,
            generation: 1
        }
    );
    assert_eq!(table.counters().retired_slots, 1);
    assert_eq!(
        rejected(status(&mut table, &sm(2, &[(0, 100)]), 0)),
        StatusRejected::TableFull
    );
}

/// A copy of an accepted SM from a second path changes no bound.
#[test]
fn a_duplicate_sm_changes_nothing_more() {
    let mut table = table(config(1), &Roles::default());
    accepted(status(&mut table, &sm(1, &[(100, 100)]), 0));
    accepted(status(&mut table, &sm(1, &[(150, 100)]), MS));
    let (_, joined, fresh) = accepted(status(&mut table, &sm(1, &[(150, 100)]), MS));
    assert!(!joined && !fresh);
    assert_eq!(table.limit(lane(0), MS), Limit::Edge(250));
    assert_eq!(table.retention(lane(0)), None);
}

/// MC-9 and ACS 15636: one receiver over two paths is one member; a
/// binding beyond `max_paths` is refused while its SM still applies.
#[test]
fn a_receiver_over_several_paths_is_one_member() {
    let mut table = table(
        MembershipConfig {
            max_paths: 2,
            ..config(1)
        },
        &Roles {
            required: &[1],
            tags: &[],
        },
    );
    let one = sm(1, &[(100, 100)]);
    let (first, _, _) = accepted(table.status(&path(one.receiver, 1), &one, 0));
    let (again, joined, _) = accepted(table.status(&path(one.receiver, 2), &one, 0));
    assert_eq!(first, again);
    assert!(!joined);
    accepted(status(&mut table, &sm(2, &[(50, 100)]), 0));
    assert_eq!(table.limit(lane(0), 0), Limit::Edge(150));
    assert_eq!(table.retention(lane(0)), Some(100));
    let ahead = sm(1, &[(120, 100)]);
    let (_, _, fresh) = accepted(table.status(&path(ahead.receiver, 3), &ahead, MS));
    assert!(fresh, "liveness is per member");
    assert_eq!(table.counters().paths_full, 1);
    assert_eq!(table.counters().joins, 2);
    assert_eq!(
        table.binding_gone(&path(ahead.receiver, 3), 0),
        Gone::Unknown
    );
}

/// The key must be the SM's own; a mismatch is rejected whole.
#[test]
fn a_key_of_another_receiver_is_rejected() {
    let mut table = table(config(1), &Roles::default());
    let one = sm(1, &[(0, 100)]);
    assert_eq!(
        rejected(table.status(&path(receiver(2, 1), 1), &one, 0)),
        StatusRejected::Key
    );
    let mut other = one;
    other.alias.session_id = 4;
    assert_eq!(
        rejected(table.status(&path(other.receiver, 1), &other, 0)),
        StatusRejected::Key
    );
    let mut both = path(other.receiver, 1);
    both.alias = other.alias;
    assert_eq!(
        rejected(table.status(&both, &other, 0)),
        StatusRejected::Identity
    );
    assert_eq!((table.counters().key, table.counters().identity), (2, 1));
    assert!(!table.connected(0));
}

/// ACS 15633 and 15636: a gone binding removes its member only when it was
/// the last; a required member is then lost, as at its timeout (M5).
#[test]
fn only_the_last_gone_binding_removes_a_member() {
    let mut table = table(
        config(1),
        &Roles {
            required: &[1],
            tags: &[],
        },
    );
    let one = sm(1, &[(10, 100)]);
    accepted(table.status(&path(one.receiver, 1), &one, 0));
    accepted(table.status(&path(one.receiver, 2), &one, 0));
    let two = sm(2, &[(20, 100)]);
    let (optional, _, _) = accepted(status(&mut table, &two, 0));
    assert_eq!(table.admission(0), Admission::Open);

    assert_eq!(
        table.binding_gone(&path(one.receiver, 1), 0),
        Gone::Remaining
    );
    assert_eq!(table.admission(0), Admission::Open);
    assert_eq!(table.binding_gone(&path(one.receiver, 1), 0), Gone::Unknown);
    assert_eq!(table.binding_gone(&path(two.receiver, 1), 0), Gone::Removed);
    assert!(!table.current(optional));
    assert_eq!(table.binding_gone(&path(one.receiver, 2), 0), Gone::Lost);
    assert_eq!(table.admission(0), Admission::LostRequired);
    assert_eq!(table.limit(lane(0), 0), Limit::Held);
    assert_eq!(table.retention(lane(0)), Some(10));
    let all = events(&mut table);
    assert!(matches!(all[2], MemberEvent::Expired { member, .. } if member == optional));
    assert!(
        matches!(all[3], MemberEvent::LostRequired { receiver, .. } if receiver == one.receiver)
    );
    let counts = *table.counters();
    assert_eq!((counts.bindings_gone, counts.unbound), (3, 2));
    // An expected entry that loses its only binding is removed.
    let pending = table.expect(&path(receiver(3, 1), 1), &[0], 0).unwrap();
    assert_eq!(
        table.binding_gone(&path(receiver(3, 1), 1), 0),
        Gone::Removed
    );
    assert!(!table.current(pending));
}

/// P1-1 of the #251 review (ACS 15647): a paused optional member expired
/// at `pause_timeout` does not rejoin on its stationary SMs, so the sender
/// stays unblocked; it rejoins once it advances.
#[test]
fn a_paused_member_does_not_rejoin_on_stationary_sms() {
    let mut table = Membership::new(config(1), identity(1), alias(), &Roles::default(), 0).unwrap();
    assert!(table.advance_sent(lane(0), 1000));
    accepted(status(&mut table, &sm(1, &[(100, 100)]), 0));
    accepted(status(&mut table, &sm(2, &[(900, 100)]), 0));
    let mut now = 0;
    while now < PAUSE + 10 * SECOND {
        now += 10 * MS;
        let _ = status(&mut table, &sm(1, &[(100, 100)]), now);
        accepted(status(&mut table, &sm(2, &[(1000, 100)]), now));
    }
    assert_eq!(
        table.limit(lane(0), now),
        Limit::Edge(1100),
        "only 2 bounds"
    );
    assert!(table.counters().expired_rejected > 0);
    assert_eq!(table.counters().expired, 1);
    let (_, joined, _) = accepted(status(&mut table, &sm(1, &[(101, 100)]), now + MS));
    assert!(joined);
    assert_eq!(table.limit(lane(0), now + MS), Limit::Edge(201));
}

/// A tombstone is cleared by `receiver_timeout` of silence, by a new
/// `expect` and when its slot is needed; a caught-up SM rejoins at once.
#[test]
fn a_tombstone_lifts_on_silence_expect_or_need() {
    let mut table = Membership::new(
        MembershipConfig {
            max_receivers: 2,
            max_pending: 2,
            ..config(1)
        },
        identity(1),
        alias(),
        &Roles::default(),
        0,
    )
    .unwrap();
    assert!(table.advance_sent(lane(0), 100));
    accepted(status(&mut table, &sm(1, &[(50, 100)]), 0));
    table.timers(TIMEOUT, 64);
    // Silence: a stationary SM after receiver_timeout joins afresh.
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(50, 100)]), 2 * TIMEOUT - 1)),
        StatusRejected::Expired
    );
    let (_, joined, _) = accepted(status(&mut table, &sm(1, &[(50, 100)]), 3 * TIMEOUT));
    assert!(joined, "silent since 2 * TIMEOUT - 1");
    assert_eq!(table.counters().tombstones_cleared, 1);
    // A new expect lifts it.
    table.timers(4 * TIMEOUT, 64);
    table
        .expect(&path(receiver(1, 1), 1), &[0], 4 * TIMEOUT)
        .unwrap();
    let (_, joined, _) = accepted(status(&mut table, &sm(1, &[(50, 100)]), 4 * TIMEOUT));
    assert!(joined);
    // Caught up: fresh against the tombstone.
    table.timers(5 * TIMEOUT, 64);
    let (_, joined, _) = accepted(status(&mut table, &sm(1, &[(100, 100)]), 5 * TIMEOUT));
    assert!(joined);
    // Need: with the table full of a member and a tombstone, a newcomer's
    // establishment takes the tombstone's slot.
    table.timers(6 * TIMEOUT, 64);
    accepted(status(&mut table, &sm(2, &[(0, 100)]), 6 * TIMEOUT));
    table
        .expect(&path(receiver(3, 1), 1), &[0], 6 * TIMEOUT)
        .unwrap();
    accepted(status(&mut table, &sm(3, &[(0, 100)]), 6 * TIMEOUT));
    assert_eq!(table.counters().tombstones_cleared, 2);
}

/// ACS 15663 (a): an SM-driven optional join never takes another
/// receiver's tombstone, so a member whose tombstone was taken cannot come
/// back through a second one; a new establishment, or a configured
/// required receiver, may take it.
#[test]
fn only_an_establishment_takes_another_tombstone() {
    let mut table = Membership::new(
        MembershipConfig {
            max_receivers: 4,
            max_pending: 4,
            ..config(1)
        },
        identity(1),
        alias(),
        &Roles {
            required: &[9],
            tags: &[],
        },
        0,
    )
    .unwrap();
    assert!(table.advance_sent(lane(0), 1000));
    // 1 and 2 expire into tombstones; 3 stays.
    accepted(status(&mut table, &sm(1, &[(10, 100)]), 0));
    accepted(status(&mut table, &sm(2, &[(10, 100)]), MS));
    accepted(status(&mut table, &sm(3, &[(10, 100)]), TIMEOUT));
    table.timers(TIMEOUT + MS, 64);
    assert_eq!(table.counters().expired, 2);
    // A newcomer's SM finds only the slot reserved for 9 and tombstones.
    assert_eq!(
        rejected(status(&mut table, &sm(4, &[(0, 100)]), TIMEOUT + MS)),
        StatusRejected::TableFull
    );
    // Its establishment may: it takes the free slot, and the required
    // receiver then takes the oldest tombstone, receiver 1's.
    table
        .expect(&path(receiver(4, 1), 1), &[0], TIMEOUT + MS)
        .unwrap();
    accepted(status(&mut table, &sm(4, &[(0, 100)]), TIMEOUT + MS));
    accepted(status(&mut table, &sm(9, &[(0, 100)]), TIMEOUT + MS));
    // Receiver 1, its tombstone gone, cannot come back through 2's.
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(10, 100)]), TIMEOUT + 2 * MS)),
        StatusRejected::TableFull
    );
    assert_eq!(
        rejected(status(&mut table, &sm(2, &[(10, 100)]), TIMEOUT + 2 * MS)),
        StatusRejected::Expired,
        "2's tombstone still holds"
    );
    assert_eq!(table.counters().tombstones_cleared, 1);
}

/// ACS 15663 (b): an establishment refused for the pending or table limit
/// leaves the tombstone in place.
#[test]
fn a_refused_expect_keeps_the_tombstone() {
    let mut table = Membership::new(
        MembershipConfig {
            max_receivers: 2,
            max_pending: 1,
            ..config(1)
        },
        identity(1),
        alias(),
        &Roles::default(),
        0,
    )
    .unwrap();
    assert!(table.advance_sent(lane(0), 1000));
    accepted(status(&mut table, &sm(1, &[(10, 100)]), 0));
    table.timers(TIMEOUT, 64);
    table
        .expect(&path(receiver(2, 1), 1), &[0], TIMEOUT)
        .unwrap();
    assert_eq!(
        table.expect(&path(receiver(1, 1), 1), &[0], TIMEOUT),
        Err(StatusRejected::PendingFull)
    );
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(10, 100)]), TIMEOUT + MS)),
        StatusRejected::Expired,
        "the tombstone holds"
    );
    assert_eq!(table.counters().tombstones_cleared, 0);
}

/// ACS 15663 (c): an SM that breaks credit is counted for that first, even
/// for an expired member.
#[test]
fn credit_faults_count_before_the_tombstone() {
    let mut table = table(config(1), &Roles::default());
    accepted(status(&mut table, &sm(1, &[(10, 100)]), 0));
    table.timers(TIMEOUT, 64);
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(10, 1)]), TIMEOUT + MS)),
        StatusRejected::Window
    );
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(1 << 31, 100)]), TIMEOUT + MS)),
        StatusRejected::Beyond
    );
    assert_eq!(table.counters().expired_rejected, 0);
    assert_eq!(
        rejected(status(&mut table, &sm(1, &[(10, 100)]), TIMEOUT + MS)),
        StatusRejected::Expired
    );
}

/// The timers stop at their limit and resume from their cursor.
#[test]
fn timers_are_bounded_and_fair() {
    let mut table = table(
        MembershipConfig {
            max_receivers: 4,
            max_pending: 4,
            ..config(1)
        },
        &Roles::default(),
    );
    for id in 1..=4 {
        accepted(status(&mut table, &sm(id, &[(0, 100)]), 0));
    }
    assert_eq!(table.timers(TIMEOUT, 3), 3);
    assert_eq!(table.counters().expired, 3);
    assert_eq!(table.timers(TIMEOUT, 3), 3);
    assert_eq!(table.counters().expired, 4);
    assert_eq!(table.timers(TIMEOUT, 0), 0);
}

/// A full event queue drops and marks the report incomplete.
#[test]
fn a_full_event_queue_is_sticky() {
    let mut table = table(
        MembershipConfig {
            max_events: 2,
            ..config(1)
        },
        &Roles::default(),
    );
    for id in 1..=3 {
        accepted(status(&mut table, &sm(id, &[(0, 100)]), 0));
    }
    assert_eq!(events(&mut table).len(), 2);
    assert_eq!(table.counters().events_dropped, 1);
    accepted(status(&mut table, &sm(4, &[(0, 100)]), 0));
    assert_eq!(events(&mut table).len(), 1);
    assert!(table.counters().events_incomplete);
}

/// The reference model: per lane, the strategy's extremum over the live
/// members' edges, then the minimum with every live required edge.
/// Random tables of one to four lanes and mixed roles and tags agree.
#[test]
fn limits_match_the_reference_model() {
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move |bound: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % bound
    };
    for round in 0..400 {
        let lanes = u8::try_from(1 + next(4)).unwrap();
        let strategy = match next(3) {
            0 => Strategy::Min,
            1 => Strategy::Max,
            _ => Strategy::Tagged(7),
        };
        let required: Vec<u64> = (1..=8).filter(|_| next(3) == 0).collect();
        let tags: Vec<(u64, u64)> = (1..=8)
            .filter_map(|id| (next(2) == 0).then_some((id, 7)))
            .collect();
        let mut table = table(
            MembershipConfig {
                strategy,
                ..config(lanes)
            },
            &Roles {
                required: &[],
                tags: &tags,
            },
        );
        table.required = required.clone();
        table.required_joined = vec![false; required.len()];
        table.required_reported = vec![false; required.len()];
        let mut model: Vec<(u64, Vec<u64>, u64)> = Vec::new();
        for id in 1..=8 {
            if next(4) == 0 {
                continue;
            }
            let reported: Vec<(u64, u32)> = (0..lanes)
                .map(|_| (next(1 << 20), u32::try_from(10 + next(1000)).unwrap()))
                .collect();
            let tag = tags
                .iter()
                .find(|(t, _)| *t == id)
                .map_or(0, |(_, tag)| *tag);
            let at = next(2 * TIMEOUT);
            accepted(status(
                &mut table,
                &sm_from(receiver(id, 1), tag, &reported),
                at,
            ));
            let edges = reported.iter().map(|&(c, w)| c + u64::from(w)).collect();
            model.push((id, edges, at));
        }
        let now = TIMEOUT + next(TIMEOUT);
        let age = |at: u64| age_ns(now, at);
        let live: Vec<_> = model.iter().filter(|m| age(m.2) < TIMEOUT).collect();
        for at in 0..lanes {
            let l = usize::from(at);
            let lost = model
                .iter()
                .any(|m| required.contains(&m.0) && age(m.2) >= TIMEOUT);
            let members = live.iter().filter(|m| match strategy {
                Strategy::Tagged(tag) => tags.contains(&(m.0, tag)),
                _ => true,
            });
            let edges: Vec<u64> = members.map(|m| m.1[l]).collect();
            let strategy_edge = match strategy {
                Strategy::Max => edges.iter().max(),
                _ => edges.iter().min(),
            };
            let required_edge = live
                .iter()
                .filter(|m| required.contains(&m.0))
                .map(|m| m.1[l])
                .min();
            let expected = if lost {
                Limit::Held
            } else {
                match (strategy_edge, required_edge) {
                    (None, _) => Limit::NoReceiverWindow,
                    (Some(&s), None) => Limit::Edge(s),
                    (Some(&s), Some(r)) => Limit::Edge(s.min(r)),
                }
            };
            assert_eq!(
                table.limit(lane(at), now),
                expected,
                "round {round} lane {at}"
            );
        }
    }
}

/// R4 step 2: a live member's join, consumption and window; an expected
/// entry's answered join before its first SM, kept at the join; nothing
/// for an expired member, an unknown receiver or a lane outside; a rejoin
/// starts a new join point.
#[test]
fn a_requester_is_what_a_nak_is_checked_against() {
    let mut table = table(config(2), &Roles::default());
    accepted(status(&mut table, &sm(1, &[(100, 200), (5, 300)]), 0));
    accepted(status(&mut table, &sm(1, &[(150, 200), (9, 300)]), MS));
    assert_eq!(
        table.requester(receiver(1, 1), lane(0), MS),
        Requester::Member {
            join: 100,
            consumption: 150,
            window: 200
        }
    );
    assert_eq!(
        table.requester(receiver(1, 1), lane(1), MS),
        Requester::Member {
            join: 5,
            consumption: 9,
            window: 300
        }
    );
    assert_eq!(
        table.requester(receiver(1, 1), lane(2), MS),
        Requester::Unknown
    );
    assert_eq!(
        table.requester(receiver(2, 1), lane(0), MS),
        Requester::Unknown
    );
    // Expected with its answered joins, kept when its first SM is higher.
    table
        .expect(&path(receiver(2, 1), 1), &[40, 7], MS)
        .unwrap();
    assert_eq!(
        table.requester(receiver(2, 1), lane(0), MS),
        Requester::Joined { join: 40 }
    );
    accepted(status(&mut table, &sm(2, &[(60, 200), (8, 300)]), MS));
    assert_eq!(
        table.requester(receiver(2, 1), lane(1), MS),
        Requester::Member {
            join: 7,
            consumption: 8,
            window: 300
        }
    );
    // Expired: unknown. A rejoin, fresh against the tombstone, joins anew.
    assert_eq!(
        table.requester(receiver(1, 1), lane(0), MS + TIMEOUT),
        Requester::Unknown
    );
    table.timers(MS + TIMEOUT, 64);
    accepted(status(
        &mut table,
        &sm(1, &[(400, 200), (9, 300)]),
        MS + TIMEOUT,
    ));
    assert_eq!(
        table.requester(receiver(1, 1), lane(0), MS + TIMEOUT),
        Requester::Member {
            join: 400,
            consumption: 400,
            window: 200
        }
    );
}

/// Sender join over redundant paths (redundant-paths.md section 8), at the
/// membership: `expect` for a later path's binding, with a higher join,
/// binds that path to the same member and leaves its join unchanged; its
/// SMs on the later path are accepted below that join, and retention
/// follows them. The sender role does not call `expect` yet (a member joins
/// by its first SM, on any path, which binds that path); this pins the
/// rule for when an ANSWER does.
#[test]
fn a_later_paths_answer_keeps_the_members_join() {
    let mut table = table(
        config(1),
        &Roles {
            required: &[1],
            tags: &[],
        },
    );
    let first = table.expect(&path(receiver(1, 1), 1), &[0], 0).unwrap();
    let later = table.expect(&path(receiver(1, 1), 2), &[8192], SECOND);
    assert_eq!(later, Ok(first), "the same member, not a new one");
    let outcome = table.status(&path(receiver(1, 1), 2), &sm(1, &[(0, 4096)]), SECOND);
    let (member, _, _) = accepted(outcome);
    assert_eq!(member, first);
    assert_eq!(table.retention(lane(0)), Some(0));
    // The founding path's binding is kept: its SMs are accepted too.
    let outcome = status(&mut table, &sm(1, &[(64, 4096)]), 2 * SECOND);
    assert_eq!(accepted(outcome).0, first);

    // The answers alone bind both paths: either path's loss leaves the
    // other, and the member goes only with its last path.
    let mut table = table_of_one();
    let _ = table.expect(&path(receiver(1, 1), 1), &[0], 0).unwrap();
    let _ = table
        .expect(&path(receiver(1, 1), 2), &[8192], SECOND)
        .unwrap();
    assert_eq!(
        table.binding_gone(&path(receiver(1, 1), 1), SECOND),
        Gone::Remaining
    );
    assert_eq!(
        table.binding_gone(&path(receiver(1, 1), 2), SECOND),
        Gone::Removed
    );
}

/// A table of one lane whose receiver 1 is required.
fn table_of_one() -> Membership {
    table(
        config(1),
        &Roles {
            required: &[1],
            tags: &[],
        },
    )
}

/// karyos#630, design 3.7: a removed destination's member, released by its
/// source, stops counting for the strategy edge at once (no wait for its
/// liveness), so under `min` the others' edge moves; releasing an address
/// with no member changes nothing.
#[test]
fn a_released_source_stops_bounding_the_strategy_edge() {
    let mut table = table(config(1), &Roles::default());
    accepted(status(&mut table, &sm(1, &[(100, 100)]), 0));
    accepted(status(&mut table, &sm(2, &[(150, 10)]), 0));
    assert_eq!(table.limit(lane(0), 0), Limit::Edge(160));
    let second = path(receiver(2, 1), 1).source;
    assert!(table.live_at(second, 1));
    assert!(table.release_source(second, 1));
    assert!(!table.live_at(second, 1));
    assert_eq!(table.limit(lane(0), 1), Limit::Edge(200));
    assert!(!table.release_source(second, 2));
}

/// H8-28: `would_accept` decides each SM as `status` then does: a join
/// window, a join, a changed window, a stale and a beyond consumption, a
/// table full for an optional newcomer, a required join and its changed
/// boot id, an expired member's tombstone (stationary, then fresh) and a
/// required loss.
#[test]
fn would_accept_decides_as_status_does() {
    let mut config = config(1);
    config.max_receivers = 2;
    config.max_pending = 2;
    let mut table = table(
        config,
        &Roles {
            required: &[3],
            tags: &[],
        },
    );
    let steps = [
        (sm(1, &[(0, 5)]), 0, Some(StatusRejected::Window)),
        (sm(1, &[(0, 100)]), 0, None),
        (sm(1, &[(0, 200)]), 0, Some(StatusRejected::WindowChanged)),
        (sm(1, &[(50, 100)]), 0, None),
        (sm(1, &[(40, 100)]), 0, Some(StatusRejected::Stale)),
        (
            sm(1, &[((1 << 30) + 1, 100)]),
            0,
            Some(StatusRejected::Beyond),
        ),
        (sm(2, &[(0, 100)]), 0, Some(StatusRejected::TableFull)),
        (sm(3, &[(0, 100)]), 0, None),
        (
            sm_from(receiver(3, 2), 0, &[(0, 100)]),
            0,
            Some(StatusRejected::BootChanged),
        ),
        (sm(1, &[(50, 100)]), TIMEOUT, Some(StatusRejected::Expired)),
        (sm(1, &[(60, 100)]), TIMEOUT + 1, None),
        (sm(3, &[(0, 100)]), TIMEOUT + 2, Some(StatusRejected::Lost)),
    ];
    for (sm, now, expected) in steps {
        let key = path(sm.receiver, 1);
        let would = table.would_accept(&key, &sm, now);
        assert_eq!(would, expected.map_or(Ok(()), Err), "{sm:?} at {now}");
        match table.status(&key, &sm, now) {
            StatusOutcome::Accepted { .. } => assert_eq!(would, Ok(()), "{sm:?}"),
            StatusOutcome::Rejected(reason) => assert_eq!(would, Err(reason), "{sm:?}"),
        }
    }
}
