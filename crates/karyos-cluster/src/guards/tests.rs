// SPDX-License-Identifier: Apache-2.0

//! The guard table's rules (quantstratum-docs:
//! karyos/design/replicated-guards.md §8, part (a)).

use super::*;

const L: u64 = 100;

fn bounds(profile: Profile) -> GuardBounds {
    GuardBounds::new(4, L, 25, profile).unwrap()
}

/// A table with its bounds logged at index 1.
fn table(profile: Profile) -> GuardTable {
    let mut t = GuardTable::new(bounds(profile));
    assert_eq!(
        t.apply(GuardEntry::Bounds(bounds(profile)), 1, 0),
        Ok(GuardOutcome::Bounds)
    );
    t
}

fn close(guard: u64, operation: u64) -> GuardEntry {
    GuardEntry::Close {
        guard,
        operation,
        requester: 7,
        reason: 1,
    }
}

fn reopen(guard: u64, fence: u64, operation: u64) -> GuardEntry {
    GuardEntry::Reopen {
        guard,
        fence,
        operation,
        requester: 7,
        reason: 2,
    }
}

fn state(t: &GuardTable, guard: u64) -> (u64, u64, bool) {
    let g = t.guard(guard).unwrap();
    (g.epoch, g.fence, g.open())
}

/// A table with guard 9 defined, a lease granted at 10, and the guard
/// open: epoch 2, fence 1.
fn open_table() -> GuardTable {
    let mut t = table(Profile::Durable);
    assert_eq!(
        t.apply(
            GuardEntry::Define {
                guard: 9,
                policy: 1
            },
            2,
            0
        ),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(
        t.apply(GuardEntry::Renew { issued: 10 }, 3, 10),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(
        t.apply(reopen(9, 1, 100), 4, 11),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(state(&t, 9), (2, 1, true));
    t
}

#[test]
fn every_entry_round_trips_at_its_length() {
    for (entry, length) in [
        (GuardEntry::Bounds(bounds(Profile::Volatile)), 33),
        (
            GuardEntry::Define {
                guard: 1,
                policy: 1,
            },
            24,
        ),
        (close(1, 2), 40),
        (reopen(1, 3, 4), 48),
        (GuardEntry::Renew { issued: 5 }, 20),
    ] {
        let bytes = entry.to_vec().unwrap();
        assert_eq!(bytes.len(), length, "{entry:?}");
        assert_eq!(GuardEntry::decode(&bytes), Ok(entry));
    }
    // A zero, the lapse's reserved reason and a lifetime past the maximum
    // are out of range.
    assert!(close(0, 1).to_vec().is_err());
    assert!(
        GuardEntry::Define {
            guard: 1,
            policy: 0
        }
        .to_vec()
        .is_err()
    );
    assert!(
        GuardEntry::Close {
            guard: 1,
            operation: 1,
            requester: 1,
            reason: LAPSE_REASON
        }
        .to_vec()
        .is_err()
    );
    assert!(GuardBounds::new(1, MAX_GUARD_LIFETIME + 1, 1, Profile::Durable).is_err());
    assert!(GuardBounds::new(1, 10, 10, Profile::Durable).is_err());
}

#[test]
fn a_stale_reopen_is_rejected_and_the_guard_stays_closed() {
    let mut t = open_table();
    // A close (fence 2), then a second close (fence 3).
    assert_eq!(t.apply(close(9, 101), 5, 12), Ok(GuardOutcome::Accepted));
    assert_eq!(state(&t, 9), (3, 2, false));
    assert_eq!(t.apply(close(9, 102), 6, 13), Ok(GuardOutcome::Accepted));
    assert_eq!(
        state(&t, 9),
        (3, 3, false),
        "a close of a closed guard raises the fence, not the epoch"
    );
    // A reopen prepared for the first close is stale.
    assert_eq!(
        t.apply(reopen(9, 2, 103), 7, 14),
        Ok(GuardOutcome::Refused(Refusal::Stale))
    );
    assert_eq!(state(&t, 9), (3, 3, false));
    // The current fence's reopen applies.
    assert_eq!(
        t.apply(reopen(9, 3, 104), 8, 15),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(state(&t, 9), (4, 3, true));
}

#[test]
fn a_reopen_queued_before_a_lapse_is_stale_after_a_fresh_grant() {
    let mut t = open_table();
    assert_eq!(t.apply(close(9, 101), 5, 12), Ok(GuardOutcome::Accepted));
    assert_eq!(state(&t, 9), (3, 2, false));
    // The lease (until 110) lapses at the next guard entry at or past it:
    // the fence rises, the epoch is unchanged (already closed).
    assert_eq!(
        t.apply(GuardEntry::Renew { issued: 120 }, 6, 120),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(state(&t, 9), (3, 3, false));
    // A reopen prepared before the lapse names fence 2: stale.
    assert_eq!(
        t.apply(reopen(9, 2, 105), 7, 121),
        Ok(GuardOutcome::Refused(Refusal::Stale))
    );
    assert_eq!(state(&t, 9), (3, 3, false));
}

#[test]
fn a_retried_operation_changes_the_table_once_and_an_older_close_is_a_new_decision() {
    let mut t = open_table();
    assert_eq!(t.apply(close(9, 101), 5, 12), Ok(GuardOutcome::Accepted));
    assert_eq!(t.apply(close(9, 101), 6, 13), Ok(GuardOutcome::Retry));
    assert_eq!(state(&t, 9), (3, 2, false));
    assert_eq!(
        t.apply(reopen(9, 2, 102), 7, 14),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(t.apply(reopen(9, 2, 102), 8, 15), Ok(GuardOutcome::Retry));
    assert_eq!(state(&t, 9), (4, 2, true));
    // The first close, retried after the reopen: a new decision.
    assert_eq!(t.apply(close(9, 101), 9, 16), Ok(GuardOutcome::Accepted));
    assert_eq!(state(&t, 9), (5, 3, false));
}

#[test]
fn epochs_keep_the_local_parity() {
    let mut t = open_table();
    for (n, index) in (0..6u64).zip(10..) {
        let g = t.guard(9).unwrap();
        let entry = if g.open() {
            close(9, 200 + n)
        } else {
            reopen(9, g.fence, 200 + n)
        };
        assert_eq!(t.apply(entry, index, 20 + n), Ok(GuardOutcome::Accepted));
        let g = t.guard(9).unwrap();
        assert_eq!(g.open(), g.epoch.is_multiple_of(2));
    }
}

#[test]
fn a_reopen_needs_an_active_lease_and_a_durable_profile() {
    let mut t = table(Profile::Durable);
    assert_eq!(
        t.apply(
            GuardEntry::Define {
                guard: 9,
                policy: 1
            },
            2,
            0
        ),
        Ok(GuardOutcome::Accepted)
    );
    // Before any grant.
    assert_eq!(
        t.apply(reopen(9, 1, 1), 3, 1),
        Ok(GuardOutcome::Refused(Refusal::NoAuthority))
    );
    // An earlier term's renewal committed late grants nothing past its
    // `issued`: issued at 1, lifetime 100, applied at log time 150.
    assert_eq!(
        t.apply(GuardEntry::Renew { issued: 1 }, 4, 150),
        Ok(GuardOutcome::NotGranted)
    );
    assert_eq!(t.lease(), Lease::NeverGranted);
    // A grant, then equality at `until` is expired.
    assert_eq!(
        t.apply(GuardEntry::Renew { issued: 150 }, 5, 150),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(
        t.apply(reopen(9, 1, 2), 6, 250),
        Ok(GuardOutcome::Refused(Refusal::NoAuthority))
    );
    assert!(matches!(t.lease(), Lease::Lapsed { until: 250, .. }));
    // A volatile profile refuses every reopen.
    let mut v = table(Profile::Volatile);
    assert_eq!(
        v.apply(
            GuardEntry::Define {
                guard: 9,
                policy: 1
            },
            2,
            0
        ),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(
        v.apply(GuardEntry::Renew { issued: 10 }, 3, 10),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(
        v.apply(reopen(9, 1, 3), 4, 11),
        Ok(GuardOutcome::Refused(Refusal::NotDurable))
    );
}

#[test]
fn a_replica_with_other_bounds_stops_the_profile_included() {
    let mut t = GuardTable::new(bounds(Profile::Durable));
    // The log carries a volatile profile: this replica stops.
    let logged = bounds(Profile::Volatile);
    assert_eq!(
        t.apply(GuardEntry::Bounds(logged), 1, 0),
        Err(GuardStop::BoundsDiffer {
            logged,
            configured: bounds(Profile::Durable),
        })
    );
    assert!(!t.bounds_logged());
    // Nothing applies before the bounds.
    assert_eq!(
        t.apply(
            GuardEntry::Define {
                guard: 1,
                policy: 1
            },
            2,
            0
        ),
        Ok(GuardOutcome::Refused(Refusal::NoBounds))
    );
}

#[test]
fn a_full_table_refuses_a_definition() {
    let mut t = table(Profile::Durable);
    for guard in 1..=4 {
        assert_eq!(
            t.apply(GuardEntry::Define { guard, policy: 1 }, guard + 1, 0),
            Ok(GuardOutcome::Accepted)
        );
    }
    assert_eq!(
        t.apply(
            GuardEntry::Define {
                guard: 5,
                policy: 1
            },
            6,
            0
        ),
        Ok(GuardOutcome::Refused(Refusal::GuardsFull))
    );
    assert_eq!(
        t.apply(close(5, 1), 7, 0),
        Ok(GuardOutcome::Refused(Refusal::Undefined))
    );
}

#[test]
fn a_lapse_closes_every_open_guard_before_the_entry_and_the_lease() {
    let mut t = table(Profile::Durable);
    for guard in [3, 5] {
        assert_eq!(
            t.apply(GuardEntry::Define { guard, policy: 1 }, guard, 0),
            Ok(GuardOutcome::Accepted)
        );
    }
    assert_eq!(
        t.apply(GuardEntry::Renew { issued: 10 }, 6, 10),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(t.apply(reopen(3, 1, 1), 7, 11), Ok(GuardOutcome::Accepted));
    // Guard 3 open, guard 5 closed. A refused reopen past expiry still
    // carries the lapse: 3 closed (epoch and fence), 5 fence only, then the
    // lapsed lease, then nothing of its own.
    assert_eq!(
        t.apply(reopen(5, 1, 2), 8, 110),
        Ok(GuardOutcome::Refused(Refusal::NoAuthority))
    );
    let effects = t.effects();
    assert_eq!(effects.len(), 3, "{effects:?}");
    assert!(
        matches!(effects[0], GuardEffect::Guard { guard, index: 8, log_time: 110 } if guard.guard == 3 && guard.epoch == 3 && guard.fence == 2 && guard.last.reason == LAPSE_REASON)
    );
    assert!(
        matches!(effects[1], GuardEffect::Guard { guard, .. } if guard.guard == 5 && guard.epoch == 1 && guard.fence == 2)
    );
    assert!(matches!(
        effects[2],
        GuardEffect::Lease {
            lease: Lease::Lapsed { until: 110, .. },
            ..
        }
    ));
    // A grant ending the lapse comes after it, and lifts no guard.
    assert_eq!(
        t.apply(GuardEntry::Renew { issued: 200 }, 9, 200),
        Ok(GuardOutcome::Accepted)
    );
    assert!(matches!(
        t.effects(),
        [GuardEffect::Lease {
            lease: Lease::Active { until: 300, .. },
            ..
        }]
    ));
    assert!(!t.guard(3).unwrap().open());
}

#[test]
fn saturation_still_closes_and_never_reopens() {
    let mut t = open_table();
    if let Ok(at) = t.slot(9) {
        t.guards[at].fence = u64::MAX - 1;
    }
    assert_eq!(t.apply(close(9, 1), 5, 12), Ok(GuardOutcome::Accepted));
    assert_eq!(state(&t, 9), (3, u64::MAX, false));
    assert_eq!(t.apply(close(9, 2), 6, 13), Ok(GuardOutcome::Accepted));
    assert_eq!(
        state(&t, 9),
        (3, u64::MAX, false),
        "a saturated fence still takes the close"
    );
    assert_eq!(
        t.apply(reopen(9, u64::MAX, 3), 7, 14),
        Ok(GuardOutcome::Refused(Refusal::GuardExhausted))
    );
    let mut e = open_table();
    if let Ok(at) = e.slot(9) {
        e.guards[at].epoch = MAX_EPOCH - 1;
    }
    assert_eq!(e.apply(close(9, 1), 5, 12), Ok(GuardOutcome::Accepted));
    assert_eq!(e.guard(9).unwrap().epoch, MAX_EPOCH);
    let fence = e.guard(9).unwrap().fence;
    assert_eq!(
        e.apply(reopen(9, fence, 2), 6, 13),
        Ok(GuardOutcome::Refused(Refusal::GuardExhausted))
    );
}

#[test]
fn a_section_restores_the_table_and_every_unreachable_one_is_refused() {
    let mut t = open_table();
    assert_eq!(t.apply(close(9, 101), 5, 12), Ok(GuardOutcome::Accepted));
    let b = bounds(Profile::Durable);
    let bytes = t.section().unwrap();
    let restored = GuardTable::restore(SECTION_VERSION, &bytes, b, 5, 12).unwrap();
    assert_eq!(
        (
            restored.guards(),
            restored.lease(),
            restored.bounds_logged()
        ),
        (t.guards(), t.lease(), t.bounds_logged())
    );
    assert!(
        restored.effects().is_empty(),
        "a restored table carries no pending effects"
    );
    // Each byte change that breaks a rule of §6 refuses the whole section.
    let guard_at = HEAD;
    let mutate = |at: usize, value: &[u8]| {
        let mut b = bytes.clone();
        b[at..at + value.len()].copy_from_slice(value);
        b
    };
    let cases: Vec<(&str, Vec<u8>, SectionError)> = vec![
        (
            "short",
            bytes[..bytes.len() - 1].to_vec(),
            SectionError::Length,
        ),
        ("other profile", mutate(20, &[2]), SectionError::Bounds),
        ("lease state", mutate(21, &[9]), SectionError::Lease),
        (
            "never granted with times",
            mutate(21, &[0]),
            SectionError::Lease,
        ),
        (
            "guard 0",
            mutate(guard_at, &0u64.to_le_bytes()),
            SectionError::Guard(0),
        ),
        (
            "epoch 0",
            mutate(guard_at + 8, &0u64.to_le_bytes()),
            SectionError::Guard(0),
        ),
        (
            "fence 0",
            mutate(guard_at + 16, &0u64.to_le_bytes()),
            SectionError::Guard(0),
        ),
        (
            "audit index past the snapshot",
            mutate(guard_at + RECORD - 8, &99u64.to_le_bytes()),
            SectionError::Guard(0),
        ),
        (
            "zero reason",
            mutate(guard_at + RECORD - 12, &0u32.to_le_bytes()),
            SectionError::Guard(0),
        ),
    ];
    for (name, bytes, error) in cases {
        assert_eq!(
            GuardTable::restore(SECTION_VERSION, &bytes, b, 5, 12).err(),
            Some(error),
            "{name}"
        );
    }
    // A lapsed lease whose `until` is past the snapshot's log time.
    let mut l = open_table();
    assert_eq!(l.apply(close(9, 1), 5, 12), Ok(GuardOutcome::Accepted));
    assert_eq!(
        l.apply(GuardEntry::Renew { issued: 1 }, 6, 110),
        Ok(GuardOutcome::NotGranted)
    );
    assert!(matches!(l.lease(), Lease::Lapsed { until: 110, .. }));
    assert_eq!(
        GuardTable::restore(SECTION_VERSION, &l.section().unwrap(), b, 6, 109).err(),
        Some(SectionError::Lease)
    );
    assert!(GuardTable::restore(SECTION_VERSION, &l.section().unwrap(), b, 6, 110).is_ok());
}

#[test]
fn an_overflowing_renewal_stops_and_changes_nothing() {
    let mut t = open_table();
    let before = t.clone();
    // Expired (until 110), so a lapse would run; the overflow stops first.
    assert_eq!(
        t.apply(GuardEntry::Renew { issued: u64::MAX }, 5, 200),
        Err(GuardStop::Overflow)
    );
    assert_eq!(t, before, "a stop applies nothing, effects included");
}

#[test]
fn every_guard_entry_at_expiry_runs_the_lapse_and_ends_with_one_lease_effect() {
    let lapsed = |effects: &[GuardEffect]| -> Vec<&'static str> {
        effects
            .iter()
            .map(|effect| match effect {
                GuardEffect::Guard { guard, .. } if guard.last.reason == LAPSE_REASON => "lapse",
                GuardEffect::Guard { .. } => "own",
                GuardEffect::Lease {
                    lease: Lease::Lapsed { .. },
                    ..
                } => "lapsed",
                GuardEffect::Lease { .. } => "granted",
            })
            .collect()
    };
    // A matching bounds entry.
    let mut t = open_table();
    assert_eq!(
        t.apply(GuardEntry::Bounds(bounds(Profile::Durable)), 5, 110),
        Ok(GuardOutcome::Bounds)
    );
    assert_eq!(lapsed(t.effects()), ["lapse", "lapsed"]);
    assert!(!t.guard(9).unwrap().open());
    // A close: the lapse's change, its own, then the lease.
    let mut t = open_table();
    assert_eq!(t.apply(close(9, 101), 5, 110), Ok(GuardOutcome::Accepted));
    assert_eq!(lapsed(t.effects()), ["lapse", "own", "lapsed"]);
    // A renewal that lapses and grants: one lease effect, the grant.
    let mut t = open_table();
    assert_eq!(
        t.apply(GuardEntry::Renew { issued: 110 }, 5, 110),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(lapsed(t.effects()), ["lapse", "granted"]);
}

#[test]
fn no_section_before_the_bounds_and_an_unread_version_is_refused() {
    let t = GuardTable::new(bounds(Profile::Durable));
    assert_eq!(t.section(), None);
    let bytes = open_table().section().unwrap();
    assert_eq!(
        GuardTable::restore(SECTION_VERSION + 1, &bytes, bounds(Profile::Durable), 4, 11).err(),
        Some(SectionError::Version(SECTION_VERSION + 1))
    );
}

/// Two guards, for the snapshot matrix: guard 3 open, guard 5 closed by a
/// lapse later.
fn two_guards() -> GuardTable {
    let mut t = table(Profile::Durable);
    assert_eq!(
        t.apply(
            GuardEntry::Define {
                guard: 3,
                policy: 1
            },
            2,
            0
        ),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(
        t.apply(
            GuardEntry::Define {
                guard: 5,
                policy: 1
            },
            3,
            0
        ),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(
        t.apply(GuardEntry::Renew { issued: 10 }, 4, 10),
        Ok(GuardOutcome::Accepted)
    );
    assert_eq!(t.apply(reopen(3, 1, 1), 5, 11), Ok(GuardOutcome::Accepted));
    t
}

#[test]
fn every_unreachable_section_is_refused_whole() {
    let b = bounds(Profile::Durable);
    let bytes = two_guards().section().unwrap();
    let record = |n: usize| HEAD + n * RECORD;
    let mutate = |at: usize, value: &[u8]| {
        let mut b = bytes.clone();
        b[at..at + value.len()].copy_from_slice(value);
        b
    };
    assert!(GuardTable::restore(SECTION_VERSION, &bytes, b, 5, 11).is_ok());
    let cases: Vec<(&str, Vec<u8>, SectionError)> = vec![
        (
            "duplicate id",
            mutate(record(1), &3u64.to_le_bytes()),
            SectionError::Guard(1),
        ),
        (
            "descending ids",
            mutate(record(1), &2u64.to_le_bytes()),
            SectionError::Guard(1),
        ),
        (
            "count above capacity",
            {
                let mut b = mutate(HEAD - 4, &5u32.to_le_bytes());
                b.resize(HEAD + 5 * RECORD, 0);
                b
            },
            SectionError::Length,
        ),
        (
            "epoch above the maximum",
            mutate(record(1) + 8, &(MAX_EPOCH + 1).to_le_bytes()),
            SectionError::Guard(1),
        ),
        (
            "open while never granted",
            mutate(21, &[0; 17]),
            SectionError::Guard(0),
        ),
        (
            "open at a saturated fence",
            mutate(record(0) + 16, &u64::MAX.to_le_bytes()),
            SectionError::Guard(0),
        ),
        (
            "a lapse record with an operation",
            {
                let mut b = mutate(record(0) + 52, &LAPSE_REASON.to_le_bytes());
                b[record(0) + 36..record(0) + 44].copy_from_slice(&1u64.to_le_bytes());
                b
            },
            SectionError::Guard(0),
        ),
    ];
    for (name, bytes, error) in cases {
        assert_eq!(
            GuardTable::restore(SECTION_VERSION, &bytes, b, 5, 11).err(),
            Some(error),
            "{name}"
        );
    }
    // An open guard under a lapsed lease.
    let mut lapsed = two_guards();
    lapsed.lease = Lease::Lapsed {
        issued: 10,
        until: 110,
    };
    assert_eq!(
        GuardTable::restore(SECTION_VERSION, &lapsed.section().unwrap(), b, 5, 200).err(),
        Some(SectionError::Guard(0))
    );
}

/// A stale reopen replayed on a live replica and on one restored from a
/// snapshot gives the same outcome and the same effects.
#[test]
fn a_live_and_a_restored_replica_agree_on_a_stale_reopen() {
    let mut live = open_table();
    assert_eq!(live.apply(close(9, 101), 5, 12), Ok(GuardOutcome::Accepted));
    assert_eq!(live.apply(close(9, 102), 6, 13), Ok(GuardOutcome::Accepted));
    let mut restored = GuardTable::restore(
        SECTION_VERSION,
        &live.section().unwrap(),
        bounds(Profile::Durable),
        6,
        13,
    )
    .unwrap();
    for t in [&mut live, &mut restored] {
        assert_eq!(
            t.apply(reopen(9, 2, 103), 7, 14),
            Ok(GuardOutcome::Refused(Refusal::Stale))
        );
    }
    assert_eq!(live.effects(), restored.effects());
    assert_eq!(live.guards(), restored.guards());
}
