// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use karyos_protocol::frame::Lane;
use karyos_protocol::network::{Alias, Identity, NakRange};

use super::*;

const MS: u64 = 1_000_000;
const TERM: u32 = 64 * 1024;

fn receiver(id: u64) -> Receiver {
    Receiver {
        receiver_boot_id: [id, 1],
        receiver_id: id,
    }
}

fn nak(id: u64, lane: u8, start: u64, length: u32) -> Nak {
    Nak {
        alias: Alias {
            session_id: 1,
            stream_id: 2,
        },
        identity: Identity {
            driver_id: [1, 2],
            registration_id: 1,
            incarnation: 1,
        },
        receiver: receiver(id),
        range: NakRange {
            lane: Lane::try_new(lane).unwrap(),
            length,
            start,
        },
    }
}

/// A member at consumption 1024, window 8192, joined at 0; floor 512,
/// sent to 4096.
fn ctx() -> NakContext {
    NakContext {
        reliable: true,
        lane_count: 2,
        requester: Requester::Member {
            join: 0,
            consumption: 1024,
            window: 8192,
        },
        floor: 512,
        nak_bound: 4096,
        term_length: TERM,
    }
}

fn admission() -> Admission {
    Admission::new(MS, 4).unwrap()
}

fn reason(outcome: Admitted) -> NakReplyReason {
    match outcome {
        Admitted::Reply(reply) => reply.reason,
        other => panic!("not a reply: {other:?}"),
    }
}

#[test]
fn a_nak_within_every_bound_passes() {
    let mut admission = admission();
    assert_eq!(
        admission.admit(&nak(1, 1, 1024, 3072), &ctx(), 0),
        Admitted::Pass(Request {
            receiver: receiver(1),
            lane: 1,
            start: 1024,
            length: 3072,
        })
    );
    assert_eq!(admission.counts().passed, 1);
    assert_eq!(Admission::new(MS, 0).err(), Some(AdmissionError::Entries));
}

/// Step 1: unreliable, unknown requester and a lane outside drop with no
/// reply.
#[test]
fn context_failures_drop_silently() {
    let mut admission = admission();
    let unreliable = NakContext {
        reliable: false,
        ..ctx()
    };
    let unknown = NakContext {
        requester: Requester::Unknown,
        ..ctx()
    };
    assert_eq!(
        admission.admit(&nak(1, 0, 1024, 32), &unreliable, 0),
        Admitted::Dropped(Dropped::Unreliable)
    );
    assert_eq!(
        admission.admit(&nak(1, 0, 1024, 32), &unknown, 0),
        Admitted::Dropped(Dropped::Context)
    );
    assert_eq!(
        admission.admit(&nak(1, 2, 1024, 32), &ctx(), 0),
        Admitted::Dropped(Dropped::Context)
    );
    let counts = admission.counts();
    assert_eq!((counts.unreliable, counts.context), (1, 2));
}

/// Step 2: below the join, stale, beyond the window, and before an SM the
/// join point alone; it comes before the term, floor and sent checks.
#[test]
fn the_requester_window_drops_silently() {
    let mut admission = admission();
    let joined_late = NakContext {
        requester: Requester::Member {
            join: 2048,
            consumption: 2048,
            window: 8192,
        },
        ..ctx()
    };
    assert_eq!(
        admission.admit(&nak(1, 0, 1024, 32), &joined_late, 0),
        Admitted::Dropped(Dropped::BelowJoin)
    );
    assert_eq!(
        admission.admit(&nak(1, 0, 992, 32), &ctx(), 0),
        Admitted::Dropped(Dropped::Stale),
        "below consumption, even above the floor"
    );
    assert_eq!(
        admission.admit(&nak(1, 0, 1024, 8192 + 32), &ctx(), 0),
        Admitted::Dropped(Dropped::BeyondWindow),
        "1024 + 8224 > 1024 + 8192, before the sent check"
    );
    let joined = NakContext {
        requester: Requester::Joined { join: 1024 },
        ..ctx()
    };
    assert_eq!(
        admission.admit(&nak(1, 0, 992, 32), &joined, 0),
        Admitted::Dropped(Dropped::BeforeSm)
    );
    assert!(matches!(
        admission.admit(&nak(1, 0, 1024, 32), &joined, 0),
        Admitted::Pass(_)
    ));
    let counts = admission.counts();
    assert_eq!(
        (
            counts.below_join,
            counts.before_sm,
            counts.stale,
            counts.beyond_window
        ),
        (1, 1, 1, 1)
    );
}

/// Step 3: a range ending exactly at the term end is valid; one crossing
/// it, or overflowing, is RANGE_INVALID.
#[test]
fn a_range_stays_in_one_term() {
    let mut admission = admission();
    let wide = NakContext {
        requester: Requester::Member {
            join: 0,
            consumption: 0,
            window: u32::MAX,
        },
        floor: 0,
        nak_bound: u64::MAX,
        ..ctx()
    };
    let term = u64::from(TERM);
    assert!(matches!(
        admission.admit(&nak(1, 0, term - 64, 64), &wide, 0),
        Admitted::Pass(_)
    ));
    assert_eq!(
        reason(admission.admit(&nak(1, 0, term - 32, 64), &wide, 0)),
        NakReplyReason::RangeInvalid
    );
    let beyond = (1u64 << 31) * term;
    let far = NakContext {
        requester: Requester::Joined { join: 0 },
        ..wide
    };
    assert_eq!(
        reason(admission.admit(&nak(1, 0, beyond, 32), &far, 0)),
        NakReplyReason::RangeInvalid,
        "beyond 2^31 terms"
    );
    assert_eq!(
        reason(admission.admit(&nak(1, 0, u64::MAX - 31, 64), &far, 0)),
        NakReplyReason::RangeInvalid,
        "start + length overflows"
    );
}

/// Step 4 before step 5: a byte below the floor is RANGE_UNAVAILABLE with
/// the floor, even when the range also runs past the sent frontier.
#[test]
fn the_floor_answers_before_the_frontier() {
    let mut admission = admission();
    let behind = NakContext {
        requester: Requester::Joined { join: 0 },
        ..ctx()
    };
    assert_eq!(
        reason(admission.admit(&nak(1, 0, 480, 8000), &behind, 0)),
        NakReplyReason::RangeUnavailable {
            lowest_retained: 512
        }
    );
    // 5. Beyond the NAK bound, read once.
    assert_eq!(
        reason(admission.admit(&nak(1, 0, 4064, 64), &ctx(), 0)),
        NakReplyReason::RangeInvalid
    );
    assert!(matches!(
        admission.admit(&nak(1, 0, 4064, 32), &ctx(), 0),
        Admitted::Pass(_)
    ));
    let counts = admission.counts();
    assert_eq!((counts.range_unavailable, counts.range_invalid), (1, 1));
}

/// At most one ERR per receiver, lane and range within the linger; another
/// range or receiver is answered; a full table of live entries drops.
#[test]
fn errs_linger_per_range() {
    let mut admission = admission();
    let beyond = nak(1, 0, 4096, 32);
    assert!(matches!(
        admission.admit(&beyond, &ctx(), 0),
        Admitted::Reply(_)
    ));
    assert_eq!(
        admission.admit(&beyond, &ctx(), MS - 1),
        Admitted::Dropped(Dropped::ErrLinger)
    );
    assert!(matches!(
        admission.admit(&beyond, &ctx(), MS),
        Admitted::Reply(_)
    ));
    for id in 2..=4 {
        assert!(matches!(
            admission.admit(&nak(id, 0, 4096, 32), &ctx(), MS),
            Admitted::Reply(_)
        ));
    }
    assert_eq!(
        admission.admit(&nak(5, 0, 4096, 32), &ctx(), MS),
        Admitted::Dropped(Dropped::ErrTableFull)
    );
    // Expired entries are reused.
    assert!(matches!(
        admission.admit(&nak(5, 0, 4096, 32), &ctx(), 2 * MS),
        Admitted::Reply(_)
    ));
    // A step 8 refusal goes through the same linger.
    assert_eq!(
        admission.reply_to(&nak(5, 0, 4096, 32), NakReplyReason::RangeInvalid, 2 * MS),
        Admitted::Dropped(Dropped::ErrLinger)
    );
    let counts = admission.counts();
    assert_eq!((counts.err_linger, counts.err_table_full), (2, 1));
}

/// The floor is inclusive: a NAK starting at it passes; one straddling it
/// within the NAK bound is RANGE_UNAVAILABLE with the floor (step 4 alone).
#[test]
fn the_floor_is_the_lowest_retained_byte() {
    let mut admission = admission();
    let joined = NakContext {
        requester: Requester::Joined { join: 0 },
        ..ctx()
    };
    assert!(matches!(
        admission.admit(&nak(1, 0, 512, 64), &joined, 0),
        Admitted::Pass(_)
    ));
    assert_eq!(
        reason(admission.admit(&nak(1, 0, 480, 64), &joined, 0)),
        NakReplyReason::RangeUnavailable {
            lowest_retained: 512
        }
    );
}

/// Step 3 before step 4: a range leaving its term is RANGE_INVALID even
/// when it also starts below the floor.
#[test]
fn the_term_bound_comes_before_the_floor() {
    let mut admission = admission();
    let term = u64::from(TERM);
    let high_floor = NakContext {
        requester: Requester::Joined { join: 0 },
        floor: term - 16,
        nak_bound: u64::MAX,
        ..ctx()
    };
    assert_eq!(
        reason(admission.admit(&nak(1, 0, term - 32, 64), &high_floor, 0)),
        NakReplyReason::RangeInvalid
    );
    assert_eq!(admission.counts().range_unavailable, 0);
}

/// Step 2 before step 3: a member's NAK beyond its window is dropped
/// silently even when it also leaves its term (RC-10).
#[test]
fn the_window_comes_before_the_term_bound() {
    let mut admission = admission();
    let term = u64::from(TERM);
    let member = NakContext {
        requester: Requester::Member {
            join: 0,
            consumption: term - 64,
            window: 32,
        },
        floor: 0,
        nak_bound: u64::MAX,
        ..ctx()
    };
    assert_eq!(
        admission.admit(&nak(1, 0, term - 32, 64), &member, 0),
        Admitted::Dropped(Dropped::BeyondWindow)
    );
    assert_eq!(admission.counts().range_invalid, 0);
}
