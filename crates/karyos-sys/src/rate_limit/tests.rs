// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use proptest::prelude::*;

use super::*;

const SECOND: u64 = 1_000_000_000;

fn policy(per_second: u64, burst: u64, bytes: Option<(u64, u64)>) -> RatePolicy {
    RatePolicy {
        messages: Rate { per_second, burst },
        bytes: bytes.map(|(per_second, burst)| Rate { per_second, burst }),
    }
}

#[test]
fn a_full_bucket_admits_its_burst_then_waits() {
    let mut limiter = RateLimiter::new(policy(10, 3, None), 0);
    for _ in 0..3 {
        assert!(limiter.admit_frame(0, 100, true));
    }
    assert!(!limiter.admit_frame(0, 100, true));
    // Later frames of a message cost no message token.
    assert!(limiter.admit_frame(0, 100, false));
    // A tenth of a second earns one token at 10 per second.
    assert!(!limiter.admit_frame(SECOND / 10 - 1, 100, true));
    assert!(limiter.admit_frame(SECOND / 10, 100, true));
}

#[test]
fn fractions_of_a_token_are_kept() {
    // 3 per second: a token every 333 333 333.33 ns. Three refills of a
    // third of a second each, none of which alone makes a whole token
    // after the first, still add up to exactly one per third.
    let mut limiter = RateLimiter::new(policy(3, 1, None), 0);
    assert!(limiter.admit_frame(0, 1, true));
    for step in 1..=3u64 {
        assert!(!limiter.admit_frame(step * 111_111_111, 1, true));
    }
    assert!(limiter.admit_frame(SECOND / 3 + 1, 1, true));
}

#[test]
fn a_backward_clock_step_grants_nothing() {
    let mut limiter = RateLimiter::new(policy(10, 1, None), SECOND);
    assert!(limiter.admit_frame(SECOND, 1, true));
    // The clock steps back a second: nothing is earned, and the refill
    // time is kept, so time is measured from the last real refill.
    assert!(!limiter.admit_frame(0, 1, true));
    assert!(!limiter.admit_frame(SECOND + SECOND / 10 - 1, 1, true));
    assert!(limiter.admit_frame(SECOND + SECOND / 10, 1, true));
}

#[test]
fn a_frame_is_charged_to_every_bucket_or_none() {
    // Plenty of messages, 1000 bytes of burst.
    let mut limiter = RateLimiter::new(policy(1000, 1000, Some((1000, 1000))), 0);
    assert!(limiter.admit_frame(0, 600, true));
    // 400 bytes left: a 600-byte frame waits and takes no message token.
    let before = limiter.message_tokens();
    assert!(!limiter.admit_frame(0, 600, true));
    assert_eq!(limiter.message_tokens(), before);
    assert_eq!(limiter.byte_tokens(), Some(400));
    assert!(limiter.admit_frame(0, 400, false));
    assert_eq!(limiter.byte_tokens(), Some(0));
}

/// The gate's check charges nothing and agrees with the charge that
/// follows it.
#[test]
fn admits_charges_nothing_and_agrees_with_try_admit() {
    let mut limiter = RateLimiter::new(policy(10, 1, Some((1000, 500))), 0);
    for _ in 0..3 {
        assert!(limiter.admits(500, true));
    }
    assert_eq!(
        (limiter.message_tokens(), limiter.byte_tokens()),
        (1, Some(500))
    );
    assert!(!limiter.admits(501, false));
    assert!(limiter.try_admit(500, true));
    assert!(!limiter.admits(1, false));
    assert!(!limiter.admits(0, true));
    // A refill earns what admit_frame's would, and charges nothing.
    limiter.refill_at(SECOND / 10);
    assert!(limiter.admits(100, true));
    assert_eq!(limiter.message_tokens(), 1);
    assert_eq!(limiter.byte_tokens(), Some(100));
    // A backward step keeps the last refill time.
    limiter.refill_at(0);
    limiter.refill_at(SECOND / 10 + SECOND / 10);
    assert_eq!(limiter.message_tokens(), 1);
    assert_eq!(limiter.byte_tokens(), Some(200));
}

/// A refund gives back exactly a charge, capped at the burst.
#[test]
fn a_refund_gives_back_a_charge_capped_at_the_burst() {
    let mut limiter = RateLimiter::new(policy(10, 2, Some((1000, 500))), 0);
    assert!(limiter.try_admit(300, true));
    assert_eq!(
        (limiter.message_tokens(), limiter.byte_tokens()),
        (1, Some(200))
    );
    limiter.refund(300, true);
    assert_eq!(
        (limiter.message_tokens(), limiter.byte_tokens()),
        (2, Some(500))
    );
    // Already full: the refund is capped, never above the burst.
    limiter.refund(300, true);
    assert_eq!(
        (limiter.message_tokens(), limiter.byte_tokens()),
        (2, Some(500))
    );
    // A later frame of a message gives back bytes only.
    assert!(limiter.try_admit(500, false));
    limiter.refund(500, false);
    assert_eq!(
        (limiter.message_tokens(), limiter.byte_tokens()),
        (2, Some(500))
    );
}

/// A datagram that starts several messages costs one message token each,
/// all or none, and its refund gives them all back.
#[test]
fn a_datagram_charges_every_message_it_starts() {
    let mut limiter = RateLimiter::new(policy(10, 3, Some((1000, 500))), 0);
    assert!(limiter.admits_datagram(400, 3));
    assert!(!limiter.admits_datagram(400, 4));
    assert!(!limiter.admits_datagram(501, 0));
    assert!(limiter.try_admit_datagram(400, 2));
    assert_eq!(
        (limiter.message_tokens(), limiter.byte_tokens()),
        (1, Some(100))
    );
    assert!(!limiter.try_admit_datagram(50, 2), "all or none");
    assert_eq!(
        (limiter.message_tokens(), limiter.byte_tokens()),
        (1, Some(100))
    );
    limiter.refund_datagram(400, 2);
    assert_eq!(
        (limiter.message_tokens(), limiter.byte_tokens()),
        (3, Some(500))
    );
    // A continuation datagram starts no message.
    assert!(limiter.try_admit_datagram(500, 0));
    assert_eq!(limiter.message_tokens(), 3);
}

#[test]
fn a_long_idle_time_caps_at_the_burst() {
    let mut limiter = RateLimiter::new(policy(u64::MAX, 5, Some((u64::MAX, 1 << 40))), 0);
    for _ in 0..5 {
        assert!(limiter.admit_frame(0, 1, true));
    }
    assert!(limiter.admit_frame(u64::MAX, 1, true));
    assert_eq!(limiter.message_tokens(), 4);
    // Five bytes were taken, the refill capped the bucket at its burst,
    // and the last frame took one more.
    assert_eq!(limiter.byte_tokens(), Some((1 << 40) - 1));
}

#[test]
fn policies_are_validated() {
    assert_eq!(policy(0, 1, None).validate(64), Err(RatePolicyError::Zero));
    assert_eq!(policy(1, 0, None).validate(64), Err(RatePolicyError::Zero));
    assert_eq!(
        policy(1, 1, Some((0, 64))).validate(64),
        Err(RatePolicyError::Zero)
    );
    assert_eq!(
        policy(1, 1, Some((10, 63))).validate(64),
        Err(RatePolicyError::BurstBelowFrame {
            burst: 63,
            frame: 64
        })
    );
    assert_eq!(policy(1, 1, Some((10, 64))).validate(64), Ok(()));
    assert_eq!(policy(1, 1, None).validate(u64::MAX), Ok(()));
}

proptest! {
    #![proptest_config(crate::receive::tests_config())]

    /// With the elapsed time injected: a bucket never holds more than its
    /// burst, and the frames admitted never exceed the burst plus what the
    /// total elapsed time earns.
    #[test]
    fn admissions_never_exceed_burst_plus_earned(
        per_second in 1..1_000u64,
        burst in 1..50u64,
        steps in proptest::collection::vec(0..SECOND / 10, 1..200),
    ) {
        let mut limiter = RateLimiter::new(policy(per_second, burst, None), 0);
        let mut elapsed = 0u64;
        let mut admitted = 0u64;
        for step in steps {
            limiter.refill(step);
            elapsed += step;
            if limiter.try_admit(1, true) {
                admitted += 1;
            }
            prop_assert!(limiter.message_tokens() <= burst);
        }
        let earned = u128::from(elapsed) * u128::from(per_second) / NANOS;
        prop_assert!(u128::from(admitted) <= u128::from(burst) + earned);
    }

    /// Refilling in pieces earns exactly what one refill of the sum earns:
    /// no fraction of a token is lost.
    #[test]
    fn split_refills_earn_the_same(
        per_second in 1..1_000_000u64,
        pieces in proptest::collection::vec(0..SECOND, 1..20),
    ) {
        let burst = u64::MAX / 1_000_000_000_000;
        let mut split = RateLimiter::new(policy(per_second, burst, None), 0);
        // Empty, so nothing caps the refills.
        split.messages.level = 0;
        let mut whole = split;
        let total: u64 = pieces.iter().sum();
        for piece in pieces {
            split.refill(piece);
        }
        whole.refill(total);
        prop_assert_eq!(split.message_tokens(), whole.message_tokens());
    }
}

/// R-CORE-21: the transition table. Each of the four dimensions (message
/// rate and burst, byte rate and burst) alone, then every pair with one
/// tighter and the other looser, then the byte limit added and removed.
#[test]
fn only_a_change_tighter_in_every_dimension_is_a_tightening() {
    use crate::rate_limit::Transition;

    let base = policy(100, 10, Some((10_000, 2_000)));
    let with = |dimension: usize, by: i64| {
        let mut values = [100u64, 10, 10_000, 2_000];
        values[dimension] = values[dimension].checked_add_signed(by).unwrap();
        policy(values[0], values[1], Some((values[2], values[3])))
    };
    assert_eq!(base.transition(&base), Transition::Unchanged);
    for dimension in 0..4 {
        assert_eq!(
            base.transition(&with(dimension, -1)),
            Transition::Tightening,
            "{dimension}"
        );
        assert_eq!(
            base.transition(&with(dimension, 1)),
            Transition::Other,
            "{dimension}"
        );
    }
    // Every pair: one tighter, the other looser, is never a tightening.
    for tighter in 0..4 {
        for looser in 0..4 {
            if tighter == looser {
                continue;
            }
            let mut values = [100u64, 10, 10_000, 2_000];
            values[tighter] -= 1;
            values[looser] += 1;
            let next = policy(values[0], values[1], Some((values[2], values[3])));
            assert_eq!(
                base.transition(&next),
                Transition::Other,
                "{tighter} {looser}"
            );
        }
    }
    // Every dimension tighter at once.
    assert_eq!(
        base.transition(&policy(99, 9, Some((9_999, 1_999)))),
        Transition::Tightening
    );
    let messages_only = policy(100, 10, None);
    // A byte limit added takes away only; removed, it only gives.
    assert_eq!(messages_only.transition(&base), Transition::Tightening);
    assert_eq!(base.transition(&messages_only), Transition::Other);
    // Added, with the messages loosened: mixed.
    assert_eq!(policy(99, 10, None).transition(&base), Transition::Other);
}

/// R-CORE-21: the control reserve is a floor on the message rate and burst.
#[test]
fn a_policy_keeps_its_reserve_only_at_or_above_it() {
    use crate::rate_limit::Rate;

    let reserve = Rate {
        per_second: 10,
        burst: 2,
    };
    assert!(policy(10, 2, None).keeps(&reserve));
    assert!(policy(50, 5, Some((1, 1))).keeps(&reserve));
    assert!(!policy(9, 5, None).keeps(&reserve));
    assert!(!policy(50, 1, None).keeps(&reserve));
}

/// R-CORE-21: a new policy earns the old rates up to the change, then
/// clamps each level to its new burst and never raises it; a byte limit
/// added starts empty and earns at its own rate.
#[test]
fn a_policy_change_clamps_and_never_grants_tokens() {
    use crate::rate_limit::RateLimiter;

    let mut limiter = RateLimiter::new(policy(10, 8, None), 0);
    for _ in 0..6 {
        assert!(limiter.try_admit(100, true));
    }
    assert_eq!(limiter.message_tokens(), 2);
    // 0.1 s at the old 10/s earns one token, then the tighter burst of 2
    // clamps the 3 held.
    limiter.set_policy(policy(5, 2, Some((1_000, 500))), 100_000_000);
    assert_eq!(limiter.message_tokens(), 2);
    assert_eq!(limiter.byte_tokens(), Some(0));
    assert!(
        !limiter.try_admit(100, true),
        "the new byte limit starts empty"
    );
    // A looser policy does not refill either: the level stays.
    limiter.set_policy(policy(100, 50, None), 100_000_000);
    assert_eq!(limiter.message_tokens(), 2);
    assert_eq!(limiter.byte_tokens(), None);
    // Then it earns at the new rate: 0.1 s at 100/s.
    limiter.refill_at(200_000_000);
    assert_eq!(limiter.message_tokens(), 12);
}
