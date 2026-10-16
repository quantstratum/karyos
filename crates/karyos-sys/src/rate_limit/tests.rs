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
