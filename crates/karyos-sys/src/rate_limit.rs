// SPDX-License-Identifier: Apache-2.0

//! Rate limits of a guarded publication (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, Rate limits, G6): token buckets per
//! publication, a message bucket and an optional byte bucket.
//!
//! - One message costs one message token, charged with its first frame;
//!   with a byte bucket, each frame costs its bytes in byte tokens.
//!   Retransmissions are never charged: the caller asks only for first
//!   sends.
//! - A frame is admitted only when every bucket it is charged to holds
//!   enough; then all of them are charged together, else none is.
//! - The core takes the elapsed time ([`RateLimiter::refill`]), so it is
//!   deterministic; [`RateLimiter::admit_frame`] is the thin wrapper that
//!   reads it with [`crate::host_clock::age_ns`] against the last refill,
//!   so a backward clock step refills nothing and never grants early.
//!   Levels are kept in nano-tokens, so a fraction of a token earned is
//!   never lost, and every product and sum is checked; a refill that would
//!   overflow caps the bucket at its burst, a stated limit of the
//!   algorithm.
//! - A limiter made with a policy ([`RateLimiter::new`]) starts full; one
//!   that takes a policy at run time ([`RateLimiter::empty`]) starts empty,
//!   as a change never grants tokens.
//!
//! The authoritative buckets live in the driver, at the sender gate; a
//! client keeps its own copy only to reject earlier.

use crate::host_clock::age_ns;

/// Nanoseconds per second: the scale of a level in nano-tokens.
const NANOS: u128 = 1_000_000_000;

/// A token rate and burst.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// Tokens added per second.
    pub per_second: u64,
    /// The most tokens the bucket holds.
    pub burst: u64,
}

/// A publication's rate limit policy, fixed on the control path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatePolicy {
    /// Messages per second and message burst.
    pub messages: Rate,
    /// Bytes per second and byte burst, when bytes are limited too.
    pub bytes: Option<Rate>,
}

/// Why a policy was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RatePolicyError {
    /// A rate or a burst of zero would never admit anything.
    #[error("a rate limit needs a nonzero rate and burst")]
    Zero,
    /// The byte burst cannot hold the largest frame, which would then wait
    /// for good and stall its lane.
    #[error("the byte burst {burst} cannot hold the largest frame of {frame} bytes")]
    BurstBelowFrame {
        /// The byte burst.
        burst: u64,
        /// The largest frame the publication can produce.
        frame: u64,
    },
}

impl RatePolicy {
    /// Checks the policy against the largest frame the publication can
    /// produce.
    ///
    /// # Errors
    ///
    /// [`RatePolicyError::Zero`] and [`RatePolicyError::BurstBelowFrame`].
    pub const fn validate(&self, largest_frame: u64) -> Result<(), RatePolicyError> {
        if self.messages.per_second == 0 || self.messages.burst == 0 {
            return Err(RatePolicyError::Zero);
        }
        if let Some(bytes) = self.bytes {
            if bytes.per_second == 0 || bytes.burst == 0 {
                return Err(RatePolicyError::Zero);
            }
            if bytes.burst < largest_frame {
                return Err(RatePolicyError::BurstBelowFrame {
                    burst: bytes.burst,
                    frame: largest_frame,
                });
            }
        }
        Ok(())
    }
}

/// What a change from one policy to another is (R-CORE-21;
/// `quantstratum-docs: karyos/design/guards-and-abort.md`, Rate limit
/// transitions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Provably tighter: no rate or burst grows and at least one shrinks,
    /// over messages and bytes; a byte limit added counts as tighter.
    Tightening,
    /// The same policy.
    Unchanged,
    /// Anything else: a loosening, a mixed change, or a byte limit
    /// removed. Never taken as a tightening (fail closed).
    Other,
}

impl RatePolicy {
    /// What changing from `self` to `next` is (R-CORE-21). Only a change in
    /// which every dimension stays or shrinks, and one shrinks, is a
    /// [`Transition::Tightening`]: a change that tightens one dimension and
    /// loosens another is [`Transition::Other`].
    #[must_use]
    pub const fn transition(&self, next: &Self) -> Transition {
        // Per dimension: -1 tighter, 0 the same, 1 looser.
        const fn order(old: u64, new: u64) -> i8 {
            if new < old {
                -1
            } else if new == old {
                0
            } else {
                1
            }
        }
        let (bytes_rate, bytes_burst, added, removed) = match (self.bytes, next.bytes) {
            (None, None) => (0, 0, false, false),
            // A byte limit added only takes away; removed, it only gives.
            (None, Some(_)) => (0, 0, true, false),
            (Some(_), None) => (0, 0, false, true),
            (Some(old), Some(new)) => (
                order(old.per_second, new.per_second),
                order(old.burst, new.burst),
                false,
                false,
            ),
        };
        let messages_rate = order(self.messages.per_second, next.messages.per_second);
        let messages_burst = order(self.messages.burst, next.messages.burst);
        let tighter =
            added || messages_rate < 0 || messages_burst < 0 || bytes_rate < 0 || bytes_burst < 0;
        let looser =
            removed || messages_rate > 0 || messages_burst > 0 || bytes_rate > 0 || bytes_burst > 0;
        match (tighter, looser) {
            (true, false) => Transition::Tightening,
            (false, false) => Transition::Unchanged,
            _ => Transition::Other,
        }
    }

    /// Whether `self` keeps at least `reserve`, the least message rate and
    /// burst a member needs for its cancellations and resolutions
    /// (R-CORE-21's control reserve), in both buckets: a byte limit keeps
    /// `reserve` messages of `frame` bytes each, its rate and its burst, so
    /// a tight byte bucket never holds back the reserved messages. Each
    /// reserved message counts as a full frame, since a cancel or a
    /// resolution may travel in one: on a stream of a 64 KiB MTU, a reserve
    /// of 10 messages a second needs a byte rate of at least 655 360 bytes
    /// a second.
    #[must_use]
    pub const fn keeps(&self, reserve: &Rate, frame: u64) -> bool {
        let messages =
            self.messages.per_second >= reserve.per_second && self.messages.burst >= reserve.burst;
        match self.bytes {
            None => messages,
            Some(bytes) => {
                messages
                    && bytes.per_second >= reserve.per_second.saturating_mul(frame)
                    && bytes.burst >= reserve.burst.saturating_mul(frame)
            }
        }
    }
}

/// One token bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bucket {
    rate: Rate,
    /// The level, in nano-tokens.
    level: u128,
}

impl Bucket {
    fn full(rate: Rate) -> Self {
        Self {
            rate,
            level: Self::cap(rate),
        }
    }

    /// A bucket of `rate` holding `level` nano-tokens, at most its burst.
    fn clamped(rate: Rate, level: u128) -> Self {
        Self {
            rate,
            level: level.min(Self::cap(rate)),
        }
    }

    /// `tokens` in nano-tokens; `None` on overflow, which a `u64` times
    /// 10^9 never reaches in a `u128`.
    fn nanos(tokens: u64) -> Option<u128> {
        u128::from(tokens).checked_mul(NANOS)
    }

    /// The burst in nano-tokens. A `u64` burst always fits; the fallback
    /// is unreachable.
    fn cap(rate: Rate) -> u128 {
        Self::nanos(rate.burst).unwrap_or(u128::MAX)
    }

    /// Adds the tokens `elapsed` nanoseconds earn, capped at the burst: a
    /// product or a sum that would overflow caps the bucket too.
    fn refill(&mut self, elapsed: u64) {
        let cap = Self::cap(self.rate);
        let earned = u128::from(elapsed).checked_mul(u128::from(self.rate.per_second));
        self.level = match earned.and_then(|earned| self.level.checked_add(earned)) {
            Some(level) if level < cap => level,
            _ => cap,
        };
    }

    fn holds(&self, tokens: u64) -> bool {
        Self::nanos(tokens).is_some_and(|need| self.level >= need)
    }

    /// Takes `tokens`; the caller checked [`Self::holds`], so the
    /// subtraction cannot fail. Were it to, nothing is taken.
    fn take(&mut self, tokens: u64) {
        let left = Self::nanos(tokens).and_then(|need| self.level.checked_sub(need));
        debug_assert!(left.is_some(), "a take the bucket does not hold");
        if let Some(left) = left {
            self.level = left;
        }
    }

    /// Gives back `tokens` taken earlier, capped at the burst: a sum that
    /// would overflow caps the bucket too.
    fn give(&mut self, tokens: u64) {
        let cap = Self::cap(self.rate);
        self.level = match Self::nanos(tokens).and_then(|back| self.level.checked_add(back)) {
            Some(level) if level < cap => level,
            _ => cap,
        };
    }

    /// Whole tokens held. The level is at most the burst in nano-tokens, so
    /// the quotient fits a `u64`; the burst is the unreachable fallback.
    fn tokens(&self) -> u64 {
        u64::try_from(self.level / NANOS).unwrap_or(self.rate.burst)
    }
}

/// The buckets of one publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimiter {
    messages: Bucket,
    bytes: Option<Bucket>,
    /// The clock time of the last refill, for [`Self::admit_frame`].
    last: u64,
}

impl RateLimiter {
    /// Full buckets for `policy`, the clock read at `now`. The caller
    /// validated the policy.
    #[must_use]
    pub fn new(policy: RatePolicy, now: u64) -> Self {
        Self {
            messages: Bucket::full(policy.messages),
            bytes: policy.bytes.map(Bucket::full),
            last: now,
        }
    }

    /// The policy its buckets follow.
    #[must_use]
    pub const fn policy(&self) -> RatePolicy {
        RatePolicy {
            messages: self.messages.rate,
            bytes: match &self.bytes {
                Some(bytes) => Some(bytes.rate),
                None => None,
            },
        }
    }

    /// Empty buckets for `policy`, the clock read at `now`: a limiter that
    /// takes a policy at run time, which never grants tokens (R-CORE-21).
    /// The caller validated the policy.
    #[must_use]
    pub fn empty(policy: RatePolicy, now: u64) -> Self {
        Self {
            messages: Bucket::clamped(policy.messages, 0),
            bytes: policy.bytes.map(|rate| Bucket::clamped(rate, 0)),
            last: now,
        }
    }

    /// Adds the tokens `elapsed` nanoseconds earn to every bucket, capped
    /// at its burst. The deterministic core: the caller measures `elapsed`.
    pub fn refill(&mut self, elapsed: u64) {
        if elapsed == 0 {
            return;
        }
        self.messages.refill(elapsed);
        if let Some(bytes) = &mut self.bytes {
            bytes.refill(elapsed);
        }
    }

    /// [`Self::refill`] for the time since the last refill, read from the
    /// clock at `now` with [`age_ns`] (a backward step earns nothing and
    /// keeps the last refill time), then [`Self::try_admit`].
    pub fn admit_frame(&mut self, now: u64, length: u64, first_of_message: bool) -> bool {
        self.refill_at(now);
        self.try_admit(length, first_of_message)
    }

    /// Whether [`Self::try_admit`] would admit a first-send frame of
    /// `length` bytes with the tokens held, charging nothing: a gate's
    /// check before the frame is sent.
    #[must_use]
    pub fn admits(&self, length: u64, first_of_message: bool) -> bool {
        self.admits_datagram(length, u64::from(first_of_message))
    }

    /// Whether a first-send datagram of `length` bytes that starts
    /// `messages` messages would be admitted with the tokens held, charging
    /// nothing. A datagram may carry several frames, each starting a
    /// message (`quantstratum-docs: karyos/design/aggregate-lanes.md`).
    #[must_use]
    pub fn admits_datagram(&self, length: u64, messages: u64) -> bool {
        let message_ok = messages == 0 || self.messages.holds(messages);
        message_ok && self.bytes.as_ref().is_none_or(|bytes| bytes.holds(length))
    }

    /// [`Self::refill`] for the time since the last refill, read from the
    /// clock at `now` as [`Self::admit_frame`] does, charging nothing.
    pub fn refill_at(&mut self, now: u64) {
        let elapsed = age_ns(now, self.last);
        if elapsed > 0 {
            self.last = now;
            self.refill(elapsed);
        }
    }

    /// Admits a first-send frame of `length` bytes with the tokens held:
    /// the first frame of a message costs one message token, and with a
    /// byte bucket every frame costs its length. Either every bucket is
    /// charged or none is; `false` means the frame waits, in order.
    pub fn try_admit(&mut self, length: u64, first_of_message: bool) -> bool {
        self.try_admit_datagram(length, u64::from(first_of_message))
    }

    /// Admits a first-send datagram of `length` bytes that starts
    /// `messages` messages: `messages` message tokens and, with a byte
    /// bucket, `length` byte tokens, all or none.
    pub fn try_admit_datagram(&mut self, length: u64, messages: u64) -> bool {
        if !self.admits_datagram(length, messages) {
            return false;
        }
        if messages > 0 {
            self.messages.take(messages);
        }
        if let Some(bytes) = &mut self.bytes {
            bytes.take(length);
        }
        true
    }

    /// Gives back what [`Self::try_admit`] charged a frame that was not
    /// sent after all (a reservation released), each bucket capped at its
    /// burst. The caller refunds only a charge it made.
    pub fn refund(&mut self, length: u64, first_of_message: bool) {
        self.refund_datagram(length, u64::from(first_of_message));
    }

    /// Gives back what [`Self::try_admit_datagram`] charged a datagram that
    /// was not sent after all, each bucket capped at its burst.
    pub fn refund_datagram(&mut self, length: u64, messages: u64) {
        if messages > 0 {
            self.messages.give(messages);
        }
        if let Some(bytes) = &mut self.bytes {
            bytes.give(length);
        }
    }

    /// Applies `policy`, a newer version of the publication's policy, at
    /// `now` (R-CORE-21): the buckets first earn what the old rates gave up
    /// to `now`, then take the new rates, each level clamped to its new
    /// burst and never raised. A byte limit the old policy did not have
    /// starts empty, so a change never grants tokens. The caller validated
    /// the policy and its transition.
    pub fn set_policy(&mut self, policy: RatePolicy, now: u64) {
        self.refill_at(now);
        self.messages = Bucket::clamped(policy.messages, self.messages.level);
        self.bytes = policy
            .bytes
            .map(|rate| Bucket::clamped(rate, self.bytes.as_ref().map_or(0, |bytes| bytes.level)));
    }

    /// Whole message tokens held at the last refill.
    #[must_use]
    pub fn message_tokens(&self) -> u64 {
        self.messages.tokens()
    }

    /// Whole byte tokens held at the last refill; `None` without a byte
    /// bucket.
    #[must_use]
    pub fn byte_tokens(&self) -> Option<u64> {
        self.bytes.as_ref().map(Bucket::tokens)
    }
}

#[cfg(all(test, not(loom)))]
mod tests;
