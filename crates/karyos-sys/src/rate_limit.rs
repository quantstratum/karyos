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
//! - Buckets start full.
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
            level: Self::nanos(rate.burst),
        }
    }

    const fn nanos(tokens: u64) -> u128 {
        // A u64 times 10^9 fits a u128.
        tokens as u128 * NANOS
    }

    /// Adds the tokens `elapsed` nanoseconds earn, capped at the burst.
    fn refill(&mut self, elapsed: u64) {
        let cap = Self::nanos(self.rate.burst);
        // elapsed and the rate are u64: their product fits a u128.
        let earned = u128::from(elapsed) * u128::from(self.rate.per_second);
        self.level = match self.level.checked_add(earned) {
            Some(level) if level < cap => level,
            _ => cap,
        };
    }

    fn holds(&self, tokens: u64) -> bool {
        self.level >= Self::nanos(tokens)
    }

    /// Takes `tokens`; the caller checked [`Self::holds`].
    fn take(&mut self, tokens: u64) {
        self.level -= Self::nanos(tokens);
    }

    /// Whole tokens held.
    fn tokens(&self) -> u64 {
        // The level is at most the burst in nano-tokens.
        u64::try_from(self.level / NANOS).unwrap_or(u64::MAX)
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
        let elapsed = age_ns(now, self.last);
        if elapsed > 0 {
            self.last = now;
            self.refill(elapsed);
        }
        self.try_admit(length, first_of_message)
    }

    /// Admits a first-send frame of `length` bytes with the tokens held:
    /// the first frame of a message costs one message token, and with a
    /// byte bucket every frame costs its length. Either every bucket is
    /// charged or none is; `false` means the frame waits, in order.
    pub fn try_admit(&mut self, length: u64, first_of_message: bool) -> bool {
        let message_ok = !first_of_message || self.messages.holds(1);
        let bytes_ok = self.bytes.as_ref().is_none_or(|bytes| bytes.holds(length));
        if !(message_ok && bytes_ok) {
            return false;
        }
        if first_of_message {
            self.messages.take(1);
        }
        if let Some(bytes) = &mut self.bytes {
            bytes.take(length);
        }
        true
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
