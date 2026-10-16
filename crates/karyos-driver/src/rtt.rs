// SPDX-License-Identifier: Apache-2.0

//! RTT observations (`quantstratum-docs: karyos/design/reliable-transport.md`,
//! "RTT observations"; RC-1; P2.7 B).
//!
//! The receiver measures the round trip to the sender on each established
//! path with RTTM; the sender only replies.
//!
//! - **Probes** ([`RttProbes`], one per image). Each path holds at most one
//!   outstanding REQUEST, whose `probe_id` comes from a checked per-image
//!   counter starting at 1; exhaustion stops probing for good, never wraps.
//!   A probe is due every `rtt_probe_interval` and expires after
//!   `rtt_probe_timeout`. Its start is the time read immediately before the
//!   backend call that the backend reports as submitting it; a probe only
//!   accepted, failed or uncertain yields no sample.
//! - **Samples.** A REPLY is validated against the outstanding probe of its
//!   path and binding generation; a duplicate, expired, unmatched, wrong
//!   path or old generation reply changes no estimate and is counted. The
//!   sample is `age_ns(reply_seen, probe_start)` on the receiver's own
//!   clock; the REPLY's `service_delay_ns` is untrusted and never
//!   subtracted. A zero sample (a clock regression) is invalid and counted;
//!   a positive sample below `rtt_floor` counts as `rtt_floor`, a stated
//!   minimum.
//! - **Estimate.** A path's estimate is the largest of its last
//!   `rtt_sample_window` accepted samples, so one fast sample cannot
//!   shorten every retry at once; before the first sample, and after a
//!   rebinding, it is `rtt_initial`. A stale estimate is kept while probes
//!   continue. With redundant paths, NAK timing uses the largest estimate
//!   over the image's live paths ([`RttProbes::snapshot`]).
//! - **Replies** ([`RttReplies`], the sender's, per receiver): at most
//!   `rttm_reply_rate` per second; excess requests are dropped and counted.
//!
//! Every per-path array is sized at construction; the data calls do not
//! allocate. Times are checked: an overflowing deadline is never wrapped.

use karyos_sys::host_clock::age_ns;
use karyos_sys::rate_limit::{Rate, RateLimiter, RatePolicy};

/// The RTT settings (RC-1; provisional and configurable), in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttConfig {
    /// How often a path is probed (default 1 s).
    pub rtt_probe_interval: u64,
    /// When an outstanding probe expires (default 1 s).
    pub rtt_probe_timeout: u64,
    /// The least sample used (default 0.1 ms).
    pub rtt_floor: u64,
    /// The estimate before any sample (default 1 ms).
    pub rtt_initial: u64,
    /// Accepted samples kept per path (default 4).
    pub rtt_sample_window: u8,
    /// REPLYs a sender sends per receiver per second (default 16).
    pub rttm_reply_rate: u64,
}

impl Default for RttConfig {
    fn default() -> Self {
        Self {
            rtt_probe_interval: 1_000_000_000,
            rtt_probe_timeout: 1_000_000_000,
            rtt_floor: 100_000,
            rtt_initial: 1_000_000,
            rtt_sample_window: 4,
            rttm_reply_rate: 16,
        }
    }
}

/// Why an [`RttConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RttConfigError {
    /// `rtt_floor <= rtt_initial <= rtt_probe_timeout` does not hold, or
    /// the floor is zero.
    #[error("rtt_floor <= rtt_initial <= rtt_probe_timeout does not hold, or the floor is 0")]
    Order,
    /// The probe interval, the sample window or the reply rate is zero.
    #[error("the probe interval, the sample window or the reply rate is 0")]
    Zero,
}

impl RttConfig {
    /// Checks the settings, at configuration.
    ///
    /// # Errors
    ///
    /// See [`RttConfigError`].
    pub const fn validate(&self) -> Result<(), RttConfigError> {
        if self.rtt_floor == 0
            || self.rtt_floor > self.rtt_initial
            || self.rtt_initial > self.rtt_probe_timeout
        {
            return Err(RttConfigError::Order);
        }
        if self.rtt_probe_interval == 0 || self.rtt_sample_window == 0 || self.rttm_reply_rate == 0
        {
            return Err(RttConfigError::Zero);
        }
        Ok(())
    }
}

/// What the probes counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RttCounts {
    /// Probes handed out to send.
    pub probes: u64,
    /// Probes reported submitted: they can yield a sample.
    pub submitted: u64,
    /// Probes not submitted (accepted only, failed or uncertain).
    pub unsubmitted: u64,
    /// Probes that expired before a valid reply.
    pub expired: u64,
    /// Samples accepted.
    pub samples: u64,
    /// Accepted samples raised to `rtt_floor`.
    pub floored: u64,
    /// Zero samples: a clock regression, invalid.
    pub invalid: u64,
    /// Replies to the probe answered last: duplicates.
    pub duplicates: u64,
    /// Replies matching no outstanding probe of their path: unmatched,
    /// from the wrong path, of an old generation, or for an unsubmitted
    /// probe.
    pub unmatched: u64,
    /// Replies to an outstanding probe past its timeout.
    pub late: u64,
    /// Whether the probe ids are exhausted: probing stopped for good.
    pub exhausted: bool,
    /// Counts that would have overflowed and kept their last value.
    pub overflows: u64,
}

/// Adds one to `count`; at its end it keeps its value and `overflows`
/// counts it, itself kept at its end (SPEC.md section 14).
fn bump(count: &mut u64, overflows: &mut u64) {
    match count.checked_add(1) {
        Some(next) => *count = next,
        None => {
            if let Some(next) = overflows.checked_add(1) {
                *overflows = next;
            }
        }
    }
}

/// A probe on its way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Outstanding {
    probe_id: u64,
    /// When it was handed out, for its expiry.
    issued_at: u64,
    /// The time read before the submitting backend call, once the backend
    /// reported it submitted.
    start: Option<u64>,
}

/// One path of an image.
#[derive(Debug, Clone)]
struct PathRtt {
    /// The path binding's generation: a rebinding moves it.
    generation: u64,
    outstanding: Option<Outstanding>,
    /// The probe answered last, to tell a duplicate.
    answered: Option<u64>,
    /// When the last probe was handed out.
    last_probe: Option<u64>,
    /// The last accepted samples, oldest overwritten first.
    samples: Vec<u64>,
    next_sample: usize,
}

/// A probe the caller sends on a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// The path.
    pub path: usize,
    /// The path binding's generation, carried back with the reply.
    pub generation: u64,
    /// The REQUEST's `probe_id`.
    pub probe_id: u64,
}

/// What a REPLY did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyOutcome {
    /// A sample, in nanoseconds (raised to the floor if below it).
    Sample(u64),
    /// Counted and ignored: see [`RttCounts`].
    Ignored,
}

/// The receiver's RTT probes of one image.
#[derive(Debug)]
pub struct RttProbes {
    config: RttConfig,
    paths: Vec<PathRtt>,
    /// The next `probe_id`; `None` once exhausted.
    next_id: Option<u64>,
    counts: RttCounts,
}

impl RttProbes {
    /// The probes of an image with `paths` paths; it allocates only here.
    ///
    /// # Errors
    ///
    /// See [`RttConfigError`].
    pub fn new(config: RttConfig, paths: usize) -> Result<Self, RttConfigError> {
        config.validate()?;
        let window = usize::from(config.rtt_sample_window);
        Ok(Self {
            config,
            paths: (0..paths)
                .map(|_| PathRtt {
                    generation: 0,
                    outstanding: None,
                    answered: None,
                    last_probe: None,
                    samples: Vec::with_capacity(window),
                    next_sample: 0,
                })
                .collect(),
            next_id: Some(1),
            counts: RttCounts::default(),
        })
    }

    /// What the probes counted.
    #[must_use]
    pub fn counts(&self) -> RttCounts {
        self.counts
    }

    /// The probe `path` should send at `now`, if one is due: none is
    /// outstanding (an expired one is dropped and counted first) and
    /// `rtt_probe_interval` passed since the last. `None` once the probe
    /// ids are exhausted.
    pub fn due(&mut self, path: usize, now: u64) -> Option<Probe> {
        let timeout = self.config.rtt_probe_timeout;
        let interval = self.config.rtt_probe_interval;
        let state = self.paths.get_mut(path)?;
        if let Some(probe) = state.outstanding {
            if age_ns(now, probe.issued_at) < timeout {
                return None;
            }
            state.outstanding = None;
            bump(&mut self.counts.expired, &mut self.counts.overflows);
        }
        if state
            .last_probe
            .is_some_and(|last| age_ns(now, last) < interval)
        {
            return None;
        }
        let probe_id = self.next_id?;
        self.next_id = probe_id.checked_add(1);
        if self.next_id.is_none() {
            self.counts.exhausted = true;
        }
        state.outstanding = Some(Outstanding {
            probe_id,
            issued_at: now,
            start: None,
        });
        state.last_probe = Some(now);
        bump(&mut self.counts.probes, &mut self.counts.overflows);
        Some(Probe {
            path,
            generation: state.generation,
            probe_id,
        })
    }

    /// The backend reported `probe` submitted; `start` is the time read
    /// immediately before that backend call. Only a submitted probe can
    /// yield a sample.
    pub fn submitted(&mut self, probe: Probe, start: u64) {
        if let Some(outstanding) = self.outstanding_mut(probe) {
            outstanding.start = Some(start);
            bump(&mut self.counts.submitted, &mut self.counts.overflows);
        }
    }

    /// The backend did not submit `probe` (accepted only, failed or
    /// uncertain): it yields no sample, and the next is due at the
    /// interval.
    pub fn not_submitted(&mut self, probe: Probe) {
        if self.outstanding_mut(probe).is_some()
            && let Some(state) = self.paths.get_mut(probe.path)
        {
            state.outstanding = None;
            bump(&mut self.counts.unsubmitted, &mut self.counts.overflows);
        }
    }

    fn outstanding_mut(&mut self, probe: Probe) -> Option<&mut Outstanding> {
        let state = self.paths.get_mut(probe.path)?;
        if state.generation != probe.generation {
            return None;
        }
        state
            .outstanding
            .as_mut()
            .filter(|outstanding| outstanding.probe_id == probe.probe_id)
    }

    /// A validated RTTM REPLY with `probe_id` from `path` at binding
    /// `generation`, seen by the receive owner at `now`.
    pub fn reply(&mut self, path: usize, generation: u64, probe_id: u64, now: u64) -> ReplyOutcome {
        let timeout = self.config.rtt_probe_timeout;
        let floor = self.config.rtt_floor;
        let window = usize::from(self.config.rtt_sample_window);
        let Some(state) = self.paths.get_mut(path) else {
            bump(&mut self.counts.unmatched, &mut self.counts.overflows);
            return ReplyOutcome::Ignored;
        };
        let matched = state.outstanding.filter(|outstanding| {
            state.generation == generation && outstanding.probe_id == probe_id
        });
        let Some(outstanding) = matched else {
            let duplicate = state.generation == generation && state.answered == Some(probe_id);
            let count = if duplicate {
                &mut self.counts.duplicates
            } else {
                &mut self.counts.unmatched
            };
            bump(count, &mut self.counts.overflows);
            return ReplyOutcome::Ignored;
        };
        let Some(start) = outstanding.start else {
            bump(&mut self.counts.unmatched, &mut self.counts.overflows);
            return ReplyOutcome::Ignored;
        };
        state.outstanding = None;
        state.answered = Some(probe_id);
        if age_ns(now, outstanding.issued_at) >= timeout {
            bump(&mut self.counts.late, &mut self.counts.overflows);
            return ReplyOutcome::Ignored;
        }
        let sample = age_ns(now, start);
        if sample == 0 {
            bump(&mut self.counts.invalid, &mut self.counts.overflows);
            return ReplyOutcome::Ignored;
        }
        let sample = if sample < floor {
            bump(&mut self.counts.floored, &mut self.counts.overflows);
            floor
        } else {
            sample
        };
        if state.samples.len() < window {
            state.samples.push(sample);
        } else if let Some(slot) = state.samples.get_mut(state.next_sample) {
            *slot = sample;
        }
        state.next_sample = state
            .next_sample
            .checked_add(1)
            .filter(|next| *next < window)
            .unwrap_or(0);
        bump(&mut self.counts.samples, &mut self.counts.overflows);
        ReplyOutcome::Sample(sample)
    }

    /// `path` was bound again (a path lost and re-established): its
    /// generation moves, its samples go, and its estimate is
    /// `rtt_initial` until the first new sample. A reply to the old
    /// binding's probe is unmatched.
    pub fn rebind(&mut self, path: usize) {
        if let Some(state) = self.paths.get_mut(path) {
            state.generation = state.generation.checked_add(1).unwrap_or(state.generation);
            state.outstanding = None;
            state.answered = None;
            state.last_probe = None;
            state.samples.clear();
            state.next_sample = 0;
        }
    }

    /// `path`'s estimate: the largest of its last accepted samples, or
    /// `rtt_initial` before any.
    #[must_use]
    pub fn estimate(&self, path: usize) -> u64 {
        self.paths
            .get(path)
            .and_then(|state| state.samples.iter().copied().max())
            .unwrap_or(self.config.rtt_initial)
    }

    /// The RTT snapshot NAK timing uses for the image: the largest
    /// estimate over its live `paths`, or `rtt_initial` with none.
    #[must_use]
    pub fn snapshot(&self, paths: impl IntoIterator<Item = usize>) -> u64 {
        paths
            .into_iter()
            .map(|path| self.estimate(path))
            .max()
            .unwrap_or(self.config.rtt_initial)
    }
}

/// The sender's RTTM replies to one receiver: at most `rttm_reply_rate`
/// per second, excess requests dropped and counted.
#[derive(Debug)]
pub struct RttReplies {
    limiter: RateLimiter,
    dropped: u64,
    overflows: u64,
}

impl RttReplies {
    /// The replies to one receiver, starting at `now`.
    #[must_use]
    pub fn new(config: &RttConfig, now: u64) -> Self {
        let rate = Rate {
            per_second: config.rttm_reply_rate,
            burst: config.rttm_reply_rate,
        };
        Self {
            limiter: RateLimiter::new(
                RatePolicy {
                    messages: rate,
                    bytes: None,
                },
                now,
            ),
            dropped: 0,
            overflows: 0,
        }
    }

    /// Whether a valid REQUEST seen at `now` is answered; one that is not
    /// is dropped and counted.
    pub fn admit(&mut self, now: u64) -> bool {
        self.limiter.refill_at(now);
        if self.limiter.try_admit_datagram(0, 1) {
            return true;
        }
        bump(&mut self.dropped, &mut self.overflows);
        false
    }

    /// REQUESTs dropped over the rate.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The REPLY's `service_delay_ns`: from the REQUEST's receipt at
    /// `request_seen` to `now`, before the reply's submission. A bounded
    /// diagnostic: the receiver never subtracts it.
    #[must_use]
    pub fn service_delay(request_seen: u64, now: u64) -> u64 {
        age_ns(now, request_seen)
    }
}

#[cfg(test)]
mod tests;
