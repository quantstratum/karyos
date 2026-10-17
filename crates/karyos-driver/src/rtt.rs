// SPDX-License-Identifier: Apache-2.0

//! RTT observations (`quantstratum-docs: karyos/design/reliable-transport.md`,
//! "RTT observations"; RC-1; P2.7 B).
//!
//! The receiver measures the round trip to the sender on each established
//! path with RTTM; the sender only replies.
//!
//! - **Probes** ([`RttProbes`], one per image). Each path holds at most one
//!   outstanding REQUEST, whose `probe_id` is a random nonzero 64-bit value
//!   ([`ProbeIds`]), so an off-path spoofer cannot forge a reply and skew
//!   the RTT that NAK timing uses. In the driver the ids come from a pool
//!   ([`OsProbeIds`]) drawn from the operating system on the control path,
//!   at construction and at [`RttProbes::refill_ids`]; the duty path only
//!   takes one, with no system call. An empty pool or a failed draw sends
//!   nothing until the next interval and is counted. A probe is due every
//!   `rtt_probe_interval` and expires after `rtt_probe_timeout`. Its start
//!   is the time read immediately before the backend call that the backend
//!   reports as submitting it; a probe only accepted, failed or uncertain
//!   yields no sample.
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
//!   continue. A path whose binding generation is exhausted stops probing
//!   for good and is counted; the generation never wraps. With redundant
//!   paths, NAK timing uses the largest estimate over the image's live
//!   paths ([`RttProbes::snapshot`]).
//! - **Replies** ([`RttReplies`], the sender's): at most `rttm_reply_rate`
//!   per second per source endpoint, in a table of `rttm_reply_sources`
//!   (as the SETUP answer rate), so one source cannot starve the others;
//!   excess requests and sources beyond the table are dropped and counted.
//!
//! Every per-path array is sized at construction; the data calls do not
//! allocate. Times are checked: an overflowing deadline is never wrapped.

use std::net::SocketAddr;

use karyos_sys::host_clock::age_ns;

use crate::sessions::rate::{EndpointRates, RateRefused};

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
    /// REPLYs a sender sends per source endpoint per second (default 16).
    pub rttm_reply_rate: u64,
    /// Source endpoints the reply rate tracks at once (default 64).
    pub rttm_reply_sources: usize,
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
            rttm_reply_sources: 64,
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
    /// The probe interval, the sample window, the reply rate or the reply
    /// sources is zero.
    #[error("the probe interval, the sample window, the reply rate or the reply sources is 0")]
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
        if self.rtt_probe_interval == 0
            || self.rtt_sample_window == 0
            || self.rttm_reply_rate == 0
            || self.rttm_reply_sources == 0
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
    /// Probes not sent because the id source failed.
    pub id_failures: u64,
    /// Paths whose binding generation is exhausted: they stopped probing.
    pub generations_exhausted: u64,
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

/// Where probe ids come from: random nonzero 64-bit values.
pub trait ProbeIds {
    /// A fresh nonzero id, on the duty path; `None` when none is at hand.
    fn probe_id(&mut self) -> Option<u64>;

    /// Restocks the source, on the control path; returns whether it drew
    /// from its own source. The default does nothing.
    fn refill(&mut self) -> bool {
        false
    }
}

/// Probe ids the pool holds: a probe per path per `rtt_probe_interval`
/// for up to `MAX_PATHS` paths, twice over.
const ID_POOL: usize = 32;

/// The pool is restocked only at or below this many ids, so a refill each
/// control cycle makes no system call in steady state.
const ID_LOW_WATER: usize = ID_POOL / 2;

/// Probe ids from the operating system (`karyos_sys::random::fill_u64s`),
/// drawn into a pool on the control path ([`ProbeIds::refill`]); taking
/// one makes no system call, and a refill draws only once the pool is at
/// or below half full. Neither `Copy` nor `Clone`: a copied pool would
/// hand out the same ids twice.
#[derive(Debug)]
pub struct OsProbeIds {
    pool: [u64; ID_POOL],
    len: usize,
}

impl OsProbeIds {
    /// A full pool, drawn now: call it on the control path.
    #[must_use]
    pub fn new() -> Self {
        let mut ids = Self {
            pool: [0; ID_POOL],
            len: 0,
        };
        let _ = ids.refill();
        ids
    }

    /// The ids at hand.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no id is at hand.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for OsProbeIds {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeIds for OsProbeIds {
    fn probe_id(&mut self) -> Option<u64> {
        let last = self.len.checked_sub(1)?;
        let id = self.pool.get(last).copied()?;
        self.len = last;
        Some(id)
    }

    fn refill(&mut self) -> bool {
        if self.len > ID_LOW_WATER {
            return false;
        }
        let Some(missing) = self.pool.get_mut(self.len..) else {
            return false;
        };
        if karyos_sys::random::fill_u64s(missing).is_err() {
            return true;
        }
        // Zero draws are left out: an id is nonzero.
        let drawn = self.pool;
        let kept = drawn
            .iter()
            .take(self.len)
            .copied()
            .chain(drawn.iter().skip(self.len).copied().filter(|id| *id != 0));
        let mut len = 0;
        for (count, (slot, id)) in (1..).zip(self.pool.iter_mut().zip(kept)) {
            *slot = id;
            len = count;
        }
        self.len = len;
        true
    }
}

/// One path of an image.
#[derive(Debug, Clone)]
struct PathRtt {
    /// The path binding's generation: a rebinding moves it.
    generation: u64,
    /// The generation is exhausted: the path never probes again.
    retired: bool,
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
pub struct RttProbes<I: ProbeIds = OsProbeIds> {
    config: RttConfig,
    paths: Vec<PathRtt>,
    ids: I,
    counts: RttCounts,
}

impl RttProbes {
    /// The probes of an image with `paths` paths, with ids from the
    /// operating system drawn now; it allocates only here. Call it on the
    /// control path.
    ///
    /// # Errors
    ///
    /// See [`RttConfigError`].
    pub fn new(config: RttConfig, paths: usize) -> Result<Self, RttConfigError> {
        Self::with_ids(config, paths, OsProbeIds::new())
    }
}

impl<I: ProbeIds> RttProbes<I> {
    /// The probes of an image with `paths` paths, with ids from `ids`; it
    /// allocates only here.
    ///
    /// # Errors
    ///
    /// See [`RttConfigError`].
    pub fn with_ids(config: RttConfig, paths: usize, ids: I) -> Result<Self, RttConfigError> {
        config.validate()?;
        let window = usize::from(config.rtt_sample_window);
        Ok(Self {
            config,
            paths: (0..paths)
                .map(|_| PathRtt {
                    generation: 0,
                    retired: false,
                    outstanding: None,
                    answered: None,
                    last_probe: None,
                    samples: Vec::with_capacity(window),
                    next_sample: 0,
                })
                .collect(),
            ids,
            counts: RttCounts::default(),
        })
    }

    /// Restocks the probe ids, on the control path: the duty path only
    /// takes them. With [`OsProbeIds`] it draws only once the pool is at or
    /// below half full, so calling it every control cycle is free in steady
    /// state. Returns whether it drew from the source (a system call with
    /// [`OsProbeIds`]).
    pub fn refill_ids(&mut self) -> bool {
        self.ids.refill()
    }

    /// `path`'s binding generation, `None` for a path beyond the image's.
    #[must_use]
    pub fn generation(&self, path: usize) -> Option<u64> {
        self.paths.get(path).map(|state| state.generation)
    }

    /// What the probes counted.
    #[must_use]
    pub fn counts(&self) -> RttCounts {
        self.counts
    }

    /// The probe `path` should send at `now`, if one is due: none is
    /// outstanding (an expired one is dropped and counted first) and
    /// `rtt_probe_interval` passed since the last. `None` for a retired
    /// path, and when the id source fails (counted; the next try waits an
    /// interval).
    pub fn due(&mut self, path: usize, now: u64) -> Option<Probe> {
        let timeout = self.config.rtt_probe_timeout;
        let interval = self.config.rtt_probe_interval;
        let state = self.paths.get_mut(path).filter(|state| !state.retired)?;
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
        state.last_probe = Some(now);
        let Some(probe_id) = self.ids.probe_id().filter(|id| *id != 0) else {
            bump(&mut self.counts.id_failures, &mut self.counts.overflows);
            return None;
        };
        state.outstanding = Some(Outstanding {
            probe_id,
            issued_at: now,
            start: None,
        });
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
    /// binding's probe is unmatched. At an exhausted generation the path
    /// is retired instead: it never probes again, and that is counted.
    pub fn rebind(&mut self, path: usize) {
        if let Some(state) = self.paths.get_mut(path) {
            match state.generation.checked_add(1) {
                Some(next) => state.generation = next,
                None => {
                    if !state.retired {
                        state.retired = true;
                        bump(
                            &mut self.counts.generations_exhausted,
                            &mut self.counts.overflows,
                        );
                    }
                }
            }
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

/// The sender's RTTM replies: at most `rttm_reply_rate` per second per
/// source endpoint, in a bounded table of `rttm_reply_sources` (a source
/// idle for a second may be replaced); excess requests and sources beyond
/// the table are dropped and counted.
#[derive(Debug)]
pub struct RttReplies {
    rates: EndpointRates,
    dropped: u64,
    sources_full: u64,
    overflows: u64,
}

impl RttReplies {
    /// The sender's replies; the table is allocated here.
    ///
    /// # Errors
    ///
    /// See [`RttConfigError`].
    pub fn new(config: &RttConfig) -> Result<Self, RttConfigError> {
        config.validate()?;
        let rates = EndpointRates::new(config.rttm_reply_rate, config.rttm_reply_sources)
            .ok_or(RttConfigError::Zero)?;
        Ok(Self {
            rates,
            dropped: 0,
            sources_full: 0,
            overflows: 0,
        })
    }

    /// Whether a valid REQUEST from `source` seen at `now` is answered;
    /// one that is not is dropped and counted.
    pub fn admit(&mut self, source: SocketAddr, now: u64) -> bool {
        match self.rates.admit(source, now) {
            Ok(()) => true,
            Err(RateRefused::Limited) => {
                bump(&mut self.dropped, &mut self.overflows);
                false
            }
            Err(RateRefused::TableFull) => {
                bump(&mut self.sources_full, &mut self.overflows);
                false
            }
        }
    }

    /// REQUESTs dropped over their source's rate.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// REQUESTs dropped because the source table was full.
    #[must_use]
    pub fn sources_full(&self) -> u64 {
        self.sources_full
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
