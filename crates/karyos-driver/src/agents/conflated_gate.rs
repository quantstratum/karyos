// SPDX-License-Identifier: Apache-2.0

//! The seal gate of a conflated network image lane (`quantstratum-docs:
//! karyos/design/conflated-network-images.md`, (b) and (c)): the receiver
//! side of the barrier mailbox.
//!
//! - While the view's feeder is not attached, a seal is permitted at once:
//!   no view exists to protect, and the feeder meets the committed gap
//!   itself while it catches up.
//! - Once attached, the gate posts the interval and answers Pending; it
//!   permits the seal once the feeder acknowledged, which it does only
//!   after its barrier recorded the loss. An acknowledged interval stays
//!   permitted until it is sealed (a seal can wait for its term), so it is
//!   never posted, and recorded, twice.
//! - Past `barrier_ack_timeout`, counted from the request's own post, it
//!   publishes the view's terminal cell (`TERMINAL_BARRIER_TIMEOUT`) and
//!   permits the seal. If the feeder claimed the cell first, the gate
//!   permits only once the cell reads published, answering Pending (and
//!   counting the wait) meanwhile, so a reader that sees the seal never
//!   reads a claimed, unpublished cell.
//! - A published terminal cell, whoever published it, closes the view:
//!   every later seal is permitted.
//!
//! The gate never blocks: every answer comes from a few atomic loads and
//! stores of the shared [`FreshnessLink`].

use karyos_sys::frame::Lane;
use karyos_sys::freshness::{FreshnessLink, TERMINAL_BARRIER_TIMEOUT, Terminal, TerminalCell};
use karyos_sys::host_clock::age_ns;
use karyos_sys::log_buffer::{GateAnswer, SealGate};

/// The smallest `barrier_ack_timeout`: ten idle sleeps of a duty loop
/// (1 ms each), so an ordinary conductor delay never reaches it.
pub const MIN_BARRIER_ACK_TIMEOUT_NS: u64 = 10_000_000;
/// The default `barrier_ack_timeout` (an owner flag of the design).
pub const DEFAULT_BARRIER_ACK_TIMEOUT_NS: u64 = 100_000_000;
/// The default `conductor_duty_period`: the longest idle sleep of the
/// default duty loops (`YieldThenSleep`, karyosd's backoff), 1 ms.
pub const DEFAULT_CONDUCTOR_DUTY_PERIOD_NS: u64 = 1_000_000;
/// How many conductor duty periods `barrier_ack_timeout` covers at least
/// (SPEC.md §7.1, "Lane seal and terminal closure"; owner decisions of
/// 2026-10-21, item 10).
pub const BARRIER_DUTY_PERIODS: u64 = 10;

/// Which bound a `barrier_ack_timeout` misses (SPEC.md §7.1; karyos#658).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BarrierAckBound {
    /// Below 10 ms.
    #[error("barrier_ack_timeout below 10 ms")]
    Floor,
    /// Below ten conductor duty periods (`conductor_duty_period`), or the
    /// product overflows.
    #[error("barrier_ack_timeout below ten conductor_duty_period")]
    DutyPeriods,
    /// On an unreliable channel, the skip policy's seal deadline plus
    /// `barrier_ack_timeout` reaches `far_window_timeout`: the far-window
    /// close could end the image before the fail-safe closes its view.
    #[error("unreliable seal deadline plus barrier_ack_timeout reaches far_window_timeout")]
    FarWindow,
}

/// Checks `timeout_ns` against its floor and against
/// [`BARRIER_DUTY_PERIODS`] periods of `duty_period_ns`, in that order.
///
/// # Errors
///
/// The first [`BarrierAckBound`] missed.
pub(crate) fn check_duty(timeout_ns: u64, duty_period_ns: u64) -> Result<(), BarrierAckBound> {
    if timeout_ns < MIN_BARRIER_ACK_TIMEOUT_NS {
        return Err(BarrierAckBound::Floor);
    }
    match duty_period_ns.checked_mul(BARRIER_DUTY_PERIODS) {
        Some(periods) if timeout_ns >= periods => Ok(()),
        _ => Err(BarrierAckBound::DutyPeriods),
    }
}

/// Checks `timeout_ns` against an unreliable image's skip deadlines:
/// `max(gap_reorder_timeout, path_skew_window) + barrier_ack_timeout <
/// far_window_timeout`. The far-window clock starts at the first `Ahead`
/// arrival (`SkipPolicy::arrived`), which can come as soon as a hole
/// appears, while the fail-safe counts from the hole's post, after its
/// seal deadline. A reliable image never closes by the far-window timer,
/// so this applies to unreliable channels only.
///
/// # Errors
///
/// [`BarrierAckBound::FarWindow`], also when the sum overflows.
pub(crate) fn check_far_window(
    timeout_ns: u64,
    skip: &karyos_sys::log_buffer::SkipConfig,
) -> Result<(), BarrierAckBound> {
    match skip.deadline_ns().checked_add(timeout_ns) {
        Some(total) if total < skip.far_window_timeout_ns => Ok(()),
        _ => Err(BarrierAckBound::FarWindow),
    }
}

/// What a gate did since its counts were last taken. Increments are
/// checked: one that would overflow keeps its value and sets `overflowed`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct GateCounts {
    /// Intervals posted to the feeder.
    pub(crate) posted: u64,
    /// Seals permitted after the feeder's acknowledgement.
    pub(crate) acknowledged: u64,
    /// Seals permitted at once: no feeder attached.
    pub(crate) unattached: u64,
    /// Acknowledgements that did not come within the bound: the terminal
    /// cell was published (or already held by the feeder).
    pub(crate) timeouts: u64,
    /// Answers Pending while the feeder's claimed cell was unpublished.
    pub(crate) claim_waits: u64,
    /// Posts the mailbox refused: the view closes as at a timeout.
    pub(crate) post_failures: u64,
    /// An increment did not apply because it would have overflowed.
    pub(crate) overflowed: bool,
}

impl GateCounts {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64) {
        let counter = field(self);
        match counter.checked_add(1) {
            Some(next) => *counter = next,
            None => self.overflowed = true,
        }
    }
}

/// An interval posted and not resolved.
#[derive(Debug, Clone, Copy)]
struct Posted {
    request: u64,
    start: u64,
    end: u64,
    /// When this request was posted: its bound counts from here.
    at: u64,
    /// The fail-safe ran for it.
    timed_out: bool,
}

/// The seal gate of one image's conflated lane.
#[derive(Debug)]
pub(crate) struct ConflatedGate {
    lane: Lane,
    link: FreshnessLink,
    timeout_ns: u64,
    posted: Option<Posted>,
    /// The interval the feeder acknowledged and not yet sealed.
    acknowledged: Option<(u64, u64)>,
    /// The view is terminally stale: every later seal is permitted.
    closed: bool,
    counts: GateCounts,
}

impl ConflatedGate {
    /// The gate of `lane` over `link`, with `timeout_ns` as
    /// `barrier_ack_timeout`.
    pub(crate) fn new(lane: Lane, link: FreshnessLink, timeout_ns: u64) -> Self {
        Self {
            lane,
            link,
            timeout_ns,
            posted: None,
            acknowledged: None,
            closed: false,
            counts: GateCounts::default(),
        }
    }

    /// Moves the gate to `link`, a recreated view's (SPEC.md §7.1, "recovery
    /// recreates the view"; karyos#658), once the current view's terminal
    /// cell is published: the gate starts over unattached, its counts
    /// kept. `false`, and nothing changes, while the current view is open.
    pub(crate) fn relink(&mut self, link: FreshnessLink) -> bool {
        if !self.terminal_published() {
            return false;
        }
        self.link = link;
        self.posted = None;
        self.acknowledged = None;
        self.closed = false;
        true
    }

    /// The conflated lane this gate holds.
    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    /// The counts since the last call, which resets them.
    pub(crate) fn take_counts(&mut self) -> GateCounts {
        std::mem::take(&mut self.counts)
    }

    /// Whether the terminal cell closed the view.
    #[cfg(test)]
    pub(crate) fn closed(&self) -> bool {
        self.closed
    }

    /// Whether the view's terminal cell is published.
    fn terminal_published(&self) -> bool {
        TerminalCell::read(&self.link.terminal_words()).is_some()
    }

    /// The fail-safe for `posted`: publishes the terminal cell once, then
    /// permits the seal when the cell reads published.
    fn fail_safe(&mut self, mut posted: Posted) -> GateAnswer {
        if !posted.timed_out {
            posted.timed_out = true;
            if let Ok(cell) = self.link.terminal() {
                // A lost claim is fine only once the winner published.
                let _ = cell.publish(Terminal {
                    start: posted.start,
                    end: posted.end,
                    reason: TERMINAL_BARRIER_TIMEOUT,
                });
            }
        }
        if self.terminal_published() {
            self.closed = true;
            self.posted = None;
            return GateAnswer::Permit;
        }
        self.counts.bump(|c| &mut c.claim_waits);
        self.posted = Some(posted);
        GateAnswer::Pending
    }
}

impl SealGate for ConflatedGate {
    fn before_seal(&mut self, lane: Lane, position: u64, extent: u32, now: u64) -> GateAnswer {
        if lane != self.lane || self.closed {
            return GateAnswer::Permit;
        }
        // A terminal cell published by anyone (the feeder's exhaustion,
        // say) leaves no view to protect.
        if self.terminal_published() {
            self.closed = true;
            self.posted = None;
            return GateAnswer::Permit;
        }
        let Some(end) = position.checked_add(u64::from(extent)) else {
            return GateAnswer::Permit;
        };
        // Acknowledged and not sealed yet (the seal waited for its term):
        // still permitted, never posted again.
        if self.acknowledged == Some((position, end)) {
            return GateAnswer::Permit;
        }
        let Ok(mailbox) = self.link.mailbox() else {
            return GateAnswer::Permit;
        };
        if let Some(posted) = self.posted {
            if !posted.timed_out && mailbox.is_acknowledged(posted.request) {
                self.posted = None;
                self.acknowledged = Some((posted.start, posted.end));
                if (posted.start, posted.end) == (position, end) {
                    self.counts.bump(|c| &mut c.acknowledged);
                    return GateAnswer::Permit;
                }
                // Not the interval acknowledged: post this one below.
            } else if posted.timed_out || age_ns(now, posted.at) >= self.timeout_ns {
                if !posted.timed_out {
                    self.counts.bump(|c| &mut c.timeouts);
                }
                return self.fail_safe(posted);
            } else {
                return GateAnswer::Pending;
            }
        }
        if !mailbox.is_attached() {
            self.counts.bump(|c| &mut c.unattached);
            return GateAnswer::Permit;
        }
        match mailbox.post(position, end) {
            Ok(request) => {
                self.counts.bump(|c| &mut c.posted);
                self.posted = Some(Posted {
                    request,
                    start: position,
                    end,
                    at: now,
                    timed_out: false,
                });
                GateAnswer::Pending
            }
            // A mailbox that cannot take the post cannot protect the view:
            // the fail-safe closes it before the seal.
            Err(_) => {
                self.counts.bump(|c| &mut c.post_failures);
                self.fail_safe(Posted {
                    request: 0,
                    start: position,
                    end,
                    at: now,
                    timed_out: false,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests;
