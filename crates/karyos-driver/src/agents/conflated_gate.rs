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
//!   after its barrier recorded the loss.
//! - Past `barrier_ack_timeout` it publishes the view's terminal cell
//!   (`TERMINAL_BARRIER_TIMEOUT`) and permits the seal. If the feeder
//!   claimed the cell first, the gate permits only once the cell reads
//!   published, answering Pending (and counting the wait) meanwhile, so a
//!   reader that sees the seal never reads a claimed, unpublished cell.
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

/// What a gate did since its counts were last taken.
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
}

impl GateCounts {
    fn bump(counter: &mut u64) {
        if let Some(next) = counter.checked_add(1) {
            *counter = next;
        }
    }
}

/// An interval posted and not resolved.
#[derive(Debug, Clone, Copy)]
struct Posted {
    request: u64,
    start: u64,
    end: u64,
    at: u64,
    timed_out: bool,
}

/// The seal gate of one image's conflated lane.
#[derive(Debug)]
pub(crate) struct ConflatedGate {
    lane: Lane,
    link: FreshnessLink,
    timeout_ns: u64,
    posted: Option<Posted>,
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
            closed: false,
            counts: GateCounts::default(),
        }
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

    /// The fail-safe for `posted`: publishes the terminal cell once, then
    /// permits the seal when the cell reads published.
    fn fail_safe(&mut self, mut posted: Posted) -> GateAnswer {
        if !posted.timed_out {
            posted.timed_out = true;
            GateCounts::bump(&mut self.counts.timeouts);
            if let Ok(cell) = self.link.terminal() {
                // A lost claim is fine only once the winner published.
                let _ = cell.publish(Terminal {
                    start: posted.start,
                    end: posted.end,
                    reason: TERMINAL_BARRIER_TIMEOUT,
                });
            }
        }
        if TerminalCell::read(&self.link.terminal_words()).is_some() {
            self.closed = true;
            self.posted = None;
            return GateAnswer::Permit;
        }
        GateCounts::bump(&mut self.counts.claim_waits);
        self.posted = Some(posted);
        GateAnswer::Pending
    }
}

impl SealGate for ConflatedGate {
    fn before_seal(&mut self, lane: Lane, position: u64, extent: u32, now: u64) -> GateAnswer {
        if lane != self.lane || self.closed {
            return GateAnswer::Permit;
        }
        let Some(end) = position.checked_add(u64::from(extent)) else {
            return GateAnswer::Permit;
        };
        let Ok(mailbox) = self.link.mailbox() else {
            return GateAnswer::Permit;
        };
        if let Some(posted) = self.posted {
            if !posted.timed_out && mailbox.is_acknowledged(posted.request) {
                self.posted = None;
                if (posted.start, posted.end) == (position, end) {
                    GateCounts::bump(&mut self.counts.acknowledged);
                    return GateAnswer::Permit;
                }
                // Not the interval acknowledged: post this one below.
            } else if posted.timed_out || age_ns(now, posted.at) >= self.timeout_ns {
                return self.fail_safe(posted);
            } else {
                return GateAnswer::Pending;
            }
        }
        if !mailbox.is_attached() {
            GateCounts::bump(&mut self.counts.unattached);
            return GateAnswer::Permit;
        }
        match mailbox.post(position, end) {
            Ok(request) => {
                GateCounts::bump(&mut self.counts.posted);
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
            Err(_) => self.fail_safe(Posted {
                request: 0,
                start: position,
                end,
                at: now,
                timed_out: false,
            }),
        }
    }
}

#[cfg(test)]
mod tests;
