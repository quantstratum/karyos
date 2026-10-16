// SPDX-License-Identifier: Apache-2.0

//! The guard gate of a lane sender (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, The sender gate and applied epoch,
//! and Rate limits; G-e2b).
//!
//! A [`GuardGate`] serves one guard for one [`LaneSender`]: each DRR lane
//! is one guarded incarnation's publication lane, bound to the open epoch
//! it was admitted under. The gate is both the probe's predicate
//! ([`LaneGate::admits`]) and the exposure-time check
//! ([`SenderGate::check`]):
//!
//! - **Guard.** One Acquire load of the guard word per check. A word other
//!   than exactly `(e, Open)` denies the exposure and puts the lane's
//!   incarnation in `Aborting` for good; a later reopen cannot resume it.
//!   If the observed epoch is above the applied epoch, the gate publishes
//!   it once, with the last positions submitted per lane, through the
//!   [`AppliedEpoch`] cell.
//! - **Rate.** The authoritative bucket of the publication, one per gate:
//!   a channel's lanes are one publication (GC-5, ACS 15344). A head the
//!   bucket cannot pay for is held in order, never skipped; its lane is
//!   ineligible, so it forfeits its DRR deficit as any lane its gate
//!   closed, and with the bucket empty every lane is held. Tokens are reserved when an exposure is permitted and kept
//!   once the head is reported submitted (or unknown, which may have left).
//!   A head exposed again while pending is not charged twice; a head that
//!   left without exposure, or that an abort or a reopen drops, gets its
//!   tokens back. Only first sends are charged.
//!
//! The gate records each staged head in step with the sender's own record
//! ([`GuardGate::staged`] next to [`LaneSender::staged`]) and hears of each
//! head that left through [`LaneGate::left`]. It allocates only in
//! [`GuardGate::new`].
//!
//! [`LaneSender`]: karyos_io::lanes::LaneSender
//! [`LaneSender::staged`]: karyos_io::lanes::LaneSender::staged

use std::collections::VecDeque;
use std::sync::Arc;

use core::num::NonZeroU16;

use karyos_client::HeapWords;
use karyos_io::backend::{Exposure, GateDecision, SenderGate, SenderToken};
use karyos_io::lanes::{LaneGate, Left, Staged};
use karyos_sys::applied_epoch::{Applied, AppliedEpoch};
use karyos_sys::frame::Lane;
use karyos_sys::guard::{self, GuardState};
use karyos_sys::rate_limit::{RateLimiter, RatePolicy};

/// One DRR lane of a gate: a guarded incarnation's publication lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateLane {
    /// The publication lane, which indexes the applied positions.
    pub lane: Lane,
    /// The open epoch the incarnation was admitted under.
    pub epoch: u64,
    /// Heads the lane may record: its queue's bound.
    pub bound: usize,
}

/// A head staged on a lane, as the gate sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateHead {
    /// The token the head's frame was committed with.
    pub token: SenderToken,
    /// Its frame length in bytes: its byte charge.
    pub length: u64,
    /// Whether it carries the first frame of a message: one message token.
    pub first_of_message: bool,
    /// The stream position just past it.
    pub end: u64,
}

/// Why [`GuardGate::staged`] refused a head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GateStageError {
    /// No such lane.
    #[error("no gate lane {lane}")]
    UnknownLane {
        /// The lane named.
        lane: usize,
    },
    /// The lane already records its bound.
    #[error("gate lane {lane} is full")]
    Full {
        /// The lane named.
        lane: usize,
    },
}

/// What a gate counted, for the driver's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GateCounts {
    /// Probes and checks that held a head for its rate: not faults.
    pub rate_held: u64,
    /// Exposures denied because the guard was not the lane's open epoch.
    pub guard_denied: u64,
    /// Incarnations that entered `Aborting`.
    pub aborted: u64,
    /// Applied epochs published.
    pub applied: u64,
    /// Exposures that contradicted the gate's record (a token other than
    /// its head's, more candidates than staged heads, two lanes' heads): a
    /// sender fault, denied.
    pub faults: u64,
    /// Guard words that broke the encoding, treated as closed.
    pub corrupt: u64,
    /// Counts that would have overflowed and kept their last value.
    pub overflows: u64,
}

/// Adds one to `count`; at its end it keeps its value and `overflows`
/// counts it (SPEC.md section 14: checked, never wrapped).
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

#[derive(Debug, Clone, Copy)]
struct Head {
    head: GateHead,
    /// Its tokens are reserved: it was permitted and has not left.
    charged: bool,
}

#[derive(Debug)]
struct State {
    lane: Lane,
    epoch: u64,
    heads: VecDeque<Head>,
    bound: usize,
    aborting: bool,
}

fn refund(limiter: &mut Option<RateLimiter>, entry: &Head) {
    if entry.charged
        && let Some(limiter) = limiter
    {
        limiter.refund(entry.head.length, entry.head.first_of_message);
    }
}

/// The gate of one guard over one lane sender's lanes.
#[derive(Debug)]
pub struct GuardGate {
    word: Arc<HeapWords>,
    cell: Arc<AppliedEpoch>,
    lanes: Vec<State>,
    /// The publication's bucket, shared by its lanes.
    limiter: Option<RateLimiter>,
    /// The epoch last published to the cell.
    applied: u64,
    /// The last position submitted per publication lane.
    submitted: [u64; Lane::COUNT as usize],
    counts: GateCounts,
}

impl GuardGate {
    /// A gate over the guard `word` (word 0 of the guard's view), writing
    /// its applied epoch to `cell`, for `lanes` in DRR lane order, with the
    /// publication's validated `rate` policy. Every buffer it will use is
    /// allocated here; the bucket starts full at clock time `now`.
    #[must_use]
    pub fn new(
        word: Arc<HeapWords>,
        cell: Arc<AppliedEpoch>,
        lanes: &[GateLane],
        rate: Option<RatePolicy>,
        now: u64,
    ) -> Self {
        let lanes = lanes
            .iter()
            .map(|lane| State {
                lane: lane.lane,
                epoch: lane.epoch,
                heads: VecDeque::with_capacity(lane.bound),
                bound: lane.bound,
                aborting: false,
            })
            .collect();
        Self {
            word,
            cell,
            lanes,
            limiter: rate.map(|policy| RateLimiter::new(policy, now)),
            applied: 0,
            submitted: [0; Lane::COUNT as usize],
            counts: GateCounts::default(),
        }
    }

    /// What the gate counted.
    #[must_use]
    pub fn counts(&self) -> GateCounts {
        self.counts
    }

    /// Whether `lane`'s incarnation is aborting.
    #[must_use]
    pub fn aborting(&self, lane: usize) -> Option<bool> {
        self.lanes.get(lane).map(|state| state.aborting)
    }

    /// The last position submitted on publication lane `lane`.
    #[must_use]
    pub fn last_submitted(&self, lane: Lane) -> u64 {
        self.submitted
            .get(usize::from(lane.get()))
            .copied()
            .unwrap_or(0)
    }

    /// Whole message tokens the bucket holds; `None` without a rate.
    #[must_use]
    pub fn message_tokens(&self) -> Option<u64> {
        self.limiter.as_ref().map(RateLimiter::message_tokens)
    }

    /// Whole byte tokens the bucket holds; `None` without a byte rate.
    #[must_use]
    pub fn byte_tokens(&self) -> Option<u64> {
        self.limiter.as_ref().and_then(RateLimiter::byte_tokens)
    }

    /// Refills the bucket from the clock time `now`, before a serve call.
    /// A backward step earns nothing.
    pub fn set_now(&mut self, now: u64) {
        if let Some(limiter) = &mut self.limiter {
            limiter.refill_at(now);
        }
    }

    /// Records a head committed to `lane`'s queue, at its tail, next to
    /// [`karyos_io::lanes::LaneSender::staged`].
    ///
    /// # Errors
    ///
    /// See [`GateStageError`]; nothing is recorded on error.
    pub fn staged(&mut self, lane: usize, head: GateHead) -> Result<(), GateStageError> {
        let state = self
            .lanes
            .get_mut(lane)
            .ok_or(GateStageError::UnknownLane { lane })?;
        if state.heads.len() >= state.bound {
            return Err(GateStageError::Full { lane });
        }
        state.heads.push_back(Head {
            head,
            charged: false,
        });
        Ok(())
    }

    /// The control path gave `lane` a new queue
    /// ([`karyos_io::lanes::LaneSender::reopen`]): its records go, and the
    /// tokens reserved for them come back, since the reset returned them
    /// unsent.
    pub fn reopen(&mut self, lane: usize) {
        if let Some(state) = self.lanes.get_mut(lane) {
            while let Some(entry) = state.heads.pop_front() {
                refund(&mut self.limiter, &entry);
            }
        }
    }

    /// The guard is no longer `lane`'s open epoch: its incarnation aborts
    /// for good, once, and an epoch above the applied one is published
    /// once, with the last positions submitted per lane.
    fn deny_guard(&mut self, index: usize, observed: Option<GuardState>) {
        bump(&mut self.counts.guard_denied, &mut self.counts.overflows);
        self.apply_close(index, observed);
    }

    /// `index`'s incarnation aborts for good, once, and an observed epoch
    /// above the applied one is published once.
    fn apply_close(&mut self, index: usize, observed: Option<GuardState>) {
        if let Some(state) = self.lanes.get_mut(index)
            && !state.aborting
        {
            state.aborting = true;
            // Reserved tokens of heads that will never be sent come back.
            for entry in &mut state.heads {
                refund(&mut self.limiter, entry);
                entry.charged = false;
            }
            bump(&mut self.counts.aborted, &mut self.counts.overflows);
        }
        if let Some(observed) = observed
            && observed.epoch > self.applied
        {
            self.applied = observed.epoch;
            self.cell.publish(Applied {
                epoch: observed.epoch,
                positions: self.submitted,
            });
            bump(&mut self.counts.applied, &mut self.counts.overflows);
        }
    }

    /// The between gates step (`quantstratum-docs:
    /// karyos/design/driver-network-agents.md`, 3.1 step 10 and 6.1): once
    /// per sender cycle, even when nothing was flushed, so a close becomes
    /// effective with no pending traffic. A guard that is no longer a lane's
    /// open epoch aborts that incarnation and publishes the applied epoch,
    /// as a denied exposure does; nothing is exposed here.
    pub fn between_gates(&mut self) {
        let observed = self.load();
        for index in 0..self.lanes.len() {
            let Some(state) = self.lanes.get(index) else {
                continue;
            };
            let open = observed
                == Some(GuardState {
                    epoch: state.epoch,
                    open: true,
                });
            if !open {
                self.apply_close(index, observed);
            }
        }
    }

    /// The guard's state from one Acquire load; a corrupt word reads as
    /// `None`, which no epoch admits.
    fn load(&mut self) -> Option<GuardState> {
        match guard::load_in(&*self.word, 0) {
            Ok(state) => Some(state),
            Err(_) => {
                bump(&mut self.counts.corrupt, &mut self.counts.overflows);
                None
            }
        }
    }

    fn fault(&mut self) -> GateDecision {
        bump(&mut self.counts.faults, &mut self.counts.overflows);
        GateDecision::Deny
    }
}

impl SenderGate for GuardGate {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        let Some(&first) = candidate.tokens.first() else {
            return self.fault();
        };
        // The lane whose head the exposure starts with.
        let Some(index) = self.lanes.iter().position(|state| {
            state
                .heads
                .front()
                .is_some_and(|entry| entry.head.token == first)
        }) else {
            return self.fault();
        };
        let observed = self.load();
        let Some(state) = self.lanes.get(index) else {
            return self.fault();
        };
        let open = observed.is_some_and(|observed| {
            observed
                == GuardState {
                    epoch: state.epoch,
                    open: true,
                }
        });
        if state.aborting || !open {
            self.deny_guard(index, observed);
            return GateDecision::Deny;
        }
        // Each candidate must be the lane's next head, in order; the
        // prefix whose tokens are reserved is permitted.
        let limiter = &mut self.limiter;
        let Some(state) = self.lanes.get_mut(index) else {
            return self.fault();
        };
        if candidate.tokens.len() > state.heads.len() {
            return self.fault();
        }
        let mut permitted: u16 = 0;
        let mut fault = false;
        let mut held = false;
        for (entry, token) in state.heads.iter_mut().zip(candidate.tokens) {
            if entry.head.token != *token {
                fault = true;
                break;
            }
            if !entry.charged {
                let paid = limiter.as_mut().is_none_or(|limiter| {
                    limiter.try_admit(entry.head.length, entry.head.first_of_message)
                });
                if !paid {
                    held = true;
                    break;
                }
                entry.charged = true;
            }
            let Some(next) = permitted.checked_add(1) else {
                break;
            };
            permitted = next;
        }
        if held {
            bump(&mut self.counts.rate_held, &mut self.counts.overflows);
        }
        if fault {
            bump(&mut self.counts.faults, &mut self.counts.overflows);
        }
        NonZeroU16::new(permitted)
            .map_or(GateDecision::Deny, |count| GateDecision::Permit { count })
    }
}

impl LaneGate for GuardGate {
    fn admits(&mut self, lane: usize) -> bool {
        let Some(epoch) = self.lanes.get(lane).map(|state| state.epoch) else {
            return false;
        };
        // The probe asks the gate's rule, so a lane closed by its guard
        // aborts and publishes here as at an exposure (one Acquire load).
        let observed = self.load();
        let open = observed == Some(GuardState { epoch, open: true });
        let aborting = self.lanes.get(lane).is_none_or(|state| state.aborting);
        if aborting || !open {
            self.deny_guard(lane, observed);
            return false;
        }
        let Some(state) = self.lanes.get(lane) else {
            return false;
        };
        let Some(entry) = state.heads.front() else {
            return true;
        };
        let affordable = entry.charged
            || self.limiter.as_ref().is_none_or(|limiter| {
                limiter.admits(entry.head.length, entry.head.first_of_message)
            });
        if !affordable {
            bump(&mut self.counts.rate_held, &mut self.counts.overflows);
        }
        affordable
    }

    fn left(&mut self, lane: usize, _staged: Staged, how: Left) {
        let Some(state) = self.lanes.get_mut(lane) else {
            return;
        };
        let Some(entry) = state.heads.pop_front() else {
            return;
        };
        match how {
            Left::Submitted => {
                if let Some(slot) = self.submitted.get_mut(usize::from(state.lane.get())) {
                    *slot = (*slot).max(entry.head.end);
                }
            }
            // It may have been sent: its charge stays, and its position is
            // not counted as submitted.
            Left::Unknown => {}
            // It left without exposure: not a send.
            Left::Returned => refund(&mut self.limiter, &entry),
        }
    }
}

#[cfg(test)]
mod tests;
