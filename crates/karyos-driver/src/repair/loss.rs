// SPDX-License-Identifier: Apache-2.0

//! The receiver's side of reliable repair for unicast
//! (`quantstratum-docs: karyos/design/reliable-transport.md`, "Proposed
//! receiver loss state", "Timers, retries and suppression" and
//! "Unrecoverable loss, windows and terminal state"; phase 6; ACS 15711
//! and 15712), as a standalone component the receiver agent wires.
//!
//! Each image lane holds one earliest-gap decision. The caller reports the
//! lane's first hole every cycle ([`ImageLoss::observe`], from
//! `ReceiveOwner::first_hole`, already term-bounded) and asks what is due
//! ([`ImageLoss::due`]):
//!
//! - **NoGap.** No proven missing interval.
//! - **NakDue.** A hole was detected: its NAK is due at once (ordinary
//!   unicast adds no delay). A NAK that could not be submitted stays due.
//! - **AwaitRepair.** The NAK was submitted at `submitted_at`, with the RTT
//!   estimate copied then; it is due again when
//!   `age_ns(now, submitted_at) >= rtt`. New RTT samples do not move it.
//! - **Unrecoverable.** Retention evidence proves the loss, or the sender
//!   kept refusing the range: the gap owner closes or skips.
//!
//! A hole that shrinks from its front, or from its end, is the same hole: a
//! partial repair keeps its first-detection anchor, its state and its
//! retry anchor. A hole that lies elsewhere is a new decision. A hole
//! that disappears was repaired.
//!
//! **Uncertain submission (RC-6).** An uncertain NAK is treated as
//! submitted at the time it is reported; its retry is a new NAK from new
//! storage. The image holds at most one unresolved uncertain NAK; a second
//! one is a route fault for the session owner, and nothing more is
//! submitted on the image until [`ImageLoss::uncertain_resolved`].
//!
//! **Replies.** An ERR NAK_REPLY counts only when it echoes the lane's
//! outstanding NAK exactly: alias, identity, receiver block, lane, start
//! and length. `RANGE_INVALID` keeps the hole in its retry schedule; after
//! `range_invalid_limit` consecutive ones for the same interval the image
//! reports a protocol fault (RC-8) and closes, never by skipping.
//! `RANGE_UNAVAILABLE` makes the whole NAKed hole unrecoverable (RC-9,
//! ACS 15712), with the lowest retained position as evidence; when that
//! position lies at or beyond the end of the lane's receive window, the
//! image closes with `GapCannotResume` whatever the skip policy. Anything
//! else is counted and ignored.
//!
//! **Terminal.** After a protocol fault or `GapCannotResume` the image is
//! closed: nothing more is due and observations change nothing. Recovery
//! is a fresh establishment.
//!
//! **RTT.** NAK timing reads the image's RTT snapshot through
//! [`RttSource`] at each submission ([`RttProbes`] in the agent, a fake in
//! tests); the value is copied, so later samples do not move a retry.
//!
//! Multicast cycles with B+C suppression and the redundant-path skew wait
//! come later. Nothing here allocates; positions and times are checked.

use karyos_protocol::frame::Lane;
use karyos_protocol::network::{
    Alias, Identity, MAX_NAK_LENGTH, Nak, NakRange, NakReply, NakReplyReason, Receiver,
};
use karyos_sys::host_clock::age_ns;

use crate::rtt::{ProbeIds, RttProbes};

/// Where NAK timing reads the RTT of an image's path.
pub trait RttSource {
    /// The RTT snapshot for `path`, in ns.
    fn rtt_snapshot(&self, path: usize) -> u64;
}

impl<I: ProbeIds> RttSource for RttProbes<I> {
    fn rtt_snapshot(&self, path: usize) -> u64 {
        self.snapshot([path])
    }
}

/// A frame's alignment and the shortest NAK.
const FRAME: u32 = 32;

/// The most lanes an image has.
const MAX_LANES: usize = 4;

/// The receiver's repair limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossConfig {
    /// Consecutive `RANGE_INVALID` replies for one interval before the
    /// image reports a protocol fault (`range_invalid_limit`, RC-8,
    /// default 3).
    pub range_invalid_limit: u32,
}

impl Default for LossConfig {
    fn default() -> Self {
        Self {
            range_invalid_limit: 3,
        }
    }
}

/// A configuration the component refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LossConfigError {
    /// `range_invalid_limit` is zero.
    #[error("range_invalid_limit is zero")]
    ZeroLimit,
    /// The image has no lanes or more than four.
    #[error("an image has 1 to 4 lanes")]
    LaneCount,
}

/// One missing interval of a lane, within one term.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hole {
    /// The first missing position.
    pub start: u64,
    /// Its length in bytes.
    pub length: u32,
}

impl Hole {
    /// The end of the hole, or `None` past `u64`.
    fn end(self) -> Option<u64> {
        self.start.checked_add(u64::from(self.length))
    }

    /// Whether `other` is what remains of `self` after a partial repair:
    /// a nonempty interval inside it.
    fn contains(self, other: Self) -> bool {
        match (self.end(), other.end()) {
            (Some(end), Some(other_end)) => other.start >= self.start && other_end <= end,
            _ => false,
        }
    }
}

/// A lane's earliest-gap decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    NoGap,
    NakDue {
        hole: Hole,
        detected_at: u64,
    },
    AwaitRepair {
        hole: Hole,
        detected_at: u64,
        /// The range of the NAK submitted, which a reply must echo.
        requested: Hole,
        submitted_at: u64,
        /// The RTT estimate copied at submission.
        rtt: u64,
    },
    Unrecoverable {
        hole: Hole,
    },
}

#[derive(Debug, Clone, Copy)]
struct LaneLoss {
    decision: Decision,
    /// Consecutive `RANGE_INVALID` replies for the current interval.
    invalid: u32,
    /// The range of the decision's first NAK: a later hole inside it is
    /// the same decision, with the same anchors, after late data split it.
    span: Option<Hole>,
    /// The range a `RANGE_UNAVAILABLE` answered (the NAK it echoed), with
    /// its lowest retained position: a later hole inside that range is
    /// unrecoverable at once (RC-9). A hole outside it, even inside the
    /// span, is still the sender's to repair.
    unavailable: Option<(Hole, u64)>,
    /// The decision's hole was found unnameable (counted once).
    unnameable: bool,
}

impl LaneLoss {
    const IDLE: Self = Self {
        decision: Decision::NoGap,
        invalid: 0,
        span: None,
        unavailable: None,
        unnameable: false,
    };
}

/// What an observation found that the gap owner must act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// Nothing for the gap owner.
    Nothing,
    /// A hole inside a span `RANGE_UNAVAILABLE` already answered: it is
    /// unrecoverable at once, never NAKed again (RC-9, ACS 15712).
    Unrecoverable {
        /// The lane.
        lane: Lane,
        /// The hole.
        hole: Hole,
        /// The lowest retained position of the span's reply.
        lowest_retained: u64,
    },
}

/// What a reply did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyOutcome {
    /// It did not echo an outstanding NAK of this image: counted, no
    /// change.
    Unmatched,
    /// `RANGE_INVALID`, below the limit: the hole stays in its retry
    /// schedule.
    StillDue,
    /// `range_invalid_limit` consecutive `RANGE_INVALID`: the image
    /// reports a protocol fault and closes with the unresolved range,
    /// never by skipping.
    ProtocolFault {
        /// The lane.
        lane: Lane,
        /// The unresolved range.
        hole: Hole,
    },
    /// `RANGE_UNAVAILABLE` with the lowest retained position at or beyond
    /// the end of the lane's receive window: the image closes with
    /// `GapCannotResume`, whatever the skip policy; it is terminal.
    GapCannotResume {
        /// The lane.
        lane: Lane,
        /// The unresolved hole.
        hole: Hole,
        /// The sender's lowest retained position.
        lowest_retained: u64,
    },
    /// `RANGE_UNAVAILABLE`: the whole hole is unrecoverable; the caller
    /// rechecks arrival and hands it to the gap owner.
    Unrecoverable {
        /// The lane.
        lane: Lane,
        /// The whole hole.
        hole: Hole,
        /// The sender's lowest retained position: the evidence.
        lowest_retained: u64,
    },
}

/// A second uncertain NAK while one is unresolved (RC-6): a route fault
/// for the session owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a second uncertain NAK while one is unresolved")]
pub struct RouteFault;

/// The component's counters; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LossCounters {
    /// Holes detected (new decisions).
    pub detected: u64,
    /// Holes repaired (gone before they became unrecoverable).
    pub repaired: u64,
    /// Partial repairs: a hole that shrank and kept its anchors.
    pub partial_repairs: u64,
    /// NAKs submitted, first sends and retries.
    pub submitted: u64,
    /// Retries: NAKs due again after one RTT.
    pub retries: u64,
    /// NAKs due that could not be submitted (budget or backend).
    pub not_submitted: u64,
    /// Uncertain submissions.
    pub uncertain: u64,
    /// Second uncertain submissions while one was unresolved.
    pub route_faults: u64,
    /// NAKs not built: a hole that no NAK can name (misaligned or too
    /// long; never from a valid receive owner).
    pub unnameable: u64,
    /// Replies that echoed no outstanding NAK.
    pub replies_unmatched: u64,
    /// `RANGE_INVALID` replies matched.
    pub range_invalid: u64,
    /// `RANGE_UNAVAILABLE` replies matched.
    pub range_unavailable: u64,
    /// Protocol faults after `range_invalid_limit`.
    pub protocol_faults: u64,
    /// Closes with `GapCannotResume`.
    pub gap_cannot_resume: u64,
    /// `RANGE_UNAVAILABLE` replies whose lowest retained position is at or
    /// below the hole's start: contradictory, counted.
    pub anomalies: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

impl LossCounters {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64) {
        let mut overflowed = self.overflowed;
        let value = field(self);
        match value.checked_add(1) {
            Some(next) => *value = next,
            None => overflowed = true,
        }
        self.overflowed = overflowed;
    }
}

/// One image's repair state on the receiver.
#[derive(Debug, Clone)]
pub struct ImageLoss {
    config: LossConfig,
    alias: Alias,
    identity: Identity,
    /// The image's receiver block, as its SMs carry it.
    receiver: Receiver,
    /// The path whose RTT times its NAKs.
    path: usize,
    /// Closed by a protocol fault or `GapCannotResume`.
    closed: bool,
    lanes: [LaneLoss; MAX_LANES],
    lane_count: usize,
    /// An uncertain NAK is unresolved (RC-6).
    uncertain: bool,
    /// A route fault was reported: nothing is submitted until the
    /// uncertain outcome is resolved.
    faulted: bool,
    counters: LossCounters,
}

impl ImageLoss {
    /// The repair state of an image of `lane_count` lanes.
    ///
    /// # Errors
    ///
    /// [`LossConfigError`] for a zero limit or a lane count outside 1 to 4.
    pub fn new(
        config: LossConfig,
        alias: Alias,
        identity: Identity,
        receiver: Receiver,
        lane_count: u8,
        path: usize,
    ) -> Result<Self, LossConfigError> {
        if config.range_invalid_limit == 0 {
            return Err(LossConfigError::ZeroLimit);
        }
        let lane_count = usize::from(lane_count);
        if !(1..=MAX_LANES).contains(&lane_count) {
            return Err(LossConfigError::LaneCount);
        }
        Ok(Self {
            config,
            alias,
            identity,
            receiver,
            path,
            closed: false,
            lanes: [LaneLoss::IDLE; MAX_LANES],
            lane_count,
            uncertain: false,
            faulted: false,
            counters: LossCounters::default(),
        })
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> LossCounters {
        self.counters
    }

    /// Whether the image closed (a protocol fault or `GapCannotResume`).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn lane_mut(&mut self, lane: Lane) -> Option<&mut LaneLoss> {
        let index = usize::from(lane.get());
        if index >= self.lane_count {
            return None;
        }
        self.lanes.get_mut(index)
    }

    /// The lane's first hole at `now`, as the receive owner reports it
    /// (`None` while nothing above the prefix is missing).
    ///
    /// - A new hole is detected and due at once.
    /// - A hole inside the current one is a partial repair: it keeps every
    ///   anchor, and the `RANGE_INVALID` count starts over.
    /// - A hole inside the span of the decision's NAK, after late data
    ///   split it, is the same decision with the same anchors; once
    ///   `RANGE_UNAVAILABLE` answered that span it is unrecoverable at
    ///   once, which the return value hands to the gap owner.
    /// - A hole elsewhere replaces the decision; no hole ends it.
    ///
    /// Besides [`ImageLoss::reply`], this is the only path by which RC-9
    /// reaches the gap owner: the caller acts on both.
    #[must_use = "an unrecoverable hole must reach the gap owner"]
    pub fn observe(&mut self, lane: Lane, hole: Option<Hole>, now: u64) -> Observation {
        if self.closed {
            return Observation::Nothing;
        }
        let Some(state) = self.lane_mut(lane) else {
            return Observation::Nothing;
        };
        let current = match state.decision {
            Decision::NoGap => None,
            Decision::NakDue { hole, .. }
            | Decision::AwaitRepair { hole, .. }
            | Decision::Unrecoverable { hole } => Some(hole),
        };
        let in_span = |seen: Hole| state.span.is_some_and(|span| span.contains(seen));
        let mut event: Option<fn(&mut LossCounters) -> &mut u64> = None;
        let mut observation = Observation::Nothing;
        match (current, hole) {
            (None, None) => {}
            (Some(_), None) => {
                if !matches!(state.decision, Decision::Unrecoverable { .. }) {
                    event = Some(|c| &mut c.repaired);
                }
                *state = LaneLoss::IDLE;
            }
            (Some(held), Some(seen)) if held == seen => {}
            (Some(held), Some(seen)) if held.contains(seen) || in_span(seen) => {
                let answered = state
                    .unavailable
                    .filter(|(answered, _)| answered.contains(seen));
                let was_unrecoverable = matches!(state.decision, Decision::Unrecoverable { .. });
                match answered {
                    // Inside the answered range: unrecoverable, reported to
                    // the gap owner once. A shrink of the hole it already
                    // has only narrows it; another part is reported.
                    Some((_, lowest_retained)) => {
                        state.decision = Decision::Unrecoverable { hole: seen };
                        if !(was_unrecoverable && held.contains(seen)) {
                            observation = Observation::Unrecoverable {
                                lane,
                                hole: seen,
                                lowest_retained,
                            };
                        }
                    }
                    // Outside it, after the answered part was resolved: the
                    // sender retains it, so it is due again at once.
                    None if was_unrecoverable => {
                        state.decision = Decision::NakDue {
                            hole: seen,
                            detected_at: now,
                        };
                    }
                    // A partial repair, or late data split the span: the
                    // remainder keeps its anchors.
                    None => match &mut state.decision {
                        Decision::NakDue { hole, .. }
                        | Decision::AwaitRepair { hole, .. }
                        | Decision::Unrecoverable { hole } => *hole = seen,
                        Decision::NoGap => {}
                    },
                }
                // Another interval: RANGE_INVALID counts start over.
                state.invalid = 0;
                event = Some(|c| &mut c.partial_repairs);
            }
            (_, Some(seen)) => {
                *state = LaneLoss {
                    decision: Decision::NakDue {
                        hole: seen,
                        detected_at: now,
                    },
                    ..LaneLoss::IDLE
                };
                event = Some(|c| &mut c.detected);
            }
        }
        if let Some(field) = event {
            self.counters.bump(field);
        }
        observation
    }

    /// The NAK due on `lane` at `now`, if any: a hole just detected or
    /// left unsubmitted, or one whose submission is at least its RTT old.
    /// Nothing changes until the caller reports the submission. `None`
    /// also while a route fault holds the image.
    pub fn due(&mut self, lane: Lane, now: u64) -> Option<Nak> {
        if self.faulted || self.closed {
            return None;
        }
        let (alias, identity, receiver) = (self.alias, self.identity, self.receiver);
        let state = self.lane_mut(lane)?;
        let hole = match state.decision {
            Decision::NakDue { hole, .. } => hole,
            Decision::AwaitRepair {
                hole,
                submitted_at,
                rtt,
                ..
            } if age_ns(now, submitted_at) >= rtt => hole,
            _ => return None,
        };
        let nameable = hole.length >= FRAME
            && hole.length <= MAX_NAK_LENGTH
            && hole.length.is_multiple_of(FRAME)
            && hole.start.is_multiple_of(u64::from(FRAME))
            && hole.end().is_some();
        if !nameable {
            // Never from a valid receive owner: one fault per decision.
            if !state.unnameable {
                state.unnameable = true;
                self.counters.bump(|c| &mut c.unnameable);
            }
            return None;
        }
        Some(Nak {
            alias,
            identity,
            receiver,
            range: NakRange {
                lane,
                length: hole.length,
                start: hole.start,
            },
        })
    }

    /// `nak`, from [`ImageLoss::due`], was submitted at `now`: its retry
    /// is due one RTT later, the snapshot copied now from `rtt`.
    pub fn submitted(&mut self, nak: &Nak, now: u64, rtt: &impl RttSource) {
        let rtt = rtt.rtt_snapshot(self.path);
        self.record_submission(nak, now, rtt);
    }

    /// `nak` could not be submitted (budget or backend): it stays due.
    pub fn not_submitted(&mut self, _nak: &Nak) {
        self.counters.bump(|c| &mut c.not_submitted);
    }

    /// `nak`'s submission is uncertain, reported at `now` (RC-6): it is
    /// treated as submitted then, and its retry is a new NAK.
    ///
    /// # Errors
    ///
    /// [`RouteFault`] when another uncertain NAK of the image is
    /// unresolved: nothing more is submitted on the image until
    /// [`ImageLoss::uncertain_resolved`].
    pub fn uncertain(
        &mut self,
        nak: &Nak,
        now: u64,
        rtt: &impl RttSource,
    ) -> Result<(), RouteFault> {
        if self.uncertain {
            self.faulted = true;
            self.counters.bump(|c| &mut c.route_faults);
            return Err(RouteFault);
        }
        self.uncertain = true;
        self.counters.bump(|c| &mut c.uncertain);
        let rtt = rtt.rtt_snapshot(self.path);
        self.record_submission(nak, now, rtt);
        Ok(())
    }

    /// The image's uncertain NAKs are resolved, by the endpoint reset or
    /// by the late completion (release proof) of the uncertain NAK:
    /// submissions resume.
    pub fn uncertain_resolved(&mut self) {
        self.uncertain = false;
        self.faulted = false;
    }

    fn record_submission(&mut self, nak: &Nak, now: u64, rtt: u64) {
        let requested = Hole {
            start: nak.range.start,
            length: nak.range.length,
        };
        let Some(state) = self.lane_mut(nak.range.lane) else {
            return;
        };
        let (hole, detected_at, retry) = match state.decision {
            Decision::NakDue { hole, detected_at } => (hole, detected_at, false),
            Decision::AwaitRepair {
                hole, detected_at, ..
            } => (hole, detected_at, true),
            _ => return,
        };
        if hole != requested {
            // Not the lane's current hole: a stale NAK.
            return;
        }
        // The decision's first NAK sets its span; retries of fragments
        // inside it keep it.
        if !state.span.is_some_and(|span| span.contains(requested)) {
            state.span = Some(requested);
        }
        state.decision = Decision::AwaitRepair {
            hole,
            detected_at,
            requested,
            submitted_at: now,
            rtt,
        };
        self.counters.bump(|c| &mut c.submitted);
        if retry {
            self.counters.bump(|c| &mut c.retries);
        }
    }

    /// An ERR NAK_REPLY: it counts only as an exact echo of a lane's
    /// outstanding NAK. `window_end` is the end of the lane's current
    /// receive window, which decides `GapCannotResume`.
    pub fn reply(&mut self, reply: &NakReply, window_end: u64) -> ReplyOutcome {
        let limit = self.config.range_invalid_limit;
        let ours = reply.alias == self.alias
            && reply.identity == self.identity
            && reply.receiver == self.receiver;
        let lane = reply.range.lane;
        let echoed = Hole {
            start: reply.range.start,
            length: reply.range.length,
        };
        let outstanding = ours
            && !self.closed
            && self.lane_mut(lane).is_some_and(|state| {
                matches!(state.decision,
                    Decision::AwaitRepair { requested, .. } if requested == echoed)
            });
        if !outstanding {
            self.counters.bump(|c| &mut c.replies_unmatched);
            return ReplyOutcome::Unmatched;
        }
        let Some(state) = self.lane_mut(lane) else {
            return ReplyOutcome::Unmatched;
        };
        let Decision::AwaitRepair {
            hole, requested, ..
        } = state.decision
        else {
            return ReplyOutcome::Unmatched;
        };
        match reply.reason {
            // An echo of a NAK for a larger interval, from before a partial
            // repair, keeps the hole due but does not count toward the
            // limit of the current interval.
            NakReplyReason::RangeInvalid if requested != hole => {
                self.counters.bump(|c| &mut c.range_invalid);
                ReplyOutcome::StillDue
            }
            NakReplyReason::RangeInvalid => {
                // A count past `u32` is past any limit.
                let next = state.invalid.checked_add(1);
                let fault = next.is_none_or(|count| count >= limit);
                if let Some(count) = next {
                    state.invalid = count;
                }
                if fault {
                    state.decision = Decision::Unrecoverable { hole };
                    self.closed = true;
                }
                self.counters.bump(|c| &mut c.range_invalid);
                if fault {
                    self.counters.bump(|c| &mut c.protocol_faults);
                    ReplyOutcome::ProtocolFault { lane, hole }
                } else {
                    ReplyOutcome::StillDue
                }
            }
            NakReplyReason::RangeUnavailable { lowest_retained } => {
                state.decision = Decision::Unrecoverable { hole };
                state.unavailable = Some((requested, lowest_retained));
                self.counters.bump(|c| &mut c.range_unavailable);
                // A floor at or below the hole's start contradicts the
                // refusal: still unrecoverable, and counted.
                if lowest_retained <= hole.start {
                    self.counters.bump(|c| &mut c.anomalies);
                }
                if lowest_retained >= window_end {
                    self.closed = true;
                    self.counters.bump(|c| &mut c.gap_cannot_resume);
                    return ReplyOutcome::GapCannotResume {
                        lane,
                        hole,
                        lowest_retained,
                    };
                }
                ReplyOutcome::Unrecoverable {
                    lane,
                    hole,
                    lowest_retained,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
