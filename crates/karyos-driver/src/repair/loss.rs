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
//! **Multicast cycles, B with C** (owner decision P4; RC-2, RC-3, RC-5,
//! RC-14; ACS 15898), with [`ImageLoss::multicast`]. A hole's NAK is not
//! due at once: the caller runs [`ImageLoss::cycle`] each step, which
//! starts a cycle with one delay `d` drawn uniformly from
//! `[0, rtt * nak_delay_scale / 16]` ([`DelayDraw`]). The local NAK is due
//! once `d` has passed, unless before that (an exact tie goes to the local
//! deadline):
//!
//! - an eligible peer NAK covering the whole hole arrived
//!   ([`ImageLoss::peer_nak`]): eligible only with the `group` response
//!   domain, from a peer that has not failed to suppress this hole; or
//! - the receive owner published data inside the hole (a repair in
//!   progress, seen as a shrink by [`ImageLoss::observe`]).
//!
//! Either cancels the cycle's local NAK and opens its window, anchored
//! then; a local NAK opens the window at its submission. The window is
//! `W = rtt + repair_linger + repair_slack`; at its end a persisting hole
//! starts the next cycle with a new draw. A peer whose suppression ended a
//! cycle with nothing published inside the hole cannot suppress it again;
//! after `max_failed_suppressors` such peers the hole accepts no peer
//! suppression (RC-14). Each hole counts its consecutive suppressed
//! cycles, and the image keeps the maximum as a diagnostic.
//!
//! **Redundant paths** (RP-4, RP-5): a hole detected while two or more
//! paths are live ([`ImageLoss::set_live_paths`]) waits the skew window
//! (`path_skew_window`) from detection before its NAK, or its first
//! multicast cycle, in case another path still delivers it. The deadline
//! is fixed at detection; with one live path there is no wait.
//!
//! Nothing here allocates; positions and times are checked.

use karyos_protocol::frame::Lane;
use karyos_protocol::network::{
    Alias, Identity, MAX_NAK_LENGTH, Nak, NakRange, NakReply, NakReplyReason, Receiver,
};
use karyos_sys::host_clock::age_ns;

use crate::paths::skew::SkewDeadline;
use crate::rtt::{ProbeIds, RttProbes};

/// The bounded random draw of a multicast cycle's NAK delay (RC-2).
pub trait DelayDraw {
    /// An integer drawn uniformly from `[0, bound]`, without bias.
    fn draw(&mut self, bound: u64) -> u64;
}

/// The most failed suppressors one hole remembers (RC-14).
pub const MAX_FAILED_SUPPRESSORS: usize = 4;

/// A multicast image's NAK timing and suppression (RC-2, RC-3, RC-5, RC-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MulticastConfig {
    /// The delay bound in sixteenths of an RTT (`nak_delay_scale`, 1 to
    /// 256, default 16: one RTT).
    pub nak_delay_scale: u64,
    /// The sender's coalescing linger (`repair_linger`, default 1 ms).
    pub repair_linger_ns: u64,
    /// Repair scheduling and publication slack (`repair_slack`, 0 to 1 s,
    /// default 1 ms).
    pub repair_slack_ns: u64,
    /// Whether repairs go to the group (`repair_domain = group`): only then
    /// does a peer NAK suppress (B). A `requester` domain, or a channel
    /// without peer evidence, suppresses nothing.
    pub group_domain: bool,
    /// Failed suppressors a hole remembers before it accepts no peer
    /// suppression (`max_failed_suppressors`, 1 to 4, default 4).
    pub max_failed_suppressors: usize,
}

impl Default for MulticastConfig {
    fn default() -> Self {
        Self {
            nak_delay_scale: 16,
            repair_linger_ns: 1_000_000,
            repair_slack_ns: 1_000_000,
            group_domain: true,
            max_failed_suppressors: MAX_FAILED_SUPPRESSORS,
        }
    }
}

impl MulticastConfig {
    /// Checks the ranges: `nak_delay_scale` 1 to 256, `repair_slack` at
    /// most 1 s, `max_failed_suppressors` 1 to 4.
    ///
    /// # Errors
    ///
    /// [`LossConfigError::Multicast`].
    pub fn validate(&self) -> Result<(), LossConfigError> {
        if !(1..=256).contains(&self.nak_delay_scale) {
            return Err(LossConfigError::Multicast(
                "nak_delay_scale is not in 1..=256",
            ));
        }
        if self.repair_slack_ns > 1_000_000_000 {
            return Err(LossConfigError::Multicast("repair_slack above 1 s"));
        }
        if !(1..=MAX_FAILED_SUPPRESSORS).contains(&self.max_failed_suppressors) {
            return Err(LossConfigError::Multicast(
                "max_failed_suppressors is not in 1..=4",
            ));
        }
        Ok(())
    }

    /// Checks the timing of every RTT snapshot from `min_rtt` (the
    /// `rtt_floor`, below which no sample counts) to `max_rtt` (the
    /// `rtt_probe_timeout`, which bounds every sample): the delay bound
    /// `rtt * scale / 16` is nonzero at `min_rtt`, so the delay is random
    /// (#296 review), and the bound and the window `rtt + repair_linger +
    /// repair_slack` fit in `u64` at `max_rtt`.
    ///
    /// # Errors
    ///
    /// [`LossConfigError::Multicast`].
    pub fn validate_for(&self, min_rtt: u64, max_rtt: u64) -> Result<(), LossConfigError> {
        self.validate()?;
        if self.delay_bound(min_rtt).is_none_or(|bound| bound == 0) {
            return Err(LossConfigError::Multicast(
                "the NAK delay bound of rtt_floor is zero",
            ));
        }
        if self.delay_bound(max_rtt).is_none() || self.window(max_rtt).is_none() {
            return Err(LossConfigError::Multicast(
                "the NAK timing of rtt_probe_timeout does not fit in u64",
            ));
        }
        Ok(())
    }

    /// The delay bound of a cycle with `rtt`: `rtt * scale / 16`.
    fn delay_bound(&self, rtt: u64) -> Option<u64> {
        rtt.checked_mul(self.nak_delay_scale)?.checked_div(16)
    }

    /// The window of a cycle with `rtt`: `rtt + linger + slack`.
    fn window(&self, rtt: u64) -> Option<u64> {
        rtt.checked_add(self.repair_linger_ns)?
            .checked_add(self.repair_slack_ns)
    }
}

/// One multicast cycle of a hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cycle {
    /// When the cycle started.
    start: u64,
    /// Its drawn delay: the local NAK is due `delay` after `start`.
    delay: u64,
    /// Its window `W`, from the RTT copied at its start.
    window: u64,
    /// When its window opened, once suppressed: at the first suppressing
    /// peer NAK or published repair.
    suppressed: Option<u64>,
    /// The peer whose NAK suppressed it, if a peer did.
    by: Option<Receiver>,
    /// Data was published inside the hole during the cycle.
    progress: bool,
}

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
    /// `path_skew_window` (RP-4): how long after detection a gap waits
    /// for another live path to deliver it before its NAK, 0 to 1 s,
    /// default 1 ms. With fewer than two live paths at detection there is
    /// no wait (RP-5).
    pub skew_window_ns: u64,
}

/// The largest `path_skew_window` (RP-4): one second.
pub const MAX_SKEW_WINDOW_NS: u64 = 1_000_000_000;

impl Default for LossConfig {
    fn default() -> Self {
        Self {
            range_invalid_limit: 3,
            skew_window_ns: 1_000_000,
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
    /// A multicast setting is out of its range.
    #[error("invalid multicast repair setting: {0}")]
    Multicast(&'static str),
    /// `path_skew_window` above [`MAX_SKEW_WINDOW_NS`].
    #[error("path_skew_window above 1 s")]
    SkewWindow,
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
    /// The current multicast cycle, if any.
    cycle: Option<Cycle>,
    /// Peers whose suppression of this hole brought no repair (RC-14).
    failed: [Option<Receiver>; MAX_FAILED_SUPPRESSORS],
    /// Failed suppressors recorded for this hole.
    failed_count: usize,
    /// More peers failed than the hole remembers: no peer suppression.
    no_peer: bool,
    /// Consecutive suppressed cycles of this hole.
    suppressed_run: u64,
    /// The decision's skew deadline (RP-4, RP-5): its NAK, or its first
    /// multicast cycle, waits until then. Fixed at detection; neither a
    /// duplicate, a path's arrival nor a path's loss moves it.
    skew_until: u64,
}

impl LaneLoss {
    const IDLE: Self = Self {
        decision: Decision::NoGap,
        invalid: 0,
        span: None,
        unavailable: None,
        unnameable: false,
        cycle: None,
        failed: [None; MAX_FAILED_SUPPRESSORS],
        failed_count: 0,
        no_peer: false,
        suppressed_run: 0,
        skew_until: 0,
    };
}

/// Marks `peer` as a failed suppressor of `state`'s hole (RC-14); the
/// `max`-th one disables peer suppression for the hole, so its own NAK
/// goes within `max + 1` cycles (coordinator ruling, ACS 16108). Returns
/// the counters to bump.
fn fail_suppressor(state: &mut LaneLoss, peer: Receiver, max: usize) -> [Option<Counter>; 2] {
    let mut events: [Option<Counter>; 2] = [None; 2];
    if state.no_peer {
        return events;
    }
    if let (Some(slot), Some(next)) = (
        state.failed.get_mut(state.failed_count),
        state.failed_count.checked_add(1),
    ) {
        *slot = Some(peer);
        state.failed_count = next;
        events[0] = Some(|c| &mut c.failed_suppressors_marked);
    }
    if state.failed_count >= max {
        state.no_peer = true;
        events[1] = Some(|c| &mut c.peer_suppression_disabled);
    }
    events
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

/// One of the component's counters.
type Counter = fn(&mut LossCounters) -> &mut u64;

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
    /// Multicast cycles started.
    pub cycles: u64,
    /// Cycles whose local NAK an eligible peer NAK cancelled.
    pub peer_suppressions: u64,
    /// Cycles whose local NAK a published repair cancelled.
    pub repair_suppressions: u64,
    /// Peer NAKs that suppressed nothing: not covering, ineligible, too
    /// late, or not for this image.
    pub peer_naks_ignored: u64,
    /// Peers marked as failed suppressors (RC-14).
    pub failed_suppressors_marked: u64,
    /// Holes that stopped accepting peer suppression (RC-14).
    pub peer_suppression_disabled: u64,
    /// The most consecutive suppressed cycles of any hole (a gauge).
    pub max_suppressed_run: u64,
    /// Multicast timings past `u64` (an RTT beyond what
    /// [`MulticastConfig::validate_for`] admitted): the cycle's NAK went
    /// at once, or its window was the RTT alone.
    pub timing_overflows: u64,
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
    /// Multicast timing and suppression, when the image is multicast.
    multicast: Option<MulticastConfig>,
    /// The image's live path bindings, as the caller last reported them
    /// ([`ImageLoss::set_live_paths`]): a gap detected with two or more
    /// waits the skew window.
    live_paths: usize,
    /// Another path route of the image is healthy
    /// ([`ImageLoss::set_other_route_healthy`]).
    other_route_healthy: bool,
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
        if config.skew_window_ns > MAX_SKEW_WINDOW_NS {
            return Err(LossConfigError::SkewWindow);
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
            multicast: None,
            live_paths: 1,
            other_route_healthy: false,
            counters: LossCounters::default(),
        })
    }

    /// Whether another path route than the image's own is healthy now
    /// (redundant paths, RP-7): then a fault of the own route stops only
    /// that route, and NAKs stay due for the others.
    pub fn set_other_route_healthy(&mut self, healthy: bool) {
        self.other_route_healthy = healthy;
    }

    /// The image's live path bindings now (RP-5): the caller reports them
    /// before it observes, so a gap is detected with the count of its
    /// moment. Later changes never move a deadline already fixed.
    pub fn set_live_paths(&mut self, live: usize) {
        self.live_paths = live;
    }

    /// The same state, timed by multicast cycles with B+C suppression.
    ///
    /// # Errors
    ///
    /// [`LossConfigError::Multicast`] for a setting out of its range.
    pub fn multicast(mut self, config: MulticastConfig) -> Result<Self, LossConfigError> {
        config.validate()?;
        self.multicast = Some(config);
        Ok(self)
    }

    /// A multicast step of `lane` at `now`: starts a hole's first cycle,
    /// and the next one when the current cycle's window ended with the
    /// hole still there, drawing its delay from `draw` over the RTT
    /// snapshot of `rtt`. A suppressed cycle that ended with nothing
    /// published inside the hole marks its suppressor failed (RC-14). A
    /// no-op on a unicast image.
    pub fn cycle(&mut self, lane: Lane, now: u64, rtt: &impl RttSource, draw: &mut impl DelayDraw) {
        let Some(config) = self.multicast else {
            return;
        };
        if self.closed {
            return;
        }
        let snapshot = rtt.rtt_snapshot(self.path);
        let mut events: [Option<Counter>; 3] = [None; 3];
        let mut run = None;
        let mut overflowed = false;
        let Some(state) = self.lane_mut(lane) else {
            return;
        };
        let start = match (state.decision, state.cycle) {
            // A hole's first cycle starts once its skew deadline passed.
            (Decision::NakDue { .. }, None) => now >= state.skew_until,
            // A suppressed cycle's window ended with the hole still there.
            (Decision::NakDue { .. }, Some(cycle)) => {
                let ended = cycle
                    .suppressed
                    .is_some_and(|at| age_ns(now, at) >= cycle.window);
                if ended {
                    if let (Some(peer), false) = (cycle.by, cycle.progress) {
                        let [marked, disabled] =
                            fail_suppressor(state, peer, config.max_failed_suppressors);
                        events[0] = marked;
                        events[1] = disabled;
                    }
                    match state.suppressed_run.checked_add(1) {
                        Some(next) => state.suppressed_run = next,
                        None => overflowed = true,
                    }
                    run = Some(state.suppressed_run);
                }
                ended
            }
            // The local NAK's window ended with the hole still there.
            (
                Decision::AwaitRepair {
                    hole,
                    detected_at,
                    submitted_at,
                    rtt: window,
                    ..
                },
                _,
            ) if age_ns(now, submitted_at) >= window => {
                state.decision = Decision::NakDue { hole, detected_at };
                state.suppressed_run = 0;
                true
            }
            _ => false,
        };
        let mut timing_overflowed = false;
        if start {
            // A timing past `u64` NAKs at once, with the RTT as window,
            // and is counted.
            let delay = match config.delay_bound(snapshot) {
                Some(bound) => draw.draw(bound).min(bound),
                None => {
                    timing_overflowed = true;
                    0
                }
            };
            let window = match config.window(snapshot) {
                Some(window) => window,
                None => {
                    timing_overflowed = true;
                    snapshot
                }
            };
            state.cycle = Some(Cycle {
                start: now,
                delay,
                window,
                suppressed: None,
                by: None,
                progress: false,
            });
            events[2] = Some(|c| &mut c.cycles);
        }
        for field in events.into_iter().flatten() {
            self.counters.bump(field);
        }
        if timing_overflowed {
            self.counters.bump(|c| &mut c.timing_overflows);
        }
        self.counters.overflowed |= overflowed;
        if let Some(run) = run
            && run > self.counters.max_suppressed_run
        {
            self.counters.max_suppressed_run = run;
        }
    }

    /// A peer NAK from the control group, at `now` (B with C): it cancels
    /// the local NAK of the lane's current cycle, and opens its window,
    /// when it names this image, comes from another receiver, covers the
    /// whole hole and arrives before the cycle's deadline (an exact tie
    /// goes to the local deadline), on a `group` response domain, from a
    /// peer that has not failed to suppress this hole. Returns whether it
    /// suppressed; anything else is counted and ignored.
    pub fn peer_nak(&mut self, nak: &Nak, now: u64) -> bool {
        let suppressed = self.suppress(nak, now);
        self.counters.bump(if suppressed {
            |c: &mut LossCounters| &mut c.peer_suppressions
        } else {
            |c: &mut LossCounters| &mut c.peer_naks_ignored
        });
        suppressed
    }

    fn suppress(&mut self, nak: &Nak, now: u64) -> bool {
        let Some(config) = self.multicast else {
            return false;
        };
        if self.closed
            || !config.group_domain
            || nak.alias != self.alias
            || nak.identity != self.identity
            || nak.receiver == self.receiver
        {
            return false;
        }
        let Some(state) = self.lane_mut(nak.range.lane) else {
            return false;
        };
        let (Decision::NakDue { hole, .. }, Some(cycle)) = (state.decision, &mut state.cycle)
        else {
            return false;
        };
        let peer = Hole {
            start: nak.range.start,
            length: nak.range.length,
        };
        let eligible = !state.no_peer
            && !state
                .failed
                .iter()
                .flatten()
                .any(|failed| *failed == nak.receiver);
        let in_time = cycle.suppressed.is_none() && age_ns(now, cycle.start) < cycle.delay;
        if !(eligible && in_time && peer.contains(hole)) {
            return false;
        }
        cycle.suppressed = Some(now);
        cycle.by = Some(nak.receiver);
        true
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> LossCounters {
        self.counters
    }

    /// Whether a route fault holds the image (RC-6): its NAKs wait for the
    /// endpoint's reset.
    #[must_use]
    pub fn is_faulted(&self) -> bool {
        self.faulted
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
        let (window, live) = (self.config.skew_window_ns, self.live_paths);
        let mut timing_overflowed = false;
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
        let mut repair_suppressed = false;
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
                        state.cycle = None;
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
                // Multicast: data published inside the hole is a repair in
                // progress. Before the cycle's deadline it cancels the local
                // NAK and opens the window (B with C).
                if let Some(cycle) = &mut state.cycle {
                    cycle.progress = true;
                    let in_time = cycle.suppressed.is_none()
                        && matches!(state.decision, Decision::NakDue { .. })
                        && age_ns(now, cycle.start) < cycle.delay;
                    if in_time {
                        cycle.suppressed = Some(now);
                        repair_suppressed = true;
                    }
                }
            }
            (_, Some(seen)) => {
                // RP-4, RP-5: fixed now; a deadline past the clock waits
                // nothing, counted.
                let skew_until = match SkewDeadline::reliable(now, window, live) {
                    Ok(deadline) => deadline.at(),
                    Err(_) => {
                        timing_overflowed = true;
                        now
                    }
                };
                *state = LaneLoss {
                    decision: Decision::NakDue {
                        hole: seen,
                        detected_at: now,
                    },
                    skew_until,
                    ..LaneLoss::IDLE
                };
                event = Some(|c| &mut c.detected);
            }
        }
        if let Some(field) = event {
            self.counters.bump(field);
        }
        if repair_suppressed {
            self.counters.bump(|c| &mut c.repair_suppressions);
        }
        if timing_overflowed {
            self.counters.bump(|c| &mut c.timing_overflows);
        }
        observation
    }

    /// The NAK due on `lane` at `now`, if any: a hole just detected or
    /// left unsubmitted, or one whose submission is at least its RTT old.
    /// Nothing changes until the caller reports the submission. `None`
    /// also while a route fault holds the image.
    pub fn due(&mut self, lane: Lane, now: u64) -> Option<Nak> {
        // RC-6 per route: a fault of the image's own route stops only that
        // route while another is healthy (redundant paths, #310 review).
        if (self.faulted && !self.other_route_healthy) || self.closed {
            return None;
        }
        let (alias, identity, receiver) = (self.alias, self.identity, self.receiver);
        let multicast = self.multicast.is_some();
        let state = self.lane_mut(lane)?;
        // RP-4: a gap waits its skew deadline before any NAK.
        if matches!(state.decision, Decision::NakDue { .. }) && now < state.skew_until {
            return None;
        }
        let hole = match (state.decision, multicast) {
            (Decision::NakDue { hole, .. }, false) => hole,
            // Multicast: once the cycle's drawn delay passed, unless the
            // cycle was suppressed.
            (Decision::NakDue { hole, .. }, true) => match state.cycle {
                Some(cycle)
                    if cycle.suppressed.is_none() && age_ns(now, cycle.start) >= cycle.delay =>
                {
                    hole
                }
                _ => return None,
            },
            // Unicast retries one RTT after submission; multicast retries
            // through the next cycle (ImageLoss::cycle).
            (
                Decision::AwaitRepair {
                    hole,
                    submitted_at,
                    rtt,
                    ..
                },
                false,
            ) if age_ns(now, submitted_at) >= rtt => hole,
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

    /// `nak`, from [`ImageLoss::due`], was submitted at `now`. On a
    /// unicast image its retry is due one RTT later, the snapshot copied
    /// now from `rtt`; on a multicast image it opens its cycle's window
    /// `W`, computed from the RTT copied at the cycle's start, and the next
    /// cycle starts when the window ends with the hole still there.
    pub fn submitted(&mut self, nak: &Nak, now: u64, rtt: &impl RttSource) {
        let rtt = self.interval(nak.range.lane, rtt.rtt_snapshot(self.path));
        self.record_submission(nak, now, rtt);
    }

    /// The wait after a submission of `lane`'s NAK: one RTT for unicast;
    /// for multicast the current cycle's window `W` (without a cycle, `W`
    /// over `rtt`; a timing past `u64` falls back to the RTT and is
    /// counted).
    fn interval(&mut self, lane: Lane, rtt: u64) -> u64 {
        let Some(config) = self.multicast else {
            return rtt;
        };
        if let Some(cycle) = self.lane_mut(lane).and_then(|state| state.cycle) {
            return cycle.window;
        }
        config.window(rtt).unwrap_or_else(|| {
            self.counters.bump(|c| &mut c.timing_overflows);
            rtt
        })
    }

    /// `nak` could not be submitted (budget or backend): it stays due.
    pub fn not_submitted(&mut self, _nak: &Nak) {
        self.counters.bump(|c| &mut c.not_submitted);
    }

    /// `nak`'s submission is uncertain, reported at `now` (RC-6): it is
    /// treated as submitted then, and its retry is a new NAK.
    ///
    /// The receiver role no longer calls this: an uncertain copy is only an
    /// anchor candidate there ([`ImageLoss::route_uncertain`], then
    /// [`ImageLoss::submitted`] once no copy of its round was submitted;
    /// #310 review). It stays for single-path callers and tests.
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
        self.route_uncertain()?;
        let rtt = self.interval(nak.range.lane, rtt.rtt_snapshot(self.path));
        self.record_submission(nak, now, rtt);
        Ok(())
    }

    /// An uncertain outcome on the image's own route for a NAK already
    /// anchored by another path's copy (redundant paths, RP-7): the RC-6
    /// limit and route fault apply as for [`ImageLoss::uncertain`], but no
    /// submission is recorded, since the copy that anchored the NAK did.
    ///
    /// # Errors
    ///
    /// [`RouteFault`] when another uncertain NAK of the route is
    /// unresolved.
    pub fn route_uncertain(&mut self) -> Result<(), RouteFault> {
        if self.uncertain {
            self.faulted = true;
            self.counters.bump(|c| &mut c.route_faults);
            return Err(RouteFault);
        }
        self.uncertain = true;
        self.counters.bump(|c| &mut c.uncertain);
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
