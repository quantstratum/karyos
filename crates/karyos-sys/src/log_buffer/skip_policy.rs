// SPDX-License-Identifier: Apache-2.0

//! The skip policy of an image (`quantstratum-docs:
//! karyos/design/gaps-and-unreliable-delivery.md`, "GP3: skip policy and
//! far-window defaults", GU-4 to GU-6): when a hole above a lane's resolved
//! prefix is sealed as a local gap, and when the image must close instead.
//!
//! - **Unreliable.** A hole is sealed once `gap_reorder_timeout` (or the
//!   redundant-path skew window, if larger; never their sum) has passed
//!   since its first detection. A hole is detected by the first `duty` call
//!   that finds it, not at the arrival that revealed it, so the caller runs
//!   `duty` after its arrivals. A duplicate never restarts the deadline. At
//!   expiry the extent maps are read again and only what is still uncovered
//!   is sealed, up to the start of the next committed extent. No NAK is
//!   sent.
//! - **Reliable.** A timer never seals. Under `on_unrecoverable = close`
//!   (the default) a correlated `RANGE_UNAVAILABLE` closes the image with
//!   the interval; under `skip` it seals the whole hole with reason
//!   `RangeUnavailable`.
//! - **Far window.** No catch-up: a lowest retained position beyond the
//!   window closes the image with `GapCannotResume` under every policy, and
//!   on an unreliable channel so does a run of arrivals all `Ahead` for
//!   `far_window_timeout` while no committed arrival fills or reveals a
//!   hole.
//!
//! The caller passes a monotonic time in nanoseconds and the outcomes of
//! its arrivals; closing the image is the caller's ordered session
//! transition. Every allocation happens in [`SkipPolicy::new`].
//!
//! A [`SealGate`] is asked before each seal (`quantstratum-docs:
//! karyos/design/conflated-network-images.md`, (b)): a conflated lane's
//! gate holds the seal until the view's feeder recorded the loss. While it
//! answers [`GateAnswer::Pending`], the hole stays due and is posted to the
//! receive owner ([`ReceiveOwner::post_seal`]), so nothing lands in it
//! before its seal. [`SkipPolicy::duty`] and
//! [`SkipPolicy::range_unavailable`] use [`Ungated`], which always permits:
//! an unconflated lane seals as before.

use super::receive_owner::{ReceiveError, ReceiveOwner, Received};
use crate::frame::Lane;
use crate::host_clock::age_ns;
use crate::local_gap::GapReason;
use crate::term_bytes::TermBytes;

/// The largest `gap_reorder_timeout` (GU-4): one second.
pub const MAX_REORDER_TIMEOUT_NS: u64 = 1_000_000_000;
/// The default `gap_reorder_timeout` (GU-4): one millisecond.
pub const DEFAULT_REORDER_TIMEOUT_NS: u64 = 1_000_000;
/// The default `far_window_timeout` (GU-6): one second.
pub const DEFAULT_FAR_WINDOW_TIMEOUT_NS: u64 = 1_000_000_000;
/// Seals one duty applies at most per lane, so a duty stays bounded.
const SEALS_PER_DUTY: u32 = 8;

/// What a reliable channel does with a range proven unrecoverable (GU-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Unrecoverable {
    /// Close the image with the interval recorded (the default).
    #[default]
    Close,
    /// Seal the whole hole as a local gap with reason `RangeUnavailable`.
    Skip,
}

/// The skip policy's configuration (GU-4 to GU-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkipConfig {
    /// Whether the channel is reliable: then no timer seals.
    pub reliable: bool,
    /// The unreliable reorder interval, 0 to [`MAX_REORDER_TIMEOUT_NS`].
    pub reorder_timeout_ns: u64,
    /// The redundant-path skew window (`SkewWait`), 0 without redundant
    /// paths.
    pub skew_window_ns: u64,
    /// What a reliable channel does with an unrecoverable range.
    pub on_unrecoverable: Unrecoverable,
    /// How long arrivals all `Ahead` close an unreliable image.
    pub far_window_timeout_ns: u64,
}

impl SkipConfig {
    /// The defaults of an unreliable channel without redundant paths.
    #[must_use]
    pub const fn unreliable() -> Self {
        Self {
            reliable: false,
            reorder_timeout_ns: DEFAULT_REORDER_TIMEOUT_NS,
            skew_window_ns: 0,
            on_unrecoverable: Unrecoverable::Close,
            far_window_timeout_ns: DEFAULT_FAR_WINDOW_TIMEOUT_NS,
        }
    }

    /// The defaults of a reliable channel.
    #[must_use]
    pub const fn reliable() -> Self {
        Self {
            reliable: true,
            ..Self::unreliable()
        }
    }

    /// The unreliable deadline after first detection: the larger of the
    /// reorder interval and the skew window, never their sum.
    #[must_use]
    pub fn deadline_ns(&self) -> u64 {
        self.reorder_timeout_ns.max(self.skew_window_ns)
    }
}

/// What a [`SealGate`] answers before a seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAnswer {
    /// Seal now.
    Permit,
    /// Not yet: the hole stays due, posted to the receive owner, and the
    /// gate is asked again on a later call.
    Pending,
}

/// Asked before each seal of a hole: whether it may be sealed now.
pub trait SealGate {
    /// Whether `[position, position + extent)` of `lane` may be sealed at
    /// `now`. Never blocks: a seal that must wait answers
    /// [`GateAnswer::Pending`].
    fn before_seal(&mut self, lane: Lane, position: u64, extent: u32, now: u64) -> GateAnswer;
}

/// The gate of an unconflated lane: always permits.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ungated;

impl SealGate for Ungated {
    fn before_seal(&mut self, _lane: Lane, _position: u64, _extent: u32, _now: u64) -> GateAnswer {
        GateAnswer::Permit
    }
}

/// Why the image must close (GU-5, GU-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCause {
    /// A reliable range proven unrecoverable under `on_unrecoverable =
    /// close`.
    Unrecoverable,
    /// A position the window cannot reach: no far-window catch-up.
    GapCannotResume,
}

/// A close the caller must carry out, with the interval it records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Close {
    /// The lane.
    pub lane: Lane,
    /// Why.
    pub cause: CloseCause,
    /// The interval `[from, to)` recorded with it.
    pub from: u64,
    /// See `from`.
    pub to: u64,
}

/// What one call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SkipReport {
    /// Gaps sealed.
    pub sealed: u32,
    /// Bytes sealed.
    pub sealed_bytes: u64,
    /// A close the caller must carry out; the policy seals nothing more on
    /// that lane once it reported one.
    pub close: Option<Close>,
    /// A seal whose record was published before a later step failed
    /// (GU-11, [`ReceiveError::GapCommitted`]): it is counted in `sealed`,
    /// the caller never seals that interval again, and the call stopped
    /// there.
    pub committed_failure: Option<ReceiveError>,
    /// Due holes whose gate answered [`GateAnswer::Pending`]: posted, not
    /// sealed.
    pub gated: u32,
}

impl SkipReport {
    /// Counts one seal of `extent` bytes. One call seals at most
    /// `SEALS_PER_DUTY` holes on each of at most `Lane::COUNT` lanes, each
    /// within one term, so neither sum can overflow; the increments are
    /// checked and apply together.
    fn count(&mut self, extent: u32) {
        if let (Some(sealed), Some(bytes)) = (
            self.sealed.checked_add(1),
            self.sealed_bytes.checked_add(u64::from(extent)),
        ) {
            self.sealed = sealed;
            self.sealed_bytes = bytes;
        }
    }
}

/// Why a [`SkipPolicy`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SkipConfigError {
    /// `reorder_timeout_ns` above [`MAX_REORDER_TIMEOUT_NS`].
    #[error("reorder timeout {0} ns above the 1 s limit")]
    ReorderTimeout(u64),
}

/// One lane's closes the policy reported (GU-11). Increments are checked:
/// one that would overflow keeps its value and sets `overflowed`, which
/// stays set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkipCounters {
    /// Closes because a position could not be resumed.
    pub gap_cannot_resume: u64,
    /// Closes on an unrecoverable reliable range.
    pub unrecoverable: u64,
    /// An increment did not apply because it would have overflowed.
    pub overflowed: bool,
}

impl SkipCounters {
    fn count(&mut self, cause: CloseCause) {
        let value = match cause {
            CloseCause::GapCannotResume => &mut self.gap_cannot_resume,
            CloseCause::Unrecoverable => &mut self.unrecoverable,
        };
        match value.checked_add(1) {
            Some(next) => *value = next,
            None => self.overflowed = true,
        }
    }
}

/// One lane's hole and far-window state.
#[derive(Debug, Clone, Copy, Default)]
struct LaneState {
    /// The current loss episode: when holes were first detected, and the
    /// covered end then. A hole starting below that end was detected then;
    /// one at or above it is a new detection.
    episode: Option<(u64, u64)>,
    /// Holes below this position are proven unrecoverable (reliable, skip).
    unrecoverable_to: u64,
    /// Since when every arrival was `Ahead`, and the earliest such position.
    ahead: Option<(u64, u64)>,
    /// The lane was reported closed.
    closed: bool,
    /// The closes reported on the lane.
    counters: SkipCounters,
}

/// The skip policy of one image: one state per lane.
#[derive(Debug, Clone)]
pub struct SkipPolicy {
    config: SkipConfig,
    lanes: Vec<LaneState>,
}

impl SkipPolicy {
    /// A policy for an image of `lanes` lanes.
    ///
    /// # Errors
    ///
    /// [`SkipConfigError::ReorderTimeout`] for an interval above one second.
    pub fn new(config: SkipConfig, lanes: usize) -> Result<Self, SkipConfigError> {
        if config.reorder_timeout_ns > MAX_REORDER_TIMEOUT_NS {
            return Err(SkipConfigError::ReorderTimeout(config.reorder_timeout_ns));
        }
        Ok(Self {
            config,
            lanes: vec![LaneState::default(); lanes],
        })
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &SkipConfig {
        &self.config
    }

    /// The closes reported on `lane` so far; `None` for a lane the policy
    /// does not have.
    #[must_use]
    pub fn counters(&self, lane: Lane) -> Option<SkipCounters> {
        self.lanes.get(usize::from(lane.get())).map(|l| l.counters)
    }

    /// Records an arrival's outcome on `lane` at `now`, the frame at
    /// `position`: a run of `Ahead` arrivals starts the far-window clock, a
    /// committed arrival stops it.
    pub fn arrived(
        &mut self,
        lane: Lane,
        outcome: &Result<Received, ReceiveError>,
        position: u64,
        now: u64,
    ) {
        let Some(state) = self.lanes.get_mut(usize::from(lane.get())) else {
            return;
        };
        match outcome {
            Ok(Received::Ahead) => {
                let (since, earliest) = state.ahead.unwrap_or((now, position));
                state.ahead = Some((since, earliest.min(position)));
            }
            Ok(Received::Committed { .. }) => state.ahead = None,
            // Duplicates, late copies and refusals neither fill nor reveal
            // a hole, and never restart a deadline.
            _ => {}
        }
    }

    /// Bounded work at `now`: seals the expired or unrecoverable holes of
    /// every lane, at most a few per lane, and reports a far-window close.
    ///
    /// # Errors
    ///
    /// [`ReceiveError::Sys`] for a corrupt owner state.
    pub fn duty<T: TermBytes>(
        &mut self,
        owner: &mut ReceiveOwner<T>,
        now: u64,
    ) -> Result<SkipReport, ReceiveError> {
        self.duty_gated(owner, now, &mut Ungated)
    }

    /// [`SkipPolicy::duty`], asking `gate` before each seal.
    ///
    /// # Errors
    ///
    /// As [`SkipPolicy::duty`].
    pub fn duty_gated<T: TermBytes, G: SealGate + ?Sized>(
        &mut self,
        owner: &mut ReceiveOwner<T>,
        now: u64,
        gate: &mut G,
    ) -> Result<SkipReport, ReceiveError> {
        self.duty_observed(owner, now, gate, |_, _, _| {})
    }

    /// [`SkipPolicy::duty_gated`], telling `sealed` of each committed seal:
    /// its lane, position and extent, once, after the seal's record is
    /// published (also when a later step failed, GU-11). A seal that is
    /// not committed (posted to the gate, or its term not prepared yet)
    /// tells nothing.
    ///
    /// # Errors
    ///
    /// As [`SkipPolicy::duty`].
    pub fn duty_observed<T: TermBytes, G: SealGate + ?Sized>(
        &mut self,
        owner: &mut ReceiveOwner<T>,
        now: u64,
        gate: &mut G,
        mut sealed: impl FnMut(Lane, u64, u32),
    ) -> Result<SkipReport, ReceiveError> {
        let mut report = SkipReport::default();
        for index in 0..self.lanes.len() {
            let Some(lane) = u8::try_from(index).ok().and_then(|l| Lane::try_new(l).ok()) else {
                continue;
            };
            self.seal_due(owner, lane, now, gate, &mut report, &mut sealed)?;
            if report.committed_failure.is_some() {
                break;
            }
            if report.close.is_none() {
                report.close = self.far_window(owner, lane, now)?;
            }
        }
        Ok(report)
    }

    /// A correlated `RANGE_UNAVAILABLE` on a reliable channel (GU-5, GU-6),
    /// reporting `floor`, the sender's lowest retained position of `lane`:
    /// everything below it is unrecoverable.
    ///
    /// - A floor beyond the window `{r, r + 1}` closes the lane with
    ///   `GapCannotResume` under every policy: there is no far-window
    ///   catch-up, so nothing is sealed.
    /// - Otherwise `close` closes the lane with `[prefix, floor)`, and
    ///   `skip` seals every hole that starts below the floor, each whole
    ///   (a hole straddling the floor is unrecoverable in full, RC-9).
    ///
    /// # Errors
    ///
    /// [`ReceiveError::Foreign`] for a lane the image does not have,
    /// [`ReceiveError::Sys`] for a corrupt owner state. A floor outside the
    /// incarnation is beyond the window.
    pub fn range_unavailable<T: TermBytes>(
        &mut self,
        owner: &mut ReceiveOwner<T>,
        lane: Lane,
        floor: u64,
        now: u64,
    ) -> Result<SkipReport, ReceiveError> {
        self.range_unavailable_gated(owner, lane, floor, now, &mut Ungated)
    }

    /// [`SkipPolicy::range_unavailable`], asking `gate` before each seal.
    ///
    /// # Errors
    ///
    /// As [`SkipPolicy::range_unavailable`].
    pub fn range_unavailable_gated<T: TermBytes, G: SealGate + ?Sized>(
        &mut self,
        owner: &mut ReceiveOwner<T>,
        lane: Lane,
        floor: u64,
        now: u64,
        gate: &mut G,
    ) -> Result<SkipReport, ReceiveError> {
        self.range_unavailable_observed(owner, lane, floor, now, gate, |_, _, _| {})
    }

    /// [`SkipPolicy::range_unavailable_gated`], telling `sealed` of each
    /// committed seal as [`SkipPolicy::duty_observed`] does.
    ///
    /// # Errors
    ///
    /// As [`SkipPolicy::range_unavailable`].
    pub fn range_unavailable_observed<T: TermBytes, G: SealGate + ?Sized>(
        &mut self,
        owner: &mut ReceiveOwner<T>,
        lane: Lane,
        floor: u64,
        now: u64,
        gate: &mut G,
        mut sealed: impl FnMut(Lane, u64, u32),
    ) -> Result<SkipReport, ReceiveError> {
        let mut report = SkipReport::default();
        let Some(state) = self.lanes.get_mut(usize::from(lane.get())) else {
            return Err(ReceiveError::Foreign);
        };
        if state.closed {
            return Ok(report);
        }
        let prefix = owner.rebuild_position(lane).ok_or(ReceiveError::Foreign)?;
        if !owner.within_window(lane, floor)? {
            state.closed = true;
            report.close = Some(Close {
                lane,
                cause: CloseCause::GapCannotResume,
                from: prefix,
                to: floor,
            });
            state.counters.count(CloseCause::GapCannotResume);
            return Ok(report);
        }
        match self.config.on_unrecoverable {
            Unrecoverable::Close => {
                state.closed = true;
                report.close = Some(Close {
                    lane,
                    cause: CloseCause::Unrecoverable,
                    from: prefix,
                    to: floor,
                });
                state.counters.count(CloseCause::Unrecoverable);
            }
            Unrecoverable::Skip => {
                state.unrecoverable_to = state.unrecoverable_to.max(floor);
                self.seal_due(owner, lane, now, gate, &mut report, &mut sealed)?;
            }
        }
        Ok(report)
    }

    /// Seals the holes of `lane` that are due: expired on an unreliable
    /// channel, proven unrecoverable on a reliable one under `skip`.
    fn seal_due<T: TermBytes, G: SealGate + ?Sized>(
        &mut self,
        owner: &mut ReceiveOwner<T>,
        lane: Lane,
        now: u64,
        gate: &mut G,
        report: &mut SkipReport,
        sealed: &mut impl FnMut(Lane, u64, u32),
    ) -> Result<(), ReceiveError> {
        let config = self.config;
        let Some(state) = self.lanes.get_mut(usize::from(lane.get())) else {
            return Ok(());
        };
        if state.closed {
            return Ok(());
        }
        for _ in 0..SEALS_PER_DUTY {
            // The extent maps are read again before each seal: only what is
            // still uncovered is sealed, up to the next committed extent.
            let Some((position, extent)) = owner.first_hole(lane)? else {
                state.episode = None;
                return Ok(());
            };
            let high = owner.high_water(lane).unwrap_or(position);
            let (detected, seen_to) = match state.episode {
                Some((at, seen_to)) if position < seen_to => (at, seen_to),
                // A hole above what the episode saw: a new detection.
                _ => (now, high),
            };
            state.episode = Some((detected, seen_to));
            let reason = if config.reliable {
                if config.on_unrecoverable == Unrecoverable::Skip
                    && position < state.unrecoverable_to
                {
                    GapReason::RangeUnavailable
                } else {
                    return Ok(());
                }
            } else if age_ns(now, detected) >= config.deadline_ns() {
                GapReason::ReorderExpired
            } else {
                return Ok(());
            };
            if gate.before_seal(lane, position, extent, now) == GateAnswer::Pending {
                // Posted: nothing lands in it until the gate permits. A lane
                // holds one posted interval, so the lane's sealing stops at
                // its first Pending: no later hole is posted while this one
                // waits.
                debug_assert!(
                    owner.posted(lane).is_none_or(|posted| posted.0 == position),
                    "a second posted interval on one lane"
                );
                owner.post_seal(lane, position, extent)?;
                if let Some(gated) = report.gated.checked_add(1) {
                    report.gated = gated;
                }
                return Ok(());
            }
            match owner.seal_gap(lane, position, extent, reason) {
                Ok(Received::Committed { position, extent }) => {
                    report.count(extent);
                    sealed(lane, position, extent);
                }
                // Published, then a later step failed: count it, report it
                // and stop.
                Err(
                    failure @ ReceiveError::GapCommitted {
                        position, extent, ..
                    },
                ) => {
                    report.count(extent);
                    sealed(lane, position, extent);
                    report.committed_failure = Some(failure);
                    return Ok(());
                }
                Err(error) => return Err(error),
                // The term is not prepared yet: the hole stays due.
                Ok(_) => return Ok(()),
            }
        }
        Ok(())
    }

    /// GU-6 on an unreliable channel: arrivals all `Ahead` for
    /// `far_window_timeout` close the lane with `GapCannotResume`, from its
    /// resolved prefix to the earliest `Ahead` position seen.
    fn far_window<T: TermBytes>(
        &mut self,
        owner: &ReceiveOwner<T>,
        lane: Lane,
        now: u64,
    ) -> Result<Option<Close>, ReceiveError> {
        let config = self.config;
        let Some(state) = self.lanes.get_mut(usize::from(lane.get())) else {
            return Ok(None);
        };
        if config.reliable || state.closed {
            return Ok(None);
        }
        let Some((since, earliest)) = state.ahead else {
            return Ok(None);
        };
        if age_ns(now, since) < config.far_window_timeout_ns {
            return Ok(None);
        }
        state.closed = true;
        state.counters.count(CloseCause::GapCannotResume);
        let prefix = owner.rebuild_position(lane).ok_or(ReceiveError::Foreign)?;
        Ok(Some(Close {
            lane,
            cause: CloseCause::GapCannotResume,
            from: prefix,
            to: earliest,
        }))
    }
}

#[cfg(test)]
mod tests;
