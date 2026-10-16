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
}

/// Why a [`SkipPolicy`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SkipConfigError {
    /// `reorder_timeout_ns` above [`MAX_REORDER_TIMEOUT_NS`].
    #[error("reorder timeout {0} ns above the 1 s limit")]
    ReorderTimeout(u64),
}

/// Closes a policy reported (GU-11).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkipCounters {
    /// Lanes closed because a position could not be resumed.
    pub gap_cannot_resume: u64,
    /// Lanes closed on an unrecoverable reliable range.
    pub unrecoverable: u64,
}

impl SkipCounters {
    fn count(&mut self, cause: CloseCause) {
        let value = match cause {
            CloseCause::GapCannotResume => &mut self.gap_cannot_resume,
            CloseCause::Unrecoverable => &mut self.unrecoverable,
        };
        // A lane closes once; an increment that would overflow keeps the
        // value, never wraps.
        if let Some(next) = value.checked_add(1) {
            *value = next;
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
}

/// The skip policy of one image: one state per lane.
#[derive(Debug, Clone)]
pub struct SkipPolicy {
    config: SkipConfig,
    lanes: Vec<LaneState>,
    counters: SkipCounters,
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
            counters: SkipCounters::default(),
        })
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &SkipConfig {
        &self.config
    }

    /// The closes reported so far.
    #[must_use]
    pub fn counters(&self) -> SkipCounters {
        self.counters
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
        let mut report = SkipReport::default();
        for index in 0..self.lanes.len() {
            let Some(lane) = u8::try_from(index).ok().and_then(|l| Lane::try_new(l).ok()) else {
                continue;
            };
            self.seal_due(owner, lane, now, &mut report)?;
            if report.close.is_none() {
                report.close = self.far_window(owner, lane, now)?;
                if let Some(close) = report.close {
                    self.counters.count(close.cause);
                }
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
    /// [`ReceiveError::Sys`] for a corrupt owner state or a floor outside
    /// the incarnation.
    pub fn range_unavailable<T: TermBytes>(
        &mut self,
        owner: &mut ReceiveOwner<T>,
        lane: Lane,
        floor: u64,
        now: u64,
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
            self.counters.count(CloseCause::GapCannotResume);
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
                self.counters.count(CloseCause::Unrecoverable);
            }
            Unrecoverable::Skip => {
                state.unrecoverable_to = state.unrecoverable_to.max(floor);
                self.seal_due(owner, lane, now, &mut report)?;
            }
        }
        Ok(report)
    }

    /// Seals the holes of `lane` that are due: expired on an unreliable
    /// channel, proven unrecoverable on a reliable one under `skip`.
    fn seal_due<T: TermBytes>(
        &mut self,
        owner: &mut ReceiveOwner<T>,
        lane: Lane,
        now: u64,
        report: &mut SkipReport,
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
            match owner.seal_gap(lane, position, extent, reason)? {
                Received::Committed { extent, .. } => {
                    report.sealed = report.sealed.saturating_add(1);
                    report.sealed_bytes = report.sealed_bytes.saturating_add(u64::from(extent));
                }
                // The term is not prepared yet: the hole stays due.
                _ => return Ok(()),
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
