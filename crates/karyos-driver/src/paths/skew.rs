// SPDX-License-Identifier: Apache-2.0

//! The skew deadline of a lane's earliest gap (`quantstratum-docs:
//! karyos/design/redundant-paths.md`, section 4; RP-4, RP-5).
//!
//! The deadline belongs to the image's receive owner, in the lane's
//! earliest-gap decision; no path reader holds a timer. It is fixed at
//! detection, detection time plus the window, and neither a duplicate, a
//! new path nor a path loss moves it: a [`SkewDeadline`] is a value with
//! no setter. With fewer than two live paths at detection the window is
//! 0, since no other path can still deliver the gap; a gap detected while
//! two paths were live keeps its deadline if one is lost afterwards.

/// When a gap detected at a given time may be requested, at the earliest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkewDeadline {
    at: u64,
}

/// Why no deadline exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SkewError {
    /// Detection time plus the window does not fit the clock: never a
    /// wrapped deadline.
    #[error("the skew deadline overflows the clock")]
    Overflow,
}

impl SkewDeadline {
    /// The deadline of a gap detected at `now` on a reliable channel, with
    /// `live_paths` path bindings live at detection and the channel's
    /// `window` (`path_skew_window`).
    ///
    /// # Errors
    ///
    /// [`SkewError::Overflow`] when `now + window` does not fit.
    pub const fn reliable(now: u64, window: u64, live_paths: usize) -> Result<Self, SkewError> {
        let window = if live_paths < 2 { 0 } else { window };
        match now.checked_add(window) {
            Some(at) => Ok(Self { at }),
            None => Err(SkewError::Overflow),
        }
    }

    /// The one deadline of a gap detected at `now` on an unreliable
    /// channel: the larger of `reorder` (`gap_reorder_timeout`) and the
    /// skew window as [`Self::reliable`] gives it, never their sum (GU-4).
    ///
    /// # Errors
    ///
    /// [`SkewError::Overflow`] when the deadline does not fit.
    pub const fn unreliable(
        now: u64,
        window: u64,
        live_paths: usize,
        reorder: u64,
    ) -> Result<Self, SkewError> {
        let window = if live_paths < 2 { 0 } else { window };
        let wait = if reorder > window { reorder } else { window };
        match now.checked_add(wait) {
            Some(at) => Ok(Self { at }),
            None => Err(SkewError::Overflow),
        }
    }

    /// The deadline.
    #[must_use]
    pub const fn at(self) -> u64 {
        self.at
    }

    /// Whether the gap may be requested at `now`.
    #[must_use]
    pub const fn passed(self, now: u64) -> bool {
        now >= self.at
    }
}
