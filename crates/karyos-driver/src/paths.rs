// SPDX-License-Identifier: Apache-2.0

//! Redundant paths at an image's receive owner (`quantstratum-docs:
//! karyos/design/redundant-paths.md`, sections 4 and 5; P2.9, coordinator
//! decisions ACS 15519).
//!
//! The owner-side components that need no DATA path:
//!
//! - [`skew`]: the skew deadline of a lane's earliest gap, fixed at
//!   detection (RP-4, RP-5);
//! - [`queues`]: one bounded queue per path between its backend reader and
//!   the owner, served round robin;
//! - [`stats`]: the per-path statistics (RP-6), with each path's freshness
//!   (RP-2) and the arrival ring of each lane.
//!
//! Every per-path array is sized by [`PathConfig::max_paths`] and
//! allocated at construction; the data calls do not allocate. The path
//! binding table and join reconciliation (RP-1) extend the receive
//! sessions and come separately.

pub mod queues;
pub mod skew;
pub mod stats;

/// The largest `path_skew_window`: 1 s (RP-4).
pub const MAX_SKEW_WINDOW: u64 = 1_000_000_000;

/// The largest `max_paths` a publication may declare (provisional).
pub const MAX_PATHS: u8 = 16;

/// An image's redundant path settings (redundant-paths.md, sections 4
/// and 5; provisional and configurable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathConfig {
    /// Paths of a publication (default 4, SN-5), 1 to [`MAX_PATHS`].
    pub max_paths: u8,
    /// Datagrams each path's queue to the owner holds (default 256).
    pub path_queue_datagrams: u16,
    /// First arrivals each lane keeps for arrival differences (default
    /// 1024).
    pub skew_sample_frames: u16,
    /// The skew window in nanoseconds (default 1 ms, at most
    /// [`MAX_SKEW_WINDOW`]): a channel setting the sender and the
    /// receivers both read (RP-4).
    pub path_skew_window: u64,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            max_paths: 4,
            path_queue_datagrams: 256,
            skew_sample_frames: 1024,
            path_skew_window: 1_000_000,
        }
    }
}

/// Why a [`PathConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathConfigError {
    /// `max_paths` is 0 or above [`MAX_PATHS`].
    #[error("max_paths {value} is not in 1..={MAX_PATHS}")]
    MaxPaths {
        /// The value given.
        value: u8,
    },
    /// A path queue or the arrival ring holds nothing.
    #[error("a path queue or the arrival ring holds no entry")]
    ZeroCapacity,
    /// The skew window is above [`MAX_SKEW_WINDOW`].
    #[error("path_skew_window {value} ns is above 1 s")]
    SkewWindow {
        /// The value given.
        value: u64,
    },
}

impl PathConfig {
    /// Checks the settings, at configuration.
    ///
    /// # Errors
    ///
    /// See [`PathConfigError`].
    pub const fn validate(&self) -> Result<(), PathConfigError> {
        if self.max_paths == 0 || self.max_paths > MAX_PATHS {
            return Err(PathConfigError::MaxPaths {
                value: self.max_paths,
            });
        }
        if self.path_queue_datagrams == 0 || self.skew_sample_frames == 0 {
            return Err(PathConfigError::ZeroCapacity);
        }
        if self.path_skew_window > MAX_SKEW_WINDOW {
            return Err(PathConfigError::SkewWindow {
                value: self.path_skew_window,
            });
        }
        Ok(())
    }
}

/// Adds one to `count`; at its end it keeps its value and `overflows`
/// counts it (SPEC.md section 14: checked, never wrapped).
fn bump(count: &mut u64, overflows: &mut u64) {
    add(count, 1, overflows);
}

/// Adds `delta` to `count`, checked; an overflow leaves it and counts in
/// `overflows`, itself kept at its end.
fn add(count: &mut u64, delta: u64, overflows: &mut u64) {
    match count.checked_add(delta) {
        Some(next) => *count = next,
        None => {
            if let Some(next) = overflows.checked_add(1) {
                *overflows = next;
            }
        }
    }
}

#[cfg(test)]
mod tests;
