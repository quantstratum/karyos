// SPDX-License-Identifier: Apache-2.0

//! When a receiver sends its SMs (`quantstratum-docs:
//! karyos/design/multicast-flow-control.md`, "Cadence and expiry"; M3,
//! MC-6, ACS 15597 and 15689).
//!
//! One [`SmSchedule`] per image. The receiver agent asks it each cycle,
//! with the image's per-lane consumption, whether an SM is due:
//!
//! - **Join.** The first SM is due at once: it is the member's join.
//! - **Interval.** An SM is due every `sm_interval` (default 10 ms) after
//!   the last one sent, judged by `age_ns`, so a backward clock read
//!   sends nothing early.
//! - **Progress.** An SM is also due as soon as a lane's consumption has
//!   advanced by at least a quarter of that lane's window since the last
//!   SM sent, so a small window does not cap throughput at one window per
//!   interval.
//!
//! The SM reports, per lane, the larger of the consumption given and the
//! last reported, so the receiver never sends an SM the sender must reject
//! as stale. A lower consumption is a fault of the caller: it is counted
//! (`regressions`) and reported as the last value. A consumption that
//! does not move gives an unchanged SM at each interval: the sender counts
//! it as stationary, or as fresh when the member is caught up, and keeps a
//! paused member for up to `pause_timeout` (ACS 15604, 15610). The
//! schedule cannot tell caught up from paused, since it does not know the
//! sender's `sent_high`; it needs to send neither more nor less often for
//! either.
//!
//! An SM is reported to the schedule as sent ([`SmSchedule::sent`]) only
//! when the backend took it; one that was not sent stays due. Nothing here
//! allocates; times and counts are checked, and a count at its end sets
//! the sticky `overflowed` flag (SPEC.md section 14).

use karyos_protocol::network::MAX_LANES;
use karyos_sys::host_clock::age_ns;

/// Why an SM is due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmReason {
    /// The member's first SM.
    Join,
    /// `sm_interval` passed since the last one.
    Interval,
    /// A lane advanced by a quarter of its window.
    Progress,
}

/// An SM to send: why, and the per-lane consumption to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmDue {
    /// Why it is due.
    pub reason: SmReason,
    /// The consumption to report, lane 0 first; lanes beyond the count are
    /// 0.
    pub consumption: [u64; MAX_LANES],
}

/// Why an [`SmSchedule`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SmScheduleError {
    /// `sm_interval` is 0.
    #[error("sm_interval is 0")]
    Interval,
    /// Not 1 to 4 windows, or a window of 0.
    #[error("not 1 to 4 windows, or a window of 0")]
    Windows,
}

/// What the schedule counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SmScheduleCounts {
    /// SMs sent at the join.
    pub joins: u64,
    /// SMs sent at the interval.
    pub interval: u64,
    /// SMs sent for a quarter-window advance.
    pub progress: u64,
    /// SMs due while a lane's consumption was given below the last
    /// reported (reported as the last value instead).
    pub regressions: u64,
    /// An increment did not apply (sticky).
    pub overflowed: bool,
}

impl SmScheduleCounts {
    fn bump(&mut self, field: impl FnOnce(&mut Self) -> &mut u64) {
        let count = field(self);
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => self.overflowed = true,
        }
    }
}

/// One image's SM schedule.
#[derive(Debug, Clone)]
pub struct SmSchedule {
    interval: u64,
    lanes: usize,
    /// A quarter of each lane's window, at least 1.
    quarters: [u64; MAX_LANES],
    /// The consumption of the last SM sent; `None` before the join.
    reported: Option<[u64; MAX_LANES]>,
    /// When the last SM was sent.
    last_sent: u64,
    counts: SmScheduleCounts,
}

impl SmSchedule {
    /// The schedule of an image whose lanes have these receiver `windows`
    /// (lane 0 first), sending at least every `sm_interval` nanoseconds.
    ///
    /// # Errors
    ///
    /// See [`SmScheduleError`].
    pub fn new(sm_interval: u64, windows: &[u32]) -> Result<Self, SmScheduleError> {
        if sm_interval == 0 {
            return Err(SmScheduleError::Interval);
        }
        if windows.is_empty() || windows.len() > MAX_LANES || windows.contains(&0) {
            return Err(SmScheduleError::Windows);
        }
        let mut quarters = [0; MAX_LANES];
        for (quarter, window) in quarters.iter_mut().zip(windows) {
            *quarter = u64::from(window / 4).max(1);
        }
        Ok(Self {
            interval: sm_interval,
            lanes: windows.len(),
            quarters,
            reported: None,
            last_sent: 0,
            counts: SmScheduleCounts::default(),
        })
    }

    /// The counts.
    #[must_use]
    pub const fn counts(&self) -> &SmScheduleCounts {
        &self.counts
    }

    /// Whether an SM is due at `now` with this per-lane `consumption`
    /// (lane 0 first; lanes beyond the image's are ignored, missing ones
    /// read as 0), and what it reports. Asking changes nothing but the
    /// regression count of a due SM; [`SmSchedule::sent`] records a sent
    /// SM.
    pub fn due(&mut self, now: u64, consumption: &[u64]) -> Option<SmDue> {
        let mut report = [0; MAX_LANES];
        for (slot, value) in report.iter_mut().zip(consumption).take(self.lanes) {
            *slot = *value;
        }
        let Some(last) = self.reported else {
            return Some(SmDue {
                reason: SmReason::Join,
                consumption: report,
            });
        };
        let mut regressed = false;
        let mut progress = false;
        for ((slot, previous), quarter) in report
            .iter_mut()
            .zip(last)
            .zip(self.quarters)
            .take(self.lanes)
        {
            match slot.checked_sub(previous) {
                Some(advance) => progress |= advance >= quarter,
                None => {
                    regressed = true;
                    *slot = previous;
                }
            }
        }
        let reason = if progress {
            SmReason::Progress
        } else if age_ns(now, self.last_sent) >= self.interval {
            SmReason::Interval
        } else {
            return None;
        };
        // Counted once per SM due, not once per cycle.
        if regressed {
            self.counts.bump(|c| &mut c.regressions);
        }
        Some(SmDue {
            reason,
            consumption: report,
        })
    }

    /// The SM `due` was sent at `now`: the backend took it. The interval
    /// and the progress reference restart from it.
    pub fn sent(&mut self, due: &SmDue, now: u64) {
        self.counts.bump(|c| match due.reason {
            SmReason::Join => &mut c.joins,
            SmReason::Interval => &mut c.interval,
            SmReason::Progress => &mut c.progress,
        });
        // Never below what was already reported: a stale `due` kept from
        // an earlier cycle cannot move the reference back.
        let mut reported = due.consumption;
        if let Some(last) = self.reported {
            for (slot, previous) in reported.iter_mut().zip(last) {
                *slot = (*slot).max(previous);
            }
        }
        self.reported = Some(reported);
        self.last_sent = now;
    }
}

#[cfg(test)]
mod tests;
