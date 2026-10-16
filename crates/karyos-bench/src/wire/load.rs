// SPDX-License-Identifier: Apache-2.0

//! The loads of manifest 6.1 for the wire workloads
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.3).
//!
//! - **R1** keeps one message in flight: the sender waits for the
//!   receiver's acknowledgement of message `n` before sending `n + 1`, as
//!   `ping_pong` of `workloads.rs` does. It needs no schedule.
//! - **R2** sends message `n` at `start + n / rate`. A send that starts
//!   late keeps its scheduled instant as its origin, so the delay it
//!   suffered stays in its latency and coordinated omission stays visible
//!   ([`Schedule::lateness`]).
//! - **R3** searches for the highest rate whose run has no drop
//!   ([`search_saturation`]); it is reported only.

use std::time::{Duration, Instant};

use crate::workloads::{BenchError, scheduled_instant};

/// The open-loop schedule of R2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    start: Instant,
    rate: u64,
}

impl Schedule {
    /// A schedule of `rate` messages per second from `start`.
    ///
    /// # Errors
    ///
    /// A rate of zero.
    pub fn new(start: Instant, rate: u64) -> Result<Self, BenchError> {
        if rate == 0 {
            return Err(BenchError("R2 rate of zero".into()));
        }
        Ok(Self { start, rate })
    }

    /// The instant message `index` is scheduled for: `start + index / rate`,
    /// in exact integer nanoseconds.
    ///
    /// # Errors
    ///
    /// An instant past what the clock represents.
    pub fn instant(&self, index: u64) -> Result<Instant, BenchError> {
        // The open-loop schedule of `workloads.rs`, shared.
        scheduled_instant(self.start, index, self.rate)
    }

    /// How late a send that started at `actual` was against message
    /// `index`'s instant; zero when it started on time or early. The
    /// latency of a late message is measured from its scheduled instant,
    /// so this delay is part of it.
    ///
    /// # Errors
    ///
    /// As [`Self::instant`].
    pub fn lateness(&self, index: u64, actual: Instant) -> Result<Duration, BenchError> {
        Ok(actual
            .checked_duration_since(self.instant(index)?)
            .unwrap_or(Duration::ZERO))
    }
}

/// The outcome of one rate tried by the saturation search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trial {
    /// Messages per second tried.
    pub rate: u64,
    /// Whether the run at that rate had no drop.
    pub clean: bool,
}

/// R3: the highest rate in `[low, high]` whose run has no drop, found by
/// bisection to within `resolution` messages per second. `run` measures
/// one rate and reports whether it was clean; every trial is returned so
/// the report can show the search. `None` when even `low` drops.
///
/// # Errors
///
/// An empty range, a zero resolution, or an error of `run`.
pub fn search_saturation(
    low: u64,
    high: u64,
    resolution: u64,
    mut run: impl FnMut(u64) -> Result<bool, BenchError>,
) -> Result<(Option<u64>, Vec<Trial>), BenchError> {
    if low == 0 || low > high || resolution == 0 {
        return Err(BenchError(format!(
            "R3 search range {low}..={high} with resolution {resolution}"
        )));
    }
    let mut trials = Vec::new();
    let mut attempt = |rate: u64| -> Result<bool, BenchError> {
        let clean = run(rate)?;
        trials.push(Trial { rate, clean });
        Ok(clean)
    };
    if !attempt(low)? {
        return Ok((None, trials));
    }
    if attempt(high)? {
        return Ok((Some(high), trials));
    }
    // Invariant: `good` is clean, `bad` drops.
    let (mut good, mut bad) = (low, high);
    while bad - good > resolution {
        let middle = good + (bad - good) / 2;
        if attempt(middle)? {
            good = middle;
        } else {
            bad = middle;
        }
    }
    Ok((Some(good), trials))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schedule_is_exact_and_keeps_late_sends_late() {
        let start = Instant::now();
        let schedule = Schedule::new(start, 100_000).unwrap_or_else(|_| unreachable!());
        assert_eq!(schedule.instant(0).ok(), Some(start));
        assert_eq!(
            schedule.instant(3).ok(),
            start.checked_add(Duration::from_nanos(30_000))
        );
        let late = start
            .checked_add(Duration::from_nanos(25_000))
            .unwrap_or(start);
        // Message 2 was due at 20 µs and started at 25 µs: 5 µs late.
        assert_eq!(
            schedule.lateness(2, late).ok(),
            Some(Duration::from_nanos(5_000))
        );
        // Message 3 was due at 30 µs: on time is zero, never negative.
        assert_eq!(schedule.lateness(3, late).ok(), Some(Duration::ZERO));
        assert!(Schedule::new(start, 0).is_err());
        assert!(schedule.instant(u64::MAX).is_err());
    }

    #[test]
    fn lateness_beyond_one_period_is_kept_whole() {
        let start = Instant::now();
        let schedule = Schedule::new(start, 100_000).unwrap();
        // Message 1 was due at 10 µs and started at 95 µs: 85 µs late,
        // more than eight periods, all kept.
        let late = start.checked_add(Duration::from_nanos(95_000)).unwrap();
        assert_eq!(
            schedule.lateness(1, late).ok(),
            Some(Duration::from_nanos(85_000))
        );
    }

    #[test]
    fn a_rate_that_does_not_divide_a_second_rounds_down_exactly() {
        let start = Instant::now();
        let schedule = Schedule::new(start, 3).unwrap();
        assert_eq!(
            schedule.instant(1).ok(),
            start.checked_add(Duration::from_nanos(333_333_333))
        );
        assert_eq!(
            schedule.instant(2).ok(),
            start.checked_add(Duration::from_nanos(666_666_666))
        );
        assert_eq!(
            schedule.instant(3).ok(),
            start.checked_add(Duration::from_secs(1))
        );
    }

    #[test]
    fn the_search_finds_the_highest_clean_rate() {
        let (found, trials) =
            search_saturation(1_000, 1_000_000, 1_000, |rate| Ok(rate <= 437_000))
                .unwrap_or_else(|_| unreachable!());
        let found = found.unwrap_or(0);
        assert!((436_000..=437_000).contains(&found), "{found}");
        assert!(trials.len() < 15, "{}", trials.len());
        assert!(trials.iter().all(|t| t.clean == (t.rate <= 437_000)));
    }

    #[test]
    fn the_search_reports_the_edges() {
        assert_eq!(
            search_saturation(10, 100, 1, |_| Ok(true))
                .map(|r| r.0)
                .ok(),
            Some(Some(100))
        );
        assert_eq!(
            search_saturation(10, 100, 1, |_| Ok(false))
                .map(|r| r.0)
                .ok(),
            Some(None)
        );
        assert!(search_saturation(0, 100, 1, |_| Ok(true)).is_err());
        assert!(search_saturation(100, 10, 1, |_| Ok(true)).is_err());
        assert!(search_saturation(10, 100, 0, |_| Ok(true)).is_err());
    }
}
