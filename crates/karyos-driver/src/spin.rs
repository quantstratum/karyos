// SPDX-License-Identifier: Apache-2.0

//! Spin time per idle loop (counter type 3, `quantstratum-docs:
//! karyos/design/cnc-primitives.md`; SPEC §11, low-rate workloads;
//! ADR-0055, ADR-0066; management-agent-gap-analysis.md, M5).
//!
//! - **What counts.** The lifetime host `CLOCK_MONOTONIC` nanoseconds an
//!   idle loop spent in busy-spin phases of its idle strategy without
//!   finding work. Sleeping, parking and yielding are excluded, so a
//!   backoff strategy that saves CPU shows a lower value, and one that
//!   never spins, such as [`crate::agents::YieldThenSleep`], shows 0.
//! - **How (coordinator ruling on M5).** Per spin run, never per
//!   iteration: the clock is read when a run starts (the first spin after
//!   work or after another phase) and when it ends (work found, or the
//!   strategy leaving the spin phase). The end read comes after the cycle
//!   that found work, so it never delays a wake-up. A strategy that spins
//!   without end flushes every [`FLUSH_SPINS`] spins, one more read.
//! - **Cells.** One driver-wide type-3 cell per idle loop, allocated when
//!   the driver is created. An agent loop's meter owns its keyed cell and
//!   is its only writer, with a plain store of its checked total. The
//!   conductor loop's cell is one of the fixed counters, which the driver
//!   keeps: that meter stores its total into a word the driver shares
//!   with it, and the conductor copies the word into the cell at each duty
//!   cycle, on the thread that drives it. Dropping that meter leaves the
//!   fixed cell where it is.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_sys::counters::Counter;

/// Where a meter stores its total.
#[derive(Debug, Default)]
enum Sink {
    /// Nowhere (a meter without a cell).
    #[default]
    None,
    /// A keyed cell the meter owns.
    Cell(Counter),
    /// A word the driver shares and copies into a fixed cell it keeps.
    Shared(Arc<AtomicU64>),
}

/// Spins after which a run still going is measured and stored.
pub const FLUSH_SPINS: u32 = 1024;

/// One idle loop's spin time and its cell.
#[derive(Debug, Default)]
pub struct SpinMeter {
    sink: Sink,
    total: u64,
    /// When the current spin run started, if one is going.
    started: Option<u64>,
    /// Spins of the current run since it was last measured.
    spins: u32,
}

impl SpinMeter {
    /// A meter storing into `cell`, which it owns.
    pub(crate) fn new(cell: Option<Counter>) -> Self {
        Self {
            sink: cell.map_or(Sink::None, Sink::Cell),
            ..Self::default()
        }
    }

    /// A meter storing into `word`, which the driver copies into a cell it
    /// keeps.
    pub(crate) fn shared(word: Arc<AtomicU64>) -> Self {
        Self {
            sink: Sink::Shared(word),
            ..Self::default()
        }
    }

    /// The nanoseconds measured so far.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// One spin of the idle strategy: starts a run, or every
    /// [`FLUSH_SPINS`] spins measures it so far.
    pub fn spin(&mut self) {
        match self.started {
            None => {
                self.started = Some(karyos_sys::host_clock::host_monotonic_ns());
                self.spins = 0;
            }
            Some(_) => {
                if let Some(spins) = self.spins.checked_add(1) {
                    self.spins = spins;
                }
                if self.spins >= FLUSH_SPINS {
                    self.measure(true);
                }
            }
        }
    }

    /// Ends the current spin run, if one is going: work was found, or the
    /// strategy left its spin phase.
    pub fn end_run(&mut self) {
        if self.started.is_some() {
            self.measure(false);
        }
    }

    /// Adds the time since the run started (or was last measured) and
    /// stores the total; a run that goes on restarts its measure now.
    fn measure(&mut self, going_on: bool) {
        let now = karyos_sys::host_clock::host_monotonic_ns();
        if let Some(elapsed) = self.started.and_then(|start| now.checked_sub(start))
            && let Some(total) = self.total.checked_add(elapsed)
        {
            self.total = total;
            match &self.sink {
                Sink::None => {}
                Sink::Cell(cell) => cell.set(total),
                // The conductor reads it on the same thread, in its next
                // duty cycle.
                Sink::Shared(word) => word.store(total, Ordering::Relaxed),
            }
        }
        self.started = going_on.then_some(now);
        self.spins = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run's time counts once it ends; with no run nothing counts.
    #[test]
    fn a_run_counts_when_it_ends() {
        let mut meter = SpinMeter::default();
        meter.end_run();
        assert_eq!(meter.total(), 0);
        meter.spin();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(meter.total(), 0, "a run going on is not counted yet");
        meter.end_run();
        assert!(meter.total() >= 2_000_000, "{}", meter.total());
        let first = meter.total();
        meter.end_run();
        assert_eq!(meter.total(), first, "no run, nothing added");
    }

    /// A run that never ends is measured every `FLUSH_SPINS` spins.
    #[test]
    fn an_unbounded_run_flushes() {
        let mut meter = SpinMeter::default();
        meter.spin();
        std::thread::sleep(std::time::Duration::from_millis(1));
        for _ in 1..FLUSH_SPINS {
            meter.spin();
        }
        assert_eq!(meter.total(), 0);
        meter.spin();
        assert!(meter.total() >= 1_000_000, "{}", meter.total());
    }
}
