// SPDX-License-Identifier: Apache-2.0

//! The clock of a trace agent (`quantstratum-docs:
//! karyos/design/trace-data-path.md`, "Identities and clocks"): every
//! observation carries its time with the clock's domain, epoch and
//! uncertainty.

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::record::ObservedTime;

/// Where a clock's time comes from, which decides whether the driver may
/// calibrate two clocks automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClockProvenance {
    /// [`MonotonicClock`]: the process-wide monotonic clock of the standard
    /// library, in nanoseconds, with one origin per process. Two such clocks
    /// in one process share their source.
    StdMonotonic,
    /// Supplied by the application: nothing is known about its origin,
    /// scale or source, so it is never calibrated automatically.
    Opaque,
}

/// The time source of one trace agent.
pub trait TraceClock: Send {
    /// The current time in the clock's domain and epoch.
    fn now(&mut self) -> ObservedTime;

    /// Where the time comes from.
    fn provenance(&self) -> ClockProvenance {
        ClockProvenance::Opaque
    }
}

/// The process-wide origin and epoch of every [`MonotonicClock`].
struct ProcessClock {
    origin: Instant,
    epoch: u64,
    resolution: u64,
}

fn process_clock() -> &'static ProcessClock {
    static CLOCK: OnceLock<ProcessClock> = OnceLock::new();
    CLOCK.get_or_init(|| ProcessClock {
        origin: Instant::now(),
        // A new epoch per process start: the wall time at the first use.
        // Only its difference from other processes' epochs matters.
        epoch: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |since| {
                u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
            }),
        resolution: measured_resolution(),
    })
}

/// The smallest step the monotonic clock is seen to take, in nanoseconds,
/// over a few samples; at least 1.
fn measured_resolution() -> u64 {
    let mut smallest = u64::MAX;
    for _ in 0..8 {
        let start = Instant::now();
        let mut next = Instant::now();
        while next == start {
            next = Instant::now();
        }
        let step = u64::try_from(next.duration_since(start).as_nanos()).unwrap_or(u64::MAX);
        smallest = smallest.min(step);
    }
    smallest.max(1)
}

/// The standard trace clock: nanoseconds since the process origin of the
/// standard library's monotonic clock, one domain per agent, one epoch per
/// process start, and the measured resolution as the uncertainty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonotonicClock {
    domain: u64,
}

impl MonotonicClock {
    /// A clock in `domain`, which must be the agent's own (control path:
    /// the first clock of a process measures the resolution).
    #[must_use]
    pub fn new(domain: u64) -> Self {
        let _ = process_clock();
        Self { domain }
    }

    /// The clock domain.
    #[must_use]
    pub fn domain(&self) -> u64 {
        self.domain
    }

    /// The process epoch every [`MonotonicClock`] of this process uses.
    #[must_use]
    pub fn epoch() -> u64 {
        process_clock().epoch
    }

    /// The declared resolution, in nanoseconds.
    #[must_use]
    pub fn resolution() -> u64 {
        process_clock().resolution
    }
}

impl TraceClock for MonotonicClock {
    fn now(&mut self) -> ObservedTime {
        let clock = process_clock();
        ObservedTime {
            time: u64::try_from(clock.origin.elapsed().as_nanos()).unwrap_or(u64::MAX),
            clock: self.domain,
            epoch: clock.epoch,
            uncertainty: clock.resolution,
        }
    }

    fn provenance(&self) -> ClockProvenance {
        ClockProvenance::StdMonotonic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_clocks_share_the_process_origin_and_epoch() {
        let mut first = MonotonicClock::new(7);
        let mut second = MonotonicClock::new(8);
        let a = first.now();
        let b = second.now();
        let c = first.now();
        assert!(a.time <= b.time && b.time <= c.time);
        assert_eq!((a.clock, b.clock), (7, 8));
        assert_eq!(a.epoch, b.epoch);
        assert_eq!(a.epoch, MonotonicClock::epoch());
        assert!(a.uncertainty >= 1);
        assert_eq!(a.uncertainty, MonotonicClock::resolution());
        assert_eq!(first.provenance(), ClockProvenance::StdMonotonic);
    }

    #[test]
    fn an_application_clock_is_opaque_by_default() {
        struct Fixed;
        impl TraceClock for Fixed {
            fn now(&mut self) -> ObservedTime {
                ObservedTime::default()
            }
        }
        assert_eq!(Fixed.provenance(), ClockProvenance::Opaque);
    }
}
