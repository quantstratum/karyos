// SPDX-License-Identifier: Apache-2.0

//! The clock of a trace agent (`quantstratum-docs:
//! karyos/design/trace-data-path.md`, "Identities and clocks"): every
//! observation carries its time with the clock's domain, epoch and
//! uncertainty.

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use karyos_protocol::host_clock::host_monotonic_ns;

use crate::record::ObservedTime;

/// Where a clock's time comes from, which decides whether the report may
/// calibrate two clocks automatically.
///
/// **Provenance word** (`quantstratum-docs: karyos/design/trace-tool.md`,
/// T2): a client sends it in `TraceJournal`'s `provenance` word and the
/// driver records it in the journal's table entry without interpreting it.
/// 0 is [`ClockProvenance::Opaque`], 1 [`ClockProvenance::StdMonotonic`]
/// and 2 [`ClockProvenance::HostMonotonic`]; a reader takes any other value
/// as `Opaque`, which is never calibrated automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClockProvenance {
    /// [`MonotonicClock`]: the process-wide monotonic clock of the standard
    /// library, in nanoseconds, with one origin per process. Two such clocks
    /// in one process share their source.
    StdMonotonic,
    /// [`HostMonotonicClock`]: the host's `CLOCK_MONOTONIC`, in nanoseconds.
    /// Two such clocks share their source only within one Linux time
    /// namespace, which the driver checks for each journal.
    HostMonotonic,
    /// Supplied by the application: nothing is known about its origin,
    /// scale or source, so it is never calibrated automatically.
    Opaque,
}

impl ClockProvenance {
    /// The provenance word of `TraceJournal` and of the journal's table
    /// entry.
    #[must_use]
    pub const fn word(self) -> u64 {
        match self {
            Self::Opaque => 0,
            Self::StdMonotonic => 1,
            Self::HostMonotonic => karyos_protocol::trace_hook::HOST_MONOTONIC_PROVENANCE,
        }
    }

    /// The provenance a word names; any value no client sends is
    /// [`ClockProvenance::Opaque`].
    #[must_use]
    pub const fn from_word(word: u64) -> Self {
        match word {
            1 => Self::StdMonotonic,
            karyos_protocol::trace_hook::HOST_MONOTONIC_PROVENANCE => Self::HostMonotonic,
            _ => Self::Opaque,
        }
    }
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

/// The smallest step the host clock is seen to take, in nanoseconds, over a
/// few samples; at least 1. Measured once per process.
fn host_resolution() -> u64 {
    static RESOLUTION: OnceLock<u64> = OnceLock::new();
    *RESOLUTION.get_or_init(|| {
        let mut smallest = u64::MAX;
        for _ in 0..8 {
            let start = host_monotonic_ns();
            let mut next = host_monotonic_ns();
            while next == start {
                next = host_monotonic_ns();
            }
            smallest = smallest.min(next.checked_sub(start).unwrap_or(u64::MAX));
        }
        smallest.max(1)
    })
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

/// The host clock: nanoseconds of the host's `CLOCK_MONOTONIC`
/// (`host_monotonic_ns`, the clock of every diagnostic region), one domain
/// per agent, the epoch [`HostMonotonicClock::EPOCH`] and the measured
/// resolution as the uncertainty. Its provenance is
/// [`ClockProvenance::HostMonotonic`]: a report calibrates two such clocks
/// of different processes with zero offset only when the driver found both
/// processes in its own time namespace (`quantstratum-docs:
/// karyos/design/trace-tool.md`, T2). Off Linux the clock is the process's
/// own monotonic clock, where IPC is in process only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostMonotonicClock {
    domain: u64,
}

impl HostMonotonicClock {
    /// The epoch of every host clock: `CLOCK_MONOTONIC` restarts only with
    /// the host, and a driver instance lives within one host boot.
    pub const EPOCH: u64 = 1;

    /// A clock in `domain`, which must be the agent's own (control path:
    /// the first clock of a process measures the resolution).
    #[must_use]
    pub fn new(domain: u64) -> Self {
        let _ = host_resolution();
        Self { domain }
    }

    /// The clock domain.
    #[must_use]
    pub fn domain(&self) -> u64 {
        self.domain
    }

    /// The declared resolution, in nanoseconds.
    #[must_use]
    pub fn resolution() -> u64 {
        host_resolution()
    }
}

impl TraceClock for HostMonotonicClock {
    fn now(&mut self) -> ObservedTime {
        ObservedTime {
            time: host_monotonic_ns(),
            clock: self.domain,
            epoch: Self::EPOCH,
            uncertainty: host_resolution(),
        }
    }

    fn provenance(&self) -> ClockProvenance {
        ClockProvenance::HostMonotonic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_words_round_trip_and_unknown_words_are_opaque() {
        for provenance in [
            ClockProvenance::Opaque,
            ClockProvenance::StdMonotonic,
            ClockProvenance::HostMonotonic,
        ] {
            assert_eq!(ClockProvenance::from_word(provenance.word()), provenance);
        }
        assert_eq!(
            [
                ClockProvenance::Opaque.word(),
                ClockProvenance::StdMonotonic.word(),
                ClockProvenance::HostMonotonic.word()
            ],
            [0, 1, 2]
        );
        assert_eq!(ClockProvenance::from_word(3), ClockProvenance::Opaque);
        assert_eq!(
            ClockProvenance::from_word(u64::MAX),
            ClockProvenance::Opaque
        );
    }

    #[test]
    fn host_clocks_share_the_host_scale_and_epoch() {
        let mut first = HostMonotonicClock::new(3);
        let mut second = HostMonotonicClock::new(4);
        let a = first.now();
        let b = second.now();
        assert!(a.time <= b.time);
        assert_eq!((a.clock, b.clock), (3, 4));
        assert_eq!(
            (a.epoch, b.epoch),
            (HostMonotonicClock::EPOCH, HostMonotonicClock::EPOCH)
        );
        assert_eq!(a.uncertainty, HostMonotonicClock::resolution());
        assert!(a.uncertainty >= 1);
        assert_eq!(first.provenance(), ClockProvenance::HostMonotonic);
    }

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
