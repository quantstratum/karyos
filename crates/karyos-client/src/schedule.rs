// SPDX-License-Identifier: Apache-2.0

//! Timed transmission on the client side (`quantstratum-docs:
//! karyos/design/timed-tx.md`, sections 2 and 3; P2.11 T1).
//!
//! A timed lane's publication handle holds a [`ScheduleBinding`]: the
//! publication's clock domain and its limits. `offer_at` checks a requested
//! time against them before anything is reserved, then appends the message
//! with its entry (`karyos_sys::log_buffer::Publication::append_scheduled`,
//! whose publisher is the sys publication's own).

use std::sync::Arc;

use karyos_sys::counters::Counter;

use crate::error::ClientError;

/// The clock a timed publication's requested times are read in (TT-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockDomain {
    /// The host's monotonic clock (`karyos_sys::host_clock::host_monotonic_ns`):
    /// the default, for software scheduling.
    #[default]
    Monotonic,
    /// The host's `CLOCK_TAI`, Linux only.
    Tai,
}

impl ClockDomain {
    /// The domain's name in counter labels.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Monotonic => "monotonic",
            Self::Tai => "tai",
        }
    }

    /// The clock of the domain, on this host.
    ///
    /// # Errors
    ///
    /// [`ClientError::InvalidSchedule`] for `Tai` off Linux.
    pub fn clock(self) -> Result<fn() -> u64, ClientError> {
        match self {
            Self::Monotonic => Ok(karyos_sys::host_clock::host_monotonic_ns),
            // The kernel's `CLOCK_TAI` is checked once, here.
            #[cfg(target_os = "linux")]
            Self::Tai => karyos_sys::host_clock::host_tai_ns()
                .map(|_| tai_now as fn() -> u64)
                .ok_or(ClientError::InvalidSchedule {
                    reason: "the kernel refuses CLOCK_TAI",
                }),
            #[cfg(not(target_os = "linux"))]
            Self::Tai => Err(ClientError::InvalidSchedule {
                reason: "the Tai domain is Linux only",
            }),
        }
    }
}

/// `CLOCK_TAI` once its availability was checked: a later refusal by the
/// kernel reads as [`CLOCK_UNAVAILABLE`], and the offer is refused
/// (`ScheduleOverflow`), never scheduled on a guess.
#[cfg(target_os = "linux")]
fn tai_now() -> u64 {
    karyos_sys::host_clock::host_tai_ns().unwrap_or(CLOCK_UNAVAILABLE)
}

/// What a schedule clock returns when it cannot read the time: an offer
/// checked against it is refused with `ScheduleOverflow`, whatever the
/// horizon, never scheduled on a guess.
pub const CLOCK_UNAVAILABLE: u64 = u64::MAX;

/// The current time in `domain`, so an application reads the clock it
/// schedules in.
///
/// # Errors
///
/// As [`ClockDomain::clock`].
pub fn now(domain: ClockDomain) -> Result<u64, ClientError> {
    domain.clock().map(|clock| clock())
}

/// A timed publication's settings (TT-2, TT-3); the defaults are
/// provisional and configurable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleOptions {
    /// The clock domain of requested times.
    pub domain: ClockDomain,
    /// How far ahead a time may be requested, in nanoseconds (default 1 s).
    pub max_horizon: u64,
    /// How late a message may be submitted before it is late, in
    /// nanoseconds (default 1 ms).
    pub lateness_tolerance: u64,
    /// Whether a head past its time plus the tolerance aborts the
    /// incarnation (G7) instead of being sent late.
    pub cancel_on_deadline: bool,
}

impl Default for ScheduleOptions {
    fn default() -> Self {
        Self {
            domain: ClockDomain::Monotonic,
            max_horizon: 1_000_000_000,
            lateness_tolerance: 1_000_000,
            cancel_on_deadline: false,
        }
    }
}

/// The clock a timed lane's offers are checked against, in its domain:
/// the host's clock of the domain ([`ClockDomain::clock`]) unless the
/// driver or a simulator sets another.
///
/// It runs on the offer path, once per `offer_at`: it must not allocate,
/// block or take a lock another thread may hold. A clock that cannot read
/// the time returns [`CLOCK_UNAVAILABLE`], and the offer is refused
/// (`ScheduleOverflow`), never scheduled on a guess.
#[derive(Clone)]
pub struct ScheduleClock(Arc<dyn Fn() -> u64 + Send + Sync>);

impl ScheduleClock {
    /// A clock that reads `now`.
    pub fn new(now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self(Arc::new(now))
    }

    /// The host clock of `domain`.
    ///
    /// # Errors
    ///
    /// As [`ClockDomain::clock`].
    pub fn host(domain: ClockDomain) -> Result<Self, ClientError> {
        Ok(Self::new(domain.clock()?))
    }

    /// The current time.
    #[must_use]
    pub fn now(&self) -> u64 {
        (self.0)()
    }
}

impl core::fmt::Debug for ScheduleClock {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ScheduleClock")
    }
}

/// A timed lane's offer counters (`quantstratum-docs:
/// karyos/design/timed-tx.md`, section 6), cells of the driver's counters
/// region that the driver allocates for the lane and shares with each of
/// its handles. A cell the region had no room for is `None`, and its count
/// is not kept. An increment that would overflow leaves the value
/// unchanged; it is not counted elsewhere, since a client handle has no
/// `counter overflows` cell.
#[derive(Debug, Default)]
pub struct ScheduleCounters {
    /// Timed offers accepted.
    pub scheduled_offers: Option<Counter>,
    /// Timed offers refused with `InvalidSchedule` (a time below the
    /// lane's last).
    pub rejected_invalid: Option<Counter>,
    /// Timed offers refused with `ScheduleTooFar`.
    pub rejected_too_far: Option<Counter>,
    /// Timed offers refused with `ScheduleOverflow`.
    pub rejected_overflow: Option<Counter>,
    /// Timed offers back pressured by a full schedule ring.
    pub rejected_ring_full: Option<Counter>,
}

/// Adds one to `counter`, if it has a cell; see [`ScheduleCounters`].
pub(crate) fn count(counter: Option<&Counter>) {
    if let Some(counter) = counter {
        let _ = counter.increment(1);
    }
}

/// A timed lane's publication side: the settings, the clock, the counters
/// and the last time accepted. The ring's publisher is the sys
/// publication's own, built from its own lane's ring, so a handle cannot
/// push to another lane's.
#[derive(Debug)]
pub struct ScheduleBinding {
    options: ScheduleOptions,
    clock: ScheduleClock,
    pub(crate) counters: Arc<ScheduleCounters>,
    last: Option<u64>,
}

impl ScheduleBinding {
    /// The binding of a timed lane, its offers read against `clock` in
    /// `options.domain`.
    #[must_use]
    pub fn new(options: ScheduleOptions, clock: ScheduleClock) -> Self {
        Self {
            options,
            clock,
            counters: Arc::new(ScheduleCounters::default()),
            last: None,
        }
    }

    /// The binding counting into `counters`, which the lane's handles
    /// share.
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<ScheduleCounters>) -> Self {
        self.counters = counters;
        self
    }

    /// The lane's offer counters.
    #[must_use]
    pub fn counters(&self) -> &ScheduleCounters {
        &self.counters
    }

    /// The publication's settings.
    #[must_use]
    pub fn options(&self) -> ScheduleOptions {
        self.options
    }

    /// The last requested time accepted on the lane.
    #[must_use]
    pub fn last_time(&self) -> Option<u64> {
        self.last
    }

    /// The checks at offer (section 3), before anything is reserved: a time
    /// below the lane's last is `InvalidSchedule` (times never go backwards
    /// within a timed lane, or its head-time rule breaks); one beyond
    /// `now + max_horizon` is `ScheduleTooFar`; a deadline that overflows
    /// is `ScheduleOverflow`, as is a clock that cannot read the time
    /// ([`CLOCK_UNAVAILABLE`]). A time already past is accepted.
    /// Each refusal counts under its reason.
    pub(crate) fn check(&self, tx_time: u64) -> Result<(), ClientError> {
        let checked = self.check_time(tx_time);
        let counter = match &checked {
            Ok(()) => None,
            Err(ClientError::InvalidSchedule { .. }) => self.counters.rejected_invalid.as_ref(),
            Err(ClientError::ScheduleTooFar { .. }) => self.counters.rejected_too_far.as_ref(),
            Err(ClientError::ScheduleOverflow) => self.counters.rejected_overflow.as_ref(),
            Err(_) => None,
        };
        count(counter);
        checked
    }

    fn check_time(&self, tx_time: u64) -> Result<(), ClientError> {
        if self.last.is_some_and(|last| tx_time < last) {
            return Err(ClientError::InvalidSchedule {
                reason: "a requested time below the lane's last",
            });
        }
        tx_time
            .checked_add(self.options.lateness_tolerance)
            .ok_or(ClientError::ScheduleOverflow)?;
        let now = self.clock.now();
        if now == CLOCK_UNAVAILABLE {
            return Err(ClientError::ScheduleOverflow);
        }
        let limit = now
            .checked_add(self.options.max_horizon)
            .ok_or(ClientError::ScheduleOverflow)?;
        if tx_time > limit {
            return Err(ClientError::ScheduleTooFar { tx_time, limit });
        }
        Ok(())
    }

    /// Records an accepted message's time, and counts it.
    pub(crate) fn accepted(&mut self, tx_time: u64) {
        self.last = Some(tx_time);
        count(self.counters.scheduled_offers.as_ref());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    thread_local! {
        static NOW: core::cell::Cell<u64> = const { core::cell::Cell::new(1_000) };
    }

    fn now_for_tests() -> u64 {
        NOW.with(core::cell::Cell::get)
    }

    fn binding(options: ScheduleOptions) -> ((), ScheduleBinding) {
        (
            (),
            ScheduleBinding::new(options, ScheduleClock::new(now_for_tests)),
        )
    }

    fn unavailable() -> u64 {
        CLOCK_UNAVAILABLE
    }

    /// A clock that cannot read the time refuses every offer with
    /// `ScheduleOverflow`, also with a zero horizon, where the sum alone
    /// would not overflow (#234 P3).
    #[test]
    fn an_unavailable_clock_refuses() {
        for max_horizon in [0, 1, 1_000_000_000] {
            let binding = ScheduleBinding::new(
                ScheduleOptions {
                    max_horizon,
                    ..ScheduleOptions::default()
                },
                ScheduleClock::new(unavailable),
            );
            for time in [0, 1_000, u64::MAX - 1_000_000_000] {
                assert_eq!(binding.check(time), Err(ClientError::ScheduleOverflow));
            }
        }
    }

    /// `ScheduleTooFar` at `max_horizon` plus 1 ns, never at the horizon
    /// itself (timed-tx.md section 8).
    #[test]
    fn the_horizon_is_exact() {
        let options = ScheduleOptions {
            max_horizon: 500,
            ..ScheduleOptions::default()
        };
        let (_ring, binding) = binding(options);
        assert_eq!(binding.check(1_500), Ok(()));
        assert_eq!(
            binding.check(1_501),
            Err(ClientError::ScheduleTooFar {
                tx_time: 1_501,
                limit: 1_500
            })
        );
        // A time already past is accepted.
        assert_eq!(binding.check(0), Ok(()));
    }

    /// Times never go backwards within a timed lane; equal times are fine.
    #[test]
    fn times_never_go_backwards() {
        let (_ring, mut binding) = binding(ScheduleOptions::default());
        binding.accepted(1_200);
        assert_eq!(binding.check(1_200), Ok(()));
        assert!(matches!(
            binding.check(1_199),
            Err(ClientError::InvalidSchedule { .. })
        ));
        assert_eq!(binding.last_time(), Some(1_200));
    }

    /// Deadline sums that overflow are refused, never wrapped.
    #[test]
    fn overflowing_deadlines_are_refused() {
        let (_ring, binding) = binding(ScheduleOptions {
            max_horizon: u64::MAX,
            ..ScheduleOptions::default()
        });
        assert_eq!(binding.check(2_000), Err(ClientError::ScheduleOverflow));
        let (_ring, binding) = self::binding(ScheduleOptions::default());
        assert_eq!(binding.check(u64::MAX), Err(ClientError::ScheduleOverflow));
    }

    /// `Tai` exists on Linux only.
    #[test]
    fn the_tai_domain_is_linux_only() {
        assert!(now(ClockDomain::Monotonic).is_ok());
        assert_eq!(now(ClockDomain::Tai).is_ok(), cfg!(target_os = "linux"));
    }
}
