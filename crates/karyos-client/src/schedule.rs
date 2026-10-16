// SPDX-License-Identifier: Apache-2.0

//! Timed transmission on the client side (`quantstratum-docs:
//! karyos/design/timed-tx.md`, sections 2 and 3; P2.11 T1).
//!
//! A timed lane's publication handle holds a [`ScheduleBinding`]: the
//! lane's schedule ring publisher, the publication's clock domain and its
//! limits. `offer_at` checks a requested time against them before anything
//! is reserved, then appends the message with its entry
//! (`karyos_sys::log_buffer::Publication::append_scheduled`).

use karyos_sys::schedule_ring::SchedulePublisher;
use karyos_sys::sync::AtomicU64;

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
/// kernel reads as the end of time, so every deadline sum overflows and
/// the offer is refused (`ScheduleOverflow`), never scheduled on a guess.
#[cfg(target_os = "linux")]
fn tai_now() -> u64 {
    karyos_sys::host_clock::host_tai_ns().unwrap_or(u64::MAX)
}

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

/// A timed lane's publication side: the ring's publisher, the settings and
/// the last time accepted.
#[derive(Debug)]
pub struct ScheduleBinding {
    pub(crate) publisher: SchedulePublisher,
    options: ScheduleOptions,
    clock: fn() -> u64,
    last: Option<u64>,
}

impl ScheduleBinding {
    /// The binding of the timed lane whose schedule ring is `ring`, read
    /// against `clock` in `options.domain`.
    ///
    /// # Errors
    ///
    /// [`ClientError::Sys`] for a ring that is not one.
    pub fn new(
        ring: &[AtomicU64],
        options: ScheduleOptions,
        clock: fn() -> u64,
    ) -> Result<Self, ClientError> {
        let publisher = SchedulePublisher::attach(ring)
            .map_err(|error| ClientError::from(karyos_sys::error::SysError::from(error)))?;
        Ok(Self {
            publisher,
            options,
            clock,
            last: None,
        })
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
    /// is `ScheduleOverflow`. A time already past is accepted.
    pub(crate) fn check(&self, tx_time: u64) -> Result<(), ClientError> {
        if self.last.is_some_and(|last| tx_time < last) {
            return Err(ClientError::InvalidSchedule {
                reason: "a requested time below the lane's last",
            });
        }
        tx_time
            .checked_add(self.options.lateness_tolerance)
            .ok_or(ClientError::ScheduleOverflow)?;
        let limit = (self.clock)()
            .checked_add(self.options.max_horizon)
            .ok_or(ClientError::ScheduleOverflow)?;
        if tx_time > limit {
            return Err(ClientError::ScheduleTooFar { tx_time, limit });
        }
        Ok(())
    }

    /// Records an accepted message's time.
    pub(crate) fn accepted(&mut self, tx_time: u64) {
        self.last = Some(tx_time);
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

    fn binding(options: ScheduleOptions) -> (Vec<AtomicU64>, ScheduleBinding) {
        let words = karyos_sys::schedule_ring::ring_words(4).unwrap();
        let ring: Vec<AtomicU64> = (0..words).map(|_| AtomicU64::new(0)).collect();
        karyos_sys::schedule_ring::init(&ring, 4).unwrap();
        let binding = ScheduleBinding::new(&ring, options, now_for_tests).unwrap();
        (ring, binding)
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
