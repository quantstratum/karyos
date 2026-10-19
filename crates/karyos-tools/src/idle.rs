// SPDX-License-Identifier: Apache-2.0

//! A backoff idle strategy for a duty-cycle loop (SPEC.md §2, principle 9):
//! after a cycle with work it returns at once; after consecutive idle
//! cycles it spins, then yields, then sleeps with a doubling period up to a
//! bound. A cycle with work resets it.
//!
//! With a spin meter (`karyos_driver::spin`, M5) it measures its spin
//! runs: a run starts at its first spin and ends at work, at a reset or
//! when the strategy moves on to yielding; yields and sleeps never count.

use std::time::Duration;

use karyos_driver::spin::SpinMeter;

/// Spins, yields, then sleeps up to a bound while no work is done.
#[derive(Debug)]
pub struct BackoffIdle {
    max_spins: u32,
    max_yields: u32,
    min_sleep: Duration,
    max_sleep: Duration,
    spins: u32,
    yields: u32,
    sleep: Duration,
    /// Its loop's spin time, if it reports one.
    meter: Option<SpinMeter>,
}

impl BackoffIdle {
    /// A strategy that spins `max_spins` idle cycles, yields `max_yields`
    /// more, then sleeps from `min_sleep`, doubling up to `max_sleep`.
    #[must_use]
    pub fn new(max_spins: u32, max_yields: u32, min_sleep: Duration, max_sleep: Duration) -> Self {
        Self {
            max_spins,
            max_yields,
            min_sleep,
            max_sleep: max_sleep.max(min_sleep),
            spins: 0,
            yields: 0,
            sleep: min_sleep,
            meter: None,
        }
    }

    /// Reporting its spin time into `meter`, its loop's
    /// (`EmbeddedDriver::take_spin_meter` for the conductor's loop).
    #[must_use]
    pub fn with_spin_meter(mut self, meter: Option<SpinMeter>) -> Self {
        self.meter = meter;
        self
    }

    /// Called after each duty cycle with the work it did: resets on work,
    /// backs off one step otherwise.
    pub fn idle(&mut self, work: u32) {
        if work > 0 {
            self.reset();
        } else if self.spins < self.max_spins {
            self.spins += 1;
            if let Some(meter) = &mut self.meter {
                meter.spin();
            }
            std::hint::spin_loop();
        } else if self.yields < self.max_yields {
            self.end_spin_run();
            self.yields += 1;
            std::thread::yield_now();
        } else {
            self.end_spin_run();
            std::thread::sleep(self.sleep);
            self.sleep = self.sleep.saturating_mul(2).min(self.max_sleep);
        }
    }

    /// Ends the spin run going on, if any.
    fn end_spin_run(&mut self) {
        if let Some(meter) = &mut self.meter {
            meter.end_run();
        }
    }

    /// Back to spinning; a spin run going on ends.
    pub fn reset(&mut self) {
        self.end_spin_run();
        self.spins = 0;
        self.yields = 0;
        self.sleep = self.min_sleep;
    }

    /// The sleep of the next idle cycle once spinning and yielding are
    /// exhausted.
    #[must_use]
    pub fn next_sleep(&self) -> Duration {
        self.sleep
    }
}

impl Default for BackoffIdle {
    /// 100 spins, 10 yields, then sleeps from 1 µs to 1 ms.
    fn default() -> Self {
        Self::new(100, 10, Duration::from_micros(1), Duration::from_millis(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_cycles_back_off_to_the_bound_and_work_resets() {
        let mut idle = BackoffIdle::new(2, 1, Duration::from_nanos(1), Duration::from_nanos(4));
        // Two spins and one yield leave the sleep untouched.
        for _ in 0..3 {
            idle.idle(0);
            assert_eq!(idle.next_sleep(), Duration::from_nanos(1));
        }
        for expected in [2, 4, 4] {
            idle.idle(0);
            assert_eq!(idle.next_sleep(), Duration::from_nanos(expected));
        }
        idle.idle(1);
        assert_eq!(idle.next_sleep(), Duration::from_nanos(1));
        assert_eq!((idle.spins, idle.yields), (0, 0));
    }

    /// The value of the driver's `conductor spin time`.
    fn spin_time(driver: &karyos_driver::EmbeddedDriver) -> u64 {
        let reader = driver.counters();
        (0..reader.capacity())
            .find_map(|index| match reader.read(index) {
                karyos_sys::counters::CellRead::Allocated {
                    metadata, value, ..
                } if metadata.label() == b"conductor spin time" => {
                    assert_eq!(metadata.type_id, karyos_driver::counters::TYPE_SPIN_TIME);
                    Some(value)
                }
                _ => None,
            })
            .expect("the conductor spin time cell")
    }

    /// M5: a spinning backoff reports its spin runs in its loop's cell, and
    /// only once a run ends; yields and sleeps never count, so a backoff
    /// that does not spin reports 0 (the negative control).
    #[test]
    fn spin_runs_reach_the_loop_cell_and_yields_never_count() {
        let mut driver = karyos_driver::EmbeddedDriver::new().unwrap();
        let mut idle = BackoffIdle::new(100_000, 0, Duration::ZERO, Duration::ZERO)
            .with_spin_meter(driver.take_spin_meter());
        assert!(driver.take_spin_meter().is_none(), "taken once");
        for _ in 0..20_000 {
            idle.idle(0);
        }
        // Past the 1024-spin flushes, the run so far is stored; the rest
        // counts at the end of the run.
        let flushed = spin_time(&driver);
        assert!(flushed > 0);
        idle.idle(1);
        let ended = spin_time(&driver);
        assert!(ended >= flushed);
        idle.idle(1);
        assert_eq!(spin_time(&driver), ended, "no run, nothing added");

        let mut driver = karyos_driver::EmbeddedDriver::new().unwrap();
        let mut idle = BackoffIdle::new(0, 10, Duration::from_micros(1), Duration::from_micros(2))
            .with_spin_meter(driver.take_spin_meter());
        for _ in 0..50 {
            idle.idle(0);
        }
        idle.idle(1);
        assert_eq!(spin_time(&driver), 0);
    }

    #[test]
    fn the_bound_is_never_below_the_first_sleep() {
        let idle = BackoffIdle::new(0, 0, Duration::from_millis(2), Duration::from_millis(1));
        assert_eq!(idle.max_sleep, Duration::from_millis(2));
    }
}
