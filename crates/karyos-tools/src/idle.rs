// SPDX-License-Identifier: Apache-2.0

//! A backoff idle strategy for a duty-cycle loop (SPEC.md §2, principle 9):
//! after a cycle with work it returns at once; after consecutive idle
//! cycles it spins, then yields, then sleeps with a doubling period up to a
//! bound. A cycle with work resets it.

use std::time::Duration;

/// Spins, yields, then sleeps up to a bound while no work is done.
#[derive(Debug, Clone)]
pub struct BackoffIdle {
    max_spins: u32,
    max_yields: u32,
    min_sleep: Duration,
    max_sleep: Duration,
    spins: u32,
    yields: u32,
    sleep: Duration,
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
        }
    }

    /// Called after each duty cycle with the work it did: resets on work,
    /// backs off one step otherwise.
    pub fn idle(&mut self, work: u32) {
        if work > 0 {
            self.reset();
        } else if self.spins < self.max_spins {
            self.spins += 1;
            std::hint::spin_loop();
        } else if self.yields < self.max_yields {
            self.yields += 1;
            std::thread::yield_now();
        } else {
            std::thread::sleep(self.sleep);
            self.sleep = self.sleep.saturating_mul(2).min(self.max_sleep);
        }
    }

    /// Back to spinning.
    pub fn reset(&mut self) {
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

    #[test]
    fn the_bound_is_never_below_the_first_sleep() {
        let idle = BackoffIdle::new(0, 0, Duration::from_millis(2), Duration::from_millis(1));
        assert_eq!(idle.max_sleep, Duration::from_millis(2));
    }
}
