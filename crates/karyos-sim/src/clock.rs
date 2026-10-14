// SPDX-License-Identifier: Apache-2.0

//! Virtual time: the driver's clock, advanced only by the scheduler.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_driver::MonotonicClock;

/// A clock whose time only the simulator advances. Clones share it.
#[derive(Debug, Clone, Default)]
pub struct SimClock {
    now: Arc<AtomicU64>,
}

impl SimClock {
    /// The current virtual time.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }

    /// Advances virtual time by `by`, saturating.
    pub fn advance(&self, by: u64) {
        let now = self.get().saturating_add(by);
        self.now.store(now, Ordering::Relaxed);
    }
}

impl MonotonicClock for SimClock {
    fn now(&mut self) -> u64 {
        self.get()
    }
}
