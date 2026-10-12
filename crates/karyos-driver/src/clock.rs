// SPDX-License-Identifier: Apache-2.0

//! The driver's injectable monotonic clock (SPEC.md principle 7), used for
//! the commit deadline of claims (`quantstratum-docs: karyos/design/client-claims.md`).

use std::time::Instant;

/// A monotonic clock in ticks, nanoseconds by convention. The driver reads
/// it only when a claim's deadline needs the time.
pub trait MonotonicClock: Send + core::fmt::Debug {
    /// The current time.
    fn now(&mut self) -> u64;
}

/// The system's monotonic clock: nanoseconds since the clock was created.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// A clock starting at zero now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemClock {
    /// Nanoseconds since creation; after about 584 years, when they no
    /// longer fit, the last representable tick, which never makes an abort
    /// earlier.
    fn now(&mut self) -> u64 {
        u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}
