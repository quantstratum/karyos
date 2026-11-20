// SPDX-License-Identifier: Apache-2.0

//! Driver slots for this crate's tests (karyos#993).
//!
//! The driver table holds [`MAX_DRIVERS`] drivers per process, and the
//! tests of every module share it: run in parallel on a host with more
//! test threads than that, they would open a ninth driver at once and get
//! `KARYOS_E_HANDLES_EXHAUSTED` (300) where they expect their own answer.
//! A test that opens drivers first takes a [`Permit`] for as many as it
//! holds open at once, and keeps it until they are closed. A test that
//! fills the table on purpose takes all of them.

use std::sync::{Condvar, Mutex, PoisonError};

use crate::api::driver::MAX_DRIVERS;

/// Slots taken, and their change.
static TAKEN: Mutex<u32> = Mutex::new(0);
static FREED: Condvar = Condvar::new();

/// Slots of the driver table held by one test.
#[must_use = "the slots are released when the permit is dropped"]
pub(crate) struct Permit(u32);

impl Drop for Permit {
    fn drop(&mut self) {
        let mut taken = TAKEN.lock().unwrap_or_else(PoisonError::into_inner);
        *taken = taken.saturating_sub(self.0);
        FREED.notify_all();
    }
}

/// Waits for `count` free slots (at most [`MAX_DRIVERS`]) and holds them.
pub(crate) fn drivers(count: u32) -> Permit {
    let count = count.min(MAX_DRIVERS);
    let mut taken = TAKEN.lock().unwrap_or_else(PoisonError::into_inner);
    while taken.saturating_add(count) > MAX_DRIVERS {
        taken = FREED.wait(taken).unwrap_or_else(PoisonError::into_inner);
    }
    *taken = taken.saturating_add(count);
    Permit(count)
}

/// Every slot: for a test that fills the driver table.
pub(crate) fn all_drivers() -> Permit {
    drivers(MAX_DRIVERS)
}
