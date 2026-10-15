// SPDX-License-Identifier: Apache-2.0

//! Pause points of the exclusive publication, for multi-process tests that
//! kill a writer at an exact step (`quantstratum-docs:
//! karyos/design/ipc-data-path.md`, Tests: a publisher "killed mid-offer",
//! "killed while updating its claim record" and "killed after reserving
//! across the term end"). Test hook only.
//!
//! A child process arms one point with a hook, then publishes; the first
//! time this process reaches the point, the hook runs there, typically
//! reporting to the parent and waiting to be killed. Disarmed points cost
//! one Relaxed load.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, PoisonError};

/// Where the exclusive publication can pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PausePoint {
    /// An append reserved its block (the reserved head is published) and
    /// has written none of it.
    ExclusiveReserved = 1,
    /// The claim record's serial is odd: its update is half done.
    ClaimRecordOdd = 2,
    /// An append reserved the rest of the term up to its end (the reserved
    /// head is the term boundary) and has written no `PAD`.
    TermEndReserved = 3,
}

/// The armed point, 0 for none.
static ARMED: AtomicU8 = AtomicU8::new(0);
/// The hook of the armed point.
static HOOK: Mutex<Option<fn(PausePoint)>> = Mutex::new(None);

/// Arms `point`: the first time this process reaches it, `hook` runs there,
/// once.
pub fn arm(point: PausePoint, hook: fn(PausePoint)) {
    *HOOK.lock().unwrap_or_else(PoisonError::into_inner) = Some(hook);
    ARMED.store(point as u8, Ordering::SeqCst);
}

/// The publication reached `point`.
#[inline]
pub(crate) fn reached(point: PausePoint) {
    if ARMED.load(Ordering::Relaxed) != point as u8 {
        return;
    }
    ARMED.store(0, Ordering::SeqCst);
    let hook = HOOK.lock().unwrap_or_else(PoisonError::into_inner).take();
    if let Some(hook) = hook {
        hook(point);
    }
}
