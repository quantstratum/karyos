// SPDX-License-Identifier: Apache-2.0

//! Pause points of the publication paths, for multi-process tests that
//! kill a writer at an exact step (`quantstratum-docs:
//! karyos/design/ipc-data-path.md`, Tests: a publisher "killed mid-offer",
//! "killed while updating its claim record" and "killed after reserving
//! across the term end"), and for Loom models that pin a thread at one
//! step (SPEC.md §13, Rotation helpers). Test hook only.
//!
//! A child process arms one point with a hook, then publishes; the first
//! time this process reaches the point, the hook runs there, typically
//! reporting to the parent and waiting to be killed. Disarmed points cost
//! one Relaxed load.
//!
//! Under Loom (`--cfg loom`) the module is compiled without the feature
//! and the armed point lives in a thread local: Loom runs every thread of
//! a model on the OS thread of its test, so a model arms only its own
//! executions and tests running in parallel never see each other's
//! points. A model arms its point at the start of every execution.

/// Where a publication path can pause.
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
    /// A rotation attempt (`loan::rotate_to`) activated the next term's
    /// descriptor and has not advanced the active count.
    RotationActivated = 4,
}

#[cfg(not(loom))]
mod armed {
    use super::PausePoint;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::{Mutex, PoisonError};

    /// The armed point, 0 for none.
    static ARMED: AtomicU8 = AtomicU8::new(0);
    /// The hook of the armed point.
    static HOOK: Mutex<Option<fn(PausePoint)>> = Mutex::new(None);

    pub(super) fn arm(point: PausePoint, hook: fn(PausePoint)) {
        *HOOK.lock().unwrap_or_else(PoisonError::into_inner) = Some(hook);
        ARMED.store(point as u8, Ordering::SeqCst);
    }

    #[inline]
    pub(super) fn take(point: PausePoint) -> Option<fn(PausePoint)> {
        if ARMED.load(Ordering::Relaxed) != point as u8 {
            return None;
        }
        ARMED.store(0, Ordering::SeqCst);
        HOOK.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

#[cfg(loom)]
mod armed {
    use super::PausePoint;
    use std::cell::Cell;

    /// An armed point and its hook.
    type Armed = Option<(PausePoint, fn(PausePoint))>;

    std::thread_local! {
        /// The armed point and its hook, for the models of this OS thread.
        static ARMED: Cell<Armed> = const { Cell::new(None) };
    }

    pub(super) fn arm(point: PausePoint, hook: fn(PausePoint)) {
        ARMED.with(|armed| armed.set(Some((point, hook))));
    }

    #[inline]
    pub(super) fn take(point: PausePoint) -> Option<fn(PausePoint)> {
        ARMED.with(|armed| match armed.get() {
            Some((armed_point, hook)) if armed_point == point => {
                armed.set(None);
                Some(hook)
            }
            _ => None,
        })
    }
}

/// Arms `point`: the first time this process (under Loom, this model's
/// OS thread) reaches it, `hook` runs there, once.
pub fn arm(point: PausePoint, hook: fn(PausePoint)) {
    armed::arm(point, hook);
}

/// The publication reached `point`.
#[inline]
pub(crate) fn reached(point: PausePoint) {
    if let Some(hook) = armed::take(point) {
        hook(point);
    }
}
