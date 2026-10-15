// SPDX-License-Identifier: Apache-2.0

//! Client counters (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Client counters"): a cell of
//! the driver's client counters region that the driver allocated for this
//! client with `AllocateCounter`, and the release of that cell.
//!
//! A [`ClientCounterHandle`] writes its cell with checked Relaxed
//! increments and swaps. [`ClientCounterHandle::release`], or dropping the
//! handle, makes no further access and queues the release in the client's
//! [`CounterReleases`]; the client conductor drains that queue on its next
//! poll and sends `ReleaseCounter`, which the driver serves only from the
//! owning client for the exact allocation. Command records are published
//! with Release and consumed with Acquire, so the driver observes every
//! access made before the release.
//!
//! Memory safety never depends on the drop: a forgotten handle keeps its
//! cell charged to the client. The driver frees the cells left when the
//! client's slot is removed after its exit proof (its close flag), and, for
//! an in-process client, only once no handle of it is alive
//! ([`CounterReleases::live`]), because a handle can outlive its conductor.
//! A handle of a client process keeps the admission session, so `Leave` is
//! not sent while it lives.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use karyos_sys::counters::{ClientCounter, CounterError};

/// One queued release: the cell and the allocation's registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Release {
    pub(crate) cell: u64,
    pub(crate) registration: u64,
}

/// The releases a client's counter handles queued for its conductor, and
/// the number of those handles alive. Shared by the conductor, its handles
/// and, through the [`ClientLink`](crate::link::ClientLink), an in-process
/// driver. The queue holds at most one entry per handle ever delivered and
/// not yet sent, so it is bounded by the counters the driver allocated for
/// the client (`max_counters_per_client`).
#[derive(Debug, Default)]
pub struct CounterReleases {
    queue: Mutex<VecDeque<Release>>,
    live: AtomicU64,
}

impl CounterReleases {
    fn queue(&self) -> MutexGuard<'_, VecDeque<Release>> {
        // Every critical section is a single push or pop, so a panic
        // elsewhere cannot leave the queue half updated.
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counter handles of this client alive (Acquire): after the client's
    /// close flag, 0 proves that none of them can access its cell again.
    #[must_use]
    pub fn live(&self) -> u64 {
        self.live.load(Ordering::Acquire)
    }

    /// Releases queued and not yet sent.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue().len()
    }

    pub(crate) fn pop(&self) -> Option<Release> {
        self.queue().pop_front()
    }

    /// Puts back a release that could not be sent yet, first in line.
    pub(crate) fn unpop(&self, release: Release) {
        self.queue().push_front(release);
    }
}

/// The application's capability to update one client counter (not
/// `Clone`; share it by reference). Dropping it releases the cell, as
/// [`ClientCounterHandle::release`] does.
#[derive(Debug)]
pub struct ClientCounterHandle {
    /// The cell's writer; its fields are dropped in this order, so the
    /// mapping it keeps goes before the session below.
    inner: ClientCounter,
    releases: Arc<CounterReleases>,
    /// A client process's admission session, kept so that `Leave` is not
    /// sent while this handle lives; `None` in process.
    _session: Option<Arc<dyn core::any::Any + Send + Sync>>,
}

impl ClientCounterHandle {
    /// Wraps `inner`, counted alive in `releases` until dropped.
    pub(crate) fn new(
        inner: ClientCounter,
        releases: Arc<CounterReleases>,
        session: Option<Arc<dyn core::any::Any + Send + Sync>>,
    ) -> Self {
        // Ordered before the conductor's close flag (Release) and observed
        // by the driver after it (Acquire).
        releases.live.fetch_add(1, Ordering::Release);
        Self {
            inner,
            releases,
            _session: session,
        }
    }

    /// The cell in the client counters region.
    #[must_use]
    pub fn cell(&self) -> usize {
        self.inner.cell()
    }

    /// The allocation's registration.
    #[must_use]
    pub fn registration(&self) -> u64 {
        self.inner.registration()
    }

    /// Adds `delta` with a checked Relaxed read-modify-write; never wraps
    /// or saturates.
    ///
    /// # Errors
    ///
    /// Returns [`CounterError::Overflow`], leaving the value unchanged,
    /// when the sum exceeds `u64::MAX`.
    pub fn increment(&self, delta: u64) -> Result<u64, CounterError> {
        self.inner.increment(delta)
    }

    /// Sets the value with a Relaxed swap (gauges).
    pub fn set(&self, value: u64) {
        self.inner.set(value);
    }

    /// Releases the cell: consumes the capability, which makes no further
    /// access, and hands the release to the client conductor, which sends
    /// `ReleaseCounter` on its next poll. Same as dropping the handle.
    pub fn release(self) {
        drop(self);
    }
}

impl Drop for ClientCounterHandle {
    fn drop(&mut self) {
        let release = Release {
            cell: self.inner.cell() as u64,
            registration: self.inner.registration(),
        };
        self.releases.queue().push_back(release);
        // Every access of this handle happened before: an in-process driver
        // that reads 0 after the close flag may free the cell.
        self.releases.live.fetch_sub(1, Ordering::Release);
    }
}
