// SPDX-License-Identifier: Apache-2.0

//! State shared by a client conductor and its driver registration in
//! embedded mode (quantstratum-docs: karyos/design/client-commands.md): the close flag, the
//! hand-over table, and the capability leases that keep a stream charged
//! while any of its capabilities lives.
//!
//! The hand-over table is control-path state behind a mutex; the data path
//! never touches it. Crossing processes replaces these mechanisms under
//! ADR-0045.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use karyos_sys::log_buffer::{LogBuffer, Publication, Subscription};

/// Who issued a capability: the driver instance and the client id. A handle
/// can be removed only through the conductor with the same owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Owner {
    /// The driver instance.
    pub driver: u64,
    /// The client id within that driver.
    pub client: u64,
}

/// Where a handed-over handle came from: its owner, its registration and
/// its lease. Dropping the handle ends the lease.
#[derive(Debug)]
pub struct Origin {
    /// The owning client.
    pub owner: Owner,
    /// The registration id.
    pub registration: u64,
    /// The stream lease.
    pub lease: Lease,
}

/// Live capability leases of one stream.
#[derive(Debug, Default)]
pub struct StreamLeases {
    live: AtomicU64,
}

impl StreamLeases {
    /// Number of live leases (Acquire): capabilities held for hand-over or
    /// owned by handles.
    #[must_use]
    pub fn live(&self) -> u64 {
        self.live.load(Ordering::Acquire)
    }
}

/// Set when a registration's capability is gone (its lease ended), so the
/// driver can forget the registration.
#[derive(Debug, Default)]
pub struct LeaseEnd {
    ended: AtomicBool,
}

impl LeaseEnd {
    /// Whether the lease ended (Acquire).
    #[must_use]
    pub fn ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }
}

/// One capability lease; dropping it ends the lease (Release): the stream's
/// count drops and the registration's end flag is set.
#[derive(Debug)]
pub struct Lease {
    leases: Arc<StreamLeases>,
    end: Arc<LeaseEnd>,
}

impl Lease {
    /// Starts a lease on `leases` for one registration, whose end is
    /// reported through `end`. Called by the driver when it creates a
    /// capability.
    #[must_use]
    pub fn acquire(leases: &Arc<StreamLeases>, end: &Arc<LeaseEnd>) -> Self {
        // A lease count cannot reach u64::MAX: each lease is a live object.
        leases.live.fetch_add(1, Ordering::Relaxed);
        Self {
            leases: Arc::clone(leases),
            end: Arc::clone(end),
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.leases.live.fetch_sub(1, Ordering::Release);
        self.end.ended.store(true, Ordering::Release);
    }
}

/// A capability created by the driver for a registration.
#[derive(Debug)]
pub enum Capability {
    /// A stream's exclusive publication.
    Publication {
        /// The log buffer capability.
        inner: Publication<Arc<LogBuffer>>,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
    },
    /// An admitted subscriber.
    Subscription(Subscription<Arc<LogBuffer>>),
}

/// A capability with its lease and owner, waiting in the hand-over table.
#[derive(Debug)]
pub struct HandOverEntry {
    /// The hand-over key from the response.
    pub key: u64,
    /// The capability.
    pub capability: Capability,
    /// Its lease.
    pub lease: Lease,
}

#[derive(Debug, Default)]
struct HandOver {
    entries: Vec<HandOverEntry>,
    /// Set when the driver is dropped: takes fail from then on.
    driver_gone: bool,
}

/// State shared by one client conductor and its driver registration.
#[derive(Debug, Default)]
pub struct ClientLink {
    closed: AtomicBool,
    hand_over: Mutex<HandOver>,
}

/// Why a hand-over put or take failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandOverError {
    /// The driver is gone or the entry was dropped.
    Closed,
}

impl ClientLink {
    /// A new link.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn table(&self) -> MutexGuard<'_, HandOver> {
        // Every critical section is a single push, remove or clear, so a
        // panic elsewhere cannot leave the table half updated.
        self.hand_over
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Marks the client closed (Release). The client conductor calls this
    /// only after dropping its command ring producer.
    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Whether the client closed (Acquire).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Driver side: holds `entry` for the client (`Held`).
    pub fn hold(&self, entry: HandOverEntry) {
        self.table().entries.push(entry);
    }

    /// Driver side: number of `Held` entries.
    #[must_use]
    pub fn held(&self) -> usize {
        self.table().entries.len()
    }

    /// Driver side: drops the entry with `key` if still `Held` (`Dropped`);
    /// returns whether one was dropped.
    pub fn drop_entry(&self, key: u64) -> bool {
        let entry = {
            let mut table = self.table();
            let index = table.entries.iter().position(|entry| entry.key == key);
            index.map(|index| table.entries.swap_remove(index))
        };
        entry.is_some()
    }

    /// Driver side: drops every `Held` entry; with `driver_gone`, later takes
    /// fail with [`HandOverError::Closed`].
    pub fn drop_all(&self, driver_gone: bool) {
        let entries = {
            let mut table = self.table();
            table.driver_gone |= driver_gone;
            core::mem::take(&mut table.entries)
        };
        drop(entries);
    }

    /// Whether the driver was dropped.
    #[must_use]
    pub fn driver_gone(&self) -> bool {
        self.table().driver_gone
    }

    /// Client side: takes the entry with `key` (`Taken`), exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`HandOverError::Closed`] if the driver is gone or the entry
    /// is missing or was dropped.
    pub fn take(&self, key: u64) -> Result<HandOverEntry, HandOverError> {
        let mut table = self.table();
        if table.driver_gone {
            return Err(HandOverError::Closed);
        }
        let index = table
            .entries
            .iter()
            .position(|entry| entry.key == key)
            .ok_or(HandOverError::Closed)?;
        Ok(table.entries.swap_remove(index))
    }
}
