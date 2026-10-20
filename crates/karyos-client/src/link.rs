// SPDX-License-Identifier: Apache-2.0

//! State shared by a client conductor and its driver registration in
//! embedded mode (quantstratum-docs: karyos/design/client-commands.md): the close flag, the
//! hand-over table, the capability leases that keep a stream charged
//! while any of its capabilities lives, the client's counter releases and
//! its subscriptions' loss reports. The table also holds the writers of the
//! trace journals the driver created for the client (`quantstratum-docs:
//! karyos/design/trace-journal-region.md`) until the client takes them.
//!
//! The hand-over table is control-path state behind a mutex; the data path
//! never touches it. Crossing processes replaces these mechanisms under
//! ADR-0045.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use karyos_sys::conflation::ConflationConfig;
use karyos_sys::log_buffer::{ConcurrentPublication, LogBuffer, Publication, Subscription};
use karyos_sys::record_journal::JournalWriter;
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use karyos_protocol::trace_hook::PublicationIdentity;

use crate::counter::CounterReleases;
use crate::generation::GenerationLink;
use crate::loss::LossReports;

/// Who issued a capability: the driver instance and the client id. A handle
/// can be removed only through the conductor with the same owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Owner {
    /// The driver instance.
    pub driver: u64,
    /// The client id within that driver.
    pub client: u64,
}

impl Owner {
    /// Client `client` of driver instance `driver`.
    #[must_use]
    pub const fn new(driver: u64, client: u64) -> Self {
        Self { driver, client }
    }
}

/// Where a handed-over handle came from: its owner, its registration and
/// its lease. Dropping the handle ends the lease.
#[derive(Debug)]
pub struct Origin {
    pub(crate) owner: Owner,
    pub(crate) registration: u64,
    pub(crate) lease: Lease,
}

impl Origin {
    /// The owning client.
    #[must_use]
    pub fn owner(&self) -> Owner {
        self.owner
    }

    /// The registration id.
    #[must_use]
    pub fn registration(&self) -> u64 {
        self.registration
    }
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

const LEASE_ALIVE: u8 = 0;
const LEASE_DROPPED: u8 = 1;
const LEASE_REMOVING: u8 = 2;

/// How a registration's lease ended, so the driver knows whether to forget
/// the registration now or wait for its queued `Remove`.
#[derive(Debug, Default)]
pub struct LeaseEnd {
    state: AtomicU8,
}

/// The observed state of a [`LeaseEnd`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseState {
    /// The capability is alive (held for hand-over or in a handle).
    Alive,
    /// The capability was dropped without `remove`: no `Remove` will come.
    Dropped,
    /// The handle was dropped by `remove` after its `Remove` was written:
    /// the registration ends when that command is served.
    Removing,
}

impl LeaseEnd {
    /// The current state (Acquire).
    #[must_use]
    pub fn state(&self) -> LeaseState {
        match self.state.load(Ordering::Acquire) {
            LEASE_ALIVE => LeaseState::Alive,
            LEASE_REMOVING => LeaseState::Removing,
            _ => LeaseState::Dropped,
        }
    }
}

/// One capability lease; dropping it ends the lease (Release): the stream's
/// count drops and the registration's end state becomes `Dropped`, unless
/// the client conductor marked it `Removing` after writing its `Remove`.
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

impl Lease {
    /// Records that a `Remove` for this registration was written, before
    /// the handle holding this lease is dropped (Release). Only the client
    /// conductor calls this, after a successful write, so no caller can
    /// keep a registration alive without a queued `Remove`.
    pub(crate) fn mark_removing(&self) {
        self.end.state.store(LEASE_REMOVING, Ordering::Release);
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.leases.live.fetch_sub(1, Ordering::Release);
        // Keep `Removing` if it was set; otherwise the lease was dropped.
        let _ = self.end.state.compare_exchange(
            LEASE_ALIVE,
            LEASE_DROPPED,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }
}

/// The export of a handle adopted from another process's grant
/// (`quantstratum-docs: karyos/design/ipc-data-path.md`, The client): kept
/// as the handle's last field, so it is dropped after the handle's mapping,
/// and its drop sends the grant's `Detach`.
#[derive(Debug)]
pub struct Export {
    /// Held only for its drop.
    _detach: Box<dyn core::any::Any + Send + Sync>,
}

impl Export {
    /// Wraps the value whose drop detaches the grant.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn new(detach: impl core::any::Any + Send + Sync) -> Self {
        Self {
            _detach: Box::new(detach),
        }
    }
}

/// A capability created by the driver for a registration.
///
/// Not `#[non_exhaustive]`: the driver matches every kind when it joins a
/// member, where a kind it did not know could not be handled; a contract
/// between the driver and the client crates (quantstratum-docs:
/// `karyos/testing/public-api-audit-alpha2.md`).
#[derive(Debug)]
pub enum Capability<T: TermBytes = HeapTerms> {
    /// A stream's exclusive publication.
    Publication {
        /// The log buffer capability.
        inner: Publication<Arc<LogBuffer<T>>>,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
    },
    /// A concurrent publication handle: one of the stream's publisher
    /// slots, held until the handle or the entry is dropped.
    ConcurrentPublication {
        /// The log buffer capability.
        inner: ConcurrentPublication<Arc<LogBuffer<T>>>,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
    },
    /// An admitted subscriber.
    Subscription(Subscription<Arc<LogBuffer<T>>>),
}

/// A capability with its lease and owner, waiting in the hand-over table.
#[derive(Debug)]
#[non_exhaustive]
pub struct HandOverEntry<T: TermBytes = HeapTerms> {
    /// The hand-over key from the response.
    pub key: u64,
    /// The capability.
    pub capability: Capability<T>,
    /// Its lease.
    pub lease: Lease,
    /// The generation link and base the delivered handle starts with
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`), when the driver keeps one.
    pub generation: Option<(Arc<GenerationLink<T>>, u64)>,
    /// The stream's full publication identity, with which a subscription
    /// reports its overruns (`quantstratum-docs:
    /// karyos/design/observability-and-tools.md`, "Loss reports from
    /// clients"); `None` reports nothing.
    pub publication: Option<PublicationIdentity>,
    /// The stream's conflation table shape, which a delivered publication
    /// checks its keys against before it appends
    /// (`quantstratum-docs: karyos/design/conflation-end-to-end.md`);
    /// `None` checks nothing.
    pub conflation: Option<ConflationConfig>,
}

impl<T: TermBytes> HandOverEntry<T> {
    /// The entry of hand-over `key` for `capability` and its `lease`,
    /// with no generation link, no publication identity and no conflation
    /// table: add them with [`HandOverEntry::with_generation`],
    /// [`HandOverEntry::with_publication`] and
    /// [`HandOverEntry::with_conflation`].
    #[must_use]
    pub const fn new(key: u64, capability: Capability<T>, lease: Lease) -> Self {
        Self {
            key,
            capability,
            lease,
            generation: None,
            publication: None,
            conflation: None,
        }
    }

    /// The generation link and base the delivered handle starts with,
    /// when the driver keeps one.
    #[must_use]
    pub fn with_generation(mut self, generation: Option<(Arc<GenerationLink<T>>, u64)>) -> Self {
        self.generation = generation;
        self
    }

    /// The stream's publication identity, for its overrun reports.
    #[must_use]
    pub const fn with_publication(mut self, publication: PublicationIdentity) -> Self {
        self.publication = Some(publication);
        self
    }

    /// The stream's conflation table shape, when the stream has one: a
    /// delivered publication refuses a key outside it.
    #[must_use]
    pub const fn with_conflation(mut self, conflation: Option<ConflationConfig>) -> Self {
        self.conflation = conflation;
        self
    }
}

#[derive(Debug)]
struct HandOver<T: TermBytes = HeapTerms> {
    entries: Vec<HandOverEntry<T>>,
    /// Trace journal writers by hand-over key. Dropping one closes its
    /// journal, which the driver then drains to its end.
    journals: Vec<(u64, JournalWriter)>,
    /// Set when the driver is dropped: takes fail from then on.
    driver_gone: bool,
}

/// State shared by one client conductor and its driver registration.
#[derive(Debug)]
pub struct ClientLink<T: TermBytes = HeapTerms> {
    closed: AtomicBool,
    hand_over: Mutex<HandOver<T>>,
    /// The client's counter handles: their queued releases and how many
    /// are alive.
    counters: Arc<CounterReleases>,
    /// The loss reports of the client's subscriptions.
    losses: Arc<LossReports>,
}

/// Why a hand-over put or take failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandOverError {
    /// The driver is gone or the entry was dropped.
    Closed,
}

impl<T: TermBytes> Default for ClientLink<T> {
    fn default() -> Self {
        Self {
            closed: AtomicBool::new(false),
            hand_over: Mutex::new(HandOver {
                entries: Vec::new(),
                journals: Vec::new(),
                driver_gone: false,
            }),
            counters: Arc::new(CounterReleases::default()),
            losses: Arc::new(LossReports::default()),
        }
    }
}

impl<T: TermBytes> ClientLink<T> {
    /// A new link.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn table(&self) -> MutexGuard<'_, HandOver<T>> {
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

    /// The client's counter releases and live counter handles
    /// (`quantstratum-docs: karyos/design/observability-and-tools.md`,
    /// "Client counters").
    #[must_use]
    pub fn counter_releases(&self) -> &Arc<CounterReleases> {
        &self.counters
    }

    /// The loss reports the client's subscriptions queued for its
    /// conductor (`quantstratum-docs:
    /// karyos/design/observability-and-tools.md`, "Loss reports from
    /// clients").
    #[must_use]
    pub fn loss_reports(&self) -> &Arc<LossReports> {
        &self.losses
    }

    /// Driver side: holds `entry` for the client (`Held`).
    pub fn hold(&self, entry: HandOverEntry<T>) {
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

    /// Driver side: drops every `Held` entry and journal writer; with
    /// `driver_gone`, later takes fail with [`HandOverError::Closed`].
    pub fn drop_all(&self, driver_gone: bool) {
        let (entries, journals) = {
            let mut table = self.table();
            table.driver_gone |= driver_gone;
            (
                core::mem::take(&mut table.entries),
                core::mem::take(&mut table.journals),
            )
        };
        drop(entries);
        drop(journals);
    }

    /// Driver side: holds the writer of a trace journal under `key`.
    pub fn hold_journal(&self, key: u64, writer: JournalWriter) {
        self.table().journals.push((key, writer));
    }

    /// Client side: takes the trace journal writer held under `key`,
    /// exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`HandOverError::Closed`] if the driver is gone or no writer
    /// is held under `key`.
    pub fn take_journal(&self, key: u64) -> Result<JournalWriter, HandOverError> {
        let mut table = self.table();
        if table.driver_gone {
            return Err(HandOverError::Closed);
        }
        let index = table
            .journals
            .iter()
            .position(|(held, _)| *held == key)
            .ok_or(HandOverError::Closed)?;
        Ok(table.journals.swap_remove(index).1)
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
    pub fn take(&self, key: u64) -> Result<HandOverEntry<T>, HandOverError> {
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
