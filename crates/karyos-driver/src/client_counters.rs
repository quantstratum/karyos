// SPDX-License-Identifier: Apache-2.0

//! The client counters region and its owner table (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Client counters").
//!
//! The driver is the region's single allocator. Each cell it allocates for
//! a client's `AllocateCounter` is recorded with that client as its owner,
//! and the driver keeps the cell's [`Counter`] capability, so the cell is
//! never reused while the entry exists. An entry ends only:
//!
//! - on the owner's `ReleaseCounter` for that exact allocation, which the
//!   client sends after its handle made its last access; or
//! - when the owner's slot is removed after its exit proof (its close
//!   flag: the client process exited or sent `Leave`, or an in-process
//!   client dropped its conductor), and, for an in-process client, once no
//!   counter handle of it is alive, since a handle can outlive its
//!   conductor.
//!
//! A timeout, a protocol violation or `stop_serving` frees nothing.

use std::sync::Arc;

use karyos_client::CounterReleases;
use karyos_sys::counters::{
    ClientCells, Counter, CounterError, CounterKeys, CountersManager, CountersReader,
};

use crate::error::DriverError;

/// One allocated cell and its owner.
#[derive(Debug)]
struct Owned {
    client: u64,
    counter: Counter,
    /// Whether the cell names a trace point (type id 8).
    point: bool,
}

/// The highest application trace point id (R-CORE-1): ids are `u16`.
const MAX_TRACE_POINT_ID: u32 = u16::MAX as u32;

/// The cells of a removed in-process client with counter handles still
/// alive: freed once none is.
#[derive(Debug)]
struct Orphans {
    client: u64,
    releases: Arc<CounterReleases>,
    counters: Vec<Counter>,
}

/// Why an allocation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The client holds `max_counters_per_client` cells.
    ClientLimit,
    /// No cell is free.
    Exhausted,
    /// Registration ids or a cell's version would wrap.
    IdentitiesExhausted,
    /// The client holds `max_trace_points_per_client` trace points.
    TracePointLimit,
    /// The client made `max_trace_point_registrations_per_client`
    /// registrations over its life.
    TracePointRegistrations,
    /// The instance assigned every trace point id.
    TracePointIdsExhausted,
}

/// The client counters region and who owns each allocated cell.
#[derive(Debug)]
pub(crate) struct ClientCounters {
    manager: CountersManager,
    reader: CountersReader,
    cells: ClientCells,
    owned: Vec<Owned>,
    orphans: Vec<Orphans>,
    max_per_client: usize,
    /// The next trace point id to assign: never reused within the
    /// instance, past [`MAX_TRACE_POINT_ID`] when all are used.
    next_point: u32,
    /// Trace point registrations per client over its life, live or not;
    /// a client's entry goes with its slot.
    point_registrations: Vec<(u64, usize)>,
    max_points_per_client: usize,
    max_point_registrations: usize,
}

impl ClientCounters {
    /// A heap region of `capacity` cells (embedded mode).
    pub(crate) fn new(capacity: usize, max_per_client: usize) -> Result<Self, DriverError> {
        let (manager, reader, cells) = karyos_sys::counters::client_counters(capacity)?;
        Ok(Self::from_parts(manager, reader, cells, max_per_client))
    }

    /// A shared region of `capacity` cells (IPC mode), which clients map
    /// writable.
    #[cfg(target_os = "linux")]
    pub(crate) fn new_in(
        instance: u128,
        region: u64,
        capacity: usize,
        max_per_client: usize,
    ) -> Result<Self, DriverError> {
        let (manager, reader, cells) =
            karyos_sys::counters::client_counters_in(instance, region, capacity)?;
        Ok(Self::from_parts(manager, reader, cells, max_per_client))
    }

    fn from_parts(
        manager: CountersManager,
        reader: CountersReader,
        cells: ClientCells,
        max_per_client: usize,
    ) -> Self {
        Self {
            manager,
            reader,
            cells,
            owned: Vec::new(),
            orphans: Vec::new(),
            max_per_client,
            next_point: 1,
            point_registrations: Vec::new(),
            max_points_per_client: usize::MAX,
            max_point_registrations: usize::MAX,
        }
    }

    /// The same, with the trace point bounds per client: live points and
    /// registrations over a client's life.
    #[must_use]
    pub(crate) fn with_trace_points(mut self, live: usize, registrations: usize) -> Self {
        self.max_points_per_client = live;
        self.max_point_registrations = registrations;
        self
    }

    /// Sets the next trace point id, to reach exhaustion in tests.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn set_next_trace_point(&mut self, next: u32) {
        self.next_point = next;
    }

    /// The writer view an in-process client shares.
    pub(crate) fn cells(&self) -> ClientCells {
        self.cells.clone()
    }

    /// A read-only view for tools.
    pub(crate) fn reader(&self) -> CountersReader {
        self.reader.clone()
    }

    /// The shared region, in IPC mode.
    #[cfg(target_os = "linux")]
    pub(crate) fn region(&self) -> Option<&karyos_sys::ipc::Region> {
        self.reader.region()
    }

    /// Cells owned by `client`, those awaiting its last handle included;
    /// `None` if the count does not fit `usize` (checked, SPEC.md §14),
    /// which an allocation treats as over the limit.
    pub(crate) fn owned_by(&self, client: u64) -> Option<usize> {
        let owned = self
            .owned
            .iter()
            .filter(|owned| owned.client == client)
            .count();
        self.orphans
            .iter()
            .filter(|orphans| orphans.client == client)
            .try_fold(owned, |sum, orphans| {
                sum.checked_add(orphans.counters.len())
            })
    }

    /// Allocates a cell for `client` with `keys`; returns the cell and the
    /// allocation's registration. Nothing changes on a refusal.
    pub(crate) fn allocate(
        &mut self,
        client: u64,
        type_id: u64,
        label: &str,
        keys: CounterKeys,
    ) -> Result<(usize, u64), Refusal> {
        self.allocate_with(client, type_id, label, keys, 0)
    }

    /// As [`ClientCounters::allocate`], the cell published with `value`.
    fn allocate_with(
        &mut self,
        client: u64,
        type_id: u64,
        label: &str,
        keys: CounterKeys,
        value: u64,
    ) -> Result<(usize, u64), Refusal> {
        if self
            .owned_by(client)
            .is_none_or(|owned| owned >= self.max_per_client)
        {
            return Err(Refusal::ClientLimit);
        }
        // Clients can write the state words, so the driver's own record of
        // the cells it still holds decides, never the region: a clobbered
        // state word cannot hand a held cell to a second owner.
        let held: Vec<usize> = self
            .owned
            .iter()
            .map(|owned| owned.counter.index())
            .chain(
                self.orphans
                    .iter()
                    .flat_map(|orphans| orphans.counters.iter().map(Counter::index)),
            )
            .collect();
        let counter = self
            .manager
            .allocate_valued_where(type_id, label, keys, value, |index| !held.contains(&index))
            .map_err(|error| match error {
                CounterError::Exhausted => Refusal::Exhausted,
                // The protocol bounds labels to the cell's; the remaining
                // errors are identity exhaustion.
                _ => Refusal::IdentitiesExhausted,
            })?;
        let allocated = (counter.index(), counter.registration_id());
        self.owned.push(Owned {
            client,
            counter,
            point: false,
        });
        Ok(allocated)
    }

    /// Allocates a trace point's cell for `client` (type id 8, keyed to the
    /// client): assigns the next id of the instance and publishes it as the
    /// cell's value with the cell. Returns the cell, the allocation's
    /// registration and the id. Nothing changes on a refusal, the id
    /// included.
    pub(crate) fn allocate_point(
        &mut self,
        client: u64,
        label: &str,
        keys: CounterKeys,
    ) -> Result<(usize, u64, u16), Refusal> {
        let live = self
            .owned
            .iter()
            .filter(|owned| owned.client == client && owned.point)
            .count();
        if live >= self.max_points_per_client {
            return Err(Refusal::TracePointLimit);
        }
        let registered = self
            .point_registrations
            .iter()
            .find(|(owner, _)| *owner == client)
            .map_or(0, |(_, count)| *count);
        if registered >= self.max_point_registrations {
            return Err(Refusal::TracePointRegistrations);
        }
        let Some(id) = u16::try_from(self.next_point)
            .ok()
            .filter(|_| self.next_point <= MAX_TRACE_POINT_ID)
        else {
            return Err(Refusal::TracePointIdsExhausted);
        };
        let (cell, registration) = self.allocate_with(
            client,
            karyos_sys::counters::TYPE_TRACE_POINT,
            label,
            keys,
            u64::from(id),
        )?;
        if let Some(owned) = self.owned.last_mut() {
            owned.point = true;
        }
        self.next_point += 1;
        match self
            .point_registrations
            .iter_mut()
            .find(|(owner, _)| *owner == client)
        {
            Some((_, count)) => *count += 1,
            None => self.point_registrations.push((client, 1)),
        }
        Ok((cell, registration, id))
    }

    /// Writes `value` into allocation `registration`'s cell, as a client
    /// can write its own cells.
    #[cfg(test)]
    pub(crate) fn overwrite(&self, registration: u64, value: u64) {
        if let Some(owned) = self
            .owned
            .iter()
            .find(|owned| owned.counter.registration_id() == registration)
        {
            owned.counter.set(value);
        }
    }

    /// Whether `client` still holds the trace point allocated as
    /// `registration`.
    pub(crate) fn holds_point(&self, client: u64, registration: u64) -> bool {
        self.owned.iter().any(|owned| {
            owned.point && owned.client == client && owned.counter.registration_id() == registration
        })
    }

    /// Frees `client`'s allocation `registration` in `cell` (its
    /// `ReleaseCounter`); `false`, freeing nothing, unless the client owns
    /// exactly that allocation.
    pub(crate) fn release(&mut self, client: u64, cell: u64, registration: u64) -> bool {
        let found = self.owned.iter().position(|owned| {
            owned.client == client
                && owned.counter.registration_id() == registration
                && u64::try_from(owned.counter.index()).is_ok_and(|index| index == cell)
        });
        let Some(index) = found else {
            return false;
        };
        let owned = self.owned.swap_remove(index);
        self.free(owned.counter);
        true
    }

    /// The slot of `client` was removed after its exit proof: frees its
    /// cells now when no counter handle of it is alive in this process,
    /// otherwise once none is ([`ClientCounters::free_orphans`]).
    pub(crate) fn client_removed(&mut self, client: u64, releases: &Arc<CounterReleases>) {
        self.point_registrations
            .retain(|(owner, _)| *owner != client);
        let mut counters = Vec::new();
        let mut index = 0;
        while let Some(owned) = self.owned.get(index) {
            if owned.client == client {
                counters.push(self.owned.swap_remove(index).counter);
            } else {
                index += 1;
            }
        }
        if counters.is_empty() {
            return;
        }
        self.orphans.push(Orphans {
            client,
            releases: Arc::clone(releases),
            counters,
        });
        self.free_orphans();
    }

    /// Frees the cells of removed clients whose last counter handle is
    /// gone.
    pub(crate) fn free_orphans(&mut self) {
        let mut index = 0;
        while let Some(orphans) = self.orphans.get(index) {
            if orphans.releases.live() == 0 {
                let orphans = self.orphans.swap_remove(index);
                for counter in orphans.counters {
                    self.free(counter);
                }
            } else {
                index += 1;
            }
        }
    }

    fn free(&mut self, counter: Counter) {
        // The owner made its last access: a refused free (a cell version
        // that would wrap) only leaves the cell pending release.
        let _ = self.manager.free(counter);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test helpers, as ADR-0007 allows in tests"
)]
mod tests {
    use super::*;

    /// A client's stray store of `FREE` into a cell another client holds
    /// never hands that cell to a second owner (review of #120).
    #[test]
    fn a_clobbered_state_word_never_reallocates_a_held_cell() {
        let mut counters = ClientCounters::new(2, 2).unwrap();
        let (held, _) = counters
            .allocate(1, 1, "held", CounterKeys::DRIVER)
            .unwrap();
        counters.manager.clobber_state_free(held);
        let (other, _) = counters
            .allocate(2, 1, "other", CounterKeys::DRIVER)
            .unwrap();
        assert_ne!(other, held);
        // Every remaining cell is held: the region is exhausted even though
        // the clobbered state word reads free.
        assert_eq!(
            counters.allocate(2, 1, "third", CounterKeys::DRIVER),
            Err(Refusal::Exhausted)
        );
    }
}
