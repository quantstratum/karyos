// SPDX-License-Identifier: Apache-2.0

//! A bounded table of control path handles: queues and routes
//! (`quantstratum-docs: karyos/design/sockets-backend.md`, 3.2 "Handles").
//!
//! Generations count per instance, not per epoch: one counter per table,
//! which never restarts, also across `reset` and `reopen`; its overflow is
//! terminal. The table stores the current epoch, which [`HandleTable::clear`]
//! replaces at reset. Each handle carries the epoch it was issued in, and a
//! lookup compares it with the table's epoch, then the index and generation,
//! so a handle from before a reset never matches an entry of the new epoch,
//! even one at the same index, whatever the endpoint checks.

use std::num::{NonZeroU16, NonZeroU32};

use super::{BackendEpoch, RouteId, TxQueueId};

/// A handle a [`HandleTable`] issues.
pub(crate) trait Handle: Copy + Eq {
    /// Builds the handle of `index` with `generation` in `epoch`.
    fn issue(epoch: BackendEpoch, index: u16, generation: NonZeroU32) -> Self;
    /// The table index the handle names.
    fn table_index(self) -> u16;
    /// The epoch the handle was issued in.
    fn issue_epoch(self) -> BackendEpoch;
}

impl Handle for TxQueueId {
    fn issue(epoch: BackendEpoch, index: u16, generation: NonZeroU32) -> Self {
        Self::new(epoch, index, generation)
    }

    fn table_index(self) -> u16 {
        self.index()
    }

    fn issue_epoch(self) -> BackendEpoch {
        self.epoch()
    }
}

impl Handle for RouteId {
    fn issue(epoch: BackendEpoch, index: u16, generation: NonZeroU32) -> Self {
        Self::new(epoch, index, generation)
    }

    fn table_index(self) -> u16 {
        self.index()
    }

    fn issue_epoch(self) -> BackendEpoch {
        self.epoch()
    }
}

/// Why a handle could not be issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IssueError {
    /// Every entry is in use.
    Full,
    /// The instance's generation counter cannot advance. Terminal.
    IdentityExhausted,
}

/// Up to `capacity` live entries, each named by one handle.
#[derive(Debug)]
pub(crate) struct HandleTable<H, T> {
    entries: Box<[Option<(H, T)>]>,
    /// The epoch new handles are issued in; only handles of this epoch
    /// match.
    epoch: BackendEpoch,
    /// The last generation issued; 0 before the first.
    last_generation: u32,
}

impl<H: Handle, T> HandleTable<H, T> {
    /// An empty table of `capacity` entries in `epoch`, allocated here, on
    /// the control path.
    pub(crate) fn new(capacity: NonZeroU16, epoch: BackendEpoch) -> Self {
        let entries = (0..capacity.get()).map(|_| None).collect();
        Self {
            entries,
            epoch,
            last_generation: 0,
        }
    }

    /// Whether an entry is free.
    pub(crate) fn has_free(&self) -> bool {
        self.entries.iter().any(Option::is_none)
    }

    /// The epoch new handles are issued in.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn epoch(&self) -> BackendEpoch {
        self.epoch
    }

    /// Stores `value` in the first free entry and returns its handle,
    /// issued in the table's epoch.
    pub(crate) fn insert(&mut self, value: T) -> Result<H, IssueError> {
        let (index, free) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| entry.is_none())
            .ok_or(IssueError::Full)?;
        let index = u16::try_from(index).map_err(|_| IssueError::Full)?;
        let generation = self
            .last_generation
            .checked_add(1)
            .and_then(NonZeroU32::new)
            .ok_or(IssueError::IdentityExhausted)?;
        let handle = H::issue(self.epoch, index, generation);
        *free = Some((handle, value));
        self.last_generation = generation.get();
        Ok(handle)
    }

    /// The entry `handle` names, if it is live: its epoch is the table's,
    /// and the index and generation match.
    pub(crate) fn get(&self, handle: H) -> Option<&T> {
        if handle.issue_epoch() != self.epoch {
            return None;
        }
        match self.entries.get(usize::from(handle.table_index())) {
            Some(Some((live, value))) if *live == handle => Some(value),
            _ => None,
        }
    }

    /// The entry `handle` names, mutably, if it is live.
    pub(crate) fn get_mut(&mut self, handle: H) -> Option<&mut T> {
        if handle.issue_epoch() != self.epoch {
            return None;
        }
        match self.entries.get_mut(usize::from(handle.table_index())) {
            Some(Some((live, value))) if *live == handle => Some(value),
            _ => None,
        }
    }

    /// Removes the entry `handle` names, if it is live.
    pub(crate) fn remove(&mut self, handle: H) -> Option<T> {
        if handle.issue_epoch() != self.epoch {
            return None;
        }
        let entry = self.entries.get_mut(usize::from(handle.table_index()))?;
        match entry {
            Some((live, _)) if *live == handle => entry.take().map(|(_, value)| value),
            _ => None,
        }
    }

    /// Removes every entry and moves the table to `new_epoch` (reset), so
    /// no handle of an earlier epoch matches again. The generation counter
    /// is kept.
    pub(crate) fn clear(&mut self, new_epoch: BackendEpoch) {
        self.entries.iter_mut().for_each(|entry| *entry = None);
        self.epoch = new_epoch;
    }

    /// The live entries with their handles.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (H, &T)> {
        self.entries
            .iter()
            .filter_map(|entry| entry.as_ref().map(|(handle, value)| (*handle, value)))
    }

    #[cfg(test)]
    pub(crate) fn set_last_generation(&mut self, generation: u32) {
        self.last_generation = generation;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(value: u32) -> BackendEpoch {
        BackendEpoch::new(NonZeroU32::new(value).unwrap())
    }

    fn capacity(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    #[test]
    fn a_handle_matches_only_its_own_epoch_index_and_generation() {
        let mut table: HandleTable<TxQueueId, u8> = HandleTable::new(capacity(2), epoch(1));
        let first = table.insert(10).unwrap();
        assert_eq!(first.epoch(), epoch(1));
        assert_eq!(table.get(first), Some(&10));
        // Same index and generation, another epoch: no match.
        let other_epoch = TxQueueId::new(epoch(2), first.index(), first.generation());
        assert_eq!(table.get(other_epoch), None);
        // Same epoch and index, another generation: no match.
        let other_generation = TxQueueId::new(epoch(1), first.index(), NonZeroU32::MAX);
        assert_eq!(table.get(other_generation), None);
        assert_eq!(table.remove(other_generation), None);
        assert_eq!(table.remove(first), Some(10));
        assert_eq!(table.get(first), None);
    }

    #[test]
    fn handles_across_reset_never_match_a_reused_index() {
        let mut table: HandleTable<RouteId, u8> = HandleTable::new(capacity(2), epoch(1));
        let old = table.insert(1).unwrap();
        table.clear(epoch(2));
        assert_eq!(table.epoch(), epoch(2));
        let new = table.insert(2).unwrap();
        assert_eq!(new.epoch(), epoch(2));
        assert_eq!(new.index(), old.index(), "the index is reused");
        assert!(
            new.generation() > old.generation(),
            "generations never restart"
        );
        assert_eq!(table.get(old), None);
        assert_eq!(table.get_mut(old), None);
        assert_eq!(table.get(new), Some(&2));
        // Generation exhaustion is terminal.
        table.set_last_generation(u32::MAX);
        assert_eq!(table.insert(3), Err(IssueError::IdentityExhausted));
        assert_eq!(table.iter().count(), 1);
    }

    #[test]
    fn a_full_table_issues_nothing() {
        let mut table: HandleTable<TxQueueId, u8> = HandleTable::new(capacity(1), epoch(1));
        assert!(table.has_free());
        let handle = table.insert(1).unwrap();
        assert!(!table.has_free());
        assert_eq!(table.insert(2), Err(IssueError::Full));
        *table.get_mut(handle).unwrap() = 7;
        assert_eq!(table.iter().collect::<Vec<_>>(), vec![(handle, &7)]);
    }

    #[test]
    fn a_stale_epoch_handle_never_matches_even_with_a_reused_generation() {
        let mut table: HandleTable<TxQueueId, u8> = HandleTable::new(capacity(1), epoch(1));
        let old = table.insert(1).unwrap();
        table.clear(epoch(2));
        // Force the next handle to reuse the old index and generation: only
        // the stored epoch tells them apart.
        table.set_last_generation(old.generation().get() - 1);
        let new = table.insert(2).unwrap();
        assert_eq!(
            (new.index(), new.generation()),
            (old.index(), old.generation())
        );
        assert_ne!(new, old);
        assert_eq!(table.get(old), None);
        assert_eq!(table.get_mut(old), None);
        assert_eq!(table.remove(old), None);
        assert_eq!(table.get(new), Some(&2));
    }
}
