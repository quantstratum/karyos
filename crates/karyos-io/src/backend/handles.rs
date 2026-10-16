// SPDX-License-Identifier: Apache-2.0

//! A bounded table of control path handles: queues and routes
//! (`quantstratum-docs: karyos/design/sockets-backend.md`, 3.2 "Handles").
//!
//! Generations count per instance, not per epoch: one counter per table,
//! which never restarts, also across `reset` and `reopen`; its overflow is
//! terminal. Each handle carries the epoch it was issued in, and a lookup
//! compares epoch, index and generation, so a handle from before a reset
//! never matches an entry of the new epoch, even one at the same index.

use std::num::{NonZeroU16, NonZeroU32};

use super::{BackendEpoch, RouteId, TxQueueId};

/// A handle a [`HandleTable`] issues.
pub(crate) trait Handle: Copy + Eq {
    /// Builds the handle of `index` with `generation` in `epoch`.
    fn issue(epoch: BackendEpoch, index: u16, generation: NonZeroU32) -> Self;
    /// The table index the handle names.
    fn table_index(self) -> u16;
}

impl Handle for TxQueueId {
    fn issue(epoch: BackendEpoch, index: u16, generation: NonZeroU32) -> Self {
        Self::new(epoch, index, generation)
    }

    fn table_index(self) -> u16 {
        self.index()
    }
}

impl Handle for RouteId {
    fn issue(epoch: BackendEpoch, index: u16, generation: NonZeroU32) -> Self {
        Self::new(epoch, index, generation)
    }

    fn table_index(self) -> u16 {
        self.index()
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
    /// The last generation issued; 0 before the first.
    last_generation: u32,
}

impl<H: Handle, T> HandleTable<H, T> {
    /// An empty table of `capacity` entries, allocated here, on the control
    /// path.
    pub(crate) fn new(capacity: NonZeroU16) -> Self {
        let entries = (0..capacity.get()).map(|_| None).collect();
        Self {
            entries,
            last_generation: 0,
        }
    }

    /// Whether an entry is free.
    pub(crate) fn has_free(&self) -> bool {
        self.entries.iter().any(Option::is_none)
    }

    /// Stores `value` in the first free entry and returns its handle.
    pub(crate) fn insert(&mut self, epoch: BackendEpoch, value: T) -> Result<H, IssueError> {
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
        let handle = H::issue(epoch, index, generation);
        *free = Some((handle, value));
        self.last_generation = generation.get();
        Ok(handle)
    }

    /// The entry `handle` names, if it is live: epoch, index and generation
    /// all match.
    pub(crate) fn get(&self, handle: H) -> Option<&T> {
        match self.entries.get(usize::from(handle.table_index())) {
            Some(Some((live, value))) if *live == handle => Some(value),
            _ => None,
        }
    }

    /// The entry `handle` names, mutably, if it is live.
    pub(crate) fn get_mut(&mut self, handle: H) -> Option<&mut T> {
        match self.entries.get_mut(usize::from(handle.table_index())) {
            Some(Some((live, value))) if *live == handle => Some(value),
            _ => None,
        }
    }

    /// Removes the entry `handle` names, if it is live.
    pub(crate) fn remove(&mut self, handle: H) -> Option<T> {
        let entry = self.entries.get_mut(usize::from(handle.table_index()))?;
        match entry {
            Some((live, _)) if *live == handle => entry.take().map(|(_, value)| value),
            _ => None,
        }
    }

    /// Removes every entry (reset). The generation counter is kept.
    pub(crate) fn clear(&mut self) {
        self.entries.iter_mut().for_each(|entry| *entry = None);
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
        let mut table: HandleTable<TxQueueId, u8> = HandleTable::new(capacity(2));
        let first = table.insert(epoch(1), 10).unwrap();
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
        let mut table: HandleTable<RouteId, u8> = HandleTable::new(capacity(2));
        let old = table.insert(epoch(1), 1).unwrap();
        table.clear();
        let new = table.insert(epoch(2), 2).unwrap();
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
        assert_eq!(
            table.insert(epoch(2), 3),
            Err(IssueError::IdentityExhausted)
        );
        assert_eq!(table.iter().count(), 1);
    }

    #[test]
    fn a_full_table_issues_nothing() {
        let mut table: HandleTable<TxQueueId, u8> = HandleTable::new(capacity(1));
        assert!(table.has_free());
        let handle = table.insert(epoch(1), 1).unwrap();
        assert!(!table.has_free());
        assert_eq!(table.insert(epoch(1), 2), Err(IssueError::Full));
        *table.get_mut(handle).unwrap() = 7;
        assert_eq!(table.iter().collect::<Vec<_>>(), vec![(handle, &7)]);
    }
}
