// SPDX-License-Identifier: Apache-2.0

//! The public mapping between the Cluster log's entries and the positions
//! of the Archive recording that holds them (R-CORE-8; quantstratum-docs:
//! karyos/design/product-requirements-on-core.md, "Public entry and slot
//! mapping for event and Archive replay"; karyos#745).
//!
//! The log is an A2 recording, [`LOG_RECORDING`](super::LOG_RECORDING),
//! in the node's log directory: each entry is one frame at a write
//! boundary. Its slot is that frame: the log's epoch, the frame's
//! position and its length.
//!
//! - **Both directions.** [`RaftLog::slot_of`] answers, for an entry
//!   index, where its frame is; [`RaftLog::entry_at`] answers, for a
//!   slot's epoch and position, the entry whose frame starts there.
//! - **Identities a consumer can hold.** An index, and an epoch with a
//!   position, both survive a restart: positions are A2's, and the epoch
//!   is the seal subject of the log's bytes since its last install
//!   (karyos#990), which the integrity journal keeps. An install cuts
//!   every frame and writes the next ones from the same positions, so a
//!   position alone would name two entries; with its epoch it names one.
//! - **No answer is a value.** Each case where there is no correspondence
//!   is a variant, never an error: not yet durable, purged under
//!   retention, below an installed snapshot, not an entry's start, of
//!   another epoch.
//! - **Bounded by the durable prefix.** Nothing past the log's durable
//!   index is answered: a mapping never promises what a crash could still
//!   take away. Such a request answers [`EntryAnswer::NotYet`] or
//!   [`SlotAnswer::NotYet`], with the durable index now.
//! - **Snapshot install.** Entries up to an installed snapshot's base are
//!   no longer in the log: their index answers
//!   [`EntryAnswer::BelowSnapshot`], and a slot of an earlier epoch
//!   [`SlotAnswer::OtherEpoch`]. A replay below the base starts from the
//!   snapshot.
//! - **Determinism.** Under ADR-0024 a replay of the same range applies
//!   the same entries in the same order. Walking slots from a first
//!   position by each slot's length visits the entries in index order,
//!   which is the order the live log applied them.

use karyos_archive::disk::Disk;

use super::{LogError, RaftLog};
use crate::Entry;

/// Where an entry's frame is in the log's recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntrySlot {
    /// The log's epoch: the recording's positions restart at each install.
    pub epoch: u64,
    /// The frame's first byte.
    pub position: u64,
    /// The bytes from the frame's start to the next frame's: the next
    /// slot starts at `position + length`.
    pub length: u64,
    /// The entry's index.
    pub index: u64,
    /// Its term.
    pub term: u64,
}

impl EntrySlot {
    /// Where the next slot starts.
    #[must_use]
    pub const fn next_position(&self) -> Option<u64> {
        self.position.checked_add(self.length)
    }
}

/// An entry index's place in the log's recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryAnswer {
    /// The entry is durable at this slot.
    Recorded(EntrySlot),
    /// Not durable yet, or not written: past the durable prefix, nothing
    /// is promised. `durable` is the log's durable index now.
    NotYet {
        /// The last durable index, `None` while none is.
        durable: Option<u64>,
    },
    /// Purged under retention: the log starts at `first` now.
    Purged {
        /// The log's first index.
        first: u64,
    },
    /// At or below an installed snapshot's base: the snapshot holds its
    /// effect, the log no longer holds the entry.
    BelowSnapshot {
        /// The snapshot's last included index.
        base: u64,
    },
}

/// A slot's entry in the log's recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlotAnswer {
    /// An entry's frame starts at the position.
    Entry(EntrySlot),
    /// The position is inside the durable log but no frame starts there:
    /// inside `within`'s frame.
    NotAnEntry {
        /// The entry whose frame holds the position.
        within: u64,
    },
    /// At or past the durable prefix's end: nothing promised yet.
    NotYet {
        /// The last durable index, `None` while none is.
        durable: Option<u64>,
    },
    /// Below the recording's start: purged under retention.
    Purged {
        /// The recording's start now.
        start: u64,
    },
    /// A slot of another epoch: an install cut that recording.
    OtherEpoch {
        /// The log's epoch now.
        epoch: u64,
    },
}

impl<D: Disk + Clone> RaftLog<D> {
    /// The log's epoch: the seal subject of its bytes since its last
    /// install, the first part of every [`EntrySlot`].
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Where entry `index` is in the log's recording, or why it is not
    /// answered.
    #[must_use]
    pub fn slot_of(&self, index: u64) -> EntryAnswer {
        let durable = self.durable_index();
        if index < self.first_index {
            return match self.base() {
                Some((base, _)) if index <= base => EntryAnswer::BelowSnapshot { base },
                _ => EntryAnswer::Purged {
                    first: self.first_index,
                },
            };
        }
        if durable.is_none_or(|durable| index > durable) {
            return EntryAnswer::NotYet { durable };
        }
        self.recorded(index)
            .map_or(EntryAnswer::NotYet { durable }, EntryAnswer::Recorded)
    }

    /// The entry whose frame starts at `position` of the log's recording
    /// in `epoch`, or why there is none.
    #[must_use]
    pub fn entry_at(&self, epoch: u64, position: u64) -> SlotAnswer {
        if epoch != self.epoch {
            return SlotAnswer::OtherEpoch { epoch: self.epoch };
        }
        let start = self.store.start();
        if position < start {
            return SlotAnswer::Purged { start };
        }
        let durable = self.durable_index();
        let Some(last) = durable else {
            return SlotAnswer::NotYet { durable };
        };
        let durable_end = match self.recorded(last).and_then(|slot| slot.next_position()) {
            Some(end) => end,
            None => return SlotAnswer::NotYet { durable },
        };
        if position >= durable_end {
            return SlotAnswer::NotYet { durable };
        }
        // The frame starting at or before `position`.
        let holding = self
            .entries
            .partition_point(|(frame, _)| *frame <= position);
        let Some(slot) = holding.checked_sub(1) else {
            return SlotAnswer::Purged { start };
        };
        let Some(index) = u64::try_from(slot)
            .ok()
            .and_then(|slot| self.first_index.checked_add(slot))
        else {
            return SlotAnswer::NotYet { durable };
        };
        match self.recorded(index) {
            Some(found) if found.position == position => SlotAnswer::Entry(found),
            Some(_) => SlotAnswer::NotAnEntry { within: index },
            None => SlotAnswer::NotYet { durable },
        }
    }

    /// Reads the entry of `slot`, checked against it: a replay driven by
    /// the mapping.
    ///
    /// # Errors
    ///
    /// [`LogError::OutOfRange`] for a slot the log no longer names as
    /// durable (another epoch, a truncated suffix, a purge), and the
    /// errors of [`RaftLog::entries`].
    pub fn read_slot(&mut self, slot: &EntrySlot) -> Result<Entry, LogError> {
        let not_held = LogError::OutOfRange {
            index: slot.index,
            first: self.first_index,
            last: self.last_index(),
        };
        if self.entry_at(slot.epoch, slot.position) != SlotAnswer::Entry(*slot) {
            return Err(not_held);
        }
        let Some(next) = slot.index.checked_add(1) else {
            return Err(not_held);
        };
        let mut read = self.entries(slot.index..next, u64::MAX)?;
        read.pop().ok_or(not_held)
    }

    /// The slot of entry `index` the log holds, durable or not.
    fn recorded(&self, index: u64) -> Option<EntrySlot> {
        let slot = self.slot(index)?;
        let (position, term) = *self.entries.get(slot)?;
        Some(EntrySlot {
            epoch: self.epoch,
            position,
            length: self.frame_span(index)?,
            index,
            term,
        })
    }
}
