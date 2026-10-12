// SPDX-License-Identifier: Apache-2.0

//! Keyed conflation table (SPEC.md §7.1, ADR-0017; design in
//! `quantstratum-docs: karyos/design/keyed-conflation.md`): one fixed-size slot per dense `u32`
//! key, one writer, any number of readers that see the latest coherent value
//! of each key and may skip intermediate ones.
//!
//! Each slot is a version word, a length word and the value words, on its
//! own 128-byte strides. Slots use the fence-based seqlock with atomic data
//! words (Boehm, "Can seqlocks get along with programming language memory
//! models?", MSPC 2012): the writer stores the odd version (Relaxed), issues
//! a Release fence, stores the length and value words (Relaxed) and stores
//! the next even version (Release). A reader loads the version (Acquire),
//! copies the length and value words (Relaxed) into private storage, issues
//! an Acquire fence and reloads the version (Relaxed); it uses the copy only
//! if both loads saw the same even, nonzero version. If the copy contains a
//! word of a later write, that write's Release fence synchronizes with the
//! reader's Acquire fence, so the second load sees at least that write's odd
//! version and the copy is rejected.
//!
//! Every word is accessed only atomically, so a reader racing the writer
//! copies stale or mixed values and discards them, never a data race.
//!
//! After each write the writer appends `(key, version)` to an update
//! journal (a broadcast buffer). A reader queues the keys it reads from the
//! journal; when the journal laps it, entries were lost and it scans the
//! slot versions instead. Every poll is bounded by a key budget and a retry
//! budget, and pending keys are served in FIFO order, so a slot that stays
//! unstable cannot stall a poll or starve the other keys.
//!
//! [`SlotWords`] and its functions are the protocol over any atomic words
//! (also checked with Loom); [`conflation`] builds the owned, safe API over
//! heap memory.

use crate::sync::{AtomicU64, Ordering, fence};

/// Words per stride: 128 bytes, as for counters.
pub const STRIDE_WORDS: usize = 16;
/// Word index of the version in a slot.
const VERSION: usize = 0;
/// Word index of the value length in a slot.
const LENGTH: usize = 1;
/// Word index of the first value word in a slot.
const VALUE: usize = 2;
/// Bytes per word.
const WORD_BYTES: usize = 8;

/// Errors of the conflation table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConflationError {
    /// A size is zero or does not fit the address space.
    #[error("invalid conflation table configuration")]
    InvalidConfig,
    /// The key is not below the declared key count.
    #[error("key {key} is out of range")]
    KeyOutOfRange {
        /// The rejected key.
        key: u32,
    },
    /// The value is longer than the slot capacity.
    #[error("value of {length} bytes exceeds the slot capacity of {max}")]
    ValueTooLarge {
        /// Value length.
        length: usize,
        /// Slot capacity.
        max: usize,
    },
    /// A version or the journal would overflow. The table is now closed.
    #[error("conflation versions exhausted; the table is closed")]
    VersionsExhausted,
    /// The table is closed; no further writes are accepted.
    #[error("conflation table closed")]
    Closed,
}

/// The words of one slot: version, length and value words.
///
/// This is the protocol layer, exposed for models and for backings built on
/// it; it does not enforce its own preconditions. Values are coherent only
/// if at most one thread ever calls [`SlotWords::write`] on a slot (the view
/// is `Copy`, so nothing stops a second writer) and the words start zeroed
/// or as left by earlier writes through this protocol. Memory safety never
/// depends on this: every access is atomic and bounds-checked. The owned
/// [`conflation`] API enforces both conditions with its single
/// [`ConflationWriter`].
#[derive(Debug, Clone, Copy)]
pub struct SlotWords<'a> {
    words: &'a [AtomicU64],
}

/// What a slot read found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotRead {
    /// The key was never written.
    Empty,
    /// A write was in progress, or the copy was overwritten; retry later.
    Unstable,
    /// A coherent value was copied.
    Value {
        /// Its version (even, nonzero).
        version: u64,
        /// Bytes copied into the caller's buffer.
        length: usize,
    },
}

impl<'a> SlotWords<'a> {
    /// Wraps a slot's words: the version, the length and at least one value
    /// word.
    #[must_use]
    pub fn new(words: &'a [AtomicU64]) -> Option<Self> {
        (words.len() > VALUE).then_some(Self { words })
    }

    /// Value capacity in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        (self.words.len() - VALUE) * WORD_BYTES
    }

    fn word(&self, index: usize) -> Option<&'a AtomicU64> {
        self.words.get(index)
    }

    /// The current version, for a scan (Relaxed: it only decides whether
    /// the key is read again through [`SlotWords::read`]).
    #[must_use]
    pub fn version(&self) -> u64 {
        self.word(VERSION)
            .map_or(0, |word| word.load(Ordering::Relaxed))
    }

    /// Writes `value`. Only the slot's single writer calls this (see
    /// [`SlotWords`]). Returns the new version.
    ///
    /// # Errors
    ///
    /// Returns [`ConflationError::ValueTooLarge`] and
    /// [`ConflationError::VersionsExhausted`]; nothing is stored on error.
    pub fn write(&self, value: &[u8]) -> Result<u64, ConflationError> {
        if value.len() > self.capacity() {
            return Err(ConflationError::ValueTooLarge {
                length: value.len(),
                max: self.capacity(),
            });
        }
        let Some(version) = self.word(VERSION) else {
            return Err(ConflationError::InvalidConfig);
        };
        // Only this writer stores the version, so it is even here.
        let current = version.load(Ordering::Relaxed);
        let (Some(odd), Some(even)) = (current.checked_add(1), current.checked_add(2)) else {
            return Err(ConflationError::VersionsExhausted);
        };
        version.store(odd, Ordering::Relaxed);
        fence(Ordering::Release);
        if let Some(length) = self.word(LENGTH) {
            length.store(value.len() as u64, Ordering::Relaxed);
        }
        for (index, chunk) in value.chunks(WORD_BYTES).enumerate() {
            let mut bytes = [0u8; WORD_BYTES];
            if let Some(prefix) = bytes.get_mut(..chunk.len()) {
                prefix.copy_from_slice(chunk);
            }
            if let Some(word) = self.word(VALUE + index) {
                word.store(u64::from_le_bytes(bytes), Ordering::Relaxed);
            }
        }
        version.store(even, Ordering::Release);
        Ok(even)
    }

    /// Copies the current value into `out` if it is coherent. `out` must
    /// hold the slot capacity; a shorter buffer reads as
    /// [`SlotRead::Unstable`] for values that do not fit.
    #[must_use]
    pub fn read(&self, out: &mut [u8]) -> SlotRead {
        let (Some(version), Some(length)) = (self.word(VERSION), self.word(LENGTH)) else {
            return SlotRead::Unstable;
        };
        let first = version.load(Ordering::Acquire);
        if first == 0 {
            return SlotRead::Empty;
        }
        if first % 2 == 1 {
            return SlotRead::Unstable;
        }
        let copied = usize::try_from(length.load(Ordering::Relaxed))
            .ok()
            .filter(|&length| length <= self.capacity() && length <= out.len());
        if let Some(target) = copied.and_then(|copied| out.get_mut(..copied)) {
            for (index, chunk) in target.chunks_mut(WORD_BYTES).enumerate() {
                if let Some(word) = self.word(VALUE + index) {
                    let bytes = word.load(Ordering::Relaxed).to_le_bytes();
                    if let Some(prefix) = bytes.get(..chunk.len()) {
                        chunk.copy_from_slice(prefix);
                    }
                }
            }
        }
        fence(Ordering::Acquire);
        let second = version.load(Ordering::Relaxed);
        match copied {
            Some(length) if first == second => SlotRead::Value {
                version: first,
                length,
            },
            _ => SlotRead::Unstable,
        }
    }
}

#[cfg(not(loom))]
pub use owned::{Budget, ConflationReader, ConflationWriter, PollReport, conflation};

#[cfg(not(loom))]
mod owned {
    use std::sync::Arc;

    use super::{ConflationError, STRIDE_WORDS, SlotRead, SlotWords, VALUE, WORD_BYTES};
    use crate::atomic_view::HeapWords;
    use crate::broadcast::{BroadcastReceiver, BroadcastTransmitter, Received, broadcast};

    /// Message type of a journal record.
    const JOURNAL_TYPE: u32 = 1;
    /// Bytes of a journal record payload: key, padding, version.
    const JOURNAL_PAYLOAD: usize = 16;

    #[derive(Debug)]
    struct Table {
        slots: HeapWords,
        keys: u32,
        slot_words: usize,
    }

    impl Table {
        fn slot(&self, key: u32) -> Option<SlotWords<'_>> {
            if key >= self.keys {
                return None;
            }
            let start = (key as usize).checked_mul(self.slot_words)?;
            SlotWords::new(self.slots.range(start, self.slot_words)?)
        }
    }

    /// Creates a table of `keys` slots of `value_capacity` bytes each, with
    /// a journal of `journal_capacity` bytes (control path), and returns its
    /// only writer.
    ///
    /// # Errors
    ///
    /// Returns [`ConflationError::InvalidConfig`] when a size is zero or
    /// overflows, or the journal capacity is not a valid broadcast capacity.
    pub fn conflation(
        keys: u32,
        value_capacity: usize,
        journal_capacity: usize,
    ) -> Result<ConflationWriter, ConflationError> {
        let invalid = ConflationError::InvalidConfig;
        if keys == 0 || value_capacity == 0 {
            return Err(invalid);
        }
        let value_words = value_capacity.div_ceil(WORD_BYTES);
        let slot_words = value_words
            .checked_add(VALUE)
            .and_then(|words| words.checked_next_multiple_of(STRIDE_WORDS))
            .ok_or(invalid)?;
        let total = slot_words.checked_mul(keys as usize).ok_or(invalid)?;
        let slots = HeapWords::zeroed(total).map_err(|_| invalid)?;
        let journal = broadcast(journal_capacity).map_err(|_| invalid)?;
        if journal.max_payload() < JOURNAL_PAYLOAD {
            return Err(invalid);
        }
        Ok(ConflationWriter {
            table: Arc::new(Table {
                slots,
                keys,
                slot_words,
            }),
            journal,
            value_capacity,
            closed: false,
        })
    }

    /// The table's only writer (not `Clone`). Dropping it closes the table.
    #[derive(Debug)]
    pub struct ConflationWriter {
        table: Arc<Table>,
        journal: BroadcastTransmitter,
        value_capacity: usize,
        closed: bool,
    }

    impl ConflationWriter {
        /// Writes the value of `key` and records it in the journal. Returns
        /// the new version.
        ///
        /// # Errors
        ///
        /// Returns [`ConflationError::KeyOutOfRange`] and
        /// [`ConflationError::ValueTooLarge`] (nothing is stored),
        /// [`ConflationError::VersionsExhausted`] (nothing is stored; the
        /// table is closed) and [`ConflationError::Closed`].
        pub fn write(&mut self, key: u32, value: &[u8]) -> Result<u64, ConflationError> {
            if self.closed {
                return Err(ConflationError::Closed);
            }
            if value.len() > self.value_capacity {
                return Err(ConflationError::ValueTooLarge {
                    length: value.len(),
                    max: self.value_capacity,
                });
            }
            let slot = self
                .table
                .slot(key)
                .ok_or(ConflationError::KeyOutOfRange { key })?;
            // Admit the journal record before the slot changes: under the
            // single writer, the transmit below then cannot fail, so every
            // committed version gets its record.
            if !self.journal.has_room(JOURNAL_PAYLOAD) {
                self.close();
                return Err(ConflationError::VersionsExhausted);
            }
            let version = match slot.write(value) {
                Ok(version) => version,
                Err(ConflationError::VersionsExhausted) => {
                    self.close();
                    return Err(ConflationError::VersionsExhausted);
                }
                Err(error) => return Err(error),
            };
            let mut record = [0u8; JOURNAL_PAYLOAD];
            record[..4].copy_from_slice(&key.to_le_bytes());
            record[8..].copy_from_slice(&version.to_le_bytes());
            if self.journal.transmit(JOURNAL_TYPE, &record).is_err() {
                // Unreachable after `has_room`; if it ever happens, close: a
                // reader that sees the table closed scans every slot once.
                self.close();
            }
            Ok(version)
        }

        /// Closes the table for good: later writes fail with
        /// [`ConflationError::Closed`]; readers keep reading the last
        /// values and see [`PollReport::closed`].
        pub fn close(&mut self) {
            self.closed = true;
            self.journal.close();
        }

        /// A new reader (control path: allocates its private state). It
        /// starts with a full scan, so it delivers every key already written.
        #[must_use]
        pub fn reader(&self) -> ConflationReader {
            let keys = self.table.keys as usize;
            ConflationReader {
                table: Arc::clone(&self.table),
                journal: self.journal.receiver(),
                delivered: vec![0; keys].into_boxed_slice(),
                queued: vec![0; keys.div_ceil(64)].into_boxed_slice(),
                queue: vec![0; keys].into_boxed_slice(),
                head: 0,
                len: 0,
                in_flight: None,
                scan_cursor: 0,
                scan_remaining: self.table.keys,
                closed_seen: false,
                value: vec![0; self.value_capacity].into_boxed_slice(),
            }
        }

        #[cfg(test)]
        pub(super) fn seed_version(&self, key: u32, version: u64) {
            use crate::sync::Ordering;
            if let Some(slot) = self.table.slot(key)
                && let Some(word) = slot.word(super::VERSION)
            {
                word.store(version, Ordering::Relaxed);
            }
        }

        #[cfg(test)]
        pub(super) fn table_slot(&self, key: u32) -> Option<SlotWords<'_>> {
            self.table.slot(key)
        }

        #[cfg(test)]
        pub(super) fn seed_journal(&self, position: u64) {
            self.journal.seed(position);
        }

        #[cfg(test)]
        pub(super) fn slot_version_word(&self, key: u32) -> Option<&crate::sync::AtomicU64> {
            self.table.slot(key)?.word(super::VERSION)
        }
    }

    impl Drop for ConflationWriter {
        fn drop(&mut self) {
            self.close();
        }
    }

    /// Bounds of one poll.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Budget {
        /// Most journal records read, slots swept and keys served, each.
        /// Zero makes the poll do nothing.
        pub keys: u32,
        /// Read attempts per served key; zero counts as one.
        pub retries: u32,
    }

    /// What one poll did.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PollReport {
        /// Values handed to the handler.
        pub delivered: u32,
        /// Served keys whose value was already delivered.
        pub skipped: u32,
        /// Served keys that stayed unstable and were queued again.
        pub unstable: u32,
        /// Keys still queued after the poll.
        pub pending: u32,
        /// Whether the journal lapped this reader during the poll (entries
        /// were lost; the reader scans).
        pub lapped: bool,
        /// Whether a full pass over the slots (when the reader starts, after
        /// a lap, after the table closes) is still in progress.
        pub scanning: bool,
        /// Whether the poll read the journal to its end. With nothing
        /// pending and no scan, the reader has delivered every change the
        /// journal had recorded when it was read.
        pub journal_drained: bool,
        /// Whether the writer closed the table.
        pub closed: bool,
        /// Whether the table is closed and this reader has delivered the
        /// last value of every key (a slot left unstable stays pending).
        pub finished: bool,
    }

    /// A reader with private delivered versions, queue and value buffer.
    #[derive(Debug)]
    pub struct ConflationReader {
        table: Arc<Table>,
        journal: BroadcastReceiver,
        delivered: Box<[u64]>,
        queued: Box<[u64]>,
        queue: Box<[u32]>,
        head: usize,
        len: usize,
        in_flight: Option<u32>,
        scan_cursor: u32,
        scan_remaining: u32,
        closed_seen: bool,
        value: Box<[u8]>,
    }

    impl ConflationReader {
        /// The version last delivered for `key` (0 if none).
        #[must_use]
        pub fn delivered_version(&self, key: u32) -> Option<u64> {
            self.delivered.get(key as usize).copied()
        }

        fn is_queued(&self, key: u32) -> bool {
            self.queued
                .get(key as usize / 64)
                .is_some_and(|bits| bits & (1 << (key % 64)) != 0)
        }

        fn set_queued(&mut self, key: u32, queued: bool) {
            if let Some(bits) = self.queued.get_mut(key as usize / 64) {
                let mask = 1 << (key % 64);
                if queued {
                    *bits |= mask;
                } else {
                    *bits &= !mask;
                }
            }
        }

        /// Queues `key` at the back unless it is already queued. The queue
        /// holds each key at most once, so it never overflows.
        fn push(&mut self, key: u32) {
            if self.is_queued(key) || self.len >= self.queue.len() {
                return;
            }
            let tail = (self.head + self.len) % self.queue.len();
            if let Some(entry) = self.queue.get_mut(tail) {
                *entry = key;
                self.len += 1;
                self.set_queued(key, true);
            }
        }

        fn pop(&mut self) -> Option<u32> {
            if self.len == 0 {
                return None;
            }
            let key = *self.queue.get(self.head)?;
            self.head = (self.head + 1) % self.queue.len();
            self.len -= 1;
            self.set_queued(key, false);
            Some(key)
        }

        fn changed(&self, key: u32, version: u64) -> bool {
            self.delivered
                .get(key as usize)
                .is_some_and(|&delivered| version != delivered)
        }

        /// Delivers the latest value of changed keys to `handler(key,
        /// version, value)`, within `budget`. The value borrows this
        /// reader's private copy.
        ///
        /// If the handler panics, its key is not marked delivered: the next
        /// poll queues it again (at the back, behind keys already pending) and
        /// it is served within that or later budgets.
        pub fn poll_changed(
            &mut self,
            budget: Budget,
            mut handler: impl FnMut(u32, u64, &[u8]),
        ) -> PollReport {
            let mut report = PollReport::default();
            if let Some(key) = self.in_flight.take() {
                self.push(key);
            }
            // Once closed, the journal may lack the last record: scan every
            // slot once.
            if !self.closed_seen && self.journal.is_closed() {
                self.closed_seen = true;
                self.scan_remaining = self.table.keys;
            }
            if budget.keys == 0 {
                return self.report(report);
            }
            self.drain_journal(budget.keys, &mut report);
            self.sweep(budget.keys);
            // Serve only the keys queued now, so a key requeued as unstable
            // is not retried again in this poll.
            let eligible = budget.keys.min(u32::try_from(self.len).unwrap_or(u32::MAX));
            for _ in 0..eligible {
                let Some(key) = self.pop() else {
                    break;
                };
                self.serve(key, budget.retries, &mut handler, &mut report);
            }
            self.report(report)
        }

        fn report(&self, mut report: PollReport) -> PollReport {
            report.pending = u32::try_from(self.len).unwrap_or(u32::MAX);
            report.scanning = self.scan_remaining > 0;
            report.closed = self.closed_seen;
            report.finished = self.closed_seen
                && report.journal_drained
                && self.len == 0
                && self.scan_remaining == 0;
            report
        }

        fn drain_journal(&mut self, limit: u32, report: &mut PollReport) {
            for _ in 0..limit {
                let (key, version) = match self.journal.receive() {
                    Received::Pending => {
                        report.journal_drained = true;
                        return;
                    }
                    Received::Lapped { .. } => {
                        report.lapped = true;
                        self.scan_remaining = self.table.keys;
                        continue;
                    }
                    Received::Message { payload, .. } => {
                        let key = payload
                            .get(..4)
                            .and_then(|bytes| bytes.try_into().ok())
                            .map(u32::from_le_bytes);
                        let version = payload
                            .get(8..16)
                            .and_then(|bytes| bytes.try_into().ok())
                            .map(u64::from_le_bytes);
                        match (key, version) {
                            (Some(key), Some(version)) => (key, version),
                            _ => continue,
                        }
                    }
                };
                if self.changed(key, version) {
                    self.push(key);
                }
            }
        }

        /// Checks the versions of up to `limit` slots from the persistent
        /// cursor, on every poll: this finds values whose journal record was
        /// lost, or not yet appended when the journal was read. Counts down
        /// a full pass when one is in progress.
        fn sweep(&mut self, limit: u32) {
            let keys = self.table.keys;
            for _ in 0..limit.min(keys) {
                let key = self.scan_cursor;
                self.scan_cursor = (key + 1) % keys;
                if self.scan_remaining > 0 {
                    self.scan_remaining -= 1;
                }
                let version = self.table.slot(key).map_or(0, |slot| slot.version());
                if version != 0 && self.changed(key, version) {
                    self.push(key);
                }
            }
        }

        fn serve(
            &mut self,
            key: u32,
            retries: u32,
            handler: &mut impl FnMut(u32, u64, &[u8]),
            report: &mut PollReport,
        ) {
            let Some(slot) = self.table.slot(key) else {
                return;
            };
            for _ in 0..retries.max(1) {
                match slot.read(&mut self.value) {
                    SlotRead::Unstable => continue,
                    SlotRead::Empty => return,
                    SlotRead::Value { version, length } => {
                        let delivered = self.delivered.get(key as usize).copied().unwrap_or(0);
                        if version <= delivered {
                            report.skipped += 1;
                            return;
                        }
                        self.in_flight = Some(key);
                        handler(key, version, self.value.get(..length).unwrap_or(&[]));
                        self.in_flight = None;
                        if let Some(entry) = self.delivered.get_mut(key as usize) {
                            *entry = version;
                        }
                        report.delivered += 1;
                        return;
                    }
                }
            }
            report.unstable += 1;
            self.push(key);
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests;
