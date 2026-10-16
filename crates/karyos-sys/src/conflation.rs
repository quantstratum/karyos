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

use crate::load_words::LoadWords;
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
        key: i64,
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

/// Configuration shared by a conflated publication and its table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConflationConfig {
    /// Number of dense keys, valid keys are `0..keys`.
    pub keys: u32,
    /// Maximum value size in bytes.
    pub value_capacity: usize,
    /// Capacity of the update journal in bytes.
    pub journal_capacity: usize,
}

impl ConflationConfig {
    /// Checks a publication's reserved value and payload length before it
    /// attempts a reservation.
    pub fn validate_publication(
        &self,
        reserved_value: i64,
        value_length: usize,
    ) -> Result<(), ConflationError> {
        if self.keys == 0 || self.value_capacity == 0 {
            return Err(ConflationError::InvalidConfig);
        }
        if u32::try_from(reserved_value)
            .ok()
            .filter(|key| *key < self.keys)
            .is_none()
        {
            return Err(ConflationError::KeyOutOfRange {
                key: reserved_value,
            });
        }
        if value_length > self.value_capacity {
            return Err(ConflationError::ValueTooLarge {
                length: value_length,
                max: self.value_capacity,
            });
        }
        Ok(())
    }
}

/// The words of one slot: version, length and value words.
///
/// This is the protocol layer, exposed for models and for backings built on
/// it; it does not enforce its own preconditions. Values are coherent only
/// if a slot has a single logical writer: its [`SlotWords::write`] calls
/// never overlap, and when they move to another thread the handoff is
/// synchronized (the view is `Copy`, so nothing here stops a second writer);
/// and if the words start zeroed or as left by earlier writes through this
/// protocol. Memory safety never
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

    /// Whether one more write fits the version space: a writer can check
    /// every slot it is about to touch before mutating any of them.
    #[must_use]
    pub fn can_write(&self) -> bool {
        self.word(VERSION)
            .is_some_and(|word| word.load(Ordering::Relaxed).checked_add(2).is_some())
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
        read_slot(&self.words, out)
    }
}

/// The slot reader over any words a reader can load ([`LoadWords`]): a
/// slot's version, length and value words, as [`SlotWords`] lays them out.
/// It only loads, so it also reads a slot mapped without write access.
/// See [`SlotWords::read`].
#[must_use]
pub fn read_slot<W: LoadWords>(words: &W, out: &mut [u8]) -> SlotRead {
    let Some(capacity) = words
        .len()
        .checked_sub(VALUE)
        .and_then(|value_words| value_words.checked_mul(WORD_BYTES))
    else {
        return SlotRead::Unstable;
    };
    // The version first (Acquire), then the length, as the writer orders
    // them.
    let (Some(first), Some(length)) = (words.load_acquire(VERSION), words.load(LENGTH)) else {
        return SlotRead::Unstable;
    };
    if first == 0 {
        return SlotRead::Empty;
    }
    if first % 2 == 1 {
        return SlotRead::Unstable;
    }
    let copied = usize::try_from(length)
        .ok()
        .filter(|&length| length <= capacity && length <= out.len());
    if let Some(target) = copied.and_then(|copied| out.get_mut(..copied)) {
        for (index, chunk) in target.chunks_mut(WORD_BYTES).enumerate() {
            if let Some(word) = words.load(VALUE + index) {
                let bytes = word.to_le_bytes();
                if let Some(prefix) = bytes.get(..chunk.len()) {
                    chunk.copy_from_slice(prefix);
                }
            }
        }
    }
    fence(Ordering::Acquire);
    let second = words.load(VERSION).unwrap_or(0);
    match copied {
        Some(length) if first == second => SlotRead::Value {
            version: first,
            length,
        },
        _ => SlotRead::Unstable,
    }
}

#[cfg(not(loom))]
pub use owned::{Budget, ConflationReader, ConflationWriter, PollReport, conflation};

#[cfg(all(not(loom), target_os = "linux"))]
pub use owned::{LAYOUT_VERSION, conflation_in};

#[cfg(not(loom))]
mod owned {
    use std::sync::Arc;

    use super::{
        ConflationConfig, ConflationError, STRIDE_WORDS, SlotRead, SlotWords, VALUE, VERSION,
        WORD_BYTES, read_slot,
    };
    use crate::atomic_view::HeapWords;
    use crate::broadcast::{
        BroadcastError, BroadcastReader, BroadcastWords, MIN_CAPACITY, Receive, TRAILER_WORDS,
    };
    use crate::load_words::LoadWords;
    use crate::sync::AtomicU64;

    /// Message type of a journal record.
    const JOURNAL_TYPE: u32 = 1;
    /// Bytes of a journal record payload: key, padding, version.
    const JOURNAL_PAYLOAD: usize = 16;

    /// Layout version of a conflation table region. Readers reject any
    /// other version.
    #[cfg(target_os = "linux")]
    pub const LAYOUT_VERSION: u64 = 1;

    /// The sizes of a table, checked once: `keys` slots of `slot_words`
    /// words each, then the journal's trailer and its data area of
    /// `journal_capacity` bytes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Geometry {
        keys: u32,
        value_capacity: usize,
        slot_words: usize,
        slots_words: usize,
        journal_capacity: usize,
        journal_words: usize,
        max_extent: u64,
    }

    impl Geometry {
        /// The geometry of a table, or `None` when a size is zero or
        /// overflows, or the journal capacity is not a power of two of at
        /// least [`MIN_CAPACITY`] bytes (largest record extent
        /// `journal_capacity / 8`, as for every owned broadcast buffer).
        fn new(keys: u32, value_capacity: usize, journal_capacity: usize) -> Option<Self> {
            if keys == 0
                || value_capacity == 0
                || journal_capacity < MIN_CAPACITY
                || !journal_capacity.is_power_of_two()
            {
                return None;
            }
            let slot_words = value_capacity
                .div_ceil(WORD_BYTES)
                .checked_add(VALUE)?
                .checked_next_multiple_of(STRIDE_WORDS)?;
            Some(Self {
                keys,
                value_capacity,
                slot_words,
                slots_words: slot_words.checked_mul(keys as usize)?,
                journal_capacity,
                journal_words: journal_capacity / WORD_BYTES,
                max_extent: u64::try_from(journal_capacity / 8).ok()?,
            })
        }

        /// The configuration a publication checks against.
        fn config(&self) -> ConflationConfig {
            ConflationConfig {
                keys: self.keys,
                value_capacity: self.value_capacity,
                journal_capacity: self.journal_capacity,
            }
        }

        /// Word index of the journal trailer in a region's structure, after
        /// the configuration line and the slots.
        #[cfg(target_os = "linux")]
        fn trailer_at(&self) -> Option<usize> {
            STRIDE_WORDS.checked_add(self.slots_words)
        }

        /// Word index of the journal data area in a region's structure.
        #[cfg(target_os = "linux")]
        fn data_at(&self) -> Option<usize> {
            self.trailer_at()?.checked_add(TRAILER_WORDS)
        }

        /// Bytes of a region's structure: the configuration line, the
        /// slots, the journal trailer and the journal data area.
        #[cfg(target_os = "linux")]
        fn structure_length(&self) -> Option<usize> {
            self.data_at()?
                .checked_add(self.journal_words)?
                .checked_mul(WORD_BYTES)
        }

        /// The configuration line of a region: keys, value capacity, slot
        /// words and journal capacity; the rest of the stride is zero.
        #[cfg(target_os = "linux")]
        fn config_line(&self) -> [u64; 4] {
            [
                u64::from(self.keys),
                self.value_capacity as u64,
                self.slot_words as u64,
                self.journal_capacity as u64,
            ]
        }
    }

    /// Words a table reader takes slices of: writable heap or region
    /// words, or a read-only mapping (Linux).
    trait Words: LoadWords + Sized {
        /// The words `start..start + count`; `None` when out of bounds.
        fn sub(&self, start: usize, count: usize) -> Option<Self>;
    }

    impl Words for &[AtomicU64] {
        fn sub(&self, start: usize, count: usize) -> Option<Self> {
            let end = start.checked_add(count)?;
            self.get(start..end)
        }
    }

    #[cfg(target_os = "linux")]
    impl Words for crate::atomic_view::ReadOnlyWords<'_> {
        fn sub(&self, start: usize, count: usize) -> Option<Self> {
            let words = self.range(start, count);
            (words.len() == count).then_some(words)
        }
    }

    /// What a reader loads: the slots and the journal.
    struct View<W> {
        slots: W,
        journal: BroadcastReader<W>,
        geometry: Geometry,
    }

    impl<W: Words> View<W> {
        fn new(slots: W, data: W, trailer: W, geometry: Geometry) -> Option<Self> {
            let journal = BroadcastReader::new(data, trailer, geometry.max_extent).ok()?;
            (slots.len() == geometry.slots_words && journal.max_payload() >= JOURNAL_PAYLOAD)
                .then_some(Self {
                    slots,
                    journal,
                    geometry,
                })
        }

        fn slot(&self, key: u32) -> Option<W> {
            if key >= self.geometry.keys {
                return None;
            }
            let start = (key as usize).checked_mul(self.geometry.slot_words)?;
            self.slots.sub(start, self.geometry.slot_words)
        }

        /// The current version, for a scan (Relaxed, as
        /// [`SlotWords::version`]).
        fn version(&self, key: u32) -> u64 {
            self.slot(key)
                .and_then(|slot| slot.load(VERSION))
                .unwrap_or(0)
        }

        fn read(&self, key: u32, out: &mut [u8]) -> Option<SlotRead> {
            Some(read_slot(&self.slot(key)?, out))
        }
    }

    /// Where a writable table lives.
    #[derive(Debug)]
    enum Store {
        /// Heap memory of this process.
        Heap {
            slots: HeapWords,
            data: HeapWords,
            trailer: HeapWords,
        },
        /// A shared region (Linux): configuration line, slots, journal
        /// trailer, journal data.
        #[cfg(target_os = "linux")]
        Mapped(crate::ipc::Region),
    }

    #[derive(Debug)]
    struct Table {
        store: Store,
        geometry: Geometry,
    }

    impl Table {
        /// The slots, the journal data area and the journal trailer.
        fn parts(&self) -> (&[AtomicU64], &[AtomicU64], &[AtomicU64]) {
            match &self.store {
                Store::Heap {
                    slots,
                    data,
                    trailer,
                } => (
                    slots.words().as_slice(),
                    data.words().as_slice(),
                    trailer.words().as_slice(),
                ),
                #[cfg(target_os = "linux")]
                Store::Mapped(region) => {
                    let structure = region.structure().as_slice();
                    let geometry = &self.geometry;
                    let part = |start: Option<usize>, count: usize| {
                        start
                            .and_then(|start| structure.sub(start, count))
                            .unwrap_or(&[])
                    };
                    (
                        part(Some(STRIDE_WORDS), geometry.slots_words),
                        part(geometry.data_at(), geometry.journal_words),
                        part(geometry.trailer_at(), TRAILER_WORDS),
                    )
                }
            }
        }

        fn journal(&self) -> Result<BroadcastWords<'_>, BroadcastError> {
            let (_, data, trailer) = self.parts();
            BroadcastWords::new(data, trailer, self.geometry.max_extent)
        }

        fn view(&self) -> Option<View<&[AtomicU64]>> {
            let (slots, data, trailer) = self.parts();
            View::new(slots, data, trailer, self.geometry)
        }

        fn slot(&self, key: u32) -> Option<SlotWords<'_>> {
            SlotWords::new(self.view()?.slot(key)?)
        }
    }

    /// A table in a region mapped read-only (Linux).
    #[cfg(target_os = "linux")]
    #[derive(Debug)]
    struct ReadOnlyTable {
        region: crate::ipc::ReadOnlyRegion,
        geometry: Geometry,
    }

    #[cfg(target_os = "linux")]
    impl ReadOnlyTable {
        fn view(&self) -> Option<View<crate::atomic_view::ReadOnlyWords<'_>>> {
            let structure = self.region.structure();
            let geometry = self.geometry;
            View::new(
                structure.sub(STRIDE_WORDS, geometry.slots_words)?,
                structure.sub(geometry.data_at()?, geometry.journal_words)?,
                structure.sub(geometry.trailer_at()?, TRAILER_WORDS)?,
                geometry,
            )
        }
    }

    /// The table a reader reads.
    #[derive(Debug)]
    enum Source {
        Local(Arc<Table>),
        #[cfg(target_os = "linux")]
        ReadOnly(ReadOnlyTable),
    }

    /// Runs `$body` with `$view` bound to the source's view (an `Option`),
    /// whatever words it loads.
    macro_rules! with_view {
        ($source:expr, $view:ident => $body:expr) => {
            match $source {
                Source::Local(table) => {
                    let $view = table.view();
                    $body
                }
                #[cfg(target_os = "linux")]
                Source::ReadOnly(table) => {
                    let $view = table.view();
                    $body
                }
            }
        };
    }

    fn writer(table: Table) -> ConflationWriter {
        let value_capacity = table.geometry.value_capacity;
        ConflationWriter {
            table: Arc::new(table),
            value_capacity,
            closed: false,
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
        let geometry = Geometry::new(keys, value_capacity, journal_capacity).ok_or(invalid)?;
        let zeroed = |count| HeapWords::zeroed(count).map_err(|_| invalid);
        let table = Table {
            store: Store::Heap {
                slots: zeroed(geometry.slots_words)?,
                data: zeroed(geometry.journal_words)?,
                trailer: zeroed(TRAILER_WORDS)?,
            },
            geometry,
        };
        table.view().ok_or(invalid)?;
        Ok(writer(table))
    }

    /// Creates a table as [`conflation`] in a new shared region of kind
    /// `ConflationTable` (driver side; `quantstratum-docs:
    /// karyos/design/conflation-end-to-end.md`, Cross-process views) and
    /// returns its only writer. Only the driver writes the region, so it is
    /// created in the A2 seal order and views attach it read-only with
    /// [`ConflationReader::attach_read_only`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::SysError::InvalidRegion`] for a geometry
    /// [`conflation`] refuses, and the errors of
    /// [`crate::ipc::Region::create_driver_only`].
    #[cfg(target_os = "linux")]
    pub fn conflation_in(
        instance: u128,
        region: u64,
        keys: u32,
        value_capacity: usize,
        journal_capacity: usize,
    ) -> Result<ConflationWriter, crate::error::SysError> {
        use crate::sync::Ordering;
        let geometry = Geometry::new(keys, value_capacity, journal_capacity);
        let structure_length = geometry.and_then(|geometry| geometry.structure_length());
        let (Some(geometry), Some(structure_length)) = (geometry, structure_length) else {
            return Err(crate::error::SysError::InvalidRegion { address: 0, len: 0 });
        };
        let invalid = crate::error::SysError::InvalidRegion {
            address: 0,
            len: structure_length,
        };
        let mapped = crate::ipc::Region::create_driver_only(crate::ipc::RegionRecord {
            instance,
            region,
            kind: crate::ipc::RegionKind::ConflationTable,
            generation: 0,
            layout: LAYOUT_VERSION,
            structure_length,
        })?;
        let structure = mapped.structure();
        for (index, value) in geometry.config_line().into_iter().enumerate() {
            structure
                .get(index)
                .ok_or(invalid)?
                .store(value, Ordering::Release);
        }
        let table = Table {
            store: Store::Mapped(mapped),
            geometry,
        };
        table.view().ok_or(invalid)?;
        Ok(writer(table))
    }

    /// The table's only writer (not `Clone`). Dropping it closes the table.
    #[derive(Debug)]
    pub struct ConflationWriter {
        table: Arc<Table>,
        value_capacity: usize,
        closed: bool,
    }

    impl ConflationWriter {
        /// The shared region, to pass its descriptor; `None` on the heap.
        #[cfg(target_os = "linux")]
        #[must_use]
        pub fn region(&self) -> Option<&crate::ipc::Region> {
            match &self.table.store {
                Store::Mapped(region) => Some(region),
                Store::Heap { .. } => None,
            }
        }

        /// The table's configuration.
        #[must_use]
        pub fn config(&self) -> ConflationConfig {
            self.table.geometry.config()
        }

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
            let slot = self.table.slot(key).ok_or(ConflationError::KeyOutOfRange {
                key: i64::from(key),
            })?;
            let journal = self
                .table
                .journal()
                .map_err(|_| ConflationError::InvalidConfig)?;
            // Admit the journal record before the slot changes: under the
            // single writer, the transmit below then cannot fail, so every
            // committed version gets its record.
            if !journal.has_room(JOURNAL_PAYLOAD) {
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
            if journal.transmit(JOURNAL_TYPE, &record).is_err() {
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
            if let Ok(journal) = self.table.journal() {
                journal.close();
            }
        }

        /// A new reader (control path: allocates its private state). It
        /// starts with a full scan, so it delivers every key already written.
        #[must_use]
        pub fn reader(&self) -> ConflationReader {
            ConflationReader::new(Source::Local(Arc::clone(&self.table)), self.table.geometry)
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
            if let Ok(journal) = self.table.journal() {
                journal.seed(position);
            }
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
        /// Whether this poll verified that the table is closed and this
        /// reader has delivered the last value of every key (a slot left
        /// unstable stays pending). It is computed per poll: a later poll
        /// that does not read the journal, such as a zero-key poll, reports
        /// `false` again.
        pub finished: bool,
    }

    /// A reader with private delivered versions, queue and value buffer.
    #[derive(Debug)]
    pub struct ConflationReader {
        source: Source,
        keys: u32,
        cursor: u64,
        scratch: Box<[u8]>,
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
        fn new(source: Source, geometry: Geometry) -> Self {
            let keys = geometry.keys as usize;
            let (cursor, max_payload) = with_view!(&source, view => view
                .map_or((0, 0), |view| (view.journal.tail(), view.journal.max_payload())));
            Self {
                source,
                keys: geometry.keys,
                cursor,
                scratch: vec![0; max_payload].into_boxed_slice(),
                delivered: vec![0; keys].into_boxed_slice(),
                queued: vec![0; keys.div_ceil(64)].into_boxed_slice(),
                queue: vec![0; keys].into_boxed_slice(),
                head: 0,
                len: 0,
                in_flight: None,
                scan_cursor: 0,
                scan_remaining: geometry.keys,
                closed_seen: false,
                value: vec![0; geometry.value_capacity].into_boxed_slice(),
            }
        }

        /// A reader of a table in a region mapped read-only (a view's side;
        /// `quantstratum-docs: karyos/design/conflation-end-to-end.md`,
        /// Cross-process views), starting with a full scan. The
        /// configuration line is read once and must describe a table that
        /// fills the region exactly; from then on every slot read and
        /// journal record is validated as on the heap, with loads only.
        ///
        /// # Errors
        ///
        /// Returns [`crate::error::SysError::InvalidRegion`] unless the
        /// region is a conflation table of this layout that matches its
        /// configuration line.
        #[cfg(target_os = "linux")]
        pub fn attach_read_only(
            region: crate::ipc::ReadOnlyRegion,
        ) -> Result<Self, crate::error::SysError> {
            let record = region.record();
            let invalid = crate::error::SysError::InvalidRegion {
                address: 0,
                len: record.structure_length,
            };
            if record.kind != crate::ipc::RegionKind::ConflationTable
                || record.layout != LAYOUT_VERSION
                || record.generation != 0
            {
                return Err(invalid);
            }
            let structure = region.structure();
            let mut line = [0u64; STRIDE_WORDS];
            for (index, word) in line.iter_mut().enumerate() {
                *word = structure.load_acquire(index).ok_or(invalid)?;
            }
            let [
                keys,
                value_capacity,
                slot_words,
                journal_capacity,
                rest @ ..,
            ] = line;
            let geometry = u32::try_from(keys).ok().zip(
                usize::try_from(value_capacity)
                    .ok()
                    .zip(usize::try_from(journal_capacity).ok()),
            );
            let geometry = geometry
                .and_then(|(keys, (value_capacity, journal_capacity))| {
                    Geometry::new(keys, value_capacity, journal_capacity)
                })
                .ok_or(invalid)?;
            if geometry.config_line() != [keys, value_capacity, slot_words, journal_capacity]
                || rest.iter().any(|word| *word != 0)
                || geometry.structure_length() != Some(record.structure_length)
            {
                return Err(invalid);
            }
            let table = ReadOnlyTable { region, geometry };
            table.view().ok_or(invalid)?;
            Ok(Self::new(Source::ReadOnly(table), geometry))
        }

        /// The configuration of the table this reader reads, to compare
        /// with what a view was granted.
        #[must_use]
        pub fn config(&self) -> ConflationConfig {
            match &self.source {
                Source::Local(table) => table.geometry.config(),
                #[cfg(target_os = "linux")]
                Source::ReadOnly(table) => table.geometry.config(),
            }
        }

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
            let closed = with_view!(&self.source, view => view
                .is_none_or(|view| view.journal.is_closed()));
            if !self.closed_seen && closed {
                self.closed_seen = true;
                self.scan_remaining = self.keys;
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
                let received = with_view!(&self.source, view => view.map_or(
                    Ok(Receive::Pending),
                    |view| view.journal.receive(&mut self.cursor, &mut self.scratch),
                ));
                let (key, version) = match received {
                    // The scratch is sized for the largest payload at
                    // creation, so an error is not expected; it reads as
                    // nothing new, as for a broadcast receiver.
                    Ok(Receive::Pending) | Err(_) => {
                        report.journal_drained = true;
                        return;
                    }
                    Ok(Receive::Lapped { .. }) => {
                        report.lapped = true;
                        self.scan_remaining = self.keys;
                        continue;
                    }
                    Ok(Receive::Message { length, .. }) => {
                        let payload = self.scratch.get(..length).unwrap_or(&[]);
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
            let keys = self.keys;
            for _ in 0..limit.min(keys) {
                let key = self.scan_cursor;
                self.scan_cursor = (key + 1) % keys;
                if self.scan_remaining > 0 {
                    self.scan_remaining -= 1;
                }
                let version = with_view!(&self.source, view => view
                    .map_or(0, |view| view.version(key)));
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
            for _ in 0..retries.max(1) {
                let read = with_view!(&self.source, view => view
                    .and_then(|view| view.read(key, &mut self.value)));
                match read {
                    None => return,
                    Some(SlotRead::Unstable) => continue,
                    Some(SlotRead::Empty) => return,
                    Some(SlotRead::Value { version, length }) => {
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
