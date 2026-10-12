// SPDX-License-Identifier: Apache-2.0

//! Counters (SPEC.md §11) with checked increments (SPEC.md §4, counter row).
//!
//! A counters region has a fixed number of cells. Each cell has a value word
//! on its own 128-byte stride and a metadata record (version, state,
//! registration id, type id and a label of up to 64 bytes) published with a
//! seqlock: the allocator makes the version odd, issues a Release fence,
//! writes the metadata with Relaxed stores, resets the value with a Relaxed
//! swap (a read-modify-write), and makes the version even with a Release
//! store. A reader loads the version
//! (Acquire), copies the metadata and the value (Relaxed), issues an Acquire
//! fence and reloads the version (Relaxed); it accepts the copy only if the
//! version is even and unchanged.
//!
//! Value updates are read-modify-write operations (increments and `set` by
//! swap), so a reader that observes a value written for a later allocation
//! also observes that allocation's odd version and rejects the copy: the
//! later allocation's Release fence synchronizes with the reader's Acquire
//! fence through the release sequence of its value reset.
//!
//! A cell is reused only after its capability has been consumed by `free`
//! or dropped; a paused or forgotten capability keeps its cell allocated.
//! The value carries no generation tag, so this rule, not the reader, is
//! what keeps a stale writer away from a reused cell.
//!
//! Every word is accessed only atomically, so a reader racing an allocation
//! sees stale or mixed values and discards them, never a data race.
//!
//! [`CellWords`] and its functions are the protocol over any atomic words
//! (also checked with Loom); [`counters`] builds the owned, safe API over
//! heap memory.

use crate::sync::{AtomicU64, Ordering, fence};

/// Words per stride: 128 bytes, the conservative aarch64 cache-line default
/// of SPEC.md §1, also used on x86_64.
pub const STRIDE_WORDS: usize = 16;
/// Maximum label length in bytes.
pub const MAX_LABEL_LENGTH: usize = 64;

const LABEL_WORDS: usize = MAX_LABEL_LENGTH / 8;
const META_VERSION: usize = 0;
const META_STATE: usize = 1;
const META_REGISTRATION: usize = 2;
const META_TYPE: usize = 3;
const META_LABEL_LENGTH: usize = 4;
const META_LABEL: usize = 5;
/// Metadata words used per cell (the rest of the stride is reserved).
pub const META_WORDS: usize = META_LABEL + LABEL_WORDS;

/// The cell holds no counter.
pub const STATE_FREE: u64 = 0;
/// The cell holds an allocated counter.
pub const STATE_ALLOCATED: u64 = 1;
/// The counter's capability was dropped; the allocator may reuse the cell.
pub const STATE_RELEASE_PENDING: u64 = 2;

/// Read attempts before a reader reports a cell as changing.
const READ_ATTEMPTS: usize = 4;

/// The words of one cell: its metadata record and its value word.
#[derive(Debug, Clone, Copy)]
pub struct CellWords<'a> {
    meta: &'a [AtomicU64],
    value: &'a AtomicU64,
}

/// Metadata of an allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterMetadata {
    /// Identity of this allocation; never reused within a region.
    pub registration_id: u64,
    /// Application-defined counter type.
    pub type_id: u64,
    label: [u8; MAX_LABEL_LENGTH],
    label_length: u8,
}

impl CounterMetadata {
    /// Builds metadata.
    ///
    /// # Errors
    ///
    /// Returns [`CounterError::LabelTooLong`] when `label` exceeds
    /// [`MAX_LABEL_LENGTH`] bytes.
    pub fn new(registration_id: u64, type_id: u64, label: &str) -> Result<Self, CounterError> {
        let bytes = label.as_bytes();
        let length = u8::try_from(bytes.len())
            .ok()
            .filter(|&length| usize::from(length) <= MAX_LABEL_LENGTH)
            .ok_or(CounterError::LabelTooLong {
                length: bytes.len(),
            })?;
        let mut stored = [0u8; MAX_LABEL_LENGTH];
        stored
            .get_mut(..bytes.len())
            .ok_or(CounterError::LabelTooLong {
                length: bytes.len(),
            })?
            .copy_from_slice(bytes);
        Ok(Self {
            registration_id,
            type_id,
            label: stored,
            label_length: length,
        })
    }

    /// The label bytes.
    #[must_use]
    pub fn label(&self) -> &[u8] {
        self.label
            .get(..usize::from(self.label_length))
            .unwrap_or(&[])
    }
}

/// What a reader found in a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellRead {
    /// No counter.
    Free,
    /// An allocation was being written during every attempt.
    Changing,
    /// A consistent snapshot.
    Allocated {
        /// The allocation's metadata.
        metadata: CounterMetadata,
        /// The value read with it.
        value: u64,
        /// The capability was dropped and the cell awaits reuse.
        release_pending: bool,
    },
}

/// Errors of counter operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CounterError {
    /// The increment would exceed `u64::MAX`; the value is unchanged.
    #[error("counter increment would exceed u64::MAX; the value is unchanged")]
    Overflow,
    /// The label exceeds [`MAX_LABEL_LENGTH`] bytes.
    #[error("label of {length} bytes exceeds the maximum of 64")]
    LabelTooLong {
        /// The label's length.
        length: usize,
    },
    /// Every cell is in use.
    #[error("no free counter cell")]
    Exhausted,
    /// Registration ids or a cell's version would wrap.
    #[error("counter identities exhausted")]
    IdentitiesExhausted,
    /// The counter belongs to another region.
    #[error("the counter belongs to another region")]
    ForeignCounter,
}

impl<'a> CellWords<'a> {
    /// Wraps a cell's words; `None` if `meta` has fewer than [`META_WORDS`]
    /// words.
    #[must_use]
    pub fn new(meta: &'a [AtomicU64], value: &'a AtomicU64) -> Option<Self> {
        (meta.len() >= META_WORDS).then_some(Self { meta, value })
    }

    fn word(&self, index: usize) -> Option<&'a AtomicU64> {
        self.meta.get(index)
    }

    /// The cell's state (Acquire): observes a release by the capability's
    /// drop before the allocator reuses the cell.
    #[must_use]
    pub fn state(&self) -> u64 {
        self.word(META_STATE)
            .map_or(STATE_FREE, |word| word.load(Ordering::Acquire))
    }

    /// Writes an allocation under the seqlock and resets the value to 0.
    /// Only the cell's single allocator calls this.
    ///
    /// # Errors
    ///
    /// Returns [`CounterError::IdentitiesExhausted`] when the version would
    /// wrap; the cell is unchanged.
    pub fn allocate(&self, metadata: &CounterMetadata) -> Result<(), CounterError> {
        self.write(STATE_ALLOCATED, Some(metadata))
    }

    /// Returns the cell to `FREE` under the seqlock. Only the allocator
    /// calls this, after the capability is gone.
    ///
    /// # Errors
    ///
    /// As [`CellWords::allocate`].
    pub fn free(&self) -> Result<(), CounterError> {
        self.write(STATE_FREE, None)
    }

    fn write(&self, state: u64, metadata: Option<&CounterMetadata>) -> Result<(), CounterError> {
        let Some(version) = self.word(META_VERSION) else {
            return Ok(());
        };
        let current = version.load(Ordering::Relaxed);
        let (Some(odd), Some(even)) = (current.checked_add(1), current.checked_add(2)) else {
            return Err(CounterError::IdentitiesExhausted);
        };
        version.store(odd, Ordering::Relaxed);
        fence(Ordering::Release);
        let store = |index: usize, value: u64| {
            if let Some(word) = self.word(index) {
                word.store(value, Ordering::Relaxed);
            }
        };
        let empty = [0u8; MAX_LABEL_LENGTH];
        let (registration, type_id, length, label) = metadata.map_or((0, 0, 0, &empty), |m| {
            (m.registration_id, m.type_id, m.label_length, &m.label)
        });
        store(META_REGISTRATION, registration);
        store(META_TYPE, type_id);
        store(META_LABEL_LENGTH, u64::from(length));
        for (index, chunk) in label.as_chunks::<8>().0.iter().enumerate() {
            store(META_LABEL + index, u64::from_le_bytes(*chunk));
        }
        // A swap, not a store: the reset heads the release sequence that
        // later increments extend.
        let _ = self.value.swap(0, Ordering::Relaxed);
        store(META_STATE, state);
        version.store(even, Ordering::Release);
        Ok(())
    }

    /// Marks the cell for reuse (Release), from the capability's drop.
    pub fn mark_release_pending(&self) {
        if let Some(word) = self.word(META_STATE) {
            word.store(STATE_RELEASE_PENDING, Ordering::Release);
        }
    }

    /// Adds `delta` with a checked Relaxed read-modify-write. The value
    /// never wraps or saturates: on overflow it is left unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`CounterError::Overflow`] when the sum exceeds `u64::MAX`.
    pub fn increment(&self, delta: u64) -> Result<u64, CounterError> {
        let mut current = self.value.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(delta).ok_or(CounterError::Overflow)?;
            match self.value.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(next),
                Err(actual) => current = actual,
            }
        }
    }

    /// Sets the value with a Relaxed swap (a read-modify-write, see the
    /// module documentation).
    pub fn set(&self, value: u64) {
        let _ = self.value.swap(value, Ordering::Relaxed);
    }

    /// Reads a consistent snapshot, or reports the cell as changing after a
    /// bounded number of attempts. Never waits.
    #[must_use]
    pub fn read(&self) -> CellRead {
        let Some(version) = self.word(META_VERSION) else {
            return CellRead::Free;
        };
        for _ in 0..READ_ATTEMPTS {
            let before = version.load(Ordering::Acquire);
            if before % 2 == 1 {
                continue;
            }
            let load = |index: usize| {
                self.word(index)
                    .map_or(0, |word| word.load(Ordering::Relaxed))
            };
            let state = load(META_STATE);
            let registration_id = load(META_REGISTRATION);
            let type_id = load(META_TYPE);
            let length = load(META_LABEL_LENGTH);
            let mut label = [0u8; MAX_LABEL_LENGTH];
            for (index, chunk) in label.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                *chunk = load(META_LABEL + index).to_le_bytes();
            }
            let value = self.value.load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            if version.load(Ordering::Relaxed) != before {
                continue;
            }
            return match state {
                STATE_ALLOCATED | STATE_RELEASE_PENDING => {
                    let Some(label_length) = u8::try_from(length)
                        .ok()
                        .filter(|&l| usize::from(l) <= MAX_LABEL_LENGTH)
                    else {
                        return CellRead::Changing;
                    };
                    CellRead::Allocated {
                        metadata: CounterMetadata {
                            registration_id,
                            type_id,
                            label,
                            label_length,
                        },
                        value,
                        release_pending: state == STATE_RELEASE_PENDING,
                    }
                }
                _ => CellRead::Free,
            };
        }
        CellRead::Changing
    }
}

#[cfg(not(loom))]
pub use owned::{Counter, CountersManager, CountersReader, counters};

#[cfg(not(loom))]
mod owned {
    use std::sync::Arc;

    use super::{
        CellRead, CellWords, CounterError, CounterMetadata, META_WORDS, STATE_ALLOCATED,
        STATE_FREE, STATE_RELEASE_PENDING, STRIDE_WORDS,
    };
    use crate::atomic_view::HeapWords;
    use crate::error::SysError;

    #[derive(Debug)]
    struct Region {
        values: HeapWords,
        metadata: HeapWords,
        capacity: usize,
    }

    impl Region {
        fn cell(&self, index: usize) -> Option<CellWords<'_>> {
            let start = index.checked_mul(STRIDE_WORDS)?;
            let meta = self
                .metadata
                .words()
                .as_slice()
                .get(start..start.checked_add(META_WORDS)?)?;
            let value = self.values.words().get(start)?;
            CellWords::new(meta, value)
        }
    }

    /// Creates a region of `capacity` counters: its single allocator and a
    /// reader (control path: allocates `2 * capacity` strides).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] for a zero or oversized capacity.
    pub fn counters(capacity: usize) -> Result<(CountersManager, CountersReader), SysError> {
        let words = capacity
            .checked_mul(STRIDE_WORDS)
            .ok_or(SysError::InvalidRegion { address: 0, len: 0 })?;
        let region = Arc::new(Region {
            values: HeapWords::zeroed(words)?,
            metadata: HeapWords::zeroed(words)?,
            capacity,
        });
        Ok((
            CountersManager {
                region: Arc::clone(&region),
                next_registration: 1,
            },
            CountersReader { region },
        ))
    }

    /// The region's only allocator (not `Clone`).
    #[derive(Debug)]
    pub struct CountersManager {
        region: Arc<Region>,
        next_registration: u64,
    }

    impl CountersManager {
        /// Allocates a counter with value 0 (control path).
        ///
        /// # Errors
        ///
        /// Returns [`CounterError::Exhausted`] when no cell is free or
        /// pending release, [`CounterError::LabelTooLong`] and
        /// [`CounterError::IdentitiesExhausted`].
        pub fn allocate(&mut self, type_id: u64, label: &str) -> Result<Counter, CounterError> {
            let next = self
                .next_registration
                .checked_add(1)
                .ok_or(CounterError::IdentitiesExhausted)?;
            let metadata = CounterMetadata::new(self.next_registration, type_id, label)?;
            let index = (0..self.region.capacity)
                .find(|&index| {
                    self.region.cell(index).is_some_and(|cell| {
                        matches!(cell.state(), STATE_FREE | STATE_RELEASE_PENDING)
                    })
                })
                .ok_or(CounterError::Exhausted)?;
            let cell = self.region.cell(index).ok_or(CounterError::Exhausted)?;
            cell.allocate(&metadata)?;
            self.next_registration = next;
            Ok(Counter {
                region: Arc::clone(&self.region),
                index,
                registration_id: metadata.registration_id,
            })
        }

        /// Frees a counter at once; its cell becomes `FREE`.
        ///
        /// # Errors
        ///
        /// Returns [`CounterError::ForeignCounter`] for a counter of another
        /// region (it is dropped, which marks its own cell for reuse), and
        /// [`CounterError::IdentitiesExhausted`] if the cell's version would
        /// wrap (the cell stays pending release).
        pub fn free(&mut self, counter: Counter) -> Result<(), CounterError> {
            if !Arc::ptr_eq(&self.region, &counter.region) {
                return Err(CounterError::ForeignCounter);
            }
            let index = counter.index;
            // The drop marks the cell pending; reclaim it now.
            drop(counter);
            match self.region.cell(index) {
                Some(cell) => cell.free(),
                None => Ok(()),
            }
        }
    }

    /// The capability to update one counter. Not `Clone`; share it by
    /// reference. Dropping it marks the cell for reuse.
    #[derive(Debug)]
    pub struct Counter {
        region: Arc<Region>,
        index: usize,
        registration_id: u64,
    }

    impl Counter {
        /// The cell index.
        #[must_use]
        pub fn index(&self) -> usize {
            self.index
        }

        /// This allocation's registration id.
        #[must_use]
        pub fn registration_id(&self) -> u64 {
            self.registration_id
        }

        /// Adds `delta`; never wraps or saturates.
        ///
        /// # Errors
        ///
        /// Returns [`CounterError::Overflow`], leaving the value unchanged,
        /// when the sum exceeds `u64::MAX`.
        pub fn increment(&self, delta: u64) -> Result<u64, CounterError> {
            self.region
                .cell(self.index)
                .map_or(Ok(0), |cell| cell.increment(delta))
        }

        /// Sets the value (gauges).
        pub fn set(&self, value: u64) {
            if let Some(cell) = self.region.cell(self.index) {
                cell.set(value);
            }
        }
    }

    impl Drop for Counter {
        fn drop(&mut self) {
            if let Some(cell) = self.region.cell(self.index)
                && cell.state() == STATE_ALLOCATED
            {
                cell.mark_release_pending();
            }
        }
    }

    /// A read-only view of the region, for tools and tests.
    #[derive(Debug, Clone)]
    pub struct CountersReader {
        region: Arc<Region>,
    }

    impl CountersReader {
        /// Number of cells.
        #[must_use]
        pub fn capacity(&self) -> usize {
            self.region.capacity
        }

        /// Reads cell `index`; `Free` when out of range.
        #[must_use]
        pub fn read(&self, index: usize) -> CellRead {
            self.region
                .cell(index)
                .map_or(CellRead::Free, |cell| cell.read())
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn allocate_increment_read_and_free() {
        let (mut manager, reader) = counters(2).unwrap();
        let sent = manager.allocate(7, "bytes sent").unwrap();
        assert_eq!(sent.increment(5), Ok(5));
        assert_eq!(sent.increment(3), Ok(8));
        let CellRead::Allocated {
            metadata,
            value,
            release_pending,
        } = reader.read(sent.index())
        else {
            panic!("expected an allocated cell");
        };
        assert_eq!(metadata.type_id, 7);
        assert_eq!(metadata.label(), b"bytes sent");
        assert_eq!(metadata.registration_id, sent.registration_id());
        assert_eq!(value, 8);
        assert!(!release_pending);
        let index = sent.index();
        manager.free(sent).unwrap();
        assert_eq!(reader.read(index), CellRead::Free);
    }

    #[test]
    fn overflow_is_reported_and_leaves_the_value_unchanged() {
        let (mut manager, reader) = counters(1).unwrap();
        let counter = manager.allocate(1, "x").unwrap();
        counter.set(u64::MAX - 2);
        assert_eq!(counter.increment(3), Err(CounterError::Overflow));
        assert!(matches!(
            reader.read(0),
            CellRead::Allocated { value, .. } if value == u64::MAX - 2
        ));
        assert_eq!(counter.increment(2), Ok(u64::MAX));
        assert_eq!(counter.increment(1), Err(CounterError::Overflow));
    }

    #[test]
    fn exhaustion_drop_and_reuse_with_fresh_identity() {
        let (mut manager, reader) = counters(1).unwrap();
        let first = manager.allocate(1, "first").unwrap();
        assert_eq!(
            manager.allocate(1, "second").err(),
            Some(CounterError::Exhausted)
        );
        let first_id = first.registration_id();
        first.increment(9).unwrap();
        drop(first);
        assert!(matches!(
            reader.read(0),
            CellRead::Allocated {
                release_pending: true,
                value: 9,
                ..
            }
        ));
        let second = manager.allocate(2, "second").unwrap();
        assert_ne!(second.registration_id(), first_id);
        let CellRead::Allocated {
            metadata, value, ..
        } = reader.read(0)
        else {
            panic!("expected an allocated cell");
        };
        assert_eq!(
            (metadata.type_id, metadata.label(), value),
            (2, &b"second"[..], 0)
        );
    }

    #[test]
    fn labels_are_bounded_and_foreign_counters_rejected() {
        let (mut manager, _) = counters(1).unwrap();
        let (mut other, other_reader) = counters(1).unwrap();
        assert_eq!(
            manager.allocate(1, &"x".repeat(65)).err(),
            Some(CounterError::LabelTooLong { length: 65 })
        );
        assert!(manager.allocate(1, &"x".repeat(64)).is_ok());
        let foreign = other.allocate(1, "other").unwrap();
        assert_eq!(manager.free(foreign), Err(CounterError::ForeignCounter));
        // The rejected counter was dropped: its own cell awaits reuse.
        assert!(matches!(
            other_reader.read(0),
            CellRead::Allocated {
                release_pending: true,
                ..
            }
        ));
        assert!(counters(0).is_err());
    }

    #[test]
    fn concurrent_increments_and_reads() {
        let (mut manager, reader) = counters(4).unwrap();
        let counter = manager.allocate(1, "hits").unwrap();
        let threads = 4u64;
        let per_thread = if cfg!(miri) { 50 } else { 10_000 };
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    for _ in 0..per_thread {
                        counter.increment(1).unwrap();
                    }
                });
            }
            scope.spawn(|| {
                let mut last = 0;
                for _ in 0..per_thread {
                    if let CellRead::Allocated { value, .. } = reader.read(0) {
                        assert!(value >= last);
                        last = value;
                    }
                }
            });
        });
        assert!(matches!(
            reader.read(0),
            CellRead::Allocated { value, .. } if value == threads * per_thread
        ));
    }
}
