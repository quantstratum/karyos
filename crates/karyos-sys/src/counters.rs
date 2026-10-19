// SPDX-License-Identifier: Apache-2.0

//! Counters (SPEC.md §11) with checked increments (SPEC.md §4, counter row).
//!
//! A counters region has a fixed number of cells. Each cell has a value word
//! on its own 128-byte stride and a metadata record (version, state,
//! registration id, type id, a label of up to 64 bytes and, from layout
//! version 2, three key words; `quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Counters") published with a
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
const META_KEYS: usize = META_LABEL + LABEL_WORDS;
/// Key words per cell (layout version 2).
pub const KEY_WORDS: usize = 3;
/// Metadata words used per cell: the whole stride from layout version 2.
pub const META_WORDS: usize = META_KEYS + KEY_WORDS;

/// Counter type: an event count (cnc-primitives.md).
pub const TYPE_EVENT: u64 = 1;
/// Counter type: a gauge (cnc-primitives.md).
pub const TYPE_GAUGE: u64 = 2;
/// Counter type: a stream position in bytes, sampled by the driver.
pub const TYPE_POSITION: u64 = 4;
/// Counter type: a host `CLOCK_MONOTONIC` time in nanoseconds.
pub const TYPE_TIMESTAMP: u64 = 5;

/// Participant kind in `key1` bits 15 to 8: none.
pub const KIND_NONE: u8 = 0;
/// Participant kind: a subscriber.
pub const KIND_SUBSCRIBER: u8 = 1;
/// Participant kind: a publication.
pub const KIND_PUBLICATION: u8 = 2;
/// Participant kind: a client.
pub const KIND_CLIENT: u8 = 3;
/// Participant kind: a network endpoint, `key2` its instance id; its
/// effective capabilities are gauges of this kind
/// (`quantstratum-docs: karyos/design/management-agent-gap-analysis.md`,
/// M3).
pub const KIND_ENDPOINT: u8 = 4;
/// Participant kind: a guard, `key2` its id; its word is a gauge labelled
/// with the guard's name (`quantstratum-docs:
/// karyos/design/management-agent-gap-analysis.md`, M4).
pub const KIND_GUARD: u8 = 5;

/// The three key words that let tools group counters without parsing
/// labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CounterKeys {
    /// `key0`: registration id of the stream, 0 for driver-wide counters.
    pub stream: u64,
    /// `key1` bits 7 to 0: the lane.
    pub lane: u8,
    /// `key1` bits 15 to 8: the participant kind (`KIND_*`).
    pub kind: u8,
    /// `key2`: registration id of the participant or client, 0 when none.
    pub participant: u64,
}

impl CounterKeys {
    /// Keys of a driver-wide counter: all zero.
    pub const DRIVER: Self = Self {
        stream: 0,
        lane: 0,
        kind: KIND_NONE,
        participant: 0,
    };

    fn words(self) -> [u64; KEY_WORDS] {
        [
            self.stream,
            u64::from(self.lane) | (u64::from(self.kind) << 8),
            self.participant,
        ]
    }

    /// Decodes the key words; `None` when `key1` has bits set above bit 15.
    fn from_words([stream, key1, participant]: [u64; KEY_WORDS]) -> Option<Self> {
        if key1 >> 16 != 0 {
            return None;
        }
        Some(Self {
            stream,
            lane: (key1 & 0xFF) as u8,
            kind: ((key1 >> 8) & 0xFF) as u8,
            participant,
        })
    }
}

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
    /// The key words.
    pub keys: CounterKeys,
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
            keys: CounterKeys::DRIVER,
            label: stored,
            label_length: length,
        })
    }

    /// The same metadata with `keys`.
    #[must_use]
    pub fn with_keys(mut self, keys: CounterKeys) -> Self {
        self.keys = keys;
        self
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
        let (registration, type_id, length, label, keys) =
            metadata.map_or((0, 0, 0, &empty, CounterKeys::DRIVER), |m| {
                (
                    m.registration_id,
                    m.type_id,
                    m.label_length,
                    &m.label,
                    m.keys,
                )
            });
        store(META_REGISTRATION, registration);
        store(META_TYPE, type_id);
        store(META_LABEL_LENGTH, u64::from(length));
        for (index, chunk) in label.as_chunks::<8>().0.iter().enumerate() {
            store(META_LABEL + index, u64::from_le_bytes(*chunk));
        }
        for (index, key) in keys.words().into_iter().enumerate() {
            store(META_KEYS + index, key);
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

    /// Loads the value word alone with a `Relaxed` load, without the
    /// metadata: the cells of a sampling pass, its epoch included, are read
    /// this way ([`read_pass`] adds the fences). Only `Relaxed` so the same
    /// read is valid over read-only memory.
    #[must_use]
    pub fn load_value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Begins a sampling pass on this epoch cell (`quantstratum-docs:
    /// karyos/design/observability-and-tools.md`, "The sampling pass"): sets
    /// the odd `epoch`, then a Release fence orders it before every cell the
    /// pass writes.
    pub fn begin_pass(&self, epoch: u64) {
        self.set(epoch);
        fence(Ordering::Release);
    }

    /// Ends a sampling pass: a Release fence orders every cell the pass
    /// wrote before the even `epoch`.
    pub fn end_pass(&self, epoch: u64) {
        fence(Ordering::Release);
        self.set(epoch);
    }

    /// Reads a consistent snapshot, or reports the cell as changing after a
    /// bounded number of attempts. Never waits.
    #[must_use]
    pub fn read(&self) -> CellRead {
        read_cell(
            |index| self.word(index).map(|word| word.load(Ordering::Relaxed)),
            || self.value.load(Ordering::Relaxed),
        )
    }
}

/// The seqlock read of one cell over `Relaxed` load functions: `meta`
/// loads metadata word `index` (`None` out of range) and `value` the value
/// word. Only `Relaxed` loads and `Acquire` fences are issued, so the same
/// read works over a writable view or a read-only mapping, where Rust
/// guarantees only `Relaxed` loads.
pub(crate) fn read_cell(meta: impl Fn(usize) -> Option<u64>, value: impl Fn() -> u64) -> CellRead {
    if meta(META_VERSION).is_none() {
        return CellRead::Free;
    }
    for _ in 0..READ_ATTEMPTS {
        let before = meta(META_VERSION).unwrap_or(0);
        // Pairs with the writer's Release on the version: the reads below
        // see at least what that version published.
        fence(Ordering::Acquire);
        if before % 2 == 1 {
            continue;
        }
        let load = |index: usize| meta(index).unwrap_or(0);
        let state = load(META_STATE);
        let registration_id = load(META_REGISTRATION);
        let type_id = load(META_TYPE);
        let length = load(META_LABEL_LENGTH);
        let mut label = [0u8; MAX_LABEL_LENGTH];
        for (index, chunk) in label.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            *chunk = load(META_LABEL + index).to_le_bytes();
        }
        let mut keys = [0u64; KEY_WORDS];
        for (index, key) in keys.iter_mut().enumerate() {
            *key = load(META_KEYS + index);
        }
        let value = value();
        fence(Ordering::Acquire);
        if meta(META_VERSION) != Some(before) {
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
                let Some(keys) = CounterKeys::from_words(keys) else {
                    return CellRead::Changing;
                };
                CellRead::Allocated {
                    metadata: CounterMetadata {
                        registration_id,
                        type_id,
                        keys,
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

/// What a reader of a sampling pass got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassRead<R> {
    /// The values come from one completed pass.
    Consistent(R),
    /// Every attempt overlapped a pass: the values may mix passes. A tool
    /// shows them marked inconsistent and computes differences with
    /// checked arithmetic.
    Inconsistent(R),
}

/// The reader side of a sampling pass: loads the epoch with `epoch()` (a
/// `Relaxed` load) and issues an Acquire fence, runs `read` (`Relaxed`
/// loads of the pass's cells), issues an Acquire fence and loads the epoch
/// again; accepts when both loads are equal and even. After `attempts` (at
/// least one) failures it returns the last values as inconsistent. Only
/// `Relaxed` loads are needed, so the read works over read-only memory.
pub fn read_pass<R>(
    epoch: impl Fn() -> u64,
    mut read: impl FnMut() -> R,
    attempts: usize,
) -> PassRead<R> {
    let mut remaining = attempts.max(1);
    loop {
        let before = epoch();
        // Pairs with the Release fence of `begin_pass`/`end_pass`.
        fence(Ordering::Acquire);
        let values = read();
        fence(Ordering::Acquire);
        let after = epoch();
        if before.is_multiple_of(2) && before == after {
            return PassRead::Consistent(values);
        }
        remaining -= 1;
        if remaining == 0 {
            return PassRead::Inconsistent(values);
        }
    }
}

#[cfg(not(loom))]
pub use owned::{
    ClientCells, ClientCounter, Counter, CountersManager, CountersReader, client_counters, counters,
};
#[cfg(all(not(loom), target_os = "linux"))]
pub use owned::{LAYOUT_VERSION, client_counters_in, counters_in};

#[cfg(not(loom))]
mod owned {
    use std::sync::Arc;

    use super::{
        CellRead, CellWords, CounterError, CounterMetadata, META_WORDS, STATE_ALLOCATED,
        STATE_FREE, STATE_RELEASE_PENDING, STRIDE_WORDS,
    };
    use crate::atomic_view::HeapWords;
    use crate::error::SysError;
    use crate::sync::AtomicU64;
    #[cfg(target_os = "linux")]
    use crate::sync::Ordering;

    /// Where the cells live.
    #[derive(Debug)]
    enum Store {
        /// Two heap allocations of this process.
        Heap {
            values: HeapWords,
            metadata: HeapWords,
        },
        /// A shared region (Linux): a configuration line, the values and
        /// then the metadata (`quantstratum-docs: karyos/design/ipc-cnc-regions.md`).
        #[cfg(target_os = "linux")]
        Mapped(crate::ipc::Region),
        /// The same layout mapped read-only (Linux): readers only.
        #[cfg(target_os = "linux")]
        ReadOnly(crate::ipc::ReadOnlyRegion),
    }

    #[derive(Debug)]
    struct Region {
        store: Store,
        capacity: usize,
    }

    impl Region {
        /// The values and the metadata, `capacity` strides each.
        fn sections(&self) -> (&[AtomicU64], &[AtomicU64]) {
            match &self.store {
                Store::Heap { values, metadata } => {
                    (values.words().as_slice(), metadata.words().as_slice())
                }
                #[cfg(target_os = "linux")]
                Store::Mapped(region) => {
                    let words = region.structure().as_slice();
                    let section = self.capacity.saturating_mul(STRIDE_WORDS);
                    let values = words
                        .get(STRIDE_WORDS..)
                        .and_then(|rest| rest.get(..section))
                        .unwrap_or(&[]);
                    let metadata = words
                        .get(STRIDE_WORDS.saturating_add(section)..)
                        .and_then(|rest| rest.get(..section))
                        .unwrap_or(&[]);
                    (values, metadata)
                }
                // Only readers hold a read-only store; they read through
                // `read_only_cell`.
                #[cfg(target_os = "linux")]
                Store::ReadOnly(_) => (&[], &[]),
            }
        }

        /// Reads cell `index` of a read-only store with loads only.
        #[cfg(target_os = "linux")]
        fn read_only_cell(
            region: &crate::ipc::ReadOnlyRegion,
            capacity: usize,
            index: usize,
        ) -> CellRead {
            let words = region.structure();
            let section = capacity.saturating_mul(STRIDE_WORDS);
            let Some(start) = index.checked_mul(STRIDE_WORDS).filter(|_| index < capacity) else {
                return CellRead::Free;
            };
            let values = words.range(STRIDE_WORDS, section);
            let metadata = words.range(STRIDE_WORDS.saturating_add(section), section);
            let meta = metadata.range(start, META_WORDS);
            if meta.len() < META_WORDS {
                return CellRead::Free;
            }
            super::read_cell(|word| meta.load(word), || values.load(start).unwrap_or(0))
        }

        fn cell(&self, index: usize) -> Option<CellWords<'_>> {
            let (values, metadata) = self.sections();
            let start = index.checked_mul(STRIDE_WORDS)?;
            let meta = metadata.get(start..start.checked_add(META_WORDS)?)?;
            CellWords::new(meta, values.get(start)?)
        }
    }

    fn pair(region: Region) -> (CountersManager, CountersReader) {
        let region = Arc::new(region);
        (
            CountersManager {
                region: Arc::clone(&region),
                next_registration: 1,
            },
            CountersReader { region },
        )
    }

    /// The allocator, a reader and the client writer view of one client
    /// counters region.
    fn client_triple(region: Region) -> (CountersManager, CountersReader, ClientCells) {
        let (manager, reader) = pair(region);
        let cells = ClientCells {
            region: Arc::clone(&manager.region),
        };
        (manager, reader, cells)
    }

    /// The cells of `capacity` counters on the heap.
    fn heap(capacity: usize) -> Result<Region, SysError> {
        let words = capacity
            .checked_mul(STRIDE_WORDS)
            .ok_or(SysError::InvalidRegion { address: 0, len: 0 })?;
        Ok(Region {
            store: Store::Heap {
                values: HeapWords::zeroed(words)?,
                metadata: HeapWords::zeroed(words)?,
            },
            capacity,
        })
    }

    /// Creates a region of `capacity` counters: its single allocator and a
    /// reader (control path: allocates `2 * capacity` strides).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] for a zero or oversized capacity.
    pub fn counters(capacity: usize) -> Result<(CountersManager, CountersReader), SysError> {
        Ok(pair(heap(capacity)?))
    }

    /// Creates a client counters region of `capacity` counters on the heap
    /// (`quantstratum-docs: karyos/design/observability-and-tools.md`,
    /// "Client counters"): the driver's single allocator, a reader, and the
    /// writer view that in-process clients share (control path: allocates
    /// `2 * capacity` strides).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] for a zero or oversized capacity.
    pub fn client_counters(
        capacity: usize,
    ) -> Result<(CountersManager, CountersReader, ClientCells), SysError> {
        Ok(client_triple(heap(capacity)?))
    }

    /// Words of a counters region's structure: the configuration line and
    /// two sections of `capacity` strides.
    #[cfg(target_os = "linux")]
    fn structure_words(capacity: usize) -> Option<usize> {
        capacity
            .checked_mul(2 * STRIDE_WORDS)?
            .checked_add(STRIDE_WORDS)
    }

    /// Layout version of a counters region: 2 adds the key words
    /// (`quantstratum-docs: karyos/design/observability-and-tools.md`).
    /// Readers reject any other version.
    #[cfg(target_os = "linux")]
    pub const LAYOUT_VERSION: u64 = 2;

    /// Creates a region of `capacity` counters in a new shared region
    /// (driver side, `quantstratum-docs: karyos/design/ipc-cnc-regions.md`): its single
    /// allocator and a reader. Clients attach readers through
    /// [`CountersReader::region`].
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] for a zero or oversized capacity,
    /// and the errors of [`crate::ipc::Region::create`].
    #[cfg(target_os = "linux")]
    pub fn counters_in(
        instance: u128,
        region: u64,
        capacity: usize,
    ) -> Result<(CountersManager, CountersReader), SysError> {
        Ok(pair(mapped(
            instance,
            region,
            capacity,
            crate::ipc::RegionKind::Counters,
        )?))
    }

    /// Creates a client counters region of `capacity` counters in a new
    /// shared region (driver side; `quantstratum-docs:
    /// karyos/design/observability-and-tools.md`, "Client counters"): the
    /// layout of [`counters_in`] under the kind `ClientCounters`. Clients
    /// write their own cells, so the region keeps the size seals only
    /// ([`crate::ipc::Region::create`]), as a command ring does; clients
    /// attach it writable with `ClientCells::attach` (Linux).
    ///
    /// # Errors
    ///
    /// As [`counters_in`].
    #[cfg(target_os = "linux")]
    pub fn client_counters_in(
        instance: u128,
        region: u64,
        capacity: usize,
    ) -> Result<(CountersManager, CountersReader, ClientCells), SysError> {
        Ok(client_triple(mapped(
            instance,
            region,
            capacity,
            crate::ipc::RegionKind::ClientCounters,
        )?))
    }

    /// A new shared counters region of `kind`, its configuration line
    /// written.
    #[cfg(target_os = "linux")]
    fn mapped(
        instance: u128,
        region: u64,
        capacity: usize,
        kind: crate::ipc::RegionKind,
    ) -> Result<Region, SysError> {
        let invalid = SysError::InvalidRegion { address: 0, len: 0 };
        let structure_length = structure_words(capacity)
            .and_then(|words| words.checked_mul(crate::atomic_view::WORD_BYTES))
            .filter(|_| capacity > 0)
            .ok_or(invalid)?;
        let record = crate::ipc::RegionRecord {
            instance,
            region,
            kind,
            generation: 0,
            layout: LAYOUT_VERSION,
            structure_length,
        };
        let mapped = if kind == crate::ipc::RegionKind::Counters {
            // Only the driver writes this region: A2 seal order (owner
            // decision Q7), so clients and tools can map it only read-only.
            crate::ipc::Region::create_driver_only(record)?
        } else {
            crate::ipc::Region::create(record)?
        };
        mapped
            .structure()
            .get(0)
            .ok_or(invalid)?
            .store(capacity as u64, Ordering::Release);
        Ok(Region {
            store: Store::Mapped(mapped),
            capacity,
        })
    }

    /// Validates the record and the configuration line of an attached
    /// counters region (`load` reads structure word `index`) and returns its
    /// capacity: the kind must be one of `kinds`, the layout this one, the
    /// capacity nonzero, the unused words zero, and the layout must fill
    /// the region exactly.
    #[cfg(target_os = "linux")]
    fn configured_capacity(
        record: crate::ipc::RegionRecord,
        kinds: &[crate::ipc::RegionKind],
        load: impl Fn(usize) -> Option<u64>,
    ) -> Result<usize, SysError> {
        let invalid = SysError::InvalidRegion {
            address: 0,
            len: record.structure_length,
        };
        if !kinds.contains(&record.kind)
            || record.layout != LAYOUT_VERSION
            || record.generation != 0
        {
            return Err(invalid);
        }
        let mut config = [0u64; STRIDE_WORDS];
        for (index, word) in config.iter_mut().enumerate() {
            *word = load(index).ok_or(invalid)?;
        }
        let [capacity, rest @ ..] = config;
        let capacity = usize::try_from(capacity).map_err(|_| invalid)?;
        let structure_length = structure_words(capacity)
            .and_then(|words| words.checked_mul(crate::atomic_view::WORD_BYTES));
        if capacity == 0
            || rest.iter().any(|word| *word != 0)
            || structure_length != Some(record.structure_length)
        {
            return Err(invalid);
        }
        Ok(capacity)
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
            self.allocate_keyed(type_id, label, super::CounterKeys::DRIVER)
        }

        /// Allocates a counter with value 0 and its key words (control
        /// path).
        ///
        /// # Errors
        ///
        /// As [`CountersManager::allocate`].
        pub fn allocate_keyed(
            &mut self,
            type_id: u64,
            label: &str,
            keys: super::CounterKeys,
        ) -> Result<Counter, CounterError> {
            self.allocate_keyed_where(type_id, label, keys, |_| true)
        }

        /// Allocates as [`CountersManager::allocate_keyed`], considering
        /// only the cells for which `eligible` holds. A region that other
        /// processes can write (client counters) uses it to skip every cell
        /// the allocator still tracks, whatever its state word says.
        ///
        /// # Errors
        ///
        /// As [`CountersManager::allocate`].
        pub fn allocate_keyed_where(
            &mut self,
            type_id: u64,
            label: &str,
            keys: super::CounterKeys,
            eligible: impl Fn(usize) -> bool,
        ) -> Result<Counter, CounterError> {
            let next = self
                .next_registration
                .checked_add(1)
                .ok_or(CounterError::IdentitiesExhausted)?;
            let metadata =
                CounterMetadata::new(self.next_registration, type_id, label)?.with_keys(keys);
            let index = (0..self.region.capacity)
                .find(|&index| {
                    eligible(index)
                        && self.region.cell(index).is_some_and(|cell| {
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

        /// Stores `FREE` into cell `index`'s state word as a stray client
        /// write would, leaving its capability alive (tests, and dependent
        /// crates' tests through feature `test-hooks`).
        #[cfg(any(test, feature = "test-hooks"))]
        pub fn clobber_state_free(&self, index: usize) {
            if let Some(cell) = self.region.cell(index) {
                let _ = cell.free();
            }
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

        /// Begins a sampling pass with this counter as its epoch; see
        /// [`CellWords::begin_pass`].
        pub fn begin_pass(&self, epoch: u64) {
            if let Some(cell) = self.region.cell(self.index) {
                cell.begin_pass(epoch);
            }
        }

        /// Ends a sampling pass; see [`CellWords::end_pass`].
        pub fn end_pass(&self, epoch: u64) {
            if let Some(cell) = self.region.cell(self.index) {
                cell.end_pass(epoch);
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
        /// A reader of a counters region mapped read-only (client and tool
        /// side; owner decision Q7, A2: the driver creates it with
        /// `F_SEAL_FUTURE_WRITE`, so no other mapping can write), or of a
        /// client counters region, which has the same layout. The
        /// configuration line is read once: the capacity must be nonzero,
        /// the unused words zero, and the layout must fill the region
        /// exactly. Every cell read is validated as on the heap, with loads
        /// only.
        ///
        /// # Errors
        ///
        /// Returns [`SysError::InvalidRegion`] unless the region is a
        /// counters region of this layout that matches its configuration.
        #[cfg(target_os = "linux")]
        pub fn attach_read_only(region: crate::ipc::ReadOnlyRegion) -> Result<Self, SysError> {
            let structure = region.structure();
            let capacity = configured_capacity(
                region.record(),
                &[
                    crate::ipc::RegionKind::Counters,
                    crate::ipc::RegionKind::ClientCounters,
                ],
                |index| structure.load_acquire(index),
            )?;
            Ok(Self {
                region: Arc::new(Region {
                    store: Store::ReadOnly(region),
                    capacity,
                }),
            })
        }

        /// The shared region, to pass its descriptor; `None` on the heap.
        #[cfg(target_os = "linux")]
        #[must_use]
        pub fn region(&self) -> Option<&crate::ipc::Region> {
            match &self.region.store {
                Store::Mapped(region) => Some(region),
                Store::Heap { .. } | Store::ReadOnly(_) => None,
            }
        }

        /// Number of cells.
        #[must_use]
        pub fn capacity(&self) -> usize {
            self.region.capacity
        }

        /// Loads the value word of cell `index` alone with a `Relaxed`
        /// load, for a sampling pass ([`super::read_pass`]); `None` when
        /// out of range.
        #[must_use]
        pub fn load_value(&self, index: usize) -> Option<u64> {
            #[cfg(target_os = "linux")]
            if let Store::ReadOnly(region) = &self.region.store {
                // The value word of cell `index` follows the configuration
                // stride; a Relaxed load is valid on read-only memory.
                let word = index
                    .checked_mul(STRIDE_WORDS)
                    .filter(|_| index < self.region.capacity)?
                    .checked_add(STRIDE_WORDS)?;
                return region.structure().load(word);
            }
            self.region.cell(index).map(|cell| cell.load_value())
        }

        /// Reads cell `index`; `Free` when out of range.
        #[must_use]
        pub fn read(&self, index: usize) -> CellRead {
            #[cfg(target_os = "linux")]
            if let Store::ReadOnly(region) = &self.region.store {
                return Region::read_only_cell(region, self.region.capacity, index);
            }
            self.region
                .cell(index)
                .map_or(CellRead::Free, |cell| cell.read())
        }
    }

    /// The client writer view of a client counters region
    /// (`quantstratum-docs: karyos/design/observability-and-tools.md`,
    /// "Client counters"): it turns a cell the driver allocated for a client
    /// into that client's [`ClientCounter`]. In-process clients share the
    /// driver's region through [`client_counters`]; a client process attaches
    /// the region it received with `ClientCells::attach` (Linux).
    #[derive(Debug, Clone)]
    pub struct ClientCells {
        region: Arc<Region>,
    }

    impl ClientCells {
        /// The writer view of a client counters region attached writable
        /// (client side): the region must be a client counters region of
        /// this layout whose configuration line, read once, matches it, as
        /// [`CountersReader::attach_read_only`] checks.
        ///
        /// # Errors
        ///
        /// Returns [`SysError::InvalidRegion`] otherwise.
        #[cfg(target_os = "linux")]
        pub fn attach(region: crate::ipc::Region) -> Result<Self, SysError> {
            let capacity = {
                let structure = region.structure();
                configured_capacity(
                    region.record(),
                    &[crate::ipc::RegionKind::ClientCounters],
                    |index| {
                        structure
                            .get(index)
                            .map(|word| word.load(Ordering::Acquire))
                    },
                )?
            };
            Ok(Self {
                region: Arc::new(Region {
                    store: Store::Mapped(region),
                    capacity,
                }),
            })
        }

        /// Number of cells.
        #[must_use]
        pub fn capacity(&self) -> usize {
            self.region.capacity
        }

        /// The capability to write cell `cell`, only while the cell holds the
        /// allocation `registration` (allocated, not pending release); `None`
        /// otherwise. The driver allocated the cell for this client and frees
        /// it only on the client's release or exit proof.
        #[must_use]
        pub fn counter(&self, cell: usize, registration: u64) -> Option<ClientCounter> {
            match self.region.cell(cell)?.read() {
                CellRead::Allocated {
                    metadata,
                    release_pending: false,
                    ..
                } if metadata.registration_id == registration => Some(ClientCounter {
                    region: Arc::clone(&self.region),
                    index: cell,
                    registration_id: registration,
                }),
                _ => None,
            }
        }
    }

    /// A client's capability to update one cell of a client counters region
    /// (not `Clone`). It has no effect on the cell when dropped: the driver
    /// frees the cell on the client's `ReleaseCounter` or exit proof, so
    /// memory safety never depends on this drop.
    #[derive(Debug)]
    pub struct ClientCounter {
        region: Arc<Region>,
        index: usize,
        registration_id: u64,
    }

    impl ClientCounter {
        /// The cell index.
        #[must_use]
        pub fn cell(&self) -> usize {
            self.index
        }

        /// The allocation's registration id.
        #[must_use]
        pub fn registration(&self) -> u64 {
            self.registration_id
        }

        /// Adds `delta` with a checked Relaxed read-modify-write; never wraps
        /// or saturates.
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

        /// Sets the value with a Relaxed swap (gauges).
        pub fn set(&self, value: u64) {
            if let Some(cell) = self.region.cell(self.index) {
                cell.set(value);
            }
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
    fn keys_round_trip_and_a_bad_key1_is_never_accepted() {
        let (mut manager, reader) = counters(2).unwrap();
        let keys = CounterKeys {
            stream: u64::MAX,
            lane: 0xFF,
            kind: KIND_CLIENT,
            participant: 7,
        };
        let keyed = manager
            .allocate_keyed(TYPE_TIMESTAMP, "positions sampled at", keys)
            .unwrap();
        let CellRead::Allocated { metadata, .. } = reader.read(keyed.index()) else {
            panic!("expected an allocated cell");
        };
        assert_eq!(metadata.keys, keys);
        let plain = manager.allocate(TYPE_EVENT, "events").unwrap();
        let CellRead::Allocated { metadata, .. } = reader.read(plain.index()) else {
            panic!("expected an allocated cell");
        };
        assert_eq!(metadata.keys, CounterKeys::DRIVER);
        // key1 bits above 15 are reserved: a cell carrying them is never
        // accepted as a snapshot.
        let meta: Vec<AtomicU64> = (0..META_WORDS).map(|_| AtomicU64::new(0)).collect();
        let value = AtomicU64::new(0);
        let cell = CellWords::new(&meta, &value).unwrap();
        cell.allocate(&CounterMetadata::new(1, TYPE_EVENT, "x").unwrap())
            .unwrap();
        meta[META_KEYS + 1].store(1 << 16, Ordering::Relaxed);
        assert_eq!(cell.read(), CellRead::Changing);
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
    fn allocation_considers_only_eligible_cells() {
        let (mut manager, _reader, _cells) = client_counters(3).unwrap();
        // Cell 0 is free but not eligible: the allocator still holds it.
        let counter = manager
            .allocate_keyed_where(TYPE_EVENT, "x", CounterKeys::DRIVER, |index| index != 0)
            .unwrap();
        assert_eq!(counter.index(), 1);
        // A stray client write marks the held cell 0 free: a plain
        // allocation would hand it to a second owner, the eligibility check
        // does not.
        let held = manager
            .allocate_keyed_where(TYPE_EVENT, "held", CounterKeys::DRIVER, |_| true)
            .unwrap();
        assert_eq!(held.index(), 0);
        manager.clobber_state_free(0);
        let other = manager
            .allocate_keyed_where(TYPE_EVENT, "z", CounterKeys::DRIVER, |index| {
                index != held.index() && index != counter.index()
            })
            .unwrap();
        assert_eq!(other.index(), 2);
        // With no eligible free cell, the region is exhausted.
        assert_eq!(
            manager
                .allocate_keyed_where(TYPE_EVENT, "y", CounterKeys::DRIVER, |index| index == 1)
                .unwrap_err(),
            CounterError::Exhausted
        );
    }

    #[test]
    fn client_cells_write_only_the_exact_allocation() {
        let (mut manager, reader, cells) = client_counters(2).unwrap();
        assert_eq!(cells.capacity(), 2);
        // A free cell gives no capability.
        assert!(cells.counter(0, 1).is_none());
        let allocated = manager
            .allocate_keyed(
                TYPE_EVENT,
                "messages dropped",
                CounterKeys {
                    stream: 4,
                    lane: 1,
                    kind: KIND_SUBSCRIBER,
                    participant: 9,
                },
            )
            .unwrap();
        let (cell, registration) = (allocated.index(), allocated.registration_id());
        assert!(cells.counter(cell, registration + 1).is_none());
        assert!(cells.counter(2, registration).is_none());
        let counter = cells.counter(cell, registration).unwrap();
        assert_eq!(
            (counter.cell(), counter.registration()),
            (cell, registration)
        );
        assert_eq!(counter.increment(3), Ok(3));
        counter.set(u64::MAX - 1);
        assert_eq!(counter.increment(2), Err(CounterError::Overflow));
        assert_eq!(counter.increment(1), Ok(u64::MAX));
        let CellRead::Allocated {
            metadata, value, ..
        } = reader.read(cell)
        else {
            panic!("expected an allocated cell");
        };
        assert_eq!(value, u64::MAX);
        assert_eq!(metadata.keys.participant, 9);
        // Dropping the client's capability changes nothing in the cell.
        drop(counter);
        assert!(matches!(
            reader.read(cell),
            CellRead::Allocated {
                release_pending: false,
                ..
            }
        ));
        // Once the driver freed the cell, the old allocation gives nothing,
        // and a reuse has its own registration.
        manager.free(allocated).unwrap();
        assert!(cells.counter(cell, registration).is_none());
        let reused = manager.allocate(TYPE_EVENT, "again").unwrap();
        assert_eq!(reused.index(), cell);
        assert!(cells.counter(cell, registration).is_none());
        assert!(cells.counter(cell, reused.registration_id()).is_some());
        // A capability the driver dropped (pending release) gives nothing.
        let reused_id = reused.registration_id();
        drop(reused);
        assert!(cells.counter(cell, reused_id).is_none());
        assert!(client_counters(0).is_err());
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
