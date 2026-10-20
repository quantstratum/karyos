// SPDX-License-Identifier: Apache-2.0

//! Keyed conflation table (SPEC.md §7.1, ADR-0017; design in
//! `quantstratum-docs: karyos/design/keyed-conflation.md`): one fixed-size slot per dense `u32`
//! key, one writer, any number of readers that see the latest coherent value
//! of each key and may skip intermediate ones.
//!
//! Each table slot ([`FreshSlotWords`], table layout version 2) is a
//! sequence word, a value version word, a length word, the two freshness
//! words of [`SlotFreshness`] (`quantstratum-docs:
//! karyos/design/gaps-and-unreliable-delivery.md`, GU-8) and the value
//! words, on its own 128-byte strides. Slots use the fence-based seqlock
//! with atomic data words (Boehm, "Can seqlocks get along with programming
//! language memory models?", MSPC 2012) on the sequence: the writer stores
//! the odd sequence (Relaxed), issues a Release fence, stores the other
//! words (Relaxed) and stores the next even sequence (Release). A reader
//! loads the sequence (Acquire), copies the other words (Relaxed) into
//! private storage, issues an Acquire fence and reloads the sequence
//! (Relaxed); it uses the copy only if both loads saw the same even
//! sequence. If the copy contains a word of a later write, that write's
//! Release fence synchronizes with the reader's Acquire fence, so the second
//! load sees at least that write's odd sequence and the copy is rejected. A
//! value write advances the value version by 2 (even, nonzero once
//! written); a freshness-only write advances the sequence alone.
//!
//! Every word is accessed only atomically, so a reader racing the writer
//! copies stale or mixed values and discards them, never a data race.
//!
//! After each value write the writer appends `(key, value version)` to an
//! update journal (a broadcast buffer). A reader queues the keys it reads
//! from the journal; when the journal laps it, entries were lost and it
//! scans the slots' value versions instead. A slot whose sequence is odd
//! (mid-write, a freshness-only write included) stays queued until it
//! settles. Freshness-only changes reach readers through the loss barrier
//! ([`crate::freshness`]), not through the journal. Every poll is bounded by a key budget and a retry
//! budget, and pending keys are served in FIFO order, so a slot that stays
//! unstable cannot stall a poll or starve the other keys.
//!
//! A heap table built with [`conflation_fresh`] (a network image's view)
//! has a loss barrier: its writer records losses before the receive owner
//! seals them, reconciles the slots and retires the records, and its
//! readers deliver each value with its [`crate::freshness::Freshness`]. A
//! reader keeps the newest loss sequence it saw and serves every written
//! key again after a new one, so a freshness change reaches it without a
//! new value version. A table without a barrier, every IPC table included
//! (an IPC stream has no loss), delivers every value Fresh.
//!
//! [`SlotWords`] (the version-1 slot, which the record journal keeps),
//! [`FreshSlotWords`] and their functions are the protocols over any atomic
//! words (also checked with Loom); [`conflation`] builds the owned, safe API
//! over heap memory.

use crate::freshness::SlotFreshness;
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
    /// A value of a table with a loss barrier written without its stream
    /// position: its freshness cannot be told (use
    /// `ConflationWriter::write_at`). Nothing is stored.
    #[error("a table with a loss barrier needs each value's position")]
    PositionRequired,
    /// A value below the writer's frontier: a gap behind the frontier may
    /// already be retired, so its freshness cannot be told. A feeder writes
    /// in log order: `passed(position)`, then `write_at` at that position.
    /// Nothing is stored.
    #[error("value at {position} below the frontier {frontier}")]
    BehindFrontier {
        /// The value's position.
        position: u64,
        /// The writer's frontier.
        frontier: u64,
    },
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
    /// The shape of this table that its publications check: its keys and
    /// its largest value.
    ///
    /// # Errors
    ///
    /// [`ConflationError::ValueTooLarge`] for a value capacity past `u32`,
    /// which no message carries (SPEC §14: refused, not saturated).
    // Loom builds leave `log_buffer` out, and model no publication.
    #[cfg(not(loom))]
    pub fn shape(&self) -> Result<crate::log_buffer::ConflationShape, ConflationError> {
        let value_capacity = u32::try_from(self.value_capacity).map_err(|_| {
            // A capacity past u32 holds on this target, so u32::MAX does.
            usize::try_from(u32::MAX).map_or(ConflationError::InvalidConfig, |max| {
                ConflationError::ValueTooLarge {
                    length: self.value_capacity,
                    max,
                }
            })
        })?;
        Ok(crate::log_buffer::ConflationShape::new(
            self.keys,
            value_capacity,
        ))
    }

    /// Checks a publication's reserved value and payload length before it
    /// attempts a reservation, as [`ConflationShape::validate_publication`]
    /// of [`ConflationConfig::shape`].
    ///
    /// [`ConflationShape::validate_publication`]:
    ///     crate::log_buffer::ConflationShape::validate_publication
    ///
    /// # Errors
    ///
    /// As [`ConflationConfig::shape`], then as
    /// [`ConflationShape::validate_publication`].
    #[cfg(not(loom))]
    pub fn validate_publication(
        &self,
        reserved_value: i64,
        value_length: usize,
    ) -> Result<(), ConflationError> {
        self.shape()?
            .validate_publication(reserved_value, value_length)
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
        let stored_length =
            u64::try_from(value.len()).map_err(|_| ConflationError::InvalidConfig)?;
        // Only this writer stores the version, so it is even here.
        let current = version.load(Ordering::Relaxed);
        let (Some(odd), Some(even)) = (current.checked_add(1), current.checked_add(2)) else {
            return Err(ConflationError::VersionsExhausted);
        };
        version.store(odd, Ordering::Relaxed);
        fence(Ordering::Release);
        if let Some(length) = self.word(LENGTH) {
            length.store(stored_length, Ordering::Relaxed);
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

/// Word index of a fresh slot's seqlock sequence.
const FRESH_SEQ: usize = 0;
/// Word index of a fresh slot's public value version.
const FRESH_VERSION: usize = 1;
/// Word index of a fresh slot's value length.
const FRESH_LENGTH: usize = 2;
/// Word index of a fresh slot's applied loss sequence ([`SlotFreshness`]).
const FRESH_APPLIED: usize = 3;
/// Word index of a fresh slot's stale start.
const FRESH_STALE_SINCE: usize = 4;
/// Word index of a fresh slot's first value word.
const FRESH_VALUE: usize = 5;

/// The words of one slot of a conflation view with freshness (`quantstratum-docs:
/// karyos/design/gaps-and-unreliable-delivery.md`, GU-8): a seqlock
/// sequence, the public value version, the length, the two freshness words
/// of [`SlotFreshness`] and the value words.
///
/// One fence-based seqlock on the sequence covers every other word, as for
/// [`SlotWords`]: a reader that validates the copy sees the value and its
/// freshness coherent. A value write advances the value version; a
/// freshness-only write ([`FreshSlotWords::set_freshness`]) advances the
/// sequence but not the value version, so application versions count value
/// replacements only. The single-writer preconditions of [`SlotWords`]
/// apply.
#[derive(Debug, Clone, Copy)]
pub struct FreshSlotWords<'a> {
    words: &'a [AtomicU64],
}

/// What a fresh slot read found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshRead {
    /// The key was never written.
    Empty,
    /// A write was in progress, or the copy was overwritten; retry later.
    Unstable,
    /// A coherent value was copied, with its freshness words.
    Value {
        /// Its value version (even, nonzero).
        version: u64,
        /// Bytes copied into the caller's buffer.
        length: usize,
        /// The slot's freshness words, coherent with the value.
        freshness: SlotFreshness,
    },
}

impl<'a> FreshSlotWords<'a> {
    /// Wraps a slot's words: the five header words and at least one value
    /// word.
    #[must_use]
    pub fn new(words: &'a [AtomicU64]) -> Option<Self> {
        (words.len() > FRESH_VALUE).then_some(Self { words })
    }

    /// Value capacity in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        (self.words.len() - FRESH_VALUE) * WORD_BYTES
    }

    fn word(&self, index: usize) -> Option<&'a AtomicU64> {
        self.words.get(index)
    }

    /// The current value version, for a scan (Relaxed: it only decides
    /// whether the key is read again).
    #[must_use]
    pub fn version(&self) -> u64 {
        self.word(FRESH_VERSION)
            .map_or(0, |word| word.load(Ordering::Relaxed))
    }

    /// Whether one more value write fits both the sequence and the value
    /// version space.
    #[must_use]
    pub fn can_write(&self) -> bool {
        [FRESH_SEQ, FRESH_VERSION].iter().all(|&index| {
            self.word(index)
                .is_some_and(|word| word.load(Ordering::Relaxed).checked_add(2).is_some())
        })
    }

    /// Writes `value`, keeping the freshness words. Returns the new value
    /// version.
    ///
    /// The value version advances by 2, checked, so public versions stay
    /// the even, nonzero sequence of layout 1 (2, 4, 6, ...): readers keep
    /// 0 as "never written" and compare delivered versions and journal
    /// records as before. The seqlock has its own word, so the value
    /// version is never odd as a lock state.
    ///
    /// # Errors
    ///
    /// [`ConflationError::ValueTooLarge`] and
    /// [`ConflationError::VersionsExhausted`]; nothing is stored on error.
    pub fn write(&self, value: &[u8]) -> Result<u64, ConflationError> {
        self.write_value(value, None)
    }

    /// Writes `value` and the freshness words together, in one seqlock
    /// write: a replacement and the freshness it restores or keeps are
    /// never seen apart (GU-8). Returns the new value version.
    ///
    /// # Errors
    ///
    /// As [`FreshSlotWords::write`]; nothing is stored on error.
    pub fn write_with_freshness(
        &self,
        value: &[u8],
        freshness: SlotFreshness,
    ) -> Result<u64, ConflationError> {
        self.write_value(value, Some(freshness))
    }

    /// The freshness words, as the single writer last stored them
    /// (Relaxed: the writer's own words).
    #[must_use]
    pub fn freshness(&self) -> SlotFreshness {
        let load = |index| {
            self.word(index)
                .map_or(0, |word| word.load(Ordering::Relaxed))
        };
        SlotFreshness {
            loss_applied: load(FRESH_APPLIED),
            stale_since: load(FRESH_STALE_SINCE),
        }
    }

    fn write_value(
        &self,
        value: &[u8],
        freshness: Option<SlotFreshness>,
    ) -> Result<u64, ConflationError> {
        if value.len() > self.capacity() {
            return Err(ConflationError::ValueTooLarge {
                length: value.len(),
                max: self.capacity(),
            });
        }
        let version = self
            .word(FRESH_VERSION)
            .ok_or(ConflationError::InvalidConfig)?;
        let next = version
            .load(Ordering::Relaxed)
            .checked_add(2)
            .ok_or(ConflationError::VersionsExhausted)?;
        let stored_length =
            u64::try_from(value.len()).map_err(|_| ConflationError::InvalidConfig)?;
        self.locked(|| {
            version.store(next, Ordering::Relaxed);
            if let Some(length) = self.word(FRESH_LENGTH) {
                length.store(stored_length, Ordering::Relaxed);
            }
            for (index, chunk) in value.chunks(WORD_BYTES).enumerate() {
                let mut bytes = [0u8; WORD_BYTES];
                if let Some(prefix) = bytes.get_mut(..chunk.len()) {
                    prefix.copy_from_slice(chunk);
                }
                if let Some(word) = self.word(FRESH_VALUE + index) {
                    word.store(u64::from_le_bytes(bytes), Ordering::Relaxed);
                }
            }
            if let Some(freshness) = freshness {
                if let Some(word) = self.word(FRESH_APPLIED) {
                    word.store(freshness.loss_applied, Ordering::Relaxed);
                }
                if let Some(word) = self.word(FRESH_STALE_SINCE) {
                    word.store(freshness.stale_since, Ordering::Relaxed);
                }
            }
        })?;
        Ok(next)
    }

    /// Writes the freshness words only: the sequence advances, the value
    /// version does not.
    ///
    /// # Errors
    ///
    /// [`ConflationError::VersionsExhausted`]; nothing is stored on error.
    pub fn set_freshness(&self, freshness: SlotFreshness) -> Result<(), ConflationError> {
        self.locked(|| {
            if let Some(word) = self.word(FRESH_APPLIED) {
                word.store(freshness.loss_applied, Ordering::Relaxed);
            }
            if let Some(word) = self.word(FRESH_STALE_SINCE) {
                word.store(freshness.stale_since, Ordering::Relaxed);
            }
        })
    }

    /// Runs `body`'s Relaxed stores inside one seqlock write: the odd
    /// sequence (Relaxed), a Release fence, the body, the next even
    /// sequence (Release).
    fn locked(&self, body: impl FnOnce()) -> Result<(), ConflationError> {
        let seq = self.word(FRESH_SEQ).ok_or(ConflationError::InvalidConfig)?;
        // Only this writer stores the sequence, so it is even here.
        let current = seq.load(Ordering::Relaxed);
        let (Some(odd), Some(even)) = (current.checked_add(1), current.checked_add(2)) else {
            return Err(ConflationError::VersionsExhausted);
        };
        seq.store(odd, Ordering::Relaxed);
        fence(Ordering::Release);
        body();
        seq.store(even, Ordering::Release);
        Ok(())
    }

    /// Copies the current value and freshness into `out` if coherent. See
    /// [`read_fresh_slot`].
    #[must_use]
    pub fn read(&self, out: &mut [u8]) -> FreshRead {
        read_fresh_slot(&self.words, out)
    }
}

/// The fresh slot reader over any words a reader can load: the protocol of
/// [`read_slot`] on the sequence, copying the value version, length,
/// freshness words and value words in between.
#[must_use]
pub fn read_fresh_slot<W: LoadWords>(words: &W, out: &mut [u8]) -> FreshRead {
    let Some(capacity) = words
        .len()
        .checked_sub(FRESH_VALUE)
        .and_then(|value_words| value_words.checked_mul(WORD_BYTES))
    else {
        return FreshRead::Unstable;
    };
    let Some(first) = words.load_acquire(FRESH_SEQ) else {
        return FreshRead::Unstable;
    };
    if first % 2 == 1 {
        return FreshRead::Unstable;
    }
    let (Some(version), Some(length), Some(loss_applied), Some(stale_since)) = (
        words.load(FRESH_VERSION),
        words.load(FRESH_LENGTH),
        words.load(FRESH_APPLIED),
        words.load(FRESH_STALE_SINCE),
    ) else {
        return FreshRead::Unstable;
    };
    let copied = usize::try_from(length)
        .ok()
        .filter(|&length| length <= capacity && length <= out.len());
    if let Some(target) = copied.and_then(|copied| out.get_mut(..copied)) {
        for (index, chunk) in target.chunks_mut(WORD_BYTES).enumerate() {
            if let Some(word) = words.load(FRESH_VALUE + index) {
                let bytes = word.to_le_bytes();
                if let Some(prefix) = bytes.get(..chunk.len()) {
                    chunk.copy_from_slice(prefix);
                }
            }
        }
    }
    fence(Ordering::Acquire);
    if words.load(FRESH_SEQ) != Some(first) {
        return FreshRead::Unstable;
    }
    if version == 0 {
        return FreshRead::Empty;
    }
    // Value versions are even (the writer advances them by 2): an odd one
    // is not a version this protocol wrote.
    if version % 2 == 1 {
        return FreshRead::Unstable;
    }
    match copied {
        Some(length) => FreshRead::Value {
            version,
            length,
            freshness: SlotFreshness {
                loss_applied,
                stale_since,
            },
        },
        None => FreshRead::Unstable,
    }
}

#[cfg(not(loom))]
pub use owned::{
    Budget, ConflationReader, ConflationWriter, FreshCounters, LossError, PollReport, conflation,
    conflation_fresh,
};

#[cfg(all(not(loom), target_os = "linux"))]
pub use owned::{LAYOUT_VERSION, conflation_in};

#[cfg(not(loom))]
mod owned {
    use std::sync::Arc;

    use super::{
        ConflationConfig, ConflationError, FRESH_SEQ, FRESH_VALUE, FRESH_VERSION, FreshRead,
        FreshSlotWords, STRIDE_WORDS, WORD_BYTES, read_fresh_slot,
    };
    use crate::atomic_view::HeapWords;
    use crate::broadcast::{
        BroadcastError, BroadcastReader, BroadcastWords, MIN_CAPACITY, Receive, TRAILER_WORDS,
    };
    use crate::freshness::{
        BarrierSnapshot, BarrierWords, DEFAULT_RING, Freshness, FreshnessError, FreshnessLink,
        STALE, SlotFreshness, TERMINAL_BELOW_FRONTIER, TERMINAL_FRESHNESS_EXHAUSTED, Terminal,
        TerminalCell, barrier_words,
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
    /// Version 2: slots carry the freshness words (GU-8).
    pub const LAYOUT_VERSION: u64 = 2;

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
                .checked_add(FRESH_VALUE)?
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
        fn config_line(&self) -> Option<[u64; 4]> {
            Some([
                u64::from(self.keys),
                u64::try_from(self.value_capacity).ok()?,
                u64::try_from(self.slot_words).ok()?,
                u64::try_from(self.journal_capacity).ok()?,
            ])
        }
    }

    #[cfg(target_os = "linux")]
    impl ConflationConfig {
        /// Bytes of the structure of a table region of this configuration
        /// ([`conflation_in`]); `None` for a configuration it refuses. A
        /// view compares a region's length with it before mapping it.
        #[must_use]
        pub fn structure_length(&self) -> Option<usize> {
            Geometry::new(self.keys, self.value_capacity, self.journal_capacity)?.structure_length()
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

        /// The current value version, for a scan (Relaxed, as
        /// [`FreshSlotWords::version`]).
        fn version(&self, key: u32) -> u64 {
            self.slot(key)
                .and_then(|slot| slot.load(FRESH_VERSION))
                .unwrap_or(0)
        }

        /// Whether the slot's seqlock is mid-write (Relaxed, as
        /// [`View::version`]): a freshness-only write leaves the value
        /// version unchanged, so the sweep keeps such a key queued until it
        /// settles.
        fn unsettled(&self, key: u32) -> bool {
            self.slot(key)
                .and_then(|slot| slot.load(FRESH_SEQ))
                .is_some_and(|seq| seq % 2 == 1)
        }

        fn read(&self, key: u32, out: &mut [u8]) -> Option<FreshRead> {
            Some(read_fresh_slot(&self.slot(key)?, out))
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

    /// The loss barrier of a heap table and the link it shares with the
    /// image's receive owner (`quantstratum-docs:
    /// karyos/design/conflated-network-images.md`). A mapped table has
    /// none: an IPC stream has no loss, so its values read Fresh.
    #[derive(Debug)]
    struct Barrier {
        words: HeapWords,
        link: FreshnessLink,
    }

    #[derive(Debug)]
    struct Table {
        store: Store,
        geometry: Geometry,
        barrier: Option<Barrier>,
    }

    impl Table {
        /// The barrier's words, with a barrier.
        fn barrier_words(&self) -> Option<&[AtomicU64]> {
            self.barrier
                .as_ref()
                .map(|barrier| barrier.words.words().as_slice())
        }

        /// The view's terminal cell words, with a barrier.
        fn terminal_words(&self) -> Option<&[AtomicU64]> {
            self.barrier
                .as_ref()
                .map(|barrier| barrier.link.terminal_words())
        }

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

        fn slot(&self, key: u32) -> Option<FreshSlotWords<'_>> {
            FreshSlotWords::new(self.view()?.slot(key)?)
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

    impl Source {
        /// The barrier's and the terminal cell's words of a heap table
        /// with a barrier; `None` otherwise (an IPC table has no loss, so
        /// its values read Fresh).
        fn barrier(&self) -> Option<(&[AtomicU64], &[AtomicU64])> {
            match self {
                Source::Local(table) => Some((table.barrier_words()?, table.terminal_words()?)),
                #[cfg(target_os = "linux")]
                Source::ReadOnly(_) => None,
            }
        }
    }

    /// A delivered value's freshness, as a reader records it: [`FRESH`] or
    /// the stale start.
    const FRESH: u64 = u64::MAX;

    fn freshness_code(freshness: Freshness) -> u64 {
        match freshness {
            Freshness::Stale { since } => since,
            Freshness::Fresh | Freshness::Retry => FRESH,
        }
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
        let fresh = table.barrier.is_some().then(|| {
            Box::new(FreshState {
                frontier: 0,
                ahead: Vec::with_capacity(DEFAULT_RING),
                unretired: Vec::with_capacity(DEFAULT_RING),
                pass: None,
                counters: FreshCounters::default(),
            })
        });
        ConflationWriter {
            table: Arc::new(table),
            value_capacity,
            closed: false,
            fresh,
        }
    }

    /// Why [`ConflationWriter::record_loss`] recorded nothing.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    pub enum LossError {
        /// The table has no loss barrier ([`conflation`], or a region).
        #[error("the table has no loss barrier")]
        NoBarrier,
        /// An empty or reversed interval.
        #[error("invalid loss interval [{start}, {end})")]
        InvalidInterval {
            /// The interval start.
            start: u64,
            /// The interval end.
            end: u64,
        },
        /// The loss ring or the gaps ahead of the frontier are full: retry
        /// after a reconciliation retires records. A feeder withholds its
        /// acknowledgement meanwhile.
        #[error("loss records full")]
        Full,
        /// The interval starts below the writer's frontier: every value
        /// already written would not lie below it, which readers'
        /// classification assumes. The terminal cell was published (if no
        /// other publisher won it) and the view is done.
        #[error("loss at {start} below the frontier {frontier}")]
        BelowFrontier {
            /// The interval start.
            start: u64,
            /// The writer's frontier.
            frontier: u64,
        },
        /// The loss sequence or the barrier version is exhausted: the
        /// terminal cell was published (if no other publisher won it).
        #[error("loss sequence exhausted")]
        Exhausted,
    }

    /// The freshness work of a writer (GU-11). Increments are checked: one
    /// that would overflow keeps its value.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct FreshCounters {
        /// Losses recorded in the barrier.
        pub losses: u64,
        /// Losses refused while the ring or the gaps ahead were full.
        pub full: u64,
        /// Losses below the frontier, each closing the view terminally.
        pub below_frontier: u64,
        /// Slot reconciliations written.
        pub reconciled: u64,
        /// Retirements published, each after a full pass over the slots.
        pub retirements: u64,
        /// Losses refused because the loss sequence or the barrier version
        /// was exhausted, and slot sequences exhausted by a reconciliation,
        /// each closing the view terminally.
        pub exhausted: u64,
    }

    fn bump(counter: &mut u64) {
        if let Some(next) = counter.checked_add(1) {
            *counter = next;
        }
    }

    /// The writer's freshness state: the frontier, the recorded gaps still
    /// ahead of it and the records not yet retired, each bounded by the
    /// ring.
    #[derive(Debug)]
    struct FreshState {
        /// The stream position below which the feeder consumed the log.
        frontier: u64,
        /// Recorded gaps `[start, end)` whose end is above the frontier.
        ahead: Vec<(u64, u64)>,
        /// Recorded losses not yet retired, as `(seq, start)`.
        unretired: Vec<(u64, u64)>,
        /// The reconciliation pass in progress: through which sequence, and
        /// the next key.
        pass: Option<(u64, u32)>,
        counters: FreshCounters,
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
        heap(keys, value_capacity, journal_capacity, None)
    }

    /// Creates a table as [`conflation`] with a loss barrier of
    /// [`DEFAULT_RING`] records over the terminal cell of `link`: the view
    /// of a network image's lane (`quantstratum-docs:
    /// karyos/design/conflated-network-images.md`). Its writer records
    /// losses ([`ConflationWriter::record_loss`]), and its readers report
    /// each value's freshness.
    ///
    /// # Errors
    ///
    /// As [`conflation`].
    pub fn conflation_fresh(
        keys: u32,
        value_capacity: usize,
        journal_capacity: usize,
        link: FreshnessLink,
    ) -> Result<ConflationWriter, ConflationError> {
        heap(keys, value_capacity, journal_capacity, Some(link))
    }

    fn heap(
        keys: u32,
        value_capacity: usize,
        journal_capacity: usize,
        link: Option<FreshnessLink>,
    ) -> Result<ConflationWriter, ConflationError> {
        let invalid = ConflationError::InvalidConfig;
        let geometry = Geometry::new(keys, value_capacity, journal_capacity).ok_or(invalid)?;
        let zeroed = |count| HeapWords::zeroed(count).map_err(|_| invalid);
        let barrier = match link {
            Some(link) => Some(Barrier {
                words: zeroed(barrier_words(DEFAULT_RING).ok_or(invalid)?)?,
                link,
            }),
            None => None,
        };
        let table = Table {
            store: Store::Heap {
                slots: zeroed(geometry.slots_words)?,
                data: zeroed(geometry.journal_words)?,
                trailer: zeroed(TRAILER_WORDS)?,
            },
            geometry,
            barrier,
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
        let line = geometry.config_line().ok_or(invalid)?;
        for (index, value) in line.into_iter().enumerate() {
            structure
                .get(index)
                .ok_or(invalid)?
                .store(value, Ordering::Release);
        }
        let table = Table {
            store: Store::Mapped(mapped),
            geometry,
            barrier: None,
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
        /// The freshness state of a table with a barrier.
        fresh: Option<Box<FreshState>>,
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
        ///
        /// A table with a loss barrier refuses it with
        /// [`ConflationError::PositionRequired`]: its values go through
        /// [`ConflationWriter::write_at`].
        pub fn write(&mut self, key: u32, value: &[u8]) -> Result<u64, ConflationError> {
            if self.fresh.is_some() {
                return Err(ConflationError::PositionRequired);
            }
            self.write_slot(key, value, None)
        }

        /// Writes the value of `key` that starts at stream `position`, with
        /// its freshness (GU-9): Stale since the earliest recorded gap still
        /// ahead whose end lies above `position`, else Fresh, through the
        /// newest loss. A replacement past every gap restores its key; it
        /// restores no other. Without a barrier, as [`ConflationWriter::write`].
        ///
        /// The value lies at or above the frontier: a feeder calls
        /// [`ConflationWriter::passed`] with a value's position, then this.
        ///
        /// # Errors
        ///
        /// As [`ConflationWriter::write`], and
        /// [`ConflationError::BehindFrontier`] for a value below the
        /// frontier. Nothing is stored on error.
        pub fn write_at(
            &mut self,
            key: u32,
            value: &[u8],
            position: u64,
        ) -> Result<u64, ConflationError> {
            let freshness = match (&self.fresh, self.table.barrier_words()) {
                (Some(fresh), Some(words)) => {
                    if position < fresh.frontier {
                        return Err(ConflationError::BehindFrontier {
                            position,
                            frontier: fresh.frontier,
                        });
                    }
                    let barrier = BarrierWords::new(words, DEFAULT_RING)
                        .map_err(|_| ConflationError::InvalidConfig)?;
                    let since = fresh
                        .ahead
                        .iter()
                        .filter(|&&(_, end)| end > position)
                        .map(|&(start, _)| start)
                        .min();
                    Some(SlotFreshness {
                        loss_applied: since
                            .map_or(barrier.loss_seq(), |_| barrier.loss_seq() | STALE),
                        stale_since: since.unwrap_or(0),
                    })
                }
                _ => None,
            };
            self.write_slot(key, value, freshness)
        }

        fn write_slot(
            &mut self,
            key: u32,
            value: &[u8],
            freshness: Option<SlotFreshness>,
        ) -> Result<u64, ConflationError> {
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
            let written = match freshness {
                Some(freshness) => slot.write_with_freshness(value, freshness),
                None => slot.write(value),
            };
            let version = match written {
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

        /// Records the loss of `[start, end)` (GU-8 step 1): appends it to
        /// the barrier and publishes it, so readers classify every value
        /// below its end Stale before any slot is reconciled. Call before
        /// the receive owner seals the gap, then [`ConflationWriter::reconcile`]
        /// until done. Returns the loss sequence.
        ///
        /// The interval must start at or above the frontier
        /// ([`ConflationWriter::passed`]): readers classify a value against
        /// a record it has not applied without its position, which is exact
        /// only because every value already written lies below a new gap.
        /// A loss below the frontier publishes the terminal cell instead.
        ///
        /// # Errors
        ///
        /// [`LossError::NoBarrier`], [`LossError::InvalidInterval`],
        /// [`LossError::Full`] (retry later; nothing stored),
        /// [`LossError::BelowFrontier`] and [`LossError::Exhausted`] (the
        /// terminal cell published).
        pub fn record_loss(&mut self, start: u64, end: u64) -> Result<u64, LossError> {
            if start >= end {
                return Err(LossError::InvalidInterval { start, end });
            }
            let (Some(fresh), Some(words)) = (self.fresh.as_mut(), self.table.barrier_words())
            else {
                return Err(LossError::NoBarrier);
            };
            if start < fresh.frontier {
                bump(&mut fresh.counters.below_frontier);
                let frontier = fresh.frontier;
                self.close_terminally(start, end, TERMINAL_BELOW_FRONTIER);
                return Err(LossError::BelowFrontier { start, frontier });
            }
            if fresh.ahead.len() >= DEFAULT_RING || fresh.unretired.len() >= DEFAULT_RING {
                bump(&mut fresh.counters.full);
                return Err(LossError::Full);
            }
            let barrier =
                BarrierWords::new(words, DEFAULT_RING).map_err(|_| LossError::NoBarrier)?;
            match barrier.append_loss(start, end) {
                Ok(seq) => {
                    fresh.ahead.push((start, end));
                    fresh.unretired.push((seq, start));
                    bump(&mut fresh.counters.losses);
                    Ok(seq)
                }
                Err(FreshnessError::RingFull { .. }) => {
                    bump(&mut fresh.counters.full);
                    Err(LossError::Full)
                }
                Err(FreshnessError::Exhausted) => {
                    bump(&mut fresh.counters.exhausted);
                    self.close_terminally(start, end, TERMINAL_FRESHNESS_EXHAUSTED);
                    Err(LossError::Exhausted)
                }
                Err(_) => Err(LossError::NoBarrier),
            }
        }

        /// Publishes the terminal cell and closes the table: its readers
        /// deliver nothing more and report the terminal close and the
        /// closed table.
        fn close_terminally(&mut self, start: u64, end: u64, reason: u64) {
            let _ = self.publish_terminal(start, end, reason);
            self.close();
        }

        /// Whether `[start, end)` is a recorded gap still ahead of the
        /// frontier: a feeder that met a gap it already recorded through
        /// the mailbox records it once.
        #[must_use]
        pub fn recorded(&self, start: u64, end: u64) -> bool {
            self.fresh
                .as_ref()
                .is_some_and(|fresh| fresh.ahead.contains(&(start, end)))
        }

        /// The feeder consumed the log below `position`: recorded gaps
        /// ending at or below it are behind, so a value written past them
        /// is Fresh with respect to them. The frontier never moves back.
        pub fn passed(&mut self, position: u64) {
            if let Some(fresh) = self.fresh.as_mut() {
                fresh.frontier = fresh.frontier.max(position);
                let frontier = fresh.frontier;
                fresh.ahead.retain(|&(_, end)| end > frontier);
            }
        }

        /// Reconciles up to `budget` slots of the pass in progress (GU-8
        /// step 2): each slot not yet through the pass's sequence becomes
        /// Stale since the earliest start among the records it had not
        /// applied, or its own earlier start. A pass that reaches the last
        /// key retires its records (step 3). Returns the slots written.
        ///
        /// # Errors
        ///
        /// [`ConflationError::VersionsExhausted`] for a slot whose sequence
        /// is exhausted: the table closes and the terminal cell is
        /// published.
        pub fn reconcile(&mut self, budget: u32) -> Result<u32, ConflationError> {
            let keys = self.table.geometry.keys;
            let (Some(fresh), Some(words)) = (self.fresh.as_mut(), self.table.barrier_words())
            else {
                return Ok(0);
            };
            let barrier = BarrierWords::new(words, DEFAULT_RING)
                .map_err(|_| ConflationError::InvalidConfig)?;
            let (through, mut key) = match fresh.pass {
                Some(pass) => pass,
                None if fresh.unretired.is_empty() => return Ok(0),
                None => (barrier.loss_seq(), 0),
            };
            let mut written = 0u32;
            let mut steps = 0u32;
            while steps < budget && key < keys {
                let slot = self.table.slot(key).ok_or(ConflationError::InvalidConfig)?;
                let current = slot.freshness();
                if current.applied() < through {
                    let since = fresh
                        .unretired
                        .iter()
                        .filter(|&&(seq, _)| seq > current.applied() && seq <= through)
                        .map(|&(_, start)| start)
                        .chain(current.is_stale().then_some(current.stale_since))
                        .min();
                    let reconciled = SlotFreshness {
                        loss_applied: since.map_or(through, |_| through | STALE),
                        stale_since: since.unwrap_or(0),
                    };
                    if let Err(error) = slot.set_freshness(reconciled) {
                        fresh.pass = Some((through, key));
                        bump(&mut fresh.counters.exhausted);
                        self.close_terminally(0, through, TERMINAL_FRESHNESS_EXHAUSTED);
                        return Err(error);
                    }
                    bump(&mut fresh.counters.reconciled);
                    written += 1;
                }
                key += 1;
                steps += 1;
            }
            if key < keys {
                fresh.pass = Some((through, key));
                return Ok(written);
            }
            // Every slot's Release fence precedes this in program order.
            barrier
                .retire_through(through)
                .map_err(|_| ConflationError::InvalidConfig)?;
            fresh.unretired.retain(|&(seq, _)| seq > through);
            fresh.pass = None;
            bump(&mut fresh.counters.retirements);
            Ok(written)
        }

        /// Whether recorded losses wait for reconciliation and retirement.
        #[must_use]
        pub fn reconciling(&self) -> bool {
            self.fresh
                .as_ref()
                .is_some_and(|fresh| !fresh.unretired.is_empty())
        }

        /// Publishes the view's terminal cell (GU-8): readers classify every
        /// value below `end` Stale since `start` and the view closes with
        /// `reason`. Returns whether this publisher won the one-shot cell;
        /// `false` without a barrier.
        pub fn publish_terminal(&self, start: u64, end: u64, reason: u64) -> bool {
            self.table
                .terminal_words()
                .and_then(|words| TerminalCell::new(words).ok())
                .is_some_and(|cell| cell.publish(Terminal { start, end, reason }))
        }

        /// The freshness counters; `None` without a barrier.
        #[must_use]
        pub fn fresh_counters(&self) -> Option<FreshCounters> {
            self.fresh.as_ref().map(|fresh| fresh.counters)
        }

        /// A new reader (control path: allocates its private state). It
        /// starts with a full scan, so it delivers every key already written.
        #[must_use]
        pub fn reader(&self) -> ConflationReader {
            ConflationReader::new(Source::Local(Arc::clone(&self.table)), self.table.geometry)
        }

        /// The barrier's retired-through sequence (tests).
        #[cfg(test)]
        pub(super) fn retired_through(&self) -> Option<u64> {
            let words = self.table.barrier_words()?;
            Some(
                BarrierWords::new(words, DEFAULT_RING)
                    .ok()?
                    .retired_through(),
            )
        }

        /// Seeds the barrier's loss and retired sequences (tests).
        #[cfg(test)]
        pub(super) fn seed_loss_seq(&self, seq: u64) {
            use crate::sync::Ordering;
            if let Some(words) = self.table.barrier_words() {
                for index in [1, 2] {
                    if let Some(word) = words.get(index) {
                        word.store(seq, Ordering::Relaxed);
                    }
                }
            }
        }

        /// Seeds `key`'s version word, so that a test can exhaust it
        /// (tests; dependent crates' tests through `test-hooks`).
        #[cfg(any(test, feature = "test-hooks"))]
        #[doc(hidden)]
        pub fn seed_version(&self, key: u32, version: u64) {
            use crate::sync::Ordering;
            if let Some(slot) = self.table.slot(key)
                && let Some(word) = slot.word(super::FRESH_VERSION)
            {
                word.store(version, Ordering::Relaxed);
            }
        }

        #[cfg(test)]
        pub(super) fn table_slot(&self, key: u32) -> Option<FreshSlotWords<'_>> {
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
            self.table.slot(key)?.word(super::FRESH_VERSION)
        }

        #[cfg(test)]
        pub(super) fn slot_seq_word(&self, key: u32) -> Option<&crate::sync::AtomicU64> {
            self.table.slot(key)?.word(super::FRESH_SEQ)
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
        /// The view's published terminal invalidation (GU-8): every value
        /// below its end is stale since its start, and the view delivers
        /// nothing more. Its reason is a `TERMINAL_*` code of
        /// [`crate::freshness`]. A poll that sees it returns before reading
        /// the journal: `closed` reports the writer's close only once seen
        /// before (a writer that publishes the cell closes the table, and
        /// the conductor's feeder closes it when the receive owner
        /// published), and `finished` stays `false`, since the reader
        /// stopped before the last values.
        pub terminal: Option<Terminal>,
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
        /// Keys queued: at most `keys`, the queue's capacity, so a `u32`
        /// always holds it (SPEC §14: no conversion to saturate).
        len: u32,
        in_flight: Option<u32>,
        scan_cursor: u32,
        scan_remaining: u32,
        closed_seen: bool,
        value: Box<[u8]>,
        /// The freshness delivered with each key's value ([`FRESH`] or the
        /// stale start).
        delivered_freshness: Box<[u64]>,
        /// The newest loss sequence this reader observed.
        loss_seen: u64,
        /// Keys left in the sweep a new loss started: every written key is
        /// served again, so a freshness change reaches the reader even
        /// though no value version changed (GU-8).
        loss_scan: u32,
        /// The terminal invalidation, once observed.
        terminal: Option<Terminal>,
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
                delivered_freshness: vec![FRESH; keys].into_boxed_slice(),
                loss_seen: 0,
                loss_scan: 0,
                terminal: None,
            }
        }

        /// A reader of a table in a region mapped read-only (a view's side;
        /// `quantstratum-docs: karyos/design/conflation-end-to-end.md`,
        /// Cross-process views), starting with a full scan. The
        /// configuration line is read once: it must equal `expected`, the
        /// configuration the view was granted, and describe a table that
        /// fills the region exactly. Both are checked before the reader
        /// allocates its private state, whose size follows the key count
        /// and the value capacity, so the region cannot make it allocate
        /// more than the view accepted. From then on every slot read and
        /// journal record is validated as on the heap, with loads only.
        ///
        /// # Errors
        ///
        /// Returns [`crate::error::SysError::InvalidRegion`] unless the
        /// region is a conflation table of this layout and generation 0
        /// whose configuration line is `expected` and matches the region.
        #[cfg(target_os = "linux")]
        pub fn attach_read_only(
            region: crate::ipc::ReadOnlyRegion,
            expected: ConflationConfig,
        ) -> Result<Self, crate::error::SysError> {
            let record = region.record();
            let invalid = crate::error::SysError::InvalidRegion {
                address: 0,
                len: record.structure_length,
            };
            if record.kind != crate::ipc::RegionKind::ConflationTable || record.generation != 0 {
                return Err(invalid);
            }
            // A version-1 table has no freshness words: refused, typed.
            if record.layout != LAYOUT_VERSION {
                return Err(crate::error::SysError::LayoutVersion {
                    found: record.layout,
                    expected: LAYOUT_VERSION,
                });
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
            if geometry.config() != expected
                || geometry.config_line()
                    != Some([keys, value_capacity, slot_words, journal_capacity])
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
            if self.is_queued(key) || self.len >= self.keys {
                return;
            }
            // Below `keys`, so the increment cannot overflow; a length no
            // usize of this target holds queues nothing.
            let (Ok(len), Some(next)) = (usize::try_from(self.len), self.len.checked_add(1)) else {
                return;
            };
            let tail = (self.head + len) % self.queue.len();
            if let Some(entry) = self.queue.get_mut(tail) {
                *entry = key;
                self.len = next;
                self.set_queued(key, true);
            }
        }

        fn pop(&mut self) -> Option<u32> {
            let rest = self.len.checked_sub(1)?;
            let key = *self.queue.get(self.head)?;
            self.head = (self.head + 1) % self.queue.len();
            self.len = rest;
            self.set_queued(key, false);
            Some(key)
        }

        fn changed(&self, key: u32, version: u64) -> bool {
            self.delivered
                .get(key as usize)
                .is_some_and(|&delivered| version != delivered)
        }

        /// Delivers the latest value of changed keys to `handler(key,
        /// version, value, freshness)`, within `budget`. The value borrows
        /// this reader's private copy; its freshness (never
        /// [`Freshness::Retry`]) was classified with that copy (GU-8): a
        /// key whose freshness changed is delivered again with the same
        /// version. A table without a barrier delivers every value Fresh.
        /// Once the view's terminal cell is published, nothing more is
        /// delivered and the report carries it.
        ///
        /// If the handler panics, its key is not marked delivered: the next
        /// poll queues it again (at the back, behind keys already pending) and
        /// it is served within that or later budgets.
        pub fn poll_changed(
            &mut self,
            budget: Budget,
            mut handler: impl FnMut(u32, u64, &[u8], Freshness),
        ) -> PollReport {
            let mut report = PollReport::default();
            if let Some(key) = self.in_flight.take() {
                self.push(key);
            }
            if self.observe_barrier() {
                return self.report(report);
            }
            // Once closed, the journal may lack the last record: scan every
            // slot once.
            let closed = with_view!(&self.source, view => view
                .is_none_or(|view| view.journal.is_closed()));
            if !self.closed_seen && closed {
                self.closed_seen = true;
                self.scan_remaining = self.keys;
            }
            // A terminal published before the close it precedes (an image's
            // retirement) is seen with the close: this read is ordered after
            // the close was observed, so a closed report carries it. One
            // published after the close (exhausted versions) reaches a later
            // poll's report.
            if closed && self.observe_barrier() {
                return self.report(report);
            }
            if budget.keys == 0 {
                return self.report(report);
            }
            self.drain_journal(budget.keys, &mut report);
            self.sweep(budget.keys);
            // Serve only the keys queued now, so a key requeued as unstable
            // is not retried again in this poll.
            let eligible = budget.keys.min(self.len);
            for _ in 0..eligible {
                let Some(key) = self.pop() else {
                    break;
                };
                self.serve(key, budget.retries, &mut handler, &mut report);
            }
            self.report(report)
        }

        fn report(&self, mut report: PollReport) -> PollReport {
            report.pending = self.len;
            report.scanning = self.scan_remaining > 0 || self.loss_scan > 0;
            report.closed = self.closed_seen;
            report.terminal = self.terminal;
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

        /// Reads the terminal cell and the newest loss sequence: a new loss
        /// starts a sweep that serves every written key again. Returns
        /// whether the terminal cell is published (the view delivers
        /// nothing more).
        fn observe_barrier(&mut self) -> bool {
            if self.terminal.is_some() {
                return true;
            }
            let Some((words, terminal)) = self.source.barrier() else {
                return false;
            };
            if let Some(published) = TerminalCell::read(&terminal) {
                self.terminal = Some(published);
                return true;
            }
            if let Ok(snapshot) = BarrierSnapshot::take(&words, DEFAULT_RING)
                && snapshot.loss_seq() > self.loss_seen
            {
                self.loss_seen = snapshot.loss_seq();
                self.loss_scan = self.keys;
            }
            false
        }

        /// Checks the versions of up to `limit` slots from the persistent
        /// cursor, on every poll: this finds values whose journal record was
        /// lost, or not yet appended when the journal was read. Counts down
        /// a full pass when one is in progress, and a loss sweep, which
        /// queues every written key.
        fn sweep(&mut self, limit: u32) {
            let keys = self.keys;
            for _ in 0..limit.min(keys) {
                let key = self.scan_cursor;
                self.scan_cursor = (key + 1) % keys;
                if self.scan_remaining > 0 {
                    self.scan_remaining -= 1;
                }
                let (version, unsettled) = with_view!(&self.source, view => view
                    .map_or((0, false), |view| (view.version(key), view.unsettled(key))));
                let loss = self.loss_scan > 0;
                if loss {
                    self.loss_scan -= 1;
                }
                if unsettled || (version != 0 && (loss || self.changed(key, version))) {
                    self.push(key);
                }
            }
        }

        fn serve(
            &mut self,
            key: u32,
            retries: u32,
            handler: &mut impl FnMut(u32, u64, &[u8], Freshness),
            report: &mut PollReport,
        ) {
            for _ in 0..retries.max(1) {
                // The barrier snapshot comes before the slot copy, which
                // the classification then checks against it (GU-8).
                let snapshot = match self.source.barrier() {
                    Some((words, _)) => match BarrierSnapshot::take(&words, DEFAULT_RING) {
                        Ok(snapshot) => Some(snapshot),
                        Err(_) => continue,
                    },
                    None => None,
                };
                let read = with_view!(&self.source, view => view
                    .and_then(|view| view.read(key, &mut self.value)));
                match read {
                    None => return,
                    Some(FreshRead::Unstable) => continue,
                    Some(FreshRead::Empty) => return,
                    Some(FreshRead::Value {
                        version,
                        length,
                        freshness,
                    }) => {
                        // Every record the slot has not applied starts at or
                        // above the writer's frontier, which `record_loss`
                        // enforces, so every value written before it lies
                        // below its end: classifying at position 0 marks
                        // exactly the values GU-9 marks.
                        let classified = match (snapshot, self.source.barrier()) {
                            (Some(snapshot), Some((words, _))) => {
                                snapshot.classify(&words, freshness, 0)
                            }
                            _ => Freshness::Fresh,
                        };
                        if classified == Freshness::Retry {
                            continue;
                        }
                        // A terminal publication after the copy: nothing
                        // more is delivered.
                        if self.observe_barrier() {
                            return;
                        }
                        let delivered = self.delivered.get(key as usize).copied().unwrap_or(0);
                        let code = freshness_code(classified);
                        let same = self
                            .delivered_freshness
                            .get(key as usize)
                            .is_some_and(|&delivered| delivered == code);
                        if version < delivered || (version == delivered && same) {
                            report.skipped += 1;
                            return;
                        }
                        self.in_flight = Some(key);
                        handler(
                            key,
                            version,
                            self.value.get(..length).unwrap_or(&[]),
                            classified,
                        );
                        self.in_flight = None;
                        if let Some(entry) = self.delivered.get_mut(key as usize) {
                            *entry = version;
                        }
                        if let Some(entry) = self.delivered_freshness.get_mut(key as usize) {
                            *entry = code;
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
