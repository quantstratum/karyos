// SPDX-License-Identifier: Apache-2.0

//! The orderings of block publication (SPEC.md §4, publish and read), as
//! small helpers over one word 0 each. `term_memory` uses them on real term
//! memory; the Loom model uses the same helpers on model atomics, so the model
//! checks the production orderings.
//!
//! Values are stored little-endian so the bytes in memory match the wire
//! layout on every target.

use crate::frame::Word0;
use crate::sync::{AtomicU64, Ordering};

/// Stores an interior fragment's word 0. It becomes visible to readers
/// through the `Release` of the block's first word 0, so `Relaxed` suffices.
#[inline]
pub fn store_interior(word: &AtomicU64, word0: Word0) {
    word.store(word0.pack().to_le(), Ordering::Relaxed);
}

/// Publishes a block by storing its first word 0 with `Release`, after every
/// other byte and interior word 0 of the block has been written.
#[inline]
pub fn publish_block(first: &AtomicU64, word0: Word0) {
    first.store(word0.pack().to_le(), Ordering::Release);
}

/// Loads a block's first word 0 with `Acquire`; if it is committed, every
/// write made before its publication is visible afterwards.
#[inline]
#[must_use]
pub fn observe_block(first: &AtomicU64) -> u64 {
    u64::from_le(first.load(Ordering::Acquire))
}

/// Loads an interior fragment's word 0 after [`observe_block`] saw the
/// block committed.
#[inline]
#[must_use]
pub fn load_interior(word: &AtomicU64) -> u64 {
    u64::from_le(word.load(Ordering::Relaxed))
}

/// Stores eight body bytes (header words 1 to 3, extension or payload) of a
/// block on shared terms, which are written only as atomic words. Like an
/// interior word 0 they become visible through the block's `Release`
/// publication, so `Relaxed` suffices. Bytes keep their memory order, as a
/// plain copy would.
#[inline]
pub fn store_body(word: &AtomicU64, bytes: [u8; 8]) {
    word.store(u64::from_ne_bytes(bytes), Ordering::Relaxed);
}

/// Loads eight body bytes of a block on shared terms after
/// [`observe_block`] saw it committed.
#[inline]
#[must_use]
pub fn load_body(word: &AtomicU64) -> [u8; 8] {
    word.load(Ordering::Relaxed).to_ne_bytes()
}

/// Clears a location that may have held a word 0, during exclusive cleaning.
/// The `Release` publication of `FREE` afterwards orders it before any later
/// use of the slot.
#[inline]
pub fn clear_word(word: &AtomicU64) {
    word.store(0, Ordering::Relaxed);
}

/// Marks a claimed block: compare-exchanges its first word 0 from 0 to the
/// `reserved` value, a negative length (SPEC.md §4, claims). It is the
/// claim's first write to the block; it fails only if the block was already
/// aborted, and then nothing else may be written.
#[inline]
pub fn mark_block(first: &AtomicU64, reserved: Word0) -> bool {
    first
        .compare_exchange(
            0,
            reserved.pack().to_le(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Commits a marked block: compare-exchanges its first word 0 from
/// `reserved` to the final `committed` word 0. Its `Release` publishes the
/// block like [`publish_block`]. Fails if an abort won.
#[inline]
pub fn commit_block(first: &AtomicU64, reserved: Word0, committed: Word0) -> bool {
    first
        .compare_exchange(
            reserved.pack().to_le(),
            committed.pack().to_le(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Aborts a marked block: compare-exchanges its first word 0 from
/// `reserved` to the `aborted` word 0 stating the reserved extent. Fails if
/// a commit won (or another abort did).
#[inline]
pub fn abort_block(first: &AtomicU64, reserved: Word0, aborted: Word0) -> bool {
    first
        .compare_exchange(
            reserved.pack().to_le(),
            aborted.pack().to_le(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}
