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

/// Clears a location that may have held a word 0, during exclusive cleaning.
/// The `Release` publication of `FREE` afterwards orders it before any later
/// use of the slot.
#[inline]
pub fn clear_word(word: &AtomicU64) {
    word.store(0, Ordering::Relaxed);
}
