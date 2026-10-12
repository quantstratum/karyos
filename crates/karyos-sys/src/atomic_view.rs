// SPDX-License-Identifier: Apache-2.0

//! Atomic-only views over raw memory, and a heap backing that goes through the
//! same construction path as mappings so Miri can check it.
//!
//! A region viewed through [`AtomicWords`] is accessed by this process only as
//! `AtomicU64` words. The view never exposes ordinary or mixed-size access to
//! the same bytes.

use core::ptr::NonNull;
use core::sync::atomic::AtomicU64;

use crate::error::SysError;

/// Size in bytes of one atomic word.
pub const WORD_BYTES: usize = size_of::<AtomicU64>();

/// A borrowed view of a region as `AtomicU64` words.
#[derive(Debug, Clone, Copy)]
pub struct AtomicWords<'a> {
    words: &'a [AtomicU64],
}

impl<'a> AtomicWords<'a> {
    /// Validates a raw region and views it as atomic words.
    ///
    /// Checks that `base` is non-null and aligned for `AtomicU64`, and that
    /// `len_bytes` is non-zero, a multiple of [`WORD_BYTES`] and at most
    /// `isize::MAX`.
    ///
    /// # Safety
    ///
    /// For the whole lifetime `'a`:
    ///
    /// - `base..base + len_bytes` must be one allocation (one heap block or one
    ///   mapping) that `base` has provenance over, and the range must not wrap
    ///   around the address space;
    /// - every byte must be initialized, readable and writable, and stay
    ///   allocated (mapped) and the same size;
    /// - this process must access those bytes only through atomic operations
    ///   on naturally aligned 64-bit words, never through ordinary or
    ///   mixed-size accesses.
    ///
    /// The function checks the address and length properties it can check;
    /// the caller guarantees the rest.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] when a check fails.
    pub(crate) unsafe fn from_raw(base: *mut u8, len_bytes: usize) -> Result<Self, SysError> {
        let address = base.addr();
        let valid = !base.is_null()
            && address.is_multiple_of(align_of::<AtomicU64>())
            && len_bytes > 0
            && len_bytes.is_multiple_of(WORD_BYTES)
            && isize::try_from(len_bytes).is_ok();
        if !valid {
            return Err(SysError::InvalidRegion {
                address,
                len: len_bytes,
            });
        }
        let count = len_bytes / WORD_BYTES;
        // SAFETY: `base` is non-null and aligned for `AtomicU64` (checked
        // above); the caller guarantees the `count * 8 = len_bytes` bytes are
        // allocated and live for `'a`, and `len_bytes <= isize::MAX` (checked).
        // `AtomicU64` has the size and alignment of `u64` and permits shared
        // mutation, and the caller guarantees only atomic access, so shared
        // references to these words are valid.
        let words = unsafe { core::slice::from_raw_parts(base.cast::<AtomicU64>(), count) };
        Ok(Self { words })
    }

    /// An empty view, used only as an unreachable fallback for regions that
    /// were already validated.
    #[inline]
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self { words: &[] }
    }

    /// Number of words.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// Whether the view has no words; never true for a valid view.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// The word at `index`, if in bounds.
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&'a AtomicU64> {
        self.words.get(index)
    }

    /// All words as a slice, for scans such as `loan_held`.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &'a [AtomicU64] {
        self.words
    }
}

/// Heap-backed atomic words, for tests and single-process use. Built through
/// the same internal constructor as a mapping (`AtomicWords::from_raw`), so
/// Miri exercises that path.
#[derive(Debug)]
pub struct HeapWords {
    base: NonNull<AtomicU64>,
    count: usize,
    len_bytes: usize,
}

// SAFETY: `HeapWords` owns a heap allocation of `AtomicU64`, which is `Send`
// and `Sync`; it exposes only shared references to atomics, so moving or
// sharing the owner across threads is sound.
unsafe impl Send for HeapWords {}
// SAFETY: see the `Send` impl; all access goes through `&AtomicU64`.
unsafe impl Sync for HeapWords {}

impl HeapWords {
    /// Allocates `count` zeroed words.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] when `count` is zero or its byte
    /// size overflows.
    pub fn zeroed(count: usize) -> Result<Self, SysError> {
        let len = count
            .checked_mul(WORD_BYTES)
            .ok_or(SysError::InvalidRegion { address: 0, len: 0 })?;
        if count == 0 || isize::try_from(len).is_err() {
            return Err(SysError::InvalidRegion { address: 0, len });
        }
        let boxed: Box<[AtomicU64]> = (0..count).map(|_| AtomicU64::new(0)).collect();
        let raw = Box::into_raw(boxed);
        let base = NonNull::new(raw.cast::<AtomicU64>())
            .ok_or(SysError::InvalidRegion { address: 0, len })?;
        Ok(Self {
            base,
            count,
            len_bytes: len,
        })
    }

    /// The word at `index`, if in bounds, without forming a view of the
    /// whole region (cheap per access, also under Miri).
    #[inline]
    #[must_use]
    #[cfg_attr(
        loom,
        allow(dead_code, reason = "used by the owned APIs, absent under loom")
    )]
    pub(crate) fn word(&self, index: usize) -> Option<&AtomicU64> {
        if index >= self.count {
            return None;
        }
        // SAFETY: `index < count`, so the pointer stays inside the live
        // allocation of `count` `AtomicU64`s owned by `self`.
        let pointer = unsafe { self.base.as_ptr().add(index) };
        // SAFETY: the word is initialized and lives as long as `self`, which
        // the reference borrows; `AtomicU64` permits shared mutation.
        Some(unsafe { &*pointer })
    }

    /// The `len` words starting at `start`, if in bounds, without forming a
    /// view of the whole region.
    #[must_use]
    #[cfg_attr(
        loom,
        allow(dead_code, reason = "used by the owned APIs, absent under loom")
    )]
    pub(crate) fn range(&self, start: usize, len: usize) -> Option<&[AtomicU64]> {
        let end = start.checked_add(len)?;
        if end > self.count {
            return None;
        }
        // SAFETY: `start <= end <= count`, so the pointer stays inside (or
        // one past) the live allocation owned by `self`.
        let pointer = unsafe { self.base.as_ptr().add(start) };
        // SAFETY: the `len` words from `pointer` are initialized `AtomicU64`s
        // of the allocation and live as long as `self`, which the slice
        // borrows; `AtomicU64` permits shared mutation.
        Some(unsafe { core::slice::from_raw_parts(pointer, len) })
    }

    /// Views the words.
    #[must_use]
    pub fn words(&self) -> AtomicWords<'_> {
        // SAFETY: the allocation of `count` words lives until `self` is
        // dropped, and the returned view borrows `self`; it is only accessed
        // atomically. The checks in `from_raw` cannot fail for a live boxed
        // slice, which `zeroed` validated.
        let view =
            unsafe { AtomicWords::from_raw(self.base.as_ptr().cast::<u8>(), self.len_bytes) };
        match view {
            Ok(view) => view,
            // `zeroed` guarantees a non-empty, aligned, isize-bounded region,
            // so `from_raw` cannot reject it; never panic on this path.
            Err(_) => AtomicWords::empty(),
        }
    }
}

impl Drop for HeapWords {
    fn drop(&mut self) {
        let slice = core::ptr::slice_from_raw_parts_mut(self.base.as_ptr(), self.count);
        // SAFETY: `slice` is exactly the pointer and length produced by
        // `Box::into_raw` in `zeroed`, dropped once here; no view outlives
        // `self` because views borrow it.
        drop(unsafe { Box::from_raw(slice) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn heap_words_round_trip() {
        let heap = HeapWords::zeroed(4).unwrap();
        let words = heap.words();
        assert_eq!(words.len(), 4);
        words.get(3).unwrap().store(42, Ordering::SeqCst);
        assert_eq!(heap.words().get(3).unwrap().load(Ordering::SeqCst), 42);
        assert!(words.get(4).is_none());
    }

    #[test]
    fn heap_words_reject_zero_and_overflow() {
        assert!(HeapWords::zeroed(0).is_err());
        assert!(HeapWords::zeroed(usize::MAX).is_err());
    }

    #[test]
    fn from_raw_rejects_invalid_regions() {
        let heap = HeapWords::zeroed(2).unwrap();
        let base = heap.words().as_slice().as_ptr().cast_mut().cast::<u8>();
        // SAFETY: every call below is rejected by the checks before any
        // reference is created.
        unsafe {
            assert!(AtomicWords::from_raw(core::ptr::null_mut(), 8).is_err());
        }
        // SAFETY: as above; misaligned base is rejected.
        unsafe {
            assert!(AtomicWords::from_raw(base.wrapping_add(1), 8).is_err());
        }
        // SAFETY: as above; zero length is rejected.
        unsafe {
            assert!(AtomicWords::from_raw(base, 0).is_err());
        }
        // SAFETY: as above; a length that is not a multiple of 8 is rejected.
        unsafe {
            assert!(AtomicWords::from_raw(base, 12).is_err());
        }
    }
}
