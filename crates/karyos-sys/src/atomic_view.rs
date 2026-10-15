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

    /// The words from `index` on; empty when `index` is past the end.
    #[inline]
    #[must_use]
    pub fn slice_from(&self, index: usize) -> Self {
        Self {
            words: self.words.get(index..).unwrap_or(&[]),
        }
    }

    /// All words as a slice, for scans such as `loan_held`.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &'a [AtomicU64] {
        self.words
    }
}

/// A borrowed, load-only view of a region as 64-bit words: it exposes atomic
/// loads and nothing that could store, so it can view memory mapped without
/// write access (`quantstratum-docs: karyos/design/observability-and-tools.md`,
/// "Read-only views"). Plain atomic loads of naturally aligned, lock-free
/// 64-bit words are allowed on read-only memory; no read-modify-write or
/// store is ever issued through it.
#[derive(Debug, Clone, Copy)]
pub struct ReadOnlyWords<'a> {
    words: &'a [AtomicU64],
}

impl<'a> ReadOnlyWords<'a> {
    /// Validates a raw region and views it as load-only words.
    ///
    /// Checks the same address and length properties as
    /// [`AtomicWords::from_raw`].
    ///
    /// # Safety
    ///
    /// For the whole lifetime `'a`: `base..base + len_bytes` must be one
    /// allocation or mapping that `base` has provenance over, not wrapping
    /// the address space; every byte must be initialized and readable (it
    /// need not be writable) and stay mapped and the same size; and this
    /// process must access those bytes only through atomic operations on
    /// naturally aligned 64-bit words. The view itself only loads.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] when a check fails.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "read-only mappings exist only on Linux")
    )]
    pub(crate) unsafe fn from_raw(base: *const u8, len_bytes: usize) -> Result<Self, SysError> {
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
        // SAFETY: `base` is non-null and aligned (checked); the caller
        // guarantees `count * 8` readable, initialized bytes that stay
        // mapped for `'a`, accessed only atomically, and `len_bytes <=
        // isize::MAX` (checked). The shared references are never used to
        // store: this type exposes only loads.
        let words = unsafe { core::slice::from_raw_parts(base.cast::<AtomicU64>(), count) };
        Ok(Self { words })
    }

    /// An empty view, used only as an unreachable fallback for regions that
    /// were already validated.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "read-only mappings exist only on Linux")
    )]
    #[inline]
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self { words: &[] }
    }

    /// A load-only view of words this process may also write: for readers
    /// that must work over either mapping.
    #[inline]
    #[must_use]
    pub fn of(words: AtomicWords<'a>) -> Self {
        Self {
            words: words.as_slice(),
        }
    }

    /// Number of words.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// Whether the view has no words.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// Loads the word at `index` with a `Relaxed` load, if in bounds.
    ///
    /// The view may cover `PROT_READ` memory, where Rust guarantees only
    /// `Relaxed` loads of at most word size
    /// (<https://doc.rust-lang.org/std/sync/atomic/index.html#atomic-accesses-to-read-only-memory>);
    /// stronger orderings are therefore not offered. Order later reads with
    /// [`load_acquire`](Self::load_acquire) or an explicit `Acquire` fence.
    #[inline]
    #[must_use]
    pub fn load(&self, index: usize) -> Option<u64> {
        self.words
            .get(index)
            .map(|word| word.load(core::sync::atomic::Ordering::Relaxed))
    }

    /// Loads the word at `index` with acquire semantics, if in bounds: a
    /// `Relaxed` load followed by an `Acquire` fence, which synchronizes
    /// with a `Release` store of the value read (or a `Release` fence before
    /// it) without an acquire load on read-only memory.
    #[inline]
    #[must_use]
    pub fn load_acquire(&self, index: usize) -> Option<u64> {
        let value = self.load(index);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        value
    }

    /// The words from `index` on; empty when `index` is past the end.
    #[inline]
    #[must_use]
    pub fn slice_from(&self, index: usize) -> Self {
        Self {
            words: self.words.get(index..).unwrap_or(&[]),
        }
    }

    /// The words `index..index + count`; empty when out of bounds.
    #[inline]
    #[must_use]
    pub fn range(&self, index: usize, count: usize) -> Self {
        let words = index
            .checked_add(count)
            .and_then(|end| self.words.get(index..end))
            .unwrap_or(&[]);
        Self { words }
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

    /// The first word, for backings that derive section pointers.
    #[inline]
    #[must_use]
    #[cfg_attr(
        loom,
        allow(
            dead_code,
            reason = "used by the log buffer storage, absent under loom"
        )
    )]
    pub(crate) fn base(&self) -> NonNull<AtomicU64> {
        self.base
    }

    /// The number of words.
    #[inline]
    #[must_use]
    #[cfg_attr(
        loom,
        allow(
            dead_code,
            reason = "used by the log buffer storage, absent under loom"
        )
    )]
    pub(crate) fn count(&self) -> usize {
        self.count
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

    /// A read-only view over a heap block: built through the raw
    /// constructor that mappings use, so Miri checks its provenance and
    /// bounds.
    fn read_only(heap: &HeapWords) -> ReadOnlyWords<'_> {
        let base = heap.words().as_slice().as_ptr().cast::<u8>();
        // SAFETY: `base` covers `heap.count()` initialized, aligned words of
        // one allocation that `heap` keeps alive for the borrow, accessed
        // only atomically.
        unsafe { ReadOnlyWords::from_raw(base, heap.count() * WORD_BYTES) }.unwrap()
    }

    #[test]
    fn read_only_from_raw_reads_heap_words() {
        let heap = HeapWords::zeroed(6).unwrap();
        for (index, word) in heap.words().as_slice().iter().enumerate() {
            word.store(index as u64 * 10, Ordering::Release);
        }
        let view = read_only(&heap);
        assert_eq!(view.len(), 6);
        assert!(!view.is_empty());
        assert_eq!(view.load(0), Some(0));
        assert_eq!(view.load_acquire(5), Some(50));
        assert_eq!(view.load(6), None);
        assert_eq!(view.load_acquire(usize::MAX), None);
        // A later store through the writable view is seen by the reader.
        heap.words().get(2).unwrap().store(7, Ordering::Release);
        assert_eq!(view.load_acquire(2), Some(7));
    }

    #[test]
    fn read_only_subviews_stay_in_bounds() {
        let heap = HeapWords::zeroed(6).unwrap();
        for (index, word) in heap.words().as_slice().iter().enumerate() {
            word.store(index as u64, Ordering::Relaxed);
        }
        let view = read_only(&heap);
        let tail = view.slice_from(4);
        assert_eq!(
            (tail.len(), tail.load(0), tail.load(1)),
            (2, Some(4), Some(5))
        );
        assert_eq!(tail.load(2), None);
        assert!(view.slice_from(6).is_empty());
        assert!(view.slice_from(usize::MAX).is_empty());
        let range = view.range(1, 3);
        assert_eq!(range.len(), 3);
        assert_eq!(
            (range.load(0), range.load(2), range.load(3)),
            (Some(1), Some(3), None)
        );
        assert_eq!(range.range(1, 2).load(1), Some(3));
        assert!(view.range(4, 3).is_empty());
        assert!(view.range(usize::MAX, 2).is_empty());
        assert!(view.range(2, usize::MAX).is_empty());
        assert!(ReadOnlyWords::empty().is_empty());
        assert_eq!(ReadOnlyWords::empty().load(0), None);
        let of = ReadOnlyWords::of(heap.words());
        assert_eq!((of.len(), of.load(3)), (6, Some(3)));
    }

    #[test]
    fn read_only_from_raw_rejects_invalid_regions() {
        let heap = HeapWords::zeroed(2).unwrap();
        let base = heap.words().as_slice().as_ptr().cast::<u8>();
        // SAFETY: every call below is rejected by the checks before any
        // reference is created.
        unsafe {
            assert!(ReadOnlyWords::from_raw(core::ptr::null(), 8).is_err());
        }
        // SAFETY: as above; misaligned base is rejected.
        unsafe {
            assert!(ReadOnlyWords::from_raw(base.wrapping_add(1), 8).is_err());
        }
        // SAFETY: as above; zero length is rejected.
        unsafe {
            assert!(ReadOnlyWords::from_raw(base, 0).is_err());
        }
        // SAFETY: as above; a length that is not a multiple of 8 is rejected.
        unsafe {
            assert!(ReadOnlyWords::from_raw(base, 12).is_err());
        }
        // SAFETY: as above; a length over isize::MAX is rejected.
        unsafe {
            assert!(ReadOnlyWords::from_raw(base, usize::MAX - 7).is_err());
        }
    }
}
