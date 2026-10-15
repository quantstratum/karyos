// SPDX-License-Identifier: Apache-2.0

//! Raw memory of the term slots of one lane, and how its bytes are moved
//! (`quantstratum-docs: karyos/design/shared-payload-access.md`).
//!
//! The access mode is a property of the backing, fixed by its type:
//!
//! - [`HeapTerms`]: one zeroed private heap allocation of
//!   `slots × term_length` bytes. Word 0 locations are accessed only
//!   atomically, every other byte with plain copies. It is only ever built
//!   by allocating; nothing adapts a mapping or other storage into it.
//! - [`SharedTerms`]: storage that another process may access. Every byte
//!   is moved as naturally aligned `AtomicU64` words; it has no plain path.
//!   Its words live in the log buffer's backing (`quantstratum-docs: karyos/design/ipc-log-buffer.md`):
//!   heap words of this process, or a shared region.
//!
//! Both implement the sealed [`TermBytes`] trait. Every access is an
//! `unsafe fn` whose caller (the log buffer) proves it holds the right to
//! that slot for the whole access: a loan for the exact term, or exclusive
//! `CLEANING`.
//!
//! Cleaning sweeps every 32-byte boundary so it never relies on the old
//! term's frames: [`HeapTerms`] stores an atomic zero for the first 8 bytes
//! and a plain zero for the other 24; [`SharedTerms`] stores atomic zeros
//! for all four words.

use core::alloc::Layout;
use core::fmt::Debug;
use core::ptr::NonNull;
use core::sync::atomic::AtomicU64;

use std::sync::Arc;

use crate::atomic_view::WORD_BYTES;
use crate::error::SysError;
use crate::frame::FRAME_ALIGNMENT;
use crate::log_buffer::storage::Backing;
use crate::publication::{clear_word, load_body, store_body};
use crate::sizing::TermLength;

/// Alignment of the heap slot allocation.
const REGION_ALIGNMENT: usize = 4096;

/// Bytes of a 32-byte boundary that may hold a word 0.
const WORD0_BYTES: usize = 8;

pub(crate) mod sealed {
    use super::{Arc, AtomicU64, Backing, NonNull, SysError, TermLength};

    /// Proof that the caller is this crate: only it can build one.
    #[derive(Debug, Clone, Copy)]
    pub struct Token(pub(super) ());

    impl Token {
        pub(crate) const fn new() -> Self {
            Self(())
        }
    }

    /// The byte movement of a backing. Not nameable outside the crate.
    pub trait Access: Sized {
        /// Whether [`Access::direct_bytes`] exposes term bytes.
        const DIRECT: bool;

        /// Whether the terms live in the buffer's backing (the atomic-only
        /// ABI) rather than in a private allocation.
        const IN_BACKING: bool;

        /// The `slots` zeroed terms: a private allocation, or the words from
        /// `first` of `backing` for a backing that holds them.
        fn create(
            token: Token,
            term_length: TermLength,
            slots: u8,
            backing: &Arc<Backing>,
            first: usize,
        ) -> Result<Self, SysError>;

        /// The atomic word 0 at `offset` of `slot`.
        ///
        /// # Safety
        ///
        /// `slot < slots`, `offset` is a multiple of 32 below the term
        /// length, and one of:
        ///
        /// - the caller holds a loan for the slot's current term for as long
        ///   as the reference is used, and `offset` is a frame start of that
        ///   term's layout, a location accessed only atomically during the
        ///   term incarnation; or
        /// - the caller holds exclusive `CLEANING` for the slot (no loan and
        ///   no other access exists). The sweep may then target 32-byte
        ///   boundaries that the old term used as payload; their earlier
        ///   accesses all happen before the `CLEANING` transition through the
        ///   loan handshake.
        /// - the caller is the buffer's conductor serving commit deadlines
        ///   (`quantstratum-docs: karyos/design/concurrent-deadline.md`): it has just validated
        ///   that the slot holds the term `ACTIVE` or `RECLAIMING`, only it
        ///   moves the slot on to `CLEANING`, and not while it uses the
        ///   reference; and `offset` is a location no party accesses
        ///   non-atomically during the term incarnation: a frame start, or
        ///   a 32-byte boundary of a zero span its span walk takes, where
        ///   every writer whose block starts in the span fails its mark
        ///   before any write.
        unsafe fn word0(&self, slot: u8, offset: u32) -> &AtomicU64;

        /// Copies `bytes` into `slot` at `offset`.
        ///
        /// # Safety
        ///
        /// `offset` is a multiple of 8; the range rounded up to a multiple
        /// of 8 bytes is inside the slot, inside the frame being written and
        /// contains no word 0 of the current term; the caller holds the
        /// slot's write loan for its current term, and no reader can reach
        /// the range before a later `Release` publication. A backing may
        /// store zeros in the bytes between the end of `bytes` and the next
        /// multiple of 8; they must already read as zero.
        unsafe fn write_bytes(&self, slot: u8, offset: u32, bytes: &[u8]);

        /// The term bytes at `offset` of `slot` for direct plain writes by
        /// a claim, or `None` when the backing moves bytes only as atomic
        /// words (the claim then writes through a staging buffer and
        /// [`Access::write_bytes`]).
        ///
        /// # Safety
        ///
        /// As [`Access::write_bytes`], for a range of `len` bytes, for as
        /// long as the pointer is used: the range is inside one frame being
        /// written, contains no word 0 and no other control word, and the
        /// caller keeps the slot's write loan until its last access through
        /// the pointer.
        unsafe fn direct_bytes(&self, slot: u8, offset: u32, len: u32) -> Option<NonNull<u8>>;

        /// Copies from `slot` at `offset` into `out`.
        ///
        /// # Safety
        ///
        /// `offset` is a multiple of 8; the range rounded up to a multiple
        /// of 8 bytes is inside the slot and contains no word 0 of the
        /// current term; it belongs to a block whose first word 0 the caller
        /// loaded with Acquire, and the caller holds a read loan for the
        /// slot's current term until the copy returns.
        unsafe fn read_bytes(&self, slot: u8, offset: u32, out: &mut [u8]);

        /// Zeroes `slot`.
        ///
        /// # Safety
        ///
        /// The caller moved the slot to `CLEANING` after a complete loan
        /// scan found no loan for its term, so no other thread accesses it
        /// until the caller publishes `FREE`.
        unsafe fn clean(&self, slot: u8);
    }
}

/// The term memory of a log buffer: [`HeapTerms`] or [`SharedTerms`].
/// Sealed: no other implementation exists.
pub trait TermBytes: sealed::Access + Debug + Send + Sync {}

fn checked_len(term_length: TermLength, slots: u8) -> Result<usize, SysError> {
    let len = (term_length.get() as usize)
        .checked_mul(usize::from(slots))
        .filter(|len| *len > 0 && isize::try_from(*len).is_ok());
    len.ok_or(SysError::InvalidRegion { address: 0, len: 0 })
}

/// Term slots in a private heap allocation: plain copies under loans.
#[derive(Debug)]
pub struct HeapTerms {
    base: NonNull<u8>,
    layout: Layout,
    term_length: u32,
    slots: u8,
}

// SAFETY: the allocation is owned and freed only in `drop`. All access goes
// through the `unsafe fn`s of `Access`, whose callers serialise conflicting
// access with loans and slot states (see the module documentation).
unsafe impl Send for HeapTerms {}
// SAFETY: see the `Send` impl.
unsafe impl Sync for HeapTerms {}

impl HeapTerms {
    /// Pointer to byte `offset` of `slot`.
    ///
    /// # Safety
    ///
    /// `slot < self.slots` and `offset <= term_length`.
    unsafe fn at(&self, slot: u8, offset: u32) -> *mut u8 {
        debug_assert!(slot < self.slots && offset <= self.term_length);
        let byte = usize::from(slot) * self.term_length as usize + offset as usize;
        // SAFETY: the caller keeps `slot` and `offset` in range, so the
        // result stays inside (or one past) the allocation.
        unsafe { self.base.as_ptr().add(byte) }
    }
}

impl sealed::Access for HeapTerms {
    const DIRECT: bool = true;
    const IN_BACKING: bool = false;

    fn create(
        _token: sealed::Token,
        term_length: TermLength,
        slots: u8,
        _backing: &Arc<Backing>,
        _first: usize,
    ) -> Result<Self, SysError> {
        let len = checked_len(term_length, slots)?;
        let layout = Layout::from_size_align(len, REGION_ALIGNMENT)
            .map_err(|_| SysError::InvalidRegion { address: 0, len })?;
        // SAFETY: `layout` has a non-zero size (at least one 64 KiB term).
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let base = NonNull::new(raw).ok_or(SysError::InvalidRegion { address: 0, len })?;
        Ok(Self {
            base,
            layout,
            term_length: term_length.get(),
            slots,
        })
    }

    unsafe fn word0(&self, slot: u8, offset: u32) -> &AtomicU64 {
        debug_assert!(offset.is_multiple_of(FRAME_ALIGNMENT) && offset < self.term_length);
        // SAFETY: in range per the caller's contract.
        let pointer = unsafe { self.at(slot, offset) };
        // SAFETY: 32-aligned inside the 4096-aligned allocation and valid
        // while `&self` lives. Under the caller's contract no non-atomic
        // access to this location races with the reference: either it is a
        // frame start of the loaned term (atomic-only), or the caller holds
        // exclusive CLEANING.
        unsafe { AtomicU64::from_ptr(pointer.cast::<u64>()) }
    }

    unsafe fn write_bytes(&self, slot: u8, offset: u32, bytes: &[u8]) {
        debug_assert!(offset as usize + bytes.len() <= self.term_length as usize);
        // SAFETY: in range per the caller's contract.
        let destination = unsafe { self.at(slot, offset) };
        // SAFETY: the caller owns the destination range exclusively; the
        // source is caller memory outside the allocation, so no overlap.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len()) };
    }

    unsafe fn direct_bytes(&self, slot: u8, offset: u32, len: u32) -> Option<NonNull<u8>> {
        debug_assert!(offset as usize + len as usize <= self.term_length as usize);
        // SAFETY: in range per the caller's contract.
        NonNull::new(unsafe { self.at(slot, offset) })
    }

    unsafe fn read_bytes(&self, slot: u8, offset: u32, out: &mut [u8]) {
        debug_assert!(offset as usize + out.len() <= self.term_length as usize);
        // SAFETY: in range per the caller's contract.
        let source = unsafe { self.at(slot, offset) };
        // SAFETY: the published bytes are not written while the loan is held;
        // `out` is caller memory outside the allocation.
        unsafe { core::ptr::copy_nonoverlapping(source, out.as_mut_ptr(), out.len()) };
    }

    unsafe fn clean(&self, slot: u8) {
        let mut offset = 0;
        while offset < self.term_length {
            // SAFETY: exclusive CLEANING; the location is 32-aligned in range.
            clear_word(unsafe { self.word0(slot, offset) });
            // SAFETY: exclusive CLEANING; bytes 8..32 of the boundary lie in
            // range and are never word 0 locations.
            let rest = unsafe { self.at(slot, offset + WORD0_BYTES as u32) };
            // SAFETY: as above.
            unsafe { core::ptr::write_bytes(rest, 0, FRAME_ALIGNMENT as usize - WORD0_BYTES) };
            offset += FRAME_ALIGNMENT;
        }
    }
}

impl TermBytes for HeapTerms {}

impl Drop for HeapTerms {
    fn drop(&mut self) {
        // SAFETY: `base` came from `alloc_zeroed` with `self.layout` and is
        // freed once; no reference into it outlives `self`.
        unsafe { std::alloc::dealloc(self.base.as_ptr(), self.layout) };
    }
}

/// Term slots accessed only as aligned atomic 64-bit words, the access ABI
/// for memory another process may touch. No plain copy reaches it.
#[derive(Debug)]
pub struct SharedTerms {
    backing: Arc<Backing>,
    /// The first word of the terms in the backing.
    first: usize,
    /// Words of all terms.
    count: usize,
    term_length: u32,
    slots: u8,
}

impl SharedTerms {
    fn word(&self, index: usize) -> Option<&AtomicU64> {
        if index >= self.count {
            return None;
        }
        self.backing.word(self.first.checked_add(index)?)
    }

    /// The word at `index` of the terms, for tests that act as a peer
    /// keeping the access ABI.
    #[cfg(test)]
    pub(crate) fn test_word(&self, index: usize) -> Option<&AtomicU64> {
        self.word(index)
    }

    /// Index of the word at byte `offset` of `slot`.
    fn index(&self, slot: u8, offset: u32) -> usize {
        debug_assert!(slot < self.slots && offset <= self.term_length);
        debug_assert!((offset as usize).is_multiple_of(WORD_BYTES));
        (usize::from(slot) * self.term_length as usize + offset as usize) / WORD_BYTES
    }
}

impl sealed::Access for SharedTerms {
    const DIRECT: bool = false;
    const IN_BACKING: bool = true;

    fn create(
        _token: sealed::Token,
        term_length: TermLength,
        slots: u8,
        backing: &Arc<Backing>,
        first: usize,
    ) -> Result<Self, SysError> {
        let len = checked_len(term_length, slots)?;
        let count = len / WORD_BYTES;
        // Every term word must lie inside the backing.
        let last = first
            .checked_add(count)
            .and_then(|end| end.checked_sub(1))
            .ok_or(SysError::InvalidRegion { address: 0, len })?;
        if backing.word(last).is_none() {
            return Err(SysError::InvalidRegion { address: 0, len });
        }
        Ok(Self {
            backing: Arc::clone(backing),
            first,
            count,
            term_length: term_length.get(),
            slots,
        })
    }

    unsafe fn word0(&self, slot: u8, offset: u32) -> &AtomicU64 {
        debug_assert!(offset.is_multiple_of(FRAME_ALIGNMENT) && offset < self.term_length);
        match self.word(self.index(slot, offset)) {
            Some(word) => word,
            // In range per the caller's contract; an out-of-range request is
            // a bug, answered without touching the region.
            None => unreachable_word(),
        }
    }

    unsafe fn write_bytes(&self, slot: u8, offset: u32, bytes: &[u8]) {
        let first = self.index(slot, offset);
        let (words, rest) = bytes.as_chunks::<WORD_BYTES>();
        for (index, word) in (first..).zip(words) {
            if let Some(target) = self.word(index) {
                store_body(target, *word);
            }
        }
        if !rest.is_empty() {
            // The padding bytes up to the word boundary belong to the frame
            // being written and already read as zero.
            let mut word = [0u8; WORD_BYTES];
            if let Some(prefix) = word.get_mut(..rest.len()) {
                prefix.copy_from_slice(rest);
            }
            if let Some(target) = self.word(first + words.len()) {
                store_body(target, word);
            }
        }
    }

    unsafe fn direct_bytes(&self, _slot: u8, _offset: u32, _len: u32) -> Option<NonNull<u8>> {
        None
    }

    unsafe fn read_bytes(&self, slot: u8, offset: u32, out: &mut [u8]) {
        let first = self.index(slot, offset);
        let (words, rest) = out.as_chunks_mut::<WORD_BYTES>();
        let full = words.len();
        for (index, word) in (first..).zip(words) {
            if let Some(source) = self.word(index) {
                *word = load_body(source);
            }
        }
        if !rest.is_empty()
            && let Some(source) = self.word(first + full)
        {
            let word = load_body(source);
            if let Some(prefix) = word.get(..rest.len()) {
                rest.copy_from_slice(prefix);
            }
        }
    }

    unsafe fn clean(&self, slot: u8) {
        let start = self.index(slot, 0);
        let count = self.term_length as usize / WORD_BYTES;
        for index in start..start + count {
            if let Some(word) = self.word(index) {
                clear_word(word);
            }
        }
    }
}

impl TermBytes for SharedTerms {}

/// A word outside every region, returned for a request outside the region
/// (a caller bug, asserted in debug builds) so that no path panics or
/// touches memory it does not own.
fn unreachable_word() -> &'static AtomicU64 {
    static SPARE: AtomicU64 = AtomicU64::new(0);
    debug_assert!(false, "word 0 outside the term region");
    &SPARE
}
