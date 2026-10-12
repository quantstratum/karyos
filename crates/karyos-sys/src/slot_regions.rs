// SPDX-License-Identifier: Apache-2.0

//! Raw memory of the term slots of one lane: one zeroed heap allocation of
//! `slots × term_length` bytes. Crate-private; every access is an `unsafe fn`
//! whose caller (the log buffer) proves it holds the right to that slot for
//! the whole access: a loan for the exact term, or exclusive `CLEANING`.
//!
//! Within a term incarnation, word 0 locations are accessed only atomically
//! and other bytes only with plain copies. Cleaning sweeps every 32-byte
//! boundary: an atomic zero for its first 8 bytes and a plain zero for the
//! other 24, so it never relies on the old term's frames.

use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::AtomicU64;

use crate::error::SysError;
use crate::frame::FRAME_ALIGNMENT;
use crate::publication::clear_word;
use crate::sizing::TermLength;

/// Alignment of the slot allocation.
const REGION_ALIGNMENT: usize = 4096;

/// Bytes of a 32-byte boundary that may hold a word 0.
const WORD0_BYTES: usize = 8;

/// The slots of one lane.
#[derive(Debug)]
pub(crate) struct SlotRegions {
    base: NonNull<u8>,
    layout: Layout,
    term_length: u32,
    slots: u8,
}

// SAFETY: the allocation is owned and freed only in `drop`. All access goes
// through the `unsafe fn`s below, whose callers serialise conflicting access
// with loans and slot states (see the module documentation).
unsafe impl Send for SlotRegions {}
// SAFETY: see the `Send` impl.
unsafe impl Sync for SlotRegions {}

impl SlotRegions {
    /// Allocates `slots` zeroed terms.
    pub(crate) fn new(term_length: TermLength, slots: u8) -> Result<Self, SysError> {
        let len = Self::layout_len(term_length, slots)?;
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

    fn layout_len(term_length: TermLength, slots: u8) -> Result<usize, SysError> {
        let len = (term_length.get() as usize)
            .checked_mul(usize::from(slots))
            .filter(|len| *len > 0 && isize::try_from(*len).is_ok());
        len.ok_or(SysError::InvalidRegion { address: 0, len: 0 })
    }

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

    /// The atomic word 0 at `offset` of `slot`.
    ///
    /// # Safety
    ///
    /// `slot < slots`, `offset` is a multiple of 32 below the term length,
    /// and one of:
    ///
    /// - the caller holds a loan for the slot's current term for as long as
    ///   the reference is used, and `offset` is a frame start of that term's
    ///   layout, a location accessed only atomically during the term
    ///   incarnation; or
    /// - the caller holds exclusive `CLEANING` for the slot (no loan and no
    ///   other access exists). The sweep may then target 32-byte boundaries
    ///   that the old term used as payload; their earlier plain accesses all
    ///   happen before the `CLEANING` transition through the loan handshake.
    pub(crate) unsafe fn word0(&self, slot: u8, offset: u32) -> &AtomicU64 {
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

    /// Plain copy of `bytes` into `slot` at `offset`.
    ///
    /// # Safety
    ///
    /// The range is inside the slot, contains no word 0 of the current term,
    /// the caller holds the slot's write loan for its current term, and no
    /// reader can reach the range before a later `Release` publication.
    pub(crate) unsafe fn write_plain(&self, slot: u8, offset: u32, bytes: &[u8]) {
        debug_assert!(offset as usize + bytes.len() <= self.term_length as usize);
        // SAFETY: in range per the caller's contract.
        let destination = unsafe { self.at(slot, offset) };
        // SAFETY: the caller owns the destination range exclusively; the
        // source is caller memory outside the allocation, so no overlap.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len()) };
    }

    /// Plain copy from `slot` at `offset` into `out`.
    ///
    /// # Safety
    ///
    /// The range is inside the slot, contains no word 0 of the current term,
    /// belongs to a block whose first word 0 the caller loaded with Acquire,
    /// and the caller holds a read loan for the slot's current term until the
    /// copy returns.
    pub(crate) unsafe fn read_plain(&self, slot: u8, offset: u32, out: &mut [u8]) {
        debug_assert!(offset as usize + out.len() <= self.term_length as usize);
        // SAFETY: in range per the caller's contract.
        let source = unsafe { self.at(slot, offset) };
        // SAFETY: the published bytes are not written while the loan is held;
        // `out` is caller memory outside the allocation.
        unsafe { core::ptr::copy_nonoverlapping(source, out.as_mut_ptr(), out.len()) };
    }

    /// Zeroes `slot`: at every 32-byte boundary an atomic zero for the first
    /// 8 bytes, a plain zero for the other 24.
    ///
    /// # Safety
    ///
    /// The caller moved the slot to `CLEANING` after a complete loan scan
    /// found no loan for its term, so no other thread accesses it until the
    /// caller publishes `FREE`.
    pub(crate) unsafe fn clean(&self, slot: u8) {
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

impl Drop for SlotRegions {
    fn drop(&mut self) {
        // SAFETY: `base` came from `alloc_zeroed` with `self.layout` and is
        // freed once; no reference into it outlives `self`.
        unsafe { std::alloc::dealloc(self.base.as_ptr(), self.layout) };
    }
}
