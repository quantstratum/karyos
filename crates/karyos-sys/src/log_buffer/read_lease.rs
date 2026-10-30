// SPDX-License-Identifier: Apache-2.0

//! Read leases on committed term bytes (R-CORE-45; SPEC.md §16.6, §16.7;
//! `quantstratum-docs: karyos/design/backend-contract.md`, borrowed-term
//! TX).
//!
//! A [`ReadLease`] is what [`SenderRead::lease_committed`] returns instead
//! of copying: the same validated whole frames, left in the term, under a
//! loan held in a word of the buffer's lease bank
//! ([`LogBuffer::install_leases`]) past the read that took it. While it
//! lives, reclaim finds the loan in its scan and keeps the slot
//! quarantined, so the term is never cleaned or reused under it, across
//! any number of rotations. Dropping it ends the loan with one `Release`
//! store, from any thread, with no lock and no allocation, as a backend's
//! completion or a NIC driver's free callback needs.
//!
//! Safety (ADR-0034): the lease's bytes were validated as committed DATA
//! frames under the loan, with the first word 0 of each block loaded with
//! `Acquire` and every word 0 loaded again after the frame was checked, as
//! the copy path does; the loan is never released before the lease ends,
//! so the term incarnation the frames belong to stays in the slot (the
//! `loom_read_lease` models check that cleaning never races a live
//! lease). [`ReadLease::copy_to`] reads them as the copy path does: each
//! word 0 atomically, the rest with `read_bytes`.
//!
//! [`SenderRead::lease_committed`]: super::SenderRead::lease_committed

use core::sync::atomic::{Ordering, fence};

use super::{BufferOwner, LogBuffer};
use crate::frame::Word0;
use crate::loan::release_loan;
use crate::publication::load_interior;
use crate::sizing::align_frame;
use crate::term_bytes::sealed::Access as _;

/// Whole committed frames of one term, left in place under a read lease
/// (R-CORE-45). The term cannot be cleaned or reused until the lease ends;
/// it ends when dropped, on any thread.
#[derive(Debug)]
#[must_use = "a lease pins its term until it is dropped"]
pub struct ReadLease<O: BufferOwner> {
    buffer: O,
    /// The lease bank word holding the loan.
    word: usize,
    slot: u8,
    /// The first frame's offset in the term.
    start: u32,
    /// Bytes from `start` to the end of the last frame.
    len: usize,
    /// The stream position of the first frame.
    position: u64,
    /// The cursor after the lease.
    next: u64,
}

impl<O: BufferOwner> ReadLease<O> {
    pub(super) fn new(
        buffer: O,
        word: usize,
        slot: u8,
        start: u32,
        len: usize,
        position: u64,
        next: u64,
    ) -> Self {
        Self {
            buffer,
            word,
            slot,
            start,
            len,
            position,
            next,
        }
    }

    /// Bytes of the datagram: the last frame ends here, as for a copy.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the lease holds no byte (never, for a granted lease).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The stream position of the first frame.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.position
    }

    /// The reader's cursor after this lease, as [`super::ReadOutcome`]'s
    /// `next`.
    #[must_use]
    pub fn next(&self) -> u64 {
        self.next
    }

    /// Copies the leased frames into `out`, laid out exactly as
    /// [`super::SenderRead::read_committed`] lays them out (the staging
    /// path). Returns the bytes written, [`ReadLease::len`].
    ///
    /// # Errors
    ///
    /// [`LeaseCopyError::TooSmall`] when `out` is shorter than the lease;
    /// [`LeaseCopyError::Changed`] when a word 0 no longer reads as a
    /// frame inside the lease (a producer wrote committed bytes: nothing
    /// may be sent).
    pub fn copy_to(&self, out: &mut [u8]) -> Result<usize, LeaseCopyError> {
        let out = out
            .get_mut(..self.len)
            .ok_or(LeaseCopyError::TooSmall { needed: self.len })?;
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let end = u32::try_from(self.len)
            .ok()
            .and_then(|len| self.start.checked_add(len))
            .ok_or(LeaseCopyError::Changed)?;
        let mut at = self.start;
        let mut stride = 0usize;
        while at < end {
            // SAFETY: the lease's loan pins this slot's term (module
            // documentation, Safety); `at` is a frame start the lease
            // validated, a location only ever accessed atomically.
            let word = unsafe { buffer.regions.word0(self.slot, at) };
            let raw = load_interior(word);
            let length = Word0::unpack(raw)
                .ok()
                .and_then(|word| u32::try_from(word.frame_length()).ok())
                .ok_or(LeaseCopyError::Changed)?;
            let reserved = align_frame(length).map_err(|_| LeaseCopyError::Changed)?;
            let frame_end = at.checked_add(length).filter(|frame_end| *frame_end <= end);
            let (Some(_), Ok(length)) = (frame_end, usize::try_from(length)) else {
                return Err(LeaseCopyError::Changed);
            };
            let target = stride
                .checked_add(length)
                .and_then(|frame_end| out.get_mut(stride..frame_end))
                .ok_or(LeaseCopyError::Changed)?;
            let (head, body) = target
                .split_at_mut_checked(8)
                .ok_or(LeaseCopyError::Changed)?;
            head.copy_from_slice(&raw.to_le_bytes());
            let body_at = at.checked_add(8).ok_or(LeaseCopyError::Changed)?;
            // SAFETY: the lease's loan is held; the bytes after word 0 lie
            // inside the frame, inside a block the lease validated.
            unsafe { buffer.regions.read_bytes(self.slot, body_at, body) };
            // As the copy path: a word 0 that changed means the copy may
            // mix two values.
            fence(Ordering::Acquire);
            if load_interior(word) != raw {
                return Err(LeaseCopyError::Changed);
            }
            let padded = stride
                .checked_add(usize::try_from(reserved).map_err(|_| LeaseCopyError::Changed)?)
                .ok_or(LeaseCopyError::Changed)?;
            if let Some(padding) = out.get_mut(stride + length..padded.min(out.len())) {
                padding.fill(0);
            }
            stride = padded;
            at = at.checked_add(reserved).ok_or(LeaseCopyError::Changed)?;
        }
        Ok(self.len)
    }
}

impl<O: BufferOwner> Drop for ReadLease<O> {
    fn drop(&mut self) {
        // Ends the loan: every access through the lease happened before
        // this `Release`, which reclaim's scan synchronizes with.
        if let Some(word) = self.buffer.lease_words().get(self.word) {
            release_loan(word);
        }
    }
}

/// What [`super::SenderRead::lease_committed`] got.
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum LeaseOutcome<O: BufferOwner> {
    /// Whole committed frames under a lease; the cursor moved to its
    /// `next`.
    Leased(ReadLease<O>),
    /// Nothing is committed at the position yet.
    Pending,
    /// No lease was taken and the cursor did not move: stage the position
    /// with [`super::SenderRead::read_committed`].
    Stage(StageReason),
}

/// Why a position is staged rather than leased.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StageReason {
    /// Every word of the lease bank is held, or none is installed: the
    /// sender's declared bound of pinned terms is reached.
    BankFull,
    /// The block at the position is padding or aborted: its canonical
    /// record is synthesized, not term bytes.
    Record,
}

/// Why [`ReadLease::copy_to`] copied nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseCopyError {
    /// `out` is shorter than the lease.
    TooSmall {
        /// The bytes needed.
        needed: usize,
    },
    /// A leased frame's word 0 changed.
    Changed,
}
