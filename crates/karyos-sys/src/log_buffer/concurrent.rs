// SPDX-License-Identifier: Apache-2.0

//! Concurrent publication handles (`quantstratum-docs: karyos/design/concurrent-publication.md`,
//! batch a): publisher slots and their handoff, one `fetch_add` reservation
//! per message on the active slot's raw tail, commit-or-abort publication,
//! the crossing owner's `PAD`, and catching up to the active term. Rotation
//! is completed by the conductor; publisher-side rotation comes in batch b.

use super::{
    AppendOptions, AppendOutcome, BufferOwner, Conductor, FragmentPlan, LayoutError, LogBuffer,
    Lookup, SysError, TermBytes, write_fragments, write_header_tail,
};
use crate::frame::{Flags, FrameType, Word0};
use crate::loan::{LoanOutcome, release_loan, take_loan};
use crate::publication::{
    acquire_publisher_slot, commit_block, mark_block, reissue_from, release_publisher_slot,
};
use crate::slot::{Descriptor, SlotState};
use crate::term::TermCount;
use crate::term_bytes::sealed::Access as _;
use core::sync::atomic::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandleState {
    /// A standing write loan on `count` in `slot`. `crossed` once this
    /// handle made its one end-crossing reservation in `count`, or found
    /// the term full: it makes no other reservation there.
    Active {
        count: TermCount,
        slot: u8,
        crossed: bool,
    },
    /// No loan: eligible once the active count reaches `from`.
    Waiting { from: TermCount },
}

/// A concurrent publication handle. Issued by
/// [`Conductor::concurrent_publication`]; it holds one publisher slot and
/// its write loan until it is closed or dropped.
#[derive(Debug)]
pub struct ConcurrentPublication<O: BufferOwner> {
    buffer: O,
    /// Publisher slot, also the registry cell of the handle's loan.
    index: usize,
    state: HandleState,
}

impl<O: BufferOwner> Conductor<O> {
    /// Issues a concurrent handle on a free publisher slot (control path),
    /// or `None` when all `P` slots are held. A reused slot starts at the
    /// active term unless its previous holder closed in the still active
    /// term after a crossing in it, in which case the handle waits for the
    /// next term (`quantstratum-docs: karyos/design/concurrent-publication.md`, handoff).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidPublicationMode`] for an exclusive
    /// buffer, and errors from the descriptor protocol.
    pub fn concurrent_publication(&mut self) -> Result<Option<ConcurrentPublication<O>>, SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        if !buffer.concurrent() {
            return Err(SysError::InvalidPublicationMode {
                reason: "a concurrent handle of an exclusive buffer",
            });
        }
        // The Acquire load observes a closing holder's Release of FREE,
        // made after its last access.
        let Some((index, previous)) =
            buffer
                .publishers
                .iter()
                .enumerate()
                .find_map(|(index, word)| {
                    acquire_publisher_slot(word).map(|previous| (index, previous))
                })
        else {
            return Ok(None);
        };
        let issue = || -> Result<TermCount, SysError> {
            let active = TermCount::try_new(buffer.active_count.load(Ordering::Acquire) as u32)?;
            let mut crossed_error = None;
            let from = reissue_from(previous, active.get(), || {
                // `t_close` is still active here.
                crossed(buffer, active).unwrap_or_else(|error| {
                    crossed_error = Some(error);
                    true
                })
            });
            if let Some(error) = crossed_error {
                return Err(error);
            }
            TermCount::try_new(from)
        };
        let from = match issue() {
            Ok(from) => from,
            Err(error) => {
                // Not issued: give the slot back as it was.
                if let Some(word) = buffer.publishers.get(index) {
                    word.store(
                        previous.map_or(0, |t_close| u64::from(t_close) + 1),
                        Ordering::Release,
                    );
                }
                return Err(error);
            }
        };
        let mut handle = ConcurrentPublication {
            buffer: self.buffer.clone(),
            index,
            state: HandleState::Waiting { from },
        };
        let _ = handle.catch_up()?;
        Ok(Some(handle))
    }
}

/// Whether term `count`, still active, has been crossed: its raw tail is at
/// or past the term end. The conductor calls it while `count` is active, so
/// its slot is not reclaimable, and it is the only reclaimer.
fn crossed<T: TermBytes>(buffer: &LogBuffer<T>, count: TermCount) -> Result<bool, SysError> {
    let Lookup::Slot(slot) = buffer.lookup(count)? else {
        return Ok(true);
    };
    let term_id = buffer.initial_term_id.advanced_by(count);
    let found = Descriptor::decode(buffer.descriptor(slot)?.load(Ordering::Acquire))?;
    if found.state() != SlotState::Active || found.term_id() != term_id {
        return Ok(true);
    }
    let raw = buffer.tail(slot)?.load(Ordering::Acquire);
    Ok((raw >> 32) as u32 != term_id.get() || raw as u32 >= buffer.term_length)
}

impl<O: BufferOwner> ConcurrentPublication<O> {
    /// The buffer this handle publishes to.
    #[must_use]
    pub fn buffer(&self) -> &LogBuffer<O::Terms> {
        &self.buffer
    }

    /// Offers one message with one reservation attempt (SPEC.md §4,
    /// concurrent publication): `Appended` once committed, `BackPressured`
    /// past the limit, `AdminAction` when the handle waits for a later term
    /// or its reservation crossed or landed past the term end (the crossing
    /// owner first commits a `PAD` over the remainder it owns).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::EmptyMessage`], layout errors for messages that
    /// are too large, and errors from the descriptor protocol. A validation
    /// error (empty or too large) reserves nothing; an error after the
    /// reservation means another party marked a block this handle owns.
    pub fn offer(
        &mut self,
        payload: &[u8],
        options: AppendOptions,
    ) -> Result<AppendOutcome, SysError> {
        if payload.is_empty() {
            return Err(SysError::EmptyMessage);
        }
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let ext = options.extension.is_some();
        let lane = buffer.config.lane;
        let plan = FragmentPlan::new(
            buffer.config.mtu,
            Flags::new(false, false, false, ext, lane),
        )?;
        let length = u32::try_from(payload.len()).map_err(|_| LayoutError::LengthOverflow {
            value: payload.len() as u64,
        })?;
        let max = if ext {
            plan.max_message_length(buffer.config.max_reserved, buffer.config.term_length)?
        } else {
            buffer.max_message_length
        };
        FragmentPlan::check_message(length, max)?;
        let reserved = plan.reserved(length)?;
        if !self.catch_up()? {
            return Ok(AppendOutcome::AdminAction);
        }
        let HandleState::Active { count, slot, .. } = self.state else {
            return Ok(AppendOutcome::AdminAction);
        };
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let tail = buffer.tail(slot)?;
        let term_length = buffer.term_length;
        // Under the handle's loan on `count`, the slot holds `count`.
        let offset = tail.load(Ordering::Acquire) as u32;
        // The last representable term has no successor: a reservation
        // that would reach its end is refused before any `fetch_add`, every
        // time (SPEC.md §4: positions stop at `2^31` terms).
        if count.next().is_err() && u64::from(offset) + u64::from(reserved) > u64::from(term_length)
        {
            count.next()?;
        }
        if offset >= term_length {
            self.mark_crossed();
            return Ok(AppendOutcome::AdminAction);
        }
        // The head of the handle's own term, never above the true head.
        let head = buffer.position(count, offset);
        if head + u64::from(reserved) > buffer.limit.load(Ordering::Acquire) {
            return Ok(AppendOutcome::BackPressured);
        }
        let old = tail.fetch_add(u64::from(reserved), Ordering::AcqRel);
        debug_assert_eq!(
            (old >> 32) as u32,
            buffer.initial_term_id.advanced_by(count).get()
        );
        let start = old as u32;
        if start >= term_length {
            // Landed past the end: holds nothing.
            self.mark_crossed();
            return Ok(AppendOutcome::AdminAction);
        }
        // `start < 2^31` and `reserved ≤ term_length / 8`: no overflow.
        if start + reserved > term_length {
            // Crossing: this handle owns the remainder.
            let extent = term_length - start;
            let flags = Flags::new(false, false, false, false, lane);
            let pad = Word0::new(extent as i32, flags, FrameType::Pad);
            let reserved_pad = Word0::new(-(extent as i32), flags, FrameType::Pad);
            // SAFETY: the handle's write loan on `count` in `slot` is held;
            // `start` is the frame start of the remainder it owns.
            let word = unsafe { buffer.regions.word0(slot, start) };
            if !mark_block(word, reserved_pad) {
                return Err(foreign_mark(start));
            }
            write_header_tail(buffer, slot, count, start, 0);
            if !commit_block(word, reserved_pad, pad) {
                return Err(foreign_mark(start));
            }
            self.mark_crossed();
            return Ok(AppendOutcome::AdminAction);
        }
        // The block `[start, start + reserved)` is this handle's alone.
        let fragments = plan.fragments(length);
        let first_flags = Flags::new(true, fragments == 1, false, ext, lane);
        let reserved_word = Word0::new(-(reserved as i32), first_flags, FrameType::Data);
        // SAFETY: write loan held; `start` is the block's first frame start.
        let word = unsafe { buffer.regions.word0(slot, start) };
        if !mark_block(word, reserved_word) {
            return Err(foreign_mark(start));
        }
        let first = write_fragments(buffer, slot, count, start, payload, &plan, options);
        if !commit_block(word, reserved_word, first) {
            return Err(foreign_mark(start));
        }
        Ok(AppendOutcome::Appended {
            position: buffer.position(count, start),
        })
    }

    /// Closes the handle: releases its loan and its publisher slot, as
    /// dropping it does.
    pub fn close(self) {}

    fn mark_crossed(&mut self) {
        if let HandleState::Active { crossed, .. } = &mut self.state {
            *crossed = true;
        }
    }

    /// Moves to the active term when this handle may: after its crossing
    /// in an earlier term, or once a waiting handle is eligible. Returns
    /// whether the handle holds a loan on a term it may reserve in.
    fn catch_up(&mut self) -> Result<bool, SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let active = TermCount::try_new(buffer.active_count.load(Ordering::Acquire) as u32)?;
        let cell = buffer.cell(self.index)?;
        match self.state {
            HandleState::Active { crossed: false, .. } => return Ok(true),
            HandleState::Active {
                count,
                crossed: true,
                ..
            } => {
                // A crossing in the last term (another handle's reservation
                // pushed this one past the end) has no successor to wait for.
                count.next()?;
                if active.get() <= count.get() {
                    return Ok(false);
                }
                // Every access to `count` has ended.
                release_loan(&cell.loan);
                self.state = HandleState::Waiting { from: active };
            }
            HandleState::Waiting { from } => {
                if active.get() < from.get() {
                    return Ok(false);
                }
            }
        }
        let Lookup::Slot(slot) = buffer.lookup(active)? else {
            return Ok(false);
        };
        match take_loan(
            &cell.loan,
            &cell.revoked,
            buffer.descriptor(slot)?,
            buffer.target(slot, active)?,
        )? {
            LoanOutcome::Granted => {
                self.state = HandleState::Active {
                    count: active,
                    slot,
                    crossed: false,
                };
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

impl<O: BufferOwner> Drop for ConcurrentPublication<O> {
    fn drop(&mut self) {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        if let HandleState::Active { .. } = self.state
            && let Ok(cell) = buffer.cell(self.index)
        {
            release_loan(&cell.loan);
        }
        let active = buffer.active_count.load(Ordering::Acquire) as u32;
        if let Some(word) = buffer.publishers.get(self.index) {
            // After the handle's last access.
            release_publisher_slot(word, active);
        }
    }
}

/// A marked or terminal word where this handle's reservation starts:
/// another party wrote a block this handle owns, which no legal history
/// produces while nothing aborts concurrent blocks (batch a).
fn foreign_mark(offset: u32) -> SysError {
    SysError::CorruptTerm {
        offset,
        reason: "concurrent reservation already marked",
    }
}
