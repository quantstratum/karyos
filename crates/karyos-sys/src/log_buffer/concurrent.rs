// SPDX-License-Identifier: Apache-2.0

//! Concurrent publication handles (`quantstratum-docs: karyos/design/concurrent-publication.md`,
//! batch a): publisher slots and their handoff, one `fetch_add` reservation
//! per message on the active slot's raw tail, commit-or-abort publication,
//! the crossing owner's `PAD`, and catching up to the active term. Rotation
//! is completed by the conductor; publisher-side rotation comes in batch b.

use super::{
    AppendOptions, AppendOutcome, BufferOwner, CommitOutcome, Conductor, FragmentPlan,
    HEADER_LENGTH, LayoutError, LogBuffer, Lookup, SysError, TermBytes, write_fragments,
    write_header_tail,
};
use crate::frame::{FRAME_ALIGNMENT, Flags, FrameType, PROTOCOL_VERSION, Word0};
use crate::loan::{LoanOutcome, release_loan, rotate_to, take_loan};
use crate::publication::{
    ABORTING_MARKER, abort_block, acquire_publisher_slot, commit_block, mark_block, observe_block,
    reissue_from, release_publisher_slot,
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
    /// The outstanding claim, private to the handle (claims.md); never in
    /// the buffer's claim record.
    pending: Option<Pending>,
    /// Claim payload staging on backings without direct bytes.
    staging: Box<[u8]>,
}

/// A marked claim block of a concurrent handle.
#[derive(Debug, Clone, Copy)]
struct Pending {
    slot: u8,
    start: u32,
    position: u64,
    length: u32,
    header_length: u32,
    reserved: Word0,
    committed: Word0,
    aborted: Word0,
}

/// Result of [`ConcurrentPublication::offer`]. Unlike the exclusive
/// [`AppendOutcome`], a concurrent offer can lose its block to the
/// commit-deadline abort (`quantstratum-docs: karyos/design/concurrent-deadline.md`): pre-1.0,
/// `offer` returns this type instead of `AppendOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "back pressure, aborts and admin actions must be handled"]
pub enum ConcurrentOfferOutcome {
    /// The message was published; its block starts at `position`.
    Appended {
        /// Stream position of the block.
        position: u64,
    },
    /// The message was not published: the conductor's deadline abort won
    /// the block reserved at `position` on the buffer's lane, before its
    /// mark or its commit. Readers skip it; the message may be offered
    /// again.
    Aborted {
        /// Stream position of the reserved block.
        position: u64,
    },
    /// The flow-control limit does not admit the reservation; retry later.
    BackPressured,
    /// The handle waits for a later term, or its reservation crossed or
    /// landed past the term end; retry later.
    AdminAction,
}

impl From<AppendOutcome> for ConcurrentOfferOutcome {
    fn from(outcome: AppendOutcome) -> Self {
        match outcome {
            AppendOutcome::Appended { position } => Self::Appended { position },
            AppendOutcome::BackPressured => Self::BackPressured,
            AppendOutcome::AdminAction => Self::AdminAction,
        }
    }
}

/// Result of [`ConcurrentPublication::try_claim`].
#[derive(Debug)]
#[must_use = "back pressure and admin actions must be handled"]
pub enum ConcurrentClaimOutcome<'a, O: BufferOwner> {
    /// A block was reserved and marked; write the payload, then commit.
    Claimed(ConcurrentClaim<'a, O>),
    /// The flow-control limit does not admit the reservation; retry later.
    BackPressured,
    /// The handle waits for a later term, or its reservation crossed or
    /// landed past the term end; retry later.
    AdminAction,
    /// The block reserved at `position` was aborted by the conductor's
    /// deadline before this call marked it: nothing was written. Pre-1.0
    /// addition (`quantstratum-docs: karyos/design/concurrent-deadline.md`).
    Aborted {
        /// Stream position of the reserved block.
        position: u64,
    },
}

/// A claimed block of a concurrent handle: it mutably borrows the handle;
/// [`ConcurrentClaim::commit`] publishes it, and [`ConcurrentClaim::abort`]
/// or dropping it uncommitted aborts it. A forgotten claim is aborted by
/// the handle's next mutable operation or its drop.
///
/// The payload cannot outlive the claim:
///
/// ```compile_fail,E0597
/// # use karyos_sys::log_buffer::*;
/// fn escape<O: BufferOwner + core::fmt::Debug>(handle: &mut ConcurrentPublication<O>) {
///     let payload;
///     {
///         let Ok(ConcurrentClaimOutcome::Claimed(mut claim)) =
///             handle.try_claim(8, AppendOptions::default())
///         else {
///             return;
///         };
///         payload = claim.payload();
///     }
///     payload[0] = 1;
/// }
/// ```
///
/// nor be used after `commit`:
///
/// ```compile_fail,E0505
/// # use karyos_sys::log_buffer::*;
/// fn after_commit<O: BufferOwner>(mut claim: ConcurrentClaim<'_, O>) {
///     let payload = claim.payload();
///     let _ = claim.commit();
///     payload[0] = 1;
/// }
/// ```
#[derive(Debug)]
pub struct ConcurrentClaim<'a, O: BufferOwner> {
    handle: &'a mut ConcurrentPublication<O>,
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
    /// buffer, [`SysError::ResourcesUnavailable`] when the claim staging of
    /// a shared buffer cannot be allocated (no slot is taken then), and
    /// errors from the descriptor protocol (the slot is given back).
    pub fn concurrent_publication(&mut self) -> Result<Option<ConcurrentPublication<O>>, SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        if !buffer.concurrent() {
            return Err(SysError::InvalidPublicationMode {
                reason: "a concurrent handle of an exclusive buffer",
            });
        }
        // Allocated before a slot is taken, so a failure leaves no slot held.
        let staging = if <O::Terms as crate::term_bytes::sealed::Access>::DIRECT {
            Box::default()
        } else {
            let plan = FragmentPlan::new(
                buffer.config.mtu,
                Flags::new(true, true, false, false, buffer.config.lane),
            )?;
            let size = plan.payload_per_fragment().min(buffer.max_message_length) as usize;
            let mut staging = Vec::new();
            staging
                .try_reserve_exact(size)
                .map_err(|_| SysError::ResourcesUnavailable)?;
            staging.resize(size, 0u8);
            staging.into_boxed_slice()
        };
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
            // `from` is the active count, or the successor of the still
            // active closing term: its exhaustion is MaxPositionExceeded.
            if from == active.get() {
                Ok(active)
            } else {
                active.next()
            }
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
            pending: None,
            staging,
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
    /// concurrent publication): `Appended` once committed, `Aborted` when
    /// the conductor's deadline abort won its block, `BackPressured` past
    /// the limit, `AdminAction` when the handle waits for a later term or
    /// its reservation crossed or landed past the term end (the crossing
    /// owner first commits a `PAD` over the remainder it owns).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::EmptyMessage`], layout errors for messages that
    /// are too large, and errors from the descriptor protocol. A validation
    /// error (empty or too large) reserves nothing; an error after the
    /// reservation means a word this handle owns holds something no legal
    /// history writes.
    pub fn offer(
        &mut self,
        payload: &[u8],
        options: AppendOptions,
    ) -> Result<ConcurrentOfferOutcome, SysError> {
        self.offer_pausing(payload, options, &mut |_| {})
    }

    /// [`ConcurrentPublication::offer`] with test pause points.
    pub(super) fn offer_pausing(
        &mut self,
        payload: &[u8],
        options: AppendOptions,
        pause: &mut dyn FnMut(WriterPause),
    ) -> Result<ConcurrentOfferOutcome, SysError> {
        self.resolve_claim();
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
        let (count, slot, start) = match self.reserve(reserved, pause)? {
            Reserved::Own { count, slot, start } => (count, slot, start),
            Reserved::Outcome(outcome) => return Ok(outcome.into()),
        };
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let position = buffer.position(count, start);
        // The block `[start, start + reserved)` is this handle's alone,
        // unless the deadline's span walk takes its first word first.
        let fragments = plan.fragments(length);
        let first_flags = Flags::new(true, fragments == 1, false, ext, lane);
        let reserved_word = Word0::new(-(reserved as i32), first_flags, FrameType::Data);
        // SAFETY: write loan held; `start` is the block's first frame start.
        let word = unsafe { buffer.regions.word0(slot, start) };
        pause(WriterPause::Mark);
        if !mark_block(word, reserved_word) {
            // Nothing written.
            span_taken(buffer, word, start)?;
            return Ok(ConcurrentOfferOutcome::Aborted { position });
        }
        let first = write_fragments(buffer, slot, count, start, payload, &plan, options);
        pause(WriterPause::Commit);
        if !commit_block(word, reserved_word, first) {
            lost_commit(buffer, word, start, reserved)?;
            return Ok(ConcurrentOfferOutcome::Aborted { position });
        }
        Ok(ConcurrentOfferOutcome::Appended { position })
    }

    /// Claims one unfragmented block of `length` payload bytes with one
    /// reservation attempt (SPEC.md §4 claims). The claim's payload starts
    /// zeroed.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::EmptyMessage`] and
    /// [`LayoutError::MessageTooLarge`] when `length` exceeds
    /// `max_message_length`, one fragment or `max_reserved`, and
    /// [`SysError::MaxPositionExceeded`] at the last term. A validation
    /// error reserves nothing (a forgotten claim is still resolved first);
    /// an error after the reservation means a word this handle owns holds
    /// something no legal history writes. `Aborted` means the conductor's
    /// deadline abort took the block before its mark: nothing was written.
    pub fn try_claim(
        &mut self,
        length: u32,
        options: AppendOptions,
    ) -> Result<ConcurrentClaimOutcome<'_, O>, SysError> {
        self.try_claim_pausing(length, options, &mut |_| {})
    }

    /// [`ConcurrentPublication::try_claim`] with test pause points.
    pub(super) fn try_claim_pausing(
        &mut self,
        length: u32,
        options: AppendOptions,
        pause: &mut dyn FnMut(WriterPause),
    ) -> Result<ConcurrentClaimOutcome<'_, O>, SysError> {
        self.resolve_claim();
        if length == 0 {
            return Err(SysError::EmptyMessage);
        }
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let ext = options.extension.is_some();
        let lane = buffer.config.lane;
        let flags = Flags::new(true, true, options.end_of_stream, ext, lane);
        let plan = FragmentPlan::new(buffer.config.mtu, flags)?;
        let max = if ext {
            plan.max_message_length(buffer.config.max_reserved, buffer.config.term_length)?
        } else {
            buffer.max_message_length
        };
        FragmentPlan::check_message(length, max)?;
        FragmentPlan::check_message(length, plan.payload_per_fragment())?;
        let reserved = plan.reserved(length)?;
        if reserved > buffer.config.max_reserved {
            return Err(LayoutError::MessageTooLarge { length, max }.into());
        }
        let (count, slot, start) = match self.reserve(reserved, pause)? {
            Reserved::Own { count, slot, start } => (count, slot, start),
            Reserved::Outcome(AppendOutcome::BackPressured) => {
                return Ok(ConcurrentClaimOutcome::BackPressured);
            }
            Reserved::Outcome(_) => return Ok(ConcurrentClaimOutcome::AdminAction),
        };
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let header_length = flags.header_length();
        let reserved_word = Word0::new(-(reserved as i32), flags, FrameType::Data);
        // SAFETY: write loan held; `start` is the block's first frame start.
        let word = unsafe { buffer.regions.word0(slot, start) };
        pause(WriterPause::Mark);
        if !mark_block(word, reserved_word) {
            span_taken(buffer, word, start)?;
            return Ok(ConcurrentClaimOutcome::Aborted {
                position: buffer.position(count, start),
            });
        }
        write_header_tail(buffer, slot, count, start, options.reserved_value);
        if let Some(extension) = &options.extension {
            // SAFETY: write loan held; the extension follows the header of
            // the marked, unpublished frame; not a word 0.
            unsafe {
                buffer
                    .regions
                    .write_bytes(slot, start + HEADER_LENGTH, extension)
            };
        }
        if let Some(staging) = self.staging.get_mut(..length as usize) {
            staging.fill(0);
        }
        self.pending = Some(Pending {
            slot,
            start,
            position: buffer.position(count, start),
            length,
            header_length,
            reserved: reserved_word,
            committed: Word0::new((header_length + length) as i32, flags, FrameType::Data),
            aborted: Word0::new(
                reserved as i32,
                Flags::new(false, false, false, false, lane),
                FrameType::Aborted,
            ),
        });
        Ok(ConcurrentClaimOutcome::Claimed(ConcurrentClaim {
            handle: self,
        }))
    }

    /// Aborts the outstanding claim, if any: no reference into it remains
    /// (the claim borrowed the handle mutably).
    fn resolve_claim(&mut self) {
        let Some(claim) = self.pending.take() else {
            return;
        };
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        // SAFETY: the handle's loan on the claim's term is still held: no
        // catch-up ran while the claim was outstanding.
        let word = unsafe { buffer.regions.word0(claim.slot, claim.start) };
        let _ = abort_block(word, claim.reserved, claim.aborted);
    }

    /// One reservation attempt of `reserved` bytes: catch up, check the
    /// tail and the limit, one `fetch_add`. A crossing commits the `PAD`
    /// this handle owns; a reservation past the end holds nothing.
    fn reserve(
        &mut self,
        reserved: u32,
        pause: &mut dyn FnMut(WriterPause),
    ) -> Result<Reserved, SysError> {
        // At most one rotation attempt per call (SPEC.md §4).
        let mut help = true;
        if !self.catch_up_helping(&mut help)? {
            return Ok(Reserved::Outcome(AppendOutcome::AdminAction));
        }
        let HandleState::Active { count, slot, .. } = self.state else {
            return Ok(Reserved::Outcome(AppendOutcome::AdminAction));
        };
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let lane = buffer.config.lane;
        let tail = buffer.tail(slot)?;
        let term_length = buffer.term_length;
        // Under the handle's loan on `count`, the slot holds `count`.
        let offset = tail.load(Ordering::Acquire) as u32;
        // The last representable term has no successor: a reservation
        // that would exceed its end is refused before any `fetch_add`, every
        // time (SPEC.md §4: positions stop at `2^31` terms).
        if count.next().is_err() && u64::from(offset) + u64::from(reserved) > u64::from(term_length)
        {
            count.next()?;
        }
        if offset >= term_length {
            // Full: no reservation here; help the rotation once and let the
            // next call catch up.
            self.mark_crossed();
            self.help_rotation(count, &mut help)?;
            return Ok(Reserved::Outcome(AppendOutcome::AdminAction));
        }
        // The head of the handle's own term, never above the true head.
        let head = buffer.position(count, offset);
        if head + u64::from(reserved) > buffer.limit.load(Ordering::Acquire) {
            return Ok(Reserved::Outcome(AppendOutcome::BackPressured));
        }
        let old = tail.fetch_add(u64::from(reserved), Ordering::AcqRel);
        debug_assert_eq!(
            (old >> 32) as u32,
            buffer.initial_term_id.advanced_by(count).get()
        );
        let start = old as u32;
        if start >= term_length {
            // Landed past the end: holds nothing; helps rotate once.
            self.mark_crossed();
            self.help_rotation(count, &mut help)?;
            return Ok(Reserved::Outcome(AppendOutcome::AdminAction));
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
            // A remainder the deadline aborted holds no message: the
            // crossing still ends this handle's term either way.
            pause(WriterPause::PadMark);
            if mark_block(word, reserved_pad) {
                write_header_tail(buffer, slot, count, start, 0);
                pause(WriterPause::PadCommit);
                if !commit_block(word, reserved_pad, pad) {
                    lost_commit(buffer, word, start, extent)?;
                }
            } else {
                span_taken(buffer, word, start)?;
            }
            self.mark_crossed();
            self.help_rotation(count, &mut help)?;
            return Ok(Reserved::Outcome(AppendOutcome::AdminAction));
        }
        Ok(Reserved::Own { count, slot, start })
    }

    /// Closes the handle: releases its loan and its publisher slot, as
    /// dropping it does.
    pub fn close(self) {}

    /// One rotation attempt from `count` to the next term (SPEC.md §4
    /// rotation), by the crossing owner or a producer that landed past the
    /// end. Its result does not change the call's outcome (`AdminAction`).
    fn help_rotation(&self, count: TermCount, help: &mut bool) -> Result<(), SysError> {
        if !core::mem::replace(help, false) {
            return Ok(());
        }
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let next = count.next()?;
        let Lookup::Slot(slot) = buffer.lookup(next)? else {
            return Ok(());
        };
        let _ = rotate_to(
            buffer.descriptor(slot)?,
            &buffer.active_count,
            buffer.initial_term_id.advanced_by(next),
            buffer.generation,
            next,
        )?;
        Ok(())
    }

    fn mark_crossed(&mut self) {
        if let HandleState::Active { crossed, .. } = &mut self.state {
            *crossed = true;
        }
    }

    /// Moves to the active term when this handle may: after its crossing
    /// in an earlier term, or once a waiting handle is eligible. Returns
    /// whether the handle holds a loan on a term it may reserve in.
    fn catch_up(&mut self) -> Result<bool, SysError> {
        self.catch_up_helping(&mut false)
    }

    /// [`ConcurrentPublication::catch_up`], spending the call's rotation
    /// attempt (`help`) when a crossed handle finds no later active term.
    fn catch_up_helping(&mut self, help: &mut bool) -> Result<bool, SysError> {
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
                    // The successor may have become ready since: help the
                    // rotation once, then wait for a later call.
                    self.help_rotation(count, help)?;
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
        self.resolve_claim();
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

impl<O: BufferOwner> ConcurrentClaim<'_, O> {
    /// Stream position of the block.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.handle.pending.map_or(0, |claim| claim.position)
    }

    /// The payload: exactly the claimed length, zeroed at claim time.
    pub fn payload(&mut self) -> &mut [u8] {
        let handle = &mut *self.handle;
        let Some(claim) = handle.pending else {
            return &mut [];
        };
        // SAFETY: the claim marked its block under the handle's write
        // loan, held while the claim exists (a borrow of `self`); the range
        // is the frame's payload, holding no control word; readers do not
        // access a block whose word 0 is negative, and no other party
        // writes a block this handle reserved.
        let direct = unsafe {
            handle.buffer.regions.direct_bytes(
                claim.slot,
                claim.start + claim.header_length,
                claim.length,
            )
        };
        match direct {
            // SAFETY: as above; the slice borrows `self` mutably.
            Some(pointer) => unsafe {
                core::slice::from_raw_parts_mut(pointer.as_ptr(), claim.length as usize)
            },
            None => handle
                .staging
                .get_mut(..claim.length as usize)
                .unwrap_or_default(),
        }
    }

    /// Commits the block: exactly one of commit and abort wins.
    pub fn commit(self) -> CommitOutcome {
        let handle = &mut *self.handle;
        let Some(claim) = handle.pending.take() else {
            return CommitOutcome::Aborted { position: 0 };
        };
        let buffer: &LogBuffer<O::Terms> = &handle.buffer;
        if let Some(staging) = handle.staging.get(..claim.length as usize)
            && !<O::Terms as crate::term_bytes::sealed::Access>::DIRECT
        {
            // SAFETY: write loan held; the payload range of the marked,
            // unpublished frame; the bytes up to the next word read as zero.
            unsafe {
                buffer
                    .regions
                    .write_bytes(claim.slot, claim.start + claim.header_length, staging)
            };
        }
        // SAFETY: write loan held; the block's first frame start.
        let word = unsafe { buffer.regions.word0(claim.slot, claim.start) };
        if commit_block(word, claim.reserved, claim.committed) {
            CommitOutcome::Committed {
                position: claim.position,
            }
        } else {
            CommitOutcome::Aborted {
                position: claim.position,
            }
        }
    }

    /// Aborts the block; readers skip it.
    pub fn abort(self) {}
}

impl<O: BufferOwner> Drop for ConcurrentClaim<'_, O> {
    fn drop(&mut self) {
        self.handle.resolve_claim();
    }
}

/// Where a test pauses a concurrent writer, after its `fetch_add`: before
/// the named compare-exchange of its block or of its crossing `PAD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriterPause {
    Mark,
    Commit,
    PadMark,
    PadCommit,
}

/// Result of one reservation attempt.
enum Reserved {
    /// `[start, start + reserved)` in `slot`'s term `count` is this
    /// handle's alone.
    Own {
        count: TermCount,
        slot: u8,
        start: u32,
    },
    /// No block: the outcome to report.
    Outcome(AppendOutcome),
}

/// A failed mark at `start`: the deadline's span walk took the word first
/// (`quantstratum-docs: karyos/design/concurrent-deadline.md`), so it holds the exact aborting
/// marker or, once the walk ended, a valid `ABORTED` word starting there.
/// Anything else is a broken invariant.
fn span_taken<T: TermBytes>(
    buffer: &LogBuffer<T>,
    word: &core::sync::atomic::AtomicU64,
    start: u32,
) -> Result<(), SysError> {
    let found = observe_block(word);
    let aborted = Word0::unpack(found).is_ok_and(|word0| {
        let extent = word0.frame_length();
        word0.version() == PROTOCOL_VERSION
            && word0.frame_type_code() == FrameType::Aborted.code()
            && word0.flags() == Flags::new(false, false, false, false, buffer.config.lane)
            && extent > 0
            && (extent as u32).is_multiple_of(FRAME_ALIGNMENT)
            && extent as u32 <= buffer.term_length - start
    });
    if found == ABORTING_MARKER.pack() || aborted {
        Ok(())
    } else {
        Err(SysError::CorruptTerm {
            offset: start,
            reason: "concurrent reservation already marked",
        })
    }
}

/// A lost commit of the marked block of `extent` bytes at `start`: the
/// deadline abort won, so the word is exactly its `ABORTED` word.
fn lost_commit<T: TermBytes>(
    buffer: &LogBuffer<T>,
    word: &core::sync::atomic::AtomicU64,
    start: u32,
    extent: u32,
) -> Result<(), SysError> {
    let aborted = Word0::new(
        extent as i32,
        Flags::new(false, false, false, false, buffer.config.lane),
        FrameType::Aborted,
    );
    if observe_block(word) == aborted.pack() {
        Ok(())
    } else {
        Err(SysError::CorruptTerm {
            offset: start,
            reason: "concurrent commit lost to a foreign word",
        })
    }
}
