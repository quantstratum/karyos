// SPDX-License-Identifier: Apache-2.0

//! The network sender's read capability (`quantstratum-docs:
//! karyos/design/network-sessions-sender.md` S2; driver network agents
//! phase 5a).
//!
//! [`SenderRead`] owns one subscriber cell of one lane's log buffer: a SPEC
//! §4 participant with its own loan word and revoked flag. It is a
//! required participant on every channel (SPEC §4: the sender's position
//! bounds the publisher; on an unreliable channel it is the sent
//! position), admitted with its `L_send` slot credit reserved against
//! `S - C` (S2 2.1, `Conductor::subscribe_as` with `reserve`). Each
//! [`SenderRead::read_committed`] call takes one
//! loan on the exact `(generation, term)` of its position, copies whole
//! committed frames into the caller's TX storage and releases the loan
//! before it returns, on every path. A loan never spans a backend
//! submission, a flush or a duty cycle.
//!
//! - **Reads.** Committed DATA frames are copied whole, extension
//!   included, at 32-byte strides as a DATA datagram carries them; each
//!   frame's word 0 is written from the value the read loaded and
//!   validated, and loaded again after the copy (a change is
//!   `CorruptTerm`). An ABORTED or PAD block yields its canonical 32-byte
//!   record, alone; no byte of its extent is read. A committed DATA frame
//!   with no payload breaks the log's rules (an application message has at
//!   least one byte) and is `CorruptTerm`. One call never crosses a term
//!   end or the seal (C-2).
//! - **Seal.** At the seal position a read is `Pending`, as for a frontier;
//!   the sender tells the two apart with [`SenderRead::seal_position`].
//! - **Sent position.** Reading never moves the registered position; only
//!   [`SenderRead::sent`], called on the backend's submission, does.
//! - **Corruption (C-9).** `CorruptTerm` at the cursor is retried on later
//!   calls, at most `corrupt_retries` times for that block, the count
//!   resetting when the cursor advances; then the reader is faulted and
//!   every later call returns [`ReadError::Faulted`]. The block is never
//!   skipped.
//!
//! Limits of this phase: the only origin is the sender's own cursor
//! ([`ReadOrigin::Cursor`]); NAK reads (S2 2.3, `BadRequest` and the
//! checkpoint arrays) and reads of a draining generation (2.4) come with
//! repair in phase 6, and so does the retention floor at `sent -
//! retransmit_window`: until then the registered position bounds it. A
//! reader covers one lane; the incarnation's lanes are the sender agent's.
//!
//! Safety (ADR-0034): every term byte is read under a loan taken with the
//! SPEC §4 acquisition (`take_loan`: loan word `SeqCst`, then the slot
//! descriptor and the revoked flag) for the exact term of the position,
//! and released with a `Release` store after the last read. The retention
//! floor is checked again after the loan is granted. A block's first word
//! 0 is loaded with `Acquire` and its whole geometry validated before any
//! of its bytes is read; interior word 0s are read after that `Acquire`,
//! in this call or, for a block resumed at an interior frame, in an
//! earlier call under a loan of the same term incarnation, so the block is
//! the one observed. Interior loads are `Relaxed`, where S2 2.3 says
//! `Acquire`: a block is published by one `Release` of its first word 0,
//! whose `Acquire` already orders every interior frame (as `FrameReader`
//! reads them). Only committed DATA bytes are read; an aborted extent is
//! never read past its word 0.

use core::sync::atomic::{Ordering, fence};
use std::collections::VecDeque;

use super::{
    BufferOwner, Cursor, LogBuffer, Lookup, Role, SealWord, Subscription, SubscriptionContext,
    Validated, decode_seal,
};
use crate::error::SysError;
use crate::frame::{Flags, FrameType, HEADER_LENGTH, Word0};
use crate::loan::{LoanOutcome, release_loan, take_loan};
use crate::participant::CELL_REQUIRED_RESERVED;
use crate::publication::load_interior;
use crate::sizing::align_frame;
use crate::term::TermCount;
use crate::term_bytes::sealed::Access as _;

/// The default `corrupt_retries` (C-9).
pub const DEFAULT_CORRUPT_RETRIES: u32 = 3;

/// Bytes of a canonical PAD or ABORTED record.
const CANONICAL_LENGTH: usize = HEADER_LENGTH as usize;

/// Where a read's position came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOrigin {
    /// The sender's own cursor: a frame boundary it computed. NAK reads
    /// come with phase 6.
    Cursor,
}

/// The kind of a canonical record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalKind {
    /// Padding to the term end.
    Pad,
    /// An aborted block.
    Aborted,
}

/// What a read produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// `len` bytes of whole frames were copied; the next read starts at
    /// `next`.
    Copied {
        /// Bytes of the datagram: the last frame ends here.
        len: usize,
        /// The cursor after the copy.
        next: u64,
    },
    /// Nothing is committed at the position yet.
    Pending,
    /// The block at the position is an aborted block or padding: `out`
    /// holds its canonical 32-byte record, alone, and `next` is past its
    /// logical extent.
    Canonical {
        /// Which record.
        record: CanonicalKind,
        /// The cursor after the record.
        next: u64,
    },
}

/// Why a read copied nothing. The loan word is empty on every one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The position is below the retention floor, or its term was
    /// reclaimed; `lowest` is the floor read after the refusal.
    Unavailable {
        /// The lowest retained position.
        lowest: u64,
    },
    /// The term of the position is not active yet, or the head could not
    /// be read consistently: try on a later cycle.
    Retry,
    /// The position is not the cursor, lies past the head, or the buffer's
    /// state broke an invariant: a sender bug; nothing was read.
    Invariant,
    /// The reader's participant is revoked; no loan was taken.
    Revoked,
    /// A word 0 failed validation or changed between its two loads: the
    /// frame is not sent. `failures` counts the consecutive failures at
    /// this block, this one included.
    CorruptTerm {
        /// Failures at this block so far.
        failures: u32,
    },
    /// The corruption at `position` persisted past `corrupt_retries`: the
    /// lane is faulted and its incarnation ends (C-9).
    Faulted {
        /// The block that stayed corrupt.
        position: u64,
    },
    /// `out` cannot hold the first frame (or a 32-byte canonical record).
    TooSmall {
        /// Bytes needed.
        needed: usize,
    },
}

/// The reader's counters (S2 2.6): checked, sticky on overflow. The NAK
/// counter comes with phase 6; `invariant` raises an error log record once
/// the error log exists (phase 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SenderReadCounters {
    /// Reads that copied frames or a canonical record.
    pub reads: u64,
    /// Bytes copied.
    pub read_bytes: u64,
    /// Canonical records produced.
    pub canonical_records: u64,
    /// `Unavailable` results.
    pub unavailable: u64,
    /// `Retry` results.
    pub retry: u64,
    /// `CorruptTerm` and `Faulted` results.
    pub corrupt: u64,
    /// `Invariant` results.
    pub invariant: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

impl SenderReadCounters {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64, by: u64) {
        let value = field(self);
        match value.checked_add(by) {
            Some(next) => *value = next,
            None => self.overflowed = true,
        }
    }
}

/// A block the cursor stands inside: its first frames were copied by an
/// earlier call, under a loan of the same term.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpenBlock {
    count: TermCount,
    /// The term offset where the block ends.
    end: u32,
}

/// What one copy under a loan produced.
enum Copy {
    Frames {
        len: usize,
        end: u32,
        open: Option<u32>,
    },
    Pending,
    Canonical {
        record: CanonicalKind,
        end: u32,
    },
}

/// Why a copy under a loan stopped with nothing to send.
enum CopyError {
    Corrupt,
    TooSmall(usize),
    Invariant,
}

/// The sender read capability of one lane (see the module documentation).
#[derive(Debug)]
pub struct SenderRead<O: BufferOwner> {
    subscription: Subscription<O>,
    open: Option<OpenBlock>,
    /// The block of the last `CorruptTerm` and the failures there.
    corrupt: Option<(u64, u32)>,
    corrupt_retries: u32,
    faulted: Option<u64>,
    counters: SenderReadCounters,
    /// An interleaving injected by tests; nothing outside them.
    hook: HookSlot,
    /// The block-boundary `next` values of reads not yet registered, oldest
    /// first, at most `BOUNDARIES` (allocated at construction): the only
    /// positions [`SenderRead::sent`] accepts, so the registered position
    /// is always a block start that [`SenderRead::rewind`] can restart at.
    boundaries: VecDeque<u64>,
}

/// Block-boundary read ends a reader remembers until they are registered.
const BOUNDARIES: usize = 256;

#[cfg(test)]
type HookSlot = Option<TestHook>;
#[cfg(not(test))]
type HookSlot = ();

/// An interleaving a test injects into the next read: what another party
/// does at that point of the read.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum TestHook {
    /// The conductor raises the floor after the first floor check, before
    /// the loan.
    FloorBeforeLoan(u64),
    /// The slot descriptor becomes this raw value before the loan.
    DescriptorBeforeLoan(u64),
    /// A peer stores this raw word 0 at this term offset after the copy,
    /// before the second load.
    Word0BetweenLoads { offset: u32, raw: u64 },
}

impl<O: BufferOwner> SenderRead<O> {
    /// The read capability over `subscription`, a cell the conductor
    /// admitted as [`Role::Required`] with its slot credit reserved
    /// (`Conductor::subscribe_as(Role::Required, true, occupant)`). Its
    /// cursor and its registered position start at the subscription's
    /// acknowledged position.
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidPublicationMode`] for an image, or for any other
    /// cell (another role, or a required cell without its reservation).
    pub fn new(mut subscription: Subscription<O>, corrupt_retries: u32) -> Result<Self, SysError> {
        if subscription.buffer.image() {
            return Err(SysError::InvalidPublicationMode {
                reason: "a sender read of an image",
            });
        }
        let reserved = subscription
            .buffer
            .cell(subscription.cursor.cell)
            .is_ok_and(|cell| cell.state.load(Ordering::Acquire) == CELL_REQUIRED_RESERVED);
        if subscription.cursor.role != Role::Required || !reserved {
            return Err(SysError::InvalidPublicationMode {
                reason: "a sender read is a required participant with its L_send reservation",
            });
        }
        if subscription.cursor.pending.take().is_some() {
            subscription.cursor.position = subscription.cursor.acknowledged;
        }
        Ok(Self {
            subscription,
            open: None,
            corrupt: None,
            corrupt_retries,
            faulted: None,
            counters: SenderReadCounters::default(),
            hook: HookSlot::default(),
            boundaries: VecDeque::with_capacity(BOUNDARIES),
        })
    }

    /// Injects `hook` into the next read (tests).
    #[cfg(test)]
    pub(crate) fn inject(&mut self, hook: TestHook) {
        self.hook = Some(hook);
    }

    /// The buffer it reads.
    #[must_use]
    pub fn subscription(&self) -> &Subscription<O> {
        &self.subscription
    }

    /// The read cursor: where the next read starts, a frame boundary.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.subscription.cursor.position
    }

    /// The registered (sent) position.
    #[must_use]
    pub fn sent_position(&self) -> u64 {
        self.subscription.cursor.acknowledged
    }

    /// Whether the cursor stands at a block boundary: the last read left
    /// no block open.
    #[must_use]
    pub fn at_boundary(&self) -> bool {
        self.open.is_none()
    }

    /// The highest block boundary this reader returned above the registered
    /// position and at or below `position`: what [`SenderRead::sent`]
    /// accepts for a submission (or a consumption bound) reaching
    /// `position`. `None` when there is none.
    #[must_use]
    pub fn boundary_at_or_below(&self, position: u64) -> Option<u64> {
        let registered = self.subscription.cursor.acknowledged;
        self.boundaries
            .iter()
            .rev()
            .copied()
            .find(|boundary| *boundary > registered && *boundary <= position)
    }

    /// Moves the cursor back to the registered position, dropping what was
    /// read past it and not submitted (an endpoint reset returned it): the
    /// next read starts there again. The registered position is a block
    /// start by construction (the join, or a boundary [`SenderRead::sent`]
    /// accepted), and never below the floor, so nothing it rereads is
    /// reclaimed. The C-9 count is kept: a rewind onto a corrupt block does
    /// not restore its retries.
    ///
    /// # Errors
    ///
    /// [`ReadError::Faulted`] once the reader is faulted; nothing moves.
    pub fn rewind(&mut self) -> Result<(), ReadError> {
        if let Some(position) = self.faulted {
            return Err(ReadError::Faulted { position });
        }
        let cursor = &mut self.subscription.cursor;
        cursor.position = cursor.acknowledged;
        self.open = None;
        self.boundaries.clear();
        Ok(())
    }

    /// Remembers `next`, a block boundary a read just returned.
    fn remember(boundaries: &mut VecDeque<u64>, next: u64) {
        if boundaries.len() >= BOUNDARIES {
            let _ = boundaries.pop_front();
        }
        boundaries.push_back(next);
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> SenderReadCounters {
        self.counters
    }

    /// The seal position, once the publication is sealed and positioned:
    /// nothing is committed at or after it.
    #[must_use]
    pub fn seal_position(&self) -> Option<u64> {
        match decode_seal(self.subscription.buffer.seal().load(Ordering::Acquire)) {
            SealWord::Positioned(position) => Some(position),
            SealWord::Active | SealWord::Sealed => None,
        }
    }

    /// Records the backend's submission up to `position`: the registered
    /// position, which bounds the publisher and the retention floor, moves
    /// there. Only a block boundary this reader returned is accepted (see
    /// [`SenderRead::boundary_at_or_below`]), so the registered position is
    /// always a valid restart; the registered position itself is a no-op.
    ///
    /// # Errors
    ///
    /// [`ReadError::Invariant`] for any other position; nothing moves.
    pub fn sent(&mut self, position: u64) -> Result<(), ReadError> {
        if position == self.subscription.cursor.acknowledged {
            return Ok(());
        }
        if !self.boundaries.contains(&position) {
            self.counters.bump(|c| &mut c.invariant, 1);
            return Err(ReadError::Invariant);
        }
        while self
            .boundaries
            .front()
            .is_some_and(|boundary| *boundary <= position)
        {
            let _ = self.boundaries.pop_front();
        }
        let cursor = &mut self.subscription.cursor;
        let cell = self
            .subscription
            .buffer
            .cell(cursor.cell)
            .map_err(|_| ReadError::Invariant)?;
        cursor.acknowledged = position;
        cell.position.store(position, Ordering::Release);
        Ok(())
    }

    /// Copies committed frames of this lane starting at `from` into `out`
    /// (S2 2.2), without crossing a term end or the seal. `from` must be
    /// the cursor ([`SenderRead::position`]); a copy moves the cursor to
    /// its `next`.
    ///
    /// # Errors
    ///
    /// See [`ReadError`]; the loan word is empty on every return.
    pub fn read_committed(
        &mut self,
        from: u64,
        origin: ReadOrigin,
        out: &mut [u8],
    ) -> Result<ReadOutcome, ReadError> {
        let ReadOrigin::Cursor = origin;
        if let Some(position) = self.faulted {
            self.counters.bump(|c| &mut c.corrupt, 1);
            return Err(ReadError::Faulted { position });
        }
        let result = self.read(from, out);
        match result {
            Ok(ReadOutcome::Copied { len, .. }) => {
                self.corrupt = None;
                self.counters.bump(|c| &mut c.reads, 1);
                match u64::try_from(len) {
                    Ok(len) => self.counters.bump(|c| &mut c.read_bytes, len),
                    Err(_) => self.counters.overflowed = true,
                }
            }
            Ok(ReadOutcome::Canonical { .. }) => {
                self.corrupt = None;
                self.counters.bump(|c| &mut c.reads, 1);
                self.counters.bump(|c| &mut c.canonical_records, 1);
                self.counters
                    .bump(|c| &mut c.read_bytes, u64::from(HEADER_LENGTH));
            }
            Ok(ReadOutcome::Pending) | Err(ReadError::TooSmall { .. }) => {}
            Err(ReadError::Unavailable { .. }) => self.counters.bump(|c| &mut c.unavailable, 1),
            Err(ReadError::Retry) => self.counters.bump(|c| &mut c.retry, 1),
            Err(ReadError::Invariant) => self.counters.bump(|c| &mut c.invariant, 1),
            Err(ReadError::Revoked) => {}
            Err(ReadError::CorruptTerm { .. }) => {
                self.counters.bump(|c| &mut c.corrupt, 1);
                // A count past `u32::MAX` faults like one past the limit.
                let failures = match self.corrupt {
                    Some((at, failures)) if at == from => failures.checked_add(1),
                    _ => Some(1),
                };
                self.corrupt = failures.map(|failures| (from, failures));
                let Some(failures) = failures.filter(|f| *f <= self.corrupt_retries) else {
                    self.faulted = Some(from);
                    return Err(ReadError::Faulted { position: from });
                };
                return Err(ReadError::CorruptTerm { failures });
            }
            Err(ReadError::Faulted { .. }) => self.counters.bump(|c| &mut c.corrupt, 1),
        }
        result
    }

    fn read(&mut self, from: u64, out: &mut [u8]) -> Result<ReadOutcome, ReadError> {
        let invariant = |_| ReadError::Invariant;
        // Split borrows: the buffer (and the cell taken from it) stays
        // borrowed across the copy, so the loan is released through the
        // very cell it was taken in.
        let Self {
            subscription,
            open: open_block,
            hook,
            boundaries,
            ..
        } = self;
        if from != subscription.cursor.position {
            return Err(ReadError::Invariant);
        }
        let buffer = &*subscription.buffer;
        // Step 1: the retention floor, before any loan.
        let floor = buffer.floor().load(Ordering::Acquire);
        if from < floor {
            return Err(ReadError::Unavailable { lowest: floor });
        }
        // Step 2: resolve the position (one generation in this phase).
        let (count, offset) = buffer.split(from).map_err(invariant)?;
        let head = match buffer.head() {
            Ok(Some(head)) => head,
            Ok(None) => return Err(ReadError::Retry),
            Err(_) => return Err(ReadError::Invariant),
        };
        if from > head {
            return Err(ReadError::Invariant);
        }
        if from == head {
            return Ok(ReadOutcome::Pending);
        }
        let slot = match buffer.lookup(count).map_err(invariant)? {
            Lookup::Slot(slot) => slot,
            Lookup::Missing => return Err(ReadError::Retry),
            Lookup::Gone => {
                return Err(ReadError::Unavailable {
                    lowest: buffer.floor().load(Ordering::Acquire),
                });
            }
        };
        // Step 3: the SPEC §4 acquisition on the exact term.
        let cell = buffer.cell(subscription.cursor.cell).map_err(invariant)?;
        let descriptor = buffer.descriptor(slot).map_err(invariant)?;
        #[cfg(test)]
        match *hook {
            Some(TestHook::FloorBeforeLoan(floor)) => {
                *hook = None;
                buffer.floor().store(floor, Ordering::Release);
            }
            Some(TestHook::DescriptorBeforeLoan(raw)) => {
                *hook = None;
                descriptor.store(raw, Ordering::Release);
            }
            _ => {}
        }
        let target = buffer.target(slot, count).map_err(invariant)?;
        match take_loan(&cell.loan, &cell.revoked, descriptor, target) {
            Ok(LoanOutcome::Granted) => {}
            Ok(LoanOutcome::Retry) => return Err(ReadError::Retry),
            Ok(LoanOutcome::Overrun) => {
                return Err(ReadError::Unavailable {
                    lowest: buffer.floor().load(Ordering::Acquire),
                });
            }
            Ok(LoanOutcome::Revoked) => return Err(ReadError::Revoked),
            // `take_loan` cleared the word.
            Err(_) => return Err(ReadError::Invariant),
        }
        // The floor again, after the loan and before any read.
        let floor = buffer.floor().load(Ordering::Acquire);
        if from < floor {
            release_loan(&cell.loan);
            return Err(ReadError::Unavailable { lowest: floor });
        }
        // Steps 4 and 5 under the loan; step 6 releases it, on every path,
        // through the cell it was taken in.
        let copied = Self::copy(
            buffer,
            &mut subscription.cursor,
            *open_block,
            hook,
            slot,
            count,
            offset,
            out,
        );
        release_loan(&cell.loan);
        let next = |end: u32| buffer.position(count, end);
        match copied {
            Ok(Copy::Frames { len, end, open }) => {
                let next = next(end);
                subscription.cursor.position = next;
                *open_block = open.map(|end| OpenBlock { count, end });
                if open.is_none() {
                    Self::remember(boundaries, next);
                }
                Ok(ReadOutcome::Copied { len, next })
            }
            Ok(Copy::Pending) => Ok(ReadOutcome::Pending),
            Ok(Copy::Canonical { record, end }) => {
                let next = next(end);
                subscription.cursor.position = next;
                *open_block = None;
                Self::remember(boundaries, next);
                Ok(ReadOutcome::Canonical { record, next })
            }
            Err(CopyError::Corrupt) => Err(ReadError::CorruptTerm { failures: 0 }),
            Err(CopyError::TooSmall(needed)) => Err(ReadError::TooSmall { needed }),
            Err(CopyError::Invariant) => Err(ReadError::Invariant),
        }
    }

    /// Steps 4 and 5: under the caller's loan of `count` in `slot`, copies
    /// whole committed frames from `start` into `out`.
    #[allow(clippy::too_many_arguments, reason = "the split borrows of one read")]
    fn copy(
        buffer: &LogBuffer<O::Terms>,
        cursor: &mut Cursor,
        open: Option<OpenBlock>,
        hook: &mut HookSlot,
        slot: u8,
        count: TermCount,
        start: u32,
        out: &mut [u8],
    ) -> Result<Copy, CopyError> {
        let _ = &hook;
        let term_length = buffer.term_length;
        let lane = buffer.config.lane;
        // A block resumed at an interior frame: its first word 0 was
        // observed with Acquire by an earlier call under a loan of this term.
        let mut open = open
            .filter(|block| block.count == count && block.end > start)
            .map(|block| block.end);
        let mut at = start;
        // Where the next frame goes in `out` (32-byte strides), and where
        // the last copied frame ends.
        let mut stride: usize = 0;
        let mut len: usize = 0;
        while at < term_length {
            let (block_end, mut begin) = match open {
                Some(end) => (end, false),
                None => {
                    let context = SubscriptionContext {
                        buffer,
                        cursor: &mut *cursor,
                    };
                    match context.validate_block(slot, at) {
                        Ok(Validated::Block(block)) => (block.end, true),
                        Ok(Validated::Pending) => break,
                        Ok(Validated::Pad) if len == 0 => {
                            let extent = term_length.checked_sub(at).ok_or(CopyError::Invariant)?;
                            return Self::canonical(
                                buffer,
                                CanonicalKind::Pad,
                                count,
                                at,
                                extent,
                                out,
                            );
                        }
                        Ok(Validated::Aborted { extent }) if len == 0 => {
                            return Self::canonical(
                                buffer,
                                CanonicalKind::Aborted,
                                count,
                                at,
                                extent,
                                out,
                            );
                        }
                        // A record ends a copy; it is the next read, alone.
                        Ok(Validated::Pad | Validated::Aborted { .. }) => break,
                        Ok(Validated::Skip { .. }) => return Err(CopyError::Invariant),
                        // Frames copied before it are sent; the next read
                        // meets the corruption at the cursor.
                        Err(SysError::CorruptTerm { .. }) if len > 0 => break,
                        Err(SysError::CorruptTerm { .. }) => return Err(CopyError::Corrupt),
                        Err(_) => return Err(CopyError::Invariant),
                    }
                }
            };
            while at < block_end {
                // The block stays open only once one of its frames was
                // copied: a stop before its first frame leaves the cursor
                // at its start, a block boundary.
                let open = (!begin).then_some(block_end);
                // SAFETY: loan held on this slot's term; `at` is a frame
                // start inside a block whose first word 0 was observed with
                // Acquire and whose frames were validated, in this call or,
                // for a resumed block, in an earlier call on the same term
                // incarnation (the loan's exact term proves it).
                let word = unsafe { buffer.regions.word0(slot, at) };
                let raw = load_interior(word);
                let frame = match check_frame(raw, at, block_end, begin, lane) {
                    Some(frame) => frame,
                    None if len > 0 => return Ok(Copy::Frames { len, end: at, open }),
                    None => return Err(CopyError::Corrupt),
                };
                let length = usize::try_from(frame.length).map_err(|_| CopyError::Invariant)?;
                let reserved = usize::try_from(frame.reserved).map_err(|_| CopyError::Invariant)?;
                let frame_end = stride.checked_add(length).ok_or(CopyError::Invariant)?;
                let padded = stride.checked_add(reserved).ok_or(CopyError::Invariant)?;
                let body_at = at.checked_add(8).ok_or(CopyError::Invariant)?;
                let Some(target) = out.get_mut(stride..frame_end) else {
                    if len == 0 {
                        return Err(CopyError::TooSmall(length));
                    }
                    return Ok(Copy::Frames { len, end: at, open });
                };
                let (head, body) = target.split_at_mut(8);
                head.copy_from_slice(&raw.to_le_bytes());
                // SAFETY: loan held; the frame's bytes after word 0 lie
                // inside the validated block (`check_frame`).
                unsafe { buffer.regions.read_bytes(slot, body_at, body) };
                #[cfg(test)]
                if let Some(TestHook::Word0BetweenLoads { offset, raw }) = *hook
                    && offset == at
                {
                    *hook = None;
                    word.store(raw.to_le(), Ordering::Relaxed);
                }
                // The second load: a changed word 0 means the copy may mix
                // two values; it is not sent. The fence keeps the copy's
                // plain reads before it.
                fence(Ordering::Acquire);
                if load_interior(word) != raw {
                    if len > 0 {
                        return Ok(Copy::Frames { len, end: at, open });
                    }
                    return Err(CopyError::Corrupt);
                }
                if let Some(padding) = out.get_mut(frame_end..padded.min(out.len())) {
                    padding.fill(0);
                }
                len = frame_end;
                stride = padded;
                at = frame.next;
                begin = false;
            }
            open = None;
        }
        if len == 0 {
            return Ok(Copy::Pending);
        }
        // The loop ends at a block boundary or the term end.
        Ok(Copy::Frames {
            len,
            end: at,
            open: None,
        })
    }

    /// Step 5: the canonical record of the PAD or ABORTED block at `at`.
    fn canonical(
        buffer: &LogBuffer<O::Terms>,
        record: CanonicalKind,
        count: TermCount,
        at: u32,
        extent: u32,
        out: &mut [u8],
    ) -> Result<Copy, CopyError> {
        let out = out
            .get_mut(..CANONICAL_LENGTH)
            .ok_or(CopyError::TooSmall(CANONICAL_LENGTH))?;
        let frame_type = match record {
            CanonicalKind::Pad => FrameType::Pad,
            CanonicalKind::Aborted => FrameType::Aborted,
        };
        let flags = Flags::new(false, false, false, false, buffer.config.lane);
        let length = i32::try_from(HEADER_LENGTH).map_err(|_| CopyError::Invariant)?;
        let word0 = Word0::new(length, flags, frame_type).pack();
        let term_offset = i32::try_from(at).map_err(|_| CopyError::Invariant)?;
        let end = at.checked_add(extent).ok_or(CopyError::Invariant)?;
        let term_id = buffer.initial_term_id.advanced_by(count);
        let fields: [(usize, &[u8]); 6] = [
            (0, &word0.to_le_bytes()),
            (8, &term_offset.to_le_bytes()),
            (12, &buffer.config.session_id.to_le_bytes()),
            (16, &buffer.config.stream_id.to_le_bytes()),
            (20, &term_id.get().to_le_bytes()),
            (24, &i64::from(extent).to_le_bytes()),
        ];
        for (offset, bytes) in fields {
            out.get_mut(offset..)
                .and_then(|rest| rest.get_mut(..bytes.len()))
                .ok_or(CopyError::Invariant)?
                .copy_from_slice(bytes);
        }
        Ok(Copy::Canonical { record, end })
    }
}

/// A frame whose word 0 passed [`check_frame`].
struct Frame {
    /// `frame_length`.
    length: u32,
    /// Its aligned extent.
    reserved: u32,
    /// The next frame's offset.
    next: u32,
}

/// Validates the DATA word 0 `raw` of the frame at `at` inside the block
/// ending at `block_end`: committed DATA of `lane`, BEGIN only at the block
/// start (`begin`), at least its header, aligned inside the block, END only
/// on the last frame. `None` for any failure.
fn check_frame(
    raw: u64,
    at: u32,
    block_end: u32,
    begin: bool,
    lane: crate::frame::Lane,
) -> Option<Frame> {
    let word = Word0::unpack(raw).ok()?;
    let flags = word.flags();
    if word.frame_type_code() != FrameType::Data.code()
        || word.version() != crate::frame::PROTOCOL_VERSION
        || flags.begin() != begin
        || flags.lane() != lane
    {
        return None;
    }
    let length = u32::try_from(word.frame_length()).ok()?;
    // A log frame carries at least one payload byte: a header-only DATA
    // frame would leave as a heartbeat.
    length
        .checked_sub(flags.header_length())
        .filter(|payload| *payload > 0)?;
    let reserved = align_frame(length).ok()?;
    let next = at.checked_add(reserved).filter(|next| *next <= block_end)?;
    if flags.end() != (next == block_end) {
        return None;
    }
    Some(Frame {
        length,
        reserved,
        next,
    })
}
