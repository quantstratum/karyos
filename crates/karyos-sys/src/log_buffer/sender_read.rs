// SPDX-License-Identifier: Apache-2.0

//! The network sender's read capability (`quantstratum-docs:
//! karyos/design/network-sessions-sender.md` S2; driver network agents
//! phase 5a).
//!
//! [`SenderRead`] owns one subscriber cell of one lane's log buffer: a SPEC
//! §4 participant with its own loan word and revoked flag. For the network
//! sender it is a required participant on every channel (SPEC §4: the
//! sender's position bounds the publisher; on an unreliable channel it is
//! the sent position), admitted with its `L_send` slot credit reserved
//! against `S - C` (S2 2.1, `Conductor::subscribe_as` with `reserve`). An
//! Archive recording's reader ([`SenderRead::for_recording`]) is that, or
//! an optional participant the publisher may lap, which rejoins at the
//! head ([`SenderRead::rejoin_at_head`]). Each
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
//! - **NAK reads** (S2 2.3; ACS 15762, 15763). [`SenderRead::read_nak`]
//!   copies from an untrusted position below the NAK bound, never moving
//!   the cursor, the open block, the registered position or the boundary
//!   ring, and never feeding C-9. It proves the position a frame boundary
//!   by walking word 0 values forward, frame by frame, from a checkpoint:
//!   as the cursor path copies, every frame it copies records, for each
//!   multiple of `nak_checkpoint_stride` it passes in that term (or starts
//!   on), the first frame start at or after it, with its block's end and
//!   whether it starts the block. Each term slot's array is tagged with its
//!   term count, cleared when the slot's term changes, and read only for
//!   that count; a missing or other tag falls back to an earlier entry or
//!   the term start, itself a boundary. The walk passes the entry's block
//!   by its recorded end, or walks its fragments when the position lies
//!   inside it. A block entered past the entry takes its end from the
//!   cursor's open block or the next stride's entry when the position
//!   lies inside it, and from its END otherwise, so every load is of a
//!   frame start in the position's stride or below the next stride's
//!   first frame start: from the entry of the position's own stride a
//!   scan makes at most `stride / 32 + 1` word 0 loads, each charged
//!   against the caller's budget before it is made. It never reads a
//!   payload word, so a forged header inside a payload is never landed on.
//!   The copy that follows validates the block it starts in as the cursor
//!   path does; its loads are the read's, not the scan's.
//!
//! Limits of this phase: reads of a draining generation (2.4) and the
//! retention floor at `sent - retransmit_window` come later; until then
//! the registered position bounds the floor. A reader covers one lane; the
//! incarnation's lanes are the sender agent's.
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
//!
//! A NAK read trusts a recorded frame start, block end or open block only
//! under the term count it was recorded for. Checkpoint arrays are tagged
//! with their count, cleared when the tag changes and read only through
//! the tag check; the cursor's open block is used only when it and the
//! cursor lie in the NAK's term count. Each such value was recorded by the
//! cursor path from a block it validated in that term incarnation, and the
//! loan on the exact term keeps that incarnation, so the frames it names
//! are the ones recorded: a walk from them never lands inside a payload.
//! The copy that follows checks every frame against the block end it is
//! given.

use core::sync::atomic::{Ordering, fence};
use std::collections::VecDeque;

use super::{
    BufferOwner, Cursor, LogBuffer, Lookup, RetentionHold, Role, SealWord, Subscription,
    SubscriptionContext, Validated, decode_seal,
};
use crate::error::SysError;
use crate::frame::{Flags, FrameType, HEADER_LENGTH, Word0};
use crate::loan::{LoanOutcome, release_loan, take_loan};
use crate::participant;
use crate::publication::{load_interior, observe_block};
use crate::sizing::align_frame;
use crate::term::TermCount;
use crate::term_bytes::sealed::Access as _;

/// The default `corrupt_retries` (C-9).
pub const DEFAULT_CORRUPT_RETRIES: u32 = 3;

/// Bytes of a canonical PAD or ABORTED record.
const CANONICAL_LENGTH: usize = HEADER_LENGTH as usize;

/// The default `nak_checkpoint_stride` (C-8): at most the term length.
pub const DEFAULT_NAK_CHECKPOINT_STRIDE: u32 = 64 * 1024;

/// The least `nak_checkpoint_stride` (C-8).
pub const MIN_NAK_CHECKPOINT_STRIDE: u32 = 4 * 1024;

/// A checkpoint entry: a frame's term offset, its block's end (0 for a PAD
/// or ABORTED record, whose first word 0 gives its extent) and whether the
/// frame starts its block.
type Checkpoint = (u32, u32, bool);

/// One term slot's checkpoints and the term count they belong to.
type CheckpointArray = (Option<TermCount>, Vec<Checkpoint>);

/// A checkpoint entry with nothing recorded.
const NO_CHECKPOINT: Checkpoint = (u32::MAX, 0, false);

/// A NAK read's bounds (S2 2.3): the lane's NAK bound, read once by the
/// caller (`sent_position`, or `sent_high` with redundant paths), and the
/// word 0 loads the scan may spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NakRead {
    /// Positions at or above it are `BadRequest`.
    pub bound: u64,
    /// Word 0 loads the scan may spend.
    pub loads: u32,
}

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
    /// A NAK position that is not a frame boundary, is at or above the NAK
    /// bound, lies past the head, or overflows: a peer error, counted,
    /// never an `Invariant`.
    BadRequest,
    /// A NAK scan did not fit its load budget: dropped and counted, never
    /// answered; the receiver repeats it.
    Budget,
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
    /// NAK reads that copied frames or a canonical record.
    pub nak_reads: u64,
    /// NAK reads refused as `BadRequest`.
    pub nak_bad_request: u64,
    /// NAK reads dropped for their load budget.
    pub nak_budget: u64,
    /// NAK reads that met a corrupt word 0 (never C-9).
    pub nak_corrupt: u64,
    /// Restart moves that kept no boundary between the hold and the
    /// receivers' consumption and rose past that consumption to the
    /// oldest boundary at or above the hold ([`SenderRead::restart_at`]):
    /// a reset then resends less at once, and the rest stays repairable by
    /// NAK above the hold.
    pub restart_raised: u64,
    /// Word 0 loads spent by NAK scans.
    pub nak_loads: u64,
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

/// The NAK checkpoints of one lane (S2 2.3, C-8): per term slot, an array
/// tagged with its term count whose entry `i` is the first frame start at
/// or after `i * stride` in that term, with the end of its block and
/// whether it starts the block, recorded only by the cursor path from
/// frames it copied.
#[derive(Debug)]
struct Checkpoints {
    stride: u32,
    arrays: Vec<CheckpointArray>,
    /// The last frame start the cursor path recorded.
    last: u64,
}

impl Checkpoints {
    fn new(term_length: u32, slots: u8, stride: u32, last: u64) -> Self {
        let per_term = term_length
            .checked_div(stride)
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0);
        let arrays = (0..slots)
            .map(|_| (None, vec![NO_CHECKPOINT; per_term]))
            .collect();
        Self {
            stride,
            arrays,
            last,
        }
    }

    fn index(&self, count: TermCount) -> Option<usize> {
        let slots = u32::try_from(self.arrays.len()).ok()?;
        usize::try_from(count.get().checked_rem(slots)?).ok()
    }

    /// The array of `count`, if its tag is `count`.
    fn array(&self, count: TermCount) -> Option<&[Checkpoint]> {
        let (tag, entries) = self.arrays.get(self.index(count)?)?;
        (*tag == Some(count)).then_some(entries.as_slice())
    }

    /// Records `frame`, the start of a frame the cursor path copied after
    /// `self.last` (`block_end` its block's end, 0 for a PAD or ABORTED
    /// record; `begin` whether it starts the block): every stride multiple
    /// `m` of its term with `last < m <= frame`, or `m == frame`, gets it. Arithmetic that
    /// cannot be done records nothing (a missing entry only costs loads).
    fn record(&mut self, term_length: u32, frame: u64, block_end: u32, begin: bool) {
        let last = core::mem::replace(&mut self.last, frame);
        let term = u64::from(term_length);
        let (Some(index), Some(offset)) = (frame.checked_div(term), frame.checked_rem(term)) else {
            return;
        };
        let Some(count) = u32::try_from(index)
            .ok()
            .and_then(|count| TermCount::try_new(count).ok())
        else {
            return;
        };
        let Some(base) = index.checked_mul(term) else {
            return;
        };
        let stride = u64::from(self.stride);
        // The first stride past the previous frame: in this term, the one
        // after it; from an earlier term, this term's first.
        let first = match last.checked_sub(base) {
            Some(within) => within.checked_div(stride).and_then(|i| i.checked_add(1)),
            None => Some(0),
        };
        let (Some(first), Some(end)) = (first, offset.checked_div(stride)) else {
            return;
        };
        // A frame starting on a multiple is that multiple's entry, even
        // when it is where the cursor started (the term start).
        let first = if offset.is_multiple_of(stride) {
            first.min(end)
        } else {
            first
        };
        let Ok(value) = u32::try_from(offset) else {
            return;
        };
        let Some(slot) = self.index(count) else {
            return;
        };
        let Some((tag, entries)) = self.arrays.get_mut(slot) else {
            return;
        };
        if *tag != Some(count) {
            *tag = Some(count);
            entries.fill(NO_CHECKPOINT);
        }
        for i in first..=end {
            if let Some(entry) = usize::try_from(i).ok().and_then(|i| entries.get_mut(i)) {
                *entry = (value, block_end, begin);
            }
        }
    }
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
    /// The block-boundary `next` values of reads above the restart
    /// position, oldest first, at most `BOUNDARIES` (allocated at
    /// construction), thinned when full: the only positions
    /// [`SenderRead::sent`] and [`SenderRead::restart_at`] accept, so the
    /// registered and the restart positions are always block starts that
    /// [`SenderRead::rewind`] can restart at.
    boundaries: VecDeque<u64>,
    /// Where [`SenderRead::rewind`] reads again: the registered position
    /// without a hold; with one, a block start at or between the hold and
    /// the registered position, from the receivers' consumption
    /// ([`SenderRead::restart_at`]), so a reset resends at once what they
    /// had not consumed (quantstratum-docs:
    /// karyos/design/retention-floor-optional-receivers.md). Only grows.
    restart: u64,
    /// The NAK checkpoints (S2 2.3).
    checkpoints: Checkpoints,
    /// The last cursor read found the position below the floor: an
    /// optional reader was lapped, and may rejoin at the head.
    lapped: bool,
    /// A reliable lane's retention hold ([`SenderRead::with_hold`]), freed
    /// on drop.
    hold: Option<RetentionHold>,
}

impl<O: BufferOwner> Drop for SenderRead<O> {
    fn drop(&mut self) {
        if let Some(hold) = self.hold.take()
            && let Ok(cell) = self.subscription.buffer.cell(hold.cell)
        {
            // As a subscriber's detach: the registration is cleared before
            // the cell is freed, and FREE is this holder's last access.
            participant::leave(&cell.state, &cell.registration);
        }
    }
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
    /// The floor becomes this value after a NAK read's loan, before its
    /// second floor check.
    FloorAfterLoan(u64),
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
    pub fn new(subscription: Subscription<O>, corrupt_retries: u32) -> Result<Self, SysError> {
        let stride = DEFAULT_NAK_CHECKPOINT_STRIDE.min(subscription.buffer.term_length);
        Self::with_nak_stride(subscription, corrupt_retries, stride)
    }

    /// [`SenderRead::new`] with NAK checkpoints every `nak_checkpoint_stride`
    /// bytes of a term (C-8), allocated here.
    ///
    /// # Errors
    ///
    /// As [`SenderRead::new`], and [`SysError::InvalidPublicationMode`] for a
    /// stride that is not a power of two from
    /// [`MIN_NAK_CHECKPOINT_STRIDE`] to the term length.
    pub fn with_nak_stride(
        subscription: Subscription<O>,
        corrupt_retries: u32,
        nak_checkpoint_stride: u32,
    ) -> Result<Self, SysError> {
        Self::build(subscription, corrupt_retries, nak_checkpoint_stride, false)
    }

    /// The read capability of an Archive recording (quantstratum-docs:
    /// karyos/design/archive-gap-analysis.md, A4): over a cell admitted as
    /// [`Role::Required`] with its reservation (a `required` recording,
    /// which bounds the publisher), or as [`Role::Optional`] (an `async`
    /// one, which the publisher may lap; see
    /// [`SenderRead::rejoin_at_head`]). One read holds one loan, released
    /// before it returns, so an optional reader's single admission credit
    /// covers it.
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidPublicationMode`] for an image, or for any other
    /// cell.
    pub fn for_recording(
        subscription: Subscription<O>,
        corrupt_retries: u32,
    ) -> Result<Self, SysError> {
        let stride = DEFAULT_NAK_CHECKPOINT_STRIDE.min(subscription.buffer.term_length);
        Self::build(subscription, corrupt_retries, stride, true)
    }

    fn build(
        mut subscription: Subscription<O>,
        corrupt_retries: u32,
        nak_checkpoint_stride: u32,
        recording: bool,
    ) -> Result<Self, SysError> {
        let term_length = subscription.buffer.term_length;
        if !nak_checkpoint_stride.is_power_of_two()
            || nak_checkpoint_stride < MIN_NAK_CHECKPOINT_STRIDE
            || nak_checkpoint_stride > term_length
        {
            return Err(SysError::InvalidPublicationMode {
                reason: "nak_checkpoint_stride is a power of two from 4 KiB to the term length",
            });
        }
        if subscription.buffer.image() {
            return Err(SysError::InvalidPublicationMode {
                reason: "a sender read of an image",
            });
        }
        let reserved = subscription
            .buffer
            .cell(subscription.cursor.cell)
            .is_ok_and(|cell| {
                participant::is_required_reserved(cell.state.load(Ordering::Acquire))
            });
        let admitted = match subscription.cursor.role {
            Role::Required => reserved,
            Role::Optional => recording,
            Role::Observer | Role::Walker => false,
        };
        if !admitted {
            return Err(SysError::InvalidPublicationMode {
                reason: "a sender read is a required participant with its L_send reservation \
                         (or, for a recording, an optional one)",
            });
        }
        if subscription.cursor.pending.take().is_some() {
            subscription.cursor.position = subscription.cursor.acknowledged;
        }
        let checkpoints = Checkpoints::new(
            term_length,
            subscription.buffer.slots,
            nak_checkpoint_stride,
            subscription.cursor.position,
        );
        Ok(Self {
            open: None,
            corrupt: None,
            corrupt_retries,
            faulted: None,
            counters: SenderReadCounters::default(),
            hook: HookSlot::default(),
            boundaries: VecDeque::with_capacity(BOUNDARIES),
            restart: subscription.cursor.acknowledged,
            checkpoints,
            lapped: false,
            hold: None,
            subscription,
        })
    }

    /// Takes `hold`, a retention hold the same buffer's conductor admitted
    /// at or below this reader's registered position
    /// ([`super::Conductor::admit_hold`]), for a reliable lane: from then on
    /// [`SenderRead::hold_at`] keeps the floor there, and dropping the
    /// reader frees it. So `hold <= restart <= registered` holds from the
    /// start, and the hold only grows.
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidPublicationMode`] for a reader that holds one
    /// already, a cell that is not that hold (another state or occupant),
    /// or a hold above the registered position; the hold is handed back,
    /// in place, for its conductor's [`super::Conductor::release_hold`].
    pub fn with_hold(&mut self, hold: RetentionHold) -> Result<(), (SysError, RetentionHold)> {
        let registered = self.subscription.cursor.acknowledged;
        let held = self.subscription.buffer.cell(hold.cell).is_ok_and(|cell| {
            cell.state.load(Ordering::Acquire) == participant::CELL_SENDER_HOLD
                && cell.registration.load(Ordering::Acquire) == hold.occupant
                && cell.position.load(Ordering::Relaxed) <= registered
        });
        if self.hold.is_some() || !held {
            return Err((
                SysError::InvalidPublicationMode {
                    reason: "a retention hold of this buffer's conductor at or below the \
                             registered position, one per sender reader",
                },
                hold,
            ));
        }
        self.hold = Some(hold);
        Ok(())
    }

    /// Raises the retention hold to `position`, the lane's `sent -
    /// retransmit_window` lowered by its required receivers: never lowers
    /// it, so the cell's position only grows, as `reader_minima` requires
    /// (docs#336, condition 1). Returns the hold, or `None` with none.
    ///
    /// The hold never passes the registered position, and the restart
    /// position rises with it: `hold <= restart <= registered`, so a rewind
    /// reads only what the floor retains.
    pub fn hold_at(&mut self, position: u64) -> Option<u64> {
        let hold = self.hold.as_ref()?;
        let cell = self.subscription.buffer.cell(hold.cell).ok()?;
        let position = position.min(self.subscription.cursor.acknowledged);
        // The only writer: the load reads its own last store.
        let held = cell.position.load(Ordering::Relaxed);
        let held = if position > held {
            cell.position.store(position, Ordering::Release);
            position
        } else {
            held
        };
        if self.restart < held {
            self.raise_restart(held);
        }
        self.debug_assert_ordered(held);
        Some(held)
    }

    /// The retention hold's position, `None` without one.
    #[must_use]
    pub fn hold_position(&self) -> Option<u64> {
        let hold = self.hold.as_ref()?;
        let cell = self.subscription.buffer.cell(hold.cell).ok()?;
        Some(cell.position.load(Ordering::Relaxed))
    }

    /// The restart position ([`SenderRead::rewind`] reads again from it).
    #[must_use]
    pub fn restart_position(&self) -> u64 {
        self.restart
    }

    /// Moves the restart position toward `consumption`, the least position
    /// every receiver consumed, optional ones included (a hint, never a
    /// bound): to the highest kept boundary at or below it, within the
    /// hold and the registered position. With no boundary there it stays,
    /// or, below the hold, rises to the oldest boundary at or above the
    /// hold (counted `restart_raised`). It never lowers, and without a hold
    /// it is the registered position. Returns it.
    pub fn restart_at(&mut self, consumption: u64) -> u64 {
        let Some(hold) = self.hold_position() else {
            return self.restart;
        };
        let registered = self.subscription.cursor.acknowledged;
        let target = consumption.max(hold).min(registered);
        if target <= self.restart {
            return self.restart;
        }
        let restart = self.restart;
        let chosen = if target == registered {
            Some(registered)
        } else {
            self.boundaries
                .iter()
                .rev()
                .copied()
                .find(|boundary| *boundary > restart && *boundary <= target)
        };
        match chosen {
            Some(boundary) if boundary >= hold => self.set_restart(boundary),
            _ if restart < hold => self.raise_restart(hold),
            _ => {}
        }
        self.debug_assert_ordered(hold);
        self.restart
    }

    /// Raises the restart position to the oldest kept boundary at or above
    /// `at_least`, or to the registered position with none.
    fn raise_restart(&mut self, at_least: u64) {
        let registered = self.subscription.cursor.acknowledged;
        let boundary = self
            .boundaries
            .iter()
            .copied()
            .find(|boundary| *boundary >= at_least && *boundary <= registered)
            .unwrap_or(registered);
        if boundary > at_least {
            self.counters.bump(|c| &mut c.restart_raised, 1);
        }
        self.set_restart(boundary);
    }

    /// Moves the restart position up to `position`, a block start, and
    /// forgets the boundaries at or below it.
    fn set_restart(&mut self, position: u64) {
        if position <= self.restart {
            return;
        }
        self.restart = position;
        while self
            .boundaries
            .front()
            .is_some_and(|boundary| *boundary <= position)
        {
            let _ = self.boundaries.pop_front();
        }
    }

    /// `hold <= restart <= registered` (docs#336, (a')).
    fn debug_assert_ordered(&self, hold: u64) {
        debug_assert!(
            hold <= self.restart && self.restart <= self.subscription.cursor.acknowledged,
            "hold {hold}, restart {}, registered {}",
            self.restart,
            self.subscription.cursor.acknowledged
        );
    }

    /// Rejoins an optional reader the publisher lapped at the reserved
    /// head, as a lapped optional subscription does (`rejoin_at_head`): its
    /// last cursor read returned [`ReadError::Unavailable`]. The retention
    /// floor of an optional-only lane need not be a frame boundary; the
    /// reserved head always is a block boundary. The cursor and the
    /// registered position move there, the boundary ring and any open block
    /// are dropped, and the cell's position is stored with `Release`, as
    /// [`SenderRead::sent`] stores it. Returns the head: everything from the
    /// old cursor to it is lost to this reader.
    ///
    /// The floor is read before the head (the conductor publishes a floor
    /// only from an earlier head snapshot), so the head is at or above it.
    /// The floor may pass the head before the next read, once the publisher
    /// writes on: that read checks it, before its loan and after, and
    /// returns `Unavailable` again, so no byte of a reclaimed term is ever
    /// read.
    ///
    /// # Errors
    ///
    /// [`ReadError::Faulted`] once the reader is faulted;
    /// [`ReadError::Revoked`] when its cell was revoked;
    /// [`ReadError::Retry`] when no consistent head can be read now;
    /// [`ReadError::Invariant`] for a required reader, or one whose last
    /// read was not `Unavailable`. Nothing moves on an error.
    pub fn rejoin_at_head(&mut self) -> Result<u64, ReadError> {
        if let Some(position) = self.faulted {
            return Err(ReadError::Faulted { position });
        }
        if self.subscription.cursor.role != Role::Optional || !self.lapped {
            self.counters.bump(|c| &mut c.invariant, 1);
            return Err(ReadError::Invariant);
        }
        let Ok(cell) = self.subscription.buffer.cell(self.subscription.cursor.cell) else {
            self.counters.bump(|c| &mut c.invariant, 1);
            return Err(ReadError::Invariant);
        };
        if cell.revoked.load(Ordering::SeqCst) != 0 {
            return Err(ReadError::Revoked);
        }
        let buffer = &*self.subscription.buffer;
        let floor = buffer.floor().load(Ordering::Acquire);
        let head = match buffer.head() {
            Ok(Some(head)) if head >= floor => head,
            Ok(_) => return Err(ReadError::Retry),
            Err(_) => return Err(ReadError::Invariant),
        };
        let cursor = &mut self.subscription.cursor;
        let resume = head.max(cursor.position);
        cursor.position = resume;
        cursor.acknowledged = resume;
        self.restart = resume;
        self.open = None;
        self.boundaries.clear();
        self.checkpoints.last = resume;
        self.lapped = false;
        cell.position.store(resume, Ordering::Release);
        Ok(resume)
    }

    /// Injects `hook` into the next read (tests).
    #[cfg(test)]
    pub(crate) fn inject(&mut self, hook: TestHook) {
        self.hook = Some(hook);
    }

    /// Plants checkpoint `index` of the array of `count`'s slot, tagged
    /// `tag` (tests: a stale or foreign entry).
    #[cfg(test)]
    pub(crate) fn plant_checkpoint(
        &mut self,
        count: TermCount,
        tag: TermCount,
        index: usize,
        entry: Checkpoint,
    ) {
        if let Some(slot) = self.checkpoints.index(count)
            && let Some((held, entries)) = self.checkpoints.arrays.get_mut(slot)
        {
            *held = Some(tag);
            if let Some(planted) = entries.get_mut(index) {
                *planted = entry;
            }
        }
    }

    /// The buffer it reads.
    #[must_use]
    pub fn subscription(&self) -> &Subscription<O> {
        &self.subscription
    }

    /// Makes the reader's cell count for the publication's connection
    /// while a receiver's status messages are live (`live`), or not
    /// (SPEC.md §4): `participant::set_sender_counts` on its own cell. The
    /// bound and the credit are the same either way. Returns whether the
    /// cell moved: `false` when it already was so, or when it was revoked
    /// or left.
    pub fn set_receivers_live(&self, live: bool) -> bool {
        self.subscription
            .buffer
            .cell(self.subscription.cursor.cell)
            .is_ok_and(|cell| participant::set_sender_counts(&cell.state, live))
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

    /// The retention floor (Acquire): the lowest position still retained,
    /// as the conductor last published it. A read below it is refused as
    /// unavailable; it only rises, so a later read may refuse a position
    /// this one admitted. NAK admission checks requests against it before
    /// the read checks it again.
    #[must_use]
    pub fn floor(&self) -> u64 {
        let buffer: &LogBuffer<O::Terms> = self.subscription.buffer();
        buffer.floor().load(Ordering::Acquire)
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

    /// Moves the cursor back to the restart position, dropping what was
    /// read past it and not submitted (an endpoint reset returned it): the
    /// next read starts there again. Without a hold that is the registered
    /// position; with one, it is at or above the hold, so a reset resends
    /// at once what the receivers had not consumed. It is a block start by
    /// construction (the join, or a boundary [`SenderRead::sent`] or
    /// [`SenderRead::restart_at`] accepted). A required reader's is never
    /// below the floor, so nothing it rereads is reclaimed; an optional
    /// recording reader's can fall below it, and the read's floor checks
    /// then return
    /// [`ReadError::Unavailable`]. The C-9 count is kept: a rewind onto a
    /// corrupt block does not restore its retries.
    ///
    /// # Errors
    ///
    /// [`ReadError::Faulted`] once the reader is faulted; nothing moves.
    pub fn rewind(&mut self) -> Result<(), ReadError> {
        if let Some(position) = self.faulted {
            return Err(ReadError::Faulted { position });
        }
        let cursor = &mut self.subscription.cursor;
        cursor.position = self.restart;
        self.open = None;
        self.boundaries.clear();
        // The rereads record the same boundaries again, from here.
        self.checkpoints.last = self.restart;
        Ok(())
    }

    /// Remembers `next`, a block boundary a read just returned. A full
    /// ring is thinned in place to every second entry, the newest kept, so
    /// it still spans everything read above the registered position: a
    /// lane read far ahead (many small frames within one window) keeps a
    /// registrable boundary within a bounded distance below any position,
    /// never none.
    fn remember(boundaries: &mut VecDeque<u64>, next: u64) {
        if boundaries.len() >= BOUNDARIES {
            // Every second entry, from the second: the newest stays (the
            // ring is full, so of even length).
            let mut keep = false;
            boundaries.retain(|_| {
                keep = !keep;
                !keep
            });
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

    /// The buffer this reader reads.
    #[must_use]
    pub fn buffer(&self) -> &LogBuffer<O::Terms> {
        self.subscription.buffer()
    }

    /// Whether the publication is sealed for a mapping-generation cutover:
    /// the stream continues in a successor mapping (Acquire). `false`
    /// while active and for a final seal.
    #[must_use]
    pub fn sealed_with_successor(&self) -> bool {
        self.subscription.buffer.sealed_with_successor()
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
        // Kept boundaries can lie below it (above the restart position):
        // the registered position never moves back.
        if position < self.subscription.cursor.acknowledged || !self.boundaries.contains(&position)
        {
            self.counters.bump(|c| &mut c.invariant, 1);
            return Err(ReadError::Invariant);
        }
        // The cell first: a failed lookup leaves the ring and the cursor
        // as they were.
        let Ok(cell) = self.subscription.buffer.cell(self.subscription.cursor.cell) else {
            self.counters.bump(|c| &mut c.invariant, 1);
            return Err(ReadError::Invariant);
        };
        self.subscription.cursor.acknowledged = position;
        cell.position.store(position, Ordering::Release);
        // Without a hold the restart is the registered position; with one
        // the boundaries above the restart stay for `restart_at`.
        if self.hold.is_none() {
            self.set_restart(position);
        }
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
        self.lapped = matches!(result, Err(ReadError::Unavailable { .. }));
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
            // NAK reads only.
            Err(ReadError::BadRequest | ReadError::Budget) => {}
        }
        result
    }

    /// Copies committed frames of this lane starting at `from`, a NAK's
    /// untrusted position, into `out` (S2 2.3), without crossing a term
    /// end or the seal. Nothing of the cursor path moves: not the cursor,
    /// the open block, the registered position, the boundary ring or the
    /// C-9 count. `from` must be a frame boundary below `nak.bound`, proved
    /// by a word 0 walk from a checkpoint within `nak.loads`. Returns the
    /// result and the loads spent.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadRequest`], [`ReadError::Budget`], `Unavailable`,
    /// `Retry`, `Revoked`, `CorruptTerm` (counted as a NAK corruption,
    /// never C-9), `TooSmall` or `Faulted`; the loan word is empty on every
    /// return.
    pub fn read_nak(
        &mut self,
        from: u64,
        nak: NakRead,
        out: &mut [u8],
    ) -> (Result<ReadOutcome, ReadError>, u32) {
        let (result, loads) = match self.faulted {
            Some(position) => (Err(ReadError::Faulted { position }), 0),
            None => self.nak(from, nak, out),
        };
        self.counters.bump(|c| &mut c.nak_loads, u64::from(loads));
        match result {
            Ok(ReadOutcome::Copied { .. } | ReadOutcome::Canonical { .. }) => {
                self.counters.bump(|c| &mut c.nak_reads, 1);
            }
            Err(ReadError::BadRequest) => self.counters.bump(|c| &mut c.nak_bad_request, 1),
            Err(ReadError::Budget) => self.counters.bump(|c| &mut c.nak_budget, 1),
            Err(ReadError::CorruptTerm { .. }) => self.counters.bump(|c| &mut c.nak_corrupt, 1),
            Err(ReadError::Unavailable { .. }) => self.counters.bump(|c| &mut c.unavailable, 1),
            Err(ReadError::Retry) => self.counters.bump(|c| &mut c.retry, 1),
            Err(ReadError::Invariant) => self.counters.bump(|c| &mut c.invariant, 1),
            Ok(ReadOutcome::Pending)
            | Err(ReadError::TooSmall { .. } | ReadError::Revoked | ReadError::Faulted { .. }) => {}
        }
        (result, loads)
    }

    fn nak(
        &mut self,
        from: u64,
        nak: NakRead,
        out: &mut [u8],
    ) -> (Result<ReadOutcome, ReadError>, u32) {
        let Self {
            subscription,
            open,
            hook,
            checkpoints,
            ..
        } = self;
        let buffer = &*subscription.buffer;
        if from >= nak.bound || !from.is_multiple_of(u64::from(crate::frame::FRAME_ALIGNMENT)) {
            return (Err(ReadError::BadRequest), 0);
        }
        // The retention floor, before any loan.
        let floor = buffer.floor().load(Ordering::Acquire);
        if from < floor {
            return (Err(ReadError::Unavailable { lowest: floor }), 0);
        }
        let Ok((count, offset)) = buffer.split(from) else {
            return (Err(ReadError::BadRequest), 0);
        };
        match buffer.head() {
            Ok(Some(head)) if from < head => {}
            Ok(Some(_)) => return (Err(ReadError::BadRequest), 0),
            Ok(None) => return (Err(ReadError::Retry), 0),
            Err(_) => return (Err(ReadError::Invariant), 0),
        }
        let slot = match buffer.lookup(count) {
            Ok(Lookup::Slot(slot)) => slot,
            Ok(Lookup::Missing) => return (Err(ReadError::Retry), 0),
            Ok(Lookup::Gone) => {
                let lowest = buffer.floor().load(Ordering::Acquire);
                return (Err(ReadError::Unavailable { lowest }), 0);
            }
            Err(_) => return (Err(ReadError::Invariant), 0),
        };
        // The scan's start: the last recorded checkpoint at or below
        // `offset` of this exact term count, or the term start. Only the
        // array tagged with `count` is read (module documentation, Safety).
        let entries = checkpoints.array(count).unwrap_or(&[]);
        let start = match Self::scan_start(entries, checkpoints.stride, offset) {
            Ok(start) => start,
            Err(error) => return (Err(error), 0),
        };
        // The cursor's open block, only when it and the cursor lie in this
        // term count.
        let at_cursor = open.filter(|block| block.count == count).and_then(|block| {
            let (cursor_count, at) = buffer.split(subscription.cursor.position).ok()?;
            (cursor_count == count).then_some((at, block.end))
        });
        let ends = Ends {
            entries,
            stride: checkpoints.stride,
            at_cursor,
        };
        // The SPEC §4 acquisition on the exact term, as for the cursor.
        let (cell, descriptor, target) = match (
            buffer.cell(subscription.cursor.cell),
            buffer.descriptor(slot),
            buffer.target(slot, count),
        ) {
            (Ok(cell), Ok(descriptor), Ok(target)) => (cell, descriptor, target),
            _ => return (Err(ReadError::Invariant), 0),
        };
        #[cfg(test)]
        if let Some(TestHook::FloorBeforeLoan(floor)) = *hook {
            *hook = None;
            buffer.floor().store(floor, Ordering::Release);
        }
        match take_loan(&cell.loan, &cell.revoked, descriptor, target) {
            Ok(LoanOutcome::Granted) => {}
            Ok(LoanOutcome::Retry) => return (Err(ReadError::Retry), 0),
            Ok(LoanOutcome::Overrun) => {
                let lowest = buffer.floor().load(Ordering::Acquire);
                return (Err(ReadError::Unavailable { lowest }), 0);
            }
            Ok(LoanOutcome::Revoked) => return (Err(ReadError::Revoked), 0),
            Err(_) => return (Err(ReadError::Invariant), 0),
        }
        #[cfg(test)]
        if let Some(TestHook::FloorAfterLoan(floor)) = *hook {
            *hook = None;
            buffer.floor().store(floor, Ordering::Release);
        }
        let floor = buffer.floor().load(Ordering::Acquire);
        if from < floor {
            release_loan(&cell.loan);
            return (Err(ReadError::Unavailable { lowest: floor }), 0);
        }
        let scanned = Self::scan(buffer, slot, &ends, start, offset, nak.loads);
        let (open, loads) = match scanned {
            Ok(found) => found,
            Err((error, loads)) => {
                release_loan(&cell.loan);
                return (Err(error), loads);
            }
        };
        let open = open.map(|end| OpenBlock { count, end });
        let copied = Self::copy(
            buffer,
            &mut subscription.cursor,
            open,
            hook,
            None,
            slot,
            count,
            offset,
            out,
        );
        release_loan(&cell.loan);
        let next = |end: u32| buffer.position(count, end);
        let result = match copied {
            Ok(Copy::Frames { len, end, .. }) => Ok(ReadOutcome::Copied {
                len,
                next: next(end),
            }),
            // Below the NAK bound every block was sent, so committed: an
            // uncommitted one is a position the sender never sent.
            Ok(Copy::Pending) => Err(ReadError::BadRequest),
            Ok(Copy::Canonical { record, end }) => Ok(ReadOutcome::Canonical {
                record,
                next: next(end),
            }),
            Err(CopyError::Corrupt) => Err(ReadError::CorruptTerm { failures: 0 }),
            Err(CopyError::TooSmall(needed)) => Err(ReadError::TooSmall { needed }),
            Err(CopyError::Invariant) => Err(ReadError::Invariant),
        };
        (result, loads)
    }

    /// Where a NAK scan of `offset` starts in `entries`, the checkpoints of
    /// its term count (empty for none): the greatest recorded checkpoint at
    /// or below it, or the term start. An entry above `offset` in its own
    /// stride means no frame starts between the stride and the entry:
    /// `offset` is not a frame boundary, so `BadRequest`.
    fn scan_start(
        entries: &[Checkpoint],
        stride: u32,
        offset: u32,
    ) -> Result<Checkpoint, ReadError> {
        const TERM_START: Checkpoint = (0, 0, true);
        let Some(own) = offset
            .checked_div(stride)
            .and_then(|i| usize::try_from(i).ok())
        else {
            return Ok(TERM_START);
        };
        // `own` lies inside the array: `offset` is below the term length.
        let upto = entries.get(..=own).unwrap_or(entries);
        for entry in upto.iter().rev() {
            match *entry {
                NO_CHECKPOINT => {}
                (frame, _, _) if frame <= offset => return Ok(*entry),
                _ => return Err(ReadError::BadRequest),
            }
        }
        Ok(TERM_START)
    }

    /// Walks word 0 values frame by frame from the checkpoint `start` to
    /// `offset`, under the caller's loan of the exact term in `slot`,
    /// charging each load against `loads` before it is made. Returns, for a
    /// frame boundary, the end of its block when it is an interior
    /// fragment, and the loads spent. From the checkpoint of `offset`'s own
    /// stride every load is of a frame start inside that stride or, to
    /// find a block's end, the next one, below its first frame start: at
    /// most `stride / 32 + 1` loads.
    fn scan(
        buffer: &LogBuffer<O::Terms>,
        slot: u8,
        ends: &Ends<'_>,
        start: Checkpoint,
        offset: u32,
        loads: u32,
    ) -> Result<(Option<u32>, u32), (ReadError, u32)> {
        let lane = buffer.config.lane;
        let term_length = buffer.term_length;
        let mut budget = Loads { spent: 0, loads };
        let (entry, end, begin) = start;
        let mut at = entry;
        let mut walk = if end <= entry {
            Walk::Boundary
        } else if offset >= end {
            // The entry's whole block lies below `offset`: its end,
            // recorded by the cursor path, is a block boundary of this
            // term count, reached without a load.
            at = end;
            Walk::Boundary
        } else {
            Walk::Known { end, begin }
        };
        loop {
            if at > offset {
                return Err((ReadError::BadRequest, budget.spent));
            }
            let corrupt = |spent| (ReadError::CorruptTerm { failures: 0 }, spent);
            walk = match walk {
                Walk::Boundary if at == offset => return Ok((None, budget.spent)),
                Walk::Boundary => {
                    budget.charge()?;
                    // SAFETY: loan held on this slot's term; `at` is a block
                    // boundary of this term count: the term start, a block
                    // start or end the cursor path recorded from a block it
                    // copied, in an array tagged with this count
                    // (`scan_start`), or the end of a block this walk
                    // checked. Only validated lengths lead to the next `at`,
                    // so no payload word is ever read as a header.
                    let first = observe_block(unsafe { buffer.regions.word0(slot, at) });
                    match classify(first, at, term_length, lane) {
                        // An uncommitted block, or padding to the term end,
                        // lies across `offset`.
                        Some(First::Pending | First::Pad) => {
                            return Err((ReadError::BadRequest, budget.spent));
                        }
                        Some(First::Aborted(extent)) => {
                            at = at
                                .checked_add(extent)
                                .ok_or((ReadError::BadRequest, budget.spent))?;
                            Walk::Boundary
                        }
                        Some(First::Data(frame, last)) => {
                            at = frame.next;
                            if last { Walk::Boundary } else { Walk::Open }
                        }
                        None => return Err(corrupt(budget.spent)),
                    }
                }
                Walk::Known { end, begin } if at == offset => {
                    return Ok(((!begin).then_some(end), budget.spent));
                }
                Walk::Known { end, begin } => {
                    budget.charge()?;
                    // SAFETY: loan held on this slot's term; `at` is the
                    // entry's frame, recorded by the cursor path from a
                    // frame it copied in an array tagged with this term
                    // count, or the next frame start a validated length
                    // gave. A block's first word 0 is loaded with Acquire
                    // here; an interior entry's block had its first word 0
                    // observed with Acquire by the cursor path, under a loan
                    // of this term incarnation (as for a resumed block).
                    let word = unsafe { buffer.regions.word0(slot, at) };
                    let raw = if begin {
                        observe_block(word)
                    } else {
                        load_interior(word)
                    };
                    let frame = check_frame(raw, at, end, begin, lane)
                        .ok_or_else(|| corrupt(budget.spent))?;
                    at = frame.next;
                    if at == end {
                        Walk::Boundary
                    } else {
                        Walk::Known { end, begin: false }
                    }
                }
                Walk::Open if at == offset => {
                    let end = Self::open_end(buffer, slot, ends, offset, &mut budget)?;
                    return Ok((Some(end), budget.spent));
                }
                Walk::Open => {
                    budget.charge()?;
                    // SAFETY: loan held on this slot's term; `at` is a
                    // fragment start a validated length gave, inside a block
                    // whose first word 0 this walk observed with Acquire.
                    let raw = load_interior(unsafe { buffer.regions.word0(slot, at) });
                    let (frame, last) = check_open(raw, at, term_length, false, lane)
                        .ok_or_else(|| corrupt(budget.spent))?;
                    at = frame.next;
                    if last { Walk::Boundary } else { Walk::Open }
                }
            };
        }
    }

    /// The end of the block whose interior fragment starts at `offset`, a
    /// block the walk entered at its first word 0 and has not met the END
    /// of. Its first source in fragment order: the cursor's open block,
    /// when the cursor stands at one of its fragments; the checkpoint of
    /// the next stride, when that is one of its fragments (the first frame
    /// start there); its END, loaded fragment by fragment. A block reaching
    /// past the next stride has a fragment start there, recorded by the
    /// cursor path once it copied it, so the loads stay below it.
    fn open_end(
        buffer: &LogBuffer<O::Terms>,
        slot: u8,
        ends: &Ends<'_>,
        offset: u32,
        budget: &mut Loads,
    ) -> Result<u32, (ReadError, u32)> {
        let lane = buffer.config.lane;
        let term_length = buffer.term_length;
        let recorded = offset
            .checked_div(ends.stride)
            .and_then(|i| i.checked_add(1))
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| ends.entries.get(i))
            .copied()
            .filter(|&(frame, end, begin)| !begin && end > frame);
        let mut at = offset;
        loop {
            // Both sources were recorded under this term count (`entries`
            // is the array tagged with it, `at_cursor` the open block of
            // this count), from blocks the cursor path validated in this
            // term incarnation, which the loan keeps. A fragment start of
            // this block is in no other block: the recorded end is this
            // block's.
            if let Some((cursor, end)) = ends.at_cursor
                && cursor == at
                && end > at
            {
                return Ok(end);
            }
            if let Some((frame, end, _)) = recorded
                && frame == at
            {
                return Ok(end);
            }
            budget.charge()?;
            // SAFETY: loan held on this slot's term; `at` is a fragment
            // start a validated length gave, inside a block whose first word
            // 0 the walk observed with Acquire.
            let raw = load_interior(unsafe { buffer.regions.word0(slot, at) });
            let (frame, last) = check_open(raw, at, term_length, false, lane)
                .ok_or((ReadError::CorruptTerm { failures: 0 }, budget.spent))?;
            at = frame.next;
            if last {
                return Ok(at);
            }
        }
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
            checkpoints,
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
            Some(&mut *checkpoints),
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
                checkpoints.record(buffer.term_length, from, 0, true);
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
        mut checkpoints: Option<&mut Checkpoints>,
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
                // incarnation (the loan's exact term proves it). For a NAK
                // read, a resumed block's end comes only from values the
                // cursor path recorded under this term count, and its first
                // word 0 was observed by the walk or the cursor path.
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
                // A frame the cursor path copied: a NAK checkpoint (S2 2.3).
                if let Some(checkpoints) = checkpoints.as_deref_mut() {
                    checkpoints.record(term_length, buffer.position(count, at), block_end, begin);
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
    let (frame, last) = check_fragment(raw, at, block_end, begin, lane)?;
    (last == (frame.next == block_end)).then_some(frame)
}

/// [`check_frame`] for a block whose end is not known yet: the frame lies
/// inside the term, and one without END ends before the term end. Returns
/// the frame and whether it has END.
fn check_open(
    raw: u64,
    at: u32,
    term_length: u32,
    begin: bool,
    lane: crate::frame::Lane,
) -> Option<(Frame, bool)> {
    let (frame, last) = check_fragment(raw, at, term_length, begin, lane)?;
    (last || frame.next < term_length).then_some((frame, last))
}

/// The checks of [`check_frame`] but END's: committed DATA of `lane`, BEGIN
/// only at the block start (`begin`), at least one payload byte, aligned
/// and ending at or before `limit`. Returns the frame and its END flag.
fn check_fragment(
    raw: u64,
    at: u32,
    limit: u32,
    begin: bool,
    lane: crate::frame::Lane,
) -> Option<(Frame, bool)> {
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
    let next = at.checked_add(reserved).filter(|next| *next <= limit)?;
    Some((
        Frame {
            length,
            reserved,
            next,
        },
        flags.end(),
    ))
}

/// What a block's first word 0 says, for a NAK walk.
enum First {
    /// Not committed yet.
    Pending,
    /// PAD to the term end.
    Pad,
    /// An ABORTED block of this extent.
    Aborted(u32),
    /// A DATA block's first frame, and whether it has END.
    Data(Frame, bool),
}

/// Classifies `raw`, the first word 0 of the block at `at`, with the checks
/// `validate_block` makes of PAD and ABORTED and [`check_open`] of DATA.
/// `None` for corruption.
fn classify(raw: u64, at: u32, term_length: u32, lane: crate::frame::Lane) -> Option<First> {
    // `frame_length`, the low 32 bits: a committed block's is positive.
    let length = u32::try_from(raw & u64::from(u32::MAX)).ok()?;
    if length.cast_signed() <= 0 {
        return Some(First::Pending);
    }
    let word = Word0::unpack(raw).ok()?;
    if word.version() != crate::frame::PROTOCOL_VERSION {
        return None;
    }
    let rest = term_length.checked_sub(at)?;
    match FrameType::try_from_code(word.frame_type_code()).ok()? {
        FrameType::Pad => (length == rest).then_some(First::Pad),
        FrameType::Aborted => (word.flags().lane() == lane
            && length.is_multiple_of(crate::frame::FRAME_ALIGNMENT)
            && length <= rest)
            .then_some(First::Aborted(length)),
        FrameType::Data => check_open(raw, at, term_length, true, lane)
            .map(|(frame, last)| First::Data(frame, last)),
        _ => None,
    }
}

/// What a NAK walk may take a block's end from ([`SenderRead::open_end`]).
struct Ends<'a> {
    /// The checkpoints of the NAK's term count (empty for none).
    entries: &'a [Checkpoint],
    stride: u32,
    /// The cursor's term offset and its open block's end, when it stands
    /// inside a block of the NAK's term count.
    at_cursor: Option<(u32, u32)>,
}

/// A NAK walk's word 0 loads: each is charged before it is made.
struct Loads {
    spent: u32,
    loads: u32,
}

impl Loads {
    fn charge(&mut self) -> Result<(), (ReadError, u32)> {
        match self
            .spent
            .checked_add(1)
            .filter(|total| *total <= self.loads)
        {
            Some(total) => {
                self.spent = total;
                Ok(())
            }
            None => Err((ReadError::Budget, self.spent)),
        }
    }
}

/// Where a NAK walk stands.
#[derive(Clone, Copy)]
enum Walk {
    /// At a block boundary.
    Boundary,
    /// At a frame start of a block whose end is known (`begin` for its
    /// first frame).
    Known { end: u32, begin: bool },
    /// At a fragment start of a block whose END is not met yet.
    Open,
}
