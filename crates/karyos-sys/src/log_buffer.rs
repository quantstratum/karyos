// SPDX-License-Identifier: Apache-2.0

//! Embedded log buffer for one lane with exclusive publication and term reuse
//! (SPEC.md §4; design in `quantstratum-docs: karyos/design/embedded-log-buffer.md`).
//!
//! `LogBuffer` owns `3 + S` term slots, their descriptors, a slot table, the
//! active term count, a registry of loan cells and the published reserved
//! head, limit and floor. Three capabilities act on it:
//!
//! - [`Publication`], issued once, appends under a standing write loan and
//!   rotates through a recoverable no-loan state;
//! - [`Subscription`], one per registry cell, copies messages out under a
//!   read loan held through the last byte;
//! - [`Conductor`], issued once, serialises admission, flow control,
//!   retention, rotation help, reclamation, cleaning and preparation through
//!   `&mut self`.
//!
//! Scope: embedded mode (one process), one lane, copy delivery, `hold`
//! required subscribers and `rejoin_at_head` optional subscribers. No
//! concurrent publication, claims, observers, revocation policies or mapping
//! generations. This low-level copy primitive also allows a publication with
//! no subscribers at all: the `NotConnected` / `allow_unconnected` connection
//! rules of SPEC.md §4 are left to a later, higher layer.

use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::error::{LayoutError, SysError};
use crate::frame::{
    EXTENSION_LENGTH, Flags, FrameType, HEADER_LENGTH, Lane, PROTOCOL_VERSION, Word0,
};
use crate::loan::{
    LoanOutcome, LoanTarget, activate, begin_cleaning, begin_reclaim, loan_held, publish,
    release_loan, take_loan,
};
use crate::publication::{load_interior, observe_block, publish_block, store_interior};
use crate::sizing::{FragmentPlan, TermLength, align_frame};
use crate::slot::{Descriptor, SlotIndex, SlotState};
use crate::term::{Generation, TermCount, TermId};
use crate::term_bytes::sealed::Token;
use crate::term_bytes::{HeapTerms, SharedTerms, TermBytes};

mod sealed {
    /// Prevents implementations of [`super::BufferOwner`] outside this
    /// module.
    pub trait Sealed {}
}

/// A stable owner of a [`LogBuffer`]: every dereference returns the same
/// buffer. Implemented only for `&LogBuffer` and `Arc<LogBuffer>`.
pub trait BufferOwner: Deref<Target = LogBuffer<Self::Terms>> + Clone + sealed::Sealed {
    /// The buffer's term memory.
    type Terms: TermBytes;
}

impl<T: TermBytes> sealed::Sealed for &LogBuffer<T> {}
impl<T: TermBytes> BufferOwner for &LogBuffer<T> {
    type Terms = T;
}
impl<T: TermBytes> sealed::Sealed for Arc<LogBuffer<T>> {}
impl<T: TermBytes> BufferOwner for Arc<LogBuffer<T>> {
    type Terms = T;
}

/// Slots reserved as headroom for slots awaiting cleaning (`C`).
pub const CLEANING_HEADROOM: u8 = 1;

const CELL_FREE: u64 = 0;
const CELL_REQUIRED: u64 = 1;
const CELL_OPTIONAL: u64 = 2;
const CELL_PUBLICATION: u64 = 3;

/// A subscriber's role (SPEC.md §4 reader roles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Bounds the publisher; never lapped (`hold` policy).
    Required,
    /// Does not bound the publisher; lapped readers rejoin at the head.
    Optional,
}

/// Construction parameters of a [`LogBuffer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogBufferConfig {
    /// Length of every term.
    pub term_length: TermLength,
    /// Spare slots `S` beyond the three rotation slots.
    pub spare_slots: u8,
    /// Registry capacity for subscribers.
    pub max_subscribers: u8,
    /// Maximum frame bytes per fragment.
    pub mtu: u32,
    /// Maximum bytes one message may reserve (at most `term_length / 8`).
    pub max_reserved: u32,
    /// Initial term id of the incarnation.
    pub initial_term_id: TermId,
    /// The lane of this buffer.
    pub lane: Lane,
    /// Session alias written in every header.
    pub session_id: i32,
    /// Stream id written in every header.
    pub stream_id: i32,
}

#[derive(Debug)]
struct Cell {
    loan: AtomicU64,
    revoked: AtomicU64,
    position: AtomicU64,
    state: AtomicU64,
}

impl Cell {
    fn new(state: u64) -> Self {
        Self {
            loan: AtomicU64::new(0),
            revoked: AtomicU64::new(0),
            position: AtomicU64::new(0),
            state: AtomicU64::new(state),
        }
    }
}

/// One lane's log buffer. Its term memory `T` fixes how payload bytes are
/// moved: [`HeapTerms`] (the default) with plain copies, [`SharedTerms`]
/// only as atomic words.
#[derive(Debug)]
pub struct LogBuffer<T: TermBytes = HeapTerms> {
    regions: T,
    slots: u8,
    spare_slots: u8,
    term_length: u32,
    initial_term_id: TermId,
    generation: Generation,
    config: LogBufferConfig,
    max_message_length: u32,
    descriptors: Box<[AtomicU64]>,
    table: Box<[AtomicU64]>,
    active_count: AtomicU64,
    reserved_head: AtomicU64,
    limit: AtomicU64,
    floor: AtomicU64,
    cells: Box<[Cell]>,
    publication_taken: AtomicBool,
    conductor_taken: AtomicBool,
}

impl LogBuffer<HeapTerms> {
    /// Creates a buffer in a private heap allocation holding `ACTIVE(t0)`
    /// and `READY(t0 + 1)`, every other slot `FREE`.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::ResourcesUnavailable`] when `3 + S > 128` or `S`
    /// leaves no credit for the publication, and layout errors for the MTU
    /// and budget.
    pub fn new(config: LogBufferConfig) -> Result<Self, SysError> {
        Self::build(config)
    }
}

impl LogBuffer<SharedTerms> {
    /// Creates a buffer whose terms are accessed only as aligned atomic
    /// words, as a shared mapping requires; the storage itself is heap
    /// memory of this process for now (`quantstratum-docs: karyos/design/shared-payload-access.md`).
    ///
    /// # Errors
    ///
    /// As [`LogBuffer::new`].
    pub fn new_shared(config: LogBufferConfig) -> Result<Self, SysError> {
        Self::build(config)
    }
}

impl<T: TermBytes> LogBuffer<T> {
    fn build(config: LogBufferConfig) -> Result<Self, SysError> {
        let slots = config
            .spare_slots
            .checked_add(3)
            .filter(|slots| *slots <= crate::slot::MAX_SLOTS)
            .ok_or(SysError::ResourcesUnavailable)?;
        if config.spare_slots < CLEANING_HEADROOM + 1 {
            return Err(SysError::ResourcesUnavailable);
        }
        let plan = FragmentPlan::new(config.mtu, Flags::NONE)?;
        let max_message_length =
            plan.max_message_length(config.max_reserved, config.term_length)?;
        let regions = T::allocate(Token::new(), config.term_length, slots)?;
        let generation = Generation::default();
        let t0 = config.initial_term_id;
        let one = TermCount::ZERO.next()?;
        let descriptors: Box<[AtomicU64]> = (0..slots)
            .map(|slot| {
                let state = match slot {
                    0 => Descriptor::new(t0, generation, SlotState::Active),
                    1 => Descriptor::new(t0.advanced_by(one), generation, SlotState::Ready),
                    _ => Descriptor::new(t0, generation, SlotState::Free),
                };
                AtomicU64::new(state.encode())
            })
            .collect();
        let table: Box<[AtomicU64]> = (0..slots).map(|_| AtomicU64::new(0)).collect();
        let table_len = u32::from(slots);
        if let Some(entry) = table.first() {
            entry.store(table_entry(0, 0), Ordering::Relaxed);
        }
        if let Some(entry) = table.get((1 % table_len) as usize) {
            entry.store(table_entry(1, 1), Ordering::Relaxed);
        }
        let cells: Box<[Cell]> = (0..=config.max_subscribers)
            .map(|index| {
                Cell::new(if index == 0 {
                    CELL_PUBLICATION
                } else {
                    CELL_FREE
                })
            })
            .collect();
        let window = u64::from(config.term_length.get() / 2);
        Ok(Self {
            regions,
            slots,
            spare_slots: config.spare_slots,
            term_length: config.term_length.get(),
            initial_term_id: t0,
            generation,
            config,
            max_message_length,
            descriptors,
            table,
            active_count: AtomicU64::new(0),
            reserved_head: AtomicU64::new(0),
            limit: AtomicU64::new(window),
            floor: AtomicU64::new(0),
            cells,
            publication_taken: AtomicBool::new(false),
            conductor_taken: AtomicBool::new(false),
        })
    }

    /// Takes the only publication, borrowing the buffer. Returns `None` once
    /// a publication has been issued in either form; it is never reissued.
    ///
    /// # Errors
    ///
    /// Returns an error when the initial write loan cannot be taken.
    pub fn publication(&self) -> Result<Option<Publication<&Self>>, SysError> {
        issue_publication(self)
    }

    /// Takes the only publication, owning a share of the buffer.
    ///
    /// # Errors
    ///
    /// As [`LogBuffer::publication`].
    pub fn publication_owned(self: &Arc<Self>) -> Result<Option<Publication<Arc<Self>>>, SysError> {
        issue_publication(Arc::clone(self))
    }

    /// Takes the only conductor, borrowing the buffer. Returns `None` once a
    /// conductor has been issued in either form.
    #[must_use]
    pub fn conductor(&self) -> Option<Conductor<&Self>> {
        issue_conductor(self)
    }

    /// Takes the only conductor, owning a share of the buffer.
    #[must_use]
    pub fn conductor_owned(self: &Arc<Self>) -> Option<Conductor<Arc<Self>>> {
        issue_conductor(Arc::clone(self))
    }

    /// The lane this buffer carries; positions are local to it.
    #[inline]
    #[must_use]
    pub fn lane(&self) -> Lane {
        self.config.lane
    }

    /// Largest message without the trace extension.
    #[inline]
    #[must_use]
    pub fn max_message_length(&self) -> u32 {
        self.max_message_length
    }

    /// Number of attached subscribers. Advisory: it can change right after
    /// it is read; used for connection policy, never for memory safety.
    #[must_use]
    pub fn attached_subscribers(&self) -> u32 {
        let attached = self
            .cells
            .iter()
            .skip(1)
            .filter(|cell| cell.state.load(Ordering::Acquire) != CELL_FREE)
            .count();
        u32::try_from(attached).unwrap_or(u32::MAX)
    }

    fn cell(&self, index: usize) -> Result<&Cell, SysError> {
        self.cells.get(index).ok_or(SysError::ResourcesUnavailable)
    }

    fn descriptor(&self, slot: u8) -> Result<&AtomicU64, SysError> {
        self.descriptors
            .get(usize::from(slot))
            .ok_or(SysError::ResourcesUnavailable)
    }

    fn table_slot(&self, count: TermCount) -> Result<&AtomicU64, SysError> {
        let index = count.get() % u32::from(self.slots);
        self.table
            .get(index as usize)
            .ok_or(SysError::ResourcesUnavailable)
    }

    fn position(&self, count: TermCount, offset: u32) -> u64 {
        u64::from(count.get()) * u64::from(self.term_length) + u64::from(offset)
    }

    fn split(&self, position: u64) -> Result<(TermCount, u32), SysError> {
        let term = u64::from(self.term_length);
        let count = u32::try_from(position / term)
            .map_err(|_| LayoutError::LengthOverflow { value: position })?;
        Ok((TermCount::try_new(count)?, (position % term) as u32))
    }

    fn target(&self, slot: u8, count: TermCount) -> Result<LoanTarget, SysError> {
        Ok(LoanTarget::new(
            SlotIndex::try_new(slot)?,
            self.generation,
            self.initial_term_id,
            count,
        ))
    }

    /// Looks up the slot recorded for `count` in the table hint.
    fn lookup(&self, count: TermCount) -> Result<Lookup, SysError> {
        let raw = self.table_slot(count)?.load(Ordering::Acquire);
        Ok(match decode_entry(raw) {
            None => Lookup::Missing,
            Some((entry_count, slot)) if entry_count == count.get() => Lookup::Slot(slot),
            Some((entry_count, _)) if entry_count > count.get() => Lookup::Gone,
            Some(_) => Lookup::Missing,
        })
    }
}

fn issue_publication<O: BufferOwner>(owner: O) -> Result<Option<Publication<O>>, SysError> {
    let buffer: &LogBuffer<O::Terms> = &owner;
    if buffer
        .publication_taken
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(None);
    }
    let cell = buffer.cell(0)?;
    let slot = SlotIndex::try_new(0)?;
    let target = LoanTarget::new(
        slot,
        buffer.generation,
        buffer.initial_term_id,
        TermCount::ZERO,
    );
    match take_loan(&cell.loan, &cell.revoked, buffer.descriptor(0)?, target)? {
        LoanOutcome::Granted => Ok(Some(Publication {
            buffer: owner,
            state: PublicationState::Active {
                count: TermCount::ZERO,
                slot: 0,
                tail: 0,
            },
        })),
        _ => Err(SysError::CorruptTerm {
            offset: 0,
            reason: "initial term not active",
        }),
    }
}

fn issue_conductor<O: BufferOwner>(owner: O) -> Option<Conductor<O>> {
    owner
        .conductor_taken
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()?;
    Some(Conductor {
        buffer: owner,
        quarantined: Vec::new(),
    })
}

enum Lookup {
    Slot(u8),
    Missing,
    Gone,
}

fn table_entry(count: u32, slot: u8) -> u64 {
    ((u64::from(count) + 1) << 8) | u64::from(slot)
}

fn decode_entry(raw: u64) -> Option<(u32, u8)> {
    let count = raw >> 8;
    if count == 0 {
        return None;
    }
    Some(((count - 1) as u32, (raw & 0x7F) as u8))
}

/// Per-message options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AppendOptions {
    /// Set EOS on the last fragment.
    pub end_of_stream: bool,
    /// Application value written in every fragment's header.
    pub reserved_value: i64,
    /// Opaque, already encoded trace extension; its presence sets EXT.
    pub extension: Option<[u8; EXTENSION_LENGTH as usize]>,
}

/// Result of an append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "back pressure and admin actions must be handled"]
pub enum AppendOutcome {
    /// The message was published; its block starts at `position`.
    Appended {
        /// Stream position of the block.
        position: u64,
    },
    /// The flow-control limit does not admit the reservation; retry later.
    BackPressured,
    /// The append only padded or rotated, or rotation waits for the
    /// conductor; retry later.
    AdminAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationState {
    Active {
        count: TermCount,
        slot: u8,
        tail: u32,
    },
    Rotating {
        next: TermCount,
    },
}

/// The buffer's only publication.
#[derive(Debug)]
pub struct Publication<O: BufferOwner> {
    buffer: O,
    state: PublicationState,
}

impl<O: BufferOwner> Publication<O> {
    /// The buffer this publication appends to.
    #[inline]
    #[must_use]
    pub fn buffer(&self) -> &LogBuffer<O::Terms> {
        &self.buffer
    }

    /// Appends one message (SPEC.md §4, exclusive offer).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::EmptyMessage`], layout errors for messages that
    /// are too large, and [`SysError::MaxPositionExceeded`] when the next
    /// term would reach `2^31`. Nothing is written on error.
    pub fn append(
        &mut self,
        payload: &[u8],
        options: AppendOptions,
    ) -> Result<AppendOutcome, SysError> {
        PublicationContext {
            buffer: &self.buffer,
            state: &mut self.state,
        }
        .append(payload, options)
    }
}

/// The publication's state borrowed together with its buffer.
struct PublicationContext<'a, T: TermBytes> {
    buffer: &'a LogBuffer<T>,
    state: &'a mut PublicationState,
}

impl<T: TermBytes> PublicationContext<'_, T> {
    fn append(
        &mut self,
        payload: &[u8],
        options: AppendOptions,
    ) -> Result<AppendOutcome, SysError> {
        if payload.is_empty() {
            return Err(SysError::EmptyMessage);
        }
        let buffer = self.buffer;
        let ext = options.extension.is_some();
        let plan = FragmentPlan::new(
            buffer.config.mtu,
            Flags::new(false, false, false, ext, buffer.config.lane),
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

        if let PublicationState::Rotating { next } = *self.state {
            return self.rotate(next);
        }
        let PublicationState::Active { count, slot, tail } = *self.state else {
            return Ok(AppendOutcome::AdminAction);
        };
        let limit = buffer.limit.load(Ordering::Acquire);
        let remaining = buffer.term_length - tail;
        if reserved > remaining {
            // Reserve only the PAD up to the term boundary.
            let boundary = buffer.position(count, buffer.term_length);
            if boundary > limit {
                return Ok(AppendOutcome::BackPressured);
            }
            let next = count.next()?;
            buffer.reserved_head.store(boundary, Ordering::Release);
            if remaining > 0 {
                self.write_pad(slot, count, tail, remaining);
            }
            // Every access to the old term has ended: release its loan before
            // touching anything else.
            release_loan(&buffer.cell(0)?.loan);
            *self.state = PublicationState::Rotating { next };
            let _ = self.rotate(next)?;
            return Ok(AppendOutcome::AdminAction);
        }
        let start = buffer.position(count, tail);
        let end = start + u64::from(reserved);
        if end > limit {
            return Ok(AppendOutcome::BackPressured);
        }
        buffer.reserved_head.store(end, Ordering::Release);
        self.write_block(slot, count, tail, payload, &plan, options);
        *self.state = PublicationState::Active {
            count,
            slot,
            tail: tail + reserved,
        };
        Ok(AppendOutcome::Appended { position: start })
    }

    /// Rotation from the no-loan state: find, activate and advance to `next`,
    /// then take the standing loan on exactly `next`.
    fn rotate(&mut self, next: TermCount) -> Result<AppendOutcome, SysError> {
        let buffer = self.buffer;
        let Lookup::Slot(slot) = buffer.lookup(next)? else {
            return Ok(AppendOutcome::AdminAction);
        };
        let descriptor_word = buffer.descriptor(slot)?;
        let term_id = buffer.initial_term_id.advanced_by(next);
        let found = Descriptor::decode(descriptor_word.load(Ordering::Acquire))?;
        if found.term_id() != term_id {
            return Ok(AppendOutcome::AdminAction);
        }
        match found.state() {
            SlotState::Ready => {
                let _ = activate(descriptor_word, found)?;
            }
            SlotState::Active => {}
            _ => return Ok(AppendOutcome::AdminAction),
        }
        let previous = u64::from(next.get() - 1);
        let _ = buffer.active_count.compare_exchange(
            previous,
            u64::from(next.get()),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let cell = buffer.cell(0)?;
        match take_loan(
            &cell.loan,
            &cell.revoked,
            descriptor_word,
            buffer.target(slot, next)?,
        )? {
            LoanOutcome::Granted => {
                *self.state = PublicationState::Active {
                    count: next,
                    slot,
                    tail: 0,
                };
                Ok(AppendOutcome::AdminAction)
            }
            _ => Ok(AppendOutcome::AdminAction),
        }
    }

    fn write_pad(&self, slot: u8, count: TermCount, tail: u32, extent: u32) {
        let buffer = self.buffer;
        let flags = Flags::new(false, false, false, false, buffer.config.lane);
        self.write_header_tail(slot, count, tail, 0);
        // SAFETY: the publication holds its standing write loan on `count`
        // in `slot`; `tail` is a 32-aligned frame start inside the term.
        let word = unsafe { buffer.regions.word0(slot, tail) };
        publish_block(word, Word0::new(extent as i32, flags, FrameType::Pad));
    }

    fn write_block(
        &self,
        slot: u8,
        count: TermCount,
        start: u32,
        payload: &[u8],
        plan: &FragmentPlan,
        options: AppendOptions,
    ) {
        let buffer = self.buffer;
        let ext = options.extension.is_some();
        let lane = buffer.config.lane;
        let fragments = plan.fragments(payload.len() as u32);
        let chunk = plan.payload_per_fragment() as usize;
        let mut offset = start;
        let mut rest = payload;
        let mut first = None;
        for index in 0..fragments {
            let (body, next) = rest.split_at(chunk.min(rest.len()));
            rest = next;
            let last = index + 1 == fragments;
            let flags = Flags::new(index == 0, last, last && options.end_of_stream, ext, lane);
            let header_length = flags.header_length();
            let frame_length = header_length + body.len() as u32;
            let word0 = Word0::new(frame_length as i32, flags, FrameType::Data);
            self.write_header_tail(slot, count, offset, options.reserved_value);
            if let Some(extension) = &options.extension {
                // SAFETY: write loan held; bytes after the header of a frame
                // in the unpublished range; not a word 0.
                unsafe {
                    buffer
                        .regions
                        .write_bytes(slot, offset + HEADER_LENGTH, extension)
                };
            }
            // SAFETY: as above, for the payload bytes.
            unsafe {
                buffer
                    .regions
                    .write_bytes(slot, offset + header_length, body)
            };
            let frame_reserved = align_frame(frame_length).unwrap_or(frame_length);
            // The slot was cleaned before reuse, so alignment padding and the
            // rest of the reserved range already read as zero.
            if index == 0 {
                first = Some(word0);
            } else {
                // SAFETY: write loan held; 32-aligned frame start in range.
                store_interior(unsafe { buffer.regions.word0(slot, offset) }, word0);
            }
            offset += frame_reserved;
        }
        if let Some(word0) = first {
            // SAFETY: write loan held; the block's first frame start.
            publish_block(unsafe { buffer.regions.word0(slot, start) }, word0);
        }
    }

    /// Writes header bytes 8..32 of the frame at `offset`.
    fn write_header_tail(&self, slot: u8, count: TermCount, offset: u32, reserved_value: i64) {
        let buffer = self.buffer;
        let term_id = buffer.initial_term_id.advanced_by(count).get() as i32;
        let mut bytes = [0u8; 24];
        let fields: [&[u8]; 5] = [
            &(offset as i32).to_le_bytes(),
            &buffer.config.session_id.to_le_bytes(),
            &buffer.config.stream_id.to_le_bytes(),
            &term_id.to_le_bytes(),
            &reserved_value.to_le_bytes(),
        ];
        let mut at = 0;
        for field in fields {
            if let Some(destination) = bytes.get_mut(at..at + field.len()) {
                destination.copy_from_slice(field);
            }
            at += field.len();
        }
        // SAFETY: write loan held; header bytes 8..32 of a frame in the
        // unpublished range, never a word 0.
        unsafe { buffer.regions.write_bytes(slot, offset + 8, &bytes) };
    }
}

/// Result of a poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// A message was copied into the caller's buffer.
    Message {
        /// Stream position of the block.
        position: u64,
        /// Bytes copied.
        length: u32,
        /// Whether the last fragment carries EOS.
        end_of_stream: bool,
        /// Reserved value of the first fragment.
        reserved_value: i64,
        /// The first fragment's trace extension, copied under the loan
        /// (opaque; validated by protocol-level callers).
        extension: Option<[u8; EXTENSION_LENGTH as usize]>,
    },
    /// Nothing published at the position yet.
    Pending,
    /// The subscriber was lapped. Data in `[from, lost_to)` is no longer
    /// retained (below the retention floor). Under `rejoin_at_head` the
    /// subscriber resumes at `resume`, the reserved head; data in
    /// `[lost_to, resume)` may still be retained but is skipped by policy.
    Overrun {
        /// First position not delivered.
        from: u64,
        /// End of the range known lost: the retention floor when the
        /// overrun was detected (at least `from`).
        lost_to: u64,
        /// Position the subscriber resumes from (a block boundary).
        resume: u64,
    },
}

/// A registered subscriber's private cursor.
#[derive(Debug)]
struct Cursor {
    cell: usize,
    role: Role,
    /// Next block to copy.
    position: u64,
    /// Position published in the registry (acknowledged).
    acknowledged: u64,
    /// For a required subscriber, the position after a copied but not yet
    /// acknowledged message.
    pending: Option<u64>,
    detached: bool,
}

/// A registered subscriber.
///
/// Optional subscribers acknowledge every copy automatically. A required
/// subscriber must call [`Subscription::acknowledge`] after it has handled a
/// copied message; until then its registry position, which bounds the
/// publisher and the retention floor, stays at the message, and the next
/// poll copies the same message again (redelivery after a failed handler).
#[derive(Debug)]
pub struct Subscription<O: BufferOwner> {
    buffer: O,
    cursor: Cursor,
}

impl<O: BufferOwner> Subscription<O> {
    /// The buffer this subscription reads.
    #[inline]
    #[must_use]
    pub fn buffer(&self) -> &LogBuffer<O::Terms> {
        &self.buffer
    }

    /// The read cursor: where the next copy starts. With a pending
    /// (unacknowledged) message the next poll rewinds to the acknowledged
    /// position instead; see [`Subscription::acknowledged_position`].
    #[inline]
    #[must_use]
    pub fn position(&self) -> u64 {
        self.cursor.position
    }

    /// The acknowledged position published in the registry.
    #[inline]
    #[must_use]
    pub fn acknowledged_position(&self) -> u64 {
        self.cursor.acknowledged
    }

    /// Copies the next message into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::BufferTooShort`] when `out` is too small,
    /// [`SysError::RequiredSubscriberLapped`] when a required subscriber's
    /// data is gone, and [`SysError::CorruptTerm`] for inconsistent published
    /// geometry. On error a pending message and its acknowledgement are
    /// preserved, and the read cursor may have been rewound to the
    /// acknowledged position for redelivery. A PAD stepped over before the
    /// failing read is still acknowledged: the acknowledged position can
    /// advance past it.
    pub fn poll(&mut self, out: &mut [u8]) -> Result<PollOutcome, SysError> {
        SubscriptionContext {
            buffer: &self.buffer,
            cursor: &mut self.cursor,
        }
        .poll(out)
    }

    /// Acknowledges the last copied message: publishes the stored end of
    /// that block to the registry. It takes no caller position. A no-op when
    /// nothing is pending, so repeated calls are harmless. At most one
    /// message is pending; until it is acknowledged every poll copies that
    /// same message again (same position, payload and extension).
    ///
    /// Optional subscribers acknowledge automatically on copy; this
    /// low-level API does not replay a message to an optional subscriber
    /// whose handler failed. `close` and `Drop` abandon a pending message.
    pub fn acknowledge(&mut self) {
        if let Some(position) = self.cursor.pending.take() {
            // A failed redelivery may have reset the read cursor to the
            // acknowledged position; the acknowledged block ends here.
            self.cursor.position = position;
            SubscriptionContext {
                buffer: &self.buffer,
                cursor: &mut self.cursor,
            }
            .publish(position);
        }
    }

    /// Detaches, freeing the registry cell for a later subscriber.
    pub fn close(mut self) {
        self.detach();
    }

    fn detach(&mut self) {
        SubscriptionContext {
            buffer: &self.buffer,
            cursor: &mut self.cursor,
        }
        .detach();
    }
}

impl<O: BufferOwner> Drop for Subscription<O> {
    fn drop(&mut self) {
        self.detach();
    }
}

/// A subscriber's cursor borrowed together with its buffer.
struct SubscriptionContext<'a, T: TermBytes> {
    buffer: &'a LogBuffer<T>,
    cursor: &'a mut Cursor,
}

impl<T: TermBytes> SubscriptionContext<'_, T> {
    fn poll(&mut self, out: &mut [u8]) -> Result<PollOutcome, SysError> {
        // An unacknowledged copy is delivered again: never skip ahead. The
        // pending end stays recorded until a redelivery succeeds, so failed,
        // short-buffer or pending polls never invalidate it.
        if self.cursor.pending.is_some() {
            self.cursor.position = self.cursor.acknowledged;
        }
        // At most two iterations: the end of one term and the next term.
        for _ in 0..2 {
            let (count, offset) = self.buffer.split(self.cursor.position)?;
            if offset == self.buffer.term_length {
                self.advance_to(self.buffer.position(count.next()?, 0));
                continue;
            }
            match self.poll_term(count, offset, out)? {
                Step::Done(outcome) => return Ok(outcome),
                Step::NextTerm => {
                    self.advance_to(self.buffer.position(count.next()?, 0));
                }
            }
        }
        Ok(PollOutcome::Pending)
    }

    fn poll_term(
        &mut self,
        count: TermCount,
        offset: u32,
        out: &mut [u8],
    ) -> Result<Step, SysError> {
        let buffer = self.buffer;
        let slot = match buffer.lookup(count)? {
            Lookup::Slot(slot) => slot,
            Lookup::Missing => return Ok(Step::Done(PollOutcome::Pending)),
            Lookup::Gone => return self.overrun(),
        };
        let cell = buffer.cell(self.cursor.cell)?;
        match take_loan(
            &cell.loan,
            &cell.revoked,
            buffer.descriptor(slot)?,
            buffer.target(slot, count)?,
        )? {
            LoanOutcome::Granted => {}
            LoanOutcome::Retry => return Ok(Step::Done(PollOutcome::Pending)),
            LoanOutcome::Overrun | LoanOutcome::Revoked => return self.overrun(),
        }
        // Retention admission point: the floor is checked after the loan is
        // granted and before any plain read.
        if self.cursor.position < buffer.floor.load(Ordering::Acquire) {
            release_loan(&cell.loan);
            return self.overrun();
        }
        let result = self.read_block(slot, offset, out);
        release_loan(&cell.loan);
        match result? {
            Read::Pending => Ok(Step::Done(PollOutcome::Pending)),
            Read::Pad => Ok(Step::NextTerm),
            Read::Message {
                length,
                reserved,
                end_of_stream,
                reserved_value,
                extension,
            } => {
                let position = self.cursor.position;
                let next = position + u64::from(reserved);
                self.cursor.position = next;
                match self.cursor.role {
                    Role::Optional => self.publish(next),
                    Role::Required => self.cursor.pending = Some(next),
                }
                Ok(Step::Done(PollOutcome::Message {
                    position,
                    length,
                    end_of_stream,
                    reserved_value,
                    extension,
                }))
            }
        }
    }

    /// Reads one block of `slot` at `start` under the caller's read loan.
    fn read_block(&self, slot: u8, start: u32, out: &mut [u8]) -> Result<Read, SysError> {
        match self.validate_block(slot, start)? {
            Validated::Pending => Ok(Read::Pending),
            Validated::Pad => Ok(Read::Pad),
            Validated::Block(block) => self.copy_block(slot, start, block, out),
        }
    }

    /// First pass: classifies the block at `start` from its first word 0
    /// and, for data, walks and checks every fragment's word 0.
    fn validate_block(&self, slot: u8, start: u32) -> Result<Validated, SysError> {
        let buffer = self.buffer;
        let term_length = buffer.term_length;
        // SAFETY: read loan held for this slot's term; `start` is a block
        // boundary reached by the walk.
        let first = observe_block(unsafe { buffer.regions.word0(slot, start) });
        let signed = first as u32 as i32;
        if signed <= 0 {
            return Ok(Validated::Pending);
        }
        let word0 = Word0::unpack(first).map_err(|_| corrupt(start, "reserved flags"))?;
        if word0.version() != PROTOCOL_VERSION {
            return Err(corrupt(start, "version"));
        }
        match FrameType::try_from_code(word0.frame_type_code()) {
            Ok(FrameType::Pad) => {
                if signed as u32 != term_length - start {
                    return Err(corrupt(start, "pad extent"));
                }
                return Ok(Validated::Pad);
            }
            Ok(FrameType::Data) => {}
            _ => return Err(corrupt(start, "frame type")),
        }
        let mut offset = start;
        let mut word = word0;
        let mut length: u32 = 0;
        let end_of_stream;
        loop {
            let flags = word.flags();
            if flags.begin() != (offset == start) {
                return Err(corrupt(offset, "BEGIN placement"));
            }
            let frame_length = u32::try_from(word.frame_length())
                .map_err(|_| corrupt(offset, "uncommitted fragment"))?;
            let header_length = flags.header_length();
            if frame_length < header_length {
                return Err(corrupt(offset, "frame shorter than header"));
            }
            let reserved = align_frame(frame_length)?;
            if reserved > term_length - offset {
                return Err(corrupt(offset, "frame past term end"));
            }
            length = length
                .checked_add(frame_length - header_length)
                .ok_or_else(|| corrupt(offset, "length overflow"))?;
            offset += reserved;
            if flags.end() {
                end_of_stream = flags.eos();
                break;
            }
            if offset == term_length {
                return Err(corrupt(offset, "block without END"));
            }
            // SAFETY: read loan held; `offset` is the next frame start.
            word = Word0::unpack(load_interior(unsafe { buffer.regions.word0(slot, offset) }))
                .map_err(|_| corrupt(offset, "reserved flags"))?;
            if word.frame_type_code() != FrameType::Data.code() {
                return Err(corrupt(offset, "interior frame type"));
            }
        }
        Ok(Validated::Block(Block {
            end: offset,
            length,
            end_of_stream,
            ext: word0.flags().ext(),
        }))
    }

    /// Second pass: copies a block validated by the first. Every word 0 is
    /// loaded again and checked again before its value is used, against the
    /// extent and length the first pass found, so a word changed in between
    /// (possible on shared terms) yields `CorruptTerm`, never unchecked
    /// arithmetic or a copy outside the block.
    fn copy_block(
        &self,
        slot: u8,
        start: u32,
        block: Block,
        out: &mut [u8],
    ) -> Result<Read, SysError> {
        let buffer = self.buffer;
        let Block {
            end,
            length,
            end_of_stream,
            ext,
        } = block;
        if out.len() < length as usize {
            return Err(SysError::BufferTooShort {
                required: length as usize,
                available: out.len(),
            });
        }
        let mut reserved_value = [0u8; 8];
        // SAFETY: read loan held; header bytes 24..32 of the published block,
        // inside its first frame (validated by the first pass).
        unsafe {
            buffer
                .regions
                .read_bytes(slot, start + 24, &mut reserved_value)
        };
        let extension = if ext {
            let mut bytes = [0u8; EXTENSION_LENGTH as usize];
            // SAFETY: read loan held; the extension follows the first header
            // inside the published frame (frame_length >= 96 was checked).
            unsafe {
                buffer
                    .regions
                    .read_bytes(slot, start + HEADER_LENGTH, &mut bytes)
            };
            Some(bytes)
        } else {
            None
        };
        let mut offset = start;
        let mut written: u32 = 0;
        while offset < end {
            // SAFETY: read loan held; `offset` is a frame start inside the
            // published block, checked below before any use.
            let word = Word0::unpack(load_interior(unsafe { buffer.regions.word0(slot, offset) }))
                .map_err(|_| corrupt(offset, "reserved flags"))?;
            let flags = word.flags();
            if word.frame_type_code() != FrameType::Data.code() {
                return Err(corrupt(offset, "frame type changed"));
            }
            if flags.begin() != (offset == start) {
                return Err(corrupt(offset, "BEGIN placement changed"));
            }
            let frame_length = u32::try_from(word.frame_length())
                .map_err(|_| corrupt(offset, "frame length changed"))?;
            let header_length = flags.header_length();
            let payload = frame_length
                .checked_sub(header_length)
                .ok_or_else(|| corrupt(offset, "frame shorter than header"))?;
            let next = offset
                .checked_add(
                    align_frame(frame_length)
                        .map_err(|_| corrupt(offset, "frame length changed"))?,
                )
                .filter(|next| *next <= end)
                .ok_or_else(|| corrupt(offset, "frame past block end"))?;
            if flags.end() != (next == end) {
                return Err(corrupt(offset, "END placement changed"));
            }
            let total = written
                .checked_add(payload)
                .filter(|total| *total <= length)
                .ok_or_else(|| corrupt(offset, "block length changed"))?;
            let target = out
                .get_mut(written as usize..total as usize)
                .ok_or_else(|| corrupt(offset, "block length changed"))?;
            // SAFETY: read loan held; the payload of a frame lying inside the
            // published block (checked above).
            unsafe {
                buffer
                    .regions
                    .read_bytes(slot, offset + header_length, target)
            };
            written = total;
            offset = next;
        }
        if written != length {
            return Err(corrupt(start, "block length changed"));
        }
        Ok(Read::Message {
            length,
            reserved: end - start,
            end_of_stream,
            reserved_value: i64::from_le_bytes(reserved_value),
            extension,
        })
    }

    /// Applies `rejoin_at_head`: report the lost range and resume at the
    /// reserved head, which is always a block boundary. A required
    /// subscriber is never lapped while it bounds the publisher; if it ever
    /// finds its data gone, that is an error and its cursor does not move.
    fn overrun(&mut self) -> Result<Step, SysError> {
        if self.cursor.role == Role::Required {
            return Err(SysError::RequiredSubscriberLapped {
                position: self.cursor.position,
            });
        }
        let from = self.cursor.position;
        let lost_to = self.buffer.floor.load(Ordering::Acquire).max(from);
        let resume = self.buffer.reserved_head.load(Ordering::Acquire).max(from);
        self.advance_to(resume);
        Ok(Step::Done(PollOutcome::Overrun {
            from,
            lost_to,
            resume,
        }))
    }

    /// Moves past bytes that deliver nothing (PAD, term ends, overrun),
    /// publishing the position: there is no message to acknowledge.
    fn advance_to(&mut self, position: u64) {
        self.cursor.position = position;
        self.publish(position);
    }

    /// Publishes `position` as the acknowledged registry position.
    fn publish(&mut self, position: u64) {
        self.cursor.acknowledged = position;
        if let Ok(cell) = self.buffer.cell(self.cursor.cell) {
            cell.position.store(position, Ordering::Release);
        }
    }

    fn detach(&mut self) {
        if self.cursor.detached {
            return;
        }
        self.cursor.detached = true;
        if let Ok(cell) = self.buffer.cell(self.cursor.cell) {
            // No loan is held outside `poll`; publishing FREE is the last
            // access of this holder to its cell.
            cell.state.store(CELL_FREE, Ordering::Release);
        }
    }
}

enum Step {
    Done(PollOutcome),
    NextTerm,
}

/// Outcome of the first pass over a block.
enum Validated {
    Pending,
    Pad,
    Block(Block),
}

/// Geometry of a data block checked by the first pass.
#[derive(Debug, Clone, Copy)]
struct Block {
    /// End of the block's last frame.
    end: u32,
    /// Payload bytes over all fragments.
    length: u32,
    end_of_stream: bool,
    /// Whether the first fragment carries the trace extension.
    ext: bool,
}

#[derive(Debug)]
enum Read {
    Pending,
    Pad,
    Message {
        length: u32,
        reserved: u32,
        end_of_stream: bool,
        reserved_value: i64,
        extension: Option<[u8; EXTENSION_LENGTH as usize]>,
    },
}

/// What one duty cycle did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DutyReport {
    /// Slots cleaned and freed.
    pub cleaned: u32,
    /// Slots still quarantined by a loan.
    pub quarantined: u32,
    /// Whether the next term was prepared in this cycle.
    pub prepared: bool,
    /// Whether no FREE slot was available for the next term (cleaner lag).
    pub lagging: bool,
}

/// The buffer's only conductor; every operation takes `&mut self`.
#[derive(Debug)]
pub struct Conductor<O: BufferOwner> {
    buffer: O,
    quarantined: Vec<u8>,
}

impl<O: BufferOwner> Conductor<O> {
    /// Admits a subscriber at the reserved head.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::ResourcesUnavailable`] when no registry cell is
    /// free or an optional subscriber's slot credit does not fit `S - C`.
    pub fn subscribe(&mut self, role: Role) -> Result<Subscription<O>, SysError> {
        let cursor = self.context().subscribe(role)?;
        Ok(Subscription {
            buffer: self.buffer.clone(),
            cursor,
        })
    }

    /// One duty cycle: flow control and retention, rotation help,
    /// reclamation and cleaning, and preparation of the next term.
    ///
    /// # Errors
    ///
    /// Returns errors from the descriptor protocol, which indicate a broken
    /// invariant.
    pub fn duty_cycle(&mut self) -> Result<DutyReport, SysError> {
        self.context().duty_cycle()
    }

    fn context(&mut self) -> ConductorContext<'_, O::Terms> {
        ConductorContext {
            buffer: &self.buffer,
            quarantined: &mut self.quarantined,
        }
    }
}

/// The conductor's state borrowed together with its buffer.
struct ConductorContext<'a, T: TermBytes> {
    buffer: &'a LogBuffer<T>,
    quarantined: &'a mut Vec<u8>,
}

impl<T: TermBytes> ConductorContext<'_, T> {
    fn subscribe(&mut self, role: Role) -> Result<Cursor, SysError> {
        let buffer = self.buffer;
        let mut optional = 0u32;
        let mut free = None;
        for (index, cell) in buffer.cells.iter().enumerate().skip(1) {
            match cell.state.load(Ordering::Acquire) {
                CELL_OPTIONAL => optional += 1,
                CELL_FREE if free.is_none() => free = Some(index),
                _ => {}
            }
        }
        let credits = optional + 1 + u32::from(role == Role::Optional);
        if credits > u32::from(buffer.spare_slots - CLEANING_HEADROOM) {
            return Err(SysError::ResourcesUnavailable);
        }
        let index = free.ok_or(SysError::ResourcesUnavailable)?;
        let cell = buffer.cell(index)?;
        // The Acquire load above observed the previous holder's FREE, so its
        // loan release happens before this reuse; its loan word is zero.
        debug_assert_eq!(cell.loan.load(Ordering::Relaxed), 0);
        cell.revoked.store(0, Ordering::Relaxed);
        let start = buffer.reserved_head.load(Ordering::Acquire);
        cell.position.store(start, Ordering::Relaxed);
        let state = match role {
            Role::Required => CELL_REQUIRED,
            Role::Optional => CELL_OPTIONAL,
        };
        cell.state.store(state, Ordering::Release);
        Ok(Cursor {
            cell: index,
            role,
            position: start,
            acknowledged: start,
            pending: None,
            detached: false,
        })
    }

    fn duty_cycle(&mut self) -> Result<DutyReport, SysError> {
        let mut report = DutyReport::default();
        self.publish_floor_and_limit();
        self.help_rotation()?;
        self.reclaim(&mut report)?;
        self.prepare_next(&mut report)?;
        Ok(report)
    }

    /// Floor and limit from one head snapshot; the floor is published first.
    fn publish_floor_and_limit(&self) {
        let buffer = self.buffer;
        let window = u64::from(buffer.term_length / 2);
        let head = buffer.reserved_head.load(Ordering::Acquire);
        let mut bound = None::<u64>;
        for cell in buffer.cells.iter().skip(1) {
            if cell.state.load(Ordering::Acquire) == CELL_REQUIRED {
                let position = cell.position.load(Ordering::Acquire);
                bound = Some(bound.map_or(position, |b| b.min(position)));
            }
        }
        // SPEC.md §4 retention floor: the minimum required position, or,
        // without required participants, `head_snapshot - window` bounded
        // below by position 0 through an explicit comparison.
        let (floor, base) = match bound {
            Some(required) => (required, required),
            // `max` bounds the subtraction at the publication start without
            // wrapping or saturating arithmetic.
            None => (head.max(window) - window, head),
        };
        // Neither the floor nor the limit ever decreases.
        let floor = floor.max(buffer.floor.load(Ordering::Relaxed));
        let limit = (base + window).max(buffer.limit.load(Ordering::Relaxed));
        buffer.floor.store(floor, Ordering::Release);
        buffer.limit.store(limit, Ordering::Release);
    }

    /// Completes a full term's rotation the publication left half-done.
    fn help_rotation(&self) -> Result<(), SysError> {
        let buffer = self.buffer;
        let active = TermCount::try_new(buffer.active_count.load(Ordering::Acquire) as u32)?;
        let boundary = buffer.position(active, buffer.term_length);
        if buffer.reserved_head.load(Ordering::Acquire) < boundary {
            return Ok(());
        }
        let next = active.next()?;
        let Lookup::Slot(slot) = buffer.lookup(next)? else {
            return Ok(());
        };
        let word = buffer.descriptor(slot)?;
        let found = Descriptor::decode(word.load(Ordering::Acquire))?;
        if found.term_id() != buffer.initial_term_id.advanced_by(next) {
            return Ok(());
        }
        if found.state() == SlotState::Ready {
            let _ = activate(word, found)?;
        }
        let _ = buffer.active_count.compare_exchange(
            u64::from(active.get()),
            u64::from(next.get()),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        Ok(())
    }

    /// Reclaims and cleans every term wholly below the floor.
    fn reclaim(&mut self, report: &mut DutyReport) -> Result<(), SysError> {
        let buffer = self.buffer;
        let floor = buffer.floor.load(Ordering::Acquire);
        let active = buffer.active_count.load(Ordering::Acquire);
        for slot in 0..buffer.slots {
            let word = buffer.descriptor(slot)?;
            let found = Descriptor::decode(word.load(Ordering::Acquire))?;
            let reclaiming = match found.state() {
                SlotState::Active => {
                    let count = found.term_id().count_from(buffer.initial_term_id)?;
                    let end = buffer.position(count, buffer.term_length);
                    if u64::from(count.get()) >= active || end > floor {
                        continue;
                    }
                    begin_reclaim(word, found)?
                }
                SlotState::Reclaiming if self.quarantined.contains(&slot) => found,
                _ => continue,
            };
            if self.loan_held(slot, reclaiming)? {
                if !self.quarantined.contains(&slot) {
                    self.quarantined.push(slot);
                }
                report.quarantined += 1;
                continue;
            }
            self.quarantined.retain(|s| *s != slot);
            let cleaning = begin_cleaning(word, reclaiming)?;
            // SAFETY: this conductor moved the slot to CLEANING after a
            // complete scan of every registry cell found no loan for its term.
            unsafe { buffer.regions.clean(slot) };
            publish(word, cleaning.with_state(SlotState::Free));
            report.cleaned += 1;
        }
        Ok(())
    }

    /// Scans every registry cell, publication included.
    fn loan_held(&self, slot: u8, reclaiming: Descriptor) -> Result<bool, SysError> {
        let index = SlotIndex::try_new(slot)?;
        for cell in self.buffer.cells.iter() {
            if loan_held(core::slice::from_ref(&cell.loan), index, reclaiming)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Prepares `t + 1` in any FREE slot if it is not prepared yet.
    fn prepare_next(&self, report: &mut DutyReport) -> Result<(), SysError> {
        let buffer = self.buffer;
        let active = TermCount::try_new(buffer.active_count.load(Ordering::Acquire) as u32)?;
        let Ok(next) = active.next() else {
            return Ok(());
        };
        if let Lookup::Slot(_) = buffer.lookup(next)? {
            return Ok(());
        }
        let mut free = None;
        for slot in 0..buffer.slots {
            let found = Descriptor::decode(buffer.descriptor(slot)?.load(Ordering::Acquire))?;
            if found.state() == SlotState::Free {
                free = Some(slot);
                break;
            }
        }
        let Some(slot) = free else {
            report.lagging = true;
            return Ok(());
        };
        let term_id = buffer.initial_term_id.advanced_by(next);
        publish(
            buffer.descriptor(slot)?,
            Descriptor::new(term_id, buffer.generation, SlotState::Ready),
        );
        let entry = buffer.table_slot(next)?;
        let previous = entry.load(Ordering::Acquire);
        let _ = entry.compare_exchange(
            previous,
            table_entry(next.get(), slot),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        report.prepared = true;
        Ok(())
    }
}

fn corrupt(offset: u32, reason: &'static str) -> SysError {
    SysError::CorruptTerm { offset, reason }
}

/// The log buffer tests run on both backings.
#[cfg(test)]
mod heap_tests {
    use super::*;

    type Terms = HeapTerms;

    fn new_buffer(config: LogBufferConfig) -> Result<LogBuffer<Terms>, SysError> {
        LogBuffer::new(config)
    }

    include!("log_buffer_tests/common.rs");
}

#[cfg(test)]
mod shared_tests {
    use super::*;

    type Terms = SharedTerms;

    fn new_buffer(config: LogBufferConfig) -> Result<LogBuffer<Terms>, SysError> {
        LogBuffer::new_shared(config)
    }

    include!("log_buffer_tests/common.rs");

    /// A peer that keeps the access ABI (aligned `AtomicU64` stores) but not
    /// the protocol stores arbitrary values into the term a subscriber
    /// polls: every poll returns, with data, a protocol error or no data,
    /// and never panics or copies past its output.
    #[test]
    fn a_misbehaving_peer_cannot_make_the_reader_panic() {
        let buffer = new_buffer(config(3, 2)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut subscription = conductor.subscribe(Role::Optional).unwrap();
        let mut publication = buffer.publication().unwrap().unwrap();
        let _ = publication
            .append(&sized_message(1, 3000), AppendOptions::default())
            .unwrap();
        let term_words = (MIN_TERM_LENGTH / 8) as usize;
        let rounds: u32 = if cfg!(miri) { 40 } else { 20_000 };
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let words = buffer.regions.words();
                let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
                while !stop.load(Ordering::Relaxed) {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    // Mostly near the block start, sometimes a plausible
                    // word 0 with a random length and flags.
                    let index =
                        (state as usize >> 3) % if state & 1 == 0 { 512 } else { term_words };
                    let value = if state & 2 == 0 {
                        let flags = Flags::try_new((state >> 40) as u8).unwrap_or(Flags::NONE);
                        let length = ((state >> 8) as i32) % 9000;
                        Word0::new(length, flags, FrameType::Data).pack().to_le()
                    } else {
                        state
                    };
                    if let Some(word) = words.get(index) {
                        word.store(value, Ordering::Relaxed);
                    }
                }
            });
            let mut out = vec![0u8; 8192];
            for _ in 0..rounds {
                if let Ok(PollOutcome::Message { length, .. }) = subscription.poll(&mut out) {
                    assert!(length as usize <= out.len());
                }
            }
            stop.store(true, Ordering::Relaxed);
        });
    }
}
