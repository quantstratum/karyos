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
//! required subscribers and `rejoin_at_head` optional subscribers. Claims
//! on the exclusive publication follow `quantstratum-docs: karyos/design/claims.md`, without the
//! driver's commit-deadline abort. No concurrent publication, observers,
//! revocation policies or mapping generations. This low-level copy primitive also allows a publication with
//! no subscribers at all: the `NotConnected` / `allow_unconnected` connection
//! rules of SPEC.md §4 are left to a later, higher layer.

use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::error::{LayoutError, SysError};
use crate::frame::{
    EXTENSION_LENGTH, FRAME_ALIGNMENT, Flags, FrameType, HEADER_LENGTH, Lane, PROTOCOL_VERSION,
    Word0,
};
use crate::loan::{
    LoanOutcome, LoanTarget, activate, begin_cleaning, begin_reclaim, loan_held, publish,
    release_loan, take_loan,
};
use crate::publication::{
    abort_block, commit_block, deadline_abort, load_interior, mark_block, observe_block,
    publish_block, read_claim_record, store_interior, write_claim_record,
};
use crate::sizing::{FragmentPlan, TermLength, align_frame};
use crate::slot::{Descriptor, SlotIndex, SlotState};
use crate::term::{Generation, TermCount, TermId};
use crate::term_bytes::sealed::{Access as _, Token};
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
    /// Exclusive or concurrent publication, fixed for the buffer's life
    /// (`quantstratum-docs: karyos/design/concurrent-publication.md`).
    pub publication: PublicationMode,
    /// Commit deadline of claims, in ticks of the clock passed to
    /// [`Conductor::abort_expired_claims`] (nanoseconds by convention); at
    /// least 1 (`quantstratum-docs: karyos/design/claim-deadline.md`).
    pub claim_deadline: u64,
}

/// How a buffer is published to (`quantstratum-docs: karyos/design/concurrent-publication.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PublicationMode {
    /// One publication with a private cached tail (the latency path).
    #[default]
    Exclusive,
    /// Up to `publishers` concurrent handles reserving with one
    /// `fetch_add` on the active slot's raw tail.
    Concurrent {
        /// Concurrent handles at once (`P`), at least 1.
        publishers: u8,
        /// Allow concurrent mode on aarch64 without LSE, where `fetch_add`
        /// is not a single instruction (SPEC.md §4, ADR-0012).
        allow_non_lse: bool,
    },
}

/// A default commit deadline of claims: one second in nanoseconds.
pub const DEFAULT_CLAIM_DEADLINE: u64 = 1_000_000_000;

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
    /// The claim record and its seqlock serial
    /// (`quantstratum-docs: karyos/design/claim-deadline.md`).
    claim_record: AtomicU64,
    claim_serial: AtomicU64,
    /// Raw tail of each physical slot: `term_id << 32 | offset`
    /// (concurrent mode; initialised for every prepared term).
    tails: Box<[AtomicU64]>,
    /// Test hook: an injected deadline fault (feature `test-hooks`).
    #[cfg(feature = "test-hooks")]
    deadline_fault: AtomicBool,
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
        if config.claim_deadline == 0 {
            return Err(SysError::InvalidClaimDeadline {
                value: config.claim_deadline,
            });
        }
        check_publication_mode(&config)?;
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
        let publisher_cells = publisher_cells(config.publication);
        let cells: Box<[Cell]> = (0..usize::from(config.max_subscribers) + publisher_cells)
            .map(|index| {
                Cell::new(if index < publisher_cells {
                    CELL_PUBLICATION
                } else {
                    CELL_FREE
                })
            })
            .collect();
        let tails: Box<[AtomicU64]> = (0..slots)
            .map(|slot| {
                let term = match slot {
                    0 => t0,
                    _ => t0.advanced_by(one),
                };
                AtomicU64::new(u64::from(term.get()) << 32)
            })
            .collect();
        let window = window(&config);
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
            claim_record: AtomicU64::new(0),
            claim_serial: AtomicU64::new(0),
            tails,
            #[cfg(feature = "test-hooks")]
            deadline_fault: AtomicBool::new(false),
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
            .skip(self.first_subscriber_cell())
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

    /// Whether the buffer is published to concurrently.
    fn concurrent(&self) -> bool {
        matches!(self.config.publication, PublicationMode::Concurrent { .. })
    }

    /// The first registry cell of subscribers.
    fn first_subscriber_cell(&self) -> usize {
        publisher_cells(self.config.publication)
    }

    fn tail(&self, slot: u8) -> Result<&AtomicU64, SysError> {
        self.tails
            .get(usize::from(slot))
            .ok_or(SysError::ResourcesUnavailable)
    }

    /// The head (`quantstratum-docs: karyos/design/concurrent-publication.md`): the reserved
    /// head in exclusive mode; in concurrent mode one snapshot of the
    /// active count, its slot-table entry, its `ACTIVE` descriptor and the
    /// slot's raw tail, whose term id must match, clamped to the term end.
    /// `None` when the parts disagree (a slot reassigned while the caller
    /// paused): no head is fabricated.
    fn head(&self) -> Result<Option<u64>, SysError> {
        if !self.concurrent() {
            return Ok(Some(self.reserved_head.load(Ordering::Acquire)));
        }
        let count = TermCount::try_new(self.active_count.load(Ordering::Acquire) as u32)?;
        let Lookup::Slot(slot) = self.lookup(count)? else {
            return Ok(None);
        };
        let term_id = self.initial_term_id.advanced_by(count);
        let found = Descriptor::decode(self.descriptor(slot)?.load(Ordering::Acquire))?;
        if found.state() != SlotState::Active || found.term_id() != term_id {
            return Ok(None);
        }
        let raw = self.tail(slot)?.load(Ordering::Acquire);
        if (raw >> 32) as u32 != term_id.get() {
            return Ok(None);
        }
        let offset = (raw as u32).min(self.term_length);
        Ok(Some(self.position(count, offset)))
    }

    /// The head as the conductor sees it: it is the only party that
    /// reassigns slots, so a disagreeing snapshot is a protocol error.
    fn conductor_head(&self) -> Result<u64, SysError> {
        self.head()?.ok_or(SysError::CorruptTerm {
            offset: 0,
            reason: "head snapshot of mismatched identity",
        })
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

/// Registry cells reserved for publishers: 1 exclusive, `P` concurrent.
fn publisher_cells(mode: PublicationMode) -> usize {
    match mode {
        PublicationMode::Exclusive => 1,
        PublicationMode::Concurrent { publishers, .. } => usize::from(publishers),
    }
}

/// The publication window: `term_length / 2`, less the concurrent
/// overshoot `(P - 1) × max_reserved` (SPEC.md §4 IPC flow control).
fn window(config: &LogBufferConfig) -> u64 {
    let half = u64::from(config.term_length.get() / 2);
    match config.publication {
        PublicationMode::Exclusive => half,
        PublicationMode::Concurrent { publishers, .. } => {
            let overshoot =
                u64::from(publishers.saturating_sub(1)) * u64::from(config.max_reserved);
            // Creation checked `P × max_reserved ≤ term_length / 2`.
            half.max(overshoot) - overshoot
        }
    }
}

/// Creation checks of the publication mode
/// (`quantstratum-docs: karyos/design/concurrent-publication.md`).
fn check_publication_mode(config: &LogBufferConfig) -> Result<(), SysError> {
    check_publication_mode_on(config, single_instruction_fetch_add())
}

/// [`check_publication_mode`] for a target whose `fetch_add` is (`lse`) or
/// is not a single instruction.
fn check_publication_mode_on(config: &LogBufferConfig, lse: bool) -> Result<(), SysError> {
    let PublicationMode::Concurrent {
        publishers,
        allow_non_lse,
    } = config.publication
    else {
        return Ok(());
    };
    let invalid = |reason| Err(SysError::InvalidPublicationMode { reason });
    if publishers == 0 {
        return invalid("no concurrent publishers");
    }
    let term = u64::from(config.term_length.get());
    let spread = u64::from(publishers) * u64::from(config.max_reserved);
    if spread > term / 2 {
        return invalid("publishers × max_reserved exceeds term_length / 2");
    }
    if term + spread >= 1 << 31 {
        return invalid("term_length + publishers × max_reserved reaches 2^31");
    }
    if publishers > config.spare_slots.saturating_sub(CLEANING_HEADROOM) {
        return Err(SysError::ResourcesUnavailable);
    }
    if !allow_non_lse && !lse {
        return invalid("fetch_add is not a single instruction on this target (no LSE)");
    }
    Ok(())
}

/// Whether `fetch_add` on `AtomicU64` is one instruction: `LOCK XADD` on
/// x86_64, LSE `LDADDAL` on aarch64 (checked at run time).
fn single_instruction_fetch_add() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        true
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("lse")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Claim record layout (`quantstratum-docs: karyos/design/claim-deadline.md`): valid bit, slot,
/// term offset and extent in units of 32.
const RECORD_VALID: u64 = 1 << 55;
const RECORD_SLOT_SHIFT: u32 = 48;
const RECORD_OFFSET_SHIFT: u32 = 23;
const RECORD_FIELD_MASK_23: u64 = (1 << 23) - 1;
const RECORD_FIELD_MASK_25: u64 = (1 << 25) - 1;
/// Serial increments of one claim: set and clear, two each.
const CLAIM_SERIAL_COST: u64 = 4;

fn encode_record(slot: u8, offset: u32, extent: u32) -> u64 {
    RECORD_VALID
        | (u64::from(slot) << RECORD_SLOT_SHIFT)
        | (u64::from(offset / FRAME_ALIGNMENT) << RECORD_OFFSET_SHIFT)
        | u64::from(extent / FRAME_ALIGNMENT)
}

/// `(slot, offset, extent)` of a valid record.
fn decode_record(record: u64) -> Option<(u8, u32, u32)> {
    if record & RECORD_VALID == 0 {
        return None;
    }
    let slot = ((record >> RECORD_SLOT_SHIFT) & 0x7F) as u8;
    let offset = ((record >> RECORD_OFFSET_SHIFT) & RECORD_FIELD_MASK_25) as u32 * FRAME_ALIGNMENT;
    let extent = (record & RECORD_FIELD_MASK_23) as u32 * FRAME_ALIGNMENT;
    Some((slot, offset, extent))
}

impl<T: TermBytes> LogBuffer<T> {
    /// Rewrites the claim record; only the publication calls it.
    fn write_record(&self, value: u64) {
        write_claim_record(&self.claim_serial, &self.claim_record, value);
    }
}

#[cfg(feature = "test-hooks")]
impl<T: TermBytes> LogBuffer<T> {
    /// Test hook (feature `test-hooks`): makes every later deadline call of
    /// this buffer's conductor return an injected error before it reads the
    /// claim record or touches any word, without changing the protocol
    /// state. Only for tests of error handling in dependent crates.
    #[doc(hidden)]
    pub fn inject_deadline_fault(&self) {
        self.deadline_fault.store(true, Ordering::Relaxed);
    }
}

fn issue_publication<O: BufferOwner>(owner: O) -> Result<Option<Publication<O>>, SysError> {
    let buffer: &LogBuffer<O::Terms> = &owner;
    if buffer.concurrent() {
        return Err(SysError::InvalidPublicationMode {
            reason: "the exclusive publication of a concurrent buffer",
        });
    }
    // Already issued: no allocation. The compare-exchange below still
    // decides a race.
    if buffer.publication_taken.load(Ordering::Acquire) {
        return Ok(None);
    }
    // The staging buffer of claims on a backing without direct bytes, sized
    // for the largest admissible claim and allocated fallibly before the
    // publication is issued.
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
            pending: None,
            staging,
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
        observed: None,
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

/// The publication's record of its outstanding claim (claims.md,
/// forgotten claims): set when the claim marks its block, cleared when it
/// commits or aborts. A forgotten claim leaves it set.
#[derive(Debug, Clone, Copy)]
struct PendingClaim {
    /// The term the claim reserved in, under the standing write loan.
    count: TermCount,
    slot: u8,
    /// Term offset of the block.
    start: u32,
    position: u64,
    /// Payload length.
    length: u32,
    header_length: u32,
    /// The decision word's expected values.
    reserved: Word0,
    committed: Word0,
    aborted: Word0,
}

/// Result of [`Publication::try_claim`].
#[derive(Debug)]
#[must_use = "back pressure and admin actions must be handled"]
pub enum ClaimOutcome<'a, O: BufferOwner> {
    /// A block was reserved and marked; write the payload, then commit.
    Claimed(Claim<'a, O>),
    /// The flow-control limit does not admit the reservation; retry later.
    BackPressured,
    /// The call only padded or rotated, or rotation waits for the
    /// conductor; retry later.
    AdminAction,
    /// The block was aborted before it could be marked; nothing was
    /// written. Not produced while no other party aborts blocks.
    Aborted {
        /// Stream position of the block.
        position: u64,
    },
}

/// Result of [`Claim::commit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a commit can lose to an abort"]
pub enum CommitOutcome {
    /// The message was published at `position`.
    Committed {
        /// Stream position of the block.
        position: u64,
    },
    /// An abort won; readers skip the block.
    Aborted {
        /// Stream position of the block.
        position: u64,
    },
}

/// The buffer's only publication.
#[derive(Debug)]
pub struct Publication<O: BufferOwner> {
    buffer: O,
    state: PublicationState,
    pending: Option<PendingClaim>,
    /// Claim payload staging on backings without direct bytes.
    staging: Box<[u8]>,
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
    /// term would reach `2^31`. Nothing new is reserved or written on
    /// error; a forgotten claim is still resolved first.
    pub fn append(
        &mut self,
        payload: &[u8],
        options: AppendOptions,
    ) -> Result<AppendOutcome, SysError> {
        self.resolve_claim();
        PublicationContext {
            buffer: &self.buffer,
            state: &mut self.state,
        }
        .append(payload, options)
    }

    /// Claims one unfragmented block of `length` payload bytes (SPEC.md §4,
    /// claims; `quantstratum-docs: karyos/design/claims.md`). The returned [`Claim`] borrows the
    /// publication; its payload starts zeroed.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::EmptyMessage`], [`LayoutError::MessageTooLarge`]
    /// when `length` exceeds `max_message_length`, one fragment or
    /// `max_reserved`, and [`SysError::MaxPositionExceeded`] as
    /// [`Publication::append`]. Nothing is written on error, except the
    /// resolution of a forgotten claim.
    pub fn try_claim(
        &mut self,
        length: u32,
        options: AppendOptions,
    ) -> Result<ClaimOutcome<'_, O>, SysError> {
        self.resolve_claim();
        let step = PublicationContext {
            buffer: &self.buffer,
            state: &mut self.state,
        }
        .claim(length, options, &mut |_| {})?;
        self.finish_claim(step)
    }

    /// [`Publication::try_claim`] with `pause` called at the pause points
    /// of `quantstratum-docs: karyos/design/claim-deadline.md`: before the reserved head is
    /// published (not admitted) and before the mark (admitted).
    #[cfg(test)]
    fn try_claim_pausing(
        &mut self,
        length: u32,
        options: AppendOptions,
        pause: &mut dyn FnMut(ClaimPause),
    ) -> Result<ClaimOutcome<'_, O>, SysError> {
        self.resolve_claim();
        let step = PublicationContext {
            buffer: &self.buffer,
            state: &mut self.state,
        }
        .claim(length, options, pause)?;
        self.finish_claim(step)
    }

    fn finish_claim(&mut self, step: ClaimStep) -> Result<ClaimOutcome<'_, O>, SysError> {
        match step {
            ClaimStep::Marked(pending) => {
                if let Some(staging) = self.staging.get_mut(..pending.length as usize) {
                    staging.fill(0);
                }
                self.pending = Some(pending);
                Ok(ClaimOutcome::Claimed(Claim { publication: self }))
            }
            ClaimStep::Outcome(AppendOutcome::BackPressured) => Ok(ClaimOutcome::BackPressured),
            ClaimStep::Outcome(_) => Ok(ClaimOutcome::AdminAction),
            ClaimStep::Aborted { position } => Ok(ClaimOutcome::Aborted { position }),
        }
    }

    /// Closes the publication: aborts a forgotten claim first, then releases
    /// the standing write loan, as dropping it does. The publication is
    /// issued once: closing does not let the buffer issue another.
    pub fn close(self) {}

    /// Resolves a forgotten claim: aborts its decision word unless it is
    /// already terminal and clears its record. Every mutable operation of
    /// the publication (`append`, `try_claim`, `close`) and its drop do
    /// this first; a wrapper whose mutable operation may return early
    /// without calling into the publication calls it itself
    /// (`quantstratum-docs: karyos/design/client-claims.md`). A no-op without a forgotten claim.
    pub fn resolve_forgotten_claim(&mut self) {
        self.resolve_claim();
    }

    /// Aborts the outstanding claim, if any, and clears its record. Called
    /// only where no reference into the block can remain: by the next call
    /// on the publication (the claim borrowed it mutably), by `Drop` of the
    /// claim or of the publication.
    fn resolve_claim(&mut self) {
        let Some(claim) = self.pending.take() else {
            return;
        };
        debug_assert!(matches!(
            self.state,
            PublicationState::Active { count, slot, .. }
                if count == claim.count && slot == claim.slot
        ));
        // SAFETY: the standing write loan on the claim's term is still
        // held: no call rotated while the claim was recorded. `start` is
        // the block's first frame start.
        let word = unsafe { self.buffer.regions.word0(claim.slot, claim.start) };
        // Losing means the block is already terminal.
        let _ = abort_block(word, claim.reserved, claim.aborted);
        // Terminal: the record may go, before any loan release.
        self.buffer.write_record(0);
    }
}

impl<O: BufferOwner> Drop for Publication<O> {
    fn drop(&mut self) {
        // A claim's accesses have ended: it borrowed the publication, which
        // is being dropped. Resolve it, then release the loan.
        self.resolve_claim();
        if let PublicationState::Active { .. } = self.state
            && let Ok(cell) = self.buffer.cell(0)
        {
            // The last access of the publication to its term.
            release_loan(&cell.loan);
        }
    }
}

/// A claimed block (SPEC.md §4, claims). It mutably borrows its
/// publication; [`Claim::commit`] publishes it, and [`Claim::abort`] or
/// dropping it uncommitted aborts it. A claim forgotten with
/// `mem::forget` is aborted by the publication's next call, `close` or
/// drop.
///
/// The payload cannot outlive the claim:
///
/// ```compile_fail,E0597
/// # use karyos_sys::log_buffer::*;
/// fn escape<O: BufferOwner + core::fmt::Debug>(publication: &mut Publication<O>) {
///     let payload;
///     {
///         let Ok(ClaimOutcome::Claimed(mut claim)) =
///             publication.try_claim(8, AppendOptions::default())
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
/// fn after_commit<O: BufferOwner>(mut claim: Claim<'_, O>) {
///     let payload = claim.payload();
///     let _ = claim.commit();
///     payload[0] = 1;
/// }
/// ```
#[derive(Debug)]
pub struct Claim<'a, O: BufferOwner> {
    publication: &'a mut Publication<O>,
}

impl<O: BufferOwner> Claim<'_, O> {
    /// Stream position of the block.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.publication.pending.map_or(0, |claim| claim.position)
    }

    /// The payload: exactly the claimed length, zeroed at claim time. On
    /// [`HeapTerms`] it is the block's payload range in the term; on
    /// [`SharedTerms`] a staging buffer copied in at commit.
    pub fn payload(&mut self) -> &mut [u8] {
        let publication = &mut *self.publication;
        let Some(claim) = publication.pending else {
            return &mut [];
        };
        // SAFETY: the claim marked the block under the standing write loan,
        // which stays held while the claim exists (a borrow of `self`); the
        // range is the frame's payload, after the header and extension and
        // before the alignment padding, so it holds no control word; readers
        // do not access a block whose word 0 is negative, and nothing else
        // writes it while the publication is mutably borrowed.
        let direct = unsafe {
            publication.buffer.regions.direct_bytes(
                claim.slot,
                claim.start + claim.header_length,
                claim.length,
            )
        };
        match direct {
            // SAFETY: as above; the slice borrows `self` mutably, so it ends
            // before commit, abort or drop.
            Some(pointer) => unsafe {
                core::slice::from_raw_parts_mut(pointer.as_ptr(), claim.length as usize)
            },
            None => publication
                .staging
                .get_mut(..claim.length as usize)
                .unwrap_or_default(),
        }
    }

    /// Commits the block: exactly one of commit and abort wins.
    pub fn commit(self) -> CommitOutcome {
        let publication = &mut *self.publication;
        let Some(claim) = publication.pending.take() else {
            return CommitOutcome::Aborted { position: 0 };
        };
        let buffer = &*publication.buffer;
        if let Some(staging) = publication.staging.get(..claim.length as usize)
            && !<O::Terms as crate::term_bytes::sealed::Access>::DIRECT
        {
            // SAFETY: write loan held; the payload range of the marked,
            // unpublished frame; the bytes up to the next word already read
            // as zero (cleaned slot).
            unsafe {
                buffer
                    .regions
                    .write_bytes(claim.slot, claim.start + claim.header_length, staging)
            };
        }
        // SAFETY: write loan held; the block's first frame start.
        let word = unsafe { buffer.regions.word0(claim.slot, claim.start) };
        let committed = commit_block(word, claim.reserved, claim.committed);
        // Terminal: the record stayed eligible through the staging copy.
        buffer.write_record(0);
        if committed {
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

impl<O: BufferOwner> Drop for Claim<'_, O> {
    fn drop(&mut self) {
        self.publication.resolve_claim();
    }
}

/// Pause points of a claim, for tests of the deadline abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimPause {
    /// The record is set; the head store has not admitted the claim.
    BeforeHead,
    /// Admitted; the mark has not been attempted.
    BeforeMark,
}

enum ClaimStep {
    Marked(PendingClaim),
    Outcome(AppendOutcome),
    Aborted { position: u64 },
}

enum Reservation {
    Reserved {
        count: TermCount,
        slot: u8,
        tail: u32,
        position: u64,
    },
    Outcome(AppendOutcome),
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
        match self.reserve(reserved, None)? {
            Reservation::Outcome(outcome) => Ok(outcome),
            Reservation::Reserved {
                count,
                slot,
                tail,
                position,
            } => {
                self.write_block(slot, count, tail, payload, &plan, options);
                Ok(AppendOutcome::Appended { position })
            }
        }
    }

    /// Checks and marks a claim (claims.md, the claim).
    fn claim(
        &mut self,
        length: u32,
        options: AppendOptions,
        pause: &mut dyn FnMut(ClaimPause),
    ) -> Result<ClaimStep, SysError> {
        if length == 0 {
            return Err(SysError::EmptyMessage);
        }
        let buffer = self.buffer;
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
        // Both record rewrites of this claim must fit the serial.
        if buffer.claim_serial.load(Ordering::Relaxed) > u64::MAX - CLAIM_SERIAL_COST {
            return Err(SysError::ResourcesUnavailable);
        }
        let (count, slot, tail, position) = match self.reserve(reserved, Some(pause))? {
            Reservation::Outcome(outcome) => return Ok(ClaimStep::Outcome(outcome)),
            Reservation::Reserved {
                count,
                slot,
                tail,
                position,
            } => (count, slot, tail, position),
        };
        let header_length = flags.header_length();
        let reserved_word = Word0::new(-(reserved as i32), flags, FrameType::Data);
        // SAFETY: the standing write loan on `count` in `slot` is held;
        // `tail` is the reserved block's first frame start.
        let word = unsafe { buffer.regions.word0(slot, tail) };
        pause(ClaimPause::BeforeMark);
        if !mark_block(word, reserved_word) {
            // The deadline abort won before the mark: nothing was written.
            buffer.write_record(0);
            return Ok(ClaimStep::Aborted { position });
        }
        // Marked: only now write the rest of the header.
        self.write_header_tail(slot, count, tail, options.reserved_value);
        if let Some(extension) = &options.extension {
            // SAFETY: write loan held; the extension follows the header of
            // the marked, unpublished frame; not a word 0.
            unsafe {
                buffer
                    .regions
                    .write_bytes(slot, tail + HEADER_LENGTH, extension)
            };
        }
        Ok(ClaimStep::Marked(PendingClaim {
            count,
            slot,
            start: tail,
            position,
            length,
            header_length,
            reserved: reserved_word,
            committed: Word0::new((header_length + length) as i32, flags, FrameType::Data),
            aborted: Word0::new(
                reserved as i32,
                Flags::new(false, false, false, false, lane),
                FrameType::Aborted,
            ),
        }))
    }

    /// Reserves `reserved` bytes at the tail, once: publishes the reserved
    /// head and advances the cached tail past the block. Without room it
    /// pads and rotates, and without credit it reports back pressure.
    /// A claim passes `announce`: its record is set once the reservation is
    /// decided and before the head store that admits it.
    fn reserve(
        &mut self,
        reserved: u32,
        announce: Option<&mut dyn FnMut(ClaimPause)>,
    ) -> Result<Reservation, SysError> {
        let buffer = self.buffer;
        if let PublicationState::Rotating { next } = *self.state {
            return Ok(Reservation::Outcome(self.rotate(next)?));
        }
        let PublicationState::Active { count, slot, tail } = *self.state else {
            return Ok(Reservation::Outcome(AppendOutcome::AdminAction));
        };
        let limit = buffer.limit.load(Ordering::Acquire);
        let remaining = buffer.term_length - tail;
        if reserved > remaining {
            // Reserve only the PAD up to the term boundary.
            let boundary = buffer.position(count, buffer.term_length);
            if boundary > limit {
                return Ok(Reservation::Outcome(AppendOutcome::BackPressured));
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
            return Ok(Reservation::Outcome(AppendOutcome::AdminAction));
        }
        let start = buffer.position(count, tail);
        let end = start + u64::from(reserved);
        if end > limit {
            return Ok(Reservation::Outcome(AppendOutcome::BackPressured));
        }
        if let Some(pause) = announce {
            // The claim's intent; the head store below admits it.
            buffer.write_record(encode_record(slot, tail, reserved));
            pause(ClaimPause::BeforeHead);
        }
        buffer.reserved_head.store(end, Ordering::Release);
        *self.state = PublicationState::Active {
            count,
            slot,
            tail: tail + reserved,
        };
        Ok(Reservation::Reserved {
            count,
            slot,
            tail,
            position: start,
        })
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
    /// An aborted block was skipped: only its word 0 was read. Its extent
    /// carries no message and needs no acknowledgement.
    Aborted {
        /// Stream position of the block.
        position: u64,
        /// Bytes skipped.
        extent: u32,
    },
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
            Read::Aborted { extent } => {
                let position = self.cursor.position;
                self.advance_to(position + u64::from(extent));
                Ok(Step::Done(PollOutcome::Aborted { position, extent }))
            }
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
            Validated::Aborted { extent } => Ok(Read::Aborted { extent }),
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
            Ok(FrameType::Aborted) => {
                // Only word 0 of an aborted block is read.
                let extent = signed as u32;
                if word0.flags().lane() != buffer.config.lane {
                    return Err(corrupt(start, "aborted lane"));
                }
                if !extent.is_multiple_of(FRAME_ALIGNMENT) || extent > term_length - start {
                    return Err(corrupt(start, "aborted extent"));
                }
                return Ok(Validated::Aborted { extent });
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
        self.overrun_with(&mut || {})
    }

    /// [`SubscriptionContext::overrun`] with `between` run between the
    /// floor and head reads (tests reproduce a pause there).
    fn overrun_with(&mut self, between: &mut dyn FnMut()) -> Result<Step, SysError> {
        if self.cursor.role == Role::Required {
            return Err(SysError::RequiredSubscriberLapped {
                position: self.cursor.position,
            });
        }
        let from = self.cursor.position;
        // The floor first: the head read after it is at or above it (the
        // conductor publishes a floor only from an earlier head snapshot).
        let lost_to = self.buffer.floor.load(Ordering::Acquire).max(from);
        between();
        let Some(head) = self.buffer.head()? else {
            // No consistent head now: retry later instead of rejoining.
            return Ok(Step::Done(PollOutcome::Pending));
        };
        if head < lost_to {
            // Never resume inside the range just reported lost.
            return Ok(Step::Done(PollOutcome::Pending));
        }
        let resume = head.max(from);
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
    Aborted { extent: u32 },
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
    Aborted {
        extent: u32,
    },
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
    /// The claim being timed: `(serial, first_seen)`.
    observed: Option<(u64, u64)>,
}

/// What [`Conductor::abort_expired_claims`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ClaimDeadline {
    /// No admitted claim.
    Idle,
    /// An admitted claim whose deadline has not passed.
    Waiting,
    /// The clock went back below the claim's first observation; its timer
    /// was re-anchored.
    ClockWentBack,
    /// The expiry instant `first_seen + claim_deadline` does not fit `u64`:
    /// no representable `now` reaches it.
    Unrepresentable,
    /// This call aborted the claim.
    Aborted {
        /// Stream position of the block.
        position: u64,
        /// Bytes aborted.
        extent: u32,
    },
    /// The expired claim was already terminal.
    Resolved,
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

    /// The commit-deadline abort of claims (`quantstratum-docs: karyos/design/claim-deadline.md`):
    /// times the admitted claim named by the claim record from its first
    /// observation, with `now` from a monotonic clock in the unit of
    /// `claim_deadline`, and aborts it once expired, touching only its first
    /// word 0.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::CorruptTerm`] for a record outside the term and
    /// errors from the descriptor protocol.
    pub fn abort_expired_claims(&mut self, now: u64) -> Result<ClaimDeadline, SysError> {
        self.abort_expired_claims_with(&mut || now)
    }

    /// [`Conductor::abort_expired_claims`] reading the time from `clock`
    /// only after the claim record and the reserved head show an admitted
    /// claim, so its first observation is dated at or after its admission
    /// (`quantstratum-docs: karyos/design/client-claims.md`). The clock is not called otherwise.
    ///
    /// # Errors
    ///
    /// As [`Conductor::abort_expired_claims`].
    pub fn abort_expired_claims_with(
        &mut self,
        clock: &mut dyn FnMut() -> u64,
    ) -> Result<ClaimDeadline, SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        #[cfg(feature = "test-hooks")]
        if buffer.deadline_fault.load(Ordering::Relaxed) {
            return Err(SysError::ResourcesUnavailable);
        }
        // The claim record has a single writer, the exclusive publication;
        // concurrent buffers have no deadline abort yet
        // (`quantstratum-docs: karyos/design/concurrent-publication.md`, batch c).
        if buffer.concurrent() {
            self.observed = None;
            return Ok(ClaimDeadline::Idle);
        }
        let Some((serial, record)) = read_claim_record(&buffer.claim_serial, &buffer.claim_record)
        else {
            self.observed = None;
            return Ok(ClaimDeadline::Idle);
        };
        let Some((slot, offset, extent)) = decode_record(record) else {
            self.observed = None;
            return Ok(ClaimDeadline::Idle);
        };
        if slot >= buffer.slots
            || extent == 0
            || u64::from(offset) + u64::from(extent) > u64::from(buffer.term_length)
        {
            return Err(corrupt(offset, "claim record"));
        }
        let found = Descriptor::decode(buffer.descriptor(slot)?.load(Ordering::Acquire))?;
        if !matches!(found.state(), SlotState::Active | SlotState::Reclaiming) {
            self.observed = None;
            return Ok(ClaimDeadline::Idle);
        }
        let count = found.term_id().count_from(buffer.initial_term_id)?;
        let position = buffer.position(count, offset);
        // Admission: the reserved head covers the block.
        if buffer.conductor_head()? < position + u64::from(extent) {
            self.observed = None;
            return Ok(ClaimDeadline::Idle);
        }
        // Admitted: only now is the time read.
        let now = clock();
        let first_seen = match self.observed {
            Some((seen, first_seen)) if seen == serial => first_seen,
            _ => {
                self.observed = Some((serial, now));
                now
            }
        };
        if now < first_seen {
            self.observed = Some((serial, now));
            return Ok(ClaimDeadline::ClockWentBack);
        }
        let Some(expiry) = first_seen.checked_add(buffer.config.claim_deadline) else {
            return Ok(ClaimDeadline::Unrepresentable);
        };
        if now < expiry {
            return Ok(ClaimDeadline::Waiting);
        }
        let lane = buffer.config.lane;
        let aborted = Word0::new(
            extent as i32,
            Flags::new(false, false, false, false, lane),
            FrameType::Aborted,
        );
        // SAFETY: the location is the first word 0 of the admitted claim's
        // block in `slot`, a frame start accessed only atomically during
        // this term incarnation. Only this conductor cleans or reassigns
        // slots, never during this call, and the record names this term:
        // the publication clears it before releasing its write loan, and
        // the reclaim scan that precedes any cleaning observed that release
        // (quantstratum-docs: karyos/design/claim-deadline.md).
        let word = unsafe { buffer.regions.word0(slot, offset) };
        if deadline_abort(word, extent, lane, aborted) {
            Ok(ClaimDeadline::Aborted { position, extent })
        } else {
            Ok(ClaimDeadline::Resolved)
        }
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
        for (index, cell) in buffer
            .cells
            .iter()
            .enumerate()
            .skip(buffer.first_subscriber_cell())
        {
            match cell.state.load(Ordering::Acquire) {
                CELL_OPTIONAL => optional += 1,
                CELL_FREE if free.is_none() => free = Some(index),
                _ => {}
            }
        }
        // Publisher credits are reserved for the buffer's life: 1 for the
        // exclusive publication, `P` for concurrent ones.
        let publishers = buffer.first_subscriber_cell() as u32;
        let credits = optional + publishers + u32::from(role == Role::Optional);
        if credits > u32::from(buffer.spare_slots - CLEANING_HEADROOM) {
            return Err(SysError::ResourcesUnavailable);
        }
        let index = free.ok_or(SysError::ResourcesUnavailable)?;
        let cell = buffer.cell(index)?;
        // The Acquire load above observed the previous holder's FREE, so its
        // loan release happens before this reuse; its loan word is zero.
        debug_assert_eq!(cell.loan.load(Ordering::Relaxed), 0);
        cell.revoked.store(0, Ordering::Relaxed);
        let start = buffer.conductor_head()?;
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
        self.publish_floor_and_limit()?;
        self.help_rotation()?;
        self.reclaim(&mut report)?;
        self.prepare_next(&mut report)?;
        Ok(report)
    }

    /// Floor and limit from one head snapshot; the floor is published first.
    fn publish_floor_and_limit(&self) -> Result<(), SysError> {
        let buffer = self.buffer;
        let window = window(&buffer.config);
        let head = buffer.conductor_head()?;
        let mut bound = None::<u64>;
        for cell in buffer.cells.iter().skip(buffer.first_subscriber_cell()) {
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
        Ok(())
    }

    /// Completes a full term's rotation the publication left half-done.
    fn help_rotation(&self) -> Result<(), SysError> {
        let buffer = self.buffer;
        let active = TermCount::try_new(buffer.active_count.load(Ordering::Acquire) as u32)?;
        let boundary = buffer.position(active, buffer.term_length);
        if buffer.conductor_head()? < boundary {
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
        // The slot is FREE: no loan, no producer. Its tail is ready before
        // the READY publication below (Release) makes the term reachable.
        buffer
            .tail(slot)?
            .store(u64::from(term_id.get()) << 32, Ordering::Relaxed);
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
        let mutations = AtomicU64::new(0);
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
                        mutations.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
            // Stops the writer however the reader ends, so a reader panic
            // fails the test instead of hanging it in the scope's join.
            struct StopOnDrop<'a>(&'a AtomicBool);
            impl Drop for StopOnDrop<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Relaxed);
                }
            }
            let _stop = StopOnDrop(&stop);
            // The peer has really stored before polling starts, and keeps
            // storing while it runs.
            while mutations.load(Ordering::Relaxed) == 0 {
                std::thread::yield_now();
            }
            let started = mutations.load(Ordering::Relaxed);
            let mut out = vec![0u8; 8192];
            for _ in 0..rounds {
                if let Ok(PollOutcome::Message { length, .. }) = subscription.poll(&mut out) {
                    assert!(length as usize <= out.len());
                }
            }
            while mutations.load(Ordering::Relaxed) == started {
                std::thread::yield_now();
            }
        });
    }
}
