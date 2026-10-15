// SPDX-License-Identifier: Apache-2.0

//! Log buffer for one lane (SPEC.md §4; design in quantstratum-docs:
//! `karyos/design/embedded-log-buffer.md` and the documents named below).
//!
//! `LogBuffer` owns `3 + S` term slots, their descriptors, a slot table, the
//! active term count, a registry of loan cells and the published reserved
//! head, limit and floor. Its shared words live in one backing
//! (quantstratum-docs: karyos/`design/ipc-log-buffer.md`): heap memory of this process, or a
//! shared region that a driver creates (`LogBuffer::create_in`, Linux) and a
//! participant in another process attaches to (`LogBuffer::attach`).
//! Capabilities that act on it:
//!
//! - [`Publication`], the exclusive publication, issued once, appends and
//!   claims under a standing write loan and rotates through a recoverable
//!   no-loan state (quantstratum-docs: karyos/`design/claims.md`);
//! - [`ConcurrentPublication`], one per publisher slot of a concurrent
//!   buffer, reserves with `fetch_add` on the active tail
//!   (quantstratum-docs: karyos/`design/concurrent-publication.md`);
//! - [`Subscription`], one per registry cell, copies messages out under a
//!   read loan held through the last byte;
//! - [`Conductor`], issued once per buffer, serialises admission, flow
//!   control, retention, rotation help, reclamation, cleaning, preparation
//!   and the claim deadlines through `&mut self`.
//!
//! A participant in another process does not register itself: the driver
//! registers it and the participant adopts that grant once
//! ([`Subscription::adopt`], [`Publication::adopt`],
//! [`ConcurrentPublication::adopt`]). A buffer belongs to one mapping
//! generation; sealing and fencing it hand its streams over to a successor
//! (quantstratum-docs: karyos/`design/mapping-generations.md`).
//!
//! Scope: one lane, copy delivery, `hold` required subscribers and
//! `rejoin_at_head` optional subscribers. Not yet: observers, the
//! `continue` and `abort` loss policies with revocation, and the
//! `snapshot`, `close` and `replay` rejoin policies. This primitive also
//! allows a publication with no subscribers at all; the `NotConnected` /
//! `allow_unconnected` rules of SPEC.md §4 belong to the client layer
//! (quantstratum-docs: karyos/`design/embedded-api.md`).

use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::atomic_view::HeapWords;
use crate::error::{LayoutError, SysError};
use crate::frame::{
    EXTENSION_LENGTH, FRAME_ALIGNMENT, Flags, FrameType, HEADER_LENGTH, Lane, PROTOCOL_VERSION,
    Word0,
};
use crate::loan::{
    Loan, LoanOutcome, LoanTarget, activate, begin_cleaning, begin_reclaim, loan_held,
    participant_quiescent, publish, release_loan, revoke, take_loan,
};
use crate::publication::{
    SEAL_POSITIONED, SEAL_SEALED, abort_block, active_term_count, commit_block, deadline_abort,
    fence_rotation, fence_tail, invalidate_claim_record, issuer_sees_seal, load_interior,
    mark_block, observe_block, observe_seal, position_seal, publication_released,
    publication_taken, publish_block, read_claim_record, release_publication,
    release_publisher_slot, seal, store_interior, take_publication, write_claim_record,
};
use crate::registration::{self, claim, valid_export};
use crate::sizing::{FragmentPlan, TermLength, align_frame};
use crate::slot::{Descriptor, SlotIndex, SlotState};
use crate::term::{Generation, TermCount, TermId};
use crate::term_bytes::sealed::{Access as _, Token};
use crate::term_bytes::{HeapTerms, SharedTerms, TermBytes};
use core::ptr::NonNull;
use storage::{Backing, CONFIG_WORDS, Cell, Control, Layout, Line, PublisherSlot};

mod concurrent;
mod deadline;
mod image_read;
mod receive_owner;

pub use receive_owner::{ReceiveCounter, ReceiveCounters, ReceiveError, ReceiveOwner, Received};
pub(crate) mod storage;

#[cfg(test)]
use crate::loan::{Rotation, rotate_to};

pub use concurrent::{
    ConcurrentClaim, ConcurrentClaimOutcome, ConcurrentOfferOutcome, ConcurrentPublication,
    PreparedConcurrentPublication,
};

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
/// A required reader admitted under `continue`: it bounds the publisher
/// and holds a spare-slot credit (quantstratum-docs: `karyos/design/required-participant-loss.md`).
const CELL_REQUIRED_RESERVED: u64 = 4;
/// A revoked required reader under `hold`: it still bounds the publisher
/// until a scan after the revocation finds its loan word empty.
const CELL_LOST_HOLDING: u64 = 5;
/// A revoked reader that no longer bounds and holds no credit.
const CELL_LOST: u64 = 6;
/// A revoked reader that keeps its credit until it is freed.
const CELL_LOST_RESERVED: u64 = 7;

/// Whether a subscriber cell in `state` bounds the publication limit.
const fn bounds(state: u64) -> bool {
    matches!(
        state,
        CELL_REQUIRED | CELL_REQUIRED_RESERVED | CELL_LOST_HOLDING
    )
}

/// Whether a subscriber cell in `state` keeps the publication connected.
const fn connected(state: u64) -> bool {
    matches!(
        state,
        CELL_REQUIRED | CELL_REQUIRED_RESERVED | CELL_OPTIONAL
    )
}

/// Whether a subscriber cell in `state` holds a spare-slot credit.
const fn holds_credit(state: u64) -> bool {
    matches!(
        state,
        CELL_OPTIONAL | CELL_REQUIRED_RESERVED | CELL_LOST_RESERVED
    )
}

/// The seal position bits of the seal word (`quantstratum-docs: karyos/design/publication-seal.md`):
/// `0` while active, `SEAL_SEALED` once sealed, and `SEAL_SEALED |
/// SEAL_POSITIONED | position` once the seal position is known.
const SEAL_POSITION: u64 = SEAL_POSITIONED - 1;

/// A subscriber's role (SPEC.md §4 reader roles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Bounds the publisher; never lapped (`hold` policy).
    Required,
    /// Does not bound the publisher; lapped readers rejoin at the head.
    Optional,
}

/// What the conductor does with a required participant whose client was
/// lost (SPEC.md §4 `on_required_loss`;
/// quantstratum-docs: `karyos/design/required-participant-loss.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LossPolicy {
    /// The revoked reader keeps bounding the publisher until a scan after
    /// the revocation finds its loan word empty.
    #[default]
    Hold,
    /// The bound is withdrawn at once; the reader was admitted with a
    /// reservation, which a held loan stays inside.
    Continue,
    /// The publication is sealed.
    Abort,
}

/// What [`Conductor::revoke_participant`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// The cell holds another occupant, or is free: nothing was done.
    Stale,
    /// Revoked under `hold`; it still bounds the publisher while its loan
    /// word is held.
    Holding,
    /// Revoked; it no longer bounds the publisher.
    Withdrawn,
    /// Revoked under `abort`, and the buffer is sealed.
    Sealed,
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
    /// An image: the lane of a remote stream written only by its receive
    /// owner (`quantstratum-docs: karyos/design/receive-publication.md`).
    /// It issues no publication. Its head is the owner's rebuild position,
    /// which starts at `join`, the join point of the image.
    Image {
        /// The join point: the stream position where the image starts.
        join: u64,
    },
}

/// A default commit deadline of claims: one second in nanoseconds.
pub const DEFAULT_CLAIM_DEADLINE: u64 = 1_000_000_000;

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
    /// Section pointers into `backing`, checked at construction
    /// (`quantstratum-docs: karyos/design/ipc-log-buffer.md`). Declared before `backing` so that
    /// nothing derived from it outlives it.
    control: NonNull<Control>,
    descriptors: NonNull<[Line]>,
    table: NonNull<[AtomicU64]>,
    tails: NonNull<[Line]>,
    cells: NonNull<[Cell]>,
    publishers: NonNull<[PublisherSlot]>,
    /// Every word more than one party touches: heap words of this process
    /// or a shared region.
    backing: Arc<Backing>,
    layout: Layout,
    /// Local: only the creator issues the conductor.
    conductor_taken: AtomicBool,
    /// Test hook: an injected deadline fault (feature `test-hooks`).
    #[cfg(feature = "test-hooks")]
    deadline_fault: AtomicBool,
}

// SAFETY: the section pointers point into `backing`, an `Arc` the buffer
// holds for its whole life; they are only turned into shared references to
// overlays made of `AtomicU64` (`Sync`) by accessors borrowing `self`. The
// other fields are `Send` and `Sync` when `T` is.
unsafe impl<T: TermBytes> Send for LogBuffer<T> {}
// SAFETY: see the `Send` impl.
unsafe impl<T: TermBytes> Sync for LogBuffer<T> {}

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
        Self::build(config, Generation::default())
    }

    /// As [`LogBuffer::new`], for mapping generation `generation`
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`): its descriptors and loans
    /// carry it, so they never validate against another generation's.
    ///
    /// # Errors
    ///
    /// As [`LogBuffer::new`].
    pub fn new_with_generation(
        config: LogBufferConfig,
        generation: Generation,
    ) -> Result<Self, SysError> {
        Self::build(config, generation)
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
        Self::build(config, Generation::default())
    }

    /// As [`LogBuffer::new_shared`], for mapping generation `generation`.
    ///
    /// # Errors
    ///
    /// As [`LogBuffer::new`].
    pub fn new_shared_with_generation(
        config: LogBufferConfig,
        generation: Generation,
    ) -> Result<Self, SysError> {
        Self::build(config, generation)
    }
}

#[cfg(target_os = "linux")]
impl LogBuffer<SharedTerms> {
    /// Creates a buffer in a new shared region (driver side,
    /// `quantstratum-docs: karyos/design/ipc-log-buffer.md`): the region is created and
    /// size-sealed for this layout, then initialised. Its descriptor is
    /// passed to participants through [`LogBuffer::region`].
    ///
    /// # Errors
    ///
    /// As [`LogBuffer::new`], and the errors of [`crate::ipc::Region::create`].
    pub fn create_in(
        instance: u128,
        region: u64,
        config: LogBufferConfig,
        generation: Generation,
    ) -> Result<Self, SysError> {
        let (layout, slots, max_message_length) = Self::plan(&config)?;
        let structure_length = layout
            .total
            .checked_mul(crate::atomic_view::WORD_BYTES)
            .ok_or(SysError::InvalidRegion { address: 0, len: 0 })?;
        let mapped = crate::ipc::Region::create(crate::ipc::RegionRecord {
            instance,
            region,
            kind: crate::ipc::RegionKind::LogBuffer,
            generation: u64::from(generation.get()),
            layout: LAYOUT_VERSION,
            structure_length,
        })?;
        let backing = Arc::new(Backing::Region(mapped));
        let buffer = Self::over(
            backing,
            layout,
            config,
            generation,
            slots,
            max_message_length,
        )?;
        buffer.initialise();
        Ok(buffer)
    }

    /// Attaches to a buffer in an attached region (participant side). The
    /// configuration block is read once and validated as
    /// [`LogBuffer::new`] validates a configuration; the layout it implies
    /// must fill the region exactly, and its generation and layout version
    /// must match the region's. Every later index comes from this validated
    /// copy. The attached buffer never issues a conductor.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] for a region that is not a log
    /// buffer region, a configuration block that is not valid or does not
    /// match the region, and the validation errors of [`LogBuffer::new`].
    pub fn attach(region: crate::ipc::Region) -> Result<Self, SysError> {
        let record = region.record();
        let invalid = SysError::InvalidRegion {
            address: 0,
            len: record.structure_length,
        };
        // The header matched the caller's record, which may name any kind:
        // only a log buffer region holds this layout.
        if record.kind != crate::ipc::RegionKind::LogBuffer {
            return Err(invalid);
        }
        let structure = region.structure();
        let mut words = [0u64; CONFIG_WORDS];
        for (index, word) in words.iter_mut().enumerate() {
            *word = structure.get(index).ok_or(invalid)?.load(Ordering::Acquire);
        }
        let (config, generation, max_message_length) = parse_config(&words).ok_or(invalid)?;
        let (layout, slots, expected_max) = Self::plan(&config)?;
        let structure_length = layout.total.checked_mul(crate::atomic_view::WORD_BYTES);
        if record.layout != LAYOUT_VERSION
            || record.generation != u64::from(generation.get())
            || structure_length != Some(record.structure_length)
            || max_message_length != expected_max
        {
            return Err(invalid);
        }
        let backing = Arc::new(Backing::Region(region));
        let buffer = Self::over(
            backing,
            layout,
            config,
            generation,
            slots,
            max_message_length,
        )?;
        buffer.conductor_taken.store(true, Ordering::Relaxed);
        Ok(buffer)
    }

    /// The region of a buffer created in or attached to one: its record and,
    /// for the creator, the descriptor to pass.
    #[must_use]
    pub fn region(&self) -> Option<&crate::ipc::Region> {
        match &*self.backing {
            Backing::Region(region) => Some(region),
            Backing::Heap(_) => None,
        }
    }
}

impl<T: TermBytes> LogBuffer<T> {
    fn build(config: LogBufferConfig, generation: Generation) -> Result<Self, SysError> {
        let (layout, slots, max_message_length) = Self::plan(&config)?;
        let backing = Arc::new(Backing::Heap(HeapWords::zeroed(layout.total)?));
        let buffer = Self::over(
            backing,
            layout,
            config,
            generation,
            slots,
            max_message_length,
        )?;
        buffer.initialise();
        Ok(buffer)
    }

    /// Validates `config` and computes its layout, slot count and largest
    /// message: the same checks for a new buffer and for an attachment.
    fn plan(config: &LogBufferConfig) -> Result<(Layout, u8, u32), SysError> {
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
        check_publication_mode(config)?;
        let plan = FragmentPlan::new(config.mtu, Flags::NONE)?;
        let max_message_length =
            plan.max_message_length(config.max_reserved, config.term_length)?;
        let publisher_cells = publisher_cells(config.publication);
        let layout = Layout::new(
            slots,
            usize::from(config.max_subscribers) + publisher_cells,
            publisher_cells,
            config.term_length.get(),
            T::IN_BACKING,
        )?;
        Ok((layout, slots, max_message_length))
    }

    /// A buffer over `backing` laid out as `layout`, its section pointers
    /// derived after their bounds are checked. Writes nothing.
    fn over(
        backing: Arc<Backing>,
        layout: Layout,
        config: LogBufferConfig,
        generation: Generation,
        slots: u8,
        max_message_length: u32,
    ) -> Result<Self, SysError> {
        let regions = T::create(
            Token::new(),
            config.term_length,
            slots,
            &backing,
            layout.terms,
        )?;
        let control = backing
            .overlays::<Control>(layout.control, 1)?
            .cast::<Control>();
        Ok(Self {
            regions,
            slots,
            spare_slots: config.spare_slots,
            term_length: config.term_length.get(),
            initial_term_id: config.initial_term_id,
            generation,
            config,
            max_message_length,
            control,
            descriptors: backing.overlays(layout.descriptors, layout.slots)?,
            table: backing.overlays(layout.table, layout.slots)?,
            tails: backing.overlays(layout.tails, layout.slots)?,
            cells: backing.overlays(layout.cells, layout.cell_count)?,
            publishers: backing.overlays(layout.publishers, layout.publisher_count)?,
            backing,
            layout,
            conductor_taken: AtomicBool::new(false),
            #[cfg(feature = "test-hooks")]
            deadline_fault: AtomicBool::new(false),
        })
    }

    /// The initial state of a new buffer: `ACTIVE(t0)` and `READY(t0 + 1)`,
    /// every other slot `FREE`, the table, the cells, the tails, the limit
    /// and the configuration block. Only for a buffer no other party sees.
    fn initialise(&self) {
        // An image starts at the term of its join point; every other
        // buffer at term 0. Creation checked the count.
        let join = self.join();
        let start = u32::try_from(join / u64::from(self.term_length))
            .ok()
            .and_then(|count| TermCount::try_new(count).ok())
            .unwrap_or(TermCount::ZERO);
        let t0 = self.initial_term_id.advanced_by(start);
        // The last term of the incarnation has no next term to prepare.
        let next = start.next().ok();
        let one = next.map_or(t0, |next| self.initial_term_id.advanced_by(next));
        for (slot, line) in self.descriptors().iter().enumerate() {
            let state = match slot {
                0 => Descriptor::new(t0, self.generation, SlotState::Active),
                1 if next.is_some() => Descriptor::new(one, self.generation, SlotState::Ready),
                _ => Descriptor::new(t0, self.generation, SlotState::Free),
            };
            line.word.store(state.encode(), Ordering::Relaxed);
        }
        let table_len = u32::from(self.slots);
        if let Some(entry) = self.table().get((start.get() % table_len) as usize) {
            entry.store(table_entry(start.get(), 0), Ordering::Relaxed);
        }
        if let Some(next) = next
            && let Some(entry) = self.table().get((next.get() % table_len) as usize)
        {
            entry.store(table_entry(next.get(), 1), Ordering::Relaxed);
        }
        self.active_count()
            .store(u64::from(start.get()), Ordering::Relaxed);
        self.reserved_head().store(join, Ordering::Relaxed);
        self.floor().store(join, Ordering::Relaxed);
        let publisher_cells = self.layout.publisher_count;
        for (index, cell) in self.cells().iter().enumerate() {
            let state = if index < publisher_cells {
                CELL_PUBLICATION
            } else {
                CELL_FREE
            };
            cell.state.store(state, Ordering::Relaxed);
        }
        for (slot, line) in self.tails().iter().enumerate() {
            let term = if slot == 0 || next.is_none() { t0 } else { one };
            line.word
                .store(u64::from(term.get()) << 32, Ordering::Relaxed);
        }
        self.limit()
            .store(join + window(&self.config), Ordering::Relaxed);
        self.write_config();
    }

    /// Whether this buffer is an image.
    fn image(&self) -> bool {
        matches!(self.config.publication, PublicationMode::Image { .. })
    }

    /// The join point of an image; 0 for any other buffer.
    fn join(&self) -> u64 {
        match self.config.publication {
            PublicationMode::Image { join } => join,
            _ => 0,
        }
    }

    /// The configuration block (`quantstratum-docs: karyos/design/ipc-log-buffer.md`).
    fn write_config(&self) {
        let words = config_words(&self.config, self.generation, self.max_message_length);
        for (index, value) in words.into_iter().enumerate() {
            if let Some(word) = self.backing.word(self.layout.config + index) {
                word.store(value, Ordering::Relaxed);
            }
        }
    }

    // Accessors of the shared words. Each turns a section pointer, derived
    // from `backing` after a bounds check, into a reference that borrows
    // `self` and therefore the `Arc` that keeps `backing` alive.

    fn control(&self) -> &Control {
        // SAFETY: `control` points to one `Control` inside `backing`
        // (checked by `overlays` at construction), which lives as long as
        // `self`. `Control` is an `Overlay`: only `AtomicU64` words, every
        // bit pattern valid, accessed only atomically, aligned as
        // `AtomicU64` like every backing word.
        unsafe { self.control.as_ref() }
    }

    fn descriptors(&self) -> &[Line] {
        // SAFETY: as `control`, for the descriptor section.
        unsafe { self.descriptors.as_ref() }
    }

    fn table(&self) -> &[AtomicU64] {
        // SAFETY: as `control`, for the slot table.
        unsafe { self.table.as_ref() }
    }

    fn tails(&self) -> &[Line] {
        // SAFETY: as `control`, for the tails.
        unsafe { self.tails.as_ref() }
    }

    fn cells(&self) -> &[Cell] {
        // SAFETY: as `control`, for the registry cells.
        unsafe { self.cells.as_ref() }
    }

    fn publisher_lines(&self) -> &[PublisherSlot] {
        // SAFETY: as `control`, for the publisher slots (possibly empty: an
        // empty slice is never indexed).
        unsafe { self.publishers.as_ref() }
    }

    fn publisher(&self, index: usize) -> Option<&AtomicU64> {
        self.publisher_lines().get(index).map(|line| &line.word)
    }

    fn publisher_words(&self) -> impl Iterator<Item = &AtomicU64> {
        self.publisher_lines().iter().map(|line| &line.word)
    }

    fn active_count(&self) -> &AtomicU64 {
        &self.control().active_count.word
    }

    fn reserved_head(&self) -> &AtomicU64 {
        &self.control().reserved_head.word
    }

    fn limit(&self) -> &AtomicU64 {
        &self.control().limit.word
    }

    fn floor(&self) -> &AtomicU64 {
        &self.control().floor.word
    }

    fn seal(&self) -> &AtomicU64 {
        &self.control().seal.word
    }

    fn publication_taken(&self) -> &AtomicU64 {
        &self.control().publication_taken.word
    }

    fn exclusive_released(&self) -> &AtomicU64 {
        &self.control().exclusive_released.word
    }

    fn claim_record(&self) -> &AtomicU64 {
        &self.control().claim_record.word
    }

    fn claim_serial(&self) -> &AtomicU64 {
        &self.control().claim_serial.word
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

    /// The configuration the buffer was created with; for a buffer attached
    /// from a region, the one its region carries, validated at attach.
    #[inline]
    #[must_use]
    pub fn config(&self) -> &LogBufferConfig {
        &self.config
    }

    /// The term length in bytes.
    #[inline]
    #[must_use]
    pub fn term_length(&self) -> u32 {
        self.term_length
    }

    /// The mapping generation (`quantstratum-docs: karyos/design/mapping-generations.md`).
    #[inline]
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
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
            .cells()
            .iter()
            .skip(self.first_subscriber_cell())
            .filter(|cell| connected(cell.state.load(Ordering::Acquire)))
            .count();
        u32::try_from(attached).unwrap_or(u32::MAX)
    }

    fn cell(&self, index: usize) -> Result<&Cell, SysError> {
        self.cells()
            .get(index)
            .ok_or(SysError::ResourcesUnavailable)
    }

    fn descriptor(&self, slot: u8) -> Result<&AtomicU64, SysError> {
        self.descriptors()
            .get(usize::from(slot))
            .map(|line| &line.word)
            .ok_or(SysError::ResourcesUnavailable)
    }

    fn table_slot(&self, count: TermCount) -> Result<&AtomicU64, SysError> {
        let index = count.get() % u32::from(self.slots);
        self.table()
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
        self.tails()
            .get(usize::from(slot))
            .map(|line| &line.word)
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
            return Ok(Some(self.reserved_head().load(Ordering::Acquire)));
        }
        let count = TermCount::try_new(self.active_count().load(Ordering::Acquire) as u32)?;
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
        let head = self.position(count, offset);
        // A fenced term's tail is past its end; the seal position is the end
        // of what was granted (`quantstratum-docs: karyos/design/mapping-generations.md`).
        Ok(Some(
            match decode_seal(self.seal().load(Ordering::Acquire)) {
                SealWord::Positioned(position) => head.min(position),
                _ => head,
            },
        ))
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
        PublicationMode::Image { .. } => IMAGE_OWNER_CELLS,
    }
}

/// Loan words of an image's receive owner, per lane: a standing write loan
/// on each of the two terms it may write and a transient read loan on the
/// trailing term it compares (`L = 3`, owner decision D2).
const IMAGE_OWNER_CELLS: usize = 3;

/// The publication window: `term_length / 2`, less the concurrent
/// overshoot `(P - 1) × max_reserved` (SPEC.md §4 IPC flow control).
fn window(config: &LogBufferConfig) -> u64 {
    let half = u64::from(config.term_length.get() / 2);
    match config.publication {
        PublicationMode::Exclusive | PublicationMode::Image { .. } => half,
        PublicationMode::Concurrent { publishers, .. } => {
            let overshoot =
                u64::from(publishers.saturating_sub(1)) * u64::from(config.max_reserved);
            // Creation checked `P × max_reserved ≤ term_length / 2`.
            half.max(overshoot) - overshoot
        }
    }
}

/// Creation checks of an image: its join point names a term count below
/// `2^31`, and the spare slots cover the owner's loans.
fn check_image(config: &LogBufferConfig, join: u64) -> Result<(), SysError> {
    // Readers and the owner access word 0 at the join point: a frame
    // boundary, aligned like every frame.
    if !join.is_multiple_of(u64::from(FRAME_ALIGNMENT)) {
        return Err(SysError::InvalidPublicationMode {
            reason: "the join point is not a multiple of the frame alignment",
        });
    }
    let count = join / u64::from(config.term_length.get());
    if count >= u64::from(crate::term::TERM_COUNT_LIMIT) {
        return Err(SysError::InvalidPublicationMode {
            reason: "the join point is past the last term of the incarnation",
        });
    }
    if IMAGE_OWNER_CELLS > usize::from(config.spare_slots.saturating_sub(CLEANING_HEADROOM)) {
        return Err(SysError::ResourcesUnavailable);
    }
    Ok(())
}

/// Creation checks of the publication mode
/// (`quantstratum-docs: karyos/design/concurrent-publication.md`).
fn check_publication_mode(config: &LogBufferConfig) -> Result<(), SysError> {
    check_publication_mode_on(config, single_instruction_fetch_add())
}

/// [`check_publication_mode`] for a target whose `fetch_add` is (`lse`) or
/// is not a single instruction.
fn check_publication_mode_on(config: &LogBufferConfig, lse: bool) -> Result<(), SysError> {
    let (publishers, allow_non_lse) = match config.publication {
        PublicationMode::Exclusive => return Ok(()),
        PublicationMode::Image { join } => return check_image(config, join),
        PublicationMode::Concurrent {
            publishers,
            allow_non_lse,
        } => (publishers, allow_non_lse),
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
        write_claim_record(self.claim_serial(), self.claim_record(), value);
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

    /// Test hook (feature `test-hooks`): takes a read loan on term 0 for
    /// the reader in `cell`, as a reader paused inside its copy would hold
    /// it, so dependent crates can observe a lost `hold` reader that still
    /// bounds the publisher. Returns whether the loan was granted.
    #[doc(hidden)]
    pub fn hold_read_loan(&self, cell: usize) -> bool {
        let (Some(found), Ok(descriptor), Ok(target)) = (
            self.cells().get(cell),
            self.descriptor(0),
            self.target(0, TermCount::ZERO),
        ) else {
            return false;
        };
        matches!(
            take_loan(&found.loan, &found.revoked, descriptor, target),
            Ok(LoanOutcome::Granted)
        )
    }

    /// Test hook (feature `test-hooks`): ends the loan
    /// [`Self::hold_read_loan`] took.
    #[doc(hidden)]
    pub fn release_read_loan(&self, cell: usize) {
        if let Some(found) = self.cells().get(cell) {
            release_loan(&found.loan);
        }
    }
}

fn issue_publication<O: BufferOwner>(owner: O) -> Result<Option<Publication<O>>, SysError> {
    let buffer: &LogBuffer<O::Terms> = &owner;
    if buffer.concurrent() {
        return Err(SysError::InvalidPublicationMode {
            reason: "the exclusive publication of a concurrent buffer",
        });
    }
    if buffer.image() {
        return Err(SysError::InvalidPublicationMode {
            reason: "the exclusive publication of an image",
        });
    }
    // Already issued: no allocation. The compare-exchange below still
    // decides a race.
    if buffer.publication_taken().load(Ordering::Acquire) != 0 {
        return Ok(None);
    }
    // The staging buffer of claims on a backing without direct bytes, sized
    // for the largest admissible claim and allocated fallibly before the
    // publication is issued.
    let staging = staging_buffer(buffer)?;
    // `SeqCst` with the seal load below and the conductor's seal store and
    // positioning load: at least one side observes the other
    // (`quantstratum-docs: karyos/design/publication-seal.md`, issuance).
    if !take_publication(buffer.publication_taken()) {
        return Ok(None);
    }
    if issuer_sees_seal(buffer.seal()) {
        // Taken but never used: released at once, and never reissued.
        release_publication(buffer.exclusive_released());
        return Err(SysError::Sealed);
    }
    first_loan(owner, staging).map(Some)
}

/// The exclusive publication's initial write loan on term 0, for a fresh
/// publication taken by this process or adopted from a registration.
fn first_loan<O: BufferOwner>(owner: O, staging: Box<[u8]>) -> Result<Publication<O>, SysError> {
    take_initial_loan(&owner)?;
    Ok(initial_publication(owner, staging))
}

/// Takes the exclusive publication's write loan on term 0, in slot 0: a
/// fixed number of atomic operations, no allocation.
fn take_initial_loan<T: TermBytes>(buffer: &LogBuffer<T>) -> Result<(), SysError> {
    let cell = buffer.cell(0)?;
    let slot = SlotIndex::try_new(0)?;
    let target = LoanTarget::new(
        slot,
        buffer.generation,
        buffer.initial_term_id,
        TermCount::ZERO,
    );
    match take_loan(&cell.loan, &cell.revoked, buffer.descriptor(0)?, target)? {
        LoanOutcome::Granted => Ok(()),
        _ => Err(SysError::CorruptTerm {
            offset: 0,
            reason: "initial term not active",
        }),
    }
}

/// The exclusive publication at term 0 under its initial write loan.
fn initial_publication<O: BufferOwner>(owner: O, staging: Box<[u8]>) -> Publication<O> {
    Publication {
        buffer: owner,
        state: PublicationState::Active {
            count: TermCount::ZERO,
            slot: 0,
            tail: 0,
        },
        pending: None,
        staging,
    }
}

/// The staging buffer of claims on a backing without direct bytes, sized for
/// the largest admissible claim and allocated fallibly; empty otherwise.
fn staging_buffer<T: TermBytes>(buffer: &LogBuffer<T>) -> Result<Box<[u8]>, SysError> {
    if <T as crate::term_bytes::sealed::Access>::DIRECT {
        return Ok(Box::default());
    }
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
    Ok(staging.into_boxed_slice())
}

/// The refusal of an adoption whose registration does not match its grant.
const NOT_GRANTED: SysError = SysError::Protocol {
    reason: "the registration does not match the grant",
};

/// An activation that failed (`quantstratum-docs:
/// karyos/design/ipc-data-path.md`, Preparing off the data path): the
/// prepared handle comes back, so that the caller drops it, and the memory
/// it holds, on its control path.
#[derive(Debug)]
pub struct ActivateError<P> {
    /// Why the activation failed.
    pub error: SysError,
    /// The prepared handle, unless the activation got as far as building
    /// the adopted one, which was dropped (a corrupt buffer). A grant whose
    /// registration was claimed is spent: activating it again fails.
    pub prepared: Option<P>,
}

/// An exclusive publication prepared for adoption: its handle memory and
/// staging scratch are allocated, and no shared word has been touched.
#[derive(Debug)]
pub struct PreparedPublication<O: BufferOwner> {
    owner: O,
    export: u64,
    staging: Box<[u8]>,
}

impl<O: BufferOwner> Publication<O> {
    /// Prepares the adoption of the exclusive publication registered for
    /// `export` (`quantstratum-docs: karyos/design/ipc-data-path.md`,
    /// Preparing off the data path): everything that allocates, and no
    /// access to a shared word. [`PreparedPublication::activate`] then
    /// adopts it without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidPublicationMode`] for a concurrent buffer,
    /// [`SysError::Protocol`] for an export that is not valid, and
    /// [`SysError::ResourcesUnavailable`] when the scratch cannot be
    /// allocated.
    pub fn prepare_adopt(owner: O, export: u64) -> Result<PreparedPublication<O>, SysError> {
        let buffer: &LogBuffer<O::Terms> = &owner;
        if buffer.concurrent() {
            return Err(SysError::InvalidPublicationMode {
                reason: "the exclusive publication of a concurrent buffer",
            });
        }
        if !valid_export(export) {
            return Err(NOT_GRANTED);
        }
        let staging = staging_buffer(buffer)?;
        Ok(PreparedPublication {
            owner,
            export,
            staging,
        })
    }

    /// Adopts the exclusive publication that the creator registered for
    /// export `export` (`quantstratum-docs: karyos/design/ipc-log-buffer.md`): taken, not
    /// released, registered for exactly this export, and fresh (nothing
    /// reserved yet). Takes the initial write loan in this process.
    /// [`Publication::prepare_adopt`] then [`PreparedPublication::activate`].
    ///
    /// # Errors
    ///
    /// As those two calls.
    pub fn adopt(owner: O, export: u64) -> Result<Self, SysError> {
        Self::prepare_adopt(owner, export)?
            .activate()
            .map_err(|refused| refused.error)
    }
}

impl<O: BufferOwner> PreparedPublication<O> {
    /// Adopts the prepared publication: the registration compare-exchange
    /// and the initial write loan, a bounded number of atomic operations
    /// and no allocation.
    ///
    /// # Errors
    ///
    /// Returns the prepared handle with [`SysError::Protocol`] when the
    /// publication is not taken, released, fresh and registered for exactly
    /// this export, and with [`SysError::CorruptTerm`] when the initial term
    /// is not active.
    pub fn activate(self) -> Result<Publication<O>, ActivateError<Self>> {
        let buffer: &LogBuffer<O::Terms> = &self.owner;
        if buffer.publication_taken().load(Ordering::Acquire) == 0
            || buffer.exclusive_released().load(Ordering::Acquire) != 0
            || buffer.reserved_head().load(Ordering::Acquire) != 0
            || !claim(&buffer.control().publication_registration.word, self.export)
        {
            return Err(ActivateError {
                error: NOT_GRANTED,
                prepared: Some(self),
            });
        }
        if let Err(error) = take_initial_loan(buffer) {
            return Err(ActivateError {
                error,
                prepared: Some(self),
            });
        }
        Ok(initial_publication(self.owner, self.staging))
    }
}

/// A subscription prepared for adoption. A subscription allocates nothing,
/// so preparing only checks the shape of the request.
#[derive(Debug)]
pub struct PreparedSubscription<O: BufferOwner> {
    owner: O,
    cell: usize,
    role: Role,
    export: u64,
}

impl<O: BufferOwner> Subscription<O> {
    /// Prepares the adoption of subscriber cell `cell`, registered with
    /// `role` for `export`, as [`Publication::prepare_adopt`].
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Protocol`] for a cell that is not a subscriber
    /// cell of the buffer or an export that is not valid.
    pub fn prepare_adopt(
        owner: O,
        cell: usize,
        role: Role,
        export: u64,
    ) -> Result<PreparedSubscription<O>, SysError> {
        let buffer: &LogBuffer<O::Terms> = &owner;
        if cell < buffer.first_subscriber_cell() || cell >= buffer.cells().len() {
            return Err(NOT_GRANTED);
        }
        if !valid_export(export) {
            return Err(NOT_GRANTED);
        }
        Ok(PreparedSubscription {
            owner,
            cell,
            role,
            export,
        })
    }

    /// Adopts the subscriber cell `cell` that the creator registered with
    /// `role` for export `export` (`quantstratum-docs: karyos/design/ipc-log-buffer.md`). The
    /// subscription resumes at the cell's published position.
    /// [`Subscription::prepare_adopt`] then [`PreparedSubscription::activate`].
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Protocol`] when the cell is not a subscriber cell
    /// attached with `role` and registered for exactly this export.
    pub fn adopt(owner: O, cell: usize, role: Role, export: u64) -> Result<Self, SysError> {
        Self::prepare_adopt(owner, cell, role, export)?
            .activate()
            .map_err(|refused| refused.error)
    }
}

impl<O: BufferOwner> PreparedSubscription<O> {
    /// Adopts the prepared subscription: the cell's state check, the
    /// registration compare-exchange and its position, with no allocation.
    ///
    /// # Errors
    ///
    /// Returns the prepared handle with [`SysError::Protocol`] when the cell
    /// is not attached with its role and registered for exactly its export.
    pub fn activate(self) -> Result<Subscription<O>, ActivateError<Self>> {
        let buffer: &LogBuffer<O::Terms> = &self.owner;
        let Ok(found) = buffer.cell(self.cell) else {
            return Err(ActivateError {
                error: NOT_GRANTED,
                prepared: Some(self),
            });
        };
        let expected = match self.role {
            Role::Required => CELL_REQUIRED,
            Role::Optional => CELL_OPTIONAL,
        };
        let state = found.state.load(Ordering::Acquire);
        let admitted =
            state == expected || (expected == CELL_REQUIRED && state == CELL_REQUIRED_RESERVED);
        if !admitted || !claim(&found.registration, self.export) {
            return Err(ActivateError {
                error: NOT_GRANTED,
                prepared: Some(self),
            });
        }
        let position = found.position.load(Ordering::Acquire);
        let joining = self.owner.image();
        Ok(Subscription {
            buffer: self.owner,
            cursor: Cursor {
                cell: self.cell,
                role: self.role,
                position,
                acknowledged: position,
                pending: None,
                detached: false,
                joining,
            },
        })
    }
}

fn issue_conductor<O: BufferOwner>(owner: O) -> Option<Conductor<O>> {
    owner
        .conductor_taken
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()?;
    let publishers = owner.first_subscriber_cell();
    Some(Conductor {
        buffer: owner,
        quarantined: Vec::new(),
        observed: None,
        deadlines: deadline::ConcurrentDeadlines::new(publishers),
        ending: Vec::with_capacity(publishers),
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
    /// The buffer is sealed: this publication reserves nothing again
    /// (`quantstratum-docs: karyos/design/publication-seal.md`).
    Closed,
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
    /// The publication observed the seal and released.
    Closed,
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
    /// The buffer is sealed: this publication reserves nothing again
    /// (`quantstratum-docs: karyos/design/publication-seal.md`).
    Closed,
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
        if self.state == PublicationState::Closed {
            return Ok(AppendOutcome::Closed);
        }
        let outcome = PublicationContext {
            buffer: &self.buffer,
            state: &mut self.state,
        }
        .append(payload, options)?;
        match outcome {
            AppendOutcome::Appended { .. } => Ok(outcome),
            _ if self.observe_seal() => Ok(AppendOutcome::Closed),
            _ => Ok(outcome),
        }
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
        self.try_claim_with(length, options, &mut |_| {})
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
        self.try_claim_with(length, options, pause)
    }

    fn try_claim_with(
        &mut self,
        length: u32,
        options: AppendOptions,
        pause: &mut dyn FnMut(ClaimPause),
    ) -> Result<ClaimOutcome<'_, O>, SysError> {
        self.resolve_claim();
        if self.state == PublicationState::Closed {
            return Ok(ClaimOutcome::Closed);
        }
        let step = PublicationContext {
            buffer: &self.buffer,
            state: &mut self.state,
        }
        .claim(length, options, pause)?;
        if matches!(step, ClaimStep::Outcome(_)) && self.observe_seal() {
            return Ok(ClaimOutcome::Closed);
        }
        self.finish_claim(step)
    }

    /// Whether the publication is closed by the seal, releasing it now if
    /// the buffer is sealed and it has not released yet
    /// (`quantstratum-docs: karyos/design/publication-seal.md`). Resolves a forgotten claim
    /// first. For wrappers that return before an attempt (the connection
    /// rule), so that a sealed publication is still released.
    pub fn close_if_sealed(&mut self) -> bool {
        self.resolve_claim();
        self.state == PublicationState::Closed || self.observe_seal()
    }

    /// Whether the handle is closed: it observed the seal and released. A
    /// field read; touches no shared state.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state == PublicationState::Closed
    }

    /// After an attempt that was not granted: if the buffer is sealed,
    /// releases the publication (its loan, then `exclusive_released` after
    /// its last `reserved_head` store) and returns `true`; every later call
    /// returns `Closed` at once (`quantstratum-docs: karyos/design/publication-seal.md`). The
    /// caller resolved any forgotten claim first.
    fn observe_seal(&mut self) -> bool {
        if !observe_seal(self.buffer.seal()) {
            return false;
        }
        self.release();
        self.state = PublicationState::Closed;
        true
    }

    /// Releases the standing write loan, if any, then announces the
    /// release. The last access of the publication to the buffer.
    fn release(&mut self) {
        if let PublicationState::Active { .. } = self.state
            && let Ok(cell) = self.buffer.cell(0)
        {
            release_loan(&cell.loan);
        }
        registration::clear(&self.buffer.control().publication_registration.word);
        release_publication(self.buffer.exclusive_released());
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

impl<O: BufferOwner> Publication<O> {
    /// Test hook: the holder dies. Nothing it owns in the buffer is
    /// released (no claim resolution, loan or publication release), as for
    /// a process that exited; only its private heap memory is freed.
    #[cfg(test)]
    fn die(self) {
        let mut this = core::mem::ManuallyDrop::new(self);
        drop(core::mem::take(&mut this.staging));
        // SAFETY: `this` is never used again and its destructor never
        // runs; the owner is dropped once, here.
        unsafe { core::ptr::drop_in_place(&raw mut this.buffer) };
    }
}

impl<O: BufferOwner> Drop for Publication<O> {
    fn drop(&mut self) {
        // A claim's accesses have ended: it borrowed the publication, which
        // is being dropped. Resolve it, then release the loan.
        self.resolve_claim();
        if self.state != PublicationState::Closed {
            // The last access of the publication to its term.
            self.release();
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
        if buffer.claim_serial().load(Ordering::Relaxed) > u64::MAX - CLAIM_SERIAL_COST {
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
        let limit = buffer.limit().load(Ordering::Acquire);
        let remaining = buffer.term_length - tail;
        if reserved > remaining {
            // Reserve only the PAD up to the term boundary.
            let boundary = buffer.position(count, buffer.term_length);
            if boundary > limit {
                return Ok(Reservation::Outcome(AppendOutcome::BackPressured));
            }
            let next = count.next()?;
            buffer.reserved_head().store(boundary, Ordering::Release);
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
        buffer.reserved_head().store(end, Ordering::Release);
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
        let _ = buffer.active_count().compare_exchange(
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
        let first = write_fragments(buffer, slot, count, start, payload, plan, options);
        // SAFETY: write loan held; the block's first frame start.
        publish_block(unsafe { buffer.regions.word0(slot, start) }, first);
    }

    /// Writes header bytes 8..32 of the frame at `offset`.
    fn write_header_tail(&self, slot: u8, count: TermCount, offset: u32, reserved_value: i64) {
        write_header_tail(self.buffer, slot, count, offset, reserved_value);
    }
}

/// Writes every byte of a block except its first word 0, which it
/// returns: headers 8..32, extensions, payloads and interior words 0. The
/// caller publishes the first word 0 (a Release store, or the commit
/// compare-exchange of a marked block).
///
/// The caller holds the slot's write loan for `count` and owns
/// `[start, start + reserved)`: no reader reaches it before that
/// publication.
fn write_fragments<T: TermBytes>(
    buffer: &LogBuffer<T>,
    slot: u8,
    count: TermCount,
    start: u32,
    payload: &[u8],
    plan: &FragmentPlan,
    options: AppendOptions,
) -> Word0 {
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
        write_header_tail(buffer, slot, count, offset, options.reserved_value);
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
    first.unwrap_or(Word0::new(0, Flags::NONE, FrameType::Data))
}

/// Writes header bytes 8..32 of the frame at `offset` under the caller's
/// write loan, in a range it owns and no reader reaches yet.
fn write_header_tail<T: TermBytes>(
    buffer: &LogBuffer<T>,
    slot: u8,
    count: TermCount,
    offset: u32,
    reserved_value: i64,
) {
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

/// The seal state of a buffer (`quantstratum-docs: karyos/design/publication-seal.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealState {
    /// Not sealed.
    Active,
    /// Sealed; some issued publisher has not released yet.
    Sealed,
    /// Every publisher released: no block at or above `position` exists,
    /// and every block below it is terminal.
    Positioned {
        /// The seal position.
        position: u64,
    },
    /// Positioned, and every attached subscriber has reached `position`.
    Retired {
        /// The seal position.
        position: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SealWord {
    Active,
    Sealed,
    Positioned(u64),
}

fn decode_seal(raw: u64) -> SealWord {
    if raw & SEAL_POSITIONED != 0 {
        SealWord::Positioned(raw & SEAL_POSITION)
    } else if raw & SEAL_SEALED != 0 {
        SealWord::Sealed
    } else {
        SealWord::Active
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
    /// The subscriber was revoked: its client was lost, and the driver
    /// handled the loss under the publication's policy (quantstratum-docs: `karyos/design/required-participant-loss.md`). Terminal
    /// for this subscription, for both roles; a client that reconnects
    /// subscribes again. Every later poll returns it again.
    Revoked {
        /// The subscriber's read position.
        position: u64,
    },
    /// The buffer is sealed and the subscriber reached the seal position:
    /// no message can follow. Every later poll returns it again
    /// (`quantstratum-docs: karyos/design/publication-seal.md`).
    Closed {
        /// The seal position.
        position: u64,
    },
    /// An aborted block was skipped: only its word 0 was read. Its extent
    /// carries no message and needs no acknowledgement.
    Aborted {
        /// Stream position of the block.
        position: u64,
        /// Bytes skipped.
        extent: u32,
    },
    /// Only on an image (`quantstratum-docs: karyos/design/receive-publication.md`,
    /// fragments are published one by one): a range that delivers no
    /// message was skipped, and reading continues after it. It needs no
    /// acknowledgement.
    Skipped {
        /// Stream position of the skipped range.
        position: u64,
        /// Bytes skipped.
        extent: u32,
        /// Why the range delivers no message.
        reason: SkipReason,
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

/// Why an image reader skipped a range (`PollOutcome::Skipped`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReason {
    /// A message whose reserved length or payload exceeds the image's
    /// `max_reserved_length` or `max_message_length`: skipped from its
    /// BEGIN to the end of the fragment that crossed the bound.
    MessageTooLarge,
    /// A message with no END before the term end: skipped to the term end.
    MissingEnd,
    /// A message interrupted by an ABORTED, PAD or new BEGIN frame:
    /// skipped up to the interrupting frame, which is read next.
    Interrupted,
    /// Fragments without their BEGIN, after this reader joined: a peer
    /// fault.
    Orphan,
    /// Fragments without their BEGIN where this reader joined, in the
    /// middle of a message: the rest of a message it never saw start.
    JoinedMidMessage,
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
    /// An image reader that has not yet reached a BEGIN, ABORTED or PAD
    /// frame since it joined.
    joining: bool,
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

    /// The registry cell of this subscriber, for its conductor's
    /// [`Conductor::cell_position`].
    #[inline]
    #[must_use]
    pub fn cell(&self) -> usize {
        self.cursor.cell
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
        let outcome = SubscriptionContext {
            buffer: &self.buffer,
            cursor: &mut self.cursor,
        }
        .poll(out)?;
        if outcome != PollOutcome::Pending || self.cursor.pending.is_some() {
            return Ok(outcome);
        }
        // Only where the poll found nothing: the seal is positioned once
        // every block below it is terminal, so a cursor at the position has
        // read everything (`quantstratum-docs: karyos/design/publication-seal.md`).
        match decode_seal(self.buffer.seal().load(Ordering::Acquire)) {
            SealWord::Positioned(position) if self.cursor.position >= position => {
                Ok(PollOutcome::Closed { position })
            }
            _ => Ok(outcome),
        }
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
            LoanOutcome::Overrun => return self.overrun(),
            LoanOutcome::Revoked => {
                return Ok(Step::Done(PollOutcome::Revoked {
                    position: self.cursor.position,
                }));
            }
        }
        // Retention admission point: the floor is checked after the loan is
        // granted and before any plain read.
        if self.cursor.position < buffer.floor().load(Ordering::Acquire) {
            release_loan(&cell.loan);
            return self.overrun();
        }
        let result = self.read_block(slot, offset, out);
        release_loan(&cell.loan);
        let result = result?;
        if !matches!(
            result,
            Read::Pending
                | Read::Skip {
                    reason: SkipReason::Orphan | SkipReason::JoinedMidMessage,
                    ..
                }
        ) {
            // The cursor reached a BEGIN, ABORTED or PAD frame.
            self.cursor.joining = false;
        }
        match result {
            Read::Pending => Ok(Step::Done(PollOutcome::Pending)),
            Read::Skip { extent, reason } => {
                let position = self.cursor.position;
                self.advance_to(position + u64::from(extent));
                Ok(Step::Done(PollOutcome::Skipped {
                    position,
                    extent,
                    reason,
                }))
            }
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
            Validated::Skip { extent, reason } => Ok(Read::Skip { extent, reason }),
            Validated::Block(block) => self.copy_block(slot, start, block, out),
        }
    }

    /// First pass: classifies the block at `start` from its first word 0
    /// and, for data, walks and checks every fragment's word 0.
    fn validate_block(&self, slot: u8, start: u32) -> Result<Validated, SysError> {
        if self.buffer.image() {
            return self.validate_image_block(slot, start);
        }
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
        let lost_to = self.buffer.floor().load(Ordering::Acquire).max(from);
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
            // The registration is cleared before the cell is freed, so a
            // delayed end of this export never touches the next occupant.
            // No loan is held outside `poll`; publishing FREE is the last
            // access of this holder to its cell.
            registration::clear(&cell.registration);
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
    Aborted {
        extent: u32,
    },
    /// Only on an image: a range that delivers no message.
    Skip {
        extent: u32,
        reason: SkipReason,
    },
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
    Skip {
        extent: u32,
        reason: SkipReason,
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
    /// Revoked `hold` readers whose bound this cycle withdrew.
    pub bounds_withdrawn: u32,
}

/// The buffer's only conductor; every operation takes `&mut self`.
#[derive(Debug)]
pub struct Conductor<O: BufferOwner> {
    buffer: O,
    quarantined: Vec<u8>,
    /// The claim being timed: `(serial, first_seen)`.
    observed: Option<(u64, u64)>,
    /// The concurrent deadline state (`quantstratum-docs: karyos/design/concurrent-deadline.md`).
    deadlines: deadline::ConcurrentDeadlines,
    /// Ended concurrent publishers whose slot and write loan are held
    /// until the deadline resolves their blocks, `P` entries reserved at
    /// issue.
    ending: Vec<Ending>,
}

/// What [`Conductor::end_publication`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationEnd {
    /// The registration names another export or none: nothing was done.
    Stale,
    /// Ended; every block below the reserved head was terminal.
    Ended,
    /// Ended; the pending range at `position`, of `extent` bytes, was
    /// aborted.
    Aborted {
        /// Its stream position.
        position: u64,
        /// Its extent in bytes.
        extent: u32,
    },
    /// Ended; the reservation reached the term end with nothing written:
    /// padded from `position` to the term end.
    Padded {
        /// Its stream position.
        position: u64,
        /// Its extent in bytes.
        extent: u32,
    },
}

/// Resolves the exclusive writer's pending range in the term its standing
/// write loan names (see [`Conductor::end_publication`]). The loan is
/// still set, so the slot holds that term and is not reclaimed.
fn resolve_pending<T: TermBytes>(buffer: &LogBuffer<T>) -> Result<PublicationEnd, SysError> {
    let Some(loan) = Loan::decode(buffer.cell(0)?.loan.load(Ordering::Acquire))? else {
        return Ok(PublicationEnd::Ended);
    };
    let slot = loan.slot().get();
    let count = loan.term_id().count_from(buffer.initial_term_id)?;
    let term_length = buffer.term_length;
    let base = buffer.position(count, 0);
    let head = buffer.conductor_head()?;
    let end = buffer.position(count, term_length);
    let bound = (head.min(end).saturating_sub(base)) as u32;
    let lane = buffer.config.lane;
    let mut offset = 0;
    while offset < bound {
        // SAFETY: the writer's loan on `count` in `slot` is still set, so
        // the slot holds that term and is neither reclaimed nor cleaned;
        // `offset` is a frame start below the reserved head, a location
        // accessed only atomically during this incarnation.
        let first = unsafe { buffer.regions.word0(slot, offset) };
        let raw = observe_block(first);
        if raw == 0 || (raw as u32 as i32) < 0 {
            let extent = bound - offset;
            let position = buffer.position(count, offset);
            if raw == 0 && head >= end {
                // A crossing whose padding was not written, as the crossing
                // writer would have written it.
                let pad = Word0::new(
                    extent as i32,
                    Flags::new(false, false, false, false, lane),
                    FrameType::Pad,
                );
                publish_block(first, pad);
                return Ok(PublicationEnd::Padded { position, extent });
            }
            let aborted = Word0::new(
                extent as i32,
                Flags::new(false, false, false, false, lane),
                FrameType::Aborted,
            );
            if !deadline_abort(first, extent, lane, aborted) {
                return Err(corrupt(offset, "pending block"));
            }
            return Ok(PublicationEnd::Aborted { position, extent });
        }
        let word0 = Word0::unpack(raw).map_err(|_| corrupt(offset, "reserved flags"))?;
        if word0.version() != PROTOCOL_VERSION {
            return Err(corrupt(offset, "version"));
        }
        let length = u32::try_from(word0.frame_length()).map_err(|_| corrupt(offset, "length"))?;
        let extent = align_frame(length)?;
        if extent == 0 || extent > term_length - offset {
            return Err(corrupt(offset, "frame past term end"));
        }
        offset += extent;
    }
    Ok(PublicationEnd::Ended)
}

/// An ended concurrent publisher: its slot, and the reserved head observed
/// when it ended. Every block below that head is its or another writer's,
/// and is resolved once the deadline frontier reaches it.
#[derive(Debug, Clone, Copy)]
struct Ending {
    slot: usize,
    head: u64,
}

/// Every outcome of one [`Conductor::service_deadlines`] call
/// (`quantstratum-docs: karyos/design/concurrent-deadline.md`, Results). Each count is at most
/// `P + S + 1` (`P ≤ 255`, `S` the scan budget), so it fits `u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeadlineReport {
    /// Blocks and spans this call aborted.
    pub aborted: u32,
    /// Their total extent in bytes.
    pub aborted_bytes: u64,
    /// Expired points found already terminal.
    pub resolved: u32,
    /// Timers re-anchored because the clock went back.
    pub clock_went_back: u32,
    /// Points whose expiry instant does not fit `u64`.
    pub unrepresentable: u32,
    /// Concurrent: an observation or span walk remains after the call.
    /// Exclusive: the claim's result was `Waiting`.
    pub waiting: bool,
}

/// A deadline service call that failed, with the effects it completed
/// before the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("deadline service failed after {} aborts: {error}", report.aborted)]
pub struct DeadlineError {
    /// What the call completed before the error.
    pub report: DeadlineReport,
    /// The error.
    pub error: SysError,
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

    /// Registers a subscriber for a participant in another process, for
    /// export `export` (nonzero, never reused): the cell is attached as
    /// [`Conductor::subscribe`] attaches it, and its registration word
    /// records the export. Returns the cell, which the participant adopts
    /// with [`Subscription::adopt`] (`quantstratum-docs: karyos/design/ipc-log-buffer.md`).
    ///
    /// # Errors
    ///
    /// As [`Conductor::subscribe`]; [`SysError::Protocol`] for export 0 or
    /// an export above [`registration::MAX_EXPORT`].
    pub fn register_subscriber(&mut self, role: Role, export: u64) -> Result<usize, SysError> {
        self.register_subscriber_with(role, false, export)
    }

    /// [`Conductor::register_subscriber`], with `reserve` as in
    /// [`Conductor::subscribe_as`].
    ///
    /// # Errors
    ///
    /// As [`Conductor::register_subscriber`].
    pub fn register_subscriber_with(
        &mut self,
        role: Role,
        reserve: bool,
        export: u64,
    ) -> Result<usize, SysError> {
        if !valid_export(export) {
            return Err(NOT_GRANTED);
        }
        Ok(self.context().subscribe_with(role, reserve, export)?.cell)
    }

    /// Admits a subscriber in this process as occupant `occupant` of its
    /// cell (quantstratum-docs: `karyos/design/required-participant-loss.md`: nonzero, never
    /// reused, from the same namespace as export ids). With `reserve`, a
    /// required reader is admitted with a spare-slot credit, as the
    /// `continue` loss policy needs; an optional reader always takes one.
    ///
    /// # Errors
    ///
    /// As [`Conductor::subscribe`]; [`SysError::Protocol`] for an occupant
    /// that is not a valid export id.
    pub fn subscribe_as(
        &mut self,
        role: Role,
        reserve: bool,
        occupant: u64,
    ) -> Result<Subscription<O>, SysError> {
        if !valid_export(occupant) {
            return Err(NOT_GRANTED);
        }
        let cursor = self.context().subscribe_with(role, reserve, occupant)?;
        Ok(Subscription {
            buffer: self.buffer.clone(),
            cursor,
        })
    }

    /// Ends the registration of the subscriber registered in `cell` for
    /// `export`, adopted or not, and frees its cell
    /// (`quantstratum-docs: karyos/design/ipc-data-path.md`, Ending a
    /// registration). Returns whether it did: a cell that holds another
    /// export, an in-process occupant or nothing is left untouched, so a
    /// delayed end never touches a later occupant.
    ///
    /// The caller must hold a proof that the participant makes no further
    /// access to the cell: a `Detach` of `export` after its client unmapped
    /// the buffer, the client's exit proof, or the knowledge that the grant
    /// was never sent. In that order, the loan word is cleared, the
    /// registration word is cleared, and only then is the cell freed.
    pub fn end_subscriber(&mut self, cell: usize, export: u64) -> bool {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        if cell < buffer.first_subscriber_cell() {
            return false;
        }
        let Some(found) = buffer.cells().get(cell) else {
            return false;
        };
        if !registration::names(found.registration.load(Ordering::Acquire), export) {
            return false;
        }
        // The proof: no access under this loan can follow.
        release_loan(&found.loan);
        // Only the conductor reuses the cell, and an adoption or a fence
        // keeps the export, so the end does not miss; if it did, the cell
        // is not freed.
        if !registration::end(&found.registration, export) {
            return false;
        }
        found.state.store(CELL_FREE, Ordering::Release);
        true
    }

    /// Ends the registration of the concurrent publisher registered in
    /// publisher slot `slot` for `export`, adopted or not
    /// (`quantstratum-docs: karyos/design/ipc-data-path.md`, Ending a
    /// registration). Returns whether it did; a slot registered for
    /// another export, or none, is left untouched.
    ///
    /// The registration ends at once, so no adoption can follow. Shared
    /// memory does not say which undecided block was this publisher's, so
    /// none is aborted early: the slot and its write loan stay held until
    /// the commit deadline (`karyos/design/concurrent-deadline.md`) has
    /// resolved every block below the reserved head observed now; a later
    /// [`Conductor::service_deadlines`] then releases the loan and frees
    /// the slot.
    ///
    /// The caller must hold a proof that the publisher makes no further
    /// access, as for [`Conductor::end_subscriber`].
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidPublicationMode`] for an exclusive buffer
    /// and errors reading the reserved head.
    pub fn end_concurrent_publication(
        &mut self,
        slot: usize,
        export: u64,
    ) -> Result<bool, SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        if !buffer.concurrent() {
            return Err(SysError::InvalidPublicationMode {
                reason: "a concurrent handle of an exclusive buffer",
            });
        }
        let Some(found) = buffer.publisher_lines().get(slot) else {
            return Ok(false);
        };
        // Read before the end: the registration is the participant's, and
        // the head bounds its reservations, all made before the proof.
        let head = buffer.conductor_head()?;
        if !registration::end(&found.registration, export) {
            return Ok(false);
        }
        // At most one entry per slot: the registration ended once, and the
        // slot is not reissued while held. `P` entries were reserved.
        self.ending.push(Ending { slot, head });
        Ok(true)
    }

    /// Ends the registration of the exclusive publication registered for
    /// `export`, adopted or not, and releases it for good
    /// (`quantstratum-docs: karyos/design/ipc-data-path.md`, Ending a
    /// registration): it is never issued again, as when an in-process
    /// handle drops.
    ///
    /// There is one writer, so every undecided block below the reserved
    /// head is its own and is resolved at once. In order: the claim record
    /// is invalidated (the writer may have died mid-update); the term the
    /// standing write loan names is walked block by block from its start,
    /// keeping every terminal block; the first undecided block starts the
    /// pending range, which runs to the reserved head clamped to the term
    /// end and is closed as `PAD` if the reservation reached the term end
    /// with nothing written, else `ABORTED` with the deadline's protocol;
    /// then the write loan is released, the registration word cleared and
    /// the publication released. A half-done rotation is completed by a
    /// later duty cycle.
    ///
    /// The caller must hold a proof that the writer makes no further
    /// access, as for [`Conductor::end_subscriber`].
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidPublicationMode`] for a concurrent buffer,
    /// [`SysError::CorruptTerm`] for a block word that no writer of this
    /// buffer writes, and errors from the descriptor protocol. On error
    /// nothing is released.
    pub fn end_publication(&mut self, export: u64) -> Result<PublicationEnd, SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        if buffer.concurrent() {
            return Err(SysError::InvalidPublicationMode {
                reason: "the exclusive publication of a concurrent buffer",
            });
        }
        let word = &buffer.control().publication_registration.word;
        if !registration::names(word.load(Ordering::Acquire), export) {
            return Ok(PublicationEnd::Stale);
        }
        invalidate_claim_record(buffer.claim_serial(), buffer.claim_record());
        self.observed = None;
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let ended = resolve_pending(buffer)?;
        release_loan(&buffer.cell(0)?.loan);
        let cleared = registration::end(word, export);
        debug_assert!(cleared, "only the conductor ends a registration");
        release_publication(buffer.exclusive_released());
        Ok(ended)
    }

    /// Ended concurrent publishers whose slot is still held.
    #[must_use]
    pub fn ending_publishers(&self) -> usize {
        self.ending.len()
    }

    /// Releases the write loan and frees the slot of every ended concurrent
    /// publisher whose blocks the deadline frontier has passed.
    fn release_ended_publishers(&mut self) {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let frontier = self.deadlines.frontier_position(buffer);
        let mut index = 0;
        while let Some(ending) = self.ending.get(index).copied() {
            if frontier < ending.head {
                index += 1;
                continue;
            }
            if let Ok(cell) = buffer.cell(ending.slot) {
                release_loan(&cell.loan);
            }
            let active = buffer.active_count().load(Ordering::Acquire) as u32;
            if let Some(word) = buffer.publisher(ending.slot) {
                release_publisher_slot(word, active);
            }
            self.ending.swap_remove(index);
        }
    }

    /// Whether `cell` is still held by `occupant` in the `hold` state: it
    /// was revoked and still bounds the publisher because its loan word was
    /// held at the last scan.
    #[must_use]
    pub fn holding(&self, cell: usize, occupant: u64) -> bool {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        buffer.cells().get(cell).is_some_and(|found| {
            found.state.load(Ordering::Acquire) == CELL_LOST_HOLDING
                && registration::names(found.registration.load(Ordering::Acquire), occupant)
        })
    }

    /// Revokes the reader that occupies `cell` as `occupant`, whose client
    /// was lost, under `policy` (quantstratum-docs: `karyos/design/required-participant-loss.md`).
    /// A cell that is free or holds another occupant is left untouched
    /// ([`Revocation::Stale`]): the action outlived its participant.
    ///
    /// - A required reader under `hold` moves to `LOST_HOLDING`: it keeps
    ///   bounding the publisher until a duty cycle's scan finds its loan
    ///   word empty, or at once if this call's scan does.
    /// - A reader admitted with a reservation, under `continue`, and any
    ///   optional reader move to `LOST_RESERVED`: the bound, if any, is
    ///   withdrawn at once; a held loan stays inside the reservation.
    /// - A required reader under `abort` moves to `LOST` and the buffer is
    ///   sealed.
    ///
    /// The revocation flag stays set until the cell is freed by the
    /// reader's own detach (the detach proof); the reader's next loan
    /// attempt fails and its poll reports [`PollOutcome::Revoked`].
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Protocol`] for `continue` on a required reader
    /// admitted without a reservation, and errors from the descriptor
    /// protocol, which indicate a broken invariant.
    pub fn revoke_participant(
        &mut self,
        cell: usize,
        occupant: u64,
        policy: LossPolicy,
    ) -> Result<Revocation, SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        if cell < buffer.first_subscriber_cell() {
            return Ok(Revocation::Stale);
        }
        let Some(found) = buffer.cells().get(cell) else {
            return Ok(Revocation::Stale);
        };
        if !registration::names(found.registration.load(Ordering::Acquire), occupant) {
            return Ok(Revocation::Stale);
        }
        let state = found.state.load(Ordering::Acquire);
        let target = match (state, policy) {
            (CELL_OPTIONAL, _) | (CELL_REQUIRED_RESERVED, LossPolicy::Continue) => {
                CELL_LOST_RESERVED
            }
            (CELL_REQUIRED, LossPolicy::Hold) => CELL_LOST_HOLDING,
            (CELL_REQUIRED | CELL_REQUIRED_RESERVED, LossPolicy::Abort) => CELL_LOST,
            (CELL_REQUIRED, LossPolicy::Continue) | (CELL_REQUIRED_RESERVED, LossPolicy::Hold) => {
                return Err(SysError::Protocol {
                    reason: "the loss policy does not match the reader's admission",
                });
            }
            _ => return Ok(Revocation::Stale),
        };
        let quiescent = revoke(&found.revoked, core::slice::from_ref(&found.loan))?;
        // From the expected state only: a detach that stored FREE first
        // means the participant left and nothing was lost.
        if found
            .state
            .compare_exchange(state, target, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(Revocation::Stale);
        }
        match target {
            CELL_LOST_HOLDING if quiescent => {
                // The scan after the revocation found the word empty.
                let _ = found.state.compare_exchange(
                    CELL_LOST_HOLDING,
                    CELL_LOST,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                Ok(Revocation::Withdrawn)
            }
            CELL_LOST_HOLDING => Ok(Revocation::Holding),
            CELL_LOST => {
                self.seal()?;
                Ok(Revocation::Sealed)
            }
            _ => Ok(Revocation::Withdrawn),
        }
    }

    /// Registers the exclusive publication for a participant in another
    /// process, for export `export`: taken as
    /// [`LogBuffer::publication`] takes it, without a loan (the participant
    /// takes its own with [`Publication::adopt`]). Returns `false` when it
    /// was already issued.
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidPublicationMode`] for a concurrent buffer,
    /// [`SysError::Sealed`] for a sealed one, [`SysError::Protocol`] for
    /// export 0 or an export above [`registration::MAX_EXPORT`].
    pub fn register_publication(&mut self, export: u64) -> Result<bool, SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        if !valid_export(export) {
            return Err(NOT_GRANTED);
        }
        if buffer.concurrent() {
            return Err(SysError::InvalidPublicationMode {
                reason: "the exclusive publication of a concurrent buffer",
            });
        }
        if buffer.image() {
            return Err(SysError::InvalidPublicationMode {
                reason: "the exclusive publication of an image",
            });
        }
        if !take_publication(buffer.publication_taken()) {
            return Ok(false);
        }
        if issuer_sees_seal(buffer.seal()) {
            release_publication(buffer.exclusive_released());
            return Err(SysError::Sealed);
        }
        buffer
            .control()
            .publication_registration
            .word
            .store(export, Ordering::Release);
        Ok(true)
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

    /// Seals the buffer (`quantstratum-docs: karyos/design/publication-seal.md`): no reservation
    /// is granted from now on, and publishers return `Closed` on their next
    /// attempt that is not granted and release. An exclusive buffer's seal
    /// is positioned by a later duty cycle once its publication has
    /// released; a concurrent buffer's is fenced and positioned here
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`). A second call has no effect.
    ///
    /// # Errors
    ///
    /// Returns errors from the descriptor protocol, which indicate a broken
    /// invariant.
    pub fn seal(&mut self) -> Result<(), SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        if buffer.seal().load(Ordering::Relaxed) != 0 {
            return Ok(());
        }
        // Every reservation ends above the zero limit this stores.
        seal(buffer.seal(), buffer.limit());
        if buffer.concurrent() {
            self.context().fence()?;
        }
        Ok(())
    }

    /// The registry position of subscriber cell `cell` (Acquire), while it
    /// is attached; `None` for a detached or unknown cell. The driver's
    /// cutover lease samples it (`quantstratum-docs: karyos/design/mapping-generations.md`).
    #[must_use]
    pub fn cell_position(&self, cell: usize) -> Option<u64> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        if cell < buffer.first_subscriber_cell() {
            return None;
        }
        let cell = buffer.cells().get(cell)?;
        match cell.state.load(Ordering::Acquire) {
            CELL_REQUIRED | CELL_REQUIRED_RESERVED | CELL_OPTIONAL => {
                Some(cell.position.load(Ordering::Acquire))
            }
            _ => None,
        }
    }

    /// The publication limit (Acquire): no reservation granted from now on
    /// ends above it plus the concurrent spread, until a later duty cycle of
    /// this conductor raises it.
    #[must_use]
    pub fn limit(&self) -> u64 {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        buffer.limit().load(Ordering::Acquire)
    }

    /// The head: the end of what was reserved, capped at a positioned seal.
    ///
    /// # Errors
    ///
    /// Returns errors from the descriptor protocol, which indicate a broken
    /// invariant.
    pub fn head(&self) -> Result<u64, SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        buffer.conductor_head()
    }

    /// The buffer's seal state; retirement is computed from the attached
    /// subscribers' positions.
    #[must_use]
    pub fn seal_state(&self) -> SealState {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        match decode_seal(buffer.seal().load(Ordering::Acquire)) {
            SealWord::Active => SealState::Active,
            SealWord::Sealed => SealState::Sealed,
            SealWord::Positioned(position) => {
                let passed = buffer
                    .cells()
                    .iter()
                    .skip(buffer.first_subscriber_cell())
                    .filter(|cell| {
                        let state = cell.state.load(Ordering::Acquire);
                        bounds(state) || state == CELL_OPTIONAL
                    })
                    .all(|cell| cell.position.load(Ordering::Acquire) >= position);
                if passed {
                    SealState::Retired { position }
                } else {
                    SealState::Positioned { position }
                }
            }
        }
    }

    /// The commit-deadline abort of claims (`quantstratum-docs: karyos/design/claim-deadline.md`):
    /// times the admitted claim named by the claim record from its first
    /// observation, with `now` from a monotonic clock in the unit of
    /// `claim_deadline`, and aborts it once expired, touching only its first
    /// word 0.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::CorruptTerm`] for a record outside the term,
    /// errors from the descriptor protocol, and
    /// [`SysError::InvalidPublicationMode`] for a concurrent buffer, whose
    /// deadlines are served by [`Conductor::service_deadlines`].
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
        // concurrent buffers are served by `service_deadlines`
        // (`quantstratum-docs: karyos/design/concurrent-deadline.md`).
        if buffer.concurrent() {
            return Err(SysError::InvalidPublicationMode {
                reason: "a concurrent buffer's deadlines are served by service_deadlines",
            });
        }
        self.exclusive_deadline(clock)
    }

    /// The deadline service (`quantstratum-docs: karyos/design/concurrent-deadline.md`,
    /// Results): every outcome of this call counted in a fixed-size
    /// report. For an exclusive buffer the report is derived from the
    /// single claim of [`Conductor::abort_expired_claims_with`]; its
    /// `waiting` is set exactly when that result is `Waiting`.
    ///
    /// For a concurrent buffer it serves every expired marked block,
    /// advances the span walk and scans under fixed budgets
    /// (`quantstratum-docs: karyos/design/concurrent-deadline.md`, Work per call and bounds);
    /// `waiting` is set while an observation or a span walk remains.
    ///
    /// # Errors
    ///
    /// Returns [`DeadlineError`] carrying the effects completed before the
    /// error (a corrupt record or a broken descriptor invariant).
    pub fn service_deadlines(
        &mut self,
        clock: &mut dyn FnMut() -> u64,
    ) -> Result<DeadlineReport, DeadlineError> {
        self.service_deadlines_pausing(clock, &mut || {})
    }

    /// [`Conductor::service_deadlines`] with a test pause point after the
    /// marked blocks are served (concurrent buffers).
    fn service_deadlines_pausing(
        &mut self,
        clock: &mut dyn FnMut() -> u64,
        after_marked: &mut dyn FnMut(),
    ) -> Result<DeadlineReport, DeadlineError> {
        let mut report = DeadlineReport::default();
        #[cfg(feature = "test-hooks")]
        if self.buffer.deadline_fault.load(Ordering::Relaxed) {
            return Err(DeadlineError {
                report,
                error: SysError::ResourcesUnavailable,
            });
        }
        if self.buffer.concurrent() {
            let buffer: &LogBuffer<O::Terms> = &self.buffer;
            let result = self
                .deadlines
                .service(buffer, clock, &mut report, after_marked);
            if result.is_ok() {
                self.release_ended_publishers();
            }
            report.waiting = self.deadlines.waiting();
            return match result {
                Ok(()) => Ok(report),
                Err(error) => Err(DeadlineError { report, error }),
            };
        }
        match self.exclusive_deadline(clock) {
            Ok(ClaimDeadline::Idle) => {}
            Ok(ClaimDeadline::Waiting) => report.waiting = true,
            Ok(ClaimDeadline::ClockWentBack) => report.clock_went_back = 1,
            Ok(ClaimDeadline::Unrepresentable) => report.unrepresentable = 1,
            Ok(ClaimDeadline::Resolved) => report.resolved = 1,
            Ok(ClaimDeadline::Aborted { extent, .. }) => {
                report.aborted = 1;
                report.aborted_bytes = u64::from(extent);
            }
            Err(error) => return Err(DeadlineError { report, error }),
        }
        Ok(report)
    }

    /// The exclusive claim's deadline (`quantstratum-docs: karyos/design/claim-deadline.md`).
    fn exclusive_deadline(
        &mut self,
        clock: &mut dyn FnMut() -> u64,
    ) -> Result<ClaimDeadline, SysError> {
        let buffer: &LogBuffer<O::Terms> = &self.buffer;
        let Some((serial, record)) =
            read_claim_record(buffer.claim_serial(), buffer.claim_record())
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
            deadlines: &mut self.deadlines,
        }
    }
}

/// The conductor's state borrowed together with its buffer.
struct ConductorContext<'a, T: TermBytes> {
    buffer: &'a LogBuffer<T>,
    quarantined: &'a mut Vec<u8>,
    deadlines: &'a mut deadline::ConcurrentDeadlines,
}

impl<T: TermBytes> ConductorContext<'_, T> {
    fn subscribe(&mut self, role: Role) -> Result<Cursor, SysError> {
        self.subscribe_with(role, false, 0)
    }

    /// Admits a subscriber: `reserve` admits a required reader with a
    /// spare-slot credit (`CELL_REQUIRED_RESERVED`, for `continue`), and
    /// `occupant` is stored in the cell's registration word before the
    /// state is published.
    fn subscribe_with(
        &mut self,
        role: Role,
        reserve: bool,
        occupant: u64,
    ) -> Result<Cursor, SysError> {
        let buffer = self.buffer;
        let mut credited = 0u32;
        let mut free = None;
        for (index, cell) in buffer
            .cells()
            .iter()
            .enumerate()
            .skip(buffer.first_subscriber_cell())
        {
            match cell.state.load(Ordering::Acquire) {
                CELL_FREE if free.is_none() => free = Some(index),
                state if holds_credit(state) => credited += 1,
                _ => {}
            }
        }
        // Publisher credits are reserved for the buffer's life: 1 for the
        // exclusive publication, `P` for concurrent ones.
        let publishers = buffer.first_subscriber_cell() as u32;
        let takes_credit = role == Role::Optional || reserve;
        let credits = credited + publishers + u32::from(takes_credit);
        if credits > u32::from(buffer.spare_slots - CLEANING_HEADROOM) {
            return Err(SysError::ResourcesUnavailable);
        }
        let index = free.ok_or(SysError::ResourcesUnavailable)?;
        let cell = buffer.cell(index)?;
        // The Acquire load above observed the previous holder's FREE, so its
        // loan release happens before this reuse; its loan word is zero.
        debug_assert_eq!(cell.loan.load(Ordering::Relaxed), 0);
        cell.revoked.store(0, Ordering::Relaxed);
        cell.registration.store(occupant, Ordering::Relaxed);
        let start = buffer.conductor_head()?;
        cell.position.store(start, Ordering::Relaxed);
        let state = match (role, reserve) {
            (Role::Required, false) => CELL_REQUIRED,
            (Role::Required, true) => CELL_REQUIRED_RESERVED,
            (Role::Optional, _) => CELL_OPTIONAL,
        };
        cell.state.store(state, Ordering::Release);
        Ok(Cursor {
            cell: index,
            role,
            position: start,
            acknowledged: start,
            pending: None,
            detached: false,
            joining: buffer.image(),
        })
    }

    fn duty_cycle(&mut self) -> Result<DutyReport, SysError> {
        let mut report = DutyReport {
            bounds_withdrawn: self.rescan_revoked()?,
            ..DutyReport::default()
        };
        self.publish_floor_and_limit()?;
        self.position_seal()?;
        // A sealed buffer starts no later term.
        if self.buffer.seal().load(Ordering::Relaxed) == 0 {
            self.help_rotation()?;
        }
        self.reclaim(&mut report)?;
        self.prepare_next(&mut report)?;
        Ok(report)
    }

    /// Moves every `hold` cell whose loan word a scan finds empty to
    /// `CELL_LOST`: the revocation came before this scan, so no later
    /// acquisition succeeds, and the bound is withdrawn. Returns how many.
    fn rescan_revoked(&mut self) -> Result<u32, SysError> {
        let buffer = self.buffer;
        let mut withdrawn = 0u32;
        for cell in buffer.cells().iter().skip(buffer.first_subscriber_cell()) {
            if cell.state.load(Ordering::Acquire) == CELL_LOST_HOLDING
                && participant_quiescent(core::slice::from_ref(&cell.loan))?
                && cell
                    .state
                    .compare_exchange(
                        CELL_LOST_HOLDING,
                        CELL_LOST,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            {
                withdrawn = withdrawn.saturating_add(1);
            }
        }
        Ok(withdrawn)
    }

    /// Floor and limit from one head snapshot; the floor is published first.
    fn publish_floor_and_limit(&self) -> Result<(), SysError> {
        let buffer = self.buffer;
        let window = window(&buffer.config);
        let head = buffer.conductor_head()?;
        let mut bound = None::<u64>;
        for cell in buffer.cells().iter().skip(buffer.first_subscriber_cell()) {
            if bounds(cell.state.load(Ordering::Acquire)) {
                let position = cell.position.load(Ordering::Acquire);
                bound = Some(bound.map_or(position, |b| b.min(position)));
            }
        }
        // SPEC.md §4 retention floor: the minimum required position, or,
        // without required participants, `head_snapshot - window` bounded
        // below by position 0 through an explicit comparison.
        let (floor, base) = match bound {
            // An image keeps its floor at least half a term behind the
            // rebuild position whatever its subscribers do, so the owner can
            // compare late copies (receive-publication.md, owner decision
            // D1); a lagging required subscriber only lowers it. It never
            // goes below the join point.
            _ if buffer.image() => {
                let trailing = (head.max(window) - window).max(buffer.join());
                (
                    bound.map_or(trailing, |required| required.min(trailing)),
                    head,
                )
            }
            Some(required) => (required, required),
            // `max` bounds the subtraction at the publication start without
            // wrapping or saturating arithmetic.
            None => (head.max(window) - window, head),
        };
        // Neither the floor nor the limit ever decreases.
        let floor = floor.max(buffer.floor().load(Ordering::Relaxed));
        let limit = (base + window).max(buffer.limit().load(Ordering::Relaxed));
        buffer.floor().store(floor, Ordering::Release);
        // A sealed buffer's limit stays zero (only the conductor seals).
        if buffer.seal().load(Ordering::Relaxed) == 0 {
            buffer.limit().store(limit, Ordering::Release);
        }
        Ok(())
    }

    /// Stores an exclusive buffer's seal position once its publication has
    /// released (`quantstratum-docs: karyos/design/publication-seal.md`): it released only after
    /// observing the seal, so its Release orders every reservation it was
    /// granted before this head read, and nothing is granted after it. A
    /// concurrent buffer's seal is positioned by [`Self::fence`].
    fn position_seal(&self) -> Result<(), SysError> {
        let buffer = self.buffer;
        if buffer.concurrent()
            || decode_seal(buffer.seal().load(Ordering::Relaxed)) != SealWord::Sealed
        {
            return Ok(());
        }
        if publication_taken(buffer.publication_taken())
            && !publication_released(buffer.exclusive_released())
        {
            return Ok(());
        }
        position_seal(buffer.seal(), buffer.conductor_head()?);
        Ok(())
    }

    /// Fences a sealed concurrent buffer and positions its seal
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`): stops rotation, closes the
    /// active term's tail and stores the end of what was granted in it as
    /// the seal position. The head is capped there from then on.
    fn fence(&self) -> Result<(), SysError> {
        let buffer = self.buffer;
        let count = TermCount::try_new(fence_rotation(buffer.active_count()))?;
        let Lookup::Slot(slot) = buffer.lookup(count)? else {
            return Err(corrupt(0, "active term without a slot"));
        };
        let term_id = buffer.initial_term_id.advanced_by(count);
        let found = Descriptor::decode(buffer.descriptor(slot)?.load(Ordering::Acquire))?;
        if found.state() != SlotState::Active || found.term_id() != term_id {
            return Err(corrupt(0, "active term not active"));
        }
        let term_length = buffer.term_length;
        let old = fence_tail(buffer.tail(slot)?, term_length);
        if (old >> 32) as u32 != term_id.get() {
            return Err(corrupt(0, "fenced tail of another term"));
        }
        // Every grant in term `count` ends at or below this offset; a
        // crossing's end is clamped at the term end, where its owner pads.
        let offset = (old as u32).min(term_length);
        let position = buffer.position(count, offset);
        position_seal(buffer.seal(), position);
        Ok(())
    }

    /// Completes a full term's rotation the publication left half-done.
    fn help_rotation(&self) -> Result<(), SysError> {
        let buffer = self.buffer;
        let active = TermCount::try_new(buffer.active_count().load(Ordering::Acquire) as u32)?;
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
        let _ = buffer.active_count().compare_exchange(
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
        let floor = buffer.floor().load(Ordering::Acquire);
        let active = u64::from(active_term_count(
            buffer.active_count().load(Ordering::Acquire),
        ));
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
            // The deadline service keeps nothing of a term it cannot inspect.
            self.deadlines.forget_slot(slot);
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
        for cell in self.buffer.cells().iter() {
            if loan_held(core::slice::from_ref(&cell.loan), index, reclaiming)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Prepares `t + 1` in any FREE slot if it is not prepared yet.
    fn prepare_next(&self, report: &mut DutyReport) -> Result<(), SysError> {
        let buffer = self.buffer;
        let active = TermCount::try_new(buffer.active_count().load(Ordering::Acquire) as u32)?;
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
/// The configuration block of a buffer (`quantstratum-docs: karyos/design/ipc-log-buffer.md`):
/// a layout version, every configuration field, the generation and the
/// largest message, padded with zeros to [`CONFIG_WORDS`].
fn config_words(
    config: &LogBufferConfig,
    generation: Generation,
    max_message_length: u32,
) -> [u64; CONFIG_WORDS] {
    let (mode, publishers, allow_non_lse, join) = match config.publication {
        PublicationMode::Exclusive => (1, 0, 0, 0),
        PublicationMode::Concurrent {
            publishers,
            allow_non_lse,
        } => (2, u64::from(publishers), u64::from(allow_non_lse), 0),
        PublicationMode::Image { join } => (3, 0, 0, join),
    };
    let mut words = [0u64; CONFIG_WORDS];
    let fields = [
        LAYOUT_VERSION,
        u64::from(config.term_length.get()),
        u64::from(config.spare_slots),
        u64::from(config.max_subscribers),
        u64::from(config.mtu),
        u64::from(config.max_reserved),
        u64::from(config.initial_term_id.get()),
        u64::from(config.lane.get()),
        u64::from(config.session_id.cast_unsigned()),
        u64::from(config.stream_id.cast_unsigned()),
        config.claim_deadline,
        mode,
        publishers,
        allow_non_lse,
        u64::from(generation.get()),
        u64::from(max_message_length),
        join,
    ];
    for (word, field) in words.iter_mut().zip(fields) {
        *word = field;
    }
    words
}

/// The configuration, generation and largest message of a configuration
/// block, or `None` when a field is out of its type's range or the version
/// is unknown. Range checks of the configuration itself are left to
/// [`LogBuffer::new`]'s validation.
#[cfg(target_os = "linux")]
fn parse_config(words: &[u64; CONFIG_WORDS]) -> Option<(LogBufferConfig, Generation, u32)> {
    let [
        version,
        term_length,
        spare_slots,
        max_subscribers,
        mtu,
        max_reserved,
        initial_term_id,
        lane,
        session_id,
        stream_id,
        claim_deadline,
        mode,
        publishers,
        allow_non_lse,
        generation,
        max_message_length,
        join,
        rest @ ..,
    ] = words;
    if *version != LAYOUT_VERSION || rest.iter().any(|word| *word != 0) {
        return None;
    }
    let small = |value: &u64| u32::try_from(*value).ok();
    let publication = match (*mode, *allow_non_lse) {
        (1, 0) if *publishers == 0 && *join == 0 => PublicationMode::Exclusive,
        (2, flag @ (0 | 1)) if *join == 0 => PublicationMode::Concurrent {
            publishers: u8::try_from(*publishers).ok()?,
            allow_non_lse: flag == 1,
        },
        (3, 0) if *publishers == 0 => PublicationMode::Image { join: *join },
        _ => return None,
    };
    let config = LogBufferConfig {
        term_length: TermLength::try_new(small(term_length)?).ok()?,
        spare_slots: u8::try_from(*spare_slots).ok()?,
        max_subscribers: u8::try_from(*max_subscribers).ok()?,
        mtu: small(mtu)?,
        max_reserved: small(max_reserved)?,
        initial_term_id: TermId::new(small(initial_term_id)?),
        lane: Lane::try_new(u8::try_from(*lane).ok()?).ok()?,
        session_id: small(session_id)?.cast_signed(),
        stream_id: small(stream_id)?.cast_signed(),
        claim_deadline: *claim_deadline,
        publication,
    };
    Some((
        config,
        Generation::try_new(small(generation)?).ok()?,
        small(max_message_length)?,
    ))
}

/// The layout version of the shared log buffer region.
pub const LAYOUT_VERSION: u64 = 1;

#[cfg(test)]
mod heap_tests {
    use super::*;

    type Terms = HeapTerms;

    fn new_buffer(config: LogBufferConfig) -> Result<LogBuffer<Terms>, SysError> {
        LogBuffer::new(config)
    }

    fn new_buffer_with_generation(
        config: LogBufferConfig,
        generation: Generation,
    ) -> Result<LogBuffer<Terms>, SysError> {
        LogBuffer::new_with_generation(config, generation)
    }

    include!("log_buffer_tests/common.rs");
    include!("log_buffer_tests/seal.rs");
    include!("log_buffer_tests/adoption.rs");
    include!("log_buffer_tests/contracts.rs");
    include!("log_buffer_tests/loss.rs");
}

#[cfg(test)]
mod shared_tests {
    use super::*;

    type Terms = SharedTerms;

    fn new_buffer(config: LogBufferConfig) -> Result<LogBuffer<Terms>, SysError> {
        LogBuffer::new_shared(config)
    }

    fn new_buffer_with_generation(
        config: LogBufferConfig,
        generation: Generation,
    ) -> Result<LogBuffer<Terms>, SysError> {
        LogBuffer::new_shared_with_generation(config, generation)
    }

    include!("log_buffer_tests/common.rs");
    include!("log_buffer_tests/seal.rs");
    include!("log_buffer_tests/adoption.rs");
    include!("log_buffer_tests/contracts.rs");
    include!("log_buffer_tests/loss.rs");

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
                let words = &buffer.regions;
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
                    if let Some(word) = words.test_word(index) {
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

// A buffer in a shared region, attached through a passed descriptor
// (`quantstratum-docs: karyos/design/ipc-log-buffer.md`), in one process on Linux.
#[cfg(all(test, target_os = "linux", not(miri)))]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod region_tests {
    use super::*;
    use crate::ipc::{Recv, Region, RegionKind, RegionRecord, Sent, recv, send, seqpacket_pair};
    use crate::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH};
    use rustix::fd::AsFd;

    fn config(publication: PublicationMode) -> LogBufferConfig {
        LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 4,
            max_subscribers: 3,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: DEFAULT_CLAIM_DEADLINE,
            publication,
        }
    }

    fn generation() -> Generation {
        Generation::try_new(3).unwrap()
    }

    /// Passes the creator's region descriptor over a socket pair and
    /// attaches it as a participant would.
    fn attach(creator: &LogBuffer<SharedTerms>) -> Result<LogBuffer<SharedTerms>, SysError> {
        let region = creator.region().unwrap();
        let (a, b) = seqpacket_pair().unwrap();
        assert_eq!(
            send(a.as_fd(), b"lb", region.descriptor()).unwrap(),
            Sent::Sent
        );
        let mut buffer = [0u8; 8];
        let Recv::Message(received) = recv(b.as_fd(), &mut buffer).unwrap() else {
            panic!("no message");
        };
        let attached = Region::attach(received.fd.unwrap(), region.record())?;
        LogBuffer::attach(attached)
    }

    #[test]
    fn a_participant_attaches_adopts_and_exchanges_messages() {
        let creator = Arc::new(
            LogBuffer::create_in(1, 5, config(PublicationMode::Exclusive), generation()).unwrap(),
        );
        let mut conductor = creator.conductor_owned().unwrap();
        assert!(conductor.register_publication(31).unwrap());
        let cell = conductor.register_subscriber(Role::Required, 32).unwrap();
        let participant = Arc::new(attach(&creator).unwrap());
        assert_eq!(participant.generation(), generation());
        assert!(participant.conductor_owned().is_none());
        let mut writer = Publication::adopt(Arc::clone(&participant), 31).unwrap();
        let mut reader =
            Subscription::adopt(Arc::clone(&creator), cell, Role::Required, 32).unwrap();
        let mut out = vec![0u8; 8192];
        for round in 0..600u32 {
            let payload = round.to_le_bytes().repeat(100);
            loop {
                match writer.append(&payload, AppendOptions::default()).unwrap() {
                    AppendOutcome::Appended { .. } => break,
                    _ => {
                        // Drain and let the creator's conductor rotate.
                        while let PollOutcome::Message { .. } = reader.poll(&mut out).unwrap() {
                            reader.acknowledge();
                        }
                        let _ = conductor.duty_cycle().unwrap();
                    }
                }
            }
            match reader.poll(&mut out).unwrap() {
                PollOutcome::Message { length, .. } => {
                    assert_eq!(&out[..length as usize], payload.as_slice());
                    reader.acknowledge();
                }
                other => panic!("round {round}: {other:?}"),
            }
            let _ = conductor.duty_cycle().unwrap();
        }
        // Many rotations through the shared slots.
        assert!(creator.active_count().load(Ordering::Acquire) >= 2);
    }

    #[test]
    fn concurrent_handles_adopted_on_both_sides_share_one_buffer() {
        let mode = PublicationMode::Concurrent {
            publishers: 2,
            allow_non_lse: true,
        };
        let creator = Arc::new(LogBuffer::create_in(1, 6, config(mode), generation()).unwrap());
        let mut conductor = creator.conductor_owned().unwrap();
        let mut reader = conductor.subscribe(Role::Optional).unwrap();
        let slot = conductor
            .register_concurrent_publication(41)
            .unwrap()
            .unwrap();
        let local = conductor.concurrent_publication().unwrap().unwrap();
        let participant = Arc::new(attach(&creator).unwrap());
        let mut remote = ConcurrentPublication::adopt(Arc::clone(&participant), slot, 41).unwrap();
        let mut local = local;
        for (handle, payload) in [(&mut remote, b"remote"), (&mut local, b"local!")] {
            assert!(matches!(
                handle.offer(payload, AppendOptions::default()).unwrap(),
                ConcurrentOfferOutcome::Appended { .. }
            ));
        }
        let mut out = vec![0u8; 64];
        let mut seen = Vec::new();
        while let PollOutcome::Message { length, .. } = reader.poll(&mut out).unwrap() {
            seen.push(out[..length as usize].to_vec());
        }
        assert_eq!(seen, vec![b"remote".to_vec(), b"local!".to_vec()]);
    }

    #[test]
    fn attach_refuses_a_configuration_block_that_does_not_validate() {
        let creator =
            LogBuffer::create_in(1, 7, config(PublicationMode::Exclusive), generation()).unwrap();
        // Valid as created.
        assert!(attach(&creator).is_ok());
        let structure = creator.region().unwrap().structure();
        let corrupt = |index: usize, value: u64| {
            let word = structure.get(index).unwrap();
            let before = word.swap(value, Ordering::AcqRel);
            let result = attach(&creator);
            word.store(before, Ordering::Release);
            result
        };
        // Version, term length, spare slots beyond the slot bound, a zero
        // claim deadline, an unknown mode, a generation that differs from
        // the region's, a largest message that differs, a trailing word.
        for (index, value) in [
            (0, 2),
            (1, 1000),
            (2, 200),
            (10, 0),
            (11, 3),
            (14, 4),
            (15, 1),
            (20, 1),
        ] {
            assert!(
                corrupt(index, value).is_err(),
                "word {index} = {value} accepted"
            );
        }
        // More subscribers than the region holds: the layout no longer fits.
        assert!(corrupt(3, 9).is_err());
        // A record of another kind or generation never attaches (the
        // header check of the region).
        let region = creator.region().unwrap();
        let other = RegionRecord {
            kind: RegionKind::Counters,
            ..region.record()
        };
        let (a, b) = seqpacket_pair().unwrap();
        assert_eq!(
            send(a.as_fd(), b"lb", region.descriptor()).unwrap(),
            Sent::Sent
        );
        let mut buffer = [0u8; 8];
        let Recv::Message(received) = recv(b.as_fd(), &mut buffer).unwrap() else {
            panic!("no message");
        };
        assert!(Region::attach(received.fd.unwrap(), other).is_err());
    }

    /// A self-consistent region of another kind whose structure holds a
    /// valid log buffer layout passes the region's own header check, and
    /// is refused by the kind gate of `LogBuffer::attach`.
    #[test]
    fn attach_refuses_a_region_of_another_kind() {
        let creator =
            LogBuffer::create_in(1, 7, config(PublicationMode::Exclusive), generation()).unwrap();
        let record = creator.region().unwrap().record();
        let imposter = Region::create(RegionRecord {
            kind: RegionKind::Counters,
            region: 8,
            ..record
        })
        .unwrap();
        let source = creator.region().unwrap().structure();
        let target = imposter.structure();
        for index in 0..CONFIG_WORDS {
            let value = source.get(index).unwrap().load(Ordering::Acquire);
            target.get(index).unwrap().store(value, Ordering::Release);
        }
        let (a, b) = seqpacket_pair().unwrap();
        assert_eq!(
            send(a.as_fd(), b"lb", imposter.descriptor()).unwrap(),
            Sent::Sent
        );
        let mut buffer = [0u8; 8];
        let Recv::Message(received) = recv(b.as_fd(), &mut buffer).unwrap() else {
            panic!("no message");
        };
        let attached = Region::attach(received.fd.unwrap(), imposter.record()).unwrap();
        assert!(matches!(
            LogBuffer::attach(attached),
            Err(SysError::InvalidRegion { .. })
        ));
    }
}
