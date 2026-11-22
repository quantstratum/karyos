// SPDX-License-Identifier: Apache-2.0

//! The shared outcome ring of a guarded or scheduled incarnation with
//! concurrent handles (ADR-0092; `quantstratum-docs:
//! karyos/design/guards-and-abort.md`, "Concurrent guarded and scheduled
//! publications (GC-7 lifted)").
//!
//! - **Layout version 3.** Header words 0 to 13 keep their version 2
//!   meanings, word 2 being each handle's message quota `C_m`; word 14 is
//!   the handle slot count `H`. The ring holds `H * C_m + C_r + H` records.
//! - **One client.** Every handle of the incarnation belongs to one client
//!   (ADR-0092 decision 2); the driver enforces that at admission, not here.
//! - **Room budget.** An ordinary record is written while fewer than
//!   `H * C_m + C_r` records are unread against the minimum consumed count
//!   of the attached, unfaulted handles; an `OutcomesLost` record while
//!   fewer than `H * C_m + C_r + H` are, at most one per handle.
//! - **Faults, in order.** A record that finds no room faults every handle
//!   at the minimum, ties included, in slot order, each with one
//!   `OutcomesLost` record naming its slot plus 1 in word 1 bits 32 to 39
//!   and an unknown lost count; the minimum is then recomputed and the
//!   record retried. An invalid consumed count faults its handle the same
//!   way first.
//! - **Reading.** A handle delivers the message records of the
//!   `(lane, start)` pairs it reserved, every range-side record, and the
//!   `OutcomesLost` record that names it, which ends its stream; it skips
//!   every other record. Its consumed count is the last sequence it read,
//!   delivered or skipped. A faulted handle leaves the minimum, so the
//!   others may lap it: a reader that finds a later round's record in the
//!   slot it expects was faulted, and its stream ends there as at its
//!   overwritten `OutcomesLost` record, the lost count unknown.

use super::{
    CAPACITY, EPOCH, GUARD_INDEX, HEADER_WORDS, Kind, LOST_UNKNOWN, MESSAGES, OutcomeError, RANGES,
    Record, VERSION, check_layout, slot_base, write,
};
use crate::load_words::LoadWords;
use crate::sync::{AtomicU64, Ordering};

/// The shared ring's layout version.
pub const SHARED_OUTCOME_LAYOUT_VERSION: u64 = 3;
/// Header word: `H`, the handle slot count.
pub const HANDLES: usize = 14;
/// The most handle slots a shared ring has.
pub const MAX_HANDLES: u64 = 64;
/// Word 1 bits of an `OutcomesLost` record that name its handle.
const HANDLE_SHIFT: u32 = 32;
const HANDLE_MASK: u64 = 0xFF << HANDLE_SHIFT;

const _: () = assert!(HANDLES > super::REINCARNATED_AT && HANDLES < HEADER_WORDS);

/// What a shared ring's header says of its incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedBinding {
    /// `C_m`, each handle's message quota.
    pub messages: u64,
    /// `C_r`, the incarnation's range capacity.
    pub ranges: u64,
    /// The guard's word index in the guard region.
    pub guard_index: u64,
    /// The open epoch the incarnation is bound to.
    pub epoch: u64,
    /// `H`, the handle slots, 1 to [`MAX_HANDLES`].
    pub handles: u64,
}

impl SharedBinding {
    /// `H * C_m + C_r`: the room bound of an ordinary record; `None` on
    /// overflow.
    #[must_use]
    pub const fn ordinary_bound(&self) -> Option<u64> {
        match self.handles.checked_mul(self.messages) {
            Some(quotas) => quotas.checked_add(self.ranges),
            None => None,
        }
    }

    /// The slot count, `H * C_m + C_r + H`; `None` on overflow or for a
    /// handle count outside 1 to [`MAX_HANDLES`].
    #[must_use]
    pub const fn capacity(&self) -> Option<u64> {
        if self.handles == 0 || self.handles > MAX_HANDLES {
            return None;
        }
        match self.ordinary_bound() {
            Some(bound) => bound.checked_add(self.handles),
            None => None,
        }
    }
}

/// Writes the header of a new shared ring for `binding`, its reserved
/// words zeroed (the rate policy slot, words 6 to 12, and word 13 read as
/// "none" and "first incarnation" until written). Control path, before the
/// region is shared.
///
/// # Errors
///
/// [`OutcomeError::Layout`] when the binding has no valid slot count or
/// `ring` is too small for it.
pub fn init(ring: &[AtomicU64], binding: &SharedBinding) -> Result<(), OutcomeError> {
    let capacity = binding.capacity().ok_or(OutcomeError::Layout)?;
    check_layout(ring.len(), capacity)?;
    for cell in ring.iter().take(HEADER_WORDS) {
        cell.store(0, Ordering::Relaxed);
    }
    for (word, value) in [
        (VERSION, SHARED_OUTCOME_LAYOUT_VERSION),
        (CAPACITY, capacity),
        (MESSAGES, binding.messages),
        (RANGES, binding.ranges),
        (GUARD_INDEX, binding.guard_index),
        (EPOCH, binding.epoch),
        (HANDLES, binding.handles),
    ] {
        if let Some(cell) = ring.get(word) {
            cell.store(value, Ordering::Relaxed);
        }
    }
    Ok(())
}

/// The binding a shared ring's header names, checked for a client given
/// `guard_words` guard words: version 3, the slot count `H * C_m + C_r +
/// H`, the guard's index within them and an open epoch.
///
/// # Errors
///
/// [`OutcomeError::Version`] for another layout version;
/// [`OutcomeError::Layout`] for a header that breaks these.
pub fn binding(
    ring: &(impl LoadWords + ?Sized),
    guard_words: usize,
) -> Result<SharedBinding, OutcomeError> {
    let version = ring.load_acquire(VERSION).ok_or(OutcomeError::Layout)?;
    if version != SHARED_OUTCOME_LAYOUT_VERSION {
        return Err(OutcomeError::Version(version));
    }
    let word = |index| ring.load(index).ok_or(OutcomeError::Layout);
    let binding = SharedBinding {
        messages: word(MESSAGES)?,
        ranges: word(RANGES)?,
        guard_index: word(GUARD_INDEX)?,
        epoch: word(EPOCH)?,
        handles: word(HANDLES)?,
    };
    let capacity = word(CAPACITY)?;
    let index_fits = usize::try_from(binding.guard_index).is_ok_and(|index| index < guard_words);
    if binding.capacity() != Some(capacity)
        || !index_fits
        || binding.epoch == 0
        || !binding.epoch.is_multiple_of(2)
    {
        return Err(OutcomeError::Layout);
    }
    check_layout(ring.len(), capacity)?;
    Ok(binding)
}

/// The `OutcomesLost` record's word 1 naming handle `slot`.
fn lost_word1(slot: u64) -> Option<u64> {
    let field = slot.checked_add(1)?;
    (field <= MAX_HANDLES).then_some(u64::from(Kind::OutcomesLost as u8) | (field << HANDLE_SHIFT))
}

/// The fields of the `OutcomesLost` record of handle `slot`.
fn lost_fields(slot: u64) -> Option<[u64; 7]> {
    Some([lost_word1(slot)?, 0, 0, 0, 0, 0, LOST_UNKNOWN])
}

/// One handle's state in the writer.
#[derive(Debug, Clone, Copy, Default)]
struct HandleState {
    /// Admitted and not detached.
    attached: bool,
    /// Ever admitted in this incarnation: a slot is never reused.
    used: bool,
    /// Faulted: its stream ended at its `OutcomesLost` record.
    faulted: bool,
    /// The last consumed count validated.
    consumed: u64,
}

impl HandleState {
    const fn live(&self) -> bool {
        self.attached && !self.faulted
    }
}

/// What [`SharedOutcomeWriter::produce`] did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedProduced {
    /// Written with this sequence.
    Written(u64),
    /// No handle is live: the record is counted, not written.
    Unread,
}

/// The driver's writer of one shared ring. Nothing waits: a record is
/// written at once, after faulting the handles that hold it back.
#[derive(Debug)]
pub struct SharedOutcomeWriter {
    capacity: u64,
    ordinary_bound: u64,
    written: u64,
    handles: Vec<HandleState>,
    /// Records counted while no handle was live.
    unread: u64,
}

impl SharedOutcomeWriter {
    /// A writer for a ring of `binding` (control path: allocates its handle
    /// table).
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Layout`] for a binding with no valid slot count.
    pub fn new(binding: &SharedBinding) -> Result<Self, OutcomeError> {
        let capacity = binding.capacity().ok_or(OutcomeError::Layout)?;
        let ordinary_bound = binding.ordinary_bound().ok_or(OutcomeError::Layout)?;
        let slots = usize::try_from(binding.handles).map_err(|_| OutcomeError::Layout)?;
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(slots)
            .map_err(|_| OutcomeError::Layout)?;
        handles.resize(slots, HandleState::default());
        Ok(Self {
            capacity,
            ordinary_bound,
            written: 0,
            handles,
            unread: 0,
        })
    }

    /// Admits handle `slot`, whose consumed count starts at the last
    /// sequence written: it reads only later records.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Layout`] for a slot outside the table or one already
    /// used in this incarnation.
    pub fn attach(&mut self, slot: usize) -> Result<u64, OutcomeError> {
        let written = self.written;
        let state = self.handles.get_mut(slot).ok_or(OutcomeError::Layout)?;
        if state.used {
            return Err(OutcomeError::Layout);
        }
        *state = HandleState {
            attached: true,
            used: true,
            faulted: false,
            consumed: written,
        };
        Ok(written)
    }

    /// Takes back slot `slot`, attached and never issued: its handle's
    /// setup failed before it existed, so no handle has read or reserved
    /// through it, and the slot is free for the next handle (ADR-0092
    /// decision 3: a slot index still names at most one handle). Returns
    /// whether it was taken back; a slot not attached, or faulted, stays
    /// as it is.
    pub fn revoke(&mut self, slot: usize) -> bool {
        match self.handles.get_mut(slot) {
            Some(state) if state.attached && !state.faulted => {
                *state = HandleState::default();
                true
            }
            _ => false,
        }
    }

    /// Detaches handle `slot`: it leaves the minimum. Its slot stays used.
    pub fn detach(&mut self, slot: usize) {
        if let Some(state) = self.handles.get_mut(slot) {
            state.attached = false;
        }
    }

    /// Whether handle `slot` was faulted.
    #[must_use]
    pub fn faulted(&self, slot: usize) -> bool {
        self.handles.get(slot).is_some_and(|state| state.faulted)
    }

    /// Records counted while no handle was live.
    #[must_use]
    pub fn unread(&self) -> u64 {
        self.unread
    }

    /// The last sequence written.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Produces `record` (never `OutcomesLost`): validates each live
    /// handle's consumed cell (`cells[slot]`), faulting an invalid one;
    /// then, while the record finds no room against the minimum, faults
    /// every handle at it, in slot order; then writes the record, or counts
    /// it when no handle is live.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Layout`] for a record that breaks the layout, an
    /// `OutcomesLost` record, a cell table shorter than the handle table or
    /// a ring shorter than its capacity; [`OutcomeError::Exhausted`] when a
    /// sequence would overflow.
    pub fn produce(
        &mut self,
        ring: &[AtomicU64],
        cells: &[&AtomicU64],
        record: Record,
    ) -> Result<SharedProduced, OutcomeError> {
        if record.kind == Kind::OutcomesLost || cells.len() < self.handles.len() {
            return Err(OutcomeError::Layout);
        }
        let fields = record.fields().ok_or(OutcomeError::Layout)?;
        for slot in 0..self.handles.len() {
            let live = self.handles.get(slot).is_some_and(HandleState::live);
            let cell = cells.get(slot).ok_or(OutcomeError::Layout)?;
            if live && !self.read_consumed(slot, cell) {
                self.fault(ring, slot)?;
            }
        }
        // Each pass faults at least one handle, so at most `H + 1` passes.
        for _ in 0..=self.handles.len() {
            let Some(minimum) = self.minimum() else {
                self.unread = self.unread.checked_add(1).ok_or(OutcomeError::Exhausted)?;
                return Ok(SharedProduced::Unread);
            };
            // `written - minimum` never underflows: a validated count is at
            // most `written`.
            if self.written - minimum < self.ordinary_bound {
                let sequence = self.written.checked_add(1).ok_or(OutcomeError::Exhausted)?;
                if !write(ring, self.capacity, sequence, fields) {
                    return Err(OutcomeError::Layout);
                }
                self.written = sequence;
                return Ok(SharedProduced::Written(sequence));
            }
            for slot in 0..self.handles.len() {
                let at_minimum = self
                    .handles
                    .get(slot)
                    .is_some_and(|state| state.live() && state.consumed == minimum);
                if at_minimum {
                    self.fault(ring, slot)?;
                }
            }
        }
        Err(OutcomeError::Layout)
    }

    /// Faults every live handle, in slot order, each with its
    /// `OutcomesLost` record and an unknown lost count: the walker was
    /// lapped (a broken invariant), so nothing more is recorded for them.
    /// Every fault finds room: a produced record leaves at most `H * C_m +
    /// C_r` unread, and each fault adds one within the extra `H`.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Layout`] for a ring shorter than its capacity and
    /// [`OutcomeError::Exhausted`] when a sequence would overflow.
    pub fn abandon(&mut self, ring: &[AtomicU64]) -> Result<(), OutcomeError> {
        for slot in 0..self.handles.len() {
            if self.handles.get(slot).is_some_and(HandleState::live) {
                self.fault(ring, slot)?;
            }
        }
        Ok(())
    }

    /// The minimum consumed count of the live handles.
    fn minimum(&self) -> Option<u64> {
        self.handles
            .iter()
            .filter(|state| state.live())
            .map(|state| state.consumed)
            .min()
    }

    /// Validates handle `slot`'s cell (Acquire): monotonic, at most the
    /// last sequence written.
    fn read_consumed(&mut self, slot: usize, cell: &AtomicU64) -> bool {
        let written = self.written;
        let Some(state) = self.handles.get_mut(slot) else {
            return false;
        };
        let count = cell.load(Ordering::Acquire);
        if count < state.consumed || count > written {
            return false;
        }
        state.consumed = count;
        true
    }

    /// Faults handle `slot` with its `OutcomesLost` record, written within
    /// the extra `H` records of room: fewer than `capacity` are unread
    /// against the minimum, which still counts this handle.
    fn fault(&mut self, ring: &[AtomicU64], slot: usize) -> Result<(), OutcomeError> {
        let minimum = self.minimum().unwrap_or(self.written);
        if self.written - minimum >= self.capacity {
            return Err(OutcomeError::Layout);
        }
        let fields = u64::try_from(slot)
            .ok()
            .and_then(lost_fields)
            .ok_or(OutcomeError::Layout)?;
        let sequence = self.written.checked_add(1).ok_or(OutcomeError::Exhausted)?;
        if !write(ring, self.capacity, sequence, fields) {
            return Err(OutcomeError::Layout);
        }
        self.written = sequence;
        if let Some(state) = self.handles.get_mut(slot) {
            state.faulted = true;
        }
        Ok(())
    }
}

/// The end a lapped handle reads in place of its overwritten
/// `OutcomesLost` record: the same kind, the lost count unknown.
const fn lapped_end() -> Record {
    Record {
        kind: Kind::OutcomesLost,
        lane: 0,
        receiver: 0,
        incarnation: 0,
        start: 0,
        end: 0,
        epoch: 0,
        reason: 0,
        lost: LOST_UNKNOWN,
    }
}

/// What a handle's reader made of one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedRecord {
    /// A record for this handle.
    Delivered(Record),
    /// Another handle's record, read and skipped.
    Skipped,
}

/// One handle's reader of a shared ring.
#[derive(Debug)]
pub struct SharedOutcomeReader {
    capacity: u64,
    lanes: u8,
    handles: u64,
    slot: u64,
    /// The `(lane, start)` pairs this handle reserved, at most `C_m`.
    reserved: Vec<(u8, u64)>,
    quota: usize,
    next: u64,
    ended: bool,
}

impl SharedOutcomeReader {
    /// A reader of `ring` for handle `slot` of a publication of `lanes`
    /// lanes, reading from the record after `after` (the sequence written
    /// when the handle was admitted). Allocates its reserved set of `C_m`
    /// pairs.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Version`] for another layout version;
    /// [`OutcomeError::Layout`] for a header, slot or lane count it cannot
    /// read.
    pub fn attach(
        ring: &(impl LoadWords + ?Sized),
        lanes: u8,
        slot: u64,
        after: u64,
    ) -> Result<Self, OutcomeError> {
        let version = ring.load_acquire(VERSION).ok_or(OutcomeError::Layout)?;
        if version != SHARED_OUTCOME_LAYOUT_VERSION {
            return Err(OutcomeError::Version(version));
        }
        let word = |index| ring.load(index).ok_or(OutcomeError::Layout);
        let binding = SharedBinding {
            messages: word(MESSAGES)?,
            ranges: word(RANGES)?,
            guard_index: word(GUARD_INDEX)?,
            epoch: word(EPOCH)?,
            handles: word(HANDLES)?,
        };
        let capacity = word(CAPACITY)?;
        if binding.capacity() != Some(capacity)
            || slot >= binding.handles
            || lanes == 0
            || lanes > 4
        {
            return Err(OutcomeError::Layout);
        }
        check_layout(ring.len(), capacity)?;
        let quota = usize::try_from(binding.messages).map_err(|_| OutcomeError::Layout)?;
        let mut reserved = Vec::new();
        reserved
            .try_reserve_exact(quota)
            .map_err(|_| OutcomeError::Layout)?;
        Ok(Self {
            capacity,
            lanes,
            handles: binding.handles,
            slot,
            reserved,
            quota,
            next: after.checked_add(1).ok_or(OutcomeError::Exhausted)?,
            ended: false,
        })
    }

    /// Records a block this handle reserved at `start` on `lane`; `false`
    /// when the quota `C_m` is reached (the caller answers `BackPressured`).
    #[must_use]
    pub fn reserve(&mut self, lane: u8, start: u64) -> bool {
        if self.reserved.len() >= self.quota {
            return false;
        }
        self.reserved.push((lane, start));
        true
    }

    /// Blocks reserved without a final record read yet.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.reserved.len()
    }

    /// Whether this handle's `OutcomesLost` record was read.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// Reads up to `limit` records in sequence order, handing each to
    /// `handler` as delivered or skipped, and publishes the consumed count
    /// (Release) after each. Returns how many were read.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Corrupt`] for a record that breaks the layout, an
    /// `OutcomesLost` record naming no slot of the ring, or a slot holding
    /// anything but the expected sequence or the record it replaces.
    pub fn poll(
        &mut self,
        ring: &(impl LoadWords + ?Sized),
        consumed: &AtomicU64,
        limit: usize,
        mut handler: impl FnMut(u64, SharedRecord),
    ) -> Result<usize, OutcomeError> {
        let mut read = 0;
        while read < limit && !self.ended {
            let sequence = self.next;
            let corrupt = OutcomeError::Corrupt { sequence };
            let base = slot_base(self.capacity, sequence).ok_or(corrupt)?;
            let head = ring.load_acquire(base).ok_or(corrupt)?;
            if head != sequence {
                let pending = match sequence.checked_sub(self.capacity) {
                    Some(previous) => head == previous,
                    None => head == 0,
                };
                if pending {
                    break;
                }
                if head > sequence && (head - sequence).is_multiple_of(self.capacity) {
                    // Lapped: the writer never overwrites a record a live
                    // handle has not read (its room check counts every live
                    // handle), so this handle was faulted and left the
                    // minimum, and its `OutcomesLost` record was written
                    // over (ADR-0092 decision 7). Its stream ends here, as
                    // at that record, with the lost count unknown.
                    self.ended = true;
                    handler(sequence, SharedRecord::Delivered(lapped_end()));
                    read += 1;
                    break;
                }
                return Err(corrupt);
            }
            let mut fields = [0u64; 7];
            for (index, field) in (1..).zip(fields.iter_mut()) {
                let word = base.checked_add(index).ok_or(corrupt)?;
                *field = ring.load(word).ok_or(corrupt)?;
            }
            let outcome = self.classify(fields).ok_or(corrupt)?;
            handler(sequence, outcome);
            consumed.store(sequence, Ordering::Release);
            self.next = sequence.checked_add(1).ok_or(OutcomeError::Exhausted)?;
            read += 1;
        }
        Ok(read)
    }

    /// Decodes `fields` and decides whether this handle delivers them.
    fn classify(&mut self, fields: [u64; 7]) -> Option<SharedRecord> {
        let [word1, rest @ ..] = fields;
        let handle = (word1 & HANDLE_MASK) >> HANDLE_SHIFT;
        let [incarnation, start, end, epoch, reason, lost] = rest;
        let fields = [
            word1 & !HANDLE_MASK,
            incarnation,
            start,
            end,
            epoch,
            reason,
            lost,
        ];
        let record = Record::decode(fields, self.lanes)?;
        if record.kind == Kind::OutcomesLost {
            if handle == 0 || handle > self.handles {
                return None;
            }
            if handle == self.slot.checked_add(1)? {
                self.ended = true;
                return Some(SharedRecord::Delivered(record));
            }
            return Some(SharedRecord::Skipped);
        }
        if handle != 0 {
            return None;
        }
        if record.kind.is_range() {
            return Some(SharedRecord::Delivered(record));
        }
        match self
            .reserved
            .iter()
            .position(|&pair| pair == (record.lane, record.start))
        {
            Some(index) => {
                let _ = self.reserved.swap_remove(index);
                Some(SharedRecord::Delivered(record))
            }
            None => Some(SharedRecord::Skipped),
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests;
