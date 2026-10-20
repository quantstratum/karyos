// SPDX-License-Identifier: Apache-2.0

//! The outcome ring of a guarded or scheduled publication handle
//! (`quantstratum-docs: karyos/design/guards-and-abort.md`, "The outcome
//! stream", G5, and GC-4).
//!
//! - **Placement.** The driver writes the ring and the client maps it
//!   read-only; the client never writes it. The client publishes the
//!   sequence of the last record it consumed in a cell it owns (the
//!   consumed cell), which the driver reads.
//! - **Layout.** A header of [`HEADER_WORDS`] words (word 0 the layout
//!   version, word 1 the slot count, words 2 to 5 the handle's
//!   [`Binding`], the rest reserved and zero), then `capacity` records of
//!   [`RECORD_WORDS`] words. Record `seq` (from 1, gapless) lives in slot
//!   `(seq - 1) mod capacity`. Word 0 of a record is its sequence; words 1
//!   to 7 are its fields.
//! - **Writing.** The driver stores a record's fields with Relaxed stores,
//!   then its sequence with Release. It writes an ordinary record only
//!   while fewer than `capacity - 1` are unread, so the last slot is always
//!   free for the one `OutcomesLost` record of a faulted client. A record
//!   that finds no room faults the client (below): the room check and the
//!   lag fault are one bound, so nothing is ever deferred.
//! - **The consumed count.** The driver loads the consumed cell with
//!   Acquire before every write and validates it: monotonic, and at most
//!   the last sequence written. The client stores it with Release only
//!   after it has read the records it counts, so a slot is never rewritten
//!   while its record is being read. An invalid count, or a client so far
//!   behind that the records produced minus its count would exceed
//!   `capacity - 1`, faults it: the driver writes one final `OutcomesLost`
//!   record against the last count it validated, counting the record that
//!   faulted it, then stops writing and only counts later records.
//! - **Reading.** The reader loads a slot's word 0 with Acquire; when it
//!   is the next expected sequence, the fields are complete. It validates
//!   them, hands the record to the handler, and only then publishes the
//!   consumed count, so a panicking handler gets the record again.

use crate::load_words::LoadWords;
use crate::sync::{AtomicU64, Ordering};

/// The writer's load of the consumed count: Acquire, so a slot is reused
/// only after the client's reads of it. One constant for every build, so
/// the Loom controls weaken exactly the ordering production uses.
const CONSUMED_LOAD: Ordering = Ordering::Acquire;
/// The client's store of the consumed count: Release, after its reads.
const CONSUMED_STORE: Ordering = Ordering::Release;

/// The outcome ring's layout version: 2 (unreleased) names the handle's
/// binding in header words 2 to 5 (`quantstratum-docs:
/// karyos/design/guards-and-abort.md`, "The binding across processes",
/// G-x1).
pub const OUTCOME_LAYOUT_VERSION: u64 = 2;
/// The consumed cell region's layout version (`ConsumedCell`, G-x2):
/// the client's consumed count in word 0, the rest reserved.
pub const CONSUMED_CELL_LAYOUT_VERSION: u64 = 1;
/// Words of the header stride.
pub const HEADER_WORDS: usize = 16;
/// Words of one record: 64 bytes.
pub const RECORD_WORDS: usize = 8;
/// Header word: the layout version.
const VERSION: usize = 0;
/// Header word: the slot count.
const CAPACITY: usize = 1;
/// Header word: `C_m`, the message capacity.
const MESSAGES: usize = 2;
/// Header word: `C_r`, the range capacity.
const RANGES: usize = 3;
/// Header word: the guard's word index in the guard region.
const GUARD_INDEX: usize = 4;
/// Header word: the open epoch the handle was admitted under.
const EPOCH: usize = 5;

/// Words of a ring of `capacity` slots, header included; `None` on
/// overflow.
#[must_use]
pub const fn ring_words(capacity: usize) -> Option<usize> {
    match capacity.checked_mul(RECORD_WORDS) {
        Some(records) => records.checked_add(HEADER_WORDS),
        None => None,
    }
}

/// The slot count for `messages` message records and `ranges` range
/// records (`C_m + C_r + 1`); `None` on overflow.
#[must_use]
pub const fn capacity(messages: u64, ranges: u64) -> Option<u64> {
    match messages.checked_add(ranges) {
        Some(records) => records.checked_add(1),
        None => None,
    }
}

/// What a ring's header says of its handle (header words 2 to 5): the
/// driver writes it at creation, before the region is granted, and a
/// client reads it to bind the handle across processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// `C_m`, the message capacity.
    pub messages: u64,
    /// `C_r`, the range capacity.
    pub ranges: u64,
    /// The guard's word index in the guard region.
    pub guard_index: u64,
    /// The open epoch the handle was admitted under.
    pub epoch: u64,
}

impl Binding {
    /// The ring's slot count, `C_m + C_r + 1`; `None` on overflow.
    #[must_use]
    pub const fn capacity(&self) -> Option<u64> {
        capacity(self.messages, self.ranges)
    }
}

/// Why a ring operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OutcomeError {
    /// The words are too few for the header and the slot count, or the
    /// slot count is below 2.
    #[error("the outcome ring layout is invalid")]
    Layout,
    /// The header names a layout version this build does not know.
    #[error("outcome layout version {0} is not supported")]
    Version(u64),
    /// A record breaks the layout: a broken invariant, never skipped.
    #[error("corrupt outcome record {sequence}")]
    Corrupt {
        /// The sequence expected at that slot.
        sequence: u64,
    },
    /// A sequence counter would overflow.
    #[error("outcome sequences exhausted")]
    Exhausted,
}

/// The kind of a record (word 1, bits 0 to 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Handed to the backend under an open guard.
    Submitted = 1,
    /// A pending backend operation whose cancellation the backend
    /// established.
    ConfirmedCancelled = 2,
    /// The backend could not establish whether the operation was handed
    /// off.
    Unknown = 3,
    /// Refused at the gate under a closed or changed guard.
    Rejected = 4,
    /// The incarnation was aborted before submission, the message was a
    /// partial fragmented one, or its claim was aborted.
    Aborted = 5,
    /// A receiver's delivered prefix and unresolved range on a lane.
    Range = 16,
    /// A required receiver that did not acknowledge an abort.
    Interrupted = 17,
    /// The summary that ends an incarnation's records.
    Ended = 18,
    /// The final record of a faulted client: records lost.
    OutcomesLost = 19,
}

impl Kind {
    const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::Submitted,
            2 => Self::ConfirmedCancelled,
            3 => Self::Unknown,
            4 => Self::Rejected,
            5 => Self::Aborted,
            16 => Self::Range,
            17 => Self::Interrupted,
            18 => Self::Ended,
            19 => Self::OutcomesLost,
            _ => return None,
        })
    }

    /// Whether this is a range-side kind, which carries a receiver index.
    #[must_use]
    pub const fn is_range(self) -> bool {
        matches!(
            self,
            Self::Range | Self::Interrupted | Self::Ended | Self::OutcomesLost
        )
    }
}

/// One outcome record, without its sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// The kind.
    pub kind: Kind,
    /// The lane, 0 to 3.
    pub lane: u8,
    /// The receiver index, for range-side kinds; 0 otherwise.
    pub receiver: u16,
    /// The incarnation.
    pub incarnation: u64,
    /// Message start position, or a receiver's contiguous delivered prefix.
    pub start: u64,
    /// Message end position, or the unresolved range end.
    pub end: u64,
    /// The guard epoch at the decision, or of the abort.
    pub epoch: u64,
    /// The reason (G4), for `Rejected`, `Aborted` and range kinds.
    pub reason: u64,
    /// The lost count, for `OutcomesLost` only.
    pub lost: u64,
}

impl Record {
    /// The fields, words 1 to 7; `None` when the record breaks the layout.
    fn fields(&self) -> Option<[u64; 7]> {
        if self.lane > 3 || (!self.kind.is_range() && self.receiver != 0) {
            return None;
        }
        if self.kind != Kind::OutcomesLost && self.lost != 0 {
            return None;
        }
        let word1 = u64::from(self.kind as u8)
            | (u64::from(self.lane) << 8)
            | (u64::from(self.receiver) << 16);
        Some([
            word1,
            self.incarnation,
            self.start,
            self.end,
            self.epoch,
            self.reason,
            self.lost,
        ])
    }

    /// The record of `fields`, for a publication of `lanes` lanes.
    fn decode(fields: [u64; 7], lanes: u8) -> Option<Self> {
        let [word1, incarnation, start, end, epoch, reason, lost] = fields;
        let kind = Kind::from_code(word1 & 0xFF)?;
        let lane = u8::try_from((word1 >> 8) & 0x3).ok()?;
        let receiver = u16::try_from((word1 >> 16) & 0xFFFF).ok()?;
        // Bits 10 to 15 and 32 to 63 are reserved.
        let reserved = word1 & !(0xFF | (0x3 << 8) | (0xFFFF << 16));
        if reserved != 0
            || lane >= lanes
            || (!kind.is_range() && receiver != 0)
            || (kind != Kind::OutcomesLost && lost != 0)
        {
            return None;
        }
        Some(Self {
            kind,
            lane,
            receiver,
            incarnation,
            start,
            end,
            epoch,
            reason,
            lost,
        })
    }
}

/// Writes the header of a new ring for `binding`, of
/// [`Binding::capacity`] slots, its reserved words zeroed. Called on the
/// control path before the region is shared.
///
/// # Errors
///
/// [`OutcomeError::Layout`] when the slot count overflows or is below 2,
/// or `ring` is too small for it.
pub fn init(ring: &[AtomicU64], binding: &Binding) -> Result<(), OutcomeError> {
    let capacity = binding.capacity().ok_or(OutcomeError::Layout)?;
    check_layout(ring.len(), capacity)?;
    for (word, value) in [
        (VERSION, OUTCOME_LAYOUT_VERSION),
        (CAPACITY, capacity),
        (MESSAGES, binding.messages),
        (RANGES, binding.ranges),
        (GUARD_INDEX, binding.guard_index),
        (EPOCH, binding.epoch),
    ] {
        if let Some(cell) = ring.get(word) {
            cell.store(value, Ordering::Relaxed);
        }
    }
    // The reserved words are zero whatever memory the ring was given
    // (DESIGN's P3 on #501).
    for cell in ring.iter().take(HEADER_WORDS).skip(EPOCH + 1) {
        cell.store(0, Ordering::Relaxed);
    }
    Ok(())
}

/// The binding a ring's header names, checked for a client given
/// `guard_words` guard words: the slot count is `C_m + C_r + 1`, the
/// guard's index is within them and the epoch is open (even, and never
/// 0: a guard is created closed at epoch 1). Read after the region is
/// mapped, whose header the driver wrote before granting it.
///
/// # Errors
///
/// [`OutcomeError::Version`] for another layout version;
/// [`OutcomeError::Layout`] for a header that breaks these, a protocol
/// error.
pub fn binding(
    ring: &(impl LoadWords + ?Sized),
    guard_words: usize,
) -> Result<Binding, OutcomeError> {
    let version = ring.load_acquire(VERSION).ok_or(OutcomeError::Layout)?;
    if version != OUTCOME_LAYOUT_VERSION {
        return Err(OutcomeError::Version(version));
    }
    let word = |index| ring.load(index).ok_or(OutcomeError::Layout);
    let binding = Binding {
        messages: word(MESSAGES)?,
        ranges: word(RANGES)?,
        guard_index: word(GUARD_INDEX)?,
        epoch: word(EPOCH)?,
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

fn check_layout(words: usize, capacity: u64) -> Result<(), OutcomeError> {
    let needed = usize::try_from(capacity)
        .ok()
        .and_then(ring_words)
        .ok_or(OutcomeError::Layout)?;
    if capacity < 2 || words < needed {
        return Err(OutcomeError::Layout);
    }
    Ok(())
}

/// The first word of the slot of `sequence`.
fn slot_base(capacity: u64, sequence: u64) -> Option<usize> {
    let slot = usize::try_from((sequence.checked_sub(1)?) % capacity).ok()?;
    slot.checked_mul(RECORD_WORDS)?.checked_add(HEADER_WORDS)
}

/// The lost count of an `OutcomesLost` record whose lost records cannot
/// be counted (coordinator, ACS 15161): never read as "nothing lost".
pub const LOST_UNKNOWN: u64 = u64::MAX;

/// What [`OutcomeWriter::produce`] did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Produced {
    /// Written into the ring with this sequence.
    Written(u64),
    /// The client is faulted: the record is counted as lost.
    Lost,
}

/// The driver's writer of one ring.
///
/// A record is written at once or the client is faulted; nothing waits.
/// The room check and the lag fault are the same bound: a record needs
/// fewer than `capacity - 1` unread records, and a client whose unread
/// records would exceed `capacity - 1` is faulted. A protocol-following
/// client's reservations bound its unread records to `C_m + C_r =
/// capacity - 1`, so it is never faulted, and no record is ever deferred
/// (the design's deferral queue is unreachable and is not built).
#[derive(Debug)]
pub struct OutcomeWriter {
    capacity: u64,
    /// The last sequence written into the ring.
    written: u64,
    /// The last consumed count validated.
    consumed: u64,
    /// Records lost since the client faulted, the triggering record
    /// included; `None` while not faulted.
    lost: Option<u64>,
    /// Loom only: the ordering of the consumed load (Acquire), weakened by
    /// the negative control.
    #[cfg(loom)]
    consumed_load: Ordering,
    /// Loom only: one witness per slot, see [`OutcomeWriter::with_witness`].
    #[cfg(loom)]
    witness: Option<Witness>,
}

/// Loom only: one ownership witness per slot, shared by the writer and the
/// reader of one ring.
#[cfg(loom)]
pub type Witness = loom::sync::Arc<Vec<loom::cell::UnsafeCell<u64>>>;

impl OutcomeWriter {
    /// A writer of a ring of `capacity` slots.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Layout`] when `capacity` is below 2.
    pub fn new(capacity: u64) -> Result<Self, OutcomeError> {
        if capacity < 2 {
            return Err(OutcomeError::Layout);
        }
        Ok(Self {
            capacity,
            written: 0,
            consumed: 0,
            lost: None,
            #[cfg(loom)]
            consumed_load: CONSUMED_LOAD,
            #[cfg(loom)]
            witness: None,
        })
    }

    /// Loom only: the negative control's ordering for the consumed load.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_consumed_load(mut self, order: Ordering) -> Self {
        self.consumed_load = order;
        self
    }

    /// Loom only: attaches one witness per slot. The writer writes a slot's
    /// witness after it validated the room and before it stores the
    /// record; the reader reads it before it publishes the consumed count,
    /// with no other synchronization, so Loom reports a race when the
    /// consumed handoff is too weak to order a slot's reuse after its read.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_witness(mut self, witness: Witness) -> Self {
        self.witness = Some(witness);
        self
    }

    /// The records lost since the client faulted, the record that faulted
    /// it included; `None` while it has not.
    #[must_use]
    pub fn faulted(&self) -> Option<u64> {
        self.lost
    }

    /// Produces `record`: validates the consumed cell, then writes the
    /// record with the next sequence, or faults the client when its count
    /// is invalid or it lags so far that the record finds no room. Never
    /// blocks.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Layout`] for a record that breaks the layout or a
    /// ring shorter than its capacity (a caller bug: nothing is written);
    /// [`OutcomeError::Exhausted`] when sequences or the lost count would
    /// overflow.
    pub fn produce(
        &mut self,
        ring: &[AtomicU64],
        consumed: &AtomicU64,
        record: Record,
    ) -> Result<Produced, OutcomeError> {
        let fields = record.fields().ok_or(OutcomeError::Layout)?;
        if let Some(lost) = &mut self.lost {
            // An unknown count stays unknown.
            if *lost != LOST_UNKNOWN {
                *lost = lost.checked_add(1).ok_or(OutcomeError::Exhausted)?;
            }
            return Ok(Produced::Lost);
        }
        let sequence = self.written.checked_add(1).ok_or(OutcomeError::Exhausted)?;
        // `written - consumed` never underflows: a validated count is at
        // most `written`. `capacity - 1` never does: `capacity >= 2`.
        if !self.read_consumed(consumed) || self.written - self.consumed >= self.capacity - 1 {
            // The record that faults the client is the first one lost.
            self.fault(ring, 1)?;
            return Ok(Produced::Lost);
        }
        #[cfg(loom)]
        self.witness_write(sequence);
        if !write(ring, self.capacity, sequence, fields) {
            return Err(OutcomeError::Layout);
        }
        self.written = sequence;
        Ok(Produced::Written(sequence))
    }

    /// Faults the client for a reason outside the ring, such as a source of
    /// records the driver lost (its walker lapped, a broken invariant):
    /// writes the final `OutcomesLost` record with `lost`, which is
    /// [`LOST_UNKNOWN`] when the lost records cannot be counted. A writer
    /// already faulted changes nothing.
    ///
    /// # Errors
    ///
    /// As [`OutcomeWriter::produce`].
    pub fn abandon(&mut self, ring: &[AtomicU64], lost: u64) -> Result<(), OutcomeError> {
        if self.lost.is_some() {
            return Ok(());
        }
        self.fault(ring, lost)
    }

    /// Validates the consumed cell (Acquire): monotonic, and at most the
    /// last sequence written. Returns `false` for an invalid count, which
    /// the caller answers with a fault; the last valid count is kept.
    fn read_consumed(&mut self, consumed: &AtomicU64) -> bool {
        #[cfg(not(loom))]
        let order = CONSUMED_LOAD;
        #[cfg(loom)]
        let order = self.consumed_load;
        let count = consumed.load(order);
        if count < self.consumed || count > self.written {
            return false;
        }
        self.consumed = count;
        true
    }

    /// Faults the client with `lost` records lost so far, and writes the
    /// one `OutcomesLost` record carrying that count in the reserved slot,
    /// against the last validated count: `written - consumed <= capacity -
    /// 1` always holds, so its slot's record has been read.
    fn fault(&mut self, ring: &[AtomicU64], lost: u64) -> Result<(), OutcomeError> {
        self.lost = Some(lost);
        let sequence = self.written.checked_add(1).ok_or(OutcomeError::Exhausted)?;
        debug_assert!(
            self.written - self.consumed < self.capacity,
            "the reserved slot is free"
        );
        let record = Record {
            kind: Kind::OutcomesLost,
            lane: 0,
            receiver: 0,
            incarnation: 0,
            start: 0,
            end: 0,
            epoch: 0,
            reason: 0,
            lost,
        };
        let fields = record.fields().ok_or(OutcomeError::Layout)?;
        #[cfg(loom)]
        self.witness_write(sequence);
        if !write(ring, self.capacity, sequence, fields) {
            return Err(OutcomeError::Layout);
        }
        self.written = sequence;
        Ok(())
    }

    #[cfg(loom)]
    fn witness_write(&self, sequence: u64) {
        if let Some(cell) = witness(self.witness.as_ref(), self.capacity, sequence) {
            // SAFETY: Loom checks that this write is ordered after the
            // reader's last read of the slot's witness.
            cell.with_mut(|value| unsafe { *value = sequence });
        }
    }
}

/// Loom only: the witness of `sequence`'s slot.
#[cfg(loom)]
fn witness(
    witness: Option<&Witness>,
    capacity: u64,
    sequence: u64,
) -> Option<&loom::cell::UnsafeCell<u64>> {
    let slot = usize::try_from(sequence.checked_sub(1)? % capacity).ok()?;
    witness?.get(slot)
}

/// Stores a record: fields Relaxed, then the sequence with Release.
fn write(ring: &[AtomicU64], capacity: u64, sequence: u64, fields: [u64; 7]) -> bool {
    let Some(base) = slot_base(capacity, sequence) else {
        return false;
    };
    let Some(slot) = base
        .checked_add(RECORD_WORDS)
        .and_then(|end| ring.get(base..end))
    else {
        return false;
    };
    let [head, rest @ ..] = slot else {
        return false;
    };
    for (word, value) in rest.iter().zip(fields) {
        word.store(value, Ordering::Relaxed);
    }
    head.store(sequence, Ordering::Release);
    true
}

/// The client's reader of one ring.
#[derive(Debug)]
pub struct OutcomeReader {
    capacity: u64,
    lanes: u8,
    /// The next sequence expected.
    next: u64,
    /// Set once the `OutcomesLost` record was read: nothing follows it.
    ended: bool,
    /// Loom only: the ordering of the consumed store (Release), weakened by
    /// the negative control.
    #[cfg(loom)]
    consumed_store: Ordering,
    /// Loom only: the writer's witnesses, see [`OutcomeWriter::with_witness`].
    #[cfg(loom)]
    witness: Option<Witness>,
}

impl OutcomeReader {
    /// A reader of `ring` for a publication of `lanes` lanes: checks the
    /// layout version and the slot count.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Version`] for another layout version;
    /// [`OutcomeError::Layout`] for a slot count the ring cannot hold.
    pub fn attach(ring: &(impl LoadWords + ?Sized), lanes: u8) -> Result<Self, OutcomeError> {
        let version = ring.load_acquire(VERSION).ok_or(OutcomeError::Layout)?;
        if version != OUTCOME_LAYOUT_VERSION {
            return Err(OutcomeError::Version(version));
        }
        let capacity = ring.load(CAPACITY).ok_or(OutcomeError::Layout)?;
        check_layout(ring.len(), capacity)?;
        if lanes == 0 || lanes > 4 {
            return Err(OutcomeError::Layout);
        }
        Ok(Self {
            capacity,
            lanes,
            next: 1,
            ended: false,
            #[cfg(loom)]
            consumed_store: CONSUMED_STORE,
            #[cfg(loom)]
            witness: None,
        })
    }

    /// Loom only: the negative control's ordering for the consumed store.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_consumed_store(mut self, order: Ordering) -> Self {
        self.consumed_store = order;
        self
    }

    /// Loom only: the writer's witnesses, read before each consumed store.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_witness(mut self, witness: Witness) -> Self {
        self.witness = Some(witness);
        self
    }

    /// Delivers up to `limit` records in sequence order. Each is counted
    /// as consumed, and the count published with Release, only after
    /// `handler` returns. Returns how many were delivered.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Corrupt`] for a record that breaks the layout, or a
    /// slot holding anything but the expected sequence or, while pending,
    /// the record it replaces (`sequence - capacity`, or 0 on the first
    /// round).
    pub fn poll(
        &mut self,
        ring: &(impl LoadWords + ?Sized),
        consumed: &AtomicU64,
        limit: usize,
        mut handler: impl FnMut(u64, Record),
    ) -> Result<usize, OutcomeError> {
        let mut delivered = 0;
        while delivered < limit && !self.ended {
            let sequence = self.next;
            let corrupt = OutcomeError::Corrupt { sequence };
            let base = slot_base(self.capacity, sequence).ok_or(corrupt)?;
            let head = ring.load_acquire(base).ok_or(corrupt)?;
            if head != sequence {
                // Not written yet: the slot still holds the record it
                // replaces. Anything else is corrupt.
                // A later round's slot holds the record it replaces; a
                // first-round slot holds 0.
                let pending = match sequence.checked_sub(self.capacity) {
                    Some(previous) => head == previous,
                    None => head == 0,
                };
                if pending {
                    break;
                }
                return Err(corrupt);
            }
            let mut fields = [0u64; 7];
            for (index, field) in (1..).zip(fields.iter_mut()) {
                let word = base.checked_add(index).ok_or(corrupt)?;
                *field = ring.load(word).ok_or(corrupt)?;
            }
            let record = Record::decode(fields, self.lanes).ok_or(corrupt)?;
            handler(sequence, record);
            #[cfg(loom)]
            if let Some(cell) = witness(self.witness.as_ref(), self.capacity, sequence) {
                // SAFETY: Loom checks that this read is ordered after the
                // writer's witness write for this record and before the
                // slot's reuse.
                let owner = cell.with(|value| unsafe { *value });
                assert_eq!(owner, sequence, "the slot's witness names another record");
            }
            #[cfg(not(loom))]
            let order = CONSUMED_STORE;
            #[cfg(loom)]
            let order = self.consumed_store;
            consumed.store(sequence, order);
            self.next = sequence.checked_add(1).ok_or(OutcomeError::Exhausted)?;
            self.ended = record.kind == Kind::OutcomesLost;
            delivered += 1;
        }
        Ok(delivered)
    }

    /// Whether the faulted client's `OutcomesLost` record was read.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.ended
    }
}

#[cfg(all(test, not(loom)))]
mod tests;
