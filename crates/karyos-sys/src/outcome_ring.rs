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
//!   version, word 1 the slot count), then `capacity` records of
//!   [`RECORD_WORDS`] words. Record `seq` (from 1, gapless) lives in slot
//!   `(seq - 1) mod capacity`. Word 0 of a record is its sequence; words 1
//!   to 7 are its fields.
//! - **Writing.** The driver stores a record's fields with Relaxed stores,
//!   then its sequence with Release. It writes an ordinary record only
//!   while fewer than `capacity - 1` are unread, so the last slot is always
//!   free for the one `OutcomesLost` record of a faulted client.
//! - **The consumed count.** The driver loads the consumed cell with
//!   Acquire before every write and validates it: monotonic, and at most
//!   the last sequence written. The client stores it with Release only
//!   after it has read the records it counts, so a slot is never rewritten
//!   while its record is being read. An invalid count, or a client so far
//!   behind that the records produced minus its count would exceed
//!   `capacity - 1`, faults it: the driver stops writing, counts what it
//!   could not write, and writes one final `OutcomesLost` record against
//!   the last count it validated.
//! - **Deferral.** A record that finds no room is deferred in a
//!   preallocated queue of `capacity - 1` entries and retried, never
//!   dropped and never blocking a close, a reopen or the sender. Sequences
//!   are assigned when a record is produced, and the queue drains first in
//!   first out, so the ring receives records in sequence order.
//! - **Reading.** The reader loads a slot's word 0 with Acquire; when it
//!   is the next expected sequence, the fields are complete. It validates
//!   them, hands the record to the handler, and only then publishes the
//!   consumed count, so a panicking handler gets the record again.

use std::collections::VecDeque;

use crate::load_words::LoadWords;
use crate::sync::{AtomicU64, Ordering};

/// The outcome ring's layout version.
pub const OUTCOME_LAYOUT_VERSION: u64 = 1;
/// Words of the header stride.
pub const HEADER_WORDS: usize = 16;
/// Words of one record: 64 bytes.
pub const RECORD_WORDS: usize = 8;
/// Header word: the layout version.
const VERSION: usize = 0;
/// Header word: the slot count.
const CAPACITY: usize = 1;

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

/// Writes the header of a new ring of `capacity` slots. Called on the
/// control path before the region is shared.
///
/// # Errors
///
/// [`OutcomeError::Layout`] when `ring` is too small or `capacity` is
/// below 2.
pub fn init(ring: &[AtomicU64], capacity: u64) -> Result<(), OutcomeError> {
    check_layout(ring.len(), capacity)?;
    if let (Some(version), Some(slots)) = (ring.get(VERSION), ring.get(CAPACITY)) {
        version.store(OUTCOME_LAYOUT_VERSION, Ordering::Relaxed);
        slots.store(capacity, Ordering::Relaxed);
    }
    Ok(())
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

/// What [`OutcomeWriter::produce`] did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Produced {
    /// Written into the ring with this sequence.
    Written(u64),
    /// Assigned this sequence and deferred until the client consumes.
    Deferred(u64),
    /// The client is faulted: the record is counted as lost.
    Lost,
}

/// The driver's writer of one ring.
#[derive(Debug)]
pub struct OutcomeWriter {
    capacity: u64,
    /// The last sequence assigned.
    produced: u64,
    /// The last sequence written into the ring.
    written: u64,
    /// The last consumed count validated.
    consumed: u64,
    /// Produced records not yet written, oldest first; at most
    /// `capacity - 1`.
    deferred: VecDeque<[u64; 7]>,
    /// Records lost since the client faulted; `None` while not faulted.
    lost: Option<u64>,
}

impl OutcomeWriter {
    /// A writer of a ring of `capacity` slots, with its deferral queue
    /// preallocated.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Layout`] when `capacity` is below 2.
    pub fn new(capacity: u64) -> Result<Self, OutcomeError> {
        let queue = capacity
            .checked_sub(1)
            .filter(|queue| *queue >= 1)
            .and_then(|queue| usize::try_from(queue).ok())
            .ok_or(OutcomeError::Layout)?;
        Ok(Self {
            capacity,
            produced: 0,
            written: 0,
            consumed: 0,
            deferred: VecDeque::with_capacity(queue),
            lost: None,
        })
    }

    /// The records lost since the client faulted; `None` while it has not.
    #[must_use]
    pub fn faulted(&self) -> Option<u64> {
        self.lost
    }

    /// Records produced and not yet written.
    #[must_use]
    pub fn deferred(&self) -> usize {
        self.deferred.len()
    }

    /// Produces `record`: assigns it the next sequence and writes it, or
    /// defers it when the client has not consumed enough. Never blocks.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Layout`] for a record that breaks the layout (a
    /// caller bug: nothing is assigned); [`OutcomeError::Exhausted`] when
    /// sequences would overflow.
    pub fn produce(
        &mut self,
        ring: &[AtomicU64],
        consumed: &AtomicU64,
        record: Record,
    ) -> Result<Produced, OutcomeError> {
        let fields = record.fields().ok_or(OutcomeError::Layout)?;
        if let Some(lost) = &mut self.lost {
            *lost = lost.checked_add(1).ok_or(OutcomeError::Exhausted)?;
            return Ok(Produced::Lost);
        }
        let sequence = self
            .produced
            .checked_add(1)
            .ok_or(OutcomeError::Exhausted)?;
        // A client so far behind that its unread records would exceed the
        // ordinary room, or whose count is invalid, is faulted rather than
        // queued past the bound.
        if sequence - self.consumed > self.capacity - 1
            && (!self.read_consumed(consumed) || sequence - self.consumed > self.capacity - 1)
        {
            self.fault(ring);
            if let Some(lost) = &mut self.lost {
                *lost = lost.checked_add(1).ok_or(OutcomeError::Exhausted)?;
            }
            return Ok(Produced::Lost);
        }
        self.produced = sequence;
        self.deferred.push_back(fields);
        self.drain(ring, consumed);
        // A fault in the drain counted this record with the unwritten ones.
        Ok(if self.lost.is_some() {
            Produced::Lost
        } else if self.written >= sequence {
            Produced::Written(sequence)
        } else {
            Produced::Deferred(sequence)
        })
    }

    /// Writes deferred records the client has made room for; returns how
    /// many it wrote. Called each duty cycle while records are deferred.
    pub fn retry(&mut self, ring: &[AtomicU64], consumed: &AtomicU64) -> usize {
        if self.lost.is_some() {
            return 0;
        }
        self.drain(ring, consumed)
    }

    /// Validates the consumed cell (Acquire): monotonic, and at most the
    /// last sequence written. Returns `false` for an invalid count, which
    /// the caller answers with a fault; the last valid count is kept.
    fn read_consumed(&mut self, consumed: &AtomicU64) -> bool {
        let count = consumed.load(Ordering::Acquire);
        if count < self.consumed || count > self.written {
            return false;
        }
        self.consumed = count;
        true
    }

    fn drain(&mut self, ring: &[AtomicU64], consumed: &AtomicU64) -> usize {
        let mut wrote = 0;
        if self.deferred.is_empty() {
            return wrote;
        }
        if !self.read_consumed(consumed) {
            self.fault(ring);
            return wrote;
        }
        while self.written - self.consumed < self.capacity - 1 {
            let Some(fields) = self.deferred.pop_front() else {
                break;
            };
            let sequence = self.written + 1;
            if !write(ring, self.capacity, sequence, fields) {
                // The layout was checked at init; a short ring is a caller
                // bug, so the record is kept rather than lost.
                self.deferred.push_front(fields);
                break;
            }
            self.written = sequence;
            wrote += 1;
        }
        wrote
    }

    /// Faults the client: counts every unwritten record as lost, and
    /// writes the one `OutcomesLost` record in the reserved slot, against
    /// the last validated count.
    fn fault(&mut self, ring: &[AtomicU64]) {
        // The queue holds at most `capacity - 1` entries, a `u64` count.
        let lost = u64::try_from(self.deferred.len()).unwrap_or(u64::MAX);
        self.deferred.clear();
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
        let sequence = self.written + 1;
        if let Some(fields) = record.fields()
            && write(ring, self.capacity, sequence, fields)
        {
            self.written = sequence;
            self.produced = self.produced.max(sequence);
        }
        self.lost = Some(lost);
    }
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
}

impl OutcomeReader {
    /// A reader of `ring` for a publication of `lanes` lanes: checks the
    /// layout version and the slot count.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Version`] for another layout version;
    /// [`OutcomeError::Layout`] for a slot count the ring cannot hold.
    pub fn attach(ring: &impl LoadWords, lanes: u8) -> Result<Self, OutcomeError> {
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
        })
    }

    /// Delivers up to `limit` records in sequence order. Each is counted
    /// as consumed, and the count published with Release, only after
    /// `handler` returns. Returns how many were delivered.
    ///
    /// # Errors
    ///
    /// [`OutcomeError::Corrupt`] for a record that breaks the layout or a
    /// slot holding a sequence ahead of the expected one.
    pub fn poll(
        &mut self,
        ring: &impl LoadWords,
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
            if head < sequence {
                // Not written yet: the slot still holds an older record.
                break;
            }
            if head != sequence {
                return Err(corrupt);
            }
            let mut fields = [0u64; 7];
            for (index, field) in fields.iter_mut().enumerate() {
                *field = ring.load(base + 1 + index).ok_or(corrupt)?;
            }
            let record = Record::decode(fields, self.lanes).ok_or(corrupt)?;
            handler(sequence, record);
            consumed.store(sequence, Ordering::Release);
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
