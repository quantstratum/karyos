// SPDX-License-Identifier: Apache-2.0

//! Bounded record journal with loss accounting (SPEC.md §7.3, ADR-0019;
//! design in `quantstratum-docs: karyos/design/record-journal.md`): the storage under the trace
//! journals. One writer, one consumer, fixed-size records.
//!
//! - **Atomic publication.** The writer stores a record's sequence and
//!   payload words (Relaxed) and then the next `head` (Release); the consumer
//!   loads `head` (Acquire) before copying, so it sees a record whole.
//! - **No overwrite.** The writer reuses a slot only after loading `consumed`
//!   (Acquire) past it; the consumer stores `consumed` (Release) after its
//!   copy. When the ring is full the record is dropped instead.
//! - **Every attempt is numbered.** Stored or dropped, each append takes the
//!   next `u64` sequence; stored records carry it, so gaps show losses.
//! - **Loss is readable on its own.** Drops are summarised in a ring of drop
//!   ranges, each published through the conflation seqlock
//!   ([`SlotWords`]); when the ring is full the oldest range is folded into
//!   a `lost_before` watermark, raised before the range's entry is reused.
//! - **Exhaustion is explicit.** A sequence that would overflow closes the
//!   journal.
//!
//! Every word is accessed only atomically. [`JournalWords`] is the protocol
//! over any atomic words (also checked with Loom); [`record_journal`] builds
//! the owned, safe API over heap memory.

use crate::conflation::{SlotRead, SlotWords};
use crate::sync::{AtomicU64, Ordering};

/// Words per stride: 128 bytes.
const STRIDE: usize = 16;
/// Control word: stored records (the writer's next slot).
const HEAD: usize = 0;
/// Control word: records the consumer has released.
const CONSUMED: usize = STRIDE;
/// Control word: the next sequence the writer assigns.
const ATTEMPTED: usize = 2 * STRIDE;
/// Control word: nonzero once closed (written only by the writer).
const CLOSED: usize = ATTEMPTED + 1;
/// Writer-private control word: index + 1 of the current drop range (0 if
/// none).
const CURRENT_RANGE: usize = ATTEMPTED + 2;
/// Writer-private control word: drop-range entries ever used, capped at the
/// ring size.
const RANGES_USED: usize = ATTEMPTED + 3;
/// Writer-private control words: the last accepted stamp.
const LAST_TIME: usize = ATTEMPTED + 4;
const LAST_CLOCK: usize = ATTEMPTED + 5;
const LAST_EPOCH: usize = ATTEMPTED + 6;
/// Writer-private control word: nonzero once a stamp was accepted.
const HAS_STAMP: usize = ATTEMPTED + 7;
/// Start of the watermark seqlock slot (version, length, one value word).
const WATERMARK: usize = 3 * STRIDE;
/// Words of the watermark slot.
const WATERMARK_WORDS: usize = 3;
/// Control words in total.
pub const CONTROL_WORDS: usize = 4 * STRIDE;
/// Words of one drop-range entry: a seqlock slot of version, length and
/// six value words.
pub const RANGE_WORDS: usize = 8;
/// Value bytes of a drop range: first and last sequence, first and last
/// time, clock and epoch.
const RANGE_BYTES: usize = 48;
/// Read attempts per seqlock slot in [`JournalWords::losses`].
const READ_ATTEMPTS: usize = 4;

/// Errors of the record journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// A size is zero, overflows, or the capacity is not a power of two.
    #[error("invalid record journal configuration")]
    InvalidConfig,
    /// The payload does not have the journal's record length.
    #[error("payload of {length} words, expected {expected}")]
    PayloadLength {
        /// Words given.
        length: usize,
        /// Words per record.
        expected: usize,
    },
    /// The stamp has the same clock and epoch as the immediately preceding
    /// accepted stamp and an earlier time; nothing was stored or counted.
    /// Only that adjacent stamp is checked: a writer that alternates clocks
    /// keeps each clock and epoch monotonic itself, and starts a new epoch
    /// rather than reuse a clock and epoch whose time restarted.
    #[error("stamp earlier than the preceding one of the same clock and epoch")]
    StampRegression,
    /// The next sequence, or a drop-range or watermark version, would
    /// overflow. The journal is now closed; nothing was stored or counted.
    #[error("journal sequences or versions exhausted; the journal is closed")]
    Exhausted,
    /// The journal is closed.
    #[error("record journal closed")]
    Closed,
    /// The caller's buffer cannot hold every drop range; nothing was read.
    #[error("buffer of {length} drop ranges, at least {required} required")]
    OutputTooSmall {
        /// Entries given.
        length: usize,
        /// Drop-range entries of the journal.
        required: usize,
    },
}

/// The writer's own time of an append, with its clock domain and
/// calibration epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stamp {
    /// Monotonic time in the clock's unit.
    pub time: u64,
    /// Clock domain.
    pub clock: u64,
    /// Calibration epoch of that clock.
    pub epoch: u64,
}

/// What an append did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Append {
    /// The record was stored with this sequence.
    Stored {
        /// Its sequence.
        sequence: u64,
    },
    /// The ring was full: the record was dropped and its sequence counted in
    /// a drop range.
    Dropped {
        /// Its sequence.
        sequence: u64,
    },
}

/// A run of consecutive dropped sequences with the same clock and epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DropRange {
    /// First dropped sequence.
    pub first: u64,
    /// Last dropped sequence.
    pub last: u64,
    /// Writer time at the first drop.
    pub first_time: u64,
    /// Writer time at the last drop.
    pub last_time: u64,
    /// Clock domain of both times.
    pub clock: u64,
    /// Calibration epoch of both times.
    pub epoch: u64,
}

impl DropRange {
    fn encode(&self) -> [u8; RANGE_BYTES] {
        let mut bytes = [0u8; RANGE_BYTES];
        let fields = [
            self.first,
            self.last,
            self.first_time,
            self.last_time,
            self.clock,
            self.epoch,
        ];
        for (chunk, field) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(fields) {
            chunk.copy_from_slice(&field.to_le_bytes());
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut fields = bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| Some(u64::from_le_bytes(*chunk)));
        Some(Self {
            first: fields.next()??,
            last: fields.next()??,
            first_time: fields.next()??,
            last_time: fields.next()??,
            clock: fields.next()??,
            epoch: fields.next()??,
        })
    }
}

/// A checked drop to record: the range entry to write and, when a full
/// ring evicts its oldest range, the watermark to raise first.
struct DropPlan<'a> {
    slot: SlotWords<'a>,
    range: DropRange,
    index: usize,
    watermark: Option<(SlotWords<'a>, u64)>,
    used: Option<u64>,
}

/// What a consumer read of one record found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// No record is waiting; the journal is open.
    Empty,
    /// The journal is closed and every record was taken: none will follow.
    Closed,
    /// A record was copied and released.
    Record {
        /// Its sequence.
        sequence: u64,
    },
}

/// The words of one journal.
#[derive(Debug, Clone, Copy)]
pub struct JournalWords<'a> {
    records: &'a [AtomicU64],
    control: &'a [AtomicU64],
    ranges: &'a [AtomicU64],
    capacity: u64,
    payload_words: usize,
    /// Loom only: per-slot ownership witnesses, see
    /// [`JournalWords::with_witness`].
    #[cfg(loom)]
    witness: Option<&'a [loom::cell::UnsafeCell<u64>]>,
}

impl<'a> JournalWords<'a> {
    /// Loom only: attaches one ownership witness per record slot. The writer
    /// writes a slot's witness at its reuse point (after loading `consumed`,
    /// before storing the record) and the consumer reads it during its copy
    /// (before storing `consumed`), with no other synchronization, so Loom
    /// reports a race if the `consumed` or `head` handoff is too weak.
    #[cfg(loom)]
    #[must_use]
    pub fn with_witness(mut self, witness: &'a [loom::cell::UnsafeCell<u64>]) -> Self {
        self.witness = Some(witness);
        self
    }

    #[cfg(loom)]
    fn witness(&self, position: u64) -> Option<&'a loom::cell::UnsafeCell<u64>> {
        let index = usize::try_from(position % self.capacity).ok()?;
        self.witness?.get(index)
    }

    /// Wraps the record words, the control words and the drop-range words.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidConfig`] unless `records` holds a
    /// power-of-two number of records of `1 + payload_words` words,
    /// `payload_words > 0`, `control` has [`CONTROL_WORDS`] words and
    /// `ranges` a nonzero multiple of [`RANGE_WORDS`].
    pub fn new(
        records: &'a [AtomicU64],
        control: &'a [AtomicU64],
        ranges: &'a [AtomicU64],
        payload_words: usize,
    ) -> Result<Self, JournalError> {
        let invalid = JournalError::InvalidConfig;
        let record_words = payload_words.checked_add(1).ok_or(invalid)?;
        let count = records.len() / record_words;
        let valid = payload_words > 0
            && records.len().is_multiple_of(record_words)
            && count.is_power_of_two()
            && control.len() >= CONTROL_WORDS
            && !ranges.is_empty()
            && ranges.len().is_multiple_of(RANGE_WORDS);
        if !valid {
            return Err(invalid);
        }
        Ok(Self {
            records,
            control,
            ranges,
            capacity: u64::try_from(count).map_err(|_| invalid)?,
            payload_words,
            #[cfg(loom)]
            witness: None,
        })
    }

    fn control(&self, index: usize) -> Option<&'a AtomicU64> {
        self.control.get(index)
    }

    fn load(&self, index: usize, order: Ordering) -> u64 {
        self.control(index).map_or(0, |word| word.load(order))
    }

    fn store(&self, index: usize, value: u64, order: Ordering) {
        if let Some(word) = self.control(index) {
            word.store(value, order);
        }
    }

    fn record(&self, position: u64) -> Option<&'a [AtomicU64]> {
        let words = self.payload_words + 1;
        let start = usize::try_from(position % self.capacity).ok()? * words;
        self.records.get(start..start + words)
    }

    fn range(&self, index: usize) -> Option<SlotWords<'a>> {
        let start = index.checked_mul(RANGE_WORDS)?;
        SlotWords::new(self.ranges.get(start..start + RANGE_WORDS)?)
    }

    fn range_count(&self) -> usize {
        self.ranges.len() / RANGE_WORDS
    }

    fn watermark(&self) -> Option<SlotWords<'a>> {
        SlotWords::new(self.control.get(WATERMARK..WATERMARK + WATERMARK_WORDS)?)
    }

    /// Words per record payload.
    #[must_use]
    pub fn payload_words(&self) -> usize {
        self.payload_words
    }

    /// The attempted count `A` alone (Acquire): every append, stored or
    /// dropped, raises it, so a consumer can tell whether the loss
    /// accounting changed without reading it.
    #[must_use]
    pub fn attempted(&self) -> u64 {
        self.load(ATTEMPTED, Ordering::Acquire)
    }

    /// Whether the writer closed the journal (Acquire).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.load(CLOSED, Ordering::Acquire) != 0
    }

    /// Closes the journal for good (Release). Only the writer calls this.
    pub fn close(&self) {
        self.store(CLOSED, 1, Ordering::Release);
    }

    /// Appends one record. Only the single writer calls this.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::PayloadLength`] and
    /// [`JournalError::StampRegression`] (nothing counted),
    /// [`JournalError::Exhausted`] (the journal closes; nothing stored or
    /// counted) and [`JournalError::Closed`].
    pub fn append(&self, payload: &[u64], stamp: Stamp) -> Result<Append, JournalError> {
        if self.is_closed() {
            return Err(JournalError::Closed);
        }
        if payload.len() != self.payload_words {
            return Err(JournalError::PayloadLength {
                length: payload.len(),
                expected: self.payload_words,
            });
        }
        if self.load(HAS_STAMP, Ordering::Relaxed) != 0
            && stamp.clock == self.load(LAST_CLOCK, Ordering::Relaxed)
            && stamp.epoch == self.load(LAST_EPOCH, Ordering::Relaxed)
            && stamp.time < self.load(LAST_TIME, Ordering::Relaxed)
        {
            return Err(JournalError::StampRegression);
        }
        let sequence = self.load(ATTEMPTED, Ordering::Relaxed);
        let Some(next) = sequence.checked_add(1) else {
            self.close();
            return Err(JournalError::Exhausted);
        };
        let head = self.load(HEAD, Ordering::Relaxed);
        let consumed = self.load(CONSUMED, Ordering::Acquire);
        let room = head
            .checked_sub(consumed)
            .is_some_and(|pending| pending < self.capacity);
        let outcome = match self.record(head) {
            Some(slot) if room => {
                #[cfg(loom)]
                if let Some(witness) = self.witness(head) {
                    // SAFETY: Loom checks that this write is ordered after
                    // the consumer's last read of the slot's witness.
                    witness.with_mut(|value| unsafe { *value = sequence });
                }
                if let Some(word) = slot.first() {
                    word.store(sequence, Ordering::Relaxed);
                }
                for (word, value) in slot.iter().skip(1).zip(payload) {
                    word.store(*value, Ordering::Relaxed);
                }
                // `head` never exceeds `sequence`, so this cannot overflow.
                self.store(HEAD, head + 1, Ordering::Release);
                Append::Stored { sequence }
            }
            _ => {
                let Some(plan) = self.drop_plan(sequence, stamp) else {
                    // A drop-range or watermark version would overflow:
                    // nothing is stored or counted, and no further drop
                    // could be recorded, so the journal closes.
                    self.close();
                    return Err(JournalError::Exhausted);
                };
                self.apply(plan);
                Append::Dropped { sequence }
            }
        };
        self.store(LAST_TIME, stamp.time, Ordering::Relaxed);
        self.store(LAST_CLOCK, stamp.clock, Ordering::Relaxed);
        self.store(LAST_EPOCH, stamp.epoch, Ordering::Relaxed);
        self.store(HAS_STAMP, 1, Ordering::Relaxed);
        self.store(ATTEMPTED, next, Ordering::Release);
        Ok(outcome)
    }

    /// Plans recording `sequence` as dropped: extend the current range when
    /// it is the next sequence with the same clock and epoch, otherwise
    /// start a range in the next entry, folding the evicted range (if the
    /// ring is full) into the watermark first. Returns `None`, before any
    /// mutation, if a seqlock it would touch has no version left.
    fn drop_plan(&self, sequence: u64, stamp: Stamp) -> Option<DropPlan<'a>> {
        let current = usize::try_from(self.load(CURRENT_RANGE, Ordering::Relaxed)).ok()?;
        let mut scratch = [0u8; RANGE_BYTES];
        if let Some(index) = current.checked_sub(1)
            && let Some(slot) = self.range(index)
            && let SlotRead::Value { .. } = slot.read(&mut scratch)
            && let Some(mut range) = DropRange::decode(&scratch)
            && range.last.checked_add(1) == Some(sequence)
            && range.clock == stamp.clock
            && range.epoch == stamp.epoch
        {
            range.last = sequence;
            range.last_time = stamp.time;
            return slot.can_write().then_some(DropPlan {
                slot,
                range,
                index,
                watermark: None,
                used: None,
            });
        }
        let count = self.range_count();
        let index = current % count;
        let used = usize::try_from(self.load(RANGES_USED, Ordering::Relaxed)).ok()?;
        let slot = self.range(index)?;
        let mut watermark = None;
        let mut new_used = None;
        if used >= count {
            if let SlotRead::Value { .. } = slot.read(&mut scratch)
                && let Some(evicted) = DropRange::decode(&scratch)
            {
                let raised = evicted.last.checked_add(1)?;
                let target = self.watermark()?;
                let mut old = [0u8; 8];
                let previous = match target.read(&mut old) {
                    SlotRead::Value { .. } => u64::from_le_bytes(old),
                    _ => 0,
                };
                if raised > previous {
                    if !target.can_write() {
                        return None;
                    }
                    watermark = Some((target, raised));
                }
            }
        } else {
            new_used = Some(used as u64 + 1);
        }
        let range = DropRange {
            first: sequence,
            last: sequence,
            first_time: stamp.time,
            last_time: stamp.time,
            clock: stamp.clock,
            epoch: stamp.epoch,
        };
        slot.can_write().then_some(DropPlan {
            slot,
            range,
            index,
            watermark,
            used: new_used,
        })
    }

    /// Applies a checked plan: the watermark first, then the range entry.
    fn apply(&self, plan: DropPlan<'a>) {
        if let Some((target, raised)) = plan.watermark {
            let _ = target.write(&raised.to_le_bytes());
        }
        let _ = plan.slot.write(&plan.range.encode());
        if let Some(used) = plan.used {
            self.store(RANGES_USED, used, Ordering::Relaxed);
        }
        self.store(CURRENT_RANGE, plan.index as u64 + 1, Ordering::Relaxed);
    }

    /// Copies the oldest unreleased record's payload into `out` and releases
    /// it. Only the single consumer calls this.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::PayloadLength`] when `out` does not have the
    /// record length; nothing is released.
    pub fn take(&self, out: &mut [u64]) -> Result<Next, JournalError> {
        if out.len() != self.payload_words {
            return Err(JournalError::PayloadLength {
                length: out.len(),
                expected: self.payload_words,
            });
        }
        let consumed = self.load(CONSUMED, Ordering::Relaxed);
        let mut head = self.load(HEAD, Ordering::Acquire);
        if consumed == head {
            if !self.is_closed() {
                return Ok(Next::Empty);
            }
            // Closed (Acquire) after the writer's last record: reload `head`
            // before deciding that nothing will follow.
            head = self.load(HEAD, Ordering::Acquire);
            if consumed == head {
                return Ok(Next::Closed);
            }
        }
        let Some(slot) = self.record(consumed) else {
            return Ok(Next::Empty);
        };
        let sequence = slot.first().map_or(0, |word| word.load(Ordering::Relaxed));
        for (value, word) in out.iter_mut().zip(slot.iter().skip(1)) {
            *value = word.load(Ordering::Relaxed);
        }
        #[cfg(loom)]
        if let Some(witness) = self.witness(consumed) {
            // SAFETY: Loom checks that this read is ordered after the
            // writer's witness write for this record and before its reuse.
            let owner = witness.with(|value| unsafe { *value });
            assert_eq!(owner, sequence, "the slot's witness names its record");
        }
        // `consumed < head`, so this cannot overflow.
        self.store(CONSUMED, consumed + 1, Ordering::Release);
        Ok(Next::Record { sequence })
    }

    /// Reads the loss accounting without consuming anything, in this order:
    /// the attempted count `A` (Acquire), the stored count (Acquire, so it
    /// covers every record stored below `A`), the drop ranges into `out`
    /// (stable ones, clipped to sequences below `A`), then the watermark.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::OutputTooSmall`], before reading anything,
    /// when `out` has fewer entries than the journal has drop ranges: a
    /// shorter buffer would silently hide ranges.
    pub fn losses(&self, out: &mut [DropRange]) -> Result<LossSnapshot, JournalError> {
        if out.len() < self.range_count() {
            return Err(JournalError::OutputTooSmall {
                length: out.len(),
                required: self.range_count(),
            });
        }
        let attempted = self.load(ATTEMPTED, Ordering::Acquire);
        let stored = self.load(HEAD, Ordering::Acquire);
        let mut snapshot = LossSnapshot {
            attempted,
            stored,
            ranges: 0,
            unstable: 0,
            lost_before: None,
        };
        let mut scratch = [0u8; RANGE_BYTES];
        for index in 0..self.range_count() {
            let Some(slot) = self.range(index) else {
                continue;
            };
            let mut read = SlotRead::Unstable;
            for _ in 0..READ_ATTEMPTS {
                read = slot.read(&mut scratch);
                if read != SlotRead::Unstable {
                    break;
                }
            }
            match read {
                SlotRead::Value { .. } => {
                    // Sequences at or above `A` belong to appends after the
                    // horizon: clip them off.
                    if let Some(mut range) = DropRange::decode(&scratch)
                        && range.first < attempted
                        && let Some(target) = out.get_mut(snapshot.ranges)
                    {
                        range.last = range.last.min(attempted - 1);
                        *target = range;
                        snapshot.ranges += 1;
                    }
                }
                SlotRead::Unstable => snapshot.unstable += 1,
                SlotRead::Empty => {}
            }
        }
        // After the ranges: an evicted range's entry is reused only after
        // the watermark was raised past it.
        let mut bytes = [0u8; 8];
        if let Some(slot) = self.watermark() {
            let mut settled = false;
            for _ in 0..READ_ATTEMPTS {
                match slot.read(&mut bytes) {
                    SlotRead::Value { .. } => {
                        snapshot.lost_before = Some(u64::from_le_bytes(bytes).min(attempted));
                        settled = true;
                        break;
                    }
                    SlotRead::Empty => {
                        settled = true;
                        break;
                    }
                    SlotRead::Unstable => {}
                }
            }
            if !settled {
                snapshot.unstable += 1;
            }
        }
        Ok(snapshot)
    }
}

/// The loss accounting of a journal at one horizon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossSnapshot {
    /// The horizon `A`: every sequence below it was attempted.
    pub attempted: u64,
    /// Records stored, read after `A`: it counts every record stored below
    /// `A` and possibly some stored after it. A consumer that has received
    /// every stored record and still expects a sequence below `A` knows that
    /// sequence was dropped, even if no later record arrives.
    pub stored: u64,
    /// Stable drop ranges written to the caller's buffer.
    pub ranges: usize,
    /// Drop-range or watermark entries that kept changing within the read
    /// budget. When nonzero the snapshot is partial: it never shows that no
    /// loss happened.
    pub unstable: usize,
    /// Every sequence below this that is not a stored record may have been
    /// lost, with no known time; `None` if no range was ever evicted.
    pub lost_before: Option<u64>,
}

#[cfg(not(loom))]
pub use owned::{JournalConsumer, JournalWriter, Losses, Record, Taken, record_journal};
#[cfg(not(loom))]
pub use shared::{
    Drained, JOURNAL_LAYOUT_VERSION, JOURNAL_MAGIC, JournalDrain, JournalLayout, Violation,
    journal_block,
};
#[cfg(not(loom))]
#[cfg(target_os = "linux")]
pub use shared::{attach_journal, journal_region};

// Journals in one block of words: journal regions and their drain.
#[cfg(not(loom))]
mod shared;

#[cfg(not(loom))]
mod owned {
    use std::sync::Arc;

    use super::{
        Append, CONTROL_WORDS, DropRange, JournalError, JournalWords, Next, RANGE_WORDS, Stamp,
    };
    use crate::atomic_view::HeapWords;

    /// Where a journal's words live.
    #[derive(Debug)]
    pub(super) enum Backing {
        /// Three heap allocations: records, control and drop ranges.
        Heap {
            records: HeapWords,
            control: HeapWords,
            ranges: HeapWords,
        },
        /// One heap block in the layout of a journal region's structure
        /// ([`super::JournalLayout`]).
        Block(HeapWords),
        /// A journal region (Linux): created by the driver or attached by
        /// its client.
        #[cfg(target_os = "linux")]
        Mapped(crate::ipc::Region),
    }

    #[derive(Debug)]
    pub(super) struct Region {
        pub(super) backing: Backing,
        pub(super) record_words: usize,
        pub(super) capacity: usize,
        pub(super) range_count: usize,
        pub(super) payload_words: usize,
    }

    impl Region {
        /// The words of a block backing: the whole structure.
        pub(super) fn block(&self) -> Option<&[crate::sync::AtomicU64]> {
            match &self.backing {
                Backing::Heap { .. } => None,
                Backing::Block(heap) => Some(heap.words().as_slice()),
                #[cfg(target_os = "linux")]
                Backing::Mapped(region) => Some(region.structure().as_slice()),
            }
        }

        pub(super) fn words(&self) -> Result<JournalWords<'_>, JournalError> {
            let invalid = JournalError::InvalidConfig;
            if let Some(block) = self.block() {
                let layout = super::JournalLayout {
                    capacity: self.capacity,
                    payload_words: self.payload_words,
                    drop_ranges: self.range_count,
                };
                return layout.words(block).ok_or(invalid);
            }
            let Backing::Heap {
                records,
                control,
                ranges,
            } = &self.backing
            else {
                return Err(invalid);
            };
            JournalWords::new(
                records
                    .range(0, self.capacity * self.record_words)
                    .ok_or(invalid)?,
                control.range(0, CONTROL_WORDS).ok_or(invalid)?,
                ranges
                    .range(0, self.range_count * RANGE_WORDS)
                    .ok_or(invalid)?,
                self.payload_words,
            )
        }
    }

    /// Creates a journal of `capacity` records (a power of two) of
    /// `payload_words` words each, with `drop_ranges` drop-range entries
    /// (control path).
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidConfig`] when a size is zero or
    /// overflows, or `capacity` is not a power of two.
    pub fn record_journal(
        capacity: usize,
        payload_words: usize,
        drop_ranges: usize,
    ) -> Result<(JournalWriter, JournalConsumer), JournalError> {
        let invalid = JournalError::InvalidConfig;
        if capacity == 0 || !capacity.is_power_of_two() || payload_words == 0 || drop_ranges == 0 {
            return Err(invalid);
        }
        let record_words = payload_words.checked_add(1).ok_or(invalid)?;
        let records = HeapWords::zeroed(capacity.checked_mul(record_words).ok_or(invalid)?)
            .map_err(|_| invalid)?;
        let control = HeapWords::zeroed(CONTROL_WORDS).map_err(|_| invalid)?;
        let ranges = HeapWords::zeroed(drop_ranges.checked_mul(RANGE_WORDS).ok_or(invalid)?)
            .map_err(|_| invalid)?;
        let region = Arc::new(Region {
            backing: Backing::Heap {
                records,
                control,
                ranges,
            },
            record_words,
            capacity,
            range_count: drop_ranges,
            payload_words,
        });
        region.words()?;
        Ok((
            JournalWriter {
                region: Arc::clone(&region),
                guard: None,
            },
            JournalConsumer {
                payload: vec![0; payload_words].into_boxed_slice(),
                ranges: vec![DropRange::default(); drop_ranges].into_boxed_slice(),
                expected: 0,
                region,
            },
        ))
    }

    /// The journal's only writer (not `Clone`). Dropping it closes the
    /// journal.
    #[derive(Debug)]
    pub struct JournalWriter {
        pub(super) region: Arc<Region>,
        /// Dropped after the writer's last access and after `region`: a
        /// remote client's detach, sent once its mapping is gone.
        pub(super) guard: Option<Box<dyn core::any::Any + Send + Sync>>,
    }

    impl JournalWriter {
        /// Appends one record of the journal's payload length.
        ///
        /// # Errors
        ///
        /// As [`JournalWords::append`].
        pub fn append(&mut self, payload: &[u64], stamp: Stamp) -> Result<Append, JournalError> {
            self.region.words()?.append(payload, stamp)
        }

        /// Closes the journal; the consumer can still drain it.
        pub fn close(&mut self) {
            if let Ok(words) = self.region.words() {
                words.close();
            }
        }

        /// The same writer with `guard`, a value dropped after the writer's
        /// storage: for a journal region, after its mapping is gone (a
        /// remote client sends its `Detach` from it).
        #[must_use]
        pub fn with_guard(mut self, guard: impl core::any::Any + Send + Sync) -> Self {
            self.guard = Some(Box::new(guard));
            self
        }

        /// Words per record payload.
        #[must_use]
        pub fn payload_words(&self) -> usize {
            self.region.payload_words
        }

        /// Records the journal holds.
        #[must_use]
        pub fn capacity(&self) -> usize {
            self.region.capacity
        }

        #[cfg(test)]
        pub(super) fn seed_range_version(&self, index: usize, version: u64) {
            use crate::sync::Ordering;
            if let Ok(words) = self.region.words()
                && let Some(word) = words.ranges.get(index * super::RANGE_WORDS)
            {
                word.store(version, Ordering::Relaxed);
            }
        }

        #[cfg(test)]
        pub(super) fn seed_attempted(&self, sequence: u64) {
            use crate::sync::Ordering;
            if let Ok(words) = self.region.words() {
                words.store(super::ATTEMPTED, sequence, Ordering::Relaxed);
            }
        }
    }

    impl Drop for JournalWriter {
        fn drop(&mut self) {
            // Then the fields drop in order: the storage (a mapping is
            // unmapped with its last reference) before the guard.
            self.close();
        }
    }

    /// A record copied out of the journal; its payload borrows the
    /// consumer's buffer.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Record<'a> {
        /// Its sequence.
        pub sequence: u64,
        /// Sequences `[from, to)` before it that were never stored (dropped),
        /// if any.
        pub gap: Option<(u64, u64)>,
        /// Its payload words.
        pub payload: &'a [u64],
    }

    /// What [`JournalConsumer::take`] found.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Taken<'a> {
        /// A record, now released.
        Record(Record<'a>),
        /// No record is waiting; the journal is open.
        Empty,
        /// The journal is closed and fully drained: no record will follow.
        Closed,
    }

    /// The journal's loss accounting, read without consuming records.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Losses<'a> {
        /// The horizon: every sequence below it was attempted.
        pub attempted: u64,
        /// Records stored, read after the horizon.
        pub stored: u64,
        /// Stable drop ranges, clipped to the horizon.
        pub ranges: &'a [DropRange],
        /// Entries that kept changing; when nonzero the losses are partial.
        pub unstable: usize,
        /// Every sequence below this that is not a stored record may have
        /// been lost, with no known time; `None` if no range was evicted.
        pub lost_before: Option<u64>,
    }

    /// The journal's only consumer (not `Clone`).
    #[derive(Debug)]
    pub struct JournalConsumer {
        region: Arc<Region>,
        payload: Box<[u64]>,
        ranges: Box<[DropRange]>,
        expected: u64,
    }

    impl JournalConsumer {
        /// Copies and releases the oldest record.
        #[must_use]
        pub fn take(&mut self) -> Taken<'_> {
            let Ok(words) = self.region.words() else {
                return Taken::Closed;
            };
            match words.take(&mut self.payload) {
                Ok(Next::Record { sequence }) => {
                    let gap = (sequence != self.expected).then_some((self.expected, sequence));
                    self.expected = sequence.checked_add(1).unwrap_or(sequence);
                    Taken::Record(Record {
                        sequence,
                        gap,
                        payload: &self.payload,
                    })
                }
                Ok(Next::Closed) => Taken::Closed,
                // The payload buffer has the record length by construction.
                Ok(Next::Empty) | Err(_) => Taken::Empty,
            }
        }

        /// The loss accounting at a fresh horizon; see
        /// [`JournalWords::losses`].
        #[must_use]
        pub fn losses(&mut self) -> Losses<'_> {
            let Ok(words) = self.region.words() else {
                return Losses {
                    attempted: 0,
                    stored: 0,
                    ranges: &[],
                    unstable: 0,
                    lost_before: None,
                };
            };
            // The buffer holds every drop range by construction.
            let Ok(snapshot) = words.losses(&mut self.ranges) else {
                return Losses {
                    attempted: 0,
                    stored: 0,
                    ranges: &[],
                    unstable: 1,
                    lost_before: None,
                };
            };
            Losses {
                attempted: snapshot.attempted,
                stored: snapshot.stored,
                ranges: self.ranges.get(..snapshot.ranges).unwrap_or(&[]),
                unstable: snapshot.unstable,
                lost_before: snapshot.lost_before,
            }
        }

        /// Whether the writer closed the journal.
        #[must_use]
        pub fn is_closed(&self) -> bool {
            self.region.words().is_ok_and(|words| words.is_closed())
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests;
