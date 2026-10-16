// SPDX-License-Identifier: Apache-2.0

//! The schedule ring of a timed lane (`quantstratum-docs:
//! karyos/design/timed-tx.md`, section 2, TT-1, decided in ACS 15387).
//!
//! A timed lane's requested times travel from its exclusive publisher to
//! the sender agent outside the wire data: one entry per message, the
//! position of its first frame and its requested time, in a bounded ring
//! preallocated with the lane. The publisher alone writes the entries and
//! the `tail`; the sender alone writes the `head`.
//!
//! Layout, in `u64` words: `[capacity, tail, head]`, then `capacity`
//! entries of two words, `[position, time]`. The capacity is a power of
//! two, and entry `n` (counted from 0) lives in slot `n % capacity`.
//!
//! - **Publisher.** Before it reserves a message, [`SchedulePublisher::has_room`]
//!   loads `head` with Acquire and refuses when `tail - head` is the
//!   capacity: the offer is back pressured before any reservation. The
//!   Acquire orders the slot's reuse after the sender's last read of it.
//!   After the reservation and before the message's commit store,
//!   [`SchedulePublisher::push`] stores the entry's words Relaxed and then
//!   `tail + 1` with Release. A sender that sees the committed frame and
//!   loads `tail` with Acquire sees the entry.
//! - **Sender.** [`ScheduleReader::peek`] loads `tail` with Acquire and
//!   reads the entry at `head`; [`ScheduleReader::release`] stores
//!   `head + 1` with Release once every path submitted the message, which
//!   frees the slot.
//!
//! `tail` and `head` count entries and never wrap: 2^64 messages on one
//! lane are refused as exhausted, never wrapped (SPEC.md section 14).

use crate::sync::{AtomicU64, Ordering};

/// Words before the first entry: capacity, tail, head.
pub const HEADER_WORDS: usize = 3;
/// Words of one entry: position, time.
pub const ENTRY_WORDS: usize = 2;

const CAPACITY: usize = 0;
const TAIL: usize = 1;
const HEAD: usize = 2;

/// Loom only: the production orderings, which the negative controls
/// weaken.
#[cfg(loom)]
const HEAD_LOAD: Ordering = Ordering::Acquire;

/// Why a ring operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScheduleError {
    /// The words do not hold a ring of the declared capacity, or the
    /// capacity is not a power of two.
    #[error("the schedule ring's layout is invalid")]
    Layout,
    /// `capacity` entries wait for the sender: back pressure.
    #[error("the schedule ring is full")]
    Full,
    /// The publisher pushed without checking room first, or the counts
    /// contradict each other: a broken invariant.
    #[error("the schedule ring's counts are inconsistent")]
    Invariant,
    /// The lane is not timed, or a timed lane was given a plain offer or
    /// claim: a timed lane carries timed messages only.
    #[error("not a timed lane, or a timed lane offered without a time")]
    NotScheduled,
    /// 2^64 entries were pushed on the lane.
    #[error("the schedule ring's entries are exhausted")]
    Exhausted,
}

/// One message's schedule: the position of its first frame and its
/// requested time in the publication's clock domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The stream position of the message's first frame.
    pub position: u64,
    /// The requested not-before time.
    pub time: u64,
}

/// Words a ring of `capacity` entries needs; `None` on overflow.
#[must_use]
pub fn ring_words(capacity: usize) -> Option<usize> {
    capacity
        .checked_mul(ENTRY_WORDS)
        .and_then(|entries| entries.checked_add(HEADER_WORDS))
}

/// Initializes `ring` as an empty ring of `capacity` entries.
///
/// # Errors
///
/// [`ScheduleError::Layout`] for a capacity that is not a power of two,
/// or words that do not match it.
pub fn init(ring: &[AtomicU64], capacity: u64) -> Result<(), ScheduleError> {
    check_layout(ring, capacity)?;
    for word in ring {
        word.store(0, Ordering::Relaxed);
    }
    ring.get(CAPACITY)
        .ok_or(ScheduleError::Layout)?
        .store(capacity, Ordering::Release);
    Ok(())
}

fn check_layout(ring: &[AtomicU64], capacity: u64) -> Result<(), ScheduleError> {
    let words = usize::try_from(capacity)
        .ok()
        .filter(|capacity| capacity.is_power_of_two())
        .and_then(ring_words)
        .ok_or(ScheduleError::Layout)?;
    if ring.len() == words {
        Ok(())
    } else {
        Err(ScheduleError::Layout)
    }
}

/// The capacity a ring declares, checked against its words.
fn declared(ring: &[AtomicU64]) -> Result<u64, ScheduleError> {
    let capacity = ring
        .get(CAPACITY)
        .ok_or(ScheduleError::Layout)?
        .load(Ordering::Acquire);
    check_layout(ring, capacity)?;
    Ok(capacity)
}

/// The first word of entry `count`'s slot.
fn slot_base(capacity: u64, count: u64) -> Option<usize> {
    let slot = usize::try_from(count.checked_rem(capacity)?).ok()?;
    slot.checked_mul(ENTRY_WORDS)?.checked_add(HEADER_WORDS)
}

fn word(ring: &[AtomicU64], index: usize) -> Result<&AtomicU64, ScheduleError> {
    ring.get(index).ok_or(ScheduleError::Layout)
}

/// Loom only: one ownership witness per slot, shared by the publisher and
/// the reader of one ring.
#[cfg(loom)]
pub type Witness = loom::sync::Arc<Vec<loom::cell::UnsafeCell<u64>>>;

/// Loom only: the witness of entry `count`'s slot.
#[cfg(loom)]
fn witness(
    witness: Option<&Witness>,
    capacity: u64,
    count: u64,
) -> Option<&loom::cell::UnsafeCell<u64>> {
    let slot = usize::try_from(count.checked_rem(capacity)?).ok()?;
    witness?.get(slot)
}

/// The exclusive publisher's side of one ring.
#[derive(Debug)]
pub struct SchedulePublisher {
    capacity: u64,
    /// Entries pushed: the `tail` this side alone writes.
    tail: u64,
    /// `has_room` admitted the next push.
    room: bool,
    #[cfg(loom)]
    head_load: Ordering,
    #[cfg(loom)]
    witness: Option<Witness>,
}

impl SchedulePublisher {
    /// The publisher of the initialized `ring`.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Layout`].
    pub fn attach(ring: &[AtomicU64]) -> Result<Self, ScheduleError> {
        let capacity = declared(ring)?;
        let tail = word(ring, TAIL)?.load(Ordering::Relaxed);
        Ok(Self {
            capacity,
            tail,
            room: false,
            #[cfg(loom)]
            head_load: HEAD_LOAD,
            #[cfg(loom)]
            witness: None,
        })
    }

    /// Loom only: the negative control's ordering for the head load.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_head_load(mut self, order: Ordering) -> Self {
        self.head_load = order;
        self
    }

    /// Loom only: attaches one witness per slot. The publisher writes a
    /// slot's witness in `push`, after `has_room`; the reader reads it in
    /// `peek`, before `release`, with no other synchronization, so Loom
    /// reports a race when the head handoff does not order a slot's reuse.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_witness(mut self, witness: Witness) -> Self {
        self.witness = Some(witness);
        self
    }

    /// Whether the next message's entry fits, checked before the message
    /// is reserved: `false` is back pressure, and nothing is reserved.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Layout`] and [`ScheduleError::Invariant`] for a
    /// head past the tail.
    pub fn has_room(&mut self, ring: &[AtomicU64]) -> Result<bool, ScheduleError> {
        #[cfg(loom)]
        let order = self.head_load;
        #[cfg(not(loom))]
        let order = Ordering::Acquire;
        // 2^64 entries are refused before the reservation, not after it.
        if self.tail == u64::MAX {
            return Err(ScheduleError::Exhausted);
        }
        let head = word(ring, HEAD)?.load(order);
        let waiting = self
            .tail
            .checked_sub(head)
            .ok_or(ScheduleError::Invariant)?;
        if waiting > self.capacity {
            return Err(ScheduleError::Invariant);
        }
        self.room = waiting < self.capacity;
        Ok(self.room)
    }

    /// Records the reserved message's entry, before its commit store: the
    /// entry's words Relaxed, then `tail + 1` with Release.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Invariant`] without a `has_room` that admitted it,
    /// [`ScheduleError::Exhausted`] past 2^64 entries, and
    /// [`ScheduleError::Layout`]. Nothing is stored on error.
    pub fn push(&mut self, ring: &[AtomicU64], entry: Entry) -> Result<(), ScheduleError> {
        if !self.room {
            return Err(ScheduleError::Invariant);
        }
        let next = self.tail.checked_add(1).ok_or(ScheduleError::Exhausted)?;
        let base = slot_base(self.capacity, self.tail).ok_or(ScheduleError::Layout)?;
        let position = word(ring, base)?;
        let time = word(ring, base.checked_add(1).ok_or(ScheduleError::Layout)?)?;
        let tail = word(ring, TAIL)?;
        #[cfg(loom)]
        if let Some(cell) = witness(self.witness.as_ref(), self.capacity, self.tail) {
            let count = self.tail;
            // SAFETY: Loom checks that this write is ordered after the
            // reader's last read of the slot's witness.
            cell.with_mut(|value| unsafe { *value = count });
        }
        position.store(entry.position, Ordering::Relaxed);
        time.store(entry.time, Ordering::Relaxed);
        tail.store(next, Ordering::Release);
        self.tail = next;
        self.room = false;
        Ok(())
    }
}

/// The sender's side of one ring.
#[derive(Debug)]
pub struct ScheduleReader {
    capacity: u64,
    /// Entries released: the `head` this side alone writes.
    head: u64,
    #[cfg(loom)]
    witness: Option<Witness>,
    /// Loom only: the negative control that stores the head before the
    /// entry is read, so the publisher may overwrite it mid-read.
    #[cfg(loom)]
    release_first: bool,
}

impl ScheduleReader {
    /// The reader of the initialized `ring`.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Layout`].
    pub fn attach(ring: &[AtomicU64]) -> Result<Self, ScheduleError> {
        let capacity = declared(ring)?;
        let head = word(ring, HEAD)?.load(Ordering::Relaxed);
        Ok(Self {
            capacity,
            head,
            #[cfg(loom)]
            witness: None,
            #[cfg(loom)]
            release_first: false,
        })
    }

    /// Loom only: the negative control that releases the head before the
    /// entry's words are read.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_release_first(mut self) -> Self {
        self.release_first = true;
        self
    }

    /// Loom only: see [`SchedulePublisher::with_witness`].
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_witness(mut self, witness: Witness) -> Self {
        self.witness = Some(witness);
        self
    }

    /// The entry at the head, if the publisher pushed one: `tail` with
    /// Acquire, then the entry's words.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Layout`] and [`ScheduleError::Invariant`] for a
    /// tail behind the head or more than the capacity ahead.
    pub fn peek(&self, ring: &[AtomicU64]) -> Result<Option<Entry>, ScheduleError> {
        let tail = word(ring, TAIL)?.load(Ordering::Acquire);
        let waiting = tail
            .checked_sub(self.head)
            .ok_or(ScheduleError::Invariant)?;
        if waiting > self.capacity {
            return Err(ScheduleError::Invariant);
        }
        if waiting == 0 {
            return Ok(None);
        }
        let base = slot_base(self.capacity, self.head).ok_or(ScheduleError::Layout)?;
        #[cfg(loom)]
        if self.release_first {
            let next = self.head.checked_add(1).ok_or(ScheduleError::Invariant)?;
            word(ring, HEAD)?.store(next, Ordering::Release);
        }
        let position = word(ring, base)?.load(Ordering::Relaxed);
        let time =
            word(ring, base.checked_add(1).ok_or(ScheduleError::Layout)?)?.load(Ordering::Relaxed);
        #[cfg(loom)]
        if let Some(cell) = witness(self.witness.as_ref(), self.capacity, self.head) {
            // SAFETY: Loom checks that this read is ordered before the
            // publisher's next write of the slot's witness.
            let _ = cell.with(|value| unsafe { *value });
        }
        Ok(Some(Entry { position, time }))
    }

    /// Frees the head's slot once every path submitted its message:
    /// `head + 1` with Release.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Invariant`] with no entry at the head, and
    /// [`ScheduleError::Layout`].
    pub fn release(&mut self, ring: &[AtomicU64]) -> Result<(), ScheduleError> {
        let tail = word(ring, TAIL)?.load(Ordering::Acquire);
        if tail == self.head {
            return Err(ScheduleError::Invariant);
        }
        let next = self.head.checked_add(1).ok_or(ScheduleError::Invariant)?;
        #[cfg(loom)]
        let stored = self.release_first;
        #[cfg(not(loom))]
        let stored = false;
        if !stored {
            word(ring, HEAD)?.store(next, Ordering::Release);
        }
        self.head = next;
        Ok(())
    }

    /// Entries released so far.
    #[must_use]
    pub fn released(&self) -> u64 {
        self.head
    }
}

#[cfg(all(test, not(loom)))]
mod tests;
