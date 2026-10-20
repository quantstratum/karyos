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
//! Layout, in `u64` words: an eight word header `[capacity, tail, head,
//! domain, max_horizon, lateness_tolerance, flags, reserved]`, then
//! `capacity` entries of two words, `[position, time]`. The capacity is a
//! power of two, and entry `n` (counted from 0) lives in slot
//! `n % capacity`. Words 3 to 6 are the lane's binding ([`Binding`],
//! timed-tx.md section 11, TT-6b): the driver writes them when it creates
//! the lane, before any handle is issued; the publisher only reads them,
//! and the sender never does.
//!
//! - **Publisher.** Before it reserves a message, [`SchedulePublisher::has_room`]
//!   loads `head` with Acquire and refuses when `tail - head` is the
//!   capacity: the offer is back pressured before any reservation. The
//!   Acquire orders the slot's reuse after the sender's last read of it.
//!   After the reservation and before the message's commit store,
//!   [`SchedulePublisher::push`] stores the entry's words Relaxed and then
//!   `tail + 1` with Release. A sender that sees the committed frame and
//!   loads `tail` with Acquire sees the entry.
//! - **Sender.** The sender trusts no word the publisher writes
//!   (timed-tx.md section 11, TT-6): a remote publisher is another
//!   process. [`ScheduleReader::peek`] loads `tail` with Acquire and copies
//!   the entry at its read cursor into private memory, each word loaded
//!   once; it checks the copies and acts only on them, never reading the
//!   shared words of that entry again. It keeps `head` privately and only
//!   stores it: [`ScheduleReader::release`] stores `head + 1` with Release
//!   once every path submitted the message, which frees the slot.
//!   [`ScheduleReader::rewind_to_released`] reads again from `head`, from
//!   the private copies. A breach of the checks is
//!   [`ScheduleError::Violation`], for good.
//!
//! `tail` and `head` count entries and never wrap: 2^64 messages on one
//! lane are refused as exhausted, never wrapped (SPEC.md section 14).
//!
//! The sender's copies take 16 bytes per entry of the ring's capacity,
//! allocated once at attach, on the control path.

use crate::sync::{AtomicU64, Ordering};

/// Words before the first entry: capacity, tail, head, then the binding's
/// domain, `max_horizon`, `lateness_tolerance` and flags, and a reserved
/// word.
pub const HEADER_WORDS: usize = 8;
/// Words of one entry: position, time.
pub const ENTRY_WORDS: usize = 2;

const CAPACITY: usize = 0;
const TAIL: usize = 1;
const HEAD: usize = 2;
const DOMAIN: usize = 3;
const MAX_HORIZON: usize = 4;
const LATENESS_TOLERANCE: usize = 5;
const FLAGS: usize = 6;

/// Bit 0 of the binding's flags word: cancel on deadline.
const CANCEL_ON_DEADLINE: u64 = 1;

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
    /// A requested time below the lane's last: times never go backwards
    /// on a timed lane.
    #[error("a requested time below the lane's last")]
    Backwards,
    /// The publisher's words breach the sender's checks (timed-tx.md
    /// section 11, TT-6): a tail below its last copy or past
    /// `head + capacity`, or an entry's time below the lane's last or past
    /// the sender's `now + max_horizon`. A protocol violation of the
    /// publisher, for good: the reader refuses every later read.
    #[error("the schedule ring's publisher breached its protocol")]
    Violation,
    /// 2^64 entries were pushed on the lane.
    #[error("the schedule ring's entries are exhausted")]
    Exhausted,
    /// A lane's schedule capacity is not a power of two up to
    /// [`MAX_CAPACITY`].
    #[error("schedule capacity {capacity} is not a power of two in 1..={max}", max = MAX_CAPACITY)]
    Capacity {
        /// The capacity given.
        capacity: u32,
    },
}

/// The largest schedule capacity a lane takes: 2^20 entries (16 MiB of
/// ring), a second of timed messages at a million a second.
pub const MAX_CAPACITY: u32 = 1 << 20;

/// One message's schedule: the position of its first frame and its
/// requested time in the publication's clock domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The stream position of the message's first frame.
    pub position: u64,
    /// The requested not-before time.
    pub time: u64,
}

/// A timed lane's binding (timed-tx.md section 11, TT-6b): the parameters
/// a publisher needs to check its own offers. The driver writes it with
/// [`write_binding`] when it creates the lane; the publisher reads it with
/// [`binding`]. The sender checks entries against its own configuration,
/// never against these words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// The clock domain's code, as the client's `ClockDomain` gives it.
    pub domain: u64,
    /// The furthest ahead of `now` a requested time may be.
    pub max_horizon: u64,
    /// How far past its time a message may be submitted and not be late.
    pub lateness_tolerance: u64,
    /// A missed deadline aborts the lane instead of sending late.
    pub cancel_on_deadline: bool,
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

/// Writes `binding` into the initialized `ring`'s header: the driver, when
/// it creates the lane, before any handle is issued.
///
/// # Errors
///
/// [`ScheduleError::Layout`].
pub fn write_binding(ring: &[AtomicU64], binding: Binding) -> Result<(), ScheduleError> {
    declared(ring)?;
    let flags = if binding.cancel_on_deadline {
        CANCEL_ON_DEADLINE
    } else {
        0
    };
    for (index, value) in [
        (DOMAIN, binding.domain),
        (MAX_HORIZON, binding.max_horizon),
        (LATENESS_TOLERANCE, binding.lateness_tolerance),
        (FLAGS, flags),
    ] {
        word(ring, index)?.store(value, Ordering::Release);
    }
    Ok(())
}

/// The binding the driver wrote into `ring`'s header: the publisher's
/// read. The sender never reads it.
///
/// # Errors
///
/// [`ScheduleError::Layout`], also for a flag this build does not know.
pub fn binding(ring: &[AtomicU64]) -> Result<Binding, ScheduleError> {
    declared(ring)?;
    let load = |index| word(ring, index).map(|word| word.load(Ordering::Acquire));
    let flags = load(FLAGS)?;
    if flags & !CANCEL_ON_DEADLINE != 0 {
        return Err(ScheduleError::Layout);
    }
    Ok(Binding {
        domain: load(DOMAIN)?,
        max_horizon: load(MAX_HORIZON)?,
        lateness_tolerance: load(LATENESS_TOLERANCE)?,
        cancel_on_deadline: flags & CANCEL_ON_DEADLINE != 0,
    })
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

/// The sender's side of one ring. It reads entries ahead of the ones it
/// releases: `next`, private to the reader, is the next entry to read, and
/// `head`, the only count the publisher sees, is the next one to free. An
/// entry is read when its message's first frame is staged and freed only
/// once every path submitted the message's last fragment (timed-tx.md,
/// section 2 step 4), so the ring's capacity bounds the timed messages
/// outstanding, which is the publisher's back pressure.
///
/// It trusts no word the publisher writes (timed-tx.md section 11, TT-6).
/// It never loads `head` after attach; it loads `tail` only to learn of
/// new entries, and checks each copy; it copies each entry once, checks
/// the copy and serves every later read of it, a rewind's included, from
/// the copy. A breach is [`ScheduleError::Violation`], and every later
/// read is refused the same way.
#[derive(Debug)]
pub struct ScheduleReader {
    capacity: u64,
    /// Entries released: the `head` this side alone writes, and never
    /// loads back after attach.
    head: u64,
    /// Entries read; never behind `head`, never past `copied`. Private to
    /// the reader.
    next: u64,
    /// Entries copied; never past `tail`.
    copied: u64,
    /// The last valid copy of `tail`.
    tail: u64,
    /// The time of the last entry copied: the next one's floor.
    last_time: u64,
    /// The copies, entry `n` in slot `n % capacity`: those from `head` to
    /// `copied` are live, and `copied - head` never exceeds the capacity.
    copies: Vec<Entry>,
    /// A breach was found: every later read is refused.
    violated: bool,
    #[cfg(loom)]
    witness: Option<Witness>,
    /// Loom only: the negative control whose release does not check the
    /// read cursor, so a slot can be freed before its entry is read.
    #[cfg(loom)]
    unchecked_release: bool,
    /// Loom only: the negative control that reads an entry's shared words
    /// again instead of its copy.
    #[cfg(loom)]
    reread: bool,
}

impl ScheduleReader {
    /// The reader of the initialized `ring`, attached before any handle of
    /// the lane is issued, so the `head` it loads is the driver's own. Its
    /// copies are allocated here, sized to the ring's capacity.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Layout`].
    pub fn attach(ring: &[AtomicU64]) -> Result<Self, ScheduleError> {
        let capacity = declared(ring)?;
        let head = word(ring, HEAD)?.load(Ordering::Relaxed);
        let slots = usize::try_from(capacity).map_err(|_| ScheduleError::Layout)?;
        Ok(Self {
            capacity,
            head,
            next: head,
            copied: head,
            tail: head,
            last_time: 0,
            copies: vec![
                Entry {
                    position: 0,
                    time: 0,
                };
                slots
            ],
            violated: false,
            #[cfg(loom)]
            witness: None,
            #[cfg(loom)]
            unchecked_release: false,
            #[cfg(loom)]
            reread: false,
        })
    }

    /// Loom only: the negative control that reads an entry's shared words
    /// again on every read, a rewind's included, instead of its copy.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_reread(mut self) -> Self {
        self.reread = true;
        self
    }

    /// Loom only: the negative control whose `release` may pass the read
    /// cursor.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_unchecked_release(mut self) -> Self {
        self.unchecked_release = true;
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

    /// Records a breach, for good.
    fn breach(&mut self) -> ScheduleError {
        self.violated = true;
        ScheduleError::Violation
    }

    /// Loads `tail` with Acquire and checks the copy: at least the last
    /// valid one, at most `head + capacity`, compared without wrapping.
    fn load_tail(&mut self, ring: &[AtomicU64]) -> Result<u64, ScheduleError> {
        let tail = word(ring, TAIL)?.load(Ordering::Acquire);
        // A bound past 2^64 bounds nothing a word can hold.
        let past = self
            .head
            .checked_add(self.capacity)
            .is_some_and(|bound| tail > bound);
        if tail < self.tail || past {
            return Err(self.breach());
        }
        self.tail = tail;
        Ok(tail)
    }

    /// Copies entry `copied` from the ring, each word loaded once, and
    /// checks its time: at least the last entry's, at most `now +
    /// max_horizon` (the sender's own clock and horizon).
    fn copy(
        &mut self,
        ring: &[AtomicU64],
        now: u64,
        max_horizon: u64,
    ) -> Result<(), ScheduleError> {
        let base = slot_base(self.capacity, self.copied).ok_or(ScheduleError::Layout)?;
        let position = word(ring, base)?.load(Ordering::Relaxed);
        let time =
            word(ring, base.checked_add(1).ok_or(ScheduleError::Layout)?)?.load(Ordering::Relaxed);
        #[cfg(loom)]
        if let Some(cell) = witness(self.witness.as_ref(), self.capacity, self.copied) {
            // SAFETY: Loom checks that this read is ordered before the
            // publisher's next write of the slot's witness.
            let _ = cell.with(|value| unsafe { *value });
        }
        let ahead = now
            .checked_add(max_horizon)
            .is_some_and(|bound| time > bound);
        if time < self.last_time || ahead {
            return Err(self.breach());
        }
        let slot = self.slot(self.copied)?;
        *slot = Entry { position, time };
        self.last_time = time;
        self.copied = self.copied.checked_add(1).ok_or(ScheduleError::Invariant)?;
        Ok(())
    }

    /// The copy slot of entry `count`.
    fn slot(&mut self, count: u64) -> Result<&mut Entry, ScheduleError> {
        let slot = count
            .checked_rem(self.capacity)
            .and_then(|slot| usize::try_from(slot).ok())
            .ok_or(ScheduleError::Layout)?;
        self.copies.get_mut(slot).ok_or(ScheduleError::Layout)
    }

    /// The next entry to read, if the publisher pushed it. An entry read
    /// for the first time is copied: `tail` with Acquire when the copies
    /// have reached the last one, then the entry's words, checked against
    /// the sender's `now` and `max_horizon`. Every later read of it is the
    /// copy. Reading it does not consume it; [`Self::advance`] does.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Violation`] for a breach, now or before, and
    /// [`ScheduleError::Layout`].
    pub fn peek(
        &mut self,
        ring: &[AtomicU64],
        now: u64,
        max_horizon: u64,
    ) -> Result<Option<Entry>, ScheduleError> {
        if self.violated {
            return Err(ScheduleError::Violation);
        }
        if self.next == self.copied {
            if self.copied == self.tail && self.load_tail(ring)? == self.copied {
                return Ok(None);
            }
            self.copy(ring, now, max_horizon)?;
        }
        #[cfg(loom)]
        if self.reread {
            let base = slot_base(self.capacity, self.next).ok_or(ScheduleError::Layout)?;
            let position = word(ring, base)?.load(Ordering::Relaxed);
            let time = word(ring, base.checked_add(1).ok_or(ScheduleError::Layout)?)?
                .load(Ordering::Relaxed);
            return Ok(Some(Entry { position, time }));
        }
        let next = self.next;
        self.slot(next).map(|entry| Some(*entry))
    }

    /// Moves the read cursor past the entry [`Self::peek`] returned.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Invariant`] with no entry peeked, and
    /// [`ScheduleError::Violation`] after a breach.
    pub fn advance(&mut self) -> Result<(), ScheduleError> {
        if self.violated {
            return Err(ScheduleError::Violation);
        }
        if self.next == self.copied {
            return Err(ScheduleError::Invariant);
        }
        self.next = self.next.checked_add(1).ok_or(ScheduleError::Invariant)?;
        Ok(())
    }

    /// Frees the oldest read entry's slot once every path submitted its
    /// message: `head + 1` with Release. It never passes the read cursor.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Invariant`] with no read entry left to free, and
    /// [`ScheduleError::Layout`].
    pub fn release(&mut self, ring: &[AtomicU64]) -> Result<(), ScheduleError> {
        #[cfg(loom)]
        let checked = !self.unchecked_release;
        #[cfg(not(loom))]
        let checked = true;
        if checked && self.head == self.next {
            return Err(ScheduleError::Invariant);
        }
        let head = self.head.checked_add(1).ok_or(ScheduleError::Invariant)?;
        word(ring, HEAD)?.store(head, Ordering::Release);
        self.head = head;
        Ok(())
    }

    /// Moves the read cursor back to the oldest entry not released, so the
    /// entries read since are read again, in order: a reliable lane's
    /// sender rewinds its log to a position whose messages' entries it has
    /// not released yet. It touches no word of the ring: the entries read
    /// again are the copies, whatever the publisher wrote since.
    pub fn rewind_to_released(&mut self) {
        self.next = self.head;
    }

    /// Whether a breach was found ([`ScheduleError::Violation`]).
    #[must_use]
    pub fn violated(&self) -> bool {
        self.violated
    }

    /// The ring's capacity in entries, as it declared it at attach.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Entries read so far.
    #[must_use]
    pub fn read(&self) -> u64 {
        self.next
    }

    /// Entries released so far.
    #[must_use]
    pub fn released(&self) -> u64 {
        self.head
    }
}

#[cfg(all(test, not(loom)))]
mod tests;
