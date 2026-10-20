// SPDX-License-Identifier: Apache-2.0

//! Bounded tables of generation-tagged handles (quantstratum-docs:
//! karyos/design/ffi-gap-analysis.md §4.2).
//!
//! A handle is a `u64`: the slot's generation in the high 32 bits (never
//! 0), the table's kind in the next 8, the slot index in the low 24. `0` is
//! never a handle. A slot's object sits in a `Mutex`, taken with
//! `try_lock` only, so a call never blocks: a slot held by another thread
//! answers [`Status::Busy`], one held by this thread (a callback that
//! reenters its handle) answers [`Status::Reentrant`]. A panic while a
//! slot is held poisons its mutex, and every later use of its handle
//! answers [`Status::Internal`] until the handle is closed; a stale handle
//! of that slot still answers [`Status::Closed`] and never clears it.
//!
//! Closing moves the slot's generation on at once, so a stale or twice
//! closed handle answers [`Status::Closed`]. Every slot of this copy of the
//! library starts at one base generation, drawn once per copy
//! ([`copy_base`]), and counts on from it, skipping 0; a slot whose next
//! generation would come back to the base has cycled all 2^32 - 1 and is
//! retired, never reused. A handle of another copy in the same process
//! (two static copies, BIND-CPP-Q12) therefore names a slot at another
//! generation and answers [`Status::Closed`], except with probability
//! 2^-32 per call: a copy cannot tell a foreign handle from a stale one.
//! The generation is an atomic read before the mutex is tried, so a stale
//! handle never disturbs a live one. One
//! narrow window is left: a call that read the generation just before a
//! concurrent close and a reuse of the slot holds the mutex for a moment,
//! and a call on the new handle at that instant answers [`Status::Busy`].
//! Both are racing a close; `BUSY` around a close is transient, and a
//! retry succeeds.

use std::cell::Cell;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, TryLockError};

use crate::status::Status;

/// The largest table: indices have 24 bits.
pub(crate) const MAX_CAPACITY: u32 = 1 << 24;

/// Bits of the slot index in a handle.
const INDEX_BITS: u32 = 24;
/// Bits of the kind in a handle, above the index.
const KIND_BITS: u32 = 8;
/// The mask of the slot index.
const INDEX_MASK: u64 = (1 << INDEX_BITS) - 1;
/// The mask of the kind, once shifted down.
const KIND_MASK: u64 = (1 << KIND_BITS) - 1;
/// A thread token no thread has.
const NO_THREAD: u64 = 0;

/// The kind of object a table holds; part of each handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    /// An embedded driver.
    Driver = 2,
    /// A client.
    Client = 3,
    /// A publication.
    Publication = 4,
    /// A staged claim.
    Claim = 5,
    /// A subscription.
    Subscription = 6,
    /// A conflated subscription.
    ConflatedSubscription = 7,
    /// The outcome stream of a guarded publication.
    OutcomeStream = 8,
    /// A connection to an Archive (F9a).
    Archive = 9,
}

/// A handle's parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Handle(u64);

impl Handle {
    /// The handle of `index` at `generation` in a table of `kind`.
    const fn new(kind: Kind, index: u32, generation: u32) -> Self {
        Self(
            ((generation as u64) << (INDEX_BITS + KIND_BITS))
                | ((kind as u64) << INDEX_BITS)
                | (index as u64 & INDEX_MASK),
        )
    }

    /// The raw value the C ABI carries.
    pub(crate) const fn raw(self) -> u64 {
        self.0
    }

    /// A raw value as a handle.
    pub(crate) const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The generation.
    const fn generation(self) -> u32 {
        (self.0 >> (INDEX_BITS + KIND_BITS)) as u32
    }

    /// The kind byte.
    const fn kind(self) -> u64 {
        (self.0 >> INDEX_BITS) & KIND_MASK
    }

    /// The slot index.
    const fn index(self) -> u32 {
        (self.0 & INDEX_MASK) as u32
    }
}

/// The next thread token handed out; tokens start at 1.
static NEXT_THREAD: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// This thread's token, taken on first use.
    static THREAD: Cell<u64> = const { Cell::new(NO_THREAD) };
}

/// This thread's token: nonzero and distinct from every other live
/// thread's.
fn thread_token() -> u64 {
    THREAD.with(|token| {
        if token.get() == NO_THREAD {
            token.set(NEXT_THREAD.fetch_add(1, Ordering::Relaxed));
        }
        token.get()
    })
}

/// A slot: its object under a mutex, the generation of the handle that
/// names it, and the token of the thread holding it.
///
/// The generation is an atomic read before the mutex is tried, so a stale
/// handle answers [`Status::Closed`] without touching the mutex: it never
/// makes a live handle's call on another thread answer [`Status::Busy`].
/// A close moves it on at once (a slot whose generation cannot grow is
/// retired), and a create hands out the slot's current one.
#[derive(Debug)]
struct Slot<T> {
    entry: Mutex<Option<T>>,
    /// The generation of the slot's next or current handle; never 0. It
    /// changes only under the mutex.
    generation: AtomicU32,
    holder: AtomicU64,
}

/// Clears a slot's holder when the slot is let go of, also by unwinding.
struct Held<'a> {
    holder: &'a AtomicU64,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.holder.store(NO_THREAD, Ordering::Release);
    }
}

/// A slot taken by a close: its object, and whether a panic poisoned it.
type Taken<'a, T> = (MutexGuard<'a, Option<T>>, bool);

/// A bounded table of one kind of object.
#[derive(Debug)]
pub(crate) struct Table<T> {
    kind: Kind,
    /// The generation every slot starts at, and comes back to only after
    /// all 2^32 - 1 ([`copy_base`] for the library's tables).
    base: u32,
    slots: Box<[Slot<T>]>,
    /// Slots free to take, as a stack. Taken on the control path only.
    free: Mutex<Vec<u32>>,
}

/// Slots [`Table::take_all`] holds for a close.
pub(crate) struct TakenAll<'a, T> {
    table: &'a Table<T>,
    taken: Vec<(Handle, &'a Slot<T>, Taken<'a, T>)>,
}

impl<T> TakenAll<'_, T> {
    /// Closes every handle taken and returns their objects.
    ///
    /// # Errors
    ///
    /// As [`Table::remove`] once its slot is taken.
    pub(crate) fn close(self) -> Result<Vec<T>, Status> {
        let mut values = Vec::with_capacity(self.taken.len());
        for (handle, slot, held) in self.taken {
            values.push(self.table.close(slot, handle, held)?);
        }
        Ok(values)
    }
}

/// This copy of the library's base generation: drawn once, never 0, from
/// the address of a static of this copy. Two copies in one process hold
/// their statics at different addresses, so their bases differ except
/// with probability 2^-32 (the module). No clock or process id: an
/// address is what tells copies apart, and it is read without a system
/// call, as Miri's isolation requires.
pub(crate) fn copy_base() -> u32 {
    static BASE: OnceLock<u32> = OnceLock::new();
    *BASE.get_or_init(|| {
        static ANCHOR: u8 = 0;
        // The address's bytes, folded into a `u64` with no cast.
        let address = core::ptr::from_ref(&ANCHOR)
            .addr()
            .to_le_bytes()
            .iter()
            .rev()
            .fold(0_u64, |folded, byte| {
                folded.rotate_left(8) ^ u64::from(*byte)
            });
        nonzero(mix(address))
    })
}

/// SplitMix64's finalizer: every input bit reaches every output bit. The
/// wrapping multiplications are modular hashing, not quantities.
const fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// The high 32 bits of `value`, or 1 if they are 0.
fn nonzero(value: u64) -> u32 {
    // The high 32 bits always fit.
    match u32::try_from(value >> 32) {
        Ok(0) | Err(_) => 1,
        Ok(high) => high,
    }
}

impl<T> Table<T> {
    /// A table of `capacity` slots, at most [`MAX_CAPACITY`], at this
    /// copy's base generation.
    pub(crate) fn new(kind: Kind, capacity: u32) -> Self {
        Self::with_base(kind, capacity, copy_base())
    }

    /// A table whose slots start at generation `base` (never 0).
    pub(crate) fn with_base(kind: Kind, capacity: u32, base: u32) -> Self {
        let base = base.max(1);
        let capacity = capacity.min(MAX_CAPACITY);
        let slots = (0..capacity)
            .map(|_| Slot {
                entry: Mutex::new(None),
                generation: AtomicU32::new(base),
                holder: AtomicU64::new(NO_THREAD),
            })
            .collect();
        // Lowest index on top.
        let free = (0..capacity).rev().collect();
        Self {
            kind,
            base,
            slots,
            free: Mutex::new(free),
        }
    }

    /// Stores `value` and returns its handle.
    ///
    /// # Errors
    ///
    /// [`Status::HandlesExhausted`] when every slot is taken or retired.
    pub(crate) fn insert(&self, value: T) -> Result<Handle, Status> {
        self.insert_or_return(value).map_err(|(status, _)| status)
    }

    /// [`Table::insert`], giving `value` back when it fails, so the caller
    /// can release what it holds.
    ///
    /// # Errors
    ///
    /// As [`Table::insert`], with the value.
    pub(crate) fn insert_or_return(&self, value: T) -> Result<Handle, (Status, T)> {
        let index = {
            let Ok(mut free) = self.free.lock() else {
                return Err((Status::Internal, value));
            };
            match free.pop() {
                Some(index) => index,
                None => return Err((Status::HandlesExhausted, value)),
            }
        };
        let Ok(slot) = self.slot(index) else {
            return Err((Status::Internal, value));
        };
        // A free slot holds no object, so it is held only for the moment a
        // racing use of its previous handle compares generations, never
        // across a callback: waiting for it is short. Its mutex is not
        // poisoned (a close clears the poison of the handle it ends).
        let mut entry = slot
            .entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *entry = Some(value);
        let generation = slot.generation.load(Ordering::Acquire);
        Ok(Handle::new(self.kind, index, generation))
    }

    /// Runs `f` on the object `handle` names, holding its slot.
    ///
    /// # Errors
    ///
    /// [`Status::InvalidHandle`] for a handle of another kind or none,
    /// [`Status::Closed`] for a stale one, [`Status::Busy`] while another
    /// thread holds the slot, [`Status::Reentrant`] while this thread does,
    /// [`Status::Internal`] after a panic poisoned it.
    pub(crate) fn with<R>(&self, handle: Handle, f: impl FnOnce(&mut T) -> R) -> Result<R, Status> {
        let slot = self.current(handle)?;
        let mut entry = match slot.entry.try_lock() {
            Ok(entry) => entry,
            Err(TryLockError::Poisoned(_)) => return Err(Self::poisoned(slot, handle)),
            Err(TryLockError::WouldBlock) => return Err(Self::contended(slot, handle)),
        };
        let _held = Held {
            holder: &slot.holder,
        };
        slot.holder.store(thread_token(), Ordering::Release);
        // Closed between the check and the lock.
        if slot.generation.load(Ordering::Acquire) != handle.generation() {
            return Err(Status::Closed);
        }
        let value = entry.as_mut().ok_or(Status::Closed)?;
        Ok(f(value))
    }

    /// Reads the object `handle` names even when a panic poisoned its slot,
    /// for what a close needs before it takes the slot. `f` must read only
    /// fields written when the object was created and never assigned
    /// afterwards (the client a publication or a subscription belongs to):
    /// a panic cannot have left such a field half-written, while any other
    /// field of a poisoned object may be inconsistent.
    ///
    /// # Errors
    ///
    /// As [`Table::with`], except that a poisoned slot is not an error.
    pub(crate) fn read_even_poisoned<R>(
        &self,
        handle: Handle,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, Status> {
        let slot = self.current(handle)?;
        let entry = match slot.entry.try_lock() {
            Ok(entry) => entry,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return Err(Self::contended(slot, handle)),
        };
        if slot.generation.load(Ordering::Acquire) != handle.generation() {
            return Err(Status::Closed);
        }
        entry.as_ref().map(f).ok_or(Status::Closed)
    }

    /// Closes `handle` and returns its object. A poisoned slot is closed
    /// too, and its object returned.
    ///
    /// # Errors
    ///
    /// As [`Table::with`], except that a poisoned slot is not an error.
    pub(crate) fn remove(&self, handle: Handle) -> Result<T, Status> {
        let slot = self.current(handle)?;
        let taken = Self::take(slot, handle)?;
        self.close(slot, handle, taken)
    }

    /// [`Table::remove`] for a table whose slots are never held across a
    /// callback (claims: a call only reads the handle they name): it waits
    /// for a slot another thread holds instead of answering
    /// [`Status::Busy`], so a close that must end the handle never fails
    /// for a moment's contention.
    ///
    /// # Errors
    ///
    /// [`Status::InvalidHandle`], [`Status::Closed`], and
    /// [`Status::Reentrant`] when this thread holds the slot.
    pub(crate) fn remove_waiting(&self, handle: Handle) -> Result<T, Status> {
        let slot = self.current(handle)?;
        if slot.holder.load(Ordering::Acquire) == thread_token() {
            return Err(Status::Reentrant);
        }
        let (entry, poisoned) = match slot.entry.lock() {
            Ok(entry) => (entry, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        if slot.generation.load(Ordering::Acquire) != handle.generation() || entry.is_none() {
            return Err(Status::Closed);
        }
        self.close(slot, handle, (entry, poisoned))
    }

    /// Closes `handle` after `before` succeeded on its object, holding
    /// the slot throughout: a parent's close ends its children in
    /// `before` and is refused as a whole when one of them is held. A
    /// poisoned slot is closed too.
    ///
    /// # Errors
    ///
    /// As [`Table::remove`], and `before`'s error, with nothing closed.
    pub(crate) fn remove_with<R>(
        &self,
        handle: Handle,
        before: impl FnOnce(&mut T) -> Result<R, Status>,
    ) -> Result<(T, R), Status> {
        let slot = self.current(handle)?;
        let (mut entry, poisoned) = Self::take(slot, handle)?;
        let held = Held {
            holder: &slot.holder,
        };
        slot.holder.store(thread_token(), Ordering::Release);
        let value = entry.as_mut().ok_or(Status::Closed)?;
        let done = before(value)?;
        drop(held);
        Ok((self.close(slot, handle, (entry, poisoned))?, done))
    }

    /// Closes every handle of `handles`, all or none: when one is held by
    /// a thread, nothing is closed. Stale handles are skipped.
    ///
    /// # Errors
    ///
    /// [`Status::Reentrant`] or [`Status::Busy`] for a held one.
    pub(crate) fn remove_all(&self, handles: &[Handle]) -> Result<Vec<T>, Status> {
        self.take_all(handles)?.close()
    }

    /// Takes the slot of every handle of `handles` for a close, all or
    /// none, and holds them: [`TakenAll::close`] closes them, and dropping
    /// the result lets them go with nothing closed. So a close that ends
    /// handles of several tables takes every table first and closes none
    /// while one is held (a client's publications and subscriptions).
    /// Stale handles are skipped.
    ///
    /// # Errors
    ///
    /// [`Status::Reentrant`] or [`Status::Busy`] for a held one.
    pub(crate) fn take_all(&self, handles: &[Handle]) -> Result<TakenAll<'_, T>, Status> {
        let mut taken = Vec::with_capacity(handles.len());
        for (at, &handle) in handles.iter().enumerate() {
            if handles.get(..at).is_some_and(|seen| seen.contains(&handle)) {
                continue;
            }
            let Ok(slot) = self.current(handle) else {
                continue;
            };
            match Self::take(slot, handle) {
                Ok(held) => taken.push((handle, slot, held)),
                Err(Status::Closed) => {}
                Err(status) => return Err(status),
            }
        }
        Ok(TakenAll { table: self, taken })
    }

    /// The slot `handle` names, if it is one of this table and its handle
    /// is current: a stale handle answers [`Status::Closed`] without
    /// touching the slot's mutex.
    fn current(&self, handle: Handle) -> Result<&Slot<T>, Status> {
        if handle.generation() == 0 || handle.kind() != self.kind as u64 {
            return Err(Status::InvalidHandle);
        }
        let slot = self.slot(handle.index())?;
        if slot.generation.load(Ordering::Acquire) != handle.generation() {
            return Err(Status::Closed);
        }
        Ok(slot)
    }

    /// Takes `handle`'s slot for a close, poisoned or not; the handle is
    /// still current and its slot holds an object.
    fn take<'a>(slot: &'a Slot<T>, handle: Handle) -> Result<Taken<'a, T>, Status> {
        let (entry, poisoned) = match slot.entry.try_lock() {
            Ok(entry) => (entry, false),
            Err(TryLockError::Poisoned(poisoned)) => (poisoned.into_inner(), true),
            Err(TryLockError::WouldBlock) => return Err(Self::contended(slot, handle)),
        };
        // A stale handle closes nothing, and leaves the poison of the
        // live handle that reused its slot.
        if slot.generation.load(Ordering::Acquire) != handle.generation() || entry.is_none() {
            return Err(Status::Closed);
        }
        Ok((entry, poisoned))
    }

    /// Ends `handle` in its taken slot: takes its object, moves the
    /// generation on (skipping 0), clears a poison and frees the slot; a
    /// slot whose next generation would be the base again has used all
    /// 2^32 - 1 and is retired, never reused.
    fn close(&self, slot: &Slot<T>, handle: Handle, taken: Taken<'_, T>) -> Result<T, Status> {
        let (mut entry, poisoned) = taken;
        let value = entry.take().ok_or(Status::Closed)?;
        let next =
            Some(handle.generation().checked_add(1).unwrap_or(1)).filter(|next| *next != self.base);
        if let Some(next) = next {
            slot.generation.store(next, Ordering::Release);
        }
        if poisoned {
            slot.entry.clear_poison();
        }
        drop(entry);
        if next.is_some() {
            let mut free = self.free.lock().map_err(|_| Status::Internal)?;
            free.push(handle.index());
        }
        Ok(value)
    }

    /// The slot at `index`.
    fn slot(&self, index: u32) -> Result<&Slot<T>, Status> {
        let index = usize::try_from(index).map_err(|_| Status::InvalidHandle)?;
        self.slots.get(index).ok_or(Status::InvalidHandle)
    }

    /// Why `handle`'s held slot cannot be taken: closed meanwhile, or held
    /// by this thread or another.
    fn contended(slot: &Slot<T>, handle: Handle) -> Status {
        if slot.generation.load(Ordering::Acquire) != handle.generation() {
            Status::Closed
        } else if slot.holder.load(Ordering::Acquire) == thread_token() {
            Status::Reentrant
        } else {
            Status::Busy
        }
    }

    /// What a poisoned slot answers `handle`: poisoned if current, closed
    /// if not.
    fn poisoned(slot: &Slot<T>, handle: Handle) -> Status {
        if slot.generation.load(Ordering::Acquire) == handle.generation() {
            Status::Internal
        } else {
            Status::Closed
        }
    }

    /// Sets the generation of the free slot at `index`, so a test reaches
    /// the last one.
    #[cfg(test)]
    fn set_generation(&self, index: u32, generation: u32) {
        if let Ok(slot) = self.slot(index) {
            slot.generation.store(generation, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests;
