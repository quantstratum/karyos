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
//! of that slot still answers [`Status::Closed`] and never clears it. Closing bumps the
//! generation, so a stale or twice closed handle answers
//! [`Status::Closed`]; a slot whose generation would wrap is retired,
//! never reused.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, TryLockError};

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

/// A slot's state under its mutex.
#[derive(Debug)]
struct Entry<T> {
    /// The generation of the handle that names the object; 0 while the
    /// slot has never held one.
    generation: u32,
    /// The object, while the handle is open.
    value: Option<T>,
}

/// A slot: its entry, and the token of the thread holding it.
#[derive(Debug)]
struct Slot<T> {
    entry: Mutex<Entry<T>>,
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

/// A bounded table of one kind of object.
#[derive(Debug)]
pub(crate) struct Table<T> {
    kind: Kind,
    slots: Box<[Slot<T>]>,
    /// Slots free to take, as a stack. Taken on the control path only.
    free: Mutex<Vec<u32>>,
}

impl<T> Table<T> {
    /// A table of `capacity` slots, at most [`MAX_CAPACITY`].
    pub(crate) fn new(kind: Kind, capacity: u32) -> Self {
        let capacity = capacity.min(MAX_CAPACITY);
        let slots = (0..capacity)
            .map(|_| Slot {
                entry: Mutex::new(Entry {
                    generation: 0,
                    value: None,
                }),
                holder: AtomicU64::new(NO_THREAD),
            })
            .collect();
        // Lowest index on top.
        let free = (0..capacity).rev().collect();
        Self {
            kind,
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
        // use of a stale handle compares generations, never across a
        // callback: waiting for it is short. Its mutex is not poisoned (a
        // close clears the poison of the handle it ends), but a poisoned
        // one would hold no object either.
        let mut entry = slot
            .entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A free slot's generation is below u32::MAX (see remove).
        let Some(generation) = entry.generation.checked_add(1) else {
            return Err((Status::Internal, value));
        };
        entry.generation = generation;
        entry.value = Some(value);
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
        let slot = self.check(handle)?;
        let mut entry = match slot.entry.try_lock() {
            Ok(entry) => entry,
            // Poisoned: a stale handle is still only closed.
            Err(TryLockError::Poisoned(poisoned)) => {
                let entry = poisoned.into_inner();
                return Err(if entry.generation == handle.generation() {
                    Status::Internal
                } else {
                    Status::Closed
                });
            }
            Err(TryLockError::WouldBlock) => return Err(Self::contended(slot)),
        };
        let _held = Held {
            holder: &slot.holder,
        };
        slot.holder.store(thread_token(), Ordering::Release);
        if entry.generation != handle.generation() {
            return Err(Status::Closed);
        }
        let value = entry.value.as_mut().ok_or(Status::Closed)?;
        Ok(f(value))
    }

    /// Closes `handle` and returns its object. A poisoned slot is closed
    /// too, and its object returned.
    ///
    /// # Errors
    ///
    /// As [`Table::with`], except that a poisoned slot is not an error.
    pub(crate) fn remove(&self, handle: Handle) -> Result<T, Status> {
        let slot = self.check(handle)?;
        let (mut entry, poisoned) = match slot.entry.try_lock() {
            Ok(entry) => (entry, false),
            Err(TryLockError::Poisoned(poisoned)) => (poisoned.into_inner(), true),
            Err(TryLockError::WouldBlock) => return Err(Self::contended(slot)),
        };
        // A stale handle closes nothing, and leaves the poison of the
        // live handle that reused its slot.
        if entry.generation != handle.generation() {
            return Err(Status::Closed);
        }
        let value = entry.value.take().ok_or(Status::Closed)?;
        if poisoned {
            slot.entry.clear_poison();
        }
        // The next handle of the slot gets the next generation; a slot
        // whose generation cannot grow is retired, never reused.
        let reusable = entry.generation < u32::MAX;
        drop(entry);
        if reusable {
            let mut free = self.free.lock().map_err(|_| Status::Internal)?;
            free.push(handle.index());
        }
        Ok(value)
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
        let slot = self.check(handle)?;
        let (mut entry, poisoned) = match slot.entry.try_lock() {
            Ok(entry) => (entry, false),
            Err(TryLockError::Poisoned(poisoned)) => (poisoned.into_inner(), true),
            Err(TryLockError::WouldBlock) => return Err(Self::contended(slot)),
        };
        let _held = Held {
            holder: &slot.holder,
        };
        slot.holder.store(thread_token(), Ordering::Release);
        if entry.generation != handle.generation() {
            return Err(Status::Closed);
        }
        let value = entry.value.as_mut().ok_or(Status::Closed)?;
        let done = before(value)?;
        let value = entry.value.take().ok_or(Status::Closed)?;
        if poisoned {
            slot.entry.clear_poison();
        }
        let reusable = entry.generation < u32::MAX;
        drop(entry);
        if reusable {
            let mut free = self.free.lock().map_err(|_| Status::Internal)?;
            free.push(handle.index());
        }
        Ok((value, done))
    }

    /// Closes every handle of `handles`, all or none: when one is held by
    /// a thread, nothing is closed. Stale handles are skipped.
    ///
    /// # Errors
    ///
    /// [`Status::Reentrant`] or [`Status::Busy`] for a held one.
    pub(crate) fn remove_all(&self, handles: &[Handle]) -> Result<Vec<T>, Status> {
        let mut taken = Vec::with_capacity(handles.len());
        for (at, &handle) in handles.iter().enumerate() {
            if handles.get(..at).is_some_and(|seen| seen.contains(&handle)) {
                continue;
            }
            let Ok(slot) = self.check(handle) else {
                continue;
            };
            let (entry, poisoned) = match slot.entry.try_lock() {
                Ok(entry) => (entry, false),
                Err(TryLockError::Poisoned(poisoned)) => (poisoned.into_inner(), true),
                Err(TryLockError::WouldBlock) => return Err(Self::contended(slot)),
            };
            if entry.generation == handle.generation() && entry.value.is_some() {
                taken.push((handle, slot, entry, poisoned));
            }
        }
        let mut values = Vec::with_capacity(taken.len());
        let mut freed = Vec::with_capacity(taken.len());
        for (handle, slot, mut entry, poisoned) in taken {
            if let Some(value) = entry.value.take() {
                values.push(value);
            }
            if poisoned {
                slot.entry.clear_poison();
            }
            if entry.generation < u32::MAX {
                freed.push(handle.index());
            }
        }
        let mut free = self.free.lock().map_err(|_| Status::Internal)?;
        free.extend(freed);
        Ok(values)
    }

    /// The slot `handle` names, if it is one of this table.
    fn check(&self, handle: Handle) -> Result<&Slot<T>, Status> {
        if handle.generation() == 0 || handle.kind() != self.kind as u64 {
            return Err(Status::InvalidHandle);
        }
        self.slot(handle.index())
    }

    /// The slot at `index`.
    fn slot(&self, index: u32) -> Result<&Slot<T>, Status> {
        let index = usize::try_from(index).map_err(|_| Status::InvalidHandle)?;
        self.slots.get(index).ok_or(Status::InvalidHandle)
    }

    /// Why a held slot cannot be taken: this thread holds it, or another.
    fn contended(slot: &Slot<T>) -> Status {
        if slot.holder.load(Ordering::Acquire) == thread_token() {
            Status::Reentrant
        } else {
            Status::Busy
        }
    }

    /// Sets the generation of the free slot at `index`, so a test reaches
    /// the last one.
    #[cfg(test)]
    fn set_generation(&self, index: u32, generation: u32) {
        if let Ok(slot) = self.slot(index)
            && let Ok(mut entry) = slot.entry.lock()
        {
            entry.generation = generation;
        }
    }
}

#[cfg(test)]
mod tests;
