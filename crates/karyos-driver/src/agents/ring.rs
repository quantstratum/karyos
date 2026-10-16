// SPDX-License-Identifier: Apache-2.0

//! The bounded rings between the conductor and the network agents
//! (`quantstratum-docs: karyos/design/driver-network-agents.md` §2.3,
//! DN-3): capacity fixed at creation, at least one entry.
//!
//! A ring is a `std::sync::mpsc::sync_channel` of the ring's capacity (its
//! buffer is allocated once, at creation) with one shared count of the
//! slots in use: occupied by a queued item, or reserved for one. A slot is
//! taken with a compare-and-swap below the capacity, so the channel itself
//! is never full and a send never blocks. The invariant is "queued items
//! never exceed the count": a producer takes its slot (Acquire) before it
//! sends, and the consumer frees a slot (Release) only after it has taken
//! the item, so a producer that sees the freed slot also finds the
//! channel's room.
//!
//! A [`Reservation`] holds a slot of one ring for a later item, possibly
//! posted by another thread: the conductor reserves the reply slot of a
//! command when it posts the command, so the agent's reply never finds the
//! ring full. A reservation is tied to its ring; posting it into another
//! ring is refused. Dropping an unused reservation frees its slot.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};

/// A ring's producer. A ring may have several producer handles
/// ([`RingSender::clone_sender`]) sharing its slots.
#[derive(Debug)]
pub struct RingSender<T> {
    channel: SyncSender<T>,
    used: Arc<AtomicUsize>,
    capacity: usize,
}

/// A ring's consumer.
#[derive(Debug)]
pub struct RingReceiver<T> {
    channel: Receiver<T>,
    used: Arc<AtomicUsize>,
}

/// Every producer of a ring is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disconnected;

/// Why [`RingSender::post`] returned its item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostError<T> {
    /// The consumer is gone.
    Gone(T),
    /// The reservation belongs to another ring.
    Foreign(T),
    /// No slot was free ([`RingSender::try_post`]), or the channel was full
    /// although the slot was held ([`RingSender::post`]: a broken
    /// invariant, never expected).
    Full(T),
}

/// One slot of one ring, held for one item.
#[derive(Debug)]
pub struct Reservation {
    used: Arc<AtomicUsize>,
    spent: bool,
}

/// A ring of `capacity` items.
#[must_use]
pub fn ring<T>(capacity: NonZeroUsize) -> (RingSender<T>, RingReceiver<T>) {
    let capacity = capacity.get();
    let (channel, receiver) = sync_channel(capacity);
    let used = Arc::new(AtomicUsize::new(0));
    (
        RingSender {
            channel,
            used: Arc::clone(&used),
            capacity,
        },
        RingReceiver {
            channel: receiver,
            used,
        },
    )
}

impl<T> RingSender<T> {
    /// Holds one slot for a later item; `None` when every slot is used.
    #[must_use]
    pub fn reserve(&self) -> Option<Reservation> {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(1).filter(|&next| next <= self.capacity)?;
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::Acquire, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(Reservation {
                        used: Arc::clone(&self.used),
                        spent: false,
                    });
                }
                Err(seen) => used = seen,
            }
        }
    }

    /// Posts `item` into the slot `reservation` holds.
    ///
    /// # Errors
    ///
    /// [`PostError::Foreign`] for a reservation of another ring (its slot is
    /// freed), [`PostError::Gone`] when the consumer was dropped and
    /// [`PostError::Full`] for a broken invariant; the item comes back.
    pub fn post(&self, mut reservation: Reservation, item: T) -> Result<(), PostError<T>> {
        if !Arc::ptr_eq(&reservation.used, &self.used) {
            return Err(PostError::Foreign(item));
        }
        match self.channel.try_send(item) {
            Ok(()) => {
                // The slot moves from reserved to occupied: the count is
                // unchanged.
                reservation.spent = true;
                Ok(())
            }
            // The reservation's drop frees the slot the item did not take.
            Err(TrySendError::Disconnected(item)) => Err(PostError::Gone(item)),
            Err(TrySendError::Full(item)) => Err(PostError::Full(item)),
        }
    }

    /// Reserves and posts `item`.
    ///
    /// # Errors
    ///
    /// [`PostError::Full`] when no slot is free, or as
    /// [`RingSender::post`]; the item comes back unposted.
    pub fn try_post(&self, item: T) -> Result<(), PostError<T>> {
        match self.reserve() {
            Some(reservation) => self.post(reservation, item),
            None => Err(PostError::Full(item)),
        }
    }

    /// Another producer handle of this ring, sharing its slots: the
    /// conductor reserves a reply slot and the agent posts into it.
    #[must_use]
    pub fn clone_sender(&self) -> Self {
        Self {
            channel: self.channel.clone(),
            used: Arc::clone(&self.used),
            capacity: self.capacity,
        }
    }

    /// The ring's capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl<T> RingReceiver<T> {
    /// Takes the oldest item, if any, and frees its slot.
    ///
    /// # Errors
    ///
    /// [`Disconnected`] once every producer is gone and the ring is empty.
    pub fn try_take(&self) -> Result<Option<T>, Disconnected> {
        match self.channel.try_recv() {
            Ok(item) => {
                self.used.fetch_sub(1, Ordering::Release);
                Ok(Some(item))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(Disconnected),
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.spent {
            self.used.fetch_sub(1, Ordering::Release);
        }
    }
}
