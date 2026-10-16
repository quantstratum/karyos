// SPDX-License-Identifier: Apache-2.0

//! The bounded rings between the conductor and the network agents
//! (`quantstratum-docs: karyos/design/driver-network-agents.md` §2.3,
//! DN-3): one producer, one consumer, capacity fixed at creation.
//!
//! A ring is a `std::sync::mpsc::sync_channel` of the ring's capacity (its
//! buffer is allocated once, at creation) with one shared count of the
//! slots in use: occupied by a queued item, or reserved for one. A slot is
//! taken with a compare-and-swap below the capacity, so the channel itself
//! is never full and a send never blocks. A [`Reservation`] holds a slot
//! for a later item, possibly posted by another thread: the conductor
//! reserves the reply slot of a command when it posts the command, so the
//! agent's reply never finds the ring full. Dropping an unused reservation
//! frees its slot.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};

/// A ring's producer.
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

/// One slot of a ring, held for one item.
#[derive(Debug)]
pub struct Reservation {
    used: Arc<AtomicUsize>,
    spent: bool,
}

/// A ring of `capacity` items, at least one.
#[must_use]
pub fn ring<T>(capacity: usize) -> (RingSender<T>, RingReceiver<T>) {
    let capacity = capacity.max(1);
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
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            if used >= self.capacity {
                return None;
            }
            match self.used.compare_exchange_weak(
                used,
                used + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
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

    /// Posts `item` into a slot `reservation` holds. Returns the item if
    /// the consumer is gone.
    ///
    /// # Errors
    ///
    /// The item, when the consumer was dropped.
    pub fn post(&self, mut reservation: Reservation, item: T) -> Result<(), T> {
        // The slot moves from reserved to occupied: the count is unchanged.
        reservation.spent = true;
        self.channel.try_send(item).map_err(|error| {
            // Disconnected (never full: the slot was held). The slot is
            // released, as the consumer will not take it.
            reservation.used.fetch_sub(1, Ordering::Relaxed);
            match error {
                std::sync::mpsc::TrySendError::Full(item)
                | std::sync::mpsc::TrySendError::Disconnected(item) => item,
            }
        })
    }

    /// Reserves and posts `item`; returns it when no slot is free or the
    /// consumer is gone.
    ///
    /// # Errors
    ///
    /// The item, unposted.
    pub fn try_post(&self, item: T) -> Result<(), T> {
        match self.reserve() {
            Some(reservation) => self.post(reservation, item),
            None => Err(item),
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
                self.used.fetch_sub(1, Ordering::Relaxed);
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
            self.used.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
