// SPDX-License-Identifier: Apache-2.0

//! The client side of a guarded publication (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, Admission and The outcome stream).
//!
//! - **Early check.** The client reads the guard word through a view of the
//!   driver's guard region (read-only across processes) and refuses with
//!   `Gated` unless the word is exactly the open epoch the publication was
//!   bound to. The check only rejects earlier: the driver's gate and the
//!   `GuardClosed` seal arbitrate.
//! - **Reservation (GC-4).** Each reserved message (an accepted offer, or a
//!   claim) gets exactly one final message record. Admission accepts a
//!   message only while `reserved - released` is below the message
//!   capacity `C_m`, and returns `BackPressured` otherwise; a reservation
//!   is released when its final record has been read.
//! - **Fault.** Once the driver's final `OutcomesLost` record is read, the
//!   outstanding reservations can never be released: offers and claims
//!   fail with [`ClientError::OutcomesLost`] for good, never
//!   `BackPressured` forever.
//! - **Outcomes.** [`GuardBinding::poll_outcomes`] reads the driver's
//!   outcome ring in sequence order and publishes the consumed count with
//!   Release once each record's handler returns, before any admission that
//!   relies on the slots it freed.

use std::fmt;
use std::sync::Arc;

use karyos_sys::guard;
use karyos_sys::load_words::LoadWords;
use karyos_sys::outcome_ring::{Kind, OutcomeError, OutcomeReader, Record};
use karyos_sys::sync::AtomicU64;

use crate::error::ClientError;

/// Words the client only loads: a view of a driver region that it owns for
/// as long as the binding lives.
pub trait SharedWords: LoadWords + Send + Sync + fmt::Debug {}

impl<T: LoadWords + Send + Sync + fmt::Debug + ?Sized> SharedWords for T {}

/// The client-owned cell that carries the consumed count to the driver.
pub trait ConsumedCell: Send + Sync + fmt::Debug {
    /// The cell.
    fn cell(&self) -> &AtomicU64;
}

impl ConsumedCell for AtomicU64 {
    fn cell(&self) -> &AtomicU64 {
        self
    }
}

/// Words on the heap, for an in-process driver and for tests.
#[derive(Debug)]
pub struct HeapWords(Box<[AtomicU64]>);

impl HeapWords {
    /// `length` zeroed words.
    #[must_use]
    pub fn zeroed(length: usize) -> Self {
        Self((0..length).map(|_| AtomicU64::new(0)).collect())
    }

    /// The words, for their owner's stores.
    #[must_use]
    pub fn words(&self) -> &[AtomicU64] {
        &self.0
    }
}

impl LoadWords for HeapWords {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn load(&self, index: usize) -> Option<u64> {
        self.0.as_ref().load(index)
    }

    fn load_acquire(&self, index: usize) -> Option<u64> {
        self.0.as_ref().load_acquire(index)
    }
}

/// What the guarded admission allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// The guard is open at the bound epoch and a record is free.
    Open,
    /// The guard is not exactly open at the bound epoch.
    Gated,
    /// `C_m` reservations wait for their records.
    BackPressured,
    /// The outcome stream ended with `OutcomesLost`: terminal.
    Lost,
}

/// The guard and outcome ring a publication handle is bound to.
#[derive(Debug)]
pub struct GuardBinding {
    guard: Arc<dyn SharedWords>,
    index: usize,
    epoch: u64,
    ring: Arc<dyn SharedWords>,
    consumed: Arc<dyn ConsumedCell>,
    reader: OutcomeReader,
    message_capacity: u64,
    reserved: u64,
    released: u64,
}

impl GuardBinding {
    /// Binds a handle to guard word `index` of `guard`, admitted under open
    /// epoch `epoch`, with outcome ring `ring` of a publication with
    /// `lanes` lanes, `message_capacity` (`C_m`) and the client's consumed
    /// cell.
    ///
    /// # Errors
    ///
    /// The ring's layout and version refusals of [`OutcomeReader::attach`],
    /// as [`ClientError::Outcomes`]; `OutcomeError::Layout` for a zero
    /// `C_m`.
    pub fn new(
        guard: Arc<dyn SharedWords>,
        index: usize,
        epoch: u64,
        ring: Arc<dyn SharedWords>,
        consumed: Arc<dyn ConsumedCell>,
        lanes: u8,
        message_capacity: u64,
    ) -> Result<Self, ClientError> {
        if message_capacity == 0 {
            return Err(OutcomeError::Layout.into());
        }
        let reader = OutcomeReader::attach(&*ring, lanes)?;
        Ok(Self {
            guard,
            index,
            epoch,
            ring,
            consumed,
            reader,
            message_capacity,
            reserved: 0,
            released: 0,
        })
    }

    /// The open epoch the handle was admitted under.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Reserved messages whose final record has not been read yet.
    #[must_use]
    pub fn outstanding(&self) -> u64 {
        self.reserved.saturating_sub(self.released)
    }

    /// Whether the ring's records ended (`OutcomesLost`).
    #[must_use]
    pub fn outcomes_ended(&self) -> bool {
        self.reader.ended()
    }

    /// The early check, then the reservation bound. A faulted outcome
    /// stream is terminal before either.
    pub(crate) fn admission(&self) -> Admission {
        if self.reader.ended() {
            return Admission::Lost;
        }
        if !guard::admits_in(&*self.guard, self.index, self.epoch) {
            return Admission::Gated;
        }
        if self.outstanding() >= self.message_capacity {
            return Admission::BackPressured;
        }
        Admission::Open
    }

    /// Counts one reserved message.
    pub(crate) fn reserve(&mut self) {
        self.reserved = self.reserved.saturating_add(1);
    }

    /// Reads up to `limit` records in sequence order. A final message
    /// record releases one reservation once `handler` returns; a handler
    /// that panics gets the record again.
    ///
    /// # Errors
    ///
    /// [`ClientError::Outcomes`] for a corrupt record; it is never skipped.
    pub fn poll_outcomes(
        &mut self,
        limit: usize,
        mut handler: impl FnMut(u64, Record),
    ) -> Result<usize, ClientError> {
        let Self {
            ring,
            consumed,
            reader,
            released,
            ..
        } = self;
        Ok(
            reader.poll(&**ring, consumed.cell(), limit, |sequence, record| {
                let message = is_message(record.kind);
                handler(sequence, record);
                if message {
                    *released = released.saturating_add(1);
                }
            })?,
        )
    }
}

/// Whether `kind` is a message's final record, which releases its
/// reservation.
const fn is_message(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Submitted | Kind::ConfirmedCancelled | Kind::Unknown | Kind::Rejected | Kind::Aborted
    )
}
