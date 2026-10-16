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
use karyos_sys::rate_limit::{RateLimiter, RatePolicy};
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
    rate: Option<RateCopy>,
}

/// The handle's copy of its publication's message bucket: an early
/// rejection only. The sender gate's bucket is authoritative
/// (`quantstratum-docs: karyos/design/guards-and-abort.md`, Rate limits).
#[derive(Debug, Clone, Copy)]
struct RateCopy {
    limiter: RateLimiter,
    clock: fn() -> u64,
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
        if message_capacity == 0 || index >= guard.len() {
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
            rate: None,
        })
    }

    /// Gives the handle a copy of its publication's rate limit, read
    /// against `clock` (monotonic nanoseconds): `offer` and `try_claim`
    /// return `RateLimited` while the copy holds no message token, and an
    /// accepted message takes one; a claim that is never sent (dropped,
    /// aborted, or aborted by its deadline) gives its token back.
    ///
    /// The copy is an early rejection only. It charges a message when it is
    /// accepted, before the sender gate charges it at its send, so a
    /// `RateLimited` message is one the gate would hold at that instant; it
    /// is not a claim that the gate would never have admitted it later.
    /// `RateLimited` means retry later: nothing is appended or dropped.
    /// Only the message bucket is copied, since the gate charges bytes per
    /// datagram, which a whole message cannot be checked against early.
    ///
    /// The copy can be stricter than the gate: a message accepted and later
    /// aborted (by its deadline, or returned or dropped by a reopen at the
    /// gate) keeps the copy's charge, and so does a claim leaked with
    /// `mem::forget`, which no drop reaches. A sealed handle reports its
    /// seal before the copy is asked.
    #[must_use]
    pub fn with_rate(mut self, policy: RatePolicy, clock: fn() -> u64) -> Self {
        let messages = RatePolicy {
            messages: policy.messages,
            bytes: None,
        };
        self.rate = Some(RateCopy {
            limiter: RateLimiter::new(messages, clock()),
            clock,
        });
        self
    }

    /// Whole message tokens the handle's copy holds at its last refill;
    /// `None` without a rate limit.
    #[must_use]
    pub fn rate_tokens(&self) -> Option<u64> {
        self.rate.as_ref().map(|copy| copy.limiter.message_tokens())
    }

    /// Whether the rate copy admits one more message now (refilled from the
    /// clock, charging nothing); always without a rate limit.
    pub(crate) fn rate_admits(&mut self) -> bool {
        self.rate.as_mut().is_none_or(|copy| {
            copy.limiter.refill_at((copy.clock)());
            copy.limiter.admits(0, true)
        })
    }

    /// Whether the handle keeps a rate copy.
    pub(crate) fn has_rate(&self) -> bool {
        self.rate.is_some()
    }

    /// Gives back the token of a claim that will never be sent: aborted,
    /// dropped, or aborted by its deadline (capped at the burst).
    pub(crate) fn refund_rate(&mut self) {
        if let Some(copy) = &mut self.rate {
            copy.limiter.refund(0, true);
        }
    }

    /// Takes one message token for an accepted message; the caller checked
    /// [`Self::rate_admits`] in the same call, and tokens only grow since.
    pub(crate) fn charge_rate(&mut self) {
        if let Some(copy) = &mut self.rate {
            let charged = copy.limiter.try_admit(0, true);
            debug_assert!(charged, "a charge the copy did not admit");
        }
    }

    /// The open epoch the handle was admitted under.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Reserved messages whose final record has not been read yet.
    #[must_use]
    pub fn outstanding(&self) -> u64 {
        // `released <= reserved`: a release needs an outstanding
        // reservation (see `poll_outcomes`).
        self.reserved - self.released
    }

    /// Whether the ring's records ended (`OutcomesLost`).
    #[must_use]
    pub fn outcomes_ended(&self) -> bool {
        self.reader.ended()
    }

    /// The early check, then the reservation bound. A faulted outcome
    /// stream is terminal before either.
    pub(crate) fn admission(&self) -> Admission {
        // An exhausted reservation count is as terminal as a fault; it
        // takes 2^64 messages.
        if self.reader.ended() || self.reserved == u64::MAX {
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
        // Admission refuses at `u64::MAX`, so this cannot overflow.
        debug_assert!(self.reserved < u64::MAX, "reservations exhausted");
        self.reserved += 1;
    }

    /// Reads up to `limit` records in sequence order. A final message
    /// record releases one reservation once `handler` returns; a handler
    /// that panics gets the record again.
    ///
    /// # Errors
    ///
    /// [`ClientError::Outcomes`] for a corrupt record, which is never
    /// skipped, and for a final message record with no outstanding
    /// reservation (a driver that broke the reservation protocol), which
    /// is consumed but releases nothing.
    pub fn poll_outcomes(
        &mut self,
        limit: usize,
        mut handler: impl FnMut(u64, Record),
    ) -> Result<usize, ClientError> {
        let Self {
            ring,
            consumed,
            reader,
            reserved,
            released,
            ..
        } = self;
        let mut unreserved = None;
        let delivered = reader.poll(&**ring, consumed.cell(), limit, |sequence, record| {
            let message = is_message(record.kind);
            handler(sequence, record);
            if message {
                if *released < *reserved {
                    *released += 1;
                } else {
                    unreserved = unreserved.or(Some(sequence));
                }
            }
        })?;
        match unreserved {
            Some(sequence) => Err(OutcomeError::Corrupt { sequence }.into()),
            None => Ok(delivered),
        }
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
