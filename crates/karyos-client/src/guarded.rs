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
use karyos_sys::outcome_ring::shared::{SharedOutcomeReader, SharedRecord};
use karyos_sys::outcome_ring::{Kind, OutcomeError, OutcomeReader, Record};
use karyos_sys::rate_limit::{RateLimiter, RatePolicy};
use karyos_sys::rate_policy_slot::{OUTCOME_SLOT, SEQUENCE, SlotRead, try_read_sequenced};
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
    reader: Reader,
    message_capacity: u64,
    reserved: u64,
    released: u64,
    rate: Option<RateCopy>,
    /// A handle with no copy that watches its ring for a policy (R-CORE-21):
    /// the clock to create the copy with, and the slot's sequence word when
    /// last read whole (`None` while a publication was in progress). A
    /// policy published later, a rateless lane's publication getting one,
    /// gives the handle its copy at its next call.
    pending_rate: Option<RateWatch>,
    /// How a copy made at bind starts: full, or empty for a reincarnation
    /// ([`Self::reincarnated_at`]).
    bind_bucket: Bucket,
    /// A block of a shared ring's handle could not be kept in its
    /// reservation set: its final record would go unread, so the outcome
    /// stream is lost from here (a broken invariant: admission checked the
    /// quota).
    untracked: bool,
}

/// A handle's reader of its outcome records: its own ring, or its slot of
/// the incarnation's shared ring (ADR-0092).
#[derive(Debug)]
enum Reader {
    /// An exclusive handle's ring: every record is its.
    Exclusive(OutcomeReader),
    /// A concurrent handle's slot: it delivers the records of the blocks
    /// it reserved, every range-side record and its own `OutcomesLost`.
    Shared(SharedOutcomeReader),
}

impl Reader {
    fn ended(&self) -> bool {
        match self {
            Self::Exclusive(reader) => reader.ended(),
            Self::Shared(reader) => reader.ended(),
        }
    }
}

/// How a handle's rate copy starts: full when the handle binds to a policy
/// in force, read whole at bind, as a lane guarded with it; empty when it
/// takes one later, which never grants tokens, or binds to a reincarnation,
/// whose gate starts empty (R-CORE-21).
#[derive(Debug, Clone, Copy)]
enum Bucket {
    Full,
    Empty,
    /// Empty at the reincarnation's start, host monotonic nanoseconds,
    /// refilled from then on, as its gate.
    EmptySince(u64),
}

/// A handle's watch of its ring for a published policy: the clock to make
/// its copy with, and the slot's sequence word when last read whole.
#[derive(Debug, Clone, Copy)]
struct RateWatch {
    clock: fn() -> u64,
    seen: Option<u64>,
}

/// The handle's copy of its publication's message bucket: an early
/// rejection only. The sender gate's bucket is authoritative
/// (`quantstratum-docs: karyos/design/guards-and-abort.md`, Rate limits).
#[derive(Debug, Clone, Copy)]
struct RateCopy {
    limiter: RateLimiter,
    clock: fn() -> u64,
    /// The version of the published policy the copy applies; 0 for the
    /// policy it was created with.
    version: u64,
    /// The slot's sequence word when the copy last read it whole; `None`
    /// before the first read.
    sequence: Option<u64>,
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
        let reader = Reader::Exclusive(OutcomeReader::attach(&*ring, lanes)?);
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
            pending_rate: None,
            bind_bucket: Bucket::Full,
            untracked: false,
        })
    }

    /// Binds a concurrent handle to slot `slot` of its incarnation's shared
    /// outcome ring `ring` (layout version 3, ADR-0092), which reads only
    /// the records after sequence `after`, with guard word `index` of
    /// `guard`, admitted under open epoch `epoch`, for a publication with
    /// `lanes` lanes. Its quota `C_m` is the ring's: the handle admits a
    /// message only while fewer than `C_m` of its own blocks wait for
    /// their records.
    ///
    /// # Errors
    ///
    /// [`ClientError::Outcomes`] for a ring whose header is not a valid
    /// version 3 binding of this guard word and epoch, or a slot outside
    /// it.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per part of a grant, as GuardBinding::new"
    )]
    pub fn new_shared(
        guard: Arc<dyn SharedWords>,
        index: usize,
        epoch: u64,
        ring: Arc<dyn SharedWords>,
        consumed: Arc<dyn ConsumedCell>,
        lanes: u8,
        slot: u64,
        after: u64,
    ) -> Result<Self, ClientError> {
        let binding = karyos_sys::outcome_ring::shared::binding(&*ring, guard.len())?;
        let index_word = u64::try_from(index).map_err(|_| OutcomeError::Layout)?;
        if binding.guard_index != index_word || binding.epoch != epoch {
            return Err(OutcomeError::Layout.into());
        }
        let reader = Reader::Shared(SharedOutcomeReader::attach(&*ring, lanes, slot, after)?);
        Ok(Self {
            guard,
            index,
            epoch,
            ring,
            consumed,
            reader,
            message_capacity: binding.messages,
            reserved: 0,
            released: 0,
            rate: None,
            pending_rate: None,
            bind_bucket: Bucket::Full,
            untracked: false,
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
        self.set_rate(policy, clock, 0, None, self.bind_bucket);
        self
    }

    /// Binds to a reincarnation of its publication (an incarnation past the
    /// first) that began at `at`, host monotonic nanoseconds (the ring's
    /// `REINCARNATED_AT` word): a rate copy made at bind starts empty at
    /// `at` and has earned since, as the reincarnation's sender gate has,
    /// so reincarnating buys no new burst and a handle bound later is not
    /// stricter than the gate (R-CORE-21). `at` 0 (unknown) starts it
    /// empty now. Call it before [`Self::with_rate`] or
    /// [`Self::with_published_rate`]; a copy already made keeps its level.
    #[must_use]
    pub fn reincarnated_at(mut self, at: u64) -> Self {
        self.bind_bucket = if at == 0 {
            Bucket::Empty
        } else {
            Bucket::EmptySince(at)
        };
        self
    }

    /// Gives the handle a copy of `policy`'s message bucket at `version`,
    /// read at slot `sequence`, starting `bucket`.
    fn set_rate(
        &mut self,
        policy: RatePolicy,
        clock: fn() -> u64,
        version: u64,
        sequence: Option<u64>,
        bucket: Bucket,
    ) {
        let messages = RatePolicy {
            messages: policy.messages,
            bytes: None,
        };
        let limiter = match bucket {
            Bucket::Full => RateLimiter::new(messages, clock()),
            Bucket::Empty => RateLimiter::empty(messages, clock()),
            Bucket::EmptySince(at) => {
                let mut limiter = RateLimiter::empty(messages, at);
                limiter.refill_at(clock());
                limiter
            }
        };
        self.rate = Some(RateCopy {
            limiter,
            clock,
            version,
            sequence,
        });
        self.pending_rate = None;
    }

    /// [`Self::with_rate`] from the policy the driver published in the
    /// outcome ring, if any (R-CORE-21): how a handle gets its copy when
    /// the grant carries no policy, a remote one's or a rateless lane's.
    /// A policy read whole here starts the copy full, as a lane guarded
    /// with it. With none published yet, or one being written, the handle
    /// watches the ring: its sequence word, one Acquire load a call, and
    /// takes the policy at its next call that reads it whole, its copy
    /// starting empty; the sender gate stays authoritative.
    #[must_use]
    pub fn with_published_rate(mut self, clock: fn() -> u64) -> Self {
        // A publication in progress is short: a few reads see it whole.
        for _ in 0..8 {
            if self.adopt_published(clock, self.bind_bucket)
                || self.pending_rate.is_some_and(|watch| watch.seen.is_some())
            {
                return self;
            }
            core::hint::spin_loop();
        }
        self
    }

    /// One read of the published policy for a handle without a copy:
    /// `true` with the copy made from it, starting `bucket`; `false` with
    /// the handle watching the ring, at the sequence it read whole (none
    /// published) or at none (a publication in progress).
    fn adopt_published(&mut self, clock: fn() -> u64, bucket: Bucket) -> bool {
        match try_read_sequenced(&*self.ring, OUTCOME_SLOT) {
            (SlotRead::Policy { version, policy }, sequence) => {
                self.set_rate(policy, clock, version, sequence, bucket);
                true
            }
            (SlotRead::Unpublished, seen) => {
                self.pending_rate = Some(RateWatch { clock, seen });
                false
            }
            (SlotRead::Busy, _) => {
                self.pending_rate = Some(RateWatch { clock, seen: None });
                false
            }
        }
    }

    /// Whole message tokens the handle's copy holds at its last refill;
    /// `None` without a rate limit.
    #[must_use]
    pub fn rate_tokens(&self) -> Option<u64> {
        self.rate.as_ref().map(|copy| copy.limiter.message_tokens())
    }

    /// Whether the rate copy admits one more message now (refilled from the
    /// clock, charging nothing); always without a rate limit. Every call
    /// first compares the published policy's sequence word (one Acquire
    /// load) and, when it moved, applies a newer version (R-CORE-21,
    /// clamped, never granting tokens), so a tightening binds the handle's
    /// next call whether or not its bucket ran out; a read that finds a
    /// publication in progress keeps the copy as it is until the next call.
    pub(crate) fn rate_admits(&mut self) -> bool {
        // A handle without a copy reads the slot again only when its
        // sequence word moved.
        if let Some(watch) = self.pending_rate
            && self.ring.load_acquire(OUTCOME_SLOT + SEQUENCE) != watch.seen
        {
            // A policy taken at run time never grants tokens: the copy
            // starts empty, as the sender gate's bucket does (R-CORE-21).
            // So does one a read at bind found mid-write: the handle cannot
            // tell a policy in force from one coming then.
            let _ = self.adopt_published(watch.clock, Bucket::Empty);
        }
        let Some(copy) = self.rate.as_mut() else {
            return true;
        };
        let now = (copy.clock)();
        copy.limiter.refill_at(now);
        if self.ring.load_acquire(OUTCOME_SLOT + SEQUENCE) != copy.sequence {
            let (read, sequence) = try_read_sequenced(&*self.ring, OUTCOME_SLOT);
            if let SlotRead::Policy { version, policy } = read
                && version > copy.version
            {
                let messages = RatePolicy {
                    messages: policy.messages,
                    bytes: None,
                };
                copy.limiter.set_policy(messages, now);
                copy.version = version;
            }
            if sequence.is_some() {
                copy.sequence = sequence;
            }
        }
        copy.limiter.admits(0, true)
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
        match &self.reader {
            // At most `C_m` pairs.
            Reader::Shared(reader) => u64::try_from(reader.outstanding()).unwrap_or(u64::MAX),
            // `released <= reserved`: a release needs an outstanding
            // reservation (see `poll_outcomes`).
            Reader::Exclusive(_) => self.reserved - self.released,
        }
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
        if self.reader.ended() || self.reserved == u64::MAX || self.untracked {
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

    /// Records the block a shared ring's handle reserved, on wire lane
    /// `lane` at stream position `start`: its final record is the handle's.
    /// The admission that preceded it checked the quota, so the set has
    /// room; a block it could not keep loses the handle's outcome stream,
    /// and its next call reports `OutcomesLost`.
    pub(crate) fn reserve_block(&mut self, lane: u8, start: u64) {
        if let Reader::Shared(reader) = &mut self.reader
            && !reader.reserve(lane, start)
        {
            self.untracked = true;
        }
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
        let reader = match reader {
            Reader::Shared(reader) => {
                // The reader releases a block's pair as it delivers its
                // record; another handle's records are skipped.
                let mut delivered = 0;
                let _ = reader.poll(&**ring, consumed.cell(), limit, |sequence, record| {
                    if let SharedRecord::Delivered(record) = record {
                        handler(sequence, record);
                        delivered += 1;
                    }
                })?;
                return Ok(delivered);
            }
            Reader::Exclusive(reader) => reader,
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_sys::outcome_ring::shared::{SharedBinding, init};

    /// Review of #1153: a shared ring's handle whose block cannot be kept
    /// in its reservation set (past its quota, a broken invariant) loses
    /// its outcome stream instead of asserting: its next admission is
    /// `Lost`.
    #[test]
    fn an_untracked_block_loses_the_outcome_stream() {
        let binding = SharedBinding {
            messages: 1,
            ranges: 1,
            guard_index: 0,
            epoch: 2,
            handles: 1,
        };
        let capacity = usize::try_from(binding.capacity().unwrap()).unwrap();
        let ring = Arc::new(HeapWords::zeroed(
            karyos_sys::outcome_ring::ring_words(capacity).unwrap(),
        ));
        init(ring.words(), &binding).unwrap();
        // The guard word open at epoch 2: `(2 << 1) | 1`.
        let guard = HeapWords::zeroed(1);
        guard.words()[0].store(5, karyos_sys::sync::Ordering::Relaxed);
        let mut bound = GuardBinding::new_shared(
            Arc::new(guard),
            0,
            2,
            ring,
            Arc::new(AtomicU64::new(0)),
            1,
            0,
            0,
        )
        .unwrap();
        assert_eq!(bound.admission(), Admission::Open);
        bound.reserve_block(0, 0);
        assert_eq!(bound.admission(), Admission::BackPressured);
        // Past the quota: the set refuses the pair.
        bound.reserve_block(0, 64);
        assert_eq!(bound.admission(), Admission::Lost);
    }
}
