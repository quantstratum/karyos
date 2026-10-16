// SPDX-License-Identifier: Apache-2.0

//! Guarded local streams (`quantstratum-docs: karyos/design/guards-and-abort.md`,
//! "Local streams: the log as the backend", decisions ACS 15085 and 15161).
//!
//! - **Binding.** A stream is guarded on the control path before any
//!   publication handle is issued. Each exclusive handle issued while the
//!   guard is open is bound to that open epoch and gets its own outcome
//!   ring of `C_m + 1` records (`C_r` is the one local `Ended` record).
//! - **The walker.** The driver reads the stream's log through a walker
//!   (`Role::Walker`: copy only, never counted for connection, holding the
//!   retention floor but not the limit). Each duty cycle, under a bounded
//!   budget, it writes one final record per reserved message: `Submitted`
//!   for a committed message, `Aborted` for an aborted block, and one
//!   `Ended` record when it reaches the seal. A committed frame is exposed
//!   to subscribers at once, so on a local stream it is submitted when
//!   committed.
//! - **Handles in turn.** Records go to the ring of the handle that
//!   reserved the message: a ring is kept until the walker has passed the
//!   head position at which the next handle was issued.
//! - **Overrun.** The walker holds the floor, so it cannot be lapped; if it
//!   is anyway (a broken invariant), the bound handle's outcome stream is
//!   abandoned with an unknown lost count, and the handle ends with
//!   `OutcomesLost`.

use std::collections::VecDeque;
use std::sync::Arc;

use karyos_client::HeapWords;
use karyos_sys::log_buffer::{LogBuffer, PollOutcome, SealReason, Subscription};
use karyos_sys::outcome_ring::{Kind, LOST_UNKNOWN, OutcomeError, OutcomeWriter, Produced, Record};
use karyos_sys::sync::AtomicU64;
use karyos_sys::term_bytes::TermBytes;

use crate::guards::GuardHandle;

/// `AbortReason::GUARD_CLOSED` (guards-and-abort.md, G4).
pub(crate) const REASON_GUARD_CLOSED: u64 = 1;
/// `AbortReason::WRITER_ABORTED` (G4): outcome records only.
pub(crate) const REASON_WRITER_ABORTED: u64 = 6;

/// The outcome ring of one issued handle.
#[derive(Debug)]
pub(crate) struct Bound {
    /// The buffer position at which the handle was issued: the walker
    /// writes records for blocks at or after it here.
    pub(crate) from: u64,
    pub(crate) epoch: u64,
    pub(crate) ring: Arc<HeapWords>,
    pub(crate) consumed: Arc<AtomicU64>,
    pub(crate) writer: OutcomeWriter,
}

/// A guarded stream's driver state.
#[derive(Debug)]
pub(crate) struct GuardedStream<T: TermBytes> {
    pub(crate) guard: GuardHandle,
    /// `C_m`.
    pub(crate) messages: u64,
    walker: Subscription<Arc<LogBuffer<T>>>,
    scratch: Vec<u8>,
    /// Rings of issued handles, oldest first.
    bounds: VecDeque<Bound>,
    /// Whether the walker reached the seal and wrote `Ended`.
    ended: bool,
}

/// What one walk did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Walked {
    /// Records written into rings.
    pub(crate) written: u32,
    /// Records counted as lost (a faulted client or no bound ring).
    pub(crate) lost: u32,
    /// Whether the budget ran out with records still to read.
    pub(crate) budget_exhausted: bool,
    /// Whether the walker was lapped (a broken invariant).
    pub(crate) overrun: bool,
}

impl<T: TermBytes> GuardedStream<T> {
    pub(crate) fn new(
        guard: GuardHandle,
        messages: u64,
        walker: Subscription<Arc<LogBuffer<T>>>,
        max_message: usize,
    ) -> Self {
        Self {
            guard,
            messages,
            walker,
            scratch: vec![0; max_message],
            bounds: VecDeque::new(),
            ended: false,
        }
    }

    /// Binds a newly issued handle's ring, for blocks from `from` on.
    pub(crate) fn bind(&mut self, bound: Bound) {
        self.bounds.push_back(bound);
    }

    /// The ring for a block at `position`: the newest bound issued at or
    /// before it. Older rings the walker has passed are dropped.
    fn ring_for(&mut self, position: u64) -> Option<&mut Bound> {
        while self.bounds.get(1).is_some_and(|next| next.from <= position) {
            let _ = self.bounds.pop_front();
        }
        self.bounds
            .front_mut()
            .filter(|bound| bound.from <= position)
    }

    /// Reads up to `budget` blocks and writes their final records. `base`
    /// is the stream position of the buffer's start, `lane` the wire lane
    /// and `incarnation` the stream's incarnation.
    ///
    /// # Errors
    ///
    /// [`DriverError::Sys`] from the walker's poll (a broken invariant)
    /// and [`DriverError::Outcomes`] for a record the ring refuses.
    pub(crate) fn walk(
        &mut self,
        budget: u32,
        base: u64,
        lane: u8,
        incarnation: u64,
        guard_sealed: bool,
    ) -> Result<Walked, crate::error::DriverError> {
        let mut walked = Walked::default();
        if self.ended {
            return Ok(walked);
        }
        for _ in 0..budget {
            let polled = self.walker.poll(&mut self.scratch)?;
            let (position, end, kind, reason) = match polled {
                PollOutcome::Message { position, .. } => {
                    (position, self.walker.position(), Kind::Submitted, 0)
                }
                PollOutcome::Aborted { position, extent } => {
                    let reason = if guard_sealed {
                        REASON_GUARD_CLOSED
                    } else {
                        REASON_WRITER_ABORTED
                    };
                    // Positions stay below 2^63 (the stream position range).
                    (
                        position,
                        position + u64::from(extent),
                        Kind::Aborted,
                        reason,
                    )
                }
                PollOutcome::Closed {
                    position,
                    reason: seal,
                } => {
                    self.ended = true;
                    let reason = if seal == SealReason::GuardClosed {
                        REASON_GUARD_CLOSED
                    } else {
                        0
                    };
                    (position, position, Kind::Ended, reason)
                }
                PollOutcome::Overrun { .. } => {
                    walked.overrun = true;
                    for bound in &mut self.bounds {
                        bound
                            .writer
                            .abandon(bound.ring.words(), LOST_UNKNOWN)
                            .map_err(crate::error::DriverError::Outcomes)?;
                    }
                    return Ok(walked);
                }
                // An image's skipped range carries no message; a revoked
                // walker reads nothing more.
                PollOutcome::Skipped { .. } => continue,
                PollOutcome::Pending | PollOutcome::Revoked { .. } => return Ok(walked),
            };
            let record = Record {
                kind,
                lane,
                receiver: 0,
                incarnation,
                start: base + position,
                end: base + end,
                epoch: 0,
                reason,
                lost: 0,
            };
            match self.ring_for(position) {
                Some(bound) => {
                    let record = Record {
                        epoch: bound.epoch,
                        ..record
                    };
                    match bound
                        .writer
                        .produce(bound.ring.words(), &bound.consumed, record)
                        .map_err(crate::error::DriverError::Outcomes)?
                    {
                        Produced::Written(_) => walked.written += 1,
                        Produced::Lost => walked.lost += 1,
                    }
                }
                // No handle was issued before this block: none reserved it.
                None => walked.lost += 1,
            }
            if self.ended {
                return Ok(walked);
            }
        }
        walked.budget_exhausted = true;
        Ok(walked)
    }
}

/// The ring and writer of a new handle: `C_m` message records plus the
/// one local `Ended` record.
///
/// # Errors
///
/// [`OutcomeError::Layout`] when `messages` is too large to size.
pub(crate) fn new_ring(messages: u64) -> Result<(Arc<HeapWords>, OutcomeWriter), OutcomeError> {
    let capacity = karyos_sys::outcome_ring::capacity(messages, 1).ok_or(OutcomeError::Layout)?;
    let words = usize::try_from(capacity)
        .ok()
        .and_then(karyos_sys::outcome_ring::ring_words)
        .ok_or(OutcomeError::Layout)?;
    let ring = Arc::new(HeapWords::zeroed(words));
    karyos_sys::outcome_ring::init(ring.words(), capacity)?;
    Ok((ring, OutcomeWriter::new(capacity)?))
}
