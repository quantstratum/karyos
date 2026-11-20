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
//! - **Concurrent streams (ADR-0092).** A concurrent stream is guarded
//!   with `H` handle slots, its publisher slot count. Its first guarded
//!   handle creates one shared outcome ring (layout version 3) bound to
//!   the guard's open epoch and to that handle's client; a handle of any
//!   other client is refused (`GC-7-client`), and one beyond `H` too. The
//!   walker writes every record into the shared ring through one
//!   [`SharedOutcomeWriter`], against one consumed cell per slot; each
//!   handle keeps the records of the blocks it reserved itself.
//! - **Network lanes.** A guarded network publication's lane is submitted
//!   by its sender gate, not at commit ("Trusted sockets in Phase 2"). The
//!   gate publishes its submission frontier
//!   (`karyos_sys::submission_frontier`), and the walker decides each
//!   message by it: `Submitted` once a backend took every frame of it,
//!   `Unknown` when it may have left whole unproven, and, once the gate
//!   will decide nothing more, `Aborted` for what never left whole (its
//!   last frame never left: a partial fragmented message is `Aborted`). A message not
//!   decided yet waits, with everything after it, so records stay in
//!   position order; `Ended` waits for the gate's final word too. A
//!   message's reservation is therefore released at its network
//!   submission, so the publisher holds at most `C_m` messages committed
//!   and not yet sent.

use std::collections::VecDeque;
use std::sync::Arc;

use karyos_client::ConsumedCell;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBuffer, PollOutcome, SealReason, Subscription};
use karyos_sys::outcome_ring::shared::{
    MAX_HANDLES, SharedBinding, SharedOutcomeWriter, SharedProduced,
};
use karyos_sys::outcome_ring::{Kind, LOST_UNKNOWN, OutcomeError, OutcomeWriter, Produced, Record};
use karyos_sys::submission_frontier::{Final, SubmissionFrontier};
use karyos_sys::term_bytes::TermBytes;

use crate::error::DriverError;
use crate::guards::GuardHandle;
use crate::shared_words::Words;

/// `AbortReason::GUARD_CLOSED` (guards-and-abort.md, G4).
pub(crate) const REASON_GUARD_CLOSED: u64 = 1;
/// `AbortReason::DEADLINE_MISSED` (G4).
pub(crate) const REASON_DEADLINE_MISSED: u64 = 2;
/// `AbortReason::PUBLICATION_FAULT` (G4).
pub(crate) const REASON_PUBLICATION_FAULT: u64 = 4;
/// `AbortReason::DRIVER_SHUTDOWN` (G4).
pub(crate) const REASON_DRIVER_SHUTDOWN: u64 = 5;
/// `AbortReason::WRITER_ABORTED` (G4): outcome records only.
pub(crate) const REASON_WRITER_ABORTED: u64 = 6;

/// The outcome ring of one issued handle.
#[derive(Debug)]
pub(crate) struct Bound {
    /// The buffer position at which the handle was issued: the walker
    /// writes records for blocks at or after it here.
    pub(crate) from: u64,
    pub(crate) epoch: u64,
    /// The ring the walker writes. Held until its last record is
    /// written, which can be after the handle is gone; a granted ring's
    /// region is unmapped by the driver when the bound drops, and its
    /// memory freed once the client has detached it too.
    pub(crate) ring: Arc<Words>,
    /// The client's consumed count, in word 0; held as the ring is.
    pub(crate) consumed: Arc<Words>,
    pub(crate) writer: OutcomeWriter,
}

/// [`MAX_HANDLES`] as a length: the walker's cell table is this long.
const SLOTS: usize = 64;
const _: () = assert!(MAX_HANDLES == 64);

/// The client that holds a concurrent guarded incarnation's handles
/// (ADR-0092 decision 2): every handle of the incarnation is its.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the client handles bind slots in karyos#1102 (c) and (d)"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShareClient {
    /// A handle issued in the driver's process.
    InProcess,
    /// A remote client, by its client id.
    Remote(u64),
}

/// The shared outcome ring of a concurrent guarded incarnation
/// (ADR-0092), created by its first guarded handle.
#[derive(Debug)]
struct Shared {
    /// The client whose handles the incarnation admits.
    client: ShareClient,
    /// The open epoch the ring is bound to.
    epoch: u64,
    /// What the ring's header names.
    binding: SharedBinding,
    ring: Arc<Words>,
    /// The consumed cell of each slot issued so far, in slot order.
    cells: Vec<Arc<Words>>,
    /// Stands in for the cells of slots not issued yet, which the writer
    /// never reads (they are not attached).
    unissued: Words,
    writer: SharedOutcomeWriter,
}

/// A handle slot of a concurrent guarded incarnation's shared ring, as
/// its handle binds it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the client handles bind slots in karyos#1102 (c) and (d)"
    )
)]
#[derive(Debug, Clone)]
pub(crate) struct SharedSlot {
    /// The slot index, 0 to `H - 1`.
    pub(crate) slot: usize,
    /// The shared ring, written by the driver only.
    pub(crate) ring: Arc<Words>,
    /// The slot's consumed cell, written by its handle.
    pub(crate) cell: Arc<Words>,
    /// What the ring's header names.
    pub(crate) binding: SharedBinding,
    /// The sequence the handle reads after: it starts there, and its
    /// cell holds it.
    pub(crate) consumed: u64,
}

/// A guarded stream's driver state.
#[derive(Debug)]
pub(crate) struct GuardedStream<T: TermBytes> {
    pub(crate) guard: GuardHandle,
    /// `C_m`.
    pub(crate) messages: u64,
    /// The publication's rate limit, validated: every handle's early
    /// check, and the sender gate's authoritative bucket. Until the network
    /// agents wire the gate (phase 7 of `quantstratum-docs:
    /// karyos/design/driver-network-agents.md`), the handles' copies are
    /// the only limiter in practice.
    pub(crate) rate: Option<karyos_sys::rate_limit::RatePolicy>,
    /// The version of `rate` (R-CORE-21): 1 when the stream was guarded
    /// with a rate, one more for each accepted change; 0 without a rate.
    pub(crate) rate_version: u64,
    /// The control reserve no policy goes below (R-CORE-21).
    pub(crate) reserve: Option<karyos_sys::rate_limit::Rate>,
    /// A guarded network publication's policy slot, which its sender gate
    /// reads at each serve (driver heap words, shared by its lanes).
    gate_slot: Option<Arc<Words>>,
    walker: Subscription<Arc<LogBuffer<T>>>,
    scratch: Vec<u8>,
    /// Rings of issued handles, oldest first.
    bounds: VecDeque<Bound>,
    /// Whether the walker reached the seal and wrote `Ended`.
    ended: bool,
    /// Positions of the blocks a guard close aborted: the walker labels
    /// those `GUARD_CLOSED`, every other aborted block `WRITER_ABORTED`
    /// (G4), whatever the seal state when it walks.
    guard_aborted: Vec<u64>,
    /// A network lane's submission frontier and its lane in it.
    network: Option<(Arc<SubmissionFrontier>, Lane)>,
    /// The block read and not decided yet: the walk resumes with it.
    pending: Option<Block>,
    /// `H`, a concurrent stream's handle slots; `None` for an exclusive
    /// stream.
    handles: Option<u64>,
    /// A concurrent stream's shared ring, once its first guarded handle
    /// was issued.
    shared: Option<Shared>,
    /// Blocks a guard close aborted on a concurrent stream, not labelled
    /// yet: its abort reports a count, not positions, so the walker labels
    /// that many aborted blocks `GUARD_CLOSED`, the first it reads after
    /// the close.
    close_aborts: u64,
}

/// One block the walker read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Block {
    /// A committed message, `[position, end)`.
    Message { position: u64, end: u64 },
    /// An aborted block and its reason.
    Aborted {
        position: u64,
        end: u64,
        reason: u64,
    },
    /// The seal.
    Closed { position: u64, seal: SealReason },
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
        (rate, reserve): (
            Option<karyos_sys::rate_limit::RatePolicy>,
            Option<karyos_sys::rate_limit::Rate>,
        ),
        walker: Subscription<Arc<LogBuffer<T>>>,
        max_message: usize,
    ) -> Self {
        Self {
            guard,
            messages,
            rate,
            rate_version: u64::from(rate.is_some()),
            reserve,
            gate_slot: None,
            walker,
            scratch: vec![0; max_message],
            bounds: VecDeque::new(),
            ended: false,
            guard_aborted: Vec::new(),
            network: None,
            pending: None,
            handles: None,
            shared: None,
            close_aborts: 0,
        }
    }

    /// Makes the stream a concurrent one with `handles` slots (`H`, 1 to
    /// [`MAX_HANDLES`]): its handles share one ring (ADR-0092).
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidConfig`] for `handles` outside that range.
    pub(crate) fn with_handles(mut self, handles: u64) -> Result<Self, DriverError> {
        if handles == 0 || handles > MAX_HANDLES {
            return Err(DriverError::InvalidConfig);
        }
        self.handles = Some(handles);
        Ok(self)
    }

    /// `H`, for a concurrent stream.
    pub(crate) fn handles(&self) -> Option<u64> {
        self.handles
    }

    /// Admits a concurrent guarded handle of `client` under open epoch
    /// `epoch` into the next slot of the incarnation's shared ring,
    /// creating the ring, on the heap, at the first one: bound to `epoch`
    /// and to guard word `guard_index`, with the current rate policy and,
    /// for a reincarnation, its start (`reincarnated_at`) in its header.
    ///
    /// # Errors
    ///
    /// [`DriverError::InvalidPublicationMode`] for an exclusive stream;
    /// [`DriverError::Sys`] with `InvalidPublicationMode` (reason
    /// `GC-7-client`) for a client other than the ring's (ADR-0092
    /// decision 2); [`DriverError::GuardHandleSlotsExhausted`] once `H`
    /// slots were issued; [`DriverError::GuardNotOpen`] for an epoch other
    /// than the ring's; [`DriverError::Outcomes`] for a ring too large to
    /// size. Nothing changes on error.
    pub(crate) fn attach_shared(
        &mut self,
        stream: u64,
        client: ShareClient,
        epoch: u64,
        guard_index: usize,
        reincarnated_at: Option<u64>,
    ) -> Result<SharedSlot, DriverError> {
        let handles = self.handles.ok_or(DriverError::InvalidPublicationMode)?;
        if let Some(shared) = &self.shared {
            if shared.client != client {
                return Err(DriverError::Sys(
                    karyos_sys::error::SysError::InvalidPublicationMode {
                        reason: "GC-7-client",
                    },
                ));
            }
            if shared.epoch != epoch {
                return Err(DriverError::GuardNotOpen {
                    guard: self.guard.id(),
                });
            }
        }
        let slot = self.shared.as_ref().map_or(0, |shared| shared.cells.len());
        if u64::try_from(slot).ok().is_none_or(|slot| slot >= handles) {
            return Err(DriverError::GuardHandleSlotsExhausted { stream, handles });
        }
        if self.shared.is_none() {
            self.shared = Some(self.new_shared(client, epoch, guard_index, reincarnated_at)?);
        }
        let shared = self
            .shared
            .as_mut()
            .ok_or(DriverError::InvalidPublicationMode)?;
        // Within the `H` cells reserved with the ring: no allocation.
        let consumed = shared.writer.attach(slot).map_err(DriverError::Outcomes)?;
        let cell = Arc::new(Words::heap(1));
        cell.cell()
            .store(consumed, karyos_sys::sync::Ordering::Release);
        shared.cells.push(Arc::clone(&cell));
        Ok(SharedSlot {
            slot,
            ring: Arc::clone(&shared.ring),
            cell,
            binding: shared.binding,
            consumed,
        })
    }

    /// The shared ring of a first concurrent guarded handle.
    fn new_shared(
        &self,
        client: ShareClient,
        epoch: u64,
        guard_index: usize,
        reincarnated_at: Option<u64>,
    ) -> Result<Shared, DriverError> {
        let layout = || DriverError::Outcomes(OutcomeError::Layout);
        let binding = SharedBinding {
            messages: self.messages,
            ranges: 1,
            guard_index: u64::try_from(guard_index).map_err(|_| layout())?,
            epoch,
            handles: self.handles.ok_or_else(layout)?,
        };
        let words = binding
            .capacity()
            .and_then(|capacity| usize::try_from(capacity).ok())
            .and_then(karyos_sys::outcome_ring::ring_words)
            .ok_or_else(layout)?;
        let ring = Words::heap(words);
        karyos_sys::outcome_ring::shared::init(ring.words(), &binding)
            .map_err(DriverError::Outcomes)?;
        if let Some(at) = reincarnated_at {
            karyos_sys::outcome_ring::set_reincarnated_at(ring.words(), at);
        }
        if let Some(policy) = &self.rate {
            karyos_sys::rate_policy_slot::publish(
                ring.words(),
                karyos_sys::rate_policy_slot::OUTCOME_SLOT,
                self.rate_version,
                policy,
            );
        }
        let writer = SharedOutcomeWriter::new(&binding).map_err(DriverError::Outcomes)?;
        let slots = usize::try_from(binding.handles).map_err(|_| layout())?;
        let mut cells = Vec::new();
        cells.try_reserve_exact(slots).map_err(|_| layout())?;
        Ok(Shared {
            client,
            epoch,
            binding,
            ring: Arc::new(ring),
            cells,
            unissued: Words::heap(1),
            writer,
        })
    }

    /// Detaches handle `slot` from the shared ring: it leaves the room
    /// minimum, its blocks' records are still written, and its slot is not
    /// issued again in this incarnation (ADR-0092 decisions 3 and 8).
    pub(crate) fn detach_shared(&mut self, slot: usize) {
        if let Some(shared) = &mut self.shared {
            shared.writer.detach(slot);
        }
    }

    /// Counts `aborted` blocks a guard close aborted on a concurrent
    /// stream (`Conductor::abort_marked_claims`).
    pub(crate) fn note_close_aborts(&mut self, aborted: u32) {
        self.close_aborts = self.close_aborts.saturating_add(u64::from(aborted));
    }

    /// From now on its messages are decided by `frontier`'s `lane`: the
    /// lane is a guarded network publication's (control path, before the
    /// sender is posted).
    pub(crate) fn submit_through(&mut self, frontier: Arc<SubmissionFrontier>, lane: Lane) {
        self.network = Some((frontier, lane));
    }

    /// `block`'s record, `(position, end, kind, reason)`; `None` while a
    /// network lane's gate has not decided it.
    fn decide(&self, block: Block) -> Option<(u64, u64, Kind, u64)> {
        let decided = match (block, &self.network) {
            (
                Block::Aborted {
                    position,
                    end,
                    reason,
                },
                _,
            ) => (position, end, Kind::Aborted, reason),
            (Block::Message { position, end }, None) => (position, end, Kind::Submitted, 0),
            (Block::Closed { position, seal }, None) => {
                (position, position, Kind::Ended, end_reason(seal))
            }
            (Block::Message { position, end }, Some((frontier, lane))) => {
                let (state, at) = frontier.read(*lane);
                if end <= at.resolved {
                    // Every frame was submitted, or is a hole that may
                    // have left.
                    let kind = if position < at.unknown_hi {
                        Kind::Unknown
                    } else {
                        Kind::Submitted
                    };
                    (position, end, kind, 0)
                } else {
                    // Above `resolved` once final: whole only if its last
                    // frame may have left (a later route may have
                    // submitted it, or it may have left unproven), never
                    // whole otherwise, so `Aborted` (a partial fragmented
                    // message is `Aborted`). A superseded gate may have
                    // exposed whatever it staged.
                    let (left, reason) = match state {
                        Final::Open => return None,
                        Final::Finished { reason } => (at.sent_hi, reason),
                        Final::Superseded { reason } => (at.staged_hi, reason),
                    };
                    if end <= left {
                        (position, end, Kind::Unknown, 0)
                    } else {
                        (position, end, Kind::Aborted, reason)
                    }
                }
            }
            (Block::Closed { position, seal }, Some((frontier, lane))) => {
                if frontier.read(*lane).0 == Final::Open {
                    return None;
                }
                (position, position, Kind::Ended, end_reason(seal))
            }
        };
        Some(decided)
    }

    /// Whether the walker reached the seal and wrote `Ended`, or was
    /// lapped and abandoned its rings.
    pub(crate) fn ended(&self) -> bool {
        self.ended
    }

    /// Ends the walk: nothing more is recorded (a lapped walker).
    pub(crate) fn finish(&mut self) {
        self.ended = true;
    }

    /// Records a block the guard close aborted (`ClaimDeadline::Aborted`).
    pub(crate) fn note_guard_abort(&mut self, position: u64) {
        self.guard_aborted.push(position);
    }

    /// Abandons every bound ring with an unknown lost count: the walker
    /// was lapped, a broken invariant.
    ///
    /// # Errors
    ///
    /// [`DriverError::Outcomes`] for a ring that refuses the record.
    pub(crate) fn abandon_all(&mut self) -> Result<(), crate::error::DriverError> {
        if let Some(shared) = &mut self.shared {
            shared
                .writer
                .abandon(shared.ring.words())
                .map_err(crate::error::DriverError::Outcomes)?;
        }
        for bound in &mut self.bounds {
            bound
                .writer
                .abandon(bound.ring.words(), LOST_UNKNOWN)
                .map_err(crate::error::DriverError::Outcomes)?;
        }
        Ok(())
    }

    /// Its sender gate's policy slot, if it has one.
    pub(crate) fn gate_slot(&self) -> Option<&Arc<Words>> {
        self.gate_slot.as_ref()
    }

    /// Gives the stream its sender gate's policy slot, which starts with
    /// the current policy (R-CORE-21).
    pub(crate) fn set_gate_slot(&mut self, slot: Arc<Words>) {
        self.gate_slot = Some(slot);
        self.publish_gate();
    }

    /// Keeps the slot of the incarnation it replaces, which already holds
    /// this stream's policy at its version: nothing is published again.
    pub(crate) fn keep_gate_slot(&mut self, slot: Arc<Words>) {
        self.gate_slot = Some(slot);
    }

    /// Binds a newly issued handle's ring, for blocks from `from` on. The
    /// ring starts with the stream's current rate policy published in its
    /// header (R-CORE-21).
    pub(crate) fn bind(&mut self, bound: Bound) {
        if let Some(policy) = &self.rate {
            karyos_sys::rate_policy_slot::publish(
                bound.ring.words(),
                karyos_sys::rate_policy_slot::OUTCOME_SLOT,
                self.rate_version,
                policy,
            );
        }
        self.bounds.push_back(bound);
    }

    /// Publishes the stream's policy at its version into its sender gate's
    /// slot, if it has one (R-CORE-21). An aggregate's lanes share the slot,
    /// so the caller publishes it once per change, from one lane.
    pub(crate) fn publish_gate(&self) {
        if let (Some(slot), Some(policy)) = (&self.gate_slot, &self.rate) {
            karyos_sys::rate_policy_slot::publish(slot.words(), 0, self.rate_version, policy);
        }
    }

    /// Makes `policy` the stream's rate policy as version `version`, and
    /// publishes it into every bound handle's ring, which each handle reads
    /// on its next call (R-CORE-21); the gate's slot is the caller's
    /// ([`Self::publish_gate`]). The caller validated the policy and its
    /// transition.
    pub(crate) fn set_rate(&mut self, policy: karyos_sys::rate_limit::RatePolicy, version: u64) {
        self.rate = Some(policy);
        self.rate_version = version;
        if let Some(shared) = &self.shared {
            karyos_sys::rate_policy_slot::publish(
                shared.ring.words(),
                karyos_sys::rate_policy_slot::OUTCOME_SLOT,
                version,
                &policy,
            );
        }
        for bound in &self.bounds {
            karyos_sys::rate_policy_slot::publish(
                bound.ring.words(),
                karyos_sys::rate_policy_slot::OUTCOME_SLOT,
                version,
                &policy,
            );
        }
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
    ) -> Result<Walked, crate::error::DriverError> {
        let mut walked = Walked::default();
        if self.ended {
            return Ok(walked);
        }
        for _ in 0..budget {
            let block = match self.pending.take() {
                Some(block) => block,
                None => match self.walker.poll(&mut self.scratch)? {
                    PollOutcome::Message { position, .. } => Block::Message {
                        position,
                        end: self.walker.position(),
                    },
                    PollOutcome::Aborted { position, extent } => {
                        let by_close = self.guard_aborted.iter().position(|&at| at == position);
                        let reason = match by_close {
                            Some(index) => {
                                let _ = self.guard_aborted.swap_remove(index);
                                REASON_GUARD_CLOSED
                            }
                            None if self.close_aborts > 0 => {
                                self.close_aborts = self.close_aborts.saturating_sub(1);
                                REASON_GUARD_CLOSED
                            }
                            None => REASON_WRITER_ABORTED,
                        };
                        // Positions stay below 2^63 (the stream position
                        // range).
                        Block::Aborted {
                            position,
                            end: position + u64::from(extent),
                            reason,
                        }
                    }
                    PollOutcome::Closed {
                        position,
                        reason: seal,
                    } => Block::Closed { position, seal },
                    PollOutcome::Overrun { .. } => {
                        walked.overrun = true;
                        self.abandon_all()?;
                        return Ok(walked);
                    }
                    // An image's skipped range carries no message; a revoked
                    // walker reads nothing more.
                    PollOutcome::Skipped { .. } => continue,
                    PollOutcome::Pending | PollOutcome::Revoked { .. } => return Ok(walked),
                },
            };
            // Not decided yet: it waits, and so does everything after it.
            let Some((position, end, kind, reason)) = self.decide(block) else {
                self.pending = Some(block);
                return Ok(walked);
            };
            if kind == Kind::Ended {
                self.ended = true;
            }
            let (Some(start), Some(end)) = (base.checked_add(position), base.checked_add(end))
            else {
                return Err(crate::error::DriverError::PositionsExhausted);
            };
            let record = Record {
                kind,
                lane,
                receiver: 0,
                incarnation,
                start,
                end,
                epoch: 0,
                reason,
                lost: 0,
            };
            if let Some(shared) = &mut self.shared {
                let record = Record {
                    epoch: shared.epoch,
                    ..record
                };
                let mut cells = [shared.unissued.cell(); SLOTS];
                for (cell, issued) in cells.iter_mut().zip(&shared.cells) {
                    *cell = issued.cell();
                }
                match shared
                    .writer
                    .produce(shared.ring.words(), &cells, record)
                    .map_err(crate::error::DriverError::Outcomes)?
                {
                    SharedProduced::Written(_) => walked.written += 1,
                    SharedProduced::Unread => walked.lost += 1,
                }
                if self.ended {
                    return Ok(walked);
                }
                continue;
            }
            match self.ring_for(position) {
                Some(bound) => {
                    let record = Record {
                        epoch: bound.epoch,
                        ..record
                    };
                    match bound
                        .writer
                        .produce(bound.ring.words(), bound.consumed.cell(), record)
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

/// The `AbortReason` (G4) an incarnation's `Ended` record carries for the
/// seal that ended it: `GUARD_CLOSED` (1) for a guard close,
/// `DEADLINE_MISSED` (2) for cancel-on-deadline, `DRIVER_SHUTDOWN` (5) for
/// a removal or an image's end of stream (orderly ends that cannot drain),
/// and `PUBLICATION_FAULT` (4) for a schedule violation (its publisher
/// breached the ring's protocol, timed-tx.md section 11) and any other
/// seal. Code 0 is reserved and never written.
pub(crate) const fn end_reason(seal: SealReason) -> u64 {
    match seal {
        SealReason::GuardClosed => REASON_GUARD_CLOSED,
        SealReason::DeadlineMissed => REASON_DEADLINE_MISSED,
        SealReason::StreamRemoved | SealReason::EndOfStream => REASON_DRIVER_SHUTDOWN,
        SealReason::ScheduleViolation => REASON_PUBLICATION_FAULT,
        _ => REASON_PUBLICATION_FAULT,
    }
}

/// Where a handle's outcome ring and consumed cell live.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Place {
    /// On the heap, for an in-process handle.
    Heap,
    /// In two new regions of driver instance `instance` (Linux), for a
    /// grant: the ring driver-only, the cell writable by its client.
    #[cfg(target_os = "linux")]
    Regions {
        /// The driver instance.
        instance: u128,
        /// The ring's region id.
        ring: u64,
        /// The cell's region id.
        cell: u64,
    },
}

/// The outcome ring, consumed cell and writer of a new handle bound to
/// guard word `guard_index` and admitted under open epoch `epoch`: `C_m`
/// message records plus the one local `Ended` record. The ring's header
/// names its binding before anything can read it.
///
/// # Errors
///
/// [`DriverError::Outcomes`] with [`OutcomeError::Layout`] when
/// `messages` is too large to size, and the regions' errors.
pub(crate) fn new_ring(
    messages: u64,
    epoch: u64,
    guard_index: usize,
    place: Place,
) -> Result<(Arc<Words>, Arc<Words>, OutcomeWriter), DriverError> {
    let layout = |_| DriverError::Outcomes(OutcomeError::Layout);
    let binding = karyos_sys::outcome_ring::Binding {
        messages,
        ranges: 1,
        guard_index: u64::try_from(guard_index).map_err(layout)?,
        epoch,
    };
    let capacity = binding
        .capacity()
        .ok_or(DriverError::Outcomes(OutcomeError::Layout))?;
    let words = usize::try_from(capacity)
        .ok()
        .and_then(karyos_sys::outcome_ring::ring_words)
        .ok_or(DriverError::Outcomes(OutcomeError::Layout))?;
    let (ring, consumed) = match place {
        Place::Heap => (Words::heap(words), Words::heap(1)),
        #[cfg(target_os = "linux")]
        Place::Regions {
            instance,
            ring,
            cell,
        } => (
            Words::region(
                instance,
                ring,
                karyos_sys::ipc::RegionKind::OutcomeRing,
                karyos_sys::outcome_ring::OUTCOME_LAYOUT_VERSION,
                words,
                true,
            )?,
            Words::region(
                instance,
                cell,
                karyos_sys::ipc::RegionKind::ConsumedCell,
                karyos_sys::outcome_ring::CONSUMED_CELL_LAYOUT_VERSION,
                1,
                false,
            )?,
        ),
    };
    karyos_sys::outcome_ring::init(ring.words(), &binding).map_err(DriverError::Outcomes)?;
    let writer = OutcomeWriter::new(capacity).map_err(DriverError::Outcomes)?;
    Ok((Arc::new(ring), Arc::new(consumed), writer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
    use karyos_sys::outcome_ring::{OutcomeReader, Produced};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    #[test]
    fn a_lapped_walker_abandons_with_an_unknown_count() {
        let buffer = Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 3,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: karyos_sys::frame::Lane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            })
            .unwrap(),
        );
        let mut conductor = buffer.conductor_owned().unwrap();
        let walker = conductor.subscribe(Role::Walker).unwrap();
        let guard = GuardHandle {
            driver: 1,
            guard: 1,
        };
        let mut guarded = GuardedStream::new(guard, 2, (None, None), walker, 64);
        let (ring, consumed, writer) = new_ring(2, 2, 0, Place::Heap).unwrap();
        guarded.bind(Bound {
            from: 0,
            epoch: 2,
            ring: Arc::clone(&ring),
            consumed: Arc::clone(&consumed),
            writer,
        });
        guarded.abandon_all().unwrap();
        let bound = guarded.bounds.front_mut().unwrap();
        assert_eq!(bound.writer.faulted(), Some(LOST_UNKNOWN));
        let record = Record {
            kind: Kind::Submitted,
            lane: 0,
            receiver: 0,
            incarnation: 1,
            start: 0,
            end: 64,
            epoch: 2,
            reason: 0,
            lost: 0,
        };
        assert_eq!(
            bound
                .writer
                .produce(bound.ring.words(), bound.consumed.cell(), record)
                .unwrap(),
            Produced::Lost
        );
        let mut reader = OutcomeReader::attach(&*ring, 1).unwrap();
        let mut seen = Vec::new();
        let _ = reader
            .poll(&*ring, consumed.cell(), 8, |_, record| seen.push(record))
            .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (seen[0].kind, seen[0].lost),
            (Kind::OutcomesLost, LOST_UNKNOWN)
        );
    }

    fn guarded() -> GuardedStream<karyos_sys::term_bytes::HeapTerms> {
        let buffer = Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 3,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: karyos_sys::frame::Lane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            })
            .unwrap(),
        );
        let mut conductor = buffer.conductor_owned().unwrap();
        let walker = conductor.subscribe(Role::Walker).unwrap();
        let guard = GuardHandle {
            driver: 1,
            guard: 1,
        };
        GuardedStream::new(guard, 2, (None, None), walker, 64)
    }

    fn message(position: u64, end: u64) -> Block {
        Block::Message { position, end }
    }

    /// Records plan v2: a network lane's message is `Submitted` only below
    /// `resolved` and clear of every hole, `Unknown` when it may have left,
    /// waits while the gate may still decide it, and is `Aborted` once the
    /// gate will not; `Ended` waits for the final word. A local stream's
    /// message is submitted at commit, as before.
    #[test]
    fn a_network_lanes_message_is_decided_by_its_frontier() {
        use karyos_sys::submission_frontier::{Frontier, SubmissionFrontier};

        let closed = Block::Closed {
            position: 192,
            seal: SealReason::GuardClosed,
        };
        let local = guarded();
        assert_eq!(
            local.decide(message(0, 64)),
            Some((0, 64, Kind::Submitted, 0))
        );
        assert_eq!(local.decide(closed), Some((192, 192, Kind::Ended, 1)));

        let frontier = Arc::new(SubmissionFrontier::new());
        let mut network = guarded();
        network.submit_through(Arc::clone(&frontier), Lane::ZERO);
        frontier.publish(
            Lane::ZERO,
            Frontier {
                resolved: 128,
                unknown_hi: 64,
                sent_hi: 160,
                staged_hi: 192,
            },
        );
        assert_eq!(
            network.decide(message(0, 64)),
            Some((0, 64, Kind::Unknown, 0))
        );
        assert_eq!(
            network.decide(message(64, 128)),
            Some((64, 128, Kind::Submitted, 0))
        );
        assert_eq!(network.decide(message(128, 192)), None, "not decided");
        assert_eq!(network.decide(closed), None, "Ended waits");
        let aborted = Block::Aborted {
            position: 128,
            end: 192,
            reason: REASON_WRITER_ABORTED,
        };
        assert_eq!(
            network.decide(aborted),
            Some((128, 192, Kind::Aborted, REASON_WRITER_ABORTED))
        );
        assert_eq!(frontier.finish(Lane::ZERO, REASON_GUARD_CLOSED), Ok(true));
        // Its last frame may have left (a later route, or unproven): it
        // may be whole.
        assert_eq!(
            network.decide(message(128, 160)),
            Some((128, 160, Kind::Unknown, 0))
        );
        // Its last frame never left: never whole, whatever went before.
        assert_eq!(
            network.decide(message(128, 192)),
            Some((128, 192, Kind::Aborted, REASON_GUARD_CLOSED))
        );
        assert_eq!(network.decide(closed), Some((192, 192, Kind::Ended, 1)));

        // Superseded: the gate never ran again, so what it staged may have
        // left; nothing above it ever did.
        let frontier = Arc::new(SubmissionFrontier::new());
        let mut network = guarded();
        network.submit_through(Arc::clone(&frontier), Lane::ZERO);
        frontier.publish(
            Lane::ZERO,
            Frontier {
                resolved: 128,
                unknown_hi: 0,
                sent_hi: 128,
                staged_hi: 192,
            },
        );
        assert_eq!(
            frontier.supersede(Lane::ZERO, REASON_DRIVER_SHUTDOWN),
            Ok(true)
        );
        assert_eq!(
            network.decide(message(128, 192)),
            Some((128, 192, Kind::Unknown, 0))
        );
        // Straddling `staged_hi`: its last frame was never staged.
        assert_eq!(
            network.decide(message(160, 224)),
            Some((160, 224, Kind::Aborted, REASON_DRIVER_SHUTDOWN))
        );
        assert_eq!(
            network.decide(message(192, 256)),
            Some((192, 256, Kind::Aborted, REASON_DRIVER_SHUTDOWN))
        );
    }

    #[test]
    fn every_seal_ends_with_a_defined_reason() {
        assert_eq!(end_reason(SealReason::GuardClosed), 1);
        assert_eq!(end_reason(SealReason::DeadlineMissed), 2);
        assert_eq!(end_reason(SealReason::StreamRemoved), 5);
        assert_eq!(end_reason(SealReason::EndOfStream), 5);
        assert_eq!(end_reason(SealReason::Unspecified), 4);
        assert_eq!(end_reason(SealReason::ScheduleViolation), 4);
    }
}
