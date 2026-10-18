// SPDX-License-Identifier: Apache-2.0

//! Repair scheduling (`quantstratum-docs: karyos/design/reliable-transport.md`,
//! "Repair and control scheduling"; R7; RC-12 and RC-13, owner decision
//! P3; ACS 15597 and 15701).
//!
//! [`Scheduler`] serves one incarnation's pending repair jobs ([`Jobs`])
//! with its own [`Drr`] over the lanes, configured with the data path's
//! quanta, within the per-cycle **repair budget**. It never touches the
//! data DRR or the control budget: the sender agent's cycle runs control,
//! then repair, then first sends, each to its own budget.
//!
//! - **Selection.** Each lane serves its oldest pending job, one job per
//!   lane at a time, from the job's unsent cursor, one whole frame at a
//!   time. The head comes from [`RepairRead::head`]: a DATA frame is
//!   charged its aligned length, PAD and ABORTED their canonical 32
//!   bytes (SPEC section 7.4). Repair charges debit only this DRR.
//! - **Budget.** A head that does not fit the remaining bytes suspends the
//!   call and keeps the lane's deficit (owner decision P3); the protocol
//!   [`Drr`] carries that rule.
//! - **Start boundary (step 8)** and the end proof, at every head:
//!   - `BadRequest` answers `RANGE_INVALID`; `Unavailable` and `Revoked`
//!     answer `RANGE_UNAVAILABLE` with the floor read again after the
//!     refusal; each goes to every requester of the job, which fails;
//!   - `CorruptTerm`, `Retry` and `TooSmall` drop the job, counted, with no
//!     ERR: the receivers' retries are the next opportunity;
//!   - a head whose extent crosses the job's end answers `RANGE_INVALID`
//!     and sends no part of it; the whole frames already submitted stay
//!     valid repairs.
//! - **Submission.** [`RepairSubmit::submit`] copies the head into backend
//!   storage and submits it. Only a submitted head is debited and moves
//!   the job's cursor; the job is done when its last frame is submitted,
//!   which starts its linger. A known failure costs work only; an
//!   uncertain submission ends the job unresolved (no linger, no retry);
//!   no room ends the visit as backpressure. A copy staged before the
//!   floor moves is still submitted (RC-13): the floor is not read again
//!   between the read and the submission.
//!
//! - **Bounds per call.** A probe reads at most one head, so reads, and the
//!   ERRs they cause, stay within the loads budget: a refused job makes the
//!   probe ineligible and the lane's next job waits for its next probe. A
//!   known failed submission holds its lane for the rest of the call, the
//!   job kept, so one failing queue cannot spend the call's budget. A head
//!   the DRR would refuse (a charge of zero or above the largest, or one
//!   that does not move forward) is dropped and counted rather than left to
//!   fail every later call.
//!
//! The admitted-NAK count of the repair budget is spent by admission (R4);
//! this component spends its bytes and its word 0 loads, one probe each.
//! One [`Scheduler`] serves one incarnation; the round robin across
//! incarnations with a persistent cursor, sharing one repair budget per
//! cycle, is the sender agent's (the wiring, ACS 15773).

use karyos_protocol::lanes::drr::{Budget, Drr, DrrConfig, LaneSource, Probe, Report, Service};
use karyos_protocol::network::{NakReplyReason, Receiver};

use super::jobs::{JobKey, JobRef, Jobs};

/// A frame's alignment, and the charge of PAD and ABORTED records.
const RECORD: u64 = 32;

/// The head of a lane at a position, read under the NAK origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Head {
    /// A DATA frame whose extent ends at `next`; charged its aligned
    /// length.
    Data {
        /// The aligned length.
        aligned: u64,
        /// The position after it.
        next: u64,
    },
    /// A PAD or ABORTED record whose logical extent ends at `next`; its
    /// canonical 32 bytes travel.
    Record {
        /// The position after its extent.
        next: u64,
    },
}

impl Head {
    const fn next(self) -> u64 {
        match self {
            Self::Data { next, .. } | Self::Record { next } => next,
        }
    }

    const fn charge(self) -> u64 {
        match self {
            Self::Data { aligned, .. } => aligned,
            Self::Record { .. } => RECORD,
        }
    }
}

/// Why a repair read failed (the NAK origin of `read_committed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairReadError {
    /// Not a frame boundary, or beyond the NAK bound: `RANGE_INVALID`.
    BadRequest,
    /// Below the retention floor, or reclaimed: `RANGE_UNAVAILABLE`.
    Unavailable {
        /// The floor read after the refusal.
        lowest: u64,
    },
    /// The participant is revoked: `RANGE_UNAVAILABLE` at the floor.
    Revoked,
    /// A word 0 failed validation: dropped, no ERR.
    CorruptTerm,
    /// The head could not be read consistently: dropped, no ERR.
    Retry,
    /// The frame does not fit the backend storage: dropped, no ERR.
    TooSmall,
    /// The word 0 loads this call may spend ran out before the head was
    /// proved: the call ends, the job and the lane's deficit kept.
    Budget,
}

/// The lane reads repair uses.
pub trait RepairRead {
    /// The head of `lane` at `from`, from its word 0 only, ending at or
    /// before `end`, the request's end: a repair repeats only what the NAK
    /// asked for, whatever the datagrams the lane first sent held (a timed
    /// lane sends one frame per datagram).
    ///
    /// # Errors
    ///
    /// [`RepairReadError`].
    fn head(&mut self, lane: u8, from: u64, end: Option<u64>) -> Result<Head, RepairReadError>;

    /// The lane's retention floor now.
    fn floor(&self, lane: u8) -> u64;
}

/// The outcome of submitting one repair head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submit {
    /// Copied and submitted.
    Submitted,
    /// A known failure: not submitted.
    NotSubmitted,
    /// Exposure unknown: the job ends unresolved.
    Uncertain,
    /// The backend had no room.
    NoRoom,
    /// The backend or its queue is broken.
    Broken,
}

/// Where repair heads go.
pub trait RepairSubmit {
    /// Copies the head of `lane` at `from` into backend storage and submits
    /// it, for `job`.
    fn submit(&mut self, lane: u8, job: JobRef, from: u64, head: Head) -> Submit;

    /// An ERR NAK_REPLY for `key`'s range to each of `requesters`, on the
    /// route in `routes` that requester asked on (same order).
    fn reply(
        &mut self,
        key: &JobKey,
        requesters: &[Receiver],
        routes: &[usize],
        reason: NakReplyReason,
    );
}

/// What the scheduler counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SchedulerCounts {
    /// Heads submitted.
    pub submitted: u64,
    /// Jobs completed.
    pub done: u64,
    /// Jobs answered `RANGE_INVALID` at a head.
    pub range_invalid: u64,
    /// Jobs answered `RANGE_UNAVAILABLE` at a head.
    pub range_unavailable: u64,
    /// Jobs dropped with no ERR (`CorruptTerm`, `Retry`, `TooSmall`).
    pub dropped: u64,
    /// Jobs dropped for a head the DRR would refuse: a charge of zero or
    /// above the largest, or one that does not move forward.
    pub invalid_heads: u64,
    /// Jobs ended by an uncertain submission.
    pub unresolved: u64,
    /// Calls ended because a head read ran out of word 0 loads.
    pub budget_suspended: u64,
    /// An increment did not apply (sticky).
    pub overflowed: bool,
}

impl SchedulerCounts {
    fn bump(&mut self, field: impl FnOnce(&mut Self) -> &mut u64) {
        let count = field(self);
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => self.overflowed = true,
        }
    }
}

/// The per-cycle repair budget (RC-12; provisional and configurable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairBudget {
    /// Charged bytes (default 64 KiB).
    pub bytes: u64,
    /// Word 0 loads, one per probe (default 4096).
    pub loads: u32,
}

impl Default for RepairBudget {
    fn default() -> Self {
        Self {
            bytes: 64 * 1024,
            loads: 4096,
        }
    }
}

/// One incarnation's repair scheduler.
#[derive(Debug)]
pub struct Scheduler {
    drr: Drr,
    counts: SchedulerCounts,
}

/// The selected head of each lane between a probe and its service.
#[derive(Debug, Clone, Copy)]
struct Selected {
    job: JobRef,
    key: JobKey,
    from: u64,
    head: Head,
}

/// The jobs as a [`LaneSource`] for one call.
struct Source<'a, R, S> {
    jobs: &'a mut Jobs,
    read: &'a mut R,
    submit: &'a mut S,
    counts: &'a mut SchedulerCounts,
    selected: [Option<Selected>; karyos_protocol::lanes::drr::MAX_LANES],
    /// Lanes held for the rest of the call after a known failed
    /// submission: the job is kept for the next call.
    held: [bool; karyos_protocol::lanes::drr::MAX_LANES],
    /// The largest valid charge.
    max_charge: u64,
    /// A head read ran out of loads: the next service halts the call,
    /// which keeps the visit and every lane's deficit (an ineligible probe
    /// would forfeit it).
    suspended: bool,
    now: u64,
}

impl<R: RepairRead, S: RepairSubmit> Source<'_, R, S> {
    /// Ends `job` with an ERR to its requesters.
    fn refuse(&mut self, job: JobRef, key: &JobKey, reason: NakReplyReason) {
        self.submit.reply(
            key,
            self.jobs.requesters(job),
            self.jobs.requester_routes(job),
            reason,
        );
        self.jobs.failed(job);
        self.counts.bump(|c| match reason {
            NakReplyReason::RangeInvalid => &mut c.range_invalid,
            NakReplyReason::RangeUnavailable { .. } => &mut c.range_unavailable,
        });
    }
}

impl<R: RepairRead, S: RepairSubmit> LaneSource for Source<'_, R, S> {
    fn probe(&mut self, lane: usize) -> Probe {
        let Ok(lane_id) = u8::try_from(lane) else {
            return Probe::Ineligible;
        };
        if let Some(slot) = self.selected.get_mut(lane) {
            *slot = None;
        }
        if self.suspended {
            return Probe::Eligible { charge: RECORD };
        }
        if self.held.get(lane).copied().unwrap_or(true) {
            return Probe::Ineligible;
        }
        // At most one head is read per probe: a refused or dropped job
        // makes this probe ineligible, and the lane's next job waits for
        // its next probe, so reads and ERRs stay within the loads budget.
        let Some(pending) = self.jobs.next_for_lane(lane_id) else {
            return Probe::Ineligible;
        };
        let key = pending.key;
        let end = key.start.checked_add(u64::from(key.length));
        match self.read.head(lane_id, pending.cursor, end) {
            Ok(head) if end.is_some_and(|end| head.next() <= end) => {
                let charge = head.charge();
                if charge == 0 || charge > self.max_charge || head.next() <= pending.cursor {
                    // A head the DRR would refuse: dropped, never left to
                    // fail every later call.
                    self.jobs.failed(pending.job);
                    self.counts.bump(|c| &mut c.invalid_heads);
                    return Probe::Ineligible;
                }
                if let Some(slot) = self.selected.get_mut(lane) {
                    *slot = Some(Selected {
                        job: pending.job,
                        key,
                        from: pending.cursor,
                        head,
                    });
                }
                return Probe::Eligible { charge };
            }
            Ok(_) | Err(RepairReadError::BadRequest) => {
                self.refuse(pending.job, &key, NakReplyReason::RangeInvalid);
            }
            Err(error @ (RepairReadError::Unavailable { .. } | RepairReadError::Revoked)) => {
                // The floor read after the refusal, never below the one
                // the read reported.
                let floor = self.read.floor(lane_id);
                let lowest = match error {
                    RepairReadError::Unavailable { lowest } => lowest.max(floor),
                    _ => floor,
                };
                self.refuse(
                    pending.job,
                    &key,
                    NakReplyReason::RangeUnavailable {
                        lowest_retained: lowest,
                    },
                );
            }
            // Out of loads: the job waits; the least charge reaches serve,
            // which halts the call.
            Err(RepairReadError::Budget) => {
                self.suspended = true;
                self.counts.bump(|c| &mut c.budget_suspended);
                return Probe::Eligible { charge: RECORD };
            }
            Err(
                RepairReadError::CorruptTerm | RepairReadError::Retry | RepairReadError::TooSmall,
            ) => {
                self.jobs.failed(pending.job);
                self.counts.bump(|c| &mut c.dropped);
            }
        }
        Probe::Ineligible
    }

    fn serve(&mut self, lane: usize) -> Service {
        // A suspended call selected nothing: its service halts here.
        let Some(selected) = self.selected.get_mut(lane).and_then(Option::take) else {
            return Service::Halt;
        };
        let Ok(lane_id) = u8::try_from(lane) else {
            return Service::Halt;
        };
        let end = selected
            .key
            .start
            .checked_add(u64::from(selected.key.length));
        match self
            .submit
            .submit(lane_id, selected.job, selected.from, selected.head)
        {
            Submit::Submitted => {
                self.counts.bump(|c| &mut c.submitted);
                let next = selected.head.next();
                if end == Some(next) {
                    self.jobs.done(selected.job, self.now);
                    self.counts.bump(|c| &mut c.done);
                } else {
                    self.jobs.progress(selected.job, next);
                }
                Service::Served
            }
            Submit::NotSubmitted => {
                if let Some(held) = self.held.get_mut(lane) {
                    *held = true;
                }
                Service::NotServed
            }
            Submit::Uncertain => {
                self.jobs.unresolved(selected.job);
                self.counts.bump(|c| &mut c.unresolved);
                Service::Uncertain
            }
            Submit::NoRoom => Service::Backpressure,
            Submit::Broken => Service::Halt,
        }
    }
}

impl Scheduler {
    /// The scheduler of an incarnation whose data path uses `config`.
    #[must_use]
    pub fn new(config: DrrConfig) -> Self {
        Self {
            drr: Drr::new(config),
            counts: SchedulerCounts::default(),
        }
    }

    /// The counts.
    #[must_use]
    pub const fn counts(&self) -> &SchedulerCounts {
        &self.counts
    }

    /// A lane's repair deficit, kept across calls.
    #[must_use]
    pub fn deficit(&self, lane: usize) -> Option<u64> {
        self.drr.deficit(lane)
    }

    /// Serves `jobs` within `budget` at `now`, reading through `read` and
    /// submitting through `submit`.
    pub fn serve<R: RepairRead, S: RepairSubmit>(
        &mut self,
        jobs: &mut Jobs,
        budget: RepairBudget,
        read: &mut R,
        submit: &mut S,
        now: u64,
    ) -> Report {
        let mut source = Source {
            jobs,
            read,
            submit,
            counts: &mut self.counts,
            selected: [None; karyos_protocol::lanes::drr::MAX_LANES],
            held: [false; karyos_protocol::lanes::drr::MAX_LANES],
            max_charge: self.drr.config().max_charge(),
            suspended: false,
            now,
        };
        self.drr.run(
            Budget {
                work: budget.loads,
                bytes: budget.bytes,
            },
            &mut source,
        )
    }
}

#[cfg(test)]
mod tests;
