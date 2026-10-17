// SPDX-License-Identifier: Apache-2.0

//! The sender agent's repair path of one reliable publication
//! (`quantstratum-docs: karyos/design/reliable-transport.md`, "Sender
//! request and retention validation", "Coalescing and repair work" and
//! "Repair and control scheduling"; R4, R5 and R7 wired; ACS 15919 and
//! 15920).
//!
//! - **NAKs.** [`RepairPath::nak`] runs admission steps 1 to 5
//!   ([`Admission`]) against the lane's retention floor (the floor its
//!   reads enforce, [`LaneReader::floor`]) and NAK bound (the highest
//!   position submitted on the lane), then coalescing and capacity
//!   ([`Jobs`]). At most `naks_per_cycle` NAKs are admitted per cycle; the
//!   rest are dropped and counted, and the receivers retry. Every job
//!   answers the group (`Domain::Group`): the repair goes over the
//!   publication's channel route, the receiver for unicast. The requester
//!   domain (a unicast return route under multicast) comes later.
//! - **Repairs.** [`RepairPath::serve`] runs the scheduler ([`Scheduler`])
//!   within the cycle's shared [`RepairBudget`]. A head is read with the
//!   NAK origin (`SenderRead::read_nak`) into a scratch buffer of one
//!   datagram, allocated with the path, and spends the budget's word 0
//!   loads; it is then copied into a frame of the publication's repair
//!   queue and submitted alone (RC-13 allows the staged copy). The repair
//!   queue is opened with the lane queues, outside the lane sender, so a
//!   repair never touches the data DRR. A head still pending after its
//!   flush is cancelled: it was not submitted.
//! - **ERRs.** Step 8 refusals go through admission's ERR linger, as an
//!   admission refusal does, and wait in a bounded list for the sender
//!   agent, which sends each to its requester's bound source; a full list
//!   drops and counts.
//!
//! Two checks are defense in depth, unreachable through the scheduler: a
//! read never goes past the lane's NAK bound (admission already refused
//! such a range), and a submission must name the head read last.
//!
//! Nothing allocates after construction; counts are checked and sticky on
//! overflow.

use std::cell::RefCell;
use std::num::NonZeroU16;

use karyos_io::backend::{
    ClaimError, Commit, Exposure, FlushRequest, GateDecision, PendingCause, SenderGate,
    SenderToken, TxBackend, TxFrame, TxItemOutcome, TxOptions, TxQueueId, TxReport,
};
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::frame::Lane;
use karyos_protocol::lanes::drr::{DrrConfig, Report};
use karyos_protocol::network::{
    Alias, Identity, Nak, NakRange, NakReply, NakReplyReason, Receiver,
};
use karyos_sys::log_buffer::{NakRead, ReadError, ReadOutcome};
use karyos_sys::sizing::align_frame;

use super::data::LaneReader;
use crate::embedded::StreamTerms;
use crate::repair::admission::{Admission, AdmissionError, Admitted, NakContext, Requester};
use crate::repair::jobs::{Domain, JobKey, JobRef, Jobs, JobsConfig, JobsError, Joined};
use crate::repair::scheduler::{
    Head, RepairBudget, RepairRead, RepairReadError, RepairSubmit, Scheduler, Submit,
};

/// The repair settings of the sender agent (RC-11, RC-12; provisional and
/// configurable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairConfig {
    /// The ERR linger, in ns (default 1 ms).
    pub nak_reply_linger: u64,
    /// ERR linger entries per publication (default 256).
    pub err_linger_entries: usize,
    /// The job table of each publication.
    pub jobs: JobsConfig,
    /// The repair budget per cycle, shared by every publication.
    pub budget: RepairBudget,
    /// NAKs admitted per cycle, over every publication (default 16).
    pub naks_per_cycle: u32,
    /// Step 8 ERRs a publication holds for sending (default 64).
    pub replies: usize,
}

impl Default for RepairConfig {
    fn default() -> Self {
        Self {
            nak_reply_linger: 1_000_000,
            err_linger_entries: 256,
            jobs: JobsConfig::default(),
            budget: RepairBudget::default(),
            naks_per_cycle: 16,
            replies: 64,
        }
    }
}

/// Why a repair path could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RepairConfigError {
    /// The ERR linger table is empty.
    #[error("invalid NAK admission settings")]
    Admission(#[from] AdmissionError),
    /// The job table settings are invalid.
    #[error("invalid repair job settings")]
    Jobs(#[from] JobsError),
    /// No room for a step 8 ERR, or no NAK admitted per cycle.
    #[error("repair replies and naks_per_cycle must be at least 1")]
    Zero,
}

/// What a repair path counted, besides its components' counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RepairCounts {
    /// NAKs that created a job.
    pub jobs_created: u64,
    /// NAKs that joined a pending job.
    pub jobs_joined: u64,
    /// NAKs dropped within a done job's linger.
    pub lingering: u64,
    /// NAKs dropped for a full job table.
    pub jobs_full: u64,
    /// Repair datagrams submitted.
    pub submitted: u64,
    /// Repair datagrams cancelled after their flush left them pending.
    pub cancelled: u64,
    /// Step 8 ERRs dropped for a full reply list.
    pub replies_full: u64,
    /// A head submitted for a read it was not staged from: a broken
    /// invariant.
    pub unstaged: u64,
    /// An increment did not apply (sticky).
    pub overflowed: bool,
}

impl RepairCounts {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64) {
        let count = field(self);
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => self.overflowed = true,
        }
    }
}

/// The head read last, staged for its submission.
#[derive(Debug)]
struct Scratch {
    bytes: Vec<u8>,
    /// Lane, position and length of the staged head.
    staged: Option<(u8, u64, usize)>,
}

/// One reliable publication's repair path.
#[derive(Debug)]
pub struct RepairPath {
    admission: Admission,
    jobs: Jobs,
    scheduler: Scheduler,
    scratch: RefCell<Scratch>,
    /// The repair queue of the current endpoint epoch.
    queue: Option<TxQueueId>,
    /// Step 8 ERRs waiting for the sender agent (allocated here).
    replies: Vec<NakReply>,
    max_replies: usize,
    /// The incarnation's term length.
    term_length: u32,
    /// The publication, for its step 8 ERRs.
    alias: Alias,
    identity: Identity,
    report: TxReport,
    counts: RepairCounts,
}

/// What [`RepairPath::nak`] did with a NAK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NakOutcome {
    /// Dropped with no reply (counted by admission or the job table).
    Dropped,
    /// Answered with this ERR, to the NAK's source.
    Reply(NakReply),
    /// A job holds it.
    Queued,
}

impl RepairPath {
    /// The repair path of the publication `alias` and `identity`, whose
    /// data path uses `drr` and datagrams of at most `mtu` bytes, with terms
    /// of `term_length`; it allocates only here.
    ///
    /// # Errors
    ///
    /// [`RepairConfigError`].
    pub fn new(
        config: &RepairConfig,
        drr: DrrConfig,
        mtu: usize,
        (term_length, alias, identity): (u32, Alias, Identity),
    ) -> Result<Self, RepairConfigError> {
        if config.replies == 0 || config.naks_per_cycle == 0 {
            return Err(RepairConfigError::Zero);
        }
        Ok(Self {
            admission: Admission::new(config.nak_reply_linger, config.err_linger_entries)?,
            jobs: Jobs::new(config.jobs)?,
            scheduler: Scheduler::new(drr),
            scratch: RefCell::new(Scratch {
                bytes: vec![0; mtu],
                staged: None,
            }),
            queue: None,
            replies: Vec::with_capacity(config.replies),
            max_replies: config.replies,
            term_length,
            alias,
            identity,
            report: TxReport::new(),
            counts: RepairCounts::default(),
        })
    }

    /// What it counted.
    #[must_use]
    pub fn counts(&self) -> RepairCounts {
        self.counts
    }

    /// Its admission, job table and scheduler, for their counts.
    #[must_use]
    pub fn parts(&self) -> (&Admission, &Jobs, &Scheduler) {
        (&self.admission, &self.jobs, &self.scheduler)
    }

    /// The repair queue of the current endpoint epoch.
    #[must_use]
    pub fn queue(&self) -> Option<TxQueueId> {
        self.queue
    }

    /// The endpoint epoch changed: `queue` is the new repair queue (or none
    /// could be opened). Nothing staged in the old one survives.
    pub fn reopened(&mut self, queue: Option<TxQueueId>) {
        self.queue = queue;
        if let Ok(mut scratch) = self.scratch.try_borrow_mut() {
            scratch.staged = None;
        }
    }

    /// Admits `nak` from a bound receiver, whose state on the lane is
    /// `requester`, against `reader`'s retention floor and the lane's NAK
    /// bound `sent_high`, at `now` (R4 steps 1 to 5, then R5).
    pub fn nak<T: StreamTerms>(
        &mut self,
        nak: &Nak,
        requester: Requester,
        reader: Option<&LaneReader<T>>,
        sent_high: u64,
        lane_count: u8,
        now: u64,
    ) -> NakOutcome {
        let ctx = NakContext {
            reliable: true,
            lane_count,
            requester,
            floor: reader.map_or(0, LaneReader::<T>::floor),
            nak_bound: sent_high,
            term_length: self.term_length,
        };
        match self.admission.admit(nak, &ctx, now) {
            Admitted::Dropped(_) => NakOutcome::Dropped,
            Admitted::Reply(reply) => NakOutcome::Reply(reply),
            Admitted::Pass(request) => match self.jobs.join_or_create(&request, Domain::Group, now)
            {
                Joined::Created(_) => {
                    self.counts.bump(|c| &mut c.jobs_created);
                    NakOutcome::Queued
                }
                Joined::Joined(_) => {
                    self.counts.bump(|c| &mut c.jobs_joined);
                    NakOutcome::Queued
                }
                Joined::Lingering => {
                    self.counts.bump(|c| &mut c.lingering);
                    NakOutcome::Dropped
                }
                Joined::Full => {
                    self.counts.bump(|c| &mut c.jobs_full);
                    NakOutcome::Dropped
                }
            },
        }
    }

    /// Serves its pending jobs on `tx` within `budget`, which it spends
    /// (bytes and word 0 loads), reading `readers` below each lane's NAK
    /// bound in `sent_high`, at `now`. A lane in `closed` (its guard closed:
    /// nothing more leaves the sender, GC-6) reads nothing: its jobs are
    /// dropped, with no ERR. Returns the DRR report.
    pub fn serve<O: SocketOps, T: StreamTerms>(
        &mut self,
        tx: &mut SocketsTx<O>,
        readers: &mut [LaneReader<T>],
        (sent_high, closed): (&[u64], &[bool]),
        budget: &mut RepairBudget,
        now: u64,
    ) -> Report {
        let mut read = ReadView {
            readers,
            sent_high,
            closed,
            scratch: &self.scratch,
            loads: budget.loads,
        };
        let mut submit = SubmitView {
            tx,
            queue: self.queue,
            scratch: &self.scratch,
            report: &mut self.report,
            admission: &mut self.admission,
            replies: &mut self.replies,
            max_replies: self.max_replies,
            alias: self.alias,
            identity: self.identity,
            counts: &mut self.counts,
            now,
        };
        let report = self
            .scheduler
            .serve(&mut self.jobs, *budget, &mut read, &mut submit, now);
        // Served bytes never exceed the budget the call was given.
        let bytes = report.lanes.iter().try_fold(0u64, |sum, lane| {
            sum.checked_add(lane.served_bytes)?
                .checked_add(lane.uncertain_bytes)
        });
        budget.bytes = bytes
            .and_then(|bytes| budget.bytes.checked_sub(bytes))
            .unwrap_or(0);
        budget.loads = read.loads;
        report
    }

    /// The step 8 ERRs waiting to be sent, in order; `send` gets each.
    pub fn drain_replies(&mut self, mut send: impl FnMut(&NakReply)) {
        for reply in self.replies.drain(..) {
            send(&reply);
        }
    }
}

/// The lane reads of one call.
struct ReadView<'a, T: StreamTerms> {
    readers: &'a mut [LaneReader<T>],
    sent_high: &'a [u64],
    /// Lanes whose guard closed.
    closed: &'a [bool],
    scratch: &'a RefCell<Scratch>,
    /// Word 0 loads left in the cycle.
    loads: u32,
}

impl<T: StreamTerms> RepairRead for ReadView<'_, T> {
    fn head(&mut self, lane: u8, from: u64) -> Result<Head, RepairReadError> {
        let index = usize::from(lane);
        if self.closed.get(index).copied().unwrap_or(false) {
            return Err(RepairReadError::Retry);
        }
        let (Some(reader), Some(bound)) = (
            self.readers.get_mut(index),
            self.sent_high.get(index).copied(),
        ) else {
            return Err(RepairReadError::BadRequest);
        };
        let Ok(mut scratch) = self.scratch.try_borrow_mut() else {
            return Err(RepairReadError::Retry);
        };
        scratch.staged = None;
        let (result, used) = reader.read_nak(
            from,
            NakRead {
                bound,
                loads: self.loads,
            },
            &mut scratch.bytes,
        );
        self.loads = match self.loads.checked_sub(used) {
            Some(left) => left,
            // Never: a read spends at most what it was given. The call's
            // loads end here.
            None => {
                debug_assert!(false, "a NAK read spent {used} of {} loads", self.loads);
                0
            }
        };
        let (len, head) = match result {
            Ok(ReadOutcome::Copied { len, next }) => {
                let aligned = u32::try_from(len)
                    .ok()
                    .and_then(|len| align_frame(len).ok())
                    .ok_or(RepairReadError::TooSmall)?;
                (
                    len,
                    Head::Data {
                        aligned: u64::from(aligned),
                        next,
                    },
                )
            }
            Ok(ReadOutcome::Canonical { next, .. }) => (32, Head::Record { next }),
            Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => {
                return Err(RepairReadError::Retry);
            }
            Err(ReadError::BadRequest) => return Err(RepairReadError::BadRequest),
            Err(ReadError::Budget) => return Err(RepairReadError::Budget),
            Err(ReadError::Unavailable { lowest }) => {
                return Err(RepairReadError::Unavailable { lowest });
            }
            Err(ReadError::Revoked) => return Err(RepairReadError::Revoked),
            Err(ReadError::CorruptTerm { .. }) => return Err(RepairReadError::CorruptTerm),
            Err(ReadError::TooSmall { .. }) => return Err(RepairReadError::TooSmall),
            // A faulted lane or a broken invariant: dropped, no ERR.
            Err(_) => return Err(RepairReadError::Retry),
        };
        scratch.staged = Some((lane, from, len));
        Ok(head)
    }

    fn floor(&self, lane: u8) -> u64 {
        self.readers
            .get(usize::from(lane))
            .map_or(0, LaneReader::<T>::floor)
    }
}

/// The repair queue and the ERR list of one call.
struct SubmitView<'a, O: SocketOps> {
    tx: &'a mut SocketsTx<O>,
    queue: Option<TxQueueId>,
    scratch: &'a RefCell<Scratch>,
    report: &'a mut TxReport,
    admission: &'a mut Admission,
    replies: &'a mut Vec<NakReply>,
    max_replies: usize,
    alias: Alias,
    identity: Identity,
    counts: &'a mut RepairCounts,
    now: u64,
}

/// The gate of repair traffic: every candidate is permitted. A guarded
/// publication's close holds its repairs before this gate: the lanes in
/// `closed`, read from a fresh load of the guard word each cycle, read
/// nothing (GC-6).
struct RepairGate;

impl SenderGate for RepairGate {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        match u16::try_from(candidate.tokens.len())
            .ok()
            .and_then(NonZeroU16::new)
        {
            Some(count) => GateDecision::Permit { count },
            None => GateDecision::Deny,
        }
    }
}

impl<O: SocketOps> SubmitView<'_, O> {
    /// Returns what the repair queue still holds after a flush; `false`
    /// when the queue could not be emptied.
    fn cancel(&mut self, queue: TxQueueId) -> bool {
        while self.report.pop_front().is_some() {}
        loop {
            match self.tx.cancel_pending(queue, self.report) {
                Ok(outcome) => {
                    while self.report.pop_front().is_some() {
                        self.counts.bump(|c| &mut c.cancelled);
                    }
                    if !outcome.more {
                        return true;
                    }
                }
                Err(_) => return false,
            }
        }
    }
}

impl<O: SocketOps> RepairSubmit for SubmitView<'_, O> {
    fn submit(&mut self, lane: u8, _job: JobRef, from: u64, _head: Head) -> Submit {
        let Some(queue) = self.queue else {
            return Submit::Broken;
        };
        let Ok(scratch) = self.scratch.try_borrow() else {
            return Submit::Broken;
        };
        let Some((staged_lane, staged_from, len)) = scratch.staged else {
            self.counts.bump(|c| &mut c.unstaged);
            return Submit::Broken;
        };
        if (staged_lane, staged_from) != (lane, from) {
            self.counts.bump(|c| &mut c.unstaged);
            return Submit::Broken;
        }
        let Some(bytes) = scratch.bytes.get(..len) else {
            return Submit::Broken;
        };
        let mut frame = match self.tx.claim_tx(queue, len) {
            Ok(frame) => frame,
            Err(
                ClaimError::QueueFull { .. }
                | ClaimError::PoolExhausted
                | ClaimError::IdentityExhausted,
            ) => return Submit::NoRoom,
            Err(_) => return Submit::Broken,
        };
        let Some(target) = frame.bytes_mut().get_mut(..len) else {
            return Submit::Broken;
        };
        target.copy_from_slice(bytes);
        drop(scratch);
        if frame
            .commit(Commit {
                len,
                token: SenderToken::new(0),
                options: TxOptions::none(),
            })
            .is_err()
        {
            return Submit::NotSubmitted;
        }
        let _ = self.tx.flush(
            FlushRequest {
                queue,
                max_datagrams: NonZeroU16::MIN,
                max_bytes: u32::MAX,
            },
            &mut RepairGate,
            self.report,
        );
        let mut outcome = None;
        while let Some(entry) = self.report.pop_front() {
            outcome = Some(entry.outcome);
        }
        match outcome {
            Some(TxItemOutcome::Submitted { .. }) => {
                self.counts.bump(|c| &mut c.submitted);
                Submit::Submitted
            }
            Some(TxItemOutcome::Returned { .. }) => Submit::NotSubmitted,
            Some(TxItemOutcome::Unknown) => Submit::Uncertain,
            // Not taken now: cancelled, so no stale repair waits; the job
            // keeps its cursor. A queue left faulted is retried.
            Some(TxItemOutcome::Pending { cause }) => {
                if !self.cancel(queue) {
                    return Submit::Broken;
                }
                if matches!(cause, PendingCause::Faulted(_)) && self.tx.retry_queue(queue).is_err()
                {
                    return Submit::Broken;
                }
                Submit::NotSubmitted
            }
            // The flush reported nothing: the backend stopped.
            None => {
                let _ = self.cancel(queue);
                Submit::Broken
            }
        }
    }

    fn reply(&mut self, key: &JobKey, requesters: &[Receiver], reason: NakReplyReason) {
        let Ok(lane) = Lane::try_new(key.lane) else {
            return;
        };
        for receiver in requesters {
            let nak = Nak {
                alias: self.alias,
                identity: self.identity,
                receiver: *receiver,
                range: NakRange {
                    lane,
                    length: key.length,
                    start: key.start,
                },
            };
            if let Admitted::Reply(reply) = self.admission.reply_to(&nak, reason, self.now) {
                if self.replies.len() < self.max_replies {
                    self.replies.push(reply);
                } else {
                    self.counts.bump(|c| &mut c.replies_full);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
