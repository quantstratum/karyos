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
use karyos_io::lanes::routes::MAX_ROUTES;
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::frame::{FRAME_ALIGNMENT, Lane};
use karyos_protocol::lanes::drr::{DrrConfig, Report};
use karyos_protocol::network::{
    Alias, Identity, Nak, NakRange, NakReply, NakReplyReason, Receiver,
};
use karyos_sys::log_buffer::{NakRead, ReadError, ReadOutcome};
use karyos_sys::sizing::align_frame;

use super::data::LaneReader;
use crate::embedded::StreamTerms;
use crate::repair::absorb::{Absorb, AbsorbCounts, CopyKey};
use crate::repair::admission::{Admission, AdmissionError, Admitted, NakContext, Requester};
use crate::repair::jobs::{Domain, JobKey, JobRef, Jobs, JobsConfig, JobsError, Joined};
use crate::repair::scheduler::{
    Head, RepairBudget, RepairRead, RepairReadError, RepairSubmit, Scheduler, Submit,
};
use crate::wire_enc::DatagramSeal;

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
    /// How far below its sent position a reliable publication keeps its
    /// lanes for repair, in bytes: the retention floor at `sent -
    /// retransmit_window`, lowered only by required receivers (SPEC §4,
    /// §6; quantstratum-docs:
    /// karyos/design/retention-floor-optional-receivers.md). `None`, the
    /// default, is half a term, which is also the most: a counted
    /// receiver's window is at most half a term, so its holes stay above
    /// the floor. A smaller window can lose data even for a counted
    /// receiver, reported as unrecoverable. A channel's `retransmit-window`
    /// overrides it for that channel.
    pub retransmit_window: Option<u32>,
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
            retransmit_window: None,
        }
    }
}

/// Why a repair path could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
    /// A multi-destination publication's job table holds less than one job
    /// per destination: MD-8 gives each its share, `repair_jobs /
    /// max_destinations`, of at least 1.
    #[error("repair_jobs {repair_jobs} is below one job for each of {destinations} destinations")]
    DestinationShare {
        /// The configured `repair_jobs`.
        repair_jobs: usize,
        /// The most destinations of the publication.
        destinations: usize,
    },
    /// Another of a multi-destination publication's repair tables holds
    /// less than one entry per destination: each destination gets its
    /// share, `value / max_destinations`, of at least 1, so the tables of
    /// every destination together stay within the configured one
    /// (karyos#802).
    #[error("{table} {value} is below one entry for each of {destinations} destinations")]
    TableShare {
        /// The table: `err_linger_entries`, `repair_linger_entries` or
        /// `replies`.
        table: &'static str,
        /// Its configured size.
        value: usize,
        /// The most destinations of the publication.
        destinations: usize,
    },
    /// A `retransmit_window` of zero, above half the term, or not
    /// frame-aligned.
    #[error("retransmit_window must be frame-aligned, nonzero and at most half a term")]
    RetransmitWindow,
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
    /// Catch-up jobs created after an endpoint reset (MD-20, karyos#802).
    pub catch_ups: u64,
    /// Catch-up jobs that found the destination's job share full: they
    /// wait and are tried again.
    pub catch_ups_full: u64,
    /// Bytes a catch-up could not repair, being below the retention floor:
    /// lost for the destination, as a NAK for them would be.
    pub catch_up_lost: u64,
    /// An increment did not apply (sticky).
    pub overflowed: bool,
}

/// What a sender-initiated catch-up did (MD-20, karyos#802).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchUp {
    /// A job covers the range from `from` (its start past the floor) up
    /// to `through`. What it submits moves
    /// [`RepairPath::catch_up_through`]; once it ends, done or refused, the
    /// rest of the range starts there, never at `through` (karyos#890
    /// review).
    Queued {
        /// Where the job starts.
        from: u64,
        /// The end of what the job covers.
        through: u64,
        /// The job, to know when it ends.
        job: crate::repair::jobs::JobRef,
    },
    /// The destination's job share is full: try again from `from`, the
    /// range's start past the floor, so a lost prefix is counted once.
    Full {
        /// Where the range now starts.
        from: u64,
    },
    /// Nothing left to repair (the range was empty or below the floor).
    Done,
}

/// What a repair path counted on one route of a routed publication
/// (RP-11): each repair datagram goes on every live route.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteRepairCounts {
    /// Repair datagrams submitted on the route.
    pub submitted: u64,
    /// Repair datagrams the route skipped: no room, a known failure or a
    /// broken queue. Its receivers ask again by NAK.
    pub skipped: u64,
    /// Repair datagrams whose exposure on the route is unknown.
    pub uncertain: u64,
    /// An increment did not apply (sticky).
    pub overflowed: bool,
}

impl RouteRepairCounts {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64) {
        let count = field(self);
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => self.overflowed = true,
        }
    }
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
    /// Its length already leaves room for an envelope.
    reserved: bool,
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
    /// The repair queue of each route's current endpoint epoch; one path
    /// uses route 0.
    queues: [Option<TxQueueId>; MAX_ROUTES],
    /// What each route counted.
    route_counts: [RouteRepairCounts; MAX_ROUTES],
    /// The absorption of NAK copies across routes; empty on one path.
    absorb: Absorb,
    /// Step 8 ERRs waiting for the sender agent (allocated here).
    replies: Vec<(NakReply, usize)>,
    max_replies: usize,
    /// The incarnation's term length.
    term_length: u32,
    /// [`RepairConfig::retransmit_window`], resolved for that term.
    retransmit_window: u32,
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
        let half = term_length / 2;
        let retransmit_window = config.retransmit_window.unwrap_or(half);
        if retransmit_window == 0
            || retransmit_window > half
            || !retransmit_window.is_multiple_of(FRAME_ALIGNMENT)
        {
            return Err(RepairConfigError::RetransmitWindow);
        }
        Ok(Self {
            admission: Admission::new(config.nak_reply_linger, config.err_linger_entries)?,
            jobs: Jobs::new(config.jobs)?,
            scheduler: Scheduler::new(drr),
            scratch: RefCell::new(Scratch {
                bytes: vec![0; mtu],
                reserved: false,
                staged: None,
            }),
            queues: [None; MAX_ROUTES],
            route_counts: [RouteRepairCounts::default(); MAX_ROUTES],
            absorb: Absorb::new(0, 0),
            replies: Vec::with_capacity(config.replies),
            max_replies: config.replies,
            term_length,
            retransmit_window,
            alias,
            identity,
            report: TxReport::new(),
            counts: RepairCounts::default(),
        })
    }

    /// Takes the publication's fresh incarnation identity, which its
    /// later ERRs carry (ADR-0114 section 10 step 3).
    pub(crate) fn set_identity(&mut self, identity: Identity) {
        self.identity = identity;
    }

    /// The incarnation identity its ERRs carry (tests).
    #[cfg(test)]
    pub(crate) fn identity(&self) -> Identity {
        self.identity
    }

    /// How far below the sent position its lanes stay repairable
    /// ([`RepairConfig::retransmit_window`]).
    #[must_use]
    pub fn retransmit_window(&self) -> u32 {
        self.retransmit_window
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

    /// The repair queue of the current endpoint epoch (route 0).
    #[must_use]
    pub fn queue(&self) -> Option<TxQueueId> {
        self.queue_on(0)
    }

    /// The repair queue of `route`'s current endpoint epoch.
    #[must_use]
    pub fn queue_on(&self, route: usize) -> Option<TxQueueId> {
        self.queues.get(route).copied().flatten()
    }

    /// What `route` counted; `None` past [`MAX_ROUTES`].
    #[must_use]
    pub fn route_counts(&self, route: usize) -> Option<RouteRepairCounts> {
        self.route_counts.get(route).copied()
    }

    /// Counts `count` repair datagrams that `route`, in the live set but
    /// unable to take repairs, skipped.
    pub fn count_skipped(&mut self, route: usize, count: u32) {
        if let Some(counts) = self.route_counts.get_mut(route) {
            match counts.skipped.checked_add(u64::from(count)) {
                Some(total) => counts.skipped = total,
                None => counts.overflowed = true,
            }
        }
    }

    /// A sender-initiated catch-up of `lane` over `[start, end)` after its
    /// destination's endpoint reset (MD-20, karyos#802): one job in the
    /// destination's share, no admission and no ERR. The part below
    /// `floor`, the lane's retention floor, cannot be repaired and is
    /// counted lost; a full share leaves the range to try again.
    pub fn catch_up(&mut self, lane: u8, (start, end): (u64, u64), floor: u64) -> CatchUp {
        let from = start.max(floor);
        if from > start {
            let lost = from.min(end).saturating_sub(start);
            match self.counts.catch_up_lost.checked_add(lost) {
                Some(next) => self.counts.catch_up_lost = next,
                None => self.counts.overflowed = true,
            }
        }
        if from >= end {
            return CatchUp::Done;
        }
        let length = u32::try_from(end.saturating_sub(from)).unwrap_or(u32::MAX);
        match self.jobs.create_catch_up(lane, from, length) {
            Joined::Created(job) | Joined::Joined(job) => {
                self.counts.bump(|c| &mut c.catch_ups);
                CatchUp::Queued {
                    from,
                    through: from.saturating_add(u64::from(length)),
                    job,
                }
            }
            Joined::Lingering | Joined::Full => {
                self.counts.bump(|c| &mut c.catch_ups_full);
                CatchUp::Full { from }
            }
        }
    }

    /// Restarts `lane`'s catch-up watermark at `at`
    /// ([`crate::repair::jobs::Jobs::restart_catch_up`]): the next job's
    /// progress alone moves it from there.
    pub fn restart_catch_up(&mut self, lane: u8, at: u64) {
        self.jobs.restart_catch_up(lane, at);
    }

    /// Whether catch-up `job` is still pending: not done, refused nor
    /// dropped.
    #[must_use]
    pub fn catch_up_pending(&self, job: crate::repair::jobs::JobRef) -> bool {
        self.jobs.current(job)
    }

    /// The end of what its catch-up jobs have submitted on `lane`, 0 for
    /// none (MD-20): moved only by a backend submission.
    #[must_use]
    pub fn catch_up_through(&self, lane: u8) -> u64 {
        self.jobs.catch_up_through(lane)
    }

    /// Fills its step 8 reply list with `reply` up to its bound, as a
    /// cycle of failed jobs would (tests of the shares, karyos#802); how
    /// many it holds.
    #[cfg(test)]
    pub(crate) fn fill_replies(&mut self, reply: NakReply) -> usize {
        while self.replies.len() < self.max_replies {
            self.replies.push((reply, 0));
        }
        self.replies.len()
    }

    /// The endpoint epoch changed: `queue` is the new repair queue (or none
    /// could be opened). Nothing staged in the old one survives.
    pub fn reopened(&mut self, queue: Option<TxQueueId>) {
        self.reopened_route(0, queue);
    }

    /// [`RepairPath::reopened`] for `route` of a routed publication.
    pub fn reopened_route(&mut self, route: usize, queue: Option<TxQueueId>) {
        if let Some(slot) = self.queues.get_mut(route) {
            *slot = queue;
        }
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
        self.nak_on(
            nak,
            (requester, 0, true),
            reader,
            sent_high,
            lane_count,
            now,
        )
    }

    /// [`RepairPath::nak`] for a NAK that arrived on route `route`: one
    /// that creates or joins a job is recorded for absorbing its copies on
    /// the other routes ([`RepairPath::absorbs`]).
    pub fn nak_on<T: StreamTerms>(
        &mut self,
        nak: &Nak,
        (requester, route, validated): (Requester, usize, bool),
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
            Admitted::Pass(request) => {
                match self
                    .jobs
                    .join_or_create_on(&request, Domain::Group, route, now)
                {
                    Joined::Created(_) => {
                        self.counts.bump(|c| &mut c.jobs_created);
                        if validated {
                            self.absorb.record(&copy_key(nak), route, now);
                        }
                        NakOutcome::Queued
                    }
                    Joined::Joined(_) => {
                        self.counts.bump(|c| &mut c.jobs_joined);
                        if validated {
                            self.absorb.record(&copy_key(nak), route, now);
                        }
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
                }
            }
        }
    }

    /// Whether [`Self::nak_on`] would queue or answer `nak` (an outcome
    /// other than a drop), in the same context, changing nothing: a domain
    /// 4 open decides with it before the NAK's sequence is marked or an
    /// epoch promoted (H8-24).
    #[must_use]
    pub fn would_take<T: StreamTerms>(
        &self,
        nak: &Nak,
        requester: Requester,
        reader: Option<&LaneReader<T>>,
        sent_high: u64,
        lane_count: u8,
        now: u64,
    ) -> bool {
        let ctx = NakContext {
            reliable: true,
            lane_count,
            requester,
            floor: reader.map_or(0, LaneReader::<T>::floor),
            nak_bound: sent_high,
            term_length: self.term_length,
        };
        match self.admission.would_admit(nak, &ctx, now) {
            Admitted::Dropped(_) => false,
            Admitted::Reply(_) => true,
            Admitted::Pass(request) => self.jobs.would_take(&request, Domain::Group, now),
        }
    }

    /// Whether `nak` on route `route` at `now` is a copy of a NAK another
    /// route carried within `path_skew_window` (RP-11). It is decided on
    /// the validated receiver and the exact interval, before the NAK
    /// budget, so an absorbed copy spends none.
    pub fn absorbs(&mut self, nak: &Nak, route: usize, now: u64) -> bool {
        self.absorb.absorbs(&copy_key(nak), route, now)
    }

    /// Sizes the absorption of NAK copies for a routed publication:
    /// `entries` (`path_copy_entries`) over `window` ns
    /// (`path_skew_window`). It allocates; called when the publication is
    /// added, never in a duty cycle.
    pub fn set_absorb(&mut self, entries: usize, window: u64) {
        self.absorb = Absorb::new(entries, window);
    }

    /// What its absorption of NAK copies counted.
    #[must_use]
    pub fn absorb_counts(&self) -> AbsorbCounts {
        self.absorb.counts()
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
        limits: (&[u64], &[bool]),
        budget: &mut RepairBudget,
        now: u64,
    ) -> Report {
        self.serve_routes(&mut [Some(tx)], readers, limits, budget, now, None)
    }

    /// Leaves room for an envelope of `envelope` bytes in every repair
    /// datagram: reads stop that much short of the MTU, so a sealed repair
    /// stays within it (ADR-0086 section 5). Allocates nothing; once is
    /// enough.
    pub(crate) fn reserve_envelope(&mut self, envelope: usize) {
        if let Ok(mut scratch) = self.scratch.try_borrow_mut()
            && !scratch.reserved
        {
            let inner = scratch.bytes.len().saturating_sub(envelope);
            scratch.bytes.truncate(inner);
            scratch.reserved = true;
        }
    }

    /// [`RepairPath::serve`] over the live routes of a routed publication
    /// (RP-11): `routes` holds, by route, the TX half of each live route
    /// (`None` for one out of the live set or not open). Each repair
    /// datagram is read once and submitted on every one of them, debited
    /// once, at its first submission; a route that cannot take it skips
    /// it, counted, and its receivers ask again by NAK. The job completes
    /// once every live route has submitted or skipped each datagram. An
    /// authenticated publication passes its `seal`: each copy is sealed in
    /// its own TX frame, under a fresh envelope sequence (ADR-0086 section
    /// 6), never on the shared read.
    pub fn serve_routes<O: SocketOps, T: StreamTerms>(
        &mut self,
        routes: &mut [Option<&mut SocketsTx<O>>],
        readers: &mut [LaneReader<T>],
        (sent_high, closed): (&[u64], &[bool]),
        budget: &mut RepairBudget,
        now: u64,
        seal: Option<&mut (dyn DatagramSeal + 'static)>,
    ) -> Report {
        let mut read = ReadView {
            readers,
            sent_high,
            closed,
            scratch: &self.scratch,
            loads: budget.loads,
        };
        let mut submit = SubmitView {
            routes,
            seal,
            queues: self.queues,
            route_counts: &mut self.route_counts,
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

    /// Cancels its pending repair jobs and the step 8 ERRs not sent yet,
    /// with no outcome: the incarnation is aborting (guards-and-abort.md,
    /// Session abort, sender step 2). Datagrams already handed to the
    /// backend are untouched, so their storage leases are kept until the
    /// backend releases them. Returns the jobs cancelled.
    pub fn cancel_pending(&mut self) -> u64 {
        self.replies.clear();
        self.jobs.cancel_all()
    }

    /// The step 8 ERRs waiting to be sent, in order; `send` gets each.
    pub fn drain_replies(&mut self, mut send: impl FnMut(&NakReply)) {
        self.drain_replies_on(|reply, _| send(reply));
    }

    /// [`RepairPath::drain_replies`] with each ERR's route: the one its
    /// requester asked on (0 on one path).
    pub fn drain_replies_on(&mut self, mut send: impl FnMut(&NakReply, usize)) {
        for (reply, route) in self.replies.drain(..) {
            send(&reply, route);
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
    fn head(&mut self, lane: u8, from: u64, end: Option<u64>) -> Result<Head, RepairReadError> {
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
        // Only the frames the request covers: a datagram read past its end
        // would repeat frames the receiver has.
        let room = end
            .and_then(|end| end.checked_sub(from))
            .and_then(|room| usize::try_from(room).ok())
            .map_or(scratch.bytes.len(), |room| room.min(scratch.bytes.len()));
        let bounded = room < scratch.bytes.len();
        let Some(out) = scratch.bytes.get_mut(..room) else {
            return Err(RepairReadError::TooSmall);
        };
        let (result, used) = reader.read_nak(
            from,
            NakRead {
                bound,
                loads: self.loads,
            },
            out,
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
            // The request ends inside the frame at `from`: it names no
            // whole frame there, so it is refused as a range, as before the
            // read was bounded.
            Err(ReadError::TooSmall { .. }) if bounded => {
                return Err(RepairReadError::BadRequest);
            }
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

/// The repair queues and the ERR list of one call.
struct SubmitView<'a, 'b, O: SocketOps> {
    /// The live routes' TX halves, by route.
    routes: &'a mut [Option<&'b mut SocketsTx<O>>],
    /// An authenticated publication's sealer.
    seal: Option<&'a mut (dyn DatagramSeal + 'static)>,
    queues: [Option<TxQueueId>; MAX_ROUTES],
    route_counts: &'a mut [RouteRepairCounts; MAX_ROUTES],
    scratch: &'a RefCell<Scratch>,
    report: &'a mut TxReport,
    admission: &'a mut Admission,
    replies: &'a mut Vec<(NakReply, usize)>,
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

/// Returns what the repair queue still holds after a flush; `false` when
/// the queue could not be emptied.
fn cancel<O: SocketOps>(
    tx: &mut SocketsTx<O>,
    queue: TxQueueId,
    report: &mut TxReport,
    counts: &mut RepairCounts,
) -> bool {
    while report.pop_front().is_some() {}
    loop {
        match tx.cancel_pending(queue, report) {
            Ok(outcome) => {
                while report.pop_front().is_some() {
                    counts.bump(|c| &mut c.cancelled);
                }
                if !outcome.more {
                    return true;
                }
            }
            Err(_) => return false,
        }
    }
}

/// Copies `bytes` into `queue` on `tx`, sealed under `seal` when the
/// publication is authenticated, and submits it: one route's submission of
/// a repair datagram.
fn submit_on<O: SocketOps>(
    tx: &mut SocketsTx<O>,
    queue: TxQueueId,
    bytes: &[u8],
    seal: Option<&mut (dyn DatagramSeal + 'static)>,
    report: &mut TxReport,
    counts: &mut RepairCounts,
) -> Submit {
    let frames = bytes.len();
    // A sealer at its usage limit sends nothing; the job keeps its cursor.
    if seal.as_deref().is_some_and(|seal| !seal.can_seal()) {
        return Submit::NotSubmitted;
    }
    let envelope = seal.as_deref().map_or(0, DatagramSeal::envelope);
    let mut frame = match tx.claim_tx(queue, frames + envelope) {
        Ok(frame) => frame,
        Err(
            ClaimError::QueueFull { .. }
            | ClaimError::PoolExhausted
            | ClaimError::IdentityExhausted,
        ) => return Submit::NoRoom,
        Err(_) => return Submit::Broken,
    };
    let Some(target) = frame.bytes_mut().get_mut(..frames) else {
        return Submit::Broken;
    };
    target.copy_from_slice(bytes);
    let len = match seal {
        Some(seal) => match seal.seal_datagram(frame.bytes_mut(), frames) {
            Some(len) => len,
            None => return Submit::NotSubmitted,
        },
        None => frames,
    };
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
    let _ = tx.flush(
        FlushRequest {
            queue,
            max_datagrams: NonZeroU16::MIN,
            max_bytes: u32::MAX,
        },
        &mut RepairGate,
        report,
    );
    let mut outcome = None;
    while let Some(entry) = report.pop_front() {
        outcome = Some(entry.outcome);
    }
    match outcome {
        Some(TxItemOutcome::Submitted { .. }) => Submit::Submitted,
        Some(TxItemOutcome::Returned { .. }) => Submit::NotSubmitted,
        Some(TxItemOutcome::Unknown) => Submit::Uncertain,
        // Not taken now: cancelled, so no stale repair waits; the job keeps
        // its cursor. A queue left faulted is retried.
        Some(TxItemOutcome::Pending { cause }) => {
            if !cancel(tx, queue, report, counts) {
                return Submit::Broken;
            }
            if matches!(cause, PendingCause::Faulted(_)) && tx.retry_queue(queue).is_err() {
                return Submit::Broken;
            }
            Submit::NotSubmitted
        }
        // The flush reported nothing: the backend stopped.
        None => {
            let _ = cancel(tx, queue, report, counts);
            Submit::Broken
        }
    }
}

/// The absorption key of `nak`: its receiver and exact interval.
fn copy_key(nak: &Nak) -> CopyKey {
    CopyKey {
        receiver: nak.receiver,
        lane: nak.range.lane.get(),
        start: nak.range.start,
        length: nak.range.length,
    }
}

/// The rank of a route's outcome in the outcome of a datagram over every
/// live route: one submission submits it; else an unknown exposure is
/// uncertain; else a known failure holds the lane; else no room is
/// backpressure; only every route broken is broken.
fn rank(outcome: Submit) -> u8 {
    match outcome {
        Submit::Submitted => 4,
        Submit::Uncertain => 3,
        Submit::NotSubmitted => 2,
        Submit::NoRoom => 1,
        Submit::Broken => 0,
    }
}

impl<O: SocketOps> RepairSubmit for SubmitView<'_, '_, O> {
    fn submit(&mut self, lane: u8, _job: JobRef, from: u64, _head: Head) -> Submit {
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
        let mut best: Option<Submit> = None;
        for (index, tx) in self.routes.iter_mut().enumerate() {
            let queue = self.queues.get(index).copied().flatten();
            let (Some(tx), Some(queue)) = (tx.as_deref_mut(), queue) else {
                // A lent route whose repair queue did not open skips it.
                if tx.is_some()
                    && let Some(counts) = self.route_counts.get_mut(index)
                {
                    counts.bump(|c| &mut c.skipped);
                }
                continue;
            };
            let outcome = submit_on(
                tx,
                queue,
                bytes,
                self.seal.as_deref_mut(),
                self.report,
                self.counts,
            );
            if let Some(counts) = self.route_counts.get_mut(index) {
                match outcome {
                    Submit::Submitted => counts.bump(|c| &mut c.submitted),
                    Submit::Uncertain => counts.bump(|c| &mut c.uncertain),
                    Submit::NotSubmitted | Submit::NoRoom | Submit::Broken => {
                        counts.bump(|c| &mut c.skipped);
                    }
                }
            }
            best = Some(match best {
                Some(held) if rank(held) >= rank(outcome) => held,
                _ => outcome,
            });
        }
        // No live route with a repair queue: as one path without one.
        let outcome = best.unwrap_or(Submit::Broken);
        if outcome == Submit::Submitted {
            self.counts.bump(|c| &mut c.submitted);
        }
        outcome
    }

    fn reply(
        &mut self,
        key: &JobKey,
        requesters: &[Receiver],
        routes: &[usize],
        reason: NakReplyReason,
    ) {
        let Ok(lane) = Lane::try_new(key.lane) else {
            return;
        };
        for (at, receiver) in requesters.iter().enumerate() {
            // One ERR, on the route the requester asked on (RP-11).
            let route = routes.get(at).copied().unwrap_or(0);
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
                    self.replies.push((reply, route));
                } else {
                    self.counts.bump(|c| &mut c.replies_full);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
