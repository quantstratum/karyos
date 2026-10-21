// SPDX-License-Identifier: Apache-2.0

//! Lane selection at backend submission (`quantstratum-docs:
//! karyos/design/lane-sender.md`, P2.4 l2): a DRR sender over one TX queue
//! per lane of one route.
//!
//! Packetization commits a lane's datagrams to its own queue ahead of time
//! and records each one here with [`LaneSender::staged`]: staged work moves
//! no sent position and consumes no credit. [`LaneSender::serve`] runs the
//! DRR of `karyos_protocol::lanes::drr`, whose `serve` step flushes exactly
//! the selected lane's head (`max_datagrams = 1`, `max_bytes` its committed
//! length). Only an item the backend reports `Submitted` is service; an
//! `Unknown` item is uncertain: not debited, charged to the byte budget, and
//! its lane suspended until the control path resolves it
//! ([`LaneSender::needs_control`] reports the suspension).
//!
//! Every allocation happens in [`LaneSender::new`]; the data calls do not
//! allocate.

use std::collections::VecDeque;

use core::num::NonZeroU16;

use karyos_protocol::lanes::drr::{
    Budget, Drr, DrrConfig, DrrError, LaneSource, Probe, Report, Service, Stop,
};

use crate::backend::{
    BackendFailure, FlushRequest, FlushStop, PendingCause, QueueError, SenderGate, TxBackend,
    TxItemOutcome, TxQueueId, TxReport, TxTicket,
};

/// The driver's gate for a lane sender: the exposure-time
/// [`SenderGate`], and the same rule asked by the probe, so a lane whose
/// guard, lifecycle or flow window is closed is ineligible before any
/// flush (lane-sender.md, "Probe").
pub trait LaneGate: SenderGate {
    /// Whether `lane` may send its head now.
    fn admits(&mut self, lane: usize) -> bool;

    /// The sender is about to flush `lane`'s head: the next
    /// [`SenderGate::check`] is that lane's exposure, so a gate need not
    /// place it by its tokens, which need not be unique across lanes.
    fn flushing(&mut self, lane: usize) {
        let _ = lane;
    }

    /// Whether `lane` is aborting for good in this gate (its guard closed,
    /// a sender fault): a gate that wraps this one must not then declare
    /// another end for the lane, such as a missed deadline
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`, G7: the
    /// loser of a close against a deadline changes nothing).
    fn aborting(&self, lane: usize) -> bool {
        let _ = lane;
        false
    }

    /// `lane`'s head left its queue, reported `how`: the gate's own record
    /// of the head moves on with the sender's. A head the backend keeps
    /// pending is not reported; it is exposed again, through the gate.
    fn left(&mut self, lane: usize, staged: Staged, how: Left) {
        let _ = (lane, staged, how);
    }
}

/// How a staged head left its queue ([`LaneGate::left`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Left {
    /// The backend submitted it.
    Submitted,
    /// It left without exposure.
    Returned,
    /// Its exposure is unproven: it may have been sent.
    Unknown,
}

/// One datagram committed to a lane's queue and not yet reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Staged {
    /// Its ticket.
    pub ticket: TxTicket,
    /// Its DRR charge: the aligned lengths of the frames it carries.
    pub charge: u64,
    /// Its committed length in bytes: the flush's `max_bytes`.
    pub len: u16,
}

/// Why [`LaneSender::staged`] refused a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StageError {
    /// No such lane.
    #[error("no lane {lane}")]
    UnknownLane {
        /// The lane named.
        lane: usize,
    },
    /// The lane already records its queue's bound.
    #[error("lane {lane} is full")]
    Full {
        /// The lane named.
        lane: usize,
    },
    /// The charge is zero or above the sender's largest datagram charge.
    #[error("charge {charge} outside 1..={max}")]
    InvalidCharge {
        /// The charge given.
        charge: u64,
        /// The largest charge.
        max: u64,
    },
    /// The committed length exceeds the charge (lane-sender.md: the charge
    /// is the aligned length of the frames the datagram carries).
    #[error("length {len} above charge {charge}")]
    LengthAboveCharge {
        /// The committed length.
        len: u16,
        /// The charge given.
        charge: u64,
    },
    /// A routed copy's position is not above the route's last copy
    /// ([`routes::RoutedLaneSender::staged`]).
    #[error("lane {lane}: copy out of position order")]
    OutOfOrder {
        /// The lane named.
        lane: usize,
    },
}

/// A call that could not go on: the queue, the half or the sender itself
/// is broken, and the control path must act (lane-sender.md, outcome
/// table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderFailure {
    /// The DRR refused a step.
    Drr(DrrError),
    /// The backend reported a fault or failure for `lane`'s head:
    /// `Pending { Faulted | Failed }` or `FlushStop::Failed`.
    Backend {
        /// The lane flushed.
        lane: usize,
        /// The flush's stop.
        stop: FlushStop,
    },
    /// The flush contradicted what the sender knows: `QueueEmpty`,
    /// `HeadExceedsBudget`, `NotAttempted` with one datagram, or a report
    /// entry for another ticket.
    Invariant {
        /// The lane flushed.
        lane: usize,
        /// The flush's stop.
        stop: FlushStop,
    },
    /// A sender bug: `ReportNotEmpty` or `GateError`.
    Sender {
        /// The lane flushed.
        lane: usize,
        /// The flush's stop.
        stop: FlushStop,
    },
}

/// What one [`LaneSender::serve`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderReport {
    /// The DRR's report: confirmed service, credits, forfeits and
    /// uncertain bytes per lane.
    pub drr: Report,
    /// Set when the call stopped on a failure.
    pub failure: Option<SenderFailure>,
    /// The endpoint was resetting or retired (`Queue(NotActive)`): every
    /// lane was ineligible for the rest of the call. Backpressure is the
    /// DRR's own stop, `Stop::Backpressure`.
    pub inactive: bool,
}

#[derive(Debug)]
struct Lane {
    queue: TxQueueId,
    staged: VecDeque<Staged>,
    bound: usize,
    /// An uncertain item awaits the control path.
    suspended: bool,
    /// The queue is faulted, closed or without its route: ineligible until
    /// the control path reopens it ([`LaneSender::reopen`]).
    control: bool,
    /// Ineligible for the rest of the current call.
    paused: bool,
}

/// A DRR sender over one TX queue per lane of one route.
#[derive(Debug)]
pub struct LaneSender {
    drr: Drr,
    lanes: Vec<Lane>,
    max_charge: u64,
    report: TxReport,
}

impl LaneSender {
    /// A sender of `config`'s lanes over `queues`, one per lane in lane
    /// order, each recording at most `bound` staged datagrams (its queue's
    /// `max_pending`). Allocates every buffer it will use.
    ///
    /// # Errors
    ///
    /// Returns [`DrrError::InvalidConfig`] when `queues` does not name one
    /// queue per configured lane.
    pub fn new(config: DrrConfig, queues: &[TxQueueId], bound: usize) -> Result<Self, DrrError> {
        if queues.len() != config.lanes() {
            return Err(DrrError::InvalidConfig);
        }
        let max_charge = config.max_charge();
        let lanes = queues
            .iter()
            .map(|&queue| Lane {
                queue,
                staged: VecDeque::with_capacity(bound),
                bound,
                suspended: false,
                control: false,
                paused: false,
            })
            .collect();
        Ok(Self {
            drr: Drr::new(config),
            lanes,
            max_charge,
            report: TxReport::new(),
        })
    }

    /// The DRR state, for diagnostics.
    #[must_use]
    pub fn drr(&self) -> &Drr {
        &self.drr
    }

    /// Records a datagram the packetizer committed to `lane`'s queue, at its
    /// tail. Staged work is not service: it moves no position and no credit.
    ///
    /// # Errors
    ///
    /// See [`StageError`]; nothing is recorded on error.
    pub fn staged(&mut self, lane: usize, staged: Staged) -> Result<(), StageError> {
        if staged.charge == 0 || staged.charge > self.max_charge {
            return Err(StageError::InvalidCharge {
                charge: staged.charge,
                max: self.max_charge,
            });
        }
        if u64::from(staged.len) > staged.charge {
            return Err(StageError::LengthAboveCharge {
                len: staged.len,
                charge: staged.charge,
            });
        }
        let entry = self
            .lanes
            .get_mut(lane)
            .ok_or(StageError::UnknownLane { lane })?;
        if entry.staged.len() >= entry.bound {
            return Err(StageError::Full { lane });
        }
        entry.staged.push_back(staged);
        Ok(())
    }

    /// Staged datagrams of `lane` not yet reported.
    #[must_use]
    pub fn pending(&self, lane: usize) -> Option<usize> {
        self.lanes.get(lane).map(|entry| entry.staged.len())
    }

    /// Whether `lane` is suspended on an uncertain item.
    #[must_use]
    pub fn suspended(&self, lane: usize) -> Option<bool> {
        self.lanes.get(lane).map(|entry| entry.suspended)
    }

    /// Whether `lane` waits for the control path: an uncertain item, or a
    /// faulted, closed or unrouted queue.
    #[must_use]
    pub fn needs_control(&self, lane: usize) -> Option<bool> {
        self.lanes
            .get(lane)
            .map(|entry| entry.suspended || entry.control)
    }

    /// The control path cleared `lane`'s send fault with `retry_queue`: the
    /// same queue keeps its pending items, so the lane keeps its staged
    /// records and its faulted head is tried again, after a fresh gate
    /// check. An invariant fault or an uncertain item needs
    /// [`LaneSender::reopen`] after a reset instead.
    pub fn retry(&mut self, lane: usize) {
        if let Some(entry) = self.lanes.get_mut(lane) {
            entry.control = false;
        }
    }

    /// The control path gave `lane` a new `queue`, after an endpoint reset
    /// (which returned every pending item and closed every queue) or after
    /// `close_queue`. The lane's staged records are dropped: the packetizer
    /// stages again from the first position not confirmed submitted (a
    /// resend on a reliable channel), or the session reports the uncertain
    /// range as a gap (an unreliable one).
    pub fn reopen(&mut self, lane: usize, queue: TxQueueId) {
        if let Some(entry) = self.lanes.get_mut(lane) {
            entry.queue = queue;
            entry.staged.clear();
            entry.suspended = false;
            entry.control = false;
        }
    }

    /// Returns the pending items of `lane`'s queue that were never exposed
    /// to the kernel, for a lane its gate aborted: such a lane is never
    /// flushed again, so an item the kernel refused (would block) before
    /// the close would stay staged, and counted in flight, for good. Each
    /// returned item leaves through `gate` as [`Left::Returned`], in staging
    /// order, with its staged record. Items already handed to the kernel are
    /// not pending, so none of them is returned. A report that names another
    /// item than the lane's next one stops the call (drained), leaving the
    /// rest staged.
    ///
    /// # Errors
    ///
    /// The queue's [`QueueError`] from [`TxBackend::cancel_pending`].
    pub fn cancel<B: TxBackend, G: LaneGate>(
        &mut self,
        backend: &mut B,
        lane: usize,
        gate: &mut G,
    ) -> Result<(), QueueError> {
        let Self { lanes, report, .. } = self;
        let Some(entry) = lanes.get_mut(lane) else {
            return Ok(());
        };
        loop {
            let outcome = backend.cancel_pending(entry.queue, report)?;
            while let Some(item) = report.pop_front() {
                match entry.staged.front().copied() {
                    Some(head) if head.ticket == item.ticket => {
                        entry.staged.pop_front();
                        gate.left(lane, head, Left::Returned);
                    }
                    _ => {
                        while report.pop_front().is_some() {}
                        return Ok(());
                    }
                }
            }
            if !outcome.more {
                return Ok(());
            }
        }
    }

    /// Serves the lanes within `budget` through `backend`, asking `gate`
    /// at each probe and at each exposure.
    pub fn serve<B: TxBackend, G: LaneGate>(
        &mut self,
        backend: &mut B,
        gate: &mut G,
        budget: Budget,
    ) -> SenderReport {
        for lane in &mut self.lanes {
            lane.paused = false;
        }
        let mut source = Source {
            backend,
            gate,
            lanes: &mut self.lanes,
            report: &mut self.report,
            failure: None,
            inactive: false,
        };
        let drr = self.drr.run(budget, &mut source);
        let failure = source.failure.or(match drr.stop {
            Stop::Failed(error) => Some(SenderFailure::Drr(error)),
            _ => None,
        });
        SenderReport {
            drr,
            failure,
            inactive: source.inactive,
        }
    }
}

/// The DRR's view of the lanes for one call.
struct Source<'a, B, G> {
    backend: &'a mut B,
    gate: &'a mut G,
    lanes: &'a mut [Lane],
    report: &'a mut TxReport,
    failure: Option<SenderFailure>,
    inactive: bool,
}

impl<B: TxBackend, G: LaneGate> Source<'_, B, G> {
    /// Stops the call with `Stop::Halted`: nothing is forfeited and the
    /// visit is kept for the control path to resume after it acts.
    fn fail(&mut self, failure: SenderFailure) -> Service {
        self.failure = Some(failure);
        Service::Halt
    }

    /// `lane` waits for the control path: its queue is faulted, closed or
    /// without its route. The other lanes go on.
    fn hold(&mut self, lane: usize) -> Service {
        if let Some(entry) = self.lanes.get_mut(lane) {
            entry.control = true;
        }
        Service::NotServed
    }

    /// A flush that reported no entry for the head: the stop alone says
    /// why (lane-sender.md, outcome table).
    fn without_entry(&mut self, lane: usize, stop: FlushStop) -> Service {
        match stop {
            FlushStop::Queue(QueueError::NotActive) => {
                // The endpoint is resetting or retired: stop the call, as
                // backpressure does, rather than an empty pass.
                self.inactive = true;
                Service::Backpressure
            }
            FlushStop::Queue(
                QueueError::UnknownQueue | QueueError::RouteUnknown | QueueError::NeedsReset,
            )
            | FlushStop::Faulted(_) => self.hold(lane),
            FlushStop::ReportNotEmpty | FlushStop::GateError { .. } => {
                self.fail(SenderFailure::Sender { lane, stop })
            }
            // An invariant fault of this queue only; it shows as
            // `NeedsReset` from now on.
            FlushStop::Failed(BackendFailure::Invariant { .. }) => self.hold(lane),
            // An OS failure stopped the half: every lane waits for the reset.
            FlushStop::Failed(_) => self.fail(SenderFailure::Backend { lane, stop }),
            // `QueueEmpty` contradicts the staged count and
            // `HeadExceedsBudget` the committed length; nothing else stops
            // a flush before its candidates.
            _ => self.fail(SenderFailure::Invariant { lane, stop }),
        }
    }
}

impl<B: TxBackend, G: LaneGate> LaneSource for Source<'_, B, G> {
    fn probe(&mut self, lane: usize) -> Probe {
        if self.failure.is_some() || self.inactive {
            return Probe::Ineligible;
        }
        let Some(entry) = self.lanes.get(lane) else {
            return Probe::Ineligible;
        };
        if entry.suspended || entry.control || entry.paused {
            return Probe::Ineligible;
        }
        let Some(head) = entry.staged.front() else {
            return Probe::Ineligible;
        };
        let charge = head.charge;
        if self.gate.admits(lane) {
            Probe::Eligible { charge }
        } else {
            Probe::Ineligible
        }
    }

    fn serve(&mut self, lane: usize) -> Service {
        let Some(entry) = self.lanes.get_mut(lane) else {
            return Service::NotServed;
        };
        let Some(head) = entry.staged.front().copied() else {
            return Service::NotServed;
        };
        let request = FlushRequest {
            queue: entry.queue,
            max_datagrams: NonZeroU16::MIN,
            max_bytes: u32::from(head.len),
        };
        self.gate.flushing(lane);
        let outcome = self.backend.flush(request, &mut *self.gate, self.report);
        let reported = self.report.pop_front();
        // One datagram offered: at most one entry. Anything left is a
        // backend contradiction; drain it so the next flush is not refused.
        let extra = self.report.pop_front().is_some();
        while self.report.pop_front().is_some() {}
        let stop = outcome.stop;
        let Some(item) = reported else {
            return self.without_entry(lane, stop);
        };
        if extra || item.ticket != head.ticket {
            return self.fail(SenderFailure::Invariant { lane, stop });
        }
        let Some(entry) = self.lanes.get_mut(lane) else {
            return Service::NotServed;
        };
        match item.outcome {
            TxItemOutcome::Submitted { .. } => {
                entry.staged.pop_front();
                self.gate.left(lane, head, Left::Submitted);
                Service::Served
            }
            TxItemOutcome::Returned { .. } => {
                // The item left its queue without exposure: not service.
                entry.staged.pop_front();
                self.gate.left(lane, head, Left::Returned);
                Service::NotServed
            }
            TxItemOutcome::Unknown => {
                // Exposure unproven, with `Failed(Invariant)` faulting only
                // this queue: the item left it and is never retried; this
                // lane waits for the control path, the others go on.
                entry.staged.pop_front();
                entry.suspended = true;
                self.gate.left(lane, head, Left::Unknown);
                Service::Uncertain
            }
            TxItemOutcome::Pending { cause } => match cause {
                PendingCause::GateDenied => {
                    // The probe raced the exposure-time gate: the ordinary
                    // ineligibility, not a penalty.
                    entry.paused = true;
                    Service::NotServed
                }
                // Not lane conditions: the lane stays eligible and the
                // retry costs one work unit.
                PendingCause::Interrupted | PendingCause::PeerError => Service::NotServed,
                // Per socket: the lane forfeits, the call stops on the next
                // lane (LS-4).
                PendingCause::WouldBlock | PendingCause::NoBuffers => Service::Backpressure,
                PendingCause::Faulted(_) => self.hold(lane),
                // One datagram per flush: neither can occur.
                PendingCause::ErrorLost | PendingCause::NotAttempted => {
                    self.fail(SenderFailure::Invariant { lane, stop })
                }
                PendingCause::Failed(BackendFailure::Invariant { .. }) => self.hold(lane),
                PendingCause::Failed(_) => self.fail(SenderFailure::Backend { lane, stop }),
            },
        }
    }
}

pub mod routes;

#[cfg(test)]
mod tests;
