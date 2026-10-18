// SPDX-License-Identifier: Apache-2.0

//! Loss reports from clients (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Loss reports from clients").
//!
//! An overrun is detected by the subscriber. When a subscription handed
//! over by a client conductor is overrun, it captures the loss at once (the
//! stream's full publication identity, its own registration, the lane, the
//! lost range, the configured rejoin policy and the outcome applied) and
//! queues it in its client's [`LossReports`]. The conductor drains the queue
//! on its next poll and sends one `ReportLoss` per report; those requests
//! are its own and never reported.
//!
//! The queue holds at most [`LOSS_REPORT_QUEUE`] reports. When it is full,
//! the oldest report is dropped and counted; the count is the client's
//! `loss reports dropped`, which the conductor also mirrors into a client
//! counter of its own once one is needed.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use karyos_protocol::cnc::{FallbackReasonCode, RejoinOutcomeCode, RejoinPolicyCode, ReportedLoss};
use karyos_protocol::trace_hook::PublicationIdentity;

use crate::subscription::{
    Overrun, RejoinOutcome, RejoinPolicy, ReplayFallbackReason, SecondaryOutcome,
};

/// Loss reports a client keeps for its conductor. Overruns are rare, so
/// the bound is small; the queue is allocated with the client.
pub const LOSS_REPORT_QUEUE: usize = 64;

/// The loss reports a client's subscriptions queued for its conductor, and
/// the reports dropped because the queue was full. Shared by the
/// conductor and its subscriptions through the
/// [`ClientLink`](crate::link::ClientLink).
#[derive(Debug)]
pub struct LossReports {
    queue: Mutex<VecDeque<ReportedLoss>>,
    dropped: AtomicU64,
}

impl Default for LossReports {
    fn default() -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(LOSS_REPORT_QUEUE)),
            dropped: AtomicU64::new(0),
        }
    }
}

impl LossReports {
    fn queue(&self) -> MutexGuard<'_, VecDeque<ReportedLoss>> {
        // Every critical section is a single push or pop, so a panic
        // elsewhere cannot leave the queue half updated.
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reports queued and not yet sent.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue().len()
    }

    /// Reports dropped because the queue was full (Relaxed). The count is
    /// checked: it would stop at `u64::MAX`, which one drop per overrun
    /// cannot reach.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn count_dropped(&self) {
        let _ = self
            .dropped
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_add(1)
            });
    }

    /// Queues `loss`, dropping and counting the oldest report when the
    /// queue is full. Never allocates: the queue keeps its capacity.
    pub(crate) fn push(&self, loss: ReportedLoss) {
        let mut queue = self.queue();
        if queue.len() >= LOSS_REPORT_QUEUE {
            queue.pop_front();
            self.count_dropped();
        }
        queue.push_back(loss);
    }

    pub(crate) fn pop(&self) -> Option<ReportedLoss> {
        self.queue().pop_front()
    }

    /// Puts back a report that could not be sent yet, first in line. If
    /// newer reports filled the queue meanwhile, it is the oldest: it is
    /// dropped and counted instead.
    pub(crate) fn unpop(&self, loss: ReportedLoss) {
        let mut queue = self.queue();
        if queue.len() >= LOSS_REPORT_QUEUE {
            self.count_dropped();
        } else {
            queue.push_front(loss);
        }
    }
}

/// What a subscription handed over by a client conductor needs to report
/// its overruns: the stream's publication identity, its own registration
/// and its client's queue.
#[derive(Debug)]
pub(crate) struct LossReporter {
    pub(crate) publication: PublicationIdentity,
    pub(crate) registration: u64,
    pub(crate) reports: Arc<LossReports>,
}

impl LossReporter {
    /// Queues the report of `overrun` on `lane`, handled by `policy` with
    /// `outcome`.
    pub(crate) fn report(
        &self,
        lane: u8,
        overrun: &Overrun,
        policy: &RejoinPolicy,
        outcome: RejoinOutcome,
    ) {
        let configured = match policy {
            RejoinPolicy::RejoinAtHead => RejoinPolicyCode::RejoinAtHead,
            RejoinPolicy::Snapshot(_) => RejoinPolicyCode::Snapshot,
            RejoinPolicy::Close => RejoinPolicyCode::Close,
            RejoinPolicy::Replay { .. } => RejoinPolicyCode::Replay,
        };
        self.report_as(lane, overrun, configured, outcome);
    }

    /// Queues the report of `overrun` on `lane`, handled by the policy
    /// `configured` with `outcome`. `Replaying` is no outcome yet: nothing
    /// is reported until it resolves.
    pub(crate) fn report_as(
        &self,
        lane: u8,
        overrun: &Overrun,
        configured: RejoinPolicyCode,
        outcome: RejoinOutcome,
    ) {
        let (applied, fallback) = match outcome {
            RejoinOutcome::Replaying => return,
            RejoinOutcome::Replayed { .. } => (RejoinOutcomeCode::Replayed, None),
            RejoinOutcome::ResumedAtHead => (RejoinOutcomeCode::ResumedAtHead, None),
            RejoinOutcome::SnapshotRebuilt => (RejoinOutcomeCode::SnapshotRebuilt, None),
            RejoinOutcome::SnapshotFailed => (RejoinOutcomeCode::SnapshotFailed, None),
            RejoinOutcome::Closed => (RejoinOutcomeCode::Closed, None),
            RejoinOutcome::ReplayFallback { reason, secondary } => (
                match secondary {
                    SecondaryOutcome::ResumedAtHead => RejoinOutcomeCode::ResumedAtHead,
                    SecondaryOutcome::SnapshotRebuilt => RejoinOutcomeCode::SnapshotRebuilt,
                    SecondaryOutcome::SnapshotFailed => RejoinOutcomeCode::SnapshotFailed,
                    SecondaryOutcome::Closed => RejoinOutcomeCode::Closed,
                },
                Some(match reason {
                    ReplayFallbackReason::NoArchive => FallbackReasonCode::NoArchive,
                    ReplayFallbackReason::NoRecording => FallbackReasonCode::NoRecording,
                    ReplayFallbackReason::RetentionShort => FallbackReasonCode::RetentionShort,
                    ReplayFallbackReason::RecordingBehind => FallbackReasonCode::RecordingBehind,
                    ReplayFallbackReason::Refused => FallbackReasonCode::Refused,
                    ReplayFallbackReason::MergeFailed => FallbackReasonCode::MergeFailed,
                    ReplayFallbackReason::Withdrawn => FallbackReasonCode::Withdrawn,
                }),
            ),
        };
        self.reports.push(ReportedLoss {
            driver: self.publication.driver,
            stream_registration: self.publication.registration,
            incarnation: self.publication.incarnation,
            subscription: self.registration,
            lane,
            from: overrun.from,
            to: overrun.lost_to,
            configured,
            applied,
            fallback,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loss(from: u64) -> ReportedLoss {
        ReportedLoss {
            driver: [1, 2],
            stream_registration: 3,
            incarnation: 1,
            subscription: 4,
            lane: 0,
            from,
            to: from + 1,
            configured: RejoinPolicyCode::RejoinAtHead,
            applied: RejoinOutcomeCode::ResumedAtHead,
            fallback: None,
        }
    }

    #[test]
    fn an_overflow_drops_the_oldest_and_counts_it() {
        let reports = LossReports::default();
        for from in 0..LOSS_REPORT_QUEUE as u64 + 3 {
            reports.push(loss(from));
        }
        assert_eq!(reports.queued(), LOSS_REPORT_QUEUE);
        assert_eq!(reports.dropped(), 3);
        // The three oldest went; the rest are in order.
        assert_eq!(reports.pop().unwrap().from, 3);
        // A report put back while newer ones filled the queue is the
        // oldest: it is dropped and counted.
        let next = reports.pop().unwrap();
        assert_eq!(next.from, 4);
        reports.push(loss(1000));
        reports.push(loss(1001));
        assert_eq!(reports.queued(), LOSS_REPORT_QUEUE);
        assert_eq!(reports.dropped(), 3);
        reports.unpop(next);
        assert_eq!(reports.dropped(), 4);
        assert_eq!(reports.pop().unwrap().from, 5);
        // With room, it goes back first in line.
        let next = reports.pop().unwrap();
        reports.unpop(next);
        assert_eq!(reports.pop().unwrap(), next);
    }

    #[test]
    fn the_report_carries_the_policy_and_the_applied_outcome() {
        let reports = Arc::new(LossReports::default());
        let reporter = LossReporter {
            publication: PublicationIdentity {
                driver: [7, 8],
                registration: 9,
                stream_id: 2,
                session_id: 1,
                incarnation: 1,
            },
            registration: 10,
            reports: Arc::clone(&reports),
        };
        let overrun = Overrun {
            from: 64,
            lost_to: 4096,
            resume: 8192,
        };
        let policy = RejoinPolicy::Replay {
            secondary: crate::subscription::Secondary::Close,
        };
        reporter.report(
            2,
            &overrun,
            &policy,
            RejoinOutcome::ReplayFallback {
                reason: ReplayFallbackReason::NoArchive,
                secondary: SecondaryOutcome::Closed,
            },
        );
        assert_eq!(
            reports.pop(),
            Some(ReportedLoss {
                driver: [7, 8],
                stream_registration: 9,
                incarnation: 1,
                subscription: 10,
                lane: 2,
                from: 64,
                to: 4096,
                configured: RejoinPolicyCode::Replay,
                applied: RejoinOutcomeCode::Closed,
                fallback: Some(FallbackReasonCode::NoArchive),
            })
        );
    }

    /// A replay that recovered reports `Replayed` with no reason; one that
    /// fell back carries the phase 3 reasons; one still replaying reports
    /// nothing yet.
    #[test]
    fn a_replay_rejoin_reports_once_it_resolved() {
        let reports = Arc::new(LossReports::default());
        let reporter = LossReporter {
            publication: PublicationIdentity::default(),
            registration: 10,
            reports: Arc::clone(&reports),
        };
        let overrun = Overrun {
            from: 64,
            lost_to: 4096,
            resume: 4096,
        };
        let replay = RejoinPolicyCode::Replay;
        reporter.report_as(0, &overrun, replay, RejoinOutcome::Replaying);
        assert_eq!(reports.pop(), None);
        reporter.report_as(
            0,
            &overrun,
            replay,
            RejoinOutcome::Replayed { cutover: 4096 },
        );
        let replayed = reports.pop().unwrap();
        assert_eq!(
            (replayed.applied, replayed.fallback),
            (RejoinOutcomeCode::Replayed, None)
        );
        for (reason, code) in [
            (
                ReplayFallbackReason::RecordingBehind,
                FallbackReasonCode::RecordingBehind,
            ),
            (ReplayFallbackReason::Refused, FallbackReasonCode::Refused),
            (
                ReplayFallbackReason::MergeFailed,
                FallbackReasonCode::MergeFailed,
            ),
            (
                ReplayFallbackReason::Withdrawn,
                FallbackReasonCode::Withdrawn,
            ),
        ] {
            reporter.report_as(
                0,
                &overrun,
                replay,
                RejoinOutcome::ReplayFallback {
                    reason,
                    secondary: SecondaryOutcome::ResumedAtHead,
                },
            );
            let fell_back = reports.pop().unwrap();
            assert_eq!(
                (fell_back.configured, fell_back.applied, fell_back.fallback),
                (
                    RejoinPolicyCode::Replay,
                    RejoinOutcomeCode::ResumedAtHead,
                    Some(code)
                )
            );
        }
    }
}
