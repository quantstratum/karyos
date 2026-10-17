// SPDX-License-Identifier: Apache-2.0

//! Client view of a keyed conflation table (SPEC.md §7.1, §10).
//!
//! The reader-side counters of SPEC.md §11 ("conflation skips and
//! exhausted read budgets"; `quantstratum-docs:
//! karyos/design/conflation-end-to-end.md`, Counters, and
//! observability-and-tools.md, Client counters) are kept by every view:
//! [`ConflatedSubscription::counts`] reads them in any mode. A view whose
//! client has a client counters region can also feed them into two client
//! counter cells ([`ConflatedSubscription::with_counters`]), where tools
//! read them; an embedded view without such a client has only the
//! accessors.

use karyos_sys::conflation::{Budget, ConflationReader, PollReport};
use karyos_sys::freshness::{
    Freshness, TERMINAL_BARRIER_TIMEOUT, TERMINAL_BELOW_FRONTIER, TERMINAL_FRESHNESS_EXHAUSTED,
    Terminal,
};

use crate::counter::ClientCounterHandle;
use crate::error::ClientError;

/// A key's latest coherent value as a poll delivers it (SPEC.md §7.1,
/// §10): borrowed for the handler's call only, as a fragment is.
///
/// The payload cannot escape the handler:
///
/// ```compile_fail,E0521
/// # use karyos_client::ConflatedSubscription;
/// fn escape(view: &mut ConflatedSubscription) {
///     let mut kept: &[u8] = &[];
///     let _ = view.poll_changed(|_key, value| kept = value.payload());
///     let _ = kept;
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ConflatedValue<'a> {
    payload: &'a [u8],
    version: u64,
    freshness: Freshness,
}

impl<'a> ConflatedValue<'a> {
    /// The value's bytes: a private copy, valid during the handler's call.
    #[must_use]
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// The value's version: it only grows for a key.
    #[must_use]
    #[inline]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Whether a committed gap covers the value (SPEC.md §7.1): `Fresh`,
    /// or `Stale` since the gap's start.
    #[must_use]
    #[inline]
    pub fn freshness(&self) -> Freshness {
        self.freshness
    }
}

/// Why a view closed for good: its table published a terminal
/// invalidation, so every value below the end of its interval is stale and
/// the view delivers nothing more (`quantstratum-docs:
/// karyos/design/conflated-network-images.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ViewClosed {
    /// The receive owner's seal waited past its bound for the feeder's
    /// acknowledgement.
    #[error("the conflated view closed: barrier timeout (stale since {since})")]
    BarrierTimeout {
        /// The start of the unresolved interval.
        since: u64,
    },
    /// The loss sequence or a slot's versions are exhausted.
    #[error("the conflated view closed: freshness exhausted (stale since {since})")]
    FreshnessExhausted {
        /// The start of the unresolved interval.
        since: u64,
    },
    /// A loss below the feeder's frontier, which breaks the invariant the
    /// readers' classification rests on.
    #[error("the conflated view closed: a loss below the frontier (stale since {since})")]
    BelowFrontier {
        /// The start of the unresolved interval.
        since: u64,
    },
    /// The network image the view reads retired (`quantstratum-docs:
    /// karyos/design/conflated-network-images.md`). Reserved: the view of
    /// a network image reports it once that close is wired.
    #[error("the conflated view closed: its image retired")]
    ImageRetired {
        /// The image's last position, when known.
        since: Option<u64>,
    },
    /// A reason code this client does not know.
    #[error("the conflated view closed (reason {reason}, stale since {since})")]
    Other {
        /// The reason code.
        reason: u64,
        /// The start of the unresolved interval.
        since: u64,
    },
}

impl ViewClosed {
    /// The close of `terminal`.
    #[must_use]
    pub fn of(terminal: Terminal) -> Self {
        let since = terminal.start;
        match terminal.reason {
            TERMINAL_BARRIER_TIMEOUT => Self::BarrierTimeout { since },
            TERMINAL_FRESHNESS_EXHAUSTED => Self::FreshnessExhausted { since },
            TERMINAL_BELOW_FRONTIER => Self::BelowFrontier { since },
            reason => Self::Other { reason, since },
        }
    }
}

/// Label of the client counter of conflation skips.
pub const CONFLATION_SKIPS: &str = "conflation skips";
/// Label of the client counter of exhausted conflation read budgets.
pub const CONFLATION_BUDGETS_EXHAUSTED: &str = "conflation budgets exhausted";

/// A view's reader-side counts since it was created.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReaderCounts {
    /// Served keys whose value was already delivered (`PollReport::skipped`
    /// summed over every poll).
    pub skips: u64,
    /// Polls that ended before every known change was delivered: keys
    /// still queued, a full scan still in progress or the journal not read
    /// to its end, so the read budget ran out.
    pub budgets_exhausted: u64,
}

/// The client counter cells a view feeds.
#[derive(Debug)]
struct CounterSink {
    skips: ClientCounterHandle,
    budgets_exhausted: ClientCounterHandle,
}

/// A bounded reader of the latest coherent value for each changed key.
///
/// The reader's private buffers are allocated when it is created. A handler
/// receives a borrowed copy that does not hold a slot or publication loan.
#[must_use]
pub struct ConflatedSubscription {
    reader: ConflationReader,
    budget: Budget,
    counts: ReaderCounts,
    sink: Option<CounterSink>,
    /// Dropped last, after the reader and its mapping: a remote view's
    /// `Detach` (`quantstratum-docs:
    /// karyos/design/conflation-end-to-end.md`, Lifetime).
    guard: Option<Box<dyn core::any::Any + Send + Sync>>,
}

impl ConflatedSubscription {
    /// Wraps a reader and the budget used by [`Self::poll_changed`].
    pub fn new(reader: ConflationReader, budget: Budget) -> Self {
        Self {
            reader,
            budget,
            counts: ReaderCounts::default(),
            sink: None,
            guard: None,
        }
    }

    /// Keeps `guard` until the view is dropped, after its reader: a remote
    /// view's `Detach`, sent once its table is unmapped.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote views exist only on Linux")
    )]
    pub(crate) fn with_guard(mut self, guard: impl core::any::Any + Send + Sync) -> Self {
        self.guard = Some(Box::new(guard));
        self
    }

    /// Feeds the reader-side counts into two client counter cells, which
    /// the client allocated for this view (labels [`CONFLATION_SKIPS`] and
    /// [`CONFLATION_BUDGETS_EXHAUSTED`]): every later poll adds its counts
    /// to them. An increment the cell refuses (overflow) leaves the cell
    /// unchanged; [`Self::counts`] stays exact.
    pub fn with_counters(
        mut self,
        skips: ClientCounterHandle,
        budgets_exhausted: ClientCounterHandle,
    ) -> Self {
        self.sink = Some(CounterSink {
            skips,
            budgets_exhausted,
        });
        self
    }

    /// The reader-side counts since the view was created.
    #[must_use]
    pub fn counts(&self) -> ReaderCounts {
        self.counts
    }

    /// Adds one poll's report to the counts and the cells.
    fn account(&mut self, report: PollReport) -> PollReport {
        let skips = u64::from(report.skipped);
        let caught_up = report.pending == 0 && !report.scanning && report.journal_drained;
        let exhausted = u64::from(!report.closed && !caught_up);
        self.counts.skips = self.counts.skips.saturating_add(skips);
        self.counts.budgets_exhausted = self.counts.budgets_exhausted.saturating_add(exhausted);
        if let Some(sink) = &self.sink {
            for (counter, delta) in [(&sink.skips, skips), (&sink.budgets_exhausted, exhausted)] {
                if delta > 0 {
                    let _ = counter.increment(delta);
                }
            }
        }
        report
    }

    /// Delivers changed keys using this subscription's budget: each key
    /// with its latest coherent value, borrowed for the call (SPEC.md §10).
    ///
    /// Intermediate versions may be skipped. A handler panic leaves its key
    /// pending for a later poll.
    ///
    /// # Errors
    ///
    /// [`ClientError::ViewClosed`] once the table published a terminal
    /// invalidation: that poll and every later one deliver nothing.
    pub fn poll_changed(
        &mut self,
        handler: impl FnMut(u32, &ConflatedValue<'_>),
    ) -> Result<PollReport, ClientError> {
        let budget = self.budget;
        self.poll_changed_with(budget, handler)
    }

    /// As [`Self::poll_changed`], with an explicit budget.
    ///
    /// # Errors
    ///
    /// As [`Self::poll_changed`].
    pub fn poll_changed_with(
        &mut self,
        budget: Budget,
        mut handler: impl FnMut(u32, &ConflatedValue<'_>),
    ) -> Result<PollReport, ClientError> {
        let report = self
            .reader
            .poll_changed(budget, |key, version, payload, freshness| {
                handler(
                    key,
                    &ConflatedValue {
                        payload,
                        version,
                        freshness,
                    },
                );
            });
        let report = self.account(report);
        match report.terminal {
            Some(terminal) => Err(ClientError::ViewClosed(ViewClosed::of(terminal))),
            None => Ok(report),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_sys::conflation::conflation;

    #[test]
    fn poll_changed_uses_the_subscription_budget() {
        let mut writer = conflation(2, 8, 1024).unwrap();
        let mut subscription = ConflatedSubscription::new(
            writer.reader(),
            Budget {
                keys: 2,
                retries: 2,
            },
        );
        writer.write(1, b"value").unwrap();
        let mut seen = Vec::new();

        let report = subscription
            .poll_changed(|key, value| {
                seen.push((key, value.payload().to_vec()));
            })
            .unwrap();

        assert_eq!(report.delivered, 1);
        assert_eq!(seen, vec![(1, b"value".to_vec())]);
    }

    /// A poll whose budget ends with keys queued counts one exhausted
    /// budget; skips add up over polls.
    #[test]
    fn the_reader_side_counts_add_up_over_polls() {
        let mut writer = conflation(4, 8, 1024).unwrap();
        let mut subscription = ConflatedSubscription::new(
            writer.reader(),
            Budget {
                keys: 1,
                retries: 1,
            },
        );
        for key in 0..3 {
            writer.write(key, b"v").unwrap();
        }
        let mut reports = Vec::new();
        for _ in 0..4 {
            reports.push(subscription.poll_changed(|_, _| {}).unwrap());
        }
        let short = |r: &PollReport| !(r.pending == 0 && !r.scanning && r.journal_drained);
        let expected = ReaderCounts {
            skips: reports.iter().map(|r| u64::from(r.skipped)).sum(),
            budgets_exhausted: reports.iter().filter(|r| short(r)).count() as u64,
        };
        assert_eq!(subscription.counts(), expected);
        // One key per poll for three keys: the first three polls ran out,
        // the fourth caught up.
        assert_eq!(subscription.counts().budgets_exhausted, 3, "{reports:?}");
    }

    #[test]
    fn poll_changed_with_uses_its_budget_and_reports_versions() {
        let mut writer = conflation(3, 8, 1024).unwrap();
        let mut subscription = ConflatedSubscription::new(
            writer.reader(),
            Budget {
                keys: 0,
                retries: 0,
            },
        );
        let version = writer.write(2, b"new").unwrap();
        let mut seen = Vec::new();

        let report = subscription
            .poll_changed_with(
                Budget {
                    keys: 3,
                    retries: 1,
                },
                |key, value| {
                    seen.push((key, value.version(), value.payload().to_vec()));
                },
            )
            .unwrap();

        assert_eq!(report.delivered, 1);
        assert_eq!(seen, vec![(2, version, b"new".to_vec())]);
    }

    /// SPEC §7.1, §10: a value reaches the handler with its freshness; a
    /// recorded loss over it makes it Stale since the gap's start, and the
    /// view delivers it again.
    #[test]
    fn values_carry_their_freshness() {
        use karyos_sys::conflation::conflation_fresh;
        use karyos_sys::freshness::FreshnessLink;

        let mut writer = conflation_fresh(2, 8, 1024, FreshnessLink::new()).unwrap();
        let mut view = ConflatedSubscription::new(
            writer.reader(),
            Budget {
                keys: 4,
                retries: 2,
            },
        );
        let _ = writer.write_at(0, b"a", 0).unwrap();
        writer.passed(32);
        let mut seen = Vec::new();
        let _ = view
            .poll_changed(|key, value| seen.push((key, value.freshness())))
            .unwrap();
        assert_eq!(seen, [(0, Freshness::Fresh)]);
        let _ = writer.record_loss(32, 64).unwrap();
        seen.clear();
        let _ = view
            .poll_changed(|key, value| seen.push((key, value.freshness())))
            .unwrap();
        assert_eq!(seen, [(0, Freshness::Stale { since: 32 })]);
    }

    /// docs#119 (3): once the table published its terminal cell, the poll
    /// reports the typed close, and every later poll again; each reason
    /// maps to its own variant.
    #[test]
    fn a_terminal_cell_closes_the_view_with_its_reason() {
        use karyos_sys::conflation::conflation_fresh;
        use karyos_sys::freshness::FreshnessLink;

        for (reason, closed) in [
            (
                TERMINAL_BARRIER_TIMEOUT,
                ViewClosed::BarrierTimeout { since: 16 },
            ),
            (
                TERMINAL_FRESHNESS_EXHAUSTED,
                ViewClosed::FreshnessExhausted { since: 16 },
            ),
            (
                TERMINAL_BELOW_FRONTIER,
                ViewClosed::BelowFrontier { since: 16 },
            ),
            (
                99,
                ViewClosed::Other {
                    reason: 99,
                    since: 16,
                },
            ),
        ] {
            let mut writer = conflation_fresh(2, 8, 1024, FreshnessLink::new()).unwrap();
            let mut view = ConflatedSubscription::new(
                writer.reader(),
                Budget {
                    keys: 4,
                    retries: 2,
                },
            );
            let _ = writer.write_at(1, b"v", 0).unwrap();
            assert!(view.poll_changed(|_, _| {}).is_ok());
            assert!(writer.publish_terminal(16, 48, reason));
            for _ in 0..2 {
                let mut delivered = 0;
                assert_eq!(
                    view.poll_changed(|_, _| delivered += 1),
                    Err(ClientError::ViewClosed(closed))
                );
                assert_eq!(delivered, 0);
            }
        }
    }
}
