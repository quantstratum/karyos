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

use crate::counter::ClientCounterHandle;

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
}

impl ConflatedSubscription {
    /// Wraps a reader and the budget used by [`Self::poll_changed`].
    pub fn new(reader: ConflationReader, budget: Budget) -> Self {
        Self {
            reader,
            budget,
            counts: ReaderCounts::default(),
            sink: None,
        }
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

    /// Delivers changed keys using this subscription's budget.
    ///
    /// Intermediate versions may be skipped. A handler panic leaves its key
    /// pending for a later poll.
    pub fn poll_changed(&mut self, mut handler: impl FnMut(u32, &[u8])) -> PollReport {
        let report = self
            .reader
            .poll_changed(self.budget, |key, _version, value| handler(key, value));
        self.account(report)
    }

    /// Delivers changed keys with versions using an explicit budget.
    ///
    /// Intermediate versions may be skipped. A handler panic leaves its key
    /// pending for a later poll.
    pub fn poll_changed_with(
        &mut self,
        budget: Budget,
        handler: impl FnMut(u32, u64, &[u8]),
    ) -> PollReport {
        let report = self.reader.poll_changed(budget, handler);
        self.account(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_sys::conflation::conflation;

    #[test]
    fn poll_changed_uses_the_subscription_budget_and_hides_versions() {
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

        let report = subscription.poll_changed(|key, value| {
            seen.push((key, value.to_vec()));
        });

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
            reports.push(subscription.poll_changed(|_, _| {}));
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

        let report = subscription.poll_changed_with(
            Budget {
                keys: 3,
                retries: 1,
            },
            |key, found_version, value| {
                seen.push((key, found_version, value.to_vec()));
            },
        );

        assert_eq!(report.delivered, 1);
        assert_eq!(seen, vec![(2, version, b"new".to_vec())]);
    }
}
