// SPDX-License-Identifier: Apache-2.0

//! What a [`TraceReport`](crate::TraceReport) reads one journal through
//! (`quantstratum-docs: karyos/design/trace-tool.md`, "Feeding the report",
//! T1): a [`JournalSource`] delivers the journal's records in sequence
//! order with their gaps, its loss accounting and its terminal state. The
//! in-process [`TraceCollector`] is one source; a tool's reader of the
//! driver's trace mirror is another. The attributor is the same for both:
//! it works from sequences and gaps.

use std::fmt::Debug;

use karyos_protocol::journal::DropRange;

use crate::journal::{Collected, ObserverId, TraceCollector};

/// The terminal state a source knows of its journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    /// The journal may still deliver records, or its terminal close is
    /// reported by its owner with
    /// [`TraceReport::closed`](crate::TraceReport::closed) (a collector).
    Open,
    /// The writer closed the journal; for a subscriber journal, with its
    /// final delivery boundary. The source returns [`Collected::Closed`]
    /// once every record it holds was taken.
    Closed {
        /// The final delivery boundary, when known.
        boundary: Option<u64>,
    },
    /// The journal ended without a decided membership: its writer is gone
    /// without a final boundary, or its records contradict what it
    /// observes (malformed, `quantstratum-docs:
    /// karyos/design/trace-tool.md`, T4). Every trace it could be expected
    /// in becomes final `Incomplete`; it never drops out of an expected
    /// set. The source returns [`Collected::Closed`] once every record it
    /// holds was taken.
    Lost,
}

/// The loss accounting of a journal, as its source reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceLosses {
    /// The horizon: every sequence below it was attempted.
    pub attempted: u64,
    /// Stored records at or above the source's start, read after
    /// `attempted`, that the source delivered or will deliver. When every
    /// one was taken and `attempted` is past the next expected sequence,
    /// the tail was lost.
    pub stored: u64,
    /// Every sequence below it that is not a stored record may have been
    /// lost; `None` if no drop range was evicted.
    pub lost_before: Option<u64>,
    /// The journal's own drop ranges: loss attributed to the stream.
    pub ranges: Vec<DropRange>,
    /// Sequences `[first, last]` the source lost after the journal stored
    /// them (a tool's mirror loss), never attributed to the stream. Where
    /// they overlap the journal's own ranges, those win.
    pub mirror_ranges: Vec<(u64, u64)>,
}

/// A journal as a report reads it: an iterator of `(sequence, record)` with
/// the gaps between them, plus loss accounting and terminal state.
///
/// **Contract.** [`JournalSource::take`] returns every record of the
/// journal from [`JournalSource::start`] on, exactly once and in sequence
/// order, with the sequences never delivered before each one as its gap,
/// then [`Collected::Empty`] while the journal may still deliver more, or
/// [`Collected::Closed`] once it never will.
pub trait JournalSource: Debug {
    /// The observer that owns the journal; it scopes the clocks of every
    /// record.
    fn observer(&self) -> ObserverId;

    /// The first sequence this source delivers: 0 for a source that reads
    /// the journal from its start. Observations below it are out of the
    /// report's scope.
    fn start(&self) -> u64 {
        0
    }

    /// The next item, in sequence order.
    fn take(&mut self) -> Collected;

    /// The journal's loss accounting now.
    fn losses(&mut self) -> SourceLosses;

    /// The journal's terminal state as the source knows it.
    fn state(&self) -> SourceState {
        SourceState::Open
    }
}

/// The in-process collector: it reads the journal from its start, and its
/// owner reports the terminal close with
/// [`TraceReport::closed`](crate::TraceReport::closed).
impl JournalSource for TraceCollector {
    fn observer(&self) -> ObserverId {
        TraceCollector::observer(self)
    }

    fn take(&mut self) -> Collected {
        TraceCollector::take(self)
    }

    fn losses(&mut self) -> SourceLosses {
        let losses = TraceCollector::losses(self);
        SourceLosses {
            attempted: losses.attempted,
            stored: losses.stored,
            lost_before: losses.lost_before,
            ranges: losses.ranges.to_vec(),
            mirror_ranges: Vec::new(),
        }
    }
}
