// SPDX-License-Identifier: Apache-2.0

//! Loss attribution to traces in one journal (SPEC.md §7.3; design in
//! `quantstratum-docs: karyos/design/trace-attribution.md`).
//!
//! The attributor reads a trace journal's stream in sequence order. With one
//! collection clock and epochs that never go back, sequence order is
//! collection order, so every lost sequence lies, on the collection axis,
//! between the retained records around it. A loss within one epoch becomes
//! an interval; a loss that cannot be placed within one epoch marks the
//! sticky incarnation cohort. A trace is marked incomplete when a loss could
//! have removed one of its observations; it is never reported complete
//! after such a loss.
//!
//! `Incomplete` is final as soon as it is reached. `Complete` is final only
//! at the journal's terminal close: [`Attributor::close`].
//!
//! All state is preallocated: up to `max_traces` trace entries and
//! `max_intervals` loss intervals; overflow only marks more traces
//! incomplete.

use karyos_protocol::journal::Stamp;

use crate::error::TraceError;
use crate::journal::Collected;

/// Configuration of an [`Attributor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributionConfig {
    /// `D`: the longest span, in collection-clock units, between any two
    /// observations of one trace in this journal, lost ones, late stamps and
    /// observation uncertainty included. A caller precondition; `u64::MAX`
    /// when no finite bound is defensible.
    pub span: u64,
    /// Trace entries (`T`).
    pub max_traces: usize,
    /// Loss intervals (`L`).
    pub max_intervals: usize,
}

/// Final or provisional verdict of a trace in one journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No loss could have removed an observation of the trace. Final only
    /// when returned by [`Attributor::close`].
    Complete,
    /// A loss may have removed an observation, or the trace could not be
    /// followed. Final as soon as it is reached.
    Incomplete,
}

/// What [`Attributor::observe`] did with one collected item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// A record of a tracked trace.
    Tracked,
    /// A record of a trace that found the table full: it is `Incomplete`,
    /// final, and reported only here.
    Untracked {
        /// Its trace id.
        trace_id: [u64; 2],
    },
    /// A record whose trace id is zero: counted, attributed to no trace.
    Unattributed,
    /// The trace's retained records in one epoch span more than `D`: `D`
    /// was declared too small. The trace is `Incomplete`.
    WindowViolation {
        /// Its trace id.
        trace_id: [u64; 2],
    },
    /// A loss (gap or corrupt record), resolved now or at the next record.
    Loss,
    /// Nothing to attribute (empty journal or closed).
    Nothing,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    trace_id: [u64; 2],
    first_epoch: u64,
    last_epoch: u64,
    /// First and last collection time in `last_epoch`.
    first: u64,
    last: u64,
    incomplete: bool,
}

impl Entry {
    /// Whether the window of this trace in `epoch` overlaps `[low, high]`
    /// (inclusive), with checked arithmetic widening to the axis ends.
    #[expect(
        clippy::implicit_saturating_sub,
        reason = "ADR-0007 keeps saturating_* out of positions and counters; a window end clamped to the axis end is written out explicitly"
    )]
    fn window_overlaps(&self, epoch: u64, low: u64, high: u64, span: u64) -> bool {
        if self.last_epoch != epoch {
            return false;
        }
        // Widening to the axis ends only makes the window larger, which is
        // the conservative direction.
        let start = if span > self.first {
            0
        } else {
            self.first - span
        };
        let end = if span > u64::MAX - self.last {
            u64::MAX
        } else {
            self.last + span
        };
        start <= high && low <= end
    }
}

#[derive(Debug, Clone, Copy)]
struct Interval {
    epoch: u64,
    high: u64,
}

/// The last retained record: its sequence and collection stamp.
#[derive(Debug, Clone, Copy)]
struct Retained {
    epoch: u64,
    time: u64,
}

/// Loss attribution for one trace journal.
#[derive(Debug)]
pub struct Attributor {
    config: AttributionConfig,
    entries: Vec<Entry>,
    intervals: Vec<Interval>,
    /// Sticky: every trace tracked or first retained later is incomplete.
    cohort: bool,
    earliest_loss_epoch: Option<u64>,
    /// The last retained record, if any.
    previous: Option<Retained>,
    /// A loss seen since `previous` and not yet bounded by a later record.
    pending_loss: bool,
    /// The next sequence expected from the journal.
    next_sequence: u64,
    /// Stored records taken so far (records and corrupt ones).
    taken: u64,
    /// Whether [`Collected::Closed`] was observed.
    closed: bool,
}

impl Attributor {
    /// Creates an attributor (control path: allocates its tables).
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::Attribution`] when a table size is zero.
    pub fn new(config: AttributionConfig) -> Result<Self, TraceError> {
        if config.max_traces == 0 || config.max_intervals == 0 {
            return Err(TraceError::Attribution);
        }
        Ok(Self {
            config,
            entries: Vec::with_capacity(config.max_traces),
            intervals: Vec::with_capacity(config.max_intervals),
            cohort: false,
            earliest_loss_epoch: None,
            previous: None,
            pending_loss: false,
            next_sequence: 0,
            taken: 0,
            closed: false,
        })
    }

    /// Marks every tracked trace and every trace first retained later.
    fn mark_cohort(&mut self) {
        self.cohort = true;
        for entry in &mut self.entries {
            entry.incomplete = true;
        }
    }

    /// Applies a loss between the previous retained record and one at
    /// `(epoch, time)`.
    fn apply_loss(&mut self, epoch: u64, time: u64) {
        let Some(previous) = self.previous else {
            // Before the first retained record: earlier epochs may be lost
            // too.
            self.mark_cohort();
            return;
        };
        if previous.epoch != epoch {
            // Spanning epochs: not comparable.
            self.mark_cohort();
            return;
        }
        let (low, high) = (previous.time, time);
        let span = self.config.span;
        for entry in &mut self.entries {
            if entry.window_overlaps(epoch, low, high, span) || entry.first_epoch < epoch {
                entry.incomplete = true;
            }
        }
        self.earliest_loss_epoch = Some(self.earliest_loss_epoch.map_or(epoch, |e| e.min(epoch)));
        if self.intervals.len() < self.config.max_intervals {
            self.intervals.push(Interval { epoch, high });
        } else {
            self.mark_cohort();
        }
    }

    /// Advances the epoch frontier to `(epoch, time)`: drops intervals that no
    /// trace first retained later can reach.
    fn advance_frontier(&mut self, epoch: u64, time: u64) {
        let span = self.config.span;
        // An interval of an older epoch can no longer meet a first retained
        // record in its epoch (epochs never go back); later epochs are covered
        // by the earliest loss epoch.
        self.intervals.retain(|interval| {
            interval.epoch == epoch
                && interval
                    .high
                    .checked_add(span)
                    .is_none_or(|limit| time <= limit)
        });
    }

    /// Whether a trace first retained now, at `(epoch, time)`, may have lost
    /// an earlier observation.
    fn exposed_at_first(&self, epoch: u64, time: u64) -> bool {
        let span = self.config.span;
        self.cohort
            || self.earliest_loss_epoch.is_some_and(|e| e < epoch)
            || self.intervals.iter().any(|interval| {
                interval.epoch == epoch
                    && interval
                        .high
                        .checked_add(span)
                        .is_none_or(|limit| time <= limit)
            })
    }

    /// Feeds one collected item, in the order the collector returned them.
    pub fn observe(&mut self, item: &Collected) -> Observed {
        match *item {
            Collected::Record {
                sequence,
                gap,
                ref record,
                collected,
            } => {
                self.next_sequence = sequence.checked_add(1).unwrap_or(sequence);
                self.taken += 1;
                self.on_record(gap.is_some(), record.ids.trace_id, collected)
            }
            Collected::Corrupt { sequence, .. } => {
                self.next_sequence = sequence.checked_add(1).unwrap_or(sequence);
                self.taken += 1;
                // A corrupt record is a lost observation; it is bounded by the
                // next retained record.
                self.pending_loss = true;
                Observed::Loss
            }
            Collected::Empty => Observed::Nothing,
            Collected::Closed => {
                self.closed = true;
                Observed::Nothing
            }
        }
    }

    fn on_record(&mut self, gap: bool, trace_id: [u64; 2], collected: Stamp) -> Observed {
        let (epoch, time) = (collected.epoch, collected.time);
        let lost = gap || self.pending_loss;
        if lost {
            self.apply_loss(epoch, time);
            self.pending_loss = false;
        }
        self.advance_frontier(epoch, time);
        self.previous = Some(Retained { epoch, time });
        if trace_id == [0, 0] {
            return Observed::Unattributed;
        }
        let span = self.config.span;
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.trace_id == trace_id)
        {
            if epoch > entry.last_epoch {
                entry.last_epoch = epoch;
                entry.first = time;
                entry.last = time;
            } else {
                entry.last = entry.last.max(time);
                if entry
                    .last
                    .checked_sub(entry.first)
                    .is_some_and(|width| width > span)
                {
                    entry.incomplete = true;
                    return Observed::WindowViolation { trace_id };
                }
            }
            return if lost {
                Observed::Loss
            } else {
                Observed::Tracked
            };
        }
        if self.entries.len() >= self.config.max_traces {
            return Observed::Untracked { trace_id };
        }
        let incomplete = self.exposed_at_first(epoch, time);
        self.entries.push(Entry {
            trace_id,
            first_epoch: epoch,
            last_epoch: epoch,
            first: time,
            last: time,
            incomplete,
        });
        if lost {
            Observed::Loss
        } else {
            Observed::Tracked
        }
    }

    /// Feeds a loss snapshot: `attempted` is its horizon and `stored` its
    /// stored count read after the horizon. When every stored record has been
    /// observed here and the horizon is past the next expected sequence, the
    /// tail was lost: its epochs are unknown, so it marks the incarnation
    /// cohort.
    pub fn observe_snapshot(&mut self, attempted: u64, stored: u64) {
        if self.taken >= stored && attempted > self.next_sequence {
            self.mark_cohort();
        }
    }

    /// A provisional view of a trace before the close: `Some(Incomplete)` is
    /// final; `Some(Complete)` only means no loss was seen so far and must
    /// not be treated as final.
    #[must_use]
    pub fn provisional(&self, trace_id: [u64; 2]) -> Option<Verdict> {
        self.entries
            .iter()
            .find(|entry| entry.trace_id == trace_id)
            .map(|entry| {
                if entry.incomplete || self.cohort {
                    Verdict::Incomplete
                } else {
                    Verdict::Complete
                }
            })
    }

    /// Final verdicts at the terminal close. Requires that the collector
    /// returned [`Collected::Closed`] and that a loss snapshot taken after it
    /// has `attempted` (its horizon) equal to the next expected sequence;
    /// otherwise the tail may hold lost records and every trace is reported
    /// `Incomplete`. The owner closes the journal only after every producer,
    /// pending late-stamp callbacks included, has finished.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::NotClosed`] before [`Collected::Closed`] was
    /// observed.
    pub fn close(
        &mut self,
        attempted: u64,
    ) -> Result<impl Iterator<Item = ([u64; 2], Verdict)> + '_, TraceError> {
        if !self.closed {
            return Err(TraceError::NotClosed);
        }
        if attempted != self.next_sequence || self.pending_loss {
            self.mark_cohort();
        }
        let cohort = self.cohort;
        Ok(self.entries.iter().map(move |entry| {
            let verdict = if entry.incomplete || cohort {
                Verdict::Incomplete
            } else {
                Verdict::Complete
            };
            (entry.trace_id, verdict)
        }))
    }
}

/// Combines a trace's verdicts over the journals it is expected in: complete
/// only if every expected journal gave a final `Complete`. `None` means the
/// trace was absent from that journal at its terminal close: `Incomplete`.
pub fn combine(verdicts: impl IntoIterator<Item = Option<Verdict>>) -> Verdict {
    let mut any = false;
    for verdict in verdicts {
        any = true;
        if verdict != Some(Verdict::Complete) {
            return Verdict::Incomplete;
        }
    }
    if any {
        Verdict::Complete
    } else {
        Verdict::Incomplete
    }
}

#[cfg(test)]
mod tests;
