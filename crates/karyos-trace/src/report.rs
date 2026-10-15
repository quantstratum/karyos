// SPDX-License-Identifier: Apache-2.0

//! The in-process trace report (`quantstratum-docs:
//! karyos/design/trace-data-path.md`, "Journals and the report", batch
//! p6b2). It is built here, not in the driver, so the SPEC.md §14 crate
//! graph stays unchanged (ACS 12439, on the owner decision ACS 11410):
//! whoever built the agents registers their collectors with the facts the
//! client handles know (a subscription's join position, and its delivery
//! boundary at its terminal close), drains them on the control path, and
//! reads per-stream latency histograms between `Publish` and
//! `SubscriberPoll` and each trace's attribution verdict, following
//! trace-attribution.md.
//!
//! A trace's expected set is the union, over its messages, of the
//! publishing journal and the subscription journals eligible for the
//! message: those that joined at or before its position and whose delivery
//! boundary passed it. Any journal still open could still be eligible: an
//! open publisher journal could publish another message of the trace, such
//! as a child. So the set is frozen, and a final `Complete` possible, only
//! once every journal registered in the report reached its terminal close
//! (coordinator decision ACS 12662 on trace-data-path.md, "Trace-wide
//! expected set"); until then a trace gets a provisional answer.
//! `Incomplete` is final as soon as it is reached.
//!
//! Automatic calibration: two [`ClockProvenance::StdMonotonic`] clocks with
//! the same epoch (one process start) share their source, so a latency
//! between them uses offset 0, drift 0 and the sum of their declared
//! resolutions, valid over the times observed so far. Register only
//! journals of agents in this process; an opaque clock gets no automatic
//! calibration, only those given to [`TraceReport::add_calibration`].

use std::collections::{BTreeMap, HashMap};

use crate::attribution::{AttributionConfig, Attributor, Verdict, combine};
use crate::clocks::{Calibration, ClockKey, Observation, latency};
use crate::error::TraceError;
use crate::histogram::{Histogram, HistogramError};
use crate::journal::{Collected, ObserverId, TraceCollector};
use crate::record::{ObservedTime, Point, PublicationId};
use crate::trace_clock::ClockProvenance;

/// A journal registered with a [`TraceReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JournalId(usize);

/// What the report can say about a trace now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceAnswer {
    /// Final: no further evidence changes it.
    Final(Verdict),
    /// No loss seen so far; not a verdict.
    Provisional,
    /// The report holds no observation of this trace.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Publisher,
    Subscriber { join: u64 },
}

#[derive(Debug)]
struct Journal {
    collector: TraceCollector,
    observer: ObserverId,
    attributor: Attributor,
    kind: Kind,
    publication: PublicationId,
    provenance: ClockProvenance,
    /// The owner closed the handle (its writer is closed); for a
    /// subscription, with its final delivery boundary.
    owner_closed: bool,
    boundary: Option<u64>,
    /// The collector reported `Closed`.
    drained: bool,
    /// Final verdicts per trace, once terminally closed.
    finals: Option<BTreeMap<[u64; 2], Verdict>>,
    /// Traces that found the attributor's table full: final `Incomplete`.
    untracked: Vec<[u64; 2]>,
    /// Observed times per clock `(domain, epoch)`: lowest, highest, and the
    /// declared uncertainty.
    clocks: BTreeMap<(u64, u64), (u64, u64, u64)>,
}

impl Journal {
    fn terminal(&self) -> bool {
        self.finals.is_some()
    }

    /// For a subscription journal of `publication`, whether it is expected
    /// for a message at `position`: `Some` once decided.
    fn eligible(&self, publication: &PublicationId, position: u64) -> Option<bool> {
        let Kind::Subscriber { join } = self.kind else {
            return Some(false);
        };
        if self.publication != *publication || join > position {
            return Some(false);
        }
        self.boundary.map(|boundary| boundary > position)
    }

    /// This journal's verdict for a trace: final, provisional, or absent.
    fn verdict(&self, trace_id: [u64; 2]) -> Option<Verdict> {
        if self.untracked.contains(&trace_id) {
            return Some(Verdict::Incomplete);
        }
        match &self.finals {
            Some(finals) => finals.get(&trace_id).copied(),
            None => self.attributor.provisional(trace_id),
        }
    }

    fn observation(&self, observed: &ObservedTime) -> Observation {
        Observation {
            clock: ClockKey {
                observer: self.observer,
                domain: observed.clock,
                epoch: observed.epoch,
            },
            time: observed.time,
            uncertainty: observed.uncertainty,
        }
    }
}

/// One message of a trace, keyed by its publication, lane and position.
#[derive(Debug, Default)]
struct Message {
    trace_id: [u64; 2],
    publish: Option<(JournalId, ObservedTime)>,
    polls: Vec<(JournalId, ObservedTime)>,
}

/// `[low - by, high + by]`, each end clamped to the axis end, written out
/// explicitly (ADR-0007 keeps `saturating_*` out of positions and counters).
#[expect(
    clippy::implicit_saturating_sub,
    reason = "ADR-0007 keeps saturating_* out of positions and counters; a window end clamped to the axis end is written out explicitly"
)]
fn widened(low: u64, high: u64, by: u64) -> (u64, u64) {
    let from = if by > low { 0 } else { low - by };
    let to = if by > u64::MAX - high {
        u64::MAX
    } else {
        high + by
    };
    (from, to)
}

/// Histogram parameters of [`TraceReport::latencies`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistogramConfig {
    /// Significant decimal digits.
    pub digits: u8,
    /// Highest trackable value, in `unit`.
    pub highest: u64,
    /// Unit of the recorded latencies, in clock units.
    pub unit: u64,
}

/// The report over a set of journals (control path).
#[derive(Debug)]
pub struct TraceReport {
    attribution: AttributionConfig,
    histogram: HistogramConfig,
    journals: Vec<Journal>,
    messages: HashMap<(PublicationId, u8, u64), Message>,
    calibrations: Vec<Calibration>,
}

impl TraceReport {
    /// An empty report whose journals use `attribution` and whose latency
    /// histograms use `histogram`.
    #[must_use]
    pub fn new(attribution: AttributionConfig, histogram: HistogramConfig) -> Self {
        Self {
            attribution,
            histogram,
            journals: Vec::new(),
            messages: HashMap::new(),
            calibrations: Vec::new(),
        }
    }

    fn add(
        &mut self,
        collector: TraceCollector,
        provenance: ClockProvenance,
        kind: Kind,
        publication: PublicationId,
    ) -> Result<JournalId, TraceError> {
        let id = JournalId(self.journals.len());
        self.journals.push(Journal {
            observer: collector.observer(),
            collector,
            attributor: Attributor::new(self.attribution)?,
            kind,
            publication,
            provenance,
            owner_closed: false,
            boundary: None,
            drained: false,
            finals: None,
            untracked: Vec::new(),
            clocks: BTreeMap::new(),
        });
        Ok(id)
    }

    /// Registers the journal of a publication handle of `publication`,
    /// stamped by a clock of `provenance`.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::Attribution`] when the attributor's tables
    /// cannot be allocated.
    pub fn add_publisher(
        &mut self,
        collector: TraceCollector,
        provenance: ClockProvenance,
        publication: PublicationId,
    ) -> Result<JournalId, TraceError> {
        self.add(collector, provenance, Kind::Publisher, publication)
    }

    /// Registers the journal of a subscription of `publication` that joined
    /// at stream position `join`.
    ///
    /// # Errors
    ///
    /// As [`TraceReport::add_publisher`].
    pub fn add_subscriber(
        &mut self,
        collector: TraceCollector,
        provenance: ClockProvenance,
        publication: PublicationId,
        join: u64,
    ) -> Result<JournalId, TraceError> {
        self.add(
            collector,
            provenance,
            Kind::Subscriber { join },
            publication,
        )
    }

    /// Records the terminal close of a journal's handle, after its writer
    /// closed and every observation it will make was made. A subscription
    /// passes its final delivery boundary, which decides the messages it is
    /// expected for; a publication passes `None`.
    pub fn closed(&mut self, journal: JournalId, boundary: Option<u64>) {
        if let Some(journal) = self.journals.get_mut(journal.0) {
            journal.owner_closed = true;
            if matches!(journal.kind, Kind::Subscriber { .. }) {
                journal.boundary = boundary;
            }
        }
    }

    /// Adds an explicit calibration, for clocks the report cannot calibrate
    /// automatically.
    pub fn add_calibration(&mut self, calibration: Calibration) {
        self.calibrations.push(calibration);
    }

    /// Drains every journal: feeds its attributor, keeps its observations,
    /// and computes final verdicts for journals that reached their terminal
    /// close.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::NotClosed`] only if the attributor's close
    /// preconditions are broken, which this report never does.
    pub fn drain(&mut self) -> Result<(), TraceError> {
        for index in 0..self.journals.len() {
            self.drain_journal(index)?;
        }
        Ok(())
    }

    fn drain_journal(&mut self, index: usize) -> Result<(), TraceError> {
        let id = JournalId(index);
        let Some(journal) = self.journals.get_mut(index) else {
            return Ok(());
        };
        if journal.terminal() {
            return Ok(());
        }
        loop {
            let item = journal.collector.take();
            if let crate::attribution::Observed::Untracked { trace_id } =
                journal.attributor.observe(&item)
            {
                journal.untracked.push(trace_id);
            }
            match item {
                Collected::Record { record, .. } => {
                    let observed = record.observed;
                    let clock = journal
                        .clocks
                        .entry((observed.clock, observed.epoch))
                        .or_insert((observed.time, observed.time, observed.uncertainty));
                    clock.0 = clock.0.min(observed.time);
                    clock.1 = clock.1.max(observed.time);
                    clock.2 = clock.2.max(observed.uncertainty);
                    let message = self
                        .messages
                        .entry((record.publication, record.lane, record.position))
                        .or_default();
                    message.trace_id = record.ids.trace_id;
                    match record.point {
                        Point::Publish => message.publish = Some((id, observed)),
                        Point::SubscriberPoll => message.polls.push((id, observed)),
                        _ => {}
                    }
                }
                Collected::Corrupt { .. } => {}
                Collected::Empty => break,
                Collected::Closed => {
                    journal.drained = true;
                    break;
                }
            }
        }
        let losses = journal.collector.losses();
        let (attempted, stored) = (losses.attempted, losses.stored);
        journal.attributor.observe_snapshot(attempted, stored);
        if journal.drained && journal.owner_closed {
            let finals = journal.attributor.close(attempted)?.collect();
            journal.finals = Some(finals);
        }
        Ok(())
    }

    /// What the report can say about the trace `trace_id` now.
    #[must_use]
    pub fn trace(&self, trace_id: [u64; 2]) -> TraceAnswer {
        let messages: Vec<_> = self
            .messages
            .iter()
            .filter(|(_, message)| message.trace_id == trace_id)
            .collect();
        if messages.is_empty() {
            return TraceAnswer::Unknown;
        }
        let mut expected: Vec<usize> = Vec::new();
        let mut decided = true;
        let mut publish_missing = false;
        // Per message: an eligible subscription journal, terminally closed
        // without this message's SubscriberPoll, makes the trace Incomplete,
        // even if the journal holds the trace for another message.
        let mut poll_missing = false;
        for ((publication, _lane, position), message) in &messages {
            match message.publish {
                Some((JournalId(journal), _)) => expected.push(journal),
                None => publish_missing = true,
            }
            // Every publisher journal of this publication could hold the
            // missing Publish record until it is terminally closed.
            for (index, journal) in self.journals.iter().enumerate() {
                if journal.kind == Kind::Publisher && journal.publication == *publication {
                    decided &= journal.terminal();
                    continue;
                }
                match journal.eligible(publication, *position) {
                    Some(true) => {
                        expected.push(index);
                        let polled = message
                            .polls
                            .iter()
                            .any(|(JournalId(journal), _)| *journal == index);
                        if journal.terminal() && !polled {
                            poll_missing = true;
                        }
                    }
                    Some(false) => {}
                    None => decided = false,
                }
            }
        }
        expected.sort_unstable();
        expected.dedup();
        let verdicts: Vec<(bool, Option<Verdict>)> = expected
            .iter()
            .filter_map(|index| self.journals.get(*index))
            .map(|journal| (journal.terminal(), journal.verdict(trace_id)))
            .collect();
        // Incomplete is final as soon as it is reached: a reported loss, or
        // a terminally closed expected journal without the trace.
        let incomplete = poll_missing
            || verdicts.iter().any(|(terminal, verdict)| {
                *verdict == Some(Verdict::Incomplete) || (*terminal && verdict.is_none())
            });
        if incomplete {
            return TraceAnswer::Final(Verdict::Incomplete);
        }
        let all_terminal = verdicts.iter().all(|(terminal, _)| *terminal);
        // Every registered journal, not only those already holding the
        // trace: an open one could still add a message of it.
        let registered_terminal = self.journals.iter().all(Journal::terminal);
        if !decided || !all_terminal || !registered_terminal {
            return TraceAnswer::Provisional;
        }
        if publish_missing {
            return TraceAnswer::Final(Verdict::Incomplete);
        }
        TraceAnswer::Final(combine(verdicts.into_iter().map(|(_, verdict)| verdict)))
    }

    /// The automatic calibrations between standard clocks of one process,
    /// over the times observed so far, with the explicit ones.
    fn calibrations(&self) -> Vec<Calibration> {
        let mut out = self.calibrations.clone();
        for from in self.journals.iter().filter(|j| j.kind == Kind::Publisher) {
            for to in self.journals.iter().filter(|j| j.kind != Kind::Publisher) {
                if from.provenance != ClockProvenance::StdMonotonic
                    || to.provenance != ClockProvenance::StdMonotonic
                {
                    continue;
                }
                for (&(domain, epoch), &(low, high, resolution)) in &from.clocks {
                    for (&(to_domain, to_epoch), &(_, _, to_resolution)) in &to.clocks {
                        if to_epoch != epoch {
                            continue;
                        }
                        // The interval widens to the axis ends, which only
                        // makes it larger: the conservative direction.
                        let Some(offset_uncertainty) = resolution.checked_add(to_resolution) else {
                            continue;
                        };
                        let (valid_from, valid_to) = widened(low, high, resolution);
                        out.push(Calibration {
                            from: ClockKey {
                                observer: from.observer,
                                domain,
                                epoch,
                            },
                            to: ClockKey {
                                observer: to.observer,
                                domain: to_domain,
                                epoch,
                            },
                            reference: low,
                            offset: 0,
                            offset_uncertainty,
                            drift: 0,
                            drift_uncertainty: 0,
                            valid_from,
                            valid_to,
                        });
                    }
                }
            }
        }
        out
    }

    /// Per-publication latency histograms between each message's `Publish`
    /// observation and each of its `SubscriberPoll` observations. A pair
    /// without a usable calibration is recorded as unavailable with its
    /// reason. The interval may have a negative lower bound: the `Publish`
    /// time is taken after the commit.
    ///
    /// # Errors
    ///
    /// Returns the histogram's errors for an invalid configuration.
    pub fn latencies(&self) -> Result<Vec<(PublicationId, Histogram)>, HistogramError> {
        let calibrations = self.calibrations();
        let mut out: Vec<(PublicationId, Histogram)> = Vec::new();
        for ((publication, _, _), message) in &self.messages {
            let Some((JournalId(from), published)) = message.publish else {
                continue;
            };
            let Some(from) = self.journals.get(from) else {
                continue;
            };
            let a = from.observation(&published);
            for (JournalId(to), polled) in &message.polls {
                let Some(to) = self.journals.get(*to) else {
                    continue;
                };
                let b = to.observation(polled);
                let index = match out.iter().position(|(p, _)| p == publication) {
                    Some(index) => index,
                    None => {
                        out.push((
                            *publication,
                            Histogram::new(
                                self.histogram.digits,
                                self.histogram.highest,
                                self.histogram.unit,
                            )?,
                        ));
                        out.len() - 1
                    }
                };
                if let Some((_, histogram)) = out.get_mut(index) {
                    histogram.record(latency(&a, &b, &calibrations))?;
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
