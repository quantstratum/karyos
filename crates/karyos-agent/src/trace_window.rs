// SPDX-License-Identifier: Apache-2.0

//! The trace latency window (quantstratum-docs:
//! karyos/design/agent-trace-window.md, M6c): a follower of a driver's
//! trace mirror whose memory is bounded by configuration.
//!
//! - **What it reports.** Per publication lane, the latencies between a
//!   message's `Publish` and each `SubscriberPoll` of it that the mirror
//!   delivered, recorded in the last `window` of the agent's time. Never a
//!   trace verdict: those need the expected sets of `karyos-trace`'s
//!   report, which stays with the tool.
//! - **Matching.** A record is filed under its publication registration,
//!   incarnation, lane and position, in a pending map of at most
//!   `max_pending` keys; a `Publish` pairs with every poll of its key, in
//!   whichever order the mirror drains them. Network journals are counted
//!   and ignored in this version.
//! - **Calibration.** As `karyos-trace`'s report: two standard monotonic
//!   clocks, or two host monotonic clocks whose journals are both in the
//!   driver's time namespace, with equal epochs share their source, and the
//!   pair is calibrated with offset 0, drift 0 and the two observations'
//!   uncertainties. Any other pair is recorded as unavailable.
//! - **The window.** The agent's time is cut into `slices` slices of
//!   `window / slices`; a pair is recorded in the slice of the scan that
//!   made it, and the reported histogram merges the slices of the last
//!   window. Pending keys older than the window age out, counted.
//! - **Bounds.** Journals, pending keys, polls per key and lanes are each
//!   bounded; what a bound refuses is counted, never kept.

use std::collections::{BTreeMap, VecDeque};

use karyos_sys::trace_mirror::{EntryRead, TimeNamespace, TraceMirrorReader};
use karyos_trace::{
    Calibration, ClockKey, ClockProvenance, Histogram, Latency, ObserverId, Point, Quantile,
    RECORD_WORDS, TraceRecord, Unavailable, decode_record,
};

use crate::api::{LaneLatency, QuantileBounds, TraceCounts};

/// Histogram significant digits, as the trace tool's.
const DIGITS: u8 = 3;
/// Histogram highest magnitude: 10 s in nanoseconds.
const HIGHEST: u64 = 10_000_000_000;

/// The window's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WindowConfig {
    /// The window, in nanoseconds of the agent's host clock.
    pub window: u64,
    /// Slices of the window, at least 1.
    pub slices: u64,
    /// Journals tracked at most.
    pub max_journals: usize,
    /// Pending message keys at most.
    pub max_pending: usize,
    /// Polls kept per pending key at most.
    pub max_polls: usize,
    /// Publication lanes with histograms at most.
    pub max_lanes: usize,
}

impl Default for WindowConfig {
    /// A minute in six slices; 1024 journals, 65 536 pending keys of up to
    /// 16 polls, and 256 lanes.
    fn default() -> Self {
        Self {
            window: 60_000_000_000,
            slices: 6,
            max_journals: 1024,
            max_pending: 65_536,
            max_polls: 16,
            max_lanes: 256,
        }
    }
}

impl WindowConfig {
    /// With a window of `window` nanoseconds in `slices` slices.
    #[must_use]
    pub fn with_window(mut self, window: u64, slices: u64) -> Self {
        self.window = window;
        self.slices = slices;
        self
    }

    /// With the bounds on journals, pending keys, polls per key and lanes.
    #[must_use]
    pub fn with_bounds(
        mut self,
        max_journals: usize,
        max_pending: usize,
        max_polls: usize,
        max_lanes: usize,
    ) -> Self {
        self.max_journals = max_journals;
        self.max_pending = max_pending;
        self.max_polls = max_polls;
        self.max_lanes = max_lanes;
        self
    }

    /// One slice's length; at least 1.
    fn slice(&self) -> u64 {
        self.window
            .checked_div(self.slices.max(1))
            .unwrap_or(self.window)
            .max(1)
    }
}

/// What a pair's calibration needs of a journal's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JournalClock {
    provenance: ClockProvenance,
    same_namespace: bool,
}

/// Whether two journal clocks read one source (the report's rule).
fn shared_source(a: JournalClock, b: JournalClock) -> bool {
    match (a.provenance, b.provenance) {
        (ClockProvenance::StdMonotonic, ClockProvenance::StdMonotonic) => true,
        (ClockProvenance::HostMonotonic, ClockProvenance::HostMonotonic) => {
            a.same_namespace && b.same_namespace
        }
        _ => false,
    }
}

/// A message: its publication registration, incarnation, lane, position.
type Key = (u64, u64, u8, u64);

/// One observation of a message.
#[derive(Debug, Clone, Copy)]
struct Seen {
    clock: JournalClock,
    observer: ObserverId,
    time: u64,
    domain: u64,
    epoch: u64,
    uncertainty: u64,
}

/// A message waiting for its pair.
#[derive(Debug)]
struct Pending {
    /// The agent's time it was first seen.
    since: u64,
    publish: Option<Seen>,
    polls: Vec<Seen>,
}

/// One lane's histograms, one per slice.
#[derive(Debug)]
struct Slices {
    /// (slice number, histogram), newest last.
    slices: VecDeque<(u64, Histogram)>,
}

/// The follower of one driver's trace mirror.
#[derive(Debug)]
pub(crate) struct TraceWindow {
    config: WindowConfig,
    driver: [u64; 2],
    cursor: u64,
    /// The clock of each tracked journal; `None` for a network journal.
    journals: BTreeMap<u64, Option<JournalClock>>,
    pending: BTreeMap<Key, Pending>,
    lanes: BTreeMap<(u64, u64, u8), Slices>,
    counts: TraceCounts,
}

impl TraceWindow {
    /// A follower of the mirror of the driver whose `driver_id` is
    /// `driver`.
    pub(crate) fn new(config: WindowConfig, driver: [u64; 2]) -> Self {
        Self {
            config,
            driver,
            cursor: 0,
            journals: BTreeMap::new(),
            pending: BTreeMap::new(),
            lanes: BTreeMap::new(),
            counts: TraceCounts::default(),
        }
    }

    /// Reads the table and the ring at the agent's time `now`.
    pub(crate) fn scan(&mut self, mirror: &TraceMirrorReader, now: u64) {
        for index in 0..mirror.entries() {
            if let EntryRead::Entry(entry) = mirror.entry(index) {
                let clock = (!entry.kind.is_network()).then_some(JournalClock {
                    provenance: ClockProvenance::from_word(entry.provenance),
                    same_namespace: entry.time_namespace == TimeNamespace::Same,
                });
                self.journal(entry.journal, clock);
            }
        }
        let mut cursor = self.cursor;
        let mut records = Vec::new();
        let scan = mirror.scan(&mut cursor, |record| {
            let decoded = <&[u64; RECORD_WORDS]>::try_from(record.payload)
                .ok()
                .and_then(|words| decode_record(words).ok())
                .map(|(decoded, _)| decoded);
            records.push((record.journal, decoded));
        });
        self.cursor = cursor;
        count(&mut self.counts.mirror_overwritten, scan.overwritten);
        for (journal, decoded) in records {
            match decoded {
                Some(record) => self.observe(journal, &record, now),
                None => count(&mut self.counts.malformed, 1),
            }
        }
        self.age(now);
    }

    /// Notes a journal's clock, `None` for a network journal.
    fn journal(&mut self, journal: u64, clock: Option<JournalClock>) {
        if self.journals.contains_key(&journal) {
            return;
        }
        if self.journals.len() >= self.config.max_journals {
            count(&mut self.counts.journals_dropped, 1);
            return;
        }
        let _ = self.journals.insert(journal, clock);
    }

    /// Files one record of `journal` at the agent's time `now`.
    fn observe(&mut self, journal: u64, record: &TraceRecord, now: u64) {
        count(&mut self.counts.records, 1);
        let clock = match self.journals.get(&journal) {
            None => return count(&mut self.counts.unknown_journal, 1),
            Some(None) => return count(&mut self.counts.network_ignored, 1),
            Some(Some(clock)) => *clock,
        };
        let poll = match record.point {
            Point::Publish => false,
            Point::SubscriberPoll => true,
            _ => return count(&mut self.counts.network_ignored, 1),
        };
        let seen = Seen {
            clock,
            observer: ObserverId {
                driver: self.driver,
                journal,
            },
            time: record.observed.time,
            domain: record.observed.clock,
            epoch: record.observed.epoch,
            uncertainty: record.observed.uncertainty,
        };
        let key = (
            record.publication.registration,
            record.publication.incarnation,
            record.lane,
            record.position,
        );
        if !self.pending.contains_key(&key) && self.pending.len() >= self.config.max_pending {
            return count(&mut self.counts.pending_dropped, 1);
        }
        let pending = self.pending.entry(key).or_insert(Pending {
            since: now,
            publish: None,
            polls: Vec::new(),
        });
        let mut pairs = Vec::new();
        if poll {
            if let Some(publish) = pending.publish {
                pairs.push((publish, seen));
            } else if pending.polls.len() < self.config.max_polls {
                pending.polls.push(seen);
            } else {
                count(&mut self.counts.polls_dropped, 1);
            }
        } else if pending.publish.is_none() {
            pending.publish = Some(seen);
            pairs.extend(pending.polls.drain(..).map(|poll| (seen, poll)));
        }
        let lane = (key.0, key.1, key.2);
        for (publish, poll) in pairs {
            self.record(lane, latency(&publish, &poll), now);
        }
    }

    /// Records one pair's latency in `lane`'s slice of `now`.
    fn record(&mut self, lane: (u64, u64, u8), latency: Latency, now: u64) {
        if !self.lanes.contains_key(&lane) && self.lanes.len() >= self.config.max_lanes {
            return count(&mut self.counts.lanes_dropped, 1);
        }
        let slice = now.checked_div(self.config.slice()).unwrap_or(0);
        let slices = self.config.slices.max(1);
        let lane = self.lanes.entry(lane).or_insert(Slices {
            slices: VecDeque::new(),
        });
        if lane
            .slices
            .back()
            .is_none_or(|(number, _)| *number != slice)
        {
            let Ok(histogram) = Histogram::new(DIGITS, HIGHEST, 1) else {
                return;
            };
            lane.slices.push_back((slice, histogram));
        }
        // Slices older than the window are dropped: their pairs leave it.
        while lane
            .slices
            .front()
            .is_some_and(|(number, _)| number.checked_add(slices).is_some_and(|end| end <= slice))
        {
            let _ = lane.slices.pop_front();
        }
        if let Some((_, histogram)) = lane.slices.back_mut() {
            // An overflow marks the histogram incomplete, which the view
            // reports.
            let _ = histogram.record(latency);
        }
    }

    /// Ages out pending keys older than the window.
    fn age(&mut self, now: u64) {
        let window = self.config.window;
        let mut aged = 0;
        self.pending.retain(|_, pending| {
            let keep = now
                .checked_sub(pending.since)
                .is_none_or(|age| age < window);
            if !keep {
                aged += 1;
            }
            keep
        });
        count(&mut self.counts.aged_out, aged);
    }

    /// The window's histograms at the agent's time `now`, and the counts.
    pub(crate) fn view(&self, now: u64) -> (Vec<LaneLatency>, TraceCounts) {
        let slice = now.checked_div(self.config.slice()).unwrap_or(0);
        let slices = self.config.slices.max(1);
        let mut out = Vec::new();
        for (&(stream, incarnation, lane), held) in &self.lanes {
            let Ok(mut merged) = Histogram::new(DIGITS, HIGHEST, 1) else {
                continue;
            };
            let mut any = false;
            for (number, histogram) in &held.slices {
                if number.checked_add(slices).is_some_and(|end| end > slice) {
                    any = true;
                    let _ = merged.merge(histogram);
                }
            }
            if !any {
                continue;
            }
            let quantile = |numerator, denominator| match merged.quantile(numerator, denominator) {
                Ok(Quantile::Interval { low, high }) => Some(QuantileBounds { low, high }),
                _ => None,
            };
            let unavailable = [
                Unavailable::NoCalibration,
                Unavailable::NotValid,
                Unavailable::Ambiguous,
                Unavailable::Overflow,
            ]
            .iter()
            .map(|reason| merged.unavailable(*reason))
            .fold(0u64, |sum, value| sum.checked_add(value).unwrap_or(sum));
            out.push(LaneLatency {
                stream,
                incarnation,
                lane,
                available: merged.available(),
                unavailable,
                incomplete: merged.is_incomplete(),
                p50: quantile(1, 2),
                p90: quantile(9, 10),
                p99: quantile(99, 100),
                p999: quantile(999, 1000),
                max: quantile(1, 1),
            });
        }
        let mut counts = self.counts;
        counts.pending = u64::try_from(self.pending.len()).unwrap_or(u64::MAX);
        (out, counts)
    }
}

/// `poll - publish` under the report's automatic calibration, or
/// unavailable.
fn latency(publish: &Seen, poll: &Seen) -> Latency {
    if !shared_source(publish.clock, poll.clock) || publish.epoch != poll.epoch {
        return Latency::Unavailable(Unavailable::NoCalibration);
    }
    let key = |seen: &Seen| ClockKey {
        observer: seen.observer,
        domain: seen.domain,
        epoch: seen.epoch,
    };
    // A publish interval past either end of the clock's axis fits no
    // calibration.
    let (Some(offset_uncertainty), Some(valid_from), Some(valid_to)) = (
        publish.uncertainty.checked_add(poll.uncertainty),
        publish.time.checked_sub(publish.uncertainty),
        publish.time.checked_add(publish.uncertainty),
    ) else {
        return Latency::Unavailable(Unavailable::Overflow);
    };
    let calibration = Calibration {
        from: key(publish),
        to: key(poll),
        reference: publish.time,
        offset: 0,
        offset_uncertainty,
        drift: 0,
        drift_uncertainty: 0,
        valid_from,
        valid_to,
    };
    let observation = |seen: &Seen| karyos_trace::Observation {
        clock: key(seen),
        time: seen.time,
        uncertainty: seen.uncertainty,
    };
    karyos_trace::latency(&observation(publish), &observation(poll), &[calibration])
}

/// Adds `by` to a count; a count that cannot rise keeps its value.
fn count(value: &mut u64, by: u64) {
    if let Some(next) = value.checked_add(by) {
        *value = next;
    }
}

#[cfg(test)]
mod tests;
