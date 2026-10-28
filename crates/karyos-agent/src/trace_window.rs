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
//!   uncertainties. The report uses each journal's largest uncertainty
//!   instead; they agree for clocks of constant uncertainty, as every
//!   monotonic clock's is, and the pair's own is never wider. Any other
//!   pair is recorded as unavailable.
//! - **Forgetting.** A journal leaves the map one window after it left the
//!   table (journal numbers are never reused), and a lane one window after
//!   its last pair (a new incarnation is a new lane), so the bounds hold for
//!   a run of any length.
//! - **The window.** The agent's time is cut into `slices` slices of
//!   `window / slices`; a pair is recorded in the slice of the scan that
//!   made it, and the reported histogram merges the slices of the last
//!   window. Pending keys older than the window age out, counted.
//! - **Bounds.** Journals, pending keys, polls per key and lanes are each
//!   bounded; what a bound refuses is counted, never kept. The rolling
//!   view's histograms are dense: at most `max_lanes x slices` of them, each
//!   [`HISTOGRAM_BYTES`].
//! - **Buckets (R-CORE-23).** A slice the scan has moved past is closed:
//!   no pair is recorded in it again, so it shares no record with any other
//!   and is a disjoint bucket. It is kept, sparse (each lane's
//!   [`HistogramCounts`]), with the loss counted while it was current,
//!   under `max_bucket_bytes`: retained buckets never hold more than that
//!   budget, the oldest evicted first. A bucket larger than the budget on
//!   its own is not kept and evicts nothing; its number is remembered for
//!   its own refusal. Reading is not consuming: there is no reset, any
//!   number of readers read the same buckets, each with its own cursor,
//!   and a reader that crashes reads the same bucket again. `epoch`
//!   identifies this window's run: slice numbers of another run are not a
//!   continuation.

use std::collections::{BTreeMap, VecDeque};

use karyos_sys::trace_mirror::{EntryRead, TimeNamespace, TraceMirrorReader};
use karyos_trace::{
    Calibration, ClockKey, ClockProvenance, Histogram, HistogramCounts, Latency, ObserverId, Point,
    Quantile, RECORD_WORDS, TraceRecord, Unavailable, decode_record,
};

use crate::api::{BucketLane, LaneLatency, QuantileBounds, TraceBucket, TraceCounts};

/// Histogram significant digits, as the trace tool's.
const DIGITS: u8 = 3;
/// Histogram highest magnitude: 10 s in nanoseconds.
const HIGHEST: u64 = 10_000_000_000;
/// One dense window histogram's memory at [`DIGITS`] and [`HIGHEST`]: its
/// 24 745 buckets in four `u64` arrays (two sides, two signs).
pub const HISTOGRAM_BYTES: usize = 24_745 * 4 * 8;
/// A retained bucket's bytes besides its lanes' counts, and each lane's
/// key: what [`Bucket::bytes`] adds to the counts' own.
const BUCKET_OVERHEAD: usize = 128;
const LANE_OVERHEAD: usize = 24;
/// Bucket numbers refused as over budget remembered at most.
const OVER_BUDGET_KEPT: usize = 64;

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
    /// Bytes the retained closed buckets hold at most (R-CORE-23).
    pub max_bucket_bytes: usize,
}

impl Default for WindowConfig {
    /// A minute in six slices; 1024 journals, 65 536 pending keys of up to
    /// 16 polls, 256 lanes, and 64 MiB of retained buckets.
    fn default() -> Self {
        Self {
            window: 60_000_000_000,
            slices: 6,
            max_journals: 1024,
            max_pending: 65_536,
            max_polls: 16,
            max_lanes: 256,
            max_bucket_bytes: 64 << 20,
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

    /// With `bytes` of retained buckets at most (R-CORE-23).
    #[must_use]
    pub fn with_bucket_budget(mut self, bytes: usize) -> Self {
        self.max_bucket_bytes = bytes;
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

/// One closed slice, kept (R-CORE-23).
#[derive(Debug)]
struct Bucket {
    number: u64,
    lanes: Vec<((u64, u64, u8), HistogramCounts)>,
    loss: Loss,
    bytes: usize,
}

/// The loss counted while a slice was current: what its histograms miss.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Loss {
    /// Messages refused at the pending bound.
    pub pending_dropped: u64,
    /// Polls past the bound of one message.
    pub polls_dropped: u64,
    /// Pairs of lanes past the bound.
    pub lanes_dropped: u64,
    /// Messages aged out unmatched.
    pub aged_out: u64,
    /// Mirror records overwritten unread.
    pub mirror_overwritten: u64,
    /// Records of journals past the bound.
    pub journals_dropped: u64,
}

impl Loss {
    fn of(counts: &TraceCounts) -> Self {
        Self {
            pending_dropped: counts.pending_dropped,
            polls_dropped: counts.polls_dropped,
            lanes_dropped: counts.lanes_dropped,
            aged_out: counts.aged_out,
            mirror_overwritten: counts.mirror_overwritten,
            journals_dropped: counts.journals_dropped,
        }
    }

    fn since(self, start: Self) -> Self {
        let less = |now: u64, then: u64| now.saturating_sub(then);
        Self {
            pending_dropped: less(self.pending_dropped, start.pending_dropped),
            polls_dropped: less(self.polls_dropped, start.polls_dropped),
            lanes_dropped: less(self.lanes_dropped, start.lanes_dropped),
            aged_out: less(self.aged_out, start.aged_out),
            mirror_overwritten: less(self.mirror_overwritten, start.mirror_overwritten),
            journals_dropped: less(self.journals_dropped, start.journals_dropped),
        }
    }

    /// Whether anything was lost.
    #[must_use]
    pub fn any(&self) -> bool {
        *self != Self::default()
    }
}

/// Why a bucket read is refused (R-CORE-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketRefusal {
    /// The reader's cursor belongs to another run of the window.
    EpochChanged {
        /// This run's epoch.
        epoch: u64,
        /// The oldest bucket number kept.
        oldest: u64,
    },
    /// The bucket is no longer kept.
    Expired {
        /// The oldest bucket number kept.
        oldest: u64,
    },
    /// The bucket was larger than the whole budget and never kept.
    OverBudget {
        /// Its number.
        number: u64,
    },
}

/// What a bucket read returns: the buckets from the asked number on, in
/// order, with no gap.
#[derive(Debug)]
pub struct BucketRead {
    /// This run's epoch.
    pub epoch: u64,
    /// One slice's length, in ns.
    pub slice_ns: u64,
    /// The slice now current: buckets are the numbers below it.
    pub current: u64,
    /// The oldest bucket number kept.
    pub oldest: u64,
    /// The buckets, oldest first.
    pub buckets: Vec<TraceBucket>,
}

/// The follower of one driver's trace mirror.
#[derive(Debug)]
pub(crate) struct TraceWindow {
    config: WindowConfig,
    driver: [u64; 2],
    cursor: u64,
    /// Each tracked journal: its clock (`None` for a network journal) and
    /// the agent's time of the last scan that saw it in the table.
    journals: BTreeMap<u64, (Option<JournalClock>, u64)>,
    pending: BTreeMap<Key, Pending>,
    lanes: BTreeMap<(u64, u64, u8), Slices>,
    counts: TraceCounts,
    /// This run's identity (R-CORE-23): a nonce drawn at creation.
    epoch: u64,
    /// The slice current at the last scan, and the loss counts at its start.
    current: Option<(u64, Loss)>,
    /// Closed slices kept, oldest first, and their bytes.
    closed: VecDeque<Bucket>,
    closed_bytes: usize,
    /// Numbers of buckets refused as over budget, the newest kept.
    over_budget: VecDeque<u64>,
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
            epoch: draw_epoch(),
            current: None,
            closed: VecDeque::new(),
            closed_bytes: 0,
            over_budget: VecDeque::with_capacity(OVER_BUDGET_KEPT),
        }
    }

    /// This run's epoch.
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Closes the slices the agent's time `now` has moved past
    /// (R-CORE-23): the slice current at the last scan becomes a bucket,
    /// with the loss counted while it was current.
    fn close_slices(&mut self, now: u64) {
        let slice = now.checked_div(self.config.slice()).unwrap_or(0);
        let loss = Loss::of(&self.counts);
        let Some((current, start)) = self.current else {
            self.current = Some((slice, loss));
            return;
        };
        if slice <= current {
            return;
        }
        let mut lanes = Vec::new();
        for (&key, held) in &self.lanes {
            if let Some((_, histogram)) = held.slices.iter().find(|(number, _)| *number == current)
            {
                lanes.push((key, histogram.counts()));
            }
        }
        let bytes = lanes.iter().fold(BUCKET_OVERHEAD, |sum, (_, counts)| {
            sum.saturating_add(counts.bytes())
                .saturating_add(LANE_OVERHEAD)
        });
        self.current = Some((slice, loss));
        let bucket = Bucket {
            number: current,
            lanes,
            loss: loss.since(start),
            bytes,
        };
        if bucket.bytes > self.config.max_bucket_bytes {
            // Larger than the whole budget: not kept, and nothing evicted
            // for it.
            if self.over_budget.len() >= OVER_BUDGET_KEPT {
                let _ = self.over_budget.pop_front();
            }
            self.over_budget.push_back(current);
            count(&mut self.counts.buckets_over_budget, 1);
            return;
        }
        while self.closed_bytes.saturating_add(bucket.bytes) > self.config.max_bucket_bytes {
            let Some(old) = self.closed.pop_front() else {
                break;
            };
            self.closed_bytes = self.closed_bytes.saturating_sub(old.bytes);
            count(&mut self.counts.buckets_evicted, 1);
        }
        self.closed_bytes = self.closed_bytes.saturating_add(bucket.bytes);
        self.closed.push_back(bucket);
    }

    /// The bytes the retained buckets hold (tests).
    #[cfg(test)]
    pub(crate) fn bucket_bytes(&self) -> usize {
        self.closed_bytes
    }

    /// Up to `count` buckets from number `from` on, of the run `epoch`
    /// when given (R-CORE-23). A number below the current slice that holds
    /// no kept bucket and was never refused had no pairs: it is an empty
    /// bucket, not a gap. The read stops before a bucket refused as over
    /// budget, which a read from its own number reports.
    ///
    /// # Errors
    ///
    /// [`BucketRefusal`]: another run's epoch, a number no longer kept, or
    /// a bucket over budget.
    pub(crate) fn buckets(
        &self,
        from: u64,
        count: usize,
        epoch: Option<u64>,
    ) -> Result<BucketRead, BucketRefusal> {
        let current = self.current.map_or(0, |(number, _)| number);
        let oldest = self
            .closed
            .front()
            .map_or(current, |bucket| bucket.number)
            .min(self.over_budget.iter().copied().min().unwrap_or(current));
        if epoch.is_some_and(|asked| asked != self.epoch) {
            return Err(BucketRefusal::EpochChanged {
                epoch: self.epoch,
                oldest,
            });
        }
        if self.over_budget.contains(&from) {
            return Err(BucketRefusal::OverBudget { number: from });
        }
        // Below the oldest kept, unless it is one of the empty numbers
        // after it: evicted or never seen.
        if from < oldest {
            return Err(BucketRefusal::Expired { oldest });
        }
        let slice_ns = self.config.slice();
        let mut buckets = Vec::new();
        let mut number = from;
        while number < current && buckets.len() < count {
            if self.over_budget.contains(&number) {
                break;
            }
            let kept = self.closed.iter().find(|bucket| bucket.number == number);
            buckets.push(bucket_of(number, slice_ns, kept));
            number = number.saturating_add(1);
        }
        Ok(BucketRead {
            epoch: self.epoch,
            slice_ns,
            current,
            oldest,
            buckets,
        })
    }

    /// Reads the table and the ring at the agent's time `now`.
    pub(crate) fn scan(&mut self, mirror: &TraceMirrorReader, now: u64) {
        for index in 0..mirror.entries() {
            if let EntryRead::Entry(entry) = mirror.entry(index) {
                let clock = (!entry.kind.is_network()).then_some(JournalClock {
                    provenance: ClockProvenance::from_word(entry.provenance),
                    same_namespace: entry.time_namespace == TimeNamespace::Same,
                });
                self.journal(entry.journal, clock, now);
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
        // A pair is filed in the slice of the scan that makes it, so a
        // slice is closed before this scan's records land.
        self.close_slices(now);
        for (journal, decoded) in records {
            match decoded {
                Some(record) => self.observe(journal, &record, now),
                None => count(&mut self.counts.malformed, 1),
            }
        }
        self.age(now);
    }

    /// Notes a journal's clock, `None` for a network journal, seen in the
    /// table at the agent's time `now`.
    fn journal(&mut self, journal: u64, clock: Option<JournalClock>, now: u64) {
        if let Some((_, seen)) = self.journals.get_mut(&journal) {
            *seen = now;
            return;
        }
        if self.journals.len() >= self.config.max_journals {
            count(&mut self.counts.journals_dropped, 1);
            return;
        }
        let _ = self.journals.insert(journal, (clock, now));
    }

    /// Files one record of `journal` at the agent's time `now`.
    fn observe(&mut self, journal: u64, record: &TraceRecord, now: u64) {
        count(&mut self.counts.records, 1);
        let clock = match self.journals.get(&journal) {
            None => return count(&mut self.counts.unknown_journal, 1),
            Some((None, _)) => return count(&mut self.counts.network_ignored, 1),
            Some((Some(clock), _)) => *clock,
        };
        let poll = match record.point {
            Point::Publish => false,
            Point::SubscriberPoll => true,
            _ => return count(&mut self.counts.points_ignored, 1),
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
        } else {
            count(&mut self.counts.duplicates, 1);
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

    /// Ages out what is older than the window: pending keys, journals no
    /// longer in the table (their numbers are never reused, so a map that
    /// kept them would fill for good), and lanes whose newest slice left
    /// the window (a new incarnation is a new lane).
    fn age(&mut self, now: u64) {
        let window = self.config.window;
        self.journals
            .retain(|_, (_, seen)| now.checked_sub(*seen).is_none_or(|age| age < window));
        let slice = now.checked_div(self.config.slice()).unwrap_or(0);
        let slices = self.config.slices.max(1);
        self.lanes.retain(|_, lane| {
            lane.slices
                .back()
                .is_some_and(|(number, _)| number.checked_add(slices).is_none_or(|end| end > slice))
        });
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

/// The bucket `number` of `slice_ns`, from `kept` or empty.
fn bucket_of(number: u64, slice_ns: u64, kept: Option<&Bucket>) -> TraceBucket {
    let start_ns = number.saturating_mul(slice_ns);
    let Some(kept) = kept else {
        return TraceBucket {
            number,
            start_ns,
            end_ns: start_ns.saturating_add(slice_ns),
            lanes: Vec::new(),
            loss: Loss::default(),
            incomplete: false,
        };
    };
    let lanes: Vec<BucketLane> = kept
        .lanes
        .iter()
        .map(|((stream, incarnation, lane), counts)| BucketLane {
            stream: *stream,
            incarnation: *incarnation,
            lane: *lane,
            counts: counts.clone(),
        })
        .collect();
    let incomplete = kept.loss.any() || lanes.iter().any(|lane| lane.counts.incomplete);
    TraceBucket {
        number,
        start_ns,
        end_ns: start_ns.saturating_add(slice_ns),
        lanes,
        loss: kept.loss,
        incomplete,
    }
}

/// A nonce for a window's run: the random source, or the host clock when
/// it fails (distinct per run in practice either way).
fn draw_epoch() -> u64 {
    let mut word = [0u64; 1];
    match karyos_sys::random::fill_u64s(&mut word) {
        Ok(()) if word[0] != 0 => word[0],
        _ => karyos_sys::host_clock::host_monotonic_ns().max(1),
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
