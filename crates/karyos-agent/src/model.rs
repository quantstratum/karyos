// SPDX-License-Identifier: Apache-2.0

//! The parts of a driver's model that do not touch a mapping, so every
//! platform tests them: a sampling pass's cells grouped into API v1, and a
//! bounded follower of a diagnostic ring.

use std::collections::{BTreeMap, HashMap, VecDeque};

use karyos_sys::counters::{CounterMetadata, KIND_SUBSCRIBER, TYPE_POSITION};
use karyos_sys::host_clock::age_ns;

use crate::api::{Counter, Feed, Lane, Sample, Subscriber};

/// One allocated cell: its metadata and value.
pub(crate) type Cell = (CounterMetadata, u64);

/// `a - b` as a signed difference, `None` when it does not fit.
fn difference(a: u64, b: u64) -> Option<i64> {
    i64::try_from(i128::from(a) - i128::from(b)).ok()
}

/// The last value of each datum and when the agent last saw it change,
/// over one driver instance, by the cell's registration: a region never
/// reuses one, so a registration is one allocation of one identity, and
/// a counter freed and allocated again under the same identity is a new
/// datum. It holds only the registrations of the last pass: one absent
/// from a pass (a freed counter) is dropped, so it never holds more
/// entries than the counters region has cells.
///
/// A pass reads the cells in region order, so the last pass's entries
/// are matched in that order with a cursor: a pass costs one comparison
/// per cell when nothing was allocated or freed, and allocates nothing
/// once both buffers have grown to the region's cells. A cell the cursor
/// does not find (cells were allocated or freed) is looked up in an index
/// of the last pass, built once in that pass, so a pass of any churn
/// costs O(cells).
#[derive(Debug, Default)]
pub(crate) struct Changes {
    /// The last pass's registration, value and `changed_ns`, in order.
    last: Vec<(u64, u64, Option<u64>)>,
    /// This pass's, as it is read.
    next: Vec<(u64, u64, Option<u64>)>,
    /// The next entry of `last` to match.
    cursor: usize,
    /// `last`'s positions by registration, built at the first miss of a
    /// pass.
    index: HashMap<u64, usize>,
    indexed: bool,
}

impl Changes {
    /// A new driver instance: nothing joins its old series.
    pub(crate) fn restart(&mut self) {
        self.last.clear();
        self.next.clear();
        self.cursor = 0;
    }

    /// The registrations kept.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.last.len()
    }

    fn begin(&mut self) {
        self.next.clear();
        self.cursor = 0;
        self.indexed = false;
    }

    /// The position in `last` of `registration`, if the last pass had it.
    fn find(&mut self, registration: u64) -> Option<usize> {
        if self
            .last
            .get(self.cursor)
            .is_some_and(|entry| entry.0 == registration)
        {
            return Some(self.cursor);
        }
        if !self.indexed {
            self.index.clear();
            self.index.extend(
                self.last
                    .iter()
                    .enumerate()
                    .map(|(at, entry)| (entry.0, at)),
            );
            self.indexed = true;
        }
        self.index.get(&registration).copied()
    }

    /// `value` of `metadata`'s datum in this pass, read at `now`: its
    /// `changed_ns`. A datum seen for the first time has none; one whose
    /// value differs from its last pass changed by `now`.
    fn observe(&mut self, metadata: &CounterMetadata, value: u64, now: u64) -> Option<u64> {
        let registration = metadata.registration_id;
        let found = self.find(registration);
        let changed = match found.and_then(|index| {
            self.cursor = index + 1;
            self.last.get(index)
        }) {
            Some(&(_, last, changed)) if last == value => changed,
            Some(_) => Some(now),
            None => None,
        };
        self.next.push((registration, value, changed));
        changed
    }

    /// This pass's entries become the last pass's.
    fn end(&mut self) {
        std::mem::swap(&mut self.last, &mut self.next);
    }
}

/// A cell as API v1 reports it, read at `read_ns` with its `changed_ns`.
pub(crate) fn counter(
    metadata: &CounterMetadata,
    value: u64,
    read_ns: u64,
    changed_ns: Option<u64>,
) -> Counter {
    Counter {
        label: String::from_utf8_lossy(metadata.label()).into_owned(),
        type_id: metadata.type_id,
        stream: metadata.keys.stream,
        lane: metadata.keys.lane,
        kind: metadata.keys.kind,
        participant: metadata.keys.participant,
        cell_registration: metadata.registration_id,
        value,
        read_ns,
        changed_ns,
    }
}

/// `cells` as counters read at `now`, with their changes.
pub(crate) fn counters(cells: &[Cell], now: u64, changes: &mut Changes) -> Vec<Counter> {
    changes.begin();
    let counters = cells
        .iter()
        .map(|(metadata, value)| {
            let changed = changes.observe(metadata, *value, now);
            counter(metadata, *value, now, changed)
        })
        .collect();
    changes.end();
    counters
}

/// The sample one pass's `cells` make, read at host time `now`: the
/// counters by key (driver-wide first), and per stream lane the limit,
/// head, floor, headroom and each subscriber's lag, as `karyos-stat`
/// shows them.
pub(crate) fn sample(cells: &[Cell], consistent: bool, now: u64, changes: &mut Changes) -> Sample {
    // The driver's copies of trace points (karyos#869) are names, not
    // metrics, and their labels are the clients' own: they never enter
    // the sample, so no point can pose as a driver counter.
    let cells: Vec<&Cell> = cells
        .iter()
        .filter(|(metadata, _)| metadata.type_id != karyos_sys::counters::TYPE_TRACE_POINT)
        .collect();
    let cells = cells.as_slice();
    let fixed = |name: &str| {
        cells
            .iter()
            .find(|(metadata, _)| metadata.label() == name.as_bytes() && metadata.keys.stream == 0)
            .map(|(_, value)| *value)
    };
    let sampled = fixed("positions epoch").is_some_and(|epoch| epoch > 0);
    let sampled_at = fixed("positions sampled at");
    let age_ns = sampled_at.map(|at| age_ns(now, at));
    // A position's time is the driver's sampling time; a counter's, the
    // agent's read. An inconsistent pass may mix samples, so its position
    // changes are stamped with this pass's read instead.
    let position_ns = if consistent {
        sampled_at.unwrap_or(now)
    } else {
        now
    };
    changes.begin();
    let mut counters = Vec::new();
    let mut lanes: BTreeMap<(u64, u8), Lane> = BTreeMap::new();
    for (metadata, value) in cells {
        let keys = metadata.keys;
        if metadata.type_id != TYPE_POSITION {
            let changed = changes.observe(metadata, *value, now);
            counters.push(counter(metadata, *value, now, changed));
            continue;
        }
        let lane = lanes
            .entry((keys.stream, keys.lane))
            .or_insert_with(|| Lane {
                stream: keys.stream,
                lane: keys.lane,
                limit: None,
                head: None,
                floor: None,
                headroom: None,
                subscribers: Vec::new(),
                sampled_ns: sampled_at,
            });
        match metadata.label() {
            b"stream limit" => lane.limit = Some(*value),
            b"stream head" => lane.head = Some(*value),
            b"stream floor" => lane.floor = Some(*value),
            _ if keys.kind == KIND_SUBSCRIBER => {
                let changed = changes.observe(metadata, *value, position_ns);
                lane.subscribers.push(Subscriber {
                    registration: keys.participant,
                    cell_registration: metadata.registration_id,
                    label: String::from_utf8_lossy(metadata.label()).into_owned(),
                    position: *value,
                    lag: None,
                    changed_ns: changed,
                });
            }
            _ => {}
        }
    }
    counters.sort_by_key(|counter| {
        (
            counter.stream,
            counter.lane,
            counter.kind,
            counter.participant,
            counter.label.clone(),
            counter.cell_registration,
        )
    });
    let lanes = lanes
        .into_values()
        .map(|mut lane| {
            lane.headroom = lane
                .limit
                .zip(lane.head)
                .and_then(|(limit, head)| difference(limit, head));
            let head = lane.head;
            for subscriber in &mut lane.subscribers {
                subscriber.lag = head.and_then(|head| difference(head, subscriber.position));
            }
            lane.subscribers
                .sort_by_key(|subscriber| (subscriber.registration, subscriber.cell_registration));
            lane
        })
        .collect();
    changes.end();
    Sample {
        consistent,
        sampled,
        age_ns,
        counters,
        lanes,
    }
}

/// A follower of one diagnostic ring: its cursor, the newest records up to
/// a bound, and what it delivered and missed. The cursor stays across
/// refreshes of one attach; a new attach (a new driver instance) starts
/// a new one.
#[derive(Debug)]
pub(crate) struct Follower<T> {
    pub(crate) cursor: u64,
    history: usize,
    records: VecDeque<T>,
    delivered: u64,
    overwritten: u64,
}

impl<T: Clone> Follower<T> {
    pub(crate) fn new(history: usize) -> Self {
        Self {
            cursor: 0,
            history,
            records: VecDeque::new(),
            delivered: 0,
            overwritten: 0,
        }
    }

    /// Keeps `record`, dropping the oldest past the bound.
    pub(crate) fn push(&mut self, record: T) {
        if self.history == 0 {
            return;
        }
        if self.records.len() >= self.history {
            let _ = self.records.pop_front();
        }
        self.records.push_back(record);
    }

    /// Adds one scan's counts. A ring's sequences are 64-bit, so these
    /// counts cannot pass `u64::MAX`; were they to, they would stop.
    pub(crate) fn count(&mut self, delivered: u64, overwritten: u64) {
        if let Some(sum) = self.delivered.checked_add(delivered) {
            self.delivered = sum;
        }
        if let Some(sum) = self.overwritten.checked_add(overwritten) {
            self.overwritten = sum;
        }
    }

    /// The oldest record kept.
    pub(crate) fn oldest(&self) -> Option<&T> {
        self.records.front()
    }

    /// Replaces the kept record `same` matches with `record`; a record no
    /// longer kept is dropped.
    pub(crate) fn update(&mut self, record: T, same: impl Fn(&T, &T) -> bool) {
        if let Some(kept) = self.records.iter_mut().find(|kept| same(kept, &record)) {
            *kept = record;
        }
    }

    /// A new driver instance: its rings start over, so the records and
    /// counts of the old one are dropped (their sequences would overlap the
    /// new ones), and the next scan starts from the oldest record.
    pub(crate) fn restart(&mut self) {
        self.cursor = 0;
        self.records.clear();
        self.delivered = 0;
        self.overwritten = 0;
    }

    pub(crate) fn feed(&self) -> Feed<T> {
        Feed {
            records: self.records.iter().cloned().collect(),
            delivered: self.delivered,
            overwritten: self.overwritten,
        }
    }
}

#[cfg(test)]
mod tests;
