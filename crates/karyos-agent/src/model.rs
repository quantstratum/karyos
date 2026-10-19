// SPDX-License-Identifier: Apache-2.0

//! The parts of a driver's model that do not touch a mapping, so every
//! platform tests them: a sampling pass's cells grouped into API v1, and a
//! bounded follower of a diagnostic ring.

use std::collections::{BTreeMap, VecDeque};

use karyos_sys::counters::{CounterMetadata, KIND_SUBSCRIBER, TYPE_POSITION};
use karyos_sys::host_clock::age_ns;

use crate::api::{Counter, Feed, Lane, Sample, Subscriber};

/// One allocated cell: its metadata and value.
pub(crate) type Cell = (CounterMetadata, u64);

/// `a - b` as a signed difference, `None` when it does not fit.
fn difference(a: u64, b: u64) -> Option<i64> {
    i64::try_from(i128::from(a) - i128::from(b)).ok()
}

/// A cell as API v1 reports it.
pub(crate) fn counter(metadata: &CounterMetadata, value: u64) -> Counter {
    Counter {
        label: String::from_utf8_lossy(metadata.label()).into_owned(),
        type_id: metadata.type_id,
        stream: metadata.keys.stream,
        lane: metadata.keys.lane,
        kind: metadata.keys.kind,
        participant: metadata.keys.participant,
        value,
    }
}

/// The sample one pass's `cells` make, read at host time `now`: the
/// counters by key (driver-wide first), and per stream lane the limit,
/// head, floor, headroom and each subscriber's lag, as `karyos-stat`
/// shows them.
pub(crate) fn sample(cells: &[Cell], consistent: bool, now: u64) -> Sample {
    let fixed = |name: &str| {
        cells
            .iter()
            .find(|(metadata, _)| metadata.label() == name.as_bytes() && metadata.keys.stream == 0)
            .map(|(_, value)| *value)
    };
    let sampled = fixed("positions epoch").is_some_and(|epoch| epoch > 0);
    let age_ns = fixed("positions sampled at").map(|at| age_ns(now, at));
    let mut counters = Vec::new();
    let mut lanes: BTreeMap<(u64, u8), Lane> = BTreeMap::new();
    for (metadata, value) in cells {
        let keys = metadata.keys;
        if metadata.type_id != TYPE_POSITION {
            counters.push(counter(metadata, *value));
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
            });
        match metadata.label() {
            b"stream limit" => lane.limit = Some(*value),
            b"stream head" => lane.head = Some(*value),
            b"stream floor" => lane.floor = Some(*value),
            _ if keys.kind == KIND_SUBSCRIBER => lane.subscribers.push(Subscriber {
                registration: keys.participant,
                label: String::from_utf8_lossy(metadata.label()).into_owned(),
                position: *value,
                lag: None,
            }),
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
                .sort_by_key(|subscriber| subscriber.registration);
            lane
        })
        .collect();
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

    /// A new attach: the next scan starts from the ring's oldest record.
    pub(crate) fn restart(&mut self) {
        self.cursor = 0;
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
