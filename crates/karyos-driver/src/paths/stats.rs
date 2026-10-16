// SPDX-License-Identifier: Apache-2.0

//! The per-path statistics of an image (`quantstratum-docs:
//! karyos/design/redundant-paths.md`, sections 2, 3 and 5; RP-1, RP-2,
//! RP-6).
//!
//! The receive owner reports each validated frame it takes from a bound
//! path, with what arbitration made of it ([`Arrival`]). Per path, bounded
//! and preallocated:
//!
//! | Statistic | Rule |
//! | --- | --- |
//! | Wins | Frames this path committed first |
//! | Duplicates | Valid frames, fresh on this path, that another path committed first |
//! | Stale | Frames at or below this path's own mark: a replay, or a late copy on the path |
//! | Conflicts | Valid frames whose bytes differ from the committed copy |
//! | Late | Frames below the image's join point (RP-1) |
//! | Missing bytes | Per whole term the path was bound for, at its cleaning: committed bytes minus the fresh bytes this path delivered in it |
//! | Arrival difference | Per duplicate, its arrival minus the first arrival, on the receiver's clock, in a log2 histogram |
//!
//! **Freshness (RP-2, ACS 15519).** A frame is fresh on a path when it
//! ends above the path's mark on its lane: the highest position the path
//! delivered, seeded at binding with the join point its answer stated
//! (RP-1), and kept across a loss, since a rebound path's history is still
//! old history. A copy of a frame another path committed is fresh on this
//! path; a replay or a late copy at or below the mark is not. Path
//! liveness takes only fresh evidence ([`PathStats::arrived`] says which);
//! it never refreshes the image.
//!
//! **Missing bytes.** A path is charged only for whole terms of its
//! binding: from the first term after the one holding its join point,
//! until the term in which it was lost (excluded). Only fresh bytes of
//! winning or duplicate copies count as delivered, so a replay or a
//! conflicting copy cannot hide a loss, and the bytes delivered in a term
//! stay counted across a loss. Under reordering on one path, a frame that
//! arrives after a later one is not fresh and counts as missing: missing
//! bytes are an upper bound. Each term of a lane is cleaned once, in
//! order; a term cleaned again, or out of order, charges nothing and
//! counts as an accounting fault.
//!
//! **Arrival differences.** First arrivals are kept per lane in a ring of
//! the last `skew_sample_frames` committed frames, as position and time.
//! A duplicate whose position is in the ring yields a difference, found by
//! a scan from the newest entry (duplicates trail their first arrival by
//! at most the skew, so the scan is short; it is bounded by the ring); one
//! that is not counts as unmatched. Times are the readers' receive times
//! ([`Delivered::now`]), never the owner's service time, which would add
//! queueing to the skew; a difference that reads negative is 0
//! (`host_clock::age_ns`). Nothing grows with the term size.

use karyos_sys::host_clock::age_ns;

use super::{PathConfig, add, bump};

/// Buckets of the arrival difference histogram: bucket `k` holds
/// differences below `2^k` ns and at least `2^(k-1)` (bucket 0 holds 0);
/// the last holds everything from `2^(ARRIVAL_BUCKETS - 2)` ns up.
pub const ARRIVAL_BUCKETS: usize = 32;

/// What arbitration made of a frame a path delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// This path's copy was committed: the first arrival.
    First,
    /// Another path committed it first; this copy matched it.
    Duplicate,
    /// A valid copy whose bytes differ from the committed one (a protocol
    /// error).
    Conflict,
    /// Below the image's join point, whatever path carries it: dropped
    /// (RP-1).
    Late,
}

/// One frame a path delivered, as the owner reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivered {
    /// The path.
    pub path: usize,
    /// The lane.
    pub lane: usize,
    /// The term, by its count since the image's first.
    pub term: u64,
    /// The frame's stream position.
    pub position: u64,
    /// Its aligned length in bytes.
    pub length: u64,
    /// When the path's reader received it, on the receiver's monotonic
    /// clock: not when the owner served it.
    pub now: u64,
}

/// One path's counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathCounts {
    /// Frames this path committed first.
    pub wins: u64,
    /// Valid frames, fresh on this path, another path committed first.
    pub duplicates: u64,
    /// Frames at or below this path's own mark.
    pub stale: u64,
    /// Valid frames whose bytes differ from the committed copy.
    pub conflicts: u64,
    /// Frames below the image's join point.
    pub late: u64,
    /// Committed bytes of cleaned terms this path never delivered fresh.
    pub missing_bytes: u64,
    /// Duplicates whose first arrival had left the ring.
    pub unmatched: u64,
    /// The arrival difference histogram ([`ARRIVAL_BUCKETS`]).
    pub arrival: [u64; ARRIVAL_BUCKETS],
}

impl Default for PathCounts {
    fn default() -> Self {
        Self {
            wins: 0,
            duplicates: 0,
            stale: 0,
            conflicts: 0,
            late: 0,
            missing_bytes: 0,
            unmatched: 0,
            arrival: [0; ARRIVAL_BUCKETS],
        }
    }
}

/// The fresh bytes one path delivered in one term of one lane.
#[derive(Debug, Clone, Copy, Default)]
struct TermBytes {
    term: Option<u64>,
    bytes: u64,
}

/// One path on one lane.
#[derive(Debug, Clone)]
struct PathLane {
    /// Whether the path is bound now.
    bound: bool,
    /// The end of the highest frame the path delivered, seeded at the join.
    mark: Option<u64>,
    /// The first term charged for missing bytes; `None` before any binding.
    charge_from: Option<u64>,
    /// The term of the loss, not charged; `None` while bound.
    charge_until: Option<u64>,
    /// Fresh bytes per term slot.
    terms: Vec<TermBytes>,
}

impl PathLane {
    fn charged(&self, term: u64) -> bool {
        self.charge_from.is_some_and(|from| term >= from)
            && self.charge_until.is_none_or(|until| term < until)
    }
}

/// One lane's ring of first arrivals.
#[derive(Debug)]
struct ArrivalRing {
    /// `(position, time)`, oldest overwritten first.
    entries: Vec<(u64, u64)>,
    /// The next entry written.
    head: usize,
}

impl ArrivalRing {
    fn record(&mut self, position: u64, now: u64, capacity: usize) {
        if self.entries.len() < capacity {
            self.entries.push((position, now));
        } else if let Some(entry) = self.entries.get_mut(self.head) {
            *entry = (position, now);
        }
        self.head = self
            .head
            .checked_add(1)
            .filter(|next| *next < capacity)
            .unwrap_or(0);
    }

    /// The first arrival of `position`, searched from the newest entry.
    fn find(&self, position: u64) -> Option<u64> {
        let head = self.head.min(self.entries.len());
        (0..head)
            .rev()
            .chain((head..self.entries.len()).rev())
            .filter_map(|index| self.entries.get(index))
            .find(|(at, _)| *at == position)
            .map(|(_, time)| *time)
    }
}

/// The histogram bucket of an arrival difference.
#[must_use]
pub fn arrival_bucket(difference: u64) -> usize {
    let last = ARRIVAL_BUCKETS - 1;
    difference
        .checked_ilog2()
        .and_then(|log| log.checked_add(1))
        .map_or(0, |bits| {
            usize::try_from(bits).map_or(last, |bits| bits.min(last))
        })
}

/// The statistics of one image's paths.
#[derive(Debug)]
pub struct PathStats {
    term_slots: u64,
    ring_capacity: usize,
    counts: Vec<PathCounts>,
    /// Per path, then per lane.
    paths: Vec<Vec<PathLane>>,
    rings: Vec<ArrivalRing>,
    /// Per lane: the last term cleaned.
    cleaned: Vec<Option<u64>>,
    /// Accounting faults, not counted as statistics: a path that delivered
    /// more fresh bytes in a term than were committed, a term slot
    /// overwritten before its cleaning, or a term cleaned again or out of
    /// order.
    inconsistent: u64,
    overflows: u64,
}

impl PathStats {
    /// The statistics of an image of `lanes` lanes, each with
    /// `term_slots` terms in flight (its slots), for `config.max_paths`
    /// paths; it allocates only here. `lanes` and `term_slots` are at
    /// least 1.
    #[must_use]
    pub fn new(config: &PathConfig, lanes: usize, term_slots: usize) -> Self {
        let lanes = lanes.max(1);
        let slots = term_slots.max(1);
        let ring_capacity = usize::from(config.skew_sample_frames).max(1);
        let lane = PathLane {
            bound: false,
            mark: None,
            charge_from: None,
            charge_until: None,
            terms: vec![TermBytes::default(); slots],
        };
        Self {
            term_slots: u64::try_from(slots).unwrap_or(u64::MAX),
            ring_capacity,
            counts: vec![PathCounts::default(); usize::from(config.max_paths)],
            paths: (0..config.max_paths)
                .map(|_| vec![lane.clone(); lanes])
                .collect(),
            rings: (0..lanes)
                .map(|_| ArrivalRing {
                    entries: Vec::with_capacity(ring_capacity),
                    head: 0,
                })
                .collect(),
            cleaned: vec![None; lanes],
            inconsistent: 0,
            overflows: 0,
        }
    }

    fn slot(&self, term: u64) -> usize {
        term.checked_rem(self.term_slots)
            .and_then(|slot| usize::try_from(slot).ok())
            .unwrap_or(0)
    }

    /// `path` was bound with the join point its answer stated per lane,
    /// `(position, term)` (RP-1): its mark rises to the join (a rebound
    /// path keeps a higher mark), and it is charged for missing bytes from
    /// the term after the join's.
    pub fn path_bound(&mut self, path: usize, joins: &[(u64, u64)]) {
        let Some(lanes) = self.paths.get_mut(path) else {
            return;
        };
        for (lane, (position, term)) in lanes.iter_mut().zip(joins) {
            lane.bound = true;
            lane.mark = Some(lane.mark.map_or(*position, |mark| mark.max(*position)));
            lane.charge_from = term.checked_add(1);
            lane.charge_until = None;
        }
    }

    /// `path`'s binding went, during `terms` (per lane): it is no longer
    /// charged from those terms on. Its mark and the bytes it delivered
    /// stay; its counts stay.
    pub fn path_lost(&mut self, path: usize, terms: &[u64]) {
        let Some(lanes) = self.paths.get_mut(path) else {
            return;
        };
        for (lane, term) in lanes.iter_mut().zip(terms) {
            if lane.bound {
                lane.bound = false;
                lane.charge_until = Some(*term);
            }
        }
    }

    /// Records a frame `delivered` by a bound path and what arbitration
    /// made of it; returns whether it was fresh on that path (RP-2):
    /// liveness evidence for the path, never for the image. An unknown or
    /// unbound path or lane records nothing and is not fresh.
    pub fn arrived(&mut self, delivered: Delivered, arrival: Arrival) -> bool {
        let Delivered {
            path,
            lane,
            term,
            position,
            length,
            now,
        } = delivered;
        let slot = self.slot(term);
        let Some(state) = self
            .paths
            .get_mut(path)
            .and_then(|lanes| lanes.get_mut(lane))
            .filter(|state| state.bound)
        else {
            return false;
        };
        let Some(end) = position.checked_add(length) else {
            return false;
        };
        let fresh = state.mark.is_none_or(|mark| end > mark);
        if fresh {
            state.mark = Some(end);
        }
        if fresh
            && matches!(arrival, Arrival::First | Arrival::Duplicate)
            && let Some(bytes) = state.terms.get_mut(slot)
        {
            if bytes.term != Some(term) {
                if bytes.term.is_some() {
                    // The slot's earlier term was never cleaned.
                    bump(&mut self.inconsistent, &mut self.overflows);
                }
                *bytes = TermBytes {
                    term: Some(term),
                    bytes: 0,
                };
            }
            add(&mut bytes.bytes, length, &mut self.overflows);
        }
        let Some(counts) = self.counts.get_mut(path) else {
            return fresh;
        };
        match arrival {
            Arrival::First => {
                bump(&mut counts.wins, &mut self.overflows);
                if let Some(ring) = self.rings.get_mut(lane) {
                    ring.record(position, now, self.ring_capacity);
                }
            }
            // A replay or a late copy on this path: stale, out of the
            // duplicates and of the histogram.
            Arrival::Duplicate if !fresh => bump(&mut counts.stale, &mut self.overflows),
            Arrival::Duplicate => {
                bump(&mut counts.duplicates, &mut self.overflows);
                match self.rings.get(lane).and_then(|ring| ring.find(position)) {
                    Some(first) => {
                        let bucket = arrival_bucket(age_ns(now, first));
                        if let Some(bucket) = counts.arrival.get_mut(bucket) {
                            bump(bucket, &mut self.overflows);
                        }
                    }
                    None => bump(&mut counts.unmatched, &mut self.overflows),
                }
            }
            Arrival::Conflict => bump(&mut counts.conflicts, &mut self.overflows),
            Arrival::Late => bump(&mut counts.late, &mut self.overflows),
        }
        fresh
    }

    /// `term` of `lane` was cleaned with `committed` bytes: each path
    /// charged for that term has its missing bytes grow by what it did not
    /// deliver fresh in it, and the term's slots are freed. Terms are
    /// cleaned once each, in order.
    pub fn term_cleaned(&mut self, lane: usize, term: u64, committed: u64) {
        let Some(last) = self.cleaned.get_mut(lane) else {
            return;
        };
        if last.is_some_and(|last| term <= last) {
            bump(&mut self.inconsistent, &mut self.overflows);
            return;
        }
        *last = Some(term);
        let slot = self.slot(term);
        for (path, lanes) in self.paths.iter_mut().enumerate() {
            let Some(state) = lanes.get_mut(lane) else {
                continue;
            };
            let delivered = match state.terms.get_mut(slot) {
                Some(bytes) if bytes.term == Some(term) => {
                    let delivered = bytes.bytes;
                    *bytes = TermBytes::default();
                    delivered
                }
                _ => 0,
            };
            if !state.charged(term) {
                continue;
            }
            match committed.checked_sub(delivered) {
                Some(missing) => {
                    if let Some(counts) = self.counts.get_mut(path) {
                        add(&mut counts.missing_bytes, missing, &mut self.overflows);
                    }
                }
                None => bump(&mut self.inconsistent, &mut self.overflows),
            }
        }
    }

    /// `path`'s counts.
    #[must_use]
    pub fn counts(&self, path: usize) -> Option<&PathCounts> {
        self.counts.get(path)
    }

    /// Accounting faults: see the field.
    #[must_use]
    pub fn inconsistent(&self) -> u64 {
        self.inconsistent
    }

    /// Counts that would have overflowed and kept their last value.
    #[must_use]
    pub fn overflows(&self) -> u64 {
        self.overflows
    }
}
