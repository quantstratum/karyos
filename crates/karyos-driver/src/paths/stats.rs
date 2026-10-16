// SPDX-License-Identifier: Apache-2.0

//! The per-path statistics of an image (`quantstratum-docs:
//! karyos/design/redundant-paths.md`, sections 2, 3 and 5; RP-1, RP-2,
//! RP-6).
//!
//! The receive owner reports each validated frame it takes from a path,
//! with what arbitration made of it ([`Arrival`]). Per path, bounded and
//! preallocated:
//!
//! | Statistic | Rule |
//! | --- | --- |
//! | Wins | Frames this path committed first |
//! | Duplicates | Valid frames this path delivered after another path committed them |
//! | Conflicts | Valid frames whose bytes differ from the committed copy |
//! | Late | Frames below the image's join point (RP-1) |
//! | Missing bytes | Per term, at its cleaning: committed bytes minus the fresh bytes this path delivered in it |
//! | Arrival difference | Per duplicate, its arrival minus the first arrival, on the receiver's clock, in a log2 histogram |
//!
//! **Freshness (RP-2, ACS 15519).** A frame is fresh on a path when it
//! ends above the highest position that path had delivered on its lane: a
//! copy of a frame another path committed is fresh on this path, a replay
//! or a late copy at or below the path's own mark is not. Path liveness
//! takes only fresh evidence ([`PathStats::arrived`] says which); it never
//! refreshes the image. Only fresh bytes count as delivered for the
//! missing bytes, so a replay cannot hide a path's losses.
//!
//! First arrivals are kept per lane in a ring of the last
//! `skew_sample_frames` committed frames, as position and time. A
//! duplicate whose position is in the ring yields a difference, found by
//! a scan from the newest entry (duplicates trail their first arrival by
//! at most the skew, so the scan is short; it is bounded by the ring);
//! one that is not is counted as unmatched. Nothing grows with the term
//! size.

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
    /// The arrival on the receiver's monotonic clock.
    pub now: u64,
}

/// One path's counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathCounts {
    /// Frames this path committed first.
    pub wins: u64,
    /// Valid frames delivered after another path committed them.
    pub duplicates: u64,
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
        self.head = (self.head + 1) % capacity;
    }

    /// The first arrival of `position`, searched from the newest entry.
    fn find(&self, position: u64) -> Option<u64> {
        let len = self.entries.len();
        (0..len)
            .map(|back| (self.head + len - 1 - back) % len)
            .filter_map(|index| self.entries.get(index))
            .find(|(at, _)| *at == position)
            .map(|(_, time)| *time)
    }
}

/// The histogram bucket of an arrival difference.
#[must_use]
pub fn arrival_bucket(difference: u64) -> usize {
    let bits = (u64::BITS - difference.leading_zeros()) as usize;
    bits.min(ARRIVAL_BUCKETS - 1)
}

/// The statistics of one image's paths.
#[derive(Debug)]
pub struct PathStats {
    lanes: usize,
    term_slots: usize,
    ring_capacity: usize,
    counts: Vec<PathCounts>,
    /// Per path and lane: the end of the highest frame the path delivered.
    high_water: Vec<Option<u64>>,
    /// Per path, lane and term slot.
    term_bytes: Vec<TermBytes>,
    rings: Vec<ArrivalRing>,
    /// Terms cleaned with more fresh bytes on a path than committed, a term
    /// slot overwritten before its cleaning, or a duplicate timed before
    /// its first arrival: accounting faults, not counted as statistics.
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
        let paths = usize::from(config.max_paths);
        let lanes = lanes.max(1);
        let term_slots = term_slots.max(1);
        let ring_capacity = usize::from(config.skew_sample_frames).max(1);
        Self {
            lanes,
            term_slots,
            ring_capacity,
            counts: vec![PathCounts::default(); paths],
            high_water: vec![None; paths * lanes],
            term_bytes: vec![TermBytes::default(); paths * lanes * term_slots],
            rings: (0..lanes)
                .map(|_| ArrivalRing {
                    entries: Vec::with_capacity(ring_capacity),
                    head: 0,
                })
                .collect(),
            inconsistent: 0,
            overflows: 0,
        }
    }

    /// Records a frame `delivered` by a path and what arbitration made of
    /// it; returns whether it was fresh on that path (RP-2): liveness
    /// evidence for the path, never for the image. An unknown path or
    /// lane records nothing and is not fresh.
    pub fn arrived(&mut self, delivered: Delivered, arrival: Arrival) -> bool {
        let Delivered {
            path,
            lane,
            term,
            position,
            length,
            now,
        } = delivered;
        if lane >= self.lanes || path >= self.counts.len() {
            return false;
        }
        let Some(end) = position.checked_add(length) else {
            return false;
        };
        let lane_index = path * self.lanes + lane;
        let fresh = match self.high_water.get_mut(lane_index) {
            Some(mark) if mark.is_none_or(|mark| end > mark) => {
                *mark = Some(end);
                true
            }
            _ => false,
        };
        if fresh && arrival != Arrival::Late {
            let slot = lane_index * self.term_slots
                + usize::try_from(term % self.term_slots as u64).unwrap_or(0);
            if let Some(bytes) = self.term_bytes.get_mut(slot) {
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
            Arrival::Duplicate => {
                bump(&mut counts.duplicates, &mut self.overflows);
                match self.rings.get(lane).and_then(|ring| ring.find(position)) {
                    // The receiver's own clock is monotonic: a copy that
                    // reads as arriving before the first is an accounting
                    // fault, never a difference.
                    Some(first) => match now.checked_sub(first) {
                        Some(difference) => {
                            if let Some(bucket) = counts.arrival.get_mut(arrival_bucket(difference))
                            {
                                bump(bucket, &mut self.overflows);
                            }
                        }
                        None => bump(&mut self.inconsistent, &mut self.overflows),
                    },
                    None => bump(&mut counts.unmatched, &mut self.overflows),
                }
            }
            Arrival::Conflict => bump(&mut counts.conflicts, &mut self.overflows),
            Arrival::Late => bump(&mut counts.late, &mut self.overflows),
        }
        fresh
    }

    /// `term` of `lane` was cleaned with `committed` bytes: each path's
    /// missing bytes grow by what it did not deliver fresh in it, and the
    /// term's slots are freed.
    pub fn term_cleaned(&mut self, lane: usize, term: u64, committed: u64) {
        if lane >= self.lanes {
            return;
        }
        let slot = usize::try_from(term % self.term_slots as u64).unwrap_or(0);
        for path in 0..self.counts.len() {
            let index = (path * self.lanes + lane) * self.term_slots + slot;
            let delivered = match self.term_bytes.get_mut(index) {
                Some(bytes) if bytes.term == Some(term) => {
                    let delivered = bytes.bytes;
                    *bytes = TermBytes::default();
                    delivered
                }
                _ => 0,
            };
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

    /// Forgets `path`'s freshness and term bytes, when its binding goes;
    /// its counts stay.
    pub fn path_lost(&mut self, path: usize) {
        if path >= self.counts.len() {
            return;
        }
        for lane in 0..self.lanes {
            let lane_index = path * self.lanes + lane;
            if let Some(mark) = self.high_water.get_mut(lane_index) {
                *mark = None;
            }
            for slot in 0..self.term_slots {
                if let Some(bytes) = self.term_bytes.get_mut(lane_index * self.term_slots + slot) {
                    *bytes = TermBytes::default();
                }
            }
        }
    }

    /// `path`'s counts.
    #[must_use]
    pub fn counts(&self, path: usize) -> Option<&PathCounts> {
        self.counts.get(path)
    }

    /// Accounting faults: a path that delivered more fresh bytes in a term
    /// than were committed, a term overwritten before its cleaning, or a
    /// duplicate timed before its first arrival.
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
