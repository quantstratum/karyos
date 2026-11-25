// SPDX-License-Identifier: Apache-2.0

//! The drop ledger of a publication on the `etf` route (ADR-0109 points 6
//! to 8; karyos#625).
//!
//! The `etf` qdisc reports only drops, on the etf socket's error queue,
//! each named by its datagram's `SCM_TXTIME`. The [`EtfLedger`] keeps, per
//! lane, the datagrams handed to the etf queue and not yet settled, as
//! `(txtime, position range)`, oldest first:
//!
//! - **Reserve.** An entry is reserved when the datagram is staged, before
//!   it is sent, so the list never overflows: its bound is the lane's
//!   schedule capacity, and a full list holds the lane's next timed head
//!   until an entry leaves (counted in [`EtfCounts::held_full`]).
//! - **Drain, then expire.** Each sender duty drains every lane's error
//!   queue first ([`EtfLedger::drained`] per report), coalescing the
//!   reports of one time: **every** entry of the lane with that time is
//!   dropped (fragments and messages that share a time all recover).
//!   Then [`EtfLedger::expire`] retires, as sent, every entry whose
//!   `txtime + advance + margin` has passed in `CLOCK_TAI`: no report by
//!   then means the datagram left on time; a report lost to a failed clone
//!   is backstopped by the receiver (a NAK repairs a reliable lane, an
//!   unreliable one has a gap anyway).
//! - **A late report** names a time no entry holds (retired already): it
//!   resubmits nothing, and is counted in
//!   [`EtfCounts::late_drop_reports`], with one diagnostic event each
//!   ([`EtfLedger::take_late`]).
//! - **Policies.** A dropped range of a reliable lane is caught up late on
//!   the immediate route, in position order (the repair path's catch-up
//!   job, one at a time per lane, [`EtfLedger::next_catch_up`]); one of an
//!   unreliable lane is a gap at the receiver, counted in
//!   [`EtfCounts::gaps`].
//!
//! It allocates only in [`EtfLedger::new`].

use std::collections::VecDeque;

/// How long past `txtime + advance` an entry waits for a drop report
/// before it is retired as sent, in nanoseconds: the kernel reports a drop
/// when the qdisc dequeues the datagram, within its `delta` of the time,
/// so 100 ms leaves the report ample room on a loaded host.
pub const EXPIRY_MARGIN: u64 = 100_000_000;

/// The reports one drain reads from one lane's error queue at most.
pub const DRAIN_BATCH: usize = 64;

/// One datagram handed to the etf queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InFlight {
    /// Its send time, in `CLOCK_TAI` nanoseconds.
    txtime: u64,
    /// The stream positions it carries, `[start, end)`.
    start: u64,
    end: u64,
}

/// What the ledger counted; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EtfCounts {
    /// Entries reserved.
    pub reserved: u64,
    /// Entries the qdisc dropped, matched by a report.
    pub dropped: u64,
    /// Dropped ranges of an unreliable lane: gaps at the receiver.
    pub gaps: u64,
    /// Dropped ranges of a reliable lane handed to a catch-up.
    pub caught_up: u64,
    /// Entries retired as sent at expiry.
    pub expired: u64,
    /// Reports naming a time no entry holds (ADR-0109 point 7).
    pub late_drop_reports: u64,
    /// Times a full list held a lane's next timed head.
    pub held_full: u64,
    /// Reports of another origin, or that did not decode.
    pub other_reports: u64,
    /// Increments that would have overflowed.
    pub overflows: u64,
}

fn bump(count: &mut u64, overflows: &mut u64) {
    match count.checked_add(1) {
        Some(next) => *count = next,
        None => *overflows = overflows.saturating_add(1),
    }
}

/// A late drop report, for the driver's diagnostic ring: the lane and the
/// report's time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateReport {
    /// The lane.
    pub lane: usize,
    /// The report's time, in `CLOCK_TAI` nanoseconds.
    pub txtime: u64,
}

/// One lane of the ledger.
#[derive(Debug)]
struct EtfLane {
    in_flight: VecDeque<InFlight>,
    /// Dropped ranges of a reliable lane waiting for their catch-up,
    /// ordered by position and merged where they touch.
    catch_ups: VecDeque<(u64, u64)>,
}

/// The drop ledger of one publication on the `etf` route.
#[derive(Debug)]
pub struct EtfLedger {
    lanes: Vec<EtfLane>,
    bound: usize,
    reliable: bool,
    /// `advance + margin`: an entry expires that long after its time.
    expiry: u64,
    /// Late reports not yet posted, oldest first.
    late: VecDeque<LateReport>,
    late_bound: usize,
    counts: EtfCounts,
}

impl EtfLedger {
    /// A ledger of `lanes` lanes, each holding up to `bound` entries (the
    /// lane's schedule capacity), of a `reliable` publication whose
    /// declared advance is `advance`. Allocates here only.
    #[must_use]
    pub fn new(lanes: usize, bound: usize, reliable: bool, advance: u64) -> Self {
        Self {
            lanes: (0..lanes)
                .map(|_| EtfLane {
                    in_flight: VecDeque::with_capacity(bound),
                    catch_ups: VecDeque::with_capacity(bound),
                })
                .collect(),
            bound,
            reliable,
            expiry: advance.saturating_add(EXPIRY_MARGIN),
            late: VecDeque::with_capacity(DRAIN_BATCH),
            late_bound: DRAIN_BATCH,
            counts: EtfCounts::default(),
        }
    }

    /// What the ledger counted (tests).
    #[cfg(test)]
    #[must_use]
    pub fn counts(&self) -> EtfCounts {
        self.counts
    }

    /// Whether `lane` has room for one more entry; a full lane is counted
    /// held once per call.
    pub fn has_room(&mut self, lane: usize) -> bool {
        let room = self
            .lanes
            .get(lane)
            .is_some_and(|state| state.in_flight.len() < self.bound);
        if !room {
            bump(&mut self.counts.held_full, &mut self.counts.overflows);
        }
        room
    }

    /// Reserves an entry on `lane` for a datagram sent at `txtime` carrying
    /// `[start, end)`; `false`, nothing recorded, when the lane is full or
    /// unknown.
    pub fn reserve(&mut self, lane: usize, txtime: u64, (start, end): (u64, u64)) -> bool {
        let Some(state) = self.lanes.get_mut(lane) else {
            return false;
        };
        if state.in_flight.len() >= self.bound {
            bump(&mut self.counts.held_full, &mut self.counts.overflows);
            return false;
        }
        state.in_flight.push_back(InFlight { txtime, start, end });
        bump(&mut self.counts.reserved, &mut self.counts.overflows);
        true
    }

    /// Entries in flight on `lane` (tests).
    #[cfg(test)]
    #[must_use]
    pub fn in_flight(&self, lane: usize) -> usize {
        self.lanes
            .get(lane)
            .map_or(0, |state| state.in_flight.len())
    }

    /// One drained report of `lane`'s etf socket: a drop of the datagrams
    /// sent at `txtime`. Every entry with that time is dropped (a second
    /// report of the same time finds none, and is late). A reliable lane's
    /// ranges wait for their catch-up; an unreliable lane's are gaps.
    /// Returns how many entries it dropped.
    pub fn drained(&mut self, lane: usize, txtime: u64) -> usize {
        let Some(state) = self.lanes.get_mut(lane) else {
            bump(&mut self.counts.other_reports, &mut self.counts.overflows);
            return 0;
        };
        let mut dropped = 0usize;
        let mut index = 0;
        while index < state.in_flight.len() {
            let Some(entry) = state.in_flight.get(index).copied() else {
                break;
            };
            if entry.txtime != txtime {
                index = index.saturating_add(1);
                continue;
            }
            let _ = state.in_flight.remove(index);
            dropped = dropped.saturating_add(1);
            bump(&mut self.counts.dropped, &mut self.counts.overflows);
            if self.reliable {
                insert_merged(&mut state.catch_ups, (entry.start, entry.end));
                bump(&mut self.counts.caught_up, &mut self.counts.overflows);
            } else {
                bump(&mut self.counts.gaps, &mut self.counts.overflows);
            }
        }
        if dropped == 0 {
            bump(
                &mut self.counts.late_drop_reports,
                &mut self.counts.overflows,
            );
            if self.late.len() < self.late_bound {
                self.late.push_back(LateReport { lane, txtime });
            }
        }
        dropped
    }

    /// Counts a report that is not an etf drop.
    pub fn other_report(&mut self) {
        bump(&mut self.counts.other_reports, &mut self.counts.overflows);
    }

    /// Retires, as sent, every entry whose time plus the advance and the
    /// margin is before `tai_now` (ADR-0109 point 7). Call it after the
    /// duty's drain. Returns how many it retired.
    pub fn expire(&mut self, tai_now: u64) -> usize {
        let expiry = self.expiry;
        let mut retired = 0usize;
        for state in &mut self.lanes {
            // Times never go backwards on a lane, so the oldest expire
            // first; a reset's resend may break the order, so every entry
            // is checked.
            let before = state.in_flight.len();
            state
                .in_flight
                .retain(|entry| entry.txtime.saturating_add(expiry) >= tai_now);
            retired = retired.saturating_add(before.saturating_sub(state.in_flight.len()));
        }
        for _ in 0..retired {
            bump(&mut self.counts.expired, &mut self.counts.overflows);
        }
        retired
    }

    /// The oldest late report not yet posted to the driver's diagnostic
    /// ring; at most [`DRAIN_BATCH`] wait (every one is counted).
    #[must_use]
    pub fn peek_late(&self) -> Option<LateReport> {
        self.late.front().copied()
    }

    /// The oldest late report was posted.
    pub fn pop_late(&mut self) {
        let _ = self.late.pop_front();
    }

    /// The first dropped range of `lane` waiting for its catch-up, in
    /// position order, if any.
    #[must_use]
    pub fn next_catch_up(&self, lane: usize) -> Option<(u64, u64)> {
        self.lanes
            .get(lane)
            .and_then(|state| state.catch_ups.front().copied())
    }

    /// The catch-up of `lane`'s first range covered it up to `through`: the
    /// range shrinks to what is left, and goes once nothing is.
    pub fn caught_up_through(&mut self, lane: usize, through: u64) {
        let Some(state) = self.lanes.get_mut(lane) else {
            return;
        };
        if let Some(front) = state.catch_ups.front_mut() {
            front.0 = front.0.max(through);
            if front.0 >= front.1 {
                let _ = state.catch_ups.pop_front();
            }
        }
    }

    /// Forgets `lane`'s entries and catch-ups: its queue was reset, and a
    /// reliable lane reads again from its registered position.
    pub fn forget(&mut self, lane: usize) {
        if let Some(state) = self.lanes.get_mut(lane) {
            state.in_flight.clear();
            state.catch_ups.clear();
        }
    }
}

/// Inserts `range` into `ranges`, kept ordered by start and merged where
/// two touch or overlap. The list is bounded by the in-flight list, whose
/// entries each give at most one range.
fn insert_merged(ranges: &mut VecDeque<(u64, u64)>, range: (u64, u64)) {
    let at = ranges.partition_point(|existing| existing.0 < range.0);
    ranges.insert(at, range);
    // Merge with the neighbours.
    let mut index = at.saturating_sub(1);
    while index.saturating_add(1) < ranges.len() {
        let (Some(left), Some(right)) = (
            ranges.get(index).copied(),
            ranges.get(index.saturating_add(1)).copied(),
        ) else {
            break;
        };
        if right.0 <= left.1 {
            if let Some(merged) = ranges.get_mut(index) {
                merged.1 = merged.1.max(right.1);
            }
            let _ = ranges.remove(index.saturating_add(1));
        } else if index > at {
            break;
        } else {
            index = index.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests;
