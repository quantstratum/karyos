// SPDX-License-Identifier: Apache-2.0

//! The absorption of NAK copies across redundant paths
//! (`quantstratum-docs: karyos/design/redundant-paths.md` section 7,
//! "Repair (RP-11)").
//!
//! A receiver sends one copy of each NAK on every path (RP-7), up to the
//! paths' skew apart. [`Absorb`] remembers, per incarnation, the NAKs that
//! created or joined a repair job: the validated receiver, the exact
//! interval, the route it came on and when. A later NAK with the same
//! receiver and interval, on another route, within `path_skew_window`, is
//! a copy: it is absorbed and counted, not a new job, and it spends no NAK
//! budget. One on the same route is a retry and is served. When the
//! retry's first copy arrives on another route within the window it is
//! absorbed too; the next retry, one RTT later, is served.
//!
//! The table holds `path_copy_entries` entries, allocated at construction.
//! An entry past the window is free again. When no entry is free, the NAK
//! is not recorded (counted `full`): its copies are served as ordinary
//! NAKs, so no NAK is dropped for lack of absorption state.

use karyos_protocol::network::Receiver;

/// What [`Absorb`] counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AbsorbCounts {
    /// NAK copies absorbed: another route carried the same request within
    /// the window.
    pub absorbed: u64,
    /// NAKs not recorded for a full table: their copies are served.
    pub full: u64,
    /// An increment did not apply (sticky).
    pub overflowed: bool,
}

impl AbsorbCounts {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64) {
        let count = field(self);
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => self.overflowed = true,
        }
    }
}

/// One NAK's request: who asked, and the exact interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyKey {
    /// The validated receiver.
    pub receiver: Receiver,
    /// The lane.
    pub lane: u8,
    /// The first requested position.
    pub start: u64,
    /// The length in bytes.
    pub length: u32,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    key: CopyKey,
    route: usize,
    at: u64,
}

/// One incarnation's table of recent NAKs, for absorbing their copies.
#[derive(Debug)]
pub struct Absorb {
    entries: Vec<Entry>,
    capacity: usize,
    window: u64,
    counts: AbsorbCounts,
}

impl Absorb {
    /// A table of `capacity` entries (`path_copy_entries`) over a
    /// `window` in ns (`path_skew_window`). It allocates only here; a
    /// capacity of 0 absorbs nothing (one path).
    #[must_use]
    pub fn new(capacity: usize, window: u64) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
            window,
            counts: AbsorbCounts::default(),
        }
    }

    /// What it counted.
    #[must_use]
    pub fn counts(&self) -> AbsorbCounts {
        self.counts
    }

    /// Whether `now` is within the window after `at`. A clock read behind
    /// `at` is within it.
    fn within(&self, at: u64, now: u64) -> bool {
        now.checked_sub(at).is_none_or(|age| age <= self.window)
    }

    /// Whether the NAK `key` on `route` at `now` is a copy of one another
    /// route carried within the window; it is then counted absorbed.
    pub fn absorbs(&mut self, key: &CopyKey, route: usize, now: u64) -> bool {
        let copy = self
            .entries
            .iter()
            .any(|entry| entry.key == *key && entry.route != route && self.within(entry.at, now));
        if copy {
            self.counts.bump(|c| &mut c.absorbed);
        }
        copy
    }

    /// Records the NAK `key` that `route` carried at `now`, which created
    /// or joined a job: the entry of the same request and route is
    /// refreshed, else a free one (unused, or past the window) is taken.
    /// With none free it is counted `full` and not recorded.
    pub fn record(&mut self, key: &CopyKey, route: usize, now: u64) {
        if self.capacity == 0 {
            return;
        }
        let window = self.window;
        let within = |at: u64| now.checked_sub(at).is_none_or(|age| age <= window);
        let entry = Entry {
            key: *key,
            route,
            at: now,
        };
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|held| held.key == *key && held.route == route)
        {
            *slot = entry;
            return;
        }
        if let Some(slot) = self.entries.iter_mut().find(|held| !within(held.at)) {
            *slot = entry;
            return;
        }
        if self.entries.len() < self.capacity {
            self.entries.push(entry);
            return;
        }
        self.counts.bump(|c| &mut c.full);
    }
}

#[cfg(test)]
mod tests;
