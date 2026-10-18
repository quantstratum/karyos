// SPDX-License-Identifier: Apache-2.0

//! A recording group's three prefixes (`quantstratum-docs:
//! karyos/SPEC.md` §8.3, "Completeness and persistence"; ADR-0024;
//! archive-gap-analysis.md, phase 3 batch A7c).
//!
//! - **`delivered_seq`**: the last event the Gateway handed to the handler.
//! - **`complete_recording_seq`**: the last event of the complete prefix.
//!   An event is complete when its records, through its end, are written
//!   to the journal, its end says it is complete, and the payload it names
//!   by reference is written in its recording. The prefix advances only
//!   over complete events, in order.
//! - **`durable_group_seq`**: the same with every part durable: the
//!   journal through the event's end, and the referenced payload, by the
//!   storage persistence policy.
//!
//! An incomplete event, or a gap marker, stops both prefixes there for
//! good: replay claims nothing across them (a consistent checkpoint, A9,
//! is what lets a prefix resume). Each value is the `group_seq` of the
//! last event in it; before any, it is `first_group_seq - 1`.
//!
//! The tracker holds the events written and not yet durable in a queue
//! sized when it is made: an event it has no room for is refused, which
//! is how strict capture stops admitting (A7d). It allocates nothing after
//! it is made. A [`PrefixView`] publishes the three values to other threads,
//! each a wait-free Acquire load.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::record::{EndOutcome, GroupRecord, Payload};

#[cfg(test)]
mod tests;

/// How far a recording's frames are written and durable.
pub trait Coverage {
    /// Recording `recording_id`'s `(written, durable)` positions, or `None`
    /// for a recording this Archive does not keep.
    fn positions(&self, recording_id: u64) -> Option<(u64, u64)>;
}

/// Why the tracker refused a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PrefixError {
    /// The queue of events not yet durable is full.
    #[error("{capacity} events wait to be durable")]
    Full {
        /// The queue's capacity.
        capacity: usize,
    },
    /// A record out of the order the journal checks: the tracker takes
    /// only the journal's records, in order.
    #[error("record out of order")]
    OutOfOrder,
    /// A `group_seq` or a position past `u64`.
    #[error("sequence or position exhausted")]
    Exhausted,
}

/// What one complete event still needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Waiting {
    /// Its `group_seq`.
    seq: u64,
    /// The journal position after its end.
    journal_end: u64,
    /// The recording and the end of the frames its payload names.
    reference: Option<(u64, u64)>,
}

/// The three values, for other threads.
#[derive(Debug, Default)]
pub struct PrefixView {
    delivered: AtomicU64,
    complete: AtomicU64,
    durable: AtomicU64,
}

impl PrefixView {
    /// `delivered_seq`.
    #[must_use]
    pub fn delivered_seq(&self) -> u64 {
        self.delivered.load(Ordering::Acquire)
    }

    /// `complete_recording_seq`.
    #[must_use]
    pub fn complete_recording_seq(&self) -> u64 {
        self.complete.load(Ordering::Acquire)
    }

    /// `durable_group_seq`.
    #[must_use]
    pub fn durable_group_seq(&self) -> u64 {
        self.durable.load(Ordering::Acquire)
    }
}

/// The prefixes of one group.
#[derive(Debug)]
pub struct PrefixTracker {
    /// Complete events not yet durable, in order.
    waiting: VecDeque<Waiting>,
    capacity: usize,
    /// The event whose records are being taken, and its reference.
    open: Option<(u64, Option<(u64, u64)>)>,
    /// No header taken yet.
    started: bool,
    /// The last event delivered, complete and durable.
    delivered: u64,
    complete: u64,
    durable: u64,
    /// The journal position after the complete prefix's last record.
    complete_end: u64,
    /// An incomplete event or a gap stopped the prefixes.
    stopped: bool,
    view: Arc<PrefixView>,
}

impl PrefixTracker {
    /// A tracker with room for `capacity` events written and not yet
    /// durable, at least 1.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            waiting: VecDeque::with_capacity(capacity),
            capacity,
            open: None,
            started: false,
            delivered: 0,
            complete: 0,
            durable: 0,
            complete_end: 0,
            stopped: false,
            view: Arc::new(PrefixView::default()),
        }
    }

    /// The view other threads read.
    #[must_use]
    pub fn view(&self) -> Arc<PrefixView> {
        Arc::clone(&self.view)
    }

    /// Takes the journal's next `record`, which ends at `journal_end` in
    /// the journal: in the journal's order, after the journal took it.
    ///
    /// # Errors
    ///
    /// [`PrefixError::Full`] for a complete event with no room (nothing
    /// changes), [`PrefixError::OutOfOrder`] and
    /// [`PrefixError::Exhausted`].
    pub fn record(
        &mut self,
        record: &GroupRecord<'_>,
        journal_end: u64,
    ) -> Result<(), PrefixError> {
        match record {
            GroupRecord::Header(header) => {
                if self.started {
                    return Err(PrefixError::OutOfOrder);
                }
                let before = header
                    .first_group_seq
                    .checked_sub(1)
                    .ok_or(PrefixError::OutOfOrder)?;
                self.started = true;
                (self.delivered, self.complete, self.durable) = (before, before, before);
                self.complete_end = journal_end;
                self.publish();
                return Ok(());
            }
            _ if !self.started => return Err(PrefixError::OutOfOrder),
            GroupRecord::Message(message) => {
                let reference = match message.payload {
                    Payload::Inline(_) => None,
                    Payload::Reference { recording_id, .. } => Some((
                        recording_id,
                        message
                            .position
                            .checked_add(u64::from(message.extent))
                            .ok_or(PrefixError::Exhausted)?,
                    )),
                };
                self.open_event(message.group_seq, reference)?;
            }
            GroupRecord::Conflated(event) => self.open_event(event.group_seq, None)?,
            GroupRecord::Timer(event) => self.open_event(event.group_seq, None)?,
            GroupRecord::Lifecycle(event) => self.open_event(event.group_seq, None)?,
            GroupRecord::External(event) => self.open_event(event.group_seq, None)?,
            GroupRecord::Outcome(_)
            | GroupRecord::TimerOperation(_)
            | GroupRecord::ExternalObservation(_)
            | GroupRecord::Delivery(_) => {
                if self.open.is_none() {
                    return Err(PrefixError::OutOfOrder);
                }
            }
            GroupRecord::End(end) => {
                let Some((seq, reference)) = self.open else {
                    return Err(PrefixError::OutOfOrder);
                };
                if seq != end.group_seq {
                    return Err(PrefixError::OutOfOrder);
                }
                if end.outcome == EndOutcome::Incomplete {
                    self.stopped = true;
                } else if !self.stopped {
                    if self.waiting.len() >= self.capacity {
                        return Err(PrefixError::Full {
                            capacity: self.capacity,
                        });
                    }
                    self.waiting.push_back(Waiting {
                        seq,
                        journal_end,
                        reference,
                    });
                }
                self.open = None;
            }
            GroupRecord::Gap(_) => {
                if self.open.is_some() {
                    return Err(PrefixError::OutOfOrder);
                }
                self.stopped = true;
            }
        }
        Ok(())
    }

    fn open_event(&mut self, seq: u64, reference: Option<(u64, u64)>) -> Result<(), PrefixError> {
        if self.open.is_some() {
            return Err(PrefixError::OutOfOrder);
        }
        self.open = Some((seq, reference));
        Ok(())
    }

    /// Whether the queue has room for one more complete event: the strict
    /// admission check before a dispatch.
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.waiting.len() < self.capacity
    }

    /// The Gateway handed event `seq` to the handler.
    pub fn delivered(&mut self, seq: u64) {
        if seq > self.delivered {
            self.delivered = seq;
            self.view.delivered.store(seq, Ordering::Release);
        }
    }

    /// Advances the prefixes over what is now written and durable: the
    /// journal's `written` and `durable` positions, and the recordings'
    /// through `coverage`. Returns `(complete, durable)`.
    pub fn advance(&mut self, written: u64, durable: u64, coverage: &impl Coverage) -> (u64, u64) {
        let covered = |waiting: &Waiting, durable_only: bool| match waiting.reference {
            None => true,
            Some((recording, end)) => {
                coverage
                    .positions(recording)
                    .is_some_and(|(written, durable)| {
                        end <= if durable_only { durable } else { written }
                    })
            }
        };
        // Durable events leave the queue; they are complete too.
        while let Some(front) = self.waiting.front().copied() {
            if front.journal_end > durable || !covered(&front, true) {
                break;
            }
            self.durable = front.seq;
            if front.seq > self.complete {
                self.complete = front.seq;
                self.complete_end = front.journal_end;
            }
            let _ = self.waiting.pop_front();
        }
        for waiting in &self.waiting {
            if waiting.seq <= self.complete {
                continue;
            }
            if waiting.journal_end > written || !covered(waiting, false) {
                break;
            }
            self.complete = waiting.seq;
            self.complete_end = waiting.journal_end;
        }
        self.publish();
        (self.complete, self.durable)
    }

    fn publish(&self) {
        self.view.delivered.store(self.delivered, Ordering::Release);
        self.view.complete.store(self.complete, Ordering::Release);
        self.view.durable.store(self.durable, Ordering::Release);
    }

    /// `delivered_seq`.
    #[must_use]
    pub const fn delivered_seq(&self) -> u64 {
        self.delivered
    }

    /// `complete_recording_seq`.
    #[must_use]
    pub const fn complete_recording_seq(&self) -> u64 {
        self.complete
    }

    /// `durable_group_seq`.
    #[must_use]
    pub const fn durable_group_seq(&self) -> u64 {
        self.durable
    }

    /// The journal position after the complete prefix's last record: the
    /// header's end before any event.
    #[must_use]
    pub const fn complete_end(&self) -> u64 {
        self.complete_end
    }

    /// Whether an incomplete event or a gap stopped the prefixes.
    #[must_use]
    pub const fn stopped(&self) -> bool {
        self.stopped
    }
}

/// A journal's prefixes after a restart.
#[derive(Debug)]
pub struct Recovery {
    /// The tracker, with the complete and durable prefixes of what the
    /// journal kept.
    pub tracker: PrefixTracker,
    /// The last event the journal holds records of, complete or not: the
    /// events after the complete prefix, up to it, are outside the replay
    /// guarantee.
    pub last_seen: u64,
}

/// Recomputes the prefixes of a recovered `journal`, every record of it
/// taken as written and durable (recovery made it so), the payloads by
/// `coverage`. Events the tracker had no room for, with `capacity` events
/// waiting on their payloads, stay outside the prefix.
///
/// # Errors
///
/// The journal's read errors.
pub fn recover<D: crate::disk::Disk>(
    journal: &mut super::journal::GroupJournal<D>,
    coverage: &impl Coverage,
    capacity: usize,
) -> Result<Recovery, super::journal::JournalError> {
    let mut tracker = PrefixTracker::new(capacity);
    let mut last_seen = 0u64;
    let mut full = false;
    let durable = journal.durable();
    journal.walk(0, |_, end, record| {
        if let super::record::Role::Event(seq) = record.role() {
            last_seen = seq;
        }
        if full {
            return true;
        }
        if tracker.record(record, end).is_err() {
            full = true;
            return true;
        }
        if matches!(record, GroupRecord::End(_)) {
            let _ = tracker.advance(end, durable.min(end), coverage);
        }
        true
    })?;
    let written = journal.written();
    let _ = tracker.advance(written, durable, coverage);
    Ok(Recovery { tracker, last_seen })
}
