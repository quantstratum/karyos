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
///
/// Version 1 answers only for a `required` recording (ADR-0023), which is
/// never lapped, so every position below its written position holds
/// frames: an `async` recording may have recorded a lost range as a gap
/// and moved its written position past it (`recording-group-records.md`
/// sections 4.1 and 9). For any other recording it answers `None`, and an
/// event that references one never completes. A range-aware check comes in
/// a later version.
pub trait Coverage {
    /// Recording `recording_id`'s `(written, durable)` positions when it is
    /// a `required` recording this Archive keeps, else `None`.
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
    /// A reference unavailable record naming no event that waits on that
    /// recording's frames: none by that `group_seq`, one whose payload is
    /// not by reference to it, or one already marked.
    #[error("no event {group_seq} waits on recording {recording_id}")]
    NoReference {
        /// The event named.
        group_seq: u64,
        /// The recording named.
        recording_id: u64,
    },
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

    /// `(delivered_seq, complete_recording_seq, durable_group_seq)` read so
    /// that durable is never above complete: durable first, then complete
    /// (each published value is at least the one before, and complete is
    /// published before durable). Three separate reads may see a newer
    /// durable than complete.
    #[must_use]
    pub fn snapshot(&self) -> (u64, u64, u64) {
        let durable = self.durable.load(Ordering::Acquire);
        let complete = self.complete.load(Ordering::Acquire);
        let delivered = self.delivered.load(Ordering::Acquire);
        (delivered, complete, durable)
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
    /// Where an incomplete event or a gap stopped the prefixes: the first
    /// event not queued (the incomplete one, or the one after the gap),
    /// and no later one is either.
    stop: Option<u64>,
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
            stop: None,
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
    /// [`PrefixError::Full`] for a complete event with no room: nothing
    /// changes, the tracker stays inside the event, and the caller takes
    /// the same end again once [`PrefixTracker::has_room`] after
    /// [`PrefixTracker::advance`]. [`PrefixError::OutOfOrder`] and
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
                    Payload::Inline(_) | Payload::Unavailable { .. } => None,
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
            GroupRecord::Loss(event) => self.open_event(event.group_seq, None)?,
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
                    let _ = self.stop.get_or_insert(seq);
                } else if self.stop.is_none() {
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
            GroupRecord::Gap(gap) => {
                if self.open.is_some() {
                    return Err(PrefixError::OutOfOrder);
                }
                let after = gap.to_seq.checked_add(1).ok_or(PrefixError::Exhausted)?;
                let _ = self.stop.get_or_insert(after);
            }
            GroupRecord::Unavailable(unavailable) => {
                if self.open.is_some() {
                    return Err(PrefixError::OutOfOrder);
                }
                self.settle(unavailable.group_seq, unavailable.recording_id)?;
            }
        }
        Ok(())
    }

    /// Event `seq`'s payload, by reference to `recording_id`, will never be
    /// there: the event counts complete with its payload unavailable.
    ///
    /// A waiting event is always settled, also after the prefixes stopped:
    /// the events queued before the stop still complete. An event not
    /// waiting is taken as it is in two cases. One already durable: the
    /// recording held its frames after all, as one that recovers more after
    /// a crash than it reported before (`recording-group-gateway.md`
    /// section 7). One at or past the stop: no event is queued there, and
    /// the prefixes cannot reach it. A `group_seq` inside the gap that
    /// stopped them names no event, and is refused.
    fn settle(&mut self, seq: u64, recording_id: u64) -> Result<(), PrefixError> {
        let no_reference = PrefixError::NoReference {
            group_seq: seq,
            recording_id,
        };
        if let Some(waiting) = self.waiting.iter_mut().find(|waiting| waiting.seq == seq) {
            return match waiting.reference {
                Some((recording, _)) if recording == recording_id => {
                    waiting.reference = None;
                    Ok(())
                }
                _ => Err(no_reference),
            };
        }
        if seq <= self.durable || self.stop.is_some_and(|stop| seq >= stop) {
            Ok(())
        } else {
            Err(no_reference)
        }
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
        self.stop.is_some()
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
/// `coverage`. When the queue is full at an event's end, the prefixes are
/// advanced and the end taken again; an event that still finds no room,
/// with `capacity` events waiting on their payloads, stops the feed there,
/// so `capacity` should be at least the running tracker's.
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
        if let super::record::Role::Event(seq) | super::record::Role::Uncaptured(seq) =
            record.role()
        {
            last_seen = seq;
        }
        if full {
            return true;
        }
        let mut taken = tracker.record(record, end);
        if matches!(taken, Err(PrefixError::Full { .. })) {
            // Room comes back as events become durable: everything kept
            // is written, and durable up to `durable`.
            let _ = tracker.advance(end, durable.min(end), coverage);
            taken = tracker.record(record, end);
        }
        if taken.is_err() {
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
