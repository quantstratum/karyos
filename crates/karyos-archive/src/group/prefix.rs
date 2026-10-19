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
//! An incomplete event, or a gap marker, stops both prefixes there: replay
//! claims nothing across them. A checkpoint recorded after the stop opens
//! a new range (A9, `recording-group-checkpoints.md` section 5): the state
//! at its `group_seq` is known, so the events after it are replayable
//! again. The tracker follows the current range only; recovery derives
//! the earlier ones from the journal. A range a checkpoint opens starts
//! its complete prefix at the checkpoint once its record is written (its
//! bytes are then in the checkpoint store), and its durable prefix once
//! the record and the bytes are durable. A checkpoint inside a range holds
//! back nothing. Each value is the `group_seq` of the last event in it;
//! before any, it is `first_group_seq - 1`.
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

    /// The durable end of recording `recording_id` once it ended, which
    /// will never cover more: its stop for a `required` recording, or its
    /// frames durable at a failure; 0 for any other (it vouches for
    /// nothing), for a recording this Archive does not know, and for a
    /// failed one whose entry was reclaimed (A7d-1c). `None` while it
    /// records. A reference that reaches the journal after its recording
    /// ended is settled by it.
    fn ended(&self, recording_id: u64) -> Option<u64>;

    /// What the checkpoint store holds of `[position, end)`; the default,
    /// with no checkpoint store, is [`CheckpointHeld::Missing`]. A lost
    /// checkpoint never opens its range, and the next one may.
    fn checkpoint(&self, position: u64, end: u64) -> CheckpointHeld {
        let _ = (position, end);
        CheckpointHeld::Missing
    }
}

/// What a checkpoint store holds of a checkpoint's range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointHeld {
    /// Not written yet.
    Missing,
    /// Lost: a crash took its bytes after its record was kept, or they
    /// fail their check. It never will be held.
    Lost,
    /// Written, not yet durable.
    Written,
    /// Written and durable.
    Durable,
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
    /// For the checkpoint opening a range: its range in the checkpoint
    /// store.
    checkpoint: Option<(u64, u64)>,
}

/// What the tracker keeps of the journal after a stop, for a checkpoint
/// that may open a range there: an ended event, or a later stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Candidate {
    /// A complete event.
    Event(Waiting),
    /// An incomplete event or a gap: the first event not queued, and the
    /// lowest checkpoint `group_seq` past it.
    Stop { stop: u64, reopen_at: u64 },
}

impl Candidate {
    /// The checkpoint `group_seq` at or above which it lies behind.
    const fn behind_at(&self) -> u64 {
        match self {
            Self::Event(waiting) => waiting.seq,
            Self::Stop { reopen_at, .. } => *reopen_at,
        }
    }
}

/// The checkpoint that opened a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeStart {
    /// Its id.
    pub checkpoint_id: u64,
    /// The last event its state includes.
    pub group_seq: u64,
}

/// The range the tracker follows (`recording-group-checkpoints.md`
/// section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// The checkpoint that opened it; `None` for the journal's first.
    pub start: Option<RangeStart>,
    /// Its `complete_recording_seq`. Until the checkpoint that opened it
    /// completes, the value the previous range ended at.
    pub complete: u64,
    /// Its `durable_group_seq`, with the same rule.
    pub durable: u64,
}

/// The journal's first range as it ended, frozen when a checkpoint opened
/// another: replay from the journal's start stops there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstRange {
    /// Its final `complete_recording_seq`.
    pub complete: u64,
    /// The journal position after its last complete event.
    pub complete_end: u64,
    /// Its final `durable_group_seq`.
    pub durable: u64,
}

/// The three values, for other threads, and where the current range
/// starts.
#[derive(Debug, Default)]
pub struct PrefixView {
    delivered: AtomicU64,
    complete: AtomicU64,
    durable: AtomicU64,
    /// The `group_seq` of the checkpoint that opened the current range; 0
    /// in the journal's first range.
    range_start: AtomicU64,
    /// The first range's `durable_group_seq`, once a checkpoint opened
    /// another.
    first_durable: AtomicU64,
    /// The highest `group_seq` of the first range's events still
    /// settling, 0 with none: up to it, an event may yet be durable.
    first_settling: AtomicU64,
}

/// Whether an event is durable, as [`PrefixView::durable_for`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableFor {
    /// It is: the `durable_group_seq` that covers it.
    Reached(u64),
    /// It never will be: an event before the current range that the first
    /// range's durable prefix does not cover and that is not still
    /// settling. The value is that prefix.
    Never(u64),
    /// Not yet: the current range's `durable_group_seq`, or, for an event
    /// of the first range still settling, the first range's.
    Pending(u64),
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

    /// `durable_group_seq`: the current range's. Across a checkpoint that
    /// opened another range it says nothing of the events before it; a
    /// wait for one event uses [`PrefixView::durable_for`].
    #[must_use]
    pub fn durable_group_seq(&self) -> u64 {
        self.durable.load(Ordering::Acquire)
    }

    /// Whether event `seq` is durable. An event at or before the current
    /// range's checkpoint is answered from the first range's final
    /// durable prefix, frozen when a checkpoint opened another range: an
    /// event of a middle range counts as never durable, a conservative
    /// answer, since replay claims nothing across a stop.
    #[must_use]
    pub fn durable_for(&self, seq: u64) -> DurableFor {
        // Durable first: a range's values are published after its start.
        let durable = self.durable.load(Ordering::Acquire);
        let start = self.range_start.load(Ordering::Acquire);
        if start != 0 && seq <= start {
            // Settling before durable: an emptied queue's last value is
            // seen with it.
            let settling = self.first_settling.load(Ordering::Acquire);
            let first = self.first_durable.load(Ordering::Acquire);
            return if seq <= first {
                DurableFor::Reached(first)
            } else if seq <= settling {
                DurableFor::Pending(first)
            } else {
                DurableFor::Never(first)
            };
        }
        if durable >= seq {
            DurableFor::Reached(durable)
        } else {
            DurableFor::Pending(durable)
        }
    }

    /// `(delivered_seq, complete_recording_seq, durable_group_seq)`, the
    /// current range's values (see [`PrefixView::durable_group_seq`]), read so
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
    /// The lowest checkpoint `group_seq` that opens a range past `stop`.
    reopen_at: u64,
    /// After a stop: what a checkpoint opening a range needs, in order,
    /// bounded by `capacity`.
    candidates: VecDeque<Candidate>,
    /// The highest `group_seq` a full `candidates` let go: a range opened
    /// below it cannot advance, since what lies between is unknown.
    lost_through: u64,
    /// How many events `candidates` holds past a stop: the reopening
    /// window's own capacity ([`PrefixTracker::reserve_reopen_hold`]).
    hold: usize,
    /// Checkpoints that opened a range which stayed at them, `candidates`
    /// having let go of events after them.
    failed_reopens: u64,
    /// The checkpoint that opened the current range.
    start: Option<RangeStart>,
    /// A checkpoint past the stop whose bytes the coverage has not yet
    /// answered for: its record, and where the record ends.
    pending: Option<(super::record::CheckpointRecord, u64)>,
    /// The checkpoint opening the current range, until it is durable: the
    /// range's events wait behind it.
    opening: Option<Waiting>,
    /// The first range: its values once a checkpoint opened another, which
    /// keep following the events it still waits on (`settling`).
    first: Option<FirstRange>,
    /// The first range's events still waiting when a checkpoint opened
    /// another: they settle as before, into `first`, never into the new
    /// range.
    settling: VecDeque<Waiting>,
    view: Arc<PrefixView>,
}

/// Makes room in `queue` for `hold` entries in all, fallibly.
fn hold_room<T>(
    queue: &mut VecDeque<T>,
    hold: usize,
) -> Result<(), std::collections::TryReserveError> {
    if let Some(more) = hold.checked_sub(queue.len()) {
        queue.try_reserve_exact(more)?;
    }
    Ok(())
}

impl PrefixTracker {
    /// [`PrefixTracker::new`], allocating fallibly: the configured bound
    /// may be one the host cannot hold.
    ///
    /// # Errors
    ///
    /// The allocation's failure.
    pub fn try_new(capacity: usize) -> Result<Self, std::collections::TryReserveError> {
        let mut tracker = Self::new(1);
        let capacity = capacity.max(1);
        hold_room(&mut tracker.waiting, capacity)?;
        hold_room(&mut tracker.candidates, capacity)?;
        hold_room(&mut tracker.settling, capacity)?;
        tracker.capacity = capacity;
        tracker.hold = capacity;
        Ok(tracker)
    }

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
            reopen_at: 0,
            candidates: VecDeque::with_capacity(capacity),
            hold: capacity,
            failed_reopens: 0,
            lost_through: 0,
            start: None,
            pending: None,
            opening: None,
            first: None,
            settling: VecDeque::with_capacity(capacity),
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
            | GroupRecord::Delivery(_)
            | GroupRecord::Poll(_) => {
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
                    self.stopped_at(seq, seq);
                } else if self.stop.is_some() {
                    self.candidate(Candidate::Event(Waiting {
                        seq,
                        journal_end,
                        reference,
                        checkpoint: None,
                    }));
                } else {
                    if self.waiting.len() >= self.capacity {
                        return Err(PrefixError::Full {
                            capacity: self.capacity,
                        });
                    }
                    self.waiting.push_back(Waiting {
                        seq,
                        journal_end,
                        reference,
                        checkpoint: None,
                    });
                }
                self.open = None;
            }
            GroupRecord::Gap(gap) => {
                if self.open.is_some() {
                    return Err(PrefixError::OutOfOrder);
                }
                let after = gap.to_seq.checked_add(1).ok_or(PrefixError::Exhausted)?;
                self.stopped_at(after, gap.to_seq);
            }
            GroupRecord::Checkpoint(checkpoint) => {
                if self.open.is_some() {
                    return Err(PrefixError::OutOfOrder);
                }
                // It opens a range once the coverage says its bytes are
                // held ([`PrefixTracker::advance`]); a later one past the
                // stop takes its place.
                let opens = self.stop.is_some() && checkpoint.group_seq >= self.reopen_at;
                if opens && checkpoint.end().is_some() {
                    self.pending = Some((*checkpoint, journal_end));
                }
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
    /// the prefixes cannot reach it; such a mark is taken unchecked,
    /// since checking it would need to remember every event past the
    /// stop, without bound. A `group_seq` inside the gap that stopped them
    /// names no event, and is refused.
    fn settle(&mut self, seq: u64, recording_id: u64) -> Result<(), PrefixError> {
        let no_reference = PrefixError::NoReference {
            group_seq: seq,
            recording_id,
        };
        let candidates = self
            .candidates
            .iter_mut()
            .filter_map(|candidate| match candidate {
                Candidate::Event(waiting) => Some(waiting),
                Candidate::Stop { .. } => None,
            });
        if let Some(waiting) = self
            .waiting
            .iter_mut()
            .chain(self.settling.iter_mut())
            .chain(candidates)
            .find(|waiting| waiting.seq == seq)
        {
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

    /// An incomplete event or a gap: `stop` is the first event not queued,
    /// `reopen_at` the lowest checkpoint past it. The first stops the
    /// current range; a later one is kept for a range a checkpoint opens.
    fn stopped_at(&mut self, stop: u64, reopen_at: u64) {
        if self.stop.is_none() {
            self.stop = Some(stop);
            self.reopen_at = reopen_at;
        } else {
            self.candidate(Candidate::Stop { stop, reopen_at });
        }
    }

    /// Keeps `candidate`, letting the oldest go when there is no room.
    fn candidate(&mut self, candidate: Candidate) {
        if self.candidates.len() >= self.hold
            && let Some(oldest) = self.candidates.pop_front()
        {
            self.lost_through = self.lost_through.max(oldest.behind_at());
        }
        self.candidates.push_back(candidate);
    }

    /// The checkpoint `checkpoint`, whose record ends at `journal_end`,
    /// opens a range past the stop. The first range's values are kept, for
    /// replay from the start and for [`PrefixView::durable_for`], and the
    /// events it still waits on keep settling into them; a later range's
    /// are let go. Neither is ever claimed by the new range. The range starts at the checkpoint,
    /// then takes the events after it that ended before its record, up to
    /// the next stop.
    fn open_range(
        &mut self,
        checkpoint: &super::record::CheckpointRecord,
        end: u64,
        journal_end: u64,
    ) -> Result<(), PrefixError> {
        let seq = checkpoint.group_seq;
        let after = seq.checked_add(1).ok_or(PrefixError::Exhausted)?;
        if self.first.is_none() {
            self.first = Some(FirstRange {
                complete: self.complete,
                complete_end: self.complete_end,
                durable: self.durable,
            });
            // `settling` is empty: the first range's waiting events move
            // there, and `waiting` is left empty, with its room.
            std::mem::swap(&mut self.waiting, &mut self.settling);
        }
        self.waiting.clear();
        self.opening = Some(Waiting {
            seq,
            journal_end,
            reference: None,
            checkpoint: Some((checkpoint.position, end)),
        });
        self.start = Some(RangeStart {
            checkpoint_id: checkpoint.checkpoint_id,
            group_seq: seq,
        });
        if self.lost_through > seq {
            // What lies between is unknown: the range stays at the
            // checkpoint, and a later one may open the next.
            // Past `u64` the count holds.
            if let Some(failed) = self.failed_reopens.checked_add(1) {
                self.failed_reopens = failed;
            }
            self.stop = Some(after);
            self.reopen_at = after;
            return Ok(());
        }
        self.stop = None;
        while let Some(candidate) = self.candidates.pop_front() {
            if candidate.behind_at() <= seq {
                continue;
            }
            match candidate {
                Candidate::Event(waiting) => self.waiting.push_back(waiting),
                Candidate::Stop { stop, reopen_at } => {
                    self.stop = Some(stop.max(after));
                    self.reopen_at = reopen_at;
                    break;
                }
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

    /// Recording `recording_id` stopped or failed with its frames durable
    /// to `durable`: each waiting event whose payload it covers counts
    /// covered for good, and `uncovered` is called with each one it does
    /// not cover, which will never be covered (A7d,
    /// `recording-group-gateway.md` section 7).
    pub fn recording_ended(
        &mut self,
        recording_id: u64,
        durable: u64,
        mut uncovered: impl FnMut(u64),
    ) {
        let candidates = self
            .candidates
            .iter_mut()
            .filter_map(|candidate| match candidate {
                Candidate::Event(waiting) => Some(waiting),
                Candidate::Stop { .. } => None,
            });
        for waiting in self
            .waiting
            .iter_mut()
            .chain(self.settling.iter_mut())
            .chain(candidates)
        {
            match waiting.reference {
                Some((recording, end)) if recording == recording_id => {
                    if end <= durable {
                        waiting.reference = None;
                    } else {
                        uncovered(waiting.seq);
                    }
                }
                _ => {}
            }
        }
    }

    /// The recordings and frame ends the waiting events' payloads name, in
    /// order: `(recording_id, end)`. Past a stop, those of the events a
    /// checkpoint may yet take into a range.
    pub fn references(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        let candidates = self
            .candidates
            .iter()
            .filter_map(|candidate| match candidate {
                Candidate::Event(waiting) => waiting.reference,
                Candidate::Stop { .. } => None,
            });
        self.waiting
            .iter()
            .chain(self.settling.iter())
            .filter_map(|waiting| waiting.reference)
            .chain(candidates)
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
        if let Some((checkpoint, journal_end)) = self.pending
            && let Some(end) = checkpoint.end()
        {
            match coverage.checkpoint(checkpoint.position, end) {
                CheckpointHeld::Missing => {}
                // Lost: it opens nothing, and the next one may.
                CheckpointHeld::Lost => self.pending = None,
                CheckpointHeld::Written | CheckpointHeld::Durable => {
                    self.pending = None;
                    // Only a `group_seq` past `u64` fails, which the order
                    // rules refuse: the range stays stopped.
                    let _ = self.open_range(&checkpoint, end, journal_end);
                }
            }
        }
        let covered = |waiting: &Waiting, durable_only: bool| match waiting.reference {
            None => waiting.checkpoint.is_none_or(|(position, end)| {
                match coverage.checkpoint(position, end) {
                    CheckpointHeld::Durable => true,
                    CheckpointHeld::Written => !durable_only,
                    CheckpointHeld::Missing | CheckpointHeld::Lost => false,
                }
            }),
            Some((recording, end)) => {
                coverage
                    .positions(recording)
                    .is_some_and(|(written, durable)| {
                        end <= if durable_only { durable } else { written }
                    })
            }
        };
        // The first range's events still settling, into its values.
        if let Some(first) = self.first.as_mut() {
            while let Some(front) = self.settling.front().copied() {
                if front.journal_end > durable || !covered(&front, true) {
                    break;
                }
                first.durable = front.seq;
                if front.seq > first.complete {
                    first.complete = front.seq;
                    first.complete_end = front.journal_end;
                }
                let _ = self.settling.pop_front();
            }
            for waiting in &self.settling {
                if waiting.seq <= first.complete {
                    continue;
                }
                if waiting.journal_end > written || !covered(waiting, false) {
                    break;
                }
                first.complete = waiting.seq;
                first.complete_end = waiting.journal_end;
            }
        }
        // A range's opening checkpoint first: its events wait behind it.
        if let Some(opening) = self.opening {
            if opening.journal_end <= durable && covered(&opening, true) {
                self.opening = None;
                self.durable = opening.seq;
                if opening.seq > self.complete {
                    self.complete = opening.seq;
                    self.complete_end = opening.journal_end;
                }
            } else {
                if opening.seq > self.complete
                    && opening.journal_end <= written
                    && covered(&opening, false)
                {
                    self.complete = opening.seq;
                    self.complete_end = opening.journal_end;
                }
                if self.complete < opening.seq {
                    self.publish();
                    return (self.complete, self.durable);
                }
            }
        }
        // Durable events leave the queue; they are complete too.
        while let Some(front) = self.waiting.front().copied() {
            if self.opening.is_some() {
                break;
            }
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
        // The range's start before its values (PrefixView::durable_for).
        if let (Some(first), Some(start)) = (self.first, self.start) {
            let settling = self.settling.back().map_or(0, |waiting| waiting.seq);
            self.view
                .first_durable
                .store(first.durable, Ordering::Release);
            self.view.first_settling.store(settling, Ordering::Release);
            self.view
                .range_start
                .store(start.group_seq, Ordering::Release);
        }
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

    /// The range it follows: the checkpoint that opened it, and its complete
    /// and durable values.
    #[must_use]
    pub const fn range(&self) -> Range {
        Range {
            start: self.start,
            complete: self.complete,
            durable: self.durable,
        }
    }

    /// Sizes the reopening window (A9-3): past a stop, exactly `hold`
    /// events (the tracker's capacity for a hold of 0) are kept for a
    /// checkpoint that may open a range, and the queues have room for
    /// them once it does, at least the capacity. The events expected
    /// while one checkpoint is written, under the Gateway unbounded while
    /// stopped, are its measure. Allocates here, at configuration, before
    /// any record.
    ///
    /// # Errors
    ///
    /// The allocation's failure, with the window unchanged.
    pub fn reserve_reopen_hold(
        &mut self,
        hold: usize,
    ) -> Result<(), std::collections::TryReserveError> {
        let hold = if hold == 0 { self.capacity } else { hold };
        let room = hold.max(self.capacity);
        hold_room(&mut self.candidates, room)?;
        hold_room(&mut self.waiting, room)?;
        hold_room(&mut self.settling, room)?;
        self.hold = hold;
        Ok(())
    }

    /// Checkpoints that opened a range which stayed at them: events after
    /// them were let go while it was written, beyond the reopening
    /// window. A later checkpoint opens the range.
    #[must_use]
    pub const fn failed_reopens(&self) -> u64 {
        self.failed_reopens
    }

    /// The first range as it ended, once a checkpoint opened another:
    /// replay from the journal's start stops there.
    #[must_use]
    pub const fn first_range(&self) -> Option<FirstRange> {
        self.first
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
    /// The feed stopped: an event found no room, with `capacity` events
    /// waiting on their payloads (or a record was refused). The tracker
    /// then holds only the journal's start, and cannot take the next
    /// events.
    pub full: bool,
}

/// Recomputes the prefixes of a recovered `journal`, every record of it
/// taken as written and durable (recovery made it so), the payloads by
/// `coverage`. When the queue is full at an event's end, the prefixes are
/// advanced and the end taken again; an event that still finds no room,
/// with `capacity` events waiting on their payloads, stops the feed there,
/// so `capacity` should be at least the running tracker's. The reopening
/// window holds the events the journal's header records
/// ([`JournalHeader::reopen_hold`](super::record::JournalHeader::reopen_hold),
/// at least `capacity`), as the run's did: a range a checkpoint reopened
/// is recovered as it ran, by any reader of the journal.
///
/// # Errors
///
/// The journal's read errors, and
/// [`JournalError::Allocation`](super::journal::JournalError::Allocation)
/// for a tracker or a hold that cannot be allocated.
pub fn recover<D: crate::disk::Disk>(
    journal: &mut super::journal::GroupJournal<D>,
    coverage: &impl Coverage,
    capacity: usize,
) -> Result<Recovery, super::journal::JournalError> {
    // The reopening window is exactly the header's (A9), as the run's
    // was, whatever `capacity` the reader gives: that sizes the queues.
    let allocation = |_| super::journal::JournalError::Allocation;
    // A journal without a header holds no event: no window.
    let recorded = journal.reopen_hold()?.unwrap_or(0);
    let hold = usize::try_from(recorded).map_err(|_| super::journal::JournalError::Allocation)?;
    let mut tracker = PrefixTracker::try_new(capacity).map_err(allocation)?;
    tracker.reserve_reopen_hold(hold).map_err(allocation)?;
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
    Ok(Recovery {
        tracker,
        last_seen,
        full,
    })
}
