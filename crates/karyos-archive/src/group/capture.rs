// SPDX-License-Identifier: Apache-2.0

//! A recording group's capture path (`quantstratum-docs:
//! karyos/design/recording-group-gateway.md` section 9, phase 3 batch
//! A7d-1b): from the event loop to the group's journal on the Archive's
//! thread.
//!
//! - **The ring.** One single producer, single consumer
//!   [`command_ring`] per group, made when the group is. Each message is
//!   one event's records back to back (or one gap marker), as
//!   [`GroupJournal::append`] takes them. A message is at most an eighth
//!   of the ring.
//! - **Room.** The ring has no free space query, so both ends count it in
//!   the ring's own positions: the [`CaptureSender`] the end of the last
//!   message it wrote, the [`CaptureJob`] the end of the last it read
//!   (each a message's position plus its framed, aligned extent, so a
//!   padding record at the ring's end is counted too). Before an event,
//!   [`CaptureSender::admit`] checks that the largest event fits, with the
//!   padding a wrap would need, and that fewer events are in flight than
//!   the prefix tracker holds; the tracker then never refuses an event.
//! - **The job.** [`CaptureJob::duty`], on the Archive's thread, reads the
//!   messages, appends each to the journal, feeds the tracker every record
//!   and marks each event delivered, then advances the prefixes over the
//!   journal's positions and the recordings' [`Coverage`].
//! - **Recordings that end.** [`CaptureJob::recording_ended`] settles every
//!   reference to a recording that stopped or failed: what its durable
//!   frames cover counts covered; what they do not is marked unavailable
//!   in a best-effort group ([`ReferenceUnavailable`]), and ends a strict
//!   one.
//! - **What comes back.** The [`PrefixView`]'s three values, each a
//!   wait-free load, and the group's [`GroupState`]. A [`GroupWaiter`]
//!   waits for durability on any thread but the event loop's; the job only
//!   notifies it, through a lock held for no work.
//!
//! The sender and the job allocate nothing after they are made.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use karyos_codec::{CodecError, Envelope};
use karyos_sys::command_ring::{RingConsumer, RingError, RingProducer, command_ring};

use super::journal::{GroupJournal, JournalError};
use super::prefix::{self, Coverage, PrefixError, PrefixTracker, PrefixView};
use super::record::{Capture, GroupRecord, ReferenceUnavailable, Role};
use crate::disk::Disk;

#[cfg(test)]
mod tests;

/// The ring message type of a group's records.
const RECORDS: u32 = 1;
/// A ring record's header, in bytes.
const RING_HEADER: u64 = 8;
/// A reference unavailable record's length: the envelope and its block.
const UNAVAILABLE_LENGTH: usize = 12 + 16;

/// A capture path's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureConfig {
    /// The ring's capacity in bytes: a power of two, at least eight times
    /// the largest event's framed extent.
    pub ring_capacity: usize,
    /// The largest event, in bytes of records: the event byte budget.
    pub max_event: usize,
    /// The events written and not yet durable the tracker holds, at least 1.
    pub in_flight: usize,
}

/// A capture path that cannot be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    /// The ring's capacity is not a power of two of at least 1024 bytes,
    /// or a whole event does not fit an eighth of it.
    #[error("the ring cannot hold an event of {max_event} bytes")]
    Ring {
        /// The largest event.
        max_event: usize,
    },
    /// No event can be in flight.
    #[error("no event can be in flight")]
    InFlight,
}

/// Why an event was not taken: the Gateway's refusals, typed so it can
/// count them (A7d-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The ring has no room for a whole event.
    #[error("the ring is full")]
    RingFull,
    /// As many events are in flight as the tracker holds.
    #[error("the prefix tracker is full")]
    InFlight,
    /// The event's records are larger than the event budget.
    #[error("the event is larger than its budget")]
    TooLarge,
    /// The journal failed: the group records nothing more.
    #[error("the group failed")]
    Failed,
    /// The group ended: closed, or strict and at a reference that will
    /// never be covered.
    #[error("the group ended")]
    Ended,
}

/// Where a group stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupState {
    /// Recording.
    Running,
    /// The journal failed.
    Failed,
    /// Closed, or a strict group ended at a reference its recording will
    /// never cover.
    Ended,
}

const RUNNING: u8 = 0;
const FAILED: u8 = 1;
const ENDED: u8 = 2;

/// What both ends share.
#[derive(Debug)]
struct Shared {
    /// The ring position after the last message the job read.
    consumed: AtomicU64,
    state: AtomicU8,
    /// The prefixes stopped at an incomplete event or a gap: no event is
    /// queued any more, so none is in flight.
    stopped: std::sync::atomic::AtomicBool,
    view: Arc<PrefixView>,
    /// Held for no work: the job takes it before it notifies, so a waiter
    /// that checked under it is already waiting.
    lock: Mutex<()>,
    signal: Condvar,
}

impl Shared {
    fn state(&self) -> GroupState {
        match self.state.load(Ordering::Acquire) {
            RUNNING => GroupState::Running,
            FAILED => GroupState::Failed,
            _ => GroupState::Ended,
        }
    }

    fn set(&self, state: u8) {
        self.state.store(state, Ordering::Release);
        self.notify();
    }

    fn notify(&self) {
        drop(self.lock.lock().unwrap_or_else(PoisonError::into_inner));
        self.signal.notify_all();
    }
}

/// A ring record's extent: its header and payload, aligned to 8 bytes.
fn extent(payload: usize) -> u64 {
    u64::try_from(payload)
        .unwrap_or(u64::MAX)
        .saturating_add(RING_HEADER)
        .next_multiple_of(8)
}

/// Makes a group's capture path over `journal`, which holds at least its
/// header: the event loop's sender and the Archive thread's job. The
/// tracker is recomputed from the journal, every payload by `coverage`.
///
/// # Errors
///
/// [`CaptureError`] for settings that cannot work, and the journal's read
/// errors as [`CaptureSetup::Journal`].
pub fn capture<D: Disk>(
    config: CaptureConfig,
    mut journal: GroupJournal<D>,
    coverage: &impl Coverage,
) -> Result<(CaptureSender, CaptureJob<D>), CaptureSetup> {
    let ring = u64::try_from(config.ring_capacity).unwrap_or(u64::MAX);
    let max_extent = extent(config.max_event);
    if !config.ring_capacity.is_power_of_two() || max_extent > ring / 8 {
        return Err(CaptureSetup::Config(CaptureError::Ring {
            max_event: config.max_event,
        }));
    }
    if config.in_flight == 0 {
        return Err(CaptureSetup::Config(CaptureError::InFlight));
    }
    let (producer, consumer) = command_ring(config.ring_capacity).map_err(|_| {
        CaptureSetup::Config(CaptureError::Ring {
            max_event: config.max_event,
        })
    })?;
    let recovery =
        prefix::recover(&mut journal, coverage, config.in_flight).map_err(CaptureSetup::Journal)?;
    let tracker = recovery.tracker;
    let shared = Arc::new(Shared {
        consumed: AtomicU64::new(0),
        state: AtomicU8::new(RUNNING),
        stopped: std::sync::atomic::AtomicBool::new(tracker.stopped()),
        view: tracker.view(),
        lock: Mutex::new(()),
        signal: Condvar::new(),
    });
    let capture = journal_capture(&mut journal).map_err(CaptureSetup::Journal)?;
    let dispatched = recovery.last_seen.max(tracker.durable_group_seq());
    let sender = CaptureSender {
        producer,
        shared: Arc::clone(&shared),
        capacity: ring,
        max_event: config.max_event,
        max_extent,
        tail: 0,
        dispatched,
        in_flight: u64::try_from(config.in_flight).unwrap_or(u64::MAX),
    };
    let job = CaptureJob {
        consumer,
        journal,
        tracker,
        shared,
        capture,
        uncovered: Vec::with_capacity(config.in_flight),
        signalled: 0,
    };
    Ok((sender, job))
}

/// Why [`capture`] could not make a group's capture path.
#[derive(Debug, thiserror::Error)]
pub enum CaptureSetup {
    /// Settings that cannot work.
    #[error(transparent)]
    Config(CaptureError),
    /// The journal could not be read.
    #[error(transparent)]
    Journal(JournalError),
}

/// The journal's capture mode, from its header.
fn journal_capture<D: Disk>(journal: &mut GroupJournal<D>) -> Result<Capture, JournalError> {
    let mut capture = Capture::Strict;
    journal.walk(0, |_, _, record| {
        if let Role::Header { capture: mode, .. } = record.role() {
            capture = mode;
        }
        false
    })?;
    Ok(capture)
}

/// The event loop's end: it admits events and sends their records.
#[derive(Debug)]
pub struct CaptureSender {
    producer: RingProducer,
    shared: Arc<Shared>,
    capacity: u64,
    max_event: usize,
    max_extent: u64,
    /// The ring position after the last message written.
    tail: u64,
    /// The last `group_seq` sent.
    dispatched: u64,
    in_flight: u64,
}

impl CaptureSender {
    /// Whether a whole event can be taken now: the group runs, the ring
    /// has room for the largest event with the padding a wrap would need,
    /// and fewer events are in flight than the tracker holds (until the
    /// prefixes stop, after which none is). Wait-free.
    ///
    /// # Errors
    ///
    /// The [`Refusal`] that keeps the event out.
    pub fn admit(&self) -> Result<(), Refusal> {
        self.room()?;
        if !self.shared.stopped.load(Ordering::Acquire) {
            let durable = self.shared.view.durable_group_seq();
            if self.dispatched.saturating_sub(durable) >= self.in_flight {
                return Err(Refusal::InFlight);
            }
        }
        Ok(())
    }

    /// Whether a gap marker can be sent now: the group runs and the ring
    /// has room for the largest event, with a wrap's padding. A gap is not
    /// in flight: it stops the prefixes. Wait-free.
    ///
    /// # Errors
    ///
    /// [`Refusal::RingFull`] and the state refusals.
    pub fn room(&self) -> Result<(), Refusal> {
        match self.shared.state() {
            GroupState::Running => {}
            GroupState::Failed => return Err(Refusal::Failed),
            GroupState::Ended => return Err(Refusal::Ended),
        }
        let consumed = self.shared.consumed.load(Ordering::Acquire);
        let used = self.tail.saturating_sub(consumed);
        let free = self.capacity.saturating_sub(used);
        let to_end = self.capacity - (self.tail & (self.capacity - 1));
        let padding = if self.max_extent > to_end { to_end } else { 0 };
        if padding + self.max_extent > free {
            return Err(Refusal::RingFull);
        }
        Ok(())
    }

    /// Sends one event's records, or one gap marker, back to back, as one
    /// message; `last_seq` is the event's `group_seq`, or the gap's last.
    /// Call it only after [`CaptureSender::admit`] took the event.
    ///
    /// # Errors
    ///
    /// [`Refusal::TooLarge`] for records above the event budget, and the
    /// state refusals; [`Refusal::RingFull`] only for an event not
    /// admitted.
    pub fn send(&mut self, records: &[u8], last_seq: u64) -> Result<(), Refusal> {
        if records.len() > self.max_event {
            return Err(Refusal::TooLarge);
        }
        match self.producer.write(RECORDS, records) {
            Ok(start) => {
                self.tail = start.saturating_add(extent(records.len()));
                self.dispatched = self.dispatched.max(last_seq);
                Ok(())
            }
            Err(RingError::Full) => Err(Refusal::RingFull),
            Err(_) => {
                self.shared.set(FAILED);
                Err(Refusal::Failed)
            }
        }
    }

    /// The group's prefixes, each a wait-free load.
    #[must_use]
    pub fn view(&self) -> &PrefixView {
        &self.shared.view
    }

    /// Where the group stands.
    #[must_use]
    pub fn state(&self) -> GroupState {
        self.shared.state()
    }

    /// A waiter for durability, for threads other than the event loop's.
    #[must_use]
    pub fn waiter(&self) -> GroupWaiter {
        GroupWaiter {
            shared: Arc::clone(&self.shared),
        }
    }
}

/// Why a wait ended without its `group_seq` durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WaitError {
    /// The deadline passed; `durable` is how far the group got.
    #[error("not durable by the deadline (durable to {durable})")]
    Timeout {
        /// `durable_group_seq` then.
        durable: u64,
    },
    /// The group failed or ended first; `durable` is how far it got.
    #[error("the group stopped at {durable}")]
    Stopped {
        /// `durable_group_seq` then.
        durable: u64,
        /// Failed or ended.
        state: GroupState,
    },
}

/// Waits for a group's events to be durable. Never on the event loop: a
/// wait there would stall the loop the wait is for.
#[derive(Debug, Clone)]
pub struct GroupWaiter {
    shared: Arc<Shared>,
}

impl GroupWaiter {
    /// Waits until `durable_group_seq` reaches `seq`, the group fails or
    /// ends, or `timeout` passes; returns `durable_group_seq`.
    ///
    /// # Errors
    ///
    /// [`WaitError`] when it did not reach `seq`.
    pub fn wait_durable(&self, seq: u64, timeout: Duration) -> Result<u64, WaitError> {
        let deadline = Instant::now().checked_add(timeout);
        let mut guard = self
            .shared
            .lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        loop {
            let durable = self.shared.view.durable_group_seq();
            if durable >= seq {
                return Ok(durable);
            }
            let state = self.shared.state();
            if state != GroupState::Running {
                return Err(WaitError::Stopped { durable, state });
            }
            let left = deadline.map_or(Duration::MAX, |deadline| {
                deadline.saturating_duration_since(Instant::now())
            });
            if left.is_zero() {
                return Err(WaitError::Timeout { durable });
            }
            guard = self
                .shared
                .signal
                .wait_timeout(guard, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// The Archive thread's end: it drains the ring into the journal and keeps
/// the prefixes.
#[derive(Debug)]
pub struct CaptureJob<D: Disk> {
    consumer: RingConsumer,
    journal: GroupJournal<D>,
    tracker: PrefixTracker,
    shared: Arc<Shared>,
    capture: Capture,
    /// Events a recording that ended does not cover, sized to the tracker.
    uncovered: Vec<u64>,
    /// The `durable_group_seq` waiters were last notified of.
    signalled: u64,
}

/// Why the job stopped recording.
#[derive(Debug, thiserror::Error)]
pub enum JobError {
    /// The journal refused or failed a write.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The ring held what a well-behaved sender never writes.
    #[error("the ring is malformed")]
    Ring,
    /// A message's records did not decode once the journal took them.
    #[error(transparent)]
    Record(#[from] CodecError),
    /// The tracker refused a record the journal took.
    #[error(transparent)]
    Prefix(#[from] PrefixError),
}

impl<D: Disk> CaptureJob<D> {
    /// Reads up to `budget` messages into the journal, runs its sync
    /// policy at `now`, and advances the prefixes over the journal's
    /// positions and `coverage`; returns whether it read any. Does
    /// nothing once the group failed or ended.
    ///
    /// # Errors
    ///
    /// [`JobError`]: the group is then failed, and records nothing more.
    pub fn duty(
        &mut self,
        now: u64,
        budget: usize,
        coverage: &impl Coverage,
    ) -> Result<bool, JobError> {
        if self.shared.state() != GroupState::Running {
            return Ok(false);
        }
        let result = self.drain(now, budget, coverage);
        if result.is_err() {
            self.shared.set(FAILED);
        }
        result
    }

    fn drain(
        &mut self,
        now: u64,
        budget: usize,
        coverage: &impl Coverage,
    ) -> Result<bool, JobError> {
        let mut read = false;
        for _ in 0..budget {
            let Some(message) = self.consumer.read().map_err(|_| JobError::Ring)? else {
                break;
            };
            read = true;
            let end = message
                .position
                .saturating_add(extent(message.payload.len()));
            self.journal.append(message.payload)?;
            let written = self.journal.written();
            let mut records = message.payload;
            while !records.is_empty() {
                let length = usize::try_from(Envelope::read(records)?.message_length)
                    .map_err(|_| JobError::Ring)?;
                let (record, rest) = records.split_at_checked(length).ok_or(JobError::Ring)?;
                let record = GroupRecord::decode(record)?;
                // Only an end's and a header's positions count, and a
                // message ends at the event's end.
                self.tracker.record(&record, written)?;
                if let Role::Event(seq) | Role::Uncaptured(seq) = record.role() {
                    self.tracker.delivered(seq);
                }
                records = rest;
            }
            self.shared.consumed.store(end, Ordering::Release);
        }
        let _ = self.journal.tick(now)?;
        self.advance(coverage);
        Ok(read)
    }

    /// Advances the prefixes, and notifies waiters when the durable one
    /// moved.
    fn advance(&mut self, coverage: &impl Coverage) {
        let (_, durable) =
            self.tracker
                .advance(self.journal.written(), self.journal.durable(), coverage);
        if self.tracker.stopped() {
            self.shared.stopped.store(true, Ordering::Release);
        }
        if durable > self.signalled {
            self.signalled = durable;
            self.shared.notify();
        }
    }

    /// Syncs the journal and advances the prefixes over `coverage`.
    ///
    /// # Errors
    ///
    /// [`JobError::Journal`]: the group is then failed.
    pub fn sync(&mut self, coverage: &impl Coverage) -> Result<(), JobError> {
        if self.shared.state() == GroupState::Failed {
            return Ok(());
        }
        if let Err(error) = self.journal.sync() {
            self.shared.set(FAILED);
            return Err(error.into());
        }
        self.advance(coverage);
        Ok(())
    }

    /// Recording `recording_id` stopped or failed with its frames durable
    /// to `durable`: every reference it covers counts covered; a reference
    /// it does not cover is marked unavailable in a best-effort group, and
    /// ends a strict one. Call it between duties, so the journal is between
    /// events.
    ///
    /// # Errors
    ///
    /// [`JobError`] when a mark cannot be written: the group is then
    /// failed.
    pub fn recording_ended(
        &mut self,
        recording_id: u64,
        durable: u64,
        coverage: &impl Coverage,
    ) -> Result<(), JobError> {
        if self.shared.state() != GroupState::Running {
            return Ok(());
        }
        let uncovered = &mut self.uncovered;
        uncovered.clear();
        self.tracker
            .recording_ended(recording_id, durable, |seq| uncovered.push(seq));
        if !self.uncovered.is_empty() && self.capture == Capture::Strict {
            self.shared.set(ENDED);
            return Ok(());
        }
        let result = self.mark(recording_id);
        if result.is_err() {
            self.shared.set(FAILED);
        }
        self.advance(coverage);
        result
    }

    /// Appends a reference unavailable mark for each uncovered event.
    fn mark(&mut self, recording_id: u64) -> Result<(), JobError> {
        let mut out = [0u8; UNAVAILABLE_LENGTH];
        for index in 0..self.uncovered.len() {
            let Some(&group_seq) = self.uncovered.get(index) else {
                break;
            };
            let record = GroupRecord::Unavailable(ReferenceUnavailable {
                group_seq,
                recording_id,
            });
            let length = record.encode(&mut out)?;
            let bytes = out.get(..length).ok_or(JobError::Ring)?;
            self.journal.append(bytes)?;
            self.tracker.record(&record, self.journal.written())?;
        }
        Ok(())
    }

    /// The group's tracker, for its three values and its state.
    #[must_use]
    pub const fn tracker(&self) -> &PrefixTracker {
        &self.tracker
    }

    /// Where the group stands.
    #[must_use]
    pub fn state(&self) -> GroupState {
        self.shared.state()
    }

    /// The journal, for its positions.
    #[must_use]
    pub const fn journal(&self) -> &GroupJournal<D> {
        &self.journal
    }

    /// Closes the journal (syncing it); the group records nothing more.
    /// Returns the journal's durable position.
    ///
    /// # Errors
    ///
    /// The journal's close errors.
    pub fn close(self) -> Result<u64, JournalError> {
        self.shared.set(ENDED);
        self.journal.close()
    }
}
