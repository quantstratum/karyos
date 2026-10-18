// SPDX-License-Identifier: Apache-2.0

//! A recording group's checkpoints: the store, the writer and the record
//! (`quantstratum-docs: karyos/design/recording-group-checkpoints.md`
//! sections 2 to 4; A9-1).
//!
//! - **The store.** Each group has a [`CheckpointStore`]: a segment store
//!   (A2) named by the group, in a checkpoint directory beside the
//!   group's journal, with the journal's sync policy for its segments.
//!   Each checkpoint is one contiguous range of it, checked by the store's
//!   CRC-32C on every write; its `position` is where the range starts. A
//!   checkpoint's bytes are synced before its record is appended, so a
//!   recorded checkpoint is durable by construction (one sync per
//!   checkpoint, which is rare). Retention follows
//!   the journal's: a checkpoint is kept while its record is (the journal
//!   deletes nothing yet, so neither does the store).
//! - **The writer.** [`CheckpointWriter::write`] runs on the Archive's
//!   thread, between the group's events. It checks the record against the
//!   journal's order rules first, so a refusal writes nothing; then it
//!   appends the bytes to the store and syncs them, and only then appends
//!   template 30 to the journal. A record never names bytes that are not
//!   durable, and a failed write leaves no record. After an I/O error the
//!   store fails until it is recovered, as every segment store does: a
//!   retry then fails too ([`SegmentError::Failed`]), and the retry that
//!   may name the same `group_seq` is one after recovery, or after a
//!   refusal.
//! - **The handoff.** The Gateway owns one buffer of `max_checkpoint`
//!   bytes ([`CheckpointSlot`]), allocated at configuration. A checkpoint
//!   fills it and hands it, by ownership, to the writer, which gives it
//!   back once the write ended. While it is away another checkpoint is
//!   refused, as is a snapshot longer than the buffer and one after a
//!   strict journal's end; each refusal is typed and counted, and nothing
//!   is recorded for it. `Gateway::checkpoint` builds on it once the
//!   Gateway lands (A7d-2).
//! - **Recovery.** A crash can leave bytes no record names (the write
//!   ended, the record was never appended): [`CheckpointStore::recover`]
//!   cuts them back to the last record's end. Since the bytes are synced
//!   before the record, a kept record names durable bytes; should the
//!   store still hold less (its files damaged), the range is marked lost,
//!   so the next checkpoint never reuses a range a record names and a lost
//!   one never reads as written, and never opens its range.
//!
//! Nothing allocates per checkpoint after configuration.

use std::path::Path;

use super::journal::{GroupJournal, JournalConfig, JournalError};
use super::order::OrderError;
use super::prefix::CheckpointHeld;
use super::record::{CHECKPOINT, CheckpointRecord, GroupRecord};
use crate::crc32c::crc32c;
use crate::disk::Disk;
use crate::segment::{Geometry, SegmentError, SegmentStore};

#[cfg(test)]
mod tests;

/// The name of a group journal directory's subdirectory that holds the
/// groups' checkpoint stores: a store is named by its group, as its
/// journal is, so it cannot share the journals' directory.
pub const CHECKPOINT_DIR: &str = "checkpoints";

/// Where the checkpoint stores of the groups whose journals are in
/// `journal_dir` live: `<journal_dir>/checkpoints`, found so by the
/// Archive, by replay and by `replay diff --from-checkpoint`.
#[must_use]
pub fn store_dir(journal_dir: &Path) -> std::path::PathBuf {
    journal_dir.join(CHECKPOINT_DIR)
}

/// The encoded length of a checkpoint record.
const RECORD_LENGTH: usize = 12 + 40;
/// The same, as the template declares it.
const RECORD_LENGTH_U32: u32 = 12 + 40;

const _: () = assert!(CHECKPOINT.max_length == RECORD_LENGTH_U32);

/// Why a checkpoint was not taken or not written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckpointError {
    /// Another checkpoint is with the writer.
    #[error("a checkpoint is in flight")]
    InFlight,
    /// The snapshot is longer than the buffer.
    #[error("a snapshot of {length} bytes, above {max}")]
    TooLarge {
        /// What `write` reported.
        length: usize,
        /// `max_checkpoint`.
        max: usize,
    },
    /// The snapshot is empty.
    #[error("an empty snapshot")]
    Empty,
    /// A strict journal ended at an incomplete event: nothing can open
    /// another range.
    #[error("the journal ended")]
    Ended,
    /// The record breaks the journal's order rules: nothing is written.
    #[error(transparent)]
    Order(#[from] OrderError),
    /// The store failed: the bytes may be partly written, and no record
    /// names them. The store then fails until recovered.
    #[error(transparent)]
    Store(#[from] SegmentError),
    /// The group stopped, failed or ended: the checkpoint is not written,
    /// and its buffer comes back.
    #[error("the group stopped")]
    Stopped,
    /// The group was started without checkpoints
    /// (`StartGroup::checkpoints` was `None`).
    #[error("the group keeps no checkpoints")]
    NoCheckpoints,
    /// No event has been dispatched yet, in this run or the journal's:
    /// there is no state after an event to name.
    #[error("no event was dispatched yet")]
    NothingDispatched,
    /// No checkpoint is being written, or `advance` was given another
    /// request than `begin`.
    #[error("no checkpoint is being written for this request")]
    NotStarted,
    /// The store's sync left the bytes short of durable (`durable`, below
    /// their `end`): no record is appended. Under `SyncPolicy::None`,
    /// which capture refuses for a journal, a checkpoint crossing a
    /// segment ends so.
    #[error("the checkpoint's bytes are durable to {durable}, not {end}")]
    NotDurable {
        /// The store's durable position after the sync.
        durable: u64,
        /// The checkpoint's end.
        end: u64,
    },
    /// The journal failed to take the record after the bytes were
    /// written: they stay unnamed until recovery cuts them.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// A group's checkpoint store.
#[derive(Debug)]
pub struct CheckpointStore<D: Disk> {
    store: SegmentStore<D>,
}

impl<D: Disk> CheckpointStore<D> {
    /// Creates group `group_id`'s store in `dir`, the checkpoint directory
    /// beside its journal, with the journal's `config`.
    ///
    /// # Errors
    ///
    /// [`SegmentError::InvalidGeometry`] for a segment length the journal
    /// would refuse, and the store's errors.
    pub fn create(
        disk: D,
        dir: &Path,
        group_id: u64,
        config: JournalConfig,
    ) -> Result<Self, SegmentError> {
        let store = SegmentStore::create(disk, dir, group_id, geometry(config)?, config.policy, 0)?;
        Ok(Self { store })
    }

    /// Recovers group `group_id`'s store in `dir` after a crash or a
    /// close, consistent with its journal, whose last checkpoint record
    /// ends at `recorded_end` ([`recorded_end`]): bytes past it, which no
    /// record names, are cut; a range up to it the store lost is marked
    /// lost, so it never reads as written and is never reused.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn recover(
        disk: D,
        dir: &Path,
        group_id: u64,
        config: JournalConfig,
        recorded_end: u64,
    ) -> Result<Self, SegmentError> {
        let recovered =
            SegmentStore::recover(disk, dir, group_id, geometry(config)?, config.policy)?;
        let mut store = recovered.store;
        let written = store.written();
        if written > recorded_end {
            let _ = store.truncate(recorded_end)?;
        } else if written < recorded_end {
            let _ = store.append_gap(written, recorded_end)?;
            let _ = store.sync()?;
        }
        Ok(Self { store })
    }

    /// What it holds of `[position, end)`, the prefix tracker's
    /// [`super::prefix::Coverage::checkpoint`]: lost when recovery marked
    /// it so, or below the store's start; missing past its written
    /// position; else written, or durable.
    #[must_use]
    pub fn holds(&self, position: u64, end: u64) -> CheckpointHeld {
        let lost = self
            .store
            .gaps()
            .iter()
            .any(|(from, to)| *from < end && position < *to);
        if lost || position < self.store.start() {
            CheckpointHeld::Lost
        } else if end > self.store.written() {
            CheckpointHeld::Missing
        } else if end <= self.store.durable() {
            CheckpointHeld::Durable
        } else {
            CheckpointHeld::Written
        }
    }

    /// Marks `[written, end)` lost, for a store recreated after it went
    /// missing while its journal's records name ranges up to `end`: they
    /// read as lost, never open their ranges, and are never reused.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn mark_lost(&mut self, end: u64) -> Result<(), SegmentError> {
        let written = self.store.written();
        if end > written {
            let _ = self.store.append_gap(written, end)?;
            let _ = self.store.sync()?;
        }
        Ok(())
    }

    /// Reads `buf.len()` bytes at `position`.
    ///
    /// # Errors
    ///
    /// The store's errors, [`SegmentError::Gap`] for a lost range.
    pub fn read(&mut self, position: u64, buf: &mut [u8]) -> Result<(), SegmentError> {
        self.store.read(position, buf)
    }

    /// The end of the last write.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.store.written()
    }

    /// The end of what a sync made durable.
    #[must_use]
    pub const fn durable(&self) -> u64 {
        self.store.durable()
    }

    /// Makes everything written durable; returns the durable position.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn sync(&mut self) -> Result<u64, SegmentError> {
        self.store.sync()
    }

    /// The interval policy's clock, as the journal's.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn tick(&mut self, now_ns: u64) -> Result<u64, SegmentError> {
        self.store.tick(now_ns)
    }

    /// Closes the store with everything written durable.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn close(self) -> Result<u64, SegmentError> {
        self.store.close_synced()
    }
}

fn geometry(config: JournalConfig) -> Result<Geometry, SegmentError> {
    if config.segment_length < super::journal::MIN_SEGMENT_LENGTH {
        return Err(SegmentError::InvalidGeometry);
    }
    Geometry::new(config.segment_length, u64::from(config.segment_length))
}

/// The end in the checkpoint store of the last checkpoint `journal`
/// records, 0 with none: what [`CheckpointStore::recover`] keeps.
///
/// # Errors
///
/// The journal's read errors.
pub fn recorded_end<D: Disk>(journal: &mut GroupJournal<D>) -> Result<u64, JournalError> {
    let mut end = 0u64;
    let _ = journal.walk(0, |_, _, record| {
        if let GroupRecord::Checkpoint(checkpoint) = record
            && let Some(checkpoint_end) = checkpoint.end()
        {
            end = end.max(checkpoint_end);
        }
        true
    })?;
    Ok(end)
}

/// A snapshot handed to the writer: the Gateway's buffer, by ownership.
#[derive(Debug)]
pub struct CheckpointRequest {
    buffer: Box<[u8]>,
    length: usize,
    /// The last event the state includes.
    pub group_seq: u64,
    /// The application's tag for its snapshot format.
    pub format: u32,
}

impl CheckpointRequest {
    /// The snapshot's bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.buffer.get(..self.length).unwrap_or_default()
    }
}

/// What the Gateway counts of its checkpoints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckpointStats {
    /// Handed to the writer.
    pub taken: u64,
    /// Recorded.
    pub recorded: u64,
    /// Refused: one in flight.
    pub in_flight: u64,
    /// Refused: above `max_checkpoint`, or empty.
    pub too_large: u64,
    /// Refused: the strict journal ended.
    pub ended: u64,
    /// Written and failed: no record.
    pub failed: u64,
    /// A count reached `u64::MAX` and holds there.
    pub overflowed: bool,
}

impl CheckpointStats {
    /// Adds one to `count`, which holds at `u64::MAX` and sets
    /// `overflowed` there.
    fn bump(count: &mut u64, overflowed: &mut bool) {
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => *overflowed = true,
        }
    }
}

/// How the last checkpoint the writer took ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastCheckpoint {
    /// Recorded.
    Recorded(CheckpointRecord),
    /// Failed, with no record, for the `group_seq` it named.
    Failed {
        /// The last event its state included.
        group_seq: u64,
    },
}

/// The Gateway's side of the one-slot handoff: one buffer of
/// `max_checkpoint` bytes, with the writer or here.
#[derive(Debug)]
pub struct CheckpointSlot {
    buffer: Option<Box<[u8]>>,
    max: usize,
    ended: bool,
    stats: CheckpointStats,
    last: Option<LastCheckpoint>,
}

impl CheckpointSlot {
    /// A slot whose buffer holds `max_checkpoint` bytes, at least 1;
    /// allocated here only.
    #[must_use]
    pub fn new(max_checkpoint: usize) -> Self {
        let max = max_checkpoint.max(1);
        Self {
            buffer: Some(vec![0u8; max].into_boxed_slice()),
            max,
            ended: false,
            stats: CheckpointStats::default(),
            last: None,
        }
    }

    /// Takes a checkpoint of the state after event `group_seq`: `write`
    /// fills the buffer and returns the snapshot's length. The request
    /// goes to the writer; the buffer comes back with
    /// [`CheckpointSlot::returned`].
    ///
    /// # Errors
    ///
    /// [`CheckpointError::InFlight`], [`CheckpointError::Ended`],
    /// [`CheckpointError::TooLarge`] and [`CheckpointError::Empty`], each
    /// counted, with the buffer kept.
    pub fn take(
        &mut self,
        group_seq: u64,
        format: u32,
        write: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<CheckpointRequest, CheckpointError> {
        if self.ended {
            CheckpointStats::bump(&mut self.stats.ended, &mut self.stats.overflowed);
            return Err(CheckpointError::Ended);
        }
        let Some(mut buffer) = self.buffer.take() else {
            CheckpointStats::bump(&mut self.stats.in_flight, &mut self.stats.overflowed);
            return Err(CheckpointError::InFlight);
        };
        let length = write(&mut buffer);
        if length == 0 || length > self.max {
            self.buffer = Some(buffer);
            CheckpointStats::bump(&mut self.stats.too_large, &mut self.stats.overflowed);
            return Err(if length == 0 {
                CheckpointError::Empty
            } else {
                CheckpointError::TooLarge {
                    length,
                    max: self.max,
                }
            });
        }
        CheckpointStats::bump(&mut self.stats.taken, &mut self.stats.overflowed);
        Ok(CheckpointRequest {
            buffer,
            length,
            group_seq,
            format,
        })
    }

    /// The writer gave `request`'s buffer back, with how the write ended.
    pub fn returned(
        &mut self,
        request: CheckpointRequest,
        result: &Result<CheckpointRecord, CheckpointError>,
    ) {
        self.last = Some(match result {
            Ok(record) => {
                CheckpointStats::bump(&mut self.stats.recorded, &mut self.stats.overflowed);
                LastCheckpoint::Recorded(*record)
            }
            Err(_) => {
                CheckpointStats::bump(&mut self.stats.failed, &mut self.stats.overflowed);
                LastCheckpoint::Failed {
                    group_seq: request.group_seq,
                }
            }
        });
        self.buffer = Some(request.buffer);
    }

    /// A strict journal ended at an incomplete event: every later
    /// checkpoint is refused.
    pub fn end(&mut self) {
        self.ended = true;
    }

    /// How the last checkpoint the writer took ended.
    #[must_use]
    pub const fn last_checkpoint(&self) -> Option<LastCheckpoint> {
        self.last
    }

    /// Its counts.
    #[must_use]
    pub const fn stats(&self) -> CheckpointStats {
        self.stats
    }
}

/// The checkpoint writer on the Archive's thread.
#[derive(Debug)]
pub struct CheckpointWriter<D: Disk> {
    store: CheckpointStore<D>,
    next_id: u64,
    record: [u8; RECORD_LENGTH],
    /// The checkpoint being written in chunks: its record, and how many of
    /// its bytes are in the store.
    writing: Option<(CheckpointRecord, usize)>,
}

/// How far [`CheckpointWriter::advance`] got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// Its bytes are written up to `written`; the record waits for the
    /// rest.
    Writing {
        /// The bytes in the store so far.
        written: usize,
    },
    /// Written, synced, and recorded.
    Recorded(CheckpointRecord),
}

impl<D: Disk> CheckpointWriter<D> {
    /// The writer of `journal`'s group into `store`: its ids follow the
    /// last one the journal records.
    ///
    /// # Errors
    ///
    /// [`CheckpointError::Order`] when the journal's ids are exhausted.
    pub fn new(
        store: CheckpointStore<D>,
        journal: &GroupJournal<D>,
    ) -> Result<Self, CheckpointError> {
        let last = journal.order().last_checkpoint().map_or(0, |(_, id)| id);
        let next_id = last.checked_add(1).ok_or(OrderError {
            ordinal: journal.order().records(),
            rule: super::order::OrderRule::Exhausted,
        })?;
        Ok(Self {
            store,
            next_id,
            record: [0; RECORD_LENGTH],
            writing: None,
        })
    }

    /// Starts writing `request` in chunks ([`CheckpointWriter::advance`]):
    /// its record is fixed and checked against `journal`'s order rules, so
    /// a refusal writes nothing. A checkpoint already being written is let
    /// go: its bytes stay unnamed.
    ///
    /// # Errors
    ///
    /// As [`CheckpointWriter::write`] before anything is written.
    pub fn begin(
        &mut self,
        journal: &GroupJournal<D>,
        request: &CheckpointRequest,
    ) -> Result<(), CheckpointError> {
        self.writing = None;
        let bytes = request.bytes();
        let length = u64::try_from(bytes.len()).map_err(|_| SegmentError::PositionOverflow)?;
        let record = CheckpointRecord {
            group_seq: request.group_seq,
            checkpoint_id: self.next_id,
            position: self.store.written(),
            length,
            crc32c: crc32c(bytes),
            format: request.format,
        };
        let mut check = *journal.order();
        check.push(GroupRecord::Checkpoint(record).role())?;
        let _ = self.next_id.checked_add(1).ok_or(OrderError {
            ordinal: journal.order().records(),
            rule: super::order::OrderRule::Exhausted,
        })?;
        self.writing = Some((record, 0));
        Ok(())
    }

    /// Writes at most `budget` more bytes of the checkpoint
    /// [`CheckpointWriter::begin`] started, `request` the same; once they
    /// are all written, syncs them and appends its record to `journal`.
    /// A crash before then leaves no record, and recovery cuts the bytes.
    ///
    /// # Errors
    ///
    /// [`CheckpointError::NotStarted`] with none begun, or for another
    /// request; then as [`CheckpointWriter::write`]. On an error the
    /// checkpoint is let go.
    pub fn advance(
        &mut self,
        journal: &mut GroupJournal<D>,
        request: &CheckpointRequest,
        budget: usize,
    ) -> Result<Progress, CheckpointError> {
        let result = self.advance_inner(journal, request, budget);
        if !matches!(result, Ok(Progress::Writing { .. })) {
            self.writing = None;
        }
        result
    }

    fn advance_inner(
        &mut self,
        journal: &mut GroupJournal<D>,
        request: &CheckpointRequest,
        budget: usize,
    ) -> Result<Progress, CheckpointError> {
        let (record, written) = self.writing.ok_or(CheckpointError::NotStarted)?;
        let bytes = request.bytes();
        if record.group_seq != request.group_seq
            || u64::try_from(bytes.len()).ok() != Some(record.length)
        {
            return Err(CheckpointError::NotStarted);
        }
        let take = budget.min(
            bytes
                .len()
                .checked_sub(written)
                .ok_or(CheckpointError::NotStarted)?,
        );
        let to = written
            .checked_add(take)
            .ok_or(CheckpointError::NotStarted)?;
        let chunk = bytes.get(written..to).ok_or(CheckpointError::NotStarted)?;
        let at = record
            .position
            .checked_add(u64::try_from(written).map_err(|_| SegmentError::PositionOverflow)?)
            .ok_or(SegmentError::PositionOverflow)?;
        if !chunk.is_empty() {
            let _ = self.store.store.append(at, chunk)?;
        }
        if to < bytes.len() {
            self.writing = Some((record, to));
            return Ok(Progress::Writing { written: to });
        }
        // Checked again: the journal moved on while the bytes were written.
        let mut check = *journal.order();
        check.push(GroupRecord::Checkpoint(record).role())?;
        let encoded = record
            .encode(&mut self.record)
            .map_err(JournalError::Record)?;
        let next_id = self.next_id.checked_add(1).ok_or(OrderError {
            ordinal: journal.order().records(),
            rule: super::order::OrderRule::Exhausted,
        })?;
        let end = record.end().ok_or(SegmentError::PositionOverflow)?;
        // Durable before its record: a kept record never names lost bytes.
        let durable = self.store.store.sync()?;
        if durable < end {
            return Err(CheckpointError::NotDurable { durable, end });
        }
        let _ = journal.append(self.record.get(..encoded).unwrap_or_default())?;
        self.next_id = next_id;
        Ok(Progress::Recorded(record))
    }

    /// Whether a checkpoint is being written.
    #[must_use]
    pub const fn writing(&self) -> bool {
        self.writing.is_some()
    }

    /// Writes `request`'s bytes to the store, then its record to
    /// `journal`; returns the record.
    ///
    /// # Errors
    ///
    /// [`CheckpointError::Order`] for a record the journal would refuse
    /// (inside an event, naming an event not ended, or not above the last
    /// recorded checkpoint) or exhausted ids, with nothing written; the
    /// store's errors, with no record; the journal's, after the bytes were
    /// written and synced.
    pub fn write(
        &mut self,
        journal: &mut GroupJournal<D>,
        request: &CheckpointRequest,
    ) -> Result<CheckpointRecord, CheckpointError> {
        self.begin(journal, request)?;
        match self.advance(journal, request, usize::MAX)? {
            Progress::Recorded(record) => Ok(record),
            // Never with an unbounded budget.
            Progress::Writing { .. } => Err(CheckpointError::NotStarted),
        }
    }

    /// The store.
    #[must_use]
    pub const fn store(&self) -> &CheckpointStore<D> {
        &self.store
    }

    /// The store, to sync or read.
    pub fn store_mut(&mut self) -> &mut CheckpointStore<D> {
        &mut self.store
    }

    /// Closes the store with everything written durable.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn close(self) -> Result<u64, SegmentError> {
        self.store.close()
    }
}

/// What one handoff holds: the request the writer has to take, and the
/// one it gave back, with how its write ended.
#[derive(Debug, Default)]
struct Handoff {
    request: Option<CheckpointRequest>,
    returned: Option<(CheckpointRequest, Result<CheckpointRecord, CheckpointError>)>,
    /// The group stopped, failed or ended: nothing more is written.
    closed: bool,
}

/// The one-slot handoff between the Gateway's thread and the Archive's,
/// shared by a [`CheckpointHandle`] and a [`CheckpointInbox`]. Each side
/// locks it only to move the buffer, by ownership: nothing is copied or
/// allocated per checkpoint.
type Shared = std::sync::Arc<std::sync::Mutex<Handoff>>;

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, Handoff> {
    shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The Gateway's end of a group's checkpoints (A9-3): its
/// [`CheckpointSlot`], and the handoff to the Archive's writer.
#[derive(Debug)]
pub struct CheckpointHandle {
    slot: CheckpointSlot,
    shared: Shared,
}

/// The Archive's end: it takes the requests and gives the buffers back.
#[derive(Debug)]
pub struct CheckpointInbox {
    shared: Shared,
}

/// A handoff of `max_checkpoint` bytes: both ends, allocated here only.
#[must_use]
pub fn handoff(max_checkpoint: usize) -> (CheckpointHandle, CheckpointInbox) {
    let shared = Shared::default();
    // A platform mutex may allocate at its first lock: done here, so no
    // checkpoint does.
    drop(lock(&shared));
    (
        CheckpointHandle {
            slot: CheckpointSlot::new(max_checkpoint),
            shared: std::sync::Arc::clone(&shared),
        },
        CheckpointInbox { shared },
    )
}

impl CheckpointHandle {
    /// Takes a checkpoint of the state after event `group_seq`, as
    /// [`CheckpointSlot::take`] does, and hands it to the Archive's writer.
    ///
    /// # Errors
    ///
    /// [`CheckpointSlot::take`]'s, each counted.
    pub fn checkpoint(
        &mut self,
        group_seq: u64,
        format: u32,
        write: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<(), CheckpointError> {
        self.poll();
        let request = self.slot.take(group_seq, format, write)?;
        let mut shared = lock(&self.shared);
        if shared.closed {
            drop(shared);
            // The buffer stays here, the refusal counted as a failure.
            self.slot.returned(request, &Err(CheckpointError::Stopped));
            return Err(CheckpointError::Stopped);
        }
        shared.request = Some(request);
        Ok(())
    }

    /// Takes back the buffer of a write that ended, if one did: its result
    /// is then [`CheckpointHandle::last_checkpoint`]'s.
    pub fn poll(&mut self) {
        let returned = lock(&self.shared).returned.take();
        if let Some((request, result)) = returned {
            self.slot.returned(request, &result);
        }
    }

    /// A strict journal ended: every later checkpoint is refused.
    pub fn end(&mut self) {
        self.slot.end();
    }

    /// Whether a checkpoint handed over still waits for the writer to
    /// take it.
    #[must_use]
    pub fn pending(&self) -> bool {
        lock(&self.shared).request.is_some()
    }

    /// How the last checkpoint the writer took ended.
    #[must_use]
    pub const fn last_checkpoint(&self) -> Option<LastCheckpoint> {
        self.slot.last_checkpoint()
    }

    /// Its counts.
    #[must_use]
    pub const fn stats(&self) -> CheckpointStats {
        self.slot.stats()
    }
}

impl CheckpointInbox {
    /// The request waiting, taken.
    #[must_use]
    pub fn take(&self) -> Option<CheckpointRequest> {
        lock(&self.shared).request.take()
    }

    /// Closes the handoff: the group stopped, failed or ended. A request
    /// still waiting goes back, [`CheckpointError::Stopped`], and every
    /// later one is refused so.
    pub fn close(&self) {
        let mut shared = lock(&self.shared);
        shared.closed = true;
        if let Some(request) = shared.request.take() {
            shared.returned = Some((request, Err(CheckpointError::Stopped)));
        }
    }

    /// Gives `request`'s buffer back, with how its write ended.
    pub fn give_back(
        &self,
        request: CheckpointRequest,
        result: Result<CheckpointRecord, CheckpointError>,
    ) {
        lock(&self.shared).returned = Some((request, result));
    }
}
