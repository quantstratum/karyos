// SPDX-License-Identifier: Apache-2.0

//! Replay of a recording group (`quantstratum-docs: karyos/SPEC.md` §8.3;
//! ADR-0024; archive-gap-analysis.md, phase 3 batch A8;
//! recording-group-replay.md).
//!
//! The journal side, here:
//!
//! - [`check_header`]: a journal replays only under this build's capture
//!   contract and a clock replay knows, and only for the replaying
//!   caller's manifest, compared byte for byte unless it accepts another
//!   (`recording-group-replay.md` section 8).
//! - [`ReplayCursor`]: the events of a recovered journal's complete
//!   prefix, in order, each with its observations and its end, from a
//!   buffer sized when the cursor is opened. Each event says whether a
//!   reference unavailable (template 22) names it, before it is presented
//!   (section 7). Where the prefix ends, the cursor says why with a typed
//!   [`Stop`]. With checkpoints (A9-2, `recording-group-checkpoints.md`
//!   section 6), [`ReplayCursor::open`] replays the journal's first range,
//!   [`ReplayCursor::open_at_checkpoint`] the range a checkpoint lies in
//!   from the event after it, and each recorded checkpoint of the range
//!   comes right after its event ([`Step::Checkpoint`]), for
//!   [`compare_state`].
//! - [`CaptureJournal`]: the journal a replay writes what it observes to,
//!   under the replaying caller's manifest (section 9).
//!
//! The Gateway side: [`gateway::ReplayGateway`], the replay implementation
//! of [`super::gateway::GroupGateway`], presents the events through
//! [`effects::ReplayEffects`], which checks each call against its recorded
//! observation; [`mod@reference`] reads a payload by reference from its
//! recording.

use std::path::Path;

use super::journal::{GroupJournal, JournalConfig, JournalError};
use super::prefix::Recovery;
use karyos_codec::CodecError;

use super::checkpoint::CheckpointStore;
use super::prefix::CheckpointHeld;
use super::record::{
    CAPTURE_POSITION, CONTRACT_VERSION, CheckpointRecord, Clock, EndOutcome, GapMarker,
    GroupRecord, JournalHeader, MAX_RECORD, Role,
};
use crate::crc32c::crc32c;
use crate::disk::Disk;

#[cfg(test)]
mod checkpoint_tests;
#[cfg(test)]
mod tests;

pub mod effects;
pub mod gateway;
pub mod reference;

/// The clock replay presents the readings of.
const CLOCK: Clock = Clock::HostMonotonic;

/// The replaying caller's side of the header check. The contract and the
/// clock are this build's, never the caller's: another contract is not
/// comparable, with no override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayConfig<'a> {
    /// The caller's identity of what replays: the recorded manifest must
    /// be the same bytes, unless `accept_manifest`.
    pub manifest: &'a [u8],
    /// Accept a recorded manifest that differs, as a strategy or version
    /// comparison does on purpose.
    pub accept_manifest: bool,
}

/// How a journal's header differs from what the replay expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeaderMismatch {
    /// Another capture contract.
    #[error("captured under contract {found}, replaying {expected}")]
    Contract {
        /// The journal's.
        found: u16,
        /// The replay's.
        expected: u16,
    },
    /// Another clock.
    #[error("captured with clock {found:?}, replaying {expected:?}")]
    Clock {
        /// The journal's.
        found: Clock,
        /// The replay's.
        expected: Clock,
    },
    /// Another manifest.
    #[error("the manifest differs")]
    Manifest,
}

/// Checks a journal's `header`: this build's contract, a clock replay
/// knows, then `config`'s manifest, byte for byte unless it accepts
/// another.
///
/// # Errors
///
/// The first [`HeaderMismatch`] found.
pub fn check_header(
    header: &JournalHeader<'_>,
    config: &ReplayConfig<'_>,
) -> Result<(), HeaderMismatch> {
    if header.contract_version != CONTRACT_VERSION {
        return Err(HeaderMismatch::Contract {
            found: header.contract_version,
            expected: CONTRACT_VERSION,
        });
    }
    if header.clock != CLOCK {
        return Err(HeaderMismatch::Clock {
            found: header.clock,
            expected: CLOCK,
        });
    }
    if !config.accept_manifest && header.manifest != config.manifest {
        return Err(HeaderMismatch::Manifest);
    }
    Ok(())
}

/// A replay's errors.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The journal holds no header.
    #[error("the journal holds no header")]
    NoHeader,
    /// The header is not what the replay expects.
    #[error(transparent)]
    Header(#[from] HeaderMismatch),
    /// An event's records do not fit the buffer's bytes.
    #[error("an event needs more than {capacity} bytes")]
    Bytes {
        /// The buffer's bytes.
        capacity: usize,
    },
    /// An event has more records than the buffer holds.
    #[error("an event has more than {capacity} records")]
    Records {
        /// The buffer's records.
        capacity: usize,
    },
    /// A cursor configuration with fewer than two records per event, or
    /// a buffer (or the list of the events a reference unavailable names)
    /// that cannot be allocated or counted.
    #[error("invalid cursor configuration")]
    InvalidConfig,
    /// The recovery stopped feeding the journal (`Recovery::full`): its
    /// prefixes cover only the journal's start, so replay would claim
    /// less than the journal holds.
    #[error("the recovery's feed stopped")]
    Truncated,
    /// The complete prefix ends inside an event, at `position`: the
    /// recovery and the journal disagree.
    #[error("the complete prefix ends inside an event at {position}")]
    Torn {
        /// Where the event's records stop.
        position: u64,
    },
    /// An event that starts at `position` with a record that is no
    /// event's first.
    #[error("no event starts at {position}")]
    NotAnEvent {
        /// Where.
        position: u64,
    },
    /// The record at `position` encodes again to another length than it
    /// has in the journal.
    #[error("the record at {position} encodes to {found} bytes, not {expected}")]
    Reencoded {
        /// Where.
        position: u64,
        /// Its length in the journal.
        expected: usize,
        /// Its length encoded again.
        found: usize,
    },
    /// A record that does not encode again.
    #[error(transparent)]
    Record(#[from] CodecError),
    /// No recorded checkpoint has this id.
    #[error("no checkpoint {checkpoint_id}")]
    UnknownCheckpoint {
        /// The id asked for.
        checkpoint_id: u64,
    },
    /// The checkpoint lies outside a replayable range's complete prefix:
    /// past it, or in a middle range. Replay never starts outside the
    /// guarantee.
    #[error("checkpoint {checkpoint_id} is outside a replayable prefix")]
    NotInPrefix {
        /// Its id.
        checkpoint_id: u64,
    },
    /// The snapshot is lost, or its bytes differ from its record's
    /// digest: not comparable.
    #[error("checkpoint {checkpoint_id} is corrupt")]
    CheckpointCorrupt {
        /// Its id.
        checkpoint_id: u64,
    },
    /// The caller's snapshot buffer is shorter than the snapshot.
    #[error("a snapshot of {length} bytes, the buffer holds {capacity}")]
    SnapshotTooSmall {
        /// The snapshot's length.
        length: u64,
        /// The buffer's.
        capacity: usize,
    },
    /// The journal's errors.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// The replay's state differs from the recorded checkpoint at its
/// `group_seq`: a divergence of kind `state checkpoint`, which stops
/// replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "state checkpoint at {group_seq}: {length} bytes, crc {crc32c:#x}; \
     recorded {recorded_length}, {recorded_crc32c:#x}"
)]
pub struct StateDivergence {
    /// The event the state follows.
    pub group_seq: u64,
    /// The recorded snapshot's length.
    pub recorded_length: u64,
    /// The recorded snapshot's digest.
    pub recorded_crc32c: u32,
    /// The replay's snapshot's length.
    pub length: u64,
    /// The replay's snapshot's digest.
    pub crc32c: u32,
}

/// Compares the replay's state at a recorded checkpoint, `bytes` as the
/// handler's `write` produced them, with `recorded` by length and digest
/// (`recording-group-checkpoints.md` section 6). Equal, it returns the
/// capture journal's record: the replay's digest at
/// [`CAPTURE_POSITION`], stored nowhere.
///
/// # Errors
///
/// [`StateDivergence`] when they differ, also when `bytes` is longer than
/// a `u64` counts.
pub fn compare_state(
    recorded: &CheckpointRecord,
    bytes: &[u8],
) -> Result<CheckpointRecord, StateDivergence> {
    let crc = crc32c(bytes);
    let divergence = |length| StateDivergence {
        group_seq: recorded.group_seq,
        recorded_length: recorded.length,
        recorded_crc32c: recorded.crc32c,
        length,
        crc32c: crc,
    };
    let length = u64::try_from(bytes.len()).map_err(|_| divergence(u64::MAX))?;
    if length != recorded.length || crc != recorded.crc32c {
        return Err(divergence(length));
    }
    Ok(CheckpointRecord {
        position: CAPTURE_POSITION,
        ..*recorded
    })
}

/// Why a cursor gives no event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The prefix ends at a gap marker: the events it names were not
    /// captured.
    Gap(GapMarker),
    /// The prefix ends at an event whose capture is incomplete.
    Incomplete {
        /// Its `group_seq`.
        group_seq: u64,
    },
    /// The complete prefix ends with nothing recorded against it: what
    /// follows, if anything, is not complete yet.
    EndOfPrefix {
        /// The prefix's last event, `first_group_seq - 1` before any.
        complete_recording_seq: u64,
    },
}

/// What [`ReplayCursor::step`] gives: once it gives a stop, it gives the
/// same stop on every later call.
#[derive(Debug)]
pub enum Step<'c> {
    /// The next event of the complete prefix.
    Event(ReplayEvent<'c>),
    /// A recorded checkpoint of the state after the event just given
    /// (A9-2): the replay side writes its own state there and compares it
    /// ([`compare_state`]).
    Checkpoint(CheckpointRecord),
    /// No event.
    Stop(Stop),
}

/// What a read gave, before it is lent.
#[derive(Debug, Clone, Copy)]
enum Next {
    Event { group_seq: u64, incomplete: bool },
    Checkpoint(CheckpointRecord),
    Stop(Stop),
}

/// One event's records: its first record, its observations in order, and
/// its end, borrowed from the cursor's buffer.
#[derive(Debug, Clone, Copy)]
pub struct ReplayEvent<'c> {
    group_seq: u64,
    reference_unavailable: bool,
    incomplete: bool,
    bytes: &'c [u8],
    spans: &'c [(usize, usize)],
}

impl<'c> ReplayEvent<'c> {
    /// The event's `group_seq`.
    #[must_use]
    pub const fn group_seq(&self) -> u64 {
        self.group_seq
    }

    /// Whether a reference unavailable (template 22) names the event: its
    /// payload by reference will never be there, so replay cannot present
    /// it whole (`recording-group-replay.md` section 7). The record may
    /// lie anywhere after the event; the cursor found it when it opened.
    #[must_use]
    pub const fn reference_unavailable(&self) -> bool {
        self.reference_unavailable
    }

    /// Whether the event's capture is incomplete: its records are those
    /// captured, and its end says incomplete. Replay presents it with its
    /// recorded observations, and stops after it (section 7); the cursor
    /// gives [`Stop::Incomplete`] next.
    #[must_use]
    pub const fn incomplete(&self) -> bool {
        self.incomplete
    }

    /// The number of records, its first and its end included.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.spans.len()
    }

    /// Never: an event has at least its first record and its end.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// The records' encoded bytes, back to back.
    #[must_use]
    pub fn bytes(&self) -> &'c [u8] {
        let end = self.spans.last().map_or(0, |&(_, end)| end);
        self.bytes.get(..end).unwrap_or_default()
    }

    /// Record `index`'s encoded bytes.
    #[must_use]
    pub fn record_bytes(&self, index: usize) -> Option<&'c [u8]> {
        let &(start, end) = self.spans.get(index)?;
        self.bytes.get(start..end)
    }

    /// Record `index`, decoded.
    ///
    /// # Errors
    ///
    /// The decoder's: none for a record the journal checked.
    pub fn record(&self, index: usize) -> Option<Result<GroupRecord<'c>, CodecError>> {
        let &(start, end) = self.spans.get(index)?;
        let bytes = self.bytes.get(start..end)?;
        Some(GroupRecord::decode(bytes))
    }

    /// The records, decoded, in order.
    pub fn records(&self) -> impl Iterator<Item = Result<GroupRecord<'c>, CodecError>> + '_ {
        (0..self.spans.len()).filter_map(|index| self.record(index))
    }
}

/// The room a cursor's buffer has for one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorConfig {
    /// Bytes for one event's records: at least [`MAX_RECORD`] times
    /// `records` holds any event of that many records.
    pub bytes: usize,
    /// Records in one event, its first and its end included: at least 2.
    pub records: usize,
}

/// One allocation of `capacity` elements, or [`ReplayError::InvalidConfig`].
pub(crate) fn allocate<T>(capacity: usize) -> Result<Vec<T>, ReplayError> {
    let mut vec = Vec::new();
    vec.try_reserve_exact(capacity)
        .map_err(|_| ReplayError::InvalidConfig)?;
    Ok(vec)
}

/// The events of a recovered journal's complete prefix, in order: the
/// first range's from the journal's start, or a range's from a checkpoint
/// in it, each recorded checkpoint given right after its event.
///
/// It allocates only when opened: the buffer, the events a reference
/// unavailable names, and the recorded checkpoints of the range it
/// replays. Each [`ReplayCursor::step`] reads one
/// event's records into the buffer and lends them until the next call.
#[derive(Debug)]
pub struct ReplayCursor<D: Disk> {
    journal: GroupJournal<D>,
    /// The next record to read.
    position: u64,
    /// The journal position after the complete prefix's last record.
    complete_end: u64,
    complete_seq: u64,
    /// The `group_seq`s of the prefix that a reference unavailable names,
    /// sorted.
    unavailable: Vec<u64>,
    /// The recorded checkpoints of the replayed range, by `group_seq`.
    checkpoints: Vec<CheckpointRecord>,
    /// The next of them to give.
    next_checkpoint: usize,
    /// The last event given (the checkpoint's `group_seq` when opened at
    /// one).
    last_seq: u64,
    buffer: Vec<u8>,
    spans: Vec<(usize, usize)>,
    /// The final stop, once reached.
    stopped: Option<Stop>,
    /// The incomplete event the prefix stopped at, while the cursor gives
    /// its records.
    incomplete: Option<u64>,
}

impl<D: Disk> ReplayCursor<D> {
    /// Opens a cursor over `journal`, whose prefixes `recovery` computed
    /// (by [`super::prefix::recover`] on the same journal), after checking
    /// its header against `config`. It reads the journal once to find the
    /// events of the prefix a reference unavailable names, and the
    /// checkpoints it gives. It replays the journal's first range: once a
    /// checkpoint opened another, that one replays from its checkpoint.
    ///
    /// # Errors
    ///
    /// [`ReplayError::NoHeader`], [`ReplayError::Header`],
    /// [`ReplayError::InvalidConfig`], [`ReplayError::Truncated`], and the
    /// journal's errors.
    pub fn open(
        journal: GroupJournal<D>,
        recovery: &Recovery,
        config: &ReplayConfig<'_>,
        room: CursorConfig,
    ) -> Result<Self, ReplayError> {
        // Replay from the start stops at the first range's end: a later
        // range a checkpoint opened is replayed from it.
        let range = recovery.tracker.first_range().map_or(
            (
                recovery.tracker.complete_recording_seq(),
                recovery.tracker.complete_end(),
            ),
            |first| (first.complete, first.complete_end),
        );
        Self::open_range(journal, recovery, config, room, None, range)
    }

    /// Opens a cursor at checkpoint `checkpoint_id` (A9-2,
    /// `recording-group-checkpoints.md` section 6): its snapshot is read
    /// from `store` into `snapshot` and checked against its record's
    /// `length` and `crc32c`, for the caller's `restore`; the cursor then
    /// gives the events after its `group_seq`, up to the end of the range
    /// it lies in, and stops there as replay from the start does. The
    /// checkpoint must lie in the first range or in the current one, at or
    /// before its complete prefix: a middle range is not replayable yet.
    /// Returns the cursor and the checkpoint's record; the snapshot is
    /// `snapshot[..length]`.
    ///
    /// Recover with the group's reopen hold
    /// ([`super::prefix::recover_with_hold`]): with another, a range a
    /// checkpoint reopened may be recovered otherwise than it ran.
    ///
    /// # Errors
    ///
    /// [`ReplayError::UnknownCheckpoint`], [`ReplayError::NotInPrefix`],
    /// [`ReplayError::SnapshotTooSmall`], [`ReplayError::CheckpointCorrupt`]
    /// (lost, or its digest differs: not comparable), the store's errors,
    /// and [`ReplayCursor::open`]'s.
    #[allow(clippy::too_many_arguments, reason = "the seam agreed for A8")]
    pub fn open_at_checkpoint(
        mut journal: GroupJournal<D>,
        recovery: &Recovery,
        store: &mut CheckpointStore<D>,
        checkpoint_id: u64,
        config: &ReplayConfig<'_>,
        room: CursorConfig,
        snapshot: &mut [u8],
    ) -> Result<(Self, CheckpointRecord), ReplayError> {
        let mut found = None;
        let _ = journal.walk(0, |_, _, record| {
            if let GroupRecord::Checkpoint(checkpoint) = record
                && checkpoint.checkpoint_id == checkpoint_id
            {
                found = Some(*checkpoint);
                return false;
            }
            true
        })?;
        let checkpoint = found.ok_or(ReplayError::UnknownCheckpoint { checkpoint_id })?;
        let seq = checkpoint.group_seq;
        let tracker = &recovery.tracker;
        let current = (tracker.complete_recording_seq(), tracker.complete_end());
        let range = match (tracker.first_range(), tracker.range().start) {
            (Some(first), Some(_)) if seq <= first.complete => (first.complete, first.complete_end),
            (Some(_), Some(start)) if seq >= start.group_seq && seq <= current.0 => current,
            // Only one range: the journal's first.
            (None, _) if seq <= current.0 => current,
            _ => return Err(ReplayError::NotInPrefix { checkpoint_id }),
        };
        let corrupt = || ReplayError::CheckpointCorrupt { checkpoint_id };
        let end = checkpoint.end().ok_or_else(corrupt)?;
        let length = usize::try_from(checkpoint.length).map_err(|_| corrupt())?;
        // Lost before too small: a lost checkpoint is not comparable,
        // whatever the buffer.
        match store.holds(checkpoint.position, end) {
            CheckpointHeld::Written | CheckpointHeld::Durable => {}
            CheckpointHeld::Missing | CheckpointHeld::Lost => return Err(corrupt()),
        }
        let capacity = snapshot.len();
        let bytes = snapshot
            .get_mut(..length)
            .ok_or(ReplayError::SnapshotTooSmall {
                length: checkpoint.length,
                capacity,
            })?;
        store
            .read(checkpoint.position, bytes)
            .map_err(JournalError::Segment)?;
        if crc32c(bytes) != checkpoint.crc32c {
            return Err(corrupt());
        }
        let cursor = Self::open_range(journal, recovery, config, room, Some(seq), range)?;
        Ok((cursor, checkpoint))
    }

    /// The cursor over the range whose complete prefix is `range`
    /// (`(complete_seq, complete_end)`), from its first event, or from the
    /// first above `after`.
    fn open_range(
        mut journal: GroupJournal<D>,
        recovery: &Recovery,
        config: &ReplayConfig<'_>,
        room: CursorConfig,
        after: Option<u64>,
        (complete_seq, complete_end): (u64, u64),
    ) -> Result<Self, ReplayError> {
        if recovery.full {
            return Err(ReplayError::Truncated);
        }
        if room.records < 2 {
            return Err(ReplayError::InvalidConfig);
        }
        let mut checked = None;
        let mut header_end = 0;
        let _ = journal.walk(0, |_, end, record| {
            if let GroupRecord::Header(header) = record {
                checked = Some(check_header(header, config));
                header_end = end;
            }
            false
        })?;
        checked.ok_or(ReplayError::NoHeader)??;
        let from = after.unwrap_or(0);
        // Counted first, so each list is one allocation that fails typed.
        // The prefix's events, and the incomplete event the cursor may
        // give after them.
        let last = complete_seq.checked_add(1).unwrap_or(complete_seq);
        let names = |record: &GroupRecord<'_>| match record {
            GroupRecord::Unavailable(record) if record.group_seq <= last => Some(record.group_seq),
            _ => None,
        };
        let replayed = |record: &GroupRecord<'_>| match record {
            GroupRecord::Checkpoint(checkpoint)
                if checkpoint.group_seq > from && checkpoint.group_seq <= complete_seq =>
            {
                Some(*checkpoint)
            }
            _ => None,
        };
        let mut counts = Some((0usize, 0usize));
        let mut start = None;
        let _ = journal.walk(header_end, |position, _, record| {
            if let (None, Some(after), Role::Event(seq) | Role::Uncaptured(seq)) =
                (start, after, record.role())
                && seq > after
            {
                start = Some(position);
            }
            counts = match (counts, names(record), replayed(record)) {
                (Some((names, checkpoints)), Some(_), _) => {
                    names.checked_add(1).map(|names| (names, checkpoints))
                }
                (Some((names, checkpoints)), _, Some(_)) => checkpoints
                    .checked_add(1)
                    .map(|checkpoints| (names, checkpoints)),
                (counts, _, _) => counts,
            };
            counts.is_some()
        })?;
        let (names_count, replayed_count) = counts.ok_or(ReplayError::InvalidConfig)?;
        let mut unavailable = allocate::<u64>(names_count)?;
        let mut checkpoints = allocate::<CheckpointRecord>(replayed_count)?;
        let _ = journal.walk(header_end, |_, _, record| {
            if let Some(seq) = names(record)
                && unavailable.len() < unavailable.capacity()
            {
                unavailable.push(seq);
            }
            if let Some(checkpoint) = replayed(record)
                && checkpoints.len() < checkpoints.capacity()
            {
                checkpoints.push(checkpoint);
            }
            true
        })?;
        unavailable.sort_unstable();
        unavailable.dedup();
        // Recorded checkpoints rise in `group_seq` (the order rules), so
        // the list is in order as read.
        let complete_end = complete_end.max(header_end);
        // From a checkpoint: its range's first event above it, or the
        // range's end with none.
        let position = match after {
            None => header_end,
            Some(_) => start.map_or(complete_end, |start| start.min(complete_end)),
        };
        let mut buffer = allocate(room.bytes)?;
        buffer.resize(room.bytes, 0u8);
        Ok(Self {
            journal,
            position,
            complete_end,
            complete_seq,
            unavailable,
            checkpoints,
            next_checkpoint: 0,
            last_seq: from,
            buffer,
            spans: allocate(room.records)?,
            stopped: None,
            incomplete: None,
        })
    }

    /// The next event of the complete prefix, or why there is none. A
    /// reference unavailable record is not an event, and is skipped: its
    /// event says it was named. An incomplete event the prefix stopped at
    /// is given once, marked [`ReplayEvent::incomplete`], before
    /// [`Stop::Incomplete`]. A recorded checkpoint comes right after the
    /// event it names ([`Step::Checkpoint`]). An event past the range's
    /// complete prefix ends it, also one that lies before the checkpoint
    /// record that opened the range.
    ///
    /// # Errors
    ///
    /// [`ReplayError::Bytes`] and [`ReplayError::Records`] for an event
    /// larger than the buffer, which is not consumed;
    /// [`ReplayError::Torn`], [`ReplayError::NotAnEvent`],
    /// [`ReplayError::Reencoded`]; and the journal's errors.
    pub fn step(&mut self) -> Result<Step<'_>, ReplayError> {
        let next = self.read_next()?;
        Ok(self.view(next))
    }

    /// [`ReplayCursor::step`], past the events before `from`: the first
    /// event at or after it, or the stop.
    ///
    /// # Errors
    ///
    /// As [`ReplayCursor::step`].
    pub fn step_from(&mut self, from: u64) -> Result<Step<'_>, ReplayError> {
        loop {
            let next = self.read_next()?;
            // A checkpoint below `from` is skipped with its event.
            let below = match next {
                Next::Event { group_seq, .. } => group_seq < from,
                Next::Checkpoint(checkpoint) => checkpoint.group_seq < from,
                Next::Stop(_) => false,
            };
            if !below {
                return Ok(self.view(next));
            }
        }
    }

    /// What [`Self::read_next`] read, lent from the buffer.
    fn view(&self, next: Next) -> Step<'_> {
        match next {
            Next::Stop(stop) => Step::Stop(stop),
            Next::Checkpoint(checkpoint) => Step::Checkpoint(checkpoint),
            Next::Event {
                group_seq,
                incomplete,
            } => Step::Event(ReplayEvent {
                group_seq,
                incomplete,
                reference_unavailable: self.unavailable.binary_search(&group_seq).is_ok(),
                bytes: &self.buffer,
                spans: &self.spans,
            }),
        }
    }

    /// Reads the next event's records into the buffer, or the stop.
    fn read_next(&mut self) -> Result<Next, ReplayError> {
        // A checkpoint right after the event it names.
        if let Some(checkpoint) = self.due_checkpoint()? {
            return Ok(Next::Checkpoint(checkpoint));
        }
        if let Some(stop) = self.stopped {
            return Ok(Next::Stop(stop));
        }
        loop {
            if self.position >= self.complete_end {
                match self.past_prefix()? {
                    Some(stop) => return Ok(Next::Stop(stop)),
                    // The incomplete event: read it, up to its end.
                    None => continue,
                }
            }
            self.spans.clear();
            let (buffer, spans) = (&mut self.buffer, &mut self.spans);
            let mut fill = 0usize;
            let mut first = None;
            let mut done = None;
            let mut failed = None;
            let mut past = false;
            let (complete_seq, incomplete) = (self.complete_seq, self.incomplete);
            let _ = self.journal.walk(self.position, |position, end, record| {
                if spans.is_empty() {
                    // An event past the prefix is not read: the stop is
                    // found from it, whatever its size.
                    if let Role::Event(seq) | Role::Uncaptured(seq) = record.role()
                        && seq > complete_seq
                        && incomplete != Some(seq)
                    {
                        past = true;
                        return false;
                    }
                    match record.role() {
                        // Not events: a reference unavailable, and a
                        // checkpoint (A9), which A9-2 replays against.
                        Role::Unavailable(_) | Role::Checkpoint { .. } => {
                            done = Some((end, false));
                            return false;
                        }
                        Role::Event(seq) | Role::Uncaptured(seq) => first = Some(seq),
                        _ => {
                            failed = Some(ReplayError::NotAnEvent { position });
                            return false;
                        }
                    }
                }
                let Some(length) = end
                    .checked_sub(position)
                    .and_then(|length| usize::try_from(length).ok())
                else {
                    failed = Some(ReplayError::Torn { position });
                    return false;
                };
                let Some((to, slot)) = fill
                    .checked_add(length)
                    .and_then(|to| buffer.get_mut(fill..to).map(|slot| (to, slot)))
                else {
                    failed = Some(ReplayError::Bytes {
                        capacity: buffer.len(),
                    });
                    return false;
                };
                if spans.len() == spans.capacity() {
                    failed = Some(ReplayError::Records {
                        capacity: spans.capacity(),
                    });
                    return false;
                }
                match record.encode(slot) {
                    Ok(found) if found == length => {}
                    Ok(found) => {
                        failed = Some(ReplayError::Reencoded {
                            position,
                            expected: length,
                            found,
                        });
                        return false;
                    }
                    Err(error) => {
                        failed = Some(ReplayError::Record(error));
                        return false;
                    }
                }
                spans.push((fill, to));
                fill = to;
                if matches!(record, GroupRecord::End(_)) {
                    done = Some((end, true));
                    return false;
                }
                true
            })?;
            if past {
                self.spans.clear();
                self.complete_end = self.position;
                continue;
            }
            if let Some(error) = failed {
                self.spans.clear();
                return Err(error);
            }
            match (done, first) {
                // A reference unavailable or a checkpoint record: skipped.
                (Some((end, false)), _) => self.position = end,
                (Some((end, true)), Some(group_seq)) if end <= self.complete_end => {
                    self.position = end;
                    self.last_seq = group_seq;
                    let incomplete = self.incomplete == Some(group_seq);
                    if incomplete {
                        self.stopped = Some(Stop::Incomplete { group_seq });
                    }
                    return Ok(Next::Event {
                        group_seq,
                        incomplete,
                    });
                }
                _ => {
                    return Err(ReplayError::Torn {
                        position: self.position,
                    });
                }
            }
        }
    }

    /// The stop at the end of the complete prefix, from the records after
    /// it: the gap the prefix stopped at, if one comes before the next
    /// complete event. At an incomplete event it gives `None`, having set
    /// the cursor to give that event's records next. Reference unavailable
    /// records are skipped: the cursor found those of the prefix when it
    /// opened.
    fn past_prefix(&mut self) -> Result<Option<Stop>, ReplayError> {
        if self.incomplete.is_some() {
            // The incomplete event's records ended before its end record.
            return Err(ReplayError::Torn {
                position: self.position,
            });
        }
        let mut stop = None;
        let mut incomplete = None;
        let _ = self.journal.walk(self.position, |_, end, record| {
            match record {
                GroupRecord::Gap(gap) => {
                    stop = Some(Stop::Gap(*gap));
                    return false;
                }
                GroupRecord::End(record) if record.outcome == EndOutcome::Incomplete => {
                    incomplete = Some((record.group_seq, end));
                    return false;
                }
                // The first event past the prefix is complete and waits on
                // its payload, or on durability.
                GroupRecord::End(_) => return false,
                _ => {}
            }
            true
        })?;
        if let Some((group_seq, end)) = incomplete {
            self.incomplete = Some(group_seq);
            self.complete_end = end;
            return Ok(None);
        }
        let stop = stop.unwrap_or(Stop::EndOfPrefix {
            complete_recording_seq: self.complete_seq,
        });
        self.stopped = Some(stop);
        Ok(Some(stop))
    }

    /// The recorded checkpoint of the event just given, if one is due,
    /// taken: as [`Step::Checkpoint`] gives it, for a caller that handles
    /// it within the event's own dispatch.
    ///
    /// # Errors
    ///
    /// [`ReplayError::InvalidConfig`] past `usize` checkpoints.
    pub fn due_checkpoint(&mut self) -> Result<Option<CheckpointRecord>, ReplayError> {
        let Some(checkpoint) = self.checkpoints.get(self.next_checkpoint).copied() else {
            return Ok(None);
        };
        if checkpoint.group_seq > self.last_seq {
            return Ok(None);
        }
        self.next_checkpoint = self
            .next_checkpoint
            .checked_add(1)
            .ok_or(ReplayError::InvalidConfig)?;
        Ok(Some(checkpoint))
    }

    /// The journal, given back.
    #[must_use]
    pub fn into_journal(self) -> GroupJournal<D> {
        self.journal
    }
}

/// The journal a replay captures to: one record at a time, each checked
/// by the journal's order rules.
#[derive(Debug)]
pub struct CaptureJournal<D: Disk> {
    journal: GroupJournal<D>,
    /// One encoded record.
    scratch: Vec<u8>,
}

impl<D: Disk> CaptureJournal<D> {
    /// Creates the capture journal of the recorded `header`'s group in
    /// `dir`, with the replaying caller's `manifest` in its header
    /// (`recording-group-replay.md` section 9). `dir` is the capture's own
    /// directory: the original's holds the group's journal already, and
    /// is refused ([`crate::segment::SegmentError::Exists`]).
    ///
    /// # Errors
    ///
    /// [`GroupJournal::create`]'s.
    pub fn create(
        disk: D,
        dir: &Path,
        header: &JournalHeader<'_>,
        manifest: &[u8],
        config: JournalConfig,
    ) -> Result<Self, JournalError> {
        let header = JournalHeader {
            manifest,
            ..*header
        };
        Ok(Self {
            journal: GroupJournal::create(disk, dir, &header, config)?,
            scratch: vec![0u8; MAX_RECORD],
        })
    }

    /// [`CaptureJournal::create`] for a replay from a checkpoint
    /// (A9-2): the capture's first event is `first_group_seq`, the one
    /// after the checkpoint's.
    ///
    /// # Errors
    ///
    /// [`GroupJournal::create`]'s.
    pub fn create_from(
        disk: D,
        dir: &Path,
        header: &JournalHeader<'_>,
        manifest: &[u8],
        first_group_seq: u64,
        config: JournalConfig,
    ) -> Result<Self, JournalError> {
        let header = JournalHeader {
            first_group_seq,
            ..*header
        };
        Self::create(disk, dir, &header, manifest, config)
    }

    /// Appends `record`; returns the written position.
    ///
    /// # Errors
    ///
    /// [`JournalError::Record`] for a record that does not encode, and
    /// [`GroupJournal::append`]'s.
    pub fn append(&mut self, record: &GroupRecord<'_>) -> Result<u64, JournalError> {
        let length = record.encode(&mut self.scratch)?;
        let bytes = self
            .scratch
            .get(..length)
            .ok_or(JournalError::NotWhole { length })?;
        self.journal.append(bytes)
    }

    /// The journal.
    #[must_use]
    pub const fn journal(&self) -> &GroupJournal<D> {
        &self.journal
    }

    /// The journal, given back, to sync or close.
    #[must_use]
    pub fn into_journal(self) -> GroupJournal<D> {
        self.journal
    }
}
